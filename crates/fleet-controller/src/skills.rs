//! The Skills Manager executor (FM-302): probe, deploy, and undeploy
//! through the documented `skills-manager-cli --json` contract, over the
//! bounded SSH transport.
//!
//! The transport rule from the provider holds in full: the CLI's name is
//! fixed, and every caller-controlled value — skill ids, agent ids, an
//! external skills root — rides the base64 metadata blob as positional
//! arguments, never through a remote shell. A version probe runs first on
//! every kind: a CLI outside the tested range, or one that answers in an
//! undocumented shape, degrades explicitly to `unsupported_version`
//! instead of guessing.
//!
//! Deploy and undeploy are audited durable operations with bounded
//! output; `--dry-run` is preserved when the caller supplied it, never
//! silently upgraded to a real mutation. Secrets never ride arguments,
//! output, or audit: the result path redacts before anything becomes
//! public.
//!
//! Install with checksum verification: the probe payload may pin a
//! release (URL, sha256, version range); the fixed script verifies the
//! digest before placing the binary and refuses a mismatch loudly.

use std::sync::Arc;
use std::time::Duration;

use fleet_application::machine::MachinePort;
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_provider_ssh::{ExecutionLimiter, ScriptMetadata, SshConnectionSpec};

use crate::exec::{MAX_SCRIPT_TIMEOUT, resolve_ssh_endpoint};

/// The version gate's outcome, typed so each failure keeps its own public
/// reason.
#[derive(Debug)]
enum GateOutcome {
    /// The CLI is present, identified, and within the tested range.
    Pass,
    /// The CLI is absent: the machine answered, the tool is not there.
    Absent,
    /// The CLI answered but not in the documented shape, or its version
    /// is outside the tested range.
    Unsupported {
        /// The caller-safe detail.
        detail: String,
    },
    /// The transport failed before the CLI could answer.
    Connection {
        /// The redacted detail.
        detail: String,
    },
    /// The deadline killed the gate.
    Deadline,
}

/// The highest CLI version the contract fixtures were recorded against.
/// A CLI answering a higher major version degrades explicitly.
pub const TESTED_CLI_VERSION: &str = "1.34.2";

/// The deadline bound for one skills operation.
pub const MAX_SKILLS_TIMEOUT: u64 = MAX_SCRIPT_TIMEOUT;

/// How the endpoint authenticates.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
enum Auth {
    /// The controller's agent supplies the key.
    Agent,
    /// A specific identity file.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// The `skills.probe` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProbePayload {
    machine_id: String,
    endpoint_id: String,
    auth: Auth,
    /// An external skills root to probe against, when one is named.
    #[serde(default)]
    skills_root: Option<String>,
    /// An optional pinned release to install when the CLI is absent:
    /// the download URL.
    #[serde(default)]
    artifact_url: Option<String>,
    /// The pinned release's expected sha256.
    #[serde(default)]
    artifact_sha256: Option<String>,
    timeout_seconds: u64,
}

/// The `skills.deploy` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeployPayload {
    machine_id: String,
    endpoint_id: String,
    auth: Auth,
    /// The skill to deploy.
    skill_id: String,
    /// The agents to deploy to, as documented ids.
    agents: Vec<String>,
    /// An external skills root, when the deployment targets one.
    #[serde(default)]
    skills_root: Option<String>,
    /// Preserve a caller's dry run: never upgraded to a real mutation.
    #[serde(default)]
    dry_run: bool,
    timeout_seconds: u64,
}

/// The `skills.undeploy` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct UndeployPayload {
    machine_id: String,
    endpoint_id: String,
    auth: Auth,
    skill_id: String,
    agents: Vec<String>,
    #[serde(default)]
    skills_root: Option<String>,
    #[serde(default)]
    dry_run: bool,
    timeout_seconds: u64,
}

/// The kind-dispatching skills executor.
#[derive(Debug)]
pub struct SkillsExecutor {
    machines: Arc<dyn MachinePort>,
    provider: fleet_provider_ssh::SshProvider,
    limiter: Arc<ExecutionLimiter>,
    /// Retained for the provider's isolated directory lifetime.
    #[allow(dead_code)]
    work_dir: std::path::PathBuf,
}

impl SkillsExecutor {
    /// Composes the executor from its parts.
    ///
    /// # Panics
    ///
    /// Panics only if the SSH work directory cannot be prepared, which the
    /// store's own data-directory preparation already ensures.
    #[must_use]
    pub fn new(
        machines: Arc<dyn MachinePort>,
        work_dir: std::path::PathBuf,
        limiter: Arc<ExecutionLimiter>,
    ) -> Self {
        let provider = fleet_provider_ssh::SshProvider::new(work_dir.clone())
            .expect("the SSH work dir must prepare");
        Self {
            machines,
            provider,
            limiter,
            work_dir,
        }
    }

    async fn resolve(
        &self,
        machine_id: &str,
        endpoint_id: &str,
        auth: &Auth,
    ) -> Result<SshConnectionSpec, String> {
        let ssh_auth = match auth {
            Auth::Agent => fleet_provider_ssh::SshAuth::Agent,
            Auth::IdentityFile { path } => {
                fleet_provider_ssh::SshAuth::IdentityFile { path: path.clone() }
            }
        };
        let (spec, _verified, _host) =
            resolve_ssh_endpoint(self.machines.as_ref(), machine_id, endpoint_id, ssh_auth).await?;
        Ok(spec)
    }

    async fn run(
        &self,
        spec: &SshConnectionSpec,
        script: &str,
        metadata: &ScriptMetadata,
        deadline: Duration,
    ) -> (Option<fleet_provider_ssh::ExecutionResult>, Option<String>) {
        let provider = self.provider.clone();
        let limiter = self.limiter.clone();
        let spec = spec.clone();
        let script = script.to_owned();
        let metadata = metadata.clone();
        tokio::task::spawn_blocking(move || {
            fleet_provider_ssh::execute_script(
                &provider, &limiter, &spec, &script, &metadata, deadline,
            )
        })
        .await
        .map_or_else(
            |join_error| {
                (
                    None,
                    Some(format!("the execution thread failed: {join_error}")),
                )
            },
            |outcome| match outcome {
                Ok(result) => (Some(result), None),
                Err(error) => (None, Some(error.to_string())),
            },
        )
    }
}

#[async_trait::async_trait]
impl OperationExecutor for SkillsExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "skills.probe" => self.probe(operations, operation).await,
            "skills.deploy" => self.deploy(operations, operation).await,
            "skills.undeploy" => self.undeploy(operations, operation).await,
            _ => Err("not a skills kind".to_owned()),
        }
    }
}

impl SkillsExecutor {
    async fn probe(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: ProbePayload = payload(operation)?;
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        operations
            .record_progress(&operation.id, Some(0), Some(1), Some("probing the CLI"))
            .await
            .map_err(|error| error.to_string())?;
        let deadline = deadline(payload.timeout_seconds);
        // A pinned release installs when the CLI is absent; the fixed
        // script verifies the digest before placing the binary.
        // A partial pin is refused before anything runs: a silent unpinned
        // probe would pretend the caller's intent was honored.
        if payload.artifact_url.is_some() != payload.artifact_sha256.is_some() {
            return Err("the pinned release requires both an artifact URL and a sha256".to_owned());
        }
        let pinned = payload
            .artifact_url
            .as_deref()
            .zip(payload.artifact_sha256.as_deref());
        if let Some((url, sha256)) = &pinned {
            if url.is_empty() || sha256.is_empty() {
                return Err(
                    "the pinned release requires both an artifact URL and a sha256".to_owned(),
                );
            }
            // The URL rides the metadata's NUL-framed environment; control
            // characters cannot break the framing but would smuggle fields.
            if url.chars().any(char::is_control) {
                return Err("the artifact URL must not contain control characters".to_owned());
            }
            if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("the artifact sha256 must be 64 hex characters".to_owned());
            }
        }
        // The pin rides the environment (absent means no pin) because the
        // prologue drops empty positional arguments; the root rides $1.
        let mut environment = Vec::new();
        if let Some((url, sha256)) = &pinned {
            environment.push(("FLEET_PIN_URL".to_owned(), (*url).to_owned()));
            environment.push(("FLEET_PIN_SHA256".to_owned(), (*sha256).to_owned()));
        }
        let arguments: Vec<String> = match &payload.skills_root {
            Some(root) => {
                validate_root(root)?;
                vec![root.clone()]
            }
            None => Vec::new(),
        };
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment,
            arguments,
        };
        let (result, detail) = self.run(&spec, &probe_script(), &metadata, deadline).await;
        match (result, detail) {
            (Some(result), _) if result.killed_by_deadline => {
                complete_failure(
                    operations,
                    &operation.id,
                    "deadline_killed",
                    "the probe was killed at its deadline; the CLI's state is unknown",
                )
                .await
            }
            (Some(result), _) if result.exit_code == Some(0) => {
                let parsed: Option<serde_json::Value> = result
                    .stdout
                    .lines()
                    .find_map(|line| serde_json::from_str(line).ok());
                // An empty or non-conforming answer is an unsupported CLI,
                // not a success with a null probe.
                let Some(parsed) = parsed else {
                    return complete_failure(
                        operations,
                        &operation.id,
                        "unsupported_version",
                        "the CLI's probe did not answer in the documented shape",
                    )
                    .await;
                };
                let result_json = serde_json::json!({ "probe": parsed }).to_string();
                operations
                    .complete(&operation.id, "succeeded", Some(&result_json), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            (Some(result), _) => {
                complete_failure(
                    operations,
                    &operation.id,
                    "probe_failed",
                    &redact_output(&result.stderr),
                )
                .await
            }
            (None, Some(detail)) => {
                complete_failure(operations, &operation.id, "connection_failed", &detail).await
            }
            (None, None) => Err("the probe produced neither a result nor a detail".to_owned()),
        }
    }

    async fn deploy(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: DeployPayload = payload(operation)?;
        validate_id(&payload.skill_id, "the skill id")?;
        for agent in &payload.agents {
            validate_id(agent, "an agent id")?;
        }
        if let Some(root) = &payload.skills_root {
            validate_root(root)?;
        }
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        // The version gate runs before every mutation: an untested CLI
        // degrades explicitly instead of guessing. One deadline covers
        // the gate and the mutation together.
        let operation_deadline = deadline(payload.timeout_seconds);
        match self.version_gate(&spec, operation_deadline).await {
            GateOutcome::Pass => {}
            GateOutcome::Absent => {
                return complete_failure(
                    operations,
                    &operation.id,
                    "cli_absent",
                    "skills-manager-cli is not installed",
                )
                .await;
            }
            GateOutcome::Unsupported { detail } => {
                return complete_failure(operations, &operation.id, "unsupported_version", &detail)
                    .await;
            }
            GateOutcome::Connection { detail } => {
                return complete_failure(operations, &operation.id, "connection_failed", &detail)
                    .await;
            }
            GateOutcome::Deadline => {
                return complete_failure(
                    operations,
                    &operation.id,
                    "deadline_killed",
                    "the version gate was killed at its deadline; the machine's skill state is unknown",
                )
                .await;
            }
        }
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!(
                    "deploying {} to {} agent(s){}",
                    payload.skill_id,
                    payload.agents.len(),
                    if payload.dry_run { " (dry run)" } else { "" },
                )),
            )
            .await
            .map_err(|error| error.to_string())?;
        // The CLI is resolved off-PATH by the fixed script; the skill id
        // and every agent id stay separate positional parameters, and the
        // skills root rides the environment.
        let mut arguments = vec![payload.skill_id.clone()];
        arguments.extend(payload.agents.iter().cloned());
        let script = if payload.dry_run {
            mutation_script("deploy", true)
        } else {
            mutation_script("deploy", false)
        };
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment: root_environment(payload.skills_root.as_deref()),
            arguments,
        };
        let (result, detail) = self
            .run(&spec, &script, &metadata, operation_deadline)
            .await;
        finish_cli(operations, &operation.id, result, detail, "deploy").await
    }

    async fn undeploy(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: UndeployPayload = payload(operation)?;
        validate_id(&payload.skill_id, "the skill id")?;
        for agent in &payload.agents {
            validate_id(agent, "an agent id")?;
        }
        if let Some(root) = &payload.skills_root {
            validate_root(root)?;
        }
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        // The version gate runs before every mutation.
        let operation_deadline = deadline(payload.timeout_seconds);
        match self.version_gate(&spec, operation_deadline).await {
            GateOutcome::Pass => {}
            GateOutcome::Absent => {
                return complete_failure(
                    operations,
                    &operation.id,
                    "cli_absent",
                    "skills-manager-cli is not installed",
                )
                .await;
            }
            GateOutcome::Unsupported { detail } => {
                return complete_failure(operations, &operation.id, "unsupported_version", &detail)
                    .await;
            }
            GateOutcome::Connection { detail } => {
                return complete_failure(operations, &operation.id, "connection_failed", &detail)
                    .await;
            }
            GateOutcome::Deadline => {
                return complete_failure(
                    operations,
                    &operation.id,
                    "deadline_killed",
                    "the version gate was killed at its deadline; the machine's skill state is unknown",
                )
                .await;
            }
        }
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!(
                    "undeploying {} from {} agent(s){}",
                    payload.skill_id,
                    payload.agents.len(),
                    if payload.dry_run { " (dry run)" } else { "" },
                )),
            )
            .await
            .map_err(|error| error.to_string())?;
        let mut arguments = vec![payload.skill_id.clone()];
        arguments.extend(payload.agents.iter().cloned());
        let script = mutation_script("undeploy", payload.dry_run);
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment: root_environment(payload.skills_root.as_deref()),
            arguments,
        };
        let (result, detail) = self
            .run(&spec, &script, &metadata, operation_deadline)
            .await;
        finish_cli(operations, &operation.id, result, detail, "undeploy").await
    }

    /// The version gate shared by every kind: the CLI must identify
    /// itself in a documented shape with a version at or below the tested
    /// one. A failure names the reason; `None` means the gate passed.
    async fn version_gate(&self, spec: &SshConnectionSpec, deadline: Duration) -> GateOutcome {
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment: Vec::new(),
            arguments: Vec::new(),
        };
        let script = r#"for fleet_candidate in "$HOME/.local/bin/skills-manager-cli" "$(command -v skills-manager-cli 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
if [ -z "${fleet_cli:-}" ]; then
  echo '{"present":false,"reason64":"'$(printf '%s' "skills-manager-cli is not installed" | base64 -w0)'"}'
  exit 0
fi
fleet_version=$("$fleet_cli" --version 2>/dev/null | head -n 1)
printf '{"version64":"%s"}\n' "$(printf '%s' "$fleet_version" | base64 -w0)"
"#
        .to_owned();
        let (result, detail) = self.run(spec, &script, &metadata, deadline).await;
        let Some(result) = result else {
            return GateOutcome::Connection {
                detail: detail.unwrap_or_else(|| "the gate produced no result".to_owned()),
            };
        };
        if result.killed_by_deadline {
            return GateOutcome::Deadline;
        }
        if result.exit_code != Some(0) {
            return GateOutcome::Connection {
                detail: redact_output(&result.stderr),
            };
        }
        // Parse the gate's answer; a malformed answer is an unsupported
        // CLI, not a pass.
        let parsed: Option<serde_json::Value> = result
            .stdout
            .lines()
            .find_map(|line| serde_json::from_str(line).ok());
        let Some(parsed) = parsed else {
            return GateOutcome::Unsupported {
                detail: "the CLI's version gate did not answer in the documented shape".to_owned(),
            };
        };
        if parsed["present"].as_bool() == Some(false) {
            return GateOutcome::Absent;
        }
        // The documented version shapes: the provider's JSON document or
        // the bare `skills-manager-cli <version>` line, both base64'd by
        // the gate script.
        let version = decoded_field(&parsed, "version64");
        let Some(version) = version else {
            return GateOutcome::Unsupported {
                detail: "the CLI did not report a version in the documented shape".to_owned(),
            };
        };
        let Some(version) = parse_version_text(&version) else {
            return GateOutcome::Unsupported {
                detail: "the CLI did not report a version in the documented shape".to_owned(),
            };
        };
        if !version_acceptable(&version) {
            return GateOutcome::Unsupported {
                detail: format!(
                    "the CLI reports {version}, which is outside the tested range (up to {TESTED_CLI_VERSION})"
                ),
            };
        }
        GateOutcome::Pass
    }
}

/// The fixed probe script: presence, version, and the agent listing, as
/// one JSON line with base64 values. An absent CLI reports honestly.
fn probe_script() -> String {
    r#"fleet_b64() { printf '%s' "$1" | base64 -w0; }
# The CLI may live off-PATH (the app publishes it to ~/.local/bin).
for fleet_candidate in "$HOME/.local/bin/skills-manager-cli" "$(command -v skills-manager-cli 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
# $1 is the skills root (empty means the default); FLEET_PIN_URL and
# FLEET_PIN_SHA256 carry an optional pinned release to install when the
# CLI is absent.
fleet_root=$1
if [ -n "$fleet_cli" ]; then
  fleet_version=$("$fleet_cli" --version 2>/dev/null | head -n 1)
  if [ -z "$fleet_version" ]; then
    printf '{"present":false,"reason64":"%s"}\n' "$(fleet_b64 "the binary did not answer --version")"
    exit 0
  fi
  if [ -n "$fleet_root" ]; then
    fleet_agents=$("$fleet_cli" --skills-root "$fleet_root" --json agents list 2>/dev/null | head -c 65536) || {{ fleet_agents=""; fleet_agents_failed=1; }}
  else
    fleet_agents=$("$fleet_cli" --json agents list 2>/dev/null | head -c 65536) || {{ fleet_agents=""; fleet_agents_failed=1; }}
  fi
  if [ "${fleet_agents_failed:-0}" = "1" ]; then
    printf '{"present":true,"version64":"%s","agentsFailed":true}\n' "$(fleet_b64 "$fleet_version")"
    exit 0
  fi
  printf '{"present":true,"version64":"%s","agents64":"%s"}\n' \
    "$(fleet_b64 "$fleet_version")" "$(fleet_b64 "$fleet_agents")"
elif [ -n "${FLEET_PIN_URL:-}" ] && [ -n "${FLEET_PIN_SHA256:-}" ]; then
  # Pinned install: verify the digest before the binary lands anywhere.
  fleet_tmp=$(mktemp)
  curl -fsSL --max-time 120 -o "$fleet_tmp" "$FLEET_PIN_URL" || { rm -f "$fleet_tmp"; printf '{"present":false,"reason64":"%s"}\n' "$(fleet_b64 "the pinned release could not be downloaded")"; exit 0; }
  fleet_digest=$(sha256sum "$fleet_tmp" | awk '{print $1}')
  if [ "$fleet_digest" != "$FLEET_PIN_SHA256" ]; then
    rm -f "$fleet_tmp"
    printf '{"present":false,"reason64":"%s"}\n' "$(fleet_b64 "the pinned release's checksum did not match")"
    exit 0
  fi
  chmod +x "$fleet_tmp"
  mkdir -p "$HOME/.local/bin"
  mv "$fleet_tmp" "$HOME/.local/bin/skills-manager-cli"
  fleet_version=$("$HOME/.local/bin/skills-manager-cli" --version 2>/dev/null | head -n 1)
  printf '{"present":true,"installed":true,"version64":"%s","agents64":""}\n' "$(fleet_b64 "$fleet_version")"
else
  printf '{"present":false,"reason64":"%s"}\n' "$(fleet_b64 "skills-manager-cli is not installed")"
fi
"#
    .to_owned()
}

/// The fixed mutation script: `$1` is the skill id, `$2` onwards the
/// agent ids, each kept as a separate positional parameter so an id with
/// spaces or glob characters stays one argument. `FLEET_SKILLS_ROOT`
/// carries an external root when one is named. `--json` is always passed:
/// the completion path parses the CLI's own contract.
#[must_use]
pub fn mutation_script_for_test(verb: &str, dry_run: bool) -> String {
    mutation_script(verb, dry_run)
}

fn mutation_script(verb: &str, dry_run: bool) -> String {
    let dry_run_line: &str = if dry_run { "fleet_dry=--dry-run\n" } else { "" };
    format!(
        r#"for fleet_candidate in "$HOME/.local/bin/skills-manager-cli" "$(command -v skills-manager-cli 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
[ -n "${{fleet_cli:-}}" ] || {{ echo "skills-manager-cli is not installed" >&2; exit 3; }}
{dry_run_line}fleet_root_arg=""
if [ -n "${{FLEET_SKILLS_ROOT:-}}" ]; then
  fleet_root_arg="--skills-root"
fi
# Each agent becomes its own `--agent <id>` pair. The positional
# parameters are rebuilt in place: $1 (the skill id) is saved, then every
# agent is re-set as `--agent <id>` pairs, so each id stays a single
# argument and nothing expands unquoted.
fleet_skill=$1
shift
fleet_agent_args=()
for fleet_agent in "$@"; do
  fleet_agent_args+=("--agent" "$fleet_agent")
done
fleet_dry_args=()
[ -n "${{fleet_dry:-}}" ] && fleet_dry_args+=(--dry-run)
fleet_verb={verb:?}
case "$fleet_verb" in
  deploy)
    if [ -n "$fleet_root_arg" ]; then
      "$fleet_cli" --skills-root "$FLEET_SKILLS_ROOT" --json skills deploy "$fleet_skill" "${{fleet_agent_args[@]}}" "${{fleet_dry_args[@]}}"
    else
      "$fleet_cli" --json skills deploy "$fleet_skill" "${{fleet_agent_args[@]}}" "${{fleet_dry_args[@]}}"
    fi
    ;;
  undeploy)
    if [ -n "$fleet_root_arg" ]; then
      "$fleet_cli" --skills-root "$FLEET_SKILLS_ROOT" --json skills undeploy "$fleet_skill" "${{fleet_agent_args[@]}}" --yes "${{fleet_dry_args[@]}}"
    else
      "$fleet_cli" --json skills undeploy "$fleet_skill" "${{fleet_agent_args[@]}}" --yes "${{fleet_dry_args[@]}}"
    fi
    ;;
esac
"#
    )
}

/// The skills-root environment: empty means the default library.
fn root_environment(root: Option<&str>) -> Vec<(String, String)> {
    match root {
        Some(root) => vec![("FLEET_SKILLS_ROOT".to_owned(), root.to_owned())],
        None => Vec::new(),
    }
}

/// Parses the documented `--version` shapes: the provider's JSON
/// document, the `skills-manager-cli <version>` line, or a bare semver.
fn parse_version_text(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed)
        && let Some(version) = value["version"].as_str()
        && !version.is_empty()
    {
        return Some(version.to_owned());
    }
    let first = trimmed.lines().next().unwrap_or_default().trim();
    if let Some(version) = first.strip_prefix("skills-manager-cli ") {
        return Some(version.to_owned());
    }
    let parts: Vec<&str> = first.split('.').collect();
    if (2..=3).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    {
        return Some(first.to_owned());
    }
    None
}

/// Whether the CLI's reported version is within the tested range: same
/// major and a minor at or below the tested minor, or an older one.
fn version_acceptable(version: &str) -> bool {
    let (tested_major, tested_minor) =
        TESTED_CLI_VERSION
            .split_once('.')
            .map_or((1, 34), |(major, minor)| {
                (
                    major.parse::<u64>().unwrap_or(0),
                    minor
                        .split('.')
                        .next()
                        .and_then(|minor| minor.parse::<u64>().ok())
                        .unwrap_or(0),
                )
            });
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let Ok(major) = parts[0].parse::<u64>() else {
        return false;
    };
    let Ok(minor) = parts[1]
        .split(['-', '+'])
        .next()
        .unwrap_or(parts[1])
        .parse::<u64>()
    else {
        return false;
    };
    major < tested_major || (major == tested_major && minor <= tested_minor)
}

/// Decodes one base64 field from a probe JSON line.
fn decoded_field(line: &serde_json::Value, key: &str) -> Option<String> {
    use base64::Engine as _;
    let raw = line[key].as_str()?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())?;
    Some(decoded).filter(|decoded| !decoded.is_empty())
}

/// Validates an identifier: bounded, no control characters, no leading
/// dash (so it can never be mistaken for an option).
fn validate_id(id: &str, what: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 255 {
        return Err(format!("{what} must be 1..=255 characters"));
    }
    if id.starts_with('-') {
        return Err(format!("{what} must not start with a dash"));
    }
    if id.chars().any(char::is_control) {
        return Err(format!("{what} must not contain control characters"));
    }
    Ok(())
}

/// Validates an absolute skills root: absolute-shaped, bounded, no `..`
/// segment, no control characters.
fn validate_root(root: &str) -> Result<(), String> {
    if !root.starts_with('/') || root.len() > 400 {
        return Err(
            "the skills root must be an absolute path of at most 400 characters".to_owned(),
        );
    }
    if root.split('/').any(|segment| segment == "..") {
        return Err("the skills root must not contain a `..` segment".to_owned());
    }
    if root.chars().any(char::is_control) {
        return Err("the skills root must not contain control characters".to_owned());
    }
    Ok(())
}

/// The deadline clamp shared by every skills kind.
fn deadline(seconds: u64) -> Duration {
    Duration::from_secs(seconds.min(MAX_SKILLS_TIMEOUT))
}

/// Decodes and validates an operation's payload.
fn payload<T: serde::de::DeserializeOwned>(operation: &Operation) -> Result<T, String> {
    serde_json::from_str(
        operation
            .payload_json
            .as_deref()
            .ok_or("the operation carries no payload")?,
    )
    .map_err(|error| format!("the payload is not a valid skills record: {error}"))
}

/// Completes an operation as a failure with a redacted detail.
async fn complete_failure(
    operations: &Operations,
    operation_id: &str,
    reason: &str,
    detail: &str,
) -> Result<(), String> {
    let error_json = serde_json::json!({ "reason": reason, "detail": detail }).to_string();
    operations
        .complete(operation_id, "failed", None, Some(&error_json))
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Finishes a deploy or undeploy from the execution outcome.
async fn finish_cli(
    operations: &Operations,
    operation_id: &str,
    result: Option<fleet_provider_ssh::ExecutionResult>,
    detail: Option<String>,
    what: &str,
) -> Result<(), String> {
    match (result, detail) {
        (Some(result), _) if result.killed_by_deadline => {
            complete_failure(
                operations,
                operation_id,
                "deadline_killed",
                &format!(
                    "the {what} was killed at its deadline; the machine's skill state is unknown"
                ),
            )
            .await
        }
        (Some(result), _) if result.exit_code == Some(0) => {
            let parsed: Option<serde_json::Value> = result
                .stdout
                .lines()
                .find_map(|line| serde_json::from_str(line).ok());
            let result_json = serde_json::json!({ "outcome": parsed }).to_string();
            operations
                .complete(operation_id, "succeeded", Some(&result_json), None)
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
        (Some(result), _) => {
            complete_failure(
                operations,
                operation_id,
                "cli_failed",
                &redact_output(&result.stderr),
            )
            .await
        }
        (None, Some(detail)) => {
            complete_failure(operations, operation_id, "connection_failed", &detail).await
        }
        (None, None) => Err(format!("the {what} produced neither a result nor a detail")),
    }
}

/// Redacts credential-shaped userinfo and control noise from CLI output
/// before it becomes a public result.
fn redact_output(text: &str) -> String {
    let trimmed = text.trim();
    let bounded = if trimmed.len() > 3_000 {
        let mut end = 3_000;
        while !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        &trimmed[..end]
    } else {
        trimmed
    };
    fleet_provider_skills_manager::redact(bounded)
}

/// The kind-dispatching wrapper the controller composes: the skills kinds
/// route to the [`SkillsExecutor`], everything else falls through to the
/// rest of the chain unchanged.
#[derive(Debug)]
pub struct SkillsDispatch {
    fallback: Arc<dyn OperationExecutor>,
    skills: Arc<dyn OperationExecutor>,
}

impl SkillsDispatch {
    /// Composes the dispatch from the fallback chain and the skills
    /// executor.
    #[must_use]
    pub fn new(fallback: Arc<dyn OperationExecutor>, skills: Arc<dyn OperationExecutor>) -> Self {
        Self { fallback, skills }
    }
}

#[async_trait::async_trait]
impl OperationExecutor for SkillsDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "skills.probe" | "skills.deploy" | "skills.undeploy" => {
                self.skills.execute(operations, operation).await
            }
            _ => self.fallback.execute(operations, operation).await,
        }
    }
}
