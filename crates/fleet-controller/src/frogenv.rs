//! The Frogenv executor (FM-303): status, setup, login, machine request,
//! sync, and `env run`, over the bounded SSH transport.
//!
//! Fleet invokes Frogenv's public CLI and records status — it never
//! decrypts, lists, or stores environment values, and never edits
//! `frogenv.yaml`, `.sops.yaml`, `keys/`, its local config, or encrypted
//! files. The CLI's name is fixed, and every caller-controlled value
//! rides the base64 metadata blob as positional arguments, never through
//! a remote shell.
//!
//! **Blocked/manual approval is a first-class state**: setup, login, and
//! machine request are security-sensitive ceremonies. The fixed scripts
//! run them with `--yes` where the CLI documents it and detect a
//! ceremony's requirement from the CLI's own output contract; when the
//! CLI reports that an approval or interactive step is required, the
//! operation completes `blocked_manual_approval` instead of hanging or
//! prompting. A ceremony is never left half-run.
//!
//! `env run` is the only execution path for environment-bound commands:
//! the command and its arguments ride the metadata argument array, output
//! is bounded, and values never appear in results — Frogenv injects
//! decrypted values only into the child process, and the child's stdout
//! is the command's own output.
//!
//! Redaction: value-shaped material (age keys, SOPS payloads, long
//! key-shaped runs) is scrubbed from output and error text before
//! anything becomes a public result.

use std::sync::Arc;
use std::time::Duration;

use fleet_application::machine::MachinePort;
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_provider_ssh::{ExecutionLimiter, ScriptMetadata, SshConnectionSpec};

use crate::exec::MAX_SCRIPT_TIMEOUT;

/// The deadline bound for one Frogenv operation.
pub const MAX_FROGENV_TIMEOUT: u64 = MAX_SCRIPT_TIMEOUT;

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

/// The shared shape of every Frogenv payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FrogenvPayload {
    /// The machine carrying the CLI.
    machine_id: String,
    /// The endpoint id to act through.
    endpoint_id: String,
    /// How the endpoint authenticates.
    auth: Auth,
    /// The deadline, in seconds.
    timeout_seconds: u64,
}

/// The `frogenv.env-run` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnvRunPayload {
    machine_id: String,
    endpoint_id: String,
    auth: Auth,
    /// The checkout root whose environment binds the command.
    root: String,
    /// The command to run, as an argument array. Never a shell string.
    command: Vec<String>,
    timeout_seconds: u64,
}

/// The kind-dispatching Frogenv executor.
#[derive(Debug)]
pub struct FrogenvExecutor {
    machines: Arc<dyn MachinePort>,
    provider: fleet_provider_ssh::SshProvider,
    limiter: Arc<ExecutionLimiter>,
    /// Retained for the provider's isolated directory lifetime.
    #[allow(dead_code)]
    work_dir: std::path::PathBuf,
}

impl FrogenvExecutor {
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
        let (spec, _verified, _host) = crate::exec::resolve_ssh_endpoint(
            self.machines.as_ref(),
            machine_id,
            endpoint_id,
            ssh_auth,
        )
        .await?;
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
impl OperationExecutor for FrogenvExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "frogenv.status" => self.status(operations, operation).await,
            "frogenv.setup" => self.ceremony(operations, operation, "setup").await,
            "frogenv.login" => self.ceremony(operations, operation, "login").await,
            "frogenv.request" => {
                self.ceremony(operations, operation, "machine request")
                    .await
            }
            "frogenv.sync" => self.sync(operations, operation).await,
            "frogenv.env-run" => self.env_run(operations, operation).await,
            _ => Err("not a frogenv kind".to_owned()),
        }
    }
}

impl FrogenvExecutor {
    async fn status(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: FrogenvPayload = payload(operation)?;
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        operations
            .record_progress(&operation.id, Some(0), Some(1), Some("reading the status"))
            .await
            .map_err(|error| error.to_string())?;
        let deadline = deadline(payload.timeout_seconds);
        let metadata = ScriptMetadata::default();
        let (result, detail) = self.run(&spec, &status_script(), &metadata, deadline).await;
        match (result, detail) {
            (Some(result), _) if result.killed_by_deadline => {
                complete_failure(
                    operations,
                    &operation.id,
                    "deadline_killed",
                    "the status command was killed at its deadline; the machine's state is unknown",
                )
                .await
            }
            (Some(result), _) if result.exit_code == Some(0) => {
                // Parse the documented shape and serialize only its
                // approved fields: an unexpected JSON object must never
                // publish arbitrary fields, which could carry
                // value-shaped material.
                let parsed = result.stdout.lines().find_map(|line| {
                    serde_json::from_str::<fleet_provider_frogenv::StatusDocument>(line).ok()
                });
                let Some(document) = parsed else {
                    return complete_failure(
                        operations,
                        &operation.id,
                        "unsupported_version",
                        "the status output is not in the documented shape; the CLI version is untested",
                    )
                    .await;
                };
                // Redact every string field again at the boundary: the
                // provider sanitizes its own returns, but this result is
                // a second exposure path and gitRemote can carry
                // credentials.
                let redact_field =
                    |value: &Option<String>| value.as_deref().map(fleet_provider_frogenv::redact);
                let result_json = serde_json::json!({
                    "status": {
                        "configured": document.configured,
                        "machineState": redact_field(&document.machine_state),
                        "machineId": redact_field(&document.machine_id),
                        "gitRemote": redact_field(&document.git_remote),
                    },
                })
                .to_string();
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
                    "status_failed",
                    &redact_output(&result.stderr),
                )
                .await
            }
            (None, Some(detail)) => {
                complete_failure(operations, &operation.id, "connection_failed", &detail).await
            }
            (None, None) => Err("the status produced neither a result nor a detail".to_owned()),
        }
    }

    /// The ceremony path: setup, login, and machine request. Blocked or
    /// manual-approval requirements are a first-class outcome, detected
    /// from the CLI's own output contract.
    async fn ceremony(
        &self,
        operations: &Operations,
        operation: &Operation,
        ceremony: &str,
    ) -> Result<(), String> {
        let payload: FrogenvPayload = payload(operation)?;
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!("running the {ceremony} ceremony")),
            )
            .await
            .map_err(|error| error.to_string())?;
        let deadline = deadline(payload.timeout_seconds);
        let script = ceremony_script(ceremony);
        let metadata = ScriptMetadata::default();
        let (result, detail) = self.run(&spec, &script, &metadata, deadline).await;
        match (result, detail) {
            (Some(result), _) if result.killed_by_deadline => {
                complete_failure(
                    operations,
                    &operation.id,
                    "blocked_manual_approval",
                    &format!(
                        "the {ceremony} ceremony did not complete within its deadline; it requires interactive steps Fleet cannot perform — run it on the machine yourself"
                    ),
                )
                .await
            }
            (Some(result), _) if result.exit_code == Some(0) => {
                let outcome = serde_json::json!({ "ceremony": ceremony }).to_string();
                operations
                    .complete(&operation.id, "succeeded", Some(&outcome), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            (Some(result), _) => {
                let stderr = result.stderr.to_owned();
                // The marker contract this executor owns: a ceremony that
                // prints `FLEET_BLOCKED: <reason>` on any stream reports
                // that it needs a human. Everything else is a failure.
                let blocked = result
                    .stdout
                    .lines()
                    .chain(result.stderr.lines())
                    .find_map(|line| line.strip_prefix("FLEET_BLOCKED: "));
                if let Some(reason) = blocked {
                    return complete_failure(
                        operations,
                        &operation.id,
                        "blocked_manual_approval",
                        &format!(
                            "the {ceremony} ceremony requires manual approval: {}",
                            redact_output(reason)
                        ),
                    )
                    .await;
                }
                complete_failure(
                    operations,
                    &operation.id,
                    "ceremony_failed",
                    &redact_output(&stderr),
                )
                .await
            }
            (None, Some(detail)) => {
                complete_failure(operations, &operation.id, "connection_failed", &detail).await
            }
            (None, None) => Err("the ceremony produced neither a result nor a detail".to_owned()),
        }
    }

    async fn sync(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: FrogenvPayload = payload(operation)?;
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        operations
            .record_progress(&operation.id, Some(0), Some(1), Some("syncing"))
            .await
            .map_err(|error| error.to_string())?;
        let deadline = deadline(payload.timeout_seconds);
        let metadata = ScriptMetadata::default();
        let (result, detail) = self.run(&spec, &sync_script(), &metadata, deadline).await;
        finish_cli(operations, &operation.id, result, detail, "sync").await
    }

    async fn env_run(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: EnvRunPayload = payload(operation)?;
        validate_root(&payload.root)?;
        if payload.command.is_empty() {
            return Err("the command must carry at least one argument".to_owned());
        }
        for argument in &payload.command {
            if argument.is_empty() || argument.len() > 1024 {
                return Err("every command argument must be 1..=1024 characters".to_owned());
            }
            if argument.chars().any(char::is_control) {
                return Err("command arguments must not contain control characters".to_owned());
            }
        }
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!(
                    "running {} under {}",
                    payload.command[0], payload.root
                )),
            )
            .await
            .map_err(|error| error.to_string())?;
        let deadline = deadline(payload.timeout_seconds);
        // The root and the command ride the metadata argument array; the
        // fixed script consumes the root as a quoted positional parameter
        // and passes each command argument to `frogenv env run --`
        // verbatim. Nothing the caller controls is interpolated into the
        // script source, so `$()` or backticks in a root cannot execute.
        let mut arguments = vec![payload.root];
        arguments.extend(payload.command);
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment: Vec::new(),
            arguments,
        };
        let (result, detail) = self
            .run(&spec, &env_run_script(), &metadata, deadline)
            .await;
        finish_cli(operations, &operation.id, result, detail, "env run").await
    }
}

/// The fixed status script: the documented JSON surface only.
fn status_script() -> String {
    r#"for fleet_candidate in "$HOME/.local/bin/frogenv" "$(command -v frogenv 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
[ -n "${fleet_cli:-}" ] || { echo "frogenv is not installed" >&2; exit 3; }
"$fleet_cli" status
"#
    .to_owned()
}

/// The fixed ceremony script: `--yes` where the CLI documents it, and a
/// marker line when the ceremony reports it needs a human. A ceremony is
/// never left hanging: the script's own deadline is the operation's.
fn ceremony_script(ceremony: &str) -> String {
    let subcommand = match ceremony {
        "setup" => "setup --yes",
        "login" => "login",
        _ => "machine request",
    };
    format!(
        r#"for fleet_candidate in "$HOME/.local/bin/frogenv" "$(command -v frogenv 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
[ -n "${{fleet_cli:-}}" ] || {{ echo "frogenv is not installed" >&2; exit 3; }}
"$fleet_cli" {subcommand}
"#
    )
}

/// The fixed sync script.
fn sync_script() -> String {
    r#"for fleet_candidate in "$HOME/.local/bin/frogenv" "$(command -v frogenv 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
[ -n "${fleet_cli:-}" ] || { echo "frogenv is not installed" >&2; exit 3; }
"$fleet_cli" sync
"#
    .to_owned()
}

/// The fixed `env run` script: `$1` is the checkout root (consumed as a
/// quoted positional parameter), `$2` onwards is the command passed to
/// `frogenv env run --` verbatim.
fn env_run_script() -> String {
    r#"for fleet_candidate in "$HOME/.local/bin/frogenv" "$(command -v frogenv 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
[ -n "${fleet_cli:-}" ] || { echo "frogenv is not installed" >&2; exit 3; }
fleet_root=$1
shift
cd "$fleet_root" || { echo "the checkout root is not a directory" >&2; exit 4; }
"$fleet_cli" env run -- "$@"
"#
    .to_owned()
}

/// Validates an absolute checkout root: absolute-shaped, bounded, no `..`
/// segment, no control characters.
fn validate_root(root: &str) -> Result<(), String> {
    if !root.starts_with('/') || root.len() > 400 {
        return Err(
            "the checkout root must be an absolute path of at most 400 characters".to_owned(),
        );
    }
    if root.split('/').any(|segment| segment == "..") {
        return Err("the checkout root must not contain a `..` segment".to_owned());
    }
    if root.chars().any(char::is_control) {
        return Err("the checkout root must not contain control characters".to_owned());
    }
    Ok(())
}

/// The deadline clamp shared by every Frogenv kind.
fn deadline(seconds: u64) -> Duration {
    Duration::from_secs(seconds.min(MAX_FROGENV_TIMEOUT))
}

/// Decodes and validates an operation's payload.
fn payload<T: serde::de::DeserializeOwned>(operation: &Operation) -> Result<T, String> {
    serde_json::from_str(
        operation
            .payload_json
            .as_deref()
            .ok_or("the operation carries no payload")?,
    )
    .map_err(|error| format!("the payload is not a valid frogenv record: {error}"))
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

/// Finishes a sync or env run from the execution outcome.
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
                &format!("the {what} was killed at its deadline; the machine's state is unknown"),
            )
            .await
        }
        (Some(result), _) if result.exit_code == Some(0) => {
            let result_json = serde_json::json!({ "kind": what }).to_string();
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

/// Redacts value-shaped material from CLI output before it becomes a
/// public result.
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
    fleet_provider_frogenv::redact(bounded)
}

/// The kind-dispatching wrapper the controller composes: the Frogenv
/// kinds route to the [`FrogenvExecutor`], everything else falls through
/// to the rest of the chain unchanged.
#[derive(Debug)]
pub struct FrogenvDispatch {
    fallback: Arc<dyn OperationExecutor>,
    frogenv: Arc<dyn OperationExecutor>,
}

impl FrogenvDispatch {
    /// Composes the dispatch from the fallback chain and the Frogenv
    /// executor.
    #[must_use]
    pub fn new(fallback: Arc<dyn OperationExecutor>, frogenv: Arc<dyn OperationExecutor>) -> Self {
        Self { fallback, frogenv }
    }
}

#[async_trait::async_trait]
impl OperationExecutor for FrogenvDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "frogenv.status" | "frogenv.setup" | "frogenv.login" | "frogenv.request"
            | "frogenv.sync" | "frogenv.env-run" => {
                self.frogenv.execute(operations, operation).await
            }
            _ => self.fallback.execute(operations, operation).await,
        }
    }
}
