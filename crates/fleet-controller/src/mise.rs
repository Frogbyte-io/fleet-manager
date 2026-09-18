//! The mise executor (FM-304): tool inventory, status, install, and
//! project-task exec, over the bounded SSH transport.
//!
//! Fleet observes what `mise` itself reports and optionally drives
//! install/exec through its documented CLI. It never reads or translates
//! `.mise.toml`/`mise.toml` into a second tool-version model: the project
//! files stay authoritative, and the executor's scripts never touch them.
//!
//! The CLI's name is fixed, and every caller-controlled value — tool
//! names, versions, a checkout root, a command array — rides the base64
//! metadata blob as positional arguments, never through a remote shell.
//! Install is idempotent by the CLI's own contract (installing an
//! installed version is a success) and uses pinned versions; a version is
//! validated locally before it can reach the CLI. Exec passes the command
//! array to `mise exec --` verbatim.

use std::sync::Arc;
use std::time::Duration;

use fleet_application::machine::MachinePort;
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_provider_ssh::{ExecutionLimiter, ScriptMetadata, SshConnectionSpec};

use crate::exec::MAX_SCRIPT_TIMEOUT;

/// The deadline bound for one mise operation.
pub const MAX_MISE_TIMEOUT: u64 = MAX_SCRIPT_TIMEOUT;

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

/// The shared shape of every mise payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MisePayload {
    /// The machine carrying the CLI.
    machine_id: String,
    /// The endpoint id to act through.
    endpoint_id: String,
    /// How the endpoint authenticates.
    auth: Auth,
    /// The deadline, in seconds.
    timeout_seconds: u64,
}

/// The `mise.status` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatusPayload {
    machine_id: String,
    endpoint_id: String,
    auth: Auth,
    timeout_seconds: u64,
}

/// The `mise.install` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstallPayload {
    machine_id: String,
    endpoint_id: String,
    auth: Auth,
    /// The tool to install, e.g. `node`.
    tool: String,
    /// The pinned version to install, e.g. `20.11.0`.
    version: String,
    timeout_seconds: u64,
}

/// The `mise.exec` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecPayload {
    machine_id: String,
    endpoint_id: String,
    auth: Auth,
    /// The checkout root whose mise configuration binds the command.
    root: String,
    /// The command to run, as an argument array. Never a shell string.
    command: Vec<String>,
    timeout_seconds: u64,
}

/// The kind-dispatching mise executor.
#[derive(Debug)]
pub struct MiseExecutor {
    machines: Arc<dyn MachinePort>,
    provider: fleet_provider_ssh::SshProvider,
    limiter: Arc<ExecutionLimiter>,
    /// Retained for the provider's isolated directory lifetime.
    #[allow(dead_code)]
    work_dir: std::path::PathBuf,
}

impl MiseExecutor {
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

    /// Runs one script; the third element distinguishes a thread/join
    /// failure from a connection failure, which are different diagnostic
    /// paths.
    async fn run(
        &self,
        spec: &SshConnectionSpec,
        script: &str,
        metadata: &ScriptMetadata,
        deadline: Duration,
    ) -> (
        Option<fleet_provider_ssh::ExecutionResult>,
        Option<String>,
        Option<String>,
    ) {
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
                    None,
                    Some(format!("the execution thread failed: {join_error}")),
                )
            },
            |outcome| match outcome {
                Ok(result) => (Some(result), None, None),
                Err(error) => (None, Some(error.to_string()), None),
            },
        )
    }
}

#[async_trait::async_trait]
impl OperationExecutor for MiseExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "tools.inventory" => self.inventory(operations, operation).await,
            "mise.status" => self.status(operations, operation).await,
            "mise.install" => self.install(operations, operation).await,
            "mise.exec" => self.exec(operations, operation).await,
            _ => Err("not a mise kind".to_owned()),
        }
    }
}

impl MiseExecutor {
    async fn inventory(
        &self,
        operations: &Operations,
        operation: &Operation,
    ) -> Result<(), String> {
        let payload: MisePayload = payload(operation)?;
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        operations
            .record_progress(&operation.id, Some(0), Some(1), Some("probing tools"))
            .await
            .map_err(|error| error.to_string())?;
        let deadline = deadline(payload.timeout_seconds);
        let metadata = ScriptMetadata::default();
        let (result, detail, thread_failure) = self
            .run(&spec, &inventory_script(), &metadata, deadline)
            .await;
        finish_json(
            operations,
            &operation.id,
            result,
            detail,
            thread_failure,
            "inventory",
            "tools",
        )
        .await
    }

    async fn status(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: StatusPayload = payload(operation)?;
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        operations
            .record_progress(&operation.id, Some(0), Some(1), Some("reading mise status"))
            .await
            .map_err(|error| error.to_string())?;
        let deadline = deadline(payload.timeout_seconds);
        let metadata = ScriptMetadata::default();
        let (result, detail, thread_failure) =
            self.run(&spec, &status_script(), &metadata, deadline).await;
        finish_json(
            operations,
            &operation.id,
            result,
            detail,
            thread_failure,
            "mise status",
            "mise",
        )
        .await
    }

    async fn install(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: InstallPayload = payload(operation)?;
        validate_id(&payload.tool, "the tool name")?;
        validate_version(&payload.version)?;
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!("installing {}@{}", payload.tool, payload.version)),
            )
            .await
            .map_err(|error| error.to_string())?;
        let deadline = deadline(payload.timeout_seconds);
        // The tool and version ride the metadata argument array; the
        // fixed script passes them as separate positionals. Install is
        // idempotent by the CLI's own contract.
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment: Vec::new(),
            arguments: vec![payload.tool, payload.version],
        };
        let (result, detail, thread_failure) = self
            .run(&spec, &install_script(), &metadata, deadline)
            .await;
        finish_cli(
            operations,
            &operation.id,
            result,
            detail,
            thread_failure,
            "mise install",
        )
        .await
    }

    async fn exec(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: ExecPayload = payload(operation)?;
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
        // and passes each command argument to `mise exec --` verbatim.
        let mut arguments = vec![payload.root];
        arguments.extend(payload.command);
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment: Vec::new(),
            arguments,
        };
        let (result, detail, thread_failure) =
            self.run(&spec, &exec_script(), &metadata, deadline).await;
        finish_cli(
            operations,
            &operation.id,
            result,
            detail,
            thread_failure,
            "mise exec",
        )
        .await
    }
}

/// The fixed inventory script: tool presence and versions as one JSON
/// line with base64 values, honest gaps for absent tools.
fn inventory_script() -> String {
    r#"fleet_b64() { printf '%s' "$1" | base64 -w0; }
fleet_tool() {
  if command -v "$1" >/dev/null 2>&1; then
    fleet_version=$("$1" --version 2>/dev/null | head -n 1)
    printf '{"name64":"%s","version64":"%s","present":true},' \
      "$(fleet_b64 "$1")" "$(fleet_b64 "$fleet_version")"
  else
    printf '{"name64":"%s","present":false},' "$(fleet_b64 "$1")"
  fi
}
fleet_entries=""
for fleet_name in git docker tailscale claude codex gemini cursor-agent; do
  fleet_entries="$fleet_entries$(fleet_tool "$fleet_name")"
done
# The last entry's trailing comma is stripped to close the array.
printf '%s\n' "[$(printf '%s' "$fleet_entries" | sed 's/,$//')]"
"#
    .to_owned()
}

/// The fixed status script: the documented `mise ls --json` surface.
fn status_script() -> String {
    r#"for fleet_candidate in "$HOME/.local/bin/mise" "$(command -v mise 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
[ -n "${fleet_cli:-}" ] || { echo "mise is not installed" >&2; exit 3; }
"$fleet_cli" ls --json
"#
    .to_owned()
}

/// The fixed install script: `$1` is the tool, `$2` the pinned version.
/// Idempotent by the CLI's own contract.
fn install_script() -> String {
    r#"for fleet_candidate in "$HOME/.local/bin/mise" "$(command -v mise 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
[ -n "${fleet_cli:-}" ] || { echo "mise is not installed" >&2; exit 3; }
"$fleet_cli" install "$1@$2"
"#
    .to_owned()
}

/// The fixed exec script: `$1` is the checkout root (consumed as a quoted
/// positional parameter), `$2` onwards is the command passed to
/// `mise exec --` verbatim.
fn exec_script() -> String {
    r#"for fleet_candidate in "$HOME/.local/bin/mise" "$(command -v mise 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
[ -n "${fleet_cli:-}" ] || { echo "mise is not installed" >&2; exit 3; }
fleet_root=$1
shift
cd "$fleet_root" || { echo "the checkout root is not a directory" >&2; exit 4; }
"$fleet_cli" exec -- "$@"
"#
    .to_owned()
}

/// Validates a tool name: bounded, no control characters, no leading
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

/// Validates a pinned version: bounded, no control characters, no
/// leading dash.
fn validate_version(version: &str) -> Result<(), String> {
    if version.is_empty() || version.len() > 64 {
        return Err("the version must be 1..=64 characters".to_owned());
    }
    if version.starts_with('-') {
        return Err("the version must not start with a dash".to_owned());
    }
    if version.chars().any(char::is_control) {
        return Err("the version must not contain control characters".to_owned());
    }
    Ok(())
}

/// Validates an absolute checkout root: absolute-shaped, bounded, no `..`
/// segment, no control characters.
fn validate_root(root: &str) -> Result<(), String> {
    if !root.starts_with('/') || root.chars().count() > 400 {
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

/// The deadline clamp shared by every mise kind.
fn deadline(seconds: u64) -> Duration {
    Duration::from_secs(seconds.min(MAX_MISE_TIMEOUT))
}

/// Decodes and validates an operation's payload.
fn payload<T: serde::de::DeserializeOwned>(operation: &Operation) -> Result<T, String> {
    serde_json::from_str(
        operation
            .payload_json
            .as_deref()
            .ok_or("the operation carries no payload")?,
    )
    .map_err(|error| format!("the payload is not a valid mise record: {error}"))
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

/// Finishes a JSON-surface kind from the execution outcome: the parsed
/// document is the public result, a non-conforming answer is
/// `unsupported_version`.
async fn finish_json(
    operations: &Operations,
    operation_id: &str,
    result: Option<fleet_provider_ssh::ExecutionResult>,
    detail: Option<String>,
    thread_failure: Option<String>,
    what: &str,
    field: &str,
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
            let parsed: Option<serde_json::Value> = result
                .stdout
                .lines()
                .find_map(|line| serde_json::from_str(line).ok());
            let Some(parsed) = parsed else {
                return complete_failure(
                    operations,
                    operation_id,
                    "unsupported_version",
                    &format!("the {what} output is not in the documented shape; the CLI version is untested"),
                )
                .await;
            };
            let result_json = serde_json::json!({ field: parsed }).to_string();
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
        (None, None) => match thread_failure {
            Some(detail) => complete_failure(operations, operation_id, "internal", &detail).await,
            None => Err(format!("the {what} produced neither a result nor a detail")),
        },
    }
}

/// Finishes an install or exec from the execution outcome.
async fn finish_cli(
    operations: &Operations,
    operation_id: &str,
    result: Option<fleet_provider_ssh::ExecutionResult>,
    detail: Option<String>,
    thread_failure: Option<String>,
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
        (None, None) => match thread_failure {
            Some(detail) => complete_failure(operations, operation_id, "internal", &detail).await,
            None => Err(format!("the {what} produced neither a result nor a detail")),
        },
    }
}

/// Redacts credential-shaped userinfo from CLI output before it becomes a
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
    fleet_provider_mise::redact(bounded)
}

/// The kind-dispatching wrapper the controller composes: the mise kinds
/// route to the [`MiseExecutor`], everything else falls through to the
/// rest of the chain unchanged.
#[derive(Debug)]
pub struct MiseDispatch {
    fallback: Arc<dyn OperationExecutor>,
    mise: Arc<dyn OperationExecutor>,
}

impl MiseDispatch {
    /// Composes the dispatch from the fallback chain and the mise
    /// executor.
    #[must_use]
    pub fn new(fallback: Arc<dyn OperationExecutor>, mise: Arc<dyn OperationExecutor>) -> Self {
        Self { fallback, mise }
    }
}

#[async_trait::async_trait]
impl OperationExecutor for MiseDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "tools.inventory" | "mise.status" | "mise.install" | "mise.exec" => {
                self.mise.execute(operations, operation).await
            }
            _ => self.fallback.execute(operations, operation).await,
        }
    }
}
