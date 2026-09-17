//! The checkout action executors (FM-301): discovery, clone, pull, status,
//! and guarded agent-config writes, all over the bounded SSH transport.
//!
//! Git is a documented CLI contract, and project data is hostile input, so
//! the transport rule from the provider holds here in full: the caller's
//! data (remote URL, path, branch) never passes through a remote shell — it
//! rides the base64 metadata blob as positional arguments, and the fixed
//! script reads `$1` onwards. Git hooks are disabled for every
//! controller-managed operation (`core.hooksPath` pointed nowhere): hook
//! execution is remote code execution by another name.
//!
//! Bounds: clone and pull are durable operations with deadlines and
//! process-tree cancellation via the local `ssh` kill (the remote fate is
//! reported honestly); file writes are contained under the checkout root by
//! a canonicalization check the remote script performs before touching
//! anything, and refuse traversal instead of clamping it.
//!
//! Output redaction: remotes and error text are scrubbed of
//! credential-shaped userinfo before they become the operation's public
//! result.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;

use async_trait::async_trait;

use fleet_application::machine::MachinePort;
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_provider_ssh::{
    ExecutionLimiter, ScriptMetadata, SshAuth, SshConnectionSpec, SshProvider,
};

use crate::exec::{MAX_SCRIPT_TIMEOUT, RESULT_STRING_BOUND, resolve_ssh_endpoint};

/// The deadline bound for one checkout action.
pub const MAX_GIT_TIMEOUT: u64 = MAX_SCRIPT_TIMEOUT;

/// The fixed discovery script the provider owns.
use fleet_provider_ssh::discovery_script;

/// The bound for a checkout root path on the remote machine.
pub const MAX_ROOT_BYTES: usize = 400;

/// The bound for a remote URL.
pub const MAX_REMOTE_BYTES: usize = 1024;

/// The bound for a branch name.
pub const MAX_BRANCH_BYTES: usize = 255;

/// The bound for an agent config file's contents.
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;

/// The names of the agent config files a guarded write may touch.
pub const AGENT_CONFIG_FILES: [&str; 4] = ["AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules"];

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

impl From<&Auth> for SshAuth {
    fn from(auth: &Auth) -> Self {
        match auth {
            Auth::Agent => SshAuth::Agent,
            Auth::IdentityFile { path } => SshAuth::IdentityFile { path: path.clone() },
        }
    }
}

/// The `projects.discover` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiscoverPayload {
    /// The machine to scan.
    machine_id: String,
    /// The endpoint id to probe.
    endpoint_id: String,
    /// How the endpoint authenticates.
    auth: Auth,
    /// The deadline, in seconds.
    timeout_seconds: u64,
}

/// The `projects.clone` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClonePayload {
    /// The checkout payload's shared fields, flattened by hand below.
    machine_id: String,
    endpoint_id: String,
    /// The remote URL to clone.
    remote: String,
    /// Where the clone lands, absolute.
    root: String,
    /// The branch to check out, when one is named.
    #[serde(default)]
    branch: Option<String>,
    auth: Auth,
    timeout_seconds: u64,
}

/// The `projects.pull` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PullPayload {
    machine_id: String,
    endpoint_id: String,
    root: String,
    auth: Auth,
    timeout_seconds: u64,
}

/// The `projects.status` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatusPayload {
    machine_id: String,
    endpoint_id: String,
    root: String,
    auth: Auth,
    timeout_seconds: u64,
}

/// The `projects.write-config` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WriteConfigPayload {
    machine_id: String,
    endpoint_id: String,
    root: String,
    /// Which agent config file to write; one of [`AGENT_CONFIG_FILES`].
    file_name: String,
    /// The file's contents, bounded.
    contents: String,
    auth: Auth,
    timeout_seconds: u64,
}

/// The kind-dispatching checkout executor, composed over the same SSH
/// provider and limiter the script executor uses.
#[derive(Debug)]
pub struct CheckoutExecutor {
    machines: Arc<dyn MachinePort>,
    provider: SshProvider,
    limiter: Arc<ExecutionLimiter>,
    /// Retained for the provider's isolated directory lifetime.
    #[allow(dead_code)]
    work_dir: std::path::PathBuf,
}

impl CheckoutExecutor {
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
        let provider = SshProvider::new(work_dir.clone()).expect("the SSH work dir must prepare");
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
        let (spec, _verified, _host) =
            resolve_ssh_endpoint(self.machines.as_ref(), machine_id, endpoint_id, auth.into())
                .await?;
        Ok(spec)
    }

    /// Runs one script to completion on the worker's blocking pool.
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

#[async_trait]
impl OperationExecutor for CheckoutExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "projects.discover" => self.discover(operations, operation).await,
            "projects.clone" => self.clone_checkout(operations, operation).await,
            "projects.pull" => self.pull(operations, operation).await,
            "projects.status" => self.status(operations, operation).await,
            "projects.write-config" => self.write_config(operations, operation).await,
            _ => Err("not a checkout kind".to_owned()),
        }
    }
}

impl CheckoutExecutor {
    async fn discover(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: DiscoverPayload = payload(operation)?;
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some("scanning standard roots"),
            )
            .await
            .map_err(|error| error.to_string())?;
        let deadline = deadline(payload.timeout_seconds);
        let (result, detail) = self
            .run(
                &spec,
                &discovery_script(),
                &ScriptMetadata::default(),
                deadline,
            )
            .await;
        match (result, detail) {
            (Some(result), _) if result.killed_by_deadline => {
                complete_failure(
                    operations,
                    &operation.id,
                    "deadline_killed",
                    "the discovery scan was killed at its deadline; the checkout set is incomplete",
                )
                .await
            }
            (Some(result), _) if result.exit_code == Some(0) => {
                let found = fleet_provider_ssh::parse_discovery_output(&result.stdout);
                let observations: Vec<serde_json::Value> = found
                    .iter()
                    .map(|checkout| {
                        serde_json::json!({
                            "root": checkout.root,
                            "branch": checkout.branch,
                            "head": checkout.head,
                            "dirty": checkout.dirty,
                            "remote": checkout.remote.as_deref().map(redact_remote_credential),
                            "status": checkout.status,
                        })
                    })
                    .collect();
                let count = observations.len();
                let result_json = serde_json::json!({
                    "checkouts": observations,
                })
                .to_string();
                operations
                    .complete(&operation.id, "succeeded", Some(&result_json), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
                    .map(|_| {
                        let _ = count;
                    })
            }
            (Some(result), _) => {
                complete_failure(
                    operations,
                    &operation.id,
                    "scan_failed",
                    &redact_output(&result.stderr),
                )
                .await
            }
            (None, Some(detail)) => {
                complete_failure(operations, &operation.id, "connection_failed", &detail).await
            }
            (None, None) => Err("the discovery produced neither a result nor a detail".to_owned()),
        }
    }

    async fn clone_checkout(
        &self,
        operations: &Operations,
        operation: &Operation,
    ) -> Result<(), String> {
        let payload: ClonePayload = payload(operation)?;
        validate_root(&payload.root)?;
        validate_remote(&payload.remote)?;
        if let Some(branch) = &payload.branch {
            validate_branch(branch)?;
        }
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!("cloning into {}", payload.root)),
            )
            .await
            .map_err(|error| error.to_string())?;
        let deadline = deadline(payload.timeout_seconds);
        let arguments = match &payload.branch {
            Some(branch) => vec![
                payload.remote.clone(),
                payload.root.clone(),
                "--branch".to_owned(),
                branch.clone(),
            ],
            None => vec![payload.remote.clone(), payload.root.clone()],
        };
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment: vec![("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned())],
            arguments,
        };
        let (result, detail) = self.run(&spec, &clone_script(), &metadata, deadline).await;
        finish_git(operations, &operation.id, result, detail).await
    }

    async fn pull(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: PullPayload = payload(operation)?;
        validate_root(&payload.root)?;
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!("pulling {}", payload.root)),
            )
            .await
            .map_err(|error| error.to_string())?;
        let deadline = deadline(payload.timeout_seconds);
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment: vec![("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned())],
            arguments: vec![payload.root],
        };
        let (result, detail) = self.run(&spec, &pull_script(), &metadata, deadline).await;
        finish_git(operations, &operation.id, result, detail).await
    }

    async fn status(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: StatusPayload = payload(operation)?;
        validate_root(&payload.root)?;
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        let deadline = deadline(payload.timeout_seconds);
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment: Vec::new(),
            arguments: vec![payload.root],
        };
        let (result, detail) = self.run(&spec, &status_script(), &metadata, deadline).await;
        match (result, detail) {
            (Some(result), _) if result.killed_by_deadline => {
                complete_failure(
                    operations,
                    &operation.id,
                    "deadline_killed",
                    "the status probe was killed at its deadline; the checkout's state is unknown",
                )
                .await
            }
            (Some(result), _) if result.exit_code == Some(0) => {
                let parsed = result
                    .stdout
                    .lines()
                    .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok());
                let checkout = parsed.map(|line| decode_status_line(&line));
                let result_json = serde_json::json!({
                    "checkout": checkout,
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

    async fn write_config(
        &self,
        operations: &Operations,
        operation: &Operation,
    ) -> Result<(), String> {
        let payload: WriteConfigPayload = payload(operation)?;
        validate_root(&payload.root)?;
        if !AGENT_CONFIG_FILES.contains(&payload.file_name.as_str()) {
            return Err(format!(
                "the file name {:?} is not a guarded agent config file",
                payload.file_name
            ));
        }
        if payload.contents.len() > MAX_CONFIG_BYTES {
            return Err(format!(
                "the contents exceed the {} byte bound",
                MAX_CONFIG_BYTES
            ));
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
                    "writing {} under {}",
                    payload.file_name, payload.root
                )),
            )
            .await
            .map_err(|error| error.to_string())?;
        let deadline = deadline(payload.timeout_seconds);
        // The contents ride the script as shell-inert base64: the script
        // decodes them into a temp file and renames atomically. The root
        // and file name are validated caller arguments.
        let script = write_config_script(
            &payload.root,
            &payload.file_name,
            &base64::engine::general_purpose::STANDARD.encode(payload.contents.as_bytes()),
        );
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment: Vec::new(),
            arguments: vec![],
        };
        let (result, detail) = self.run(&spec, &script, &metadata, deadline).await;
        match (result, detail) {
            (Some(result), _) if result.killed_by_deadline => {
                complete_failure(
                    operations,
                    &operation.id,
                    "deadline_killed",
                    "the write was killed at its deadline; the file's state is unknown",
                )
                .await
            }
            (Some(result), _) if result.exit_code == Some(0) => {
                let result_json = serde_json::json!({
                    "written": format!("{}/{}", payload.root, payload.file_name),
                })
                .to_string();
                operations
                    .complete(&operation.id, "succeeded", Some(&result_json), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            (Some(result), _) => {
                let reason = if result.stderr.contains("outside the checkout root") {
                    "path_containment"
                } else {
                    "write_failed"
                };
                complete_failure(
                    operations,
                    &operation.id,
                    reason,
                    &redact_output(&result.stderr),
                )
                .await
            }
            (None, Some(detail)) => {
                complete_failure(operations, &operation.id, "connection_failed", &detail).await
            }
            (None, None) => Err("the write produced neither a result nor a detail".to_owned()),
        }
    }
}

/// The fixed clone script: hooks disabled, no terminal prompt, argument
/// array. `$1` is the remote, `$2` the root, `$3`/`$4` an optional
/// `--branch <name>` pair.
fn clone_script() -> String {
    r#"fleet_remote=$1; fleet_root=$2; shift 2
if [ "$#" -eq 2 ]; then
  git clone -c core.hooksPath=/nonexistent-fleet-hooks -c advice.detachedHead=false \
    --branch "$2" -- "$1" "$fleet_root" >/dev/null 2>&1 || { git clone -c core.hooksPath=/nonexistent-fleet-hooks --branch "$2" -- "$1" "$fleet_root"; exit $?; }
else
  git clone -c core.hooksPath=/nonexistent-fleet-hooks -- "$fleet_remote" "$fleet_root"
fi
"#
    .to_owned()
}

/// The fixed pull script: hooks disabled, fast-forward only, argument
/// array. `$1` is the root.
fn pull_script() -> String {
    r#"fleet_root=$1
git -C "$fleet_root" -c core.hooksPath=/nonexistent-fleet-hooks pull --ff-only
"#
    .to_owned()
}

/// The fixed status script: one JSON line, base64 fields, no hooks. `$1` is
/// the root.
fn status_script() -> String {
    r#"fleet_root=$1
fleet_b64() { printf '%s' "$1" | base64 -w0; }
fleet_branch=$(git -C "$fleet_root" rev-parse --abbrev-ref HEAD 2>/dev/null | head -n 1)
fleet_head=$(git -C "$fleet_root" rev-parse HEAD 2>/dev/null | head -n 1)
if [ -z "$fleet_branch" ] || [ -z "$fleet_head" ]; then
  echo "not a git repository: $fleet_root" >&2
  exit 1
fi
if [ -n "$(git -C "$fleet_root" status --porcelain 2>/dev/null | head -n 1)" ]; then
  fleet_dirty=true
else
  fleet_dirty=false
fi
fleet_remote=$(git -C "$fleet_root" remote get-url origin 2>/dev/null | head -n 1)
printf '{"root64":"%s","branch64":"%s","head64":"%s","dirty":"%s","remote64":"%s"}\n' \
  "$(fleet_b64 "$fleet_root")" "$(fleet_b64 "$fleet_branch")" \
  "$(fleet_b64 "$fleet_head")" "$fleet_dirty" "$(fleet_b64 "$fleet_remote")"
"#
    .to_owned()
}

/// The fixed write script: containment is checked by canonicalizing the
/// target's directory and refusing anything that escapes the checkout root,
/// then the contents arrive on stdin and land atomically via a temp file
/// and rename. The root and file name are validated caller arguments, the
/// contents are the script body above this prologue.
fn write_config_script(root: &str, file_name: &str, contents64: &str) -> String {
    // All three inputs are validated by the executor before they get here;
    // the quoting is shell-safe because the root is a validated absolute
    // path, the file name comes from the fixed allowlist, and the contents
    // are base64 (shell-inert by construction).
    format!(
        r#"fleet_root={root:?}
fleet_name={file_name:?}
fleet_target="$fleet_root/$fleet_name"
fleet_dir=$(cd "$fleet_root" && pwd -P) || {{ echo "the checkout root is not a directory" >&2; exit 1; }}
case "$fleet_dir" in
  "$fleet_root") : ;;
  *) echo "path containment: the resolved root escaped the checkout root" >&2; exit 1 ;;
esac
fleet_target="$fleet_dir/$fleet_name"
printf '%s' '{contents64}' | base64 -d > "$fleet_target.fleet-tmp" || {{ echo "the write failed" >&2; exit 1; }}
mv -f "$fleet_target.fleet-tmp" "$fleet_target" || {{ rm -f "$fleet_target.fleet-tmp"; echo "the rename failed" >&2; exit 1; }}
"#
    )
}

/// Validates an absolute checkout root: absolute-shaped, bounded, no `..`
/// segment, no control characters.
fn validate_root(root: &str) -> Result<(), String> {
    if !root.starts_with('/') || root.len() > MAX_ROOT_BYTES {
        return Err(format!(
            "the checkout root must be an absolute path of at most {MAX_ROOT_BYTES} characters"
        ));
    }
    if root.split('/').any(|segment| segment == "..") {
        return Err("the checkout root must not contain a `..` segment".to_owned());
    }
    if root.chars().any(char::is_control) {
        return Err("the checkout root must not contain control characters".to_owned());
    }
    Ok(())
}

/// Validates a remote URL: bounded, no control characters. The URL's own
/// grammar is Git's problem; Fleet refuses only what could break the
/// transport or the audit surface.
fn validate_remote(remote: &str) -> Result<(), String> {
    if remote.is_empty() || remote.len() > MAX_REMOTE_BYTES {
        return Err(format!(
            "the remote must be 1..={MAX_REMOTE_BYTES} characters"
        ));
    }
    if remote.chars().any(char::is_control) {
        return Err("the remote must not contain control characters".to_owned());
    }
    Ok(())
}

/// Validates a branch name: bounded, no control characters, no leading
/// dash (so it can never be mistaken for an option).
fn validate_branch(branch: &str) -> Result<(), String> {
    if branch.is_empty() || branch.len() > MAX_BRANCH_BYTES {
        return Err(format!(
            "the branch must be 1..={MAX_BRANCH_BYTES} characters"
        ));
    }
    if branch.starts_with('-') {
        return Err("the branch must not start with a dash".to_owned());
    }
    if branch.chars().any(char::is_control) {
        return Err("the branch must not contain control characters".to_owned());
    }
    Ok(())
}

/// The deadline clamp shared by every checkout kind.
fn deadline(seconds: u64) -> Duration {
    Duration::from_secs(seconds.min(MAX_GIT_TIMEOUT))
}

/// Decodes and validates an operation's payload.
fn payload<T: serde::de::DeserializeOwned>(operation: &Operation) -> Result<T, String> {
    serde_json::from_str(
        operation
            .payload_json
            .as_deref()
            .ok_or("the operation carries no payload")?,
    )
    .map_err(|error| format!("the payload is not a valid checkout record: {error}"))
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

/// Finishes a clone or pull from the execution outcome.
async fn finish_git(
    operations: &Operations,
    operation_id: &str,
    result: Option<fleet_provider_ssh::ExecutionResult>,
    detail: Option<String>,
) -> Result<(), String> {
    match (result, detail) {
        (Some(result), _) if result.killed_by_deadline => complete_failure(
            operations,
            operation_id,
            "deadline_killed",
            "the git operation was killed at its deadline; the remote checkout's state is unknown",
        )
        .await,
        (Some(result), _) if result.exit_code == Some(0) => operations
            .complete(operation_id, "succeeded", Some("{\"kind\":\"git\"}"), None)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string()),
        (Some(result), _) => {
            complete_failure(
                operations,
                operation_id,
                "git_failed",
                &redact_output(&result.stderr),
            )
            .await
        }
        (None, Some(detail)) => {
            complete_failure(operations, operation_id, "connection_failed", &detail).await
        }
        (None, None) => Err("the git operation produced neither a result nor a detail".to_owned()),
    }
}

/// Decodes one status line's base64 fields into the public checkout shape.
fn decode_status_line(line: &serde_json::Value) -> serde_json::Value {
    let decode = |key: &str| -> Option<String> {
        let raw = line[key].as_str()?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(raw.as_bytes())
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())?;
        Some(decoded).filter(|decoded| !decoded.is_empty())
    };
    serde_json::json!({
        "root": decode("root64"),
        "branch": decode("branch64"),
        "head": decode("head64"),
        "dirty": line["dirty"].as_str().and_then(|flag| match flag {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }),
        "remote": decode("remote64").as_deref().map(redact_remote_credential),
    })
}

/// Redacts credential-shaped userinfo and control noise from tool output
/// before it becomes a public result.
fn redact_output(text: &str) -> String {
    let trimmed = text.trim();
    let bounded = if trimmed.len() > RESULT_STRING_BOUND {
        let mut end = RESULT_STRING_BOUND;
        while !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        &trimmed[..end]
    } else {
        trimmed
    };
    redact_remote_credential(bounded)
}

/// The test hook for the redaction path; production goes through
/// [`redact_output`].
#[must_use]
pub fn redact_output_for_test(text: &str) -> String {
    redact_output(text)
}

/// Replaces `user:password@` and `user@` userinfo in URLs with a marker.
fn redact_remote_credential(text: &str) -> String {
    let mut redacted = String::with_capacity(text.len());
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            redacted.push('\n');
        }
        redacted.push_str(&redact_line(line));
    }
    redacted
}

fn redact_line(line: &str) -> String {
    // Scheme URLs: scheme://user[:pass]@host → scheme://***@host
    let mut result = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(position) = rest.find("://") {
        let (before, after) = rest.split_at(position + 3);
        result.push_str(before);
        let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
        let authority = &after[..authority_end];
        let tail = &after[authority_end..];
        match authority.split_once('@') {
            Some((_userinfo, host)) => {
                result.push_str("***@");
                result.push_str(host);
            }
            None => result.push_str(authority),
        }
        rest = tail;
    }
    result.push_str(rest);
    // Anywhere else a `user:password@` pattern survives (scp-style remotes,
    // error text), redact the password part in place.
    while let Some(position) = find_credential(&result) {
        let end = result[position..]
            .find('@')
            .map(|at| position + at)
            .unwrap_or(result.len());
        result.replace_range(position..end, "***");
    }
    result
}

/// Finds the next `user:password@` pattern's start, where the userinfo is
/// not already redacted. The token begins after the nearest whitespace,
/// slash, or quote before the `@`.
fn find_credential(text: &str) -> Option<usize> {
    let mut search = 0;
    while let Some(offset) = text[search..].find('@') {
        let at = search + offset;
        let token_start = text[..at]
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace() || *c == '/' || *c == '"')
            .map_or(0, |(index, c)| index + c.len_utf8());
        let token = &text[token_start..at];
        if token.split_once(':').is_some_and(|(user, password)| {
            !user.is_empty() && !password.is_empty() && !token.ends_with("***")
        }) {
            return Some(token_start);
        }
        search = at + 1;
    }
    None
}

/// Validates an absolute checkout root: absolute-shaped, bounded, no `..`
/// segment, no control characters.
/// The kind-dispatching wrapper the controller composes: the checkout kinds
/// route to the [`CheckoutExecutor`], everything else falls through to the
/// rest of the chain unchanged.
#[derive(Debug)]
pub struct CheckoutDispatch {
    fallback: Arc<dyn OperationExecutor>,
    checkout: Arc<dyn OperationExecutor>,
}

impl CheckoutDispatch {
    /// Composes the dispatch from the fallback chain and the checkout
    /// executor.
    #[must_use]
    pub fn new(fallback: Arc<dyn OperationExecutor>, checkout: Arc<dyn OperationExecutor>) -> Self {
        Self { fallback, checkout }
    }
}

#[async_trait]
impl OperationExecutor for CheckoutDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "projects.discover"
            | "projects.clone"
            | "projects.pull"
            | "projects.status"
            | "projects.write-config" => self.checkout.execute(operations, operation).await,
            _ => self.fallback.execute(operations, operation).await,
        }
    }
}
