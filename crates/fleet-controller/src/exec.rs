//! The controller's operation executor: dispatches durable operations to
//! their kind-specific work.
//!
//! `noop` does bounded no work so the durable path stays exercised.
//! `ssh.exec` runs a bounded script on a verified SSH endpoint: the payload
//! names the endpoint and carries the script, and the executor refuses to
//! run against an endpoint whose host key was never confirmed — the trust
//! workflow (FM-201) is the gate, not a suggestion. Output becomes the
//! operation's bounded public result; the remote script never sees caller
//! data through a shell (see the provider's transport rule).
//!
//! Unknown kinds fail their operation instead of guessing: a kind the
//! controller cannot describe is a defect in creation, and the worker is
//! the place that truth lands.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use fleet_application::machine::MachinePort;
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_provider_ssh::{
    ExecutionLimiter, ScriptMetadata, SshAuth, SshConnectionSpec, SshProvider,
};

/// The payload of an `ssh.exec` operation, as validated JSON.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshExecPayload {
    /// The machine carrying the SSH endpoint.
    machine_id: String,
    /// The endpoint id to execute on.
    endpoint_id: String,
    /// The script to run.
    script: String,
    /// Working directory; empty means the remote login's default.
    #[serde(default)]
    working_directory: String,
    /// Environment to export.
    #[serde(default)]
    environment: Vec<(String, String)>,
    /// Positional arguments.
    #[serde(default)]
    arguments: Vec<String>,
    /// How the endpoint authenticates.
    auth: SshExecAuth,
    /// The deadline, in seconds. Bounded hard.
    timeout_seconds: u64,
}

/// How the endpoint authenticates.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
enum SshExecAuth {
    /// The controller's agent supplies the key.
    Agent,
    /// A specific identity file.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// The deadline bound for one SSH script. Longer work belongs in fleetd
/// operations, which survive controller restarts.
pub const MAX_SCRIPT_TIMEOUT: u64 = 900;

/// The bound for the operation's public result; output is trimmed to fit.
const RESULT_STRING_BOUND: usize = 3_000;

/// The kind-dispatching executor.
#[derive(Debug)]
pub struct ScriptExecutor {
    machines: Arc<dyn MachinePort>,
    provider: SshProvider,
    limiter: Arc<ExecutionLimiter>,
    /// Retained for the provider's isolated directory lifetime.
    #[allow(dead_code)]
    work_dir: PathBuf,
}

impl ScriptExecutor {
    /// Composes the executor from its parts.
    ///
    /// # Panics
    ///
    /// Panics only if the SSH work directory cannot be prepared, which the
    /// store's own data-directory preparation already ensures.
    #[must_use]
    pub fn new(
        machines: Arc<dyn MachinePort>,
        work_dir: PathBuf,
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
}

#[async_trait]
impl OperationExecutor for ScriptExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "noop" => self.execute_noop(operations, operation).await,
            "ssh.exec" => self.execute_ssh(operations, operation).await,
            other => {
                let error_json = serde_json::json!({
                    "reason": "unknown_kind",
                    "detail": format!("the controller cannot describe {other:?} work"),
                })
                .to_string();
                operations
                    .complete(&operation.id, "failed", None, Some(&error_json))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
        }
    }
}

impl ScriptExecutor {
    async fn execute_noop(
        &self,
        operations: &Operations,
        operation: &Operation,
    ) -> Result<(), String> {
        operations
            .record_progress(&operation.id, Some(1), Some(1), Some("noop complete"))
            .await
            .map_err(|error| error.to_string())?;
        operations
            .complete(
                &operation.id,
                "succeeded",
                Some("{\"kind\":\"noop\"}"),
                None,
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn execute_ssh(
        &self,
        operations: &Operations,
        operation: &Operation,
    ) -> Result<(), String> {
        let payload: SshExecPayload = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a valid ssh.exec record: {error}"))?;

        let (spec, verified, host) = self.resolve_endpoint(&payload).await?;

        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!(
                    "running on {host}:{} (verified {verified})",
                    payload.endpoint_id
                )),
            )
            .await
            .map_err(|error| error.to_string())?;

        let deadline = Duration::from_secs(payload.timeout_seconds.min(MAX_SCRIPT_TIMEOUT));
        let metadata = ScriptMetadata {
            working_directory: payload.working_directory.clone(),
            environment: payload.environment.clone(),
            arguments: payload.arguments.clone(),
        };
        let (result, detail) = self
            .run_script(&spec, &payload.script, &metadata, deadline)
            .await;

        match (result, detail) {
            (Some(result), _) => {
                let result_json = serde_json::json!({
                    "exitCode": result.exit_code,
                    "stdout": trim_to_bound(&result.stdout),
                    "stderr": trim_to_bound(&result.stderr),
                    "truncatedStdout": result.truncated_stdout,
                    "truncatedStderr": result.truncated_stderr,
                })
                .to_string();
                if result.killed_by_deadline {
                    let error_json = serde_json::json!({
                        "reason": "deadline_killed",
                        "detail": "the local ssh process was killed at the deadline; the remote command's fate is unknown",
                        "partialOutput": {
                            "stdout": trim_to_bound(&result.stdout),
                            "stderr": trim_to_bound(&result.stderr),
                        },
                    })
                    .to_string();
                    operations
                        .complete(&operation.id, "failed", None, Some(&error_json))
                        .await
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                } else if result.exit_code == Some(0) {
                    operations
                        .complete(&operation.id, "succeeded", Some(&result_json), None)
                        .await
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                } else {
                    operations
                        .complete(&operation.id, "failed", None, Some(&result_json))
                        .await
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                }
            }
            (None, Some(detail)) => {
                let error_json =
                    serde_json::json!({ "reason": "connection_failed", "detail": detail })
                        .to_string();
                operations
                    .complete(&operation.id, "failed", None, Some(&error_json))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            (None, None) => Err("the execution produced neither a result nor a detail".to_owned()),
        }
    }
}

impl ScriptExecutor {
    /// Runs one script to completion on the worker's blocking pool.
    async fn run_script(
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

    /// Resolves the payload's endpoint into a connection spec, enforcing the
    /// trust gate: an unverified host key refuses to execute, full stop.
    async fn resolve_endpoint(
        &self,
        payload: &SshExecPayload,
    ) -> Result<(SshConnectionSpec, String, String), String> {
        let verified = self
            .machines
            .verified_fingerprint(&payload.endpoint_id)
            .await
            .map_err(|failure| failure.to_string())?
            .ok_or("the endpoint's host key was never confirmed; run the trust workflow first")?;
        let machine = self
            .machines
            .get(&payload.machine_id)
            .await
            .map_err(|failure| failure.to_string())?;
        let endpoint = machine
            .endpoints
            .iter()
            .find(|endpoint| endpoint.id == payload.endpoint_id)
            .ok_or("the named endpoint does not belong to the machine")?
            .clone();
        if endpoint.kind != fleet_core::EndpointKind::Ssh {
            return Err(format!(
                "the endpoint is {:?}, not an SSH endpoint",
                endpoint.kind.id()
            ));
        }
        let (user, host_port) = endpoint
            .reference
            .split_once('@')
            .ok_or("the endpoint reference must be user@host:port")?;
        let (host, port) = host_port
            .rsplit_once(':')
            .ok_or("the endpoint reference must be user@host:port")?;
        let port: u16 = port
            .parse()
            .map_err(|_| "the endpoint reference's port is not a number")?;
        let auth = match &payload.auth {
            SshExecAuth::Agent => SshAuth::Agent,
            SshExecAuth::IdentityFile { path } => SshAuth::IdentityFile { path: path.clone() },
        };
        Ok((
            SshConnectionSpec {
                host: host.to_owned(),
                port,
                user: user.to_owned(),
                auth,
            },
            verified,
            host.to_owned(),
        ))
    }
}

fn trim_to_bound(text: &str) -> String {
    if text.len() <= RESULT_STRING_BOUND {
        text.to_owned()
    } else {
        let mut end = RESULT_STRING_BOUND;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &text[..end])
    }
}

/// Convenience: the noop executor remains available for hosts that do not
/// carry SSH machines.
#[must_use]
pub fn noop_only_executor() -> impl OperationExecutor {
    fleet_application::worker::NoopExecutor
}
