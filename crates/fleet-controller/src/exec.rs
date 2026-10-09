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
    COLLECTION_DEADLINE, ExecutionLimiter, ScriptMetadata, SshAuth, SshConnectionSpec, SshProvider,
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

/// The payload of an `agentless.inventory` operation.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct InventoryPayload {
    /// The machine carrying the SSH endpoint.
    machine_id: String,
    /// The endpoint id to probe.
    endpoint_id: String,
    /// How the endpoint authenticates.
    auth: SshExecAuth,
    /// The deadline, in seconds. Bounded hard.
    timeout_seconds: u64,
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
            "agentless.inventory" => self.execute_inventory(operations, operation).await,
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

    /// The agentless inventory path: probe, ingest capabilities, snapshot.
    async fn execute_inventory(
        &self,
        operations: &Operations,
        operation: &Operation,
    ) -> Result<(), String> {
        let payload: InventoryPayload = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a valid inventory record: {error}"))?;
        let (spec, verified, host) = self.resolve_inventory_endpoint(&payload).await?;

        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!("probing {host} (verified {verified})")),
            )
            .await
            .map_err(|error| error.to_string())?;

        let (collected, detail) = {
            let provider = self.provider.clone();
            let limiter = self.limiter.clone();
            let spec = spec.clone();
            tokio::task::spawn_blocking(move || {
                fleet_provider_ssh::collect(&provider, &limiter, &spec, COLLECTION_DEADLINE)
            })
            .await
            .unwrap_or_else(|join_error| {
                Err(fleet_provider_ssh::SshProviderError::Tool {
                    tool: "ssh",
                    detail: format!("the collection thread failed: {join_error}"),
                })
            })
            .map_or_else(
                |error| (None, Some(error.to_string())),
                |result| (Some(result), None),
            )
        };

        match (collected, detail) {
            (Some(facts), _) => {
                let count = facts.len();
                self.machines
                    .record_capabilities(&payload.machine_id, &facts)
                    .await
                    .map_err(|failure| failure.to_string())?;
                let snapshot = serde_json::to_string(&facts)
                    .map_err(|error| format!("the fact set does not serialize: {error}"))?;
                self.machines
                    .record_snapshot(
                        &payload.machine_id,
                        fleet_provider_ssh::PROBE_SOURCE,
                        &snapshot,
                        fleet_core::SystemClock::now_unix_millis(),
                    )
                    .await
                    .map_err(|failure| failure.to_string())?;
                let result_json = serde_json::json!({ "facts": count }).to_string();
                operations
                    .complete(&operation.id, "succeeded", Some(&result_json), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            (None, Some(detail)) => {
                let error_json = transport_failure_json("collection_failed", &detail);
                operations
                    .complete(&operation.id, "failed", None, Some(&error_json))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            (None, None) => Err("the collection produced neither facts nor a detail".to_owned()),
        }
    }

    /// The inventory variant of endpoint resolution: the trust gate is the
    /// same, the payload shape differs.
    async fn resolve_inventory_endpoint(
        &self,
        payload: &InventoryPayload,
    ) -> Result<(SshConnectionSpec, String, String), String> {
        self.resolve_endpoint(&SshExecPayload {
            machine_id: payload.machine_id.clone(),
            endpoint_id: payload.endpoint_id.clone(),
            script: String::new(),
            working_directory: String::new(),
            environment: Vec::new(),
            arguments: Vec::new(),
            auth: match &payload.auth {
                SshExecAuth::Agent => SshExecAuth::Agent,
                SshExecAuth::IdentityFile { path } => {
                    SshExecAuth::IdentityFile { path: path.clone() }
                }
            },
            timeout_seconds: payload.timeout_seconds,
        })
        .await
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
                // The stored output is scrubbed of credential shapes and
                // then bounded; each flag stays true when either the
                // provider or this bound dropped output.
                let (stdout, truncated_stdout) =
                    scrub_and_bound(&result.stdout, result.truncated_stdout);
                let (stderr, truncated_stderr) =
                    scrub_and_bound(&result.stderr, result.truncated_stderr);
                let result_json = serde_json::json!({
                    "exitCode": result.exit_code,
                    "stdout": stdout,
                    "stderr": stderr,
                    "truncatedStdout": truncated_stdout,
                    "truncatedStderr": truncated_stderr,
                })
                .to_string();
                if result.killed_by_deadline {
                    let error_json = serde_json::json!({
                        "reason": "deadline_killed",
                        "detail": "the local ssh process was killed at the deadline; the remote command's fate is unknown",
                        "partialOutput": {
                            "stdout": stdout,
                            "stderr": stderr,
                            "truncatedStdout": truncated_stdout,
                            "truncatedStderr": truncated_stderr,
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
                let error_json = transport_failure_json("connection_failed", &detail);
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
        let auth = match &payload.auth {
            SshExecAuth::Agent => SshAuth::Agent,
            SshExecAuth::IdentityFile { path } => SshAuth::IdentityFile { path: path.clone() },
        };
        let (spec, verified, host) = resolve_ssh_endpoint(
            self.machines.as_ref(),
            &payload.machine_id,
            &payload.endpoint_id,
            auth,
        )
        .await?;
        Ok((spec, verified, host))
    }
}

/// Resolves a machine's SSH endpoint into a connection spec, enforcing the
/// trust gate the whole SSH surface shares: the endpoint's host key must be
/// verified, the endpoint must be the machine's, and it must be an SSH
/// endpoint. Returns the spec, the verified fingerprint, and the host.
pub(crate) async fn resolve_ssh_endpoint(
    machines: &dyn MachinePort,
    machine_id: &str,
    endpoint_id: &str,
    auth: SshAuth,
) -> Result<(SshConnectionSpec, String, String), String> {
    let verified = machines
        .verified_fingerprint(endpoint_id)
        .await
        .map_err(|failure| failure.to_string())?
        .ok_or("the endpoint's host key was never confirmed; run the trust workflow first")?;
    let machine = machines
        .get(machine_id)
        .await
        .map_err(|failure| failure.to_string())?;
    let endpoint = machine
        .endpoints
        .iter()
        .find(|endpoint| endpoint.id == endpoint_id)
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

/// Convenience: the noop executor remains available for hosts that do not
/// carry SSH machines.
#[must_use]
pub fn noop_only_executor() -> impl OperationExecutor {
    fleet_application::worker::NoopExecutor
}

/// The stored error for a failure whose detail is transport or tool text
/// (node- and network-supplied): scrubbed and bounded like command output.
fn transport_failure_json(reason: &str, detail: &str) -> String {
    let (detail, _) = scrub_and_bound(detail, false);
    serde_json::json!({ "reason": reason, "detail": detail }).to_string()
}

/// Scrubs credential shapes from command output, then bounds it. Scrubbing
/// first means a credential straddling the bound is never half kept. The
/// returned flag is true when the provider already truncated the output or
/// this bound cut it.
fn scrub_and_bound(text: &str, provider_truncated: bool) -> (String, bool) {
    scrub_and_bound_with(text, provider_truncated, str::to_owned)
}

pub(crate) use fleet_core::{scrub_and_bound_with, scrub_window};

#[cfg(test)]
mod tests {
    use super::{scrub_and_bound, transport_failure_json};
    use fleet_core::RESULT_STRING_BOUND;

    /// The transport error text for a failed connection or collection is
    /// node- and tool-supplied: a userinfo URL is masked and a huge detail cut.
    #[test]
    fn a_transport_failure_detail_is_scrubbed_and_bounded() {
        for reason in ["connection_failed", "collection_failed"] {
            let raw = format!(
                "ssh: connect via https://user:hunter2pw@proxy.invalid/ failed {}",
                "e".repeat(RESULT_STRING_BOUND * 2)
            );
            let json = transport_failure_json(reason, &raw);
            assert!(!json.contains("hunter2"), "{json}");
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(value["reason"], reason);
            let detail = value["detail"].as_str().unwrap();
            assert!(detail.len() <= RESULT_STRING_BOUND + 4, "{}", detail.len());
        }
    }

    #[test]
    fn a_credential_at_the_bound_of_a_huge_stream_is_never_half_kept() {
        for tail in ["y".repeat(20_000), format!(" {}", "y".repeat(20_000))] {
            for secret in [
                "https://user:hunter2pw@host.invalid/r",
                "user:hunter2pw@host.invalid",
            ] {
                let text = format!("{} {secret}{tail}", "x".repeat(2_990));
                let (out, truncated) = scrub_and_bound(&text, false);
                assert!(!out.contains("hunter2"), "{out}");
                assert!(!out.contains("user:"), "{out}");
                assert!(truncated);
                assert!(out.ends_with('…'), "the cut is visible in the text");
            }
        }
    }

    #[test]
    fn output_is_scrubbed_before_it_is_stored() {
        let (text, truncated) =
            scrub_and_bound("cloned https://user:secret@host.invalid/repo\n", false);
        assert!(!text.contains("secret"), "{text}");
        assert!(text.contains("***@host.invalid"), "{text}");
        assert!(!truncated);
    }

    #[test]
    fn a_credential_at_the_bound_is_not_half_kept() {
        let filler = "x".repeat(RESULT_STRING_BOUND - 100);
        let password = "p".repeat(200);
        let (text, truncated) = scrub_and_bound(
            &format!("{filler} https://user:{password}@host.invalid/repo"),
            false,
        );
        assert!(!text.contains("pppp"), "no part of the password survives");
        assert!(
            text.ends_with("***@host.invalid/repo"),
            "{}",
            &text[text.len() - 40..]
        );
        assert!(
            !truncated,
            "the raw text was over the bound but nothing was dropped after scrubbing"
        );
        // Cut at the bound: the credential is already gone, so the cut can
        // never leave a fragment of it.
        let (text, truncated) = scrub_and_bound(
            &format!(
                "https://user:{password}@host.invalid/{}",
                "z".repeat(RESULT_STRING_BOUND)
            ),
            false,
        );
        assert!(!text.contains("pppp"), "no part of the password survives");
        assert!(truncated);
    }

    #[test]
    fn huge_adversarial_output_is_scrubbed_in_bounded_time() {
        let started = std::time::Instant::now();
        let (text, truncated) = scrub_and_bound(&"@".repeat(1024 * 1024), false);
        assert!(truncated);
        assert!(text.len() <= RESULT_STRING_BOUND + 4);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        let emails = "abc@example.com,".repeat(64 * 1024);
        let (_, truncated) = scrub_and_bound(&emails, false);
        assert!(truncated);
    }

    /// A credential wrapped in terminal colour codes is still redacted:
    /// scrubbing runs before control characters become spaces.
    #[test]
    fn a_credential_wrapped_in_terminal_escapes_is_redacted() {
        for text in [
            "remote: \u{1b}[1muser:secretpw\u{1b}[0m@host.invalid",
            "https://\u{1b}[1muser:secretpw\u{1b}[0m@host.invalid/x",
            "user:sec\0retpw@host.invalid",
        ] {
            let (out, _) = scrub_and_bound(text, false);
            assert!(!out.contains("secretpw"), "{out:?}");
            assert!(!out.contains("sec retpw"), "{out:?}");
            assert!(!out.chars().any(|c| c.is_control() && c != '\n'), "{out:?}");
        }
    }

    #[test]
    fn a_window_cut_never_splits_a_credential() {
        let filler = "x ".repeat(RESULT_STRING_BOUND);
        let tail = format!(
            "{filler}{}https://user:secret@host.invalid/r",
            "y ".repeat(16 * 1024)
        );
        let (text, truncated) = scrub_and_bound(&tail, false);
        assert!(truncated);
        assert!(!text.contains("secret"), "{text}");
    }

    #[test]
    fn the_flags_stay_accurate() {
        let (_, provider) = scrub_and_bound("short", true);
        assert!(provider, "a provider truncation is kept");
        let (text, cut) = scrub_and_bound(&"y".repeat(RESULT_STRING_BOUND + 50), false);
        assert!(cut, "this bound's own cut is reported");
        assert!(text.ends_with('…'));
        let (_, clean) = scrub_and_bound("short", false);
        assert!(!clean);
    }

    /// #382: control characters are flattened and the bound counts escaped
    /// bytes, so both streams together always fit the stored result limit.
    #[test]
    fn control_characters_and_escapes_cannot_exceed_the_stored_limit() {
        for filler in ["\u{1}", "\u{1b}", "\"", "\\", "\n", "\0"] {
            let stream = filler.repeat(RESULT_STRING_BOUND);
            let (stdout, _) = scrub_and_bound(&stream, false);
            let (stderr, _) = scrub_and_bound(&stream, false);
            assert!(!stdout.chars().any(|c| c.is_control() && c != '\n'));
            let record = serde_json::json!({
                "exitCode": 1, "stdout": stdout, "stderr": stderr,
                "truncatedStdout": true, "truncatedStderr": true,
            })
            .to_string();
            assert!(
                record.len() <= fleet_storage_sqlite::operations::MAX_RESULT_JSON,
                "{filler:?}: {}",
                record.len()
            );
        }
    }
}
