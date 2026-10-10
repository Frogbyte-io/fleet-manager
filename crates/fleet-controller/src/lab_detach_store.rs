//! The controller side of detached Lab commands (#394): the guest reader
//! behind `lab exec-status` and the `lab.exec_detach` executor.
//!
//! [`LabDetachDispatch`] wraps the Lab executor. A `lab.exec_detach`
//! operation re-checks that the lease is ready, registers its record if the
//! API did not get to it, and hands the fixed start script to the SSH exec
//! executor (the same session pool, trust gate, and bounds as `lab.exec`).
//! The command rides inside that script as base64 and is never a payload
//! field the transport parses. The operation ends when the guest has
//! started the command, not when the command ends.
//!
//! [`SshGuestExec`] reads a handle's state over the same verified endpoint
//! with the provider's fixed status script.

use std::sync::Arc;

use async_trait::async_trait;

use fleet_application::lab::{LeasePort, ProvisionPort};
use fleet_application::lab_exec_detach::{
    DETACH_KIND, DetachedExecPort, GuestExecPort, GuestProcess, GuestProcessState, StartState,
    record_from_payload,
};
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_provider_ssh::detached::{GuestReport, GuestState};

use crate::lab_artifacts_store::{payload_lease, resolve_lab_machine};

/// [`GuestExecPort`] over the controller's OpenSSH trust store: the
/// endpoint's host key must already be verified.
#[derive(Debug)]
pub struct SshGuestExec {
    machines: Arc<dyn fleet_application::machine::MachinePort>,
    provider: fleet_provider_ssh::SshProvider,
    limiter: Arc<fleet_provider_ssh::ExecutionLimiter>,
}

impl SshGuestExec {
    /// Composes the reader over the controller's SSH work directory.
    ///
    /// # Errors
    ///
    /// Fails when the SSH work directory cannot be prepared.
    pub fn new(
        machines: Arc<dyn fleet_application::machine::MachinePort>,
        work_dir: std::path::PathBuf,
        limiter: Arc<fleet_provider_ssh::ExecutionLimiter>,
    ) -> Result<Self, String> {
        Ok(Self {
            machines,
            provider: fleet_provider_ssh::SshProvider::new(work_dir)
                .map_err(|error| error.to_string())?,
            limiter,
        })
    }
}

/// A [`GuestExecPort`] for a controller whose SSH work directory could not
/// be prepared: every read fails, so status answers `unreachable`.
#[derive(Debug)]
pub struct UnavailableGuestExec {
    /// Why.
    pub reason: String,
}

#[async_trait]
impl GuestExecPort for UnavailableGuestExec {
    async fn probe(&self, _: &str, _: &str, _: &str) -> Result<GuestProcess, String> {
        Err(self.reason.clone())
    }
}

#[async_trait]
impl GuestExecPort for SshGuestExec {
    async fn probe(
        &self,
        machine_id: &str,
        endpoint_id: &str,
        handle: &str,
    ) -> Result<GuestProcess, String> {
        let (spec, _, _) = crate::exec::resolve_ssh_endpoint(
            self.machines.as_ref(),
            machine_id,
            endpoint_id,
            fleet_provider_ssh::SshAuth::Agent,
        )
        .await?;
        let provider = self.provider.clone();
        let limiter = self.limiter.clone();
        let handle = handle.to_owned();
        tokio::task::spawn_blocking(move || {
            fleet_provider_ssh::detached::probe_detached(&provider, &limiter, &spec, &handle)
        })
        .await
        .map_err(|error| format!("the status thread failed: {error}"))?
        .map(process_of)
        .map_err(|error| error.to_string())
    }
}

/// Translates the provider's report at the boundary.
pub fn process_of(report: GuestReport) -> GuestProcess {
    GuestProcess {
        state: match report.state {
            GuestState::Absent => GuestProcessState::Absent,
            GuestState::Starting => GuestProcessState::Starting,
            GuestState::Running => GuestProcessState::Running,
            GuestState::Exited => GuestProcessState::Exited,
            GuestState::Lost => GuestProcessState::Lost,
        },
        reason: report.reason,
        exit_code: report.exit_code,
        started_at: report.started_at,
        finished_at: report.finished_at,
        stdout_bytes: report.stdout_bytes,
        stderr_bytes: report.stderr_bytes,
        stdout_tail: report.stdout_tail,
        stderr_tail: report.stderr_tail,
    }
}

/// Wraps the Lab executor with `lab.exec_detach` (see the module docs).
#[derive(Debug)]
pub struct LabDetachDispatch {
    inner: Arc<dyn OperationExecutor>,
    records: Arc<dyn DetachedExecPort>,
    leases: Arc<dyn LeasePort>,
    provisions: Arc<dyn ProvisionPort>,
    templates: Arc<dyn fleet_application::lab::LabTemplatePort>,
}

impl LabDetachDispatch {
    /// Composes the wrapper.
    #[must_use]
    pub fn new(
        inner: Arc<dyn OperationExecutor>,
        records: Arc<dyn DetachedExecPort>,
        leases: Arc<dyn LeasePort>,
        provisions: Arc<dyn ProvisionPort>,
        templates: Arc<dyn fleet_application::lab::LabTemplatePort>,
    ) -> Self {
        Self {
            inner,
            records,
            leases,
            provisions,
            templates,
        }
    }

    async fn fail(
        &self,
        operations: &Operations,
        operation: &Operation,
        reason: &str,
        detail: &str,
    ) -> Result<(), String> {
        if let Err(error) = self
            .records
            .set_start_state(&operation.id, StartState::Failed, None)
            .await
        {
            eprintln!(
                "lab exec detach: record of {} not marked failed: {error}",
                operation.id
            );
        }
        let error = serde_json::json!({
            "reason": reason,
            "detail": fleet_core::scrub_failure_detail(detail),
            "handle": operation.id,
        })
        .to_string();
        operations
            .complete(&operation.id, "failed", None, Some(&error))
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn detach(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let now = fleet_core::SystemClock::now_unix_millis();
        let Some(raw) = operation.payload_json.as_deref() else {
            return self
                .fail(
                    operations,
                    operation,
                    "invalid_payload",
                    "the operation carries no payload",
                )
                .await;
        };
        // The API registers the record after queueing; a crash between the
        // two leaves it to this executor. Either way it is inserted once.
        if let Some(record) = record_from_payload(&operation.id, raw, now)
            && let Err(error) = self.records.insert_if_absent(&record).await
        {
            eprintln!(
                "lab exec detach: record of {} not stored: {error}",
                operation.id
            );
        }
        let payload: serde_json::Value = match serde_json::from_str(raw) {
            Ok(payload) => payload,
            Err(_) => {
                return self
                    .fail(
                        operations,
                        operation,
                        "invalid_payload",
                        "the payload is not a detached exec",
                    )
                    .await;
            }
        };
        let (Some(script), Some(timeout)) = (
            payload["script"].as_str(),
            payload["timeoutSeconds"].as_u64(),
        ) else {
            return self
                .fail(
                    operations,
                    operation,
                    "invalid_payload",
                    "the payload is not a detached exec",
                )
                .await;
        };
        let lease_id = payload_lease(operation);
        // The start script is Bash: a Windows lease is refused, whatever the
        // payload says.
        let (machine_id, endpoint_id) = match resolve_lab_machine(
            self.leases.as_ref(),
            self.provisions.as_ref(),
            self.templates.as_ref(),
            fleet_core::GuestOs::Linux,
            &lease_id,
            now,
        )
        .await
        {
            Ok(found) => found,
            Err((reason, detail)) => {
                return self.fail(operations, operation, reason, &detail).await;
            }
        };
        // The bound never reaches past the lease: re-clamp to what is left
        // now, in case the operation sat queued.
        let remaining = self
            .leases
            .get(&lease_id)
            .await
            .ok()
            .and_then(|lease| lease.expires_at)
            .map_or(0, |expires| {
                u64::try_from((expires - now) / 1000).unwrap_or(0)
            });
        let timeout = timeout.min(remaining).max(1);
        let mut ssh = operation.clone();
        ssh.kind = "ssh.exec".to_owned();
        ssh.payload_json = Some(
            serde_json::json!({
                "machineId": machine_id,
                "endpointId": endpoint_id,
                "auth": {"type": "agent"},
                "script": fleet_provider_ssh::detached::start_script(script),
                "arguments": [operation.id, timeout.to_string()],
                "timeoutSeconds": fleet_provider_ssh::detached::SESSION_DEADLINE.as_secs(),
            })
            .to_string(),
        );
        let ran = self.inner.execute(operations, &ssh).await;
        // How the guest start ended decides the record; the operation was
        // completed by the SSH executor.
        let ended = operations.get_state(&operation.id).await;
        let state = match ended.as_deref() {
            Ok("succeeded") => Some((StartState::Started, Some(now))),
            Ok("failed" | "cancelled") => Some((StartState::Failed, None)),
            _ => None,
        };
        if let Some((state, at)) = state
            && let Err(error) = self.records.set_start_state(&operation.id, state, at).await
        {
            eprintln!(
                "lab exec detach: record of {} not updated: {error}",
                operation.id
            );
        }
        ran
    }
}

#[async_trait]
impl OperationExecutor for LabDetachDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        if operation.kind == DETACH_KIND {
            self.detach(operations, operation).await
        } else {
            self.inner.execute(operations, operation).await
        }
    }
}
