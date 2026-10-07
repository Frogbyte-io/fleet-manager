//! The Lab cleanup executor (FM-713): `lab.cleanup` converges one releasing
//! lease to `released` without leaving a Fleet-owned guest behind.
//!
//! - **destroy** (the default) runs FM-712's reviewed `proxmox.guest.destroy`
//!   as a child operation whose review token the controller computes itself
//!   (it never comes from a caller). The child stops the guest first,
//!   refuses templates and promoted image artifacts, and treats an
//!   already-absent guest as done. Then the Lab-owned machine record goes,
//!   and the lease is released.
//! - **keep** releases the lease and leaves the guest and its machine in
//!   place, out of automatic cleanup.
//! - **revert** needs pooled guests (FM-717) and is refused without touching
//!   anything: the lease stays `releasing`, so an operator can still keep it.
//!
//! A failed attempt is recorded on the lease with a backoff
//! ([`fleet_application::lab::record_cleanup_failure`]); after the last one
//! the lease becomes `cleanup_failed` and an audit event names the guest it
//! still owns. Every step is idempotent, so a re-run after a crash resumes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_application::audit::{AuditIntent, AuditMetadata};
use fleet_application::authz::{Decision, Permission};
use fleet_application::lab::{LeasePort, ProvisionPort, record_cleanup_failure};
use fleet_application::machine::MachinePort;
use fleet_application::operation::{AuditPort, NewOperation, Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_core::{CleanupStrategy, LeaseState};
use serde::Deserialize;

/// How long the destroy child may take, including its stop.
const DESTROY_TIMEOUT_SECONDS: u64 = 600;
/// How long the executor waits for a child the worker claimed first.
const CHILD_WAIT: Duration = Duration::from_secs(DESTROY_TIMEOUT_SECONDS + 60);

/// The `lab.cleanup` payload.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CleanupPayload {
    lease_id: String,
}

/// How a cleanup ended for the lease.
enum Released {
    /// The guest was destroyed (or was already gone).
    Destroyed,
    /// The guest was kept out of automatic cleanup.
    Kept,
    /// The lease never owned a guest.
    NothingAllocated,
}

impl Released {
    const fn id(&self) -> &'static str {
        match self {
            Self::Destroyed => "destroyed",
            Self::Kept => "kept",
            Self::NothingAllocated => "nothing_allocated",
        }
    }
}

/// The Lab cleanup executor.
#[derive(Debug)]
pub struct LabCleanupExecutor {
    leases: Arc<dyn LeasePort>,
    provisions: Arc<dyn ProvisionPort>,
    machines: Arc<dyn MachinePort>,
    audit: Arc<dyn AuditPort>,
    /// Executes the `proxmox.guest.destroy` child (the destructive executor).
    destroyer: Arc<dyn OperationExecutor>,
}

impl LabCleanupExecutor {
    /// Composes the executor from its parts.
    #[must_use]
    pub fn new(
        leases: Arc<dyn LeasePort>,
        provisions: Arc<dyn ProvisionPort>,
        machines: Arc<dyn MachinePort>,
        audit: Arc<dyn AuditPort>,
        destroyer: Arc<dyn OperationExecutor>,
    ) -> Self {
        Self {
            leases,
            provisions,
            machines,
            audit,
            destroyer,
        }
    }

    async fn audit(&self, lease_id: &str, event: &str, facts: &[(&str, String)]) {
        let mut metadata = AuditMetadata::default();
        let _ = metadata.insert("event", event);
        for (key, value) in facts {
            let _ = metadata.insert(key, value);
        }
        // Audit is best effort here: the lease row is the durable truth,
        // and a refused audit sink must not strand a half-done cleanup.
        let _ = self
            .audit
            .record_intent(&AuditIntent {
                actor: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
                action: Permission::LabLease.id().to_owned(),
                resource: Some(lease_id.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await;
    }

    /// Marks the lease released and completes the operation.
    async fn release(
        &self,
        operations: &Operations,
        operation: &Operation,
        mut lease: fleet_core::Lease,
        how: Released,
    ) -> Result<(), String> {
        lease.state = LeaseState::Released;
        lease.cleanup_next_at = None;
        self.leases.update(&lease).await?;
        self.audit(
            &lease.id,
            "lab_lease_released",
            &[("outcome", how.id().to_owned())],
        )
        .await;
        let result = serde_json::json!({ "leaseId": lease.id, "outcome": how.id() }).to_string();
        operations
            .complete(&operation.id, "succeeded", Some(&result), None)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Records a failed attempt on the lease and completes the operation as
    /// failed. The last attempt leaves the lease `cleanup_failed`.
    async fn fail_attempt(
        &self,
        operations: &Operations,
        operation: &Operation,
        mut lease: fleet_core::Lease,
        reason: &str,
        guest: Option<(String, u32)>,
    ) -> Result<(), String> {
        record_cleanup_failure(&mut lease, fleet_core::SystemClock::now_unix_millis());
        self.leases.update(&lease).await?;
        let exhausted = lease.state == LeaseState::CleanupFailed;
        if exhausted {
            let mut facts = vec![("reason", reason.to_owned())];
            if let Some((node, vmid)) = &guest {
                facts.push(("node", node.clone()));
                facts.push(("vmid", vmid.to_string()));
            }
            self.audit(&lease.id, "lab_lease_cleanup_failed", &facts)
                .await;
        }
        let error = serde_json::json!({
            "reason": if exhausted { "cleanup_failed" } else { "cleanup_retry" },
            "detail": reason,
            "attempts": lease.cleanup_attempts,
            "nextAttemptAt": lease.cleanup_next_at,
        })
        .to_string();
        operations
            .complete(&operation.id, "failed", None, Some(&error))
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Creates (or re-finds) the reviewed destroy child and runs it to a
    /// terminal state. Answers the child's final record.
    async fn destroy(
        &self,
        operations: &Operations,
        lease: &fleet_core::Lease,
        account_id: &str,
        node: &str,
        vmid: u32,
    ) -> Result<Operation, String> {
        let kind = "proxmox.guest.destroy";
        let payload = serde_json::json!({
            "accountId": account_id,
            "node": node,
            "vmid": vmid,
            "timeoutSeconds": DESTROY_TIMEOUT_SECONDS,
            "params": { "purge": true },
        })
        .to_string();
        // The controller reviews its own cleanup: the token is computed
        // from these exact bytes, as the reviewed endpoint does.
        let review_token = fleet_application::operation::review_token_for(kind, &payload);
        let child = operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &NewOperation {
                    kind: kind.to_owned(),
                    idempotency_key: Some(format!(
                        "lab-cleanup-destroy:{}:{}",
                        lease.id, lease.cleanup_attempts
                    )),
                    deadline_at: None,
                    correlation_id: Some(lease.id.clone()),
                    payload_json: Some(payload),
                    review_token: Some(review_token),
                },
            )
            .await
            .map_err(|_| "the destroy child could not be created".to_owned())?;
        // Run it here; if the worker claimed it first, wait for its result.
        let _ = operations
            .claim_only_execute(
                self.destroyer.as_ref(),
                &child.id,
                fleet_auth::LAN_PRINCIPAL_ID,
            )
            .await;
        let started = Instant::now();
        loop {
            let current = operations
                .get(
                    &fleet_auth::LanAllowAllAuthorizer,
                    fleet_auth::LAN_PRINCIPAL_ID,
                    &child.id,
                )
                .await
                .map_err(|_| "the destroy child is unreadable".to_owned())?;
            if !matches!(current.state.as_str(), "pending" | "running" | "cancelling") {
                return Ok(current);
            }
            if started.elapsed() > CHILD_WAIT {
                return Err("the destroy child did not finish in time".to_owned());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Removes the Lab-owned machine record, when the guest had one.
    async fn remove_machine(&self, machine_id: &str) -> Result<(), String> {
        match self.machines.delete(machine_id).await {
            Ok(()) | Err(fleet_application::operation::PortFailure::NotFound { .. }) => Ok(()),
            Err(_) => Err("the Lab-owned machine record could not be removed".to_owned()),
        }
    }
}

#[async_trait::async_trait]
impl OperationExecutor for LabCleanupExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: CleanupPayload = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a cleanup request: {error}"))?;
        let lease = self.leases.get(&payload.lease_id).await?;
        match lease.state {
            LeaseState::Releasing => {}
            LeaseState::Released => {
                // A duplicate delivery after the release committed.
                let result =
                    serde_json::json!({ "leaseId": lease.id, "outcome": "already_released" })
                        .to_string();
                return operations
                    .complete(&operation.id, "succeeded", Some(&result), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string());
            }
            other => {
                let error = serde_json::json!({
                    "reason": "not_releasing",
                    "detail": format!("the lease is {}, not releasing", other.id()),
                })
                .to_string();
                return operations
                    .complete(&operation.id, "failed", None, Some(&error))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string());
            }
        }
        match lease.cleanup {
            CleanupStrategy::Keep => {
                self.release(operations, operation, lease, Released::Kept)
                    .await
            }
            CleanupStrategy::Revert => {
                // Pooled guests do not exist yet (FM-717). Refuse without a
                // destroy and without spending an attempt: the lease stays
                // releasing, so an operator can keep it instead.
                let error = serde_json::json!({
                    "reason": "unsupported_until_pooled",
                    "detail": "revert cleanup needs pooled guests (FM-717); release the lease with keep, or wait for pools",
                })
                .to_string();
                operations
                    .complete(&operation.id, "failed", None, Some(&error))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            CleanupStrategy::Destroy => {
                let record = match &lease.provision_id {
                    Some(id) => Some(self.provisions.get(id).await?),
                    None => None,
                };
                let Some((record, vmid)) =
                    record.and_then(|record| record.vmid.map(|vmid| (record, vmid)))
                else {
                    return self
                        .release(operations, operation, lease, Released::NothingAllocated)
                        .await;
                };
                let Some(node) = record.node.clone() else {
                    return self
                        .fail_attempt(
                            operations,
                            operation,
                            lease,
                            "the guest's node is unknown",
                            None,
                        )
                        .await;
                };
                let guest = Some((node.clone(), vmid));
                let Some(account_id) = record.account_id.clone() else {
                    return self
                        .fail_attempt(
                            operations,
                            operation,
                            lease,
                            "the guest's Proxmox account was not recorded (a pre-FM-713 provision); destroy it by hand, then keep the lease",
                            guest,
                        )
                        .await;
                };
                let child = match self
                    .destroy(operations, &lease, &account_id, &node, vmid)
                    .await
                {
                    Ok(child) => child,
                    Err(detail) => {
                        return self
                            .fail_attempt(operations, operation, lease, &detail, guest)
                            .await;
                    }
                };
                if child.state != "succeeded" {
                    let reason = child
                        .error_json
                        .as_deref()
                        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
                        .and_then(|error| error["reason"].as_str().map(str::to_owned))
                        .unwrap_or_else(|| child.state.clone());
                    return self
                        .fail_attempt(
                            operations,
                            operation,
                            lease,
                            &format!("the destroy ended {}: {reason}", child.state),
                            guest,
                        )
                        .await;
                }
                if let Some(machine_id) = &record.machine_id
                    && let Err(detail) = self.remove_machine(machine_id).await
                {
                    return self
                        .fail_attempt(operations, operation, lease, &detail, guest)
                        .await;
                }
                self.release(operations, operation, lease, Released::Destroyed)
                    .await
            }
        }
    }
}
