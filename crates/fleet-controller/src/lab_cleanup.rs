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
//! - **revert** (FM-717) rolls a pooled lease's member back to its pool's
//!   baseline through FM-603's reviewed `proxmox.guest.snapshot-revert`,
//!   verifies it, removes the Lab-owned machine record, and returns the
//!   member to the pool in the same transaction that releases the lease. A
//!   failed revert quarantines the member at once (it never returns to the
//!   pool) and is a failed attempt. A lease bound to a member is never
//!   destroyed, whatever its strategy; `keep` releases it and quarantines
//!   the member. A `revert` lease without a member is refused without
//!   touching anything (`not_pooled`): the lease stays `releasing`, so an
//!   operator can still keep it.
//!
//! A failed attempt is recorded on the lease with a backoff
//! ([`fleet_application::lab::record_cleanup_failure`]); after the last one
//! the lease becomes `cleanup_failed` and an audit event names the guest it
//! still owns. Every step is idempotent, so a re-run after a crash resumes.

use std::sync::Arc;
use std::time::Duration;

use fleet_application::audit::{AuditIntent, AuditMetadata};
use fleet_application::authz::{Decision, Permission};
use fleet_application::lab::{LeasePort, ProvisionPort, record_cleanup_failure};
use fleet_application::lab_placement::CapacityReservationPort;
use fleet_application::lab_pool::{
    CleanupPlan, LabPoolPort, MemberRelease, MemberReleased, PoolGuestPort, PoolMember,
    cleanup_plan, member_audit,
};
use fleet_application::machine::MachinePort;
use fleet_application::operation::{AuditPort, Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_core::LeaseState;
use serde::Deserialize;

/// How long the destroy child may take, including its stop.
const DESTROY_TIMEOUT_SECONDS: u64 = 600;
/// How long the executor waits for a child the worker claimed first.
const CHILD_WAIT: Duration = Duration::from_secs(DESTROY_TIMEOUT_SECONDS + 60);

/// The pool parts of cleanup (FM-717).
#[derive(Debug)]
struct PoolCleanup {
    pools: Arc<dyn LabPoolPort>,
    guests: Arc<dyn PoolGuestPort>,
    /// Executes the reviewed `proxmox.guest.snapshot-revert` child.
    reverter: Arc<dyn OperationExecutor>,
}

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
    /// The capacity reservations released once the guest is gone (FM-715).
    reservations: Option<Arc<dyn CapacityReservationPort>>,
    /// Pooled guests (FM-717).
    pools: Option<PoolCleanup>,
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
            reservations: None,
            pools: None,
        }
    }

    /// Reverts pooled leases' members instead of destroying them (FM-717).
    /// The controller always composes it. Without it the executor knows no
    /// pool, so it must not run where pools exist: a `revert` lease is then
    /// refused (`not_pooled`), but a `destroy` lease is destroyed as a
    /// clone, with no pool-membership check.
    #[must_use]
    pub fn with_pools(
        mut self,
        pools: Arc<dyn LabPoolPort>,
        guests: Arc<dyn PoolGuestPort>,
        reverter: Arc<dyn OperationExecutor>,
    ) -> Self {
        self.pools = Some(PoolCleanup {
            pools,
            guests,
            reverter,
        });
        self
    }

    /// Releases each lease's capacity reservation when its cleanup
    /// completes (FM-715).
    #[must_use]
    pub fn with_reservations(mut self, reservations: Arc<dyn CapacityReservationPort>) -> Self {
        self.reservations = Some(reservations);
        self
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
        self.finish_released(operations, operation, &lease, how.id(), &[])
            .await
    }

    /// The bookkeeping after a lease was marked released: its reservation,
    /// the audit, and the operation's completion.
    async fn finish_released(
        &self,
        operations: &Operations,
        operation: &Operation,
        lease: &fleet_core::Lease,
        outcome: &str,
        facts: &[(&str, String)],
    ) -> Result<(), String> {
        // FM-715: the guest is gone (or was never allocated, or was kept out
        // of Lab ownership). The released lease already stops its held
        // reservation from counting (the reservation transaction reads the
        // lease's state), so marking the row released is bookkeeping and
        // never costs a cleanup attempt.
        if let Some(reservations) = &self.reservations {
            let _ = crate::proxmox_exec::release_reservation(
                reservations.as_ref(),
                self.audit.as_ref(),
                &lease.id,
                outcome,
            )
            .await;
        }
        let mut audited = vec![("outcome", outcome.to_owned())];
        audited.extend(facts.iter().cloned());
        self.audit(&lease.id, "lab_lease_released", &audited).await;
        let result = serde_json::json!({ "leaseId": lease.id, "outcome": outcome }).to_string();
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
        // The reason carries provider, Proxmox and node text, and is stored
        // in the audit trail and the operation error: scrub it once here.
        let reason = fleet_core::scrub_failure_detail(reason);
        let reason = reason.as_str();
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
        crate::lab_pool::run_reviewed_child(
            operations,
            self.destroyer.as_ref(),
            "proxmox.guest.destroy",
            payload,
            format!(
                "lab-cleanup-destroy:{}:{}",
                lease.id, lease.cleanup_attempts
            ),
            &lease.id,
            CHILD_WAIT,
        )
        .await
    }

    /// Reverts a pooled lease's member, verifies it, removes the Lab-owned
    /// machine record, and returns the member while releasing the lease.
    /// A failed check, revert, or verification quarantines the member and
    /// is a failed attempt.
    async fn revert_pooled(
        &self,
        operations: &Operations,
        operation: &Operation,
        pools: &PoolCleanup,
        lease: fleet_core::Lease,
        member: &PoolMember,
    ) -> Result<(), String> {
        let guest = member.node.clone().map(|node| (node, member.vmid));
        let pool = match pools.pools.get(&member.pool_id).await {
            Ok(pool) => pool,
            Err(error) => {
                let detail = format!("the member's pool is unreadable: {error}");
                return self
                    .fail_attempt(operations, operation, lease, &detail, guest)
                    .await;
            }
        };
        let reverted = crate::lab_pool::revert_member(
            operations,
            pools.reverter.as_ref(),
            pools.guests.as_ref(),
            crate::lab_pool::Revert {
                account_id: &member.account_id,
                vmid: member.vmid,
                recorded_name: member.name.as_deref(),
                baseline: &pool.baseline_snapshot,
                idempotency_key: format!(
                    "lab-cleanup-revert:{}:{}",
                    lease.id, lease.cleanup_attempts
                ),
                correlation_id: &lease.id,
            },
        )
        .await;
        let now = fleet_core::SystemClock::now_unix_millis();
        let node = match reverted {
            Ok((node, _name)) => node,
            Err(crate::lab_pool::RevertFailure::Unavailable(detail)) => {
                // Undecided: a failed attempt, but nothing condemns the
                // member, which stays bound and out of rotation anyway.
                return self
                    .fail_attempt(operations, operation, lease, &detail, guest)
                    .await;
            }
            Err(crate::lab_pool::RevertFailure::Refused(detail)) => {
                let detail = fleet_core::scrub_failure_detail(&detail);
                // Quarantined at once: the member never returns unverified,
                // and stays bound so the lease still owes its revert.
                if pools
                    .pools
                    .quarantine_bound(&lease.id, &detail, now)
                    .await
                    .is_ok()
                {
                    self.audit_member(
                        &pool.id,
                        operation,
                        "lab_pool_member_quarantined",
                        member.vmid,
                        &[("leaseId", lease.id.clone()), ("reason", detail.clone())],
                    )
                    .await;
                }
                return self
                    .fail_attempt(operations, operation, lease, &detail, guest)
                    .await;
            }
        };
        if member.node.as_deref() != Some(node.as_str()) {
            // Bookkeeping only: the next revert re-reads the live node.
            let _ = pools.pools.set_member_node(&member.id, &node, now).await;
        }
        let guest = Some((node, member.vmid));
        if let Some(detail) = self.remove_lease_machine(&lease).await {
            return self
                .fail_attempt(operations, operation, lease, &detail, guest)
                .await;
        }
        let returned = match pools
            .pools
            .release_lease(&lease.id, &MemberRelease::Return, now)
            .await
        {
            Ok(returned) => returned,
            Err(error) => {
                let detail = format!("the member could not be returned: {error}");
                return self
                    .fail_attempt(operations, operation, lease, &detail, guest)
                    .await;
            }
        };
        let event = if returned == MemberReleased::Removed {
            "lab_pool_member_removed"
        } else {
            "lab_pool_member_returned"
        };
        self.audit_member(
            &pool.id,
            operation,
            event,
            member.vmid,
            &[("leaseId", lease.id.clone())],
        )
        .await;
        self.finish_released(
            operations,
            operation,
            &lease,
            "reverted",
            &[
                ("poolId", pool.id.clone()),
                ("vmid", member.vmid.to_string()),
                ("member", returned.id().to_owned()),
            ],
        )
        .await
    }

    /// Releases a pooled lease with `keep`: the guest and its machine record
    /// stay, and the member leaves rotation (quarantined) until drained.
    async fn keep_pooled(
        &self,
        operations: &Operations,
        operation: &Operation,
        pools: &PoolCleanup,
        lease: fleet_core::Lease,
        member: &PoolMember,
    ) -> Result<(), String> {
        let now = fleet_core::SystemClock::now_unix_millis();
        let guest = member.node.clone().map(|node| (node, member.vmid));
        let kept = match pools
            .pools
            .release_lease(&lease.id, &MemberRelease::Keep, now)
            .await
        {
            Ok(kept) => kept,
            Err(error) => {
                let detail = format!("the kept member could not be released: {error}");
                return self
                    .fail_attempt(operations, operation, lease, &detail, guest)
                    .await;
            }
        };
        let event = if kept == MemberReleased::Removed {
            "lab_pool_member_removed"
        } else {
            "lab_pool_member_quarantined"
        };
        self.audit_member(
            &member.pool_id,
            operation,
            event,
            member.vmid,
            &[("leaseId", lease.id.clone()), ("reason", "kept".to_owned())],
        )
        .await;
        self.finish_released(
            operations,
            operation,
            &lease,
            Released::Kept.id(),
            &[
                ("poolId", member.pool_id.clone()),
                ("vmid", member.vmid.to_string()),
                ("member", kept.id().to_owned()),
            ],
        )
        .await
    }

    /// Removes the Lab-owned machine record of the lease's provision, when
    /// it has one. Answers why it could not.
    async fn remove_lease_machine(&self, lease: &fleet_core::Lease) -> Option<String> {
        let id = lease.provision_id.as_deref()?;
        let record = match self.provisions.get(id).await {
            Ok(record) => record,
            Err(detail) => return Some(format!("the provision record is unreadable: {detail}")),
        };
        let machine_id = record.machine_id?;
        self.remove_machine(&machine_id).await.err()
    }

    /// Best effort, like every cleanup audit: the member row is the truth.
    async fn audit_member(
        &self,
        pool_id: &str,
        operation: &Operation,
        event: &str,
        vmid: u32,
        facts: &[(&str, String)],
    ) {
        let mut all = vec![("vmid", vmid.to_string())];
        all.extend(facts.iter().cloned());
        let _ = self
            .audit
            .record_intent(&member_audit(
                fleet_auth::LAN_PRINCIPAL_ID,
                pool_id,
                Some(&operation.id),
                event,
                &all,
            ))
            .await;
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
        // FM-717: a lease bound to a pool member reverts it (or keeps it)
        // and is never destroyed. An unreadable binding fails the attempt
        // rather than read as "not pooled", which could destroy a member.
        let member = match &self.pools {
            Some(pools) => match pools.pools.member_for_lease(&lease.id).await {
                Ok(member) => member,
                Err(error) => {
                    return self
                        .fail_attempt(
                            operations,
                            operation,
                            lease,
                            &format!("the lease's pool member is unreadable: {error}"),
                            None,
                        )
                        .await;
                }
            },
            None => None,
        };
        let plan = cleanup_plan(lease.cleanup, member.is_some());
        match (plan, &self.pools, member) {
            (CleanupPlan::Keep, _, _) => {
                self.release(operations, operation, lease, Released::Kept)
                    .await
            }
            (CleanupPlan::NotPooled, _, _) => {
                // A revert lease whose guest is a clone, not a pool member.
                // Refuse without a destroy and without spending an attempt:
                // the lease stays releasing, so an operator can keep it.
                let error = serde_json::json!({
                    "reason": "not_pooled",
                    "detail": "revert cleanup applies only to a lease holding a pool member (FM-717); release the lease with keep, then remove its guest yourself",
                })
                .to_string();
                operations
                    .complete(&operation.id, "failed", None, Some(&error))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            (CleanupPlan::KeepPooled, Some(pools), Some(member)) => {
                self.keep_pooled(operations, operation, pools, lease, &member)
                    .await
            }
            (CleanupPlan::Revert, Some(pools), Some(member)) => {
                self.revert_pooled(operations, operation, pools, lease, &member)
                    .await
            }
            (CleanupPlan::KeepPooled | CleanupPlan::Revert, _, _) => {
                Err("a pooled cleanup without its pool parts".to_owned())
            }
            (CleanupPlan::Destroy, _, _) => self.destroy_clone(operations, operation, lease).await,
        }
    }
}

impl LabCleanupExecutor {
    /// FM-713's destroy of a lease's clone.
    async fn destroy_clone(
        &self,
        operations: &Operations,
        operation: &Operation,
        lease: fleet_core::Lease,
    ) -> Result<(), String> {
        let record = match &lease.provision_id {
            Some(id) => Some(self.provisions.get(id).await?),
            None => None,
        };
        let Some((record, vmid)) = record.and_then(|record| record.vmid.map(|vmid| (record, vmid)))
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
        // FM-717: a pool member is never destroyed, even when no lease
        // binds it any more; an unreadable answer refuses too.
        if let Some(pools) = &self.pools {
            let refusal = match pools.pools.member_by_vmid(&account_id, vmid).await {
                Ok(None) => None,
                Ok(Some(member)) => Some(format!(
                    "VMID {vmid} is a member of pool {}; Lab never destroys a pool member",
                    member.pool_id
                )),
                Err(error) => Some(format!("the pool membership is unreadable: {error}")),
            };
            if let Some(refusal) = refusal {
                return self
                    .fail_attempt(operations, operation, lease, &refusal, guest)
                    .await;
            }
        }
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
            let reason = crate::lab_pool::child_reason(&child);
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
