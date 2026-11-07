//! The Skills Manager setup follow-up (#600): after Fleet sets a machine up,
//! queue a pinned, checksum-verified `skills.probe` so the machine ends with
//! the tested `skills-manager-cli` for its SSH login.
//!
//! The pin comes from the provider's built-in table, chosen by the machine's
//! own `os/family` and `host/architecture` (or fleetd's `os/arch`) facts. The
//! operation is created through [`Operations::create`], so the caller's
//! authorization (`operation.create` on `skills.probe`, and `skills.deploy`
//! on the machine, because a pinned probe installs a binary) and the audit
//! event apply exactly as for an operator's own pinned probe. The probe script installs only when the
//! CLI is absent, so an existing CLI is never replaced.

use std::sync::Arc;

use fleet_application::authz::Authorizer;
use fleet_application::machine::{CAPABILITY_FRESHNESS_MS, MachinePort};
use fleet_application::machine_setup::{MachineSetup, MachineSetupPort, SetupFollowUp, SetupKind};
use fleet_application::operation::{
    NewOperation, OperationUseCaseError, Operations, SETUP_FOLLOW_UP_IDEMPOTENCY_PREFIX,
};
use fleet_application::skills::SkillsPort;
use fleet_core::{CapabilityFact, CapabilityStatus};

/// The deadline of the queued probe: the download is bounded at 120 seconds
/// by the script, and the inventory read follows.
pub const SETUP_PROBE_TIMEOUT_SECONDS: u64 = 300;

/// Queues the pinned Skills Manager install after a machine is set up.
pub struct SkillsManagerSetup {
    machines: Arc<dyn MachinePort>,
    operations: Arc<Operations>,
    /// The Skills Manager observations; an upgrade consults them. Without
    /// them an upgrade never queues.
    snapshots: Option<Arc<dyn SkillsPort>>,
}

impl std::fmt::Debug for SkillsManagerSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkillsManagerSetup").finish_non_exhaustive()
    }
}

impl SkillsManagerSetup {
    /// Composes the hook over the machine records (for the platform facts)
    /// and the operation use cases (for the authorized, audited create).
    #[must_use]
    pub fn new(machines: Arc<dyn MachinePort>, operations: Arc<Operations>) -> Self {
        Self {
            machines,
            operations,
            snapshots: None,
        }
    }

    /// Lets an upgrade (a fleetd install over a live identity) queue the
    /// follow-up when the machine has no Skills Manager observation at all:
    /// the earlier enrolling install then failed before its follow-up. Any
    /// observation, `absent` included (an operator's removal), keeps the
    /// upgrade skipped.
    #[must_use]
    pub fn with_snapshots(mut self, snapshots: Arc<dyn SkillsPort>) -> Self {
        self.snapshots = Some(snapshots);
        self
    }

    /// Whether an upgrade still owes the follow-up, or why not.
    async fn upgrade_owes_follow_up(&self, machine_id: &str) -> Result<(), SetupFollowUp> {
        const OBSERVED: &str = "a fleetd upgrade does not set the machine up again, and Skills Manager was already observed on this machine";
        let Some(snapshots) = &self.snapshots else {
            return Err(SetupFollowUp::Skipped {
                reason: "a fleetd upgrade does not set the machine up again, and this controller cannot read Skills Manager observations to tell whether an earlier setup was missed".to_owned(),
            });
        };
        match snapshots.get(machine_id).await {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(SetupFollowUp::Skipped {
                reason: OBSERVED.to_owned(),
            }),
            Err(failure) => Err(SetupFollowUp::Failed {
                reason: format!("the Skills Manager observation is unreadable: {failure}"),
            }),
        }
    }

    /// The pinned probe payload for one machine, or why there is none.
    async fn payload(&self, setup: &MachineSetup) -> Result<serde_json::Value, SetupFollowUp> {
        let machine = self
            .machines
            .get(&setup.machine_id)
            .await
            .map_err(|failure| SetupFollowUp::Failed {
                reason: format!("the machine is unreadable: {failure}"),
            })?;
        let now =
            fleet_core::Timestamp::from_unix_millis(fleet_core::SystemClock::now_unix_millis());
        let family = freshest_fact(&machine.capabilities, &[("os", "family")], now);
        // Agentless inventory reports `host/architecture` (`uname -m`);
        // fleetd reports `os/arch` (Rust's `std::env::consts::ARCH`, the
        // same spellings for the pinned platforms). A machine can carry
        // both, so the freshest known observation wins.
        let architecture = freshest_fact(
            &machine.capabilities,
            &[("host", "architecture"), ("os", "arch")],
            now,
        );
        let pin =
            fleet_provider_skills_manager::release_pin(family.as_deref(), architecture.as_deref())
                .map_err(|why| SetupFollowUp::Skipped {
                    reason: why.to_string(),
                })?;
        Ok(serde_json::json!({
            "machineId": setup.machine_id,
            "endpointId": setup.endpoint_id,
            "auth": setup.auth,
            "artifactUrl": pin.url,
            "artifactSha256": pin.sha256,
            "timeoutSeconds": SETUP_PROBE_TIMEOUT_SECONDS,
        }))
    }
}

/// The value of the best observation among `names`, ranked by each fact's
/// effective status at `now` (the read model's staleness rule: a `known`
/// fact older than [`CAPABILITY_FRESHNESS_MS`] reads as `stale`): a fresh
/// known fact over a stale one, then the newest `observed_at`. Other
/// statuses carry no value worth acting on.
fn freshest_fact(
    facts: &[CapabilityFact],
    names: &[(&str, &str)],
    now: fleet_core::Timestamp,
) -> Option<String> {
    facts
        .iter()
        .filter(|fact| {
            fact.value.is_some()
                && names
                    .iter()
                    .any(|(namespace, name)| fact.namespace == *namespace && fact.name == *name)
        })
        .filter_map(|fact| {
            let status = fact.effective_status(now, CAPABILITY_FRESHNESS_MS);
            matches!(status, CapabilityStatus::Known | CapabilityStatus::Stale)
                .then_some((status == CapabilityStatus::Known, fact))
        })
        .max_by_key(|(known, fact)| (*known, fact.observed_at.unix_millis()))
        .and_then(|(_, fact)| fact.value.clone())
}

/// Whether the operation a setup key answered with is the follow-up this
/// setup would have created: a `skills.probe` for the same machine and pin.
fn is_our_follow_up(
    operation: &fleet_application::operation::Operation,
    payload: &serde_json::Value,
) -> bool {
    if operation.kind != "skills.probe" {
        return false;
    }
    let Some(existing) = operation
        .payload_json
        .as_deref()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
    else {
        return false;
    };
    ["machineId", "artifactUrl", "artifactSha256"]
        .iter()
        .all(|field| existing[*field] == payload[*field])
}

#[async_trait::async_trait]
impl MachineSetupPort for SkillsManagerSetup {
    async fn machine_set_up(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        setup: &MachineSetup,
    ) -> SetupFollowUp {
        if setup.kind == SetupKind::Upgrade
            && let Err(outcome) = self.upgrade_owes_follow_up(&setup.machine_id).await
        {
            return outcome;
        }
        let payload = match self.payload(setup).await {
            Ok(payload) => payload,
            Err(outcome) => return outcome,
        };
        let new = NewOperation {
            kind: "skills.probe".to_owned(),
            idempotency_key: Some(format!(
                "{SETUP_FOLLOW_UP_IDEMPOTENCY_PREFIX}{}",
                setup.trigger
            )),
            deadline_at: None,
            correlation_id: setup.correlation_id.clone(),
            payload_json: Some(payload.to_string()),
            review_token: None,
        };
        match self
            .operations
            .create_setup_follow_up(authorizer, principal_id, &new)
            .await
        {
            // The key can answer with an existing operation; it counts only
            // when it is this very follow-up (the generic route cannot use
            // the prefix, so this is defense in depth).
            Ok(operation) if is_our_follow_up(&operation, &payload) => SetupFollowUp::Queued {
                operation_id: operation.id,
                version: fleet_provider_skills_manager::PINNED_CLI_VERSION.to_owned(),
            },
            Ok(_) => SetupFollowUp::Failed {
                reason: "the setup key is held by another operation; nothing was queued".to_owned(),
            },
            // A backend failure can come after the row was inserted (the
            // audit write failed), so the outcome is uncertain.
            Err(error @ OperationUseCaseError::Backend { .. }) => SetupFollowUp::Failed {
                reason: format!("the Skills Manager install may not have been queued: {error}"),
            },
            Err(error) => SetupFollowUp::Failed {
                reason: format!("the Skills Manager install could not be queued: {error}"),
            },
        }
    }
}
