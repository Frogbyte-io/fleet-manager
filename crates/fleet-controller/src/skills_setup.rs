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
use fleet_application::machine::MachinePort;
use fleet_application::machine_setup::{MachineSetup, MachineSetupPort, SetupFollowUp};
use fleet_application::operation::{NewOperation, Operations};

/// The deadline of the queued probe: the download is bounded at 120 seconds
/// by the script, and the inventory read follows.
pub const SETUP_PROBE_TIMEOUT_SECONDS: u64 = 300;

/// The idempotency-key prefix of a setup follow-up.
pub const SETUP_IDEMPOTENCY_PREFIX: &str = "skills-manager-setup:";

/// Queues the pinned Skills Manager install after a machine is set up.
#[derive(Debug)]
pub struct SkillsManagerSetup {
    machines: Arc<dyn MachinePort>,
    operations: Arc<Operations>,
}

impl SkillsManagerSetup {
    /// Composes the hook over the machine records (for the platform facts)
    /// and the operation use cases (for the authorized, audited create).
    #[must_use]
    pub fn new(machines: Arc<dyn MachinePort>, operations: Arc<Operations>) -> Self {
        Self {
            machines,
            operations,
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
        let fact = |namespace: &str, name: &str| -> Option<String> {
            machine
                .capabilities
                .iter()
                .find(|candidate| {
                    candidate.namespace == namespace
                        && candidate.name == name
                        && matches!(
                            candidate.status,
                            fleet_core::CapabilityStatus::Known
                                | fleet_core::CapabilityStatus::Stale
                        )
                })
                .and_then(|candidate| candidate.value.clone())
        };
        let family = fact("os", "family");
        // Agentless inventory reports `host/architecture` (`uname -m`);
        // fleetd reports `os/arch` (Rust's `std::env::consts::ARCH`, the
        // same spellings for the pinned platforms).
        let architecture = fact("host", "architecture").or_else(|| fact("os", "arch"));
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

#[async_trait::async_trait]
impl MachineSetupPort for SkillsManagerSetup {
    async fn machine_set_up(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        setup: &MachineSetup,
    ) -> SetupFollowUp {
        let payload = match self.payload(setup).await {
            Ok(payload) => payload,
            Err(outcome) => return outcome,
        };
        let new = NewOperation {
            kind: "skills.probe".to_owned(),
            idempotency_key: Some(format!("{SETUP_IDEMPOTENCY_PREFIX}{}", setup.trigger)),
            deadline_at: None,
            correlation_id: None,
            payload_json: Some(payload.to_string()),
            review_token: None,
        };
        match self.operations.create(authorizer, principal_id, &new).await {
            Ok(operation) => SetupFollowUp::Queued {
                operation_id: operation.id,
                version: fleet_provider_skills_manager::PINNED_CLI_VERSION.to_owned(),
            },
            Err(error) => SetupFollowUp::Failed {
                reason: format!("the Skills Manager install could not be queued: {error}"),
            },
        }
    }
}
