//! Follow-up work after Fleet sets a machine up (#600).
//!
//! A machine is "set up" when `machine.install-fleetd` succeeds or an SSH
//! onboarding `add` registers it. Both paths call a [`MachineSetupPort`]
//! afterwards; the controller's adapter queues a pinned, checksum-verified
//! Skills Manager install through the normal authorized, audited operation
//! path. The follow-up is best effort by contract: it answers with a
//! [`SetupFollowUp`] instead of an error, so a failed follow-up can never
//! fail the install or the add that triggered it.

use serde::{Deserialize, Serialize};

use crate::authz::Authorizer;
use crate::onboarding::OnboardAuth;

/// The machine that was just set up, and how the controller reaches it.
#[derive(Clone, Debug)]
pub struct MachineSetup {
    /// The machine's identity.
    pub machine_id: String,
    /// The SSH endpoint the follow-up runs over.
    pub endpoint_id: String,
    /// How the controller authenticates to that endpoint.
    pub auth: OnboardAuth,
    /// A stable identity of the setup event (the install operation's id, or
    /// the onboarded machine's id). The follow-up uses it as an idempotency
    /// key, so a retried setup does not queue a second follow-up, and the
    /// follow-up's audit names it.
    pub trigger: String,
    /// The correlation identity the follow-up joins, so its operation and
    /// audit trace back to the setup (the install operation's correlation id,
    /// or its id when it has none).
    pub correlation_id: Option<String>,
}

/// What the follow-up did. Serialized into the install operation's result as
/// `skillsManager`; every reason is caller-safe text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "status"
)]
pub enum SetupFollowUp {
    /// The follow-up operation was queued.
    Queued {
        /// The queued operation's id.
        operation_id: String,
        /// The CLI version the pinned release installs.
        version: String,
    },
    /// Nothing was queued, by rule: e.g. the platform has no pinned release.
    Skipped {
        /// Why.
        reason: String,
    },
    /// The controller setting turned the follow-up off.
    Disabled,
    /// Queueing was attempted and failed (denied, invalid, backend).
    Failed {
        /// Why, caller-safe.
        reason: String,
    },
}

/// The hook run after a machine is set up.
#[async_trait::async_trait]
pub trait MachineSetupPort: std::fmt::Debug + Send + Sync {
    /// Runs the follow-up as `principal_id` under `authorizer`. Never fails:
    /// the outcome, including a failure, is the answer.
    async fn machine_set_up(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        setup: &MachineSetup,
    ) -> SetupFollowUp;
}
