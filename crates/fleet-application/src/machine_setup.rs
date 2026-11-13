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

/// What set the machine up.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupKind {
    /// The machine was set up for the first time, or set up again on
    /// purpose: an onboarding add, or a fleetd install that enrolled the
    /// node (first or forced enrollment).
    Initial,
    /// A fleetd install over a live node identity. It is not a new setup, so
    /// a follow-up must not undo what the operator changed since (e.g. a
    /// removed CLI); it applies only when the earlier setup never got as far
    /// as the follow-up (e.g. an enrolled install that failed before it).
    Upgrade,
}

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
    /// What set the machine up.
    pub kind: SetupKind,
}

/// What the follow-up did. Serialized into the install operation's result as
/// `skillsManager`. The non-failure reasons are caller-safe text; a `Failed`
/// reason may carry a backend detail, so anything returned or stored for a
/// caller goes through [`SetupFollowUp::public`] first.
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
    /// Queueing was attempted and failed (denied, invalid, backend), or
    /// timed out, so the operation may or may not exist.
    Failed {
        /// Why. Safe to log, not to return: a backend failure carries its
        /// error text. Callers see [`SetupFollowUp::public`] instead.
        reason: String,
    },
}

/// What a failed follow-up reports to callers. Uncertain on purpose: a
/// backend failure after the insert, or a timeout, can leave the operation
/// queued.
pub const FAILED_PUBLIC_REASON: &str =
    "the Skills Manager install may not have been queued; the detail is in the controller log";

impl SetupFollowUp {
    /// The form an API response or a stored operation result may carry: a
    /// failure's reason is replaced with [`FAILED_PUBLIC_REASON`] (log the
    /// original first); the other outcomes are caller-safe already.
    #[must_use]
    pub fn public(self) -> Self {
        match self {
            Self::Failed { .. } => Self::Failed {
                reason: FAILED_PUBLIC_REASON.to_owned(),
            },
            other => other,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_form_never_carries_a_failure_detail() {
        let failed = SetupFollowUp::Failed {
            reason: "backend: pool timed out while waiting for an open connection".to_owned(),
        };
        assert_eq!(
            failed.public(),
            SetupFollowUp::Failed {
                reason: FAILED_PUBLIC_REASON.to_owned()
            }
        );
        let skipped = SetupFollowUp::Skipped {
            reason: "no pinned release".to_owned(),
        };
        assert_eq!(skipped.clone().public(), skipped);
        assert_eq!(SetupFollowUp::Disabled.public(), SetupFollowUp::Disabled);
    }
}
