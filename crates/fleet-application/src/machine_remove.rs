//! Removing a machine from Fleet (#616): the reviewed, payload-bound use case
//! behind `fleetctl machines remove`.
//!
//! A removal deletes the machine record and everything that is only a fact
//! about it, and leaves everything that is history. The rules live here; the
//! API route, `fleetctl` and the controller's uninstall adapter are adapters.
//!
//! - **Authorization.** `machine.delete`, resource = the machine id, through
//!   the central [`authorize`] funnel, on the review and on the removal. The
//!   permission is risky and no delegated (Lab) credential carries it.
//! - **Reviewed and payload-bound.** A review reads the machine and answers
//!   what the removal will do and a token over it: the machine, its
//!   endpoints, the hosts whose pinned keys go and the hosts that keep them,
//!   the counts of stored SSH keys and Windows administrator passwords the
//!   removal destroys, and the optional uninstall (endpoint, authentication
//!   and the install layout it uses). The removal recomputes the same payload
//!   and refuses a token that no longer matches.
//! - **Refused while something holds the machine.** A Lab provision record
//!   (Lab cleanup owns the record), a persistent marker (the persistent
//!   unregister or destroy flow owns it), a live USB reservation the machine
//!   owns (detach first), and a pending, running or cancelling operation on
//!   the machine. A controller without a secret store also refuses a machine
//!   that has stored secrets, because it could not revoke them. The review
//!   lists every hold with what to do. The delete itself re-checks the Lab,
//!   persistent, USB and operation holds in the same statement as the delete
//!   ([`MachineRemovalPort::delete_unheld`]), so a hold taken after the review
//!   or during the uninstall still refuses.
//! - **What goes.** The record and everything that cascades from it:
//!   endpoints and their stored default authentication, capability facts,
//!   inventory snapshots, tags, groups, the node identity with its
//!   credentials, sessions, challenges and enrollment tokens, project
//!   checkout observations, the Skills Manager snapshot, recorded catalog
//!   skill installs and a confirmed guest link. The keys and rotated
//!   passwords bound to the machine are revoked, a live node gateway session
//!   is closed, and the pinned host keys of its SSH hosts are removed from
//!   the Fleet known-hosts file unless another machine's endpoint or an
//!   onboarding draft uses the same host, checked again after the delete.
//! - **What stays.** The audit trail, finished operations, released hardware
//!   reservations, action requests, collected files (until their retention
//!   pass) and Fleet Git (the Registry) are history and are not touched.
//! - **Nothing on the machine is touched** unless the caller asks for the
//!   uninstall: then the shipped fleetd uninstall (`deploy/fleetd/uninstall.sh
//!   --purge`) runs over SSH first, and a failed uninstall leaves the machine
//!   registered.
//!
//! Every step is audited under `machine.delete`, with the request's
//! correlation id and without secrets: the uninstall's start and result, the
//! delete, the secret revocation when it fails, and a summary of the removal.
#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::audit::{AuditIntent, AuditMetadata};
use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::machine::{Machine, MachinePort};
use crate::machine_access::{EndpointAuth, EndpointAuthPort, MachineKeyPort};
use crate::machine_usb::MachineHardwareGate;
use crate::onboarding::{OnboardTrustPort, reference_host};
use crate::operation::{AuditPort, PortFailure, review_token_for};
use fleet_core::EndpointKind;

/// The review-token kind of a removal.
pub const REMOVE_KIND: &str = "machine.remove";

pub use crate::fleetd_layout::LAYOUT_VARIABLES;

/// The uninstall the caller asked for, as the request carries it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UninstallRequest {
    /// The machine's SSH endpoint the uninstall runs over.
    pub endpoint_id: String,
    /// How to authenticate; absent means the endpoint's stored default, or
    /// the controller's agent when it has none.
    pub auth: Option<EndpointAuth>,
}

/// The uninstall a removal will run, with the authentication resolved.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UninstallPlan {
    /// The SSH endpoint.
    pub endpoint_id: String,
    /// The authentication it uses.
    pub auth: EndpointAuth,
    /// The installer layout overrides of the machine's last successful
    /// fleetd install (empty for the default layout).
    pub layout: BTreeMap<String, String>,
}

/// What the uninstall port is asked to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FleetdUninstall {
    /// The machine.
    pub machine_id: String,
    /// The SSH endpoint, authentication and layout.
    pub plan: UninstallPlan,
}

/// Runs the fleetd uninstall on a machine over SSH. The controller implements
/// it over the SSH provider and the shipped `deploy/fleetd/uninstall.sh`.
#[async_trait]
pub trait FleetdUninstallPort: fmt::Debug + Send + Sync {
    /// Runs the uninstall and answers its last line of output.
    ///
    /// # Errors
    ///
    /// Fails, with a scrubbed and bounded detail, when the endpoint cannot be
    /// reached or trusted, no fleetd service is found in the layout, or the
    /// script does not exit 0.
    async fn uninstall(&self, request: &FleetdUninstall) -> Result<String, String>;
}

/// Closes a machine's live node gateway session after the machine is gone.
#[async_trait]
pub trait NodeSessionPort: fmt::Debug + Send + Sync {
    /// Closes the session, if one is open; answers whether one was.
    async fn close(&self, machine_id: &str) -> bool;
}

/// A Lab provision record that names the machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabProvisionHold {
    /// The provision.
    pub provision_id: String,
    /// Its state.
    pub state: String,
    /// The lease that owns it, only when the lease links back to this
    /// provision (`provision_id`).
    pub lease_id: Option<String>,
    /// The owning lease's state.
    pub lease_state: Option<String>,
}

/// A persistent marker that names the machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistentMarkerHold {
    /// The Proxmox account.
    pub account_id: String,
    /// The guest's VMID.
    pub vmid: u32,
    /// The marked name.
    pub name: String,
    /// Whether the VM was registered (rather than created by Fleet).
    pub registered: bool,
}

/// An operation on the machine that has not finished.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveOperationHold {
    /// The operation.
    pub id: String,
    /// Its kind.
    pub kind: String,
    /// Its state: `pending`, `running` or `cancelling`.
    pub state: String,
}

/// The records a removal deletes, and the collected files it keeps, counted
/// for the review. The secret counts are bound by the review token; the rest
/// move with inventory and are informational.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovalFootprint {
    /// Endpoints.
    pub endpoints: u64,
    /// Stored default endpoint authentication records.
    pub endpoint_auth: u64,
    /// Endpoints whose stored default authentication is a stored key.
    pub endpoint_auth_secrets: u64,
    /// Capability facts.
    pub capabilities: u64,
    /// Inventory snapshots.
    pub inventory_snapshots: u64,
    /// Tag and group memberships.
    pub tags_and_groups: u64,
    /// Node identity records (0 or 1).
    pub node_identity: u64,
    /// Node credentials, sessions, challenges and enrollment tokens.
    pub node_credentials: u64,
    /// Project checkout observations.
    pub project_checkouts: u64,
    /// Skills Manager snapshots (0 or 1).
    pub skills_snapshot: u64,
    /// Recorded catalog skill installs.
    pub catalog_skill_installs: u64,
    /// Confirmed Proxmox guest links (0 or 1).
    pub guest_link: u64,
    /// SSH private keys Fleet holds for this machine (revoked).
    pub stored_ssh_keys: u64,
    /// Rotated Windows administrator passwords Fleet holds for this machine
    /// (destroyed: nobody can read them afterwards).
    pub admin_passwords: u64,
    /// Collected files kept until their retention pass (not deleted).
    pub collected_files_kept: u64,
}

impl RemovalFootprint {
    /// The secrets bound to this machine that the removal revokes. An
    /// endpoint's stored-key reference can name a fleet-wide key the removal
    /// never touches, so it does not count.
    fn machine_secrets(&self) -> u64 {
        self.stored_ssh_keys + self.admin_passwords
    }
}

/// What the store answers about a machine before it is removed, and the
/// guarded delete.
#[async_trait]
pub trait MachineRemovalPort: fmt::Debug + Send + Sync {
    /// The Lab provision records that name the machine.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read; the removal then refuses.
    async fn lab_provisions(&self, machine_id: &str) -> Result<Vec<LabProvisionHold>, String>;

    /// The persistent markers that name the machine.
    ///
    /// # Errors
    ///
    /// As [`Self::lab_provisions`].
    async fn persistent_markers(
        &self,
        machine_id: &str,
    ) -> Result<Vec<PersistentMarkerHold>, String>;

    /// The pending, running and cancelling operations whose payload names
    /// the machine (`machineId`).
    ///
    /// # Errors
    ///
    /// As [`Self::lab_provisions`].
    async fn active_operations(&self, machine_id: &str)
    -> Result<Vec<ActiveOperationHold>, String>;

    /// The SSH endpoint references of every other machine and the hosts of
    /// every onboarding draft: whoever else still needs a host's pins.
    ///
    /// # Errors
    ///
    /// As [`Self::lab_provisions`].
    async fn other_host_users(&self, machine_id: &str) -> Result<OtherHostUsers, String>;

    /// The records the removal deletes, counted.
    ///
    /// # Errors
    ///
    /// As [`Self::lab_provisions`].
    async fn footprint(&self, machine_id: &str) -> Result<RemovalFootprint, String>;

    /// The installer layout overrides ([`LAYOUT_VARIABLES`]) of the
    /// machine's last successful fleetd install.
    ///
    /// # Errors
    ///
    /// As [`Self::lab_provisions`].
    async fn install_layout(&self, machine_id: &str) -> Result<BTreeMap<String, String>, String>;

    /// Deletes the machine in one statement that also requires no Lab
    /// provision, persistent marker, live USB reservation or unfinished
    /// operation to name it.
    ///
    /// # Errors
    ///
    /// The [`GuardedDeleteError`] that says why nothing was deleted.
    async fn delete_unheld(&self, machine_id: &str) -> Result<(), GuardedDeleteError>;
}

/// Why the guarded delete deleted nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuardedDeleteError {
    /// The machine does not exist.
    NotFound,
    /// A hold names the machine; the sentence names the hold.
    Held(String),
    /// The delete was refused, but no hold was found when it was looked for
    /// and the machine still exists: a hold came and went. Retrying is safe.
    Raced,
    /// The store failed.
    Backend(String),
}

/// Who else uses a host, as the store reports it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OtherHostUsers {
    /// `user@host:port` references of other machines' SSH endpoints.
    pub endpoint_references: Vec<String>,
    /// The hosts of onboarding drafts.
    pub draft_hosts: Vec<String>,
}

impl OtherHostUsers {
    /// The hosts in use, lower-cased.
    fn hosts(&self) -> BTreeSet<String> {
        self.endpoint_references
            .iter()
            .filter_map(|reference| reference_host(reference))
            .chain(self.draft_hosts.iter().map(String::as_str))
            .map(str::to_ascii_lowercase)
            .collect()
    }
}

/// Why a removal is refused, with what to do about it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovalBlocker {
    /// `lab_provision`, `persistent_marker`, `hardware_reservation`,
    /// `active_operation` or `stored_secret`.
    pub kind: String,
    /// The holding record's id.
    pub id: String,
    /// Its state.
    pub state: String,
    /// The refusal and what to do, as a sentence.
    pub detail: String,
}

/// One of the machine's endpoints, as the review shows it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewedEndpoint {
    /// The endpoint.
    pub id: String,
    /// `ssh` or `fleetd`.
    pub kind: String,
    /// The SSH host, when it is an SSH endpoint.
    pub host: Option<String>,
}

/// What a review found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemovalReview {
    /// The token the removal must present; absent while something blocks it.
    pub review_token: Option<String>,
    /// The machine.
    pub machine_id: String,
    /// Its name.
    pub name: String,
    /// Its endpoints.
    pub endpoints: Vec<ReviewedEndpoint>,
    /// The node identity's status (`active` or `revoked`), when it has one.
    pub node_identity: Option<String>,
    /// The hosts whose pinned keys the removal deletes.
    pub unpin_hosts: Vec<String>,
    /// The hosts whose pins stay because another machine or a draft uses
    /// them.
    pub kept_hosts: Vec<String>,
    /// The uninstall the removal runs first, when asked.
    pub uninstall: Option<UninstallPlan>,
    /// What the removal deletes and keeps.
    pub footprint: RemovalFootprint,
    /// What the caller must know before confirming (a destroyed Windows
    /// administrator password).
    pub warnings: Vec<String>,
    /// What refuses the removal now.
    pub blockers: Vec<RemovalBlocker>,
}

/// What a removal did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemovalOutcome {
    /// The machine that was removed.
    pub machine_id: String,
    /// Its name.
    pub name: String,
    /// Whether fleetd was uninstalled first.
    pub uninstalled: bool,
    /// The uninstall's last line of output, when it ran.
    pub uninstall_summary: Option<String>,
    /// Whether a node identity was deleted with the machine.
    pub node_identity_removed: bool,
    /// Whether a live node gateway session was closed.
    pub session_closed: bool,
    /// The stored secrets bound to the machine that were revoked.
    pub secrets_revoked: u64,
    /// Why the revocation of the machine's stored secrets failed, when it
    /// did; the machine is gone and the secrets must be deleted by hand.
    pub secret_revocation_error: Option<String>,
    /// The hosts whose pins were removed.
    pub unpinned_hosts: Vec<String>,
    /// The hosts whose pins stayed because they are shared, including hosts
    /// another machine or draft started using during the removal.
    pub kept_hosts: Vec<String>,
    /// The hosts whose pins could not be removed (the machine is gone; the
    /// pin is left for the operator to remove).
    pub unpin_failed_hosts: Vec<String>,
    /// The audit events that could not be written (the removal went on).
    pub audit_gaps: Vec<String>,
    /// What was deleted.
    pub footprint: RemovalFootprint,
}

/// A refusal of a removal.
#[derive(Debug)]
pub enum MachineRemovalError {
    /// The caller may not remove machines.
    Denied(Decision),
    /// The machine does not exist.
    NotFound {
        /// What was not found.
        what: String,
    },
    /// The request is malformed, or the review token does not match.
    Invalid {
        /// What is wrong.
        detail: String,
    },
    /// Something holds the machine.
    Blocked {
        /// Every hold.
        blockers: Vec<RemovalBlocker>,
    },
    /// A hold appeared after the review (the guarded delete refused it), or
    /// the recorded install layout is not safe to uninstall with.
    Conflict {
        /// The hold.
        detail: String,
    },
    /// Another removal of the machine is in progress, or a hold came and
    /// went during the delete. Nothing was deleted; retrying is safe.
    Busy {
        /// What happened.
        detail: String,
    },
    /// The uninstall was asked for but the controller cannot run it.
    UninstallUnavailable,
    /// The uninstall failed; the machine was not removed.
    UninstallFailed {
        /// The scrubbed failure detail.
        detail: String,
    },
    /// A port failed.
    Backend {
        /// Where.
        context: &'static str,
        /// The detail.
        detail: String,
    },
}

impl fmt::Display for MachineRemovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Invalid { detail } => write!(f, "invalid request: {detail}"),
            Self::Blocked { blockers } => {
                write!(f, "the machine cannot be removed: ")?;
                let details: Vec<&str> = blockers.iter().map(|b| b.detail.as_str()).collect();
                write!(f, "{}", details.join("; "))
            }
            Self::Conflict { detail } => write!(f, "conflict: {detail}"),
            Self::Busy { detail } => write!(f, "busy: {detail}"),
            Self::UninstallUnavailable => write!(
                f,
                "the controller cannot run the fleetd uninstall (no SSH executor is wired); remove without --uninstall and uninstall by hand"
            ),
            Self::UninstallFailed { detail } => write!(
                f,
                "the fleetd uninstall failed, so the machine was not removed: {detail}"
            ),
            Self::Backend { context, detail } => {
                write!(f, "machine removal {context} failed: {detail}")
            }
        }
    }
}

impl std::error::Error for MachineRemovalError {}

fn backend(context: &'static str) -> impl FnOnce(String) -> MachineRemovalError {
    move |detail| MachineRemovalError::Backend { context, detail }
}

/// The removal use case.
#[derive(Debug)]
pub struct MachineRemoval {
    records: Arc<dyn MachinePort>,
    store: Arc<dyn MachineRemovalPort>,
    hardware: Arc<dyn MachineHardwareGate>,
    trust: Arc<dyn OnboardTrustPort>,
    audit: Arc<dyn AuditPort>,
    keys: Option<Arc<dyn MachineKeyPort>>,
    endpoint_auth: Option<Arc<dyn EndpointAuthPort>>,
    uninstaller: Option<Arc<dyn FleetdUninstallPort>>,
    sessions: Option<Arc<dyn NodeSessionPort>>,
    /// The machines a removal is running for, so a second removal of the
    /// same machine waits for nothing and is refused.
    in_progress: std::sync::Mutex<BTreeSet<String>>,
}

/// Holds a machine in [`MachineRemoval::in_progress`] until it is dropped.
struct InProgress<'a> {
    set: &'a std::sync::Mutex<BTreeSet<String>>,
    machine_id: String,
}

impl Drop for InProgress<'_> {
    fn drop(&mut self) {
        if let Ok(mut set) = self.set.lock() {
            set.remove(&self.machine_id);
        }
    }
}

impl MachineRemoval {
    /// Composes the use case: `records` reads the machine, `store` answers
    /// the holds and performs the guarded delete, `trust` removes pins.
    #[must_use]
    pub fn new(
        records: Arc<dyn MachinePort>,
        store: Arc<dyn MachineRemovalPort>,
        hardware: Arc<dyn MachineHardwareGate>,
        trust: Arc<dyn OnboardTrustPort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            records,
            store,
            hardware,
            trust,
            audit,
            keys: None,
            endpoint_auth: None,
            uninstaller: None,
            sessions: None,
            in_progress: std::sync::Mutex::new(BTreeSet::new()),
        }
    }

    /// Revokes the keys and rotated passwords bound to a removed machine.
    /// Without it (no secret store) a machine with stored secrets is refused.
    #[must_use]
    pub fn with_key_revocation(mut self, keys: Arc<dyn MachineKeyPort>) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Reads an endpoint's stored default authentication for an uninstall
    /// that names none.
    #[must_use]
    pub fn with_endpoint_auth(mut self, auths: Arc<dyn EndpointAuthPort>) -> Self {
        self.endpoint_auth = Some(auths);
        self
    }

    /// Enables `--uninstall`.
    #[must_use]
    pub fn with_uninstaller(mut self, uninstaller: Arc<dyn FleetdUninstallPort>) -> Self {
        self.uninstaller = Some(uninstaller);
        self
    }

    /// Closes a removed machine's live gateway session.
    #[must_use]
    pub fn with_sessions(mut self, sessions: Arc<dyn NodeSessionPort>) -> Self {
        self.sessions = Some(sessions);
        self
    }

    /// Reviews removing a machine: what goes, what stays, which pins are
    /// removed, and what holds the machine. Nothing is written.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown machine, an uninstall endpoint that is not
    /// one of the machine's SSH endpoints, an uninstall the controller cannot
    /// run, or a store failure.
    pub async fn review(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
        uninstall: Option<&UninstallRequest>,
    ) -> Result<RemovalReview, MachineRemovalError> {
        self.authorize(authorizer, principal, machine_id)?;
        self.assess(machine_id, uninstall).await
    }

    /// Removes a reviewed machine: re-checks every hold, runs the uninstall
    /// when asked (a failure leaves the machine), deletes the record in a
    /// statement that refuses any hold, revokes its stored secrets, closes
    /// its gateway session, and removes the pins of hosts nobody else uses
    /// after the delete. Audited.
    ///
    /// Callers that can be cancelled (an HTTP request) should run this to
    /// completion on its own task, so a dropped request never leaves an
    /// uninstall running unobserved.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown machine, a review token that does not
    /// match, a hold, a failed uninstall, or a store failure.
    pub async fn remove(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
        uninstall: Option<&UninstallRequest>,
        review_token: &str,
        correlation_id: Option<&str>,
    ) -> Result<RemovalOutcome, MachineRemovalError> {
        self.authorize(authorizer, principal, machine_id)?;
        // One removal per machine at a time, held across the uninstall and
        // the delete: a second one is refused, never interleaved.
        let _running = self.claim(machine_id)?;
        let review = self.assess(machine_id, uninstall).await?;
        if !review.blockers.is_empty() {
            return Err(MachineRemovalError::Blocked {
                blockers: review.blockers,
            });
        }
        if review.review_token.as_deref() != Some(review_token) {
            return Err(MachineRemovalError::Invalid {
                detail: "the review token does not match this machine as it is now (its endpoints, shared hosts, stored secrets or the uninstall changed, or the token is for another request); review the removal again".to_owned(),
            });
        }
        let audit = Recorder {
            audit: self.audit.as_ref(),
            principal,
            machine_id,
            correlation_id,
        };

        let summary = match &review.uninstall {
            Some(plan) => Some(self.uninstall(&audit, machine_id, plan).await?),
            None => None,
        };

        // One statement deletes the machine only while nothing holds it: a
        // hold taken after the review, or during the uninstall, refuses here.
        self.store
            .delete_unheld(machine_id)
            .await
            .map_err(|failure| match failure {
                GuardedDeleteError::NotFound => MachineRemovalError::NotFound {
                    what: format!("machine {machine_id:?}"),
                },
                GuardedDeleteError::Held(detail) => MachineRemovalError::Conflict { detail },
                GuardedDeleteError::Raced => MachineRemovalError::Busy {
                    detail: format!(
                        "the delete of machine {machine_id} was refused by a hold that is gone now; nothing was deleted; review the removal again"
                    ),
                },
                GuardedDeleteError::Backend(detail) => MachineRemovalError::Backend {
                    context: "delete",
                    detail,
                },
            })?;
        Ok(self.finish(&audit, review, summary).await)
    }

    /// Everything after the delete. The machine is gone, so nothing here
    /// fails the removal: a step that fails (an audit write, the secret
    /// revocation, an unpin) is logged and reported in the outcome.
    async fn finish(
        &self,
        audit: &Recorder<'_>,
        review: RemovalReview,
        summary: Option<String>,
    ) -> RemovalOutcome {
        let machine_id = audit.machine_id;
        let mut audit_gaps = Vec::new();
        if let Err(error) = audit
            .record(&[
                ("event", "machine_deleted"),
                ("name", &review.name),
                ("endpoints", &review.endpoints.len().to_string()),
            ])
            .await
        {
            eprintln!("machine removal {machine_id}: the delete was not audited: {error}");
            audit_gaps.push("machine_deleted".to_owned());
        }

        let (secrets_revoked, secret_revocation_error) = self
            .revoke_secrets(audit, machine_id, &mut audit_gaps)
            .await;
        let session_closed = match &self.sessions {
            Some(sessions) => sessions.close(machine_id).await,
            None => false,
        };
        let (unpinned, kept, failed) = self.unpin(machine_id, &review).await;

        let node = review
            .node_identity
            .clone()
            .unwrap_or_else(|| "none".to_owned());
        let gaps = if audit_gaps.is_empty() {
            "none".to_owned()
        } else {
            audit_gaps.join(",")
        };
        if let Err(error) = audit
            .record(&[
                ("event", "machine_removed"),
                ("name", &review.name),
                ("endpoints", &review.endpoints.len().to_string()),
                ("nodeIdentity", &node),
                ("sessionClosed", bool_text(session_closed)),
                ("uninstalled", bool_text(review.uninstall.is_some())),
                ("hostsUnpinned", &unpinned.len().to_string()),
                ("hostsKept", &kept.len().to_string()),
                ("hostsUnpinFailed", &failed.len().to_string()),
                ("credentialsRevoked", &secrets_revoked.to_string()),
                (
                    "credentialRevocationFailed",
                    bool_text(secret_revocation_error.is_some()),
                ),
                (
                    "skillInstallsDropped",
                    &review.footprint.catalog_skill_installs.to_string(),
                ),
                ("auditGaps", &gaps),
            ])
            .await
        {
            eprintln!("machine removal {machine_id}: the summary was not audited: {error}");
            audit_gaps.push("machine_removed".to_owned());
        }
        RemovalOutcome {
            machine_id: review.machine_id,
            name: review.name,
            uninstalled: review.uninstall.is_some(),
            uninstall_summary: summary,
            node_identity_removed: review.node_identity.is_some(),
            session_closed,
            secrets_revoked,
            secret_revocation_error,
            unpinned_hosts: unpinned,
            kept_hosts: kept,
            unpin_failed_hosts: failed,
            audit_gaps,
            footprint: review.footprint,
        }
    }

    fn claim(&self, machine_id: &str) -> Result<InProgress<'_>, MachineRemovalError> {
        let mut set = self
            .in_progress
            .lock()
            .map_err(|_| MachineRemovalError::Backend {
                context: "in_progress",
                detail: "the removal registry is poisoned".to_owned(),
            })?;
        if !set.insert(machine_id.to_owned()) {
            return Err(MachineRemovalError::Busy {
                detail: format!(
                    "a removal of machine {machine_id} is already in progress; wait for it to finish"
                ),
            });
        }
        Ok(InProgress {
            set: &self.in_progress,
            machine_id: machine_id.to_owned(),
        })
    }

    /// Revokes the machine's bound secrets. A failure is audited and
    /// reported, never hidden, and never stops the rest of the removal: the
    /// machine is already gone.
    async fn revoke_secrets(
        &self,
        audit: &Recorder<'_>,
        machine_id: &str,
        audit_gaps: &mut Vec<String>,
    ) -> (u64, Option<String>) {
        let Some(keys) = &self.keys else {
            return (0, None);
        };
        match keys.revoke_for_machine(machine_id).await {
            Ok(count) => (u64::try_from(count).unwrap_or(u64::MAX), None),
            Err(detail) => {
                eprintln!(
                    "machine removal {machine_id}: stored secrets were not revoked: {detail}"
                );
                let reason = bounded(&detail);
                if audit
                    .record(&[
                        ("event", "machine_secret_revocation_failed"),
                        ("reason", &reason),
                    ])
                    .await
                    .is_err()
                {
                    audit_gaps.push("machine_secret_revocation_failed".to_owned());
                }
                (0, Some(reason))
            }
        }
    }

    /// Removes the pins of the reviewed hosts that nobody uses now. Sharing
    /// is read again after the delete: a host another machine or a draft
    /// started using during the removal keeps its pins and is reported as
    /// kept.
    async fn unpin(
        &self,
        machine_id: &str,
        review: &RemovalReview,
    ) -> (Vec<String>, Vec<String>, Vec<String>) {
        let mut kept = review.kept_hosts.clone();
        let mut unpinned = Vec::new();
        let mut failed = Vec::new();
        if review.unpin_hosts.is_empty() {
            return (unpinned, kept, failed);
        }
        let used = match self.store.other_host_users(machine_id).await {
            Ok(others) => others.hosts(),
            Err(detail) => {
                // Without knowing who else uses a host, unpinning could break
                // another machine's trust: keep every pin and say so.
                eprintln!(
                    "machine removal {machine_id}: host sharing unreadable, pins kept: {detail}"
                );
                failed.extend(review.unpin_hosts.iter().cloned());
                return (unpinned, kept, failed);
            }
        };
        for host in &review.unpin_hosts {
            if used.contains(host) {
                kept.push(host.clone());
                continue;
            }
            match self.trust.unpin(host).await {
                Ok(()) => unpinned.push(host.clone()),
                Err(failure) => {
                    eprintln!("machine removal {machine_id}: the pin for a host stayed: {failure}");
                    failed.push(host.clone());
                }
            }
        }
        kept.sort();
        (unpinned, kept, failed)
    }

    /// Runs the uninstall the review planned, audited before and after. A
    /// failure is the removal's failure: nothing has been deleted yet.
    async fn uninstall(
        &self,
        audit: &Recorder<'_>,
        machine_id: &str,
        plan: &UninstallPlan,
    ) -> Result<String, MachineRemovalError> {
        let uninstaller = self
            .uninstaller
            .as_ref()
            .ok_or(MachineRemovalError::UninstallUnavailable)?;
        let layout = if plan.layout.is_empty() {
            "default".to_owned()
        } else {
            "recorded".to_owned()
        };
        audit
            .record(&[
                ("event", "fleetd_uninstall_started"),
                ("endpointId", &plan.endpoint_id),
                ("auth", plan.auth.kind()),
                ("layout", &layout),
            ])
            .await?;
        match uninstaller
            .uninstall(&FleetdUninstall {
                machine_id: machine_id.to_owned(),
                plan: plan.clone(),
            })
            .await
        {
            Ok(line) => {
                audit
                    .record(&[
                        ("event", "fleetd_uninstalled"),
                        ("endpointId", &plan.endpoint_id),
                    ])
                    .await?;
                Ok(line)
            }
            Err(detail) => {
                audit
                    .record(&[
                        ("event", "fleetd_uninstall_failed"),
                        ("endpointId", &plan.endpoint_id),
                        ("reason", &bounded(&detail)),
                    ])
                    .await?;
                Err(MachineRemovalError::UninstallFailed { detail })
            }
        }
    }

    /// The review token of a removal payload.
    #[must_use]
    pub fn token_for(payload: &serde_json::Value) -> String {
        review_token_for(REMOVE_KIND, &payload.to_string())
    }

    #[allow(clippy::unused_self)]
    fn authorize(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
    ) -> Result<(), MachineRemovalError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineDelete,
                resource: Some(machine_id),
            },
        )
        .map(|_| ())
        .map_err(MachineRemovalError::Denied)
    }

    async fn assess(
        &self,
        machine_id: &str,
        uninstall: Option<&UninstallRequest>,
    ) -> Result<RemovalReview, MachineRemovalError> {
        let machine = self
            .records
            .get(machine_id)
            .await
            .map_err(|failure| match failure {
                PortFailure::NotFound { what } => MachineRemovalError::NotFound { what },
                other => MachineRemovalError::Backend {
                    context: "get",
                    detail: other.to_string(),
                },
            })?;
        let uninstall = match uninstall {
            Some(request) => Some(self.plan_uninstall(&machine, request).await?),
            None => None,
        };
        let footprint = self
            .store
            .footprint(machine_id)
            .await
            .map_err(backend("footprint"))?;
        let mut blockers = self.blockers(machine_id).await?;
        if self.keys.is_none() && footprint.machine_secrets() > 0 {
            blockers.push(RemovalBlocker {
                kind: "stored_secret".to_owned(),
                id: machine_id.to_owned(),
                state: "unrevocable".to_owned(),
                detail: format!(
                    "machine {machine_id} has secrets bound to it in Fleet's secret store ({} SSH keys, {} Windows administrator passwords) and this controller runs without its secret store, so it could not revoke them; start the controller with its master key, then remove the machine",
                    footprint.stored_ssh_keys, footprint.admin_passwords
                ),
            });
        }
        let mut warnings = Vec::new();
        if footprint.admin_passwords > 0 {
            warnings.push(format!(
                "the removal destroys the Windows administrator password Fleet rotated and stored for machine {machine_id} ({} stored); read it first (it is the only copy) if anyone may still need to log in as the administrator",
                footprint.admin_passwords
            ));
        }
        let (unpin_hosts, kept_hosts) = self.host_split(&machine).await?;
        let endpoints: Vec<ReviewedEndpoint> = machine
            .endpoints
            .iter()
            .map(|endpoint| ReviewedEndpoint {
                id: endpoint.id.clone(),
                kind: endpoint.kind.id().to_owned(),
                host: (endpoint.kind == EndpointKind::Ssh)
                    .then(|| reference_host(&endpoint.reference).map(str::to_owned))
                    .flatten(),
            })
            .collect();
        let payload = serde_json::json!({
            "machineId": machine.id,
            "name": machine.name,
            "endpoints": machine
                .endpoints
                .iter()
                .map(|endpoint| serde_json::json!([endpoint.id, endpoint.kind.id(), endpoint.reference]))
                .collect::<Vec<_>>(),
            "unpin": unpin_hosts,
            "keep": kept_hosts,
            "storedSshKeys": footprint.stored_ssh_keys,
            "adminPasswords": footprint.admin_passwords,
            "uninstall": uninstall,
        });
        let review_token = blockers.is_empty().then(|| Self::token_for(&payload));
        Ok(RemovalReview {
            review_token,
            machine_id: machine.id.clone(),
            name: machine.name.clone(),
            endpoints,
            node_identity: machine
                .node
                .as_ref()
                .map(|node| node.identity_status.id().to_owned()),
            unpin_hosts,
            kept_hosts,
            uninstall,
            footprint,
            warnings,
            blockers,
        })
    }

    async fn plan_uninstall(
        &self,
        machine: &Machine,
        request: &UninstallRequest,
    ) -> Result<UninstallPlan, MachineRemovalError> {
        if self.uninstaller.is_none() {
            return Err(MachineRemovalError::UninstallUnavailable);
        }
        let endpoint = machine
            .endpoints
            .iter()
            .find(|endpoint| endpoint.id == request.endpoint_id)
            .ok_or_else(|| MachineRemovalError::Invalid {
                detail: format!(
                    "endpoint {:?} is not one of machine {}'s endpoints",
                    request.endpoint_id, machine.id
                ),
            })?;
        if endpoint.kind != EndpointKind::Ssh {
            return Err(MachineRemovalError::Invalid {
                detail: format!(
                    "the uninstall runs over SSH; endpoint {} is a {} endpoint",
                    endpoint.id,
                    endpoint.kind.id()
                ),
            });
        }
        let auth = match &request.auth {
            Some(auth) => {
                auth.validate()
                    .map_err(|detail| MachineRemovalError::Invalid { detail })?;
                auth.clone()
            }
            None => match &self.endpoint_auth {
                Some(auths) => auths
                    .get(&endpoint.id)
                    .await
                    .map_err(backend("endpoint_auth"))?
                    .unwrap_or(EndpointAuth::Agent),
                None => EndpointAuth::Agent,
            },
        };
        let layout = self
            .store
            .install_layout(&machine.id)
            .await
            .map_err(backend("install_layout"))?
            .into_iter()
            .filter(|(name, _)| LAYOUT_VARIABLES.contains(&name.as_str()))
            .collect::<BTreeMap<String, String>>();
        // The layout reaches a root script that deletes FLEETD_STATE_DIR: a
        // recorded value that breaks a rule refuses the uninstall.
        for (name, value) in &layout {
            crate::fleetd_layout::validate_installer_variable(
                name,
                value,
                crate::fleetd_layout::InstallerTools::System,
            )
            .map_err(|reason| {
                MachineRemovalError::Conflict {
                    detail: format!(
                        "the layout recorded by machine {}'s last fleetd install is not safe to uninstall with ({reason}); remove the machine without --uninstall and remove fleetd by hand",
                        machine.id
                    ),
                }
            })?;
        }
        Ok(UninstallPlan {
            endpoint_id: endpoint.id.clone(),
            auth,
            layout,
        })
    }

    async fn blockers(&self, machine_id: &str) -> Result<Vec<RemovalBlocker>, MachineRemovalError> {
        let mut blockers = Vec::new();
        for provision in self
            .store
            .lab_provisions(machine_id)
            .await
            .map_err(backend("lab_provisions"))?
        {
            let instruction = match (&provision.lease_id, provision.lease_state.as_deref()) {
                (Some(lease), Some("cleanup_failed")) => format!(
                    "its lease {lease} failed cleanup; retry it with `fleetctl lab cleanup-retry {lease}`, which removes the machine"
                ),
                (Some(lease), Some(state)) => format!(
                    "Lab owns it: release lease {lease} ({state}) with `fleetctl lab destroy {lease}`, and its cleanup removes the machine"
                ),
                _ => "Lab owns it and no lease links back to it (a pool member or an unleased provision): drain it from its pool with `fleetctl lab pool drain <pool-id> --vmid <vmid>` (see `fleetctl lab provisions`), and Lab's cleanup removes the machine".to_owned(),
            };
            blockers.push(RemovalBlocker {
                kind: "lab_provision".to_owned(),
                id: provision.provision_id.clone(),
                state: provision.state.clone(),
                detail: format!(
                    "machine {machine_id} is the Lab guest of provision {} ({}); {instruction}",
                    provision.provision_id, provision.state
                ),
            });
        }
        for marker in self
            .store
            .persistent_markers(machine_id)
            .await
            .map_err(backend("persistent_markers"))?
        {
            let instruction = if marker.registered {
                format!(
                    "unregister it first with `fleetctl machines persistent unregister --account {} --vmid {}` (the VM is left as it is), then remove the machine",
                    marker.account_id, marker.vmid
                )
            } else {
                format!(
                    "Fleet created that VM: destroy it with the reviewed destroy (`fleetctl proxmox destroy {} <node> {} --confirm-persistent`), or abandon an unfinished creation with `fleetctl machines abandon --account {} --vmid {}`",
                    marker.account_id, marker.vmid, marker.account_id, marker.vmid
                )
            };
            blockers.push(RemovalBlocker {
                kind: "persistent_marker".to_owned(),
                id: format!("{}/{}", marker.account_id, marker.vmid),
                state: if marker.registered {
                    "registered".to_owned()
                } else {
                    "created".to_owned()
                },
                detail: format!(
                    "machine {machine_id} is the persistent machine of VM {} ({}/{}); {instruction}",
                    marker.name, marker.account_id, marker.vmid
                ),
            });
        }
        for hold in self
            .hardware
            .holds_of_machine(machine_id)
            .await
            .map_err(backend("hardware"))?
        {
            blockers.push(RemovalBlocker {
                kind: "hardware_reservation".to_owned(),
                id: hold.reservation_id.clone(),
                state: hold.state.id().to_owned(),
                detail: hold.refusal("remove the machine"),
            });
        }
        for operation in self
            .store
            .active_operations(machine_id)
            .await
            .map_err(backend("active_operations"))?
        {
            blockers.push(RemovalBlocker {
                kind: "active_operation".to_owned(),
                id: operation.id.clone(),
                state: operation.state.clone(),
                detail: format!(
                    "operation {} ({}) on machine {machine_id} is {}; wait for it (`fleetctl operations get {}`) or cancel it (`fleetctl operations cancel {}`)",
                    operation.id, operation.kind, operation.state, operation.id, operation.id
                ),
            });
        }
        Ok(blockers)
    }

    /// Splits the machine's SSH hosts into those whose pins go and those
    /// another machine's endpoint or an onboarding draft still uses. Hosts
    /// compare case-insensitively, as the onboarding cancel's guard does.
    async fn host_split(
        &self,
        machine: &Machine,
    ) -> Result<(Vec<String>, Vec<String>), MachineRemovalError> {
        let own: BTreeSet<String> = machine
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.kind == EndpointKind::Ssh)
            .filter_map(|endpoint| reference_host(&endpoint.reference))
            .map(str::to_ascii_lowercase)
            .collect();
        if own.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let used = self
            .store
            .other_host_users(&machine.id)
            .await
            .map_err(backend("other_host_users"))?
            .hosts();
        let (kept, unpin): (Vec<String>, Vec<String>) =
            own.into_iter().partition(|host| used.contains(host));
        Ok((unpin, kept))
    }
}

/// Writes one removal's audit events: all under `machine.delete`, on the
/// machine, with the request's correlation id.
struct Recorder<'a> {
    audit: &'a dyn AuditPort,
    principal: &'a ActingPrincipal,
    machine_id: &'a str,
    correlation_id: Option<&'a str>,
}

impl Recorder<'_> {
    async fn record(&self, facts: &[(&str, &str)]) -> Result<(), MachineRemovalError> {
        let mut metadata = AuditMetadata::default();
        for (key, value) in facts {
            metadata
                .insert(key, value)
                .map_err(|error| MachineRemovalError::Backend {
                    context: "audit",
                    detail: error.to_string(),
                })?;
        }
        self.audit
            .record_intent(&AuditIntent {
                actor: self.principal.id.clone(),
                action: Permission::MachineDelete.id().to_owned(),
                resource: Some(self.machine_id.to_owned()),
                decision: Decision::allow(),
                correlation_id: self.correlation_id.map(str::to_owned),
                operation_id: None,
                metadata,
            })
            .await
            .map_err(backend("audit"))
    }
}

const fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// A failure detail bounded for an audit value.
fn bounded(detail: &str) -> String {
    const LIMIT: usize = 512;
    if detail.len() <= LIMIT {
        return detail.to_owned();
    }
    let mut end = LIMIT;
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &detail[..end])
}
