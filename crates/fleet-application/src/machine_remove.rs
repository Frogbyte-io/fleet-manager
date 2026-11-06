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
//!   and the optional uninstall (endpoint and authentication). The removal
//!   recomputes the same payload and refuses a token that no longer matches,
//!   so an endpoint added, a host now shared, or a different uninstall
//!   between the two is reviewed again.
//! - **Refused while something holds the machine.** A Lab provision record
//!   (the machine is a Lab guest, and Lab cleanup owns its record), a
//!   persistent marker (the persistent unregister or destroy flow owns it), a
//!   live USB reservation the machine owns (detach first), and a pending,
//!   running or cancelling operation on the machine. The review lists every
//!   hold with what to do; the removal re-checks and refuses while any
//!   remains. The storage delete re-checks the USB hold in the same statement
//!   as the delete, so a reservation taken between the check and the delete
//!   still refuses.
//! - **What goes.** The record goes through [`Machines::delete`]: its
//!   endpoints and their stored default authentication, capability facts,
//!   inventory snapshots, tags, groups, node identity with its credentials,
//!   sessions and enrollment tokens, project checkout observations, the
//!   Skills Manager snapshot, recorded catalog skill installs and a confirmed
//!   guest link all cascade, and the keys and rotated passwords bound to the
//!   machine are revoked. The pinned host keys of its SSH hosts are removed
//!   from the Fleet known-hosts file unless another machine's endpoint or an
//!   onboarding draft uses the same host (pins are host-scoped, as in the
//!   onboarding cancel).
//! - **What stays.** The audit trail, finished operations, released hardware
//!   reservations, action requests, collected files (until their retention
//!   pass) and Fleet Git (the Registry) are history and are not touched.
//! - **Nothing on the machine is touched** unless the caller asks for the
//!   uninstall: then the existing fleetd uninstall (`deploy/fleetd/uninstall.sh
//!   --purge`) runs over SSH first, and a failed uninstall leaves the machine
//!   registered.
//!
//! Every step is audited, without secrets: the uninstall's start and result,
//! the delete (`machine.delete`, by [`Machines::delete`]) and a summary of the
//! removal.
#![warn(missing_docs)]

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::audit::{AuditIntent, AuditMetadata};
use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::machine::{Machine, MachinePort, MachineUseCaseError, Machines};
use crate::machine_access::{EndpointAuth, EndpointAuthPort};
use crate::machine_usb::MachineHardwareGate;
use crate::onboarding::{OnboardTrustPort, reference_host};
use crate::operation::{AuditPort, PortFailure, review_token_for};
use fleet_core::EndpointKind;

/// The review-token kind of a removal.
pub const REMOVE_KIND: &str = "machine.remove";

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
}

/// What the uninstall port is asked to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FleetdUninstall {
    /// The machine.
    pub machine_id: String,
    /// The SSH endpoint and authentication.
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
    /// reached or trusted, or the script does not exit 0.
    async fn uninstall(&self, request: &FleetdUninstall) -> Result<String, String>;
}

/// A Lab provision record that names the machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabProvisionHold {
    /// The provision.
    pub provision_id: String,
    /// Its state.
    pub state: String,
    /// The lease it belongs to, when any.
    pub lease_id: Option<String>,
    /// The lease's state, when there is a lease.
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

/// The records a removal deletes, counted for the review. Informational: the
/// counts move with inventory and are not bound by the review token.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovalFootprint {
    /// Endpoints.
    pub endpoints: u64,
    /// Stored default endpoint authentication records.
    pub endpoint_auth: u64,
    /// Capability facts.
    pub capabilities: u64,
    /// Inventory snapshots.
    pub inventory_snapshots: u64,
    /// Tag and group memberships.
    pub tags_and_groups: u64,
    /// Node identity records (0 or 1).
    pub node_identity: u64,
    /// Node credentials, sessions and enrollment tokens.
    pub node_credentials: u64,
    /// Project checkout observations.
    pub project_checkouts: u64,
    /// Skills Manager snapshots (0 or 1).
    pub skills_snapshot: u64,
    /// Recorded catalog skill installs.
    pub catalog_skill_installs: u64,
    /// Confirmed Proxmox guest links (0 or 1).
    pub guest_link: u64,
    /// Collected files kept until their retention pass (not deleted).
    pub collected_files_kept: u64,
}

/// What the store answers about a machine before it is removed.
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
}

/// Who else uses a host, as the store reports it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OtherHostUsers {
    /// `user@host:port` references of other machines' SSH endpoints.
    pub endpoint_references: Vec<String>,
    /// The hosts of onboarding drafts.
    pub draft_hosts: Vec<String>,
}

/// Why a removal is refused, with what to do about it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovalBlocker {
    /// `lab_provision`, `persistent_marker`, `hardware_reservation` or
    /// `active_operation`.
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
    /// What the removal deletes.
    pub footprint: RemovalFootprint,
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
    /// The hosts whose pins were removed.
    pub unpinned_hosts: Vec<String>,
    /// The hosts whose pins stayed because they are shared.
    pub kept_hosts: Vec<String>,
    /// The hosts whose pins could not be removed (the machine is gone; the
    /// pin is left for the operator to remove).
    pub unpin_failed_hosts: Vec<String>,
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
    /// A hold raced the removal (the store refused the delete).
    Conflict {
        /// What conflicts.
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
    machines: Arc<Machines>,
    records: Arc<dyn MachinePort>,
    store: Arc<dyn MachineRemovalPort>,
    hardware: Arc<dyn MachineHardwareGate>,
    trust: Arc<dyn OnboardTrustPort>,
    audit: Arc<dyn AuditPort>,
    endpoint_auth: Option<Arc<dyn EndpointAuthPort>>,
    uninstaller: Option<Arc<dyn FleetdUninstallPort>>,
}

impl MachineRemoval {
    /// Composes the use case. `machines` performs the delete (and revokes the
    /// machine's bound keys when it was composed to); `records` reads the
    /// machine; `trust` removes pins.
    #[must_use]
    pub fn new(
        machines: Arc<Machines>,
        records: Arc<dyn MachinePort>,
        store: Arc<dyn MachineRemovalPort>,
        hardware: Arc<dyn MachineHardwareGate>,
        trust: Arc<dyn OnboardTrustPort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            machines,
            records,
            store,
            hardware,
            trust,
            audit,
            endpoint_auth: None,
            uninstaller: None,
        }
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
    /// when asked (a failure leaves the machine), deletes the record, and
    /// removes the pins of hosts nobody else uses. Audited.
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
        let review = self.assess(machine_id, uninstall).await?;
        if !review.blockers.is_empty() {
            return Err(MachineRemovalError::Blocked {
                blockers: review.blockers,
            });
        }
        if review.review_token.as_deref() != Some(review_token) {
            return Err(MachineRemovalError::Invalid {
                detail: "the review token does not match this machine as it is now (its endpoints, shared hosts or the uninstall changed, or the token is for another request); review the removal again".to_owned(),
            });
        }

        let summary = match &review.uninstall {
            Some(plan) => Some(
                self.uninstall(principal, machine_id, plan, correlation_id)
                    .await?,
            ),
            None => None,
        };

        self.machines
            .delete(authorizer, principal, machine_id)
            .await
            .map_err(|error| match error {
                MachineUseCaseError::Denied(decision) => MachineRemovalError::Denied(decision),
                MachineUseCaseError::NotFound { what } => MachineRemovalError::NotFound { what },
                MachineUseCaseError::Conflict { detail } => {
                    MachineRemovalError::Conflict { detail }
                }
                MachineUseCaseError::Invalid { detail } => MachineRemovalError::Invalid { detail },
                MachineUseCaseError::Backend { context, detail } => {
                    MachineRemovalError::Backend { context, detail }
                }
            })?;

        // The record is gone; its hosts' pins follow unless shared. A pin
        // that cannot be removed is reported, not hidden: the removal itself
        // already happened.
        let mut unpinned = Vec::new();
        let mut failed = Vec::new();
        for host in &review.unpin_hosts {
            match self.trust.unpin(host).await {
                Ok(()) => unpinned.push(host.clone()),
                Err(failure) => {
                    eprintln!("machine removal {machine_id}: the pin for a host stayed: {failure}");
                    failed.push(host.clone());
                }
            }
        }
        let uninstalled = review.uninstall.is_some();
        let endpoints = review.endpoints.len().to_string();
        let unpinned_count = unpinned.len().to_string();
        let kept_count = review.kept_hosts.len().to_string();
        let failed_count = failed.len().to_string();
        let node = review
            .node_identity
            .clone()
            .unwrap_or_else(|| "none".to_owned());
        self.record(
            principal,
            machine_id,
            correlation_id,
            &[
                ("event", "machine_removed"),
                ("name", &review.name),
                ("endpoints", &endpoints),
                ("nodeIdentity", &node),
                ("uninstalled", if uninstalled { "true" } else { "false" }),
                ("hostsUnpinned", &unpinned_count),
                ("hostsKept", &kept_count),
                ("hostsUnpinFailed", &failed_count),
                (
                    "skillInstallsDropped",
                    &review.footprint.catalog_skill_installs.to_string(),
                ),
            ],
        )
        .await?;
        Ok(RemovalOutcome {
            machine_id: review.machine_id,
            name: review.name,
            uninstalled,
            uninstall_summary: summary,
            node_identity_removed: review.node_identity.is_some(),
            unpinned_hosts: unpinned,
            kept_hosts: review.kept_hosts,
            unpin_failed_hosts: failed,
            footprint: review.footprint,
        })
    }

    /// Runs the uninstall the review planned, audited before and after. A
    /// failure is the removal's failure: nothing has been deleted yet.
    async fn uninstall(
        &self,
        principal: &ActingPrincipal,
        machine_id: &str,
        plan: &UninstallPlan,
        correlation_id: Option<&str>,
    ) -> Result<String, MachineRemovalError> {
        let uninstaller = self
            .uninstaller
            .as_ref()
            .ok_or(MachineRemovalError::UninstallUnavailable)?;
        self.record(
            principal,
            machine_id,
            correlation_id,
            &[
                ("event", "fleetd_uninstall_started"),
                ("endpointId", &plan.endpoint_id),
                ("auth", plan.auth.kind()),
            ],
        )
        .await?;
        match uninstaller
            .uninstall(&FleetdUninstall {
                machine_id: machine_id.to_owned(),
                plan: plan.clone(),
            })
            .await
        {
            Ok(line) => {
                self.record(
                    principal,
                    machine_id,
                    correlation_id,
                    &[
                        ("event", "fleetd_uninstalled"),
                        ("endpointId", &plan.endpoint_id),
                    ],
                )
                .await?;
                Ok(line)
            }
            Err(detail) => {
                self.record(
                    principal,
                    machine_id,
                    correlation_id,
                    &[
                        ("event", "fleetd_uninstall_failed"),
                        ("endpointId", &plan.endpoint_id),
                        ("reason", &bounded(&detail)),
                    ],
                )
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
        let blockers = self.blockers(machine_id).await?;
        let (unpin_hosts, kept_hosts) = self.host_split(&machine).await?;
        let footprint = self
            .store
            .footprint(machine_id)
            .await
            .map_err(backend("footprint"))?;
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
        Ok(UninstallPlan {
            endpoint_id: endpoint.id.clone(),
            auth,
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
                _ => "Lab owns it (a pool member or an unleased provision): drain or release it through Lab, and its cleanup removes the machine".to_owned(),
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
        let others = self
            .store
            .other_host_users(&machine.id)
            .await
            .map_err(backend("other_host_users"))?;
        let used: BTreeSet<String> = others
            .endpoint_references
            .iter()
            .filter_map(|reference| reference_host(reference))
            .chain(others.draft_hosts.iter().map(String::as_str))
            .map(str::to_ascii_lowercase)
            .collect();
        let (kept, unpin): (Vec<String>, Vec<String>) =
            own.into_iter().partition(|host| used.contains(host));
        Ok((unpin, kept))
    }

    async fn record(
        &self,
        principal: &ActingPrincipal,
        machine_id: &str,
        correlation_id: Option<&str>,
        facts: &[(&str, &str)],
    ) -> Result<(), MachineRemovalError> {
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
                actor: principal.id.clone(),
                action: Permission::MachineDelete.id().to_owned(),
                resource: Some(machine_id.to_owned()),
                decision: Decision::allow(),
                correlation_id: correlation_id.map(str::to_owned),
                operation_id: None,
                metadata,
            })
            .await
            .map_err(backend("audit"))
    }
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
