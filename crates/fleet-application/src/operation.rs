//! The durable operation service: the authorized use cases over the
//! [`OperationPort`].
//!
//! Remote work cannot be request-scoped, so an accepted action becomes an
//! operation row that survives restarts. This module owns the *use cases* —
//! who may create, read, list, or cancel an operation — while the port below
//! owns the mechanics (idempotency, deadlines, state transitions) that the
//! storage adapter implements. Every use case funnels through the
//! authorization catalog, and every accepted mutation appends an audit intent
//! through the [`AuditPort`], in that order: authorize first, audit second,
//! mutate last.
//!
//! There is intentionally no execution here. Claiming, retrying, and running
//! steps belongs to the operation worker (FM-109); node dispatch belongs to
//! the node protocol. This module can complete, but never on its own behalf.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::audit::{AuditMetadata, AuditOutcome};
use crate::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId, authorize};

/// The kinds of operation the public API accepts. Until providers and nodes
/// teach the controller their own kinds, the vocabulary is deliberately tiny:
/// an unknown kind is refused rather than accepted as an unspecified promise.
/// `ssh.exec` carries its bounded script payload in `payload_json`; the node
/// kinds dispatch through the gateway with a `{"machineId": …}` payload; the
/// onboarding kinds carry a `{"draftId": …}` payload and touch the draft
/// record, never a machine (FM-210); the checkout and skills kinds carry a
/// machine-scoped `{"machineId", "endpointId", "auth", …}` payload, with
/// `skills.deploy`/`skills.undeploy` adding `skillId`, `agents`, and
/// `dryRun` (FM-301, FM-302); library and preset kinds add typed references,
/// explicit confirmation, and supported dry-run data (FM-921); the frogenv
/// kinds carry the same
/// machine-scoped shape, with `frogenv.env-run` adding `root` (the
/// checkout directory) and `command` with its argument array (FM-303);
/// the mise kinds carry the same shape, with `mise.install` adding a
/// pinned `tool@version` and `mise.exec` adding `root` and `command`
/// (FM-304); the ready workflow carries the machine-scoped shape plus
/// `projectId` and `dryRun` (FM-305); the apply workflow carries the
/// machine-scoped shape plus the plan and its approval identities
/// (FM-402); the source kinds carry the remote/commit payloads and are
/// catalog-level (FM-403).
pub const CREATABLE_KINDS: [&str; 57] = [
    "noop",
    "ssh.exec",
    "agentless.inventory",
    "machine.onboard.test",
    "machine.onboard.discover",
    "machine.install-fleetd",
    "node.noop",
    "node.diagnostic",
    "node.inventory",
    "projects.discover",
    "projects.clone",
    "projects.pull",
    "projects.status",
    "projects.write-config",
    "skills.probe",
    "skills.deploy",
    "skills.undeploy",
    "skills.install",
    "skills.update",
    "skills.check",
    "skills.remove",
    "skills.adopt",
    "skills.set-source",
    "skills.catalog-rollout",
    "presets.create",
    "presets.update",
    "presets.delete",
    "presets.add-skill",
    "presets.remove-skill",
    "presets.deploy",
    "presets.undeploy",
    "frogenv.status",
    "frogenv.setup",
    "frogenv.login",
    "frogenv.request",
    "frogenv.sync",
    "frogenv.env-run",
    "tools.inventory",
    "mise.status",
    "mise.install",
    "mise.exec",
    "ready.workflow",
    "apply.workflow",
    "source.fetch",
    "source.activate",
    "proxmox.guest.start",
    "proxmox.guest.stop",
    "proxmox.guest.shutdown",
    "proxmox.guest.reboot",
    "proxmox.guest.snapshot",
    "proxmox.guest.snapshot-revert",
    "proxmox.guest.snapshot-delete",
    "proxmox.guest.clone",
    "proxmox.guest.template",
    "proxmox.task-cancel",
    "image.build",
    "lab.provision",
];

/// The machine-scoped permission a kind's creation requires, when any.
/// The checkout and skills kinds act on machines through SSH; creating
/// their operations is itself the risky act, so the same catalog entry
/// governs both the dedicated endpoint and the generic one.
#[must_use]
fn machine_scoped_kind_permission(kind: &str, payload: Option<&str>) -> Option<Permission> {
    machine_scoped_kind_permission_inner(kind, payload)
}

/// The catalog-level permission a kind's creation requires, when any.
/// The source and Proxmox lifecycle kinds act on infrastructure that is
/// not a Fleet machine, so their permission is enforced with
/// `resource: None` — never a machine id.
#[must_use]
fn catalog_scoped_kind_permission(kind: &str) -> Option<Permission> {
    match kind {
        "source.fetch" => Some(Permission::SourceFetch),
        "source.activate" => Some(Permission::SourceActivate),
        "proxmox.guest.start"
        | "proxmox.guest.stop"
        | "proxmox.guest.shutdown"
        | "proxmox.guest.reboot" => Some(Permission::ProxmoxOperate),
        "proxmox.guest.snapshot"
        | "proxmox.guest.snapshot-revert"
        | "proxmox.guest.snapshot-delete"
        | "proxmox.guest.clone"
        | "proxmox.guest.template"
        | "proxmox.task-cancel" => Some(Permission::ProxmoxDestructive),
        _ => None,
    }
}

fn machine_scoped_kind_permission_inner(kind: &str, payload: Option<&str>) -> Option<Permission> {
    match kind {
        "projects.discover" => Some(Permission::ProjectsDiscover),
        "projects.clone" | "projects.pull" | "projects.status" => {
            Some(Permission::ProjectsGitWrite)
        }
        "projects.write-config" => Some(Permission::ProjectsFileWrite),
        "skills.probe" => {
            // A pinned probe downloads and installs a binary: that is a
            // mutation, never a read.
            let pinned = payload
                .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
                .is_some_and(|payload| {
                    payload["artifactUrl"].as_str().is_some()
                        && payload["artifactSha256"].as_str().is_some()
                });
            if pinned {
                Some(Permission::SkillsDeploy)
            } else {
                Some(Permission::SkillsRead)
            }
        }
        "skills.deploy"
        | "skills.undeploy"
        | "skills.catalog-rollout"
        | "presets.deploy"
        | "presets.undeploy" => Some(Permission::SkillsDeploy),
        "skills.install"
        | "skills.update"
        | "skills.check"
        | "skills.remove"
        | "skills.adopt"
        | "skills.set-source"
        | "presets.create"
        | "presets.update"
        | "presets.delete"
        | "presets.add-skill"
        | "presets.remove-skill" => Some(Permission::SkillsModify),
        "frogenv.status" => Some(Permission::FrogenvRead),
        "frogenv.setup" | "frogenv.login" | "frogenv.request" | "frogenv.sync"
        | "frogenv.env-run" => Some(Permission::FrogenvOperate),
        "tools.inventory" | "mise.status" => Some(Permission::ToolsRead),
        "mise.install" | "mise.exec" => Some(Permission::MiseOperate),
        "ready.workflow" => Some(Permission::ProjectsReady),
        "apply.workflow" => Some(Permission::ApplyExecute),

        _ => None,
    }
}

/// The payload bound for provider inputs.
pub const MAX_PAYLOAD_JSON: usize = 128 * 1024;

/// The destructive-adjacent kinds: their creation requires a review token
/// computed over exactly the payload being created.
pub const DESTRUCTIVE_KINDS: [&str; 6] = [
    "proxmox.guest.snapshot",
    "proxmox.guest.snapshot-revert",
    "proxmox.guest.snapshot-delete",
    "proxmox.guest.clone",
    "proxmox.guest.template",
    "proxmox.task-cancel",
];

/// The review token for one destructive operation: the SHA-256 of the
/// kind and the exact payload bytes. Deterministic, payload-bound, and
/// computable only over material the caller actually holds.
#[must_use]
pub fn review_token_for(kind: &str, payload_json: &str) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update(b"\n");
    hasher.update(payload_json.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    digest.iter().fold(String::with_capacity(64), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Compares two token strings in constant time over their bytes.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The public view of a durable operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Operation {
    /// The operation's identity.
    pub id: String,
    /// What kind of work this is.
    pub kind: String,
    /// The current domain state id.
    pub state: String,
    /// The caller's idempotency key, when one was supplied.
    pub idempotency_key: Option<String>,
    /// Progress numerator, when reported.
    pub progress_current: Option<i64>,
    /// Progress denominator, when reported.
    pub progress_total: Option<i64>,
    /// Bounded progress message, when reported.
    pub progress_message: Option<String>,
    /// The deadline, in epoch milliseconds, when one was set.
    pub deadline_at: Option<i64>,
    /// Whether cancellation has been requested but not yet observed.
    pub cancel_requested: bool,
    /// The bounded provider input, decided at creation.
    pub payload_json: Option<String>,
    /// The bounded public result, present when the operation succeeded.
    pub result_json: Option<String>,
    /// The bounded public error, present when the operation failed.
    pub error_json: Option<String>,
    /// The correlation identity joining this operation to the caller's flow.
    pub correlation_id: Option<String>,
    /// Creation time (epoch milliseconds).
    pub created_at: i64,
    /// Last update (epoch milliseconds).
    pub updated_at: i64,
    /// The claim timestamp the owning worker set, when the operation is
    /// running under a claim; the lease-recovery compare-and-set uses it.
    pub claimed_at: Option<i64>,
    /// The worker that owns the current claim, when any.
    pub worker_id: Option<String>,
}

/// A use-case rejection. Variants map onto public API errors by the adapter
/// that surfaces them; the strings here are safe to print.
#[derive(Debug)]
pub enum OperationUseCaseError {
    /// The caller may not perform the action.
    Denied(Decision),
    /// The action names an unknown kind, id, or key.
    NotFound {
        /// What was not found.
        what: String,
    },
    /// The request is malformed for this use case.
    Invalid {
        /// What is wrong, safe to print.
        detail: String,
    },
    /// The port or audit sink failed.
    Backend {
        /// The failing half.
        context: &'static str,
        /// The failure detail.
        detail: String,
    },
}

impl fmt::Display for OperationUseCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Invalid { detail } => write!(f, "invalid request: {detail}"),
            Self::Backend { context, detail } => write!(f, "operation {context} failed: {detail}"),
        }
    }
}

impl std::error::Error for OperationUseCaseError {}

/// The port's failures, typed so the use cases can answer honestly: a
/// missing operation is a client-visible 404, a backend failure is not.
#[derive(Debug)]
pub enum PortFailure {
    /// The referenced operation does not exist.
    NotFound {
        /// The reference that was not found.
        what: String,
    },
    /// The record conflicts with an existing one (a unique constraint).
    Conflict {
        /// The caller-safe detail.
        detail: String,
    },
    /// Something failed in the backend; the detail is safe to log.
    Backend {
        /// The failure detail.
        detail: String,
    },
}

impl fmt::Display for PortFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Conflict { detail } => write!(f, "conflict: {detail}"),
            Self::Backend { detail } => write!(f, "backend failure: {detail}"),
        }
    }
}

impl std::error::Error for PortFailure {}

/// The storage-side port. Mechanics only: no authorization and no audit, both
/// of which belong to the use cases here.
#[async_trait]
pub trait OperationPort: fmt::Debug + Send + Sync {
    /// Creates an operation, honoring the idempotency key when given.
    ///
    /// # Errors
    ///
    /// Fails on backend errors, reported as [`OperationUseCaseError`]-shaped
    /// problems by the caller.
    async fn create(
        &self,
        kind: &str,
        idempotency_key: Option<&str>,
        deadline_at: Option<i64>,
        correlation_id: Option<&str>,
        payload_json: Option<&str>,
    ) -> Result<Operation, PortFailure>;
    /// Reads one operation.
    ///
    /// # Errors
    ///
    /// Fails when the id is unknown or the backend errors.
    async fn get(&self, id: &str) -> Result<Operation, PortFailure>;
    /// Lists operations, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list(&self, limit: u32) -> Result<Vec<Operation>, PortFailure>;
    /// Records a durable cancellation request.
    ///
    /// # Errors
    ///
    /// Fails when the id is unknown or the backend errors.
    async fn request_cancel(&self, id: &str) -> Result<Operation, PortFailure>;
    /// Transitions state, validating through the domain machine.
    ///
    /// # Errors
    ///
    /// Fails on an illegal transition or a backend error.
    async fn transition(&self, id: &str, state: &str) -> Result<Operation, PortFailure>;
    /// Records a terminal state with bounded public payloads.
    ///
    /// # Errors
    ///
    /// Fails on an illegal transition or a backend error.
    async fn complete(
        &self,
        id: &str,
        state: &str,
        result_json: Option<&str>,
        error_json: Option<&str>,
    ) -> Result<Operation, PortFailure>;
    /// Records progress.
    ///
    /// # Errors
    ///
    /// Fails when the message is too long or the backend errors.
    async fn record_progress(
        &self,
        id: &str,
        current: Option<i64>,
        total: Option<i64>,
        message: Option<&str>,
    ) -> Result<(), PortFailure>;
    /// Atomically claims one pending operation for `worker_id`: pending to
    /// running with the claim recorded, or `None` when the queue is empty.
    /// The compare-and-set in the adapter is what lets two workers race
    /// without both owning a claim.
    ///
    /// # Errors
    ///
    /// Fails on backend errors.
    async fn claim_pending(
        &self,
        worker_id: &str,
        now: i64,
    ) -> Result<Option<Operation>, PortFailure>;
    /// Atomically claims one specific operation by id for `worker_id`:
    /// pending to running with the claim recorded, or `None` when the
    /// operation is not pending. The addressed claim the ready workflow's
    /// steps use.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn claim_pending_by_id(
        &self,
        id: &str,
        worker_id: &str,
        now: i64,
    ) -> Result<Option<Operation>, PortFailure>;
    /// Returns live operations whose worker claim is older than
    /// `lease_ms`: a crashed worker's leftovers, ready to be resolved.
    ///
    /// # Errors
    ///
    /// Fails on backend errors.
    async fn expired_claims(&self, now: i64, lease_ms: i64) -> Result<Vec<Operation>, PortFailure>;
    /// Renews a running operation's lease: the owning worker proves it is
    /// alive so the recovery sweep does not resolve work that is still
    /// running. Returns whether the lease was renewed (false when the
    /// operation is no longer running under this worker — it was recovered,
    /// completed, or cancelled out from under the task).
    async fn renew_lease(
        &self,
        id: &str,
        worker_id: &str,
        now: i64,
        lease_ms: i64,
    ) -> Result<bool, PortFailure>;
    /// Fails an expired claim with a compare-and-set against the claim
    /// timestamp recovery selected. Returns false when a heartbeat renewed
    /// the claim in the interim — recovery then leaves it alone.
    async fn fail_expired_claim(
        &self,
        id: &str,
        expected_claimed_at: i64,
        now: i64,
        error_json: &str,
    ) -> Result<bool, PortFailure>;
    /// Completes deadline-expired live operations as timed out, returning
    /// the ids that transitioned.
    ///
    /// # Errors
    ///
    /// Fails on backend errors.
    async fn sweep_deadlines(&self, now: i64) -> Result<Vec<String>, PortFailure>;
    /// The queue depths per state, for backpressure visibility.
    ///
    /// # Errors
    ///
    /// Fails on backend errors.
    async fn queue_depths(&self) -> Result<QueueDepths, PortFailure>;
}

/// How much work sits in the queue, per state that matters for backpressure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QueueDepths {
    /// Accepted, not yet claimed.
    pub pending: i64,
    /// Claimed and executing.
    pub running: i64,
    /// Asked to stop, not yet stopped.
    pub cancelling: i64,
}

/// The audit half: accepted mutations append an intent, and the terminal
/// outcome is appended separately.
#[async_trait]
pub trait AuditPort: fmt::Debug + Send + Sync {
    /// Appends an intent for the accepted action.
    ///
    /// # Errors
    ///
    /// Fails when the sink refuses; the use case then refuses too, so state
    /// and audit stay consistent.
    async fn record_intent(&self, intent: &crate::audit::AuditIntent) -> Result<(), String>;
    /// Appends the terminal outcome.
    ///
    /// # Errors
    ///
    /// Fails when the sink refuses.
    async fn record_outcome(&self, operation_id: &str, outcome: AuditOutcome)
    -> Result<(), String>;
}

/// A creation request: everything the use case needs in one place.
#[derive(Clone, Debug, Default)]
pub struct NewOperation {
    /// The kind of work to create.
    pub kind: String,
    /// A caller-chosen key making the request idempotent.
    pub idempotency_key: Option<String>,
    /// The absolute deadline, in epoch milliseconds.
    pub deadline_at: Option<i64>,
    /// The correlation identity joining this operation to the caller's flow.
    pub correlation_id: Option<String>,
    /// The bounded provider input, for kinds that need one.
    pub payload_json: Option<String>,
    /// The verified review material for destructive-adjacent kinds: the
    /// review token recomputed over exactly this payload, which only a
    /// caller that ran the review over the same bytes can present. The
    /// generic surface leaves it `None`, which refuses destructive kinds
    /// outright; a `Some` value that does not match the payload is refused
    /// as well, so the field cannot be forged by setting it.
    pub review_token: Option<String>,
}

/// The authorized operation use cases.
#[derive(Debug)]
pub struct Operations {
    pub(crate) port: Arc<dyn OperationPort>,
    audit: Arc<dyn AuditPort>,
    catalog_rollout_targets: Option<Arc<dyn CatalogRolloutTargetPort>>,
    pub(crate) events: Option<Arc<crate::events::EventHub>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CatalogRolloutPayload {
    version_id: String,
    catalog_id: String,
    machine_id: String,
    endpoint_id: String,
    agents: Vec<String>,
    timeout_seconds: u64,
}

fn catalog_rollout_payload(
    new: &NewOperation,
) -> Result<Option<CatalogRolloutPayload>, OperationUseCaseError> {
    if new.kind != "skills.catalog-rollout" {
        return Ok(None);
    }
    let payload = new
        .payload_json
        .as_deref()
        .and_then(|json| serde_json::from_str::<CatalogRolloutPayload>(json).ok())
        .ok_or(OperationUseCaseError::Invalid {
            detail: "the skills.catalog-rollout payload is malformed".to_owned(),
        })?;
    let unique_agents: std::collections::HashSet<_> = payload.agents.iter().collect();
    if payload.version_id.trim().is_empty()
        || payload.catalog_id.trim().is_empty()
        || payload.machine_id.trim().is_empty()
        || payload.endpoint_id.trim().is_empty()
        || payload.agents.is_empty()
        || payload.agents.len() > 32
        || unique_agents.len() != payload.agents.len()
        || payload.agents.iter().any(|agent| agent.trim().is_empty())
        || !(1..=3600).contains(&payload.timeout_seconds)
    {
        return Err(OperationUseCaseError::Invalid {
            detail: "catalog rollout requires a version, catalog, machine, SSH endpoint, 1..=32 unique agents, and a timeout in 1..=3600 seconds".to_owned(),
        });
    }
    Ok(Some(payload))
}

/// Reads endpoint kinds needed to validate catalog rollout targets.
#[async_trait]
pub trait CatalogRolloutTargetPort: fmt::Debug + Send + Sync {
    /// Returns the endpoint kind for a machine endpoint, or `None` when absent.
    ///
    /// # Errors
    ///
    /// Returns a backend failure when the machine store cannot be read.
    async fn endpoint_kind(
        &self,
        machine_id: &str,
        endpoint_id: &str,
    ) -> Result<Option<fleet_core::EndpointKind>, PortFailure>;
}

impl Operations {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(port: Arc<dyn OperationPort>, audit: Arc<dyn AuditPort>) -> Self {
        Self {
            port,
            audit,
            catalog_rollout_targets: None,
            events: None,
        }
    }

    /// Composes the service with a shared fleet event publisher.
    #[must_use]
    pub fn new_with_events(
        port: Arc<dyn OperationPort>,
        audit: Arc<dyn AuditPort>,
        events: Arc<crate::events::EventHub>,
    ) -> Self {
        Self {
            port,
            audit,
            catalog_rollout_targets: None,
            events: Some(events),
        }
    }

    /// Composes the service with target validation for catalog rollouts.
    #[must_use]
    pub fn new_with_catalog_rollout_targets(
        port: Arc<dyn OperationPort>,
        audit: Arc<dyn AuditPort>,
        targets: Arc<dyn CatalogRolloutTargetPort>,
    ) -> Self {
        Self {
            port,
            audit,
            catalog_rollout_targets: Some(targets),
            events: None,
        }
    }

    /// Composes the service with events and target validation for catalog rollouts.
    #[must_use]
    pub fn new_with_events_and_catalog_rollout_targets(
        port: Arc<dyn OperationPort>,
        audit: Arc<dyn AuditPort>,
        events: Arc<crate::events::EventHub>,
        targets: Arc<dyn CatalogRolloutTargetPort>,
    ) -> Self {
        Self {
            port,
            audit,
            catalog_rollout_targets: Some(targets),
            events: Some(events),
        }
    }

    pub(crate) fn publish_operation(&self, operation: &Operation, completed: bool) {
        let Some(events) = &self.events else {
            return;
        };
        events.publish(crate::events::EventKind::OperationChanged);
        if completed {
            let kind = match operation.kind.as_str() {
                "agentless.inventory" | "node.inventory" | "machine.install-fleetd" => {
                    Some(crate::events::EventKind::MachineChanged)
                }
                "lab.provision" => Some(crate::events::EventKind::LeaseChanged),
                kind if kind.starts_with("proxmox.") => {
                    Some(crate::events::EventKind::ProxmoxChanged)
                }
                kind if kind.starts_with("tailnet.") || kind.starts_with("tailscale.") => {
                    Some(crate::events::EventKind::TailnetChanged)
                }
                kind if kind.starts_with("onboarding.")
                    || kind.starts_with("machine.onboarding.")
                    || kind.starts_with("machine.onboard.") =>
                {
                    Some(crate::events::EventKind::OnboardingChanged)
                }
                _ => None,
            };
            if let Some(kind) = kind {
                events.publish(kind);
            }
        }
    }

    /// Creates an operation after authorization, recording the audit intent
    /// for the accepted mutation.
    ///
    /// # Errors
    ///
    /// Fails on denial, unknown kind, or a backend failure.
    #[allow(clippy::too_many_lines)]
    pub async fn create(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        new: &NewOperation,
    ) -> Result<Operation, OperationUseCaseError> {
        self.create_inner(authorizer, principal_id, new, false)
            .await
    }

    /// Creates the one lease-scoped Lab provision operation from the
    /// dedicated lease provisioning use case. Generic operation creation
    /// refuses `lab.provision` so callers cannot queue duplicate sagas.
    ///
    /// # Errors
    ///
    /// Fails if the payload does not name `lease_id`, authorization is
    /// denied, the kind is invalid, or a backend fails.
    pub async fn create_lab_provision(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        lease_id: &str,
        new: &NewOperation,
    ) -> Result<Operation, OperationUseCaseError> {
        let linked_lease_id = new
            .payload_json
            .as_deref()
            .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
            .and_then(|payload| payload["leaseId"].as_str().map(str::to_owned))
            .ok_or(OperationUseCaseError::Invalid {
                detail: "the lab.provision payload must carry a leaseId".to_owned(),
            })?;
        if new.kind != "lab.provision" || linked_lease_id != lease_id {
            return Err(OperationUseCaseError::Invalid {
                detail: "the lab.provision payload must match its dedicated lease route".to_owned(),
            });
        }
        self.create_inner(authorizer, principal_id, new, true).await
    }

    #[allow(clippy::too_many_lines)]
    async fn create_inner(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        new: &NewOperation,
        allow_lab_provision: bool,
    ) -> Result<Operation, OperationUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::OperationCreate,
                resource: None,
            },
        )
        .map_err(OperationUseCaseError::Denied)?;

        if !CREATABLE_KINDS.contains(&new.kind.as_str()) {
            return Err(OperationUseCaseError::Invalid {
                detail: format!(
                    "kind {:?} is not accepted; known kinds: {}",
                    new.kind,
                    CREATABLE_KINDS.join(", ")
                ),
            });
        }

        if matches!(new.kind.as_str(), "skills.remove" | "presets.delete")
            && new
                .payload_json
                .as_deref()
                .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
                .is_none_or(|payload| payload["confirm"].as_bool() != Some(true))
        {
            return Err(OperationUseCaseError::Invalid {
                detail: "this operation requires explicit confirmation".to_owned(),
            });
        }

        if (new.kind.starts_with("skills.") || new.kind.starts_with("presets."))
            && new
                .payload_json
                .as_deref()
                .is_some_and(skills_payload_has_credentials)
        {
            return Err(OperationUseCaseError::Invalid {
                detail: "credential-bearing URLs are not accepted".to_owned(),
            });
        }

        if (new.kind.starts_with("skills.") || new.kind.starts_with("presets."))
            && let Some(payload) = new
                .payload_json
                .as_deref()
                .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
            && let Some(dry_run) = payload.get("dryRun")
        {
            let Some(dry_run) = dry_run.as_bool() else {
                return Err(OperationUseCaseError::Invalid {
                    detail: "dryRun must be a boolean".to_owned(),
                });
            };
            if dry_run
                && !matches!(
                    new.kind.as_str(),
                    "skills.deploy"
                        | "skills.undeploy"
                        | "skills.remove"
                        | "skills.adopt"
                        | "skills.set-source"
                        | "presets.delete"
                        | "presets.deploy"
                        | "presets.undeploy"
                )
            {
                return Err(OperationUseCaseError::Invalid {
                    detail: "the pinned CLI does not support dry-run for this operation".to_owned(),
                });
            }
        }

        if (new.kind.starts_with("skills.") || new.kind.starts_with("presets."))
            && let Some(payload) = new
                .payload_json
                .as_deref()
                .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
            && let Some(force) = payload.get("force")
        {
            let Some(force) = force.as_bool() else {
                return Err(OperationUseCaseError::Invalid {
                    detail: "force must be a boolean".to_owned(),
                });
            };
            if force && new.kind != "skills.set-source" {
                return Err(OperationUseCaseError::Invalid {
                    detail: "force is supported only for skills.set-source".to_owned(),
                });
            }
        }
        if new.kind == "presets.create"
            && new
                .payload_json
                .as_deref()
                .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
                .is_some_and(|payload| payload.get("name").is_some())
        {
            return Err(OperationUseCaseError::Invalid {
                detail: "presets.create uses reference as its name; name is only valid for update"
                    .to_owned(),
            });
        }

        if let Some(payload_json) = &new.payload_json
            && payload_json.len() > MAX_PAYLOAD_JSON
        {
            return Err(OperationUseCaseError::Invalid {
                detail: format!("the payload exceeds {MAX_PAYLOAD_JSON} bytes"),
            });
        }
        let rollout_payload = catalog_rollout_payload(new)?;

        // The checkout and skills kinds act on a machine through SSH, so
        // their creation carries the machine-scoped authorization the
        // dedicated endpoints enforce: a caller with operation.create but
        // without the kind's permission cannot route around it through
        // the generic surface. The machine id is read from the payload
        // without deserializing the whole record.
        if let Some(permission) =
            machine_scoped_kind_permission(&new.kind, new.payload_json.as_deref())
        {
            let machine_id = new
                .payload_json
                .as_deref()
                .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
                .and_then(|payload| {
                    payload["machineId"]
                        .as_str()
                        .map(std::borrow::ToOwned::to_owned)
                })
                .ok_or(OperationUseCaseError::Invalid {
                    detail: format!("the {} payload must carry a machineId", new.kind),
                })?;
            authorize(
                authorizer,
                AccessRequest {
                    principal_id,
                    action: permission,
                    resource: Some(&machine_id),
                },
            )
            .map_err(OperationUseCaseError::Denied)?;
            if new.kind == "skills.catalog-rollout" {
                let rollout = rollout_payload
                    .as_ref()
                    .expect("catalog rollout parsed above");
                authorize(
                    authorizer,
                    AccessRequest {
                        principal_id,
                        action: Permission::SkillsRead,
                        resource: Some(&rollout.catalog_id),
                    },
                )
                .map_err(OperationUseCaseError::Denied)?;
                let targets = self.catalog_rollout_targets.as_ref().ok_or(
                    OperationUseCaseError::Invalid {
                        detail: "catalog rollout target validation is unavailable".to_owned(),
                    },
                )?;
                let endpoint_kind = targets
                    .endpoint_kind(&rollout.machine_id, &rollout.endpoint_id)
                    .await
                    .map_err(|failure| match failure {
                        PortFailure::NotFound { what } => OperationUseCaseError::NotFound { what },
                        failure => OperationUseCaseError::Backend {
                            context: "catalog rollout target lookup",
                            detail: failure.to_string(),
                        },
                    })?
                    .ok_or(OperationUseCaseError::NotFound {
                        what: format!(
                            "endpoint {} on machine {}",
                            rollout.endpoint_id, rollout.machine_id
                        ),
                    })?;
                if endpoint_kind != fleet_core::EndpointKind::Ssh {
                    return Err(OperationUseCaseError::Invalid {
                        detail: "catalog rollout requires an SSH endpoint".to_owned(),
                    });
                }
            }
        } else if new.kind == "lab.provision" {
            if !allow_lab_provision {
                return Err(OperationUseCaseError::Invalid {
                    detail: "lab.provision must use the dedicated lease provisioning route"
                        .to_owned(),
                });
            }
            let lease_id = new
                .payload_json
                .as_deref()
                .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
                .and_then(|payload| payload["leaseId"].as_str().map(str::to_owned))
                .ok_or(OperationUseCaseError::Invalid {
                    detail: "the lab.provision payload must carry a leaseId".to_owned(),
                })?;
            authorize(
                authorizer,
                AccessRequest {
                    principal_id,
                    action: Permission::LabProvision,
                    resource: Some(&lease_id),
                },
            )
            .map_err(OperationUseCaseError::Denied)?;
        } else if let Some(permission) = catalog_scoped_kind_permission(&new.kind) {
            // The destructive-adjacent Proxmox kinds never route through
            // the generic surface: their creation goes through the
            // dedicated reviewed endpoint, which binds the operation to a
            // confirmed review token. A generic-surface create is a
            // route-around attempt, refused as malformed.
            if DESTRUCTIVE_KINDS.contains(&new.kind.as_str()) {
                // The review token is the SHA-256 of the canonical
                // operation material, recomputed here: a caller that never
                // reviewed these exact bytes cannot present a matching
                // token, and setting the field arbitrarily fails the
                // comparison.
                let expected =
                    review_token_for(&new.kind, new.payload_json.as_deref().unwrap_or_default());
                match new.review_token.as_deref() {
                    Some(presented) if constant_time_eq(presented, &expected) => {}
                    _ => {
                        return Err(OperationUseCaseError::Invalid {
                            detail: format!(
                                "the {kind} kind is destructive-adjacent and requires a valid review token; review the operation first",
                                kind = new.kind
                            ),
                        });
                    }
                }
            }
            authorize(
                authorizer,
                AccessRequest {
                    principal_id,
                    action: permission,
                    resource: None,
                },
            )
            .map_err(OperationUseCaseError::Denied)?;
        }
        let operation = self
            .port
            .create(
                &new.kind,
                new.idempotency_key.as_deref(),
                new.deadline_at,
                new.correlation_id.as_deref(),
                new.payload_json.as_deref(),
            )
            .await
            .map_err(map_port_failure("create"))?;
        self.publish_operation(&operation, false);

        let mut metadata = AuditMetadata::default();
        metadata
            .insert("kind", &new.kind)
            .map_err(|error| OperationUseCaseError::Backend {
                context: "create_audit",
                detail: error.to_string(),
            })?;
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal_id.to_owned(),
                action: Permission::OperationCreate.id().to_owned(),
                resource: Some(operation.id.clone()),
                decision: Decision::allow(),
                correlation_id: new.correlation_id.clone(),
                operation_id: Some(operation.id.clone()),
                metadata,
            })
            .await
            .map_err(|detail| OperationUseCaseError::Backend {
                context: "create_audit",
                detail,
            })?;
        Ok(operation)
    }

    /// Claims one specific operation for `worker_id` if it is still
    /// pending, executes it through `executor`, and records the terminal
    /// state — the same shape a queue tick produces, but addressed. The
    /// ready workflow's steps run through this so each inner operation is
    /// durable and audited without re-entering the queue.
    ///
    /// # Errors
    ///
    /// Fails when the claim or execution fails; the operation records its
    /// own terminal state either way.
    pub async fn claim_only_execute(
        &self,
        executor: &dyn crate::worker::OperationExecutor,
        id: &str,
        worker_id: &str,
    ) -> Result<(), String> {
        let now = fleet_core::SystemClock::now_unix_millis();
        // Only a successfully claimed operation executes: an already
        // claimed, cancelled, or completed operation returns None, and
        // running it anyway would duplicate or contradict its state.
        let Some(operation) = self
            .port
            .claim_pending_by_id(id, worker_id, now)
            .await
            .map_err(|failure| failure.to_string())?
        else {
            return Err(format!("the operation {id} could not be claimed"));
        };
        self.publish_operation(&operation, false);
        // The claim is renewed while the step runs, so a long SSH step
        // cannot be marked failed by maintenance mid-flight.
        let renewal = {
            let port = self.port.clone();
            let id = id.to_owned();
            let worker_id = worker_id.to_owned();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    if port
                        .renew_lease(
                            &id,
                            &worker_id,
                            fleet_core::SystemClock::now_unix_millis(),
                            60_000,
                        )
                        .await
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    break;
                }
            })
        };
        let outcome = executor.execute(self, &operation).await;
        renewal.abort();
        if let Err(detail) = outcome {
            // The failure goes through the use case so the audit outcome
            // is recorded exactly like the queue execution path.
            self.complete(
                id,
                "failed",
                None,
                Some(
                    &serde_json::json!({
                        "reason": "step_failed",
                        "detail": detail,
                    })
                    .to_string(),
                ),
            )
            .await
            .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    /// Reads one operation's current state id, when it exists. The
    /// workflow executor polls this between steps.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    pub async fn get_state(&self, id: &str) -> Result<String, PortFailure> {
        let operation = self.port.get(id).await?;
        Ok(operation.state)
    }

    /// Whether cancellation has been requested for the operation. The
    /// worker reads this between poll cycles; it bypasses authorization
    /// like the other worker-side reads, because the worker already owns
    /// the claimed operation.
    ///
    /// # Errors
    ///
    /// Fails when the operation is unknown or the backend errors.
    pub async fn cancel_requested(&self, id: &str) -> Result<bool, PortFailure> {
        let operation = self.port.get(id).await?;
        Ok(operation.cancel_requested)
    }

    /// Reads one operation.
    ///
    /// # Errors
    ///
    /// Fails on denial, unknown id, or a backend failure.
    pub async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        id: &str,
    ) -> Result<Operation, OperationUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::OperationRead,
                resource: Some(id),
            },
        )
        .map_err(OperationUseCaseError::Denied)?;
        self.port.get(id).await.map_err(map_port_failure("get"))
    }

    /// Lists operations, newest first.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        limit: u32,
    ) -> Result<Vec<Operation>, OperationUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::OperationRead,
                resource: None,
            },
        )
        .map_err(OperationUseCaseError::Denied)?;
        self.port
            .list(limit)
            .await
            .map_err(map_port_failure("list"))
    }

    /// Requests cancellation of an operation.
    ///
    /// # Errors
    ///
    /// Fails on denial, unknown id, or a backend failure.
    pub async fn cancel(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        id: &str,
    ) -> Result<Operation, OperationUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::OperationCancel,
                resource: Some(id),
            },
        )
        .map_err(OperationUseCaseError::Denied)?;

        let existing = self
            .port
            .get(id)
            .await
            .map_err(map_port_failure("cancel_get"))?;
        if existing.state == "succeeded"
            || existing.state == "failed"
            || existing.state == "cancelled"
            || existing.state == "timed_out"
            || existing.state == "blocked_manual_approval"
        {
            return Err(OperationUseCaseError::NotFound {
                what: format!("live operation {id}"),
            });
        }

        let operation = self
            .port
            .request_cancel(id)
            .await
            .map_err(map_port_failure("cancel"))?;
        self.publish_operation(&operation, false);

        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal_id.to_owned(),
                action: Permission::OperationCancel.id().to_owned(),
                resource: Some(id.to_owned()),
                decision: Decision::allow(),
                correlation_id: operation.correlation_id.clone(),
                operation_id: Some(id.to_owned()),
                metadata: AuditMetadata::default(),
            })
            .await
            .map_err(|detail| OperationUseCaseError::Backend {
                context: "cancel_audit",
                detail,
            })?;
        Ok(operation)
    }

    /// Marks an operation terminal with bounded public payloads and appends
    /// the audit outcome. Called by the operation worker, not by callers.
    ///
    /// # Errors
    ///
    /// Fails on a backend failure or an illegal transition.
    pub async fn complete(
        &self,
        id: &str,
        state: &str,
        result_json: Option<&str>,
        error_json: Option<&str>,
    ) -> Result<Operation, OperationUseCaseError> {
        let operation = self
            .port
            .complete(id, state, result_json, error_json)
            .await
            .map_err(map_port_failure("complete"))?;
        self.publish_operation(&operation, true);
        let outcome = match state {
            "succeeded" => AuditOutcome::Succeeded,
            "cancelled" => AuditOutcome::Cancelled,
            "blocked_manual_approval" => AuditOutcome::BlockedManualApproval,
            _ => AuditOutcome::Failed,
        };
        self.audit
            .record_outcome(id, outcome)
            .await
            .map_err(|detail| OperationUseCaseError::Backend {
                context: "complete_audit",
                detail,
            })?;
        Ok(operation)
    }
}

fn skills_payload_has_credentials(payload: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
        return false;
    };
    let mut candidates = Vec::new();
    for key in ["reference", "sourceUrl", "artifactUrl"] {
        if let Some(value) = value.get(key).and_then(serde_json::Value::as_str) {
            candidates.push(value);
        }
    }
    if let Some(references) = value
        .get("references")
        .and_then(serde_json::Value::as_array)
    {
        candidates.extend(references.iter().filter_map(serde_json::Value::as_str));
    }
    candidates.into_iter().any(|value| {
        let has_credential_parameter = |query: &str| {
            query.split('&').any(|pair| {
                let key = pair
                    .split('=')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                [
                    "token",
                    "access_token",
                    "refresh_token",
                    "password",
                    "passwd",
                    "secret",
                    "client_secret",
                    "api_key",
                    "apikey",
                    "auth",
                    "signature",
                    "sig",
                    "credential",
                ]
                .contains(&key.as_str())
            })
        };
        let credential_query = value
            .split(['?', '#'])
            .skip(1)
            .any(has_credential_parameter);
        let credential_userinfo = value.split_once("://").is_some_and(|(scheme, rest)| {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
            authority.split_once('@').is_some_and(|(userinfo, _)| {
                !(scheme.eq_ignore_ascii_case("ssh")
                    && userinfo == "git"
                    && authority.matches('@').count() == 1)
            })
        });
        credential_query || value.chars().any(char::is_control) || credential_userinfo
    })
}

fn map_port_failure(context: &'static str) -> impl Fn(PortFailure) -> OperationUseCaseError {
    move |failure| match failure {
        PortFailure::Conflict { detail } => OperationUseCaseError::Invalid { detail },
        PortFailure::NotFound { what } => OperationUseCaseError::NotFound { what },
        PortFailure::Backend { detail } => OperationUseCaseError::Backend { context, detail },
    }
}

/// Convenience: the reason a denied use case surfaces.
impl OperationUseCaseError {
    /// The stable denial reason, when this error is a denial.
    #[must_use]
    pub const fn reason(&self) -> Option<ReasonId> {
        match self {
            Self::Denied(decision) => Some(decision.reason),
            _ => None,
        }
    }
}

#[cfg(test)]
mod skills_permission_tests {
    use super::{CREATABLE_KINDS, machine_scoped_kind_permission, skills_payload_has_credentials};
    use crate::authz::Permission;

    #[test]
    fn every_library_and_preset_kind_is_creatable_with_its_dedicated_permission() {
        for kind in [
            "skills.install",
            "skills.update",
            "skills.check",
            "skills.remove",
            "skills.adopt",
            "skills.set-source",
            "presets.create",
            "presets.update",
            "presets.delete",
            "presets.add-skill",
            "presets.remove-skill",
        ] {
            assert!(CREATABLE_KINDS.contains(&kind), "{kind}");
            assert_eq!(
                machine_scoped_kind_permission(kind, None),
                Some(Permission::SkillsModify),
                "{kind}"
            );
        }
        for kind in [
            "skills.catalog-rollout",
            "presets.deploy",
            "presets.undeploy",
        ] {
            assert!(CREATABLE_KINDS.contains(&kind), "{kind}");
            assert_eq!(
                machine_scoped_kind_permission(kind, None),
                Some(Permission::SkillsDeploy),
                "{kind}"
            );
        }
    }

    #[test]
    fn skills_source_credential_queries_are_rejected_without_a_url_scheme() {
        assert!(skills_payload_has_credentials(
            r#"{"reference":"skill?access_token=secret"}"#
        ));
        assert!(skills_payload_has_credentials(
            r#"{"sourceUrl":"org/repo?token=secret"}"#
        ));
        assert!(!skills_payload_has_credentials(
            r#"{"reference":"org/repo/skill?branch=stable"}"#
        ));
        assert!(skills_payload_has_credentials(
            r#"{"sourceUrl":"https://example.invalid/repo#access_token=secret"}"#
        ));
        assert!(!skills_payload_has_credentials(
            r#"{"sourceUrl":"ssh://git@github.com/org/repo.git"}"#
        ));
        assert!(skills_payload_has_credentials(
            r#"{"sourceUrl":"ssh://git@user:secret@github.com/org/repo.git"}"#
        ));
    }
}

#[cfg(test)]
mod catalog_rollout_authorization_tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use super::{
        AuditPort, CatalogRolloutTargetPort, NewOperation, Operation, OperationPort, Operations,
        PortFailure, QueueDepths,
    };
    use crate::audit::{AuditIntent, AuditOutcome};
    use crate::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
    use fleet_core::EndpointKind;

    #[derive(Debug, Default)]
    struct RecordingPort(Mutex<Vec<Operation>>);

    #[async_trait]
    impl OperationPort for RecordingPort {
        async fn create(
            &self,
            kind: &str,
            key: Option<&str>,
            deadline: Option<i64>,
            correlation: Option<&str>,
            payload: Option<&str>,
        ) -> Result<Operation, PortFailure> {
            let operation = Operation {
                id: "operation-1".to_owned(),
                kind: kind.to_owned(),
                state: "pending".to_owned(),
                idempotency_key: key.map(str::to_owned),
                progress_current: None,
                progress_total: None,
                progress_message: None,
                deadline_at: deadline,
                cancel_requested: false,
                payload_json: payload.map(str::to_owned),
                result_json: None,
                error_json: None,
                correlation_id: correlation.map(str::to_owned),
                created_at: 0,
                updated_at: 0,
                claimed_at: None,
                worker_id: None,
            };
            self.0.lock().unwrap().push(operation.clone());
            Ok(operation)
        }
        async fn get(&self, _: &str) -> Result<Operation, PortFailure> {
            Err(missing())
        }
        async fn list(&self, _: u32) -> Result<Vec<Operation>, PortFailure> {
            Ok(Vec::new())
        }
        async fn request_cancel(&self, _: &str) -> Result<Operation, PortFailure> {
            Err(missing())
        }
        async fn transition(&self, _: &str, _: &str) -> Result<Operation, PortFailure> {
            Err(missing())
        }
        async fn complete(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<Operation, PortFailure> {
            Err(missing())
        }
        async fn record_progress(
            &self,
            _: &str,
            _: Option<i64>,
            _: Option<i64>,
            _: Option<&str>,
        ) -> Result<(), PortFailure> {
            Ok(())
        }
        async fn claim_pending(&self, _: &str, _: i64) -> Result<Option<Operation>, PortFailure> {
            Ok(None)
        }
        async fn claim_pending_by_id(
            &self,
            _: &str,
            _: &str,
            _: i64,
        ) -> Result<Option<Operation>, PortFailure> {
            Ok(None)
        }
        async fn expired_claims(&self, _: i64, _: i64) -> Result<Vec<Operation>, PortFailure> {
            Ok(Vec::new())
        }
        async fn renew_lease(&self, _: &str, _: &str, _: i64, _: i64) -> Result<bool, PortFailure> {
            Ok(false)
        }
        async fn fail_expired_claim(
            &self,
            _: &str,
            _: i64,
            _: i64,
            _: &str,
        ) -> Result<bool, PortFailure> {
            Ok(false)
        }
        async fn sweep_deadlines(&self, _: i64) -> Result<Vec<String>, PortFailure> {
            Ok(Vec::new())
        }
        async fn queue_depths(&self) -> Result<QueueDepths, PortFailure> {
            Ok(QueueDepths::default())
        }
    }

    fn missing() -> PortFailure {
        PortFailure::NotFound {
            what: "test operation".to_owned(),
        }
    }

    #[derive(Debug, Default)]
    struct RecordingAudit;

    #[async_trait]
    impl AuditPort for RecordingAudit {
        async fn record_intent(&self, _: &AuditIntent) -> Result<(), String> {
            Ok(())
        }
        async fn record_outcome(&self, _: &str, _: AuditOutcome) -> Result<(), String> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct Policy {
        deny: Option<Permission>,
        seen: Mutex<Vec<Permission>>,
    }

    impl Authorizer for Policy {
        fn decide(&self, request: AccessRequest<'_>) -> Decision {
            self.seen.lock().unwrap().push(request.action);
            if self.deny == Some(request.action) {
                Decision::deny(ReasonId::UnknownPrincipal)
            } else {
                Decision::allow()
            }
        }
    }

    #[derive(Debug)]
    struct RecordingTargets(Option<EndpointKind>);

    #[async_trait]
    impl CatalogRolloutTargetPort for RecordingTargets {
        async fn endpoint_kind(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<EndpointKind>, PortFailure> {
            Ok(self.0)
        }
    }

    fn request(payload: &serde_json::Value) -> NewOperation {
        NewOperation {
            kind: "skills.catalog-rollout".to_owned(),
            payload_json: Some(payload.to_string()),
            ..NewOperation::default()
        }
    }

    #[tokio::test]
    async fn catalog_rollout_rejects_missing_catalog_id_before_creation() {
        let port = Arc::new(RecordingPort::default());
        let operations = Operations::new(port.clone(), Arc::new(RecordingAudit));
        let authorizer = Policy {
            deny: None,
            seen: Mutex::new(Vec::new()),
        };
        let result = operations
            .create(
                &authorizer,
                "operator",
                &request(&serde_json::json!({"machineId":"m1"})),
            )
            .await;
        assert!(matches!(
            result,
            Err(super::OperationUseCaseError::Invalid { .. })
        ));
        assert!(port.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn catalog_rollout_requires_catalog_read_after_machine_deploy_permission() {
        let port = Arc::new(RecordingPort::default());
        let operations = Operations::new_with_catalog_rollout_targets(
            port.clone(),
            Arc::new(RecordingAudit),
            Arc::new(RecordingTargets(Some(EndpointKind::Ssh))),
        );
        let authorizer = Policy {
            deny: Some(Permission::SkillsRead),
            seen: Mutex::new(Vec::new()),
        };
        let result = operations
            .create(
                &authorizer,
                "operator",
                &request(&serde_json::json!({
                    "machineId":"m1", "endpointId":"ssh1", "versionId":"v1", "catalogId":"c1",
                    "agents":["codex"], "timeoutSeconds":60
                })),
            )
            .await;
        assert!(matches!(
            result,
            Err(super::OperationUseCaseError::Denied(_))
        ));
        assert!(
            authorizer
                .seen
                .lock()
                .unwrap()
                .contains(&Permission::SkillsDeploy)
        );
        assert!(
            authorizer
                .seen
                .lock()
                .unwrap()
                .contains(&Permission::SkillsRead)
        );
        assert!(port.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn catalog_rollout_creation_passes_both_scoped_authorization_checks() {
        let port = Arc::new(RecordingPort::default());
        let operations = Operations::new_with_catalog_rollout_targets(
            port.clone(),
            Arc::new(RecordingAudit),
            Arc::new(RecordingTargets(Some(EndpointKind::Ssh))),
        );
        let authorizer = Policy {
            deny: None,
            seen: Mutex::new(Vec::new()),
        };
        let result = operations
            .create(
                &authorizer,
                "operator",
                &request(&serde_json::json!({
                    "machineId":"m1", "endpointId":"ssh1", "versionId":"v1", "catalogId":"c1",
                    "agents":["codex"], "timeoutSeconds":60
                })),
            )
            .await
            .unwrap();
        assert_eq!(result.kind, "skills.catalog-rollout");
        let seen = authorizer.seen.lock().unwrap();
        assert!(seen.contains(&Permission::OperationCreate));
        assert!(seen.contains(&Permission::SkillsDeploy));
        assert!(seen.contains(&Permission::SkillsRead));
        assert_eq!(port.0.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn catalog_rollout_rejects_duplicate_agents_and_out_of_range_timeouts() {
        for payload in [
            serde_json::json!({
                "machineId":"m1", "endpointId":"ssh1", "versionId":"v1", "catalogId":"c1",
                "agents":["codex", "codex"], "timeoutSeconds":60
            }),
            serde_json::json!({
                "machineId":"m1", "endpointId":"ssh1", "versionId":"v1", "catalogId":"c1",
                "agents":["codex"], "timeoutSeconds":3601
            }),
        ] {
            let port = Arc::new(RecordingPort::default());
            let operations = Operations::new(port.clone(), Arc::new(RecordingAudit));
            let authorizer = Policy {
                deny: None,
                seen: Mutex::new(Vec::new()),
            };
            let result = operations
                .create(&authorizer, "operator", &request(&payload))
                .await;
            assert!(matches!(
                result,
                Err(super::OperationUseCaseError::Invalid { .. })
            ));
            assert!(port.0.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn catalog_rollout_rejects_non_ssh_endpoint_before_creation() {
        let port = Arc::new(RecordingPort::default());
        let operations = Operations::new_with_catalog_rollout_targets(
            port.clone(),
            Arc::new(RecordingAudit),
            Arc::new(RecordingTargets(Some(EndpointKind::Fleetd))),
        );
        let authorizer = Policy {
            deny: None,
            seen: Mutex::new(Vec::new()),
        };
        let result = operations
            .create(
                &authorizer,
                "operator",
                &request(&serde_json::json!({
                    "machineId":"m1", "endpointId":"node1", "versionId":"v1", "catalogId":"c1",
                    "agents":["codex"], "timeoutSeconds":60
                })),
            )
            .await;
        assert!(matches!(
            result,
            Err(super::OperationUseCaseError::Invalid { .. })
        ));
        assert!(port.0.lock().unwrap().is_empty());
    }
}
