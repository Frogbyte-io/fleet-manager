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
/// `dryRun` (FM-301, FM-302).
pub const CREATABLE_KINDS: [&str; 17] = [
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
];

/// The machine-scoped permission a kind's creation requires, when any.
/// The checkout and skills kinds act on machines through SSH; creating
/// their operations is itself the risky act, so the same catalog entry
/// governs both the dedicated endpoint and the generic one.
#[must_use]
fn machine_scoped_kind_permission(kind: &str) -> Option<Permission> {
    match kind {
        "projects.discover" => Some(Permission::ProjectsDiscover),
        "projects.clone" | "projects.pull" | "projects.status" | "projects.write-config" => {
            Some(Permission::ProjectsGitWrite)
        }
        "skills.probe" => Some(Permission::SkillsRead),
        "skills.deploy" | "skills.undeploy" => Some(Permission::SkillsDeploy),
        _ => None,
    }
}

/// The payload bound for provider inputs.
pub const MAX_PAYLOAD_JSON: usize = 128 * 1024;

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
}

/// The authorized operation use cases.
#[derive(Debug)]
pub struct Operations {
    pub(crate) port: Arc<dyn OperationPort>,
    audit: Arc<dyn AuditPort>,
}

impl Operations {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(port: Arc<dyn OperationPort>, audit: Arc<dyn AuditPort>) -> Self {
        Self { port, audit }
    }

    /// Creates an operation after authorization, recording the audit intent
    /// for the accepted mutation.
    ///
    /// # Errors
    ///
    /// Fails on denial, unknown kind, or a backend failure.
    pub async fn create(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        new: &NewOperation,
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

        if let Some(payload_json) = &new.payload_json
            && payload_json.len() > MAX_PAYLOAD_JSON
        {
            return Err(OperationUseCaseError::Invalid {
                detail: format!("the payload exceeds {MAX_PAYLOAD_JSON} bytes"),
            });
        }

        // The checkout and skills kinds act on a machine through SSH, so
        // their creation carries the machine-scoped authorization the
        // dedicated endpoints enforce: a caller with operation.create but
        // without the kind's permission cannot route around it through
        // the generic surface. The machine id is read from the payload
        // without deserializing the whole record.
        if let Some(permission) = machine_scoped_kind_permission(&new.kind) {
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
        let outcome = match state {
            "succeeded" => AuditOutcome::Succeeded,
            "cancelled" => AuditOutcome::Cancelled,
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
