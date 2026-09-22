//! The operation endpoints: create, list, detail, and cancel, all behind the
//! application's authorized use cases.
//!
//! These handlers decide nothing about permissions and nothing about
//! operations; they translate HTTP into use-case calls and use-case outcomes
//! into the public envelopes. The acting principal arrives from the caller
//! resolution middleware, the correlation identity from the correlation
//! middleware, and the application service owns the rest.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use fleet_application::authz::Authorizer;
use fleet_application::operation::{Operation, OperationUseCaseError, Operations, PortFailure};
use fleet_core::PublicError;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};
use std::str::FromStr as _;

use fleet_core::{CorrelationId, ErrorCode, RetryClass};

/// Everything the handlers need: the authorized use cases and the policy that
/// decides who may call them.
#[derive(Clone)]
pub struct ApiState {
    /// The operation use cases.
    pub operations: Arc<Operations>,
    /// The active authorization policy.
    pub authorizer: Arc<dyn Authorizer>,
    /// The system view's source, assembled by the controller.
    pub system: Arc<dyn crate::system::SystemInfoSource>,
    /// The node trust use cases, when the controller was composed with a
    /// database and a master key; `None` only in document/test states.
    pub nodes: Option<Arc<fleet_application::node::Nodes>>,
    /// The machine use cases, when the controller was composed with a
    /// database; `None` only in document/test states.
    pub machines: Option<Arc<fleet_application::machine::Machines>>,
    /// The Add Machine onboarding use cases, when the controller was
    /// composed with a database; `None` only in document/test states.
    pub onboarding: Option<Arc<fleet_application::onboarding::Onboarding>>,
    /// The Tailscale discovery use cases, when the controller was composed
    /// with a database, a secret store, and the integration wired;
    /// `None` only in document/test states.
    pub tailnet: Option<Arc<fleet_application::tailnet::TailnetIntegration>>,
    /// The project use cases, when the controller was composed with a
    /// database; `None` only in document/test states.
    pub projects: Option<Arc<fleet_application::project::Projects>>,
    /// The Proxmox use cases, when the controller was composed with a
    /// database, a secret store, and the provider wired; `None` only in
    /// document/test states.
    pub proxmox: Option<Arc<fleet_application::proxmox::ProxmoxAccounts>>,
    /// The image use cases, when the controller was composed with a
    /// database; `None` only in document/test states.
    pub images: Option<Arc<fleet_application::images::Images>>,
}

impl std::fmt::Debug for ApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiState")
            .field("operations", &self.operations)
            .field("authorizer", &"dyn Authorizer")
            .field("system", &"dyn SystemInfoSource")
            .field("nodes", &self.nodes)
            .field("machines", &self.machines)
            .field("onboarding", &self.onboarding)
            .field("tailnet", &self.tailnet)
            .field("projects", &self.projects)
            .field("proxmox", &self.proxmox)
            .field("images", &self.images)
            .finish()
    }
}

/// A backend that answers nothing. It exists so the `OpenAPI` document can be
/// generated from the real router without touching a database.
#[derive(Debug)]
struct UnavailableBackend;

#[async_trait::async_trait]
impl fleet_application::operation::OperationPort for UnavailableBackend {
    async fn create(
        &self,
        _kind: &str,
        _idempotency_key: Option<&str>,
        _deadline_at: Option<i64>,
        _correlation_id: Option<&str>,
        _payload_json: Option<&str>,
    ) -> Result<Operation, PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "no backend is wired".to_owned(),
        })
    }
    async fn get(&self, _id: &str) -> Result<Operation, PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "no backend is wired".to_owned(),
        })
    }
    async fn list(&self, _limit: u32) -> Result<Vec<Operation>, PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "no backend is wired".to_owned(),
        })
    }
    async fn request_cancel(&self, _id: &str) -> Result<Operation, PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "no backend is wired".to_owned(),
        })
    }
    async fn transition(&self, _id: &str, _state: &str) -> Result<Operation, PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "no backend is wired".to_owned(),
        })
    }
    async fn complete(
        &self,
        _id: &str,
        _state: &str,
        _result_json: Option<&str>,
        _error_json: Option<&str>,
    ) -> Result<Operation, PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "no backend is wired".to_owned(),
        })
    }
    async fn record_progress(
        &self,
        _id: &str,
        _current: Option<i64>,
        _total: Option<i64>,
        _message: Option<&str>,
    ) -> Result<(), PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "no backend is wired".to_owned(),
        })
    }
    async fn claim_pending(
        &self,
        _worker_id: &str,
        _now: i64,
    ) -> Result<Option<Operation>, PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "no backend is wired".to_owned(),
        })
    }
    async fn claim_pending_by_id(
        &self,
        _id: &str,
        _worker_id: &str,
        _now: i64,
    ) -> Result<Option<Operation>, PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "no backend is wired".to_owned(),
        })
    }
    async fn expired_claims(
        &self,
        _now: i64,
        _lease_ms: i64,
    ) -> Result<Vec<Operation>, PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "no backend is wired".to_owned(),
        })
    }
    async fn renew_lease(
        &self,
        _id: &str,
        _worker_id: &str,
        _now: i64,
        _lease_ms: i64,
    ) -> Result<bool, PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "no backend is wired".to_owned(),
        })
    }
    async fn fail_expired_claim(
        &self,
        _id: &str,
        _expected_claimed_at: i64,
        _now: i64,
        _error_json: &str,
    ) -> Result<bool, PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "no backend is wired".to_owned(),
        })
    }
    async fn sweep_deadlines(&self, _now: i64) -> Result<Vec<String>, PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "no backend is wired".to_owned(),
        })
    }
    async fn queue_depths(&self) -> Result<fleet_application::operation::QueueDepths, PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "no backend is wired".to_owned(),
        })
    }
}

#[async_trait::async_trait]
impl fleet_application::operation::AuditPort for UnavailableBackend {
    async fn record_intent(
        &self,
        _intent: &fleet_application::audit::AuditIntent,
    ) -> Result<(), String> {
        Err("no backend is wired".to_owned())
    }
    async fn record_outcome(
        &self,
        _operation_id: &str,
        _outcome: fleet_application::audit::AuditOutcome,
    ) -> Result<(), String> {
        Err("no backend is wired".to_owned())
    }
}

/// Answers nothing; document generation only.
#[derive(Debug)]
struct UnavailableSystemInfo;

#[async_trait::async_trait]
impl crate::system::SystemInfoSource for UnavailableSystemInfo {
    async fn info(&self) -> Result<crate::system::SystemInfo, String> {
        Err("no backend is wired".to_owned())
    }
}

impl ApiState {
    /// A state whose backends answer nothing, for document generation.
    #[must_use]
    pub fn for_document() -> Self {
        Self {
            operations: Arc::new(Operations::new(
                Arc::new(UnavailableBackend),
                Arc::new(UnavailableBackend),
            )),
            authorizer: Arc::new(PermitAllForDocument),
            system: Arc::new(UnavailableSystemInfo),
            nodes: None,
            machines: None,
            onboarding: None,
            tailnet: None,
            projects: None,
            proxmox: None,
            images: None,
        }
    }
}

/// Permits the catalog so document generation exercises the same code paths
/// as a serving router; it never answers real traffic.
#[derive(Debug)]
struct PermitAllForDocument;

impl Authorizer for PermitAllForDocument {
    fn decide(
        &self,
        _request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        fleet_application::authz::Decision::allow()
    }
}

/// The public operation resource. The application type is the transport
/// truth; this type is the documented shape, kept one `From` away so the two
/// cannot drift silently.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperationDto {
    /// The operation's identity.
    pub id: String,
    /// What kind of work this is.
    #[schema(example = "noop")]
    pub kind: String,
    /// The current state: `pending`, `running`, `cancelling`, `succeeded`,
    /// `failed`, `cancelled`, `timed_out`, or `blocked_manual_approval`.
    #[schema(example = "pending")]
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
    /// The bounded public result, present when the operation succeeded.
    pub result_json: Option<String>,
    /// The bounded public error, present when the operation failed.
    pub error_json: Option<String>,
    /// The correlation identity joining this operation to the caller's flow.
    pub correlation_id: Option<String>,
    /// Creation time, in epoch milliseconds.
    pub created_at: i64,
    /// Last update, in epoch milliseconds.
    pub updated_at: i64,
}

impl From<Operation> for OperationDto {
    fn from(operation: Operation) -> Self {
        Self {
            id: operation.id,
            kind: operation.kind,
            state: operation.state,
            idempotency_key: operation.idempotency_key,
            progress_current: operation.progress_current,
            progress_total: operation.progress_total,
            progress_message: operation.progress_message,
            deadline_at: operation.deadline_at,
            cancel_requested: operation.cancel_requested,
            result_json: operation.result_json,
            error_json: operation.error_json,
            correlation_id: operation.correlation_id,
            created_at: operation.created_at,
            updated_at: operation.updated_at,
        }
    }
}

/// The body of the create-operation request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateOperationRequest {
    /// The kind of work to create; only kinds the controller can describe are
    /// accepted.
    #[schema(example = "noop")]
    pub kind: String,
    /// The bounded provider input for kinds that need one, e.g. the script
    /// payload of `ssh.exec`.
    pub payload_json: Option<String>,
    /// A caller-chosen key making this request idempotent: replaying it
    /// returns the original operation instead of creating a second one.
    #[schema(example = "bootstrap-2026-09-03")]
    pub idempotency_key: Option<String>,
    /// The absolute deadline, in Unix epoch milliseconds, after which the
    /// operation must be treated as timed out. Absent means no deadline.
    pub deadline_at: Option<i64>,
}

/// The list-operations query parameters.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListOperationsParams {
    /// The maximum number of operations to return.
    pub limit: Option<u32>,
}

/// Creates an operation.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    post,
    path = "/operations",
    tag = "operations",
    operation_id = "createOperation",
    request_body = CreateOperationRequest,
    responses(
        (
            status = 201,
            description = "The operation was accepted and is durable.",
            body = Resource<OperationDto>
        ),
        (
            status = 400,
            description = "The request is malformed, or names an unknown kind.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not create operations.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn create_operation(
    State(state): State<Arc<ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Json(request): Json<CreateOperationRequest>,
) -> Result<(StatusCode, Json<Resource<OperationDto>>), ApiErrorResponse> {
    let principal = principal_or_error(principal, correlation_id)?;
    let operation = state
        .operations
        .create(
            state.authorizer.as_ref(),
            &principal.id,
            &fleet_application::operation::NewOperation {
                kind: request.kind.clone(),
                idempotency_key: request.idempotency_key.clone(),
                deadline_at: request.deadline_at,
                correlation_id: Some(correlation_id.to_string()),
                payload_json: request.payload_json.clone(),
                review_token: None,
            },
        )
        .await
        .map_err(|error| map_use_case_error(&error, correlation_id))?;
    Ok((
        StatusCode::CREATED,
        Json(Resource::new(OperationDto::from(operation))),
    ))
}

/// Lists operations, newest first.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/operations",
    tag = "operations",
    operation_id = "listOperations",
    params(
        ("limit" = Option<u32>, Query, description = "The maximum number of operations to return.")
    ),
    responses(
        (
            status = 200,
            description = "A page of operations.",
            body = Page<OperationDto>
        ),
        (
            status = 403,
            description = "The caller may not read operations.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn list_operations(
    State(state): State<Arc<ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<ListOperationsParams>,
) -> Result<Json<Page<OperationDto>>, ApiErrorResponse> {
    let principal = principal_or_error(principal, correlation_id)?;
    let limit = params
        .limit
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .min(MAX_PAGE_LIMIT);
    let operations = state
        .operations
        .list(state.authorizer.as_ref(), &principal.id, limit)
        .await
        .map_err(|error| map_use_case_error(&error, correlation_id))?;
    let next_cursor = (operations.len() == usize::try_from(limit).unwrap_or(0))
        .then(|| operations.last().map(|operation| operation.id.clone()))
        .flatten();
    Ok(Json(Page {
        items: operations.into_iter().map(OperationDto::from).collect(),
        page: PageInfo { next_cursor, limit },
    }))
}

/// Reads one operation.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/operations/{id}",
    tag = "operations",
    operation_id = "getOperation",
    params(
        ("id" = String, Path, description = "The operation's identity.")
    ),
    responses(
        (
            status = 200,
            description = "The operation.",
            body = Resource<OperationDto>
        ),
        (
            status = 404,
            description = "No such operation.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not read operations.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn get_operation(
    State(state): State<Arc<ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(id): Path<String>,
) -> Result<Json<Resource<OperationDto>>, ApiErrorResponse> {
    let principal = principal_or_error(principal, correlation_id)?;
    let operation = state
        .operations
        .get(state.authorizer.as_ref(), &principal.id, &id)
        .await
        .map_err(|error| map_use_case_error(&error, correlation_id))?;
    Ok(Json(Resource::new(OperationDto::from(operation))))
}

/// Requests cancellation of an operation.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    post,
    path = "/operations/{id}/cancel",
    tag = "operations",
    operation_id = "cancelOperation",
    params(
        ("id" = String, Path, description = "The operation's identity.")
    ),
    responses(
        (
            status = 200,
            description = "The cancellation request is durable.",
            body = Resource<OperationDto>
        ),
        (
            status = 404,
            description = "No such live operation.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not cancel operations.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn cancel_operation(
    State(state): State<Arc<ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(id): Path<String>,
) -> Result<Json<Resource<OperationDto>>, ApiErrorResponse> {
    let principal = principal_or_error(principal, correlation_id)?;
    let operation = state
        .operations
        .cancel(state.authorizer.as_ref(), &principal.id, &id)
        .await
        .map_err(|error| map_use_case_error(&error, correlation_id))?;
    Ok(Json(Resource::new(OperationDto::from(operation))))
}

/// Resolves the acting principal, refusing requests that arrived without one
/// with the proper envelope instead of an extractor's plain-text failure:
/// caller resolution is a deployment invariant, and its absence is a
/// configuration defect worth a machine-readable answer.
pub(crate) fn principal_or_error(
    principal: Option<Extension<crate::ActingPrincipal>>,
    correlation_id: CorrelationId,
) -> Result<crate::ActingPrincipal, ApiErrorResponse> {
    principal.map(|Extension(principal)| principal).map_or_else(
        || {
            let public = PublicError::new(
                ErrorCode::from_str("principal_unresolved").expect("the literal is valid error code syntax"),
                "no caller identity was resolved for this request; caller resolution is misconfigured",
                RetryClass::Never,
            );
            Err(ApiError::new(&public, correlation_id).with_status(StatusCode::INTERNAL_SERVER_ERROR))
        },
        Ok,
    )
}

/// Maps a use-case outcome onto the public error envelope. Status codes are
/// decided here, once; the codes are stable and the messages carry the
/// caller-safe detail the use case produced.
pub(crate) fn map_use_case_error(
    error: &OperationUseCaseError,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    let (status, code, retry, message): (StatusCode, &str, RetryClass, String) = match error {
        OperationUseCaseError::Denied(_) => (
            StatusCode::FORBIDDEN,
            "denied",
            RetryClass::Never,
            error.to_string(),
        ),
        OperationUseCaseError::NotFound { .. } => (
            StatusCode::NOT_FOUND,
            "not_found",
            RetryClass::Never,
            error.to_string(),
        ),
        OperationUseCaseError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
            error.to_string(),
        ),
        OperationUseCaseError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
            "the request could not be completed; the detail is in the controller log".to_owned(),
        ),
    };
    let public = PublicError::new(
        ErrorCode::from_str(code).expect("the literal is valid error code syntax"),
        message,
        retry,
    );
    ApiError::new(&public, correlation_id).with_status(status)
}
