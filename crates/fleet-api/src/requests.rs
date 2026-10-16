//! The action broker surface (FM-1040): agents `POST /requests` to ask Fleet
//! to run a provider action; a person approves or denies it.
//!
//! The handlers are adapters. Authorization (separate `action.request`,
//! `action.approve`, `action.deny`, and `action.read` permissions), policy,
//! the credential refusal, the state machine, and audit are the
//! application's `Broker`.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use fleet_application::broker::{ActionRequest, Broker, BrokerError, NewActionRequest};
use fleet_core::{ActionRequestState, CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};

/// The origin recorded for a request that arrived over this HTTP API.
const API_ORIGIN: &str = "api";

fn broker_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<Broker>, ApiErrorResponse> {
    state.requests.clone().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "the action broker is not wired; the controller needs its database",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

fn map_broker_error(error: &BrokerError, correlation_id: CorrelationId) -> ApiErrorResponse {
    let (status, code, retry) = match error {
        BrokerError::Denied(_) | BrokerError::PolicyDenied { .. } => {
            (StatusCode::FORBIDDEN, "denied", RetryClass::Never)
        }
        BrokerError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
        ),
        BrokerError::NotFound { .. } => (StatusCode::NOT_FOUND, "not_found", RetryClass::Never),
        BrokerError::Conflict { .. } => (StatusCode::CONFLICT, "conflict", RetryClass::Never),
        BrokerError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    let message = match error {
        BrokerError::Backend { .. } => {
            "the request could not be completed; the detail is in the controller log".to_owned()
        }
        other => other.to_string(),
    };
    let public = PublicError::new(
        ErrorCode::from_str(code).expect("the literal is valid error code syntax"),
        message,
        retry,
    );
    ApiError::new(&public, correlation_id).with_status(status)
}

fn invalid(message: &str, correlation_id: CorrelationId) -> ApiErrorResponse {
    map_broker_error(
        &BrokerError::Invalid {
            detail: message.to_owned(),
        },
        correlation_id,
    )
}

/// An action request.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ActionRequestDto {
    /// The request's identity.
    pub id: String,
    /// The principal that asked.
    pub requester: String,
    /// Where the request came from (`api`).
    pub origin: String,
    /// The provider action's id.
    pub action_id: String,
    /// What the action acts on.
    pub target: String,
    /// The structured, secret-free parameters.
    #[schema(value_type = Object)]
    pub parameters: serde_json::Value,
    /// The effective risk class when the request was made: `auto` (ran
    /// without a decision), `approve` (waits for a person), or `deny`
    /// (refused by policy).
    pub risk_class: String,
    /// Why the requester wants it.
    pub reason: String,
    /// `pending`, `approved`, `denied`, `expired`, `executing`,
    /// `succeeded`, or `failed`.
    pub state: String,
    /// Whether the state will never change.
    pub terminal: bool,
    /// Who approved or denied it: a principal, `policy:auto`, or
    /// `policy:deny`.
    pub decided_by: Option<String>,
    /// When it was decided (epoch milliseconds).
    pub decided_at: Option<i64>,
    /// A denier's note.
    pub decision_note: Option<String>,
    /// The durable operation that executes it, once created. Poll it at
    /// `/operations/{id}`.
    pub operation_id: Option<String>,
    /// Why it failed.
    pub failure: Option<String>,
    /// When it was made (epoch milliseconds).
    pub created_at: i64,
    /// When an undecided request expires (epoch milliseconds).
    pub expires_at: i64,
    /// The last change (epoch milliseconds).
    pub updated_at: i64,
}

impl From<ActionRequest> for ActionRequestDto {
    fn from(request: ActionRequest) -> Self {
        Self {
            id: request.id,
            requester: request.requester,
            origin: request.origin,
            action_id: request.action_id,
            target: request.target,
            parameters: request.parameters,
            risk_class: request.risk_class.id().to_owned(),
            reason: request.reason,
            state: request.state.id().to_owned(),
            terminal: request.state.is_terminal(),
            decided_by: request.decided_by,
            decided_at: request.decided_at,
            decision_note: request.decision_note,
            operation_id: request.operation_id,
            failure: request.failure,
            created_at: request.created_at,
            expires_at: request.expires_at,
            updated_at: request.updated_at,
        }
    }
}

/// What to ask for.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateActionRequest {
    /// The provider action's id, for example `coolify.application.redeploy`.
    pub action_id: String,
    /// What the action acts on, in the provider's terms (at most 256
    /// characters).
    pub target: String,
    /// Structured parameters the action defines (an object of at most 8
    /// KiB). They must be secret-free: Fleet holds provider credentials and
    /// refuses a request whose parameters look like one.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub parameters: serde_json::Value,
    /// Why, for the approver (at most 1000 characters).
    pub reason: String,
}

/// An optional note with a denial.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DenyActionRequest {
    /// Why it was denied (at most 1000 characters).
    #[serde(default)]
    pub note: Option<String>,
}

/// Query parameters of the list.
#[derive(Debug, Deserialize)]
pub struct ListActionRequestsParams {
    state: Option<String>,
    limit: Option<u32>,
}

/// Asks Fleet to run a provider action. The action's risk class decides
/// what happens next: `auto` starts the operation at once (the response is
/// `executing` with its `operationId`), `approve` records the request as
/// `pending` until a person approves or denies it before `expiresAt`, and
/// `deny` records it as `denied`. The response always states which.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown action, or
/// invalid or credential-like input.
#[utoipa::path(
    post,
    path = "/requests",
    tag = "requests",
    operation_id = "createActionRequest",
    request_body = CreateActionRequest,
    responses(
        (status = 201, description = "The request was recorded; its state shows what policy did.", body = Resource<ActionRequestDto>),
        (status = 400, description = "The action is unknown, a field is invalid, or the parameters look like a credential.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not request actions.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn create_action_request(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    request: Result<Json<CreateActionRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<ActionRequestDto>>), ApiErrorResponse> {
    let broker = broker_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        invalid(
            "the request body must be valid JSON with actionId, target, and reason",
            correlation_id,
        )
    })?;
    let created = broker
        .create(
            state.authorizer.as_ref(),
            &principal.id,
            NewActionRequest {
                action_id: request.action_id,
                target: request.target,
                parameters: request.parameters,
                reason: request.reason,
                origin: API_ORIGIN.to_owned(),
                correlation_id: Some(correlation_id.to_string()),
            },
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_broker_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(created.into()))))
}

/// Lists action requests, newest first, optionally only those in one state
/// (for the approver's inbox: `state=pending`). Expiry and the outcome of an
/// executing request's operation are applied as they are read.
///
/// # Errors
///
/// Returns the public error envelope on refusal or a malformed filter.
#[utoipa::path(
    get,
    path = "/requests",
    tag = "requests",
    operation_id = "listActionRequests",
    params(
        ("state" = Option<String>, Query, description = "Only requests in this state: pending, approved, denied, expired, executing, succeeded, or failed."),
        ("limit" = Option<u32>, Query, description = "The maximum number of requests to return (default 50, at most 200).")
    ),
    responses(
        (status = 200, description = "The newest requests.", body = Page<ActionRequestDto>),
        (status = 400, description = "The state filter is unknown.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not read action requests.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn list_action_requests(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<ListActionRequestsParams>,
) -> Result<Json<Page<ActionRequestDto>>, ApiErrorResponse> {
    let broker = broker_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let filter = params
        .state
        .as_deref()
        .map(ActionRequestState::from_id)
        .transpose()
        .map_err(|detail| invalid(&detail, correlation_id))?;
    let limit = params
        .limit
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .clamp(1, MAX_PAGE_LIMIT);
    let items: Vec<ActionRequestDto> = broker
        .list(
            state.authorizer.as_ref(),
            &principal.id,
            filter,
            limit,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_broker_error(&error, correlation_id))?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(Json(Page {
        items,
        page: PageInfo {
            next_cursor: None,
            limit,
        },
    }))
}

/// Reads one action request.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown id.
#[utoipa::path(
    get,
    path = "/requests/{requestId}",
    tag = "requests",
    operation_id = "getActionRequest",
    params(("requestId" = String, Path, description = "The request's identity.")),
    responses(
        (status = 200, description = "The request.", body = Resource<ActionRequestDto>),
        (status = 403, description = "The caller may not read action requests.", body = crate::error::ApiError),
        (status = 404, description = "The request does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn get_action_request(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(request_id): Path<String>,
) -> Result<Json<Resource<ActionRequestDto>>, ApiErrorResponse> {
    let broker = broker_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let found = broker
        .get(
            state.authorizer.as_ref(),
            &principal.id,
            &request_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_broker_error(&error, correlation_id))?;
    Ok(Json(Resource::new(found.into())))
}

/// Approves a pending request and starts its operation. The approver is
/// recorded, and their authorization is checked again when the operation is
/// created. Of concurrent approvals exactly one succeeds; the rest get 409.
/// An approval whose operation cannot be created answers 200 with the
/// request `failed` and the reason.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown id, or a request
/// that is no longer pending.
#[utoipa::path(
    post,
    path = "/requests/{requestId}/approve",
    tag = "requests",
    operation_id = "approveActionRequest",
    params(("requestId" = String, Path, description = "The request's identity.")),
    responses(
        (status = 200, description = "The request was approved; it is `executing` with its `operationId`, or `failed` with the reason.", body = Resource<ActionRequestDto>),
        (status = 403, description = "The caller may not approve, or policy now denies the action.", body = crate::error::ApiError),
        (status = 404, description = "The request does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The request is not pending: it was decided, expired, or another decision won.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn approve_action_request(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(request_id): Path<String>,
) -> Result<Json<Resource<ActionRequestDto>>, ApiErrorResponse> {
    let broker = broker_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let approved = broker
        .approve(
            state.authorizer.as_ref(),
            &principal.id,
            &request_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_broker_error(&error, correlation_id))?;
    Ok(Json(Resource::new(approved.into())))
}

/// Denies a pending request, with an optional note.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown id, or a request
/// that is no longer pending.
#[utoipa::path(
    post,
    path = "/requests/{requestId}/deny",
    tag = "requests",
    operation_id = "denyActionRequest",
    params(("requestId" = String, Path, description = "The request's identity.")),
    request_body(content = Option<DenyActionRequest>, description = "An optional note."),
    responses(
        (status = 200, description = "The request was denied.", body = Resource<ActionRequestDto>),
        (status = 400, description = "The note is invalid.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not deny requests.", body = crate::error::ApiError),
        (status = 404, description = "The request does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The request is not pending: it was decided, expired, or another decision won.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn deny_action_request(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(request_id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<Resource<ActionRequestDto>>, ApiErrorResponse> {
    let broker = broker_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // An empty body is a denial without a note, whatever its content type.
    let note = if body.iter().all(u8::is_ascii_whitespace) {
        None
    } else {
        serde_json::from_slice::<DenyActionRequest>(&body)
            .map_err(|_| {
                invalid(
                    "the body must be empty or a JSON object with a note",
                    correlation_id,
                )
            })?
            .note
    };
    let denied = broker
        .deny(
            state.authorizer.as_ref(),
            &principal.id,
            &request_id,
            note.as_deref(),
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_broker_error(&error, correlation_id))?;
    Ok(Json(Resource::new(denied.into())))
}
