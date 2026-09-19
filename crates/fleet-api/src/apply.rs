//! The apply surface (FM-402): authorized plan execution with approvals.
//! This adapter decides nothing; it translates HTTP into operation
//! creation and authorization calls.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use fleet_core::CorrelationId;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::ApiErrorResponse;

/// How the apply workflow's endpoint authenticates.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum ApplyAuthDto {
    /// The controller's agent supplies the key.
    Agent,
    /// A specific identity file.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// One field difference, as the planner produced it.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FieldDifferenceDto {
    /// The field's stable identity.
    pub identity: String,
    /// The drift state.
    pub state: String,
    /// The desired value, when the field is desired.
    pub desired: Option<String>,
    /// The observed value, when one was observed.
    pub observed: Option<String>,
    /// Why the state is `unknown` or `unsupported`, when it is.
    pub reason: Option<String>,
}

/// One planned action the caller submits.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplyActionDto {
    /// The execution order.
    pub order: u32,
    /// The operation kind.
    pub kind: String,
    /// The difference the action resolves.
    pub difference: FieldDifferenceDto,
}

/// One approval the caller supplies.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplyApprovalDto {
    /// The plan's identity the approval is bound to.
    pub plan_id: String,
    /// The action's order the approval covers.
    pub action_order: u32,
    /// The action's operation kind the approval covers.
    pub kind: String,
}

/// The body of the start-apply-workflow request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartApplyRequest {
    /// The machine to apply on (must match the path's machine).
    pub machine_id: String,
    /// The SSH endpoint id to act through.
    pub endpoint_id: String,
    /// How the endpoint authenticates.
    pub auth: ApplyAuthDto,
    /// The plan's identity, which every approval is bound to.
    pub plan_id: String,
    /// The planned actions, in order.
    pub actions: Vec<ApplyActionDto>,
    /// The approvals supplied with the plan.
    #[serde(default)]
    pub approvals: Vec<ApplyApprovalDto>,
    /// The deadline, in seconds, for the whole workflow.
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    1800
}

/// Starts the apply workflow.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/apply",
    tag = "machines",
    operation_id = "startApplyWorkflow",
    request_body = StartApplyRequest,
    params(
        ("machineId" = String, Path, description = "The machine to apply on.")
    ),
    responses(
        (
            status = 202,
            description = "The apply workflow was accepted. Requires machine.read for the machine in addition to apply.execute.",
            body = Resource<crate::operations::OperationDto>
        ),
        (
            status = 400,
            description = "The request is malformed.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not execute apply plans.",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "The machine does not exist.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn start_apply_workflow(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: axum::http::HeaderMap,
    Path(machine_id): Path<String>,
    Json(request): Json<StartApplyRequest>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let machines = crate::machines::machines_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    if request.machine_id != machine_id {
        return Err(crate::machines::invalid_request(
            "the body's machineId does not match the path's machine",
            correlation_id,
        ));
    }
    let _machine = machines
        .get(
            state.authorizer.as_ref(),
            &principal,
            &machine_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| crate::machines::map_machine_error(&error, correlation_id))?;
    if let Err(decision) = fleet_application::authz::authorize(
        state.authorizer.as_ref(),
        fleet_application::authz::AccessRequest {
            principal_id: &principal.id,
            action: fleet_application::authz::Permission::ApplyExecute,
            resource: Some(&machine_id),
        },
    ) {
        return Err(crate::machines::denied_error(decision, correlation_id));
    }
    if request.actions.is_empty() {
        return Err(crate::machines::invalid_request(
            "the plan must carry at least one action",
            correlation_id,
        ));
    }
    // The plan identity is required: approvals are bound to it.
    if request.plan_id.is_empty() {
        return Err(crate::machines::invalid_request(
            "the plan identity is required; approvals are bound to it",
            correlation_id,
        ));
    }
    let payload = serde_json::json!({
        "machineId": machine_id,
        "endpointId": request.endpoint_id,
        "auth": serde_json::to_value(&request.auth)
            .map_err(|error| crate::machines::invalid_request(&error.to_string(), correlation_id))?,
        "planId": request.plan_id,
        "actions": request.actions,
        "approvals": request.approvals,
        "timeoutSeconds": request.timeout_seconds,
    });
    let idempotency_key = headers
        .get(crate::IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|key| format!("{}:{key}", principal.id));
    let operation = state
        .operations
        .create(
            state.authorizer.as_ref(),
            &principal.id,
            &fleet_application::operation::NewOperation {
                kind: "apply.workflow".to_owned(),
                idempotency_key,
                deadline_at: None,
                correlation_id: Some(correlation_id.to_string()),
                payload_json: Some(payload.to_string()),
            },
        )
        .await
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(Resource::new(crate::operations::OperationDto::from(
            operation,
        ))),
    ))
}
