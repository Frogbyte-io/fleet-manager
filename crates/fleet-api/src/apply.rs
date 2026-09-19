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

/// The action kinds the apply workflow can execute.
const SUPPORTED_KINDS: [&str; 4] = [
    "mise.install",
    "skills.deploy",
    "skills.undeploy",
    "projects.clone",
];

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
#[allow(clippy::too_many_lines)]
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
    // Each action's kind must be one the apply executor can run, and its
    // state must be one of the five documented drift states; orders must
    // be unique and strictly increasing. Malformed input is a 400, never
    // a queued failure.
    let mut previous_order: Option<u32> = None;
    for action in &request.actions {
        if !SUPPORTED_KINDS.contains(&action.kind.as_str()) {
            return Err(crate::machines::invalid_request(
                &format!(
                    "the action kind {:?} is not one the apply workflow can execute",
                    action.kind
                ),
                correlation_id,
            ));
        }
        let state = fleet_core::DifferenceState::deserialize(serde_json::Value::String(
            action.difference.state.clone(),
        ))
        .map_err(|_| {
            crate::machines::invalid_request(
                &format!(
                    "the difference state {:?} is not one of the documented drift states",
                    action.difference.state
                ),
                correlation_id,
            )
        })?;
        // The state must be actionable AND pair with the kind the way the
        // planner maps them: an unknown/unsupported state has no bounded
        // action, and a kind/state mismatch (skills.deploy with extra)
        // would perform a side effect the plan never declared.
        if !state.actionable() {
            return Err(crate::machines::invalid_request(
                "an apply action must carry an actionable difference state",
                correlation_id,
            ));
        }
        let state_matches_kind = matches!(
            (action.kind.as_str(), state),
            (
                "mise.install" | "skills.deploy" | "projects.clone",
                fleet_core::DifferenceState::Missing
            ) | (
                "mise.install" | "projects.clone",
                fleet_core::DifferenceState::Changed
            ) | ("skills.undeploy", fleet_core::DifferenceState::Extra)
        );
        if !state_matches_kind {
            return Err(crate::machines::invalid_request(
                &format!(
                    "the action kind {:?} does not resolve a {:?} difference",
                    action.kind, state
                ),
                correlation_id,
            ));
        }
        if previous_order.is_some_and(|previous| action.order <= previous) {
            return Err(crate::machines::invalid_request(
                "the action orders must be unique and strictly increasing",
                correlation_id,
            ));
        }
        previous_order = Some(action.order);
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
