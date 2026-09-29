//! The plan surface (FM-407, ADR 0013): the controller computes a
//! machine's plan from the active desired revision and its observations,
//! and applying executes that plan by its content-derived identity.
//! This adapter decides nothing; planning and staleness live in the
//! application layer.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use fleet_application::planning::{ComputedPlan, Planning, PlanningError};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::apply::{
    ApplyActionDto, ApplyApprovalDto, ApplyAuthDto, FieldDifferenceDto, StartApplyRequest,
};
use crate::envelope::Resource;
use crate::error::{ApiError, ApiErrorResponse};
use crate::operations::ApiState;

/// The desired revision a plan was computed against.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PlanRevisionDto {
    /// The commit SHA.
    pub commit_sha: String,
    /// The content digest.
    pub content_digest: String,
}

/// One planned action.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PlanActionDto {
    /// The execution order, starting at 1.
    pub order: u32,
    /// The operation kind that resolves the difference.
    pub kind: String,
    /// Why the action sits at this position.
    pub reason: String,
    /// Whether applying this action needs an explicit approval.
    pub requires_approval: bool,
    /// The difference the action resolves.
    pub difference: FieldDifferenceDto,
}

/// A controller-computed plan.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PlanDto {
    /// The content digest identifying this plan; approvals and apply bind to it.
    pub plan_id: String,
    /// The machine the plan is for.
    pub machine_id: String,
    /// The desired revision the plan was computed against.
    pub revision: PlanRevisionDto,
    /// The ordered actions.
    pub actions: Vec<PlanActionDto>,
    /// The differences the planner refused to act on (`unknown`,
    /// `unsupported`), reported and never acted on.
    pub unactionable: Vec<FieldDifferenceDto>,
}

fn difference_dto(difference: &fleet_core::FieldDifference) -> FieldDifferenceDto {
    FieldDifferenceDto {
        identity: difference.identity.clone(),
        state: serde_json::to_value(difference.state)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default(),
        desired: difference.desired.clone(),
        observed: difference.observed.clone(),
        reason: difference.reason.clone(),
    }
}

impl From<&ComputedPlan> for PlanDto {
    fn from(computed: &ComputedPlan) -> Self {
        Self {
            plan_id: computed.plan_id.clone(),
            machine_id: computed.machine_id.clone(),
            revision: PlanRevisionDto {
                commit_sha: computed.revision.commit_sha.clone(),
                content_digest: computed.revision.content_digest.clone(),
            },
            actions: computed
                .plan
                .actions
                .iter()
                .map(|action| PlanActionDto {
                    order: action.order,
                    kind: action.kind.clone(),
                    reason: action.reason.clone(),
                    requires_approval: fleet_application::apply::requires_approval(&action.kind),
                    difference: difference_dto(&action.difference),
                })
                .collect(),
            unactionable: computed
                .plan
                .unactionable
                .iter()
                .map(difference_dto)
                .collect(),
        }
    }
}

/// One approval of a computed plan's action. The plan id comes from the path.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PlanApprovalDto {
    /// The action's order the approval covers.
    pub action_order: u32,
    /// The action's operation kind the approval covers.
    pub kind: String,
}

/// Applies a computed plan.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplyPlanRequest {
    /// The SSH endpoint id to act through.
    pub endpoint_id: String,
    /// How the endpoint authenticates.
    pub auth: ApplyAuthDto,
    /// The approvals for the plan's risky actions.
    #[serde(default)]
    pub approvals: Vec<PlanApprovalDto>,
    /// The deadline, in seconds, for the whole workflow.
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    1800
}

fn planning_or_error(
    state: &ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<Planning>, ApiErrorResponse> {
    state.planning.clone().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("planning_unavailable").expect("valid error code"),
            "the planning surface is not wired; the controller needs its database",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

fn map_planning_error(error: &PlanningError, correlation_id: CorrelationId) -> ApiErrorResponse {
    let (status, code, retry) = match error {
        PlanningError::Denied(_) => (StatusCode::FORBIDDEN, "denied", RetryClass::Never),
        PlanningError::UnknownMachine => (StatusCode::NOT_FOUND, "not_found", RetryClass::Never),
        PlanningError::NoActiveRevision => (
            StatusCode::CONFLICT,
            "no_active_revision",
            RetryClass::Never,
        ),
        PlanningError::ResourcesUnavailable => (
            StatusCode::CONFLICT,
            "resources_unavailable",
            RetryClass::Never,
        ),
        PlanningError::Stale { .. } => (StatusCode::CONFLICT, "stale_plan", RetryClass::Never),
        PlanningError::Composition(_) => (
            StatusCode::CONFLICT,
            "composition_failed",
            RetryClass::Never,
        ),
        PlanningError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    let message = match error {
        PlanningError::Backend { .. } => {
            "the request could not be completed; the detail is in the controller log".to_owned()
        }
        other => other.to_string(),
    };
    let public = PublicError::new(
        ErrorCode::from_str(code).expect("valid error code"),
        message,
        retry,
    );
    ApiError::new(&public, correlation_id).with_status(status)
}

/// Computes a plan for the machine from the active desired revision.
///
/// # Errors
///
/// Returns an API error when no revision is active, the machine is unknown,
/// or authentication, authorization, or storage fails.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/plans",
    tag = "machines",
    operation_id = "createMachinePlan",
    params(("machineId" = String, Path, description = "The machine to plan for.")),
    responses(
        (status = 200, description = "The computed plan.", body = Resource<PlanDto>),
        (status = 403, description = "The caller may not plan for the machine.", body = ApiError),
        (status = 404, description = "The machine does not exist.", body = ApiError),
        (status = 409, description = "No desired revision is active, its resources are unavailable, or it could not be composed.", body = ApiError),
        (status = 503, description = "The planning surface is not wired.", body = ApiError),
    )
)]
pub async fn create_machine_plan(
    State(state): State<Arc<ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
) -> Result<Json<Resource<PlanDto>>, ApiErrorResponse> {
    let planning = planning_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let computed = planning
        .create_plan(
            state.authorizer.as_ref(),
            &principal.id,
            &machine_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_planning_error(&error, correlation_id))?;
    Ok(Json(Resource::new(PlanDto::from(&computed))))
}

/// Applies a plan by its identity: the controller recomputes the plan and
/// runs it only if it is still exactly the plan that was reviewed.
///
/// # Errors
///
/// Returns an API error when the plan is stale, or on refusal or backend failure.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/plans/{planId}/apply",
    tag = "machines",
    operation_id = "applyMachinePlan",
    request_body = ApplyPlanRequest,
    params(
        ("machineId" = String, Path, description = "The machine to apply on."),
        ("planId" = String, Path, description = "The plan identity returned by the plan request."),
    ),
    responses(
        (status = 202, description = "The apply workflow was accepted.", body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The request is malformed or the plan has nothing to apply.", body = ApiError),
        (status = 403, description = "The caller may not execute apply plans.", body = ApiError),
        (status = 404, description = "The machine does not exist.", body = ApiError),
        (status = 409, description = "The plan is stale (plan again), or no desired revision is active.", body = ApiError),
        (status = 503, description = "The planning surface is not wired.", body = ApiError),
    )
)]
pub async fn apply_machine_plan(
    State(state): State<Arc<ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: HeaderMap,
    Path((machine_id, plan_id)): Path<(String, String)>,
    Json(request): Json<ApplyPlanRequest>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let planning = planning_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let computed = planning
        .resolve_for_apply(
            state.authorizer.as_ref(),
            &principal.id,
            &machine_id,
            &plan_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_planning_error(&error, correlation_id))?;
    // The executed actions are the controller's own, never the caller's.
    let dto = PlanDto::from(&computed);
    let apply = StartApplyRequest {
        machine_id: machine_id.clone(),
        endpoint_id: request.endpoint_id,
        auth: request.auth,
        plan_id: computed.plan_id.clone(),
        actions: dto
            .actions
            .into_iter()
            .map(|action| ApplyActionDto {
                order: action.order,
                kind: action.kind,
                difference: action.difference,
            })
            .collect(),
        approvals: request
            .approvals
            .into_iter()
            .map(|approval| ApplyApprovalDto {
                plan_id: computed.plan_id.clone(),
                action_order: approval.action_order,
                kind: approval.kind,
            })
            .collect(),
        timeout_seconds: request.timeout_seconds,
    };
    crate::apply::start_apply(
        &state,
        &principal,
        correlation_id,
        &headers,
        &machine_id,
        apply,
    )
    .await
}

/// How many differences of each drift state a machine has.
#[derive(Clone, Debug, Default, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DriftCountsDto {
    /// Desired but not observed.
    pub missing: u32,
    /// Observed with a different value.
    pub changed: u32,
    /// Observed but no longer desired.
    pub extra: u32,
    /// The observation did not answer, so the state is unknown.
    pub unknown: u32,
    /// Fleet cannot manage this on the machine.
    pub unsupported: u32,
}

/// One machine's drift against the active desired revision.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineDriftDto {
    /// The machine.
    pub machine_id: String,
    /// The machine's current name.
    pub machine_name: String,
    /// `computed`, `no_revision` (nothing is active, so nothing can drift),
    /// or `unavailable` (drift could not be computed for this machine).
    pub status: String,
    /// The revision the machine was compared with, when computed.
    pub revision: Option<PlanRevisionDto>,
    /// The number of differences per state. A machine with `computed`
    /// status and all zeros is in sync.
    pub counts: DriftCountsDto,
    /// The differences. Fields that are in sync are not listed.
    pub differences: Vec<FieldDifferenceDto>,
    /// Why drift is unavailable, when it is.
    pub detail: Option<String>,
}

impl From<fleet_application::planning::DriftEntry> for MachineDriftDto {
    fn from(entry: fleet_application::planning::DriftEntry) -> Self {
        use fleet_application::planning::DriftOutcome;
        let mut dto = Self {
            machine_id: entry.machine_id,
            machine_name: entry.machine_name,
            status: String::new(),
            revision: None,
            counts: DriftCountsDto::default(),
            differences: Vec::new(),
            detail: None,
        };
        match entry.outcome {
            DriftOutcome::Computed {
                revision,
                differences,
            } => {
                "computed".clone_into(&mut dto.status);
                dto.revision = Some(PlanRevisionDto {
                    commit_sha: revision.commit_sha,
                    content_digest: revision.content_digest,
                });
                for difference in &differences {
                    let counter = match difference.state {
                        fleet_core::DifferenceState::Missing => &mut dto.counts.missing,
                        fleet_core::DifferenceState::Changed => &mut dto.counts.changed,
                        fleet_core::DifferenceState::Extra => &mut dto.counts.extra,
                        fleet_core::DifferenceState::Unknown => &mut dto.counts.unknown,
                        fleet_core::DifferenceState::Unsupported => &mut dto.counts.unsupported,
                    };
                    *counter += 1;
                }
                dto.differences = differences.iter().map(difference_dto).collect();
            }
            DriftOutcome::NoRevision => "no_revision".clone_into(&mut dto.status),
            DriftOutcome::Unavailable { detail } => {
                "unavailable".clone_into(&mut dto.status);
                dto.detail = Some(detail);
            }
        }
        dto
    }
}

/// Cursor and bound for the drift list.
#[derive(Clone, Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct DriftParams {
    /// Opaque machine id returned as the previous page's cursor.
    pub cursor: Option<String>,
    /// Requested page size, clamped to the API maximum.
    pub limit: Option<u32>,
}

/// Lists each readable machine's drift against the active desired revision.
///
/// # Errors
///
/// Returns an API error when authentication or the machine list fails.
#[utoipa::path(
    get,
    path = "/desired/drift",
    tag = "desired",
    operation_id = "listDesiredDrift",
    params(DriftParams),
    responses(
        (status = 200, description = "Drift per machine the caller may read; machines it may not read are omitted.", body = crate::envelope::Page<MachineDriftDto>),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The planning surface is not wired.", body = ApiError),
    )
)]
pub async fn list_desired_drift(
    State(state): State<Arc<ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    axum::extract::Query(params): axum::extract::Query<DriftParams>,
) -> Result<Json<crate::envelope::Page<MachineDriftDto>>, ApiErrorResponse> {
    let planning = planning_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let limit = params
        .limit
        .filter(|n| *n > 0)
        .unwrap_or(crate::envelope::DEFAULT_PAGE_LIMIT)
        .min(crate::envelope::MAX_PAGE_LIMIT);
    let page = planning
        .drift_page(
            state.authorizer.as_ref(),
            &principal.id,
            params.cursor.as_deref(),
            limit,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_planning_error(&error, correlation_id))?;
    Ok(Json(crate::envelope::Page {
        items: page.entries.into_iter().map(Into::into).collect(),
        page: crate::envelope::PageInfo {
            next_cursor: page.next_cursor,
            limit,
        },
    }))
}

/// Reads one machine's drift against the active desired revision.
///
/// # Errors
///
/// Returns an API error when the machine is unknown or authentication or
/// authorization fails.
#[utoipa::path(
    get,
    path = "/machines/{machineId}/drift",
    tag = "machines",
    operation_id = "getMachineDrift",
    params(("machineId" = String, Path, description = "The machine.")),
    responses(
        (status = 200, body = Resource<MachineDriftDto>),
        (status = 403, description = "The caller may not read the machine's skills.", body = ApiError),
        (status = 404, description = "The machine does not exist.", body = ApiError),
        (status = 503, description = "The planning surface is not wired.", body = ApiError),
    )
)]
pub async fn get_machine_drift(
    State(state): State<Arc<ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
) -> Result<Json<Resource<MachineDriftDto>>, ApiErrorResponse> {
    let planning = planning_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let entry = planning
        .machine_drift(
            state.authorizer.as_ref(),
            &principal.id,
            &machine_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_planning_error(&error, correlation_id))?;
    Ok(Json(Resource::new(entry.into())))
}
