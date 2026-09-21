//! The ready-project surface (FM-305): plan inspection (dry run) and
//! workflow execution. This adapter decides nothing; it translates HTTP
//! into operation creation and authorization calls.

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

/// How the workflow's endpoint authenticates.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum ReadyAuthDto {
    /// The controller's agent supplies the key.
    Agent,
    /// A specific identity file.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// A pinned tool request the workflow installs through mise.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReadyToolDto {
    /// The tool name.
    pub tool: String,
    /// The pinned version.
    pub version: String,
}

/// The body of the start-ready-workflow request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartReadyRequest {
    /// The machine to make ready (must match the path's machine).
    pub machine_id: String,
    /// The SSH endpoint id to act through.
    pub endpoint_id: String,
    /// How the endpoint authenticates.
    pub auth: ReadyAuthDto,
    /// The checkout root the workflow targets.
    pub root: String,
    /// The tools the project declares, as pinned requests.
    #[serde(default)]
    pub tools: Vec<ReadyToolDto>,
    /// The skill to deploy, when the project declares one.
    pub skill_id: Option<String>,
    /// The agents the skill deploys to.
    #[serde(default)]
    pub agents: Vec<String>,
    /// Compute and return the plan without executing it.
    #[serde(default)]
    pub dry_run: bool,
    /// The deadline, in seconds, for the whole workflow.
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    1800
}

/// The dry run's plan response: the step vocabulary and the conditions
/// under which each step runs.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReadyPlanDto {
    /// The project the plan targets.
    pub project_id: String,
    /// The machine the plan targets.
    pub machine_id: String,
    /// The checkout root the plan targets.
    pub root: String,
    /// The steps, in execution order.
    pub steps: Vec<ReadyPlanStepDto>,
    /// How the executed plan relates to this description.
    pub note: String,
}

/// One step in the dry run's plan response.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReadyPlanStepDto {
    /// The step's kind.
    pub kind: String,
    /// The condition under which the step runs (it is skipped otherwise).
    pub when: String,
}

/// Starts the ready-project workflow, or answers the plan on a dry run.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    post,
    path = "/projects/{projectId}/ready",
    tag = "projects",
    operation_id = "startReadyWorkflow",
    request_body = StartReadyRequest,
    params(
        ("projectId" = String, Path, description = "The project's identity.")
    ),
    responses(
        (
            status = 202,
            description = "The workflow was accepted.",
            body = Resource<crate::operations::OperationDto>
        ),
        (
            status = 200,
            description = "The dry run's plan description.",
            body = Resource<ReadyPlanDto>
        ),
        (
            status = 400,
            description = "The request is malformed.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not run the workflow.",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "The project or machine does not exist.",
            body = crate::error::ApiError
        ),
    )
)]
#[allow(clippy::too_many_lines)]
pub async fn start_ready_workflow(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: axum::http::HeaderMap,
    Path(project_id): Path<String>,
    Json(request): Json<StartReadyRequest>,
) -> Result<(StatusCode, Json<Resource<serde_json::Value>>), ApiErrorResponse> {
    let projects = crate::projects::projects_or_error(&state, correlation_id)?;
    let machines = crate::machines::machines_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // The project and the machine must exist and be readable: the
    // workflow names both.
    let project = projects
        .get(state.authorizer.as_ref(), &principal, &project_id)
        .await
        .map_err(|error| crate::projects::map_project_error(&error, correlation_id))?;
    let _machine = machines
        .get(
            state.authorizer.as_ref(),
            &principal,
            &request.machine_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| crate::machines::map_machine_error(&error, correlation_id))?;
    // The resource is the MACHINE, matching the kind's machine-scoped
    // creation check in Operations::create: one documented resource on
    // both paths, so a resource-scoped authorizer sees one answer.
    if let Err(decision) = fleet_application::authz::authorize(
        state.authorizer.as_ref(),
        fleet_application::authz::AccessRequest {
            principal_id: &principal.id,
            action: fleet_application::authz::Permission::ProjectsReady,
            resource: Some(&request.machine_id),
        },
    ) {
        return Err(crate::machines::denied_error(decision, correlation_id));
    }
    // Root validation mirrors the executor's rules: a malformed root is a
    // 400, never a queued failure.
    let root = &request.root;
    if !root.starts_with('/') || root.chars().count() > 400 {
        return Err(crate::machines::invalid_request(
            "the checkout root must be an absolute path of at most 400 characters",
            correlation_id,
        ));
    }
    if root.split('/').any(|segment| segment == "..") {
        return Err(crate::machines::invalid_request(
            "the checkout root must not contain a `..` segment",
            correlation_id,
        ));
    }
    if root.chars().any(char::is_control) {
        return Err(crate::machines::invalid_request(
            "the checkout root must not contain control characters",
            correlation_id,
        ));
    }
    if request.dry_run {
        // The dry run answers a dedicated plan-response schema without
        // creating anything: the executed plan is computed from observed
        // state at execution time, so this documents the step vocabulary
        // and the caller's inputs rather than pretending to know the
        // machine's state.
        let plan = ReadyPlanDto {
            project_id: project_id.clone(),
            machine_id: request.machine_id.clone(),
            root: root.clone(),
            steps: vec![
                ReadyPlanStepDto {
                    kind: "clone".to_owned(),
                    when: "no checkout matches the project's normalized remote".to_owned(),
                },
                ReadyPlanStepDto {
                    kind: "miseInstall".to_owned(),
                    when: "mise does not report the requested versions installed".to_owned(),
                },
                ReadyPlanStepDto {
                    kind: "frogenvSetup".to_owned(),
                    when: "Frogenv is not configured".to_owned(),
                },
                ReadyPlanStepDto {
                    kind: "skillsDeploy".to_owned(),
                    when: "the deployment status does not match".to_owned(),
                },
                ReadyPlanStepDto {
                    kind: "verify".to_owned(),
                    when: "always".to_owned(),
                },
            ],
            note: "the executed plan is computed from observed state at execution time; completed steps are skipped".to_owned(),
        };
        let value = serde_json::to_value(&plan).map_err(|error| {
            crate::machines::invalid_request(&error.to_string(), correlation_id)
        })?;
        return Ok((StatusCode::OK, Json(Resource::new(value))));
    }
    let payload = serde_json::json!({
        "machineId": request.machine_id,
        "endpointId": request.endpoint_id,
        "auth": serde_json::to_value(&request.auth)
            .map_err(|error| crate::machines::invalid_request(&error.to_string(), correlation_id))?,
        "remote": project.remote,
        "root": root,
        "tools": request.tools,
        "skillId": request.skill_id,
        "agents": request.agents,
        "timeoutSeconds": request.timeout_seconds,
    });
    // A caller-scoped idempotency key makes a retried POST return the
    // original operation instead of a second one.
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
                kind: "ready.workflow".to_owned(),
                idempotency_key,
                deadline_at: None,
                correlation_id: Some(correlation_id.to_string()),
                payload_json: Some(payload.to_string()),
                reviewed: false,
            },
        )
        .await
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
    let operation = crate::operations::OperationDto::from(operation);
    let value = serde_json::to_value(&operation)
        .map_err(|error| crate::machines::invalid_request(&error.to_string(), correlation_id))?;
    Ok((StatusCode::ACCEPTED, Json(Resource::new(value))))
}
