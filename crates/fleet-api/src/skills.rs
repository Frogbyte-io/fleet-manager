//! The Skills Manager surface (FM-302): durable, audited operations
//! through the documented CLI contract. This adapter decides nothing; it
//! translates HTTP into operation creation and authorization calls.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use std::str::FromStr as _;
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::{ApiError, ApiErrorResponse};

/// Extracts the machine use cases from the API state, or answers with the
/// standard envelope when the controller was composed without a database.
fn machines_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<fleet_application::machine::Machines>, ApiErrorResponse> {
    state.machines.clone().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "the machine surface is not wired; the controller needs its database",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// How a skills operation's endpoint authenticates.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum SkillsAuthDto {
    /// The controller's agent supplies the key.
    Agent,
    /// A specific identity file.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// The body of the start-skills-operation request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartSkillsOperationRequest {
    /// The machine to act on (must match the path's machine).
    pub machine_id: String,
    /// The SSH endpoint id to act through.
    pub endpoint_id: String,
    /// How the endpoint authenticates.
    pub auth: SkillsAuthDto,
    /// The skill to deploy or undeploy; absent for a probe.
    pub skill_id: Option<String>,
    /// The agents to deploy to or undeploy from, as documented ids.
    #[serde(default)]
    pub agents: Vec<String>,
    /// An external skills root, when the operation targets one.
    pub skills_root: Option<String>,
    /// Preserve a dry run: never upgraded to a real mutation.
    #[serde(default)]
    pub dry_run: bool,
    /// An optional pinned release for the probe's install: the URL.
    pub artifact_url: Option<String>,
    /// The pinned release's expected sha256.
    pub artifact_sha256: Option<String>,
    /// The operation's direction: `deploy` (the default when a skill is
    /// named) or `undeploy`.
    pub direction: Option<String>,
    /// The deadline, in seconds. Bounded by the executor.
    pub timeout_seconds: u64,
}

/// Starts a skills operation: `probe` reads the CLI's state (and may
/// install a pinned release); `deploy` and `undeploy` change agent state.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/skills/operations",
    tag = "machines",
    operation_id = "startSkillsOperation",
    request_body = StartSkillsOperationRequest,
    params(
        ("machineId" = String, Path, description = "The machine to act on.")
    ),
    responses(
        (
            status = 202,
            description = "The skills operation was accepted.",
            body = Resource<crate::operations::OperationDto>
        ),
        (
            status = 400,
            description = "The request is malformed.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not perform the skills action.",
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
pub async fn start_skills_operation(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
    Json(request): Json<StartSkillsOperationRequest>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let machines = machines_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // The body's machine must agree with the path's: two names for one
    // machine is a malformed request, not a fallback.
    if request.machine_id != machine_id {
        return Err(crate::machines::invalid_request(
            "the body's machineId does not match the path's machine",
            correlation_id,
        ));
    }
    // The machine must exist before the authorization names it.
    let _machine = machines
        .get(
            state.authorizer.as_ref(),
            &principal,
            &machine_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| crate::machines::map_machine_error(&error, correlation_id))?;
    // Probe is a risky read; deploy and undeploy are mutations. Both name
    // the machine as their resource.
    let permission = match request.skill_id {
        None => fleet_application::authz::Permission::SkillsRead,
        Some(_) => fleet_application::authz::Permission::SkillsDeploy,
    };
    if let Err(decision) = fleet_application::authz::authorize(
        state.authorizer.as_ref(),
        fleet_application::authz::AccessRequest {
            principal_id: &principal.id,
            action: permission,
            resource: Some(&machine_id),
        },
    ) {
        return Err(crate::machines::denied_error(decision, correlation_id));
    }
    let kind = match request.skill_id {
        None => "skills.probe",
        Some(_) if request_undeploy(&request) => "skills.undeploy",
        Some(_) => "skills.deploy",
    };
    let mut payload = serde_json::json!({
        "machineId": machine_id,
        "endpointId": request.endpoint_id,
        "auth": serde_json::to_value(&request.auth)
            .map_err(|error| crate::machines::invalid_request(&error.to_string(), correlation_id))?,
        "timeoutSeconds": request.timeout_seconds,
    });
    if let Some(skill_id) = &request.skill_id {
        payload["skillId"] = serde_json::json!(skill_id);
        payload["agents"] = serde_json::json!(request.agents);
        payload["dryRun"] = serde_json::json!(request.dry_run);
    }
    if let Some(root) = &request.skills_root {
        payload["skillsRoot"] = serde_json::json!(root);
    }
    if let Some(url) = &request.artifact_url {
        payload["artifactUrl"] = serde_json::json!(url);
    }
    if let Some(sha256) = &request.artifact_sha256 {
        payload["artifactSha256"] = serde_json::json!(sha256);
    }
    let operation = state
        .operations
        .create(
            state.authorizer.as_ref(),
            &principal.id,
            &fleet_application::operation::NewOperation {
                kind: kind.to_owned(),
                idempotency_key: None,
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

/// Whether the request carries the undeploy marker. The body names the
/// direction explicitly so the adapter never guesses from context.
fn request_undeploy(request: &StartSkillsOperationRequest) -> bool {
    request
        .direction
        .as_deref()
        .is_some_and(|direction| direction == "undeploy")
}
