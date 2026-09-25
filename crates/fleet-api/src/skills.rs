//! The Skills Manager surface (FM-302): durable, audited operations
//! through the documented CLI contract. This adapter decides nothing; it
//! translates HTTP into operation creation and authorization calls.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass, SystemClock};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Page, PageInfo, Resource};
use crate::error::ApiErrorResponse;

/// The direction a skills operation takes.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SkillsDirectionDto {
    /// Deploy the skill to the named agents.
    Deploy,
    /// Undeploy the skill from the named agents.
    Undeploy,
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
    /// named) or `undeploy`. A closed enum: anything else is malformed.
    pub direction: Option<SkillsDirectionDto>,
    /// The deadline, in seconds. Bounded by the executor.
    pub timeout_seconds: u64,
}

/// One machine's observed skill inventory.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SkillsSnapshotDto {
    /// Machine identity.
    pub machine_id: String,
    /// `available`, `absent`, or `unsupported`.
    pub availability: String,
    /// Exact supported CLI version, when present.
    pub cli_version: Option<String>,
    /// Safe normalized skill, preset, and agent data.
    pub data: serde_json::Value,
    /// `complete`, `failed`, `unavailable`, or `unsupported`.
    pub update_check: String,
    /// When the inventory was collected (epoch milliseconds).
    pub observed_at: i64,
    /// True when older than the 24 hour freshness window.
    pub stale: bool,
}

impl From<fleet_application::skills::SkillsView> for SkillsSnapshotDto {
    fn from(view: fleet_application::skills::SkillsView) -> Self {
        use fleet_application::skills::SkillsAvailability as A;
        let snapshot = view.snapshot;
        Self {
            machine_id: snapshot.machine_id,
            availability: match snapshot.availability {
                A::Available => "available",
                A::Absent => "absent",
                A::Unsupported => "unsupported",
            }
            .into(),
            cli_version: snapshot.cli_version,
            data: snapshot.data,
            update_check: snapshot.update_check,
            observed_at: snapshot.observed_at,
            stale: view.stale,
        }
    }
}

fn skills_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<fleet_application::skills::Skills>, ApiErrorResponse> {
    state.skills.clone().ok_or_else(|| {
        let error = PublicError::new(
            ErrorCode::from_str("skills_unavailable").expect("valid code"),
            "the skills read model is not wired",
            RetryClass::Backoff,
        );
        crate::error::ApiError::new(&error, correlation_id)
            .with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

fn map_skills_error(
    error: &fleet_application::skills::SkillsError,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    let (status, code, message, retry) = match error {
        fleet_application::skills::SkillsError::Denied(_) => (
            StatusCode::FORBIDDEN,
            "denied",
            "the caller may not read skills on this machine",
            RetryClass::Never,
        ),
        fleet_application::skills::SkillsError::Backend => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "the skills snapshot could not be read",
            RetryClass::Backoff,
        ),
    };
    let public = PublicError::new(
        ErrorCode::from_str(code).expect("valid code"),
        message,
        retry,
    );
    crate::error::ApiError::new(&public, correlation_id).with_status(status)
}

/// Reads one machine's latest Skills Manager observation.
///
/// # Errors
///
/// Returns the standard envelope for denial, a missing snapshot, or an unavailable backend.
#[utoipa::path(get, path = "/machines/{machineId}/skills", tag = "machines", operation_id = "getMachineSkills", params(("machineId" = String, Path)), responses((status = 200, body = Resource<SkillsSnapshotDto>), (status = 403, body = crate::error::ApiError), (status = 404, body = crate::error::ApiError), (status = 500, body = crate::error::ApiError), (status = 503, body = crate::error::ApiError)))]
#[allow(clippy::missing_panics_doc)]
pub async fn get_machine_skills(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
) -> Result<Json<Resource<SkillsSnapshotDto>>, ApiErrorResponse> {
    use std::str::FromStr as _;
    let skills = skills_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let view = skills
        .get(
            state.authorizer.as_ref(),
            &principal,
            &machine_id,
            SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|e| map_skills_error(&e, correlation_id))?;
    let Some(view) = view else {
        let error = PublicError::new(
            ErrorCode::from_str("not_found").expect("valid code"),
            "no skills observation exists for this machine",
            RetryClass::Never,
        );
        return Err(
            crate::error::ApiError::new(&error, correlation_id).with_status(StatusCode::NOT_FOUND)
        );
    };
    Ok(Json(Resource::new(view.into())))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Query parameters for the paginated skills matrix.
pub struct SkillsMatrixParams {
    /// The machine identity after which to continue.
    pub cursor: Option<String>,
    /// The maximum rows to return, clamped to the public maximum.
    pub limit: Option<u32>,
}

#[utoipa::path(get, path = "/skills/matrix", tag = "skills", operation_id = "getSkillsMatrix", params(("cursor" = Option<String>, Query), ("limit" = Option<u32>, Query)), responses((status = 200, body = Page<SkillsSnapshotDto>), (status = 500, body = crate::error::ApiError), (status = 503, body = crate::error::ApiError)))]
/// Reads the fleet-wide matrix of observed skill inventories.
///
/// # Errors
///
/// Returns the standard error envelope when authorization or the backend fails.
pub async fn get_skills_matrix(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<SkillsMatrixParams>,
) -> Result<Json<Page<SkillsSnapshotDto>>, ApiErrorResponse> {
    let skills = skills_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let limit = params
        .limit
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .min(MAX_PAGE_LIMIT);
    let skills_page = skills
        .matrix(
            state.authorizer.as_ref(),
            &principal,
            SystemClock::now_unix_millis(),
            params.cursor.as_deref(),
            limit,
        )
        .await
        .map_err(|e| map_skills_error(&e, correlation_id))?;
    Ok(Json(Page {
        items: skills_page.items.into_iter().map(Into::into).collect(),
        page: PageInfo {
            next_cursor: skills_page.next_cursor,
            limit: skills_page.limit,
        },
    }))
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
    headers: axum::http::HeaderMap,
    Path(machine_id): Path<String>,
    Json(request): Json<StartSkillsOperationRequest>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let machines = crate::machines::machines_or_error(&state, correlation_id)?;
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
    // A pin downloads and installs a binary: that is a mutation, never a
    // read, so a pinned probe requires the deploy permission.
    let permission = match (&request.skill_id, &request.artifact_url) {
        (None, None) => fleet_application::authz::Permission::SkillsRead,
        _ => fleet_application::authz::Permission::SkillsDeploy,
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
    let kind = match (&request.skill_id, &request.direction) {
        (None, _) => "skills.probe",
        (Some(_), Some(SkillsDirectionDto::Undeploy)) => "skills.undeploy",
        (Some(_), _) => "skills.deploy",
    };
    // A partial pin is refused here, before the executor would drop it.
    if request.artifact_url.is_some() != request.artifact_sha256.is_some() {
        return Err(crate::machines::invalid_request(
            "the pinned release requires both an artifact URL and a sha256",
            correlation_id,
        ));
    }
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
                kind: kind.to_owned(),
                idempotency_key,
                deadline_at: None,
                correlation_id: Some(correlation_id.to_string()),
                payload_json: Some(payload.to_string()),
                review_token: None,
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
