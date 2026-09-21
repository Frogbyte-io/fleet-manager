//! The project surface: identity, display facts, and observed checkouts
//! behind the application's authorized use cases (FM-300).
//!
//! This adapter decides nothing about projects; it translates HTTP into
//! use-case calls and use-case outcomes into the documented shapes. The
//! normalized remote is the identity — a conflict is a 409 carrying the
//! normalized form of what already exists.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use fleet_application::project::{NewProject, ProjectFilter, ProjectUseCaseError, Projects};
use fleet_core::{CheckoutFact, CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use std::str::FromStr as _;
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};

/// Extracts the project use cases from the API state, or answers with the
/// standard envelope when the controller was composed without a database.
pub(crate) fn projects_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<Projects>, ApiErrorResponse> {
    state.projects.clone().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("project_unavailable")
                .expect("the literal is valid error code syntax"),
            "the project surface is not wired; the controller needs its database",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// Maps a project use-case outcome onto the public error envelope, once.
pub(crate) fn map_project_error(
    error: &ProjectUseCaseError,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    let (status, code, retry): (StatusCode, &str, RetryClass) = match error {
        ProjectUseCaseError::Denied(_) => (StatusCode::FORBIDDEN, "denied", RetryClass::Never),
        ProjectUseCaseError::NotFound { .. } => {
            (StatusCode::NOT_FOUND, "not_found", RetryClass::Never)
        }
        ProjectUseCaseError::Conflict { .. } => {
            (StatusCode::CONFLICT, "conflict", RetryClass::Never)
        }
        ProjectUseCaseError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
        ),
        ProjectUseCaseError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    let message = match error {
        ProjectUseCaseError::Backend { .. } => {
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

/// A 400 response with a caller-safe message. Kept as a helper so the
/// pinned literal error code lives in one place.
fn invalid_request(message: &str, correlation_id: CorrelationId) -> ApiErrorResponse {
    let public = PublicError::new(
        ErrorCode::from_str("invalid_request").expect("the literal is valid error code syntax"),
        message.to_owned(),
        RetryClass::Never,
    );
    ApiError::new(&public, correlation_id).with_status(StatusCode::BAD_REQUEST)
}

/// One observed checkout of a project.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CheckoutFactDto {
    /// The machine carrying the checkout.
    pub machine_id: String,
    /// The checkout's root path.
    pub root: String,
    /// The checked-out branch, when observed.
    pub branch: Option<String>,
    /// Whether the worktree was dirty at observation.
    pub dirty: Option<bool>,
    /// What observed it.
    pub source: String,
    /// When it was observed (epoch milliseconds).
    pub observed_at: i64,
}

/// A project as the detail view displays it.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectDto {
    /// The project's identity.
    pub id: String,
    /// The normalized remote.
    pub remote: String,
    /// The display name.
    pub name: String,
    /// Operator notes.
    pub description: String,
    /// The observed checkouts across machines, newest observation first.
    pub checkouts: Vec<CheckoutFactDto>,
    /// Creation time (epoch milliseconds).
    pub created_at: i64,
    /// Last mutation (epoch milliseconds).
    pub updated_at: i64,
}

impl From<fleet_core::Project> for ProjectDto {
    fn from(project: fleet_core::Project) -> Self {
        Self {
            id: project.id,
            remote: project.remote,
            name: project.name,
            description: project.description,
            checkouts: Vec::new(),
            created_at: project.created_at,
            updated_at: project.updated_at,
        }
    }
}

impl From<fleet_core::ProjectView> for ProjectDto {
    fn from(view: fleet_core::ProjectView) -> Self {
        Self {
            id: view.id,
            remote: view.remote,
            name: view.name,
            description: view.description,
            checkouts: view
                .checkouts
                .into_iter()
                .map(|fact: CheckoutFact| CheckoutFactDto {
                    machine_id: fact.machine_id,
                    root: fact.root,
                    branch: fact.branch,
                    dirty: fact.dirty,
                    source: fact.source,
                    observed_at: fact.observed_at,
                })
                .collect(),
            created_at: view.created_at,
            updated_at: view.updated_at,
        }
    }
}

/// The create-project request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateProjectRequest {
    /// The Git remote, in any common spelling; normalized here.
    pub remote: String,
    /// The mutable, unique display name.
    pub name: String,
    /// Operator notes.
    pub description: Option<String>,
}

/// The update-project request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProjectRequest {
    /// The display name.
    pub name: String,
    /// Operator notes. Absent means "keep the current description".
    pub description: Option<String>,
}

/// The list-projects query parameters.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListProjectsParams {
    /// Only projects whose normalized remote starts with this prefix.
    pub remote_prefix: Option<String>,
    /// Only projects whose name contains this substring.
    pub name_substring: Option<String>,
    /// The opaque cursor from a previous page (the last project's id).
    pub cursor: Option<String>,
    /// The maximum number of projects to return.
    pub limit: Option<u32>,
}

/// Registers a project.
///
/// # Errors
///
/// Returns the public error envelope on refusal, a conflicting remote or
/// name, or a backend failure.
#[utoipa::path(
    post,
    path = "/projects",
    tag = "projects",
    operation_id = "createProject",
    request_body = CreateProjectRequest,
    responses(
        (
            status = 201,
            description = "The project was registered.",
            body = Resource<ProjectDto>
        ),
        (
            status = 400,
            description = "The remote or name is malformed (or credential-bearing).",
            body = crate::error::ApiError
        ),
        (
            status = 409,
            description = "The remote or name is already registered.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not create projects.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn create_project(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: axum::http::HeaderMap,
    Json(request): Json<CreateProjectRequest>,
) -> Result<(StatusCode, Json<Resource<ProjectDto>>), ApiErrorResponse> {
    let projects = projects_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // The idempotency key scopes to the caller: a replay returns the
    // original project instead of a conflict.
    let idempotency_key = headers
        .get(crate::IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|key| format!("{}:{key}", principal.id));
    let project = projects
        .register(
            state.authorizer.as_ref(),
            &principal,
            NewProject {
                remote: request.remote,
                name: request.name,
                description: request.description.unwrap_or_default(),
                idempotency_key: idempotency_key.clone(),
            },
            idempotency_key,
        )
        .await
        .map_err(|error| map_project_error(&error, correlation_id))?;
    Ok((
        StatusCode::CREATED,
        Json(Resource::new(ProjectDto::from(project))),
    ))
}

/// Lists projects, newest first.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/projects",
    tag = "projects",
    operation_id = "listProjects",
    params(
        ("remotePrefix" = Option<String>, Query, description = "Only projects whose normalized remote starts with this prefix."),
        ("nameSubstring" = Option<String>, Query, description = "Only projects whose name contains this substring."),
        ("cursor" = Option<String>, Query, description = "The opaque cursor from a previous page (the last project's id)."),
        ("limit" = Option<u32>, Query, description = "The maximum number of projects to return.")
    ),
    responses(
        (
            status = 200,
            description = "A page of projects.",
            body = Page<ProjectDto>
        ),
        (
            status = 403,
            description = "The caller may not read projects.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn list_projects(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<ListProjectsParams>,
) -> Result<Json<Page<ProjectDto>>, ApiErrorResponse> {
    let projects = projects_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // A zero or absent limit means the default; the page never advertises
    // more than it returns.
    let limit = params
        .limit
        .filter(|limit| *limit > 0)
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .min(MAX_PAGE_LIMIT);
    let filter = ProjectFilter {
        remote_prefix: params.remote_prefix,
        name_substring: params.name_substring,
        after_id: params.cursor,
    };
    let items = projects
        .list(state.authorizer.as_ref(), &principal, &filter, limit)
        .await
        .map_err(|error| map_project_error(&error, correlation_id))?;
    let next_cursor = (items.len() == usize::try_from(limit).unwrap_or(0))
        .then(|| items.last().map(|project| project.id.clone()))
        .flatten();
    Ok(Json(Page {
        items: items.into_iter().map(ProjectDto::from).collect(),
        page: PageInfo { next_cursor, limit },
    }))
}

/// Reads one project with its observed checkouts.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown project.
#[utoipa::path(
    get,
    path = "/projects/{projectId}",
    tag = "projects",
    operation_id = "getProject",
    params(
        ("projectId" = String, Path, description = "The project's identity.")
    ),
    responses(
        (
            status = 200,
            description = "The project with its observed checkouts.",
            body = Resource<ProjectDto>
        ),
        (
            status = 404,
            description = "No such project.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not read projects.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn get_project(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(project_id): Path<String>,
) -> Result<Json<Resource<ProjectDto>>, ApiErrorResponse> {
    let projects = projects_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let view = projects
        .get(state.authorizer.as_ref(), &principal, &project_id)
        .await
        .map_err(|error| map_project_error(&error, correlation_id))?;
    Ok(Json(Resource::new(ProjectDto::from(view))))
}

/// Renames or re-describes a project.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown project.
#[utoipa::path(
    patch,
    path = "/projects/{projectId}",
    tag = "projects",
    operation_id = "updateProject",
    params(
        ("projectId" = String, Path, description = "The project's identity.")
    ),
    request_body = UpdateProjectRequest,
    responses(
        (
            status = 200,
            description = "The project was updated.",
            body = Resource<ProjectDto>
        ),
        (
            status = 404,
            description = "No such project.",
            body = crate::error::ApiError
        ),
        (
            status = 409,
            description = "The name is already taken.",
            body = crate::error::ApiError
        ),
        (
            status = 400,
            description = "The name or description is malformed.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not update projects.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn update_project(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(project_id): Path<String>,
    Json(request): Json<UpdateProjectRequest>,
) -> Result<Json<Resource<ProjectDto>>, ApiErrorResponse> {
    let projects = projects_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // A missing description means "keep the current one": the CLI's rename
    // path cannot know the current text, so it omits the field.
    let description = if let Some(description) = request.description {
        description
    } else {
        let current = projects
            .get(state.authorizer.as_ref(), &principal, &project_id)
            .await
            .map_err(|error| map_project_error(&error, correlation_id))?;
        current.description
    };
    let project = projects
        .update(
            state.authorizer.as_ref(),
            &principal,
            &project_id,
            &request.name,
            &description,
        )
        .await
        .map_err(|error| map_project_error(&error, correlation_id))?;
    Ok(Json(Resource::new(ProjectDto::from(project))))
}

/// Removes a project and its observed checkouts. The Git repositories
/// themselves are untouched.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown project.
#[utoipa::path(
    delete,
    path = "/projects/{projectId}",
    tag = "projects",
    operation_id = "deleteProject",
    params(
        ("projectId" = String, Path, description = "The project's identity.")
    ),
    responses(
        (
            status = 204,
            description = "The project was removed."
        ),
        (
            status = 404,
            description = "No such project.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not delete projects.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn delete_project(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(project_id): Path<String>,
) -> Result<StatusCode, ApiErrorResponse> {
    let projects = projects_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    projects
        .delete(state.authorizer.as_ref(), &principal, &project_id)
        .await
        .map_err(|error| map_project_error(&error, correlation_id))?;
    Ok(StatusCode::NO_CONTENT)
}

/// The body of the start-discovery request: which machine and endpoint to
/// scan, and how the endpoint authenticates.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartDiscoveryRequest {
    /// The machine whose standard roots to scan.
    pub machine_id: String,
    /// The SSH endpoint id to probe through.
    pub endpoint_id: String,
    /// How the endpoint authenticates.
    pub auth: CheckoutAuthDto,
    /// The deadline, in seconds. Bounded by the executor.
    pub timeout_seconds: u64,
}

/// How a checkout action's endpoint authenticates.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum CheckoutAuthDto {
    /// The controller's agent supplies the key.
    Agent,
    /// A specific identity file.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// The body of the record-checkouts request: the discovery result to ingest
/// as observed facts, matched to this project by its normalized remote.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecordCheckoutsRequest {
    /// The machine the checkouts were observed on.
    pub machine_id: String,
    /// The observed checkouts, as the discovery operation reported them.
    pub checkouts: Vec<DiscoveredCheckoutDto>,
}

/// One discovered checkout, as the discovery operation reported it.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredCheckoutDto {
    /// The checkout's root path on the machine.
    pub root: String,
    /// The checked-out branch, when observed.
    pub branch: Option<String>,
    /// The HEAD commit, when observed.
    pub head: Option<String>,
    /// Whether the worktree was dirty at observation.
    pub dirty: Option<bool>,
    /// The origin remote URL, when one is configured (already redacted).
    pub remote: Option<String>,
    /// Whether the observation is complete (`known`) or the checkout was
    /// unreadable (`unavailable`).
    pub status: String,
}

/// Starts a checkout discovery: a `projects.discover` operation against the
/// named machine's standard roots.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    post,
    path = "/projects/{projectId}/discoveries",
    tag = "projects",
    operation_id = "startProjectDiscovery",
    request_body = StartDiscoveryRequest,
    params(
        ("projectId" = String, Path, description = "The project's identity.")
    ),
    responses(
        (
            status = 202,
            description = "The discovery operation was accepted.",
            body = Resource<crate::operations::OperationDto>
        ),
        (
            status = 403,
            description = "The caller may not discover checkouts.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn start_discovery(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(id): Path<String>,
    Json(request): Json<StartDiscoveryRequest>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let projects = projects_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // The project must exist and be readable: discovery names it.
    projects
        .get(state.authorizer.as_ref(), &principal, &id)
        .await
        .map_err(|error| map_project_error(&error, correlation_id))?;
    // Discovery authorization is machine-scoped: the probe reveals the
    // machine's filesystem topology.
    if let Err(decision) = fleet_application::authz::authorize(
        state.authorizer.as_ref(),
        fleet_application::authz::AccessRequest {
            principal_id: &principal.id,
            action: fleet_application::authz::Permission::ProjectsDiscover,
            resource: Some(&request.machine_id),
        },
    ) {
        return Err(map_project_error(
            &ProjectUseCaseError::Denied(decision),
            correlation_id,
        ));
    }
    let payload = serde_json::json!({
        "machineId": request.machine_id,
        "endpointId": request.endpoint_id,
        "auth": serde_json::to_value(&request.auth)
            .map_err(|error| invalid_request(&error.to_string(), correlation_id))?,
        "timeoutSeconds": request.timeout_seconds,
    })
    .to_string();
    let operation = state
        .operations
        .create(
            state.authorizer.as_ref(),
            &principal.id,
            &fleet_application::operation::NewOperation {
                kind: "projects.discover".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: Some(correlation_id.to_string()),
                payload_json: Some(payload),
                reviewed: false,
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

/// Records discovered checkouts as this project's observed facts. Checkouts
/// whose remote does not normalize to this project's remote are refused as
/// a batch: mixed observations would silently corrupt the identity.
///
/// # Errors
///
/// Returns the public error envelope on refusal, a mismatched remote, or a
/// backend failure.
#[utoipa::path(
    post,
    path = "/projects/{projectId}/checkouts",
    tag = "projects",
    operation_id = "recordProjectCheckouts",
    request_body = RecordCheckoutsRequest,
    params(
        ("projectId" = String, Path, description = "The project's identity.")
    ),
    responses(
        (
            status = 201,
            description = "The observations were recorded.",
            body = Resource<ProjectDto>
        ),
        (
            status = 400,
            description = "A checkout's remote does not match the project.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not update the project.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn record_checkouts(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(id): Path<String>,
    Json(request): Json<RecordCheckoutsRequest>,
) -> Result<(StatusCode, Json<Resource<ProjectDto>>), ApiErrorResponse> {
    let projects = projects_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let project = projects
        .get(state.authorizer.as_ref(), &principal, &id)
        .await
        .map_err(|error| map_project_error(&error, correlation_id))?;
    let now = fleet_core::SystemClock::now_unix_millis();
    for checkout in &request.checkouts {
        // The remote must match the project's identity: an observation of a
        // different repository is refused, not silently re-keyed.
        if let Some(remote) = &checkout.remote {
            let normalized = fleet_core::NormalizedRemote::parse(remote)
                .map_err(|detail| invalid_request(&detail, correlation_id))?;
            if normalized.as_str() != project.remote {
                return Err(invalid_request(
                    &format!(
                        "the checkout at {} observes remote {}, which is not this project ({})",
                        checkout.root, remote, project.remote
                    ),
                    correlation_id,
                ));
            }
        }
        projects
            .record_checkout(
                state.authorizer.as_ref(),
                &principal,
                CheckoutFact {
                    project_id: id.clone(),
                    machine_id: request.machine_id.clone(),
                    root: checkout.root.clone(),
                    branch: checkout.branch.clone(),
                    dirty: checkout.dirty,
                    source: "checkout-discovery/1".to_owned(),
                    observed_at: now,
                },
            )
            .await
            .map_err(|error| map_project_error(&error, correlation_id))?;
    }
    let view = projects
        .get(state.authorizer.as_ref(), &principal, &id)
        .await
        .map_err(|error| map_project_error(&error, correlation_id))?;
    Ok((
        StatusCode::CREATED,
        Json(Resource::new(ProjectDto::from(view))),
    ))
}
