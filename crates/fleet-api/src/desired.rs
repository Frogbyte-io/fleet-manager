//! The desired-state surface: reads of the active revision and its
//! validated resources (FM-404), and the source management endpoints
//! (FM-405). Fetch, activate, and rollback are durable operations
//! (`source.fetch`, `source.activate`, `source.rollback`); the fetch remote
//! always comes from the configured source, never from the caller.

use std::collections::BTreeMap;
use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};
use crate::operations::ApiState;

fn service(
    state: &ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<fleet_application::source::DesiredSource>, ApiErrorResponse> {
    state.desired.clone().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("desired_unavailable").expect("valid error code"),
            "the desired-state surface is not wired; the controller needs its database",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// The active desired revision and what its snapshot holds.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DesiredRevisionDto {
    /// The commit SHA of the active revision.
    pub commit_sha: String,
    /// The content digest of the active revision.
    pub content_digest: String,
    /// When the revision was activated (epoch milliseconds).
    pub activated_at: i64,
    /// Whether the revision's resources are held. A revision activated
    /// before snapshots existed has none until it is fetched again.
    pub resources_available: bool,
    /// The number of held resources per kind.
    pub resource_counts: BTreeMap<String, i64>,
}

/// The desired-state status: no revision is active until one is activated.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DesiredStatusDto {
    /// The active revision, when one has been activated.
    pub active: Option<DesiredRevisionDto>,
}

/// One validated desired resource of the active revision.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DesiredResourceDto {
    /// The resource kind.
    pub kind: String,
    /// The stable resource identity.
    pub id: String,
    /// The mutable human-facing label.
    pub name: String,
    /// The kind-specific non-secret spec.
    pub spec: serde_json::Value,
}

/// Filter, cursor and bound for the resource list.
#[derive(Clone, Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct DesiredResourcesParams {
    /// Only resources of this kind.
    pub kind: Option<String>,
    /// Opaque identifier returned as the previous page's cursor.
    pub cursor: Option<String>,
    /// Requested page size, clamped to the API maximum.
    pub limit: Option<u32>,
}

fn principal(
    principal: Option<Extension<crate::ActingPrincipal>>,
    correlation_id: CorrelationId,
) -> Result<crate::ActingPrincipal, ApiErrorResponse> {
    crate::operations::principal_or_error(principal, correlation_id)
}

/// Reads the active desired revision.
///
/// # Errors
///
/// Returns an API error when authentication, authorization, or storage fails.
#[utoipa::path(get, path = "/desired/revision", tag = "desired", operation_id = "getDesiredRevision", responses(
        (status = 200, body = Resource<DesiredStatusDto>),
        (status = 403, description = "The caller may not read the desired state.", body = ApiError),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The desired-state surface is not wired.", body = ApiError),
    ))]
pub async fn get_desired_revision(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<Resource<DesiredStatusDto>>, ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    let summary = service(&state, correlation_id)?
        .status(state.authorizer.as_ref(), &acting.id)
        .await
        .map_err(|error| crate::projects::map_project_error(&error, correlation_id))?;
    Ok(Json(Resource::new(DesiredStatusDto {
        active: summary.map(|summary| DesiredRevisionDto {
            commit_sha: summary.revision.commit_sha,
            content_digest: summary.revision.content_digest,
            activated_at: summary.activated_at,
            resources_available: summary.snapshot_held,
            resource_counts: summary.kind_counts,
        }),
    })))
}

/// Lists the active revision's resources.
///
/// # Errors
///
/// Returns an API error when authentication, authorization, or storage fails.
#[utoipa::path(get, path = "/desired/resources", tag = "desired", operation_id = "listDesiredResources", params(DesiredResourcesParams), responses(
        (status = 200, body = Page<DesiredResourceDto>),
        (status = 403, description = "The caller may not read the desired state.", body = ApiError),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The desired-state surface is not wired.", body = ApiError),
    ))]
pub async fn list_desired_resources(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<DesiredResourcesParams>,
) -> Result<Json<Page<DesiredResourceDto>>, ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    let limit = params
        .limit
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .clamp(1, MAX_PAGE_LIMIT);
    let mut found = service(&state, correlation_id)?
        .resources(
            state.authorizer.as_ref(),
            &acting.id,
            params.kind.as_deref(),
            params.cursor.as_deref(),
            i64::from(limit),
        )
        .await
        .map_err(|error| crate::projects::map_project_error(&error, correlation_id))?;
    let more = found.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    found.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    let next_cursor = more
        .then(|| found.last().map(|resource| resource.id.clone()))
        .flatten();
    Ok(Json(Page {
        items: found
            .into_iter()
            .map(|resource| DesiredResourceDto {
                kind: resource.kind,
                id: resource.id,
                name: resource.name,
                spec: resource.spec,
            })
            .collect(),
        page: PageInfo { next_cursor, limit },
    }))
}

/// The configured desired-source remote.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DesiredSourceDto {
    /// The remote, when one is configured. Never carries credentials.
    pub remote: Option<String>,
    /// The Git credential reference (an opaque id), when one is
    /// configured. Never the credential value.
    pub credential_ref: Option<String>,
}

/// Sets the desired-source remote.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigureSourceRequest {
    /// The Git remote. Embedded credentials are refused.
    pub remote: String,
    /// An optional reference returned by `POST /desired/source/credential`.
    /// Omitting it clears any reference: git then authenticates with the
    /// controller host's own configuration.
    #[serde(default)]
    pub credential_ref: Option<String>,
}

/// A Git credential to store: an HTTPS access token, or an SSH private key
/// in PEM/OpenSSH form. Write-only.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoreCredentialRequest {
    /// The credential value.
    pub value: String,
}

impl std::fmt::Debug for StoreCredentialRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreCredentialRequest")
            .field("value", &"[redacted]")
            .finish()
    }
}

/// The reference of a stored Git credential.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoredCredentialDto {
    /// The opaque reference to pass as `credentialRef`.
    pub credential_ref: String,
}

/// One recorded desired revision.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DesiredHistoryEntryDto {
    /// The commit SHA.
    pub commit_sha: String,
    /// The content digest.
    pub content_digest: String,
    /// Whether this is the active revision.
    pub active: bool,
}

/// Fetches one commit of the configured source as a candidate.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FetchDesiredRequest {
    /// The full 40-character lowercase hexadecimal commit SHA.
    pub commit_sha: String,
}

/// Names one recorded revision to activate or return to.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevisionRequest {
    /// The commit SHA.
    pub commit_sha: String,
    /// The content digest the candidate was fetched with.
    pub content_digest: String,
}

fn is_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn check_revision(
    commit_sha: &str,
    content_digest: Option<&str>,
    correlation_id: CorrelationId,
) -> Result<(), ApiErrorResponse> {
    if !is_hex(commit_sha, 40) {
        return Err(crate::machines::invalid_request(
            "commitSha must be a full 40-character lowercase hexadecimal commit id",
            correlation_id,
        ));
    }
    if content_digest.is_some_and(|digest| !is_hex(digest, 64)) {
        return Err(crate::machines::invalid_request(
            "contentDigest must be a 64-character lowercase hexadecimal digest",
            correlation_id,
        ));
    }
    Ok(())
}

/// Reads the configured desired-source remote.
///
/// # Errors
///
/// Returns an API error when authentication, authorization, or storage fails.
#[utoipa::path(
    get, path = "/desired/source", tag = "desired", operation_id = "getDesiredSource",
    responses(
        (status = 200, body = Resource<DesiredSourceDto>),
        (status = 403, description = "The caller may not read the desired state.", body = ApiError),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The desired-state surface is not wired.", body = ApiError),
    )
)]
pub async fn get_desired_source(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<Resource<DesiredSourceDto>>, ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    let config = service(&state, correlation_id)?
        .configuration(state.authorizer.as_ref(), &acting.id)
        .await
        .map_err(|error| crate::projects::map_project_error(&error, correlation_id))?;
    Ok(Json(Resource::new(DesiredSourceDto {
        remote: config.as_ref().map(|config| config.remote.clone()),
        credential_ref: config.and_then(|config| config.credential_ref),
    })))
}

/// Configures the desired-source remote.
///
/// # Errors
///
/// Returns an API error when authentication, authorization, validation, or storage fails.
#[utoipa::path(
    put, path = "/desired/source", tag = "desired", operation_id = "configureDesiredSource",
    request_body = ConfigureSourceRequest,
    responses(
        (status = 200, body = Resource<DesiredSourceDto>),
        (status = 400, description = "The remote is malformed or embeds credentials.", body = ApiError),
        (status = 403, description = "The caller may not configure the desired source.", body = ApiError),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The desired-state surface is not wired.", body = ApiError),
    )
)]
pub async fn configure_desired_source(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Json(request): Json<ConfigureSourceRequest>,
) -> Result<Json<Resource<DesiredSourceDto>>, ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    let config = service(&state, correlation_id)?
        .configure_remote(
            state.authorizer.as_ref(),
            &acting.id,
            &request.remote,
            request.credential_ref.as_deref(),
        )
        .await
        .map_err(|error| crate::projects::map_project_error(&error, correlation_id))?;
    Ok(Json(Resource::new(DesiredSourceDto {
        remote: Some(config.remote),
        credential_ref: config.credential_ref,
    })))
}

/// Stores a Git credential (HTTPS token or SSH private key) in the
/// controller's encrypted secret store and returns its reference. The value
/// is write-only: no endpoint returns it.
///
/// # Errors
///
/// Returns an API error when authentication, authorization, validation, or storage fails.
#[utoipa::path(
    post, path = "/desired/source/credential", tag = "desired", operation_id = "storeDesiredSourceCredential",
    request_body = StoreCredentialRequest,
    responses(
        (status = 201, body = Resource<StoredCredentialDto>),
        (status = 400, description = "The credential is empty or oversized, or no secret store is available.", body = ApiError),
        (status = 403, description = "The caller may not store secrets or configure the desired source.", body = ApiError),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The desired-state surface is not wired.", body = ApiError),
    )
)]
pub async fn store_desired_source_credential(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Json(request): Json<StoreCredentialRequest>,
) -> Result<(StatusCode, Json<Resource<StoredCredentialDto>>), ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    let credential_ref = service(&state, correlation_id)?
        .store_credential(state.authorizer.as_ref(), &acting.id, &request.value)
        .await
        .map_err(|error| crate::projects::map_project_error(&error, correlation_id))?;
    Ok((
        StatusCode::CREATED,
        Json(Resource::new(StoredCredentialDto { credential_ref })),
    ))
}

/// Lists the recorded desired revisions, newest first.
///
/// # Errors
///
/// Returns an API error when authentication, authorization, or storage fails.
#[utoipa::path(
    get, path = "/desired/history", tag = "desired", operation_id = "listDesiredHistory",
    responses(
        (status = 200, body = Page<DesiredHistoryEntryDto>),
        (status = 403, description = "The caller may not read the desired state.", body = ApiError),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The desired-state surface is not wired.", body = ApiError),
    )
)]
pub async fn list_desired_history(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<Page<DesiredHistoryEntryDto>>, ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    let (revisions, active) = service(&state, correlation_id)?
        .history(state.authorizer.as_ref(), &acting.id)
        .await
        .map_err(|error| crate::projects::map_project_error(&error, correlation_id))?;
    let items: Vec<_> = revisions
        .into_iter()
        .map(|revision| DesiredHistoryEntryDto {
            active: active.as_ref() == Some(&revision),
            commit_sha: revision.commit_sha,
            content_digest: revision.content_digest,
        })
        .collect();
    let limit = u32::try_from(items.len()).unwrap_or(u32::MAX);
    Ok(Json(Page {
        items,
        page: PageInfo {
            next_cursor: None,
            limit,
        },
    }))
}

async fn start(
    state: &ApiState,
    acting: &crate::ActingPrincipal,
    headers: &HeaderMap,
    correlation_id: CorrelationId,
    kind: &str,
    payload: serde_json::Value,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let idempotency_key = headers
        .get(crate::IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|key| format!("{}:{key}", acting.id));
    let operation = state
        .operations
        .create(
            state.authorizer.as_ref(),
            &acting.id,
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

/// Fetches a commit of the configured source as a candidate.
///
/// # Errors
///
/// Returns an API error when no remote is configured, or on authentication,
/// authorization, validation, or storage failure.
#[utoipa::path(
    post, path = "/desired/fetch", tag = "desired", operation_id = "fetchDesiredRevision",
    request_body = FetchDesiredRequest,
    responses(
        (status = 202, body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The commit is malformed or no remote is configured.", body = ApiError),
        (status = 403, description = "The caller may not fetch the desired source.", body = ApiError),
        (status = 503, description = "The desired-state surface is not wired.", body = ApiError),
    )
)]
pub async fn fetch_desired_revision(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: HeaderMap,
    Json(request): Json<FetchDesiredRequest>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    check_revision(&request.commit_sha, None, correlation_id)?;
    let config = service(&state, correlation_id)?
        .configuration(state.authorizer.as_ref(), &acting.id)
        .await
        .map_err(|error| crate::projects::map_project_error(&error, correlation_id))?
        .ok_or_else(|| {
            crate::machines::invalid_request(
                "no desired-source remote is configured; set one first",
                correlation_id,
            )
        })?;
    start(
        &state,
        &acting,
        &headers,
        correlation_id,
        "source.fetch",
        // The payload carries the credential reference id and never a value.
        serde_json::json!({
            "remote": config.remote,
            "commitSha": request.commit_sha,
            "credentialRef": config.credential_ref,
        }),
    )
    .await
}

/// Activates a fetched, valid candidate.
///
/// # Errors
///
/// Returns an API error on authentication, authorization, validation, or storage failure.
#[utoipa::path(
    post, path = "/desired/activate", tag = "desired", operation_id = "activateDesiredRevision",
    request_body = RevisionRequest,
    responses(
        (status = 202, body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The revision is malformed.", body = ApiError),
        (status = 403, description = "The caller may not activate the desired source.", body = ApiError),
        (status = 503, description = "The desired-state surface is not wired.", body = ApiError),
    )
)]
pub async fn activate_desired_revision(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: HeaderMap,
    Json(request): Json<RevisionRequest>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    check_revision(
        &request.commit_sha,
        Some(&request.content_digest),
        correlation_id,
    )?;
    start(
        &state,
        &acting,
        &headers,
        correlation_id,
        "source.activate",
        serde_json::json!({ "commitSha": request.commit_sha, "contentDigest": request.content_digest }),
    )
    .await
}

/// Returns to a prior valid revision from its stored snapshot.
///
/// # Errors
///
/// Returns an API error on authentication, authorization, validation, or storage failure.
#[utoipa::path(
    post, path = "/desired/rollback", tag = "desired", operation_id = "rollbackDesiredRevision",
    request_body = RevisionRequest,
    responses(
        (status = 202, body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The revision is malformed.", body = ApiError),
        (status = 403, description = "The caller may not activate the desired source.", body = ApiError),
        (status = 503, description = "The desired-state surface is not wired.", body = ApiError),
    )
)]
pub async fn rollback_desired_revision(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: HeaderMap,
    Json(request): Json<RevisionRequest>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    check_revision(
        &request.commit_sha,
        Some(&request.content_digest),
        correlation_id,
    )?;
    start(
        &state,
        &acting,
        &headers,
        correlation_id,
        "source.rollback",
        serde_json::json!({ "commitSha": request.commit_sha, "contentDigest": request.content_digest }),
    )
    .await
}
