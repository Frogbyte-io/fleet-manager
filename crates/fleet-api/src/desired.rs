//! The read-only desired-state surface (FM-404): the active revision and
//! the validated resources it holds. Mutations stay on the operations
//! surface (`source.fetch`, `source.activate`).

use std::collections::BTreeMap;
use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Query, State},
    http::StatusCode,
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
