//! HTTP adapter for Fleet's authored skill catalog.
use crate::{
    envelope::{Page, PageInfo, Resource},
    error::{ApiError, ApiErrorResponse},
    operations::ApiState,
};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use fleet_application::skill_catalog::{
    SkillCatalogEntry, SkillCatalogError, SkillCatalogFile, SkillCatalogSource, SkillCatalogVersion,
};
use fleet_core::SkillCatalogContent;
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use std::str::FromStr as _;
use std::sync::Arc;
use utoipa::ToSchema;

/// Catalog draft response.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CatalogSourceDto {
    /// Fleet-owned authored content.
    Authored,
    /// External source reference.
    Referenced {
        /// Reference or Git URL.
        reference: String,
        /// Optional Git subpath.
        subpath: Option<String>,
        /// Optional immutable revision.
        revision: Option<String>,
    },
}
impl From<SkillCatalogSource> for CatalogSourceDto {
    fn from(v: SkillCatalogSource) -> Self {
        match v {
            SkillCatalogSource::Authored => Self::Authored,
            SkillCatalogSource::Referenced {
                reference,
                subpath,
                revision,
            } => Self::Referenced {
                reference,
                subpath,
                revision,
            },
        }
    }
}
impl From<CatalogSourceDto> for SkillCatalogSource {
    fn from(v: CatalogSourceDto) -> Self {
        match v {
            CatalogSourceDto::Authored => Self::Authored,
            CatalogSourceDto::Referenced {
                reference,
                subpath,
                revision,
            } => Self::Referenced {
                reference,
                subpath,
                revision,
            },
        }
    }
}
/// One text file included in an authored skill.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogFileDto {
    /// Relative file path.
    pub path: String,
    /// UTF-8 text file contents.
    pub content: String,
}
impl From<SkillCatalogFile> for CatalogFileDto {
    fn from(v: SkillCatalogFile) -> Self {
        Self {
            path: v.path,
            content: v.content,
        }
    }
}
/// Submitted or returned catalog content.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogContentDto {
    /// Agent Skills name.
    pub name: String,
    /// Agent Skills description.
    pub description: String,
    /// Authored files, empty for referenced entries.
    pub files: Vec<CatalogFileDto>,
    /// Source contract.
    pub source: CatalogSourceDto,
}
impl From<SkillCatalogContent> for CatalogContentDto {
    fn from(v: SkillCatalogContent) -> Self {
        Self {
            name: v.name,
            description: v.description,
            files: v.files.into_iter().map(Into::into).collect(),
            source: v.source.into(),
        }
    }
}
impl From<CatalogContentDto> for SkillCatalogContent {
    fn from(v: CatalogContentDto) -> Self {
        Self {
            name: v.name,
            description: v.description,
            files: v
                .files
                .into_iter()
                .map(|f| SkillCatalogFile {
                    path: f.path,
                    content: f.content,
                })
                .collect(),
            source: v.source.into(),
        }
    }
}

/// Catalog draft response.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogDto {
    /// Draft identity.
    pub id: String,
    /// Draft content.
    pub content: CatalogContentDto,
    /// Prior published version.
    pub published_from: Option<String>,
    /// Creation time.
    pub created_at: i64,
    /// Last update time.
    pub updated_at: i64,
}
impl From<SkillCatalogEntry> for CatalogDto {
    fn from(v: SkillCatalogEntry) -> Self {
        Self {
            id: v.id,
            content: v.content.into(),
            published_from: v.published_from,
            created_at: v.created_at,
            updated_at: v.updated_at,
        }
    }
}

/// Immutable published version response.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogVersionDto {
    /// Version identity.
    pub id: String,
    /// Parent entry.
    pub catalog_id: String,
    /// Skill name.
    pub name: String,
    /// Skill description.
    pub description: String,
    /// SHA-256 content digest.
    pub content_digest: String,
    /// Frozen content.
    pub content: CatalogContentDto,
    /// Publication time.
    pub published_at: i64,
}
impl From<SkillCatalogVersion> for CatalogVersionDto {
    fn from(v: SkillCatalogVersion) -> Self {
        Self {
            id: v.id,
            catalog_id: v.catalog_id,
            name: v.name,
            description: v.description,
            content_digest: v.content_digest,
            content: v.content.into(),
            published_at: v.published_at,
        }
    }
}

/// Draft input.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SaveCatalogRequest {
    /// Content to save.
    pub content: CatalogContentDto,
}

/// Machine-scoped request to preview or execute one pinned catalog version.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogRolloutRequest {
    /// Immutable catalog version id.
    pub version_id: String,
    /// Target machine id.
    pub machine_id: String,
    /// SSH endpoint id.
    pub endpoint_id: String,
    /// SSH authentication mode.
    pub auth: crate::skills::SkillsAuthDto,
    /// Explicit Skills Manager agent ids.
    pub agents: Vec<String>,
    /// Operation deadline in seconds.
    pub timeout_seconds: u64,
}
/// Preview of the steps for a catalog rollout.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogRolloutPlanDto {
    /// Pinned version.
    pub version_id: String,
    /// Frozen content digest.
    pub content_digest: String,
    /// Target machine.
    pub machine_id: String,
    /// Fleet-owned destination.
    pub staging_path: Option<String>,
    /// Explicit agents.
    pub agents: Vec<String>,
    /// Ordered steps.
    pub steps: Vec<String>,
}

/// Cursor and bound for catalog list endpoints.
#[derive(Clone, Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct CatalogPageParams {
    /// Opaque identifier returned as the previous page's cursor.
    pub cursor: Option<String>,
    /// Requested page size, clamped to the API maximum.
    pub limit: Option<u32>,
}

fn service(
    state: &ApiState,
    cid: CorrelationId,
) -> Result<Arc<fleet_application::skill_catalog::SkillCatalog>, ApiErrorResponse> {
    state.skill_catalog.clone().ok_or_else(|| {
        let e = PublicError::new(
            ErrorCode::from_str("machine_unavailable").expect("valid code"),
            "the skill catalog is not wired; the controller needs its database",
            RetryClass::Backoff,
        );
        ApiError::new(&e, cid).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}
fn mapped(error: &SkillCatalogError, cid: CorrelationId) -> ApiErrorResponse {
    let (status, code, retry) = match error {
        SkillCatalogError::Denied(_) => (StatusCode::FORBIDDEN, "denied", RetryClass::Never),
        SkillCatalogError::Invalid(_) => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
        ),
        SkillCatalogError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found", RetryClass::Never),
        SkillCatalogError::Conflict(_) => (StatusCode::CONFLICT, "conflict", RetryClass::Never),
        SkillCatalogError::Backend(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    let message = if matches!(error, SkillCatalogError::Backend(_)) {
        "the request could not be completed; the detail is in the controller log".to_owned()
    } else {
        error.to_string()
    };
    ApiError::new(
        &PublicError::new(
            ErrorCode::from_str(code).expect("valid code"),
            message,
            retry,
        ),
        cid,
    )
    .with_status(status)
}
fn principal(
    p: Option<Extension<crate::ActingPrincipal>>,
    cid: CorrelationId,
) -> Result<crate::ActingPrincipal, ApiErrorResponse> {
    crate::operations::principal_or_error(p, cid)
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Lists catalog drafts.
///
/// # Errors
///
/// Returns an API error when authentication, authorization, or the catalog backend fails.
#[utoipa::path(get,path="/skills/catalog",tag="skills",operation_id="listSkillCatalog",params(CatalogPageParams),responses((status=200,body=Page<CatalogDto>)))]
pub async fn list_catalog(
    State(st): State<Arc<ApiState>>,
    p: Option<Extension<crate::ActingPrincipal>>,
    Extension(cid): Extension<CorrelationId>,
    Query(params): Query<CatalogPageParams>,
) -> Result<Json<Page<CatalogDto>>, ApiErrorResponse> {
    let p = principal(p, cid)?;
    let limit = params
        .limit
        .unwrap_or(crate::envelope::DEFAULT_PAGE_LIMIT)
        .clamp(1, crate::envelope::MAX_PAGE_LIMIT);
    let mut v = service(&st, cid)?
        .list(st.authorizer.as_ref(), &p, params.cursor.as_deref(), limit)
        .await
        .map_err(|e| mapped(&e, cid))?;
    let has_more = v.len() > usize::try_from(limit).unwrap_or(0);
    v.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    let next_cursor = has_more
        .then(|| v.last().map(|entry| entry.id.clone()))
        .flatten();
    Ok(Json(Page {
        items: v.into_iter().map(Into::into).collect(),
        page: PageInfo { next_cursor, limit },
    }))
}

/// Creates a catalog draft.
///
/// # Errors
///
/// Returns an API error when authentication, validation, authorization, auditing, or storage fails.
#[utoipa::path(post,path="/skills/catalog",tag="skills",operation_id="createSkillCatalog",request_body=SaveCatalogRequest,responses((status=201,body=Resource<CatalogDto>)))]
pub async fn create_catalog(
    State(st): State<Arc<ApiState>>,
    p: Option<Extension<crate::ActingPrincipal>>,
    Extension(cid): Extension<CorrelationId>,
    Json(req): Json<SaveCatalogRequest>,
) -> Result<(StatusCode, Json<Resource<CatalogDto>>), ApiErrorResponse> {
    let p = principal(p, cid)?;
    let v = service(&st, cid)?
        .create(st.authorizer.as_ref(), &p, req.content.into(), now())
        .await
        .map_err(|e| mapped(&e, cid))?;
    Ok((StatusCode::CREATED, Json(Resource::new(v.into()))))
}

/// Reads a catalog draft.
///
/// # Errors
///
/// Returns an API error when authentication, authorization, or storage fails.
#[utoipa::path(get,path="/skills/catalog/{id}",tag="skills",operation_id="getSkillCatalog",params(("id"=String,Path)),responses((status=200,body=Resource<CatalogDto>)))]
pub async fn get_catalog(
    State(st): State<Arc<ApiState>>,
    p: Option<Extension<crate::ActingPrincipal>>,
    Extension(cid): Extension<CorrelationId>,
    Path(id): Path<String>,
) -> Result<Json<Resource<CatalogDto>>, ApiErrorResponse> {
    let p = principal(p, cid)?;
    let v = service(&st, cid)?
        .get(st.authorizer.as_ref(), &p, &id)
        .await
        .map_err(|e| mapped(&e, cid))?;
    Ok(Json(Resource::new(v.into())))
}

/// Updates a catalog draft.
///
/// # Errors
///
/// Returns an API error when authentication, validation, authorization, auditing, or storage fails.
#[utoipa::path(put,path="/skills/catalog/{id}",tag="skills",operation_id="updateSkillCatalog",params(("id"=String,Path)),request_body=SaveCatalogRequest,responses((status=200,body=Resource<CatalogDto>)))]
pub async fn update_catalog(
    State(st): State<Arc<ApiState>>,
    p: Option<Extension<crate::ActingPrincipal>>,
    Extension(cid): Extension<CorrelationId>,
    Path(id): Path<String>,
    Json(req): Json<SaveCatalogRequest>,
) -> Result<Json<Resource<CatalogDto>>, ApiErrorResponse> {
    let p = principal(p, cid)?;
    let v = service(&st, cid)?
        .update(st.authorizer.as_ref(), &p, &id, req.content.into(), now())
        .await
        .map_err(|e| mapped(&e, cid))?;
    Ok(Json(Resource::new(v.into())))
}

/// Publishes a content-addressed immutable catalog version.
///
/// # Errors
///
/// Returns an API error when authentication, authorization, auditing, or storage fails.
#[utoipa::path(post,path="/skills/catalog/{id}/publish",tag="skills",operation_id="publishSkillCatalog",params(("id"=String,Path)),responses((status=201,body=Resource<CatalogVersionDto>)))]
pub async fn publish_catalog(
    State(st): State<Arc<ApiState>>,
    p: Option<Extension<crate::ActingPrincipal>>,
    Extension(cid): Extension<CorrelationId>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<Resource<CatalogVersionDto>>), ApiErrorResponse> {
    let p = principal(p, cid)?;
    let v = service(&st, cid)?
        .publish(st.authorizer.as_ref(), &p, &id, now())
        .await
        .map_err(|e| mapped(&e, cid))?;
    Ok((StatusCode::CREATED, Json(Resource::new(v.into()))))
}

/// Lists immutable versions for a catalog entry.
///
/// # Errors
///
/// Returns an API error when authentication, authorization, or storage fails.
#[utoipa::path(get,path="/skills/catalog/{id}/versions",tag="skills",operation_id="listSkillCatalogVersions",params(("id"=String,Path),CatalogPageParams),responses((status=200,body=Page<CatalogVersionDto>)))]
pub async fn list_catalog_versions(
    State(st): State<Arc<ApiState>>,
    p: Option<Extension<crate::ActingPrincipal>>,
    Extension(cid): Extension<CorrelationId>,
    Path(id): Path<String>,
    Query(params): Query<CatalogPageParams>,
) -> Result<Json<Page<CatalogVersionDto>>, ApiErrorResponse> {
    let p = principal(p, cid)?;
    let limit = params
        .limit
        .unwrap_or(crate::envelope::DEFAULT_PAGE_LIMIT)
        .clamp(1, crate::envelope::MAX_PAGE_LIMIT);
    let mut v = service(&st, cid)?
        .versions(
            st.authorizer.as_ref(),
            &p,
            &id,
            params.cursor.as_deref(),
            limit,
        )
        .await
        .map_err(|e| mapped(&e, cid))?;
    let has_more = v.len() > usize::try_from(limit).unwrap_or(0);
    v.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    let next_cursor = has_more
        .then(|| v.last().map(|version| version.id.clone()))
        .flatten();
    Ok(Json(Page {
        items: v.into_iter().map(Into::into).collect(),
        page: PageInfo { next_cursor, limit },
    }))
}

fn rollout_plan(
    version: &SkillCatalogVersion,
    request: &CatalogRolloutRequest,
) -> CatalogRolloutPlanDto {
    let authored = matches!(
        &version.content.source,
        fleet_core::SkillCatalogSource::Authored
    );
    CatalogRolloutPlanDto {
        version_id: version.id.clone(),
        content_digest: version.content_digest.clone(),
        machine_id: request.machine_id.clone(),
        staging_path: authored.then(|| format!("~/.local/share/fleet/skills/{}", version.name)),
        agents: request.agents.clone(),
        steps: if authored {
            vec![
                "stage and verify authored files".to_owned(),
                "install locally or update the pinned local source".to_owned(),
                "deploy to the explicit agents".to_owned(),
                "verify with skills show and skills status".to_owned(),
            ]
        } else {
            vec![
                "install or update the referenced Skills Manager source".to_owned(),
                "deploy to the explicit agents".to_owned(),
                "verify with skills show and skills status".to_owned(),
            ]
        },
    }
}
pub(crate) async fn authorize_rollout(
    st: &ApiState,
    p: &crate::ActingPrincipal,
    cid: CorrelationId,
    request: &CatalogRolloutRequest,
) -> Result<SkillCatalogVersion, ApiErrorResponse> {
    if request.agents.is_empty()
        || request.agents.len() > 32
        || request.machine_id.trim().is_empty()
        || request.endpoint_id.trim().is_empty()
        || request.timeout_seconds == 0
        || request.timeout_seconds > 3600
    {
        return Err(crate::machines::invalid_request(
            "catalog rollout requires a machine, endpoint, 1..=32 agents, and a timeout in 1..=3600 seconds",
            cid,
        ));
    }
    let mut unique_agents = request.agents.clone();
    unique_agents.sort();
    unique_agents.dedup();
    if unique_agents.len() != request.agents.len() {
        return Err(crate::machines::invalid_request(
            "catalog rollout agent ids must be unique",
            cid,
        ));
    }
    fleet_application::authz::authorize(
        st.authorizer.as_ref(),
        fleet_application::authz::AccessRequest {
            principal_id: &p.id,
            action: fleet_application::authz::Permission::SkillsDeploy,
            resource: Some(&request.machine_id),
        },
    )
    .map_err(|d| mapped(&SkillCatalogError::Denied(d), cid))?;
    let machines = crate::machines::machines_or_error(st, cid)?;
    let machine = machines
        .get(st.authorizer.as_ref(), p, &request.machine_id, now())
        .await
        .map_err(|error| crate::machines::map_machine_error(&error, cid))?;
    let endpoint = machine
        .endpoints
        .iter()
        .find(|endpoint| endpoint.id == request.endpoint_id)
        .ok_or_else(|| {
            crate::machines::map_machine_error(
                &fleet_application::machine::MachineUseCaseError::NotFound {
                    what: format!(
                        "endpoint {} on machine {}",
                        request.endpoint_id, request.machine_id
                    ),
                },
                cid,
            )
        })?;
    if endpoint.kind != fleet_core::EndpointKind::Ssh {
        return Err(crate::machines::invalid_request(
            "catalog rollout requires an SSH endpoint",
            cid,
        ));
    }
    let version = service(st, cid)?
        .get_version(st.authorizer.as_ref(), p, &request.version_id)
        .await
        .map_err(|e| mapped(&e, cid))?;
    Ok(version)
}

/// Previews a rollout without creating an operation or changing a machine.
///
/// # Errors
///
/// Returns an API error when authentication, request validation, authorization,
/// machine lookup, or storage fails.
#[utoipa::path(post,path="/skills/catalog/rollout-plan",tag="skills",operation_id="previewSkillCatalogRollout",request_body=CatalogRolloutRequest,responses((status=200,body=Resource<CatalogRolloutPlanDto>)))]
pub async fn preview_catalog_rollout(
    State(st): State<Arc<ApiState>>,
    p: Option<Extension<crate::ActingPrincipal>>,
    Extension(cid): Extension<CorrelationId>,
    Json(req): Json<CatalogRolloutRequest>,
) -> Result<Json<Resource<CatalogRolloutPlanDto>>, ApiErrorResponse> {
    let p = principal(p, cid)?;
    let version = authorize_rollout(&st, &p, cid, &req).await?;
    Ok(Json(Resource::new(rollout_plan(&version, &req))))
}

/// Starts a durable, machine-scoped rollout of one immutable version.
///
/// # Errors
///
/// Returns an API error when authentication, request validation, authorization,
/// auditing, machine lookup, or operation creation fails.
#[utoipa::path(post,path="/skills/catalog/rollouts",tag="skills",operation_id="startSkillCatalogRollout",request_body=CatalogRolloutRequest,params(("Idempotency-Key"=Option<String>,Header,description="Caller-chosen idempotency key; a stable key is derived from the request when omitted.")),responses((status=202,body=Resource<crate::operations::OperationDto>)))]
pub async fn start_catalog_rollout(
    State(st): State<Arc<ApiState>>,
    p: Option<Extension<crate::ActingPrincipal>>,
    Extension(cid): Extension<CorrelationId>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CatalogRolloutRequest>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let p = principal(p, cid)?;
    let version = authorize_rollout(&st, &p, cid, &req).await?;
    let mut agents = req.agents.clone();
    agents.sort();
    let payload=serde_json::json!({"machineId":req.machine_id,"endpointId":req.endpoint_id,"auth":req.auth,"versionId":req.version_id,"catalogId":version.catalog_id,"agents":agents,"timeoutSeconds":req.timeout_seconds}).to_string();
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map_or_else(
            || {
                use sha2::Digest as _;
                let digest = sha2::Sha256::digest(payload.as_bytes());
                format!(
                    "{}:catalog-rollout-{}",
                    p.id,
                    digest.iter().fold(String::with_capacity(64), |mut out, b| {
                        use std::fmt::Write as _;
                        let _ = write!(out, "{b:02x}");
                        out
                    })
                )
            },
            |key| format!("{}:{key}", p.id),
        );
    let new_operation = fleet_application::operation::NewOperation {
        kind: "skills.catalog-rollout".to_owned(),
        idempotency_key: Some(key),
        deadline_at: Some(
            now().saturating_add(
                i64::try_from(req.timeout_seconds)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1000),
            ),
        ),
        correlation_id: Some(cid.to_string()),
        payload_json: Some(payload),
        review_token: None,
    };
    let operation = st
        .operations
        .create(st.authorizer.as_ref(), &p.id, &new_operation)
        .await
        .map_err(|e| crate::operations::map_use_case_error(&e, cid))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(Resource::new(crate::operations::OperationDto::from(
            operation,
        ))),
    ))
}
