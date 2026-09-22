//! The Lab surface: template drafts, immutable versions, and the
//! provisioning records (FM-710).

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use fleet_application::lab::{
    LabTemplate, LabTemplateVersion, LabUseCaseError, NewLabTemplate, ProvisionRecord,
};
use std::str::FromStr as _;

use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};

/// Extracts the Lab use cases from the API state, or answers with the
/// standard envelope when the controller was composed without one.
fn lab_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<fleet_application::lab::Lab>, ApiErrorResponse> {
    state.lab.clone().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "the Lab surface is not wired; the controller needs its database",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// Maps a Lab use-case outcome onto the public error envelope, once.
fn map_lab_error(error: &LabUseCaseError, correlation_id: CorrelationId) -> ApiErrorResponse {
    let (status, code, retry): (StatusCode, &str, RetryClass) = match error {
        LabUseCaseError::Denied(_) => (StatusCode::FORBIDDEN, "denied", RetryClass::Never),
        LabUseCaseError::NotFound { .. } => (StatusCode::NOT_FOUND, "not_found", RetryClass::Never),
        LabUseCaseError::Conflict { .. } => (StatusCode::CONFLICT, "conflict", RetryClass::Never),
        LabUseCaseError::PinRefused { .. } => {
            (StatusCode::CONFLICT, "lab_pin_refused", RetryClass::Never)
        }
        LabUseCaseError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
        ),
        LabUseCaseError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    let message = match error {
        LabUseCaseError::Backend { .. } => {
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

/// One template draft.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LabTemplateDto {
    /// The draft's identity.
    pub id: String,
    /// The template name.
    pub name: String,
    /// The template description.
    pub description: String,
    /// The pinned image version id.
    pub image_version_id: String,
    /// The vCPU count.
    pub cores: u32,
    /// The memory in MiB.
    pub memory_mib: u32,
    /// The disk size in GiB.
    pub disk_gib: u32,
    /// The bootstrap profile reference, when pinned.
    pub bootstrap_project_id: Option<String>,
    /// The readiness probe.
    pub readiness_probe: String,
    /// The SSH probe command, when pinned.
    pub readiness_command: Option<String>,
    /// The readiness deadline in seconds.
    pub readiness_deadline_seconds: u32,
    /// The default TTL in seconds, beginning at ready.
    pub ttl_seconds: u32,
    /// The cleanup strategy.
    pub cleanup: String,
    /// The published version this draft descends from, when any.
    pub published_from: Option<String>,
    /// When the draft was created.
    pub created_at: i64,
    /// When the draft was last edited.
    pub updated_at: i64,
}

impl From<LabTemplate> for LabTemplateDto {
    fn from(template: LabTemplate) -> Self {
        Self {
            id: template.id,
            name: template.content.name,
            description: template.content.description,
            image_version_id: template.content.image_version_id,
            cores: template.content.cores,
            memory_mib: template.content.memory_mib,
            disk_gib: template.content.disk_gib,
            bootstrap_project_id: template.content.bootstrap_project_id,
            readiness_probe: template.content.readiness_probe.id().to_owned(),
            readiness_command: template.content.readiness_command,
            readiness_deadline_seconds: template.content.readiness_deadline_seconds,
            ttl_seconds: template.content.ttl_seconds,
            cleanup: template.content.cleanup.id().to_owned(),
            published_from: template.published_from,
            created_at: template.created_at,
            updated_at: template.updated_at,
        }
    }
}

/// One published template version.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LabTemplateVersionDto {
    /// The version's identity.
    pub id: String,
    /// The template the version came from.
    pub template_id: String,
    /// The template name at publication time.
    pub name: String,
    /// The frozen content.
    pub content: LabTemplateContentDto,
    /// The pinned image version's digest at publication time.
    pub image_digest: String,
    /// Who published the version.
    pub published_by: String,
    /// When the version was published.
    pub published_at: i64,
}

/// The frozen template content.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LabTemplateContentDto {
    /// The template name.
    pub name: String,
    /// The template description.
    pub description: String,
    /// The pinned image version id.
    pub image_version_id: String,
    /// The vCPU count.
    pub cores: u32,
    /// The memory in MiB.
    pub memory_mib: u32,
    /// The disk size in GiB.
    pub disk_gib: u32,
    /// The bootstrap profile reference, when pinned.
    pub bootstrap_project_id: Option<String>,
    /// The readiness probe.
    pub readiness_probe: String,
    /// The SSH probe command, when pinned.
    pub readiness_command: Option<String>,
    /// The readiness deadline in seconds.
    pub readiness_deadline_seconds: u32,
    /// The default TTL in seconds.
    pub ttl_seconds: u32,
    /// The cleanup strategy.
    pub cleanup: String,
}

impl From<LabTemplateVersion> for LabTemplateVersionDto {
    fn from(version: LabTemplateVersion) -> Self {
        Self {
            id: version.id,
            template_id: version.template_id,
            name: version.name,
            content: LabTemplateContentDto {
                name: version.content.name,
                description: version.content.description,
                image_version_id: version.content.image_version_id,
                cores: version.content.cores,
                memory_mib: version.content.memory_mib,
                disk_gib: version.content.disk_gib,
                bootstrap_project_id: version.content.bootstrap_project_id,
                readiness_probe: version.content.readiness_probe.id().to_owned(),
                readiness_command: version.content.readiness_command,
                readiness_deadline_seconds: version.content.readiness_deadline_seconds,
                ttl_seconds: version.content.ttl_seconds,
                cleanup: version.content.cleanup.id().to_owned(),
            },
            image_digest: version.image_digest,
            published_by: version.published_by,
            published_at: version.published_at,
        }
    }
}

/// One provisioning record.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionRecordDto {
    /// The record's identity.
    pub id: String,
    /// The template version the guest was provisioned from.
    pub template_version_id: String,
    /// The guest's current state.
    pub state: String,
    /// The PVE node the guest landed on, once cloned.
    pub node: Option<String>,
    /// The guest's VMID, once cloned.
    pub vmid: Option<u32>,
    /// The guest's IPv4 address, once reported.
    pub guest_ipv4: Option<String>,
    /// The clone task's UPID, while running.
    pub clone_upid: Option<String>,
    /// When the guest reached ready, when it did.
    pub ready_at: Option<i64>,
    /// When the record was created.
    pub created_at: i64,
    /// When the record was last updated.
    pub updated_at: i64,
}

impl From<ProvisionRecord> for ProvisionRecordDto {
    fn from(record: ProvisionRecord) -> Self {
        Self {
            id: record.id,
            template_version_id: record.template_version_id,
            state: record.state.id().to_owned(),
            node: record.node,
            vmid: record.vmid,
            clone_upid: record.clone_upid,
            guest_ipv4: record.guest_ipv4,
            ready_at: record.ready_at,
            created_at: record.created_at,
            updated_at: record.updated_at,
        }
    }
}

/// The create/update request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SaveLabTemplateRequest {
    /// The template name.
    pub name: String,
    /// The template description.
    pub description: String,
    /// The pinned image version id.
    pub image_version_id: String,
    /// The vCPU count.
    pub cores: u32,
    /// The memory in MiB.
    pub memory_mib: u32,
    /// The disk size in GiB.
    pub disk_gib: u32,
    /// The bootstrap profile reference, when pinned.
    pub bootstrap_project_id: Option<String>,
    /// The readiness probe.
    pub readiness_probe: String,
    /// The SSH probe command, when pinned.
    pub readiness_command: Option<String>,
    /// The readiness deadline in seconds.
    pub readiness_deadline_seconds: u32,
    /// The default TTL in seconds.
    pub ttl_seconds: u32,
    /// The cleanup strategy.
    pub cleanup: String,
}

impl SaveLabTemplateRequest {
    fn into_content(
        self,
        correlation_id: CorrelationId,
    ) -> Result<fleet_core::LabTemplateContent, ApiErrorResponse> {
        let probe = fleet_core::ReadinessProbe::from_id(&self.readiness_probe)
            .map_err(|detail| crate::machines::invalid_request(&detail, correlation_id))?;
        let cleanup = fleet_core::CleanupStrategy::from_id(&self.cleanup)
            .map_err(|detail| crate::machines::invalid_request(&detail, correlation_id))?;
        Ok(fleet_core::LabTemplateContent {
            name: self.name,
            description: self.description,
            image_version_id: self.image_version_id,
            cores: self.cores,
            memory_mib: self.memory_mib,
            disk_gib: self.disk_gib,
            bootstrap_project_id: self.bootstrap_project_id,
            readiness_probe: probe,
            readiness_command: self.readiness_command,
            readiness_deadline_seconds: self.readiness_deadline_seconds,
            ttl_seconds: self.ttl_seconds,
            cleanup,
        })
    }
}

/// Lists the template drafts.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/lab/templates",
    tag = "lab",
    operation_id = "listLabTemplates",
    responses(
        (status = 200, description = "The template drafts, newest first.", body = Page<LabTemplateDto>),
        (status = 403, description = "The caller may not read the Lab surface.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn list_lab_templates(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<Page<LabTemplateDto>>, ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let templates = lab
        .list_templates(state.authorizer.as_ref(), &principal)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    let items: Vec<LabTemplateDto> = templates.into_iter().map(Into::into).collect();
    Ok(Json(Page {
        page: PageInfo {
            next_cursor: None,
            limit: items.len().try_into().unwrap_or(u32::MAX),
        },
        items,
    }))
}

/// Creates a template draft.
///
/// # Errors
///
/// Returns the public error envelope on refusal, conflict, refused pin,
/// or malformed request.
#[utoipa::path(
    post,
    path = "/lab/templates",
    tag = "lab",
    operation_id = "createLabTemplate",
    request_body = SaveLabTemplateRequest,
    responses(
        (status = 201, description = "The draft was created.", body = Resource<LabTemplateDto>),
        (status = 400, description = "The request is malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not configure the Lab surface.", body = crate::error::ApiError),
        (status = 409, description = "The name is taken or the image pin was refused.", body = crate::error::ApiError),
    )
)]
pub async fn create_lab_template(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Json(request): Json<SaveLabTemplateRequest>,
) -> Result<(StatusCode, Json<Resource<LabTemplateDto>>), ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let content = request.into_content(correlation_id)?;
    let template = lab
        .create_template(
            state.authorizer.as_ref(),
            &principal,
            NewLabTemplate { content },
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(template.into()))))
}

/// Reads one draft.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown template.
#[utoipa::path(
    get,
    path = "/lab/templates/{templateId}",
    tag = "lab",
    operation_id = "getLabTemplate",
    params(("templateId" = String, Path, description = "The template's identity.")),
    responses(
        (status = 200, description = "The draft.", body = Resource<LabTemplateDto>),
        (status = 404, description = "The template does not exist.", body = crate::error::ApiError),
    )
)]
pub async fn get_lab_template(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(template_id): Path<String>,
) -> Result<Json<Resource<LabTemplateDto>>, ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let template = lab
        .get_template(state.authorizer.as_ref(), &principal, &template_id)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(Json(Resource::new(template.into())))
}

/// Updates a draft.
///
/// # Errors
///
/// Returns the public error envelope on refusal, refused pin, or unknown
/// template.
#[utoipa::path(
    put,
    path = "/lab/templates/{templateId}",
    tag = "lab",
    operation_id = "updateLabTemplate",
    params(("templateId" = String, Path, description = "The template's identity.")),
    request_body = SaveLabTemplateRequest,
    responses(
        (status = 200, description = "The draft was updated.", body = Resource<LabTemplateDto>),
        (status = 400, description = "The request is malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not configure the Lab surface.", body = crate::error::ApiError),
        (status = 404, description = "The template does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The name is taken or the image pin was refused.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn update_lab_template(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(template_id): Path<String>,
    Json(request): Json<SaveLabTemplateRequest>,
) -> Result<Json<Resource<LabTemplateDto>>, ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let content = request.into_content(correlation_id)?;
    let template = lab
        .update_template(
            state.authorizer.as_ref(),
            &principal,
            &template_id,
            content,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(Json(Resource::new(template.into())))
}

/// Removes a draft. Published versions stay.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown template.
#[utoipa::path(
    delete,
    path = "/lab/templates/{templateId}",
    tag = "lab",
    operation_id = "deleteLabTemplate",
    params(("templateId" = String, Path, description = "The template's identity.")),
    responses(
        (status = 204, description = "The draft was removed."),
        (status = 403, description = "The caller may not configure the Lab surface.", body = crate::error::ApiError),
        (status = 404, description = "The template does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn delete_lab_template(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(template_id): Path<String>,
) -> Result<StatusCode, ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    lab.delete_template(state.authorizer.as_ref(), &principal, &template_id)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Publishes a draft: freezes an immutable version with provenance. The
/// pin is re-validated at publish time.
///
/// # Errors
///
/// Returns the public error envelope on refusal, refused pin, or unknown
/// template.
#[utoipa::path(
    post,
    path = "/lab/templates/{templateId}/publish",
    tag = "lab",
    operation_id = "publishLabTemplate",
    params(("templateId" = String, Path, description = "The template's identity.")),
    responses(
        (status = 201, description = "The version was published.", body = Resource<LabTemplateVersionDto>),
        (status = 403, description = "The caller may not configure the Lab surface.", body = crate::error::ApiError),
        (status = 404, description = "The template does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The image pin was refused.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn publish_lab_template(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(template_id): Path<String>,
) -> Result<(StatusCode, Json<Resource<LabTemplateVersionDto>>), ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let version = lab
        .publish_template(
            state.authorizer.as_ref(),
            &principal,
            &template_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(version.into()))))
}

/// Starts provisioning a published template version.
///
/// # Errors
///
/// Returns the public error envelope on refusal, refused pin, or unknown
/// version.
#[utoipa::path(
    post,
    path = "/lab/versions/{versionId}/provision",
    tag = "lab",
    operation_id = "startLabProvision",
    params(("versionId" = String, Path, description = "The template version's identity.")),
    responses(
        (status = 201, description = "The provisioning record was created; the saga runs.", body = Resource<ProvisionRecordDto>),
        (status = 403, description = "The caller may not provision Lab guests.", body = crate::error::ApiError),
        (status = 404, description = "The version does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The image pin was refused.", body = crate::error::ApiError),
    )
)]
pub async fn start_lab_provision(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: axum::http::HeaderMap,
    Path(version_id): Path<String>,
) -> Result<(StatusCode, Json<Resource<ProvisionRecordDto>>), ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // A caller-scoped idempotency key makes a retry return the in-flight
    // record instead of creating a second guest saga.
    let idempotency_key = headers
        .get(crate::IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|key| format!("{}:{key}", principal.id));
    let record = lab
        .start_provision(
            state.authorizer.as_ref(),
            &principal,
            &version_id,
            idempotency_key.as_deref(),
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(record.into()))))
}

/// Lists the provisioning records.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/lab/provisions",
    tag = "lab",
    operation_id = "listLabProvisions",
    responses(
        (status = 200, description = "The provisioning records, newest first.", body = Page<ProvisionRecordDto>),
        (status = 403, description = "The caller may not read the Lab surface.", body = crate::error::ApiError),
    )
)]
pub async fn list_lab_provisions(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<Page<ProvisionRecordDto>>, ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let records = lab
        .list_provisions(state.authorizer.as_ref(), &principal)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    let items: Vec<ProvisionRecordDto> = records.into_iter().map(Into::into).collect();
    Ok(Json(Page {
        page: PageInfo {
            next_cursor: None,
            limit: items.len().try_into().unwrap_or(u32::MAX),
        },
        items,
    }))
}

/// One lease.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LeaseDto {
    /// The lease's identity.
    pub id: String,
    /// The template version the lease was created from.
    pub template_version_id: String,
    /// The owner's principal id.
    pub owner: String,
    /// The purpose the lease records.
    pub purpose: String,
    /// The project the lease is scoped to, when any.
    pub project_id: Option<String>,
    /// The current state.
    pub state: String,
    /// The cleanup strategy.
    pub cleanup: String,
    /// When the lease was created.
    pub created_at: i64,
    /// When the lease reached ready, when it did.
    pub ready_at: Option<i64>,
    /// When the lease's TTL expires, once ready.
    pub expires_at: Option<i64>,
}

impl From<fleet_application::lab::Lease> for LeaseDto {
    fn from(lease: fleet_application::lab::Lease) -> Self {
        Self {
            id: lease.id,
            template_version_id: lease.template_version_id,
            owner: lease.owner,
            purpose: lease.purpose,
            project_id: lease.project_id,
            state: lease.state.id().to_owned(),
            cleanup: lease.cleanup.id().to_owned(),
            created_at: lease.created_at,
            ready_at: lease.ready_at,
            expires_at: lease.expires_at,
        }
    }
}

/// The lease creation request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateLeaseRequest {
    /// The template version to lease from.
    pub template_version_id: String,
    /// The purpose the lease records.
    pub purpose: String,
    /// The project the lease is scoped to, when any.
    pub project_id: Option<String>,
}

/// Creates a lease from a published template version.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown version.
#[utoipa::path(
    post,
    path = "/lab/leases",
    tag = "lab",
    operation_id = "createLabLease",
    request_body = CreateLeaseRequest,
    responses(
        (status = 201, description = "The lease was created.", body = Resource<LeaseDto>),
        (status = 400, description = "The request is malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not lease Lab guests.", body = crate::error::ApiError),
        (status = 404, description = "The version does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn create_lab_lease(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Json(request): Json<CreateLeaseRequest>,
) -> Result<(StatusCode, Json<Resource<LeaseDto>>), ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let lease = lab
        .create_lease(
            state.authorizer.as_ref(),
            &principal,
            fleet_application::lab::NewLease {
                template_version_id: request.template_version_id,
                purpose: request.purpose,
                project_id: request.project_id,
                cleanup: fleet_core::CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(lease.into()))))
}

/// Lists the leases.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/lab/leases",
    tag = "lab",
    operation_id = "listLabLeases",
    responses(
        (status = 200, description = "The leases, newest first.", body = Page<LeaseDto>),
        (status = 403, description = "The caller may not read the Lab surface.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn list_lab_leases(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<Page<LeaseDto>>, ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let leases = lab
        .list_leases(state.authorizer.as_ref(), &principal)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    let items: Vec<LeaseDto> = leases.into_iter().map(Into::into).collect();
    Ok(Json(Page {
        page: PageInfo {
            next_cursor: None,
            limit: items.len().try_into().unwrap_or(u32::MAX),
        },
        items,
    }))
}

/// Releases a lease (or keeps its VM with the elevated permission).
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown lease.
#[utoipa::path(
    post,
    path = "/lab/leases/{leaseId}/release",
    tag = "lab",
    operation_id = "releaseLabLease",
    params(("leaseId" = String, Path, description = "The lease's identity.")),
    request_body = ReleaseLeaseRequest,
    responses(
        (status = 200, description = "The lease entered releasing (or keeping).", body = Resource<LeaseDto>),
        (status = 400, description = "The lease is already terminal.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not release (or keep) the lease.", body = crate::error::ApiError),
        (status = 404, description = "The lease does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn release_lab_lease(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(lease_id): Path<String>,
    Json(request): Json<ReleaseLeaseRequest>,
) -> Result<Json<Resource<LeaseDto>>, ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let lease = lab
        .release_lease(
            state.authorizer.as_ref(),
            &principal,
            &lease_id,
            request.keep,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(Json(Resource::new(lease.into())))
}

/// The release request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseLeaseRequest {
    /// Whether to keep the VM out of automatic cleanup (elevated).
    #[serde(default)]
    pub keep: bool,
}

/// Runs the expiry sweeper: every lease whose TTL has expired moves into
/// releasing. The controller's background sweeper calls this on its tick;
/// exposing it lets an operator sweep manually.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    post,
    path = "/lab/leases/sweep",
    tag = "lab",
    operation_id = "sweepLabLeases",
    responses(
        (status = 200, description = "The leases transitioned into releasing.", body = Page<LeaseDto>),
        (status = 403, description = "The caller may not lease Lab guests.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn sweep_lab_leases(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<Page<LeaseDto>>, ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let released = lab
        .sweep_expired(
            state.authorizer.as_ref(),
            &principal,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    let items: Vec<LeaseDto> = released.into_iter().map(Into::into).collect();
    Ok(Json(Page {
        page: PageInfo {
            next_cursor: None,
            limit: items.len().try_into().unwrap_or(u32::MAX),
        },
        items,
    }))
}
