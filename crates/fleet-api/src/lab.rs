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
pub(crate) fn lab_or_error(
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
pub(crate) fn map_lab_error(
    error: &LabUseCaseError,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
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
    /// The SSH account preconfigured in the image.
    pub ssh_user: String,
    /// The guest SSH listener port.
    pub ssh_port: u16,
    /// Host-key trust: tofu or pinned.
    pub ssh_trust_mode: String,
    /// Public OpenSSH SHA256 fingerprint for pinned trust.
    pub ssh_fingerprint: Option<String>,
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
            ssh_user: template.content.ssh_user,
            ssh_port: template.content.ssh_port,
            ssh_trust_mode: template.content.ssh_trust_mode,
            ssh_fingerprint: template.content.ssh_fingerprint,
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
    /// The SSH account preconfigured in the image.
    pub ssh_user: String,
    /// The guest SSH listener port.
    pub ssh_port: u16,
    /// Host-key trust: tofu or pinned.
    pub ssh_trust_mode: String,
    /// Public OpenSSH SHA256 fingerprint for pinned trust.
    pub ssh_fingerprint: Option<String>,
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
                ssh_user: version.content.ssh_user,
                ssh_port: version.content.ssh_port,
                ssh_trust_mode: version.content.ssh_trust_mode,
                ssh_fingerprint: version.content.ssh_fingerprint,
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
    /// The SSH account preconfigured in the image.
    #[serde(default = "default_lab_ssh_user")]
    pub ssh_user: String,
    /// The guest SSH listener port.
    #[serde(default = "default_lab_ssh_port")]
    pub ssh_port: u16,
    /// Host-key trust: tofu or pinned.
    #[serde(default = "default_lab_ssh_trust_mode")]
    pub ssh_trust_mode: String,
    /// Public OpenSSH SHA256 fingerprint for pinned trust.
    #[serde(default)]
    pub ssh_fingerprint: Option<String>,
    /// The readiness deadline in seconds.
    pub readiness_deadline_seconds: u32,
    /// The default TTL in seconds.
    pub ttl_seconds: u32,
    /// The cleanup strategy.
    pub cleanup: String,
}

fn default_lab_ssh_user() -> String {
    fleet_core::LabTemplateContent::default().ssh_user
}
fn default_lab_ssh_port() -> u16 {
    fleet_core::LabTemplateContent::default().ssh_port
}
fn default_lab_ssh_trust_mode() -> String {
    fleet_core::LabTemplateContent::default().ssh_trust_mode
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
            ssh_user: self.ssh_user,
            ssh_port: self.ssh_port,
            ssh_trust_mode: self.ssh_trust_mode,
            ssh_fingerprint: self.ssh_fingerprint,
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
            None,
            idempotency_key.as_deref(),
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(record.into()))))
}

/// How to provision a lease: through an explicit Proxmox account, or through
/// the one placement selects.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartLeaseProvisionRequest {
    /// The identity of the explicitly configured Proxmox account. When
    /// omitted, placement selects the one trusted account whose cluster
    /// holds the pinned image's template; none or several fail the
    /// provision operation with an explanation.
    #[serde(default)]
    pub account_id: Option<String>,
}

/// Starts provisioning the requested lease and queues its durable operation.
///
/// # Errors
///
/// Returns the standard error envelope when the lease cannot be provisioned,
/// the operation is denied, or a backend fails.
#[utoipa::path(
    post,
    path = "/lab/leases/{leaseId}/provision",
    tag = "lab",
    operation_id = "startLabLeaseProvision",
    params(("leaseId" = String, Path, description = "The requested lease's identity.")),
    request_body = StartLeaseProvisionRequest,
    responses(
        (status = 201, description = "The lease provision operation was queued.", body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The lease or request cannot be provisioned.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not provision this lease or create operations.", body = crate::error::ApiError),
        (status = 404, description = "The lease does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The lease already moved through a different lifecycle transition.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn start_lab_lease_provision(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(lease_id): Path<String>,
    Json(request): Json<StartLeaseProvisionRequest>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    if request
        .account_id
        .as_deref()
        .is_some_and(|account_id| account_id.trim().is_empty())
    {
        return Err(map_lab_error(
            &LabUseCaseError::Invalid {
                detail: "accountId must not be empty".to_owned(),
            },
            correlation_id,
        ));
    }
    fleet_application::authz::authorize(
        state.authorizer.as_ref(),
        fleet_application::authz::AccessRequest {
            principal_id: &principal.id,
            action: fleet_application::authz::Permission::OperationCreate,
            resource: None,
        },
    )
    .map_err(|decision| {
        crate::operations::map_use_case_error(
            &fleet_application::operation::OperationUseCaseError::Denied(decision),
            correlation_id,
        )
    })?;
    let (provision, lease_changed) = lab
        .start_lease_provision(
            state.authorizer.as_ref(),
            &principal,
            &lease_id,
            None,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    if lease_changed {
        state
            .events
            .publish(fleet_application::events::EventKind::LeaseChanged);
    }
    let mut payload = serde_json::json!({
        "recordId": provision.id,
        "leaseId": lease_id,
    });
    if let Some(account_id) = &request.account_id {
        payload["accountId"] = serde_json::Value::String(account_id.clone());
    }
    let payload = payload.to_string();
    let operation = state
        .operations
        .create_lab_provision(
            state.authorizer.as_ref(),
            &principal.id,
            &lease_id,
            &fleet_application::operation::NewOperation {
                kind: "lab.provision".to_owned(),
                idempotency_key: Some(format!("{}:lab-lease-provision:{lease_id}", principal.id)),
                deadline_at: None,
                correlation_id: Some(correlation_id.to_string()),
                payload_json: Some(payload),
                review_token: None,
            },
        )
        .await
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(operation.into()))))
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
    /// The template's ready TTL, in seconds.
    pub ttl_seconds: u32,
    /// Absolute lifetime deadline measured from creation.
    pub max_lifetime_at: i64,
    /// When the lease reached ready, when it did.
    pub ready_at: Option<i64>,
    /// When the lease's TTL expires, once ready.
    pub expires_at: Option<i64>,
    /// Failed cleanup attempts so far (FM-713).
    pub cleanup_attempts: u32,
    /// When the next cleanup attempt is due (epoch millis), while a
    /// releasing lease backs off after a failed attempt.
    pub cleanup_next_at: Option<i64>,
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
            ttl_seconds: lease.ttl_seconds,
            max_lifetime_at: lease.max_lifetime_at,
            ready_at: lease.ready_at,
            expires_at: lease.expires_at,
            cleanup_attempts: lease.cleanup_attempts,
            cleanup_next_at: lease.cleanup_next_at,
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
    state
        .events
        .publish(fleet_application::events::EventKind::LeaseChanged);
    Ok((StatusCode::CREATED, Json(Resource::new(lease.into()))))
}

/// The list-leases query parameters.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListLeasesParams {
    /// Only leases serving this project.
    pub project_id: Option<String>,
}

/// Lists the leases, narrowed by the project when given.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/lab/leases",
    tag = "lab",
    operation_id = "listLabLeases",
    params(("projectId" = Option<String>, Query, description = "Only leases serving this project.")),
    responses(
        (status = 200, description = "The leases, newest first.", body = Page<LeaseDto>),
        (status = 400, description = "The query parameters are malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not read the Lab surface.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn list_lab_leases(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    params: Result<
        axum::extract::Query<ListLeasesParams>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<Page<LeaseDto>>, ApiErrorResponse> {
    let params = params.map_err(|rejection| {
        crate::machines::invalid_request(
            &format!("the leases list query is malformed: {rejection}"),
            correlation_id,
        )
    })?;
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let leases = lab
        .list_leases(
            state.authorizer.as_ref(),
            &principal,
            params.project_id.as_deref(),
        )
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
        (status = 200, description = "The lease entered releasing (or keeping), and its `lab.cleanup` operation is queued: it destroys the guest (or keeps it) and completes the release, or leaves the lease `cleanup_failed` after its retries.", body = Resource<LeaseDto>),
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
    // The release owes a cleanup: refuse before the lease changes if the
    // caller could not queue it.
    state
        .operations
        .authorize_lab_cleanup(state.authorizer.as_ref(), &principal.id, Some(&lease_id))
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
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
    state
        .events
        .publish(fleet_application::events::EventKind::LeaseChanged);
    queue_cleanup(&state, &principal.id, &lease, correlation_id).await?;
    Ok(Json(Resource::new(lease.into())))
}

/// Queues the `lab.cleanup` operation for a releasing lease (FM-713). The
/// key names the cleanup attempt, so repeating a release never queues a
/// second cleanup for the same attempt. A lease backing off after a failed
/// attempt is not queued before its `cleanupNextAt`: the sweeper (FM-716)
/// queues the retry when it is due, so repeated releases cannot burn the
/// attempts. Answers the queued (or re-found) operation, or nothing when
/// the attempt is not due yet.
async fn queue_cleanup(
    state: &crate::operations::ApiState,
    principal_id: &str,
    lease: &fleet_core::Lease,
    correlation_id: CorrelationId,
) -> Result<Option<fleet_application::operation::Operation>, ApiErrorResponse> {
    if !fleet_application::lab::cleanup_due(lease, fleet_core::SystemClock::now_unix_millis()) {
        return Ok(None);
    }
    state
        .operations
        .create_lab_cleanup(
            state.authorizer.as_ref(),
            principal_id,
            &lease.id,
            &fleet_application::lab::cleanup_operation(lease, Some(correlation_id.to_string())),
        )
        .await
        .map(Some)
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))
}

/// Re-arms the cleanup of a `cleanup_failed` lease once its cause is fixed
/// (#292) and queues the next `lab.cleanup` attempt.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown lease, a lease
/// that is not `cleanup_failed`, or a concurrent re-arm.
#[utoipa::path(
    post,
    path = "/lab/leases/{leaseId}/cleanup/retry",
    tag = "lab",
    operation_id = "retryLabLeaseCleanup",
    params(("leaseId" = String, Path, description = "The lease's identity.")),
    responses(
        (status = 202, description = "The lease is `releasing` again with a fresh round of cleanup attempts (its `cleanupAttempts` total is kept), and its next `lab.cleanup` operation is queued. A guest that is already gone counts as destroyed, so a guest removed by hand resolves the lease to `released`.", body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The lease is not `cleanup_failed`.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not release the lease or queue its cleanup.", body = crate::error::ApiError),
        (status = 404, description = "The lease does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The lease changed while its cleanup was being re-armed.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn retry_lab_lease_cleanup(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(lease_id): Path<String>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // The re-arm owes a cleanup: refuse before the lease changes if the
    // caller could not queue it.
    state
        .operations
        .authorize_lab_cleanup(state.authorizer.as_ref(), &principal.id, Some(&lease_id))
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
    let lease = lab
        .retry_cleanup(state.authorizer.as_ref(), &principal, &lease_id)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    state
        .events
        .publish(fleet_application::events::EventKind::LeaseChanged);
    // A re-armed lease is due at once, so the attempt is always queued.
    let operation = queue_cleanup(&state, &principal.id, &lease, correlation_id)
        .await?
        .ok_or_else(|| {
            map_lab_error(
                &LabUseCaseError::Backend {
                    context: "cleanup",
                    detail: "the re-armed lease was not due".to_owned(),
                },
                correlation_id,
            )
        })?;
    Ok((StatusCode::ACCEPTED, Json(Resource::new(operation.into()))))
}

/// The release request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseLeaseRequest {
    /// Whether to keep the VM out of automatic cleanup (elevated).
    #[serde(default)]
    pub keep: bool,
}

/// The requested ready-TTL extension.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExtendLeaseRequest {
    /// Seconds to add to the lease's existing expiry.
    pub by_seconds: u32,
}

/// Extends the expiry of a ready lease within its absolute lifetime cap.
///
/// # Errors
///
/// Returns the standard error envelope for denial, an invalid or expired
/// lease, a concurrent change, or backend failure.
#[utoipa::path(
    post,
    path = "/lab/leases/{leaseId}/extend",
    tag = "lab",
    operation_id = "extendLabLease",
    params(("leaseId" = String, Path, description = "The lease's identity.")),
    request_body = ExtendLeaseRequest,
    responses(
        (status = 200, description = "The lease expiry was extended.", body = Resource<LeaseDto>),
        (status = 400, description = "The lease is not ready, is expired, or would exceed its maximum lifetime.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not extend the lease.", body = crate::error::ApiError),
        (status = 404, description = "The lease does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The lease changed while the extension was being applied.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn extend_lab_lease(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(lease_id): Path<String>,
    request: Result<Json<ExtendLeaseRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Resource<LeaseDto>>, ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        map_lab_error(
            &LabUseCaseError::Invalid {
                detail: "the request body must be valid JSON for a lease extension".to_owned(),
            },
            correlation_id,
        )
    })?;
    let lease = lab
        .extend_lease(
            state.authorizer.as_ref(),
            &principal,
            &lease_id,
            request.by_seconds,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    state
        .events
        .publish(fleet_application::events::EventKind::LeaseChanged);
    Ok(Json(Resource::new(lease.into())))
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
        (status = 200, description = "All expired leases transitioned into releasing, each with its `lab.cleanup` operation queued. Claims commit and emit lease.changed immediately; if a later claim fails, earlier transitions remain committed and the handler returns 500. Retrying safely continues with leases that remain expired.", body = Page<LeaseDto>),
        (status = 403, description = "The caller may not lease Lab guests.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed. Earlier claims in this sweep may already be committed; retry to process the remaining expired leases.", body = crate::error::ApiError),
    )
)]
pub async fn sweep_lab_leases(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<Page<LeaseDto>>, ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    state
        .operations
        .authorize_lab_cleanup(state.authorizer.as_ref(), &principal.id, None)
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
    let released = lab
        .sweep_expired_with_progress(
            state.authorizer.as_ref(),
            &principal,
            fleet_core::SystemClock::now_unix_millis(),
            || {
                state
                    .events
                    .publish(fleet_application::events::EventKind::LeaseChanged);
            },
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    for lease in &released {
        queue_cleanup(&state, &principal.id, lease, correlation_id).await?;
    }
    let items: Vec<LeaseDto> = released.into_iter().map(Into::into).collect();
    Ok(Json(Page {
        page: PageInfo {
            next_cursor: None,
            limit: items.len().try_into().unwrap_or(u32::MAX),
        },
        items,
    }))
}

/// One lease with its guest's connection details (FM-720).
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LeaseDetailDto {
    /// The lease.
    #[serde(flatten)]
    pub lease: LeaseDto,
    /// The guest's provision state, once provisioning started.
    pub provision_state: Option<String>,
    /// The PVE node the guest runs on.
    pub node: Option<String>,
    /// The guest's VMID.
    pub vmid: Option<u32>,
    /// The guest's IPv4 address, once its agent reported one.
    pub address: Option<String>,
    /// The Lab-owned Fleet machine the guest was registered as.
    pub machine_id: Option<String>,
    /// That machine's SSH endpoint.
    pub endpoint_id: Option<String>,
    /// The saga step that failed, when provisioning failed.
    pub failed_step: Option<String>,
    /// The lease's last failed artifact collection, when any (FM-721).
    /// Collection never changes the lease or holds up its cleanup.
    pub collection_failure: Option<crate::lab_artifacts::CollectionFailureDto>,
    /// The capacity Fleet reserved for the lease (FM-715), when it has one.
    /// Null for a lease that reserved nothing, such as a pooled lease.
    pub reservation: Option<LeaseReservationDto>,
}

/// A lease's capacity reservation: what it holds on a node.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LeaseReservationDto {
    /// The PVE node the capacity is reserved on.
    pub node: String,
    /// The Proxmox account the guest is cloned through.
    pub account_id: String,
    /// The storage pool the disk is allocated on.
    pub storage_pool: String,
    /// Reserved vCPU cores.
    pub cores: u32,
    /// Reserved memory, in bytes.
    pub memory_bytes: u64,
    /// Reserved disk, in bytes.
    pub disk_bytes: u64,
    /// The reservation record's state: `held` until it is released.
    pub state: String,
}

impl From<fleet_application::lab_placement::CapacityReservation> for LeaseReservationDto {
    fn from(reservation: fleet_application::lab_placement::CapacityReservation) -> Self {
        use fleet_application::lab_placement::ReservationState;
        let demand = reservation.demand;
        Self {
            node: reservation.node,
            account_id: reservation.account_id,
            storage_pool: demand.storage,
            cores: demand.cores,
            memory_bytes: u64::from(demand.memory_mib) * 1024 * 1024,
            disk_bytes: u64::from(demand.disk_gib) * 1024 * 1024 * 1024,
            state: match reservation.state {
                ReservationState::Held => "held",
                ReservationState::Released => "released",
            }
            .to_owned(),
        }
    }
}

/// Reads one lease with its guest's connection details.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown lease.
#[utoipa::path(
    get,
    path = "/lab/leases/{leaseId}",
    tag = "lab",
    operation_id = "getLabLease",
    params(("leaseId" = String, Path, description = "The lease's identity.")),
    responses(
        (status = 200, description = "The lease and, once provisioned, its guest.", body = Resource<LeaseDetailDto>),
        (status = 403, description = "The caller may not read Lab leases.", body = crate::error::ApiError),
        (status = 404, description = "The lease does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn get_lab_lease(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(lease_id): Path<String>,
) -> Result<Json<Resource<LeaseDetailDto>>, ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let lease = lab
        .get_lease(state.authorizer.as_ref(), &principal, &lease_id)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    let record = match &lease.provision_id {
        Some(id) => Some(
            lab.get_provision(state.authorizer.as_ref(), &principal, id)
                .await
                .map_err(|error| map_lab_error(&error, correlation_id))?,
        ),
        None => None,
    };
    let collection_failure = crate::lab_artifacts::lease_collection_failure(
        &state,
        &principal,
        &lease_id,
        correlation_id,
    )
    .await?;
    let reservation = lab
        .lease_reservation(state.authorizer.as_ref(), &principal, &lease_id)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?
        .map(Into::into);
    Ok(Json(Resource::new(LeaseDetailDto {
        lease: lease.into(),
        provision_state: record.as_ref().map(|record| record.state.id().to_owned()),
        node: record.as_ref().and_then(|record| record.node.clone()),
        vmid: record.as_ref().and_then(|record| record.vmid),
        address: record.as_ref().and_then(|record| record.guest_ipv4.clone()),
        machine_id: record.as_ref().and_then(|record| record.machine_id.clone()),
        endpoint_id: record
            .as_ref()
            .and_then(|record| record.endpoint_id.clone()),
        failed_step: record.and_then(|record| record.failed_step),
        collection_failure,
        reservation,
    })))
}

/// A command to run on a ready lease's guest.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExecLeaseRequest {
    /// The shell script to run (at most 64 KiB). It is never audited.
    pub script: String,
    /// The deadline, in seconds (1–900; default 60).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

/// Runs a command on a ready lease's guest as a `lab.exec` operation. The
/// result carries the exit code and stdout and stderr, each scrubbed of
/// credentials (URL userinfo and `user:password@`) and bounded, as machine
/// exec does. A truncated flag is true when output was dropped, whether by
/// the transport or by the result bound.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown lease, a lease
/// that is not ready, or an invalid command.
#[utoipa::path(
    post,
    path = "/lab/leases/{leaseId}/exec",
    tag = "lab",
    operation_id = "execLabLease",
    params(("leaseId" = String, Path, description = "The lease's identity.")),
    request_body = ExecLeaseRequest,
    responses(
        (status = 202, description = "The command is queued as a `lab.exec` operation.", body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The lease is not ready or has expired, its guest has no Lab machine, or the command is invalid.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not run commands on Lab leases.", body = crate::error::ApiError),
        (status = 404, description = "The lease does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn exec_lab_lease(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(lease_id): Path<String>,
    headers: axum::http::HeaderMap,
    request: Result<Json<ExecLeaseRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let lab = lab_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        map_lab_error(
            &LabUseCaseError::Invalid {
                detail: "the request body must be valid JSON with a script".to_owned(),
            },
            correlation_id,
        )
    })?;
    let mut new = lab
        .exec_lease(
            state.authorizer.as_ref(),
            &principal,
            &lease_id,
            &request.script,
            request.timeout_seconds.unwrap_or(60),
            // A retried request with the same key returns the original
            // command operation instead of running the script again.
            headers
                .get(crate::IDEMPOTENCY_KEY_HEADER)
                .and_then(|value| value.to_str().ok()),
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    new.correlation_id = Some(correlation_id.to_string());
    let operation = state
        .operations
        .create_lab_exec(state.authorizer.as_ref(), &principal.id, &lease_id, &new)
        .await
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
    Ok((StatusCode::ACCEPTED, Json(Resource::new(operation.into()))))
}

#[cfg(test)]
mod template_mapping_tests {
    use super::*;
    use fleet_core::IdGenerator as _;

    #[test]
    fn template_ssh_settings_default_and_round_trip() {
        let base = serde_json::json!({
            "name":"lab", "description":"", "imageVersionId":"image-1", "cores":2,
            "memoryMib":2048, "diskGib":20, "readinessProbe":"guest_agent",
            "readinessDeadlineSeconds":120, "ttlSeconds":3600, "cleanup":"destroy"
        });
        let request: SaveLabTemplateRequest = serde_json::from_value(base.clone()).unwrap();
        assert_eq!(
            (
                request.ssh_user.as_str(),
                request.ssh_port,
                request.ssh_trust_mode.as_str()
            ),
            ("root", 22, "tofu")
        );
        let mut configured = base;
        configured["sshUser"] = serde_json::json!("developer");
        configured["sshPort"] = serde_json::json!(2222);
        configured["sshTrustMode"] = serde_json::json!("pinned");
        configured["sshFingerprint"] =
            serde_json::json!("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let request: SaveLabTemplateRequest = serde_json::from_value(configured).unwrap();
        let content = request
            .into_content(fleet_core::UuidV7Generator.next_correlation_id())
            .unwrap();
        let dto = LabTemplateVersionDto::from(LabTemplateVersion {
            id: "version".to_owned(),
            template_id: "template".to_owned(),
            name: "lab".to_owned(),
            content,
            image_digest: "digest".to_owned(),
            published_by: "tester".to_owned(),
            published_at: 0,
        })
        .content;
        assert_eq!(dto.ssh_user, "developer");
        assert_eq!(dto.ssh_port, 2222);
        assert_eq!(dto.ssh_trust_mode, "pinned");
        assert_eq!(
            dto.ssh_fingerprint.as_deref(),
            Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
    }
}
