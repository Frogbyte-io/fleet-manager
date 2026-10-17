//! Site templates (FM-1035): deploy a new site on Coolify from a preset.
//!
//! `GET /site-templates` lists the built-in templates (id, version, digest,
//! what each creates, default variables, the variables a person still sets).
//! `POST /site-deployments` files the `coolify.site.deploy` action request
//! (risk class `approve`): the answer is the action request, followed at
//! `/requests/{id}` and, once approved, at `/operations/{id}`, whose result
//! names the created resource and every step. This adapter decides nothing:
//! the template, the target, and the domain checks are the use case's.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{Extension, Json, extract::State, http::StatusCode};
use fleet_application::site_templates::{
    DeployRequest, SiteTemplate, SiteTemplates, TemplateSource,
};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::{ApiError, ApiErrorResponse};
use crate::services::{invalid, map_lifecycle_error};

/// What a template creates.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SiteTemplateSourceDto {
    /// `service` (a Coolify one-click service) or `git` (a public Git
    /// repository built by Coolify).
    pub kind: String,
    /// The one-click service type (`service` templates).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    /// The build pack (`git` templates).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_pack: Option<String>,
    /// The port the application listens on (`git` templates).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports_exposes: Option<u16>,
}

/// A default variable of a template: a non-secret literal.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SiteTemplateEnvDto {
    /// The variable's name.
    pub key: String,
    /// The default value.
    pub value: String,
}

/// One site template.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SiteTemplateDto {
    /// The stable id.
    pub id: String,
    /// The definition's version.
    pub version: u32,
    /// The SHA-256 that pins the definition; a request carries it.
    pub digest: String,
    /// A short display name.
    pub name: String,
    /// What the template makes.
    pub description: String,
    /// What it creates.
    pub source: SiteTemplateSourceDto,
    /// Whether a deploy needs a public repository and a branch.
    pub needs_repository: bool,
    /// Default environment values written after creation.
    pub default_env: Vec<SiteTemplateEnvDto>,
    /// Variables to set after the deploy, by name only.
    pub follow_up_env_keys: Vec<String>,
}

impl From<&SiteTemplate> for SiteTemplateDto {
    fn from(template: &SiteTemplate) -> Self {
        let source = match &template.source {
            TemplateSource::Service { service_type, .. } => SiteTemplateSourceDto {
                kind: "service".to_owned(),
                service_type: Some(service_type.clone()),
                build_pack: None,
                ports_exposes: None,
            },
            TemplateSource::Git {
                build_pack,
                ports_exposes,
                ..
            } => SiteTemplateSourceDto {
                kind: "git".to_owned(),
                service_type: None,
                build_pack: Some(build_pack.clone()),
                ports_exposes: Some(*ports_exposes),
            },
        };
        Self {
            id: template.id.clone(),
            version: template.version,
            digest: template.digest(),
            name: template.name.clone(),
            description: template.description.clone(),
            source,
            needs_repository: template.needs_repository(),
            default_env: template
                .default_env
                .iter()
                .map(|env| SiteTemplateEnvDto {
                    key: env.key.clone(),
                    value: env.value.clone(),
                })
                .collect(),
            follow_up_env_keys: template.follow_up_env_keys.clone(),
        }
    }
}

/// The site templates.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SiteTemplatesDto {
    /// The built-in templates.
    pub templates: Vec<SiteTemplateDto>,
}

/// The body of a deploy request.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SiteDeployBody {
    /// The Fleet Coolify account id.
    pub account_id: String,
    /// The template id.
    pub template_id: String,
    /// The target server's Coolify uuid, or its exact name when unambiguous.
    pub server_uuid: String,
    /// The target project's Coolify uuid, or its exact name when unambiguous.
    pub project_uuid: String,
    /// The environment name within the project.
    pub environment_name: String,
    /// The destination uuid, when the server has several.
    #[serde(default)]
    pub destination_uuid: Option<String>,
    /// The site's domain: a host name or an `https://` URL.
    pub domain: String,
    /// The resource name; derived from the domain when absent.
    #[serde(default)]
    pub name: Option<String>,
    /// The public repository URL (templates that deploy a repository).
    #[serde(default)]
    pub repository: Option<String>,
    /// The branch (templates that deploy a repository).
    #[serde(default)]
    pub branch: Option<String>,
    /// Why, for the approver (at most 1000 characters).
    #[serde(default)]
    pub reason: String,
    /// A key making a retry return the request already made (scoped to the
    /// caller).
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

fn sites_or_error(
    extension: Option<Extension<Arc<SiteTemplates>>>,
    correlation_id: CorrelationId,
) -> Result<Arc<SiteTemplates>, ApiErrorResponse> {
    extension.map(|Extension(sites)| sites).ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("services_unavailable").expect("valid error code"),
            "the site-template surface is not wired; the controller needs its database and secret store",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// Lists the built-in site templates. Needs `external_account.read`.
///
/// # Errors
///
/// Returns the public error envelope on refusal or when the surface is not
/// wired.
#[utoipa::path(
    get,
    path = "/site-templates",
    tag = "services",
    operation_id = "listSiteTemplates",
    responses(
        (status = 200, description = "The built-in templates, each pinned by version and digest.", body = Resource<SiteTemplatesDto>),
        (status = 403, description = "The caller may not do this.", body = ApiError),
        (status = 503, description = "The surface is not wired.", body = ApiError),
    )
)]
pub async fn list_site_templates(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    sites: Option<Extension<Arc<SiteTemplates>>>,
) -> Result<Json<Resource<SiteTemplatesDto>>, ApiErrorResponse> {
    let _sites = sites_or_error(sites, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let templates = SiteTemplates::templates(state.authorizer.as_ref(), &principal)
        .map_err(|error| map_lifecycle_error(&error, correlation_id))?;
    Ok(Json(Resource::new(SiteTemplatesDto {
        templates: templates.iter().map(SiteTemplateDto::from).collect(),
    })))
}

/// Files a request to deploy a new site from a template: it creates the
/// Coolify resource, sets the domain, and starts the first deployment. The
/// server, project, and environment must be in the account's latest Coolify
/// observation and the domain must not already be routed there. The request
/// is `approve` class (it waits for a person unless policy says otherwise);
/// the answer is the action request. Follow it at `/requests/{id}` and its
/// operation at `/operations/{id}`: the result names the created uuid and
/// every step, and a deployment that stopped after creating the resource is a
/// failed operation whose result still carries them.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown template,
/// account, or target, a domain already in use, or a broker refusal.
#[utoipa::path(
    post,
    path = "/site-deployments",
    tag = "services",
    operation_id = "requestSiteDeployment",
    request_body = SiteDeployBody,
    responses(
        (status = 201, description = "The action request was recorded; its state shows what policy did.", body = Resource<crate::requests::ActionRequestDto>),
        (status = 400, description = "A field is invalid, or the domain is already routed.", body = ApiError),
        (status = 403, description = "The caller may not do this, or policy denies the action.", body = ApiError),
        (status = 404, description = "No such account, server, project, or environment in the latest observation.", body = ApiError),
        (status = 409, description = "The idempotency key was already used for a different request.", body = ApiError),
        (status = 503, description = "The surface is not wired.", body = ApiError),
    )
)]
pub async fn request_site_deployment(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    sites: Option<Extension<Arc<SiteTemplates>>>,
    body: Result<Json<SiteDeployBody>, axum::extract::rejection::JsonRejection>,
) -> Result<
    (
        StatusCode,
        Json<Resource<crate::requests::ActionRequestDto>>,
    ),
    ApiErrorResponse,
> {
    let sites = sites_or_error(sites, correlation_id)?;
    let broker = crate::requests::broker_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(body) = body.map_err(|_| {
        invalid(
            "the request body must be JSON: accountId, templateId, serverUuid, projectUuid, environmentName, domain, and optional destinationUuid, name, repository, branch, reason, idempotencyKey",
            correlation_id,
        )
    })?;
    let reason = if body.reason.trim().is_empty() {
        format!("deploy {} at {}", body.template_id, body.domain)
    } else {
        body.reason
    };
    let created = sites
        .request_deploy(
            &broker,
            state.authorizer.as_ref(),
            &principal,
            DeployRequest {
                account_id: body.account_id,
                template_id: body.template_id,
                server_uuid: body.server_uuid,
                project_uuid: body.project_uuid,
                environment_name: body.environment_name,
                destination_uuid: body.destination_uuid,
                domain: body.domain,
                name: body.name,
                repository: body.repository,
                branch: body.branch,
                reason,
                origin: "api".to_owned(),
                correlation_id: Some(correlation_id.to_string()),
                idempotency_key: body.idempotency_key,
            },
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lifecycle_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(created.into()))))
}
