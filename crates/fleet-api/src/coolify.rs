//! The Coolify discovery surface (FM-1030): run a read-only discovery of a
//! Coolify account and read the cached, stamped, stale-aware snapshot.
//!
//! This adapter decides nothing: authorization, audit, and the folding of
//! runs into snapshots live in the application's `CoolifyDiscovery`. The
//! use case arrives as a request extension set by the controller, like the
//! external accounts surface it extends.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use fleet_application::coolify::{
    ClassFailure, ClassObservation, CoolifyApplication, CoolifyDatabase, CoolifyDeployment,
    CoolifyDiscovery, CoolifyEnvironment, CoolifyObservation, CoolifyProject, CoolifyServer,
    CoolifyService,
};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::Serialize;
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::{ApiError, ApiErrorResponse};

/// A classified, credential-free failure of one resource class.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyFailureDto {
    /// `unauthorized`, `insufficient_permission`, `not_found`,
    /// `unreachable`, `timeout`, `rate_limited`, or `invalid_response`.
    pub kind: String,
    /// A short explanation; never a token, URL, or response body.
    pub detail: String,
}

impl From<&ClassFailure> for CoolifyFailureDto {
    fn from(failure: &ClassFailure) -> Self {
        Self {
            kind: failure.kind.id().to_owned(),
            detail: failure.detail.clone(),
        }
    }
}

/// The observation state of one resource class.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyClassDto {
    /// `servers`, `projects`, `applications`, `services`, `databases`, or
    /// `deployments`.
    pub class: String,
    /// How many items the snapshot holds for the class.
    pub item_count: usize,
    /// When the latest attempt ran (epoch millis).
    pub attempted_at: i64,
    /// When the items were last listed successfully; absent when never.
    pub observed_at: Option<i64>,
    /// Whether the items are stale: the latest attempt failed, the class was
    /// never listed, or the last success is old.
    pub stale: bool,
    /// Why the latest attempt failed; the previous items are kept.
    pub failure: Option<CoolifyFailureDto>,
    /// Why the latest attempt was only partial.
    pub partial: Vec<CoolifyFailureDto>,
    /// Whether the stored items were cut to fit the snapshot size bound.
    pub truncated: bool,
}

/// A Coolify server.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyServerDto {
    /// Coolify's identity.
    pub uuid: String,
    /// The name.
    pub name: String,
    /// The description.
    pub description: String,
    /// The address Coolify connects to.
    pub address: String,
    /// The proxy kind, when set.
    pub proxy_type: Option<String>,
    /// Whether Coolify considers it reachable.
    pub reachable: Option<bool>,
    /// Whether Coolify considers it usable.
    pub usable: Option<bool>,
}

impl From<CoolifyServer> for CoolifyServerDto {
    fn from(item: CoolifyServer) -> Self {
        Self {
            uuid: item.uuid,
            name: item.name,
            description: item.description,
            address: item.address,
            proxy_type: item.proxy_type,
            reachable: item.reachable,
            usable: item.usable,
        }
    }
}

/// An environment of a project.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyEnvironmentDto {
    /// Coolify's numeric environment id.
    pub id: i64,
    /// The name.
    pub name: String,
    /// The description.
    pub description: String,
}

impl From<CoolifyEnvironment> for CoolifyEnvironmentDto {
    fn from(item: CoolifyEnvironment) -> Self {
        Self {
            id: item.id,
            name: item.name,
            description: item.description,
        }
    }
}

/// A project with its environments.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyProjectDto {
    /// Coolify's identity.
    pub uuid: String,
    /// The name.
    pub name: String,
    /// The description.
    pub description: String,
    /// The environments; carried from the previous run when `detailsStale`.
    pub environments: Vec<CoolifyEnvironmentDto>,
    /// Whether the environments could not be refreshed by the latest run.
    pub details_stale: bool,
}

impl From<CoolifyProject> for CoolifyProjectDto {
    fn from(item: CoolifyProject) -> Self {
        Self {
            uuid: item.uuid,
            name: item.name,
            description: item.description,
            environments: item.environments.into_iter().map(Into::into).collect(),
            details_stale: item.details_stale,
        }
    }
}

/// A deployed application.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyApplicationDto {
    /// Coolify's identity.
    pub uuid: String,
    /// The name.
    pub name: String,
    /// The description.
    pub description: String,
    /// Coolify's status, such as `running:healthy`.
    pub status: String,
    /// The public hostnames and URLs.
    pub fqdns: Vec<String>,
    /// The numeric environment id.
    pub environment_id: Option<i64>,
    /// The build pack.
    pub build_pack: Option<String>,
    /// The source repository, credentials removed.
    pub git_repository: Option<String>,
    /// The source branch.
    pub git_branch: Option<String>,
    /// The image reference of an image application.
    pub docker_image: Option<String>,
    /// When Coolify created it.
    pub created_at: Option<String>,
    /// When Coolify last changed it.
    pub updated_at: Option<String>,
}

impl From<CoolifyApplication> for CoolifyApplicationDto {
    fn from(item: CoolifyApplication) -> Self {
        Self {
            uuid: item.uuid,
            name: item.name,
            description: item.description,
            status: item.status,
            fqdns: item.fqdns,
            environment_id: item.environment_id,
            build_pack: item.build_pack,
            git_repository: item.git_repository,
            git_branch: item.git_branch,
            docker_image: item.docker_image,
            created_at: item.created_at,
            updated_at: item.updated_at,
        }
    }
}

/// A one-click or Compose service.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyServiceDto {
    /// Coolify's identity.
    pub uuid: String,
    /// The name.
    pub name: String,
    /// The description.
    pub description: String,
    /// Coolify's status, when the list reports one.
    pub status: Option<String>,
    /// The one-click service type.
    pub service_type: Option<String>,
    /// The numeric environment id.
    pub environment_id: Option<i64>,
    /// The public hostnames of its applications; carried from the previous
    /// run when `detailsStale`.
    pub fqdns: Vec<String>,
    /// Whether the hostnames could not be refreshed by the latest run.
    pub details_stale: bool,
    /// When Coolify created it.
    pub created_at: Option<String>,
    /// When Coolify last changed it.
    pub updated_at: Option<String>,
}

impl From<CoolifyService> for CoolifyServiceDto {
    fn from(item: CoolifyService) -> Self {
        Self {
            uuid: item.uuid,
            name: item.name,
            description: item.description,
            status: item.status,
            service_type: item.service_type,
            environment_id: item.environment_id,
            fqdns: item.fqdns,
            details_stale: item.details_stale,
            created_at: item.created_at,
            updated_at: item.updated_at,
        }
    }
}

/// A managed database. No credentials or connection URLs.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyDatabaseDto {
    /// Coolify's identity.
    pub uuid: String,
    /// The name.
    pub name: String,
    /// The description.
    pub description: String,
    /// Coolify's status.
    pub status: String,
    /// The engine, such as `postgresql`.
    pub engine: Option<String>,
    /// The image reference.
    pub image: Option<String>,
    /// The numeric environment id.
    pub environment_id: Option<i64>,
    /// Whether the database is exposed on a public port.
    pub is_public: Option<bool>,
    /// The public port.
    pub public_port: Option<i64>,
}

impl From<CoolifyDatabase> for CoolifyDatabaseDto {
    fn from(item: CoolifyDatabase) -> Self {
        Self {
            uuid: item.uuid,
            name: item.name,
            description: item.description,
            status: item.status,
            engine: item.engine,
            image: item.image,
            environment_id: item.environment_id,
            is_public: item.is_public,
            public_port: item.public_port,
        }
    }
}

/// One deployment of an application. No logs.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyDeploymentDto {
    /// Coolify's identity.
    pub deployment_uuid: String,
    /// The application's name.
    pub application_name: Option<String>,
    /// The application's identity, when known.
    pub application_uuid: Option<String>,
    /// The server's name.
    pub server_name: Option<String>,
    /// `queued`, `in_progress`, `finished`, `failed`, or `cancelled`.
    pub status: String,
    /// The commit.
    pub commit: Option<String>,
    /// The first line of the commit message.
    pub commit_message: Option<String>,
    /// Whether a webhook started it.
    pub is_webhook: Option<bool>,
    /// Whether the API started it.
    pub is_api: Option<bool>,
    /// The pull request number for preview deployments.
    pub pull_request_id: Option<i64>,
    /// When it was queued.
    pub created_at: Option<String>,
    /// When it last changed.
    pub updated_at: Option<String>,
}

impl From<CoolifyDeployment> for CoolifyDeploymentDto {
    fn from(item: CoolifyDeployment) -> Self {
        Self {
            deployment_uuid: item.deployment_uuid,
            application_name: item.application_name,
            application_uuid: item.application_uuid,
            server_name: item.server_name,
            status: item.status,
            commit: item.commit,
            commit_message: item.commit_message,
            is_webhook: item.is_webhook,
            is_api: item.is_api,
            pull_request_id: item.pull_request_id,
            created_at: item.created_at,
            updated_at: item.updated_at,
        }
    }
}

/// The stamped, stale-aware Coolify snapshot of one account.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyObservationDto {
    /// The account the snapshot belongs to.
    pub account_id: String,
    /// The Coolify version last seen.
    pub version: Option<String>,
    /// When the snapshot was last written (epoch millis).
    pub recorded_at: i64,
    /// The time staleness was evaluated against (epoch millis).
    pub evaluated_at: i64,
    /// Warnings from the latest run, such as a token that can read
    /// sensitive values (use a read-only token).
    pub warnings: Vec<String>,
    /// The per-class state: stamps, staleness, and failures.
    pub classes: Vec<CoolifyClassDto>,
    /// Servers.
    pub servers: Vec<CoolifyServerDto>,
    /// Projects with their environments.
    pub projects: Vec<CoolifyProjectDto>,
    /// Applications.
    pub applications: Vec<CoolifyApplicationDto>,
    /// Services.
    pub services: Vec<CoolifyServiceDto>,
    /// Databases.
    pub databases: Vec<CoolifyDatabaseDto>,
    /// Recent deployments, newest first.
    pub deployments: Vec<CoolifyDeploymentDto>,
}

fn class_dto<T>(name: &str, observation: &ClassObservation<T>, now: i64) -> CoolifyClassDto {
    CoolifyClassDto {
        class: name.to_owned(),
        item_count: observation.items.len(),
        attempted_at: observation.attempted_at,
        observed_at: observation.observed_at,
        stale: observation.is_stale(now),
        failure: observation.failure.as_ref().map(Into::into),
        partial: observation.partial.iter().map(Into::into).collect(),
        truncated: observation.truncated,
    }
}

fn convert<T, D: From<T>>(items: Vec<T>) -> Vec<D> {
    items.into_iter().map(Into::into).collect()
}

impl From<CoolifyObservation> for CoolifyObservationDto {
    fn from(observation: CoolifyObservation) -> Self {
        let now = observation.evaluated_at;
        let snapshot = observation.snapshot;
        let classes = vec![
            class_dto("servers", &snapshot.servers, now),
            class_dto("projects", &snapshot.projects, now),
            class_dto("applications", &snapshot.applications, now),
            class_dto("services", &snapshot.services, now),
            class_dto("databases", &snapshot.databases, now),
            class_dto("deployments", &snapshot.deployments, now),
        ];
        Self {
            account_id: observation.account_id,
            version: snapshot.version,
            recorded_at: observation.recorded_at,
            evaluated_at: observation.evaluated_at,
            warnings: snapshot.warnings,
            classes,
            servers: convert(snapshot.servers.items),
            projects: convert(snapshot.projects.items),
            applications: convert(snapshot.applications.items),
            services: convert(snapshot.services.items),
            databases: convert(snapshot.databases.items),
            deployments: convert(snapshot.deployments.items),
        }
    }
}

fn discovery_or_error(
    extension: Option<Extension<Arc<CoolifyDiscovery>>>,
    correlation_id: CorrelationId,
) -> Result<Arc<CoolifyDiscovery>, ApiErrorResponse> {
    extension
        .map(|Extension(discovery)| discovery)
        .ok_or_else(|| {
            let public = PublicError::new(
                ErrorCode::from_str("external_accounts_unavailable")
                    .expect("the literal is valid error code syntax"),
                "the Coolify discovery surface is not wired; the controller needs its database and secret store",
                RetryClass::Backoff,
            );
            ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
        })
}

/// Runs a read-only discovery of a Coolify account and records the
/// snapshot. An unreachable or refusing Coolify is a successful run whose
/// per-class state says so; the previous items stay, marked stale.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown or non-Coolify
/// account, or a missing stored token.
#[utoipa::path(
    post,
    path = "/external-accounts/{accountId}/coolify/discover",
    tag = "external-accounts",
    operation_id = "discoverCoolifyAccount",
    params(("accountId" = String, Path, description = "The Coolify account's identity.")),
    responses(
        (status = 200, description = "The snapshot after the run.", body = Resource<CoolifyObservationDto>),
        (status = 400, description = "The account is not a Coolify account.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not configure external accounts.", body = crate::error::ApiError),
        (status = 404, description = "The account does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The account's token is not in the secret store.", body = crate::error::ApiError),
    )
)]
pub async fn discover_coolify_account(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    discovery: Option<Extension<Arc<CoolifyDiscovery>>>,
    Path(account_id): Path<String>,
) -> Result<Json<Resource<CoolifyObservationDto>>, ApiErrorResponse> {
    let discovery = discovery_or_error(discovery, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let observation = discovery
        .discover(state.authorizer.as_ref(), &principal, &account_id)
        .await
        .map_err(|error| crate::external_accounts::map_error(&error, correlation_id))?;
    Ok(Json(Resource::new(observation.into())))
}

/// Reads the cached Coolify snapshot of an account, with per-class stamps
/// and staleness evaluated now.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown or non-Coolify
/// account, or when no discovery has run yet.
#[utoipa::path(
    get,
    path = "/external-accounts/{accountId}/coolify/observations",
    tag = "external-accounts",
    operation_id = "getCoolifyObservations",
    params(("accountId" = String, Path, description = "The Coolify account's identity.")),
    responses(
        (status = 200, description = "The cached snapshot.", body = Resource<CoolifyObservationDto>),
        (status = 400, description = "The account is not a Coolify account.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not read external accounts.", body = crate::error::ApiError),
        (status = 404, description = "The account does not exist or has not been discovered yet.", body = crate::error::ApiError),
    )
)]
pub async fn get_coolify_observations(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    discovery: Option<Extension<Arc<CoolifyDiscovery>>>,
    Path(account_id): Path<String>,
) -> Result<Json<Resource<CoolifyObservationDto>>, ApiErrorResponse> {
    let discovery = discovery_or_error(discovery, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let observation = discovery
        .observation(state.authorizer.as_ref(), &principal, &account_id)
        .await
        .map_err(|error| crate::external_accounts::map_error(&error, correlation_id))?;
    Ok(Json(Resource::new(observation.into())))
}
