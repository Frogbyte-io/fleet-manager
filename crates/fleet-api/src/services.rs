//! The running-service read surface (FM-1031): what is running, where, and
//! whether it is healthy, joined from Coolify observations, Docker
//! containers, and the Registry.
//!
//! Read-only. This adapter decides nothing: the join, the per-input
//! authorization (there is no `services.read`; each input's own permission
//! filters the answer), and the staleness rules live in the application's
//! `RunningServices`. The use case arrives as a request extension set by
//! the controller.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use fleet_application::services::{
    AccountCoverage, AmbiguousServer, ContainerRef, CoolifyRef, Coverage, InputState, LastDeploy,
    MachineRef, Placement, RegistryLink, RunningService, RunningServices, ServerRef, ServiceFilter,
    ServiceSource, ServicesError,
};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};

const MAX_QUERY_TEXT: usize = 200;

/// A machine reference.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceMachineRefDto {
    /// The machine's identity.
    pub id: String,
    /// The machine's name.
    pub name: String,
}

impl From<&MachineRef> for ServiceMachineRefDto {
    fn from(machine: &MachineRef) -> Self {
        Self {
            id: machine.id.clone(),
            name: machine.name.clone(),
        }
    }
}

/// Where a service sits on Fleet machines.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServicePlacementDto {
    /// `matched`, `ambiguous`, `unmatched`, or `unknown`.
    pub state: String,
    /// The evidence: `explicit_tag`, `address`, or `container`.
    pub basis: Option<String>,
    /// The machine, when matched.
    pub machine: Option<ServiceMachineRefDto>,
    /// The candidate machines, when ambiguous; none is chosen.
    pub candidates: Vec<ServiceMachineRefDto>,
}

impl From<&Placement> for ServicePlacementDto {
    fn from(placement: &Placement) -> Self {
        Self {
            state: placement.state.id().to_owned(),
            basis: placement.basis.map(|basis| basis.id().to_owned()),
            machine: placement.machine.as_ref().map(Into::into),
            candidates: placement.candidates.iter().map(Into::into).collect(),
        }
    }
}

/// A Coolify server.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceServerDto {
    /// The server's uuid.
    pub uuid: String,
    /// The server's name.
    pub name: String,
    /// The address Coolify connects to.
    pub address: String,
}

impl From<&ServerRef> for ServiceServerDto {
    fn from(server: &ServerRef) -> Self {
        Self {
            uuid: server.uuid.clone(),
            name: server.name.clone(),
            address: server.address.clone(),
        }
    }
}

/// The Coolify identity of a service.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceCoolifyDto {
    /// The account the resource was discovered through.
    pub account_id: String,
    /// The account's label.
    pub account_label: String,
    /// The resource uuid.
    pub uuid: String,
    /// Coolify's raw status string.
    pub status: Option<String>,
    /// The project uuid, when resolved.
    pub project_uuid: Option<String>,
    /// The project name.
    pub project_name: Option<String>,
    /// The environment name.
    pub environment_name: Option<String>,
    /// The image, build pack, service type, or engine.
    pub detail: Option<String>,
}

impl From<&CoolifyRef> for ServiceCoolifyDto {
    fn from(item: &CoolifyRef) -> Self {
        Self {
            account_id: item.account_id.clone(),
            account_label: item.account_label.clone(),
            uuid: item.uuid.clone(),
            status: item.status.clone(),
            project_uuid: item.project_uuid.clone(),
            project_name: item.project_name.clone(),
            environment_name: item.environment_name.clone(),
            detail: item.detail.clone(),
        }
    }
}

/// A container of a service.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceContainerDto {
    /// The machine it runs on.
    pub machine_id: String,
    /// The container id.
    pub id: String,
    /// The container name.
    pub name: String,
    /// The image.
    pub image: String,
    /// `running`, `degraded`, `stopped`, or `unknown`.
    pub state: String,
    /// The human status text.
    pub status: String,
}

impl From<&ContainerRef> for ServiceContainerDto {
    fn from(container: &ContainerRef) -> Self {
        Self {
            machine_id: container.machine_id.clone(),
            id: container.id.clone(),
            name: container.name.clone(),
            image: container.image.clone(),
            state: container.state.id().to_owned(),
            status: container.status.clone(),
        }
    }
}

/// The latest known deployment of an application.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDeployDto {
    /// The deployment uuid.
    pub deployment_uuid: String,
    /// Coolify's deployment status.
    pub status: String,
    /// The commit.
    pub commit: Option<String>,
    /// When it last changed, as Coolify reports it.
    pub at: Option<String>,
    /// Whether the deployments observation is stale.
    pub stale: bool,
}

impl From<&LastDeploy> for ServiceDeployDto {
    fn from(deploy: &LastDeploy) -> Self {
        Self {
            deployment_uuid: deploy.deployment_uuid.clone(),
            status: deploy.status.clone(),
            commit: deploy.commit.clone(),
            at: deploy.at.clone(),
            stale: deploy.stale,
        }
    }
}

/// A Registry entry related to a service.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceRegistryLinkDto {
    /// The entry's type.
    #[serde(rename = "type")]
    pub entry_type: String,
    /// The entry's key.
    pub key: String,
    /// `hosted_on` (an explicit relation) or `domain_match` (a domain entry
    /// whose fqdn equals or is a parent of a service hostname).
    pub link: String,
    /// The service hostname a domain match went through.
    pub host: Option<String>,
}

impl From<&RegistryLink> for ServiceRegistryLinkDto {
    fn from(link: &RegistryLink) -> Self {
        Self {
            entry_type: link.entry_type.clone(),
            key: link.key.clone(),
            link: link.link.id().to_owned(),
            host: link.host.clone(),
        }
    }
}

/// One running service.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunningServiceDto {
    /// The stable id: `coolify:<account>:<uuid>` or `docker:<machine>:<name>`.
    pub id: String,
    /// The display name.
    pub name: String,
    /// `application`, `service`, `database`, or `container`.
    pub kind: String,
    /// Where it was observed: `coolify`, `docker`, or both.
    pub sources: Vec<String>,
    /// `running`, `degraded`, `stopped`, or `unknown`.
    pub state: String,
    /// The Coolify identity, for Coolify resources.
    pub coolify: Option<ServiceCoolifyDto>,
    /// The Coolify server, when known.
    pub server: Option<ServiceServerDto>,
    /// The Fleet machine placement.
    pub placement: ServicePlacementDto,
    /// The containers observed for it.
    pub containers: Vec<ServiceContainerDto>,
    /// The public hostnames, as Coolify reports them.
    pub fqdns: Vec<String>,
    /// The latest known deployment, for applications.
    pub last_deploy: Option<ServiceDeployDto>,
    /// The related Registry entries.
    pub registry: Vec<ServiceRegistryLinkDto>,
    /// A link into the Coolify UI (the project page).
    pub deep_link: Option<String>,
    /// Whether any input behind this service is stale.
    pub stale: bool,
    /// Why: `coolify_<class>_stale`, `fqdns_stale`, `machine_offline`,
    /// `machine_stale`, `containers_stale`.
    pub stale_reasons: Vec<String>,
}

impl From<&RunningService> for RunningServiceDto {
    fn from(service: &RunningService) -> Self {
        Self {
            id: service.id.clone(),
            name: service.name.clone(),
            kind: service.kind.id().to_owned(),
            sources: service
                .sources
                .iter()
                .map(|source| source.id().to_owned())
                .collect(),
            state: service.state.id().to_owned(),
            coolify: service.coolify.as_ref().map(Into::into),
            server: service.server.as_ref().map(Into::into),
            placement: (&service.placement).into(),
            containers: service.containers.iter().map(Into::into).collect(),
            fqdns: service.fqdns.clone(),
            last_deploy: service.last_deploy.as_ref().map(Into::into),
            registry: service.registry.iter().map(Into::into).collect(),
            deep_link: service.deep_link.clone(),
            stale: service.stale,
            stale_reasons: service.stale_reasons.clone(),
        }
    }
}

/// A Coolify server that matched more than one machine.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AmbiguousServerDto {
    /// The account.
    pub account_id: String,
    /// The server.
    pub server: ServiceServerDto,
    /// `explicit_tag` or `address`.
    pub basis: String,
    /// The machines that fit; none is chosen.
    pub candidates: Vec<ServiceMachineRefDto>,
}

impl From<&AmbiguousServer> for AmbiguousServerDto {
    fn from(item: &AmbiguousServer) -> Self {
        Self {
            account_id: item.account_id.clone(),
            server: (&item.server).into(),
            basis: item.basis.id().to_owned(),
            candidates: item.candidates.iter().map(Into::into).collect(),
        }
    }
}

/// The state of one input of the read model.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InputStateDto {
    /// `available`, `not_configured`, `denied`, or `unavailable`. A denied
    /// or unavailable input is left out of the answer.
    pub state: String,
    /// Why it was unavailable.
    pub detail: Option<String>,
}

impl From<&InputState> for InputStateDto {
    fn from(state: &InputState) -> Self {
        Self {
            state: state.id().to_owned(),
            detail: match state {
                InputState::Unavailable(detail) => Some(detail.clone()),
                _ => None,
            },
        }
    }
}

/// One Coolify account's observation state.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountCoverageDto {
    /// The account.
    pub account_id: String,
    /// Its label.
    pub label: String,
    /// Whether a discovery was ever recorded.
    pub observed: bool,
    /// When the snapshot was recorded (epoch millis).
    pub recorded_at: Option<i64>,
    /// The resource classes that are stale.
    pub stale_classes: Vec<String>,
    /// The resource classes cut to fit the snapshot bound; services of
    /// these classes may be missing.
    pub truncated_classes: Vec<String>,
}

impl From<&AccountCoverage> for AccountCoverageDto {
    fn from(item: &AccountCoverage) -> Self {
        Self {
            account_id: item.account_id.clone(),
            label: item.label.clone(),
            observed: item.observed,
            recorded_at: item.recorded_at,
            stale_classes: item.stale_classes.clone(),
            truncated_classes: item.truncated_classes.clone(),
        }
    }
}

/// What the answer was built from.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServicesCoverageDto {
    /// Coolify observations.
    pub coolify: InputStateDto,
    /// Per-account detail.
    pub accounts: Vec<AccountCoverageDto>,
    /// Fleet machines.
    pub machines: InputStateDto,
    /// Docker container observations (not stored until M5 lands).
    pub containers: InputStateDto,
    /// The Registry.
    pub registry: InputStateDto,
}

impl From<&Coverage> for ServicesCoverageDto {
    fn from(coverage: &Coverage) -> Self {
        Self {
            coolify: (&coverage.coolify).into(),
            accounts: coverage.accounts.iter().map(Into::into).collect(),
            machines: (&coverage.machines).into(),
            containers: (&coverage.containers).into(),
            registry: (&coverage.registry).into(),
        }
    }
}

/// A page of running services.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServicesPage {
    /// The services, ordered by id.
    pub items: Vec<RunningServiceDto>,
    /// Where this page sits in the result set.
    pub page: PageInfo,
    /// Coolify servers that matched more than one machine.
    pub ambiguous_servers: Vec<AmbiguousServerDto>,
    /// What the answer was built from.
    pub coverage: ServicesCoverageDto,
    /// The read time (epoch millis).
    pub evaluated_at: i64,
}

/// One service and what its answer was built from.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDetailDto {
    /// The service.
    pub service: RunningServiceDto,
    /// What the answer was built from.
    pub coverage: ServicesCoverageDto,
}

/// Filters, cursor, and bound for the services list.
#[derive(Clone, Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ServicesParams {
    /// Only services observed by this source: `coolify` or `docker`.
    pub source: Option<String>,
    /// Only services placed on this machine id.
    pub machine: Option<String>,
    /// Only services whose name or hostname contains this text
    /// (case-insensitive).
    pub q: Option<String>,
    /// Opaque cursor returned as the previous page's `nextCursor`.
    pub cursor: Option<String>,
    /// Requested page size, clamped to the API maximum.
    pub limit: Option<u32>,
}

fn invalid(detail: &str, correlation_id: CorrelationId) -> ApiErrorResponse {
    let public = PublicError::new(
        ErrorCode::from_str("invalid_request").expect("valid error code"),
        detail.to_owned(),
        RetryClass::Never,
    );
    ApiError::new(&public, correlation_id).with_status(StatusCode::BAD_REQUEST)
}

fn use_case(
    extension: Option<Extension<Arc<RunningServices>>>,
    correlation_id: CorrelationId,
) -> Result<Arc<RunningServices>, ApiErrorResponse> {
    extension
        .map(|Extension(services)| services)
        .ok_or_else(|| {
            let public = PublicError::new(
                ErrorCode::from_str("services_unavailable").expect("valid error code"),
                "the running-services surface is not wired; the controller needs its database",
                RetryClass::Backoff,
            );
            ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
        })
}

fn map_error(error: &ServicesError, correlation_id: CorrelationId) -> ApiErrorResponse {
    let (status, code) = match error {
        ServicesError::Denied(_) => (StatusCode::FORBIDDEN, "denied"),
        ServicesError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
    };
    let public = PublicError::new(
        ErrorCode::from_str(code).expect("valid error code"),
        error.to_string(),
        RetryClass::Never,
    );
    ApiError::new(&public, correlation_id).with_status(status)
}

/// Lists running services: Coolify resources joined with Docker
/// containers on Fleet machines and with Registry entries, ordered by id.
/// Inputs the caller may not read are left out and reported in `coverage`.
///
/// # Errors
///
/// Returns the public error envelope on a malformed filter, or when the
/// caller may read none of the inputs.
#[utoipa::path(
    get,
    path = "/services",
    tag = "services",
    operation_id = "listRunningServices",
    params(ServicesParams),
    responses(
        (status = 200, description = "A page of running services.", body = ServicesPage),
        (status = 400, description = "A filter or the cursor is malformed.", body = ApiError),
        (status = 403, description = "The caller may read none of the inputs.", body = ApiError),
        (status = 503, description = "The surface is not wired.", body = ApiError),
    )
)]
pub async fn list_running_services(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    services: Option<Extension<Arc<RunningServices>>>,
    Query(params): Query<ServicesParams>,
) -> Result<Json<ServicesPage>, ApiErrorResponse> {
    let services = use_case(services, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let source = match params.source.as_deref() {
        None => None,
        Some(text) => Some(ServiceSource::from_id(text).ok_or_else(|| {
            invalid(
                "the source filter must be coolify or docker",
                correlation_id,
            )
        })?),
    };
    let query = match params.q.as_deref().map(str::trim) {
        None => None,
        Some(text) if text.is_empty() || text.len() > MAX_QUERY_TEXT => {
            return Err(invalid(
                "the q filter is empty or longer than 200 bytes",
                correlation_id,
            ));
        }
        Some(text) => Some(text.to_owned()),
    };
    let filter = ServiceFilter {
        source,
        machine_id: params.machine.filter(|machine| !machine.is_empty()),
        query,
    };
    let limit = params
        .limit
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .clamp(1, MAX_PAGE_LIMIT);
    let view = services
        .list(state.authorizer.as_ref(), &principal, &filter)
        .await
        .map_err(|error| map_error(&error, correlation_id))?;
    let bound = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut rest: Vec<&RunningService> = view.services.iter().collect();
    if let Some(cursor) = params.cursor.as_deref() {
        rest.retain(|service| service.id.as_str() > cursor);
    }
    let more = rest.len() > bound;
    rest.truncate(bound);
    let next_cursor = more
        .then(|| rest.last().map(|service| service.id.clone()))
        .flatten();
    Ok(Json(ServicesPage {
        items: rest.into_iter().map(Into::into).collect(),
        page: PageInfo { next_cursor, limit },
        ambiguous_servers: view.ambiguous_servers.iter().map(Into::into).collect(),
        coverage: (&view.coverage).into(),
        evaluated_at: view.evaluated_at,
    }))
}

/// Reads one running service by id.
///
/// # Errors
///
/// Returns the public error envelope on refusal or when no such service is
/// in the caller's view.
#[utoipa::path(
    get,
    path = "/services/{serviceId}",
    tag = "services",
    operation_id = "getRunningService",
    params(("serviceId" = String, Path, description = "The service id, as the list returns it.")),
    responses(
        (status = 200, description = "The service.", body = Resource<ServiceDetailDto>),
        (status = 403, description = "The caller may read none of the inputs.", body = ApiError),
        (status = 404, description = "No such service in the caller's view.", body = ApiError),
        (status = 503, description = "The surface is not wired.", body = ApiError),
    )
)]
pub async fn get_running_service(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    services: Option<Extension<Arc<RunningServices>>>,
    Path(service_id): Path<String>,
) -> Result<Json<Resource<ServiceDetailDto>>, ApiErrorResponse> {
    let services = use_case(services, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let (service, coverage) = services
        .get(state.authorizer.as_ref(), &principal, &service_id)
        .await
        .map_err(|error| map_error(&error, correlation_id))?;
    Ok(Json(Resource::new(ServiceDetailDto {
        service: (&service).into(),
        coverage: (&coverage).into(),
    })))
}
