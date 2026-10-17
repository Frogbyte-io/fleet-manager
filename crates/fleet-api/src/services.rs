//! The running-service read surface (FM-1031): what is running, where, and
//! whether it is healthy, joined from Coolify observations, Docker
//! containers, and the Registry.
//!
//! Read-only. This adapter decides nothing: the join, the per-input
//! authorization (there is no `services.read`; each input's own permission
//! filters the answer), and the staleness rules live in the application's
//! `RunningServices`. The use case arrives as a request extension set by
//! the controller.
//!
//! FM-1033 adds two Coolify routes beside the reads: `POST
//! /services/{id}/actions/{verb}` files a brokered lifecycle request (the
//! risk class decides whether it runs or waits for a person), and `GET
//! /services/{id}/logs` tails the newest deployment's log, bounded and
//! redacted. Both are adapters over `CoolifyLifecycle`.
//!
//! FM-1034 adds the settings routes: `GET /services/{id}/settings` (keys and
//! flags, domains, health check; never a value) and `POST
//! /services/{id}/settings/{env|domains|health}`, which file `approve`-class
//! requests with a preview. Environment values are write-only: they pass
//! through this adapter once, into the use case, which holds them in the
//! encrypted secret store. Adapters over `CoolifySettings`.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use fleet_application::coolify::lifecycle::{
    CoolifyLifecycle, LifecycleError, LifecycleFailureClass, LifecycleRequest, LifecycleVerb,
    LogTail,
};
use fleet_application::coolify::settings::{
    CoolifySettings, DomainsRequest, EnvChangeInput, EnvFlagOverrides, EnvOp, EnvRequest,
    HealthPatch, HealthRequest, HealthSettings, RequestMeta, SettingsView,
};
use fleet_application::services::{
    AccountCoverage, AmbiguousServer, ContainerRef, CoolifyRef, Coverage, InputState, LastDeploy,
    MachineRef, Placement, RegistryLink, RunningService, RunningServices, ServerRef, ServiceFilter,
    ServiceSource, ServicesError,
};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass, SensitiveString};
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
    /// The candidate machines the caller may read, when ambiguous; none is
    /// chosen.
    pub candidates: Vec<ServiceMachineRefDto>,
    /// How many further candidates the caller may not read.
    pub hidden_candidates: usize,
}

impl From<&Placement> for ServicePlacementDto {
    fn from(placement: &Placement) -> Self {
        Self {
            state: placement.state.id().to_owned(),
            basis: placement.basis.map(|basis| basis.id().to_owned()),
            machine: placement.machine.as_ref().map(Into::into),
            candidates: placement.candidates.iter().map(Into::into).collect(),
            hidden_candidates: placement.hidden_candidates,
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
    /// How the server was derived: `deployment`, `container`,
    /// `sole_server`, or `unknown`.
    pub server_basis: String,
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
            server_basis: service.server_basis.id().to_owned(),
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
    /// The machines that fit and that the caller may read; none is chosen.
    pub candidates: Vec<ServiceMachineRefDto>,
    /// How many further machines fit that the caller may not read.
    pub hidden_candidates: usize,
}

impl From<&AmbiguousServer> for AmbiguousServerDto {
    fn from(item: &AmbiguousServer) -> Self {
        Self {
            account_id: item.account_id.clone(),
            server: (&item.server).into(),
            basis: item.basis.id().to_owned(),
            candidates: item.candidates.iter().map(Into::into).collect(),
            hidden_candidates: item.hidden_candidates,
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
    /// A fixed, caller-safe sentence when the input was unavailable; never
    /// a backend error.
    pub detail: Option<String>,
}

impl From<&InputState> for InputStateDto {
    fn from(state: &InputState) -> Self {
        Self {
            state: state.id().to_owned(),
            detail: match state {
                InputState::Unavailable(detail) => Some((*detail).to_owned()),
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

/// The page after `cursor` (exclusive) of services already ordered by id,
/// and the cursor of the next page when more follow.
fn page_of<'a>(
    services: &'a [RunningService],
    cursor: Option<&str>,
    limit: u32,
) -> (Vec<&'a RunningService>, Option<String>) {
    let bound = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut rest: Vec<&RunningService> = services
        .iter()
        .filter(|service| cursor.is_none_or(|cursor| service.id.as_str() > cursor))
        .collect();
    let more = rest.len() > bound;
    rest.truncate(bound);
    let next = more
        .then(|| rest.last().map(|service| service.id.clone()))
        .flatten();
    (rest, next)
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
    let (items, next_cursor) = page_of(&view.services, params.cursor.as_deref(), limit);
    Ok(Json(ServicesPage {
        items: items.into_iter().map(Into::into).collect(),
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

/// What to say when filing a lifecycle action on a service.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceActionBody {
    /// Why, for the approver (at most 1000 characters).
    #[serde(default)]
    pub reason: String,
    /// A key making a retry return the request already made (scoped to the
    /// caller).
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// A deployment log tail: bounded, redacted, never stored.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceLogsDto {
    /// The deployment the lines belong to.
    pub deployment_uuid: String,
    /// Coolify's deployment status.
    pub deployment_status: String,
    /// The log lines, oldest first, after redaction.
    pub lines: Vec<String>,
    /// Whether earlier lines were cut to fit the bounds.
    pub truncated: bool,
    /// Whether redaction changed any line.
    pub redacted: bool,
}

impl From<LogTail> for ServiceLogsDto {
    fn from(tail: LogTail) -> Self {
        Self {
            deployment_uuid: tail.deployment_uuid,
            deployment_status: tail.deployment_status,
            lines: tail.lines,
            truncated: tail.truncated,
            redacted: tail.redacted,
        }
    }
}

fn lifecycle_or_error(
    extension: Option<Extension<Arc<CoolifyLifecycle>>>,
    correlation_id: CorrelationId,
) -> Result<Arc<CoolifyLifecycle>, ApiErrorResponse> {
    extension
        .map(|Extension(lifecycle)| lifecycle)
        .ok_or_else(|| {
            let public = PublicError::new(
                ErrorCode::from_str("services_unavailable").expect("valid error code"),
                "the Coolify action surface is not wired; the controller needs its database and secret store",
                RetryClass::Backoff,
            );
            ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
        })
}

fn map_lifecycle_error(error: &LifecycleError, correlation_id: CorrelationId) -> ApiErrorResponse {
    if let LifecycleError::Broker(broker) = error {
        return crate::requests::map_broker_error(broker, correlation_id);
    }
    let (status, code, retry) = match error {
        LifecycleError::Denied(_) => (StatusCode::FORBIDDEN, "denied", RetryClass::Never),
        LifecycleError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
        ),
        LifecycleError::NotFound { .. } => (StatusCode::NOT_FOUND, "not_found", RetryClass::Never),
        LifecycleError::Provider(failure) => match failure.class {
            LifecycleFailureClass::Permission => (
                StatusCode::FORBIDDEN,
                "provider_permission",
                RetryClass::Never,
            ),
            LifecycleFailureClass::NotFound => {
                (StatusCode::NOT_FOUND, "not_found", RetryClass::Never)
            }
            LifecycleFailureClass::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                RetryClass::Backoff,
            ),
            LifecycleFailureClass::Unsupported => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "provider_unsupported",
                RetryClass::Never,
            ),
            LifecycleFailureClass::Invalid => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                RetryClass::Never,
            ),
            LifecycleFailureClass::Auth | LifecycleFailureClass::Unavailable => (
                StatusCode::BAD_GATEWAY,
                "provider_unavailable",
                RetryClass::Backoff,
            ),
        },
        LifecycleError::Backend { .. } | LifecycleError::Broker(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    let message = match error {
        LifecycleError::Backend { .. } => {
            "the request could not be completed; the detail is in the controller log".to_owned()
        }
        other => other.to_string(),
    };
    let public = PublicError::new(
        ErrorCode::from_str(code).expect("valid error code"),
        message,
        retry,
    );
    ApiError::new(&public, correlation_id).with_status(status)
}

/// Files a lifecycle action (`start`, `stop`, `restart`, or `redeploy`) on a
/// Coolify service as a brokered action request. `restart`, `redeploy`, and
/// `start` run at once; `stop` waits for a person to approve it. The
/// resource must be in the account's latest Coolify observation. The answer
/// is the action request; follow it at `/requests/{id}` and its operation at
/// `/operations/{id}`, whose result records the status observed after the
/// call.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown service or verb,
/// or a broker refusal.
#[utoipa::path(
    post,
    path = "/services/{serviceId}/actions/{verb}",
    tag = "services",
    operation_id = "requestServiceAction",
    params(
        ("serviceId" = String, Path, description = "A Coolify service id, `coolify:<account>:<uuid>`, as the list returns it."),
        ("verb" = String, Path, description = "start, stop, restart, or redeploy (applications only).")
    ),
    request_body = ServiceActionBody,
    responses(
        (status = 201, description = "The action request was recorded; its state shows what policy did.", body = Resource<crate::requests::ActionRequestDto>),
        (status = 400, description = "The service id, the verb, or a field is invalid.", body = ApiError),
        (status = 403, description = "The caller may not do this, or policy denies the action.", body = ApiError),
        (status = 404, description = "No such resource in the account's latest observation.", body = ApiError),
        (status = 409, description = "The idempotency key was already used for a different request.", body = ApiError),
        (status = 503, description = "The surface is not wired.", body = ApiError),
    )
)]
pub async fn request_service_action(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    lifecycle: Option<Extension<Arc<CoolifyLifecycle>>>,
    Path((service_id, verb)): Path<(String, String)>,
    body: Result<Json<ServiceActionBody>, axum::extract::rejection::JsonRejection>,
) -> Result<
    (
        StatusCode,
        Json<Resource<crate::requests::ActionRequestDto>>,
    ),
    ApiErrorResponse,
> {
    let lifecycle = lifecycle_or_error(lifecycle, correlation_id)?;
    let broker = crate::requests::broker_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let verb = LifecycleVerb::from_id(&verb).ok_or_else(|| {
        invalid(
            "the verb must be start, stop, restart, or redeploy",
            correlation_id,
        )
    })?;
    let Json(body) = body.map_err(|_| {
        invalid(
            "the request body must be JSON with an optional reason and idempotencyKey",
            correlation_id,
        )
    })?;
    let reason = if body.reason.trim().is_empty() {
        format!("{} {service_id}", verb.id())
    } else {
        body.reason
    };
    let created = lifecycle
        .request_action(
            &broker,
            state.authorizer.as_ref(),
            &principal,
            LifecycleRequest {
                service_id,
                verb,
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

/// Query parameters of the log tail.
#[derive(Clone, Debug, Default, Deserialize, utoipa::IntoParams)]
pub struct ServiceLogsParams {
    /// A deployment uuid; the newest deployment when absent.
    pub deployment: Option<String>,
    /// How many trailing lines to return (default 200, at most 1000).
    pub lines: Option<usize>,
}

/// Tails the log of a Coolify application's deployment, bounded in lines
/// and bytes and redacted before it is returned; it is never stored.
/// Coolify returns deployment logs only to a token with the `read:sensitive`
/// ability, so an account whose token lacks it answers 403 with
/// `provider_permission`. Needs `external_account.config` on the account.
///
/// # Errors
///
/// Returns the public error envelope on refusal, a service that is not a
/// known application, or a provider failure.
#[utoipa::path(
    get,
    path = "/services/{serviceId}/logs",
    tag = "services",
    operation_id = "getServiceLogs",
    params(
        ("serviceId" = String, Path, description = "A Coolify application id, `coolify:<account>:<uuid>`."),
        ServiceLogsParams
    ),
    responses(
        (status = 200, description = "The redacted log tail.", body = Resource<ServiceLogsDto>),
        (status = 400, description = "The service is not an application or a parameter is invalid.", body = ApiError),
        (status = 403, description = "The caller may not read logs (`denied`), or the Coolify token lacks read:sensitive (`provider_permission`).", body = ApiError),
        (status = 404, description = "No such service, or it has no deployment.", body = ApiError),
        (status = 503, description = "The surface is not wired.", body = ApiError),
    )
)]
pub async fn get_service_logs(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    lifecycle: Option<Extension<Arc<CoolifyLifecycle>>>,
    Path(service_id): Path<String>,
    Query(params): Query<ServiceLogsParams>,
) -> Result<Json<Resource<ServiceLogsDto>>, ApiErrorResponse> {
    let lifecycle = lifecycle_or_error(lifecycle, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let tail = lifecycle
        .logs(
            state.authorizer.as_ref(),
            &principal,
            &service_id,
            params.deployment.as_deref(),
            params.lines,
        )
        .await
        .map_err(|error| map_lifecycle_error(&error, correlation_id))?;
    Ok(Json(Resource::new(tail.into())))
}

// ---------------------------------------------------------------------
// Settings (FM-1034): environment variables, domains, health checks.
// ---------------------------------------------------------------------

/// One environment variable of a service: its name and flags. There is no
/// value field: Coolify hides values from Fleet's token and Fleet never
/// asks for them.
#[allow(clippy::struct_excessive_bools)] // the flags Coolify reports
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEnvVarDto {
    /// The variable's name.
    pub key: String,
    /// Whether it belongs to preview deployments.
    pub is_preview: bool,
    /// Whether the value refers to a shared variable.
    pub is_shared: bool,
    /// Available while building (applications).
    pub is_buildtime: bool,
    /// Available at runtime (applications).
    pub is_runtime: bool,
    /// A multiline value.
    pub is_multiline: bool,
    /// A literal value: nothing is escaped or expanded.
    pub is_literal: bool,
    /// Coolify hides the value after saving.
    pub is_shown_once: bool,
}

/// An application's health check (the HTTP kind).
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceHealthDto {
    /// Whether Coolify runs the check.
    pub enabled: bool,
    /// The request path.
    pub path: String,
    /// The port, when not the application's own.
    pub port: Option<u16>,
    /// The host header, when set.
    pub host: Option<String>,
    /// The HTTP method.
    pub method: String,
    /// `http` or `https`.
    pub scheme: String,
    /// The status code that counts as healthy.
    pub return_code: u16,
    /// Text the response must contain, when set.
    pub response_text: Option<String>,
    /// Seconds between checks.
    pub interval: u32,
    /// Seconds a check may take.
    pub timeout: u32,
    /// Failures before the application is unhealthy.
    pub retries: u32,
    /// Seconds before the first check.
    pub start_period: u32,
}

impl From<HealthSettings> for ServiceHealthDto {
    fn from(health: HealthSettings) -> Self {
        Self {
            enabled: health.enabled,
            path: health.path,
            port: health.port,
            host: health.host,
            method: health.method,
            scheme: health.scheme,
            return_code: health.return_code,
            response_text: health.response_text,
            interval: health.interval,
            timeout: health.timeout,
            retries: health.retries,
            start_period: health.start_period,
        }
    }
}

/// A Coolify resource's settings as Fleet can show and change them.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSettingsDto {
    /// The running-service id.
    pub service_id: String,
    /// `application`, `service`, or `database`.
    pub resource_kind: String,
    /// The resource's name.
    pub name: String,
    /// The variables (keys and flags only), when the kind has them.
    pub env: Option<Vec<ServiceEnvVarDto>>,
    /// The domains, when Fleet can change them for this resource.
    pub domains: Option<Vec<String>>,
    /// The health check, when the kind has one.
    pub health: Option<ServiceHealthDto>,
    /// What Fleet cannot show or change here, and why.
    pub notes: Vec<String>,
}

impl From<SettingsView> for ServiceSettingsDto {
    fn from(view: SettingsView) -> Self {
        Self {
            service_id: view.service_id,
            resource_kind: view.resource_kind.id().to_owned(),
            name: view.name,
            env: view.env.map(|envs| {
                envs.into_iter()
                    .map(|env| ServiceEnvVarDto {
                        key: env.key,
                        is_preview: env.is_preview,
                        is_shared: env.is_shared,
                        is_buildtime: env.flags.is_buildtime,
                        is_runtime: env.flags.is_runtime,
                        is_multiline: env.flags.is_multiline,
                        is_literal: env.flags.is_literal,
                        is_shown_once: env.flags.is_shown_once,
                    })
                    .collect()
            }),
            domains: view.domains,
            health: view.health.map(Into::into),
            notes: view.notes,
        }
    }
}

fn settings_or_error(
    extension: Option<Extension<Arc<CoolifySettings>>>,
    correlation_id: CorrelationId,
) -> Result<Arc<CoolifySettings>, ApiErrorResponse> {
    extension
        .map(|Extension(settings)| settings)
        .ok_or_else(|| {
            let public = PublicError::new(
                ErrorCode::from_str("services_unavailable").expect("valid error code"),
                "the Coolify settings surface is not wired; the controller needs its database and secret store",
                RetryClass::Backoff,
            );
            ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
        })
}

/// Reads a Coolify resource's settings: environment variable names and
/// flags (never values), an application's domains, and its health check.
/// Needs `external_account.read`.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown service, an
/// unsupported Coolify version, or a provider failure.
#[utoipa::path(
    get,
    path = "/services/{serviceId}/settings",
    tag = "services",
    operation_id = "getServiceSettings",
    params(("serviceId" = String, Path, description = "A Coolify service id, `coolify:<account>:<uuid>`.")),
    responses(
        (status = 200, description = "The settings. Environment variable values are never included.", body = Resource<ServiceSettingsDto>),
        (status = 400, description = "The service id is invalid.", body = ApiError),
        (status = 403, description = "The caller may not read accounts, or the Coolify token lacks the read ability.", body = ApiError),
        (status = 404, description = "No such resource in the account's latest observation.", body = ApiError),
        (status = 422, description = "The Coolify version is not supported.", body = ApiError),
        (status = 503, description = "The surface is not wired.", body = ApiError),
    )
)]
pub async fn get_service_settings(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    settings: Option<Extension<Arc<CoolifySettings>>>,
    Path(service_id): Path<String>,
) -> Result<Json<Resource<ServiceSettingsDto>>, ApiErrorResponse> {
    let settings = settings_or_error(settings, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let view = settings
        .view(state.authorizer.as_ref(), &principal, &service_id)
        .await
        .map_err(|error| map_lifecycle_error(&error, correlation_id))?;
    Ok(Json(Resource::new(view.into())))
}

/// The fields every settings request shares.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSettingsMeta {
    /// Why, for the approver (at most 1000 characters).
    #[serde(default)]
    pub reason: String,
    /// A key making a retry return the request already made (scoped to the
    /// caller).
    #[serde(default)]
    pub idempotency_key: Option<String>,
    /// Redeploy an application (restart a service) once the change is
    /// applied, as part of the same approved operation.
    #[serde(default)]
    pub redeploy: bool,
}

/// One variable change.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceEnvChangeBody {
    /// `set` or `unset`.
    pub op: String,
    /// The variable's name.
    pub key: String,
    /// Whether the change is to the preview-deployment variable.
    #[serde(default)]
    pub is_preview: bool,
    /// The new value (`set` only). It is write-only: it is moved into the
    /// encrypted secret store, never stored in the request, never audited,
    /// and never returned.
    #[serde(default)]
    #[schema(write_only)]
    pub value: Option<String>,
    /// Build-time availability (applications; unset keeps the current one).
    #[serde(default)]
    pub is_buildtime: Option<bool>,
    /// Runtime availability (applications; unset keeps the current one).
    #[serde(default)]
    pub is_runtime: Option<bool>,
    /// A multiline value (unset keeps the current one).
    #[serde(default)]
    pub is_multiline: Option<bool>,
    /// A literal value (unset keeps the current one).
    #[serde(default)]
    pub is_literal: Option<bool>,
    /// Hide the value after saving (unset keeps the current one).
    #[serde(default)]
    pub is_shown_once: Option<bool>,
}

/// A request to set or unset environment variables.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEnvBody {
    /// The variables to change (one to eight).
    pub changes: Vec<ServiceEnvChangeBody>,
    /// The shared fields.
    #[serde(flatten)]
    pub meta: ServiceSettingsMeta,
}

/// A request to replace an application's domains.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDomainsBody {
    /// The complete new list of URLs (`https://shop.example.com`); an empty
    /// list clears the domains.
    pub domains: Vec<String>,
    /// The shared fields.
    #[serde(flatten)]
    pub meta: ServiceSettingsMeta,
}

/// A request to change an application's health check. Only the fields named
/// change.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceHealthBody {
    /// Turn the check on or off.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// The request path, starting with `/`.
    #[serde(default)]
    pub path: Option<String>,
    /// The port (1 to 65535).
    #[serde(default)]
    pub port: Option<u16>,
    /// The host header.
    #[serde(default)]
    pub host: Option<String>,
    /// `GET`, `HEAD`, `POST`, or `OPTIONS`.
    #[serde(default)]
    pub method: Option<String>,
    /// `http` or `https`.
    #[serde(default)]
    pub scheme: Option<String>,
    /// The healthy status code (100 to 599).
    #[serde(default)]
    pub return_code: Option<u16>,
    /// Text the response must contain.
    #[serde(default)]
    pub response_text: Option<String>,
    /// Seconds between checks (1 to 3600).
    #[serde(default)]
    pub interval: Option<u32>,
    /// Seconds a check may take (1 to 3600).
    #[serde(default)]
    pub timeout: Option<u32>,
    /// Failures before unhealthy (1 to 100).
    #[serde(default)]
    pub retries: Option<u32>,
    /// Seconds before the first check (0 to 3600).
    #[serde(default)]
    pub start_period: Option<u32>,
    /// The shared fields.
    #[serde(flatten)]
    pub meta: ServiceSettingsMeta,
}

fn meta_of(
    service_id: String,
    meta: ServiceSettingsMeta,
    what: &str,
    correlation_id: CorrelationId,
) -> RequestMeta {
    let reason = if meta.reason.trim().is_empty() {
        format!("change {what} of {service_id}")
    } else {
        meta.reason
    };
    RequestMeta {
        service_id,
        redeploy: meta.redeploy,
        reason,
        origin: "api".to_owned(),
        correlation_id: Some(correlation_id.to_string()),
        idempotency_key: meta.idempotency_key,
    }
}

type Filed = Result<
    (
        StatusCode,
        Json<Resource<crate::requests::ActionRequestDto>>,
    ),
    ApiErrorResponse,
>;

/// Files a request to set or unset environment variables of a Coolify
/// application or service. The values are write-only: each is moved into
/// the encrypted secret store and the request records only key names,
/// flags, and a digest per value, so the approver sees names and never a
/// value. The held values are deleted after execution, denial, or expiry.
/// The change is an `approve`-class action request; the answer is that
/// request. A secret-shaped value never appears in any response.
///
/// # Errors
///
/// Returns the public error envelope on refusal, invalid input, an unknown
/// resource, or a broker refusal.
#[utoipa::path(
    post,
    path = "/services/{serviceId}/settings/env",
    tag = "services",
    operation_id = "requestServiceEnvChange",
    params(("serviceId" = String, Path, description = "A Coolify application or service id, `coolify:<account>:<uuid>`.")),
    request_body = ServiceEnvBody,
    responses(
        (status = 201, description = "The action request was recorded; its preview lists the variables and flags (values show as write-only).", body = Resource<crate::requests::ActionRequestDto>),
        (status = 400, description = "The service id or a field is invalid, or the resource has no variables.", body = ApiError),
        (status = 403, description = "The caller may not do this, or policy denies the action.", body = ApiError),
        (status = 404, description = "No such resource or variable.", body = ApiError),
        (status = 409, description = "The idempotency key was already used for a different request.", body = ApiError),
        (status = 503, description = "The surface is not wired.", body = ApiError),
    )
)]
pub async fn request_service_env_change(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    settings: Option<Extension<Arc<CoolifySettings>>>,
    Path(service_id): Path<String>,
    body: Result<Json<ServiceEnvBody>, axum::extract::rejection::JsonRejection>,
) -> Filed {
    let settings = settings_or_error(settings, correlation_id)?;
    let broker = crate::requests::broker_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // The rejection is never echoed: its text can quote the body.
    let Json(body) = body.map_err(|_| {
        invalid(
            "the request body must be JSON: changes (op, key, value for a set), and optional reason, idempotencyKey, redeploy",
            correlation_id,
        )
    })?;
    let mut changes = Vec::with_capacity(body.changes.len());
    for change in body.changes {
        let op = match change.op.as_str() {
            "set" => EnvOp::Set,
            "unset" => EnvOp::Unset,
            _ => return Err(invalid("op must be set or unset", correlation_id)),
        };
        changes.push(EnvChangeInput {
            op,
            key: change.key,
            is_preview: change.is_preview,
            value: change.value.map(SensitiveString::new),
            flags: EnvFlagOverrides {
                is_buildtime: change.is_buildtime,
                is_runtime: change.is_runtime,
                is_multiline: change.is_multiline,
                is_literal: change.is_literal,
                is_shown_once: change.is_shown_once,
            },
        });
    }
    let created = settings
        .request_env(
            &broker,
            state.authorizer.as_ref(),
            &principal,
            EnvRequest {
                meta: meta_of(
                    service_id,
                    body.meta,
                    "environment variables",
                    correlation_id,
                ),
                changes,
            },
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lifecycle_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(created.into()))))
}

/// Files a request to replace a Coolify application's domains, with a
/// preview of the difference (`before`, `after`, and the changed fields).
/// An `approve`-class action request; stale at execution when the domains
/// changed in the meantime.
///
/// # Errors
///
/// Returns the public error envelope on refusal, invalid domains, an
/// unknown or non-application resource, a Compose application, a change
/// that would do nothing, or a broker refusal.
#[utoipa::path(
    post,
    path = "/services/{serviceId}/settings/domains",
    tag = "services",
    operation_id = "requestServiceDomainsChange",
    params(("serviceId" = String, Path, description = "A Coolify application id, `coolify:<account>:<uuid>`.")),
    request_body = ServiceDomainsBody,
    responses(
        (status = 201, description = "The action request was recorded; its parameters carry the preview.", body = Resource<crate::requests::ActionRequestDto>),
        (status = 400, description = "The service id or a domain is invalid, the resource is not an application, or nothing would change.", body = ApiError),
        (status = 403, description = "The caller may not do this, or policy denies the action.", body = ApiError),
        (status = 404, description = "No such resource in the account's latest observation.", body = ApiError),
        (status = 409, description = "The idempotency key was already used for a different request.", body = ApiError),
        (status = 503, description = "The surface is not wired.", body = ApiError),
    )
)]
pub async fn request_service_domains_change(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    settings: Option<Extension<Arc<CoolifySettings>>>,
    Path(service_id): Path<String>,
    body: Result<Json<ServiceDomainsBody>, axum::extract::rejection::JsonRejection>,
) -> Filed {
    let settings = settings_or_error(settings, correlation_id)?;
    let broker = crate::requests::broker_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(body) = body.map_err(|_| {
        invalid(
            "the request body must be JSON: domains (a list of URLs), and optional reason, idempotencyKey, redeploy",
            correlation_id,
        )
    })?;
    let created = settings
        .request_domains(
            &broker,
            state.authorizer.as_ref(),
            &principal,
            DomainsRequest {
                meta: meta_of(service_id, body.meta, "domains", correlation_id),
                domains: body.domains,
            },
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lifecycle_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(created.into()))))
}

/// Files a request to change a Coolify application's health check, with a
/// preview of the difference. Only the named fields change. An
/// `approve`-class action request.
///
/// # Errors
///
/// Returns the public error envelope on refusal, invalid fields, an unknown
/// or non-application resource, a change that would do nothing, or a broker
/// refusal.
#[utoipa::path(
    post,
    path = "/services/{serviceId}/settings/health",
    tag = "services",
    operation_id = "requestServiceHealthChange",
    params(("serviceId" = String, Path, description = "A Coolify application id, `coolify:<account>:<uuid>`.")),
    request_body = ServiceHealthBody,
    responses(
        (status = 201, description = "The action request was recorded; its parameters carry the preview.", body = Resource<crate::requests::ActionRequestDto>),
        (status = 400, description = "The service id or a field is invalid, the resource is not an application, or nothing would change.", body = ApiError),
        (status = 403, description = "The caller may not do this, or policy denies the action.", body = ApiError),
        (status = 404, description = "No such resource in the account's latest observation.", body = ApiError),
        (status = 409, description = "The idempotency key was already used for a different request.", body = ApiError),
        (status = 503, description = "The surface is not wired.", body = ApiError),
    )
)]
pub async fn request_service_health_change(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    settings: Option<Extension<Arc<CoolifySettings>>>,
    Path(service_id): Path<String>,
    body: Result<Json<ServiceHealthBody>, axum::extract::rejection::JsonRejection>,
) -> Filed {
    let settings = settings_or_error(settings, correlation_id)?;
    let broker = crate::requests::broker_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(body) = body.map_err(|_| {
        invalid(
            "the request body must be JSON with the health-check fields to change, and optional reason, idempotencyKey, redeploy",
            correlation_id,
        )
    })?;
    let patch = HealthPatch {
        enabled: body.enabled,
        path: body.path,
        port: body.port,
        host: body.host,
        method: body.method,
        scheme: body.scheme,
        return_code: body.return_code,
        response_text: body.response_text,
        interval: body.interval,
        timeout: body.timeout,
        retries: body.retries,
        start_period: body.start_period,
    };
    let created = settings
        .request_health(
            &broker,
            state.authorizer.as_ref(),
            &principal,
            HealthRequest {
                meta: meta_of(service_id, body.meta, "health check", correlation_id),
                patch,
            },
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lifecycle_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(created.into()))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_application::services::{Placement, ServerBasis, ServiceKind, ServiceState};

    fn service(id: &str) -> RunningService {
        RunningService {
            id: id.to_owned(),
            name: id.to_owned(),
            kind: ServiceKind::Container,
            sources: vec![ServiceSource::Docker],
            state: ServiceState::Running,
            coolify: None,
            server: None,
            server_basis: ServerBasis::Unknown,
            placement: Placement {
                state: fleet_application::services::MatchState::Unknown,
                basis: None,
                machine: None,
                candidates: Vec::new(),
                hidden_candidates: 0,
            },
            containers: Vec::new(),
            fqdns: Vec::new(),
            last_deploy: None,
            registry: Vec::new(),
            deep_link: None,
            stale: false,
            stale_reasons: Vec::new(),
        }
    }

    fn ids(items: &[&RunningService]) -> Vec<String> {
        items.iter().map(|s| s.id.clone()).collect()
    }

    #[test]
    fn pages_walk_the_whole_list_by_cursor() {
        let all: Vec<_> = ["a", "b", "c", "d", "e"].into_iter().map(service).collect();
        let (first, next) = page_of(&all, None, 2);
        assert_eq!(ids(&first), ["a", "b"]);
        assert_eq!(next.as_deref(), Some("b"));
        let (second, next) = page_of(&all, next.as_deref(), 2);
        assert_eq!(ids(&second), ["c", "d"]);
        assert_eq!(next.as_deref(), Some("d"));
        let (last, next) = page_of(&all, next.as_deref(), 2);
        assert_eq!(ids(&last), ["e"]);
        assert_eq!(next, None);
    }

    #[test]
    fn an_exact_fit_has_no_next_page_and_an_unknown_cursor_resumes_after_it() {
        let all: Vec<_> = ["a", "b", "c"].into_iter().map(service).collect();
        let (page, next) = page_of(&all, None, 3);
        assert_eq!(
            (ids(&page), next),
            (vec!["a".into(), "b".into(), "c".into()], None)
        );
        // A cursor naming a service that has since gone resumes after it.
        let (page, next) = page_of(&all, Some("aa"), 5);
        assert_eq!((ids(&page), next), (vec!["b".into(), "c".into()], None));
        let (page, _) = page_of(&all, Some("zzz"), 5);
        assert!(page.is_empty());
        let (page, _) = page_of(&[], None, 5);
        assert!(page.is_empty());
    }

    #[test]
    fn unavailable_inputs_report_only_the_fixed_sentence() {
        let dto = InputStateDto::from(&InputState::Unavailable("the machines could not be read"));
        assert_eq!(dto.state, "unavailable");
        assert_eq!(
            dto.detail.as_deref(),
            Some("the machines could not be read")
        );
        assert_eq!(InputStateDto::from(&InputState::Denied).detail, None);
    }

    #[test]
    fn the_dto_carries_server_basis_and_hidden_candidates() {
        let mut item = service("x");
        item.server_basis = ServerBasis::SoleServer;
        item.placement.hidden_candidates = 2;
        let dto = RunningServiceDto::from(&item);
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["serverBasis"], "sole_server");
        assert_eq!(json["placement"]["hiddenCandidates"], 2);
    }
}
