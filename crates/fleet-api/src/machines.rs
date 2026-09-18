//! The machine read surface: list and detail over the application's
//! authorized use cases.
//!
//! This adapter decides nothing about machines; it translates HTTP query
//! parameters into the application's filter, and the application's
//! [`MachineView`] into the documented shapes. The view already carries the
//! derived machine status, the effective capability statuses at the read
//! time, and endpoint redaction decided by the authorization funnel —
//! nothing here re-derives or re-decides it.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use fleet_application::machine::{
    CapabilityFactView, Endpoint, InventoryObservation, MachineFilter, MachineStatus,
    MachineUseCaseError, MachineView, Machines,
};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use std::str::FromStr as _;
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};

/// Extracts the machine use cases from the API state, or answers with the
/// standard envelope when the controller was composed without a database.
pub(crate) fn machines_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<Machines>, ApiErrorResponse> {
    state.machines.clone().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "the machine surface is not wired; the controller needs its database",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// Maps a machine use-case outcome onto the public error envelope, once.
/// Backend details stay out of the response; every other detail is
/// caller-safe by construction in the use cases.
pub(crate) fn map_machine_error(
    error: &MachineUseCaseError,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    let (status, code, retry): (StatusCode, &str, RetryClass) = match error {
        MachineUseCaseError::Denied(_) => (StatusCode::FORBIDDEN, "denied", RetryClass::Never),
        MachineUseCaseError::NotFound { .. } => {
            (StatusCode::NOT_FOUND, "not_found", RetryClass::Never)
        }
        MachineUseCaseError::Conflict { .. } => {
            (StatusCode::CONFLICT, "conflict", RetryClass::Never)
        }
        MachineUseCaseError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
        ),
        MachineUseCaseError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    let message = match error {
        MachineUseCaseError::Backend { .. } => {
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

/// One connection endpoint of a machine. The reference arrives redacted
/// from the use case unless the caller may read sensitive endpoint detail.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EndpointDto {
    /// The endpoint's identity.
    pub id: String,
    /// How this endpoint reaches the machine: `ssh` or `fleetd`.
    pub kind: String,
    /// The reference, e.g. `***@host:port` for SSH when redacted, or the
    /// node id for fleetd. Never carries a secret.
    pub reference: String,
}

/// One capability fact as the read model displays it: the recorded status
/// with the staleness rule applied at the read time.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityFactDto {
    /// The namespace, e.g. `os`, `tool`, `agent`.
    pub namespace: String,
    /// The capability name within the namespace, e.g. `git`, `family`.
    pub name: String,
    /// The observed value, when the capability has one.
    pub value: Option<String>,
    /// The effective status: `known`, `stale`, `unknown`, or `unavailable`.
    /// `stale` means the fact was once known but nothing re-observed it
    /// within the freshness threshold; `unknown` means no probe ever
    /// answered for it; they are deliberately different states.
    pub status: String,
    /// When the fact was observed (epoch milliseconds).
    pub observed_at: i64,
    /// What observed it: a probe name and version, e.g. `agentless/1`.
    pub source: String,
}

/// The newest inventory observation of a machine: what probed it and when.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InventoryObservationDto {
    /// What observed it, e.g. `agentless/1` or `fleetd/1.2.3`.
    pub source: String,
    /// When the observation was collected (epoch milliseconds).
    pub collected_at: i64,
}

/// A machine, as the list and detail endpoints display it.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineDto {
    /// The stable identity.
    pub id: String,
    /// The mutable, unique label.
    pub name: String,
    /// Operator notes.
    pub description: String,
    /// How the machine is reached today; endpoint references are redacted
    /// unless the caller may read sensitive endpoint detail.
    pub endpoints: Vec<EndpointDto>,
    /// Tags.
    pub tags: Vec<String>,
    /// Groups.
    pub groups: Vec<String>,
    /// The derived connectivity state: `connected`, `stale`, `offline`, or
    /// `agentless`.
    pub machine_status: String,
    /// The last gateway observation time, when the node ever connected
    /// (epoch milliseconds).
    pub last_seen_at: Option<i64>,
    /// The newest inventory observation, when the machine was ever probed.
    pub last_observation: Option<InventoryObservationDto>,
    /// The capability facts with effective statuses at the read time.
    pub capabilities: Vec<CapabilityFactDto>,
    /// Registration time (epoch milliseconds).
    pub created_at: i64,
    /// Last mutation (epoch milliseconds).
    pub updated_at: i64,
}

impl From<MachineView> for MachineDto {
    fn from(view: MachineView) -> Self {
        Self {
            id: view.id,
            name: view.name,
            description: view.description,
            endpoints: view
                .endpoints
                .into_iter()
                .map(|endpoint: Endpoint| EndpointDto {
                    id: endpoint.id,
                    kind: endpoint.kind.id().to_owned(),
                    reference: endpoint.reference,
                })
                .collect(),
            tags: view.tags,
            groups: view.groups,
            machine_status: view.machine_status.id().to_owned(),
            last_seen_at: view.last_seen_at,
            last_observation: view
                .last_observation
                .map(
                    |observation: InventoryObservation| InventoryObservationDto {
                        source: observation.source,
                        collected_at: observation.collected_at,
                    },
                ),
            capabilities: view
                .capabilities
                .into_iter()
                .map(|fact: CapabilityFactView| CapabilityFactDto {
                    namespace: fact.namespace,
                    name: fact.name,
                    value: fact.value,
                    status: fact.status.id().to_owned(),
                    observed_at: fact.observed_at,
                    source: fact.source,
                })
                .collect(),
            created_at: view.created_at,
            updated_at: view.updated_at,
        }
    }
}

/// The list-machines query parameters.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListMachinesParams {
    /// Only machines carrying this tag.
    pub tag: Option<String>,
    /// Only machines in this group.
    pub group: Option<String>,
    /// Only machines carrying this capability, as `namespace:name`, e.g.
    /// `tool:git`.
    pub capability: Option<String>,
    /// Only machines in this connectivity state: `connected`, `stale`,
    /// `offline`, or `agentless`.
    pub status: Option<String>,
    /// The maximum number of machines to return.
    pub limit: Option<u32>,
}

/// Parses the `namespace:name` capability parameter.
fn parse_capability(
    raw: Option<&String>,
    correlation_id: CorrelationId,
) -> Result<Option<(String, String)>, ApiErrorResponse> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let (namespace, name) = raw.split_once(':').ok_or_else(|| {
        invalid_request(
            &format!("the capability filter must be namespace:name, not {raw:?}"),
            correlation_id,
        )
    })?;
    if namespace.is_empty() || name.is_empty() {
        return Err(invalid_request(
            "the capability filter needs a non-empty namespace and name",
            correlation_id,
        ));
    }
    Ok(Some((namespace.to_owned(), name.to_owned())))
}

/// Parses the machine-status parameter.
fn parse_status(
    raw: Option<&String>,
    correlation_id: CorrelationId,
) -> Result<Option<MachineStatus>, ApiErrorResponse> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    MachineStatus::from_id(raw).map_or_else(
        || {
            Err(invalid_request(
                &format!(
                    "unknown machine status {raw:?}; use connected, stale, offline, or agentless"
                ),
                correlation_id,
            ))
        },
        |status| Ok(Some(status)),
    )
}

/// A 403 response carrying the denial's stable reason. Kept as a helper
/// so the pinned literal error code lives in one place.
pub(crate) fn denied_error(
    decision: fleet_application::authz::Decision,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    let public = PublicError::new(
        ErrorCode::from_str("denied").expect("the literal is valid error code syntax"),
        format!("denied: {decision}"),
        RetryClass::Never,
    );
    ApiError::new(&public, correlation_id).with_status(StatusCode::FORBIDDEN)
}

pub(crate) fn invalid_request(message: &str, correlation_id: CorrelationId) -> ApiErrorResponse {
    let public = PublicError::new(
        ErrorCode::from_str("invalid_request").expect("the literal is valid error code syntax"),
        message.to_owned(),
        RetryClass::Never,
    );
    ApiError::new(&public, correlation_id).with_status(StatusCode::BAD_REQUEST)
}

/// Lists machines, newest first, narrowed by the filters.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/machines",
    tag = "machines",
    operation_id = "listMachines",
    params(
        ("tag" = Option<String>, Query, description = "Only machines carrying this tag."),
        ("group" = Option<String>, Query, description = "Only machines in this group."),
        ("capability" = Option<String>, Query, description = "Only machines carrying this capability, as `namespace:name`."),
        ("status" = Option<String>, Query, description = "Only machines in this state: connected, stale, offline, or agentless."),
        ("limit" = Option<u32>, Query, description = "The maximum number of machines to return.")
    ),
    responses(
        (
            status = 200,
            description = "A page of machines.",
            body = Page<MachineDto>
        ),
        (
            status = 400,
            description = "A filter is malformed.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not read machines.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn list_machines(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<ListMachinesParams>,
) -> Result<Json<Page<MachineDto>>, ApiErrorResponse> {
    let machines = machines_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let capability = parse_capability(params.capability.as_ref(), correlation_id)?;
    let status = parse_status(params.status.as_ref(), correlation_id)?;
    let filter = MachineFilter {
        tag: params.tag,
        group: params.group,
        capability,
        status,
    };
    let limit = params
        .limit
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .min(MAX_PAGE_LIMIT);
    let views = machines
        .list(
            state.authorizer.as_ref(),
            &principal,
            &filter,
            limit,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_machine_error(&error, correlation_id))?;
    let next_cursor = (views.len() == usize::try_from(limit).unwrap_or(0))
        .then(|| views.last().map(|view| view.id.clone()))
        .flatten();
    Ok(Json(Page {
        items: views.into_iter().map(MachineDto::from).collect(),
        page: PageInfo { next_cursor, limit },
    }))
}

/// Reads one machine.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/machines/{machineId}",
    tag = "machines",
    operation_id = "getMachine",
    params(
        ("machineId" = String, Path, description = "The machine's identity.")
    ),
    responses(
        (
            status = 200,
            description = "The machine.",
            body = Resource<MachineDto>
        ),
        (
            status = 404,
            description = "No such machine.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not read machines.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn get_machine(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
) -> Result<Json<Resource<MachineDto>>, ApiErrorResponse> {
    let machines = machines_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let view = machines
        .get(
            state.authorizer.as_ref(),
            &principal,
            &machine_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_machine_error(&error, correlation_id))?;
    Ok(Json(Resource::new(MachineDto::from(view))))
}
