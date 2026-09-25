//! The Tailscale discovery surface: integration status and configuration,
//! correlated device listing, and the import handoff into the FM-210
//! onboarding flow (FM-213).
//!
//! This adapter decides nothing about correlation or trust; it translates
//! HTTP into the application's use cases and their outcomes into the public
//! envelopes. The client secret is write-only: it arrives in the configure
//! request and is never returned by any endpoint.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use fleet_application::tailnet::{CorrelatedDevice, TailnetUseCaseError};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use std::str::FromStr as _;
use utoipa::ToSchema;

use crate::envelope::{Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};

/// Extracts the tailnet use cases from the API state, or answers with the
/// standard envelope when the controller was composed without one.
fn tailnet_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<fleet_application::tailnet::TailnetIntegration>, ApiErrorResponse> {
    state.tailnet.clone().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "the tailscale surface is not wired; the controller needs its database and secret store",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// Maps a tailnet use-case outcome onto the public error envelope, once.
fn map_tailnet_error(
    error: &TailnetUseCaseError,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    let (status, code, retry): (StatusCode, &str, RetryClass) = match error {
        TailnetUseCaseError::Denied(_) => (StatusCode::FORBIDDEN, "denied", RetryClass::Never),
        TailnetUseCaseError::Unconfigured => (
            StatusCode::CONFLICT,
            "tailscale_unconfigured",
            RetryClass::Never,
        ),
        TailnetUseCaseError::NotFound { .. } => {
            (StatusCode::NOT_FOUND, "not_found", RetryClass::Never)
        }
        TailnetUseCaseError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
        ),
        TailnetUseCaseError::Source(
            fleet_application::tailnet::TailnetSourceError::RateLimited { .. },
        ) => (
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            RetryClass::Backoff,
        ),
        TailnetUseCaseError::Source(_) => (
            StatusCode::BAD_GATEWAY,
            "tailscale_source",
            RetryClass::Backoff,
        ),
        TailnetUseCaseError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    let message = match error {
        TailnetUseCaseError::Backend { .. } => {
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

/// The integration's status: configured or not, the client id, and the
/// fixed read-only scope.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TailnetStatusDto {
    /// Whether an OAuth client is configured.
    pub configured: bool,
    /// The configured client identifier, when any. Not secret.
    pub client_id: Option<String>,
    /// The scope the integration requests: always `devices:core:read`.
    pub scope: String,
}

/// One tailnet device with its Fleet-machine candidates (evidence only).
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CorrelatedDeviceDto {
    /// The device's preferred identifier (`nodeId`).
    pub node_id: String,
    /// The device's legacy numeric identifier, when carried.
    pub id: Option<String>,
    /// The `MagicDNS` name.
    pub name: String,
    /// The short hostname.
    pub hostname: String,
    /// The device's operating system.
    pub os: String,
    /// The Tailscale addresses.
    pub addresses: Vec<String>,
    /// Tailnet policy tags.
    pub tags: Vec<String>,
    /// The registering user.
    pub user: String,
    /// Whether the device reports itself online.
    pub online: Option<bool>,
    /// Whether the device recently connected to control.
    pub connected_to_control: Option<bool>,
    /// When the device was last seen, when carried.
    pub last_seen: Option<String>,
    /// Existing machines this device may be — evidence, never merged.
    pub candidates: Vec<CorrelationCandidateDto>,
}

/// One Fleet machine a tailnet device may be.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CorrelationCandidateDto {
    /// The existing machine's identity.
    pub machine_id: String,
    /// The existing machine's name.
    pub machine_name: String,
    /// The machine's derived connectivity state.
    pub machine_status: String,
    /// The matching endpoint reference.
    pub reference: String,
    /// Why: `address_match` or `name_match`.
    pub kind: String,
}

impl From<CorrelatedDevice> for CorrelatedDeviceDto {
    fn from(correlated: CorrelatedDevice) -> Self {
        Self {
            node_id: correlated.device.node_id,
            id: correlated.device.id,
            name: correlated.device.name,
            hostname: correlated.device.hostname,
            os: correlated.device.os,
            addresses: correlated.device.addresses,
            tags: correlated.device.tags,
            user: correlated.device.user,
            online: correlated.device.online,
            connected_to_control: correlated.device.connected_to_control,
            last_seen: correlated.device.last_seen,
            candidates: correlated
                .candidates
                .iter()
                .map(|candidate| CorrelationCandidateDto {
                    machine_id: candidate.machine_id.clone(),
                    machine_name: candidate.machine_name.clone(),
                    machine_status: candidate.machine_status.id().to_owned(),
                    reference: candidate.reference.clone(),
                    kind: candidate.kind.id().to_owned(),
                })
                .collect(),
        }
    }
}

/// The configure request: the OAuth client's id and secret. The secret is
/// stored encrypted and never returned by any endpoint.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigureTailnetRequest {
    /// The OAuth client identifier.
    pub client_id: String,
    /// The OAuth client secret (write-only).
    pub client_secret: String,
}

/// The import request: the SSH login user and port for the draft.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImportTailnetDeviceRequest {
    /// The SSH login user on the target machine.
    pub user: String,
    /// The SSH port; 22 when omitted.
    pub port: Option<u16>,
}

/// The integration's status.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/tailnet/status",
    tag = "tailnet",
    operation_id = "getTailnetStatus",
    responses(
        (
            status = 200,
            description = "The integration's status.",
            body = Resource<TailnetStatusDto>
        ),
        (
            status = 403,
            description = "The caller may not read the tailnet surface.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn get_tailnet_status(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<Resource<TailnetStatusDto>>, ApiErrorResponse> {
    let tailnet = tailnet_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let status = tailnet
        .status(state.authorizer.as_ref(), &principal)
        .await
        .map_err(|error| map_tailnet_error(&error, correlation_id))?;
    state
        .events
        .publish(fleet_application::events::EventKind::TailnetChanged);
    Ok(Json(Resource::new(TailnetStatusDto {
        configured: status.configured,
        client_id: status.client_id,
        scope: status.scope.to_owned(),
    })))
}

/// Stores the OAuth client. The secret is write-only.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    put,
    path = "/tailnet/config",
    tag = "tailnet",
    operation_id = "configureTailnet",
    request_body = ConfigureTailnetRequest,
    responses(
        (
            status = 200,
            description = "The integration is configured; the secret is never echoed.",
            body = Resource<TailnetStatusDto>
        ),
        (
            status = 400,
            description = "The request is malformed.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not configure the integration.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn configure_tailnet(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Json(request): Json<ConfigureTailnetRequest>,
) -> Result<Json<Resource<TailnetStatusDto>>, ApiErrorResponse> {
    let tailnet = tailnet_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let status = tailnet
        .configure(
            state.authorizer.as_ref(),
            &principal,
            &request.client_id,
            &request.client_secret,
        )
        .await
        .map_err(|error| map_tailnet_error(&error, correlation_id))?;
    state
        .events
        .publish(fleet_application::events::EventKind::TailnetChanged);
    Ok(Json(Resource::new(TailnetStatusDto {
        configured: status.configured,
        client_id: status.client_id,
        scope: status.scope.to_owned(),
    })))
}

/// Removes the stored OAuth client.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    delete,
    path = "/tailnet/config",
    tag = "tailnet",
    operation_id = "clearTailnet",
    responses(
        (
            status = 200,
            description = "The integration is cleared.",
            body = Resource<TailnetStatusDto>
        ),
        (
            status = 403,
            description = "The caller may not configure the integration.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn clear_tailnet(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<Resource<TailnetStatusDto>>, ApiErrorResponse> {
    let tailnet = tailnet_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let status = tailnet
        .clear(state.authorizer.as_ref(), &principal)
        .await
        .map_err(|error| map_tailnet_error(&error, correlation_id))?;
    Ok(Json(Resource::new(TailnetStatusDto {
        configured: status.configured,
        client_id: status.client_id,
        scope: status.scope.to_owned(),
    })))
}

/// The list-tailnet query parameters.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListTailnetDevicesParams {
    /// The maximum number of devices to return.
    pub limit: Option<u32>,
    /// The opaque cursor from a previous page (the last device's node id).
    pub cursor: Option<String>,
}

/// Lists the tailnet's devices, correlated with Fleet machines by evidence
/// only.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unconfigured
/// integration, a source failure, or a backend failure.
#[utoipa::path(
    get,
    path = "/tailnet/devices",
    tag = "tailnet",
    operation_id = "listTailnetDevices",
    params(
        ("limit" = Option<u32>, Query, description = "The maximum number of devices to return."),
        ("cursor" = Option<String>, Query, description = "The opaque cursor from a previous page (the last device's node id).")
    ),
    responses(
        (
            status = 200,
            description = "A page of correlated devices.",
            body = Page<CorrelatedDeviceDto>
        ),
        (
            status = 403,
            description = "The caller may not read the tailnet surface.",
            body = crate::error::ApiError
        ),
        (
            status = 409,
            description = "The integration is not configured.",
            body = crate::error::ApiError
        ),
        (
            status = 429,
            description = "The tailnet source asked to slow down.",
            body = crate::error::ApiError
        ),
        (
            status = 502,
            description = "The tailnet source failed.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn list_tailnet_devices(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<ListTailnetDevicesParams>,
) -> Result<Json<Page<CorrelatedDeviceDto>>, ApiErrorResponse> {
    let tailnet = tailnet_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let limit = params
        .limit
        .unwrap_or(crate::envelope::DEFAULT_PAGE_LIMIT)
        .min(crate::envelope::MAX_PAGE_LIMIT);
    let mut devices = tailnet
        .list(
            state.authorizer.as_ref(),
            &principal,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_tailnet_error(&error, correlation_id))?;
    // The cursor is the last node id of the previous page; everything at or
    // before it is dropped before the limit is applied.
    if let Some(cursor) = &params.cursor {
        devices.retain(|correlated| correlated.device.node_id.as_str() > cursor.as_str());
    }
    let shown = devices
        .drain(
            ..usize::try_from(limit)
                .unwrap_or(usize::MAX)
                .min(devices.len()),
        )
        .map(CorrelatedDeviceDto::from)
        .collect::<Vec<_>>();
    let next_cursor = (!devices.is_empty())
        .then(|| shown.last().map(|d| d.node_id.clone()))
        .flatten();
    Ok(Json(Page {
        items: shown,
        page: PageInfo { next_cursor, limit },
    }))
}

/// Imports a tailnet device as an SSH onboarding draft: the draft carries
/// the device's Tailscale IPv4 address; everything after is the standard
/// staged flow (test, explicit fingerprint confirm, review, add).
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown device, or a
/// backend failure.
#[utoipa::path(
    post,
    path = "/tailnet/devices/{nodeId}/import",
    tag = "tailnet",
    operation_id = "importTailnetDevice",
    params(
        ("nodeId" = String, Path, description = "The device's node id.")
    ),
    request_body = ImportTailnetDeviceRequest,
    responses(
        (
            status = 201,
            description = "The onboarding draft was created; continue with the onboarding flow.",
            body = Resource<crate::onboarding::OnboardingDraftDetailDto>
        ),
        (
            status = 404,
            description = "No such device.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not import.",
            body = crate::error::ApiError
        ),
        (
            status = 409,
            description = "The integration is not configured.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn import_tailnet_device(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: axum::http::HeaderMap,
    Path(node_id): Path<String>,
    Json(request): Json<ImportTailnetDeviceRequest>,
) -> Result<
    (
        StatusCode,
        Json<Resource<crate::onboarding::OnboardingDraftDetailDto>>,
    ),
    ApiErrorResponse,
> {
    let tailnet = tailnet_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let draft = tailnet
        .import(
            state.authorizer.as_ref(),
            &principal,
            &node_id,
            &request.user,
            request.port,
            headers
                .get(crate::IDEMPOTENCY_KEY_HEADER)
                .and_then(|value| value.to_str().ok()),
        )
        .await
        .map_err(|error| map_tailnet_error(&error, correlation_id))?;
    state
        .events
        .publish(fleet_application::events::EventKind::OnboardingChanged);
    Ok((
        StatusCode::CREATED,
        Json(Resource::new(
            crate::onboarding::OnboardingDraftDetailDto::from(draft),
        )),
    ))
}
