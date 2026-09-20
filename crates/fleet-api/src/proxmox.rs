//! The Proxmox surface: account management with the TLS trust flow and
//! cluster discovery (FM-600).
//!
//! This adapter decides nothing about trust; it translates HTTP into the
//! application's use cases and their outcomes into the public envelopes.
//! The token secret is write-only: it arrives in the create request and is
//! never returned by any endpoint. Discovery is a read; account mutations
//! are audited through the application layer.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use fleet_application::proxmox::{NewProxmoxAccount, ProxmoxAccount, ProxmoxUseCaseError};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use std::str::FromStr as _;
use utoipa::ToSchema;

use crate::envelope::{Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};

/// Extracts the Proxmox use cases from the API state, or answers with the
/// standard envelope when the controller was composed without one.
fn proxmox_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<fleet_application::proxmox::ProxmoxAccounts>, ApiErrorResponse> {
    state.proxmox.clone().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "the Proxmox surface is not wired; the controller needs its database and secret store",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// Maps a Proxmox use-case outcome onto the public error envelope, once.
fn map_proxmox_error(
    error: &ProxmoxUseCaseError,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    let (status, code, retry): (StatusCode, &str, RetryClass) = match error {
        ProxmoxUseCaseError::Denied(_) => (StatusCode::FORBIDDEN, "denied", RetryClass::Never),
        ProxmoxUseCaseError::NotFound { .. } => {
            (StatusCode::NOT_FOUND, "not_found", RetryClass::Never)
        }
        ProxmoxUseCaseError::Conflict { .. } => {
            (StatusCode::CONFLICT, "conflict", RetryClass::Never)
        }
        ProxmoxUseCaseError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
        ),
        ProxmoxUseCaseError::UnconfirmedTrust { .. } => (
            StatusCode::CONFLICT,
            "proxmox_unconfirmed",
            RetryClass::Never,
        ),
        ProxmoxUseCaseError::NoSecret { .. } => {
            (StatusCode::CONFLICT, "proxmox_no_secret", RetryClass::Never)
        }
        ProxmoxUseCaseError::Source(fleet_application::proxmox::ProxmoxSourceError::Auth) => {
            (StatusCode::BAD_GATEWAY, "proxmox_auth", RetryClass::Backoff)
        }
        ProxmoxUseCaseError::Source(
            fleet_application::proxmox::ProxmoxSourceError::FingerprintMismatch { .. },
        ) => (
            StatusCode::CONFLICT,
            "proxmox_fingerprint_mismatch",
            RetryClass::Never,
        ),
        ProxmoxUseCaseError::Source(_) => (
            StatusCode::BAD_GATEWAY,
            "proxmox_source",
            RetryClass::Backoff,
        ),
        ProxmoxUseCaseError::Credentials(_) | ProxmoxUseCaseError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    let message = match error {
        ProxmoxUseCaseError::Backend { .. } => {
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

/// One configured Proxmox account. The token secret is never here.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxAccountDto {
    /// The account's identity.
    pub id: String,
    /// The operator-facing name.
    pub name: String,
    /// The PVE host.
    pub host: String,
    /// The API port.
    pub port: u16,
    /// The API token id (`user@realm!tokenname`), not secret on its own.
    pub token_id: String,
    /// The trust state: `unconfirmed` until the fingerprint is pinned.
    pub fingerprint_state: String,
    /// The pinned fingerprint, once confirmed.
    pub fingerprint: Option<String>,
    /// When the account was created.
    pub created_at: i64,
}

impl From<ProxmoxAccount> for ProxmoxAccountDto {
    fn from(account: ProxmoxAccount) -> Self {
        Self {
            id: account.id,
            name: account.name,
            host: account.host,
            port: account.port,
            token_id: account.token_id,
            fingerprint_state: match account.fingerprint {
                Some(_) => "confirmed".to_owned(),
                None => "unconfirmed".to_owned(),
            },
            fingerprint: account.fingerprint,
            created_at: account.created_at,
        }
    }
}

/// One normalized discovery observation.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxResourceDto {
    /// The normalized kind: `node`, `qemu`, `lxc`, `qemu-template`, or
    /// `storage`.
    pub kind: String,
    /// The cluster-visible id.
    pub id: String,
    /// The hosting node, when the resource has one.
    pub node: Option<String>,
    /// The VMID, when the resource has one.
    pub vmid: Option<u32>,
    /// The display name, when carried.
    pub name: Option<String>,
    /// The PVE status string, when carried.
    pub status: Option<String>,
    /// The account that observed the resource.
    pub account_id: String,
    /// The PVE version the observation came from.
    pub pve_version: String,
    /// When the observation was taken.
    pub observed_at: i64,
}

/// The discovery snapshot.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxDiscoveryDto {
    /// The account that produced the snapshot.
    pub account_id: String,
    /// The PVE version seen.
    pub pve_version: String,
    /// The normalized resources.
    pub resources: Vec<ProxmoxResourceDto>,
    /// The per-resource normalization warnings.
    pub warnings: Vec<String>,
    /// The count the API reported.
    pub reported_count: usize,
    /// When the snapshot was taken.
    pub observed_at: i64,
}

/// The create-account request. The token secret is write-only.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateProxmoxAccountRequest {
    /// The operator-facing name.
    pub name: String,
    /// The PVE host (IP or DNS name).
    pub host: String,
    /// The API port; 8006 when omitted.
    pub port: Option<u16>,
    /// The API token id (`user@realm!tokenname`).
    pub token_id: String,
    /// The API token secret (write-only).
    pub token_secret: String,
}

/// The confirm-trust request: the fingerprint the caller observed.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmProxmoxFingerprintRequest {
    /// The SHA-256 fingerprint as observed (colons optional).
    pub fingerprint: String,
}

/// Lists the configured accounts.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/proxmox/accounts",
    tag = "proxmox",
    operation_id = "listProxmoxAccounts",
    responses(
        (
            status = 200,
            description = "The configured accounts, newest first.",
            body = Page<ProxmoxAccountDto>
        ),
        (
            status = 403,
            description = "The caller may not read the Proxmox surface.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn list_proxmox_accounts(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<Page<ProxmoxAccountDto>>, ApiErrorResponse> {
    let proxmox = proxmox_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let accounts = proxmox
        .list(state.authorizer.as_ref(), &principal)
        .await
        .map_err(|error| map_proxmox_error(&error, correlation_id))?;
    let items: Vec<ProxmoxAccountDto> = accounts.into_iter().map(Into::into).collect();
    Ok(Json(Page {
        page: PageInfo {
            next_cursor: None,
            limit: items.len().try_into().unwrap_or(u32::MAX),
        },
        items,
    }))
}

/// Registers an account and stores its token secret. The account starts
/// `unconfirmed`: discovery stays locked until the fingerprint is confirmed.
///
/// # Errors
///
/// Returns the public error envelope on refusal, conflict, or backend
/// failure.
#[utoipa::path(
    post,
    path = "/proxmox/accounts",
    tag = "proxmox",
    operation_id = "createProxmoxAccount",
    request_body = CreateProxmoxAccountRequest,
    responses(
        (
            status = 201,
            description = "The account was created; confirm its fingerprint before discovery.",
            body = Resource<ProxmoxAccountDto>
        ),
        (
            status = 400,
            description = "The request is malformed.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not configure the Proxmox surface.",
            body = crate::error::ApiError
        ),
        (
            status = 409,
            description = "The account name is taken.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn create_proxmox_account(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Json(request): Json<CreateProxmoxAccountRequest>,
) -> Result<(StatusCode, Json<Resource<ProxmoxAccountDto>>), ApiErrorResponse> {
    let proxmox = proxmox_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let account = proxmox
        .create(
            state.authorizer.as_ref(),
            &principal,
            NewProxmoxAccount {
                name: request.name,
                host: request.host,
                port: request.port,
                token_id: request.token_id,
            },
            &request.token_secret,
        )
        .await
        .map_err(|error| map_proxmox_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(account.into()))))
}

/// Removes an account and its secret.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown account, or a
/// backend failure.
#[utoipa::path(
    delete,
    path = "/proxmox/accounts/{accountId}",
    tag = "proxmox",
    operation_id = "deleteProxmoxAccount",
    params(
        (
            "accountId" = String,
            Path,
            description = "The account's identity."
        ),
    ),
    responses(
        (
            status = 204,
            description = "The account was removed."
        ),
        (
            status = 403,
            description = "The caller may not configure the Proxmox surface.",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "The account does not exist.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn delete_proxmox_account(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(account_id): Path<String>,
) -> Result<StatusCode, ApiErrorResponse> {
    let proxmox = proxmox_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    proxmox
        .delete(state.authorizer.as_ref(), &principal, &account_id)
        .await
        .map_err(|error| map_proxmox_error(&error, correlation_id))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Captures the host's certificate fingerprint without sending any
/// credential. The report is the input to the confirm step.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown account, or an
/// unreachable host.
#[utoipa::path(
    post,
    path = "/proxmox/accounts/{accountId}/observe",
    tag = "proxmox",
    operation_id = "observeProxmoxFingerprint",
    params(
        (
            "accountId" = String,
            Path,
            description = "The account's identity."
        ),
    ),
    responses(
        (
            status = 200,
            description = "The observed fingerprint; confirm it to trust the host.",
            body = Resource<ProxmoxFingerprintDto>
        ),
        (
            status = 403,
            description = "The caller may not read the Proxmox surface.",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "The account does not exist.",
            body = crate::error::ApiError
        ),
        (
            status = 502,
            description = "The host is unreachable.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn observe_proxmox_fingerprint(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(account_id): Path<String>,
) -> Result<Json<Resource<ProxmoxFingerprintDto>>, ApiErrorResponse> {
    let proxmox = proxmox_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let observed = proxmox
        .observe(state.authorizer.as_ref(), &principal, &account_id)
        .await
        .map_err(|error| map_proxmox_error(&error, correlation_id))?;
    Ok(Json(Resource::new(ProxmoxFingerprintDto {
        account_id,
        fingerprint: observed,
    })))
}

/// The observed fingerprint report.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxFingerprintDto {
    /// The account the fingerprint was observed for.
    pub account_id: String,
    /// The host certificate's SHA-256 fingerprint.
    pub fingerprint: String,
}

/// Pins the confirmed fingerprint as the account's trust anchor.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown account, or a
/// malformed fingerprint.
#[utoipa::path(
    post,
    path = "/proxmox/accounts/{accountId}/confirm",
    tag = "proxmox",
    operation_id = "confirmProxmoxFingerprint",
    params(
        (
            "accountId" = String,
            Path,
            description = "The account's identity."
        ),
    ),
    request_body = ConfirmProxmoxFingerprintRequest,
    responses(
        (
            status = 200,
            description = "The fingerprint is pinned; discovery is unlocked.",
            body = Resource<ProxmoxAccountDto>
        ),
        (
            status = 400,
            description = "The fingerprint is malformed.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not configure the Proxmox surface.",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "The account does not exist.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn confirm_proxmox_fingerprint(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(account_id): Path<String>,
    Json(request): Json<ConfirmProxmoxFingerprintRequest>,
) -> Result<Json<Resource<ProxmoxAccountDto>>, ApiErrorResponse> {
    let proxmox = proxmox_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let account = proxmox
        .confirm(
            state.authorizer.as_ref(),
            &principal,
            &account_id,
            &request.fingerprint,
        )
        .await
        .map_err(|error| map_proxmox_error(&error, correlation_id))?;
    Ok(Json(Resource::new(account.into())))
}

/// Discovers the cluster through one trusted account.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unconfirmed account, or
/// a source failure.
#[utoipa::path(
    get,
    path = "/proxmox/accounts/{accountId}/discovery",
    tag = "proxmox",
    operation_id = "discoverProxmoxCluster",
    params(
        (
            "accountId" = String,
            Path,
            description = "The account's identity."
        ),
    ),
    responses(
        (
            status = 200,
            description = "The discovery snapshot, availability-honest.",
            body = Resource<ProxmoxDiscoveryDto>
        ),
        (
            status = 403,
            description = "The caller may not read the Proxmox surface.",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "The account does not exist.",
            body = crate::error::ApiError
        ),
        (
            status = 409,
            description = "The account's trust is unconfirmed or its fingerprint was refused.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn discover_proxmox_cluster(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(account_id): Path<String>,
) -> Result<Json<Resource<ProxmoxDiscoveryDto>>, ApiErrorResponse> {
    let proxmox = proxmox_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let discovery = proxmox
        .discover(
            state.authorizer.as_ref(),
            &principal,
            &account_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_proxmox_error(&error, correlation_id))?;
    Ok(Json(Resource::new(ProxmoxDiscoveryDto {
        account_id: discovery.account_id,
        pve_version: discovery.pve_version,
        resources: discovery
            .resources
            .into_iter()
            .map(|resource| ProxmoxResourceDto {
                kind: resource.kind,
                id: resource.id,
                node: resource.node,
                vmid: resource.vmid,
                name: resource.name,
                status: resource.status,
                account_id: resource.account_id,
                pve_version: resource.pve_version,
                observed_at: resource.observed_at,
            })
            .collect(),
        warnings: discovery.warnings,
        reported_count: discovery.reported_count,
        observed_at: discovery.observed_at,
    })))
}
