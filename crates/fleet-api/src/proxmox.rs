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
    extract::{Path, Query, State},
    http::StatusCode,
};
use fleet_application::proxmox::{
    AssociatedGuest, NewProxmoxAccount, ProxmoxAccount, ProxmoxUseCaseError,
};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use std::str::FromStr as _;
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Page, PageInfo, Resource};
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

/// One discovered guest with its Fleet-machine association candidates.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AssociatedGuestDto {
    /// The normalized kind: `qemu` or `lxc`.
    pub kind: String,
    /// The cluster-visible id.
    pub id: String,
    /// The hosting node.
    pub node: Option<String>,
    /// The VMID.
    pub vmid: Option<u32>,
    /// The display name, when carried.
    pub name: Option<String>,
    /// The PVE status string, when carried.
    pub status: Option<String>,
    /// The config's MAC addresses, normalized.
    pub macs: Vec<String>,
    /// The guest-agent view, when the guest has one.
    pub agent: Option<ProviderAgentDto>,
    /// The bounded per-surface warnings.
    pub warnings: Vec<String>,
    /// The PVE version the observation came from.
    pub pve_version: String,
    /// When the observation was taken.
    pub observed_at: i64,
    /// The Fleet machines this guest may be — evidence, never merged.
    pub candidates: Vec<AssociationCandidateDto>,
}

/// The guest-agent view.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAgentDto {
    /// The agent answered `info`: installed and reachable.
    pub online: bool,
    /// The agent version, when carried.
    pub version: Option<String>,
    /// The guest's OS name, when `get-osinfo` answered.
    pub os_name: Option<String>,
    /// The guest's kernel release, when carried.
    pub kernel: Option<String>,
    /// The network interfaces the agent saw.
    pub interfaces: Vec<ProviderInterfaceDto>,
}

/// One guest network interface.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInterfaceDto {
    /// The interface name inside the guest.
    pub name: String,
    /// The normalized MAC, when carried.
    pub mac: Option<String>,
    /// The interface's addresses.
    pub addresses: Vec<String>,
}

/// One Fleet machine a guest may be, with the evidence.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AssociationCandidateDto {
    /// The existing machine's identity.
    pub machine_id: String,
    /// The existing machine's name.
    pub machine_name: String,
    /// The machine's derived connectivity state.
    pub machine_status: String,
    /// Why: `mac_match`, `address_match`, or `name_match`.
    pub kind: String,
    /// The evidence value that matched.
    pub evidence: String,
}

impl From<AssociatedGuest> for AssociatedGuestDto {
    fn from(associated: AssociatedGuest) -> Self {
        Self {
            kind: associated.guest.kind,
            id: associated.guest.id,
            node: associated.guest.node,
            vmid: associated.guest.vmid,
            name: associated.guest.name,
            status: associated.guest.status,
            macs: associated.guest.macs,
            agent: associated.guest.agent.map(|agent| ProviderAgentDto {
                online: agent.online,
                version: agent.version,
                os_name: agent.os_name,
                kernel: agent.kernel,
                interfaces: agent
                    .interfaces
                    .into_iter()
                    .map(|interface| ProviderInterfaceDto {
                        name: interface.name,
                        mac: interface.mac,
                        addresses: interface.addresses,
                    })
                    .collect(),
            }),
            warnings: associated.guest.warnings,
            pve_version: associated.pve_version,
            observed_at: associated.observed_at,
            candidates: associated
                .candidates
                .into_iter()
                .map(|candidate| AssociationCandidateDto {
                    machine_id: candidate.machine_id,
                    machine_name: candidate.machine_name,
                    machine_status: candidate.machine_status,
                    kind: candidate.kind,
                    evidence: candidate.evidence,
                })
                .collect(),
        }
    }
}

/// The observe-guest request: which machine the guest's facts record onto.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ObserveProxmoxGuestRequest {
    /// The machine the guest is confirmed to be.
    pub machine_id: String,
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

/// The list-accounts query parameters.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListProxmoxAccountsParams {
    /// The maximum number of accounts to return.
    pub limit: Option<u32>,
    /// The opaque cursor: the last account id of the previous page.
    pub cursor: Option<String>,
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
    ),
    params(
        (
            "limit" = Option<u32>,
            Query,
            description = "The maximum number of accounts to return."
        ),
        (
            "cursor" = Option<String>,
            Query,
            description = "The opaque cursor: the last account id of the previous page."
        ),
    )
)]
pub async fn list_proxmox_accounts(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<ListProxmoxAccountsParams>,
) -> Result<Json<Page<ProxmoxAccountDto>>, ApiErrorResponse> {
    let proxmox = proxmox_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // A zero or absent limit means the default; the reported limit is the
    // clamp applied to the page, matching the sibling list endpoints.
    let limit = params
        .limit
        .filter(|limit| *limit > 0)
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .min(MAX_PAGE_LIMIT);
    let accounts = proxmox
        .list(
            state.authorizer.as_ref(),
            &principal,
            limit,
            params.cursor.as_deref(),
        )
        .await
        .map_err(|error| map_proxmox_error(&error, correlation_id))?;
    let next_cursor = (accounts.len() == usize::try_from(limit).unwrap_or(0))
        .then(|| accounts.last().map(|account| account.id.clone()))
        .flatten();
    let items: Vec<ProxmoxAccountDto> = accounts.into_iter().map(Into::into).collect();
    Ok(Json(Page {
        page: PageInfo { next_cursor, limit },
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

/// Lists the account's guests with their Fleet-machine association
/// candidates (evidence only).
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unconfirmed account, or
/// a source failure.
#[utoipa::path(
    get,
    path = "/proxmox/accounts/{accountId}/guests",
    tag = "proxmox",
    operation_id = "listProxmoxGuests",
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
            description = "The guests with their association candidates.",
            body = Page<AssociatedGuestDto>
        ),
        (
            status = 403,
            description = "The caller may not read the Proxmox surface.",
            body = crate::error::ApiError
        ),
        (
            status = 409,
            description = "The account's trust is unconfirmed.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn list_proxmox_guests(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(account_id): Path<String>,
) -> Result<Json<Page<AssociatedGuestDto>>, ApiErrorResponse> {
    let proxmox = proxmox_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let guests = proxmox
        .guests(
            state.authorizer.as_ref(),
            &principal,
            &account_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_proxmox_error(&error, correlation_id))?;
    let items: Vec<AssociatedGuestDto> = guests.into_iter().map(Into::into).collect();
    Ok(Json(Page {
        page: PageInfo {
            next_cursor: None,
            limit: items.len().try_into().unwrap_or(u32::MAX),
        },
        items,
    }))
}

/// Records one guest's facts onto a confirmed Fleet machine. The machine
/// funnel authorizes and audits the capability write.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown account,
/// guest, or machine, or a source failure.
#[utoipa::path(
    post,
    path = "/proxmox/accounts/{accountId}/guests/{vmid}/observe",
    tag = "proxmox",
    operation_id = "observeProxmoxGuest",
    params(
        (
            "accountId" = String,
            Path,
            description = "The account's identity."
        ),
        (
            "vmid" = u32,
            Path,
            description = "The guest's VMID."
        ),
    ),
    request_body = ObserveProxmoxGuestRequest,
    responses(
        (
            status = 204,
            description = "The guest's facts were recorded on the machine."
        ),
        (
            status = 403,
            description = "The caller may not read the Proxmox surface or write the machine's facts.",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "The account, guest, or machine does not exist.",
            body = crate::error::ApiError
        ),
        (
            status = 409,
            description = "The account's trust is unconfirmed or the source refused.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn observe_proxmox_guest(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path((account_id, vmid)): Path<(String, u32)>,
    Json(request): Json<ObserveProxmoxGuestRequest>,
) -> Result<StatusCode, ApiErrorResponse> {
    let proxmox = proxmox_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    proxmox
        .observe_guest(
            state.authorizer.as_ref(),
            &principal,
            &account_id,
            vmid,
            &request.machine_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_proxmox_error(&error, correlation_id))?;
    Ok(StatusCode::NO_CONTENT)
}
