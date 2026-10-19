//! The external accounts surface: Coolify and Cloudflare API-token
//! accounts (FM-1001).
//!
//! This adapter decides nothing: it translates HTTP into the application's
//! use cases and their outcomes into the public envelopes. The token is
//! write-only: it arrives in a create or update request and is never
//! returned by any endpoint. The use cases take their wiring from a
//! request extension set by the controller, so the shared API state is not
//! widened for them.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use fleet_application::external_accounts::{
    CreateExternalAccount, ExternalAccount, ExternalAccountError, ExternalAccounts,
    UpdateExternalAccount,
};
use fleet_core::{CorrelationId, ErrorCode, ExternalProviderKind, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};

/// The provider kinds an account may belong to.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExternalProviderKindDto {
    /// A Coolify instance.
    Coolify,
    /// Cloudflare.
    Cloudflare,
}

impl From<ExternalProviderKindDto> for ExternalProviderKind {
    fn from(kind: ExternalProviderKindDto) -> Self {
        match kind {
            ExternalProviderKindDto::Coolify => Self::Coolify,
            ExternalProviderKindDto::Cloudflare => Self::Cloudflare,
        }
    }
}

impl From<ExternalProviderKind> for ExternalProviderKindDto {
    fn from(kind: ExternalProviderKind) -> Self {
        match kind {
            ExternalProviderKind::Coolify => Self::Coolify,
            ExternalProviderKind::Cloudflare => Self::Cloudflare,
        }
    }
}

/// The classified outcome of a probe.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatusDto {
    /// Reachable and authorized, and every permission the probe could
    /// verify is present; see `unverified` for what it could not check.
    Ok,
    /// The service could not be reached.
    Unreachable,
    /// The service refused the token.
    Unauthorized,
    /// The token is valid but lacks permissions Fleet needs.
    InsufficientPermission,
}

impl From<fleet_core::ProbeStatus> for ProbeStatusDto {
    fn from(status: fleet_core::ProbeStatus) -> Self {
        match status {
            fleet_core::ProbeStatus::Ok => Self::Ok,
            fleet_core::ProbeStatus::Unreachable => Self::Unreachable,
            fleet_core::ProbeStatus::Unauthorized => Self::Unauthorized,
            fleet_core::ProbeStatus::InsufficientPermission => Self::InsufficientPermission,
        }
    }
}

/// The latest probe of an account.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExternalProbeDto {
    /// The classification.
    pub status: ProbeStatusDto,
    /// A short, redacted explanation.
    pub detail: String,
    /// Permissions the token was seen to hold.
    pub granted: Vec<String>,
    /// Permissions Fleet needs that the token was seen to lack.
    pub missing: Vec<String>,
    /// Permissions the probe did not verify: it never calls a route that
    /// could change state, so their state is unknown.
    pub unverified: Vec<String>,
    /// When the probe ran (epoch millis).
    pub checked_at: i64,
}

/// One external provider account. The token is never here.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExternalAccountDto {
    /// The account's identity.
    pub id: String,
    /// The provider kind.
    pub kind: ExternalProviderKindDto,
    /// The operator-facing label, unique within the kind.
    pub label: String,
    /// The provider's API base URL.
    pub base_url: String,
    /// The provider-side account id (Cloudflare account-owned tokens).
    pub account_id: Option<String>,
    /// Free-form operator notes.
    pub notes: String,
    /// A policy the stored record breaks: `https_required` for an http base
    /// URL that is not a loopback address. Such an account is never probed
    /// or discovered until its base URL is edited to https.
    pub policy_violation: Option<String>,
    /// The latest probe, absent until one runs after the last credential
    /// or endpoint change.
    pub last_probe: Option<ExternalProbeDto>,
    /// When the account was created (epoch millis).
    pub created_at: i64,
    /// When the account last changed (epoch millis).
    pub updated_at: i64,
}

impl From<ExternalAccount> for ExternalAccountDto {
    fn from(account: ExternalAccount) -> Self {
        Self {
            policy_violation: account.policy_violation().map(str::to_owned),
            id: account.id,
            kind: account.kind.into(),
            label: account.label,
            base_url: account.base_url,
            account_id: account.scope_id,
            notes: account.notes,
            last_probe: account.last_probe.map(|probe| ExternalProbeDto {
                status: probe.report.status.into(),
                detail: probe.report.detail,
                granted: probe.report.granted,
                missing: probe.report.missing,
                unverified: probe.report.unverified,
                checked_at: probe.checked_at,
            }),
            created_at: account.created_at,
            updated_at: account.updated_at,
        }
    }
}

/// The create-account request. The token is write-only.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateExternalAccountRequest {
    /// The provider kind.
    pub kind: ExternalProviderKindDto,
    /// The operator-facing label, unique within the kind.
    pub label: String,
    /// The API base URL; Cloudflare defaults to its public API, Coolify
    /// needs the instance URL.
    pub base_url: Option<String>,
    /// The Cloudflare account id, for account-owned tokens.
    pub account_id: Option<String>,
    /// Free-form notes.
    pub notes: Option<String>,
    /// The API token (write-only).
    pub token: String,
}

/// The update-account request. Absent fields are left alone.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateExternalAccountRequest {
    /// A new label.
    pub label: Option<String>,
    /// A new base URL.
    pub base_url: Option<String>,
    /// A new Cloudflare account id; an empty string clears it.
    pub account_id: Option<String>,
    /// New notes.
    pub notes: Option<String>,
    /// A replacement API token (write-only).
    pub token: Option<String>,
}

impl std::fmt::Debug for CreateExternalAccountRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateExternalAccountRequest")
            .field("kind", &self.kind)
            .field("label", &self.label)
            .field("base_url", &self.base_url)
            .field("account_id", &self.account_id)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for UpdateExternalAccountRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateExternalAccountRequest")
            .field("label", &self.label)
            .field("base_url", &self.base_url)
            .field("account_id", &self.account_id)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

/// The list-accounts query parameters.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListExternalAccountsParams {
    /// Restrict to one provider kind.
    pub kind: Option<ExternalProviderKindDto>,
    /// The maximum number of accounts to return.
    pub limit: Option<u32>,
    /// The opaque cursor: the last account id of the previous page.
    pub cursor: Option<String>,
}

fn accounts_or_error(
    extension: Option<Extension<Arc<ExternalAccounts>>>,
    correlation_id: CorrelationId,
) -> Result<Arc<ExternalAccounts>, ApiErrorResponse> {
    extension.map(|Extension(accounts)| accounts).ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("external_accounts_unavailable")
                .expect("the literal is valid error code syntax"),
            "the external accounts surface is not wired; the controller needs its database and secret store",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

pub(crate) fn map_error(
    error: &ExternalAccountError,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    let (status, code, retry): (StatusCode, &str, RetryClass) = match error {
        ExternalAccountError::Denied(_) => (StatusCode::FORBIDDEN, "denied", RetryClass::Never),
        ExternalAccountError::NotFound { .. } => {
            (StatusCode::NOT_FOUND, "not_found", RetryClass::Never)
        }
        ExternalAccountError::Conflict { .. } => {
            (StatusCode::CONFLICT, "conflict", RetryClass::Never)
        }
        ExternalAccountError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
        ),
        ExternalAccountError::NoSecret { .. } => (
            StatusCode::CONFLICT,
            "external_account_no_secret",
            RetryClass::Never,
        ),
        ExternalAccountError::Credentials(_) | ExternalAccountError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    let message = match error {
        ExternalAccountError::Backend { .. } | ExternalAccountError::Credentials(_) => {
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

/// Lists external provider accounts.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/external-accounts",
    tag = "external-accounts",
    operation_id = "listExternalAccounts",
    responses(
        (
            status = 200,
            description = "The accounts, newest first.",
            body = Page<ExternalAccountDto>
        ),
        (
            status = 403,
            description = "The caller may not read external accounts.",
            body = crate::error::ApiError
        ),
    ),
    params(
        (
            "kind" = Option<ExternalProviderKindDto>,
            Query,
            description = "Restrict to one provider kind."
        ),
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
pub async fn list_external_accounts(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    accounts: Option<Extension<Arc<ExternalAccounts>>>,
    Query(params): Query<ListExternalAccountsParams>,
) -> Result<Json<Page<ExternalAccountDto>>, ApiErrorResponse> {
    let accounts = accounts_or_error(accounts, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let limit = params
        .limit
        .filter(|limit| *limit > 0)
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .min(MAX_PAGE_LIMIT);
    let listed = accounts
        .list(
            state.authorizer.as_ref(),
            &principal,
            params.kind.map(Into::into),
            limit,
            params.cursor.as_deref(),
        )
        .await
        .map_err(|error| map_error(&error, correlation_id))?;
    let next_cursor = (listed.len() == usize::try_from(limit).unwrap_or(0))
        .then(|| listed.last().map(|account| account.id.clone()))
        .flatten();
    Ok(Json(Page {
        page: PageInfo { next_cursor, limit },
        items: listed.into_iter().map(Into::into).collect(),
    }))
}

/// Reads one external provider account.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown account.
#[utoipa::path(
    get,
    path = "/external-accounts/{accountId}",
    tag = "external-accounts",
    operation_id = "getExternalAccount",
    params(("accountId" = String, Path, description = "The account's identity.")),
    responses(
        (status = 200, description = "The account.", body = Resource<ExternalAccountDto>),
        (status = 403, description = "The caller may not read external accounts.", body = crate::error::ApiError),
        (status = 404, description = "The account does not exist.", body = crate::error::ApiError),
    )
)]
pub async fn get_external_account(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    accounts: Option<Extension<Arc<ExternalAccounts>>>,
    Path(account_id): Path<String>,
) -> Result<Json<Resource<ExternalAccountDto>>, ApiErrorResponse> {
    let accounts = accounts_or_error(accounts, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let account = accounts
        .get(state.authorizer.as_ref(), &principal, &account_id)
        .await
        .map_err(|error| map_error(&error, correlation_id))?;
    Ok(Json(Resource::new(account.into())))
}

/// Registers an account and stores its token.
///
/// # Errors
///
/// Returns the public error envelope on refusal, conflict, or backend
/// failure.
#[utoipa::path(
    post,
    path = "/external-accounts",
    tag = "external-accounts",
    operation_id = "createExternalAccount",
    request_body = CreateExternalAccountRequest,
    responses(
        (status = 201, description = "The account was created.", body = Resource<ExternalAccountDto>),
        (status = 400, description = "The request is malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not configure external accounts.", body = crate::error::ApiError),
        (status = 409, description = "The label is taken for that kind.", body = crate::error::ApiError),
    )
)]
pub async fn create_external_account(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    accounts: Option<Extension<Arc<ExternalAccounts>>>,
    body: Result<Json<CreateExternalAccountRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<ExternalAccountDto>>), ApiErrorResponse> {
    let accounts = accounts_or_error(accounts, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // The rejection is never echoed: its text can quote the token.
    let Json(request) = body.map_err(|_| {
        crate::machines::invalid_request(
            "the request body is not valid JSON for this request",
            correlation_id,
        )
    })?;
    let account = accounts
        .create(
            state.authorizer.as_ref(),
            &principal,
            CreateExternalAccount {
                kind: request.kind.into(),
                label: request.label,
                base_url: request.base_url,
                scope_id: request.account_id,
                notes: request.notes,
            },
            &request.token,
        )
        .await
        .map_err(|error| map_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(account.into()))))
}

/// Updates an account; a supplied token replaces the stored one.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown account, a
/// conflict, or a malformed request.
#[utoipa::path(
    patch,
    path = "/external-accounts/{accountId}",
    tag = "external-accounts",
    operation_id = "updateExternalAccount",
    params(("accountId" = String, Path, description = "The account's identity.")),
    request_body = UpdateExternalAccountRequest,
    responses(
        (status = 200, description = "The updated account.", body = Resource<ExternalAccountDto>),
        (status = 400, description = "The request is malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not configure external accounts.", body = crate::error::ApiError),
        (status = 404, description = "The account does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The label is taken for that kind.", body = crate::error::ApiError),
    )
)]
pub async fn update_external_account(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    accounts: Option<Extension<Arc<ExternalAccounts>>>,
    Path(account_id): Path<String>,
    body: Result<Json<UpdateExternalAccountRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Resource<ExternalAccountDto>>, ApiErrorResponse> {
    let accounts = accounts_or_error(accounts, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // The rejection is never echoed: its text can quote the token.
    let Json(request) = body.map_err(|_| {
        crate::machines::invalid_request(
            "the request body is not valid JSON for this request",
            correlation_id,
        )
    })?;
    let account = accounts
        .update(
            state.authorizer.as_ref(),
            &principal,
            &account_id,
            UpdateExternalAccount {
                label: request.label,
                base_url: request.base_url,
                scope_id: request.account_id,
                notes: request.notes,
            },
            request.token.as_deref(),
        )
        .await
        .map_err(|error| map_error(&error, correlation_id))?;
    Ok(Json(Resource::new(account.into())))
}

/// Removes an account and its token.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown account, or a
/// backend failure.
#[utoipa::path(
    delete,
    path = "/external-accounts/{accountId}",
    tag = "external-accounts",
    operation_id = "deleteExternalAccount",
    params(("accountId" = String, Path, description = "The account's identity.")),
    responses(
        (status = 204, description = "The account was removed."),
        (status = 403, description = "The caller may not configure external accounts.", body = crate::error::ApiError),
        (status = 404, description = "The account does not exist.", body = crate::error::ApiError),
    )
)]
pub async fn delete_external_account(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    accounts: Option<Extension<Arc<ExternalAccounts>>>,
    Path(account_id): Path<String>,
) -> Result<StatusCode, ApiErrorResponse> {
    let accounts = accounts_or_error(accounts, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    accounts
        .delete(state.authorizer.as_ref(), &principal, &account_id)
        .await
        .map_err(|error| map_error(&error, correlation_id))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Probes an account with its stored token and records the classified
/// result. An unreachable or refusing service is a successful probe whose
/// status says so.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown account, or a
/// missing stored token.
#[utoipa::path(
    post,
    path = "/external-accounts/{accountId}/probe",
    tag = "external-accounts",
    operation_id = "probeExternalAccount",
    params(("accountId" = String, Path, description = "The account's identity.")),
    responses(
        (status = 200, description = "The account with its fresh probe result.", body = Resource<ExternalAccountDto>),
        (status = 403, description = "The caller may not configure external accounts.", body = crate::error::ApiError),
        (status = 404, description = "The account does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The account's token is not in the secret store.", body = crate::error::ApiError),
    )
)]
pub async fn probe_external_account(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    accounts: Option<Extension<Arc<ExternalAccounts>>>,
    Path(account_id): Path<String>,
) -> Result<Json<Resource<ExternalAccountDto>>, ApiErrorResponse> {
    let accounts = accounts_or_error(accounts, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let account = accounts
        .probe(state.authorizer.as_ref(), &principal, &account_id)
        .await
        .map_err(|error| map_error(&error, correlation_id))?;
    Ok(Json(Resource::new(account.into())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_debug_output_never_carries_the_token() {
        let create: CreateExternalAccountRequest = serde_json::from_str(
            r#"{"kind":"coolify","label":"x","baseUrl":"https://c.example.test","token":"super-secret-1234"}"#,
        )
        .unwrap();
        let update: UpdateExternalAccountRequest =
            serde_json::from_str(r#"{"token":"super-secret-5678"}"#).unwrap();
        let rendered = format!("{create:?} {update:?}");
        assert!(!rendered.contains("super-secret"), "{rendered}");
        assert!(rendered.contains("<redacted>"));
    }
}
