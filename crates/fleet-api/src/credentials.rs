//! The delegated credential surface (ADR 0011): an operator issues, lists,
//! and revokes scoped, short-lived credentials for CI and agents. The rules
//! and the authorization are `fleet_application::credentials`'s; the token
//! is returned exactly once, by the issue response, with `Cache-Control:
//! no-store`, and is never logged or audited.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderName, StatusCode, header::CACHE_CONTROL},
};
use fleet_application::credentials::{
    CredentialError, Credentials, DelegatedCredential, IssueCredential,
};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};

fn credentials_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<Credentials>, ApiErrorResponse> {
    state.credentials.clone().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "delegated credentials are not wired; the controller needs its database",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

fn map_credential_error(
    error: &CredentialError,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    let (status, code, retry) = match error {
        CredentialError::Denied(_) => (StatusCode::FORBIDDEN, "denied", RetryClass::Never),
        CredentialError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
        ),
        CredentialError::NotFound { .. } => (StatusCode::NOT_FOUND, "not_found", RetryClass::Never),
        CredentialError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    let message = match error {
        CredentialError::Backend { .. } => {
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

/// A credential's metadata. The token and its hash are never part of it.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDto {
    /// The credential's identity.
    pub id: String,
    /// The owner label: the ownership identity of the leases it creates.
    pub owner: String,
    /// An operator's free-text label.
    pub label: String,
    /// Allowed Lab template ids.
    pub templates: Vec<String>,
    /// Allowed Lab template version ids.
    pub versions: Vec<String>,
    /// The administrator that issued it.
    pub issued_by: String,
    /// When it was issued (epoch millis).
    pub issued_at: i64,
    /// When it expires (epoch millis).
    pub expires_at: i64,
    /// When it was revoked (epoch millis), when it was.
    pub revoked_at: Option<i64>,
    /// `active`, `expired`, or `revoked`.
    pub status: String,
}

impl CredentialDto {
    fn new(credential: DelegatedCredential, now: i64) -> Self {
        let status = credential.status(now).id().to_owned();
        Self {
            id: credential.id,
            owner: credential.owner,
            label: credential.label,
            templates: credential.templates,
            versions: credential.versions,
            issued_by: credential.issued_by,
            issued_at: credential.issued_at,
            expires_at: credential.expires_at,
            revoked_at: credential.revoked_at,
            status,
        }
    }
}

/// A freshly issued credential: its metadata and the token, shown once.
#[derive(Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssuedCredentialDto {
    /// The credential's metadata.
    #[serde(flatten)]
    pub credential: CredentialDto,
    /// The bearer token. It is returned only by this response and cannot be
    /// read again; present it as `Authorization: Bearer <token>` (or set
    /// `FLEET_TOKEN` for `fleetctl`).
    pub token: String,
}

impl std::fmt::Debug for IssuedCredentialDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedCredentialDto")
            .field("credential", &self.credential)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// What to issue.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssueCredentialRequest {
    /// The owner label (`a-z`, `0-9`, `.`, `_`, `-`; at most 63).
    pub owner: String,
    /// The lifetime in seconds (60 to 86400).
    pub ttl_seconds: u64,
    /// Allowed Lab template ids.
    #[serde(default)]
    pub templates: Vec<String>,
    /// Allowed Lab template version ids.
    #[serde(default)]
    pub versions: Vec<String>,
    /// A free-text label.
    #[serde(default)]
    pub label: String,
}

/// Issues a delegated credential. The response carries the token exactly
/// once.
///
/// # Errors
///
/// Returns the public error envelope on refusal or a malformed request.
#[utoipa::path(
    post,
    path = "/credentials",
    tag = "credentials",
    operation_id = "issueCredential",
    request_body = IssueCredentialRequest,
    responses(
        (status = 201, description = "The credential was issued; the token is in this response only.", body = Resource<IssuedCredentialDto>),
        (status = 400, description = "The request is malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not issue credentials.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn issue_credential(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Json(request): Json<IssueCredentialRequest>,
) -> Result<
    (
        StatusCode,
        [(HeaderName, &'static str); 1],
        Json<Resource<IssuedCredentialDto>>,
    ),
    ApiErrorResponse,
> {
    let credentials = credentials_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let now = fleet_core::SystemClock::now_unix_millis();
    let issued = credentials
        .issue(
            state.authorizer.as_ref(),
            &principal.id,
            IssueCredential {
                owner: request.owner,
                ttl_seconds: request.ttl_seconds,
                templates: request.templates,
                versions: request.versions,
                label: request.label,
            },
            now,
        )
        .await
        .map_err(|error| map_credential_error(&error, correlation_id))?;
    Ok((
        StatusCode::CREATED,
        [(CACHE_CONTROL, "no-store")],
        Json(Resource::new(IssuedCredentialDto {
            credential: CredentialDto::new(issued.credential, now),
            token: issued.token,
        })),
    ))
}

/// Lists the delegated credentials' metadata, newest first.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/credentials",
    tag = "credentials",
    operation_id = "listCredentials",
    responses(
        (status = 200, description = "The credentials, newest first. Tokens are never listed.", body = Page<CredentialDto>),
        (status = 403, description = "The caller may not read credentials.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn list_credentials(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<Page<CredentialDto>>, ApiErrorResponse> {
    let credentials = credentials_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let now = fleet_core::SystemClock::now_unix_millis();
    let items: Vec<CredentialDto> = credentials
        .list(state.authorizer.as_ref(), &principal.id)
        .await
        .map_err(|error| map_credential_error(&error, correlation_id))?
        .into_iter()
        .map(|credential| CredentialDto::new(credential, now))
        .collect();
    Ok(Json(Page {
        page: PageInfo {
            next_cursor: None,
            limit: items.len().try_into().unwrap_or(u32::MAX),
        },
        items,
    }))
}

/// Revokes a credential. Its next request is refused.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown credential.
#[utoipa::path(
    post,
    path = "/credentials/{credentialId}/revoke",
    tag = "credentials",
    operation_id = "revokeCredential",
    params(("credentialId" = String, Path, description = "The credential's identity.")),
    responses(
        (status = 200, description = "The credential is revoked.", body = Resource<CredentialDto>),
        (status = 403, description = "The caller may not revoke credentials.", body = crate::error::ApiError),
        (status = 404, description = "The credential does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn revoke_credential(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(credential_id): Path<String>,
) -> Result<Json<Resource<CredentialDto>>, ApiErrorResponse> {
    let credentials = credentials_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let now = fleet_core::SystemClock::now_unix_millis();
    let revoked = credentials
        .revoke(
            state.authorizer.as_ref(),
            &principal.id,
            &credential_id,
            now,
        )
        .await
        .map_err(|error| map_credential_error(&error, correlation_id))?;
    Ok(Json(Resource::new(CredentialDto::new(revoked, now))))
}
