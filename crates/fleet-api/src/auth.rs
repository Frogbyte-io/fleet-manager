//! HTTP authentication rejection helpers shared by configured caller modes.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use fleet_core::{CorrelationId, ErrorCode, IdGenerator as _, PublicError, RetryClass};
use std::str::FromStr as _;

use crate::error::ApiError;

/// Rejects a Tailscale listener request whose caller resolver did not accept
/// exactly one trusted user identity. If the request did not pass through the
/// public API correlation middleware, this reuses a valid supplied id or
/// assigns a new one; a malformed supplied id keeps the standard 400 response.
///
/// # Panics
///
/// Panics only if the pinned error-code literal becomes invalid syntax.
pub async fn reject_unauthenticated_tailscale_caller(request: Request, next: Next) -> Response {
    reject_unauthenticated_caller(request, next).await
}

/// Rejects a request whose caller resolution failed: a Tailscale listener
/// request without one trusted user identity, or a request that presented a
/// delegated credential that did not authenticate. A presented credential
/// never falls back to another principal. Correlation handling is as for
/// [`reject_unauthenticated_tailscale_caller`].
///
/// # Panics
///
/// Panics only if a pinned error-code literal becomes invalid syntax.
pub async fn reject_unauthenticated_caller(request: Request, next: Next) -> Response {
    let rejected_credential = request
        .extensions()
        .get::<fleet_auth::RejectedCredential>()
        .copied();
    if rejected_credential.is_none()
        && request
            .extensions()
            .get::<fleet_auth::UnauthenticatedTailscaleRequest>()
            .is_none()
    {
        return next.run(request).await;
    }
    let correlation_extension = request.extensions().get::<CorrelationId>().copied();
    let supplied_header = request
        .headers()
        .get(crate::correlation::CORRELATION_ID_HEADER);
    let supplied_correlation = supplied_header
        .and_then(|value| value.to_str().ok())
        .and_then(|value| CorrelationId::from_str(value).ok());
    let mut generator = fleet_core::UuidV7Generator;
    if correlation_extension.is_none()
        && supplied_header.is_some()
        && supplied_correlation.is_none()
    {
        let assigned = generator.next_correlation_id();
        return crate::correlation::with_header(
            crate::correlation::malformed_correlation_id(assigned),
            assigned,
        );
    }
    let correlation_id = correlation_extension
        .or(supplied_correlation)
        .unwrap_or_else(|| generator.next_correlation_id());
    // The message never says which part of a credential was wrong: an
    // unknown, malformed, expired, or revoked token all read the same.
    let (status, code, message, retry) = match rejected_credential.map(|rejected| rejected.0) {
        Some(fleet_auth::CredentialRejection::Unavailable) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
            "the credential could not be checked; try again",
            RetryClass::Backoff,
        ),
        Some(_) => (
            StatusCode::UNAUTHORIZED,
            "authentication_required",
            "the presented credential is not valid",
            RetryClass::Never,
        ),
        None => (
            StatusCode::UNAUTHORIZED,
            "authentication_required",
            "a valid Tailscale user identity is required on this listener",
            RetryClass::Never,
        ),
    };
    let error = PublicError::new(
        ErrorCode::from_str(code).expect("the literal is valid error-code syntax"),
        message,
        retry,
    );
    let response = ApiError::new(&error, correlation_id)
        .with_status(status)
        .into_response();
    crate::correlation::with_header(response, correlation_id)
}
