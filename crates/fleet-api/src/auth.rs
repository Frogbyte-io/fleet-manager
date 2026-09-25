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
    if request
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
    let error = PublicError::new(
        ErrorCode::from_str("authentication_required")
            .expect("the literal is valid error-code syntax"),
        "a valid Tailscale user identity is required on this listener",
        RetryClass::Never,
    );
    let response = ApiError::new(&error, correlation_id)
        .with_status(StatusCode::UNAUTHORIZED)
        .into_response();
    crate::correlation::with_header(response, correlation_id)
}
