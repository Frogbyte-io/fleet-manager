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
/// public API correlation middleware, this rejection assigns its own id.
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
    let correlation_id = request
        .extensions()
        .get::<CorrelationId>()
        .copied()
        .or_else(|| {
            request
                .headers()
                .get(crate::correlation::CORRELATION_ID_HEADER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| CorrelationId::from_str(value).ok())
        })
        .unwrap_or_else(|| {
            let mut generator = fleet_core::UuidV7Generator;
            generator.next_correlation_id()
        });
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
