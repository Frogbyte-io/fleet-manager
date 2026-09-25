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
/// exactly one trusted user identity. Correlation middleware wraps this layer,
/// so the response uses the same standard error envelope as handler failures.
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
    ApiError::new(&error, correlation_id)
        .with_status(StatusCode::UNAUTHORIZED)
        .into_response()
}
