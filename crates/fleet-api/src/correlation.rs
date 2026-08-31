use std::str::FromStr as _;

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use fleet_core::{
    CorrelationId, ErrorCode, IdGenerator as _, PublicError, RetryClass, UuidV7Generator,
};

use crate::error::ApiError;

/// Request and response header carrying the correlation identity.
pub const CORRELATION_ID_HEADER: &str = "x-correlation-id";

/// Request header carrying a caller-chosen idempotency key on mutations.
///
/// Replaying a mutation with the same key must return the original operation
/// rather than starting a second one. Enforcement belongs to the use cases that
/// mutate state; the header name is fixed here so every endpoint agrees on it.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// Attaches a correlation identity to every request and every response.
///
/// A caller may supply one to tie an API request to work it already tracks. A
/// malformed one is refused rather than replaced, because silently substituting
/// an identity would break the audit trail the caller is trying to join.
///
/// This runs as middleware rather than as a per-handler extractor so that
/// responses no handler produced — the 404 fallback, a rejected body, a future
/// timeout layer — carry the header too.
pub async fn correlate(mut request: Request, next: Next) -> Response {
    let mut generator = UuidV7Generator;

    let supplied = request.headers().get(CORRELATION_ID_HEADER).map(|value| {
        value
            .to_str()
            .ok()
            .and_then(|text| CorrelationId::from_str(text).ok())
    });

    let correlation_id = match supplied {
        None => generator.next_correlation_id(),
        Some(Some(correlation_id)) => correlation_id,
        Some(None) => {
            let assigned = generator.next_correlation_id();
            return with_header(malformed_correlation_id(assigned), assigned);
        }
    };

    request.extensions_mut().insert(correlation_id);
    with_header(next.run(request).await, correlation_id)
}

fn malformed_correlation_id(assigned: CorrelationId) -> Response {
    let public = PublicError::new(
        ErrorCode::from_str("malformed_correlation_id")
            .expect("the literal is valid error code syntax"),
        format!(
            "the {CORRELATION_ID_HEADER} header must be a canonical opaque Fleet identity; \
             the identity in this response was assigned instead"
        ),
        RetryClass::Never,
    );
    ApiError::new(&public, assigned)
        .with_status(StatusCode::BAD_REQUEST)
        .into_response()
}

fn with_header(mut response: Response, correlation_id: CorrelationId) -> Response {
    let name = HeaderName::from_static(CORRELATION_ID_HEADER);
    let value = HeaderValue::from_str(&correlation_id.to_string())
        .expect("an opaque identity is printable ASCII");
    response.headers_mut().insert(name, value);
    response
}
