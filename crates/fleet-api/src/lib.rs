//! The public HTTP API adapter.
//!
//! This crate owns the shape of `/api/v1`: its envelopes, its error contract,
//! its correlation and idempotency headers, its pagination conventions, and the
//! `OpenAPI` document generated from them. Business rules live in the application
//! and domain layers; nothing here decides what an operation means.
//!
//! The document at `packages/api-client/openapi.json` is generated from this
//! code by the `fleet-openapi` binary and is the sole input to the generated
//! TypeScript client. Hand-editing either artifact is a defect.

#![warn(missing_docs)]

mod correlation;
mod envelope;
mod error;
mod meta;

use axum::{Extension, Router, http::StatusCode, middleware};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use std::str::FromStr as _;
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

pub use correlation::{CORRELATION_ID_HEADER, IDEMPOTENCY_KEY_HEADER};
pub use envelope::{
    DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, OperationAccepted, OperationStatus, Page, PageInfo,
    Resource,
};
pub use error::{ApiError, ApiErrorResponse, FieldViolation, Retry};
pub use meta::Meta;

/// The version segment of every published path.
pub const API_VERSION: &str = "v1";

/// The prefix every published path is served under.
pub const API_BASE_PATH: &str = "/api/v1";

/// The generated `OpenAPI` document's root definition.
///
/// `info.version` tracks the API path version rather than the crate version, so
/// releasing the controller does not rewrite the document and every client
/// generated from it.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Fleet Manager API",
        version = "v1",
        description = "The public Fleet Manager control API. Mutations return durable operations; \
                       the controller-node channel is a separate, separately versioned protocol.",
        license(name = "Apache-2.0", url = "https://www.apache.org/licenses/LICENSE-2.0")
    ),
    components(schemas(
        ApiError,
        FieldViolation,
        Retry,
        PageInfo,
        OperationAccepted,
        OperationStatus
    )),
    tags((name = "meta", description = "Service and contract description."))
)]
pub struct ApiDoc;

/// Builds the API router and the `OpenAPI` document describing it.
///
/// Both come from one registration, so a handler cannot be served without being
/// documented or documented without being served.
pub fn api() -> (Router, utoipa::openapi::OpenApi) {
    let (router, openapi) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .nest(
            API_BASE_PATH,
            OpenApiRouter::new().routes(routes!(meta::get_meta)),
        )
        .split_for_parts();

    let router = router
        .fallback(not_found)
        .layer(middleware::from_fn(correlation::correlate));

    (router, openapi)
}

/// Builds the API router.
pub fn router() -> Router {
    api().0
}

/// Builds the `OpenAPI` document.
#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    api().1
}

/// Returns the canonical serialization of the `OpenAPI` document.
///
/// # Panics
///
/// Panics only if the document cannot be serialized as JSON.
#[must_use]
pub fn openapi_json() -> String {
    let mut text = serde_json::to_string_pretty(&openapi())
        .expect("the generated OpenAPI document must serialize as JSON");
    text.push('\n');
    text
}

/// Answers any unrouted path with the standard error envelope.
async fn not_found(Extension(correlation_id): Extension<CorrelationId>) -> ApiErrorResponse {
    let public = PublicError::new(
        ErrorCode::from_str("not_found").expect("the literal is valid error code syntax"),
        "no such endpoint",
        RetryClass::Never,
    );
    ApiError::new(&public, correlation_id).with_status(StatusCode::NOT_FOUND)
}
