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
pub mod machines;
mod meta;
pub mod node;
pub mod onboarding;
pub mod operations;
pub mod system;

use std::sync::Arc;

use axum::{Extension, Router, http::StatusCode, middleware};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};

pub use fleet_application::authz::ActingPrincipal;
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
        OperationStatus,
        operations::CreateOperationRequest,
        operations::OperationDto,
        machines::CapabilityFactDto,
        machines::EndpointDto,
        machines::InventoryObservationDto,
        machines::MachineDto,
        onboarding::AddedMachineDto,
        onboarding::ConfirmHostKeyRequest,
        onboarding::CreateOnboardingDraftRequest,
        onboarding::DraftEndpointDto,
        onboarding::DuplicateCandidateDto,
        onboarding::OnboardAuthDto,
        onboarding::OnboardHostKeyDto,
        onboarding::OnboardingDraftDetailDto,
        onboarding::OnboardingDraftDto,
        onboarding::TestOutcomeDto,
        system::SystemInfo,
        node::CreateEnrollmentTokenRequest,
        node::EnrollmentTokenCreatedDto,
        node::EnrollmentTokenDto,
        node::EnrollmentTokenListDto,
        node::NodeCredentialDto,
        node::NodeIdentityDto,
        node::NodeRevokedDto,
        node::NodeViewDto
    )),
    tags(
        (name = "meta", description = "Service and contract description."),
        (name = "system", description = "The controller's own view of itself."),
        (name = "operations", description = "Durable operations: accepted remote work."),
        (
            name = "machines",
            description = "The operational machine view: identity, endpoints, capability facts, \
                           connectivity state, and the last observation. Endpoint references are \
                           redacted unless the caller may read sensitive endpoint detail."
        ),
        (
            name = "nodes",
            description = "Node enrollment and identity: enrollment tokens, node state, and revocation. \
                           The machine-facing enrollment endpoints under /api/node/v1 are versioned with \
                           the node protocol and documented in proto/README.md, not here."
        )
    )
)]
pub struct ApiDoc;

/// Builds the API router and the `OpenAPI` document describing it.
///
/// Both come from one registration, so a handler cannot be served without being
/// documented or documented without being served.
pub fn api(state: Arc<operations::ApiState>) -> (Router, utoipa::openapi::OpenApi) {
    let (router, openapi) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .nest(
            API_BASE_PATH,
            OpenApiRouter::new()
                .routes(routes!(meta::get_meta))
                .routes(routes!(
                    operations::create_operation,
                    operations::list_operations
                ))
                .routes(routes!(operations::get_operation))
                .routes(routes!(operations::cancel_operation))
                .routes(routes!(system::get_system_info))
                .routes(routes!(system::stream_operation_events))
                .routes(routes!(machines::list_machines))
                .routes(routes!(machines::get_machine))
                .routes(routes!(
                    onboarding::create_onboarding_draft,
                    onboarding::list_onboarding_drafts
                ))
                .routes(routes!(onboarding::get_onboarding_draft))
                .routes(routes!(onboarding::test_onboarding_draft))
                .routes(routes!(onboarding::discover_onboarding_draft))
                .routes(routes!(onboarding::confirm_onboarding_host_key))
                .routes(routes!(onboarding::add_onboarding_machine))
                .routes(routes!(onboarding::cancel_onboarding_draft))
                .routes(routes!(
                    node::create_enrollment_token,
                    node::list_enrollment_tokens
                ))
                .routes(routes!(node::get_node))
                .routes(routes!(node::revoke_node))
                .with_state(state),
        )
        .split_for_parts();

    let router = router
        .fallback(not_found)
        .layer(middleware::from_fn(correlation::correlate));

    (router, openapi)
}

/// Builds the API router over the given state.
pub fn router(state: Arc<operations::ApiState>) -> Router {
    api(state).0
}

/// Builds the `OpenAPI` document. The document describes the router's
/// contract; the state is needed to build the router, so a throwaway state
/// documents the same paths without touching any backend.
#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    let (router, openapi) = api(Arc::new(operations::ApiState::for_document()));
    let _ = router;
    openapi
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
