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

pub mod apply;
pub mod audit;
pub mod auth;
mod correlation;
mod envelope;
mod error;
pub mod frogenv;
pub mod images;
pub mod lab;
pub mod machines;
mod meta;
pub mod mise;
pub mod node;
pub mod onboarding;
pub mod operations;
pub mod projects;
pub mod proxmox;
pub mod ready;
pub mod skills;
pub mod system;
pub mod tailnet;

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
        projects::CheckoutFactDto,
        projects::CheckoutAuthDto,
        projects::DiscoveredCheckoutDto,
        projects::RecordCheckoutsRequest,
        projects::StartDiscoveryRequest,
        skills::SkillsAuthDto,
        skills::StartSkillsOperationRequest,
        frogenv::FrogenvActionDto,
        frogenv::FrogenvAuthDto,
        frogenv::StartFrogenvOperationRequest,
        mise::MiseActionDto,
        mise::MiseAuthDto,
        mise::StartMiseOperationRequest,
        ready::ReadyAuthDto,
        ready::ReadyToolDto,
        ready::StartReadyRequest,
        apply::ApplyActionDto,
        apply::ApplyApprovalDto,
        apply::ApplyAuthDto,
        apply::FieldDifferenceDto,
        apply::StartApplyRequest,
        audit::AuditEventDto,
        projects::CreateProjectRequest,
        projects::ProjectDto,
        projects::UpdateProjectRequest,
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
        tailnet::ConfigureTailnetRequest,
        tailnet::CorrelatedDeviceDto,
        tailnet::CorrelationCandidateDto,
        tailnet::ImportTailnetDeviceRequest,
        tailnet::TailnetStatusDto,
        proxmox::ConfirmProxmoxFingerprintRequest,
        proxmox::CreateProxmoxAccountRequest,
        proxmox::ProxmoxAccountDto,
        proxmox::ProxmoxDiscoveryDto,
        proxmox::ProxmoxFingerprintDto,
        proxmox::ProxmoxResourceDto,
        proxmox::AssociatedGuestDto,
        proxmox::AssociationCandidateDto,
        proxmox::ObserveProxmoxGuestRequest,
        proxmox::StartProxmoxLifecycleRequest,
        proxmox::ProxmoxReviewDto,
        proxmox::ReviewProxmoxOperationRequest,
        proxmox::StartReviewedProxmoxOperationRequest,
        images::BuildImageRequest,
        lab::LabTemplateDto,
        lab::LabTemplateContentDto,
        lab::LabTemplateVersionDto,
        lab::ProvisionRecordDto,
        lab::SaveLabTemplateRequest,
        lab::CreateLeaseRequest,
        lab::LeaseDto,
        lab::ReleaseLeaseRequest,
        images::RecipeDto,
        images::RecipeVersionDto,
        images::SaveRecipeRequest,
        proxmox::ProviderAgentDto,
        proxmox::ProviderInterfaceDto,
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
        (name = "audit", description = "Authorized, metadata-only audit event queries."),
        (name = "operations", description = "Durable operations: accepted remote work."),
        (
            name = "machines",
            description = "The operational machine view: identity, endpoints, capability facts, \
                           connectivity state, and the last observation. Endpoint references are \
                           redacted unless the caller may read sensitive endpoint detail."
        ),
        (
            name = "projects",
            description = "Projects keyed by normalized Git remote, with per-machine observed checkouts. The remote is the identity; checkouts are facts."
        ),
        (
            name = "tailnet",
            description = "Optional Tailscale discovery: correlated tailnet devices and the import handoff into the onboarding flow. Correlation is evidence only; Fleet identity never derives from Tailscale."
        ),
        (
            name = "lab",
            description = "Fleet Lab: versioned templates pinning promoted image versions, the provisioning saga's records, and the readiness states. TTL begins at ready."
        ),
        (
            name = "images",
            description = "Image recipes and their immutable published versions, built over the operator-installed Packer CLI. The content passes through verbatim; Fleet never re-validates Packer's own fields."
        ),
        (
            name = "lab",
            description = "Fleet Lab: versioned templates pinning promoted image versions, the provisioning saga's records, and the readiness states. TTL begins at ready."
        ),
        (
            name = "images",
            description = "Image recipes and their immutable published versions, built over the operator-installed Packer CLI. The content passes through verbatim; Fleet never re-validates Packer's own fields."
        ),
        (
            name = "proxmox",
            description = "Proxmox accounts, TLS fingerprint trust, and cluster discovery. The token secret is write-only; discovery is locked until the host fingerprint is confirmed."
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
                .routes(routes!(audit::list_audit_events))
                .routes(routes!(system::stream_operation_events))
                .routes(routes!(machines::list_machines))
                .routes(routes!(machines::get_machine))
                .routes(routes!(projects::create_project, projects::list_projects))
                .routes(routes!(projects::get_project))
                .routes(routes!(projects::update_project))
                .routes(routes!(projects::delete_project))
                .routes(routes!(projects::start_discovery))
                .routes(routes!(projects::record_checkouts))
                .routes(routes!(skills::start_skills_operation))
                .routes(routes!(frogenv::start_frogenv_operation))
                .routes(routes!(mise::start_mise_operation))
                .routes(routes!(ready::start_ready_workflow))
                .routes(routes!(apply::start_apply_workflow))
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
                .routes(routes!(tailnet::get_tailnet_status))
                .routes(routes!(tailnet::configure_tailnet))
                .routes(routes!(tailnet::clear_tailnet))
                .routes(routes!(tailnet::list_tailnet_devices))
                .routes(routes!(tailnet::import_tailnet_device))
                .routes(routes!(
                    proxmox::list_proxmox_accounts,
                    proxmox::create_proxmox_account
                ))
                .routes(routes!(proxmox::delete_proxmox_account))
                .routes(routes!(proxmox::observe_proxmox_fingerprint))
                .routes(routes!(proxmox::confirm_proxmox_fingerprint))
                .routes(routes!(proxmox::discover_proxmox_cluster))
                .routes(routes!(proxmox::list_proxmox_guests))
                .routes(routes!(proxmox::observe_proxmox_guest))
                .routes(routes!(proxmox::start_proxmox_lifecycle))
                .routes(routes!(proxmox::review_proxmox_operation))
                .routes(routes!(
                    images::list_image_recipes,
                    images::create_image_recipe
                ))
                .routes(routes!(images::get_image_recipe))
                .routes(routes!(images::update_image_recipe))
                .routes(routes!(images::delete_image_recipe))
                .routes(routes!(images::publish_image_recipe))
                .routes(routes!(images::list_image_recipe_versions))
                .routes(routes!(images::start_image_build))
                .routes(routes!(images::promote_image_version))
                .routes(routes!(images::get_image_version))
                .routes(routes!(lab::list_lab_templates, lab::create_lab_template))
                .routes(routes!(lab::get_lab_template))
                .routes(routes!(lab::update_lab_template))
                .routes(routes!(lab::delete_lab_template))
                .routes(routes!(lab::publish_lab_template))
                .routes(routes!(lab::start_lab_provision))
                .routes(routes!(lab::list_lab_provisions))
                .routes(routes!(lab::create_lab_lease))
                .routes(routes!(lab::list_lab_leases))
                .routes(routes!(lab::release_lab_lease))
                .routes(routes!(lab::sweep_lab_leases))
                .routes(routes!(proxmox::start_reviewed_proxmox_operation))
                .with_state(state),
        )
        .split_for_parts();

    let router = router.fallback(not_found);

    (router, openapi)
}

/// Builds the API router over the given state.
pub fn router(state: Arc<operations::ApiState>) -> Router {
    correlate_router(unwrapped_router(state))
}

/// Builds the API routes without correlation middleware, for a controller
/// composition root that applies a wider request gate and correlation layer.
pub fn unwrapped_router(state: Arc<operations::ApiState>) -> Router {
    api(state).0
}

/// Applies the API correlation contract to a wider controller router.
pub fn correlate_router(router: Router) -> Router {
    router.layer(middleware::from_fn(correlation::correlate))
}

/// Builds the API router for a dedicated Tailscale Serve listener. A request
/// must be resolved by the configured loopback caller middleware; rejected
/// requests receive a correlated API error before reaching the route router.
pub fn tailscale_serve_router(
    state: Arc<operations::ApiState>,
    peer: fleet_auth::TailscaleServePeer,
) -> Router {
    tailscale_serve_guard(router(state), peer)
}

/// Applies loopback Tailscale caller resolution and the corresponding 401
/// rejection to a complete controller router. The public API can keep its
/// correlation middleware scoped to its handlers; the node protocol retains
/// its separate correlation contract.
pub fn tailscale_serve_guard(router: Router, peer: fleet_auth::TailscaleServePeer) -> Router {
    router
        .layer(middleware::from_fn(
            auth::reject_unauthenticated_tailscale_caller,
        ))
        .layer(middleware::from_fn_with_state(
            peer,
            fleet_auth::resolve_tailscale_serve_caller,
        ))
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
