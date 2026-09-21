//! The Add Machine onboarding surface: the staged draft/test/discover/
//! review/add workflow behind the application's authorized use cases.
//!
//! This adapter decides nothing about trust or machines. It translates the
//! workflow's HTTP shape into use-case calls; the test and discover stages
//! become durable operations of the `machine.onboard.*` kinds, so their
//! progress, cancellation, and audit travel the same road as every other
//! accepted remote work. The draft's credential-bearing endpoint detail is
//! redacted by the use case unless the caller may read sensitive endpoint
//! detail — the same rule the machine read model applies.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use fleet_application::onboarding::{
    DraftEndpoint, DraftView, OnboardAuth, OnboardingUseCaseError,
};
use fleet_core::{CapabilityFact, CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use std::str::FromStr as _;
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};
use crate::machines::{CapabilityFactDto, MachineDto};
use crate::operations::OperationDto;

/// Extracts the onboarding use cases from the API state, or answers with the
/// standard envelope when the controller was composed without a database.
fn onboarding_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<fleet_application::onboarding::Onboarding>, ApiErrorResponse> {
    state.onboarding.clone().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "the onboarding surface is not wired; the controller needs its database",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// Maps an onboarding use-case outcome onto the public error envelope, once.
/// Backend details stay out of the response; every other detail is
/// caller-safe by construction in the use cases.
fn map_onboarding_error(
    error: &OnboardingUseCaseError,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    let (status, code, retry): (StatusCode, &str, RetryClass) = match error {
        OnboardingUseCaseError::Denied(_) => (StatusCode::FORBIDDEN, "denied", RetryClass::Never),
        OnboardingUseCaseError::NotFound { .. } => {
            (StatusCode::NOT_FOUND, "not_found", RetryClass::Never)
        }
        OnboardingUseCaseError::Conflict { .. } => {
            (StatusCode::CONFLICT, "conflict", RetryClass::Never)
        }
        OnboardingUseCaseError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
        ),
        OnboardingUseCaseError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    let message = match error {
        OnboardingUseCaseError::Backend { .. } => {
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

/// The proposed endpoint of a draft. The user arrives redacted unless the
/// caller may read sensitive endpoint detail.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DraftEndpointDto {
    /// The remote login user, `***` when redacted.
    pub user: String,
    /// The host or address.
    pub host: String,
    /// The TCP port.
    pub port: u16,
}

/// How the controller would authenticate to a draft's endpoint.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum OnboardAuthDto {
    /// The controller's running agent supplies the key.
    Agent,
    /// A specific identity file, referenced by path. The path is a
    /// reference, not a secret.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// A host key as observed from the network, staged for review. Public data.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OnboardHostKeyDto {
    /// The key type, e.g. `ED25519`.
    pub key_type: String,
    /// The OpenSSH `SHA256:` fingerprint to confirm.
    pub fingerprint: String,
    /// The raw `known_hosts` line behind the fingerprint.
    pub raw_line: String,
}

/// The outcome of the connect check a test performed, when it ran.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TestOutcomeDto {
    /// Whether the connect check ran.
    pub connect_attempted: bool,
    /// Whether the connect check succeeded.
    pub connected: bool,
    /// The bounded, already-redacted failure detail, when the check failed.
    pub detail: Option<String>,
    /// When the test ran (epoch milliseconds).
    pub at: i64,
}

/// One existing machine whose endpoint matches a draft's host and port.
/// Candidates warn; they never merge or block.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateCandidateDto {
    /// The existing machine's identity.
    pub machine_id: String,
    /// The existing machine's name.
    pub name: String,
    /// The existing machine's derived connectivity state.
    pub machine_status: String,
    /// The matching endpoint reference, as the caller may see it.
    pub reference: String,
}

/// The shared fields of a draft, as the list and detail endpoints display
/// them.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OnboardingDraftDto {
    /// The draft's identity.
    pub id: String,
    /// The proposed endpoint; the user is redacted unless the caller may
    /// read sensitive endpoint detail.
    pub endpoint: DraftEndpointDto,
    /// The proposed machine name.
    pub name: String,
    /// Tags carried onto the machine.
    pub tags: Vec<String>,
    /// Groups carried onto the machine.
    pub groups: Vec<String>,
    /// The derived stage: `untested`, `review`, or `ready`.
    pub stage: String,
    /// The host-key trust stage: `unseen`, `observed`, `confirmed`, or
    /// `changed`.
    pub host_key_stage: String,
    /// How many facts discovery recorded.
    pub fact_count: i64,
    /// Creation time (epoch milliseconds).
    pub created_at: i64,
    /// Last mutation (epoch milliseconds).
    pub updated_at: i64,
}

/// A draft in full: everything the review step renders.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OnboardingDraftDetailDto {
    /// The draft's identity.
    pub id: String,
    /// The proposed endpoint; the user is redacted unless the caller may
    /// read sensitive endpoint detail.
    pub endpoint: DraftEndpointDto,
    /// How the controller would authenticate.
    pub auth: OnboardAuthDto,
    /// The proposed machine name.
    pub name: String,
    /// Operator notes carried onto the machine.
    pub description: String,
    /// Tags carried onto the machine.
    pub tags: Vec<String>,
    /// Groups carried onto the machine.
    pub groups: Vec<String>,
    /// The derived stage: `untested`, `review`, or `ready`.
    pub stage: String,
    /// The host-key trust stage, as recorded.
    pub host_key_stage: String,
    /// The newest observed host key, when a test ran.
    pub host_key: Option<OnboardHostKeyDto>,
    /// The fingerprint the operator confirmed, when any.
    pub confirmed_fingerprint: Option<String>,
    /// The newest test outcome, when a test ran.
    pub last_test: Option<TestOutcomeDto>,
    /// The facts discovery recorded for review.
    pub facts: Vec<CapabilityFactDto>,
    /// When discovery completed (epoch milliseconds).
    pub discovered_at: Option<i64>,
    /// The OS/profile hint derived from the facts, when the facts name an
    /// operating system. A display hint only; nothing is applied.
    pub profile_hint: Option<String>,
    /// Existing machines whose endpoints share the draft's host and port.
    pub duplicates: Vec<DuplicateCandidateDto>,
    /// Creation time (epoch milliseconds).
    pub created_at: i64,
    /// Last mutation (epoch milliseconds).
    pub updated_at: i64,
}

/// The body of the create-draft request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateOnboardingDraftRequest {
    /// The remote login user.
    pub user: String,
    /// The host or address.
    pub host: String,
    /// The TCP port; 22 when omitted.
    pub port: Option<u16>,
    /// How the controller would authenticate.
    pub auth: OnboardAuthDto,
    /// The proposed machine name; derived from the host when omitted.
    pub name: Option<String>,
    /// Operator notes carried onto the machine.
    pub description: Option<String>,
    /// Tags carried onto the machine.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Groups carried onto the machine.
    #[serde(default)]
    pub groups: Vec<String>,
}

/// The body of the confirm-host-key request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmHostKeyRequest {
    /// The OpenSSH `SHA256:` fingerprint being confirmed. It must match the
    /// fingerprint the host presented.
    pub fingerprint: String,
}

/// The outcome of an add: the new machine plus the duplicates that were
/// warned about.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AddedMachineDto {
    /// The registered machine, redacted per the caller's permissions.
    pub machine: MachineDto,
    /// Existing machines that shared the draft's host and port. The add
    /// proceeded anyway: candidates warn, they do not merge.
    pub duplicates: Vec<DuplicateCandidateDto>,
}

impl From<DraftView> for OnboardingDraftDto {
    fn from(view: DraftView) -> Self {
        let DraftView {
            id,
            endpoint,
            name,
            tags,
            groups,
            stage,
            host_key_stage,
            facts,
            created_at,
            updated_at,
            ..
        } = view;
        Self {
            id,
            endpoint: DraftEndpointDto {
                user: endpoint.user,
                host: endpoint.host,
                port: endpoint.port,
            },
            name,
            tags,
            groups,
            stage: stage.id().to_owned(),
            host_key_stage: host_key_stage.id().to_owned(),
            fact_count: i64::try_from(facts.len()).unwrap_or(i64::MAX),
            created_at,
            updated_at,
        }
    }
}

impl From<DraftView> for OnboardingDraftDetailDto {
    fn from(view: DraftView) -> Self {
        let DraftView {
            id,
            endpoint,
            auth,
            name,
            description,
            tags,
            groups,
            stage,
            host_key_stage,
            host_key,
            confirmed_fingerprint,
            last_test,
            facts,
            discovered_at,
            profile_hint,
            duplicates,
            created_at,
            updated_at,
        } = view;
        Self {
            id,
            endpoint: DraftEndpointDto {
                user: endpoint.user,
                host: endpoint.host,
                port: endpoint.port,
            },
            auth: match auth {
                OnboardAuth::Agent => OnboardAuthDto::Agent,
                OnboardAuth::IdentityFile { path } => OnboardAuthDto::IdentityFile { path },
            },
            name,
            description,
            tags,
            groups,
            stage: stage.id().to_owned(),
            host_key_stage: host_key_stage.id().to_owned(),
            host_key: host_key.map(|key| OnboardHostKeyDto {
                key_type: key.key_type,
                fingerprint: key.fingerprint,
                raw_line: key.raw_line,
            }),
            confirmed_fingerprint,
            last_test: last_test.map(|outcome| TestOutcomeDto {
                connect_attempted: outcome.connect_attempted,
                connected: outcome.connected,
                detail: outcome.detail,
                at: outcome.at,
            }),
            facts: facts
                .iter()
                .map(|fact: &CapabilityFact| CapabilityFactDto {
                    namespace: fact.namespace.clone(),
                    name: fact.name.clone(),
                    value: fact.value.clone(),
                    status: fact.status.id().to_owned(),
                    observed_at: fact.observed_at.unix_millis(),
                    source: fact.source.clone(),
                })
                .collect(),
            discovered_at,
            profile_hint,
            duplicates: duplicates
                .iter()
                .map(|candidate| DuplicateCandidateDto {
                    machine_id: candidate.machine_id.clone(),
                    name: candidate.name.clone(),
                    machine_status: candidate.machine_status.id().to_owned(),
                    reference: candidate.reference.clone(),
                })
                .collect(),
            created_at,
            updated_at,
        }
    }
}

/// Creates a draft: the first stage. No network contact happens here.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    post,
    path = "/machines/onboarding/drafts",
    tag = "machines",
    operation_id = "createOnboardingDraft",
    request_body = CreateOnboardingDraftRequest,
    responses(
        (
            status = 201,
            description = "The draft was created.",
            body = Resource<OnboardingDraftDto>
        ),
        (
            status = 400,
            description = "The request is malformed.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not create machines.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn create_onboarding_draft(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: axum::http::HeaderMap,
    Json(request): Json<CreateOnboardingDraftRequest>,
) -> Result<(StatusCode, Json<Resource<OnboardingDraftDto>>), ApiErrorResponse> {
    let onboarding = onboarding_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let auth = match request.auth {
        OnboardAuthDto::Agent => OnboardAuth::Agent,
        OnboardAuthDto::IdentityFile { path } => OnboardAuth::IdentityFile { path },
    };
    let draft = onboarding
        .create_draft(
            state.authorizer.as_ref(),
            &principal,
            fleet_application::onboarding::NewDraft {
                endpoint: DraftEndpoint {
                    user: request.user,
                    host: request.host,
                    port: request.port.unwrap_or(22),
                },
                auth,
                name: request.name,
                description: request.description.unwrap_or_default(),
                tags: request.tags,
                groups: request.groups,
                idempotency_key: headers
                    .get(crate::IDEMPOTENCY_KEY_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
            },
        )
        .await
        .map_err(|error| map_onboarding_error(&error, correlation_id))?;
    Ok((
        StatusCode::CREATED,
        Json(Resource::new(OnboardingDraftDto::from(draft))),
    ))
}

/// Lists drafts, newest first.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/machines/onboarding/drafts",
    tag = "machines",
    operation_id = "listOnboardingDrafts",
    params(
        ("limit" = Option<u32>, Query, description = "The maximum number of drafts to return.")
    ),
    responses(
        (
            status = 200,
            description = "A page of drafts.",
            body = Page<OnboardingDraftDto>
        ),
        (
            status = 403,
            description = "The caller may not read machines.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn list_onboarding_drafts(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<ListDraftsParams>,
) -> Result<Json<Page<OnboardingDraftDto>>, ApiErrorResponse> {
    let onboarding = onboarding_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let limit = params
        .limit
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .min(MAX_PAGE_LIMIT);
    let views = onboarding
        .list_drafts(state.authorizer.as_ref(), &principal, limit)
        .await
        .map_err(|error| map_onboarding_error(&error, correlation_id))?;
    let next_cursor = (views.len() == usize::try_from(limit).unwrap_or(0))
        .then(|| views.last().map(|view| view.id.clone()))
        .flatten();
    Ok(Json(Page {
        items: views.into_iter().map(OnboardingDraftDto::from).collect(),
        page: PageInfo { next_cursor, limit },
    }))
}

/// The list-drafts query parameters.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListDraftsParams {
    /// The maximum number of drafts to return.
    pub limit: Option<u32>,
}

/// Reads one draft in full: the review surface.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/machines/onboarding/drafts/{draftId}",
    tag = "machines",
    operation_id = "getOnboardingDraft",
    params(
        ("draftId" = String, Path, description = "The draft's identity.")
    ),
    responses(
        (
            status = 200,
            description = "The draft, with facts, hint, and duplicate candidates.",
            body = Resource<OnboardingDraftDetailDto>
        ),
        (
            status = 404,
            description = "No such draft.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not read machines.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn get_onboarding_draft(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(draft_id): Path<String>,
) -> Result<Json<Resource<OnboardingDraftDetailDto>>, ApiErrorResponse> {
    let onboarding = onboarding_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let view = onboarding
        .get_draft(
            state.authorizer.as_ref(),
            &principal,
            &draft_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_onboarding_error(&error, correlation_id))?;
    Ok(Json(Resource::new(OnboardingDraftDetailDto::from(view))))
}

/// Starts a test: probes the draft's host key and, once the fingerprint is
/// confirmed, tests authentication. The work runs as a durable
/// `machine.onboard.test` operation; it has no persistent machine side
/// effect.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown draft, or a
/// backend failure.
#[utoipa::path(
    post,
    path = "/machines/onboarding/drafts/{draftId}/test",
    tag = "machines",
    operation_id = "testOnboardingDraft",
    params(
        ("draftId" = String, Path, description = "The draft's identity.")
    ),
    responses(
        (
            status = 202,
            description = "The test operation was accepted.",
            body = Resource<OperationDto>
        ),
        (
            status = 404,
            description = "No such draft.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not create operations.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn test_onboarding_draft(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(draft_id): Path<String>,
) -> Result<(StatusCode, Json<Resource<OperationDto>>), ApiErrorResponse> {
    start_onboarding_operation(
        state,
        principal,
        correlation_id,
        draft_id,
        "machine.onboard.test",
        60_000,
    )
    .await
}

/// Starts a discover: the agentless inventory probe against a confirmed
/// draft, ingested into the draft for review.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown draft, or a
/// backend failure.
#[utoipa::path(
    post,
    path = "/machines/onboarding/drafts/{draftId}/discover",
    tag = "machines",
    operation_id = "discoverOnboardingDraft",
    params(
        ("draftId" = String, Path, description = "The draft's identity.")
    ),
    responses(
        (
            status = 202,
            description = "The discover operation was accepted.",
            body = Resource<OperationDto>
        ),
        (
            status = 404,
            description = "No such draft.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not create operations.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn discover_onboarding_draft(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(draft_id): Path<String>,
) -> Result<(StatusCode, Json<Resource<OperationDto>>), ApiErrorResponse> {
    start_onboarding_operation(
        state,
        principal,
        correlation_id,
        draft_id,
        "machine.onboard.discover",
        300_000,
    )
    .await
}

/// The shared shape of the test and discover stage starts: the draft must
/// exist, the operation is durable, and the deadline bounds a lost worker.
async fn start_onboarding_operation(
    state: Arc<crate::operations::ApiState>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    correlation_id: CorrelationId,
    draft_id: String,
    kind: &'static str,
    deadline_ms: i64,
) -> Result<(StatusCode, Json<Resource<OperationDto>>), ApiErrorResponse> {
    let onboarding = onboarding_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // The draft must exist before the operation is accepted, so a typo is a
    // 404 now rather than a failed operation later.
    onboarding
        .get_draft(
            state.authorizer.as_ref(),
            &principal,
            &draft_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_onboarding_error(&error, correlation_id))?;
    let operation = state
        .operations
        .create(
            state.authorizer.as_ref(),
            &principal.id,
            &fleet_application::operation::NewOperation {
                kind: kind.to_owned(),
                idempotency_key: None,
                deadline_at: Some(fleet_core::SystemClock::now_unix_millis() + deadline_ms),
                correlation_id: Some(correlation_id.to_string()),
                payload_json: Some(serde_json::json!({ "draftId": draft_id }).to_string()),
                review_token: None,
            },
        )
        .await
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(Resource::new(OperationDto::from(operation))),
    ))
}

/// Confirms the observed fingerprint explicitly. This is the
/// trust-on-first-use act the security architecture requires.
///
/// # Errors
///
/// Returns the public error envelope on refusal, a mismatched fingerprint,
/// or a backend failure.
#[utoipa::path(
    post,
    path = "/machines/onboarding/drafts/{draftId}/confirm-host-key",
    tag = "machines",
    operation_id = "confirmOnboardingHostKey",
    params(
        ("draftId" = String, Path, description = "The draft's identity.")
    ),
    request_body = ConfirmHostKeyRequest,
    responses(
        (
            status = 200,
            description = "The fingerprint was confirmed and pinned.",
            body = Resource<OnboardingDraftDetailDto>
        ),
        (
            status = 400,
            description = "The fingerprint is malformed or does not match.",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "No such draft.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not create machines.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn confirm_onboarding_host_key(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(draft_id): Path<String>,
    Json(request): Json<ConfirmHostKeyRequest>,
) -> Result<Json<Resource<OnboardingDraftDetailDto>>, ApiErrorResponse> {
    let onboarding = onboarding_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let view = onboarding
        .confirm_host_key(
            state.authorizer.as_ref(),
            &principal,
            &draft_id,
            &request.fingerprint,
        )
        .await
        .map_err(|error| map_onboarding_error(&error, correlation_id))?;
    Ok(Json(Resource::new(OnboardingDraftDetailDto::from(view))))
}

/// Completes onboarding: registers the machine under the draft's identity
/// and answers with the new machine plus the duplicates that were warned
/// about. The draft is deleted; its facts, if any, are ingested first.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unconfirmed host key, or
/// a backend failure.
#[utoipa::path(
    post,
    path = "/machines/onboarding/drafts/{draftId}/add",
    tag = "machines",
    operation_id = "addOnboardingMachine",
    params(
        ("draftId" = String, Path, description = "The draft's identity.")
    ),
    responses(
        (
            status = 201,
            description = "The machine was registered; the draft is gone.",
            body = Resource<AddedMachineDto>
        ),
        (
            status = 409,
            description = "The host key is not confirmed, or the draft state forbids the add.",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "No such draft.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not create machines.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn add_onboarding_machine(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(draft_id): Path<String>,
) -> Result<(StatusCode, Json<Resource<AddedMachineDto>>), ApiErrorResponse> {
    let onboarding = onboarding_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let added = onboarding
        .add(
            state.authorizer.as_ref(),
            &principal,
            &draft_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_onboarding_error(&error, correlation_id))?;
    Ok((
        StatusCode::CREATED,
        Json(Resource::new(AddedMachineDto {
            machine: MachineDto::from(added.machine),
            duplicates: added
                .duplicates
                .iter()
                .map(|candidate| DuplicateCandidateDto {
                    machine_id: candidate.machine_id.clone(),
                    name: candidate.name.clone(),
                    machine_status: candidate.machine_status.id().to_owned(),
                    reference: candidate.reference.clone(),
                })
                .collect(),
        })),
    ))
}

/// Cancels a draft: the row is deleted and the host's pins are removed
/// unless an existing machine endpoint shares the host.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    post,
    path = "/machines/onboarding/drafts/{draftId}/cancel",
    tag = "machines",
    operation_id = "cancelOnboardingDraft",
    params(
        ("draftId" = String, Path, description = "The draft's identity.")
    ),
    responses(
        (
            status = 204,
            description = "The draft was cancelled and deleted."
        ),
        (
            status = 404,
            description = "No such draft.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not create machines.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn cancel_onboarding_draft(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(draft_id): Path<String>,
) -> Result<StatusCode, ApiErrorResponse> {
    let onboarding = onboarding_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    onboarding
        .cancel_draft(
            state.authorizer.as_ref(),
            &principal,
            &draft_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_onboarding_error(&error, correlation_id))?;
    Ok(StatusCode::NO_CONTENT)
}
