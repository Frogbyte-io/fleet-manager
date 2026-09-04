//! The node trust surface: the machine-facing enrollment endpoints and the
//! operator endpoints over a machine's node state.
//!
//! Two shapes live here, and they answer different callers:
//!
//! - **Machine-facing** (`/api/node/v1/*`): `fleetd` calls `enroll`,
//!   `challenge`, `session`, and `rotate`. These are versioned with the node
//!   protocol — not the public API — and are deliberately absent from the
//!   `OpenAPI` document; `proto/README.md` is their contract. They authorize
//!   with cryptographic material (a single-use token or a signed key proof),
//!   never with the trusted-LAN principal, and each handler builds its own
//!   correlation identity because the node channel does not share the
//!   browser/CLI request correlation.
//! - **Operator-facing** (`/api/v1/machines/{machineId}/node/...`): creating
//!   tokens, viewing node state, and revocation. These are part of the public
//!   contract, run through the application's authorization funnel, and are
//!   audited there.
//!
//! Node sessions are a node-surface credential. No operator endpoint accepts
//! one, so a node session cannot reach the user API; the gateway (FM-205) is
//! its only consumer.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use fleet_application::node::{
    ChallengePurpose, EnrollmentTokenCreated, EnrollmentTokenView, NodeStatus, NodeUseCaseError,
    NodeView, Nodes,
};
use fleet_core::{
    CorrelationId, ErrorCode, IdGenerator as _, PublicError, RetryClass, UuidV7Generator,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr as _;
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::{ApiError, ApiErrorResponse};

/// Extracts the node use cases from the API state, or answers with the
/// standard envelope when the controller was composed without one: the node
/// surface needs a database and a configured master key, and an unwired
/// controller must say so instead of failing obscurely.
fn nodes_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<Nodes>, ApiErrorResponse> {
    state.nodes.clone().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("node_unavailable")
                .expect("the literal is valid error code syntax"),
            "the node trust surface is not wired; the controller needs its database and master key",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// A 400 response with a caller-safe message. Kept as a helper so the
/// pinned literal error code lives in one place.
fn invalid_request(message: &str) -> ApiErrorResponse {
    let public = PublicError::new(
        ErrorCode::from_str("invalid_request").expect("the literal is valid error code syntax"),
        message.to_owned(),
        RetryClass::Never,
    );
    ApiError::new(&public, fresh_correlation_id()).with_status(StatusCode::BAD_REQUEST)
}

/// Maps a node use-case outcome onto the public error envelope, once.
pub(crate) fn map_node_error(
    error: &NodeUseCaseError,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    let (status, code, retry): (StatusCode, &str, RetryClass) = match error {
        NodeUseCaseError::Denied(_) => (StatusCode::FORBIDDEN, "denied", RetryClass::Never),
        NodeUseCaseError::NotFound { .. } => {
            (StatusCode::NOT_FOUND, "not_found", RetryClass::Never)
        }
        NodeUseCaseError::Conflict { .. } => (StatusCode::CONFLICT, "conflict", RetryClass::Never),
        NodeUseCaseError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
        ),
        NodeUseCaseError::Unauthorized { .. } => {
            (StatusCode::UNAUTHORIZED, "unauthorized", RetryClass::Never)
        }
        NodeUseCaseError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    // Backend details stay out of the response; every other detail is
    // caller-safe by construction in the use cases.
    let message = match error {
        NodeUseCaseError::Backend { .. } => {
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

// ---------------------------------------------------------------------------
// Machine-facing endpoints (node protocol surface, not in the OpenAPI doc)
// ---------------------------------------------------------------------------

/// The machine-facing node router, nested at `/api/node/v1` by the
/// controller. Paths are relative to that prefix.
pub fn node_router(state: Arc<crate::operations::ApiState>) -> axum::Router {
    use axum::routing::post;
    axum::Router::new()
        .route("/enroll", post(enroll))
        .route("/challenge", post(challenge))
        .route("/session", post(session))
        .route("/rotate", post(rotate))
        .with_state(state)
}

/// A fresh correlation identity for the node surface, which does not share
/// the browser/CLI request correlation middleware.
fn fresh_correlation_id() -> CorrelationId {
    UuidV7Generator.next_correlation_id()
}

/// The enrollment request from `fleetd`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollRequest {
    /// The single-use enrollment token, as shown to the operator once.
    pub token: String,
    /// The node's hex-encoded Ed25519 public key. The private key never
    /// leaves the node.
    pub public_key: String,
    /// The node's operating system, e.g. `linux`.
    #[serde(default)]
    pub os: String,
    /// The node's architecture, e.g. `x86_64`.
    #[serde(default)]
    pub arch: String,
    /// The node software version.
    #[serde(default)]
    pub node_version: String,
}

/// The enrollment response: the confirmed machine and the signed credential.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollResponse {
    /// The machine the node now belongs to.
    pub machine_id: String,
    /// The signed node credential token.
    pub credential: String,
    /// Credential expiry (epoch milliseconds).
    pub credential_expires_at: i64,
    /// Whether this enrollment replaced a revoked identity.
    pub rebind: bool,
}

/// Enrolls a node: consumes the single-use token, binds the public key, and
/// returns the machine plus a signed credential.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
pub async fn enroll(
    State(state): State<Arc<crate::operations::ApiState>>,
    Json(request): Json<EnrollRequest>,
) -> Result<(StatusCode, Json<Resource<EnrollResponse>>), ApiErrorResponse> {
    let nodes = nodes_or_error(&state, fresh_correlation_id())?;
    let outcome = nodes
        .enroll(
            &request.token,
            &request.public_key,
            &request.os,
            &request.arch,
            &request.node_version,
        )
        .await
        .map_err(|error| map_node_error(&error, fresh_correlation_id()))?;
    Ok((
        StatusCode::CREATED,
        Json(Resource::new(EnrollResponse {
            machine_id: outcome.machine_id,
            credential: outcome.credential_token,
            credential_expires_at: outcome.credential_expires_at,
            rebind: outcome.rebind,
        })),
    ))
}

/// The challenge request: a live node credential.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeRequest {
    /// The node credential token.
    pub credential: String,
    /// The requested purpose; `session` by default, `rotate` needs
    /// `new_public_key`.
    pub purpose: Option<String>,
    /// For rotate challenges, the new hex-encoded public key.
    pub new_public_key: Option<String>,
}

/// The challenge response: the nonce to sign.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    /// The challenge's identity; part of the signed proof message.
    pub challenge_id: String,
    /// The machine the challenge was issued to.
    pub machine_id: String,
    /// The hex-encoded nonce to sign.
    pub nonce: String,
    /// What the proof will obtain.
    pub purpose: String,
    /// Expiry (epoch milliseconds).
    pub expires_at: i64,
}

/// Issues a single-use proof challenge for a live credential.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
pub async fn challenge(
    State(state): State<Arc<crate::operations::ApiState>>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<Resource<ChallengeResponse>>, ApiErrorResponse> {
    let nodes = nodes_or_error(&state, fresh_correlation_id())?;
    let purpose = match request.purpose.as_deref() {
        None | Some("session") => ChallengePurpose::Session,
        Some("rotate") => ChallengePurpose::Rotate,
        Some(other) => {
            return Err(invalid_request(&format!(
                "unknown challenge purpose {other:?}; use \"session\" or \"rotate\""
            )));
        }
    };
    let challenge = nodes
        .challenge(
            &request.credential,
            purpose,
            request.new_public_key.as_deref(),
        )
        .await
        .map_err(|error| map_node_error(&error, fresh_correlation_id()))?;
    Ok(Json(Resource::new(ChallengeResponse {
        challenge_id: challenge.id,
        machine_id: challenge.machine_id,
        nonce: challenge.nonce,
        purpose: challenge.purpose.id().to_owned(),
        expires_at: challenge.expires_at,
    })))
}

/// The session request: the credential plus the proof of key possession.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRequest {
    /// The node credential token.
    pub credential: String,
    /// The challenge that was issued for this proof.
    pub challenge_id: String,
    /// The hex-encoded Ed25519 signature over the canonical proof message.
    pub signature: String,
}

/// The session response: the short-lived signed session token.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    /// The machine the session belongs to.
    pub machine_id: String,
    /// The signed session token.
    pub session: String,
    /// Session expiry (epoch milliseconds).
    pub session_expires_at: i64,
}

/// Exchanges a verified key proof for a short-lived node session.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
pub async fn session(
    State(state): State<Arc<crate::operations::ApiState>>,
    Json(request): Json<SessionRequest>,
) -> Result<Json<Resource<SessionResponse>>, ApiErrorResponse> {
    let nodes = nodes_or_error(&state, fresh_correlation_id())?;
    let outcome = nodes
        .prove_session(
            &request.credential,
            &request.challenge_id,
            &request.signature,
        )
        .await
        .map_err(|error| map_node_error(&error, fresh_correlation_id()))?;
    Ok(Json(Resource::new(SessionResponse {
        machine_id: outcome.machine_id,
        session: outcome.session_token,
        session_expires_at: outcome.session_expires_at,
    })))
}

/// The rotation request: the current credential, the new public key, and the
/// proof signed with the new key.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateRequest {
    /// The current node credential token.
    pub credential: String,
    /// The new hex-encoded public key.
    pub new_public_key: String,
    /// The rotate challenge that was issued for this rotation.
    pub challenge_id: String,
    /// The hex-encoded signature made with the *new* private key.
    pub signature: String,
}

/// The rotation response: the machine and a new credential bound to the new
/// key. Every outstanding credential and session of the machine was revoked.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateResponse {
    /// The machine whose identity rotated.
    pub machine_id: String,
    /// The new signed credential token.
    pub credential: String,
    /// The new node key version.
    pub node_key_version: i64,
    /// The new credential's expiry (epoch milliseconds).
    pub credential_expires_at: i64,
}

/// Rotates the node identity with a new key, proven by signature.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
pub async fn rotate(
    State(state): State<Arc<crate::operations::ApiState>>,
    Json(request): Json<RotateRequest>,
) -> Result<Json<Resource<RotateResponse>>, ApiErrorResponse> {
    let nodes = nodes_or_error(&state, fresh_correlation_id())?;
    let outcome = nodes
        .rotate(
            &request.credential,
            &request.new_public_key,
            &request.challenge_id,
            &request.signature,
        )
        .await
        .map_err(|error| map_node_error(&error, fresh_correlation_id()))?;
    Ok(Json(Resource::new(RotateResponse {
        machine_id: outcome.machine_id,
        credential: outcome.credential_token,
        node_key_version: outcome.node_key_version,
        credential_expires_at: outcome.credential_expires_at,
    })))
}

// ---------------------------------------------------------------------------
// Operator-facing endpoints (public OpenAPI contract)
// ---------------------------------------------------------------------------

/// A node identity, as the operator sees it.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeIdentityDto {
    /// The machine the identity belongs to.
    pub machine_id: String,
    /// The hex-encoded Ed25519 public key.
    pub public_key: String,
    /// Monotonic key version.
    pub key_version: i64,
    /// `active` or `revoked`.
    pub status: String,
    /// The operating system the node reported.
    pub os: String,
    /// The architecture the node reported.
    pub arch: String,
    /// The node software version the node reported.
    pub node_version: String,
    /// First enrollment time (epoch milliseconds).
    pub enrolled_at: i64,
    /// Last rotation time, when any (epoch milliseconds).
    pub rotated_at: Option<i64>,
}

/// A node credential record. The signed token is never stored or returned.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeCredentialDto {
    /// The credential's identity.
    pub id: String,
    /// The machine the credential belongs to.
    pub machine_id: String,
    /// The node key version the credential is bound to.
    pub node_key_version: i64,
    /// Issue time (epoch milliseconds).
    pub issued_at: i64,
    /// Expiry (epoch milliseconds).
    pub expires_at: i64,
    /// `active` or `revoked`.
    pub status: String,
    /// Last presentation time, when any (epoch milliseconds).
    pub last_used_at: Option<i64>,
}

/// An enrollment token's facts. The token value appears only once, in the
/// create response.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentTokenDto {
    /// The token record's identity.
    pub id: String,
    /// The machine the token is scoped to.
    pub machine_id: String,
    /// `pending`, `consumed`, or `expired`.
    pub status: String,
    /// Creation time (epoch milliseconds).
    pub created_at: i64,
    /// Expiry (epoch milliseconds).
    pub expires_at: i64,
    /// Consumption time, when consumed (epoch milliseconds).
    pub consumed_at: Option<i64>,
}

/// A machine's node state.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeViewDto {
    /// The machine the view describes.
    pub machine_id: String,
    /// The bound identity, when the machine is enrolled.
    pub identity: Option<NodeIdentityDto>,
    /// Tokens that are still pending.
    pub pending_tokens: Vec<EnrollmentTokenDto>,
    /// Active credentials.
    pub active_credentials: Vec<NodeCredentialDto>,
    /// The number of active sessions.
    pub active_sessions: i64,
}

/// The create-enrollment-token request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateEnrollmentTokenRequest {
    /// The token's lifetime in milliseconds, between one minute and one day.
    /// Absent means one hour.
    pub ttl_millis: Option<i64>,
}

/// The create-enrollment-token response. The token value is shown exactly
/// once; only its hash is stored.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentTokenCreatedDto {
    /// The token record's identity.
    pub id: String,
    /// The machine the token is scoped to.
    pub machine_id: String,
    /// The token value. Shown once.
    pub token: String,
    /// Expiry (epoch milliseconds).
    pub expires_at: i64,
}

/// The list-enrollment-tokens response.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct EnrollmentTokenListDto {
    /// The machine's tokens, newest first.
    pub items: Vec<EnrollmentTokenDto>,
}

fn identity_dto(identity: fleet_application::node::NodeIdentity) -> NodeIdentityDto {
    NodeIdentityDto {
        machine_id: identity.machine_id,
        public_key: identity.public_key,
        key_version: identity.key_version,
        status: identity.status.id().to_owned(),
        os: identity.os,
        arch: identity.arch,
        node_version: identity.node_version,
        enrolled_at: identity.enrolled_at,
        rotated_at: identity.rotated_at,
    }
}

fn credential_dto(credential: fleet_application::node::NodeCredential) -> NodeCredentialDto {
    NodeCredentialDto {
        id: credential.id,
        machine_id: credential.machine_id,
        node_key_version: credential.node_key_version,
        issued_at: credential.issued_at,
        expires_at: credential.expires_at,
        status: credential.status.id().to_owned(),
        last_used_at: credential.last_used_at,
    }
}

fn token_dto(token: EnrollmentTokenView) -> EnrollmentTokenDto {
    EnrollmentTokenDto {
        id: token.id,
        machine_id: token.machine_id,
        status: token.status,
        created_at: token.created_at,
        expires_at: token.expires_at,
        consumed_at: token.consumed_at,
    }
}

/// Creates a single-use enrollment token for a machine.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/node/enrollments",
    tag = "nodes",
    operation_id = "createEnrollmentToken",
    params(
        ("machineId" = String, Path, description = "The machine to enroll a node for.")
    ),
    request_body = CreateEnrollmentTokenRequest,
    responses(
        (
            status = 201,
            description = "The token was created. Its value is shown exactly once.",
            body = Resource<EnrollmentTokenCreatedDto>
        ),
        (
            status = 400,
            description = "The request is malformed, or the TTL is out of range.",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "No such machine.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not create enrollment tokens.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn create_enrollment_token(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
    Json(request): Json<CreateEnrollmentTokenRequest>,
) -> Result<(StatusCode, Json<Resource<EnrollmentTokenCreatedDto>>), ApiErrorResponse> {
    let nodes = nodes_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let created = nodes
        .create_token(
            state.authorizer.as_ref(),
            &principal,
            &machine_id,
            request.ttl_millis,
        )
        .await
        .map_err(|error| map_node_error(&error, correlation_id))?;
    Ok((
        StatusCode::CREATED,
        Json(Resource::new(created_dto(created))),
    ))
}

fn created_dto(created: EnrollmentTokenCreated) -> EnrollmentTokenCreatedDto {
    EnrollmentTokenCreatedDto {
        id: created.id,
        machine_id: created.machine_id,
        token: created.token,
        expires_at: created.expires_at,
    }
}

/// Lists a machine's enrollment tokens, newest first, with effective status.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/machines/{machineId}/node/enrollments",
    tag = "nodes",
    operation_id = "listEnrollmentTokens",
    params(
        ("machineId" = String, Path, description = "The machine whose tokens to list.")
    ),
    responses(
        (
            status = 200,
            description = "The machine's tokens.",
            body = EnrollmentTokenListDto
        ),
        (
            status = 404,
            description = "No such machine.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not read node state.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn list_enrollment_tokens(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
) -> Result<Json<EnrollmentTokenListDto>, ApiErrorResponse> {
    let nodes = nodes_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let tokens = nodes
        .list_tokens(state.authorizer.as_ref(), &principal, &machine_id)
        .await
        .map_err(|error| map_node_error(&error, correlation_id))?;
    Ok(Json(EnrollmentTokenListDto {
        items: tokens.into_iter().map(token_dto).collect(),
    }))
}

/// Reads a machine's node state.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/machines/{machineId}/node",
    tag = "nodes",
    operation_id = "getNode",
    params(
        ("machineId" = String, Path, description = "The machine whose node state to read.")
    ),
    responses(
        (
            status = 200,
            description = "The machine's node state.",
            body = Resource<NodeViewDto>
        ),
        (
            status = 404,
            description = "No such machine.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not read node state.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn get_node(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
) -> Result<Json<Resource<NodeViewDto>>, ApiErrorResponse> {
    let nodes = nodes_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let view = nodes
        .node_view(state.authorizer.as_ref(), &principal, &machine_id)
        .await
        .map_err(|error| map_node_error(&error, correlation_id))?;
    Ok(Json(Resource::new(view_dto(view))))
}

fn view_dto(view: NodeView) -> NodeViewDto {
    NodeViewDto {
        machine_id: view.machine_id,
        identity: view.identity.map(identity_dto),
        pending_tokens: view.pending_tokens.into_iter().map(token_dto).collect(),
        active_credentials: view
            .active_credentials
            .into_iter()
            .map(credential_dto)
            .collect(),
        active_sessions: view.active_sessions,
    }
}

/// Revokes a machine's node identity, every credential, and every session.
/// Renewal fails until an explicit re-enrollment.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/node/revoke",
    tag = "nodes",
    operation_id = "revokeNode",
    params(
        ("machineId" = String, Path, description = "The machine whose node to revoke.")
    ),
    responses(
        (
            status = 200,
            description = "The node identity and all credentials and sessions are revoked.",
            body = crate::envelope::Resource<NodeRevokedDto>
        ),
        (
            status = 404,
            description = "No such machine, or the machine has no node identity.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not revoke nodes.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn revoke_node(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
) -> Result<Json<Resource<NodeRevokedDto>>, ApiErrorResponse> {
    let nodes = nodes_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    nodes
        .revoke(state.authorizer.as_ref(), &principal, &machine_id)
        .await
        .map_err(|error| map_node_error(&error, correlation_id))?;
    Ok(Json(Resource::new(NodeRevokedDto {
        machine_id,
        status: NodeStatus::Revoked.id().to_owned(),
    })))
}

/// The outcome of a revocation.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeRevokedDto {
    /// The machine whose node was revoked.
    pub machine_id: String,
    /// The resulting identity status; `revoked`.
    pub status: String,
}
