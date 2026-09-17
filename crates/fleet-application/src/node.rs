//! Node enrollment and identity: how a machine becomes a fully managed node.
//!
//! The controller–node trust model is asymmetric by design (`ADR-0003`): a
//! node generates and keeps an Ed25519 private key in its own storage — the
//! private key never crosses the network — and proves possession of the
//! matching public key on demand. The controller side of that exchange lives
//! here:
//!
//! 1. An **operator** creates a short-lived, single-use enrollment token for
//!    one expected machine (authorized through the permission catalog,
//!    audited). The token value is shown once; only its hash is stored.
//! 2. A **node** enrolls by presenting the token and its public key. The
//!    claim is a single compare-and-set: exactly one enrollment wins; a
//!    replayed or concurrent claim fails.
//! 3. The controller issues a short-lived **node credential**, signed by the
//!    controller and bound to the public key's version.
//! 4. Connections then **prove possession**: the controller issues a
//!    single-use nonce, the node signs the canonical proof message with its
//!    private key, and the controller exchanges the verified proof for a
//!    short-lived node session.
//! 5. **Rotation** replaces the public key (and invalidates every outstanding
//!    credential and session) after the same nonce proof made with the *new*
//!    key. **Revocation** invalidates everything and prevents renewal; the
//!    disconnect itself is the gateway's job (FM-205).
//!
//! Authorization has two shapes, and both are deliberate:
//!
//! - Operator actions go through the centralized
//!   [`crate::authz::Authorizer`] with the `node.*` permissions.
//! - Node-driven actions (enroll, proof, rotation) are authorized by the
//!   cryptographic material itself — a single-use, expiring, hashed token, or
//!   a signature over a controller-issued nonce. They never touch the user
//!   catalog, and their audit events record `node:<machine-id>` as the actor.
//!
//! Node sessions are a separate principal surface: no user-API use case
//! accepts a node session, so a compromised node cannot reach the operator
//! API with it.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::audit::AuditIntent;
use crate::audit::AuditMetadata;
use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::operation::{AuditPort, PortFailure};

/// The shortest enrollment-token lifetime: one minute.
pub const MIN_TOKEN_TTL_MILLIS: i64 = 60_000;
/// The longest enrollment-token lifetime: one day.
pub const MAX_TOKEN_TTL_MILLIS: i64 = 86_400_000;
/// The default enrollment-token lifetime: one hour.
pub const DEFAULT_TOKEN_TTL_MILLIS: i64 = 3_600_000;

/// The default node-credential lifetime: seven days. Credentials are renewed
/// by key proof, so they are deliberately short relative to node lifetime.
pub const DEFAULT_CREDENTIAL_TTL_MILLIS: i64 = 7 * 24 * 3_600_000;
/// The longest node-credential lifetime: thirty days.
pub const MAX_CREDENTIAL_TTL_MILLIS: i64 = 30 * 24 * 3_600_000;

/// The default node-session lifetime: ten minutes.
pub const DEFAULT_SESSION_TTL_MILLIS: i64 = 600_000;
/// The longest node-session lifetime: one hour.
pub const MAX_SESSION_TTL_MILLIS: i64 = 3_600_000;

/// The lifetime of a proof challenge nonce: sixty seconds.
pub const CHALLENGE_TTL_MILLIS: i64 = 60_000;

/// The status of a node identity, credential, or session.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    /// Live and trusted.
    Active,
    /// Revoked or superseded; nothing may be renewed against it.
    Revoked,
}

impl NodeStatus {
    /// The stable string used in storage and the API.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    /// Parses the stable string.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// What a proof challenge is for.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengePurpose {
    /// Prove possession to obtain a node session.
    Session,
    /// Prove possession *with a new key* to rotate the node identity.
    Rotate,
}

impl ChallengePurpose {
    /// The stable string used in storage and in the proof message.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Rotate => "rotate",
        }
    }

    /// Parses the stable string.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "session" => Some(Self::Session),
            "rotate" => Some(Self::Rotate),
            _ => None,
        }
    }
}

/// The durable gateway connectivity state of a node, as the session
/// registry persists it. Only transitions are written; heartbeats never
/// touch storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayState {
    /// The gateway session is open and heartbeats are fresh.
    Connected,
    /// The session is open but heartbeats aged past the threshold: a
    /// half-dead connection, not an absent one.
    Stale,
    /// No open session: the node is absent.
    Offline,
}

impl GatewayState {
    /// The stable string used in storage and the API.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Stale => "stale",
            Self::Offline => "offline",
        }
    }

    /// Parses the stable string.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "connected" => Some(Self::Connected),
            "stale" => Some(Self::Stale),
            "offline" => Some(Self::Offline),
            _ => None,
        }
    }
}

/// A node's bound identity: the public key and its monotonic version.
///
/// `key_version` exists so a credential records which key it was bound to:
/// rotation bumps the version and every credential of an older version is
/// invalid even before its row is revoked.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeIdentity {
    /// The machine this node belongs to.
    pub machine_id: String,
    /// The hex-encoded 32-byte Ed25519 public key.
    pub public_key: String,
    /// Monotonic key version; bumped by rotation and re-enrollment.
    pub key_version: i64,
    /// The identity's status.
    pub status: NodeStatus,
    /// The operating system the node reported at enrollment.
    pub os: String,
    /// The architecture the node reported at enrollment.
    pub arch: String,
    /// The node software version the node reported at enrollment.
    pub node_version: String,
    /// First enrollment time (epoch milliseconds).
    pub enrolled_at: i64,
    /// Last rotation or re-bind time, when any (epoch milliseconds).
    pub rotated_at: Option<i64>,
    /// The durable gateway state the session registry last persisted.
    pub gateway_state: GatewayState,
    /// The last gateway observation time, when the node ever connected
    /// (epoch milliseconds).
    pub last_seen_at: Option<i64>,
    /// The boot session id of the last open gateway session, when any.
    pub boot_session_id: Option<String>,
}

/// A node credential as recorded: the signed token is derived from these
/// facts, never stored.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeCredential {
    /// The credential's identity.
    pub id: String,
    /// The machine the credential belongs to.
    pub machine_id: String,
    /// The node key version this credential is bound to.
    pub node_key_version: i64,
    /// Issue time (epoch milliseconds).
    pub issued_at: i64,
    /// Expiry (epoch milliseconds).
    pub expires_at: i64,
    /// The credential's status.
    pub status: NodeStatus,
    /// Last successful presentation, when any (epoch milliseconds).
    pub last_used_at: Option<i64>,
}

/// A single-use proof challenge.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeChallenge {
    /// The challenge's identity.
    pub id: String,
    /// The machine the challenge was issued to.
    pub machine_id: String,
    /// The hex-encoded nonce the node must sign.
    pub nonce: String,
    /// What the proof will obtain.
    pub purpose: ChallengePurpose,
    /// For `rotate` challenges: the new public key the proof must bind.
    pub new_public_key: Option<String>,
    /// Expiry (epoch milliseconds).
    pub expires_at: i64,
}

/// The facts stored about an enrollment token. The token value itself is
/// shown once at creation and never stored.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentTokenView {
    /// The token record's identity.
    pub id: String,
    /// The machine the token is scoped to.
    pub machine_id: String,
    /// The effective status: `pending`, `consumed`, or `expired` (computed
    /// against the read time, so a pending token that aged out reports
    /// honestly).
    pub status: String,
    /// Creation time (epoch milliseconds).
    pub created_at: i64,
    /// Expiry (epoch milliseconds).
    pub expires_at: i64,
    /// Consumption time, when consumed (epoch milliseconds).
    pub consumed_at: Option<i64>,
}

/// The result of creating an enrollment token: the record's facts plus the
/// token value, which is returned exactly once.
#[derive(Clone, Debug)]
pub struct EnrollmentTokenCreated {
    /// The token record's identity.
    pub id: String,
    /// The machine the token is scoped to.
    pub machine_id: String,
    /// The raw token value. Shown once; only its hash is stored.
    pub token: String,
    /// Expiry (epoch milliseconds).
    pub expires_at: i64,
}

/// The durable facts of a new token record, as returned by the port. The
/// token value lives only in the use case that generated it.
#[derive(Clone, Debug)]
pub struct EnrollmentTokenRecord {
    /// The token record's identity.
    pub id: String,
    /// The machine the token is scoped to.
    pub machine_id: String,
    /// Expiry (epoch milliseconds).
    pub expires_at: i64,
}

/// A node view: everything the operator surface needs about one machine's
/// node state. Values never appear here.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeView {
    /// The machine the view describes.
    pub machine_id: String,
    /// The bound identity, when the machine is enrolled.
    pub identity: Option<NodeIdentity>,
    /// Tokens that are still pending (not consumed and not expired).
    pub pending_tokens: Vec<EnrollmentTokenView>,
    /// Active credentials.
    pub active_credentials: Vec<NodeCredential>,
    /// The number of active sessions.
    pub active_sessions: i64,
}

/// The outcome of a successful enrollment.
#[derive(Clone, Debug)]
pub struct EnrolledNode {
    /// The machine that now has a node identity.
    pub machine_id: String,
    /// The minted credential's identity.
    pub credential_id: String,
    /// The node key version the credential is bound to.
    pub node_key_version: i64,
    /// Credential expiry (epoch milliseconds).
    pub credential_expires_at: i64,
    /// Whether this enrollment replaced a previously revoked identity.
    pub rebind: bool,
}

/// The claims of a node credential token. The codec signs exactly these
/// facts; every byte of them must round-trip through verification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeCredentialClaims {
    /// The credential record's identity.
    pub credential_id: String,
    /// The machine the credential belongs to.
    pub machine_id: String,
    /// The node key version the credential is bound to.
    pub node_key_version: i64,
    /// Expiry (epoch milliseconds).
    pub expires_at: i64,
}

/// The claims of a node session token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSessionClaims {
    /// The session record's identity.
    pub session_id: String,
    /// The credential the session was exchanged from.
    pub credential_id: String,
    /// The machine the session belongs to.
    pub machine_id: String,
    /// Expiry (epoch milliseconds).
    pub expires_at: i64,
}

/// The outcome of proving possession: a signed session token.
#[derive(Clone, Debug)]
pub struct NodeSessionIssued {
    /// The session record's identity.
    pub session_id: String,
    /// The machine the session belongs to.
    pub machine_id: String,
    /// The credential the session was exchanged from.
    pub credential_id: String,
    /// Expiry (epoch milliseconds).
    pub expires_at: i64,
}

/// The outcome of a successful key rotation.
#[derive(Clone, Debug)]
pub struct RotationOutcome {
    /// The machine whose identity rotated.
    pub machine_id: String,
    /// The new credential's identity.
    pub credential_id: String,
    /// The new node key version.
    pub node_key_version: i64,
    /// The new credential's expiry (epoch milliseconds).
    pub credential_expires_at: i64,
}

/// Whether a node session is currently valid, and for which machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionValidity {
    /// The session, its credential, and the identity are all live.
    Valid {
        /// The machine the session belongs to.
        machine_id: String,
        /// The credential the session was exchanged from.
        credential_id: String,
    },
    /// The session is not trustworthy; the detail names why, safe to log.
    Invalid {
        /// Why the session is invalid.
        detail: String,
    },
}

/// Facts read from a token record before claiming it, letting the use case
/// build the audit intent with the right machine before the atomic claim.
#[derive(Clone, Debug)]
pub struct TokenFacts {
    /// The token record's identity.
    pub id: String,
    /// The machine the token is scoped to.
    pub machine_id: String,
    /// Whether the token is still `pending`.
    pub status: String,
    /// Expiry (epoch milliseconds).
    pub expires_at: i64,
}

/// A storage problem on the node port. Distinguishable so the node-facing
/// surface can answer honestly: `Used` and `Expired` are authentication
/// outcomes, not server faults.
#[derive(Debug)]
pub enum NodePortError {
    /// The referenced record does not exist.
    NotFound {
        /// What was not found.
        what: String,
    },
    /// The action conflicts with existing state, e.g. the machine is
    /// already enrolled.
    Conflict {
        /// What conflicts.
        detail: String,
    },
    /// The token, challenge, credential, or session aged out.
    Expired {
        /// What expired.
        what: String,
    },
    /// A single-use record was already consumed.
    AlreadyUsed {
        /// What was consumed.
        what: String,
    },
    /// The action is refused because the security state behind it is no
    /// longer live: a revoked identity, a credential whose key rotated, or
    /// a challenge that does not match the request.
    Rejected {
        /// Why the action was refused; safe to return to the caller.
        detail: String,
    },
    /// A backend failure; the detail is safe to print.
    Backend {
        /// The failure detail.
        detail: String,
    },
}

impl fmt::Display for NodePortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Conflict { detail } => write!(f, "conflict: {detail}"),
            Self::Expired { what } => write!(f, "expired: {what}"),
            Self::AlreadyUsed { what } => write!(f, "already used: {what}"),
            Self::Rejected { detail } => write!(f, "rejected: {detail}"),
            Self::Backend { detail } => write!(f, "node backend failure: {detail}"),
        }
    }
}

impl std::error::Error for NodePortError {}

impl From<PortFailure> for NodePortError {
    fn from(failure: PortFailure) -> Self {
        match failure {
            PortFailure::NotFound { what } => Self::NotFound { what },
            PortFailure::Conflict { detail } => Self::Conflict { detail },
            PortFailure::Backend { detail } => Self::Backend { detail },
        }
    }
}

/// A use-case rejection, mapped onto HTTP statuses by the adapters.
#[derive(Debug)]
pub enum NodeUseCaseError {
    /// The operator may not perform the action.
    Denied(Decision),
    /// The machine, token, credential, or challenge named does not exist.
    NotFound {
        /// What was not found.
        what: String,
    },
    /// The action conflicts with existing state.
    Conflict {
        /// What conflicts.
        detail: String,
    },
    /// The request is malformed.
    Invalid {
        /// What is wrong.
        detail: String,
    },
    /// Authentication failed: a token, credential, or proof did not verify,
    /// or the state behind them is no longer live.
    Unauthorized {
        /// Why authentication failed; safe to return to the caller.
        detail: String,
    },
    /// The port or audit sink failed.
    Backend {
        /// The failing half.
        context: &'static str,
        /// The failure detail.
        detail: String,
    },
}

impl fmt::Display for NodeUseCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Conflict { detail } => write!(f, "conflict: {detail}"),
            Self::Invalid { detail } => write!(f, "invalid request: {detail}"),
            Self::Unauthorized { detail } => write!(f, "unauthorized: {detail}"),
            Self::Backend { context, detail } => write!(f, "node {context} failed: {detail}"),
        }
    }
}

impl std::error::Error for NodeUseCaseError {}

fn map_port(context: &'static str, error: NodePortError) -> NodeUseCaseError {
    match error {
        NodePortError::NotFound { what } => NodeUseCaseError::NotFound { what },
        NodePortError::Conflict { detail } => NodeUseCaseError::Conflict { detail },
        NodePortError::Expired { what } => NodeUseCaseError::Unauthorized {
            detail: format!("{what} has expired"),
        },
        NodePortError::AlreadyUsed { what } => NodeUseCaseError::Unauthorized {
            detail: format!("{what} was already used"),
        },
        NodePortError::Rejected { detail } => NodeUseCaseError::Unauthorized { detail },
        NodePortError::Backend { detail } => NodeUseCaseError::Backend { context, detail },
    }
}

/// A new enrollment token, before the value is generated.
#[derive(Clone, Debug)]
pub struct NewEnrollmentToken {
    /// The machine the token is scoped to.
    pub machine_id: String,
    /// The token's SHA-256 hash (the only durable form of the value).
    pub token_hash: String,
    /// Lifetime in milliseconds, bounded by the use case.
    pub ttl_millis: i64,
    /// The creating principal.
    pub created_by: String,
    /// Creation time (epoch milliseconds).
    pub now: i64,
}

/// The read that precedes an enrollment claim: machine and status facts the
/// use case needs to build the audit intent.
#[derive(Clone, Debug)]
pub struct EnrollClaim {
    /// The token's hash, the lookup key.
    pub token_hash: String,
    /// The node's hex-encoded Ed25519 public key.
    pub public_key: String,
    /// The node's reported operating system.
    pub os: String,
    /// The node's reported architecture.
    pub arch: String,
    /// The node's reported software version.
    pub node_version: String,
    /// Claim time (epoch milliseconds).
    pub now: i64,
    /// The minted credential's lifetime in milliseconds.
    pub credential_ttl_millis: i64,
    /// The audit intent written inside the claim transaction.
    pub audit: AuditIntent,
}

/// A session-exchange claim, executed atomically by the port.
#[derive(Clone, Debug)]
pub struct SessionClaim {
    /// The challenge to consume.
    pub challenge_id: String,
    /// The credential the session is exchanged from.
    pub credential_id: String,
    /// The session's lifetime in milliseconds.
    pub session_ttl_millis: i64,
    /// Claim time (epoch milliseconds).
    pub now: i64,
    /// The audit intent written inside the claim transaction.
    pub audit: AuditIntent,
}

/// A rotation claim, executed atomically by the port.
#[derive(Clone, Debug)]
pub struct RotateClaim {
    /// The rotate challenge to consume.
    pub challenge_id: String,
    /// The still-valid credential that requested the rotation.
    pub credential_id: String,
    /// The new hex-encoded public key, proven by the signature.
    pub new_public_key: String,
    /// The new credential's lifetime in milliseconds.
    pub credential_ttl_millis: i64,
    /// Claim time (epoch milliseconds).
    pub now: i64,
    /// The audit intent written inside the rotation transaction.
    pub audit: AuditIntent,
}

/// The storage contract for node enrollment and identity. Methods that mint
/// or consume security state run in one transaction each — including the
/// audit intent they are handed — so an accepted action and its audit record
/// commit together or not at all.
#[async_trait]
pub trait NodePort: fmt::Debug + Send + Sync {
    /// Creates an enrollment token record from its hash. The value was shown
    /// to the operator already; only the hash crosses this boundary.
    ///
    /// # Errors
    ///
    /// Fails when the machine is unknown or the backend errors.
    async fn create_token(
        &self,
        new: &NewEnrollmentToken,
    ) -> Result<EnrollmentTokenRecord, NodePortError>;
    /// Lists a machine's enrollment tokens, newest first, with their
    /// effective status computed against `now`.
    ///
    /// # Errors
    ///
    /// Fails when the machine is unknown or the backend errors.
    async fn list_tokens(
        &self,
        machine_id: &str,
        now: i64,
    ) -> Result<Vec<EnrollmentTokenView>, NodePortError>;
    /// The facts of a token by hash, when it exists.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn token_facts(&self, token_hash: &str) -> Result<Option<TokenFacts>, NodePortError>;
    /// Claims a token and binds the node identity atomically: the token CAS
    /// (`pending` → `consumed`), the identity insert-or-rebind, the minted
    /// credential row, and the audit intent commit together.
    ///
    /// # Errors
    ///
    /// Fails when the token is unknown, used, or expired, when the machine
    /// already has an active identity, or the backend errors.
    async fn enroll(&self, claim: &EnrollClaim) -> Result<EnrolledNode, NodePortError>;
    /// A machine's node identity, when enrolled.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn identity(&self, machine_id: &str) -> Result<Option<NodeIdentity>, NodePortError>;
    /// Issues a single-use proof challenge.
    ///
    /// # Errors
    ///
    /// Fails when the machine has no active identity or the backend errors.
    async fn issue_challenge(&self, new: &NewChallenge) -> Result<NodeChallenge, NodePortError>;
    /// A challenge by id, when it exists.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn challenge(&self, challenge_id: &str) -> Result<Option<NodeChallenge>, NodePortError>;
    /// A credential by id, when it exists.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<NodeCredential>, NodePortError>;
    /// Consumes a session challenge and issues a session atomically: the
    /// challenge CAS, the session row, and the audit intent commit together.
    /// The transaction re-validates the challenge, credential, and identity
    /// state, so a proof race loses here even if the reads raced earlier.
    ///
    /// # Errors
    ///
    /// Fails when the challenge is unknown, used, or expired, the credential
    /// or identity is no longer live, or the backend errors.
    async fn consume_challenge_and_issue_session(
        &self,
        claim: &SessionClaim,
    ) -> Result<NodeSessionIssued, NodePortError>;
    /// Rotates the node identity atomically: the challenge CAS, the key
    /// bump, the revocation of every outstanding credential and session, the
    /// new credential row, and the audit intent commit together.
    ///
    /// # Errors
    ///
    /// Fails when the challenge is unknown, used, expired, or for another
    /// key, the credential is no longer live, or the backend errors.
    async fn rotate_key(&self, claim: &RotateClaim) -> Result<RotationOutcome, NodePortError>;
    /// Revokes the identity and every credential and session of a machine.
    /// Renewal fails until an explicit re-enrollment replaces the revoked
    /// identity.
    ///
    /// # Errors
    ///
    /// Fails when the machine has no identity or the backend errors.
    async fn revoke_identity(&self, machine_id: &str) -> Result<(), NodePortError>;
    /// The node view of a machine, or `None` when the machine is unknown.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn node_view(
        &self,
        machine_id: &str,
        now: i64,
    ) -> Result<Option<NodeView>, NodePortError>;
    /// Validates a session against durable state: session, credential, and
    /// identity must all be live and unexpired.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn validate_session(
        &self,
        session_id: &str,
        now: i64,
    ) -> Result<SessionValidity, NodePortError>;
    /// Records that a credential was presented successfully. Best effort.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn touch_credential(
        &self,
        credential_id: &str,
        used_at: i64,
    ) -> Result<(), NodePortError>;
    /// Persists one gateway-state transition. The session registry calls
    /// this on connect, staleness, and disconnect only — never per
    /// heartbeat — so an open, healthy session costs no writes at all.
    ///
    /// # Errors
    ///
    /// Fails when the machine has no identity or the backend errors.
    async fn record_gateway_state(
        &self,
        machine_id: &str,
        state: GatewayState,
        boot_session: Option<&str>,
        last_seen: i64,
    ) -> Result<(), NodePortError>;
}

/// A new proof challenge.
#[derive(Clone, Debug)]
pub struct NewChallenge {
    /// The machine to challenge.
    pub machine_id: String,
    /// The hex-encoded nonce the node must sign.
    pub nonce: String,
    /// What the proof will obtain.
    pub purpose: ChallengePurpose,
    /// For rotate challenges, the new public key the proof must bind.
    pub new_public_key: Option<String>,
    /// Issue time (epoch milliseconds).
    pub now: i64,
    /// Expiry (epoch milliseconds).
    pub expires_at: i64,
}

/// The cryptographic adapter behind node trust: randomness, hashing, proof
/// verification, and the signed token codec. The application layer depends
/// on this port, never on an implementation.
pub trait NodeCrypto: fmt::Debug + Send + Sync {
    /// Generates a raw enrollment token value. Shown once; never stored.
    fn generate_token(&self) -> String;
    /// The durable form of a token value (its hash).
    fn hash_token(&self, token: &str) -> String;
    /// Generates a hex-encoded proof nonce.
    fn generate_nonce(&self) -> String;
    /// Verifies an Ed25519 signature over `message` with `public_key`.
    /// Returns `false` on any failure; never throws on hostile input.
    fn verify_key_proof(&self, public_key: &str, message: &[u8], signature_hex: &str) -> bool;
    /// Signs a node credential token from its claims.
    ///
    /// # Errors
    ///
    /// Fails only when the codec cannot represent the claims.
    fn issue_credential_token(&self, claims: &NodeCredentialClaims) -> Result<String, String>;
    /// Verifies a node credential token and returns its claims.
    ///
    /// # Errors
    ///
    /// Fails on a malformed, foreign, or tampered token.
    fn verify_credential_token(&self, token: &str) -> Result<NodeCredentialClaims, String>;
    /// Signs a node session token from its claims.
    ///
    /// # Errors
    ///
    /// Fails only when the codec cannot represent the claims.
    fn issue_session_token(&self, claims: &NodeSessionClaims) -> Result<String, String>;
    /// Verifies a node session token and returns its claims.
    ///
    /// # Errors
    ///
    /// Fails on a malformed, foreign, or tampered token.
    fn verify_session_token(&self, token: &str) -> Result<NodeSessionClaims, String>;
}

/// The canonical proof message a node signs: domain-separated, binding the
/// challenge, the machine, the purpose, and — for rotation — the new key.
#[must_use]
pub fn proof_message(
    challenge_id: &str,
    machine_id: &str,
    purpose: ChallengePurpose,
    new_public_key: Option<&str>,
) -> Vec<u8> {
    let mut message = b"fleet-node-proof/v1".to_vec();
    for part in [
        challenge_id,
        machine_id,
        purpose.id(),
        new_public_key.unwrap_or(""),
    ] {
        message.push(0);
        message.extend_from_slice(part.as_bytes());
    }
    message
}

/// Validates the format of a hex-encoded Ed25519 public key: 64 lowercase
/// hex characters. Cryptographic validity is checked at proof verification.
fn validate_public_key(public_key: &str) -> Result<(), NodeUseCaseError> {
    if public_key.len() != 64
        || !public_key
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(NodeUseCaseError::Invalid {
            detail: "the public key must be 64 lowercase hex characters (32 bytes)".to_owned(),
        });
    }
    Ok(())
}

fn validate_facts(value: &str, what: &str) -> Result<(), NodeUseCaseError> {
    if value.len() > 64 {
        return Err(NodeUseCaseError::Invalid {
            detail: format!("{what} must be at most 64 characters"),
        });
    }
    Ok(())
}

/// The authorized node enrollment use cases.
#[derive(Debug)]
pub struct Nodes {
    port: Arc<dyn NodePort>,
    crypto: Arc<dyn NodeCrypto>,
    audit: Arc<dyn AuditPort>,
}

impl Nodes {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(
        port: Arc<dyn NodePort>,
        crypto: Arc<dyn NodeCrypto>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            port,
            crypto,
            audit,
        }
    }

    /// Creates a single-use enrollment token for a machine. The value is
    /// returned exactly once; only its hash is stored.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown machine, a malformed TTL, or a backend
    /// failure.
    pub async fn create_token(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
        ttl_millis: Option<i64>,
    ) -> Result<EnrollmentTokenCreated, NodeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::NodeEnroll,
                resource: Some(machine_id),
            },
        )
        .map_err(NodeUseCaseError::Denied)?;
        let ttl_millis = ttl_millis.unwrap_or(DEFAULT_TOKEN_TTL_MILLIS);
        if !(MIN_TOKEN_TTL_MILLIS..=MAX_TOKEN_TTL_MILLIS).contains(&ttl_millis) {
            return Err(NodeUseCaseError::Invalid {
                detail: format!(
                    "the token TTL must be {MIN_TOKEN_TTL_MILLIS}..={MAX_TOKEN_TTL_MILLIS} ms"
                ),
            });
        }
        let token = self.crypto.generate_token();
        let token_hash = self.crypto.hash_token(&token);
        let record = self
            .port
            .create_token(&NewEnrollmentToken {
                machine_id: machine_id.to_owned(),
                token_hash,
                ttl_millis,
                created_by: principal.id.clone(),
                now: fleet_core::SystemClock::now_unix_millis(),
            })
            .await
            .map_err(|error| map_port("create_token", error))?;
        self.audit_event(
            principal.id.clone(),
            Permission::NodeEnroll.id().to_owned(),
            machine_id,
            "enrollment_token_created",
        )
        .await?;
        Ok(EnrollmentTokenCreated {
            id: record.id,
            machine_id: record.machine_id,
            token,
            expires_at: record.expires_at,
        })
    }

    /// Lists a machine's enrollment tokens, newest first.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown machine, or a backend failure.
    pub async fn list_tokens(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
    ) -> Result<Vec<EnrollmentTokenView>, NodeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::NodeRead,
                resource: Some(machine_id),
            },
        )
        .map_err(NodeUseCaseError::Denied)?;
        self.port
            .list_tokens(machine_id, fleet_core::SystemClock::now_unix_millis())
            .await
            .map_err(|error| map_port("list_tokens", error))
    }

    /// The node view of a machine.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown machine, or a backend failure.
    pub async fn node_view(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
    ) -> Result<NodeView, NodeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::NodeRead,
                resource: Some(machine_id),
            },
        )
        .map_err(NodeUseCaseError::Denied)?;
        self.port
            .node_view(machine_id, fleet_core::SystemClock::now_unix_millis())
            .await
            .map_err(|error| map_port("node_view", error))?
            .ok_or_else(|| NodeUseCaseError::NotFound {
                what: format!("machine {machine_id:?}"),
            })
    }

    /// Revokes a machine's node identity, every credential, and every
    /// session. Renewal fails until an explicit re-enrollment.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown machine or identity, or a backend
    /// failure.
    pub async fn revoke(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
    ) -> Result<(), NodeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::NodeRevoke,
                resource: Some(machine_id),
            },
        )
        .map_err(NodeUseCaseError::Denied)?;
        self.port
            .revoke_identity(machine_id)
            .await
            .map_err(|error| map_port("revoke", error))?;
        self.audit_event(
            principal.id.clone(),
            Permission::NodeRevoke.id().to_owned(),
            machine_id,
            "node_identity_revoked",
        )
        .await?;
        Ok(())
    }

    /// Enrolls a node: consumes the single-use token, binds the public key,
    /// and returns the machine plus a signed node credential. The token is
    /// the authorization; the claim is atomic.
    ///
    /// # Errors
    ///
    /// Fails when the token is malformed, unknown, used, or expired, when
    /// the machine already has an active identity, or on a backend failure.
    pub async fn enroll(
        &self,
        raw_token: &str,
        public_key: &str,
        os: &str,
        arch: &str,
        node_version: &str,
    ) -> Result<EnrollOutcome, NodeUseCaseError> {
        validate_public_key(public_key)?;
        validate_facts(os, "os")?;
        validate_facts(arch, "arch")?;
        validate_facts(node_version, "node version")?;
        let token_hash = self.crypto.hash_token(raw_token);
        let facts = self
            .port
            .token_facts(&token_hash)
            .await
            .map_err(|error| map_port("token_facts", error))?
            .ok_or_else(|| NodeUseCaseError::Unauthorized {
                detail: "the enrollment token is not valid".to_owned(),
            })?;

        let mut metadata = AuditMetadata::default();
        metadata
            .insert("event", "node_enrolled")
            .map_err(|error| NodeUseCaseError::Backend {
                context: "enroll_audit",
                detail: error.to_string(),
            })?;
        let claim = EnrollClaim {
            token_hash,
            public_key: public_key.to_owned(),
            os: os.to_owned(),
            arch: arch.to_owned(),
            node_version: node_version.to_owned(),
            now: fleet_core::SystemClock::now_unix_millis(),
            credential_ttl_millis: DEFAULT_CREDENTIAL_TTL_MILLIS,
            audit: AuditIntent {
                actor: format!("node:{}", facts.machine_id),
                action: Permission::NodeEnroll.id().to_owned(),
                resource: Some(facts.machine_id.clone()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            },
        };
        let enrolled = self
            .port
            .enroll(&claim)
            .await
            .map_err(|error| map_port("enroll", error))?;
        let credential_token = self
            .crypto
            .issue_credential_token(&NodeCredentialClaims {
                credential_id: enrolled.credential_id.clone(),
                machine_id: enrolled.machine_id.clone(),
                node_key_version: enrolled.node_key_version,
                expires_at: enrolled.credential_expires_at,
            })
            .map_err(|detail| NodeUseCaseError::Backend {
                context: "enroll_codec",
                detail,
            })?;
        Ok(EnrollOutcome {
            machine_id: enrolled.machine_id,
            credential_token,
            credential_expires_at: enrolled.credential_expires_at,
            rebind: enrolled.rebind,
        })
    }

    /// Issues a proof challenge for a live credential. Not audited: a
    /// challenge is unauthenticated pre-work — issuing one grants nothing —
    /// and nodes poll often enough that auditing would drown the ledger.
    /// The proof, which does grant something, is audited.
    ///
    /// # Errors
    ///
    /// Fails when the credential does not verify or is no longer live, the
    /// request is malformed, or a backend failure.
    pub async fn challenge(
        &self,
        credential_token: &str,
        purpose: ChallengePurpose,
        new_public_key: Option<&str>,
    ) -> Result<NodeChallenge, NodeUseCaseError> {
        let claims = self
            .crypto
            .verify_credential_token(credential_token)
            .map_err(|detail| NodeUseCaseError::Unauthorized {
                detail: format!("the node credential is not valid: {detail}"),
            })?;
        let identity = self.live_identity(&claims).await?;
        if let Some(new_key) = new_public_key {
            if purpose != ChallengePurpose::Rotate {
                return Err(NodeUseCaseError::Invalid {
                    detail: "a new public key is only accepted for rotate challenges".to_owned(),
                });
            }
            validate_public_key(new_key)?;
            if new_key == identity.public_key {
                return Err(NodeUseCaseError::Invalid {
                    detail: "the new public key must differ from the bound key".to_owned(),
                });
            }
        } else if purpose == ChallengePurpose::Rotate {
            return Err(NodeUseCaseError::Invalid {
                detail: "a rotate challenge requires the new public key".to_owned(),
            });
        }
        let now = fleet_core::SystemClock::now_unix_millis();
        self.port
            .touch_credential(&claims.credential_id, now)
            .await
            .map_err(|error| map_port("touch", error))?;
        self.port
            .issue_challenge(&NewChallenge {
                machine_id: claims.machine_id.clone(),
                nonce: self.crypto.generate_nonce(),
                purpose,
                new_public_key: new_public_key.map(str::to_owned),
                now,
                expires_at: now + CHALLENGE_TTL_MILLIS,
            })
            .await
            .map_err(|error| map_port("issue_challenge", error))
    }

    /// Exchanges a verified key proof for a short-lived node session.
    ///
    /// # Errors
    ///
    /// Fails when the credential, challenge, or proof does not verify, when
    /// the underlying state is no longer live, or on a backend failure.
    pub async fn prove_session(
        &self,
        credential_token: &str,
        challenge_id: &str,
        signature_hex: &str,
    ) -> Result<SessionOutcome, NodeUseCaseError> {
        let claims = self
            .crypto
            .verify_credential_token(credential_token)
            .map_err(|detail| NodeUseCaseError::Unauthorized {
                detail: format!("the node credential is not valid: {detail}"),
            })?;
        let identity = self.live_identity(&claims).await?;
        let challenge = self
            .port
            .challenge(challenge_id)
            .await
            .map_err(|error| map_port("challenge", error))?
            .ok_or_else(|| NodeUseCaseError::NotFound {
                what: format!("challenge {challenge_id:?}"),
            })?;
        if challenge.machine_id != claims.machine_id
            || challenge.purpose != ChallengePurpose::Session
        {
            return Err(NodeUseCaseError::Unauthorized {
                detail: "the challenge does not match this credential".to_owned(),
            });
        }
        if challenge.expires_at <= fleet_core::SystemClock::now_unix_millis() {
            return Err(NodeUseCaseError::Unauthorized {
                detail: "the challenge has expired".to_owned(),
            });
        }
        let message = proof_message(
            challenge_id,
            &claims.machine_id,
            ChallengePurpose::Session,
            None,
        );
        if !self
            .crypto
            .verify_key_proof(&identity.public_key, &message, signature_hex)
        {
            return Err(NodeUseCaseError::Unauthorized {
                detail: "the key proof did not verify".to_owned(),
            });
        }

        let mut metadata = AuditMetadata::default();
        metadata
            .insert("event", "node_session_issued")
            .map_err(|error| NodeUseCaseError::Backend {
                context: "session_audit",
                detail: error.to_string(),
            })?;
        let claim = SessionClaim {
            challenge_id: challenge_id.to_owned(),
            credential_id: claims.credential_id.clone(),
            session_ttl_millis: DEFAULT_SESSION_TTL_MILLIS,
            now: fleet_core::SystemClock::now_unix_millis(),
            audit: AuditIntent {
                actor: format!("node:{}", claims.machine_id),
                action: "node.session".to_owned(),
                resource: Some(claims.machine_id.clone()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            },
        };
        let issued = self
            .port
            .consume_challenge_and_issue_session(&claim)
            .await
            .map_err(|error| map_port("issue_session", error))?;
        let session_token = self
            .crypto
            .issue_session_token(&NodeSessionClaims {
                session_id: issued.session_id.clone(),
                credential_id: issued.credential_id.clone(),
                machine_id: issued.machine_id.clone(),
                expires_at: issued.expires_at,
            })
            .map_err(|detail| NodeUseCaseError::Backend {
                context: "session_codec",
                detail,
            })?;
        Ok(SessionOutcome {
            machine_id: issued.machine_id,
            session_token,
            session_expires_at: issued.expires_at,
        })
    }

    /// Rotates the node identity: the new key proves possession, every
    /// outstanding credential and session is revoked, and a new credential
    /// is issued.
    ///
    /// # Errors
    ///
    /// Fails when the credential or challenge does not verify, the proof is
    /// wrong or was made with the old key, the underlying state is no longer
    /// live, or on a backend failure.
    pub async fn rotate(
        &self,
        credential_token: &str,
        new_public_key: &str,
        challenge_id: &str,
        signature_hex: &str,
    ) -> Result<RotateOutcome, NodeUseCaseError> {
        validate_public_key(new_public_key)?;
        let claims = self
            .crypto
            .verify_credential_token(credential_token)
            .map_err(|detail| NodeUseCaseError::Unauthorized {
                detail: format!("the node credential is not valid: {detail}"),
            })?;
        // The rotation gate still requires a live identity and credential;
        // the signature itself is verified against the *new* key below.
        self.live_identity(&claims).await?;
        let challenge = self
            .port
            .challenge(challenge_id)
            .await
            .map_err(|error| map_port("challenge", error))?
            .ok_or_else(|| NodeUseCaseError::NotFound {
                what: format!("challenge {challenge_id:?}"),
            })?;
        if challenge.machine_id != claims.machine_id
            || challenge.purpose != ChallengePurpose::Rotate
            || challenge.new_public_key.as_deref() != Some(new_public_key)
        {
            return Err(NodeUseCaseError::Unauthorized {
                detail: "the challenge does not match this rotation".to_owned(),
            });
        }
        if challenge.expires_at <= fleet_core::SystemClock::now_unix_millis() {
            return Err(NodeUseCaseError::Unauthorized {
                detail: "the challenge has expired".to_owned(),
            });
        }
        let message = proof_message(
            challenge_id,
            &claims.machine_id,
            ChallengePurpose::Rotate,
            Some(new_public_key),
        );
        // Rotation is proven by the *new* key: whoever controls the new key
        // pair must have signed the challenge the controller bound it to.
        if !self
            .crypto
            .verify_key_proof(new_public_key, &message, signature_hex)
        {
            return Err(NodeUseCaseError::Unauthorized {
                detail: "the key proof did not verify".to_owned(),
            });
        }

        let mut metadata = AuditMetadata::default();
        metadata
            .insert("event", "node_key_rotated")
            .map_err(|error| NodeUseCaseError::Backend {
                context: "rotate_audit",
                detail: error.to_string(),
            })?;
        let claim = RotateClaim {
            challenge_id: challenge_id.to_owned(),
            credential_id: claims.credential_id.clone(),
            new_public_key: new_public_key.to_owned(),
            credential_ttl_millis: DEFAULT_CREDENTIAL_TTL_MILLIS,
            now: fleet_core::SystemClock::now_unix_millis(),
            audit: AuditIntent {
                actor: format!("node:{}", claims.machine_id),
                action: "node.rotate".to_owned(),
                resource: Some(claims.machine_id.clone()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            },
        };
        let outcome = self
            .port
            .rotate_key(&claim)
            .await
            .map_err(|error| map_port("rotate", error))?;
        let credential_token = self
            .crypto
            .issue_credential_token(&NodeCredentialClaims {
                credential_id: outcome.credential_id.clone(),
                machine_id: outcome.machine_id.clone(),
                node_key_version: outcome.node_key_version,
                expires_at: outcome.credential_expires_at,
            })
            .map_err(|detail| NodeUseCaseError::Backend {
                context: "rotate_codec",
                detail,
            })?;
        Ok(RotateOutcome {
            machine_id: outcome.machine_id,
            credential_token,
            node_key_version: outcome.node_key_version,
            credential_expires_at: outcome.credential_expires_at,
        })
    }

    /// Validates a node session token against durable state. This is the
    /// check the node gateway (FM-205) will make on every connection; the
    /// user API never accepts a node session.
    ///
    /// # Errors
    ///
    /// Fails on a backend failure; an invalid session is a `Valid`/`Invalid`
    /// outcome, not an error.
    pub async fn validate_session(
        &self,
        session_token: &str,
    ) -> Result<SessionValidity, NodeUseCaseError> {
        let claims = self
            .crypto
            .verify_session_token(session_token)
            .map_err(|detail| NodeUseCaseError::Unauthorized {
                detail: format!("the node session is not valid: {detail}"),
            })?;
        self.port
            .validate_session(
                &claims.session_id,
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await
            .map_err(|error| map_port("validate_session", error))
    }

    /// The identity behind a live credential, refusing anything not active
    /// and unexpired. The one shared authentication gate for the node
    /// surface.
    async fn live_identity(
        &self,
        claims: &NodeCredentialClaims,
    ) -> Result<NodeIdentity, NodeUseCaseError> {
        let credential = self
            .port
            .credential(&claims.credential_id)
            .await
            .map_err(|error| map_port("credential", error))?
            .ok_or_else(|| NodeUseCaseError::Unauthorized {
                detail: "the node credential does not exist".to_owned(),
            })?;
        let now = fleet_core::SystemClock::now_unix_millis();
        if credential.status != NodeStatus::Active || credential.expires_at <= now {
            return Err(NodeUseCaseError::Unauthorized {
                detail: "the node credential is revoked or expired".to_owned(),
            });
        }
        if credential.machine_id != claims.machine_id
            || credential.node_key_version != claims.node_key_version
        {
            return Err(NodeUseCaseError::Unauthorized {
                detail: "the node credential does not match its record".to_owned(),
            });
        }
        let identity = self
            .port
            .identity(&claims.machine_id)
            .await
            .map_err(|error| map_port("identity", error))?
            .ok_or_else(|| NodeUseCaseError::Unauthorized {
                detail: "the machine has no node identity".to_owned(),
            })?;
        if identity.status != NodeStatus::Active || identity.key_version != claims.node_key_version
        {
            return Err(NodeUseCaseError::Unauthorized {
                detail: "the node identity is revoked or the key has rotated".to_owned(),
            });
        }
        Ok(identity)
    }

    /// Appends one audit intent for an operator action.
    async fn audit_event(
        &self,
        actor: String,
        action: String,
        machine_id: &str,
        event: &'static str,
    ) -> Result<(), NodeUseCaseError> {
        let mut metadata = AuditMetadata::default();
        metadata
            .insert("event", event)
            .map_err(|error| NodeUseCaseError::Backend {
                context: "audit",
                detail: error.to_string(),
            })?;
        self.audit
            .record_intent(&AuditIntent {
                actor,
                action,
                resource: Some(machine_id.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| NodeUseCaseError::Backend {
                context: "audit",
                detail,
            })
    }
}

/// The outcome of a successful enrollment, as the node receives it.
#[derive(Clone, Debug)]
pub struct EnrollOutcome {
    /// The machine the node now belongs to.
    pub machine_id: String,
    /// The signed node credential token.
    pub credential_token: String,
    /// Credential expiry (epoch milliseconds).
    pub credential_expires_at: i64,
    /// Whether the enrollment replaced a revoked identity.
    pub rebind: bool,
}

/// The outcome of a successful session proof, as the node receives it.
#[derive(Clone, Debug)]
pub struct SessionOutcome {
    /// The machine the session belongs to.
    pub machine_id: String,
    /// The signed session token.
    pub session_token: String,
    /// Session expiry (epoch milliseconds).
    pub session_expires_at: i64,
}

/// The outcome of a successful rotation, as the node receives it.
#[derive(Clone, Debug)]
pub struct RotateOutcome {
    /// The machine whose identity rotated.
    pub machine_id: String,
    /// The new signed credential token, bound to the new key.
    pub credential_token: String,
    /// The new node key version.
    pub node_key_version: i64,
    /// The new credential's expiry (epoch milliseconds).
    pub credential_expires_at: i64,
}
