//! The node enrollment use cases, over an in-memory port and a deterministic
//! fake codec. These tests own the application rules — authorization, token
//! and key validation, live-identity gating, proof ordering, and audit —
//! while the SQLite adapter's atomicity and the real cryptography have their
//! own suites.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use fleet_application::audit::AuditIntent;
use fleet_application::audit::AuditOutcome;
use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, ReasonId};
use fleet_application::node::{
    ChallengePurpose, EnrollClaim, EnrolledNode, EnrollmentTokenCreated, EnrollmentTokenRecord,
    EnrollmentTokenView, GatewayState, NewChallenge, NewEnrollmentToken, NodeChallenge,
    NodeCredential, NodeCredentialClaims, NodeCrypto, NodeIdentity, NodePort, NodePortError,
    NodeSessionClaims, NodeSessionIssued, NodeStatus, NodeUseCaseError, NodeView, Nodes,
    RotateClaim, RotationOutcome, SessionClaim, SessionValidity, TokenFacts, proof_message,
};
use fleet_application::operation::AuditPort;

const PRINCIPAL: &str = "anonymous-lan-admin";
const TEST_MACHINE: &str = "0195f3c8-6a2c-7111-b04a-2f4b1e9d77aa";

/// A public key that passes format validation: 64 lowercase hex characters.
const GOOD_KEY: &str = "aa0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const OTHER_KEY: &str = "bb0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

// ---------------------------------------------------------------------------
// Deterministic fake codec
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct FakeCrypto {
    counter: Mutex<u32>,
}

impl FakeCrypto {
    fn next(&self) -> u32 {
        let mut counter = self.counter.lock().expect("uncontended");
        *counter += 1;
        *counter
    }
}

impl NodeCrypto for FakeCrypto {
    fn generate_token(&self) -> String {
        format!("fmtenr1.test{}", self.next())
    }

    fn hash_token(&self, token: &str) -> String {
        format!("hash({token})")
    }

    fn generate_nonce(&self) -> String {
        format!("nonce{}", self.next())
    }

    fn verify_key_proof(&self, _public_key: &str, message: &[u8], signature_hex: &str) -> bool {
        // The test "signature" is the message text; anything else fails.
        signature_hex == format!("sig:{}", String::from_utf8_lossy(message))
    }

    fn issue_credential_token(&self, claims: &NodeCredentialClaims) -> Result<String, String> {
        serde_json::to_string(claims)
            .map(|json| format!("cred:{json}"))
            .map_err(|error| error.to_string())
    }

    fn verify_credential_token(&self, token: &str) -> Result<NodeCredentialClaims, String> {
        token
            .strip_prefix("cred:")
            .ok_or_else(|| "not a credential token".to_owned())
            .and_then(|json| serde_json::from_str(json).map_err(|error| error.to_string()))
    }

    fn issue_session_token(&self, claims: &NodeSessionClaims) -> Result<String, String> {
        serde_json::to_string(claims)
            .map(|json| format!("session:{json}"))
            .map_err(|error| error.to_string())
    }

    fn verify_session_token(&self, token: &str) -> Result<NodeSessionClaims, String> {
        token
            .strip_prefix("session:")
            .ok_or_else(|| "not a session token".to_owned())
            .and_then(|json| serde_json::from_str(json).map_err(|error| error.to_string()))
    }
}

// ---------------------------------------------------------------------------
// In-memory port, mirroring the port's documented decisions
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct MemoryPort {
    machines: Mutex<HashSet<String>>,
    tokens: Mutex<HashMap<String, TokenRow>>,
    identities: Mutex<HashMap<String, NodeIdentity>>,
    credentials: Mutex<HashMap<String, NodeCredential>>,
    sessions: Mutex<HashMap<String, SessionRow>>,
    challenges: Mutex<HashMap<String, ChallengeRow>>,
    audits: Mutex<Vec<AuditIntent>>,
}

#[derive(Clone, Debug)]
struct TokenRow {
    id: String,
    machine_id: String,
    status: String,
    created_at: i64,
    expires_at: i64,
    consumed_at: Option<i64>,
}

#[derive(Clone, Debug)]
struct ChallengeRow {
    challenge: NodeChallenge,
    consumed: bool,
}

#[derive(Clone, Debug)]
struct SessionRow {
    machine_id: String,
    credential_id: String,
    expires_at: i64,
    status: NodeStatus,
}

fn live_credential(credential: &NodeCredential, now: i64) -> bool {
    credential.status == NodeStatus::Active && credential.expires_at > now
}

fn live_identity_or_reject(
    port: &MemoryPort,
    credential: &NodeCredential,
) -> Result<NodeIdentity, NodePortError> {
    let identities = port.identities.lock().expect("uncontended");
    let identity = identities
        .get(&credential.machine_id)
        .cloned()
        .ok_or_else(|| NodePortError::Rejected {
            detail: "the machine has no node identity".to_owned(),
        })?;
    if identity.status != NodeStatus::Active || identity.key_version != credential.node_key_version
    {
        return Err(NodePortError::Rejected {
            detail: "the node identity is revoked or the key has rotated".to_owned(),
        });
    }
    Ok(identity)
}

#[async_trait]
impl NodePort for MemoryPort {
    async fn create_token(
        &self,
        new: &NewEnrollmentToken,
    ) -> Result<EnrollmentTokenRecord, NodePortError> {
        if !self
            .machines
            .lock()
            .expect("uncontended")
            .contains(&new.machine_id)
        {
            return Err(NodePortError::NotFound {
                what: format!("machine {:?}", new.machine_id),
            });
        }
        let id = format!(
            "token-{}",
            self.tokens.lock().expect("uncontended").len() + 1
        );
        self.machines
            .lock()
            .expect("uncontended")
            .insert(new.machine_id.clone());
        self.tokens.lock().expect("uncontended").insert(
            new.token_hash.clone(),
            TokenRow {
                id: id.clone(),
                machine_id: new.machine_id.clone(),
                status: "pending".to_owned(),
                created_at: new.now,
                expires_at: new.now + new.ttl_millis,
                consumed_at: None,
            },
        );
        Ok(EnrollmentTokenRecord {
            id,
            machine_id: new.machine_id.clone(),
            expires_at: new.now + new.ttl_millis,
        })
    }

    async fn list_tokens(
        &self,
        machine_id: &str,
        now: i64,
    ) -> Result<Vec<EnrollmentTokenView>, NodePortError> {
        let tokens = self.tokens.lock().expect("uncontended");
        let mut views: Vec<EnrollmentTokenView> = tokens
            .values()
            .filter(|row| row.machine_id == machine_id)
            .map(|row| EnrollmentTokenView {
                id: row.id.clone(),
                machine_id: row.machine_id.clone(),
                status: match (row.consumed_at.is_some(), row.expires_at <= now) {
                    (true, _) => "consumed".to_owned(),
                    (false, true) => "expired".to_owned(),
                    (false, false) => row.status.clone(),
                },
                created_at: row.created_at,
                expires_at: row.expires_at,
                consumed_at: row.consumed_at,
            })
            .collect();
        views.reverse();
        Ok(views)
    }

    async fn token_facts(&self, token_hash: &str) -> Result<Option<TokenFacts>, NodePortError> {
        Ok(self
            .tokens
            .lock()
            .expect("uncontended")
            .get(token_hash)
            .map(|row| TokenFacts {
                id: row.id.clone(),
                machine_id: row.machine_id.clone(),
                status: row.status.clone(),
                expires_at: row.expires_at,
            }))
    }

    async fn enroll(&self, claim: &EnrollClaim) -> Result<EnrolledNode, NodePortError> {
        let mut tokens = self.tokens.lock().expect("uncontended");
        let Some(row) = tokens.get(&claim.token_hash).cloned() else {
            return Err(NodePortError::NotFound {
                what: "enrollment token".to_owned(),
            });
        };
        if row.consumed_at.is_some() {
            return Err(NodePortError::AlreadyUsed {
                what: "enrollment token".to_owned(),
            });
        }
        if row.expires_at <= claim.now {
            return Err(NodePortError::Expired {
                what: "enrollment token".to_owned(),
            });
        }
        let mut identities = self.identities.lock().expect("uncontended");
        let (key_version, rebind) = match identities.get(&row.machine_id) {
            Some(identity) if identity.status == NodeStatus::Active => {
                return Err(NodePortError::Conflict {
                    detail: "the machine already has an active node identity".to_owned(),
                });
            }
            Some(identity) => (identity.key_version + 1, true),
            None => (1, false),
        };
        tokens.insert(
            claim.token_hash.clone(),
            TokenRow {
                consumed_at: Some(claim.now),
                ..row.clone()
            },
        );
        identities.insert(
            row.machine_id.clone(),
            NodeIdentity {
                machine_id: row.machine_id.clone(),
                public_key: claim.public_key.clone(),
                key_version,
                status: NodeStatus::Active,
                os: claim.os.clone(),
                arch: claim.arch.clone(),
                node_version: claim.node_version.clone(),
                enrolled_at: claim.now,
                rotated_at: rebind.then_some(claim.now),
                gateway_state: GatewayState::Offline,
                last_seen_at: None,
                boot_session_id: None,
            },
        );
        drop(identities);
        let mut credentials = self.credentials.lock().expect("uncontended");
        let credential_id = format!("cred-{}", credentials.len() + 1);
        credentials.insert(
            credential_id.clone(),
            NodeCredential {
                id: credential_id.clone(),
                machine_id: row.machine_id.clone(),
                node_key_version: key_version,
                issued_at: claim.now,
                expires_at: claim.now + claim.credential_ttl_millis,
                status: NodeStatus::Active,
                last_used_at: None,
            },
        );
        drop(credentials);
        self.audits
            .lock()
            .expect("uncontended")
            .push(claim.audit.clone());
        Ok(EnrolledNode {
            machine_id: row.machine_id,
            credential_id,
            node_key_version: key_version,
            credential_expires_at: claim.now + claim.credential_ttl_millis,
            rebind,
        })
    }

    async fn identity(&self, machine_id: &str) -> Result<Option<NodeIdentity>, NodePortError> {
        Ok(self
            .identities
            .lock()
            .expect("uncontended")
            .get(machine_id)
            .cloned())
    }

    async fn issue_challenge(&self, new: &NewChallenge) -> Result<NodeChallenge, NodePortError> {
        let mut challenges = self.challenges.lock().expect("uncontended");
        let id = format!("challenge-{}", challenges.len() + 1);
        let challenge = NodeChallenge {
            id: id.clone(),
            machine_id: new.machine_id.clone(),
            nonce: new.nonce.clone(),
            purpose: new.purpose,
            new_public_key: new.new_public_key.clone(),
            expires_at: new.expires_at,
        };
        challenges.insert(
            id,
            ChallengeRow {
                challenge: challenge.clone(),
                consumed: false,
            },
        );
        Ok(challenge)
    }

    async fn challenge(&self, challenge_id: &str) -> Result<Option<NodeChallenge>, NodePortError> {
        Ok(self
            .challenges
            .lock()
            .expect("uncontended")
            .get(challenge_id)
            .map(|row| row.challenge.clone()))
    }

    async fn credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<NodeCredential>, NodePortError> {
        Ok(self
            .credentials
            .lock()
            .expect("uncontended")
            .get(credential_id)
            .cloned())
    }

    async fn consume_challenge_and_issue_session(
        &self,
        claim: &SessionClaim,
    ) -> Result<NodeSessionIssued, NodePortError> {
        let mut challenges = self.challenges.lock().expect("uncontended");
        let Some(row) = challenges.get(&claim.challenge_id) else {
            return Err(NodePortError::NotFound {
                what: "challenge".to_owned(),
            });
        };
        if row.consumed {
            return Err(NodePortError::AlreadyUsed {
                what: "challenge".to_owned(),
            });
        }
        if row.challenge.purpose != ChallengePurpose::Session {
            return Err(NodePortError::Rejected {
                detail: "the challenge is not for a session proof".to_owned(),
            });
        }
        let challenge_machine = row.challenge.machine_id.clone();
        let credentials = self.credentials.lock().expect("uncontended");
        let credential =
            credentials
                .get(&claim.credential_id)
                .cloned()
                .ok_or(NodePortError::NotFound {
                    what: "credential".to_owned(),
                })?;
        if !live_credential(&credential, claim.now) {
            return Err(NodePortError::Rejected {
                detail: "the credential is revoked or expired".to_owned(),
            });
        }
        if challenge_machine != credential.machine_id {
            return Err(NodePortError::Rejected {
                detail: "the challenge does not belong to this credential's machine".to_owned(),
            });
        }
        live_identity_or_reject(self, &credential)?;
        drop(credentials);
        challenges
            .get_mut(&claim.challenge_id)
            .expect("checked above")
            .consumed = true;
        let mut sessions = self.sessions.lock().expect("uncontended");
        let session_id = format!("session-{}", sessions.len() + 1);
        let expires_at = claim.now + claim.session_ttl_millis;
        sessions.insert(
            session_id.clone(),
            SessionRow {
                machine_id: credential.machine_id.clone(),
                credential_id: credential.id.clone(),
                expires_at,
                status: NodeStatus::Active,
            },
        );
        drop(sessions);
        self.audits
            .lock()
            .expect("uncontended")
            .push(claim.audit.clone());
        Ok(NodeSessionIssued {
            session_id,
            machine_id: credential.machine_id,
            credential_id: credential.id,
            expires_at,
        })
    }

    async fn rotate_key(&self, claim: &RotateClaim) -> Result<RotationOutcome, NodePortError> {
        let mut challenges = self.challenges.lock().expect("uncontended");
        let Some(row) = challenges.get(&claim.challenge_id) else {
            return Err(NodePortError::NotFound {
                what: "challenge".to_owned(),
            });
        };
        if row.consumed {
            return Err(NodePortError::AlreadyUsed {
                what: "challenge".to_owned(),
            });
        }
        if row.challenge.purpose != ChallengePurpose::Rotate
            || row.challenge.new_public_key.as_deref() != Some(claim.new_public_key.as_str())
        {
            return Err(NodePortError::Rejected {
                detail: "the challenge does not match this rotation".to_owned(),
            });
        }
        let mut credentials = self.credentials.lock().expect("uncontended");
        let credential =
            credentials
                .get(&claim.credential_id)
                .cloned()
                .ok_or(NodePortError::NotFound {
                    what: "credential".to_owned(),
                })?;
        if !live_credential(&credential, claim.now) {
            return Err(NodePortError::Rejected {
                detail: "the credential is revoked or expired".to_owned(),
            });
        }
        let machine_id = credential.machine_id.clone();
        {
            let mut identities = self.identities.lock().expect("uncontended");
            let identity = identities
                .get_mut(&machine_id)
                .ok_or(NodePortError::Rejected {
                    detail: "the machine has no node identity".to_owned(),
                })?;
            if identity.status != NodeStatus::Active
                || identity.key_version != credential.node_key_version
            {
                return Err(NodePortError::Rejected {
                    detail: "the node identity is revoked or the key has rotated".to_owned(),
                });
            }
            identity.public_key.clone_from(&claim.new_public_key);
            identity.key_version += 1;
            identity.rotated_at = Some(claim.now);
            let new_key_version = identity.key_version;
            drop(identities);
            for stored in credentials.values_mut() {
                if stored.machine_id == machine_id {
                    stored.status = NodeStatus::Revoked;
                }
            }
            for session in self.sessions.lock().expect("uncontended").values_mut() {
                if session.machine_id == machine_id {
                    session.status = NodeStatus::Revoked;
                }
            }
            let new_credential_id = format!("cred-{}", credentials.len() + 1);
            let expires_at = claim.now + claim.credential_ttl_millis;
            credentials.insert(
                new_credential_id.clone(),
                NodeCredential {
                    id: new_credential_id.clone(),
                    machine_id: machine_id.clone(),
                    node_key_version: new_key_version,
                    issued_at: claim.now,
                    expires_at,
                    status: NodeStatus::Active,
                    last_used_at: None,
                },
            );
            challenges
                .get_mut(&claim.challenge_id)
                .expect("checked above")
                .consumed = true;
            self.audits
                .lock()
                .expect("uncontended")
                .push(claim.audit.clone());
            return Ok(RotationOutcome {
                machine_id,
                credential_id: new_credential_id,
                node_key_version: new_key_version,
                credential_expires_at: expires_at,
            });
        }
    }

    async fn revoke_identity(&self, machine_id: &str) -> Result<(), NodePortError> {
        let mut identities = self.identities.lock().expect("uncontended");
        let identity = identities
            .get_mut(machine_id)
            .ok_or(NodePortError::NotFound {
                what: "node identity".to_owned(),
            })?;
        if identity.status != NodeStatus::Active {
            return Err(NodePortError::NotFound {
                what: "active node identity".to_owned(),
            });
        }
        identity.status = NodeStatus::Revoked;
        drop(identities);
        for credential in self.credentials.lock().expect("uncontended").values_mut() {
            if credential.machine_id == machine_id {
                credential.status = NodeStatus::Revoked;
            }
        }
        for session in self.sessions.lock().expect("uncontended").values_mut() {
            if session.machine_id == machine_id {
                session.status = NodeStatus::Revoked;
            }
        }
        Ok(())
    }

    async fn node_view(
        &self,
        machine_id: &str,
        now: i64,
    ) -> Result<Option<NodeView>, NodePortError> {
        if !self
            .machines
            .lock()
            .expect("uncontended")
            .contains(machine_id)
        {
            return Ok(None);
        }
        let identity = self.identity(machine_id).await?;
        let credentials = self.credentials.lock().expect("uncontended");
        let active_credentials: Vec<NodeCredential> = credentials
            .values()
            .filter(|credential| {
                credential.machine_id == machine_id && live_credential(credential, now)
            })
            .cloned()
            .collect();
        let active_sessions = self
            .sessions
            .lock()
            .expect("uncontended")
            .values()
            .filter(|session| {
                session.machine_id == machine_id
                    && session.status == NodeStatus::Active
                    && session.expires_at > now
            })
            .count();
        Ok(Some(NodeView {
            machine_id: machine_id.to_owned(),
            identity,
            pending_tokens: Vec::new(),
            active_credentials,
            active_sessions: i64::try_from(active_sessions).unwrap_or(i64::MAX),
        }))
    }

    async fn validate_session(
        &self,
        session_id: &str,
        now: i64,
    ) -> Result<SessionValidity, NodePortError> {
        let session = {
            let sessions = self.sessions.lock().expect("uncontended");
            sessions.get(session_id).cloned()
        };
        let Some(session) = session else {
            return Ok(SessionValidity::Invalid {
                detail: "the session does not exist".to_owned(),
            });
        };
        if session.status != NodeStatus::Active || session.expires_at <= now {
            return Ok(SessionValidity::Invalid {
                detail: "the session is revoked or expired".to_owned(),
            });
        }
        let credential =
            self.credential(&session.credential_id)
                .await?
                .ok_or(NodePortError::Backend {
                    detail: "dangling session credential".to_owned(),
                })?;
        if !live_credential(&credential, now) {
            return Ok(SessionValidity::Invalid {
                detail: "the session's credential is revoked or expired".to_owned(),
            });
        }
        let identity = self
            .identity(&session.machine_id)
            .await?
            .ok_or(NodePortError::Backend {
                detail: "dangling identity".to_owned(),
            })?;
        if identity.status != NodeStatus::Active
            || identity.key_version != credential.node_key_version
        {
            return Ok(SessionValidity::Invalid {
                detail: "the node identity is revoked or the key has rotated".to_owned(),
            });
        }
        Ok(SessionValidity::Valid {
            machine_id: session.machine_id.clone(),
            credential_id: session.credential_id.clone(),
        })
    }

    async fn touch_credential(
        &self,
        credential_id: &str,
        used_at: i64,
    ) -> Result<(), NodePortError> {
        if let Some(credential) = self
            .credentials
            .lock()
            .expect("uncontended")
            .get_mut(credential_id)
        {
            credential.last_used_at = Some(used_at);
        }
        Ok(())
    }

    async fn record_gateway_state(
        &self,
        machine_id: &str,
        state: GatewayState,
        boot_session: Option<&str>,
        last_seen: i64,
    ) -> Result<(), NodePortError> {
        let mut identities = self.identities.lock().expect("uncontended");
        let identity = identities
            .get_mut(machine_id)
            .ok_or(NodePortError::NotFound {
                what: "node identity".to_owned(),
            })?;
        identity.gateway_state = state;
        identity.last_seen_at = Some(last_seen);
        identity.boot_session_id = boot_session.map(str::to_owned);
        Ok(())
    }
}

#[async_trait]
impl AuditPort for MemoryPort {
    async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
        self.audits
            .lock()
            .expect("uncontended")
            .push(intent.clone());
        Ok(())
    }

    async fn record_outcome(
        &self,
        _operation_id: &str,
        _outcome: AuditOutcome,
    ) -> Result<(), String> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Authorizers and helpers
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PermitAll;

impl Authorizer for PermitAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

#[derive(Debug)]
struct DenyAll;

impl Authorizer for DenyAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::deny(ReasonId::UnknownPrincipal)
    }
}

fn principal() -> ActingPrincipal {
    ActingPrincipal {
        id: PRINCIPAL.to_owned(),
    }
}

impl MemoryPort {
    /// Registers a machine with the fake, so token creation can fail for
    /// unknown machines the way the real port does.
    fn add_machine(&self, machine_id: &str) {
        self.machines
            .lock()
            .expect("uncontended")
            .insert(machine_id.to_owned());
    }
}

#[derive(Clone)]
struct TestService {
    nodes: Arc<Nodes>,
    port: Arc<MemoryPort>,
    crypto: Arc<FakeCrypto>,
}

fn service() -> TestService {
    let port = Arc::new(MemoryPort::default());
    let crypto = Arc::new(FakeCrypto::default());
    TestService {
        nodes: Arc::new(Nodes::new(port.clone(), crypto.clone(), port.clone())),
        port,
        crypto,
    }
}

async fn create_token(service: &TestService, machine_id: &str) -> EnrollmentTokenCreated {
    service.port.add_machine(machine_id);
    service
        .nodes
        .create_token(&PermitAll, &principal(), machine_id, None)
        .await
        .expect("the token must be creatable")
}

async fn enroll(
    service: &TestService,
    token: &EnrollmentTokenCreated,
    public_key: &str,
) -> fleet_application::node::EnrollOutcome {
    service
        .nodes
        .enroll(&token.token, public_key, "linux", "x86_64", "0.1.0")
        .await
        .expect("the enrollment must succeed")
}

/// Proves a session for a machine's credential and returns its outcome.
async fn prove_session(
    service: &TestService,
    credential_token: &str,
    machine_id: &str,
) -> fleet_application::node::SessionOutcome {
    let challenge = service
        .nodes
        .challenge(credential_token, ChallengePurpose::Session, None)
        .await
        .expect("the challenge must issue");
    let message = proof_message(&challenge.id, machine_id, ChallengePurpose::Session, None);
    service
        .nodes
        .prove_session(
            credential_token,
            &challenge.id,
            &format!("sig:{}", String::from_utf8_lossy(&message)),
        )
        .await
        .expect("the proof must verify")
}

fn audit_events(service: &TestService) -> Vec<String> {
    service
        .port
        .audits
        .lock()
        .expect("uncontended")
        .iter()
        .filter_map(|intent| {
            intent
                .metadata
                .entries()
                .find(|(key, _)| *key == "event")
                .map(|(_, value)| value.to_owned())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn denied_principals_cannot_create_tokens_read_state_or_revoke() {
    let service = service();
    for outcome in [
        service
            .nodes
            .create_token(&DenyAll, &principal(), TEST_MACHINE, None)
            .await
            .err(),
        service
            .nodes
            .node_view(&DenyAll, &principal(), TEST_MACHINE)
            .await
            .err(),
        service
            .nodes
            .revoke(&DenyAll, &principal(), TEST_MACHINE)
            .await
            .err(),
    ] {
        let outcome = outcome.expect("each call must fail");
        assert!(
            matches!(outcome, NodeUseCaseError::Denied(_)),
            "{outcome:?}"
        );
    }
    assert!(
        service.port.audits.lock().expect("uncontended").is_empty(),
        "denied actions must not be audited as allowed intents"
    );
}

#[tokio::test]
async fn token_creation_validates_the_ttl_and_the_machine() {
    let service = service();
    service.port.add_machine(TEST_MACHINE);
    for ttl in [Some(1), Some(86_400_001)] {
        let error = service
            .nodes
            .create_token(&PermitAll, &principal(), TEST_MACHINE, ttl)
            .await
            .unwrap_err();
        assert!(
            matches!(error, NodeUseCaseError::Invalid { .. }),
            "{error:?}"
        );
    }
    let error = service
        .nodes
        .create_token(
            &PermitAll,
            &principal(),
            "01990000-0000-7000-8000-000000000000",
            None,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, NodeUseCaseError::NotFound { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn enrollment_replays_fail_and_a_second_token_cannot_override_an_active_identity() {
    let service = service();
    let token = create_token(&service, TEST_MACHINE).await;
    let first = enroll(&service, &token, GOOD_KEY).await;
    assert_eq!(first.machine_id, TEST_MACHINE);
    assert!(!first.rebind);

    let replay = service
        .nodes
        .enroll(&token.token, GOOD_KEY, "linux", "x86_64", "0.1.0")
        .await
        .unwrap_err();
    assert!(
        replay.to_string().contains("already used"),
        "replay must fail as used: {replay}"
    );

    let second = create_token(&service, TEST_MACHINE).await;
    let conflict = service
        .nodes
        .enroll(&second.token, GOOD_KEY, "linux", "x86_64", "0.1.0")
        .await
        .unwrap_err();
    assert!(
        matches!(conflict, NodeUseCaseError::Conflict { .. }),
        "{conflict:?}"
    );
    let conflict_again = service
        .nodes
        .enroll(&second.token, GOOD_KEY, "linux", "x86_64", "0.1.0")
        .await
        .unwrap_err();
    assert!(
        matches!(conflict_again, NodeUseCaseError::Conflict { .. }),
        "a conflicting attempt leaves the token usable: {conflict_again:?}"
    );

    let events = audit_events(&service);
    assert!(events.contains(&"node_enrolled".to_owned()), "{events:?}");
    assert!(
        events.contains(&"enrollment_token_created".to_owned()),
        "{events:?}"
    );
}

#[tokio::test]
async fn enrollment_rejects_malformed_keys_and_facts_without_consuming_the_token() {
    let service = service();
    let token = create_token(&service, TEST_MACHINE).await;
    for bad_key in ["", "zz01", "aa01"] {
        let error = service
            .nodes
            .enroll(&token.token, bad_key, "linux", "x86_64", "0.1.0")
            .await
            .unwrap_err();
        assert!(
            matches!(error, NodeUseCaseError::Invalid { .. }),
            "{bad_key}: {error:?}"
        );
    }
    for bad_key in ["a".repeat(63), "a".repeat(65), "A".repeat(64)] {
        let error = service
            .nodes
            .enroll(&token.token, &bad_key, "linux", "x86_64", "0.1.0")
            .await
            .unwrap_err();
        assert!(
            matches!(error, NodeUseCaseError::Invalid { .. }),
            "{bad_key}: {error:?}"
        );
    }
    let long = "x".repeat(65);
    for (field, os, arch, version) in [
        ("os", long.as_str(), "x86_64", "0.1.0"),
        ("arch", "linux", long.as_str(), "0.1.0"),
        ("node version", "linux", "x86_64", long.as_str()),
    ] {
        let error = service
            .nodes
            .enroll(&token.token, GOOD_KEY, os, arch, version)
            .await
            .unwrap_err();
        assert!(
            matches!(error, NodeUseCaseError::Invalid { .. }),
            "{field}: {error:?}"
        );
    }

    // A rejected enrollment never consumed the token.
    enroll(&service, &token, GOOD_KEY).await;
}

#[tokio::test]
async fn a_session_requires_a_valid_credential_challenge_and_proof() {
    let service = service();
    let token = create_token(&service, TEST_MACHINE).await;
    let enrolled = enroll(&service, &token, GOOD_KEY).await;

    let bad_proof = {
        let challenge = service
            .nodes
            .challenge(&enrolled.credential_token, ChallengePurpose::Session, None)
            .await
            .expect("the challenge must issue");
        service
            .nodes
            .prove_session(&enrolled.credential_token, &challenge.id, "sig:wrong")
            .await
            .unwrap_err()
    };
    assert!(
        matches!(bad_proof, NodeUseCaseError::Unauthorized { .. }),
        "{bad_proof:?}"
    );

    let unknown_challenge = service
        .nodes
        .prove_session(&enrolled.credential_token, "challenge-nope", "sig:anything")
        .await
        .unwrap_err();
    assert!(matches!(
        unknown_challenge,
        NodeUseCaseError::NotFound { .. }
    ));

    let session = prove_session(&service, &enrolled.credential_token, TEST_MACHINE).await;
    assert_eq!(session.machine_id, TEST_MACHINE);

    let challenge = service
        .nodes
        .challenge(&enrolled.credential_token, ChallengePurpose::Session, None)
        .await
        .expect("the second challenge must issue");
    let message = proof_message(&challenge.id, TEST_MACHINE, ChallengePurpose::Session, None);
    service
        .nodes
        .prove_session(
            &enrolled.credential_token,
            &challenge.id,
            &format!("sig:{}", String::from_utf8_lossy(&message)),
        )
        .await
        .expect("the second proof succeeds");
    let replay_again = service
        .nodes
        .prove_session(
            &enrolled.credential_token,
            &challenge.id,
            &format!("sig:{}", String::from_utf8_lossy(&message)),
        )
        .await
        .unwrap_err();
    assert!(
        replay_again.to_string().contains("already used"),
        "a challenge is single use: {replay_again:?}"
    );

    let validity = service
        .nodes
        .validate_session(&session.session_token)
        .await
        .expect("the validity check must run");
    assert!(
        matches!(validity, SessionValidity::Valid { .. }),
        "{validity:?}"
    );

    let garbage_credential = service
        .nodes
        .challenge("cred:not-a-token", ChallengePurpose::Session, None)
        .await
        .unwrap_err();
    assert!(matches!(
        garbage_credential,
        NodeUseCaseError::Unauthorized { .. }
    ));

    let unknown_credential_id = {
        let claims = NodeCredentialClaims {
            credential_id: "cred-unknown".to_owned(),
            machine_id: TEST_MACHINE.to_owned(),
            node_key_version: 1,
            expires_at: i64::MAX,
        };
        service
            .nodes
            .challenge(
                &service
                    .crypto
                    .issue_credential_token(&claims)
                    .expect("the fake signs"),
                ChallengePurpose::Session,
                None,
            )
            .await
            .unwrap_err()
    };
    assert!(matches!(
        unknown_credential_id,
        NodeUseCaseError::Unauthorized { .. }
    ));
}

#[tokio::test]
async fn rotate_replaces_the_key_and_invalidates_old_sessions() {
    let service = service();
    let token = create_token(&service, TEST_MACHINE).await;
    let enrolled = enroll(&service, &token, GOOD_KEY).await;
    let old_session = prove_session(&service, &enrolled.credential_token, TEST_MACHINE).await;

    let rotate_challenge = service
        .nodes
        .challenge(
            &enrolled.credential_token,
            ChallengePurpose::Rotate,
            Some(OTHER_KEY),
        )
        .await
        .expect("the rotate challenge must issue");
    let message = proof_message(
        &rotate_challenge.id,
        TEST_MACHINE,
        ChallengePurpose::Rotate,
        Some(OTHER_KEY),
    );
    let rotated = service
        .nodes
        .rotate(
            &enrolled.credential_token,
            OTHER_KEY,
            &rotate_challenge.id,
            &format!("sig:{}", String::from_utf8_lossy(&message)),
        )
        .await
        .expect("the rotation must succeed");
    assert_eq!(rotated.node_key_version, 2);

    // The old session and the old credential are dead.
    let old_validity = service
        .nodes
        .validate_session(&old_session.session_token)
        .await
        .expect("the validity check must run");
    assert!(
        matches!(old_validity, SessionValidity::Invalid { .. }),
        "{old_validity:?}"
    );
    let old_credential = service
        .nodes
        .challenge(&enrolled.credential_token, ChallengePurpose::Session, None)
        .await
        .unwrap_err();
    assert!(matches!(
        old_credential,
        NodeUseCaseError::Unauthorized { .. }
    ));

    // A session from the new credential works.
    let new_session = prove_session(&service, &rotated.credential_token, TEST_MACHINE).await;
    let validity = service
        .nodes
        .validate_session(&new_session.session_token)
        .await
        .expect("the validity check must run");
    assert!(
        matches!(validity, SessionValidity::Valid { .. }),
        "{validity:?}"
    );

    // The rotation consumed its challenge; a well-signed replay still fails.
    let replay = {
        let message = proof_message(
            &rotate_challenge.id,
            TEST_MACHINE,
            ChallengePurpose::Rotate,
            Some(OTHER_KEY),
        );
        service
            .nodes
            .rotate(
                &rotated.credential_token,
                OTHER_KEY,
                &rotate_challenge.id,
                &format!("sig:{}", String::from_utf8_lossy(&message)),
            )
            .await
            .unwrap_err()
    };
    assert!(replay.to_string().contains("already used"), "{replay:?}");

    let events = audit_events(&service);
    assert!(
        events.contains(&"node_key_rotated".to_owned()),
        "{events:?}"
    );
}

#[tokio::test]
async fn revocation_prevents_renewal_and_re_enrollment_is_explicit() {
    let service = service();
    let token = create_token(&service, TEST_MACHINE).await;
    let enrolled = enroll(&service, &token, GOOD_KEY).await;
    let session = prove_session(&service, &enrolled.credential_token, TEST_MACHINE).await;

    service
        .nodes
        .revoke(&PermitAll, &principal(), TEST_MACHINE)
        .await
        .expect("the revocation must succeed");

    let renewal = service
        .nodes
        .challenge(&enrolled.credential_token, ChallengePurpose::Session, None)
        .await
        .unwrap_err();
    assert!(
        matches!(renewal, NodeUseCaseError::Unauthorized { .. }),
        "{renewal:?}"
    );
    let validity = service
        .nodes
        .validate_session(&session.session_token)
        .await
        .expect("the validity check must run");
    assert!(
        matches!(validity, SessionValidity::Invalid { .. }),
        "{validity:?}"
    );
    let second_revoke = service
        .nodes
        .revoke(&PermitAll, &principal(), TEST_MACHINE)
        .await
        .unwrap_err();
    assert!(matches!(second_revoke, NodeUseCaseError::NotFound { .. }));

    // Re-enrollment over the revoked identity needs a fresh token, and the
    // result records that it replaced a revoked identity.
    let new_token = create_token(&service, TEST_MACHINE).await;
    let rebind = enroll(&service, &new_token, OTHER_KEY).await;
    assert!(rebind.rebind, "re-enrollment must record the replacement");
    assert!(matches!(
        prove_session(&service, &rebind.credential_token, TEST_MACHINE).await,
        fleet_application::node::SessionOutcome { .. }
    ));

    let events = audit_events(&service);
    assert!(
        events.contains(&"node_identity_revoked".to_owned()),
        "{events:?}"
    );
    assert!(events.contains(&"node_enrolled".to_owned()), "{events:?}");
}

#[tokio::test]
async fn the_node_view_reports_state_without_secrets() {
    let service = service();
    let token = create_token(&service, TEST_MACHINE).await;
    enroll(&service, &token, GOOD_KEY).await;
    let view = service
        .nodes
        .node_view(&PermitAll, &principal(), TEST_MACHINE)
        .await
        .expect("the view must read");
    assert!(view.identity.is_some());
    assert_eq!(view.active_credentials.len(), 1);
    assert_eq!(view.active_sessions, 0);
    let json = serde_json::to_string(&view).expect("the view must serialize");
    assert!(
        !json.contains(&token.token),
        "a token value must never appear in a view"
    );
}

#[tokio::test]
async fn an_unknown_machine_view_is_not_found() {
    let service = service();
    let error = service
        .nodes
        .node_view(
            &PermitAll,
            &principal(),
            "01990000-0000-7000-8000-000000000000",
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, NodeUseCaseError::NotFound { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn challenges_tie_the_purpose_and_new_key_together() {
    let service = service();
    let token = create_token(&service, TEST_MACHINE).await;
    let enrolled = enroll(&service, &token, GOOD_KEY).await;

    let key_on_session = service
        .nodes
        .challenge(
            &enrolled.credential_token,
            ChallengePurpose::Session,
            Some(GOOD_KEY),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(key_on_session, NodeUseCaseError::Invalid { .. }),
        "{key_on_session:?}"
    );

    let no_key_on_rotate = service
        .nodes
        .challenge(&enrolled.credential_token, ChallengePurpose::Rotate, None)
        .await
        .unwrap_err();
    assert!(matches!(no_key_on_rotate, NodeUseCaseError::Invalid { .. }));

    let same_key_on_rotate = service
        .nodes
        .challenge(
            &enrolled.credential_token,
            ChallengePurpose::Rotate,
            Some(GOOD_KEY),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        same_key_on_rotate,
        NodeUseCaseError::Invalid { .. }
    ));
}
