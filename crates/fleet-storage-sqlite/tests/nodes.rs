//! The node enrollment repository against real SQLite: token single-use
//! (including a concurrent-claim race), enrollment, rotation, revocation,
//! session validation, and the node view. Every test uses its own temporary
//! directory.

use std::sync::Arc;

use fleet_application::audit::{AuditIntent, AuditMetadata};
use fleet_application::authz::Decision;
use fleet_application::machine::{MachinePort, NewEndpoint, RegisterMachine};
use fleet_application::node::{
    ChallengePurpose, EnrollClaim, NewChallenge, NewEnrollmentToken, NodePort, NodePortError,
    NodeStatus, RevokeClaim, RotateClaim, SessionClaim,
};
use fleet_core::EndpointKind;
use fleet_storage_sqlite::{MachineRepository, NodeRepository, Store};

/// A public key that passes format checks: 64 lowercase hex characters.
const KEY_A: &str = "aa0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const KEY_B: &str = "bb0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn audit_event(event: &str) -> AuditIntent {
    let mut metadata = AuditMetadata::default();
    metadata.insert("event", event).expect("the key is clean");
    AuditIntent {
        actor: "node:test-machine".to_owned(),
        action: "node.enroll".to_owned(),
        resource: None,
        decision: Decision::allow(),
        correlation_id: None,
        operation_id: None,
        metadata,
    }
}

fn revoke_claim(machine_id: &str, now: i64) -> RevokeClaim {
    let mut audit = audit_event("node_identity_revoked");
    "node.revoke".clone_into(&mut audit.action);
    audit.resource = Some(machine_id.to_owned());
    RevokeClaim {
        machine_id: machine_id.to_owned(),
        now,
        audit,
    }
}

struct Setup {
    _dir: tempfile::TempDir,
    store: Store,
    nodes: NodeRepository,
    machines: MachineRepository,
}

async fn setup() -> Setup {
    let dir = tempfile::tempdir().expect("a temp directory");
    let store = Store::open(&dir.path().join("fleet.db"))
        .await
        .expect("the store must open");
    Setup {
        _dir: dir,
        nodes: NodeRepository::new(store.pool().clone()),
        machines: MachineRepository::new(store.pool().clone()),
        store,
    }
}

async fn register_machine(machines: &MachineRepository, name: &str) -> String {
    let machine = machines
        .register(&RegisterMachine {
            name: name.to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: "ops@host:22".to_owned(),
            }],
            tags: Vec::new(),
            groups: Vec::new(),
        })
        .await
        .expect("the machine must register");
    machine.id
}

async fn new_token(setup: &Setup, machine_id: &str, hash: &str, ttl: i64, now: i64) {
    setup
        .nodes
        .create_token(&NewEnrollmentToken {
            machine_id: machine_id.to_owned(),
            token_hash: hash.to_owned(),
            ttl_millis: ttl,
            created_by: "operator".to_owned(),
            now,
        })
        .await
        .expect("the token must be created");
}

fn enroll_claim(token_hash: &str, public_key: &str, now: i64) -> EnrollClaim {
    EnrollClaim {
        token_hash: token_hash.to_owned(),
        public_key: public_key.to_owned(),
        os: "linux".to_owned(),
        arch: "x86_64".to_owned(),
        node_version: "0.1.0".to_owned(),
        now,
        credential_ttl_millis: 3_600_000,
        audit: audit_event("node_enrolled"),
    }
}

async fn enrolled_machine(setup: &Setup, machine_name: &str, key: &str) -> (String, String) {
    let machine_id = register_machine(&setup.machines, machine_name).await;
    let now = fleet_core::SystemClock::now_unix_millis();
    new_token(setup, &machine_id, "hash-enroll", 60_000, now).await;
    let enrolled = setup
        .nodes
        .enroll(&enroll_claim("hash-enroll", key, now + 1))
        .await
        .expect("the enrollment must succeed");
    (machine_id, enrolled.credential_id)
}

#[tokio::test]
async fn a_token_claims_once_and_replays_are_classified() {
    let setup = setup().await;
    let machine_id = register_machine(&setup.machines, "alpha").await;
    let now = fleet_core::SystemClock::now_unix_millis();
    new_token(&setup, &machine_id, "hash-1", 60_000, now).await;

    let enrolled = setup
        .nodes
        .enroll(&enroll_claim("hash-1", KEY_A, now + 1))
        .await
        .expect("the first claim must win");
    assert_eq!(enrolled.machine_id, machine_id);
    assert_eq!(enrolled.node_key_version, 1);
    assert!(!enrolled.rebind);
    assert_eq!(enrolled.credential_expires_at, now + 1 + 3_600_000);

    let replay = setup
        .nodes
        .enroll(&enroll_claim("hash-1", KEY_B, now + 2))
        .await
        .unwrap_err();
    assert!(
        matches!(replay, NodePortError::AlreadyUsed { .. }),
        "{replay:?}"
    );

    let facts = setup
        .nodes
        .token_facts("hash-1")
        .await
        .expect("the facts must read")
        .expect("the token exists");
    assert_eq!(facts.status, "consumed");
    assert_eq!(facts.machine_id, machine_id);

    // An expired token refuses with the honest classification.
    new_token(&setup, &machine_id, "hash-2", 1_000, now).await;
    let expired = setup
        .nodes
        .enroll(&enroll_claim("hash-2", KEY_A, now + 5_000))
        .await
        .unwrap_err();
    assert!(
        matches!(expired, NodePortError::Expired { .. }),
        "{expired:?}"
    );

    // An unknown hash refuses as not found.
    let unknown = setup
        .nodes
        .enroll(&enroll_claim("hash-nope", KEY_A, now))
        .await
        .unwrap_err();
    assert!(
        matches!(unknown, NodePortError::NotFound { .. }),
        "{unknown:?}"
    );
}

#[tokio::test]
async fn concurrent_claims_of_one_token_produce_exactly_one_enrollment() {
    let setup = setup().await;
    let machine_id = Arc::new(register_machine(&setup.machines, "racy").await);
    let now = fleet_core::SystemClock::now_unix_millis();
    new_token(&setup, &machine_id, "hash-race", 60_000, now).await;

    let nodes = Arc::new(NodeRepository::new(setup.store.pool().clone()));
    let mut tasks = tokio::task::JoinSet::new();
    for task_index in 0..8 {
        let nodes = nodes.clone();
        tasks.spawn(async move {
            let mut claim = enroll_claim(
                "hash-race",
                if task_index % 2 == 0 { KEY_A } else { KEY_B },
                now + 1,
            );
            claim.audit = audit_event("node_enrolled");
            (task_index, nodes.enroll(&claim).await)
        });
    }
    let mut winners = 0;
    let mut losers = 0;
    while let Some(result) = tasks.join_next().await {
        let (_, outcome) = result.expect("a claim task must not panic");
        match outcome {
            Ok(_) => winners += 1,
            Err(NodePortError::AlreadyUsed { .. }) => losers += 1,
            Err(error) => panic!("a loser must be classified as used, not {error:?}"),
        }
    }
    assert_eq!(winners, 1, "exactly one enrollment wins the race");
    assert_eq!(losers, 7, "every other claim loses");
}

#[tokio::test]
async fn a_second_token_cannot_override_an_active_identity() {
    let setup = setup().await;
    let machine_id = register_machine(&setup.machines, "double").await;
    let now = fleet_core::SystemClock::now_unix_millis();
    new_token(&setup, &machine_id, "hash-first", 60_000, now).await;
    new_token(&setup, &machine_id, "hash-second", 60_000, now).await;

    setup
        .nodes
        .enroll(&enroll_claim("hash-first", KEY_A, now + 1))
        .await
        .expect("the first enrollment must succeed");

    let conflict = setup
        .nodes
        .enroll(&enroll_claim("hash-second", KEY_B, now + 2))
        .await
        .unwrap_err();
    assert!(
        matches!(conflict, NodePortError::Conflict { .. }),
        "{conflict:?}"
    );

    // The conflicting attempt left its token pending: the transaction
    // rolled back, so the operator can still hand it to a node.
    let facts = setup
        .nodes
        .token_facts("hash-second")
        .await
        .expect("the facts must read")
        .expect("the token exists");
    assert_eq!(facts.status, "pending");
}

#[tokio::test]
async fn rotation_bumps_the_key_and_revokes_old_credentials_and_sessions() {
    let setup = setup().await;
    let (machine_id, credential_id) = enrolled_machine(&setup, "rotating", KEY_A).await;
    let now = fleet_core::SystemClock::now_unix_millis();

    // A live session from the original credential.
    setup
        .nodes
        .issue_challenge(&NewChallenge {
            machine_id: machine_id.clone(),
            nonce: "nonce-1".to_owned(),
            purpose: ChallengePurpose::Session,
            new_public_key: None,
            now,
            expires_at: now + 60_000,
        })
        .await
        .expect("the challenge must issue");
    setup
        .nodes
        .consume_challenge_and_issue_session(&SessionClaim {
            challenge_id: setup.challenge_id_of("nonce-1").await,
            credential_id: credential_id.clone(),
            session_ttl_millis: 600_000,
            now,
            audit: audit_event("node_session_issued"),
        })
        .await
        .expect("the session must issue");

    // The rotate challenge binds the new key.
    let challenge = setup
        .nodes
        .issue_challenge(&NewChallenge {
            machine_id: machine_id.clone(),
            nonce: "nonce-2".to_owned(),
            purpose: ChallengePurpose::Rotate,
            new_public_key: Some(KEY_B.to_owned()),
            now,
            expires_at: now + 60_000,
        })
        .await
        .expect("the rotate challenge must issue");

    let rotated = setup
        .nodes
        .rotate_key(&RotateClaim {
            challenge_id: challenge.id,
            credential_id: credential_id.clone(),
            new_public_key: KEY_B.to_owned(),
            credential_ttl_millis: 3_600_000,
            now: now + 1,
            audit: audit_event("node_key_rotated"),
        })
        .await
        .expect("the rotation must succeed");
    assert_eq!(rotated.node_key_version, 2);
    assert_ne!(rotated.credential_id, credential_id);

    let identity = setup
        .nodes
        .identity(&machine_id)
        .await
        .expect("the identity must read")
        .expect("the identity exists");
    assert_eq!(identity.public_key, KEY_B);
    assert_eq!(identity.key_version, 2);
    assert_eq!(identity.status, NodeStatus::Active);

    // The old credential is revoked; the new one is live and bound to v2.
    let old = setup
        .nodes
        .credential(&credential_id)
        .await
        .expect("the credential must read")
        .expect("the credential exists");
    assert_eq!(old.status, NodeStatus::Revoked);
    let new = setup
        .nodes
        .credential(&rotated.credential_id)
        .await
        .expect("the credential must read")
        .expect("the credential exists");
    assert_eq!(new.status, NodeStatus::Active);
    assert_eq!(new.node_key_version, 2);

    let view = setup
        .nodes
        .node_view(&machine_id, now + 2)
        .await
        .expect("the view must read")
        .expect("the machine exists");
    assert_eq!(view.active_credentials.len(), 1);
    assert_eq!(view.active_sessions, 0, "rotation revokes sessions");
}

#[tokio::test]
async fn a_rotate_challenge_for_another_key_is_rejected() {
    let setup = setup().await;
    let (machine_id, credential_id) = enrolled_machine(&setup, "mismatched", KEY_A).await;
    let now = fleet_core::SystemClock::now_unix_millis();
    let challenge = setup
        .nodes
        .issue_challenge(&NewChallenge {
            machine_id: machine_id.clone(),
            nonce: "nonce-3".to_owned(),
            purpose: ChallengePurpose::Rotate,
            new_public_key: Some(KEY_B.to_owned()),
            now,
            expires_at: now + 60_000,
        })
        .await
        .expect("the challenge must issue");

    let mismatch = setup
        .nodes
        .rotate_key(&RotateClaim {
            challenge_id: challenge.id,
            credential_id,
            new_public_key: "cc0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                .to_owned(),
            credential_ttl_millis: 3_600_000,
            now,
            audit: audit_event("node_key_rotated"),
        })
        .await
        .unwrap_err();
    assert!(
        matches!(mismatch, NodePortError::Rejected { .. }),
        "{mismatch:?}"
    );
}

#[tokio::test]
async fn challenges_are_single_use_and_expiry_is_visible() {
    let setup = setup().await;
    let (machine_id, credential_id) = enrolled_machine(&setup, "challenged", KEY_A).await;
    let now = fleet_core::SystemClock::now_unix_millis();

    let challenge = setup
        .nodes
        .issue_challenge(&NewChallenge {
            machine_id,
            nonce: "nonce-4".to_owned(),
            purpose: ChallengePurpose::Session,
            new_public_key: None,
            now,
            expires_at: now + 60_000,
        })
        .await
        .expect("the challenge must issue");

    let claim = SessionClaim {
        challenge_id: challenge.id.clone(),
        credential_id: credential_id.clone(),
        session_ttl_millis: 600_000,
        now,
        audit: audit_event("node_session_issued"),
    };
    setup
        .nodes
        .consume_challenge_and_issue_session(&claim)
        .await
        .expect("the first consumption must win");
    let replay = setup
        .nodes
        .consume_challenge_and_issue_session(&claim)
        .await
        .unwrap_err();
    assert!(
        matches!(replay, NodePortError::AlreadyUsed { .. }),
        "{replay:?}"
    );

    // An expired challenge refuses honestly.
    let expired_challenge = setup
        .nodes
        .issue_challenge(&NewChallenge {
            machine_id: setup.machine_id_of("challenged").await,
            nonce: "nonce-5".to_owned(),
            purpose: ChallengePurpose::Session,
            new_public_key: None,
            now,
            expires_at: now,
        })
        .await
        .expect("the challenge must issue");
    let expired = setup
        .nodes
        .consume_challenge_and_issue_session(&SessionClaim {
            challenge_id: expired_challenge.id,
            credential_id,
            session_ttl_millis: 600_000,
            now: now + 1,
            audit: audit_event("node_session_issued"),
        })
        .await
        .unwrap_err();
    assert!(
        matches!(expired, NodePortError::Expired { .. }),
        "{expired:?}"
    );
}

#[tokio::test]
async fn revocation_stops_renewal_and_sessions_and_allows_explicit_rebind() {
    let setup = setup().await;
    let (machine_id, credential_id) = enrolled_machine(&setup, "revocable", KEY_A).await;
    let now = fleet_core::SystemClock::now_unix_millis();

    setup
        .nodes
        .issue_challenge(&NewChallenge {
            machine_id: machine_id.clone(),
            nonce: "nonce-6".to_owned(),
            purpose: ChallengePurpose::Session,
            new_public_key: None,
            now,
            expires_at: now + 60_000,
        })
        .await
        .expect("the challenge must issue");
    let session = setup
        .nodes
        .consume_challenge_and_issue_session(&SessionClaim {
            challenge_id: setup.challenge_id_of("nonce-6").await,
            credential_id: credential_id.clone(),
            session_ttl_millis: 600_000,
            now,
            audit: audit_event("node_session_issued"),
        })
        .await
        .expect("the session must issue");

    setup
        .nodes
        .revoke_identity(&revoke_claim(&machine_id, now))
        .await
        .expect("the revocation must succeed");

    let validity = setup
        .nodes
        .validate_session(&session.session_id, now + 1)
        .await
        .expect("the validity must read");
    assert!(matches!(
        validity,
        fleet_application::node::SessionValidity::Invalid { .. }
    ));

    let renewal = setup
        .nodes
        .issue_challenge(&NewChallenge {
            machine_id,
            nonce: "nonce-7".to_owned(),
            purpose: ChallengePurpose::Session,
            new_public_key: None,
            now: now + 1,
            expires_at: now + 60_000,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(renewal, NodePortError::Rejected { .. }),
        "{renewal:?}"
    );

    // Re-enrollment over the revoked identity replaces it with a version bump.
    new_token(
        &setup,
        &setup.machine_id_of("revocable").await,
        "hash-rebind",
        60_000,
        now + 2,
    )
    .await;
    let rebind = setup
        .nodes
        .enroll(&enroll_claim("hash-rebind", KEY_B, now + 3))
        .await
        .expect("the rebind must succeed");
    assert!(rebind.rebind);
    assert_eq!(rebind.node_key_version, 2);
}

#[tokio::test]
async fn revocation_consumes_pending_tokens_and_records_the_count() {
    let setup = setup().await;
    let (machine_id, _) = enrolled_machine(&setup, "revoked-tokens", KEY_A).await;
    let now = fleet_core::SystemClock::now_unix_millis();
    new_token(&setup, &machine_id, "hash-pending-1", 60_000, now).await;
    new_token(&setup, &machine_id, "hash-pending-2", 60_000, now).await;

    let invalidated = setup
        .nodes
        .revoke_identity(&revoke_claim(&machine_id, now + 1))
        .await
        .expect("the revoke transaction must succeed");
    assert_eq!(invalidated, 2);

    for hash in ["hash-pending-1", "hash-pending-2"] {
        let facts = setup
            .nodes
            .token_facts(hash)
            .await
            .expect("the token read must succeed")
            .expect("the token must still be recorded");
        assert_eq!(facts.status, "consumed");
    }
    let audit_json: String = sqlx::query_scalar(
        "SELECT metadata_json FROM audit_events WHERE action = 'node.revoke' \
         AND resource = ?1 ORDER BY occurred_at DESC LIMIT 1",
    )
    .bind(&machine_id)
    .fetch_one(setup.store.pool())
    .await
    .expect("the revoke audit intent must be stored");
    let metadata: serde_json::Value =
        serde_json::from_str(&audit_json).expect("audit metadata must be valid JSON");
    assert_eq!(metadata["event"], "node_identity_revoked");
    assert_eq!(metadata["invalidatedEnrollmentCount"], "2");
    assert_eq!(metadata.as_object().map(serde_json::Map::len), Some(2));

    let statuses: Vec<String> = sqlx::query_scalar(
        "SELECT status FROM node_enrollment_tokens WHERE machine_id = ?1 AND token_hash LIKE 'hash-pending-%'",
    )
    .bind(&machine_id)
    .fetch_all(setup.store.pool())
    .await
    .expect("the token statuses must be readable");
    assert_eq!(statuses, vec!["consumed", "consumed"]);
}

#[tokio::test]
async fn a_failed_revoke_audit_rolls_back_identity_and_pending_token_changes() {
    let setup = setup().await;
    let (machine_id, _) = enrolled_machine(&setup, "revoke-audit-failure", KEY_A).await;
    let now = fleet_core::SystemClock::now_unix_millis();
    new_token(&setup, &machine_id, "hash-revoke-rollback", 60_000, now).await;
    sqlx::query(
        "CREATE TRIGGER reject_node_revoke_audit BEFORE INSERT ON audit_events \
         WHEN NEW.action = 'node.revoke' BEGIN SELECT RAISE(FAIL, 'injected audit failure'); END",
    )
    .execute(setup.store.pool())
    .await
    .expect("the audit failure trigger must be installed");

    let error = setup
        .nodes
        .revoke_identity(&revoke_claim(&machine_id, now + 1))
        .await
        .expect_err("the injected audit failure must abort revocation");
    assert!(matches!(error, NodePortError::Backend { .. }), "{error:?}");

    let identity = setup
        .nodes
        .identity(&machine_id)
        .await
        .expect("the identity read must succeed")
        .expect("the identity must remain recorded");
    assert_eq!(identity.status, NodeStatus::Active);
    let token = setup
        .nodes
        .token_facts("hash-revoke-rollback")
        .await
        .expect("the token read must succeed")
        .expect("the token must remain recorded");
    assert_eq!(token.status, "pending");
}

#[tokio::test]
async fn session_validation_walks_the_whole_chain() {
    let setup = setup().await;
    let (machine_id, credential_id) = enrolled_machine(&setup, "validated", KEY_A).await;
    let now = fleet_core::SystemClock::now_unix_millis();

    setup
        .nodes
        .issue_challenge(&NewChallenge {
            machine_id: machine_id.clone(),
            nonce: "nonce-8".to_owned(),
            purpose: ChallengePurpose::Session,
            new_public_key: None,
            now,
            expires_at: now + 60_000,
        })
        .await
        .expect("the challenge must issue");
    let session = setup
        .nodes
        .consume_challenge_and_issue_session(&SessionClaim {
            challenge_id: setup.challenge_id_of("nonce-8").await,
            credential_id: credential_id.clone(),
            session_ttl_millis: 600_000,
            now,
            audit: audit_event("node_session_issued"),
        })
        .await
        .expect("the session must issue");

    let valid = setup
        .nodes
        .validate_session(&session.session_id, now + 1)
        .await
        .expect("the validity must read");
    assert_eq!(
        valid,
        fleet_application::node::SessionValidity::Valid {
            machine_id: machine_id.clone(),
            credential_id: credential_id.clone(),
        }
    );

    // An unknown session is invalid, not an error.
    let unknown = setup
        .nodes
        .validate_session("no-such-session", now + 1)
        .await
        .expect("the validity must read");
    assert!(matches!(
        unknown,
        fleet_application::node::SessionValidity::Invalid { .. }
    ));

    // Revoking the credential invalidates the session.
    setup
        .nodes
        .revoke_identity(&revoke_claim(&machine_id, now + 2))
        .await
        .expect("the revocation must succeed");
    let revoked = setup
        .nodes
        .validate_session(&session.session_id, now + 2)
        .await
        .expect("the validity must read");
    assert!(matches!(
        revoked,
        fleet_application::node::SessionValidity::Invalid { .. }
    ));
}

#[tokio::test]
async fn the_node_view_lists_pending_tokens_and_reports_absence_for_unknown_machines() {
    let setup = setup().await;
    let machine_id = register_machine(&setup.machines, "viewed").await;
    let now = fleet_core::SystemClock::now_unix_millis();
    new_token(&setup, &machine_id, "hash-view-1", 60_000, now).await;
    new_token(&setup, &machine_id, "hash-view-2", 60_000, now).await;

    let view = setup
        .nodes
        .node_view(&machine_id, now + 1)
        .await
        .expect("the view must read")
        .expect("the machine exists");
    assert!(view.identity.is_none());
    assert_eq!(view.pending_tokens.len(), 2);
    assert_eq!(view.active_credentials.len(), 0);
    assert_eq!(view.active_sessions, 0);

    let unknown = setup
        .nodes
        .node_view("01990000-0000-7000-8000-000000000000", now)
        .await
        .expect("the view must read");
    assert!(unknown.is_none(), "an unknown machine has no node view");
}

#[tokio::test]
async fn the_audit_intent_commits_with_the_state_change() {
    let setup = setup().await;
    let (machine_id, _) = enrolled_machine(&setup, "audited", KEY_A).await;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE action = 'node.enroll'")
            .fetch_one(setup.store.pool())
            .await
            .expect("the audit query must run");
    assert!(count >= 1, "the enrollment's audit intent must be durable");
    let machine_exists: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM node_identities WHERE machine_id = ?1")
            .bind(&machine_id)
            .fetch_one(setup.store.pool())
            .await
            .expect("the identity query must run");
    assert_eq!(machine_exists, 1);
}

impl Setup {
    /// The machine id registered under `name`, for test convenience.
    async fn machine_id_of(&self, name: &str) -> String {
        let machines = self
            .machines
            .list(&fleet_application::machine::MachineFilter::default(), 10)
            .await
            .expect("the machine list must read");
        machines
            .into_iter()
            .find(|machine| machine.name == name)
            .expect("the machine exists")
            .id
    }

    /// The challenge id that was issued with `nonce`, for test convenience.
    async fn challenge_id_of(&self, nonce: &str) -> String {
        let row: (String,) = sqlx::query_as("SELECT id FROM node_challenges WHERE nonce = ?1")
            .bind(nonce)
            .fetch_one(self.store.pool())
            .await
            .expect("the challenge exists");
        row.0
    }
}
