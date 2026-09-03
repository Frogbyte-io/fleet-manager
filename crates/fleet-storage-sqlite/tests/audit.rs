//! Exercises the audit ledger: append-only enforcement, transactional
//! intents, ordered pagination, correlation filtering, metadata redaction
//! rules, and authorized queries.

use fleet_application::audit::{AuditIntent, AuditMetadata, AuditOutcome, MetadataError};
use fleet_application::authz::{AccessRequest, Decision, Permission, ReasonId};
use fleet_storage_sqlite::audit::Query;
use fleet_storage_sqlite::{AuditLedger, Store};

async fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    (dir, store)
}

fn intent(action: Permission, allowed: bool, correlation: Option<&str>) -> AuditIntent {
    AuditIntent {
        actor: "anonymous-lan-admin".to_owned(),
        action: action.id().to_owned(),
        resource: None,
        decision: if allowed {
            Decision::allow()
        } else {
            Decision::deny(ReasonId::UnknownPrincipal)
        },
        correlation_id: correlation.map(str::to_owned),
        operation_id: None,
        metadata: AuditMetadata::default(),
    }
}

#[tokio::test]
async fn the_ledger_is_append_only_at_the_database_level() {
    let (_dir, store) = store().await;
    let ledger = AuditLedger::new(store.pool());
    let id = ledger
        .append_intent(&intent(Permission::SystemRead, true, None))
        .await
        .unwrap();

    // No UPDATE, no DELETE — not even by the owning process.
    let update = sqlx::query("UPDATE audit_events SET actor = 'root' WHERE id = ?1")
        .bind(&id)
        .execute(store.pool())
        .await;
    assert!(update.is_err(), "updates must be refused");

    let delete = sqlx::query("DELETE FROM audit_events WHERE id = ?1")
        .bind(&id)
        .execute(store.pool())
        .await;
    assert!(delete.is_err(), "deletes must be refused");
}

#[tokio::test]
async fn an_intent_rolled_back_with_its_transaction_leaves_no_event() {
    let (_dir, store) = store().await;
    let mut tx = store.begin_write().await.unwrap();
    let intent = intent(Permission::SecretWrite, true, None);
    let id = fleet_storage_sqlite::audit::append_intent_tx(&mut tx, &intent)
        .await
        .unwrap();
    tx.rollback().await.unwrap();

    let ledger = AuditLedger::new(store.pool());
    let page = ledger
        .query(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            Query::default(),
        )
        .await
        .unwrap();
    assert!(
        page.events.iter().all(|event| event.id != id),
        "a rolled-back intent must not persist"
    );
}

#[tokio::test]
async fn pagination_is_ordered_and_the_cursor_advances() {
    let (_dir, store) = store().await;
    let ledger = AuditLedger::new(store.pool());
    for i in 0..5 {
        ledger
            .append_intent(&intent(
                Permission::SystemRead,
                true,
                Some(&format!("corr-{i}")),
            ))
            .await
            .unwrap();
    }

    let authorizer = fleet_auth::LanAllowAllAuthorizer;
    let mut seen = Vec::new();
    let mut after_seq = None;
    loop {
        let page = ledger
            .query(
                &authorizer,
                "anonymous-lan-admin",
                Query {
                    after_seq,
                    limit: 2,
                    correlation_id: None,
                },
            )
            .await
            .unwrap();
        seen.extend(page.events.iter().map(|event| event.seq));
        match page.next_seq {
            Some(next) => after_seq = Some(next),
            None => break,
        }
    }
    let mut sorted = seen.clone();
    sorted.sort_unstable();
    assert_eq!(seen, sorted, "pages are in append order");
    assert_eq!(seen.len(), 5);
}

#[tokio::test]
async fn a_correlation_filter_returns_only_that_flow() {
    let (_dir, store) = store().await;
    let ledger = AuditLedger::new(store.pool());
    ledger
        .append_intent(&intent(Permission::SystemRead, true, Some("flow-a")))
        .await
        .unwrap();
    ledger
        .append_intent(&intent(Permission::SystemRead, true, Some("flow-b")))
        .await
        .unwrap();

    let page = ledger
        .query(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            Query {
                after_seq: None,
                limit: 10,
                correlation_id: Some("flow-b"),
            },
        )
        .await
        .unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].correlation_id.as_deref(), Some("flow-b"));
}

/// An authorizer that denies everything, to drive the real denial path.
#[derive(Debug)]
struct DenyAll;
impl fleet_application::authz::Authorizer for DenyAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::deny(ReasonId::UnknownPrincipal)
    }
}

#[tokio::test]
async fn an_unauthorized_caller_cannot_read_the_ledger() {
    let (_dir, store) = store().await;
    let ledger = AuditLedger::new(store.pool());
    ledger
        .append_intent(&intent(Permission::SystemRead, true, None))
        .await
        .unwrap();

    let error = ledger
        .query(&DenyAll, "someone-else", Query::default())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        fleet_storage_sqlite::audit::AuditError::Unauthorized(_)
    ));
    assert!(error.to_string().contains("policy.unknown_principal"));
}

#[tokio::test]
async fn outcomes_append_separately_and_reference_their_intent() {
    let (_dir, store) = store().await;
    let ledger = AuditLedger::new(store.pool());
    let intent_id = ledger
        .append_intent(&intent(Permission::SecretWrite, true, Some("flow-x")))
        .await
        .unwrap();

    ledger
        .append_outcome(&intent_id, AuditOutcome::Succeeded)
        .await
        .unwrap();

    let page = ledger
        .query(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            Query {
                after_seq: None,
                limit: 10,
                correlation_id: Some("flow-x"),
            },
        )
        .await
        .unwrap();
    assert_eq!(page.events.len(), 2);
    assert_eq!(page.events[0].outcome, None);
    assert_eq!(page.events[1].outcome, Some(AuditOutcome::Succeeded));

    // An outcome without an intent is refused.
    let error = ledger
        .append_outcome("no-such-intent", AuditOutcome::Failed)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("no audit intent"));
}

#[test]
fn the_metadata_guard_rejects_raw_request_and_credential_material() {
    let corpus = [
        "authorization",
        "X-Forwarded-For",
        "x-api-key",
        "session-token",
        "password",
        "user-secret",
        "private-key",
        "headers",
        "env",
        "Environment",
        "cookie",
    ];
    for key in corpus {
        let mut metadata = AuditMetadata::default();
        let error = metadata.insert(key, "value");
        assert!(
            matches!(error, Err(MetadataError::ForbiddenKey { .. })),
            "{key:?} must be forbidden"
        );
        assert!(
            error
                .unwrap_err()
                .to_string()
                .contains("must never be recorded")
        );
    }
}

#[test]
fn the_metadata_guard_bounds_sizes_and_counts() {
    let mut metadata = AuditMetadata::default();
    let error = metadata.insert("big", &"x".repeat(4096));
    assert!(matches!(error, Err(MetadataError::ValueTooLarge { .. })));

    for i in 0..40 {
        let result = metadata.insert(&format!("key-{i}"), "value");
        if i < 32 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(MetadataError::TooManyEntries { .. })));
        }
    }
}

#[tokio::test]
async fn validated_metadata_is_stored_and_readable() {
    let (_dir, store) = store().await;
    let ledger = AuditLedger::new(store.pool());
    let mut metadata = AuditMetadata::default();
    metadata.insert("node", "workshop-1").unwrap();
    metadata.insert("attempt", "2").unwrap();

    let intent = AuditIntent {
        actor: "anonymous-lan-admin".to_owned(),
        action: Permission::SystemRead.id().to_owned(),
        resource: None,
        decision: Decision::allow(),
        correlation_id: Some("flow-m".to_owned()),
        operation_id: None,
        metadata,
    };
    ledger.append_intent(&intent).await.unwrap();

    let page = ledger
        .query(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            Query {
                after_seq: None,
                limit: 10,
                correlation_id: Some("flow-m"),
            },
        )
        .await
        .unwrap();
    assert!(
        page.events[0]
            .metadata_json
            .contains("\"node\":\"workshop-1\"")
    );
    assert!(page.events[0].metadata_json.contains("\"attempt\":\"2\""));
}
