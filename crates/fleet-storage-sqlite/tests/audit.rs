//! Exercises the audit ledger: append-only enforcement, transactional
//! intents, ordered pagination, correlation filtering, metadata redaction
//! rules, and authorized queries.

use fleet_application::audit::{AuditIntent, AuditMetadata, AuditOutcome, MetadataError};
use fleet_application::authz::{Decision, Permission, ReasonId};
use fleet_storage_sqlite::audit::Query;
use fleet_storage_sqlite::{AuditLedger, MIGRATOR, Store};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

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
    let page = ledger.query(&Query::default()).await.unwrap();
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

    let mut seen = Vec::new();
    let mut after_seq = None;
    loop {
        let page = ledger
            .query(&Query {
                after_seq,
                limit: 2,
                correlation_id: None,
                ..Query::default()
            })
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
        .query(&Query {
            after_seq: None,
            limit: 10,
            correlation_id: Some("flow-b".to_owned()),
            ..Query::default()
        })
        .await
        .unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].correlation_id.as_deref(), Some("flow-b"));
}

#[tokio::test]
async fn audit_filters_are_applied_before_sequence_cursor_pagination() {
    let (_dir, store) = store().await;
    let ledger = AuditLedger::new(store.pool());
    let first = AuditIntent {
        actor: "alice".to_owned(),
        action: "machine.update".to_owned(),
        resource: Some("machine-1".to_owned()),
        decision: Decision::allow(),
        correlation_id: None,
        operation_id: None,
        metadata: AuditMetadata::default(),
    };
    let first_id = ledger.append_intent(&first).await.unwrap();
    ledger
        .append_outcome(&first_id, AuditOutcome::Succeeded)
        .await
        .unwrap();
    let second_id = ledger
        .append_intent(&AuditIntent {
            actor: "alice".to_owned(),
            action: "machine.update".to_owned(),
            resource: Some("machine-1".to_owned()),
            decision: Decision::allow(),
            correlation_id: None,
            operation_id: None,
            metadata: AuditMetadata::default(),
        })
        .await
        .unwrap();
    ledger
        .append_outcome(&second_id, AuditOutcome::Succeeded)
        .await
        .unwrap();
    ledger
        .append_intent(&AuditIntent {
            actor: "bob".to_owned(),
            action: "machine.delete".to_owned(),
            resource: Some("machine-2".to_owned()),
            decision: Decision::deny(ReasonId::UnknownPrincipal),
            correlation_id: None,
            operation_id: None,
            metadata: AuditMetadata::default(),
        })
        .await
        .unwrap();

    let page = ledger
        .query(&Query {
            after_seq: None,
            limit: 1,
            correlation_id: None,
            actor: Some("alice".to_owned()),
            action: Some("machine.update".to_owned()),
            resource: Some("machine-1".to_owned()),
            outcome: Some("succeeded".to_owned()),
            from: None,
            to: None,
        })
        .await
        .unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].actor, "alice");
    assert_eq!(page.events[0].outcome, Some(AuditOutcome::Succeeded));
    assert_eq!(page.next_seq, Some(page.events[0].seq));

    let next_page = ledger
        .query(&Query {
            after_seq: page.next_seq,
            limit: 1,
            actor: Some("alice".to_owned()),
            action: Some("machine.update".to_owned()),
            resource: Some("machine-1".to_owned()),
            outcome: Some("succeeded".to_owned()),
            ..Query::default()
        })
        .await
        .unwrap();
    assert_eq!(next_page.events.len(), 1);
    assert_eq!(next_page.events[0].actor, "alice");
    assert_eq!(next_page.events[0].outcome, Some(AuditOutcome::Succeeded));
    assert!(next_page.events[0].seq > page.events[0].seq);

    let no_events = ledger
        .query(&Query {
            from: Some(i64::MAX),
            ..Query::default()
        })
        .await
        .unwrap();
    assert!(
        no_events.events.is_empty(),
        "the inclusive lower time bound is applied"
    );
    let no_events = ledger
        .query(&Query {
            to: Some(0),
            ..Query::default()
        })
        .await
        .unwrap();
    assert!(
        no_events.events.is_empty(),
        "the inclusive upper time bound is applied"
    );
}

#[tokio::test]
async fn completed_intents_are_not_returned_as_pending() {
    let (_dir, store) = store().await;
    let ledger = AuditLedger::new(store.pool());
    let intent_id = ledger
        .append_intent(&AuditIntent {
            actor: "pending-actor".to_owned(),
            action: "operation.run".to_owned(),
            resource: None,
            decision: Decision::allow(),
            correlation_id: None,
            operation_id: Some("operation-pending".to_owned()),
            metadata: AuditMetadata::default(),
        })
        .await
        .unwrap();

    let pending = ledger
        .query(&Query {
            actor: Some("pending-actor".to_owned()),
            outcome: Some("pending".to_owned()),
            ..Query::default()
        })
        .await
        .unwrap();
    assert_eq!(pending.events.len(), 1);

    ledger
        .append_outcome(&intent_id, AuditOutcome::Succeeded)
        .await
        .unwrap();
    let no_longer_pending = ledger
        .query(&Query {
            actor: Some("pending-actor".to_owned()),
            outcome: Some("pending".to_owned()),
            ..Query::default()
        })
        .await
        .unwrap();
    assert!(no_longer_pending.events.is_empty());
}

#[tokio::test]
async fn migration_does_not_guess_pending_status_for_historical_events() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fleet.db");
    let legacy_pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    MIGRATOR.run_to(22, &legacy_pool).await.unwrap();

    // Before migration 23 outcomes did not reference their intent. Even when
    // the fields match exactly, do not infer whether an old intent is pending.
    sqlx::query(
        "INSERT INTO audit_events \
         (id, occurred_at, actor, action, resource, allowed, reason, correlation_id, operation_id, outcome, metadata_json) \
         VALUES ('legacy-intent', 1, 'actor', 'operation.run', NULL, 1, 'permitted', NULL, 'op-1', NULL, '{}'), \
                ('legacy-outcome', 2, 'actor', 'operation.run', NULL, 1, 'permitted', NULL, 'op-1', 'succeeded', '{}')",
    )
    .execute(&legacy_pool)
    .await
    .unwrap();
    legacy_pool.close().await;

    let store = Store::open(&path).await.unwrap();
    let ledger = AuditLedger::new(store.pool());
    let historical = ledger
        .query(&Query {
            outcome: Some("pending".to_owned()),
            ..Query::default()
        })
        .await
        .unwrap();
    assert!(historical.events.is_empty());

    ledger
        .append_intent(&intent(Permission::SystemRead, true, None))
        .await
        .unwrap();
    let current = ledger
        .query(&Query {
            outcome: Some("pending".to_owned()),
            ..Query::default()
        })
        .await
        .unwrap();
    assert_eq!(current.events.len(), 1);
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
        .query(&Query {
            after_seq: None,
            limit: 10,
            correlation_id: Some("flow-x".to_owned()),
            ..Query::default()
        })
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
        .query(&Query {
            after_seq: None,
            limit: 10,
            correlation_id: Some("flow-m".to_owned()),
            ..Query::default()
        })
        .await
        .unwrap();
    assert!(
        page.events[0]
            .metadata_json
            .contains("\"node\":\"workshop-1\"")
    );
    assert!(page.events[0].metadata_json.contains("\"attempt\":\"2\""));
}
