//! Exercises the operation worker over a real database: atomic claims, lease
//! recovery after a crash, cancellation, and the end-to-end noop path.

use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::{NoopExecutor, TickReport};
use fleet_storage_sqlite::{AuditSink, OperationRepository, Store};
use sqlx::SqlitePool;

async fn service() -> (tempfile::TempDir, Operations, SqlitePool) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool = store.pool().clone();
    let service = Operations::new(
        std::sync::Arc::new(OperationRepository::new(pool.clone())),
        std::sync::Arc::new(AuditSink::new(pool.clone())),
    );
    (dir, service, pool)
}

#[tokio::test]
async fn the_noop_operation_runs_end_to_end() {
    let (_dir, operations, _pool) = service().await;
    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &fleet_application::operation::NewOperation {
                kind: "noop".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: Some("corr-worker-1".to_owned()),
                payload_json: None,
                reviewed: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(operation.state, "pending");

    let now = fleet_core::SystemClock::now_unix_millis();
    let report = operations
        .tick(&NoopExecutor, "worker-a", now, 60_000)
        .await
        .unwrap();
    assert!(report.claimed);
    assert!(
        report.completed,
        "a claimed noop completes in the same tick"
    );

    let finished = operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &operation.id,
        )
        .await
        .unwrap();
    assert_eq!(finished.state, "succeeded");
    assert_eq!(finished.result_json.as_deref(), Some("{\"kind\":\"noop\"}"));
}

#[tokio::test]
async fn two_workers_cannot_claim_the_same_operation() {
    let (_dir, operations, _pool) = service().await;
    operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &fleet_application::operation::NewOperation {
                kind: "noop".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: None,
                reviewed: false,
            },
        )
        .await
        .unwrap();
    let now = fleet_core::SystemClock::now_unix_millis();

    let first = operations
        .tick(&NoopExecutor, "worker-a", now, 60_000)
        .await
        .unwrap();
    assert!(first.claimed);

    // Worker B's claim finds nothing pending: the row is running.
    let second = operations
        .tick(&NoopExecutor, "worker-b", now, 60_000)
        .await
        .unwrap();
    assert!(
        !second.claimed,
        "the second worker must not steal the claim"
    );
    assert_eq!(second.pending, 0);
    assert_eq!(second.running, 0, "worker A completed the operation");
}

#[tokio::test]
async fn a_crashed_workers_lease_is_recovered_as_failed_not_retried() {
    let (_dir, operations, pool) = service().await;
    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &fleet_application::operation::NewOperation {
                kind: "noop".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: None,
                reviewed: false,
            },
        )
        .await
        .unwrap();

    // A worker claims the operation and then "dies": the claim stays, the
    // clock moves past the lease, and no completion ever lands.
    let claimed_at = fleet_core::SystemClock::now_unix_millis();
    let repository: std::sync::Arc<dyn fleet_application::operation::OperationPort> =
        std::sync::Arc::new(OperationRepository::new(pool));
    let claimed = repository
        .claim_pending("doomed-worker", claimed_at)
        .await
        .unwrap();
    assert!(claimed.is_some());

    let after_lease = claimed_at + 61_000;
    let report = operations
        .tick(&NoopExecutor, "worker-b", after_lease, 60_000)
        .await
        .unwrap();
    assert_eq!(report.recovered, 1, "the expired claim is resolved");
    assert!(!report.claimed, "the expired operation is not retried");

    let resolved = operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &operation.id,
        )
        .await
        .unwrap();
    assert_eq!(resolved.state, "failed");
    let error = resolved.error_json.expect("the recovery names its reason");
    assert!(error.contains("worker_lease_expired"), "{error}");
}

#[tokio::test]
async fn a_cancelled_operation_stops_without_running() {
    let (_dir, operations, _pool) = service().await;
    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &fleet_application::operation::NewOperation {
                kind: "noop".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: None,
                reviewed: false,
            },
        )
        .await
        .unwrap();

    let cancelled = operations
        .cancel(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &operation.id,
        )
        .await
        .unwrap();
    assert!(cancelled.cancel_requested);
    assert_eq!(
        cancelled.state, "pending",
        "a pending operation is refused before it starts"
    );

    let now = fleet_core::SystemClock::now_unix_millis();
    let report = operations
        .tick(&NoopExecutor, "worker-a", now, 60_000)
        .await
        .unwrap();
    assert!(report.claimed);
    assert!(report.completed);

    let finished = operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &operation.id,
        )
        .await
        .unwrap();
    assert_eq!(finished.state, "cancelled");
}

#[tokio::test]
async fn a_deadline_expires_even_when_no_worker_claims_it() {
    let (_dir, operations, _pool) = service().await;
    let now = fleet_core::SystemClock::now_unix_millis();
    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &fleet_application::operation::NewOperation {
                kind: "noop".to_owned(),
                idempotency_key: None,
                deadline_at: Some(now - 1_000),
                correlation_id: None,
                payload_json: None,
                reviewed: false,
            },
        )
        .await
        .unwrap();

    let report = operations
        .tick(&NoopExecutor, "worker-a", now, 60_000)
        .await
        .unwrap();
    assert_eq!(report.timed_out, 1);
    assert!(!report.claimed, "a timed-out operation is never claimed");

    let finished = operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &operation.id,
        )
        .await
        .unwrap();
    assert_eq!(finished.state, "timed_out");
}

#[tokio::test]
async fn restart_preserves_terminal_truth() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fleet.db");
    let store = Store::open(&path).await.unwrap();
    let operations = Operations::new(
        std::sync::Arc::new(OperationRepository::new(store.pool().clone())),
        std::sync::Arc::new(AuditSink::new(store.pool().clone())),
    );
    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &fleet_application::operation::NewOperation {
                kind: "noop".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: None,
                reviewed: false,
            },
        )
        .await
        .unwrap();
    operations
        .tick(
            &NoopExecutor,
            "worker-a",
            fleet_core::SystemClock::now_unix_millis(),
            60_000,
        )
        .await
        .unwrap();
    drop(operations);
    store.close().await;

    // A "restart": a brand-new store over the same file.
    let store = Store::open(&path).await.unwrap();
    let operations = Operations::new(
        std::sync::Arc::new(OperationRepository::new(store.pool().clone())),
        std::sync::Arc::new(AuditSink::new(store.pool().clone())),
    );
    let reopened = operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &operation.id,
        )
        .await
        .unwrap();
    assert_eq!(
        reopened.state, "succeeded",
        "terminal truth survives the restart"
    );

    // And the queue is empty: nothing re-executes.
    let report = operations
        .tick(
            &NoopExecutor,
            "worker-a",
            fleet_core::SystemClock::now_unix_millis(),
            60_000,
        )
        .await
        .unwrap();
    assert_eq!(report, TickReport::default());
    let _ = std::marker::PhantomData::<Operation>;
}
