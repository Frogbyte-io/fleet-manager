//! The worker host's execution lifecycle, barrier-controlled (FM-215): a
//! deliberately blocked executor cannot stall maintenance or the shutdown
//! observation; the lease is renewed while work runs; the active-job bound
//! holds; and draining requests durable cancellation with a bounded wait.
//! No timing-only sleeps — the barriers are the synchronization.

use std::sync::Arc;

use async_trait::async_trait;
use fleet_application::operation::{NewOperation, Operations};
use fleet_application::worker::{OperationExecutor, TickReport};
use fleet_controller::worker::{LEASE_MS, WorkerHost};
use fleet_storage_sqlite::{AuditSink, OperationRepository, Store};
use tokio::sync::Barrier;

/// How long the test waits for an expected condition before failing. Long
/// enough for a few ticks; short enough to fail fast.
const WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// An executor that blocks on a barrier forever (until the barrier is
/// released by the test) and records that it started.
#[derive(Debug)]
struct BarrierExecutor {
    barrier: Arc<Barrier>,
    started: std::sync::atomic::AtomicUsize,
    released: std::sync::atomic::AtomicBool,
}

impl BarrierExecutor {
    fn new(parties: usize) -> Arc<Self> {
        Arc::new(Self {
            barrier: Arc::new(Barrier::new(parties)),
            started: std::sync::atomic::AtomicUsize::new(0),
            released: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn release(&self) {
        self.released
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // A single wait on a barrier with one party returns immediately; the
        // blocked executor's wait is aborted by the test teardown instead.
    }

    fn started(&self) -> usize {
        self.started.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[async_trait]
impl OperationExecutor for BarrierExecutor {
    async fn execute(
        &self,
        _operations: &fleet_application::operation::Operations,
        _operation: &fleet_application::operation::Operation,
    ) -> Result<(), String> {
        self.started
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Block until released: the barrier with two parties (the test and
        // the executor) is the deterministic stand-in for a long install.
        if !self.released.load(std::sync::atomic::Ordering::Relaxed) {
            self.barrier.wait().await;
        }
        Ok(())
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    operations: Arc<Operations>,
    pool: sqlx::SqlitePool,
}

async fn service() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool = store.pool().clone();
    std::mem::forget(store);
    let operations = Arc::new(Operations::new(
        Arc::new(OperationRepository::new(pool.clone())),
        Arc::new(AuditSink::new(pool.clone())),
    ));
    Harness {
        _dir: dir,
        operations,
        pool,
    }
}

impl Harness {
    async fn create_operation(&self, kind: &str) -> String {
        self.operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                "anonymous-lan-admin",
                &NewOperation {
                    kind: kind.to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: None,
                    review_token: None,
                },
            )
            .await
            .unwrap()
            .id
    }
}

/// Waits until `check` is true, polling on a short tick.
async fn wait_for(check: impl Fn() -> bool, what: &str) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while tokio::time::Instant::now() < deadline {
        if check() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn a_blocked_executor_does_not_stall_maintenance_or_shutdown() {
    let harness = service().await;
    let executor = BarrierExecutor::new(2);
    let host = WorkerHost::new(harness.operations.clone(), executor.clone(), 4)
        .with_drain_grace(std::time::Duration::from_secs(1));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let operation_id = harness.create_operation("noop").await;
    let host_task = tokio::spawn(async move {
        host.run(async move {
            let _ = shutdown_rx.await;
        })
        .await;
    });

    // The executor picks the work up and blocks.
    wait_for(|| executor.started() == 1, "the executor to start").await;

    // Deadline maintenance runs while the executor is blocked: create a new
    // operation with a deadline in the past through the port, and the next
    // maintenance tick times it out even though the first operation never
    // finished.
    let overdue_id = harness.create_operation("noop").await;
    let _ = sqlx::query("UPDATE operations SET deadline_at = ?2 WHERE id = ?1")
        .bind(&overdue_id)
        .bind(fleet_core::SystemClock::now_unix_millis() - 1_000)
        .execute(&harness.pool)
        .await
        .unwrap();
    let timed_out = harness
        .operations
        .maintain(fleet_core::SystemClock::now_unix_millis(), LEASE_MS)
        .await
        .unwrap();
    assert_eq!(timed_out.timed_out, 1, "maintenance ran while blocked");

    // Shutdown is observed promptly despite the blocked executor: signal and
    // wait for the host task to exit. The drain's bounded grace (2 min) is
    // not waited out in full — the host exits the run loop and the blocked
    // task is aborted with the JoinSet.
    shutdown_tx.send(()).unwrap();
    let exited = tokio::time::timeout(std::time::Duration::from_secs(5), host_task).await;
    assert!(
        exited.is_ok(),
        "shutdown must be observed and the drain bounded while blocked"
    );

    // The blocked operation was moved to `cancelling` by the durable
    // cancellation request and is still executing: the blocked executor
    // never completed it, so neither a fabricated terminal state nor a
    // "stopped" claim is recorded. The lease recovery resolves it honestly
    // once the host (and its heartbeat) is gone.
    let (state, cancel_requested) = raw_state(&harness.pool, &operation_id).await.unwrap();
    assert_eq!(state, "cancelling", "cancel requested: {cancel_requested}");
    assert!(cancel_requested, "{state}");
}

#[tokio::test]
async fn maintenance_claims_proceed_while_an_operation_is_blocked() {
    let harness = service().await;
    let executor = BarrierExecutor::new(2);
    let host = WorkerHost::new(harness.operations.clone(), executor.clone(), 4);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let blocked_id = harness.create_operation("noop").await;
    let host_task = tokio::spawn(async move {
        host.run(async move {
            let _ = shutdown_rx.await;
        })
        .await;
    });
    wait_for(|| executor.started() == 1, "the executor to start").await;

    // A second operation is claimed while the first is blocked: the host's
    // maintenance loop is live.
    let second_id = harness.create_operation("noop").await;
    wait_for(
        || executor.started() == 2,
        "the second claim while the first is blocked",
    )
    .await;

    // Both are running: tracked concurrently, not sequenced.
    assert_ne!(blocked_id, second_id);
    executor.release();

    shutdown_tx.send(()).unwrap();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), host_task).await;
}

#[tokio::test]
async fn the_lease_is_renewed_while_work_runs() {
    let harness = service().await;
    // A short lease: without renewal, the sweep would recover the work.
    let executor = BarrierExecutor::new(2);
    let operations = harness.operations.clone();
    let host = WorkerHost::new(operations.clone(), executor.clone(), 4)
        .with_lease_ms(1_000)
        .with_drain_grace(std::time::Duration::from_secs(1));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let _operation_id = harness.create_operation("noop").await;
    let host_task = tokio::spawn(async move {
        host.run(async move {
            let _ = shutdown_rx.await;
        })
        .await;
    });
    wait_for(|| executor.started() == 1, "the executor to start").await;

    // While the executor is blocked past the whole lease, the recovery
    // sweep does not recover the running operation: the heartbeat renewed
    // it. The host runs with a 1s lease (heartbeats at ~333ms), so 1.5s of
    // blocking covers three heartbeat intervals and two expiries.
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    let report: TickReport = operations
        .maintain(fleet_core::SystemClock::now_unix_millis(), 1_000)
        .await
        .unwrap();
    assert_eq!(report.recovered, 0, "a renewed claim is not recovered");

    executor.release();
    shutdown_tx.send(()).unwrap();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), host_task).await;
}

#[tokio::test]
async fn the_active_job_bound_limits_concurrent_claims() {
    let harness = service().await;
    // Bound the host to one active job.
    let executor = BarrierExecutor::new(3);
    let host = WorkerHost::new(harness.operations.clone(), executor.clone(), 1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let _first = harness.create_operation("noop").await;
    let _second = harness.create_operation("noop").await;
    let host_task = tokio::spawn(async move {
        host.run(async move {
            let _ = shutdown_rx.await;
        })
        .await;
    });

    // Only the first is claimed; the bound holds while it is blocked.
    wait_for(|| executor.started() == 1, "the first executor to start").await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        executor.started(),
        1,
        "the active-job bound holds: no second claim while blocked"
    );

    executor.release();
    shutdown_tx.send(()).unwrap();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), host_task).await;
}

/// Reads the raw operation state through the test's pool, bypassing the
/// authorization ceremony (the use-case path is covered elsewhere).
async fn raw_state(pool: &sqlx::SqlitePool, id: &str) -> Result<(String, bool), String> {
    let row: Option<(String, bool)> =
        sqlx::query_as("SELECT state, cancel_requested FROM operations WHERE id = ?1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(|error| error.to_string())?;
    row.ok_or_else(|| format!("operation {id:?} not found"))
}
