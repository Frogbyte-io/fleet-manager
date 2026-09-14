//! The operation worker host: maintenance, claiming, and bounded tracked
//! execution.
//!
//! The loop separates the queue's maintenance (recovery sweeps, deadline
//! sweeps, queue depths — FM-109) from the execution of claimed work. Each
//! claimed operation runs in a tracked task that renews its lease on a
//! heartbeat, so the recovery sweep never resolves legitimately running
//! work. On shutdown the host stops claiming, requests durable
//! cancellation through the store for every in-flight operation, and waits
//! a bounded grace for the tracked tasks; work that ignores cancellation
//! is left to the lease recovery, and its outcome stays truthful. An
//! active-job bound keeps the host from claiming work it cannot run.
//!
//! Cancellation semantics are unchanged and remain honest: on drain, the
//! host requests cancellation through the durable `request_cancel` path and
//! waits a bounded grace; remote work that does not observe it is left
//! running, its terminal state resolved by the lease recovery — never
//! reported as "stopped".
//!
//! Nothing auto-retries: a task that dies with its worker is recovered by
//! lease expiry exactly as before.
//!
//! Barrier-controlled tests (`worker_lifecycle.rs`) prove the
//! responsiveness and draining properties rather than sleeping through
//! them.

use std::collections::HashMap;
use std::sync::Arc;

use fleet_application::operation::Operations;
use fleet_application::worker::TickReport;

/// The loop tick: maintenance and claiming cadence.
pub const TICK: std::time::Duration = std::time::Duration::from_millis(250);
/// The claim lease. A running task renews at a third of this interval; if
/// the host dies, the sweep resolves the work honestly after expiry.
pub const LEASE_MS: i64 = 60_000;
/// The default active-job bound. Matches the SSH limiter's default: the
/// worker claims no more work than it can run.
pub const DEFAULT_MAX_ACTIVE: usize = 4;
/// The bounded grace a draining host gives in-flight work after requesting
/// cancellation. Remote work still running after the grace is left to the
/// lease recovery, and its outcome stays truthful.
pub const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(120);

/// The worker host over one controller's operations.
pub struct WorkerHost {
    operations: Arc<Operations>,
    executor: Arc<dyn fleet_application::worker::OperationExecutor>,
    worker_id: String,
    lease_ms: i64,
    max_active: usize,
    drain_grace: std::time::Duration,
}

impl std::fmt::Debug for WorkerHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerHost")
            .field("worker_id", &self.worker_id)
            .field("lease_ms", &self.lease_ms)
            .field("max_active", &self.max_active)
            .finish()
    }
}

impl WorkerHost {
    /// Composes the host. `max_active` bounds how many claimed operations
    /// execute concurrently.
    #[must_use]
    pub fn new(
        operations: Arc<Operations>,
        executor: Arc<dyn fleet_application::worker::OperationExecutor>,
        max_active: usize,
    ) -> Self {
        Self {
            operations,
            executor,
            worker_id: format!("controller-{}", uuid::Uuid::now_v7()),
            lease_ms: LEASE_MS,
            max_active: max_active.max(1),
            drain_grace: DRAIN_GRACE,
        }
    }

    /// Overrides the drain grace. Tests shorten it so the bounded-exit
    /// behavior is proven without waiting the production interval.
    #[must_use]
    pub fn with_drain_grace(mut self, grace: std::time::Duration) -> Self {
        self.drain_grace = grace;
        self
    }

    /// Overrides the claim lease. Tests shorten it so the heartbeat/recovery
    /// interaction is proven in seconds instead of minutes.
    #[must_use]
    pub fn with_lease_ms(mut self, lease_ms: i64) -> Self {
        self.lease_ms = lease_ms;
        self
    }

    /// Runs the host until `shutdown` completes, then drains: no new claims,
    /// cancellation requested on in-flight work, bounded wait, exit.
    pub async fn run(&self, shutdown: impl std::future::Future<Output = ()> + Send) {
        eprintln!(
            "operation worker {} started (tick {TICK:?}, lease {}ms, max active {})",
            self.worker_id, self.lease_ms, self.max_active
        );
        let mut interval = tokio::time::interval(TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(shutdown);

        // The tracked in-flight tasks: the operation id → the real spawned
        // task (heartbeat + executor run together). The drain iterates the
        // ids for durable cancellation and aborts the handles when the
        // grace expires.
        let mut in_flight: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
        let permits = Arc::new(tokio::sync::Semaphore::new(self.max_active));
        let mut shutting_down = false;
        // One absolute drain deadline, computed when shutdown begins: the
        // documented bound covers the whole drain, not each joined task.
        let mut drain_deadline: Option<tokio::time::Instant> = None;

        loop {
            // Reap finished tasks so the map tracks reality.
            in_flight.retain(|_, handle| !handle.is_finished());

            if shutting_down {
                if in_flight.is_empty() {
                    eprintln!("operation worker drained");
                    break;
                }
                let deadline = drain_deadline
                    .unwrap_or_else(|| tokio::time::Instant::now() + self.drain_grace);
                if tokio::time::Instant::now() >= deadline {
                    eprintln!(
                        "operation drain grace expired; aborting in-flight tasks — \
                         the lease recovery resolves their truth"
                    );
                    for handle in in_flight.values() {
                        handle.abort();
                    }
                    while !in_flight.is_empty() {
                        for handle in in_flight.values_mut() {
                            let _ = handle.await;
                        }
                        in_flight.retain(|_, handle| !handle.is_finished());
                    }
                    eprintln!("operation worker drained after grace");
                    break;
                }
                // Wait out the grace while reaping any task that finishes.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }

            // Maintenance + claim cadence, raced against shutdown so neither
            // is dropped while work claims.
            tokio::select! {
                () = &mut shutdown => {
                    shutting_down = true;
                    eprintln!("operation worker draining; cancelling in-flight work");
                    for id in in_flight.keys() {
                        let _ = self
                            .operations
                            .cancel(
                                &fleet_auth::LanAllowAllAuthorizer,
                                fleet_auth::LAN_PRINCIPAL_ID,
                                id,
                            )
                            .await;
                    }
                    drain_deadline = Some(tokio::time::Instant::now() + self.drain_grace);
                }
                _ = interval.tick() => {
                    let now = fleet_core::SystemClock::now_unix_millis();
                    let mut report = match self.operations.maintain(now, self.lease_ms).await {
                        Ok(report) => report,
                        Err(error) => {
                            eprintln!("operation worker maintenance failed: {error}");
                            continue;
                        }
                    };
                    // Claim only while there is capacity.
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        continue;
                    };
                    match self
                        .operations
                        .claim_only(&self.worker_id, now, &mut report)
                        .await
                    {
                        Ok(Some(claimed)) => {
                            let operations = self.operations.clone();
                            let executor = self.executor.clone();
                            let worker_id = self.worker_id.clone();
                            let lease_ms = self.lease_ms;
                            let operation_id = claimed.id.clone();
                            let task = tokio::spawn(async move {
                                let _permit = permit;
                                run_with_heartbeat(
                                    operations,
                                    executor,
                                    worker_id,
                                    lease_ms,
                                    claimed,
                                )
                                .await;
                            });
                            in_flight.insert(operation_id, task);
                        }
                        Ok(None) => {}
                        Err(error) => eprintln!("operation worker claim failed: {error}"),
                    }
                    log_tick(&report);
                }
            }
        }
        eprintln!("operation worker stopped");
    }
}

/// Runs one claimed operation to its terminal state: renews the lease on a
/// heartbeat while the executor runs, and completes through the same path
/// `tick` has always used.
async fn run_with_heartbeat(
    operations: Arc<Operations>,
    executor: Arc<dyn fleet_application::worker::OperationExecutor>,
    worker_id: String,
    lease_ms: i64,
    claimed: fleet_application::operation::Operation,
) {
    let operation_id = claimed.id.clone();
    let heartbeat_id = operation_id.clone();
    let heartbeat_worker = worker_id.clone();
    let heartbeat_operations = operations.clone();
    let heartbeat = tokio::spawn(async move {
        // A third of the lease, floored at 100 ms: the heartbeat must fire
        // comfortably inside the lease window, including short test leases.
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(
            u64::try_from((lease_ms / 3).max(100)).unwrap_or(100),
        ));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let now = fleet_core::SystemClock::now_unix_millis();
            match heartbeat_operations
                .renew_lease(&heartbeat_id, &heartbeat_worker, now, lease_ms)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    // The claim was recovered or resolved out from under the
                    // task; stop renewing. The executor's completion path
                    // will lose its terminal write and the state stays
                    // truthful to whichever side won.
                    eprintln!("operation lease lost: {heartbeat_id}");
                    return;
                }
                Err(error) => eprintln!("lease renewal failed: {error}"),
            }
        }
    });

    let completed = operations.execute_claimed(&*executor, claimed).await;
    heartbeat.abort();
    let _ = heartbeat.await;
    if !completed {
        eprintln!("operation task did not reach a terminal state: {operation_id}");
    }
}

fn log_tick(report: &TickReport) {
    if *report != TickReport::default() {
        eprintln!(
            "operation queue: pending={} running={} recovered={} timed_out={} claimed={}",
            report.pending, report.running, report.recovered, report.timed_out, report.claimed
        );
    }
}

/// Composes the worker host for the controller binary and tests.
#[must_use]
pub fn worker_host(
    operations: Arc<Operations>,
    executor: Arc<dyn fleet_application::worker::OperationExecutor>,
    max_active: usize,
) -> WorkerHost {
    WorkerHost::new(operations, executor, max_active)
}
