//! The controller's operation-worker host.
//!
//! The worker loop owns no policy: each tick asks the application what to do
//! (see `fleet_application::worker`), logs the queue's depth so saturation is
//! visible, and stops draining cleanly when shutdown fires. The tick interval
//! is deliberately short — a tick on an empty queue is a handful of indexed
//! queries.

use std::sync::Arc;
use std::time::Duration;

use fleet_application::operation::Operations;
use fleet_application::worker::{TickReport, noop_executor};

/// How long a worker's claim stays believable without a heartbeat. The M1
/// worker heartbeats by completing work; the lease exists so a crashed
/// controller's claims are recognized by age, not by trust.
pub const LEASE_MS: i64 = 60_000;

/// The interval between ticks.
pub const TICK: Duration = Duration::from_millis(250);

/// Runs the worker loop until `shutdown` completes, then returns. Each tick
/// claims at most one operation, so shutdown never waits on long work.
pub async fn run(
    operations: Arc<Operations>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) {
    let executor = noop_executor();
    let worker_id = format!("controller-{}", uuid::Uuid::now_v7());
    eprintln!("operation worker {worker_id} started (tick {TICK:?}, lease {LEASE_MS}ms)");

    let mut interval = tokio::time::interval(TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let shutdown = std::pin::pin!(shutdown);
    let mut shutdown = shutdown;

    loop {
        tokio::select! {
            () = &mut shutdown => {
                eprintln!("operation worker draining");
                break;
            }
            _ = interval.tick() => {
                let now = fleet_core::SystemClock::now_unix_millis();
                match operations.tick(&*executor, &worker_id, now, LEASE_MS).await {
                    Ok(report) => log_tick(&report),
                    Err(error) => eprintln!("operation worker tick failed: {error}"),
                }
            }
        }
    }
    eprintln!("operation worker stopped");
}

fn log_tick(report: &TickReport) {
    if *report != TickReport::default() {
        eprintln!(
            "operation queue: pending={} running={} recovered={} timed_out={} claimed={} completed={}",
            report.pending,
            report.running,
            report.recovered,
            report.timed_out,
            report.claimed,
            report.completed
        );
    }
}
