//! The operation worker: claim, execute, and resolve durable operations.
//!
//! The tick below is the whole execution model: recover what a crashed
//! worker left behind, time out what passed its deadline, claim one pending
//! operation with a compare-and-set, and drive it to a terminal state. One
//! tick touches at most one claimed operation, so a tick is the unit of
//! crash recovery — a controller that dies mid-tick leaves the operation
//! claimed with a stale lease, and a later tick resolves it honestly as
//! failed ("the worker died; the result is unknown") rather than retrying
//! work whose side effects may already have happened.
//!
//! That is the retry policy in one sentence: **nothing auto-retries.** An
//! operation that failed, was cancelled, or expired stays terminal; a caller
//! who wants the work done creates a new operation. Auto-retry belongs to
//! the work classification work that lands with real providers, where each
//! step can be proven idempotent.
//!
//! The Effectum evaluation behind this design is recorded in
//! `docs/planning/spikes.md` (FM-S03): Effectum's own database and job
//! records would duplicate the operation lifecycle across two schemas with
//! no shared transaction, so the purpose-built loop over the existing table
//! won.
#![warn(missing_docs)]

use std::sync::Arc;

use async_trait::async_trait;

use crate::operation::{Operation, Operations};

/// Executes one claimed operation to a terminal state. The executor never
/// authorizes and never audits; it does the work and reports failure, and the
/// tick records the outcome.
#[async_trait]
pub trait OperationExecutor: fmt::Debug + Send + Sync {
    /// Drives `operation` to a terminal state through the service.
    ///
    /// # Errors
    ///
    /// Returns a caller-safe failure detail; the tick turns it into the
    /// operation's terminal error.
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String>;
}

/// The M1 executor: the `noop` kind does bounded, observable no work —
/// progress goes to complete and the operation succeeds. It exists so the
/// durable path is exercised end to end before any provider has work to do.
#[derive(Debug)]
pub struct NoopExecutor;

#[async_trait]
impl OperationExecutor for NoopExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        operations
            .record_progress(&operation.id, Some(1), Some(1), Some("noop complete"))
            .await
            .map_err(|error| error.to_string())?;
        operations
            .complete(
                &operation.id,
                "succeeded",
                Some("{\"kind\":\"noop\"}"),
                None,
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

use std::fmt;

/// What one tick did, for logs and for tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TickReport {
    /// Operations resolved as failed because their worker's lease expired.
    pub recovered: usize,
    /// Operations that passed their deadline and were timed out.
    pub timed_out: usize,
    /// Whether a pending operation was claimed this tick.
    pub claimed: bool,
    /// Whether the claimed operation reached a terminal state this tick.
    pub completed: bool,
    /// Queue depths observed after the work.
    pub pending: i64,
    /// Running operations observed after the work.
    pub running: i64,
}

impl Operations {
    /// Records progress on an operation without authorization: the worker is
    /// trusted infrastructure acting on operations callers already created.
    ///
    /// # Errors
    ///
    /// Fails when the port refuses.
    pub async fn record_progress(
        &self,
        id: &str,
        current: Option<i64>,
        total: Option<i64>,
        message: Option<&str>,
    ) -> Result<(), crate::operation::OperationUseCaseError> {
        self.port
            .record_progress(id, current, total, message)
            .await
            .map_err(|failure| crate::operation::OperationUseCaseError::Backend {
                context: "record_progress",
                detail: failure.to_string(),
            })
    }

    /// Runs one worker tick.
    ///
    /// # Errors
    ///
    /// Backend failures bubble up so the host can log them; the queue's
    /// state stays consistent because every step is a transaction.
    pub async fn tick(
        &self,
        executor: &dyn OperationExecutor,
        worker_id: &str,
        now: i64,
        lease_ms: i64,
    ) -> Result<TickReport, String> {
        let mut report = TickReport::default();

        // 1. Resolve claims whose worker died. The result is unknown, so the
        //    operation fails instead of being retried.
        let expired = self
            .port
            .expired_claims(now, lease_ms)
            .await
            .map_err(|failure| failure.to_string())?;
        for operation in expired {
            let detail = format!(
                "worker lease expired; the result of {kind} work is unknown",
                kind = operation.kind
            );
            let error_json =
                serde_json::json!({ "reason": "worker_lease_expired", "detail": detail })
                    .to_string();
            if self
                .complete(&operation.id, "failed", None, Some(&error_json))
                .await
                .is_ok()
            {
                report.recovered += 1;
            }
        }

        // 2. Time out what passed its deadline.
        for id in self
            .port
            .sweep_deadlines(now)
            .await
            .map_err(|failure| failure.to_string())?
        {
            if self.complete(&id, "timed_out", None, None).await.is_ok() {
                report.timed_out += 1;
            }
        }

        // 3. Claim and execute one pending operation.
        if let Some(claimed) = self
            .port
            .claim_pending(worker_id, now)
            .await
            .map_err(|failure| failure.to_string())?
        {
            report.claimed = true;
            let completed = if claimed.cancel_requested {
                // The machine routes a running operation through `cancelling`
                // on its way out; the request was already durable.
                let cancelling = self
                    .port
                    .transition(&claimed.id, "cancelling")
                    .await
                    .is_ok();
                cancelling
                    && self
                        .complete(&claimed.id, "cancelled", None, None)
                        .await
                        .is_ok()
            } else {
                match executor.execute(self, &claimed).await {
                    Ok(()) => true,
                    Err(detail) => self
                        .complete(
                            &claimed.id,
                            "failed",
                            None,
                            Some(
                                &serde_json::json!({ "reason": "step_failed", "detail": detail })
                                    .to_string(),
                            ),
                        )
                        .await
                        .is_ok(),
                }
            };
            report.completed = completed;
        }

        // 4. Make the queue depth visible.
        let depths = self
            .port
            .queue_depths()
            .await
            .map_err(|failure| failure.to_string())?;
        report.pending = depths.pending;
        report.running = depths.running;
        Ok(report)
    }
}

/// Convenience constructor: a worker over the service with the noop executor.
#[must_use]
pub fn noop_executor() -> Arc<dyn OperationExecutor> {
    Arc::new(NoopExecutor)
}
