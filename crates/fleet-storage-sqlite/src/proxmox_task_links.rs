//! Durable UPID-to-operation links for the Proxmox task history (FM-609).

use std::collections::HashMap;

use async_trait::async_trait;
use fleet_application::operation::PortFailure;
use fleet_application::proxmox::tasks::ProxmoxTaskLinkPort;
use sqlx::SqlitePool;

/// How long a task link is kept: 90 days. The task history is a "recent
/// tasks" view, and a link older than this mostly names a task PVE no
/// longer lists. A pruned link only drops `fleetOperationId` from that
/// task's row; the operation itself is untouched.
pub const TASK_LINK_RETENTION_MILLIS: i64 = 90 * 24 * 60 * 60 * 1000;

/// The most expired links one `record` deletes. Each new link removes at
/// most this many old ones, so the cleanup cost per write is bounded and
/// the table still shrinks faster than it grows after a backlog.
pub const TASK_LINK_PRUNE_BATCH: i64 = 64;

/// SQLite adapter for the task links.
#[derive(Debug)]
pub struct ProxmoxTaskLinkRepository {
    pool: SqlitePool,
}

impl ProxmoxTaskLinkRepository {
    /// Creates a repository on the controller database.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Deletes at most `limit` links recorded before `cutoff` (epoch
    /// millis), oldest first, and returns how many were deleted. `record`
    /// calls this with the retention window after every committed write;
    /// it is public so a sweeper or a test can drive it directly.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    pub async fn prune_recorded_before(&self, cutoff: i64, limit: i64) -> Result<u64, PortFailure> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(backend)?;
        let deleted = prune(&mut transaction, cutoff, limit).await?;
        transaction.commit().await.map_err(backend)?;
        Ok(deleted)
    }
}

/// The bounded retention delete. The `recorded_at` index (migration 0034)
/// serves the ordered range scan, so a batch never walks the whole table.
async fn prune(
    connection: &mut sqlx::SqliteConnection,
    cutoff: i64,
    limit: i64,
) -> Result<u64, PortFailure> {
    let result = sqlx::query(
        "DELETE FROM proxmox_task_links WHERE rowid IN ( \
             SELECT rowid FROM proxmox_task_links WHERE recorded_at < ?1 \
             ORDER BY recorded_at LIMIT ?2)",
    )
    .bind(cutoff)
    .bind(limit.max(0))
    .execute(connection)
    .await
    .map_err(backend)?;
    Ok(result.rows_affected())
}

#[async_trait]
impl ProxmoxTaskLinkPort for ProxmoxTaskLinkRepository {
    async fn record(
        &self,
        account_id: &str,
        upid: &str,
        operation_id: &str,
    ) -> Result<(), PortFailure> {
        // The first record wins: a UPID is started once, by one operation.
        // Like every write in this crate, it takes the write lock up front
        // so the busy timeout applies under contention.
        let now = fleet_core::SystemClock::now_unix_millis();
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(backend)?;
        sqlx::query(
            "INSERT INTO proxmox_task_links (account_id, upid, operation_id, recorded_at) \
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT (account_id, upid) DO NOTHING",
        )
        .bind(account_id)
        .bind(upid)
        .bind(operation_id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(backend)?;
        transaction.commit().await.map_err(backend)?;
        // Retention rides on the only write path: links only accumulate
        // here, so a bounded batch per record keeps the table bounded
        // without a separate sweeper. It runs after the commit and is
        // best-effort: callers never retry `record`, and the insert is
        // first-wins, so a cleanup failure must not cost the fresh link.
        // The next record retries the cleanup.
        if let Err(error) = self
            .prune_recorded_before(
                now.saturating_sub(TASK_LINK_RETENTION_MILLIS),
                TASK_LINK_PRUNE_BATCH,
            )
            .await
        {
            eprintln!("proxmox: the task link retention cleanup failed: {error}");
        }
        Ok(())
    }

    async fn operations_for(
        &self,
        account_id: &str,
        upids: &[String],
    ) -> Result<HashMap<String, String>, PortFailure> {
        // One statement whatever the page size: the UPIDs travel as one
        // bound JSON array, never as interpolated SQL. The join drops a
        // link whose operation no longer exists, so the history never
        // names an operation that cannot be read (migration 0014 forbids
        // an FK onto `operations`, so the link itself may outlive it).
        let wanted = serde_json::to_string(upids).map_err(|error| PortFailure::Backend {
            detail: format!("the UPID list did not serialize: {error}"),
        })?;
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT links.upid, links.operation_id FROM proxmox_task_links AS links \
             JOIN operations ON operations.id = links.operation_id \
             WHERE links.account_id = ?1 \
             AND links.upid IN (SELECT value FROM json_each(?2))",
        )
        .bind(account_id)
        .bind(wanted)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        let links = rows.into_iter().collect();
        Ok(links)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn backend(error: sqlx::Error) -> PortFailure {
    PortFailure::Backend {
        detail: format!("task link storage failed: {error}"),
    }
}
