//! Durable UPID-to-operation links for the Proxmox task history (FM-609).

use std::collections::HashMap;

use async_trait::async_trait;
use fleet_application::operation::PortFailure;
use fleet_application::proxmox::tasks::ProxmoxTaskLinkPort;
use sqlx::SqlitePool;

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
        sqlx::query(
            "INSERT INTO proxmox_task_links (account_id, upid, operation_id, recorded_at) \
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT (account_id, upid) DO NOTHING",
        )
        .bind(account_id)
        .bind(upid)
        .bind(operation_id)
        .bind(fleet_core::SystemClock::now_unix_millis())
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn operations_for(
        &self,
        account_id: &str,
        upids: &[String],
    ) -> Result<HashMap<String, String>, PortFailure> {
        // One statement whatever the page size: the UPIDs travel as one
        // bound JSON array, never as interpolated SQL.
        let wanted = serde_json::to_string(upids).map_err(|error| PortFailure::Backend {
            detail: format!("the UPID list did not serialize: {error}"),
        })?;
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT upid, operation_id FROM proxmox_task_links \
             WHERE account_id = ?1 AND upid IN (SELECT value FROM json_each(?2))",
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
