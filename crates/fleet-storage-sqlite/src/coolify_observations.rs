//! The Coolify observation repository: the SQLite implementation of the
//! application's [`CoolifyObservationPort`] (FM-1030).

use async_trait::async_trait;
use fleet_application::coolify::{CoolifyObservationPort, CoolifySnapshot};
use sqlx::Row as _;
use sqlx::SqlitePool;

/// The most snapshot JSON bytes stored per account.
const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;

/// The Coolify observation repository over a pool.
#[derive(Debug)]
pub struct CoolifyObservationRepository {
    pool: SqlitePool,
}

impl CoolifyObservationRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CoolifyObservationPort for CoolifyObservationRepository {
    async fn load(&self, account_id: &str) -> Result<Option<(CoolifySnapshot, i64)>, String> {
        let row = sqlx::query(
            "SELECT snapshot, recorded_at FROM coolify_observations WHERE account_id = ?1",
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| format!("load failed: {error}"))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let json: String = row.get("snapshot");
        // An unreadable snapshot (a future shape) reads as none rather than
        // failing the account; the next discovery replaces it.
        Ok(serde_json::from_str::<CoolifySnapshot>(&json)
            .ok()
            .map(|snapshot| (snapshot, row.get("recorded_at"))))
    }

    async fn save(
        &self,
        account_id: &str,
        snapshot: &CoolifySnapshot,
        recorded_at: i64,
    ) -> Result<(), String> {
        let json = serde_json::to_string(snapshot)
            .map_err(|error| format!("snapshot encode failed: {error}"))?;
        if json.len() > MAX_SNAPSHOT_BYTES {
            return Err("the discovery snapshot is larger than the storage limit".to_owned());
        }
        sqlx::query(
            "INSERT INTO coolify_observations (account_id, snapshot, recorded_at) VALUES (?1, ?2, ?3) \
             ON CONFLICT(account_id) DO UPDATE SET snapshot = excluded.snapshot, recorded_at = excluded.recorded_at",
        )
        .bind(account_id)
        .bind(json)
        .bind(recorded_at)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("save failed: {error}"))?;
        Ok(())
    }
}
