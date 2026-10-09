//! The detached Lab command repository (#394): the SQLite implementation of
//! the application's [`DetachedExecPort`]. Metadata only: the command text
//! is never stored, just its digest and size.

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;

use fleet_application::lab_exec_detach::{DetachedExec, DetachedExecPort, StartState};

/// The repository over a pool.
#[derive(Debug)]
pub struct DetachedExecRepository {
    pool: SqlitePool,
}

impl DetachedExecRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn row_to_record(row: &sqlx::sqlite::SqliteRow) -> Result<DetachedExec, String> {
    let start_state: String = row.get("start_state");
    let unsigned = |column: &str| {
        u64::try_from(row.get::<i64, _>(column))
            .map_err(|_| format!("a detached exec {column} is negative"))
    };
    Ok(DetachedExec {
        handle: row.get("handle"),
        lease_id: row.get("lease_id"),
        owner: row.get("owner"),
        command_sha256: row.get("command_sha256"),
        command_bytes: unsigned("command_bytes")?,
        timeout_seconds: unsigned("timeout_seconds")?,
        start_state: StartState::from_id(&start_state)?,
        created_at: row.get("created_at"),
        started_at: row.get("started_at"),
        final_json: row.get("final_json"),
    })
}

#[async_trait]
impl DetachedExecPort for DetachedExecRepository {
    async fn insert_if_absent(&self, record: &DetachedExec) -> Result<bool, String> {
        let bytes = i64::try_from(record.command_bytes)
            .map_err(|_| "the command size does not fit the store".to_owned())?;
        let timeout = i64::try_from(record.timeout_seconds)
            .map_err(|_| "the timeout does not fit the store".to_owned())?;
        let result = sqlx::query(
            "INSERT OR IGNORE INTO lab_detached_execs \
             (handle, lease_id, owner, command_sha256, command_bytes, timeout_seconds, start_state, created_at, started_at, final_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(&record.handle)
        .bind(&record.lease_id)
        .bind(&record.owner)
        .bind(&record.command_sha256)
        .bind(bytes)
        .bind(timeout)
        .bind(record.start_state.id())
        .bind(record.created_at)
        .bind(record.started_at)
        .bind(&record.final_json)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("detached exec insert failed: {error}"))?;
        Ok(result.rows_affected() == 1)
    }

    async fn get(&self, handle: &str) -> Result<Option<DetachedExec>, String> {
        sqlx::query("SELECT * FROM lab_detached_execs WHERE handle = ?1")
            .bind(handle)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("detached exec read failed: {error}"))?
            .map(|row| row_to_record(&row))
            .transpose()
    }

    async fn set_final(&self, handle: &str, final_json: &str) -> Result<(), String> {
        sqlx::query("UPDATE lab_detached_execs SET final_json = ?2 WHERE handle = ?1 AND final_json IS NULL")
            .bind(handle)
            .bind(final_json)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|error| format!("detached exec update failed: {error}"))
    }

    async fn set_start_state(
        &self,
        handle: &str,
        state: StartState,
        started_at: Option<i64>,
    ) -> Result<(), String> {
        sqlx::query(
            "UPDATE lab_detached_execs SET start_state = ?2, started_at = COALESCE(?3, started_at) WHERE handle = ?1",
        )
        .bind(handle)
        .bind(state.id())
        .bind(started_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("detached exec update failed: {error}"))
    }
}
