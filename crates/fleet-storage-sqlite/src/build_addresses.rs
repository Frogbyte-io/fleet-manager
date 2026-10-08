//! The SQLite implementation of the application's [`BuildAddressPort`]
//! (#337): Fleet-assigned image build addresses, allocated in one
//! `BEGIN IMMEDIATE` transaction.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use async_trait::async_trait;
use fleet_application::images::{BuildAddressError, BuildAddressPort};
use fleet_core::BuildAddressPool;
use sqlx::Row as _;
use sqlx::SqlitePool;

/// Releases held rows whose operation is terminal or unknown: they no longer
/// count. `?1` is the release time.
const RELEASE_STALE: &str = "UPDATE image_build_addresses SET state = 'released', released_at = ?1 \
     WHERE state = 'held' AND NOT EXISTS (SELECT 1 FROM operations o \
     WHERE o.id = image_build_addresses.operation_id \
     AND o.state NOT IN ('succeeded', 'failed', 'cancelled', 'timed_out'))";

/// The build address repository over a pool.
#[derive(Debug)]
pub struct BuildAddressRepository {
    pool: SqlitePool,
}

impl BuildAddressRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn storage(error: impl std::fmt::Display) -> BuildAddressError {
    BuildAddressError::Storage(error.to_string())
}

#[async_trait]
impl BuildAddressPort for BuildAddressRepository {
    async fn allocate(
        &self,
        operation_id: &str,
        pool: &BuildAddressPool,
        count: usize,
        now_millis: i64,
    ) -> Result<Vec<Ipv4Addr>, BuildAddressError> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(storage)?;
        sqlx::query(RELEASE_STALE)
            .bind(now_millis)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;

        // A repeat of the same request returns what the operation holds.
        let own: Vec<String> = sqlx::query(
            "SELECT address FROM image_build_addresses \
             WHERE operation_id = ?1 AND state = 'held' ORDER BY slot",
        )
        .bind(operation_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(storage)?
        .iter()
        .map(|row| row.get("address"))
        .collect();
        let own: Vec<Ipv4Addr> = own.iter().filter_map(|a| a.parse().ok()).collect();
        if own.len() == count && own.iter().all(|a| pool.contains(*a)) {
            tx.commit().await.map_err(storage)?;
            return Ok(own);
        }
        // Anything else it held (another count, or a pool that changed) goes.
        sqlx::query("DELETE FROM image_build_addresses WHERE operation_id = ?1")
            .bind(operation_id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;

        let held: HashSet<Ipv4Addr> =
            sqlx::query("SELECT address FROM image_build_addresses WHERE state = 'held'")
                .fetch_all(&mut *tx)
                .await
                .map_err(storage)?
                .iter()
                .filter_map(|row| row.get::<String, _>("address").parse().ok())
                .collect();
        let released: HashMap<Ipv4Addr, i64> = sqlx::query(
            "SELECT address, MAX(released_at) AS at FROM image_build_addresses \
             WHERE state = 'released' GROUP BY address",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(storage)?
        .iter()
        .filter_map(|row| {
            Some((
                row.get::<String, _>("address").parse().ok()?,
                row.get::<i64, _>("at"),
            ))
        })
        .collect();
        let mut free: Vec<Ipv4Addr> = pool.candidates().filter(|a| !held.contains(a)).collect();
        if free.len() < count {
            return Err(BuildAddressError::Exhausted);
        }
        // Never-used first, then the longest since release, then by address.
        free.sort_by_key(|a| (released.get(a).copied().unwrap_or(i64::MIN), u32::from(*a)));
        free.truncate(count);
        for (slot, address) in free.iter().enumerate() {
            sqlx::query(
                "INSERT INTO image_build_addresses \
                 (operation_id, slot, address, state, created_at) VALUES (?1, ?2, ?3, 'held', ?4)",
            )
            .bind(operation_id)
            .bind(i64::try_from(slot).map_err(storage)?)
            .bind(address.to_string())
            .bind(now_millis)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        }
        tx.commit().await.map_err(storage)?;
        Ok(free)
    }

    async fn release(&self, operation_id: &str, now_millis: i64) -> Result<usize, String> {
        let done = sqlx::query(
            "UPDATE image_build_addresses SET state = 'released', released_at = ?2 \
             WHERE operation_id = ?1 AND state = 'held'",
        )
        .bind(operation_id)
        .bind(now_millis)
        .execute(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        usize::try_from(done.rows_affected()).map_err(|e| e.to_string())
    }

    async fn reconcile(&self, now_millis: i64) -> Result<usize, String> {
        let done = sqlx::query(RELEASE_STALE)
            .bind(now_millis)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        usize::try_from(done.rows_affected()).map_err(|e| e.to_string())
    }
}
