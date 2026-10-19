//! The SQLite implementation of the application's [`BuildAddressPort`]
//! (#337): Fleet-assigned image build addresses, allocated in one
//! `BEGIN IMMEDIATE` transaction.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use async_trait::async_trait;
use fleet_application::images::{
    BUILD_ADDRESS_QUARANTINE_MILLIS, BuildAddressError, BuildAddressPort, BuildAddressRecord,
    BuildAddressStatus, ClearQuarantine,
};
use fleet_core::BuildAddressPool;
use sqlx::Row as _;
use sqlx::SqlitePool;

/// Releases held rows whose operation is not live (terminal or unknown): they
/// no longer count. The holder died without releasing, so nothing says its VM
/// is gone, and the address is quarantined. `?1` is the release time, `?2`
/// the end of the quarantine.
const RELEASE_STALE: &str = "UPDATE image_build_addresses \
     SET state = 'released', released_at = ?1, hold_until = ?2 \
     WHERE state = 'held' AND NOT EXISTS (SELECT 1 FROM operations o \
     WHERE o.id = image_build_addresses.operation_id \
     AND o.state IN ('pending', 'running', 'cancelling'))";

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
            .bind(now_millis + BUILD_ADDRESS_QUARANTINE_MILLIS)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;

        // A repeat of the same request returns what the operation holds.
        let own: Vec<Ipv4Addr> = sqlx::query(
            "SELECT address FROM image_build_addresses \
             WHERE operation_id = ?1 AND state = 'held' ORDER BY slot",
        )
        .bind(operation_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(storage)?
        .iter()
        .filter_map(|row| row.get::<String, _>("address").parse().ok())
        .collect();
        if own.len() == count && own.iter().all(|a| pool.contains(*a)) {
            tx.commit().await.map_err(storage)?;
            return Ok(own);
        }
        // Anything else it held (another count, or a pool that changed) is
        // let go, with quarantine: an earlier attempt may have started a
        // guest on it.
        sqlx::query(
            "UPDATE image_build_addresses \
             SET state = 'released', released_at = ?2, hold_until = ?3 \
             WHERE operation_id = ?1 AND state = 'held'",
        )
        .bind(operation_id)
        .bind(now_millis)
        .bind(now_millis + BUILD_ADDRESS_QUARANTINE_MILLIS)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        let first_slot: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(slot) + 1, 0) FROM image_build_addresses WHERE operation_id = ?1",
        )
        .bind(operation_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage)?;

        // Unavailable: held now, or quarantined until a later time.
        let unavailable: HashSet<Ipv4Addr> = sqlx::query(
            "SELECT DISTINCT address FROM image_build_addresses \
             WHERE state = 'held' OR hold_until > ?1",
        )
        .bind(now_millis)
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
        let mut free: Vec<Ipv4Addr> = pool
            .candidates()
            .filter(|a| !unavailable.contains(a))
            .collect();
        if free.len() < count {
            // The reclaim above is real whatever this request gets: keep it,
            // so the quarantine of a dead holder starts when it was noticed.
            tx.commit().await.map_err(storage)?;
            return Err(BuildAddressError::Exhausted);
        }
        // Never-used first, then the longest since release, then by address.
        free.sort_by_key(|a| (released.get(a).copied().unwrap_or(i64::MIN), u32::from(*a)));
        free.truncate(count);
        for (offset, address) in free.iter().enumerate() {
            sqlx::query(
                "INSERT INTO image_build_addresses \
                 (operation_id, slot, address, state, created_at) VALUES (?1, ?2, ?3, 'held', ?4)",
            )
            .bind(operation_id)
            .bind(first_slot + i64::try_from(offset).map_err(storage)?)
            .bind(address.to_string())
            .bind(now_millis)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        }
        tx.commit().await.map_err(storage)?;
        Ok(free)
    }

    async fn release(
        &self,
        operation_id: &str,
        now_millis: i64,
        quarantine: bool,
    ) -> Result<usize, String> {
        let done = sqlx::query(
            "UPDATE image_build_addresses \
             SET state = 'released', released_at = ?2, hold_until = ?3 \
             WHERE operation_id = ?1 AND state = 'held'",
        )
        .bind(operation_id)
        .bind(now_millis)
        .bind(quarantine.then_some(now_millis + BUILD_ADDRESS_QUARANTINE_MILLIS))
        .execute(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        usize::try_from(done.rows_affected()).map_err(|e| e.to_string())
    }

    async fn reconcile(&self, now_millis: i64) -> Result<usize, String> {
        let done = sqlx::query(RELEASE_STALE)
            .bind(now_millis)
            .bind(now_millis + BUILD_ADDRESS_QUARANTINE_MILLIS)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        usize::try_from(done.rows_affected()).map_err(|e| e.to_string())
    }

    async fn list_unavailable(&self, now_millis: i64) -> Result<Vec<BuildAddressRecord>, String> {
        // A held row whose operation is not live is reported as quarantined,
        // as the next allocation or startup would make it (RELEASE_STALE).
        let rows = sqlx::query(
            "SELECT address, operation_id, state, created_at, released_at, hold_until, \
             EXISTS (SELECT 1 FROM operations o WHERE o.id = image_build_addresses.operation_id \
             AND o.state IN ('pending', 'running', 'cancelling')) AS live \
             FROM image_build_addresses \
             WHERE state = 'held' OR hold_until > ?1 \
             ORDER BY state, hold_until DESC, created_at DESC",
        )
        .bind(now_millis)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        let mut seen = HashSet::new();
        let mut records = Vec::new();
        for row in &rows {
            let Ok(address) = row.get::<String, _>("address").parse::<Ipv4Addr>() else {
                continue;
            };
            let held = row.get::<String, _>("state") == "held";
            let live = row.get::<i64, _>("live") != 0;
            // A live hold wins over an older quarantine of the same address.
            if held && live {
                if !seen.insert(address) {
                    continue;
                }
                records.push(BuildAddressRecord {
                    address,
                    status: BuildAddressStatus::Held,
                    operation_id: row.get("operation_id"),
                    since: row.get("created_at"),
                    until: None,
                });
                continue;
            }
            if !seen.insert(address) {
                continue;
            }
            let (since, until) = if held {
                (
                    now_millis,
                    Some(now_millis + BUILD_ADDRESS_QUARANTINE_MILLIS),
                )
            } else {
                (
                    row.get::<Option<i64>, _>("released_at").unwrap_or_default(),
                    row.get("hold_until"),
                )
            };
            records.push(BuildAddressRecord {
                address,
                status: BuildAddressStatus::Quarantined,
                operation_id: row.get("operation_id"),
                since,
                until,
            });
        }
        records.sort_by_key(|record| u32::from(record.address));
        Ok(records)
    }

    async fn clear_quarantine(
        &self,
        address: Ipv4Addr,
        now_millis: i64,
    ) -> Result<ClearQuarantine, String> {
        let text = address.to_string();
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| e.to_string())?;
        sqlx::query(RELEASE_STALE)
            .bind(now_millis)
            .bind(now_millis + BUILD_ADDRESS_QUARANTINE_MILLIS)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        let held: Option<String> = sqlx::query_scalar(
            "SELECT operation_id FROM image_build_addresses \
             WHERE address = ?1 AND state = 'held'",
        )
        .bind(&text)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        let outcome = if let Some(operation_id) = held {
            ClearQuarantine::Held { operation_id }
        } else {
            let holder: Option<String> = sqlx::query_scalar(
                "SELECT operation_id FROM image_build_addresses \
                 WHERE address = ?1 AND state = 'released' AND hold_until > ?2 \
                 ORDER BY hold_until DESC LIMIT 1",
            )
            .bind(&text)
            .bind(now_millis)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
            match holder {
                Some(operation_id) => {
                    sqlx::query(
                        "UPDATE image_build_addresses SET hold_until = NULL \
                         WHERE address = ?1 AND state = 'released' AND hold_until > ?2",
                    )
                    .bind(&text)
                    .bind(now_millis)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                    ClearQuarantine::Cleared { operation_id }
                }
                None => ClearQuarantine::NotQuarantined,
            }
        };
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(outcome)
    }
}
