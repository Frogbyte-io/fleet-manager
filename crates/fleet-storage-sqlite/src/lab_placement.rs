//! The Lab capacity repository (FM-715): node capacity observations and
//! per-lease capacity reservations. The capacity rule itself is the
//! application's [`check_capacity`]; this adapter runs it inside one
//! `BEGIN IMMEDIATE` transaction, so the read of live reservations and the
//! insert cannot interleave with another reservation.

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;
use uuid::Uuid;

use fleet_application::lab_placement::{
    CapacityDemand, CapacityReservation, CapacityReservationPort, ImageStoragePort,
    PlacementPolicy, ReservationRequest, ReservationState, ReserveOutcome, ReservedTotals,
    check_capacity,
};
use fleet_application::proxmox::{ProxmoxNodeCapacity, ProxmoxStorageCapacity};

/// The capacity repository over a pool.
#[derive(Debug)]
pub struct CapacityRepository {
    pool: SqlitePool,
}

impl CapacityRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_reservation(row: &sqlx::sqlite::SqliteRow) -> Result<CapacityReservation, String> {
        let state: String = row.get("state");
        let state = match state.as_str() {
            "held" => ReservationState::Held,
            "released" => ReservationState::Released,
            other => return Err(format!("unknown reservation state {other:?}")),
        };
        let count = |column: &str| {
            u32::try_from(row.get::<i64, _>(column))
                .map_err(|_| format!("the reservation's {column} is out of range"))
        };
        Ok(CapacityReservation {
            id: row.get("id"),
            lease_id: row.get("lease_id"),
            account_id: row.get("account_id"),
            node: row.get("node"),
            demand: CapacityDemand {
                cores: count("cores")?,
                memory_mib: count("memory_mib")?,
                disk_gib: count("disk_gib")?,
                storage: row.get("storage"),
            },
            state,
            created_at: row.get("created_at"),
            released_at: row.get("released_at"),
        })
    }
}

/// The stored storage-capacity shape (camelCase JSON, like the API).
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredStorage {
    storage: String,
    used_bytes: u64,
    total_bytes: u64,
}

/// Converts an observed figure for storage. A figure SQLite cannot hold is
/// an error, never a clamped value: clamping would fabricate free capacity.
fn to_i64(value: Option<u64>, figure: &str) -> Result<Option<i64>, String> {
    value
        .map(|value| {
            i64::try_from(value)
                .map_err(|_| format!("the observation's {figure} ({value}) is out of range"))
        })
        .transpose()
}

fn to_u64(value: Option<i64>) -> Option<u64> {
    value.and_then(|value| u64::try_from(value).ok())
}

fn row_to_observation(row: &sqlx::sqlite::SqliteRow) -> Result<ProxmoxNodeCapacity, String> {
    let storages: Vec<StoredStorage> = serde_json::from_str(&row.get::<String, _>("storages_json"))
        .map_err(|error| format!("decode storages failed: {error}"))?;
    Ok(ProxmoxNodeCapacity {
        node: row.get("node"),
        cpu_usage_ratio: None,
        cpu_count: to_u64(row.get("cpu_count")),
        memory_used_bytes: to_u64(row.get("memory_used_bytes")),
        memory_total_bytes: to_u64(row.get("memory_total_bytes")),
        storages: storages
            .into_iter()
            .map(|storage| ProxmoxStorageCapacity {
                storage: storage.storage,
                used_bytes: storage.used_bytes,
                total_bytes: storage.total_bytes,
            })
            .collect(),
        observed_at: row.get("observed_at"),
    })
}

/// Sums the node's held reservations whose leases still count.
async fn held_totals(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    node: &str,
    storage: &str,
) -> Result<ReservedTotals, String> {
    // Held reservations count per node across every account: two
    // clusters with the same node name share the count, which is
    // conservative, never permissive. The lease's state is
    // authoritative: a held row whose lease is released, or failed
    // without an allocated VMID, no longer counts, even if its own
    // release write was lost.
    let totals = sqlx::query(
        "SELECT COALESCE(SUM(r.cores), 0) AS cores, COALESCE(SUM(r.memory_mib), 0) AS memory_mib, \
         COALESCE(SUM(CASE WHEN r.storage = ?2 THEN r.disk_gib ELSE 0 END), 0) AS disk_gib \
         FROM lab_capacity_reservations r \
         JOIN lab_leases l ON l.id = r.lease_id \
         LEFT JOIN lab_provisions p ON p.id = l.provision_id \
         WHERE r.node = ?1 AND r.state = 'held' AND l.state != 'released' \
         AND NOT (l.state = 'failed' AND p.vmid IS NULL)",
    )
    .bind(node)
    .bind(storage)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| format!("read held reservations failed: {error}"))?;
    // A negative sum cannot come from the CHECKed rows; if it does, the
    // reservation errors rather than counting it as nothing reserved.
    let sum = |column: &str| {
        to_u64(Some(totals.get(column)))
            .ok_or_else(|| format!("the held reservations' {column} total is out of range"))
    };
    Ok(ReservedTotals {
        cores: sum("cores")?,
        memory_mib: sum("memory_mib")?,
        disk_gib: sum("disk_gib")?,
    })
}

/// Whether a reservation of `lease_id` counts, the rule the held totals
/// apply: the lease exists, is not `released`, and has not `failed` without
/// an allocated VMID.
async fn lease_counts(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    lease_id: &str,
) -> Result<bool, String> {
    Ok(sqlx::query_scalar(
        "SELECT l.state != 'released' AND NOT (l.state = 'failed' AND p.vmid IS NULL) \
         FROM lab_leases l LEFT JOIN lab_provisions p ON p.id = l.provision_id \
         WHERE l.id = ?1",
    )
    .bind(lease_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| format!("read the reservation's lease failed: {error}"))?
    .unwrap_or(false))
}

/// Releases `existing` when its lease no longer counts (released, or failed
/// without an allocated VMID), the same rule the held totals apply, and
/// answers whether it did.
async fn release_if_finished(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    existing: &CapacityReservation,
    now: i64,
) -> Result<bool, String> {
    if lease_counts(transaction, &existing.lease_id).await? {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE lab_capacity_reservations SET state = 'released', released_at = ?2 \
         WHERE id = ?1 AND state = 'held'",
    )
    .bind(&existing.id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| format!("release the stale reservation failed: {error}"))?;
    Ok(true)
}

#[async_trait]
impl CapacityReservationPort for CapacityRepository {
    async fn record_observation(
        &self,
        account_id: &str,
        observation: &ProxmoxNodeCapacity,
    ) -> Result<(), String> {
        let storages = serde_json::to_string(
            &observation
                .storages
                .iter()
                .map(|storage| StoredStorage {
                    storage: storage.storage.clone(),
                    used_bytes: storage.used_bytes,
                    total_bytes: storage.total_bytes,
                })
                .collect::<Vec<_>>(),
        )
        .map_err(|error| format!("encode storages failed: {error}"))?;
        sqlx::query(
            "INSERT INTO lab_capacity_observations \
             (account_id, node, cpu_count, memory_total_bytes, memory_used_bytes, storages_json, observed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT (account_id, node) DO UPDATE SET \
             cpu_count = excluded.cpu_count, memory_total_bytes = excluded.memory_total_bytes, \
             memory_used_bytes = excluded.memory_used_bytes, storages_json = excluded.storages_json, \
             observed_at = excluded.observed_at \
             WHERE excluded.observed_at >= lab_capacity_observations.observed_at",
        )
        .bind(account_id)
        .bind(&observation.node)
        .bind(to_i64(observation.cpu_count, "CPU count")?)
        .bind(to_i64(observation.memory_total_bytes, "total memory")?)
        .bind(to_i64(observation.memory_used_bytes, "used memory")?)
        .bind(storages)
        .bind(observation.observed_at)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("record capacity observation failed: {error}"))?;
        Ok(())
    }

    async fn reserve(
        &self,
        request: &ReservationRequest,
        policy: &PlacementPolicy,
        now: i64,
    ) -> Result<ReserveOutcome, String> {
        // One immediate transaction: the capacity read and the insert
        // cannot interleave with another reservation.
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| format!("begin reservation transaction failed: {error}"))?;
        if let Some(existing) =
            sqlx::query("SELECT * FROM lab_capacity_reservations WHERE lease_id = ?1")
                .bind(&request.lease_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|error| format!("read reservation failed: {error}"))?
        {
            let existing = Self::row_to_reservation(&existing)?;
            if existing.state == ReservationState::Released {
                return Err(format!(
                    "the capacity reservation of lease {} was already released",
                    request.lease_id
                ));
            }
            // The same eligibility rule the totals apply: a held row whose
            // lease is released, or failed without an allocated VMID, is a
            // lost release write, not a reservation. It is released here, in
            // this transaction, and the request errors like one for an
            // already released row; a finished lease is never re-reserved.
            if !release_if_finished(&mut transaction, &existing, now).await? {
                // Nothing changed: the row still counts for a live lease.
                return Ok(ReserveOutcome::Reserved(existing));
            }
            transaction
                .commit()
                .await
                .map_err(|error| format!("commit reservation transaction failed: {error}"))?;
            return Err(format!(
                "the capacity reservation of lease {} belonged to a finished lease and was released",
                request.lease_id
            ));
        }
        // A finished lease gets no new reservation: the totals would not
        // count it, so it would hold capacity no later request sees.
        if !lease_counts(&mut transaction, &request.lease_id).await? {
            return Err(format!(
                "lease {} is finished or unknown; it reserves no capacity",
                request.lease_id
            ));
        }
        let observation = sqlx::query(
            "SELECT * FROM lab_capacity_observations WHERE account_id = ?1 AND node = ?2",
        )
        .bind(&request.account_id)
        .bind(&request.node)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| format!("read capacity observation failed: {error}"))?
        .map(|row| row_to_observation(&row))
        .transpose()?;
        let reserved =
            held_totals(&mut transaction, &request.node, &request.demand.storage).await?;
        if let Err(refusal) = check_capacity(
            &request.node,
            observation.as_ref(),
            reserved,
            &request.demand,
            policy,
            now,
        ) {
            return Ok(ReserveOutcome::Refused(refusal));
        }
        let id = Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO lab_capacity_reservations \
             (id, lease_id, account_id, node, storage, cores, memory_mib, disk_gib, state, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'held', ?9)",
        )
        .bind(&id)
        .bind(&request.lease_id)
        .bind(&request.account_id)
        .bind(&request.node)
        .bind(&request.demand.storage)
        .bind(i64::from(request.demand.cores))
        .bind(i64::from(request.demand.memory_mib))
        .bind(i64::from(request.demand.disk_gib))
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("insert reservation failed: {error}"))?;
        transaction
            .commit()
            .await
            .map_err(|error| format!("commit reservation transaction failed: {error}"))?;
        Ok(ReserveOutcome::Reserved(CapacityReservation {
            id,
            lease_id: request.lease_id.clone(),
            account_id: request.account_id.clone(),
            node: request.node.clone(),
            demand: request.demand.clone(),
            state: ReservationState::Held,
            created_at: now,
            released_at: None,
        }))
    }

    async fn release_for_lease(&self, lease_id: &str, now: i64) -> Result<bool, String> {
        let result = sqlx::query(
            "UPDATE lab_capacity_reservations SET state = 'released', released_at = ?2 \
             WHERE lease_id = ?1 AND state = 'held'",
        )
        .bind(lease_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("release reservation failed: {error}"))?;
        Ok(result.rows_affected() > 0)
    }

    async fn for_lease(&self, lease_id: &str) -> Result<Option<CapacityReservation>, String> {
        sqlx::query("SELECT * FROM lab_capacity_reservations WHERE lease_id = ?1")
            .bind(lease_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("read reservation failed: {error}"))?
            .map(|row| Self::row_to_reservation(&row))
            .transpose()
    }
}

#[async_trait]
impl ImageStoragePort for CapacityRepository {
    async fn template_storage(&self, image_version_id: &str) -> Result<Option<String>, String> {
        // The pool of the build Lab clones: the promotion's pinned build
        // (issue #281), else, for a version promoted before pins existed,
        // its newest successful build. A build from before first-class
        // records falls back to the version's declared pool.
        let pinned: Option<String> = sqlx::query_scalar(
            "SELECT b.storage_pool FROM image_recipe_versions v \
             JOIN image_build_records b ON b.id = v.promoted_build_id WHERE v.id = ?1",
        )
        .bind(image_version_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| format!("read pinned build storage pool failed: {error}"))?;
        if pinned.is_some() {
            return Ok(pinned);
        }
        let built: Option<String> = sqlx::query_scalar(
            "SELECT storage_pool FROM image_build_records WHERE version_id = ?1 \
             AND outcome = 'succeeded' ORDER BY started_at DESC, id DESC LIMIT 1",
        )
        .bind(image_version_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| format!("read build storage pool failed: {error}"))?;
        if built.is_some() {
            return Ok(built);
        }
        sqlx::query_scalar("SELECT storage_pool FROM image_recipe_versions WHERE id = ?1")
            .bind(image_version_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("read version storage pool failed: {error}"))
    }
}
