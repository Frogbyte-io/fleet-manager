//! The Lab pool repository (FM-717): pools of preallocated guests and their
//! members. Every write that changes a member's binding runs in one
//! `BEGIN IMMEDIATE` transaction, so a claim's read of free members and its
//! binding cannot interleave with another claim; the partial unique index
//! on `lab_pool_members.lease_id` backs the exclusivity in the schema.

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;
use uuid::Uuid;

use fleet_application::lab_pool::{
    ClaimOutcome, DrainReport, FillResult, LabPool, LabPoolPort, MemberRelease, MemberReleased,
    MemberState, NewLabPool, PoolMember, PoolStoreError,
};

/// The pool repository over a store's pool.
#[derive(Debug)]
pub struct LabPoolRepository {
    pool: SqlitePool,
}

impl LabPoolRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn backend(context: &str) -> impl FnOnce(sqlx::Error) -> PoolStoreError + '_ {
    move |error| PoolStoreError::Backend(format!("{context} failed: {error}"))
}

fn row_to_pool(row: &sqlx::sqlite::SqliteRow) -> Result<LabPool, PoolStoreError> {
    Ok(LabPool {
        id: row.get("id"),
        template_version_id: row.get("template_version_id"),
        account_id: row.get("account_id"),
        baseline_snapshot: row.get("baseline_snapshot"),
        size: u32::try_from(row.get::<i64, _>("size"))
            .map_err(|_| PoolStoreError::Backend("the pool size is out of range".to_owned()))?,
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
    })
}

fn row_to_member(row: &sqlx::sqlite::SqliteRow) -> Result<PoolMember, PoolStoreError> {
    let state: String = row.get("state");
    Ok(PoolMember {
        id: row.get("id"),
        pool_id: row.get("pool_id"),
        account_id: row.get("account_id"),
        vmid: u32::try_from(row.get::<i64, _>("vmid"))
            .map_err(|_| PoolStoreError::Backend("the member VMID is out of range".to_owned()))?,
        node: row.get("node"),
        name: row.get("name"),
        state: MemberState::from_id(&state).map_err(PoolStoreError::Backend)?,
        lease_id: row.get("lease_id"),
        draining: row.get::<i64, _>("draining") != 0,
        detail: row.get("detail"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

/// Bounds a recorded detail to the column's limit on a char boundary.
fn bounded(detail: &str) -> String {
    detail.chars().take(1024).collect()
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl LabPoolPort for LabPoolRepository {
    async fn create(
        &self,
        new: &NewLabPool,
        created_by: &str,
        now: i64,
    ) -> Result<LabPool, PoolStoreError> {
        let id = Uuid::now_v7().to_string();
        let result = sqlx::query(
            "INSERT INTO lab_pools (id, template_version_id, account_id, baseline_snapshot, size, created_by, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(&id)
        .bind(&new.template_version_id)
        .bind(&new.account_id)
        .bind(&new.baseline_snapshot)
        .bind(i64::from(new.size))
        .bind(created_by)
        .bind(now)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => self.get(&id).await,
            Err(error) if crate::lab::is_unique_violation(&error) => {
                Err(PoolStoreError::Conflict(format!(
                    "the template version {} already has a pool",
                    new.template_version_id
                )))
            }
            Err(error) => Err(backend("insert pool")(error)),
        }
    }

    async fn get(&self, id: &str) -> Result<LabPool, PoolStoreError> {
        sqlx::query("SELECT * FROM lab_pools WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend("read pool"))?
            .map(|row| row_to_pool(&row))
            .transpose()?
            .ok_or_else(|| PoolStoreError::NotFound(format!("pool {id}")))
    }

    async fn list(&self) -> Result<Vec<LabPool>, PoolStoreError> {
        sqlx::query("SELECT * FROM lab_pools ORDER BY created_at DESC, id DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(backend("list pools"))?
            .iter()
            .map(row_to_pool)
            .collect()
    }

    async fn delete(&self, id: &str) -> Result<(), PoolStoreError> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(backend("begin pool delete"))?;
        let members: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM lab_pool_members WHERE pool_id = ?1")
                .bind(id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(backend("count members"))?;
        if members > 0 {
            return Err(PoolStoreError::Conflict(format!(
                "the pool {id} still holds {members} members; drain it first"
            )));
        }
        let deleted = sqlx::query("DELETE FROM lab_pools WHERE id = ?1")
            .bind(id)
            .execute(&mut *transaction)
            .await
            .map_err(backend("delete pool"))?;
        if deleted.rows_affected() == 0 {
            return Err(PoolStoreError::NotFound(format!("pool {id}")));
        }
        transaction
            .commit()
            .await
            .map_err(backend("commit pool delete"))
    }

    async fn for_template_version(
        &self,
        template_version_id: &str,
    ) -> Result<Option<LabPool>, PoolStoreError> {
        sqlx::query("SELECT * FROM lab_pools WHERE template_version_id = ?1")
            .bind(template_version_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend("read pool"))?
            .map(|row| row_to_pool(&row))
            .transpose()
    }

    async fn members(&self, pool_id: &str) -> Result<Vec<PoolMember>, PoolStoreError> {
        sqlx::query("SELECT * FROM lab_pool_members WHERE pool_id = ?1 ORDER BY vmid")
            .bind(pool_id)
            .fetch_all(&self.pool)
            .await
            .map_err(backend("list members"))?
            .iter()
            .map(row_to_member)
            .collect()
    }

    async fn add_members(
        &self,
        pool_id: &str,
        vmids: &[u32],
        now: i64,
    ) -> Result<Vec<PoolMember>, PoolStoreError> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(backend("begin fill"))?;
        let pool = sqlx::query("SELECT * FROM lab_pools WHERE id = ?1")
            .bind(pool_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(backend("read pool"))?
            .map(|row| row_to_pool(&row))
            .transpose()?
            .ok_or_else(|| PoolStoreError::NotFound(format!("pool {pool_id}")))?;
        // The size is re-checked here, where concurrent fills serialize.
        let held: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM lab_pool_members WHERE pool_id = ?1")
                .bind(pool_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(backend("count members"))?;
        let total = held.saturating_add(i64::try_from(vmids.len()).unwrap_or(i64::MAX));
        if total > i64::from(pool.size) {
            return Err(PoolStoreError::Conflict(format!(
                "the pool holds {held} of {} members; {} more would exceed its size",
                pool.size,
                vmids.len()
            )));
        }
        let mut ids = Vec::with_capacity(vmids.len());
        for vmid in vmids {
            let id = Uuid::now_v7().to_string();
            let inserted = sqlx::query(
                "INSERT INTO lab_pool_members (id, pool_id, account_id, vmid, state, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, 'filling', ?5, ?5)",
            )
            .bind(&id)
            .bind(pool_id)
            .bind(&pool.account_id)
            .bind(i64::from(*vmid))
            .bind(now)
            .execute(&mut *transaction)
            .await;
            match inserted {
                Ok(_) => ids.push(id),
                Err(error) if crate::lab::is_unique_violation(&error) => {
                    return Err(PoolStoreError::Conflict(format!(
                        "VMID {vmid} on account {} is already a pool member",
                        pool.account_id
                    )));
                }
                Err(error) => return Err(backend("insert member")(error)),
            }
        }
        let mut added = Vec::with_capacity(ids.len());
        for id in &ids {
            let row = sqlx::query("SELECT * FROM lab_pool_members WHERE id = ?1")
                .bind(id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(backend("read member"))?;
            added.push(row_to_member(&row)?);
        }
        transaction.commit().await.map_err(backend("commit fill"))?;
        Ok(added)
    }

    async fn finish_fill(
        &self,
        member_id: &str,
        result: &FillResult,
        now: i64,
    ) -> Result<(), PoolStoreError> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(backend("begin fill result"))?;
        let draining: Option<i64> = sqlx::query_scalar(
            "SELECT draining FROM lab_pool_members WHERE id = ?1 AND state = 'filling'",
        )
        .bind(member_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(backend("read member"))?;
        match draining {
            // Another fill already finished it, or a drain removed it.
            None => {}
            Some(1) => {
                sqlx::query("DELETE FROM lab_pool_members WHERE id = ?1")
                    .bind(member_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(backend("remove drained member"))?;
            }
            Some(_) => match result {
                FillResult::Available { node, name } => {
                    sqlx::query(
                        "UPDATE lab_pool_members SET state = 'available', node = ?2, name = ?3, detail = NULL, updated_at = ?4 \
                         WHERE id = ?1 AND state = 'filling'",
                    )
                    .bind(member_id)
                    .bind(node)
                    .bind(name.chars().take(128).collect::<String>())
                    .bind(now)
                    .execute(&mut *transaction)
                    .await
                    .map_err(backend("record fill"))?;
                }
                FillResult::Quarantined { detail } => {
                    sqlx::query(
                        "UPDATE lab_pool_members SET state = 'quarantined', detail = ?2, updated_at = ?3 \
                         WHERE id = ?1 AND state = 'filling'",
                    )
                    .bind(member_id)
                    .bind(bounded(detail))
                    .bind(now)
                    .execute(&mut *transaction)
                    .await
                    .map_err(backend("record fill"))?;
                }
            },
        }
        transaction
            .commit()
            .await
            .map_err(backend("commit fill result"))
    }

    async fn drain(
        &self,
        pool_id: &str,
        vmids: Option<&[u32]>,
        now: i64,
    ) -> Result<DrainReport, PoolStoreError> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(backend("begin drain"))?;
        let exists: Option<String> = sqlx::query_scalar("SELECT id FROM lab_pools WHERE id = ?1")
            .bind(pool_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(backend("read pool"))?;
        if exists.is_none() {
            return Err(PoolStoreError::NotFound(format!("pool {pool_id}")));
        }
        let members =
            sqlx::query("SELECT * FROM lab_pool_members WHERE pool_id = ?1 ORDER BY vmid")
                .bind(pool_id)
                .fetch_all(&mut *transaction)
                .await
                .map_err(backend("list members"))?
                .iter()
                .map(row_to_member)
                .collect::<Result<Vec<_>, _>>()?;
        let selected: Vec<&PoolMember> = match vmids {
            None => members.iter().collect(),
            Some(vmids) => {
                let mut selected = Vec::with_capacity(vmids.len());
                for vmid in vmids {
                    let member = members
                        .iter()
                        .find(|member| member.vmid == *vmid)
                        .ok_or_else(|| {
                            PoolStoreError::NotFound(format!("VMID {vmid} in pool {pool_id}"))
                        })?;
                    selected.push(member);
                }
                selected
            }
        };
        let mut report = DrainReport::default();
        for member in selected {
            // A bound member still owes its lease's cleanup, and a filling
            // one may be mid-revert: both leave when that finishes.
            if member.lease_id.is_some() || member.state == MemberState::Filling {
                sqlx::query(
                    "UPDATE lab_pool_members SET draining = 1, updated_at = ?2 WHERE id = ?1",
                )
                .bind(&member.id)
                .bind(now)
                .execute(&mut *transaction)
                .await
                .map_err(backend("flag member"))?;
                report.deferred.push(member.vmid);
            } else {
                sqlx::query("DELETE FROM lab_pool_members WHERE id = ?1 AND lease_id IS NULL")
                    .bind(&member.id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(backend("remove member"))?;
                report.removed.push(member.vmid);
            }
        }
        transaction
            .commit()
            .await
            .map_err(backend("commit drain"))?;
        Ok(report)
    }

    async fn claim(
        &self,
        pool_id: &str,
        lease_id: &str,
        record_id: &str,
        now: i64,
    ) -> Result<ClaimOutcome, PoolStoreError> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(backend("begin claim"))?;
        let lease = sqlx::query("SELECT state, provision_id FROM lab_leases WHERE id = ?1")
            .bind(lease_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(backend("read lease"))?
            .ok_or_else(|| PoolStoreError::NotFound(format!("lease {lease_id}")))?;
        let lease_state: String = lease.get("state");
        let provision_id: Option<String> = lease.get("provision_id");
        if provision_id.as_deref() != Some(record_id) {
            return Err(PoolStoreError::Conflict(format!(
                "the lease {lease_id} does not name the provision {record_id}"
            )));
        }
        let record = sqlx::query(
            "SELECT lease_id, vmid, account_id, clone_upid, state FROM lab_provisions WHERE id = ?1",
        )
        .bind(record_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(backend("read provision"))?
        .ok_or_else(|| PoolStoreError::NotFound(format!("provision {record_id}")))?;
        if record.get::<Option<String>, _>("lease_id").as_deref() != Some(lease_id) {
            return Err(PoolStoreError::Conflict(format!(
                "the provision {record_id} does not link back to the lease {lease_id}"
            )));
        }
        // Resume: the member already bound to this lease, when its record
        // still names it.
        if let Some(row) = sqlx::query("SELECT * FROM lab_pool_members WHERE lease_id = ?1")
            .bind(lease_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(backend("read bound member"))?
        {
            let member = row_to_member(&row)?;
            let recorded = record
                .get::<Option<i64>, _>("vmid")
                .and_then(|vmid| u32::try_from(vmid).ok());
            // Only a member still leased to this lease resumes: a
            // quarantined one owes a revert and never boots again.
            if member.state != MemberState::Leased
                || member.pool_id != pool_id
                || recorded != Some(member.vmid)
                || record.get::<Option<String>, _>("account_id").as_deref()
                    != Some(member.account_id.as_str())
            {
                return Err(PoolStoreError::Conflict(format!(
                    "the lease {lease_id} holds member {} of pool {}, which its provision record does not name",
                    member.vmid, member.pool_id
                )));
            }
            transaction
                .commit()
                .await
                .map_err(backend("commit claim"))?;
            return Ok(ClaimOutcome::Claimed(member));
        }
        // A new binding only for a lease that is provisioning, and a record
        // that has not taken a guest of its own.
        if lease_state != "provisioning" {
            return Err(PoolStoreError::Conflict(format!(
                "the lease {lease_id} is {lease_state}; only a provisioning lease takes a pool member"
            )));
        }
        if record.get::<String, _>("state") != "provisioning"
            || record.get::<Option<i64>, _>("vmid").is_some()
            || record.get::<Option<String>, _>("clone_upid").is_some()
        {
            return Err(PoolStoreError::Conflict(format!(
                "the provision {record_id} already holds a guest of its own"
            )));
        }
        let Some(row) = sqlx::query(
            "SELECT * FROM lab_pool_members \
             WHERE pool_id = ?1 AND state = 'available' AND lease_id IS NULL AND draining = 0 \
             ORDER BY vmid LIMIT 1",
        )
        .bind(pool_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(backend("read free member"))?
        else {
            return Ok(ClaimOutcome::Exhausted);
        };
        let member = row_to_member(&row)?;
        let node = member.node.clone().ok_or_else(|| {
            PoolStoreError::Backend(format!(
                "the available member {} records no node",
                member.vmid
            ))
        })?;
        let bound = sqlx::query(
            "UPDATE lab_pool_members SET state = 'leased', lease_id = ?2, detail = NULL, updated_at = ?3 \
             WHERE id = ?1 AND state = 'available' AND lease_id IS NULL AND draining = 0",
        )
        .bind(&member.id)
        .bind(lease_id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(backend("bind member"))?;
        if bound.rows_affected() != 1 {
            return Err(PoolStoreError::Conflict(format!(
                "member {} changed during the claim",
                member.vmid
            )));
        }
        let recorded = sqlx::query(
            "UPDATE lab_provisions SET account_id = ?2, node = ?3, vmid = ?4, updated_at = ?5 \
             WHERE id = ?1 AND state = 'provisioning' AND vmid IS NULL AND clone_upid IS NULL",
        )
        .bind(record_id)
        .bind(&member.account_id)
        .bind(&node)
        .bind(i64::from(member.vmid))
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(backend("record member on provision"))?;
        if recorded.rows_affected() != 1 {
            return Err(PoolStoreError::Conflict(format!(
                "the provision {record_id} changed during the claim"
            )));
        }
        let row = sqlx::query("SELECT * FROM lab_pool_members WHERE id = ?1")
            .bind(&member.id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(backend("read member"))?;
        let claimed = row_to_member(&row)?;
        transaction
            .commit()
            .await
            .map_err(backend("commit claim"))?;
        Ok(ClaimOutcome::Claimed(claimed))
    }

    async fn member_for_lease(&self, lease_id: &str) -> Result<Option<PoolMember>, PoolStoreError> {
        sqlx::query("SELECT * FROM lab_pool_members WHERE lease_id = ?1")
            .bind(lease_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend("read bound member"))?
            .map(|row| row_to_member(&row))
            .transpose()
    }

    async fn member_by_vmid(
        &self,
        account_id: &str,
        vmid: u32,
    ) -> Result<Option<PoolMember>, PoolStoreError> {
        sqlx::query("SELECT * FROM lab_pool_members WHERE account_id = ?1 AND vmid = ?2")
            .bind(account_id)
            .bind(i64::from(vmid))
            .fetch_optional(&self.pool)
            .await
            .map_err(backend("read member"))?
            .map(|row| row_to_member(&row))
            .transpose()
    }

    async fn set_member_node(
        &self,
        member_id: &str,
        node: &str,
        now: i64,
    ) -> Result<(), PoolStoreError> {
        sqlx::query("UPDATE lab_pool_members SET node = ?2, updated_at = ?3 WHERE id = ?1")
            .bind(member_id)
            .bind(node)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(backend("record member node"))
            .map(|_| ())
    }

    async fn quarantine_bound(
        &self,
        lease_id: &str,
        detail: &str,
        now: i64,
    ) -> Result<(), PoolStoreError> {
        sqlx::query(
            "UPDATE lab_pool_members SET state = 'quarantined', detail = ?2, updated_at = ?3 \
             WHERE lease_id = ?1",
        )
        .bind(lease_id)
        .bind(bounded(detail))
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(backend("quarantine member"))
        .map(|_| ())
    }

    async fn release_lease(
        &self,
        lease_id: &str,
        how: &MemberRelease,
        now: i64,
    ) -> Result<MemberReleased, PoolStoreError> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(backend("begin pooled release"))?;
        let member = sqlx::query("SELECT * FROM lab_pool_members WHERE lease_id = ?1")
            .bind(lease_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(backend("read bound member"))?
            .map(|row| row_to_member(&row))
            .transpose()?
            .ok_or_else(|| {
                PoolStoreError::Conflict(format!("the lease {lease_id} holds no pool member"))
            })?;
        let released = sqlx::query(
            "UPDATE lab_leases SET state = 'released', cleanup_next_at = NULL \
             WHERE id = ?1 AND state = 'releasing'",
        )
        .bind(lease_id)
        .execute(&mut *transaction)
        .await
        .map_err(backend("release lease"))?;
        if released.rows_affected() != 1 {
            return Err(PoolStoreError::Conflict(format!(
                "the lease {lease_id} is no longer releasing"
            )));
        }
        let outcome = if member.draining {
            sqlx::query("DELETE FROM lab_pool_members WHERE id = ?1")
                .bind(&member.id)
                .execute(&mut *transaction)
                .await
                .map_err(backend("remove drained member"))?;
            MemberReleased::Removed
        } else {
            match how {
                MemberRelease::Return => {
                    sqlx::query(
                        "UPDATE lab_pool_members SET state = 'available', lease_id = NULL, detail = NULL, updated_at = ?2 \
                         WHERE id = ?1",
                    )
                    .bind(&member.id)
                    .bind(now)
                    .execute(&mut *transaction)
                    .await
                    .map_err(backend("return member"))?;
                    MemberReleased::Returned
                }
                MemberRelease::Keep => {
                    sqlx::query(
                        "UPDATE lab_pool_members SET state = 'quarantined', lease_id = NULL, detail = ?2, updated_at = ?3 \
                         WHERE id = ?1",
                    )
                    .bind(&member.id)
                    .bind(bounded(&format!(
                        "kept by lease {lease_id}; drain it, then fill it again once it is back at its baseline"
                    )))
                    .bind(now)
                    .execute(&mut *transaction)
                    .await
                    .map_err(backend("quarantine kept member"))?;
                    MemberReleased::Quarantined
                }
            }
        };
        transaction
            .commit()
            .await
            .map_err(backend("commit pooled release"))?;
        Ok(outcome)
    }
}
