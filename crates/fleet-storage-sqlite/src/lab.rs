//! The Lab repository: the SQLite implementation of the application's
//! [`LabTemplatePort`] and [`ProvisionPort`] (FM-710).

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;
use uuid::Uuid;

use fleet_application::lab::{
    LabTemplate, LabTemplateContent, LabTemplatePort, LabTemplateVersion, Lease, LeasePort,
    NewLabTemplate, NewLease, NewProvision, ProvisionPort, ProvisionRecord,
};
use fleet_core::{CleanupStrategy, GuestState, LeaseState, ReadinessProbe};

/// The Lab repository over a pool.
#[derive(Debug)]
pub struct LabRepository {
    pool: SqlitePool,
}

impl LabRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn content_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<LabTemplateContent, String> {
        let probe: String = row.get("readiness_probe");
        let cleanup: String = row.get("cleanup");
        Ok(LabTemplateContent {
            name: row.get("name"),
            description: row.get("description"),
            image_version_id: row.get("image_version_id"),
            cores: u32::try_from(row.get::<i64, _>("cores")).unwrap_or(1),
            memory_mib: u32::try_from(row.get::<i64, _>("memory_mib")).unwrap_or(1),
            disk_gib: u32::try_from(row.get::<i64, _>("disk_gib")).unwrap_or(1),
            bootstrap_project_id: row.get("bootstrap_project_id"),
            readiness_probe: ReadinessProbe::from_id(&probe)?,
            readiness_command: row.get("readiness_command"),
            readiness_deadline_seconds: u32::try_from(
                row.get::<i64, _>("readiness_deadline_seconds"),
            )
            .unwrap_or(1),
            ttl_seconds: u32::try_from(row.get::<i64, _>("ttl_seconds")).unwrap_or(1),
            cleanup: CleanupStrategy::from_id(&cleanup)?,
        })
    }

    fn row_to_template(row: &sqlx::sqlite::SqliteRow) -> Result<LabTemplate, String> {
        Ok(LabTemplate {
            id: row.get("id"),
            content: Self::content_from_row(row)?,
            published_from: row.get("published_from"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    fn row_to_version(row: &sqlx::sqlite::SqliteRow) -> Result<LabTemplateVersion, String> {
        let content_text: String = row.get("content");
        Ok(LabTemplateVersion {
            id: row.get("id"),
            template_id: row.get("template_id"),
            name: row.get("name"),
            content: serde_json::from_str(&content_text)
                .map_err(|error| format!("the version content is not JSON: {error}"))?,
            image_digest: row.get("image_digest"),
            published_by: row.get("published_by"),
            published_at: row.get("published_at"),
        })
    }

    fn row_to_provision(row: &sqlx::sqlite::SqliteRow) -> Result<ProvisionRecord, String> {
        let state: String = row.get("state");
        Ok(ProvisionRecord {
            id: row.get("id"),
            template_version_id: row.get("template_version_id"),
            lease_id: row.get("lease_id"),
            state: GuestState::from_id(&state)?,
            node: row.get("node"),
            vmid: row
                .get::<Option<i64>, _>("vmid")
                .and_then(|value| u32::try_from(value).ok()),
            clone_upid: row.get("clone_upid"),
            guest_ipv4: row.get("guest_ipv4"),
            ready_at: row.get("ready_at"),
            idempotency_key: row.get("idempotency_key"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
}
#[async_trait]
impl LabTemplatePort for LabRepository {
    async fn create(&self, template: &NewLabTemplate, now: i64) -> Result<LabTemplate, String> {
        let id = Uuid::now_v7().to_string();
        let content = &template.content;
        let result = sqlx::query(
            "INSERT INTO lab_templates (id, name, description, image_version_id, cores, memory_mib, disk_gib, bootstrap_project_id, readiness_probe, readiness_command, readiness_deadline_seconds, ttl_seconds, cleanup, published_from, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL, ?14, ?14)",
        )
        .bind(&id)
        .bind(&content.name)
        .bind(&content.description)
        .bind(&content.image_version_id)
        .bind(i64::from(content.cores))
        .bind(i64::from(content.memory_mib))
        .bind(i64::from(content.disk_gib))
        .bind(&content.bootstrap_project_id)
        .bind(content.readiness_probe.id())
        .bind(&content.readiness_command)
        .bind(i64::from(content.readiness_deadline_seconds))
        .bind(i64::from(content.ttl_seconds))
        .bind(content.cleanup.id())
        .bind(now)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => <Self as LabTemplatePort>::get(self, &id).await,
            Err(error) if is_unique_violation(&error) => Err(format!(
                "the template name {:?} is already taken",
                content.name
            )),
            Err(error) => Err(format!("create failed: {error}")),
        }
    }

    async fn get(&self, id: &str) -> Result<LabTemplate, String> {
        sqlx::query("SELECT * FROM lab_templates WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("get failed: {error}"))?
            .map(|row| Self::row_to_template(&row))
            .transpose()?
            .ok_or_else(|| format!("template {id} not found"))
    }

    async fn list(&self) -> Result<Vec<LabTemplate>, String> {
        let rows = sqlx::query("SELECT * FROM lab_templates ORDER BY updated_at DESC, id DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|error| format!("list failed: {error}"))?;
        rows.iter().map(Self::row_to_template).collect()
    }

    async fn update(
        &self,
        id: &str,
        content: &LabTemplateContent,
        now: i64,
    ) -> Result<LabTemplate, String> {
        let updated = sqlx::query(
            "UPDATE lab_templates SET name = ?2, description = ?3, image_version_id = ?4, cores = ?5, memory_mib = ?6, disk_gib = ?7, bootstrap_project_id = ?8, readiness_probe = ?9, readiness_command = ?10, readiness_deadline_seconds = ?11, ttl_seconds = ?12, cleanup = ?13, updated_at = ?14 WHERE id = ?1",
        )
        .bind(id)
        .bind(&content.name)
        .bind(&content.description)
        .bind(&content.image_version_id)
        .bind(i64::from(content.cores))
        .bind(i64::from(content.memory_mib))
        .bind(i64::from(content.disk_gib))
        .bind(&content.bootstrap_project_id)
        .bind(content.readiness_probe.id())
        .bind(&content.readiness_command)
        .bind(i64::from(content.readiness_deadline_seconds))
        .bind(i64::from(content.ttl_seconds))
        .bind(content.cleanup.id())
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("update failed: {error}"))?;
        if updated.rows_affected() == 0 {
            return Err(format!("template {id} not found"));
        }
        <Self as LabTemplatePort>::get(self, id).await
    }

    async fn delete(&self, id: &str) -> Result<(), String> {
        let result = sqlx::query("DELETE FROM lab_templates WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|error| format!("delete failed: {error}"))?;
        if result.rows_affected() == 0 {
            return Err(format!("template {id} not found"));
        }
        Ok(())
    }

    async fn publish(
        &self,
        template_id: &str,
        version: &LabTemplateVersion,
    ) -> Result<LabTemplateVersion, String> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| format!("publish failed: {error}"))?;
        let pointer = sqlx::query("UPDATE lab_templates SET published_from = ?2 WHERE id = ?1")
            .bind(template_id)
            .bind(&version.id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| format!("publish failed: {error}"))?;
        if pointer.rows_affected() == 0 {
            return Err(format!("template {template_id} not found"));
        }
        let content_text = serde_json::to_string(&version.content)
            .map_err(|error| format!("the version content cannot be serialized: {error}"))?;
        let inserted = sqlx::query(
            "INSERT INTO lab_template_versions (id, template_id, name, content, image_digest, published_by, published_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&version.id)
        .bind(&version.template_id)
        .bind(&version.name)
        .bind(&content_text)
        .bind(&version.image_digest)
        .bind(&version.published_by)
        .bind(version.published_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("publish failed: {error}"))?;
        transaction
            .commit()
            .await
            .map_err(|error| format!("publish failed: {error}"))?;
        if inserted.rows_affected() == 0 {
            // An exact retry: return the stored version, which is the
            // idempotent answer.
            return self.get_version(&version.id).await;
        }
        Ok(version.clone())
    }

    async fn get_version(&self, id: &str) -> Result<LabTemplateVersion, String> {
        sqlx::query("SELECT * FROM lab_template_versions WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("get_version failed: {error}"))?
            .map(|row| Self::row_to_version(&row))
            .transpose()?
            .ok_or_else(|| format!("version {id} not found"))
    }
}

#[async_trait]
impl ProvisionPort for LabRepository {
    async fn create(&self, new: &NewProvision, now: i64) -> Result<ProvisionRecord, String> {
        let id = Uuid::now_v7().to_string();
        let result = sqlx::query(
            "INSERT INTO lab_provisions (id, template_version_id, state, idempotency_key, created_at, updated_at, lease_id) \
             VALUES (?1, ?2, 'provisioning', ?3, ?4, ?4, ?5)",
        )
        .bind(&id)
        .bind(&new.template_version_id)
        .bind(&new.idempotency_key)
        .bind(now)
        .bind(&new.lease_id)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => <Self as ProvisionPort>::get(self, &id).await,
            Err(error) if is_unique_violation(&error) => {
                // A concurrent retry with the same key: return the winner's
                // record, which is the idempotent answer.
                let key = new
                    .idempotency_key
                    .clone()
                    .ok_or_else(|| format!("create failed: {error}"))?;
                <Self as ProvisionPort>::find_by_idempotency_key(self, &key)
                    .await?
                    .ok_or_else(|| format!("create failed: {error}"))
            }
            Err(error) => Err(format!("create failed: {error}")),
        }
    }

    async fn find_by_idempotency_key(
        &self,
        key: &str,
    ) -> Result<Option<fleet_application::lab::ProvisionRecord>, String> {
        sqlx::query("SELECT * FROM lab_provisions WHERE idempotency_key = ?1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("find_by_idempotency_key failed: {error}"))?
            .map(|row| Self::row_to_provision(&row))
            .transpose()
    }

    async fn get(&self, id: &str) -> Result<ProvisionRecord, String> {
        sqlx::query("SELECT * FROM lab_provisions WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("get failed: {error}"))?
            .map(|row| Self::row_to_provision(&row))
            .transpose()?
            .ok_or_else(|| format!("provision {id} not found"))
    }

    async fn update(&self, record: &ProvisionRecord) -> Result<(), String> {
        sqlx::query(
            "UPDATE lab_provisions SET state = ?2, node = ?3, vmid = ?4, clone_upid = ?5, guest_ipv4 = ?6, ready_at = ?7, updated_at = ?8 WHERE id = ?1",
        )
        .bind(&record.id)
        .bind(record.state.id())
        .bind(&record.node)
        .bind(record.vmid.map(i64::from))
        .bind(&record.clone_upid)
        .bind(&record.guest_ipv4)
        .bind(record.ready_at)
        .bind(fleet_core::SystemClock::now_unix_millis())
        .execute(&self.pool)
        .await
        .map_err(|error| format!("update failed: {error}"))?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<ProvisionRecord>, String> {
        let rows = sqlx::query("SELECT * FROM lab_provisions ORDER BY created_at DESC, id DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|error| format!("list failed: {error}"))?;
        rows.iter().map(Self::row_to_provision).collect()
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error
            .as_database_error()
            .map(sqlx::error::DatabaseError::kind),
        Some(sqlx::error::ErrorKind::UniqueViolation)
    )
}

/// The lease repository: the SQLite implementation of the application's
/// [`LeasePort`](fleet_application::lab::LeasePort).
#[derive(Debug)]
pub struct LeaseRepository {
    pool: SqlitePool,
}

impl LeaseRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_lease(row: &sqlx::sqlite::SqliteRow) -> Result<Lease, String> {
        let state: String = row.get("state");
        let cleanup: String = row.get("cleanup");
        let created_at: i64 = row.get("created_at");
        let max_lifetime_at = row
            .try_get::<Option<i64>, _>("max_lifetime_at")
            .map_err(|error| format!("lease maximum lifetime is unreadable: {error}"))?
            .unwrap_or_else(|| {
                created_at.saturating_add(fleet_core::MAX_LAB_LEASE_LIFETIME_MILLIS)
            });
        Ok(Lease {
            id: row.get("id"),
            template_version_id: row.get("template_version_id"),
            owner: row.get("owner"),
            purpose: row.get("purpose"),
            project_id: row.get("project_id"),
            state: LeaseState::from_id(&state)?,
            provision_id: row.get("provision_id"),
            cleanup: CleanupStrategy::from_id(&cleanup)?,
            created_at,
            max_lifetime_at,
            ttl_seconds: u32::try_from(row.get::<i64, _>("ttl_seconds")).unwrap_or(0),
            ready_at: row.get("ready_at"),
            expires_at: row.get("expires_at"),
            cleanup_attempts: u32::try_from(row.get::<i64, _>("cleanup_attempts")).unwrap_or(0),
        })
    }
}

#[async_trait]
impl LeasePort for LeaseRepository {
    async fn create(&self, lease: &NewLease, owner: &str, now: i64) -> Result<Lease, String> {
        let id = Uuid::now_v7().to_string();
        let max_lifetime_at = now
            .checked_add(fleet_core::MAX_LAB_LEASE_LIFETIME_MILLIS)
            .ok_or_else(|| {
                "the lease creation time exceeds the maximum lifetime range".to_owned()
            })?;
        sqlx::query(
            "INSERT INTO lab_leases (id, template_version_id, owner, purpose, project_id, state, cleanup, created_at, max_lifetime_at, ttl_seconds) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'requested', ?6, ?7, ?8, ?9)",
        )
        .bind(&id)
        .bind(&lease.template_version_id)
        .bind(owner)
        .bind(&lease.purpose)
        .bind(&lease.project_id)
        .bind(lease.cleanup.id())
        .bind(now)
        .bind(max_lifetime_at)
        .bind(i64::from(lease.ttl_seconds))
        .execute(&self.pool)
        .await
        .map_err(|error| format!("create failed: {error}"))?;
        <Self as fleet_application::lab::LeasePort>::get(self, &id).await
    }

    async fn get(&self, id: &str) -> Result<Lease, String> {
        sqlx::query("SELECT * FROM lab_leases WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("get failed: {error}"))?
            .map(|row| Self::row_to_lease(&row))
            .transpose()?
            .ok_or_else(|| format!("lease {id} not found"))
    }

    async fn update(&self, lease: &Lease) -> Result<(), String> {
        let updated = sqlx::query(
            "UPDATE lab_leases SET state = ?2, provision_id = ?3, ready_at = ?4, expires_at = ?5, cleanup_attempts = ?6 WHERE id = ?1",
        )
        .bind(&lease.id)
        .bind(lease.state.id())
        .bind(&lease.provision_id)
        .bind(lease.ready_at)
        .bind(lease.expires_at)
        .bind(i64::from(lease.cleanup_attempts))
        .execute(&self.pool)
        .await
        .map_err(|error| format!("update failed: {error}"))?;
        if updated.rows_affected() == 0 {
            return Err(format!("lease {} not found", lease.id));
        }
        Ok(())
    }

    async fn list(&self) -> Result<Vec<Lease>, String> {
        let rows = sqlx::query("SELECT * FROM lab_leases ORDER BY created_at DESC, id DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|error| format!("list failed: {error}"))?;
        rows.iter().map(Self::row_to_lease).collect()
    }

    async fn expired(&self, now: i64) -> Result<Vec<Lease>, String> {
        let rows = sqlx::query(
            "SELECT * FROM lab_leases WHERE state = 'ready' AND expires_at IS NOT NULL AND expires_at <= ?1",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("expired failed: {error}"))?;
        rows.iter().map(Self::row_to_lease).collect()
    }

    async fn extend_ready(
        &self,
        id: &str,
        observed_expires_at: i64,
        now: i64,
        new_expires_at: i64,
    ) -> Result<bool, String> {
        let updated = sqlx::query(
            "UPDATE lab_leases SET expires_at = ?4 \
             WHERE id = ?1 AND state = 'ready' AND expires_at = ?2 \
             AND expires_at > ?3 \
             AND ?4 <= COALESCE(max_lifetime_at, created_at + ?5)",
        )
        .bind(id)
        .bind(observed_expires_at)
        .bind(now)
        .bind(new_expires_at)
        .bind(fleet_core::MAX_LAB_LEASE_LIFETIME_MILLIS)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("extend failed: {error}"))?;
        Ok(updated.rows_affected() == 1)
    }

    async fn attach_provision(&self, id: &str, provision_id: &str) -> Result<bool, String> {
        let updated = sqlx::query(
            "UPDATE lab_leases SET state = 'provisioning', provision_id = ?2 \
             WHERE id = ?1 AND state = 'requested' AND provision_id IS NULL",
        )
        .bind(id)
        .bind(provision_id)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("attach provision failed: {error}"))?;
        if updated.rows_affected() == 1 {
            return Ok(true);
        }
        let current = sqlx::query("SELECT state, provision_id FROM lab_leases WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("read linked provision failed: {error}"))?;
        Ok(current.is_some_and(|row| {
            row.get::<String, _>("state") == "provisioning"
                && row.get::<Option<String>, _>("provision_id").as_deref() == Some(provision_id)
        }))
    }

    async fn mark_ready(
        &self,
        id: &str,
        provision_id: &str,
        ready_at: i64,
        expires_at: i64,
    ) -> Result<bool, String> {
        let updated = sqlx::query(
            "UPDATE lab_leases SET state = 'ready', ready_at = ?3, expires_at = ?4 \
             WHERE id = ?1 AND state = 'provisioning' AND provision_id = ?2 \
             AND expires_at IS NULL AND ready_at IS NULL \
             AND ?4 <= COALESCE(max_lifetime_at, created_at + ?5)",
        )
        .bind(id)
        .bind(provision_id)
        .bind(ready_at)
        .bind(expires_at)
        .bind(fleet_core::MAX_LAB_LEASE_LIFETIME_MILLIS)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("mark ready failed: {error}"))?;
        if updated.rows_affected() == 1 {
            return Ok(true);
        }
        let current = Self::row_to_lease(
            &sqlx::query("SELECT * FROM lab_leases WHERE id = ?1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| format!("read ready lease failed: {error}"))?
                .ok_or_else(|| format!("lease {id} not found"))?,
        )?;
        Ok(current.state == LeaseState::Ready
            && current.provision_id.as_deref() == Some(provision_id))
    }

    async fn claim_for_release(
        &self,
        id: &str,
        observed: LeaseState,
        observed_expires_at: i64,
        now: i64,
    ) -> Result<bool, String> {
        // Compare both state and deadline so a stale expiry scan cannot
        // release a lease whose TTL was extended before this claim.
        let claimed = sqlx::query(
            "UPDATE lab_leases SET state = 'releasing' \
             WHERE id = ?1 AND state = ?2 AND expires_at = ?3 AND expires_at <= ?4",
        )
        .bind(id)
        .bind(observed.id())
        .bind(observed_expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("claim failed: {error}"))?;
        Ok(claimed.rows_affected() == 1)
    }
}
