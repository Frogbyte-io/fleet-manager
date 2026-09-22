//! The Lab repository: the SQLite implementation of the application's
//! [`LabTemplatePort`] and [`ProvisionPort`] (FM-710).

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;
use uuid::Uuid;

use fleet_application::lab::{
    LabTemplate, LabTemplateContent, LabTemplatePort, LabTemplateVersion, NewLabTemplate,
    NewProvision, ProvisionPort, ProvisionRecord,
};
use fleet_core::{CleanupStrategy, GuestState, ReadinessProbe};

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
            state: GuestState::from_id(&state)?,
            node: row.get("node"),
            vmid: row
                .get::<Option<i64>, _>("vmid")
                .and_then(|value| u32::try_from(value).ok()),
            clone_upid: row.get("clone_upid"),
            guest_ipv4: row.get("guest_ipv4"),
            ready_at: row.get("ready_at"),
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
        sqlx::query("UPDATE lab_templates SET published_from = ?2 WHERE id = ?1")
            .bind(template_id)
            .bind(&version.id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| format!("publish failed: {error}"))?;
        let content_text = serde_json::to_string(&version.content)
            .map_err(|error| format!("the version content cannot be serialized: {error}"))?;
        sqlx::query(
            "INSERT INTO lab_template_versions (id, template_id, name, content, image_digest, published_by, published_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
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
        sqlx::query(
            "INSERT INTO lab_provisions (id, template_version_id, state, created_at, updated_at) \
             VALUES (?1, ?2, 'provisioning', ?3, ?3)",
        )
        .bind(&id)
        .bind(&new.template_version_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("create failed: {error}"))?;
        <Self as ProvisionPort>::get(self, &id).await
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
