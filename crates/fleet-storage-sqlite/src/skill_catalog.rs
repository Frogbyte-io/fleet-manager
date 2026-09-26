//! SQLite repository for mutable catalog drafts and immutable versions.

use async_trait::async_trait;
use sqlx::{Row as _, SqlitePool};
use uuid::Uuid;

use fleet_application::skill_catalog::{SkillCatalogEntry, SkillCatalogPort, SkillCatalogVersion};
use fleet_core::SkillCatalogContent;

/// Skill catalog repository over the controller store.
#[derive(Debug)]
pub struct SkillCatalogRepository {
    pool: SqlitePool,
}

impl SkillCatalogRepository {
    /// Creates a repository over a store pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn entry(row: &sqlx::sqlite::SqliteRow) -> Result<SkillCatalogEntry, String> {
        Ok(SkillCatalogEntry {
            id: row.try_get("id").map_err(|error| db_error(&error))?,
            content: serde_json::from_str(
                &row.try_get::<String, _>("content_json")
                    .map_err(|error| db_error(&error))?,
            )
            .map_err(|e| format!("decode catalog draft failed: {e}"))?,
            published_from: row
                .try_get("published_from")
                .map_err(|error| db_error(&error))?,
            created_at: row
                .try_get("created_at")
                .map_err(|error| db_error(&error))?,
            updated_at: row
                .try_get("updated_at")
                .map_err(|error| db_error(&error))?,
        })
    }
    fn version(row: &sqlx::sqlite::SqliteRow) -> Result<SkillCatalogVersion, String> {
        Ok(SkillCatalogVersion {
            id: row.try_get("id").map_err(|error| db_error(&error))?,
            catalog_id: row
                .try_get("catalog_id")
                .map_err(|error| db_error(&error))?,
            name: row.try_get("name").map_err(|error| db_error(&error))?,
            description: row
                .try_get("description")
                .map_err(|error| db_error(&error))?,
            content_digest: row
                .try_get("content_digest")
                .map_err(|error| db_error(&error))?,
            content: serde_json::from_str(
                &row.try_get::<String, _>("content_json")
                    .map_err(|error| db_error(&error))?,
            )
            .map_err(|e| format!("decode catalog version failed: {e}"))?,
            published_at: row
                .try_get("published_at")
                .map_err(|error| db_error(&error))?,
        })
    }
}

#[async_trait]
impl SkillCatalogPort for SkillCatalogRepository {
    async fn create(
        &self,
        content: &SkillCatalogContent,
        now: i64,
    ) -> Result<SkillCatalogEntry, String> {
        let id = Uuid::now_v7().to_string();
        let json =
            serde_json::to_string(content).map_err(|e| format!("encode draft failed: {e}"))?;
        sqlx::query("INSERT INTO skill_catalog_entries (id, name, content_json, published_from, created_at, updated_at) VALUES (?1, ?2, ?3, NULL, ?4, ?4)")
            .bind(&id).bind(&content.name).bind(json).bind(now).execute(&self.pool).await.map_err(|e| if is_unique(&e) { format!("catalog name {:?} is already taken", content.name) } else { format!("create failed: {e}") })?;
        self.get(&id).await
    }
    async fn get(&self, id: &str) -> Result<SkillCatalogEntry, String> {
        sqlx::query("SELECT id, content_json, published_from, created_at, updated_at FROM skill_catalog_entries WHERE id = ?1").bind(id).fetch_optional(&self.pool).await.map_err(|e| format!("get failed: {e}"))?.as_ref().ok_or_else(|| format!("catalog entry {id} not found")).and_then(Self::entry)
    }
    async fn list(&self) -> Result<Vec<SkillCatalogEntry>, String> {
        let rows = sqlx::query("SELECT id, content_json, published_from, created_at, updated_at FROM skill_catalog_entries ORDER BY updated_at DESC, id DESC").fetch_all(&self.pool).await.map_err(|e| format!("list failed: {e}"))?;
        rows.iter().map(Self::entry).collect()
    }
    async fn update(
        &self,
        id: &str,
        content: &SkillCatalogContent,
        now: i64,
    ) -> Result<SkillCatalogEntry, String> {
        let json =
            serde_json::to_string(content).map_err(|e| format!("encode draft failed: {e}"))?;
        let result = sqlx::query("UPDATE skill_catalog_entries SET name = ?2, content_json = ?3, updated_at = ?4 WHERE id = ?1").bind(id).bind(&content.name).bind(json).bind(now).execute(&self.pool).await.map_err(|e| if is_unique(&e) { format!("catalog name {:?} is already taken", content.name) } else { format!("update failed: {e}") })?;
        if result.rows_affected() == 0 {
            return Err(format!("catalog entry {id} not found"));
        }
        self.get(id).await
    }
    async fn publish(
        &self,
        id: &str,
        version: &SkillCatalogVersion,
    ) -> Result<SkillCatalogVersion, String> {
        let json = serde_json::to_string(&version.content)
            .map_err(|e| format!("encode version failed: {e}"))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| format!("begin publish failed: {e}"))?;
        sqlx::query("INSERT OR IGNORE INTO skill_catalog_versions (id, catalog_id, name, description, content_digest, content_json, published_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)")
            .bind(&version.id).bind(id).bind(&version.name).bind(&version.description).bind(&version.content_digest).bind(json).bind(version.published_at).execute(&mut *tx).await.map_err(|e| format!("publish failed: {e}"))?;
        sqlx::query("UPDATE skill_catalog_entries SET published_from = ?2 WHERE id = ?1")
            .bind(id)
            .bind(&version.id)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("record publication failed: {e}"))?;
        tx.commit()
            .await
            .map_err(|e| format!("commit publish failed: {e}"))?;
        self.get_version(&version.id).await
    }
    async fn get_version(&self, id: &str) -> Result<SkillCatalogVersion, String> {
        sqlx::query("SELECT id, catalog_id, name, description, content_digest, content_json, published_at FROM skill_catalog_versions WHERE id = ?1").bind(id).fetch_optional(&self.pool).await.map_err(|e| format!("get version failed: {e}"))?.as_ref().ok_or_else(|| format!("catalog version {id} not found")).and_then(Self::version)
    }
    async fn list_versions(&self, id: &str) -> Result<Vec<SkillCatalogVersion>, String> {
        let rows = sqlx::query("SELECT id, catalog_id, name, description, content_digest, content_json, published_at FROM skill_catalog_versions WHERE catalog_id = ?1 ORDER BY published_at DESC, id DESC").bind(id).fetch_all(&self.pool).await.map_err(|e| format!("list versions failed: {e}"))?;
        rows.iter().map(Self::version).collect()
    }
}

fn is_unique(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
}
fn db_error(error: &sqlx::Error) -> String {
    format!("read failed: {error}")
}
