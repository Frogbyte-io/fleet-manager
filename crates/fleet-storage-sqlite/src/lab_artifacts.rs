//! The Lab artifact repository: the SQLite implementation of the
//! application's [`LabArtifactPort`] (FM-721). Metadata and digests only;
//! the bytes live in the controller's artifact directory.

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;
use uuid::Uuid;

use fleet_application::lab_artifacts::{
    ArtifactKind, CollectionFailure, LabArtifact, LabArtifactPort, NewArtifact,
};

/// The artifact repository over a pool.
#[derive(Debug)]
pub struct LabArtifactRepository {
    pool: SqlitePool,
}

impl LabArtifactRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_artifact(row: &sqlx::sqlite::SqliteRow) -> Result<LabArtifact, String> {
        let kind: String = row.get("kind");
        Ok(LabArtifact {
            id: row.get("id"),
            lease_id: row.get("lease_id"),
            project_id: row.get("project_id"),
            owner: row.get("owner"),
            kind: ArtifactKind::from_id(&kind)?,
            name: row.get("name"),
            size_bytes: u64::try_from(row.get::<i64, _>("size_bytes"))
                .map_err(|_| "an artifact size is negative".to_owned())?,
            sha256: row.get("sha256"),
            location: row.get("location"),
            operation_id: row.get("operation_id"),
            created_at: row.get("created_at"),
            retain_until: row.get("retain_until"),
        })
    }
}

#[async_trait]
impl LabArtifactPort for LabArtifactRepository {
    async fn insert(&self, new: &NewArtifact) -> Result<LabArtifact, String> {
        let id = Uuid::now_v7().to_string();
        let size = i64::try_from(new.blob.size_bytes)
            .map_err(|_| "the artifact size does not fit the store".to_owned())?;
        sqlx::query(
            "INSERT INTO lab_artifacts (id, lease_id, project_id, owner, kind, name, size_bytes, sha256, location, operation_id, created_at, retain_until) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )
        .bind(&id)
        .bind(&new.lease_id)
        .bind(&new.project_id)
        .bind(&new.owner)
        .bind(new.kind.id())
        .bind(&new.name)
        .bind(size)
        .bind(&new.blob.sha256)
        .bind(&new.blob.location)
        .bind(&new.operation_id)
        .bind(new.created_at)
        .bind(new.retain_until)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("artifact insert failed: {error}"))?;
        self.get(&id)
            .await?
            .ok_or_else(|| format!("artifact {id} vanished after its insert"))
    }

    async fn get(&self, id: &str) -> Result<Option<LabArtifact>, String> {
        sqlx::query("SELECT * FROM lab_artifacts WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("artifact read failed: {error}"))?
            .map(|row| Self::row_to_artifact(&row))
            .transpose()
    }

    async fn list(
        &self,
        lease_id: Option<&str>,
        project_id: Option<&str>,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Vec<LabArtifact>, String> {
        sqlx::query(
            "SELECT * FROM lab_artifacts \
             WHERE (?1 IS NULL OR lease_id = ?1) AND (?2 IS NULL OR project_id = ?2) \
             AND (?3 IS NULL OR (created_at, id) < \
                  (SELECT created_at, id FROM lab_artifacts WHERE id = ?3)) \
             ORDER BY created_at DESC, id DESC LIMIT ?4",
        )
        .bind(lease_id)
        .bind(project_id)
        .bind(cursor)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("artifact list failed: {error}"))?
        .iter()
        .map(Self::row_to_artifact)
        .collect()
    }

    async fn expired(&self, now: i64, limit: u32) -> Result<Vec<LabArtifact>, String> {
        sqlx::query(
            "SELECT * FROM lab_artifacts WHERE retain_until <= ?1 \
             ORDER BY retain_until, id LIMIT ?2",
        )
        .bind(now)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("expired artifact list failed: {error}"))?
        .iter()
        .map(Self::row_to_artifact)
        .collect()
    }

    async fn delete(&self, id: &str) -> Result<bool, String> {
        sqlx::query("DELETE FROM lab_artifacts WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map(|done| done.rows_affected() > 0)
            .map_err(|error| format!("artifact delete failed: {error}"))
    }

    async fn location_references(&self, location: &str) -> Result<u64, String> {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM lab_artifacts WHERE location = ?1")
            .bind(location)
            .fetch_one(&self.pool)
            .await
            .map(|count| u64::try_from(count).unwrap_or(0))
            .map_err(|error| format!("artifact location check failed: {error}"))
    }

    async fn record_collection_failure(&self, failure: &CollectionFailure) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO lab_artifact_collection_failures (lease_id, operation_id, reason, detail, failed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT (lease_id) DO UPDATE SET operation_id = excluded.operation_id, \
             reason = excluded.reason, detail = excluded.detail, failed_at = excluded.failed_at",
        )
        .bind(&failure.lease_id)
        .bind(&failure.operation_id)
        .bind(&failure.reason)
        .bind(&failure.detail)
        .bind(failure.failed_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("collection failure record failed: {error}"))
    }

    async fn collection_failure(
        &self,
        lease_id: &str,
    ) -> Result<Option<CollectionFailure>, String> {
        sqlx::query("SELECT * FROM lab_artifact_collection_failures WHERE lease_id = ?1")
            .bind(lease_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("collection failure read failed: {error}"))
            .map(|row| {
                row.map(|row| CollectionFailure {
                    lease_id: row.get("lease_id"),
                    operation_id: row.get("operation_id"),
                    reason: row.get("reason"),
                    detail: row.get("detail"),
                    failed_at: row.get("failed_at"),
                })
            })
    }
}
