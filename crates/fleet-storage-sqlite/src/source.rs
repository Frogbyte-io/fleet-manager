//! The desired-source adapter (FM-403): the active revision and prior
//! valid revisions, durable in SQLite.
//!
//! The active revision is a single-row state table (upsert semantics);
//! prior valid revisions are an append-only history for manual rollback.

use sqlx::SqlitePool;

use fleet_application::source::ActiveRevision;

/// The desired-source repository over the controller's pool.
#[derive(Debug, Clone)]
pub struct SourceRepository {
    pool: SqlitePool,
}

impl SourceRepository {
    /// Composes the repository over the pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl fleet_application::source::SourcePort for SourceRepository {
    async fn active_revision(&self) -> Result<Option<ActiveRevision>, String> {
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT commit_sha, content_digest FROM source_active_revision LIMIT 1")
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| format!("the active revision read failed: {error}"))?;
        Ok(row.map(|(commit_sha, content_digest)| ActiveRevision {
            commit_sha,
            content_digest,
        }))
    }

    async fn set_active_revision(&self, revision: &ActiveRevision) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO source_active_revision (id, commit_sha, content_digest, activated_at) \
             VALUES ('active', ?1, ?2, ?3) \
             ON CONFLICT(id) DO UPDATE SET \
             commit_sha = excluded.commit_sha, \
             content_digest = excluded.content_digest, \
             activated_at = excluded.activated_at",
        )
        .bind(&revision.commit_sha)
        .bind(&revision.content_digest)
        .bind(fleet_core::SystemClock::now_unix_millis())
        .execute(&self.pool)
        .await
        .map_err(|error| format!("the active revision write failed: {error}"))?;
        Ok(())
    }

    async fn prior_revisions(&self) -> Result<Vec<ActiveRevision>, String> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT commit_sha, content_digest FROM source_revision_history \
             ORDER BY activated_at DESC LIMIT 100",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("the revision history read failed: {error}"))?;
        Ok(rows
            .into_iter()
            .map(|(commit_sha, content_digest)| ActiveRevision {
                commit_sha,
                content_digest,
            })
            .collect())
    }

    async fn record_valid_revision(&self, revision: &ActiveRevision) -> Result<(), String> {
        sqlx::query(
            "INSERT OR IGNORE INTO source_revision_history \
             (id, commit_sha, content_digest, activated_at) \
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(format!("rev-{}", revision.content_digest))
        .bind(&revision.commit_sha)
        .bind(&revision.content_digest)
        .bind(fleet_core::SystemClock::now_unix_millis())
        .execute(&self.pool)
        .await
        .map_err(|error| format!("the revision history write failed: {error}"))?;
        Ok(())
    }
}
