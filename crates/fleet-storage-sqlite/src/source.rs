//! The desired-source adapter (FM-403): the active revision and prior
//! valid revisions, durable in SQLite.
//!
//! The active revision is a single-row state table (upsert semantics);
//! prior valid revisions are an append-only history for manual rollback.

use sqlx::SqlitePool;

use fleet_application::source::{ActiveRevision, ActiveSummary, DesiredResourceRecord};

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

    async fn activate_serialized(
        &self,
        revision: &ActiveRevision,
    ) -> Result<ActiveRevision, String> {
        // The critical section is serialized by BEGIN IMMEDIATE: only one
        // activation's check-and-set can run at a time, so a concurrent
        // activation cannot race.
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| format!("the activation lock failed: {error}"))?;
        sqlx::query(
            "INSERT INTO source_active_revision (singleton, commit_sha, content_digest, activated_at) \
             VALUES ('active', ?1, ?2, ?3) \
             ON CONFLICT(singleton) DO UPDATE SET \
             commit_sha = excluded.commit_sha, \
             content_digest = excluded.content_digest, \
             activated_at = excluded.activated_at",
        )
        .bind(&revision.commit_sha)
        .bind(&revision.content_digest)
        .bind(fleet_core::SystemClock::now_unix_millis())
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("the active revision write failed: {error}"))?;
        tx.commit()
            .await
            .map_err(|error| format!("the activation commit failed: {error}"))?;
        Ok(revision.clone())
    }

    async fn record_valid_revision(
        &self,
        revision: &ActiveRevision,
        resources: &[DesiredResourceRecord],
    ) -> Result<(), String> {
        // History and snapshot land together: a recorded revision always
        // has its resources, or neither exists.
        let now = fleet_core::SystemClock::now_unix_millis();
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| format!("the revision record failed: {error}"))?;
        sqlx::query(
            "INSERT OR IGNORE INTO source_revision_history \
             (id, commit_sha, content_digest, activated_at) \
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(format!(
            "rev-{}-{}",
            revision.commit_sha, revision.content_digest
        ))
        .bind(&revision.commit_sha)
        .bind(&revision.content_digest)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("the revision history write failed: {error}"))?;
        let inserted = sqlx::query(
            "INSERT OR IGNORE INTO source_revision_snapshots \
             (commit_sha, content_digest, resource_count, recorded_at) \
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&revision.commit_sha)
        .bind(&revision.content_digest)
        .bind(i64::try_from(resources.len()).unwrap_or(i64::MAX))
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("the snapshot write failed: {error}"))?
        .rows_affected();
        // A snapshot that already exists is kept: the digest names its
        // content, and snapshots are immutable.
        if inserted == 1 {
            for resource in resources {
                sqlx::query(
                    "INSERT INTO source_revision_resources \
                     (commit_sha, content_digest, resource_id, kind, name, spec_json) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .bind(&revision.commit_sha)
                .bind(&revision.content_digest)
                .bind(&resource.id)
                .bind(&resource.kind)
                .bind(&resource.name)
                .bind(resource.spec.to_string())
                .execute(&mut *tx)
                .await
                .map_err(|error| format!("the resource write failed: {error}"))?;
            }
        }
        tx.commit()
            .await
            .map_err(|error| format!("the revision record commit failed: {error}"))?;
        Ok(())
    }

    async fn snapshot_held(&self, revision: &ActiveRevision) -> Result<bool, String> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM source_revision_snapshots WHERE commit_sha = ?1 AND content_digest = ?2",
        )
        .bind(&revision.commit_sha)
        .bind(&revision.content_digest)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| format!("the snapshot read failed: {error}"))?;
        Ok(row.is_some())
    }

    async fn active_summary(&self) -> Result<Option<ActiveSummary>, String> {
        let row: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT commit_sha, content_digest, activated_at FROM source_active_revision LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| format!("the active revision read failed: {error}"))?;
        let Some((commit_sha, content_digest, activated_at)) = row else {
            return Ok(None);
        };
        let revision = ActiveRevision {
            commit_sha,
            content_digest,
        };
        let snapshot_held = self.snapshot_held(&revision).await?;
        let counts: Vec<(String, i64)> = sqlx::query_as(
            "SELECT kind, COUNT(*) FROM source_revision_resources \
             WHERE commit_sha = ?1 AND content_digest = ?2 GROUP BY kind",
        )
        .bind(&revision.commit_sha)
        .bind(&revision.content_digest)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("the resource count read failed: {error}"))?;
        Ok(Some(ActiveSummary {
            revision,
            activated_at,
            snapshot_held,
            kind_counts: counts.into_iter().collect(),
        }))
    }

    async fn active_resources(
        &self,
        kind: Option<&str>,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<DesiredResourceRecord>, String> {
        let rows: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT r.kind, r.resource_id, r.name, r.spec_json \
             FROM source_revision_resources r \
             JOIN source_active_revision a \
               ON a.commit_sha = r.commit_sha AND a.content_digest = r.content_digest \
             WHERE (?1 IS NULL OR r.kind = ?1) AND (?2 IS NULL OR r.resource_id > ?2) \
             ORDER BY r.resource_id LIMIT ?3",
        )
        .bind(kind)
        .bind(after)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("the resource read failed: {error}"))?;
        rows.into_iter()
            .map(|(kind, id, name, spec_json)| {
                Ok(DesiredResourceRecord {
                    kind,
                    id,
                    name,
                    spec: serde_json::from_str(&spec_json)
                        .map_err(|error| format!("a stored resource spec is corrupt: {error}"))?,
                })
            })
            .collect()
    }
}
