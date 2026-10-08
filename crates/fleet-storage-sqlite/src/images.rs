//! The image-recipe repository: the SQLite implementation of the
//! application's [`RecipePort`].
//!
//! Drafts are mutable working copies; published versions are immutable
//! rows identified by (recipe, content digest), so publishing the same
//! content twice yields the same version.

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;
use uuid::Uuid;

use fleet_application::images::{
    BUILD_CURSOR_INVALID, BuildPage, BuildPageRequest, NewRecipe, PROMOTION_BUILD_REJECTED, Recipe,
    RecipeContent, RecipePort, RecipeVersion,
};
use fleet_application::lab::ImageArtifactPort;
use fleet_core::{ImageBuildRecord, ImageBuildTemplate, RecipeSource};

/// The image-recipe repository over a pool.
#[derive(Debug)]
pub struct RecipeRepository {
    pool: SqlitePool,
}

impl RecipeRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_recipe(row: &sqlx::sqlite::SqliteRow) -> Result<Recipe, String> {
        let source: String = row.get("source");
        Ok(Recipe {
            id: row.get("id"),
            content: RecipeContent {
                name: row.get("name"),
                description: row.get("description"),
                node: row.get("node"),
                storage_pool: row.get("storage_pool"),
                source: RecipeSource::from_id(&source)?,
                content: row.get("content"),
            },
            published_from: {
                let value: Option<String> = row.get("published_from");
                value
            },
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    fn row_to_version(row: &sqlx::sqlite::SqliteRow) -> Result<RecipeVersion, String> {
        let source: String = row.get("source");
        Ok(RecipeVersion {
            id: row.get("id"),
            recipe_id: row.get("recipe_id"),
            name: row.get("name"),
            description: row.get("description"),
            content_digest: row.get("content_digest"),
            content: row.get("content"),
            source: RecipeSource::from_id(&source)?,
            node: row.get("node"),
            storage_pool: row.get("storage_pool"),
            published_at: row.get("published_at"),
            promoted_at: row.get::<Option<i64>, _>("promoted_at"),
            promoted_by: row.get::<Option<String>, _>("promoted_by"),
            promoted_build_id: row.get::<Option<String>, _>("promoted_build_id"),
            allow_insecure_tls: row.get::<i64, _>("allow_insecure_tls") != 0,
        })
    }
}

#[async_trait]
impl RecipePort for RecipeRepository {
    async fn build_target_account(
        &self,
        version: &RecipeVersion,
        requested: Option<&str>,
    ) -> Result<Option<String>, String> {
        let content: serde_json::Value = serde_json::from_str(&version.content).unwrap_or_default();
        let Some(endpoint) = content
            .get("builders")
            .and_then(serde_json::Value::as_array)
            .and_then(|builders| {
                builders.iter().find_map(|builder| {
                    builder
                        .get("proxmox_url")
                        .and_then(serde_json::Value::as_str)
                })
            })
        else {
            return Ok(None);
        };
        let rows = sqlx::query("SELECT id, host, port FROM proxmox_accounts")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        let matching: Vec<String> = rows
            .iter()
            .filter_map(|row| {
                let host: String = row.get("host");
                let host = if host.contains(':') && !host.starts_with('[') {
                    format!("[{host}]")
                } else {
                    host
                };
                let port: u16 = row.get("port");
                let endpoint = endpoint.trim_end_matches('/');
                (endpoint == format!("https://{host}:{port}/api2/json")
                    || (port == 443 && endpoint == format!("https://{host}/api2/json")))
                .then(|| row.get("id"))
            })
            .collect();
        if let Some(id) = requested {
            return if matching.iter().any(|found| found == id) {
                Ok(Some(id.to_owned()))
            } else {
                Err("target account does not match the frozen recipe endpoint".to_owned())
            };
        }
        if matching.len() > 1 {
            return Err(fleet_application::images::TARGET_ACCOUNT_AMBIGUOUS.to_owned());
        }
        Ok(matching.into_iter().next())
    }

    async fn start_build(&self, record: &ImageBuildRecord) -> Result<(), String> {
        if record.outcome != "running"
            || record.ended_at.is_some()
            || record.reason.is_some()
            || record.template.is_some()
            || record.packer_version.is_some()
            || record.proxmox_plugin_version.is_some()
        {
            return Err("build records must begin with an unprobed running snapshot".to_owned());
        }
        sqlx::query("INSERT INTO image_build_records (id, operation_id, recipe_id, version_id, content_digest, asset_digests, account_id, node, storage_pool, started_at, outcome) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'running')")
            .bind(&record.id).bind(&record.operation_id).bind(&record.recipe_id)
            .bind(&record.version_id).bind(&record.content_digest)
            .bind(serde_json::to_string(&record.asset_digests).map_err(|e| e.to_string())?)
            .bind(&record.account_id).bind(&record.node).bind(&record.storage_pool).bind(record.started_at)
            .execute(&self.pool).await.map_err(|e| format!("start build failed: {e}"))?;
        Ok(())
    }

    async fn finish_build(&self, record: &ImageBuildRecord) -> Result<(), String> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| e.to_string())?;
        let updated = sqlx::query("UPDATE image_build_records SET ended_at = ?2, outcome = ?3, reason = ?4, packer_version = ?5, proxmox_plugin_version = ?6, template_node = ?7, template_vmid = ?8, template_name = ?9 WHERE id = ?1 AND outcome = 'running'")
            .bind(&record.id).bind(record.ended_at).bind(&record.outcome).bind(&record.reason)
            .bind(&record.packer_version).bind(&record.proxmox_plugin_version)
            .bind(record.template.as_ref().map(|t| &t.node))
            .bind(record.template.as_ref().map(|t| t.vmid))
            .bind(record.template.as_ref().map(|t| &t.name))
            .execute(&mut *transaction).await.map_err(|e| format!("complete build failed: {e}"))?;
        if updated.rows_affected() != 1 {
            return Err("build is missing or already completed".to_owned());
        }
        transaction.commit().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn get_build(&self, id: &str) -> Result<ImageBuildRecord, String> {
        let row = sqlx::query("SELECT * FROM image_build_records WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("build {id} not found"))?;
        row_to_build(&row)
    }

    async fn list_builds(
        &self,
        recipe: Option<&str>,
        version: Option<&str>,
    ) -> Result<Vec<ImageBuildRecord>, String> {
        sqlx::query("SELECT * FROM image_build_records WHERE (?1 IS NULL OR recipe_id = ?1) AND (?2 IS NULL OR version_id = ?2) ORDER BY started_at DESC, id DESC")
            .bind(recipe).bind(version).fetch_all(&self.pool).await.map_err(|e| e.to_string())?
            .iter().map(row_to_build).collect()
    }

    async fn list_build_page(&self, query: &BuildPageRequest) -> Result<BuildPage, String> {
        let cursor = if let Some(id) = query.cursor.as_deref() {
            Some(sqlx::query("SELECT started_at, id FROM image_build_records WHERE id = ?1 AND (?2 IS NULL OR recipe_id = ?2) AND (?3 IS NULL OR version_id = ?3)")
                .bind(id).bind(query.recipe.as_deref()).bind(query.version.as_deref())
                .fetch_optional(&self.pool).await.map_err(|e| e.to_string())?
                .ok_or_else(|| BUILD_CURSOR_INVALID.to_owned())?)
        } else {
            None
        };
        let limit = if query.limit == 0 {
            50
        } else {
            query.limit.min(200)
        };
        let mut sql =
            sqlx::QueryBuilder::<sqlx::Sqlite>::new("SELECT * FROM image_build_records WHERE 1=1");
        if let Some(recipe) = query.recipe.as_deref() {
            sql.push(" AND recipe_id = ").push_bind(recipe);
        }
        if let Some(version) = query.version.as_deref() {
            sql.push(" AND version_id = ").push_bind(version);
        }
        if let Some(cursor) = cursor.as_ref() {
            sql.push(" AND (started_at, id) < (")
                .push_bind(cursor.get::<i64, _>("started_at"))
                .push(", ")
                .push_bind(cursor.get::<String, _>("id"))
                .push(")");
        }
        sql.push(" ORDER BY started_at DESC, id DESC LIMIT ")
            .push_bind(i64::from(limit) + 1);
        let rows = sql
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        let mut items: Vec<ImageBuildRecord> =
            rows.iter().map(row_to_build).collect::<Result<_, _>>()?;
        let more = items.len() > limit as usize;
        items.truncate(limit as usize);
        let next_cursor = if more {
            items.last().map(|item| item.id.clone())
        } else {
            None
        };
        Ok(BuildPage {
            items,
            next_cursor,
            limit,
        })
    }

    async fn create(&self, recipe: &NewRecipe, now: i64) -> Result<Recipe, String> {
        let id = Uuid::now_v7().to_string();
        let content = &recipe.content;
        let result = sqlx::query(
            "INSERT INTO image_recipes (id, name, description, node, storage_pool, source, content, published_from, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?8)",
        )
        .bind(&id)
        .bind(&content.name)
        .bind(&content.description)
        .bind(&content.node)
        .bind(&content.storage_pool)
        .bind(content.source.id())
        .bind(&content.content)
        .bind(now)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => self.get(&id).await,
            Err(error) if is_unique_violation(&error) => Err(format!(
                "the recipe name {:?} is already taken",
                content.name
            )),
            Err(error) => Err(format!("create failed: {error}")),
        }
    }

    async fn get(&self, id: &str) -> Result<Recipe, String> {
        sqlx::query("SELECT id, name, description, node, storage_pool, source, content, published_from, created_at, updated_at FROM image_recipes WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("get failed: {error}"))?
            .map(|row| Self::row_to_recipe(&row))
            .transpose()?
            .ok_or_else(|| format!("recipe {id} not found"))
    }

    async fn list(&self) -> Result<Vec<Recipe>, String> {
        let rows = sqlx::query("SELECT id, name, description, node, storage_pool, source, content, published_from, created_at, updated_at FROM image_recipes ORDER BY updated_at DESC, id DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|error| format!("list failed: {error}"))?;
        rows.iter().map(Self::row_to_recipe).collect()
    }

    async fn update(&self, id: &str, content: &RecipeContent, now: i64) -> Result<Recipe, String> {
        let updated = sqlx::query(
            "UPDATE image_recipes SET name = ?2, description = ?3, node = ?4, storage_pool = ?5, source = ?6, content = ?7, updated_at = ?8 WHERE id = ?1",
        )
        .bind(id)
        .bind(&content.name)
        .bind(&content.description)
        .bind(&content.node)
        .bind(&content.storage_pool)
        .bind(content.source.id())
        .bind(&content.content)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("update failed: {error}"))?;
        if updated.rows_affected() == 0 {
            return Err(format!("recipe {id} not found"));
        }
        self.get(id).await
    }

    async fn delete(&self, id: &str) -> Result<(), String> {
        let result = sqlx::query("DELETE FROM image_recipes WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|error| format!("delete failed: {error}"))?;
        if result.rows_affected() == 0 {
            return Err(format!("recipe {id} not found"));
        }
        Ok(())
    }

    async fn publish(
        &self,
        recipe_id: &str,
        version: &RecipeVersion,
    ) -> Result<RecipeVersion, String> {
        // The draft pointer and the version row commit together: a failed
        // insert must not leave a draft referencing a missing version.
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| format!("publish failed: {error}"))?;
        sqlx::query("UPDATE image_recipes SET published_from = ?2 WHERE id = ?1")
            .bind(recipe_id)
            .bind(&version.id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| format!("publish failed: {error}"))?;
        let result = sqlx::query(
            "INSERT INTO image_recipe_versions (id, recipe_id, name, description, content_digest, content, source, node, storage_pool, published_at, allow_insecure_tls) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) \
             ON CONFLICT (recipe_id, content_digest) DO NOTHING",
        )
        .bind(&version.id)
        .bind(&version.recipe_id)
        .bind(&version.name)
        .bind(&version.description)
        .bind(&version.content_digest)
        .bind(&version.content)
        .bind(version.source.id())
        .bind(&version.node)
        .bind(&version.storage_pool)
        .bind(version.published_at)
        .bind(i64::from(version.allow_insecure_tls))
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("publish failed: {error}"))?;
        transaction
            .commit()
            .await
            .map_err(|error| format!("publish failed: {error}"))?;
        if result.rows_affected() == 0 {
            // The same content was already published: return the existing
            // version, which is the idempotent answer.
            return self.get_version(&version.id).await;
        }
        Ok(version.clone())
    }

    async fn get_version(&self, id: &str) -> Result<RecipeVersion, String> {
        sqlx::query("SELECT id, recipe_id, name, description, content_digest, content, source, node, storage_pool, published_at, promoted_at, promoted_by, promoted_build_id, allow_insecure_tls FROM image_recipe_versions WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("get_version failed: {error}"))?
            .map(|row| Self::row_to_version(&row))
            .transpose()?
            .ok_or_else(|| format!("version {id} not found"))
    }

    async fn list_versions(&self, recipe_id: &str) -> Result<Vec<RecipeVersion>, String> {
        let rows = sqlx::query("SELECT id, recipe_id, name, description, content_digest, content, source, node, storage_pool, published_at, promoted_at, promoted_by, promoted_build_id, allow_insecure_tls FROM image_recipe_versions WHERE recipe_id = ?1 ORDER BY published_at DESC, id DESC")
            .bind(recipe_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| format!("list_versions failed: {error}"))?;
        rows.iter().map(Self::row_to_version).collect()
    }

    async fn promote(
        &self,
        version_id: &str,
        build_id: &str,
        promoted_by: &str,
        promoted_at: i64,
    ) -> Result<RecipeVersion, String> {
        // The demotion of the recipe's other promoted version is part of
        // the same commit: at most one promoted version per recipe.
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| format!("promote failed: {error}"))?;
        let version = sqlx::query("SELECT recipe_id FROM image_recipe_versions WHERE id = ?1")
            .bind(version_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| format!("promote failed: {error}"))?
            .ok_or_else(|| format!("version {version_id} not found"))?;
        let recipe_id: String = version.get("recipe_id");
        // Recheck under the write transaction: a concurrent new build must
        // not slip between the application's evidence read and promotion,
        // and the build the application read is the one the promotion pins.
        let eligible: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM image_build_records b JOIN image_recipe_versions v ON v.id = b.version_id WHERE b.id = ?2 AND b.id = (SELECT id FROM image_build_records WHERE version_id = ?1 ORDER BY started_at DESC, id DESC LIMIT 1) AND b.outcome = 'succeeded' AND b.content_digest = v.content_digest AND b.template_vmid IS NOT NULL)")
            .bind(version_id).bind(build_id).fetch_one(&mut *transaction).await.map_err(|e| e.to_string())?;
        if !eligible {
            return Err(PROMOTION_BUILD_REJECTED.to_owned());
        }
        sqlx::query(
            "UPDATE image_recipe_versions SET promoted_at = NULL, promoted_by = NULL              WHERE recipe_id = ?1 AND promoted_at IS NOT NULL AND id != ?2",
        )
        .bind(&recipe_id)
        .bind(version_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("promote failed: {error}"))?;
        sqlx::query(
            "UPDATE image_recipe_versions SET promoted_at = ?3, promoted_by = ?2, promoted_build_id = ?4 WHERE id = ?1",
        )
        .bind(version_id)
        .bind(promoted_by)
        .bind(promoted_at)
        .bind(build_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("promote failed: {error}"))?;
        let row = sqlx::query("SELECT id, recipe_id, name, description, content_digest, content, source, node, storage_pool, published_at, promoted_at, promoted_by, promoted_build_id, allow_insecure_tls FROM image_recipe_versions WHERE id = ?1")
            .bind(version_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| format!("promote failed: {error}"))?;
        let promoted = Self::row_to_version(&row)?;
        transaction
            .commit()
            .await
            .map_err(|error| format!("promote failed: {error}"))?;
        Ok(promoted)
    }

    async fn promoted_version(&self, recipe_id: &str) -> Result<Option<RecipeVersion>, String> {
        let row = sqlx::query("SELECT id, recipe_id, name, description, content_digest, content, source, node, storage_pool, published_at, promoted_at, promoted_by, promoted_build_id, allow_insecure_tls FROM image_recipe_versions WHERE recipe_id = ?1 AND promoted_at IS NOT NULL LIMIT 1")
            .bind(recipe_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("promoted_version failed: {error}"))?;
        row.map(|row| Self::row_to_version(&row)).transpose()
    }
}

impl RecipeRepository {
    /// The successful `image.build` operations' (payload, result) pairs,
    /// newest first. JSON is parsed in Rust so one malformed row cannot
    /// fail the whole query.
    async fn successful_builds(&self) -> Result<Vec<(Option<String>, Option<String>)>, String> {
        let rows = sqlx::query(
            "SELECT payload_json, result_json FROM operations \
             WHERE kind = 'image.build' AND state = 'succeeded' \
             ORDER BY created_at DESC, id DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("image build artifacts failed: {error}"))?;
        Ok(rows
            .iter()
            .map(|row| (row.get("payload_json"), row.get("result_json")))
            .collect())
    }
}

/// The image version a build payload names.
fn built_version(payload_json: Option<&str>) -> Option<String> {
    let payload: serde_json::Value = serde_json::from_str(payload_json?).ok()?;
    payload["versionId"].as_str().map(str::to_owned)
}

/// The `artifactId` an image build recorded, when the result carries one.
fn recorded_artifact(result_json: Option<&str>) -> Option<String> {
    let result: serde_json::Value = serde_json::from_str(result_json?).ok()?;
    result["artifactId"].as_str().map(str::to_owned)
}

/// The template VMID in a Packer Proxmox artifact id. The builder's
/// `Artifact.Id()` is the VMID in decimal; the machine-readable stream
/// Fleet has recorded also carries a `<node>:<vmid>` shape (`pve:102`).
/// The node part is ignored: the executor reads the template's node from
/// the cluster. PVE VMIDs are 100..=999999999 (`pve-vmid`).
fn artifact_vmid(artifact: &str) -> Option<u32> {
    let vmid = match artifact.rsplit_once(':') {
        Some((node, vmid))
            if !node.is_empty()
                && node
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') =>
        {
            vmid
        }
        Some(_) => return None,
        None => artifact,
    };
    if vmid.is_empty() || !vmid.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    vmid.parse::<u32>()
        .ok()
        .filter(|vmid| (100..=999_999_999).contains(vmid))
}

#[async_trait]
impl ImageArtifactPort for RecipeRepository {
    async fn template_vmid(&self, image_version_id: &str) -> Result<Option<u32>, String> {
        // A promotion pins the build that justified it (issue #281): a later
        // rebuild of the version is evidence only and never moves the clone
        // source. The pin survives a demotion, so a lease pinned earlier keeps
        // its source.
        let pinned: Option<Option<u32>> = sqlx::query_scalar("SELECT b.template_vmid FROM image_recipe_versions v JOIN image_build_records b ON b.id = v.promoted_build_id WHERE v.id = ?1")
            .bind(image_version_id).fetch_optional(&self.pool).await.map_err(|e| e.to_string())?;
        if let Some(vmid) = pinned {
            return Ok(vmid);
        }
        // No pin: a version promoted before migration 0039 and not promoted
        // since. It keeps the pre-#281 rule, its newest successful build.
        if let Some(vmid) = sqlx::query_scalar::<_, u32>("SELECT template_vmid FROM image_build_records WHERE version_id = ?1 AND outcome = 'succeeded' ORDER BY started_at DESC, id DESC LIMIT 1")
            .bind(image_version_id).fetch_optional(&self.pool).await.map_err(|e| e.to_string())? {
            return Ok(Some(vmid));
        }
        // Compatibility for artifacts built before first-class records existed.
        // Only the version's latest successful build counts: an older
        // build's artifact is never a fallback.
        let Some((_, result)) = self
            .successful_builds()
            .await?
            .into_iter()
            .find(|(payload, _)| {
                built_version(payload.as_deref()).as_deref() == Some(image_version_id)
            })
        else {
            return Ok(None);
        };
        let Some(artifact) = recorded_artifact(result.as_deref()) else {
            return Ok(None);
        };
        artifact_vmid(&artifact).map(Some).ok_or_else(|| {
            format!(
                "the image version's build artifact {artifact:?} is not a Proxmox template VMID"
            )
        })
    }

    async fn promoted_template_vmids(&self) -> Result<Vec<u32>, String> {
        // Fetch only the artifact columns of successful builds whose versions
        // are promoted. Build provenance and failed history never enter memory.
        // Every successful build of a promoted version is protected,
        // including any rebuild: a rebuild's template is not the clone source
        // (issue #281), but cleanup still never destroys it. Every pinned
        // build is protected too, even after its version was demoted: the
        // pin survives demotion and stays the clone source for leases pinned
        // to that version.
        let mut vmids: Vec<u32> = sqlx::query_scalar("SELECT b.template_vmid FROM image_build_records b JOIN image_recipe_versions v ON v.id = b.version_id WHERE b.outcome = 'succeeded' AND v.promoted_at IS NOT NULL UNION SELECT b.template_vmid FROM image_build_records b JOIN image_recipe_versions v ON v.promoted_build_id = b.id")
            .fetch_all(&self.pool).await.map_err(|error| format!("promoted image build artifacts failed: {error}"))?;
        let legacy: Vec<Option<String>> = sqlx::query_scalar("SELECT o.result_json FROM operations o JOIN image_recipe_versions v ON v.id = json_extract(CASE WHEN json_valid(o.payload_json) THEN o.payload_json ELSE '{}' END, '$.versionId') WHERE o.kind = 'image.build' AND o.state = 'succeeded' AND v.promoted_at IS NOT NULL")
            .fetch_all(&self.pool).await.map_err(|error| format!("promoted legacy artifacts failed: {error}"))?;
        vmids.extend(
            legacy
                .iter()
                .filter_map(|result| recorded_artifact(result.as_deref()))
                .filter_map(|artifact| artifact_vmid(&artifact)),
        );
        vmids.sort_unstable();
        vmids.dedup();
        Ok(vmids)
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

#[cfg(test)]
mod tests {
    use super::artifact_vmid;

    #[test]
    fn artifact_ids_parse_in_both_recorded_shapes() {
        assert_eq!(artifact_vmid("120"), Some(120));
        assert_eq!(artifact_vmid("pve:102"), Some(102));
        assert_eq!(artifact_vmid("pve-b.lan:9000"), Some(9000));
        assert_eq!(artifact_vmid("999999999"), Some(999_999_999));
        for invalid in [
            "",
            "99",
            "pve:",
            ":120",
            "local:vztmpl/base.tar",
            "a:b:120",
            "+120",
            "4294967296",
            "1000000000",
        ] {
            assert_eq!(artifact_vmid(invalid), None, "{invalid}");
        }
    }
}

fn row_to_build(row: &sqlx::sqlite::SqliteRow) -> Result<ImageBuildRecord, String> {
    let assets: String = row.get("asset_digests");
    Ok(ImageBuildRecord {
        id: row.get("id"),
        operation_id: row.get("operation_id"),
        recipe_id: row.get("recipe_id"),
        version_id: row.get("version_id"),
        content_digest: row.get("content_digest"),
        asset_digests: serde_json::from_str(&assets).map_err(|e| e.to_string())?,
        packer_version: row.get("packer_version"),
        proxmox_plugin_version: row.get("proxmox_plugin_version"),
        account_id: row.get("account_id"),
        node: row.get("node"),
        storage_pool: row.get("storage_pool"),
        started_at: row.get("started_at"),
        ended_at: row.get("ended_at"),
        outcome: row.get("outcome"),
        reason: row.get("reason"),
        template: row
            .get::<Option<u32>, _>("template_vmid")
            .map(|vmid| ImageBuildTemplate {
                node: row.get("template_node"),
                vmid,
                name: row.get("template_name"),
            }),
    })
}

#[cfg(test)]
mod build_record_tests {
    use super::*;
    use crate::{OperationRepository, Store};
    use fleet_application::operation::OperationPort as _;

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn snapshots_are_bound_to_versions_and_only_complete_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let recipes = RecipeRepository::new(store.pool().clone());
        let draft = recipes
            .create(
                &NewRecipe {
                    content: RecipeContent {
                        name: "image".to_owned(),
                        description: String::new(),
                        node: "pve".to_owned(),
                        storage_pool: Some("local-lvm".to_owned()),
                        source: RecipeSource::Clone,
                        content: "{}".to_owned(),
                    },
                },
                1000,
            )
            .await
            .unwrap();
        let version = RecipeVersion {
            id: "image@digest".to_owned(),
            recipe_id: draft.id.clone(),
            name: "image".to_owned(),
            description: String::new(),
            content_digest: draft.content.content_digest().unwrap(),
            content: "{}".to_owned(),
            source: RecipeSource::Clone,
            node: "pve".to_owned(),
            storage_pool: "local-lvm".to_owned(),
            published_at: 1001,
            promoted_at: None,
            promoted_by: None,
            promoted_build_id: None,
            allow_insecure_tls: false,
        };
        recipes.publish(&draft.id, &version).await.unwrap();
        assert!(
            !recipes
                .get_version(&version.id)
                .await
                .unwrap()
                .allow_insecure_tls
        );
        // The insecure-TLS opt-in (#284) round-trips, and the column refuses
        // anything but 0 or 1.
        let opted = RecipeVersion {
            id: "image@opted".to_owned(),
            content_digest: draft.content.version_digest(true).unwrap(),
            allow_insecure_tls: true,
            ..version.clone()
        };
        recipes.publish(&draft.id, &opted).await.unwrap();
        assert!(
            recipes
                .get_version(&opted.id)
                .await
                .unwrap()
                .allow_insecure_tls
        );
        assert!(
            sqlx::query("UPDATE image_recipe_versions SET allow_insecure_tls = 2 WHERE id = ?1")
                .bind(&opted.id)
                .execute(store.pool())
                .await
                .is_err()
        );
        let operation = OperationRepository::new(store.pool().clone())
            .create("image.build", None, None, None, None)
            .await
            .unwrap();
        let mut record = ImageBuildRecord {
            id: operation.id.clone(),
            operation_id: operation.id.clone(),
            recipe_id: draft.id,
            version_id: version.id,
            content_digest: version.content_digest,
            asset_digests: vec!["digest".to_owned()],
            packer_version: None,
            proxmox_plugin_version: None,
            account_id: Some("account-1".to_owned()),
            node: "pve".to_owned(),
            storage_pool: "local-lvm".to_owned(),
            started_at: 1002,
            ended_at: None,
            outcome: "running".to_owned(),
            reason: None,
            template: None,
        };
        let mut forged = record.clone();
        forged.content_digest = "different".to_owned();
        assert!(recipes.start_build(&forged).await.is_err());
        recipes.start_build(&record).await.unwrap();
        assert!(recipes.start_build(&record).await.is_err());
        assert_eq!(recipes.get_build(&record.id).await.unwrap(), record);
        assert_eq!(
            recipes
                .list_builds(None, Some(&record.version_id))
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            recipes
                .list_builds(Some("another-recipe"), None)
                .await
                .unwrap()
                .is_empty()
        );
        for sql in [
            "DELETE FROM image_build_records",
            "UPDATE image_build_records SET content_digest = 'rewritten'",
            "UPDATE image_build_records SET outcome = 'failed', ended_at = 1003, node = 'other'",
            "INSERT OR REPLACE INTO image_build_records SELECT * FROM image_build_records",
            "UPDATE image_build_records SET outcome = 'succeeded', ended_at = 1003",
        ] {
            assert!(
                sqlx::query(sql).execute(store.pool()).await.is_err(),
                "{sql}"
            );
        }
        record.outcome = "failed".to_owned();
        record.ended_at = Some(1003);
        record.reason = Some("version_gate".to_owned());
        recipes.finish_build(&record).await.unwrap();
        assert_eq!(recipes.get_build(&record.id).await.unwrap(), record);
        assert!(recipes.finish_build(&record).await.is_err());
        assert!(
            sqlx::query("UPDATE image_build_records SET reason = 'changed'")
                .execute(store.pool())
                .await
                .is_err()
        );
        assert!(
            sqlx::query("DELETE FROM image_build_records")
                .execute(store.pool())
                .await
                .is_err()
        );
        // A worker recovery completion also closes a live build without
        // inferring success or an output from generic operation JSON.
        let operation = OperationRepository::new(store.pool().clone())
            .create("image.build", None, None, None, None)
            .await
            .unwrap();
        OperationRepository::new(store.pool().clone())
            .transition(&operation.id, "running")
            .await
            .unwrap();
        record.id = operation.id.clone();
        record.operation_id = operation.id.clone();
        record.outcome = "running".to_owned();
        record.ended_at = None;
        record.reason = None;
        recipes.start_build(&record).await.unwrap();
        OperationRepository::new(store.pool().clone())
            .complete(&operation.id, "failed", None, None)
            .await
            .unwrap();
        let recovered = recipes.get_build(&record.id).await.unwrap();
        assert_eq!(recovered.outcome, "failed");
        assert_eq!(
            recovered.reason.as_deref(),
            Some("operation_terminal_without_build_completion")
        );
        assert!(recovered.ended_at.is_some());
        assert!(recovered.template.is_none());
        let first = recipes
            .list_build_page(&BuildPageRequest {
                version: Some(record.version_id.clone()),
                limit: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(first.items.len(), 1);
        let cursor = first.next_cursor.unwrap();
        let second = recipes
            .list_build_page(&BuildPageRequest {
                version: Some(record.version_id.clone()),
                cursor: Some(cursor.clone()),
                limit: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(second.items.len(), 1);
        assert_ne!(first.items[0].id, second.items[0].id);
        assert!(first.items[0].id > second.items[0].id); // equal timestamps, deterministic tie break
        assert!(second.next_cursor.is_none());
        for query in [
            BuildPageRequest {
                cursor: Some("unknown".to_owned()),
                ..Default::default()
            },
            BuildPageRequest {
                recipe: Some("another-recipe".to_owned()),
                cursor: Some(cursor),
                ..Default::default()
            },
        ] {
            assert_eq!(
                recipes.list_build_page(&query).await.unwrap_err(),
                BUILD_CURSOR_INVALID
            );
        }
        assert_eq!(
            recipes
                .list_build_page(&BuildPageRequest {
                    limit: u32::MAX,
                    ..Default::default()
                })
                .await
                .unwrap()
                .limit,
            200
        );
        assert_eq!(
            recipes
                .list_build_page(&BuildPageRequest::default())
                .await
                .unwrap()
                .limit,
            50
        );
        // A newly failed build does not hide an artifact created before migration.
        let legacy = OperationRepository::new(store.pool().clone())
            .create(
                "image.build",
                None,
                None,
                None,
                Some(&serde_json::json!({"versionId": record.version_id}).to_string()),
            )
            .await
            .unwrap();
        OperationRepository::new(store.pool().clone())
            .transition(&legacy.id, "running")
            .await
            .unwrap();
        OperationRepository::new(store.pool().clone())
            .complete(
                &legacy.id,
                "succeeded",
                Some(r#"{"artifactId":"pve:123"}"#),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            recipes.template_vmid(&record.version_id).await.unwrap(),
            Some(123)
        );
        assert!(recipes.promoted_template_vmids().await.unwrap().is_empty());
        let successful = OperationRepository::new(store.pool().clone())
            .create("image.build", None, None, None, None)
            .await
            .unwrap();
        record.id = successful.id.clone();
        record.operation_id = successful.id;
        record.started_at = 1004;
        record.outcome = "running".to_owned();
        record.ended_at = None;
        record.reason = None;
        recipes.start_build(&record).await.unwrap();
        record.packer_version = Some("1.15".to_owned());
        record.proxmox_plugin_version = Some("1.2.4".to_owned());
        record.outcome = "succeeded".to_owned();
        record.ended_at = Some(1005);
        record.template = Some(ImageBuildTemplate {
            node: "pve".to_owned(),
            vmid: 124,
            name: "image".to_owned(),
        });
        recipes.finish_build(&record).await.unwrap();
        assert!(recipes.promoted_template_vmids().await.unwrap().is_empty());
        // A version promoted before migration 0039 carries no pin: its
        // newest successful build stays the clone source (legacy fallback).
        sqlx::query("UPDATE image_recipe_versions SET promoted_at = 1005, promoted_by = 'legacy' WHERE id = ?1")
            .bind(&record.version_id)
            .execute(store.pool())
            .await
            .unwrap();
        assert_eq!(
            recipes
                .get_version(&record.version_id)
                .await
                .unwrap()
                .promoted_build_id,
            None
        );
        assert_eq!(
            recipes.template_vmid(&record.version_id).await.unwrap(),
            Some(124)
        );
        assert_eq!(
            recipes.promoted_template_vmids().await.unwrap(),
            vec![123, 124]
        );
        let build_a = record.id.clone();
        recipes
            .promote(&record.version_id, &build_a, "fixture", 1006)
            .await
            .unwrap();
        assert_eq!(
            recipes
                .get_version(&record.version_id)
                .await
                .unwrap()
                .promoted_build_id
                .as_deref(),
            Some(build_a.as_str())
        );
        assert_eq!(
            recipes.promoted_template_vmids().await.unwrap(),
            vec![123, 124]
        );
        assert_eq!(
            recipes.template_vmid(&record.version_id).await.unwrap(),
            Some(124)
        );

        // Issue #281: a later successful rebuild into a new template is
        // evidence only. Lab keeps cloning the promoted build, and cleanup
        // protects both templates.
        let rebuild = OperationRepository::new(store.pool().clone())
            .create("image.build", None, None, None, None)
            .await
            .unwrap();
        record.id = rebuild.id.clone();
        record.operation_id = rebuild.id;
        record.started_at = 1007;
        record.outcome = "running".to_owned();
        record.ended_at = None;
        record.packer_version = None;
        record.proxmox_plugin_version = None;
        record.template = None;
        recipes.start_build(&record).await.unwrap();
        record.packer_version = Some("1.15".to_owned());
        record.proxmox_plugin_version = Some("1.2.4".to_owned());
        record.outcome = "succeeded".to_owned();
        record.ended_at = Some(1008);
        record.template = Some(ImageBuildTemplate {
            node: "pve".to_owned(),
            vmid: 125,
            name: "image".to_owned(),
        });
        recipes.finish_build(&record).await.unwrap();
        let build_b = record.id.clone();
        assert_eq!(
            recipes.template_vmid(&record.version_id).await.unwrap(),
            Some(124),
            "a rebuild must not move the promoted clone source"
        );
        assert_eq!(
            recipes.promoted_template_vmids().await.unwrap(),
            vec![123, 124, 125]
        );
        // A promotion can only pin the build the gate read: the stale build
        // is refused, and another version's or a failed build cannot be
        // pinned by any SQL writer.
        assert_eq!(
            recipes
                .promote(&record.version_id, &build_a, "fixture", 1009)
                .await
                .unwrap_err(),
            PROMOTION_BUILD_REJECTED
        );
        assert!(
            sqlx::query("UPDATE image_recipe_versions SET promoted_build_id = ?1 WHERE id = ?2")
                .bind(&operation.id)
                .bind(&record.version_id)
                .execute(store.pool())
                .await
                .is_err(),
            "a failed build cannot be pinned"
        );
        // Changing the clone source takes a new promotion.
        recipes
            .promote(&record.version_id, &build_b, "fixture", 1010)
            .await
            .unwrap();
        assert_eq!(
            recipes.template_vmid(&record.version_id).await.unwrap(),
            Some(125)
        );
        // A demotion (the statement `promote` runs for the recipe's other
        // versions) keeps the pin, so a lease pinned to the version before
        // the demotion keeps its clone source, and cleanup keeps protecting
        // it. The demoted version's other builds lose that protection.
        sqlx::query(
            "UPDATE image_recipe_versions SET promoted_at = NULL, promoted_by = NULL WHERE id = ?1",
        )
        .bind(&record.version_id)
        .execute(store.pool())
        .await
        .unwrap();
        assert_eq!(
            recipes.template_vmid(&record.version_id).await.unwrap(),
            Some(125)
        );
        assert_eq!(recipes.promoted_template_vmids().await.unwrap(), vec![125]);
        // A version row cannot be inserted already pinning a build.
        assert!(
            sqlx::query("INSERT INTO image_recipe_versions (id, recipe_id, name, description, content_digest, content, source, node, storage_pool, published_at, promoted_build_id) VALUES ('other@digest', 'other', 'other', '', ?2, '{}', 'clone', 'pve', 'local-lvm', 1, ?1)")
                .bind(&build_b)
                .bind(&record.content_digest)
                .execute(store.pool())
                .await
                .unwrap_err()
                .to_string()
                .contains("a promotion pins a successful build of the same version"),
            "an inserted version cannot pin another version's build"
        );
    }
}

#[cfg(test)]
mod target_account_tests {
    use super::*;
    #[tokio::test]
    async fn target_accounts_are_explicit_or_uniquely_matched_and_paths_are_never_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::Store::open(&dir.path().join("fleet.db"))
            .await
            .unwrap();
        let recipes = RecipeRepository::new(store.pool().clone());
        sqlx::query("INSERT INTO proxmox_accounts (id, name, host, port, token_id, created_at) VALUES ('one', 'one', 'pve.example.test', 8006, 'fixture@pve!builder', 1)")
            .execute(store.pool()).await.unwrap();
        let version = RecipeVersion {
            id: "version".to_owned(), recipe_id: "recipe".to_owned(), name: "image".to_owned(), description: String::new(),
            content_digest: "digest".to_owned(), content: r#"{"builders":[{"type":"proxmox-clone","proxmox_url":"https://pve.example.test:8006/api2/json/"}]}"#.to_owned(),
            source: RecipeSource::Clone, node: "pve".to_owned(), storage_pool: "local-lvm".to_owned(), published_at: 1, promoted_at: None, promoted_by: None, promoted_build_id: None, allow_insecure_tls: false,
        };
        assert_eq!(
            recipes
                .build_target_account(&version, None)
                .await
                .unwrap()
                .as_deref(),
            Some("one")
        );
        assert_eq!(
            recipes
                .build_target_account(&version, Some("one"))
                .await
                .unwrap()
                .as_deref(),
            Some("one")
        );
        assert!(
            recipes
                .build_target_account(&version, Some("unknown"))
                .await
                .is_err()
        );
        sqlx::query("INSERT INTO proxmox_accounts (id, name, host, port, token_id, created_at) VALUES ('two', 'two', 'pve.example.test', 8006, 'fixture@pve!other', 1)")
            .execute(store.pool()).await.unwrap();
        // Several matches without an explicit choice name the ambiguity.
        assert_eq!(
            recipes.build_target_account(&version, None).await,
            Err(fleet_application::images::TARGET_ACCOUNT_AMBIGUOUS.to_owned())
        );
        assert_eq!(
            recipes.build_target_account(&version, Some("two")).await,
            Ok(Some("two".to_owned()))
        );
    }
}
