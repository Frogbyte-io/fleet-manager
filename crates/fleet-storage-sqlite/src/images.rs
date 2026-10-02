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

use fleet_application::images::{NewRecipe, Recipe, RecipeContent, RecipePort, RecipeVersion};
use fleet_application::lab::ImageArtifactPort;
use fleet_core::RecipeSource;

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
        })
    }
}

#[async_trait]
impl RecipePort for RecipeRepository {
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
            "INSERT INTO image_recipe_versions (id, recipe_id, name, description, content_digest, content, source, node, storage_pool, published_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
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
        sqlx::query("SELECT id, recipe_id, name, description, content_digest, content, source, node, storage_pool, published_at, promoted_at, promoted_by FROM image_recipe_versions WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("get_version failed: {error}"))?
            .map(|row| Self::row_to_version(&row))
            .transpose()?
            .ok_or_else(|| format!("version {id} not found"))
    }

    async fn list_versions(&self, recipe_id: &str) -> Result<Vec<RecipeVersion>, String> {
        let rows = sqlx::query("SELECT id, recipe_id, name, description, content_digest, content, source, node, storage_pool, published_at, promoted_at, promoted_by FROM image_recipe_versions WHERE recipe_id = ?1 ORDER BY published_at DESC, id DESC")
            .bind(recipe_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| format!("list_versions failed: {error}"))?;
        rows.iter().map(Self::row_to_version).collect()
    }

    async fn promote(
        &self,
        version_id: &str,
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
        sqlx::query(
            "UPDATE image_recipe_versions SET promoted_at = NULL, promoted_by = NULL              WHERE recipe_id = ?1 AND promoted_at IS NOT NULL AND id != ?2",
        )
        .bind(&recipe_id)
        .bind(version_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("promote failed: {error}"))?;
        sqlx::query(
            "UPDATE image_recipe_versions SET promoted_at = ?3, promoted_by = ?2 WHERE id = ?1",
        )
        .bind(version_id)
        .bind(promoted_by)
        .bind(promoted_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("promote failed: {error}"))?;
        let row = sqlx::query("SELECT id, recipe_id, name, description, content_digest, content, source, node, storage_pool, published_at, promoted_at, promoted_by FROM image_recipe_versions WHERE id = ?1")
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
        let row = sqlx::query("SELECT id, recipe_id, name, description, content_digest, content, source, node, storage_pool, published_at, promoted_at, promoted_by FROM image_recipe_versions WHERE recipe_id = ?1 AND promoted_at IS NOT NULL LIMIT 1")
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
/// the cluster.
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
    vmid.parse::<u32>().ok().filter(|vmid| *vmid >= 100)
}

#[async_trait]
impl ImageArtifactPort for RecipeRepository {
    async fn template_vmid(&self, image_version_id: &str) -> Result<Option<u32>, String> {
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
        let promoted: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM image_recipe_versions WHERE promoted_at IS NOT NULL",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("promoted image versions failed: {error}"))?;
        let mut vmids: Vec<u32> = self
            .successful_builds()
            .await?
            .iter()
            .filter(|(payload, _)| {
                built_version(payload.as_deref()).is_some_and(|version| promoted.contains(&version))
            })
            .filter_map(|(_, result)| recorded_artifact(result.as_deref()))
            .filter_map(|artifact| artifact_vmid(&artifact))
            .collect();
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
        for invalid in [
            "",
            "99",
            "pve:",
            ":120",
            "local:vztmpl/base.tar",
            "a:b:120",
            "+120",
            "4294967296",
        ] {
            assert_eq!(artifact_vmid(invalid), None, "{invalid}");
        }
    }
}
