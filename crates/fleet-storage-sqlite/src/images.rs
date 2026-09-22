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
            content_digest: row.get("content_digest"),
            content: row.get("content"),
            source: RecipeSource::from_id(&source)?,
            node: row.get("node"),
            storage_pool: row.get("storage_pool"),
            published_at: row.get("published_at"),
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
        // The draft records what it published from; the version row is
        // immutable (insert-only, unique on recipe+digest).
        sqlx::query("UPDATE image_recipes SET published_from = ?2 WHERE id = ?1")
            .bind(recipe_id)
            .bind(&version.id)
            .execute(&self.pool)
            .await
            .map_err(|error| format!("publish failed: {error}"))?;
        let result = sqlx::query(
            "INSERT INTO image_recipe_versions (id, recipe_id, name, content_digest, content, source, node, storage_pool, published_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
             ON CONFLICT (recipe_id, content_digest) DO NOTHING",
        )
        .bind(&version.id)
        .bind(&version.recipe_id)
        .bind(&version.name)
        .bind(&version.content_digest)
        .bind(&version.content)
        .bind(version.source.id())
        .bind(&version.node)
        .bind(&version.storage_pool)
        .bind(version.published_at)
        .execute(&self.pool)
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
        sqlx::query("SELECT id, recipe_id, name, content_digest, content, source, node, storage_pool, published_at FROM image_recipe_versions WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("get_version failed: {error}"))?
            .map(|row| Self::row_to_version(&row))
            .transpose()?
            .ok_or_else(|| format!("version {id} not found"))
    }

    async fn list_versions(&self, recipe_id: &str) -> Result<Vec<RecipeVersion>, String> {
        let rows = sqlx::query("SELECT id, recipe_id, name, content_digest, content, source, node, storage_pool, published_at FROM image_recipe_versions WHERE recipe_id = ?1 ORDER BY published_at DESC, id DESC")
            .bind(recipe_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| format!("list_versions failed: {error}"))?;
        rows.iter().map(Self::row_to_version).collect()
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
