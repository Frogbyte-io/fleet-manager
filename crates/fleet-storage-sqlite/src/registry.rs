//! The Registry read-model cache (FM-1012): rebuildable tables derived
//! from the active revision's resource snapshot. Nothing here is an
//! authority; [`RegistryCachePort::replace_cache`] swaps the whole cache
//! in one transaction and only while the revision it was derived from is
//! still the active one.

use sqlx::{QueryBuilder, Sqlite, SqlitePool};

use fleet_application::registry::{
    CacheState, EntryCursor, ReferenceCursor, RegistryCachePort, RegistryEntryFilter,
    RegistryEntryRecord, RegistryProjection, RegistryReference, RegistryRelationRecord,
    RegistryTarget, RegistryTypeRecord, TypeOrigin, normalize_key,
};
use fleet_application::source::ActiveRevision;

/// The Registry cache repository over the controller's pool.
#[derive(Debug, Clone)]
pub struct RegistryRepository {
    pool: SqlitePool,
}

impl RegistryRepository {
    /// Composes the repository over the pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

/// Loads the relations of every row in ONE query on the caller's
/// connection (inside its read transaction), so a page's entries and
/// relations come from the same snapshot of the cache.
async fn attach_relations(
    conn: &mut sqlx::SqliteConnection,
    rows: Vec<EntryRow>,
) -> Result<Vec<RegistryEntryRecord>, String> {
    let mut by_entry: std::collections::HashMap<(String, String), Vec<RegistryRelationRecord>> =
        std::collections::HashMap::new();
    if !rows.is_empty() {
        let mut query: QueryBuilder<Sqlite> = QueryBuilder::new(
            "SELECT entry_type, entry_key_norm, relation_type, target_class, target_ref \
             FROM registry_relations WHERE (entry_type, entry_key_norm) IN (VALUES ",
        );
        let mut separated = query.separated(", ");
        for row in &rows {
            separated.push("(");
            separated.push_bind_unseparated(&row.0);
            separated.push_unseparated(", ");
            separated.push_bind_unseparated(normalize_key(&row.1));
            separated.push_unseparated(")");
        }
        query.push(") ORDER BY relation_type, target_class, target_ref_norm");
        let found: Vec<(String, String, String, String, String)> = query
            .build_query_as()
            .fetch_all(&mut *conn)
            .await
            .map_err(|error| format!("the registry relation read failed: {error}"))?;
        for (entry_type, key_norm, relation_type, class, reference) in found {
            by_entry
                .entry((entry_type, key_norm))
                .or_default()
                .push(RegistryRelationRecord {
                    relation_type,
                    target: RegistryTarget { class, reference },
                });
        }
    }
    rows.into_iter()
        .map(|row| {
            let relations = by_entry
                .remove(&(row.0.clone(), normalize_key(&row.1)))
                .unwrap_or_default();
            entry_from(row, relations)
        })
        .collect()
}

type EntryRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);

macro_rules! entry_select {
    () => {
        "SELECT e.entry_type, e.entry_key, e.resource_id, e.name, e.fields_json, \
         e.tags_json, e.links_json, e.notes, e.source_path FROM registry_entries e"
    };
}

fn corrupt(error: &serde_json::Error) -> String {
    format!("a cached registry value is corrupt: {error}")
}

fn entry_from(
    row: EntryRow,
    relations: Vec<RegistryRelationRecord>,
) -> Result<RegistryEntryRecord, String> {
    let (entry_type, key, resource_id, name, fields, tags, links, notes, source_path) = row;
    Ok(RegistryEntryRecord {
        entry_type,
        key,
        resource_id,
        name,
        fields: serde_json::from_str(&fields).map_err(|e| corrupt(&e))?,
        tags: serde_json::from_str(&tags).map_err(|e| corrupt(&e))?,
        links: serde_json::from_str(&links).map_err(|e| corrupt(&e))?,
        notes,
        relations,
        source_path,
    })
}

/// Writes one entry with its tags and relations.
async fn insert_entry(
    tx: &mut sqlx::SqliteConnection,
    entry: &RegistryEntryRecord,
) -> Result<(), String> {
    let write = |error: sqlx::Error| format!("the registry cache write failed: {error}");
    sqlx::query(
        "INSERT INTO registry_entries (entry_type, entry_key, entry_key_norm, resource_id, \
         name, fields_json, tags_json, links_json, notes, source_path, search_text) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )
    .bind(&entry.entry_type)
    .bind(&entry.key)
    .bind(normalize_key(&entry.key))
    .bind(&entry.resource_id)
    .bind(&entry.name)
    .bind(entry.fields.to_string())
    .bind(serde_json::to_string(&entry.tags).map_err(|e| corrupt(&e))?)
    .bind(entry.links.to_string())
    .bind(entry.notes.as_deref())
    .bind(entry.source_path.as_deref())
    .bind(entry.search_text())
    .execute(&mut *tx)
    .await
    .map_err(write)?;
    for tag in &entry.tags {
        sqlx::query(
            "INSERT OR IGNORE INTO registry_entry_tags (entry_type, entry_key_norm, tag) \
             VALUES (?1, ?2, ?3)",
        )
        .bind(&entry.entry_type)
        .bind(normalize_key(&entry.key))
        .bind(tag)
        .execute(&mut *tx)
        .await
        .map_err(write)?;
    }
    for relation in &entry.relations {
        sqlx::query(
            "INSERT OR IGNORE INTO registry_relations \
             (entry_type, entry_key_norm, relation_type, target_class, target_ref, \
              target_ref_norm) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&entry.entry_type)
        .bind(normalize_key(&entry.key))
        .bind(&relation.relation_type)
        .bind(&relation.target.class)
        .bind(&relation.target.reference)
        .bind(relation.target.normalized_reference())
        .execute(&mut *tx)
        .await
        .map_err(write)?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl RegistryCachePort for RegistryRepository {
    async fn cache_state(&self) -> Result<Option<CacheState>, String> {
        let row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT commit_sha, content_digest, builtin_fingerprint FROM registry_cache_state \
             LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| format!("the registry cache state read failed: {error}"))?;
        Ok(row.map(
            |(commit_sha, content_digest, builtin_fingerprint)| CacheState {
                revision: ActiveRevision {
                    commit_sha,
                    content_digest,
                },
                builtin_fingerprint,
            },
        ))
    }

    async fn replace_cache(
        &self,
        state: &CacheState,
        projection: &RegistryProjection,
    ) -> Result<bool, String> {
        let write = |error: sqlx::Error| format!("the registry cache write failed: {error}");
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(write)?;
        // The cache may only mirror the revision that is active at the
        // moment it is written: an activation that raced the rebuild
        // makes this derivation stale.
        let still_active: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM source_active_revision WHERE commit_sha = ?1 AND content_digest = ?2",
        )
        .bind(&state.revision.commit_sha)
        .bind(&state.revision.content_digest)
        .fetch_optional(&mut *tx)
        .await
        .map_err(write)?;
        if still_active.is_none() {
            tx.rollback().await.map_err(write)?;
            return Ok(false);
        }
        for clear in [
            "DELETE FROM registry_relations",
            "DELETE FROM registry_entry_tags",
            "DELETE FROM registry_entries",
            "DELETE FROM registry_types",
            "DELETE FROM registry_cache_state",
        ] {
            sqlx::query(clear).execute(&mut *tx).await.map_err(write)?;
        }
        for record in &projection.types {
            sqlx::query(
                "INSERT INTO registry_types (name, origin, resource_id, display_name, key_field, \
                 relations_json, spec_json, source_path) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .bind(&record.name)
            .bind(record.origin.as_str())
            .bind(record.resource_id.as_deref())
            .bind(&record.display_name)
            .bind(&record.key_field)
            .bind(serde_json::to_string(&record.relations).map_err(|e| corrupt(&e))?)
            .bind(record.spec.to_string())
            .bind(record.source_path.as_deref())
            .execute(&mut *tx)
            .await
            .map_err(write)?;
        }
        for entry in &projection.entries {
            insert_entry(&mut tx, entry).await?;
        }
        sqlx::query(
            "INSERT INTO registry_cache_state \
             (singleton, commit_sha, content_digest, builtin_fingerprint, built_at) \
             VALUES ('cache', ?1, ?2, ?3, ?4)",
        )
        .bind(&state.revision.commit_sha)
        .bind(&state.revision.content_digest)
        .bind(&state.builtin_fingerprint)
        .bind(fleet_core::SystemClock::now_unix_millis())
        .execute(&mut *tx)
        .await
        .map_err(write)?;
        tx.commit().await.map_err(write)?;
        Ok(true)
    }

    async fn list_types(&self) -> Result<Vec<RegistryTypeRecord>, String> {
        #[allow(clippy::type_complexity)]
        let rows: Vec<(
            String,
            String,
            Option<String>,
            String,
            String,
            String,
            String,
            Option<String>,
            i64,
        )> = sqlx::query_as(
            "SELECT t.name, t.origin, t.resource_id, t.display_name, t.key_field, \
             t.relations_json, t.spec_json, t.source_path, \
             (SELECT COUNT(*) FROM registry_entries e WHERE e.entry_type = t.name) \
             FROM registry_types t ORDER BY t.name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("the registry type read failed: {error}"))?;
        rows.into_iter()
            .map(
                |(
                    name,
                    origin,
                    resource_id,
                    display_name,
                    key_field,
                    relations,
                    spec,
                    source_path,
                    entry_count,
                )| {
                    Ok(RegistryTypeRecord {
                        origin: TypeOrigin::parse(&origin)
                            .ok_or("a cached registry type has an unknown origin")?,
                        name,
                        resource_id,
                        display_name,
                        key_field,
                        relations: serde_json::from_str(&relations).map_err(|e| corrupt(&e))?,
                        spec: serde_json::from_str(&spec).map_err(|e| corrupt(&e))?,
                        source_path,
                        entry_count,
                    })
                },
            )
            .collect()
    }

    async fn list_entries(
        &self,
        filter: &RegistryEntryFilter,
        after: Option<&EntryCursor>,
        limit: i64,
    ) -> Result<Vec<RegistryEntryRecord>, String> {
        let mut query: QueryBuilder<Sqlite> =
            QueryBuilder::new(concat!(entry_select!(), " WHERE 1 = 1"));
        if let Some(entry_type) = &filter.entry_type {
            query.push(" AND e.entry_type = ").push_bind(entry_type);
        }
        if let Some(tag) = &filter.tag {
            query
                .push(
                    " AND EXISTS (SELECT 1 FROM registry_entry_tags t \
                     WHERE t.entry_type = e.entry_type AND t.entry_key_norm = e.entry_key_norm \
                     AND t.tag = ",
                )
                .push_bind(tag)
                .push(")");
        }
        if let Some(text) = &filter.query {
            // `instr` on the lowercased text: a literal substring match,
            // so `%` and `_` in the query need no escaping.
            query
                .push(" AND instr(e.search_text, ")
                .push_bind(text.to_lowercase())
                .push(") > 0");
        }
        if let Some(target) = &filter.target {
            query
                .push(
                    " AND EXISTS (SELECT 1 FROM registry_relations r \
                     WHERE r.entry_type = e.entry_type AND r.entry_key_norm = e.entry_key_norm \
                     AND r.target_class = ",
                )
                .push_bind(&target.class)
                .push(" AND r.target_ref_norm = ")
                .push_bind(target.normalized_reference());
            if let Some(relation) = &filter.relation {
                query.push(" AND r.relation_type = ").push_bind(relation);
            }
            query.push(")");
        }
        if let Some(cursor) = after {
            query
                .push(" AND (e.entry_type, e.entry_key_norm) > (")
                .push_bind(&cursor.entry_type)
                .push(", ")
                .push_bind(normalize_key(&cursor.key))
                .push(")");
        }
        query
            .push(" ORDER BY e.entry_type, e.entry_key_norm LIMIT ")
            .push_bind(limit);
        // One read transaction: the page and its relations are one snapshot.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| format!("the registry read failed: {error}"))?;
        let rows: Vec<EntryRow> = query
            .build_query_as()
            .fetch_all(&mut *tx)
            .await
            .map_err(|error| format!("the registry entry read failed: {error}"))?;
        attach_relations(&mut tx, rows).await
    }

    async fn get_entry(
        &self,
        entry_type: &str,
        key: &str,
    ) -> Result<Option<RegistryEntryRecord>, String> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| format!("the registry read failed: {error}"))?;
        let row: Option<EntryRow> = sqlx::query_as(concat!(
            entry_select!(),
            " WHERE e.entry_type = ?1 AND e.entry_key_norm = ?2"
        ))
        .bind(entry_type)
        .bind(normalize_key(key))
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| format!("the registry entry read failed: {error}"))?;
        match row {
            None => Ok(None),
            Some(row) => Ok(attach_relations(&mut tx, vec![row]).await?.pop()),
        }
    }

    async fn list_references(
        &self,
        target: &RegistryTarget,
        relation: Option<&str>,
        after: Option<&ReferenceCursor>,
        limit: i64,
    ) -> Result<Vec<RegistryReference>, String> {
        let mut query: QueryBuilder<Sqlite> = QueryBuilder::new(
            "SELECT r.relation_type, r.entry_type, e.entry_key, e.name, e.source_path \
             FROM registry_relations r \
             JOIN registry_entries e \
               ON e.entry_type = r.entry_type AND e.entry_key_norm = r.entry_key_norm \
             WHERE r.target_class = ",
        );
        query
            .push_bind(&target.class)
            .push(" AND r.target_ref_norm = ")
            .push_bind(target.normalized_reference());
        if let Some(relation) = relation {
            query.push(" AND r.relation_type = ").push_bind(relation);
        }
        if let Some(cursor) = after {
            query
                .push(" AND (r.entry_type, r.entry_key_norm, r.relation_type) > (")
                .push_bind(&cursor.entry_type)
                .push(", ")
                .push_bind(normalize_key(&cursor.key))
                .push(", ")
                .push_bind(&cursor.relation_type)
                .push(")");
        }
        query
            .push(" ORDER BY r.entry_type, r.entry_key_norm, r.relation_type LIMIT ")
            .push_bind(limit);
        let rows: Vec<(String, String, String, String, Option<String>)> = query
            .build_query_as()
            .fetch_all(&self.pool)
            .await
            .map_err(|error| format!("the registry reference read failed: {error}"))?;
        Ok(rows
            .into_iter()
            .map(
                |(relation_type, entry_type, entry_key, entry_name, source_path)| {
                    RegistryReference {
                        relation_type,
                        entry_type,
                        entry_key,
                        entry_name,
                        source_path,
                    }
                },
            )
            .collect())
    }
}
