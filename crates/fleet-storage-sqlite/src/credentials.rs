//! The delegated credential repository: the SQLite implementation of the
//! application's [`CredentialStore`] (ADR 0011). It stores the SHA-256 of a
//! token and never the token.

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;

use fleet_application::credentials::{CredentialStore, DelegatedCredential, StoredCredential};

/// The credential repository over a pool.
#[derive(Debug)]
pub struct CredentialRepository {
    pool: SqlitePool,
}

impl CredentialRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_credential(row: &sqlx::sqlite::SqliteRow) -> Result<DelegatedCredential, String> {
        let list = |column: &str| -> Result<Vec<String>, String> {
            serde_json::from_str(&row.get::<String, _>(column))
                .map_err(|error| format!("a credential's {column} are unreadable: {error}"))
        };
        Ok(DelegatedCredential {
            id: row.get("id"),
            owner: row.get("owner"),
            label: row.get("label"),
            templates: list("templates")?,
            versions: list("versions")?,
            issued_by: row.get("issued_by"),
            issued_at: row.get("issued_at"),
            expires_at: row.get("expires_at"),
            revoked_at: row.get("revoked_at"),
            revoked_by: row.get("revoked_by"),
        })
    }
}

#[async_trait]
impl CredentialStore for CredentialRepository {
    async fn insert(
        &self,
        credential: &DelegatedCredential,
        token_hash: &str,
    ) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO delegated_credentials \
             (id, token_hash, owner, label, templates, versions, issued_by, issued_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&credential.id)
        .bind(token_hash)
        .bind(&credential.owner)
        .bind(&credential.label)
        .bind(serde_json::to_string(&credential.templates).map_err(|error| error.to_string())?)
        .bind(serde_json::to_string(&credential.versions).map_err(|error| error.to_string())?)
        .bind(&credential.issued_by)
        .bind(credential.issued_at)
        .bind(credential.expires_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("credential insert failed: {error}"))
    }

    async fn list(&self) -> Result<Vec<DelegatedCredential>, String> {
        sqlx::query("SELECT * FROM delegated_credentials ORDER BY issued_at DESC, id DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|error| format!("credential list failed: {error}"))?
            .iter()
            .map(Self::row_to_credential)
            .collect()
    }

    async fn get(&self, id: &str) -> Result<Option<DelegatedCredential>, String> {
        sqlx::query("SELECT * FROM delegated_credentials WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("credential read failed: {error}"))?
            .as_ref()
            .map(Self::row_to_credential)
            .transpose()
    }

    async fn find_by_hash(&self, token_hash: &str) -> Result<Option<StoredCredential>, String> {
        let Some(row) = sqlx::query("SELECT * FROM delegated_credentials WHERE token_hash = ?1")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("credential lookup failed: {error}"))?
        else {
            return Ok(None);
        };
        Ok(Some(StoredCredential {
            credential: Self::row_to_credential(&row)?,
            token_hash: row.get("token_hash"),
        }))
    }

    async fn revoke(
        &self,
        id: &str,
        revoked_by: &str,
        now: i64,
    ) -> Result<Option<DelegatedCredential>, String> {
        // The first revocation wins: re-revoking keeps its time and actor.
        sqlx::query(
            "UPDATE delegated_credentials SET revoked_at = ?2, revoked_by = ?3 \
             WHERE id = ?1 AND revoked_at IS NULL",
        )
        .bind(id)
        .bind(now)
        .bind(revoked_by)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("credential revoke failed: {error}"))?;
        self.get(id).await
    }
}
