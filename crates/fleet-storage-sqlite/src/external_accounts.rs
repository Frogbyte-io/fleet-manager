//! The external account repository: the SQLite implementation of the
//! application's [`ExternalAccountPort`] (FM-1001).
//!
//! Accounts reference their token through the encrypted secret store by
//! account id; nothing here touches secret values.

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;
use uuid::Uuid;

use fleet_application::external_accounts::{
    ExternalAccount, ExternalAccountPort, NewExternalAccount, StoredProbe,
};
use fleet_core::ExternalProviderKind;

/// The external account repository over a pool.
#[derive(Debug)]
pub struct ExternalAccountRepository {
    pool: SqlitePool,
}

impl ExternalAccountRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_account(row: &sqlx::sqlite::SqliteRow) -> Result<ExternalAccount, String> {
        let kind: String = row.get("kind");
        let scope: String = row.get("scope_id");
        let probe: Option<String> = row.get("last_probe");
        Ok(ExternalAccount {
            id: row.get("id"),
            kind: kind
                .parse::<ExternalProviderKind>()
                .map_err(|error| error.to_string())?,
            label: row.get("label"),
            base_url: row.get("base_url"),
            scope_id: (!scope.is_empty()).then_some(scope),
            notes: row.get("notes"),
            // A row whose probe JSON is unreadable reports no probe rather
            // than failing the whole list.
            last_probe: probe.and_then(|json| serde_json::from_str::<StoredProbe>(&json).ok()),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
}

#[async_trait]
impl ExternalAccountPort for ExternalAccountRepository {
    async fn create(&self, account: &NewExternalAccount) -> Result<ExternalAccount, String> {
        let id = Uuid::now_v7().to_string();
        let now = fleet_core::SystemClock::now_unix_millis();
        let result = sqlx::query(
            "INSERT INTO external_accounts (id, kind, label, base_url, scope_id, notes, last_probe, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?7)",
        )
        .bind(&id)
        .bind(account.kind.id())
        .bind(&account.label)
        .bind(&account.base_url)
        .bind(account.scope_id.as_deref().unwrap_or(""))
        .bind(&account.notes)
        .bind(now)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => self.get(&id).await,
            Err(error) if is_unique_violation(&error) => Err(taken(account)),
            Err(error) => Err(format!("create failed: {error}")),
        }
    }

    async fn get(&self, id: &str) -> Result<ExternalAccount, String> {
        let row = sqlx::query(
            "SELECT id, kind, label, base_url, scope_id, notes, last_probe, created_at, updated_at FROM external_accounts WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| format!("get failed: {error}"))?
        .ok_or_else(|| format!("account {id} not found"))?;
        Self::row_to_account(&row)
    }

    async fn list(&self) -> Result<Vec<ExternalAccount>, String> {
        let rows = sqlx::query(
            "SELECT id, kind, label, base_url, scope_id, notes, last_probe, created_at, updated_at FROM external_accounts ORDER BY created_at DESC, id DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("list failed: {error}"))?;
        rows.iter().map(Self::row_to_account).collect()
    }

    async fn update(
        &self,
        id: &str,
        account: &NewExternalAccount,
        clear_probe: bool,
    ) -> Result<ExternalAccount, String> {
        let now = fleet_core::SystemClock::now_unix_millis();
        let result = sqlx::query(
            "UPDATE external_accounts SET label = ?2, base_url = ?3, scope_id = ?4, notes = ?5, \
             last_probe = CASE WHEN ?6 THEN NULL ELSE last_probe END, updated_at = ?7 WHERE id = ?1",
        )
        .bind(id)
        .bind(&account.label)
        .bind(&account.base_url)
        .bind(account.scope_id.as_deref().unwrap_or(""))
        .bind(&account.notes)
        .bind(clear_probe)
        .bind(now)
        .execute(&self.pool)
        .await;
        match result {
            Ok(done) if done.rows_affected() == 0 => Err(format!("account {id} not found")),
            Ok(_) => {
                if clear_probe {
                    // The subject changed, so a cached discovery of the old
                    // instance would be a lie (FM-1030).
                    sqlx::query("DELETE FROM coolify_observations WHERE account_id = ?1")
                        .bind(id)
                        .execute(&self.pool)
                        .await
                        .map_err(|error| format!("observation clear failed: {error}"))?;
                }
                self.get(id).await
            }
            Err(error) if is_unique_violation(&error) => Err(taken(account)),
            Err(error) => Err(format!("update failed: {error}")),
        }
    }

    async fn record_probe(
        &self,
        id: &str,
        probe: Option<&StoredProbe>,
    ) -> Result<ExternalAccount, String> {
        let json = probe
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| format!("probe encode failed: {error}"))?;
        let done = sqlx::query("UPDATE external_accounts SET last_probe = ?2 WHERE id = ?1")
            .bind(id)
            .bind(json)
            .execute(&self.pool)
            .await
            .map_err(|error| format!("record_probe failed: {error}"))?;
        if done.rows_affected() == 0 {
            return Err(format!("account {id} not found"));
        }
        self.get(id).await
    }

    async fn delete(&self, id: &str) -> Result<(), String> {
        let done = sqlx::query("DELETE FROM external_accounts WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|error| format!("delete failed: {error}"))?;
        if done.rows_affected() == 0 {
            return Err(format!("account {id} not found"));
        }
        Ok(())
    }
}

fn taken(account: &NewExternalAccount) -> String {
    format!(
        "the {} account label {:?} is already taken",
        account.kind, account.label
    )
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error
            .as_database_error()
            .map(sqlx::error::DatabaseError::kind),
        Some(sqlx::error::ErrorKind::UniqueViolation)
    )
}
