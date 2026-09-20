//! The Proxmox account repository: the SQLite implementation of the
//! application's [`ProxmoxAccountPort`].
//!
//! Accounts reference their token secret through the encrypted secret
//! store by account id; nothing here ever touches secret values. The
//! fingerprint column is the pinned SHA-256 of the host certificate, empty
//! until the trust step confirms it.

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;
use uuid::Uuid;

use fleet_application::proxmox::{NewProxmoxAccount, ProxmoxAccount, ProxmoxAccountPort};

/// The Proxmox account repository over a pool.
#[derive(Debug)]
pub struct ProxmoxAccountRepository {
    pool: SqlitePool,
}

impl ProxmoxAccountRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_account(row: &sqlx::sqlite::SqliteRow) -> ProxmoxAccount {
        let fingerprint: String = row.get("fingerprint");
        ProxmoxAccount {
            id: row.get("id"),
            name: row.get("name"),
            host: row.get("host"),
            port: u16::try_from(row.get::<i64, _>("port")).unwrap_or(8006),
            token_id: row.get("token_id"),
            fingerprint: (!fingerprint.is_empty()).then_some(fingerprint),
            observed_fingerprint: {
                let observed: String = row.get("observed_fingerprint");
                (!observed.is_empty()).then_some(observed)
            },
            created_at: row.get("created_at"),
        }
    }
}

#[async_trait]
impl ProxmoxAccountPort for ProxmoxAccountRepository {
    async fn create(&self, account: &NewProxmoxAccount) -> Result<ProxmoxAccount, String> {
        let id = Uuid::now_v7().to_string();
        let now = fleet_core::SystemClock::now_unix_millis();
        let port = account.port.unwrap_or(8006);
        let result = sqlx::query(
            "INSERT INTO proxmox_accounts (id, name, host, port, token_id, fingerprint, observed_fingerprint, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, '', '', ?6)",
        )
        .bind(&id)
        .bind(&account.name)
        .bind(&account.host)
        .bind(i64::from(port))
        .bind(&account.token_id)
        .bind(now)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => self.get(&id).await,
            Err(error) if is_unique_violation(&error) => Err(format!(
                "the account name {:?} is already taken",
                account.name
            )),
            Err(error) => Err(format!("create failed: {error}")),
        }
    }

    async fn get(&self, id: &str) -> Result<ProxmoxAccount, String> {
        sqlx::query("SELECT id, name, host, port, token_id, fingerprint, observed_fingerprint, created_at FROM proxmox_accounts WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("get failed: {error}"))?
            .map(|row| Self::row_to_account(&row))
            .ok_or_else(|| format!("account {id} not found"))
    }

    async fn list(&self) -> Result<Vec<ProxmoxAccount>, String> {
        let rows = sqlx::query("SELECT id, name, host, port, token_id, fingerprint, observed_fingerprint, created_at FROM proxmox_accounts ORDER BY created_at DESC, id DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|error| format!("list failed: {error}"))?;
        Ok(rows.iter().map(Self::row_to_account).collect())
    }

    async fn set_fingerprint(
        &self,
        id: &str,
        fingerprint: Option<String>,
    ) -> Result<ProxmoxAccount, String> {
        self.update_fingerprint_column(id, "fingerprint", fingerprint, "set_fingerprint")
            .await
    }

    async fn set_observed_fingerprint(
        &self,
        id: &str,
        fingerprint: Option<String>,
    ) -> Result<ProxmoxAccount, String> {
        self.update_fingerprint_column(
            id,
            "observed_fingerprint",
            fingerprint,
            "set_observed_fingerprint",
        )
        .await
    }

    async fn delete(&self, id: &str) -> Result<(), String> {
        let result = sqlx::query("DELETE FROM proxmox_accounts WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|error| format!("delete failed: {error}"))?;
        if result.rows_affected() == 0 {
            return Err(format!("account {id} not found"));
        }
        Ok(())
    }
}

impl ProxmoxAccountRepository {
    /// Updates one fingerprint column and reads the row back inside one
    /// `BEGIN IMMEDIATE` transaction, so a racing confirmation cannot
    /// return (and audit) another caller's fingerprint.
    async fn update_fingerprint_column(
        &self,
        id: &str,
        column: &str,
        fingerprint: Option<String>,
        context: &str,
    ) -> Result<ProxmoxAccount, String> {
        // Two fixed queries rather than dynamic SQL: the column comes from
        // the call site, and fixed strings keep the audit surface obvious.
        let value = fingerprint.unwrap_or_default();
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| format!("{context} failed: {error}"))?;
        let updated = match column {
            "fingerprint" => {
                sqlx::query("UPDATE proxmox_accounts SET fingerprint = ?2 WHERE id = ?1")
                    .bind(id)
                    .bind(&value)
                    .execute(&mut *transaction)
                    .await
                    .map_err(|error| format!("{context} failed: {error}"))?
            }
            "observed_fingerprint" => {
                sqlx::query("UPDATE proxmox_accounts SET observed_fingerprint = ?2 WHERE id = ?1")
                    .bind(id)
                    .bind(&value)
                    .execute(&mut *transaction)
                    .await
                    .map_err(|error| format!("{context} failed: {error}"))?
            }
            other => return Err(format!("{context} failed: unknown column {other:?}")),
        };
        if updated.rows_affected() == 0 {
            return Err(format!("account {id} not found"));
        }
        let row = sqlx::query("SELECT id, name, host, port, token_id, fingerprint, observed_fingerprint, created_at FROM proxmox_accounts WHERE id = ?1")
            .bind(id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| format!("{context} failed: {error}"))?;
        let account = Self::row_to_account(&row);
        transaction
            .commit()
            .await
            .map_err(|error| format!("{context} failed: {error}"))?;
        Ok(account)
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
