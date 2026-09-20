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
            "INSERT INTO proxmox_accounts (id, name, host, port, token_id, fingerprint, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, '', ?6)",
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
        sqlx::query("SELECT id, name, host, port, token_id, fingerprint, created_at FROM proxmox_accounts WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("get failed: {error}"))?
            .map(|row| Self::row_to_account(&row))
            .ok_or_else(|| format!("account {id} not found"))
    }

    async fn list(&self) -> Result<Vec<ProxmoxAccount>, String> {
        let rows = sqlx::query("SELECT id, name, host, port, token_id, fingerprint, created_at FROM proxmox_accounts ORDER BY created_at DESC")
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
        let value = fingerprint.unwrap_or_default();
        sqlx::query("UPDATE proxmox_accounts SET fingerprint = ?2 WHERE id = ?1")
            .bind(id)
            .bind(&value)
            .execute(&self.pool)
            .await
            .map_err(|error| format!("set_fingerprint failed: {error}"))?;
        self.get(id).await
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

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error
            .as_database_error()
            .map(sqlx::error::DatabaseError::kind),
        Some(sqlx::error::ErrorKind::UniqueViolation)
    )
}
