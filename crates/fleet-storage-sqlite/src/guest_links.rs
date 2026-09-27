//! Durable, one-to-one operator-confirmed Proxmox guest associations.

use async_trait::async_trait;
use fleet_application::machine::{GuestLink, GuestLinkPort};
use fleet_application::operation::PortFailure;
use sqlx::SqlitePool;

/// SQLite adapter for confirmed machine/guest links.
#[derive(Debug)]
pub struct GuestLinkRepository {
    pool: SqlitePool,
}

impl GuestLinkRepository {
    /// Creates a repository on the controller database.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl GuestLinkPort for GuestLinkRepository {
    async fn get(&self, machine_id: &str) -> Result<Option<GuestLink>, PortFailure> {
        let row: Option<(String, String, String, i64)> = sqlx::query_as(
            "SELECT account_id, guest_kind, node, vmid FROM confirmed_guest_links WHERE machine_id = ?1",
        )
        .bind(machine_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|(account_id, guest_kind, node, vmid)| {
            u32::try_from(vmid)
                .map(|vmid| GuestLink {
                    account_id,
                    guest_kind,
                    node,
                    vmid,
                })
                .map_err(|error| PortFailure::Backend {
                    detail: format!("invalid stored VMID: {error}"),
                })
        })
        .transpose()
    }

    async fn confirm(&self, machine_id: &str, link: &GuestLink) -> Result<(), PortFailure> {
        let result = sqlx::query(
            "INSERT INTO confirmed_guest_links (machine_id, account_id, guest_kind, node, vmid, confirmed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(machine_id)
        .bind(&link.account_id)
        .bind(&link.guest_kind)
        .bind(&link.node)
        .bind(i64::from(link.vmid))
        .bind(fleet_core::SystemClock::now_unix_millis())
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(error)
                if matches!(
                    error
                        .as_database_error()
                        .map(sqlx::error::DatabaseError::kind),
                    Some(sqlx::error::ErrorKind::UniqueViolation)
                ) =>
            {
                Err(PortFailure::Conflict {
                    detail: "the machine or guest already has a confirmed link".to_owned(),
                })
            }
            Err(error)
                if matches!(
                    error
                        .as_database_error()
                        .map(sqlx::error::DatabaseError::kind),
                    Some(sqlx::error::ErrorKind::ForeignKeyViolation)
                ) =>
            {
                Err(PortFailure::Conflict {
                    detail: "the machine or Proxmox account no longer exists".to_owned(),
                })
            }
            Err(error) => Err(backend(error)),
        }
    }

    async fn unlink(&self, machine_id: &str) -> Result<(), PortFailure> {
        let deleted = sqlx::query("DELETE FROM confirmed_guest_links WHERE machine_id = ?1")
            .bind(machine_id)
            .execute(&self.pool)
            .await
            .map_err(backend)?;
        if deleted.rows_affected() == 0 {
            return Err(PortFailure::NotFound {
                what: format!("confirmed guest link for machine {machine_id:?}"),
            });
        }
        Ok(())
    }
}

#[allow(clippy::needless_pass_by_value)]
fn backend(error: sqlx::Error) -> PortFailure {
    PortFailure::Backend {
        detail: format!("guest link storage failed: {error}"),
    }
}
