//! The SQLite adapter of the persistent-guest marker (#489).

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;

use fleet_application::persistent::{
    PersistentGuest, PersistentGuestPort, PersistentState, RequestedBy,
};

/// Persistent guest markers over a pool.
#[derive(Debug)]
pub struct PersistentGuestRepository {
    pool: SqlitePool,
}

impl PersistentGuestRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn read(row: &sqlx::sqlite::SqliteRow) -> Result<PersistentGuest, String> {
    let state: String = row.get("state");
    let vmid: i64 = row.get("vmid");
    Ok(PersistentGuest {
        account_id: row.get("account_id"),
        vmid: u32::try_from(vmid).map_err(|_| "a stored VMID is out of range".to_owned())?,
        name: row.get("name"),
        node: row.get("node"),
        image_version_id: row.get("image_version_id"),
        machine_id: row.get("machine_id"),
        cloned: row.get::<i64, _>("cloned") != 0,
        state: PersistentState::from_id(&state)
            .ok_or_else(|| "a stored persistent state is unknown".to_owned())?,
        step: row.get("step"),
        operation_id: row.get("operation_id"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn owner_from(row: &sqlx::sqlite::SqliteRow) -> RequestedBy {
    RequestedBy {
        principal: row.get("owner"),
        purpose: row.get::<Option<String>, _>("purpose").unwrap_or_default(),
        request_id: row
            .get::<Option<String>, _>("request_id")
            .unwrap_or_default(),
        approved_by: None,
    }
}

#[async_trait]
impl PersistentGuestPort for PersistentGuestRepository {
    async fn reserve(&self, guest: &PersistentGuest) -> Result<PersistentGuest, String> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| format!("persistent guest reserve failed: {error}"))?;
        let existing = sqlx::query(
            "SELECT * FROM persistent_guests WHERE account_id = ?1 AND (vmid = ?2 OR name = ?3)",
        )
        .bind(&guest.account_id)
        .bind(i64::from(guest.vmid))
        .bind(&guest.name)
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| format!("persistent guest read failed: {error}"))?;
        match existing.as_slice() {
            [] => {}
            [row] => {
                let found = read(row)?;
                if found.vmid == guest.vmid && found.name == guest.name {
                    return Ok(found);
                }
                return Err(format!(
                    "VMID {} or the name {} is already a persistent guest ({} as VMID {})",
                    guest.vmid, guest.name, found.name, found.vmid
                ));
            }
            _ => {
                return Err(format!(
                    "VMID {} and the name {} belong to different persistent guests",
                    guest.vmid, guest.name
                ));
            }
        }
        sqlx::query(
            "INSERT INTO persistent_guests (account_id, vmid, name, node, image_version_id, \
             machine_id, cloned, state, step, operation_id, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?11, ?7, ?8, ?9, ?10, ?10)",
        )
        .bind(&guest.account_id)
        .bind(i64::from(guest.vmid))
        .bind(&guest.name)
        .bind(&guest.node)
        .bind(&guest.image_version_id)
        .bind(&guest.machine_id)
        .bind(guest.state.id())
        .bind(&guest.step)
        .bind(&guest.operation_id)
        .bind(guest.created_at)
        .bind(i64::from(guest.cloned))
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("persistent guest insert failed: {error}"))?;
        tx.commit()
            .await
            .map_err(|error| format!("persistent guest commit failed: {error}"))?;
        Ok(guest.clone())
    }

    async fn get(&self, account_id: &str, vmid: u32) -> Result<Option<PersistentGuest>, String> {
        sqlx::query("SELECT * FROM persistent_guests WHERE account_id = ?1 AND vmid = ?2")
            .bind(account_id)
            .bind(i64::from(vmid))
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("persistent guest read failed: {error}"))?
            .map(|row| read(&row))
            .transpose()
    }

    async fn update(&self, guest: &PersistentGuest) -> Result<(), String> {
        let done = sqlx::query(
            "UPDATE persistent_guests SET node = ?3, machine_id = ?4, state = ?5, step = ?6, \
             operation_id = ?7, updated_at = ?8, cloned = ?9 WHERE account_id = ?1 AND vmid = ?2",
        )
        .bind(&guest.account_id)
        .bind(i64::from(guest.vmid))
        .bind(&guest.node)
        .bind(&guest.machine_id)
        .bind(guest.state.id())
        .bind(&guest.step)
        .bind(&guest.operation_id)
        .bind(fleet_core::SystemClock::now_unix_millis())
        .bind(i64::from(guest.cloned))
        .execute(&self.pool)
        .await
        .map_err(|error| format!("persistent guest update failed: {error}"))?;
        if done.rows_affected() == 0 {
            return Err("the persistent guest is unknown".to_owned());
        }
        Ok(())
    }

    async fn list(&self) -> Result<Vec<PersistentGuest>, String> {
        sqlx::query("SELECT * FROM persistent_guests ORDER BY created_at DESC, vmid DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|error| format!("persistent guest list failed: {error}"))?
            .iter()
            .map(read)
            .collect()
    }

    async fn record_owner(
        &self,
        account_id: &str,
        vmid: u32,
        owner: &RequestedBy,
    ) -> Result<(), String> {
        let done = sqlx::query(
            "UPDATE persistent_guests SET owner = ?3, purpose = ?4, request_id = ?5 \
             WHERE account_id = ?1 AND vmid = ?2",
        )
        .bind(account_id)
        .bind(i64::from(vmid))
        .bind(&owner.principal)
        .bind(&owner.purpose)
        .bind(&owner.request_id)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("persistent guest owner write failed: {error}"))?;
        if done.rows_affected() == 0 {
            return Err("the persistent guest is unknown".to_owned());
        }
        Ok(())
    }

    async fn owner_of(&self, account_id: &str, vmid: u32) -> Result<Option<RequestedBy>, String> {
        let row = sqlx::query(
            "SELECT owner, purpose, request_id FROM persistent_guests \
             WHERE account_id = ?1 AND vmid = ?2 AND owner IS NOT NULL",
        )
        .bind(account_id)
        .bind(i64::from(vmid))
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| format!("persistent guest owner read failed: {error}"))?;
        Ok(row.map(|row| owner_from(&row)))
    }

    async fn owner_of_machine(&self, machine_id: &str) -> Result<Option<RequestedBy>, String> {
        let row = sqlx::query(
            "SELECT owner, purpose, request_id FROM persistent_guests \
             WHERE machine_id = ?1 AND owner IS NOT NULL",
        )
        .bind(machine_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| format!("persistent guest owner read failed: {error}"))?;
        Ok(row.map(|row| owner_from(&row)))
    }

    async fn remove(&self, account_id: &str, vmid: u32) -> Result<(), String> {
        sqlx::query("DELETE FROM persistent_guests WHERE account_id = ?1 AND vmid = ?2")
            .bind(account_id)
            .bind(i64::from(vmid))
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|error| format!("persistent guest delete failed: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    fn guest(vmid: u32, name: &str) -> PersistentGuest {
        PersistentGuest {
            account_id: "acct".to_owned(),
            vmid,
            name: name.to_owned(),
            node: "pve".to_owned(),
            image_version_id: "ver".to_owned(),
            machine_id: None,
            cloned: false,
            state: PersistentState::Creating,
            step: None,
            operation_id: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[tokio::test]
    async fn the_marker_is_idempotent_and_never_overwrites_another_guest() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let repo = PersistentGuestRepository::new(store.pool().clone());
        repo.reserve(&guest(7150, "runner")).await.unwrap();
        // The same guest resumes; a different name at the VMID, or the name at
        // another VMID, is a conflict.
        repo.reserve(&guest(7150, "runner")).await.unwrap();
        assert!(repo.reserve(&guest(7150, "other")).await.is_err());
        assert!(repo.reserve(&guest(7151, "runner")).await.is_err());
        let mut ready = repo.get("acct", 7150).await.unwrap().unwrap();
        ready.state = PersistentState::Ready;
        ready.machine_id = Some("m-1".to_owned());
        repo.update(&ready).await.unwrap();
        let read = repo.get("acct", 7150).await.unwrap().unwrap();
        assert_eq!(read.state, PersistentState::Ready);
        assert_eq!(repo.list().await.unwrap().len(), 1);
        assert!(repo.get("acct", 7151).await.unwrap().is_none());
        repo.remove("acct", 7150).await.unwrap();
        assert!(repo.get("acct", 7150).await.unwrap().is_none());
    }
}
