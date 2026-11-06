//! What the store knows about a machine before it is removed (#616): the
//! records that hold it, who else uses its hosts, and what the delete
//! cascades to. The SQLite implementation of the application's
//! [`MachineRemovalPort`].
//!
//! Every table that names a machine id is one of three things, and the
//! application's removal rules depend on this list staying complete:
//!
//! - **Holds** (refuse the removal): `lab_provisions.machine_id` (a Lab
//!   guest), `persistent_guests.machine_id` (a persistent marker),
//!   `hardware_reservations` owned by the machine and not released, and
//!   operations in `pending`, `running` or `cancelling` whose payload names
//!   the machine (`machineId`). `blocked_manual_approval` is terminal (no
//!   transition leaves it and cancel cannot clear it), so it does not hold.
//!   [`MachineRemovalRepository::delete_unheld`] re-checks all four in the
//!   statement that deletes the machine.
//! - **Facts** (cascade with the machine row): `machine_endpoints` and
//!   `machine_endpoint_auth`, `machine_capabilities`, `inventory_snapshots`,
//!   `machine_tags`, `machine_groups`, `node_identities` with
//!   `node_credentials`, `node_sessions`, `node_challenges` and
//!   `node_enrollment_tokens`, `project_checkouts`, `skills_snapshots`,
//!   `catalog_skill_installs` and `confirmed_guest_links`.
//! - **History** (kept): `audit_events`, finished `operations`, released
//!   `hardware_reservations`, `action_requests`, and `machine_files` (removed
//!   by their retention pass, not by the delete).
//! - **Secrets** (revoked by the application through the key store, counted
//!   here by name only): `secret_records` named `machines/ssh/<machine>/…`
//!   and `machines/windows-admin/<machine>/…`.

use std::collections::BTreeMap;

use async_trait::async_trait;
use sqlx::SqlitePool;

use fleet_application::machine_remove::{
    ActiveOperationHold, LabProvisionHold, MachineRemovalPort, OtherHostUsers,
    PersistentMarkerHold, RemovalFootprint,
};
use fleet_application::operation::PortFailure;
use fleet_application::persistent::{ADMIN_PASSWORD_PREFIX, REGISTERED_SOURCE};

/// The secret-record name prefix of SSH keys stored for a machine.
const SSH_KEY_PREFIX: &str = "machines/ssh/";

/// The delete, guarded by every hold in the same statement.
const GUARDED_DELETE: &str = "DELETE FROM machines WHERE id = ?1 \
     AND NOT EXISTS (SELECT 1 FROM hardware_reservations \
         WHERE owner_kind = 'machine' AND owner_id = ?1 AND state <> 'released') \
     AND NOT EXISTS (SELECT 1 FROM lab_provisions WHERE machine_id = ?1) \
     AND NOT EXISTS (SELECT 1 FROM persistent_guests WHERE machine_id = ?1) \
     AND NOT EXISTS (SELECT 1 FROM operations \
         WHERE state IN ('pending', 'running', 'cancelling') \
           AND json_valid(payload_json) \
           AND json_extract(payload_json, '$.machineId') = ?1)";

/// The SQLite [`MachineRemovalPort`].
#[derive(Clone, Debug)]
pub struct MachineRemovalRepository {
    pool: SqlitePool,
}

impl MachineRemovalRepository {
    /// Over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    async fn count_prefixed(&self, prefix: &str, machine_id: &str) -> Result<u64, String> {
        let prefix = format!("{prefix}{machine_id}/");
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM secret_records WHERE substr(name, 1, length(?1)) = ?1",
        )
        .bind(&prefix)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| format!("the machine's stored secrets could not be counted: {error}"))?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Why the guarded delete refused, once it did: the first hold found.
    async fn hold(&self, machine_id: &str) -> Result<Option<String>, PortFailure> {
        let checks: [(&'static str, &str); 4] = [
            (
                "SELECT 'Lab provision ' || id || ' (' || state || ')' FROM lab_provisions \
                 WHERE machine_id = ?1 LIMIT 1",
                "it is a Lab guest",
            ),
            (
                "SELECT 'persistent marker ' || account_id || '/' || vmid FROM persistent_guests \
                 WHERE machine_id = ?1 LIMIT 1",
                "it is a persistent machine",
            ),
            (
                "SELECT 'USB reservation ' || id || ' (' || state || ')' FROM hardware_reservations \
                 WHERE owner_kind = 'machine' AND owner_id = ?1 AND state <> 'released' LIMIT 1",
                "it holds a USB device",
            ),
            (
                "SELECT 'operation ' || id || ' (' || kind || ', ' || state || ')' FROM operations \
                 WHERE state IN ('pending', 'running', 'cancelling') AND json_valid(payload_json) \
                   AND json_extract(payload_json, '$.machineId') = ?1 LIMIT 1",
                "work on it has not finished",
            ),
        ];
        for (sql, why) in checks {
            let found: Option<String> = sqlx::query_scalar(sql)
                .bind(machine_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| PortFailure::Backend {
                    detail: format!("the machine's holds could not be read: {error}"),
                })?;
            if let Some(found) = found {
                return Ok(Some(format!(
                    "{found} took hold of machine {machine_id} after the review ({why}); nothing was deleted; review the removal again"
                )));
            }
        }
        Ok(None)
    }

    async fn count(&self, sql: &'static str, machine_id: &str) -> Result<u64, String> {
        let count: i64 = sqlx::query_scalar(sql)
            .bind(machine_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| format!("the removal footprint could not be read: {error}"))?;
        Ok(u64::try_from(count).unwrap_or(0))
    }
}

fn failed(what: &str) -> impl FnOnce(sqlx::Error) -> String + '_ {
    move |error| format!("the machine's {what} could not be read: {error}")
}

#[async_trait]
impl MachineRemovalPort for MachineRemovalRepository {
    async fn lab_provisions(&self, machine_id: &str) -> Result<Vec<LabProvisionHold>, String> {
        let rows: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
            // The lease counts only when it links back to this provision:
            // cleanup follows the lease's `provision_id`, so a lease that
            // names another provision could not clean this one up.
            "SELECT p.id, p.state, l.id, l.state FROM lab_provisions p \
             LEFT JOIN lab_leases l ON l.id = p.lease_id AND l.provision_id = p.id \
             WHERE p.machine_id = ?1 ORDER BY p.created_at, p.id",
        )
        .bind(machine_id)
        .fetch_all(&self.pool)
        .await
        .map_err(failed("Lab provisions"))?;
        Ok(rows
            .into_iter()
            .map(
                |(provision_id, state, lease_id, lease_state)| LabProvisionHold {
                    provision_id,
                    state,
                    lease_id,
                    lease_state,
                },
            )
            .collect())
    }

    async fn persistent_markers(
        &self,
        machine_id: &str,
    ) -> Result<Vec<PersistentMarkerHold>, String> {
        let rows: Vec<(String, i64, String, String)> = sqlx::query_as(
            "SELECT account_id, vmid, name, image_version_id FROM persistent_guests \
             WHERE machine_id = ?1 ORDER BY account_id, vmid",
        )
        .bind(machine_id)
        .fetch_all(&self.pool)
        .await
        .map_err(failed("persistent markers"))?;
        Ok(rows
            .into_iter()
            .map(|(account_id, vmid, name, source)| PersistentMarkerHold {
                account_id,
                vmid: u32::try_from(vmid).unwrap_or_default(),
                name,
                registered: source == REGISTERED_SOURCE,
            })
            .collect())
    }

    async fn active_operations(
        &self,
        machine_id: &str,
    ) -> Result<Vec<ActiveOperationHold>, String> {
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            // The operation states that have not finished.
            "SELECT id, kind, state FROM operations \
             WHERE state IN ('pending', 'running', 'cancelling') \
               AND json_valid(payload_json) \
               AND json_extract(payload_json, '$.machineId') = ?1 \
             ORDER BY created_at, id",
        )
        .bind(machine_id)
        .fetch_all(&self.pool)
        .await
        .map_err(failed("operations"))?;
        Ok(rows
            .into_iter()
            .map(|(id, kind, state)| ActiveOperationHold { id, kind, state })
            .collect())
    }

    async fn other_host_users(&self, machine_id: &str) -> Result<OtherHostUsers, String> {
        let endpoint_references: Vec<String> = sqlx::query_scalar(
            "SELECT reference FROM machine_endpoints WHERE kind = 'ssh' AND machine_id <> ?1",
        )
        .bind(machine_id)
        .fetch_all(&self.pool)
        .await
        .map_err(failed("shared hosts"))?;
        let draft_hosts: Vec<String> =
            sqlx::query_scalar("SELECT DISTINCT endpoint_host FROM onboarding_drafts")
                .fetch_all(&self.pool)
                .await
                .map_err(failed("shared hosts"))?;
        Ok(OtherHostUsers {
            endpoint_references,
            draft_hosts,
        })
    }

    async fn footprint(&self, machine_id: &str) -> Result<RemovalFootprint, String> {
        Ok(RemovalFootprint {
            endpoints: self
                .count(
                    "SELECT COUNT(*) FROM machine_endpoints WHERE machine_id = ?1",
                    machine_id,
                )
                .await?,
            endpoint_auth: self
                .count(
                    "SELECT COUNT(*) FROM machine_endpoint_auth a \
                     JOIN machine_endpoints e ON e.id = a.endpoint_id WHERE e.machine_id = ?1",
                    machine_id,
                )
                .await?,
            endpoint_auth_secrets: self
                .count(
                    "SELECT COUNT(*) FROM machine_endpoint_auth a \
                     JOIN machine_endpoints e ON e.id = a.endpoint_id \
                     WHERE e.machine_id = ?1 AND a.kind = 'secret'",
                    machine_id,
                )
                .await?,
            capabilities: self
                .count(
                    "SELECT COUNT(*) FROM machine_capabilities WHERE machine_id = ?1",
                    machine_id,
                )
                .await?,
            inventory_snapshots: self
                .count(
                    "SELECT COUNT(*) FROM inventory_snapshots WHERE machine_id = ?1",
                    machine_id,
                )
                .await?,
            tags_and_groups: self
                .count(
                    "SELECT (SELECT COUNT(*) FROM machine_tags WHERE machine_id = ?1) \
                     + (SELECT COUNT(*) FROM machine_groups WHERE machine_id = ?1)",
                    machine_id,
                )
                .await?,
            node_identity: self
                .count(
                    "SELECT COUNT(*) FROM node_identities WHERE machine_id = ?1",
                    machine_id,
                )
                .await?,
            node_credentials: self
                .count(
                    "SELECT (SELECT COUNT(*) FROM node_credentials WHERE machine_id = ?1) \
                     + (SELECT COUNT(*) FROM node_sessions WHERE machine_id = ?1) \
                     + (SELECT COUNT(*) FROM node_challenges WHERE machine_id = ?1) \
                     + (SELECT COUNT(*) FROM node_enrollment_tokens WHERE machine_id = ?1)",
                    machine_id,
                )
                .await?,
            project_checkouts: self
                .count(
                    "SELECT COUNT(*) FROM project_checkouts WHERE machine_id = ?1",
                    machine_id,
                )
                .await?,
            skills_snapshot: self
                .count(
                    "SELECT COUNT(*) FROM skills_snapshots WHERE machine_id = ?1",
                    machine_id,
                )
                .await?,
            catalog_skill_installs: self
                .count(
                    "SELECT COUNT(*) FROM catalog_skill_installs WHERE machine_id = ?1",
                    machine_id,
                )
                .await?,
            guest_link: self
                .count(
                    "SELECT COUNT(*) FROM confirmed_guest_links WHERE machine_id = ?1",
                    machine_id,
                )
                .await?,
            stored_ssh_keys: self.count_prefixed(SSH_KEY_PREFIX, machine_id).await?,
            admin_passwords: self
                .count_prefixed(ADMIN_PASSWORD_PREFIX, machine_id)
                .await?,
            collected_files_kept: self
                .count(
                    "SELECT COUNT(*) FROM machine_files WHERE machine_id = ?1",
                    machine_id,
                )
                .await?,
        })
    }

    async fn install_layout(&self, machine_id: &str) -> Result<BTreeMap<String, String>, String> {
        let payload: Option<String> = sqlx::query_scalar(
            "SELECT payload_json FROM operations \
             WHERE kind = 'machine.install-fleetd' AND state = 'succeeded' \
               AND json_valid(payload_json) \
               AND json_extract(payload_json, '$.machineId') = ?1 \
             ORDER BY updated_at DESC, id DESC LIMIT 1",
        )
        .bind(machine_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(failed("install record"))?;
        let Some(payload) = payload else {
            return Ok(BTreeMap::new());
        };
        let payload: serde_json::Value = serde_json::from_str(&payload)
            .map_err(|error| format!("the machine's install record is unreadable: {error}"))?;
        // `installerEnv` is a list of `[name, value]` pairs; only the layout
        // names are kept, so nothing a secret could hide in is carried over.
        Ok(payload["installerEnv"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|pair| {
                let name = pair.get(0)?.as_str()?;
                let value = pair.get(1)?.as_str()?;
                fleet_application::machine_remove::LAYOUT_VARIABLES
                    .contains(&name)
                    .then(|| (name.to_owned(), value.to_owned()))
            })
            .collect())
    }

    async fn delete_unheld(&self, machine_id: &str) -> Result<(), PortFailure> {
        let deleted = sqlx::query(GUARDED_DELETE)
            .bind(machine_id)
            .execute(&self.pool)
            .await
            .map_err(|error| PortFailure::Backend {
                detail: format!("machine delete failed: {error}"),
            })?;
        if deleted.rows_affected() == 1 {
            return Ok(());
        }
        if let Some(detail) = self.hold(machine_id).await? {
            return Err(PortFailure::Conflict { detail });
        }
        Err(PortFailure::NotFound {
            what: format!("machine {machine_id:?}"),
        })
    }
}
