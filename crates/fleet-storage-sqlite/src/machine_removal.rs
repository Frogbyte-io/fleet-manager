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
//!   `hardware_reservations` owned by the machine and not released (read
//!   through the hardware gate, and re-checked by the delete itself), and
//!   operations in `pending`, `running`, `cancelling` or
//!   `blocked_manual_approval` whose payload names the machine (`machineId`).
//! - **Facts** (cascade with the machine row): `machine_endpoints` and
//!   `machine_endpoint_auth`, `machine_capabilities`, `inventory_snapshots`,
//!   `machine_tags`, `machine_groups`, `node_identities` with
//!   `node_credentials`, `node_sessions`, `node_challenges` and
//!   `node_enrollment_tokens`, `project_checkouts`, `skills_snapshots`,
//!   `catalog_skill_installs` and `confirmed_guest_links`.
//! - **History** (kept): `audit_events`, finished `operations`, released
//!   `hardware_reservations`, `action_requests`, and `machine_files` (removed
//!   by their retention pass, not by the delete).

use async_trait::async_trait;
use sqlx::SqlitePool;

use fleet_application::machine_remove::{
    ActiveOperationHold, LabProvisionHold, MachineRemovalPort, OtherHostUsers,
    PersistentMarkerHold, RemovalFootprint,
};
use fleet_application::persistent::REGISTERED_SOURCE;

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
            "SELECT p.id, p.state, p.lease_id, l.state FROM lab_provisions p \
             LEFT JOIN lab_leases l ON l.id = p.lease_id \
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
             WHERE state IN ('pending', 'running', 'cancelling', 'blocked_manual_approval') \
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
            collected_files_kept: self
                .count(
                    "SELECT COUNT(*) FROM machine_files WHERE machine_id = ?1",
                    machine_id,
                )
                .await?,
        })
    }
}
