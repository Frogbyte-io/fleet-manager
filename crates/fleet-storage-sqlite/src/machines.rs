//! The machine repository: the SQLite implementation of the application's
//! [`MachinePort`].
//!
//! The identity rules are structural here: machines are minted with an id,
//! names are unique mutable labels, endpoints coexist per kind, capability
//! facts upsert per `(machine, namespace, name)`, and deleting a machine
//! cascades to everything that is a fact about it.

use async_trait::async_trait;
use sqlx::SqlitePool;
use uuid::Uuid;

use fleet_application::machine::{
    Endpoint, InventoryObservation, Machine, MachineFilter, MachinePort, NewEndpoint, NodeLink,
    RegisterMachine,
};
use fleet_application::node::{GatewayState, NodeStatus};
use fleet_application::operation::{CatalogRolloutTargetPort, PortFailure};
use fleet_core::{CapabilityFact, CapabilityStatus, EndpointKind, Timestamp};

/// The machine repository over a pool.
#[derive(Debug)]
pub struct MachineRepository {
    pool: SqlitePool,
}

impl MachineRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MachinePort for MachineRepository {
    async fn register(&self, registration: &RegisterMachine) -> Result<Machine, PortFailure> {
        let id = Uuid::now_v7().to_string();
        let now = fleet_core::SystemClock::now_unix_millis();
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| backend("register", &error))?;

        let inserted = sqlx::query("INSERT INTO machines (id, name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4)")
            .bind(&id)
            .bind(&registration.name)
            .bind(&registration.description)
            .bind(now)
            .execute(&mut *tx)
            .await;
        if let Err(error) = inserted {
            if is_unique_violation(&error) {
                return Err(PortFailure::Backend {
                    detail: format!("the machine name {:?} is already taken", registration.name),
                });
            }
            return Err(backend("register", &error));
        }
        for endpoint in &registration.endpoints {
            sqlx::query("INSERT INTO machine_endpoints (id, machine_id, kind, reference, created_at) VALUES (?1, ?2, ?3, ?4, ?5)")
                .bind(Uuid::now_v7().to_string())
                .bind(&id)
                .bind(endpoint.kind.id())
                .bind(&endpoint.reference)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(|error| backend("register_endpoint", &error))?;
        }
        for tag in &registration.tags {
            let tag_id = ensure_tag(&mut tx, tag).await?;
            sqlx::query("INSERT OR IGNORE INTO machine_tags (machine_id, tag_id) VALUES (?1, ?2)")
                .bind(&id)
                .bind(&tag_id)
                .execute(&mut *tx)
                .await
                .map_err(|error| backend("register_tag", &error))?;
        }
        for group in &registration.groups {
            sqlx::query(
                "INSERT OR IGNORE INTO machine_groups (machine_id, group_name) VALUES (?1, ?2)",
            )
            .bind(&id)
            .bind(group)
            .execute(&mut *tx)
            .await
            .map_err(|error| backend("register_group", &error))?;
        }
        tx.commit()
            .await
            .map_err(|error| backend("register", &error))?;
        self.get(&id).await
    }

    async fn get(&self, id: &str) -> Result<Machine, PortFailure> {
        let row = sqlx::query("SELECT * FROM machines WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| backend("get", &error))?
            .ok_or_else(|| PortFailure::NotFound {
                what: format!("machine {id:?}"),
            })?;
        self.hydrate(&row).await
    }

    async fn list(&self, filter: &MachineFilter, limit: u32) -> Result<Vec<Machine>, PortFailure> {
        let limit = limit.clamp(1, 200);
        let status = filter.status.as_ref().map(|status| status.id());
        let cursor_created_at = if let Some(cursor) = filter.cursor.as_deref() {
            Some(
                sqlx::query_scalar::<_, i64>("SELECT created_at FROM machines WHERE id = ?1")
                    .bind(cursor)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|error| backend("list_cursor", &error))?
                    .ok_or_else(|| PortFailure::NotFound {
                        what: format!("machine {cursor:?}"),
                    })?,
            )
        } else {
            None
        };
        let rows = sqlx::query(
            "SELECT DISTINCT m.* FROM machines m \
             LEFT JOIN machine_tags mt ON mt.machine_id = m.id \
             LEFT JOIN tags t ON t.id = mt.tag_id \
             LEFT JOIN machine_groups mg ON mg.machine_id = m.id \
             LEFT JOIN machine_capabilities mc ON mc.machine_id = m.id \
             LEFT JOIN node_identities ni ON ni.machine_id = m.id \
             WHERE (?1 IS NULL OR t.name = ?1) \
               AND (?2 IS NULL OR mg.group_name = ?2) \
               AND (?3 IS NULL OR (mc.namespace = ?3 AND mc.name = ?4)) \
               AND (?5 IS NULL OR (?5 = 'agentless' AND ni.machine_id IS NULL) \
                    OR (?5 <> 'agentless' AND ni.gateway_state = ?6)) \
               AND (?7 IS NULL OR m.created_at < ?8 OR (m.created_at = ?8 AND m.id < ?7)) \
             ORDER BY m.created_at DESC, m.id DESC LIMIT ?9",
        )
        .bind(&filter.tag)
        .bind(&filter.group)
        .bind(filter.capability.as_ref().map(|(ns, _)| ns))
        .bind(filter.capability.as_ref().map(|(_, name)| name))
        .bind(status)
        .bind(status)
        .bind(filter.cursor.as_deref())
        .bind(cursor_created_at)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| backend("list", &error))?;

        let mut machines = Vec::with_capacity(rows.len());
        for row in &rows {
            machines.push(self.hydrate(row).await?);
        }
        Ok(machines)
    }

    async fn update(
        &self,
        id: &str,
        name: &str,
        description: &str,
    ) -> Result<Machine, PortFailure> {
        let updated = sqlx::query(
            "UPDATE machines SET name = ?2, description = ?3, updated_at = ?4 WHERE id = ?1",
        )
        .bind(id)
        .bind(name)
        .bind(description)
        .bind(fleet_core::SystemClock::now_unix_millis())
        .execute(&self.pool)
        .await;
        match updated {
            Ok(result) if result.rows_affected() == 0 => Err(PortFailure::NotFound {
                what: format!("machine {id:?}"),
            }),
            Err(error) if is_unique_violation(&error) => Err(PortFailure::Backend {
                detail: format!("the machine name {name:?} is already taken"),
            }),
            Err(error) => Err(backend("update", &error)),
            Ok(_) => self.get(id).await,
        }
    }

    async fn set_endpoints(
        &self,
        id: &str,
        endpoints: &[NewEndpoint],
    ) -> Result<Machine, PortFailure> {
        let now = fleet_core::SystemClock::now_unix_millis();
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| backend("set_endpoints", &error))?;
        let replaced = sqlx::query("DELETE FROM machine_endpoints WHERE machine_id = ?1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|error| backend("set_endpoints", &error))?;
        if replaced.rows_affected() == 0 {
            sqlx::query("SELECT 1 FROM machines WHERE id = ?1")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|error| backend("set_endpoints", &error))?
                .ok_or_else(|| PortFailure::NotFound {
                    what: format!("machine {id:?}"),
                })?;
        }
        for endpoint in endpoints {
            sqlx::query("INSERT INTO machine_endpoints (id, machine_id, kind, reference, created_at) VALUES (?1, ?2, ?3, ?4, ?5)")
                .bind(Uuid::now_v7().to_string())
                .bind(id)
                .bind(endpoint.kind.id())
                .bind(&endpoint.reference)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(|error| backend("set_endpoints", &error))?;
        }
        sqlx::query("UPDATE machines SET updated_at = ?2 WHERE id = ?1")
            .bind(id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|error| backend("set_endpoints", &error))?;
        tx.commit()
            .await
            .map_err(|error| backend("set_endpoints", &error))?;
        self.get(id).await
    }

    async fn add_tag(&self, id: &str, tag: &str) -> Result<Machine, PortFailure> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| backend("add_tag", &error))?;
        require_machine(&mut tx, id).await?;
        let tag_id = ensure_tag(&mut tx, tag).await?;
        sqlx::query("INSERT OR IGNORE INTO machine_tags (machine_id, tag_id) VALUES (?1, ?2)")
            .bind(id)
            .bind(&tag_id)
            .execute(&mut *tx)
            .await
            .map_err(|error| backend("add_tag", &error))?;
        tx.commit()
            .await
            .map_err(|error| backend("add_tag", &error))?;
        self.get(id).await
    }

    async fn remove_tag(&self, id: &str, tag: &str) -> Result<Machine, PortFailure> {
        sqlx::query(
            "DELETE FROM machine_tags WHERE machine_id = ?1 AND tag_id = (SELECT id FROM tags WHERE name = ?2)",
        )
        .bind(id)
        .bind(tag)
        .execute(&self.pool)
        .await
        .map_err(|error| backend("remove_tag", &error))?;
        self.get(id).await
    }

    async fn add_group(&self, id: &str, group: &str) -> Result<Machine, PortFailure> {
        sqlx::query(
            "INSERT OR IGNORE INTO machine_groups (machine_id, group_name) VALUES (?1, ?2)",
        )
        .bind(id)
        .bind(group)
        .execute(&self.pool)
        .await
        .map_err(|error| backend("add_group", &error))?;
        self.get(id).await
    }

    async fn remove_group(&self, id: &str, group: &str) -> Result<Machine, PortFailure> {
        sqlx::query("DELETE FROM machine_groups WHERE machine_id = ?1 AND group_name = ?2")
            .bind(id)
            .bind(group)
            .execute(&self.pool)
            .await
            .map_err(|error| backend("remove_group", &error))?;
        self.get(id).await
    }

    async fn record_snapshot(
        &self,
        id: &str,
        source: &str,
        payload_json: &str,
        collected_at: i64,
    ) -> Result<(), PortFailure> {
        let result = sqlx::query("INSERT INTO inventory_snapshots (id, machine_id, source, collected_at, payload_json) VALUES (?1, ?2, ?3, ?4, ?5)")
            .bind(Uuid::now_v7().to_string())
            .bind(id)
            .bind(source)
            .bind(collected_at)
            .bind(payload_json)
            .execute(&self.pool)
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .as_database_error()
                    .is_some_and(|e| e.to_string().contains("FOREIGN KEY")) =>
            {
                Err(PortFailure::NotFound {
                    what: format!("machine {id:?}"),
                })
            }
            Err(error) => Err(backend("record_snapshot", &error)),
        }
    }

    async fn record_capabilities(
        &self,
        id: &str,
        facts: &[CapabilityFact],
    ) -> Result<(), PortFailure> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| backend("record_capabilities", &error))?;
        require_machine(&mut tx, id).await?;
        for fact in facts {
            // The `fleet` namespace is Fleet's own record keeping and is
            // never written from a report: a node or an inventory probe
            // could otherwise forge it.
            if fact
                .namespace
                .eq_ignore_ascii_case(fleet_core::RESERVED_FACT_NAMESPACE)
            {
                continue;
            }
            sqlx::query(
                "INSERT INTO machine_capabilities (machine_id, namespace, name, value, status, observed_at, source) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                 ON CONFLICT(machine_id, namespace, name) DO UPDATE SET \
                 value = excluded.value, status = excluded.status, observed_at = excluded.observed_at, source = excluded.source",
            )
            .bind(id)
            .bind(&fact.namespace)
            .bind(&fact.name)
            .bind(&fact.value)
            .bind(fact.status.id())
            .bind(fact.observed_at.unix_millis())
            .bind(&fact.source)
            .execute(&mut *tx)
            .await
            .map_err(|error| backend("record_capabilities", &error))?;
        }
        tx.commit()
            .await
            .map_err(|error| backend("record_capabilities", &error))?;
        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<(), PortFailure> {
        // A machine that holds a USB device (a live hardware reservation it
        // owns, FM-1125) is not deleted, whoever asks: the reservation names
        // the machine, and deleting it would leave a device on a guest nobody
        // answers for. One statement, so the check and the delete cannot
        // interleave with a reservation.
        let deleted = sqlx::query(
            "DELETE FROM machines WHERE id = ?1 AND NOT EXISTS ( \
             SELECT 1 FROM hardware_reservations \
             WHERE owner_kind = 'machine' AND owner_id = ?1 AND state <> 'released')",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|error| backend("delete", &error))?;
        if deleted.rows_affected() == 0 {
            let held: Option<(String, String, String)> = sqlx::query_as(
                "SELECT r.id, r.state, COALESCE(d.mapping_id, '<mapping>') \
                 FROM hardware_reservations r LEFT JOIN hardware_devices d ON d.id = r.device_id \
                 WHERE r.owner_kind = 'machine' AND r.owner_id = ?1 AND r.state <> 'released' \
                 ORDER BY r.created_at LIMIT 1",
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| backend("delete", &error))?;
            if let Some((reservation, state, mapping)) = held {
                return Err(PortFailure::Conflict {
                    detail: format!(
                        "cannot delete the machine: it holds USB device {mapping} (reservation {reservation} is {state}); detach it first with `fleetctl machines usb detach {id} --mapping {mapping}` (a stuck reservation is freed with `fleetctl hardware override-release {reservation}`)"
                    ),
                });
            }
            return Err(PortFailure::NotFound {
                what: format!("machine {id:?}"),
            });
        }
        Ok(())
    }

    async fn confirm_fingerprint(
        &self,
        endpoint_id: &str,
        fingerprint: &str,
        confirmed_at: i64,
    ) -> Result<(), PortFailure> {
        let updated = sqlx::query(
            // A (re)confirmed host key may be a different machine behind the
            // same address: the recorded guest OS is cleared with it and is
            // detected again (ADR 0021).
            "UPDATE machine_endpoints SET verified_fingerprint = ?2, verified_at = ?3, \
             guest_os = NULL WHERE id = ?1",
        )
        .bind(endpoint_id)
        .bind(fingerprint)
        .bind(confirmed_at)
        .execute(&self.pool)
        .await
        .map_err(|error| backend("confirm_fingerprint", &error))?;
        if updated.rows_affected() == 0 {
            return Err(PortFailure::NotFound {
                what: format!("endpoint {endpoint_id:?}"),
            });
        }
        Ok(())
    }

    async fn latest_inventory_revision(
        &self,
        machine_id: &str,
    ) -> Result<Option<u64>, PortFailure> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT payload_json FROM inventory_snapshots WHERE machine_id = ?1 \
             ORDER BY collected_at DESC, id DESC LIMIT 1",
        )
        .bind(machine_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| PortFailure::Backend {
            detail: format!("latest_inventory_revision: {error}"),
        })?;
        Ok(row.and_then(|(payload,)| {
            serde_json::from_str::<serde_json::Value>(&payload)
                .ok()
                .and_then(|report| report["revision"].as_u64())
        }))
    }

    async fn record_endpoint_os(
        &self,
        endpoint_id: &str,
        guest_os: fleet_core::GuestOs,
    ) -> Result<(), PortFailure> {
        self.write_endpoint_os(endpoint_id, Some(guest_os.id()), "record_endpoint_os")
            .await
    }

    async fn clear_endpoint_os(&self, endpoint_id: &str) -> Result<(), PortFailure> {
        self.write_endpoint_os(endpoint_id, None, "clear_endpoint_os")
            .await
    }

    async fn verified_fingerprint(&self, endpoint_id: &str) -> Result<Option<String>, PortFailure> {
        sqlx::query_scalar("SELECT verified_fingerprint FROM machine_endpoints WHERE id = ?1")
            .bind(endpoint_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| backend("verified_fingerprint", &error))?
            .ok_or_else(|| PortFailure::NotFound {
                what: format!("endpoint {endpoint_id:?}"),
            })
    }
}

#[async_trait]
impl CatalogRolloutTargetPort for MachineRepository {
    async fn endpoint_kind(
        &self,
        machine_id: &str,
        endpoint_id: &str,
    ) -> Result<Option<EndpointKind>, PortFailure> {
        let machine = <Self as MachinePort>::get(self, machine_id).await?;
        Ok(machine
            .endpoints
            .into_iter()
            .find(|endpoint| endpoint.id == endpoint_id)
            .map(|endpoint| endpoint.kind))
    }

    async fn endpoint_guest_os(
        &self,
        machine_id: &str,
        endpoint_id: &str,
    ) -> Result<Option<fleet_core::GuestOs>, PortFailure> {
        let machine = <Self as MachinePort>::get(self, machine_id).await?;
        Ok(machine
            .endpoints
            .into_iter()
            .find(|endpoint| endpoint.id == endpoint_id)
            .and_then(|endpoint| endpoint.guest_os))
    }
}

impl MachineRepository {
    /// Writes or clears the guest OS of an SSH endpoint. Only SSH endpoints
    /// carry one; any other kind is not found.
    async fn write_endpoint_os(
        &self,
        endpoint_id: &str,
        guest_os: Option<&str>,
        context: &str,
    ) -> Result<(), PortFailure> {
        let updated = sqlx::query(
            "UPDATE machine_endpoints SET guest_os = ?2 WHERE id = ?1 AND kind = 'ssh'",
        )
        .bind(endpoint_id)
        .bind(guest_os)
        .execute(&self.pool)
        .await
        .map_err(|error| backend(context, &error))?;
        if updated.rows_affected() == 0 {
            return Err(PortFailure::NotFound {
                what: format!("SSH endpoint {endpoint_id:?}"),
            });
        }
        Ok(())
    }

    /// Assembles one machine record with everything that is a fact about
    /// it: endpoints, tags, groups, capability facts, the newest inventory
    /// observation, and the node trust link. The read-time rules — fact
    /// staleness and derived machine status — are applied later, by the
    /// application's view assembly, so this stays a faithful record.
    async fn hydrate(&self, row: &sqlx::sqlite::SqliteRow) -> Result<Machine, PortFailure> {
        use sqlx::Row as _;
        let id: String = row.get("id");
        let endpoint_rows = sqlx::query("SELECT id, kind, reference, guest_os FROM machine_endpoints WHERE machine_id = ?1 ORDER BY created_at ASC")
            .bind(&id)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| backend("hydrate_endpoints", &error))?;
        let tag_rows = sqlx::query(
            "SELECT t.name FROM tags t JOIN machine_tags mt ON mt.tag_id = t.id WHERE mt.machine_id = ?1 ORDER BY t.name",
        )
        .bind(&id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| backend("hydrate_tags", &error))?;
        let group_rows = sqlx::query(
            "SELECT group_name FROM machine_groups WHERE machine_id = ?1 ORDER BY group_name",
        )
        .bind(&id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| backend("hydrate_groups", &error))?;
        let capability_rows = sqlx::query(
            "SELECT namespace, name, value, status, observed_at, source \
             FROM machine_capabilities WHERE machine_id = ?1 ORDER BY namespace ASC, name ASC",
        )
        .bind(&id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| backend("hydrate_capabilities", &error))?;
        let snapshot_row: Option<(String, i64)> = sqlx::query_as(
            "SELECT source, collected_at FROM inventory_snapshots \
             WHERE machine_id = ?1 ORDER BY collected_at DESC, id DESC LIMIT 1",
        )
        .bind(&id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| backend("hydrate_snapshot", &error))?;
        let node_row: Option<(String, String, Option<i64>)> = sqlx::query_as(
            "SELECT gateway_state, status, last_seen_at FROM node_identities WHERE machine_id = ?1",
        )
        .bind(&id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| backend("hydrate_node", &error))?;

        Ok(Machine {
            id,
            name: row.get("name"),
            description: row.get("description"),
            endpoints: endpoint_rows
                .iter()
                .map(|row| Endpoint {
                    id: row.get("id"),
                    kind: EndpointKind::from_id(&row.get::<String, _>("kind"))
                        .unwrap_or(EndpointKind::Ssh),
                    reference: row.get("reference"),
                    // The CHECK admits only the two ids; anything else
                    // reads as unknown rather than failing the machine.
                    guest_os: row
                        .get::<Option<String>, _>("guest_os")
                        .and_then(|id| fleet_core::GuestOs::from_id(&id).ok()),
                })
                .collect(),
            tags: tag_rows.iter().map(|row| row.get(0)).collect(),
            groups: group_rows.iter().map(|row| row.get(0)).collect(),
            capabilities: capability_rows
                .iter()
                .map(|row| CapabilityFact {
                    namespace: row.get("namespace"),
                    name: row.get("name"),
                    value: row.get("value"),
                    status: CapabilityStatus::from_id(&row.get::<String, _>("status"))
                        .unwrap_or(CapabilityStatus::Unknown),
                    observed_at: Timestamp::from_unix_millis(row.get("observed_at")),
                    source: row.get("source"),
                })
                .collect(),
            last_observation: snapshot_row.map(|(source, collected_at)| InventoryObservation {
                source,
                collected_at,
            }),
            node: node_row.map(|(gateway_state, status, last_seen_at)| NodeLink {
                gateway_state: GatewayState::from_id(&gateway_state)
                    .unwrap_or(GatewayState::Offline),
                identity_status: NodeStatus::from_id(&status).unwrap_or(NodeStatus::Revoked),
                last_seen_at,
            }),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
}

async fn ensure_tag(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    name: &str,
) -> Result<String, PortFailure> {
    let existing: Option<String> = sqlx::query_scalar("SELECT id FROM tags WHERE name = ?1")
        .bind(name)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| backend("ensure_tag", &error))?;
    if let Some(id) = existing {
        return Ok(id);
    }
    let id = Uuid::now_v7().to_string();
    sqlx::query("INSERT INTO tags (id, name) VALUES (?1, ?2)")
        .bind(&id)
        .bind(name)
        .execute(&mut **tx)
        .await
        .map_err(|error| backend("ensure_tag", &error))?;
    Ok(id)
}

async fn require_machine(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: &str,
) -> Result<(), PortFailure> {
    sqlx::query("SELECT 1 FROM machines WHERE id = ?1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| backend("require_machine", &error))?
        .ok_or_else(|| PortFailure::NotFound {
            what: format!("machine {id:?}"),
        })?;
    Ok(())
}

fn backend(context: &str, error: &sqlx::Error) -> PortFailure {
    #[allow(clippy::needless_pass_by_value)]
    PortFailure::Backend {
        detail: format!("machine {context} failed: {error}"),
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
