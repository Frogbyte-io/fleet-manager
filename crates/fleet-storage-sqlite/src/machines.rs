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
    Endpoint, Machine, MachineFilter, MachinePort, NewEndpoint, RegisterMachine,
};
use fleet_application::operation::PortFailure;
use fleet_core::{CapabilityFact, EndpointKind};

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
        let rows = sqlx::query(
            "SELECT DISTINCT m.* FROM machines m \
             LEFT JOIN machine_tags mt ON mt.machine_id = m.id \
             LEFT JOIN tags t ON t.id = mt.tag_id \
             LEFT JOIN machine_groups mg ON mg.machine_id = m.id \
             LEFT JOIN machine_capabilities mc ON mc.machine_id = m.id \
             WHERE (?1 IS NULL OR t.name = ?1) \
               AND (?2 IS NULL OR mg.group_name = ?2) \
               AND (?3 IS NULL OR (mc.namespace = ?3 AND mc.name = ?4)) \
             ORDER BY m.created_at DESC, m.id DESC LIMIT ?5",
        )
        .bind(&filter.tag)
        .bind(&filter.group)
        .bind(filter.capability.as_ref().map(|(ns, _)| ns))
        .bind(filter.capability.as_ref().map(|(_, name)| name))
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
        let deleted = sqlx::query("DELETE FROM machines WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|error| backend("delete", &error))?;
        if deleted.rows_affected() == 0 {
            return Err(PortFailure::NotFound {
                what: format!("machine {id:?}"),
            });
        }
        Ok(())
    }
}

impl MachineRepository {
    async fn hydrate(&self, row: &sqlx::sqlite::SqliteRow) -> Result<Machine, PortFailure> {
        use sqlx::Row as _;
        let id: String = row.get("id");
        let endpoint_rows = sqlx::query("SELECT id, kind, reference FROM machine_endpoints WHERE machine_id = ?1 ORDER BY created_at ASC")
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
                })
                .collect(),
            tags: tag_rows.iter().map(|row| row.get(0)).collect(),
            groups: group_rows.iter().map(|row| row.get(0)).collect(),
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
