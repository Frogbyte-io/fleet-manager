//! SQLite persistence for the sensitive Skills Manager read model.

use async_trait::async_trait;
use fleet_application::operation::PortFailure;
use fleet_application::skills::{SkillsAvailability, SkillsPort, SkillsSnapshot};
use sqlx::{Row, SqlitePool};

/// Skills snapshot repository over SQLite.
#[derive(Debug)]
pub struct SkillsRepository {
    pool: SqlitePool,
}

impl SkillsRepository {
    /// Create a repository over the controller database.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SkillsPort for SkillsRepository {
    async fn get(&self, machine_id: &str) -> Result<Option<SkillsSnapshot>, PortFailure> {
        let row = sqlx::query("SELECT * FROM skills_snapshots WHERE machine_id = ?1")
            .bind(machine_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| PortFailure::Backend {
                detail: "skills snapshot read failed".into(),
            })?;
        row.map(|r| hydrate(&r)).transpose()
    }

    async fn list(
        &self,
        after_machine_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<SkillsSnapshot>, PortFailure> {
        let rows = sqlx::query("SELECT * FROM skills_snapshots WHERE (?1 IS NULL OR machine_id > ?1) ORDER BY machine_id LIMIT ?2")
            .bind(after_machine_id).bind(limit.clamp(1, 201))
            .fetch_all(&self.pool)
            .await
            .map_err(|_| PortFailure::Backend {
                detail: "skills matrix read failed".into(),
            })?;
        rows.iter().map(hydrate).collect()
    }

    async fn record(&self, snapshot: &SkillsSnapshot) -> Result<(), PortFailure> {
        let data = serde_json::to_string(&snapshot.data).map_err(|_| PortFailure::Backend {
            detail: "skills snapshot serialization failed".into(),
        })?;
        sqlx::query("INSERT INTO skills_snapshots (machine_id, availability, cli_version, data_json, update_check, observed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(machine_id) DO UPDATE SET availability=excluded.availability, cli_version=excluded.cli_version, data_json=excluded.data_json, update_check=excluded.update_check, observed_at=excluded.observed_at")
            .bind(&snapshot.machine_id).bind(availability_id(&snapshot.availability)).bind(&snapshot.cli_version).bind(data).bind(&snapshot.update_check).bind(snapshot.observed_at)
            .execute(&self.pool).await.map_err(|_| PortFailure::Backend { detail: "skills snapshot write failed".into() })?;
        Ok(())
    }
}

fn availability_id(value: &SkillsAvailability) -> &'static str {
    match value {
        SkillsAvailability::Available => "available",
        SkillsAvailability::Absent => "absent",
        SkillsAvailability::Unsupported => "unsupported",
    }
}

fn hydrate(row: &sqlx::sqlite::SqliteRow) -> Result<SkillsSnapshot, PortFailure> {
    let availability = match row.get::<String, _>("availability").as_str() {
        "available" => SkillsAvailability::Available,
        "absent" => SkillsAvailability::Absent,
        "unsupported" => SkillsAvailability::Unsupported,
        _ => {
            return Err(PortFailure::Backend {
                detail: "stored skills availability is invalid".into(),
            });
        }
    };
    let data = serde_json::from_str(row.get::<&str, _>("data_json")).map_err(|_| {
        PortFailure::Backend {
            detail: "stored skills data is invalid".into(),
        }
    })?;
    Ok(SkillsSnapshot {
        machine_id: row.get("machine_id"),
        availability,
        cli_version: row.get("cli_version"),
        data,
        update_check: row.get("update_check"),
        observed_at: row.get("observed_at"),
    })
}
