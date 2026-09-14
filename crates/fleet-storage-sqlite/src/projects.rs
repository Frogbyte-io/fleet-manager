//! The project repository: the SQLite implementation of the application's
//! [`ProjectPort`].
//!
//! The normalized remote is the identity — a unique index refuses a second
//! registration of the same repository, and the use case maps that to a
//! caller-safe conflict. Checkouts are per-machine observed facts, upserted
//! per `(project, machine, root)` with the newest observation winning;
//! deleting a project cascades to its checkouts, and never to the Git
//! repositories themselves.

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;
use uuid::Uuid;

use fleet_application::operation::PortFailure;
use fleet_application::project::{NewProject, ProjectFilter, ProjectPort};
use fleet_core::{CheckoutFact, Project};

/// The project repository over a pool.
#[derive(Debug)]
pub struct ProjectRepository {
    pool: SqlitePool,
}

impl ProjectRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ProjectPort for ProjectRepository {
    async fn create(&self, project: &NewProject) -> Result<Project, PortFailure> {
        let id = Uuid::now_v7().to_string();
        let now = fleet_core::SystemClock::now_unix_millis();
        let result = sqlx::query(
            "INSERT INTO projects (id, remote, name, description, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        )
        .bind(&id)
        .bind(&project.remote)
        .bind(&project.name)
        .bind(&project.description)
        .bind(now)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => self.get(&id).await,
            Err(error) if is_unique_violation(&error) => Err(PortFailure::Backend {
                detail: format!(
                    "the remote {:?} or name {:?} is already registered",
                    project.remote, project.name
                ),
            }),
            Err(error) => Err(backend("create", &error)),
        }
    }

    async fn get(&self, id: &str) -> Result<Project, PortFailure> {
        let row: Option<sqlx::sqlite::SqliteRow> =
            sqlx::query("SELECT * FROM projects WHERE id = ?1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| backend("get", &error))?;
        let row = row.ok_or_else(|| PortFailure::NotFound {
            what: format!("project {id:?}"),
        })?;
        Ok(hydrate(&row))
    }

    async fn list(&self, filter: &ProjectFilter, limit: u32) -> Result<Vec<Project>, PortFailure> {
        let limit = limit.clamp(1, 200);
        let rows = sqlx::query(
            "SELECT * FROM projects \
             WHERE (?1 IS NULL OR remote LIKE ?1 || '%') \
               AND (?2 IS NULL OR name LIKE '%' || ?2 || '%') \
             ORDER BY created_at DESC, id DESC LIMIT ?3",
        )
        .bind(filter.remote_prefix.as_deref())
        .bind(filter.name_substring.as_deref())
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| backend("list", &error))?;
        Ok(rows.iter().map(hydrate).collect())
    }

    async fn update(
        &self,
        id: &str,
        name: &str,
        description: &str,
    ) -> Result<Project, PortFailure> {
        let now = fleet_core::SystemClock::now_unix_millis();
        let updated = sqlx::query(
            "UPDATE projects SET name = ?2, description = ?3, updated_at = ?4 WHERE id = ?1",
        )
        .bind(id)
        .bind(name)
        .bind(description)
        .bind(now)
        .execute(&self.pool)
        .await;
        match updated {
            Ok(result) if result.rows_affected() == 0 => Err(PortFailure::NotFound {
                what: format!("project {id:?}"),
            }),
            Err(error) if is_unique_violation(&error) => Err(PortFailure::Backend {
                detail: format!("the project name {name:?} is already taken"),
            }),
            Err(error) => Err(backend("update", &error)),
            Ok(_) => self.get(id).await,
        }
    }

    async fn delete(&self, id: &str) -> Result<(), PortFailure> {
        let deleted = sqlx::query("DELETE FROM projects WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|error| backend("delete", &error))?;
        if deleted.rows_affected() == 0 {
            return Err(PortFailure::NotFound {
                what: format!("project {id:?}"),
            });
        }
        Ok(())
    }

    async fn record_checkout(&self, fact: &CheckoutFact) -> Result<(), PortFailure> {
        let result = sqlx::query(
            "INSERT INTO project_checkouts \
             (id, project_id, machine_id, root, branch, dirty, source, observed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             ON CONFLICT(project_id, machine_id, root) DO UPDATE SET \
             branch = excluded.branch, dirty = excluded.dirty, \
             source = excluded.source, observed_at = excluded.observed_at",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(&fact.project_id)
        .bind(&fact.machine_id)
        .bind(&fact.root)
        .bind(&fact.branch)
        .bind(fact.dirty)
        .bind(&fact.source)
        .bind(fact.observed_at)
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
                    what: format!("project {:?}", fact.project_id),
                })
            }
            Err(error) => Err(backend("record_checkout", &error)),
        }
    }

    async fn checkouts(&self, project_id: &str) -> Result<Vec<CheckoutFact>, PortFailure> {
        let rows = sqlx::query(
            "SELECT machine_id, root, branch, dirty, source, observed_at \
             FROM project_checkouts WHERE project_id = ?1 \
             ORDER BY observed_at DESC, id DESC",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| backend("checkouts", &error))?;
        Ok(rows
            .iter()
            .map(|row| CheckoutFact {
                project_id: project_id.to_owned(),
                machine_id: row.get("machine_id"),
                root: row.get("root"),
                branch: row.get("branch"),
                dirty: row.get("dirty"),
                source: row.get("source"),
                observed_at: row.get("observed_at"),
            })
            .collect())
    }
}

fn hydrate(row: &sqlx::sqlite::SqliteRow) -> Project {
    Project {
        id: row.get("id"),
        remote: row.get("remote"),
        name: row.get("name"),
        description: row.get("description"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn backend(context: &str, error: &sqlx::Error) -> PortFailure {
    PortFailure::Backend {
        detail: format!("project {context} failed: {error}"),
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
