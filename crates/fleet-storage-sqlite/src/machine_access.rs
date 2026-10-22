//! The SQLite adapters of machine access (#493, ADR 0017): endpoint default
//! auth and collected-file metadata. Kinds and references only; a private
//! key is never stored here.

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;
use uuid::Uuid;

use fleet_application::machine_access::{
    EndpointAuth, EndpointAuthPort, MachineFile, MachineFilePort, NewMachineFile,
};

/// Endpoint default auth over a pool.
#[derive(Debug)]
pub struct EndpointAuthRepository {
    pool: SqlitePool,
}

impl EndpointAuthRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl EndpointAuthPort for EndpointAuthRepository {
    async fn get(&self, endpoint_id: &str) -> Result<Option<EndpointAuth>, String> {
        let row =
            sqlx::query("SELECT kind, reference FROM machine_endpoint_auth WHERE endpoint_id = ?1")
                .bind(endpoint_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| format!("endpoint auth read failed: {error}"))?;
        let Some(row) = row else { return Ok(None) };
        let kind: String = row.get("kind");
        let reference: Option<String> = row.get("reference");
        match (kind.as_str(), reference) {
            ("agent", _) => Ok(Some(EndpointAuth::Agent)),
            ("identityFile", Some(path)) => Ok(Some(EndpointAuth::IdentityFile { path })),
            ("secret", Some(credential)) => Ok(Some(EndpointAuth::Secret { credential })),
            _ => Err("a stored endpoint auth is malformed".to_owned()),
        }
    }

    async fn set(&self, endpoint_id: &str, auth: Option<&EndpointAuth>) -> Result<(), String> {
        let Some(auth) = auth else {
            sqlx::query("DELETE FROM machine_endpoint_auth WHERE endpoint_id = ?1")
                .bind(endpoint_id)
                .execute(&self.pool)
                .await
                .map_err(|error| format!("endpoint auth clear failed: {error}"))?;
            return Ok(());
        };
        let (kind, reference) = match auth {
            EndpointAuth::Agent => ("agent", None),
            EndpointAuth::IdentityFile { path } => ("identityFile", Some(path.as_str())),
            EndpointAuth::Secret { credential } => ("secret", Some(credential.as_str())),
        };
        sqlx::query(
            "INSERT INTO machine_endpoint_auth (endpoint_id, kind, reference, updated_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT (endpoint_id) DO UPDATE SET kind = excluded.kind, \
             reference = excluded.reference, updated_at = excluded.updated_at",
        )
        .bind(endpoint_id)
        .bind(kind)
        .bind(reference)
        .bind(fleet_core::SystemClock::now_unix_millis())
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("endpoint auth write failed: {error}"))
    }
}

/// Collected-file metadata over a pool.
#[derive(Debug)]
pub struct MachineFileRepository {
    pool: SqlitePool,
}

impl MachineFileRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_file(row: &sqlx::sqlite::SqliteRow) -> Result<MachineFile, String> {
        Ok(MachineFile {
            id: row.get("id"),
            machine_id: row.get("machine_id"),
            owner: row.get("owner"),
            name: row.get("name"),
            size_bytes: u64::try_from(row.get::<i64, _>("size_bytes"))
                .map_err(|_| "a file size is negative".to_owned())?,
            sha256: row.get("sha256"),
            location: row.get("location"),
            operation_id: row.get("operation_id"),
            created_at: row.get("created_at"),
            retain_until: row.get("retain_until"),
        })
    }
}

#[async_trait]
impl MachineFilePort for MachineFileRepository {
    async fn insert(&self, new: &NewMachineFile) -> Result<MachineFile, String> {
        let id = Uuid::now_v7().to_string();
        let size = i64::try_from(new.blob.size_bytes)
            .map_err(|_| "the file size does not fit the store".to_owned())?;
        sqlx::query(
            "INSERT INTO machine_files (id, machine_id, owner, name, size_bytes, sha256, location, operation_id, created_at, retain_until) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(&id)
        .bind(&new.machine_id)
        .bind(&new.owner)
        .bind(&new.name)
        .bind(size)
        .bind(&new.blob.sha256)
        .bind(&new.blob.location)
        .bind(&new.operation_id)
        .bind(new.created_at)
        .bind(new.retain_until)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("machine file insert failed: {error}"))?;
        Ok(MachineFile {
            id,
            machine_id: new.machine_id.clone(),
            owner: new.owner.clone(),
            name: new.name.clone(),
            size_bytes: new.blob.size_bytes,
            sha256: new.blob.sha256.clone(),
            location: new.blob.location.clone(),
            operation_id: new.operation_id.clone(),
            created_at: new.created_at,
            retain_until: new.retain_until,
        })
    }

    async fn get(&self, id: &str) -> Result<Option<MachineFile>, String> {
        sqlx::query("SELECT * FROM machine_files WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("machine file read failed: {error}"))?
            .map(|row| Self::row_to_file(&row))
            .transpose()
    }

    async fn list(&self, machine_id: &str, limit: u32) -> Result<Vec<MachineFile>, String> {
        sqlx::query(
            "SELECT * FROM machine_files WHERE machine_id = ?1 ORDER BY created_at DESC, id DESC LIMIT ?2",
        )
        .bind(machine_id)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("machine file list failed: {error}"))?
        .iter()
        .map(Self::row_to_file)
        .collect()
    }

    async fn expired(&self, now: i64, limit: u32) -> Result<Vec<MachineFile>, String> {
        sqlx::query(
            "SELECT * FROM machine_files WHERE retain_until <= ?1 ORDER BY retain_until LIMIT ?2",
        )
        .bind(now)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("machine file expiry read failed: {error}"))?
        .iter()
        .map(Self::row_to_file)
        .collect()
    }

    async fn delete(&self, id: &str) -> Result<bool, String> {
        sqlx::query("DELETE FROM machine_files WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map(|done| done.rows_affected() > 0)
            .map_err(|error| format!("machine file delete failed: {error}"))
    }

    async fn location_references(&self, location: &str) -> Result<u64, String> {
        sqlx::query_scalar::<_, i64>(
            "SELECT (SELECT count(*) FROM machine_files WHERE location = ?1) \
             + (SELECT count(*) FROM lab_artifacts WHERE location = ?1)",
        )
        .bind(location)
        .fetch_one(&self.pool)
        .await
        .map(|count| u64::try_from(count).unwrap_or(0))
        .map_err(|error| format!("machine file location check failed: {error}"))
    }
}
