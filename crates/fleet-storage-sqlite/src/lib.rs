//! The SQLite persistence adapter.
//!
//! Runtime truth for the controller lives in one SQLite database owned by one
//! always-active controller process. This crate owns the mechanical halves of
//! that promise: connection setup (WAL, foreign keys, busy timeout), embedded
//! atomic migrations, the singleton lock, small metadata helpers, and the
//! backup procedure. It interprets nothing: desired-state semantics belong to
//! the application and domain layers, and later repositories extend this
//! foundation rather than reopening it.
//!
//! See `README.md` in this crate for the backup/restore procedure and the
//! local-filesystem constraint.
#![warn(missing_docs)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};

/// The embedded migrations; applied atomically, in order, exactly once.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// How long a writer waits for the database lock before its statement fails.
/// Enough to absorb writer bursts, small enough to fail loudly under real
/// contention.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The maximum number of pooled connections. SQLite's write path is
/// serialized by the database itself, so a larger pool does not add write
/// parallelism; it only adds reader concurrency and file-descriptor weight.
const MAX_CONNECTIONS: u32 = 4;

/// A persistence problem that is safe to print: file paths and SQL state,
/// never secret values (this crate stores none).
#[derive(Debug)]
pub enum StorageError {
    /// The database file could not be opened or another controller holds it.
    Open {
        /// The database path involved.
        path: PathBuf,
        /// What went wrong, including the OS reason.
        detail: String,
    },
    /// The schema is newer than this build knows; downgrades are unsupported.
    SchemaAhead {
        /// The newest migration version recorded in the database.
        found: i64,
        /// The newest migration version this build ships.
        known: i64,
    },
    /// Migrations failed; the database is left as migration mechanics left it.
    Migrate {
        /// The migration's failure detail.
        detail: String,
    },
    /// Another controller already owns the singleton lock.
    LockHeld {
        /// The lock file whose OS lock is owned by another process.
        path: PathBuf,
    },
    /// A query or transaction failed at runtime.
    Query {
        /// The SQL context in which the failure happened.
        context: &'static str,
        /// The database's failure detail.
        detail: String,
    },
    /// A backup could not be written.
    Backup {
        /// The target path that could not be written.
        path: PathBuf,
        /// What went wrong.
        detail: String,
    },
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open { path, detail } => {
                write!(f, "cannot open database {}: {detail}", path.display())
            }
            Self::SchemaAhead { found, known } => write!(
                f,
                "database schema version {found} is newer than this build knows ({known}); \
                 schema downgrades are unsupported"
            ),
            Self::Migrate { detail } => write!(f, "migrations failed: {detail}"),
            Self::LockHeld { path } => write!(
                f,
                "another controller already owns {}; only one active controller is supported",
                path.display()
            ),
            Self::Query { context, detail } => write!(f, "query failed in {context}: {detail}"),
            Self::Backup { path, detail } => {
                write!(f, "backup to {} failed: {detail}", path.display())
            }
        }
    }
}

impl std::error::Error for StorageError {}

/// An opened, migrated, locked database: the store every later repository is
/// built on. Dropping it closes the pool and releases the singleton lock.
#[derive(Debug)]
pub struct Store {
    pool: SqlitePool,
    database_path: PathBuf,
    /// Holding the lock file's OS lock open is what enforces the lock; the
    /// kernel releases it automatically if this process dies.
    _lock: std::fs::File,
}

impl Store {
    /// Opens (creating if needed) the database at `path`, applies pending
    /// migrations, and acquires the singleton lock that enforces the
    /// one-active-controller constraint.
    ///
    /// # Errors
    ///
    /// Fails closed: on a schema newer than this build, on migration failure,
    /// or when another controller owns the lock, the database is not opened
    /// for use.
    pub async fn open(path: &Path) -> Result<Self, StorageError> {
        // The singleton lock must be acquired before anything is written:
        // two concurrent controllers must not both run migrations. The OS
        // releases the lock if the process dies, so a crash never wedges the
        // next startup behind a stale holder.
        let lock_path = path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| StorageError::Open {
                path: lock_path.clone(),
                detail: format!("cannot create the database directory: {error}"),
            })?;
        }
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|error| StorageError::Open {
                path: lock_path.clone(),
                detail: format!("cannot open the lock file: {error}"),
            })?;
        match fs4::FileExt::try_lock(&lock) {
            Ok(()) => {}
            Err(fs4::TryLockError::WouldBlock) => {
                return Err(StorageError::LockHeld { path: lock_path });
            }
            Err(fs4::TryLockError::Error(error)) => {
                return Err(StorageError::Open {
                    path: lock_path,
                    detail: format!("cannot acquire the controller lock: {error}"),
                });
            }
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(BUSY_TIMEOUT);
        let pool = SqlitePoolOptions::new()
            .max_connections(MAX_CONNECTIONS)
            .connect_with(options)
            .await
            .map_err(|error| StorageError::Open {
                path: path.to_path_buf(),
                detail: error.to_string(),
            })?;

        Self::check_schema_ahead(&pool).await?;
        MIGRATOR
            .run(&pool)
            .await
            .map_err(|error| StorageError::Migrate {
                detail: error.to_string(),
            })?;

        let store = Self {
            pool,
            database_path: path.to_path_buf(),
            _lock: lock,
        };
        store.record_ownership().await?;
        Ok(store)
    }

    /// The pooled connection handle repositories use. Borrowed, so callers
    /// cannot outlive the store or grow the pool outside policy.
    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Begins a write transaction with `BEGIN IMMEDIATE`.
    ///
    /// Under WAL, a transaction that reads first and writes later fails with
    /// an immediate `SQLITE_BUSY_SNAPSHOT` when another writer committed in
    /// between; taking the write lock up front makes the busy timeout apply
    /// and the write path deterministic. Repositories that will write must
    /// use this instead of a plain `BEGIN`.
    ///
    /// # Errors
    ///
    /// Fails when the transaction cannot start within the busy timeout.
    pub async fn begin_write(
        &self,
    ) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>, StorageError> {
        self.pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| StorageError::Query {
                context: "begin_write",
                detail: error.to_string(),
            })
    }

    /// The database file path this store was opened from.
    #[must_use]
    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    /// Closes the pool and releases the singleton lock.
    pub async fn close(self) {
        self.pool.close().await;
        // Releasing `self._lock` happens with the drop of `self`.
    }

    /// Reads one metadata fact; `None` when unset.
    ///
    /// # Errors
    ///
    /// Fails when the query itself fails.
    pub async fn get_metadata(&self, key: &str) -> Result<Option<String>, StorageError> {
        sqlx::query("SELECT value FROM schema_metadata WHERE key = ?1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map(|row| row.map(|row| row.get(0)))
            .map_err(|error| StorageError::Query {
                context: "get_metadata",
                detail: error.to_string(),
            })
    }

    /// Writes one metadata fact.
    ///
    /// # Errors
    ///
    /// Fails when the write itself fails.
    pub async fn set_metadata(&self, key: &str, value: &str) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO schema_metadata (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|error| StorageError::Query {
            context: "set_metadata",
            detail: error.to_string(),
        })
    }

    /// Writes a consistent snapshot of the database to `target` with SQLite's
    /// online backup (`VACUUM INTO`). The controller stays live during the
    /// copy. The target must not exist: SQLite refuses to overwrite, and so
    /// does this API rather than destroying an operator file for it.
    ///
    /// # Errors
    ///
    /// Fails when the target exists or the backup statement fails.
    pub async fn backup_to(&self, target: &Path) -> Result<(), StorageError> {
        if target.exists() {
            return Err(StorageError::Backup {
                path: target.to_path_buf(),
                detail: "the target file already exists; remove it first".to_owned(),
            });
        }
        sqlx::query("VACUUM INTO ?1")
            .bind(target.to_string_lossy().as_ref())
            .execute(&self.pool)
            .await
            .map_err(|error| StorageError::Backup {
                path: target.to_path_buf(),
                detail: error.to_string(),
            })?;
        Ok(())
    }

    /// Refuses to open a database written by a newer build. `sqlx` would apply
    /// nothing and fail later on unknown columns; this fails at open with a
    /// message that names the actual problem.
    async fn check_schema_ahead(pool: &SqlitePool) -> Result<(), StorageError> {
        let known_latest = MIGRATOR
            .migrations
            .last()
            .map_or(0, |migration| migration.version);
        let migrations_table: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
        )
        .fetch_optional(pool)
        .await
        .map_err(|error| StorageError::Query {
            context: "check_schema_ahead",
            detail: error.to_string(),
        })?;
        let recorded = if migrations_table.is_some() {
            let max: Option<i64> = sqlx::query("SELECT MAX(version) FROM _sqlx_migrations")
                .fetch_one(pool)
                .await
                .map_err(|error| StorageError::Query {
                    context: "check_schema_ahead",
                    detail: error.to_string(),
                })?
                .get(0);
            max.unwrap_or(0)
        } else {
            0
        };
        if recorded > known_latest {
            return Err(StorageError::SchemaAhead {
                found: recorded,
                known: known_latest,
            });
        }
        Ok(())
    }

    /// Records durable evidence of who holds the singleton responsibility.
    /// `acquired_at` is Unix epoch milliseconds; the OS lock is the actual
    /// enforcement, so precision beyond this is not needed.
    async fn record_ownership(&self) -> Result<(), StorageError> {
        let instance = uuid::Uuid::now_v7().to_string();
        let since_epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
        let now_millis =
            i64::try_from(since_epoch.unwrap_or_default().as_millis()).unwrap_or(i64::MAX);
        sqlx::query(
            "INSERT INTO controller_lock (id, instance_id, acquired_at) VALUES (1, ?1, ?2) \
             ON CONFLICT(id) DO UPDATE SET instance_id = excluded.instance_id, \
             acquired_at = excluded.acquired_at",
        )
        .bind(instance)
        .bind(now_millis)
        .execute(&self.pool)
        .await
        .map_err(|error| StorageError::Query {
            context: "record_ownership",
            detail: error.to_string(),
        })?;
        Ok(())
    }
}
