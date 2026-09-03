//! The operation repository: the SQLite implementation of the application's
//! [`OperationPort`].
//!
//! Truth is preserved across restarts by construction — every fact lives in a
//! row, and the domain state machine (see `fleet_core`) validates every
//! transition before the row changes. Idempotency is enforced by a unique key
//! with a read-back: a duplicate accepted request returns the original
//! operation rather than a second one.

use async_trait::async_trait;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use fleet_application::operation::{Operation, OperationPort, PortFailure, QueueDepths};
use fleet_core::{OperationState, validate_transition};

/// A repository problem, carrying the context the use-case layer maps onto
/// public errors.
#[derive(Debug)]
pub enum OperationStoreError {
    /// The named operation does not exist.
    NotFound {
        /// The id that was not found.
        id: String,
    },
    /// The domain refused the state transition.
    InvalidTransition {
        /// The domain's refusal.
        error: fleet_core::InvalidTransitionError,
    },
    /// A progress or result field exceeded its bound.
    TooLarge {
        /// The field that overflowed.
        field: &'static str,
        /// The observed size.
        size: usize,
        /// The allowed size.
        limit: usize,
    },
    /// The database refused the operation.
    Query {
        /// The operation that failed.
        context: &'static str,
        /// The database's detail.
        detail: String,
    },
}

impl std::fmt::Display for OperationStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { id } => write!(f, "no operation {id:?}"),
            Self::InvalidTransition { error } => write!(f, "{error}"),
            Self::TooLarge { field, size, limit } => {
                write!(f, "{field} is {size} bytes, over the {limit}-byte bound")
            }
            Self::Query { context, detail } => write!(f, "operation {context} failed: {detail}"),
        }
    }
}

impl std::error::Error for OperationStoreError {}

/// The bound for public result and error payloads.
pub const MAX_RESULT_JSON: usize = 8 * 1024;

/// The bound for progress messages.
pub const MAX_PROGRESS_MESSAGE: usize = 256;

/// The operation repository over a pool.
#[derive(Debug)]
pub struct OperationRepository {
    pool: SqlitePool,
}

impl OperationRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OperationPort for OperationRepository {
    async fn create(
        &self,
        kind: &str,
        idempotency_key: Option<&str>,
        deadline_at: Option<i64>,
        correlation_id: Option<&str>,
    ) -> Result<Operation, PortFailure> {
        let id = Uuid::now_v7().to_string();
        let now = fleet_core::SystemClock::now_unix_millis();
        let result = sqlx::query(
            "INSERT INTO operations \
             (id, kind, state, idempotency_key, deadline_at, cancel_requested, correlation_id, created_at, updated_at) \
             VALUES (?1, ?2, 'pending', ?3, ?4, 0, ?5, ?6, ?6)",
        )
        .bind(&id)
        .bind(kind)
        .bind(idempotency_key)
        .bind(deadline_at)
        .bind(correlation_id)
        .bind(now)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => self.get(&id).await,
            Err(error) if is_unique_violation(&error) => {
                // The key existed (or raced): the original operation wins.
                let existing = sqlx::query("SELECT id FROM operations WHERE idempotency_key = ?1")
                    .bind(idempotency_key)
                    .fetch_one(&self.pool)
                    .await;
                match existing {
                    Ok(row) => {
                        let id: String = row.get(0);
                        self.get(&id).await
                    }
                    Err(_) => Err(PortFailure::Backend {
                        detail: "the idempotency key raced and the winner could not be read"
                            .to_owned(),
                    }),
                }
            }
            Err(error) => Err(PortFailure::Backend {
                detail: format!("operation create failed: {error}"),
            }),
        }
    }

    async fn get(&self, id: &str) -> Result<Operation, PortFailure> {
        let row = sqlx::query("SELECT * FROM operations WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| PortFailure::Backend {
                detail: format!("operation get failed: {error}"),
            })?
            .ok_or_else(|| PortFailure::NotFound {
                what: format!("operation {id:?}"),
            })?;
        Ok(row_to_operation(&row))
    }

    async fn list(&self, limit: u32) -> Result<Vec<Operation>, PortFailure> {
        let limit = limit.clamp(1, 200);
        let rows =
            sqlx::query("SELECT * FROM operations ORDER BY created_at DESC, id DESC LIMIT ?1")
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|error| PortFailure::Backend {
                    detail: format!("operation list failed: {error}"),
                })?;
        Ok(rows.iter().map(row_to_operation).collect())
    }

    async fn request_cancel(&self, id: &str) -> Result<Operation, PortFailure> {
        let record: Operation = self.get(id).await?;
        sqlx::query("UPDATE operations SET cancel_requested = 1, updated_at = ?2 WHERE id = ?1")
            .bind(id)
            .bind(fleet_core::SystemClock::now_unix_millis())
            .execute(&self.pool)
            .await
            .map_err(|error| PortFailure::Backend {
                detail: format!("operation request_cancel failed: {error}"),
            })?;
        // Move into `cancelling` when the domain allows; a pending or running
        // operation can, terminal ones simply carry the flag.
        let from =
            OperationState::from_id(&record.state).map_err(|error| PortFailure::Backend {
                detail: error.to_string(),
            })?;
        if validate_transition(from, OperationState::Cancelling).is_ok() {
            self.transition(id, "cancelling").await?;
        }
        self.get(id).await
    }

    async fn transition(&self, id: &str, state: &str) -> Result<Operation, PortFailure> {
        let record: Operation = self.get(id).await?;
        let from =
            OperationState::from_id(&record.state).map_err(|error| PortFailure::Backend {
                detail: error.to_string(),
            })?;
        let to = OperationState::from_id(state).map_err(|error| PortFailure::Backend {
            detail: error.to_string(),
        })?;
        validate_transition(from, to).map_err(|error| PortFailure::Backend {
            detail: error.to_string(),
        })?;
        sqlx::query("UPDATE operations SET state = ?2, updated_at = ?3 WHERE id = ?1")
            .bind(id)
            .bind(to.id())
            .bind(fleet_core::SystemClock::now_unix_millis())
            .execute(&self.pool)
            .await
            .map_err(|error| PortFailure::Backend {
                detail: format!("operation transition failed: {error}"),
            })?;
        self.get(id).await
    }

    async fn complete(
        &self,
        id: &str,
        state: &str,
        result_json: Option<&str>,
        error_json: Option<&str>,
    ) -> Result<Operation, PortFailure> {
        if let Some(result_json) = result_json {
            check_bound("result_json", result_json.len(), MAX_RESULT_JSON).map_err(|error| {
                PortFailure::Backend {
                    detail: error.to_string(),
                }
            })?;
        }
        if let Some(error_json) = error_json {
            check_bound("error_json", error_json.len(), MAX_RESULT_JSON).map_err(|error| {
                PortFailure::Backend {
                    detail: error.to_string(),
                }
            })?;
        }
        let record: Operation = self.get(id).await?;
        let from =
            OperationState::from_id(&record.state).map_err(|error| PortFailure::Backend {
                detail: error.to_string(),
            })?;
        let to = OperationState::from_id(state).map_err(|error| PortFailure::Backend {
            detail: error.to_string(),
        })?;
        validate_transition(from, to).map_err(|error| PortFailure::Backend {
            detail: error.to_string(),
        })?;
        sqlx::query(
            "UPDATE operations SET state = ?2, result_json = ?3, error_json = ?4, updated_at = ?5 WHERE id = ?1",
        )
        .bind(id)
        .bind(to.id())
        .bind(result_json)
        .bind(error_json)
        .bind(fleet_core::SystemClock::now_unix_millis())
        .execute(&self.pool)
        .await
        .map_err(|error| PortFailure::Backend {
            detail: format!("operation complete failed: {error}"),
        })?;
        self.get(id).await
    }

    async fn record_progress(
        &self,
        id: &str,
        current: Option<i64>,
        total: Option<i64>,
        message: Option<&str>,
    ) -> Result<(), PortFailure> {
        if let Some(message) = message {
            check_bound("progress_message", message.len(), MAX_PROGRESS_MESSAGE).map_err(
                |error| PortFailure::Backend {
                    detail: error.to_string(),
                },
            )?;
        }
        let updated = sqlx::query(
            "UPDATE operations SET progress_current = ?2, progress_total = ?3, progress_message = ?4, \
             updated_at = ?5 WHERE id = ?1",
        )
        .bind(id)
        .bind(current)
        .bind(total)
        .bind(message)
        .bind(fleet_core::SystemClock::now_unix_millis())
        .execute(&self.pool)
        .await
        .map_err(|error| PortFailure::Backend {
            detail: format!("operation record_progress failed: {error}"),
        })?;
        if updated.rows_affected() == 0 {
            return Err(PortFailure::NotFound {
                what: format!("operation {id:?}"),
            });
        }
        Ok(())
    }

    async fn claim_pending(
        &self,
        worker_id: &str,
        now: i64,
    ) -> Result<Option<Operation>, PortFailure> {
        // The compare-and-set: only the writer whose UPDATE lands while the
        // row is still pending owns the claim. Two racing workers get two
        // different rows, never the same one twice.
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| PortFailure::Backend {
                detail: format!("claim begin failed: {error}"),
            })?;
        let candidate: Option<String> = sqlx::query_scalar(
            "SELECT id FROM operations WHERE state = 'pending' AND (deadline_at IS NULL OR deadline_at > ?1) \
             ORDER BY created_at ASC, id ASC LIMIT 1",
        )
        .bind(now)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| PortFailure::Backend {
            detail: format!("claim select failed: {error}"),
        })?;
        let Some(id) = candidate else {
            return Ok(None);
        };
        let updated = sqlx::query(
            "UPDATE operations SET state = 'running', worker_id = ?2, claimed_at = ?3, updated_at = ?3 \
             WHERE id = ?1 AND state = 'pending'",
        )
        .bind(&id)
        .bind(worker_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|error| PortFailure::Backend {
            detail: format!("claim update failed: {error}"),
        })?;
        tx.commit().await.map_err(|error| PortFailure::Backend {
            detail: format!("claim commit failed: {error}"),
        })?;
        if updated.rows_affected() == 0 {
            return Ok(None);
        }
        Ok(Some(self.get(&id).await?))
    }

    async fn expired_claims(&self, now: i64, lease_ms: i64) -> Result<Vec<Operation>, PortFailure> {
        let rows = sqlx::query(
            "SELECT * FROM operations WHERE state IN ('running', 'cancelling') \
             AND claimed_at IS NOT NULL AND claimed_at < ?1 ORDER BY claimed_at ASC",
        )
        .bind(now.saturating_sub(lease_ms))
        .fetch_all(&self.pool)
        .await
        .map_err(|error| PortFailure::Backend {
            detail: format!("expired claims select failed: {error}"),
        })?;
        Ok(rows.iter().map(row_to_operation).collect())
    }

    async fn sweep_deadlines(&self, now: i64) -> Result<Vec<String>, PortFailure> {
        // Find, do not transition: completing is the service's decision, so
        // the audit outcome and the state change land together.
        let expired = sqlx::query(
            "SELECT id FROM operations \
             WHERE deadline_at IS NOT NULL AND deadline_at <= ?1 \
             AND state IN ('pending', 'running', 'cancelling')",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| PortFailure::Backend {
            detail: format!("sweep select failed: {error}"),
        })?;
        Ok(expired
            .iter()
            .map(|row| row.get::<String, _>("id"))
            .collect())
    }

    async fn queue_depths(&self) -> Result<QueueDepths, PortFailure> {
        use sqlx::Row as _;
        let row = sqlx::query(
            "SELECT \
             COUNT(*) FILTER (WHERE state = 'pending') AS pending, \
             COUNT(*) FILTER (WHERE state = 'running') AS running, \
             COUNT(*) FILTER (WHERE state = 'cancelling') AS cancelling \
             FROM operations",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|error| PortFailure::Backend {
            detail: format!("queue depths failed: {error}"),
        })?;
        Ok(QueueDepths {
            pending: row.get("pending"),
            running: row.get("running"),
            cancelling: row.get("cancelling"),
        })
    }
}

fn check_bound(field: &'static str, size: usize, limit: usize) -> Result<(), OperationStoreError> {
    if size > limit {
        Err(OperationStoreError::TooLarge { field, size, limit })
    } else {
        Ok(())
    }
}

fn row_to_operation(row: &sqlx::sqlite::SqliteRow) -> Operation {
    use sqlx::Row as _;
    Operation {
        id: row.get("id"),
        kind: row.get("kind"),
        state: row.get("state"),
        idempotency_key: row.get("idempotency_key"),
        progress_current: row.get("progress_current"),
        progress_total: row.get("progress_total"),
        progress_message: row.get("progress_message"),
        deadline_at: row.get("deadline_at"),
        cancel_requested: row.get::<i64, _>("cancel_requested") != 0,
        result_json: row.get("result_json"),
        error_json: row.get("error_json"),
        correlation_id: row.get("correlation_id"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
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
