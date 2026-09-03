//! The audit ledger adapter: append intents and outcomes, query with
//! authorization and pagination.
//!
//! The event shape and the metadata rules come from the application layer
//! ([`fleet_application::audit`]); this adapter adds the mechanical
//! guarantees — append-only enforcement by database triggers, ordered
//! pagination, and intent appends that join a state-changing transaction so
//! an accepted action and its audit record commit or roll back together.

use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use uuid::Uuid;

use fleet_application::audit::{AuditEvent, AuditIntent, AuditOutcome};
use fleet_application::authz::{AccessRequest, Authorizer, Permission, authorize};

/// The ledger. Borrows the store's pool; audit writes share the store's
/// connection discipline.
#[derive(Debug)]
pub struct AuditLedger<'a> {
    pool: &'a SqlitePool,
}

/// A query or constraint failure on the ledger.
#[derive(Debug)]
pub enum AuditError {
    /// The caller is not authorized to read the ledger.
    Unauthorized(String),
    /// The database refused the operation.
    Query {
        /// The operation that failed.
        context: &'static str,
        /// The database's detail.
        detail: String,
    },
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized(detail) => write!(f, "audit query refused: {detail}"),
            Self::Query { context, detail } => write!(f, "audit {context} failed: {detail}"),
        }
    }
}

impl std::error::Error for AuditError {}

/// One page of the ledger, in append order.
#[derive(Debug)]
pub struct AuditPage {
    /// The events, ascending by sequence.
    pub events: Vec<AuditEvent>,
    /// The sequence to pass as [`Query::after_seq`] for the next page, when
    /// more events exist.
    pub next_seq: Option<i64>,
}

/// A ledger query.
#[derive(Clone, Copy, Debug, Default)]
pub struct Query {
    /// The exclusive sequence lower bound; `None` starts from the beginning.
    pub after_seq: Option<i64>,
    /// The page size, clamped to [`MAX_PAGE_SIZE`].
    pub limit: u32,
    /// Restrict to one correlation identity.
    pub correlation_id: Option<&'static str>,
}

/// The largest page the ledger will return.
pub const MAX_PAGE_SIZE: u32 = 200;

impl<'a> AuditLedger<'a> {
    /// Creates a ledger view over the store's pool.
    #[must_use]
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Appends an intent event.
    ///
    /// # Errors
    ///
    /// Fails when the database refuses the insert.
    pub async fn append_intent(&self, intent: &AuditIntent) -> Result<String, AuditError> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| AuditError::Query {
                context: "append_intent",
                detail: error.to_string(),
            })?;
        let id = append_intent_tx(&mut tx, intent)
            .await
            .map_err(|error| AuditError::Query {
                context: "append_intent",
                detail: error,
            })?;
        tx.commit().await.map_err(|error| AuditError::Query {
            context: "append_intent_commit",
            detail: error.to_string(),
        })?;
        Ok(id)
    }

    /// Appends the terminal outcome of a previously recorded intent. The
    /// intent's event is referenced by its id; the outcome is a new, separate
    /// event so the ledger's history is never mutated.
    ///
    /// # Errors
    ///
    /// Fails when the referenced intent does not exist or the database
    /// refuses the insert.
    pub async fn append_outcome(
        &self,
        intent_id: &str,
        outcome: AuditOutcome,
    ) -> Result<String, AuditError> {
        let intent = sqlx::query(
            "SELECT actor, action, resource, allowed, reason, correlation_id, operation_id, metadata_json \
             FROM audit_events WHERE id = ?1",
        )
        .bind(intent_id)
        .fetch_optional(self.pool)
        .await
        .map_err(|error| AuditError::Query { context: "outcome_select", detail: error.to_string() })?
        .ok_or_else(|| AuditError::Query {
            context: "outcome_select",
            detail: format!("no audit intent {intent_id:?}"),
        })?;

        let actor: String = intent.get("actor");
        let action: String = intent.get("action");
        let event_id = Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO audit_events \
             (id, occurred_at, actor, action, resource, allowed, reason, correlation_id, operation_id, outcome, metadata_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .bind(&event_id)
        .bind(epoch_millis())
        .bind(actor)
        .bind(action)
        .bind(intent.get::<Option<String>, _>("resource"))
        .bind(intent.get::<i64, _>("allowed"))
        .bind(intent.get::<String, _>("reason"))
        .bind(intent.get::<Option<String>, _>("correlation_id"))
        .bind(intent.get::<Option<String>, _>("operation_id"))
        .bind(outcome.id())
        .bind(intent.get::<String, _>("metadata_json"))
        .execute(self.pool)
        .await
        .map_err(|error| AuditError::Query { context: "append_outcome", detail: error.to_string() })?;
        Ok(event_id)
    }

    /// Reads one authorized, paginated page in append order.
    ///
    /// # Errors
    ///
    /// Fails closed with [`AuditError::Unauthorized`] when the caller lacks
    /// the audit-read permission.
    pub async fn query(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        query: Query,
    ) -> Result<AuditPage, AuditError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::AuditRead,
                resource: None,
            },
        )
        .map_err(|denied| AuditError::Unauthorized(denied.reason.to_string()))?;

        let limit = query.limit.clamp(1, MAX_PAGE_SIZE);
        let rows = sqlx::query(
            "SELECT seq, id, occurred_at, actor, action, resource, allowed, reason, correlation_id, \
             operation_id, outcome, metadata_json \
             FROM audit_events \
             WHERE (?1 IS NULL OR seq > ?1) AND (?2 IS NULL OR correlation_id = ?2) \
             ORDER BY seq ASC LIMIT ?3",
        )
        .bind(query.after_seq)
        .bind(query.correlation_id)
        .bind(limit)
        .fetch_all(self.pool)
        .await
        .map_err(|error| AuditError::Query { context: "query", detail: error.to_string() })?;

        let events: Vec<AuditEvent> = rows
            .iter()
            .map(|row| AuditEvent {
                seq: row.get("seq"),
                id: row.get("id"),
                occurred_at: row.get("occurred_at"),
                actor: row.get("actor"),
                action: row.get("action"),
                resource: row.get("resource"),
                allowed: row.get::<i64, _>("allowed") != 0,
                reason: row.get("reason"),
                correlation_id: row.get("correlation_id"),
                operation_id: row.get("operation_id"),
                outcome: row
                    .get::<Option<String>, _>("outcome")
                    .and_then(|text| outcome_from_id(&text)),
                metadata_json: row.get("metadata_json"),
            })
            .collect();

        let next_seq = if events.len() == usize::try_from(limit).unwrap_or(0) {
            events.last().map(|event| event.seq)
        } else {
            None
        };
        Ok(AuditPage { events, next_seq })
    }
}

/// Appends an intent inside an existing transaction, so the audit record and
/// the state change it describes commit together.
///
/// # Errors
///
/// Returns the database's failure detail when the insert fails; the caller's
/// transaction then rolls back, keeping state and audit consistent.
pub async fn append_intent_tx(
    tx: &mut Transaction<'_, Sqlite>,
    intent: &AuditIntent,
) -> Result<String, String> {
    let id = Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO audit_events \
         (id, occurred_at, actor, action, resource, allowed, reason, correlation_id, operation_id, outcome, metadata_json) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10)",
    )
    .bind(&id)
    .bind(epoch_millis())
    .bind(&intent.actor)
    .bind(&intent.action)
    .bind(&intent.resource)
    .bind(i64::from(intent.decision.allowed))
    .bind(intent.decision.reason.id())
    .bind(&intent.correlation_id)
    .bind(&intent.operation_id)
    .bind(intent.metadata.to_json())
    .execute(&mut **tx)
    .await
    .map_err(|error| error.to_string())?;
    Ok(id)
}

/// The audit sink the operation use cases call: appends intents for accepted
/// mutations and terminal outcomes, keyed by the operation they belong to.
#[derive(Debug)]
pub struct AuditSink {
    pool: SqlitePool,
}

impl AuditSink {
    /// Creates a sink over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl fleet_application::operation::AuditPort for AuditSink {
    async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
        AuditLedger::new(&self.pool)
            .append_intent(intent)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    async fn record_outcome(
        &self,
        operation_id: &str,
        outcome: AuditOutcome,
    ) -> Result<(), String> {
        let intent_id: Option<String> = sqlx::query(
            "SELECT id FROM audit_events WHERE operation_id = ?1 AND outcome IS NULL ORDER BY seq DESC LIMIT 1",
        )
        .bind(operation_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| format!("audit outcome select failed: {error}"))?
        .map(|row| row.get(0));
        let Some(intent_id) = intent_id else {
            return Err(format!("no audit intent for operation {operation_id:?}"));
        };
        AuditLedger::new(&self.pool)
            .append_outcome(&intent_id, outcome)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

fn outcome_from_id(text: &str) -> Option<AuditOutcome> {
    match text {
        "succeeded" => Some(AuditOutcome::Succeeded),
        "failed" => Some(AuditOutcome::Failed),
        "cancelled" => Some(AuditOutcome::Cancelled),
        _ => None,
    }
}

fn epoch_millis() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}
