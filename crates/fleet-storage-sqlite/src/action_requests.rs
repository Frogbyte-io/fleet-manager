//! The action request repository (FM-1040): the SQLite implementation of the
//! broker's [`ActionRequestPort`].
//!
//! Every state change is a compare-and-set `UPDATE ... WHERE state = ?from`
//! inside a `BEGIN IMMEDIATE` transaction that also appends the transition's
//! audit event. A transition that loses the compare-and-set changes and
//! audits nothing, so of N concurrent approvals exactly one commits.

use async_trait::async_trait;
use fleet_application::audit::AuditIntent;
use fleet_application::broker::{ActionRequest, ActionRequestPort, TransitionUpdate};
use fleet_core::{ActionRequestState, RiskClass};
use sqlx::{Row as _, SqlitePool};

use crate::audit::append_intent_tx;

/// The repository over a pool.
#[derive(Debug)]
pub struct ActionRequestRepository {
    pool: SqlitePool,
}

impl ActionRequestRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn row_to_request(row: &sqlx::sqlite::SqliteRow) -> Result<ActionRequest, String> {
    let parameters: String = row.get("parameters_json");
    let risk_class: String = row.get("risk_class");
    let state: String = row.get("state");
    Ok(ActionRequest {
        id: row.get("id"),
        requester: row.get("requester"),
        origin: row.get("origin"),
        action_id: row.get("action_id"),
        target: row.get("target"),
        parameters: serde_json::from_str(&parameters)
            .map_err(|_| "an action request's parameters are not JSON".to_owned())?,
        risk_class: RiskClass::from_id(&risk_class)?,
        reason: row.get("reason"),
        state: ActionRequestState::from_id(&state)?,
        decided_by: row.get("decided_by"),
        decided_at: row.get("decided_at"),
        decision_note: row.get("decision_note"),
        operation_id: row.get("operation_id"),
        failure: row.get("failure"),
        correlation_id: row.get("correlation_id"),
        idempotency_key: row.get("idempotency_key"),
        created_at: row.get("created_at"),
        expires_at: row.get("expires_at"),
        updated_at: row.get("updated_at"),
    })
}

#[async_trait]
impl ActionRequestPort for ActionRequestRepository {
    async fn insert(&self, request: &ActionRequest, audit: &AuditIntent) -> Result<(), String> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| format!("action request insert failed: {error}"))?;
        sqlx::query(
            "INSERT INTO action_requests \
             (id, requester, origin, action_id, target, parameters_json, risk_class, reason, \
              state, decided_by, decided_at, decision_note, operation_id, failure, \
              correlation_id, idempotency_key, created_at, expires_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
        )
        .bind(&request.id)
        .bind(&request.requester)
        .bind(&request.origin)
        .bind(&request.action_id)
        .bind(&request.target)
        .bind(request.parameters.to_string())
        .bind(request.risk_class.id())
        .bind(&request.reason)
        .bind(request.state.id())
        .bind(&request.decided_by)
        .bind(request.decided_at)
        .bind(&request.decision_note)
        .bind(&request.operation_id)
        .bind(&request.failure)
        .bind(&request.correlation_id)
        .bind(&request.idempotency_key)
        .bind(request.created_at)
        .bind(request.expires_at)
        .bind(request.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("action request insert failed: {error}"))?;
        append_intent_tx(&mut tx, audit).await?;
        tx.commit()
            .await
            .map_err(|error| format!("action request insert failed: {error}"))
    }

    async fn record_audit(&self, audit: &AuditIntent) -> Result<(), String> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| format!("action request audit failed: {error}"))?;
        append_intent_tx(&mut tx, audit).await?;
        tx.commit()
            .await
            .map_err(|error| format!("action request audit failed: {error}"))
    }

    async fn find_by_idempotency(
        &self,
        requester: &str,
        key: &str,
    ) -> Result<Option<ActionRequest>, String> {
        sqlx::query("SELECT * FROM action_requests WHERE requester = ?1 AND idempotency_key = ?2")
            .bind(requester)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("action request read failed: {error}"))?
            .map(|row| row_to_request(&row))
            .transpose()
    }

    async fn get(&self, id: &str) -> Result<Option<ActionRequest>, String> {
        sqlx::query("SELECT * FROM action_requests WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| format!("action request read failed: {error}"))?
            .map(|row| row_to_request(&row))
            .transpose()
    }

    async fn list(
        &self,
        state: Option<ActionRequestState>,
        limit: u32,
    ) -> Result<Vec<ActionRequest>, String> {
        sqlx::query(
            "SELECT * FROM action_requests WHERE (?1 IS NULL OR state = ?1) \
             ORDER BY created_at DESC, id DESC LIMIT ?2",
        )
        .bind(state.map(ActionRequestState::id))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("action request list failed: {error}"))?
        .iter()
        .map(row_to_request)
        .collect()
    }

    async fn transition(
        &self,
        id: &str,
        update: &TransitionUpdate,
        audit: &AuditIntent,
    ) -> Result<Option<ActionRequest>, String> {
        fleet_core::validate_action_request_transition(update.from, update.to)
            .map_err(|error| error.to_string())?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| format!("action request transition failed: {error}"))?;
        let result = sqlx::query(
            "UPDATE action_requests SET \
                 state = ?3, \
                 decided_by = COALESCE(?4, decided_by), \
                 decided_at = CASE WHEN ?4 IS NULL THEN decided_at ELSE ?8 END, \
                 decision_note = COALESCE(?5, decision_note), \
                 operation_id = COALESCE(?6, operation_id), \
                 failure = COALESCE(?7, failure), \
                 updated_at = ?8 \
             WHERE id = ?1 AND state = ?2 AND (?9 = 0 OR expires_at > ?8)",
        )
        .bind(id)
        .bind(update.from.id())
        .bind(update.to.id())
        .bind(&update.decided_by)
        .bind(&update.decision_note)
        .bind(&update.operation_id)
        .bind(&update.failure)
        .bind(update.at)
        .bind(i64::from(update.require_unexpired))
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("action request transition failed: {error}"))?;
        if result.rows_affected() != 1 {
            // Lost: nothing changed, nothing is audited.
            tx.rollback()
                .await
                .map_err(|error| format!("action request transition failed: {error}"))?;
            return Ok(None);
        }
        append_intent_tx(&mut tx, audit).await?;
        let row = sqlx::query("SELECT * FROM action_requests WHERE id = ?1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| format!("action request transition failed: {error}"))?;
        let updated = row_to_request(&row)?;
        tx.commit()
            .await
            .map_err(|error| format!("action request transition failed: {error}"))?;
        Ok(Some(updated))
    }
}
