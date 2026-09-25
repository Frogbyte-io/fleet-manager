//! The read-only audit surface over the application's authorized query.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Query, State},
    http::StatusCode,
};
use fleet_application::audit::{AuditEvent, AuditFilter, AuditQueries, AuditQueryError};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use std::str::FromStr as _;
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Page, PageInfo};
use crate::error::{ApiError, ApiErrorResponse};

fn audit_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<AuditQueries>, ApiErrorResponse> {
    state.audit.clone().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("audit_unavailable").expect("valid error code"),
            "the audit surface is not wired; the controller needs its database",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

fn invalid(message: &str, correlation_id: CorrelationId) -> ApiErrorResponse {
    let public = PublicError::new(
        ErrorCode::from_str("invalid_request").expect("valid error code"),
        message.to_owned(),
        RetryClass::Never,
    );
    ApiError::new(&public, correlation_id).with_status(StatusCode::BAD_REQUEST)
}

fn map_error(error: AuditQueryError, correlation_id: CorrelationId) -> ApiErrorResponse {
    let (status, code, retry, message) = match error {
        AuditQueryError::Denied(decision) => (
            StatusCode::FORBIDDEN,
            "denied",
            RetryClass::Never,
            format!("denied: {decision}"),
        ),
        AuditQueryError::Invalid { detail } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
            detail,
        ),
        AuditQueryError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
            "the request could not be completed; the detail is in the controller log".to_owned(),
        ),
    };
    let public = PublicError::new(
        ErrorCode::from_str(code).expect("valid error code"),
        message,
        retry,
    );
    ApiError::new(&public, correlation_id).with_status(status)
}

/// One audit event, containing validated metadata and no raw request payload.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventDto {
    /// Append-only ledger sequence.
    pub seq: i64,
    /// Event identity.
    pub id: String,
    /// When the event was recorded (epoch milliseconds).
    pub occurred_at: i64,
    /// Acting principal id.
    pub actor: String,
    /// Action id.
    pub action: String,
    /// Resource id, when present.
    pub resource: Option<String>,
    /// Whether authorization allowed the request.
    pub allowed: bool,
    /// Stable authorization decision reason.
    pub reason: String,
    /// Correlation id, when present.
    pub correlation_id: Option<String>,
    /// Durable operation id, when present.
    pub operation_id: Option<String>,
    /// Terminal outcome id, when present.
    pub outcome: Option<String>,
    /// Safe metadata facts with fixed formats. Free-form strings are omitted
    /// because caller text can contain credentials even under innocuous keys.
    pub metadata: serde_json::Value,
}

impl From<AuditEvent> for AuditEventDto {
    fn from(event: AuditEvent) -> Self {
        let metadata = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(
            &event.metadata_json,
        )
        .unwrap_or_default()
        .into_iter()
        .filter(|(key, value)| safe_metadata_entry(key, value))
        .collect::<serde_json::Map<_, _>>();
        Self {
            seq: event.seq,
            id: event.id,
            occurred_at: event.occurred_at,
            actor: event.actor,
            action: event.action,
            resource: event.resource,
            allowed: event.allowed,
            reason: event.reason,
            correlation_id: event.correlation_id,
            operation_id: event.operation_id,
            outcome: event.outcome.map(|outcome| outcome.id().to_owned()),
            metadata: serde_json::Value::Object(metadata),
        }
    }
}

/// Only expose fixed-format metadata facts. Free-form strings can contain
/// credentials even when their key looks harmless (for example `purpose`).
fn safe_metadata_entry(key: &str, value: &serde_json::Value) -> bool {
    if key == "peerLoopback" {
        return value.is_boolean();
    }
    if key == "identityHeaderNames" {
        return value.as_array().is_some_and(|names| {
            !names.is_empty()
                && names.len() <= fleet_core::TAILSCALE_IDENTITY_HEADER_NAMES.len()
                && names.iter().all(|name| {
                    name.as_str().is_some_and(|name| {
                        fleet_core::TAILSCALE_IDENTITY_HEADER_NAMES.contains(&name)
                    })
                })
        });
    }
    let Some(value) = value.as_str() else {
        return false;
    };
    match key {
        // Event names are selected by application code and use this stable
        // identifier syntax; arbitrary caller text is never an event name.
        "event" => {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        }
        // Content identities are fixed-width hexadecimal digests.
        "digest" | "commitSha" => {
            (40..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        }
        // These identifiers are protocol enums or decimal counts.
        "kind" => {
            !value.is_empty()
                && value.len() <= 64
                && value.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'.' | b'-')
                })
        }
        "attempt" | "vmid" => !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        // Names, purposes, notes, hostnames, remotes, and opaque ids are
        // deliberately omitted because they can be caller-controlled text.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(metadata_json: &str) -> AuditEvent {
        AuditEvent {
            seq: 1,
            id: "event-1".to_owned(),
            occurred_at: 1,
            actor: "operator".to_owned(),
            action: "audit.read".to_owned(),
            resource: None,
            allowed: true,
            reason: "allowed".to_owned(),
            correlation_id: None,
            operation_id: None,
            outcome: None,
            metadata_json: metadata_json.to_owned(),
        }
    }

    #[test]
    fn dto_omits_free_form_metadata_values() {
        let dto = AuditEventDto::from(event(
            r#"{"event":"lab_lease_creating","kind":"mise.install","purpose":"operator supplied access phrase","name":"operator supplied"}"#,
        ));

        assert_eq!(dto.metadata["event"], "lab_lease_creating");
        assert_eq!(dto.metadata["kind"], "mise.install");
        assert!(dto.metadata.get("purpose").is_none());
        assert!(dto.metadata.get("name").is_none());
    }

    #[test]
    fn dto_rejects_malformed_values_even_for_known_metadata_keys() {
        let dto = AuditEventDto::from(event(
            r#"{"event":"authorization=example","digest":"not-a-digest","attempt":"one"}"#,
        ));

        assert!(dto.metadata.as_object().unwrap().is_empty());
    }

    #[test]
    fn dto_exposes_only_fixed_tailscale_identity_evidence() {
        let dto = AuditEventDto::from(event(
            r#"{"identityHeaderNames":["tailscale-user-login"],"peerLoopback":false,"rawLogin":"alice@example.com"}"#,
        ));
        assert_eq!(
            dto.metadata["identityHeaderNames"][0],
            "tailscale-user-login"
        );
        assert_eq!(dto.metadata["peerLoopback"], false);
        assert!(dto.metadata.get("rawLogin").is_none());

        let untrusted = AuditEventDto::from(event(
            r#"{"identityHeaderNames":["x-forwarded-for"],"peerLoopback":"false"}"#,
        ));
        assert!(untrusted.metadata.as_object().unwrap().is_empty());
    }
}

/// Query parameters for the audit ledger.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAuditParams {
    /// Acting principal id.
    pub actor: Option<String>,
    /// Action id.
    pub action: Option<String>,
    /// Resource id.
    pub resource: Option<String>,
    /// Decision or terminal outcome id.
    pub outcome: Option<String>,
    /// Inclusive lower bound, epoch milliseconds.
    pub from: Option<String>,
    /// Inclusive upper bound, epoch milliseconds.
    pub to: Option<String>,
    /// Opaque cursor returned by the preceding page.
    pub cursor: Option<String>,
    /// Maximum events returned.
    pub limit: Option<String>,
}

fn parse_i64_filter(
    name: &str,
    value: Option<String>,
    correlation_id: CorrelationId,
) -> Result<Option<i64>, ApiErrorResponse> {
    value.map_or(Ok(None), |value| {
        value.parse::<i64>().map(Some).map_err(|_| {
            invalid(
                &format!("{name} must be an integer epoch-millisecond timestamp"),
                correlation_id,
            )
        })
    })
}

/// Lists audit events by actor, action, resource, outcome, and time.
///
/// Cursor pagination follows append order; filters remain applied to every
/// page. Times are inclusive epoch milliseconds.
///
/// # Errors
///
/// Returns a standard error envelope for malformed filters, denied access,
/// an unresolved caller, an unavailable database, or a storage failure.
#[utoipa::path(
    get,
    path = "/audit",
    tag = "audit",
    operation_id = "listAuditEvents",
    params(
        ("actor" = Option<String>, Query, description = "Only events from this principal."),
        ("action" = Option<String>, Query, description = "Only events for this action id."),
        ("resource" = Option<String>, Query, description = "Only events for this resource id."),
        ("outcome" = Option<String>, Query, description = "allowed, denied, pending, succeeded, failed, cancelled, or blocked_manual_approval."),
        ("from" = Option<i64>, Query, description = "Inclusive lower event time in epoch milliseconds."),
        ("to" = Option<i64>, Query, description = "Inclusive upper event time in epoch milliseconds."),
        ("cursor" = Option<String>, Query, description = "The opaque cursor from a previous page."),
        ("limit" = Option<u32>, Query, description = "Maximum events to return (at most 200).")
    ),
    responses(
        (status = 200, description = "A page of audit events.", body = Page<AuditEventDto>),
        (status = 400, description = "A filter or cursor is malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not read the audit ledger.", body = crate::error::ApiError),
        (status = 500, description = "The audit query could not be completed.", body = crate::error::ApiError),
        (status = 503, description = "The audit surface is unavailable without a database.", body = crate::error::ApiError)
    )
)]
pub async fn list_audit_events(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<ListAuditParams>,
) -> Result<Json<Page<AuditEventDto>>, ApiErrorResponse> {
    let audit = audit_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let cursor = params
        .cursor
        .as_ref()
        .map(|cursor| {
            cursor
                .parse::<i64>()
                .ok()
                .filter(|cursor| *cursor > 0)
                .ok_or_else(|| invalid("cursor must be a positive audit sequence", correlation_id))
        })
        .transpose()?;
    let from = parse_i64_filter("from", params.from, correlation_id)?;
    let to = parse_i64_filter("to", params.to, correlation_id)?;
    let limit = params
        .limit
        .map(|limit| {
            limit
                .parse::<u32>()
                .map_err(|_| invalid("limit must be an integer", correlation_id))
        })
        .transpose()?
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .clamp(1, MAX_PAGE_LIMIT);
    let page = audit
        .list(
            state.authorizer.as_ref(),
            &principal.id,
            AuditFilter {
                after_seq: cursor,
                limit,
                actor: params.actor,
                action: params.action,
                resource: params.resource,
                outcome: params.outcome,
                from,
                to,
                correlation_id: None,
            },
        )
        .await
        .map_err(|error| map_error(error, correlation_id))?;
    let next_cursor = page.next_seq.map(|seq| seq.to_string());
    Ok(Json(Page {
        items: page.events.into_iter().map(AuditEventDto::from).collect(),
        page: PageInfo { next_cursor, limit },
    }))
}
