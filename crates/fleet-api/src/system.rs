//! The system endpoints: one assembled-at-the-composition-root view of what
//! this controller is and how it is doing, plus the live operation event
//! stream.
//!
//! System info is deliberately a presentation concern: the controller knows
//! its build, its trust mode, its storage, and its queue depth — no domain
//! rule is involved in reading them. The SSE stream re-polls the operation
//! through the authorized use case on every tick, so a subscriber who loses
//! the right to read an operation loses the stream too.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Extension, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::sse::{Event as SseEvent, KeepAlive, Sse},
};
use fleet_application::operation::Operation;
use futures_util::stream::{Stream, unfold};
use serde::Serialize;
use utoipa::ToSchema;

use crate::error::{ApiError, ApiErrorResponse};
use crate::operations::ApiState;
use fleet_core::{
    CorrelationId, ErrorCode, IdGenerator as _, PublicError, RetryClass, UuidV7Generator,
};
use std::str::FromStr as _;

/// Who answers system questions. The controller implements this; no test
/// double needs a database.
#[async_trait::async_trait]
pub trait SystemInfoSource: Send + Sync {
    /// Assembles the current system facts.
    ///
    /// # Errors
    ///
    /// Fails when a dependency (storage) cannot be reached.
    async fn info(&self) -> Result<SystemInfo, String>;
}

/// The system view served at `/api/v1/system`.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    /// The resolved principal for the request showing this system view.
    #[schema(example = "tailscale:alice@example.com")]
    pub current_principal: String,
    /// The service that answered.
    #[schema(example = "fleet-controller")]
    pub service: String,
    /// The controller's build version.
    #[schema(example = "0.1.0")]
    pub version: String,
    /// The deployment's trust mode id, e.g. `trusted-lan`.
    #[schema(example = "trusted-lan")]
    pub trust_mode: String,
    /// The trust mode's operator warning, verbatim.
    pub trust_warning: String,
    /// Whether the runtime database answered the readiness probe.
    pub storage_ok: bool,
    /// Operations accepted but not yet claimed.
    pub queue_pending: i64,
    /// Operations claimed and executing.
    pub queue_running: i64,
}

/// Reads the system view.
///
/// # Errors
///
/// Returns the public error envelope when the system source fails.
///
/// # Panics
///
/// Panics only if the pinned literal error code stops being valid syntax,
/// which is a constant path a test pins.
#[utoipa::path(
    get,
    path = "/system",
    tag = "system",
    operation_id = "getSystemInfo",
    responses(
        (
            status = 200,
            description = "What this controller is and how it is doing.",
            body = SystemInfo
        ),
        (
            status = 500,
            description = "A dependency could not be reached.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn get_system_info(
    State(state): State<Arc<ApiState>>,
    Extension(correlation_id): Extension<CorrelationId>,
    principal: Option<Extension<fleet_application::authz::ActingPrincipal>>,
) -> Result<Json<SystemInfo>, ApiErrorResponse> {
    let mut info = state.system.info().await.map_err(|_detail| {
        let public = PublicError::new(
            ErrorCode::from_str("system_unavailable")
                .expect("the literal is valid error code syntax"),
            "the system view is unavailable; the detail is in the controller log",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    info.current_principal =
        principal.map_or_else(|| "unknown".to_owned(), |Extension(principal)| principal.id);
    Ok(Json(info))
}

/// How often the SSE stream polls the operation for changes.
pub const SSE_POLL: Duration = Duration::from_secs(1);

/// How often the stream sends a keep-alive comment so proxies do not close
/// an idle connection.
const KEEP_ALIVE: Duration = Duration::from_secs(15);

/// The live event stream of one operation: a fresh snapshot whenever the
/// operation changes.
///
/// Reconnect protocol: the client sends `Last-Event-ID` with the last
/// snapshot's `updated_at`. Because snapshots are not archived, any change
/// since that cursor is announced as a `gap` event, and the client refetches
/// the operation before trusting the stream again. A terminal operation emits
/// its final snapshot and closes the stream.
///
/// # Errors
///
/// Returns the public error envelope when the caller may not read the
/// operation or it does not exist.
#[utoipa::path(
    get,
    path = "/operations/{id}/events",
    tag = "operations",
    operation_id = "streamOperationEvents",
    params(
        ("id" = String, Path, description = "The operation's identity.")
    ),
    responses(
        (
            status = 200,
            description = "A text/event-stream of operation snapshots, with `gap` markers after missed changes.",
            content_type = "text/event-stream"
        ),
        (
            status = 404,
            description = "No such operation.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not read operations.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn stream_operation_events(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Extension(correlation_id): Extension<CorrelationId>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>, ApiErrorResponse> {
    let Some(Extension(principal)) = principal else {
        return Err(unresolved_principal());
    };
    let last_seen: Option<i64> = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse().ok());

    // The stream exists only for a caller who may read the operation; every
    // later poll re-enters the same authorized path.
    state
        .operations
        .get(state.authorizer.as_ref(), &principal.id, &id)
        .await
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;

    let operations = state.operations.clone();
    let authorizer = state.authorizer.clone();
    let principal_id = principal.id.clone();

    // The stream's state: the client's reconnect cursor and the last
    // snapshot sent. A first poll after a stale cursor announces a gap and
    // resets the cursor, so the next poll's fresh snapshot is trusted.
    let initial = StreamState {
        id,
        cursor: last_seen,
        previous: None,
        closed: false,
    };

    let stream = futures_util::stream::unfold(initial, move |mut state| {
        let operations = operations.clone();
        let authorizer = authorizer.clone();
        let principal_id = principal_id.clone();
        async move {
            tokio::time::sleep(SSE_POLL).await;
            if state.closed {
                return None;
            }
            let Ok(operation) = operations.get(&*authorizer, &principal_id, &state.id).await else {
                state.closed = true;
                return Some((
                    Ok(SseEvent::default().event("closed").data("unavailable")),
                    state,
                ));
            };

            if state
                .previous
                .as_ref()
                .is_some_and(|previous| previous.updated_at == operation.updated_at)
            {
                // Nothing changed; a comment keeps the connection warm.
                return Some((Ok(SseEvent::default().comment("keep-alive")), state));
            }

            // First snapshot after a stale cursor: the caller missed changes.
            if state.previous.is_none()
                && state
                    .cursor
                    .is_some_and(|cursor| cursor != operation.updated_at)
            {
                state.cursor = None;
                return Some((
                    Ok(SseEvent::default()
                        .event("gap")
                        .data(operation.updated_at.to_string())),
                    state,
                ));
            }

            let terminal = matches!(
                operation.state.as_str(),
                "succeeded" | "failed" | "cancelled" | "timed_out" | "blocked_manual_approval"
            );
            state.previous = Some(operation.clone());
            if terminal {
                state.closed = true;
            }
            Some((Ok(snapshot_event(&operation)), state))
        }
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(KEEP_ALIVE).text("keep-alive")))
}

/// Streams payload-free notifications for fleet-wide query invalidation.
///
/// Reconnects replay events still in the bounded process buffer. An expired,
/// foreign, malformed, or lagged cursor produces a `gap` event so clients
/// refetch through authorized resource reads. Slow live subscribers are then
/// disconnected instead of accumulating memory.
///
/// # Errors
///
/// Returns the standard API error when the caller has no resolved principal
/// or lacks `events.read`.
#[utoipa::path(
    get,
    path = "/events",
    tag = "events",
    operation_id = "streamFleetEvents",
    params(
        ("Last-Event-ID" = Option<String>, Header, description = "The last event cursor received by this client.")
    ),
    responses(
        (status = 200, description = "A resumable stream of payload-free fleet change notifications.", content_type = "text/event-stream"),
        (status = 403, description = "The caller may not subscribe to fleet event metadata.", body = crate::error::ApiError)
    )
)]
pub async fn stream_fleet_events(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Extension(correlation_id): Extension<CorrelationId>,
    principal: Option<Extension<crate::ActingPrincipal>>,
) -> Result<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>, ApiErrorResponse> {
    let Some(Extension(principal)) = principal else {
        return Err(unresolved_principal());
    };
    let mut cursor_values = headers.get_all("last-event-id").iter();
    let first_cursor = cursor_values.next();
    let last_event_id = if cursor_values.next().is_some() {
        Some("")
    } else {
        first_cursor.map(|value| {
            // Preserve malformed header values as an invalid cursor so the
            // subscriber receives an explicit gap instead of silently starting
            // at the live edge.
            value.to_str().unwrap_or("")
        })
    };
    let subscription = state
        .events
        .subscribe(state.authorizer.as_ref(), &principal.id, last_event_id)
        .map_err(|denial| crate::machines::denied_error(denial, correlation_id))?;
    let events = state.events.clone();
    let stream = unfold(
        (subscription, events, false),
        |(mut subscription, events, close_after_gap)| async move {
            if close_after_gap {
                return None;
            }
            if let Some(gap_id) = subscription.gap_id.take() {
                // EventSource ignores events without a data field; one
                // whitespace-only value dispatches type/id without a payload.
                let event = SseEvent::default().event("gap").id(gap_id).data(" ");
                return Some((Ok(event), (subscription, events, true)));
            }
            if let Some(event) = subscription.replay.pop_front() {
                let event = SseEvent::default()
                    .event(event.kind.as_str())
                    .id(event.id)
                    .data(" ");
                return Some((Ok(event), (subscription, events, false)));
            }
            match subscription.receiver.recv().await {
                Ok(event) => Some((
                    Ok(SseEvent::default()
                        .event(event.kind.as_str())
                        .id(event.id)
                        .data(" ")),
                    (subscription, events, false),
                )),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    let event = SseEvent::default()
                        .event("gap")
                        .id(events.current_id())
                        .data(" ");
                    Some((Ok(event), (subscription, events, true)))
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => None,
            }
        },
    );
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(KEEP_ALIVE).text("keep-alive")))
}

/// The stream's rolling state.
struct StreamState {
    id: String,
    cursor: Option<i64>,
    previous: Option<Operation>,
    closed: bool,
}

fn snapshot_event(operation: &Operation) -> SseEvent {
    let data = serde_json::to_string(operation).expect("an operation serializes as JSON");
    SseEvent::default()
        .event("operation")
        .id(operation.updated_at.to_string())
        .data(data)
}

fn unresolved_principal() -> ApiErrorResponse {
    let mut generator = UuidV7Generator;
    let correlation_id = generator.next_correlation_id();
    let public = PublicError::new(
        ErrorCode::from_str("principal_unresolved")
            .expect("the literal is valid error code syntax"),
        "no caller identity was resolved for this request; caller resolution is misconfigured",
        RetryClass::Never,
    );
    ApiError::new(&public, correlation_id).with_status(StatusCode::INTERNAL_SERVER_ERROR)
}
