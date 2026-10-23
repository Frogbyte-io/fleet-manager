//! The interactive machine terminal: create a session (#494).
//!
//! Creating a session is a mutation in effect (a shell on the machine as the
//! endpoint's user), so it needs `machines.terminal` and leaves audit
//! events. The handler only translates the application's
//! [`NewTerminalSession`]; the session rules live in
//! `fleet_application::machine_terminal`. The WebSocket the token attaches
//! to is served by the controller beside the node gateway; this crate only
//! names its path and its subprotocols.

use std::sync::Arc;

use axum::{Extension, Json, extract::Path, extract::State, http::StatusCode};
use fleet_application::machine_access::AccessTarget;
use fleet_application::machine_access::EndpointAuth;
use fleet_application::machine_terminal::{NewTerminalSession, TerminalRequest};
use fleet_core::CorrelationId;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::ApiErrorResponse;
use crate::lab::map_lab_error;
use crate::machine_access::{EndpointAuthDto, access_or_error};

/// The path of the controller's terminal WebSocket, relative to the origin.
pub const TERMINAL_SOCKET_PATH: &str = "/api/v1/terminal/socket";

/// The WebSocket subprotocol the relay speaks: binary messages are terminal
/// bytes, text messages are JSON control messages.
pub const TERMINAL_SUBPROTOCOL: &str = "fleet-terminal";

/// The prefix of the subprotocol that carries the session token, so the
/// token never appears in a URL, a log line, or the browser history.
pub const TERMINAL_TOKEN_SUBPROTOCOL_PREFIX: &str = "fleet-terminal-token.";

/// The body of `POST /machines/{machineId}/terminal-sessions`.
#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateTerminalSessionRequest {
    /// The SSH endpoint; absent means the machine's only SSH endpoint.
    pub endpoint_id: Option<String>,
    /// An explicit auth, overriding the endpoint's default. Naming one needs
    /// `machine.update` on the machine.
    pub auth: Option<EndpointAuthDto>,
    /// The terminal's initial width in columns (1-1000; default 80).
    pub cols: Option<u16>,
    /// The terminal's initial height in rows (1-1000; default 24).
    pub rows: Option<u16>,
}

/// A created terminal session. The token is shown here once.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TerminalSessionDto {
    /// The session's identity, as it appears in audit events.
    pub session_id: String,
    /// The single-use token that attaches to the terminal WebSocket. It
    /// expires at `expiresAt` and is spent by the first attach.
    pub token: String,
    /// When an unattached token stops being valid (epoch millis).
    pub expires_at: i64,
    /// The machine.
    pub machine_id: String,
    /// The SSH endpoint the shell uses.
    pub endpoint_id: String,
    /// The WebSocket path, relative to the controller's origin.
    pub socket_path: String,
    /// The WebSocket subprotocols to offer: `fleet-terminal`, then the token
    /// subprotocol.
    pub subprotocols: Vec<String>,
    /// Close after this many seconds without input from the caller.
    pub idle_timeout_seconds: u64,
    /// Close after this many seconds regardless.
    pub max_duration_seconds: u64,
}

impl From<NewTerminalSession> for TerminalSessionDto {
    fn from(session: NewTerminalSession) -> Self {
        let token = session.token.expose().to_owned();
        Self {
            session_id: session.session_id,
            socket_path: TERMINAL_SOCKET_PATH.to_owned(),
            subprotocols: vec![
                TERMINAL_SUBPROTOCOL.to_owned(),
                format!("{TERMINAL_TOKEN_SUBPROTOCOL_PREFIX}{token}"),
            ],
            token,
            expires_at: session.expires_at,
            machine_id: session.machine_id,
            endpoint_id: session.endpoint_id,
            idle_timeout_seconds: session.limits.idle.as_secs(),
            max_duration_seconds: session.limits.max_duration.as_secs(),
        }
    }
}

/// Creates an interactive terminal session on a machine. The session token
/// is single use and short-lived; the caller attaches to the terminal
/// WebSocket with it. Every session is authorized (`machines.terminal`,
/// separate from `machines.exec`), audited at its start and end, and bounded
/// by an idle timeout and a maximum duration. Nothing typed or shown is
/// recorded.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown machine or
/// endpoint, an endpoint whose host key was never confirmed, no usable auth,
/// the session cap, or an unwired terminal relay.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/terminal-sessions",
    tag = "machines",
    operation_id = "createMachineTerminalSession",
    params(("machineId" = String, Path, description = "The machine's identity.")),
    request_body = CreateTerminalSessionRequest,
    responses(
        (status = 201, description = "The session was created; the token is shown once.", body = Resource<TerminalSessionDto>),
        (status = 400, description = "The size or target is invalid, the host key was never confirmed, or the endpoint has no auth.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not open a terminal on this machine (`machines.terminal`).", body = crate::error::ApiError),
        (status = 404, description = "The machine or endpoint does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "The terminal session cap is reached (retry later), or machine access is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn create_machine_terminal_session(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
    request: Result<Json<CreateTerminalSessionRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<TerminalSessionDto>>), ApiErrorResponse> {
    let access = access_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        crate::machines::invalid_request(
            "the request body must be valid JSON (an empty object is fine)",
            correlation_id,
        )
    })?;
    let auth: Option<EndpointAuth> = request.auth.map(Into::into);
    let session = access
        .terminal_create(
            state.authorizer.as_ref(),
            &principal,
            &TerminalRequest {
                target: AccessTarget {
                    machine_id: &machine_id,
                    endpoint_id: request.endpoint_id.as_deref(),
                    auth: auth.as_ref(),
                    ..AccessTarget::default()
                },
                cols: request.cols,
                rows: request.rows,
            },
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok((
        StatusCode::CREATED,
        Json(Resource::new(TerminalSessionDto::from(session))),
    ))
}
