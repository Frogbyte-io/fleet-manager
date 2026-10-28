//! The Proxmox VM screen: create a console session (FM-495).
//!
//! A mutation in effect (screen access implies keyboard input), so it needs
//! `proxmox.console` and leaves audit events. The handler only translates
//! the application's [`NewConsoleSession`]; the session rules live in
//! `fleet_application::proxmox::console`. The WebSocket the token attaches
//! to is served by the controller beside the node gateway, because the
//! relay needs the pinned PVE transport; this crate only names its path.

use std::sync::Arc;

use axum::{Extension, Json, extract::Path, extract::State, http::StatusCode};
use fleet_application::proxmox::console::NewConsoleSession;
use fleet_core::CorrelationId;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::ApiErrorResponse;
use crate::proxmox::{map_proxmox_error, proxmox_or_error};

/// The path of the controller's console WebSocket, relative to the origin.
pub const CONSOLE_SOCKET_PATH: &str = "/api/v1/proxmox/console/socket";

/// The WebSocket subprotocol the relay speaks (binary RFB frames).
pub const CONSOLE_SUBPROTOCOL: &str = "binary";

/// The prefix of the subprotocol that carries the session token, so the
/// token never appears in a URL, a log line, or the browser history.
pub const CONSOLE_TOKEN_SUBPROTOCOL_PREFIX: &str = "fleet-console-token.";

/// The path of the console page in the web app; the token rides in the URL
/// fragment (`#session=<token>`), which no server ever receives.
pub const CONSOLE_PAGE_PATH: &str = "/proxmox/console";

/// The guest to open.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateConsoleSessionRequest {
    /// The node the guest runs on.
    pub node: String,
    /// The QEMU guest's VMID.
    pub vmid: u32,
}

/// A created console session. The token is shown here once.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleSessionDto {
    /// The session's identity, as it appears in audit events.
    pub session_id: String,
    /// The single-use token that attaches to the console WebSocket. It
    /// expires at `expiresAt` and is spent by the first attach.
    pub token: String,
    /// When an unattached token stops being valid (epoch millis).
    pub expires_at: i64,
    /// The account.
    pub account_id: String,
    /// The node.
    pub node: String,
    /// The guest's VMID.
    pub vmid: u32,
    /// The WebSocket path, relative to the controller's origin.
    pub socket_path: String,
    /// The WebSocket subprotocols to offer: `binary`, then the token
    /// subprotocol.
    pub subprotocols: Vec<String>,
    /// The console page in the web app, relative to the controller's
    /// origin, with the token in the fragment. A human can open it.
    pub console_path: String,
    /// Close after this many seconds without browser input.
    pub idle_timeout_seconds: u64,
    /// Close after this many seconds regardless.
    pub max_duration_seconds: u64,
}

impl From<NewConsoleSession> for ConsoleSessionDto {
    fn from(session: NewConsoleSession) -> Self {
        let token = session.token.expose().to_owned();
        Self {
            session_id: session.session_id,
            socket_path: CONSOLE_SOCKET_PATH.to_owned(),
            subprotocols: vec![
                CONSOLE_SUBPROTOCOL.to_owned(),
                format!("{CONSOLE_TOKEN_SUBPROTOCOL_PREFIX}{token}"),
            ],
            console_path: format!("{CONSOLE_PAGE_PATH}#session={token}"),
            token,
            expires_at: session.expires_at,
            account_id: session.account_id,
            node: session.node,
            vmid: session.vmid,
            idle_timeout_seconds: session.limits.idle.as_secs(),
            max_duration_seconds: session.limits.max_duration.as_secs(),
        }
    }
}

/// Creates a console session for one Proxmox guest.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown or unconfirmed
/// account, a token that lacks `VM.Console` (the refusal names the
/// privilege), the session cap, or an unwired console relay.
#[utoipa::path(
    post,
    path = "/proxmox/accounts/{accountId}/console-sessions",
    tag = "proxmox",
    operation_id = "createProxmoxConsoleSession",
    params(
        (
            "accountId" = String,
            Path,
            description = "The account's identity."
        ),
    ),
    request_body = CreateConsoleSessionRequest,
    responses(
        (
            status = 201,
            description = "The session was created; the token is shown once.",
            body = Resource<ConsoleSessionDto>
        ),
        (
            status = 400,
            description = "The node or VMID is malformed.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not open guest screens (`proxmox.console`).",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "The account does not exist.",
            body = crate::error::ApiError
        ),
        (
            status = 409,
            description = "The account's trust is unconfirmed, its token secret is unavailable, or the console session cap is reached.",
            body = crate::error::ApiError
        ),
        (
            status = 502,
            description = "The account's API token lacks `VM.Console` on the guest, or the PVE API failed.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn create_proxmox_console_session(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(account_id): Path<String>,
    Json(request): Json<CreateConsoleSessionRequest>,
) -> Result<
    (
        StatusCode,
        [(axum::http::HeaderName, &'static str); 1],
        Json<Resource<ConsoleSessionDto>>,
    ),
    ApiErrorResponse,
> {
    let proxmox = proxmox_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let session = proxmox
        .console_create(
            state.authorizer.as_ref(),
            &principal,
            &account_id,
            &request.node,
            request.vmid,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_proxmox_error(&error, correlation_id))?;
    Ok((
        StatusCode::CREATED,
        // The answer holds a bearer token: no cache or proxy may keep it.
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(Resource::new(ConsoleSessionDto::from(session))),
    ))
}
