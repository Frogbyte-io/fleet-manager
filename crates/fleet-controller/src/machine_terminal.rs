//! The interactive machine terminal relay (#494).
//!
//! The caller (the console, or `fleetctl machines terminal`) creates a
//! session through the API and attaches to `/api/v1/terminal/socket` with
//! the single-use session token in a WebSocket subprotocol
//! (`fleet-terminal-token.<token>`), so the token never appears in a URL, a
//! log line, or the browser history. A browser's `Origin` must name the host
//! it connected to: a page on another origin cannot open a terminal even
//! when the browser would let it reach the controller. The use case
//! ([`MachineAccess::terminal_attach`]) re-authorizes the attaching caller
//! and starts `ssh -tt` under a PTY with the machine's stored credential; the
//! caller never holds a key.
//!
//! The wire protocol is deliberately small. Binary messages carry terminal
//! bytes in both directions. A text message from the caller is a JSON
//! control message, today only `{"type":"resize","cols":N,"rows":M}`. After
//! the shell started the controller sends one text message
//! `{"type":"ready"}`. Pings go out on a timer and any answer counts as
//! life. The relay's rules (idle, maximum duration, send deadlines,
//! shutdown) are the application's; this module only frames bytes.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::{
    Extension, Router,
    extract::{
        State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::get,
};
use fleet_application::authz::{ActingPrincipal, Authorizer};
use fleet_application::lab::LabUseCaseError;
use fleet_application::machine::MachinePort;
use fleet_application::machine_access::MachineAccess;
use fleet_application::machine_terminal::{
    ClientMessage, TerminalChannel, TerminalClient, TerminalCloseReason, TerminalLimits,
    TerminalOpen, TerminalOutput, TerminalPort, TerminalSessions,
};
use futures_util::StreamExt as _;

use crate::machine_access::SshAuthResolver;

/// The largest message the relay accepts from the caller. Keystrokes and
/// pasted text are small; a larger paste arrives in several messages.
const MAX_CLIENT_MESSAGE_BYTES: usize = 256 * 1024;

/// The most bytes a control message may carry.
const MAX_CONTROL_BYTES: usize = 256;

/// How long the controller waits at shutdown for attached terminals to close
/// and audit their end.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

/// WebSocket close codes the relay uses (private-use range, aligned with
/// the other relays).
mod close {
    pub const UNAUTHENTICATED: u16 = 4401;
    pub const DENIED: u16 = 4403;
    pub const NOT_FOUND: u16 = 4404;
    pub const IDLE: u16 = 4408;
    pub const CONFLICT: u16 = 4409;
    pub const MAX_DURATION: u16 = 4410;
    pub const PEER_LOST: u16 = 4412;
    pub const UPSTREAM: u16 = 4502;
    pub const UNAVAILABLE: u16 = 4503;
    pub const SHUTDOWN: u16 = 1001;
    pub const NORMAL: u16 = 1000;
}

/// The terminal bounds from the environment, validated. Unset variables keep
/// the defaults; a set one that is not a positive whole number (or a maximum
/// duration beyond the allowed ceiling) is an error, so a typo never
/// silently disables a bound.
///
/// - `FLEET_TERMINAL_IDLE_SECONDS`
/// - `FLEET_TERMINAL_MAX_DURATION_SECONDS`
/// - `FLEET_TERMINAL_MAX_SESSIONS`
/// - `FLEET_TERMINAL_MAX_SESSIONS_PER_PRINCIPAL`
///
/// # Errors
///
/// Names the variable that is out of range.
pub fn terminal_limits_from(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<TerminalLimits, String> {
    fn number(lookup: &impl Fn(&str) -> Option<String>, name: &str) -> Result<Option<u64>, String> {
        match lookup(name) {
            None => Ok(None),
            Some(text) => match text.trim().parse::<u64>() {
                Ok(value) if value > 0 => Ok(Some(value)),
                _ => Err(format!("{name} must be a positive whole number")),
            },
        }
    }
    let mut limits = TerminalLimits::default();
    if let Some(seconds) = number(&lookup, "FLEET_TERMINAL_IDLE_SECONDS")? {
        limits.idle = Duration::from_secs(seconds);
    }
    if let Some(seconds) = number(&lookup, "FLEET_TERMINAL_MAX_DURATION_SECONDS")? {
        limits.max_duration = Duration::from_secs(seconds);
    }
    let count =
        |value: u64, name: &str| usize::try_from(value).map_err(|_| format!("{name} is too large"));
    if let Some(value) = number(&lookup, "FLEET_TERMINAL_MAX_SESSIONS")? {
        limits.max_sessions = count(value, "FLEET_TERMINAL_MAX_SESSIONS")?;
    }
    if let Some(value) = number(&lookup, "FLEET_TERMINAL_MAX_SESSIONS_PER_PRINCIPAL")? {
        limits.max_per_principal = count(value, "FLEET_TERMINAL_MAX_SESSIONS_PER_PRINCIPAL")?;
    }
    limits.validate()?;
    Ok(limits)
}

/// Opens terminals over the SSH provider: the credential is resolved just in
/// time, the host-key trust gate applies, and `ssh -tt` runs under a PTY.
#[cfg(unix)]
#[derive(Debug)]
pub struct SshTerminalPort {
    machines: Arc<dyn MachinePort>,
    resolver: Arc<SshAuthResolver>,
    provider: fleet_provider_ssh::SshProvider,
}

#[cfg(unix)]
impl SshTerminalPort {
    /// Composes the port over the controller's SSH work directory.
    ///
    /// # Errors
    ///
    /// Fails when the SSH work directory cannot be prepared.
    pub fn new(
        machines: Arc<dyn MachinePort>,
        resolver: Arc<SshAuthResolver>,
        work_dir: std::path::PathBuf,
    ) -> Result<Self, String> {
        Ok(Self {
            machines,
            resolver,
            provider: fleet_provider_ssh::SshProvider::new(work_dir)
                .map_err(|error| error.to_string())?,
        })
    }
}

#[cfg(unix)]
struct SshChannel(fleet_provider_ssh::Terminal);

#[cfg(unix)]
impl std::fmt::Debug for SshChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SshChannel")
    }
}

#[cfg(unix)]
#[async_trait]
impl TerminalChannel for SshChannel {
    async fn next(&mut self) -> TerminalOutput {
        match self.0.next_event().await {
            fleet_provider_ssh::TerminalEvent::Output(bytes) => TerminalOutput::Data(bytes),
            fleet_provider_ssh::TerminalEvent::Exited(code) => TerminalOutput::Exited(code),
        }
    }

    async fn write(&mut self, data: &[u8]) -> Result<(), String> {
        self.0
            .write_input(data)
            .await
            .map_err(|_| "the terminal is gone".to_owned())
    }

    fn resize(&mut self, cols: u16, rows: u16) -> Result<(), String> {
        let size = fleet_provider_ssh::TerminalSize::new(cols, rows)
            .ok_or_else(|| "the size is out of range".to_owned())?;
        self.0
            .resize(size)
            .map_err(|_| "the terminal is gone".to_owned())
    }

    async fn close(&mut self) {
        self.0.kill().await;
    }
}

#[cfg(unix)]
#[async_trait]
impl TerminalPort for SshTerminalPort {
    fn new_session_token(&self) -> String {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).expect("the system random source must not fail");
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    async fn open(&self, request: &TerminalOpen) -> Result<Box<dyn TerminalChannel>, String> {
        let auth = self
            .resolver
            .resolve(&request.auth, &request.machine_id)
            .await?;
        let (spec, _, _) = crate::exec::resolve_ssh_endpoint(
            self.machines.as_ref(),
            &request.machine_id,
            &request.endpoint_id,
            auth,
        )
        .await?;
        let size = fleet_provider_ssh::TerminalSize::new(request.cols, request.rows)
            .ok_or("the size is out of range")?;
        let terminal = self
            .provider
            .open_terminal(&spec, size)
            .map_err(|error| error.to_string())?;
        Ok(Box::new(SshChannel(terminal)))
    }
}

/// What the route needs.
#[derive(Clone)]
struct TerminalRoute {
    access: Arc<MachineAccess>,
    authorizer: Arc<dyn Authorizer>,
}

/// The relay's router fragment: the one WebSocket route.
pub fn terminal_router(access: Arc<MachineAccess>, authorizer: Arc<dyn Authorizer>) -> Router {
    Router::new()
        .route(
            fleet_api::machine_terminal::TERMINAL_SOCKET_PATH,
            get(socket_handler),
        )
        .with_state(TerminalRoute { access, authorizer })
}

/// Closes attached terminals cleanly when the controller shuts down: every
/// relay closes its socket and audits its end before the process drains.
/// Upgraded sockets are not tracked by the HTTP server's own drain.
pub fn drain_on_shutdown(
    lab: Option<&Arc<fleet_application::lab::Lab>>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> impl Future<Output = ()> + Send + 'static {
    let terminals: Option<Arc<TerminalSessions>> = lab
        .and_then(|lab| lab.machine_access())
        .and_then(|access| access.terminals().cloned());
    async move {
        shutdown.await;
        if let Some(terminals) = terminals {
            terminals.shutdown();
            let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
            while terminals.active_count() > 0 && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// The token the caller offered in `Sec-WebSocket-Protocol`, when any.
fn offered_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .find_map(|protocol| {
            protocol
                .strip_prefix(fleet_api::machine_terminal::TERMINAL_TOKEN_SUBPROTOCOL_PREFIX)
                .filter(|token| !token.is_empty() && token.len() <= 256)
                .map(str::to_owned)
        })
}

/// Whether the upgrade's `Origin`, when a browser sent one, names the host
/// it connected to. A missing `Origin` is a non-browser client and is left
/// to the token.
fn origin_allowed(headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    crate::browser::same_origin(
        origin,
        headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok()),
    )
}

async fn socket_handler(
    State(route): State<TerminalRoute>,
    principal: Option<Extension<ActingPrincipal>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !origin_allowed(&headers) {
        return (
            StatusCode::FORBIDDEN,
            "cross-origin terminal sockets are refused\n",
        )
            .into_response();
    }
    let Some(token) = offered_token(&headers) else {
        return (
            StatusCode::BAD_REQUEST,
            "the upgrade must offer the terminal session token subprotocol\n",
        )
            .into_response();
    };
    let principal = principal.map(|Extension(principal)| principal);
    ws.protocols([fleet_api::machine_terminal::TERMINAL_SUBPROTOCOL])
        .max_message_size(MAX_CLIENT_MESSAGE_BYTES)
        .max_frame_size(MAX_CLIENT_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            serve(socket, route, principal, token).await;
        })
}

async fn refuse(mut socket: WebSocket, code: u16, reason: &str) {
    refuse_in_place(&mut socket, code, reason).await;
}

fn close_frame(code: u16, reason: &str) -> CloseFrame {
    // A close reason is at most 123 bytes; cut on a character boundary.
    let mut end = reason.len().min(120);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    CloseFrame {
        code,
        reason: reason[..end].to_owned().into(),
    }
}

async fn serve(
    socket: WebSocket,
    route: TerminalRoute,
    principal: Option<ActingPrincipal>,
    token: String,
) {
    let Some(principal) = principal else {
        refuse(socket, close::UNAUTHENTICATED, "authentication is required").await;
        return;
    };
    let now = fleet_core::SystemClock::now_unix_millis();
    let attached = match route
        .access
        .terminal_attach(route.authorizer.as_ref(), &principal, &token, now)
        .await
    {
        Ok(attached) => attached,
        Err(error) => {
            let (code, reason) = match &error {
                LabUseCaseError::Denied(_) => (
                    close::DENIED,
                    "denied: machines.terminal is required".to_owned(),
                ),
                LabUseCaseError::NotFound { .. } => (
                    close::NOT_FOUND,
                    "the terminal session is unknown, already used, or expired".to_owned(),
                ),
                LabUseCaseError::Busy { detail } | LabUseCaseError::Conflict { detail } => {
                    (close::CONFLICT, detail.clone())
                }
                LabUseCaseError::Invalid { detail } => (close::CONFLICT, detail.clone()),
                LabUseCaseError::Backend {
                    context: "terminal",
                    detail,
                } => (close::UPSTREAM, fleet_core::scrub_failure_detail(detail)),
                LabUseCaseError::Backend { .. } | LabUseCaseError::PinRefused { .. } => {
                    eprintln!("terminal attach failed: {error}");
                    (
                        close::UNAVAILABLE,
                        "the terminal could not be opened; the detail is in the controller log"
                            .to_owned(),
                    )
                }
            };
            refuse(socket, code, &reason).await;
            return;
        }
    };
    let mut client = WsClient { socket };
    let _ = client
        .socket
        .send(Message::Text(r#"{"type":"ready"}"#.into()))
        .await;
    let end = route.access.terminal_run(attached, &mut client).await;
    if let Some(error) = end.audit_error {
        eprintln!("terminal end audit failed: {error}");
    }
}

/// The caller's WebSocket as a [`TerminalClient`].
struct WsClient {
    socket: WebSocket,
}

/// A caller's control message.
#[derive(serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum Control {
    Resize { cols: u16, rows: u16 },
}

#[async_trait]
impl TerminalClient for WsClient {
    async fn recv(&mut self) -> ClientMessage {
        match self.socket.next().await {
            Some(Ok(Message::Binary(bytes))) => ClientMessage::Input(bytes.to_vec()),
            Some(Ok(Message::Text(text))) => {
                if text.len() > MAX_CONTROL_BYTES {
                    ClientMessage::Alive
                } else {
                    match serde_json::from_str::<Control>(text.as_str()) {
                        Ok(Control::Resize { cols, rows }) => ClientMessage::Resize { cols, rows },
                        Err(_) => ClientMessage::Alive,
                    }
                }
            }
            Some(Ok(Message::Pong(_) | Message::Ping(_))) => ClientMessage::Alive,
            Some(Ok(Message::Close(_)) | Err(_)) | None => ClientMessage::Closed,
        }
    }

    async fn send_output(&mut self, data: Vec<u8>) -> Result<(), String> {
        self.socket
            .send(Message::Binary(data.into()))
            .await
            .map_err(|_| "the connection is gone".to_owned())
    }

    async fn send_ping(&mut self) -> Result<(), String> {
        self.socket
            .send(Message::Ping(Vec::new().into()))
            .await
            .map_err(|_| "the connection is gone".to_owned())
    }

    async fn close(&mut self, reason: TerminalCloseReason, exit_code: Option<i32>) {
        let (code, text) = match reason {
            TerminalCloseReason::Client => (close::NORMAL, "closed".to_owned()),
            TerminalCloseReason::Exited => (
                close::NORMAL,
                match exit_code {
                    Some(code) => format!("the shell ended (exit status {code})"),
                    None => "the shell ended".to_owned(),
                },
            ),
            TerminalCloseReason::Idle => (close::IDLE, "the terminal was idle".to_owned()),
            TerminalCloseReason::MaxDuration => (
                close::MAX_DURATION,
                "the maximum duration was reached".to_owned(),
            ),
            TerminalCloseReason::Shutdown => (
                close::SHUTDOWN,
                "the controller is shutting down".to_owned(),
            ),
            TerminalCloseReason::PeerLost => (
                close::PEER_LOST,
                "the connection stopped answering".to_owned(),
            ),
            TerminalCloseReason::Error => (close::UPSTREAM, "the terminal failed".to_owned()),
        };
        refuse_in_place(&mut self.socket, code, &text).await;
    }
}

async fn refuse_in_place(socket: &mut WebSocket, code: u16, reason: &str) {
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        socket.send(Message::Close(Some(close_frame(code, reason)))),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_is_read_from_the_subprotocol_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            "fleet-terminal, fleet-terminal-token.abc_DEF-123"
                .parse()
                .unwrap(),
        );
        assert_eq!(offered_token(&headers).as_deref(), Some("abc_DEF-123"));
        assert_eq!(offered_token(&HeaderMap::new()), None);
    }

    #[test]
    fn cross_origin_upgrades_are_refused() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "fleet.example.test:8443".parse().unwrap());
        assert!(origin_allowed(&headers));
        headers.insert(
            header::ORIGIN,
            "https://fleet.example.test:8443".parse().unwrap(),
        );
        assert!(origin_allowed(&headers));
        headers.insert(header::ORIGIN, "https://evil.example.test".parse().unwrap());
        assert!(!origin_allowed(&headers));
    }

    #[test]
    fn limits_come_from_the_environment_and_refuse_nonsense() {
        let none = |_: &str| None;
        assert_eq!(
            terminal_limits_from(none).unwrap(),
            TerminalLimits::default()
        );
        let set = |name: &str| match name {
            "FLEET_TERMINAL_IDLE_SECONDS" => Some("30".to_owned()),
            "FLEET_TERMINAL_MAX_DURATION_SECONDS" => Some("600".to_owned()),
            "FLEET_TERMINAL_MAX_SESSIONS" => Some("3".to_owned()),
            "FLEET_TERMINAL_MAX_SESSIONS_PER_PRINCIPAL" => Some("2".to_owned()),
            _ => None,
        };
        let limits = terminal_limits_from(set).unwrap();
        assert_eq!(limits.idle, Duration::from_secs(30));
        assert_eq!(limits.max_duration, Duration::from_secs(600));
        assert_eq!((limits.max_sessions, limits.max_per_principal), (3, 2));
        for bad in ["0", "-1", "ten", ""] {
            let lookup =
                |name: &str| (name == "FLEET_TERMINAL_IDLE_SECONDS").then(|| bad.to_owned());
            assert!(terminal_limits_from(lookup).is_err(), "{bad:?}");
        }
        // A maximum duration past the ceiling is refused.
        let lookup = |name: &str| {
            (name == "FLEET_TERMINAL_MAX_DURATION_SECONDS").then(|| "86400".to_owned())
        };
        assert!(terminal_limits_from(lookup).is_err());
    }

    #[test]
    fn close_reasons_are_cut_on_a_character_boundary() {
        let frame = close_frame(4000, &"é".repeat(100));
        assert!(frame.reason.len() <= 120);
        assert!(frame.reason.as_str().chars().all(|c| c == 'é'));
    }
}
