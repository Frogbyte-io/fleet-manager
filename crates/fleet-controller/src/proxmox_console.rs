//! The Proxmox VM screen relay (FM-495).
//!
//! The browser attaches to `/api/v1/proxmox/console/socket` with the
//! single-use Fleet session token in a WebSocket subprotocol
//! (`fleet-console-token.<token>`), so the token never appears in a URL or a
//! log line. The use case (`ProxmoxAccounts::console_attach`) re-authorizes
//! the caller and opens the PVE VNC proxy through the pinned transport; the
//! controller has already authenticated to PVE's VNC server with the one-time
//! password, so toward the browser it offers RFB security type *None* on an
//! authenticated stream. The browser never holds the PVE token, the VNC
//! ticket, or the VNC password.
//!
//! After that the relay forwards binary frames both ways and enforces the
//! bounds: an idle limit measured on **input events** (key, pointer,
//! clipboard — not the automatic update requests a viewer sends), a maximum
//! duration, a clean close when the controller shuts down or the guest's
//! screen goes away. Nothing the screen shows is read, logged, or recorded.

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
use fleet_application::proxmox::console::{
    AttachedConsole, ConsoleChannel, ConsoleCloseReason, ProxmoxConsolePort,
};
use fleet_application::proxmox::{ProxmoxAccount, ProxmoxAccounts, ProxmoxSourceError};
use fleet_core::SensitiveString;
use fleet_provider_proxmox::PveSocket;

use crate::proxmox_store::{ProviderDiscovery, map_api_error, pinned_request};

/// The largest message the relay accepts from the browser. Keyboard,
/// pointer, and pasted text are small.
const MAX_BROWSER_MESSAGE_BYTES: usize = 1024 * 1024;

/// How long the browser has to complete the RFB version exchange.
const BROWSER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// WebSocket close codes the relay uses (private-use range).
mod close {
    pub const UNAUTHENTICATED: u16 = 4401;
    pub const DENIED: u16 = 4403;
    pub const NOT_FOUND: u16 = 4404;
    pub const CONFLICT: u16 = 4409;
    pub const UPSTREAM: u16 = 4502;
    pub const UNAVAILABLE: u16 = 4503;
    pub const IDLE: u16 = 4408;
    pub const MAX_DURATION: u16 = 4410;
    pub const SHUTDOWN: u16 = 1001;
    pub const NORMAL: u16 = 1000;
}

/// Adapts the provider socket to the application's channel.
struct ProviderChannel(Box<dyn PveSocket>);

impl std::fmt::Debug for ProviderChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderChannel")
    }
}

#[async_trait]
impl ConsoleChannel for ProviderChannel {
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, String> {
        self.0.recv().await.map_err(|error| error.to_string())
    }

    async fn send(&mut self, data: Vec<u8>) -> Result<(), String> {
        self.0.send(data).await.map_err(|error| error.to_string())
    }

    async fn close(&mut self) {
        self.0.close().await;
    }
}

#[async_trait]
impl ProxmoxConsolePort for ProviderDiscovery {
    fn new_session_token(&self) -> String {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).expect("the system random source must not fail");
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    async fn open(
        &self,
        account: &ProxmoxAccount,
        secret: &SensitiveString,
        node: &str,
        vmid: u32,
    ) -> Result<Box<dyn ConsoleChannel>, ProxmoxSourceError> {
        let request = pinned_request(account, secret, "/api2/json/version")?;
        let socket = self
            .client()
            .vnc_connect(request, node, vmid)
            .await
            .map_err(map_api_error)?;
        Ok(Box::new(ProviderChannel(socket)))
    }
}

/// What the route needs.
#[derive(Clone)]
struct ConsoleRoute {
    proxmox: Arc<ProxmoxAccounts>,
    authorizer: Arc<dyn Authorizer>,
}

/// The relay's router fragment: the one WebSocket route.
pub fn console_router(proxmox: Arc<ProxmoxAccounts>, authorizer: Arc<dyn Authorizer>) -> Router {
    Router::new()
        .route(
            fleet_api::proxmox_console::CONSOLE_SOCKET_PATH,
            get(socket_handler),
        )
        .with_state(ConsoleRoute {
            proxmox,
            authorizer,
        })
}

/// The token the browser offered in `Sec-WebSocket-Protocol`, when any.
fn offered_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .find_map(|protocol| {
            protocol
                .strip_prefix(fleet_api::proxmox_console::CONSOLE_TOKEN_SUBPROTOCOL_PREFIX)
                .filter(|token| !token.is_empty() && token.len() <= 256)
                .map(str::to_owned)
        })
}

/// Whether a browser-supplied `Origin` names the host it connected to. A
/// missing Origin is a non-browser client and is left to the token.
fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let origin_authority = origin.split_once("://").map_or(origin, |(_, rest)| rest);
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|host| host.eq_ignore_ascii_case(origin_authority))
}

async fn socket_handler(
    State(route): State<ConsoleRoute>,
    principal: Option<Extension<ActingPrincipal>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !same_origin(&headers) {
        return (
            StatusCode::FORBIDDEN,
            "cross-origin console sockets are refused\n",
        )
            .into_response();
    }
    let Some(token) = offered_token(&headers) else {
        return (
            StatusCode::BAD_REQUEST,
            "the upgrade must offer the console session token subprotocol\n",
        )
            .into_response();
    };
    let principal = principal.map(|Extension(principal)| principal);
    ws.protocols([fleet_api::proxmox_console::CONSOLE_SUBPROTOCOL])
        .max_message_size(MAX_BROWSER_MESSAGE_BYTES)
        .max_frame_size(MAX_BROWSER_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            serve(socket, route, principal, token).await;
        })
}

async fn refuse(mut socket: WebSocket, code: u16, reason: &str) {
    let reason: String = reason.chars().take(120).collect();
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })))
        .await;
}

async fn serve(
    socket: WebSocket,
    route: ConsoleRoute,
    principal: Option<ActingPrincipal>,
    token: String,
) {
    let Some(principal) = principal else {
        refuse(socket, close::UNAUTHENTICATED, "authentication is required").await;
        return;
    };
    let now = fleet_core::SystemClock::now_unix_millis();
    let attached = match route
        .proxmox
        .console_attach(route.authorizer.as_ref(), &principal, &token, now)
        .await
    {
        Ok(attached) => attached,
        Err(error) => {
            use fleet_application::proxmox::ProxmoxUseCaseError as E;
            let (code, reason) = match &error {
                E::Denied(_) => (
                    close::DENIED,
                    "denied: proxmox.console is required".to_owned(),
                ),
                E::NotFound { .. } => (
                    close::NOT_FOUND,
                    "the console session is unknown, already used, or expired".to_owned(),
                ),
                E::Conflict { detail } | E::Invalid { detail } => (close::CONFLICT, detail.clone()),
                E::UnconfirmedTrust { .. } | E::NoSecret { .. } => {
                    (close::CONFLICT, error.to_string())
                }
                E::Source(_) => (close::UPSTREAM, error.to_string()),
                E::Credentials(_) | E::Backend { .. } => (
                    close::UNAVAILABLE,
                    "the console could not be opened; the detail is in the controller log"
                        .to_owned(),
                ),
            };
            if matches!(error, E::Credentials(_) | E::Backend { .. }) {
                eprintln!("proxmox console attach failed: {error}");
            }
            refuse(socket, code, &reason).await;
            return;
        }
    };
    relay(socket, route.proxmox, attached).await;
}

/// Reads exactly `count` bytes from the browser, across messages.
async fn browser_read(
    socket: &mut WebSocket,
    buffer: &mut Vec<u8>,
    count: usize,
) -> Option<Vec<u8>> {
    while buffer.len() < count {
        match socket.recv().await? {
            Ok(Message::Binary(bytes)) => buffer.extend_from_slice(&bytes),
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => {}
        }
    }
    let rest = buffer.split_off(count);
    Some(std::mem::replace(buffer, rest))
}

/// The RFB 3.8 exchange toward the browser: PVE's VNC authentication is
/// already done, so the browser is offered security type *None*. Returns the
/// bytes the browser sent past the exchange.
async fn browser_handshake(socket: &mut WebSocket) -> Option<Vec<u8>> {
    let mut buffer = Vec::new();
    socket
        .send(Message::Binary(b"RFB 003.008\n".to_vec().into()))
        .await
        .ok()?;
    let version = browser_read(socket, &mut buffer, 12).await?;
    if !version.starts_with(b"RFB 003.") {
        return None;
    }
    // One security type: None (1).
    socket
        .send(Message::Binary(vec![1_u8, 1].into()))
        .await
        .ok()?;
    let chosen = browser_read(socket, &mut buffer, 1).await?;
    if chosen != [1] {
        return None;
    }
    socket
        .send(Message::Binary(vec![0_u8, 0, 0, 0].into()))
        .await
        .ok()?;
    Some(buffer)
}

async fn relay(mut socket: WebSocket, proxmox: Arc<ProxmoxAccounts>, attached: AttachedConsole) {
    let AttachedConsole {
        session_id,
        mut channel,
        limits,
        mut shutdown,
    } = attached;

    let started = tokio::time::Instant::now();
    let max_deadline = started + limits.max_duration;
    let mut idle_deadline = started + limits.idle;
    let mut activity = ClientActivity::default();

    let (reason, code, text) = 'run: {
        let leftover =
            match tokio::time::timeout(BROWSER_HANDSHAKE_TIMEOUT, browser_handshake(&mut socket))
                .await
            {
                Ok(Some(leftover)) => leftover,
                Ok(None) | Err(_) => {
                    break 'run (ConsoleCloseReason::Client, close::NORMAL, "handshake ended");
                }
            };
        if !leftover.is_empty() {
            if activity.observe(&leftover) {
                idle_deadline = tokio::time::Instant::now() + limits.idle;
            }
            if channel.send(leftover).await.is_err() {
                break 'run (
                    ConsoleCloseReason::Error,
                    close::UPSTREAM,
                    "the screen closed",
                );
            }
        }
        loop {
            tokio::select! {
                from_guest = channel.recv() => match from_guest {
                    Ok(Some(bytes)) => {
                        if socket.send(Message::Binary(bytes.into())).await.is_err() {
                            break 'run (ConsoleCloseReason::Client, close::NORMAL, "the browser went away");
                        }
                    }
                    Ok(None) => break 'run (ConsoleCloseReason::Guest, close::NORMAL, "the guest closed its screen"),
                    Err(_) => break 'run (ConsoleCloseReason::Error, close::UPSTREAM, "the screen connection failed"),
                },
                from_browser = socket.recv() => match from_browser {
                    Some(Ok(Message::Binary(bytes))) => {
                        if activity.observe(&bytes) {
                            idle_deadline = tokio::time::Instant::now() + limits.idle;
                        }
                        if channel.send(bytes.to_vec()).await.is_err() {
                            break 'run (ConsoleCloseReason::Error, close::UPSTREAM, "the screen connection failed");
                        }
                    }
                    Some(Ok(Message::Close(_)) | Err(_)) | None => {
                        break 'run (ConsoleCloseReason::Client, close::NORMAL, "closed");
                    }
                    Some(Ok(_)) => {}
                },
                () = tokio::time::sleep_until(idle_deadline) => {
                    break 'run (ConsoleCloseReason::Idle, close::IDLE, "the console was idle");
                }
                () = tokio::time::sleep_until(max_deadline) => {
                    break 'run (ConsoleCloseReason::MaxDuration, close::MAX_DURATION, "the maximum duration was reached");
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break 'run (ConsoleCloseReason::Shutdown, close::SHUTDOWN, "the controller is shutting down");
                    }
                }
            }
        }
    };

    channel.close().await;
    refuse(socket, code, text).await;
    if let Err(error) = proxmox
        .console_end(
            &session_id,
            reason,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
    {
        eprintln!("proxmox console end audit failed: {error}");
    }
}

/// Finds the input events in the browser's RFB client-to-server stream so
/// the idle bound counts a person at the keyboard, not a viewer's automatic
/// update requests. A stream it cannot follow counts as activity: the bound
/// fails open rather than closing a working console.
#[derive(Default)]
struct ClientActivity {
    buffer: Vec<u8>,
    lost: bool,
}

impl ClientActivity {
    /// Feeds bytes; true when they contain a key, pointer, or clipboard
    /// message.
    fn observe(&mut self, bytes: &[u8]) -> bool {
        if self.lost {
            return true;
        }
        self.buffer.extend_from_slice(bytes);
        let mut input = false;
        let mut offset = 0;
        loop {
            let rest = &self.buffer[offset..];
            let Some(&kind) = rest.first() else { break };
            let length = match kind {
                // SetPixelFormat.
                0 => Some(20),
                // SetEncodings: 4 + 4 * count.
                2 => rest
                    .get(2..4)
                    .map(|count| 4 + 4 * usize::from(u16::from_be_bytes([count[0], count[1]]))),
                // FramebufferUpdateRequest.
                3 => Some(10),
                // KeyEvent, PointerEvent.
                4 => Some(8),
                5 => Some(6),
                // ClientCutText: 8 + length.
                6 => rest.get(4..8).map(|len| {
                    8 + usize::try_from(u32::from_be_bytes([len[0], len[1], len[2], len[3]]))
                        .unwrap_or(usize::MAX)
                }),
                // QEMU extended key event (255, 0): 12 bytes.
                255 => rest.get(1).and_then(|sub| (*sub == 0).then_some(12)),
                _ => {
                    self.lost = true;
                    self.buffer.clear();
                    return true;
                }
            };
            let Some(length) = length else { break };
            if length > MAX_BROWSER_MESSAGE_BYTES * 2 {
                self.lost = true;
                self.buffer.clear();
                return true;
            }
            if rest.len() < length {
                break;
            }
            if matches!(kind, 4..=6 | 255) {
                input = true;
            }
            offset += length;
        }
        self.buffer.drain(..offset);
        input
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_requests_are_not_input_but_keys_and_pointers_are() {
        let mut activity = ClientActivity::default();
        // FramebufferUpdateRequest.
        assert!(!activity.observe(&[3, 1, 0, 0, 0, 0, 3, 0x20, 2, 0x58]));
        // KeyEvent down for 'a'.
        assert!(activity.observe(&[4, 1, 0, 0, 0, 0, 0, 0x61]));
        // PointerEvent.
        assert!(activity.observe(&[5, 0, 0, 10, 0, 20]));
    }

    #[test]
    fn messages_split_across_frames_are_followed() {
        let mut activity = ClientActivity::default();
        assert!(!activity.observe(&[4, 1, 0]));
        assert!(activity.observe(&[0, 0, 0, 0, 0x61]));
        // SetEncodings with two encodings arrives in three frames.
        assert!(!activity.observe(&[2, 0]));
        assert!(!activity.observe(&[0, 2, 0, 0, 0, 0]));
        assert!(!activity.observe(&[0, 0, 0, 1]));
    }

    #[test]
    fn an_unfollowable_stream_counts_as_activity() {
        let mut activity = ClientActivity::default();
        assert!(activity.observe(&[99, 1, 2, 3]));
        assert!(activity.observe(&[3, 1, 0, 0, 0, 0, 3, 0x20, 2, 0x58]));
    }

    #[test]
    fn clipboard_text_is_input() {
        let mut activity = ClientActivity::default();
        let mut message = vec![6, 0, 0, 0, 0, 0, 0, 2];
        message.extend_from_slice(b"hi");
        assert!(activity.observe(&message));
    }

    #[test]
    fn the_token_is_read_from_the_subprotocol_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            "binary, fleet-console-token.abc_DEF-123".parse().unwrap(),
        );
        assert_eq!(offered_token(&headers).as_deref(), Some("abc_DEF-123"));
        assert_eq!(offered_token(&HeaderMap::new()), None);
    }

    #[test]
    fn cross_origin_upgrades_are_refused() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "fleet.example.test:8443".parse().unwrap());
        assert!(same_origin(&headers));
        headers.insert(
            header::ORIGIN,
            "https://fleet.example.test:8443".parse().unwrap(),
        );
        assert!(same_origin(&headers));
        headers.insert(header::ORIGIN, "https://evil.example.test".parse().unwrap());
        assert!(!same_origin(&headers));
    }
}
