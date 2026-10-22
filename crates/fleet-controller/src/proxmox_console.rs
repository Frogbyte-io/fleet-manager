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

/// How long one send may take before the peer is treated as gone.
const SEND_TIMEOUT: Duration = Duration::from_secs(15);

/// How often the relay pings the browser, and how long a browser may stay
/// completely silent (no message, no pong) before it is treated as gone.
const PING_INTERVAL: Duration = Duration::from_secs(20);
const PEER_SILENCE_LIMIT: Duration = Duration::from_secs(75);

/// WebSocket close codes the relay uses (private-use range).
mod close {
    pub const UNAUTHENTICATED: u16 = 4401;
    pub const DENIED: u16 = 4403;
    pub const NOT_FOUND: u16 = 4404;
    pub const CONFLICT: u16 = 4409;
    pub const UPSTREAM: u16 = 4502;
    pub const UNAVAILABLE: u16 = 4503;
    pub const IDLE: u16 = 4408;
    pub const PROTOCOL: u16 = 4400;
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

/// Whether a browser-supplied `Origin` names the host it connected to, by the
/// same rule as the mutation guard. A missing Origin is a non-browser client
/// and is left to the token.
fn origin_allowed(headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    crate::browser::same_origin(origin, host)
}

async fn socket_handler(
    State(route): State<ConsoleRoute>,
    principal: Option<Extension<ActingPrincipal>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !origin_allowed(&headers) {
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
    // Let the close handshake finish before the socket drops: closing a TCP
    // connection with unread browser bytes in it resets the connection and can
    // discard the close frame the browser has not read yet. Bounded.
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(Ok(message)) = socket.recv().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
    })
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

/// Sends one message to the browser, bounded: a peer that stopped reading
/// (a half-open connection) cannot stall the relay and its timers.
async fn send_to_browser(socket: &mut WebSocket, message: Message) -> bool {
    matches!(
        tokio::time::timeout(SEND_TIMEOUT, socket.send(message)).await,
        Ok(Ok(()))
    )
}

/// Sends one message toward the guest, bounded like [`send_to_browser`].
async fn send_to_guest(channel: &mut dyn ConsoleChannel, bytes: Vec<u8>) -> bool {
    matches!(
        tokio::time::timeout(SEND_TIMEOUT, channel.send(bytes)).await,
        Ok(Ok(()))
    )
}

/// Why the browser-side RFB exchange did not complete.
enum HandshakeEnd {
    /// The browser went away or stalled.
    Gone,
    /// The browser speaks something the relay does not: it gets a reason.
    Refused(&'static str),
}

/// The RFB 3.8 exchange toward the browser: PVE's VNC authentication is
/// already done, so the browser is offered security type *None*. A client
/// that does not answer with 3.8 is refused cleanly (the relay offers exactly
/// the one version it has tested). Returns the bytes the browser sent past
/// the exchange.
async fn browser_handshake(socket: &mut WebSocket) -> Result<Vec<u8>, HandshakeEnd> {
    let mut buffer = Vec::new();
    if !send_to_browser(socket, Message::Binary(b"RFB 003.008\n".to_vec().into())).await {
        return Err(HandshakeEnd::Gone);
    }
    let version = browser_read(socket, &mut buffer, 12)
        .await
        .ok_or(HandshakeEnd::Gone)?;
    if version != b"RFB 003.008\n" {
        return Err(HandshakeEnd::Refused(
            "the console speaks RFB 3.8 only; this client answered another version",
        ));
    }
    // One security type: None (1).
    if !send_to_browser(socket, Message::Binary(vec![1_u8, 1].into())).await {
        return Err(HandshakeEnd::Gone);
    }
    let chosen = browser_read(socket, &mut buffer, 1)
        .await
        .ok_or(HandshakeEnd::Gone)?;
    if chosen != [1] {
        return Err(HandshakeEnd::Refused(
            "the client chose an RFB security type the console does not offer",
        ));
    }
    if !send_to_browser(socket, Message::Binary(vec![0_u8, 0, 0, 0].into())).await {
        return Err(HandshakeEnd::Gone);
    }
    Ok(buffer)
}

type Ended = (ConsoleCloseReason, u16, &'static str);

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
    let mut last_heard = started;
    let mut ping = tokio::time::interval_at(started + PING_INTERVAL, PING_INTERVAL);

    let (reason, code, text): Ended = 'run: {
        // A shutdown that began before this relay subscribed is not a
        // change the receiver will report: check the state itself.
        if *shutdown.borrow() {
            break 'run (
                ConsoleCloseReason::Shutdown,
                close::SHUTDOWN,
                "the controller is shutting down",
            );
        }
        let leftover =
            match tokio::time::timeout(BROWSER_HANDSHAKE_TIMEOUT, browser_handshake(&mut socket))
                .await
            {
                Ok(Ok(leftover)) => leftover,
                Ok(Err(HandshakeEnd::Refused(text))) => {
                    break 'run (ConsoleCloseReason::Protocol, close::PROTOCOL, text);
                }
                Ok(Err(HandshakeEnd::Gone)) | Err(_) => {
                    break 'run (ConsoleCloseReason::Client, close::NORMAL, "handshake ended");
                }
            };
        if !leftover.is_empty() {
            match activity.observe(&leftover) {
                Ok(true) => idle_deadline = tokio::time::Instant::now() + limits.idle,
                Ok(false) => {}
                Err(_) => break 'run (ConsoleCloseReason::Protocol, close::PROTOCOL, UNFOLLOWABLE),
            }
            if !send_to_guest(&mut *channel, leftover).await {
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
                        if !send_to_browser(&mut socket, Message::Binary(bytes.into())).await {
                            break 'run (ConsoleCloseReason::Client, close::NORMAL, "the browser went away");
                        }
                    }
                    Ok(None) => break 'run (ConsoleCloseReason::Guest, close::NORMAL, "the guest closed its screen"),
                    Err(_) => break 'run (ConsoleCloseReason::Error, close::UPSTREAM, "the screen connection failed"),
                },
                from_browser = socket.recv() => {
                    last_heard = tokio::time::Instant::now();
                    match from_browser {
                        Some(Ok(Message::Binary(bytes))) => {
                            match activity.observe(&bytes) {
                                Ok(true) => idle_deadline = tokio::time::Instant::now() + limits.idle,
                                Ok(false) => {}
                                Err(_) => break 'run (ConsoleCloseReason::Protocol, close::PROTOCOL, UNFOLLOWABLE),
                            }
                            if !send_to_guest(&mut *channel, bytes.to_vec()).await {
                                break 'run (ConsoleCloseReason::Error, close::UPSTREAM, "the screen connection failed");
                            }
                        }
                        Some(Ok(Message::Close(_)) | Err(_)) | None => {
                            break 'run (ConsoleCloseReason::Client, close::NORMAL, "closed");
                        }
                        // Pongs (and the library's own ping replies) prove the
                        // peer is alive; text frames are not RFB.
                        Some(Ok(_)) => {}
                    }
                }
                _ = ping.tick() => {
                    if last_heard.elapsed() > PEER_SILENCE_LIMIT {
                        break 'run (ConsoleCloseReason::Client, close::NORMAL, "the browser stopped answering");
                    }
                    if !send_to_browser(&mut socket, Message::Ping(Vec::new().into())).await {
                        break 'run (ConsoleCloseReason::Client, close::NORMAL, "the browser went away");
                    }
                }
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
    let _ = tokio::time::timeout(SEND_TIMEOUT, refuse(socket, code, text)).await;
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

/// The close text when the browser's stream could not be followed.
const UNFOLLOWABLE: &str = "the console could not follow the browser's RFB stream and closed";

/// The browser's RFB stream could not be followed.
#[derive(Debug, PartialEq, Eq)]
struct Unfollowable;

/// The largest single client message the relay follows. Clipboard text is the
/// only variable-length message that can be large.
const MAX_CLIENT_MESSAGE_BYTES: usize = 2 * 1024 * 1024;

/// `ClientCutText` extended-clipboard action bits (RFB extension, as noVNC
/// 1.7.0 sends them): `Caps` marks a capability announcement, `Provide`
/// carries the clipboard contents.
const CLIPBOARD_ACTION_CAPS: u32 = 1 << 24;
const CLIPBOARD_ACTION_PROVIDE: u32 = 1 << 28;

/// Finds the input events in the browser's RFB client-to-server stream so
/// the idle bound counts a person at the keyboard, not a viewer's automatic
/// messages (update requests, encodings, the extended-clipboard announcement
/// noVNC sends on connect). It follows every client message noVNC 1.7.0 and
/// the QEMU extensions send; a stream it cannot follow is an error the relay
/// answers by closing (reason `protocol`), never by disabling the bound.
#[derive(Default)]
struct ClientActivity {
    buffer: Vec<u8>,
    /// Whether the one-byte `ClientInit` that follows the security result
    /// (before any typed message) has been consumed.
    client_init_done: bool,
}

impl ClientActivity {
    /// Feeds bytes; true when they complete a key, pointer, or pasted-text
    /// message.
    fn observe(&mut self, bytes: &[u8]) -> Result<bool, Unfollowable> {
        self.buffer.extend_from_slice(bytes);
        let mut input = false;
        let mut offset = 0;
        if !self.client_init_done && !self.buffer.is_empty() {
            // ClientInit: the shared-session flag, one byte, not a typed
            // message.
            self.client_init_done = true;
            offset = 1;
        }
        loop {
            let rest = &self.buffer[offset..];
            let Some(&kind) = rest.first() else { break };
            let Some((length, is_input)) = Self::classify(kind, rest)? else {
                break;
            };
            if length > MAX_CLIENT_MESSAGE_BYTES {
                return Err(Unfollowable);
            }
            if rest.len() < length {
                break;
            }
            // Extended clipboard: only "provide" carries user text.
            let is_input = match (kind, is_input) {
                (6, _) => Self::clipboard_is_input(&rest[..length]),
                (_, flag) => flag,
            };
            input |= is_input;
            offset += length;
        }
        self.buffer.drain(..offset);
        if self.buffer.len() > MAX_CLIENT_MESSAGE_BYTES {
            return Err(Unfollowable);
        }
        Ok(input)
    }

    /// The total length of the message starting at `rest[0]` and whether it
    /// is input; `None` when more bytes are needed to know.
    fn classify(kind: u8, rest: &[u8]) -> Result<Option<(usize, bool)>, Unfollowable> {
        let be16 = |at: usize| {
            rest.get(at..at + 2)
                .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
        };
        let length = match kind {
            // SetPixelFormat.
            0 => Some((20, false)),
            // SetEncodings: 4 + 4 * count.
            2 => be16(2).map(|count| (4 + 4 * count, false)),
            // FramebufferUpdateRequest.
            3 => Some((10, false)),
            // KeyEvent.
            4 => Some((8, true)),
            // PointerEvent: 6 bytes, 7 with noVNC's extended-button marker
            // (bit 7 of the mask byte).
            5 => rest
                .get(1)
                .map(|mask| (if mask & 0x80 == 0 { 6 } else { 7 }, true)),
            // ClientCutText: 8 + |length|; a negative length is the
            // extended-clipboard form.
            6 => rest.get(4..8).map(|len| {
                let signed = i32::from_be_bytes([len[0], len[1], len[2], len[3]]);
                (
                    8usize.saturating_add(
                        usize::try_from(signed.unsigned_abs()).unwrap_or(usize::MAX),
                    ),
                    true,
                )
            }),
            // EnableContinuousUpdates.
            150 => Some((10, false)),
            // ClientFence: 9 + payload length.
            248 => rest.get(8).map(|n| (9 + usize::from(*n), false)),
            // xvp.
            250 => Some((4, false)),
            // SetDesktopSize: 8 + 16 * screens.
            251 => rest.get(6).map(|n| (8 + 16 * usize::from(*n), false)),
            // QEMU extended key event (255, 0): 12 bytes.
            255 => match rest.get(1) {
                Some(0) => Some((12, true)),
                Some(_) => return Err(Unfollowable),
                None => None,
            },
            _ => return Err(Unfollowable),
        };
        Ok(length)
    }

    /// Whether one complete `ClientCutText` is user text: a plain one is; an
    /// extended one only when it provides contents (not a caps announcement,
    /// notify, request, or peek, which noVNC sends by itself).
    fn clipboard_is_input(message: &[u8]) -> bool {
        let negative = message.get(4).is_some_and(|b| b & 0x80 != 0);
        if !negative {
            return true;
        }
        let Some(flags) = message.get(8..12) else {
            return false;
        };
        let flags = u32::from_be_bytes([flags[0], flags[1], flags[2], flags[3]]);
        flags & CLIPBOARD_ACTION_PROVIDE != 0 && flags & CLIPBOARD_ACTION_CAPS == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client messages noVNC 1.7.0 builds, captured from its own code.
    fn novnc() -> std::collections::BTreeMap<String, Vec<u8>> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/novnc-1.7.0-client-messages.json"
        ))
        .unwrap();
        fixture["messages"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, bytes)| {
                (
                    name.clone(),
                    bytes
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|byte| u8::try_from(byte.as_u64().unwrap()).unwrap())
                        .collect(),
                )
            })
            .collect()
    }

    /// A tracker past the one-byte `ClientInit`, as the relay has after the
    /// browser's first byte.
    fn after_client_init() -> ClientActivity {
        let mut activity = ClientActivity::default();
        assert_eq!(activity.observe(&[1]), Ok(false));
        activity
    }

    #[test]
    fn the_client_init_byte_is_not_a_message_and_not_input() {
        let mut activity = ClientActivity::default();
        assert_eq!(activity.observe(&[1]), Ok(false));
        assert_eq!(activity.observe(&novnc()["keyEvent"]), Ok(true));
        // ClientInit and a message in one frame.
        let mut activity = ClientActivity::default();
        let mut frame = vec![0_u8];
        frame.extend_from_slice(&novnc()["fbUpdateRequest"]);
        assert_eq!(activity.observe(&frame), Ok(false));
        assert!(activity.buffer.is_empty());
    }

    #[test]
    fn every_message_novnc_sends_is_followed_and_only_input_counts() {
        let messages = novnc();
        let input = [
            "keyEvent",
            "qemuKey",
            "pointer",
            "extPointer",
            "cutText",
            "extClipProvide",
        ];
        let automatic = [
            "pixelFormat",
            "clientEncodings",
            "fbUpdateRequest",
            "extClipCaps",
            "extClipNotify",
            "extClipRequest",
            "fence",
            "continuous",
            "xvp",
            "setDesktopSize",
        ];
        for name in input {
            let mut activity = after_client_init();
            assert_eq!(activity.observe(&messages[name]), Ok(true), "{name}");
            assert!(activity.buffer.is_empty(), "{name} was consumed whole");
        }
        for name in automatic {
            let mut activity = after_client_init();
            assert_eq!(activity.observe(&messages[name]), Ok(false), "{name}");
            assert!(activity.buffer.is_empty(), "{name} was consumed whole");
        }
    }

    #[test]
    fn a_real_connection_sequence_is_followed_byte_by_byte() {
        // The order noVNC sends on connect, then a keystroke, delivered one
        // byte per WebSocket message: the idle bound still sees exactly one
        // input.
        let messages = novnc();
        let mut stream = vec![1_u8];
        for name in [
            "pixelFormat",
            "clientEncodings",
            "extClipCaps",
            "fbUpdateRequest",
            "fence",
            "keyEvent",
        ] {
            stream.extend_from_slice(&messages[name]);
        }
        let mut activity = ClientActivity::default();
        let mut inputs = 0;
        for byte in stream {
            if activity.observe(&[byte]).unwrap() {
                inputs += 1;
            }
        }
        assert_eq!(inputs, 1);
        assert!(activity.buffer.is_empty());
    }

    #[test]
    fn an_extended_clipboard_announcement_is_not_a_person_typing() {
        // Sent by noVNC on its own right after connecting; counting it would
        // keep every console from ever idling.
        let messages = novnc();
        let mut activity = after_client_init();
        assert_eq!(activity.observe(&messages["extClipCaps"]), Ok(false));
        // The negative length (extended form) is read as |length|, not as a
        // 4 GiB payload.
        assert_eq!(&messages["extClipCaps"][4..8], &[255, 255, 255, 248]);
    }

    #[test]
    fn an_unfollowable_stream_is_an_error_never_a_disabled_bound() {
        assert_eq!(
            after_client_init().observe(&[99, 1, 2, 3]),
            Err(Unfollowable)
        );
        // QEMU audio and other sub-messages noVNC never sends.
        assert_eq!(
            after_client_init().observe(&[255, 7, 0, 0]),
            Err(Unfollowable)
        );
        // A cut-text length claiming more than the relay follows.
        assert_eq!(
            after_client_init().observe(&[6, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff]),
            Err(Unfollowable)
        );
    }

    #[test]
    fn plain_clipboard_text_is_input() {
        let mut activity = after_client_init();
        let mut message = vec![6, 0, 0, 0, 0, 0, 0, 2];
        message.extend_from_slice(b"hi");
        assert_eq!(activity.observe(&message), Ok(true));
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
        assert!(origin_allowed(&headers));
        headers.insert(
            header::ORIGIN,
            "https://fleet.example.test:8443".parse().unwrap(),
        );
        assert!(origin_allowed(&headers));
        headers.insert(header::ORIGIN, "https://evil.example.test".parse().unwrap());
        assert!(!origin_allowed(&headers));
    }
}
