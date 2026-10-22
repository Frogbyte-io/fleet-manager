//! The Proxmox VM screen end to end (FM-495): a real controller router, secret
//! store and audit ledger over a fake PVE transport whose `vncproxy` and
//! `vncwebsocket` answer like PVE (recorded-shape fixtures, an in-memory RFB
//! server that checks the one-time VNC password). The browser is a real
//! WebSocket client; it never sees a PVE credential, the session token is
//! single-use, the bounds close the console, and the audit trail records the
//! start and the end without any screen content.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, ReasonId};
use fleet_application::proxmox::console::ConsoleLimits;
use fleet_controller::Settings;
use fleet_controller::build_router;
use fleet_controller::proxmox_store::compose_proxmox;
use fleet_provider_proxmox::{
    PveHttpRequest, PveHttpResponse, PveSocket, PveTransport, PveTransportError, vnc_auth_response,
};
use fleet_secrets::SecretStore;
use fleet_storage_sqlite::Store;
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use tokio::net::TcpListener as TokioListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";
const SECRET: &str = "the-token-secret-material";
const VNC_PASSWORD: &str = "Zx3QpL9w";
const VNC_TICKET: &str = "PVEVNC:68E00010:SYNTHETICTICKET==::SYNTHETICSIGNATURE==";
const VERSION_9: &str =
    include_str!("../../providers/fleet-provider-proxmox/tests/fixtures/pve9/version.json");
const VNCPROXY_9: &str = include_str!(
    "../../providers/fleet-provider-proxmox/tests/fixtures/pve9/contract-vncproxy.json"
);
const PERMISSIONS_FULL: &str = include_str!(
    "../../providers/fleet-provider-proxmox/tests/fixtures/pve9/access-permissions-full.json"
);
const PERMISSIONS_READONLY: &str = include_str!(
    "../../providers/fleet-provider-proxmox/tests/fixtures/pve9/access-permissions-readonly.json"
);

/// How the fake guest's screen behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Screen {
    /// Serve until the controller closes.
    Open,
    /// Close the screen right after `ServerInit` (the guest stopped).
    ClosesAfterInit,
    /// PVE refuses the proxy: `VM.Console` is missing.
    Forbidden,
}

#[derive(Debug)]
struct ConsoleTransport {
    permissions: &'static str,
    screen: Screen,
    /// What the guest's screen received from the browser, after the
    /// controller-side authentication.
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Every API path and the pinned fingerprint it used.
    calls: Mutex<Vec<(String, Option<String>)>>,
}

impl ConsoleTransport {
    fn new(permissions: &'static str, screen: Screen) -> Arc<Self> {
        Arc::new(Self {
            permissions,
            screen,
            received: Arc::new(Mutex::new(Vec::new())),
            calls: Mutex::new(Vec::new()),
        })
    }
}

/// An in-memory binary socket.
struct MemorySocket {
    to_server: Option<mpsc::UnboundedSender<Vec<u8>>>,
    from_server: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl std::fmt::Debug for MemorySocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemorySocket")
    }
}

#[async_trait]
impl PveSocket for MemorySocket {
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, PveTransportError> {
        Ok(self.from_server.recv().await)
    }

    async fn send(&mut self, data: Vec<u8>) -> Result<(), PveTransportError> {
        match &self.to_server {
            Some(sender) if sender.send(data).is_ok() => Ok(()),
            _ => Err(PveTransportError::Connect {
                detail: "the screen is closed".to_owned(),
            }),
        }
    }

    async fn close(&mut self) {
        self.to_server = None;
    }
}

/// The RFB server side of the fake guest: VNC authentication with the
/// one-time password, then `ServerInit`, then record everything received.
async fn rfb_server(
    mut from_client: mpsc::UnboundedReceiver<Vec<u8>>,
    to_client: mpsc::UnboundedSender<Vec<u8>>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    closes_after_init: bool,
) {
    let _ = to_client.send(b"RFB 003.008\n".to_vec());
    assert_eq!(from_client.recv().await.unwrap(), b"RFB 003.008\n");
    let _ = to_client.send(vec![1, 2]);
    assert_eq!(from_client.recv().await.unwrap(), [2]);
    let challenge: [u8; 16] = *b"0123456789abcdef";
    let _ = to_client.send(challenge.to_vec());
    let response = from_client.recv().await.unwrap();
    assert_eq!(
        response,
        vnc_auth_response(VNC_PASSWORD, &challenge),
        "the controller authenticates with the one-time password"
    );
    let _ = to_client.send(vec![0, 0, 0, 0]);
    let _ = to_client.send(b"SERVERINIT".to_vec());
    if closes_after_init {
        return;
    }
    while let Some(bytes) = from_client.recv().await {
        received.lock().unwrap().push(bytes);
    }
}

#[async_trait]
impl PveTransport for ConsoleTransport {
    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        let Some(pinned) = &request.pinned_fingerprint else {
            return Err(PveTransportError::ObserveRefused {
                observed: FP.to_owned(),
            });
        };
        self.calls
            .lock()
            .unwrap()
            .push((request.path.clone(), Some(pinned.clone())));
        let (status, body) = match request.path.as_str() {
            "/api2/json/version" => (200, VERSION_9),
            "/api2/json/access/permissions" => (200, self.permissions),
            other if other.starts_with("/api2/json/cluster/nextid?vmid=") => {
                (400, r#"{"data":null,"message":"exists"}"#)
            }
            other => panic!("unexpected call {other}"),
        };
        Ok(PveHttpResponse {
            status,
            body: body.as_bytes().to_vec(),
        })
    }

    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        self.calls
            .lock()
            .unwrap()
            .push((request.path.clone(), request.pinned_fingerprint.clone()));
        assert!(request.path.ends_with("/vncproxy"), "{}", request.path);
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["websocket"], 1);
        if self.screen == Screen::Forbidden {
            return Ok(PveHttpResponse {
                status: 403,
                body:
                    br#"{"data":null,"message":"Permission check failed (/vms/101, VM.Console)"}"#
                        .to_vec(),
            });
        }
        Ok(PveHttpResponse {
            status: 200,
            body: VNCPROXY_9.as_bytes().to_vec(),
        })
    }

    async fn connect_websocket(
        &self,
        request: PveHttpRequest,
    ) -> Result<Box<dyn PveSocket>, PveTransportError> {
        assert_eq!(request.pinned_fingerprint.as_deref(), Some(FP));
        assert!(
            request.path.contains("/vncwebsocket?port=5900&vncticket="),
            "{}",
            request.path
        );
        assert!(
            request.path.contains("PVEVNC%3A68E00010"),
            "{}",
            request.path
        );
        let (to_server, from_client) = mpsc::unbounded_channel();
        let (to_client, from_server) = mpsc::unbounded_channel();
        tokio::spawn(rfb_server(
            from_client,
            to_client,
            Arc::clone(&self.received),
            self.screen == Screen::ClosesAfterInit,
        ));
        Ok(Box::new(MemorySocket {
            to_server: Some(to_server),
            from_server,
        }))
    }
}

struct Harness {
    _dist: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _key_dir: tempfile::TempDir,
    address: std::net::SocketAddr,
    proxmox: Arc<fleet_application::proxmox::ProxmoxAccounts>,
    transport: Arc<ConsoleTransport>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

async fn harness(
    permissions: &'static str,
    screen: Screen,
    limits: Option<ConsoleLimits>,
) -> Harness {
    let dist = tempfile::tempdir().unwrap();
    std::fs::write(dist.path().join("index.html"), "<html>fleet</html>").unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(&store_dir.path().join("fleet.db"))
        .await
        .unwrap();
    let key_dir = tempfile::tempdir().unwrap();
    let key_path = key_dir.path().join("master.key");
    std::fs::write(
        &key_path,
        "1 0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let secrets = Arc::new(SecretStore::open(store.pool().clone(), &key_path).unwrap());
    let transport = ConsoleTransport::new(permissions, screen);
    let mut accounts = compose_proxmox(
        store.pool().clone(),
        secrets,
        transport.clone(),
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    );
    if let Some(limits) = limits {
        accounts = accounts.with_console_limits(limits);
    }
    let proxmox = Arc::new(accounts);
    let settings = Settings {
        listen: "127.0.0.1:0".parse().unwrap(),
        web_dist: dist.path().to_path_buf(),
        artifacts_dir: None,
        tailscale_serve_listen: None,
    };
    let router = build_router(
        &settings,
        Some(store.pool().clone()),
        None,
        None,
        None,
        None,
        Some(&proxmox),
        None,
        None,
    );
    let listener = TokioListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        })
        .await
        .expect("the test server must serve");
    });
    Harness {
        _dist: dist,
        _store_dir: store_dir,
        _key_dir: key_dir,
        address,
        proxmox,
        transport,
        shutdown: Some(shutdown_tx),
    }
}

/// One raw HTTP request over TCP.
async fn raw(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: test\r\n");
    if let Some(body) = &body {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.to_string().len()
        ));
    }
    head.push_str("Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    if let Some(body) = &body {
        stream.write_all(body.to_string().as_bytes()).await.unwrap();
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    let (head, rest) = text.split_once("\r\n\r\n").expect("an HTTP response");
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap();
    let body = serde_json::from_str(rest)
        .unwrap_or_else(|error| panic!("the {status} response body is not JSON ({error}): {rest}"));
    (status, body)
}

async fn trusted_account(harness: &Harness) -> String {
    let (status, body) = raw(
        harness.address,
        "POST",
        "/api/v1/proxmox/accounts",
        Some(json!({
            "name": "pve-main", "host": "192.0.2.10", "port": 8006,
            "tokenId": "fleet@pve!fleet", "tokenSecret": SECRET
        })),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let id = body["data"]["id"].as_str().unwrap().to_owned();
    let (status, body) = raw(
        harness.address,
        "POST",
        &format!("/api/v1/proxmox/accounts/{id}/observe"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = raw(
        harness.address,
        "POST",
        &format!("/api/v1/proxmox/accounts/{id}/confirm"),
        Some(json!({"fingerprint": FP})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    id
}

async fn create_session(harness: &Harness, account: &str) -> (u16, Value) {
    raw(
        harness.address,
        "POST",
        &format!("/api/v1/proxmox/accounts/{account}/console-sessions"),
        Some(json!({"node": "pve-a", "vmid": 101})),
    )
    .await
}

type Browser =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A browser: a WebSocket offering `binary` and the token subprotocol.
async fn connect_browser(harness: &Harness, token: &str) -> Browser {
    let url = format!("ws://{}/api/v1/proxmox/console/socket", harness.address);
    let mut request = url.into_client_request().unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        format!("binary, fleet-console-token.{token}")
            .parse()
            .unwrap(),
    );
    let (socket, response) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert_eq!(
        response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|value| value.to_str().ok()),
        Some("binary"),
        "the token subprotocol is never echoed back"
    );
    socket
}

async fn next_message(browser: &mut Browser) -> Message {
    tokio::time::timeout(Duration::from_secs(10), browser.next())
        .await
        .expect("a message within 10 s")
        .expect("the socket is open")
        .expect("a message")
}

async fn expect_binary(browser: &mut Browser, expected: &[u8]) {
    match next_message(browser).await {
        Message::Binary(bytes) => assert_eq!(bytes.as_ref(), expected),
        other => panic!("expected binary {expected:?}, got {other:?}"),
    }
}

/// Plays the browser through the RFB handshake the controller offers.
async fn browser_handshake(browser: &mut Browser) {
    expect_binary(browser, b"RFB 003.008\n").await;
    browser
        .send(Message::Binary(b"RFB 003.008\n".to_vec().into()))
        .await
        .unwrap();
    // One security type: None.
    expect_binary(browser, &[1, 1]).await;
    browser
        .send(Message::Binary(vec![1_u8].into()))
        .await
        .unwrap();
    expect_binary(browser, &[0, 0, 0, 0]).await;
}

async fn expect_close(browser: &mut Browser) -> (u16, String) {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), browser.next())
            .await
            .expect("a close within 10 s")
        {
            Some(Ok(Message::Close(Some(frame)))) => {
                return (u16::from(frame.code), frame.reason.to_string());
            }
            Some(Ok(Message::Close(None))) | None => return (1005, String::new()),
            Some(Ok(_)) => {}
            Some(Err(_)) => return (1006, String::new()),
        }
    }
}

async fn console_events(harness: &Harness) -> Vec<Value> {
    // The end event lands just after the close frame.
    for _ in 0..50 {
        let (status, body) = raw(
            harness.address,
            "GET",
            "/api/v1/audit?action=proxmox.console",
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let items = body["items"].as_array().unwrap().clone();
        if items
            .iter()
            .any(|event| event["metadata"]["event"] == "proxmox_console_session_ended")
        {
            return items;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the audit events never settled");
}

fn event_names(events: &[Value]) -> Vec<String> {
    let mut names: Vec<(i64, String)> = events
        .iter()
        .map(|event| {
            (
                event["seq"].as_i64().unwrap_or_default(),
                event["metadata"]["event"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    names.sort();
    names.into_iter().map(|(_, name)| name).collect()
}

#[tokio::test]
async fn a_session_attaches_once_relays_the_screen_and_audits_start_and_end() {
    let harness = harness(PERMISSIONS_FULL, Screen::Open, None).await;
    let account = trusted_account(&harness).await;

    let (status, created) = create_session(&harness, &account).await;
    assert_eq!(status, 201, "{created}");
    let token = created["data"]["token"].as_str().unwrap().to_owned();
    // The browser-facing response carries no PVE material at all.
    let shown = created.to_string();
    for forbidden in [SECRET, VNC_PASSWORD, VNC_TICKET, "PVEVNC", "PVEAPIToken"] {
        assert!(!shown.contains(forbidden), "{forbidden} leaked: {shown}");
    }
    assert_eq!(
        created["data"]["socketPath"],
        "/api/v1/proxmox/console/socket"
    );
    assert!(
        created["data"]["consolePath"]
            .as_str()
            .unwrap()
            .starts_with("/proxmox/console#session=")
    );
    assert_eq!(created["data"]["node"], "pve-a");
    assert_eq!(created["data"]["vmid"], 101);

    let mut browser = connect_browser(&harness, &token).await;
    browser_handshake(&mut browser).await;
    // The first screen message the browser sees is the guest's own; no
    // PVE credential ever crosses the browser socket.
    expect_binary(&mut browser, b"SERVERINIT").await;
    browser
        .send(Message::Binary(vec![4_u8, 1, 0, 0, 0, 0, 0, 0x61].into()))
        .await
        .unwrap();
    for _ in 0..50 {
        if !harness.transport.received.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        harness.transport.received.lock().unwrap().clone(),
        vec![vec![4_u8, 1, 0, 0, 0, 0, 0, 0x61]],
        "the guest receives exactly the browser's key event"
    );
    browser.close(None).await.unwrap();

    let events = console_events(&harness).await;
    assert_eq!(
        event_names(&events),
        [
            "proxmox_console_session_created",
            "proxmox_console_session_started",
            "proxmox_console_session_ended"
        ]
    );
    let ended = events
        .iter()
        .find(|event| event["metadata"]["event"] == "proxmox_console_session_ended")
        .unwrap();
    assert_eq!(ended["metadata"]["reason"], "client");
    assert_eq!(ended["metadata"]["vmid"], "101");
    assert_eq!(ended["metadata"]["node"], "pve-a");
    assert!(
        ended["metadata"]["durationMs"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .is_ok()
    );
    assert_eq!(ended["resource"], account);
    // Nothing secret, and nothing the screen showed, is in the audit trail.
    let everything = serde_json::to_string(&events).unwrap();
    for forbidden in [SECRET, VNC_PASSWORD, VNC_TICKET, &token, "SERVERINIT"] {
        assert!(
            !everything.contains(forbidden),
            "{forbidden} in the audit trail"
        );
    }
    // Every PVE call used the pinned fingerprint.
    assert!(
        harness
            .transport
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|(_, pin)| pin.as_deref() == Some(FP))
    );
}

#[tokio::test]
async fn the_session_token_is_single_use() {
    let harness = harness(PERMISSIONS_FULL, Screen::Open, None).await;
    let account = trusted_account(&harness).await;
    let (_, created) = create_session(&harness, &account).await;
    let token = created["data"]["token"].as_str().unwrap().to_owned();

    let mut first = connect_browser(&harness, &token).await;
    browser_handshake(&mut first).await;
    let mut second = connect_browser(&harness, &token).await;
    let (code, reason) = expect_close(&mut second).await;
    assert_eq!(code, 4404, "{reason}");
    assert!(reason.contains("already used"), "{reason}");
    first.close(None).await.unwrap();
}

#[tokio::test]
async fn an_unknown_token_and_a_missing_subprotocol_are_refused() {
    let harness = harness(PERMISSIONS_FULL, Screen::Open, None).await;
    let mut browser = connect_browser(&harness, "not-a-real-token").await;
    assert_eq!(expect_close(&mut browser).await.0, 4404);

    // No token subprotocol at all: refused before the upgrade.
    let url = format!("ws://{}/api/v1/proxmox/console/socket", harness.address);
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
    let error = tokio_tungstenite::connect_async(request).await.unwrap_err();
    assert!(error.to_string().contains("400"), "{error}");

    // A foreign Origin is refused: a page on another site cannot drive it.
    let mut request = format!("ws://{}/api/v1/proxmox/console/socket", harness.address)
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "binary, fleet-console-token.x".parse().unwrap(),
    );
    request
        .headers_mut()
        .insert("Origin", "https://evil.example.test".parse().unwrap());
    let error = tokio_tungstenite::connect_async(request).await.unwrap_err();
    assert!(error.to_string().contains("403"), "{error}");
}

#[tokio::test]
async fn a_token_without_vm_console_gets_an_explained_refusal() {
    let harness = harness(PERMISSIONS_READONLY, Screen::Open, None).await;
    let account = trusted_account(&harness).await;
    let (status, body) = create_session(&harness, &account).await;
    assert_eq!(status, 502, "{body}");
    let message = body["message"].as_str().unwrap();
    assert!(message.contains("VM.Console"), "{message}");
    assert!(message.contains("/vms/101"), "{message}");
    assert_eq!(harness.proxmox.console_session_count(), 0);
}

#[tokio::test]
async fn a_refusal_at_the_pve_proxy_is_explained_on_the_socket() {
    // The permissions map says yes (it is token-wide, not per guest) but PVE
    // refuses the proxy for this guest: the console says why.
    let harness = harness(PERMISSIONS_FULL, Screen::Forbidden, None).await;
    let account = trusted_account(&harness).await;
    let (status, created) = create_session(&harness, &account).await;
    assert_eq!(status, 201, "{created}");
    let token = created["data"]["token"].as_str().unwrap().to_owned();
    let mut browser = connect_browser(&harness, &token).await;
    let (code, reason) = expect_close(&mut browser).await;
    assert_eq!(code, 4502);
    assert!(reason.contains("VM.Console"), "{reason}");
}

#[tokio::test]
async fn a_guest_that_stops_closes_the_console_cleanly() {
    let harness = harness(PERMISSIONS_FULL, Screen::ClosesAfterInit, None).await;
    let account = trusted_account(&harness).await;
    let (_, created) = create_session(&harness, &account).await;
    let token = created["data"]["token"].as_str().unwrap().to_owned();
    let mut browser = connect_browser(&harness, &token).await;
    browser_handshake(&mut browser).await;
    expect_binary(&mut browser, b"SERVERINIT").await;
    assert_eq!(expect_close(&mut browser).await.0, 1000);
    let events = console_events(&harness).await;
    let ended = events
        .iter()
        .find(|event| event["metadata"]["event"] == "proxmox_console_session_ended")
        .expect("an end event");
    assert_eq!(ended["metadata"]["reason"], "guest");
}

#[tokio::test]
async fn controller_shutdown_closes_every_console() {
    let harness = harness(PERMISSIONS_FULL, Screen::Open, None).await;
    let account = trusted_account(&harness).await;
    let (_, created) = create_session(&harness, &account).await;
    let token = created["data"]["token"].as_str().unwrap().to_owned();
    let mut browser = connect_browser(&harness, &token).await;
    browser_handshake(&mut browser).await;
    expect_binary(&mut browser, b"SERVERINIT").await;
    harness.proxmox.console_shutdown();
    assert_eq!(expect_close(&mut browser).await.0, 1001);
    let events = console_events(&harness).await;
    let ended = events
        .iter()
        .find(|event| event["metadata"]["event"] == "proxmox_console_session_ended")
        .expect("an end event");
    assert_eq!(ended["metadata"]["reason"], "shutdown");
}

#[tokio::test]
async fn the_idle_and_maximum_duration_bounds_close_the_console() {
    let idle = harness(
        PERMISSIONS_FULL,
        Screen::Open,
        Some(ConsoleLimits {
            idle: Duration::from_millis(400),
            max_duration: Duration::from_secs(60),
        }),
    )
    .await;
    let account = trusted_account(&idle).await;
    let (_, created) = create_session(&idle, &account).await;
    let token = created["data"]["token"].as_str().unwrap().to_owned();
    let mut browser = connect_browser(&idle, &token).await;
    browser_handshake(&mut browser).await;
    expect_binary(&mut browser, b"SERVERINIT").await;
    // A viewer's automatic update requests are not input: the console is
    // still idle and closes.
    browser
        .send(Message::Binary(
            vec![3_u8, 1, 0, 0, 0, 0, 3, 0x20, 2, 0x58].into(),
        ))
        .await
        .unwrap();
    assert_eq!(expect_close(&mut browser).await.0, 4408);

    let max = harness(
        PERMISSIONS_FULL,
        Screen::Open,
        Some(ConsoleLimits {
            idle: Duration::from_secs(60),
            max_duration: Duration::from_millis(400),
        }),
    )
    .await;
    let account = trusted_account(&max).await;
    let (_, created) = create_session(&max, &account).await;
    let token = created["data"]["token"].as_str().unwrap().to_owned();
    let mut browser = connect_browser(&max, &token).await;
    browser_handshake(&mut browser).await;
    expect_binary(&mut browser, b"SERVERINIT").await;
    assert_eq!(expect_close(&mut browser).await.0, 4410);
    let events = console_events(&max).await;
    let ended = events
        .iter()
        .find(|event| event["metadata"]["event"] == "proxmox_console_session_ended")
        .expect("an end event");
    assert_eq!(ended["metadata"]["reason"], "max_duration");
}

#[tokio::test]
async fn the_session_cap_refuses_a_fifth_session_for_one_principal() {
    let harness = harness(PERMISSIONS_FULL, Screen::Open, None).await;
    let account = trusted_account(&harness).await;
    for _ in 0..4 {
        let (status, body) = create_session(&harness, &account).await;
        assert_eq!(status, 201, "{body}");
    }
    let (status, body) = create_session(&harness, &account).await;
    assert_eq!(status, 409, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("too many console sessions")
    );
}

#[tokio::test]
async fn a_malformed_guest_is_a_bad_request_and_nothing_is_audited() {
    let harness = harness(PERMISSIONS_FULL, Screen::Open, None).await;
    let account = trusted_account(&harness).await;
    for body in [
        json!({"node": "../etc", "vmid": 101}),
        json!({"node": "pve-a", "vmid": 5}),
    ] {
        let (status, response) = raw(
            harness.address,
            "POST",
            &format!("/api/v1/proxmox/accounts/{account}/console-sessions"),
            Some(body),
        )
        .await;
        assert_eq!(status, 400, "{response}");
    }
    let (_, audit) = raw(
        harness.address,
        "GET",
        "/api/v1/audit?action=proxmox.console",
        None,
    )
    .await;
    assert!(audit["items"].as_array().unwrap().is_empty());
}

/// An authorizer that refuses `proxmox.console` and allows nothing else.
#[derive(Debug)]
struct NoConsole;

impl Authorizer for NoConsole {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::deny(ReasonId::ActionNotDelegated)
    }
}

#[tokio::test]
async fn creating_and_attaching_are_refused_without_the_console_permission() {
    let harness = harness(PERMISSIONS_FULL, Screen::Open, None).await;
    let account = trusted_account(&harness).await;
    let principal = ActingPrincipal {
        id: "restricted".to_owned(),
    };
    let denied = harness
        .proxmox
        .console_create(&NoConsole, &principal, &account, "pve-a", 101, 1)
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        matches!(
            denied,
            fleet_application::proxmox::ProxmoxUseCaseError::Denied(_)
        ),
        "{denied}"
    );
    // A token minted for an authorized caller is still refused at attach for
    // a caller who may not open screens, and the refusal spends it.
    let (_, created) = create_session(&harness, &account).await;
    let token = created["data"]["token"].as_str().unwrap().to_owned();
    let refused = harness
        .proxmox
        .console_attach(
            &NoConsole,
            &principal,
            &token,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        matches!(
            refused,
            fleet_application::proxmox::ProxmoxUseCaseError::Denied(_)
        ),
        "{refused}"
    );
    let spent = harness
        .proxmox
        .console_attach(
            harness_authorizer(),
            &ActingPrincipal {
                id: "someone".to_owned(),
            },
            &token,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        matches!(
            spent,
            fleet_application::proxmox::ProxmoxUseCaseError::NotFound { .. }
        ),
        "{spent}"
    );
}

#[derive(Debug)]
struct AllowAll;

impl Authorizer for AllowAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

fn harness_authorizer() -> &'static dyn Authorizer {
    &AllowAll
}

#[tokio::test]
async fn the_privilege_report_has_a_console_tier() {
    for (permissions, expected) in [
        (PERMISSIONS_FULL, "granted"),
        (PERMISSIONS_READONLY, "missing"),
    ] {
        let harness = harness(permissions, Screen::Open, None).await;
        let account = trusted_account(&harness).await;
        let (status, report) = raw(
            harness.address,
            "GET",
            &format!("/api/v1/proxmox/accounts/{account}/privileges"),
            None,
        )
        .await;
        assert_eq!(status, 200, "{report}");
        let console = report["data"]["tiers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tier| tier["tier"] == "console")
            .expect("a console tier");
        assert_eq!(console["status"], expected, "{console}");
        if expected == "missing" {
            assert_eq!(console["missing"][0]["privileges"], json!(["VM.Console"]));
            assert_eq!(console["missing"][0]["path"], "/vms/{vmid}");
        }
    }
}
