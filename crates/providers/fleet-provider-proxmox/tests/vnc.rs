//! The PVE VNC console channel (FM-495): the `vncproxy` contract on recorded
//! PVE 8.x and 9.x answers, and the pinned WebSocket with the RFB
//! authentication against a local TLS WebSocket server shaped like
//! pveproxy's `vncwebsocket`. The live variant runs only with
//! `FLEET_PVE_LIVE=1` and a scratch guest.

#![allow(clippy::too_many_lines, clippy::result_large_err)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_core::SensitiveString;
use fleet_provider_proxmox::{
    ProxmoxClient, PveApiError, PveCredentials, PveHttpMethod, PveHttpRequest, PveHttpResponse,
    PveSocket, PveTransport, PveTransportError, ReqwestPveTransport, vnc_auth_response,
};
use futures_util::{SinkExt as _, StreamExt as _};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::Digest as _;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};

const TOKEN_ID: &str = "fleet@pve!contract";
const TOKEN_SECRET: &str = "00000000-0000-4000-8000-000000000000";

#[derive(Clone, Copy)]
enum Behavior {
    /// Authenticate the client, then serve one message.
    Serve,
    /// Refuse the VNC authentication (wrong one-time password).
    RejectPassword,
    /// Refuse the upgrade with this HTTP status.
    Status(u16),
}

struct Server {
    port: u16,
    fingerprint: String,
    /// The path and query of every upgrade request.
    paths: Arc<Mutex<Vec<String>>>,
    /// What the client sent after authentication.
    received: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// A TLS WebSocket server on loopback. `password` is the one-time VNC
/// password the fake `vncproxy` answer carries.
async fn serve(password: &'static str, behavior: Behavior) -> Server {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let der = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let fingerprint = sha2::Sha256::digest(der.as_ref())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![der], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let paths = Arc::new(Mutex::new(Vec::new()));
    let received = Arc::new(Mutex::new(Vec::new()));
    let (paths_in, received_in) = (Arc::clone(&paths), Arc::clone(&received));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let paths = Arc::clone(&paths_in);
            let received = Arc::clone(&received_in);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let callback = |request: &Request, mut response: Response| {
                    paths
                        .lock()
                        .unwrap()
                        .push(request.uri().path_and_query().unwrap().to_string());
                    if let Behavior::Status(status) = behavior {
                        let mut error = ErrorResponse::new(None);
                        *error.status_mut() = StatusCode::from_u16(status).unwrap();
                        return Err(error);
                    }
                    let expected = format!("PVEAPIToken={TOKEN_ID}={TOKEN_SECRET}");
                    let authorized = request
                        .headers()
                        .get("authorization")
                        .is_some_and(|value| value.as_bytes() == expected.as_bytes());
                    if !authorized {
                        let mut error = ErrorResponse::new(None);
                        *error.status_mut() = StatusCode::UNAUTHORIZED;
                        return Err(error);
                    }
                    response
                        .headers_mut()
                        .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("binary"));
                    Ok(response)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(tls, callback).await else {
                    return;
                };
                // RFB 3.8, VNC authentication.
                ws.send(Message::Binary(b"RFB 003.008\n".to_vec().into()))
                    .await
                    .unwrap();
                let version = next_binary(&mut ws).await;
                assert_eq!(version, b"RFB 003.008\n");
                ws.send(Message::Binary(vec![1_u8, 2].into()))
                    .await
                    .unwrap();
                assert_eq!(next_binary(&mut ws).await, [2]);
                let challenge: [u8; 16] = *b"0123456789abcdef";
                ws.send(Message::Binary(challenge.to_vec().into()))
                    .await
                    .unwrap();
                let response = next_binary(&mut ws).await;
                let ok = response == vnc_auth_response(password, &challenge);
                let verdict: [u8; 4] = if ok && !matches!(behavior, Behavior::RejectPassword) {
                    [0, 0, 0, 0]
                } else {
                    [0, 0, 0, 1]
                };
                ws.send(Message::Binary(verdict.to_vec().into()))
                    .await
                    .unwrap();
                if verdict != [0, 0, 0, 0] {
                    return;
                }
                // One screen message out, then record what the client sends.
                ws.send(Message::Binary(b"SERVERINIT".to_vec().into()))
                    .await
                    .unwrap();
                while let Some(Ok(message)) = ws.next().await {
                    if let Message::Binary(bytes) = message {
                        received.lock().unwrap().push(bytes.to_vec());
                    }
                }
            });
        }
    });
    Server {
        port,
        fingerprint,
        paths,
        received,
    }
}

async fn next_binary<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> Vec<u8>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        if let Message::Binary(bytes) = ws.next().await.unwrap().unwrap() {
            return bytes.to_vec();
        }
    }
}

/// The recorded `vncproxy` answer for the call; the WebSocket goes to the
/// real pinned transport.
#[derive(Debug)]
struct FixtureTransport {
    real: ReqwestPveTransport,
    answer: &'static str,
    /// Method, path and JSON body of every API call.
    calls: Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl PveTransport for FixtureTransport {
    async fn execute(
        &self,
        _request: PveHttpRequest,
    ) -> Result<PveHttpResponse, PveTransportError> {
        Err(PveTransportError::Connect {
            detail: "unexpected plain call".to_owned(),
        })
    }

    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        assert_eq!(request.method, PveHttpMethod::Post);
        self.calls
            .lock()
            .unwrap()
            .push((request.path.clone(), String::from_utf8(body).unwrap()));
        Ok(PveHttpResponse {
            status: 200,
            body: self.answer.as_bytes().to_vec(),
        })
    }

    async fn connect_websocket(
        &self,
        request: PveHttpRequest,
    ) -> Result<Box<dyn PveSocket>, PveTransportError> {
        self.real.connect_websocket(request).await
    }
}

fn request(server: &Server, secret: &str, fingerprint: &str) -> PveHttpRequest {
    PveHttpRequest {
        host: "127.0.0.1".to_owned(),
        port: server.port,
        path: "/api2/json/version".to_owned(),
        pinned_fingerprint: Some(fingerprint.to_owned()),
        credentials: Arc::new(PveCredentials {
            token_id: TOKEN_ID.to_owned(),
            token: SensitiveString::new(secret.to_owned()),
        }),
        method: PveHttpMethod::Get,
    }
}

fn client(answer: &'static str) -> (ProxmoxClient, Arc<FixtureTransport>) {
    let transport = Arc::new(FixtureTransport {
        real: ReqwestPveTransport::new(),
        answer,
        calls: Mutex::new(Vec::new()),
    });
    (ProxmoxClient::new(transport.clone()), transport)
}

const PVE9_ANSWER: &str = include_str!("fixtures/pve9/contract-vncproxy.json");
const PVE8_ANSWER: &str = include_str!("fixtures/pve8/contract-vncproxy.json");

async fn connects_and_relays(answer: &'static str, password: &'static str) {
    let server = serve(password, Behavior::Serve).await;
    let (client, transport) = client(answer);
    let mut socket = client
        .vnc_connect(
            request(&server, TOKEN_SECRET, &server.fingerprint),
            "pve-a",
            101,
        )
        .await
        .expect("the console opens");

    // The first message after the controller-side VNC authentication is the
    // screen's own; the one-time password never reached the caller.
    assert_eq!(socket.recv().await.unwrap().unwrap(), b"SERVERINIT");
    socket.send(b"CLIENTINIT".to_vec()).await.unwrap();
    socket.close().await;

    let calls = transport.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "/api2/json/nodes/pve-a/qemu/101/vncproxy");
    let body: serde_json::Value = serde_json::from_str(&calls[0].1).unwrap();
    assert_eq!(body["websocket"], 1);
    assert_eq!(body["generate-password"], 1);

    let paths = server.paths.lock().unwrap().clone();
    assert_eq!(paths.len(), 1);
    assert!(
        paths[0].starts_with("/api2/json/nodes/pve-a/qemu/101/vncwebsocket?port=59"),
        "{}",
        paths[0]
    );
    assert!(
        paths[0].contains("&vncticket=PVEVNC%3A"),
        "the ticket is percent-encoded in the query: {}",
        paths[0]
    );
    // The server saw exactly the message the caller sent after the handshake.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        server.received.lock().unwrap().clone(),
        vec![b"CLIENTINIT".to_vec()]
    );
}

#[tokio::test]
async fn the_pve9_vncproxy_answer_opens_an_authenticated_console() {
    connects_and_relays(PVE9_ANSWER, "Zx3QpL9w").await;
}

#[tokio::test]
async fn the_pve8_vncproxy_answer_opens_an_authenticated_console() {
    connects_and_relays(PVE8_ANSWER, "k7Hn2VdR").await;
}

#[tokio::test]
async fn a_refused_vnc_password_is_an_error_not_a_screen() {
    let server = serve("Zx3QpL9w", Behavior::RejectPassword).await;
    let (client, _) = client(PVE9_ANSWER);
    let error = client
        .vnc_connect(
            request(&server, TOKEN_SECRET, &server.fingerprint),
            "pve-a",
            101,
        )
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        matches!(&error, PveApiError::InvalidPayload { detail } if detail.contains("password")),
        "{error}"
    );
    assert!(!error.to_string().contains("Zx3QpL9w"));
}

#[tokio::test]
async fn the_websocket_uses_the_pinned_fingerprint() {
    let server = serve("Zx3QpL9w", Behavior::Serve).await;
    let (client, _) = client(PVE9_ANSWER);
    let error = client
        .vnc_connect(
            request(&server, TOKEN_SECRET, &"00".repeat(32)),
            "pve-a",
            101,
        )
        .await
        .map(|_| ())
        .unwrap_err();
    match error {
        PveApiError::Transport(PveTransportError::FingerprintMismatch { observed, pinned }) => {
            assert_eq!(observed, server.fingerprint);
            assert_eq!(pinned, Some("00".repeat(32)));
        }
        other => panic!("expected a fingerprint mismatch, got {other}"),
    }
    assert!(
        server.paths.lock().unwrap().is_empty(),
        "no upgrade request was sent over an unpinned connection"
    );
}

#[tokio::test]
async fn a_wrong_token_and_a_missing_privilege_are_told_apart() {
    let server = serve("Zx3QpL9w", Behavior::Serve).await;
    let (client, _) = client(PVE9_ANSWER);
    let error = client
        .vnc_connect(
            request(&server, "wrong-secret", &server.fingerprint),
            "pve-a",
            101,
        )
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(error, PveApiError::Auth), "{error}");

    let forbidden = serve("Zx3QpL9w", Behavior::Status(403)).await;
    let error = client
        .vnc_connect(
            request(&forbidden, TOKEN_SECRET, &forbidden.fingerprint),
            "pve-a",
            101,
        )
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        matches!(&error, PveApiError::Forbidden { detail } if detail.contains("VM.Console")),
        "{error}"
    );
}

#[tokio::test]
async fn a_vncproxy_answer_without_a_password_is_refused() {
    let server = serve("Zx3QpL9w", Behavior::Serve).await;
    let (client, _) = client(r#"{"data":{"port":"5900","ticket":"PVEVNC:x"}}"#);
    let error = client
        .vnc_connect(
            request(&server, TOKEN_SECRET, &server.fingerprint),
            "pve-a",
            101,
        )
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        matches!(error, PveApiError::InvalidPayload { .. }),
        "{error}"
    );
}

/// Live: opens a scratch guest's console through a real PVE host and reads
/// the RFB `ServerInit` (framebuffer size and name). Needs
/// `FLEET_PVE_LIVE=1`, `PROXMOX_*`, and `PROXMOX_VNC_NODE`/`PROXMOX_VNC_VMID`
/// naming a running scratch guest; the token needs `VM.Console` on it.
#[tokio::test]
async fn live_console_reaches_the_guest_screen() {
    if std::env::var("FLEET_PVE_LIVE").ok().as_deref() != Some("1") {
        return;
    }
    let Ok(node) = std::env::var("PROXMOX_VNC_NODE") else {
        return;
    };
    let vmid: u32 = std::env::var("PROXMOX_VNC_VMID")
        .expect("PROXMOX_VNC_VMID")
        .parse()
        .unwrap();
    let request = PveHttpRequest {
        host: std::env::var("PROXMOX_HOST").unwrap(),
        port: std::env::var("PROXMOX_PORT")
            .unwrap_or_else(|_| "8006".to_owned())
            .parse()
            .unwrap(),
        path: "/api2/json/version".to_owned(),
        pinned_fingerprint: Some(std::env::var("PROXMOX_FINGERPRINT").unwrap()),
        credentials: Arc::new(PveCredentials {
            token_id: std::env::var("PROXMOX_TOKEN_ID").unwrap(),
            token: SensitiveString::new(std::env::var("PROXMOX_API_KEY").unwrap()),
        }),
        method: PveHttpMethod::Get,
    };
    let client = ProxmoxClient::new(Arc::new(ReqwestPveTransport::new()));
    let mut socket = client.vnc_connect(request, &node, vmid).await.unwrap();
    // ClientInit (shared), then ServerInit: width, height, pixel format,
    // name length, name.
    socket.send(vec![1]).await.unwrap();
    let mut init = Vec::new();
    while init.len() < 24 {
        init.extend(socket.recv().await.unwrap().expect("ServerInit"));
    }
    let width = u16::from_be_bytes([init[0], init[1]]);
    let height = u16::from_be_bytes([init[2], init[3]]);
    assert!(width > 0 && height > 0, "{width}x{height}");
    eprintln!("live console: framebuffer {width}x{height}");
    socket.close().await;
}
