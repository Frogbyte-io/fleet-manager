//! The tailnet surface end to end: a real controller router, a secret
//! store, and a fake transport over recorded Tailscale fixtures — status,
//! configure, list with correlation, clear, and the import handoff.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::machine::MachinePort as _;
use fleet_controller::Settings;
use fleet_controller::build_router;
use fleet_controller::compose_onboarding;
use fleet_controller::tailnet_store::compose_tailnet;
use fleet_provider_tailscale::{HttpRequest, HttpResponse, TailscaleClient, Transport};
use fleet_secrets::SecretStore;
use fleet_storage_sqlite::{MachineRepository, Store};
use serde_json::{Value, json};
use tokio::net::TcpListener as TokioListener;

const TOKEN_BODY: &str = r#"{"access_token":"tskey-access-recorded","scope":"devices:core:read","token_type":"Bearer","expires_in":3600}"#;

const DEVICES_BODY: &str = r#"{"devices":[
  {"nodeId":"nVM","name":"fleet-test-01.tail-example.ts.net.","hostname":"fleet-test-01","os":"linux","addresses":["100.64.0.10"],"user":"user@example.com","online":true,"connectedToControl":true}
]}"#;

#[derive(Debug, Default)]
struct FixedTransport {
    responses: Mutex<Vec<HttpResponse>>,
    requests: Mutex<Vec<HttpRequest>>,
}

impl FixedTransport {
    fn new(token: HttpResponse, devices: HttpResponse) -> Arc<Self> {
        Arc::new(Self {
            responses: Mutex::new(vec![token, devices]),
            requests: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl Transport for FixedTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        let is_token = request.url.contains("/oauth/token");
        self.requests.lock().unwrap().push(request);
        let responses = self.responses.lock().unwrap();
        if is_token {
            return responses
                .first()
                .cloned()
                .ok_or_else(|| "no canned token".to_owned());
        }
        responses
            .last()
            .cloned()
            .ok_or_else(|| "no canned devices".to_owned())
    }
}

struct Harness {
    _dist: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _key_dir: tempfile::TempDir,
    address: std::net::SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

async fn harness() -> Harness {
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

    // A machine whose endpoint host matches the recorded device's address,
    // so correlation has something to find.
    let machines = MachineRepository::new(store.pool().clone());
    machines
        .register(&fleet_application::machine::RegisterMachine {
            name: "tailnet-target".to_owned(),
            description: String::new(),
            endpoints: vec![fleet_application::machine::NewEndpoint {
                kind: fleet_core::EndpointKind::Ssh,
                reference: "ops@100.64.0.10:22".to_owned(),
            }],
            tags: Vec::new(),
            groups: Vec::new(),
        })
        .await
        .unwrap();

    let onboarding = Arc::new(compose_onboarding(
        store.pool(),
        store_dir.path().join("ssh"),
    ));
    let machines_use_cases = Arc::new(fleet_application::machine::Machines::new(
        Arc::new(MachineRepository::new(store.pool().clone())),
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    ));
    let tailnet = Arc::new(compose_tailnet(
        secrets,
        Arc::new(TailscaleClient::new(FixedTransport::new(
            HttpResponse {
                status: 200,
                body: TOKEN_BODY.as_bytes().to_vec(),
                retry_after_secs: None,
            },
            HttpResponse {
                status: 200,
                body: DEVICES_BODY.as_bytes().to_vec(),
                retry_after_secs: None,
            },
        ))),
        onboarding,
        machines_use_cases,
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    ));

    let settings = Settings {
        listen: "127.0.0.1:0".parse().unwrap(),
        web_dist: dist.path().to_path_buf(),
        artifacts_dir: None,
    };
    let router = build_router(
        &settings,
        Some(store.pool().clone()),
        None,
        None,
        Some(&tailnet),
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
        shutdown: Some(shutdown_tx),
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

impl Harness {
    async fn get(&self, path: &str) -> (axum::http::StatusCode, Value) {
        raw(self.address, "GET", path, None).await
    }

    async fn post(&self, path: &str, body: Value) -> (axum::http::StatusCode, Value) {
        raw(self.address, "POST", path, Some(body)).await
    }

    async fn put(&self, path: &str, body: Value) -> (axum::http::StatusCode, Value) {
        raw(self.address, "PUT", path, Some(body)).await
    }

    async fn delete(&self, path: &str) -> (axum::http::StatusCode, Value) {
        raw(self.address, "DELETE", path, None).await
    }
}

/// One raw HTTP request over TCP; the test asserts on bodies, not clients.
async fn raw(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (axum::http::StatusCode, Value) {
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
        .map(axum::http::StatusCode::from_u16)
        .unwrap()
        .unwrap();
    let body = if rest.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(rest).unwrap_or(Value::Null)
    };
    (status, body)
}

#[tokio::test]
async fn the_tailnet_surface_walks_configure_list_and_import() {
    let harness = harness().await;

    // Unconfigured: the status answers, listing conflicts.
    let (status, body) = harness.get("/api/v1/tailnet/status").await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["data"]["configured"], false);
    assert_eq!(body["data"]["scope"], "devices:core:read");
    let (status, body) = harness.get("/api/v1/tailnet/devices").await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "tailscale_unconfigured");

    // Configure: the secret is accepted and never echoed.
    let (status, body) = harness
        .put(
            "/api/v1/tailnet/config",
            json!({"clientId": "k-client", "clientSecret": "tskey-client-secret-material"}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["data"]["configured"], true);
    assert_eq!(body["data"]["clientId"], "k-client");
    let rendered = body.to_string();
    assert!(
        !rendered.contains("tskey-client-secret-material"),
        "the secret is write-only: {rendered}"
    );

    // List: the recorded device, correlated with the matching machine.
    let (status, body) = harness.get("/api/v1/tailnet/devices").await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let device = &body["items"][0];
    assert_eq!(device["nodeId"], "nVM");
    assert_eq!(device["candidates"].as_array().unwrap().len(), 1);
    assert_eq!(device["candidates"][0]["machineName"], "tailnet-target");
    assert_eq!(device["candidates"][0]["kind"], "address_match");

    // Import: the draft carries the device's address and provenance.
    let (status, body) = harness
        .post(
            "/api/v1/tailnet/devices/nVM/import",
            json!({"user": "ops", "port": 22}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::CREATED, "{body}");
    assert_eq!(body["data"]["endpoint"]["host"], "100.64.0.10");
    assert!(
        body["data"]["description"]
            .as_str()
            .unwrap_or_default()
            .contains("nVM"),
        "the draft carries the device provenance: {body}"
    );

    // Clear: the integration is gone.
    let (status, body) = harness.delete("/api/v1/tailnet/config").await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["data"]["configured"], false);
}

#[tokio::test]
async fn a_malformed_configure_request_is_refused_publicly() {
    let harness = harness().await;
    let (status, body) = harness
        .put(
            "/api/v1/tailnet/config",
            json!({"clientId": "k", "clientSecret": "x".repeat(300)}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");
}

#[tokio::test]
async fn an_unknown_device_import_refuses_with_not_found() {
    let harness = harness().await;
    harness
        .put(
            "/api/v1/tailnet/config",
            json!({"clientId": "k-client", "clientSecret": "tskey-client-secret"}),
        )
        .await;
    let (status, body) = harness
        .post(
            "/api/v1/tailnet/devices/nMISSING/import",
            json!({"user": "ops"}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{body}");
}
