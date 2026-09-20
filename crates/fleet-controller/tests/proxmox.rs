//! The Proxmox surface end to end: a real controller router, a secret
//! store, and a fake provider transport over recorded PVE fixtures —
//! create, observe, confirm, discover, and delete, with the trust gate
//! enforced at the surface.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_controller::Settings;
use fleet_controller::build_router;
use fleet_controller::proxmox_store::compose_proxmox;
use fleet_provider_proxmox::{PveHttpRequest, PveHttpResponse, PveTransport, PveTransportError};
use fleet_secrets::SecretStore;
use fleet_storage_sqlite::Store;
use serde_json::{Value, json};
use tokio::net::TcpListener as TokioListener;

const VERSION_BODY: &str =
    r#"{"data":{"release":"9.2","version":"9.2.2","repoid":"b9984c6d90a4bd80"}}"#;

const RESOURCES_BODY: &str = r#"{"data":[
  {"id":"node/pve","type":"node","status":"online","maxcpu":16,"maxmem":67342831616},
  {"id":"qemu/100","type":"qemu","node":"pve","vmid":100,"name":"dev-01","status":"running","template":0},
  {"id":"qemu/101","type":"qemu","node":"pve","vmid":101,"name":"fleet-test-01","status":"stopped","template":0},
  {"id":"qemu/900","type":"qemu","vmid":900,"template":1,"status":"stopped"},
  {"id":"sdn/zone1","type":"sdn"}
]}"#;

/// The pinned fingerprint the fake transport accepts.
const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";

#[derive(Debug)]
struct FixedTransport {
    behavior: Mutex<Behavior>,
}

#[derive(Debug, Clone, Copy)]
enum Behavior {
    /// Observe captures the fingerprint and refuses; pinned calls succeed.
    Normal,
    /// Pinned calls report a fingerprint mismatch with the observed value.
    Mismatch,
}

impl FixedTransport {
    fn normal() -> Arc<Self> {
        Arc::new(Self {
            behavior: Mutex::new(Behavior::Normal),
        })
    }

    fn mismatch() -> Arc<Self> {
        Arc::new(Self {
            behavior: Mutex::new(Behavior::Mismatch),
        })
    }
}

#[async_trait]
impl PveTransport for FixedTransport {
    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        let behavior = *self.behavior.lock().unwrap();
        match (&request.pinned_fingerprint, behavior) {
            (None, _) => Err(PveTransportError::ObserveRefused {
                observed: FP.to_owned(),
            }),
            (Some(pinned), Behavior::Mismatch) => Err(PveTransportError::FingerprintMismatch {
                observed: "AA:".repeat(31) + "AA",
                pinned: Some(pinned.clone()),
            }),
            (Some(_), Behavior::Normal) => {
                let body = if request.path.contains("/version") {
                    VERSION_BODY
                } else {
                    RESOURCES_BODY
                };
                Ok(PveHttpResponse {
                    status: 200,
                    body: body.as_bytes().to_vec(),
                })
            }
        }
    }
}

struct Harness {
    _dist: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _key_dir: tempfile::TempDir,
    address: std::net::SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

async fn harness_with(transport: Arc<FixedTransport>) -> Harness {
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
    let proxmox = Arc::new(compose_proxmox(
        store.pool().clone(),
        secrets,
        transport,
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
        None,
        None,
        Some(&proxmox),
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

async fn harness() -> Harness {
    harness_with(FixedTransport::normal()).await
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
async fn the_proxmox_surface_walks_create_observe_confirm_discover_delete() {
    let harness = harness().await;

    // Empty at first.
    let (status, body) = harness.get("/api/v1/proxmox/accounts").await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["items"].as_array().unwrap().len(), 0);

    // Create: the secret is accepted and never echoed.
    let (status, body) = harness
        .post(
            "/api/v1/proxmox/accounts",
            json!({
                "name": "pve-main",
                "host": "192.168.68.223",
                "port": 8006,
                "tokenId": "root@pam!GLM-AGENT",
                "tokenSecret": "the-token-secret-material"
            }),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::CREATED, "{body}");
    assert_eq!(body["data"]["fingerprintState"], "unconfirmed");
    let rendered = body.to_string();
    assert!(
        !rendered.contains("the-token-secret-material"),
        "the secret is write-only: {rendered}"
    );
    let account_id = body["data"]["id"].as_str().unwrap().to_owned();

    // Discovery is locked before trust.
    let (status, body) = harness
        .get(&format!("/api/v1/proxmox/accounts/{account_id}/discovery"))
        .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "proxmox_unconfirmed");

    // Observe: the fingerprint arrives; no credential is ever sent.
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/observe"),
            json!({}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["data"]["fingerprint"], FP);

    // Confirm: trust is pinned.
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/confirm"),
            json!({"fingerprint": FP}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["data"]["fingerprintState"], "confirmed");

    // Discover: the normalized snapshot, sdn isolated as a warning-free skip.
    let (status, body) = harness
        .get(&format!("/api/v1/proxmox/accounts/{account_id}/discovery"))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["data"]["pveVersion"], "9.2.2");
    let resources = body["data"]["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 4, "{body}");
    assert!(
        resources
            .iter()
            .any(|resource| resource["kind"] == "qemu-template" && resource["vmid"] == 900)
    );
    assert!(
        resources.iter().all(|resource| resource["kind"] != "sdn"),
        "non-resource types are skipped, not coerced"
    );
    assert_eq!(body["data"]["reportedCount"], 5);

    // Delete: the account and its secret are gone.
    let (status, _) = harness
        .delete(&format!("/api/v1/proxmox/accounts/{account_id}"))
        .await;
    assert_eq!(status, axum::http::StatusCode::NO_CONTENT);
    let (status, body) = harness.get("/api/v1/proxmox/accounts").await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn a_mismatched_fingerprint_is_reported_with_both_values() {
    let harness = harness_with(FixedTransport::mismatch()).await;
    let (status, body) = harness
        .post(
            "/api/v1/proxmox/accounts",
            json!({
                "name": "pve-main",
                "host": "192.168.68.223",
                "tokenId": "root@pam!GLM-AGENT",
                "tokenSecret": "the-token-secret-material"
            }),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::CREATED, "{body}");
    let account_id = body["data"]["id"].as_str().unwrap().to_owned();
    harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/confirm"),
            json!({"fingerprint": FP}),
        )
        .await;
    let (status, body) = harness
        .get(&format!("/api/v1/proxmox/accounts/{account_id}/discovery"))
        .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "proxmox_fingerprint_mismatch");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(message.contains("AA:"), "{message}");
    assert!(message.contains("DC2C"), "{message}");
}

#[tokio::test]
async fn a_malformed_create_request_is_refused_publicly() {
    let harness = harness().await;
    let (status, body) = harness
        .post(
            "/api/v1/proxmox/accounts",
            json!({
                "name": "pve-main",
                "host": "https://192.168.68.223",
                "tokenId": "root@pam!GLM-AGENT",
                "tokenSecret": "the-token-secret-material"
            }),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");

    // A URL-shaped host is refused: the host is a bare host or IP.
    let (status, body) = harness
        .post(
            "/api/v1/proxmox/accounts",
            json!({
                "name": "pve-main",
                "host": "192.168.68.223",
                "tokenId": "not-a-token-id",
                "tokenSecret": "the-token-secret-material"
            }),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");
}

#[tokio::test]
async fn a_duplicate_account_name_conflicts() {
    let harness = harness().await;
    let payload = json!({
        "name": "pve-main",
        "host": "192.168.68.223",
        "tokenId": "root@pam!GLM-AGENT",
        "tokenSecret": "the-token-secret-material"
    });
    let (status, _) = harness
        .post("/api/v1/proxmox/accounts", payload.clone())
        .await;
    assert_eq!(status, axum::http::StatusCode::CREATED);
    let (status, body) = harness.post("/api/v1/proxmox/accounts", payload).await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "conflict");
}

#[tokio::test]
async fn an_unknown_account_refuses_with_not_found() {
    let harness = harness().await;
    let (status, body) = harness
        .get("/api/v1/proxmox/accounts/acc-missing/discovery")
        .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["code"], "not_found");
    let (status, _) = harness.delete("/api/v1/proxmox/accounts/acc-missing").await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}
