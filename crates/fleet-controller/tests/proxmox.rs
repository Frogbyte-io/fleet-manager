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
use fleet_storage_sqlite::{MachineRepository, Store};
use serde_json::{Value, json};
use tokio::net::TcpListener as TokioListener;

const VERSION_BODY: &str =
    r#"{"data":{"release":"9.2","version":"9.2.2","repoid":"b9984c6d90a4bd80"}}"#;

const RESOURCES_BODY: &str = r#"{"data":[
  {"id":"node/pve","type":"node","status":"online","maxcpu":16,"maxmem":67342831616},
  {"id":"qemu/100","type":"qemu","node":"pve","vmid":100,"name":"dev-01","status":"running","template":0},
  {"id":"qemu/101","type":"qemu","node":"pve","vmid":101,"name":"fleet-test-01","status":"running","template":0},
  {"id":"qemu/900","type":"qemu","vmid":900,"template":1,"status":"stopped"},
  {"id":"sdn/zone1","type":"sdn"}
]}"#;

const GUEST_CONFIG_BODY: &str = r#"{"data":{"name":"fleet-test-01","net0":"virtio=DE:AD:BE:EF:00:01,bridge=vmbr0","memory":2048}}"#;

const AGENT_INFO_BODY: &str = r#"{"data":{"result":{"version":"7.2"}}}"#;

const AGENT_NETWORK_BODY: &str = r#"{"data":{"result":[
  {"name":"ens18","hardware-address":"DE:AD:BE:EF:00:01","ip-addresses":[
    {"ip-address":"192.168.68.240","ip-address-type":"ipv4","prefix":24}]},
  {"name":"lo","hardware-address":"00:00:00:00:00:00","ip-addresses":[
    {"ip-address":"127.0.0.1","ip-address-type":"ipv4","prefix":8}]}
]}}"#;

const AGENT_OSINFO_BODY: &str = r#"{"data":{"result":{"pretty-name":"Ubuntu 24.04.4 LTS","kernel-release":"6.8.0-138-generic"}}}"#;

/// Per-guest fixtures keyed by VMID: each guest carries its own MAC and
/// IP, so an association can only come from that guest's own evidence.
const GUEST_100_CONFIG_BODY: &str =
    r#"{"data":{"name":"dev-01","net0":"virtio=DE:AD:BE:EF:00:09,bridge=vmbr0","memory":2048}}"#;

const AGENT_100_NETWORK_BODY: &str = r#"{"data":{"result":[
  {"name":"ens18","hardware-address":"DE:AD:BE:EF:00:09","ip-addresses":[
    {"ip-address":"192.168.68.241","ip-address-type":"ipv4","prefix":24}]}
]}}"#;

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
    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        _body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        // The canned fixtures answer by path regardless of the body: the
        // recorded responses are keyed on the endpoint, not the payload.
        self.execute(request).await
    }

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
                } else if request.path.contains("/qemu/100/config") {
                    GUEST_100_CONFIG_BODY
                } else if request.path.contains("/config") {
                    GUEST_CONFIG_BODY
                } else if request.path.contains("/agent/info") {
                    AGENT_INFO_BODY
                } else if request
                    .path
                    .contains("/qemu/100/agent/network-get-interfaces")
                {
                    AGENT_100_NETWORK_BODY
                } else if request.path.contains("/agent/network-get-interfaces") {
                    AGENT_NETWORK_BODY
                } else if request.path.contains("/agent/get-osinfo") {
                    AGENT_OSINFO_BODY
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
    pool: sqlx::SqlitePool,
    address: std::net::SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// The lifecycle harness's worker; aborted on drop.
    _worker: Option<tokio::task::JoinHandle<()>>,
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
        pool: store.pool().clone(),
        address,
        shutdown: Some(shutdown_tx),
        _worker: None,
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
    // Trust flows through observe: capture, then confirm what was seen.
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/observe"),
            json!({}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
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

#[tokio::test]
async fn the_guest_surface_walks_list_and_observe() {
    let harness = harness().await;

    // A machine whose endpoint host is the guest-agent address.
    let machines = MachineRepository::new(harness.pool.clone());
    use fleet_application::machine::MachinePort as _;
    let machine = machines
        .register(&fleet_application::machine::RegisterMachine {
            name: "fleet-test-01".to_owned(),
            description: String::new(),
            endpoints: vec![fleet_application::machine::NewEndpoint {
                kind: fleet_core::EndpointKind::Ssh,
                reference: "ops@192.168.68.240:22".to_owned(),
            }],
            tags: Vec::new(),
            groups: Vec::new(),
        })
        .await
        .unwrap();

    let (_, body) = harness
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
    let account_id = body["data"]["id"].as_str().unwrap().to_owned();
    harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/observe"),
            json!({}),
        )
        .await;
    harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/confirm"),
            json!({"fingerprint": FP}),
        )
        .await;

    // Guests list with the address-match candidate.
    let (status, body) = harness
        .get(&format!("/api/v1/proxmox/accounts/{account_id}/guests"))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    // Two guests: the template entry carries no node, so it is isolated
    // into the warnings honestly rather than guessed.
    let guests = body["items"].as_array().unwrap();
    assert_eq!(guests.len(), 2, "{body}");
    let guest = guests
        .iter()
        .find(|guest| guest["vmid"] == 101)
        .expect("the test guest lists");
    assert_eq!(guest["macs"][0], "de:ad:be:ef:00:01");
    assert_eq!(guest["agent"]["online"], true);
    assert_eq!(guest["agent"]["osName"], "Ubuntu 24.04.4 LTS");
    assert_eq!(guest["candidates"][0]["machineId"], machine.id);
    assert_eq!(guest["candidates"][0]["kind"], "address_match");
    // The other guest carries distinct evidence and no candidate: the
    // association provably comes from this guest's own facts.
    let other = guests
        .iter()
        .find(|guest| guest["vmid"] == 100)
        .expect("the other guest lists");
    assert_eq!(other["macs"][0], "de:ad:be:ef:00:09");
    assert_eq!(other["candidates"].as_array().unwrap().len(), 0);

    // Observe records the guest facts onto the machine.
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/guests/101/observe"),
            json!({"machineId": machine.id}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::NO_CONTENT, "{body}");

    // The machine now carries the guest facts.
    let (status, body) = harness
        .get(&format!("/api/v1/machines/{}", machine.id))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let capabilities = body["data"]["capabilities"].as_array().unwrap();
    let fact = |name: &str| {
        capabilities
            .iter()
            .find(|fact| fact["name"] == name)
            .map(|fact| fact["value"].clone())
    };
    assert_eq!(fact("guest"), Some(json!("qemu/101")));
    assert_eq!(fact("vmid"), Some(json!("101")));
    assert_eq!(fact("os"), Some(json!("Ubuntu 24.04.4 LTS")));
    assert_eq!(fact("mac0"), Some(json!("de:ad:be:ef:00:01")));
    assert_eq!(fact("agent"), Some(json!("7.2")));

    // An unknown guest refuses with not-found.
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/guests/999/observe"),
            json!({"machineId": machine.id}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["code"], "not_found");
}

const LIFECYCLE_UPID_BODY: &str =
    r#"{"data":"UPID:pve:0015523F:0C6DF532:6AAFE1EC:qmstart:101:root@pam!GLM-AGENT:"}"#;

const TASK_RUNNING_BODY: &str = r#"{"data":{"status":"running"}}"#;

const TASK_OK_BODY: &str = r#"{"data":{"status":"stopped","exitstatus":"OK"}}"#;

const TASK_ERROR_BODY: &str =
    r#"{"data":{"status":"stopped","exitstatus":"ERROR: start failed: KVM is not available"}}"#;

const SNAPSHOT_CREATE_BODY: &str =
    r#"{"data":"UPID:pve:0015523F:0C6DF532:6AAFE1EC:qmsnapshot:101:root@pam!GLM-AGENT:"}"#;

const SNAPSHOT_LIST_BODY: &str = r#"{"data":[
  {"name":"current","description":"","vmstate":0}
]}"#;

/// What the lifecycle fixture answers per poll.
#[derive(Debug, Clone, Copy)]
enum TaskOutcome {
    OkAfterOne,
    Error,
    AlwaysRunning,
}

#[derive(Debug)]
struct LifecycleTransport {
    outcome: TaskOutcome,
}

impl LifecycleTransport {
    fn with(outcome: TaskOutcome) -> Arc<Self> {
        Arc::new(Self { outcome })
    }
}

#[async_trait]
impl PveTransport for LifecycleTransport {
    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        _body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        self.execute(request).await
    }

    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        // The observe-only trust probe: capture and refuse.
        if request.pinned_fingerprint.is_none() {
            return Err(PveTransportError::ObserveRefused {
                observed: FP.to_owned(),
            });
        }
        if request.path.ends_with("/snapshot")
            && request.method == fleet_provider_proxmox::PveHttpMethod::Post
        {
            return Ok(PveHttpResponse {
                status: 200,
                body: SNAPSHOT_CREATE_BODY.as_bytes().to_vec(),
            });
        }
        if request.path.ends_with("/snapshot") {
            return Ok(PveHttpResponse {
                status: 200,
                body: SNAPSHOT_LIST_BODY.as_bytes().to_vec(),
            });
        }
        if request.path.contains("/status/start") {
            return Ok(PveHttpResponse {
                status: 200,
                body: LIFECYCLE_UPID_BODY.as_bytes().to_vec(),
            });
        }
        if request.path.contains("/tasks/") && request.path.contains("/status") {
            let body = match self.outcome {
                TaskOutcome::OkAfterOne => TASK_OK_BODY,
                TaskOutcome::Error => TASK_ERROR_BODY,
                TaskOutcome::AlwaysRunning => TASK_RUNNING_BODY,
            };
            return Ok(PveHttpResponse {
                status: 200,
                body: body.as_bytes().to_vec(),
            });
        }
        if request.path.contains("/version") {
            return Ok(PveHttpResponse {
                status: 200,
                body: VERSION_BODY.as_bytes().to_vec(),
            });
        }
        Err(PveTransportError::Connect {
            detail: format!("unexpected path {}", request.path),
        })
    }
}

async fn lifecycle_harness(outcome: TaskOutcome) -> Harness {
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
    // One shared transport: the HTTP surface and the worker see the same
    // fixture, so the test exercises one consistent PVE.
    let transport = LifecycleTransport::with(outcome);
    let proxmox = Arc::new(compose_proxmox(
        store.pool().clone(),
        secrets.clone(),
        transport.clone(),
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    ));

    // The worker runs the lifecycle executor against the same transport,
    // so the durable operation executes end to end in the test.
    let worker_operations = Arc::new(fleet_application::operation::Operations::new(
        Arc::new(fleet_storage_sqlite::OperationRepository::new(
            store.pool().clone(),
        )),
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    ));
    let accounts: Arc<dyn fleet_application::proxmox::ProxmoxAccountPort> = Arc::new(
        fleet_storage_sqlite::ProxmoxAccountRepository::new(store.pool().clone()),
    );
    let credentials: Arc<dyn fleet_application::proxmox::ProxmoxCredentialStore> =
        Arc::new(fleet_controller::proxmox_store::SecretBackedProxmoxCredentials::new(secrets));
    let executor = Arc::new(fleet_controller::proxmox_exec::ProxmoxDispatch::new(
        Arc::new(fleet_application::worker::NoopExecutor),
        Arc::new(
            fleet_controller::proxmox_exec::ProxmoxLifecycleExecutor::new(
                accounts.clone(),
                credentials.clone(),
                fleet_provider_proxmox::ProxmoxClient::new(transport.clone()),
            ),
        ),
        Arc::new(
            fleet_controller::proxmox_exec::ProxmoxDestructiveExecutor::new(
                accounts,
                credentials,
                fleet_provider_proxmox::ProxmoxClient::new(transport),
            ),
        ),
    ));
    let worker_host = fleet_controller::worker::WorkerHost::new(worker_operations, executor, 4);
    // The shutdown future must never resolve while the test runs: an
    // immediately-ready `async {}` would drain the worker on the first
    // tick.
    let _worker_handle = tokio::spawn(async move {
        worker_host.run(std::future::pending::<()>()).await;
    });

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
        pool: store.pool().clone(),
        address,
        shutdown: Some(shutdown_tx),
        _worker: None,
    }
}

/// The setup shared by the lifecycle tests: a trusted account.
async fn trusted_account(harness: &Harness) -> String {
    let (_, body) = harness
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
    let account_id = body["data"]["id"].as_str().unwrap().to_owned();
    let (status, _) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/observe"),
            json!({}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "observe must answer");
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/confirm"),
            json!({"fingerprint": FP}),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "confirm must answer: {body}"
    );
    account_id
}

#[tokio::test]
async fn a_lifecycle_operation_runs_to_task_ok() {
    let harness = lifecycle_harness(TaskOutcome::OkAfterOne).await;
    let account_id = trusted_account(&harness).await;
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/guests/101/start"),
            json!({"node": "pve", "vmid": 101, "timeoutSeconds": 30}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");
    let operation_id = body["data"]["id"].as_str().unwrap().to_owned();
    eprintln!("created operation {operation_id}");

    // The worker picks it up; wait for the terminal state.
    let mut terminal = String::new();
    for _ in 0..50 {
        let (_, body) = harness
            .get(&format!("/api/v1/operations/{operation_id}"))
            .await;
        terminal = body["data"]["state"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if terminal == "succeeded" || terminal == "failed" {
            eprintln!("terminal {terminal}: {body}");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(terminal, "succeeded", "terminal={terminal} body={body}");
    let (_, body) = harness
        .get(&format!("/api/v1/operations/{operation_id}"))
        .await;
    let result: Value = serde_json::from_str(body["data"]["resultJson"].as_str().unwrap())
        .expect("the result is JSON");
    assert_eq!(result["taskState"], "ok", "{body}");
}

#[tokio::test]
async fn a_failing_task_fails_the_operation_with_the_detail() {
    let harness = lifecycle_harness(TaskOutcome::Error).await;
    let account_id = trusted_account(&harness).await;
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/guests/101/start"),
            json!({"node": "pve", "vmid": 101, "timeoutSeconds": 30}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");
    let operation_id = body["data"]["id"].as_str().unwrap().to_owned();
    let mut terminal = String::new();
    let mut error_detail = String::new();
    for _ in 0..50 {
        let (_, body) = harness
            .get(&format!("/api/v1/operations/{operation_id}"))
            .await;
        terminal = body["data"]["state"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if terminal == "succeeded" || terminal == "failed" {
            // The error detail rides the operation's errorJson string.
            if let Some(error_json) = body["data"]["errorJson"].as_str() {
                let parsed: Value = serde_json::from_str(error_json).unwrap_or(Value::Null);
                error_detail = parsed["detail"].as_str().unwrap_or_default().to_owned();
            }
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(terminal, "failed");
    assert!(
        error_detail.contains("KVM is not available"),
        "{error_detail}"
    );
}

#[tokio::test]
async fn a_deadline_expiry_fails_honestly_naming_the_uncertainty() {
    let harness = lifecycle_harness(TaskOutcome::AlwaysRunning).await;
    let account_id = trusted_account(&harness).await;
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/guests/101/start"),
            // A 1-second deadline: the poll loop expires while the task
            // still runs.
            json!({"node": "pve", "vmid": 101, "timeoutSeconds": 1}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");
    let operation_id = body["data"]["id"].as_str().unwrap().to_owned();
    let mut terminal = String::new();
    let mut error_detail = String::new();
    for _ in 0..100 {
        let (_, body) = harness
            .get(&format!("/api/v1/operations/{operation_id}"))
            .await;
        terminal = body["data"]["state"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if terminal == "succeeded" || terminal == "failed" {
            if let Some(error_json) = body["data"]["errorJson"].as_str() {
                let parsed: Value = serde_json::from_str(error_json).unwrap_or(Value::Null);
                error_detail = parsed["detail"].as_str().unwrap_or_default().to_owned();
            }
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(terminal, "failed");
    assert!(
        error_detail.contains("final state is unknown"),
        "{error_detail}"
    );
}

#[tokio::test]
async fn an_unrecognized_action_refuses_with_invalid_request() {
    let harness = lifecycle_harness(TaskOutcome::OkAfterOne).await;
    let account_id = trusted_account(&harness).await;
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/guests/101/destroy"),
            json!({"node": "pve", "vmid": 101, "timeoutSeconds": 30}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");
}

#[tokio::test]
async fn a_destructive_operation_requires_the_review_token_and_runs() {
    let harness = lifecycle_harness(TaskOutcome::OkAfterOne).await;
    let account_id = trusted_account(&harness).await;

    // The create without a review token is refused.
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/guests/101/snapshot/run"),
            json!({
                "node": "pve",
                "reviewToken": "not-the-token",
                "params": {"snapshot": "demo-snap", "description": "demo"},
                "timeoutSeconds": 30
            }),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");

    // The review renders exactly what will run and returns the token.
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/guests/101/snapshot/review"),
            json!({
                "node": "pve",
                "params": {"snapshot": "demo-snap", "description": "demo"}
            }),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["data"]["action"], "snapshot");
    assert_eq!(body["data"]["vmid"], 101);
    let token = body["data"]["reviewToken"].as_str().unwrap().to_owned();

    // The create with the token is accepted and runs to task OK.
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/guests/101/snapshot/run"),
            json!({
                "node": "pve",
                "reviewToken": token,
                "params": {"snapshot": "demo-snap", "description": "demo"},
                "timeoutSeconds": 30
            }),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");
    let operation_id = body["data"]["id"].as_str().unwrap().to_owned();
    let mut terminal = String::new();
    for _ in 0..50 {
        let (_, body) = harness
            .get(&format!("/api/v1/operations/{operation_id}"))
            .await;
        terminal = body["data"]["state"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if terminal == "succeeded" || terminal == "failed" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(terminal, "succeeded", "{body}");
}

#[tokio::test]
async fn a_tampered_review_payload_is_refused() {
    let harness = lifecycle_harness(TaskOutcome::OkAfterOne).await;
    let account_id = trusted_account(&harness).await;

    // Review one payload...
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/guests/101/snapshot/review"),
            json!({
                "node": "pve",
                "params": {"snapshot": "demo-snap", "description": "demo"}
            }),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let token = body["data"]["reviewToken"].as_str().unwrap().to_owned();

    // ...then try to run a DIFFERENT one with the same token: refused.
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/guests/101/snapshot/run"),
            json!({
                "node": "pve",
                "reviewToken": token,
                "params": {"snapshot": "OTHER-snap", "description": "demo"},
                "timeoutSeconds": 30
            }),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");
}
