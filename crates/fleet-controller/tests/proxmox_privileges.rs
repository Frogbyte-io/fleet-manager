//! The Proxmox privilege diagnostics surface end to end (FM-604): a real
//! controller router and secret store over a fake PVE transport answering
//! recorded-shape 8.x and 9.x `/access/permissions` fixtures. The trust gate
//! holds (no credential leaves before the fingerprint is confirmed), the
//! tiers come back per major, and a refused permissions read is `unknown`.

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

const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";
const SECRET: &str = "the-token-secret-material";

#[derive(Debug)]
struct PermissionsTransport {
    version: &'static str,
    permissions: (u16, &'static str),
    /// Every credential-carrying request path, for the trust-gate check.
    pinned_requests: Mutex<Vec<String>>,
}

impl PermissionsTransport {
    fn new(version: &'static str, status: u16, body: &'static str) -> Arc<Self> {
        Arc::new(Self {
            version,
            permissions: (status, body),
            pinned_requests: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl PveTransport for PermissionsTransport {
    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        let Some(pinned) = &request.pinned_fingerprint else {
            // The observe probe: capture and refuse, as the real policy does.
            return Err(PveTransportError::ObserveRefused {
                observed: FP.to_owned(),
            });
        };
        assert_eq!(pinned, FP);
        self.pinned_requests
            .lock()
            .unwrap()
            .push(request.path.clone());
        let (status, body) = match request.path.as_str() {
            "/api2/json/version" => (200, self.version),
            "/api2/json/access/permissions" => self.permissions,
            other => panic!("the privileges read called {other}"),
        };
        Ok(PveHttpResponse {
            status,
            body: body.as_bytes().to_vec(),
        })
    }

    async fn execute_with_body(
        &self,
        _request: PveHttpRequest,
        _body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        panic!("the privileges read never sends a body");
    }
}

struct Harness {
    _dist: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _key_dir: tempfile::TempDir,
    address: std::net::SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

async fn harness(transport: Arc<PermissionsTransport>) -> Harness {
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
        address,
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
    (status, serde_json::from_str(rest).unwrap_or(Value::Null))
}

async fn create_account(harness: &Harness) -> String {
    let (status, body) = raw(
        harness.address,
        "POST",
        "/api/v1/proxmox/accounts",
        Some(json!({
            "name": "pve-main",
            "host": "192.0.2.10",
            "port": 8006,
            "tokenId": "fleet@pve!fleet",
            "tokenSecret": SECRET
        })),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    body["data"]["id"].as_str().unwrap().to_owned()
}

async fn trust(harness: &Harness, account_id: &str) {
    let (status, body) = raw(
        harness.address,
        "POST",
        &format!("/api/v1/proxmox/accounts/{account_id}/observe"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = raw(
        harness.address,
        "POST",
        &format!("/api/v1/proxmox/accounts/{account_id}/confirm"),
        Some(json!({"fingerprint": FP})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
}

async fn privileges(harness: &Harness, account_id: &str) -> (u16, Value) {
    raw(
        harness.address,
        "GET",
        &format!("/api/v1/proxmox/accounts/{account_id}/privileges"),
        None,
    )
    .await
}

fn tier<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["data"]["tiers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tier| tier["tier"] == name)
        .unwrap()
}

const VERSION_9: &str =
    include_str!("../../providers/fleet-provider-proxmox/tests/fixtures/pve9/version.json");
const VERSION_8: &str =
    include_str!("../../providers/fleet-provider-proxmox/tests/fixtures/pve8/version.json");

#[tokio::test]
async fn the_trust_gate_holds_and_a_pool_scoped_9x_token_is_granted_every_tier() {
    let transport = PermissionsTransport::new(
        VERSION_9,
        200,
        include_str!(
            "../../providers/fleet-provider-proxmox/tests/fixtures/pve9/access-permissions-pool-scoped.json"
        ),
    );
    let harness = harness(transport.clone()).await;
    let account_id = create_account(&harness).await;

    // Before the fingerprint is confirmed, no credential-carrying call goes out.
    let (status, body) = privileges(&harness, &account_id).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["code"], "proxmox_unconfirmed");
    assert!(transport.pinned_requests.lock().unwrap().is_empty());

    trust(&harness, &account_id).await;
    let (status, body) = privileges(&harness, &account_id).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["pveVersion"], "9.2.2");
    assert_eq!(body["data"]["rulesMajor"], 9);
    for name in ["discover", "operate", "destructive", "lab"] {
        assert_eq!(tier(&body, name)["status"], "granted", "{name}: {body}");
    }
    let lab = tier(&body, "lab");
    let target = lab["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["requirement"] == "lab.provision.clone-target")
        .unwrap();
    assert_eq!(target["path"], "/vms/{newid}");
    assert!(
        target["grantedOn"]
            .as_array()
            .unwrap()
            .contains(&json!("/vms/9000"))
    );
    assert!(body["data"]["effectivePermissions"]["/pool/fleet"].is_object());
    assert!(!body.to_string().contains(SECRET));
    assert_eq!(
        *transport.pinned_requests.lock().unwrap(),
        ["/api2/json/version", "/api2/json/access/permissions"]
    );

    // Unknown accounts are a 404, as on every other account surface.
    let (status, _) = privileges(&harness, "no-such-account").await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn an_8x_readonly_token_misses_the_mutating_tiers_and_the_opt_in_agent_read() {
    let harness = harness(PermissionsTransport::new(
        VERSION_8,
        200,
        include_str!(
            "../../providers/fleet-provider-proxmox/tests/fixtures/pve8/access-permissions-readonly.json"
        ),
    ))
    .await;
    let account_id = create_account(&harness).await;
    trust(&harness, &account_id).await;

    let (status, body) = privileges(&harness, &account_id).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["rulesMajor"], 8);
    let discover = tier(&body, "discover");
    assert_eq!(discover["status"], "granted", "{body}");
    let agent = discover["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["requirement"] == "read.guest-agent")
        .unwrap();
    assert_eq!(agent["required"], false);
    assert_eq!(agent["status"], "missing");
    assert_eq!(agent["missing"], json!(["VM.Monitor"]));

    let operate = tier(&body, "operate");
    assert_eq!(operate["status"], "missing");
    assert_eq!(
        operate["missing"],
        json!([{
            "privileges": ["VM.PowerMgmt"],
            "anyOf": false,
            "path": "/vms/{vmid}",
            "capabilities": [
                "proxmox.guest.start",
                "proxmox.guest.stop",
                "proxmox.guest.shutdown",
                "proxmox.guest.reboot"
            ]
        }])
    );
    assert_eq!(tier(&body, "destructive")["status"], "missing");
    assert_eq!(tier(&body, "lab")["status"], "missing");
}

#[tokio::test]
async fn a_privilege_separated_token_without_acls_misses_every_tier() {
    let harness = harness(PermissionsTransport::new(
        VERSION_9,
        200,
        include_str!(
            "../../providers/fleet-provider-proxmox/tests/fixtures/pve9/access-permissions-privsep-empty.json"
        ),
    ))
    .await;
    let account_id = create_account(&harness).await;
    trust(&harness, &account_id).await;

    let (status, body) = privileges(&harness, &account_id).await;
    assert_eq!(status, 200, "{body}");
    for name in ["discover", "operate", "destructive", "lab"] {
        let entry = tier(&body, name);
        assert_eq!(entry["status"], "missing", "{name}");
        assert!(!entry["missing"].as_array().unwrap().is_empty(), "{name}");
    }
}

#[tokio::test]
async fn a_refused_permissions_read_reports_every_tier_unknown() {
    let harness = harness(PermissionsTransport::new(
        VERSION_9,
        403,
        r#"{"data":null,"message":"Permission check failed\n"}"#,
    ))
    .await;
    let account_id = create_account(&harness).await;
    trust(&harness, &account_id).await;

    let (status, body) = privileges(&harness, &account_id).await;
    assert_eq!(status, 200, "{body}");
    for name in ["discover", "operate", "destructive", "lab"] {
        assert_eq!(tier(&body, name)["status"], "unknown", "{name}");
    }
    assert!(
        body["data"]["unknownReason"]
            .as_str()
            .unwrap()
            .contains("403")
    );
}
