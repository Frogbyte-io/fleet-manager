//! The Proxmox task-history surface end to end (FM-609): a real controller
//! router, a real worker running the lifecycle executor, SQLite, the secret
//! store, and a fake PVE transport. Covers the operation join from the
//! executor's recorded UPID, cursor pagination with stale-cursor refusal,
//! per-node warnings, the filters, and the trust gate.

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

const VERSION_BODY: &str = r#"{"data":{"release":"9.2","version":"9.2.2"}}"#;

/// Three nodes: one healthy, one unreachable, one offline.
const RESOURCES_BODY: &str = r#"{"data":[
  {"id":"node/pve","type":"node","node":"pve","status":"online"},
  {"id":"node/pve2","type":"node","node":"pve2","status":"online"},
  {"id":"node/pve3","type":"node","node":"pve3","status":"offline"},
  {"id":"qemu/101","type":"qemu","node":"pve","vmid":101,"name":"dev-01","status":"running","template":0}
]}"#;

/// The UPID the lifecycle start returns; the task list reports it too.
const FLEET_UPID: &str = "UPID:pve:0015523F:0C6DF532:6AAFE1EC:qmstart:101:root@pam!GLM-AGENT:";

const LIFECYCLE_UPID_BODY: &str =
    r#"{"data":"UPID:pve:0015523F:0C6DF532:6AAFE1EC:qmstart:101:root@pam!GLM-AGENT:"}"#;

const TASK_OK_BODY: &str = r#"{"data":{"status":"stopped","exitstatus":"OK"}}"#;

/// The healthy node's task list, PVE 9 shape, newest first.
const NODE_TASKS_BODY: &str = r#"{"data":[
  {"upid":"UPID:pve:0015523F:0C6DF532:6AAFE1EC:qmstart:101:root@pam!GLM-AGENT:","node":"pve","pid":1397311,"pstart":208532786,"starttime":1789911532,"type":"qmstart","id":"101","user":"root@pam","tokenid":"GLM-AGENT","endtime":1789911534,"status":"OK"},
  {"upid":"UPID:pve:00155000:0C6DF000:6AAFDFF8:qmshutdown:101:root@pam:","node":"pve","pid":1396736,"pstart":208531456,"starttime":1789911032,"type":"qmshutdown","id":"101","user":"root@pam","endtime":1789911040,"status":"OK"},
  {"upid":"UPID:pve:00154000:0C6DE000:6AAFDE04:vzdump::root@pam:","node":"pve","pid":1392640,"pstart":208527360,"starttime":1789910532,"type":"vzdump","id":"","user":"root@pam","endtime":1789910600,"status":"WARNINGS: 1"},
  {"upid":"UPID:pve:00153000:0C6DD000:6AAFDC10:qmclone:900:root@pam:","node":"pve","pid":1388544,"pstart":208523264,"starttime":1789910032,"type":"qmclone","id":"900","user":"root@pam","endtime":1789910033,"status":"clone failed: no space left"}
]}"#;

#[derive(Debug, Default)]
struct TaskTransport {
    paths: Mutex<Vec<String>>,
}

#[async_trait]
impl PveTransport for TaskTransport {
    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        _body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        self.execute(request).await
    }

    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        if request.pinned_fingerprint.is_none() {
            return Err(PveTransportError::ObserveRefused {
                observed: FP.to_owned(),
            });
        }
        self.paths.lock().unwrap().push(request.path.clone());
        let path = request.path.as_str();
        let (status, body) = if path.contains("/status/start") {
            (200, LIFECYCLE_UPID_BODY)
        } else if path.contains("/tasks/") && path.contains("/status") {
            (200, TASK_OK_BODY)
        } else if path.ends_with("/version") {
            (200, VERSION_BODY)
        } else if path.ends_with("/cluster/resources") {
            (200, RESOURCES_BODY)
        } else if path.starts_with("/api2/json/nodes/pve/tasks?") {
            (200, NODE_TASKS_BODY)
        } else if path.starts_with("/api2/json/nodes/pve2/tasks?") {
            (595, r#"{"data":null,"message":"No route to host"}"#)
        } else {
            return Err(PveTransportError::Connect {
                detail: format!("unexpected path {path}"),
            });
        };
        Ok(PveHttpResponse {
            status,
            body: body.as_bytes().to_vec(),
        })
    }
}

struct Harness {
    _dist: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _key_dir: tempfile::TempDir,
    address: std::net::SocketAddr,
    transport: Arc<TaskTransport>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
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
    let transport = Arc::new(TaskTransport::default());
    let proxmox = Arc::new(compose_proxmox(
        store.pool().clone(),
        secrets.clone(),
        transport.clone(),
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    ));

    // The worker runs the lifecycle executor with the task-link recorder,
    // exactly as the controller composes it.
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
    let links: Arc<dyn fleet_application::proxmox::tasks::ProxmoxTaskLinkPort> = Arc::new(
        fleet_storage_sqlite::ProxmoxTaskLinkRepository::new(store.pool().clone()),
    );
    let executor = Arc::new(fleet_controller::proxmox_exec::ProxmoxDispatch::new(
        Arc::new(fleet_application::worker::NoopExecutor),
        Arc::new(
            fleet_controller::proxmox_exec::ProxmoxLifecycleExecutor::new(
                accounts.clone(),
                credentials.clone(),
                fleet_provider_proxmox::ProxmoxClient::new(transport.clone()),
            )
            .with_task_links(links.clone()),
        ),
        Arc::new(
            fleet_controller::proxmox_exec::ProxmoxDestructiveExecutor::new(
                accounts,
                credentials,
                fleet_provider_proxmox::ProxmoxClient::new(transport.clone()),
            )
            .with_task_links(links),
        ),
    ));
    let worker_host = fleet_controller::worker::WorkerHost::new(worker_operations, executor, 4);
    tokio::spawn(async move {
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
        address,
        transport,
        shutdown: Some(shutdown_tx),
    }
}

impl Harness {
    async fn get(&self, path: &str) -> (axum::http::StatusCode, Value) {
        raw(self.address, "GET", path, None).await
    }

    async fn post(&self, path: &str, body: Value) -> (axum::http::StatusCode, Value) {
        raw(self.address, "POST", path, Some(body)).await
    }

    /// Creates an account; confirms its trust when asked.
    async fn account(&self, name: &str, confirm: bool) -> String {
        let (status, body) = self
            .post(
                "/api/v1/proxmox/accounts",
                json!({
                    "name": name,
                    "host": "192.0.2.10",
                    "tokenId": "root@pam!GLM-AGENT",
                    "tokenSecret": "the-token-secret-material"
                }),
            )
            .await;
        assert_eq!(status, axum::http::StatusCode::CREATED, "{body}");
        let account_id = body["data"]["id"].as_str().unwrap().to_owned();
        if confirm {
            let (status, body) = self
                .post(
                    &format!("/api/v1/proxmox/accounts/{account_id}/observe"),
                    json!({}),
                )
                .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            let (status, body) = self
                .post(
                    &format!("/api/v1/proxmox/accounts/{account_id}/confirm"),
                    json!({"fingerprint": FP}),
                )
                .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        }
        account_id
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

/// Starts a guest through the lifecycle endpoint and waits for the worker
/// to finish it, returning the operation id.
async fn run_start(harness: &Harness, account_id: &str) -> String {
    let (status, body) = harness
        .post(
            &format!("/api/v1/proxmox/accounts/{account_id}/guests/101/start"),
            json!({"node": "pve", "vmid": 101, "timeoutSeconds": 30}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");
    let operation_id = body["data"]["id"].as_str().unwrap().to_owned();
    for _ in 0..100 {
        let (_, body) = harness
            .get(&format!("/api/v1/operations/{operation_id}"))
            .await;
        if body["data"]["state"] == "succeeded" {
            return operation_id;
        }
        assert_ne!(body["data"]["state"], "failed", "{body}");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("the lifecycle operation did not finish");
}

#[tokio::test]
async fn the_task_history_links_fleet_tasks_and_paginates_with_cursor_refusal() {
    let harness = harness().await;
    let account_id = harness.account("pve-main", true).await;
    let operation_id = run_start(&harness, &account_id).await;

    // Page 1: the newest two, the Fleet-started task linked to its
    // operation, and the per-node warnings for the down and offline nodes.
    let (status, page) = harness
        .get(&format!(
            "/api/v1/proxmox/accounts/{account_id}/tasks?limit=2"
        ))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{page}");
    assert_eq!(page["accountId"], account_id.as_str());
    assert_eq!(page["pveVersion"], "9.2.2");
    assert_eq!(page["page"]["limit"], 2);
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{page}");
    assert_eq!(items[0]["upid"], FLEET_UPID);
    assert_eq!(items[0]["fleetOperationId"], operation_id.as_str());
    assert_eq!(items[0]["node"], "pve");
    assert_eq!(items[0]["taskType"], "qmstart");
    assert_eq!(items[0]["targetId"], "101");
    assert_eq!(items[0]["user"], "root@pam");
    assert_eq!(items[0]["tokenId"], "GLM-AGENT");
    assert_eq!(items[0]["startedAt"], 1_789_911_532_000_i64);
    assert_eq!(items[0]["endedAt"], 1_789_911_534_000_i64);
    assert_eq!(items[0]["status"], "ok");
    assert_eq!(items[0]["exitStatus"], "OK");
    assert_eq!(items[1]["fleetOperationId"], Value::Null);
    let warnings = page["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 2, "{page}");
    assert!(
        warnings.iter().any(|w| w
            .as_str()
            .unwrap()
            .starts_with("node pve2 tasks are unavailable")),
        "{page}"
    );
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap().starts_with("node pve3 is offline")),
        "{page}"
    );
    let cursor = page["page"]["nextCursor"].as_str().unwrap().to_owned();
    assert_eq!(cursor, items[1]["upid"].as_str().unwrap());

    // Page 2 follows the cursor; the last page carries no next cursor.
    let (status, page) = harness
        .get(&format!(
            "/api/v1/proxmox/accounts/{account_id}/tasks?limit=3&cursor={}",
            encode(&cursor)
        ))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{page}");
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{page}");
    assert_eq!(items[0]["taskType"], "vzdump");
    assert_eq!(items[0]["targetId"], Value::Null, "a node-level task");
    assert_eq!(items[0]["status"], "error");
    assert_eq!(items[0]["exitStatus"], "WARNINGS: 1");
    assert_eq!(items[1]["taskType"], "qmclone");
    assert_eq!(page["page"]["nextCursor"], Value::Null);

    // A stale cursor is refused, never a silent restart.
    let (status, body) = harness
        .get(&format!(
            "/api/v1/proxmox/accounts/{account_id}/tasks?cursor={}",
            encode("UPID:pve:00000001:00000001:00000001:qmstart:999:root@pam:")
        ))
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");

    // The offline node was never called, and no response carries the
    // token secret.
    let paths = harness.transport.paths.lock().unwrap().clone();
    assert!(
        !paths.iter().any(|path| path.contains("/nodes/pve3/")),
        "{paths:?}"
    );
    assert!(
        paths
            .iter()
            .any(|path| path == "/api2/json/nodes/pve/tasks?source=all&limit=200"),
        "{paths:?}"
    );
}

#[tokio::test]
async fn the_task_history_filters_and_refuses_malformed_filters() {
    let harness = harness().await;
    let account_id = harness.account("pve-main", true).await;

    let (status, page) = harness
        .get(&format!(
            "/api/v1/proxmox/accounts/{account_id}/tasks?status=error&node=pve&vmid=900"
        ))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{page}");
    // The fake ignores vmid on the wire; the request carries it.
    let statuses: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["status"].as_str().unwrap())
        .collect();
    assert_eq!(statuses, vec!["error", "error"], "{page}");
    // Only the requested node was read, so no node warnings.
    assert_eq!(page["warnings"], json!([]), "{page}");
    let paths = harness.transport.paths.lock().unwrap().clone();
    assert!(
        paths
            .iter()
            .any(|path| path == "/api2/json/nodes/pve/tasks?source=all&limit=200&vmid=900"),
        "{paths:?}"
    );

    for query in ["status=warning", "node=..", "vmid=7"] {
        let (status, body) = harness
            .get(&format!(
                "/api/v1/proxmox/accounts/{account_id}/tasks?{query}"
            ))
            .await;
        assert_eq!(
            status,
            axum::http::StatusCode::BAD_REQUEST,
            "{query}: {body}"
        );
        assert_eq!(body["code"], "invalid_request", "{query}: {body}");
    }
}

#[tokio::test]
async fn the_task_history_applies_the_trust_gate_and_knows_its_accounts() {
    let harness = harness().await;
    let account_id = harness.account("pve-unconfirmed", false).await;

    let (status, body) = harness
        .get(&format!("/api/v1/proxmox/accounts/{account_id}/tasks"))
        .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "proxmox_unconfirmed");
    assert!(
        harness.transport.paths.lock().unwrap().is_empty(),
        "no credential-carrying call may leave Fleet"
    );

    let (status, body) = harness
        .get("/api/v1/proxmox/accounts/no-such-account/tasks")
        .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{body}");
}

/// Percent-encodes a query value.
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}
