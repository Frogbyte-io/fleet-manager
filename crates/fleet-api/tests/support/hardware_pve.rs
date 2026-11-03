//! A scripted Proxmox VE and a real controller around it, for the hardware
//! inventory tests of the controller and of `fleetctl` (FM-1111). Included
//! with `#[path]`; it is test support, not a test.
//!
//! The PVE answers in the shapes the FM-S11 spike recorded on 9.2.2 (mapping
//! list with and without `?check-node=`, the 403 on the node USB inventory,
//! `/access/permissions`, `/cluster/resources`, guest configs), with invented
//! device ids, VMIDs and the documentation address range: no real serial,
//! host or address appears. Every call must be a pinned, credential-carrying
//! `GET`: a refresh never mutates Proxmox.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_controller::Settings;
use fleet_controller::build_router;
use fleet_controller::proxmox_store::compose_proxmox;
use fleet_provider_proxmox::{
    PveHttpMethod, PveHttpRequest, PveHttpResponse, PveTransport, PveTransportError,
};
use fleet_secrets::SecretStore;
use fleet_storage_sqlite::Store;
use serde_json::{Value, json};

pub const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";
pub const SECRET: &str = "the-token-secret-material";

/// A scripted PVE: routes by exact path and query.
#[derive(Debug)]
pub struct ScriptedPve {
    routes: Mutex<BTreeMap<String, (u16, String)>>,
    /// Every credential-carrying request, `METHOD path`.
    pub requests: Mutex<Vec<String>>,
}

impl ScriptedPve {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            routes: Mutex::new(BTreeMap::new()),
            requests: Mutex::new(Vec::new()),
        })
    }

    /// Serves `body` wrapped in PVE's `{"data": …}` envelope.
    pub fn data(&self, path: &str, data: &Value) {
        self.route(path, 200, &json!({ "data": data }).to_string());
    }

    pub fn route(&self, path: &str, status: u16, body: &str) {
        self.routes
            .lock()
            .unwrap()
            .insert(path.to_owned(), (status, body.to_owned()));
    }

    pub fn calls(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    pub fn clear_calls(&self) {
        self.requests.lock().unwrap().clear();
    }

    /// The standard cluster: one node `pve`, seven USB mappings that cover
    /// every device status, three guests, a token with the opt-in role on
    /// every mapping but `fm-f`.
    #[allow(clippy::too_many_lines)]
    pub fn standard() -> Arc<Self> {
        let pve = Self::new();
        pve.data(
            "/api2/json/version",
            &json!({"version": "9.2.2", "release": "9.2"}),
        );
        let mapping = |id: &str, description: &str, map: &[&str], errors: Option<Value>| {
            let mut value = json!({
                "id": id, "type": "usb", "description": description,
                "digest": "0000000000000000000000000000000000000000", "map": map,
            });
            if let Some(errors) = errors {
                value["errors"] = errors;
            }
            value
        };
        let not_found = json!([{
            "message": "Invalid configuration: usb device '1-3' not found\n",
            "severity": "error"
        }]);
        let no_node = json!([{"message": "No mapping for node pve.", "severity": "warning"}]);
        let rows = |checked: bool| -> Value {
            let errors = |value: Value| checked.then_some(value);
            json!([
                mapping(
                    "fm-a",
                    "Test device A (port 1-1)",
                    &["node=pve,id=aaaa:0001,path=1-1"],
                    errors(json!([]))
                ),
                mapping(
                    "fm-b",
                    "Test device B (id only)",
                    &["node=pve,id=bbbb:0002"],
                    errors(json!([]))
                ),
                mapping(
                    "fm-c",
                    "Test device C (unplugged)",
                    &["node=pve,id=aaaa:0001,path=1-3"],
                    errors(not_found.clone())
                ),
                mapping(
                    "fm-d",
                    "Test device D (no entry)",
                    &[],
                    errors(no_node.clone())
                ),
                mapping(
                    "fm-e",
                    "Test device E (two entries)",
                    &[
                        "node=pve,id=cccc:0003,path=1-4",
                        "node=pve,id=cccc:0003,path=1-5"
                    ],
                    errors(json!([])),
                ),
                mapping(
                    "fm-f",
                    "Test device F (no Mapping.Use)",
                    &["node=pve,id=dddd:0004,path=1-6"],
                    errors(json!([]))
                ),
                mapping(
                    "fm-g",
                    "Test device G (to reserve)",
                    &["node=pve,id=eeee:0005,path=1-8"],
                    errors(json!([]))
                ),
            ])
        };
        pve.data("/api2/json/cluster/mapping/usb", &rows(false));
        pve.data("/api2/json/cluster/mapping/usb?check-node=pve", &rows(true));
        // The node inventory needs Sys.Modify on `/`, which the token lacks.
        pve.route(
            "/api2/json/nodes/pve/hardware/usb",
            403,
            r#"{"data":null,"message":"Permission check failed (/, Sys.Modify)\n"}"#,
        );
        pve.data(
            "/api2/json/access/permissions",
            &json!({
                "/mapping/usb": {"Mapping.Audit": 1},
                "/mapping/usb/fm-a": {"Mapping.Use": 0},
                "/mapping/usb/fm-b": {"Mapping.Use": 0},
                "/mapping/usb/fm-c": {"Mapping.Use": 0},
                "/mapping/usb/fm-d": {"Mapping.Use": 0},
                "/mapping/usb/fm-e": {"Mapping.Use": 0},
                "/mapping/usb/fm-g": {"Mapping.Use": 0},
                "/vms": {"VM.Audit": 1, "VM.Config.HWType": 1}
            }),
        );
        pve.data(
            "/api2/json/cluster/resources",
            &json!([
                {"id": "node/pve", "type": "node", "node": "pve", "status": "online"},
                {"id": "qemu/200", "type": "qemu", "node": "pve", "vmid": 200, "name": "guest-a", "status": "running"},
                {"id": "qemu/201", "type": "qemu", "node": "pve", "vmid": 201, "name": "guest-b", "status": "stopped"},
                {"id": "qemu/9000", "type": "qemu", "node": "pve", "vmid": 9000, "name": "base", "template": 1, "status": "stopped"}
            ]),
        );
        // Guest 200 holds fm-b by hand (the Decker case), the template
        // carries fm-a (a clone would inherit it), 201 holds nothing.
        let held = json!({"name": "guest-a", "usb0": "mapping=fm-b,usb3=1", "digest": "d200"});
        pve.data("/api2/json/nodes/pve/qemu/200/config", &held);
        pve.data("/api2/json/nodes/pve/qemu/200/config?current=1", &held);
        pve.data(
            "/api2/json/nodes/pve/qemu/201/config",
            &json!({"name": "guest-b", "digest": "d201"}),
        );
        pve.data(
            "/api2/json/nodes/pve/qemu/9000/config",
            &json!({"name": "base", "template": 1, "usb0": "mapping=fm-a", "digest": "d9000"}),
        );
        pve
    }
}

#[async_trait]
impl PveTransport for ScriptedPve {
    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        let Some(pinned) = &request.pinned_fingerprint else {
            // The observe probe: capture and refuse, as the real policy does.
            return Err(PveTransportError::ObserveRefused {
                observed: FP.to_owned(),
            });
        };
        assert_eq!(pinned, FP, "every credential-carrying call is pinned");
        assert_eq!(
            request.method,
            PveHttpMethod::Get,
            "a refresh never mutates"
        );
        self.requests
            .lock()
            .unwrap()
            .push(format!("GET {}", request.path));
        let routes = self.routes.lock().unwrap();
        let (status, body) = routes
            .get(&request.path)
            .cloned()
            .unwrap_or_else(|| (404, r#"{"data":null,"message":"not scripted"}"#.to_owned()));
        Ok(PveHttpResponse {
            status,
            body: body.into_bytes(),
        })
    }

    async fn execute_with_body(
        &self,
        _request: PveHttpRequest,
        _body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        panic!("the inventory never sends a body to Proxmox");
    }
}

/// A real controller router over SQLite and the scripted PVE, on a local
/// port.
pub struct World {
    _dist: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _key_dir: tempfile::TempDir,
    pub address: std::net::SocketAddr,
    pub pool: sqlx::SqlitePool,
    pub pve: Arc<ScriptedPve>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for World {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

impl World {
    pub async fn start(pve: Arc<ScriptedPve>) -> Self {
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
            pve.clone(),
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
        let pool = store.pool().clone();
        std::mem::forget(store);
        Self {
            _dist: dist,
            _store_dir: store_dir,
            _key_dir: key_dir,
            address,
            pool,
            pve,
            shutdown: Some(shutdown_tx),
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// One raw HTTP request over TCP.
    pub async fn raw(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut stream = tokio::net::TcpStream::connect(self.address).await.unwrap();
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: test\r\n");
        if let Some(body) = &body {
            let _ = write!(
                head,
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.to_string().len()
            );
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
        let body = serde_json::from_str(rest).unwrap_or_else(|error| {
            panic!("the {status} response body is not JSON ({error}): {rest}")
        });
        (status, body)
    }

    /// Creates the account and, when `confirm`, pins its fingerprint.
    pub async fn account(&self, confirm: bool) -> String {
        let (status, body) = self
            .raw(
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
        let id = body["data"]["id"].as_str().unwrap().to_owned();
        if confirm {
            let (status, body) = self
                .raw(
                    "POST",
                    &format!("/api/v1/proxmox/accounts/{id}/observe"),
                    Some(json!({})),
                )
                .await;
            assert_eq!(status, 200, "{body}");
            let (status, body) = self
                .raw(
                    "POST",
                    &format!("/api/v1/proxmox/accounts/{id}/confirm"),
                    Some(json!({"fingerprint": FP})),
                )
                .await;
            assert_eq!(status, 200, "{body}");
        }
        id
    }
}
