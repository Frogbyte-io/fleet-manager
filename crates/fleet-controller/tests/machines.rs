//! The machine read surface end-to-end: a real controller router serving
//! `/api/v1/machines`, with a real `fleetd` node connected over the gateway,
//! proving the hydrated view — derived status, capability facts, and the
//! last observation — against the recorded surfaces from FM-200/203/205/206.

use std::sync::Arc;
use std::time::Duration;

use fleet_controller::Settings;
use fleet_controller::build_router;
use fleet_controller::compose_node_services;
use fleet_controller::gateway::GatewayService;
use serde_json::{Value, json};
use tokio::net::TcpListener;

struct Harness {
    _dist: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _key_dir: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    machines: fleet_storage_sqlite::MachineRepository,
    gateway: Arc<GatewayService>,
    operations: Arc<fleet_application::operation::Operations>,
    address: std::net::SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

async fn harness() -> Harness {
    let dist = tempfile::tempdir().unwrap();
    std::fs::write(dist.path().join("index.html"), "<html>fleet</html>").unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let key_dir = tempfile::tempdir().unwrap();
    let store = fleet_storage_sqlite::Store::open(&store_dir.path().join("fleet.db"))
        .await
        .unwrap();
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
    let secrets = fleet_secrets::SecretStore::open(store.pool().clone(), &key_path).unwrap();
    let crypto = fleet_controller::node_crypto::NodeCryptoService::open(&secrets)
        .await
        .expect("the node signing key must provision");
    let services = compose_node_services(store.pool(), Arc::new(crypto));
    let machines = fleet_storage_sqlite::MachineRepository::new(store.pool().clone());

    let settings = Settings {
        listen: "127.0.0.1:0".parse().unwrap(),
        web_dist: dist.path().to_path_buf(),
        artifacts_dir: None,
    };
    let router = build_router(
        &settings,
        Some(store.pool().clone()),
        Some(&services),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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

    let operations = Arc::new(fleet_application::operation::Operations::new(
        Arc::new(fleet_storage_sqlite::OperationRepository::new(
            store.pool().clone(),
        )),
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    ));
    Harness {
        _dist: dist,
        _store_dir: store_dir,
        _key_dir: key_dir,
        pool: store.pool().clone(),
        machines,
        gateway: services.gateway.clone(),
        operations,
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
    /// GETs a JSON path from the test server and returns status and body.
    async fn get_json(&self, path: &str) -> (axum::http::StatusCode, Value) {
        raw_request(self.address, "GET", path, None).await
    }

    /// POSTs JSON to the test server and returns status and body.
    async fn post_json(&self, path: &str, body: Value) -> (axum::http::StatusCode, Value) {
        raw_request(self.address, "POST", path, Some(body)).await
    }

    async fn register_machine(&self, name: &str, reference: &str) -> String {
        use fleet_application::machine::{MachinePort, NewEndpoint, RegisterMachine};
        let machine = self
            .machines
            .register(&RegisterMachine {
                name: name.to_owned(),
                description: String::new(),
                endpoints: vec![NewEndpoint {
                    kind: fleet_core::EndpointKind::Ssh,
                    reference: reference.to_owned(),
                }],
                tags: Vec::new(),
                groups: Vec::new(),
            })
            .await
            .expect("the machine must register");
        machine.id
    }

    fn node_executor(&self) -> fleet_controller::gateway::NodeCommandExecutor {
        fleet_controller::gateway::NodeCommandExecutor::new(
            self.gateway.clone(),
            Arc::new(fleet_storage_sqlite::MachineRepository::new(
                self.pool.clone(),
            )),
            Arc::new(fleet_application::worker::NoopExecutor),
        )
    }

    async fn create_node_operation(
        &self,
        kind: &str,
        machine_id: &str,
    ) -> fleet_application::operation::Operation {
        self.operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                "anonymous-lan-admin",
                &fleet_application::operation::NewOperation {
                    kind: kind.to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(serde_json::json!({ "machineId": machine_id }).to_string()),
                    review_token: None,
                },
            )
            .await
            .expect("the operation must be created")
    }

    async fn tick(&self) -> fleet_application::worker::TickReport {
        self.operations
            .tick(
                &self.node_executor(),
                "test-worker",
                fleet_core::SystemClock::now_unix_millis(),
                60_000,
            )
            .await
            .expect("the tick must run")
    }
}

/// One raw HTTP request over TCP; the test asserts on bodies, not clients.
async fn raw_request(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (axum::http::StatusCode, Value) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: test\r\n");
    let payload = body.map(|body| body.to_string());
    if let Some(payload) = &payload {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            payload.len()
        ));
    }
    head.push_str("Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    if let Some(payload) = &payload {
        stream.write_all(payload.as_bytes()).await.unwrap();
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    let (head, body) = text.split_once("\r\n\r\n").expect("an HTTP response");
    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (
        axum::http::StatusCode::from_u16(status).unwrap(),
        serde_json::from_str(body.trim()).unwrap_or(Value::Null),
    )
}

/// Waits until `check` holds, with a shared deadline and poll cadence.
async fn wait_until(check: impl AsyncFn() -> bool, what: &'static str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !check().await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting: {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Starts a real fleetd gateway loop against the harness and waits for its
/// session to register. The node's state lives in a kept tempdir because the
/// daemon's own loops own it.
async fn start_real_node(
    harness: &Harness,
    name: &str,
) -> (std::path::PathBuf, String, tokio::sync::oneshot::Sender<()>) {
    let state_dir = tempfile::tempdir().unwrap().keep();
    let node_state = Arc::new(fleetd::state::NodeState::open(&state_dir).unwrap());
    let machine_id = harness.register_machine(name, "ops@managed.lan:22").await;
    let (status, body) = harness
        .post_json(
            &format!("/api/v1/machines/{machine_id}/node/enrollments"),
            json!({}),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::CREATED, "{body}");
    let token = body["data"]["token"].as_str().unwrap();
    let controller = fleetd::http::Controller::parse(&format!("http://{}", harness.address))
        .expect("the harness URL parses");
    tokio::task::spawn_blocking({
        let controller = controller.clone();
        let node_state = node_state.clone();
        let token = token.to_owned();
        move || fleetd::session::enroll(&controller, &node_state, &token)
    })
    .await
    .expect("the enroll task must not panic")
    .expect("the real node must enroll");
    let node_state = Arc::new(
        fleetd::state::NodeState::open(&state_dir).expect("the enrolled state must reopen"),
    );
    let journal = Arc::new(
        fleetd::journal::NodeJournal::open(&state_dir.join("journal.ndjson"))
            .map_err(|error| error.to_string())
            .unwrap(),
    );
    let inventory = Arc::new(
        fleetd::inventory::InventoryState::open(&state_dir.join("inventory.json"))
            .map_err(|error| error.to_string())
            .unwrap(),
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let run_controller = controller.clone();
    let run_state = node_state;
    let run_journal = journal.clone();
    tokio::spawn(async move {
        let _ = fleetd::run_gateway_connected(
            run_controller,
            run_state,
            run_journal,
            inventory,
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await;
    });
    wait_until(
        async || harness.gateway.session_of(&machine_id).await.is_some(),
        "the real node's gateway session must register",
    )
    .await;
    (state_dir, machine_id, shutdown_tx)
}

#[tokio::test]
async fn the_machine_view_reports_agentless_and_managed_states_end_to_end() {
    let harness = harness().await;
    let agentless_id = harness
        .register_machine("agentless-box", "ops@10.9.9.9:22")
        .await;

    // The agentless machine: ssh-only, no node, nothing observed yet. The
    // trusted-LAN admin may read the full endpoint reference.
    let (status, body) = harness
        .get_json(&format!("/api/v1/machines/{agentless_id}"))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["data"]["machineStatus"], "agentless");
    assert_eq!(body["data"]["endpoints"][0]["reference"], "ops@10.9.9.9:22");
    assert_eq!(body["data"]["endpoints"][0]["kind"], "ssh");
    assert!(body["data"]["capabilities"].as_array().unwrap().is_empty());
    assert!(body["data"]["lastObservation"].is_null());

    // A managed machine over a real fleetd connection: connected.
    let (_state_dir, managed_id, shutdown) = start_real_node(&harness, "managed-box").await;
    wait_until(
        async || {
            let (_, body) = harness
                .get_json(&format!("/api/v1/machines/{managed_id}"))
                .await;
            body["data"]["machineStatus"] == "connected"
        },
        "the managed machine must report connected",
    )
    .await;

    // Inventory flows through the real node and hydrates the view.
    let operation = harness
        .create_node_operation("node.inventory", &managed_id)
        .await;
    let report = harness.tick().await;
    assert!(report.completed, "{report:?}");
    wait_until(
        async || {
            let (_, body) = harness
                .get_json(&format!("/api/v1/machines/{managed_id}"))
                .await;
            body["data"]["capabilities"]
                .as_array()
                .is_some_and(|facts| {
                    facts.iter().any(|fact| {
                        fact["namespace"] == "os"
                            && fact["name"] == "family"
                            && fact["value"] == std::env::consts::OS
                            && fact["status"] == "known"
                    })
                })
        },
        "the os family fact must reach the machine view",
    )
    .await;
    let (_, body) = harness
        .get_json(&format!("/api/v1/machines/{managed_id}"))
        .await;
    let observation = &body["data"]["lastObservation"];
    assert!(
        observation["source"]
            .as_str()
            .is_some_and(|source| source.starts_with("fleetd/")),
        "{observation}"
    );
    assert!(observation["collectedAt"].as_i64().unwrap() > 0);
    let _ = operation;

    // The status filter narrows over the real router.
    let (status, body) = harness.get_json("/api/v1/machines?status=agentless").await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let ids: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|machine| machine["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![agentless_id.as_str()]);

    let (status, body) = harness.get_json("/api/v1/machines?status=connected").await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let ids: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|machine| machine["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![managed_id.as_str()]);

    let _ = shutdown.send(());
}
