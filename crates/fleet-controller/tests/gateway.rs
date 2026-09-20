//! The node gateway over a real WebSocket connection: admission, version
//! negotiation, one-session-per-node supersede, heartbeat liveness with
//! sparse state persistence, and the bounded reconnect backoff.
//!
//! The tests run a real bound listener because the parts most likely to be
//! wrong — the upgrade handshake, the subprotocol negotiation, and the
//! session registry — do not exist inside the handler functions.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use fleet_application::node::ChallengePurpose;
use fleet_application::node::proof_message;
use futures_util::{SinkExt as _, StreamExt as _};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};

use fleet_controller::Settings;
use fleet_controller::build_router;
use fleet_controller::compose_node_services;
use fleet_controller::gateway::{GatewayService, NODE_SUBPROTOCOL};
use fleet_protocol::wire;
use fleet_protocol::{decode_frame, encode_frame};

fn settings(web_dist: &std::path::Path) -> Settings {
    Settings {
        listen: "127.0.0.1:0".parse().unwrap(),
        web_dist: web_dist.to_path_buf(),
        artifacts_dir: None,
    }
}

type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct Harness {
    _dist: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _key_dir: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    machines: fleet_storage_sqlite::MachineRepository,
    nodes: Arc<fleet_application::node::Nodes>,
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

    let router = build_router(
        &settings(dist.path()),
        Some(store.pool().clone()),
        Some(&services),
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
        nodes: services.nodes.clone(),
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
    /// The node-command executor over this harness's gateway.
    fn node_executor(&self) -> fleet_controller::gateway::NodeCommandExecutor {
        fleet_controller::gateway::NodeCommandExecutor::new(
            self.gateway.clone(),
            Arc::new(fleet_storage_sqlite::MachineRepository::new(
                self.pool.clone(),
            )),
            Arc::new(fleet_application::worker::NoopExecutor),
        )
    }

    /// Creates one node operation and returns it.
    async fn create_node_operation(
        &self,
        kind: &str,
        machine_id: &str,
        deadline_at: Option<i64>,
    ) -> fleet_application::operation::Operation {
        self.operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                "anonymous-lan-admin",
                &fleet_application::operation::NewOperation {
                    kind: kind.to_owned(),
                    idempotency_key: None,
                    deadline_at,
                    correlation_id: None,
                    payload_json: Some(serde_json::json!({ "machineId": machine_id }).to_string()),
                },
            )
            .await
            .expect("the operation must be created")
    }

    /// Runs one worker tick with the node executor.
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

    /// POSTs JSON to the test server and returns the status and body.
    async fn post_json(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let mut stream = tokio::net::TcpStream::connect(self.address).await.unwrap();
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let payload = body.to_string();
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\n\
             Content-Length: {len}\r\nConnection: close\r\n\r\n{payload}",
            len = payload.len(),
        );
        stream.write_all(request.as_bytes()).await.unwrap();
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
            StatusCode::from_u16(status).unwrap(),
            serde_json::from_str(body.trim()).unwrap_or(Value::Null),
        )
    }

    async fn register_machine(&self, name: &str) -> String {
        use fleet_application::machine::{MachinePort, NewEndpoint, RegisterMachine};
        use fleet_core::EndpointKind;
        let machine = self
            .machines
            .register(&RegisterMachine {
                name: name.to_owned(),
                description: String::new(),
                endpoints: vec![NewEndpoint {
                    kind: EndpointKind::Ssh,
                    reference: "ops@host:22".to_owned(),
                }],
                tags: Vec::new(),
                groups: Vec::new(),
            })
            .await
            .expect("the machine must register");
        machine.id
    }

    /// Creates an enrollment token and enrolls a node, returning the machine
    /// id and the stored credential.
    async fn enroll_node(&self, name: &str, keys: &NodeKeys) -> (String, String) {
        let machine_id = self.register_machine(name).await;
        let (status, body) = self
            .post_json(
                &format!("/api/v1/machines/{machine_id}/node/enrollments"),
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let token = body["data"]["token"].as_str().unwrap();
        let (status, body) = self
            .post_json(
                "/api/node/v1/enroll",
                json!({
                    "token": token,
                    "publicKey": keys.public_key_hex,
                    "os": "linux",
                    "arch": "x86_64",
                    "nodeVersion": "0.1.0",
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        (
            machine_id,
            body["data"]["credential"].as_str().unwrap().to_owned(),
        )
    }

    /// Proves possession and returns the short-lived session token.
    async fn prove_session(&self, credential: &str, keys: &NodeKeys) -> String {
        let (status, body) = self
            .post_json(
                "/api/node/v1/challenge",
                json!({ "credential": credential }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let challenge_id = body["data"]["challengeId"].as_str().unwrap();
        let machine_id = body["data"]["machineId"].as_str().unwrap();
        let message = proof_message(challenge_id, machine_id, ChallengePurpose::Session, None);
        let (status, body) = self
            .post_json(
                "/api/node/v1/session",
                json!({
                    "credential": credential,
                    "challengeId": challenge_id,
                    "signature": keys.sign_hex(message.as_slice()),
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["data"]["session"].as_str().unwrap().to_owned()
    }

    /// The durable gateway state of a machine's node identity.
    async fn gateway_state(&self, machine_id: &str) -> Option<String> {
        self.nodes
            .node_view(
                &fleet_auth::LanAllowAllAuthorizer,
                &permit_all(),
                machine_id,
            )
            .await
            .ok()
            .and_then(|view| view.identity)
            .map(|identity| identity.gateway_state.id().to_owned())
    }
}

fn permit_all() -> fleet_application::authz::ActingPrincipal {
    fleet_application::authz::ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }
}

/// A simulated node's key pair.
struct NodeKeys {
    key_pair: Ed25519KeyPair,
    public_key_hex: String,
}

impl NodeKeys {
    fn generate() -> Self {
        let document =
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("a key pair must generate");
        let key_pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).expect("the pkcs8 parses");
        let public_key_hex = hex(key_pair.public_key().as_ref());
        Self {
            key_pair,
            public_key_hex,
        }
    }

    fn sign_hex(&self, message: &[u8]) -> String {
        hex(self.key_pair.sign(message).as_ref())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hello_frame(machine_id: &str, min: u32, max: u32) -> wire::Frame {
    wire::Frame {
        message_id: uuid::Uuid::now_v7().to_string(),
        correlation_id: String::new(),
        sent_at_unix_millis: fleet_core::SystemClock::now_unix_millis(),
        payload: Some(wire::frame::Payload::Hello(wire::Hello {
            machine_id: machine_id.to_owned(),
            node_version: "test".to_owned(),
            protocol_versions: Some(wire::VersionRange { min, max }),
            inventory_schema_versions: Some(wire::VersionRange { min, max }),
            session_id: uuid::Uuid::now_v7().to_string(),
            journal_position: 0,
            os: "linux".to_owned(),
            arch: "x86_64".to_owned(),
            feature_flags: Vec::new(),
            last_acknowledged_operation_id: String::new(),
        })),
    }
}

fn heartbeat_frame(sequence: u64) -> wire::Frame {
    wire::Frame {
        message_id: uuid::Uuid::now_v7().to_string(),
        correlation_id: String::new(),
        sent_at_unix_millis: fleet_core::SystemClock::now_unix_millis(),
        payload: Some(wire::frame::Payload::Heartbeat(wire::Heartbeat {
            sequence,
            node_uptime_millis: 1_000,
            journal_position: 0,
            in_flight_commands: 0,
        })),
    }
}

async fn send_frame(
    sink: &mut futures_util::stream::SplitSink<WsStream, WsMessage>,
    frame: wire::Frame,
) {
    sink.send(WsMessage::Binary(encode_frame(&frame).unwrap().into()))
        .await
        .expect("the frame must send");
}

async fn receive_frame(
    stream: &mut futures_util::stream::SplitStream<WsStream>,
) -> Option<wire::Frame> {
    loop {
        match stream.next().await {
            Some(Ok(WsMessage::Binary(bytes))) => return Some(decode_frame(&bytes).unwrap()),
            Some(Ok(WsMessage::Close(_))) | None => return None,
            Some(Ok(_)) => continue,
            Some(Err(_)) => return None,
        }
    }
}

/// Connects with the node's session header and the subprotocol offer.
async fn connect_node(
    harness: &Harness,
    session: &str,
) -> Result<(WsStream, tungstenite::http::Response<Option<Vec<u8>>>), tungstenite::Error> {
    let mut request =
        format!("ws://{}/api/node/v1/connect", harness.address).into_client_request()?;
    request.headers_mut().insert(
        "x-fleet-node-session",
        HeaderValue::from_str(session).unwrap(),
    );
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(NODE_SUBPROTOCOL),
    );
    connect_async(request).await
}

/// The status a failed upgrade was answered with.
fn upgrade_status(error: tungstenite::Error) -> StatusCode {
    match error {
        tungstenite::Error::Http(response) => response.status(),
        other => panic!("the upgrade must fail with an HTTP answer, not {other:?}"),
    }
}

/// Waits until `check` holds, with a shared deadline and poll cadence.
async fn wait_until(check: impl AsyncFn() -> bool, what: &'static str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !check().await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting: {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn a_session_connects_negotiates_and_heartbeats() {
    let harness = harness().await;
    let keys = NodeKeys::generate();
    let (machine_id, credential) = harness.enroll_node("alive", &keys).await;
    let session = harness.prove_session(&credential, &keys).await;

    let (stream, response) = connect_node(&harness, &session).await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    let (mut sink, mut source) = stream.split();

    // Hello opens the negotiation; the Welcome fixes its terms.
    send_frame(&mut sink, hello_frame(&machine_id, 1, 1)).await;
    let welcome = receive_frame(&mut source).await.expect("a Welcome frame");
    let Some(wire::frame::Payload::Welcome(welcome)) = welcome.payload else {
        panic!(
            "the first frame must be a Welcome, not {:?}",
            welcome.payload
        );
    };
    assert_eq!(welcome.protocol_version, 1);
    assert_eq!(welcome.inventory_schema_version, 1);
    assert!(!welcome.session_id.is_empty());
    let limits = welcome.limits.expect("the limits are advertised");
    assert!(limits.max_frame_bytes > 0);
    assert!(welcome.heartbeat_interval_millis > 0);

    wait_until(
        async || harness.gateway_state(&machine_id).await.as_deref() == Some("connected"),
        "the gateway state must become connected",
    )
    .await;

    // Heartbeats keep it alive without touching SQLite: the state stays
    // connected and the registry's sequence advances.
    send_frame(&mut sink, heartbeat_frame(1)).await;
    send_frame(&mut sink, heartbeat_frame(2)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let entry = harness
        .gateway
        .session_of(&machine_id)
        .await
        .expect("the session is registered");
    assert_eq!(entry.heartbeat_sequence.load(Ordering::Relaxed), 2);

    sink.close().await.unwrap();
    wait_until(
        async || harness.gateway_state(&machine_id).await.as_deref() == Some("offline"),
        "a closed session must settle offline",
    )
    .await;
}

#[tokio::test]
async fn admission_refuses_a_missing_session_or_subprotocol() {
    let harness = harness().await;
    let keys = NodeKeys::generate();
    let (_, credential) = harness.enroll_node("gated", &keys).await;
    let session = harness.prove_session(&credential, &keys).await;

    // No session header, subprotocol offered.
    let mut request = format!("ws://{}/api/node/v1/connect", harness.address)
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(NODE_SUBPROTOCOL),
    );
    let error = connect_async(request).await.unwrap_err();
    assert_eq!(
        upgrade_status(error),
        StatusCode::UNAUTHORIZED,
        "no session header"
    );

    // A session but no subprotocol offer.
    let mut request = format!("ws://{}/api/node/v1/connect", harness.address)
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "x-fleet-node-session",
        HeaderValue::from_str(&session).unwrap(),
    );
    let error = connect_async(request).await.unwrap_err();
    assert_eq!(
        upgrade_status(error),
        StatusCode::BAD_REQUEST,
        "no subprotocol"
    );

    // A forged session token.
    let error = connect_node(&harness, "fmns1.forged.0.0.0.0")
        .await
        .unwrap_err();
    assert_eq!(
        upgrade_status(error),
        StatusCode::UNAUTHORIZED,
        "a forged session"
    );
}

#[tokio::test]
async fn a_protocol_mismatch_is_answered_with_the_typed_fault() {
    let harness = harness().await;
    let keys = NodeKeys::generate();
    let (_, credential) = harness.enroll_node("behind", &keys).await;
    let session = harness.prove_session(&credential, &keys).await;

    let (stream, _) = connect_node(&harness, &session).await.unwrap();
    let (mut sink, mut source) = stream.split();
    // A node that only speaks v9 is ahead of this controller: the fault
    // names the peer that must move and carries the supported range.
    send_frame(&mut sink, hello_frame("any-machine", 9, 9)).await;
    let fault = receive_frame(&mut source).await.expect("a fault frame");
    let Some(wire::frame::Payload::Fault(fault)) = fault.payload else {
        panic!("a version mismatch must fault, not {:?}", fault.payload);
    };
    assert_eq!(
        fault.code,
        wire::FaultCode::ControllerUpgradeRequired as i32
    );
    let supported = fault
        .supported_protocol_versions
        .expect("the supported range");
    assert_eq!((supported.min, supported.max), (1, 1));
}

#[tokio::test]
async fn a_second_session_supersedes_the_first() {
    let harness = harness().await;
    let keys = NodeKeys::generate();
    let (machine_id, credential) = harness.enroll_node("superseded", &keys).await;

    let session_one = harness.prove_session(&credential, &keys).await;
    let session_two = harness.prove_session(&credential, &keys).await;

    let (first, _) = connect_node(&harness, &session_one).await.unwrap();
    let (mut first_sink, mut first_source) = first.split();
    send_frame(&mut first_sink, hello_frame(&machine_id, 1, 1)).await;

    let (second, _) = connect_node(&harness, &session_two).await.unwrap();
    let (mut _second_sink, mut second_source) = second.split();
    send_frame(&mut _second_sink, hello_frame(&machine_id, 1, 1)).await;

    // The new session negotiates normally.
    let welcome = receive_frame(&mut second_source).await.expect("a Welcome");
    let Some(wire::frame::Payload::Welcome(welcome)) = welcome.payload else {
        panic!(
            "the new session must be welcomed, not {:?}",
            welcome.payload
        );
    };

    // The old session first drains its own Welcome, then learns it was
    // superseded in the protocol's own vocabulary.
    let welcome_one = receive_frame(&mut first_source).await.expect("a Welcome");
    assert!(matches!(
        welcome_one.payload,
        Some(wire::frame::Payload::Welcome(_))
    ));
    let fault = receive_frame(&mut first_source).await.expect("a fault");
    let Some(wire::frame::Payload::Fault(fault)) = fault.payload else {
        panic!("the superseded session must fault, not {:?}", fault.payload);
    };
    assert_eq!(fault.code, wire::FaultCode::SessionRejected as i32);

    // The registry holds exactly the new session.
    let entry = harness
        .gateway
        .session_of(&machine_id)
        .await
        .expect("one session");
    assert_eq!(entry.boot_session, welcome.session_id);
}

#[tokio::test]
async fn a_quiet_session_goes_stale_and_a_heartbeat_recovers_it() {
    let harness = harness().await;
    let keys = NodeKeys::generate();
    let (machine_id, credential) = harness.enroll_node("quiet", &keys).await;

    let session = harness.prove_session(&credential, &keys).await;
    let (stream, _) = connect_node(&harness, &session).await.unwrap();
    let (mut sink, mut source) = stream.split();
    send_frame(&mut sink, hello_frame(&machine_id, 1, 1)).await;
    let _welcome = receive_frame(&mut source).await.expect("a Welcome");

    // A fast sweeper with a tiny staleness threshold stands in for the real
    // one's timing.
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let sweeper = harness.gateway.clone();
    let sweeper_task = tokio::spawn(sweeper.run_staleness_sweeper_with(
        Duration::from_millis(50),
        200,
        async move {
            let _ = done_rx.await;
        },
    ));

    // No heartbeat: the session goes stale and stays observable.
    wait_until(
        async || harness.gateway_state(&machine_id).await.as_deref() == Some("stale"),
        "a quiet session must go stale",
    )
    .await;

    // One heartbeat recovers it, and the state says connected again.
    send_frame(&mut sink, heartbeat_frame(1)).await;
    wait_until(
        async || harness.gateway_state(&machine_id).await.as_deref() == Some("connected"),
        "a heartbeat must recover a stale session",
    )
    .await;

    let _ = done_tx.send(());
    let _ = sweeper_task.await;
}

// ---------------------------------------------------------------------------
// Command dispatch (FM-207)
// ---------------------------------------------------------------------------

/// Starts a real fleetd gateway loop against the harness and waits for its
/// session to register.
async fn start_real_node(
    harness: &Harness,
    name: &str,
) -> (std::path::PathBuf, String, tokio::sync::oneshot::Sender<()>) {
    let state_dir = tempfile::tempdir().unwrap().keep();
    let node_state = std::sync::Arc::new(fleetd::state::NodeState::open(&state_dir).unwrap());
    let machine_id = harness.register_machine(name).await;
    let (status, body) = harness
        .post_json(
            &format!("/api/v1/machines/{machine_id}/node/enrollments"),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = body["data"]["token"].as_str().unwrap();
    let controller = fleetd::http::Controller::parse(&format!("http://{}", harness.address))
        .expect("the harness URL parses");
    // The node's HTTP client is deliberately blocking; keep it off the
    // test runtime's only thread.
    tokio::task::spawn_blocking({
        let controller = controller.clone();
        let node_state = node_state.clone();
        let token = token.to_owned();
        move || fleetd::session::enroll(&controller, &node_state, &token)
    })
    .await
    .expect("the enroll task must not panic")
    .expect("the real node must enroll");
    // Enrollment persists to the state directory; the run loop reloads it
    // the way a fresh `fleetd run` process would.
    let node_state = std::sync::Arc::new(
        fleetd::state::NodeState::open(&state_dir).expect("the enrolled state must reopen"),
    );
    let journal = std::sync::Arc::new(
        fleetd::journal::NodeJournal::open(&state_dir.join("journal.ndjson"))
            .map_err(|error| error.to_string())
            .unwrap(),
    );
    let inventory = std::sync::Arc::new(
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
    // The gateway loop proves and connects within its bounded backoff.
    wait_until(
        async || harness.gateway.session_of(&machine_id).await.is_some(),
        "the real node's gateway session must register",
    )
    .await;
    (state_dir, machine_id, shutdown_tx)
}

#[tokio::test]
async fn a_node_operation_dispatches_and_completes() {
    let harness = harness().await;
    let (_state_dir, machine_id, shutdown) = start_real_node(&harness, "dispatched").await;

    let operation = harness
        .create_node_operation("node.noop", &machine_id, None)
        .await;
    let report = harness.tick().await;
    assert!(report.completed, "{report:?}");

    let finished = harness
        .operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &operation.id,
        )
        .await
        .expect("the operation must read");
    assert_eq!(
        finished.state,
        "succeeded",
        "{}",
        finished.error_json.unwrap_or_default()
    );
    let result: Value = serde_json::from_str(&finished.result_json.expect("a result")).unwrap();
    assert_eq!(result["status"], "succeeded");
    let _ = shutdown.send(());
}

#[tokio::test]
async fn a_redelivered_command_replays_the_journaled_result_without_reexecution() {
    let harness = harness().await;
    let (_state_dir, machine_id, shutdown) = start_real_node(&harness, "journal").await;

    // First diagnostic run: the journal gains one record.
    let first = harness
        .create_node_operation("node.diagnostic", &machine_id, None)
        .await;
    assert!(harness.tick().await.completed);
    let first_finished = harness
        .operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &first.id,
        )
        .await
        .unwrap();
    let first_result: Value = serde_json::from_str(&first_finished.result_json.unwrap()).unwrap();
    let first_payload: Value =
        serde_json::from_str(first_result["payload"].as_str().unwrap()).unwrap();

    // A second operation executes and gains its own record.
    let second = harness
        .create_node_operation("node.diagnostic", &machine_id, None)
        .await;
    assert!(harness.tick().await.completed);
    let second_finished = harness
        .operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &second.id,
        )
        .await
        .unwrap();
    let second_result: Value = serde_json::from_str(&second_finished.result_json.unwrap()).unwrap();
    let second_payload: Value =
        serde_json::from_str(second_result["payload"].as_str().unwrap()).unwrap();
    assert_ne!(
        first_payload["journalRecords"], second_payload["journalRecords"],
        "a fresh execution observes a grown journal"
    );

    // Redelivering the FIRST command replays its journaled result verbatim —
    // the stale journalRecords value proves it was not re-executed.
    let redelivered = harness
        .gateway
        .dispatch(
            &machine_id,
            wire::Command {
                operation_id: first.id.clone(),
                kind: "node.diagnostic".to_owned(),
                kind_schema_version: 1,
                deadline_unix_millis: i64::MAX,
                idempotency_key: String::new(),
                authorization_digest: String::new(),
                max_output_bytes: 256 * 1024,
                cancellation: wire::CancellationPolicy::BestEffort as i32,
                payload: Vec::new(),
            },
        )
        .await
        .expect("the redelivery must be answered from the journal");
    let replayed: Value =
        serde_json::from_str(&String::from_utf8_lossy(&redelivered.payload)).unwrap();
    assert_eq!(
        replayed, first_payload,
        "the replay is the original result, not a new execution"
    );
    let _ = shutdown.send(());
}

#[tokio::test]
async fn a_dispatch_to_an_offline_node_fails_the_operation_honestly() {
    let harness = harness().await;
    let operation = harness
        .create_node_operation("node.noop", "01990000-0000-7000-8000-000000000000", None)
        .await;
    let report = harness.tick().await;
    assert!(report.completed);
    let finished = harness
        .operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &operation.id,
        )
        .await
        .unwrap();
    assert_eq!(finished.state, "failed");
    let error: Value = serde_json::from_str(&finished.error_json.unwrap()).unwrap();
    assert_eq!(error["reason"], "step_failed");
    assert!(
        error["detail"].as_str().unwrap().contains("not connected"),
        "{}",
        error["detail"]
    );
}

#[tokio::test]
async fn a_silent_node_times_the_operation_out_at_its_deadline() {
    let harness = harness().await;
    // A hand-rolled node that negotiates and then ignores commands.
    let keys = NodeKeys::generate();
    let (machine_id, credential) = harness.enroll_node("silent", &keys).await;
    let session = harness.prove_session(&credential, &keys).await;
    let (stream, _) = connect_node(&harness, &session).await.unwrap();
    let (mut sink, mut source) = stream.split();
    send_frame(&mut sink, hello_frame(&machine_id, 1, 1)).await;
    let _welcome = receive_frame(&mut source).await.expect("a Welcome");

    let deadline = fleet_core::SystemClock::now_unix_millis() + 400;
    let operation = harness
        .create_node_operation("node.noop", &machine_id, Some(deadline))
        .await;
    let report = harness.tick().await;
    assert!(report.completed);
    let finished = harness
        .operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &operation.id,
        )
        .await
        .unwrap();
    assert_eq!(
        finished.state,
        "timed_out",
        "{}",
        finished.result_json.unwrap_or_default()
    );
    sink.close().await.unwrap();
}

#[tokio::test]
async fn the_in_flight_bound_refuses_a_dispatch_beyond_flow_control() {
    let harness = harness().await;
    let keys = NodeKeys::generate();
    let (machine_id, credential) = harness.enroll_node("backpressure", &keys).await;
    let session = harness.prove_session(&credential, &keys).await;
    let (stream, _) = connect_node(&harness, &session).await.unwrap();
    let (mut _sink, mut source) = stream.split();
    send_frame(&mut _sink, hello_frame(&machine_id, 1, 1)).await;
    let _welcome = receive_frame(&mut source).await.expect("a Welcome");

    // Fill every in-flight slot against a node that never replies.
    let command = |operation_id: String| wire::Command {
        operation_id,
        kind: "node.noop".to_owned(),
        kind_schema_version: 1,
        deadline_unix_millis: i64::MAX,
        idempotency_key: String::new(),
        authorization_digest: String::new(),
        max_output_bytes: 1024,
        cancellation: wire::CancellationPolicy::BestEffort as i32,
        payload: Vec::new(),
    };
    let mut pending = Vec::new();
    for index in 0..32_u32 {
        let gateway = harness.gateway.clone();
        let machine = machine_id.clone();
        let dispatch = async move {
            gateway
                .dispatch(&machine, command(format!("op-flood-{index}")))
                .await
        };
        pending.push(tokio::spawn(async move {
            // Each dispatch awaits its own result; keep them alive briefly.
            tokio::time::timeout(Duration::from_secs(2), dispatch).await
        }));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let beyond = harness
        .gateway
        .dispatch(&machine_id, command("op-beyond".to_owned()))
        .await;
    match beyond {
        Err(fleet_controller::gateway::DispatchError::Backpressure { limit }) => {
            assert_eq!(limit, 32);
        }
        other => panic!("the 33rd dispatch must hit the bound, not {other:?}"),
    }
    // Release the slots.
    for task in pending {
        let _ = task.await;
    }
}

#[tokio::test]
async fn an_inventory_operation_records_facts_and_the_snapshot() {
    let harness = harness().await;
    let (_state_dir, machine_id, shutdown) = start_real_node(&harness, "inventoried").await;

    // First collection: a full snapshot, ingested as facts + a snapshot row.
    let first = harness
        .create_node_operation("node.inventory", &machine_id, None)
        .await;
    let report = harness.tick().await;
    assert!(report.completed, "{report:?}");
    let finished = harness
        .operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &first.id,
        )
        .await
        .unwrap();
    assert_eq!(
        finished.state,
        "succeeded",
        "{}",
        finished.error_json.unwrap_or_default()
    );
    let result: Value = serde_json::from_str(&finished.result_json.unwrap()).unwrap();
    assert_eq!(result["mode"], "full");
    let fact_count = result["facts"].as_i64().unwrap();
    assert!(fact_count >= 2, "os family and arch at minimum: {result}");

    let os_family: Option<(String,)> = sqlx::query_as(
        "SELECT value FROM machine_capabilities WHERE machine_id = ?1          AND namespace = 'os' AND name = 'family'",
    )
    .bind(&machine_id)
    .fetch_optional(&harness.pool)
    .await
    .expect("the facts query must run");
    assert_eq!(os_family.expect("the os fact").0, std::env::consts::OS);
    let snapshots: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM inventory_snapshots WHERE machine_id = ?1 AND source LIKE 'fleetd/%'",
    )
    .bind(&machine_id)
    .fetch_one(&harness.pool)
    .await
    .expect("the snapshot query must run");
    assert!(snapshots >= 1, "the snapshot row must be recorded");

    // Second collection: a delta with no changes is still recorded.
    let second = harness
        .create_node_operation("node.inventory", &machine_id, None)
        .await;
    assert!(harness.tick().await.completed);
    let finished = harness
        .operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &second.id,
        )
        .await
        .unwrap();
    let result: Value = serde_json::from_str(&finished.result_json.unwrap()).unwrap();
    assert_eq!(result["mode"], "delta", "{result}");
    assert_eq!(result["facts"], 0, "nothing changed between the rounds");

    // A stale expected revision forces a full snapshot (the gap rule).
    let body = harness
        .gateway
        .dispatch(
            &machine_id,
            wire::Command {
                operation_id: "op-gap-test".to_owned(),
                kind: "node.inventory".to_owned(),
                kind_schema_version: 1,
                deadline_unix_millis: i64::MAX,
                idempotency_key: String::new(),
                authorization_digest: String::new(),
                max_output_bytes: 256 * 1024,
                cancellation: wire::CancellationPolicy::BestEffort as i32,
                payload: serde_json::json!({ "expectedRevision": 99 })
                    .to_string()
                    .into_bytes(),
            },
        )
        .await
        .expect("the gap dispatch must be answered");
    assert_eq!(
        body.status,
        fleet_protocol::wire::ResultStatus::Succeeded as i32
    );
    let gap_report: Value = serde_json::from_str(&String::from_utf8_lossy(&body.payload)).unwrap();
    assert_eq!(gap_report["mode"], "full", "{gap_report}");
    let _ = shutdown.send(());
}
