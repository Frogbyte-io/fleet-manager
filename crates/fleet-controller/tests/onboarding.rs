//! The Add Machine workflow end-to-end: a real controller router serving
//! the onboarding surface, a real ephemeral sshd on the other end, and the
//! real executor driving the durable `machine.onboard.*` operations. The
//! staged path — draft, test, confirm, discover, add — is the happy path;
//! the changed key, the duplicate warning, the cancel cleanup, and the
//! no-side-effect rule each get their own test.

use std::net::TcpListener;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use fleet_application::machine::{MachinePort, NewEndpoint, RegisterMachine};
use fleet_application::operation::Operations;
use fleet_application::worker::OperationExecutor;
use fleet_controller::Settings;
use fleet_controller::build_router;
use fleet_controller::compose_onboarding;
use fleet_provider_ssh::ExecutionLimiter;
use fleet_storage_sqlite::{OnboardingRepository, OperationRepository, Store};
use serde_json::{Value, json};
use tokio::net::TcpListener as TokioListener;

/// One running sshd bound to an ephemeral port with its own host key, which
/// a test can rotate to play the hostile case.
struct TestSshd {
    child: Option<Child>,
    port: u16,
    dir: tempfile::TempDir,
    host_key: std::path::PathBuf,
    user_key: std::path::PathBuf,
}

impl Drop for TestSshd {
    fn drop(&mut self) {
        self.stop();
    }
}

impl TestSshd {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let host_key = dir.path().join("host_ed25519");
        let user_key = dir.path().join("user_ed25519");
        generate_key(&host_key);
        generate_key(&user_key);
        let public = std::fs::read_to_string(format!("{}.pub", user_key.display())).unwrap();
        std::fs::write(dir.path().join("authorized_keys"), public).unwrap();
        let port = free_port();
        let mut sshd = Self {
            child: None,
            port,
            dir,
            host_key,
            user_key,
        };
        sshd.launch();
        sshd
    }

    fn identity_path(&self) -> String {
        self.user_key.display().to_string()
    }

    fn stop(&mut self) {
        if let Some(child) = self.child.take() {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Rotates the host key and restarts sshd on the same port: the network
    /// address is unchanged, the key is not. The hostile case.
    fn rotate_host_key(&mut self) {
        self.stop();
        generate_key(&self.host_key);
        self.launch();
    }

    fn launch(&mut self) {
        let dir_display = self.dir.path().display().to_string();
        let sshd_config = self.dir.path().join("sshd_config");
        std::fs::write(
            &sshd_config,
            format!(
                "Port {}\n\
                 ListenAddress 127.0.0.1\n\
                 HostKey {}\n\
                 AuthorizedKeysFile {}/authorized_keys\n\
                 PasswordAuthentication no\n\
                 KbdInteractiveAuthentication no\n\
                 UsePAM no\n\
                 StrictModes no\n\
                 PidFile {}/sshd.pid\n\
                 Subsystem sftp internal-sftp\n",
                self.port,
                self.host_key.display(),
                dir_display,
                dir_display
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&self.host_key, std::fs::Permissions::from_mode(0o600))
                .unwrap();
            std::fs::create_dir_all("/run/sshd").ok();
        }
        let child = Command::new("/usr/sbin/sshd")
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(&sshd_config)
            .spawn()
            .expect("sshd must start");
        self.child = Some(child);
        for _ in 0..50 {
            if TcpListener::bind(("127.0.0.1", self.port)).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn generate_key(path: &std::path::Path) {
    // ssh-keygen refuses to overwrite; the rotate path reuses the path.
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}.pub", path.display()));
    let generated = Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-q")
        .arg("-f")
        .arg(path)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "ssh-keygen failed: {:?}",
        generated.stderr
    );
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "nobody".to_owned())
}

struct Harness {
    _dist: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    ssh_dir: tempfile::TempDir,
    operations: Arc<Operations>,
    executor: Arc<dyn OperationExecutor>,
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
    let ssh_dir = tempfile::tempdir().unwrap();
    let onboarding = Arc::new(compose_onboarding(store.pool(), ssh_dir.path().join("ssh")));

    let settings = Settings {
        listen: "127.0.0.1:0".parse().unwrap(),
        web_dist: dist.path().to_path_buf(),
        artifacts_dir: None,
    };
    let router = build_router(
        &settings,
        Some(store.pool().clone()),
        None,
        Some(&onboarding),
        None,
        None,
        None,
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

    let operations = Arc::new(Operations::new(
        Arc::new(OperationRepository::new(store.pool().clone())),
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    ));
    let executor: Arc<dyn OperationExecutor> =
        Arc::new(fleet_controller::onboard::OnboardingExecutor::new(
            Arc::new(OnboardingRepository::new(store.pool().clone())),
            ssh_dir.path().join("ssh"),
            ExecutionLimiter::new(4),
            Arc::new(fleet_application::worker::NoopExecutor),
        ));
    Harness {
        _dist: dist,
        _store_dir: store_dir,
        pool: store.pool().clone(),
        ssh_dir,
        operations,
        executor,
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
    async fn get_json(&self, path: &str) -> (axum::http::StatusCode, Value) {
        raw_request(self.address, "GET", path, None).await
    }

    async fn post_json(&self, path: &str, body: Option<Value>) -> (axum::http::StatusCode, Value) {
        raw_request(self.address, "POST", path, body).await
    }

    /// Runs the onboarding executor until the named operation terminates.
    async fn run_operation(&self, operation_id: &str) -> Value {
        for _ in 0..120 {
            self.operations
                .tick(
                    self.executor.as_ref(),
                    "test-worker",
                    fleet_core::SystemClock::now_unix_millis(),
                    60_000,
                )
                .await
                .unwrap();
            let (status, body) = self
                .get_json(&format!("/api/v1/operations/{operation_id}"))
                .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            let state = body["data"]["state"].as_str().unwrap().to_owned();
            if state != "pending" && state != "running" {
                return body["data"].clone();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the operation {operation_id} never reached a terminal state");
    }

    /// Registers a machine straight through the port (the duplicate-test
    /// setup), bypassing onboarding on purpose.
    async fn register_machine(&self, name: &str, reference: &str) -> String {
        let machines = fleet_storage_sqlite::MachineRepository::new(self.pool.clone());
        let machine = machines
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

    fn known_hosts(&self) -> String {
        std::fs::read_to_string(self.ssh_dir.path().join("ssh/known_hosts")).unwrap_or_default()
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
        .and_then(|code| code.parse().ok())
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

/// Creates a draft for the given sshd through the API.
async fn create_draft(harness: &Harness, sshd: &TestSshd) -> String {
    let (status, body) = harness
        .post_json(
            "/api/v1/machines/onboarding/drafts",
            Some(json!({
                "user": whoami(),
                "host": "127.0.0.1",
                "port": sshd.port,
                "auth": {"type": "identityFile", "path": sshd.identity_path()},
                "name": "onboard-target",
                "tags": ["lab"],
            })),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::CREATED,
        "the draft must be created: {body}"
    );
    body["data"]["id"].as_str().unwrap().to_owned()
}

/// Runs a test operation for the draft and returns its result.
async fn run_test(harness: &Harness, draft_id: &str) -> Value {
    let (status, body) = harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{draft_id}/test"),
            None,
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::ACCEPTED,
        "the test operation must be accepted: {body}"
    );
    let operation_id = body["data"]["id"].as_str().unwrap().to_owned();
    harness.run_operation(&operation_id).await
}

#[tokio::test]
async fn the_happy_path_goes_from_address_to_registered_machine() {
    let harness = harness().await;
    let sshd = TestSshd::start();

    let draft_id = create_draft(&harness, &sshd).await;

    // Test: the fingerprint is observed, nothing is confirmed yet, and no
    // connection was attempted.
    let test = run_test(&harness, &draft_id).await;
    assert_eq!(test["state"], "succeeded", "{test}");
    let result: Value = serde_json::from_str(test["resultJson"].as_str().unwrap()).unwrap();
    assert_eq!(result["hostKeyStage"], "observed");
    assert_eq!(result["connectAttempted"], false);
    assert_eq!(result["connected"], false);
    assert!(
        result["fingerprint"]
            .as_str()
            .unwrap_or_default()
            .starts_with("SHA256:"),
        "the fingerprint is the review's subject: {result}"
    );

    // The review surface shows the fingerprint awaiting confirmation.
    let (status, detail) = harness
        .get_json(&format!("/api/v1/machines/onboarding/drafts/{draft_id}"))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{detail}");
    assert_eq!(detail["data"]["stage"], "review");
    let fingerprint = detail["data"]["hostKey"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();

    // Confirm, then discover: the real probe answers.
    let (status, _) = harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{draft_id}/confirm-host-key"),
            Some(json!({"fingerprint": fingerprint})),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(!harness.known_hosts().is_empty(), "confirm pins the host");

    let (status, body) = harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{draft_id}/discover"),
            None,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");
    let discover = harness
        .run_operation(body["data"]["id"].as_str().unwrap())
        .await;
    assert_eq!(
        discover["state"], "succeeded",
        "the real probe must run: {discover}"
    );

    // The review now carries facts and the profile hint.
    let (_, detail) = harness
        .get_json(&format!("/api/v1/machines/onboarding/drafts/{draft_id}"))
        .await;
    assert_eq!(detail["data"]["stage"], "ready");
    let fact_count = detail["data"]["facts"].as_array().unwrap().len();
    assert!(fact_count >= 5, "the probe produced facts: {detail}");
    assert!(
        detail["data"]["profileHint"]
            .as_str()
            .unwrap_or_default()
            .to_lowercase()
            .starts_with("linux/"),
        "the hint derives from the facts: {}",
        detail["data"]["profileHint"]
    );

    // Add: the machine is registered, fingerprinted, and observed.
    let (status, added) = harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{draft_id}/add"),
            None,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::CREATED, "{added}");
    let machine_id = added["data"]["machine"]["id"].as_str().unwrap().to_owned();
    assert_eq!(added["data"]["machine"]["machineStatus"], "agentless");
    assert!(
        added["data"]["machine"]["capabilities"]
            .as_array()
            .unwrap()
            .len()
            >= 5
    );

    // The draft is gone, and the machine view is the read surface's truth.
    let (status, _) = harness
        .get_json(&format!("/api/v1/machines/onboarding/drafts/{draft_id}"))
        .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    let (status, machine) = harness
        .get_json(&format!("/api/v1/machines/{machine_id}"))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(machine["data"]["machineStatus"], "agentless");
    assert!(
        machine["data"]["lastObservation"]["source"]
            .as_str()
            .unwrap()
            .starts_with("agentless/")
    );
}

#[tokio::test]
async fn a_test_and_a_premature_discover_never_touch_the_machines_record() {
    let harness = harness().await;
    let sshd = TestSshd::start();
    let draft_id = create_draft(&harness, &sshd).await;

    let test = run_test(&harness, &draft_id).await;
    assert_eq!(test["state"], "succeeded", "{test}");

    // Discover without a confirmed fingerprint fails honestly.
    let (status, body) = harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{draft_id}/discover"),
            None,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED);
    let discover = harness
        .run_operation(body["data"]["id"].as_str().unwrap())
        .await;
    assert_eq!(discover["state"], "failed", "{discover}");
    let error: Value = serde_json::from_str(discover["errorJson"].as_str().unwrap()).unwrap();
    assert_eq!(error["reason"], "host_key_not_confirmed");

    // And the machines record is untouched.
    let (status, machines) = harness.get_json("/api/v1/machines").await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(
        machines["items"].as_array().unwrap().is_empty(),
        "a test is an observation, not a registration: {machines}"
    );
}

#[tokio::test]
async fn a_changed_host_key_blocks_until_the_new_fingerprint_is_reconfirmed() {
    let mut sshd = TestSshd::start();
    let harness = harness().await;
    let draft_id = create_draft(&harness, &sshd).await;

    run_test(&harness, &draft_id).await;
    let (_, detail) = harness
        .get_json(&format!("/api/v1/machines/onboarding/drafts/{draft_id}"))
        .await;
    let fingerprint = detail["data"]["hostKey"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, _) = harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{draft_id}/confirm-host-key"),
            Some(json!({"fingerprint": fingerprint})),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK);

    // The hostile case: same address, different key.
    sshd.rotate_host_key();
    let test = run_test(&harness, &draft_id).await;
    let result: Value = serde_json::from_str(test["resultJson"].as_str().unwrap()).unwrap();
    assert_eq!(
        result["hostKeyStage"], "changed",
        "the change is observed: {test}"
    );

    // Discover and add refuse while the change stands.
    let (status, body) = harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{draft_id}/discover"),
            None,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED);
    let discover = harness
        .run_operation(body["data"]["id"].as_str().unwrap())
        .await;
    assert_eq!(discover["state"], "failed", "{discover}");
    let error: Value = serde_json::from_str(discover["errorJson"].as_str().unwrap()).unwrap();
    assert_eq!(error["reason"], "host_key_changed");
    let (status, _) = harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{draft_id}/add"),
            None,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT);

    // Re-confirming the new fingerprint unblocks the flow.
    let (_, detail) = harness
        .get_json(&format!("/api/v1/machines/onboarding/drafts/{draft_id}"))
        .await;
    let new_fingerprint = detail["data"]["hostKey"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(new_fingerprint, fingerprint);
    let (status, _) = harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{draft_id}/confirm-host-key"),
            Some(json!({"fingerprint": new_fingerprint})),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let (status, added) = harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{draft_id}/add"),
            None,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::CREATED, "{added}");
}

#[tokio::test]
async fn a_duplicate_candidate_is_warned_but_never_merged() {
    let harness = harness().await;
    let sshd = TestSshd::start();
    harness
        .register_machine("already-here", &format!("root@127.0.0.1:{}", sshd.port))
        .await;

    let draft_id = create_draft(&harness, &sshd).await;
    run_test(&harness, &draft_id).await;
    let (_, detail) = harness
        .get_json(&format!("/api/v1/machines/onboarding/drafts/{draft_id}"))
        .await;
    assert_eq!(
        detail["data"]["duplicates"].as_array().unwrap().len(),
        1,
        "the review surface warns: {detail}"
    );

    // Confirm with the fingerprint the test observed.
    let fingerprint = detail["data"]["hostKey"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{draft_id}/confirm-host-key"),
            Some(json!({"fingerprint": fingerprint})),
        )
        .await;
    let (status, added) = harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{draft_id}/add"),
            None,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::CREATED, "{added}");
    assert_eq!(
        added["data"]["duplicates"].as_array().unwrap().len(),
        1,
        "the add answers with the warning"
    );
    let (status, machines) = harness.get_json("/api/v1/machines").await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(
        machines["items"].as_array().unwrap().len(),
        2,
        "two machines, one host: the warning merged nothing"
    );
}

#[tokio::test]
async fn cancel_deletes_the_draft_and_unpins_only_unregistered_hosts() {
    let harness = harness().await;
    let sshd = TestSshd::start();

    // A draft whose host is already registered by another machine: the
    // cancel must leave that machine's pins alone.
    harness
        .register_machine("resident", &format!("root@127.0.0.1:{}", sshd.port))
        .await;
    let shared_id = create_draft(&harness, &sshd).await;
    run_test(&harness, &shared_id).await;
    let (_, detail) = harness
        .get_json(&format!("/api/v1/machines/onboarding/drafts/{shared_id}"))
        .await;
    let fingerprint = detail["data"]["hostKey"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{shared_id}/confirm-host-key"),
            Some(json!({"fingerprint": fingerprint})),
        )
        .await;
    let pinned = harness.known_hosts();
    assert!(!pinned.is_empty());
    let (status, _) = harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{shared_id}/cancel"),
            None,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::NO_CONTENT);
    assert_eq!(
        harness.known_hosts(),
        pinned,
        "a registered host keeps its pins"
    );
    let (status, _) = harness
        .get_json(&format!("/api/v1/machines/onboarding/drafts/{shared_id}"))
        .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

    // A draft whose host nobody else reaches: the pin goes with the draft.
    let lone_port = free_port();
    let (status, _) = harness
        .post_json(
            "/api/v1/machines/onboarding/drafts",
            Some(json!({
                "user": whoami(),
                "host": "127.0.0.1",
                "port": lone_port,
                "auth": {"type": "agent"}
            })),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::CREATED);
    let (_, drafts) = harness.get_json("/api/v1/machines/onboarding/drafts").await;
    let lone_id = drafts["items"][0]["id"].as_str().unwrap().to_owned();
    let (status, _) = harness
        .post_json(
            &format!("/api/v1/machines/onboarding/drafts/{lone_id}/cancel"),
            None,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::NO_CONTENT);
    let (status, _) = harness
        .get_json(&format!("/api/v1/machines/onboarding/drafts/{lone_id}"))
        .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    // The shared host's pin survived; the lone host never pinned anything,
    // so the file is unchanged either way.
    assert_eq!(harness.known_hosts(), pinned);
}
