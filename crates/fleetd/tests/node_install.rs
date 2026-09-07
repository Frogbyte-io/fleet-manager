//! The node-install bootstrap end to end, hermetically: a real controller
//! router, a real sshd, and the real `fleetd` binary — packaged, served from
//! the controller's download surface, installed with stubbed systemd, and
//! enrolled through the single-use token. The executor's bounded connect
//! wait is satisfied by the real node loop.
//!
//! The tests also pin the two security properties that make this bootstrap
//! honest: a wrong digest refuses to install and leaves the agentless
//! endpoint usable, and the enrollment token leaves no trace in the
//! operation's JSON or on the node's disk.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use fleet_application::machine::MachinePort as _;
use fleet_application::operation::OperationPort as _;
use fleet_controller::Settings;
use fleet_controller::build_router;
use fleet_controller::compose_node_services;
use fleet_controller::exec::ScriptExecutor;
use fleet_controller::install::InstallExecutor;
use fleet_controller::onboard::OnboardingExecutor;
use fleet_provider_ssh::ExecutionLimiter;
use fleet_secrets::SecretStore;
use fleet_storage_sqlite::{MachineRepository, OnboardingRepository, OperationRepository, Store};
use serde_json::{Value, json};
use tokio::net::TcpListener as TokioListener;

/// One running sshd bound to an ephemeral port with its own host key.
struct TestSshd {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
    user_key: PathBuf,
}

impl Drop for TestSshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start_sshd() -> TestSshd {
    let dir = tempfile::tempdir().unwrap();
    let host_key = dir.path().join("host_ed25519");
    let user_key = dir.path().join("user_ed25519");
    for key in [&host_key, &user_key] {
        let generated = Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-q")
            .arg("-f")
            .arg(key)
            .output()
            .unwrap();
        assert!(
            generated.status.success(),
            "ssh-keygen failed: {:?}",
            generated.stderr
        );
    }
    let public = std::fs::read_to_string(format!("{}.pub", user_key.display())).unwrap();
    std::fs::write(dir.path().join("authorized_keys"), public).unwrap();
    let port = free_port();
    let dir_display = dir.path().display().to_string();
    let sshd_config = dir.path().join("sshd_config");
    std::fs::write(
        &sshd_config,
        format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {dir_display}/host_ed25519\n\
             AuthorizedKeysFile {dir_display}/authorized_keys\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             UsePAM no\n\
             StrictModes no\n\
             PidFile {dir_display}/sshd.pid\n\
             Subsystem sftp internal-sftp\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&host_key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::create_dir_all("/run/sshd").ok();
    }
    let child = Command::new("/usr/sbin/sshd")
        .arg("-D")
        .arg("-e")
        .arg("-f")
        .arg(&sshd_config)
        .spawn()
        .expect("sshd must start");
    for _ in 0..50 {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    TestSshd {
        child,
        port,
        _dir: dir,
        user_key,
    }
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "nobody".to_owned())
}

struct Harness {
    _dist: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    artifacts: tempfile::TempDir,
    ssh_dir: tempfile::TempDir,
    operations: Arc<fleet_application::operation::Operations>,
    nodes: Arc<fleet_application::node::Nodes>,
    pool: sqlx::SqlitePool,
    install_executor: Arc<dyn fleet_application::worker::OperationExecutor>,
    inventory_executor: Arc<dyn fleet_application::worker::OperationExecutor>,
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
    let secrets = SecretStore::open(store.pool().clone(), &key_path).unwrap();
    let crypto = fleet_controller::node_crypto::NodeCryptoService::open(&secrets)
        .await
        .expect("the node signing key must provision");
    let services = compose_node_services(store.pool(), Arc::new(crypto));
    let ssh_dir = tempfile::tempdir().unwrap();
    let artifacts = tempfile::tempdir().unwrap();

    let settings = Settings {
        listen: "127.0.0.1:0".parse().unwrap(),
        web_dist: dist.path().to_path_buf(),
        artifacts_dir: Some(artifacts.path().to_path_buf()),
    };
    let router = build_router(&settings, Some(store.pool().clone()), Some(&services), None);
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

    let operations = Arc::new(fleet_application::operation::Operations::new(
        Arc::new(OperationRepository::new(store.pool().clone())),
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    ));
    let limiter = ExecutionLimiter::new(4);
    let machines = Arc::new(MachineRepository::new(store.pool().clone()));
    let ssh_fallback: Arc<dyn fleet_application::worker::OperationExecutor> =
        Arc::new(ScriptExecutor::new(
            machines.clone(),
            ssh_dir.path().join("ssh"),
            limiter.clone(),
        ));
    let onboarding_executor: Arc<dyn fleet_application::worker::OperationExecutor> =
        Arc::new(OnboardingExecutor::new(
            Arc::new(OnboardingRepository::new(store.pool().clone())),
            ssh_dir.path().join("ssh"),
            limiter.clone(),
            ssh_fallback.clone(),
        ));
    let install_executor: Arc<dyn fleet_application::worker::OperationExecutor> =
        Arc::new(InstallExecutor::new(
            machines.clone(),
            services.nodes.clone(),
            services.gateway.clone(),
            ssh_dir.path().join("ssh"),
            limiter,
            Some(artifacts.path().to_path_buf()),
            onboarding_executor,
        ));
    Harness {
        _dist: dist,
        _store_dir: store_dir,
        artifacts,
        ssh_dir,
        operations,
        nodes: services.nodes.clone(),
        pool: store.pool().clone(),
        install_executor,
        inventory_executor: ssh_fallback,
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

    /// Registers an agentless machine with a verified fingerprint: the trust
    /// workflow already ran.
    async fn register_machine(&self, sshd: &TestSshd) -> (String, String) {
        self.register_named(sshd, "install-target").await
    }

    async fn register_named(&self, sshd: &TestSshd, name: &str) -> (String, String) {
        let machines = MachineRepository::new(self.pool.clone());
        let machine = machines
            .register(&fleet_application::machine::RegisterMachine {
                name: name.to_owned(),
                description: String::new(),
                endpoints: vec![fleet_application::machine::NewEndpoint {
                    kind: fleet_core::EndpointKind::Ssh,
                    reference: format!("{}@127.0.0.1:{}", whoami(), sshd.port),
                }],
                tags: Vec::new(),
                groups: Vec::new(),
            })
            .await
            .unwrap();
        let endpoint_id = machine.endpoints[0].id.clone();
        // The pin must land in the same trust store the executors use.
        let provider =
            fleet_provider_ssh::SshProvider::new(self.ssh_dir.path().join("ssh")).unwrap();
        let observation = provider
            .probe_host_key("127.0.0.1", sshd.port, Duration::from_secs(10))
            .unwrap();
        provider.pin(&observation).unwrap();
        machines
            .confirm_fingerprint(&endpoint_id, &observation.fingerprint, 0)
            .await
            .unwrap();
        (machine.id, endpoint_id)
    }

    async fn create_operation(&self, kind: &str, payload: Value) -> String {
        let operation = self
            .operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                "anonymous-lan-admin",
                &fleet_application::operation::NewOperation {
                    kind: kind.to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(payload.to_string()),
                },
            )
            .await
            .unwrap();
        operation.id
    }

    /// Runs the executor until the named operation terminates.
    async fn run_operation(
        &self,
        executor: &dyn fleet_application::worker::OperationExecutor,
        operation_id: &str,
    ) -> Value {
        for _ in 0..600 {
            self.operations
                .tick(
                    executor,
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
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the operation {operation_id} never reached a terminal state");
    }

    async fn node_view(&self, machine_id: &str) -> fleet_application::node::NodeView {
        self.nodes
            .node_view(
                &fleet_auth::LanAllowAllAuthorizer,
                &fleet_application::authz::ActingPrincipal {
                    id: "anonymous-lan-admin".to_owned(),
                },
                machine_id,
            )
            .await
            .unwrap()
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
        use std::fmt::Write as _;
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

/// The test package: the real `fleetd` binary plus the repository's unit and
/// scripts, packed as a tar.gz exactly like the xtask artifact.
struct TestPackage {
    archive: PathBuf,
    _dir: tempfile::TempDir,
}

impl TestPackage {
    fn build() -> Self {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("the fleetd crate lives in the workspace");
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(env!("CARGO_BIN_EXE_fleetd"), dir.path().join("fleetd")).unwrap();
        for name in ["fleetd.service", "install.sh", "uninstall.sh", "README.md"] {
            std::fs::copy(
                repo_root.join("deploy/fleetd").join(name),
                dir.path().join(name),
            )
            .unwrap();
        }
        for name in ["install.sh", "uninstall.sh", "fleetd"] {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mut perms = std::fs::metadata(dir.path().join(name))
                    .unwrap()
                    .permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(dir.path().join(name), perms).unwrap();
            }
        }
        let archive = dir.path().join("fleetd-test.tar.gz");
        let status = Command::new("tar")
            .current_dir(dir.path())
            .arg("-czf")
            .arg(&archive)
            .arg("fleetd")
            .arg("fleetd.service")
            .arg("install.sh")
            .arg("uninstall.sh")
            .arg("README.md")
            .status()
            .unwrap();
        assert!(status.success(), "tar must pack the test package");
        Self { archive, _dir: dir }
    }

    fn sha256(&self) -> String {
        let output = Command::new("sha256sum")
            .arg(&self.archive)
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned()
    }
}

/// The stubs: a systemctl that always reports active, a useradd that
/// records, and a runuser that just executes (the tests are unprivileged).
fn write_stubs(stubs_dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    std::fs::create_dir_all(stubs_dir).unwrap();
    let systemctl = stubs_dir.join("systemctl-stub");
    std::fs::write(
        &systemctl,
        "#!/bin/sh\ncase \"$1 $2\" in\n  \"is-active \"*) echo active; exit 0;;\nesac\necho \"systemctl $*\" >> \"$FLEETD_STUB_LOG\"\nexit 0\n",
    )
    .unwrap();
    let useradd = stubs_dir.join("useradd-stub");
    std::fs::write(
        &useradd,
        "#!/bin/sh\necho \"useradd $*\" >> \"$FLEETD_STUB_LOG\"\nexit 0\n",
    )
    .unwrap();
    let runuser = stubs_dir.join("runuser-stub");
    std::fs::write(
        &runuser,
        "#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do shift; done\nshift\nexec \"$@\"\n",
    )
    .unwrap();
    for stub in [&systemctl, &useradd, &runuser] {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = std::fs::metadata(stub).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(stub, perms).unwrap();
        }
    }
    (systemctl, useradd, runuser)
}

/// The install payload for one test machine, with the installer's layout
/// overrides pointed into test directories.
fn install_payload(
    machine_id: &str,
    endpoint_id: &str,
    sshd: &TestSshd,
    address: std::net::SocketAddr,
    package: &TestPackage,
    state_dir: &Path,
    stubs_dir: &Path,
) -> Value {
    let (systemctl, useradd, runuser) = write_stubs(stubs_dir);
    json!({
        "machineId": machine_id,
        "endpointId": endpoint_id,
        "auth": {"type": "identityFile", "path": sshd.user_key.display().to_string()},
        "timeoutSeconds": 120,
        "artifactUrl": format!("http://{address}/downloads/fleetd/fleetd-test.tar.gz"),
        "artifactSha256": package.sha256(),
        "installerEnv": [
            ["FLEETD_STATE_DIR", state_dir.display().to_string()],
            ["FLEETD_BIN_DIR", stubs_dir.join("bin").display().to_string()],
            ["FLEETD_UNIT_DIR", stubs_dir.join("unit").display().to_string()],
            ["FLEETD_ENV_FILE", stubs_dir.join("fleetd.env").display().to_string()],
            ["FLEETD_SYSTEMCTL", systemctl.display().to_string()],
            ["FLEETD_USER_ADD", useradd.display().to_string()],
            ["FLEETD_RUNUSER", runuser.display().to_string()],
            [
                "FLEETD_STUB_LOG",
                stubs_dir.join("stubs.log").display().to_string(),
            ],
        ],
    })
}

/// Publishes the package into the harness's artifacts directory.
fn publish(harness: &Harness, package: &TestPackage) {
    let dir = harness.artifacts.path().join("fleetd");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(&package.archive, dir.join("fleetd-test.tar.gz")).unwrap();
}

/// Spawns the real node loop for an enrolled state dir, once the install's
/// enrollment lands. `expect_credential_after` is the observation the loop
/// must see before starting: `None` means "as soon as the credential file
/// exists"; `Some(earlier)` means "after the credential is rewritten" (the
/// forced re-enrollment path).
fn spawn_node_loop(
    state_dir: PathBuf,
    controller: fleetd::http::Controller,
    expect_credential_after: Option<SystemTime>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for _ in 0..600 {
            let fresh = match std::fs::metadata(state_dir.join("credential")) {
                Ok(metadata) => {
                    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    expect_credential_after.is_none_or(|earlier| modified > earlier)
                }
                Err(_) => false,
            };
            if fresh {
                break;
            }
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let node_state = Arc::new(fleetd::state::NodeState::open(&state_dir).unwrap());
        assert!(
            node_state.credential().is_some(),
            "the install must have enrolled the node"
        );
        let journal = Arc::new(
            fleetd::journal::NodeJournal::open(&state_dir.join("journal.ndjson")).unwrap(),
        );
        let inventory = Arc::new(
            fleetd::inventory::InventoryState::open(&state_dir.join("inventory.json")).unwrap(),
        );
        let connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _ = fleetd::run_gateway_connected_with_status(
            controller,
            node_state,
            journal,
            inventory,
            connected,
            async move {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
        )
        .await;
    })
}

#[tokio::test]
async fn an_install_operation_enrolls_and_reaches_connected() {
    let harness = harness().await;
    let sshd = start_sshd();
    let (machine_id, endpoint_id) = harness.register_machine(&sshd).await;
    let package = TestPackage::build();
    publish(&harness, &package);

    let work = tempfile::tempdir().unwrap();
    let state_dir = work.path().join("state");
    let payload = install_payload(
        &machine_id,
        &endpoint_id,
        &sshd,
        harness.address,
        &package,
        &state_dir,
        &work.path().join("stubs"),
    );
    let operation_id = harness
        .create_operation("machine.install-fleetd", payload)
        .await;

    // The node loop starts as soon as the install's enrollment lands.
    let controller =
        fleetd::http::Controller::parse(&format!("http://{}", harness.address)).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loop_task = spawn_node_loop(state_dir.clone(), controller, None, stop.clone());

    let operation = harness
        .run_operation(harness.install_executor.as_ref(), &operation_id)
        .await;
    assert_eq!(operation["state"], "succeeded", "{operation}");
    let result: Value = serde_json::from_str(operation["resultJson"].as_str().unwrap()).unwrap();
    assert_eq!(result["connected"], true);
    assert_eq!(result["machineId"], machine_id.as_str());

    // The identity is bound, the token is consumed, and nothing pending
    // remains.
    let view = harness.node_view(&machine_id).await;
    let identity = view.identity.as_ref().expect("the machine is enrolled");
    assert_eq!(identity.status, fleet_application::node::NodeStatus::Active);
    assert_eq!(
        identity.gateway_state,
        fleet_application::node::GatewayState::Connected
    );
    assert!(view.pending_tokens.is_empty(), "the token was consumed");

    // The token left no trace: not in the operation's JSON, not on disk.
    let operation_text = operation.to_string();
    assert!(
        !operation_text.contains("fmtenr"),
        "the operation must not carry the token: {operation_text}"
    );
    for entry in std::fs::read_dir(&state_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            assert!(
                !text.contains("fmtenr"),
                "the token must never rest in the node state: {}",
                path.display()
            );
        }
    }

    // The state is owner-only, the key included.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&state_dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "the state dir is owner-only");
        let key_mode = std::fs::metadata(state_dir.join("node.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(key_mode & 0o777, 0o700, "the node key is owner-only");
    }

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = loop_task.await;
}

#[tokio::test]
async fn a_wrong_digest_fails_and_leaves_the_agentless_endpoint_usable() {
    let harness = harness().await;
    let sshd = start_sshd();
    let (machine_id, endpoint_id) = harness.register_machine(&sshd).await;
    let package = TestPackage::build();
    publish(&harness, &package);

    let work = tempfile::tempdir().unwrap();
    let mut payload = install_payload(
        &machine_id,
        &endpoint_id,
        &sshd,
        harness.address,
        &package,
        &work.path().join("state"),
        &work.path().join("stubs"),
    );
    payload["artifactSha256"] = json!("0".repeat(64));
    let operation_id = harness
        .create_operation("machine.install-fleetd", payload)
        .await;

    let operation = harness
        .run_operation(harness.install_executor.as_ref(), &operation_id)
        .await;
    assert_eq!(operation["state"], "failed", "{operation}");
    let error: Value = serde_json::from_str(operation["errorJson"].as_str().unwrap()).unwrap();
    assert_eq!(error["reason"], "install_failed", "{error}");
    assert!(
        error["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("digest"),
        "the refusal names the digest: {error}"
    );

    // The node was never enrolled, and the agentless surface still works.
    let view = harness.node_view(&machine_id).await;
    assert!(view.identity.is_none(), "no identity without enrollment");
    let inventory_id = harness
        .create_operation(
            "agentless.inventory",
            json!({
                "machineId": machine_id,
                "endpointId": endpoint_id,
                "auth": {"type": "identityFile", "path": sshd.user_key.display().to_string()},
                "timeoutSeconds": 60,
            }),
        )
        .await;
    let inventory = harness
        .run_operation(harness.inventory_executor.as_ref(), &inventory_id)
        .await;
    assert_eq!(inventory["state"], "succeeded", "{inventory}");
}

#[tokio::test]
async fn an_upgrade_installs_over_a_live_identity_without_minting_a_token() {
    let harness = harness().await;
    let sshd = start_sshd();
    let (machine_id, endpoint_id) = harness.register_machine(&sshd).await;
    let package = TestPackage::build();
    publish(&harness, &package);

    let work = tempfile::tempdir().unwrap();
    let state_dir = work.path().join("state");
    let payload = |package: &TestPackage| {
        install_payload(
            &machine_id,
            &endpoint_id,
            &sshd,
            harness.address,
            package,
            &state_dir,
            &work.path().join("stubs"),
        )
    };
    let first_id = harness
        .create_operation("machine.install-fleetd", payload(&package))
        .await;

    let controller =
        fleetd::http::Controller::parse(&format!("http://{}", harness.address)).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loop_task = spawn_node_loop(state_dir.clone(), controller, None, stop.clone());

    let first = harness
        .run_operation(harness.install_executor.as_ref(), &first_id)
        .await;
    assert_eq!(first["state"], "succeeded", "{first}");

    // The second install is an upgrade: no token, no enrollment, same key.
    let upgrade_id = harness
        .create_operation("machine.install-fleetd", payload(&package))
        .await;
    let upgrade = harness
        .run_operation(harness.install_executor.as_ref(), &upgrade_id)
        .await;
    assert_eq!(upgrade["state"], "succeeded", "{upgrade}");
    let view = harness.node_view(&machine_id).await;
    assert!(
        view.pending_tokens.is_empty(),
        "an upgrade mints no token: {view:?}"
    );
    assert_eq!(
        view.identity.as_ref().unwrap().gateway_state,
        fleet_application::node::GatewayState::Connected,
        "the same identity stays connected"
    );

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = loop_task.await;
}

#[tokio::test]
async fn a_revoked_identity_is_forcefully_reenrolled() {
    let harness = harness().await;
    let sshd = start_sshd();
    let (machine_id, endpoint_id) = harness.register_machine(&sshd).await;
    let package = TestPackage::build();
    publish(&harness, &package);

    let work = tempfile::tempdir().unwrap();
    let state_dir = work.path().join("state");
    let payload = install_payload(
        &machine_id,
        &endpoint_id,
        &sshd,
        harness.address,
        &package,
        &state_dir,
        &work.path().join("stubs"),
    );
    let first_id = harness
        .create_operation("machine.install-fleetd", payload.clone())
        .await;

    let controller =
        fleetd::http::Controller::parse(&format!("http://{}", harness.address)).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let first_loop = spawn_node_loop(state_dir.clone(), controller.clone(), None, stop.clone());
    let first = harness
        .run_operation(harness.install_executor.as_ref(), &first_id)
        .await;
    assert_eq!(first["state"], "succeeded", "{first}");
    let original_key = {
        let view = harness.node_view(&machine_id).await;
        view.identity.as_ref().unwrap().public_key.clone()
    };

    // Revocation disconnects and blocks; the next install re-enrolls
    // forcefully over the wiped local state.
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = first_loop.await;
    let (status, _) = harness
        .post_json(&format!("/api/v1/machines/{machine_id}/node/revoke"), None)
        .await;
    assert_eq!(status, axum::http::StatusCode::OK);

    let baseline = std::fs::metadata(state_dir.join("credential"))
        .unwrap()
        .modified()
        .unwrap();
    let second_id = harness
        .create_operation("machine.install-fleetd", payload.clone())
        .await;
    let stop2 = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let second_loop = spawn_node_loop(state_dir.clone(), controller, Some(baseline), stop2.clone());
    let second = harness
        .run_operation(harness.install_executor.as_ref(), &second_id)
        .await;
    assert_eq!(second["state"], "succeeded", "{second}");
    let view = harness.node_view(&machine_id).await;
    let identity = view.identity.as_ref().unwrap();
    assert_eq!(
        identity.status,
        fleet_application::node::NodeStatus::Active,
        "the machine is managed again"
    );
    assert_eq!(
        identity.gateway_state,
        fleet_application::node::GatewayState::Connected
    );
    assert_ne!(
        identity.public_key, original_key,
        "a forced re-enrollment generates a fresh key"
    );

    stop2.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = second_loop.await;
}

#[tokio::test]
async fn the_download_surface_is_contained() {
    let harness = harness().await;
    let package = TestPackage::build();
    publish(&harness, &package);

    // The artifact itself serves.
    let (status, _) = harness
        .get_json("/downloads/fleetd/fleetd-test.tar.gz")
        .await;
    assert_eq!(status, axum::http::StatusCode::OK);

    // Traversal attempts answer 404, never an error about the filesystem.
    for path in [
        "/downloads/fleetd/..%2F..%2Ffleet.db",
        "/downloads/fleetd/%2e%2e/fleetd-test.tar.gz",
        "/downloads/fleetd/no-such-file.tar.gz",
        "/downloads/fleetd/sub/../../fleetd-test.tar.gz",
    ] {
        let (status, _) = harness.get_json(path).await;
        assert_eq!(
            status,
            axum::http::StatusCode::NOT_FOUND,
            "traversal must be contained: {path}"
        );
    }
}

/// An install payload for the orchestrated mode: no artifact fields at all.
fn orchestrated_payload(
    machine_id: &str,
    endpoint_id: &str,
    sshd: &TestSshd,
    address: std::net::SocketAddr,
    state_dir: &Path,
    stubs_dir: &Path,
    connect_wait: Option<u64>,
) -> Value {
    let (systemctl, useradd, runuser) = write_stubs(stubs_dir);
    let mut payload = json!({
        "machineId": machine_id,
        "endpointId": endpoint_id,
        "auth": {"type": "identityFile", "path": sshd.user_key.display().to_string()},
        "timeoutSeconds": 120,
        "controllerUrl": format!("http://{address}"),
        "installerEnv": [
            ["FLEETD_STATE_DIR", state_dir.display().to_string()],
            ["FLEETD_BIN_DIR", stubs_dir.join("bin").display().to_string()],
            ["FLEETD_UNIT_DIR", stubs_dir.join("unit").display().to_string()],
            ["FLEETD_ENV_FILE", stubs_dir.join("fleetd.env").display().to_string()],
            ["FLEETD_SYSTEMCTL", systemctl.display().to_string()],
            ["FLEETD_USER_ADD", useradd.display().to_string()],
            ["FLEETD_RUNUSER", runuser.display().to_string()],
            ["FLEETD_STUB_LOG", stubs_dir.join("stubs.log").display().to_string()],
        ],
    });
    if let Some(wait) = connect_wait {
        payload["connectWaitSeconds"] = json!(wait);
    }
    payload
}

/// Plants the platform facts on a machine so the orchestrated install can
/// select the artifact.
async fn plant_facts(harness: &Harness, machine_id: &str, family: &str, architecture: &str) {
    let machines = MachineRepository::new(harness.pool.clone());
    let now = fleet_core::SystemClock::now_unix_millis();
    machines
        .record_capabilities(
            machine_id,
            &[
                fleet_core::CapabilityFact {
                    namespace: "os".to_owned(),
                    name: "family".to_owned(),
                    value: Some(family.to_owned()),
                    status: fleet_core::CapabilityStatus::Known,
                    observed_at: fleet_core::Timestamp::from_unix_millis(now),
                    source: "agentless/1".to_owned(),
                },
                fleet_core::CapabilityFact {
                    namespace: "host".to_owned(),
                    name: "architecture".to_owned(),
                    value: Some(architecture.to_owned()),
                    status: fleet_core::CapabilityStatus::Known,
                    observed_at: fleet_core::Timestamp::from_unix_millis(now),
                    source: "agentless/1".to_owned(),
                },
            ],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn the_orchestrated_install_selects_the_package_from_the_machines_facts() {
    let harness = harness().await;
    let sshd = start_sshd();
    let (machine_id, endpoint_id) = harness.register_machine(&sshd).await;
    let package = TestPackage::build();
    // The artifact store holds the package under its canonical name.
    let store = harness.artifacts.path().join("fleetd");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::copy(
        &package.archive,
        store.join("fleetd-0.1.0-linux-x86_64.tar.gz"),
    )
    .unwrap();
    plant_facts(&harness, &machine_id, "Linux", "x86_64").await;

    let work = tempfile::tempdir().unwrap();
    let state_dir = work.path().join("state");
    let payload = orchestrated_payload(
        &machine_id,
        &endpoint_id,
        &sshd,
        harness.address,
        &state_dir,
        &work.path().join("stubs"),
        None,
    );
    let operation_id = harness
        .create_operation("machine.install-fleetd", payload)
        .await;

    let controller =
        fleetd::http::Controller::parse(&format!("http://{}", harness.address)).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loop_task = spawn_node_loop(state_dir.clone(), controller, None, stop.clone());

    let operation = harness
        .run_operation(harness.install_executor.as_ref(), &operation_id)
        .await;
    assert_eq!(operation["state"], "succeeded", "{operation}");
    let result: Value = serde_json::from_str(operation["resultJson"].as_str().unwrap()).unwrap();
    assert_eq!(
        result["artifact"], "fleetd-0.1.0-linux-x86_64.tar.gz",
        "the selection is visible in the result: {result}"
    );
    let facts = result["inventoryFacts"].as_u64().unwrap();
    assert!(facts > 0, "the node reported its facts: {result}");

    // The digest came from the store; the node's download was verified
    // against it (the install would have refused otherwise).
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = loop_task.await;
}

#[tokio::test]
async fn the_orchestrated_install_states_the_platform_limitation() {
    let harness = harness().await;
    let sshd = start_sshd();
    let package = TestPackage::build();
    let store = harness.artifacts.path().join("fleetd");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::copy(
        &package.archive,
        store.join("fleetd-0.1.0-linux-x86_64.tar.gz"),
    )
    .unwrap();

    for (index, (family, architecture, expected)) in [
        ("linux", "armv7l", "supports x86_64 and aarch64"),
        ("darwin", "x86_64", "supports linux"),
    ]
    .into_iter()
    .enumerate()
    {
        let (machine_id, endpoint_id) = harness
            .register_named(&sshd, &format!("limit-{index}"))
            .await;
        plant_facts(&harness, &machine_id, family, architecture).await;
        let work = tempfile::tempdir().unwrap();
        let payload = orchestrated_payload(
            &machine_id,
            &endpoint_id,
            &sshd,
            harness.address,
            &work.path().join("state"),
            &work.path().join("stubs"),
            None,
        );
        let operation_id = harness
            .create_operation("machine.install-fleetd", payload)
            .await;
        let operation = harness
            .run_operation(harness.install_executor.as_ref(), &operation_id)
            .await;
        assert_eq!(operation["state"], "failed", "{operation}");
        let error: Value = serde_json::from_str(operation["errorJson"].as_str().unwrap()).unwrap();
        assert!(
            error["detail"]
                .as_str()
                .unwrap_or_default()
                .contains(expected),
            "the limitation is stated clearly: {error}"
        );
    }

    // A machine with no facts at all is refused just as clearly.
    let (machine_id, endpoint_id) = harness.register_machine(&sshd).await;
    let work = tempfile::tempdir().unwrap();
    let payload = orchestrated_payload(
        &machine_id,
        &endpoint_id,
        &sshd,
        harness.address,
        &work.path().join("state"),
        &work.path().join("stubs"),
        None,
    );
    let operation_id = harness
        .create_operation("machine.install-fleetd", payload)
        .await;
    let operation = harness
        .run_operation(harness.install_executor.as_ref(), &operation_id)
        .await;
    assert_eq!(operation["state"], "failed", "{operation}");
    let error: Value = serde_json::from_str(operation["errorJson"].as_str().unwrap()).unwrap();
    assert!(
        error["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("Discover the machine again"),
        "the no-facts refusal points at discovery: {error}"
    );
}

#[tokio::test]
async fn a_connect_timeout_leaves_a_recoverable_state_and_a_retry_succeeds() {
    let harness = harness().await;
    let sshd = start_sshd();
    let (machine_id, endpoint_id) = harness.register_machine(&sshd).await;
    let package = TestPackage::build();
    publish(&harness, &package);

    let work = tempfile::tempdir().unwrap();
    let state_dir = work.path().join("state");
    // The node loop never runs: the connect wait expires. The artifact is
    // explicit so the test isolates the timeout, not the selection.
    let mut payload = install_payload(
        &machine_id,
        &endpoint_id,
        &sshd,
        harness.address,
        &package,
        &state_dir,
        &work.path().join("stubs"),
    );
    payload["connectWaitSeconds"] = json!(1);
    let first_id = harness
        .create_operation("machine.install-fleetd", payload.clone())
        .await;
    let first = harness
        .run_operation(harness.install_executor.as_ref(), &first_id)
        .await;
    assert_eq!(first["state"], "failed", "{first}");
    let error: Value = serde_json::from_str(first["errorJson"].as_str().unwrap()).unwrap();
    assert_eq!(error["reason"], "node_did_not_connect");
    assert!(
        error["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("retry this install"),
        "the failure says how to recover: {error}"
    );

    // The machine kept its id; the identity exists (the enroll succeeded);
    // the retry is an upgrade and succeeds once the node loop runs.
    let view = harness.node_view(&machine_id).await;
    let identity = view.identity.as_ref().expect("the enroll landed");
    assert_eq!(identity.status, fleet_application::node::NodeStatus::Active);
    let controller =
        fleetd::http::Controller::parse(&format!("http://{}", harness.address)).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loop_task = spawn_node_loop(state_dir.clone(), controller, None, stop.clone());
    let retry_id = harness
        .create_operation("machine.install-fleetd", payload)
        .await;
    let retry = harness
        .run_operation(harness.install_executor.as_ref(), &retry_id)
        .await;
    assert_eq!(retry["state"], "succeeded", "{retry}");
    assert!(
        harness
            .node_view(&machine_id)
            .await
            .pending_tokens
            .is_empty(),
        "the retry mints no token"
    );
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = loop_task.await;
}

#[tokio::test]
async fn a_controller_restart_midway_fails_honestly_and_a_retry_succeeds() {
    let harness = harness().await;
    let sshd = start_sshd();
    let (machine_id, endpoint_id) = harness.register_machine(&sshd).await;
    let package = TestPackage::build();
    publish(&harness, &package);

    let work = tempfile::tempdir().unwrap();
    let state_dir = work.path().join("state");
    let payload = install_payload(
        &machine_id,
        &endpoint_id,
        &sshd,
        harness.address,
        &package,
        &state_dir,
        &work.path().join("stubs"),
    );
    let operation_id = harness
        .create_operation("machine.install-fleetd", payload.clone())
        .await;

    // A controller died right after claiming: the claim is on record with a
    // stale lease, and the next sweep fails the operation honestly.
    let port = OperationRepository::new(harness.pool.clone());
    port.claim_pending("dead-worker", fleet_core::SystemClock::now_unix_millis())
        .await
        .unwrap();
    harness
        .operations
        .tick(
            harness.install_executor.as_ref(),
            "sweeper",
            fleet_core::SystemClock::now_unix_millis() + 120_000,
            60_000,
        )
        .await
        .unwrap();
    let (status, body) = harness
        .get_json(&format!("/api/v1/operations/{operation_id}"))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["data"]["state"], "failed", "{body}");
    let error: Value = serde_json::from_str(body["data"]["errorJson"].as_str().unwrap()).unwrap();
    assert_eq!(error["reason"], "worker_lease_expired", "{error}");
    assert!(
        harness.node_view(&machine_id).await.identity.is_none(),
        "the interrupted install enrolled nothing"
    );

    // The retry is a fresh, clean install.
    let controller =
        fleetd::http::Controller::parse(&format!("http://{}", harness.address)).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loop_task = spawn_node_loop(state_dir.clone(), controller, None, stop.clone());
    let retry_id = harness
        .create_operation("machine.install-fleetd", payload.clone())
        .await;
    let retry = harness
        .run_operation(harness.install_executor.as_ref(), &retry_id)
        .await;
    assert_eq!(retry["state"], "succeeded", "{retry}");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = loop_task.await;
}

#[tokio::test]
async fn a_second_node_cannot_claim_the_association() {
    let harness = harness().await;
    let sshd = start_sshd();
    let (machine_id, endpoint_id) = harness.register_machine(&sshd).await;
    let package = TestPackage::build();
    publish(&harness, &package);

    let work = tempfile::tempdir().unwrap();
    let state_dir = work.path().join("state");
    let payload = install_payload(
        &machine_id,
        &endpoint_id,
        &sshd,
        harness.address,
        &package,
        &state_dir,
        &work.path().join("stubs"),
    );
    let operation_id = harness
        .create_operation("machine.install-fleetd", payload)
        .await;
    let controller =
        fleetd::http::Controller::parse(&format!("http://{}", harness.address)).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loop_task = spawn_node_loop(state_dir.clone(), controller, None, stop.clone());
    let operation = harness
        .run_operation(harness.install_executor.as_ref(), &operation_id)
        .await;
    assert_eq!(operation["state"], "succeeded", "{operation}");

    // The enrolled credential is on disk; a second node holds a different
    // key and cannot prove possession with it.
    let credential = std::fs::read_to_string(state_dir.join("credential"))
        .unwrap()
        .trim()
        .to_owned();
    let stranger = fleetd::state::NodeState::open(&work.path().join("stranger")).unwrap();
    let challenge = harness
        .nodes
        .challenge(
            &credential,
            fleet_application::node::ChallengePurpose::Session,
            None,
        )
        .await
        .expect("the credential itself is valid");
    let message = fleet_application::node::proof_message(
        &challenge.id,
        &machine_id,
        fleet_application::node::ChallengePurpose::Session,
        None,
    );
    let forged = stranger.sign_proof(&message);
    let refused = harness
        .nodes
        .prove_session(&credential, &challenge.id, &forged)
        .await;
    assert!(
        refused.is_err(),
        "a stranger's proof must be refused: {refused:?}"
    );

    // And the replayed enroll path is single-use: the token is consumed.
    assert!(
        harness
            .node_view(&machine_id)
            .await
            .pending_tokens
            .is_empty(),
        "no token is left to claim"
    );
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = loop_task.await;
}
