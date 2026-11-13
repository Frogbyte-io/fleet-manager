//! `fleetctl machines join` end to end: the real `fleetctl` binary against a
//! real controller router with the onboarding executor, and a real sshd
//! whose `authorized_keys` is the file the join writes.
//!
//! The controller connects with `--auth agent`, i.e. with the keys of the
//! process's ssh-agent. So that no developer key is involved, the parent
//! test generates a controller key, loads it into a private `ssh-agent`, and
//! re-runs this binary's child test with `SSH_AUTH_SOCK` pointing at it (no
//! process environment is changed in place). The child serves that key on
//! `GET /system/ssh-public-key` through the controller's own identity code.

#![cfg(unix)]
// The shared sshd harness and the one long scenario are test code.
#![allow(clippy::too_many_lines)]

#[path = "../../fleet-controller/tests/common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};
use std::sync::Arc;
use std::time::Duration;

use fleet_application::operation::Operations;
use fleet_application::worker::OperationExecutor;
use fleet_provider_ssh::ExecutionLimiter;
use fleet_provider_ssh::identity::{ControllerIdentity, EnsureOutcome};
use fleet_storage_sqlite::{OnboardingRepository, OperationRepository, Store};
use serde_json::Value;

/// The child test's marker: the directory holding the controller key.
const CHILD_DIR_VAR: &str = "FLEET_JOIN_E2E_DIR";

#[test]
fn join_end_to_end_through_a_private_agent() {
    let dir = tempfile::tempdir().unwrap();
    let identity = ControllerIdentity::at(dir.path().join("controller/.ssh"));
    let EnsureOutcome::Generated(key) = identity
        .ensure(true, "fleet-controller@e2e")
        .expect("ssh-keygen must run")
    else {
        panic!("a fresh directory gets a key");
    };
    let socket = dir.path().join("agent.sock");
    let mut agent = Process::new("ssh-agent")
        .arg("-D")
        .arg("-a")
        .arg(&socket)
        .stdout(Stdio::null())
        .spawn()
        .expect("ssh-agent must start");
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let added = Process::new("ssh-add")
        .arg(&key.path)
        .env("SSH_AUTH_SOCK", &socket)
        .output()
        .unwrap();
    assert!(
        added.status.success(),
        "ssh-add: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    let child = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "join_scenario",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("SSH_AUTH_SOCK", &socket)
        .env(CHILD_DIR_VAR, dir.path())
        .output()
        .unwrap();
    let _ = agent.kill();
    let _ = agent.wait();
    let stdout = String::from_utf8_lossy(&child.stdout);
    assert!(
        child.status.success(),
        "the join scenario failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(
        stdout.contains("test join_scenario ... ok"),
        "the scenario must have run:\n{stdout}"
    );
}

/// A controller router with the onboarding surface, a worker running the
/// onboarding executor, and the controller key served from `key_dir`.
struct Controller {
    url: String,
    pool: sqlx::SqlitePool,
    _store: Store,
    _dir: tempfile::TempDir,
    _server: tokio::task::JoinHandle<()>,
    _worker: tokio::task::JoinHandle<()>,
}

impl Controller {
    async fn start(key_dir: PathBuf) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        let ssh_work = dir.path().join("ssh");
        let onboarding = Arc::new(fleet_controller::compose_onboarding(
            &pool,
            ssh_work.clone(),
        ));
        let settings = fleet_controller::Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            web_dist: dir.path().to_path_buf(),
            artifacts_dir: None,
            tailscale_serve_listen: None,
        };
        let controller = fleet_controller::build_router(
            &settings,
            Some(pool.clone()),
            None,
            Some(&onboarding),
            None,
            None,
            None,
            None,
            None,
        );
        // The real identity code, over the test's key directory instead of
        // the developer's own home.
        let router = axum::Router::new()
            .route(
                "/api/v1/system/ssh-public-key",
                axum::routing::get(move || {
                    let key_dir = key_dir.clone();
                    async move {
                        axum::Json(fleet_controller::ssh_identity::to_info(
                            ControllerIdentity::at(key_dir).inspect(),
                        ))
                    }
                }),
            )
            .fallback_service(controller);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone())),
        ));
        let executor: Arc<dyn OperationExecutor> =
            Arc::new(fleet_controller::onboard::OnboardingExecutor::new(
                Arc::new(OnboardingRepository::new(pool.clone())),
                ssh_work,
                ExecutionLimiter::new(4),
                Arc::new(fleet_application::worker::NoopExecutor),
            ));
        let worker = tokio::spawn(async move {
            loop {
                let _ = operations
                    .tick(
                        executor.as_ref(),
                        "test-worker",
                        fleet_core::SystemClock::now_unix_millis(),
                        60_000,
                    )
                    .await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        Self {
            url: format!("http://{address}"),
            pool,
            _store: store,
            _dir: dir,
            _server: server,
            _worker: worker,
        }
    }

    async fn machines(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM machines")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn drafts(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM onboarding_drafts")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

struct Cli {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Cli {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|error| panic!("not JSON ({error}):\n{}\n{}", self.stdout, self.stderr))
    }
}

/// Runs the real `fleetctl` with only the given home and PATH.
async fn fleetctl(url: &str, home: &Path, path: &Path, words: Vec<String>) -> Cli {
    let url = url.to_owned();
    let home = home.to_path_buf();
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let output = Process::new(env!("CARGO_BIN_EXE_fleetctl"))
            .args(["--url", &url, "--output", "json"])
            .args(&words)
            .env_clear()
            .env("HOME", &home)
            .env("USER", common::whoami())
            .env("PATH", &path)
            .output()
            .expect("fleetctl must run");
        Cli {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    })
    .await
    .unwrap()
}

fn join_words(port: u16, name: &str, host_key: &Path, extra: &[&str]) -> Vec<String> {
    let mut words: Vec<String> = [
        "machines",
        "join",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--user",
        &common::whoami(),
        "--name",
        name,
        "--host-key-file",
        &host_key.display().to_string(),
        "--no-skills",
    ]
    .iter()
    .map(|word| (*word).to_owned())
    .collect();
    words.extend(extra.iter().map(|word| (*word).to_owned()));
    words
}

fn fingerprint_of(public: &Path) -> String {
    fleet_core::parse_public_key(&std::fs::read_to_string(public).unwrap())
        .unwrap()
        .fingerprint
}

/// The scenario, run only as the child of the test above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_scenario() {
    let Some(dir) = std::env::var_os(CHILD_DIR_VAR).map(PathBuf::from) else {
        // Run directly, this test has nothing to do: the parent test above
        // starts it with the private agent.
        return;
    };
    let key_dir = dir.join("controller/.ssh");
    let controller_key = std::fs::read_to_string(key_dir.join("id_ed25519.pub")).unwrap();
    let controller = Controller::start(key_dir.clone()).await;
    let empty_path = tempfile::tempdir().unwrap();

    // The published key is what `system ssh-public-key` prints.
    let home = tempfile::tempdir().unwrap();
    let sshd = common::start_sshd_with_home_keys(home.path());
    let host_key = sshd.keys_dir.path().join("host_ed25519.pub");
    let printed = fleetctl(
        &controller.url,
        home.path(),
        empty_path.path(),
        vec!["system".into(), "ssh-public-key".into()],
    )
    .await;
    assert_eq!(printed.code, 0, "{}", printed.stderr);
    assert_eq!(printed.json()["publicKey"], controller_key.trim());

    // 1. The join: key installed, host key compared, machine added.
    let joined = fleetctl(
        &controller.url,
        home.path(),
        empty_path.path(),
        join_words(sshd.port, "e2e-box", &host_key, &[]),
    )
    .await;
    assert_eq!(joined.code, 0, "{}\n{}", joined.stdout, joined.stderr);
    let summary = joined.json();
    let machine_id = summary["machineId"].as_str().unwrap().to_owned();
    assert_eq!(summary["name"], "e2e-box");
    assert_eq!(summary["resumed"], false);
    assert_eq!(summary["controllerKey"]["authorizedKeys"], "added");
    assert_eq!(summary["hostKey"]["fingerprint"], fingerprint_of(&host_key));
    assert_eq!(summary["skills"]["status"], "skipped");
    assert!(
        summary["endpointId"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    let authorized = std::fs::read_to_string(home.path().join(".ssh/authorized_keys")).unwrap();
    assert_eq!(
        authorized
            .matches(controller_key.split(' ').nth(1).unwrap())
            .count(),
        1
    );
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(home.path().join(".ssh/authorized_keys"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert_eq!(controller.machines().await, 1);
    assert_eq!(controller.drafts().await, 0);
    // The confirmed fingerprint is this machine's own.
    let pinned: Option<String> = sqlx::query_scalar(
        "SELECT verified_fingerprint FROM machine_endpoints WHERE machine_id = ?1",
    )
    .bind(&machine_id)
    .fetch_one(&controller.pool)
    .await
    .unwrap();
    assert_eq!(pinned.as_deref(), Some(fingerprint_of(&host_key).as_str()));

    // 2. Again: already enrolled, stop, leave no draft.
    let again = fleetctl(
        &controller.url,
        home.path(),
        empty_path.path(),
        join_words(sshd.port, "e2e-box", &host_key, &[]),
    )
    .await;
    assert_eq!(again.code, 1, "{}", again.stdout);
    assert!(
        again.stderr.contains("already enrolled"),
        "{}",
        again.stderr
    );
    assert!(again.stderr.contains("--resume"), "{}", again.stderr);
    assert_eq!(controller.drafts().await, 0);
    assert_eq!(controller.machines().await, 1);

    // 3. --resume continues with the same machine; the key is not re-added.
    let resumed = fleetctl(
        &controller.url,
        home.path(),
        empty_path.path(),
        join_words(sshd.port, "e2e-box", &host_key, &["--resume"]),
    )
    .await;
    assert_eq!(resumed.code, 0, "{}", resumed.stderr);
    assert_eq!(resumed.json()["resumed"], true);
    assert_eq!(resumed.json()["machineId"], machine_id);
    assert_eq!(resumed.json()["controllerKey"]["authorizedKeys"], "present");
    assert_eq!(
        std::fs::read_to_string(home.path().join(".ssh/authorized_keys")).unwrap(),
        authorized
    );

    // 4. A host key that is not this machine's own is refused loudly, and
    //    nothing is confirmed or added.
    let other_home = tempfile::tempdir().unwrap();
    let other = common::start_sshd_with_home_keys(other_home.path());
    let mitm = fleetctl(
        &controller.url,
        other_home.path(),
        empty_path.path(),
        join_words(other.port, "e2e-other", &host_key, &[]),
    )
    .await;
    assert_eq!(mitm.code, 1, "{}", mitm.stdout);
    assert!(mitm.stderr.contains("REFUSED"), "{}", mitm.stderr);
    assert!(
        mitm.stderr.contains(&fingerprint_of(&host_key)),
        "{}",
        mitm.stderr
    );
    assert_eq!(controller.drafts().await, 0);
    assert_eq!(controller.machines().await, 1);

    // 5. A stand-in skills-manager-cli stops the join before anything changes.
    let stub_dir = tempfile::tempdir().unwrap();
    let stub = stub_dir.path().join("skills-manager-cli");
    std::fs::write(&stub, "#!/bin/sh\necho '{\"version\":\"1.40.0\"}'\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let fresh_home = tempfile::tempdir().unwrap();
    let refused = fleetctl(
        &controller.url,
        fresh_home.path(),
        stub_dir.path(),
        join_words(
            other.port,
            "e2e-other",
            &other.keys_dir.path().join("host_ed25519.pub"),
            &[],
        ),
    )
    .await;
    assert_eq!(refused.code, 1, "{}", refused.stdout);
    assert!(
        refused.stderr.contains("not the real Skills Manager CLI"),
        "{}",
        refused.stderr
    );
    assert!(stub.exists(), "the stand-in is reported, never deleted");
    assert!(
        !fresh_home.path().join(".ssh").exists(),
        "nothing was written"
    );
    assert_eq!(controller.drafts().await, 0);
}
