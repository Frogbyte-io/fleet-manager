//! End-to-end checkout actions against a real sshd (FM-301): discovery,
//! clone, pull, status, the guarded config write, path-traversal refusal,
//! and redaction of credential-bearing output.

use fleet_application::machine::{MachinePort, NewEndpoint, RegisterMachine};
use fleet_application::operation::Operations;
use fleet_provider_ssh::ExecutionLimiter;
use fleet_storage_sqlite::{AuditSink, MachineRepository, OperationRepository, Store};
use sqlx::SqlitePool;
use std::time::Duration;

use std::process::Command;
mod common;
use common::{TestSshd, start_sshd, whoami};

/// The composed fixture: store, operations, checkout executor, pool, and a
/// registered machine with a verified endpoint.
struct Fixture {
    _dir: tempfile::TempDir,
    operations: Operations,
    executor: fleet_controller::checkout::CheckoutExecutor,
    machine_id: String,
    endpoint_id: String,
    identity_file: String,
}

async fn compose(sshd: &TestSshd) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool: SqlitePool = store.pool().clone();
    std::mem::forget(store);
    let machines = MachineRepository::new(pool.clone());
    let machine = machines
        .register(&RegisterMachine {
            name: "box".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: fleet_core::EndpointKind::Ssh,
                reference: format!("{}@127.0.0.1:{}", whoami(), sshd.port),
            }],
            tags: vec![],
            groups: vec![],
        })
        .await
        .unwrap();
    let endpoint_id = machine.endpoints[0].id.clone();

    // The trust workflow runs for real: probe, pin, confirm.
    let provider = fleet_provider_ssh::SshProvider::new(dir.path().join("ssh")).unwrap();
    let observation = provider
        .probe_host_key("127.0.0.1", sshd.port, Duration::from_secs(10))
        .unwrap();
    provider.pin(&observation).unwrap();
    machines
        .confirm_fingerprint(&endpoint_id, &observation.fingerprint, 0)
        .await
        .unwrap();

    let executor_machines: std::sync::Arc<dyn MachinePort> =
        std::sync::Arc::new(MachineRepository::new(pool.clone()));
    let executor = fleet_controller::checkout::CheckoutExecutor::new(
        executor_machines,
        dir.path().join("ssh"),
        ExecutionLimiter::new(4),
    );
    let operations = Operations::new(
        std::sync::Arc::new(OperationRepository::new(pool.clone())),
        std::sync::Arc::new(AuditSink::new(pool.clone())),
    );
    Fixture {
        _dir: dir,
        operations,
        executor,
        machine_id: machine.id,
        endpoint_id,
        identity_file: format!("{}/user_ed25519", sshd.keys_dir.path().display()),
    }
}

impl Fixture {
    fn auth_json(&self) -> serde_json::Value {
        serde_json::json!({"type": "identityFile", "path": self.identity_file})
    }

    async fn run_kind(
        &self,
        kind: &str,
        payload: serde_json::Value,
    ) -> (String, Option<String>, Option<String>) {
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
                    reviewed: false,
                },
            )
            .await
            .unwrap();
        self.operations
            .tick(
                &self.executor,
                "worker-a",
                fleet_core::SystemClock::now_unix_millis(),
                60_000,
            )
            .await
            .unwrap();
        let finished = self
            .operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                "anonymous-lan-admin",
                &operation.id,
            )
            .await
            .unwrap();
        (finished.state, finished.result_json, finished.error_json)
    }
}

#[tokio::test]
async fn discovery_reports_checkouts_from_the_real_machine() {
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    // Two checkouts in the home root: one clean, one dirty.
    let home = std::env::var("HOME").unwrap();
    let clean = std::path::PathBuf::from(home.clone())
        .join(format!(".fleet-test-clean-{}", std::process::id()));
    let dirty =
        std::path::PathBuf::from(home).join(format!(".fleet-test-dirty-{}", std::process::id()));
    for (path, make_dirty) in [(&clean, false), (&dirty, true)] {
        let _ = std::fs::remove_dir_all(path);
        std::fs::create_dir_all(path).unwrap();
        run_git(&["init", "-q", path.to_str().unwrap()]);
        std::fs::write(path.join("README.md"), "seed\n").unwrap();
        run_git(&["-C", path.to_str().unwrap(), "add", "."]);
        run_git(&[
            "-C",
            path.to_str().unwrap(),
            "-c",
            "user.email=fleet@example.com",
            "-c",
            "user.name=Fleet",
            "commit",
            "-q",
            "-m",
            "seed",
        ]);
        if make_dirty {
            std::fs::write(path.join("dirty.txt"), "uncommitted\n").unwrap();
        }
    }

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "timeoutSeconds": 60,
    });
    let (state, result, error) = fixture.run_kind("projects.discover", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let result: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    let checkouts = result["checkouts"].as_array().unwrap();
    let clean_fact = checkouts
        .iter()
        .find(|checkout| checkout["root"] == serde_json::json!(clean.display().to_string()))
        .expect("the clean checkout is discovered");
    assert_eq!(clean_fact["branch"], "master");
    assert_eq!(clean_fact["dirty"], false);
    let dirty_fact = checkouts
        .iter()
        .find(|checkout| checkout["root"] == serde_json::json!(dirty.display().to_string()))
        .expect("the dirty checkout is discovered");
    assert_eq!(dirty_fact["dirty"], true);
    let _ = std::fs::remove_dir_all(&clean);
    let _ = std::fs::remove_dir_all(&dirty);
}

#[tokio::test]
async fn clone_pull_and_status_round_trip_over_ssh() {
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    // The origin repository lives on the same machine, so the clone needs
    // no network.
    let origin = std::env::temp_dir().join(format!("fleet-origin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&origin);
    std::fs::create_dir_all(&origin).unwrap();
    run_git(&["init", "-q", "--bare", origin.to_str().unwrap()]);
    run_git(&[
        "-C",
        origin.to_str().unwrap(),
        "symbolic-ref",
        "HEAD",
        "refs/heads/main",
    ]);
    let seed = std::env::temp_dir().join(format!("fleet-seed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&seed);
    std::fs::create_dir_all(&seed).unwrap();
    run_git(&["init", "-q", seed.to_str().unwrap()]);
    std::fs::write(seed.join("README.md"), "seed\n").unwrap();
    run_git(&["-C", seed.to_str().unwrap(), "add", "."]);
    run_git(&[
        "-C",
        seed.to_str().unwrap(),
        "-c",
        "user.email=fleet@example.com",
        "-c",
        "user.name=Fleet",
        "commit",
        "-q",
        "-m",
        "seed",
    ]);
    run_git(&[
        "-C",
        seed.to_str().unwrap(),
        "push",
        "-q",
        origin.to_str().unwrap(),
        "HEAD:refs/heads/main",
    ]);

    let root = std::env::temp_dir().join(format!("fleet-clone-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "root": root.display().to_string(),
        "remote": origin.display().to_string(),
        "timeoutSeconds": 60,
    });
    let (state, _result, error) = fixture.run_kind("projects.clone", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    assert!(root.join(".git").exists(), "the clone landed");

    // A new commit upstream, then pull.
    std::fs::write(seed.join("more.txt"), "more\n").unwrap();
    run_git(&["-C", seed.to_str().unwrap(), "add", "."]);
    run_git(&[
        "-C",
        seed.to_str().unwrap(),
        "-c",
        "user.email=fleet@example.com",
        "-c",
        "user.name=Fleet",
        "commit",
        "-q",
        "-m",
        "more",
    ]);
    run_git(&[
        "-C",
        seed.to_str().unwrap(),
        "push",
        "-q",
        origin.to_str().unwrap(),
        "HEAD:refs/heads/main",
    ]);
    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "root": root.display().to_string(),
        "timeoutSeconds": 60,
    });
    let (state, _result, error) = fixture.run_kind("projects.pull", payload.clone()).await;
    assert_eq!(state, "succeeded", "{error:?}");
    assert!(root.join("more.txt").exists(), "the pull advanced");

    // Status reports the clean worktree.
    let (state, result, error) = fixture.run_kind("projects.status", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let result: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(result["checkout"]["dirty"], false);
    assert_eq!(result["checkout"]["branch"], "main");

    let _ = std::fs::remove_dir_all(&origin);
    let _ = std::fs::remove_dir_all(&seed);
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn a_traversal_root_is_refused_before_any_ssh_work() {
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "root": "/tmp/../../etc",
        "timeoutSeconds": 10,
    });
    let (state, _result, error) = fixture.run_kind("projects.pull", payload.clone()).await;
    assert_eq!(state, "failed");
    let error = error.expect("the refusal names its reason");
    assert!(error.contains("`..` segment"), "{error}");
}

#[tokio::test]
async fn the_guarded_config_write_lands_atomically_and_refuses_unknown_files() {
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let root = std::env::temp_dir().join(format!("fleet-config-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "root": root.display().to_string(),
        "fileName": "AGENTS.md",
        "contents": "# agent rules\n",
        "timeoutSeconds": 60,
    });
    let (state, _result, error) = fixture.run_kind("projects.write-config", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    assert_eq!(
        std::fs::read_to_string(root.join("AGENTS.md")).unwrap(),
        "# agent rules\n"
    );
    assert!(
        !root.join("AGENTS.md.fleet-tmp").exists(),
        "the temp file never survives the rename"
    );

    // An unknown file name is refused locally, before any SSH work.
    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "root": root.display().to_string(),
        "fileName": "../../../etc/passwd",
        "contents": "no",
        "timeoutSeconds": 60,
    });
    let (state, _result, error) = fixture.run_kind("projects.write-config", payload).await;
    assert_eq!(state, "failed");
    let error = error.expect("the refusal names its reason");
    assert!(error.contains("guarded agent config file"), "{error}");

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn credential_shaped_output_is_redacted_in_the_public_result() {
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    // A clone from a credential-bearing remote fails (no such host), and
    // the failure's public detail must not carry the credentials.
    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "root": "/tmp/fleet-redaction-target",
        "remote": "https://user:secret-password@example.invalid/repo.git",
        "timeoutSeconds": 30,
    });
    let (state, _result, error) = fixture.run_kind("projects.clone", payload).await;
    assert_eq!(state, "failed");
    let error = error.expect("the failure carries a detail");
    assert!(!error.contains("secret-password"), "{error}");
}

#[test]
fn redaction_scrubs_userinfo_from_tool_output() {
    use fleet_controller::checkout::redact_output_for_test;
    let redacted = redact_output_for_test(
        "fatal: unable to access https://user:secret-password@example.invalid/repo.git/",
    );
    assert!(!redacted.contains("secret-password"), "{redacted}");
    assert!(redacted.contains("***@example.invalid"), "{redacted}");
    let scp = redact_output_for_test("fatal: cannot run ssh-user:secret@host:repo");
    assert!(!scp.contains("secret"), "{scp}");
}

fn run_git(arguments: &[&str]) {
    let output = Command::new("git").args(arguments).output().unwrap();
    assert!(
        output.status.success(),
        "git {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn a_pull_beyond_its_deadline_is_killed_and_reported_honestly() {
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    // A repository whose remote is a routing black hole: the pull hangs
    // until the deadline kills the local ssh process, and the operation
    // must report that the remote checkout's state is unknown — never
    // success.
    let repo = std::env::temp_dir().join(format!("fleet-slow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&repo);
    std::fs::create_dir_all(&repo).unwrap();
    run_git(&["init", "-q", repo.to_str().unwrap()]);
    run_git(&[
        "-C",
        repo.to_str().unwrap(),
        "remote",
        "add",
        "origin",
        "https://10.255.255.1/nope.git",
    ]);
    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "root": repo.display().to_string(),
        "timeoutSeconds": 2,
    });
    let (state, _result, error) = fixture.run_kind("projects.pull", payload).await;
    assert_eq!(state, "failed");
    let error = error.expect("the deadline kill names its reason");
    assert!(error.contains("deadline_killed"), "{error}");
    assert!(
        error.contains("unknown"),
        "the report must not claim the remote state: {error}"
    );
    let _ = std::fs::remove_dir_all(&repo);
}
