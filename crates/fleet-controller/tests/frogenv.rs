//! End-to-end Frogenv operations against a real sshd (FM-303): the status
//! surface, the blocked-approval ceremony contract, `env run` argument
//! flow, and redaction of value-shaped material.

use fleet_application::machine::{MachinePort, NewEndpoint, RegisterMachine};
use fleet_application::operation::Operations;
use fleet_provider_ssh::ExecutionLimiter;
use fleet_storage_sqlite::{AuditSink, MachineRepository, OperationRepository, Store};
use sqlx::SqlitePool;
use std::time::Duration;

mod common;
use common::{TestSshd, start_sshd, whoami};
use tokio::sync::Mutex;

/// The stub CLI and its install location are shared machine state; the
/// tests serialize their installation and removal.
static CLI_LOCK: Mutex<()> = Mutex::const_new(());

/// The composed fixture: store, operations, frogenv executor, and a
/// verified endpoint.
struct Fixture {
    _dir: tempfile::TempDir,
    operations: Operations,
    executor: fleet_controller::frogenv::FrogenvExecutor,
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
    let executor = fleet_controller::frogenv::FrogenvExecutor::new(
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
                    review_token: None,
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

/// The stub CLI: answers the documented shapes and logs its arguments.
/// The `mode` parameter selects the scenario the stub answers with.
fn install_stub_cli(home: &str, mode: &str) -> String {
    let bin_dir = format!("{home}/.local/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let path = format!("{bin_dir}/frogenv");
    let stub = format!(
        r#"#!/usr/bin/env bash
echo "$@" >> /tmp/fleet-frogenv-stub.log
mode="{mode}"
case "$1" in
  --version) echo "frogenv 0.2.0" ;;
  status)
    if [ "$mode" = "configured" ]; then
      echo '{{"configured":true,"machineState":"approved","machineId":"host-abc123"}}'
    else
      echo '{{"configured":false}}'
    fi
    ;;
  setup)
    if [ "$mode" = "blocked" ]; then
      echo "FLEET_BLOCKED: run this yourself" >&2
      exit 2
    fi
    echo "configured"
    ;;
  login)
    if [ "$mode" = "blocked" ]; then
      echo "FLEET_BLOCKED: run this yourself" >&2
      exit 2
    fi
    echo "logged in"
    ;;
  machine)
    if [ "$mode" = "blocked" ]; then
      echo "FLEET_BLOCKED: run this yourself" >&2
      exit 2
    fi
    echo "requested"
    ;;
  sync) echo "synced" ;;
  env)
    shift
    [ "$1" = "run" ] && shift
    # Print the arguments to prove the array survives verbatim.
    echo "ran: $*"
    ;;
esac
exit 0
"#
    );
    std::fs::write(&path, stub).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    path
}

fn remove_stub_cli(home: &str) {
    let _ = std::fs::remove_file(format!("{home}/.local/bin/frogenv"));
}

#[tokio::test]
async fn the_status_surface_answers_the_documented_json() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let _path = install_stub_cli(&home, "configured");

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "timeoutSeconds": 30,
    });
    let (state, result, error) = fixture.run_kind("frogenv.status", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let result: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(result["status"]["configured"], true);
    assert_eq!(result["status"]["machineState"], "approved");
    assert_eq!(result["status"]["machineId"], "host-abc123");
    remove_stub_cli(&home);
}

#[tokio::test]
async fn a_shape_changed_status_degrades_explicitly() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    // A stub that answers human text for status (an upgrade Fleet has not
    // been taught).
    let bin_dir = format!("{home}/.local/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let path = format!("{bin_dir}/frogenv");
    std::fs::write(
        &path,
        "#!/usr/bin/env bash\necho \"everything looks great\"\nexit 0\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "timeoutSeconds": 30,
    });
    let (state, _result, error) = fixture.run_kind("frogenv.status", payload).await;
    assert_eq!(state, "failed");
    let error = error.expect("the degradation names its reason");
    assert!(error.contains("unsupported_version"), "{error}");
    remove_stub_cli(&home);
}

#[tokio::test]
async fn a_blocked_ceremony_is_a_first_class_state_not_a_hang() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let _path = install_stub_cli(&home, "blocked");

    for kind in ["frogenv.setup", "frogenv.login", "frogenv.request"] {
        let payload = serde_json::json!({
            "machineId": fixture.machine_id,
            "endpointId": fixture.endpoint_id,
            "auth": fixture.auth_json(),
            "timeoutSeconds": 10,
        });
        let (state, _result, error) = fixture.run_kind(kind, payload).await;
        // Blocked is a first-class terminal state, not a failure.
        assert_eq!(state, "blocked_manual_approval", "{kind}");
        let error = error.expect("the block names its reason");
        assert!(
            error.contains("manual approval") || error.contains("run it on the machine"),
            "{kind}: {error}"
        );
    }
    remove_stub_cli(&home);
}

#[tokio::test]
async fn a_willing_ceremony_completes() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let _path = install_stub_cli(&home, "willing");

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "timeoutSeconds": 30,
    });
    let (state, _result, error) = fixture.run_kind("frogenv.setup", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    remove_stub_cli(&home);
}

#[tokio::test]
async fn env_run_passes_the_command_array_verbatim() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let _path = install_stub_cli(&home, "willing");
    std::fs::remove_file("/tmp/fleet-frogenv-stub.log").ok();

    let root = std::env::temp_dir().join(format!("fleet-frogenv-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "root": root.display().to_string(),
        "command": ["pytest", "-q", "tests/"],
        "timeoutSeconds": 30,
    });
    let (state, result, error) = fixture.run_kind("frogenv.env-run", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let result: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(result["kind"], "env run");

    let log = std::fs::read_to_string("/tmp/fleet-frogenv-stub.log").unwrap();
    assert!(
        log.contains("env run -- pytest -q tests/"),
        "the command array survives verbatim: {log}"
    );
    let _ = std::fs::remove_dir_all(&root);
    remove_stub_cli(&home);
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
        "command": ["ls"],
        "timeoutSeconds": 10,
    });
    let (state, _result, error) = fixture.run_kind("frogenv.env-run", payload).await;
    assert_eq!(state, "failed");
    let error = error.expect("the refusal names its reason");
    assert!(error.contains("`..` segment"), "{error}");
}

#[tokio::test]
async fn value_shaped_output_is_redacted_in_the_public_result() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let bin_dir = format!("{home}/.local/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let path = format!("{bin_dir}/frogenv");
    std::fs::write(
        &path,
        "#!/usr/bin/env bash\ncase \"$1\" in\n  --version) echo \"frogenv 0.2.0\"; exit 0 ;;\nesac\necho \"failed with AGE-SECRET-KEY-1QQQQQEXAMPLEEXAMPLEQQ in the message\" >&2\nexit 2\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "timeoutSeconds": 30,
    });
    let (state, _result, error) = fixture.run_kind("frogenv.sync", payload).await;
    assert_eq!(state, "failed");
    let error = error.expect("the failure carries a detail");
    assert!(!error.contains("AGE-SECRET-KEY"), "{error}");
    assert!(error.contains("[redacted"), "{error}");
    remove_stub_cli(&home);
}

#[tokio::test]
async fn an_absent_cli_fails_honestly() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    remove_stub_cli(&home);

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "timeoutSeconds": 30,
    });
    let (state, _result, error) = fixture.run_kind("frogenv.status", payload).await;
    assert_eq!(state, "failed");
    let error = error.expect("the absence names its reason");
    assert!(error.contains("not installed"), "{error}");
}

#[tokio::test]
async fn a_hostile_root_is_data_not_script() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let _path = install_stub_cli(&home, "willing");
    std::fs::remove_file("/tmp/fleet-frogenv-stub.log").ok();

    // A root carrying shell metacharacters is a path argument, never
    // script text: the script consumes it as a quoted positional, so the
    // metacharacters cannot execute — the run fails as a missing
    // directory instead.
    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "root": format!("/tmp/$(touch /tmp/fleet-pwned-{})", std::process::id()),
        "command": ["ls"],
        "timeoutSeconds": 30,
    });
    let (state, _result, error) = fixture.run_kind("frogenv.env-run", payload).await;
    assert_eq!(state, "failed");
    let error = error.expect("the hostile root fails as a path");
    assert!(error.contains("not a directory"), "{error}");
    assert!(
        !std::path::Path::new(&format!("/tmp/fleet-pwned-{}", std::process::id())).exists(),
        "the metacharacters must never execute"
    );
    remove_stub_cli(&home);
}
