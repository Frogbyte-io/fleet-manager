//! End-to-end mise operations against a real sshd (FM-304): the inventory
//! surface, the status document, idempotent install, exec argument flow,
//! and project-file authority.

use fleet_application::machine::{MachinePort, NewEndpoint, RegisterMachine};
use fleet_application::operation::Operations;
use fleet_provider_ssh::ExecutionLimiter;
use fleet_storage_sqlite::{AuditSink, MachineRepository, OperationRepository, Store};
use sqlx::SqlitePool;
mod common;
use common::{TestSshd, start_sshd, whoami};
use std::time::Duration;
use tokio::sync::Mutex;

/// The stub CLI and its install location are shared machine state; the
/// tests serialize their installation and removal.
static CLI_LOCK: Mutex<()> = Mutex::const_new(());

/// The composed fixture: store, operations, mise executor, and a verified
/// endpoint.
struct Fixture {
    _dir: tempfile::TempDir,
    operations: Operations,
    executor: fleet_controller::mise::MiseExecutor,
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
    let executor = fleet_controller::mise::MiseExecutor::new(
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
fn install_stub_cli(home: &str) -> String {
    let bin_dir = format!("{home}/.local/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let path = format!("{bin_dir}/mise");
    let stub = r#"#!/usr/bin/env bash
echo "$@" >> /tmp/fleet-mise-stub.log
case "$1" in
  --version) echo "mise 2026.1.2" ;;
  ls) echo '{"node":[{"version":"20.11.0","requested":"20","installed":true}]}' ;;
  install)
    tool=$2; version=$3
    mkdir -p "$HOME/.mise/installs/$tool/$version"
    echo "installed $tool@$version"
    ;;
  exec)
    shift
    [ "$1" = "--" ] && shift
    echo "ran: $*"
    ;;
esac
exit 0
"#;
    std::fs::write(&path, stub).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    path
}

fn remove_stub_cli(home: &str) {
    let _ = std::fs::remove_file(format!("{home}/.local/bin/mise"));
}

#[tokio::test]
async fn the_inventory_reports_presence_and_versions() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "timeoutSeconds": 30,
    });
    let (state, result, error) = fixture.run_kind("tools.inventory", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let result: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    let tools = result["tools"].as_array().unwrap();
    let git = tools
        .iter()
        .find(|tool| tool["name64"].as_str().is_some())
        .expect("the inventory carries tool records");
    assert_eq!(git["present"], true);
}

#[tokio::test]
async fn the_status_surface_answers_the_documented_json() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let _path = install_stub_cli(&home);

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "timeoutSeconds": 30,
    });
    let (state, result, error) = fixture.run_kind("mise.status", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let result: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(result["mise"]["node"][0]["version"], "20.11.0");
    remove_stub_cli(&home);
}

#[tokio::test]
async fn install_is_idempotent_and_pins_the_version() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let _path = install_stub_cli(&home);
    std::fs::remove_file("/tmp/fleet-mise-stub.log").ok();

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "tool": "node",
        "version": "20.11.0",
        "timeoutSeconds": 60,
    });
    for _ in 0..2 {
        let (state, _result, error) = fixture.run_kind("mise.install", payload.clone()).await;
        assert_eq!(state, "succeeded", "{error:?}");
    }
    let log = std::fs::read_to_string("/tmp/fleet-mise-stub.log").unwrap();
    assert!(
        log.contains("install node@20.11.0"),
        "the pin travels as data: {log}"
    );
    remove_stub_cli(&home);
}

#[tokio::test]
async fn exec_passes_the_command_array_verbatim() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let _path = install_stub_cli(&home);
    std::fs::remove_file("/tmp/fleet-mise-stub.log").ok();

    let root = std::env::temp_dir().join(format!("fleet-mise-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "root": root.display().to_string(),
        "command": ["npm", "test"],
        "timeoutSeconds": 30,
    });
    let (state, result, error) = fixture.run_kind("mise.exec", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let result: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(result["kind"], "mise exec");

    let log = std::fs::read_to_string("/tmp/fleet-mise-stub.log").unwrap();
    assert!(
        log.contains("exec -- npm test"),
        "the command array survives verbatim: {log}"
    );
    let _ = std::fs::remove_dir_all(&root);
    remove_stub_cli(&home);
}

#[tokio::test]
async fn a_leading_dash_tool_is_refused_before_any_ssh_work() {
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "tool": "--flag",
        "version": "20.11.0",
        "timeoutSeconds": 10,
    });
    let (state, _result, error) = fixture.run_kind("mise.install", payload).await;
    assert_eq!(state, "failed");
    let error = error.expect("the refusal names its reason");
    assert!(error.contains("dash"), "{error}");
}

#[tokio::test]
async fn project_files_are_never_touched() {
    let _guard = CLI_LOCK.lock().await;
    let sshd = start_sshd();
    let fixture = compose(&sshd).await;
    let home = std::env::var("HOME").unwrap();
    let _path = install_stub_cli(&home);

    // A checkout with a native mise.toml: the stub never reads or writes
    // it, and the executor's scripts never name it. The file's content is
    // the authority and must survive byte-identical.
    let root = std::env::temp_dir().join(format!("fleet-mise-auth-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mise_toml = root.join("mise.toml");
    std::fs::write(&mise_toml, "[tools]\nnode = \"20\"\n").unwrap();
    let before = std::fs::read(&mise_toml).unwrap();

    let payload = serde_json::json!({
        "machineId": fixture.machine_id,
        "endpointId": fixture.endpoint_id,
        "auth": fixture.auth_json(),
        "root": root.display().to_string(),
        "command": ["node", "-v"],
        "timeoutSeconds": 30,
    });
    let (state, _result, error) = fixture.run_kind("mise.exec", payload).await;
    assert_eq!(state, "succeeded", "{error:?}");
    assert_eq!(
        std::fs::read(&mise_toml).unwrap(),
        before,
        "the native project file is the authority and is never rewritten"
    );
    let _ = std::fs::remove_dir_all(&root);
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
    let (state, _result, error) = fixture.run_kind("mise.status", payload).await;
    assert_eq!(state, "failed");
    let error = error.expect("the absence names its reason");
    assert!(error.contains("not installed"), "{error}");
}
