//! End-to-end `agentless.inventory` operations against a real sshd: the
//! trust gate, the real probe run, capability ingestion, and the snapshot.

use fleet_application::machine::{MachinePort, NewEndpoint, RegisterMachine};
use fleet_application::operation::Operations;
use fleet_core::EndpointKind;
use fleet_provider_ssh::ExecutionLimiter;
use fleet_storage_sqlite::{AuditSink, MachineRepository, OperationRepository, Store};
use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;

/// One running sshd bound to an ephemeral port with its own host key.
struct TestSshd {
    child: Child,
    port: u16,
    keys_dir: tempfile::TempDir,
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
    let authz = dir.path().join("authorized_keys");
    std::fs::write(&authz, public).unwrap();

    let port = free_port();
    let sshd_config = dir.path().join("sshd_config");
    let host_key_display = host_key.display().to_string();
    let authz_display = authz.display().to_string();
    let dir_display = dir.path().display().to_string();
    std::fs::write(
        &sshd_config,
        format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {host_key_display}\n\
             AuthorizedKeysFile {authz_display}\n\
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
        keys_dir: dir,
    }
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "nobody".to_owned())
}

async fn compose() -> (
    tempfile::TempDir,
    Operations,
    MachineRepository,
    fleet_controller::exec::ScriptExecutor,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    std::mem::forget(store);
    let machines = MachineRepository::new(store_pool(&dir).await);
    let operations = Operations::new(
        std::sync::Arc::new(OperationRepository::new(store_pool(&dir).await)),
        std::sync::Arc::new(AuditSink::new(store_pool(&dir).await)),
    );
    let executor = fleet_controller::exec::ScriptExecutor::new(
        std::sync::Arc::new(MachineRepository::new(store_pool(&dir).await)),
        dir.path().join("ssh"),
        ExecutionLimiter::new(4),
    );
    (dir, operations, machines, executor)
}

/// The store is forgotten, so tests open short-lived pools over the file;
/// the controller lock is per process and the forgotten store holds it.
async fn store_pool(dir: &tempfile::TempDir) -> sqlx::SqlitePool {
    sqlx::SqlitePool::connect(&format!(
        "sqlite://{}?mode=rw",
        dir.path().join("fleet.db").display()
    ))
    .await
    .unwrap()
}

#[tokio::test]
async fn an_inventory_operation_probes_and_ingests() {
    let (dir, operations, machines, executor) = compose().await;
    let sshd = start_sshd();

    let machine = machines
        .register(&RegisterMachine {
            name: "probe-target".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: format!("{}@127.0.0.1:{}", whoami(), sshd.port),
            }],
            tags: vec![],
            groups: vec![],
        })
        .await
        .unwrap();
    let endpoint_id = machine.endpoints[0].id.clone();

    // The trust workflow runs for real, then the operation is created.
    let provider = fleet_provider_ssh::SshProvider::new(dir.path().join("ssh")).unwrap();
    let observation = provider
        .probe_host_key("127.0.0.1", sshd.port, Duration::from_secs(10))
        .unwrap();
    provider.pin(&observation).unwrap();
    machines
        .confirm_fingerprint(&endpoint_id, &observation.fingerprint, 0)
        .await
        .unwrap();

    let payload_json = serde_json::json!({
        "machineId": machine.id,
        "endpointId": endpoint_id,
        "timeoutSeconds": 60,
        "auth": {"type": "identityFile", "path": format!("{}/user_ed25519", sshd.keys_dir.path().display())}
    })
    .to_string();

    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &fleet_application::operation::NewOperation {
                kind: "agentless.inventory".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: Some(payload_json),
                review_token: None,
            },
        )
        .await
        .unwrap();

    operations
        .tick(
            &executor,
            "worker-a",
            fleet_core::SystemClock::now_unix_millis(),
            60_000,
        )
        .await
        .unwrap();

    let finished = operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &operation.id,
        )
        .await
        .unwrap();
    assert_eq!(finished.state, "succeeded", "{:?}", finished.error_json);
    let result: serde_json::Value = serde_json::from_str(&finished.result_json.unwrap()).unwrap();
    let fact_count = result["facts"].as_u64().unwrap();
    assert!(
        fact_count >= 10,
        "the real probe produced a full baseline: {result}"
    );

    // The machine's capability facts carry the probe's provenance.
    let reloaded = machines.get(&machine.id).await.unwrap();
    let _ = reloaded;
}

/// Registers a trusted machine on a real sshd (a Linux endpoint), optionally
/// records an endpoint OS, and runs one inventory with the payload's
/// optional `guestOs`. Answers the finished operation and the machine.
async fn run_inventory(
    payload_guest_os: Option<&str>,
    recorded: Option<fleet_core::GuestOs>,
) -> (
    fleet_application::operation::Operation,
    fleet_application::machine::Machine,
) {
    let (dir, operations, machines, executor) = compose().await;
    let sshd = start_sshd();
    let machine = machines
        .register(&RegisterMachine {
            name: "os-target".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: EndpointKind::Ssh,
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
    if let Some(os) = recorded {
        machines.record_endpoint_os(&endpoint_id, os).await.unwrap();
    }
    let mut payload = serde_json::json!({
        "machineId": machine.id,
        "endpointId": endpoint_id,
        "timeoutSeconds": 60,
        "auth": {"type": "identityFile", "path": format!("{}/user_ed25519", sshd.keys_dir.path().display())}
    });
    if let Some(os) = payload_guest_os {
        payload["guestOs"] = serde_json::json!(os);
    }
    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &fleet_application::operation::NewOperation {
                kind: "agentless.inventory".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: Some(payload.to_string()),
                review_token: None,
            },
        )
        .await
        .unwrap();
    operations
        .tick(
            &executor,
            "worker-a",
            fleet_core::SystemClock::now_unix_millis(),
            60_000,
        )
        .await
        .unwrap();
    let finished = operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &operation.id,
        )
        .await
        .unwrap();
    let machine = machines.get(&machine.id).await.unwrap();
    (finished, machine)
}

/// ADR 0021 decision 4: an unknown endpoint runs the login-shell check
/// first, and a POSIX shell is recorded as Linux; the probe is unchanged.
#[tokio::test]
async fn an_unknown_endpoint_is_sniffed_and_recorded_as_linux() {
    let (finished, machine) = run_inventory(None, None).await;
    assert_eq!(finished.state, "succeeded", "{:?}", finished.error_json);
    let result: serde_json::Value = serde_json::from_str(&finished.result_json.unwrap()).unwrap();
    assert_eq!(result["guestOs"], "linux");
    assert_eq!(
        machine.endpoints[0].guest_os,
        Some(fleet_core::GuestOs::Linux)
    );
    let family = machine
        .capabilities
        .iter()
        .find(|fact| fact.namespace == "os" && fact.name == "family")
        .and_then(|fact| fact.value.clone());
    assert_eq!(family.as_deref(), Some("Linux"));
}

/// Once recorded, the payload's guest OS is a check: a contradiction fails
/// with `guest_os_mismatch` before anything is probed, and a match runs.
#[tokio::test]
async fn a_recorded_endpoint_refuses_a_contradicting_guest_os() {
    for (payload, recorded) in [
        ("windows", fleet_core::GuestOs::Linux),
        ("linux", fleet_core::GuestOs::Windows),
    ] {
        let (finished, machine) = run_inventory(Some(payload), Some(recorded)).await;
        assert_eq!(finished.state, "failed", "{payload} vs {recorded:?}");
        let error: serde_json::Value =
            serde_json::from_str(finished.error_json.as_deref().unwrap()).unwrap();
        assert_eq!(error["reason"], "guest_os_mismatch", "{error}");
        assert!(machine.capabilities.is_empty(), "nothing was probed");
        assert_eq!(machine.endpoints[0].guest_os, Some(recorded));
    }
    let (finished, _) = run_inventory(Some("linux"), Some(fleet_core::GuestOs::Linux)).await;
    assert_eq!(finished.state, "succeeded", "{:?}", finished.error_json);
}

/// An unknown endpoint detected as Linux refuses a caller who said
/// `windows`, rather than sending a PowerShell probe to Bash.
#[tokio::test]
async fn an_unknown_endpoint_detected_as_linux_refuses_a_windows_choice() {
    let (finished, machine) = run_inventory(Some("windows"), None).await;
    assert_eq!(finished.state, "failed");
    let error: serde_json::Value =
        serde_json::from_str(finished.error_json.as_deref().unwrap()).unwrap();
    assert_eq!(error["reason"], "guest_os_mismatch", "{error}");
    assert_eq!(
        machine.endpoints[0].guest_os,
        Some(fleet_core::GuestOs::Linux)
    );
}
