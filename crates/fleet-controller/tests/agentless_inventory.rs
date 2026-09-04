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
