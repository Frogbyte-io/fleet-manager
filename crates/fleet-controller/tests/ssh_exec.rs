//! End-to-end `ssh.exec` operations against a real sshd: the trust gate, the
//! script run, output as the public result, and the unverified refusal.

use fleet_application::machine::{MachinePort, NewEndpoint, RegisterMachine};
use fleet_application::operation::Operations;
use fleet_application::worker::TickReport;
use fleet_core::EndpointKind;
use fleet_provider_ssh::ExecutionLimiter;
use fleet_storage_sqlite::{AuditSink, MachineRepository, OperationRepository, Store};
use sqlx::SqlitePool;
use std::time::Duration;

mod common;
use common::{start_sshd, whoami};

async fn compose() -> (
    tempfile::TempDir,
    Operations,
    fleet_controller::exec::ScriptExecutor,
    SqlitePool,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool = store.pool().clone();
    std::mem::forget(store);
    let machines: std::sync::Arc<dyn MachinePort> =
        std::sync::Arc::new(MachineRepository::new(pool.clone()));
    let operations = Operations::new(
        std::sync::Arc::new(OperationRepository::new(pool.clone())),
        std::sync::Arc::new(AuditSink::new(pool.clone())),
    );
    let executor = fleet_controller::exec::ScriptExecutor::new(
        machines,
        dir.path().join("ssh"),
        ExecutionLimiter::new(4),
    );
    (dir, operations, executor, pool)
}

#[tokio::test]
async fn an_unverified_endpoint_refuses_to_execute() {
    let (_dir, operations, executor, pool) = compose().await;
    let sshd = start_sshd();

    let machines = MachineRepository::new(pool.clone());
    let machine = machines
        .register(&RegisterMachine {
            name: "box".to_owned(),
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
    let payload_json_string = serde_json::json!({
        "machineId": machine.id,
        "endpointId": endpoint_id,
        "script": "echo should-not-run",
        "timeoutSeconds": 10,
        "auth": {"type": "identityFile", "path": "/unused"}
    })
    .to_string();

    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &fleet_application::operation::NewOperation {
                kind: "ssh.exec".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: Some(payload_json_string),
                reviewed: false,
            },
        )
        .await
        .unwrap();

    let now = fleet_core::SystemClock::now_unix_millis();
    let report = operations
        .tick(&executor, "worker-a", now, 60_000)
        .await
        .unwrap();
    assert!(report.claimed);
    assert!(report.completed);

    let finished = operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &operation.id,
        )
        .await
        .unwrap();
    assert_eq!(finished.state, "failed");
    let error = finished.error_json.expect("the refusal names its reason");
    assert!(error.contains("never confirmed"), "{error}");
}

#[tokio::test]
async fn a_verified_endpoint_runs_the_script_and_reports_output() {
    let (dir, operations, executor, pool) = compose().await;
    let sshd = start_sshd();

    let machines = MachineRepository::new(pool);
    let machine = machines
        .register(&RegisterMachine {
            name: "box".to_owned(),
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

    let identity_file = format!("{}/user_ed25519", sshd.keys_dir.path().display());
    let payload_json_string = serde_json::json!({
        "machineId": machine.id,
        "endpointId": endpoint_id,
        "script": "echo executed-on-remote; exit 0",
        "timeoutSeconds": 15,
        "auth": {"type": "identityFile", "path": identity_file}
    })
    .to_string();

    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &fleet_application::operation::NewOperation {
                kind: "ssh.exec".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: Some(payload_json_string),
                reviewed: false,
            },
        )
        .await
        .unwrap();

    let now = fleet_core::SystemClock::now_unix_millis();
    let report = operations
        .tick(&executor, "worker-a", now, 60_000)
        .await
        .unwrap();
    assert!(report.claimed);
    assert!(report.completed);

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
    assert_eq!(result["exitCode"], 0);
    assert_eq!(result["stdout"], "executed-on-remote\n");
}

#[tokio::test]
async fn an_unknown_kind_fails_honestly() {
    let (_dir, operations, executor, pool) = compose().await;
    let _machines = MachineRepository::new(pool);
    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &fleet_application::operation::NewOperation {
                kind: "deploy-to-production".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: None,
                reviewed: false,
            },
        )
        .await
        .unwrap_err();
    let _ = operation; // creation itself refuses unknown kinds
    let _ = executor;
}

#[tokio::test]
async fn the_noop_kind_still_runs_through_the_composed_executor() {
    let (_dir, operations, executor, _pool) = compose().await;
    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            "anonymous-lan-admin",
            &fleet_application::operation::NewOperation {
                kind: "noop".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: None,
                reviewed: false,
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
    assert_eq!(finished.state, "succeeded");
    let _ = TickReport::default();
}
