//! FM-720 (#259): `lab.exec` runs a command on a ready lease's Lab-owned
//! machine through the SSH exec path, and refuses at execution time when the
//! lease is no longer ready. Real SQLite repositories and the real
//! `LabDispatch`; the SSH executor is a recorder.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::lab::{
    LabTemplate, LabTemplatePort, LabTemplateVersion, LeasePort, NewLabTemplate, NewLease,
    NewProvision, ProvisionPort,
};
use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::operation::{NewOperation, Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_core::{CleanupStrategy, LabTemplateContent, LeaseState, ReadinessProbe};
use fleet_storage_sqlite::{
    AuditSink, LabRepository, LeaseRepository, MachineRepository, OperationRepository,
    ProxmoxAccountRepository, RecipeRepository, Store,
};

/// Stands in for the SSH exec executor: records what it was handed and
/// completes the operation the way machine exec does.
#[derive(Debug, Default)]
struct Ssh(Mutex<Vec<(String, String, serde_json::Value)>>);

#[async_trait]
impl OperationExecutor for Ssh {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        self.0.lock().unwrap().push((
            operation.id.clone(),
            operation.kind.clone(),
            serde_json::from_str(operation.payload_json.as_deref().unwrap_or("null")).unwrap(),
        ));
        operations
            .complete(
                &operation.id,
                "succeeded",
                Some(r#"{"exitCode":0,"stdout":"Linux\n","stderr":""}"#),
                None,
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

#[tokio::test]
async fn lab_exec_runs_on_the_lease_machine_and_refuses_an_expired_lease() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool = store.pool().clone();
    let now = fleet_core::SystemClock::now_unix_millis();
    let labs = Arc::new(LabRepository::new(pool.clone()));
    let leases = Arc::new(LeaseRepository::new(pool.clone()));
    let content = LabTemplateContent {
        name: "lab-base".to_owned(),
        description: String::new(),
        image_version_id: "image-version-1".to_owned(),
        cores: 2,
        memory_mib: 2048,
        disk_gib: 20,
        bootstrap_project_id: None,
        readiness_probe: ReadinessProbe::GuestAgent,
        readiness_command: None,
        ssh_user: "root".to_owned(),
        ssh_port: 22,
        ssh_trust_mode: "tofu".to_owned(),
        ssh_fingerprint: None,
        readiness_deadline_seconds: 0,
        ttl_seconds: 3_600,
        cleanup: CleanupStrategy::Destroy,
        audio: None,
        guest_os: fleet_core::GuestOs::default(),
    };
    let template: LabTemplate = LabTemplatePort::create(
        labs.as_ref(),
        &NewLabTemplate {
            content: content.clone(),
        },
        now,
    )
    .await
    .unwrap();
    let version = labs
        .publish(
            &template.id,
            &LabTemplateVersion {
                id: "template-version-1".to_owned(),
                template_id: template.id.clone(),
                name: content.name.clone(),
                content,
                image_digest: "sha256:abc".to_owned(),
                published_by: "tester".to_owned(),
                published_at: now,
            },
        )
        .await
        .unwrap();
    let machine = MachineRepository::new(pool.clone())
        .register(&RegisterMachine {
            name: "lab-guest".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: fleet_core::EndpointKind::Ssh,
                reference: "root@192.0.2.10:22".to_owned(),
            }],
            tags: vec!["lab".to_owned()],
            groups: vec![],
        })
        .await
        .unwrap();
    let operations = Arc::new(Operations::new(
        Arc::new(OperationRepository::new(pool.clone())),
        Arc::new(AuditSink::new(pool.clone())),
    ));

    // A ready lease whose guest is the registered machine.
    let lease = leases
        .create(
            &NewLease {
                template_version_id: version.id.clone(),
                purpose: "exec".to_owned(),
                project_id: None,
                cleanup: CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            "tester",
            now,
        )
        .await
        .unwrap();
    let mut record = ProvisionPort::create(
        labs.as_ref(),
        &NewProvision {
            template_version_id: version.id.clone(),
            lease_id: Some(lease.id.clone()),
            idempotency_key: None,
            readiness_deadline_at: None,
        },
        now,
    )
    .await
    .unwrap();
    leases
        .attach_provision(&lease.id, &record.id)
        .await
        .unwrap();
    record.machine_id = Some(machine.id.clone());
    record.endpoint_id = Some(machine.endpoints[0].id.clone());
    ProvisionPort::update(labs.as_ref(), &record).await.unwrap();
    let mut ready = leases.get(&lease.id).await.unwrap();
    ready.state = LeaseState::Ready;
    ready.ready_at = Some(now);
    ready.expires_at = Some(now + 3_600_000);
    leases.update(&ready).await.unwrap();

    let ssh = Arc::new(Ssh::default());
    let dispatch = fleet_controller::proxmox_exec::LabDispatch::new(
        ssh.clone(),
        Arc::new(fleet_controller::proxmox_exec::ProvisionExecutor::new(
            Arc::new(ProxmoxAccountRepository::new(pool.clone())),
            Arc::new(fleet_controller::proxmox_store::AbsentProxmoxCredentials),
            labs.clone(),
            leases.clone(),
            labs.clone(),
            Arc::new(RecipeRepository::new(pool.clone())),
            fleet_provider_proxmox::ProxmoxClient::new(Arc::new(
                fleet_provider_proxmox::ReqwestPveTransport::new(),
            )),
        )),
    )
    .with_cleanup(
        Arc::new(fleet_controller::lab_cleanup::LabCleanupExecutor::new(
            leases.clone(),
            labs.clone(),
            Arc::new(MachineRepository::new(pool.clone())),
            Arc::new(AuditSink::new(pool.clone())),
            ssh.clone(),
        )),
        leases.clone(),
        labs.clone(),
    );
    let queue = |script: &str| NewOperation {
        kind: "lab.exec".to_owned(),
        idempotency_key: None,
        deadline_at: None,
        correlation_id: None,
        payload_json: Some(
            serde_json::json!({ "leaseId": lease.id, "script": script, "timeoutSeconds": 30 })
                .to_string(),
        ),
        review_token: None,
    };
    let run = |new: NewOperation| {
        let operations = operations.clone();
        let dispatch = &dispatch;
        let lease_id = lease.id.clone();
        async move {
            let operation = operations
                .create_lab_exec(
                    &fleet_auth::LanAllowAllAuthorizer,
                    fleet_auth::LAN_PRINCIPAL_ID,
                    &lease_id,
                    &new,
                )
                .await
                .unwrap();
            operations
                .claim_only_execute(dispatch, &operation.id, "test")
                .await
                .unwrap();
            operations
                .get(
                    &fleet_auth::LanAllowAllAuthorizer,
                    fleet_auth::LAN_PRINCIPAL_ID,
                    &operation.id,
                )
                .await
                .unwrap()
        }
    };

    let done = run(queue("uname -s")).await;
    assert_eq!(done.state, "succeeded");
    assert_eq!(
        done.kind, "lab.exec",
        "the operation keeps its lab.exec identity"
    );
    let seen = ssh.0.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let (id, kind, payload) = &seen[0];
    assert_eq!(id, &done.id);
    assert_eq!(kind, "ssh.exec");
    assert_eq!(payload["machineId"], machine.id.as_str());
    assert_eq!(payload["endpointId"], machine.endpoints[0].id.as_str());
    assert_eq!(payload["auth"]["type"], "agent");
    assert_eq!(payload["script"], "uname -s");
    assert_eq!(payload["timeoutSeconds"], 30);
    // An operation queued before `guestOs` existed is a Linux guest.
    assert_eq!(payload["guestOs"], "linux");

    // The guest OS chosen when the command was queued reaches the SSH
    // payload, where it selects the guest shell.
    let mut windows = queue("Get-Date");
    windows.payload_json = Some(
        serde_json::json!({
            "leaseId": lease.id, "script": "Get-Date", "timeoutSeconds": 30, "guestOs": "windows"
        })
        .to_string(),
    );
    assert_eq!(run(windows).await.state, "succeeded");
    assert_eq!(ssh.0.lock().unwrap()[1].2["guestOs"], "windows");

    // Expired by the time it runs: refused, nothing reaches SSH.
    let mut expired = leases.get(&lease.id).await.unwrap();
    expired.expires_at = Some(now - 1);
    leases.update(&expired).await.unwrap();
    let refused = run(queue("uname -s")).await;
    assert_eq!(refused.state, "failed");
    assert!(
        refused
            .error_json
            .unwrap_or_default()
            .contains("lease_not_ready")
    );
    assert_eq!(ssh.0.lock().unwrap().len(), 2);

    // The generic surface refuses the kind outright.
    assert!(
        operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &queue("true"),
            )
            .await
            .is_err()
    );
}
