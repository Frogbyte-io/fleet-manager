//! The Lab provision executor records the PVE tasks it starts against its
//! operation (FM-609), so the task history can link the clone and the start
//! back to the provisioning operation. Real SQLite repositories and a real
//! worker; fake PVE transport, accounts, and credentials.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::authz::{AccessRequest, Authorizer, Decision};
use fleet_application::lab::{
    ImageArtifactPort, LabTemplate, LabTemplatePort, LabTemplateVersion, LeasePort, NewLabTemplate,
    NewLease, NewProvision, ProvisionPort,
};
use fleet_application::operation::{NewOperation, Operations};
use fleet_application::proxmox::tasks::ProxmoxTaskLinkPort;
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccountPort, ProxmoxCredentialStore,
};
use fleet_core::{CleanupStrategy, LabTemplateContent, ReadinessProbe};
use fleet_provider_proxmox::{
    ProxmoxClient, PveHttpRequest, PveHttpResponse, PveTransport, PveTransportError,
};
use fleet_storage_sqlite::{
    AuditSink, LabRepository, LeaseRepository, OperationRepository, ProxmoxAccountRepository,
    ProxmoxTaskLinkRepository, Store,
};

const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";
const CLONE_UPID: &str = "UPID:pve:0015523F:0C6DF532:6AAFE1EC:qmclone:103:root@pam!GLM-AGENT:";
const START_UPID: &str = "UPID:pve:00155300:0C6DF600:6AAFE1F0:qmstart:104:root@pam!GLM-AGENT:";

#[derive(Debug, Default)]
struct Transport {
    paths: Mutex<Vec<String>>,
    /// The name the clone request gave the new guest, which its config
    /// then carries.
    clone_name: Mutex<Option<String>>,
}

#[async_trait]
impl PveTransport for Transport {
    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        if request.path.ends_with("/clone") {
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            *self.clone_name.lock().unwrap() = body["name"].as_str().map(str::to_owned);
        }
        self.execute(request).await
    }

    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        self.paths.lock().unwrap().push(request.path.clone());
        let path = request.path.as_str();
        let body = if path == "/api2/json/version" {
            r#"{"data":{"version":"9.0.3"}}"#.to_owned()
        } else if path == "/api2/json/cluster/resources" {
            // The pinned image's template: VMID 103 on node pve.
            r#"{"data":[{"id":"qemu/103","type":"qemu","node":"pve","vmid":103,"name":"lab-base","template":1}]}"#
                .to_owned()
        } else if path == "/api2/json/cluster/nextid" {
            r#"{"data":"104"}"#.to_owned()
        } else if path.ends_with("/clone") {
            format!(r#"{{"data":"{CLONE_UPID}"}}"#)
        } else if path.ends_with("/status/start") {
            format!(r#"{{"data":"{START_UPID}"}}"#)
        } else if path == "/api2/json/nodes/pve/qemu/104/config" {
            // The finished clone, without an inherited protection flag.
            let name = self.clone_name.lock().unwrap().clone().unwrap();
            // With the template's hardware, so none is applied (#372).
            serde_json::json!({ "data": {
                "name": name, "digest": "0123abcd", "cores": 2, "memory": "2048",
                "boot": "order=scsi0", "scsi0": "local-lvm:vm-104-disk-0,size=20G",
            } })
            .to_string()
        } else {
            // The agent probe and anything else: refused, so the guest
            // never reports ready.
            return Err(PveTransportError::Connect {
                detail: format!("unexpected path {path}"),
            });
        };
        Ok(PveHttpResponse {
            status: 200,
            body: body.into_bytes(),
        })
    }
}

#[derive(Debug)]
struct OneSecret;

#[async_trait]
impl ProxmoxCredentialStore for OneSecret {
    async fn load(&self, _account_id: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(Some("the-token-secret-material".to_owned()))
    }
    async fn store(&self, _account_id: &str, _secret: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("the executor never stores credentials")
    }
    async fn clear(&self, _account_id: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("the executor never clears credentials")
    }
}

/// The recorded build artifact: the pinned image's template is VMID 103.
#[derive(Debug)]
struct Artifacts;

#[async_trait]
impl ImageArtifactPort for Artifacts {
    async fn template_vmid(&self, _image_version_id: &str) -> Result<Option<u32>, String> {
        Ok(Some(103))
    }
    async fn promoted_template_vmids(&self) -> Result<Vec<u32>, String> {
        Ok(vec![103])
    }
}

#[derive(Debug)]
struct AllowAll;

impl Authorizer for AllowAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

#[tokio::test]
async fn the_provision_executor_links_its_clone_and_start_tasks_to_the_operation() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(&store_dir.path().join("fleet.db"))
        .await
        .unwrap();
    let pool = store.pool().clone();
    let now = fleet_core::SystemClock::now_unix_millis();

    // The account the links foreign-key to, with its trust pinned.
    let accounts = Arc::new(ProxmoxAccountRepository::new(pool.clone()));
    let account = accounts
        .create(&NewProxmoxAccount {
            name: "pve-main".to_owned(),
            host: "pve".to_owned(),
            port: None,
            token_id: "root@pam!GLM-AGENT".to_owned(),
        })
        .await
        .unwrap();
    accounts
        .set_fingerprint(&account.id, Some(FP.to_owned()))
        .await
        .unwrap();

    // A published template version, a requested lease, and its record.
    let labs = Arc::new(LabRepository::new(pool.clone()));
    let leases = Arc::new(LeaseRepository::new(pool.clone()));
    let content = LabTemplateContent {
        name: "lab-base".to_owned(),
        description: "the lab base".to_owned(),
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
        // Zero: the first failed agent probe ends the saga as never_ready.
        readiness_deadline_seconds: 0,
        ttl_seconds: 3_600,
        cleanup: CleanupStrategy::Destroy,
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
    let lease = leases
        .create(
            &NewLease {
                template_version_id: version.id.clone(),
                purpose: "links".to_owned(),
                project_id: None,
                cleanup: CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            "tester",
            now,
        )
        .await
        .unwrap();
    let record = ProvisionPort::create(
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

    let operations = Arc::new(Operations::new(
        Arc::new(OperationRepository::new(pool.clone())),
        Arc::new(AuditSink::new(pool.clone())),
    ));
    let operation = operations
        .create_lab_provision(
            &AllowAll,
            "tester",
            &lease.id,
            &NewOperation {
                kind: "lab.provision".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: Some(
                    serde_json::json!({
                        "recordId": record.id,
                        "accountId": account.id,
                        "leaseId": lease.id
                    })
                    .to_string(),
                ),
                review_token: None,
            },
        )
        .await
        .unwrap();

    let links: Arc<dyn ProxmoxTaskLinkPort> = Arc::new(ProxmoxTaskLinkRepository::new(pool));
    let executor = fleet_controller::proxmox_exec::ProvisionExecutor::new(
        accounts,
        Arc::new(OneSecret),
        labs.clone(),
        leases,
        labs.clone(),
        Arc::new(Artifacts),
        ProxmoxClient::new(Arc::new(Transport::default())),
    )
    .with_task_links(links.clone());
    let worker = fleet_controller::worker::WorkerHost::new(
        operations.clone(),
        Arc::new(fleet_controller::proxmox_exec::LabDispatch::new(
            Arc::new(fleet_application::worker::NoopExecutor),
            Arc::new(executor),
        )),
        2,
    );
    tokio::spawn(async move {
        worker.run(std::future::pending::<()>()).await;
    });

    let mut state = String::new();
    for _ in 0..200 {
        state = operations.get_state(&operation.id).await.unwrap();
        if matches!(state.as_str(), "succeeded" | "failed" | "cancelled") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // never_ready is a recorded failure; the links exist regardless.
    assert_eq!(state, "failed");
    // The record holds the reserved target (104 from nextid) on the
    // template's node, never the template's VMID from the clone UPID.
    let stored = ProvisionPort::get(labs.as_ref(), &record.id).await.unwrap();
    assert_eq!(stored.node.as_deref(), Some("pve"));
    assert_eq!(stored.vmid, Some(104));
    assert_eq!(stored.clone_upid.as_deref(), Some(CLONE_UPID));

    let found = links
        .operations_for(&account.id, &[CLONE_UPID.to_owned(), START_UPID.to_owned()])
        .await
        .unwrap();
    assert_eq!(found.get(CLONE_UPID), Some(&operation.id), "{found:?}");
    assert_eq!(found.get(START_UPID), Some(&operation.id), "{found:?}");
}
