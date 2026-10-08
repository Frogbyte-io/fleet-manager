//! FM-717 (#260): a lease from a pooled template version takes a pool
//! member instead of a clone. The claim binds one free member and records
//! it on the provision record in one transaction; the executor then boots
//! that guest, never asking PVE for a VMID or a clone. An exhausted pool
//! fails the provision without allocating anything. Real SQLite
//! repositories and operations; a scripted PVE transport.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::lab::{
    ImageArtifactPort, LabTemplate, LabTemplatePort, LabTemplateVersion, LeasePort, NewLabTemplate,
    NewLease, NewProvision, ProvisionPort,
};
use fleet_application::lab_pool::{FillResult, LabPoolPort, MemberState, NewLabPool};
use fleet_application::operation::{NewOperation, Operations};
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccountPort, ProxmoxCredentialStore,
};
use fleet_core::{CleanupStrategy, LabTemplateContent, LeaseState, ReadinessProbe};
use fleet_provider_proxmox::{
    ProxmoxClient, PveHttpRequest, PveHttpResponse, PveTransport, PveTransportError,
};
use fleet_storage_sqlite::{
    AuditSink, LabPoolRepository, LabRepository, LeaseRepository, OperationRepository,
    ProxmoxAccountRepository, Store,
};

const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";
const MEMBER_VMID: u32 = 700;
const MEMBER_NAME: &str = "pool-win11-a";
const START_UPID: &str = "UPID:pve-b:00155300:0C6DF600:6AAFE1F0:qmstart:700:fleet@pve!lab:";

/// The scripted host: the nodes and one pool member guest.
#[derive(Debug, Default)]
struct Pve {
    seen: Mutex<Vec<String>>,
}

#[async_trait]
impl PveTransport for Pve {
    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        _body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        self.execute(request).await
    }

    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        let path = request.path.clone();
        self.seen
            .lock()
            .unwrap()
            .push(format!("{:?} {path}", request.method));
        let data = match path.as_str() {
            "/api2/json/cluster/resources" => serde_json::json!([
                {"id": "node/pve-b", "type": "node", "node": "pve-b", "status": "online"},
                {"id": format!("qemu/{MEMBER_VMID}"), "type": "qemu", "node": "pve-b",
                 "vmid": MEMBER_VMID, "name": MEMBER_NAME, "template": 0, "status": "stopped"},
            ]),
            "/api2/json/version" => serde_json::json!({"version": "9.0.3"}),
            path if path.ends_with("/status/start") => serde_json::json!(START_UPID),
            other => panic!("unexpected PVE request {other}"),
        };
        Ok(PveHttpResponse {
            status: 200,
            body: serde_json::json!({ "data": data }).to_string().into_bytes(),
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

#[derive(Debug)]
struct Artifacts;

#[async_trait]
impl ImageArtifactPort for Artifacts {
    async fn template_vmid(&self, _image_version_id: &str) -> Result<Option<u32>, String> {
        panic!("a pooled provision never looks up a clone source")
    }
    async fn promoted_template_vmids(&self) -> Result<Vec<u32>, String> {
        Ok(vec![120])
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    labs: Arc<LabRepository>,
    leases: Arc<LeaseRepository>,
    pools: Arc<LabPoolRepository>,
    accounts: Arc<ProxmoxAccountRepository>,
    operations: Arc<Operations>,
    pool_id: String,
    version_id: String,
}

impl Harness {
    async fn new(members: &[u32]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        let now = fleet_core::SystemClock::now_unix_millis();
        let accounts = Arc::new(ProxmoxAccountRepository::new(pool.clone()));
        let account = accounts
            .create(&NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: "pve-api.example.test".to_owned(),
                port: None,
                token_id: "fleet@pve!lab".to_owned(),
            })
            .await
            .unwrap();
        accounts
            .set_fingerprint(&account.id, Some(FP.to_owned()))
            .await
            .unwrap();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let content = LabTemplateContent {
            name: "lab-pooled".to_owned(),
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
            // The deadline passes at once: the run stops after the boot.
            readiness_deadline_seconds: 0,
            ttl_seconds: 3_600,
            cleanup: CleanupStrategy::Revert,
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
        let pools = Arc::new(LabPoolRepository::new(pool.clone()));
        let created = pools
            .create(
                &NewLabPool {
                    template_version_id: version.id.clone(),
                    account_id: account.id.clone(),
                    baseline_snapshot: "baseline".to_owned(),
                    size: 4,
                },
                "tester",
                now,
            )
            .await
            .unwrap();
        for member in pools.add_members(&created.id, members, now).await.unwrap() {
            pools
                .finish_fill(
                    &member.id,
                    &FillResult::Available {
                        node: "pve-b".to_owned(),
                        name: MEMBER_NAME.to_owned(),
                    },
                    now,
                )
                .await
                .unwrap();
        }
        Self {
            _dir: dir,
            labs,
            leases: Arc::new(LeaseRepository::new(pool.clone())),
            pools,
            accounts,
            operations: Arc::new(Operations::new(
                Arc::new(OperationRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )),
            pool_id: created.id,
            version_id: version.id,
        }
    }

    /// Provisions one new lease; answers the operation's state and error
    /// reason, the lease, and its record.
    async fn provision(
        &self,
        pve: &Arc<Pve>,
    ) -> (
        String,
        String,
        fleet_core::Lease,
        fleet_application::lab::ProvisionRecord,
    ) {
        let now = fleet_core::SystemClock::now_unix_millis();
        let lease = self
            .leases
            .create(
                &NewLease {
                    template_version_id: self.version_id.clone(),
                    purpose: "pooled".to_owned(),
                    project_id: None,
                    cleanup: CleanupStrategy::Revert,
                    ttl_seconds: 3_600,
                },
                "tester",
                now,
            )
            .await
            .unwrap();
        let record = ProvisionPort::create(
            self.labs.as_ref(),
            &NewProvision {
                template_version_id: self.version_id.clone(),
                lease_id: Some(lease.id.clone()),
                idempotency_key: None,
                readiness_deadline_at: None,
            },
            now,
        )
        .await
        .unwrap();
        self.leases
            .attach_provision(&lease.id, &record.id)
            .await
            .unwrap();
        let operation = self
            .operations
            .create_lab_provision(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &lease.id,
                &NewOperation {
                    kind: "lab.provision".to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(
                        serde_json::json!({ "recordId": record.id, "leaseId": lease.id })
                            .to_string(),
                    ),
                    review_token: None,
                },
            )
            .await
            .unwrap();
        let executor = fleet_controller::proxmox_exec::ProvisionExecutor::new(
            self.accounts.clone(),
            Arc::new(OneSecret),
            self.labs.clone(),
            self.leases.clone(),
            self.labs.clone(),
            Arc::new(Artifacts),
            ProxmoxClient::new(pve.clone()),
        )
        .with_pools(self.pools.clone());
        let _ = self
            .operations
            .claim_only_execute(&executor, &operation.id, "test")
            .await;
        let done = self
            .operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &operation.id,
            )
            .await
            .unwrap();
        let reason = done
            .error_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
            .and_then(|error| error["reason"].as_str().map(str::to_owned))
            .unwrap_or_default();
        (
            done.state,
            reason,
            self.leases.get(&lease.id).await.unwrap(),
            ProvisionPort::get(self.labs.as_ref(), &record.id)
                .await
                .unwrap(),
        )
    }
}

#[tokio::test]
async fn a_pooled_lease_boots_its_member_and_never_clones() {
    let harness = Harness::new(&[MEMBER_VMID]).await;
    let pve = Arc::new(Pve::default());
    let (state, _, lease, record) = harness.provision(&pve).await;
    // The deadline of zero stops the run after the boot; what matters is
    // what it touched.
    assert_eq!(state, "failed");
    assert_eq!(record.vmid, Some(MEMBER_VMID));
    assert_eq!(record.node.as_deref(), Some("pve-b"));
    assert!(record.clone_upid.is_none());
    let seen = pve.seen.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|call| call.ends_with(&format!("/nodes/pve-b/qemu/{MEMBER_VMID}/status/start"))),
        "{seen:?}"
    );
    assert!(
        !seen
            .iter()
            .any(|call| call.contains("/clone") || call.contains("/nextid")),
        "{seen:?}"
    );
    // The member is this lease's, and the failed lease still owns it, so
    // its cleanup reverts it.
    let member = harness
        .pools
        .member_by_vmid(record.account_id.as_deref().unwrap(), MEMBER_VMID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(member.state, MemberState::Leased);
    assert_eq!(member.lease_id.as_deref(), Some(lease.id.as_str()));
    assert!(fleet_application::lab::lease_allocated(
        &lease,
        Some(&record)
    ));
}

#[tokio::test]
async fn an_exhausted_pool_fails_the_provision_without_allocating() {
    let harness = Harness::new(&[]).await;
    let pve = Arc::new(Pve::default());
    let (state, reason, lease, record) = harness.provision(&pve).await;
    assert_eq!(
        (state.as_str(), reason.as_str()),
        ("failed", "pool_exhausted")
    );
    assert_eq!(lease.state, LeaseState::Failed);
    assert_eq!(record.vmid, None);
    assert!(pve.seen.lock().unwrap().is_empty(), "nothing touched PVE");
    assert!(
        harness
            .pools
            .members(&harness.pool_id)
            .await
            .unwrap()
            .is_empty()
    );
}
