//! #556: the Lab pool flow handles a `guestOs: windows` template version.
//! Pool create accepts it, fill verifies a member whose PVE config carries
//! the TPM and the EFI disk (and whose baseline snapshot is listed), a
//! pooled lease runs readiness through the Windows `ssh_exec` probe, and
//! the release reverts the member and verifies the revert by reading the
//! config back. Real SQLite repositories and operations, the real
//! Proxmox-backed pool port over a scripted PVE transport, and a scripted
//! reviewed revert child standing in for FM-603's.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::lab::{
    ImageArtifactPort, LabReadinessPort, LabTemplatePort, LabTemplateVersion, LeasePort,
    NewLabTemplate, NewLease, NewProvision, ProvisionPort, ProvisionRecord, cleanup_operation,
};
use fleet_application::lab_pool::{LabPoolPort, MemberState, NewLabPool, fill_operation};
use fleet_application::operation::{NewOperation, Operation, Operations};
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccountPort, ProxmoxCredentialStore,
};
use fleet_application::worker::OperationExecutor;
use fleet_controller::lab_cleanup::LabCleanupExecutor;
use fleet_controller::lab_pool::{LabPoolFillExecutor, ProxmoxPoolGuests};
use fleet_core::{
    CleanupStrategy, GuestOs, GuestState, LabTemplateContent, LeaseState, ReadinessProbe,
};
use fleet_provider_proxmox::{
    ProxmoxClient, PveHttpMethod, PveHttpRequest, PveHttpResponse, PveTransport, PveTransportError,
};
use fleet_storage_sqlite::{
    AuditSink, LabPoolRepository, LabRepository, LeaseRepository, MachineRepository,
    OperationRepository, ProxmoxAccountRepository, Store,
};

const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";
const VMID: u32 = 700;
const NAME: &str = "pool-win11-a";
const BASELINE: &str = "baseline";
const START_UPID: &str = "UPID:pve-b:00155300:0C6DF600:6AAFE1F0:qmstart:700:fleet@pve!lab:";
const READY_COMMAND: &str = "Get-Service sshd";

/// A scripted PVE host with one stopped Windows 11 member: a `baseline`
/// snapshot, and a config that carries the TPM state and the EFI disk. The
/// config's `parent` is what a rollback leaves behind.
#[derive(Debug)]
struct Pve {
    seen: Mutex<Vec<(PveHttpMethod, String)>>,
    parent: &'static str,
}

impl Pve {
    fn new(parent: &'static str) -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
            parent,
        })
    }

    fn paths(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|(method, path)| format!("{method:?} {path}"))
            .collect()
    }
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
            .push((request.method, path.clone()));
        let data = match path.as_str() {
            "/api2/json/cluster/resources" => serde_json::json!([
                {"id": "node/pve-b", "type": "node", "node": "pve-b", "status": "online"},
                {"id": format!("qemu/{VMID}"), "type": "qemu", "node": "pve-b",
                 "vmid": VMID, "name": NAME, "template": 0, "status": "stopped"},
            ]),
            "/api2/json/version" => serde_json::json!({"version": "9.0.3"}),
            path if path.ends_with("/snapshot") => serde_json::json!([
                {"name": BASELINE, "description": "clean Windows 11", "snaptime": 1_700_000_000},
                {"name": "current", "description": "You are here!", "parent": BASELINE},
            ]),
            path if path.ends_with("/config") => serde_json::json!({
                "name": NAME, "bios": "ovmf", "machine": "pc-q35-9.0",
                "efidisk0": format!("local-lvm:vm-{VMID}-disk-0,efitype=4m,pre-enrolled-keys=1,size=4M"),
                "tpmstate0": format!("local-lvm:vm-{VMID}-disk-1,size=4M,version=v2.0"),
                "scsi0": format!("local-lvm:vm-{VMID}-disk-2,size=64G"),
                "parent": self.parent,
                "digest": "0123456789abcdef0123456789abcdef01234567",
            }),
            path if path.ends_with("/status/start") => serde_json::json!(START_UPID),
            path if path.ends_with("/agent/info") => {
                serde_json::json!({"result": {"version": "9"}})
            }
            path if path.ends_with("/agent/network-get-interfaces") => serde_json::json!({
                "result": [{"name": "Ethernet", "ip-addresses": [
                    {"ip-address": "192.0.2.42", "ip-address-type": "ipv4", "prefix": 24}
                ]}]
            }),
            other => {
                return Err(PveTransportError::Connect {
                    detail: format!("unexpected path {other}"),
                });
            }
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
        unimplemented!("the executors never store credentials")
    }
    async fn clear(&self, _account_id: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("the executors never clear credentials")
    }
}

#[derive(Debug)]
struct Artifacts;

#[async_trait]
impl ImageArtifactPort for Artifacts {
    async fn template_vmid(&self, _image_version_id: &str) -> Result<Option<u32>, String> {
        panic!("a pooled flow never looks up a clone source")
    }
    async fn promoted_template_vmids(&self) -> Result<Vec<u32>, String> {
        Ok(vec![120])
    }
}

/// The reviewed revert child: keeps its payload and succeeds.
#[derive(Debug, Default)]
struct Reverter(Mutex<Vec<(String, serde_json::Value)>>);

#[async_trait]
impl OperationExecutor for Reverter {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        self.0.lock().unwrap().push((
            operation.kind.clone(),
            serde_json::from_str(operation.payload_json.as_deref().unwrap_or("null")).unwrap(),
        ));
        operations
            .complete(&operation.id, "succeeded", Some("{}"), None)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// Records the readiness steps and the guest OS the SSH probe is asked for.
#[derive(Debug, Default)]
struct Readiness {
    calls: Mutex<Vec<String>>,
    ssh: Mutex<Vec<(String, GuestOs)>>,
}

#[async_trait]
impl LabReadinessPort for Readiness {
    async fn trust(
        &self,
        _record: &ProvisionRecord,
        _content: &LabTemplateContent,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        self.calls.lock().unwrap().push("trust".to_owned());
        Ok(true)
    }
    async fn ssh_probe(
        &self,
        _operations: &Operations,
        _parent_id: &str,
        _record: &ProvisionRecord,
        command: &str,
        guest_os: GuestOs,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        self.calls.lock().unwrap().push("ssh_exec".to_owned());
        self.ssh
            .lock()
            .unwrap()
            .push((command.to_owned(), guest_os));
        Ok(true)
    }
    async fn interactive_session(
        &self,
        _operations: &Operations,
        _parent_id: &str,
        _record: &ProvisionRecord,
        _user: &str,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        unreachable!("the template declares no interactive user")
    }
    async fn create_project(
        &self,
        _operations: &Operations,
        _parent_id: &str,
        _record: &ProvisionRecord,
        _project_id: &str,
        _remaining: std::time::Duration,
    ) -> Result<String, String> {
        unreachable!("the template bootstraps no project")
    }
    async fn project_verified(
        &self,
        _operations: &Operations,
        _child_id: &str,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        unreachable!("the template bootstraps no project")
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    labs: Arc<LabRepository>,
    leases: Arc<LeaseRepository>,
    pools: Arc<LabPoolRepository>,
    accounts: Arc<ProxmoxAccountRepository>,
    operations: Arc<Operations>,
    pve: Arc<Pve>,
    reverter: Arc<Reverter>,
    pool_id: String,
    account_id: String,
}

impl Harness {
    /// An empty pool over a published Windows `ssh_exec` template version;
    /// the host reads a reverted member's `parent` as `parent`.
    async fn new(parent: &'static str) -> Self {
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
            name: "lab-windows".to_owned(),
            image_version_id: "image-version-1".to_owned(),
            cores: 4,
            memory_mib: 8192,
            disk_gib: 64,
            readiness_probe: ReadinessProbe::SshExec,
            readiness_command: Some(READY_COMMAND.to_owned()),
            ssh_user: "Administrator".to_owned(),
            readiness_deadline_seconds: 60,
            ttl_seconds: 3_600,
            cleanup: CleanupStrategy::Revert,
            guest_os: GuestOs::Windows,
            ..LabTemplateContent::default()
        };
        let template = LabTemplatePort::create(
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
        assert_eq!(version.content.guest_os, GuestOs::Windows);
        let pools = Arc::new(LabPoolRepository::new(pool.clone()));
        let created = pools
            .create(
                &NewLabPool {
                    template_version_id: version.id.clone(),
                    account_id: account.id.clone(),
                    baseline_snapshot: BASELINE.to_owned(),
                    size: 2,
                },
                "tester",
                now,
            )
            .await
            .expect("pool create accepts a Windows template version");
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
            pve: Pve::new(parent),
            reverter: Arc::new(Reverter::default()),
            pool_id: created.id,
            account_id: account.id,
            pool,
        }
    }

    /// The real Proxmox-backed pool port over the scripted host.
    fn guests(&self) -> Arc<ProxmoxPoolGuests> {
        Arc::new(ProxmoxPoolGuests::new(
            self.accounts.clone() as Arc<dyn ProxmoxAccountPort>,
            Arc::new(OneSecret),
            ProxmoxClient::new(self.pve.clone()),
            Arc::new(Artifacts),
        ))
    }

    async fn operation(&self, id: &str) -> Operation {
        self.operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                id,
            )
            .await
            .unwrap()
    }

    /// Adds `VMID` to the pool and runs one `lab.pool.fill`; answers the
    /// operation's result.
    async fn fill(&self) -> serde_json::Value {
        let now = fleet_core::SystemClock::now_unix_millis();
        self.pools
            .add_members(&self.pool_id, &[VMID], now)
            .await
            .unwrap();
        let operation = self
            .operations
            .create_lab_pool_fill(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &self.pool_id,
                &fill_operation(&self.pool_id, None),
            )
            .await
            .unwrap();
        let fill = LabPoolFillExecutor::new(
            self.pools.clone(),
            self.labs.clone(),
            self.guests(),
            self.reverter.clone(),
            Arc::new(AuditSink::new(self.pool.clone())),
        );
        self.operations
            .claim_only_execute(&fill, &operation.id, "test")
            .await
            .unwrap();
        let done = self.operation(&operation.id).await;
        assert_eq!(done.state, "succeeded", "{:?}", done.error_json);
        serde_json::from_str(done.result_json.as_deref().unwrap()).unwrap()
    }

    /// Runs one pooled `lab.provision` with the recording readiness port;
    /// answers the lease and its record.
    async fn lease(&self, readiness: &Arc<Readiness>) -> (fleet_core::Lease, ProvisionRecord) {
        let now = fleet_core::SystemClock::now_unix_millis();
        let lease = self
            .leases
            .create(
                &NewLease {
                    template_version_id: "template-version-1".to_owned(),
                    purpose: "windows pool".to_owned(),
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
                template_version_id: "template-version-1".to_owned(),
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
            ProxmoxClient::new(self.pve.clone()),
        )
        .with_pools(self.pools.clone())
        .with_readiness(
            readiness.clone(),
            Arc::new(AuditSink::new(self.pool.clone())),
        );
        let _ = self
            .operations
            .claim_only_execute(&executor, &operation.id, "test")
            .await;
        let done = self.operation(&operation.id).await;
        assert_eq!(done.state, "succeeded", "{:?}", done.error_json);
        (
            self.leases.get(&lease.id).await.unwrap(),
            ProvisionPort::get(self.labs.as_ref(), &record.id)
                .await
                .unwrap(),
        )
    }

    /// Releases the lease through `lab.cleanup`; answers the operation's
    /// final state.
    async fn release(&self, lease_id: &str) -> String {
        let mut releasing = self.leases.get(lease_id).await.unwrap();
        releasing.state = LeaseState::Releasing;
        self.leases.update(&releasing).await.unwrap();
        let operation = self
            .operations
            .create_lab_cleanup(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                lease_id,
                &cleanup_operation(&releasing, None),
            )
            .await
            .unwrap();
        let executor = LabCleanupExecutor::new(
            self.leases.clone(),
            self.labs.clone(),
            Arc::new(MachineRepository::new(self.pool.clone())),
            Arc::new(AuditSink::new(self.pool.clone())),
            // Destroy is never reached for a pooled lease.
            Arc::new(Reverter::default()),
        )
        .with_pools(self.pools.clone(), self.guests(), self.reverter.clone());
        let _ = self
            .operations
            .claim_only_execute(&executor, &operation.id, "test")
            .await;
        self.operation(&operation.id).await.state
    }

    async fn member(&self) -> (MemberState, Option<String>) {
        let member = self
            .pools
            .member_by_vmid(&self.account_id, VMID)
            .await
            .unwrap()
            .unwrap();
        (member.state, member.lease_id)
    }
}

#[tokio::test]
async fn a_windows_pool_fills_leases_through_the_windows_probe_and_reverts() {
    let harness = Harness::new(BASELINE).await;

    // Fill: the member's snapshot list and config (TPM and EFI disk) are
    // read, it is reverted to the baseline and becomes available.
    let result = harness.fill().await;
    assert_eq!(result["available"], serde_json::json!([VMID]));
    assert_eq!(harness.member().await.0, MemberState::Available);
    {
        let reverted = harness.reverter.0.lock().unwrap();
        assert_eq!(reverted.len(), 1);
        assert_eq!(reverted[0].0, "proxmox.guest.snapshot-revert");
        assert_eq!(reverted[0].1["vmid"], VMID);
        assert_eq!(reverted[0].1["params"]["snapshot"], BASELINE);
    }
    let paths = harness.pve.paths();
    for suffix in ["snapshot", "config"] {
        let wanted = format!("Get /api2/json/nodes/pve-b/qemu/{VMID}/{suffix}");
        assert!(paths.contains(&wanted), "{wanted} in {paths:?}");
    }

    // Lease: the pooled member boots, never clones, and readiness runs the
    // `ssh_exec` probe for a Windows guest.
    let readiness = Arc::new(Readiness::default());
    let (lease, record) = harness.lease(&readiness).await;
    assert_eq!(record.state, GuestState::Ready, "{record:?}");
    assert_eq!(record.vmid, Some(VMID));
    assert!(record.clone_upid.is_none());
    assert_eq!(*readiness.calls.lock().unwrap(), vec!["trust", "ssh_exec"]);
    assert_eq!(
        *readiness.ssh.lock().unwrap(),
        vec![(READY_COMMAND.to_owned(), GuestOs::Windows)]
    );
    assert_eq!(
        harness.member().await,
        (MemberState::Leased, Some(lease.id.clone()))
    );
    let paths = harness.pve.paths();
    assert!(
        !paths
            .iter()
            .any(|p| p.contains("/clone") || p.contains("/nextid")),
        "{paths:?}"
    );

    // Release: the member is reverted to the baseline, the revert verified
    // from the config, and the member returns to the pool, never destroyed.
    assert_eq!(harness.release(&lease.id).await, "succeeded");
    assert_eq!(harness.member().await, (MemberState::Available, None));
    let reverted = harness.reverter.0.lock().unwrap().clone();
    assert_eq!(reverted.len(), 2, "one revert at fill, one at release");
    assert_eq!(reverted[1].1["params"]["snapshot"], BASELINE);
    let paths = harness.pve.paths();
    assert!(!paths.iter().any(|p| p.starts_with("Delete")), "{paths:?}");
    assert_eq!(
        harness.leases.get(&lease.id).await.unwrap().state,
        LeaseState::Released
    );
}

#[tokio::test]
async fn a_windows_revert_that_did_not_restore_the_baseline_quarantines_the_member() {
    // PVE reports the config derived from another snapshot: the revert is
    // not verified, so the member must not enter the pool.
    let harness = Harness::new("stale").await;
    let result = harness.fill().await;
    assert_eq!(result["available"], serde_json::json!([]));
    assert_eq!(result["quarantined"], serde_json::json!([VMID]));
    assert_eq!(harness.member().await.0, MemberState::Quarantined);
}
