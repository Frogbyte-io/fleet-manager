//! FM-1126 (#573): mid-run hotplug of a Lab lease's USB device. A lease whose
//! template declares a USB device holds it attached to its clone when it is
//! ready; its holder (or an administrator) detaches it from the running
//! guest, attaches it again, or gives it up, and cleanup still detaches
//! whatever the lease holds before it decides the guest's fate.
//!
//! **Simulated.** The shared fake Proxmox (`support/fake_pve.rs`) behind the
//! USB-aware layer (`support/usb_pve.rs`) that speaks the FM-S11 spike's
//! shapes (mapping list and `check-node`, `usbN` entries with the applied,
//! pending-add and pending-delete views, the config digest, a guest whose
//! `hotplug` option lacks `usb`), and a controller over one SQLite file with
//! the real reservation store, the real inventory, the real provider calls,
//! the real saga and the real hotplug use case. Every device id, VMID and
//! address is invented.
//!
//! What is *not* measured here, and is assumed from the spike's notes and the
//! provider's own tests: deleting a pending-only leftover from a running
//! guest, and what PVE does with a pending detach once the guest stops.

#[allow(dead_code)]
#[path = "support/fake_pve.rs"]
mod fake_pve;
#[path = "support/usb_pve.rs"]
mod usb_pve;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use fake_pve::{FINGERPRINT, FakePve, Faults, TEMPLATE_NODE, TEMPLATE_VMID};
use fleet_application::audit::AuditOutcome;
use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision};
use fleet_application::hardware::HardwareStore;
use fleet_application::hardware_inventory::{DeviceFilter, HardwareInventory};
use fleet_application::hardware_reservation::HardwareReservations;
use fleet_application::lab::{
    ImageArtifactPort, ImagePinValidator, Lab, LabReadinessPort, LabTemplatePort,
    LabTemplateVersion, LeasePort, NewLabTemplate, NewLease, ProvisionPort, ProvisionRecord,
};
use fleet_application::lab_hardware_hotplug::{
    HotplugError, HotplugOutcome, HotplugResult, LabHardwareHotplug,
};
use fleet_application::lab_placement::{HardwareDemand, HardwarePlacement};
use fleet_application::operation::{AuditPort, NewOperation, Operation, Operations};
use fleet_application::project::{NewProject, ProjectPort as _};
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccountPort, ProxmoxCredentialStore,
};
use fleet_application::worker::OperationExecutor;
use fleet_controller::hardware_reservation_store::SqliteHardwareReservations;
use fleet_controller::lab_cleanup::LabCleanupExecutor;
use fleet_controller::lab_hardware::{LabHardwareSaga, SqliteFingerprintPins};
use fleet_controller::lab_hardware_hotplug::LabHotplug;
use fleet_controller::proxmox_exec::{
    LabDispatch, ProvisionExecutor, ProxmoxDestructiveExecutor, ProxmoxDispatch,
    ProxmoxLifecycleExecutor,
};
use fleet_core::{
    CleanupStrategy, DeviceStatus, HardwareKind, HardwareReservationState as State, LabHardware,
    LabTemplateContent, Lease, LeaseState, ReadinessProbe,
};
use fleet_provider_proxmox::ProxmoxClient;
use fleet_storage_sqlite::{
    AuditSink, HardwareRepository, LabRepository, LeaseRepository, MachineRepository,
    OperationRepository, ProjectRepository, ProxmoxAccountRepository, Store,
};
use usb_pve::{UsbFault, UsbHost, UsbStep};

const PRINCIPAL: &str = fleet_auth::LAN_PRINCIPAL_ID;
const IMAGE_VERSION: &str = "image-version-1";
const TTL_SECONDS: u32 = 86_400;
const LEASE_MS: i64 = fleet_controller::worker::LEASE_MS;
/// Two devices on the template's node, one port each.
const READER_A: &str = "fm-test-reader-a";
const READER_B: &str = "fm-test-reader-b";

fn now() -> i64 {
    fleet_core::SystemClock::now_unix_millis()
}

fn usb(mapping: &str) -> LabHardware {
    LabHardware {
        kind: HardwareKind::Usb,
        mapping: mapping.to_owned(),
    }
}

#[derive(Debug)]
struct AllowAll;

impl Authorizer for AllowAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

/// The saga's audit sink, which can be told to refuse the intent of one
/// event (the attach or the detach intent is required before the write).
#[derive(Debug)]
struct GateAudit {
    inner: AuditSink,
    refuse_event: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl AuditPort for GateAudit {
    async fn record_intent(
        &self,
        intent: &fleet_application::audit::AuditIntent,
    ) -> Result<(), String> {
        let refused = self.refuse_event.lock().unwrap().clone();
        if let Some(refused) = refused
            && intent
                .metadata
                .entries()
                .any(|(key, value)| key == "event" && value == refused)
        {
            return Err("the audit sink is refusing".to_owned());
        }
        self.inner.record_intent(intent).await
    }

    async fn record_outcome(
        &self,
        operation_id: &str,
        outcome: AuditOutcome,
    ) -> Result<(), String> {
        self.inner.record_outcome(operation_id, outcome).await
    }
}

/// The world a controller runs in: one SQLite file and one Proxmox host that
/// outlive every controller.
struct World {
    _dir: tempfile::TempDir,
    database: PathBuf,
    faults: Arc<Faults>,
    pve: Arc<FakePve>,
    usb: Arc<UsbHost>,
    refuse_event: Arc<Mutex<Option<String>>>,
    account_id: String,
    version_id: String,
}

impl World {
    /// A world whose template declares `hardware` (mapping ids).
    async fn new(hardware: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("fleet.db");
        let faults = Arc::new(Faults::default());
        let pve = FakePve::new(faults.clone());
        let usb_host = UsbHost::new(pve.clone());
        usb_host.add_mapping(READER_A, &["node=pve-b,id=aaaa:0001,path=1-1"]);
        usb_host.add_mapping(READER_B, &["node=pve-b,id=bbbb:0002,path=1-2"]);
        let store = Store::open(&database).await.unwrap();
        let pool = store.pool().clone();
        let accounts = ProxmoxAccountRepository::new(pool.clone());
        let account = accounts
            .create(&NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: fake_pve::API_HOST.to_owned(),
                port: None,
                token_id: "fleet@pve!lab".to_owned(),
            })
            .await
            .unwrap();
        accounts
            .set_fingerprint(&account.id, Some(FINGERPRINT.to_owned()))
            .await
            .unwrap();
        let project = ProjectRepository::new(pool.clone())
            .create(&NewProject {
                fetch: fleet_core::RemoteFetch::default(),
                remote: "example.org/demo".to_owned(),
                idempotency_key: None,
                name: "demo".to_owned(),
                description: String::new(),
            })
            .await
            .unwrap();
        let labs = LabRepository::new(pool.clone());
        let content = LabTemplateContent {
            name: "lab-base".to_owned(),
            description: String::new(),
            image_version_id: IMAGE_VERSION.to_owned(),
            cores: 2,
            memory_mib: 2048,
            disk_gib: 20,
            bootstrap_project_id: Some(project.id.clone()),
            readiness_probe: ReadinessProbe::GuestAgent,
            readiness_command: None,
            ssh_user: "root".to_owned(),
            ssh_port: 22,
            ssh_trust_mode: "tofu".to_owned(),
            ssh_fingerprint: None,
            readiness_deadline_seconds: 30,
            ttl_seconds: TTL_SECONDS,
            cleanup: CleanupStrategy::Destroy,
            audio: None,
            guest_os: fleet_core::GuestOs::default(),
            interactive_user: None,
            hardware: hardware.iter().map(|mapping| usb(mapping)).collect(),
        };
        let template = LabTemplatePort::create(
            &labs,
            &NewLabTemplate {
                content: content.clone(),
            },
            now(),
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
                    published_by: PRINCIPAL.to_owned(),
                    published_at: now(),
                },
            )
            .await
            .unwrap();
        pool.close().await;
        drop(store);
        Self {
            _dir: dir,
            database,
            faults,
            pve,
            usb: usb_host,
            refuse_event: Arc::new(Mutex::new(None)),
            account_id: account.id,
            version_id: version.id,
        }
    }
}

#[derive(Debug)]
struct Promoted;

#[async_trait]
impl ImagePinValidator for Promoted {
    async fn promoted_version(
        &self,
        version_id: &str,
    ) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok(
            (version_id == IMAGE_VERSION).then(|| fleet_core::RecipeVersion {
                id: IMAGE_VERSION.to_owned(),
                recipe_id: "recipe-1".to_owned(),
                name: "lab-image".to_owned(),
                content_digest: "sha256:abc".to_owned(),
                description: String::new(),
                content: "{}".to_owned(),
                source: fleet_core::RecipeSource::Clone,
                node: TEMPLATE_NODE.to_owned(),
                storage_pool: "local-lvm".to_owned(),
                published_at: 0,
                promoted_at: Some(0),
                promoted_by: Some(PRINCIPAL.to_owned()),
                promoted_build_id: Some("build-1".to_owned()),
                allow_insecure_tls: false,
            }),
        )
    }
}

#[derive(Debug)]
struct Artifacts;

#[async_trait]
impl ImageArtifactPort for Artifacts {
    async fn template_vmid(&self, image_version_id: &str) -> Result<Option<u32>, String> {
        Ok((image_version_id == IMAGE_VERSION).then_some(TEMPLATE_VMID))
    }

    async fn promoted_template_vmids(&self) -> Result<Vec<u32>, String> {
        Ok(vec![TEMPLATE_VMID])
    }
}

#[derive(Debug)]
struct OneSecret;

#[async_trait]
impl ProxmoxCredentialStore for OneSecret {
    async fn load(&self, _account_id: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(Some("fake-token-material".to_owned()))
    }
    async fn store(&self, _account_id: &str, _secret: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("the Lab never stores credentials")
    }
    async fn clear(&self, _account_id: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("the Lab never clears credentials")
    }
}

/// SSH trust and the bootstrap project, scripted to succeed.
#[derive(Debug)]
struct Readiness;

#[async_trait]
impl LabReadinessPort for Readiness {
    async fn trust(
        &self,
        _record: &ProvisionRecord,
        _content: &LabTemplateContent,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
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
        Ok(true)
    }

    async fn ssh_probe(
        &self,
        _operations: &Operations,
        _parent_id: &str,
        _record: &ProvisionRecord,
        _command: &str,
        _guest_os: fleet_core::GuestOs,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        Ok(true)
    }

    async fn create_project(
        &self,
        operations: &Operations,
        _parent_id: &str,
        record: &ProvisionRecord,
        _project_id: &str,
        _remaining: std::time::Duration,
    ) -> Result<String, String> {
        let child = operations
            .create(
                &AllowAll,
                PRINCIPAL,
                &NewOperation {
                    kind: "ready.workflow".to_owned(),
                    idempotency_key: Some(format!("lab-ready:{}", record.id)),
                    deadline_at: record.readiness_deadline_at,
                    correlation_id: Some(record.id.clone()),
                    review_token: None,
                    payload_json: Some(
                        serde_json::json!({
                            "machineId": record.machine_id, "endpointId": record.endpoint_id,
                            "auth": {"type": "agent"}, "remote": "example.org/demo",
                            "root": "/tmp/fleet-projects/demo", "timeoutSeconds": 30
                        })
                        .to_string(),
                    ),
                },
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(child.id)
    }

    async fn project_verified(
        &self,
        operations: &Operations,
        child_id: &str,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        if operations
            .get_state(child_id)
            .await
            .map_err(|e| e.to_string())?
            == "pending"
        {
            operations
                .claim_only_execute(&Rest, child_id, "lab-ready")
                .await?;
        }
        Ok(operations
            .get_state(child_id)
            .await
            .map_err(|e| e.to_string())?
            == "succeeded")
    }
}

#[derive(Debug)]
struct Rest;

#[async_trait]
impl OperationExecutor for Rest {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        if operation.kind != "ready.workflow" {
            return Err(format!("unexpected operation kind {}", operation.kind));
        }
        operations
            .complete(
                &operation.id,
                "succeeded",
                Some(r#"{"ready":true,"completed":["verify"]}"#),
                None,
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// How a run of controller work ended.
#[derive(Debug, PartialEq, Eq)]
enum Run<T> {
    Done(T),
    Crashed,
}

/// One controller run over the world.
struct Controller {
    _store: Store,
    pool: sqlx::SqlitePool,
    operations: Arc<Operations>,
    executor: Arc<dyn OperationExecutor>,
    lab: Arc<Lab>,
    leases: Arc<LeaseRepository>,
    labs: Arc<LabRepository>,
    inventory: Arc<HardwareInventory>,
    placement: Arc<HardwarePlacement>,
    hotplug: Arc<LabHardwareHotplug>,
    account_id: String,
    version_id: String,
}

impl Controller {
    async fn start(world: &World) -> Self {
        let store = Store::open(&world.database)
            .await
            .expect("the previous controller released the database");
        let pool = store.pool().clone();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let leases = Arc::new(LeaseRepository::new(pool.clone()));
        let audit = Arc::new(AuditSink::new(pool.clone()));
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            audit.clone(),
        ));
        let accounts: Arc<dyn ProxmoxAccountPort> =
            Arc::new(ProxmoxAccountRepository::new(pool.clone()));
        let credentials: Arc<dyn ProxmoxCredentialStore> = Arc::new(OneSecret);
        let client = ProxmoxClient::new(world.usb.transport());
        let store_port: Arc<dyn HardwareStore> = Arc::new(HardwareRepository::new(pool.clone()));
        let reservations = Arc::new(HardwareReservations::new(
            Arc::new(SqliteHardwareReservations::new(pool.clone())),
            audit.clone(),
        ));
        let placement = Arc::new(HardwarePlacement::new(
            store_port.clone(),
            reservations.clone(),
            900_000,
        ));
        let inventory = Arc::new(HardwareInventory::new(
            accounts.clone(),
            credentials.clone(),
            store_port.clone(),
            fleet_controller::hardware_observer::shared(client.clone()),
            audit.clone(),
        ));
        let saga = Arc::new(LabHardwareSaga::new(
            accounts.clone(),
            credentials.clone(),
            client.clone(),
            store_port.clone(),
            reservations,
            inventory.clone(),
            Arc::new(GateAudit {
                inner: AuditSink::new(pool.clone()),
                refuse_event: world.refuse_event.clone(),
            }),
            leases.clone(),
            Arc::new(SqliteFingerprintPins::new(pool.clone())),
        ));
        let hotplug = Arc::new(LabHardwareHotplug::new(
            leases.clone(),
            labs.clone(),
            Arc::new(LabHotplug::new(saga.clone(), store_port.clone())),
        ));
        let destroyer = Arc::new(
            ProxmoxDestructiveExecutor::new(accounts.clone(), credentials.clone(), client.clone())
                .with_image_artifacts(Arc::new(Artifacts))
                .with_hardware_guard(store_port),
        );
        let cleanup = Arc::new(
            LabCleanupExecutor::new(
                leases.clone(),
                labs.clone(),
                Arc::new(MachineRepository::new(pool.clone())),
                audit.clone(),
                destroyer.clone(),
            )
            .with_devices(placement.clone())
            .with_device_saga(saga.clone()),
        );
        let provision = Arc::new(
            ProvisionExecutor::new(
                accounts.clone(),
                credentials.clone(),
                labs.clone(),
                leases.clone(),
                labs.clone(),
                Arc::new(Artifacts),
                client.clone(),
            )
            .with_readiness(Arc::new(Readiness), audit.clone())
            .with_device_placement(placement.clone())
            .with_device_saga(saga.clone()),
        );
        let executor: Arc<dyn OperationExecutor> = Arc::new(
            LabDispatch::new(
                Arc::new(ProxmoxDispatch::new(
                    Arc::new(Rest),
                    Arc::new(ProxmoxLifecycleExecutor::new(
                        accounts.clone(),
                        credentials.clone(),
                        client.clone(),
                    )),
                    destroyer.clone(),
                )),
                provision,
            )
            .with_cleanup(cleanup, leases.clone(), labs.clone()),
        );
        let lab = Arc::new(Lab::new(
            labs.clone(),
            labs.clone(),
            leases.clone(),
            Arc::new(Promoted),
            Arc::new(ProjectRepository::new(pool.clone())),
            audit.clone(),
        ));
        Self {
            _store: store,
            pool,
            operations,
            executor,
            lab,
            leases,
            labs,
            inventory,
            placement,
            hotplug,
            account_id: world.account_id.clone(),
            version_id: world.version_id.clone(),
        }
    }

    async fn run<T, F>(&self, world: &World, work: F) -> Run<T>
    where
        T: Send + 'static,
        F: std::future::Future<Output = T> + Send + 'static,
    {
        let mut task = tokio::spawn(work);
        tokio::select! {
            biased;
            () = world.faults.crashed() => {
                task.abort();
                let _ = task.await;
                Run::Crashed
            }
            done = tokio::time::timeout(std::time::Duration::from_secs(60), &mut task) => {
                Run::Done(done.expect("controller work finishes or crashes").unwrap())
            }
        }
    }

    /// Records the world's USB devices (the inventory refresh the operator
    /// or the API makes before a lease asks for one).
    async fn refresh_inventory(&self) {
        self.inventory
            .refresh(
                &AllowAll,
                &ActingPrincipal {
                    id: PRINCIPAL.to_owned(),
                },
                None,
                &self.account_id,
            )
            .await
            .expect("the inventory refreshes");
    }

    /// Requests a lease and queues its provision, as the API does.
    async fn request_lease(&self) -> String {
        self.request_lease_as(PRINCIPAL).await
    }

    /// The same, for a lease owned by `principal_id`.
    async fn request_lease_as(&self, principal_id: &str) -> String {
        let principal = ActingPrincipal {
            id: principal_id.to_owned(),
        };
        let lease = self
            .lab
            .create_lease(
                &AllowAll,
                &principal,
                NewLease {
                    template_version_id: self.version_id.clone(),
                    purpose: "hardware hotplug".to_owned(),
                    project_id: None,
                    cleanup: CleanupStrategy::Destroy,
                    ttl_seconds: TTL_SECONDS,
                },
                now(),
            )
            .await
            .unwrap();
        let (record, _) = self
            .lab
            .start_lease_provision(&AllowAll, &principal, &lease.id, None, now())
            .await
            .unwrap();
        self.operations
            .create_lab_provision(
                &AllowAll,
                PRINCIPAL,
                &lease.id,
                &NewOperation {
                    kind: "lab.provision".to_owned(),
                    idempotency_key: Some(fleet_application::lab::lease_provision_operation_key(
                        PRINCIPAL, &lease.id,
                    )),
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(
                        serde_json::json!({
                            "recordId": record.id,
                            "leaseId": lease.id,
                            "accountId": self.account_id,
                        })
                        .to_string(),
                    ),
                    review_token: None,
                },
            )
            .await
            .unwrap();
        lease.id
    }

    async fn release_with(&self, lease_id: &str, keep: bool) {
        let principal = ActingPrincipal {
            id: PRINCIPAL.to_owned(),
        };
        let lease = self
            .lab
            .release_lease(&AllowAll, &principal, lease_id, keep, now())
            .await
            .unwrap();
        self.operations
            .create_lab_cleanup(
                &AllowAll,
                PRINCIPAL,
                lease_id,
                &fleet_application::lab::cleanup_operation(&lease, None),
            )
            .await
            .unwrap();
    }

    async fn release(&self, lease_id: &str) {
        self.release_with(lease_id, false).await;
    }

    /// Runs the queued operations to completion, or until a crash point.
    async fn drain(&self, world: &World) -> Run<usize> {
        let operations = self.operations.clone();
        let executor = self.executor.clone();
        self.run(world, async move {
            for ran in 0..200 {
                let report = operations
                    .tick(executor.as_ref(), "hardware-suite-worker", now(), LEASE_MS)
                    .await
                    .unwrap();
                if !report.claimed {
                    return ran;
                }
            }
            panic!("the operation queue never drained");
        })
        .await
    }

    async fn lease(&self, id: &str) -> Lease {
        self.leases.get(id).await.unwrap()
    }

    async fn record(&self, lease_id: &str) -> ProvisionRecord {
        let lease = self.lease(lease_id).await;
        ProvisionPort::get(self.labs.as_ref(), lease.provision_id.as_deref().unwrap())
            .await
            .unwrap()
    }

    /// The provision operation of a lease.
    async fn provision_operation(&self, lease_id: &str) -> Operation {
        self.operations
            .find_by_idempotency_key(&fleet_application::lab::lease_provision_operation_key(
                PRINCIPAL, lease_id,
            ))
            .await
            .unwrap()
            .expect("the provision operation exists")
    }

    /// The reason the provision operation failed with.
    async fn failure_reason(&self, lease_id: &str) -> String {
        let operation = self.provision_operation(lease_id).await;
        let operation = self
            .operations
            .get(&AllowAll, PRINCIPAL, &operation.id)
            .await
            .unwrap();
        operation
            .error_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
            .and_then(|error| error["reason"].as_str().map(str::to_owned))
            .unwrap_or_default()
    }

    /// Every reservation row, oldest first: state, slot, guest VMID.
    async fn rows(&self) -> Vec<(String, Option<i64>, Option<i64>)> {
        sqlx::query_as(
            "SELECT state, usb_slot, guest_vmid FROM hardware_reservations ORDER BY created_at, id",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    async fn states(&self) -> Vec<String> {
        self.rows()
            .await
            .into_iter()
            .map(|(state, ..)| state)
            .collect()
    }

    /// The status a reader sees for the mapping's device.
    async fn device_view(&self, mapping: &str) -> DeviceStatus {
        self.inventory
            .list(
                &AllowAll,
                &ActingPrincipal {
                    id: PRINCIPAL.to_owned(),
                },
                &DeviceFilter {
                    account_id: Some(self.account_id.clone()),
                },
                50,
                None,
            )
            .await
            .unwrap()
            .into_iter()
            .find(|view| view.device.mapping_id == mapping)
            .expect("the device is inventoried")
            .status
    }

    async fn audit_events(&self, event: &str) -> usize {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE outcome IS NULL AND metadata_json LIKE ?1",
        )
        .bind(format!("%\"{event}\"%"))
        .fetch_one(&self.pool)
        .await
        .unwrap();
        usize::try_from(count).unwrap()
    }

    async fn audit_metadata(&self, event: &str) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT metadata_json FROM audit_events WHERE outcome IS NULL AND metadata_json LIKE ?1 ORDER BY rowid",
        )
        .bind(format!("%\"{event}\"%"))
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }
}

impl Controller {
    async fn attach(&self, lease: &str, mapping: &str) -> Result<HotplugOutcome, HotplugError> {
        self.attach_as(&AllowAll, PRINCIPAL, lease, mapping).await
    }

    async fn attach_as(
        &self,
        authorizer: &dyn Authorizer,
        principal: &str,
        lease: &str,
        mapping: &str,
    ) -> Result<HotplugOutcome, HotplugError> {
        self.hotplug
            .attach(
                authorizer,
                &ActingPrincipal {
                    id: principal.to_owned(),
                },
                lease,
                mapping,
                now(),
            )
            .await
    }

    async fn detach(
        &self,
        lease: &str,
        mapping: &str,
        release: bool,
    ) -> Result<HotplugOutcome, HotplugError> {
        self.detach_as(&AllowAll, PRINCIPAL, lease, mapping, release)
            .await
    }

    async fn detach_as(
        &self,
        authorizer: &dyn Authorizer,
        principal: &str,
        lease: &str,
        mapping: &str,
        release: bool,
    ) -> Result<HotplugOutcome, HotplugError> {
        self.hotplug
            .detach(
                authorizer,
                &ActingPrincipal {
                    id: principal.to_owned(),
                },
                lease,
                mapping,
                release,
                now(),
            )
            .await
    }

    /// A hook that releases the lease (the holder, an expiry or the sweeper
    /// ends it) at the step it is scripted on. The cleanup is queued, not
    /// run: the hotplug request and the lease's end interleave.
    fn release_hook(&self, lease_id: &str) -> usb_pve::Hook {
        let lab = self.lab.clone();
        let operations = self.operations.clone();
        let lease_id = lease_id.to_owned();
        Arc::new(move || {
            let lab = lab.clone();
            let operations = operations.clone();
            let lease_id = lease_id.clone();
            Box::pin(async move {
                let principal = ActingPrincipal {
                    id: PRINCIPAL.to_owned(),
                };
                let lease = lab
                    .release_lease(&AllowAll, &principal, &lease_id, false, now())
                    .await
                    .expect("the ready lease releases");
                operations
                    .create_lab_cleanup(
                        &AllowAll,
                        PRINCIPAL,
                        &lease_id,
                        &fleet_application::lab::cleanup_operation(&lease, None),
                    )
                    .await
                    .expect("the cleanup is queued");
            })
        })
    }

    /// The (actor, action) of every audited intent of an event.
    async fn audit_actors(&self, event: &str) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT actor, action FROM audit_events WHERE outcome IS NULL AND metadata_json LIKE ?1 ORDER BY seq",
        )
        .bind(format!("%\"{event}\"%"))
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }
}

/// A ready lease holding the device, on a healthy host.
async fn ready_lease(world: &World, controller: &Controller) -> (String, u32) {
    controller.refresh_inventory().await;
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(world).await, Run::Done(1));
    let record = controller.record(&lease).await;
    assert_eq!(
        controller.lease(&lease).await.state,
        LeaseState::Ready,
        "{record:?}: {}",
        controller.failure_reason(&lease).await
    );
    (lease, record.vmid.expect("the clone has a VMID"))
}

fn slot(index: u8, mapping: &str) -> (u8, String) {
    (index, format!("mapping={mapping}"))
}

fn stored(entries: &[(u8, String)]) -> BTreeMap<u8, String> {
    entries.iter().cloned().collect()
}

/// A lease that ended without its guest, its device or any entry left.
async fn assert_released(world: &World, controller: &Controller, lease: &str) {
    let record = controller.record(lease).await;
    assert_eq!(
        controller.lease(lease).await.state,
        LeaseState::Released,
        "{record:?}"
    );
    assert!(
        controller
            .states()
            .await
            .iter()
            .all(|state| state == "released"),
        "{:?}",
        controller.rows().await
    );
    assert!(
        world
            .pve
            .lab_guests()
            .values()
            .all(|guest| guest.name != format!("fm-lab-{}", record.id)),
        "the guest is gone"
    );
}

/// The stable reason of a refused request.
fn refusal(result: Result<HotplugOutcome, HotplugError>) -> String {
    match result {
        Err(HotplugError::Refused { reason, .. }) => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn is_put(line: &str) -> bool {
    line.starts_with("Put ") && line.contains("/config")
}

const ATTACH_A: &str = "attach usb0=mapping=fm-test-reader-a";
const DETACH_0: &str = "detach usb0";

fn writes(entries: &[&str]) -> Vec<String> {
    entries.iter().map(|entry| (*entry).to_owned()).collect()
}

/// The lease's one reservation: (state, slot, guest VMID).
async fn only_row(controller: &Controller) -> (String, Option<i64>, Option<i64>) {
    let mut rows = controller.rows().await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    rows.remove(0)
}

fn delegated_authorizer() -> fleet_auth::delegated::ScopedAuthorizer {
    fleet_auth::delegated::ScopedAuthorizer::new(Arc::new(
        fleet_application::credentials::GrantBook::new(),
    ))
}

// ---------------------------------------------------------------------
// Detach and attach on a running guest.
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_detach_takes_the_device_off_the_running_guest_and_the_lease_keeps_it() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    assert_eq!(world.usb.applied(vmid), stored(&[slot(0, READER_A)]));

    let outcome = controller.detach(&lease, READER_A, false).await.unwrap();

    assert_eq!(outcome.result, HotplugResult::Detached);
    assert!(!outcome.result.on_guest());
    assert_eq!(outcome.reservation_state, State::Held);
    assert_eq!(outcome.usb_slot, None);
    assert!(!outcome.released);
    // Off the running guest and off its stored config, read back by the
    // provider; the lease still holds the device.
    assert!(world.usb.applied(vmid).is_empty());
    assert!(world.usb.stored(vmid).is_empty());
    assert_eq!(world.usb.writes(), writes(&[ATTACH_A, DETACH_0]));
    assert_eq!(
        only_row(&controller).await,
        ("held".to_owned(), None, Some(i64::from(vmid)))
    );
    assert_eq!(
        controller.device_view(READER_A).await,
        DeviceStatus::Reserved
    );
    // Audited as the caller's own request, before the delete.
    assert_eq!(
        controller.audit_actors("hardware_detach_requested").await,
        vec![(PRINCIPAL.to_owned(), "lab.hardware.detach".to_owned())]
    );
    let intent = controller.audit_metadata("hardware_detach_requested").await;
    assert!(intent[0].contains("\"source\":\"hotplug\""), "{intent:?}");
    assert_eq!(controller.audit_events("hardware_detached").await, 1);
    // Nobody else can take the device meanwhile.
    controller.refresh_inventory().await;
    let other = controller
        .placement
        .reserve(
            PRINCIPAL,
            &HardwareDemand {
                lease_id: "lease-other",
                account_id: &world.account_id,
                clone_node: TEMPLATE_NODE,
                declared: &[usb(READER_A)],
                operation_id: None,
            },
            now(),
        )
        .await
        .unwrap();
    assert!(other.is_err(), "the device is still the lease's");
}

#[tokio::test]
async fn an_attach_puts_a_kept_device_back_on_the_running_guest() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    controller.detach(&lease, READER_A, false).await.unwrap();

    let outcome = controller.attach(&lease, READER_A).await.unwrap();

    assert_eq!(outcome.result, HotplugResult::Attached);
    assert!(outcome.result.on_guest());
    assert_eq!(outcome.reservation_state, State::Attached);
    assert_eq!(outcome.usb_slot, Some(0));
    assert_eq!(world.usb.applied(vmid), stored(&[slot(0, READER_A)]));
    assert_eq!(world.usb.stored(vmid), stored(&[slot(0, READER_A)]));
    assert_eq!(world.usb.writes(), writes(&[ATTACH_A, DETACH_0, ATTACH_A]));
    assert_eq!(
        only_row(&controller).await,
        ("attached".to_owned(), Some(0), Some(i64::from(vmid)))
    );
    // The required intent came first, attributed to the caller's request,
    // and the device was verified against the pinned fingerprint again.
    assert_eq!(
        controller.audit_actors("hardware_attach_requested").await,
        vec![
            (PRINCIPAL.to_owned(), "lab.provision".to_owned()),
            (PRINCIPAL.to_owned(), "lab.hardware.attach".to_owned()),
        ]
    );
    // A repeat is not a second write.
    let again = controller.attach(&lease, READER_A).await.unwrap();
    assert_eq!(again.result, HotplugResult::AlreadyAttached);
    assert_eq!(world.usb.writes(), writes(&[ATTACH_A, DETACH_0, ATTACH_A]));
}

#[tokio::test]
async fn a_detach_that_releases_gives_the_device_up_after_the_read_back() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;

    let outcome = controller.detach(&lease, READER_A, true).await.unwrap();

    assert_eq!(outcome.result, HotplugResult::Detached);
    assert_eq!(outcome.reservation_state, State::Released);
    assert!(outcome.released);
    assert!(world.usb.applied(vmid).is_empty());
    assert_eq!(controller.states().await, vec!["released"]);
    assert_eq!(
        controller.device_view(READER_A).await,
        DeviceStatus::Available
    );
    assert_eq!(controller.audit_events("hardware_released").await, 1);
    // The lease no longer holds it, so it cannot attach it again.
    assert_eq!(
        refusal(controller.attach(&lease, READER_A).await),
        "hardware_not_reserved"
    );
    assert_eq!(world.usb.writes(), writes(&[ATTACH_A, DETACH_0]));
}

#[tokio::test]
async fn releasing_an_already_detached_device_gives_it_up_without_a_write() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, _) = ready_lease(&world, &controller).await;
    controller.detach(&lease, READER_A, false).await.unwrap();

    // A repeat of the keeping detach changes nothing.
    let again = controller.detach(&lease, READER_A, false).await.unwrap();
    assert_eq!(again.result, HotplugResult::AlreadyDetached);
    assert_eq!(again.reservation_state, State::Held);

    let released = controller.detach(&lease, READER_A, true).await.unwrap();
    assert_eq!(released.result, HotplugResult::AlreadyDetached);
    assert!(released.released);
    assert_eq!(controller.states().await, vec!["released"]);
    assert_eq!(world.usb.writes(), writes(&[ATTACH_A, DETACH_0]));
}

// ---------------------------------------------------------------------
// Running-guest semantics: pending is reported, never done.
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_detach_the_guest_keeps_pending_is_reported_pending_and_stays_attached() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    // The guest's `hotplug` option lacks `usb`: PVE stores the removal and
    // applies it at the next restart.
    world.usb.set_hotplug_usb(vmid, false);

    let outcome = controller.detach(&lease, READER_A, false).await.unwrap();

    assert_eq!(outcome.result, HotplugResult::DetachPending);
    assert!(outcome.result.on_guest(), "the device is still attached");
    assert_eq!(outcome.reservation_state, State::Detaching);
    assert_eq!(outcome.usb_slot, Some(0));
    assert!(!outcome.released);
    assert_eq!(world.usb.applied(vmid), stored(&[slot(0, READER_A)]));
    assert!(world.usb.stored(vmid).is_empty(), "the removal is pending");
    assert_eq!(
        only_row(&controller).await,
        ("detaching".to_owned(), Some(0), Some(i64::from(vmid)))
    );
    assert_eq!(controller.audit_events("hardware_detach_pending").await, 1);
    // Not detached, not released, and not attachable meanwhile.
    assert_eq!(controller.audit_events("hardware_detached").await, 0);
    assert_eq!(
        refusal(controller.attach(&lease, READER_A).await),
        "hardware_detach_unconfirmed"
    );
    // The same request again is still pending, and writes nothing new.
    let writes_before = world.usb.writes();
    let again = controller.detach(&lease, READER_A, false).await.unwrap();
    assert_eq!(again.result, HotplugResult::DetachPending);
    assert_eq!(world.usb.writes(), writes_before);

    // Once the guest restarted, the read-back confirms it and the lease
    // keeps the device.
    world.usb.apply_pending(vmid);
    let confirmed = controller.detach(&lease, READER_A, false).await.unwrap();
    assert_eq!(confirmed.result, HotplugResult::Detached);
    assert_eq!(confirmed.reservation_state, State::Held);
    assert!(world.usb.applied(vmid).is_empty());
    assert_eq!(
        only_row(&controller).await,
        ("held".to_owned(), None, Some(i64::from(vmid)))
    );
}

#[tokio::test]
async fn an_attach_the_guest_would_keep_pending_is_refused_and_removed() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    controller.detach(&lease, READER_A, false).await.unwrap();
    world.usb.set_hotplug_usb(vmid, false);

    let reason = refusal(controller.attach(&lease, READER_A).await);

    assert_eq!(reason, "hardware_attach_pending");
    // Never attached, and no pending entry is left for a restart to apply.
    assert!(world.usb.applied(vmid).is_empty());
    assert!(world.usb.stored(vmid).is_empty());
    // The lease still holds the device, held, nothing recorded on the guest.
    assert_eq!(
        only_row(&controller).await,
        ("held".to_owned(), None, Some(i64::from(vmid)))
    );
    assert_eq!(
        controller.device_view(READER_A).await,
        DeviceStatus::Reserved
    );
    // Only the provision's own attach was ever recorded as attached.
    assert_eq!(controller.audit_events("hardware_attached").await, 1);
    // With `usb` hotplug back on, the same request attaches it.
    world.usb.set_hotplug_usb(vmid, true);
    let outcome = controller.attach(&lease, READER_A).await.unwrap();
    assert_eq!(outcome.result, HotplugResult::Attached);
    assert_eq!(world.usb.applied(vmid), stored(&[slot(0, READER_A)]));
}

// ---------------------------------------------------------------------
// Who may act, and on what.
// ---------------------------------------------------------------------

#[tokio::test]
async fn only_the_lease_holder_or_an_administrator_can_act() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    // A lease held by the credential owner `ci-a`.
    let lease = controller.request_lease_as("credential:ci-a:cred-1").await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_eq!(controller.lease(&lease).await.state, LeaseState::Ready);
    assert_eq!(controller.lease(&lease).await.owner, "credential:ci-a");
    let authorizer = delegated_authorizer();
    let before = world.usb.writes();

    // Another owner's credential: the lease is not found, for both actions.
    for principal in ["credential:ci-b:cred-9", "credential:ci-a2:cred-1"] {
        let attach = controller
            .attach_as(&authorizer, principal, &lease, READER_A)
            .await;
        assert!(
            matches!(attach, Err(HotplugError::NotFound { .. })),
            "{principal}: {attach:?}"
        );
        let detach = controller
            .detach_as(&authorizer, principal, &lease, READER_A, false)
            .await;
        assert!(
            matches!(detach, Err(HotplugError::NotFound { .. })),
            "{principal}: {detach:?}"
        );
    }
    // A credential whose policy has no row for the action is denied, even for
    // its own lease.
    const NO_ROWS: &[fleet_auth::delegated::DelegatedAction] = &[];
    let restricted = fleet_auth::delegated::ScopedAuthorizer::with_catalog(
        Arc::new(fleet_application::credentials::GrantBook::new()),
        NO_ROWS,
    );
    let denied = controller
        .detach_as(
            &restricted,
            "credential:ci-a:cred-1",
            &lease,
            READER_A,
            false,
        )
        .await;
    assert!(matches!(denied, Err(HotplugError::Denied(_))), "{denied:?}");
    let denied = controller
        .attach_as(&restricted, "credential:ci-a:cred-1", &lease, READER_A)
        .await;
    assert!(matches!(denied, Err(HotplugError::Denied(_))), "{denied:?}");
    assert_eq!(world.usb.writes(), before, "nothing was written");
    assert_eq!(controller.states().await, vec!["attached"]);

    // The holder, through a rotated token of the same owner, acts.
    let detached = controller
        .detach_as(
            &authorizer,
            "credential:ci-a:cred-2",
            &lease,
            READER_A,
            false,
        )
        .await
        .unwrap();
    assert_eq!(detached.result, HotplugResult::Detached);
    assert_eq!(
        controller.audit_actors("hardware_detach_requested").await,
        vec![(
            "credential:ci-a:cred-2".to_owned(),
            "lab.hardware.detach".to_owned()
        )]
    );
    // An administrator may act on any lease.
    let attached = controller
        .attach_as(&authorizer, "tailscale:alice@example.com", &lease, READER_A)
        .await
        .unwrap();
    assert_eq!(attached.result, HotplugResult::Attached);
    // And a credential never acts on a lease an administrator holds.
    let admin_world = World::new(&[READER_A]).await;
    let admin_controller = Controller::start(&admin_world).await;
    let (admin_lease, _) = ready_lease(&admin_world, &admin_controller).await;
    let result = admin_controller
        .detach_as(
            &authorizer,
            "credential:ci-a:cred-1",
            &admin_lease,
            READER_A,
            false,
        )
        .await;
    assert!(
        matches!(result, Err(HotplugError::NotFound { .. })),
        "{result:?}"
    );
    assert_eq!(admin_world.usb.writes(), writes(&[ATTACH_A]));
}

#[tokio::test]
async fn a_device_the_lease_did_not_reserve_is_refused_and_nothing_is_written() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, _) = ready_lease(&world, &controller).await;
    // READER_B is inventoried, and another lease holds it.
    let device = HardwareRepository::new(controller.pool.clone())
        .device_by_mapping(&world.account_id, READER_B)
        .await
        .unwrap()
        .expect("the device is inventoried");
    HardwareRepository::new(controller.pool.clone())
        .insert_reservation(
            &fleet_application::hardware::NewHardwareReservation {
                id: "reservation-other".to_owned(),
                device_id: device.id,
                owner_kind: fleet_core::ReservationOwnerKind::Lease,
                owner_id: "lease-other".to_owned(),
                guest: None,
            },
            now(),
        )
        .await
        .unwrap();
    let before = world.usb.writes();

    let mut messages = Vec::new();
    for mapping in [READER_B, "fm-test-no-such-device"] {
        for result in [
            controller.attach(&lease, mapping).await,
            controller.detach(&lease, mapping, false).await,
            controller.detach(&lease, mapping, true).await,
        ] {
            let Err(HotplugError::Refused { reason, detail }) = result else {
                panic!("{mapping}: expected a refusal");
            };
            assert_eq!(reason, "hardware_not_reserved");
            // The answer never names the other lease or its device state.
            assert!(!detail.contains("lease-other"), "{detail}");
            messages.push(detail.replace(mapping, "<mapping>"));
        }
    }
    messages.dedup();
    assert_eq!(messages.len(), 1, "a probe learns nothing: {messages:?}");
    assert_eq!(world.usb.writes(), before);
    // Neither the other lease's reservation nor this lease's moved.
    let mut states = controller.states().await;
    states.sort();
    assert_eq!(states, vec!["attached", "held"]);

    // A lease whose template declared no hardware reserved nothing at all.
    let bare = World::new(&[]).await;
    let bare_controller = Controller::start(&bare).await;
    bare_controller.refresh_inventory().await;
    let bare_lease = bare_controller.request_lease().await;
    assert_eq!(bare_controller.drain(&bare).await, Run::Done(1));
    assert_eq!(
        refusal(bare_controller.attach(&bare_lease, READER_A).await),
        "hardware_not_reserved"
    );
    assert!(bare.usb.writes().is_empty());
}

#[tokio::test]
async fn a_lease_that_is_not_ready_cannot_hotplug() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, _) = ready_lease(&world, &controller).await;
    controller.release(&lease).await;
    assert_eq!(controller.lease(&lease).await.state, LeaseState::Releasing);
    let before = world.usb.writes();

    assert_eq!(
        refusal(controller.detach(&lease, READER_A, false).await),
        "lease_not_ready"
    );
    assert_eq!(
        refusal(controller.attach(&lease, READER_A).await),
        "lease_not_ready"
    );
    assert!(matches!(
        controller.attach(&lease, "bad,mapping").await,
        Err(HotplugError::Invalid { .. })
    ));
    assert!(matches!(
        controller.attach("no-such-lease", READER_A).await,
        Err(HotplugError::NotFound { .. })
    ));
    assert_eq!(world.usb.writes(), before);
    // Cleanup, which owns the lease now, still detaches and destroys.
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_released(&world, &controller, &lease).await;
}

// ---------------------------------------------------------------------
// Cleanup after a hotplug.
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_detached_device_is_released_with_the_lease_and_cleanup_writes_nothing() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, _) = ready_lease(&world, &controller).await;
    controller.detach(&lease, READER_A, false).await.unwrap();

    controller.release(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));

    assert_released(&world, &controller, &lease).await;
    assert_eq!(world.usb.writes(), writes(&[ATTACH_A, DETACH_0]));
    assert_eq!(
        controller.device_view(READER_A).await,
        DeviceStatus::Available
    );
}

#[tokio::test]
async fn cleanup_still_detaches_a_reattached_device_before_the_guest_is_destroyed() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, _) = ready_lease(&world, &controller).await;
    controller.detach(&lease, READER_A, false).await.unwrap();
    controller.attach(&lease, READER_A).await.unwrap();

    controller.release(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));

    assert_released(&world, &controller, &lease).await;
    assert_eq!(
        world.usb.writes(),
        writes(&[ATTACH_A, DETACH_0, ATTACH_A, DETACH_0])
    );
    let log = world.usb.log();
    let detach = log
        .iter()
        .rposition(|line| is_put(line) && line.contains("delete"))
        .unwrap();
    let stop = log.iter().position(|line| line.contains("/status/stop"));
    let destroy = log
        .iter()
        .position(|line| line.starts_with("Delete "))
        .unwrap();
    assert!(
        detach < destroy && stop.is_none_or(|stop| detach < stop),
        "{log:#?}"
    );
}

// ---------------------------------------------------------------------
// Serialised requests.
// ---------------------------------------------------------------------

/// A hook that holds the call for a while, so requests queue up behind it.
fn slow_hook() -> usb_pve::Hook {
    Arc::new(|| {
        Box::pin(async {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        })
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_on_one_device_are_serialised() {
    let world = World::new(&[READER_A]).await;
    let controller = Arc::new(Controller::start(&world).await);
    let (lease, vmid) = ready_lease(&world, &controller).await;

    // Six detaches at once, the first held in the middle of its write: one
    // detaches, the others see it detached.
    world
        .usb
        .inject(UsbStep::Detach, UsbFault::Hook(slow_hook()), 1);
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let (controller, lease) = (controller.clone(), lease.clone());
        tasks.push(tokio::spawn(async move {
            controller.detach(&lease, READER_A, false).await
        }));
    }
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap().unwrap().result);
    }
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == HotplugResult::Detached)
            .count(),
        1,
        "{results:?}"
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == HotplugResult::AlreadyDetached)
            .count(),
        5,
        "{results:?}"
    );
    assert_eq!(world.usb.writes(), writes(&[ATTACH_A, DETACH_0]));

    // Six attaches at once: one write.
    world
        .usb
        .inject(UsbStep::Attach, UsbFault::Hook(slow_hook()), 1);
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let (controller, lease) = (controller.clone(), lease.clone());
        tasks.push(tokio::spawn(async move {
            controller.attach(&lease, READER_A).await
        }));
    }
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap().unwrap().result);
    }
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == HotplugResult::Attached)
            .count(),
        1,
        "{results:?}"
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == HotplugResult::AlreadyAttached)
            .count(),
        5,
        "{results:?}"
    );
    assert_eq!(world.usb.writes(), writes(&[ATTACH_A, DETACH_0, ATTACH_A]));

    // Attaches and detaches interleaved: every request is answered, the
    // writes strictly alternate, and the guest agrees with the reservation.
    world
        .usb
        .inject(UsbStep::Detach, UsbFault::Hook(slow_hook()), 1);
    let mut tasks = Vec::new();
    for index in 0..6 {
        let (controller, lease) = (controller.clone(), lease.clone());
        tasks.push(tokio::spawn(async move {
            if index % 2 == 0 {
                controller.detach(&lease, READER_A, false).await
            } else {
                controller.attach(&lease, READER_A).await
            }
        }));
    }
    for task in tasks {
        task.await.unwrap().expect("every request is answered");
    }
    let log = world.usb.writes();
    for pair in log.windows(2) {
        assert_ne!(
            pair[0].split(' ').next(),
            pair[1].split(' ').next(),
            "writes alternate: {log:?}"
        );
    }
    let (state, ..) = only_row(&controller).await;
    assert_eq!(
        world.usb.applied(vmid).is_empty(),
        state == "held",
        "{state}: {log:?}"
    );
    assert!(state == "held" || state == "attached", "{state}");
}

// ---------------------------------------------------------------------
// A lease that ends while the request runs.
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_lease_that_ends_during_the_re_observation_writes_nothing() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    controller.detach(&lease, READER_A, false).await.unwrap();
    world.usb.inject(
        UsbStep::CheckNode,
        UsbFault::Hook(controller.release_hook(&lease)),
        1,
    );

    let reason = refusal(controller.attach(&lease, READER_A).await);

    assert_eq!(reason, "hardware_lease_ended");
    assert!(world.usb.applied(vmid).is_empty());
    assert_eq!(world.usb.writes(), writes(&[ATTACH_A, DETACH_0]));
    // The lease does not hold the device any more; its cleanup finishes.
    assert_eq!(controller.states().await, vec!["released"]);
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_released(&world, &controller, &lease).await;
}

#[tokio::test]
async fn a_lease_that_ends_during_the_write_has_the_device_detached_again() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    controller.detach(&lease, READER_A, false).await.unwrap();
    world.usb.inject(
        UsbStep::Attach,
        UsbFault::Hook(controller.release_hook(&lease)),
        1,
    );

    let reason = refusal(controller.attach(&lease, READER_A).await);

    assert_eq!(reason, "hardware_lease_ended");
    // The write landed, was recorded, and was taken off again at once.
    assert_eq!(
        world.usb.writes(),
        writes(&[ATTACH_A, DETACH_0, ATTACH_A, DETACH_0])
    );
    assert!(world.usb.applied(vmid).is_empty());
    assert_eq!(controller.states().await, vec!["released"]);
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_released(&world, &controller, &lease).await;
}

#[tokio::test]
async fn a_lease_that_ends_during_a_detach_ends_with_the_device_off_the_guest() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    world.usb.inject(
        UsbStep::Detach,
        UsbFault::Hook(controller.release_hook(&lease)),
        1,
    );

    let outcome = controller.detach(&lease, READER_A, false).await.unwrap();

    assert_eq!(outcome.result, HotplugResult::Detached);
    assert!(world.usb.applied(vmid).is_empty());
    // The lease is releasing, and its cleanup finds nothing left to detach.
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_released(&world, &controller, &lease).await;
    assert_eq!(world.usb.writes(), writes(&[ATTACH_A, DETACH_0]));
}

// ---------------------------------------------------------------------
// An entry Fleet did not write is never deleted.
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_detach_never_deletes_an_entry_an_operator_rewrote() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    // An operator rewrote the slot Fleet wrote (same mapping, extra option).
    let rewritten = "mapping=fm-test-reader-a,usb3=1";
    world.usb.set_slot(vmid, 0, rewritten);

    let reason = refusal(controller.detach(&lease, READER_A, false).await);

    assert_eq!(reason, "hardware_detach_failed");
    assert_eq!(
        world.usb.applied(vmid),
        stored(&[(0, rewritten.to_owned())]),
        "the operator's entry is untouched"
    );
    assert_eq!(world.usb.writes(), writes(&[ATTACH_A]));
    // The device is never reported detached or released; the lease's cleanup
    // owns the retry.
    assert_eq!(
        only_row(&controller).await,
        ("detach_failed".to_owned(), Some(0), Some(i64::from(vmid)))
    );
    assert_eq!(controller.audit_events("hardware_detached").await, 0);
}

#[tokio::test]
async fn an_attach_never_adopts_or_deletes_an_identical_entry_an_operator_wrote() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    controller.detach(&lease, READER_A, false).await.unwrap();
    // While the device is detached an operator attaches it by hand.
    world.usb.set_slot(vmid, 2, "mapping=fm-test-reader-a");

    let reason = refusal(controller.attach(&lease, READER_A).await);

    assert_eq!(reason, "hardware_externally_attached");
    assert_eq!(
        world.usb.applied(vmid),
        stored(&[slot(2, READER_A)]),
        "the operator's entry is untouched"
    );
    assert_eq!(world.usb.writes(), writes(&[ATTACH_A, DETACH_0]));
    // The lease still holds the device, held, and records nothing on the
    // guest.
    assert_eq!(
        only_row(&controller).await,
        ("held".to_owned(), None, Some(i64::from(vmid)))
    );
}

// ---------------------------------------------------------------------
// The audit intent is required before the write.
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_refused_attach_intent_blocks_the_write() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    controller.detach(&lease, READER_A, false).await.unwrap();
    *world.refuse_event.lock().unwrap() = Some("hardware_attach_requested".to_owned());

    let result = controller.attach(&lease, READER_A).await;

    assert!(
        matches!(result, Err(HotplugError::Backend { .. })),
        "{result:?}"
    );
    assert!(world.usb.applied(vmid).is_empty());
    assert_eq!(world.usb.writes(), writes(&[ATTACH_A, DETACH_0]));
    assert_eq!(
        only_row(&controller).await,
        ("held".to_owned(), None, Some(i64::from(vmid)))
    );
    // Once the sink is back the same request goes through.
    *world.refuse_event.lock().unwrap() = None;
    let outcome = controller.attach(&lease, READER_A).await.unwrap();
    assert_eq!(outcome.result, HotplugResult::Attached);
}

#[tokio::test]
async fn a_refused_detach_intent_blocks_the_delete_and_a_retry_completes_it() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    *world.refuse_event.lock().unwrap() = Some("hardware_detach_requested".to_owned());

    let reason = refusal(controller.detach(&lease, READER_A, false).await);

    assert_eq!(reason, "hardware_detach_failed");
    assert_eq!(world.usb.applied(vmid), stored(&[slot(0, READER_A)]));
    assert_eq!(world.usb.writes(), writes(&[ATTACH_A]));
    assert_eq!(
        only_row(&controller).await,
        ("detach_failed".to_owned(), Some(0), Some(i64::from(vmid)))
    );
    *world.refuse_event.lock().unwrap() = None;
    let outcome = controller.detach(&lease, READER_A, false).await.unwrap();
    assert_eq!(outcome.result, HotplugResult::Detached);
    assert!(world.usb.applied(vmid).is_empty());
    assert_eq!(
        only_row(&controller).await,
        ("held".to_owned(), None, Some(i64::from(vmid)))
    );
}
