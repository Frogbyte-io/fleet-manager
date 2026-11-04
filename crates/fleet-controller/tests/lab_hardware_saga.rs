//! FM-1123 (#571): the Lab hardware saga end to end. A lease whose template
//! declares a USB device reserves it in placement (FM-1121), the provision
//! executor attaches it to the clone after the hardware step and before the
//! start, and cleanup detaches it before the guest is destroyed, with
//! compensation at every step.
//!
//! **Simulated.** The shared fake Proxmox (`support/fake_pve.rs`) behind a
//! USB-aware layer (`support/usb_pve.rs`) that speaks the FM-S11 spike's
//! shapes (mapping list and `check-node`, `usbN` entries with the applied,
//! pending-add and pending-delete views, the config digest), and a
//! restartable controller over one SQLite file with the real reservation
//! store, the real inventory and the real provider calls. Every device id,
//! VMID and address is invented.
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
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use fake_pve::{FINGERPRINT, FakePve, Fault, Faults, Step, TEMPLATE_NODE, TEMPLATE_VMID};
use fleet_application::audit::AuditOutcome;
use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision};
use fleet_application::hardware::HardwareStore;
use fleet_application::hardware_inventory::{DeviceFilter, HardwareInventory};
use fleet_application::hardware_reservation::HardwareReservations;
use fleet_application::lab::{
    ImageArtifactPort, ImagePinValidator, Lab, LabReadinessPort, LabTemplatePort,
    LabTemplateVersion, LeasePort, NewLabTemplate, NewLease, ProvisionPort, ProvisionRecord,
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
use fleet_controller::lab_hardware::{
    AttachFailure, LabHardwareSaga, LeaseGuest, SqliteFingerprintPins,
};
use fleet_controller::lab_sweeper::{LabSweeper, ProxmoxLabGuests, TickReport};
use fleet_controller::proxmox_exec::{
    LabDispatch, ProvisionExecutor, ProxmoxDestructiveExecutor, ProxmoxDispatch,
    ProxmoxLifecycleExecutor,
};
use fleet_core::{
    CleanupStrategy, DeviceStatus, HardwareKind, LabHardware, LabTemplateContent, Lease,
    LeaseState, ReadinessProbe, UnsupportedReason,
};
use fleet_provider_proxmox::ProxmoxClient;
use fleet_storage_sqlite::{
    AuditSink, HardwareRepository, LabRepository, LeaseRepository, MachineRepository,
    OperationRepository, ProjectRepository, ProxmoxAccountRepository, Store,
};
use serde_json::{Value, json};
use usb_pve::{UsbFault, UsbHost, UsbStep};

const PRINCIPAL: &str = fleet_auth::LAN_PRINCIPAL_ID;
const IMAGE_VERSION: &str = "image-version-1";
const TTL_SECONDS: u32 = 86_400;
const HOUR_MS: i64 = 3_600_000;
const LEASE_MS: i64 = fleet_controller::worker::LEASE_MS;
/// Two devices on the template's node, one port each.
const READER_A: &str = "fm-test-reader-a";
const READER_B: &str = "fm-test-reader-b";
/// The first VMID the fake host hands out.
const FIRST_VMID: u32 = fake_pve::FIRST_LAB_VMID;

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

/// The saga's audit sink, which can be told to refuse the detach intent.
#[derive(Debug)]
struct GateAudit {
    inner: AuditSink,
    refuse_detach_intent: Arc<AtomicBool>,
}

#[async_trait]
impl AuditPort for GateAudit {
    async fn record_intent(
        &self,
        intent: &fleet_application::audit::AuditIntent,
    ) -> Result<(), String> {
        if self.refuse_detach_intent.load(Ordering::SeqCst)
            && intent
                .metadata
                .entries()
                .any(|(key, value)| key == "event" && value == "hardware_detach_requested")
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
    refuse_detach_intent: Arc<AtomicBool>,
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
            refuse_detach_intent: Arc::new(AtomicBool::new(false)),
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
    store: Store,
    pool: sqlx::SqlitePool,
    operations: Arc<Operations>,
    executor: Arc<dyn OperationExecutor>,
    sweeper: Arc<LabSweeper>,
    lab: Arc<Lab>,
    leases: Arc<LeaseRepository>,
    labs: Arc<LabRepository>,
    inventory: Arc<HardwareInventory>,
    placement: Arc<HardwarePlacement>,
    saga: Arc<LabHardwareSaga>,
    destroyer: Arc<ProxmoxDestructiveExecutor>,
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
                refuse_detach_intent: world.refuse_detach_intent.clone(),
            }),
            leases.clone(),
            Arc::new(SqliteFingerprintPins::new(pool.clone())),
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
        let sweeper = Arc::new(
            LabSweeper::new(
                lab.clone(),
                leases.clone(),
                labs.clone(),
                operations.clone(),
                audit,
            )
            .with_inventory(Arc::new(ProxmoxLabGuests::new(
                accounts,
                credentials,
                client,
            ))),
        );
        Self {
            store,
            pool,
            operations,
            executor,
            sweeper,
            lab,
            leases,
            labs,
            inventory,
            placement,
            saga,
            destroyer,
            account_id: world.account_id.clone(),
            version_id: world.version_id.clone(),
        }
    }

    /// The controller dies: the store and every connection close.
    async fn kill(self) {
        self.pool.close().await;
        drop(self.store);
    }

    /// The restarted controller's worker maintenance once the dead run's
    /// claim lease ran out.
    async fn recover(&self) -> usize {
        self.operations
            .maintain(now() + LEASE_MS + 1, LEASE_MS)
            .await
            .unwrap()
            .recovered
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
        let principal = ActingPrincipal {
            id: PRINCIPAL.to_owned(),
        };
        let lease = self
            .lab
            .create_lease(
                &AllowAll,
                &principal,
                NewLease {
                    template_version_id: self.version_id.clone(),
                    purpose: "hardware saga".to_owned(),
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

    async fn release_keeping(&self, lease_id: &str) {
        self.release_with(lease_id, true).await;
    }

    /// Runs one claimed operation; answers whether one ran.
    async fn step(&self, world: &World) -> Run<bool> {
        let operations = self.operations.clone();
        let executor = self.executor.clone();
        self.run(world, async move {
            operations
                .tick(executor.as_ref(), "hardware-suite-worker", now(), LEASE_MS)
                .await
                .unwrap()
                .claimed
        })
        .await
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

    async fn sweep(&self, world: &World, at: i64) -> Run<TickReport> {
        let sweeper = self.sweeper.clone();
        self.run(world, async move { sweeper.tick(at).await.unwrap() })
            .await
    }

    /// Lets the sweeper and the worker converge at `at`.
    async fn settle(&self, world: &World, at: i64) {
        for _ in 0..20 {
            let Run::Done(report) = self.sweep(world, at).await else {
                panic!("the controller crashed while settling");
            };
            let Run::Done(ran) = self.drain(world).await else {
                panic!("the controller crashed while settling");
            };
            if report.expired == 0
                && report.compensated == 0
                && report.cleanups_queued == 0
                && report.cleanups_abandoned == 0
                && ran == 0
            {
                return;
            }
        }
        panic!("the Lab never settled");
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

fn is_put(line: &str) -> bool {
    line.starts_with("Put ") && line.contains("/config")
}

fn is_start(line: &str) -> bool {
    line.contains("/status/start")
}

// ---------------------------------------------------------------------
// The happy path.
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_lease_with_a_device_attaches_before_start_and_detaches_before_destroy() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;

    // Attached, to the clone, in the first slot, and recorded as such.
    assert_eq!(world.usb.stored(vmid), stored(&[slot(0, READER_A)]));
    assert_eq!(
        controller.rows().await,
        vec![("attached".to_owned(), Some(0), Some(i64::from(vmid)))]
    );
    assert_eq!(
        controller.device_view(READER_A).await,
        DeviceStatus::Reserved
    );
    // After the clone and the hardware step, before the start; and the
    // re-observation (check-node) came before the write.
    let log = world.usb.log();
    let check = log
        .iter()
        .rposition(|line| line.contains("check-node=") && !line.contains("Put"))
        .unwrap();
    let put = world.usb.first(is_put).unwrap();
    let start = world.usb.first(is_start).unwrap();
    assert!(check < put && put < start, "{log:#?}");
    assert_eq!(controller.audit_events("hardware_reserved").await, 1);
    assert_eq!(
        controller.audit_events("hardware_attach_requested").await,
        1
    );
    assert_eq!(controller.audit_events("hardware_attached").await, 1);

    // Cleanup detaches before anything touches the guest.
    controller.release(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_released(&world, &controller, &lease).await;
    assert_eq!(
        world.usb.writes(),
        vec![
            "attach usb0=mapping=fm-test-reader-a".to_owned(),
            "detach usb0".to_owned()
        ]
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
    assert_eq!(controller.audit_events("hardware_detached").await, 1);
    assert_eq!(controller.audit_events("hardware_released").await, 1);
    assert_eq!(
        controller.device_view(READER_A).await,
        DeviceStatus::Available
    );
}

#[tokio::test]
async fn a_lease_without_hardware_makes_no_usb_call() {
    let world = World::new(&[]).await;
    let controller = Controller::start(&world).await;
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_eq!(controller.lease(&lease).await.state, LeaseState::Ready);
    assert!(world.usb.writes().is_empty());
    assert_eq!(world.usb.count(|line| line.contains("/pending")), 0);
    assert_eq!(world.usb.count(|line| line.contains("/mapping/usb")), 0);
    controller.release(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_eq!(controller.lease(&lease).await.state, LeaseState::Released);
}

#[tokio::test]
async fn a_digest_conflict_is_retried_and_the_attach_lands() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    world
        .usb
        .inject(UsbStep::Attach, UsbFault::DigestMismatch, 1);
    let (_, vmid) = ready_lease(&world, &controller).await;
    assert_eq!(world.usb.stored(vmid), stored(&[slot(0, READER_A)]));
    assert_eq!(
        world.usb.writes(),
        vec!["attach usb0=mapping=fm-test-reader-a".to_owned()]
    );
}

#[tokio::test]
async fn two_devices_attach_in_mapping_order_and_both_detach() {
    let world = World::new(&[READER_B, READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    assert_eq!(
        world.usb.stored(vmid),
        stored(&[slot(0, READER_A), slot(1, READER_B)])
    );
    assert_eq!(controller.states().await, vec!["attached", "attached"]);
    controller.release(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_released(&world, &controller, &lease).await;
    assert_eq!(
        world
            .usb
            .writes()
            .iter()
            .filter(|write| write.starts_with("detach"))
            .count(),
        2
    );
}

// ---------------------------------------------------------------------
// Each failing step of the attach.
// ---------------------------------------------------------------------

/// A provision that failed at the attach step and was cleaned up.
async fn assert_attach_failed(
    world: &World,
    controller: &Controller,
    lease: &str,
    reason: &str,
) -> ProvisionRecord {
    assert_eq!(controller.failure_reason(lease).await, reason);
    let record = controller.record(lease).await;
    assert_eq!(
        record.failed_step.as_deref(),
        Some("usb_attach"),
        "{record:?}"
    );
    assert_released(world, controller, lease).await;
    assert_eq!(
        world.usb.count(is_start),
        0,
        "a guest whose device did not attach is never started"
    );
    record
}

#[tokio::test]
async fn an_unplugged_device_is_refused_at_the_re_observation_before_any_write() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    // Placement still sees the recent observation; the device is gone by
    // the time the saga re-observes it.
    world.usb.set_present(READER_A, false);
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(2));
    assert_attach_failed(&world, &controller, &lease, "hardware_missing").await;
    assert!(world.usb.writes().is_empty());
    assert_eq!(
        controller.device_view(READER_A).await,
        DeviceStatus::Missing
    );
}

#[tokio::test]
async fn a_device_whose_port_changed_since_it_was_recorded_is_refused() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    // The operator moved the cable (and the mapping) after placement.
    world
        .usb
        .set_entries(READER_A, &["node=pve-b,id=aaaa:0001,path=1-9"]);
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(2));
    assert_attach_failed(&world, &controller, &lease, "hardware_fingerprint_changed").await;
    assert!(world.usb.writes().is_empty());
}

#[tokio::test]
async fn an_entry_the_template_carries_is_refused_and_never_deleted() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    // The image template holds the device, so the clone inherits it.
    world.usb.template_carries(0, "mapping=fm-test-reader-a");
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(2));
    assert_attach_failed(&world, &controller, &lease, "hardware_externally_attached").await;
    // Fleet wrote nothing, so it deleted nothing: the entry went with the
    // clone, not by a detach.
    assert!(world.usb.writes().is_empty());
}

#[tokio::test]
async fn an_identical_entry_an_operator_wrote_meanwhile_is_never_claimed_or_deleted() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    // The entry lands between the saga's check and the provider's read.
    world
        .usb
        .inject(UsbStep::Pending, UsbFault::ForeignEntry, 1);
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(2));
    assert_attach_failed(&world, &controller, &lease, "hardware_externally_attached").await;
    assert!(
        world.usb.writes().is_empty(),
        "Fleet neither wrote nor deleted anything"
    );
    assert_eq!(controller.audit_events("hardware_attach_failed").await, 1);
}

#[tokio::test]
async fn a_refused_attach_write_releases_the_device() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    world.usb.inject(UsbStep::Attach, UsbFault::Forbidden, 1);
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(2));
    assert_attach_failed(&world, &controller, &lease, "hardware_attach_failed").await;
    assert!(world.usb.writes().is_empty());
    assert_eq!(controller.audit_events("hardware_attached").await, 0);
}

#[tokio::test]
async fn a_failed_hotplug_is_removed_and_the_device_released() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    world.usb.inject(UsbStep::Attach, UsbFault::HotplugFails, 1);
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(2));
    assert_attach_failed(&world, &controller, &lease, "hardware_attach_failed").await;
    // PVE kept a pending entry; the provider removed it before the saga
    // released anything.
    assert_eq!(
        world.usb.writes(),
        vec![
            "attach usb0=mapping=fm-test-reader-a (hotplug failed)".to_owned(),
            "detach usb0".to_owned()
        ]
    );
}

#[tokio::test]
async fn a_lost_answer_leaves_attach_unknown_and_cleanup_resolves_it_by_reading_the_guest() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    // The write lands, the answer is lost.
    world.usb.inject(UsbStep::Attach, UsbFault::Lost, 1);
    let lease = controller.request_lease().await;
    assert_eq!(controller.step(&world).await, Run::Done(true));
    assert_eq!(controller.states().await, vec!["attach_unknown"]);
    assert_eq!(
        controller.rows().await[0].1,
        Some(0),
        "the slot the entry may be in is recorded"
    );
    assert_eq!(
        controller.device_view(READER_A).await,
        DeviceStatus::Quarantined
    );
    assert!(
        world.usb.stored(FIRST_VMID).contains_key(&0),
        "the entry is there"
    );
    // The lease's cleanup finds it and removes it, then releases.
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_attach_failed(&world, &controller, &lease, "hardware_attach_unknown").await;
    assert_eq!(
        world.usb.writes(),
        vec![
            "attach usb0=mapping=fm-test-reader-a".to_owned(),
            "detach usb0".to_owned()
        ]
    );
}

#[tokio::test]
async fn an_attach_that_failed_without_a_trace_is_released_by_cleanup_after_a_read_back() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    // PVE answers 500: nothing proves whether the write was processed.
    world.usb.inject(UsbStep::Attach, UsbFault::ServerError, 1);
    let lease = controller.request_lease().await;
    assert_eq!(controller.step(&world).await, Run::Done(true));
    assert_eq!(controller.states().await, vec!["attach_unknown"]);
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_attach_failed(&world, &controller, &lease, "hardware_attach_unknown").await;
    assert!(
        world.usb.writes().is_empty(),
        "no entry existed, so none was deleted"
    );
}

#[tokio::test]
async fn a_later_device_that_fails_takes_the_earlier_attachment_off_again() {
    let world = World::new(&[READER_A, READER_B]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    world.usb.set_present(READER_B, false);
    let lease = controller.request_lease().await;
    assert_eq!(controller.step(&world).await, Run::Done(true));
    // The provision failed at B; A was already attached and is detached
    // and released before cleanup even starts.
    assert_eq!(controller.failure_reason(&lease).await, "hardware_missing");
    assert_eq!(
        world.usb.writes(),
        vec![
            "attach usb0=mapping=fm-test-reader-a".to_owned(),
            "detach usb0".to_owned()
        ]
    );
    assert_eq!(
        controller.device_view(READER_A).await,
        DeviceStatus::Available
    );
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_released(&world, &controller, &lease).await;
}

// ---------------------------------------------------------------------
// Cancel during the attach.
// ---------------------------------------------------------------------

fn cancel_hook(controller: &Controller, operation_id: &str) -> usb_pve::Hook {
    let operations = controller.operations.clone();
    let operation_id = operation_id.to_owned();
    Arc::new(move || {
        let operations = operations.clone();
        let operation_id = operation_id.clone();
        Box::pin(async move {
            operations
                .cancel(&AllowAll, PRINCIPAL, &operation_id)
                .await
                .expect("the running operation accepts a cancel");
        })
    })
}

#[tokio::test]
async fn a_cancel_during_the_re_observation_writes_nothing_and_releases_the_device() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    let lease = controller.request_lease().await;
    let operation = controller.provision_operation(&lease).await;
    world.usb.inject(
        UsbStep::CheckNode,
        UsbFault::Hook(cancel_hook(&controller, &operation.id)),
        1,
    );
    assert_eq!(controller.drain(&world).await, Run::Done(2));
    assert_attach_failed(&world, &controller, &lease, "cancelled").await;
    assert!(world.usb.writes().is_empty());
}

#[tokio::test]
async fn a_cancel_during_the_write_completes_the_attach_and_cleanup_detaches_it() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    let lease = controller.request_lease().await;
    let operation = controller.provision_operation(&lease).await;
    world.usb.inject(
        UsbStep::Attach,
        UsbFault::Hook(cancel_hook(&controller, &operation.id)),
        1,
    );
    assert_eq!(controller.drain(&world).await, Run::Done(2));
    // The write is not abandoned half-way: it landed and was recorded, the
    // provision stopped before the start, and cleanup took it off again.
    assert_eq!(controller.failure_reason(&lease).await, "cancelled");
    assert_released(&world, &controller, &lease).await;
    assert_eq!(world.usb.count(is_start), 0);
    assert_eq!(
        world.usb.writes(),
        vec![
            "attach usb0=mapping=fm-test-reader-a".to_owned(),
            "detach usb0".to_owned()
        ]
    );
}

// ---------------------------------------------------------------------
// The controller dies and restarts at each step of the saga.
// ---------------------------------------------------------------------

/// Requests a lease, interrupts its provision at the scripted USB step,
/// restarts the controller over the same database, and lets it converge.
async fn crash_attach(world: &World, fault: UsbFault) -> (Controller, String) {
    let controller = Controller::start(world).await;
    controller.refresh_inventory().await;
    let lease = controller.request_lease().await;
    world.usb.inject(UsbStep::Attach, fault, 1);
    assert_eq!(controller.drain(world).await, Run::Crashed);
    controller.kill().await;
    let restarted = Controller::start(world).await;
    assert_eq!(restarted.recover().await, 1);
    (restarted, lease)
}

#[tokio::test]
async fn a_crash_before_the_attach_write_converges_to_nothing() {
    let world = World::new(&[READER_A]).await;
    let (controller, lease) = crash_attach(&world, UsbFault::CrashBefore).await;
    // The row recorded the attach before the write; the write never landed.
    assert_eq!(controller.states().await, vec!["attaching"]);
    controller.settle(&world, now() + HOUR_MS).await;
    assert_released(&world, &controller, &lease).await;
    assert!(world.usb.writes().is_empty());
}

#[tokio::test]
async fn a_crash_after_the_attach_write_fails_closed_because_the_row_proves_nothing() {
    let world = World::new(&[READER_A]).await;
    let (controller, lease) = crash_attach(&world, UsbFault::CrashAfter).await;
    // The row recorded the attach before the write, so an entry on the guest
    // cannot be told from an operator's identical one: it is not adopted,
    // not marked attached, and not deleted.
    assert_eq!(controller.states().await, vec!["attaching"]);
    assert_eq!(world.usb.stored(FIRST_VMID), stored(&[slot(0, READER_A)]));
    controller.settle(&world, now() + HOUR_MS).await;
    assert_eq!(
        controller.lease(&lease).await.state,
        LeaseState::CleanupFailed,
        "the bounded retries end cleanup_failed, naming the guest"
    );
    assert_eq!(controller.states().await, vec!["attach_unknown"]);
    assert_eq!(
        controller.rows().await[0].1,
        None,
        "no slot is recorded for an entry nobody can prove Fleet wrote"
    );
    assert_eq!(
        controller.device_view(READER_A).await,
        DeviceStatus::Quarantined
    );
    assert_eq!(world.usb.stored(FIRST_VMID), stored(&[slot(0, READER_A)]));
    assert_eq!(world.usb.writes().len(), 1, "only the attach was written");
    assert!(world.pve.lab_guests().contains_key(&FIRST_VMID));
    assert_eq!(world.usb.count(|line| line.starts_with("Delete ")), 0);

    // A re-armed retry stays closed, and opens once the guest shows nothing.
    for operator_removed in [false, true] {
        if operator_removed {
            world.usb.clear_slot(FIRST_VMID, 0);
        }
        controller
            .lab
            .retry_cleanup(
                &AllowAll,
                &ActingPrincipal {
                    id: PRINCIPAL.to_owned(),
                },
                &lease,
            )
            .await
            .expect("cleanup-retry re-arms the lease");
        controller.settle(&world, now() + 2 * HOUR_MS).await;
        if !operator_removed {
            assert_eq!(controller.states().await, vec!["attach_unknown"]);
            assert_eq!(world.usb.stored(FIRST_VMID), stored(&[slot(0, READER_A)]));
        }
    }
    assert_released(&world, &controller, &lease).await;
}

#[tokio::test]
async fn an_operators_identical_entry_after_a_crash_before_the_write_is_never_adopted_or_deleted() {
    let world = World::new(&[READER_A]).await;
    let (controller, lease) = crash_attach(&world, UsbFault::CrashBefore).await;
    assert_eq!(controller.states().await, vec!["attaching"]);
    // While the controller was down an operator gave the clone the device.
    world
        .usb
        .set_slot(FIRST_VMID, 0, "mapping=fm-test-reader-a");
    let record = controller.record(&lease).await;
    let operation = controller.provision_operation(&lease).await;
    let guest = LeaseGuest {
        lease_id: &lease,
        account_id: &world.account_id,
        node: TEMPLATE_NODE,
        vmid: record.vmid.unwrap(),
        operation_id: Some(&operation.id),
    };
    // The resumed attach does not take the entry for its own.
    let result = controller
        .saga
        .attach_for_lease(&controller.operations, &guest, &[usb(READER_A)])
        .await;
    let Err(AttachFailure::Refused { reason, .. }) = result else {
        panic!("the resume must refuse: {result:?}");
    };
    assert_eq!(reason, "hardware_attach_unknown");
    assert_eq!(controller.states().await, vec!["attach_unknown"]);
    assert_eq!(controller.rows().await[0].1, None);
    // Nor does cleanup delete it: the bounded retries end cleanup_failed.
    controller.settle(&world, now() + HOUR_MS).await;
    assert_eq!(
        controller.lease(&lease).await.state,
        LeaseState::CleanupFailed
    );
    assert_eq!(world.usb.stored(FIRST_VMID), stored(&[slot(0, READER_A)]));
    assert!(
        world.usb.writes().is_empty(),
        "Fleet wrote and deleted nothing"
    );
    assert_eq!(controller.states().await, vec!["attach_unknown"]);
}

#[tokio::test]
async fn a_resumed_attach_with_no_entry_on_the_guest_writes_it_and_a_repeat_changes_nothing() {
    let world = World::new(&[READER_A]).await;
    let (controller, lease) = crash_attach(&world, UsbFault::CrashBefore).await;
    let record = controller.record(&lease).await;
    let vmid = record.vmid.unwrap();
    let operation = controller.provision_operation(&lease).await;
    let guest = LeaseGuest {
        lease_id: &lease,
        account_id: &world.account_id,
        node: TEMPLATE_NODE,
        vmid,
        operation_id: Some(&operation.id),
    };
    assert_eq!(controller.states().await, vec!["attaching"]);
    controller
        .saga
        .attach_for_lease(&controller.operations, &guest, &[usb(READER_A)])
        .await
        .expect("the resume writes the entry the crashed run never did");
    assert_eq!(
        controller.rows().await,
        vec![("attached".to_owned(), Some(0), Some(i64::from(vmid)))]
    );
    assert_eq!(world.usb.writes().len(), 1);
    // A repeat is a no-op: nothing is read from or written to the guest.
    let calls = world.usb.log().len();
    controller
        .saga
        .attach_for_lease(&controller.operations, &guest, &[usb(READER_A)])
        .await
        .expect("a repeat is idempotent");
    assert_eq!(world.usb.writes().len(), 1);
    assert_eq!(world.usb.log().len(), calls);
}

#[tokio::test]
async fn a_slot_that_sat_on_an_operators_host_entry_is_released_when_the_guest_shows_no_reference()
{
    // The expected slot (usb0) was chosen from mapping references only and
    // sits on a raw `host=` entry; the crash came before the write, so the
    // guest has no entry of Fleet's. A detach of usb0 would be refused as a
    // foreign slot and strand the row: the full read releases it instead.
    let world = World::new(&[READER_A]).await;
    world.usb.set_slot(FIRST_VMID, 0, "host=1-5");
    let (controller, lease) = crash_attach(&world, UsbFault::CrashBefore).await;
    assert_eq!(controller.states().await, vec!["attaching"]);
    assert_eq!(controller.rows().await[0].1, Some(0));
    controller.settle(&world, now() + HOUR_MS).await;
    assert_released(&world, &controller, &lease).await;
    assert!(world.usb.writes().is_empty());
}

#[tokio::test]
async fn a_crash_between_the_attach_and_the_start_is_cleaned_up() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    let lease = controller.request_lease().await;
    world.faults.inject(Step::Start, Fault::CrashBefore, 1);
    assert_eq!(controller.drain(&world).await, Run::Crashed);
    controller.kill().await;
    let controller = Controller::start(&world).await;
    assert_eq!(controller.recover().await, 1);
    assert_eq!(controller.states().await, vec!["attached"]);
    controller.settle(&world, now() + HOUR_MS).await;
    assert_released(&world, &controller, &lease).await;
    assert_eq!(world.usb.writes().len(), 2);
}

/// A ready lease, released, whose cleanup is interrupted at `fault`.
async fn crash_cleanup(world: &World, step: UsbStep, fault: UsbFault) -> (Controller, String) {
    let controller = Controller::start(world).await;
    let (lease, _) = ready_lease(world, &controller).await;
    world.usb.inject(step, fault, 1);
    controller.release(&lease).await;
    assert_eq!(controller.drain(world).await, Run::Crashed);
    controller.kill().await;
    let restarted = Controller::start(world).await;
    assert_eq!(restarted.recover().await, 1);
    (restarted, lease)
}

#[tokio::test]
async fn a_crash_before_the_detach_write_resumes_the_detach() {
    let world = World::new(&[READER_A]).await;
    let (controller, lease) = crash_cleanup(&world, UsbStep::Detach, UsbFault::CrashBefore).await;
    assert_eq!(controller.states().await, vec!["detaching"]);
    assert!(world.pve.lab_guests().contains_key(&FIRST_VMID));
    controller.settle(&world, now() + HOUR_MS).await;
    assert_released(&world, &controller, &lease).await;
    assert_eq!(
        world
            .usb
            .writes()
            .iter()
            .filter(|write| write.starts_with("detach"))
            .count(),
        1
    );
}

#[tokio::test]
async fn a_crash_after_the_detach_write_confirms_it_by_reading_and_does_not_detach_again() {
    let world = World::new(&[READER_A]).await;
    let (controller, lease) = crash_cleanup(&world, UsbStep::Detach, UsbFault::CrashAfter).await;
    assert_eq!(controller.states().await, vec!["detaching"]);
    assert!(
        world.usb.stored(FIRST_VMID).is_empty(),
        "the entry is already off the guest"
    );
    controller.settle(&world, now() + HOUR_MS).await;
    assert_released(&world, &controller, &lease).await;
    assert_eq!(
        world.usb.writes(),
        vec![
            "attach usb0=mapping=fm-test-reader-a".to_owned(),
            "detach usb0".to_owned()
        ],
        "the resume read the guest and wrote nothing"
    );
}

#[tokio::test]
async fn a_crash_after_the_release_and_before_the_destroy_destroys_without_detaching_again() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, _) = ready_lease(&world, &controller).await;
    world.faults.inject(Step::Delete, Fault::CrashBefore, 1);
    controller.release(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Crashed);
    controller.kill().await;
    let controller = Controller::start(&world).await;
    // The cleanup and its destroy child were both in flight.
    assert_eq!(controller.recover().await, 2);
    assert_eq!(controller.states().await, vec!["released"]);
    controller.settle(&world, now() + HOUR_MS).await;
    assert_released(&world, &controller, &lease).await;
    assert_eq!(world.usb.writes().len(), 2);
}

// ---------------------------------------------------------------------
// Destroy is refused while a detach is unconfirmed.
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_refused_detach_keeps_the_reservation_and_the_guest_and_the_lease_retries() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    // The token lost Mapping.Use: PVE refuses the delete.
    world.usb.inject(UsbStep::Detach, UsbFault::Forbidden, 20);
    controller.release(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));

    let after = controller.lease(&lease).await;
    assert_eq!(after.state, LeaseState::Releasing);
    assert_eq!(after.cleanup_attempts, 1);
    assert!(after.cleanup_next_at.is_some());
    assert_eq!(controller.states().await, vec!["detach_failed"]);
    assert_eq!(
        controller.device_view(READER_A).await,
        DeviceStatus::Quarantined
    );
    // The guest was neither stopped nor destroyed, and the entry is there.
    assert!(world.pve.lab_guests().contains_key(&vmid));
    assert_eq!(world.usb.count(|line| line.contains("/status/stop")), 0);
    assert_eq!(world.usb.count(|line| line.starts_with("Delete ")), 0);
    assert_eq!(world.usb.stored(vmid), stored(&[slot(0, READER_A)]));
    assert_eq!(controller.audit_events("hardware_detach_failed").await, 1);
    assert_eq!(controller.audit_events("lab_lease_released").await, 0);
    assert_eq!(controller.audit_events("hardware_released").await, 0);

    // The host recovers: the retry detaches, then destroys.
    world.usb.clear();
    controller.settle(&world, now() + HOUR_MS).await;
    assert_released(&world, &controller, &lease).await;
    assert_eq!(
        controller.device_view(READER_A).await,
        DeviceStatus::Available
    );
}

#[tokio::test]
async fn a_detach_that_pends_on_a_running_guest_is_not_a_release_and_blocks_the_destroy() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    // The guest's hotplug option lacks usb: PVE stores the removal and keeps
    // the device until the guest restarts.
    world.usb.set_hotplug_usb(vmid, false);
    controller.release(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));

    assert_eq!(controller.lease(&lease).await.state, LeaseState::Releasing);
    assert_eq!(controller.states().await, vec!["detaching"]);
    assert_eq!(
        world.usb.applied(vmid),
        stored(&[slot(0, READER_A)]),
        "the running guest still holds the device"
    );
    assert!(world.pve.lab_guests().contains_key(&vmid));
    assert_eq!(world.usb.count(|line| line.starts_with("Delete ")), 0);
    assert_eq!(controller.audit_events("hardware_detach_pending").await, 1);

    // A restart applies the removal; the next attempt reads it and releases.
    world.usb.apply_pending(vmid);
    controller.settle(&world, now() + HOUR_MS).await;
    assert_released(&world, &controller, &lease).await;
    assert_eq!(
        world
            .usb
            .writes()
            .iter()
            .filter(|write| write.starts_with("detach"))
            .count(),
        1,
        "the pending removal was written once and only read afterwards"
    );
}

#[tokio::test]
async fn an_attach_that_pends_on_a_running_guest_is_removed_never_recorded_as_attached() {
    let world = World::new(&[]).await;
    let controller = Controller::start(&world).await;
    // A ready lease whose guest is running, reserving a device afterwards
    // the way placement does (the mid-run path is FM-1126's).
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    let record = controller.record(&lease).await;
    let vmid = record.vmid.unwrap();
    controller.refresh_inventory().await;
    controller
        .placement
        .reserve(
            PRINCIPAL,
            &HardwareDemand {
                lease_id: &lease,
                account_id: &world.account_id,
                clone_node: TEMPLATE_NODE,
                declared: &[usb(READER_A)],
                operation_id: None,
            },
            now(),
        )
        .await
        .unwrap()
        .expect("the device is reserved");
    world.usb.set_hotplug_usb(vmid, false);
    let operation = controller.provision_operation(&lease).await;
    let result = controller
        .saga
        .attach_for_lease(
            &controller.operations,
            &LeaseGuest {
                lease_id: &lease,
                account_id: &world.account_id,
                node: TEMPLATE_NODE,
                vmid,
                operation_id: Some(&operation.id),
            },
            &[usb(READER_A)],
        )
        .await;
    let Err(AttachFailure::Refused { reason, .. }) = result else {
        panic!("a pending attach is a refusal: {result:?}");
    };
    assert_eq!(reason, "hardware_attach_pending");
    // The pending entry was removed, nothing is attached, the device is free.
    assert!(world.usb.stored(vmid).is_empty());
    assert!(world.usb.applied(vmid).is_empty());
    assert_eq!(controller.states().await, vec!["released"]);
    assert_eq!(controller.audit_events("hardware_attached").await, 0);
}

// ---------------------------------------------------------------------
// A slot Fleet did not write is never deleted.
// ---------------------------------------------------------------------

#[tokio::test]
async fn an_operators_entry_in_another_slot_is_never_touched() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    // The guest-to-be has an operator's raw device in usb0 (a `host=` entry
    // is invisible to the mapping reads, so Fleet's expected slot is wrong).
    world.usb.set_slot(FIRST_VMID, 0, "host=1-5");
    let (lease, vmid) = ready_lease(&world, &controller).await;
    assert_eq!(vmid, FIRST_VMID);
    assert_eq!(
        world.usb.stored(vmid),
        stored(&[(0, "host=1-5".to_owned()), slot(1, READER_A)])
    );
    // The row records the slot PVE used, not the one Fleet expected.
    assert_eq!(controller.rows().await[0].1, Some(1));
    let attached = controller.audit_metadata("hardware_attached").await;
    assert!(
        attached[0].contains("\"slot_corrected\":\"true\""),
        "{attached:?}"
    );

    // Keep the guest so the entries can be read after the cleanup.
    controller.release_keeping(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_eq!(controller.lease(&lease).await.state, LeaseState::Released);
    assert_eq!(
        world.usb.stored(vmid),
        stored(&[(0, "host=1-5".to_owned())])
    );
    assert_eq!(controller.states().await, vec!["released"]);
    assert_eq!(world.usb.writes().len(), 2);
}

#[tokio::test]
async fn a_recorded_slot_that_now_holds_something_else_is_left_untouched_and_the_detach_fails() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    // An operator replaced Fleet's entry with their own.
    world.usb.set_slot(vmid, 0, "mapping=fm-operators-own");
    controller.release_keeping(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_eq!(controller.lease(&lease).await.state, LeaseState::Releasing);
    assert_eq!(controller.states().await, vec!["detach_failed"]);
    assert_eq!(
        world.usb.stored(vmid),
        stored(&[(0, "mapping=fm-operators-own".to_owned())]),
        "the operator's entry is untouched"
    );
    assert_eq!(
        world.usb.writes().len(),
        1,
        "only the attach was ever written"
    );
}

#[tokio::test]
async fn a_failing_detach_is_never_overridden_by_the_lease_giving_up() {
    // The lease runs out of cleanup attempts: it ends `cleanup_failed` and
    // names its guest, and the reservation stays held for an operator.
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    world.usb.inject(UsbStep::Detach, UsbFault::Forbidden, 200);
    controller.release(&lease).await;
    let mut at = now();
    for _ in 0..fleet_application::lab::MAX_CLEANUP_ATTEMPTS + 2 {
        at += HOUR_MS;
        controller.settle(&world, at).await;
    }
    let after = controller.lease(&lease).await;
    assert_eq!(after.state, LeaseState::CleanupFailed);
    assert_eq!(
        after.cleanup_attempts,
        fleet_application::lab::MAX_CLEANUP_ATTEMPTS,
        "bounded retries"
    );
    assert!(world.pve.lab_guests().contains_key(&vmid));
    assert_eq!(controller.states().await, vec!["detach_failed"]);
    assert_eq!(controller.audit_events("lab_lease_cleanup_failed").await, 1);
}

// ---------------------------------------------------------------------
// Review fixes: scan completeness, the pinned fingerprint, the lease
// ending mid-provision, the reviewed routes, the detach audit.
// ---------------------------------------------------------------------

/// A hook that runs `work` once.
fn hook<F>(work: F) -> usb_pve::Hook
where
    F: Fn() + Send + Sync + 'static,
{
    let work = Arc::new(work);
    Arc::new(move || {
        let work = work.clone();
        Box::pin(async move { work() })
    })
}

#[tokio::test]
async fn an_incomplete_guest_scan_at_the_re_observation_refuses_before_any_write() {
    // The cluster's guest list is unreadable during the re-observation, so
    // a guest may reference the device unseen.
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    let usb_host = world.usb.clone();
    world.usb.inject(
        UsbStep::CheckNode,
        UsbFault::Hook(hook(move || usb_host.fail_next_resources(1))),
        1,
    );
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(2));
    assert_attach_failed(&world, &controller, &lease, "hardware_scan_incomplete").await;
    assert!(world.usb.writes().is_empty());
}

#[tokio::test]
async fn an_unreadable_guest_config_at_the_re_observation_refuses_before_any_write() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    let usb_host = world.usb.clone();
    world.usb.inject(
        UsbStep::CheckNode,
        UsbFault::Hook(hook(move || usb_host.fail_next_config(FIRST_VMID, 1))),
        1,
    );
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(2));
    assert_attach_failed(&world, &controller, &lease, "hardware_scan_incomplete").await;
    assert!(world.usb.writes().is_empty());
}

/// The token's permissions as the fake PVE reports them, with the opt-in
/// role and the given `/vms` entries.
fn permissions_with(vms: Value) -> Value {
    let mut map = json!({"/mapping/usb": {"Mapping.Audit": 1, "Mapping.Use": 1}});
    for (path, privileges) in vms.as_object().expect("an object") {
        map[path] = privileges.clone();
    }
    map
}

#[tokio::test]
async fn a_token_that_cannot_audit_every_guest_is_refused_at_the_re_observation_before_any_write() {
    // #596: a guest the token cannot audit is omitted from the cluster
    // listing, so the guest scan reads complete while a device it drives
    // would read available. Placement saw an `available` device; by the
    // re-observation the token's `VM.Audit` on the guests is gone.
    for (label, vms) in [
        (
            "no VM.Audit on /vms",
            json!({"/vms": {"VM.Config.HWType": 1}}),
        ),
        (
            "VM.Audit that does not propagate",
            json!({"/vms": {"VM.Audit": 0, "VM.Config.HWType": 1}}),
        ),
        (
            "a guest path narrowed below VM.Audit",
            json!({
                "/vms": {"VM.Audit": 1, "VM.Config.HWType": 1},
                "/vms/200": {"VM.PowerMgmt": 1}
            }),
        ),
        (
            "a guest path with nothing at all",
            json!({"/vms": {"VM.Audit": 1, "VM.Config.HWType": 1}, "/vms/200": {}}),
        ),
    ] {
        let world = World::new(&[READER_A]).await;
        let controller = Controller::start(&world).await;
        controller.refresh_inventory().await;
        assert_eq!(
            controller.device_view(READER_A).await,
            DeviceStatus::Available
        );
        world.usb.set_permissions(200, permissions_with(vms));
        let lease = controller.request_lease().await;
        assert_eq!(controller.drain(&world).await, Run::Done(2), "{label}");
        assert_attach_failed(&world, &controller, &lease, "hardware_guests_unverifiable").await;
        assert!(world.usb.writes().is_empty(), "{label}");
    }
}

#[tokio::test]
async fn a_guest_pve_says_exists_but_the_token_cannot_list_refuses_even_with_a_full_audit_grant() {
    // The Decker case with a token that holds VM.Audit on `/vms` and a
    // NoAccess ACL on one guest: the permissions read clean, but PVE answers
    // `nextid?vmid=100` with "already exists" for a guest the listing does
    // not name (the next free VMID is far above it).
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    assert_eq!(
        controller.device_view(READER_A).await,
        DeviceStatus::Available
    );
    world.usb.hide_guest(100);
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(2));
    assert_attach_failed(&world, &controller, &lease, "hardware_guests_unverifiable").await;
    assert!(world.usb.writes().is_empty());
}

#[tokio::test]
async fn permissions_that_cannot_be_read_at_the_re_observation_refuse_the_attach_too() {
    // Unverified is not verified: when the read of the token's own
    // permissions fails, Fleet cannot tell whether it audits every guest.
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    world.usb.set_permissions(403, json!(null));
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(2));
    assert_attach_failed(&world, &controller, &lease, "hardware_guests_unverifiable").await;
    assert!(world.usb.writes().is_empty());
}

#[tokio::test]
async fn a_token_that_audits_every_guest_attaches_as_before() {
    // The control for the refusals above: with `VM.Audit` propagating from
    // `/vms` nothing is refused for visibility.
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    world.usb.set_permissions(
        200,
        permissions_with(json!({"/vms": {"VM.Audit": 1, "VM.Config.HWType": 1}})),
    );
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_eq!(controller.lease(&lease).await.state, LeaseState::Ready);
    assert_eq!(world.usb.writes().len(), 1, "{:?}", world.usb.writes());
}

#[tokio::test]
async fn a_refresh_with_a_visibility_gap_makes_the_device_unallocatable_before_the_saga() {
    // The standing signal: once a refresh records the gap, no device of the
    // account reads available, so placement refuses the lease up front.
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    world.usb.set_permissions(
        200,
        permissions_with(json!({"/vms": {"VM.Config.HWType": 1}})),
    );
    controller.refresh_inventory().await;
    assert_eq!(
        controller.device_view(READER_A).await,
        DeviceStatus::Unsupported(UnsupportedReason::UsbInventoryUnreadable)
    );
    let lease = controller.request_lease().await;
    controller.drain(&world).await;
    assert!(world.usb.writes().is_empty());
    assert_ne!(controller.failure_reason(&lease).await, "");
}

#[tokio::test]
async fn a_refresh_between_the_reservation_and_the_attach_cannot_re_baseline_the_fingerprint() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    // After placement reserved the device (and pinned its fingerprint) and
    // before the attach, the operator moves the cable and an inventory
    // refresh records the new port. Comparing with the stored entry at the
    // attach would pass; comparing with the reservation's does not.
    let usb_host = world.usb.clone();
    let inventory = controller.inventory.clone();
    let account = world.account_id.clone();
    world.usb.inject(
        UsbStep::NextId,
        UsbFault::Hook(Arc::new(move || {
            let usb_host = usb_host.clone();
            let inventory = inventory.clone();
            let account = account.clone();
            Box::pin(async move {
                usb_host.set_entries(READER_A, &["node=pve-b,id=aaaa:0001,path=1-9"]);
                inventory
                    .refresh(
                        &AllowAll,
                        &ActingPrincipal {
                            id: PRINCIPAL.to_owned(),
                        },
                        None,
                        &account,
                    )
                    .await
                    .expect("the refresh runs");
            })
        })),
        1,
    );
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(2));
    assert_attach_failed(&world, &controller, &lease, "hardware_fingerprint_changed").await;
    assert!(world.usb.writes().is_empty());
    // The refresh did move the stored entry (so comparing with it would have
    // passed): the pinned fingerprint is what caught the change.
    let stored_path: String = sqlx::query_scalar("SELECT usbpath FROM hardware_device_entries")
        .fetch_one(&controller.pool)
        .await
        .unwrap();
    assert_eq!(stored_path, "1-9");
    let pinned_path: String =
        sqlx::query_scalar("SELECT usbpath FROM hardware_reservation_fingerprints")
            .fetch_one(&controller.pool)
            .await
            .unwrap();
    assert_eq!(pinned_path, "1-1");
}

#[tokio::test]
async fn an_attach_unknown_row_is_left_to_cleanup_and_never_written_over() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    world.usb.inject(UsbStep::Attach, UsbFault::Lost, 1);
    let lease = controller.request_lease().await;
    assert_eq!(controller.step(&world).await, Run::Done(true));
    assert_eq!(controller.states().await, vec!["attach_unknown"]);
    let record = controller.record(&lease).await;
    let operation = controller.provision_operation(&lease).await;
    let result = controller
        .saga
        .attach_for_lease(
            &controller.operations,
            &LeaseGuest {
                lease_id: &lease,
                account_id: &world.account_id,
                node: TEMPLATE_NODE,
                vmid: record.vmid.unwrap(),
                operation_id: Some(&operation.id),
            },
            &[usb(READER_A)],
        )
        .await;
    let Err(AttachFailure::Refused { reason, .. }) = result else {
        panic!("{result:?}");
    };
    assert_eq!(reason, "hardware_attach_unknown");
    assert_eq!(world.usb.writes().len(), 1, "nothing was written again");
    assert_eq!(controller.states().await, vec!["attach_unknown"]);
}

/// Marks the lease as ended the way a release or the sweeper's compensation
/// does (`releasing`), from inside a hook.
fn end_lease(controller: &Controller, lease_id: &str) -> usb_pve::Hook {
    let leases = controller.leases.clone();
    let lease_id = lease_id.to_owned();
    Arc::new(move || {
        let leases = leases.clone();
        let lease_id = lease_id.clone();
        Box::pin(async move {
            let mut lease = leases.get(&lease_id).await.unwrap();
            lease.state = LeaseState::Releasing;
            leases.update(&lease).await.unwrap();
        })
    })
}

#[tokio::test]
async fn a_lease_released_during_the_re_observation_gets_no_write() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    let lease = controller.request_lease().await;
    world.usb.inject(
        UsbStep::CheckNode,
        UsbFault::Hook(end_lease(&controller, &lease)),
        1,
    );
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_eq!(
        controller.failure_reason(&lease).await,
        "hardware_lease_ended"
    );
    assert!(world.usb.writes().is_empty());
    controller.settle(&world, now() + HOUR_MS).await;
    assert_released(&world, &controller, &lease).await;
    assert!(world.usb.writes().is_empty());
}

#[tokio::test]
async fn a_lease_released_during_the_write_has_the_device_detached_again() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    let lease = controller.request_lease().await;
    world.usb.inject(
        UsbStep::Attach,
        UsbFault::Hook(end_lease(&controller, &lease)),
        1,
    );
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    // The write landed after cleanup could have looked; the saga took the
    // device off again itself and released the row, so nothing is left
    // attached to a dying guest.
    assert_eq!(
        controller.failure_reason(&lease).await,
        "hardware_lease_ended"
    );
    assert_eq!(
        world.usb.writes(),
        vec![
            "attach usb0=mapping=fm-test-reader-a".to_owned(),
            "detach usb0".to_owned()
        ]
    );
    assert_eq!(controller.states().await, vec!["released"]);
    controller.settle(&world, now() + HOUR_MS).await;
    assert_released(&world, &controller, &lease).await;
}

#[tokio::test]
async fn the_reviewed_destroy_revert_and_template_routes_refuse_a_guest_that_holds_a_device() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    for kind in [
        "proxmox.guest.destroy",
        "proxmox.guest.snapshot-revert",
        "proxmox.guest.template",
    ] {
        let payload = serde_json::json!({
            "accountId": world.account_id,
            "node": TEMPLATE_NODE,
            "vmid": vmid,
            "timeoutSeconds": 60,
            "params": {"snapshot": "baseline", "purge": true},
        })
        .to_string();
        let child = fleet_controller::lab_pool::run_reviewed_child(
            &controller.operations,
            controller.destroyer.as_ref(),
            kind,
            payload,
            format!("review-{kind}"),
            &lease,
            std::time::Duration::from_secs(30),
        )
        .await
        .unwrap();
        assert_eq!(child.state, "failed", "{kind}");
        let error: serde_json::Value =
            serde_json::from_str(child.error_json.as_deref().unwrap()).unwrap();
        assert_eq!(error["reason"], "hardware_attached", "{kind}");
        assert!(
            error["detail"]
                .as_str()
                .unwrap()
                .contains("holds a USB device"),
            "{error}"
        );
    }
    assert!(world.pve.lab_guests().contains_key(&vmid));
    assert_eq!(world.usb.count(|line| line.contains("/status/stop")), 0);
    assert_eq!(world.usb.count(|line| line.starts_with("Delete ")), 0);
    // After the saga's detach the same route goes through.
    controller.release(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_released(&world, &controller, &lease).await;
}

#[tokio::test]
async fn a_guest_deleted_by_hand_while_it_held_a_device_fails_closed() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    world.usb.remove_guest(vmid).await;
    controller.release(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    // An absent guest is not a confirmed detach (the cluster list omits
    // guests the token cannot audit): the row and the lease stay, for an
    // operator to confirm and override.
    assert_eq!(controller.lease(&lease).await.state, LeaseState::Releasing);
    assert_eq!(controller.states().await, vec!["detach_failed"]);
    assert_eq!(world.usb.writes().len(), 1, "only the attach was written");
}

#[tokio::test]
async fn a_refusing_audit_sink_prevents_the_detach_delete() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    world.refuse_detach_intent.store(true, Ordering::SeqCst);
    controller.release(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_eq!(controller.lease(&lease).await.state, LeaseState::Releasing);
    assert_eq!(controller.states().await, vec!["detach_failed"]);
    assert_eq!(world.usb.writes().len(), 1, "no delete was made");
    assert_eq!(world.usb.stored(vmid), stored(&[slot(0, READER_A)]));
    assert_eq!(
        controller.audit_events("hardware_detach_requested").await,
        0
    );
    // With the sink back the retry detaches, audits the intent and finishes.
    world.refuse_detach_intent.store(false, Ordering::SeqCst);
    controller.settle(&world, now() + HOUR_MS).await;
    assert_released(&world, &controller, &lease).await;
    assert_eq!(
        controller.audit_events("hardware_detach_requested").await,
        1
    );
}

#[tokio::test]
async fn one_of_two_devices_failing_to_detach_leaves_only_that_one_held() {
    let world = World::new(&[READER_A, READER_B]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    // The first delete is refused, the second goes through.
    world.usb.inject(UsbStep::Detach, UsbFault::Forbidden, 1);
    controller.release(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_eq!(controller.lease(&lease).await.state, LeaseState::Releasing);
    let mut states = controller.states().await;
    states.sort();
    assert_eq!(states, vec!["detach_failed", "released"]);
    assert!(
        world.pve.lab_guests().contains_key(&vmid),
        "the guest is kept"
    );
    assert_eq!(
        world.usb.stored(vmid).len(),
        1,
        "exactly the device that failed to detach is still on the guest"
    );
    controller.settle(&world, now() + HOUR_MS).await;
    assert_released(&world, &controller, &lease).await;
}

/// A hook recording the id of the one reservation row (taken in placement,
/// so it exists once the saga re-observes the device).
fn capture_row_id(
    controller: &Controller,
    into: &Arc<std::sync::Mutex<Option<String>>>,
) -> usb_pve::Hook {
    let pool = controller.pool.clone();
    let into = into.clone();
    Arc::new(move || {
        let pool = pool.clone();
        let into = into.clone();
        Box::pin(async move {
            let found: Option<String> = sqlx::query_scalar("SELECT id FROM hardware_reservations")
                .fetch_optional(&pool)
                .await
                .unwrap();
            *into.lock().unwrap() = found;
        })
    })
}

/// A hook that releases the captured row, as a cleanup that read the guest
/// before the write landed would.
fn release_captured_row(
    controller: &Controller,
    id: &Arc<std::sync::Mutex<Option<String>>>,
) -> usb_pve::Hook {
    let pool = controller.pool.clone();
    let id = id.clone();
    Arc::new(move || {
        let pool = pool.clone();
        let id = id.lock().unwrap().clone().expect("the row exists");
        Box::pin(async move {
            fleet_application::hardware_reservation::HardwareReservationPort::override_release(
                &fleet_controller::hardware_reservation_store::SqliteHardwareReservations::new(
                    pool,
                ),
                &id,
                now(),
            )
            .await
            .expect("the row is released");
        })
    })
}

#[tokio::test]
async fn a_row_released_between_the_cleanup_read_and_the_write_gets_its_entry_removed_not_an_error()
{
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    let lease = controller.request_lease().await;
    let id = Arc::new(std::sync::Mutex::new(None::<String>));
    world.usb.inject(
        UsbStep::CheckNode,
        UsbFault::Hook(capture_row_id(&controller, &id)),
        1,
    );
    // The row is released when the write is about to land.
    world.usb.inject(
        UsbStep::Attach,
        UsbFault::Hook(release_captured_row(&controller, &id)),
        1,
    );
    assert_eq!(controller.drain(&world).await, Run::Done(2));
    // The write landed on a released row: its recording could not happen, so
    // exactly the entry Fleet wrote was deleted again and the failure says so.
    assert_eq!(
        controller.failure_reason(&lease).await,
        "hardware_attach_unrecorded"
    );
    assert_eq!(
        world.usb.writes(),
        vec![
            "attach usb0=mapping=fm-test-reader-a".to_owned(),
            "detach usb0".to_owned()
        ]
    );
    assert_released(&world, &controller, &lease).await;
    let metadata = controller.audit_metadata("hardware_attach_failed").await;
    assert!(
        metadata
            .iter()
            .any(|entry| entry.contains("\"outcome\":\"removed\"")),
        "{metadata:?}"
    );
}

#[tokio::test]
async fn an_unrecorded_write_whose_removal_fails_is_surfaced_not_hidden() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    let lease = controller.request_lease().await;
    let id = Arc::new(std::sync::Mutex::new(None::<String>));
    world.usb.inject(
        UsbStep::CheckNode,
        UsbFault::Hook(capture_row_id(&controller, &id)),
        1,
    );
    world.usb.inject(
        UsbStep::Attach,
        UsbFault::Hook(release_captured_row(&controller, &id)),
        1,
    );
    world.usb.inject(UsbStep::Detach, UsbFault::Forbidden, 5);
    assert_eq!(controller.step(&world).await, Run::Done(true));
    assert_eq!(
        controller.failure_reason(&lease).await,
        "hardware_attach_unrecorded"
    );
    // Fleet's entry is still on the guest, and the audit trail says so.
    assert_eq!(world.usb.stored(FIRST_VMID), stored(&[slot(0, READER_A)]));
    let metadata = controller.audit_metadata("hardware_attach_failed").await;
    assert!(
        metadata
            .iter()
            .any(|entry| entry.contains("\"outcome\":\"unremoved\"")),
        "{metadata:?}"
    );
}

#[tokio::test]
async fn the_destroy_gate_fails_closed_when_the_reservations_cannot_be_read() {
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, vmid) = ready_lease(&world, &controller).await;
    sqlx::query("ALTER TABLE hardware_reservations RENAME TO hardware_reservations_away")
        .execute(&controller.pool)
        .await
        .unwrap();
    let payload = serde_json::json!({
        "accountId": world.account_id,
        "node": TEMPLATE_NODE,
        "vmid": vmid,
        "timeoutSeconds": 60,
        "params": {"purge": true},
    })
    .to_string();
    let child = fleet_controller::lab_pool::run_reviewed_child(
        &controller.operations,
        controller.destroyer.as_ref(),
        "proxmox.guest.destroy",
        payload,
        "review-unreadable".to_owned(),
        &lease,
        std::time::Duration::from_secs(30),
    )
    .await
    .unwrap();
    sqlx::query("ALTER TABLE hardware_reservations_away RENAME TO hardware_reservations")
        .execute(&controller.pool)
        .await
        .unwrap();
    assert_eq!(child.state, "failed");
    let error: serde_json::Value =
        serde_json::from_str(child.error_json.as_deref().unwrap()).unwrap();
    assert_eq!(error["reason"], "hardware_unreadable");
    assert!(world.pve.lab_guests().contains_key(&vmid));
    assert_eq!(world.usb.count(|line| line.starts_with("Delete ")), 0);
}

#[tokio::test]
async fn a_reservation_without_a_pin_is_pinned_at_its_first_attach() {
    // A reservation taken before the pin existed (or interrupted between the
    // reserve and the pin): the attach pins from the stored entry and goes on.
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    let pool = controller.pool.clone();
    world.usb.inject(
        UsbStep::NextId,
        UsbFault::Hook(Arc::new(move || {
            let pool = pool.clone();
            Box::pin(async move {
                sqlx::query("DELETE FROM hardware_reservation_fingerprints")
                    .execute(&pool)
                    .await
                    .unwrap();
            })
        })),
        1,
    );
    let lease = controller.request_lease().await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_eq!(controller.lease(&lease).await.state, LeaseState::Ready);
    let pinned: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT vendor_id, product_id, usbpath FROM hardware_reservation_fingerprints",
    )
    .fetch_all(&controller.pool)
    .await
    .unwrap();
    assert_eq!(
        pinned,
        vec![("aaaa".to_owned(), "0001".to_owned(), Some("1-1".to_owned()))]
    );
}

#[tokio::test]
async fn cleanup_takes_a_row_that_became_attached_while_it_ran() {
    // The template declares A only. While cleanup detaches A, a provision that
    // was still running reserves B for the lease, attaches it and records it:
    // the row did not exist when cleanup first read the lease's rows (a row
    // that is `held` then is released by cleanup, which is #591's rule), and
    // is `attached` on its next read.
    let world = World::new(&[READER_A]).await;
    let controller = Controller::start(&world).await;
    let (lease, _) = ready_lease(&world, &controller).await;
    let record = controller.record(&lease).await;
    let vmid = record.vmid.unwrap();
    // The second device's entry is on the guest.
    world.usb.set_slot(vmid, 1, "mapping=fm-test-reader-b");
    let pool = controller.pool.clone();
    let account = world.account_id.clone();
    let placement = controller.placement.clone();
    let lease_id = lease.clone();
    world.usb.inject(
        UsbStep::Detach,
        UsbFault::Hook(Arc::new(move || {
            let store = HardwareRepository::new(pool.clone());
            let account = account.clone();
            let placement = placement.clone();
            let lease_id = lease_id.clone();
            let pool = pool.clone();
            Box::pin(async move {
                use fleet_application::hardware::HardwareStore as _;
                placement
                    .reserve(
                        PRINCIPAL,
                        &HardwareDemand {
                            lease_id: &lease_id,
                            account_id: &account,
                            clone_node: TEMPLATE_NODE,
                            declared: &[usb(READER_B)],
                            operation_id: None,
                        },
                        now(),
                    )
                    .await
                    .unwrap()
                    .expect("the second device is reserved");
                let second: String = sqlx::query_scalar(
                    "SELECT r.id FROM hardware_reservations r \
                     JOIN hardware_devices d ON d.id = r.device_id WHERE d.mapping_id = ?1",
                )
                .bind(READER_B)
                .fetch_one(&pool)
                .await
                .unwrap();
                let target = fleet_core::GuestTarget {
                    account_id: account,
                    node: TEMPLATE_NODE.to_owned(),
                    vmid,
                    usb_slot: Some(1),
                };
                store
                    .transition_reservation(
                        &second,
                        fleet_core::HardwareReservationState::Held,
                        fleet_core::HardwareReservationState::Attaching,
                        Some(&target),
                        now(),
                    )
                    .await
                    .unwrap();
                store
                    .transition_reservation(
                        &second,
                        fleet_core::HardwareReservationState::Attaching,
                        fleet_core::HardwareReservationState::Attached,
                        None,
                        now(),
                    )
                    .await
                    .unwrap();
            })
        })),
        1,
    );
    controller.release(&lease).await;
    assert_eq!(controller.drain(&world).await, Run::Done(1));
    assert_released(&world, &controller, &lease).await;
    assert_eq!(
        world.usb.writes(),
        vec![
            "attach usb0=mapping=fm-test-reader-a".to_owned(),
            "detach usb0".to_owned(),
            "detach usb1".to_owned()
        ],
        "the row that appeared during the first pass was detached by the second"
    );
    assert_eq!(controller.audit_events("hardware_detached").await, 2);
}
