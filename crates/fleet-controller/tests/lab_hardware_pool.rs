//! FM-1123 (#571): a pool member that holds a device. A pooled lease cannot
//! reserve hardware at provision (the template is refused, FM-1121), but a
//! member can still carry an attachment the saga recorded, so cleanup detaches
//! it before the member is reverted and returned to the pool, and quarantines
//! the member when the detach cannot be confirmed. Real SQLite, the real
//! reservation store and saga over the USB-aware fake host
//! (`support/usb_pve.rs`); the revert child and the cluster reads are
//! scripted as in `lab_pool.rs`. Every id is invented.

#[allow(dead_code)]
#[path = "support/fake_pve.rs"]
mod fake_pve;
#[path = "support/usb_pve.rs"]
mod usb_pve;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fake_pve::{FINGERPRINT, FakePve, Faults, TEMPLATE_NODE};
use fleet_application::hardware::{DeviceObservation, HardwareStore};
use fleet_application::hardware_inventory::HardwareInventory;
use fleet_application::hardware_reservation::{
    AuditContext, HardwareReservations, ReserveDecision, ReserveRequest,
};
use fleet_application::lab::{
    LabTemplatePort, LeasePort, NewLease, NewProvision, ProvisionPort, cleanup_operation,
};
use fleet_application::lab_pool::{
    ClaimOutcome, FillResult, GuestObservation, LabPoolPort, MemberState, NewLabPool,
    PoolGuestPort, RevertedConfig,
};
use fleet_application::operation::{Operation, Operations};
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccountPort, ProxmoxCredentialStore,
};
use fleet_application::worker::OperationExecutor;
use fleet_controller::hardware_reservation_store::SqliteHardwareReservations;
use fleet_controller::lab_cleanup::LabCleanupExecutor;
use fleet_controller::lab_hardware::LabHardwareSaga;
use fleet_core::{
    CleanupStrategy, DeviceNodeEntry, DeviceStatus, GuestTarget, HardwareKind,
    HardwareReservationState as State, LeaseState, ReservationOwnerKind,
};
use fleet_provider_proxmox::ProxmoxClient;
use fleet_storage_sqlite::{
    AuditSink, HardwareRepository, LabPoolRepository, LabRepository, LeaseRepository,
    MachineRepository, OperationRepository, ProxmoxAccountRepository, Store,
};
use usb_pve::{UsbFault, UsbHost, UsbStep};

const MAPPING: &str = "fm-test-reader-a";
const MEMBER_VMID: u32 = 7001;

/// Records the children it ran, and the order against the detach.
#[derive(Debug, Default)]
struct Scripted {
    ran: Mutex<Vec<String>>,
}

#[async_trait]
impl OperationExecutor for Scripted {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        self.ran.lock().unwrap().push(operation.kind.clone());
        operations
            .complete(&operation.id, "succeeded", Some("{}"), None)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

#[derive(Debug)]
struct Cluster;

#[async_trait]
impl PoolGuestPort for Cluster {
    async fn observe(
        &self,
        _account_id: &str,
        vmid: u32,
        _baseline: &str,
    ) -> Result<GuestObservation, String> {
        Ok(GuestObservation {
            kind: Some("qemu".to_owned()),
            node: Some(TEMPLATE_NODE.to_owned()),
            name: Some(format!("pool-{vmid}")),
            baseline_present: true,
            protected_artifact: false,
        })
    }

    async fn reverted_config(
        &self,
        _account_id: &str,
        _node: &str,
        _vmid: u32,
    ) -> Result<RevertedConfig, String> {
        Ok(RevertedConfig {
            template: false,
            lock: None,
            parent: Some("baseline".to_owned()),
            audio: None,
            audio_unreadable: false,
        })
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
        unimplemented!()
    }
    async fn clear(&self, _account_id: &str) -> Result<(), CredentialStoreError> {
        unimplemented!()
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    usb: Arc<UsbHost>,
    labs: Arc<LabRepository>,
    leases: Arc<LeaseRepository>,
    pools: Arc<LabPoolRepository>,
    hardware: Arc<HardwareRepository>,
    operations: Arc<Operations>,
    reverter: Arc<Scripted>,
    saga: Arc<LabHardwareSaga>,
    account_id: String,
    pool_id: String,
}

impl Harness {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        std::mem::forget(store);
        let faults = Arc::new(Faults::default());
        let pve = FakePve::new(faults);
        let usb = UsbHost::new(pve);
        usb.add_mapping(MAPPING, &["node=pve-b,id=aaaa:0001,path=1-1"]);
        usb.create_guest(MEMBER_VMID, &format!("pool-{MEMBER_VMID}"))
            .await;
        let accounts = Arc::new(ProxmoxAccountRepository::new(pool.clone()));
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
        let now = fleet_core::SystemClock::now_unix_millis();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let content = fleet_core::LabTemplateContent {
            name: "pool-template".to_owned(),
            image_version_id: "image-version-1".to_owned(),
            cores: 2,
            memory_mib: 2048,
            disk_gib: 20,
            readiness_deadline_seconds: 300,
            ttl_seconds: 3_600,
            cleanup: CleanupStrategy::Revert,
            ..fleet_core::LabTemplateContent::default()
        };
        let template = LabTemplatePort::create(
            labs.as_ref(),
            &fleet_application::lab::NewLabTemplate {
                content: content.clone(),
            },
            now,
        )
        .await
        .unwrap();
        LabTemplatePort::publish(
            labs.as_ref(),
            &template.id,
            &fleet_application::lab::LabTemplateVersion {
                id: "template-version-1".to_owned(),
                template_id: template.id.clone(),
                name: "pool-template".to_owned(),
                content,
                image_digest: "sha256:fixture".to_owned(),
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
                    template_version_id: "template-version-1".to_owned(),
                    account_id: account.id.clone(),
                    baseline_snapshot: "baseline".to_owned(),
                    size: 2,
                },
                "tester",
                now,
            )
            .await
            .unwrap();
        for member in pools
            .add_members(&created.id, &[MEMBER_VMID], now)
            .await
            .unwrap()
        {
            pools
                .finish_fill(
                    &member.id,
                    &FillResult::Available {
                        node: TEMPLATE_NODE.to_owned(),
                        name: format!("pool-{}", member.vmid),
                    },
                    now,
                )
                .await
                .unwrap();
        }
        let hardware = Arc::new(HardwareRepository::new(pool.clone()));
        let audit = Arc::new(AuditSink::new(pool.clone()));
        let client = ProxmoxClient::new(usb.transport());
        let accounts_port: Arc<dyn ProxmoxAccountPort> = accounts;
        let credentials: Arc<dyn ProxmoxCredentialStore> = Arc::new(OneSecret);
        let store_port: Arc<dyn HardwareStore> = hardware.clone();
        let saga = Arc::new(LabHardwareSaga::new(
            accounts_port.clone(),
            credentials.clone(),
            client.clone(),
            store_port.clone(),
            Arc::new(HardwareReservations::new(
                Arc::new(SqliteHardwareReservations::new(pool.clone())),
                audit.clone(),
            )),
            Arc::new(HardwareInventory::new(
                accounts_port,
                credentials,
                store_port,
                fleet_controller::hardware_observer::shared(client),
                audit.clone(),
            )),
            audit.clone(),
            Arc::new(LeaseRepository::new(pool.clone())),
            Arc::new(fleet_controller::lab_hardware::SqliteFingerprintPins::new(
                pool.clone(),
            )),
        ));
        Self {
            _dir: dir,
            labs,
            leases: Arc::new(LeaseRepository::new(pool.clone())),
            pools,
            hardware,
            operations: Arc::new(Operations::new(
                Arc::new(OperationRepository::new(pool.clone())),
                audit,
            )),
            reverter: Arc::new(Scripted::default()),
            saga,
            usb,
            account_id: account.id,
            pool_id: created.id,
            pool,
        }
    }

    /// A pooled lease, releasing, whose member carries an attachment the
    /// saga recorded: the entry is on the guest and the reservation is
    /// `attached` in usb0.
    async fn pooled_with_device(&self) -> String {
        let now = fleet_core::SystemClock::now_unix_millis();
        let lease = self
            .leases
            .create(
                &NewLease {
                    template_version_id: "template-version-1".to_owned(),
                    purpose: "pool".to_owned(),
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
        let ClaimOutcome::Claimed(member) = self
            .pools
            .claim(&self.pool_id, &lease.id, &record.id, now)
            .await
            .unwrap()
        else {
            panic!("the pool must have a free member");
        };
        assert_eq!(member.vmid, MEMBER_VMID);
        let mut releasing = self.leases.get(&lease.id).await.unwrap();
        releasing.state = LeaseState::Releasing;
        self.leases.update(&releasing).await.unwrap();

        let device = self
            .hardware
            .upsert_device(
                &DeviceObservation {
                    id: "device-reader-a".to_owned(),
                    account_id: self.account_id.clone(),
                    mapping_id: MAPPING.to_owned(),
                    kind: HardwareKind::Usb,
                    entries: vec![DeviceNodeEntry {
                        node: TEMPLATE_NODE.to_owned(),
                        vendor_id: "aaaa".to_owned(),
                        product_id: "0001".to_owned(),
                        usbpath: Some("1-1".to_owned()),
                        manufacturer: None,
                        product: None,
                        last_seen_at: now,
                    }],
                    status: DeviceStatus::Available,
                    status_detail: None,
                },
                now,
            )
            .await
            .unwrap();
        let reservations = HardwareReservations::new(
            Arc::new(SqliteHardwareReservations::new(self.pool.clone())),
            Arc::new(AuditSink::new(self.pool.clone())),
        );
        let ReserveDecision::Reserved { reservation, .. } = reservations
            .reserve(
                &AuditContext {
                    actor: "tester".to_owned(),
                    operation_id: None,
                },
                &ReserveRequest {
                    device_id: device.id.clone(),
                    owner_kind: ReservationOwnerKind::Lease,
                    owner_id: lease.id.clone(),
                },
                now,
            )
            .await
            .unwrap()
        else {
            panic!("the device is reserved");
        };
        let target = GuestTarget {
            account_id: self.account_id.clone(),
            node: TEMPLATE_NODE.to_owned(),
            vmid: MEMBER_VMID,
            usb_slot: Some(0),
        };
        self.hardware
            .transition_reservation(
                &reservation.id,
                State::Held,
                State::Attaching,
                Some(&target),
                now,
            )
            .await
            .unwrap();
        self.hardware
            .transition_reservation(
                &reservation.id,
                State::Attaching,
                State::Attached,
                None,
                now,
            )
            .await
            .unwrap();
        self.usb
            .set_slot(MEMBER_VMID, 0, &format!("mapping={MAPPING}"));
        lease.id
    }

    fn executor(&self) -> LabCleanupExecutor {
        LabCleanupExecutor::new(
            self.leases.clone(),
            self.labs.clone(),
            Arc::new(MachineRepository::new(self.pool.clone())),
            Arc::new(AuditSink::new(self.pool.clone())),
            self.reverter.clone(),
        )
        .with_pools(self.pools.clone(), Arc::new(Cluster), self.reverter.clone())
        .with_device_saga(self.saga.clone())
    }

    /// One cleanup attempt; answers the operation's state and the lease.
    async fn run(&self, lease_id: &str) -> (String, fleet_core::Lease) {
        let lease = self.leases.get(lease_id).await.unwrap();
        let operation = self
            .operations
            .create_lab_cleanup(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                lease_id,
                &cleanup_operation(&lease, None),
            )
            .await
            .unwrap();
        self.operations
            .claim_only_execute(&self.executor(), &operation.id, "test")
            .await
            .unwrap();
        let done = self
            .operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &operation.id,
            )
            .await
            .unwrap();
        (done.state, self.leases.get(lease_id).await.unwrap())
    }

    async fn member(&self) -> Option<(MemberState, Option<String>)> {
        self.pools
            .member_by_vmid(&self.account_id, MEMBER_VMID)
            .await
            .unwrap()
            .map(|member| (member.state, member.lease_id))
    }

    async fn reservation_state(&self) -> State {
        let rows: Vec<String> =
            sqlx::query_scalar("SELECT state FROM hardware_reservations ORDER BY created_at")
                .fetch_all(&self.pool)
                .await
                .unwrap();
        assert_eq!(rows.len(), 1);
        State::from_id(&rows[0]).unwrap()
    }
}

#[tokio::test]
async fn a_pool_member_is_detached_before_it_is_reverted_and_returned() {
    let harness = Harness::new().await;
    let lease = harness.pooled_with_device().await;
    // What the revert child had run when the detach's write arrived.
    let reverted_before_detach = Arc::new(Mutex::new(Vec::new()));
    {
        let reverter = harness.reverter.clone();
        let seen = reverted_before_detach.clone();
        harness.usb.inject(
            UsbStep::Detach,
            UsbFault::Hook(Arc::new(move || {
                let reverter = reverter.clone();
                let seen = seen.clone();
                Box::pin(async move {
                    seen.lock()
                        .unwrap()
                        .push(reverter.ran.lock().unwrap().len());
                })
            })),
            1,
        );
    }
    let (state, after) = harness.run(&lease).await;
    assert_eq!(state, "succeeded");
    assert_eq!(after.state, LeaseState::Released);
    assert_eq!(*reverted_before_detach.lock().unwrap(), vec![0]);
    assert_eq!(
        harness.reverter.ran.lock().unwrap().clone(),
        vec!["proxmox.guest.snapshot-revert".to_owned()]
    );
    assert_eq!(harness.usb.writes(), vec!["detach usb0".to_owned()]);
    assert!(harness.usb.stored(MEMBER_VMID).is_empty());
    assert_eq!(harness.reservation_state().await, State::Released);
    assert_eq!(
        harness.member().await,
        Some((MemberState::Available, None)),
        "the member went back with nothing attached"
    );
}

#[tokio::test]
async fn a_pool_member_whose_detach_cannot_be_confirmed_is_quarantined_and_never_reverted() {
    let harness = Harness::new().await;
    let lease = harness.pooled_with_device().await;
    harness.usb.inject(UsbStep::Detach, UsbFault::Forbidden, 1);
    let (state, after) = harness.run(&lease).await;
    assert_eq!(state, "failed");
    assert_eq!(after.state, LeaseState::Releasing);
    assert_eq!(after.cleanup_attempts, 1);
    // Quarantined at once, still bound to the lease that owes its revert,
    // and not touched: the entry is on it and no revert ran.
    assert_eq!(
        harness.member().await,
        Some((MemberState::Quarantined, Some(lease.clone())))
    );
    assert!(harness.reverter.ran.lock().unwrap().is_empty());
    assert_eq!(harness.reservation_state().await, State::DetachFailed);
    assert!(harness.usb.stored(MEMBER_VMID).contains_key(&0));

    // Once the host lets the detach through, the retry confirms it, reverts
    // the member and returns it.
    let (state, after) = harness.run(&lease).await;
    assert_eq!(state, "succeeded");
    assert_eq!(after.state, LeaseState::Released);
    assert_eq!(harness.reservation_state().await, State::Released);
    assert_eq!(harness.member().await, Some((MemberState::Available, None)));
    assert!(harness.usb.stored(MEMBER_VMID).is_empty());
}

#[tokio::test]
async fn keep_detaches_too_before_it_releases_the_lease() {
    let harness = Harness::new().await;
    let lease = harness.pooled_with_device().await;
    let mut releasing = harness.leases.get(&lease).await.unwrap();
    releasing.cleanup = CleanupStrategy::Keep;
    harness.leases.update(&releasing).await.unwrap();
    let (state, after) = harness.run(&lease).await;
    assert_eq!(state, "succeeded");
    assert_eq!(after.state, LeaseState::Released);
    assert!(harness.usb.stored(MEMBER_VMID).is_empty());
    assert_eq!(harness.reservation_state().await, State::Released);
    assert!(harness.reverter.ran.lock().unwrap().is_empty());
}
