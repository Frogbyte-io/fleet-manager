//! FM-1125 (#570): USB devices on persistent machines. A persistent machine
//! reserves a device, has it attached to its guest through a reviewed,
//! payload-bound action, and keeps it until an explicit detach releases it.
//!
//! **Simulated.** The shared fake Proxmox (`support/fake_pve.rs`) behind the
//! USB-aware layer (`support/usb_pve.rs`) that speaks the FM-S11 spike's
//! shapes (mapping list and `check-node`, `usbN` entries with the applied,
//! pending-add and pending-delete views, the config digest, a guest whose
//! `hotplug` option lacks `usb`), and a controller over one SQLite file with
//! the real reservation store, inventory, provider calls, saga and machine
//! use case. Every device id, VMID and address is invented.
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
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fake_pve::{FINGERPRINT, FakePve, Faults, TEMPLATE_NODE, TEMPLATE_VMID};
use fleet_application::audit::{AuditIntent, AuditOutcome};
use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, ReasonId};
use fleet_application::hardware::HardwareStore;
use fleet_application::hardware_inventory::HardwareInventory;
use fleet_application::hardware_reservation::{
    AuditContext, HardwareReservations, ReserveDecision, ReserveRequest,
};
use fleet_application::lab::ImageArtifactPort;
use fleet_application::lab_hardware_hotplug::{HotplugError, HotplugResult};
use fleet_application::machine::{
    GuestLink, GuestLinkPort, MachinePort, Machines, NewEndpoint, RegisterMachine,
};
use fleet_application::machine_usb::{
    MachineHardwareGate, MachineUsb, MachineUsbOutcome, MachineUsbReview, StoreMachineHardwareGate,
};
use fleet_application::operation::{AuditPort, Operations};
use fleet_application::persistent::{
    PersistentGuest, PersistentGuestPort, PersistentMachines, PersistentState,
};
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccountPort, ProxmoxCredentialStore,
};
use fleet_controller::guest_locks::GuestLocks;
use fleet_controller::hardware_reconciler::{HardwareReconciler, SqliteReconcilerRecords};
use fleet_controller::hardware_reservation_store::SqliteHardwareReservations;
use fleet_controller::lab_hardware::{LabHardwareSaga, SqliteFingerprintPins};
use fleet_controller::machine_usb::MachineUsbHost;
use fleet_controller::persistent_machines::ProxmoxRegisterGuard;
use fleet_controller::proxmox_exec::ProxmoxDestructiveExecutor;
use fleet_core::{
    DeviceStatus, EndpointKind, HardwareReservationState as State, ReservationOwnerKind,
};
use fleet_provider_proxmox::{ProxmoxClient, PveCredentials, PveHttpMethod, PveHttpRequest};
use fleet_storage_sqlite::{
    AuditSink, GuestLinkRepository, HardwareRepository, LabPoolRepository, LeaseRepository,
    MachineRepository, OperationRepository, PersistentGuestRepository, ProxmoxAccountRepository,
    Store,
};
use usb_pve::{UsbFault, UsbHost, UsbStep};

const PRINCIPAL: &str = fleet_auth::LAN_PRINCIPAL_ID;
/// Two devices on the guests' node, one port each.
const READER_A: &str = "fm-test-reader-a";
const READER_B: &str = "fm-test-reader-b";
/// The persistent guests.
const GUEST_A: u32 = 9100;
const GUEST_B: u32 = 9101;
/// A guest nobody made persistent.
const GUEST_C: u32 = 9102;
/// A persistent guest whose marker belongs to another machine.
const GUEST_D: u32 = 9103;
/// A Lab clone, and a Lab pool member.
const GUEST_LAB: u32 = 9110;
const GUEST_POOLED: u32 = 9111;
const SECRET: &str = "fake-token-material";

fn now() -> i64 {
    fleet_core::SystemClock::now_unix_millis()
}

fn entry(mapping: &str) -> String {
    format!("mapping={mapping}")
}

fn stored(entries: &[(u8, &str)]) -> BTreeMap<u8, String> {
    entries
        .iter()
        .map(|(slot, mapping)| (*slot, entry(mapping)))
        .collect()
}

fn principal(id: &str) -> ActingPrincipal {
    ActingPrincipal { id: id.to_owned() }
}

#[derive(Debug)]
struct AllowAll;

impl Authorizer for AllowAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

/// Allows only the listed catalog actions, and, when `machine` is set, only
/// on that machine (the resource of both actions is the machine id).
#[derive(Debug)]
struct Allow {
    actions: &'static [&'static str],
    machine: Option<String>,
}

impl Allow {
    fn any(actions: &'static [&'static str]) -> Self {
        Self {
            actions,
            machine: None,
        }
    }

    fn only(actions: &'static [&'static str], machine: &str) -> Self {
        Self {
            actions,
            machine: Some(machine.to_owned()),
        }
    }
}

impl Authorizer for Allow {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        let scoped = self
            .machine
            .as_deref()
            .is_none_or(|machine| request.resource == Some(machine));
        if scoped && self.actions.contains(&request.action.id()) {
            Decision::allow()
        } else {
            Decision::deny(ReasonId::UnknownPrincipal)
        }
    }
}

fn delegated_authorizer() -> fleet_auth::delegated::ScopedAuthorizer {
    fleet_auth::delegated::ScopedAuthorizer::new(Arc::new(
        fleet_application::credentials::GrantBook::new(),
    ))
}

/// The delegated Lab credential's principal id.
fn lab_credential() -> String {
    fleet_application::authz::delegated_principal_id("agent", "cred-1")
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
    async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
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

#[derive(Debug)]
struct OneSecret;

#[async_trait]
impl ProxmoxCredentialStore for OneSecret {
    async fn load(&self, _account_id: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(Some(SECRET.to_owned()))
    }
    async fn store(&self, _account_id: &str, _secret: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("machines never store Proxmox credentials")
    }
    async fn clear(&self, _account_id: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("machines never clear Proxmox credentials")
    }
}

#[derive(Debug)]
struct Artifacts;

#[async_trait]
impl ImageArtifactPort for Artifacts {
    async fn template_vmid(&self, _image_version_id: &str) -> Result<Option<u32>, String> {
        Ok(Some(TEMPLATE_VMID))
    }

    async fn promoted_template_vmids(&self) -> Result<Vec<u32>, String> {
        Ok(vec![TEMPLATE_VMID])
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
}

impl World {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("fleet.db");
        let faults = Arc::new(Faults::default());
        let pve = FakePve::new(faults.clone());
        let usb_host = UsbHost::new(pve.clone());
        usb_host.add_mapping(READER_A, &["node=pve-b,id=aaaa:0001,path=1-1"]);
        usb_host.add_mapping(READER_B, &["node=pve-b,id=bbbb:0002,path=1-2"]);
        usb_host.create_guest(GUEST_A, "persist-a").await;
        usb_host.create_guest(GUEST_B, "persist-b").await;
        usb_host.create_guest(GUEST_C, "unmarked-c").await;
        usb_host.create_guest(GUEST_D, "persist-d").await;
        usb_host.create_guest(GUEST_LAB, "fm-lab-0abc").await;
        usb_host.create_guest(GUEST_POOLED, "pool-member").await;
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
        }
    }

    /// The guest starts running (so a write to it is a hotplug).
    async fn start(&self, vmid: u32) {
        let request = PveHttpRequest {
            host: fake_pve::API_HOST.to_owned(),
            port: 8006,
            path: format!("/api2/json/nodes/{TEMPLATE_NODE}/qemu/{vmid}/status/start"),
            pinned_fingerprint: Some(FINGERPRINT.to_owned()),
            credentials: Arc::new(PveCredentials {
                token_id: "fleet@pve!lab".to_owned(),
                token: fleet_core::SensitiveString::new(SECRET),
            }),
            method: PveHttpMethod::Post,
        };
        self.usb
            .transport()
            .execute_with_body(request, b"{}".to_vec())
            .await
            .expect("the fake starts the guest");
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
    usb_case: Arc<MachineUsb>,
    inventory: Arc<HardwareInventory>,
    hardware: Arc<dyn HardwareStore>,
    reservations: Arc<HardwareReservations>,
    reconciler: Arc<HardwareReconciler>,
    guest_locks: Arc<GuestLocks>,
    machines: Arc<MachineRepository>,
    markers: Arc<PersistentGuestRepository>,
    links: Arc<GuestLinkRepository>,
    account_id: String,
}

impl Controller {
    async fn start(world: &World) -> Self {
        let store = Store::open(&world.database)
            .await
            .expect("the previous controller released the database");
        let pool = store.pool().clone();
        let audit: Arc<dyn AuditPort> = Arc::new(GateAudit {
            inner: AuditSink::new(pool.clone()),
            refuse_event: world.refuse_event.clone(),
        });
        let accounts: Arc<dyn ProxmoxAccountPort> =
            Arc::new(ProxmoxAccountRepository::new(pool.clone()));
        let credentials: Arc<dyn ProxmoxCredentialStore> = Arc::new(OneSecret);
        let client = ProxmoxClient::new(world.usb.transport());
        let hardware: Arc<dyn HardwareStore> = Arc::new(HardwareRepository::new(pool.clone()));
        let reservations = Arc::new(HardwareReservations::new(
            Arc::new(SqliteHardwareReservations::new(pool.clone())),
            audit.clone(),
        ));
        let inventory = Arc::new(HardwareInventory::new(
            accounts.clone(),
            credentials.clone(),
            hardware.clone(),
            fleet_controller::hardware_observer::shared(client.clone()),
            audit.clone(),
        ));
        let machines = Arc::new(MachineRepository::new(pool.clone()));
        let reconciler = Arc::new(HardwareReconciler::new(
            accounts.clone(),
            credentials.clone(),
            client.clone(),
            hardware.clone(),
            reservations.clone(),
            inventory.clone(),
            audit.clone(),
            Arc::new(SqliteReconcilerRecords::new(pool.clone())),
        ));
        let saga = Arc::new(LabHardwareSaga::new(
            accounts.clone(),
            credentials.clone(),
            client.clone(),
            hardware.clone(),
            reservations.clone(),
            inventory.clone(),
            audit.clone(),
            Arc::new(LeaseRepository::new(pool.clone())),
            Arc::new(SqliteFingerprintPins::new(pool.clone())),
        ));
        let guest_locks = GuestLocks::new();
        let port = Arc::new(MachineUsbHost::new(
            saga,
            hardware.clone(),
            reservations.clone(),
            machines.clone(),
            guest_locks.clone(),
        ));
        let links = Arc::new(GuestLinkRepository::new(pool.clone()));
        let markers = Arc::new(PersistentGuestRepository::new(pool.clone()));
        let guard = ProxmoxRegisterGuard::new(accounts, credentials, client, Arc::new(Artifacts))
            .with_pool_members(Arc::new(fleet_application::operation::PoolMembership(
                Arc::new(LabPoolRepository::new(pool.clone())),
            )));
        let usb_case = Arc::new(MachineUsb::new(
            machines.clone(),
            links.clone(),
            markers.clone(),
            Arc::new(guard),
            hardware.clone(),
            port.clone(),
        ));
        Self {
            _store: store,
            pool,
            usb_case,
            inventory,
            hardware,
            reservations,
            reconciler,
            guest_locks,
            machines,
            markers,
            links,
            account_id: world.account_id.clone(),
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
    /// or the API makes before a machine asks for one).
    async fn refresh_inventory(&self) {
        self.inventory
            .refresh(&AllowAll, &principal(PRINCIPAL), None, &self.account_id)
            .await
            .expect("the inventory refreshes");
    }

    /// A registered machine.
    async fn machine(&self, name: &str) -> String {
        self.machines
            .register(&RegisterMachine {
                name: name.to_owned(),
                description: String::new(),
                endpoints: vec![NewEndpoint {
                    kind: EndpointKind::Ssh,
                    reference: format!("root@{name}.invalid:22"),
                }],
                tags: vec![],
                groups: vec![],
            })
            .await
            .unwrap()
            .id
    }

    async fn link(&self, machine_id: &str, vmid: u32, kind: &str) {
        self.links
            .confirm(
                machine_id,
                &GuestLink {
                    account_id: self.account_id.clone(),
                    guest_kind: kind.to_owned(),
                    node: TEMPLATE_NODE.to_owned(),
                    vmid,
                },
            )
            .await
            .unwrap();
    }

    /// The machine's guest link changes (it is unlinked, then linked again).
    async fn relink(&self, machine_id: &str, vmid: u32) {
        self.links.unlink(machine_id).await.unwrap();
        self.link(machine_id, vmid, "qemu").await;
    }

    async fn mark(&self, machine_id: Option<&str>, vmid: u32, name: &str, state: PersistentState) {
        self.mark_as(machine_id, vmid, name, "image-version-1", state)
            .await;
    }

    async fn mark_as(
        &self,
        machine_id: Option<&str>,
        vmid: u32,
        name: &str,
        source: &str,
        state: PersistentState,
    ) {
        self.markers
            .reserve(&PersistentGuest {
                account_id: self.account_id.clone(),
                vmid,
                name: name.to_owned(),
                node: TEMPLATE_NODE.to_owned(),
                image_version_id: source.to_owned(),
                machine_id: machine_id.map(str::to_owned),
                cloned: true,
                state,
                step: None,
                operation_id: None,
                created_at: now(),
                updated_at: now(),
            })
            .await
            .unwrap();
    }

    /// A machine linked to a ready persistent guest.
    async fn persistent(&self, name: &str, vmid: u32) -> String {
        let machine_id = self.machine(name).await;
        self.link(&machine_id, vmid, "qemu").await;
        self.mark(Some(&machine_id), vmid, name, PersistentState::Ready)
            .await;
        machine_id
    }

    async fn review_attach_as(
        &self,
        authorizer: &dyn Authorizer,
        actor: &str,
        machine_id: &str,
        mapping: &str,
    ) -> Result<MachineUsbReview, HotplugError> {
        self.usb_case
            .review_attach(authorizer, &principal(actor), machine_id, mapping)
            .await
    }

    /// The reviewed attach, as the API and the CLI make it.
    async fn attach_as(
        &self,
        authorizer: &dyn Authorizer,
        actor: &str,
        machine_id: &str,
        mapping: &str,
    ) -> Result<MachineUsbOutcome, HotplugError> {
        let review = self
            .review_attach_as(authorizer, actor, machine_id, mapping)
            .await?;
        self.usb_case
            .attach(
                authorizer,
                &principal(actor),
                machine_id,
                mapping,
                &review.review_token,
            )
            .await
    }

    async fn attach(
        &self,
        machine_id: &str,
        mapping: &str,
    ) -> Result<MachineUsbOutcome, HotplugError> {
        self.attach_as(&AllowAll, PRINCIPAL, machine_id, mapping)
            .await
    }

    async fn detach_as(
        &self,
        authorizer: &dyn Authorizer,
        actor: &str,
        machine_id: &str,
        mapping: &str,
    ) -> Result<MachineUsbOutcome, HotplugError> {
        let review = self
            .usb_case
            .review_detach(authorizer, &principal(actor), machine_id, mapping)
            .await?;
        self.usb_case
            .detach(
                authorizer,
                &principal(actor),
                machine_id,
                mapping,
                &review.review_token,
            )
            .await
    }

    async fn detach(
        &self,
        machine_id: &str,
        mapping: &str,
    ) -> Result<MachineUsbOutcome, HotplugError> {
        self.detach_as(&AllowAll, PRINCIPAL, machine_id, mapping)
            .await
    }

    /// Every reservation row, oldest first: state, slot, guest VMID, owner.
    async fn rows(&self) -> Vec<(String, Option<i64>, Option<i64>, String)> {
        sqlx::query_as(
            "SELECT state, usb_slot, guest_vmid, owner_kind || ':' || owner_id \
             FROM hardware_reservations ORDER BY created_at, id",
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

    async fn live(&self) -> usize {
        self.hardware.list_live_reservations().await.unwrap().len()
    }

    async fn status(&self, mapping: &str) -> DeviceStatus {
        self.hardware
            .device_by_mapping(&self.account_id, mapping)
            .await
            .unwrap()
            .unwrap()
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

    /// `(actor, action)` of every audit intent of one event, oldest first.
    async fn audit_actions(&self, event: &str) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT actor, action FROM audit_events WHERE outcome IS NULL AND metadata_json LIKE ?1 ORDER BY seq",
        )
        .bind(format!("%\"{event}\"%"))
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    async fn audit_metadata(&self, event: &str) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT metadata_json FROM audit_events WHERE outcome IS NULL AND metadata_json LIKE ?1 ORDER BY seq",
        )
        .bind(format!("%\"{event}\"%"))
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    /// A lease in `state` that holds the device through a reservation, as
    /// the Lab's placement leaves it.
    async fn lease_holds(&self, mapping: &str, lease_id: &str, state: &str) {
        sqlx::query(
            "INSERT INTO lab_leases (id, template_version_id, owner, purpose, state, \
             cleanup, created_at) \
             VALUES (?1, 'template-version-1', 'tester', 'test', ?2, 'destroy', ?3)",
        )
        .bind(lease_id)
        .bind(state)
        .bind(now())
        .execute(&self.pool)
        .await
        .unwrap();
        let device = self
            .hardware
            .device_by_mapping(&self.account_id, mapping)
            .await
            .unwrap()
            .expect("the device is inventoried");
        let decision = self
            .reservations
            .reserve(
                &AuditContext {
                    actor: PRINCIPAL.to_owned(),
                    operation_id: None,
                },
                &ReserveRequest {
                    device_id: device.id,
                    owner_kind: ReservationOwnerKind::Lease,
                    owner_id: lease_id.to_owned(),
                },
                now(),
            )
            .await
            .unwrap();
        assert!(matches!(decision, ReserveDecision::Reserved { .. }));
    }
}

fn refused_reason(error: &HotplugError) -> &str {
    match error {
        HotplugError::Refused { reason, .. } => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn refused_detail(error: &HotplugError) -> &str {
    match error {
        HotplugError::Refused { detail, .. } => detail,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

async fn ready_controller() -> (World, Controller) {
    let world = World::new().await;
    let controller = Controller::start(&world).await;
    controller.refresh_inventory().await;
    (world, controller)
}

// ---------------------------------------------------------------------
// Attach and detach on a stopped and a running machine.
// ---------------------------------------------------------------------

#[tokio::test]
async fn an_attach_to_a_stopped_machine_is_written_read_back_and_reserved() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;

    let review = controller
        .review_attach_as(&AllowAll, PRINCIPAL, &machine, READER_A)
        .await
        .unwrap();
    let guest = review.guest.as_ref().expect("an attach names its guest");
    assert_eq!((guest.vmid, guest.name.as_str()), (GUEST_A, "persist-a"));
    assert!(world.usb.writes().is_empty(), "a review writes nothing");
    assert_eq!(controller.live().await, 0, "a review reserves nothing");

    let outcome = controller.attach(&machine, READER_A).await.unwrap();

    assert_eq!(outcome.result, HotplugResult::Attached);
    assert!(outcome.result.on_guest());
    assert_eq!(outcome.reservation_state, State::Attached);
    assert_eq!(outcome.usb_slot, Some(0));
    assert!(!outcome.released);
    // Written once, digest-conditional, and read back: the guest's stored and
    // applied views agree.
    assert_eq!(
        world.usb.writes(),
        vec!["attach usb0=mapping=fm-test-reader-a".to_owned()]
    );
    assert_eq!(world.usb.stored(GUEST_A), stored(&[(0, READER_A)]));
    assert_eq!(world.usb.applied(GUEST_A), stored(&[(0, READER_A)]));
    // Reserved by the machine, on this guest, in the slot Fleet wrote.
    assert_eq!(
        controller.rows().await,
        vec![(
            "attached".to_owned(),
            Some(0),
            Some(i64::from(GUEST_A)),
            format!("machine:{machine}")
        )]
    );
    // The device's live holder is the machine (the status shown is derived
    // from it at read time).
    let device = controller
        .hardware
        .device_by_mapping(&controller.account_id, READER_A)
        .await
        .unwrap()
        .unwrap();
    let holder = controller
        .hardware
        .live_reservation_for_device(&device.id)
        .await
        .unwrap()
        .expect("a live holder");
    assert_eq!(
        (holder.owner_kind, holder.owner_id.as_str()),
        (ReservationOwnerKind::Machine, machine.as_str())
    );
    // The write was audited as the principal's reviewed machine action,
    // before it was made.
    assert_eq!(
        controller.audit_actions("hardware_attach_requested").await,
        vec![(PRINCIPAL.to_owned(), "machines.usb.attach".to_owned())]
    );
    let facts = controller.audit_metadata("hardware_attach_requested").await;
    assert!(
        facts[0].contains("\"machine_id\"") || facts[0].contains("\"owner_id\""),
        "{facts:?}"
    );
    assert!(facts[0].contains(&machine), "{facts:?}");
    assert_eq!(controller.audit_events("hardware_attached").await, 1);
    assert_eq!(controller.audit_events("hardware_reserved").await, 1);
}

#[tokio::test]
async fn a_detach_releases_the_reservation_after_the_read_back() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    controller.attach(&machine, READER_A).await.unwrap();

    let review = controller
        .usb_case
        .review_detach(&AllowAll, &principal(PRINCIPAL), &machine, READER_A)
        .await
        .unwrap();
    let reserved = review.reservation.expect("the machine holds the device");
    assert_eq!(reserved.state, State::Attached);
    assert_eq!(reserved.guest.and_then(|guest| guest.usb_slot), Some(0));

    let outcome = controller.detach(&machine, READER_A).await.unwrap();

    assert_eq!(outcome.result, HotplugResult::Detached);
    assert!(!outcome.result.on_guest());
    assert_eq!(outcome.reservation_state, State::Released);
    assert!(outcome.released);
    assert_eq!(outcome.usb_slot, None);
    assert_eq!(
        world.usb.writes(),
        vec![
            "attach usb0=mapping=fm-test-reader-a".to_owned(),
            "detach usb0".to_owned()
        ]
    );
    assert!(world.usb.stored(GUEST_A).is_empty());
    assert!(world.usb.applied(GUEST_A).is_empty());
    assert_eq!(controller.states().await, vec!["released"]);
    assert_eq!(controller.live().await, 0);
    assert_eq!(controller.status(READER_A).await, DeviceStatus::Available);
    assert_eq!(
        controller.audit_actions("hardware_detach_requested").await,
        vec![(PRINCIPAL.to_owned(), "machines.usb.detach".to_owned())]
    );
    // The release is filed under the action the caller was authorized for.
    assert_eq!(
        controller.audit_actions("hardware_released").await,
        vec![(PRINCIPAL.to_owned(), "machines.usb.detach".to_owned())]
    );
    // The device can be reserved again.
    controller.attach(&machine, READER_A).await.unwrap();
}

#[tokio::test]
async fn a_running_machine_takes_the_device_by_hotplug_and_gives_it_back() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    world.start(GUEST_A).await;

    let attached = controller.attach(&machine, READER_A).await.unwrap();

    assert_eq!(attached.result, HotplugResult::Attached);
    // The running guest has it (the applied view), not only the stored one.
    assert_eq!(world.usb.applied(GUEST_A), stored(&[(0, READER_A)]));
    let detached = controller.detach(&machine, READER_A).await.unwrap();
    assert_eq!(detached.result, HotplugResult::Detached);
    assert!(world.usb.applied(GUEST_A).is_empty());
    assert_eq!(controller.states().await, vec!["released"]);
}

#[tokio::test]
async fn an_attach_pve_would_leave_pending_is_removed_again_and_never_reported_attached() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    world.start(GUEST_A).await;
    world.usb.set_hotplug_usb(GUEST_A, false);

    let error = controller.attach(&machine, READER_A).await.unwrap_err();

    assert_eq!(refused_reason(&error), "hardware_attach_pending");
    // The pending entry was written, removed again, and nothing is attached
    // or held: a restart cannot attach a device nobody confirmed.
    assert_eq!(
        world.usb.writes(),
        vec![
            "attach usb0=mapping=fm-test-reader-a".to_owned(),
            "detach usb0".to_owned()
        ]
    );
    assert!(world.usb.stored(GUEST_A).is_empty());
    assert!(world.usb.applied(GUEST_A).is_empty());
    assert_eq!(controller.live().await, 0, "{:?}", controller.rows().await);
    assert_eq!(controller.status(READER_A).await, DeviceStatus::Available);
    // Stopped, the same attach is applied at once.
    world.usb.set_hotplug_usb(GUEST_A, true);
    controller.attach(&machine, READER_A).await.unwrap();
}

#[tokio::test]
async fn a_detach_pve_leaves_pending_keeps_the_device_attached_and_reserved() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    world.start(GUEST_A).await;
    controller.attach(&machine, READER_A).await.unwrap();
    world.usb.set_hotplug_usb(GUEST_A, false);

    let outcome = controller.detach(&machine, READER_A).await.unwrap();

    assert_eq!(outcome.result, HotplugResult::DetachPending);
    assert!(outcome.result.on_guest(), "the device is still attached");
    assert_eq!(outcome.reservation_state, State::Detaching);
    assert!(!outcome.released);
    assert_eq!(world.usb.applied(GUEST_A), stored(&[(0, READER_A)]));
    assert_eq!(controller.states().await, vec!["detaching"]);
    assert_eq!(controller.live().await, 1, "the machine still holds it");
    // Another owner cannot take it meanwhile.
    controller.lease_attempt_is_busy(READER_A).await;

    // After the guest restarted PVE applied the removal; the repeat confirms
    // it by reading the guest and releases without a second delete.
    world.usb.apply_pending(GUEST_A);
    let writes = world.usb.writes().len();
    let done = controller.detach(&machine, READER_A).await.unwrap();
    assert_eq!(done.result, HotplugResult::Detached);
    assert_eq!(controller.states().await, vec!["released"]);
    assert_eq!(world.usb.writes().len(), writes, "no second delete");
}

impl Controller {
    /// A lease asking for the device is refused `hardware_busy` while another
    /// owner holds it.
    async fn lease_attempt_is_busy(&self, mapping: &str) {
        let device = self
            .hardware
            .device_by_mapping(&self.account_id, mapping)
            .await
            .unwrap()
            .unwrap();
        sqlx::query(
            "INSERT OR IGNORE INTO lab_leases (id, template_version_id, owner, purpose, state, \
             cleanup, created_at) \
             VALUES ('lease-probe', 'template-version-1', 'tester', 'test', 'provisioning', 'destroy', ?1)",
        )
        .bind(now())
        .execute(&self.pool)
        .await
        .unwrap();
        let decision = self
            .reservations
            .reserve(
                &AuditContext {
                    actor: PRINCIPAL.to_owned(),
                    operation_id: None,
                },
                &ReserveRequest {
                    device_id: device.id,
                    owner_kind: ReservationOwnerKind::Lease,
                    owner_id: "lease-probe".to_owned(),
                },
                now(),
            )
            .await
            .unwrap();
        match decision {
            ReserveDecision::Refused(refusal) => assert_eq!(refusal.reason(), "hardware_busy"),
            other => panic!("the device was granted to a second owner: {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------
// Authorization and the review token.
// ---------------------------------------------------------------------

fn denied(error: &HotplugError) -> bool {
    matches!(error, HotplugError::Denied(_))
}

#[tokio::test]
async fn only_an_authorized_principal_acts_and_a_denied_one_changes_nothing() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;

    // Nothing allowed: neither the review nor the execute call is let in.
    let nobody = Allow::any(&[]);
    assert!(denied(
        &controller
            .review_attach_as(&nobody, "someone", &machine, READER_A)
            .await
            .unwrap_err()
    ));
    assert!(denied(
        &controller
            .attach_as(&nobody, "someone", &machine, READER_A)
            .await
            .unwrap_err()
    ));
    assert!(denied(
        &controller
            .detach_as(&nobody, "someone", &machine, READER_A)
            .await
            .unwrap_err()
    ));
    // The Lab's hotplug entries do not open a machine's hardware.
    let lab_only = Allow::any(&[
        "lab.hardware.attach",
        "lab.hardware.detach",
        "machine.update",
        "machines.provision",
        "proxmox.guest.config",
        "hardware.override-release",
    ]);
    assert!(denied(
        &controller
            .attach_as(&lab_only, "someone", &machine, READER_A)
            .await
            .unwrap_err()
    ));
    // A delegated Lab credential has no catalog row for either action.
    let delegated = delegated_authorizer();
    let credential = lab_credential();
    assert!(denied(
        &controller
            .attach_as(&delegated, &credential, &machine, READER_A)
            .await
            .unwrap_err()
    ));
    assert!(denied(
        &controller
            .detach_as(&delegated, &credential, &machine, READER_A)
            .await
            .unwrap_err()
    ));
    assert!(world.usb.writes().is_empty());
    assert_eq!(controller.live().await, 0);
    assert!(controller.rows().await.is_empty());

    // The attach and detach entries are separate: allowing one does not
    // allow the other, and the audit names the principal that acted.
    let attach_only = Allow::any(&["machines.usb.attach"]);
    controller
        .attach_as(&attach_only, "alice", &machine, READER_A)
        .await
        .unwrap();
    assert!(denied(
        &controller
            .detach_as(&attach_only, "alice", &machine, READER_A)
            .await
            .unwrap_err()
    ));
    assert_eq!(world.usb.writes().len(), 1);
    assert_eq!(
        controller.audit_actions("hardware_attach_requested").await,
        vec![("alice".to_owned(), "machines.usb.attach".to_owned())]
    );
    let detach_only = Allow::any(&["machines.usb.detach"]);
    assert!(denied(
        &controller
            .attach_as(&detach_only, "bob", &machine, READER_A)
            .await
            .unwrap_err()
    ));
    controller
        .detach_as(&detach_only, "bob", &machine, READER_A)
        .await
        .unwrap();
    assert_eq!(
        controller.audit_actions("hardware_detach_requested").await,
        vec![("bob".to_owned(), "machines.usb.detach".to_owned())]
    );
}

#[tokio::test]
async fn a_review_token_binds_the_action_the_machine_the_device_and_the_guest() {
    let (world, controller) = ready_controller().await;
    let first = controller.persistent("persist-a", GUEST_A).await;
    let second = controller.persistent("persist-b", GUEST_B).await;
    let token = controller
        .review_attach_as(&AllowAll, PRINCIPAL, &first, READER_A)
        .await
        .unwrap()
        .review_token;
    let case = &controller.usb_case;
    let me = principal(PRINCIPAL);

    // Another device, another machine, no token, a made-up token.
    for (machine, mapping, token) in [
        (&first, READER_B, token.as_str()),
        (&second, READER_A, token.as_str()),
        (&first, READER_A, ""),
        (&first, READER_A, "not-a-token"),
    ] {
        let error = case
            .attach(&AllowAll, &me, machine, mapping, token)
            .await
            .unwrap_err();
        assert!(matches!(error, HotplugError::Invalid { .. }), "{error:?}");
    }
    // The wrong action.
    let error = case
        .detach(&AllowAll, &me, &first, READER_A, &token)
        .await
        .unwrap_err();
    assert!(matches!(error, HotplugError::Invalid { .. }), "{error:?}");
    assert!(world.usb.writes().is_empty());
    assert_eq!(controller.live().await, 0);

    // The machine's guest changed after the review: the old token no longer
    // names this request, so the device cannot be moved to another guest.
    controller.relink(&first, GUEST_C).await;
    let error = case
        .attach(&AllowAll, &me, &first, READER_A, &token)
        .await
        .unwrap_err();
    assert!(matches!(error, HotplugError::Invalid { .. }), "{error:?}");
    assert!(world.usb.writes().is_empty());

    // A fresh review of the new guest is refused on its own merits (the guest
    // was never made persistent), and the first token works again once the
    // link is what was reviewed.
    let error = controller.attach(&first, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "machine_not_persistent");
    controller.relink(&first, GUEST_A).await;
    let done = case
        .attach(&AllowAll, &me, &first, READER_A, &token)
        .await
        .unwrap();
    assert_eq!(done.result, HotplugResult::Attached);

    // The detach has its own token, bound to the machine and the device.
    let detach_token = case
        .review_detach(&AllowAll, &me, &first, READER_A)
        .await
        .unwrap()
        .review_token;
    assert_ne!(detach_token, token);
    let error = case
        .detach(&AllowAll, &me, &first, READER_B, &detach_token)
        .await
        .unwrap_err();
    assert!(matches!(error, HotplugError::Invalid { .. }), "{error:?}");
    let error = case
        .attach(&AllowAll, &me, &first, READER_A, &detach_token)
        .await
        .unwrap_err();
    assert!(matches!(error, HotplugError::Invalid { .. }), "{error:?}");
    case.detach(&AllowAll, &me, &first, READER_A, &detach_token)
        .await
        .unwrap();
}

// ---------------------------------------------------------------------
// What a machine may take a device for.
// ---------------------------------------------------------------------

async fn assert_nothing_changed(world: &World, controller: &Controller) {
    assert!(world.usb.writes().is_empty());
    assert!(controller.rows().await.is_empty());
}

#[tokio::test]
async fn a_machine_without_a_persistent_qemu_guest_is_refused() {
    let (world, controller) = ready_controller().await;

    // Unknown machine.
    let error = controller
        .attach("no-such-machine", READER_A)
        .await
        .unwrap_err();
    assert!(matches!(error, HotplugError::NotFound { .. }), "{error:?}");

    // No guest link.
    let bare = controller.machine("bare").await;
    let error = controller.attach(&bare, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "machine_has_no_guest");

    // A container.
    let boxed = controller.machine("container").await;
    controller.link(&boxed, GUEST_A, "lxc").await;
    let error = controller.attach(&boxed, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "machine_guest_not_qemu");

    // A guest nobody made persistent: the marker is what keeps Lab away.
    let unmarked = controller.machine("unmarked").await;
    controller.link(&unmarked, GUEST_C, "qemu").await;
    let error = controller.attach(&unmarked, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "machine_not_persistent");

    // A creation that is still running.
    let creating = controller.machine("creating").await;
    controller.link(&creating, GUEST_B, "qemu").await;
    controller
        .mark(
            Some(&creating),
            GUEST_B,
            "persist-b",
            PersistentState::Creating,
        )
        .await;
    let error = controller.attach(&creating, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "machine_not_ready");

    // A guest whose marker names another machine.
    let owner = controller.machine("owner").await;
    controller
        .mark(Some(&owner), GUEST_D, "persist-d", PersistentState::Ready)
        .await;
    let thief = controller.machine("thief").await;
    controller.link(&thief, GUEST_D, "qemu").await;
    let error = controller.attach(&thief, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "machine_guest_mismatch");
    assert!(refused_detail(&error).contains(&owner), "{error:?}");

    assert_nothing_changed(&world, &controller).await;
}

#[tokio::test]
async fn a_lab_clone_a_template_and_a_pool_member_are_never_a_machines_guest() {
    let (world, controller) = ready_controller().await;

    // A Lab clone carrying a marker (however it got one).
    let clone = controller.machine("clone").await;
    controller.link(&clone, GUEST_LAB, "qemu").await;
    controller
        .mark(
            Some(&clone),
            GUEST_LAB,
            "fm-lab-0abc",
            PersistentState::Ready,
        )
        .await;
    let error = controller.attach(&clone, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "guest_not_eligible");
    assert!(refused_detail(&error).contains("Lab clone"), "{error:?}");

    // A template.
    let template = controller.machine("template").await;
    controller.link(&template, TEMPLATE_VMID, "qemu").await;
    controller
        .mark(
            Some(&template),
            TEMPLATE_VMID,
            "lab-image",
            PersistentState::Ready,
        )
        .await;
    let error = controller.attach(&template, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "guest_not_eligible");
    assert!(refused_detail(&error).contains("template"), "{error:?}");

    // A Lab pool member.
    let pooled = controller.machine("pooled").await;
    controller.link(&pooled, GUEST_POOLED, "qemu").await;
    controller
        .mark(
            Some(&pooled),
            GUEST_POOLED,
            "pool-member",
            PersistentState::Ready,
        )
        .await;
    sqlx::query(
        "INSERT INTO lab_pools (id, template_version_id, account_id, baseline_snapshot, size, \
         created_by, created_at) VALUES ('pool-1', 'template-version-1', ?1, 'baseline', 1, 'tester', ?2)",
    )
    .bind(&controller.account_id)
    .bind(now())
    .execute(&controller.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO lab_pool_members (id, pool_id, account_id, vmid, state, created_at, updated_at) \
         VALUES ('member-1', 'pool-1', ?1, ?2, 'available', ?3, ?3)",
    )
    .bind(&controller.account_id)
    .bind(i64::from(GUEST_POOLED))
    .bind(now())
    .execute(&controller.pool)
    .await
    .unwrap();
    let error = controller.attach(&pooled, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "guest_not_eligible");
    assert!(refused_detail(&error).contains("pool"), "{error:?}");

    // A registered marker whose guest was renamed no longer guards it.
    let renamed = controller.machine("renamed").await;
    controller.link(&renamed, GUEST_B, "qemu").await;
    controller
        .mark_as(
            Some(&renamed),
            GUEST_B,
            "an-older-name",
            "registered",
            PersistentState::Ready,
        )
        .await;
    let error = controller.attach(&renamed, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "machine_not_persistent");

    assert_nothing_changed(&world, &controller).await;
}

// ---------------------------------------------------------------------
// A device that is not available, busy or somebody else's.
// ---------------------------------------------------------------------

#[tokio::test]
async fn an_unknown_or_missing_device_is_refused_and_reserves_nothing() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;

    // Not in the inventory at all.
    let error = controller
        .attach(&machine, "fm-test-nope")
        .await
        .unwrap_err();
    assert_eq!(refused_reason(&error), "hardware_unknown");
    let error = controller.attach(&machine, "a,host=1-7").await.unwrap_err();
    assert!(matches!(error, HotplugError::Invalid { .. }), "{error:?}");

    // Unplugged: the inventory says missing, and nothing reserves it.
    world.usb.set_present(READER_A, false);
    controller.refresh_inventory().await;
    let error = controller.attach(&machine, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "hardware_missing");
    assert_nothing_changed(&world, &controller).await;
    // Plugged back in, it attaches.
    world.usb.set_present(READER_A, true);
    controller.refresh_inventory().await;
    controller.attach(&machine, READER_A).await.unwrap();
}

/// The token's permissions as the fake PVE reports them (#596).
fn permissions_with(vms: serde_json::Value) -> serde_json::Value {
    let mut map = serde_json::json!({"/mapping/usb": {"Mapping.Audit": 1, "Mapping.Use": 1}});
    for (path, privileges) in vms.as_object().expect("an object") {
        map[path] = privileges.clone();
    }
    map
}

#[tokio::test]
async fn a_machine_attach_refuses_when_the_token_cannot_be_shown_to_audit_every_guest() {
    // The machine path reuses the saga's verify, so the refusal covers it:
    // placement saw an available device, and by the re-observation the token
    // cannot be shown to audit every guest (#596). Nothing is written and the
    // reservation is released.
    for (label, setup) in [
        ("no VM.Audit on /vms", 0),
        ("permissions unreadable", 1),
        ("a hidden guest PVE says exists", 2),
    ] {
        let (world, controller) = ready_controller().await;
        let machine = controller.persistent("persist-a", GUEST_A).await;
        match setup {
            0 => world.usb.set_permissions(
                200,
                permissions_with(serde_json::json!({"/vms": {"VM.Config.HWType": 1}})),
            ),
            1 => world.usb.set_permissions(403, serde_json::Value::Null),
            _ => world.usb.hide_guest(fake_pve::FIRST_LAB_VMID - 1),
        }

        let error = controller.attach(&machine, READER_A).await.unwrap_err();

        assert_eq!(
            refused_reason(&error),
            "hardware_guests_unverifiable",
            "{label}"
        );
        let detail = refused_detail(&error);
        assert!(detail.contains("VM.Audit on /vms"), "{label}: {detail}");
        assert!(detail.contains("try again"), "{label}: {detail}");
        assert!(world.usb.writes().is_empty(), "{label}");
        // The reservation taken before the verify is released again.
        assert_eq!(controller.live().await, 0, "{label}");
    }
}

#[tokio::test]
async fn a_machine_attach_is_refused_up_front_once_a_refresh_recorded_the_gap() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    world.usb.set_permissions(
        200,
        permissions_with(serde_json::json!({"/vms": {"VM.Config.HWType": 1}})),
    );
    controller.refresh_inventory().await;
    assert_eq!(
        controller.status(READER_A).await,
        DeviceStatus::Unsupported(fleet_core::UnsupportedReason::UsbInventoryUnreadable)
    );

    let error = controller.attach(&machine, READER_A).await.unwrap_err();

    assert_eq!(refused_reason(&error), "hardware_unsupported");
    assert_nothing_changed(&world, &controller).await;
}

#[tokio::test]
async fn a_machine_attach_with_no_evidence_of_a_hidden_guest_goes_through() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    world.usb.set_permissions(
        200,
        permissions_with(serde_json::json!({"/vms": {"VM.Audit": 1, "VM.Config.HWType": 1}})),
    );
    let outcome = controller.attach(&machine, READER_A).await.unwrap();
    assert_eq!(outcome.result, HotplugResult::Attached);
}

#[tokio::test]
async fn a_device_another_owner_holds_is_busy_and_nothing_queues() {
    let (world, controller) = ready_controller().await;
    let first = controller.persistent("persist-a", GUEST_A).await;
    let second = controller.persistent("persist-b", GUEST_B).await;

    // A lease holds it.
    controller.lease_holds(READER_A, "lease-1", "ready").await;
    let error = controller.attach(&first, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "hardware_busy");
    assert!(
        refused_detail(&error).contains("lease lease-1"),
        "{error:?}"
    );
    assert!(world.usb.writes().is_empty());
    // The other device is free.
    controller.attach(&first, READER_B).await.unwrap();

    // Another machine holds it.
    let error = controller.attach(&second, READER_B).await.unwrap_err();
    assert_eq!(refused_reason(&error), "hardware_busy");
    assert!(refused_detail(&error).contains(&first), "{error:?}");
    assert_eq!(world.usb.writes().len(), 1, "only the first attach wrote");

    // Not queued: once the holder gives it up the request is made again.
    controller.detach(&first, READER_B).await.unwrap();
    controller.attach(&second, READER_B).await.unwrap();
    assert!(world.usb.double_assignments().is_empty());
}

#[tokio::test]
async fn a_device_taken_between_the_review_and_the_attach_is_busy() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    let review = controller
        .review_attach_as(&AllowAll, PRINCIPAL, &machine, READER_A)
        .await
        .unwrap();
    controller.lease_holds(READER_A, "lease-1", "ready").await;

    let error = controller
        .usb_case
        .attach(
            &AllowAll,
            &principal(PRINCIPAL),
            &machine,
            READER_A,
            &review.review_token,
        )
        .await
        .unwrap_err();

    assert_eq!(refused_reason(&error), "hardware_busy");
    assert!(world.usb.writes().is_empty());
    assert_eq!(controller.live().await, 1, "the lease still holds it alone");
}

#[tokio::test]
async fn an_entry_an_operator_attached_elsewhere_makes_the_device_unavailable() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    // An operator attached it to a guest of their own.
    world.usb.operator_attach(GUEST_C, 0, &entry(READER_A));
    let writes = world.usb.writes();
    controller.refresh_inventory().await;
    assert_eq!(
        controller.status(READER_A).await,
        DeviceStatus::ExternallyAttached
    );

    let error = controller.attach(&machine, READER_A).await.unwrap_err();

    assert_eq!(refused_reason(&error), "hardware_externally_attached");
    assert_eq!(world.usb.writes(), writes, "Fleet wrote nothing");
    assert_eq!(world.usb.stored(GUEST_C), stored(&[(0, READER_A)]));
    assert_eq!(controller.live().await, 0);
}

// ---------------------------------------------------------------------
// A slot Fleet did not write is never touched.
// ---------------------------------------------------------------------

#[tokio::test]
async fn an_identical_entry_on_the_machines_own_guest_is_never_adopted_or_deleted() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    // The operator already attached it to this very guest, by hand.
    world.usb.operator_attach(GUEST_A, 1, &entry(READER_A));
    let writes = world.usb.writes();
    controller.refresh_inventory().await;

    let error = controller.attach(&machine, READER_A).await.unwrap_err();

    assert_eq!(refused_reason(&error), "hardware_externally_attached");
    assert_eq!(world.usb.writes(), writes);
    assert_eq!(world.usb.stored(GUEST_A), stored(&[(1, READER_A)]));
    assert_eq!(controller.live().await, 0, "{:?}", controller.rows().await);
}

#[tokio::test]
async fn the_detach_deletes_only_the_entry_fleet_wrote_and_leaves_the_operators() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    // The operator's own device sits in usb0, so Fleet's lands in usb1.
    world.usb.set_slot(GUEST_A, 0, "host=1-9");
    controller.refresh_inventory().await;

    let attached = controller.attach(&machine, READER_A).await.unwrap();
    assert_eq!(attached.usb_slot, Some(1));
    controller.detach(&machine, READER_A).await.unwrap();

    assert_eq!(
        world.usb.writes(),
        vec![
            "attach usb1=mapping=fm-test-reader-a".to_owned(),
            "detach usb1".to_owned()
        ]
    );
    let left: BTreeMap<u8, String> = [(0, "host=1-9".to_owned())].into();
    assert_eq!(world.usb.stored(GUEST_A), left, "the operator's slot stays");
}

#[tokio::test]
async fn an_entry_rewritten_by_an_operator_is_never_deleted_and_the_machine_keeps_the_device() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    controller.attach(&machine, READER_A).await.unwrap();
    // The operator rewrote the slot Fleet wrote (extra options).
    let rewritten = "mapping=fm-test-reader-a,usb3=1";
    world.usb.set_slot(GUEST_A, 0, rewritten);
    let writes = world.usb.writes();

    let error = controller.detach(&machine, READER_A).await.unwrap_err();

    assert_eq!(refused_reason(&error), "hardware_detach_failed");
    assert_eq!(world.usb.writes(), writes, "nothing was deleted");
    let kept: BTreeMap<u8, String> = [(0, rewritten.to_owned())].into();
    assert_eq!(world.usb.stored(GUEST_A), kept);
    // Never released on a guess: the machine still holds it.
    assert_eq!(controller.states().await, vec!["detach_failed"]);
    assert_eq!(controller.live().await, 1);
}

// ---------------------------------------------------------------------
// Failure compensation and the audit rule.
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_refused_write_gives_the_device_back() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    world.usb.inject(UsbStep::Attach, UsbFault::Forbidden, 1);

    let error = controller.attach(&machine, READER_A).await.unwrap_err();

    assert_eq!(refused_reason(&error), "hardware_attach_failed");
    assert!(world.usb.writes().is_empty());
    assert_eq!(controller.live().await, 0, "{:?}", controller.rows().await);
    assert_eq!(controller.states().await, vec!["released"]);
    // The next attempt works.
    controller.attach(&machine, READER_A).await.unwrap();
}

#[tokio::test]
async fn a_refusing_audit_sink_blocks_the_write_and_the_delete() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;

    // No attach intent, no write; and the reservation is not left behind.
    *world.refuse_event.lock().unwrap() = Some("hardware_attach_requested".to_owned());
    let error = controller.attach(&machine, READER_A).await.unwrap_err();
    assert!(matches!(error, HotplugError::Backend { .. }), "{error:?}");
    assert!(world.usb.writes().is_empty());
    assert!(world.usb.stored(GUEST_A).is_empty());
    assert_eq!(controller.live().await, 0, "{:?}", controller.rows().await);
    assert_eq!(
        controller.audit_events("hardware_attach_requested").await,
        0
    );

    // With the sink back the attach is made and audited first.
    *world.refuse_event.lock().unwrap() = None;
    controller.attach(&machine, READER_A).await.unwrap();
    assert_eq!(
        controller.audit_events("hardware_attach_requested").await,
        1
    );

    // No detach intent, no delete: the device stays on the guest, reserved.
    *world.refuse_event.lock().unwrap() = Some("hardware_detach_requested".to_owned());
    let error = controller.detach(&machine, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "hardware_detach_failed");
    assert_eq!(world.usb.writes().len(), 1, "no delete was made");
    assert_eq!(world.usb.stored(GUEST_A), stored(&[(0, READER_A)]));
    // (the first, refused attach left a released row behind it)
    assert_eq!(controller.states().await, vec!["released", "detach_failed"]);
    assert_eq!(
        controller.audit_events("hardware_detach_requested").await,
        0
    );

    // With the sink back the retry deletes, audits the intent and releases.
    *world.refuse_event.lock().unwrap() = None;
    let done = controller.detach(&machine, READER_A).await.unwrap();
    assert_eq!(done.result, HotplugResult::Detached);
    assert_eq!(
        controller.audit_events("hardware_detach_requested").await,
        1
    );
    assert_eq!(controller.states().await, vec!["released", "released"]);
}

// ---------------------------------------------------------------------
// Serialised requests.
// ---------------------------------------------------------------------

#[tokio::test]
async fn concurrent_attaches_of_one_device_write_once() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    let controller = Arc::new(controller);

    let mut tasks = Vec::new();
    for _ in 0..6 {
        let controller = controller.clone();
        let machine = machine.clone();
        tasks.push(tokio::spawn(async move {
            controller.attach(&machine, READER_A).await
        }));
    }
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap().expect("every request succeeds"));
    }

    // One request attached it; the others found it attached.
    let attached = results
        .iter()
        .filter(|outcome| outcome.result == HotplugResult::Attached)
        .count();
    let already = results
        .iter()
        .filter(|outcome| outcome.result == HotplugResult::AlreadyAttached)
        .count();
    assert_eq!((attached, already), (1, 5), "{results:?}");
    assert_eq!(world.usb.writes().len(), 1);
    assert_eq!(controller.states().await, vec!["attached"]);
    assert!(world.usb.double_assignments().is_empty());
}

#[tokio::test]
async fn two_machines_racing_for_one_device_get_it_once() {
    let (world, controller) = ready_controller().await;
    let first = controller.persistent("persist-a", GUEST_A).await;
    let second = controller.persistent("persist-b", GUEST_B).await;
    let controller = Arc::new(controller);

    let mut tasks = Vec::new();
    for machine in [first.clone(), second.clone()] {
        let controller = controller.clone();
        tasks.push(tokio::spawn(async move {
            controller.attach(&machine, READER_A).await
        }));
    }
    let mut won = 0;
    let mut busy = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(outcome) => {
                assert_eq!(outcome.result, HotplugResult::Attached);
                won += 1;
            }
            Err(error) => {
                assert_eq!(refused_reason(&error), "hardware_busy", "{error:?}");
                busy += 1;
            }
        }
    }
    assert_eq!((won, busy), (1, 1));
    assert_eq!(world.usb.writes().len(), 1);
    assert_eq!(controller.live().await, 1);
    assert!(world.usb.double_assignments().is_empty());
}

#[tokio::test]
async fn interleaved_attaches_and_detaches_leave_the_row_and_the_guest_in_agreement() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    let controller = Arc::new(controller);

    let mut tasks = Vec::new();
    for round in 0..8 {
        let controller = controller.clone();
        let machine = machine.clone();
        tasks.push(tokio::spawn(async move {
            if round % 2 == 0 {
                let _ = controller.attach(&machine, READER_A).await;
            } else {
                let _ = controller.detach(&machine, READER_A).await;
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }

    // Whatever order they ran in, the guest and the row say the same thing.
    let states = controller.states().await;
    let on_guest = !world.usb.stored(GUEST_A).is_empty();
    let last = states.last().expect("at least one attach ran").as_str();
    assert_eq!(
        on_guest,
        last == "attached",
        "{states:?} {:?}",
        world.usb.log()
    );
    assert!(
        states
            .iter()
            .filter(|state| state.as_str() != "released")
            .count()
            <= 1,
        "at most one live row: {states:?}"
    );
    assert!(world.usb.double_assignments().is_empty());
}

// ---------------------------------------------------------------------
// A machine's device is not lost with the machine.
// ---------------------------------------------------------------------

fn later() -> i64 {
    now() + fleet_controller::hardware_reconciler::FRESH_ROW_MS * 2
}

#[tokio::test]
async fn a_device_stays_reserved_by_the_machine_until_it_is_explicitly_detached() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    controller.attach(&machine, READER_A).await.unwrap();

    // Nobody else gets it, and nothing releases it by itself: not a restart,
    // not a reconciler pass.
    controller.lease_attempt_is_busy(READER_A).await;
    let report = controller.reconciler.startup(later()).await;
    assert_eq!(report.released, 0, "{report:?}");
    if let Some(tick) = controller.reconciler.tick(later() + 3_600_000).await {
        assert_eq!(tick.released, 0, "{tick:?}");
    }
    assert_eq!(world.usb.writes().len(), 1, "the reconciler wrote nothing");
    assert_eq!(controller.states().await, vec!["attached"]);
    let controller = restart(&world, Arc::new(controller)).await;
    assert_eq!(controller.states().await, vec!["attached"]);
    let again = controller.attach(&machine, READER_A).await.unwrap();
    assert_eq!(again.result, HotplugResult::AlreadyAttached);
    assert_eq!(world.usb.writes().len(), 1);

    // Only the explicit detach gives it up.
    controller.detach(&machine, READER_A).await.unwrap();
    assert_eq!(controller.states().await, vec!["released"]);
}

#[tokio::test]
async fn deleting_the_machine_or_unregistering_its_marker_is_refused_while_it_holds_a_device() {
    let (_world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    controller.attach(&machine, READER_A).await.unwrap();
    let audit: Arc<dyn AuditPort> = Arc::new(AuditSink::new(controller.pool.clone()));
    let gate: Arc<dyn MachineHardwareGate> =
        Arc::new(StoreMachineHardwareGate::new(controller.hardware.clone()));
    // The plain use case over the machine repository: the repository itself
    // refuses to delete a machine that holds a device, so a construction that
    // wires nothing else still fails closed.
    let machines = Machines::new(controller.machines.clone(), audit.clone())
        .with_guest_links(controller.links.clone());

    // Delete: refused, with the instruction to detach first.
    let error = machines
        .delete(&AllowAll, &principal(PRINCIPAL), &machine)
        .await
        .unwrap_err();
    let text = error.to_string();
    assert!(
        matches!(
            error,
            fleet_application::machine::MachineUseCaseError::Conflict { .. }
        ),
        "{text}"
    );
    assert!(text.contains("machines usb detach"), "{text}");
    assert!(text.contains(READER_A), "{text}");
    controller
        .machines
        .get(&machine)
        .await
        .expect("still there");

    // Unregistering a registered marker: refused too, by guest and by
    // machine.
    let registered = controller.machine("registered").await;
    controller.link(&registered, GUEST_B, "qemu").await;
    controller
        .mark_as(
            Some(&registered),
            GUEST_B,
            "persist-b",
            "registered",
            PersistentState::Ready,
        )
        .await;
    controller.attach(&registered, READER_B).await.unwrap();
    let persistent = PersistentMachines::new(Arc::new(NoImages), audit)
        .with_markers(controller.markers.clone())
        .with_hardware_gate(gate);
    let error = persistent
        .review_unregister(
            &AllowAll,
            &principal(PRINCIPAL),
            &controller.account_id,
            GUEST_B,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("machines usb detach"), "{error}");
    let (_, token) = PersistentMachines::unregister_payload(&controller.account_id, GUEST_B);
    let error = persistent
        .unregister(
            &AllowAll,
            &principal(PRINCIPAL),
            &controller.account_id,
            GUEST_B,
            &token,
            None,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("machines usb detach"), "{error}");
    assert!(
        controller
            .markers
            .get(&controller.account_id, GUEST_B)
            .await
            .unwrap()
            .is_some(),
        "the marker is still there"
    );

    // Detached, both go through.
    controller.detach(&registered, READER_B).await.unwrap();
    persistent
        .unregister(
            &AllowAll,
            &principal(PRINCIPAL),
            &controller.account_id,
            GUEST_B,
            &token,
            None,
        )
        .await
        .unwrap();
    controller.detach(&machine, READER_A).await.unwrap();
    machines
        .delete(&AllowAll, &principal(PRINCIPAL), &machine)
        .await
        .unwrap();
}

#[derive(Debug)]
struct NoImages;

#[async_trait]
impl fleet_application::lab::ImagePinValidator for NoImages {
    async fn promoted_version(
        &self,
        _version_id: &str,
    ) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok(None)
    }
}

#[tokio::test]
async fn the_guest_cannot_be_destroyed_reverted_or_templated_while_the_machine_holds_a_device() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    controller.attach(&machine, READER_A).await.unwrap();
    let audit: Arc<dyn AuditPort> = Arc::new(AuditSink::new(controller.pool.clone()));
    let operations = Operations::new(
        Arc::new(OperationRepository::new(controller.pool.clone())),
        audit,
    );
    let accounts: Arc<dyn ProxmoxAccountPort> =
        Arc::new(ProxmoxAccountRepository::new(controller.pool.clone()));
    let credentials: Arc<dyn ProxmoxCredentialStore> = Arc::new(OneSecret);
    let destroyer = ProxmoxDestructiveExecutor::new(
        accounts,
        credentials,
        ProxmoxClient::new(world.usb.transport()),
    )
    .with_image_artifacts(Arc::new(Artifacts))
    .with_hardware_guard(controller.hardware.clone())
    .with_guest_locks(controller.guest_locks.clone());
    let run = |kind: &'static str| {
        let payload = serde_json::json!({
            "accountId": controller.account_id,
            "node": TEMPLATE_NODE,
            "vmid": GUEST_A,
            "timeoutSeconds": 60,
            "params": {"snapshot": "baseline", "purge": true, "newId": 9200, "name": "copy"},
        })
        .to_string();
        let operations = &operations;
        let destroyer = &destroyer;
        async move {
            fleet_controller::lab_pool::run_reviewed_child(
                operations,
                destroyer,
                kind,
                payload,
                format!("review-{kind}-{}", now()),
                "machine-usb-test",
                std::time::Duration::from_secs(30),
            )
            .await
            .unwrap()
        }
    };
    for kind in [
        "proxmox.guest.destroy",
        "proxmox.guest.snapshot-revert",
        "proxmox.guest.template",
        "proxmox.guest.clone",
    ] {
        let child = run(kind).await;
        assert_eq!(child.state, "failed", "{kind}");
        let error: serde_json::Value =
            serde_json::from_str(child.error_json.as_deref().unwrap()).unwrap();
        assert_eq!(error["reason"], "hardware_attached", "{kind}");
        let detail = error["detail"].as_str().unwrap();
        assert!(detail.contains("machines usb detach"), "{detail}");
        assert!(detail.contains(&machine), "{detail}");
        assert!(detail.contains(READER_A), "{detail}");
    }
    assert!(world.pve.lab_guests().contains_key(&GUEST_A));
    assert_eq!(world.usb.count(|line| line.contains("/status/stop")), 0);
    assert_eq!(world.usb.count(|line| line.starts_with("Delete ")), 0);
    assert_eq!(world.usb.stored(GUEST_A), stored(&[(0, READER_A)]));

    // The API's early refusal sees the same hold, in any state.
    let gate = StoreMachineHardwareGate::new(controller.hardware.clone());
    let holds = gate
        .holds_on_guest(&controller.account_id, GUEST_A)
        .await
        .unwrap();
    assert_eq!(holds.len(), 1);
    assert!(
        holds[0]
            .refusal("destroy the guest")
            .contains("detach it first")
    );
    assert!(
        gate.holds_on_guest(&controller.account_id, GUEST_B)
            .await
            .unwrap()
            .is_empty()
    );

    // After the detach the destroy goes through.
    controller.detach(&machine, READER_A).await.unwrap();
    let child = run("proxmox.guest.destroy").await;
    assert_eq!(child.state, "succeeded", "{:?}", child.error_json);
    assert!(!world.pve.lab_guests().contains_key(&GUEST_A));
}

// ---------------------------------------------------------------------
// Restart and resume at each step.
// ---------------------------------------------------------------------

/// A crashed controller: the database closes, the host keeps whatever the
/// interrupted step left.
async fn restart(world: &World, old: Arc<Controller>) -> Arc<Controller> {
    old.pool.close().await;
    drop(old);
    Arc::new(Controller::start(world).await)
}

async fn crash_attach(
    world: &World,
    controller: &Arc<Controller>,
    machine: &str,
    step: UsbStep,
    fault: UsbFault,
) {
    world.usb.inject(step, fault, 1);
    let task = controller.clone();
    let machine = machine.to_owned();
    let run = controller
        .run(world, async move { task.attach(&machine, READER_A).await })
        .await;
    assert_eq!(run, Run::Crashed);
    world.usb.clear();
}

/// The controller dies right after the reservation, when the attach looks up
/// the guest's node (the review and the execute call each list the cluster
/// once before it). Nothing is recorded on a guest yet.
async fn crash_after_the_reservation(world: &World, controller: &Arc<Controller>, machine: &str) {
    let pass: usb_pve::Hook = Arc::new(|| Box::pin(async {}));
    world
        .usb
        .inject(UsbStep::Resources, UsbFault::Hook(pass), 2);
    crash_attach(
        world,
        controller,
        machine,
        UsbStep::Resources,
        UsbFault::CrashBefore,
    )
    .await;
}

#[tokio::test]
async fn a_crash_after_the_reservation_resumes_the_held_row_on_the_next_attach() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    let controller = Arc::new(controller);
    // Dies at the re-observation: reserved, nothing recorded on a guest.
    crash_after_the_reservation(&world, &controller, &machine).await;
    assert_eq!(controller.states().await, vec!["held"]);
    assert!(world.usb.writes().is_empty());

    let controller = restart(&world, controller).await;
    // The reconciler leaves a live machine's hold alone.
    let report = controller.reconciler.startup(later()).await;
    assert_eq!(report.released, 0, "{report:?}");
    assert_eq!(controller.states().await, vec!["held"]);
    // The same attach resumes the same row.
    let outcome = controller.attach(&machine, READER_A).await.unwrap();
    assert_eq!(outcome.result, HotplugResult::Attached);
    assert_eq!(controller.states().await, vec!["attached"]);
    assert_eq!(world.usb.writes().len(), 1);
}

#[tokio::test]
async fn a_crash_after_the_reservation_is_given_back_by_the_detach() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    let controller = Arc::new(controller);
    crash_after_the_reservation(&world, &controller, &machine).await;
    let controller = restart(&world, controller).await;

    // A held row records no guest: the detach releases it.
    let outcome = controller.detach(&machine, READER_A).await.unwrap();
    assert_eq!(outcome.result, HotplugResult::AlreadyDetached);
    assert!(outcome.released);
    assert_eq!(controller.states().await, vec!["released"]);
    assert!(world.usb.writes().is_empty());
}

#[tokio::test]
async fn a_crash_before_the_write_is_resolved_by_a_detach_that_reads_the_guest() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    let controller = Arc::new(controller);
    crash_attach(
        &world,
        &controller,
        &machine,
        UsbStep::Attach,
        UsbFault::CrashBefore,
    )
    .await;
    assert_eq!(
        controller.rows().await,
        vec![(
            "attaching".to_owned(),
            Some(0),
            Some(i64::from(GUEST_A)),
            format!("machine:{machine}")
        )]
    );
    assert!(world.usb.writes().is_empty());
    let controller = restart(&world, controller).await;

    // An attach does not guess whether the write happened.
    let error = controller.attach(&machine, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "hardware_in_progress");
    assert!(world.usb.writes().is_empty());
    // The detach reads the guest: nothing is on it, so the row is released
    // without a delete.
    let outcome = controller.detach(&machine, READER_A).await.unwrap();
    assert_eq!(outcome.result, HotplugResult::Detached);
    assert_eq!(controller.states().await, vec!["released"]);
    assert!(world.usb.writes().is_empty());
    // And the device attaches afresh.
    controller.attach(&machine, READER_A).await.unwrap();
    assert_eq!(world.usb.writes().len(), 1);
}

#[tokio::test]
async fn a_crash_after_the_write_never_deletes_an_entry_it_cannot_prove_it_wrote() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    let controller = Arc::new(controller);
    // The write landed and the controller died before it recorded it.
    crash_attach(
        &world,
        &controller,
        &machine,
        UsbStep::Attach,
        UsbFault::CrashAfter,
    )
    .await;
    assert_eq!(world.usb.stored(GUEST_A), stored(&[(0, READER_A)]));
    let controller = restart(&world, controller).await;

    // The row only recorded the attach before the write, so it proves nothing
    // about the entry: it is not adopted and not deleted.
    let error = controller.detach(&machine, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "hardware_detach_failed");
    assert_eq!(
        controller.rows().await,
        vec![(
            "attach_unknown".to_owned(),
            None,
            Some(i64::from(GUEST_A)),
            format!("machine:{machine}")
        )]
    );
    assert_eq!(world.usb.writes().len(), 1, "only the attach was written");
    assert_eq!(world.usb.stored(GUEST_A), stored(&[(0, READER_A)]));
    // Nothing resolves it by itself: not an attach, not a detach, not the
    // reconciler (the machine is alive).
    let error = controller.attach(&machine, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "hardware_attach_unknown");
    let error = controller.detach(&machine, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "hardware_attach_unknown");
    let report = controller.reconciler.startup(later()).await;
    assert_eq!(report.released, 0, "{report:?}");
    assert_eq!(world.usb.writes().len(), 1);

    // An operator who read the guest removes the entry and frees the row
    // with the elevated override; the device is usable again.
    world.usb.clear_slot(GUEST_A, 0);
    let id: String = sqlx::query_scalar("SELECT id FROM hardware_reservations")
        .fetch_one(&controller.pool)
        .await
        .unwrap();
    controller
        .reservations
        .override_release(
            &AuditContext {
                actor: PRINCIPAL.to_owned(),
                operation_id: None,
            },
            &id,
            now(),
        )
        .await
        .unwrap();
    controller.attach(&machine, READER_A).await.unwrap();
    assert_eq!(world.usb.stored(GUEST_A), stored(&[(0, READER_A)]));
}

#[tokio::test]
async fn an_attached_row_survives_a_restart_and_detaches() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    controller.attach(&machine, READER_A).await.unwrap();
    let controller = restart(&world, Arc::new(controller)).await;

    let again = controller.attach(&machine, READER_A).await.unwrap();
    assert_eq!(again.result, HotplugResult::AlreadyAttached);
    assert_eq!(again.usb_slot, Some(0));
    assert_eq!(world.usb.writes().len(), 1, "no second write");
    let done = controller.detach(&machine, READER_A).await.unwrap();
    assert_eq!(done.result, HotplugResult::Detached);
    assert_eq!(controller.states().await, vec!["released"]);
}

#[tokio::test]
async fn a_crash_at_the_detach_resumes_it() {
    for (fault, deletes_after_restart) in [(UsbFault::CrashBefore, 1), (UsbFault::CrashAfter, 0)] {
        let (world, controller) = ready_controller().await;
        let machine = controller.persistent("persist-a", GUEST_A).await;
        controller.attach(&machine, READER_A).await.unwrap();
        let controller = Arc::new(controller);
        world.usb.inject(UsbStep::Detach, fault.clone(), 1);
        let task = controller.clone();
        let target = machine.clone();
        let run = controller
            .run(&world, async move { task.detach(&target, READER_A).await })
            .await;
        assert_eq!(run, Run::Crashed, "{fault:?}");
        world.usb.clear();
        assert_eq!(controller.states().await, vec!["detaching"], "{fault:?}");
        let before = world.usb.writes().len();
        let controller = restart(&world, controller).await;

        let done = controller.detach(&machine, READER_A).await.unwrap();

        assert_eq!(done.result, HotplugResult::Detached, "{fault:?}");
        assert_eq!(controller.states().await, vec!["released"], "{fault:?}");
        assert_eq!(
            world.usb.writes().len() - before,
            deletes_after_restart,
            "{fault:?}"
        );
        assert!(world.usb.stored(GUEST_A).is_empty(), "{fault:?}");
    }
}

// ---------------------------------------------------------------------
// The reconciler and a machine that is gone.
// ---------------------------------------------------------------------

#[tokio::test]
async fn the_reconciler_leaves_a_live_machines_device_and_cleans_up_after_a_vanished_one() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    controller.attach(&machine, READER_A).await.unwrap();

    let live = controller.reconciler.startup(later()).await;
    assert_eq!(live.released, 0, "{live:?}");
    assert_eq!(controller.states().await, vec!["attached"]);
    assert_eq!(world.usb.writes().len(), 1);

    // The route refuses to delete a machine that holds a device; a row whose
    // machine was removed behind Fleet's back is the reconciler's: it detaches
    // the entry Fleet wrote and releases the row.
    sqlx::query("DELETE FROM machines WHERE id = ?1")
        .bind(&machine)
        .execute(&controller.pool)
        .await
        .unwrap();
    let gone = controller.reconciler.startup(later() + 60_000).await;
    assert_eq!(gone.released, 1, "{gone:?}");
    assert_eq!(controller.states().await, vec!["released"]);
    assert_eq!(
        world.usb.writes().last().map(String::as_str),
        Some("detach usb0")
    );
    assert!(world.usb.stored(GUEST_A).is_empty());
}

// ---------------------------------------------------------------------
// The production composition.
// ---------------------------------------------------------------------

#[tokio::test]
async fn the_controllers_own_composition_attaches_and_detaches() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    // The composition `main` makes: the same saga over the pool, the credential
    // store and the transport.
    let port = fleet_controller::machine_usb::compose(
        &controller.pool,
        Arc::new(OneSecret),
        world.usb.transport(),
        controller.machines.clone(),
        controller.guest_locks.clone(),
    );
    let accounts: Arc<dyn ProxmoxAccountPort> =
        Arc::new(ProxmoxAccountRepository::new(controller.pool.clone()));
    let guard = ProxmoxRegisterGuard::new(
        accounts,
        Arc::new(OneSecret),
        ProxmoxClient::new(world.usb.transport()),
        Arc::new(Artifacts),
    )
    .with_pool_members(Arc::new(fleet_application::operation::PoolMembership(
        Arc::new(LabPoolRepository::new(controller.pool.clone())),
    )));
    let case = MachineUsb::new(
        controller.machines.clone(),
        controller.links.clone(),
        controller.markers.clone(),
        Arc::new(guard),
        controller.hardware.clone(),
        Arc::new(port),
    );
    let me = principal(PRINCIPAL);
    let token = case
        .review_attach(&AllowAll, &me, &machine, READER_A)
        .await
        .unwrap()
        .review_token;
    let attached = case
        .attach(&AllowAll, &me, &machine, READER_A, &token)
        .await
        .unwrap();
    assert_eq!(attached.result, HotplugResult::Attached);
    let token = case
        .review_detach(&AllowAll, &me, &machine, READER_A)
        .await
        .unwrap()
        .review_token;
    let detached = case
        .detach(&AllowAll, &me, &machine, READER_A, &token)
        .await
        .unwrap();
    assert_eq!(detached.result, HotplugResult::Detached);
    assert_eq!(controller.states().await, vec!["released"]);
}

// ---------------------------------------------------------------------
// Review round: exclusion with destructive operations, the clone gate, the
// marker rule, accounts, state-aware messages and visible give-back failures.
// ---------------------------------------------------------------------

/// A destructive executor that shares the machine port's guest locks, as
/// `main` composes it.
fn destroyer_of(
    world: &World,
    controller: &Controller,
) -> (Arc<Operations>, Arc<ProxmoxDestructiveExecutor>) {
    let audit: Arc<dyn AuditPort> = Arc::new(AuditSink::new(controller.pool.clone()));
    let operations = Arc::new(Operations::new(
        Arc::new(OperationRepository::new(controller.pool.clone())),
        audit,
    ));
    let accounts: Arc<dyn ProxmoxAccountPort> =
        Arc::new(ProxmoxAccountRepository::new(controller.pool.clone()));
    let credentials: Arc<dyn ProxmoxCredentialStore> = Arc::new(OneSecret);
    let executor = Arc::new(
        ProxmoxDestructiveExecutor::new(
            accounts,
            credentials,
            ProxmoxClient::new(world.usb.transport()),
        )
        .with_image_artifacts(Arc::new(Artifacts))
        .with_hardware_guard(controller.hardware.clone())
        .with_guest_locks(controller.guest_locks.clone()),
    );
    (operations, executor)
}

/// Runs one reviewed destructive operation on `vmid` to its end.
async fn run_kind(
    operations: Arc<Operations>,
    executor: Arc<ProxmoxDestructiveExecutor>,
    account_id: String,
    kind: &'static str,
    vmid: u32,
) -> fleet_application::operation::Operation {
    let payload = serde_json::json!({
        "accountId": account_id,
        "node": TEMPLATE_NODE,
        "vmid": vmid,
        "timeoutSeconds": 60,
        "params": {"snapshot": "baseline", "purge": true, "newId": 9200, "name": "copy"},
    })
    .to_string();
    fleet_controller::lab_pool::run_reviewed_child(
        &operations,
        executor.as_ref(),
        kind,
        payload,
        format!("race-{kind}-{vmid}-{}", now()),
        "machine-usb-race",
        std::time::Duration::from_secs(30),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn an_attach_is_refused_while_a_destructive_operation_holds_the_guest() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    let held = controller
        .guest_locks
        .lock(&controller.account_id, GUEST_A)
        .await;

    let error = controller.attach(&machine, READER_A).await.unwrap_err();

    assert_eq!(refused_reason(&error), "hardware_guest_busy");
    assert!(world.usb.writes().is_empty());
    assert!(
        controller.rows().await.is_empty(),
        "nothing was reserved: the attach does not wait"
    );
    drop(held);
    controller.attach(&machine, READER_A).await.unwrap();
}

#[tokio::test]
async fn an_attach_during_a_destroy_or_clone_is_refused_and_the_operation_wins() {
    for kind in ["proxmox.guest.destroy", "proxmox.guest.clone"] {
        let (world, controller) = ready_controller().await;
        let machine = controller.persistent("persist-a", GUEST_A).await;
        let controller = Arc::new(controller);
        let (operations, executor) = destroyer_of(&world, &controller);
        // The operation is running (it listed the cluster, under the guest's
        // lock) when an attach for the same guest arrives.
        let seen: Arc<Mutex<Option<Result<MachineUsbOutcome, HotplugError>>>> = Arc::default();
        let hook: usb_pve::Hook = {
            let controller = controller.clone();
            let machine = machine.clone();
            let seen = seen.clone();
            Arc::new(move || {
                let controller = controller.clone();
                let machine = machine.clone();
                let seen = seen.clone();
                Box::pin(async move {
                    let result = controller.attach(&machine, READER_A).await;
                    *seen.lock().unwrap() = Some(result);
                })
            })
        };
        world
            .usb
            .inject(UsbStep::Resources, UsbFault::Hook(hook), 1);

        let child = run_kind(
            operations,
            executor,
            controller.account_id.clone(),
            kind,
            GUEST_A,
        )
        .await;

        assert_eq!(child.state, "succeeded", "{kind}: {:?}", child.error_json);
        let attach = seen.lock().unwrap().take().expect("the attach ran");
        assert_eq!(
            refused_reason(&attach.unwrap_err()),
            "hardware_guest_busy",
            "{kind}"
        );
        assert!(
            world.usb.writes().is_empty(),
            "{kind}: nothing was written into the guest"
        );
        assert!(controller.rows().await.is_empty(), "{kind}");
    }
}

#[tokio::test]
async fn a_destroy_or_revert_waits_for_an_attach_in_flight_and_then_refuses() {
    for kind in ["proxmox.guest.destroy", "proxmox.guest.snapshot-revert"] {
        let (world, controller) = ready_controller().await;
        let machine = controller.persistent("persist-a", GUEST_A).await;
        let (operations, executor) = destroyer_of(&world, &controller);
        let account = controller.account_id.clone();
        let started: Arc<Mutex<Option<tokio::task::JoinHandle<_>>>> = Arc::default();
        let finished_early = Arc::new(std::sync::atomic::AtomicBool::new(true));
        // The operation is queued while the attach is about to write. It
        // must not get past the lock (and so not finish) until the attach is
        // done, and then it sees the attached row.
        let hook: usb_pve::Hook = {
            let started = started.clone();
            let finished_early = finished_early.clone();
            Arc::new(move || {
                let started = started.clone();
                let finished_early = finished_early.clone();
                let operations = operations.clone();
                let executor = executor.clone();
                let account = account.clone();
                Box::pin(async move {
                    let handle =
                        tokio::spawn(run_kind(operations, executor, account, kind, GUEST_A));
                    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                    finished_early.store(handle.is_finished(), std::sync::atomic::Ordering::SeqCst);
                    *started.lock().unwrap() = Some(handle);
                })
            })
        };
        world.usb.inject(UsbStep::Attach, UsbFault::Hook(hook), 1);

        let attached = controller.attach(&machine, READER_A).await.unwrap();

        assert_eq!(attached.result, HotplugResult::Attached, "{kind}");
        let handle = started
            .lock()
            .unwrap()
            .take()
            .expect("the operation started");
        assert!(
            !finished_early.load(std::sync::atomic::Ordering::SeqCst),
            "{kind}: the operation went past the guest's lock while the attach was in flight"
        );
        let child = handle.await.unwrap();
        assert_eq!(child.state, "failed", "{kind}");
        let error: serde_json::Value =
            serde_json::from_str(child.error_json.as_deref().unwrap()).unwrap();
        assert_eq!(error["reason"], "hardware_attached", "{kind}");
        assert!(world.pve.lab_guests().contains_key(&GUEST_A), "{kind}");
        assert_eq!(world.usb.count(|line| line.starts_with("Delete ")), 0);
        assert_eq!(world.usb.stored(GUEST_A), stored(&[(0, READER_A)]));
        assert_eq!(controller.states().await, vec!["attached"], "{kind}");
    }
}

#[tokio::test]
async fn the_attach_vs_destroy_gate_is_refused_state_aware_and_agrees_with_the_api() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    controller.attach(&machine, READER_A).await.unwrap();
    let (operations, executor) = destroyer_of(&world, &controller);

    // An unknown outcome: the detach is refused too, so the message names the
    // elevated override, not "detach it first".
    sqlx::query("UPDATE hardware_reservations SET state = 'attach_unknown'")
        .execute(&controller.pool)
        .await
        .unwrap();
    let child = run_kind(
        operations.clone(),
        executor.clone(),
        controller.account_id.clone(),
        "proxmox.guest.destroy",
        GUEST_A,
    )
    .await;
    let error: serde_json::Value =
        serde_json::from_str(child.error_json.as_deref().unwrap()).unwrap();
    let detail = error["detail"].as_str().unwrap();
    assert!(detail.contains("override-release"), "{detail}");
    assert!(detail.contains("refused"), "{detail}");
    let gate = StoreMachineHardwareGate::new(controller.hardware.clone());
    let holds = gate
        .holds_on_guest(&controller.account_id, GUEST_A)
        .await
        .unwrap();
    assert!(
        holds[0]
            .refusal("destroy the guest")
            .contains("override-release")
    );

    // A failed detach is retried; a pending one waits for the restart.
    sqlx::query("UPDATE hardware_reservations SET state = 'detach_failed'")
        .execute(&controller.pool)
        .await
        .unwrap();
    let holds = gate
        .holds_on_guest(&controller.account_id, GUEST_A)
        .await
        .unwrap();
    let text = holds[0].refusal("destroy the guest");
    assert!(text.contains("machines usb detach"), "{text}");
    assert!(text.contains("override-release"), "{text}");

    // A row that holds nothing on the guest (`held`, even with the guest
    // recorded) blocks neither the API's gate nor the executor, so they agree.
    sqlx::query("UPDATE hardware_reservations SET state = 'held', usb_slot = NULL")
        .execute(&controller.pool)
        .await
        .unwrap();
    assert!(
        gate.holds_on_guest(&controller.account_id, GUEST_A)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        gate.holds_of_machine(&machine).await.unwrap().len(),
        1,
        "the machine itself still owns a live row"
    );
    let child = run_kind(
        operations,
        executor,
        controller.account_id.clone(),
        "proxmox.guest.destroy",
        GUEST_A,
    )
    .await;
    assert_eq!(child.state, "succeeded", "{:?}", child.error_json);
}

#[tokio::test]
async fn a_marker_that_names_no_machine_is_not_shown_to_be_this_machines_guest() {
    let (world, controller) = ready_controller().await;
    let machine = controller.machine("registered-box").await;
    controller.link(&machine, GUEST_A, "qemu").await;
    controller
        .mark_as(
            None,
            GUEST_A,
            "persist-a",
            "registered",
            PersistentState::Ready,
        )
        .await;

    let error = controller.attach(&machine, READER_A).await.unwrap_err();

    assert_eq!(refused_reason(&error), "machine_guest_mismatch");
    assert!(
        refused_detail(&error).contains("names no machine"),
        "{error:?}"
    );
    assert_nothing_changed(&world, &controller).await;
}

#[tokio::test]
async fn a_relinked_machine_cannot_attach_over_its_old_guest_and_a_detach_acts_on_the_recorded_one()
{
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    controller.attach(&machine, READER_A).await.unwrap();
    // The machine's marker and link move to another persistent guest. (The
    // routes cannot do this while a device is held; the records are changed
    // directly, as a repair or a bad edit would.)
    controller.relink(&machine, GUEST_D).await;
    sqlx::query("UPDATE persistent_guests SET vmid = ?1, name = 'persist-d' WHERE machine_id = ?2")
        .bind(i64::from(GUEST_D))
        .bind(&machine)
        .execute(&controller.pool)
        .await
        .unwrap();

    // The reservation records the old guest: an attach does not report it
    // attached to the new one.
    let error = controller.attach(&machine, READER_A).await.unwrap_err();
    assert_eq!(refused_reason(&error), "hardware_guest_mismatch");
    assert!(
        refused_detail(&error).contains("detach it first"),
        "{error:?}"
    );
    assert_eq!(world.usb.writes().len(), 1);

    // The detach acts on the recorded guest, whatever the link says now.
    let done = controller.detach(&machine, READER_A).await.unwrap();
    assert_eq!(done.result, HotplugResult::Detached);
    assert!(world.usb.stored(GUEST_A).is_empty());
    assert_eq!(
        world.usb.writes(),
        vec![
            "attach usb0=mapping=fm-test-reader-a".to_owned(),
            "detach usb0".to_owned()
        ]
    );
    // And the machine attaches to its new guest now.
    controller.attach(&machine, READER_A).await.unwrap();
    assert_eq!(world.usb.stored(GUEST_D), stored(&[(0, READER_A)]));
}

#[tokio::test]
async fn an_attach_while_a_detach_is_pending_is_refused_as_unconfirmed() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    world.start(GUEST_A).await;
    controller.attach(&machine, READER_A).await.unwrap();
    world.usb.set_hotplug_usb(GUEST_A, false);
    let pending = controller.detach(&machine, READER_A).await.unwrap();
    assert_eq!(pending.result, HotplugResult::DetachPending);
    let writes = world.usb.writes().len();

    let error = controller.attach(&machine, READER_A).await.unwrap_err();

    assert_eq!(refused_reason(&error), "hardware_detach_unconfirmed");
    assert_eq!(world.usb.writes().len(), writes);
    assert_eq!(controller.states().await, vec!["detaching"]);
}

#[tokio::test]
async fn a_mapping_id_is_looked_up_in_the_account_of_the_machines_guest() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    controller.attach(&machine, READER_A).await.unwrap();
    // A second Proxmox account has a device of the same mapping id; the
    // machine holds it too (a held row), and gets a guest link in that account.
    sqlx::query(
        "INSERT INTO proxmox_accounts (id, name, host, port, token_id, created_at) \
         VALUES ('acct-b', 'acct-b', 'pve-b.example.test', 8006, 'fleet@pve!lab', 1)",
    )
    .execute(&controller.pool)
    .await
    .unwrap();
    let device_b = controller
        .hardware
        .upsert_device(
            &fleet_application::hardware::DeviceObservation {
                id: "device-b".to_owned(),
                account_id: "acct-b".to_owned(),
                mapping_id: READER_A.to_owned(),
                kind: fleet_core::HardwareKind::Usb,
                entries: Vec::new(),
                status: DeviceStatus::Available,
                status_detail: None,
            },
            now(),
        )
        .await
        .unwrap();
    let in_b = controller
        .hardware
        .insert_reservation(
            &fleet_application::hardware::NewHardwareReservation {
                id: "reservation-b".to_owned(),
                device_id: device_b.id,
                owner_kind: ReservationOwnerKind::Machine,
                owner_id: machine.clone(),
                guest: None,
            },
            now(),
        )
        .await
        .unwrap();
    let mine = principal(PRINCIPAL);
    let review_for = |case: Arc<MachineUsb>, machine: String| async move {
        case.review_detach(&AllowAll, &principal(PRINCIPAL), &machine, READER_A)
            .await
    };
    let link_b = |controller: &Controller, machine: String| {
        let links = controller.links.clone();
        async move {
            links.unlink(&machine).await.unwrap();
            links
                .confirm(
                    &machine,
                    &GuestLink {
                        account_id: "acct-b".to_owned(),
                        guest_kind: "qemu".to_owned(),
                        node: TEMPLATE_NODE.to_owned(),
                        vmid: 9300,
                    },
                )
                .await
                .unwrap();
        }
    };

    // Linked in account A: A's attached reservation.
    let review = review_for(controller.usb_case.clone(), machine.clone())
        .await
        .unwrap();
    assert_eq!(review.reservation.unwrap().state, State::Attached);
    // Relinked into account B: B's reservation is the one meant.
    link_b(&controller, machine.clone()).await;
    let review = review_for(controller.usb_case.clone(), machine.clone())
        .await
        .unwrap();
    assert_eq!(review.reservation.unwrap().id, in_b.id);
    // B's released: the machine's only reservation of that id is A's, which
    // stays detachable from the relinked machine, acting on its own guest.
    controller
        .hardware
        .force_release_reservation(&in_b.id, now())
        .await
        .unwrap();
    let review = review_for(controller.usb_case.clone(), machine.clone())
        .await
        .unwrap();
    let reserved = review.reservation.expect("A's reservation");
    assert_eq!(reserved.state, State::Attached);
    assert_eq!(
        reserved.guest.map(|guest| (guest.account_id, guest.vmid)),
        Some((controller.account_id.clone(), GUEST_A))
    );
    // With no link at all and a reservation in each account the id is
    // ambiguous and refused.
    controller
        .hardware
        .insert_reservation(
            &fleet_application::hardware::NewHardwareReservation {
                id: "reservation-b2".to_owned(),
                device_id: "device-b".to_owned(),
                owner_kind: ReservationOwnerKind::Machine,
                owner_id: machine.clone(),
                guest: None,
            },
            now(),
        )
        .await
        .unwrap();
    controller.links.unlink(&machine).await.unwrap();
    let error = controller
        .usb_case
        .review_detach(&AllowAll, &mine, &machine, READER_A)
        .await
        .unwrap_err();
    assert_eq!(refused_reason(&error), "hardware_ambiguous");
    assert_eq!(world.usb.writes().len(), 1);
}

#[tokio::test]
async fn authorization_is_scoped_to_the_machine() {
    let (world, controller) = ready_controller().await;
    let first = controller.persistent("persist-a", GUEST_A).await;
    let second = controller.persistent("persist-b", GUEST_B).await;
    let only_first = Allow::only(&["machines.usb.attach", "machines.usb.detach"], &first);

    let error = controller
        .attach_as(&only_first, "alice", &second, READER_A)
        .await
        .unwrap_err();
    assert!(denied(&error), "{error:?}");
    assert!(world.usb.writes().is_empty());
    controller
        .attach_as(&only_first, "alice", &first, READER_A)
        .await
        .unwrap();
    let error = controller
        .detach_as(&only_first, "alice", &second, READER_A)
        .await
        .unwrap_err();
    assert!(denied(&error), "{error:?}");
    assert_eq!(controller.states().await, vec!["attached"]);
}

#[tokio::test]
async fn a_give_back_that_fails_is_reported_and_the_row_stays_visible() {
    let (world, controller) = ready_controller().await;
    let machine = controller.persistent("persist-a", GUEST_A).await;
    // The audit intent is refused (nothing is written) and the release of the
    // row the request made fails too.
    *world.refuse_event.lock().unwrap() = Some("hardware_attach_requested".to_owned());
    sqlx::query(
        "CREATE TRIGGER stop_release BEFORE UPDATE OF state ON hardware_reservations \
         WHEN NEW.state = 'released' BEGIN SELECT RAISE(ABORT, 'blocked'); END",
    )
    .execute(&controller.pool)
    .await
    .unwrap();

    let error = controller.attach(&machine, READER_A).await.unwrap_err();

    let HotplugError::Backend { detail } = &error else {
        panic!("expected the backend failure, got {error:?}");
    };
    assert!(detail.contains("could not be released"), "{detail}");
    assert!(detail.contains("machines usb detach"), "{detail}");
    assert!(world.usb.writes().is_empty());
    assert_eq!(controller.states().await, vec!["held"]);

    // The state is visible and the detach gives the device back.
    sqlx::query("DROP TRIGGER stop_release")
        .execute(&controller.pool)
        .await
        .unwrap();
    *world.refuse_event.lock().unwrap() = None;
    let done = controller.detach(&machine, READER_A).await.unwrap();
    assert!(done.released);
    assert_eq!(controller.states().await, vec!["released"]);
}
