//! A restartable Lab controller with hardware, for the failure-injection and
//! double-lease suite (FM-1130), and the one reusable invariant checker.
//!
//! [`Rig::start`] composes the production parts the way `main.rs` does: the
//! provision and cleanup executors with the hardware saga, placement, the
//! hardware reconciler, the hotplug use case and the override release, over a
//! [`Store`] opened on the world's one SQLite file and the shared
//! USB-aware Proxmox ([`UsbHost`] over [`FakePve`]). [`Rig::kill`] closes the
//! store, and a new `start` over the same file is the restarted controller:
//! nothing survives in memory.
//!
//! What this adds to the fault hooks the fake Proxmox already has:
//!
//! - [`Chaos`] kills the controller at a *ledger step*: before or after any
//!   reservation move (`held -> attaching`, `attaching -> attached`,
//!   `attached -> detaching`, ...), the reserve and the release commit, the
//!   readiness commit and the sweeper's expiry step. It decorates the
//!   production store ports, so the controller dies exactly between two
//!   durable steps. It can also take the hardware components' audit sink
//!   down.
//! - [`Rig::check`] is the invariant checker every scenario ends with:
//!   reservation rows against the fake guests' configs against lease states.
//!
//! Included with `#[path]` next to `fake_pve.rs` and `usb_pve.rs`: it is test
//! support, not a test. Every name, VMID and address is invented.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditOutcome};
use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision};
use fleet_application::hardware::{
    DeviceObservation, HardwareStore, HardwareStoreError, NewHardwareReservation,
};
use fleet_application::hardware_inventory::{DeviceFilter, HardwareInventory};
use fleet_application::hardware_override::{HardwareOverride, OverrideOutcome};
use fleet_application::hardware_reservation::{
    HardwareReservationPort, HardwareReservations, ReleaseOutcome, ReleasedReservation,
    ReserveOutcome, ReserveRequest,
};
use fleet_application::lab::{
    AttachProvisionOutcome, CloneTargetReservation, ImageArtifactPort, ImagePinValidator, Lab,
    LabReadinessPort, LabTemplatePort, LabTemplateVersion, LeasePort, NewLabTemplate, NewLease,
    NewProvision, ProvisionPort, ProvisionRecord, guest_owned,
};
use fleet_application::lab_hardware_hotplug::{
    HotplugAction, HotplugError, HotplugOutcome, HotplugPort as _, HotplugRequest,
    LabHardwareHotplug, LeaseGuestRef,
};
use fleet_application::lab_placement::HardwarePlacement;
use fleet_application::operation::{AuditPort, NewOperation, Operation, Operations};
use fleet_application::project::{NewProject, ProjectPort as _};
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccountPort, ProxmoxCredentialStore,
};
use fleet_application::worker::OperationExecutor;
use fleet_controller::hardware_reconciler::{
    HardwareReconciler, ReconcileReport, SqliteReconcilerRecords,
};
use fleet_controller::hardware_reservation_store::SqliteHardwareReservations;
use fleet_controller::lab_cleanup::LabCleanupExecutor;
use fleet_controller::lab_hardware::{LabHardwareSaga, SqliteFingerprintPins};
use fleet_controller::lab_hardware_hotplug::LabHotplug;
use fleet_controller::lab_sweeper::{LabSweeper, ProxmoxLabGuests, TickReport};
use fleet_controller::proxmox_exec::{
    LabDispatch, ProvisionExecutor, ProxmoxDestructiveExecutor, ProxmoxDispatch,
    ProxmoxLifecycleExecutor,
};
use fleet_core::{
    CleanupStrategy, DeviceStatus, GuestState, GuestTarget, HardwareDevice, HardwareKind,
    HardwareReservation, HardwareReservationState as State, LabHardware, LabTemplateContent, Lease,
    LeaseState, ReadinessProbe,
};
use fleet_provider_proxmox::ProxmoxClient;
use fleet_storage_sqlite::{
    AuditSink, HardwareRepository, LabRepository, LeaseRepository, MachineRepository,
    OperationRepository, ProjectRepository, ProxmoxAccountRepository, Store,
};

use crate::fake_pve::{
    API_HOST, FINGERPRINT, FIRST_LAB_VMID, FakePve, Faults, TEMPLATE_NODE, TEMPLATE_VMID,
};
use crate::usb_pve::UsbHost;

pub const PRINCIPAL: &str = fleet_auth::LAN_PRINCIPAL_ID;
pub const IMAGE_VERSION: &str = "image-version-1";
pub const TTL_SECONDS: u32 = 86_400;
pub const HOUR_MS: i64 = 3_600_000;
pub const LEASE_MS: i64 = fleet_controller::worker::LEASE_MS;
/// Two devices on the template's node, one port each.
pub const READER_A: &str = "fm-test-reader-a";
pub const READER_B: &str = "fm-test-reader-b";
/// The first VMID the fake host hands out.
pub const FIRST_VMID: u32 = FIRST_LAB_VMID;

pub fn now() -> i64 {
    fleet_core::SystemClock::now_unix_millis()
}

/// `mapping=<id>`: what Fleet writes into a slot.
pub fn entry(mapping: &str) -> String {
    format!("mapping={mapping}")
}

/// The stored view of a guest's `usbN` entries, for comparison.
pub fn stored(entries: &[(u8, &str)]) -> BTreeMap<u8, String> {
    entries
        .iter()
        .map(|(slot, mapping)| (*slot, entry(mapping)))
        .collect()
}

#[derive(Debug)]
pub struct AllowAll;

impl Authorizer for AllowAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

// ---------------------------------------------------------------------
// Chaos: kill the controller between two durable steps; take audit down.
// ---------------------------------------------------------------------

/// A durable step the controller can be killed at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Point {
    /// The reservation insert of placement (`HardwareReservationPort::reserve`).
    Reserve,
    /// A reservation move (`HardwareStore::transition_reservation`).
    Transition(State, State),
    /// A flow release (`HardwareReservationPort::release`).
    Release,
    /// The readiness transaction of the provision (`complete_ready`).
    Ready,
    /// The sweeper's expiry step (its first lease listing follows it).
    Expired,
}

/// Before the step commits, or after it committed (the answer is lost).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum When {
    Before,
    After,
}

/// The fault script of the controller-side steps, and the audit switch of the
/// hardware components. Shared by every controller the world starts.
pub struct Chaos {
    faults: Arc<Faults>,
    script: Mutex<Vec<(Point, When, u32)>>,
    /// While set, the hardware components' audit sink refuses everything
    /// (required intents and best-effort outcomes alike).
    pub audit_down: AtomicBool,
    /// While set, a VMID reservation that another record holds is granted
    /// anyway: the holder check an earlier controller had, which looked at no
    /// record that had left `provisioning` (#592). It rebuilds the databases
    /// that controller wrote.
    pub blind_vmid_holders: AtomicBool,
    refused_events: Mutex<Vec<String>>,
    hooks: Mutex<Vec<(Point, When, crate::usb_pve::Hook)>>,
    started: std::time::Instant,
    timeline: Mutex<Vec<String>>,
}

impl std::fmt::Debug for Chaos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chaos")
            .field("script", &self.script)
            .field("audit_down", &self.audit_down)
            .finish_non_exhaustive()
    }
}

impl Chaos {
    fn new(faults: Arc<Faults>) -> Self {
        Self {
            faults,
            script: Mutex::new(Vec::new()),
            audit_down: AtomicBool::new(false),
            blind_vmid_holders: AtomicBool::new(false),
            refused_events: Mutex::new(Vec::new()),
            hooks: Mutex::new(Vec::new()),
            started: std::time::Instant::now(),
            timeline: Mutex::new(Vec::new()),
        }
    }

    /// Runs `hook` once when the controller next reaches `point` (what
    /// another actor does in the window between two durable steps).
    pub fn run_at(&self, point: Point, when: When, hook: crate::usb_pve::Hook) {
        self.hooks.lock().unwrap().push((point, when, hook));
    }

    /// Records what the controller-side wrappers saw, in order, for the
    /// failure message of a race.
    fn note(&self, text: String) {
        let at = self.started.elapsed().as_micros();
        self.timeline
            .lock()
            .unwrap()
            .push(format!("{at:>9}us {text}"));
    }

    /// The notes so far.
    pub fn timeline(&self) -> Vec<String> {
        self.timeline.lock().unwrap().clone()
    }

    /// Kills the controller the next time it reaches `point`.
    pub fn crash_at(&self, point: Point, when: When) {
        self.script.lock().unwrap().push((point, when, 1));
    }

    /// Removes every scripted kill and brings the audit sink back.
    pub fn clear(&self) {
        self.script.lock().unwrap().clear();
        self.audit_down.store(false, Ordering::SeqCst);
        self.refused_events.lock().unwrap().clear();
    }

    /// The audit sink refuses (or accepts) everything the hardware
    /// components record.
    pub fn set_audit_down(&self, down: bool) {
        self.audit_down.store(down, Ordering::SeqCst);
    }

    /// The audit sink refuses the required intents of one event.
    pub fn refuse_event(&self, event: &str) {
        self.refused_events.lock().unwrap().push(event.to_owned());
    }

    fn take(&self, point: Point, when: When) -> bool {
        let mut script = self.script.lock().unwrap();
        let Some(index) = script
            .iter()
            .position(|(scripted, at, times)| *scripted == point && *at == when && *times > 0)
        else {
            return false;
        };
        script[index].2 -= 1;
        if script[index].2 == 0 {
            script.remove(index);
        }
        true
    }

    /// Dies here when `point` is scripted for `when`.
    async fn hit(&self, point: Point, when: When) {
        let hook = {
            let mut hooks = self.hooks.lock().unwrap();
            hooks
                .iter()
                .position(|(scripted, at, _)| *scripted == point && *at == when)
                .map(|index| hooks.remove(index).2)
        };
        if let Some(hook) = hook {
            hook().await;
        }
        if self.take(point, when) {
            self.faults.crash::<()>().await;
        }
    }
}

/// The audit sink of the hardware components: the real one, which `Chaos`
/// can take down.
#[derive(Debug)]
struct ChaosAudit {
    inner: AuditSink,
    chaos: Arc<Chaos>,
}

#[async_trait]
impl AuditPort for ChaosAudit {
    async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
        let refused = self.chaos.refused_events.lock().unwrap().clone();
        let refuses = self.chaos.audit_down.load(Ordering::SeqCst)
            || intent
                .metadata
                .entries()
                .any(|(key, value)| key == "event" && refused.iter().any(|event| event == value));
        if refuses {
            return Err("the audit sink is refusing".to_owned());
        }
        self.inner.record_intent(intent).await
    }

    async fn record_outcome(
        &self,
        operation_id: &str,
        outcome: AuditOutcome,
    ) -> Result<(), String> {
        if self.chaos.audit_down.load(Ordering::SeqCst) {
            return Err("the audit sink is refusing".to_owned());
        }
        self.inner.record_outcome(operation_id, outcome).await
    }
}

/// The hardware store, with kill points on the reservation moves.
#[derive(Debug)]
struct CrashingStore {
    inner: Arc<dyn HardwareStore>,
    chaos: Arc<Chaos>,
}

#[async_trait]
impl HardwareStore for CrashingStore {
    async fn upsert_device(
        &self,
        observation: &DeviceObservation,
        now: i64,
    ) -> Result<HardwareDevice, HardwareStoreError> {
        self.inner.upsert_device(observation, now).await
    }
    async fn device(&self, id: &str) -> Result<Option<HardwareDevice>, HardwareStoreError> {
        self.inner.device(id).await
    }
    async fn device_by_mapping(
        &self,
        account_id: &str,
        mapping_id: &str,
    ) -> Result<Option<HardwareDevice>, HardwareStoreError> {
        self.inner.device_by_mapping(account_id, mapping_id).await
    }
    async fn list_devices(
        &self,
        account_id: &str,
    ) -> Result<Vec<HardwareDevice>, HardwareStoreError> {
        self.inner.list_devices(account_id).await
    }
    async fn set_device_status(
        &self,
        id: &str,
        status: DeviceStatus,
        now: i64,
    ) -> Result<(), HardwareStoreError> {
        self.inner.set_device_status(id, status, now).await
    }
    async fn set_device_note(
        &self,
        id: &str,
        note: Option<&str>,
        now: i64,
    ) -> Result<(), HardwareStoreError> {
        self.inner.set_device_note(id, note, now).await
    }
    async fn insert_reservation(
        &self,
        reservation: &NewHardwareReservation,
        now: i64,
    ) -> Result<HardwareReservation, HardwareStoreError> {
        self.inner.insert_reservation(reservation, now).await
    }
    async fn reservation(
        &self,
        id: &str,
    ) -> Result<Option<HardwareReservation>, HardwareStoreError> {
        self.inner.reservation(id).await
    }
    async fn live_reservation_for_device(
        &self,
        device_id: &str,
    ) -> Result<Option<HardwareReservation>, HardwareStoreError> {
        self.inner.live_reservation_for_device(device_id).await
    }
    async fn live_reservations_for_owner(
        &self,
        owner_kind: fleet_core::ReservationOwnerKind,
        owner_id: &str,
    ) -> Result<Vec<HardwareReservation>, HardwareStoreError> {
        self.inner
            .live_reservations_for_owner(owner_kind, owner_id)
            .await
    }
    async fn list_live_reservations(&self) -> Result<Vec<HardwareReservation>, HardwareStoreError> {
        self.inner.list_live_reservations().await
    }
    async fn transition_reservation(
        &self,
        id: &str,
        from: State,
        to: State,
        guest: Option<&GuestTarget>,
        now: i64,
    ) -> Result<HardwareReservation, HardwareStoreError> {
        self.chaos
            .hit(Point::Transition(from, to), When::Before)
            .await;
        let moved = self
            .inner
            .transition_reservation(id, from, to, guest, now)
            .await;
        self.chaos.note(format!(
            "row {} {} -> {}: {}",
            &id[id.len().saturating_sub(4)..],
            from.id(),
            to.id(),
            moved
                .as_ref()
                .map_or_else(|error| error.to_string(), |_| "ok".to_owned())
        ));
        let moved = moved?;
        self.chaos
            .hit(Point::Transition(from, to), When::After)
            .await;
        Ok(moved)
    }
    async fn force_release_reservation(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HardwareReservation, HardwareStoreError> {
        self.inner.force_release_reservation(id, now).await
    }
}

/// The reservation port, with kill points on the reserve and the release.
#[derive(Debug)]
struct CrashingPort {
    inner: Arc<dyn HardwareReservationPort>,
    chaos: Arc<Chaos>,
}

#[async_trait]
impl HardwareReservationPort for CrashingPort {
    async fn reserve(
        &self,
        request: &ReserveRequest,
        now: i64,
    ) -> Result<ReserveOutcome, HardwareStoreError> {
        self.chaos.hit(Point::Reserve, When::Before).await;
        let outcome = self.inner.reserve(request, now).await?;
        self.chaos.hit(Point::Reserve, When::After).await;
        Ok(outcome)
    }
    async fn release(&self, id: &str, now: i64) -> Result<ReleaseOutcome, HardwareStoreError> {
        self.chaos.hit(Point::Release, When::Before).await;
        let outcome = self.inner.release(id, now).await;
        self.chaos.note(format!(
            "row {} release: {}",
            &id[id.len().saturating_sub(4)..],
            outcome
                .as_ref()
                .map_or_else(|error| error.to_string(), |_| "ok".to_owned())
        ));
        let outcome = outcome?;
        self.chaos.hit(Point::Release, When::After).await;
        Ok(outcome)
    }
    async fn override_release(
        &self,
        id: &str,
        now: i64,
    ) -> Result<ReleasedReservation, HardwareStoreError> {
        self.inner.override_release(id, now).await
    }
}

/// The provision store, with a kill point right after the readiness commit.
#[derive(Debug)]
struct Interruptible {
    inner: Arc<LabRepository>,
    chaos: Arc<Chaos>,
}

#[async_trait]
impl ProvisionPort for Interruptible {
    async fn create(&self, new: &NewProvision, now: i64) -> Result<ProvisionRecord, String> {
        ProvisionPort::create(self.inner.as_ref(), new, now).await
    }
    async fn find_by_idempotency_key(&self, key: &str) -> Result<Option<ProvisionRecord>, String> {
        self.inner.find_by_idempotency_key(key).await
    }
    async fn get(&self, id: &str) -> Result<ProvisionRecord, String> {
        ProvisionPort::get(self.inner.as_ref(), id).await
    }
    async fn update(&self, record: &ProvisionRecord) -> Result<(), String> {
        ProvisionPort::update(self.inner.as_ref(), record).await
    }
    async fn abandon(&self, id: &str) -> Result<Option<ProvisionRecord>, String> {
        self.inner.abandon(id).await
    }
    async fn complete_ready(
        &self,
        record: &ProvisionRecord,
        lease_expires_at: Option<i64>,
    ) -> Result<(), String> {
        self.chaos.hit(Point::Ready, When::Before).await;
        self.inner.complete_ready(record, lease_expires_at).await?;
        self.chaos.hit(Point::Ready, When::After).await;
        Ok(())
    }
    async fn ensure_guest_machine(
        &self,
        record_id: &str,
        reference: &str,
    ) -> Result<ProvisionRecord, String> {
        self.inner.ensure_guest_machine(record_id, reference).await
    }
    async fn find_by_machine_id(
        &self,
        machine_id: &str,
    ) -> Result<Option<ProvisionRecord>, String> {
        self.inner.find_by_machine_id(machine_id).await
    }
    async fn list(&self) -> Result<Vec<ProvisionRecord>, String> {
        ProvisionPort::list(self.inner.as_ref()).await
    }
    async fn reserve_clone_target(
        &self,
        record_id: &str,
        node: &str,
        vmid: u32,
    ) -> Result<CloneTargetReservation, String> {
        let outcome = self
            .inner
            .reserve_clone_target(record_id, node, vmid)
            .await?;
        if matches!(outcome, CloneTargetReservation::HeldBy { .. })
            && self.chaos.blind_vmid_holders.load(Ordering::SeqCst)
        {
            let mut record = ProvisionPort::get(self.inner.as_ref(), record_id).await?;
            record.node = Some(node.to_owned());
            record.vmid = Some(vmid);
            ProvisionPort::update(self.inner.as_ref(), &record).await?;
            return Ok(CloneTargetReservation::Reserved(record));
        }
        Ok(outcome)
    }
}

/// The sweeper's lease store, with a kill point right after the tick's
/// expiry step committed (its first listing follows the expiry).
#[derive(Debug)]
struct ExpiryLeases {
    inner: Arc<LeaseRepository>,
    chaos: Arc<Chaos>,
}

#[async_trait]
impl LeasePort for ExpiryLeases {
    async fn create(&self, lease: &NewLease, owner: &str, now: i64) -> Result<Lease, String> {
        self.inner.create(lease, owner, now).await
    }
    async fn get(&self, id: &str) -> Result<Lease, String> {
        let lease = self.inner.get(id).await;
        self.chaos.note(format!(
            "lease get: {}",
            lease
                .as_ref()
                .map_or_else(Clone::clone, |lease| lease.state.id().to_owned())
        ));
        lease
    }
    async fn update(&self, lease: &Lease) -> Result<(), String> {
        self.inner.update(lease).await
    }
    async fn list(&self, project_id: Option<&str>) -> Result<Vec<Lease>, String> {
        self.chaos.hit(Point::Expired, When::After).await;
        self.inner.list(project_id).await
    }
    async fn expired(&self, now: i64) -> Result<Vec<Lease>, String> {
        self.inner.expired(now).await
    }
    async fn extend_ready(
        &self,
        id: &str,
        observed_expires_at: i64,
        now: i64,
        new_expires_at: i64,
    ) -> Result<bool, String> {
        self.inner
            .extend_ready(id, observed_expires_at, now, new_expires_at)
            .await
    }
    async fn attach_provision(
        &self,
        id: &str,
        provision_id: &str,
    ) -> Result<AttachProvisionOutcome, String> {
        self.inner.attach_provision(id, provision_id).await
    }
    async fn claim_for_release(
        &self,
        id: &str,
        observed: LeaseState,
        observed_expires_at: i64,
        now: i64,
    ) -> Result<bool, String> {
        self.inner
            .claim_for_release(id, observed, observed_expires_at, now)
            .await
    }
    async fn transition(
        &self,
        id: &str,
        observed: LeaseState,
        provision_id: Option<&str>,
        to: LeaseState,
    ) -> Result<bool, String> {
        self.inner.transition(id, observed, provision_id, to).await
    }
    async fn rearm_cleanup(
        &self,
        id: &str,
        observed_attempts: u32,
        attempts: u32,
    ) -> Result<bool, String> {
        self.inner
            .rearm_cleanup(id, observed_attempts, attempts)
            .await
    }
    async fn record_failed_cleanup(
        &self,
        observed_attempts: u32,
        failed: &Lease,
    ) -> Result<bool, String> {
        self.inner
            .record_failed_cleanup(observed_attempts, failed)
            .await
    }
}

// ---------------------------------------------------------------------
// The scripted pieces a Lab needs that are not under test.
// ---------------------------------------------------------------------

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
        // Several workers may tick at once (the competing-lease scenarios),
        // and another worker's tick can claim the project child first: wait
        // for it instead of failing the claim.
        for _ in 0..500 {
            match operations
                .get_state(child_id)
                .await
                .map_err(|e| e.to_string())?
                .as_str()
            {
                "succeeded" => return Ok(true),
                "failed" | "cancelled" | "timed_out" => return Ok(false),
                "pending" => {
                    let _ = operations
                        .claim_only_execute(&Rest, child_id, "lab-ready")
                        .await;
                }
                _ => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }
        Ok(false)
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

// ---------------------------------------------------------------------
// The world and the controller.
// ---------------------------------------------------------------------

/// The world a controller runs in: one SQLite file and one Proxmox host that
/// outlive every controller.
pub struct World {
    _dir: tempfile::TempDir,
    pub database: PathBuf,
    pub faults: Arc<Faults>,
    pub pve: Arc<FakePve>,
    pub usb: Arc<UsbHost>,
    pub chaos: Arc<Chaos>,
    pub account_id: String,
    /// The first published template version (what [`World::new`] made).
    pub version_id: String,
    /// Every published template version and the mappings it declares.
    pub templates: BTreeMap<String, Vec<String>>,
    allowed_destroys: Mutex<BTreeSet<u32>>,
}

impl World {
    /// A world with one template declaring `hardware` (mapping ids).
    pub async fn new(hardware: &[&str]) -> Self {
        Self::with_templates(&[hardware]).await
    }

    /// A world with one published template per entry of `templates` (each a
    /// list of mapping ids). `version_id` is the first one's.
    pub async fn with_templates(templates: &[&[&str]]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("fleet.db");
        let faults = Arc::new(Faults::default());
        let pve = FakePve::new(faults.clone());
        let usb = UsbHost::new(pve.clone());
        usb.add_mapping(READER_A, &["node=pve-b,id=aaaa:0001,path=1-1"]);
        usb.add_mapping(READER_B, &["node=pve-b,id=bbbb:0002,path=1-2"]);
        let store = Store::open(&database).await.unwrap();
        let pool = store.pool().clone();
        let accounts = ProxmoxAccountRepository::new(pool.clone());
        let account = accounts
            .create(&NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: API_HOST.to_owned(),
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
        let mut published = BTreeMap::new();
        let mut first = None;
        for (index, hardware) in templates.iter().enumerate() {
            let content = LabTemplateContent {
                name: format!("lab-base-{index}"),
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
                readiness_deadline_seconds: 3,
                ttl_seconds: TTL_SECONDS,
                cleanup: CleanupStrategy::Destroy,
                audio: None,
                guest_os: fleet_core::GuestOs::default(),
                interactive_user: None,
                hardware: hardware
                    .iter()
                    .map(|mapping| LabHardware {
                        kind: HardwareKind::Usb,
                        mapping: (*mapping).to_owned(),
                    })
                    .collect(),
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
                        id: format!("template-version-{index}"),
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
            first.get_or_insert_with(|| version.id.clone());
            published.insert(
                version.id.clone(),
                hardware
                    .iter()
                    .map(|mapping| (*mapping).to_owned())
                    .collect(),
            );
        }
        pool.close().await;
        drop(store);
        Self {
            _dir: dir,
            database,
            chaos: Arc::new(Chaos::new(faults.clone())),
            faults,
            pve,
            usb,
            account_id: account.id,
            version_id: first.expect("at least one template"),
            templates: published,
            allowed_destroys: Mutex::new(BTreeSet::new()),
        }
    }

    /// The scenario expects `vmid` to be destroyed while it still holds a
    /// device: what the documented override release leads to (its lease's
    /// cleanup finds no live reservation, so it detaches nothing). Any other
    /// destroy of a guest that holds a device is a violation.
    pub fn allow_destroy_holding(&self, vmid: u32) {
        self.allowed_destroys.lock().unwrap().insert(vmid);
    }

    /// The version id of the `index`th template of [`World::with_templates`].
    pub fn version(&self, index: usize) -> String {
        let id = format!("template-version-{index}");
        assert!(self.templates.contains_key(&id), "a published template");
        id
    }
}

/// How a run of controller work ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Run<T> {
    Done(T),
    Crashed,
}

impl<T> Run<T> {
    /// The finished value; a crash is a test failure.
    pub fn done(self) -> T {
        match self {
            Self::Done(value) => value,
            Self::Crashed => panic!("the controller crashed where it should not have"),
        }
    }
}

/// One controller run over the world.
pub struct Rig {
    store: Store,
    pub pool: sqlx::SqlitePool,
    pub operations: Arc<Operations>,
    executor: Arc<dyn OperationExecutor>,
    sweeper: Arc<LabSweeper>,
    pub lab: Arc<Lab>,
    pub leases: Arc<LeaseRepository>,
    pub labs: Arc<LabRepository>,
    pub inventory: Arc<HardwareInventory>,
    pub saga: Arc<LabHardwareSaga>,
    pub reconciler: Arc<HardwareReconciler>,
    pub hotplug: Arc<LabHardwareHotplug>,
    port: Arc<LabHotplug>,
    pub overrides: Arc<HardwareOverride>,
    pub hardware: Arc<dyn HardwareStore>,
    pub account_id: String,
    pub version_id: String,
}

impl Rig {
    pub async fn start(world: &World) -> Self {
        let store = Store::open(&world.database)
            .await
            .expect("the previous controller released the database");
        let pool = store.pool().clone();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let leases = Arc::new(LeaseRepository::new(pool.clone()));
        let audit = Arc::new(AuditSink::new(pool.clone()));
        let hardware_audit: Arc<dyn AuditPort> = Arc::new(ChaosAudit {
            inner: AuditSink::new(pool.clone()),
            chaos: world.chaos.clone(),
        });
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            audit.clone(),
        ));
        let accounts: Arc<dyn ProxmoxAccountPort> =
            Arc::new(ProxmoxAccountRepository::new(pool.clone()));
        let credentials: Arc<dyn ProxmoxCredentialStore> = Arc::new(OneSecret);
        let client = ProxmoxClient::new(world.usb.transport());
        let plain_store: Arc<dyn HardwareStore> = Arc::new(HardwareRepository::new(pool.clone()));
        // The saga and the reconciler move rows through the crashing store;
        // inventory reads and the destroy guard use the plain one.
        let store_port: Arc<dyn HardwareStore> = Arc::new(CrashingStore {
            inner: plain_store.clone(),
            chaos: world.chaos.clone(),
        });
        let reservations = Arc::new(HardwareReservations::new(
            Arc::new(CrashingPort {
                inner: Arc::new(SqliteHardwareReservations::new(pool.clone())),
                chaos: world.chaos.clone(),
            }),
            hardware_audit.clone(),
        ));
        let placement = Arc::new(HardwarePlacement::new(
            plain_store.clone(),
            reservations.clone(),
            900_000,
        ));
        let inventory = Arc::new(HardwareInventory::new(
            accounts.clone(),
            credentials.clone(),
            plain_store.clone(),
            fleet_controller::hardware_observer::shared(client.clone()),
            hardware_audit.clone(),
        ));
        let saga = Arc::new(LabHardwareSaga::new(
            accounts.clone(),
            credentials.clone(),
            client.clone(),
            store_port.clone(),
            reservations.clone(),
            inventory.clone(),
            hardware_audit.clone(),
            Arc::new(ExpiryLeases {
                inner: leases.clone(),
                chaos: world.chaos.clone(),
            }),
            Arc::new(SqliteFingerprintPins::new(pool.clone())),
        ));
        let reconciler = Arc::new(HardwareReconciler::new(
            accounts.clone(),
            credentials.clone(),
            client.clone(),
            store_port.clone(),
            reservations.clone(),
            inventory.clone(),
            hardware_audit.clone(),
            Arc::new(SqliteReconcilerRecords::new(pool.clone())),
        ));
        let port = Arc::new(LabHotplug::new(saga.clone(), store_port.clone()));
        let hotplug = Arc::new(LabHardwareHotplug::new(
            leases.clone(),
            labs.clone(),
            port.clone(),
        ));
        let overrides = Arc::new(HardwareOverride::new(
            plain_store.clone(),
            reservations,
            hardware_audit,
        ));
        let destroyer = Arc::new(
            ProxmoxDestructiveExecutor::new(accounts.clone(), credentials.clone(), client.clone())
                .with_image_artifacts(Arc::new(Artifacts))
                .with_hardware_guard(plain_store.clone()),
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
                Arc::new(Interruptible {
                    inner: labs.clone(),
                    chaos: world.chaos.clone(),
                }),
                leases.clone(),
                labs.clone(),
                Arc::new(Artifacts),
                client.clone(),
            )
            .with_readiness(Arc::new(Readiness), audit.clone())
            .with_device_placement(placement)
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
                    destroyer,
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
                Arc::new(ExpiryLeases {
                    inner: leases.clone(),
                    chaos: world.chaos.clone(),
                }),
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
            saga,
            reconciler,
            hotplug,
            port,
            overrides,
            hardware: plain_store,
            account_id: world.account_id.clone(),
            version_id: world.version_id.clone(),
        }
    }

    /// The controller dies: the store and every connection close. Nothing in
    /// memory survives; the next [`Rig::start`] is the restarted controller.
    pub async fn kill(self) {
        self.pool.close().await;
        drop(self.store);
    }

    /// The restarted controller's worker maintenance once the dead run's
    /// claim lease ran out: its interrupted operations fail honestly.
    pub async fn recover(&self) -> usize {
        self.operations
            .maintain(now() + LEASE_MS + 1, LEASE_MS)
            .await
            .unwrap()
            .recovered
    }

    /// Runs `work` until it finishes or the controller reaches a crash
    /// point; a crash drops the work right there, as a dying process would.
    pub async fn run<T, F>(&self, world: &World, work: F) -> Run<T>
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
    pub async fn refresh_inventory(&self) {
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

    /// Requests a lease of the world's first template and queues its
    /// provision, as the API does.
    pub async fn request_lease(&self) -> String {
        self.request_lease_of(&self.version_id.clone()).await
    }

    /// The same, for a given published template version.
    pub async fn request_lease_of(&self, version_id: &str) -> String {
        let principal = ActingPrincipal {
            id: PRINCIPAL.to_owned(),
        };
        let lease = self
            .lab
            .create_lease(
                &AllowAll,
                &principal,
                NewLease {
                    template_version_id: version_id.to_owned(),
                    purpose: "hardware failure injection".to_owned(),
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

    /// Releases a lease the way the API does: it enters `releasing` and its
    /// cleanup is queued.
    pub async fn release(&self, lease_id: &str) {
        let principal = ActingPrincipal {
            id: PRINCIPAL.to_owned(),
        };
        let lease = self
            .lab
            .release_lease(&AllowAll, &principal, lease_id, false, now())
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

    /// `fleetctl lab cleanup-retry`: re-arms a `cleanup_failed` lease.
    pub async fn retry_cleanup(&self, lease_id: &str) {
        self.lab
            .retry_cleanup(
                &AllowAll,
                &ActingPrincipal {
                    id: PRINCIPAL.to_owned(),
                },
                lease_id,
            )
            .await
            .expect("cleanup-retry re-arms the lease");
    }

    /// `cleanup-retry`, when the lease ended `cleanup_failed`.
    pub async fn retry_cleanup_if_failed(&self, lease_id: &str) {
        if self.lease(lease_id).await.state == LeaseState::CleanupFailed {
            self.retry_cleanup(lease_id).await;
        }
    }

    /// Runs one claimed operation; answers whether one ran.
    pub async fn step(&self, world: &World) -> Run<bool> {
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
    pub async fn drain(&self, world: &World) -> Run<usize> {
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

    /// A hook that ends the lease the way the holder or the sweeper does and
    /// then lets the worker run its cleanup to completion, all inside whatever
    /// call it is scripted on.
    pub fn release_and_clean_hook(&self, lease_id: &str) -> crate::usb_pve::Hook {
        let lab = self.lab.clone();
        let operations = self.operations.clone();
        let executor = self.executor.clone();
        let lease_id = lease_id.to_owned();
        Arc::new(move || {
            let lab = lab.clone();
            let operations = operations.clone();
            let executor = executor.clone();
            let lease_id = lease_id.clone();
            Box::pin(async move {
                let lease = lab
                    .release_lease(
                        &AllowAll,
                        &ActingPrincipal {
                            id: PRINCIPAL.to_owned(),
                        },
                        &lease_id,
                        false,
                        now(),
                    )
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
                for _ in 0..50 {
                    let report = operations
                        .tick(executor.as_ref(), "hardware-suite-hook", now(), LEASE_MS)
                        .await
                        .unwrap();
                    if !report.claimed {
                        break;
                    }
                }
            })
        })
    }

    /// The holder's attach request straight through the hotplug port: a
    /// request whose lease check passed just before the lease was released
    /// (the use case would refuse it now).
    pub async fn raw_attach(
        &self,
        lease_id: &str,
        vmid: u32,
        mapping: &str,
    ) -> Result<HotplugOutcome, HotplugError> {
        self.port
            .carry_out(&HotplugRequest {
                principal_id: PRINCIPAL.to_owned(),
                lease_id: lease_id.to_owned(),
                mapping_id: mapping.to_owned(),
                guest: LeaseGuestRef {
                    account_id: self.account_id.clone(),
                    node: TEMPLATE_NODE.to_owned(),
                    vmid,
                },
                action: HotplugAction::Attach,
            })
            .await
    }

    /// Two workers drain the queue at once (two claims run side by side).
    pub async fn drain_concurrently(&self, workers: usize) -> usize {
        let mut tasks = Vec::new();
        for index in 0..workers {
            let operations = self.operations.clone();
            let executor = self.executor.clone();
            tasks.push(tokio::spawn(async move {
                for ran in 0..200 {
                    let report = operations
                        .tick(
                            executor.as_ref(),
                            &format!("hardware-suite-worker-{index}"),
                            now(),
                            LEASE_MS,
                        )
                        .await
                        .unwrap();
                    if !report.claimed {
                        // Another worker may still be running a claim whose
                        // child operations land after this look.
                        return ran;
                    }
                }
                panic!("the operation queue never drained");
            }));
        }
        let mut total = 0;
        for task in tasks {
            total += task.await.unwrap();
        }
        total
    }

    /// One sweeper tick at `at`, or until a crash point.
    pub async fn sweep(&self, world: &World, at: i64) -> Run<TickReport> {
        let sweeper = self.sweeper.clone();
        self.run(world, async move { sweeper.tick(at).await.unwrap() })
            .await
    }

    /// The reconciler's startup pass at `at` (what a restarted controller
    /// runs first), or until a crash point.
    pub async fn reconcile(&self, world: &World, at: i64) -> Run<ReconcileReport> {
        let reconciler = self.reconciler.clone();
        self.run(world, async move { reconciler.startup(at).await })
            .await
    }

    /// Lets the sweeper and the worker converge at `at`.
    pub async fn settle(&self, world: &World, at: i64) {
        for _ in 0..20 {
            let report = self.sweep(world, at).await.done();
            let ran = self.drain(world).await.done();
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

    /// Everything a restarted controller and its operator do to converge:
    /// the worker maintenance, then rounds of the reconciler's pass and the
    /// sweeper and worker, the clock moving on between rounds so every
    /// backoff elapses. Stops early when a round changes nothing. Starting
    /// from `at` (milliseconds), each round is 70 minutes later (backoffs
    /// cap at an hour, the lease TTL is a day).
    pub async fn converge(&self, world: &World, at: i64) {
        self.recover().await;
        for round in 0..8 {
            let at = at + round * 70 * 60_000;
            let report = self.reconcile(world, at).await.done();
            self.settle(world, at).await;
            let quiet = report.released == 0
                && report.entries_removed == 0
                && report.marked_unproven == 0
                && self.operations_pending().await == 0;
            if quiet && round > 0 {
                return;
            }
        }
    }

    async fn operations_pending(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM operations WHERE state IN ('pending', 'running')")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    pub async fn lease(&self, id: &str) -> Lease {
        self.leases.get(id).await.unwrap()
    }

    pub async fn record(&self, lease_id: &str) -> ProvisionRecord {
        let lease = self.lease(lease_id).await;
        ProvisionPort::get(self.labs.as_ref(), lease.provision_id.as_deref().unwrap())
            .await
            .unwrap()
    }

    /// The provision operation of a lease.
    pub async fn provision_operation(&self, lease_id: &str) -> Operation {
        self.operations
            .find_by_idempotency_key(&fleet_application::lab::lease_provision_operation_key(
                PRINCIPAL, lease_id,
            ))
            .await
            .unwrap()
            .expect("the provision operation exists")
    }

    /// The reason the provision operation failed with, or empty.
    pub async fn failure_reason(&self, lease_id: &str) -> String {
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

    /// Everything a failed scenario needs to be read: leases, rows, the
    /// operations and their errors, and the writes that landed.
    pub async fn dump(&self, world: &World) -> String {
        let leases = self.leases.list(None).await.unwrap();
        let operations: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT kind, state, error_json FROM operations ORDER BY created_at, id",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap();
        let events: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT action, json_extract(metadata_json, '$.event'), \
             json_extract(metadata_json, '$.outcome') \
             FROM audit_events WHERE metadata_json LIKE '%hardware%' ORDER BY seq",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        format!(
            "leases: {:#?}\nrows: {:#?}\noperations: {operations:#?}\naudit: {events:#?}\nwrites: {:#?}\ntimeline: {:#?}",
            leases
                .iter()
                .map(|lease| (&lease.id, lease.state, lease.cleanup_attempts))
                .collect::<Vec<_>>(),
            self.rows().await,
            world.usb.writes(),
            world.chaos.timeline()
        )
    }

    /// The raw error of the provision operation (for a failure message).
    pub async fn failure_detail(&self, lease_id: &str) -> String {
        let operation = self.provision_operation(lease_id).await;
        self.operations
            .get(&AllowAll, PRINCIPAL, &operation.id)
            .await
            .unwrap()
            .error_json
            .unwrap_or_default()
    }

    /// Every reservation row, oldest first.
    pub async fn rows(&self) -> Vec<Row> {
        let raw: Vec<RawRow> = sqlx::query_as(
            "SELECT r.id, r.device_id, d.mapping_id, r.owner_kind, r.owner_id, r.state, \
             r.guest_vmid, r.usb_slot \
             FROM hardware_reservations r JOIN hardware_devices d ON d.id = r.device_id \
             ORDER BY r.created_at, r.id",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap();
        raw.into_iter()
            .map(
                |(id, device_id, mapping, owner_kind, owner_id, state, vmid, slot)| Row {
                    id,
                    device_id,
                    mapping,
                    owner_kind,
                    owner_id,
                    state,
                    vmid: vmid.map(|vmid| u32::try_from(vmid).unwrap()),
                    slot: slot.map(|slot| u8::try_from(slot).unwrap()),
                },
            )
            .collect()
    }

    pub async fn live_rows(&self) -> Vec<Row> {
        self.rows()
            .await
            .into_iter()
            .filter(|row| row.state != "released")
            .collect()
    }

    /// The states of every row, oldest first.
    pub async fn states(&self) -> Vec<String> {
        self.rows().await.into_iter().map(|row| row.state).collect()
    }

    /// The live row of the mapping's device, when there is one.
    pub async fn live_row_of(&self, mapping: &str) -> Option<Row> {
        self.live_rows()
            .await
            .into_iter()
            .find(|row| row.mapping == mapping)
    }

    /// The status a reader sees for the mapping's device.
    pub async fn device_status(&self, mapping: &str) -> DeviceStatus {
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

    /// The number of audited intents (rows without an outcome) of an event.
    pub async fn audit_events(&self, event: &str) -> usize {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE outcome IS NULL AND metadata_json LIKE ?1",
        )
        .bind(format!("%\"{event}\"%"))
        .fetch_one(&self.pool)
        .await
        .unwrap();
        usize::try_from(count).unwrap()
    }

    /// A ready lease holding its devices, on a healthy host.
    pub async fn ready_lease(&self, world: &World) -> (String, u32) {
        self.refresh_inventory().await;
        let lease = self.request_lease().await;
        self.drain(world).await.done();
        let record = self.record(&lease).await;
        assert_eq!(
            self.lease(&lease).await.state,
            LeaseState::Ready,
            "{record:?}: {}",
            self.failure_reason(&lease).await
        );
        (lease, record.vmid.expect("the clone has a VMID"))
    }

    /// A mid-run hotplug detach request of the lease's holder.
    pub async fn hotplug_detach(
        &self,
        lease: &str,
        mapping: &str,
        release: bool,
    ) -> Result<HotplugOutcome, HotplugError> {
        self.hotplug
            .detach(
                &AllowAll,
                &ActingPrincipal {
                    id: PRINCIPAL.to_owned(),
                },
                lease,
                mapping,
                release,
                now(),
            )
            .await
    }

    /// A mid-run hotplug attach request of the lease's holder.
    pub async fn hotplug_attach(
        &self,
        lease: &str,
        mapping: &str,
    ) -> Result<HotplugOutcome, HotplugError> {
        self.hotplug
            .attach(
                &AllowAll,
                &ActingPrincipal {
                    id: PRINCIPAL.to_owned(),
                },
                lease,
                mapping,
                now(),
            )
            .await
    }

    /// The operator's override release of a reservation.
    pub async fn override_release(
        &self,
        reservation_id: &str,
    ) -> Result<OverrideOutcome, fleet_application::proxmox::ProxmoxUseCaseError> {
        self.overrides
            .release(
                &AllowAll,
                &ActingPrincipal {
                    id: PRINCIPAL.to_owned(),
                },
                None,
                reservation_id,
                true,
                now(),
            )
            .await
    }
}

/// A reservation row as SQLite returns it: id, device, mapping, owner kind,
/// owner, state, guest VMID and `usbN` slot.
type RawRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<i64>,
    Option<i64>,
);

/// One reservation row, as the checker and the scenarios read it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row {
    pub id: String,
    pub device_id: String,
    pub mapping: String,
    pub owner_kind: String,
    pub owner_id: String,
    pub state: String,
    pub vmid: Option<u32>,
    pub slot: Option<u8>,
}

// ---------------------------------------------------------------------
// The invariant checker.
// ---------------------------------------------------------------------

/// How much of the invariants to check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Level {
    /// What must hold at every instant, including a controller that was just
    /// killed mid-step: no device is reserved or referenced twice, no entry
    /// on a guest is unaccounted for, no released lease holds a row.
    Safety,
    /// Safety, plus what must hold once the controller, the sweeper, the
    /// worker and the reconciler have converged: every lease is in one of the
    /// allowed outcomes and every row agrees with its guest.
    Quiescent,
}

/// Entries an operator wrote on purpose (`vmid`, `usbN` slot): the checker
/// does not count them as Fleet's.
pub type Foreign<'a> = &'a [(u32, u8)];

/// One guest as the fake Proxmox shows it.
struct GuestView {
    name: String,
    running: bool,
    stored: BTreeMap<u8, String>,
    applied: BTreeMap<u8, String>,
}

impl GuestView {
    /// Every slot either view shows.
    fn slots(&self) -> BTreeMap<u8, String> {
        let mut slots = self.applied.clone();
        slots.extend(self.stored.clone());
        slots
    }
}

fn mapping_of(value: &str) -> Option<&str> {
    value
        .strip_prefix("mapping=")
        .map(|rest| rest.split(',').next().unwrap_or(rest))
}

impl Rig {
    /// Every violated invariant (empty when they all hold): reservation rows
    /// against the fake guests' configs against lease states.
    ///
    /// 1. **No device reserved twice.** At most one live row per device and
    ///    per (owner, mapping); no mapping referenced by two guests' configs
    ///    (or by two slots of one), in either the stored or the applied view,
    ///    except the entries an operator wrote on purpose; and the fake
    ///    host's own monitor saw no attach land on a mapping already
    ///    referenced.
    /// 2. **No released lease with a silently assigned device.** Every
    ///    reference to a mapping on any guest is accounted for by a live row
    ///    of that device recorded against that guest, or the device reads
    ///    `externally_attached` (visible to the operator); a released lease
    ///    holds no live row; no guest was destroyed while it held a device.
    /// 3. **Rows agree with guests.** A `held` row has no entry anywhere; an
    ///    `attached` row has exactly its entry in its recorded slot.
    /// 4. **Every mutation was audited first.** Attach writes never exceed
    ///    `hardware_attach_requested` intents; deletes never exceed the
    ///    detach and attach intents (a rollback is inside an attach).
    ///
    /// At [`Level::Quiescent`], also: every lease is in an allowed outcome
    /// (a ready lease owning a running guest with every declared device
    /// `attached` and entered; a released or failed lease with no guest, no
    /// live row and no entry; a `cleanup_failed` lease naming its guest), no
    /// lease is stuck mid-saga, every unresolved row's lease visibly owns it,
    /// no Fleet guest is unowned, and device statuses agree with the rows.
    #[allow(clippy::too_many_lines)]
    pub async fn check(&self, world: &World, level: Level, foreign: Foreign<'_>) -> Vec<String> {
        let rows = self.rows().await;
        let live: Vec<&Row> = rows.iter().filter(|row| row.state != "released").collect();
        let leases = self.leases.list(None).await.unwrap();
        let records: BTreeMap<String, ProvisionRecord> = ProvisionPort::list(self.labs.as_ref())
            .await
            .unwrap()
            .into_iter()
            .map(|record| (record.id.clone(), record))
            .collect();
        let guests: BTreeMap<u32, GuestView> = world
            .pve
            .lab_guests()
            .into_iter()
            .map(|(vmid, guest)| {
                (
                    vmid,
                    GuestView {
                        name: guest.name,
                        running: guest.running,
                        stored: world.usb.stored(vmid),
                        applied: world.usb.applied(vmid),
                    },
                )
            })
            .collect();
        let mut violations = Vec::new();

        // 1. No device reserved twice.
        let mut per_device: BTreeMap<&str, usize> = BTreeMap::new();
        let mut per_owner: BTreeMap<(&str, &str, &str), usize> = BTreeMap::new();
        for row in &live {
            *per_device.entry(&row.device_id).or_default() += 1;
            *per_owner
                .entry((&row.owner_kind, &row.owner_id, &row.mapping))
                .or_default() += 1;
        }
        for (device, count) in per_device {
            if count > 1 {
                violations.push(format!("device {device} has {count} live reservations"));
            }
        }
        for ((kind, owner, mapping), count) in per_owner {
            if count > 1 {
                violations.push(format!("{kind} {owner} holds {mapping} {count} times"));
            }
        }
        let mut references: BTreeMap<String, Vec<(u32, u8)>> = BTreeMap::new();
        for (vmid, guest) in &guests {
            for (slot, value) in guest.slots() {
                if foreign.contains(&(*vmid, slot)) {
                    continue;
                }
                if let Some(mapping) = mapping_of(&value) {
                    references
                        .entry(mapping.to_owned())
                        .or_default()
                        .push((*vmid, slot));
                }
            }
        }
        for (mapping, places) in &references {
            if places.len() > 1 {
                violations.push(format!(
                    "device {mapping} is on {} guest slots at once: {places:?}",
                    places.len()
                ));
            }
        }
        for doubled in world.usb.double_assignments() {
            violations.push(format!("a write assigned a device twice: {doubled}"));
        }

        // 2. No released lease with a silently assigned device.
        for (mapping, places) in &references {
            for (vmid, slot) in places {
                let accounted = live
                    .iter()
                    .any(|row| row.mapping == *mapping && row.vmid == Some(*vmid));
                if !accounted
                    && self.device_status(mapping).await != DeviceStatus::ExternallyAttached
                {
                    violations.push(format!(
                        "guest {vmid} usb{slot} holds {mapping} with no live reservation \
                         for it and the device not reading externally_attached"
                    ));
                }
            }
        }
        for row in &live {
            if row.owner_kind == "lease"
                && leases
                    .iter()
                    .find(|lease| lease.id == row.owner_id)
                    .is_none_or(|lease| lease.state == LeaseState::Released)
            {
                violations.push(format!(
                    "released lease {} still holds {} ({})",
                    row.owner_id, row.mapping, row.state
                ));
            }
        }
        let allowed = world.allowed_destroys.lock().unwrap().clone();
        for destroyed in world.usb.destroyed_holding() {
            let vmid = destroyed
                .split(':')
                .next()
                .and_then(|vmid| vmid.parse::<u32>().ok());
            if vmid.is_some_and(|vmid| allowed.contains(&vmid)) {
                continue;
            }
            violations.push(format!(
                "a guest was destroyed holding a device: {destroyed}"
            ));
        }

        // 3. Rows agree with guests.
        for row in &live {
            match row.state.as_str() {
                "held" => {
                    if let Some(places) = references.get(&row.mapping) {
                        violations.push(format!(
                            "{} is held (not attached) but referenced at {places:?}",
                            row.mapping
                        ));
                    }
                }
                "attached" => {
                    let present = row
                        .vmid
                        .zip(row.slot)
                        .and_then(|(vmid, slot)| guests.get(&vmid).map(|guest| (guest, slot)))
                        .is_some_and(|(guest, slot)| {
                            guest.stored.get(&slot).map(String::as_str)
                                == Some(entry(&row.mapping).as_str())
                        });
                    if !present {
                        violations.push(format!(
                            "{} is attached to guest {:?} usb{:?} in the row, but the guest \
                             does not hold exactly that entry",
                            row.mapping, row.vmid, row.slot
                        ));
                    }
                }
                _ => {}
            }
        }

        // 4. Every mutation audited first.
        let writes = world.usb.writes();
        let attach_writes = writes
            .iter()
            .filter(|write| write.starts_with("attach"))
            .count();
        let delete_writes = writes
            .iter()
            .filter(|write| write.starts_with("detach"))
            .count();
        let attach_intents = self.audit_events("hardware_attach_requested").await;
        let detach_intents = self.audit_events("hardware_detach_requested").await;
        if attach_writes > attach_intents {
            violations.push(format!(
                "{attach_writes} attach writes landed for {attach_intents} audited intents"
            ));
        }
        if delete_writes > detach_intents + attach_intents {
            violations.push(format!(
                "{delete_writes} deletes landed for {detach_intents} detach and \
                 {attach_intents} attach audited intents"
            ));
        }

        if level == Level::Safety {
            return violations;
        }

        // Quiescent: lease outcomes.
        let by_lease: BTreeMap<&str, &Lease> = leases
            .iter()
            .map(|lease| (lease.id.as_str(), lease))
            .collect();
        let named = |record: &ProvisionRecord| {
            guests
                .iter()
                .find(|(_, guest)| guest.name == format!("fm-lab-{}", record.id))
                .map(|(vmid, guest)| (*vmid, guest))
        };
        for lease in &leases {
            let record = lease.provision_id.as_ref().and_then(|id| records.get(id));
            let guest = record.and_then(named);
            let declared = world
                .templates
                .get(&lease.template_version_id)
                .cloned()
                .unwrap_or_default();
            let lease_rows: Vec<&&Row> = live
                .iter()
                .filter(|row| row.owner_kind == "lease" && row.owner_id == lease.id)
                .collect();
            match lease.state {
                LeaseState::Ready => {
                    let Some(record) = record else {
                        violations.push(format!("ready lease {} has no record", lease.id));
                        continue;
                    };
                    let owned = guest.is_some_and(|(vmid, guest)| {
                        Some(vmid) == record.vmid
                            && guest.running
                            && record.node.as_deref() == Some(TEMPLATE_NODE)
                    });
                    if record.state != GuestState::Ready || !owned {
                        violations.push(format!(
                            "ready lease {} does not own a running guest: {:?}",
                            lease.id, record.state
                        ));
                    }
                    for mapping in &declared {
                        let row = lease_rows.iter().find(|row| row.mapping == *mapping);
                        let valid = row.is_some_and(|row| {
                            row.state == "attached"
                                && row.vmid == record.vmid
                                && row.slot.is_some_and(|slot| {
                                    guest.is_some_and(|(_, guest)| {
                                        guest.applied.get(&slot).map(String::as_str)
                                            == Some(entry(mapping).as_str())
                                    })
                                })
                        });
                        if !valid {
                            violations.push(format!(
                                "ready lease {} does not hold {mapping} attached: {row:?}",
                                lease.id
                            ));
                        }
                    }
                    if lease_rows.len() != declared.len() {
                        violations.push(format!(
                            "ready lease {} declares {} devices and holds {} rows",
                            lease.id,
                            declared.len(),
                            lease_rows.len()
                        ));
                    }
                }
                LeaseState::Released | LeaseState::Failed => {
                    if !lease_rows.is_empty() {
                        violations.push(format!(
                            "{} lease {} still holds {:?}",
                            lease.state.id(),
                            lease.id,
                            lease_rows
                        ));
                    }
                    if lease.cleanup != CleanupStrategy::Keep
                        && let Some((vmid, _)) = guest
                    {
                        violations.push(format!(
                            "{} lease {} still has its guest {vmid}",
                            lease.state.id(),
                            lease.id
                        ));
                    }
                }
                LeaseState::CleanupFailed => {
                    let visible = record.is_some_and(|record| {
                        record.lease_id.as_deref() == Some(lease.id.as_str())
                            && record.vmid.is_some()
                            && record.node.is_some()
                            && record.account_id.is_some()
                    });
                    if !visible {
                        violations.push(format!(
                            "cleanup_failed lease {} does not name the guest it owns",
                            lease.id
                        ));
                    }
                }
                other => violations.push(format!(
                    "lease {} is stuck in {}: no allowed outcome",
                    lease.id,
                    other.id()
                )),
            }
        }
        // Rows left unresolved are visible, and their lease owns them.
        for row in &live {
            if !matches!(row.state.as_str(), "held" | "attached") {
                let lease = by_lease.get(row.owner_id.as_str());
                if lease.is_none_or(|lease| {
                    !matches!(
                        lease.state,
                        LeaseState::CleanupFailed | LeaseState::Releasing | LeaseState::Failed
                    )
                }) {
                    violations.push(format!(
                        "unresolved row {} ({}) of {} has no visibly owning lease: {:?}",
                        row.mapping,
                        row.state,
                        row.owner_id,
                        lease.map(|lease| lease.state)
                    ));
                }
            }
        }
        // No unowned Fleet guest, and no VMID held by two live leases.
        for (vmid, guest) in &guests {
            // An operator's own guest (any name but a Fleet clone's) is not
            // Lab state.
            if !guest.name.starts_with("fm-lab-") {
                continue;
            }
            let record = guest
                .name
                .strip_prefix("fm-lab-")
                .and_then(|id| records.get(id));
            let lease = record
                .and_then(|record| record.lease_id.as_deref())
                .and_then(|id| by_lease.get(id).copied());
            if !guest_owned(record, lease, &self.account_id, *vmid) {
                violations.push(format!(
                    "guest {vmid} ({}) is not owned by any Lab record",
                    guest.name
                ));
            }
        }
        // Device statuses agree with the rows.
        let mut seen = BTreeSet::new();
        for row in &rows {
            if !seen.insert(row.mapping.clone()) {
                continue;
            }
            let status = self.device_status(&row.mapping).await;
            let has_live = live.iter().any(|live| live.mapping == row.mapping);
            // `attach_unknown` and `detach_failed` quarantine the device; the
            // rows still in flight (`attaching`, `detaching`) read `reserved`.
            let unresolved = live.iter().any(|live| {
                live.mapping == row.mapping
                    && matches!(live.state.as_str(), "attach_unknown" | "detach_failed")
            });
            let ok = if unresolved {
                status == DeviceStatus::Quarantined
            } else if has_live {
                status == DeviceStatus::Reserved
            } else {
                status != DeviceStatus::Reserved && status != DeviceStatus::Quarantined
            };
            if !ok {
                violations.push(format!(
                    "{} reads {status:?} with live rows {:?}",
                    row.mapping,
                    live.iter()
                        .filter(|live| live.mapping == row.mapping)
                        .map(|live| &live.state)
                        .collect::<Vec<_>>()
                ));
            }
        }
        violations
    }

    /// Panics, naming `label`, when [`Rig::check`] finds a violation.
    pub async fn assert_invariants(&self, world: &World, level: Level, label: &str) {
        self.assert_invariants_foreign(world, level, &[], label)
            .await;
    }

    /// The same, with entries an operator wrote on purpose.
    pub async fn assert_invariants_foreign(
        &self,
        world: &World,
        level: Level,
        foreign: Foreign<'_>,
        label: &str,
    ) {
        let violations = self.check(world, level, foreign).await;
        assert!(
            violations.is_empty(),
            "{label}: {level:?} invariants violated:\n  {}\n{}",
            violations.join("\n  "),
            self.dump(world).await
        );
    }

    /// A lease that ended in nothing: released (or failed without a guest),
    /// no live row, no guest, no entry on any guest, every device free, and
    /// every invariant holds.
    pub async fn assert_nothing(&self, world: &World, lease: &str, label: &str) {
        let state = self.lease(lease).await.state;
        assert!(
            matches!(state, LeaseState::Released | LeaseState::Failed),
            "{label}: lease ended {state:?}; rows {:#?}",
            self.rows().await
        );
        assert!(
            self.live_rows().await.is_empty(),
            "{label}: rows {:#?}",
            self.rows().await
        );
        assert!(
            world.pve.lab_guests().is_empty(),
            "{label}: guests {:?}",
            world.pve.lab_guests()
        );
        self.refresh_inventory().await;
        for mapping in [READER_A, READER_B] {
            assert_eq!(
                self.device_status(mapping).await,
                DeviceStatus::Available,
                "{label}: {mapping}"
            );
        }
        self.assert_invariants(world, Level::Quiescent, label).await;
    }
}
