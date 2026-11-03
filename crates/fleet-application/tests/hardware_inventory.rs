//! The hardware inventory use cases (FM-1111) over in-memory ports: every
//! device status with its reason, the refusals that must leave nothing
//! behind (a denied caller, an unconfirmed account, a failed audit write),
//! what an empty mapping list does and does not prove, stale observations,
//! and the audit trail of a refresh.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditOutcome};
use fleet_application::authz::{
    AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, ReasonId,
};
use fleet_application::hardware::{
    DeviceObservation, HardwareStore, HardwareStoreError, NewHardwareReservation,
};
use fleet_application::hardware_inventory::{
    AccountReason, AccountSupport, DeviceFilter, HardwareInventory, HardwareObservePort,
    RawGuestReference, RawGuestScan, RawHardwareObservation, RawMapEntry, RawMapping,
    RawMappingsRead, RawNode, RawNodeCheck, RawPermissionsRead, ReferencePending, view,
};
use fleet_application::operation::AuditPort;
use fleet_application::proxmox::privileges::{EffectivePermissions, RawTokenPermissions};
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccount, ProxmoxAccountPort,
    ProxmoxCredentialStore, ProxmoxSourceError, ProxmoxUseCaseError,
};
use fleet_core::{
    DeviceStatus, GuestTarget, HardwareDevice, HardwareReservation, HardwareReservationState,
    ReservationOwnerKind, SensitiveString, UnsupportedReason,
};

const NOW: i64 = 5_000_000;
const ACCOUNT: &str = "acct-1";
const SECRET: &str = "never-in-the-ledger-secret";

// ── ports ───────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Accounts(Vec<ProxmoxAccount>);

#[async_trait]
impl ProxmoxAccountPort for Accounts {
    async fn create(&self, _account: &NewProxmoxAccount) -> Result<ProxmoxAccount, String> {
        unreachable!("the inventory never creates an account")
    }
    async fn get(&self, id: &str) -> Result<ProxmoxAccount, String> {
        self.0
            .iter()
            .find(|account| account.id == id)
            .cloned()
            .ok_or_else(|| format!("account {id} not found"))
    }
    async fn list(&self) -> Result<Vec<ProxmoxAccount>, String> {
        Ok(self.0.clone())
    }
    async fn set_fingerprint(
        &self,
        _id: &str,
        _fingerprint: Option<String>,
    ) -> Result<ProxmoxAccount, String> {
        unreachable!()
    }
    async fn set_observed_fingerprint(
        &self,
        _id: &str,
        _fingerprint: Option<String>,
    ) -> Result<ProxmoxAccount, String> {
        unreachable!()
    }
    async fn delete(&self, _id: &str) -> Result<(), String> {
        unreachable!()
    }
}

#[derive(Debug)]
struct Credentials(bool);

#[async_trait]
impl ProxmoxCredentialStore for Credentials {
    async fn load(&self, _account_id: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(self.0.then(|| SECRET.to_owned()))
    }
    async fn store(&self, _account_id: &str, _secret: &str) -> Result<(), CredentialStoreError> {
        unreachable!()
    }
    async fn clear(&self, _account_id: &str) -> Result<(), CredentialStoreError> {
        unreachable!()
    }
}

#[derive(Debug, Default)]
struct Audit {
    intents: Mutex<Vec<AuditIntent>>,
    /// Refuse the Nth intent onward (1-based); 0 never refuses.
    refuse_from: Mutex<usize>,
}

impl Audit {
    fn events(&self) -> Vec<String> {
        self.intents
            .lock()
            .unwrap()
            .iter()
            .map(|intent| {
                intent
                    .metadata
                    .entries()
                    .find(|(key, _)| *key == "event")
                    .unwrap()
                    .1
                    .to_owned()
            })
            .collect()
    }
}

#[async_trait]
impl AuditPort for Audit {
    async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
        let mut intents = self.intents.lock().unwrap();
        let from = *self.refuse_from.lock().unwrap();
        if from != 0 && intents.len() + 1 >= from {
            return Err("the audit sink is down".to_owned());
        }
        intents.push(intent.clone());
        Ok(())
    }
    async fn record_outcome(
        &self,
        _operation_id: &str,
        _outcome: AuditOutcome,
    ) -> Result<(), String> {
        unreachable!("the refresh is not an operation")
    }
}

#[derive(Debug, Default)]
struct MemStore {
    devices: Mutex<Vec<HardwareDevice>>,
    reservations: Mutex<Vec<HardwareReservation>>,
}

#[async_trait]
impl HardwareStore for MemStore {
    async fn upsert_device(
        &self,
        observation: &DeviceObservation,
        now: i64,
    ) -> Result<HardwareDevice, HardwareStoreError> {
        assert_ne!(observation.status, DeviceStatus::Reserved);
        let mut devices = self.devices.lock().unwrap();
        if let Some(device) = devices.iter_mut().find(|device| {
            device.account_id == observation.account_id
                && device.mapping_id == observation.mapping_id
        }) {
            device.entries.clone_from(&observation.entries);
            device.status = observation.status;
            device.updated_at = now;
            return Ok(device.clone());
        }
        let device = HardwareDevice {
            id: observation.id.clone(),
            account_id: observation.account_id.clone(),
            mapping_id: observation.mapping_id.clone(),
            kind: observation.kind,
            entries: observation.entries.clone(),
            status: observation.status,
            note: None,
            created_at: now,
            updated_at: now,
        };
        devices.push(device.clone());
        Ok(device)
    }
    async fn device(&self, id: &str) -> Result<Option<HardwareDevice>, HardwareStoreError> {
        Ok(self
            .devices
            .lock()
            .unwrap()
            .iter()
            .find(|device| device.id == id)
            .cloned())
    }
    async fn device_by_mapping(
        &self,
        account_id: &str,
        mapping_id: &str,
    ) -> Result<Option<HardwareDevice>, HardwareStoreError> {
        Ok(self
            .devices
            .lock()
            .unwrap()
            .iter()
            .find(|device| device.account_id == account_id && device.mapping_id == mapping_id)
            .cloned())
    }
    async fn list_devices(
        &self,
        account_id: &str,
    ) -> Result<Vec<HardwareDevice>, HardwareStoreError> {
        let mut devices: Vec<_> = self
            .devices
            .lock()
            .unwrap()
            .iter()
            .filter(|device| device.account_id == account_id)
            .cloned()
            .collect();
        devices.sort_by(|left, right| left.mapping_id.cmp(&right.mapping_id));
        Ok(devices)
    }
    async fn set_device_status(
        &self,
        id: &str,
        status: DeviceStatus,
        now: i64,
    ) -> Result<(), HardwareStoreError> {
        let mut devices = self.devices.lock().unwrap();
        let device = devices
            .iter_mut()
            .find(|device| device.id == id)
            .ok_or(HardwareStoreError::NotFound)?;
        device.status = status;
        device.updated_at = now;
        Ok(())
    }
    async fn set_device_note(
        &self,
        _id: &str,
        _note: Option<&str>,
        _now: i64,
    ) -> Result<(), HardwareStoreError> {
        unreachable!()
    }
    async fn insert_reservation(
        &self,
        reservation: &NewHardwareReservation,
        now: i64,
    ) -> Result<HardwareReservation, HardwareStoreError> {
        let stored = HardwareReservation {
            id: reservation.id.clone(),
            device_id: reservation.device_id.clone(),
            owner_kind: reservation.owner_kind,
            owner_id: reservation.owner_id.clone(),
            state: HardwareReservationState::Held,
            guest: reservation.guest.clone(),
            created_at: now,
            updated_at: now,
            released_at: None,
        };
        self.reservations.lock().unwrap().push(stored.clone());
        Ok(stored)
    }
    async fn reservation(
        &self,
        _id: &str,
    ) -> Result<Option<HardwareReservation>, HardwareStoreError> {
        unreachable!()
    }
    async fn live_reservation_for_device(
        &self,
        _device_id: &str,
    ) -> Result<Option<HardwareReservation>, HardwareStoreError> {
        unreachable!()
    }
    async fn live_reservations_for_owner(
        &self,
        _owner_kind: ReservationOwnerKind,
        _owner_id: &str,
    ) -> Result<Vec<HardwareReservation>, HardwareStoreError> {
        unreachable!()
    }
    async fn list_live_reservations(&self) -> Result<Vec<HardwareReservation>, HardwareStoreError> {
        Ok(self
            .reservations
            .lock()
            .unwrap()
            .iter()
            .filter(|reservation| reservation.state.is_live())
            .cloned()
            .collect())
    }
    async fn transition_reservation(
        &self,
        id: &str,
        _from: HardwareReservationState,
        to: HardwareReservationState,
        _guest: Option<&GuestTarget>,
        _now: i64,
    ) -> Result<HardwareReservation, HardwareStoreError> {
        // Only the tests' own set-up moves a reservation, past the state
        // machine on purpose.
        let mut reservations = self.reservations.lock().unwrap();
        let reservation = reservations
            .iter_mut()
            .find(|reservation| reservation.id == id)
            .ok_or(HardwareStoreError::NotFound)?;
        reservation.state = to;
        Ok(reservation.clone())
    }
    async fn force_release_reservation(
        &self,
        _id: &str,
        _now: i64,
    ) -> Result<HardwareReservation, HardwareStoreError> {
        unreachable!()
    }
}

#[derive(Debug)]
struct Observer {
    answer: Mutex<Result<RawHardwareObservation, ProxmoxSourceError>>,
    calls: Mutex<usize>,
    audit: Arc<Audit>,
    /// The audit events on the ledger each time the observer was called.
    audited_before_call: Mutex<Vec<Vec<String>>>,
    secrets: Mutex<Vec<String>>,
}

#[async_trait]
impl HardwareObservePort for Observer {
    async fn observe(
        &self,
        _account: &ProxmoxAccount,
        secret: &SensitiveString,
    ) -> Result<RawHardwareObservation, ProxmoxSourceError> {
        *self.calls.lock().unwrap() += 1;
        self.audited_before_call
            .lock()
            .unwrap()
            .push(self.audit.events());
        self.secrets
            .lock()
            .unwrap()
            .push(secret.expose().to_owned());
        self.answer.lock().unwrap().clone()
    }
}

#[derive(Debug)]
struct Deny(Permission);

impl Authorizer for Deny {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.action == self.0 {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

#[derive(Debug)]
struct Allow;

impl Authorizer for Allow {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

fn account(fingerprint: Option<&str>) -> ProxmoxAccount {
    ProxmoxAccount {
        id: ACCOUNT.to_owned(),
        name: "pve-main".to_owned(),
        host: "192.0.2.10".to_owned(),
        port: 8006,
        token_id: "fleet@pve!fleet".to_owned(),
        fingerprint: fingerprint.map(str::to_owned),
        observed_fingerprint: None,
        created_at: 1,
    }
}

struct Rig {
    inventory: HardwareInventory,
    store: Arc<MemStore>,
    audit: Arc<Audit>,
    observer: Arc<Observer>,
    now: Arc<Mutex<i64>>,
}

fn rig_with(
    fingerprint: Option<&str>,
    has_secret: bool,
    answer: Result<RawHardwareObservation, ProxmoxSourceError>,
) -> Rig {
    let audit = Arc::new(Audit::default());
    let store = Arc::new(MemStore::default());
    let observer = Arc::new(Observer {
        answer: Mutex::new(answer),
        calls: Mutex::new(0),
        audit: audit.clone(),
        audited_before_call: Mutex::new(Vec::new()),
        secrets: Mutex::new(Vec::new()),
    });
    let now = Arc::new(Mutex::new(NOW));
    let clock = now.clone();
    let inventory = HardwareInventory::new(
        Arc::new(Accounts(vec![account(fingerprint)])),
        Arc::new(Credentials(has_secret)),
        store.clone(),
        observer.clone(),
        audit.clone(),
    )
    .with_max_age_ms(600_000)
    .with_clock(Arc::new(move || *clock.lock().unwrap()));
    Rig {
        inventory,
        store,
        audit,
        observer,
        now,
    }
}

fn rig(answer: RawHardwareObservation) -> Rig {
    rig_with(Some("AA"), true, Ok(answer))
}

fn operator() -> ActingPrincipal {
    ActingPrincipal {
        id: "operator".to_owned(),
    }
}

// ── observations ────────────────────────────────────────────────────────

fn entry(node: &str, vendor: &str, product: &str, path: Option<&str>) -> RawMapEntry {
    RawMapEntry {
        node: node.to_owned(),
        vendor_id: vendor.to_owned(),
        product_id: product.to_owned(),
        path: path.map(str::to_owned),
    }
}

fn mapping(id: &str, entries: Vec<RawMapEntry>) -> RawMapping {
    RawMapping {
        id: id.to_owned(),
        entries,
        unreadable_entries: 0,
    }
}

fn paths(entries: &[(&str, &[(&str, bool)])]) -> EffectivePermissions {
    entries
        .iter()
        .map(|(path, privileges)| {
            (
                (*path).to_owned(),
                privileges
                    .iter()
                    .map(|(name, propagate)| ((*name).to_owned(), *propagate))
                    .collect(),
            )
        })
        .collect()
}

/// A token with the opt-in role on the named mappings and every guest.
fn token(use_on: &[&str]) -> RawPermissionsRead {
    let mut entries: BTreeMap<String, BTreeMap<String, bool>> = BTreeMap::new();
    entries.insert(
        "/mapping/usb".to_owned(),
        BTreeMap::from([("Mapping.Audit".to_owned(), true)]),
    );
    entries.insert(
        "/vms".to_owned(),
        BTreeMap::from([("VM.Config.HWType".to_owned(), true)]),
    );
    for id in use_on {
        entries.insert(
            format!("/mapping/usb/{id}"),
            BTreeMap::from([("Mapping.Use".to_owned(), false)]),
        );
    }
    RawPermissionsRead::Read(RawTokenPermissions {
        version: "9.2.2".to_owned(),
        paths: entries,
        ..RawTokenPermissions::default()
    })
}

fn node(name: &str, checks: &[(&str, RawNodeCheck)]) -> RawNode {
    RawNode {
        node: name.to_owned(),
        checks: checks
            .iter()
            .map(|(id, check)| ((*id).to_owned(), check.clone()))
            .collect(),
        inventory: None,
    }
}

fn absent() -> RawNodeCheck {
    RawNodeCheck::NotPresent {
        detail: "usb device '1-3' not found".to_owned(),
    }
}

fn reference(mapping_id: &str, vmid: u32) -> RawGuestReference {
    RawGuestReference {
        node: "pve".to_owned(),
        vmid,
        guest_name: Some("test-guest".to_owned()),
        template: false,
        slot: "usb0".to_owned(),
        mapping_id: mapping_id.to_owned(),
        pending: None,
    }
}

fn observation(
    mappings: Vec<RawMapping>,
    nodes: Vec<RawNode>,
    references: Vec<RawGuestReference>,
    permissions: RawPermissionsRead,
) -> RawHardwareObservation {
    RawHardwareObservation {
        mappings: RawMappingsRead::Read {
            version: "9.2.2".to_owned(),
            rows_returned: mappings.len(),
            mappings,
            truncated: false,
        },
        nodes,
        guests: RawGuestScan {
            references,
            guests_listed: 3,
            guests_read: 3,
            guests_unreadable: 0,
            truncated: false,
        },
        permissions,
        warnings: Vec::new(),
    }
}

/// One mapping per status the table lists, plus the reasons that matter.
fn every_status() -> RawHardwareObservation {
    let ids = [
        "m-available",
        "m-external",
        "m-missing",
        "m-ambiguous",
        "m-unreadable",
        "m-reserved",
        "m-lease",
    ];
    observation(
        vec![
            mapping(
                "m-available",
                vec![entry("pve", "aaaa", "0001", Some("1-1"))],
            ),
            mapping("m-external", vec![entry("pve", "bbbb", "0002", None)]),
            mapping("m-missing", vec![entry("pve", "aaaa", "0001", Some("1-3"))]),
            mapping("m-noentry", Vec::new()),
            mapping(
                "m-ambiguous",
                vec![
                    entry("pve", "cccc", "0003", Some("1-4")),
                    entry("pve", "cccc", "0003", Some("1-5")),
                ],
            ),
            mapping("m-nouse", vec![entry("pve", "aaaa", "0001", Some("1-6"))]),
            mapping(
                "m-unreadable",
                vec![entry("pve", "aaaa", "0001", Some("1-7"))],
            ),
            mapping(
                "m-reserved",
                vec![entry("pve", "dddd", "0004", Some("1-8"))],
            ),
            mapping("m-lease", vec![entry("pve", "eeee", "0005", Some("1-9"))]),
        ],
        vec![node(
            "pve",
            &[
                ("m-available", RawNodeCheck::Present),
                ("m-external", RawNodeCheck::Present),
                ("m-missing", absent()),
                ("m-ambiguous", RawNodeCheck::Present),
                ("m-nouse", RawNodeCheck::Present),
                (
                    "m-unreadable",
                    RawNodeCheck::Unchecked {
                        detail: "the node did not answer".to_owned(),
                    },
                ),
                ("m-reserved", RawNodeCheck::Present),
                ("m-lease", RawNodeCheck::Present),
            ],
        )],
        vec![reference("m-external", 200), reference("m-reserved", 9000)],
        token(&ids),
    )
}

fn status_of(
    report: &fleet_application::hardware_inventory::RefreshReport,
    id: &str,
) -> DeviceStatus {
    report
        .devices
        .iter()
        .find(|device| device.view.device.mapping_id == id)
        .unwrap_or_else(|| panic!("no device {id}"))
        .view
        .status
}

async fn refresh(rig: &Rig) -> fleet_application::hardware_inventory::RefreshReport {
    rig.inventory
        .refresh(&Allow, &operator(), Some("corr-1"), ACCOUNT)
        .await
        .expect("a refresh")
}

// ── statuses ────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_refresh_derives_every_status_with_its_reason() {
    let rig = rig(every_status());
    let report = refresh(&rig).await;
    assert_eq!(report.support, AccountSupport::Supported);
    assert_eq!(report.pve_version.as_deref(), Some("9.2.2"));

    assert_eq!(status_of(&report, "m-available"), DeviceStatus::Available);
    assert_eq!(
        status_of(&report, "m-external"),
        DeviceStatus::ExternallyAttached
    );
    assert_eq!(status_of(&report, "m-missing"), DeviceStatus::Missing);
    assert_eq!(
        status_of(&report, "m-noentry"),
        DeviceStatus::Unsupported(UnsupportedReason::NoNodeEntry)
    );
    assert_eq!(
        status_of(&report, "m-ambiguous"),
        DeviceStatus::Unsupported(UnsupportedReason::AmbiguousMapping)
    );
    // The token holds Mapping.Use on every mapping but this one.
    assert_eq!(
        status_of(&report, "m-nouse"),
        DeviceStatus::Unsupported(UnsupportedReason::TokenLacksMappingUse)
    );
    assert_eq!(
        status_of(&report, "m-unreadable"),
        DeviceStatus::Unsupported(UnsupportedReason::UsbInventoryUnreadable)
    );

    // The external device names the guest and says nothing is pending.
    let external = report
        .devices
        .iter()
        .find(|device| device.view.device.mapping_id == "m-external")
        .unwrap();
    assert_eq!(external.external_references.len(), 1);
    assert_eq!(external.external_references[0].vmid, 200);
    assert_eq!(external.external_references[0].pending, None);
    // The id-only entry cannot be told apart without the node inventory.
    assert!(
        external.notes.iter().any(|note| note.contains("id-only")),
        "{:?}",
        external.notes
    );

    // Nothing is stored as `reserved`: that is derived from a live row.
    let stored = rig.store.list_devices(ACCOUNT).await.unwrap();
    assert!(
        stored
            .iter()
            .all(|device| device.status != DeviceStatus::Reserved)
    );
    assert_eq!(stored.len(), 9);
}

#[tokio::test]
async fn a_token_without_guest_hardware_privilege_is_unsupported_everywhere() {
    let mut answer = every_status();
    answer.permissions = RawPermissionsRead::Read(RawTokenPermissions {
        version: "9.2.2".to_owned(),
        paths: paths(&[(
            "/mapping/usb",
            &[("Mapping.Audit", true), ("Mapping.Use", true)],
        )]),
        ..RawTokenPermissions::default()
    });
    let rig = rig(answer);
    let report = refresh(&rig).await;
    for id in ["m-available", "m-external", "m-reserved", "m-lease"] {
        assert_eq!(
            status_of(&report, id),
            DeviceStatus::Unsupported(UnsupportedReason::TokenLacksGuestHwtype),
            "{id}"
        );
    }
    // The structural reasons stay what they are, ahead of the token.
    assert_eq!(
        status_of(&report, "m-ambiguous"),
        DeviceStatus::Unsupported(UnsupportedReason::AmbiguousMapping)
    );
}

#[tokio::test]
async fn unreadable_permissions_derive_no_token_reason_and_say_so() {
    let mut answer = every_status();
    answer.permissions = RawPermissionsRead::Unreadable {
        detail: "refused (403)".to_owned(),
    };
    let rig = rig(answer);
    let report = refresh(&rig).await;
    assert_eq!(status_of(&report, "m-available"), DeviceStatus::Available);
    assert_eq!(status_of(&report, "m-nouse"), DeviceStatus::Available);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("permissions could not be read")),
        "{:?}",
        report.warnings
    );
}

#[tokio::test]
async fn a_live_reservation_decides_reserved_and_explains_its_own_reference() {
    let rig = rig(every_status());
    refresh(&rig).await;
    // The reservation store reserves `m-reserved` for a machine and attaches
    // it to guest 9000; the refresh then sees that guest's reference.
    let device = rig
        .store
        .device_by_mapping(ACCOUNT, "m-reserved")
        .await
        .unwrap()
        .unwrap();
    rig.store
        .insert_reservation(
            &NewHardwareReservation {
                id: "res-1".to_owned(),
                device_id: device.id.clone(),
                owner_kind: ReservationOwnerKind::Machine,
                owner_id: "machine-1".to_owned(),
                guest: Some(GuestTarget {
                    account_id: ACCOUNT.to_owned(),
                    node: "pve".to_owned(),
                    vmid: 9000,
                    usb_slot: Some(0),
                }),
            },
            NOW,
        )
        .await
        .unwrap();
    // A second device whose attach outcome is unknown.
    let lease_device = rig
        .store
        .device_by_mapping(ACCOUNT, "m-lease")
        .await
        .unwrap()
        .unwrap();
    rig.store
        .insert_reservation(
            &NewHardwareReservation {
                id: "res-2".to_owned(),
                device_id: lease_device.id.clone(),
                owner_kind: ReservationOwnerKind::Lease,
                owner_id: "lease-1".to_owned(),
                guest: None,
            },
            NOW,
        )
        .await
        .unwrap();
    rig.store
        .transition_reservation(
            "res-2",
            HardwareReservationState::Held,
            HardwareReservationState::AttachUnknown,
            None,
            NOW,
        )
        .await
        .unwrap();

    let report = refresh(&rig).await;
    // Fleet's own attachment is not an external one.
    let reserved = report
        .devices
        .iter()
        .find(|device| device.view.device.mapping_id == "m-reserved")
        .unwrap();
    assert_eq!(reserved.view.status, DeviceStatus::Reserved);
    assert_eq!(reserved.view.holder.as_ref().unwrap().id, "res-1");
    assert!(reserved.external_references.is_empty());
    assert_eq!(
        status_of(&report, "m-lease"),
        DeviceStatus::Quarantined,
        "an unknown attach is quarantined for the reconciler"
    );
    // The stored status of a held device is never `reserved`.
    let stored = rig.store.device(&device.id).await.unwrap().unwrap();
    assert_ne!(stored.status, DeviceStatus::Reserved);
}

#[tokio::test]
async fn a_foreign_reference_on_a_reserved_device_is_a_note_not_a_steal() {
    let rig = rig(every_status());
    refresh(&rig).await;
    let device = rig
        .store
        .device_by_mapping(ACCOUNT, "m-reserved")
        .await
        .unwrap()
        .unwrap();
    rig.store
        .insert_reservation(
            &NewHardwareReservation {
                id: "res-1".to_owned(),
                device_id: device.id,
                owner_kind: ReservationOwnerKind::Lease,
                owner_id: "lease-1".to_owned(),
                // The reservation's guest is not the one that references it.
                guest: Some(GuestTarget {
                    account_id: ACCOUNT.to_owned(),
                    node: "pve".to_owned(),
                    vmid: 7777,
                    usb_slot: None,
                }),
            },
            NOW,
        )
        .await
        .unwrap();
    let report = refresh(&rig).await;
    let reserved = report
        .devices
        .iter()
        .find(|device| device.view.device.mapping_id == "m-reserved")
        .unwrap();
    assert_eq!(reserved.view.status, DeviceStatus::Reserved);
    assert_eq!(reserved.external_references.len(), 1);
    assert!(
        reserved
            .notes
            .iter()
            .any(|note| note.contains("other than the reservation's own")),
        "{:?}",
        reserved.notes
    );
}

#[tokio::test]
async fn a_pending_removal_on_a_running_guest_still_counts_as_attached() {
    let mut answer = every_status();
    answer.guests.references = vec![RawGuestReference {
        pending: Some(ReferencePending::Remove),
        ..reference("m-available", 201)
    }];
    let rig = rig(answer);
    let report = refresh(&rig).await;
    assert_eq!(
        status_of(&report, "m-available"),
        DeviceStatus::ExternallyAttached
    );
    let device = report
        .devices
        .iter()
        .find(|device| device.view.device.mapping_id == "m-available")
        .unwrap();
    assert_eq!(
        device.external_references[0].pending,
        Some(ReferencePending::Remove)
    );
}

#[tokio::test]
async fn an_incomplete_guest_scan_is_reported_and_never_fatal() {
    let mut answer = every_status();
    answer.guests.guests_unreadable = 2;
    answer.guests.guests_read = 1;
    let rig = rig(answer);
    let report = refresh(&rig).await;
    assert_eq!(status_of(&report, "m-available"), DeviceStatus::Available);
    let scan = report.guest_scan.unwrap();
    assert_eq!((scan.listed, scan.read, scan.unreadable), (3, 1, 2));
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("guest scan is incomplete")),
        "{:?}",
        report.warnings
    );
}

// ── what the mapping list proves ────────────────────────────────────────

fn empty_list(permissions: RawPermissionsRead) -> RawHardwareObservation {
    observation(Vec::new(), Vec::new(), Vec::new(), permissions)
}

#[tokio::test]
async fn an_empty_list_without_mapping_audit_is_unsupported_and_touches_nothing() {
    // Seed a device from an earlier, privileged refresh.
    let rig = rig(every_status());
    refresh(&rig).await;
    let before = rig.store.list_devices(ACCOUNT).await.unwrap();

    *rig.observer.answer.lock().unwrap() =
        Ok(empty_list(RawPermissionsRead::Read(RawTokenPermissions {
            version: "9.2.2".to_owned(),
            paths: paths(&[("/vms", &[("VM.Audit", true)])]),
            ..RawTokenPermissions::default()
        })));
    let report = refresh(&rig).await;
    assert_eq!(
        report.support,
        AccountSupport::Unsupported(AccountReason::NoMappingAudit)
    );
    // Not one device vanished or changed: a lost privilege is not an empty
    // inventory.
    let after = rig.store.list_devices(ACCOUNT).await.unwrap();
    assert_eq!(before, after);
    assert_eq!(report.devices.len(), before.len());
}

#[tokio::test]
async fn an_empty_list_with_mapping_audit_means_the_mappings_are_gone() {
    let rig = rig(every_status());
    refresh(&rig).await;
    *rig.observer.answer.lock().unwrap() = Ok(empty_list(token(&[])));
    let report = refresh(&rig).await;
    assert_eq!(report.support, AccountSupport::Supported);
    for device in &report.devices {
        assert_eq!(
            device.view.device.status,
            DeviceStatus::Unsupported(UnsupportedReason::NoNodeEntry),
            "{}",
            device.view.device.mapping_id
        );
        assert!(
            device
                .notes
                .iter()
                .any(|note| note.contains("no longer lists")),
            "{:?}",
            device.notes
        );
    }
}

#[tokio::test]
async fn an_empty_list_with_unreadable_permissions_is_unverified_and_touches_nothing() {
    let rig = rig(every_status());
    refresh(&rig).await;
    let before = rig.store.list_devices(ACCOUNT).await.unwrap();
    *rig.observer.answer.lock().unwrap() = Ok(empty_list(RawPermissionsRead::Unreadable {
        detail: "403".to_owned(),
    }));
    let report = refresh(&rig).await;
    assert_eq!(
        report.support,
        AccountSupport::Unverified(AccountReason::PermissionsUnreadable)
    );
    assert_eq!(before, rig.store.list_devices(ACCOUNT).await.unwrap());
}

#[tokio::test]
async fn a_partial_mapping_audit_never_prunes_the_mappings_it_cannot_see() {
    let rig = rig(every_status());
    refresh(&rig).await;
    // Audit on one mapping only: the list shows that one, the rest are not
    // gone, they are invisible.
    let mut answer = observation(
        vec![mapping(
            "m-available",
            vec![entry("pve", "aaaa", "0001", Some("1-1"))],
        )],
        vec![node("pve", &[("m-available", RawNodeCheck::Present)])],
        Vec::new(),
        RawPermissionsRead::Read(RawTokenPermissions {
            version: "9.2.2".to_owned(),
            paths: paths(&[
                (
                    "/mapping/usb/m-available",
                    &[("Mapping.Audit", false), ("Mapping.Use", false)],
                ),
                ("/vms", &[("VM.Config.HWType", true)]),
            ]),
            ..RawTokenPermissions::default()
        }),
    );
    answer.guests.guests_listed = 0;
    answer.guests.guests_read = 0;
    *rig.observer.answer.lock().unwrap() = Ok(answer);
    let report = refresh(&rig).await;
    assert_eq!(status_of(&report, "m-available"), DeviceStatus::Available);
    assert_eq!(status_of(&report, "m-missing"), DeviceStatus::Missing);
    assert!(report.devices.iter().all(|device| device.view.device.status
        != DeviceStatus::Unsupported(UnsupportedReason::NoNodeEntry)
        || device.view.device.mapping_id == "m-noentry"));
}

#[tokio::test]
async fn a_refused_list_is_unsupported_and_an_old_pve_marks_the_devices() {
    let rig = rig(every_status());
    refresh(&rig).await;
    let before = rig.store.list_devices(ACCOUNT).await.unwrap();
    let mut denied = empty_list(RawPermissionsRead::Unreadable {
        detail: "not read".to_owned(),
    });
    denied.mappings = RawMappingsRead::Denied {
        version: Some("9.2.2".to_owned()),
        detail: "Permission check failed".to_owned(),
    };
    *rig.observer.answer.lock().unwrap() = Ok(denied);
    let report = refresh(&rig).await;
    assert_eq!(
        report.support,
        AccountSupport::Unsupported(AccountReason::NoMappingAudit)
    );
    assert_eq!(before, rig.store.list_devices(ACCOUNT).await.unwrap());

    // An endpoint that is absent (a PVE that predates mappings).
    let mut old = empty_list(RawPermissionsRead::Unreadable {
        detail: "not read".to_owned(),
    });
    old.mappings = RawMappingsRead::EndpointAbsent {
        version: Some("7.4-3".to_owned()),
    };
    *rig.observer.answer.lock().unwrap() = Ok(old);
    let report = refresh(&rig).await;
    assert_eq!(
        report.support,
        AccountSupport::Unsupported(AccountReason::PveTooOld)
    );
    assert_eq!(report.pve_version.as_deref(), Some("7.4-3"));
    assert!(report.devices.iter().all(
        |device| device.view.status == DeviceStatus::Unsupported(UnsupportedReason::PveTooOld)
    ));

    // A version below the first with mappings, whatever the endpoint says.
    let mut older = every_status();
    older.mappings = RawMappingsRead::Read {
        version: "7.4-3".to_owned(),
        mappings: vec![mapping("m-x", vec![entry("pve", "aaaa", "0001", None)])],
        rows_returned: 1,
        truncated: false,
    };
    *rig.observer.answer.lock().unwrap() = Ok(older);
    let report = refresh(&rig).await;
    assert_eq!(
        report.support,
        AccountSupport::Unsupported(AccountReason::PveTooOld)
    );
}

#[tokio::test]
async fn a_quarantine_survives_a_refresh() {
    let rig = rig(every_status());
    refresh(&rig).await;
    let device = rig
        .store
        .device_by_mapping(ACCOUNT, "m-available")
        .await
        .unwrap()
        .unwrap();
    rig.store
        .set_device_status(&device.id, DeviceStatus::Quarantined, NOW)
        .await
        .unwrap();
    let report = refresh(&rig).await;
    assert_eq!(status_of(&report, "m-available"), DeviceStatus::Quarantined);
}

// ── stale observations ──────────────────────────────────────────────────

async fn list_all(rig: &Rig) -> Vec<fleet_application::hardware_inventory::DeviceView> {
    rig.inventory
        .list(&Allow, &operator(), &DeviceFilter::default(), 100, None)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_listed_device_goes_stale_and_an_available_one_reads_missing() {
    let rig = rig(every_status());
    refresh(&rig).await;
    let fresh = list_all(&rig).await;
    let find = |views: &[fleet_application::hardware_inventory::DeviceView], id: &str| {
        views
            .iter()
            .find(|view| view.device.mapping_id == id)
            .cloned()
            .unwrap()
    };
    assert_eq!(find(&fresh, "m-available").status, DeviceStatus::Available);
    assert!(!find(&fresh, "m-available").stale);

    // Ten minutes and a second later (the bound is ten minutes).
    *rig.now.lock().unwrap() = NOW + 601_000;
    let stale = list_all(&rig).await;
    let available = find(&stale, "m-available");
    assert!(available.stale);
    assert_eq!(available.status, DeviceStatus::Missing);
    assert_eq!(available.device.status, DeviceStatus::Available);
    assert_eq!(available.observed_at, NOW);
    // Other statuses keep their meaning and carry the flag.
    let external = find(&stale, "m-external");
    assert_eq!(external.status, DeviceStatus::ExternallyAttached);
    assert!(external.stale);
    // A device last seen at an older time than its refresh (absent) is
    // stale on its own entry time, not the record's.
    assert_eq!(find(&stale, "m-missing").observed_at, 0);

    // A fresh observation clears it.
    refresh(&rig).await;
    let again = list_all(&rig).await;
    assert!(!find(&again, "m-available").stale);
}

#[test]
fn the_view_function_is_the_one_rule() {
    // The unit tests in the module cover the cases; this pins the public
    // function to the same behaviour the list uses.
    let device = HardwareDevice {
        id: "d".to_owned(),
        account_id: ACCOUNT.to_owned(),
        mapping_id: "m".to_owned(),
        kind: fleet_core::HardwareKind::Usb,
        entries: Vec::new(),
        status: DeviceStatus::Available,
        note: None,
        created_at: 0,
        updated_at: 10,
    };
    let seen = view(device, None, 10 + 700_000, 600_000);
    assert!(seen.stale);
    assert_eq!(seen.status, DeviceStatus::Missing);
}

// ── authorization, audit and the trust gate ─────────────────────────────

#[tokio::test]
async fn a_denied_refresh_calls_nothing_and_records_nothing() {
    let rig = rig(every_status());
    let error = rig
        .inventory
        .refresh(
            &Deny(Permission::HardwareRefresh),
            &operator(),
            None,
            ACCOUNT,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ProxmoxUseCaseError::Denied(_)), "{error}");
    assert_eq!(*rig.observer.calls.lock().unwrap(), 0);
    assert!(rig.audit.events().is_empty());
    assert!(rig.store.list_devices(ACCOUNT).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_denied_list_reads_nothing_and_the_refresh_permission_does_not_list() {
    let rig = rig(every_status());
    refresh(&rig).await;
    let error = rig
        .inventory
        .list(
            &Deny(Permission::HardwareRead),
            &operator(),
            &DeviceFilter::default(),
            10,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ProxmoxUseCaseError::Denied(_)));
    // Holding only the refresh permission lists nothing.
    let error = rig
        .inventory
        .list(
            &Deny(Permission::HardwareRead),
            &operator(),
            &DeviceFilter {
                account_id: Some(ACCOUNT.to_owned()),
            },
            10,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ProxmoxUseCaseError::Denied(_)));
}

#[tokio::test]
async fn a_refresh_is_audited_before_proxmox_is_called_and_again_when_it_is_done() {
    let rig = rig(every_status());
    refresh(&rig).await;
    // At the moment the observer ran, the intent was already on the ledger.
    assert_eq!(
        rig.observer.audited_before_call.lock().unwrap()[0],
        ["hardware_refresh_started"]
    );
    assert_eq!(
        rig.audit.events(),
        ["hardware_refresh_started", "hardware_refreshed"]
    );
    let intents = rig.audit.intents.lock().unwrap();
    for intent in intents.iter() {
        assert_eq!(intent.action, "hardware.refresh");
        assert_eq!(intent.actor, "operator");
        assert_eq!(intent.resource.as_deref(), Some(ACCOUNT));
        assert_eq!(intent.correlation_id.as_deref(), Some("corr-1"));
        // Nothing sensitive reaches the ledger.
        let json = intent.metadata.to_json();
        assert!(!json.contains(SECRET), "{json}");
        assert!(!json.contains("192.0.2.10"), "{json}");
    }
    let completion = intents[1].metadata.to_json();
    assert!(completion.contains("\"devices\":\"9\""), "{completion}");
    assert!(completion.contains("available=2"), "{completion}");
    assert!(completion.contains("externally_attached=2"), "{completion}");
    // The token went to the port, and only there.
    assert_eq!(*rig.observer.secrets.lock().unwrap(), [SECRET]);
}

#[tokio::test]
async fn a_failed_audit_write_stops_the_refresh_before_any_proxmox_call() {
    let rig = rig(every_status());
    *rig.audit.refuse_from.lock().unwrap() = 1;
    let error = rig
        .inventory
        .refresh(&Allow, &operator(), None, ACCOUNT)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            ProxmoxUseCaseError::Backend {
                context: "audit",
                ..
            }
        ),
        "{error}"
    );
    assert_eq!(*rig.observer.calls.lock().unwrap(), 0);
    assert!(rig.store.list_devices(ACCOUNT).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_failed_completion_event_is_said_in_the_report_not_hidden() {
    let rig = rig(every_status());
    *rig.audit.refuse_from.lock().unwrap() = 2;
    let report = refresh(&rig).await;
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("completion audit event")),
        "{:?}",
        report.warnings
    );
    assert_eq!(rig.audit.events(), ["hardware_refresh_started"]);
}

#[tokio::test]
async fn the_trust_gate_and_the_secret_gate_hold_before_any_call() {
    let unconfirmed = rig_with(None, true, Ok(every_status()));
    let error = unconfirmed
        .inventory
        .refresh(&Allow, &operator(), None, ACCOUNT)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ProxmoxUseCaseError::UnconfirmedTrust { .. }
    ));
    assert_eq!(*unconfirmed.observer.calls.lock().unwrap(), 0);
    assert!(unconfirmed.audit.events().is_empty());

    let no_secret = rig_with(Some("AA"), false, Ok(every_status()));
    let error = no_secret
        .inventory
        .refresh(&Allow, &operator(), None, ACCOUNT)
        .await
        .unwrap_err();
    assert!(matches!(error, ProxmoxUseCaseError::NoSecret { .. }));
    assert_eq!(*no_secret.observer.calls.lock().unwrap(), 0);

    let rig = rig(every_status());
    let error = rig
        .inventory
        .refresh(&Allow, &operator(), None, "nobody")
        .await
        .unwrap_err();
    assert!(matches!(error, ProxmoxUseCaseError::NotFound { .. }));
}

#[tokio::test]
async fn a_failing_proxmox_read_is_a_source_error_after_the_intent() {
    let rig = rig_with(Some("AA"), true, Err(ProxmoxSourceError::Auth));
    let error = rig
        .inventory
        .refresh(&Allow, &operator(), None, ACCOUNT)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ProxmoxUseCaseError::Source(ProxmoxSourceError::Auth)
    ));
    // The intent is on the ledger as evidence that a refresh was accepted
    // and its outcome is unknown.
    assert_eq!(rig.audit.events(), ["hardware_refresh_started"]);
}

// ── listing ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_list_is_ordered_paged_and_scoped_to_known_accounts() {
    let rig = rig(every_status());
    refresh(&rig).await;
    let all = rig
        .inventory
        .list(&Allow, &operator(), &DeviceFilter::default(), 100, None)
        .await
        .unwrap();
    let mappings: Vec<&str> = all
        .iter()
        .map(|view| view.device.mapping_id.as_str())
        .collect();
    let mut sorted = mappings.clone();
    sorted.sort_unstable();
    assert_eq!(mappings, sorted);
    assert_eq!(all.len(), 9);

    let first = rig
        .inventory
        .list(&Allow, &operator(), &DeviceFilter::default(), 4, None)
        .await
        .unwrap();
    assert_eq!(first.len(), 4);
    let second = rig
        .inventory
        .list(
            &Allow,
            &operator(),
            &DeviceFilter::default(),
            4,
            Some(&first[3].device.id),
        )
        .await
        .unwrap();
    assert_eq!(second[0].device.id, all[4].device.id);

    let error = rig
        .inventory
        .list(
            &Allow,
            &operator(),
            &DeviceFilter::default(),
            4,
            Some("no-such-device"),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ProxmoxUseCaseError::Invalid { .. }));
    let error = rig
        .inventory
        .list(
            &Allow,
            &operator(),
            &DeviceFilter {
                account_id: Some("nobody".to_owned()),
            },
            4,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ProxmoxUseCaseError::NotFound { .. }));
}
