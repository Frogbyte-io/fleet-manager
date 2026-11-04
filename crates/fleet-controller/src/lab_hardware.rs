//! The Lab hardware saga (FM-1123, ADR 0019): attaches the USB devices a
//! lease reserved to its clone before the guest starts, detaches them before
//! the guest's fate (destroy, revert, keep), and compensates both.
//!
//! The reservation row is the step ledger. Placement (FM-1121) inserts it
//! `held`; every step below moves it along the state machine of
//! `fleet_core::HardwareReservationState` and every move is a compare-and-set
//! in the store, so a controller that dies at any point leaves a row the next
//! run reads and continues: nothing here is remembered in memory.
//!
//! ```text
//! attach  held -> verify (re-observe, fingerprint, nobody references it)
//!              -> attaching (guest and usbN slot recorded) -> write -> attached
//!         failure: nothing written  -> read back, release
//!                  written, unknown -> attach_unknown (cleanup resolves it)
//! detach  any live state -> detaching -> delete usbN -> read back -> released
//!         failure or pending -> the row stays live, the lease stays in
//!         cleanup retry, and the guest is not destroyed
//! ```
//!
//! Rules this module keeps, from the callers' contracts:
//!
//! - **Verify immediately before attaching.** The inventory applies staleness
//!   when a device is read, not when it is reserved, and keeps a reserved
//!   device `available` on an incomplete guest scan, so the saga refreshes
//!   (re-observes) right before it writes and checks the result: the guest
//!   scan was complete, the device is present on the guest's node, its
//!   fingerprint (vendor:product and port) is the one pinned when placement
//!   reserved it (a refresh in between cannot re-baseline it), the observation
//!   is recent, the reservation is this lease's, and no guest other than the
//!   reservation's own references the mapping. The lease must still count
//!   immediately before the write and after it.
//! - **Only what Fleet may have written is ever deleted.** `qemu_usb_attach`
//!   picks the slot itself and answers `Unchanged` for an identical entry an
//!   operator wrote, so the saga records the slot it expects before it writes
//!   (the store is passed the guest and slot on `held -> attaching`) and
//!   corrects it to the one the provider reports. That record is made
//!   *before* the write, so it proves nothing about an entry the guest shows
//!   later: such an entry is never adopted, and a row that only recorded its
//!   attach becomes `attach_unknown` with no slot when the guest shows one, a
//!   state cleanup never deletes for. Only a row that attempted the write
//!   (and lost the answer) or attached carries a slot cleanup deletes at.
//! - **Never release on a guess.** A row is released only after a read of
//!   every `usbN` entry of the guest shows no reference to the mapping (after
//!   the provider's read-back of the slot, when Fleet deleted one). A failed
//!   or pending detach keeps the row; an unknown attach is `attach_unknown`.
//!   The override release is the only way out of either and is not here.
//! - **Pending is not done.** A running guest whose `hotplug` option lacks
//!   `usb` keeps the device until it restarts: a pending detach keeps the
//!   reservation `detaching`, and the lease in cleanup retry.
//!
//! Audit events (outcomes are best effort; the attach and detach intents are
//! required before the write or delete, like a pool claim): `hardware_attach_requested`,
//! `hardware_detach_requested`,
//! `hardware_attached`, `hardware_attach_failed` (outcome `released` or
//! `unknown`), `hardware_detached`, `hardware_detach_pending`,
//! `hardware_detach_failed`, and the reservation store's `hardware_released`.
//! Facts are ids, nodes, VMIDs and slots; provider detail is scrubbed and
//! bounded.
//!
//! **Mid-run hotplug (FM-1126).** `lab_hardware_hotplug` drives the same attach
//! and detach paths for a lease whose guest is running. The differences are
//! only what a finished step leaves behind: a device the lease detaches (or an
//! attach that wrote nothing) stays reserved by the lease in `held` instead of
//! being released ([`Disposition::KeepHeld`]), the acting principal and the
//! `lab.hardware.*` action are the audited ones ([`LabHardwareSaga::acting_as`])
//! and no provision operation is there to cancel.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;

use fleet_application::audit::{AuditIntent, AuditMetadata};
use fleet_application::authz::{ActingPrincipal, Decision, Permission};
use fleet_application::hardware::{HardwareStore, HardwareStoreError};
use fleet_application::hardware_inventory::{AccountSupport, HardwareInventory, reason_text};
use fleet_application::hardware_reservation::{AuditContext, HardwareReservations};
use fleet_application::lab::LeasePort;
use fleet_application::operation::{AuditPort, Operations};
use fleet_application::proxmox::{ProxmoxAccountPort, ProxmoxCredentialStore};
use fleet_core::{
    DeviceNodeEntry, DeviceStatus, GuestTarget, HardwareDevice, HardwareReservation,
    HardwareReservationState, LabHardware, LeaseState, ReservationOwnerKind, USB_SLOT_COUNT,
};
use fleet_provider_proxmox::usb_attach::{PveUsbChange, PveUsbCleanup, PveUsbError, PveUsbState};
use fleet_provider_proxmox::{ProxmoxClient, PveHttpRequest};

use HardwareReservationState as State;

/// The step name a failed attach is recorded under on the provision record.
pub const ATTACH_STEP: &str = "usb_attach";

/// The longest provider detail kept in an audit fact or a refusal.
const MAX_DETAIL_CHARS: usize = 240;

/// How many times a digest conflict (somebody else wrote the guest's config
/// between the provider's read and write; nothing was written) is retried.
const DIGEST_ATTEMPTS: u32 = 3;

/// How many times cleanup re-reads a lease's live reservations (a provision
/// that was still writing may add a row between two reads).
const DETACH_PASSES: u32 = 3;

/// The guest a lease's devices are attached to.
#[derive(Clone, Copy, Debug)]
pub struct LeaseGuest<'a> {
    /// The lease that holds the reservations.
    pub lease_id: &'a str,
    /// The Proxmox account the guest is reached through.
    pub account_id: &'a str,
    /// The node the clone runs on.
    pub node: &'a str,
    /// The clone's VMID.
    pub vmid: u32,
    /// The provision operation the step belongs to; `None` for a step that
    /// belongs to no operation (a mid-run hotplug request, FM-1126).
    pub operation_id: Option<&'a str>,
}

/// Why the attach step did not complete.
#[derive(Debug)]
pub enum AttachFailure {
    /// A classified refusal: the provision fails at the `usb_attach` step
    /// with this reason, and whatever was written has been compensated or
    /// is `attach_unknown`.
    Refused {
        /// The stable reason code.
        reason: &'static str,
        /// The scrubbed, bounded detail.
        detail: String,
    },
    /// An infrastructure failure (a store, the audit sink, the account):
    /// the provision operation ends failed through the worker. Every row is
    /// left in a state the next run or cleanup continues from.
    Infrastructure(String),
}

fn refused(reason: &'static str, detail: impl AsRef<str>) -> AttachFailure {
    AttachFailure::Refused {
        reason,
        detail: bounded(detail.as_ref()),
    }
}

/// Why a lease's devices could not all be confirmed detached. Cleanup keeps
/// the lease in retry and does not destroy, revert, or return the guest.
#[derive(Debug)]
pub struct DetachUnconfirmed {
    /// What is unconfirmed, scrubbed and bounded.
    pub detail: String,
    /// The guest that still holds a device, when known.
    pub guest: Option<(String, u32)>,
}

/// The fingerprint a device had when it was reserved (ADR 0019: observed
/// facts are compared with the fingerprint from the reservation, not with
/// whatever a later refresh recorded).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedFingerprint {
    /// The node the device was reserved on.
    pub node: String,
    /// The USB vendor id.
    pub vendor_id: String,
    /// The USB product id.
    pub product_id: String,
    /// The bus-port path, when the mapping names one.
    pub usbpath: Option<String>,
}

impl PinnedFingerprint {
    fn of(entry: &DeviceNodeEntry) -> Self {
        Self {
            node: entry.node.clone(),
            vendor_id: entry.vendor_id.clone(),
            product_id: entry.product_id.clone(),
            usbpath: entry.usbpath.clone(),
        }
    }
}

/// Where reservation-time fingerprints are kept.
#[async_trait]
pub trait FingerprintPins: std::fmt::Debug + Send + Sync {
    /// Records the fingerprint for a reservation unless one is already
    /// recorded (the first one wins: a resumed placement keeps the original).
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn pin(
        &self,
        reservation_id: &str,
        fingerprint: &PinnedFingerprint,
        now: i64,
    ) -> Result<(), String>;

    /// The fingerprint recorded for a reservation, when there is one.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn pinned(&self, reservation_id: &str) -> Result<Option<PinnedFingerprint>, String>;
}

/// SQLite-backed [`FingerprintPins`] (`hardware_reservation_fingerprints`).
#[derive(Clone, Debug)]
pub struct SqliteFingerprintPins {
    pool: sqlx::SqlitePool,
}

impl SqliteFingerprintPins {
    /// Over the controller's pool.
    #[must_use]
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FingerprintPins for SqliteFingerprintPins {
    async fn pin(
        &self,
        reservation_id: &str,
        fingerprint: &PinnedFingerprint,
        now: i64,
    ) -> Result<(), String> {
        sqlx::query(
            "INSERT OR IGNORE INTO hardware_reservation_fingerprints \
             (reservation_id, node, vendor_id, product_id, usbpath, pinned_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(reservation_id)
        .bind(&fingerprint.node)
        .bind(&fingerprint.vendor_id)
        .bind(&fingerprint.product_id)
        .bind(&fingerprint.usbpath)
        .bind(now)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("the fingerprint could not be recorded: {error}"))
    }

    async fn pinned(&self, reservation_id: &str) -> Result<Option<PinnedFingerprint>, String> {
        use sqlx::Row as _;
        sqlx::query(
            "SELECT node, vendor_id, product_id, usbpath \
             FROM hardware_reservation_fingerprints WHERE reservation_id = ?1",
        )
        .bind(reservation_id)
        .fetch_optional(&self.pool)
        .await
        .map(|row| {
            row.map(|row| PinnedFingerprint {
                node: row.get("node"),
                vendor_id: row.get("vendor_id"),
                product_id: row.get("product_id"),
                usbpath: row.get("usbpath"),
            })
        })
        .map_err(|error| format!("the fingerprint could not be read: {error}"))
    }
}

/// What a confirmed detach (or an attach that wrote nothing) leaves of the
/// reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Disposition {
    /// The reservation is released: the lease's provision and cleanup.
    Release,
    /// The lease still holds the device (`held`, slot cleared): a mid-run
    /// detach that does not release it, and a failed mid-run attach.
    KeepHeld,
}

/// Who an audited step is attributed to.
#[derive(Clone, Debug)]
struct Actor {
    /// The acting principal's id.
    id: String,
    /// The catalog action the intents are filed under.
    action: &'static str,
    /// Set on a step that is not the lease's own provision or cleanup, and
    /// recorded as the `source` fact.
    source: Option<&'static str>,
}

/// The Lab hardware saga.
#[derive(Clone, Debug)]
pub struct LabHardwareSaga {
    accounts: Arc<dyn ProxmoxAccountPort>,
    credentials: Arc<dyn ProxmoxCredentialStore>,
    client: ProxmoxClient,
    store: Arc<dyn HardwareStore>,
    reservations: Arc<HardwareReservations>,
    inventory: Arc<HardwareInventory>,
    audit: Arc<dyn AuditPort>,
    leases: Arc<dyn LeasePort>,
    pins: Arc<dyn FingerprintPins>,
    max_age_ms: i64,
    actor: Actor,
}

fn bounded(text: &str) -> String {
    let scrubbed = fleet_core::scrub_failure_detail(text);
    if scrubbed.chars().count() <= MAX_DETAIL_CHARS {
        scrubbed
    } else {
        let mut cut: String = scrubbed.chars().take(MAX_DETAIL_CHARS).collect();
        cut.push('…');
        cut
    }
}

/// Whether a refusal's detail names facts a lease-bound caller must not see:
/// another guest's VMID and node, or a device's ids and port.
fn is_revealing(reason: &str) -> bool {
    matches!(
        reason,
        "hardware_externally_attached"
            | "hardware_fingerprint_changed"
            | "hardware_wrong_node"
            | "hardware_missing"
            | "hardware_no_node_entry"
            | "hardware_stale"
    )
}

/// What a lease-bound caller is told for a [`is_revealing`] reason; the real
/// detail goes to the audit trail (`hardware_refused`).
fn public_detail(reason: &str) -> &'static str {
    match reason {
        "hardware_externally_attached" => {
            "the device is attached elsewhere (a guest other than this lease's, or an entry Fleet did not write); nothing was changed"
        }
        "hardware_fingerprint_changed" => {
            "the device is not as it was when it was reserved (a cable or the mapping changed); nothing was changed"
        }
        _ => {
            "the device was not found where it was reserved at the re-observation; nothing was changed"
        }
    }
}

fn now() -> i64 {
    fleet_core::SystemClock::now_unix_millis()
}

fn slot_name(index: u8) -> String {
    format!("usb{index}")
}

/// The index of a `usbN` slot name.
fn slot_index(slot: &str) -> Option<u8> {
    slot.strip_prefix("usb")?.parse().ok()
}

fn infra(error: &HardwareStoreError) -> AttachFailure {
    AttachFailure::Infrastructure(format!("the hardware store failed: {error}"))
}

/// What a detach of one reservation came to.
pub(crate) enum DetachResult {
    /// The device is off the guest and the reservation is released (or, for
    /// [`Disposition::KeepHeld`], back in `held`).
    Detached,
    /// PVE keeps the device until the guest restarts.
    Pending,
    /// The detach failed or could not be confirmed; the row stays live.
    Failed(String),
}

impl LabHardwareSaga {
    /// Composes the saga over the Proxmox account, the hardware store, the
    /// reservation use cases and the inventory it re-observes through.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        accounts: Arc<dyn ProxmoxAccountPort>,
        credentials: Arc<dyn ProxmoxCredentialStore>,
        client: ProxmoxClient,
        store: Arc<dyn HardwareStore>,
        reservations: Arc<HardwareReservations>,
        inventory: Arc<HardwareInventory>,
        audit: Arc<dyn AuditPort>,
        leases: Arc<dyn LeasePort>,
        pins: Arc<dyn FingerprintPins>,
    ) -> Self {
        Self {
            accounts,
            credentials,
            client,
            store,
            reservations,
            inventory,
            audit,
            leases,
            pins,
            max_age_ms: fleet_application::hardware_inventory::DEFAULT_OBSERVATION_MAX_AGE_MS,
            actor: Actor {
                id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
                action: Permission::LabProvision.id(),
                source: None,
            },
        }
    }

    /// The same saga with its audited steps attributed to `principal_id`
    /// under `action` and tagged with `source` (the caller's own request, not
    /// the lease's provision or cleanup).
    #[must_use]
    pub(crate) fn acting_as(
        &self,
        principal_id: &str,
        action: Permission,
        source: &'static str,
    ) -> Self {
        Self {
            actor: Actor {
                id: principal_id.to_owned(),
                action: action.id(),
                source: Some(source),
            },
            ..self.clone()
        }
    }

    /// Sets how old a device observation may be at the verify step (the
    /// verify step refreshes first, so this only bounds a clock step).
    #[must_use]
    pub fn with_max_age_ms(mut self, max_age_ms: i64) -> Self {
        self.max_age_ms = max_age_ms.max(1);
        self
    }

    pub(crate) async fn request(&self, account_id: &str) -> Result<PveHttpRequest, String> {
        let account = self
            .accounts
            .get(account_id)
            .await
            .map_err(|detail| format!("the account is unreadable: {detail}"))?;
        if account.fingerprint.is_none() {
            return Err(format!(
                "the account {} has no confirmed fingerprint",
                account.name
            ));
        }
        let secret = self
            .credentials
            .load(account_id)
            .await
            .map_err(|error| format!("the credential store failed: {error}"))?
            .ok_or_else(|| {
                format!(
                    "the API token for account {} is not in the secret store",
                    account.name
                )
            })?;
        Ok(crate::proxmox_exec::pve_request(&account, secret))
    }

    /// Best-effort audit of an event about one reservation; `required`
    /// events report a refused sink.
    async fn event(
        &self,
        event: &str,
        device: &HardwareDevice,
        reservation: &HardwareReservation,
        operation_id: Option<&str>,
        facts: &[(&str, String)],
        required: bool,
    ) -> Result<(), String> {
        let mut metadata = AuditMetadata::default();
        let _ = metadata.insert("event", event);
        let _ = metadata.insert("reservation_id", &reservation.id);
        let _ = metadata.insert("owner_kind", reservation.owner_kind.id());
        let _ = metadata.insert("owner_id", &reservation.owner_id);
        let _ = metadata.insert("mapping", &device.mapping_id);
        if let Some(source) = self.actor.source {
            let _ = metadata.insert("source", source);
        }
        for (key, value) in facts {
            let _ = metadata.insert(key, value);
        }
        let outcome = self
            .audit
            .record_intent(&AuditIntent {
                actor: self.actor.id.clone(),
                action: self.actor.action.to_owned(),
                resource: Some(device.id.clone()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: operation_id.map(str::to_owned),
                metadata,
            })
            .await;
        if required { outcome } else { Ok(()) }
    }

    fn audit_context(&self, operation_id: Option<&str>) -> AuditContext {
        AuditContext {
            actor: self.actor.id.clone(),
            operation_id: operation_id.map(str::to_owned),
        }
    }

    // ── attach ───────────────────────────────────────────────────────────

    /// Attaches every device the lease reserved for `declared` to its guest.
    /// Idempotent: a row that already attached is confirmed, a row that
    /// started the attach (a crashed run) is continued, a row that is only
    /// held is verified and attached.
    ///
    /// A failure at one device compensates the devices of this call that
    /// already attached (best effort; cleanup finishes any that cannot be
    /// detached now) and reports the refusal.
    ///
    /// # Errors
    ///
    /// [`AttachFailure::Refused`] for a classified failure, or
    /// [`AttachFailure::Infrastructure`].
    pub async fn attach_for_lease(
        &self,
        operations: &Operations,
        guest: &LeaseGuest<'_>,
        declared: &[LabHardware],
    ) -> Result<(), AttachFailure> {
        if declared.is_empty() {
            return Ok(());
        }
        let request = self
            .request(guest.account_id)
            .await
            .map_err(AttachFailure::Infrastructure)?;
        // Mapping order, as placement reserved them.
        let mut mappings: Vec<&str> = declared
            .iter()
            .map(|device| device.mapping.as_str())
            .collect();
        mappings.sort_unstable();
        mappings.dedup();
        let mut targets = Vec::with_capacity(mappings.len());
        for mapping in mappings {
            let device = self
                .store
                .device_by_mapping(guest.account_id, mapping)
                .await
                .map_err(|error| infra(&error))?
                .ok_or_else(|| {
                    refused(
                        "hardware_unknown",
                        format!("hardware {mapping} is not in the inventory"),
                    )
                })?;
            let held = self
                .store
                .live_reservation_for_device(&device.id)
                .await
                .map_err(|error| infra(&error))?
                .filter(|row| {
                    row.owner_kind == ReservationOwnerKind::Lease && row.owner_id == guest.lease_id
                })
                .ok_or_else(|| {
                    refused(
                        "hardware_not_reserved",
                        format!(
                            "hardware {mapping} is not reserved for lease {}; placement reserves it before the clone",
                            guest.lease_id
                        ),
                    )
                })?;
            targets.push((device, held));
        }
        let mut attached: Vec<(HardwareDevice, HardwareReservation)> = Vec::new();
        for (device, held) in targets {
            match self
                .attach_one(
                    Some(operations),
                    guest,
                    &request,
                    &device,
                    held,
                    Disposition::Release,
                )
                .await
            {
                Ok(row) => attached.push((device, row)),
                Err(failure) => {
                    for (done, row) in attached {
                        // Best effort: a failure here leaves the row live for
                        // cleanup, which owns the retry.
                        let _ = self
                            .detach_reservation(
                                &request,
                                row,
                                &done,
                                guest.operation_id,
                                guest.lease_id,
                                true,
                                Disposition::Release,
                            )
                            .await;
                    }
                    return Err(failure);
                }
            }
        }
        Ok(())
    }

    /// Whether the lease still counts for a provision: it is in the saga or
    /// ready. An unreadable lease counts (the write is not refused on a
    /// guess; the post-write check and cleanup cover the race).
    pub(crate) async fn lease_counts(&self, lease_id: &str) -> bool {
        match self.leases.get(lease_id).await {
            Ok(lease) => matches!(
                lease.state,
                LeaseState::Provisioning
                    | LeaseState::Booting
                    | LeaseState::Bootstrapping
                    | LeaseState::Ready
            ),
            Err(_) => true,
        }
    }

    /// Records the fingerprint each device of the lease has now, as of its
    /// reservation, unless one is already recorded. Called right after
    /// placement reserved the devices (before capacity, the VMID and the
    /// clone), so the attach, which comes minutes later, compares with this
    /// and not with whatever a refresh recorded in between. A repeat (a
    /// resumed provision) keeps the first.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read or written.
    pub async fn pin_fingerprints(
        &self,
        lease_id: &str,
        account_id: &str,
        node: &str,
        declared: &[LabHardware],
    ) -> Result<(), String> {
        for mapping in declared.iter().map(|device| device.mapping.as_str()) {
            let Some(device) = self
                .store
                .device_by_mapping(account_id, mapping)
                .await
                .map_err(|error| error.to_string())?
            else {
                continue;
            };
            let Some(row) = self
                .store
                .live_reservation_for_device(&device.id)
                .await
                .map_err(|error| error.to_string())?
                .filter(|row| {
                    row.owner_kind == ReservationOwnerKind::Lease && row.owner_id == lease_id
                })
            else {
                continue;
            };
            let Some(entry) = device.entries.iter().find(|entry| entry.node == node) else {
                continue;
            };
            self.pins
                .pin(&row.id, &PinnedFingerprint::of(entry), now())
                .await?;
        }
        Ok(())
    }

    async fn attach_one(
        &self,
        operations: Option<&Operations>,
        guest: &LeaseGuest<'_>,
        request: &PveHttpRequest,
        device: &HardwareDevice,
        reservation: HardwareReservation,
        keep: Disposition,
    ) -> Result<HardwareReservation, AttachFailure> {
        match reservation.state {
            State::Attached => {
                Self::same_guest(guest, &reservation)?;
                Ok(reservation)
            }
            State::Held => {
                self.attach_held(operations, guest, request, device, reservation, false, keep)
                    .await
            }
            State::Attaching => {
                Self::same_guest(guest, &reservation)?;
                self.attach_held(operations, guest, request, device, reservation, true, keep)
                    .await
            }
            // An unknown attach is resolved by reading the guest, which is
            // cleanup's job (a provision whose attach ended unknown has
            // failed and is never resumed): the saga does not write over it.
            State::AttachUnknown => Err(refused(
                "hardware_attach_unknown",
                format!(
                    "the reservation for {} is attach_unknown; the lease's cleanup resolves it by reading the guest",
                    device.mapping_id
                ),
            )),
            State::Detaching | State::DetachFailed | State::Released => Err(refused(
                "hardware_detach_unconfirmed",
                format!(
                    "the reservation for {} is {}; it is detached or released before anything attaches again",
                    device.mapping_id,
                    reservation.state.id()
                ),
            )),
        }
    }

    /// The recorded guest must be this guest: a row that names another one
    /// is never attached here and never touched. The account and the VMID
    /// identify the guest; the node is not compared, because a guest that
    /// migrated since the row recorded it is still the same guest (the node
    /// is resolved live where it matters).
    fn same_guest(
        guest: &LeaseGuest<'_>,
        reservation: &HardwareReservation,
    ) -> Result<(), AttachFailure> {
        match &reservation.guest {
            Some(recorded)
                if recorded.account_id == guest.account_id && recorded.vmid == guest.vmid =>
            {
                Ok(())
            }
            other => Err(refused(
                "hardware_guest_mismatch",
                format!(
                    "the reservation records guest {:?}, not qemu/{} through account {}",
                    other
                        .as_ref()
                        .map(|recorded| (&recorded.account_id, recorded.vmid)),
                    guest.vmid,
                    guest.account_id
                ),
            )),
        }
    }

    /// Whether the provision was cancelled. A step that belongs to no
    /// operation (a mid-run hotplug request) has nothing to cancel.
    async fn cancelled(
        operations: Option<&Operations>,
        guest: &LeaseGuest<'_>,
    ) -> Result<(), AttachFailure> {
        let (Some(operations), Some(operation_id)) = (operations, guest.operation_id) else {
            return Ok(());
        };
        if operations
            .cancel_requested(operation_id)
            .await
            .map_err(|error| AttachFailure::Infrastructure(error.to_string()))?
        {
            return Err(refused(
                "cancelled",
                "the provision was cancelled before the device was written; the reservation is released with the lease",
            ));
        }
        Ok(())
    }

    /// Verify, record, write, read back. `resumed` is a row that already
    /// recorded an attach (a crashed run): the record was made before the
    /// write, so it proves nothing about an entry the guest shows. Such an
    /// entry is never adopted (it may be an operator's identical one) and
    /// never deleted: the row becomes `attach_unknown` with no slot, and the
    /// provision fails.
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    async fn attach_held(
        &self,
        operations: Option<&Operations>,
        guest: &LeaseGuest<'_>,
        request: &PveHttpRequest,
        device: &HardwareDevice,
        reservation: HardwareReservation,
        resumed: bool,
        keep: Disposition,
    ) -> Result<HardwareReservation, AttachFailure> {
        Self::cancelled(operations, guest).await?;
        self.verify(guest, device, &reservation).await?;
        Self::cancelled(operations, guest).await?;
        let mapping = device.mapping_id.as_str();

        // The slot the write is expected to use, recorded before the write.
        let (reservation, slot) = if resumed {
            match self
                .references_of(request, guest.node, guest.vmid, mapping)
                .await
            {
                Ok(held) if held.is_empty() => {}
                Ok(held) => {
                    let detail = format!(
                        "the guest references {mapping} in {} and the row only recorded the attach, so nothing shows Fleet wrote it; it was left untouched",
                        held.join(", ")
                    );
                    return self
                        .leave_unknown(
                            guest,
                            device,
                            &reservation,
                            "hardware_attach_unknown",
                            &detail,
                            None,
                        )
                        .await;
                }
                Err(read) => {
                    return Err(refused(
                        "hardware_attach_failed",
                        format!("the guest could not be read before the resumed attach: {read}"),
                    ));
                }
            }
            let slot = reservation
                .guest
                .as_ref()
                .and_then(|recorded| recorded.usb_slot)
                .map(slot_name);
            (reservation, slot)
        } else {
            let references = match self
                .client
                .qemu_usb_references(request.clone(), guest.node, guest.vmid, true)
                .await
            {
                Ok(references) => references,
                Err(error) => {
                    return Err(refused(
                        "hardware_attach_failed",
                        format!("the guest's USB entries are unreadable: {error}"),
                    ));
                }
            };
            if references.template {
                return Err(refused(
                    "hardware_attach_failed",
                    "the guest is a template; Fleet does not change it",
                ));
            }
            if let Some(detail) = &references.applied_unread {
                return Err(refused(
                    "hardware_attach_failed",
                    format!("the guest's running USB entries are unreadable: {detail}"),
                ));
            }
            if let Some(held) = references
                .references
                .iter()
                .find(|reference| reference.mapping_id == mapping)
            {
                return Err(refused(
                    "hardware_externally_attached",
                    format!(
                        "the guest already references {mapping} in {} before Fleet attached it (an entry the template carries or an operator wrote); Fleet does not delete an entry it did not write",
                        held.slot
                    ),
                ));
            }
            let taken: BTreeSet<u8> = references
                .references
                .iter()
                .filter_map(|reference| slot_index(&reference.slot))
                .collect();
            let Some(predicted) = (0..USB_SLOT_COUNT).find(|index| !taken.contains(index)) else {
                return Err(refused(
                    "hardware_no_free_slot",
                    "every USB slot of the guest is taken",
                ));
            };
            // The intent is required: an attach the audit sink refused is
            // not made.
            self.event(
                "hardware_attach_requested",
                device,
                &reservation,
                guest.operation_id,
                &[
                    ("node", guest.node.to_owned()),
                    ("guest_vmid", guest.vmid.to_string()),
                    ("usb_slot", slot_name(predicted)),
                ],
                true,
            )
            .await
            .map_err(|detail| {
                AttachFailure::Infrastructure(format!("the attach audit failed: {detail}"))
            })?;
            let target = GuestTarget {
                account_id: guest.account_id.to_owned(),
                node: guest.node.to_owned(),
                vmid: guest.vmid,
                usb_slot: Some(predicted),
            };
            let moved = match self
                .store
                .transition_reservation(
                    &reservation.id,
                    State::Held,
                    State::Attaching,
                    Some(&target),
                    now(),
                )
                .await
            {
                Ok(moved) => moved,
                // The lease's cleanup released the row first (the lease
                // ended after the caller's lease check): nothing was written
                // and nothing is left to undo. This compare-and-set is what
                // keeps an attach from reaching a guest the cleanup is
                // about to destroy.
                Err(HardwareStoreError::IllegalTransition {
                    actual: State::Released,
                    ..
                }) => {
                    let _ = self
                        .event(
                            "hardware_attach_failed",
                            device,
                            &reservation,
                            guest.operation_id,
                            &[
                                ("outcome", "released".to_owned()),
                                ("reason", "hardware_lease_ended".to_owned()),
                            ],
                            false,
                        )
                        .await;
                    return Err(refused(
                        "hardware_lease_ended",
                        "the lease ended before the device was written; its reservation was already released",
                    ));
                }
                Err(error) => return Err(infra(&error)),
            };
            (moved, Some(slot_name(predicted)))
        };

        // The lease may have ended while the device was verified (a release,
        // an expiry, the sweeper's compensation): nothing is written for a
        // lease that no longer counts, and its cleanup finds no entry.
        if !self.lease_counts(guest.lease_id).await {
            return self
                .fail_unwritten(
                    guest,
                    request,
                    device,
                    &reservation,
                    !resumed,
                    "hardware_lease_ended",
                    "the lease ended before the device was written",
                    // A lease that no longer counts holds nothing.
                    Disposition::Release,
                )
                .await;
        }
        let mut attempt = 0;
        let result = loop {
            attempt += 1;
            let result = self
                .client
                .qemu_usb_attach(request.clone(), guest.node, guest.vmid, mapping)
                .await;
            if matches!(result, Err(PveUsbError::DigestConflict)) && attempt < DIGEST_ATTEMPTS {
                continue;
            }
            break result;
        };
        let wrote_or_ours = match result {
            Ok(outcome) => {
                if outcome.change == PveUsbChange::Unchanged {
                    // Nothing was written, and the entry is not shown to be
                    // Fleet's: the guest was verified to reference nothing,
                    // so an operator wrote it in between. Never claimed,
                    // never deleted.
                    return self
                        .fail_unwritten(
                            guest,
                            request,
                            device,
                            &reservation,
                            !resumed,
                            "hardware_externally_attached",
                            &format!(
                                "the guest holds an identical {mapping} entry in {} that Fleet did not write; it was left untouched",
                                outcome.slot
                            ),
                            keep,
                        )
                        .await;
                }
                let index = slot_index(&outcome.slot);
                match (outcome.state, index.filter(|index| *index < USB_SLOT_COUNT)) {
                    (PveUsbState::Applied, Some(index)) => {
                        // The write landed. Recording it can fail when the row
                        // moved meanwhile (cleanup read the guest before the
                        // write and released the `attaching` row): the entry
                        // is then Fleet's, unreserved. Remove exactly what was
                        // written, and say so, instead of propagating.
                        let attached = match self
                            .record_attached(guest, device, &reservation, index, slot.as_deref())
                            .await
                        {
                            Ok(attached) => attached,
                            Err(error) => {
                                return Err(self
                                    .undo_unrecorded_write(
                                        guest,
                                        request,
                                        device,
                                        &reservation,
                                        &outcome.slot,
                                        &error,
                                    )
                                    .await);
                            }
                        };
                        // The lease may have ended during the write, after
                        // cleanup looked: take the device off again now.
                        if !self.lease_counts(guest.lease_id).await {
                            let _ = self
                                .detach_reservation(
                                    request,
                                    attached.clone(),
                                    device,
                                    guest.operation_id,
                                    guest.lease_id,
                                    true,
                                    Disposition::Release,
                                )
                                .await;
                            return Err(refused(
                                "hardware_lease_ended",
                                "the lease ended while the device was written; it was detached again",
                            ));
                        }
                        return Ok(attached);
                    }
                    (PveUsbState::Applied, None) => (
                        outcome.slot,
                        "hardware_no_free_slot",
                        format!(
                            "{mapping} was attached to {}, beyond the {USB_SLOT_COUNT} slots Fleet records; it is being removed",
                            slot_name(USB_SLOT_COUNT)
                        ),
                    ),
                    (PveUsbState::Pending, _) => (
                        outcome.slot,
                        "hardware_attach_pending",
                        format!(
                            "PVE stored {mapping} as pending until the guest restarts (its hotplug option lacks usb); the entry is being removed"
                        ),
                    ),
                }
            }
            Err(error) => {
                return self
                    .fail_attach(
                        guest,
                        request,
                        device,
                        &reservation,
                        !resumed,
                        slot,
                        error,
                        keep,
                    )
                    .await;
            }
        };
        // The entry is there and cannot be kept: remove it through the
        // detach path (recorded slot: the one PVE reported).
        let (_, reason, detail) = wrote_or_ours;
        let result = self
            .detach_reservation(
                request,
                reservation.clone(),
                device,
                guest.operation_id,
                guest.lease_id,
                true,
                keep,
            )
            .await;
        let outcome = match (result, keep) {
            (Ok(DetachResult::Detached), Disposition::Release) => "released",
            (Ok(DetachResult::Detached), Disposition::KeepHeld) => "held",
            _ => "unknown",
        };
        let _ = self
            .event(
                "hardware_attach_failed",
                device,
                &reservation,
                guest.operation_id,
                &[
                    ("outcome", outcome.to_owned()),
                    ("reason", reason.to_owned()),
                ],
                false,
            )
            .await;
        Err(refused(reason, detail))
    }

    /// A write that landed could not be recorded (the row was released or
    /// moved by someone else meanwhile). Deletes exactly what was written, the
    /// `mapping=<id>` value in the slot the provider reported (the provider
    /// deletes only that exact value), behind the same required audit intent
    /// as every delete, and answers the refusal that surfaces the condition:
    /// a refused or failed delete leaves Fleet's entry on a guest with no
    /// reservation behind it, which the detail and the audit event name.
    async fn undo_unrecorded_write(
        &self,
        guest: &LeaseGuest<'_>,
        request: &PveHttpRequest,
        device: &HardwareDevice,
        reservation: &HardwareReservation,
        slot: &str,
        why: &HardwareStoreError,
    ) -> AttachFailure {
        let mapping = device.mapping_id.as_str();
        let facts = [
            ("node", guest.node.to_owned()),
            ("guest_vmid", guest.vmid.to_string()),
            ("usb_slot", slot.to_owned()),
        ];
        let intent = self
            .event(
                "hardware_detach_requested",
                device,
                reservation,
                guest.operation_id,
                &facts,
                true,
            )
            .await;
        let removed = match intent {
            Err(detail) => Err(format!(
                "the detach audit failed, so nothing was deleted: {detail}"
            )),
            Ok(()) => match self
                .client
                .qemu_usb_detach(request.clone(), guest.node, guest.vmid, slot, mapping)
                .await
            {
                Ok(done) if done.state == PveUsbState::Applied => Ok(()),
                Ok(_) => Err("PVE keeps the removal pending until the guest restarts".to_owned()),
                Err(error) => Err(error.to_string()),
            },
        };
        let (outcome, tail) = match &removed {
            Ok(()) => (
                "removed",
                "the entry Fleet wrote was removed again".to_owned(),
            ),
            Err(detail) => (
                "unremoved",
                format!(
                    "the entry Fleet wrote in {slot} is STILL on the guest with no reservation behind it ({detail})"
                ),
            ),
        };
        let _ = self
            .event(
                "hardware_attach_failed",
                device,
                reservation,
                guest.operation_id,
                &[
                    ("outcome", outcome.to_owned()),
                    ("reason", "hardware_attach_unrecorded".to_owned()),
                    ("usb_slot", slot.to_owned()),
                ],
                false,
            )
            .await;
        refused(
            "hardware_attach_unrecorded",
            format!(
                "{mapping} was written to {slot} but the reservation could not be recorded ({why}); {tail}"
            ),
        )
    }

    /// The write was read back applied: record the attachment, with the slot
    /// the provider reports.
    async fn record_attached(
        &self,
        guest: &LeaseGuest<'_>,
        device: &HardwareDevice,
        reservation: &HardwareReservation,
        index: u8,
        predicted: Option<&str>,
    ) -> Result<HardwareReservation, HardwareStoreError> {
        let target = GuestTarget {
            account_id: guest.account_id.to_owned(),
            node: guest.node.to_owned(),
            vmid: guest.vmid,
            usb_slot: Some(index),
        };
        let attached = self
            .store
            .transition_reservation(
                &reservation.id,
                reservation.state,
                State::Attached,
                Some(&target),
                now(),
            )
            .await?;
        let slot = slot_name(index);
        let mut facts = vec![
            ("node", guest.node.to_owned()),
            ("guest_vmid", guest.vmid.to_string()),
            ("usb_slot", slot.clone()),
        ];
        if predicted.is_some_and(|predicted| predicted != slot) {
            facts.push(("slot_corrected", "true".to_owned()));
        }
        let _ = self
            .event(
                "hardware_attached",
                device,
                &attached,
                guest.operation_id,
                &facts,
                false,
            )
            .await;
        Ok(attached)
    }

    /// Classifies a failed attach call and compensates.
    #[allow(clippy::too_many_arguments)]
    async fn fail_attach(
        &self,
        guest: &LeaseGuest<'_>,
        request: &PveHttpRequest,
        device: &HardwareDevice,
        reservation: &HardwareReservation,
        fresh: bool,
        predicted: Option<String>,
        error: PveUsbError,
        keep: Disposition,
    ) -> Result<HardwareReservation, AttachFailure> {
        let detail = error.to_string();
        match error {
            // Nothing was written by this call.
            PveUsbError::InvalidInput { .. }
            | PveUsbError::Template
            | PveUsbError::Locked { .. }
            | PveUsbError::DigestConflict
            | PveUsbError::Refused { .. }
            | PveUsbError::SlotsFull { .. }
            | PveUsbError::ForeignSlot { .. }
            | PveUsbError::Ambiguous { .. }
            | PveUsbError::PendingConflict { .. }
            | PveUsbError::Api(_) => {
                let reason = match &error {
                    PveUsbError::ForeignSlot { .. }
                    | PveUsbError::Ambiguous { .. }
                    | PveUsbError::PendingConflict { .. } => "hardware_externally_attached",
                    PveUsbError::SlotsFull { .. } => "hardware_no_free_slot",
                    _ => "hardware_attach_failed",
                };
                self.fail_unwritten(
                    guest,
                    request,
                    device,
                    reservation,
                    fresh,
                    reason,
                    &detail,
                    keep,
                )
                .await
            }
            PveUsbError::WriteFailed {
                cleanup: PveUsbCleanup::Removed | PveUsbCleanup::NothingToRemove,
                ..
            } => {
                // The provider wrote and removed its entry. A reference that
                // is there afterwards is not shown to be Fleet's.
                self.fail_unwritten(
                    guest,
                    request,
                    device,
                    reservation,
                    false,
                    "hardware_attach_failed",
                    &detail,
                    keep,
                )
                .await
            }
            PveUsbError::WriteFailed {
                cleanup: PveUsbCleanup::Failed { slot, .. },
                ..
            }
            | PveUsbError::ReadBackMismatch { slot, .. } => {
                self.leave_unknown(
                    guest,
                    device,
                    reservation,
                    "hardware_attach_unknown",
                    &detail,
                    Some(slot),
                )
                .await
            }
            PveUsbError::Indeterminate { slot, .. } => {
                self.leave_unknown(
                    guest,
                    device,
                    reservation,
                    "hardware_attach_unknown",
                    &detail,
                    slot.or(predicted),
                )
                .await
            }
        }
    }

    /// The attach wrote nothing Fleet can claim (the provider's contract for
    /// its refusals, `Unchanged`, and a failed write whose leftover was
    /// removed): read every `usbN` entry back. A guest that holds no
    /// reference to the mapping releases the row. A reference that is there
    /// was not written by this attach, so it is never claimed and never
    /// deleted: the row is `attach_unknown` with no slot, which cleanup only
    /// ever releases when the guest shows no reference, and otherwise leaves
    /// to an operator. An unreadable guest is the same unproven state.
    #[allow(clippy::too_many_arguments)]
    async fn fail_unwritten(
        &self,
        guest: &LeaseGuest<'_>,
        request: &PveHttpRequest,
        device: &HardwareDevice,
        reservation: &HardwareReservation,
        fresh: bool,
        reason: &'static str,
        detail: &str,
        keep: Disposition,
    ) -> Result<HardwareReservation, AttachFailure> {
        match self
            .references_of(request, guest.node, guest.vmid, &device.mapping_id)
            .await
        {
            Ok(held) if held.is_empty() => {
                self.release_failed(guest, device, reservation, reason, detail, keep)
                    .await
            }
            // Fresh attempt (the verify step proved nothing referenced the
            // mapping): the entry is somebody else's, and the row holds
            // nothing on the guest.
            Ok(_) if fresh => {
                self.release_failed(guest, device, reservation, reason, detail, keep)
                    .await
            }
            Ok(held) => {
                let detail = format!(
                    "{detail}; the guest references the mapping in {} and Fleet cannot show it wrote that entry",
                    held.join(", ")
                );
                self.leave_unknown(guest, device, reservation, reason, &detail, None)
                    .await
            }
            Err(read) => {
                let detail = format!("{detail}; the guest could not be read back: {read}");
                self.leave_unknown(guest, device, reservation, reason, &detail, None)
                    .await
            }
        }
    }

    /// The entry is confirmed absent: release through `detaching` (or, for a
    /// lease that still holds the device, return it to `held`).
    async fn release_failed(
        &self,
        guest: &LeaseGuest<'_>,
        device: &HardwareDevice,
        reservation: &HardwareReservation,
        reason: &'static str,
        detail: &str,
        keep: Disposition,
    ) -> Result<HardwareReservation, AttachFailure> {
        let detaching = self
            .store
            .transition_reservation(
                &reservation.id,
                reservation.state,
                State::Detaching,
                None,
                now(),
            )
            .await
            .map_err(|error| infra(&error))?;
        self.finish_detached(guest.operation_id, &detaching, keep)
            .await
            .map_err(|error| infra(&error))?;
        let _ = self
            .event(
                "hardware_attach_failed",
                device,
                &detaching,
                guest.operation_id,
                &[
                    (
                        "outcome",
                        match keep {
                            Disposition::Release => "released",
                            Disposition::KeepHeld => "held",
                        }
                        .to_owned(),
                    ),
                    ("reason", reason.to_owned()),
                ],
                false,
            )
            .await;
        Err(refused(
            reason,
            match keep {
                Disposition::Release => format!(
                    "{detail}; the guest holds nothing Fleet wrote and the reservation was released"
                ),
                Disposition::KeepHeld => format!(
                    "{detail}; the guest holds nothing Fleet wrote and the lease still holds the device"
                ),
            },
        ))
    }

    /// Releases a row through the reservation store. A release a caller's own
    /// request causes (mid-run hotplug) is filed under the action the caller
    /// was authorized for; the lease's provision and cleanup keep the owner's
    /// default.
    async fn release_row(
        &self,
        operation_id: Option<&str>,
        id: &str,
    ) -> Result<(), HardwareStoreError> {
        let context = self.audit_context(operation_id);
        match self.actor.source {
            Some(_) => self
                .reservations
                .release_under(&context, self.actor.action, id, now())
                .await
                .map(|_| ()),
            None => self
                .reservations
                .release(&context, id, now())
                .await
                .map(|_| ()),
        }
    }

    /// A confirmed-absent device leaves its `detaching` row: released, or
    /// (for a lease that still holds the device) back in `held` with the slot
    /// cleared. A row somebody else already released (the lease ended while
    /// the request ran) is not an error for either.
    async fn finish_detached(
        &self,
        operation_id: Option<&str>,
        detaching: &HardwareReservation,
        keep: Disposition,
    ) -> Result<(), HardwareStoreError> {
        match keep {
            Disposition::Release => self.release_row(operation_id, &detaching.id).await,
            Disposition::KeepHeld => match self
                .store
                .transition_reservation(&detaching.id, State::Detaching, State::Held, None, now())
                .await
            {
                Ok(_) => Ok(()),
                Err(HardwareStoreError::IllegalTransition {
                    actual: State::Released,
                    ..
                }) => Ok(()),
                Err(error) => Err(error),
            },
        }
    }

    /// The outcome cannot be determined: `attach_unknown`. With a slot, an
    /// attempted write of Fleet's may be there and cleanup removes it by
    /// reading the guest; with no slot, nothing shows Fleet wrote whatever is
    /// there, and cleanup never deletes it.
    async fn leave_unknown(
        &self,
        guest: &LeaseGuest<'_>,
        device: &HardwareDevice,
        reservation: &HardwareReservation,
        reason: &'static str,
        detail: &str,
        slot: Option<String>,
    ) -> Result<HardwareReservation, AttachFailure> {
        let unknown = self
            .mark_unknown(
                reservation,
                guest.account_id,
                guest.node,
                guest.vmid,
                slot.as_deref()
                    .and_then(slot_index)
                    .filter(|index| *index < USB_SLOT_COUNT),
            )
            .await
            .map_err(|error| infra(&error))?;
        let _ = self
            .event(
                "hardware_attach_failed",
                device,
                &unknown,
                guest.operation_id,
                &[
                    ("outcome", "unknown".to_owned()),
                    ("reason", reason.to_owned()),
                ],
                false,
            )
            .await;
        Err(refused(
            reason,
            format!(
                "{detail}; the reservation is attach_unknown and the lease's cleanup resolves it"
            ),
        ))
    }

    /// Moves a row to `attach_unknown` with the given slot (`None`: the
    /// ownership of anything on the guest is unproven).
    async fn mark_unknown(
        &self,
        reservation: &HardwareReservation,
        account_id: &str,
        node: &str,
        vmid: u32,
        slot: Option<u8>,
    ) -> Result<HardwareReservation, HardwareStoreError> {
        let target = GuestTarget {
            account_id: account_id.to_owned(),
            node: node.to_owned(),
            vmid,
            usb_slot: slot,
        };
        // `attach_unknown` to `attach_unknown` is not an edge: a row that
        // is already unknown keeps its record.
        if reservation.state == State::AttachUnknown {
            return Ok(reservation.clone());
        }
        self.store
            .transition_reservation(
                &reservation.id,
                reservation.state,
                State::AttachUnknown,
                Some(&target),
                now(),
            )
            .await
    }

    /// The slots of the guest that reference `mapping`, in either view.
    /// Fails when the guest cannot be read in full.
    async fn references_of(
        &self,
        request: &PveHttpRequest,
        node: &str,
        vmid: u32,
        mapping: &str,
    ) -> Result<Vec<String>, String> {
        let read = self
            .client
            .qemu_usb_references(request.clone(), node, vmid, true)
            .await
            .map_err(|error| error.to_string())?;
        if let Some(detail) = read.applied_unread {
            return Err(format!("the running configuration is unreadable: {detail}"));
        }
        Ok(read
            .references
            .into_iter()
            .filter(|reference| reference.mapping_id == mapping)
            .map(|reference| reference.slot)
            .collect())
    }

    /// Re-observes and verifies the device immediately before an attach.
    async fn verify(
        &self,
        guest: &LeaseGuest<'_>,
        device: &HardwareDevice,
        reservation: &HardwareReservation,
    ) -> Result<(), AttachFailure> {
        let mapping = device.mapping_id.as_str();
        // The fingerprint the device had when it was reserved is the one it
        // must still have. A reservation without a pin (taken before the pin
        // existed, or interrupted between the reserve and the pin) is pinned
        // from the stored entry now: the limit is that a refresh in between
        // would already have moved that entry.
        let expected = match self
            .pins
            .pinned(&reservation.id)
            .await
            .map_err(AttachFailure::Infrastructure)?
        {
            Some(pinned) => pinned,
            None => {
                let entry = device
                    .entries
                    .iter()
                    .find(|entry| entry.node == guest.node)
                    .ok_or_else(|| {
                        refused(
                            "hardware_no_node_entry",
                            format!("hardware {mapping} has no entry for node {}", guest.node),
                        )
                    })?;
                let pinned = PinnedFingerprint::of(entry);
                self.pins
                    .pin(&reservation.id, &pinned, now())
                    .await
                    .map_err(AttachFailure::Infrastructure)?;
                pinned
            }
        };
        if expected.node != guest.node {
            return Err(refused(
                "hardware_wrong_node",
                format!(
                    "hardware {mapping} was reserved on node {}, not on node {}",
                    expected.node, guest.node
                ),
            ));
        }
        let report = self
            .inventory
            .refresh(
                &fleet_auth::LanAllowAllAuthorizer,
                &ActingPrincipal {
                    id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
                },
                Some(guest.lease_id),
                guest.account_id,
            )
            .await
            .map_err(|error| {
                refused(
                    "hardware_verify_failed",
                    format!("the device could not be re-observed: {error}"),
                )
            })?;
        if report.support != AccountSupport::Supported {
            return Err(refused(
                "hardware_unsupported",
                format!(
                    "the account's USB inventory is {}{}",
                    report.support.state(),
                    report
                        .support
                        .reason()
                        .map(|reason| format!(": {}", reason.text()))
                        .unwrap_or_default()
                ),
            ));
        }
        // The scan sees only the guests the token may audit: PVE omits a guest
        // without `VM.Audit` from the cluster listing, so `listed == read`
        // proves nothing about a guest the token cannot see, and PVE gives a
        // mapping no exclusivity (#596). Unless the token's permissions show
        // `VM.Audit` on every guest, a device that another guest drives would
        // read available, so no attach is made.
        match &report.guest_visibility {
            Some(visibility) if visibility.is_verified() => {}
            other => {
                return Err(refused(
                    "hardware_guests_unverifiable",
                    format!(
                        "Fleet cannot verify that every guest is visible to its token ({}: {}), so a guest it cannot see may drive {mapping}; grant VM.Audit on /vms to the Fleet user and token (docs/operations/hardware.md)",
                        other
                            .as_ref()
                            .map_or("not assessed", |visibility| visibility.state()),
                        other
                            .as_ref()
                            .and_then(|visibility| visibility.gap())
                            .map_or("no assessment", |gap| gap.id()),
                    ),
                ));
            }
        }
        // `available` for a reserved device is kept on an incomplete guest
        // scan (the reservation is what excludes a second holder), so the
        // scan's completeness is checked here: a guest that was not read may
        // reference the device.
        match &report.guest_scan {
            Some(scan) if !scan.truncated && scan.unreadable == 0 && scan.read == scan.listed => {}
            other => {
                return Err(refused(
                    "hardware_scan_incomplete",
                    format!(
                        "not every guest config could be read at the re-observation ({}); a guest that was not read may reference {mapping}",
                        other.as_ref().map_or_else(
                            || "no guest scan".to_owned(),
                            |scan| format!(
                                "{} of {} read, {} unreadable{}",
                                scan.read,
                                scan.listed,
                                scan.unreadable,
                                if scan.truncated { ", truncated" } else { "" }
                            )
                        )
                    ),
                ));
            }
        }
        let found = report
            .devices
            .iter()
            .find(|seen| seen.view.device.id == device.id)
            .ok_or_else(|| {
                refused(
                    "hardware_unknown",
                    format!("hardware {mapping} is gone from the inventory"),
                )
            })?;
        if found.view.holder.as_ref().map(|holder| holder.id.as_str())
            != Some(reservation.id.as_str())
        {
            return Err(refused(
                "hardware_reservation_lost",
                format!("hardware {mapping} is no longer held by this lease's reservation"),
            ));
        }
        match found.view.device.status {
            DeviceStatus::Available | DeviceStatus::Reserved => {}
            DeviceStatus::Missing => {
                return Err(refused(
                    "hardware_missing",
                    format!(
                        "hardware {mapping} was not found on node {} at the re-observation before the attach",
                        guest.node
                    ),
                ));
            }
            DeviceStatus::Unsupported(reason) => {
                return Err(refused(
                    "hardware_unsupported",
                    format!(
                        "hardware {mapping} is unsupported ({}): {}",
                        reason.id(),
                        reason_text(reason)
                    ),
                ));
            }
            DeviceStatus::ExternallyAttached => {
                return Err(refused(
                    "hardware_externally_attached",
                    format!("hardware {mapping} is attached to a guest Fleet did not attach it to"),
                ));
            }
            DeviceStatus::Quarantined => {
                return Err(refused(
                    "hardware_quarantined",
                    format!("hardware {mapping} is quarantined"),
                ));
            }
        }
        if let Some(external) = found
            .external_references
            .iter()
            .find(|reference| !reference.template)
        {
            return Err(refused(
                "hardware_externally_attached",
                format!(
                    "hardware {mapping} is referenced by qemu/{} on {} ({}), a guest other than this lease's",
                    external.vmid, external.node, external.slot
                ),
            ));
        }
        let Some(entry) = found
            .view
            .device
            .entries
            .iter()
            .find(|entry| entry.node == guest.node)
        else {
            return Err(refused(
                "hardware_no_node_entry",
                format!("hardware {mapping} has no entry for node {}", guest.node),
            ));
        };
        if now().saturating_sub(entry.last_seen_at).abs() > self.max_age_ms {
            return Err(refused(
                "hardware_stale",
                format!(
                    "hardware {mapping} was not seen on node {} by the re-observation",
                    guest.node
                ),
            ));
        }
        if entry.vendor_id != expected.vendor_id
            || entry.product_id != expected.product_id
            || entry.usbpath != expected.usbpath
        {
            return Err(refused(
                "hardware_fingerprint_changed",
                format!(
                    "hardware {mapping} on node {} is {}:{} at {} now, not {}:{} at {} as it was when it was reserved; a cable or the mapping changed",
                    guest.node,
                    entry.vendor_id,
                    entry.product_id,
                    entry.usbpath.as_deref().unwrap_or("an unknown port"),
                    expected.vendor_id,
                    expected.product_id,
                    expected.usbpath.as_deref().unwrap_or("an unknown port"),
                ),
            ));
        }
        Ok(())
    }

    // ── mid-run hotplug (FM-1126) ────────────────────────────────────────

    /// Attaches a device the lease holds in `held` to its running guest:
    /// the same verify, record, write and read-back as the provision's
    /// attach, minus a provision operation to cancel. Whatever does not end
    /// attached leaves the lease holding the device in `held` (a refused,
    /// failed or pending attach), unless the lease no longer counts.
    ///
    /// A pending attach (the guest's `hotplug` option lacks `usb`) is removed
    /// again and reported as the refusal `hardware_attach_pending`: it is
    /// never attached, and a later restart cannot attach a device nobody
    /// confirmed.
    ///
    /// # Errors
    ///
    /// [`AttachFailure::Refused`] with the stable reason, or
    /// [`AttachFailure::Infrastructure`].
    pub(crate) async fn hotplug_attach(
        &self,
        guest: &LeaseGuest<'_>,
        device: &HardwareDevice,
        reservation: HardwareReservation,
    ) -> Result<HardwareReservation, AttachFailure> {
        if reservation.state != State::Held {
            return Err(refused(
                "hardware_not_detached",
                format!(
                    "the reservation for {} is {}, not held; only a held device attaches",
                    device.mapping_id,
                    reservation.state.id()
                ),
            ));
        }
        if reservation.guest.is_some() {
            Self::same_guest(guest, &reservation)?;
        }
        let request = self
            .request(guest.account_id)
            .await
            .map_err(AttachFailure::Infrastructure)?;
        // The guest may have moved since the provision recorded its node.
        let node = self
            .live_node(&request, guest.vmid)
            .await
            .unwrap_or_else(|| guest.node.to_owned());
        let guest = LeaseGuest {
            node: &node,
            ..*guest
        };
        let before = reservation.clone();
        let result = self
            .attach_held(
                None,
                &guest,
                &request,
                device,
                reservation,
                false,
                Disposition::KeepHeld,
            )
            .await;
        // The caller sees a refusal's reason and a generic detail: what the
        // verify found (another guest's VMID, a device's ids and port) is for
        // the audit trail, not for a lease-bound credential.
        match result {
            Err(AttachFailure::Refused { reason, detail }) if is_revealing(reason) => {
                let _ = self
                    .event(
                        "hardware_refused",
                        device,
                        &before,
                        None,
                        &[
                            ("reason", reason.to_owned()),
                            ("detail", detail),
                            ("node", node.clone()),
                            ("guest_vmid", guest.vmid.to_string()),
                        ],
                        false,
                    )
                    .await;
                Err(AttachFailure::Refused {
                    reason,
                    detail: public_detail(reason).to_owned(),
                })
            }
            other => other,
        }
    }

    /// Detaches an attached device from the guest it was recorded on, with
    /// the detach path's rules (only the recorded slot, only the exact value
    /// Fleet wrote, a read of every `usbN` entry before the row moves).
    /// `release` says whether the lease gives the device up (`released`) or
    /// keeps it (`held`). A `detaching` or `detach_failed` row is retried.
    ///
    /// # Errors
    ///
    /// Fails when the reservation store does.
    pub(crate) async fn hotplug_detach(
        &self,
        reservation: HardwareReservation,
        device: &HardwareDevice,
        lease_id: &str,
        release: bool,
    ) -> Result<DetachResult, HardwareStoreError> {
        let Some(account_id) = reservation
            .guest
            .as_ref()
            .map(|recorded| recorded.account_id.clone())
        else {
            return Ok(DetachResult::Failed(
                "the reservation records no guest to detach from".to_owned(),
            ));
        };
        let request = match self.request(&account_id).await {
            Ok(request) => request,
            Err(detail) => return Ok(DetachResult::Failed(bounded(&detail))),
        };
        self.detach_reservation(
            &request,
            reservation,
            device,
            None,
            lease_id,
            true,
            if release {
                Disposition::Release
            } else {
                Disposition::KeepHeld
            },
        )
        .await
    }

    /// Releases a lease's device that is already detached (`held`, no slot
    /// recorded) because the request gives it up. A `held` row proves nothing
    /// about the guest, so every `usbN` entry is read first: a reference to
    /// the mapping (somebody attached it since) or a guest that cannot be read
    /// in full keeps the row, and the refusal says so.
    ///
    /// # Errors
    ///
    /// [`AttachFailure::Refused`] when the guest still references the mapping
    /// or cannot be read; [`AttachFailure::Infrastructure`] when the store or
    /// the account fails.
    pub(crate) async fn hotplug_release_held(
        &self,
        guest: &LeaseGuest<'_>,
        device: &HardwareDevice,
        reservation: &HardwareReservation,
    ) -> Result<(), AttachFailure> {
        let request = self
            .request(guest.account_id)
            .await
            .map_err(AttachFailure::Infrastructure)?;
        let node = self
            .live_node(&request, guest.vmid)
            .await
            .unwrap_or_else(|| guest.node.to_owned());
        match self
            .references_of(&request, &node, guest.vmid, &device.mapping_id)
            .await
        {
            Ok(held) if held.is_empty() => {}
            Ok(held) => {
                return Err(refused(
                    "hardware_detach_unconfirmed",
                    format!(
                        "the guest references {} in {}; the lease keeps the reservation (detach it first)",
                        device.mapping_id,
                        held.join(", ")
                    ),
                ));
            }
            Err(read) => {
                return Err(refused(
                    "hardware_detach_unconfirmed",
                    format!(
                        "the guest could not be read in full ({read}); the lease keeps the reservation"
                    ),
                ));
            }
        }
        self.release_row(None, &reservation.id)
            .await
            .map_err(|error| infra(&error))
    }

    // ── detach ───────────────────────────────────────────────────────────

    /// Detaches every device the lease holds and releases it, before the
    /// guest's fate (destroy, revert, keep). Idempotent: a released row is
    /// not live, a `detaching` row is continued, a `detach_failed` row is
    /// retried. The live rows are read again after each pass, so a row
    /// that became attached while cleanup ran (a provision still writing) is
    /// taken too.
    ///
    /// A row that holds nothing on the guest (`held`, no slot recorded) is
    /// released here, first, instead of being left for the release after the
    /// guest's fate. A mid-run hotplug attach whose lease check passed before
    /// the lease ended may still be about to move such a row to `attaching`,
    /// and the row's compare-and-set decides who wins. If the release wins,
    /// that attach finds a released row and is refused before it writes
    /// (it never reaches a guest cleanup is about to destroy). If the attach
    /// wins, the release loses and the row, now `attaching`, is detached like
    /// any other row before the guest's fate. Either way no row is left for
    /// the destroy to orphan as `attach_unknown`. A release that fails for
    /// any other reason fails the detach: the guest is kept until it works.
    ///
    /// # Errors
    ///
    /// [`DetachUnconfirmed`] when any device could not be confirmed off the
    /// guest: the caller keeps the lease in cleanup retry and does not
    /// destroy, revert or return the guest.
    pub async fn detach_for_lease(
        &self,
        lease_id: &str,
        operation_id: Option<&str>,
    ) -> Result<(), DetachUnconfirmed> {
        let unconfirmed = |detail: String, guest| DetachUnconfirmed {
            detail: bounded(&detail),
            guest,
        };
        let mut problems = Vec::new();
        let mut guest = None;
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for _pass in 0..DETACH_PASSES {
            let live = self
                .store
                .live_reservations_for_owner(ReservationOwnerKind::Lease, lease_id)
                .await
                .map_err(|error| {
                    unconfirmed(format!("the lease's hardware is unreadable: {error}"), None)
                })?;
            let mut todo: Vec<HardwareReservation> = live
                .into_iter()
                .filter(|row| seen.insert(row.id.clone()))
                .collect();
            if todo.is_empty() {
                break;
            }
            // Rows that hold nothing go first: the sooner they are released,
            // the sooner a straddling hotplug attach is refused.
            todo.sort_by_key(|row| !Self::holds_nothing(row));
            for row in todo {
                let row = if Self::holds_nothing(&row) {
                    match self.claim_unattached(&row, operation_id).await {
                        Ok(None) => continue,
                        // A hotplug attach moved the row first: it is
                        // detached below like any other attaching row.
                        Ok(Some(moved)) => moved,
                        Err(error) => {
                            if let Some(target) = &row.guest {
                                guest.get_or_insert((target.node.clone(), target.vmid));
                            }
                            problems.push(format!(
                                "reservation {} holds nothing but could not be released: {error}",
                                row.id
                            ));
                            continue;
                        }
                    }
                } else {
                    row
                };
                let Some(target) = row.guest.clone() else {
                    problems.push(format!(
                        "reservation {} is {} with no guest recorded",
                        row.id,
                        row.state.id()
                    ));
                    continue;
                };
                let device = match self.store.device(&row.device_id).await {
                    Ok(Some(device)) => device,
                    Ok(None) => {
                        problems.push(format!("device {} of {} is unknown", row.device_id, row.id));
                        continue;
                    }
                    Err(error) => {
                        problems.push(format!("device {} is unreadable: {error}", row.device_id));
                        continue;
                    }
                };
                let request = match self.request(&target.account_id).await {
                    Ok(request) => request,
                    Err(detail) => {
                        guest.get_or_insert((target.node.clone(), target.vmid));
                        problems.push(format!("{}: {detail}", device.mapping_id));
                        continue;
                    }
                };
                // A row that only started its attach proves nothing about an
                // entry the guest shows; the others came from a write Fleet
                // made (or attempted and could not confirm).
                let proven = row.state != State::Attaching;
                let row_id = row.id.clone();
                let first = self
                    .detach_reservation(
                        &request,
                        row,
                        &device,
                        operation_id,
                        lease_id,
                        proven,
                        Disposition::Release,
                    )
                    .await;
                // A request of the lease's holder (a mid-run hotplug) may have
                // moved the row between cleanup's read and its own move: read
                // it once more and continue from where it is, instead of
                // counting a lost race as an unconfirmed detach.
                let outcome = match first {
                    Err(HardwareStoreError::IllegalTransition { .. }) => {
                        self.resync_detach(&request, &row_id, &device, operation_id, lease_id)
                            .await
                    }
                    other => other,
                };
                match outcome {
                    Ok(DetachResult::Detached) => {}
                    Ok(DetachResult::Pending) => {
                        guest.get_or_insert((target.node.clone(), target.vmid));
                        problems.push(format!(
                            "{} is detach_pending: the guest's hotplug option lacks usb, so PVE removes it when the guest restarts",
                            device.mapping_id
                        ));
                    }
                    Ok(DetachResult::Failed(detail)) => {
                        guest.get_or_insert((target.node.clone(), target.vmid));
                        problems.push(format!("{}: {detail}", device.mapping_id));
                    }
                    Err(error) => {
                        guest.get_or_insert((target.node.clone(), target.vmid));
                        problems.push(format!(
                            "{}: the reservation store failed: {error}",
                            device.mapping_id
                        ));
                    }
                }
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(unconfirmed(
                format!(
                    "the lease's hardware is not confirmed detached ({}); the guest is kept until it is",
                    problems.join("; ")
                ),
                guest,
            ))
        }
    }

    /// A row that holds nothing on any guest: `held`, with no `usbN` slot
    /// recorded. It was never attached, or a confirmed detach put it back.
    fn holds_nothing(row: &HardwareReservation) -> bool {
        row.state == State::Held && row.guest.as_ref().is_none_or(|g| g.usb_slot.is_none())
    }

    /// Releases a row that holds nothing, through the store's compare-and-set,
    /// so that a hotplug attach that is about to move it loses or wins
    /// atomically (see [`Self::detach_for_lease`]). Answers `None` when the row
    /// is released (by this call or by somebody else), and the row as it is now
    /// when a writer moved it to a state that needs the detach path.
    async fn claim_unattached(
        &self,
        row: &HardwareReservation,
        operation_id: Option<&str>,
    ) -> Result<Option<HardwareReservation>, HardwareStoreError> {
        let mut current = row.clone();
        // A request of the lease's holder can put a row back to `held` (an
        // attach that wrote nothing); a few rounds are enough for a lease
        // whose cleanup is running.
        for _ in 0..DETACH_PASSES {
            match self.release_row(operation_id, &current.id).await {
                Ok(()) => return Ok(None),
                Err(HardwareStoreError::IllegalTransition { .. }) => {
                    match self.store.reservation(&current.id).await? {
                        None => return Ok(None),
                        Some(fresh) if fresh.state == State::Released => return Ok(None),
                        Some(fresh) if Self::holds_nothing(&fresh) => current = fresh,
                        Some(fresh) => return Ok(Some(fresh)),
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(HardwareStoreError::Backend(
            "the reservation kept changing while it was released".to_owned(),
        ))
    }

    /// Continues a detach whose row another writer moved first: a released
    /// row or a `held` row that records no slot is done, any other live row is
    /// detached from its new state (once; a second lost race is reported).
    async fn resync_detach(
        &self,
        request: &PveHttpRequest,
        id: &str,
        device: &HardwareDevice,
        operation_id: Option<&str>,
        lease_id: &str,
    ) -> Result<DetachResult, HardwareStoreError> {
        let Some(fresh) = self.store.reservation(id).await? else {
            return Ok(DetachResult::Detached);
        };
        match fresh.state {
            State::Released => Ok(DetachResult::Detached),
            State::Held if fresh.guest.as_ref().is_none_or(|g| g.usb_slot.is_none()) => {
                Ok(DetachResult::Detached)
            }
            state => {
                self.detach_reservation(
                    request,
                    fresh,
                    device,
                    operation_id,
                    lease_id,
                    state != State::Attaching,
                    Disposition::Release,
                )
                .await
            }
        }
    }

    /// Detaches one reservation. The row is released only after a read of
    /// every `usbN` entry of the guest (and, when Fleet deleted one, the
    /// provider's read-back of the slot) shows no reference to the mapping.
    ///
    /// `proven` says the caller knows Fleet wrote (or attempted to write) the
    /// entry. A row that only recorded its attach proves nothing: an entry
    /// the guest shows may be an operator's identical one, so it is never
    /// deleted and the row is left `attach_unknown` without a slot, which
    /// stays that way until the guest shows nothing or an operator decides.
    ///
    /// `keep` says what a confirmed detach leaves of the row.
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub(crate) async fn detach_reservation(
        &self,
        request: &PveHttpRequest,
        reservation: HardwareReservation,
        device: &HardwareDevice,
        operation_id: Option<&str>,
        lease_id: &str,
        proven: bool,
        keep: Disposition,
    ) -> Result<DetachResult, HardwareStoreError> {
        let mapping = device.mapping_id.as_str();
        let Some(recorded) = reservation.guest.clone() else {
            // Never attached: nothing on any guest to remove. A row that is
            // kept is already `held`; a released one is released here.
            if keep == Disposition::Release {
                self.release_row(operation_id, &reservation.id).await?;
            }
            return Ok(DetachResult::Detached);
        };
        let mut recorded_slot = recorded.usb_slot.map(slot_name);
        let owned = proven && recorded_slot.is_some();
        // The guest may have moved since the row recorded it.
        let node = self
            .live_node(request, recorded.vmid)
            .await
            .unwrap_or_else(|| recorded.node.clone());

        // Every state but `attached` may hold the entry in a slot other than
        // the recorded one (a prediction that was wrong), or none at all (a
        // slot that sat on somebody's `host=` entry): the guest says which.
        if reservation.state != State::Attached {
            match self
                .references_of(request, &node, recorded.vmid, mapping)
                .await
            {
                // The full read shows nothing Fleet could have written: the
                // device is not on the guest, whatever the row recorded.
                Ok(held) if held.is_empty() => {
                    return self
                        .release_absent(&reservation, device, operation_id, &node, &recorded, keep)
                        .await;
                }
                Ok(held) if !owned => {
                    return self
                        .unproven(
                            &reservation,
                            device,
                            operation_id,
                            &recorded,
                            format!(
                                "the guest references the mapping in {}, and nothing shows Fleet wrote it (the row only recorded the attach); it is left untouched",
                                held.join(", ")
                            ),
                        )
                        .await;
                }
                Ok(held) => match held.as_slice() {
                    [only] => recorded_slot = Some(only.clone()),
                    many => {
                        return self
                            .detach_failed(
                                &reservation,
                                device,
                                operation_id,
                                format!(
                                    "the guest references the mapping in more than one slot ({}); Fleet does not guess which it wrote",
                                    many.join(", ")
                                ),
                            )
                            .await;
                    }
                },
                Err(detail) => {
                    return self
                        .detach_failed(
                            &reservation,
                            device,
                            operation_id,
                            format!("the guest could not be read: {detail}"),
                        )
                        .await;
                }
            }
        }
        let Some(slot) = recorded_slot else {
            return self
                .detach_failed(
                    &reservation,
                    device,
                    operation_id,
                    "no usb slot was recorded for the attach".to_owned(),
                )
                .await;
        };

        // The row moves to `detaching` (carrying the slot and node it is
        // detached from) before the write, so a crash resumes here.
        let detaching = if reservation.state == State::Detaching {
            reservation
        } else {
            let target = GuestTarget {
                account_id: recorded.account_id.clone(),
                node: node.clone(),
                vmid: recorded.vmid,
                usb_slot: slot_index(&slot).filter(|index| *index < USB_SLOT_COUNT),
            };
            self.store
                .transition_reservation(
                    &reservation.id,
                    reservation.state,
                    State::Detaching,
                    Some(&target),
                    now(),
                )
                .await?
        };
        let facts = |extra: &[(&'static str, String)]| -> Vec<(&'static str, String)> {
            let mut all = vec![
                ("node", node.clone()),
                ("guest_vmid", recorded.vmid.to_string()),
                ("usb_slot", slot.clone()),
                ("lease_id", lease_id.to_owned()),
            ];
            all.extend(extra.iter().cloned());
            all
        };
        // The intent is required: a delete the audit sink refused is not
        // made (the outcome events below stay best effort).
        if let Err(detail) = self
            .event(
                "hardware_detach_requested",
                device,
                &detaching,
                operation_id,
                &facts(&[]),
                true,
            )
            .await
        {
            return self
                .detach_failed(
                    &detaching,
                    device,
                    operation_id,
                    format!("the detach audit failed, so nothing was deleted: {detail}"),
                )
                .await;
        }
        let outcome = self
            .client
            .qemu_usb_detach(request.clone(), &node, recorded.vmid, &slot, mapping)
            .await;
        match outcome {
            Ok(done) if done.state == PveUsbState::Applied => {
                match self
                    .references_of(request, &node, recorded.vmid, mapping)
                    .await
                {
                    Ok(held) if held.is_empty() => {
                        self.finish_detached(operation_id, &detaching, keep).await?;
                        let _ = self
                            .event(
                                "hardware_detached",
                                device,
                                &detaching,
                                operation_id,
                                &facts(&[]),
                                false,
                            )
                            .await;
                        Ok(DetachResult::Detached)
                    }
                    Ok(held) => {
                        self.detach_failed(
                            &detaching,
                            device,
                            operation_id,
                            format!(
                                "the guest still references the mapping in {}",
                                held.join(", ")
                            ),
                        )
                        .await
                    }
                    Err(detail) => {
                        self.detach_failed(
                            &detaching,
                            device,
                            operation_id,
                            format!("the detach could not be confirmed: {detail}"),
                        )
                        .await
                    }
                }
            }
            Ok(_) => {
                let _ = self
                    .event(
                        "hardware_detach_pending",
                        device,
                        &detaching,
                        operation_id,
                        &facts(&[]),
                        false,
                    )
                    .await;
                Ok(DetachResult::Pending)
            }
            Err(error) => {
                self.detach_failed(&detaching, device, operation_id, error.to_string())
                    .await
            }
        }
    }

    /// The guest shows no reference to the mapping: release (or keep held)
    /// without a delete (nothing was written by this step, so nothing is
    /// audited as an intent), through `detaching`.
    async fn release_absent(
        &self,
        reservation: &HardwareReservation,
        device: &HardwareDevice,
        operation_id: Option<&str>,
        node: &str,
        recorded: &GuestTarget,
        keep: Disposition,
    ) -> Result<DetachResult, HardwareStoreError> {
        let detaching = if reservation.state == State::Detaching {
            reservation.clone()
        } else {
            self.store
                .transition_reservation(
                    &reservation.id,
                    reservation.state,
                    State::Detaching,
                    None,
                    now(),
                )
                .await?
        };
        self.finish_detached(operation_id, &detaching, keep).await?;
        let _ = self
            .event(
                "hardware_detached",
                device,
                &detaching,
                operation_id,
                &[
                    ("node", node.to_owned()),
                    ("guest_vmid", recorded.vmid.to_string()),
                    ("confirmed_absent", "true".to_owned()),
                ],
                false,
            )
            .await;
        Ok(DetachResult::Detached)
    }

    /// An entry the guest shows cannot be shown to be Fleet's: the row is
    /// `attach_unknown` with no slot (so no later attempt deletes it) and the
    /// detach is reported unconfirmed.
    async fn unproven(
        &self,
        reservation: &HardwareReservation,
        device: &HardwareDevice,
        operation_id: Option<&str>,
        recorded: &GuestTarget,
        detail: String,
    ) -> Result<DetachResult, HardwareStoreError> {
        let marked = match reservation.state {
            State::Attaching | State::AttachUnknown => {
                self.mark_unknown(
                    reservation,
                    &recorded.account_id,
                    &recorded.node,
                    recorded.vmid,
                    None,
                )
                .await?
            }
            // Other states are never unproven by construction; fail closed
            // without touching the row.
            _ => reservation.clone(),
        };
        let detail = bounded(&detail);
        let _ = self
            .event(
                "hardware_detach_failed",
                device,
                &marked,
                operation_id,
                &[("reason", detail.clone())],
                false,
            )
            .await;
        Ok(DetachResult::Failed(detail))
    }

    /// Records a failed or unconfirmed detach: the row goes `detach_failed`
    /// (quarantined) and stays held. Never released. A row that only
    /// recorded its attach stays unproven (`attach_unknown`, no slot).
    async fn detach_failed(
        &self,
        reservation: &HardwareReservation,
        device: &HardwareDevice,
        operation_id: Option<&str>,
        detail: String,
    ) -> Result<DetachResult, HardwareStoreError> {
        let failed = match reservation.state {
            State::Detaching => {
                self.store
                    .transition_reservation(
                        &reservation.id,
                        State::Detaching,
                        State::DetachFailed,
                        None,
                        now(),
                    )
                    .await?
            }
            State::DetachFailed => reservation.clone(),
            State::Attaching => match reservation.guest.clone() {
                Some(recorded) => {
                    self.mark_unknown(
                        reservation,
                        &recorded.account_id,
                        &recorded.node,
                        recorded.vmid,
                        None,
                    )
                    .await?
                }
                None => reservation.clone(),
            },
            // A guest that could not be read before the row moved: it goes
            // through `detaching` to say the detach failed.
            other => {
                let detaching = self
                    .store
                    .transition_reservation(&reservation.id, other, State::Detaching, None, now())
                    .await?;
                self.store
                    .transition_reservation(
                        &detaching.id,
                        State::Detaching,
                        State::DetachFailed,
                        None,
                        now(),
                    )
                    .await?
            }
        };
        let detail = bounded(&detail);
        let _ = self
            .event(
                "hardware_detach_failed",
                device,
                &failed,
                operation_id,
                &[("reason", detail.clone())],
                false,
            )
            .await;
        Ok(DetachResult::Failed(detail))
    }

    /// The node the cluster says the guest is on now, when it says.
    async fn live_node(&self, request: &PveHttpRequest, vmid: u32) -> Option<String> {
        let resources = self
            .client
            .list_guest_resources(PveHttpRequest {
                path: "/api2/json/cluster/resources".to_owned(),
                ..request.clone()
            })
            .await
            .ok()?;
        resources
            .into_iter()
            .find(|resource| resource.vmid == Some(vmid) && resource.kind == "qemu")
            .and_then(|resource| resource.node)
    }
}
