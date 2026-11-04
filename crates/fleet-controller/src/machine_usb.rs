//! USB devices on persistent machines (FM-1125, ADR 0018 and ADR 0019): the
//! [`MachineUsbPort`] over the hardware saga.
//!
//! The use case (`fleet_application::machine_usb`) has already authorized the
//! caller, checked the machine, its guest and the review token. What is left
//! is the device. This module reserves it for the machine, and drives the
//! saga's own building blocks (the lease path's verify, digest-conditional
//! write, read-back and detach), so a machine's device is attached and
//! detached exactly as a Lab guest's is:
//!
//! ```text
//! attach  reserve (machine, fail fast `hardware_busy`) -> verify
//!         (re-observe, pinned fingerprint, nobody else references it)
//!         -> attaching -> required audit intent -> digest-conditional write
//!         -> read back -> attached
//! detach  detaching -> required audit intent -> delete exactly the entry
//!         Fleet wrote -> read back every usbN -> released
//! ```
//!
//! Rules this module keeps:
//!
//! - **The machine holds the device until it is detached.** A confirmed
//!   detach is the only thing that releases an attached device. Nothing here
//!   releases on a guess: a failed, pending or unconfirmed detach keeps the
//!   reservation, and the reconciler leaves a live machine's rows alone.
//! - **An attach that wrote nothing gives the device back.** A refused attach
//!   (busy, missing, changed, externally attached, a write PVE refused, a
//!   pending attach that was removed again) leaves a slot-less `held` row; the
//!   request releases it, so a failed attach holds nothing.
//! - **Pending is not done.** A detach PVE leaves pending (the running
//!   guest's `hotplug` option lacks `usb`) answers `detach_pending` with the
//!   device still attached and the row still `detaching`. An attach PVE would
//!   leave pending is removed again and refused as `hardware_attach_pending`:
//!   it is never reported attached, and a restart cannot attach a device
//!   nobody confirmed. (Stop the machine and attach, or enable usb hotplug.)
//! - **Serialised per device, fail fast.** A request takes the device's lock
//!   before it reads the reservation, so requests on one device run one after
//!   the other and the second sees what the first left. A device another
//!   owner holds is `hardware_busy`, never queued.
//! - **Never touch what Fleet did not write.** The detach is the saga's: the
//!   recorded slot, the exact `mapping=<id>` value, and a read of every `usbN`
//!   entry before the row moves. An entry an operator rewrote or added is
//!   left untouched.
//! - **A crash resumes from the row.** An interrupted attach (`attaching`)
//!   is resolved by a detach request, which reads the guest: a guest that
//!   shows nothing releases the row, a guest that shows the mapping makes it
//!   `attach_unknown` with no slot, which nothing deletes. An unknown outcome
//!   (`attach_unknown`) is resolved by an operator, because no Lab cleanup
//!   exists for a machine's row.
//! - **The work outlives the request.** It runs in its own task, so a caller
//!   that disconnects mid-write does not abandon a half-finished step.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use fleet_application::authz::Permission;
use fleet_application::hardware::HardwareStore;
use fleet_application::hardware_reservation::{
    AuditContext, HardwareReservations, ReserveDecision, ReserveRefusal, ReserveRequest,
};
use fleet_application::lab_hardware_hotplug::{HotplugError, HotplugResult};
use fleet_application::machine::MachinePort;
use fleet_application::machine_usb::{
    MachineUsbAction, MachineUsbOutcome, MachineUsbPort, MachineUsbRequest, find_machine_hold,
    hold_instruction,
};
use fleet_core::{
    HardwareDevice, HardwareReservation, HardwareReservationState as State, ReservationOwnerKind,
};

use crate::guest_locks::GuestLocks;
use crate::lab_hardware::{AttachFailure, DetachResult, LabHardwareSaga, LeaseGuest};

/// The saga's audit `source` fact for a request made through this module.
const SOURCE: &str = "machine_usb";

/// Composes the port over the controller's database, the Proxmox credential
/// store and the shared pinned-fingerprint transport: the same parts the Lab
/// saga is composed of, so an attach re-observes through the inventory the
/// API reads.
#[must_use]
pub fn compose(
    pool: &sqlx::SqlitePool,
    credentials: Arc<dyn fleet_application::proxmox::ProxmoxCredentialStore>,
    transport: Arc<dyn fleet_provider_proxmox::PveTransport>,
    machines: Arc<dyn MachinePort>,
    guest_locks: Arc<GuestLocks>,
) -> MachineUsbHost {
    use fleet_application::hardware_inventory::HardwareInventory;
    use fleet_application::operation::AuditPort;
    use fleet_application::proxmox::ProxmoxAccountPort;
    use fleet_storage_sqlite::{
        AuditSink, HardwareRepository, LeaseRepository, ProxmoxAccountRepository,
    };

    let accounts: Arc<dyn ProxmoxAccountPort> =
        Arc::new(ProxmoxAccountRepository::new(pool.clone()));
    let store: Arc<dyn HardwareStore> = Arc::new(HardwareRepository::new(pool.clone()));
    let audit: Arc<dyn AuditPort> = Arc::new(AuditSink::new(pool.clone()));
    let client = fleet_provider_proxmox::ProxmoxClient::new(transport);
    let reservations = Arc::new(HardwareReservations::new(
        Arc::new(crate::hardware_reservation_store::SqliteHardwareReservations::new(pool.clone())),
        audit.clone(),
    ));
    let saga = LabHardwareSaga::new(
        accounts.clone(),
        credentials.clone(),
        client.clone(),
        store.clone(),
        reservations.clone(),
        Arc::new(HardwareInventory::new(
            accounts,
            credentials,
            store.clone(),
            crate::hardware_observer::shared(client),
            audit.clone(),
        )),
        audit,
        Arc::new(LeaseRepository::new(pool.clone())),
        Arc::new(crate::lab_hardware::SqliteFingerprintPins::new(
            pool.clone(),
        )),
    );
    MachineUsbHost::new(Arc::new(saga), store, reservations, machines, guest_locks)
}

type DeviceLocks = StdMutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>;

/// The machine USB port over the hardware saga.
#[derive(Clone, Debug)]
pub struct MachineUsbHost {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    saga: Arc<LabHardwareSaga>,
    store: Arc<dyn HardwareStore>,
    reservations: Arc<HardwareReservations>,
    machines: Arc<dyn MachinePort>,
    guest_locks: Arc<GuestLocks>,
    locks: DeviceLocks,
}

impl MachineUsbHost {
    /// Composes the port over the saga, the hardware store, the reservation
    /// use cases, the machine records and the per-guest locks it shares with
    /// the destructive executor.
    #[must_use]
    pub fn new(
        saga: Arc<LabHardwareSaga>,
        store: Arc<dyn HardwareStore>,
        reservations: Arc<HardwareReservations>,
        machines: Arc<dyn MachinePort>,
        guest_locks: Arc<GuestLocks>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                saga,
                store,
                reservations,
                machines,
                guest_locks,
                locks: StdMutex::new(HashMap::new()),
            }),
        }
    }
}

#[async_trait]
impl MachineUsbPort for MachineUsbHost {
    async fn carry_out(
        &self,
        request: &MachineUsbRequest,
    ) -> Result<MachineUsbOutcome, HotplugError> {
        let inner = self.inner.clone();
        let request = request.clone();
        tokio::spawn(async move { inner.carry_out(&request).await })
            .await
            .map_err(|error| HotplugError::Backend {
                detail: format!("the machine USB task failed: {error}"),
            })?
    }
}

fn backend(error: &impl std::fmt::Display) -> HotplugError {
    HotplugError::Backend {
        detail: format!("the hardware store failed: {error}"),
    }
}

fn from_failure(failure: AttachFailure) -> HotplugError {
    match failure {
        AttachFailure::Refused { reason, detail } => HotplugError::refused(reason, detail),
        AttachFailure::Infrastructure(detail) => HotplugError::Backend { detail },
    }
}

fn not_reserved(request: &MachineUsbRequest) -> HotplugError {
    HotplugError::refused(
        "hardware_not_reserved",
        format!(
            "{} is not reserved by machine {}; there is nothing to detach",
            request.mapping_id, request.machine_id
        ),
    )
}

fn context(request: &MachineUsbRequest) -> AuditContext {
    AuditContext {
        actor: request.principal_id.clone(),
        operation_id: None,
    }
}

fn now() -> i64 {
    fleet_core::SystemClock::now_unix_millis()
}

impl Inner {
    /// The device's lock: requests on one device run one at a time.
    async fn lock(&self, device_id: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self
                .locks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            locks.entry(device_id.to_owned()).or_default().clone()
        };
        lock.lock_owned().await
    }

    /// Drops the lock entry of a device nobody waits on.
    fn forget(&self, device_id: &str) {
        let mut locks = self
            .locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if locks
            .get(device_id)
            .is_some_and(|lock| Arc::strong_count(lock) == 1)
        {
            locks.remove(device_id);
        }
    }

    fn saga(&self, request: &MachineUsbRequest) -> LabHardwareSaga {
        self.saga.acting_for_machine(
            &request.principal_id,
            request.action.permission(),
            SOURCE,
            self.machines.clone(),
        )
    }

    async fn carry_out(
        &self,
        request: &MachineUsbRequest,
    ) -> Result<MachineUsbOutcome, HotplugError> {
        match request.action {
            MachineUsbAction::Attach => self.attach(request).await,
            MachineUsbAction::Detach => self.detach(request).await,
        }
    }

    async fn outcome(
        &self,
        request: &MachineUsbRequest,
        id: &str,
        result: HotplugResult,
    ) -> Result<MachineUsbOutcome, HotplugError> {
        let row = self
            .store
            .reservation(id)
            .await
            .map_err(|error| backend(&error))?
            .ok_or_else(|| HotplugError::Backend {
                detail: "the reservation vanished".to_owned(),
            })?;
        Ok(MachineUsbOutcome {
            machine_id: request.machine_id.clone(),
            mapping_id: request.mapping_id.clone(),
            result,
            reservation_id: row.id.clone(),
            reservation_state: row.state,
            // The slot the guest holds the device in. A flow release keeps
            // the slot on the released row, so a device that is not on the
            // guest reports none.
            usb_slot: result
                .on_guest()
                .then(|| row.guest.as_ref().and_then(|guest| guest.usb_slot))
                .flatten(),
            released: row.state == State::Released,
        })
    }

    // ── attach ───────────────────────────────────────────────────────────

    async fn attach(&self, request: &MachineUsbRequest) -> Result<MachineUsbOutcome, HotplugError> {
        let guest = request
            .guest
            .as_ref()
            .ok_or_else(|| HotplugError::Invalid {
                detail: "an attach names the machine's guest".to_owned(),
            })?;
        let device = self
            .store
            .device_by_mapping(&guest.account_id, &request.mapping_id)
            .await
            .map_err(|error| backend(&error))?
            .ok_or_else(|| {
                HotplugError::refused(
                    "hardware_unknown",
                    format!(
                        "no device with mapping {} is inventoried for this account; refresh the hardware inventory",
                        request.mapping_id
                    ),
                )
            })?;
        let guard = self.lock(&device.id).await;
        let outcome = self.attach_locked(request, &device).await;
        drop(guard);
        self.forget(&device.id);
        outcome
    }

    async fn attach_locked(
        &self,
        request: &MachineUsbRequest,
        device: &HardwareDevice,
    ) -> Result<MachineUsbOutcome, HotplugError> {
        let guest = request
            .guest
            .as_ref()
            .ok_or_else(|| HotplugError::Invalid {
                detail: "an attach names the machine's guest".to_owned(),
            })?;
        // A destructive operation on the guest (destroy, revert, template,
        // clone) holds the guest's lock for as long as it runs: the attach
        // does not wait for it, it is refused, so a device is never written
        // into a guest that is about to go. The lock is held to the end of
        // the attach, which the executor in turn waits for before it checks
        // the reservations.
        let Some(_guest_guard) = self.guest_locks.try_lock(&guest.account_id, guest.vmid) else {
            return Err(HotplugError::refused(
                "hardware_guest_busy",
                format!(
                    "a destructive operation (destroy, snapshot revert, template or clone) is running on guest qemu/{}; nothing was attached, try again when it has finished",
                    guest.vmid
                ),
            ));
        };
        // Reserve in the database first, under the lock: a repeat returns the
        // machine's own row in whatever state the saga took it to, another
        // owner's row is `hardware_busy`.
        let decision = self
            .reservations
            .reserve(
                &context(request),
                &ReserveRequest {
                    device_id: device.id.clone(),
                    owner_kind: ReservationOwnerKind::Machine,
                    owner_id: request.machine_id.clone(),
                },
                now(),
            )
            .await
            .map_err(|error| backend(&error))?;
        let row = match decision {
            ReserveDecision::Reserved { reservation, .. } => reservation,
            ReserveDecision::Refused(refusal) => return Err(refusal_error(request, &refusal)),
        };
        match row.state {
            State::Attached => {
                same_guest(request, &row)?;
                self.outcome(request, &row.id, HotplugResult::AlreadyAttached)
                    .await
            }
            State::Held => {
                let saga = self.saga(request);
                let lease_guest = LeaseGuest {
                    lease_id: &request.machine_id,
                    account_id: &guest.account_id,
                    node: &guest.node,
                    vmid: guest.vmid,
                    operation_id: None,
                };
                match saga.hotplug_attach(&lease_guest, device, row.clone()).await {
                    Ok(attached) => {
                        self.outcome(request, &attached.id, HotplugResult::Attached)
                            .await
                    }
                    Err(failure) => {
                        let note = self.give_back_unattached(request, &row.id).await;
                        Err(match (from_failure(failure), note) {
                            (HotplugError::Refused { reason, detail }, Some(note)) => {
                                HotplugError::Refused {
                                    reason,
                                    detail: format!("{detail}; {note}"),
                                }
                            }
                            (HotplugError::Backend { detail }, Some(note)) => {
                                HotplugError::Backend {
                                    detail: format!("{detail}; {note}"),
                                }
                            }
                            (error, _) => error,
                        })
                    }
                }
            }
            State::Attaching => Err(HotplugError::refused(
                "hardware_in_progress",
                format!(
                    "an earlier attach of {} to this machine did not finish; detach it (`machines usb detach`), which reads the guest and releases the device when nothing is on it",
                    request.mapping_id
                ),
            )),
            State::AttachUnknown => Err(HotplugError::refused(
                "hardware_attach_unknown",
                format!(
                    "the reservation for {} is attach_unknown: an earlier write may or may not have reached the guest; {}",
                    request.mapping_id,
                    hold_instruction(
                        State::AttachUnknown,
                        &request.machine_id,
                        &request.mapping_id,
                        &row.id
                    )
                ),
            )),
            State::Detaching | State::DetachFailed => Err(HotplugError::refused(
                "hardware_detach_unconfirmed",
                format!(
                    "the reservation for {} is {}: detach it again and wait until it is confirmed before attaching",
                    request.mapping_id,
                    row.state.id()
                ),
            )),
            State::Released => Err(HotplugError::Backend {
                detail: "the reservation was released while it was reserved".to_owned(),
            }),
        }
    }

    /// After a failed attach: the row, when it is back in `held` with nothing
    /// recorded on a guest, holds nothing, so it is released (the machine did
    /// not get the device). A row in any other state is left for the detach.
    /// A release that cannot be made is not swallowed: the answer says the
    /// row stays `held` by the machine and how to give it back, and the state
    /// stays visible in the reservation list.
    async fn give_back_unattached(&self, request: &MachineUsbRequest, id: &str) -> Option<String> {
        let row = match self.store.reservation(id).await {
            Ok(Some(row)) => row,
            Ok(None) => return None,
            Err(error) => {
                return Some(format!(
                    "the reservation {id} could not be read to give it back ({error}); it may stay held by the machine: run `fleetctl machines usb detach {} --mapping {}`",
                    request.machine_id, request.mapping_id
                ));
            }
        };
        let slotless = row
            .guest
            .as_ref()
            .is_none_or(|guest| guest.usb_slot.is_none());
        if row.state != State::Held || !slotless {
            return None;
        }
        match self
            .reservations
            .release_under(
                &context(request),
                Permission::MachineUsbAttach.id(),
                &row.id,
                now(),
            )
            .await
        {
            Ok(_) => None,
            Err(error) => Some(format!(
                "the reservation {id} could not be released ({error}) and stays held by the machine; run `fleetctl machines usb detach {} --mapping {}` to give the device back",
                request.machine_id, request.mapping_id
            )),
        }
    }

    // ── detach ───────────────────────────────────────────────────────────

    async fn detach(&self, request: &MachineUsbRequest) -> Result<MachineUsbOutcome, HotplugError> {
        let (device, _) = self.held_device(request).await?;
        let guard = self.lock(&device.id).await;
        let outcome = self.detach_locked(request, &device).await;
        drop(guard);
        self.forget(&device.id);
        outcome
    }

    /// The device of the machine's live reservation for the mapping (the
    /// account of its current guest link picks among several; see
    /// [`find_machine_hold`]).
    async fn held_device(
        &self,
        request: &MachineUsbRequest,
    ) -> Result<(HardwareDevice, HardwareReservation), HotplugError> {
        find_machine_hold(
            self.store.as_ref(),
            &request.machine_id,
            &request.mapping_id,
            request.account_id.as_deref(),
            false,
        )
        .await?
        .ok_or_else(|| not_reserved(request))
    }

    async fn detach_locked(
        &self,
        request: &MachineUsbRequest,
        device: &HardwareDevice,
    ) -> Result<MachineUsbOutcome, HotplugError> {
        // Read under the lock: what a request ahead of this one left.
        let row = self
            .store
            .live_reservation_for_device(&device.id)
            .await
            .map_err(|error| backend(&error))?
            .filter(|row| {
                row.owner_kind == ReservationOwnerKind::Machine
                    && row.owner_id == request.machine_id
            })
            .ok_or_else(|| not_reserved(request))?;
        let saga = self.saga(request);
        match row.state {
            State::Attached | State::Detaching | State::DetachFailed | State::Attaching => {
                let id = row.id.clone();
                match saga
                    .hotplug_detach(row, device, &request.machine_id, true)
                    .await
                    .map_err(|error| backend(&error))?
                {
                    DetachResult::Detached => {
                        self.outcome(request, &id, HotplugResult::Detached).await
                    }
                    DetachResult::Pending => {
                        self.outcome(request, &id, HotplugResult::DetachPending)
                            .await
                    }
                    DetachResult::Failed(detail) => Err(HotplugError::refused(
                        "hardware_detach_failed",
                        format!(
                            "{detail}; machine {} still holds {}. Fix the cause and detach again; an operator who has checked the guest frees it with hardware.override-release",
                            request.machine_id, request.mapping_id
                        ),
                    )),
                }
            }
            // Nothing attached: a held row records no slot. A row that
            // recorded a guest is read first (a reference somebody added
            // since, or a guest that cannot be read, keeps the row); one that
            // never recorded a guest holds nothing anywhere.
            State::Held => {
                match row.guest.clone() {
                    Some(recorded) => {
                        let lease_guest = LeaseGuest {
                            lease_id: &request.machine_id,
                            account_id: &recorded.account_id,
                            node: &recorded.node,
                            vmid: recorded.vmid,
                            operation_id: None,
                        };
                        saga.hotplug_release_held(&lease_guest, device, &row)
                            .await
                            .map_err(from_failure)?;
                    }
                    None => {
                        self.reservations
                            .release_under(
                                &context(request),
                                Permission::MachineUsbDetach.id(),
                                &row.id,
                                now(),
                            )
                            .await
                            .map_err(|error| backend(&error))?;
                    }
                }
                self.outcome(request, &row.id, HotplugResult::AlreadyDetached)
                    .await
            }
            State::AttachUnknown => Err(HotplugError::refused(
                "hardware_attach_unknown",
                format!(
                    "the reservation for {} is attach_unknown: an earlier write may or may not have reached the guest, so Fleet deletes nothing; {}",
                    request.mapping_id,
                    hold_instruction(
                        State::AttachUnknown,
                        &request.machine_id,
                        &request.mapping_id,
                        &row.id
                    )
                ),
            )),
            State::Released => Err(not_reserved(request)),
        }
    }
}

/// The recorded guest must be the machine's: a row that names another guest
/// is never reported attached to this one.
fn same_guest(request: &MachineUsbRequest, row: &HardwareReservation) -> Result<(), HotplugError> {
    let Some(guest) = &request.guest else {
        return Ok(());
    };
    match &row.guest {
        Some(recorded)
            if recorded.account_id == guest.account_id && recorded.vmid == guest.vmid =>
        {
            Ok(())
        }
        other => Err(HotplugError::refused(
            "hardware_guest_mismatch",
            format!(
                "the reservation for {} records {}, not the machine's guest qemu/{}; detach it first",
                request.mapping_id,
                other.as_ref().map_or_else(
                    || "no guest".to_owned(),
                    |recorded| format!("qemu/{}", recorded.vmid)
                ),
                guest.vmid
            ),
        )),
    }
}

fn refusal_error(request: &MachineUsbRequest, refusal: &ReserveRefusal) -> HotplugError {
    HotplugError::refused(
        refusal.reason(),
        format!("{}: {refusal}", request.mapping_id),
    )
}
