//! Mid-run hotplug of a Lab lease's USB device (FM-1126, ADR 0019): the
//! [`HotplugPort`] over the Lab hardware saga.
//!
//! The use case (`fleet_application::lab_hardware_hotplug`) has already
//! authorized the caller, scoped the lease to its owner and checked it is
//! ready; what is left is the device. This module resolves it to a reservation
//! the lease holds and drives the saga's own building blocks for a running
//! guest:
//!
//! ```text
//! attach  held     -> verify (re-observe, pinned fingerprint, nobody else
//!                     references it) -> attaching -> required audit intent
//!                     -> digest-conditional write -> read back -> attached
//! detach  attached -> detaching -> required audit intent -> delete exactly
//!                     the entry Fleet wrote -> read back every usbN -> held
//!                     (the lease keeps the device) or released
//! ```
//!
//! What differs from the provision and cleanup paths is only what a step
//! leaves behind: a device the lease detaches, or an attach that wrote
//! nothing, stays reserved by the lease in `held` (the slot cleared) until
//! the lease is released, unless the request releases it after the read-back
//! confirmed the device is gone. A lease that ends meanwhile releases it.
//!
//! Rules this module keeps:
//!
//! - **Only a device the lease reserved.** The device is found by (the
//!   guest's account, mapping id) and its live reservation must be the
//!   lease's. A device that is unknown, unreserved or another lease's all
//!   answer the same refusal, so a caller cannot probe other leases.
//! - **Serialised per device.** A request takes the device's lock before it
//!   reads the reservation, so two requests on one device run one after the
//!   other and the second sees what the first left (an attach after an
//!   attach is `already_attached`, not a second write). The saga's
//!   compare-and-set moves are the backstop against the other writers (the
//!   provision, the lease's cleanup, the sweeper), which do not take the
//!   lock.
//! - **Pending is not done.** A detach that PVE leaves pending (the guest's
//!   `hotplug` option lacks `usb`) is answered `detach_pending` with the
//!   device still attached and the reservation still `detaching`. An attach
//!   PVE leaves pending is removed again and refused as
//!   `hardware_attach_pending`: it is never attached, and a restart cannot
//!   attach a device nobody confirmed.
//! - **Never delete what Fleet did not write.** The detach is the saga's: the
//!   recorded slot, the exact `mapping=<id>` value, and a read of every `usbN`
//!   entry before the row moves. An entry an operator rewrote is left
//!   untouched and the detach fails (`hardware_detach_failed`).
//! - **The work outlives the request.** It runs in its own task, so a caller
//!   that disconnects mid-write does not abandon a half-finished saga step;
//!   whatever a crash leaves is the lease's cleanup's to resolve.
//! - **Attached means Fleet's record.** `already_attached` reports the
//!   reservation row, not a fresh read of the guest.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use fleet_application::hardware::HardwareStore;
use fleet_application::lab_hardware_hotplug::{
    HotplugAction, HotplugError, HotplugOutcome, HotplugPort, HotplugRequest, HotplugResult,
};
use fleet_core::{
    HardwareDevice, HardwareReservation, HardwareReservationState as State, ReservationOwnerKind,
};

use crate::lab_hardware::{AttachFailure, DetachResult, LabHardwareSaga, LeaseGuest};

/// Composes the hotplug port over the controller's database, the Proxmox
/// credential store and the shared pinned-fingerprint transport: the same
/// parts the provision and cleanup saga is composed of, so a hotplug request
/// re-observes through the inventory the API reads.
#[must_use]
pub fn compose(
    pool: &sqlx::SqlitePool,
    credentials: Arc<dyn fleet_application::proxmox::ProxmoxCredentialStore>,
    transport: Arc<dyn fleet_provider_proxmox::PveTransport>,
) -> LabHotplug {
    use fleet_application::hardware_inventory::HardwareInventory;
    use fleet_application::hardware_reservation::HardwareReservations;
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
    let saga = LabHardwareSaga::new(
        accounts.clone(),
        credentials.clone(),
        client.clone(),
        store.clone(),
        Arc::new(HardwareReservations::new(
            Arc::new(
                crate::hardware_reservation_store::SqliteHardwareReservations::new(pool.clone()),
            ),
            audit.clone(),
        )),
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
    LabHotplug::new(Arc::new(saga), store)
}

/// The saga's audit `source` fact for a request made through this module.
const SOURCE: &str = "hotplug";

type DeviceLocks = StdMutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>;

/// The hotplug port over the Lab hardware saga.
#[derive(Clone, Debug)]
pub struct LabHotplug {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    saga: Arc<LabHardwareSaga>,
    store: Arc<dyn HardwareStore>,
    locks: DeviceLocks,
}

impl LabHotplug {
    /// Composes the port over the saga and the hardware store it reads
    /// reservations through.
    #[must_use]
    pub fn new(saga: Arc<LabHardwareSaga>, store: Arc<dyn HardwareStore>) -> Self {
        Self {
            inner: Arc::new(Inner {
                saga,
                store,
                locks: StdMutex::new(HashMap::new()),
            }),
        }
    }
}

#[async_trait]
impl HotplugPort for LabHotplug {
    async fn carry_out(&self, request: &HotplugRequest) -> Result<HotplugOutcome, HotplugError> {
        let inner = self.inner.clone();
        let request = request.clone();
        tokio::spawn(async move { inner.carry_out(&request).await })
            .await
            .map_err(|error| HotplugError::Backend {
                detail: format!("the hotplug task failed: {error}"),
            })?
    }
}

fn backend(error: &impl std::fmt::Display) -> HotplugError {
    HotplugError::Backend {
        detail: format!("the hardware store failed: {error}"),
    }
}

/// Every refusal of a device the lease does not hold reads the same.
fn not_reserved(request: &HotplugRequest) -> HotplugError {
    HotplugError::refused(
        "hardware_not_reserved",
        format!(
            "hardware {} is not reserved by lease {}; a lease hotplugs only the devices it reserved up front",
            request.mapping_id, request.lease_id
        ),
    )
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

    async fn carry_out(&self, request: &HotplugRequest) -> Result<HotplugOutcome, HotplugError> {
        let device = self
            .store
            .device_by_mapping(&request.guest.account_id, &request.mapping_id)
            .await
            .map_err(|error| backend(&error))?
            .ok_or_else(|| not_reserved(request))?;
        let guard = self.lock(&device.id).await;
        let outcome = self.locked(request, &device).await;
        drop(guard);
        self.forget(&device.id);
        outcome
    }

    async fn locked(
        &self,
        request: &HotplugRequest,
        device: &HardwareDevice,
    ) -> Result<HotplugOutcome, HotplugError> {
        // Read under the lock: what a request ahead of this one left.
        let row = self
            .store
            .live_reservation_for_device(&device.id)
            .await
            .map_err(|error| backend(&error))?
            .filter(|row| {
                row.owner_kind == ReservationOwnerKind::Lease && row.owner_id == request.lease_id
            })
            .ok_or_else(|| not_reserved(request))?;
        let permission = request.action.permission();
        let saga = self
            .saga
            .acting_as(&request.principal_id, permission, SOURCE);
        match request.action {
            HotplugAction::Attach => self.attach(&saga, request, device, row).await,
            HotplugAction::Detach { release } => {
                self.detach(&saga, request, device, row, release).await
            }
        }
    }

    /// The row names the guest the request is about: a row recorded on
    /// another guest is never touched through this lease's guest.
    fn same_guest(request: &HotplugRequest, row: &HardwareReservation) -> Result<(), HotplugError> {
        match &row.guest {
            Some(recorded)
                if recorded.account_id == request.guest.account_id
                    && recorded.vmid == request.guest.vmid =>
            {
                Ok(())
            }
            other => Err(HotplugError::refused(
                "hardware_guest_mismatch",
                format!(
                    "the reservation for {} records {}, not the lease's guest qemu/{}",
                    request.mapping_id,
                    other.as_ref().map_or_else(
                        || "no guest".to_owned(),
                        |recorded| format!("qemu/{}", recorded.vmid)
                    ),
                    request.guest.vmid
                ),
            )),
        }
    }

    async fn outcome(
        &self,
        request: &HotplugRequest,
        id: &str,
        result: HotplugResult,
    ) -> Result<HotplugOutcome, HotplugError> {
        let row = self
            .store
            .reservation(id)
            .await
            .map_err(|error| backend(&error))?
            .ok_or_else(|| HotplugError::Backend {
                detail: "the reservation vanished".to_owned(),
            })?;
        Ok(HotplugOutcome {
            lease_id: request.lease_id.clone(),
            mapping_id: request.mapping_id.clone(),
            result,
            reservation_id: row.id.clone(),
            reservation_state: row.state,
            usb_slot: row.guest.as_ref().and_then(|guest| guest.usb_slot),
            released: row.state == State::Released,
        })
    }

    async fn attach(
        &self,
        saga: &LabHardwareSaga,
        request: &HotplugRequest,
        device: &HardwareDevice,
        row: HardwareReservation,
    ) -> Result<HotplugOutcome, HotplugError> {
        match row.state {
            State::Attached => {
                Self::same_guest(request, &row)?;
                self.outcome(request, &row.id, HotplugResult::AlreadyAttached)
                    .await
            }
            State::Held => {
                let guest = LeaseGuest {
                    lease_id: &request.lease_id,
                    account_id: &request.guest.account_id,
                    node: &request.guest.node,
                    vmid: request.guest.vmid,
                    operation_id: None,
                };
                match saga.hotplug_attach(&guest, device, row).await {
                    Ok(attached) => {
                        self.outcome(request, &attached.id, HotplugResult::Attached)
                            .await
                    }
                    Err(AttachFailure::Refused { reason, detail }) => {
                        Err(HotplugError::refused(reason, detail))
                    }
                    Err(AttachFailure::Infrastructure(detail)) => {
                        Err(HotplugError::Backend { detail })
                    }
                }
            }
            State::Attaching => Err(HotplugError::refused(
                "hardware_in_progress",
                format!(
                    "{} is being attached by another step; try again once it is done",
                    request.mapping_id
                ),
            )),
            State::AttachUnknown => Err(HotplugError::refused(
                "hardware_attach_unknown",
                format!(
                    "the reservation for {} is attach_unknown; the lease's cleanup resolves it by reading the guest",
                    request.mapping_id
                ),
            )),
            State::Detaching | State::DetachFailed => Err(HotplugError::refused(
                "hardware_detach_unconfirmed",
                format!(
                    "the reservation for {} is {}: detach it (it retries the detach) and wait until it is confirmed before attaching again",
                    request.mapping_id,
                    row.state.id()
                ),
            )),
            State::Released => Err(not_reserved(request)),
        }
    }

    async fn detach(
        &self,
        saga: &LabHardwareSaga,
        request: &HotplugRequest,
        device: &HardwareDevice,
        row: HardwareReservation,
        release: bool,
    ) -> Result<HotplugOutcome, HotplugError> {
        match row.state {
            State::Attached | State::Detaching | State::DetachFailed => {
                Self::same_guest(request, &row)?;
                let id = row.id.clone();
                match saga
                    .hotplug_detach(row, device, &request.lease_id, release)
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
                            "{detail}; the lease still holds {} and its cleanup retries the detach",
                            request.mapping_id
                        ),
                    )),
                }
            }
            // Detached already (or never attached): a held row records no
            // slot, so there is nothing to remove.
            State::Held => {
                if release {
                    saga.hotplug_release_held(&row)
                        .await
                        .map_err(|error| backend(&error))?;
                }
                self.outcome(request, &row.id, HotplugResult::AlreadyDetached)
                    .await
            }
            State::Attaching => Err(HotplugError::refused(
                "hardware_in_progress",
                format!(
                    "{} is being attached by another step; try again once it is done",
                    request.mapping_id
                ),
            )),
            State::AttachUnknown => Err(HotplugError::refused(
                "hardware_attach_unknown",
                format!(
                    "the reservation for {} is attach_unknown; the lease's cleanup resolves it by reading the guest",
                    request.mapping_id
                ),
            )),
            State::Released => Err(not_reserved(request)),
        }
    }
}
