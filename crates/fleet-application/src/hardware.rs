//! The hardware storage port (FM-1101, ADR 0019).
//!
//! Only the port lives here: device inventory rows and exclusive
//! reservations. The transactional reserve rules (FM-1120), the attach and
//! detach saga, and the provider calls are later issues. The port enforces
//! two invariants the database also guarantees: a device has at most one
//! live reservation, and a reservation only moves along
//! [`HardwareReservationState::successors`].
#![warn(missing_docs)]

use std::fmt;

use async_trait::async_trait;
use fleet_core::{
    DeviceNodeEntry, DeviceStatus, GuestTarget, HardwareDevice, HardwareKind, HardwareReservation,
    HardwareReservationState, ReservationOwnerKind,
};

/// A device to record or refresh, keyed by (account, mapping).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceObservation {
    /// The id to use when the device is new; ignored for a known device.
    pub id: String,
    /// The Proxmox account whose cluster owns the mapping.
    pub account_id: String,
    /// The PVE resource mapping id.
    pub mapping_id: String,
    /// The device kind.
    pub kind: HardwareKind,
    /// The complete current set of per-node entries; it replaces the
    /// stored set.
    pub entries: Vec<DeviceNodeEntry>,
    /// The derived status.
    pub status: DeviceStatus,
}

/// A reservation to insert in the `held` state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewHardwareReservation {
    /// The reservation id.
    pub id: String,
    /// The device to hold.
    pub device_id: String,
    /// The owner's kind.
    pub owner_kind: ReservationOwnerKind,
    /// The owner's id.
    pub owner_id: String,
    /// The guest, when already known.
    pub guest: Option<GuestTarget>,
}

/// Why a hardware store call failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HardwareStoreError {
    /// The device or reservation does not exist.
    NotFound,
    /// The device already has a live reservation; the holder is named.
    Held {
        /// The live reservation that holds the device.
        holder: Box<HardwareReservation>,
    },
    /// The move is not on the state machine, or the reservation was not in
    /// the expected state (another writer moved it first).
    IllegalTransition {
        /// The state the caller expected.
        from: HardwareReservationState,
        /// The requested state.
        to: HardwareReservationState,
        /// The state the reservation was actually in.
        actual: HardwareReservationState,
    },
    /// The input is malformed.
    Invalid(String),
    /// The backend failed.
    Backend(String),
}

impl fmt::Display for HardwareStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("the hardware record does not exist"),
            Self::Held { holder } => write!(
                f,
                "the device is already reserved by {} {}",
                holder.owner_kind.id(),
                holder.owner_id
            ),
            Self::IllegalTransition { from, to, actual } => write!(
                f,
                "cannot move a reservation from {} to {} (it is {})",
                from.id(),
                to.id(),
                actual.id()
            ),
            Self::Invalid(message) | Self::Backend(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for HardwareStoreError {}

/// The hardware inventory and reservation storage port.
#[async_trait]
pub trait HardwareStore: fmt::Debug + Send + Sync {
    /// Records a device, or refreshes the known one for the same
    /// (account, mapping): the entries are replaced and the status set.
    /// A refresh never deletes a device.
    ///
    /// # Errors
    ///
    /// Fails when the observation is malformed or the backend errors.
    async fn upsert_device(
        &self,
        observation: &DeviceObservation,
        now: i64,
    ) -> Result<HardwareDevice, HardwareStoreError>;

    /// One device by id.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn device(&self, id: &str) -> Result<Option<HardwareDevice>, HardwareStoreError>;

    /// One device by (account, mapping).
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn device_by_mapping(
        &self,
        account_id: &str,
        mapping_id: &str,
    ) -> Result<Option<HardwareDevice>, HardwareStoreError>;

    /// The account's devices, ordered by mapping id.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list_devices(
        &self,
        account_id: &str,
    ) -> Result<Vec<HardwareDevice>, HardwareStoreError>;

    /// Sets a device's status. `Reserved` is derived from a live
    /// reservation (FM-1120 sets it inside its reserve transaction), so it
    /// is refused here as [`HardwareStoreError::Invalid`], as it is in
    /// [`Self::upsert_device`].
    ///
    /// # Errors
    ///
    /// Fails when the status is `Reserved`, the device does not exist, or
    /// the backend errors.
    async fn set_device_status(
        &self,
        id: &str,
        status: DeviceStatus,
        now: i64,
    ) -> Result<(), HardwareStoreError>;

    /// Sets or clears a device's operator note.
    ///
    /// # Errors
    ///
    /// Fails when the device does not exist or the backend errors.
    async fn set_device_note(
        &self,
        id: &str,
        note: Option<&str>,
        now: i64,
    ) -> Result<(), HardwareStoreError>;

    /// Inserts a reservation in the `held` state. Fails with
    /// [`HardwareStoreError::Held`] naming the holder when the device
    /// already has a live reservation; the database's partial unique index
    /// is the arbiter, not a prior read. This does **not** check the
    /// device's status (`missing`, `unsupported`, `externally_attached`, ...):
    /// that is the reserve rule FM-1120 owns.
    ///
    /// # Errors
    ///
    /// Fails when the device does not exist, is held, or the backend errors.
    /// A reservation id already in use is [`HardwareStoreError::Invalid`],
    /// never reported as a hold conflict.
    async fn insert_reservation(
        &self,
        reservation: &NewHardwareReservation,
        now: i64,
    ) -> Result<HardwareReservation, HardwareStoreError>;

    /// One reservation by id.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn reservation(
        &self,
        id: &str,
    ) -> Result<Option<HardwareReservation>, HardwareStoreError>;

    /// The device's live reservation, when it has one.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn live_reservation_for_device(
        &self,
        device_id: &str,
    ) -> Result<Option<HardwareReservation>, HardwareStoreError>;

    /// The live reservations an owner holds, oldest first.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn live_reservations_for_owner(
        &self,
        owner_kind: ReservationOwnerKind,
        owner_id: &str,
    ) -> Result<Vec<HardwareReservation>, HardwareStoreError>;

    /// Every live reservation, oldest first (for the reconciler).
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list_live_reservations(&self) -> Result<Vec<HardwareReservation>, HardwareStoreError>;

    /// Moves a reservation from `from` to `to` as a compare-and-set: it
    /// applies only when the reservation is still in `from` and the move is
    /// on the state machine. `guest`, when given, replaces the recorded
    /// guest target (pass the target with `usb_slot: None` to clear the
    /// slot after a detach); `None` keeps it. Moving to `released` stamps
    /// the release time. The read, the compare-and-set and the returned row
    /// are one transaction.
    ///
    /// Slot rules beyond the state machine: `held -> released` is refused
    /// while a `usbN` slot is recorded (go through `detaching`), and every
    /// move into `held` clears the slot. `attaching -> held` must only be
    /// requested after a confirmed no-entry read-back of the guest config;
    /// otherwise route through `detaching`. A move into `held` that carries
    /// a slot is refused.
    ///
    /// # Errors
    ///
    /// Fails when the reservation does not exist, the move is illegal or
    /// stale, the guest target is malformed, or the backend errors.
    async fn transition_reservation(
        &self,
        id: &str,
        from: HardwareReservationState,
        to: HardwareReservationState,
        guest: Option<&GuestTarget>,
        now: i64,
    ) -> Result<HardwareReservation, HardwareStoreError>;

    /// The elevated override release (ADR 0019 decision 9): moves a live
    /// reservation in any state to `released` without the detach path, for
    /// an operator who has confirmed the device is free (or accepts it is
    /// not). It is deliberately not a state-machine edge. The caller must
    /// authorize (`hardware.override-release`) and audit it; this method
    /// does neither. A reservation that is already released is refused.
    ///
    /// # Errors
    ///
    /// Fails when the reservation does not exist, is already released, or
    /// the backend errors.
    async fn force_release_reservation(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HardwareReservation, HardwareStoreError>;
}
