//! Hardware domain types (FM-1101, ADR 0019): inventoried devices, their
//! derived status, and exclusive reservations with their state machine.
//!
//! A device is identified by the PVE resource mapping it is bound to, never
//! by the vendor:product or port it was last seen on. These types carry no
//! provider model: the Proxmox adapter translates at its boundary.

use serde::{Deserialize, Serialize};

/// The most `usbN` slots a QEMU guest has (`usb0` to `usb4`).
pub const USB_SLOT_COUNT: u8 = 5;

/// The kind of a hardware device. Only USB exists in the first release.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareKind {
    /// A USB device attached through a PVE USB resource mapping.
    Usb,
}

impl HardwareKind {
    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Usb => "usb",
        }
    }

    /// Parses the stable string.
    ///
    /// # Errors
    ///
    /// Fails on an unrecognized kind.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "usb" => Ok(Self::Usb),
            other => Err(format!("unrecognized hardware kind {other:?}")),
        }
    }
}

/// Why a device cannot be allocated. The reason is stable and explained,
/// never guessed (ADR 0019 decision 7).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedReason {
    /// The mapping has no entry for the node.
    NoNodeEntry,
    /// More than one entry matches, so the device cannot be told apart.
    AmbiguousMapping,
    /// The token lacks `Mapping.Use` on the mapping.
    TokenLacksMappingUse,
    /// The token lacks `VM.Config.HWType` on the guest.
    TokenLacksGuestHwtype,
    /// The PVE version predates USB resource mappings.
    PveTooOld,
    /// The node's USB inventory could not be read.
    UsbInventoryUnreadable,
}

impl UnsupportedReason {
    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::NoNodeEntry => "no_node_entry",
            Self::AmbiguousMapping => "ambiguous_mapping",
            Self::TokenLacksMappingUse => "token_lacks_mapping_use",
            Self::TokenLacksGuestHwtype => "token_lacks_guest_hwtype",
            Self::PveTooOld => "pve_too_old",
            Self::UsbInventoryUnreadable => "usb_inventory_unreadable",
        }
    }

    /// Parses the stable string.
    ///
    /// # Errors
    ///
    /// Fails on an unrecognized reason.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "no_node_entry" => Ok(Self::NoNodeEntry),
            "ambiguous_mapping" => Ok(Self::AmbiguousMapping),
            "token_lacks_mapping_use" => Ok(Self::TokenLacksMappingUse),
            "token_lacks_guest_hwtype" => Ok(Self::TokenLacksGuestHwtype),
            "pve_too_old" => Ok(Self::PveTooOld),
            "usb_inventory_unreadable" => Ok(Self::UsbInventoryUnreadable),
            other => Err(format!("unrecognized unsupported reason {other:?}")),
        }
    }
}

/// The derived status of a device. `unsupported` always carries its reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "reason", rename_all = "snake_case")]
pub enum DeviceStatus {
    /// Mapping valid, seen recently, nothing references it.
    Available,
    /// A live Fleet reservation holds it.
    Reserved,
    /// A guest references the mapping and Fleet has no reservation for it.
    ExternallyAttached,
    /// The mapping exists but the device was not seen on the node.
    Missing,
    /// Cannot be allocated, for the stated reason.
    Unsupported(UnsupportedReason),
    /// A failed or unknown attach or detach needs the reconciler or an
    /// operator.
    Quarantined,
}

impl DeviceStatus {
    /// The stable status string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Reserved => "reserved",
            Self::ExternallyAttached => "externally_attached",
            Self::Missing => "missing",
            Self::Unsupported(_) => "unsupported",
            Self::Quarantined => "quarantined",
        }
    }

    /// The reason, only for `unsupported`.
    #[must_use]
    pub const fn reason(self) -> Option<UnsupportedReason> {
        match self {
            Self::Unsupported(reason) => Some(reason),
            _ => None,
        }
    }

    /// Rebuilds a status from its stored parts. A reason is required for
    /// `unsupported` and refused for every other status.
    ///
    /// # Errors
    ///
    /// Fails on an unknown status or a status and reason that disagree.
    pub fn from_parts(status: &str, reason: Option<&str>) -> Result<Self, String> {
        let reason = reason.map(UnsupportedReason::from_id).transpose()?;
        match (status, reason) {
            ("unsupported", Some(reason)) => Ok(Self::Unsupported(reason)),
            ("unsupported", None) => Err("an unsupported device needs a reason".to_owned()),
            (_, Some(_)) => Err(format!("status {status:?} cannot carry a reason")),
            ("available", None) => Ok(Self::Available),
            ("reserved", None) => Ok(Self::Reserved),
            ("externally_attached", None) => Ok(Self::ExternallyAttached),
            ("missing", None) => Ok(Self::Missing),
            ("quarantined", None) => Ok(Self::Quarantined),
            (other, None) => Err(format!("unrecognized device status {other:?}")),
        }
    }
}

/// What one node observed for a device. The PVE node inventory exposes no
/// serial, so the fingerprint is vendor:product plus `usbpath`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceNodeEntry {
    /// The PVE node.
    pub node: String,
    /// The USB vendor id (four hex digits).
    pub vendor_id: String,
    /// The USB product id (four hex digits).
    pub product_id: String,
    /// The bus-port path the device was seen on.
    pub usbpath: Option<String>,
    /// The manufacturer string the device reports.
    pub manufacturer: Option<String>,
    /// The product string the device reports.
    pub product: Option<String>,
    /// When this entry was last seen (epoch milliseconds).
    pub last_seen_at: i64,
}

/// An inventoried hardware device.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardwareDevice {
    /// The Fleet id.
    pub id: String,
    /// The Proxmox account whose cluster owns the mapping.
    pub account_id: String,
    /// The PVE resource mapping id; this is the device's identity.
    pub mapping_id: String,
    /// The device kind.
    pub kind: HardwareKind,
    /// The per-node observed entries, ordered by node.
    pub entries: Vec<DeviceNodeEntry>,
    /// The derived status.
    pub status: DeviceStatus,
    /// An operator note.
    pub note: Option<String>,
    /// When the row was created (epoch milliseconds).
    pub created_at: i64,
    /// When the row last changed (epoch milliseconds).
    pub updated_at: i64,
}

/// Who holds a reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationOwnerKind {
    /// A Lab lease; released by cleanup.
    Lease,
    /// A persistent machine; released by an explicit detach.
    Machine,
}

impl ReservationOwnerKind {
    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Lease => "lease",
            Self::Machine => "machine",
        }
    }

    /// Parses the stable string.
    ///
    /// # Errors
    ///
    /// Fails on an unrecognized owner kind.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "lease" => Ok(Self::Lease),
            "machine" => Ok(Self::Machine),
            other => Err(format!("unrecognized reservation owner kind {other:?}")),
        }
    }
}

/// A reservation's state. Every state but `released` is live and counts
/// against the device.
///
/// `held` means reserved and not attached: it is where a reservation starts
/// and where a lease that detached a device mid-run (FM-1126) returns, still
/// holding the device so it can attach it again.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareReservationState {
    /// Reserved, not attached.
    Held,
    /// The attach write is in flight.
    Attaching,
    /// Attached to the guest and read back.
    Attached,
    /// The detach write is in flight.
    Detaching,
    /// Terminal. The device is free again.
    Released,
    /// The attach outcome could not be determined; the reconciler resolves
    /// it, never a guess.
    AttachUnknown,
    /// The detach failed; the reservation stays held for a retry.
    DetachFailed,
}

impl HardwareReservationState {
    /// Every state.
    pub const ALL: [Self; 7] = [
        Self::Held,
        Self::Attaching,
        Self::Attached,
        Self::Detaching,
        Self::Released,
        Self::AttachUnknown,
        Self::DetachFailed,
    ];

    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Attaching => "attaching",
            Self::Attached => "attached",
            Self::Detaching => "detaching",
            Self::Released => "released",
            Self::AttachUnknown => "attach_unknown",
            Self::DetachFailed => "detach_failed",
        }
    }

    /// Parses the stable string.
    ///
    /// # Errors
    ///
    /// Fails on an unrecognized state.
    pub fn from_id(id: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|state| state.id() == id)
            .ok_or_else(|| format!("unrecognized reservation state {id:?}"))
    }

    /// Whether the reservation still holds its device.
    #[must_use]
    pub const fn is_live(self) -> bool {
        !matches!(self, Self::Released)
    }

    /// The states a reservation may move to from this one.
    ///
    /// A device is only released through `detaching`, straight from `held`
    /// (nothing was ever written), or from `detach_failed` once a read-back
    /// proves the guest no longer references it. An attach that did not
    /// finish is never released on a guess.
    #[must_use]
    pub const fn successors(self) -> &'static [Self] {
        match self {
            Self::Held => &[Self::Attaching, Self::Released],
            Self::Attaching => &[
                Self::Attached,
                Self::Held,
                Self::Detaching,
                Self::AttachUnknown,
            ],
            Self::Attached => &[Self::Detaching],
            Self::Detaching => &[Self::Held, Self::Released, Self::DetachFailed],
            Self::AttachUnknown => &[Self::Attached, Self::Held, Self::Detaching],
            Self::DetachFailed => &[Self::Detaching, Self::Held, Self::Released],
            Self::Released => &[],
        }
    }

    /// Whether `next` is a legal move from this state.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        self.successors().contains(&next)
    }
}

/// The guest a reservation attaches to, once known.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestTarget {
    /// The Proxmox account of the guest.
    pub account_id: String,
    /// The node the guest runs on.
    pub node: String,
    /// The guest's VMID.
    pub vmid: u32,
    /// The `usbN` slot, once chosen (0 to 4).
    pub usb_slot: Option<u8>,
}

impl GuestTarget {
    /// Checks the slot is a real `usbN` index.
    ///
    /// # Errors
    ///
    /// Fails when the slot is out of range.
    pub fn validate(&self) -> Result<(), String> {
        match self.usb_slot {
            Some(slot) if slot >= USB_SLOT_COUNT => Err(format!("usb slot {slot} is out of range")),
            _ => Ok(()),
        }
    }
}

/// An exclusive reservation of a device by a lease or a machine.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardwareReservation {
    /// The reservation id.
    pub id: String,
    /// The reserved device.
    pub device_id: String,
    /// The owner's kind.
    pub owner_kind: ReservationOwnerKind,
    /// The owner's id (a lease or machine id).
    pub owner_id: String,
    /// The state.
    pub state: HardwareReservationState,
    /// The guest, once known.
    pub guest: Option<GuestTarget>,
    /// When it was reserved (epoch milliseconds).
    pub created_at: i64,
    /// When the state last changed (epoch milliseconds).
    pub updated_at: i64,
    /// When it was released, only in the `released` state.
    pub released_at: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::HardwareReservationState::{
        AttachUnknown, Attached, Attaching, DetachFailed, Detaching, Held, Released,
    };
    use super::*;

    #[test]
    fn legal_transitions_are_exactly_the_documented_set() {
        let legal = [
            (Held, Attaching),
            (Held, Released),
            (Attaching, Attached),
            (Attaching, Held),
            (Attaching, Detaching),
            (Attaching, AttachUnknown),
            (Attached, Detaching),
            (Detaching, Held),
            (Detaching, Released),
            (Detaching, DetachFailed),
            (AttachUnknown, Attached),
            (AttachUnknown, Held),
            (AttachUnknown, Detaching),
            (DetachFailed, Detaching),
            (DetachFailed, Held),
            (DetachFailed, Released),
        ];
        for from in HardwareReservationState::ALL {
            for to in HardwareReservationState::ALL {
                assert_eq!(
                    from.can_transition_to(to),
                    legal.contains(&(from, to)),
                    "{} -> {}",
                    from.id(),
                    to.id()
                );
            }
        }
    }

    #[test]
    fn released_is_terminal_and_the_only_non_live_state() {
        assert!(Released.successors().is_empty());
        for state in HardwareReservationState::ALL {
            assert_eq!(state.is_live(), state != Released);
        }
    }

    #[test]
    fn an_attached_or_unknown_device_is_never_released_directly() {
        assert!(!Attached.can_transition_to(Released));
        assert!(!Attaching.can_transition_to(Released));
        assert!(!AttachUnknown.can_transition_to(Released));
    }

    #[test]
    fn mid_run_hotplug_detach_returns_to_held_and_can_attach_again() {
        assert!(Attached.can_transition_to(Detaching));
        assert!(Detaching.can_transition_to(Held));
        assert!(Held.can_transition_to(Attaching));
    }

    #[test]
    fn state_ids_round_trip() {
        for state in HardwareReservationState::ALL {
            assert_eq!(HardwareReservationState::from_id(state.id()), Ok(state));
        }
        assert!(HardwareReservationState::from_id("stolen").is_err());
    }

    #[test]
    fn unsupported_always_carries_a_reason() {
        let status = DeviceStatus::Unsupported(UnsupportedReason::PveTooOld);
        assert_eq!(status.id(), "unsupported");
        assert_eq!(
            DeviceStatus::from_parts("unsupported", Some("pve_too_old")),
            Ok(status)
        );
        assert!(DeviceStatus::from_parts("unsupported", None).is_err());
        assert!(DeviceStatus::from_parts("available", Some("pve_too_old")).is_err());
        assert!(DeviceStatus::from_parts("unsupported", Some("because")).is_err());
        assert!(DeviceStatus::from_parts("stolen", None).is_err());
    }

    #[test]
    fn status_ids_round_trip() {
        for status in [
            DeviceStatus::Available,
            DeviceStatus::Reserved,
            DeviceStatus::ExternallyAttached,
            DeviceStatus::Missing,
            DeviceStatus::Quarantined,
            DeviceStatus::Unsupported(UnsupportedReason::NoNodeEntry),
        ] {
            let reason = status.reason().map(UnsupportedReason::id);
            assert_eq!(DeviceStatus::from_parts(status.id(), reason), Ok(status));
        }
    }

    #[test]
    fn guest_slot_is_bounded() {
        let mut target = GuestTarget {
            account_id: "a".to_owned(),
            node: "n".to_owned(),
            vmid: 100,
            usb_slot: Some(4),
        };
        assert!(target.validate().is_ok());
        target.usb_slot = Some(5);
        assert!(target.validate().is_err());
    }
}
