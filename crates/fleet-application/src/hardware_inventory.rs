//! The hardware inventory service (FM-1111, ADR 0019, M11): refresh the
//! USB devices of one Proxmox account and list them with an explained status.
//!
//! A device is a PVE USB resource mapping. A refresh reads, through the
//! account's token and the [`HardwareObservePort`], the mapping list, a
//! `check-node` of every node a mapping names, every guest's `usbN` entries,
//! and the token's own permissions; this module turns that into one
//! [`DeviceStatus`] per mapping and records it. Nothing here calls Proxmox
//! directly and no provider model leaks in: the port's shapes are this
//! module's own.
//!
//! What the statuses rest on, from the FM-S11 spike
//! (`docs/research/proxmox-usb.md`):
//!
//! - **Presence comes from the mapping list.** `GET /nodes/{node}/hardware/usb`
//!   needs `Sys.Modify` on `/`, so the node inventory is optional enrichment
//!   and an unreadable one is the normal case, not a fault. `check-node` says
//!   whether the device is at the mapped port and matches.
//! - **An empty mapping list proves nothing.** Without `Mapping.Audit` PVE
//!   answers an empty `200`. The token's own permissions settle it: an empty
//!   list with `Mapping.Audit` held is "no mappings"; without it the account
//!   is `unsupported` with `no_mapping_audit` and no device is touched, so a
//!   lost privilege never reads as every device having vanished.
//! - **PVE provides no exclusivity**, so `externally_attached` needs every
//!   guest config in the account, read bounded and tolerant: a guest that
//!   cannot be read is counted and reported, never fatal, and the report says
//!   when the scan was incomplete.
//! - **Ambiguity** (`ambiguous_mapping`) is a mapping with two entries for one
//!   node (PVE accepts it and refuses the attach) or an id-only entry whose
//!   vendor:product another mapping on the node also claims, or that more than
//!   one device on the node matches (when the node inventory is readable). An
//!   id-only entry with no such evidence is reported with a note that
//!   identical devices cannot be excluded without the inventory.
//!
//! The stored status is what the last refresh observed. What a reader sees is
//! [`view`]: a live Fleet reservation is authoritative (`reserved`, or
//! `quarantined` for an unknown attach or a failed detach), and an
//! observation older than the configured bound is `stale`, which an
//! `available` device cannot survive (it reads `missing`: not seen recently).
//!
//! Refresh is a mutation of Fleet-side records that sends the account's
//! token to Proxmox: `hardware.refresh`, with an audit intent recorded before
//! any Proxmox call and a completion event after the records are written.
//! Listing is `hardware.read` and calls nothing.
#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use fleet_core::{
    DeviceNodeEntry, DeviceStatus, HardwareDevice, HardwareKind, HardwareReservation,
    HardwareReservationState, IdGenerator as _, SensitiveString, UnsupportedReason,
};

use crate::audit::{AuditIntent, AuditMetadata};
use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Permission, authorize};
use crate::hardware::{DeviceObservation, HardwareStore, HardwareStoreError};
use crate::operation::AuditPort;
use crate::proxmox::privileges::{
    EffectivePermissions, PrivilegeStatus, RawTokenPermissions, evaluate_requirement,
    requirements_for_major, rules_major_for,
};
use crate::proxmox::{
    ProxmoxAccount, ProxmoxAccountPort, ProxmoxCredentialStore, ProxmoxSourceError,
    ProxmoxUseCaseError,
};

/// How long an observation counts as recent, in milliseconds, unless the
/// composition says otherwise. As for capacity observations, an old one is
/// not trusted.
pub const DEFAULT_OBSERVATION_MAX_AGE_MS: i64 = 900_000;

/// The oldest PVE major with USB resource mappings.
const MIN_PVE_MAJOR: u32 = 8;

/// The most warnings a report carries.
const MAX_REPORT_WARNINGS: usize = 64;

/// The most external references listed per device.
const MAX_REFERENCES_PER_DEVICE: usize = 16;

// ── what the Proxmox side observed (the port's own shapes) ──────────────

/// One `map` entry of a mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawMapEntry {
    /// The node the entry is for.
    pub node: String,
    /// The vendor id, lowercase hex.
    pub vendor_id: String,
    /// The product id, lowercase hex.
    pub product_id: String,
    /// The port (`<bus>-<usbpath>`), when the entry is path-based.
    pub path: Option<String>,
}

/// One USB resource mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawMapping {
    /// The mapping id.
    pub id: String,
    /// The readable entries.
    pub entries: Vec<RawMapEntry>,
    /// How many entries were malformed or beyond the bound; non-zero means
    /// the mapping is only partly known.
    pub unreadable_entries: usize,
}

/// What `check-node` said about one mapping on one node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RawNodeCheck {
    /// PVE reported nothing wrong: the device is at the mapped port.
    Present,
    /// PVE reported the device absent or another device at the port.
    NotPresent {
        /// PVE's finding, bounded.
        detail: String,
    },
    /// The check could not be made (the node did not answer, the call
    /// failed): presence is unknown, not absent.
    Unchecked {
        /// Why, bounded.
        detail: String,
    },
}

/// One device from a node's USB inventory (the optional enrichment).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawUsbDevice {
    /// The port (`<bus>-<usbpath>`).
    pub path: String,
    /// The vendor id, lowercase hex.
    pub vendor_id: String,
    /// The product id, lowercase hex.
    pub product_id: String,
    /// The manufacturer string.
    pub manufacturer: Option<String>,
    /// The product string.
    pub product: Option<String>,
}

/// One node's observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawNode {
    /// The node name.
    pub node: String,
    /// The `check-node` outcome per mapping id.
    pub checks: BTreeMap<String, RawNodeCheck>,
    /// The node's USB inventory; `None` when it was unreadable, which with
    /// the base token (no `Sys.Modify`) is normal.
    pub inventory: Option<Vec<RawUsbDevice>>,
}

/// Whether a guest's reference is only partly applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePending {
    /// The stored config has the entry and the running guest does not yet:
    /// the next start holds the device.
    Add,
    /// The stored config dropped the entry and the running guest still
    /// holds the device until it restarts.
    Remove,
}

impl ReferencePending {
    /// The stable string used in the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
        }
    }
}

/// One guest `usbN` entry that names a mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawGuestReference {
    /// The guest's node.
    pub node: String,
    /// The guest's VMID.
    pub vmid: u32,
    /// The guest's name, when known.
    pub guest_name: Option<String>,
    /// Whether the guest is a template. A template holds no device.
    pub template: bool,
    /// The slot, such as `usb0`.
    pub slot: String,
    /// The mapping the entry names.
    pub mapping_id: String,
    /// Set when only one of the stored and applied views holds it.
    pub pending: Option<ReferencePending>,
}

/// What the guest scan covered.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RawGuestScan {
    /// The entries found.
    pub references: Vec<RawGuestReference>,
    /// How many QEMU guests the cluster listed.
    pub guests_listed: usize,
    /// How many configs were read.
    pub guests_read: usize,
    /// How many configs could not be read (refused, unreadable).
    pub guests_unreadable: usize,
    /// Whether the bound dropped guests; the scan is then incomplete.
    pub truncated: bool,
}

impl RawGuestScan {
    /// Whether every listed guest's config was read.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.truncated && self.guests_unreadable == 0
    }
}

/// The mapping list as read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RawMappingsRead {
    /// The PVE has no resource-mapping endpoint (it predates mappings).
    EndpointAbsent {
        /// The PVE version, when it could be read.
        version: Option<String>,
    },
    /// The list was refused (403).
    Denied {
        /// The PVE version, when it could be read.
        version: Option<String>,
        /// The bounded detail.
        detail: String,
    },
    /// The list was read.
    Read {
        /// The PVE version.
        version: String,
        /// The mappings.
        mappings: Vec<RawMapping>,
        /// How many rows PVE returned. Zero is the only answer that can mean
        /// "no `Mapping.Audit`".
        rows_returned: usize,
        /// Whether the bounds dropped rows; the list is then incomplete.
        truncated: bool,
    },
}

/// The token's effective permissions, or why they could not be read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RawPermissionsRead {
    /// Read.
    Read(RawTokenPermissions),
    /// Refused or failed; token reasons cannot be derived.
    Unreadable {
        /// Why, bounded.
        detail: String,
    },
}

/// Everything one refresh observed on the Proxmox side.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawHardwareObservation {
    /// The mapping list.
    pub mappings: RawMappingsRead,
    /// One entry per node a mapping names.
    pub nodes: Vec<RawNode>,
    /// The guest scan.
    pub guests: RawGuestScan,
    /// The token's permissions.
    pub permissions: RawPermissionsRead,
    /// Normalization warnings, bounded.
    pub warnings: Vec<String>,
}

/// The Proxmox read port of the inventory. The composition implements it
/// over the provider; tests implement it over canned observations.
#[async_trait]
pub trait HardwareObservePort: fmt::Debug + Send + Sync {
    /// Reads what one refresh needs through the account's token. A read that
    /// fails for one node, mapping or guest is isolated into the result; only
    /// a failure that makes the whole observation meaningless (a refused
    /// token, an unreachable host) is an error.
    ///
    /// # Errors
    ///
    /// Fails with [`ProxmoxSourceError`].
    async fn observe(
        &self,
        account: &ProxmoxAccount,
        secret: &SensitiveString,
    ) -> Result<RawHardwareObservation, ProxmoxSourceError>;
}

// ── results ─────────────────────────────────────────────────────────────

/// Why an account as a whole cannot be inventoried, or is not verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountReason {
    /// The PVE predates USB resource mappings.
    PveTooOld,
    /// The token lacks `Mapping.Audit`, so the mapping list is empty or
    /// refused and says nothing about the devices.
    NoMappingAudit,
    /// The mapping list was empty and the token's permissions could not be
    /// read in full (refused or truncated), so "no mappings" cannot be told
    /// from "no `Mapping.Audit`".
    PermissionsUnreadable,
    /// The mapping list answered as an absent endpoint although the PVE
    /// version is one that has it: the list is unreadable, not unsupported.
    MappingListUnreadable,
}

impl AccountReason {
    /// The stable string used in the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::PveTooOld => "pve_too_old",
            Self::NoMappingAudit => "no_mapping_audit",
            Self::PermissionsUnreadable => "permissions_unreadable",
            Self::MappingListUnreadable => "mapping_list_unreadable",
        }
    }

    /// The stable human text.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::PveTooOld => "this Proxmox VE predates USB resource mappings",
            Self::NoMappingAudit => {
                "the token lacks Mapping.Audit on /mapping/usb, so the mapping list says nothing about the devices; grant the opt-in FleetUsb role"
            }
            Self::PermissionsUnreadable => {
                "the token's permissions could not be read in full, so an empty mapping list cannot be told from a token without Mapping.Audit and no token reason can be derived"
            }
            Self::MappingListUnreadable => {
                "the mapping list answered as an absent endpoint on a Proxmox VE version that has USB resource mappings, so it could not be read; no device was changed"
            }
        }
    }
}

/// Whether the account could be inventoried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountSupport {
    /// The mapping list is trustworthy.
    Supported,
    /// The account cannot be inventoried, for the reason.
    Unsupported(AccountReason),
    /// The list could not be verified (see the reason); no device was
    /// changed.
    Unverified(AccountReason),
}

impl AccountSupport {
    /// The stable state string used in the API.
    #[must_use]
    pub const fn state(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Unsupported(_) => "unsupported",
            Self::Unverified(_) => "unverified",
        }
    }

    /// The reason, unless supported.
    #[must_use]
    pub const fn reason(self) -> Option<AccountReason> {
        match self {
            Self::Supported => None,
            Self::Unsupported(reason) | Self::Unverified(reason) => Some(reason),
        }
    }
}

/// A device as a reader sees it: the stored record with the live
/// reservation and the observation's age applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceView {
    /// The stored record (its `status` is what the last refresh observed).
    pub device: HardwareDevice,
    /// The status a reader should act on.
    pub status: DeviceStatus,
    /// Whether the device was last seen longer ago than the bound. A device
    /// that was never seen on its node (`observed_at` 0) is stale.
    pub stale: bool,
    /// When the device was last seen on any node (epoch milliseconds; 0 when
    /// never): the newest entry's last seen time, else, for a device with no
    /// entry, the record's last change.
    pub observed_at: i64,
    /// The live reservation, when one holds the device.
    pub holder: Option<HardwareReservation>,
}

/// A guest reference to a device that Fleet did not make.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalReference {
    /// The guest's node.
    pub node: String,
    /// The guest's VMID.
    pub vmid: u32,
    /// The guest's name, when known.
    pub guest_name: Option<String>,
    /// The slot.
    pub slot: String,
    /// Whether the guest is a template (it holds nothing; its clones
    /// inherit the entry).
    pub template: bool,
    /// Set when only one of the stored and applied views holds it.
    pub pending: Option<ReferencePending>,
}

/// One device after a refresh: its view and what this observation added.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshedDevice {
    /// The device as a reader now sees it.
    pub view: DeviceView,
    /// The guests that reference the mapping and are not the reservation's
    /// own guest.
    pub external_references: Vec<ExternalReference>,
    /// Stable explanatory notes (an id-only entry that cannot be told apart,
    /// the finding behind `missing`, a partly read mapping).
    pub notes: Vec<String>,
}

/// What the guest scan covered, for the report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestScanSummary {
    /// How many QEMU guests the cluster listed.
    pub listed: usize,
    /// How many configs were read.
    pub read: usize,
    /// How many could not be read.
    pub unreadable: usize,
    /// Whether the bound dropped guests.
    pub truncated: bool,
}

/// The outcome of one refresh.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshReport {
    /// The account refreshed.
    pub account_id: String,
    /// When the observation was taken (epoch milliseconds).
    pub observed_at: i64,
    /// The PVE version, when it could be read.
    pub pve_version: Option<String>,
    /// Whether the account could be inventoried.
    pub support: AccountSupport,
    /// What the guest scan covered; `None` when the mapping list was not
    /// usable and no scan was needed.
    pub guest_scan: Option<GuestScanSummary>,
    /// The account's devices after the refresh, ordered by mapping id.
    pub devices: Vec<RefreshedDevice>,
    /// Warnings, bounded.
    pub warnings: Vec<String>,
}

// ── pure rules ──────────────────────────────────────────────────────────

/// The stable human text of an unsupported reason.
#[must_use]
pub const fn reason_text(reason: UnsupportedReason) -> &'static str {
    match reason {
        UnsupportedReason::NoNodeEntry => {
            "the mapping has no usable entry for any node (it was removed or names no node)"
        }
        UnsupportedReason::AmbiguousMapping => {
            "the device cannot be told apart: two entries for one node, or an id-only entry another device or mapping also matches; use a path-based entry per port"
        }
        UnsupportedReason::TokenLacksMappingUse => {
            "the token lacks Mapping.Use on the mapping (the opt-in FleetUsb role)"
        }
        UnsupportedReason::TokenLacksGuestHwtype => {
            "the token lacks VM.Config.HWType on any guest (the opt-in FleetUsb role)"
        }
        UnsupportedReason::PveTooOld => "this Proxmox VE predates USB resource mappings",
        UnsupportedReason::UsbInventoryUnreadable => {
            "whether the device is present or held could not be determined (a node check failed, the mapping is only partly readable, or not every guest config could be read)"
        }
    }
}

/// The status a reader should act on, and whether the observation is stale.
///
/// A live reservation is authoritative: `quarantined` for an unknown attach
/// or a failed detach, `reserved` otherwise. Without one, a stored `reserved`
/// is a lost write and reads `available`. An observation older than
/// `max_age_ms` is stale, and a stale `available` device was not seen
/// recently, so it reads `missing`; every other status is kept and carries
/// the stale flag.
#[must_use]
pub fn view(
    device: HardwareDevice,
    holder: Option<HardwareReservation>,
    now: i64,
    max_age_ms: i64,
) -> DeviceView {
    let observed_at = device
        .entries
        .iter()
        .map(|entry| entry.last_seen_at)
        .max()
        .unwrap_or(device.updated_at);
    // An observation from the future (a clock step) cannot be trusted either.
    let age = now.saturating_sub(observed_at);
    let stale = age > max_age_ms || age < -max_age_ms;
    let mut status = match &holder {
        Some(reservation)
            if matches!(
                reservation.state,
                HardwareReservationState::AttachUnknown | HardwareReservationState::DetachFailed
            ) =>
        {
            DeviceStatus::Quarantined
        }
        Some(_) => DeviceStatus::Reserved,
        None if device.status == DeviceStatus::Reserved => DeviceStatus::Available,
        None => device.status,
    };
    if stale && status == DeviceStatus::Available {
        status = DeviceStatus::Missing;
    }
    DeviceView {
        device,
        status,
        stale,
        observed_at,
        holder,
    }
}

/// The PVE major of a version string such as `9.2.2` or `8.4.0`.
fn pve_major(version: &str) -> Option<u32> {
    version
        .split(['.', '-'])
        .next()
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))?
        .parse()
        .ok()
}

/// Whether the token holds a privilege on a mapping: on the mapping itself
/// with any propagate flag, or from `/mapping/usb`, `/mapping` or `/` with a
/// propagating grant. Mirrors the table's `UsbMapping` scope.
fn holds_on_mapping(permissions: &EffectivePermissions, mapping_id: &str, privilege: &str) -> bool {
    let own = format!("/mapping/usb/{mapping_id}");
    permissions.iter().any(|(path, privileges)| {
        let Some(propagate) = privileges.get(privilege) else {
            return false;
        };
        path == &own || (*propagate && matches!(path.as_str(), "/mapping/usb" | "/mapping" | "/"))
    })
}

/// Whether `Mapping.Audit` is held for the whole mapping family, so a list
/// that omits a mapping omits it because it is gone.
fn audit_covers_every_mapping(permissions: &EffectivePermissions) -> bool {
    permissions.iter().any(|(path, privileges)| {
        privileges.get("Mapping.Audit") == Some(&true)
            && matches!(path.as_str(), "/mapping/usb" | "/mapping" | "/")
    })
}

/// Whether `Mapping.Audit` is held anywhere on a usb mapping path.
fn audit_held_anywhere(permissions: &EffectivePermissions) -> bool {
    permissions.iter().any(|(path, privileges)| {
        privileges.contains_key("Mapping.Audit")
            && (matches!(path.as_str(), "/mapping/usb" | "/mapping" | "/")
                || path.starts_with("/mapping/usb/"))
    })
}

/// The token, for the privileges attach and detach need.
struct TokenView<'a> {
    permissions: &'a EffectivePermissions,
    major: u8,
}

impl TokenView<'_> {
    fn guest_hwtype(&self) -> bool {
        requirements_for_major(self.major)
            .find(|row| row.id == "usb.attach-guest")
            .is_some_and(|row| {
                evaluate_requirement(row, self.permissions).status == PrivilegeStatus::Granted
            })
    }
}

/// Whether a mapping's device is at its mapped port.
enum Presence {
    Present,
    Missing,
    Unknown,
}

struct Derived {
    status: DeviceStatus,
    notes: Vec<String>,
}

struct Observation<'a> {
    too_old: bool,
    token: Option<TokenView<'a>>,
    nodes: BTreeMap<&'a str, &'a RawNode>,
    mappings: &'a [RawMapping],
    references: &'a [RawGuestReference],
    scan_complete: bool,
}

impl Observation<'_> {
    /// The ambiguity of a mapping, as a note, when it has any.
    fn ambiguity(&self, mapping: &RawMapping) -> Option<String> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for entry in &mapping.entries {
            if !seen.insert(entry.node.as_str()) {
                return Some(format!(
                    "the mapping has more than one entry for node {}; PVE refuses to attach it",
                    entry.node
                ));
            }
        }
        for entry in mapping.entries.iter().filter(|entry| entry.path.is_none()) {
            let same = |vendor: &str, product: &str| {
                vendor == entry.vendor_id && product == entry.product_id
            };
            if let Some(inventory) = self
                .nodes
                .get(entry.node.as_str())
                .and_then(|node| node.inventory.as_ref())
                && inventory
                    .iter()
                    .filter(|device| same(&device.vendor_id, &device.product_id))
                    .count()
                    > 1
            {
                return Some(format!(
                    "the id-only entry for node {} matches more than one device; PVE picks the first",
                    entry.node
                ));
            }
            if let Some(other) = self.mappings.iter().find(|other| {
                other.id != mapping.id
                    && other.entries.iter().any(|candidate| {
                        candidate.node == entry.node
                            && same(&candidate.vendor_id, &candidate.product_id)
                    })
            }) {
                return Some(format!(
                    "the id-only entry for node {} shares {}:{} with mapping {}; PVE would resolve it to the first device",
                    entry.node, entry.vendor_id, entry.product_id, other.id
                ));
            }
        }
        None
    }

    /// Whether the device is present: present on any node is present;
    /// otherwise an unchecked node leaves it unknown and only a clean "not
    /// there" is missing. What each node said is added to `notes`.
    fn presence(&self, mapping: &RawMapping, notes: &mut Vec<String>) -> Presence {
        let mut present = false;
        let mut unknown = false;
        for entry in &mapping.entries {
            match self
                .nodes
                .get(entry.node.as_str())
                .and_then(|node| node.checks.get(&mapping.id))
            {
                Some(RawNodeCheck::Present) => present = true,
                Some(RawNodeCheck::NotPresent { detail }) => {
                    notes.push(format!("node {}: {detail}", entry.node));
                }
                Some(RawNodeCheck::Unchecked { detail }) => {
                    unknown = true;
                    notes.push(format!(
                        "node {} could not be checked: {detail}",
                        entry.node
                    ));
                }
                None => {
                    unknown = true;
                    notes.push(format!("node {} was not checked", entry.node));
                }
            }
        }
        if present {
            Presence::Present
        } else if unknown {
            Presence::Unknown
        } else {
            Presence::Missing
        }
    }

    /// Says so for an id-only entry whose node inventory was not readable:
    /// identical devices cannot be excluded without it.
    fn note_unverified_id_only(&self, mapping: &RawMapping, notes: &mut Vec<String>) {
        for entry in mapping.entries.iter().filter(|entry| entry.path.is_none()) {
            let readable = self
                .nodes
                .get(entry.node.as_str())
                .is_some_and(|node| node.inventory.is_some());
            if !readable {
                notes.push(format!(
                    "the entry for node {} is id-only ({}:{}); identical devices cannot be excluded without the node USB inventory",
                    entry.node, entry.vendor_id, entry.product_id
                ));
            }
        }
    }

    fn derive(&self, mapping: &RawMapping, has_live_reservation: bool) -> Derived {
        let mut notes = Vec::new();
        if mapping.unreadable_entries > 0 {
            notes.push(format!(
                "{} map entr{} of the mapping could not be read",
                mapping.unreadable_entries,
                if mapping.unreadable_entries == 1 {
                    "y"
                } else {
                    "ies"
                }
            ));
        }
        let status = |status| Derived {
            status,
            notes: Vec::new(),
        };
        if self.too_old {
            return status(DeviceStatus::Unsupported(UnsupportedReason::PveTooOld));
        }
        if mapping.entries.is_empty() {
            return Derived {
                status: DeviceStatus::Unsupported(if mapping.unreadable_entries > 0 {
                    UnsupportedReason::UsbInventoryUnreadable
                } else {
                    UnsupportedReason::NoNodeEntry
                }),
                notes,
            };
        }
        if let Some(note) = self.ambiguity(mapping) {
            notes.push(note);
            return Derived {
                status: DeviceStatus::Unsupported(UnsupportedReason::AmbiguousMapping),
                notes,
            };
        }
        if let Some(token) = &self.token {
            if !holds_on_mapping(token.permissions, &mapping.id, "Mapping.Use") {
                return Derived {
                    status: DeviceStatus::Unsupported(UnsupportedReason::TokenLacksMappingUse),
                    notes,
                };
            }
            if !token.guest_hwtype() {
                return Derived {
                    status: DeviceStatus::Unsupported(UnsupportedReason::TokenLacksGuestHwtype),
                    notes,
                };
            }
        }
        match self.presence(mapping, &mut notes) {
            Presence::Present => {}
            Presence::Missing => {
                return Derived {
                    status: DeviceStatus::Missing,
                    notes,
                };
            }
            Presence::Unknown => {
                return Derived {
                    status: DeviceStatus::Unsupported(UnsupportedReason::UsbInventoryUnreadable),
                    notes,
                };
            }
        }
        self.note_unverified_id_only(mapping, &mut notes);
        let referenced = self
            .references
            .iter()
            .any(|reference| reference.mapping_id == mapping.id && !reference.template);
        if referenced && !has_live_reservation {
            return Derived {
                status: DeviceStatus::ExternallyAttached,
                notes,
            };
        }
        if !self.scan_complete {
            notes.push(
                "not every guest config could be read, so a guest may reference this device unseen"
                    .to_owned(),
            );
            // `available` is a claim that nothing references the device. An
            // incomplete scan cannot make it, and a stored `available` is
            // trusted by readers and by the reservation store, so it is not
            // recorded: the device is not allocatable until a complete scan.
            // A device Fleet itself holds keeps its place (the reservation
            // is what excludes a second holder).
            if !has_live_reservation {
                return Derived {
                    status: DeviceStatus::Unsupported(UnsupportedReason::UsbInventoryUnreadable),
                    notes,
                };
            }
        }
        Derived {
            status: DeviceStatus::Available,
            notes,
        }
    }
}

/// The per-node entries to record for a mapping: the first entry per node
/// (the store keeps one per node), with strings from the node inventory when
/// it was readable, and a last-seen time that moves only when the node
/// reported the device present.
fn entries_for(
    mapping: &RawMapping,
    nodes: &BTreeMap<&str, &RawNode>,
    previous: Option<&HardwareDevice>,
    now: i64,
) -> Vec<DeviceNodeEntry> {
    let mut recorded: BTreeSet<&str> = BTreeSet::new();
    let mut entries = Vec::new();
    for entry in &mapping.entries {
        if !recorded.insert(entry.node.as_str()) {
            continue;
        }
        let node = nodes.get(entry.node.as_str());
        let present = matches!(
            node.and_then(|node| node.checks.get(&mapping.id)),
            Some(RawNodeCheck::Present)
        );
        let seen = node
            .and_then(|node| node.inventory.as_ref())
            .and_then(|inventory| {
                inventory.iter().find(|device| match &entry.path {
                    Some(path) => &device.path == path,
                    None => {
                        device.vendor_id == entry.vendor_id && device.product_id == entry.product_id
                    }
                })
            });
        let last_seen_at = if present {
            now
        } else {
            previous
                .and_then(|device| device.entries.iter().find(|old| old.node == entry.node))
                .map_or(0, |old| old.last_seen_at)
        };
        entries.push(DeviceNodeEntry {
            node: entry.node.clone(),
            vendor_id: entry.vendor_id.clone(),
            product_id: entry.product_id.clone(),
            usbpath: entry
                .path
                .clone()
                .or_else(|| seen.map(|device| device.path.clone())),
            manufacturer: seen.and_then(|device| device.manufacturer.clone()),
            product: seen.and_then(|device| device.product.clone()),
            last_seen_at,
        });
    }
    entries
}

// ── the service ─────────────────────────────────────────────────────────

/// The clock the service reads, in epoch milliseconds.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// Which devices a list shows.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceFilter {
    /// Only this account's devices.
    pub account_id: Option<String>,
}

/// The hardware inventory use cases.
pub struct HardwareInventory {
    accounts: Arc<dyn ProxmoxAccountPort>,
    credentials: Arc<dyn ProxmoxCredentialStore>,
    store: Arc<dyn HardwareStore>,
    observer: Arc<dyn HardwareObservePort>,
    audit: Arc<dyn AuditPort>,
    max_age_ms: i64,
    clock: Clock,
}

impl fmt::Debug for HardwareInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HardwareInventory")
            .field("max_age_ms", &self.max_age_ms)
            .finish_non_exhaustive()
    }
}

fn backend(error: &HardwareStoreError) -> ProxmoxUseCaseError {
    ProxmoxUseCaseError::Backend {
        context: "hardware",
        detail: error.to_string(),
    }
}

impl HardwareInventory {
    /// Composes the service from its ports, with the default observation
    /// bound and the wall clock.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn ProxmoxAccountPort>,
        credentials: Arc<dyn ProxmoxCredentialStore>,
        store: Arc<dyn HardwareStore>,
        observer: Arc<dyn HardwareObservePort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            accounts,
            credentials,
            store,
            observer,
            audit,
            max_age_ms: DEFAULT_OBSERVATION_MAX_AGE_MS,
            clock: Arc::new(fleet_core::SystemClock::now_unix_millis),
        }
    }

    /// Sets how long an observation counts as recent.
    #[must_use]
    pub fn with_max_age_ms(mut self, max_age_ms: i64) -> Self {
        self.max_age_ms = max_age_ms.max(1);
        self
    }

    /// Replaces the clock (tests).
    #[must_use]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Lists the devices as a reader should see them, ordered by account
    /// then mapping id, after the cursor (the last device id of the previous
    /// page). A read of Fleet's own records: it calls nothing on Proxmox.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown account, a cursor that names no device in
    /// the list, or a backend failure.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        filter: &DeviceFilter,
        limit: usize,
        after_id: Option<&str>,
    ) -> Result<Vec<DeviceView>, ProxmoxUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::HardwareRead,
                resource: filter.account_id.as_deref(),
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)?;
        let account_ids = match &filter.account_id {
            Some(id) => vec![self.require_account(id).await?.id],
            None => self
                .accounts
                .list()
                .await
                .map_err(|detail| ProxmoxUseCaseError::Backend {
                    context: "accounts",
                    detail,
                })?
                .into_iter()
                .map(|account| account.id)
                .collect(),
        };
        let now = (self.clock)();
        let live: BTreeMap<String, HardwareReservation> = self
            .store
            .list_live_reservations()
            .await
            .map_err(|error| backend(&error))?
            .into_iter()
            .map(|reservation| (reservation.device_id.clone(), reservation))
            .collect();
        let mut views = Vec::new();
        for account_id in &account_ids {
            for device in self
                .store
                .list_devices(account_id)
                .await
                .map_err(|error| backend(&error))?
            {
                let holder = live.get(&device.id).cloned();
                views.push(view(device, holder, now, self.max_age_ms));
            }
        }
        views.sort_by(|left, right| {
            (&left.device.account_id, &left.device.mapping_id)
                .cmp(&(&right.device.account_id, &right.device.mapping_id))
        });
        if let Some(after_id) = after_id {
            let Some(position) = views.iter().position(|view| view.device.id == after_id) else {
                return Err(ProxmoxUseCaseError::Invalid {
                    detail: "the cursor names no device in the list".to_owned(),
                });
            };
            views.drain(..=position);
        }
        views.truncate(limit);
        Ok(views)
    }

    /// Refreshes one account's inventory: reads the mappings, the nodes, every
    /// guest config and the token's permissions through the account's token
    /// and records the derived status of each mapping. Authorized as
    /// `hardware.refresh` on the account; the audit intent lands before any
    /// Proxmox call, and a completion event follows the records.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown or unconfirmed account, a missing token
    /// secret, a failed audit write, a Proxmox failure that makes the
    /// observation meaningless, or a backend failure.
    pub async fn refresh(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        correlation_id: Option<&str>,
        account_id: &str,
    ) -> Result<RefreshReport, ProxmoxUseCaseError> {
        let decision = authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::HardwareRefresh,
                resource: Some(account_id),
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)?;
        let account = self.require_account(account_id).await?;
        if account.fingerprint.is_none() {
            return Err(ProxmoxUseCaseError::UnconfirmedTrust {
                account: account.name,
            });
        }
        let secret = self
            .credentials
            .load(&account.id)
            .await
            .map_err(ProxmoxUseCaseError::Credentials)?
            .ok_or_else(|| ProxmoxUseCaseError::NoSecret {
                account: account.name.clone(),
            })?;
        self.record(
            principal,
            &decision,
            correlation_id,
            &account.id,
            "hardware_refresh_started",
            &[],
        )
        .await?;
        let observed = async {
            let raw = self
                .observer
                .observe(&account, &SensitiveString::new(secret))
                .await
                .map_err(ProxmoxUseCaseError::Source)?;
            let now = (self.clock)();
            self.apply(&account.id, raw, now).await
        }
        .await;
        let mut report = match observed {
            Ok(report) => report,
            Err(error) => {
                // The intent is on the ledger; give it a result. Best
                // effort: the failure being reported matters more than an
                // audit sink that is also failing.
                let _ = self
                    .record(
                        principal,
                        &decision,
                        correlation_id,
                        &account.id,
                        "hardware_refresh_failed",
                        &[("failure", failure_class(&error))],
                    )
                    .await;
                return Err(error);
            }
        };
        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        for device in &report.devices {
            *counts.entry(device.view.status.id()).or_default() += 1;
        }
        let summary = counts
            .iter()
            .map(|(status, count)| format!("{status}={count}"))
            .collect::<Vec<_>>()
            .join(",");
        let devices = report.devices.len().to_string();
        if let Err(error) = self
            .record(
                principal,
                &decision,
                correlation_id,
                &account.id,
                "hardware_refreshed",
                &[
                    ("support", report.support.state()),
                    ("devices", &devices),
                    ("statuses", &summary),
                ],
            )
            .await
        {
            // The records are written and the intent is on the ledger; an
            // outcome that cannot be recorded is said, not hidden.
            push_warning(
                &mut report.warnings,
                format!("the completion audit event could not be recorded: {error}"),
            );
        }
        Ok(report)
    }

    async fn record(
        &self,
        principal: &ActingPrincipal,
        decision: &crate::authz::Decision,
        correlation_id: Option<&str>,
        account_id: &str,
        event: &str,
        facts: &[(&str, &str)],
    ) -> Result<(), ProxmoxUseCaseError> {
        let audit_error = |detail: String| ProxmoxUseCaseError::Backend {
            context: "audit",
            detail,
        };
        let mut metadata = AuditMetadata::default();
        metadata
            .insert("event", event)
            .map_err(|error| audit_error(error.to_string()))?;
        for (key, value) in facts {
            metadata
                .insert(key, value)
                .map_err(|error| audit_error(error.to_string()))?;
        }
        self.audit
            .record_intent(&AuditIntent {
                actor: principal.id.clone(),
                action: Permission::HardwareRefresh.id().to_owned(),
                resource: Some(account_id.to_owned()),
                decision: *decision,
                correlation_id: correlation_id.map(str::to_owned),
                operation_id: None,
                metadata,
            })
            .await
            .map_err(audit_error)
    }

    async fn require_account(&self, id: &str) -> Result<ProxmoxAccount, ProxmoxUseCaseError> {
        self.accounts.get(id).await.map_err(|detail| {
            if detail.contains("not found") {
                ProxmoxUseCaseError::NotFound {
                    what: format!("account {id}"),
                }
            } else {
                ProxmoxUseCaseError::Backend {
                    context: "accounts",
                    detail,
                }
            }
        })
    }

    /// Turns one observation into stored statuses and the report.
    #[allow(clippy::too_many_lines)]
    async fn apply(
        &self,
        account_id: &str,
        raw: RawHardwareObservation,
        now: i64,
    ) -> Result<RefreshReport, ProxmoxUseCaseError> {
        let mut warnings = raw.warnings;
        // A truncated permissions map may lack the very path that grants a
        // privilege, so it proves nothing about what is missing: it is
        // treated as unread.
        let permissions = match &raw.permissions {
            RawPermissionsRead::Read(read) if !read.truncated => Some(read),
            RawPermissionsRead::Read(_) => {
                push_warning(
                    &mut warnings,
                    "the token's permissions were truncated at the provider's bounds; token reasons and Mapping.Audit are not derived from them"
                        .to_owned(),
                );
                None
            }
            RawPermissionsRead::Unreadable { .. } => None,
        };
        if let RawPermissionsRead::Unreadable { detail } = &raw.permissions {
            push_warning(
                &mut warnings,
                format!(
                    "the token's permissions could not be read ({detail}); token reasons are not derived"
                ),
            );
        }
        let (version, mappings, rows_returned, truncated) = match raw.mappings {
            RawMappingsRead::EndpointAbsent { version } => {
                // Absent means "too old" for a version below the first that
                // has mappings, or one that is not known (the endpoint is
                // all there is). On a version that has them, the answer is a
                // fault, and calling it "too old" would contradict the
                // version in the same report.
                let known_current = version
                    .as_deref()
                    .and_then(pve_major)
                    .is_some_and(|major| major >= MIN_PVE_MAJOR);
                if known_current {
                    push_warning(
                        &mut warnings,
                        "the mapping list answered as an absent endpoint; no device was changed"
                            .to_owned(),
                    );
                    return self
                        .report(
                            account_id,
                            now,
                            version,
                            AccountSupport::Unverified(AccountReason::MappingListUnreadable),
                            None,
                            &BTreeMap::new(),
                            warnings,
                        )
                        .await;
                }
                self.mark_all(account_id, UnsupportedReason::PveTooOld, now)
                    .await?;
                return self
                    .report(
                        account_id,
                        now,
                        version,
                        AccountSupport::Unsupported(AccountReason::PveTooOld),
                        None,
                        &BTreeMap::new(),
                        warnings,
                    )
                    .await;
            }
            RawMappingsRead::Denied { version, detail } => {
                push_warning(
                    &mut warnings,
                    format!("the mapping list was refused ({detail}); no device was changed"),
                );
                return self
                    .report(
                        account_id,
                        now,
                        version,
                        AccountSupport::Unsupported(AccountReason::NoMappingAudit),
                        None,
                        &BTreeMap::new(),
                        warnings,
                    )
                    .await;
            }
            RawMappingsRead::Read {
                version,
                mappings,
                rows_returned,
                truncated,
            } => (version, mappings, rows_returned, truncated),
        };
        let major = pve_major(&version);
        let too_old = major.is_some_and(|major| major < MIN_PVE_MAJOR);
        if too_old {
            self.mark_all(account_id, UnsupportedReason::PveTooOld, now)
                .await?;
            return self
                .report(
                    account_id,
                    now,
                    Some(version),
                    AccountSupport::Unsupported(AccountReason::PveTooOld),
                    None,
                    &BTreeMap::new(),
                    warnings,
                )
                .await;
        }
        // An empty list is "no mappings" only when the token can audit them.
        if rows_returned == 0 && !truncated {
            let settled = permissions.map(|read| audit_held_anywhere(&read.paths));
            match settled {
                Some(true) => {}
                Some(false) => {
                    return self
                        .report(
                            account_id,
                            now,
                            Some(version),
                            AccountSupport::Unsupported(AccountReason::NoMappingAudit),
                            None,
                            &BTreeMap::new(),
                            warnings,
                        )
                        .await;
                }
                None => {
                    return self
                        .report(
                            account_id,
                            now,
                            Some(version),
                            AccountSupport::Unverified(AccountReason::PermissionsUnreadable),
                            None,
                            &BTreeMap::new(),
                            warnings,
                        )
                        .await;
                }
            }
        }
        if truncated {
            push_warning(
                &mut warnings,
                "the mapping list was cut at the provider's bound; mappings beyond it are not inventoried and no missing mapping was marked"
                    .to_owned(),
            );
        }
        let token = permissions.and_then(|read| {
            rules_major_for(&read.version)
                .or_else(|| rules_major_for(&version))
                .map(|(major, _)| TokenView {
                    permissions: &read.paths,
                    major,
                })
        });
        let can_prune =
            !truncated && permissions.is_some_and(|read| audit_covers_every_mapping(&read.paths));
        if !can_prune && !truncated && permissions.is_none() {
            push_warning(
                &mut warnings,
                "mappings that PVE no longer lists were not marked, because the token's permissions could not be read"
                    .to_owned(),
            );
        }
        let observation = Observation {
            too_old: false,
            token,
            nodes: raw
                .nodes
                .iter()
                .map(|node| (node.node.as_str(), node))
                .collect(),
            mappings: &mappings,
            references: &raw.guests.references,
            scan_complete: raw.guests.is_complete(),
        };
        let stored: BTreeMap<String, HardwareDevice> = self
            .store
            .list_devices(account_id)
            .await
            .map_err(|error| backend(&error))?
            .into_iter()
            .map(|device| (device.mapping_id.clone(), device))
            .collect();
        let live: BTreeMap<String, HardwareReservation> = self
            .store
            .list_live_reservations()
            .await
            .map_err(|error| backend(&error))?
            .into_iter()
            .map(|reservation| (reservation.device_id.clone(), reservation))
            .collect();
        let mut extras: BTreeMap<String, (Vec<ExternalReference>, Vec<String>)> = BTreeMap::new();
        for mapping in &mappings {
            let previous = stored.get(&mapping.id);
            let reservation = previous.and_then(|device| live.get(&device.id));
            let mut derived = observation.derive(mapping, reservation.is_some());
            // A quarantine is information the saga or an operator owns; a
            // refresh never clears it.
            if previous.is_some_and(|device| device.status == DeviceStatus::Quarantined) {
                derived.status = DeviceStatus::Quarantined;
            }
            let own_guest = reservation.and_then(|reservation| reservation.guest.as_ref());
            let references: Vec<ExternalReference> = raw
                .guests
                .references
                .iter()
                .filter(|reference| reference.mapping_id == mapping.id)
                .filter(|reference| {
                    !own_guest.is_some_and(|guest| {
                        guest.node == reference.node && guest.vmid == reference.vmid
                    })
                })
                .take(MAX_REFERENCES_PER_DEVICE)
                .map(|reference| ExternalReference {
                    node: reference.node.clone(),
                    vmid: reference.vmid,
                    guest_name: reference.guest_name.clone(),
                    slot: reference.slot.clone(),
                    template: reference.template,
                    pending: reference.pending,
                })
                .collect();
            if reservation.is_some() && references.iter().any(|reference| !reference.template) {
                derived.notes.push(
                    "a guest other than the reservation's own references this device".to_owned(),
                );
            }
            let device = self
                .store
                .upsert_device(
                    &DeviceObservation {
                        id: fleet_core::UuidV7Generator.next_resource_id().to_string(),
                        account_id: account_id.to_owned(),
                        mapping_id: mapping.id.clone(),
                        kind: HardwareKind::Usb,
                        entries: entries_for(mapping, &observation.nodes, previous, now),
                        status: derived.status,
                    },
                    now,
                )
                .await
                .map_err(|error| backend(&error))?;
            extras.insert(device.mapping_id.clone(), (references, derived.notes));
        }
        if can_prune {
            let listed: BTreeSet<&str> =
                mappings.iter().map(|mapping| mapping.id.as_str()).collect();
            for device in stored.values() {
                if listed.contains(device.mapping_id.as_str())
                    || device.status == DeviceStatus::Quarantined
                {
                    continue;
                }
                self.store
                    .set_device_status(
                        &device.id,
                        DeviceStatus::Unsupported(UnsupportedReason::NoNodeEntry),
                        now,
                    )
                    .await
                    .map_err(|error| backend(&error))?;
                extras.insert(
                    device.mapping_id.clone(),
                    (
                        Vec::new(),
                        vec!["PVE no longer lists this mapping".to_owned()],
                    ),
                );
            }
        }
        let summary = GuestScanSummary {
            listed: raw.guests.guests_listed,
            read: raw.guests.guests_read,
            unreadable: raw.guests.guests_unreadable,
            truncated: raw.guests.truncated,
        };
        if !raw.guests.is_complete() {
            push_warning(
                &mut warnings,
                format!(
                    "the guest scan is incomplete ({} of {} configs read{}); an available device may be referenced by a guest that was not read",
                    summary.read,
                    summary.listed,
                    if summary.truncated {
                        ", list truncated"
                    } else {
                        ""
                    }
                ),
            );
        }
        self.report(
            account_id,
            now,
            Some(version),
            AccountSupport::Supported,
            Some(summary),
            &extras,
            warnings,
        )
        .await
    }

    /// Marks every stored device of the account unsupported for a reason
    /// that holds for the whole account, keeping a quarantine.
    async fn mark_all(
        &self,
        account_id: &str,
        reason: UnsupportedReason,
        now: i64,
    ) -> Result<(), ProxmoxUseCaseError> {
        for device in self
            .store
            .list_devices(account_id)
            .await
            .map_err(|error| backend(&error))?
        {
            if device.status == DeviceStatus::Quarantined {
                continue;
            }
            self.store
                .set_device_status(&device.id, DeviceStatus::Unsupported(reason), now)
                .await
                .map_err(|error| backend(&error))?;
        }
        Ok(())
    }

    /// The report: the account's devices as a reader now sees them, with
    /// what this observation added.
    #[allow(clippy::too_many_arguments)]
    async fn report(
        &self,
        account_id: &str,
        now: i64,
        pve_version: Option<String>,
        support: AccountSupport,
        guest_scan: Option<GuestScanSummary>,
        extras: &BTreeMap<String, (Vec<ExternalReference>, Vec<String>)>,
        warnings: Vec<String>,
    ) -> Result<RefreshReport, ProxmoxUseCaseError> {
        let live: BTreeMap<String, HardwareReservation> = self
            .store
            .list_live_reservations()
            .await
            .map_err(|error| backend(&error))?
            .into_iter()
            .map(|reservation| (reservation.device_id.clone(), reservation))
            .collect();
        let devices = self
            .store
            .list_devices(account_id)
            .await
            .map_err(|error| backend(&error))?
            .into_iter()
            .map(|device| {
                let (external_references, notes) =
                    extras.get(&device.mapping_id).cloned().unwrap_or_default();
                let holder = live.get(&device.id).cloned();
                RefreshedDevice {
                    view: view(device, holder, now, self.max_age_ms),
                    external_references,
                    notes,
                }
            })
            .collect();
        Ok(RefreshReport {
            account_id: account_id.to_owned(),
            observed_at: now,
            pve_version,
            support,
            guest_scan,
            devices,
            warnings,
        })
    }
}

/// A stable, secret-free class of a refresh failure, for the audit ledger.
const fn failure_class(error: &ProxmoxUseCaseError) -> &'static str {
    match error {
        ProxmoxUseCaseError::Source(source) => match source {
            ProxmoxSourceError::FingerprintMismatch { .. } => "fingerprint_mismatch",
            ProxmoxSourceError::Auth => "auth",
            ProxmoxSourceError::Forbidden { .. } => "forbidden",
            ProxmoxSourceError::Http { .. } => "http",
            ProxmoxSourceError::InvalidPayload { .. } => "invalid_payload",
            ProxmoxSourceError::Connect { .. } => "connect",
            ProxmoxSourceError::Credentials(_) => "credentials",
        },
        ProxmoxUseCaseError::Credentials(_) => "credentials",
        ProxmoxUseCaseError::Backend { .. } => "backend",
        _ => "error",
    }
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_REPORT_WARNINGS {
        warnings.push(warning);
    } else if warnings.len() == MAX_REPORT_WARNINGS {
        warnings.push("further warnings were dropped".to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_core::{GuestTarget, ReservationOwnerKind};

    const NOW: i64 = 10_000_000;
    const MAX_AGE: i64 = 900_000;

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

    fn not_there() -> RawNodeCheck {
        RawNodeCheck::NotPresent {
            detail: "usb device '1-10' not found".to_owned(),
        }
    }

    fn permissions(entries: &[(&str, &[(&str, bool)])]) -> EffectivePermissions {
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

    fn full_token() -> EffectivePermissions {
        permissions(&[(
            "/",
            &[
                ("Mapping.Use", true),
                ("Mapping.Audit", true),
                ("VM.Config.HWType", true),
            ],
        )])
    }

    fn reference(mapping_id: &str, template: bool) -> RawGuestReference {
        RawGuestReference {
            node: "pve".to_owned(),
            vmid: 200,
            guest_name: Some("guest".to_owned()),
            template,
            slot: "usb0".to_owned(),
            mapping_id: mapping_id.to_owned(),
            pending: None,
        }
    }

    struct Fixture {
        mappings: Vec<RawMapping>,
        nodes: Vec<RawNode>,
        references: Vec<RawGuestReference>,
        permissions: Option<EffectivePermissions>,
        scan_complete: bool,
        too_old: bool,
    }

    impl Fixture {
        fn new(mappings: Vec<RawMapping>, nodes: Vec<RawNode>) -> Self {
            Self {
                mappings,
                nodes,
                references: Vec::new(),
                permissions: Some(full_token()),
                scan_complete: true,
                too_old: false,
            }
        }

        fn status(&self, mapping_id: &str, reserved: bool) -> Derived {
            let observation = Observation {
                too_old: self.too_old,
                token: self.permissions.as_ref().map(|permissions| TokenView {
                    permissions,
                    major: 9,
                }),
                nodes: self.nodes.iter().map(|n| (n.node.as_str(), n)).collect(),
                mappings: &self.mappings,
                references: &self.references,
                scan_complete: self.scan_complete,
            };
            let mapping = self
                .mappings
                .iter()
                .find(|mapping| mapping.id == mapping_id)
                .unwrap();
            observation.derive(mapping, reserved)
        }
    }

    fn present(ids: &[&str]) -> Vec<RawNode> {
        vec![node(
            "pve",
            &ids.iter()
                .map(|id| (*id, RawNodeCheck::Present))
                .collect::<Vec<_>>(),
        )]
    }

    #[test]
    fn a_present_unreferenced_path_mapping_is_available() {
        let fixture = Fixture::new(
            vec![mapping(
                "dev-a",
                vec![entry("pve", "05ac", "1500", Some("1-10"))],
            )],
            present(&["dev-a"]),
        );
        let derived = fixture.status("dev-a", false);
        assert_eq!(derived.status, DeviceStatus::Available);
        assert!(derived.notes.is_empty(), "{:?}", derived.notes);
    }

    #[test]
    fn a_guest_reference_without_a_reservation_is_externally_attached() {
        let mut fixture = Fixture::new(
            vec![mapping("dev-a", vec![entry("pve", "04d8", "e626", None)])],
            present(&["dev-a"]),
        );
        fixture.references = vec![reference("dev-a", false)];
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::ExternallyAttached
        );
        // Fleet's own reservation explains the reference.
        assert_eq!(
            fixture.status("dev-a", true).status,
            DeviceStatus::Available
        );
        // A template holds nothing.
        fixture.references = vec![reference("dev-a", true)];
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::Available
        );
    }

    #[test]
    fn an_absent_device_is_missing_and_an_unchecked_node_is_unreadable() {
        let fixture = Fixture::new(
            vec![mapping(
                "dev-a",
                vec![entry("pve", "05ac", "1500", Some("1-10"))],
            )],
            vec![node("pve", &[("dev-a", not_there())])],
        );
        let derived = fixture.status("dev-a", false);
        assert_eq!(derived.status, DeviceStatus::Missing);
        assert!(
            derived.notes[0].contains("not found"),
            "{:?}",
            derived.notes
        );

        let fixture = Fixture::new(
            vec![mapping(
                "dev-a",
                vec![entry("pve", "05ac", "1500", Some("1-10"))],
            )],
            vec![node(
                "pve",
                &[(
                    "dev-a",
                    RawNodeCheck::Unchecked {
                        detail: "connection refused".to_owned(),
                    },
                )],
            )],
        );
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::Unsupported(UnsupportedReason::UsbInventoryUnreadable)
        );
        // A node that was never checked is unknown, not absent.
        let fixture = Fixture::new(
            vec![mapping(
                "dev-a",
                vec![entry("pve", "05ac", "1500", Some("1-10"))],
            )],
            Vec::new(),
        );
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::Unsupported(UnsupportedReason::UsbInventoryUnreadable)
        );
    }

    #[test]
    fn present_on_any_node_is_present() {
        let fixture = Fixture::new(
            vec![mapping(
                "dev-a",
                vec![
                    entry("pve1", "05ac", "1500", Some("1-10")),
                    entry("pve2", "05ac", "1500", Some("1-7")),
                ],
            )],
            vec![
                node("pve1", &[("dev-a", not_there())]),
                node("pve2", &[("dev-a", RawNodeCheck::Present)]),
            ],
        );
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::Available
        );
    }

    #[test]
    fn a_mapping_without_a_usable_entry_has_no_node_entry() {
        let fixture = Fixture::new(vec![mapping("dev-a", Vec::new())], Vec::new());
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::Unsupported(UnsupportedReason::NoNodeEntry)
        );
        // A mapping some of whose entries could not be read is not "no entry".
        let mut partial = mapping("dev-a", Vec::new());
        partial.unreadable_entries = 2;
        let fixture = Fixture::new(vec![partial], Vec::new());
        let derived = fixture.status("dev-a", false);
        assert_eq!(
            derived.status,
            DeviceStatus::Unsupported(UnsupportedReason::UsbInventoryUnreadable)
        );
        assert!(
            derived.notes[0].contains("2 map entries"),
            "{:?}",
            derived.notes
        );
    }

    #[test]
    fn two_entries_for_one_node_are_ambiguous() {
        let fixture = Fixture::new(
            vec![mapping(
                "dev-a",
                vec![
                    entry("pve", "05ac", "1500", Some("1-10")),
                    entry("pve", "05ac", "1500", Some("1-7")),
                ],
            )],
            present(&["dev-a"]),
        );
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::Unsupported(UnsupportedReason::AmbiguousMapping)
        );
    }

    #[test]
    fn an_id_only_entry_is_ambiguous_when_another_mapping_or_the_inventory_shares_it() {
        // Another mapping on the node claims the same vendor:product.
        let fixture = Fixture::new(
            vec![
                mapping("dev-a", vec![entry("pve", "05ac", "1500", None)]),
                mapping("dev-b", vec![entry("pve", "05ac", "1500", Some("1-7"))]),
            ],
            present(&["dev-a", "dev-b"]),
        );
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::Unsupported(UnsupportedReason::AmbiguousMapping)
        );
        // The path-based mapping is not made ambiguous by the other one.
        assert_eq!(
            fixture.status("dev-b", false).status,
            DeviceStatus::Available
        );

        // Two matching devices in a readable node inventory.
        let mut nodes = present(&["dev-a"]);
        let device = |path: &str| RawUsbDevice {
            path: path.to_owned(),
            vendor_id: "05ac".to_owned(),
            product_id: "1500".to_owned(),
            manufacturer: None,
            product: None,
        };
        nodes[0].inventory = Some(vec![device("1-10"), device("1-7")]);
        let fixture = Fixture::new(
            vec![mapping("dev-a", vec![entry("pve", "05ac", "1500", None)])],
            nodes,
        );
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::Unsupported(UnsupportedReason::AmbiguousMapping)
        );
    }

    #[test]
    fn a_lone_id_only_entry_is_available_with_an_honest_note() {
        let fixture = Fixture::new(
            vec![mapping("dev-a", vec![entry("pve", "04d8", "e626", None)])],
            present(&["dev-a"]),
        );
        let derived = fixture.status("dev-a", false);
        assert_eq!(derived.status, DeviceStatus::Available);
        assert!(
            derived.notes.iter().any(|note| note.contains("id-only")),
            "{:?}",
            derived.notes
        );
    }

    #[test]
    fn token_reasons_come_from_the_effective_permissions() {
        let mut fixture = Fixture::new(
            vec![mapping(
                "dev-a",
                vec![entry("pve", "05ac", "1500", Some("1-10"))],
            )],
            present(&["dev-a"]),
        );
        // No Mapping.Use on this mapping (another mapping's grant is not it).
        fixture.permissions = Some(permissions(&[
            ("/mapping/usb/dev-z", &[("Mapping.Use", false)]),
            ("/vms/200", &[("VM.Config.HWType", false)]),
        ]));
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::Unsupported(UnsupportedReason::TokenLacksMappingUse)
        );
        // Mapping.Use but no guest hardware privilege anywhere.
        fixture.permissions = Some(permissions(&[(
            "/mapping/usb/dev-a",
            &[("Mapping.Use", false)],
        )]));
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::Unsupported(UnsupportedReason::TokenLacksGuestHwtype)
        );
        // Both, on narrow paths.
        fixture.permissions = Some(permissions(&[
            ("/mapping/usb/dev-a", &[("Mapping.Use", false)]),
            ("/vms/200", &[("VM.Config.HWType", false)]),
        ]));
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::Available
        );
        // Unknown permissions derive no token reason.
        fixture.permissions = None;
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::Available
        );
    }

    #[test]
    fn mapping_privileges_follow_propagation() {
        let held = |entries: &[(&str, &[(&str, bool)])]| {
            holds_on_mapping(&permissions(entries), "dev-a", "Mapping.Use")
        };
        assert!(held(&[("/mapping/usb/dev-a", &[("Mapping.Use", false)])]));
        assert!(held(&[("/mapping/usb", &[("Mapping.Use", true)])]));
        assert!(held(&[("/", &[("Mapping.Use", true)])]));
        assert!(!held(&[("/mapping/usb", &[("Mapping.Use", false)])]));
        assert!(!held(&[("/mapping/usb/dev-b", &[("Mapping.Use", true)])]));
        assert!(!held(&[("/mapping/pci/dev-a", &[("Mapping.Use", true)])]));
        assert!(audit_covers_every_mapping(&permissions(&[(
            "/mapping/usb",
            &[("Mapping.Audit", true)]
        )])));
        assert!(!audit_covers_every_mapping(&permissions(&[(
            "/mapping/usb/dev-a",
            &[("Mapping.Audit", false)]
        )])));
        assert!(audit_held_anywhere(&permissions(&[(
            "/mapping/usb/dev-a",
            &[("Mapping.Audit", false)]
        )])));
    }

    #[test]
    fn an_old_pve_is_unsupported_for_every_mapping() {
        let mut fixture = Fixture::new(
            vec![mapping(
                "dev-a",
                vec![entry("pve", "05ac", "1500", Some("1-10"))],
            )],
            present(&["dev-a"]),
        );
        fixture.too_old = true;
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::Unsupported(UnsupportedReason::PveTooOld)
        );
        assert_eq!(pve_major("7.4-3"), Some(7));
        assert_eq!(pve_major("9.2.2"), Some(9));
        assert_eq!(pve_major("x"), None);
    }

    #[test]
    fn an_incomplete_guest_scan_never_yields_available() {
        let mut fixture = Fixture::new(
            vec![mapping(
                "dev-a",
                vec![entry("pve", "05ac", "1500", Some("1-10"))],
            )],
            present(&["dev-a"]),
        );
        fixture.scan_complete = false;
        let derived = fixture.status("dev-a", false);
        assert_eq!(
            derived.status,
            DeviceStatus::Unsupported(UnsupportedReason::UsbInventoryUnreadable)
        );
        assert!(
            derived
                .notes
                .iter()
                .any(|note| note.contains("guest config")),
            "{:?}",
            derived.notes
        );
        // A device Fleet holds is the reservation's business, not the scan's.
        assert_eq!(
            fixture.status("dev-a", true).status,
            DeviceStatus::Available
        );
        // Positive evidence still stands: a reference found is a reference.
        fixture.references = vec![reference("dev-a", false)];
        assert_eq!(
            fixture.status("dev-a", false).status,
            DeviceStatus::ExternallyAttached
        );
    }

    #[test]
    fn entries_keep_one_per_node_and_move_last_seen_only_when_present() {
        let nodes = [
            node("pve1", &[("dev-a", RawNodeCheck::Present)]),
            node("pve2", &[("dev-a", not_there())]),
        ];
        let map: BTreeMap<&str, &RawNode> = nodes.iter().map(|n| (n.node.as_str(), n)).collect();
        let mapping = mapping(
            "dev-a",
            vec![
                entry("pve1", "05ac", "1500", Some("1-10")),
                entry("pve1", "05ac", "1500", Some("1-7")),
                entry("pve2", "05ac", "1500", None),
            ],
        );
        let previous = HardwareDevice {
            id: "d".to_owned(),
            account_id: "acc".to_owned(),
            mapping_id: "dev-a".to_owned(),
            kind: HardwareKind::Usb,
            entries: vec![DeviceNodeEntry {
                node: "pve2".to_owned(),
                vendor_id: "05ac".to_owned(),
                product_id: "1500".to_owned(),
                usbpath: None,
                manufacturer: None,
                product: None,
                last_seen_at: 5,
            }],
            status: DeviceStatus::Available,
            note: None,
            created_at: 1,
            updated_at: 1,
        };
        let entries = entries_for(&mapping, &map, Some(&previous), NOW);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].node, "pve1");
        assert_eq!(entries[0].usbpath.as_deref(), Some("1-10"));
        assert_eq!(entries[0].last_seen_at, NOW);
        assert_eq!(entries[1].node, "pve2");
        assert_eq!(entries[1].last_seen_at, 5, "absent: the old time stays");
        let entries = entries_for(&mapping, &map, None, NOW);
        assert_eq!(entries[1].last_seen_at, 0);
    }

    fn device(status: DeviceStatus, last_seen: i64) -> HardwareDevice {
        HardwareDevice {
            id: "dev".to_owned(),
            account_id: "acc".to_owned(),
            mapping_id: "dev-a".to_owned(),
            kind: HardwareKind::Usb,
            entries: vec![DeviceNodeEntry {
                node: "pve".to_owned(),
                vendor_id: "05ac".to_owned(),
                product_id: "1500".to_owned(),
                usbpath: Some("1-10".to_owned()),
                manufacturer: None,
                product: None,
                last_seen_at: last_seen,
            }],
            status,
            note: None,
            created_at: 1,
            updated_at: 2,
        }
    }

    fn reservation(state: HardwareReservationState) -> HardwareReservation {
        HardwareReservation {
            id: "res".to_owned(),
            device_id: "dev".to_owned(),
            owner_kind: ReservationOwnerKind::Lease,
            owner_id: "lease-1".to_owned(),
            state,
            guest: Some(GuestTarget {
                account_id: "acc".to_owned(),
                node: "pve".to_owned(),
                vmid: 9000,
                usb_slot: Some(0),
            }),
            created_at: 1,
            updated_at: 1,
            released_at: None,
        }
    }

    #[test]
    fn a_stale_available_device_is_missing_and_other_statuses_only_carry_the_flag() {
        let fresh = view(
            device(DeviceStatus::Available, NOW - 1_000),
            None,
            NOW,
            MAX_AGE,
        );
        assert_eq!(fresh.status, DeviceStatus::Available);
        assert!(!fresh.stale);

        let stale = view(
            device(DeviceStatus::Available, NOW - MAX_AGE - 1),
            None,
            NOW,
            MAX_AGE,
        );
        assert_eq!(stale.status, DeviceStatus::Missing);
        assert!(stale.stale);
        assert_eq!(stale.observed_at, NOW - MAX_AGE - 1);

        let external = view(
            device(DeviceStatus::ExternallyAttached, NOW - MAX_AGE - 1),
            None,
            NOW,
            MAX_AGE,
        );
        assert_eq!(external.status, DeviceStatus::ExternallyAttached);
        assert!(external.stale);

        // Exactly at the bound is still recent; a future time is not trusted.
        assert!(
            !view(
                device(DeviceStatus::Available, NOW - MAX_AGE),
                None,
                NOW,
                MAX_AGE
            )
            .stale
        );
        assert!(
            view(
                device(DeviceStatus::Available, NOW + MAX_AGE + 1),
                None,
                NOW,
                MAX_AGE
            )
            .stale
        );

        // With no entries the record's own change time is the observation.
        let mut bare = device(DeviceStatus::Unsupported(UnsupportedReason::NoNodeEntry), 0);
        bare.entries.clear();
        bare.updated_at = NOW - 5;
        let bare = view(bare, None, NOW, MAX_AGE);
        assert_eq!(bare.observed_at, NOW - 5);
        assert!(!bare.stale);
    }

    #[test]
    fn a_live_reservation_decides_reserved_or_quarantined() {
        for (state, expected) in [
            (HardwareReservationState::Held, DeviceStatus::Reserved),
            (HardwareReservationState::Attached, DeviceStatus::Reserved),
            (HardwareReservationState::Detaching, DeviceStatus::Reserved),
            (
                HardwareReservationState::AttachUnknown,
                DeviceStatus::Quarantined,
            ),
            (
                HardwareReservationState::DetachFailed,
                DeviceStatus::Quarantined,
            ),
        ] {
            let seen = view(
                device(DeviceStatus::Available, NOW),
                Some(reservation(state)),
                NOW,
                MAX_AGE,
            );
            assert_eq!(seen.status, expected, "{}", state.id());
            assert!(seen.holder.is_some());
        }
        // A stored `reserved` with no live row is a lost write.
        let lost = view(device(DeviceStatus::Reserved, NOW), None, NOW, MAX_AGE);
        assert_eq!(lost.status, DeviceStatus::Available);
    }

    #[test]
    fn every_unsupported_reason_has_text() {
        for reason in [
            UnsupportedReason::NoNodeEntry,
            UnsupportedReason::AmbiguousMapping,
            UnsupportedReason::TokenLacksMappingUse,
            UnsupportedReason::TokenLacksGuestHwtype,
            UnsupportedReason::PveTooOld,
            UnsupportedReason::UsbInventoryUnreadable,
        ] {
            assert!(!reason_text(reason).is_empty(), "{}", reason.id());
        }
    }
}
