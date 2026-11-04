//! USB devices on persistent machines (FM-1125, ADR 0018 and ADR 0019): the
//! reviewed attach and detach use cases, and the gate that keeps a machine's
//! lifecycle from losing a device silently.
//!
//! A persistent machine reserves a device for as long as the device is on its
//! guest, until an explicit, reviewed detach releases it. The device is
//! reserved by the **machine**, never by a Lab lease, so the Lab's cleanup and
//! sweeps do not touch it and nothing releases it on a guess.
//!
//! The use case owns the rules that are not about Proxmox:
//!
//! - **Authorization.** `machines.usb.attach` and `machines.usb.detach`,
//!   resource = the machine id, through the central [`authorize`] funnel.
//!   Neither is delegated to Lab credentials: ADR 0018 does not say a
//!   restricted credential may change a persistent machine's hardware, and a
//!   device on a machine is a privileged, long-lived change.
//! - **Reviewed and payload-bound.** A review checks everything and answers
//!   a token over the exact request (the action, the machine, the mapping and,
//!   for an attach, the guest it resolves to). The execute call recomputes the
//!   payload from the machine's current guest link and refuses a token that no
//!   longer matches, so a relink between the two cannot move the device to
//!   another guest.
//! - **Only a persistent machine's guest.** An attach needs the machine to be
//!   linked to a QEMU guest that carries a `ready` persistent marker which
//!   still guards it (not a Lab clone, not a template, not a promoted image
//!   artifact, not a Lab pool member, no reserved fixture tag: the live checks
//!   of a registration, [`RegisterGuard`]). A machine linked to a guest that
//!   was never made persistent is refused: the marker is what keeps Lab
//!   away from the guest (ADR 0018 decision 1).
//! - **A detach does not re-check the guest.** It acts on the reservation:
//!   the guest and slot the reservation recorded, exactly what Fleet wrote.
//!   It stays possible when the machine was relinked or its guest stopped
//!   being eligible, because it is the way a device is given back.
//! - **Lifecycle holds.** [`MachineHardwareGate`] answers what a machine or a
//!   guest holds, so deleting a machine, unregistering its marker and
//!   destroying, reverting or templating its guest are refused with the
//!   instruction to detach first.
//!
//! What the port does (reserve, verify, the digest-conditional write, the
//! read-back, `pending`, the audit intent before every write) is the hardware
//! saga's, in `fleet-controller`.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use fleet_core::{
    GuestTarget, HardwareDevice, HardwareReservation, HardwareReservationState,
    ReservationOwnerKind,
};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Permission, authorize};
use crate::hardware::HardwareStore;
use crate::lab_hardware_hotplug::{HotplugError, HotplugResult, validate_mapping_id};
use crate::machine::{GuestLinkPort, MachinePort};
use crate::operation::{PortFailure, review_token_for};
use crate::persistent::{
    GuestCheck, LAB_NAME_PREFIX, PersistentGuest, PersistentGuestPort, PersistentState,
    RegisterGuard,
};

/// The review-token kind of an attach.
pub const ATTACH_KIND: &str = "machine.usb.attach";
/// The review-token kind of a detach.
pub const DETACH_KIND: &str = "machine.usb.detach";

/// What the caller asks for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineUsbAction {
    /// Reserve the device for the machine and attach it to the machine's
    /// guest.
    Attach,
    /// Detach the device from the machine's guest and release the machine's
    /// reservation once the read-back confirms it is gone.
    Detach,
}

impl MachineUsbAction {
    /// The catalog action the request needs.
    #[must_use]
    pub const fn permission(self) -> Permission {
        match self {
            Self::Attach => Permission::MachineUsbAttach,
            Self::Detach => Permission::MachineUsbDetach,
        }
    }

    /// The review-token kind.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Attach => ATTACH_KIND,
            Self::Detach => DETACH_KIND,
        }
    }

    /// The stable string.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Attach => "attach",
            Self::Detach => "detach",
        }
    }
}

/// The guest an attach goes to: the machine's guest link, checked live.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineGuestRef {
    /// The Proxmox account that contains the guest.
    pub account_id: String,
    /// The node the guest is on now.
    pub node: String,
    /// The guest's VMID.
    pub vmid: u32,
    /// The guest's live name.
    pub name: String,
}

/// One validated request, as the port receives it.
#[derive(Clone, Debug)]
pub struct MachineUsbRequest {
    /// The authorized caller, recorded on the audit intents.
    pub principal_id: String,
    /// The machine.
    pub machine_id: String,
    /// The PVE resource mapping id of the device.
    pub mapping_id: String,
    /// What to do.
    pub action: MachineUsbAction,
    /// The guest of an attach. A detach acts on the guest the reservation
    /// recorded and carries none.
    pub guest: Option<MachineGuestRef>,
}

/// What a request came to. A refusal is [`HotplugError::Refused`], never an
/// outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineUsbOutcome {
    /// The machine.
    pub machine_id: String,
    /// The mapping id.
    pub mapping_id: String,
    /// What the request did: `attached`, `already_attached`, `detached`,
    /// `already_detached` or `detach_pending` (the device is still on the
    /// guest). An attach PVE would leave pending is refused instead.
    pub result: HotplugResult,
    /// The machine's reservation of the device.
    pub reservation_id: String,
    /// The reservation's state after the request.
    pub reservation_state: HardwareReservationState,
    /// The `usbN` slot the guest holds the device in, while it does.
    pub usb_slot: Option<u8>,
    /// Whether the request released the reservation.
    pub released: bool,
}

/// What carries a request out: the hardware saga over the reservation store
/// and Proxmox. Authorization and the machine checks are already done.
#[async_trait]
pub trait MachineUsbPort: fmt::Debug + Send + Sync {
    /// Carries one request out.
    ///
    /// # Errors
    ///
    /// A [`HotplugError::Refused`] with the stable reason, or a backend
    /// failure.
    async fn carry_out(
        &self,
        request: &MachineUsbRequest,
    ) -> Result<MachineUsbOutcome, HotplugError>;
}

/// What a review found, and the token that binds the execute call to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineUsbReview {
    /// The token the execute call must present.
    pub review_token: String,
    /// What will be done.
    pub action: MachineUsbAction,
    /// The machine.
    pub machine_id: String,
    /// The mapping id.
    pub mapping_id: String,
    /// The guest an attach will write to (live name and node).
    pub guest: Option<MachineGuestRef>,
    /// The machine's reservation of the device, when it has one: a detach
    /// acts on it, an attach resumes it.
    pub reservation: Option<ReviewedReservation>,
}

/// The reservation a review found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedReservation {
    /// The reservation.
    pub id: String,
    /// Its state.
    pub state: HardwareReservationState,
    /// The guest it records, when it does.
    pub guest: Option<GuestTarget>,
}

/// One live reservation a machine's lifecycle must respect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineHold {
    /// The machine that holds the device.
    pub machine_id: String,
    /// The reservation.
    pub reservation_id: String,
    /// The reservation's state.
    pub state: HardwareReservationState,
    /// The PVE mapping id of the device, when it could be read.
    pub mapping_id: Option<String>,
    /// The guest the reservation records.
    pub guest: Option<GuestTarget>,
}

impl MachineHold {
    /// The sentence that tells a caller what to do, for an operation that
    /// would lose the device (`what`: "delete the machine", "destroy the
    /// guest", ...).
    #[must_use]
    pub fn refusal(&self, what: &str) -> String {
        format!(
            "cannot {what}: machine {} holds USB device {} (reservation {} is {}); detach it first with `fleetctl machines usb detach {} --mapping {}`",
            self.machine_id,
            self.mapping_id.as_deref().unwrap_or("(unknown mapping)"),
            self.reservation_id,
            self.state.id(),
            self.machine_id,
            self.mapping_id.as_deref().unwrap_or("<mapping>"),
        )
    }
}

/// What the lifecycle guards ask: does a persistent machine hold a device.
#[async_trait]
pub trait MachineHardwareGate: fmt::Debug + Send + Sync {
    /// The live reservations a machine owns, in any state.
    ///
    /// # Errors
    ///
    /// Fails when the hardware records cannot be read; the caller refuses
    /// then (a guard that cannot look fails closed).
    async fn holds_of_machine(&self, machine_id: &str) -> Result<Vec<MachineHold>, String>;

    /// The live reservations a persistent machine owns that record this
    /// guest, in any state.
    ///
    /// # Errors
    ///
    /// As [`Self::holds_of_machine`].
    async fn holds_on_guest(&self, account_id: &str, vmid: u32)
    -> Result<Vec<MachineHold>, String>;
}

/// [`MachineHardwareGate`] over the hardware store.
#[derive(Debug)]
pub struct StoreMachineHardwareGate {
    store: Arc<dyn HardwareStore>,
}

impl StoreMachineHardwareGate {
    /// Over the hardware store.
    #[must_use]
    pub fn new(store: Arc<dyn HardwareStore>) -> Self {
        Self { store }
    }

    async fn hold_of(&self, row: HardwareReservation) -> MachineHold {
        let mapping_id = self
            .store
            .device(&row.device_id)
            .await
            .ok()
            .flatten()
            .map(|device| device.mapping_id);
        MachineHold {
            machine_id: row.owner_id,
            reservation_id: row.id,
            state: row.state,
            mapping_id,
            guest: row.guest,
        }
    }
}

#[async_trait]
impl MachineHardwareGate for StoreMachineHardwareGate {
    async fn holds_of_machine(&self, machine_id: &str) -> Result<Vec<MachineHold>, String> {
        let rows = self
            .store
            .live_reservations_for_owner(ReservationOwnerKind::Machine, machine_id)
            .await
            .map_err(|error| error.to_string())?;
        let mut holds = Vec::with_capacity(rows.len());
        for row in rows {
            holds.push(self.hold_of(row).await);
        }
        Ok(holds)
    }

    async fn holds_on_guest(
        &self,
        account_id: &str,
        vmid: u32,
    ) -> Result<Vec<MachineHold>, String> {
        let rows = self
            .store
            .list_live_reservations()
            .await
            .map_err(|error| error.to_string())?;
        let mut holds = Vec::new();
        for row in rows {
            if row.owner_kind == ReservationOwnerKind::Machine
                && row
                    .guest
                    .as_ref()
                    .is_some_and(|guest| guest.account_id == account_id && guest.vmid == vmid)
            {
                holds.push(self.hold_of(row).await);
            }
        }
        Ok(holds)
    }
}

/// The attach and detach use cases of a persistent machine's USB devices.
#[derive(Debug)]
pub struct MachineUsb {
    machines: Arc<dyn MachinePort>,
    links: Arc<dyn GuestLinkPort>,
    markers: Arc<dyn PersistentGuestPort>,
    guard: Arc<dyn RegisterGuard>,
    hardware: Arc<dyn HardwareStore>,
    port: Arc<dyn MachineUsbPort>,
}

fn backend(detail: impl Into<String>) -> HotplugError {
    HotplugError::Backend {
        detail: detail.into(),
    }
}

fn not_found(machine_id: &str) -> HotplugError {
    HotplugError::NotFound {
        what: format!("machine {machine_id}"),
    }
}

/// The payload an attach's token binds: the machine, the mapping and the
/// guest the machine's link resolves to.
#[must_use]
pub fn attach_payload(
    machine_id: &str,
    mapping_id: &str,
    account_id: &str,
    vmid: u32,
) -> (String, String) {
    let payload = serde_json::json!({
        "action": "attach",
        "machineId": machine_id,
        "mapping": mapping_id,
        "accountId": account_id,
        "vmid": vmid,
    })
    .to_string();
    let token = review_token_for(ATTACH_KIND, &payload);
    (payload, token)
}

/// The payload a detach's token binds: the machine and the mapping. The
/// guest is the reservation's, not the link's.
#[must_use]
pub fn detach_payload(machine_id: &str, mapping_id: &str) -> (String, String) {
    let payload = serde_json::json!({
        "action": "detach",
        "machineId": machine_id,
        "mapping": mapping_id,
    })
    .to_string();
    let token = review_token_for(DETACH_KIND, &payload);
    (payload, token)
}

impl MachineUsb {
    /// Composes the use cases.
    #[must_use]
    pub fn new(
        machines: Arc<dyn MachinePort>,
        links: Arc<dyn GuestLinkPort>,
        markers: Arc<dyn PersistentGuestPort>,
        guard: Arc<dyn RegisterGuard>,
        hardware: Arc<dyn HardwareStore>,
        port: Arc<dyn MachineUsbPort>,
    ) -> Self {
        Self {
            machines,
            links,
            markers,
            guard,
            hardware,
            port,
        }
    }

    fn authorize(
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        action: MachineUsbAction,
        machine_id: &str,
    ) -> Result<(), HotplugError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: action.permission(),
                resource: Some(machine_id),
            },
        )
        .map(|_| ())
        .map_err(HotplugError::Denied)
    }

    async fn require_machine(&self, machine_id: &str) -> Result<(), HotplugError> {
        match self.machines.get(machine_id).await {
            Ok(_) => Ok(()),
            Err(PortFailure::NotFound { .. }) => Err(not_found(machine_id)),
            Err(failure) => Err(backend(failure.to_string())),
        }
    }

    /// The machine's guest link, which an attach needs and must be a QEMU
    /// guest.
    async fn linked_guest(&self, machine_id: &str) -> Result<(String, u32), HotplugError> {
        let link = self
            .links
            .get(machine_id)
            .await
            .map_err(|failure| backend(failure.to_string()))?
            .ok_or_else(|| {
                HotplugError::refused(
                    "machine_has_no_guest",
                    format!(
                        "machine {machine_id} is not linked to a guest; link it first (`fleetctl machines link-guest`)"
                    ),
                )
            })?;
        if link.guest_kind != "qemu" {
            return Err(HotplugError::refused(
                "machine_guest_not_qemu",
                format!(
                    "machine {machine_id} is linked to a {} guest; only a QEMU VM takes a USB device",
                    link.guest_kind
                ),
            ));
        }
        Ok((link.account_id, link.vmid))
    }

    /// The live checks of the guest an attach goes to: a ready persistent
    /// marker that still guards it, and the registration's eligibility
    /// (QEMU, not a template, image artifact, Lab clone or pool member, no
    /// reserved tag).
    async fn check_guest(
        &self,
        machine_id: &str,
        account_id: &str,
        vmid: u32,
    ) -> Result<MachineGuestRef, HotplugError> {
        let marker = self
            .markers
            .get(account_id, vmid)
            .await
            .map_err(backend)?
            .ok_or_else(|| {
                HotplugError::refused(
                    "machine_not_persistent",
                    format!(
                        "the guest of machine {machine_id} (VMID {vmid}) is not a persistent machine; create or register it as one first (`fleetctl machines persistent register`)"
                    ),
                )
            })?;
        Self::check_marker(&marker, machine_id)?;
        let live = match self
            .guard
            .inspect(account_id, vmid)
            .await
            .map_err(backend)?
        {
            GuestCheck::Eligible(live) => live,
            GuestCheck::Refused(reason) => {
                return Err(HotplugError::refused("guest_not_eligible", reason));
            }
        };
        if live.name.to_ascii_lowercase().starts_with(LAB_NAME_PREFIX) {
            return Err(HotplugError::refused(
                "guest_not_eligible",
                format!(
                    "a guest named {} is a Lab clone, not a persistent machine",
                    live.name
                ),
            ));
        }
        if !marker.guards(Some(&live.name)) {
            return Err(HotplugError::refused(
                "machine_not_persistent",
                format!(
                    "the persistent marker at VMID {vmid} no longer guards the guest there (it is named {}, the marker records {})",
                    live.name, marker.name
                ),
            ));
        }
        Ok(MachineGuestRef {
            account_id: account_id.to_owned(),
            node: live.node,
            vmid,
            name: live.name,
        })
    }

    fn check_marker(marker: &PersistentGuest, machine_id: &str) -> Result<(), HotplugError> {
        if marker.state != PersistentState::Ready {
            return Err(HotplugError::refused(
                "machine_not_ready",
                format!(
                    "the persistent machine {} is still being created (step {}); attach a device once it is ready",
                    marker.name,
                    marker.step.as_deref().unwrap_or("unknown")
                ),
            ));
        }
        match marker.machine_id.as_deref() {
            Some(owner) if owner != machine_id => Err(HotplugError::refused(
                "machine_guest_mismatch",
                format!(
                    "the persistent guest {} belongs to machine {owner}, not to machine {machine_id}",
                    marker.name
                ),
            )),
            _ => Ok(()),
        }
    }

    /// The machine's live reservation of the mapping, when it has one.
    async fn reservation_of(
        &self,
        machine_id: &str,
        mapping_id: &str,
    ) -> Result<Option<ReviewedReservation>, HotplugError> {
        let rows = self
            .hardware
            .live_reservations_for_owner(ReservationOwnerKind::Machine, machine_id)
            .await
            .map_err(|error| backend(error.to_string()))?;
        for row in rows {
            let device = self
                .hardware
                .device(&row.device_id)
                .await
                .map_err(|error| backend(error.to_string()))?;
            if device.is_some_and(|device| device.mapping_id == mapping_id) {
                return Ok(Some(ReviewedReservation {
                    id: row.id,
                    state: row.state,
                    guest: row.guest,
                }));
            }
        }
        Ok(None)
    }

    /// The device of an attach, and a fail-fast look at who holds it. The
    /// authoritative decision is the reservation transaction at execution.
    async fn preview_device(
        &self,
        machine_id: &str,
        account_id: &str,
        mapping_id: &str,
    ) -> Result<HardwareDevice, HotplugError> {
        let device = self
            .hardware
            .device_by_mapping(account_id, mapping_id)
            .await
            .map_err(|error| backend(error.to_string()))?
            .ok_or_else(|| {
                HotplugError::refused(
                    "hardware_unknown",
                    format!(
                        "no device with mapping {mapping_id} is inventoried for this account; the operator creates the PVE mapping and `fleetctl hardware refresh` records it"
                    ),
                )
            })?;
        if let Some(holder) = self
            .hardware
            .live_reservation_for_device(&device.id)
            .await
            .map_err(|error| backend(error.to_string()))?
            && !(holder.owner_kind == ReservationOwnerKind::Machine
                && holder.owner_id == machine_id)
        {
            return Err(HotplugError::refused(
                "hardware_busy",
                format!(
                    "{mapping_id} is reserved by {} {} (reservation {}, {}); a device is held by one owner at a time and requests are not queued",
                    holder.owner_kind.id(),
                    holder.owner_id,
                    holder.id,
                    holder.state.id()
                ),
            ));
        }
        Ok(device)
    }

    /// Reviews an attach: checks the machine, its guest and the device and
    /// answers what will happen with the token that binds the execute call
    /// to it. Nothing is written.
    ///
    /// # Errors
    ///
    /// Fails on denial, a malformed mapping id, an unknown machine, a
    /// machine without a persistent QEMU guest, an ineligible guest, an
    /// unknown device or a device another owner holds.
    pub async fn review_attach(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
        mapping_id: &str,
    ) -> Result<MachineUsbReview, HotplugError> {
        let (guest, _) = self
            .check_attach(authorizer, principal, machine_id, mapping_id)
            .await?;
        let reservation = self.reservation_of(machine_id, mapping_id).await?;
        let (_, review_token) =
            attach_payload(machine_id, mapping_id, &guest.account_id, guest.vmid);
        Ok(MachineUsbReview {
            review_token,
            action: MachineUsbAction::Attach,
            machine_id: machine_id.to_owned(),
            mapping_id: mapping_id.to_owned(),
            guest: Some(guest),
            reservation,
        })
    }

    async fn check_attach(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
        mapping_id: &str,
    ) -> Result<(MachineGuestRef, HardwareDevice), HotplugError> {
        Self::authorize(authorizer, principal, MachineUsbAction::Attach, machine_id)?;
        validate_mapping_id(mapping_id)?;
        self.require_machine(machine_id).await?;
        let (account_id, vmid) = self.linked_guest(machine_id).await?;
        let guest = self.check_guest(machine_id, &account_id, vmid).await?;
        let device = self
            .preview_device(machine_id, &account_id, mapping_id)
            .await?;
        Ok((guest, device))
    }

    /// Attaches a device to the machine's guest and reserves it for the
    /// machine, after the same checks as the review and a token that matches
    /// them. An attach PVE would leave pending (the running guest's `hotplug`
    /// option lacks `usb`) is removed again and refused, never reported as
    /// attached.
    ///
    /// # Errors
    ///
    /// As [`Self::review_attach`], a review token that does not match the
    /// machine, mapping and guest, and what the port refuses (a device that
    /// is busy, missing, changed or externally attached, a failed write).
    pub async fn attach(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
        mapping_id: &str,
        review_token: &str,
    ) -> Result<MachineUsbOutcome, HotplugError> {
        // The token is checked against the link before the live checks, so a
        // stale review is refused without a Proxmox read.
        Self::authorize(authorizer, principal, MachineUsbAction::Attach, machine_id)?;
        validate_mapping_id(mapping_id)?;
        self.require_machine(machine_id).await?;
        let (account_id, vmid) = self.linked_guest(machine_id).await?;
        let (_, expected) = attach_payload(machine_id, mapping_id, &account_id, vmid);
        if expected != review_token {
            return Err(HotplugError::Invalid {
                detail: "the review token does not match this machine, device and guest; review the attach first".to_owned(),
            });
        }
        let (guest, _) = self
            .check_attach(authorizer, principal, machine_id, mapping_id)
            .await?;
        self.port
            .carry_out(&MachineUsbRequest {
                principal_id: principal.id.clone(),
                machine_id: machine_id.to_owned(),
                mapping_id: mapping_id.to_owned(),
                action: MachineUsbAction::Attach,
                guest: Some(guest),
            })
            .await
    }

    async fn check_detach(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
        mapping_id: &str,
    ) -> Result<ReviewedReservation, HotplugError> {
        Self::authorize(authorizer, principal, MachineUsbAction::Detach, machine_id)?;
        validate_mapping_id(mapping_id)?;
        self.require_machine(machine_id).await?;
        self.reservation_of(machine_id, mapping_id)
            .await?
            .ok_or_else(|| {
                HotplugError::refused(
                    "hardware_not_reserved",
                    format!("{mapping_id} is not reserved by machine {machine_id}; there is nothing to detach"),
                )
            })
    }

    /// Reviews a detach: the machine must hold the device. The answer names
    /// the reservation and the guest it records; nothing is written.
    ///
    /// # Errors
    ///
    /// Fails on denial, a malformed mapping id, an unknown machine, or a
    /// device the machine does not hold.
    pub async fn review_detach(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
        mapping_id: &str,
    ) -> Result<MachineUsbReview, HotplugError> {
        let reservation = self
            .check_detach(authorizer, principal, machine_id, mapping_id)
            .await?;
        let (_, review_token) = detach_payload(machine_id, mapping_id);
        Ok(MachineUsbReview {
            review_token,
            action: MachineUsbAction::Detach,
            machine_id: machine_id.to_owned(),
            mapping_id: mapping_id.to_owned(),
            guest: None,
            reservation: Some(reservation),
        })
    }

    /// Detaches a device from the guest the machine's reservation recorded
    /// and releases the reservation after the read-back confirmed the device
    /// is gone. A removal PVE leaves pending is `detach_pending`: the device
    /// is still attached and the reservation stays `detaching`.
    ///
    /// # Errors
    ///
    /// As [`Self::review_detach`], a review token that does not match, and a
    /// detach PVE refused or that could not be confirmed (the reservation
    /// stays with the machine).
    pub async fn detach(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
        mapping_id: &str,
        review_token: &str,
    ) -> Result<MachineUsbOutcome, HotplugError> {
        Self::authorize(authorizer, principal, MachineUsbAction::Detach, machine_id)?;
        let (_, expected) = detach_payload(machine_id, mapping_id);
        if expected != review_token {
            return Err(HotplugError::Invalid {
                detail: "the review token does not match this machine and device; review the detach first".to_owned(),
            });
        }
        self.check_detach(authorizer, principal, machine_id, mapping_id)
            .await?;
        self.port
            .carry_out(&MachineUsbRequest {
                principal_id: principal.id.clone(),
                machine_id: machine_id.to_owned(),
                mapping_id: mapping_id.to_owned(),
                action: MachineUsbAction::Detach,
                guest: None,
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_action_needs_its_own_catalog_entry() {
        assert_eq!(
            MachineUsbAction::Attach.permission(),
            Permission::MachineUsbAttach
        );
        assert_eq!(
            MachineUsbAction::Detach.permission(),
            Permission::MachineUsbDetach
        );
        assert_eq!(Permission::MachineUsbAttach.id(), "machines.usb.attach");
        assert_eq!(Permission::MachineUsbDetach.id(), "machines.usb.detach");
    }

    #[test]
    fn a_token_binds_the_action_the_machine_the_mapping_and_the_guest() {
        let (_, base) = attach_payload("m-1", "reader-a", "acct", 100);
        for other in [
            attach_payload("m-2", "reader-a", "acct", 100).1,
            attach_payload("m-1", "reader-b", "acct", 100).1,
            attach_payload("m-1", "reader-a", "acct-2", 100).1,
            attach_payload("m-1", "reader-a", "acct", 101).1,
            detach_payload("m-1", "reader-a").1,
        ] {
            assert_ne!(base, other);
        }
        assert_eq!(base, attach_payload("m-1", "reader-a", "acct", 100).1);
        assert_ne!(
            detach_payload("m-1", "reader-a").1,
            detach_payload("m-1", "reader-b").1
        );
    }

    #[test]
    fn a_hold_refusal_names_the_machine_the_device_and_the_command() {
        let hold = MachineHold {
            machine_id: "m-1".to_owned(),
            reservation_id: "r-1".to_owned(),
            state: HardwareReservationState::Attached,
            mapping_id: Some("reader-a".to_owned()),
            guest: None,
        };
        let text = hold.refusal("destroy the guest");
        for needle in ["m-1", "reader-a", "r-1", "attached", "machines usb detach"] {
            assert!(text.contains(needle), "{text}");
        }
    }
}
