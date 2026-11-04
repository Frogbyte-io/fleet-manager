//! Mid-run hotplug of a Lab lease's USB device (FM-1126, ADR 0019).
//!
//! A lease declares its devices up front and placement reserves them
//! (FM-1121); the saga attaches them to the clone before it starts and
//! detaches them in cleanup (FM-1123). This module is the caller-facing use
//! case for what happens in between: the lease holder detaches a device it
//! reserved from the running guest, attaches it again, or gives it up.
//!
//! The use case owns the rules that are not about Proxmox:
//!
//! - **Authorization.** `lab.hardware.attach` and `lab.hardware.detach`,
//!   resource = the lease id, through the central [`authorize`] funnel. A
//!   delegated credential has a row for both (ADR 0011) and the owner scope
//!   below limits it to its own leases; an administrator may act on any
//!   lease. A lease the caller may not see is not found, never "forbidden".
//! - **Only a lease that can run a test.** The lease must be `ready` and
//!   unexpired, and its provision record must name the guest (account, node,
//!   VMID) the lease holds.
//! - **Only a device the lease reserved.** The [`HotplugPort`] answers that
//!   with the reservation store; a device another lease holds, nobody holds
//!   or Fleet does not know all read the same, so a caller cannot probe other
//!   leases' devices.
//!
//! What the port does (the verify, the digest-conditional write, the
//! read-back, `pending`, the audit intent before the write) is the Lab
//! hardware saga's, in `fleet-controller`.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use fleet_core::{HardwareReservationState, LeaseState};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::lab::{LeasePort, ProvisionPort};

/// The longest mapping id accepted, as the provider writes it.
pub const MAX_MAPPING_ID_CHARS: usize = 64;

/// What the lease holder asks for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HotplugAction {
    /// Attach the held device to the guest.
    Attach,
    /// Detach the device from the guest. With `release` the lease also gives
    /// the device up once the read-back confirms it is gone; otherwise it
    /// stays reserved by the lease until the lease is released.
    Detach {
        /// Whether the reservation is released after a confirmed detach.
        release: bool,
    },
}

impl HotplugAction {
    /// The catalog action this request needs.
    #[must_use]
    pub const fn permission(self) -> Permission {
        match self {
            Self::Attach => Permission::LabHardwareAttach,
            Self::Detach { .. } => Permission::LabHardwareDetach,
        }
    }
}

/// The guest a lease holds, from its provision record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseGuestRef {
    /// The Proxmox account the guest was cloned through.
    pub account_id: String,
    /// The node the clone runs on.
    pub node: String,
    /// The clone's VMID.
    pub vmid: u32,
}

/// One validated hotplug request, as the port receives it.
#[derive(Clone, Debug)]
pub struct HotplugRequest {
    /// The authorized caller, recorded on the audit intent.
    pub principal_id: String,
    /// The lease.
    pub lease_id: String,
    /// The PVE resource mapping id of the device.
    pub mapping_id: String,
    /// The guest the lease holds.
    pub guest: LeaseGuestRef,
    /// What to do.
    pub action: HotplugAction,
}

/// What a hotplug request came to. A refusal is [`HotplugError::Refused`],
/// never an outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HotplugResult {
    /// The write landed, was read back and PVE applied it: the guest has the
    /// device.
    Attached,
    /// The reservation was already attached; nothing was written.
    AlreadyAttached,
    /// The detach landed, was read back and PVE applied it: the guest no
    /// longer has the device.
    Detached,
    /// The device was already off the guest; nothing was written.
    AlreadyDetached,
    /// PVE stored the removal but the guest keeps the device until it
    /// restarts (its `hotplug` option lacks `usb`). The device is **still
    /// attached**; the reservation stays `detaching`.
    DetachPending,
}

impl HotplugResult {
    /// The stable string reported to callers.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::AlreadyAttached => "already_attached",
            Self::Detached => "detached",
            Self::AlreadyDetached => "already_detached",
            Self::DetachPending => "detach_pending",
        }
    }

    /// Whether the guest has the device once the request is answered.
    #[must_use]
    pub const fn on_guest(self) -> bool {
        matches!(
            self,
            Self::Attached | Self::AlreadyAttached | Self::DetachPending
        )
    }
}

/// The answer to a hotplug request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HotplugOutcome {
    /// The lease.
    pub lease_id: String,
    /// The mapping id.
    pub mapping_id: String,
    /// What the request did.
    pub result: HotplugResult,
    /// The reservation after the request.
    pub reservation_id: String,
    /// The reservation's state after the request.
    pub reservation_state: HardwareReservationState,
    /// The `usbN` slot the reservation records, while it is attached or being
    /// detached.
    pub usb_slot: Option<u8>,
    /// Whether the reservation was released by this request.
    pub released: bool,
}

/// Why a hotplug request was not carried out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HotplugError {
    /// The caller may not perform the action.
    Denied(Decision),
    /// The lease does not exist, or belongs to another owner.
    NotFound {
        /// What was not found.
        what: String,
    },
    /// The request is malformed.
    Invalid {
        /// What is wrong.
        detail: String,
    },
    /// The request is refused for a stable reason (the lease is not ready,
    /// the device is not the lease's, the verify failed, the attach is
    /// pending, a detach could not be confirmed, ...). Whatever was written
    /// has been compensated or is named in the detail.
    Refused {
        /// The stable reason code.
        reason: String,
        /// The scrubbed, bounded detail.
        detail: String,
    },
    /// Hotplug is not wired in this controller.
    Unavailable {
        /// Why.
        detail: String,
    },
    /// A port failed.
    Backend {
        /// The failure, not shown to the caller.
        detail: String,
    },
}

impl HotplugError {
    /// A refusal with a stable reason.
    #[must_use]
    pub fn refused(reason: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::Refused {
            reason: reason.into(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for HotplugError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Invalid { detail } => write!(f, "invalid request: {detail}"),
            Self::Refused { reason, detail } => write!(f, "{reason}: {detail}"),
            Self::Unavailable { detail } => write!(f, "unavailable: {detail}"),
            Self::Backend { detail } => write!(f, "lab hardware hotplug failed: {detail}"),
        }
    }
}

impl std::error::Error for HotplugError {}

/// What carries a request out: the Lab hardware saga over the reservation
/// store and Proxmox. Authorization and the lease checks are already done.
#[async_trait]
pub trait HotplugPort: fmt::Debug + Send + Sync {
    /// Carries one request out.
    ///
    /// # Errors
    ///
    /// A [`HotplugError::Refused`] with the stable reason, or a backend
    /// failure.
    async fn carry_out(&self, request: &HotplugRequest) -> Result<HotplugOutcome, HotplugError>;
}

/// The Lab hotplug use cases.
#[derive(Debug)]
pub struct LabHardwareHotplug {
    leases: Arc<dyn LeasePort>,
    provisions: Arc<dyn ProvisionPort>,
    port: Arc<dyn HotplugPort>,
}

impl LabHardwareHotplug {
    /// Composes the use cases.
    #[must_use]
    pub fn new(
        leases: Arc<dyn LeasePort>,
        provisions: Arc<dyn ProvisionPort>,
        port: Arc<dyn HotplugPort>,
    ) -> Self {
        Self {
            leases,
            provisions,
            port,
        }
    }

    /// Attaches a device the lease reserved to the lease's running guest.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown or another owner's lease, a lease that is
    /// not ready, a device the lease did not reserve, a failed verify or
    /// write, or a pending attach (never reported as attached).
    pub async fn attach(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        lease_id: &str,
        mapping_id: &str,
        now: i64,
    ) -> Result<HotplugOutcome, HotplugError> {
        self.run(
            authorizer,
            principal,
            lease_id,
            mapping_id,
            HotplugAction::Attach,
            now,
        )
        .await
    }

    /// Detaches a device the lease reserved from the lease's running guest;
    /// with `release` it also gives the device up after the read-back
    /// confirms it is gone.
    ///
    /// # Errors
    ///
    /// As [`Self::attach`], and a detach PVE refused or could not confirm
    /// (the reservation then stays held by the lease in cleanup's hands).
    pub async fn detach(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        lease_id: &str,
        mapping_id: &str,
        release: bool,
        now: i64,
    ) -> Result<HotplugOutcome, HotplugError> {
        self.run(
            authorizer,
            principal,
            lease_id,
            mapping_id,
            HotplugAction::Detach { release },
            now,
        )
        .await
    }

    async fn run(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        lease_id: &str,
        mapping_id: &str,
        action: HotplugAction,
        now: i64,
    ) -> Result<HotplugOutcome, HotplugError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: action.permission(),
                resource: Some(lease_id),
            },
        )
        .map_err(HotplugError::Denied)?;
        validate_mapping_id(mapping_id)?;
        let lease = self.leases.get(lease_id).await.map_err(|detail| {
            if detail.contains("not found") {
                HotplugError::NotFound {
                    what: format!("lease {lease_id}"),
                }
            } else {
                HotplugError::Backend { detail }
            }
        })?;
        // A lease the principal may not see is reported as not found, so a
        // delegated credential cannot probe another owner's lease ids.
        if !crate::authz::owner_scope_permits(&principal.id, &lease.owner) {
            return Err(HotplugError::NotFound {
                what: format!("lease {lease_id}"),
            });
        }
        if lease.state != LeaseState::Ready {
            return Err(HotplugError::refused(
                "lease_not_ready",
                format!(
                    "the lease is {}; a device is hotplugged only on a ready lease",
                    lease.state.id()
                ),
            ));
        }
        if lease.expires_at.is_none_or(|expires| expires <= now) {
            return Err(HotplugError::refused(
                "lease_not_ready",
                "the lease has expired; its devices are detached by its cleanup",
            ));
        }
        let record = match &lease.provision_id {
            Some(id) => Some(
                self.provisions
                    .get(id)
                    .await
                    .map_err(|detail| HotplugError::Backend { detail })?,
            ),
            None => None,
        };
        let guest = record
            .filter(|record| record.lease_id.as_deref() == Some(lease.id.as_str()))
            .and_then(|record| {
                Some(LeaseGuestRef {
                    account_id: record.account_id?,
                    node: record.node?,
                    vmid: record.vmid?,
                })
            })
            .ok_or_else(|| {
                HotplugError::refused(
                    "lease_has_no_guest",
                    "the lease's guest is not recorded (account, node and VMID), so there is nothing to hotplug into",
                )
            })?;
        self.port
            .carry_out(&HotplugRequest {
                principal_id: principal.id.clone(),
                lease_id: lease.id,
                mapping_id: mapping_id.to_owned(),
                guest,
                action,
            })
            .await
    }
}

/// The mapping id is written into a property string, so it is checked here
/// as strictly as the provider does: letters, digits, `-`, `_` and `.`,
/// starting with a letter.
fn validate_mapping_id(id: &str) -> Result<(), HotplugError> {
    let valid = id.len() <= MAX_MAPPING_ID_CHARS
        && id.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if valid {
        Ok(())
    } else {
        Err(HotplugError::Invalid {
            detail: format!(
                "the mapping id must start with a letter and use only letters, digits, '-', '_' and '.' (at most {MAX_MAPPING_ID_CHARS} characters)"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_ids_that_could_add_a_property_are_refused() {
        for bad in ["", "1abc", "a,host=1-7", "a b", "a=b", "é", &"a".repeat(65)] {
            assert!(validate_mapping_id(bad).is_err(), "{bad:?}");
        }
        for good in ["fm-test-reader-a", "A_b.c-1", &"a".repeat(64)] {
            assert!(validate_mapping_id(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn each_action_needs_its_own_catalog_entry() {
        assert_eq!(
            HotplugAction::Attach.permission(),
            Permission::LabHardwareAttach
        );
        assert_eq!(
            HotplugAction::Detach { release: true }.permission(),
            Permission::LabHardwareDetach
        );
    }

    #[test]
    fn a_pending_detach_is_still_on_the_guest() {
        assert!(HotplugResult::DetachPending.on_guest());
        assert!(!HotplugResult::Detached.on_guest());
        assert!(!HotplugResult::AlreadyDetached.on_guest());
        assert!(HotplugResult::Attached.on_guest());
    }
}
