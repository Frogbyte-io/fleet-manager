//! The operator's override release of a hardware reservation (FM-1124,
//! ADR 0019 decision 9, `hardware.override-release`).
//!
//! A reservation that stays `attach_unknown`, `detach_failed` or `detaching`
//! blocks its device, and (for a lease) the lease's cleanup, until the guest
//! shows the device is gone. Nothing in Fleet resolves it on a guess, and the
//! reconciler repairs only what it can prove Fleet attached, so an operator
//! who has looked at the guest needs a way to free it that does not mean
//! editing the database. This is that way, and nothing else:
//!
//! - **Authorized centrally** as `hardware.override-release` on the
//!   reservation, which no delegated Lab credential holds.
//! - **Explicitly confirmed.** The caller must say Fleet did not verify the
//!   guest (`confirm_unverified`); without it nothing is read or changed.
//! - **Audited before it is done.** The `hardware_override_release_requested`
//!   intent is required: a refused audit sink means no release. It carries the
//!   row's state and `usbN` slot as they were (the release clears the slot),
//!   the guest, and `guest_verified=false`, so the trail says Fleet did not
//!   look. The store's `hardware_released` event (cause `override`) and a
//!   `hardware_override_released` event with the state and slot the row
//!   actually had follow, best effort.
//! - **Idempotent.** A reservation that is already released answers
//!   [`OverrideOutcome::AlreadyReleased`] and changes nothing.
//! - **Not a guest operation.** It frees the reservation in Fleet's records.
//!   It never calls Proxmox, so it removes nothing from the guest: a device
//!   still attached shows up as `externally_attached` at the next refresh.
//!
//! It refuses nothing a human administrator deliberately forces once
//! confirmed: any live state, with or without a slot, with or without a guest
//! that can be read.
#![warn(missing_docs)]

use std::sync::Arc;

use fleet_core::{HardwareReservation, HardwareReservationState};

use crate::audit::{AuditIntent, AuditMetadata};
use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::hardware::{HardwareStore, HardwareStoreError};
use crate::hardware_reservation::{AuditContext, HardwareReservations};
use crate::operation::AuditPort;
use crate::proxmox::ProxmoxUseCaseError;

/// What an override release came to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OverrideOutcome {
    /// This call released the reservation. `previous` is the row as it was
    /// just before (its state and slot are what the audit recorded).
    Released {
        /// The row before the release.
        previous: Box<HardwareReservation>,
        /// The row after it.
        current: Box<HardwareReservation>,
    },
    /// The reservation was already released; nothing changed.
    AlreadyReleased(Box<HardwareReservation>),
}

/// Who is overriding, for every event of one call.
struct Who<'a> {
    principal: &'a ActingPrincipal,
    decision: Decision,
    correlation_id: Option<&'a str>,
}

/// The override release use case.
#[derive(Debug)]
pub struct HardwareOverride {
    store: Arc<dyn HardwareStore>,
    reservations: Arc<HardwareReservations>,
    audit: Arc<dyn AuditPort>,
}

fn backend(context: &'static str, error: &HardwareStoreError) -> ProxmoxUseCaseError {
    ProxmoxUseCaseError::Backend {
        context,
        detail: error.to_string(),
    }
}

/// The slot as an operator reads it (`usb2`), or `none`.
fn slot_text(reservation: &HardwareReservation) -> String {
    reservation
        .guest
        .as_ref()
        .and_then(|guest| guest.usb_slot)
        .map_or_else(|| "none".to_owned(), |slot| format!("usb{slot}"))
}

impl HardwareOverride {
    /// Composes the use case over the hardware store, the reservation use
    /// cases (which run the store's override and audit its release) and the
    /// audit sink the required intent goes to.
    #[must_use]
    pub fn new(
        store: Arc<dyn HardwareStore>,
        reservations: Arc<HardwareReservations>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            store,
            reservations,
            audit,
        }
    }

    /// The facts every event of one override carries: ids, states, slots and
    /// the node and VMID; never provider output.
    fn metadata(
        event: &str,
        reservation: &HardwareReservation,
        mapping: Option<&str>,
    ) -> AuditMetadata {
        let mut metadata = AuditMetadata::default();
        let _ = metadata.insert("event", event);
        let _ = metadata.insert("reservation_id", &reservation.id);
        let _ = metadata.insert("device_id", &reservation.device_id);
        if let Some(mapping) = mapping {
            let _ = metadata.insert("mapping", mapping);
        }
        let _ = metadata.insert("owner_kind", reservation.owner_kind.id());
        let _ = metadata.insert("owner_id", &reservation.owner_id);
        let _ = metadata.insert("previous_state", reservation.state.id());
        let _ = metadata.insert("previous_slot", &slot_text(reservation));
        if let Some(guest) = &reservation.guest {
            let _ = metadata.insert("node", &guest.node);
            let _ = metadata.insert("guest_vmid", &guest.vmid.to_string());
        }
        // The point of the record: the operator forced this, and Fleet did
        // not look at the guest.
        let _ = metadata.insert("guest_verified", "false");
        let _ = metadata.insert("confirmed", "true");
        metadata
    }

    /// Records one event of an override about `reservation`.
    async fn record(
        &self,
        who: &Who<'_>,
        event: &str,
        reservation: &HardwareReservation,
        mapping: Option<&str>,
    ) -> Result<(), String> {
        self.audit
            .record_intent(&AuditIntent {
                actor: who.principal.id.clone(),
                action: Permission::HardwareOverrideRelease.id().to_owned(),
                resource: Some(reservation.id.clone()),
                decision: who.decision,
                correlation_id: who.correlation_id.map(str::to_owned),
                operation_id: None,
                metadata: Self::metadata(event, reservation, mapping),
            })
            .await
    }

    async fn row(&self, id: &str) -> Result<HardwareReservation, ProxmoxUseCaseError> {
        self.store
            .reservation(id)
            .await
            .map_err(|error| backend("hardware", &error))?
            .ok_or_else(|| ProxmoxUseCaseError::NotFound {
                what: format!("hardware reservation {id}"),
            })
    }

    /// Releases a reservation without verifying the guest.
    ///
    /// # Errors
    ///
    /// Fails with [`ProxmoxUseCaseError::Denied`] when the principal may not
    /// override (nothing is read or audited), `Invalid` when the caller did
    /// not confirm that Fleet did not verify the guest, `NotFound` for an
    /// unknown reservation, and `Backend` when the store or the required
    /// audit intent fails (nothing was released).
    pub async fn release(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        correlation_id: Option<&str>,
        reservation_id: &str,
        confirm_unverified: bool,
        now: i64,
    ) -> Result<OverrideOutcome, ProxmoxUseCaseError> {
        let decision = authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::HardwareOverrideRelease,
                resource: Some(reservation_id),
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)?;
        if !confirm_unverified {
            return Err(ProxmoxUseCaseError::Invalid {
                detail: "an override release needs confirmUnverified=true: it frees the reservation without Fleet verifying the guest, so the device may still be attached".to_owned(),
            });
        }
        let who = Who {
            principal,
            decision,
            correlation_id,
        };
        let reservation = self.row(reservation_id).await?;
        let mapping = self
            .store
            .device(&reservation.device_id)
            .await
            .map_err(|error| backend("hardware", &error))?
            .map(|device| device.mapping_id);
        let mapping = mapping.as_deref();
        if reservation.state == HardwareReservationState::Released {
            // A repeat: nothing changes, and the repeat is on the record.
            let _ = self
                .record(
                    &who,
                    "hardware_override_release_noop",
                    &reservation,
                    mapping,
                )
                .await;
            return Ok(OverrideOutcome::AlreadyReleased(Box::new(reservation)));
        }
        // The intent is required: a release the audit sink refused is not
        // made.
        self.record(
            &who,
            "hardware_override_release_requested",
            &reservation,
            mapping,
        )
        .await
        .map_err(|detail| ProxmoxUseCaseError::Backend {
            context: "audit",
            detail,
        })?;
        let context = AuditContext {
            actor: principal.id.clone(),
            operation_id: None,
        };
        match self
            .reservations
            .override_release(&context, reservation_id, now)
            .await
        {
            Ok(released) => {
                // The state and slot the row actually had (another writer may
                // have moved it since it was read), best effort.
                let _ = self
                    .record(
                        &who,
                        "hardware_override_released",
                        &released.previous,
                        mapping,
                    )
                    .await;
                Ok(OverrideOutcome::Released {
                    previous: Box::new(released.previous),
                    current: Box::new(released.current),
                })
            }
            // Released by another writer between the read and the release:
            // the same answer as a repeat.
            Err(HardwareStoreError::IllegalTransition {
                actual: HardwareReservationState::Released,
                ..
            }) => Ok(OverrideOutcome::AlreadyReleased(Box::new(
                self.row(reservation_id).await?,
            ))),
            Err(HardwareStoreError::NotFound) => Err(ProxmoxUseCaseError::NotFound {
                what: format!("hardware reservation {reservation_id}"),
            }),
            Err(error) => Err(backend("hardware", &error)),
        }
    }
}
