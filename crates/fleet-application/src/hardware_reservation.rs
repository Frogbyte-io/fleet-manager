//! Hardware reservation rules and use cases (FM-1120, ADR 0019 decision 2).
//!
//! A device is reserved in the database before any Proxmox call, in one
//! transaction that checks the device and inserts the row. This module owns
//! the rules; the controller's store runs them inside that transaction.
//! Nothing here calls Proxmox.
//!
//! The owner's state is authoritative, as for Lab capacity (FM-715): a held
//! row whose lease no longer counts (released, or failed without an
//! allocated guest) is released before the next reservation looks at the
//! device, so a lost release write never strands it. That authority is
//! deliberately narrow. A row that ever started an attach or a detach
//! (`attaching`, `attached`, `detaching`, `attach_unknown`, `detach_failed`)
//! is never released on the owner's word: an unconfirmed detach is never
//! resolved by a guess (ADR 0019 decisions 3 and 9), so only the detach
//! path, the reconciler, or the elevated override can free such a row.
//!
//! Refusal and release are audited best-effort, as capacity events are: the
//! reservation row is the truth and an audit failure never undoes it.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use fleet_core::{
    DeviceStatus, HardwareReservation, HardwareReservationState, ReservationOwnerKind,
};

use crate::audit::{AuditIntent, AuditMetadata};
use crate::authz::{Decision, Permission};
use crate::hardware::HardwareStoreError;
use crate::operation::AuditPort;

/// The catalog id of the elevated override release (ADR 0019 decision 9):
/// [`Permission::HardwareOverrideRelease`], exposed by the operator route
/// (`crate::hardware_override`).
pub const OVERRIDE_RELEASE_ACTION: &str = "hardware.override-release";

/// A request to reserve one device for one owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveRequest {
    /// The Fleet id of the device.
    pub device_id: String,
    /// The owner's kind.
    pub owner_kind: ReservationOwnerKind,
    /// The owner's id (a lease or machine id).
    pub owner_id: String,
}

/// Why a reservation was refused. Each refusal has a stable reason code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReserveRefusal {
    /// The device does not exist.
    DeviceUnknown,
    /// Another owner holds the device (`hardware_busy`); queueing is a
    /// later decision, so a conflict fails fast and names the holder.
    Busy {
        /// The live reservation that holds the device.
        holder: Box<HardwareReservation>,
    },
    /// The device exists but cannot be allocated in its current status.
    NotAllocatable {
        /// The status that refused it; never `available` or `reserved`.
        status: DeviceStatus,
    },
    /// The owner no longer counts (a finished or unknown lease, or an
    /// unknown machine) and reserves nothing.
    OwnerFinished {
        /// The owner's kind.
        owner_kind: ReservationOwnerKind,
        /// The owner's id.
        owner_id: String,
    },
}

impl ReserveRefusal {
    /// The stable reason code.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::DeviceUnknown => "hardware_unknown",
            Self::Busy { .. } => "hardware_busy",
            Self::NotAllocatable { status } => match status {
                DeviceStatus::ExternallyAttached => "hardware_externally_attached",
                DeviceStatus::Missing => "hardware_missing",
                DeviceStatus::Unsupported(_) => "hardware_unsupported",
                DeviceStatus::Quarantined => "hardware_quarantined",
                DeviceStatus::Available | DeviceStatus::Reserved => "hardware_not_allocatable",
            },
            Self::OwnerFinished { .. } => "hardware_owner_finished",
        }
    }
}

impl fmt::Display for ReserveRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceUnknown => f.write_str("the hardware device does not exist"),
            Self::Busy { holder } => write!(
                f,
                "the device is reserved by {} {} (reservation {}, {})",
                holder.owner_kind.id(),
                holder.owner_id,
                holder.id,
                holder.state.id()
            ),
            Self::NotAllocatable { status } => match status.reason() {
                Some(reason) => write!(
                    f,
                    "the device is {} ({}) and cannot be reserved",
                    status.id(),
                    reason.id()
                ),
                None => write!(f, "the device is {} and cannot be reserved", status.id()),
            },
            Self::OwnerFinished {
                owner_kind,
                owner_id,
            } => write!(
                f,
                "{} {owner_id} is finished or unknown; it reserves no hardware",
                owner_kind.id()
            ),
        }
    }
}

/// Why a reservation was released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseCause {
    /// The owner's own flow released it (a confirmed detach, or a hold that
    /// never attached).
    Completed,
    /// The owner no longer counted: the lost-release-write correction.
    OwnerFinished,
    /// The elevated override release.
    Override,
}

impl ReleaseCause {
    /// The stable string recorded in the audit event.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Completed => "released",
            Self::OwnerFinished => "owner_finished",
            Self::Override => "override",
        }
    }
}

/// A reservation that was released, with the row as it was just before.
/// The previous row carries the state and `usbN` slot that an audit of an
/// override needs, because the release clears the slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasedReservation {
    /// The row before the release.
    pub previous: HardwareReservation,
    /// The row after the release.
    pub current: HardwareReservation,
    /// Why it was released.
    pub cause: ReleaseCause,
}

/// What a reservation attempt decided.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReserveDecision {
    /// The owner holds the device. `created` is false when the owner
    /// already held it and the existing row is returned unchanged.
    Reserved {
        /// The owner's live reservation.
        reservation: HardwareReservation,
        /// Whether this call inserted it.
        created: bool,
    },
    /// The request was refused.
    Refused(ReserveRefusal),
}

/// The result of one reservation transaction. Stale rows released on the
/// way are reported whatever the decision: the release committed either
/// way.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveOutcome {
    /// What was decided.
    pub decision: ReserveDecision,
    /// Reservations of finished owners released before the decision.
    pub released: Vec<ReleasedReservation>,
}

/// The result of a release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseOutcome {
    /// The reservation was released by this call.
    Released(ReleasedReservation),
    /// It was already released (a replayed step); nothing changed.
    AlreadyReleased(HardwareReservation),
}

/// Whether a device in `status` may take a new reservation. `reserved` is
/// allocatable here only because it is derived: a `reserved` device with
/// no live row is a lost write, and the live row, not the status, is what
/// excludes a second holder.
#[must_use]
pub const fn device_allocatable(status: DeviceStatus) -> bool {
    matches!(status, DeviceStatus::Available | DeviceStatus::Reserved)
}

/// Whether a row may be released on the owner's authority alone: only a
/// hold that never started an attach (`held` with no `usbN` slot). Every
/// other live state may hold a device that is attached or whose attach or
/// detach outcome is unknown.
#[must_use]
pub const fn releasable_when_owner_finished(
    state: HardwareReservationState,
    slot_recorded: bool,
) -> bool {
    matches!(state, HardwareReservationState::Held) && !slot_recorded
}

/// Whether the owner's own flow may release a row: a hold that never
/// attached, or a detach whose caller has confirmed it by read-back. A
/// failed or unknown outcome is never released.
#[must_use]
pub const fn releasable_by_flow(state: HardwareReservationState, slot_recorded: bool) -> bool {
    match state {
        HardwareReservationState::Held => !slot_recorded,
        HardwareReservationState::Detaching => true,
        HardwareReservationState::Attaching
        | HardwareReservationState::Attached
        | HardwareReservationState::Released
        | HardwareReservationState::AttachUnknown
        | HardwareReservationState::DetachFailed => false,
    }
}

/// The transactional reservation store. Every method is one write
/// transaction; none calls Proxmox.
///
/// Reservations are released only through [`Self::release`] or
/// [`Self::override_release`]: they also return the device's derived
/// `reserved` status to `available`, which a bare
/// [`crate::hardware::HardwareStore::transition_reservation`] to `released`
/// does not. A stale `reserved` status with no live row is harmless (the
/// next reserve treats it as a lost write) but is shown until a refresh.
#[async_trait]
pub trait HardwareReservationPort: fmt::Debug + Send + Sync {
    /// Reserves a device for an owner in one `BEGIN IMMEDIATE` transaction:
    /// releases a stale row of a finished owner, answers an existing row of
    /// the same owner unchanged, refuses a second owner with the holder
    /// named, checks the device's status, and inserts a `held` row.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors. A refusal is not an error.
    async fn reserve(
        &self,
        request: &ReserveRequest,
        now: i64,
    ) -> Result<ReserveOutcome, HardwareStoreError>;

    /// Releases a reservation the owner's flow has finished with: a `held`
    /// row with no recorded slot, or a `detaching` row whose detach the
    /// caller confirmed. Any other state, in particular `attach_unknown`
    /// and `detach_failed`, is refused as an illegal transition and left
    /// untouched. Releasing a released row is a no-op.
    ///
    /// There is no expected-state precondition: any `detaching` row is
    /// released, so the caller must only call this after a confirmed
    /// read-back that the device is gone from the guest.
    ///
    /// # Errors
    ///
    /// Fails when the reservation does not exist, its state refuses the
    /// release, or the backend errors.
    async fn release(&self, id: &str, now: i64) -> Result<ReleaseOutcome, HardwareStoreError>;

    /// The elevated override release (`hardware.override-release`): moves a
    /// live reservation in any state to `released` without the detach path
    /// and returns the row as it was. The caller must authorize and audit;
    /// [`HardwareReservations::override_release`] audits.
    ///
    /// # Errors
    ///
    /// Fails when the reservation does not exist, is already released, or
    /// the backend errors.
    async fn override_release(
        &self,
        id: &str,
        now: i64,
    ) -> Result<ReleasedReservation, HardwareStoreError>;
}

/// Who is acting, for the audit trail.
#[derive(Clone, Debug)]
pub struct AuditContext {
    /// The acting principal's stable id.
    pub actor: String,
    /// The durable operation the step belongs to, when one exists.
    pub operation_id: Option<String>,
}

/// The reservation use cases: the store plus best-effort audit.
#[derive(Debug)]
pub struct HardwareReservations {
    port: Arc<dyn HardwareReservationPort>,
    audit: Arc<dyn AuditPort>,
}

impl HardwareReservations {
    /// Composes the use cases over a store and an audit sink.
    #[must_use]
    pub fn new(port: Arc<dyn HardwareReservationPort>, audit: Arc<dyn AuditPort>) -> Self {
        Self { port, audit }
    }

    /// Reserves a device. The caller has authorized the request. A new
    /// reservation, a refusal and every stale release are audited; an
    /// idempotent repeat is not (nothing changed).
    ///
    /// # Errors
    ///
    /// Fails when the store fails.
    pub async fn reserve(
        &self,
        context: &AuditContext,
        request: &ReserveRequest,
        now: i64,
    ) -> Result<ReserveDecision, HardwareStoreError> {
        let outcome = self.port.reserve(request, now).await?;
        for released in &outcome.released {
            self.record(release_audit(context, released, None)).await;
        }
        match &outcome.decision {
            ReserveDecision::Reserved {
                reservation,
                created: true,
            } => {
                self.record(audit_intent(
                    context,
                    reservation.owner_kind,
                    &reservation.device_id,
                    "hardware_reserved",
                    &[
                        ("reservation_id", reservation.id.clone()),
                        ("owner_kind", reservation.owner_kind.id().to_owned()),
                        ("owner_id", reservation.owner_id.clone()),
                    ],
                ))
                .await;
            }
            ReserveDecision::Reserved { .. } => {}
            ReserveDecision::Refused(refusal) => {
                let mut facts = vec![
                    ("reason", refusal.reason().to_owned()),
                    ("owner_kind", request.owner_kind.id().to_owned()),
                    ("owner_id", request.owner_id.clone()),
                ];
                if let ReserveRefusal::Busy { holder } = refusal {
                    facts.push(("holder_kind", holder.owner_kind.id().to_owned()));
                    facts.push(("holder_id", holder.owner_id.clone()));
                    facts.push(("holder_reservation_id", holder.id.clone()));
                    facts.push(("holder_state", holder.state.id().to_owned()));
                }
                if let ReserveRefusal::NotAllocatable { status } = refusal {
                    facts.push(("device_status", status.id().to_owned()));
                    if let Some(reason) = status.reason() {
                        facts.push(("unsupported_reason", reason.id().to_owned()));
                    }
                }
                self.record(audit_intent(
                    context,
                    request.owner_kind,
                    &request.device_id,
                    "hardware_refused",
                    &facts,
                ))
                .await;
            }
        }
        Ok(outcome.decision)
    }

    /// Releases a reservation the owner's flow has finished with and audits
    /// it. See [`HardwareReservationPort::release`] for the states it
    /// accepts.
    ///
    /// # Errors
    ///
    /// Fails when the store refuses or fails.
    pub async fn release(
        &self,
        context: &AuditContext,
        id: &str,
        now: i64,
    ) -> Result<ReleaseOutcome, HardwareStoreError> {
        let outcome = self.port.release(id, now).await?;
        if let ReleaseOutcome::Released(released) = &outcome {
            self.record(release_audit(context, released, None)).await;
        }
        Ok(outcome)
    }

    /// [`Self::release`], with the `hardware_released` event filed under
    /// `action` instead of the owner's default: a release the caller asked
    /// for (a lease holder giving a device up mid-run) is audited under the
    /// action the caller was authorized for.
    ///
    /// # Errors
    ///
    /// Fails when the store refuses or fails.
    pub async fn release_under(
        &self,
        context: &AuditContext,
        action: &str,
        id: &str,
        now: i64,
    ) -> Result<ReleaseOutcome, HardwareStoreError> {
        let outcome = self.port.release(id, now).await?;
        if let ReleaseOutcome::Released(released) = &outcome {
            self.record(release_audit(context, released, Some(action)))
                .await;
        }
        Ok(outcome)
    }

    /// The elevated override release. The caller has authorized
    /// `hardware.override-release`; this audits it with the state and slot
    /// the reservation had before.
    ///
    /// # Errors
    ///
    /// Fails when the store refuses or fails.
    pub async fn override_release(
        &self,
        context: &AuditContext,
        id: &str,
        now: i64,
    ) -> Result<ReleasedReservation, HardwareStoreError> {
        let released = self.port.override_release(id, now).await?;
        self.record(release_audit(context, &released, None)).await;
        Ok(released)
    }

    /// Best effort, as for capacity events: the reservation row is the
    /// truth, so a refused audit write is dropped, not propagated.
    async fn record(&self, intent: AuditIntent) {
        let _ = self.audit.record_intent(&intent).await;
    }
}

/// The permission an owner's hardware events are filed under until the
/// hardware catalog entries exist: the capacity events use the Lab
/// provisioning permission, so a lease's hardware does too.
fn owner_action(owner_kind: ReservationOwnerKind) -> &'static str {
    match owner_kind {
        ReservationOwnerKind::Lease => Permission::LabProvision.id(),
        ReservationOwnerKind::Machine => Permission::MachineUpdate.id(),
    }
}

/// An audit intent for a hardware event. Facts are ids, states and slots
/// only; never provider output.
fn audit_intent(
    context: &AuditContext,
    owner_kind: ReservationOwnerKind,
    device_id: &str,
    event: &str,
    facts: &[(&str, String)],
) -> AuditIntent {
    intent_with_action(context, owner_action(owner_kind), device_id, event, facts)
}

fn intent_with_action(
    context: &AuditContext,
    action: &str,
    device_id: &str,
    event: &str,
    facts: &[(&str, String)],
) -> AuditIntent {
    let mut metadata = AuditMetadata::default();
    let _ = metadata.insert("event", event);
    for (key, value) in facts {
        let _ = metadata.insert(key, value);
    }
    AuditIntent {
        actor: context.actor.clone(),
        action: action.to_owned(),
        resource: Some(device_id.to_owned()),
        decision: Decision::allow(),
        correlation_id: None,
        operation_id: context.operation_id.clone(),
        metadata,
    }
}

/// The `hardware_released` event, carrying the prior state and slot.
fn release_audit(
    context: &AuditContext,
    released: &ReleasedReservation,
    action_override: Option<&str>,
) -> AuditIntent {
    let previous = &released.previous;
    let mut facts = vec![
        ("reservation_id", previous.id.clone()),
        ("owner_kind", previous.owner_kind.id().to_owned()),
        ("owner_id", previous.owner_id.clone()),
        ("outcome", released.cause.id().to_owned()),
        ("previous_state", previous.state.id().to_owned()),
    ];
    if let Some(guest) = &previous.guest {
        facts.push(("guest_vmid", guest.vmid.to_string()));
        if let Some(slot) = guest.usb_slot {
            facts.push(("usb_slot", slot.to_string()));
        }
    }
    let action = if released.cause == ReleaseCause::Override {
        OVERRIDE_RELEASE_ACTION
    } else {
        action_override.unwrap_or_else(|| owner_action(previous.owner_kind))
    };
    intent_with_action(
        context,
        action,
        &previous.device_id,
        "hardware_released",
        &facts,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use fleet_core::{GuestTarget, UnsupportedReason};

    use super::HardwareReservationState::{
        AttachUnknown, Attached, Attaching, DetachFailed, Detaching, Held, Released,
    };
    use super::*;

    fn reservation(state: HardwareReservationState, slot: Option<u8>) -> HardwareReservation {
        HardwareReservation {
            id: "res-1".to_owned(),
            device_id: "dev-1".to_owned(),
            owner_kind: ReservationOwnerKind::Lease,
            owner_id: "lease-1".to_owned(),
            state,
            guest: Some(GuestTarget {
                account_id: "acct".to_owned(),
                node: "node-a".to_owned(),
                vmid: 9001,
                usb_slot: slot,
            }),
            created_at: 1,
            updated_at: 2,
            released_at: None,
        }
    }

    #[test]
    fn only_an_unattached_hold_is_released_on_the_owners_word() {
        for state in HardwareReservationState::ALL {
            for slot in [false, true] {
                assert_eq!(
                    releasable_when_owner_finished(state, slot),
                    state == Held && !slot,
                    "{} slot={slot}",
                    state.id()
                );
            }
        }
    }

    #[test]
    fn a_failed_or_unknown_outcome_is_never_releasable() {
        for slot in [false, true] {
            for state in [AttachUnknown, DetachFailed, Attaching, Attached, Released] {
                assert!(!releasable_by_flow(state, slot), "{}", state.id());
                assert!(!releasable_when_owner_finished(state, slot));
            }
        }
        assert!(releasable_by_flow(Detaching, true));
        assert!(releasable_by_flow(Held, false));
        assert!(!releasable_by_flow(Held, true));
    }

    #[test]
    fn the_release_rules_only_use_edges_of_the_state_machine() {
        for state in HardwareReservationState::ALL {
            for slot in [false, true] {
                if releasable_by_flow(state, slot) {
                    assert!(state.can_transition_to(Released), "{}", state.id());
                }
            }
        }
    }

    #[test]
    fn only_available_and_derived_reserved_devices_are_allocatable() {
        assert!(device_allocatable(DeviceStatus::Available));
        assert!(device_allocatable(DeviceStatus::Reserved));
        for status in [
            DeviceStatus::ExternallyAttached,
            DeviceStatus::Missing,
            DeviceStatus::Quarantined,
            DeviceStatus::Unsupported(UnsupportedReason::NoNodeEntry),
        ] {
            assert!(!device_allocatable(status), "{}", status.id());
        }
    }

    #[test]
    fn a_busy_refusal_names_the_holder_and_has_a_stable_code() {
        let refusal = ReserveRefusal::Busy {
            holder: Box::new(reservation(Attached, Some(0))),
        };
        assert_eq!(refusal.reason(), "hardware_busy");
        let message = refusal.to_string();
        assert!(message.contains("lease lease-1"), "{message}");
        assert!(message.contains("res-1"), "{message}");
        assert!(message.contains("attached"), "{message}");
    }

    #[test]
    fn refusal_codes_are_stable_per_status() {
        let code = |status| ReserveRefusal::NotAllocatable { status }.reason();
        assert_eq!(
            code(DeviceStatus::ExternallyAttached),
            "hardware_externally_attached"
        );
        assert_eq!(code(DeviceStatus::Missing), "hardware_missing");
        assert_eq!(code(DeviceStatus::Quarantined), "hardware_quarantined");
        assert_eq!(
            code(DeviceStatus::Unsupported(UnsupportedReason::PveTooOld)),
            "hardware_unsupported"
        );
        let message = ReserveRefusal::NotAllocatable {
            status: DeviceStatus::Unsupported(UnsupportedReason::PveTooOld),
        }
        .to_string();
        assert!(message.contains("pve_too_old"), "{message}");
    }

    #[test]
    fn the_release_audit_carries_the_previous_state_and_slot() {
        let context = AuditContext {
            actor: "operator".to_owned(),
            operation_id: Some("op-1".to_owned()),
        };
        let mut current = reservation(Released, None);
        current.released_at = Some(3);
        let intent = release_audit(
            &context,
            &ReleasedReservation {
                previous: reservation(DetachFailed, Some(2)),
                current,
                cause: ReleaseCause::Override,
            },
            None,
        );
        assert_eq!(intent.action, OVERRIDE_RELEASE_ACTION);
        assert_eq!(intent.resource.as_deref(), Some("dev-1"));
        let facts: std::collections::BTreeMap<_, _> = intent.metadata.entries().collect();
        assert_eq!(facts["event"], "hardware_released");
        assert_eq!(facts["previous_state"], "detach_failed");
        assert_eq!(facts["usb_slot"], "2");
        assert_eq!(facts["outcome"], "override");
        assert_eq!(facts["guest_vmid"], "9001");
    }

    #[test]
    fn a_requested_release_is_filed_under_the_action_given_and_an_override_never_is() {
        let context = AuditContext {
            actor: "holder".to_owned(),
            operation_id: None,
        };
        let released = |cause| ReleasedReservation {
            previous: reservation(Detaching, Some(0)),
            current: reservation(Released, None),
            cause,
        };
        let completed = release_audit(
            &context,
            &released(ReleaseCause::Completed),
            Some("lab.hardware.detach"),
        );
        assert_eq!(completed.action, "lab.hardware.detach");
        let default = release_audit(&context, &released(ReleaseCause::Completed), None);
        assert_eq!(default.action, "lab.provision");
        let forced = release_audit(
            &context,
            &released(ReleaseCause::Override),
            Some("lab.hardware.detach"),
        );
        assert_eq!(forced.action, OVERRIDE_RELEASE_ACTION);
    }

    #[derive(Debug, Default)]
    struct Recorder {
        events: Mutex<Vec<AuditIntent>>,
        fail: bool,
    }

    #[async_trait]
    impl AuditPort for Recorder {
        async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
            if self.fail {
                return Err("sink down".to_owned());
            }
            self.events.lock().unwrap().push(intent.clone());
            Ok(())
        }

        async fn record_outcome(
            &self,
            _: &str,
            _: crate::audit::AuditOutcome,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct Scripted(ReserveOutcome);

    #[async_trait]
    impl HardwareReservationPort for Scripted {
        async fn reserve(
            &self,
            _: &ReserveRequest,
            _: i64,
        ) -> Result<ReserveOutcome, HardwareStoreError> {
            Ok(self.0.clone())
        }

        async fn release(&self, _: &str, _: i64) -> Result<ReleaseOutcome, HardwareStoreError> {
            Err(HardwareStoreError::NotFound)
        }

        async fn override_release(
            &self,
            _: &str,
            _: i64,
        ) -> Result<ReleasedReservation, HardwareStoreError> {
            Err(HardwareStoreError::NotFound)
        }
    }

    fn context() -> AuditContext {
        AuditContext {
            actor: "controller".to_owned(),
            operation_id: None,
        }
    }

    fn request() -> ReserveRequest {
        ReserveRequest {
            device_id: "dev-1".to_owned(),
            owner_kind: ReservationOwnerKind::Lease,
            owner_id: "lease-2".to_owned(),
        }
    }

    fn events(recorder: &Recorder) -> Vec<String> {
        recorder
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|intent| {
                intent
                    .metadata
                    .entries()
                    .find(|(key, _)| *key == "event")
                    .map(|(_, value)| value.to_owned())
                    .unwrap()
            })
            .collect()
    }

    #[tokio::test]
    async fn a_refusal_is_audited_with_the_holder() {
        let recorder = Arc::new(Recorder::default());
        let service = HardwareReservations::new(
            Arc::new(Scripted(ReserveOutcome {
                decision: ReserveDecision::Refused(ReserveRefusal::Busy {
                    holder: Box::new(reservation(Held, None)),
                }),
                released: Vec::new(),
            })),
            recorder.clone(),
        );
        let decision = service.reserve(&context(), &request(), 10).await.unwrap();
        assert!(matches!(
            decision,
            ReserveDecision::Refused(ReserveRefusal::Busy { .. })
        ));
        assert_eq!(events(&recorder), ["hardware_refused"]);
        let logged = recorder.events.lock().unwrap();
        let facts: std::collections::BTreeMap<_, _> = logged[0].metadata.entries().collect();
        assert_eq!(facts["reason"], "hardware_busy");
        assert_eq!(facts["holder_id"], "lease-1");
    }

    #[tokio::test]
    async fn an_idempotent_repeat_is_not_audited_but_a_stale_release_is() {
        let recorder = Arc::new(Recorder::default());
        let stale = ReleasedReservation {
            previous: reservation(Held, None),
            current: reservation(Released, None),
            cause: ReleaseCause::OwnerFinished,
        };
        let service = HardwareReservations::new(
            Arc::new(Scripted(ReserveOutcome {
                decision: ReserveDecision::Reserved {
                    reservation: reservation(Held, None),
                    created: false,
                },
                released: vec![stale],
            })),
            recorder.clone(),
        );
        service.reserve(&context(), &request(), 10).await.unwrap();
        assert_eq!(events(&recorder), ["hardware_released"]);
    }

    #[tokio::test]
    async fn a_failing_audit_sink_never_fails_the_reservation() {
        let service = HardwareReservations::new(
            Arc::new(Scripted(ReserveOutcome {
                decision: ReserveDecision::Reserved {
                    reservation: reservation(Held, None),
                    created: true,
                },
                released: Vec::new(),
            })),
            Arc::new(Recorder {
                fail: true,
                ..Recorder::default()
            }),
        );
        let decision = service.reserve(&context(), &request(), 10).await.unwrap();
        assert!(matches!(
            decision,
            ReserveDecision::Reserved { created: true, .. }
        ));
    }

    #[test]
    fn every_refusal_reason_is_its_own_code() {
        // A status that is allocatable has no refusal of its own; if one is
        // ever reported it must not read as another refusal's code.
        let codes: Vec<&str> = [
            ReserveRefusal::DeviceUnknown,
            ReserveRefusal::OwnerFinished {
                owner_kind: ReservationOwnerKind::Lease,
                owner_id: "lease-1".to_owned(),
            },
            ReserveRefusal::NotAllocatable {
                status: DeviceStatus::Available,
            },
            ReserveRefusal::NotAllocatable {
                status: DeviceStatus::Reserved,
            },
            ReserveRefusal::NotAllocatable {
                status: DeviceStatus::Missing,
            },
            ReserveRefusal::NotAllocatable {
                status: DeviceStatus::ExternallyAttached,
            },
            ReserveRefusal::NotAllocatable {
                status: DeviceStatus::Quarantined,
            },
            ReserveRefusal::NotAllocatable {
                status: DeviceStatus::Unsupported(UnsupportedReason::PveTooOld),
            },
        ]
        .iter()
        .map(ReserveRefusal::reason)
        .collect();
        let mut distinct = codes.clone();
        distinct.sort_unstable();
        // Available and Reserved share the one "not allocatable" code.
        distinct.dedup();
        assert_eq!(distinct.len(), codes.len() - 1, "{codes:?}");
        assert!(!codes.contains(&"hardware_unavailable"), "{codes:?}");
    }
}
