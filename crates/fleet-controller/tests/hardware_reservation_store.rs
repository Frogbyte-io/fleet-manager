//! FM-1120: the transactional hardware reservation store. Real SQLite
//! (a database file, the real migrations); nothing is mocked and no
//! Proxmox call exists. Fixtures use invented ids only.

use std::collections::BTreeMap;
use std::sync::Arc;

use fleet_application::hardware::{DeviceObservation, HardwareStore as _, HardwareStoreError};
use fleet_application::hardware_reservation::{
    AuditContext, HardwareReservationPort as _, HardwareReservations, ReleaseCause, ReleaseOutcome,
    ReserveDecision, ReserveOutcome, ReserveRefusal, ReserveRequest,
};
use fleet_controller::hardware_reservation_store::SqliteHardwareReservations;
use fleet_core::{
    DeviceNodeEntry, DeviceStatus, GuestTarget, HardwareKind, HardwareReservation,
    HardwareReservationState as State, ReservationOwnerKind, UnsupportedReason,
};
use fleet_storage_sqlite::{AuditSink, HardwareRepository, Store};
use sqlx::SqlitePool;

const NOW: i64 = 1_800_000_000_000;

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    pool: SqlitePool,
    reservations: Arc<SqliteHardwareReservations>,
    hardware: HardwareRepository,
}

impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("a temp directory");
        let store = Store::open(&dir.path().join("fleet.db"))
            .await
            .expect("the store must open");
        let pool = store.pool().clone();
        Self {
            reservations: Arc::new(SqliteHardwareReservations::new(pool.clone())),
            hardware: HardwareRepository::new(pool.clone()),
            pool,
            store,
            _dir: dir,
        }
    }

    async fn device(&self, id: &str, status: DeviceStatus) {
        self.hardware
            .upsert_device(
                &DeviceObservation {
                    id: id.to_owned(),
                    account_id: "account-1".to_owned(),
                    mapping_id: format!("mapping-{id}"),
                    kind: HardwareKind::Usb,
                    entries: vec![DeviceNodeEntry {
                        node: "node-a".to_owned(),
                        vendor_id: "1234".to_owned(),
                        product_id: "abcd".to_owned(),
                        usbpath: Some("1-4".to_owned()),
                        manufacturer: None,
                        product: None,
                        last_seen_at: NOW,
                    }],
                    status,
                    status_detail: None,
                },
                NOW,
            )
            .await
            .expect("the device records");
    }

    /// A lease in `state`; `vmid` gives its provision record a guest.
    async fn lease(&self, id: &str, state: &str, vmid: Option<i64>) {
        let provision = vmid.map(|_| format!("provision-{id}"));
        if let (Some(provision), Some(vmid)) = (&provision, vmid) {
            sqlx::query(
                "INSERT INTO lab_provisions (id, template_version_id, state, vmid, created_at, \
                 updated_at) VALUES (?1, 'template-version-1', 'provisioned', ?2, ?3, ?3)",
            )
            .bind(provision)
            .bind(vmid)
            .bind(NOW)
            .execute(&self.pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO lab_leases (id, template_version_id, owner, purpose, state, \
             provision_id, cleanup, created_at) \
             VALUES (?1, 'template-version-1', 'tester', 'test', ?2, ?3, 'destroy', ?4)",
        )
        .bind(id)
        .bind(state)
        .bind(provision)
        .bind(NOW)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    /// A lease whose provision record exists but never allocated a guest
    /// (`vmid` is NULL), as a provision that failed before the clone.
    async fn lease_with_empty_provision(&self, id: &str, state: &str) {
        sqlx::query(
            "INSERT INTO lab_provisions (id, template_version_id, state, created_at, updated_at) \
             VALUES (?1, 'template-version-1', 'provisioning', ?2, ?2)",
        )
        .bind(format!("provision-{id}"))
        .bind(NOW)
        .execute(&self.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO lab_leases (id, template_version_id, owner, purpose, state, \
             provision_id, cleanup, created_at) \
             VALUES (?1, 'template-version-1', 'tester', 'test', ?2, ?3, 'destroy', ?4)",
        )
        .bind(id)
        .bind(state)
        .bind(format!("provision-{id}"))
        .bind(NOW)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn set_lease_state(&self, id: &str, state: &str) {
        sqlx::query("UPDATE lab_leases SET state = ?2 WHERE id = ?1")
            .bind(id)
            .bind(state)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    async fn machine(&self, id: &str) {
        sqlx::query(
            "INSERT INTO machines (id, name, created_at, updated_at) VALUES (?1, ?1, ?2, ?2)",
        )
        .bind(id)
        .bind(NOW)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn reserve(&self, device: &str, owner: &str) -> ReserveOutcome {
        self.reserve_for(device, ReservationOwnerKind::Lease, owner)
            .await
    }

    async fn reserve_for(
        &self,
        device: &str,
        kind: ReservationOwnerKind,
        owner: &str,
    ) -> ReserveOutcome {
        self.reservations
            .reserve(&request(device, kind, owner), NOW + 1)
            .await
            .expect("the store must not fail")
    }

    async fn live(&self, device: &str) -> Vec<HardwareReservation> {
        self.hardware
            .list_live_reservations()
            .await
            .unwrap()
            .into_iter()
            .filter(|reservation| reservation.device_id == device)
            .collect()
    }

    async fn status(&self, device: &str) -> DeviceStatus {
        self.hardware.device(device).await.unwrap().unwrap().status
    }

    /// Takes a reservation to `to` the way the saga would, for setup.
    async fn move_to(&self, id: &str, path: &[State]) {
        let mut from = self.hardware.reservation(id).await.unwrap().unwrap().state;
        for &to in path {
            let guest = (from == State::Held && to == State::Attaching).then(|| GuestTarget {
                account_id: "account-1".to_owned(),
                node: "node-a".to_owned(),
                vmid: 9001,
                usb_slot: Some(0),
            });
            self.hardware
                .transition_reservation(id, from, to, guest.as_ref(), NOW + 2)
                .await
                .unwrap_or_else(|error| panic!("{from:?} -> {to:?}: {error}"));
            from = to;
        }
    }
}

fn request(device: &str, kind: ReservationOwnerKind, owner: &str) -> ReserveRequest {
    ReserveRequest {
        device_id: device.to_owned(),
        owner_kind: kind,
        owner_id: owner.to_owned(),
    }
}

fn reserved(outcome: &ReserveOutcome) -> (&HardwareReservation, bool) {
    match &outcome.decision {
        ReserveDecision::Reserved {
            reservation,
            created,
        } => (reservation, *created),
        ReserveDecision::Refused(refusal) => panic!("expected a reservation, got: {refusal}"),
    }
}

fn refusal(outcome: &ReserveOutcome) -> &ReserveRefusal {
    match &outcome.decision {
        ReserveDecision::Refused(refusal) => refusal,
        ReserveDecision::Reserved { .. } => panic!("expected a refusal"),
    }
}

#[tokio::test]
async fn a_reservation_is_a_held_row_and_marks_the_device_reserved() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("lease-1", "reserving", None).await;

    let outcome = fixture.reserve("dev-1", "lease-1").await;
    let (reservation, created) = reserved(&outcome);
    assert!(created);
    assert_eq!(reservation.state, State::Held);
    assert_eq!(reservation.owner_kind, ReservationOwnerKind::Lease);
    assert_eq!(reservation.owner_id, "lease-1");
    assert!(reservation.guest.is_none());
    assert!(outcome.released.is_empty());
    assert_eq!(fixture.status("dev-1").await, DeviceStatus::Reserved);
}

#[tokio::test]
async fn a_repeat_for_the_same_owner_returns_the_existing_row_unchanged() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("lease-1", "reserving", None).await;

    let first = fixture.reserve("dev-1", "lease-1").await;
    let (first, _) = reserved(&first);
    let again = fixture.reserve("dev-1", "lease-1").await;
    let (again, created) = reserved(&again);
    assert!(!created);
    assert_eq!(again, first);

    // Whatever state the saga took it to, a replayed step sees that row.
    fixture
        .move_to(&first.id, &[State::Attaching, State::Attached])
        .await;
    let later = fixture.reserve("dev-1", "lease-1").await;
    let (later, created) = reserved(&later);
    assert!(!created);
    assert_eq!(later.id, first.id);
    assert_eq!(later.state, State::Attached);
    assert_eq!(fixture.live("dev-1").await.len(), 1);
}

#[tokio::test]
async fn a_second_owner_gets_hardware_busy_naming_the_holder() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("lease-1", "reserving", None).await;
    fixture.lease("lease-2", "reserving", None).await;
    let held = fixture.reserve("dev-1", "lease-1").await;
    let (held, _) = reserved(&held);

    let refused = fixture.reserve("dev-1", "lease-2").await;
    let refusal = refusal(&refused);
    assert_eq!(refusal.reason(), "hardware_busy");
    let ReserveRefusal::Busy { holder } = refusal else {
        panic!("expected busy");
    };
    assert_eq!(holder.as_ref(), held);
    assert!(refusal.to_string().contains("lease lease-1"));
    // Nothing was written for the loser.
    assert_eq!(fixture.live("dev-1").await.len(), 1);
}

#[tokio::test]
async fn a_machine_and_a_lease_exclude_each_other() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("lease-1", "reserving", None).await;
    fixture.machine("machine-1").await;
    reserved(
        &fixture
            .reserve_for("dev-1", ReservationOwnerKind::Machine, "machine-1")
            .await,
    );
    let refused = fixture.reserve("dev-1", "lease-1").await;
    assert_eq!(refusal(&refused).reason(), "hardware_busy");
}

#[tokio::test]
async fn devices_that_cannot_be_allocated_are_refused_with_their_status() {
    let fixture = Fixture::new().await;
    fixture.lease("lease-1", "reserving", None).await;
    let cases = [
        (
            DeviceStatus::ExternallyAttached,
            "hardware_externally_attached",
        ),
        (DeviceStatus::Missing, "hardware_missing"),
        (DeviceStatus::Quarantined, "hardware_quarantined"),
        (
            DeviceStatus::Unsupported(UnsupportedReason::NoNodeEntry),
            "hardware_unsupported",
        ),
    ];
    for (index, (status, code)) in cases.into_iter().enumerate() {
        let id = format!("dev-{index}");
        fixture.device(&id, status).await;
        let outcome = fixture.reserve(&id, "lease-1").await;
        assert_eq!(refusal(&outcome).reason(), code);
        assert!(fixture.live(&id).await.is_empty());
        assert_eq!(fixture.status(&id).await, status, "the status is untouched");
    }
    let outcome = fixture.reserve("no-such-device", "lease-1").await;
    assert_eq!(refusal(&outcome).reason(), "hardware_unknown");
}

#[tokio::test]
async fn a_finished_or_unknown_owner_reserves_nothing() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("released", "released", None).await;
    fixture.lease("failed-early", "failed", None).await;
    for owner in ["released", "failed-early", "no-such-lease"] {
        let outcome = fixture.reserve("dev-1", owner).await;
        assert_eq!(
            refusal(&outcome).reason(),
            "hardware_owner_finished",
            "{owner}"
        );
    }
    let outcome = fixture
        .reserve_for("dev-1", ReservationOwnerKind::Machine, "no-such-machine")
        .await;
    assert_eq!(refusal(&outcome).reason(), "hardware_owner_finished");
    assert!(fixture.live("dev-1").await.is_empty());
    assert_eq!(fixture.status("dev-1").await, DeviceStatus::Available);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_reservations_have_exactly_one_winner() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    const TASKS: usize = 32;
    for index in 0..TASKS {
        fixture
            .lease(&format!("lease-{index}"), "reserving", None)
            .await;
    }
    let mut tasks = Vec::new();
    for index in 0..TASKS {
        let reservations = fixture.reservations.clone();
        tasks.push(tokio::spawn(async move {
            reservations
                .reserve(
                    &request(
                        "dev-1",
                        ReservationOwnerKind::Lease,
                        &format!("lease-{index}"),
                    ),
                    NOW + 1,
                )
                .await
                .expect("a loser is a refusal, never an error")
        }));
    }
    let mut winners = Vec::new();
    let mut busy = 0;
    for task in tasks {
        let outcome = task.await.unwrap();
        match outcome.decision {
            ReserveDecision::Reserved {
                reservation,
                created,
            } => {
                assert!(created);
                winners.push(reservation);
            }
            ReserveDecision::Refused(ReserveRefusal::Busy { .. }) => busy += 1,
            ReserveDecision::Refused(other) => panic!("unexpected refusal: {other}"),
        }
    }
    assert_eq!(winners.len(), 1, "exactly one winner");
    assert_eq!(busy, TASKS - 1);
    let live = fixture.live("dev-1").await;
    assert_eq!(live, winners, "the database agrees with the winner");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_repeats_for_one_owner_create_one_row() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("lease-1", "reserving", None).await;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let reservations = fixture.reservations.clone();
        tasks.push(tokio::spawn(async move {
            reservations
                .reserve(
                    &request("dev-1", ReservationOwnerKind::Lease, "lease-1"),
                    NOW + 1,
                )
                .await
                .unwrap()
        }));
    }
    let mut created = 0;
    let mut ids = Vec::new();
    for task in tasks {
        let outcome = task.await.unwrap();
        let (reservation, was_created) = reserved(&outcome);
        created += usize::from(was_created);
        ids.push(reservation.id.clone());
    }
    assert_eq!(created, 1);
    ids.dedup();
    assert_eq!(ids.len(), 1, "every caller sees the same row");
}

#[tokio::test]
async fn a_row_whose_lease_no_longer_counts_is_released_first() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("old", "reserving", None).await;
    fixture.lease("new", "reserving", None).await;
    let old = fixture.reserve("dev-1", "old").await;
    let (old, _) = reserved(&old);
    let old = old.clone();

    // The lease finished but its own release write was lost.
    fixture.set_lease_state("old", "released").await;

    // A finished requester is refused, but the stale row it found is
    // released and committed, and the device goes back to `available`: no
    // insert follows, so only the release itself can have reset the status.
    fixture.lease("dead", "released", None).await;
    let refused = fixture.reserve("dev-1", "dead").await;
    assert_eq!(refusal(&refused).reason(), "hardware_owner_finished");
    assert_eq!(refused.released.len(), 1);
    assert_eq!(refused.released[0].previous, old);
    assert!(fixture.live("dev-1").await.is_empty());
    assert_eq!(fixture.status("dev-1").await, DeviceStatus::Available);

    // Put the stale hold back (the release above was real, so re-create the
    // lost-write situation with a fresh lease) and let a live owner win.
    fixture.lease("old-2", "reserving", None).await;
    let stale = fixture.reserve("dev-1", "old-2").await;
    let (stale, _) = reserved(&stale);
    let old = stale.clone();
    fixture.set_lease_state("old-2", "released").await;
    let outcome = fixture.reserve("dev-1", "new").await;
    let (winner, created) = reserved(&outcome);
    assert!(created);
    assert_eq!(winner.owner_id, "new");
    let [released] = outcome.released.as_slice() else {
        panic!("one stale release expected: {:?}", outcome.released);
    };
    assert_eq!(released.cause, ReleaseCause::OwnerFinished);
    assert_eq!(released.previous, old);
    assert_eq!(released.current.state, State::Released);
    assert!(released.current.released_at.is_some());
    let stored = fixture
        .hardware
        .reservation(&old.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, State::Released);
    assert_eq!(fixture.live("dev-1").await.len(), 1);
    assert_eq!(fixture.status("dev-1").await, DeviceStatus::Reserved);
}

#[tokio::test]
async fn the_lease_state_decides_not_the_reservation() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("other", "reserving", None).await;

    // Every state in which the lease still counts keeps its hold.
    let counting: [(&str, Option<i64>); 10] = [
        ("requested", None),
        ("queued", None),
        ("reserving", None),
        ("provisioning", Some(100)),
        ("ready", Some(100)),
        ("releasing", Some(100)),
        ("cleanup_failed", Some(100)),
        // Failed with a guest: cleanup still owes it, so it counts.
        ("failed", Some(100)),
        ("booting", Some(100)),
        ("bootstrapping", Some(100)),
    ];
    for (index, (state, vmid)) in counting.into_iter().enumerate() {
        let lease = format!("counting-{index}");
        fixture.lease(&lease, state, vmid).await;
        let held = fixture.reserve("dev-1", &lease).await;
        let (held, _) = reserved(&held);
        let refused = fixture.reserve("dev-1", "other").await;
        assert_eq!(refusal(&refused).reason(), "hardware_busy", "{state}");
        assert!(refused.released.is_empty(), "{state}");
        // Free it through the owner's flow for the next case.
        fixture
            .reservations
            .release(&held.id, NOW + 3)
            .await
            .unwrap();
    }

    // A lease that failed without ever allocating a guest does not count.
    fixture.lease("never-allocated", "reserving", None).await;
    let held = fixture.reserve("dev-1", "never-allocated").await;
    reserved(&held);
    fixture.set_lease_state("never-allocated", "failed").await;
    let outcome = fixture.reserve("dev-1", "other").await;
    assert_eq!(outcome.released.len(), 1);
    assert_eq!(reserved(&outcome).0.owner_id, "other");
}

#[tokio::test]
async fn a_failed_lease_with_a_provision_but_no_vmid_does_not_count() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("other", "reserving", None).await;
    fixture
        .lease_with_empty_provision("early-failure", "reserving")
        .await;
    reserved(&fixture.reserve("dev-1", "early-failure").await);

    // Failed before any guest existed: nothing can be attached, so the hold
    // is a lost release write.
    fixture.set_lease_state("early-failure", "failed").await;
    let outcome = fixture.reserve("dev-1", "other").await;
    assert_eq!(outcome.released.len(), 1);
    assert_eq!(outcome.released[0].previous.owner_id, "early-failure");
    assert_eq!(reserved(&outcome).0.owner_id, "other");

    // And such a lease reserves nothing new (on a free device).
    let other_hold = reserved(&outcome).0.id.clone();
    fixture
        .reservations
        .release(&other_hold, NOW + 3)
        .await
        .unwrap();
    fixture
        .lease_with_empty_provision("early-failure-2", "failed")
        .await;
    let refused = fixture.reserve("dev-1", "early-failure-2").await;
    assert_eq!(refusal(&refused).reason(), "hardware_owner_finished");
}

/// An audit sink that is down.
#[derive(Debug)]
struct DownAudit;

#[async_trait::async_trait]
impl fleet_application::operation::AuditPort for DownAudit {
    async fn record_intent(&self, _: &fleet_application::audit::AuditIntent) -> Result<(), String> {
        Err("audit sink down".to_owned())
    }

    async fn record_outcome(
        &self,
        _: &str,
        _: fleet_application::audit::AuditOutcome,
    ) -> Result<(), String> {
        Err("audit sink down".to_owned())
    }
}

#[tokio::test]
async fn a_down_audit_sink_never_fails_or_undoes_a_reserve_release_or_override() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("lease-1", "reserving", None).await;
    fixture.lease("lease-2", "reserving", None).await;
    let service = HardwareReservations::new(fixture.reservations.clone(), Arc::new(DownAudit));
    let context = AuditContext {
        actor: "controller".to_owned(),
        operation_id: None,
    };
    let ask = |owner: &str| request("dev-1", ReservationOwnerKind::Lease, owner);

    let ReserveDecision::Reserved { reservation, .. } = service
        .reserve(&context, &ask("lease-1"), NOW)
        .await
        .unwrap()
    else {
        panic!("expected a reservation");
    };
    // A refusal is returned as a refusal, not as the audit error.
    assert!(matches!(
        service
            .reserve(&context, &ask("lease-2"), NOW)
            .await
            .unwrap(),
        ReserveDecision::Refused(ReserveRefusal::Busy { .. })
    ));

    // Release.
    let ReleaseOutcome::Released(released) = service
        .release(&context, &reservation.id, NOW + 1)
        .await
        .unwrap()
    else {
        panic!("expected a release");
    };
    assert_eq!(released.current.state, State::Released);
    assert!(fixture.live("dev-1").await.is_empty());

    // Override of a row the saga left failed.
    let ReserveDecision::Reserved { reservation, .. } = service
        .reserve(&context, &ask("lease-2"), NOW + 2)
        .await
        .unwrap()
    else {
        panic!("expected a reservation");
    };
    fixture
        .move_to(&reservation.id, &[State::Attaching, State::AttachUnknown])
        .await;
    let overridden = service
        .override_release(&context, &reservation.id, NOW + 3)
        .await
        .unwrap();
    assert_eq!(overridden.previous.state, State::AttachUnknown);
    let stored = fixture
        .hardware
        .reservation(&reservation.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, State::Released);
    assert_eq!(fixture.status("dev-1").await, DeviceStatus::Available);
}

#[tokio::test]
async fn a_device_refresh_over_a_live_hold_is_repaired_by_the_next_reserve() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("lease-1", "reserving", None).await;
    fixture.lease("lease-2", "reserving", None).await;
    let held = fixture.reserve("dev-1", "lease-1").await;
    let (held, _) = reserved(&held);

    // A refresh writes the observed status over the derived `reserved`.
    fixture.device("dev-1", DeviceStatus::Available).await;
    assert_eq!(fixture.status("dev-1").await, DeviceStatus::Available);
    let again = fixture.reserve("dev-1", "lease-1").await;
    assert!(!reserved(&again).1);
    assert_eq!(reserved(&again).0.id, held.id);
    assert_eq!(fixture.status("dev-1").await, DeviceStatus::Reserved);

    // The same through a refused second owner.
    fixture.device("dev-1", DeviceStatus::Available).await;
    let refused = fixture.reserve("dev-1", "lease-2").await;
    assert_eq!(refusal(&refused).reason(), "hardware_busy");
    assert_eq!(fixture.status("dev-1").await, DeviceStatus::Reserved);

    // A status the refresh observed for a real reason is not overwritten.
    fixture.device("dev-1", DeviceStatus::Missing).await;
    fixture.reserve("dev-1", "lease-1").await;
    assert_eq!(fixture.status("dev-1").await, DeviceStatus::Missing);
}

#[tokio::test]
async fn a_machine_that_no_longer_exists_is_released_like_a_finished_lease() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.machine("machine-1").await;
    fixture.lease("lease-1", "reserving", None).await;
    reserved(
        &fixture
            .reserve_for("dev-1", ReservationOwnerKind::Machine, "machine-1")
            .await,
    );
    sqlx::query("DELETE FROM machines WHERE id = 'machine-1'")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let outcome = fixture.reserve("dev-1", "lease-1").await;
    assert_eq!(outcome.released.len(), 1);
    assert_eq!(reserved(&outcome).0.owner_id, "lease-1");
}

#[tokio::test]
async fn a_finished_owner_never_frees_a_device_after_an_unconfirmed_attach_or_detach() {
    // ADR 0019: never release after a failed or uncertain detach. A finished
    // lease does not make an attached, unknown or detach-failed device free.
    let paths: [(&str, &[State]); 5] = [
        ("attaching", &[State::Attaching]),
        ("attached", &[State::Attaching, State::Attached]),
        (
            "detaching",
            &[State::Attaching, State::Attached, State::Detaching],
        ),
        ("attach_unknown", &[State::Attaching, State::AttachUnknown]),
        (
            "detach_failed",
            &[
                State::Attaching,
                State::Attached,
                State::Detaching,
                State::DetachFailed,
            ],
        ),
    ];
    for (name, path) in paths {
        let fixture = Fixture::new().await;
        fixture.device("dev-1", DeviceStatus::Available).await;
        fixture.lease("old", "reserving", None).await;
        fixture.lease("new", "reserving", None).await;
        let old = fixture.reserve("dev-1", "old").await;
        let (old, _) = reserved(&old);
        fixture.move_to(&old.id, path).await;
        fixture.set_lease_state("old", "released").await;

        let outcome = fixture.reserve("dev-1", "new").await;
        assert_eq!(refusal(&outcome).reason(), "hardware_busy", "{name}");
        assert!(outcome.released.is_empty(), "{name}");
        let after = fixture
            .hardware
            .reservation(&old.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.state, *path.last().unwrap(), "{name} is untouched");

        // The finished owner's own replay is refused, not re-granted.
        let replay = fixture.reserve("dev-1", "old").await;
        assert_eq!(
            refusal(&replay).reason(),
            "hardware_owner_finished",
            "{name}"
        );
    }
}

#[tokio::test]
async fn release_frees_a_hold_or_a_confirmed_detach_and_restores_the_device() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("lease-1", "reserving", None).await;

    // A hold that never attached.
    let held = fixture.reserve("dev-1", "lease-1").await;
    let (held, _) = reserved(&held);
    let ReleaseOutcome::Released(released) = fixture
        .reservations
        .release(&held.id, NOW + 5)
        .await
        .unwrap()
    else {
        panic!("expected a release");
    };
    assert_eq!(released.cause, ReleaseCause::Completed);
    assert_eq!(released.current.state, State::Released);
    assert_eq!(released.current.released_at, Some(NOW + 5));
    assert_eq!(fixture.status("dev-1").await, DeviceStatus::Available);

    // A detach the saga confirmed.
    let second = fixture.reserve("dev-1", "lease-1").await;
    let (second, created) = reserved(&second);
    assert!(created, "a released row is history, not a hold");
    assert_ne!(second.id, held.id);
    fixture
        .move_to(
            &second.id,
            &[State::Attaching, State::Attached, State::Detaching],
        )
        .await;
    let ReleaseOutcome::Released(released) = fixture
        .reservations
        .release(&second.id, NOW + 6)
        .await
        .unwrap()
    else {
        panic!("expected a release");
    };
    assert_eq!(released.previous.state, State::Detaching);
    assert_eq!(fixture.status("dev-1").await, DeviceStatus::Available);
    assert!(fixture.live("dev-1").await.is_empty());
}

#[tokio::test]
async fn release_never_frees_an_unconfirmed_attach_or_a_failed_detach() {
    let paths: [(&str, &[State]); 4] = [
        ("attaching", &[State::Attaching]),
        ("attached", &[State::Attaching, State::Attached]),
        ("attach_unknown", &[State::Attaching, State::AttachUnknown]),
        (
            "detach_failed",
            &[
                State::Attaching,
                State::Attached,
                State::Detaching,
                State::DetachFailed,
            ],
        ),
    ];
    for (name, path) in paths {
        let fixture = Fixture::new().await;
        fixture.device("dev-1", DeviceStatus::Available).await;
        fixture.lease("lease-1", "reserving", None).await;
        let held = fixture.reserve("dev-1", "lease-1").await;
        let (held, _) = reserved(&held);
        fixture.move_to(&held.id, path).await;

        let error = fixture
            .reservations
            .release(&held.id, NOW + 5)
            .await
            .expect_err(name);
        assert!(
            matches!(error, HardwareStoreError::IllegalTransition { .. }),
            "{name}: {error}"
        );
        let after = fixture
            .hardware
            .reservation(&held.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.state, *path.last().unwrap(), "{name}");
        assert!(after.released_at.is_none(), "{name}");
        assert_eq!(
            fixture.status("dev-1").await,
            DeviceStatus::Reserved,
            "{name}"
        );
    }
}

#[tokio::test]
async fn a_reserved_status_with_no_live_row_is_a_lost_write_not_a_hold() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("lease-1", "reserving", None).await;
    // The derived status survived a crash that lost the release write.
    sqlx::query("UPDATE hardware_devices SET status = 'reserved' WHERE id = 'dev-1'")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let outcome = fixture.reserve("dev-1", "lease-1").await;
    assert!(reserved(&outcome).1);
    assert_eq!(fixture.live("dev-1").await.len(), 1);
}

#[tokio::test]
async fn releasing_twice_is_a_no_op_and_an_unknown_reservation_is_not_found() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("lease-1", "reserving", None).await;
    let held = fixture.reserve("dev-1", "lease-1").await;
    let (held, _) = reserved(&held);
    fixture
        .reservations
        .release(&held.id, NOW + 5)
        .await
        .unwrap();
    let ReleaseOutcome::AlreadyReleased(row) = fixture
        .reservations
        .release(&held.id, NOW + 9)
        .await
        .unwrap()
    else {
        panic!("a replayed release is a no-op");
    };
    assert_eq!(row.released_at, Some(NOW + 5), "the stamp is not rewritten");
    assert_eq!(
        fixture.reservations.release("missing", NOW).await,
        Err(HardwareStoreError::NotFound)
    );
}

#[tokio::test]
async fn the_override_release_returns_the_previous_row_with_its_slot() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("lease-1", "reserving", None).await;
    let held = fixture.reserve("dev-1", "lease-1").await;
    let (held, _) = reserved(&held);
    fixture
        .move_to(
            &held.id,
            &[
                State::Attaching,
                State::Attached,
                State::Detaching,
                State::DetachFailed,
            ],
        )
        .await;

    let released = fixture
        .reservations
        .override_release(&held.id, NOW + 7)
        .await
        .unwrap();
    assert_eq!(released.cause, ReleaseCause::Override);
    assert_eq!(released.previous.state, State::DetachFailed);
    assert_eq!(
        released.previous.guest.as_ref().and_then(|g| g.usb_slot),
        Some(0),
        "the prior slot survives for the audit"
    );
    assert_eq!(released.current.state, State::Released);
    assert_eq!(
        released.current.guest.as_ref().and_then(|g| g.usb_slot),
        None
    );
    assert_eq!(fixture.status("dev-1").await, DeviceStatus::Available);
    assert!(matches!(
        fixture
            .reservations
            .override_release(&held.id, NOW + 8)
            .await,
        Err(HardwareStoreError::IllegalTransition { .. })
    ));
}

#[tokio::test]
async fn reservations_survive_a_restart_and_a_replayed_reserve_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fleet.db");
    let reservation_id;
    {
        let store = Store::open(&path).await.unwrap();
        let fixture = Fixture {
            reservations: Arc::new(SqliteHardwareReservations::new(store.pool().clone())),
            hardware: HardwareRepository::new(store.pool().clone()),
            pool: store.pool().clone(),
            store,
            _dir: tempfile::tempdir().unwrap(),
        };
        fixture.device("dev-1", DeviceStatus::Available).await;
        fixture.lease("lease-1", "reserving", None).await;
        fixture.lease("lease-2", "reserving", None).await;
        let held = fixture.reserve("dev-1", "lease-1").await;
        let (held, _) = reserved(&held);
        fixture
            .move_to(&held.id, &[State::Attaching, State::AttachUnknown])
            .await;
        reservation_id = held.id.clone();
        let other = fixture.reserve("dev-1", "lease-2").await;
        assert_eq!(refusal(&other).reason(), "hardware_busy");
        fixture.store.close().await;
    }

    let store = Store::open(&path).await.unwrap();
    let reservations = SqliteHardwareReservations::new(store.pool().clone());
    let replay = reservations
        .reserve(
            &request("dev-1", ReservationOwnerKind::Lease, "lease-1"),
            NOW + 10,
        )
        .await
        .unwrap();
    let (row, created) = reserved(&replay);
    assert!(!created);
    assert_eq!(row.id, reservation_id);
    assert_eq!(row.state, State::AttachUnknown, "the saga's state is kept");
    let other = reservations
        .reserve(
            &request("dev-1", ReservationOwnerKind::Lease, "lease-2"),
            NOW + 10,
        )
        .await
        .unwrap();
    assert_eq!(refusal(&other).reason(), "hardware_busy");
    let live = HardwareRepository::new(store.pool().clone())
        .list_live_reservations()
        .await
        .unwrap();
    assert_eq!(live.len(), 1);
}

#[tokio::test]
async fn refusal_release_and_reservation_are_audited_without_failing_the_call() {
    let fixture = Fixture::new().await;
    fixture.device("dev-1", DeviceStatus::Available).await;
    fixture.lease("lease-1", "reserving", None).await;
    fixture.lease("lease-2", "reserving", None).await;
    let service = HardwareReservations::new(
        fixture.reservations.clone(),
        Arc::new(AuditSink::new(fixture.pool.clone())),
    );
    let context = AuditContext {
        actor: "controller".to_owned(),
        operation_id: None,
    };
    let ask = |owner: &'static str| request("dev-1", ReservationOwnerKind::Lease, owner);

    let ReserveDecision::Reserved { reservation, .. } = service
        .reserve(&context, &ask("lease-1"), NOW)
        .await
        .unwrap()
    else {
        panic!("expected a reservation");
    };
    service
        .reserve(&context, &ask("lease-1"), NOW)
        .await
        .unwrap();
    assert!(matches!(
        service
            .reserve(&context, &ask("lease-2"), NOW)
            .await
            .unwrap(),
        ReserveDecision::Refused(ReserveRefusal::Busy { .. })
    ));
    fixture.set_lease_state("lease-1", "released").await;
    service
        .reserve(&context, &ask("lease-2"), NOW)
        .await
        .unwrap();
    service
        .override_release(&context, &reservation.id, NOW)
        .await
        .expect_err("already released by the stale correction");

    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT action, metadata_json FROM audit_events ORDER BY seq")
            .fetch_all(&fixture.pool)
            .await
            .unwrap();
    let events: Vec<BTreeMap<String, String>> = rows
        .iter()
        .map(|(_, json)| serde_json::from_str(json).unwrap())
        .collect();
    let names: Vec<&str> = events.iter().map(|event| event["event"].as_str()).collect();
    assert_eq!(
        names,
        [
            "hardware_reserved",
            "hardware_refused",
            "hardware_released",
            "hardware_reserved"
        ],
        "the repeat is silent"
    );
    assert_eq!(events[1]["reason"], "hardware_busy");
    assert_eq!(events[1]["holder_id"], "lease-1");
    assert_eq!(events[2]["outcome"], "owner_finished");
    assert_eq!(events[2]["previous_state"], "held");
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    #[derive(Clone, Copy, Debug)]
    enum Op {
        Reserve {
            owner: usize,
            device: usize,
        },
        Release {
            pick: usize,
        },
        Override {
            pick: usize,
        },
        Move {
            pick: usize,
            to: usize,
            wild: bool,
        },
        FinishLease {
            owner: usize,
        },
        /// A device refresh writes the observed status over the derived one.
        Refresh {
            device: usize,
        },
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => (0..4_usize, 0..2_usize).prop_map(|(owner, device)| Op::Reserve { owner, device }),
            2 => (0..8_usize).prop_map(|pick| Op::Release { pick }),
            1 => (0..8_usize).prop_map(|pick| Op::Override { pick }),
            4 => (0..8_usize, 0..7_usize, 0..8_u8).prop_map(|(pick, to, wild)| Op::Move { pick, to, wild: wild == 0 }),
            3 => (0..3_usize).prop_map(|owner| Op::FinishLease { owner }),
            2 => (0..2_usize).prop_map(|device| Op::Refresh { device }),
        ]
    }

    async fn all_rows(pool: &SqlitePool) -> Vec<HardwareReservation> {
        let hardware = HardwareRepository::new(pool.clone());
        let mut rows = Vec::new();
        for device in ["dev-0", "dev-1"] {
            let ids: Vec<String> = sqlx::query_scalar(
                "SELECT id FROM hardware_reservations WHERE device_id = ?1 ORDER BY id",
            )
            .bind(device)
            .fetch_all(pool)
            .await
            .unwrap();
            for id in ids {
                rows.push(hardware.reservation(&id).await.unwrap().unwrap());
            }
        }
        rows
    }

    fn live_of(rows: &[HardwareReservation], device: &str) -> Vec<HardwareReservation> {
        rows.iter()
            .filter(|row| row.device_id == device && row.state.is_live())
            .cloned()
            .collect()
    }

    fn has_slot(row: &HardwareReservation) -> bool {
        row.guest
            .as_ref()
            .is_some_and(|guest| guest.usb_slot.is_some())
    }

    fn owner_of(index: usize) -> (ReservationOwnerKind, String) {
        if index < 3 {
            (ReservationOwnerKind::Lease, format!("lease-{index}"))
        } else {
            (ReservationOwnerKind::Machine, "machine-0".to_owned())
        }
    }

    async fn run(ops: Vec<Op>) {
        let fixture = Fixture::new().await;
        for device in ["dev-0", "dev-1"] {
            fixture.device(device, DeviceStatus::Available).await;
        }
        for index in 0..3 {
            fixture
                .lease(&format!("lease-{index}"), "reserving", None)
                .await;
        }
        fixture.machine("machine-0").await;
        let mut now = NOW;
        // Devices a refresh wrote over, not yet repaired by a reserve.
        let mut stale: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for op in ops {
            now += 1;
            let before = all_rows(&fixture.pool).await;
            match op {
                Op::Reserve { owner, device } => {
                    let (kind, owner_id) = owner_of(owner);
                    let device = format!("dev-{device}");
                    let outcome = fixture
                        .reservations
                        .reserve(&request(&device, kind, &owner_id), now)
                        .await
                        .unwrap();
                    let live_before = live_of(&before, &device);
                    // Only never-attached holds of finished owners are freed.
                    for released in &outcome.released {
                        assert_eq!(released.previous.state, State::Held);
                        assert_eq!(released.cause, ReleaseCause::OwnerFinished);
                        // It was a live row on this device, as read before.
                        assert!(before.contains(&released.previous));
                        assert_eq!(released.previous.device_id, device);
                        // And the database agrees with what was reported.
                        assert_eq!(released.current.state, State::Released);
                        let stored = fixture.hardware.reservation(&released.current.id).await;
                        assert_eq!(stored.unwrap().as_ref(), Some(&released.current));
                    }
                    match &outcome.decision {
                        ReserveDecision::Reserved {
                            reservation,
                            created: true,
                        } => {
                            assert_eq!(reservation.state, State::Held);
                            // Free, or only freed by the stale corrections.
                            assert!(
                                live_before.is_empty()
                                    || outcome.released.len() == live_before.len()
                            );
                        }
                        ReserveDecision::Reserved {
                            reservation,
                            created: false,
                        } => {
                            assert_eq!(live_before.as_slice(), std::slice::from_ref(reservation));
                            assert_eq!(reservation.owner_id, owner_id);
                        }
                        ReserveDecision::Refused(ReserveRefusal::Busy { holder }) => {
                            assert_eq!(live_before, [holder.as_ref().clone()]);
                            assert!(holder.owner_id != owner_id || holder.owner_kind != kind);
                        }
                        ReserveDecision::Refused(_) => {}
                    }
                }
                Op::Release { pick } | Op::Override { pick } => {
                    let live: Vec<_> = before.iter().filter(|r| r.state.is_live()).collect();
                    let Some(target) = live.get(pick % live.len().max(1)) else {
                        continue;
                    };
                    if matches!(op, Op::Release { .. }) {
                        let result = fixture.reservations.release(&target.id, now).await;
                        let may_release = matches!(target.state, State::Detaching)
                            || (target.state == State::Held && !has_slot(target));
                        assert_eq!(result.is_ok(), may_release, "{:?}", target.state);
                        if !may_release {
                            let after = fixture.hardware.reservation(&target.id).await;
                            assert_eq!(after.unwrap().unwrap().state, target.state);
                        }
                    } else {
                        let released = fixture
                            .reservations
                            .override_release(&target.id, now)
                            .await
                            .unwrap();
                        assert_eq!(&released.previous, *target);
                    }
                }
                Op::Move { pick, to, wild } => {
                    let live: Vec<_> = before.iter().filter(|r| r.state.is_live()).collect();
                    let Some(target) = live.get(pick % live.len().max(1)) else {
                        continue;
                    };
                    // Releases go through the store (which also frees the
                    // device's derived status), never a bare transition.
                    let successors = target.state.successors();
                    let to = if wild || successors.is_empty() {
                        State::ALL[to % State::ALL.len()]
                    } else {
                        successors[to % successors.len()]
                    };
                    if to == State::Released {
                        continue;
                    }
                    let guest =
                        (target.state == State::Held && to == State::Attaching).then(|| {
                            GuestTarget {
                                account_id: "account-1".to_owned(),
                                node: "node-a".to_owned(),
                                vmid: 9001,
                                usb_slot: Some(0),
                            }
                        });
                    // Illegal moves are refused by the repository; either
                    // way the invariants below must hold.
                    let _ = fixture
                        .hardware
                        .transition_reservation(&target.id, target.state, to, guest.as_ref(), now)
                        .await;
                }
                Op::FinishLease { owner } => {
                    fixture
                        .set_lease_state(&format!("lease-{owner}"), "released")
                        .await;
                }
                Op::Refresh { device } => {
                    // The refresh observes nothing referencing the mapping,
                    // so it writes `available`, over `reserved` if held.
                    let device = format!("dev-{device}");
                    fixture.device(&device, DeviceStatus::Available).await;
                    stale.insert(device);
                }
            }

            let after = all_rows(&fixture.pool).await;
            for device in ["dev-0", "dev-1"] {
                let live = live_of(&after, device);
                assert!(live.len() <= 1, "two live holders of {device}: {live:?}");
                let status = fixture.status(device).await;
                // A reserve that found the live row repairs the status in
                // the same transaction (a repeat or a busy refusal).
                let repaired = matches!(
                    op,
                    Op::Reserve { device: touched, .. } if format!("dev-{touched}") == device
                ) && !live.is_empty();
                if live.is_empty() || repaired || !stale.contains(device) {
                    let expected = if live.is_empty() {
                        DeviceStatus::Available
                    } else {
                        DeviceStatus::Reserved
                    };
                    assert_eq!(status, expected, "{device}: {live:?}");
                    stale.remove(device);
                } else {
                    // Refreshed and not touched since: only ever `available`.
                    assert_eq!(status, DeviceStatus::Available, "{device}");
                }
            }
            for row in &after {
                assert_eq!(row.state == State::Released, row.released_at.is_some());
                // Released is terminal.
                if let Some(old) = before.iter().find(|old| old.id == row.id)
                    && old.state == State::Released
                {
                    assert_eq!(old, row);
                }
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn random_transitions_never_double_hold_or_release_on_a_guess(
            ops in proptest::collection::vec(op(), 1..40)
        ) {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(run(ops));
        }
    }
}
