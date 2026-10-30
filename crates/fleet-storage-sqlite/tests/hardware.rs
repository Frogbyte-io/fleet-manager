//! FM-1101: hardware devices and exclusive reservations (migration 0067).
//! Nothing here is mocked: a real database file, the real migrations.

use std::sync::Arc;

use fleet_application::hardware::{
    DeviceObservation, HardwareStore as _, HardwareStoreError, NewHardwareReservation,
};
use fleet_core::{
    DeviceNodeEntry, DeviceStatus, GuestTarget, HardwareKind, HardwareReservationState as State,
    ReservationOwnerKind, UnsupportedReason,
};
use fleet_storage_sqlite::{HardwareRepository, MIGRATOR, Store};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

const NOW: i64 = 1_800_000_000_000;

async fn setup() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().expect("a temp directory");
    let store = Store::open(&dir.path().join("fleet.db"))
        .await
        .expect("the store must open");
    (dir, store)
}

fn entry(node: &str) -> DeviceNodeEntry {
    DeviceNodeEntry {
        node: node.to_owned(),
        vendor_id: "1234".to_owned(),
        product_id: "abcd".to_owned(),
        usbpath: Some("1-4".to_owned()),
        manufacturer: Some("Example Maker".to_owned()),
        product: Some("Example Device".to_owned()),
        last_seen_at: NOW,
    }
}

fn observation(id: &str, mapping: &str) -> DeviceObservation {
    DeviceObservation {
        id: id.to_owned(),
        account_id: "account-1".to_owned(),
        mapping_id: mapping.to_owned(),
        kind: HardwareKind::Usb,
        entries: vec![entry("pve1")],
        status: DeviceStatus::Available,
    }
}

fn hold(id: &str, device: &str, kind: ReservationOwnerKind, owner: &str) -> NewHardwareReservation {
    NewHardwareReservation {
        id: id.to_owned(),
        device_id: device.to_owned(),
        owner_kind: kind,
        owner_id: owner.to_owned(),
        guest: None,
    }
}

fn target(slot: Option<u8>) -> GuestTarget {
    GuestTarget {
        account_id: "account-1".to_owned(),
        node: "pve1".to_owned(),
        vmid: 9100,
        usb_slot: slot,
    }
}

#[tokio::test]
async fn devices_round_trip_with_entries_status_and_note() {
    let (_dir, store) = setup().await;
    let repo = HardwareRepository::new(store.pool().clone());
    let mut seen = observation("dev-1", "reader");
    seen.entries = vec![entry("pve2"), entry("pve1")];
    let created = repo.upsert_device(&seen, NOW).await.unwrap();
    assert_eq!(created.id, "dev-1");
    assert_eq!(created.entries.len(), 2);
    assert_eq!(created.entries[0].node, "pve1", "entries order by node");
    assert_eq!(created.status, DeviceStatus::Available);
    assert_eq!(created.created_at, NOW);

    repo.set_device_note("dev-1", Some("bench shelf"), NOW + 1)
        .await
        .unwrap();
    let status = DeviceStatus::Unsupported(UnsupportedReason::TokenLacksMappingUse);
    repo.set_device_status("dev-1", status, NOW + 2)
        .await
        .unwrap();
    let read = repo.device("dev-1").await.unwrap().unwrap();
    assert_eq!(read.status, status);
    assert_eq!(read.note.as_deref(), Some("bench shelf"));
    assert_eq!(read.updated_at, NOW + 2);
    assert_eq!(
        repo.device_by_mapping("account-1", "reader")
            .await
            .unwrap()
            .unwrap()
            .id,
        "dev-1"
    );
    assert_eq!(repo.list_devices("account-1").await.unwrap().len(), 1);
    assert!(repo.list_devices("other").await.unwrap().is_empty());

    // Back to a status without a reason clears the reason.
    repo.set_device_status("dev-1", DeviceStatus::Missing, NOW + 3)
        .await
        .unwrap();
    assert_eq!(
        repo.device("dev-1").await.unwrap().unwrap().status,
        DeviceStatus::Missing
    );
    assert_eq!(
        repo.set_device_status("nope", DeviceStatus::Missing, NOW)
            .await,
        Err(HardwareStoreError::NotFound)
    );
}

#[tokio::test]
async fn every_status_round_trips() {
    let (_dir, store) = setup().await;
    let repo = HardwareRepository::new(store.pool().clone());
    repo.upsert_device(&observation("dev-1", "reader"), NOW)
        .await
        .unwrap();
    for status in [
        DeviceStatus::Available,
        DeviceStatus::Reserved,
        DeviceStatus::ExternallyAttached,
        DeviceStatus::Missing,
        DeviceStatus::Quarantined,
        DeviceStatus::Unsupported(UnsupportedReason::NoNodeEntry),
        DeviceStatus::Unsupported(UnsupportedReason::AmbiguousMapping),
        DeviceStatus::Unsupported(UnsupportedReason::TokenLacksGuestHwtype),
        DeviceStatus::Unsupported(UnsupportedReason::PveTooOld),
        DeviceStatus::Unsupported(UnsupportedReason::UsbInventoryUnreadable),
    ] {
        repo.set_device_status("dev-1", status, NOW).await.unwrap();
        assert_eq!(repo.device("dev-1").await.unwrap().unwrap().status, status);
    }
}

#[tokio::test]
async fn upsert_refreshes_the_known_device_and_replaces_its_entries() {
    let (_dir, store) = setup().await;
    let repo = HardwareRepository::new(store.pool().clone());
    repo.upsert_device(&observation("dev-1", "reader"), NOW)
        .await
        .unwrap();
    let mut again = observation("ignored-id", "reader");
    again.entries = vec![entry("pve2")];
    again.status = DeviceStatus::Missing;
    let refreshed = repo.upsert_device(&again, NOW + 10).await.unwrap();
    assert_eq!(refreshed.id, "dev-1", "the identity is the mapping");
    assert_eq!(refreshed.entries.len(), 1);
    assert_eq!(refreshed.entries[0].node, "pve2");
    assert_eq!(refreshed.status, DeviceStatus::Missing);
    assert_eq!(refreshed.created_at, NOW);
    assert_eq!(refreshed.updated_at, NOW + 10);
    assert_eq!(repo.list_devices("account-1").await.unwrap().len(), 1);

    let mut duplicate = observation("dev-1", "reader");
    duplicate.entries = vec![entry("pve1"), entry("pve1")];
    assert!(matches!(
        repo.upsert_device(&duplicate, NOW + 20).await,
        Err(HardwareStoreError::Invalid(_))
    ));
    // The failed refresh rolled back as a whole.
    assert_eq!(
        repo.device("dev-1").await.unwrap().unwrap().entries[0].node,
        "pve2"
    );
}

#[tokio::test]
async fn reservations_round_trip_through_the_whole_lifecycle() {
    let (_dir, store) = setup().await;
    let repo = HardwareRepository::new(store.pool().clone());
    repo.upsert_device(&observation("dev-1", "reader"), NOW)
        .await
        .unwrap();
    let held = repo
        .insert_reservation(
            &hold("res-1", "dev-1", ReservationOwnerKind::Lease, "lease-1"),
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(held.state, State::Held);
    assert_eq!(held.owner_kind, ReservationOwnerKind::Lease);
    assert_eq!(held.guest, None);
    assert_eq!(held.released_at, None);

    let attaching = repo
        .transition_reservation(
            "res-1",
            State::Held,
            State::Attaching,
            Some(&target(Some(1))),
            NOW + 1,
        )
        .await
        .unwrap();
    assert_eq!(attaching.guest, Some(target(Some(1))));
    repo.transition_reservation("res-1", State::Attaching, State::Attached, None, NOW + 2)
        .await
        .unwrap();

    // Mid-run hotplug: detach, return to held (guest kept, slot cleared),
    // attach again.
    repo.transition_reservation("res-1", State::Attached, State::Detaching, None, NOW + 3)
        .await
        .unwrap();
    let back = repo
        .transition_reservation(
            "res-1",
            State::Detaching,
            State::Held,
            Some(&target(None)),
            NOW + 4,
        )
        .await
        .unwrap();
    assert_eq!(back.guest, Some(target(None)), "the slot is cleared");
    assert_eq!(
        repo.live_reservation_for_device("dev-1")
            .await
            .unwrap()
            .unwrap()
            .id,
        "res-1",
        "a detached-but-held device is still reserved"
    );
    repo.transition_reservation(
        "res-1",
        State::Held,
        State::Attaching,
        Some(&target(Some(2))),
        NOW + 5,
    )
    .await
    .unwrap();
    repo.transition_reservation("res-1", State::Attaching, State::Attached, None, NOW + 6)
        .await
        .unwrap();
    repo.transition_reservation("res-1", State::Attached, State::Detaching, None, NOW + 7)
        .await
        .unwrap();
    let released = repo
        .transition_reservation("res-1", State::Detaching, State::Released, None, NOW + 8)
        .await
        .unwrap();
    assert_eq!(released.state, State::Released);
    assert_eq!(released.released_at, Some(NOW + 8));
    assert_eq!(released.updated_at, NOW + 8);
    assert!(
        repo.live_reservation_for_device("dev-1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(repo.list_live_reservations().await.unwrap().is_empty());
    // History stays.
    assert!(repo.reservation("res-1").await.unwrap().is_some());
}

#[tokio::test]
async fn illegal_and_stale_transitions_are_refused_and_change_nothing() {
    let (_dir, store) = setup().await;
    let repo = HardwareRepository::new(store.pool().clone());
    repo.upsert_device(&observation("dev-1", "reader"), NOW)
        .await
        .unwrap();
    repo.insert_reservation(
        &hold("res-1", "dev-1", ReservationOwnerKind::Machine, "machine-1"),
        NOW,
    )
    .await
    .unwrap();

    // Not on the state machine.
    assert!(matches!(
        repo.transition_reservation("res-1", State::Held, State::Attached, None, NOW + 1)
            .await,
        Err(HardwareStoreError::IllegalTransition {
            actual: State::Held,
            ..
        })
    ));
    // Legal edge, but the caller's view of the state is stale.
    assert!(matches!(
        repo.transition_reservation("res-1", State::Attaching, State::Attached, None, NOW + 1)
            .await,
        Err(HardwareStoreError::IllegalTransition {
            actual: State::Held,
            ..
        })
    ));
    // A slot outside usb0..usb4.
    assert!(matches!(
        repo.transition_reservation(
            "res-1",
            State::Held,
            State::Attaching,
            Some(&target(Some(5))),
            NOW + 1
        )
        .await,
        Err(HardwareStoreError::Invalid(_))
    ));
    assert_eq!(
        repo.transition_reservation("missing", State::Held, State::Attaching, None, NOW)
            .await,
        Err(HardwareStoreError::NotFound)
    );
    let unchanged = repo.reservation("res-1").await.unwrap().unwrap();
    assert_eq!(unchanged.state, State::Held);
    assert_eq!(unchanged.updated_at, NOW);

    // Released is terminal.
    repo.transition_reservation("res-1", State::Held, State::Released, None, NOW + 2)
        .await
        .unwrap();
    assert!(matches!(
        repo.transition_reservation("res-1", State::Released, State::Held, None, NOW + 3)
            .await,
        Err(HardwareStoreError::IllegalTransition {
            actual: State::Released,
            ..
        })
    ));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_second_live_hold_on_a_device_is_refused_by_the_constraint() {
    let (_dir, store) = setup().await;
    let repo = HardwareRepository::new(store.pool().clone());
    repo.upsert_device(&observation("dev-1", "reader"), NOW)
        .await
        .unwrap();
    repo.upsert_device(&observation("dev-2", "other"), NOW)
        .await
        .unwrap();
    repo.insert_reservation(
        &hold("res-1", "dev-1", ReservationOwnerKind::Lease, "lease-1"),
        NOW,
    )
    .await
    .unwrap();

    // The same owner kind, a different kind, and a live non-held state all
    // collide.
    for (id, kind, owner) in [
        ("res-2", ReservationOwnerKind::Lease, "lease-2"),
        ("res-3", ReservationOwnerKind::Machine, "machine-1"),
    ] {
        match repo
            .insert_reservation(&hold(id, "dev-1", kind, owner), NOW + 1)
            .await
        {
            Err(HardwareStoreError::Held { holder }) => {
                assert_eq!(holder.id, "res-1");
                assert_eq!(holder.owner_id, "lease-1");
            }
            other => panic!("expected a hold conflict, got {other:?}"),
        }
    }
    repo.transition_reservation("res-1", State::Held, State::Attaching, None, NOW + 2)
        .await
        .unwrap();
    repo.transition_reservation(
        "res-1",
        State::Attaching,
        State::AttachUnknown,
        None,
        NOW + 3,
    )
    .await
    .unwrap();
    assert!(matches!(
        repo.insert_reservation(
            &hold("res-4", "dev-1", ReservationOwnerKind::Lease, "lease-3"),
            NOW + 4
        )
        .await,
        Err(HardwareStoreError::Held { .. })
    ));

    // The raw index refuses it too, bypassing the repository.
    let raw = sqlx::query(
        "INSERT INTO hardware_reservations (id, device_id, owner_kind, owner_id, state, created_at, updated_at) \
         VALUES ('raw', 'dev-1', 'lease', 'lease-9', 'held', 1, 1)",
    )
    .execute(store.pool())
    .await;
    assert!(
        raw.is_err(),
        "the partial unique index must refuse a double hold"
    );

    // Another device is unaffected, and an unknown device is not found.
    repo.insert_reservation(
        &hold("res-5", "dev-2", ReservationOwnerKind::Lease, "lease-1"),
        NOW + 5,
    )
    .await
    .unwrap();
    assert_eq!(
        repo.insert_reservation(
            &hold("res-6", "nope", ReservationOwnerKind::Lease, "lease-1"),
            NOW
        )
        .await,
        Err(HardwareStoreError::NotFound)
    );

    // Once released, the device can be held again; history stays.
    repo.transition_reservation(
        "res-1",
        State::AttachUnknown,
        State::Detaching,
        None,
        NOW + 6,
    )
    .await
    .unwrap();
    repo.transition_reservation("res-1", State::Detaching, State::Released, None, NOW + 7)
        .await
        .unwrap();
    repo.insert_reservation(
        &hold("res-7", "dev-1", ReservationOwnerKind::Machine, "machine-1"),
        NOW + 8,
    )
    .await
    .unwrap();
    assert_eq!(
        repo.live_reservations_for_owner(ReservationOwnerKind::Machine, "machine-1")
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        repo.live_reservations_for_owner(ReservationOwnerKind::Lease, "lease-1")
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn concurrent_holds_admit_exactly_one() {
    let (_dir, store) = setup().await;
    let repo = Arc::new(HardwareRepository::new(store.pool().clone()));
    repo.upsert_device(&observation("dev-1", "reader"), NOW)
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for index in 0..8 {
        let repo = Arc::clone(&repo);
        tasks.push(tokio::spawn(async move {
            repo.insert_reservation(
                &hold(
                    &format!("res-{index}"),
                    "dev-1",
                    ReservationOwnerKind::Lease,
                    &format!("lease-{index}"),
                ),
                NOW,
            )
            .await
        }));
    }
    let mut winners = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => winners += 1,
            Err(HardwareStoreError::Held { .. }) => {}
            Err(other) => panic!("unexpected failure: {other:?}"),
        }
    }
    assert_eq!(winners, 1);
    assert_eq!(repo.list_live_reservations().await.unwrap().len(), 1);
}

#[tokio::test]
async fn table_checks_reject_reasonless_unsupported_and_partial_guests() {
    let (_dir, store) = setup().await;
    let pool = store.pool();
    let bad_device = sqlx::query(
        "INSERT INTO hardware_devices (id, account_id, mapping_id, kind, status, created_at, updated_at) \
         VALUES ('d', 'a', 'm', 'usb', 'unsupported', 1, 1)",
    )
    .execute(pool)
    .await;
    assert!(bad_device.is_err(), "unsupported needs a reason");
    sqlx::query(
        "INSERT INTO hardware_devices (id, account_id, mapping_id, kind, status, created_at, updated_at) \
         VALUES ('d', 'a', 'm', 'usb', 'available', 1, 1)",
    )
    .execute(pool)
    .await
    .unwrap();
    for sql in [
        // A release without a release time.
        "INSERT INTO hardware_reservations (id, device_id, owner_kind, owner_id, state, created_at, updated_at) \
         VALUES ('r', 'd', 'lease', 'l', 'released', 1, 1)",
        // A slot without a guest.
        "INSERT INTO hardware_reservations (id, device_id, owner_kind, owner_id, state, usb_slot, created_at, updated_at) \
         VALUES ('r', 'd', 'lease', 'l', 'held', 1, 1, 1)",
        // An unknown owner kind.
        "INSERT INTO hardware_reservations (id, device_id, owner_kind, owner_id, state, created_at, updated_at) \
         VALUES ('r', 'd', 'robot', 'l', 'held', 1, 1)",
    ] {
        assert!(sqlx::query(sql).execute(pool).await.is_err(), "{sql}");
    }
    // A device with a reservation (even released history) cannot be deleted.
    sqlx::query(
        "INSERT INTO hardware_reservations (id, device_id, owner_kind, owner_id, state, created_at, updated_at, released_at) \
         VALUES ('h', 'd', 'lease', 'l', 'released', 1, 1, 1)",
    )
    .execute(pool)
    .await
    .unwrap();
    assert!(
        sqlx::query("DELETE FROM hardware_devices WHERE id = 'd'")
            .execute(pool)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn the_migration_applies_on_a_database_with_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fleet.db");
    let legacy = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    // The schema as of the previous migration, with rows in it.
    MIGRATOR.run_to(66, &legacy).await.unwrap();
    sqlx::query(
        "INSERT INTO audit_events \
         (id, occurred_at, actor, action, resource, allowed, reason, correlation_id, operation_id, outcome, metadata_json) \
         VALUES ('keep-me', 1, 'actor', 'operation.run', NULL, 1, 'permitted', NULL, 'op-1', NULL, '{}')",
    )
    .execute(&legacy)
    .await
    .unwrap();
    legacy.close().await;

    let store = Store::open(&path).await.unwrap();
    let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE id = 'keep-me'")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(kept, 1, "existing rows survive");
    let repo = HardwareRepository::new(store.pool().clone());
    repo.upsert_device(&observation("dev-1", "reader"), NOW)
        .await
        .unwrap();
    repo.insert_reservation(
        &hold("res-1", "dev-1", ReservationOwnerKind::Lease, "lease-1"),
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(repo.list_live_reservations().await.unwrap().len(), 1);
}
