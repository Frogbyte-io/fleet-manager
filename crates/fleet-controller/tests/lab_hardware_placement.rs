//! FM-1121: the hardware part of Lab placement over real SQLite (a database
//! file, the real migrations, the real reservation store). No Proxmox call
//! exists here: placement only reserves. Fixtures use invented ids.

use std::sync::Arc;

use fleet_application::hardware::{DeviceObservation, HardwareStore as _};
use fleet_application::hardware_reservation::HardwareReservations;
use fleet_application::lab_placement::{HardwareDemand, HardwarePlacement, PlacementRefusal};
use fleet_controller::hardware_reservation_store::SqliteHardwareReservations;
use fleet_core::{
    DeviceNodeEntry, DeviceStatus, GuestTarget, HardwareKind, HardwareReservation,
    HardwareReservationState as State, LabHardware, ReservationOwnerKind,
};
use fleet_storage_sqlite::{AuditSink, HardwareRepository, Store};
use sqlx::SqlitePool;

const NOW: i64 = 1_800_000_000_000;
const ACCOUNT: &str = "account-1";
const NODE: &str = "node-a";

struct Fixture {
    _dir: tempfile::TempDir,
    pool: SqlitePool,
    hardware: HardwareRepository,
    placement: Arc<HardwarePlacement>,
}

fn usb(mapping: &str) -> LabHardware {
    LabHardware {
        kind: HardwareKind::Usb,
        mapping: mapping.to_owned(),
    }
}

impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("a temp directory");
        let store = Store::open(&dir.path().join("fleet.db"))
            .await
            .expect("the store must open");
        let pool = store.pool().clone();
        // The store outlives the fixture through its pool.
        std::mem::forget(store);
        let placement = Arc::new(HardwarePlacement::new(
            Arc::new(HardwareRepository::new(pool.clone())),
            Arc::new(HardwareReservations::new(
                Arc::new(SqliteHardwareReservations::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )),
            900_000,
        ));
        Self {
            hardware: HardwareRepository::new(pool.clone()),
            pool,
            placement,
            _dir: dir,
        }
    }

    async fn device(&self, mapping: &str) -> String {
        self.device_seen(mapping, NOW).await
    }

    /// Records the device as last seen at `seen_at`.
    async fn device_seen(&self, mapping: &str, seen_at: i64) -> String {
        self.hardware
            .upsert_device(
                &DeviceObservation {
                    id: format!("device-{mapping}"),
                    account_id: ACCOUNT.to_owned(),
                    mapping_id: mapping.to_owned(),
                    kind: HardwareKind::Usb,
                    entries: vec![DeviceNodeEntry {
                        node: NODE.to_owned(),
                        vendor_id: "05ac".to_owned(),
                        product_id: "1500".to_owned(),
                        usbpath: Some("1-10".to_owned()),
                        manufacturer: None,
                        product: None,
                        last_seen_at: seen_at,
                    }],
                    status: DeviceStatus::Available,
                },
                NOW,
            )
            .await
            .expect("the device records")
            .id
    }

    /// A lease in `state` with a provision record that allocated a guest.
    async fn lease(&self, id: &str, state: &str) {
        sqlx::query(
            "INSERT INTO lab_provisions (id, template_version_id, state, vmid, created_at, \
             updated_at) VALUES (?1, 'template-version-1', 'provisioned', 9001, ?2, ?2)",
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

    async fn reserve(
        &self,
        lease: &str,
        node: &str,
        declared: &[LabHardware],
    ) -> Result<Vec<HardwareReservation>, PlacementRefusal> {
        self.reserve_at(lease, node, declared, NOW + 1).await
    }

    async fn reserve_at(
        &self,
        lease: &str,
        node: &str,
        declared: &[LabHardware],
        now: i64,
    ) -> Result<Vec<HardwareReservation>, PlacementRefusal> {
        self.placement
            .reserve(
                "tester",
                &HardwareDemand {
                    lease_id: lease,
                    account_id: ACCOUNT,
                    clone_node: node,
                    declared,
                    operation_id: None,
                },
                now,
            )
            .await
            .expect("the store must not fail")
    }

    async fn live(&self, lease: &str) -> Vec<HardwareReservation> {
        self.hardware
            .live_reservations_for_owner(ReservationOwnerKind::Lease, lease)
            .await
            .unwrap()
    }

    async fn status(&self, device: &str) -> DeviceStatus {
        self.hardware.device(device).await.unwrap().unwrap().status
    }

    async fn rows(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM hardware_reservations")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn a_declaration_of_nothing_touches_nothing() {
    let fixture = Fixture::new().await;
    fixture.lease("lease-1", "provisioning").await;
    let held = fixture.reserve("lease-1", NODE, &[]).await.unwrap();
    assert!(held.is_empty());
    assert_eq!(fixture.rows().await, 0);
}

#[tokio::test]
async fn declared_devices_are_reserved_for_the_lease_and_a_repeat_returns_the_same_rows() {
    let fixture = Fixture::new().await;
    let a = fixture.device("dev-a").await;
    let b = fixture.device("dev-b").await;
    fixture.lease("lease-1", "provisioning").await;

    let first = fixture
        .reserve("lease-1", NODE, &[usb("dev-b"), usb("dev-a")])
        .await
        .unwrap();
    // Taken in mapping order, whatever the declaration order.
    assert_eq!(
        first
            .iter()
            .map(|row| row.device_id.clone())
            .collect::<Vec<_>>(),
        vec![a.clone(), b.clone()]
    );
    assert!(first.iter().all(|row| row.state == State::Held));
    assert_eq!(fixture.status(&a).await, DeviceStatus::Reserved);

    let again = fixture
        .reserve("lease-1", NODE, &[usb("dev-a"), usb("dev-b")])
        .await
        .unwrap();
    assert_eq!(
        again.iter().map(|row| row.id.clone()).collect::<Vec<_>>(),
        first.iter().map(|row| row.id.clone()).collect::<Vec<_>>()
    );
    assert_eq!(fixture.rows().await, 2);
}

#[tokio::test]
async fn a_held_device_is_busy_to_another_lease_naming_the_holder() {
    let fixture = Fixture::new().await;
    fixture.device("dev-a").await;
    fixture.lease("lease-1", "provisioning").await;
    fixture.lease("lease-2", "provisioning").await;
    fixture
        .reserve("lease-1", NODE, &[usb("dev-a")])
        .await
        .unwrap();

    let refusal = fixture
        .reserve("lease-2", NODE, &[usb("dev-a")])
        .await
        .unwrap_err();
    assert_eq!(refusal.reason(), "hardware_busy");
    let text = refusal.to_string();
    assert!(
        text.starts_with("hardware dev-a cannot be reserved:"),
        "{text}"
    );
    assert!(text.contains("lease lease-1"), "{text}");
    assert!(fixture.live("lease-2").await.is_empty());
    assert_eq!(fixture.live("lease-1").await.len(), 1);
}

#[tokio::test]
async fn a_device_held_by_a_finished_lease_is_free_to_the_next() {
    // The owner's state is authoritative: a hold that never attached and
    // whose lease is over no longer counts, so a lost release write never
    // strands the device.
    let fixture = Fixture::new().await;
    let device = fixture.device("dev-a").await;
    fixture.lease("lease-1", "provisioning").await;
    fixture.lease("lease-2", "provisioning").await;
    fixture
        .reserve("lease-1", NODE, &[usb("dev-a")])
        .await
        .unwrap();
    sqlx::query("UPDATE lab_leases SET state = 'released' WHERE id = 'lease-1'")
        .execute(&fixture.pool)
        .await
        .unwrap();

    let held = fixture
        .reserve("lease-2", NODE, &[usb("dev-a")])
        .await
        .unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].device_id, device);
    assert!(fixture.live("lease-1").await.is_empty());
}

#[tokio::test]
async fn a_device_taken_over_from_a_finished_lease_must_still_be_fresh() {
    // The store frees a dead owner's hold, but it checks the stored status,
    // not how old the observation is: the takeover owes the freshness an
    // available device owes, or the lease would reserve on a stale view.
    let fixture = Fixture::new().await;
    let device = fixture.device("dev-a").await;
    fixture.lease("lease-1", "provisioning").await;
    fixture.lease("lease-2", "provisioning").await;
    fixture
        .reserve("lease-1", NODE, &[usb("dev-a")])
        .await
        .unwrap();
    sqlx::query("UPDATE lab_leases SET state = 'released' WHERE id = 'lease-1'")
        .execute(&fixture.pool)
        .await
        .unwrap();

    // Two hours on, nothing has refreshed the observation (seen at NOW).
    let refusal = fixture
        .reserve_at("lease-2", NODE, &[usb("dev-a")], NOW + 7_200_000)
        .await
        .unwrap_err();
    assert_eq!(refusal.reason(), "hardware_stale", "{refusal}");
    assert!(
        refusal.to_string().contains("stale observation"),
        "{refusal}"
    );
    // Nothing is held, by the dead lease or the refused one, and the device
    // is not shown reserved.
    assert!(fixture.live("lease-1").await.is_empty());
    assert!(fixture.live("lease-2").await.is_empty());
    assert_eq!(fixture.rows().await, 2, "history only, nothing live");
    assert_eq!(fixture.status(&device).await, DeviceStatus::Available);

    // The same takeover on a fresh observation is granted.
    let refreshed = fixture.device_seen("dev-a", NOW + 7_199_000).await;
    assert_eq!(refreshed, device);
    let held = fixture
        .reserve_at("lease-2", NODE, &[usb("dev-a")], NOW + 7_200_000)
        .await
        .unwrap();
    assert_eq!(held.len(), 1);
}

#[tokio::test]
async fn a_second_device_that_fails_the_takeover_check_releases_the_first() {
    let fixture = Fixture::new().await;
    fixture.device("dev-a").await;
    fixture.device("dev-b").await;
    for lease in ["lease-1", "lease-2"] {
        fixture.lease(lease, "provisioning").await;
    }
    // lease-1 held dev-b and is over.
    fixture
        .reserve("lease-1", NODE, &[usb("dev-b")])
        .await
        .unwrap();
    sqlx::query("UPDATE lab_leases SET state = 'released' WHERE id = 'lease-1'")
        .execute(&fixture.pool)
        .await
        .unwrap();
    // dev-a is freshly seen, dev-b only long ago.
    fixture.device_seen("dev-a", NOW + 7_199_000).await;

    let refusal = fixture
        .reserve_at(
            "lease-2",
            NODE,
            &[usb("dev-a"), usb("dev-b")],
            NOW + 7_200_000,
        )
        .await
        .unwrap_err();
    assert_eq!(refusal.reason(), "hardware_stale", "{refusal}");
    assert!(
        refusal.to_string().starts_with("hardware dev-b "),
        "{refusal}"
    );
    assert!(fixture.live("lease-2").await.is_empty(), "dev-a released");
}

#[tokio::test]
async fn a_device_held_in_an_unknown_state_is_never_taken_over() {
    let fixture = Fixture::new().await;
    fixture.device("dev-a").await;
    fixture.lease("lease-1", "provisioning").await;
    fixture.lease("lease-2", "provisioning").await;
    let held = fixture
        .reserve("lease-1", NODE, &[usb("dev-a")])
        .await
        .unwrap();
    let guest = GuestTarget {
        account_id: ACCOUNT.to_owned(),
        node: NODE.to_owned(),
        vmid: 9001,
        usb_slot: Some(0),
    };
    for (from, to, guest) in [
        (State::Held, State::Attaching, Some(&guest)),
        (State::Attaching, State::AttachUnknown, None),
    ] {
        fixture
            .hardware
            .transition_reservation(&held[0].id, from, to, guest, NOW + 2)
            .await
            .unwrap();
    }
    // Even once its lease is over.
    sqlx::query("UPDATE lab_leases SET state = 'released' WHERE id = 'lease-1'")
        .execute(&fixture.pool)
        .await
        .unwrap();

    let refusal = fixture
        .reserve("lease-2", NODE, &[usb("dev-a")])
        .await
        .unwrap_err();
    assert_eq!(refusal.reason(), "hardware_busy", "{refusal}");
    assert!(refusal.to_string().contains("attach_unknown"), "{refusal}");
    assert_eq!(fixture.live("lease-1").await[0].state, State::AttachUnknown);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_leases_race_for_one_device_and_exactly_one_wins() {
    let fixture = Arc::new(Fixture::new().await);
    fixture.device("dev-a").await;
    let leases: Vec<String> = (0..12).map(|n| format!("lease-{n}")).collect();
    for lease in &leases {
        fixture.lease(lease, "provisioning").await;
    }
    let mut tasks = Vec::new();
    for lease in leases {
        let fixture = fixture.clone();
        tasks.push(tokio::spawn(async move {
            let outcome = fixture.reserve(&lease, NODE, &[usb("dev-a")]).await;
            (lease, outcome)
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        let (lease, outcome) = task.await.unwrap();
        match outcome {
            Ok(held) => {
                assert_eq!(held.len(), 1);
                winners.push(lease);
            }
            Err(refusal) => assert_eq!(refusal.reason(), "hardware_busy", "{refusal}"),
        }
    }
    assert_eq!(winners.len(), 1, "{winners:?}");
    assert_eq!(fixture.rows().await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leases_that_want_the_same_pair_never_each_strand_one_device() {
    // Taken in mapping order, two leases collide on the first device: one
    // gets both, the other none, and nothing is left held by the loser.
    let fixture = Arc::new(Fixture::new().await);
    fixture.device("dev-a").await;
    fixture.device("dev-b").await;
    for lease in ["lease-1", "lease-2"] {
        fixture.lease(lease, "provisioning").await;
    }
    let one = {
        let fixture = fixture.clone();
        tokio::spawn(async move {
            fixture
                .reserve("lease-1", NODE, &[usb("dev-a"), usb("dev-b")])
                .await
        })
    };
    let two = {
        let fixture = fixture.clone();
        tokio::spawn(async move {
            fixture
                .reserve("lease-2", NODE, &[usb("dev-b"), usb("dev-a")])
                .await
        })
    };
    let (one, two) = (one.await.unwrap(), two.await.unwrap());
    assert_eq!(one.is_ok() as u8 + two.is_ok() as u8, 1, "{one:?} {two:?}");
    assert_eq!(
        fixture.rows().await,
        2,
        "the winner's two, nothing stranded"
    );
    let live = fixture.hardware.list_live_reservations().await.unwrap();
    assert_eq!(live.len(), 2);
    assert_eq!(live[0].owner_id, live[1].owner_id);
}

#[tokio::test]
async fn release_unattached_releases_only_holds_that_never_attached() {
    let fixture = Fixture::new().await;
    let held = fixture.device("dev-held").await;
    let attached = fixture.device("dev-attached").await;
    let unknown = fixture.device("dev-unknown").await;
    fixture.lease("lease-1", "provisioning").await;
    let rows = fixture
        .reserve(
            "lease-1",
            NODE,
            &[usb("dev-held"), usb("dev-attached"), usb("dev-unknown")],
        )
        .await
        .unwrap();
    let guest = GuestTarget {
        account_id: ACCOUNT.to_owned(),
        node: NODE.to_owned(),
        vmid: 9001,
        usb_slot: Some(0),
    };
    let row = |device: &str| {
        rows.iter()
            .find(|row| row.device_id == device)
            .unwrap()
            .id
            .clone()
    };
    for (device, path) in [
        (&attached, vec![State::Attaching, State::Attached]),
        (&unknown, vec![State::Attaching, State::AttachUnknown]),
    ] {
        let id = row(device);
        let mut from = State::Held;
        for to in path {
            let target = (from == State::Held).then_some(&guest);
            fixture
                .hardware
                .transition_reservation(&id, from, to, target, NOW + 2)
                .await
                .unwrap();
            from = to;
        }
    }

    let released = fixture
        .placement
        .release_unattached("tester", "lease-1", None, NOW + 3)
        .await
        .unwrap();
    assert_eq!(released, 1);
    let live = fixture.live("lease-1").await;
    let mut states: Vec<(String, State)> = live
        .iter()
        .map(|row| (row.device_id.clone(), row.state))
        .collect();
    states.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(
        states,
        vec![
            (attached.clone(), State::Attached),
            (unknown.clone(), State::AttachUnknown)
        ]
    );
    assert_eq!(fixture.status(&held).await, DeviceStatus::Available);
    // Idempotent: nothing more to release.
    assert_eq!(
        fixture
            .placement
            .release_unattached("tester", "lease-1", None, NOW + 4)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn a_refusal_names_the_constraint_and_reserves_nothing() {
    let fixture = Fixture::new().await;
    fixture.device("dev-a").await;
    fixture.lease("lease-1", "provisioning").await;

    // Wrong node: the device is on node-a, the clone on node-b.
    let wrong = fixture
        .reserve("lease-1", "node-b", &[usb("dev-a")])
        .await
        .unwrap_err();
    assert_eq!(wrong.reason(), "hardware_wrong_node");
    assert!(wrong.to_string().contains("node-a"), "{wrong}");
    assert!(wrong.to_string().contains("node-b"), "{wrong}");
    // Not inventoried at all.
    let unknown = fixture
        .reserve("lease-1", NODE, &[usb("dev-a"), usb("no-such-mapping")])
        .await
        .unwrap_err();
    assert_eq!(unknown.reason(), "hardware_unknown");
    // A declared device that is fine does not get reserved when another
    // fails the pre-check.
    assert_eq!(fixture.rows().await, 0);
}
