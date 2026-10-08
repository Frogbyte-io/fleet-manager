//! FM-715: capacity reservations are checked and written in one SQLite
//! transaction against the node's observed capacity minus its held
//! reservations. The concurrency tests race real tasks over a real
//! database file; nothing here is mocked.

use std::sync::Arc;

use fleet_application::lab::{LeasePort as _, NewLease};
use fleet_application::lab_placement::{
    CapacityDemand, CapacityReservationPort as _, ImageStoragePort as _, PlacementPolicy,
    ReservationRequest, ReservationState, ReserveOutcome,
};
use fleet_application::proxmox::{ProxmoxNodeCapacity, ProxmoxStorageCapacity};
use fleet_core::CleanupStrategy;
use fleet_storage_sqlite::{CapacityRepository, LeaseRepository, Store};

const NOW: i64 = 1_800_000_000_000;
const GIB: u64 = 1 << 30;

async fn setup() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().expect("a temp directory");
    let store = Store::open(&dir.path().join("fleet.db"))
        .await
        .expect("the store must open");
    (dir, store)
}

async fn lease(leases: &LeaseRepository) -> String {
    leases
        .create(
            &NewLease {
                template_version_id: "template-version-1".to_owned(),
                purpose: "capacity".to_owned(),
                project_id: None,
                cleanup: CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            "tester",
            NOW,
        )
        .await
        .expect("the lease must be created")
        .id
}

/// A node with `memory_free_gib` free memory, 8 CPUs, and 500 GiB free on
/// `local-lvm`.
fn observation(memory_free_gib: u64, observed_at: i64) -> ProxmoxNodeCapacity {
    ProxmoxNodeCapacity {
        node: "pve1".to_owned(),
        cpu_usage_ratio: Some(0.1),
        cpu_count: Some(8),
        memory_used_bytes: Some((32 - memory_free_gib) * GIB),
        memory_total_bytes: Some(32 * GIB),
        storages: vec![ProxmoxStorageCapacity {
            storage: "local-lvm".to_owned(),
            used_bytes: 0,
            total_bytes: 500 * GIB,
        }],
        observed_at,
    }
}

fn request(lease_id: &str, memory_mib: u32) -> ReservationRequest {
    ReservationRequest {
        lease_id: lease_id.to_owned(),
        account_id: "account-1".to_owned(),
        node: "pve1".to_owned(),
        demand: CapacityDemand {
            cores: 1,
            memory_mib,
            disk_gib: 10,
            storage: "local-lvm".to_owned(),
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_leases_that_exceed_capacity_one_wins() {
    let (_dir, store) = setup().await;
    let leases = LeaseRepository::new(store.pool().clone());
    let capacity = Arc::new(CapacityRepository::new(store.pool().clone()));
    capacity
        .record_observation("account-1", &observation(6, NOW))
        .await
        .unwrap();
    let first = lease(&leases).await;
    let second = lease(&leases).await;
    // 6 GiB free; each lease wants 4 GiB: together they exceed it.
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let race = |lease_id: String| {
        let capacity = capacity.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            capacity
                .reserve(&request(&lease_id, 4096), &PlacementPolicy::default(), NOW)
                .await
                .expect("the reservation must not error")
        })
    };
    let (left, right) = tokio::join!(race(first), race(second));
    let outcomes = [left.unwrap(), right.unwrap()];
    let won = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, ReserveOutcome::Reserved(_)))
        .count();
    assert_eq!(won, 1, "{outcomes:?}");
    let refusal = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            ReserveOutcome::Refused(refusal) => Some(refusal.to_string()),
            ReserveOutcome::Reserved(_) => None,
        })
        .unwrap();
    assert_eq!(
        refusal,
        "insufficient memory on pve1: need 4096 MiB, 2048 free"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_leases_never_over_allocate() {
    let (_dir, store) = setup().await;
    let leases = LeaseRepository::new(store.pool().clone());
    let capacity = Arc::new(CapacityRepository::new(store.pool().clone()));
    capacity
        .record_observation("account-1", &observation(13, NOW))
        .await
        .unwrap();
    let mut ids = Vec::new();
    for _ in 0..8 {
        ids.push(lease(&leases).await);
    }
    // 13 GiB free, 4 GiB each: exactly three fit.
    let barrier = Arc::new(tokio::sync::Barrier::new(ids.len()));
    let tasks = ids
        .into_iter()
        .map(|lease_id| {
            let capacity = capacity.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                capacity
                    .reserve(&request(&lease_id, 4096), &PlacementPolicy::default(), NOW)
                    .await
                    .expect("the reservation must not error")
            })
        })
        .collect::<Vec<_>>();
    let mut won = 0;
    for task in tasks {
        if matches!(task.await.unwrap(), ReserveOutcome::Reserved(_)) {
            won += 1;
        }
    }
    assert_eq!(won, 3);
}

#[tokio::test]
async fn a_release_frees_capacity_and_is_final() {
    let (_dir, store) = setup().await;
    let leases = LeaseRepository::new(store.pool().clone());
    let capacity = CapacityRepository::new(store.pool().clone());
    capacity
        .record_observation("account-1", &observation(6, NOW))
        .await
        .unwrap();
    let first = lease(&leases).await;
    let second = lease(&leases).await;
    let policy = PlacementPolicy::default();

    let held = match capacity
        .reserve(&request(&first, 4096), &policy, NOW)
        .await
        .unwrap()
    {
        ReserveOutcome::Reserved(held) => held,
        ReserveOutcome::Refused(refusal) => panic!("{refusal}"),
    };
    // A resumed provision gets the same reservation back.
    assert_eq!(
        capacity
            .reserve(&request(&first, 4096), &policy, NOW)
            .await
            .unwrap(),
        ReserveOutcome::Reserved(held.clone())
    );
    assert!(matches!(
        capacity
            .reserve(&request(&second, 4096), &policy, NOW)
            .await
            .unwrap(),
        ReserveOutcome::Refused(_)
    ));

    assert!(capacity.release_for_lease(&first, NOW + 1).await.unwrap());
    // Releasing twice is a no-op.
    assert!(!capacity.release_for_lease(&first, NOW + 2).await.unwrap());
    let released = capacity.for_lease(&first).await.unwrap().unwrap();
    assert_eq!(released.state, ReservationState::Released);
    assert_eq!(released.released_at, Some(NOW + 1));
    // A finished lease never holds capacity again.
    assert!(
        capacity
            .reserve(&request(&first, 4096), &policy, NOW)
            .await
            .is_err()
    );
    // The freed capacity admits the other lease.
    assert!(matches!(
        capacity
            .reserve(&request(&second, 4096), &policy, NOW + 3)
            .await
            .unwrap(),
        ReserveOutcome::Reserved(_)
    ));
}

#[tokio::test]
async fn stale_or_missing_observations_refuse_without_writing() {
    let (_dir, store) = setup().await;
    let leases = LeaseRepository::new(store.pool().clone());
    let capacity = CapacityRepository::new(store.pool().clone());
    let id = lease(&leases).await;
    let policy = PlacementPolicy::default();

    let ReserveOutcome::Refused(missing) = capacity
        .reserve(&request(&id, 1024), &policy, NOW)
        .await
        .unwrap()
    else {
        panic!("a node without an observation must refuse");
    };
    assert_eq!(missing.reason(), "capacity_unknown");

    capacity
        .record_observation("account-1", &observation(16, NOW - 600_000))
        .await
        .unwrap();
    let ReserveOutcome::Refused(stale) = capacity
        .reserve(&request(&id, 1024), &policy, NOW)
        .await
        .unwrap()
    else {
        panic!("a stale observation must refuse");
    };
    assert_eq!(stale.reason(), "capacity_stale");
    assert!(capacity.for_lease(&id).await.unwrap().is_none());

    // An older observation never replaces a newer one.
    capacity
        .record_observation("account-1", &observation(16, NOW))
        .await
        .unwrap();
    capacity
        .record_observation("account-1", &observation(1, NOW - 900_000))
        .await
        .unwrap();
    assert!(matches!(
        capacity
            .reserve(&request(&id, 1024), &policy, NOW)
            .await
            .unwrap(),
        ReserveOutcome::Reserved(_)
    ));
}

#[tokio::test]
async fn an_out_of_range_observation_is_rejected_not_clamped() {
    let (_dir, store) = setup().await;
    let leases = LeaseRepository::new(store.pool().clone());
    let capacity = CapacityRepository::new(store.pool().clone());
    let id = lease(&leases).await;
    let mut oversized = observation(16, NOW);
    oversized.memory_total_bytes = Some(u64::MAX);
    let error = capacity
        .record_observation("account-1", &oversized)
        .await
        .expect_err("a figure SQLite cannot hold must be rejected");
    assert!(error.contains("total memory"), "{error}");
    // Nothing was stored, so placement still has no observation to trust.
    let ReserveOutcome::Refused(refusal) = capacity
        .reserve(&request(&id, 1024), &PlacementPolicy::default(), NOW)
        .await
        .unwrap()
    else {
        panic!("a rejected observation must not admit a reservation");
    };
    assert_eq!(refusal.reason(), "capacity_unknown");
}

#[tokio::test]
async fn the_schema_rejects_invalid_reservations() {
    let (_dir, store) = setup().await;
    let leases = LeaseRepository::new(store.pool().clone());
    let id = lease(&leases).await;
    let insert = |lease_id: &str, memory: i64, state: &str, released_at: Option<i64>| {
        sqlx::query(
            "INSERT INTO lab_capacity_reservations \
             (id, lease_id, account_id, node, storage, cores, memory_mib, disk_gib, state, created_at, released_at) \
             VALUES (?1, ?2, 'a', 'pve1', 'local-lvm', 1, ?3, 1, ?4, 0, ?5)",
        )
        .bind(uuid_like(lease_id, memory, state))
        .bind(lease_id.to_owned())
        .bind(memory)
        .bind(state.to_owned())
        .bind(released_at)
        .execute(store.pool())
    };
    assert!(insert(&id, 0, "held", None).await.is_err(), "zero memory");
    assert!(
        insert(&id, 1, "released", None).await.is_err(),
        "released without a time"
    );
    assert!(insert("no-such-lease", 1, "held", None).await.is_err());
    insert(&id, 1, "held", None).await.unwrap();
    assert!(
        insert(&id, 2, "held", None).await.is_err(),
        "one reservation per lease"
    );
}

fn uuid_like(lease_id: &str, memory: i64, state: &str) -> String {
    format!("{lease_id}-{memory}-{state}")
}

#[tokio::test]
async fn an_unknown_image_version_has_no_template_storage() {
    let (_dir, store) = setup().await;
    let capacity = CapacityRepository::new(store.pool().clone());
    assert_eq!(
        capacity.template_storage("no-such-version").await.unwrap(),
        None
    );
}

#[tokio::test]
async fn a_finished_leases_held_row_never_counts_even_without_its_release_write() {
    use fleet_core::LeaseState;
    let (_dir, store) = setup().await;
    let leases = LeaseRepository::new(store.pool().clone());
    let capacity = CapacityRepository::new(store.pool().clone());
    capacity
        .record_observation("account-1", &observation(6, NOW))
        .await
        .unwrap();
    let policy = PlacementPolicy::default();
    for finished in [LeaseState::Released, LeaseState::Failed] {
        let holder = lease(&leases).await;
        assert!(matches!(
            capacity
                .reserve(&request(&holder, 4096), &policy, NOW)
                .await
                .unwrap(),
            ReserveOutcome::Reserved(_)
        ));
        let next = lease(&leases).await;
        assert!(matches!(
            capacity
                .reserve(&request(&next, 4096), &policy, NOW)
                .await
                .unwrap(),
            ReserveOutcome::Refused(_)
        ));
        // The lease ends (released, or failed with no provision and so no
        // VMID) but its reservation row is never marked released.
        let mut ended = leases.get(&holder).await.unwrap();
        ended.state = finished;
        leases.update(&ended).await.unwrap();
        assert_eq!(
            capacity.for_lease(&holder).await.unwrap().unwrap().state,
            ReservationState::Held
        );
        assert!(
            matches!(
                capacity
                    .reserve(&request(&next, 4096), &policy, NOW)
                    .await
                    .unwrap(),
                ReserveOutcome::Reserved(_)
            ),
            "{finished:?}"
        );
        capacity.release_for_lease(&next, NOW).await.unwrap();
    }
}

#[tokio::test]
async fn a_failed_lease_whose_guest_was_allocated_still_counts() {
    use fleet_application::lab::{NewProvision, ProvisionPort as _};
    use fleet_core::LeaseState;
    let (_dir, store) = setup().await;
    let leases = LeaseRepository::new(store.pool().clone());
    let labs = fleet_storage_sqlite::LabRepository::new(store.pool().clone());
    let capacity = CapacityRepository::new(store.pool().clone());
    capacity
        .record_observation("account-1", &observation(6, NOW))
        .await
        .unwrap();
    let policy = PlacementPolicy::default();
    let holder = lease(&leases).await;
    let record = labs
        .create(
            &NewProvision {
                template_version_id: "template-version-1".to_owned(),
                lease_id: Some(holder.clone()),
                idempotency_key: None,
            },
            NOW,
        )
        .await
        .unwrap();
    leases.attach_provision(&holder, &record.id).await.unwrap();
    labs.reserve_clone_target(&record.id, "pve1", 9000)
        .await
        .unwrap();
    assert!(matches!(
        capacity
            .reserve(&request(&holder, 4096), &policy, NOW)
            .await
            .unwrap(),
        ReserveOutcome::Reserved(_)
    ));
    let mut failed = leases.get(&holder).await.unwrap();
    failed.state = LeaseState::Failed;
    leases.update(&failed).await.unwrap();
    // The guest may still exist: its capacity stays counted.
    let next = lease(&leases).await;
    assert!(matches!(
        capacity
            .reserve(&request(&next, 4096), &policy, NOW)
            .await
            .unwrap(),
        ReserveOutcome::Refused(_)
    ));
}
