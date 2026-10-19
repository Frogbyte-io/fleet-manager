//! #337: build addresses are allocated in one SQLite transaction. The
//! concurrency test races real tasks over a real database file.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use fleet_application::images::{
    BUILD_ADDRESS_QUARANTINE_MILLIS, BuildAddressError, BuildAddressPort as _, BuildAddressStatus,
    ClearQuarantine,
};
use fleet_core::BuildAddressPool;
use fleet_storage_sqlite::{BuildAddressRepository, Store};

const NOW: i64 = 1_800_000_000_000;

fn pool(last: u8) -> BuildAddressPool {
    BuildAddressPool::parse(
        "192.0.2.0/24",
        &format!("192.0.2.10-192.0.2.{last}"),
        "192.0.2.1",
        None,
        false,
    )
    .expect("a valid pool")
}

fn a(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, last)
}

async fn setup() -> (tempfile::TempDir, Store, BuildAddressRepository) {
    let dir = tempfile::tempdir().expect("a temp directory");
    let store = Store::open(&dir.path().join("fleet.db"))
        .await
        .expect("the store must open");
    let repository = BuildAddressRepository::new(store.pool().clone());
    (dir, store, repository)
}

async fn operation(store: &Store, id: &str, state: &str) {
    sqlx::query(
        "INSERT INTO operations (id, kind, state, cancel_requested, created_at, updated_at) \
         VALUES (?1, 'image.build', ?2, 0, ?3, ?3)",
    )
    .bind(id)
    .bind(state)
    .bind(NOW)
    .execute(store.pool())
    .await
    .expect("an operation row");
}

async fn set_state(store: &Store, id: &str, state: &str) {
    sqlx::query("UPDATE operations SET state = ?2 WHERE id = ?1")
        .bind(id)
        .bind(state)
        .execute(store.pool())
        .await
        .expect("a state change");
}

#[tokio::test]
async fn an_address_is_held_by_one_operation_until_released() {
    let (_dir, store, repository) = setup().await;
    operation(&store, "op-1", "running").await;
    operation(&store, "op-2", "running").await;
    let pool = pool(11);
    assert_eq!(
        repository.allocate("op-1", &pool, 1, NOW).await,
        Ok(vec![a(10)])
    );
    // The same request again returns the same address.
    assert_eq!(
        repository.allocate("op-1", &pool, 1, NOW).await,
        Ok(vec![a(10)])
    );
    assert_eq!(
        repository.allocate("op-2", &pool, 1, NOW).await,
        Ok(vec![a(11)])
    );
    operation(&store, "op-3", "running").await;
    assert_eq!(
        repository.allocate("op-3", &pool, 1, NOW).await,
        Err(BuildAddressError::Exhausted)
    );
    assert_eq!(repository.release("op-1", NOW + 1, false).await, Ok(1));
    assert_eq!(repository.release("op-1", NOW + 2, false).await, Ok(0));
    assert_eq!(
        repository.allocate("op-3", &pool, 1, NOW + 3).await,
        Ok(vec![a(10)])
    );
}

#[tokio::test]
async fn an_exhausted_request_changes_nothing() {
    let (_dir, store, repository) = setup().await;
    operation(&store, "op-1", "running").await;
    operation(&store, "op-2", "running").await;
    let pool = pool(11);
    repository.allocate("op-1", &pool, 1, NOW).await.unwrap();
    // Two are needed, one is free: refused, and nothing is held for op-2.
    assert_eq!(
        repository.allocate("op-2", &pool, 2, NOW).await,
        Err(BuildAddressError::Exhausted)
    );
    assert_eq!(
        repository.allocate("op-2", &pool, 1, NOW).await,
        Ok(vec![a(11)])
    );
}

#[tokio::test]
async fn reuse_prefers_the_address_released_longest_ago() {
    let (_dir, store, repository) = setup().await;
    let pool = pool(12);
    for (id, at) in [("op-1", 10), ("op-2", 20), ("op-3", 30)] {
        operation(&store, id, "running").await;
        repository.allocate(id, &pool, 1, NOW + at).await.unwrap();
    }
    // Released in the order .11, .10, .12.
    repository.release("op-2", NOW + 100, false).await.unwrap();
    repository.release("op-1", NOW + 200, false).await.unwrap();
    repository.release("op-3", NOW + 300, false).await.unwrap();
    operation(&store, "op-4", "running").await;
    assert_eq!(
        repository.allocate("op-4", &pool, 1, NOW + 400).await,
        Ok(vec![a(11)])
    );
}

#[tokio::test]
async fn a_holder_that_ended_without_releasing_is_reclaimed_but_quarantined() {
    let (_dir, store, repository) = setup().await;
    let pool = pool(10);
    for (round, (id, ended)) in [
        ("failed", "failed"),
        ("cancelled", "cancelled"),
        ("timed_out", "timed_out"),
        ("succeeded", "succeeded"),
        ("blocked", "blocked_manual_approval"),
    ]
    .into_iter()
    .enumerate()
    {
        // Each round starts after the previous one's quarantine.
        let at = NOW + 3 * BUILD_ADDRESS_QUARANTINE_MILLIS * i64::try_from(round).unwrap();
        operation(&store, id, "running").await;
        assert_eq!(
            repository.allocate(id, &pool, 1, at).await,
            Ok(vec![a(10)]),
            "{id}"
        );
        // The controller died; the operation was failed by recovery. Its
        // VM may still be up on the address, so the address is not reused
        // for the quarantine, though the hold itself no longer counts.
        set_state(&store, id, ended).await;
        let next = format!("next-{id}");
        operation(&store, &next, "running").await;
        assert_eq!(
            repository.allocate(&next, &pool, 1, at + 1).await,
            Err(BuildAddressError::Exhausted),
            "{id}: quarantined"
        );
        let after = at + BUILD_ADDRESS_QUARANTINE_MILLIS + 1;
        assert_eq!(
            repository.allocate(&next, &pool, 1, after).await,
            Ok(vec![a(10)]),
            "{id}: free after the quarantine"
        );
        repository.release(&next, after + 1, false).await.unwrap();
    }
}

#[tokio::test]
async fn only_an_unverified_release_is_quarantined() {
    let (_dir, store, repository) = setup().await;
    let pool = pool(10);
    operation(&store, "clean", "running").await;
    repository.allocate("clean", &pool, 1, NOW).await.unwrap();
    assert_eq!(repository.release("clean", NOW + 1, false).await, Ok(1));
    operation(&store, "next", "running").await;
    assert_eq!(
        repository.allocate("next", &pool, 1, NOW + 2).await,
        Ok(vec![a(10)]),
        "a verified release is reusable at once"
    );
    // An unverified one is held out for the quarantine, then comes back.
    assert_eq!(repository.release("next", NOW + 3, true).await, Ok(1));
    operation(&store, "later", "running").await;
    assert_eq!(
        repository.allocate("later", &pool, 1, NOW + 4).await,
        Err(BuildAddressError::Exhausted)
    );
    assert_eq!(
        repository
            .allocate(
                "later",
                &pool,
                1,
                NOW + 3 + BUILD_ADDRESS_QUARANTINE_MILLIS + 1
            )
            .await,
        Ok(vec![a(10)])
    );
}

#[tokio::test]
async fn a_live_holder_keeps_its_address_across_pending_and_cancelling() {
    let (_dir, store, repository) = setup().await;
    let pool = pool(10);
    operation(&store, "op-1", "running").await;
    repository.allocate("op-1", &pool, 1, NOW).await.unwrap();
    for state in ["cancelling", "running", "pending"] {
        set_state(&store, "op-1", state).await;
        operation(&store, &format!("other-{state}"), "running").await;
        assert_eq!(
            repository
                .allocate(&format!("other-{state}"), &pool, 1, NOW)
                .await,
            Err(BuildAddressError::Exhausted),
            "{state}"
        );
    }
}

#[tokio::test]
async fn startup_reconciliation_releases_terminal_and_unknown_holders_only() {
    let (_dir, store, repository) = setup().await;
    let pool = pool(14);
    operation(&store, "live", "running").await;
    operation(&store, "dead", "running").await;
    operation(&store, "ghost", "running").await;
    for id in ["live", "dead", "ghost"] {
        repository.allocate(id, &pool, 1, NOW).await.unwrap();
    }
    set_state(&store, "dead", "failed").await;
    sqlx::query("DELETE FROM operations WHERE id = 'ghost'")
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(repository.reconcile(NOW + 1).await, Ok(2));
    assert_eq!(repository.reconcile(NOW + 2).await, Ok(0));
    assert_eq!(repository.release("live", NOW + 3, false).await, Ok(1));
}

#[tokio::test]
async fn a_changed_pool_moves_the_holder_into_the_new_range() {
    let (_dir, store, repository) = setup().await;
    operation(&store, "op-1", "running").await;
    repository
        .allocate("op-1", &pool(11), 1, NOW)
        .await
        .unwrap();
    let moved = BuildAddressPool::parse(
        "192.0.2.0/24",
        "192.0.2.50-192.0.2.51",
        "192.0.2.1",
        None,
        false,
    )
    .unwrap();
    assert_eq!(
        repository.allocate("op-1", &moved, 1, NOW).await,
        Ok(vec![a(50)])
    );
    // The address it let go of may host a guest from the earlier attempt.
    operation(&store, "op-2", "running").await;
    assert_eq!(
        repository.allocate("op-2", &pool(10), 1, NOW + 1).await,
        Err(BuildAddressError::Exhausted)
    );
}

#[tokio::test]
async fn racing_builds_never_share_an_address() {
    let (_dir, store, repository) = setup().await;
    let repository = Arc::new(repository);
    let pool = pool(17);
    for n in 0..16 {
        operation(&store, &format!("op-{n}"), "running").await;
    }
    let mut tasks = Vec::new();
    for n in 0..16 {
        let repository = repository.clone();
        let pool = pool.clone();
        tasks.push(tokio::spawn(async move {
            repository.allocate(&format!("op-{n}"), &pool, 1, NOW).await
        }));
    }
    let mut won = HashSet::new();
    let mut refused = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(addresses) => {
                assert!(won.insert(addresses[0]), "an address was handed out twice");
            }
            Err(BuildAddressError::Exhausted) => refused += 1,
            Err(other) => panic!("unexpected failure: {other}"),
        }
    }
    assert_eq!(won.len(), 8, "the pool holds eight addresses");
    assert_eq!(refused, 8);
}

#[tokio::test]
async fn an_operator_clears_a_quarantine_early_but_never_a_live_hold() {
    let (_dir, store, repository) = setup().await;
    let pool = pool(10);
    operation(&store, "op-1", "running").await;
    operation(&store, "op-2", "running").await;
    assert_eq!(
        repository.allocate("op-1", &pool, 1, NOW).await,
        Ok(vec![a(10)])
    );
    // Held by a live operation: listed, and not clearable.
    let listed = repository.list_unavailable(NOW + 1).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].address, a(10));
    assert_eq!(listed[0].status, BuildAddressStatus::Held);
    assert_eq!(listed[0].operation_id, "op-1");
    assert_eq!(listed[0].until, None);
    assert_eq!(
        repository.clear_quarantine(a(10), NOW + 2).await,
        Ok(ClearQuarantine::Held {
            operation_id: "op-1".to_owned()
        })
    );
    // An unverified end quarantines it.
    repository.release("op-1", NOW + 3, true).await.unwrap();
    assert_eq!(
        repository.allocate("op-2", &pool, 1, NOW + 4).await,
        Err(BuildAddressError::Exhausted)
    );
    let listed = repository.list_unavailable(NOW + 5).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].status, BuildAddressStatus::Quarantined);
    assert_eq!(
        listed[0].until,
        Some(NOW + 3 + BUILD_ADDRESS_QUARANTINE_MILLIS)
    );
    // A different address, or a repeat, has nothing to clear.
    assert_eq!(
        repository.clear_quarantine(a(11), NOW + 6).await,
        Ok(ClearQuarantine::NotQuarantined)
    );
    assert_eq!(
        repository.clear_quarantine(a(10), NOW + 7).await,
        Ok(ClearQuarantine::Cleared {
            operation_id: "op-1".to_owned()
        })
    );
    assert_eq!(
        repository.clear_quarantine(a(10), NOW + 8).await,
        Ok(ClearQuarantine::NotQuarantined)
    );
    assert!(
        repository
            .list_unavailable(NOW + 9)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        repository.allocate("op-2", &pool, 1, NOW + 10).await,
        Ok(vec![a(10)])
    );
}

#[tokio::test]
async fn a_dead_holders_address_can_be_cleared_in_one_step() {
    let (_dir, store, repository) = setup().await;
    let pool = pool(10);
    operation(&store, "op-1", "running").await;
    repository.allocate("op-1", &pool, 1, NOW).await.unwrap();
    set_state(&store, "op-1", "failed").await;
    // Still `held` on disk, but its operation is dead: clearing reclaims it
    // and ends the quarantine it would have got.
    // Listed as quarantined already, as reclaim would make it.
    let listed = repository.list_unavailable(NOW + 1).await.unwrap();
    assert_eq!(listed[0].status, BuildAddressStatus::Quarantined);
    assert_eq!(
        listed[0].until,
        Some(NOW + 1 + BUILD_ADDRESS_QUARANTINE_MILLIS)
    );
    assert_eq!(
        repository.clear_quarantine(a(10), NOW + 1).await,
        Ok(ClearQuarantine::Cleared {
            operation_id: "op-1".to_owned()
        })
    );
    assert!(
        repository
            .list_unavailable(NOW + 2)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_lapsed_quarantine_is_not_listed_or_clearable() {
    let (_dir, store, repository) = setup().await;
    let pool = pool(10);
    operation(&store, "op-1", "running").await;
    repository.allocate("op-1", &pool, 1, NOW).await.unwrap();
    repository.release("op-1", NOW + 1, true).await.unwrap();
    let after = NOW + 2 + BUILD_ADDRESS_QUARANTINE_MILLIS;
    assert!(repository.list_unavailable(after).await.unwrap().is_empty());
    assert_eq!(
        repository.clear_quarantine(a(10), after).await,
        Ok(ClearQuarantine::NotQuarantined)
    );
}
