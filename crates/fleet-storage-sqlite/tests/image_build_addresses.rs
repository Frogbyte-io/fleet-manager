//! #337: build addresses are allocated in one SQLite transaction. The
//! concurrency test races real tasks over a real database file.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use fleet_application::images::{BuildAddressError, BuildAddressPort as _};
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
    assert_eq!(repository.release("op-1", NOW + 1).await, Ok(1));
    assert_eq!(repository.release("op-1", NOW + 2).await, Ok(0));
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
    repository.release("op-2", NOW + 100).await.unwrap();
    repository.release("op-1", NOW + 200).await.unwrap();
    repository.release("op-3", NOW + 300).await.unwrap();
    operation(&store, "op-4", "running").await;
    assert_eq!(
        repository.allocate("op-4", &pool, 1, NOW + 400).await,
        Ok(vec![a(11)])
    );
}

#[tokio::test]
async fn a_holder_that_ended_without_releasing_is_reclaimed() {
    let (_dir, store, repository) = setup().await;
    let pool = pool(10);
    for (id, ended) in [
        ("failed", "failed"),
        ("cancelled", "cancelled"),
        ("timed_out", "timed_out"),
        ("succeeded", "succeeded"),
    ] {
        operation(&store, id, "running").await;
        assert_eq!(
            repository.allocate(id, &pool, 1, NOW).await,
            Ok(vec![a(10)]),
            "{id}"
        );
        // The controller died; the operation was failed by recovery.
        set_state(&store, id, ended).await;
        operation(&store, &format!("next-{id}"), "running").await;
        assert_eq!(
            repository
                .allocate(&format!("next-{id}"), &pool, 1, NOW + 1)
                .await,
            Ok(vec![a(10)]),
            "{id}: a terminal holder no longer counts"
        );
        repository
            .release(&format!("next-{id}"), NOW + 2)
            .await
            .unwrap();
    }
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
    assert_eq!(repository.release("live", NOW + 3).await, Ok(1));
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
