//! The FM-609 task links (FM-234 follow-up): bounded retention by
//! `recorded_at`, and the lookup never naming an operation that is gone.

use fleet_application::operation::OperationPort as _;
use fleet_application::proxmox::tasks::ProxmoxTaskLinkPort as _;
use fleet_application::proxmox::{NewProxmoxAccount, ProxmoxAccountPort as _};
use fleet_storage_sqlite::proxmox_task_links::{TASK_LINK_PRUNE_BATCH, TASK_LINK_RETENTION_MILLIS};
use fleet_storage_sqlite::{
    OperationRepository, ProxmoxAccountRepository, ProxmoxTaskLinkRepository, Store,
};

const UPID_A: &str = "UPID:pve:0015523F:0C6DF532:6AAFE1EC:qmstart:101:root@pam:";
const UPID_B: &str = "UPID:pve:0015523F:0C6DF533:6AAFE1ED:qmstop:101:root@pam:";

struct Setup {
    _dir: tempfile::TempDir,
    store: Store,
    links: ProxmoxTaskLinkRepository,
    account_id: String,
    operation_id: String,
}

async fn setup() -> Setup {
    let dir = tempfile::tempdir().expect("a temp directory");
    let store = Store::open(&dir.path().join("fleet.db"))
        .await
        .expect("the store must open");
    let account = ProxmoxAccountRepository::new(store.pool().clone())
        .create(&NewProxmoxAccount {
            name: "pve-main".to_owned(),
            host: "pve.example.test".to_owned(),
            port: None,
            token_id: "fleet@pve!fleet".to_owned(),
        })
        .await
        .expect("the account must be created");
    let operation = OperationRepository::new(store.pool().clone())
        .create("proxmox.guest.start", None, None, None, None)
        .await
        .expect("the operation must be created");
    let links = ProxmoxTaskLinkRepository::new(store.pool().clone());
    Setup {
        _dir: dir,
        store,
        links,
        account_id: account.id,
        operation_id: operation.id,
    }
}

/// Backdates every link of `upid` to `recorded_at`.
async fn backdate(store: &Store, upid: &str, recorded_at: i64) {
    sqlx::query("UPDATE proxmox_task_links SET recorded_at = ?1 WHERE upid = ?2")
        .bind(recorded_at)
        .bind(upid)
        .execute(store.pool())
        .await
        .expect("the backdate must apply");
}

async fn link_count(store: &Store) -> i64 {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM proxmox_task_links")
        .fetch_one(store.pool())
        .await
        .expect("the count must read");
    count
}

#[tokio::test]
async fn pruning_removes_only_links_recorded_before_the_cutoff_in_bounded_batches() {
    let setup = setup().await;
    // Record everything first and backdate afterwards: `record` itself
    // prunes expired links, which would race this test's own fixtures.
    let old: Vec<String> = (0..5)
        .map(|index| format!("UPID:pve:00000001:00000002:0000000{index}:qmstart:101:root@pam:"))
        .collect();
    for upid in old.iter().map(String::as_str).chain([UPID_A]) {
        setup
            .links
            .record(&setup.account_id, upid, &setup.operation_id)
            .await
            .unwrap();
    }
    for (offset, upid) in (0_i64..).zip(&old) {
        backdate(&setup.store, upid, 1_000 + offset).await;
    }
    backdate(&setup.store, UPID_A, 10_000).await;

    // The batch bound holds: two of the five old links go, oldest first.
    let deleted = setup.links.prune_recorded_before(5_000, 2).await.unwrap();
    assert_eq!(deleted, 2);
    let (oldest,): (i64,) = sqlx::query_as("SELECT MIN(recorded_at) FROM proxmox_task_links")
        .fetch_one(setup.store.pool())
        .await
        .unwrap();
    assert_eq!(oldest, 1_002, "the oldest links are pruned first");

    // The rest of the old links go; the link after the cutoff stays.
    let deleted = setup.links.prune_recorded_before(5_000, 100).await.unwrap();
    assert_eq!(deleted, 3);
    assert_eq!(link_count(&setup.store).await, 1);
    let found = setup
        .links
        .operations_for(&setup.account_id, &[UPID_A.to_owned()])
        .await
        .unwrap();
    assert_eq!(found.get(UPID_A), Some(&setup.operation_id));

    // Nothing older than the cutoff is left.
    assert_eq!(
        setup.links.prune_recorded_before(5_000, 100).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn recording_a_link_prunes_expired_links_within_the_batch_bound() {
    let setup = setup().await;
    let total = TASK_LINK_PRUNE_BATCH + 3;
    for index in 0..total {
        let upid = format!("UPID:pve:00000001:00000002:{index:08X}:qmstart:101:root@pam:");
        setup
            .links
            .record(&setup.account_id, &upid, &setup.operation_id)
            .await
            .unwrap();
    }
    // Every link so far is far past the retention window.
    let expired = fleet_core::SystemClock::now_unix_millis() - TASK_LINK_RETENTION_MILLIS - 60_000;
    sqlx::query("UPDATE proxmox_task_links SET recorded_at = ?1")
        .bind(expired)
        .execute(setup.store.pool())
        .await
        .unwrap();
    assert_eq!(link_count(&setup.store).await, total);

    // One record removes at most one batch of expired links.
    setup
        .links
        .record(&setup.account_id, UPID_A, &setup.operation_id)
        .await
        .unwrap();
    assert_eq!(link_count(&setup.store).await, 3 + 1);

    // The next record removes the remainder; the fresh links stay.
    setup
        .links
        .record(&setup.account_id, UPID_B, &setup.operation_id)
        .await
        .unwrap();
    assert_eq!(link_count(&setup.store).await, 2);
    let found = setup
        .links
        .operations_for(&setup.account_id, &[UPID_A.to_owned(), UPID_B.to_owned()])
        .await
        .unwrap();
    assert_eq!(found.len(), 2, "{found:?}");
}

#[tokio::test]
async fn a_link_whose_operation_is_gone_stops_resolving() {
    let setup = setup().await;
    setup
        .links
        .record(&setup.account_id, UPID_A, "operation-that-does-not-exist")
        .await
        .unwrap();
    setup
        .links
        .record(&setup.account_id, UPID_B, &setup.operation_id)
        .await
        .unwrap();

    let found = setup
        .links
        .operations_for(&setup.account_id, &[UPID_A.to_owned(), UPID_B.to_owned()])
        .await
        .unwrap();
    assert_eq!(found.get(UPID_A), None, "a stale link must not resolve");
    assert_eq!(found.get(UPID_B), Some(&setup.operation_id));
}

#[tokio::test]
async fn the_retention_cleanup_is_served_by_the_recorded_at_index() {
    let setup = setup().await;
    let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
        "EXPLAIN QUERY PLAN SELECT rowid FROM proxmox_task_links \
         WHERE recorded_at < ?1 ORDER BY recorded_at LIMIT ?2",
    )
    .bind(1_000_i64)
    .bind(10_i64)
    .fetch_all(setup.store.pool())
    .await
    .unwrap();
    let detail: Vec<&str> = plan.iter().map(|row| row.3.as_str()).collect();
    assert!(
        detail
            .iter()
            .any(|step| step.contains("proxmox_task_links_recorded_at")),
        "{detail:?}"
    );
}
