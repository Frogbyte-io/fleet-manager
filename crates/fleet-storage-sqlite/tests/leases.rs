//! Lab lease persistence, TTL extension, and the compare-and-set shared by
//! extension requests and expiry sweeps.

use fleet_application::lab::{LeasePort, NewLease};
use fleet_core::{CleanupStrategy, LeaseState, MAX_LAB_LEASE_LIFETIME_MILLIS};
use fleet_storage_sqlite::{LeaseRepository, Store};

const NOW: i64 = 1_800_000_000_000;

async fn setup() -> (tempfile::TempDir, Store, LeaseRepository) {
    let dir = tempfile::tempdir().expect("a temp directory");
    let store = Store::open(&dir.path().join("fleet.db"))
        .await
        .expect("the store must open");
    let leases = LeaseRepository::new(store.pool().clone());
    (dir, store, leases)
}

async fn ready_lease(leases: &LeaseRepository, expires_at: i64) -> fleet_core::Lease {
    let mut lease = leases
        .create(
            &NewLease {
                template_version_id: "template-1@digest".to_owned(),
                purpose: "the test".to_owned(),
                project_id: None,
                cleanup: CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            "operator",
            NOW,
        )
        .await
        .expect("the lease must be created");
    lease.state = LeaseState::Ready;
    lease.ready_at = Some(NOW + 100);
    lease.expires_at = Some(expires_at);
    leases.update(&lease).await.expect("the lease must update");
    lease
}

#[tokio::test]
async fn extending_and_sweeping_compare_the_same_expiry_snapshot() {
    let (_dir, _store, leases) = setup().await;
    let old_expiry = NOW + 1_000;
    let lease = ready_lease(&leases, old_expiry).await;
    assert_eq!(lease.max_lifetime_at, NOW + MAX_LAB_LEASE_LIFETIME_MILLIS);

    // The sweep has read the old expired row. The extension then wins the
    // writer race using that row's expiry as its compare-and-set value.
    let sweep_now = old_expiry + 1;
    let sweep_snapshot = leases
        .expired(sweep_now)
        .await
        .expect("the expiry scan must succeed");
    assert_eq!(sweep_snapshot.len(), 1);
    assert_eq!(sweep_snapshot[0].expires_at, Some(old_expiry));
    let extended = leases
        .extend_ready(&lease.id, old_expiry, NOW + 500, NOW + 2_000)
        .await
        .expect("the extension write must run");
    assert!(extended);

    // The stale sweep snapshot must not release the now-extended lease.
    let stale_claim = leases
        .claim_for_release(&lease.id, LeaseState::Ready, old_expiry, sweep_now)
        .await
        .expect("the sweep compare-and-set must run");
    assert!(!stale_claim);

    // The extension deadline is now the observed deadline. Once it expires,
    // a sweep can claim it exactly once.
    let fresh_claim = leases
        .claim_for_release(&lease.id, LeaseState::Ready, NOW + 2_000, NOW + 2_000)
        .await
        .expect("the fresh sweep compare-and-set must run");
    assert!(fresh_claim);
    assert!(
        !leases
            .claim_for_release(&lease.id, LeaseState::Ready, NOW + 2_000, NOW + 2_000)
            .await
            .expect("the second sweep compare-and-set must run")
    );
}

#[tokio::test]
async fn storage_extension_refuses_expired_nonready_or_over_cap_rows() {
    let (_dir, _store, leases) = setup().await;
    let old_expiry = NOW + 1_000;
    let lease = ready_lease(&leases, old_expiry).await;
    assert!(
        !leases
            .extend_ready(&lease.id, old_expiry, old_expiry, NOW + 2_000)
            .await
            .unwrap()
    );
    assert!(
        !leases
            .extend_ready(&lease.id, old_expiry, NOW + 500, lease.max_lifetime_at + 1,)
            .await
            .unwrap()
    );
    assert!(
        !leases
            .extend_ready(&lease.id, old_expiry + 1, NOW + 500, NOW + 2_000)
            .await
            .unwrap()
    );
}
