//! Lab lease persistence, TTL extension, and the compare-and-set shared by
//! extension requests and expiry sweeps.

use fleet_application::lab::{LeasePort as _, NewLease, NewProvision, ProvisionPort as _};
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
async fn an_older_lease_without_a_persisted_cap_uses_its_creation_deadline() {
    let (_dir, store, leases) = setup().await;
    let lease = ready_lease(&leases, NOW + 1_000).await;
    sqlx::query("UPDATE lab_leases SET max_lifetime_at = NULL WHERE id = ?1")
        .bind(&lease.id)
        .execute(store.pool())
        .await
        .unwrap();

    let loaded = leases.get(&lease.id).await.unwrap();
    assert_eq!(loaded.max_lifetime_at, NOW + MAX_LAB_LEASE_LIFETIME_MILLIS);
    assert!(
        !leases
            .extend_ready(
                &lease.id,
                NOW + 1_000,
                NOW + 500,
                loaded.max_lifetime_at + 1,
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn storage_extension_refuses_expired_nonready_or_over_cap_rows() {
    let (_dir, _store, leases) = setup().await;
    let old_expiry = NOW + 1_000;
    let mut lease = ready_lease(&leases, old_expiry).await;
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

    lease.state = LeaseState::Provisioning;
    leases.update(&lease).await.unwrap();
    assert!(
        !leases
            .extend_ready(&lease.id, old_expiry, NOW + 500, NOW + 2_000)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn provision_completion_marks_linked_lease_ready_and_starts_its_ttl() {
    let (_dir, store, leases) = setup().await;
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
    let provisions = fleet_storage_sqlite::LabRepository::new(store.pool().clone());
    let mut provision = provisions
        .create(
            &NewProvision {
                template_version_id: lease.template_version_id.clone(),
                lease_id: Some(lease.id.clone()),
                idempotency_key: Some("operator:lease-1".to_owned()),
            },
            NOW,
        )
        .await
        .expect("the provision must be created");
    assert!(
        leases
            .attach_provision(&lease.id, &provision.id)
            .await
            .expect("the provision must attach")
    );
    lease = leases.get(&lease.id).await.expect("the lease must reload");
    lease
        .mark_ready(NOW + 120)
        .expect("the lease must become ready");
    assert_eq!(lease.expires_at, Some(NOW + 3_600_120));
    provision.state = fleet_core::GuestState::Ready;
    provision.node = Some("pve-1".to_owned());
    provision.vmid = Some(123);
    provision.ready_at = lease.ready_at;
    provisions
        .complete_ready(&provision, lease.expires_at)
        .await
        .expect("the provision and lease must complete atomically");
    let mut stale_replay = provision.clone();
    stale_replay.ready_at = Some(NOW + 240);
    provisions
        .complete_ready(&stale_replay, Some(NOW + 3_600_240))
        .await
        .expect("a concurrent readiness replay must use the committed lease timestamp");
    let stored = leases.get(&lease.id).await.expect("the lease must reload");
    assert_eq!(stored.state, LeaseState::Ready);
    assert_eq!(stored.provision_id.as_deref(), Some(provision.id.as_str()));
    assert_eq!(stored.ready_at, Some(NOW + 120));
    assert_eq!(stored.expires_at, Some(NOW + 3_600_120));
    let stored_provision = provisions
        .get(&provision.id)
        .await
        .expect("the provision must reload");
    assert_eq!(stored_provision.state, fleet_core::GuestState::Ready);
    assert_eq!(stored_provision.node.as_deref(), Some("pve-1"));
    assert_eq!(stored_provision.vmid, Some(123));
    assert_eq!(stored_provision.ready_at, Some(NOW + 120));
}

#[tokio::test]
async fn readiness_transaction_rolls_back_when_lease_expiry_exceeds_its_cap() {
    let (_dir, store, leases) = setup().await;
    let lease = leases
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
    let provisions = fleet_storage_sqlite::LabRepository::new(store.pool().clone());
    let mut provision = provisions
        .create(
            &NewProvision {
                template_version_id: lease.template_version_id.clone(),
                lease_id: Some(lease.id.clone()),
                idempotency_key: None,
            },
            NOW,
        )
        .await
        .expect("the provision must be created");
    leases
        .attach_provision(&lease.id, &provision.id)
        .await
        .unwrap();
    provision.state = fleet_core::GuestState::Ready;
    provision.ready_at = Some(NOW + 120);
    let result = provisions
        .complete_ready(&provision, Some(lease.max_lifetime_at + 1))
        .await;
    assert!(result.is_err());
    assert_eq!(
        leases.get(&lease.id).await.unwrap().state,
        LeaseState::Provisioning
    );
    assert_eq!(
        provisions.get(&provision.id).await.unwrap().state,
        fleet_core::GuestState::Provisioning
    );
}
