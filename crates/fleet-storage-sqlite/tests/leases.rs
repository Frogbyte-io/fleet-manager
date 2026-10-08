//! Lab lease persistence, TTL extension, and the compare-and-set shared by
//! extension requests and expiry sweeps.

use fleet_application::lab::{
    AttachProvisionOutcome, LeasePort as _, NewLease, NewProvision, ProvisionPort as _,
};
use fleet_application::project::{NewProject, ProjectPort as _};
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
                readiness_deadline_at: Some(NOW + 600_000),
            },
            NOW,
        )
        .await
        .expect("the provision must be created");
    // The deadline is part of the insert (#360).
    assert_eq!(provision.readiness_deadline_at, Some(NOW + 600_000));
    assert_eq!(
        leases
            .attach_provision(&lease.id, &provision.id)
            .await
            .expect("the provision must attach"),
        AttachProvisionOutcome::Attached
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
                readiness_deadline_at: None,
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

#[tokio::test]
async fn leases_narrow_by_project_and_deleting_it_nulls_the_link() {
    let (_dir, store, leases) = setup().await;
    let projects = fleet_storage_sqlite::ProjectRepository::new(store.pool().clone());

    // The migration applies (opening the store ran it) and the stored
    // lease keeps the FK-constrained column.
    let project = projects
        .create(&NewProject {
            fetch: fleet_core::RemoteFetch::default(),
            remote: "https://github.com/example/linked.git".to_owned(),
            idempotency_key: None,
            name: "linked".to_owned(),
            description: String::new(),
        })
        .await
        .expect("the project must be registered");

    let with_project = leases
        .create(
            &NewLease {
                template_version_id: "template-1@digest".to_owned(),
                purpose: "the linked lease".to_owned(),
                project_id: Some(project.id.clone()),
                cleanup: CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            "operator",
            NOW,
        )
        .await
        .expect("the lease must store the project");
    assert_eq!(with_project.project_id, Some(project.id.clone()));
    let without_project = ready_lease(&leases, NOW + 1_000).await;
    assert_eq!(without_project.project_id, None);

    // The project filter narrows the list.
    let linked = leases
        .list(Some(&project.id))
        .await
        .expect("the project-filtered list must succeed");
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].id, with_project.id);
    let everything = leases
        .list(None)
        .await
        .expect("the unfiltered list must succeed");
    assert_eq!(everything.len(), 2);

    // Deleting the project nulls the lease's project reference instead of
    // deleting the lease.
    projects
        .delete(&project.id)
        .await
        .expect("the project must be deleted");
    let unlinked = leases
        .get(&with_project.id)
        .await
        .expect("the lease must survive the project deletion");
    assert_eq!(unlinked.project_id, None);
}

#[tokio::test]
async fn the_project_link_migration_tolerates_linked_provisions_and_orphans() {
    use sqlx::sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
    };

    let dir = tempfile::tempdir().expect("a temp directory");
    let path = dir.path().join("legacy.db");

    // Install the pre-migration schema (everything up to 0035) and seed it
    // exactly like a live controller would have had: a provision row linked
    // to a lease (0025's plain lease_id FK, no ON DELETE action) and one
    // lease pointing at a project that no longer exists (0022's project_id
    // was unconstrained).
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .expect("the legacy pool must connect");
    fleet_storage_sqlite::MIGRATOR
        .run_to(35, &pool)
        .await
        .expect("the legacy schema must install");
    sqlx::query(
        "INSERT INTO projects (id, remote, name, description, created_at, updated_at) \
         VALUES ('alive', 'https://github.com/example/alive.git', 'alive', '', 1, 1)",
    )
    .execute(&pool)
    .await
    .expect("the surviving project must exist");
    sqlx::query(
        "INSERT INTO lab_leases \
         (id, template_version_id, owner, purpose, project_id, state, cleanup, created_at, ttl_seconds) \
         VALUES ('lease-live', 'tv-1', 'tester', 'live', 'alive', 'ready', 'destroy', 1, 3600)",
    )
    .execute(&pool)
    .await
    .expect("the linked lease must exist");
    sqlx::query(
        "INSERT INTO lab_leases \
         (id, template_version_id, owner, purpose, project_id, state, cleanup, created_at, ttl_seconds) \
         VALUES ('lease-orphan', 'tv-1', 'tester', 'orphan', 'ghost', 'ready', 'destroy', 1, 3600)",
    )
    .execute(&pool)
    .await
    .expect("the orphaned lease must exist");
    sqlx::query(
        "INSERT INTO lab_provisions \
         (id, template_version_id, state, created_at, updated_at, lease_id) \
         VALUES ('p-1', 'tv-1', 'ready', 1, 1, 'lease-live')",
    )
    .execute(&pool)
    .await
    .expect("the linked provision must exist");
    pool.close().await;

    // The rebuild must survive both the referenced-parent drop and the
    // orphaned project id.
    let store = Store::open(&path)
        .await
        .expect("the migration must apply cleanly");
    let leases = LeaseRepository::new(store.pool().clone());
    let live = leases.get("lease-live").await.expect("the lease survived");
    assert_eq!(live.project_id, Some("alive".to_owned()));
    let orphan = leases
        .get("lease-orphan")
        .await
        .expect("the orphaned lease survived");
    assert_eq!(orphan.project_id, None);
    let provisions = fleet_storage_sqlite::LabRepository::new(store.pool().clone());
    let provision = provisions
        .get("p-1")
        .await
        .expect("the provision survived the parent-rename");
    assert_eq!(provision.lease_id, Some("lease-live".to_owned()));
    store.close().await;
}
