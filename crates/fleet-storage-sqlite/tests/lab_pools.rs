//! FM-717: pool members are claimed exclusively in one SQLite transaction,
//! returned or quarantined together with the lease's release, and drained
//! without touching a member that still owes its lease's cleanup. The
//! concurrency test races real tasks over a real database file.

use std::collections::BTreeSet;
use std::sync::Arc;

use fleet_application::lab::{LeasePort as _, NewLease, NewProvision, ProvisionPort as _};
use fleet_application::lab_pool::{
    ClaimOutcome, FillResult, LabPoolPort as _, MemberRelease, MemberReleased, MemberState,
    NewLabPool, PoolStoreError,
};
use fleet_core::{CleanupStrategy, LeaseState};
use fleet_storage_sqlite::{LabPoolRepository, LabRepository, LeaseRepository, Store};

const NOW: i64 = 1_800_000_000_000;

struct World {
    _dir: tempfile::TempDir,
    pools: Arc<LabPoolRepository>,
    leases: Arc<LeaseRepository>,
    labs: Arc<LabRepository>,
    pool_id: String,
}

impl World {
    /// A pool of `vmids`, every member verified and available.
    async fn new(vmids: &[u32]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pools = Arc::new(LabPoolRepository::new(store.pool().clone()));
        let pool = pools
            .create(
                &NewLabPool {
                    template_version_id: "template-version-1".to_owned(),
                    account_id: "account-1".to_owned(),
                    baseline_snapshot: "baseline".to_owned(),
                    size: 16,
                },
                "tester",
                NOW,
            )
            .await
            .unwrap();
        let world = Self {
            _dir: dir,
            pools,
            leases: Arc::new(LeaseRepository::new(store.pool().clone())),
            labs: Arc::new(LabRepository::new(store.pool().clone())),
            pool_id: pool.id,
        };
        for member in world
            .pools
            .add_members(&world.pool_id, vmids, NOW)
            .await
            .unwrap()
        {
            world
                .pools
                .finish_fill(
                    &member.id,
                    &FillResult::Available {
                        node: "pve1".to_owned(),
                        name: format!("pool-{}", member.vmid),
                    },
                    NOW,
                )
                .await
                .unwrap();
        }
        world
    }

    /// A provisioning lease with its provision record attached.
    async fn provisioning(&self) -> (String, String) {
        let lease = self
            .leases
            .create(
                &NewLease {
                    template_version_id: "template-version-1".to_owned(),
                    purpose: "pool".to_owned(),
                    project_id: None,
                    cleanup: CleanupStrategy::Revert,
                    ttl_seconds: 3_600,
                },
                "tester",
                NOW,
            )
            .await
            .unwrap();
        let record = self
            .labs
            .create(
                &NewProvision {
                    template_version_id: "template-version-1".to_owned(),
                    lease_id: Some(lease.id.clone()),
                    idempotency_key: None,
                    readiness_deadline_at: None,
                },
                NOW,
            )
            .await
            .unwrap();
        self.leases
            .attach_provision(&lease.id, &record.id)
            .await
            .unwrap();
        (lease.id, record.id)
    }

    async fn releasing(&self, lease_id: &str) {
        let mut lease = self.leases.get(lease_id).await.unwrap();
        lease.state = LeaseState::Releasing;
        self.leases.update(&lease).await.unwrap();
    }

    async fn state(&self, vmid: u32) -> Option<(MemberState, Option<String>, bool)> {
        self.pools
            .member_by_vmid("account-1", vmid)
            .await
            .unwrap()
            .map(|member| (member.state, member.lease_id, member.draining))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_claims_never_share_a_member() {
    let world = Arc::new(World::new(&[200, 201, 202]).await);
    let mut leases = Vec::new();
    for _ in 0..8 {
        leases.push(world.provisioning().await);
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(leases.len()));
    let tasks = leases
        .into_iter()
        .map(|(lease_id, record_id)| {
            let world = world.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                let outcome = world
                    .pools
                    .claim(&world.pool_id, &lease_id, &record_id, NOW)
                    .await
                    .expect("a claim must not error");
                (lease_id, record_id, outcome)
            })
        })
        .collect::<Vec<_>>();
    let mut claimed = BTreeSet::new();
    let mut exhausted = 0;
    for task in tasks {
        let (lease_id, record_id, outcome) = task.await.unwrap();
        match outcome {
            ClaimOutcome::Claimed(member) => {
                assert_eq!(member.lease_id.as_deref(), Some(lease_id.as_str()));
                assert_eq!(member.state, MemberState::Leased);
                assert!(claimed.insert(member.vmid), "member {} shared", member.vmid);
                // The record names the member, written in the same transaction.
                let record = world.labs.get(&record_id).await.unwrap();
                assert_eq!(record.vmid, Some(member.vmid));
                assert_eq!(record.node.as_deref(), Some("pve1"));
                assert_eq!(record.account_id.as_deref(), Some("account-1"));
            }
            ClaimOutcome::Exhausted => {
                exhausted += 1;
            }
        }
    }
    assert_eq!(claimed, BTreeSet::from([200, 201, 202]));
    assert_eq!(exhausted, 5);
}

#[tokio::test]
async fn a_claim_resumes_with_the_bound_member_and_refuses_a_foreign_record() {
    let world = World::new(&[200, 201]).await;
    let (lease_id, record_id) = world.provisioning().await;
    let first = world
        .pools
        .claim(&world.pool_id, &lease_id, &record_id, NOW)
        .await
        .unwrap();
    let again = world
        .pools
        .claim(&world.pool_id, &lease_id, &record_id, NOW)
        .await
        .unwrap();
    assert_eq!(first, again, "a re-run gets the same member");
    // A record that is not the lease's own is refused.
    let (_other_lease, other_record) = world.provisioning().await;
    assert!(matches!(
        world
            .pools
            .claim(&world.pool_id, &lease_id, &other_record, NOW)
            .await,
        Err(PoolStoreError::Conflict(_))
    ));
    // A record that already took a clone target never takes a member.
    let (clone_lease, clone_record) = world.provisioning().await;
    world
        .labs
        .reserve_clone_target(&clone_record, "pve1", 9000)
        .await
        .unwrap();
    assert!(matches!(
        world
            .pools
            .claim(&world.pool_id, &clone_lease, &clone_record, NOW)
            .await,
        Err(PoolStoreError::Conflict(_))
    ));
}

#[tokio::test]
async fn filling_and_quarantined_members_are_never_claimed() {
    let world = World::new(&[]).await;
    let added = world
        .pools
        .add_members(&world.pool_id, &[300, 301], NOW)
        .await
        .unwrap();
    world
        .pools
        .finish_fill(
            &added[1].id,
            &FillResult::Quarantined {
                detail: "no snapshot named baseline".to_owned(),
            },
            NOW,
        )
        .await
        .unwrap();
    let (lease_id, record_id) = world.provisioning().await;
    assert_eq!(
        world
            .pools
            .claim(&world.pool_id, &lease_id, &record_id, NOW)
            .await
            .unwrap(),
        ClaimOutcome::Exhausted
    );
    // Nothing was written on an exhausted claim.
    assert_eq!(world.labs.get(&record_id).await.unwrap().vmid, None);
}

#[tokio::test]
async fn a_verified_revert_returns_the_member_with_the_release() {
    let world = World::new(&[200]).await;
    let (lease_id, record_id) = world.provisioning().await;
    world
        .pools
        .claim(&world.pool_id, &lease_id, &record_id, NOW)
        .await
        .unwrap();
    // Not yet releasing: the release is refused and nothing moves.
    assert!(matches!(
        world
            .pools
            .release_lease(&lease_id, &MemberRelease::Return, NOW)
            .await,
        Err(PoolStoreError::Conflict(_))
    ));
    world.releasing(&lease_id).await;
    assert_eq!(
        world
            .pools
            .release_lease(&lease_id, &MemberRelease::Return, NOW)
            .await
            .unwrap(),
        MemberReleased::Returned
    );
    assert_eq!(
        world.leases.get(&lease_id).await.unwrap().state,
        LeaseState::Released
    );
    assert_eq!(
        world.state(200).await,
        Some((MemberState::Available, None, false))
    );
    // The returned member serves the next lease.
    let (next, next_record) = world.provisioning().await;
    assert!(matches!(
        world
            .pools
            .claim(&world.pool_id, &next, &next_record, NOW)
            .await
            .unwrap(),
        ClaimOutcome::Claimed(member) if member.vmid == 200
    ));
}

#[tokio::test]
async fn a_failed_revert_quarantines_the_bound_member_and_keep_unbinds_it() {
    let world = World::new(&[200, 201]).await;
    let (lease_id, record_id) = world.provisioning().await;
    world
        .pools
        .claim(&world.pool_id, &lease_id, &record_id, NOW)
        .await
        .unwrap();
    world
        .pools
        .quarantine_bound(&lease_id, "the rollback task failed", NOW)
        .await
        .unwrap();
    assert_eq!(
        world.state(200).await,
        Some((MemberState::Quarantined, Some(lease_id.clone()), false)),
        "still bound: the lease's cleanup still owes the revert"
    );
    // A quarantined member is not offered to another lease.
    let (other, other_record) = world.provisioning().await;
    assert!(matches!(
        world.pools.claim(&world.pool_id, &other, &other_record, NOW).await.unwrap(),
        ClaimOutcome::Claimed(member) if member.vmid == 201
    ));
    // A later verified revert returns it.
    world.releasing(&lease_id).await;
    world
        .pools
        .release_lease(&lease_id, &MemberRelease::Return, NOW)
        .await
        .unwrap();
    assert_eq!(
        world.state(200).await,
        Some((MemberState::Available, None, false))
    );
    // Keep leaves the guest out of the pool.
    world.releasing(&other).await;
    assert_eq!(
        world
            .pools
            .release_lease(&other, &MemberRelease::Keep, NOW)
            .await
            .unwrap(),
        MemberReleased::Quarantined
    );
    assert_eq!(
        world.state(201).await,
        Some((MemberState::Quarantined, None, false))
    );
}

#[tokio::test]
async fn drain_removes_free_members_and_defers_bound_ones() {
    let world = World::new(&[200, 201, 202]).await;
    let (lease_id, record_id) = world.provisioning().await;
    world
        .pools
        .claim(&world.pool_id, &lease_id, &record_id, NOW)
        .await
        .unwrap();
    // An unknown VMID is refused and drains nothing.
    assert!(matches!(
        world
            .pools
            .drain(&world.pool_id, Some(&[201, 999]), NOW)
            .await,
        Err(PoolStoreError::NotFound(_))
    ));
    assert!(world.state(201).await.is_some());
    let report = world.pools.drain(&world.pool_id, None, NOW).await.unwrap();
    assert_eq!(report.removed, vec![201, 202]);
    assert_eq!(report.deferred, vec![200]);
    assert_eq!(
        world.state(200).await,
        Some((MemberState::Leased, Some(lease_id.clone()), true))
    );
    // The draining member leaves when its lease's cleanup returns it.
    world.releasing(&lease_id).await;
    assert_eq!(
        world
            .pools
            .release_lease(&lease_id, &MemberRelease::Return, NOW)
            .await
            .unwrap(),
        MemberReleased::Removed
    );
    assert_eq!(world.state(200).await, None);
    assert!(
        world
            .pools
            .members(&world.pool_id)
            .await
            .unwrap()
            .is_empty()
    );
    world.pools.delete(&world.pool_id).await.unwrap();
}

#[tokio::test]
async fn a_draining_filling_member_leaves_when_its_fill_ends() {
    let world = World::new(&[]).await;
    let added = world
        .pools
        .add_members(&world.pool_id, &[300], NOW)
        .await
        .unwrap();
    let report = world.pools.drain(&world.pool_id, None, NOW).await.unwrap();
    assert_eq!(report.deferred, vec![300]);
    world
        .pools
        .finish_fill(
            &added[0].id,
            &FillResult::Available {
                node: "pve1".to_owned(),
                name: "pool-300".to_owned(),
            },
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(world.state(300).await, None);
}

#[tokio::test]
async fn fills_respect_size_and_global_membership() {
    let world = World::new(&[200]).await;
    let small = world
        .pools
        .create(
            &NewLabPool {
                template_version_id: "template-version-2".to_owned(),
                account_id: "account-1".to_owned(),
                baseline_snapshot: "baseline".to_owned(),
                size: 1,
            },
            "tester",
            NOW,
        )
        .await
        .unwrap();
    // A guest belongs to one pool only.
    assert!(matches!(
        world.pools.add_members(&small.id, &[200], NOW).await,
        Err(PoolStoreError::Conflict(_))
    ));
    world
        .pools
        .add_members(&small.id, &[400], NOW)
        .await
        .unwrap();
    assert!(matches!(
        world.pools.add_members(&small.id, &[401], NOW).await,
        Err(PoolStoreError::Conflict(_))
    ));
    // One pool per template version.
    assert!(matches!(
        world
            .pools
            .create(
                &NewLabPool {
                    template_version_id: "template-version-2".to_owned(),
                    account_id: "account-1".to_owned(),
                    baseline_snapshot: "baseline".to_owned(),
                    size: 1,
                },
                "tester",
                NOW,
            )
            .await,
        Err(PoolStoreError::Conflict(_))
    ));
    // A pool with members is not deleted.
    assert!(matches!(
        world.pools.delete(&small.id).await,
        Err(PoolStoreError::Conflict(_))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drain_racing_claims_never_leaves_a_member_bound_and_removed() {
    let world = Arc::new(World::new(&[200, 201, 202, 203]).await);
    let mut leases = Vec::new();
    for _ in 0..4 {
        leases.push(world.provisioning().await);
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(leases.len() + 1));
    let mut tasks = Vec::new();
    for (lease_id, record_id) in leases {
        let world = world.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let outcome = world
                .pools
                .claim(&world.pool_id, &lease_id, &record_id, NOW)
                .await
                .unwrap();
            (lease_id, outcome)
        }));
    }
    let drain = {
        let world = world.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            world.pools.drain(&world.pool_id, None, NOW).await.unwrap()
        })
    };
    let mut claimed = BTreeSet::new();
    for task in tasks {
        let (lease_id, outcome) = task.await.unwrap();
        if let ClaimOutcome::Claimed(member) = outcome {
            assert_eq!(member.lease_id.as_deref(), Some(lease_id.as_str()));
            claimed.insert(member.vmid);
        }
    }
    let report = drain.await.unwrap();
    // Every member a lease won is deferred, never removed; every other one
    // was removed; nothing is both.
    let removed: BTreeSet<u32> = report.removed.iter().copied().collect();
    let deferred: BTreeSet<u32> = report.deferred.iter().copied().collect();
    assert!(removed.is_disjoint(&claimed), "{removed:?} {claimed:?}");
    assert_eq!(deferred, claimed);
    assert_eq!(
        removed.union(&deferred).copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([200, 201, 202, 203])
    );
    for vmid in &claimed {
        let (state, lease, draining) = world.state(*vmid).await.unwrap();
        assert_eq!(state, MemberState::Leased);
        assert!(lease.is_some() && draining);
    }
}

#[tokio::test]
async fn a_quarantined_member_never_resumes_a_claim() {
    let world = World::new(&[200]).await;
    let (lease_id, record_id) = world.provisioning().await;
    world
        .pools
        .claim(&world.pool_id, &lease_id, &record_id, NOW)
        .await
        .unwrap();
    world
        .pools
        .quarantine_bound(&lease_id, "the rollback task failed", NOW)
        .await
        .unwrap();
    assert!(matches!(
        world
            .pools
            .claim(&world.pool_id, &lease_id, &record_id, NOW)
            .await,
        Err(PoolStoreError::Conflict(_))
    ));
}
