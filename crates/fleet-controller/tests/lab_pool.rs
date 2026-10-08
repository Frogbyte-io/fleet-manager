//! FM-717 (#260): pooled Lab guests. `lab.cleanup` reverts a pooled lease's
//! member through the reviewed snapshot-revert child, verifies it, and
//! returns it to the pool with the lease's release; a failed revert
//! quarantines the member instead. `lab.pool.fill` verifies and reverts new
//! members before any lease can take one. Real SQLite repositories and
//! operations; the revert child runs through a scripted executor standing
//! in for FM-603's reviewed revert, and the cluster reads are scripted.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::lab::{
    LeasePort, MAX_CLEANUP_ATTEMPTS, NewLease, NewProvision, ProvisionPort, cleanup_operation,
};
use fleet_application::lab_pool::{
    ClaimOutcome, FillResult, GuestObservation, LabPoolPort, MemberState, NewLabPool,
    PoolGuestPort, RevertedConfig, fill_operation,
};
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_controller::lab_cleanup::LabCleanupExecutor;
use fleet_controller::lab_pool::LabPoolFillExecutor;
use fleet_core::{CleanupStrategy, LeaseState};
use fleet_storage_sqlite::{
    AuditSink, LabPoolRepository, LabRepository, LeaseRepository, MachineRepository,
    OperationRepository, Store,
};

/// The scripted reviewed-child executor: records the children it ran and
/// ends them as told.
#[derive(Debug, Default)]
struct Scripted {
    fail: Mutex<bool>,
    ran: Mutex<Vec<(String, serde_json::Value)>>,
}

impl Scripted {
    fn kinds(&self) -> Vec<String> {
        self.ran
            .lock()
            .unwrap()
            .iter()
            .map(|(kind, _)| kind.clone())
            .collect()
    }
}

#[async_trait]
impl OperationExecutor for Scripted {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        self.ran.lock().unwrap().push((
            operation.kind.clone(),
            serde_json::from_str(operation.payload_json.as_deref().unwrap_or("null")).unwrap(),
        ));
        let (state, error) = if *self.fail.lock().unwrap() {
            ("failed", Some(r#"{"reason":"task_error"}"#))
        } else {
            ("succeeded", None)
        };
        operations
            .complete(&operation.id, state, Some("{}"), error)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// The scripted cluster: one observation per VMID and the config every
/// guest reads back after a revert.
#[derive(Debug)]
struct Cluster {
    guests: Mutex<BTreeMap<u32, GuestObservation>>,
    config: Mutex<RevertedConfig>,
    /// Whether every read fails, as an unreachable cluster does.
    unreachable: Mutex<bool>,
}

impl Cluster {
    fn new(vmids: &[u32]) -> Arc<Self> {
        Arc::new(Self {
            guests: Mutex::new(
                vmids
                    .iter()
                    .map(|vmid| (*vmid, Self::guest(&format!("pool-{vmid}"))))
                    .collect(),
            ),
            config: Mutex::new(RevertedConfig {
                template: false,
                lock: None,
                parent: Some("baseline".to_owned()),
            }),
            unreachable: Mutex::new(false),
        })
    }

    fn guest(name: &str) -> GuestObservation {
        GuestObservation {
            kind: Some("qemu".to_owned()),
            node: Some("pve-b".to_owned()),
            name: Some(name.to_owned()),
            baseline_present: true,
            protected_artifact: false,
        }
    }

    fn set(&self, vmid: u32, observation: GuestObservation) {
        self.guests.lock().unwrap().insert(vmid, observation);
    }
}

#[async_trait]
impl PoolGuestPort for Cluster {
    async fn observe(
        &self,
        _account_id: &str,
        vmid: u32,
        _baseline: &str,
    ) -> Result<GuestObservation, String> {
        if *self.unreachable.lock().unwrap() {
            return Err("the resource listing failed: unreachable".to_owned());
        }
        Ok(self
            .guests
            .lock()
            .unwrap()
            .get(&vmid)
            .cloned()
            .unwrap_or_default())
    }

    async fn reverted_config(
        &self,
        _account_id: &str,
        _node: &str,
        _vmid: u32,
    ) -> Result<RevertedConfig, String> {
        Ok(self.config.lock().unwrap().clone())
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    labs: Arc<LabRepository>,
    leases: Arc<LeaseRepository>,
    pools: Arc<LabPoolRepository>,
    operations: Arc<Operations>,
    cluster: Arc<Cluster>,
    reverter: Arc<Scripted>,
    destroyer: Arc<Scripted>,
    pool_id: String,
}

impl Harness {
    /// A pool over `vmids`, every member verified and available.
    async fn new(vmids: &[u32]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        let pools = Arc::new(LabPoolRepository::new(pool.clone()));
        let now = fleet_core::SystemClock::now_unix_millis();
        let created = pools
            .create(
                &NewLabPool {
                    template_version_id: "template-version-1".to_owned(),
                    account_id: "account-1".to_owned(),
                    baseline_snapshot: "baseline".to_owned(),
                    size: 8,
                },
                "tester",
                now,
            )
            .await
            .unwrap();
        for member in pools.add_members(&created.id, vmids, now).await.unwrap() {
            pools
                .finish_fill(
                    &member.id,
                    &FillResult::Available {
                        node: "pve-b".to_owned(),
                        name: format!("pool-{}", member.vmid),
                    },
                    now,
                )
                .await
                .unwrap();
        }
        Self {
            _dir: dir,
            labs: Arc::new(LabRepository::new(pool.clone())),
            leases: Arc::new(LeaseRepository::new(pool.clone())),
            pools,
            operations: Arc::new(Operations::new(
                Arc::new(OperationRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )),
            cluster: Cluster::new(vmids),
            reverter: Arc::new(Scripted::default()),
            destroyer: Arc::new(Scripted::default()),
            pool_id: created.id,
            pool,
        }
    }

    /// A lease that claimed a member of the pool, now releasing with
    /// `cleanup`. Answers the lease and the member's VMID.
    async fn pooled_releasing(&self, cleanup: CleanupStrategy) -> (String, u32) {
        let now = fleet_core::SystemClock::now_unix_millis();
        let lease = self
            .leases
            .create(
                &NewLease {
                    template_version_id: "template-version-1".to_owned(),
                    purpose: "pool".to_owned(),
                    project_id: None,
                    cleanup,
                    ttl_seconds: 3_600,
                },
                "tester",
                now,
            )
            .await
            .unwrap();
        let record = ProvisionPort::create(
            self.labs.as_ref(),
            &NewProvision {
                template_version_id: "template-version-1".to_owned(),
                lease_id: Some(lease.id.clone()),
                idempotency_key: None,
                readiness_deadline_at: None,
            },
            now,
        )
        .await
        .unwrap();
        self.leases
            .attach_provision(&lease.id, &record.id)
            .await
            .unwrap();
        let ClaimOutcome::Claimed(member) = self
            .pools
            .claim(&self.pool_id, &lease.id, &record.id, now)
            .await
            .unwrap()
        else {
            panic!("the pool must have a free member");
        };
        let mut releasing = self.leases.get(&lease.id).await.unwrap();
        releasing.state = LeaseState::Releasing;
        self.leases.update(&releasing).await.unwrap();
        (lease.id, member.vmid)
    }

    fn executor(&self) -> LabCleanupExecutor {
        LabCleanupExecutor::new(
            self.leases.clone(),
            self.labs.clone(),
            Arc::new(MachineRepository::new(self.pool.clone())),
            Arc::new(AuditSink::new(self.pool.clone())),
            self.destroyer.clone(),
        )
        .with_pools(
            self.pools.clone(),
            self.cluster.clone(),
            self.reverter.clone(),
        )
    }

    /// Queues and runs one cleanup attempt; answers the operation's final
    /// state, its error reason, and the lease.
    async fn run(&self, lease_id: &str) -> (String, String, fleet_core::Lease) {
        let lease = self.leases.get(lease_id).await.unwrap();
        let operation = self
            .operations
            .create_lab_cleanup(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                lease_id,
                &cleanup_operation(&lease, None),
            )
            .await
            .unwrap();
        self.operations
            .claim_only_execute(&self.executor(), &operation.id, "test")
            .await
            .unwrap();
        let done = self.operation(&operation.id).await;
        let reason = done
            .error_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
            .and_then(|error| error["reason"].as_str().map(str::to_owned))
            .unwrap_or_default();
        (done.state, reason, self.leases.get(lease_id).await.unwrap())
    }

    async fn operation(&self, id: &str) -> Operation {
        self.operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                id,
            )
            .await
            .unwrap()
    }

    async fn member(&self, vmid: u32) -> Option<(MemberState, Option<String>)> {
        self.pools
            .member_by_vmid("account-1", vmid)
            .await
            .unwrap()
            .map(|member| (member.state, member.lease_id))
    }

    /// What the provision read model reports for the lease's guest (#327):
    /// the claimed record must carry the shape that marks it pooled.
    async fn fate(&self, lease_id: &str) -> &'static str {
        let lease = self.leases.get(lease_id).await.unwrap();
        let record = ProvisionPort::get(self.labs.as_ref(), lease.provision_id.as_deref().unwrap())
            .await
            .unwrap();
        assert!(
            fleet_application::lab::may_be_pooled(&record),
            "a claimed record names the member's account and VMID and never cloned: {record:?}"
        );
        let member = self
            .pools
            .member_by_vmid(record.account_id.as_deref().unwrap(), record.vmid.unwrap())
            .await
            .unwrap();
        fleet_application::lab::provision_guest(&record, Some(&lease), member.as_ref()).id()
    }

    async fn audit_events(&self, event: &str) -> usize {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE metadata_json LIKE ?1")
                .bind(format!("%\"{event}\"%"))
                .fetch_one(&self.pool)
                .await
                .unwrap();
        usize::try_from(count).unwrap()
    }
}

#[tokio::test]
async fn a_verified_revert_returns_the_member_and_releases_the_lease() {
    let harness = Harness::new(&[200]).await;
    let (lease, vmid) = harness.pooled_releasing(CleanupStrategy::Revert).await;
    let (state, _, after) = harness.run(&lease).await;
    assert_eq!(state, "succeeded");
    assert_eq!(after.state, LeaseState::Released);
    assert_eq!(
        harness.member(vmid).await,
        Some((MemberState::Available, None))
    );
    // One reviewed revert child, to the baseline, and no destroy.
    let ran = harness.reverter.ran.lock().unwrap().clone();
    assert_eq!(ran.len(), 1);
    assert_eq!(ran[0].0, "proxmox.guest.snapshot-revert");
    assert_eq!(ran[0].1["vmid"], vmid);
    assert_eq!(ran[0].1["node"], "pve-b");
    assert_eq!(ran[0].1["accountId"], "account-1");
    assert_eq!(ran[0].1["params"]["snapshot"], "baseline");
    assert!(harness.destroyer.ran.lock().unwrap().is_empty());
    assert_eq!(harness.audit_events("lab_pool_member_returned").await, 1);
    assert_eq!(harness.audit_events("lab_lease_released").await, 1);
    assert_eq!(harness.fate(&lease).await, "returned_to_pool");
}

#[tokio::test]
async fn a_failed_revert_quarantines_the_member_until_a_retry_succeeds() {
    let harness = Harness::new(&[200, 201]).await;
    let (lease, vmid) = harness.pooled_releasing(CleanupStrategy::Revert).await;
    *harness.reverter.fail.lock().unwrap() = true;
    let (state, reason, after) = harness.run(&lease).await;
    assert_eq!(
        (state.as_str(), reason.as_str()),
        ("failed", "cleanup_retry")
    );
    assert_eq!(after.state, LeaseState::Releasing);
    assert_eq!(after.cleanup_attempts, 1);
    assert_eq!(
        harness.member(vmid).await,
        Some((MemberState::Quarantined, Some(lease.clone()))),
        "never returned unverified; still owed by its lease"
    );
    assert_eq!(harness.audit_events("lab_pool_member_quarantined").await, 1);
    // A quarantined member is never offered to the next lease.
    let (next, next_vmid) = harness.pooled_releasing(CleanupStrategy::Revert).await;
    assert_ne!(next_vmid, vmid);
    // Once the cause is fixed, the next attempt returns it.
    *harness.reverter.fail.lock().unwrap() = false;
    let (state, _, after) = harness.run(&lease).await;
    assert_eq!(state, "succeeded");
    assert_eq!(after.state, LeaseState::Released);
    assert_eq!(
        harness.member(vmid).await,
        Some((MemberState::Available, None))
    );
    let (state, _, _) = harness.run(&next).await;
    assert_eq!(state, "succeeded");
}

#[tokio::test]
async fn an_unverified_revert_quarantines_and_exhausts_into_cleanup_failed() {
    let harness = Harness::new(&[200]).await;
    let (lease, vmid) = harness.pooled_releasing(CleanupStrategy::Revert).await;
    // The rollback "succeeds" but leaves the guest elsewhere.
    harness.cluster.config.lock().unwrap().parent = Some("other".to_owned());
    let mut last = None;
    for _ in 0..MAX_CLEANUP_ATTEMPTS {
        last = Some(harness.run(&lease).await);
    }
    let (state, reason, after) = last.unwrap();
    assert_eq!(
        (state.as_str(), reason.as_str()),
        ("failed", "cleanup_failed")
    );
    assert_eq!(after.state, LeaseState::CleanupFailed);
    assert_eq!(
        harness.member(vmid).await,
        Some((MemberState::Quarantined, Some(lease.clone())))
    );
    assert_eq!(harness.audit_events("lab_lease_cleanup_failed").await, 1);
}

#[tokio::test]
async fn a_replaced_guest_is_never_reverted() {
    let harness = Harness::new(&[200]).await;
    let (lease, vmid) = harness.pooled_releasing(CleanupStrategy::Revert).await;
    // Someone else's guest now holds the VMID.
    harness.cluster.set(vmid, Cluster::guest("someone-else"));
    let (state, reason, _) = harness.run(&lease).await;
    assert_eq!(
        (state.as_str(), reason.as_str()),
        ("failed", "cleanup_retry")
    );
    assert!(harness.reverter.ran.lock().unwrap().is_empty());
    assert_eq!(
        harness.member(vmid).await,
        Some((MemberState::Quarantined, Some(lease)))
    );
}

#[tokio::test]
async fn a_pooled_lease_that_says_destroy_reverts_and_never_destroys() {
    let harness = Harness::new(&[200]).await;
    let (lease, vmid) = harness.pooled_releasing(CleanupStrategy::Destroy).await;
    let (state, _, after) = harness.run(&lease).await;
    assert_eq!(state, "succeeded");
    assert_eq!(after.state, LeaseState::Released);
    assert!(harness.destroyer.ran.lock().unwrap().is_empty());
    assert_eq!(
        harness.reverter.kinds(),
        vec!["proxmox.guest.snapshot-revert"]
    );
    assert_eq!(
        harness.member(vmid).await,
        Some((MemberState::Available, None))
    );
    // Recorded `destroy`, but the member went back to its pool.
    assert_eq!(harness.fate(&lease).await, "returned_to_pool");
}

#[tokio::test]
async fn a_clone_lease_naming_a_pool_member_is_never_destroyed() {
    let harness = Harness::new(&[200]).await;
    // A clone lease whose record (wrongly) names the member's VMID.
    let now = fleet_core::SystemClock::now_unix_millis();
    let lease = harness
        .leases
        .create(
            &NewLease {
                template_version_id: "template-version-2".to_owned(),
                purpose: "clone".to_owned(),
                project_id: None,
                cleanup: CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            "tester",
            now,
        )
        .await
        .unwrap();
    let mut record = ProvisionPort::create(
        harness.labs.as_ref(),
        &NewProvision {
            template_version_id: "template-version-2".to_owned(),
            lease_id: Some(lease.id.clone()),
            idempotency_key: None,
            readiness_deadline_at: None,
        },
        now,
    )
    .await
    .unwrap();
    harness
        .leases
        .attach_provision(&lease.id, &record.id)
        .await
        .unwrap();
    record.node = Some("pve-b".to_owned());
    record.vmid = Some(200);
    record.account_id = Some("account-1".to_owned());
    ProvisionPort::update(harness.labs.as_ref(), &record)
        .await
        .unwrap();
    let mut releasing = harness.leases.get(&lease.id).await.unwrap();
    releasing.state = LeaseState::Releasing;
    harness.leases.update(&releasing).await.unwrap();
    let (state, reason, after) = harness.run(&lease.id).await;
    assert_eq!(
        (state.as_str(), reason.as_str()),
        ("failed", "cleanup_retry")
    );
    assert_eq!(after.state, LeaseState::Releasing);
    assert!(harness.destroyer.ran.lock().unwrap().is_empty());
    assert_eq!(
        harness.member(200).await,
        Some((MemberState::Available, None))
    );
}

#[tokio::test]
async fn keep_releases_the_lease_and_takes_the_member_out_of_rotation() {
    let harness = Harness::new(&[200]).await;
    let (lease, vmid) = harness.pooled_releasing(CleanupStrategy::Keep).await;
    let (state, _, after) = harness.run(&lease).await;
    assert_eq!(state, "succeeded");
    assert_eq!(after.state, LeaseState::Released);
    assert!(harness.reverter.ran.lock().unwrap().is_empty());
    assert!(harness.destroyer.ran.lock().unwrap().is_empty());
    assert_eq!(
        harness.member(vmid).await,
        Some((MemberState::Quarantined, None))
    );
    assert_eq!(harness.fate(&lease).await, "quarantined_in_pool");
}

#[tokio::test]
async fn a_draining_member_leaves_the_pool_after_its_revert() {
    let harness = Harness::new(&[200]).await;
    let (lease, vmid) = harness.pooled_releasing(CleanupStrategy::Revert).await;
    let report = harness
        .pools
        .drain(
            &harness.pool_id,
            None,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .unwrap();
    assert_eq!(report.deferred, vec![vmid]);
    let (state, _, after) = harness.run(&lease).await;
    assert_eq!(state, "succeeded");
    assert_eq!(after.state, LeaseState::Released);
    assert_eq!(harness.member(vmid).await, None);
    assert_eq!(harness.audit_events("lab_pool_member_removed").await, 1);
}

#[tokio::test]
async fn fill_verifies_and_reverts_each_member_or_quarantines_it() {
    let harness = Harness::new(&[]).await;
    let now = fleet_core::SystemClock::now_unix_millis();
    harness
        .pools
        .add_members(&harness.pool_id, &[300, 301, 302, 303], now)
        .await
        .unwrap();
    harness.cluster.set(300, Cluster::guest("pool-a"));
    harness.cluster.set(
        301,
        GuestObservation {
            baseline_present: false,
            ..Cluster::guest("pool-b")
        },
    );
    harness.cluster.set(302, Cluster::guest("fm-lab-record"));
    harness.cluster.set(
        303,
        GuestObservation {
            kind: Some("qemu-template".to_owned()),
            ..Cluster::guest("a-template")
        },
    );
    let operation = harness
        .operations
        .create_lab_pool_fill(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &harness.pool_id,
            &fill_operation(&harness.pool_id, None),
        )
        .await
        .unwrap();
    let fill = LabPoolFillExecutor::new(
        harness.pools.clone(),
        harness.cluster.clone(),
        harness.reverter.clone(),
        Arc::new(AuditSink::new(harness.pool.clone())),
    );
    harness
        .operations
        .claim_only_execute(&fill, &operation.id, "test")
        .await
        .unwrap();
    let done = harness.operation(&operation.id).await;
    assert_eq!(done.state, "succeeded");
    let result: serde_json::Value =
        serde_json::from_str(done.result_json.as_deref().unwrap()).unwrap();
    assert_eq!(result["available"], serde_json::json!([300]));
    assert_eq!(result["quarantined"], serde_json::json!([301, 302, 303]));
    // Only the verified guest was reverted.
    let ran = harness.reverter.ran.lock().unwrap().clone();
    assert_eq!(ran.len(), 1);
    assert_eq!(ran[0].1["vmid"], 300);
    let members = harness.pools.members(&harness.pool_id).await.unwrap();
    let available = members.iter().find(|member| member.vmid == 300).unwrap();
    assert_eq!(available.state, MemberState::Available);
    assert_eq!(available.name.as_deref(), Some("pool-a"));
    assert_eq!(available.node.as_deref(), Some("pve-b"));
    for member in members.iter().filter(|member| member.vmid != 300) {
        assert_eq!(member.state, MemberState::Quarantined, "{member:?}");
        assert!(member.detail.is_some());
    }
    assert_eq!(harness.audit_events("lab_pool_member_available").await, 1);
    assert_eq!(harness.audit_events("lab_pool_member_quarantined").await, 3);
}

#[tokio::test]
async fn a_failed_fill_revert_quarantines_and_the_generic_route_refuses_the_kind() {
    let harness = Harness::new(&[]).await;
    let now = fleet_core::SystemClock::now_unix_millis();
    harness
        .pools
        .add_members(&harness.pool_id, &[300], now)
        .await
        .unwrap();
    harness.cluster.set(300, Cluster::guest("pool-a"));
    *harness.reverter.fail.lock().unwrap() = true;
    let operation = harness
        .operations
        .create_lab_pool_fill(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &harness.pool_id,
            &fill_operation(&harness.pool_id, None),
        )
        .await
        .unwrap();
    let fill = LabPoolFillExecutor::new(
        harness.pools.clone(),
        harness.cluster.clone(),
        harness.reverter.clone(),
        Arc::new(AuditSink::new(harness.pool.clone())),
    );
    harness
        .operations
        .claim_only_execute(&fill, &operation.id, "test")
        .await
        .unwrap();
    assert_eq!(
        harness.member(300).await,
        Some((MemberState::Quarantined, None))
    );
    // lab.pool.fill is queued only by the fill route.
    assert!(
        harness
            .operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &fill_operation(&harness.pool_id, None),
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn an_undecided_fill_leaves_the_member_filling_for_a_refill() {
    let harness = Harness::new(&[]).await;
    let now = fleet_core::SystemClock::now_unix_millis();
    harness
        .pools
        .add_members(&harness.pool_id, &[300], now)
        .await
        .unwrap();
    harness.cluster.set(300, Cluster::guest("pool-a"));
    *harness.cluster.unreachable.lock().unwrap() = true;
    let fill = LabPoolFillExecutor::new(
        harness.pools.clone(),
        harness.cluster.clone(),
        harness.reverter.clone(),
        Arc::new(AuditSink::new(harness.pool.clone())),
    );
    let run = || async {
        let operation = harness
            .operations
            .create_lab_pool_fill(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &harness.pool_id,
                &fill_operation(&harness.pool_id, None),
            )
            .await
            .unwrap();
        harness
            .operations
            .claim_only_execute(&fill, &operation.id, "test")
            .await
            .unwrap();
        harness.operation(&operation.id).await
    };
    let done = run().await;
    assert_eq!(done.state, "failed");
    assert!(done.error_json.unwrap().contains("fill_incomplete"));
    assert_eq!(
        harness.member(300).await,
        Some((MemberState::Filling, None))
    );
    assert!(harness.reverter.ran.lock().unwrap().is_empty());
    // Once the cluster answers, a re-fill finishes it.
    *harness.cluster.unreachable.lock().unwrap() = false;
    assert_eq!(run().await.state, "succeeded");
    assert_eq!(
        harness.member(300).await,
        Some((MemberState::Available, None))
    );
}
