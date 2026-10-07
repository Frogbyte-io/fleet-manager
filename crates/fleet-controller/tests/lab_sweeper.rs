//! FM-716 (#258): the Lab sweeper expires leases, queues due cleanups,
//! compensates stuck provisions, and reports unowned Lab guests without
//! deleting them. Real SQLite repositories and operations; the Proxmox
//! inventory is scripted. Every tick runs on a fresh sweeper over the same
//! database, as after a controller restart.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::lab::{
    Lab, LabTemplate, LabTemplatePort, LabTemplateVersion, LeasePort, NewLabTemplate, NewLease,
    NewProvision, ProvisionPort,
};
use fleet_application::operation::Operations;
use fleet_controller::lab_sweeper::{LabGuest, LabGuestInventory, LabSweeper, STUCK_GRACE_MILLIS};
use fleet_core::{CleanupStrategy, LabTemplateContent, LeaseState, ReadinessProbe};
use fleet_storage_sqlite::{
    AuditSink, LabRepository, LeaseRepository, OperationRepository, ProjectRepository, Store,
};

/// A scripted Proxmox inventory.
#[derive(Debug, Default)]
struct Guests(Mutex<Vec<LabGuest>>);

#[async_trait]
impl LabGuestInventory for Guests {
    async fn lab_guests(&self) -> Vec<LabGuest> {
        self.0.lock().unwrap().clone()
    }
}

/// Never consulted: the sweeper creates no templates.
#[derive(Debug)]
struct NoPins;

#[async_trait]
impl fleet_application::lab::ImagePinValidator for NoPins {
    async fn promoted_version(&self, _: &str) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok(None)
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    labs: Arc<LabRepository>,
    leases: Arc<LeaseRepository>,
    operations: Arc<Operations>,
    version_id: String,
    guests: Arc<Guests>,
}

const NOW: i64 = 2_000_000_000_000;

impl Harness {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let content = LabTemplateContent {
            name: "lab-base".to_owned(),
            description: String::new(),
            image_version_id: "image-version-1".to_owned(),
            cores: 2,
            memory_mib: 2048,
            disk_gib: 20,
            bootstrap_project_id: None,
            readiness_probe: ReadinessProbe::GuestAgent,
            readiness_command: None,
            ssh_user: "root".to_owned(),
            ssh_port: 22,
            ssh_trust_mode: "tofu".to_owned(),
            ssh_fingerprint: None,
            readiness_deadline_seconds: 0,
            ttl_seconds: 3_600,
            cleanup: CleanupStrategy::Destroy,
        };
        let template: LabTemplate = LabTemplatePort::create(
            labs.as_ref(),
            &NewLabTemplate {
                content: content.clone(),
            },
            NOW,
        )
        .await
        .unwrap();
        let version = labs
            .publish(
                &template.id,
                &LabTemplateVersion {
                    id: "template-version-1".to_owned(),
                    template_id: template.id.clone(),
                    name: content.name.clone(),
                    content,
                    image_digest: "sha256:abc".to_owned(),
                    published_by: "tester".to_owned(),
                    published_at: NOW,
                },
            )
            .await
            .unwrap();
        Self {
            _dir: dir,
            labs,
            leases: Arc::new(LeaseRepository::new(pool.clone())),
            operations: Arc::new(Operations::new(
                Arc::new(OperationRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )),
            pool,
            version_id: version.id,
            guests: Arc::new(Guests::default()),
        }
    }

    /// A fresh sweeper over the same database: what a restarted controller
    /// builds.
    fn sweeper(&self) -> LabSweeper {
        self.sweeper_with_audit(Arc::new(AuditSink::new(self.pool.clone())))
    }

    /// A fresh sweeper recording its audit through `audit`.
    fn sweeper_with_audit(
        &self,
        audit: Arc<dyn fleet_application::operation::AuditPort>,
    ) -> LabSweeper {
        let lab = Arc::new(Lab::new(
            self.labs.clone(),
            self.labs.clone(),
            self.leases.clone(),
            Arc::new(NoPins),
            Arc::new(ProjectRepository::new(self.pool.clone())),
            Arc::new(AuditSink::new(self.pool.clone())),
        ));
        LabSweeper::new(
            lab,
            self.leases.clone(),
            self.labs.clone(),
            self.operations.clone(),
            audit,
        )
        .with_inventory(self.guests.clone())
    }

    /// A lease in `state` with a linked record; `vmid` allocates a guest.
    async fn lease(&self, state: LeaseState, vmid: Option<u32>) -> (String, String) {
        let lease = self
            .leases
            .create(
                &NewLease {
                    template_version_id: self.version_id.clone(),
                    purpose: "sweep".to_owned(),
                    project_id: None,
                    cleanup: CleanupStrategy::Destroy,
                    ttl_seconds: 3_600,
                },
                "tester",
                NOW - 60_000,
            )
            .await
            .unwrap();
        let mut record = ProvisionPort::create(
            self.labs.as_ref(),
            &NewProvision {
                template_version_id: self.version_id.clone(),
                lease_id: Some(lease.id.clone()),
                idempotency_key: None,
            },
            NOW - 60_000,
        )
        .await
        .unwrap();
        self.leases
            .attach_provision(&lease.id, &record.id)
            .await
            .unwrap();
        record.vmid = vmid;
        record.node = vmid.map(|_| "pve-b".to_owned());
        record.account_id = vmid.map(|_| "account-1".to_owned());
        ProvisionPort::update(self.labs.as_ref(), &record)
            .await
            .unwrap();
        let mut stored = self.leases.get(&lease.id).await.unwrap();
        stored.state = state;
        self.leases.update(&stored).await.unwrap();
        (lease.id, record.id)
    }

    async fn cleanups(&self, lease_id: &str) -> usize {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM operations WHERE kind = 'lab.cleanup' AND payload_json LIKE ?1",
        )
        .bind(format!("%{lease_id}%"))
        .fetch_one(&self.pool)
        .await
        .unwrap();
        usize::try_from(count).unwrap()
    }
}

#[tokio::test]
async fn an_expired_lease_is_released_and_its_cleanup_queued_after_a_restart() {
    let harness = Harness::new().await;
    let (lease, _) = harness.lease(LeaseState::Ready, Some(9000)).await;
    // Ready, with a TTL that ran out while "no controller was running".
    let mut stored = harness.leases.get(&lease).await.unwrap();
    stored.ready_at = Some(NOW - 50_000);
    stored.expires_at = Some(NOW - 1);
    harness.leases.update(&stored).await.unwrap();

    let report = harness.sweeper().tick(NOW).await.unwrap();
    assert_eq!(report.expired, 1);
    assert_eq!(report.cleanups_queued, 1);
    assert_eq!(
        harness.leases.get(&lease).await.unwrap().state,
        LeaseState::Releasing
    );
    // The next tick (another fresh sweeper) queues nothing new.
    let again = harness.sweeper().tick(NOW + 1).await.unwrap();
    assert_eq!((again.expired, again.cleanups_queued), (0, 0));
    assert_eq!(harness.cleanups(&lease).await, 1);
}

#[tokio::test]
async fn a_backing_off_cleanup_is_queued_only_once_it_is_due() {
    let harness = Harness::new().await;
    let (lease, _) = harness.lease(LeaseState::Releasing, Some(9001)).await;
    let mut stored = harness.leases.get(&lease).await.unwrap();
    stored.cleanup_attempts = 1;
    stored.cleanup_next_at = Some(NOW + 60_000);
    harness.leases.update(&stored).await.unwrap();

    assert_eq!(
        harness.sweeper().tick(NOW).await.unwrap().cleanups_queued,
        0
    );
    assert_eq!(harness.cleanups(&lease).await, 0);
    assert_eq!(
        harness
            .sweeper()
            .tick(NOW + 60_000)
            .await
            .unwrap()
            .cleanups_queued,
        1
    );
    assert_eq!(harness.cleanups(&lease).await, 1);
}

#[tokio::test]
async fn a_lost_enqueue_is_repaired() {
    // A lease committed to releasing whose cleanup was never queued.
    let harness = Harness::new().await;
    let (lease, _) = harness.lease(LeaseState::Releasing, Some(9002)).await;
    assert_eq!(
        harness.sweeper().tick(NOW).await.unwrap().cleanups_queued,
        1
    );
    assert_eq!(harness.cleanups(&lease).await, 1);
}

#[tokio::test]
async fn a_stuck_provision_is_compensated_by_what_it_allocated() {
    let harness = Harness::new().await;
    let (with_guest, with_record) = harness.lease(LeaseState::Provisioning, Some(9003)).await;
    let (without_guest, without_record) = harness.lease(LeaseState::Booting, None).await;
    let (fresh, fresh_record) = harness.lease(LeaseState::Provisioning, Some(9004)).await;
    for (record_id, deadline) in [
        (&with_record, NOW - STUCK_GRACE_MILLIS - 1),
        (&without_record, NOW - STUCK_GRACE_MILLIS - 1),
        // Within the grace: the provision may still be running.
        (&fresh_record, NOW - 1),
    ] {
        let mut record = ProvisionPort::get(harness.labs.as_ref(), record_id)
            .await
            .unwrap();
        record.readiness_deadline_at = Some(deadline);
        ProvisionPort::update(harness.labs.as_ref(), &record)
            .await
            .unwrap();
    }

    let report = harness.sweeper().tick(NOW).await.unwrap();
    assert_eq!(report.compensated, 2);
    assert_eq!(
        harness.leases.get(&with_guest).await.unwrap().state,
        LeaseState::Releasing
    );
    assert_eq!(harness.cleanups(&with_guest).await, 1);
    assert_eq!(
        harness.leases.get(&without_guest).await.unwrap().state,
        LeaseState::Failed
    );
    assert_eq!(harness.cleanups(&without_guest).await, 0);
    assert_eq!(
        harness.leases.get(&fresh).await.unwrap().state,
        LeaseState::Provisioning
    );
}

#[tokio::test]
async fn unowned_lab_guests_are_reported_once_and_never_touched() {
    let harness = Harness::new().await;
    let (_, owned_record) = harness.lease(LeaseState::Ready, Some(9005)).await;
    let (kept, kept_record) = harness.lease(LeaseState::Released, Some(9006)).await;
    let mut kept_lease = harness.leases.get(&kept).await.unwrap();
    kept_lease.cleanup = CleanupStrategy::Keep;
    harness.leases.update(&kept_lease).await.unwrap();
    let (_, released_record) = harness.lease(LeaseState::Released, Some(9007)).await;
    let on = |account: &str, record: &str, vmid: u32| LabGuest {
        account_id: account.to_owned(),
        node: "pve-b".to_owned(),
        vmid,
        name: format!("fm-lab-{record}"),
    };
    let guest = |record: &str, vmid: u32| on("account-1", record, vmid);
    *harness.guests.0.lock().unwrap() = vec![
        guest(&owned_record, 9005),
        guest(&kept_record, 9006),
        // Destroy claimed success, yet the guest is still there.
        guest(&released_record, 9007),
        // No record at all.
        guest("00000000-0000-0000-0000-000000000000", 9008),
        // The live record's name and VMID, but on another account: not the
        // guest its cleanup would destroy.
        on("account-2", &owned_record, 9005),
    ];
    let sweeper = harness.sweeper();
    let report = sweeper.tick(NOW).await.unwrap();
    let found: Vec<(&str, u32)> = report
        .orphans
        .iter()
        .map(|guest| (guest.account_id.as_str(), guest.vmid))
        .collect();
    assert_eq!(
        found,
        vec![
            ("account-1", 9007),
            ("account-1", 9008),
            ("account-2", 9005)
        ]
    );
    // Reported once per controller run.
    assert!(sweeper.tick(NOW + 1).await.unwrap().orphans.is_empty());
    // Nothing was queued for the unowned guests: they are reported only.
    assert_eq!(report.cleanups_queued, 0);
}

#[tokio::test]
async fn the_loop_stops_promptly_on_shutdown() {
    let harness = Harness::new().await;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(Arc::new(harness.sweeper()).run(
        std::time::Duration::from_secs(3_600),
        async move {
            let _ = stopped.await;
        },
    ));
    stop.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("the sweeper stops without waiting for its interval")
        .unwrap();
}

#[tokio::test]
async fn a_failed_lease_still_holding_a_guest_is_moved_to_cleanup() {
    // A provision failed, and the controller stopped before compensating.
    let harness = Harness::new().await;
    let (with_guest, _) = harness.lease(LeaseState::Failed, Some(9010)).await;
    let (without_guest, _) = harness.lease(LeaseState::Failed, None).await;
    let report = harness.sweeper().tick(NOW).await.unwrap();
    assert_eq!(report.compensated, 1);
    assert_eq!(
        harness.leases.get(&with_guest).await.unwrap().state,
        LeaseState::Releasing
    );
    assert_eq!(harness.cleanups(&with_guest).await, 1);
    assert_eq!(
        harness.leases.get(&without_guest).await.unwrap().state,
        LeaseState::Failed
    );
}

#[tokio::test]
async fn compensation_never_overwrites_a_lease_that_moved_on() {
    // The sweeper's snapshot said provisioning; the provision completed
    // before the write. The compare-and-set loses, and the lease stays ready.
    let harness = Harness::new().await;
    let (lease, record) = harness.lease(LeaseState::Provisioning, Some(9011)).await;
    let mut ready = harness.leases.get(&lease).await.unwrap();
    ready.state = LeaseState::Ready;
    harness.leases.update(&ready).await.unwrap();
    assert!(
        !harness
            .leases
            .transition(
                &lease,
                LeaseState::Provisioning,
                Some(&record),
                LeaseState::Releasing
            )
            .await
            .unwrap()
    );
    assert_eq!(
        harness.leases.get(&lease).await.unwrap().state,
        LeaseState::Ready
    );
    // A different provision link also loses.
    assert!(
        !harness
            .leases
            .transition(
                &lease,
                LeaseState::Ready,
                Some("other"),
                LeaseState::Releasing
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_failed_enqueue_is_reported_and_the_tick_goes_on() {
    let harness = Harness::new().await;
    let (lease, record) = harness.lease(LeaseState::Releasing, Some(9012)).await;
    sqlx::query("DROP TABLE operations")
        .execute(&harness.pool)
        .await
        .unwrap();
    // An unowned guest is still reported after the failed enqueue.
    *harness.guests.0.lock().unwrap() = vec![LabGuest {
        account_id: "account-1".to_owned(),
        node: "pve-b".to_owned(),
        vmid: 9099,
        name: format!("fm-lab-{record}"),
    }];
    let report = harness.sweeper().tick(NOW).await.unwrap();
    assert_eq!(report.cleanups_queued, 0);
    assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
    assert!(report.failures[0].contains(&lease));
    assert_eq!(report.orphans.len(), 1);
}

#[tokio::test]
async fn each_committed_change_is_announced() {
    let harness = Harness::new().await;
    let events = Arc::new(fleet_application::events::EventHub::new(16));
    let before = events.current_id();
    // Nothing to do: nothing announced.
    harness
        .sweeper()
        .with_events(events.clone())
        .tick(NOW)
        .await
        .unwrap();
    assert_eq!(events.current_id(), before);
    let (lease, _) = harness.lease(LeaseState::Ready, Some(9013)).await;
    let mut stored = harness.leases.get(&lease).await.unwrap();
    stored.expires_at = Some(NOW - 1);
    harness.leases.update(&stored).await.unwrap();
    harness
        .sweeper()
        .with_events(events.clone())
        .tick(NOW)
        .await
        .unwrap();
    assert_ne!(events.current_id(), before);
}

/// An inventory whose Proxmox host never answers.
#[derive(Debug, Default)]
struct Hanging(tokio::sync::Notify);

#[async_trait]
impl LabGuestInventory for Hanging {
    async fn lab_guests(&self) -> Vec<LabGuest> {
        self.0.notify_one();
        std::future::pending().await
    }
}

#[tokio::test]
async fn shutdown_cancels_a_tick_stuck_on_proxmox() {
    let harness = Harness::new().await;
    let hanging = Arc::new(Hanging::default());
    let sweeper = harness.sweeper().with_inventory(hanging.clone());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(Arc::new(sweeper).run(
        std::time::Duration::from_millis(1),
        async move {
            let _ = stopped.await;
        },
    ));
    // Wait until the tick is inside the unreachable host's listing.
    tokio::time::timeout(std::time::Duration::from_secs(5), hanging.0.notified())
        .await
        .expect("the tick reaches the inventory");
    stop.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("shutdown does not wait for the stuck tick")
        .unwrap();
}

/// An audit sink that refuses while `refuse` is set.
#[derive(Debug)]
struct RefusingAudit {
    inner: AuditSink,
    refuse: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl fleet_application::operation::AuditPort for RefusingAudit {
    async fn record_intent(
        &self,
        intent: &fleet_application::audit::AuditIntent,
    ) -> Result<(), String> {
        if self.refuse.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("the audit sink refused".to_owned());
        }
        fleet_application::operation::AuditPort::record_intent(&self.inner, intent).await
    }

    async fn record_outcome(
        &self,
        operation_id: &str,
        outcome: fleet_application::audit::AuditOutcome,
    ) -> Result<(), String> {
        fleet_application::operation::AuditPort::record_outcome(&self.inner, operation_id, outcome)
            .await
    }
}

#[tokio::test]
async fn an_orphan_whose_audit_was_refused_is_reported_on_the_next_tick() {
    let harness = Harness::new().await;
    *harness.guests.0.lock().unwrap() = vec![LabGuest {
        account_id: "account-1".to_owned(),
        node: "pve-b".to_owned(),
        vmid: 9100,
        name: "fm-lab-00000000-0000-0000-0000-000000000000".to_owned(),
    }];
    let audit = Arc::new(RefusingAudit {
        inner: AuditSink::new(harness.pool.clone()),
        refuse: std::sync::atomic::AtomicBool::new(true),
    });
    let sweeper = harness.sweeper_with_audit(audit.clone());
    let refused = sweeper.tick(NOW).await.unwrap();
    assert!(refused.orphans.is_empty());
    assert_eq!(refused.failures.len(), 1, "{:?}", refused.failures);
    assert!(refused.failures[0].contains("refused"));

    audit
        .refuse
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let retried = sweeper.tick(NOW + 1).await.unwrap();
    assert_eq!(retried.orphans.len(), 1);
    assert!(retried.failures.is_empty(), "{:?}", retried.failures);
    // Then reported once, as before.
    assert!(sweeper.tick(NOW + 2).await.unwrap().orphans.is_empty());
}
