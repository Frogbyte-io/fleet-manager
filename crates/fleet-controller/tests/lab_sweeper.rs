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
            Arc::new(AuditSink::new(self.pool.clone())),
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
    let guest = |record: &str, vmid: u32| LabGuest {
        account_id: "account-1".to_owned(),
        node: "pve-b".to_owned(),
        vmid,
        name: format!("fm-lab-{record}"),
    };
    *harness.guests.0.lock().unwrap() = vec![
        guest(&owned_record, 9005),
        guest(&kept_record, 9006),
        // Destroy claimed success, yet the guest is still there.
        guest(&released_record, 9007),
        // No record at all.
        guest("00000000-0000-0000-0000-000000000000", 9008),
    ];
    let sweeper = harness.sweeper();
    let report = sweeper.tick(NOW).await.unwrap();
    let vmids: Vec<u32> = report.orphans.iter().map(|guest| guest.vmid).collect();
    assert_eq!(vmids, vec![9007, 9008]);
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
