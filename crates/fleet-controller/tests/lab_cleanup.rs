//! FM-713 (#254): `lab.cleanup` converges a releasing lease to `released`
//! without leaving a Fleet-owned guest behind, or leaves it visibly
//! `cleanup_failed` after its retries. Real SQLite repositories and
//! operations; the destroy child runs through a scripted executor standing
//! in for FM-712's reviewed destroy.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::lab::{
    LabTemplate, LabTemplatePort, LabTemplateVersion, LeasePort, MAX_CLEANUP_ATTEMPTS,
    NewLabTemplate, NewLease, NewProvision, ProvisionPort, cleanup_operation,
};
use fleet_application::operation::{NewOperation, Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_controller::lab_cleanup::LabCleanupExecutor;
use fleet_core::{CleanupStrategy, LabTemplateContent, LeaseState, ReadinessProbe};
use fleet_storage_sqlite::{
    AuditSink, LabRepository, LeaseRepository, MachineRepository, OperationRepository, Store,
};

/// The scripted stand-in for the reviewed destroy executor: it records the
/// child it ran and ends it as told.
#[derive(Debug, Default)]
struct Destroyer {
    fail: bool,
    ran: Mutex<Vec<serde_json::Value>>,
}

#[async_trait]
impl OperationExecutor for Destroyer {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        assert_eq!(operation.kind, "proxmox.guest.destroy");
        self.ran.lock().unwrap().push(
            serde_json::from_str(operation.payload_json.as_deref().unwrap_or("null")).unwrap(),
        );
        let (state, error) = if self.fail {
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

struct Harness {
    _dir: tempfile::TempDir,
    labs: Arc<LabRepository>,
    leases: Arc<LeaseRepository>,
    operations: Arc<Operations>,
    pool: sqlx::SqlitePool,
    version_id: String,
}

impl Harness {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        let now = fleet_core::SystemClock::now_unix_millis();
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
            now,
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
                    published_at: now,
                },
            )
            .await
            .unwrap();
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            Arc::new(AuditSink::new(pool.clone())),
        ));
        Self {
            _dir: dir,
            labs,
            leases: Arc::new(LeaseRepository::new(pool.clone())),
            operations,
            pool,
            version_id: version.id,
        }
    }

    /// A releasing lease; `guest` gives its provision record a guest
    /// (node, VMID, account), else the lease never allocated one.
    async fn releasing(
        &self,
        cleanup: CleanupStrategy,
        guest: Option<(&str, u32, Option<&str>)>,
    ) -> String {
        let now = fleet_core::SystemClock::now_unix_millis();
        let lease = self
            .leases
            .create(
                &NewLease {
                    template_version_id: self.version_id.clone(),
                    purpose: "cleanup".to_owned(),
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
                template_version_id: self.version_id.clone(),
                lease_id: Some(lease.id.clone()),
                idempotency_key: None,
            },
            now,
        )
        .await
        .unwrap();
        self.leases
            .attach_provision(&lease.id, &record.id)
            .await
            .unwrap();
        if let Some((node, vmid, account)) = guest {
            let mut record = record;
            record.node = Some(node.to_owned());
            record.vmid = Some(vmid);
            record.account_id = account.map(str::to_owned);
            ProvisionPort::update(self.labs.as_ref(), &record)
                .await
                .unwrap();
        }
        let mut lease = self.leases.get(&lease.id).await.unwrap();
        lease.state = LeaseState::Releasing;
        self.leases.update(&lease).await.unwrap();
        lease.id
    }

    fn executor(&self, destroyer: Arc<Destroyer>) -> LabCleanupExecutor {
        LabCleanupExecutor::new(
            self.leases.clone(),
            self.labs.clone(),
            Arc::new(MachineRepository::new(self.pool.clone())),
            Arc::new(AuditSink::new(self.pool.clone())),
            destroyer,
        )
    }

    /// Queues and runs one cleanup attempt; answers the operation's final
    /// state, its error reason, and the lease.
    async fn run(
        &self,
        lease_id: &str,
        destroyer: &Arc<Destroyer>,
    ) -> (String, String, fleet_core::Lease) {
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
            .claim_only_execute(&self.executor(destroyer.clone()), &operation.id, "test")
            .await
            .unwrap();
        let done = self
            .operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &operation.id,
            )
            .await
            .unwrap();
        let reason = done
            .error_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
            .and_then(|error| error["reason"].as_str().map(str::to_owned))
            .unwrap_or_default();
        (done.state, reason, self.leases.get(lease_id).await.unwrap())
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
async fn destroy_runs_the_reviewed_child_and_releases_the_lease() {
    let harness = Harness::new().await;
    let lease = harness
        .releasing(
            CleanupStrategy::Destroy,
            Some(("pve-b", 9000, Some("account-1"))),
        )
        .await;
    let destroyer = Arc::new(Destroyer::default());
    let (state, _, after) = harness.run(&lease, &destroyer).await;
    assert_eq!(state, "succeeded");
    assert_eq!(after.state, LeaseState::Released);
    // The child carried exactly this guest, through the recorded account,
    // and the create path accepted the controller's own review token.
    let ran = destroyer.ran.lock().unwrap().clone();
    assert_eq!(ran.len(), 1);
    assert_eq!(ran[0]["accountId"], "account-1");
    assert_eq!(ran[0]["node"], "pve-b");
    assert_eq!(ran[0]["vmid"], 9000);
    assert_eq!(ran[0]["params"]["purge"], true);
    assert_eq!(harness.audit_events("lab_lease_released").await, 1);

    // A duplicate delivery after the release is a no-op, not a second destroy.
    let operation = harness
        .operations
        .create_lab_cleanup(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &lease,
            &NewOperation {
                idempotency_key: Some(format!("lab-cleanup:{lease}:duplicate")),
                ..cleanup_operation(&after, None)
            },
        )
        .await
        .unwrap();
    harness
        .operations
        .claim_only_execute(&harness.executor(destroyer.clone()), &operation.id, "test")
        .await
        .unwrap();
    assert_eq!(destroyer.ran.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_failing_destroy_backs_off_then_leaves_the_lease_cleanup_failed() {
    let harness = Harness::new().await;
    let lease = harness
        .releasing(
            CleanupStrategy::Destroy,
            Some(("pve-b", 9001, Some("account-1"))),
        )
        .await;
    let destroyer = Arc::new(Destroyer {
        fail: true,
        ..Destroyer::default()
    });
    for attempt in 1..MAX_CLEANUP_ATTEMPTS {
        let (state, reason, after) = harness.run(&lease, &destroyer).await;
        assert_eq!(
            (state.as_str(), reason.as_str()),
            ("failed", "cleanup_retry")
        );
        assert_eq!(after.state, LeaseState::Releasing, "attempt {attempt}");
        assert_eq!(after.cleanup_attempts, attempt);
        assert!(after.cleanup_next_at.is_some());
    }
    let (_, reason, after) = harness.run(&lease, &destroyer).await;
    assert_eq!(reason, "cleanup_failed");
    assert_eq!(after.state, LeaseState::CleanupFailed);
    assert_eq!(after.cleanup_next_at, None);
    // Each attempt ran its own child; the exhaustion is audited once with
    // the guest the lease still owns.
    assert_eq!(
        destroyer.ran.lock().unwrap().len(),
        usize::try_from(MAX_CLEANUP_ATTEMPTS).unwrap()
    );
    assert_eq!(harness.audit_events("lab_lease_cleanup_failed").await, 1);
}

/// No image version is promoted: the re-arm never pins one.
#[derive(Debug)]
struct NoPins;

#[async_trait]
impl fleet_application::lab::ImagePinValidator for NoPins {
    async fn promoted_version(
        &self,
        _version_id: &str,
    ) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok(None)
    }
}

#[tokio::test]
async fn a_rearmed_cleanup_failed_lease_resolves_to_released_once_the_guest_is_gone() {
    let harness = Harness::new().await;
    let lease = harness
        .releasing(
            CleanupStrategy::Destroy,
            Some(("pve-b", 9005, Some("account-1"))),
        )
        .await;
    let machine = harness.link_machine(&lease).await;
    let failing = Arc::new(Destroyer {
        fail: true,
        ..Destroyer::default()
    });
    for _ in 0..MAX_CLEANUP_ATTEMPTS {
        harness.run(&lease, &failing).await;
    }
    let exhausted = harness.leases.get(&lease).await.unwrap();
    assert_eq!(exhausted.state, LeaseState::CleanupFailed);

    // The operator fixes the cause (here: removes the guest by hand) and
    // re-arms the cleanup through the authorized, audited use case.
    let lab = fleet_application::lab::Lab::new(
        harness.labs.clone(),
        harness.labs.clone(),
        harness.leases.clone(),
        Arc::new(NoPins),
        Arc::new(fleet_storage_sqlite::ProjectRepository::new(
            harness.pool.clone(),
        )),
        Arc::new(AuditSink::new(harness.pool.clone())),
    );
    let principal = fleet_application::authz::ActingPrincipal {
        id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
    };
    let rearmed = lab
        .retry_cleanup(&fleet_auth::LanAllowAllAuthorizer, &principal, &lease)
        .await
        .unwrap();
    assert_eq!(rearmed.state, LeaseState::Releasing);
    assert_eq!(rearmed.cleanup_next_at, None);
    assert_eq!(harness.audit_events("lab_lease_cleanup_rearmed").await, 1);
    // A second re-arm is refused: the lease is releasing again.
    assert!(
        lab.retry_cleanup(&fleet_auth::LanAllowAllAuthorizer, &principal, &lease)
            .await
            .is_err()
    );

    // The reviewed destroy treats the absent guest as done (the stand-in
    // succeeds), so the next attempt releases the lease and removes the
    // Lab-owned machine record.
    let gone = Arc::new(Destroyer::default());
    let (state, _, after) = harness.run(&lease, &gone).await;
    assert_eq!(state, "succeeded");
    assert_eq!(after.state, LeaseState::Released);
    assert!(!harness.machine_exists(&machine).await);
    assert_eq!(gone.ran.lock().unwrap().len(), 1);
    // The re-armed attempt was a new operation, not the last failed one
    // re-found under a reused idempotency key.
    let cleanups: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT idempotency_key) FROM operations WHERE kind = 'lab.cleanup'",
    )
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(cleanups, i64::from(MAX_CLEANUP_ATTEMPTS) + 1);
}

#[tokio::test]
async fn keep_releases_without_destroying_and_the_decision_persists() {
    let harness = Harness::new().await;
    let lease = harness
        .releasing(
            CleanupStrategy::Destroy,
            Some(("pve-b", 9002, Some("account-1"))),
        )
        .await;
    // A keep release rewrites the lease's cleanup decision; it must persist
    // through the repository, or cleanup would destroy the kept VM.
    let mut kept = harness.leases.get(&lease).await.unwrap();
    kept.cleanup = CleanupStrategy::Keep;
    harness.leases.update(&kept).await.unwrap();
    assert_eq!(
        harness.leases.get(&lease).await.unwrap().cleanup,
        CleanupStrategy::Keep
    );
    let destroyer = Arc::new(Destroyer::default());
    let (state, _, after) = harness.run(&lease, &destroyer).await;
    assert_eq!(state, "succeeded");
    assert_eq!(after.state, LeaseState::Released);
    assert!(destroyer.ran.lock().unwrap().is_empty());
}

#[tokio::test]
async fn revert_is_refused_without_a_destroy_or_a_spent_attempt() {
    let harness = Harness::new().await;
    let lease = harness
        .releasing(
            CleanupStrategy::Revert,
            Some(("pve-b", 9003, Some("account-1"))),
        )
        .await;
    let destroyer = Arc::new(Destroyer::default());
    let (state, reason, after) = harness.run(&lease, &destroyer).await;
    assert_eq!(
        (state.as_str(), reason.as_str()),
        ("failed", "unsupported_until_pooled")
    );
    assert_eq!(after.state, LeaseState::Releasing);
    assert_eq!(after.cleanup_attempts, 0);
    assert!(destroyer.ran.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_lease_without_a_guest_is_released_and_an_unknown_account_is_a_failed_attempt() {
    let harness = Harness::new().await;
    let destroyer = Arc::new(Destroyer::default());

    let empty = harness.releasing(CleanupStrategy::Destroy, None).await;
    let (state, _, after) = harness.run(&empty, &destroyer).await;
    assert_eq!(state, "succeeded");
    assert_eq!(after.state, LeaseState::Released);

    // A pre-FM-713 record names no account: the cleanup refuses to guess,
    // spends an attempt, and keeps the lease owning the guest.
    let legacy = harness
        .releasing(CleanupStrategy::Destroy, Some(("pve-b", 9004, None)))
        .await;
    let (state, reason, after) = harness.run(&legacy, &destroyer).await;
    assert_eq!(
        (state.as_str(), reason.as_str()),
        ("failed", "cleanup_retry")
    );
    assert_eq!(after.state, LeaseState::Releasing);
    assert_eq!(after.cleanup_attempts, 1);
    assert!(destroyer.ran.lock().unwrap().is_empty());
}

#[tokio::test]
async fn lab_cleanup_is_only_created_for_its_own_lease() {
    let harness = Harness::new().await;
    let lease = harness.releasing(CleanupStrategy::Destroy, None).await;
    let row = harness.leases.get(&lease).await.unwrap();
    // The generic surface refuses the kind.
    let generic = harness
        .operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &cleanup_operation(&row, None),
        )
        .await;
    assert!(generic.is_err());
    // The dedicated path refuses a payload naming another lease.
    let mismatched = harness
        .operations
        .create_lab_cleanup(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            "another-lease",
            &cleanup_operation(&row, None),
        )
        .await;
    assert!(mismatched.is_err());
    // Repeating the same attempt queues nothing new.
    let first = harness
        .operations
        .create_lab_cleanup(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &lease,
            &cleanup_operation(&row, None),
        )
        .await
        .unwrap();
    let again = harness
        .operations
        .create_lab_cleanup(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &lease,
            &cleanup_operation(&row, None),
        )
        .await
        .unwrap();
    assert_eq!(first.id, again.id);
}

impl Harness {
    /// Registers a Lab-owned machine and links it to the lease's record.
    async fn link_machine(&self, lease_id: &str) -> String {
        use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
        let machine = MachineRepository::new(self.pool.clone())
            .register(&RegisterMachine {
                name: format!("lab-{lease_id}"),
                description: String::new(),
                endpoints: vec![NewEndpoint {
                    kind: fleet_core::EndpointKind::Ssh,
                    reference: "root@192.0.2.10:22".to_owned(),
                }],
                tags: vec!["lab".to_owned()],
                groups: vec![],
            })
            .await
            .unwrap();
        let lease = self.leases.get(lease_id).await.unwrap();
        let mut record =
            ProvisionPort::get(self.labs.as_ref(), lease.provision_id.as_deref().unwrap())
                .await
                .unwrap();
        record.machine_id = Some(machine.id.clone());
        ProvisionPort::update(self.labs.as_ref(), &record)
            .await
            .unwrap();
        machine.id
    }

    /// Whether the machine row exists; any failure other than "not found"
    /// fails the test rather than reading as a deletion.
    async fn machine_exists(&self, id: &str) -> bool {
        use fleet_application::machine::MachinePort as _;
        match MachineRepository::new(self.pool.clone()).get(id).await {
            Ok(_) => true,
            Err(fleet_application::operation::PortFailure::NotFound { .. }) => false,
            Err(other) => panic!("reading machine {id} failed: {other:?}"),
        }
    }
}

#[tokio::test]
async fn the_lab_owned_machine_goes_with_a_destroyed_guest_and_stays_otherwise() {
    let harness = Harness::new().await;

    let destroyed = harness
        .releasing(
            CleanupStrategy::Destroy,
            Some(("pve-b", 9010, Some("account-1"))),
        )
        .await;
    let machine = harness.link_machine(&destroyed).await;
    let (state, _, _) = harness
        .run(&destroyed, &Arc::new(Destroyer::default()))
        .await;
    assert_eq!(state, "succeeded");
    assert!(!harness.machine_exists(&machine).await);

    let kept = harness
        .releasing(
            CleanupStrategy::Keep,
            Some(("pve-b", 9011, Some("account-1"))),
        )
        .await;
    let machine = harness.link_machine(&kept).await;
    harness.run(&kept, &Arc::new(Destroyer::default())).await;
    assert!(
        harness.machine_exists(&machine).await,
        "keep keeps the machine"
    );

    let failing = harness
        .releasing(
            CleanupStrategy::Destroy,
            Some(("pve-b", 9012, Some("account-1"))),
        )
        .await;
    let machine = harness.link_machine(&failing).await;
    let destroyer = Arc::new(Destroyer {
        fail: true,
        ..Destroyer::default()
    });
    harness.run(&failing, &destroyer).await;
    assert!(
        harness.machine_exists(&machine).await,
        "a failed destroy keeps the machine of the guest that still exists"
    );
}
