//! FM-721 (#261): Lab artifacts. Every `lab.exec` keeps its bounded,
//! redacted output as an `exec-log` artifact; `lab.collect` copies declared
//! guest files into the content-addressed store; a failed collection is
//! recorded beside the lease and never touches it, so cleanup proceeds; the
//! Lab sweeper deletes artifacts past retention, keeping shared bytes until
//! their last reference goes. Real SQLite repositories, the real store and
//! dispatch; SSH is replaced by recorders.

use std::collections::HashMap;
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use fleet_application::lab::{
    ImagePinValidator, Lab, LabTemplate, LabTemplatePort, LabTemplateVersion, LeasePort,
    NewLabTemplate, NewLease, NewProvision, ProvisionPort, RecipeVersion,
};
use fleet_application::lab_artifacts::{ArtifactKind, ArtifactPolicy, LabArtifacts};
use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::operation::{NewOperation, Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_controller::lab_artifacts_store::{
    FsArtifactStore, GuestFiles, LabArtifactDispatch, StagingFile,
};
use fleet_core::{CleanupStrategy, LabTemplateContent, LeaseState, ReadinessProbe};
use fleet_provider_ssh::FetchOutcome;
use fleet_storage_sqlite::{
    AuditSink, LabArtifactRepository, LabRepository, LeaseRepository, MachineRepository,
    OperationRepository, ProjectRepository, ProxmoxAccountRepository, RecipeRepository, Store,
};

const MAX_BYTES: u64 = 4096;

/// Stands in for the SSH exec executor: completes the operation the way
/// machine exec does, with output that carries a credential.
#[derive(Debug, Default)]
struct Ssh;

#[async_trait]
impl OperationExecutor for Ssh {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        operations
            .complete(
                &operation.id,
                "succeeded",
                Some(
                    r#"{"exitCode":0,"stdout":"pushed to https://bot:hunter2@git.example.test/repo\n","stderr":"warn\n","truncatedStdout":false,"truncatedStderr":false}"#,
                ),
                None,
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// Stands in for the guest: a path holds bytes or answers an outcome.
#[derive(Debug, Default)]
struct Guest {
    files: Mutex<HashMap<String, Result<Vec<u8>, FetchOutcome>>>,
}

#[async_trait]
impl GuestFiles for Guest {
    async fn fetch(
        &self,
        _machine_id: &str,
        _endpoint_id: &str,
        path: &str,
        max_bytes: u64,
        _deadline: Duration,
        mut sink: StagingFile,
    ) -> (Result<FetchOutcome, String>, StagingFile) {
        let entry = self.files.lock().unwrap().get(path).cloned();
        let outcome = match entry {
            None => Ok(FetchOutcome::Missing),
            Some(Err(outcome)) => Ok(outcome),
            Some(Ok(bytes)) if bytes.len() as u64 > max_bytes => {
                // A partial copy, as the real reader leaves one.
                let _ = sink.write_all(&bytes[..usize::try_from(max_bytes).unwrap()]);
                Ok(FetchOutcome::TooLarge)
            }
            Some(Ok(bytes)) => sink
                .write_all(&bytes)
                .map(|()| FetchOutcome::Fetched {
                    bytes: bytes.len() as u64,
                })
                .map_err(|error| error.to_string()),
        };
        (outcome, sink)
    }
}

#[derive(Debug)]
struct NoPins;

#[async_trait]
impl ImagePinValidator for NoPins {
    async fn promoted_version(&self, _version_id: &str) -> Result<Option<RecipeVersion>, String> {
        Ok(None)
    }
}

struct Fixture {
    _store: Store,
    _dir: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    events: Arc<fleet_application::events::EventHub>,
    leases: Arc<LeaseRepository>,
    labs: Arc<LabRepository>,
    operations: Arc<Operations>,
    artifacts: Arc<LabArtifacts>,
    store: Arc<FsArtifactStore>,
    guest: Arc<Guest>,
    dispatch: LabArtifactDispatch,
    lease_id: String,
}

impl Fixture {
    /// A ready lease whose guest is a registered Lab machine.
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        let now = fleet_core::SystemClock::now_unix_millis();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let leases = Arc::new(LeaseRepository::new(pool.clone()));
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
            audio: None,
            guest_os: fleet_core::GuestOs::default(),
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
        let machine = MachineRepository::new(pool.clone())
            .register(&RegisterMachine {
                name: "lab-guest".to_owned(),
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
        let lease = leases
            .create(
                &NewLease {
                    template_version_id: version.id.clone(),
                    purpose: "artifacts".to_owned(),
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
            labs.as_ref(),
            &NewProvision {
                template_version_id: version.id.clone(),
                lease_id: Some(lease.id.clone()),
                idempotency_key: None,
                readiness_deadline_at: None,
            },
            now,
        )
        .await
        .unwrap();
        leases
            .attach_provision(&lease.id, &record.id)
            .await
            .unwrap();
        record.machine_id = Some(machine.id.clone());
        record.endpoint_id = Some(machine.endpoints[0].id.clone());
        ProvisionPort::update(labs.as_ref(), &record).await.unwrap();
        let mut ready = leases.get(&lease.id).await.unwrap();
        ready.state = LeaseState::Ready;
        ready.ready_at = Some(now);
        ready.expires_at = Some(now + 3_600_000);
        leases.update(&ready).await.unwrap();

        let events = Arc::new(fleet_application::events::EventHub::new(64));
        let operations = Arc::new(Operations::new_with_events(
            Arc::new(OperationRepository::new(pool.clone())),
            Arc::new(AuditSink::new(pool.clone())),
            events.clone(),
        ));
        let artifact_store =
            Arc::new(FsArtifactStore::open(&dir.path().join("lab-artifacts"), MAX_BYTES).unwrap());
        let artifacts = Arc::new(LabArtifacts::new(
            Arc::new(LabArtifactRepository::new(pool.clone())),
            artifact_store.clone(),
            leases.clone(),
            labs.clone(),
            Arc::new(AuditSink::new(pool.clone())),
            ArtifactPolicy {
                retention_seconds: 60,
                max_bytes: MAX_BYTES,
            },
        ));
        let lab_dispatch = fleet_controller::proxmox_exec::LabDispatch::new(
            Arc::new(Ssh),
            Arc::new(fleet_controller::proxmox_exec::ProvisionExecutor::new(
                Arc::new(ProxmoxAccountRepository::new(pool.clone())),
                Arc::new(fleet_controller::proxmox_store::AbsentProxmoxCredentials),
                labs.clone(),
                leases.clone(),
                labs.clone(),
                Arc::new(RecipeRepository::new(pool.clone())),
                fleet_provider_proxmox::ProxmoxClient::new(Arc::new(
                    fleet_provider_proxmox::ReqwestPveTransport::new(),
                )),
            )),
        )
        .with_cleanup(
            Arc::new(fleet_controller::lab_cleanup::LabCleanupExecutor::new(
                leases.clone(),
                labs.clone(),
                Arc::new(MachineRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
                Arc::new(Ssh),
            )),
            leases.clone(),
            labs.clone(),
        );
        let guest = Arc::new(Guest::default());
        let dispatch = LabArtifactDispatch::new(
            Arc::new(lab_dispatch),
            artifacts.clone(),
            artifact_store.clone(),
            leases.clone(),
            labs.clone(),
            guest.clone(),
        );
        Self {
            _store: store,
            _dir: dir,
            pool,
            events,
            leases,
            labs,
            operations,
            artifacts,
            store: artifact_store,
            guest,
            dispatch,
            lease_id: lease.id,
        }
    }

    fn principal() -> fleet_application::authz::ActingPrincipal {
        fleet_application::authz::ActingPrincipal {
            id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        }
    }

    async fn run(&self, created: Operation) -> Operation {
        self.operations
            .claim_only_execute(&self.dispatch, &created.id, "test")
            .await
            .unwrap();
        self.operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &created.id,
            )
            .await
            .unwrap()
    }

    async fn exec(&self) -> Operation {
        let new = NewOperation {
            kind: "lab.exec".to_owned(),
            idempotency_key: None,
            deadline_at: None,
            correlation_id: None,
            payload_json: Some(
                serde_json::json!({ "leaseId": self.lease_id, "script": "git push", "timeoutSeconds": 30 })
                    .to_string(),
            ),
            review_token: None,
        };
        let created = self
            .operations
            .create_lab_exec(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &self.lease_id,
                &new,
            )
            .await
            .unwrap();
        self.run(created).await
    }

    async fn collect(&self, paths: &[&str]) -> Operation {
        let paths: Vec<String> = paths.iter().map(|path| (*path).to_owned()).collect();
        // The route's validation, against the lease as it is now; a lease
        // that changed afterwards is re-checked when the operation runs.
        let new = NewOperation {
            kind: "lab.collect".to_owned(),
            idempotency_key: None,
            deadline_at: None,
            correlation_id: None,
            payload_json: Some(
                serde_json::json!({ "leaseId": self.lease_id, "paths": paths }).to_string(),
            ),
            review_token: None,
        };
        let created = self
            .operations
            .create_lab_collect(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &self.lease_id,
                &new,
            )
            .await
            .unwrap();
        self.run(created).await
    }

    async fn read(&self, id: &str) -> Vec<u8> {
        let (_, mut reader) = self
            .artifacts
            .open(&fleet_auth::LanAllowAllAuthorizer, &Self::principal(), id)
            .await
            .unwrap();
        let mut bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut bytes)
            .await
            .unwrap();
        bytes
    }

    async fn audit_events(&self) -> Vec<String> {
        sqlx::query_scalar::<_, String>("SELECT metadata_json FROM audit_events ORDER BY seq")
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default()
    }

    fn staged_files(&self) -> usize {
        std::fs::read_dir(self.store.root().join("tmp"))
            .unwrap()
            .count()
    }
}

#[tokio::test]
async fn every_lab_exec_keeps_its_redacted_output_as_an_exec_log() {
    let fixture = Fixture::new().await;
    let done = fixture.exec().await;
    assert_eq!(done.state, "succeeded");

    let listed = fixture
        .artifacts
        .list(
            &fleet_auth::LanAllowAllAuthorizer,
            &Fixture::principal(),
            fleet_application::lab_artifacts::ArtifactFilter {
                lease_id: Some(&fixture.lease_id),
                ..Default::default()
            },
            50,
        )
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    let log = &listed[0];
    assert_eq!(log.kind, ArtifactKind::ExecLog);
    assert_eq!(log.name, format!("exec-{}.log", done.id));
    assert_eq!(log.operation_id.as_deref(), Some(done.id.as_str()));
    assert_eq!(log.owner, "tester");
    assert_eq!(
        log.location,
        format!("sha256/{}/{}", &log.sha256[..2], log.sha256)
    );
    let bytes = fixture.read(&log.id).await;
    assert_eq!(bytes.len() as u64, log.size_bytes);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("# exit code: 0"), "{text}");
    assert!(text.contains("https://***@git.example.test/repo"), "{text}");
    assert!(!text.contains("hunter2"), "the exec log kept a credential");
    // The bytes are in the store, never in SQLite.
    let stored: String =
        sqlx::query_scalar("SELECT group_concat(name || location) FROM lab_artifacts")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(!stored.contains("pushed"));
    assert!(
        fixture
            .audit_events()
            .await
            .iter()
            .any(|event| event.contains("lab_artifact_recording"))
    );

    // Listing pages newest first with a cursor.
    let second = fixture.exec().await;
    let page = |cursor: Option<String>| {
        let artifacts = fixture.artifacts.clone();
        async move {
            artifacts
                .list(
                    &fleet_auth::LanAllowAllAuthorizer,
                    &Fixture::principal(),
                    fleet_application::lab_artifacts::ArtifactFilter {
                        cursor: cursor.as_deref(),
                        ..Default::default()
                    },
                    1,
                )
                .await
                .unwrap()
        }
    };
    let first_page = page(None).await;
    assert_eq!(first_page.len(), 1);
    assert_eq!(
        first_page[0].operation_id.as_deref(),
        Some(second.id.as_str())
    );
    let next_page = page(Some(first_page[0].id.clone())).await;
    assert_eq!(next_page.len(), 1);
    assert_eq!(next_page[0].id, log.id);
    assert!(page(Some(log.id.clone())).await.is_empty());
}

#[tokio::test]
async fn collection_stores_files_and_records_failures_beside_the_lease() {
    let fixture = Fixture::new().await;
    fixture.guest.files.lock().unwrap().extend([
        (
            "/var/log/app.log".to_owned(),
            Ok(b"line one\nline two\n".to_vec()),
        ),
        ("/tmp/huge.bin".to_owned(), Ok(vec![7_u8; 5000])),
        ("/tmp/dir".to_owned(), Err(FetchOutcome::NotAFile)),
    ]);

    // Every path copies: the operation succeeds and lists what it stored.
    let done = fixture.collect(&["/var/log/app.log"]).await;
    assert_eq!(done.state, "succeeded", "{:?}", done.error_json);
    let result: serde_json::Value =
        serde_json::from_str(done.result_json.as_deref().unwrap()).unwrap();
    let id = result["artifacts"][0]["artifactId"].as_str().unwrap();
    let file = fixture
        .artifacts
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            &Fixture::principal(),
            id,
        )
        .await
        .unwrap();
    assert_eq!(file.kind, ArtifactKind::File);
    assert_eq!(file.name, "/var/log/app.log");
    assert_eq!(fixture.read(id).await, b"line one\nline two\n");

    // Some paths fail: the rest are kept, the failure is recorded beside the
    // lease (announced as a lease change), and nothing half-copied stays
    // staged.
    let cursor = fixture.events.current_id();
    let partial = fixture
        .collect(&["/var/log/app.log", "/tmp/huge.bin", "/tmp/dir", "/absent"])
        .await;
    assert_eq!(partial.state, "failed");
    let error: serde_json::Value =
        serde_json::from_str(partial.error_json.as_deref().unwrap()).unwrap();
    assert_eq!(error["reason"], "collection_partial");
    assert!(
        fixture
            .events
            .subscribe(Some(&cursor))
            .replay
            .iter()
            .any(|event| event.kind == fleet_application::events::EventKind::LeaseChanged),
        "a finished collection must announce the lease change"
    );
    assert_eq!(error["artifacts"].as_array().unwrap().len(), 1);
    let reasons: Vec<&str> = error["failures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|failure| failure["reason"].as_str().unwrap())
        .collect();
    assert_eq!(reasons, ["too_large", "not_a_file", "missing"]);
    assert_eq!(fixture.staged_files(), 0);
    let failure = fixture
        .artifacts
        .collection_failure(
            &fleet_auth::LanAllowAllAuthorizer,
            &Fixture::principal(),
            &fixture.lease_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failure.operation_id, partial.id);
    assert_eq!(failure.reason, "collection_partial");
    assert!(failure.detail.contains("/tmp/huge.bin (too_large)"));
    // The same bytes collected twice share one blob.
    let blobs = walk(fixture.store.root().join("sha256").as_path());
    assert_eq!(blobs, 1, "identical content must share one blob");

    // The lease is untouched by collection: still ready, so its lifecycle
    // (and cleanup) is exactly what it would have been.
    let lease = fixture.leases.get(&fixture.lease_id).await.unwrap();
    assert_eq!(lease.state, LeaseState::Ready);
    assert!(
        fixture
            .audit_events()
            .await
            .iter()
            .any(|event| event.contains("lab_artifacts_collection_failed"))
    );
}

#[tokio::test]
async fn a_failed_collection_never_blocks_or_skips_cleanup() {
    let fixture = Fixture::new().await;
    fixture
        .guest
        .files
        .lock()
        .unwrap()
        .insert("/tmp/report.xml".to_owned(), Ok(b"<ok/>".to_vec()));
    let kept = fixture.collect(&["/tmp/report.xml"]).await;
    assert_eq!(kept.state, "succeeded");

    // The lease is released while a collection is still queued.
    let lab = Lab::new(
        fixture.labs.clone(),
        fixture.labs.clone(),
        fixture.leases.clone(),
        Arc::new(NoPins),
        Arc::new(ProjectRepository::new(fixture.pool.clone())),
        Arc::new(AuditSink::new(fixture.pool.clone())),
    );
    let released = lab
        .release_lease(
            &fleet_auth::LanAllowAllAuthorizer,
            &Fixture::principal(),
            &fixture.lease_id,
            false,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .unwrap();
    assert_eq!(released.state, LeaseState::Releasing);

    // The queued collection refuses at execution time, records why, and
    // leaves the releasing lease exactly as it was.
    let refused = fixture.collect(&["/tmp/report.xml"]).await;
    assert_eq!(refused.state, "failed");
    assert!(refused.error_json.unwrap().contains("lease_not_ready"));
    let after = fixture.leases.get(&fixture.lease_id).await.unwrap();
    assert_eq!(after.state, LeaseState::Releasing);
    assert_eq!(after.cleanup_attempts, released.cleanup_attempts);
    assert_eq!(after.cleanup_next_at, released.cleanup_next_at);
    let failure = fixture
        .artifacts
        .collection_failure(
            &fleet_auth::LanAllowAllAuthorizer,
            &Fixture::principal(),
            &fixture.lease_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failure.reason, "lease_not_ready");

    // Its cleanup still queues.
    let cleanup = fixture
        .operations
        .create_lab_cleanup(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &fixture.lease_id,
            &fleet_application::lab::cleanup_operation(&after, None),
        )
        .await
        .unwrap();
    assert_eq!(cleanup.kind, "lab.cleanup");

    // The artifacts outlive the lease's guest.
    let listed = fixture
        .artifacts
        .list(
            &fleet_auth::LanAllowAllAuthorizer,
            &Fixture::principal(),
            fleet_application::lab_artifacts::ArtifactFilter {
                lease_id: Some(&fixture.lease_id),
                ..Default::default()
            },
            50,
        )
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
}

#[tokio::test]
async fn the_sweeper_deletes_artifacts_past_retention_and_shared_bytes_last() {
    let fixture = Fixture::new().await;
    let now = fleet_core::SystemClock::now_unix_millis();
    let record = |at: i64| {
        let artifacts = fixture.artifacts.clone();
        let lease = fixture.lease_id.clone();
        async move {
            artifacts
                .record_exec_log(
                    &fleet_auth::LanAllowAllAuthorizer,
                    &Fixture::principal(),
                    &lease,
                    "op-shared",
                    "same bytes\n",
                    at,
                )
                .await
                .unwrap()
        }
    };
    // Retention is 60 s: the first is already past it, the second is not.
    let old = record(now - 120_000).await;
    let fresh = record(now).await;
    assert_eq!(old.location, fresh.location);
    let blob = fixture.store.root().join(&old.location);

    let lab = Arc::new(Lab::new(
        fixture.labs.clone(),
        fixture.labs.clone(),
        fixture.leases.clone(),
        Arc::new(NoPins),
        Arc::new(ProjectRepository::new(fixture.pool.clone())),
        Arc::new(AuditSink::new(fixture.pool.clone())),
    ));
    let sweeper = fleet_controller::lab_sweeper::LabSweeper::new(
        lab,
        fixture.leases.clone(),
        fixture.labs.clone(),
        fixture.operations.clone(),
        Arc::new(AuditSink::new(fixture.pool.clone())),
    )
    .with_artifacts(fixture.artifacts.clone());

    let report = sweeper.tick(now).await.unwrap();
    assert_eq!(report.artifacts_expired, 1, "{:?}", report.failures);
    assert!(blob.is_file(), "bytes another artifact shares must stay");
    let remaining = fixture
        .artifacts
        .list(
            &fleet_auth::LanAllowAllAuthorizer,
            &Fixture::principal(),
            fleet_application::lab_artifacts::ArtifactFilter::default(),
            50,
        )
        .await
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, fresh.id);

    let report = sweeper.tick(now + 61_000).await.unwrap();
    assert_eq!(report.artifacts_expired, 1, "{:?}", report.failures);
    assert!(!blob.exists(), "the last reference took the bytes with it");
    assert_eq!(
        sweeper.tick(now + 120_000).await.unwrap().artifacts_expired,
        0
    );
    let expired = fixture
        .audit_events()
        .await
        .iter()
        .filter(|event| event.contains("lab_artifact_expired"))
        .count();
    assert_eq!(expired, 2);
}

fn walk(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            if path.is_dir() { walk(&path) } else { 1 }
        })
        .sum()
}

/// Only `lab.artifacts` lets a caller collect, download, record, or expire.
#[derive(Debug)]
struct DenyArtifacts;

impl fleet_application::authz::Authorizer for DenyArtifacts {
    fn decide(
        &self,
        request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        if request.action == fleet_application::authz::Permission::LabArtifacts {
            fleet_application::authz::Decision::deny(
                fleet_application::authz::ReasonId::UnknownPrincipal,
            )
        } else {
            fleet_application::authz::Decision::allow()
        }
    }
}

#[tokio::test]
async fn collection_requests_are_validated_authorized_and_audited() {
    let fixture = Fixture::new().await;
    let principal = Fixture::principal();
    let request = |paths: &[&str]| {
        let paths: Vec<String> = paths.iter().map(|path| (*path).to_owned()).collect();
        let artifacts = fixture.artifacts.clone();
        let lease = fixture.lease_id.clone();
        let principal = principal.clone();
        async move {
            artifacts
                .request_collect(
                    &fleet_auth::LanAllowAllAuthorizer,
                    &principal,
                    &lease,
                    &paths,
                    fleet_core::SystemClock::now_unix_millis(),
                )
                .await
        }
    };
    let new = request(&["/var/log/syslog"]).await.unwrap();
    assert_eq!(new.kind, "lab.collect");
    let payload: serde_json::Value =
        serde_json::from_str(new.payload_json.as_deref().unwrap()).unwrap();
    assert_eq!(payload["paths"][0], "/var/log/syslog");
    assert!(
        fixture
            .audit_events()
            .await
            .iter()
            .any(|event| event.contains("lab_artifacts_collect_requested"))
    );
    for bad in [&["relative"][..], &["/tmp/../etc/shadow"], &[]] {
        assert!(matches!(
            request(bad).await.unwrap_err(),
            fleet_application::lab::LabUseCaseError::Invalid { .. }
        ));
    }

    // The generic operation surface refuses the kind outright.
    assert!(
        fixture
            .operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &new,
            )
            .await
            .is_err()
    );

    // A caller without lab.artifacts can list, but not collect or download.
    let log = fixture
        .artifacts
        .record_exec_log(
            &fleet_auth::LanAllowAllAuthorizer,
            &principal,
            &fixture.lease_id,
            "op-1",
            "log\n",
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .unwrap();
    assert!(
        fixture
            .artifacts
            .list(
                &DenyArtifacts,
                &principal,
                fleet_application::lab_artifacts::ArtifactFilter::default(),
                50,
            )
            .await
            .is_ok()
    );
    assert!(matches!(
        fixture
            .artifacts
            .open(&DenyArtifacts, &principal, &log.id)
            .await
            .err(),
        Some(fleet_application::lab::LabUseCaseError::Denied(_))
    ));
    assert!(matches!(
        fixture
            .artifacts
            .request_collect(
                &DenyArtifacts,
                &principal,
                &fixture.lease_id,
                &["/var/log/syslog".to_owned()],
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await
            .unwrap_err(),
        fleet_application::lab::LabUseCaseError::Denied(_)
    ));
    assert!(
        fixture
            .operations
            .create_lab_collect(
                &DenyArtifacts,
                fleet_auth::LAN_PRINCIPAL_ID,
                &fixture.lease_id,
                &new,
            )
            .await
            .is_err()
    );

    // A tampered blob is refused on download, never served.
    std::fs::write(fixture.store.root().join(&log.location), b"gol\n").unwrap();
    assert!(matches!(
        fixture
            .artifacts
            .open(&fleet_auth::LanAllowAllAuthorizer, &principal, &log.id)
            .await
            .err(),
        Some(fleet_application::lab::LabUseCaseError::Conflict { .. })
    ));
}

#[tokio::test]
async fn a_store_failure_is_recorded_without_its_backend_text() {
    let fixture = Fixture::new().await;
    // The lease points at a provision record that cannot be read.
    let mut lease = fixture.leases.get(&fixture.lease_id).await.unwrap();
    lease.provision_id = Some("record-that-does-not-exist".to_owned());
    fixture.leases.update(&lease).await.unwrap();

    let refused = fixture.collect(&["/var/log/syslog"]).await;
    assert_eq!(refused.state, "failed");
    let error = refused.error_json.unwrap();
    assert!(error.contains("provision_unavailable"), "{error}");
    assert!(!error.contains("record-that-does-not-exist"), "{error}");
    let failure = fixture
        .artifacts
        .collection_failure(
            &fleet_auth::LanAllowAllAuthorizer,
            &Fixture::principal(),
            &fixture.lease_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failure.reason, "provision_unavailable");
    assert!(
        failure.detail.contains("controller log"),
        "{}",
        failure.detail
    );
    assert!(!failure.detail.contains("not found"), "{}", failure.detail);
}

/// Grants `lab.artifacts` on one lease only, as a lease-scoped policy would.
#[derive(Debug)]
struct ArtifactsOnLease(String);

impl fleet_application::authz::Authorizer for ArtifactsOnLease {
    fn decide(
        &self,
        request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        if request.action != fleet_application::authz::Permission::LabArtifacts
            || request.resource == Some(self.0.as_str())
        {
            fleet_application::authz::Decision::allow()
        } else {
            fleet_application::authz::Decision::deny(
                fleet_application::authz::ReasonId::UnknownPrincipal,
            )
        }
    }
}

#[tokio::test]
async fn a_download_is_authorized_on_the_artifacts_lease() {
    let fixture = Fixture::new().await;
    let principal = Fixture::principal();
    let log = fixture
        .artifacts
        .record_exec_log(
            &fleet_auth::LanAllowAllAuthorizer,
            &principal,
            &fixture.lease_id,
            "op-1",
            "log\n",
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .unwrap();
    // Granted on the artifact's lease: served.
    assert!(
        fixture
            .artifacts
            .open(
                &ArtifactsOnLease(fixture.lease_id.clone()),
                &principal,
                &log.id
            )
            .await
            .is_ok()
    );
    // Granted on another lease only (or on the artifact id): refused.
    for scope in ["another-lease".to_owned(), log.id.clone()] {
        assert!(matches!(
            fixture
                .artifacts
                .open(&ArtifactsOnLease(scope), &principal, &log.id)
                .await
                .err(),
            Some(fleet_application::lab::LabUseCaseError::Denied(_))
        ));
    }
}
