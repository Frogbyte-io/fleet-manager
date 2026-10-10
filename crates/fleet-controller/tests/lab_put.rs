//! #393: `lab put`. A file is streamed into controller staging (capped while
//! streaming), queued as a `lab.put` operation that carries only its id,
//! size, and SHA-256, copied into a ready lease's guest by the executor, and
//! its staging file removed whichever way the operation ends. Real SQLite
//! repositories, the real upload store and dispatch; SSH is replaced by a
//! recorder that mirrors the guest script's policy (no clobber unless
//! overwriting, SHA-256 verified before the file is placed).

use std::collections::HashMap;
use std::io::Read as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use fleet_application::authz::{
    AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, ReasonId,
};
use fleet_application::lab::{
    LabTemplate, LabTemplatePort, LabTemplateVersion, LabUseCaseError, LeasePort, NewLabTemplate,
    NewLease, NewProvision, ProvisionPort,
};
use fleet_application::lab_put::{LabPuts, PutTarget, StagedUpload};
use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::operation::{NewOperation, Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_controller::lab_artifacts_store::{GuestFiles, GuestPut, StagingFile};
use fleet_controller::lab_put_store::{FsUploadStore, LabPutDispatch};
use fleet_core::{CleanupStrategy, LabTemplateContent, LeaseState, ReadinessProbe};
use fleet_provider_ssh::{FetchOutcome, PutOutcome};
use fleet_storage_sqlite::{
    AuditSink, LabRepository, LeaseRepository, MachineRepository, OperationRepository,
    ProxmoxAccountRepository, RecipeRepository, Store,
};

const MAX_BYTES: u64 = 4096;

/// Stands in for the SSH exec executor (unused here beyond cleanup wiring).
#[derive(Debug, Default)]
struct Ssh;

#[async_trait]
impl OperationExecutor for Ssh {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        operations
            .complete(&operation.id, "succeeded", Some(r#"{"exitCode":0}"#), None)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// How the recorder behaves for the next put.
#[derive(Debug, Default)]
enum Behavior {
    /// Mirror the guest script's policy.
    #[default]
    Policy,
    /// Answer this outcome without storing anything.
    Outcome(PutOutcome),
    /// Fail the transport.
    Transport(String),
}

/// Stands in for the guest.
#[derive(Debug, Default)]
struct Guest {
    files: Mutex<HashMap<String, Vec<u8>>>,
    behavior: Mutex<Behavior>,
    /// What the executor asked for, last first seen.
    requests: Mutex<Vec<GuestPut>>,
}

#[async_trait]
impl GuestFiles for Guest {
    async fn fetch(
        &self,
        _machine_id: &str,
        _endpoint_id: &str,
        _guest_os: fleet_core::GuestOs,
        path: &str,
        _max_bytes: u64,
        _deadline: Duration,
        mut sink: StagingFile,
    ) -> (Result<FetchOutcome, String>, StagingFile) {
        use std::io::Write as _;
        let found = self.files.lock().unwrap().get(path).cloned();
        let outcome = match found {
            None => Ok(FetchOutcome::Missing),
            Some(bytes) => sink
                .write_all(&bytes)
                .map(|()| FetchOutcome::Fetched {
                    bytes: bytes.len() as u64,
                })
                .map_err(|error| error.to_string()),
        };
        (outcome, sink)
    }

    async fn put(
        &self,
        _machine_id: &str,
        _endpoint_id: &str,
        request: GuestPut,
        _deadline: Duration,
        mut source: std::fs::File,
    ) -> Result<PutOutcome, String> {
        self.requests.lock().unwrap().push(request.clone());
        match &*self.behavior.lock().unwrap() {
            Behavior::Outcome(outcome) => return Ok(outcome.clone()),
            Behavior::Transport(error) => return Err(error.clone()),
            Behavior::Policy => {}
        }
        let mut bytes = Vec::new();
        source.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        let mut files = self.files.lock().unwrap();
        if files.contains_key(&request.path) && !request.overwrite {
            return Ok(PutOutcome::TargetExists);
        }
        if sha(&bytes) != request.sha256 {
            return Ok(PutOutcome::HashMismatch);
        }
        files.insert(request.path.clone(), bytes.clone());
        Ok(PutOutcome::Put {
            bytes: bytes.len() as u64,
        })
    }
}

fn sha(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        })
}

struct Fixture {
    _store: Store,
    _dir: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    leases: Arc<LeaseRepository>,
    operations: Arc<Operations>,
    puts: Arc<LabPuts>,
    store: Arc<FsUploadStore>,
    guest: Arc<Guest>,
    dispatch: LabPutDispatch,
    lease_id: String,
}

impl Fixture {
    /// A ready lease whose guest is a registered Lab machine.
    async fn new() -> Self {
        Self::with_os(fleet_core::GuestOs::Linux).await
    }

    /// The same, for a template that declares the guest OS.
    async fn with_os(guest_os: fleet_core::GuestOs) -> Self {
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
            guest_os,
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
        let upload_store =
            Arc::new(FsUploadStore::open(&dir.path().join("lab-artifacts"), MAX_BYTES).unwrap());
        let puts = Arc::new(LabPuts::new(
            upload_store.clone(),
            leases.clone(),
            labs.clone(),
            labs.clone(),
            Arc::new(AuditSink::new(pool.clone())),
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
        let dispatch = LabPutDispatch::new(
            Arc::new(lab_dispatch),
            upload_store.clone(),
            leases.clone(),
            labs.clone(),
            guest.clone(),
        );
        Self {
            _store: store,
            _dir: dir,
            pool,
            leases,
            operations,
            puts,
            store: upload_store,
            guest,
            dispatch,
            lease_id: lease.id,
        }
    }

    fn principal() -> ActingPrincipal {
        ActingPrincipal {
            id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        }
    }

    /// Streams `bytes` through the use case in `chunk`-sized writes and
    /// queues the operation, as the route does.
    async fn upload(
        &self,
        authorizer: &dyn Authorizer,
        guest_path: &str,
        overwrite: bool,
        bytes: &[u8],
    ) -> Result<(Operation, StagedUpload), LabUseCaseError> {
        let target = PutTarget {
            lease_id: &self.lease_id,
            guest_path,
            overwrite,
        };
        let now = fleet_core::SystemClock::now_unix_millis();
        let mut writer = self
            .puts
            .begin_upload(authorizer, &Self::principal(), &target, now)
            .await?;
        for chunk in bytes.chunks(512) {
            writer
                .write(chunk)
                .await
                .map_err(|error| LabUseCaseError::Invalid {
                    detail: error.to_string(),
                })?;
        }
        let staged = writer.finish().await.unwrap();
        let new = self
            .puts
            .request_put(authorizer, &Self::principal(), &target, &staged, now)
            .await?;
        let created = self
            .operations
            .create_lab_put(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &self.lease_id,
                &new,
            )
            .await
            .unwrap();
        Ok((created, staged))
    }

    async fn run(&self, created: &Operation) -> Operation {
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

    async fn put(&self, guest_path: &str, overwrite: bool, bytes: &[u8]) -> Operation {
        let (created, _) = self
            .upload(
                &fleet_auth::LanAllowAllAuthorizer,
                guest_path,
                overwrite,
                bytes,
            )
            .await
            .unwrap();
        self.run(&created).await
    }

    async fn audit_events(&self) -> Vec<String> {
        sqlx::query_scalar::<_, String>("SELECT metadata_json FROM audit_events ORDER BY seq")
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default()
    }

    fn staged_files(&self) -> usize {
        std::fs::read_dir(self.store.dir()).unwrap().count()
    }

    fn guest_file(&self, path: &str) -> Option<Vec<u8>> {
        self.guest.files.lock().unwrap().get(path).cloned()
    }
}

/// Denies exactly one permission.
#[derive(Debug)]
struct Deny(Permission);

impl Authorizer for Deny {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.action == self.0 {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

fn error_of(done: &Operation) -> serde_json::Value {
    serde_json::from_str(done.error_json.as_deref().unwrap()).unwrap()
}

const SECRET_CONTENT: &[u8] = b"CONTENT-MARKER-hunter2-installer-bytes";

#[tokio::test]
async fn a_put_copies_the_file_records_size_and_digest_and_leaks_no_content() {
    let fixture = Fixture::new().await;
    let done = fixture.put("/opt/qa/app.deb", false, SECRET_CONTENT).await;
    assert_eq!(done.state, "succeeded", "{done:?}");
    assert_eq!(
        fixture.guest_file("/opt/qa/app.deb").as_deref(),
        Some(SECRET_CONTENT)
    );

    let result: serde_json::Value =
        serde_json::from_str(done.result_json.as_deref().unwrap()).unwrap();
    assert_eq!(result["guestPath"], "/opt/qa/app.deb");
    assert_eq!(result["sizeBytes"], SECRET_CONTENT.len());
    assert_eq!(result["sha256"], sha(SECRET_CONTENT));

    // No file content in the payload, result, or audit trail.
    let payload = done.payload_json.clone().unwrap();
    assert!(payload.contains(&sha(SECRET_CONTENT)));
    for text in [&payload, done.result_json.as_ref().unwrap()]
        .into_iter()
        .chain(fixture.audit_events().await.iter())
    {
        assert!(!text.contains("CONTENT-MARKER"), "{text}");
    }
    let audit = fixture.audit_events().await;
    assert!(audit.iter().any(|event| event.contains("lab_put_requested")
        && event.contains(&sha(SECRET_CONTENT))
        && event.contains("/opt/qa/app.deb")));
    // The staging file is gone once the operation finished.
    assert_eq!(fixture.staged_files(), 0);
}

#[tokio::test]
async fn an_existing_target_is_refused_unless_overwrite_is_requested() {
    let fixture = Fixture::new().await;
    assert_eq!(
        fixture.put("/opt/a.bin", false, b"one").await.state,
        "succeeded"
    );

    let refused = fixture.put("/opt/a.bin", false, b"two").await;
    assert_eq!(refused.state, "failed");
    assert_eq!(error_of(&refused)["reason"], "target_exists");
    assert_eq!(
        fixture.guest_file("/opt/a.bin").as_deref(),
        Some(&b"one"[..])
    );
    assert_eq!(fixture.staged_files(), 0);

    let replaced = fixture.put("/opt/a.bin", true, b"two").await;
    assert_eq!(replaced.state, "succeeded");
    assert_eq!(
        fixture.guest_file("/opt/a.bin").as_deref(),
        Some(&b"two"[..])
    );
    let result: serde_json::Value =
        serde_json::from_str(replaced.result_json.as_deref().unwrap()).unwrap();
    assert_eq!(result["overwrite"], true);
}

#[tokio::test]
async fn a_hash_mismatch_in_the_guest_fails_and_cleans_staging() {
    let fixture = Fixture::new().await;
    *fixture.guest.behavior.lock().unwrap() = Behavior::Outcome(PutOutcome::HashMismatch);
    let done = fixture.put("/opt/a.bin", false, b"payload").await;
    assert_eq!(done.state, "failed");
    let error = error_of(&done);
    assert_eq!(error["reason"], "hash_mismatch");
    assert!(
        error["detail"]
            .as_str()
            .unwrap()
            .contains("nothing was left")
    );
    assert!(done.result_json.is_none());
    assert_eq!(fixture.staged_files(), 0);
}

#[tokio::test]
async fn every_guest_refusal_has_a_stable_reason_and_cleans_staging() {
    let fixture = Fixture::new().await;
    for (outcome, reason) in [
        (PutOutcome::TargetNotFile, "target_not_file"),
        (PutOutcome::NoDirectory, "no_directory"),
        (PutOutcome::DirectoryNotWritable, "directory_not_writable"),
        (PutOutcome::SizeMismatch, "size_mismatch"),
        (PutOutcome::DeadlineKilled, "deadline_exceeded"),
        (
            PutOutcome::Failed {
                exit_code: Some(70),
            },
            "copy_failed",
        ),
        (
            PutOutcome::SourceFailed {
                detail: "gone".to_owned(),
            },
            "upload_unavailable",
        ),
    ] {
        *fixture.guest.behavior.lock().unwrap() = Behavior::Outcome(outcome);
        let done = fixture.put("/opt/a.bin", false, b"payload").await;
        assert_eq!(done.state, "failed");
        assert_eq!(error_of(&done)["reason"], reason);
        assert_eq!(fixture.staged_files(), 0, "{reason}");
    }
    // A transport error is scrubbed of anything the tool printed.
    *fixture.guest.behavior.lock().unwrap() =
        Behavior::Transport("ssh failed for https://bot:hunter2@host/x".to_owned());
    let done = fixture.put("/opt/a.bin", false, b"payload").await;
    let error = error_of(&done);
    assert_eq!(error["reason"], "transfer_failed");
    assert!(!done.error_json.as_deref().unwrap().contains("hunter2"));
    assert_eq!(fixture.staged_files(), 0);
}

#[tokio::test]
async fn an_upload_past_the_cap_is_refused_while_streaming_and_leaves_nothing() {
    let fixture = Fixture::new().await;
    let target = PutTarget {
        lease_id: &fixture.lease_id,
        guest_path: "/opt/big.bin",
        overwrite: false,
    };
    let mut writer = fixture
        .puts
        .begin_upload(
            &fleet_auth::LanAllowAllAuthorizer,
            &Fixture::principal(),
            &target,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .unwrap();
    assert_eq!(fixture.staged_files(), 1);
    // The cap is exact: MAX_BYTES bytes fit, one more does not, and the
    // refusal comes at the chunk that crosses it, not after the whole body.
    let chunk = vec![7_u8; 1024];
    let mut accepted = 0_u64;
    let mut refused_at = None;
    for index in 0..1000_u64 {
        match writer.write(&chunk).await {
            Ok(()) => accepted += chunk.len() as u64,
            Err(error) => {
                assert_eq!(
                    error,
                    fleet_application::lab_artifacts::BlobError::TooLarge {
                        max_bytes: MAX_BYTES
                    }
                );
                refused_at = Some(index);
                break;
            }
        }
    }
    assert_eq!(accepted, MAX_BYTES);
    assert_eq!(refused_at, Some(MAX_BYTES / 1024));
    // The partial file goes when the writer does.
    drop(writer);
    assert_eq!(fixture.staged_files(), 0);

    // Exactly the cap is fine.
    let done = fixture
        .put("/opt/exact.bin", false, &vec![1_u8; MAX_BYTES as usize])
        .await;
    assert_eq!(done.state, "succeeded");
    assert_eq!(fixture.staged_files(), 0);
}

#[tokio::test]
async fn an_unfinished_upload_is_removed_when_dropped() {
    let fixture = Fixture::new().await;
    let target = PutTarget {
        lease_id: &fixture.lease_id,
        guest_path: "/opt/a.bin",
        overwrite: false,
    };
    let mut writer = fixture
        .puts
        .begin_upload(
            &fleet_auth::LanAllowAllAuthorizer,
            &Fixture::principal(),
            &target,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .unwrap();
    writer.write(b"partial").await.unwrap();
    assert_eq!(fixture.staged_files(), 1);
    drop(writer);
    assert_eq!(fixture.staged_files(), 0);
}

#[tokio::test]
async fn a_finished_upload_that_is_refused_at_queue_time_is_discarded() {
    let fixture = Fixture::new().await;
    // A staged upload that cannot be queued (here: a bad digest) is removed
    // by `request_put`, never left behind.
    let target = PutTarget {
        lease_id: &fixture.lease_id,
        guest_path: "/opt/a.bin",
        overwrite: false,
    };
    let mut writer = fixture
        .puts
        .begin_upload(
            &fleet_auth::LanAllowAllAuthorizer,
            &Fixture::principal(),
            &target,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .unwrap();
    writer.write(b"abc").await.unwrap();
    let mut staged = writer.finish().await.unwrap();
    assert_eq!(fixture.staged_files(), 1);
    staged.sha256 = "NOT-HEX".to_owned();
    let refused = fixture
        .puts
        .request_put(
            &fleet_auth::LanAllowAllAuthorizer,
            &Fixture::principal(),
            &target,
            &staged,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .unwrap_err();
    assert!(matches!(refused, LabUseCaseError::Invalid { .. }));
    assert_eq!(fixture.staged_files(), 0);
}

#[tokio::test]
async fn guest_paths_follow_the_collect_rules() {
    let fixture = Fixture::new().await;
    for bad in [
        "relative/file",
        "/",
        "/tmp/../etc/shadow",
        "/tmp/./x",
        "/tmp//x",
        "/tmp/x/",
        "/tmp/x\ny",
        "/tmp/x\0",
        &format!("/{}", "a".repeat(1024)),
    ] {
        let refused = fixture
            .upload(&fleet_auth::LanAllowAllAuthorizer, bad, false, b"x")
            .await
            .unwrap_err();
        assert!(
            matches!(refused, LabUseCaseError::Invalid { .. }),
            "{bad:?}"
        );
    }
    // Nothing was staged for any of them.
    assert_eq!(fixture.staged_files(), 0);
    assert!(fixture.guest.files.lock().unwrap().is_empty());
    // Shell metacharacters are plain path text; the guest never parses them.
    let done = fixture.put("/opt/it's $(x) `y`;z.bin", false, b"x").await;
    assert_eq!(done.state, "succeeded");
}

#[tokio::test]
async fn a_lease_that_is_not_ready_takes_no_upload() {
    let fixture = Fixture::new().await;
    let mut lease = fixture.leases.get(&fixture.lease_id).await.unwrap();
    lease.state = LeaseState::Releasing;
    fixture.leases.update(&lease).await.unwrap();
    let refused = fixture
        .upload(
            &fleet_auth::LanAllowAllAuthorizer,
            "/opt/a.bin",
            false,
            b"x",
        )
        .await
        .unwrap_err();
    assert!(matches!(refused, LabUseCaseError::Invalid { .. }));
    assert!(refused.to_string().contains("releasing"));
    assert_eq!(fixture.staged_files(), 0);

    // An unknown lease is not found.
    let target = PutTarget {
        lease_id: "no-such-lease",
        guest_path: "/opt/a.bin",
        overwrite: false,
    };
    assert!(matches!(
        fixture
            .puts
            .begin_upload(
                &fleet_auth::LanAllowAllAuthorizer,
                &Fixture::principal(),
                &target,
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await
            .err(),
        Some(LabUseCaseError::NotFound { .. })
    ));
}

#[tokio::test]
async fn a_lease_that_stopped_being_ready_fails_the_queued_put_and_cleans_staging() {
    let fixture = Fixture::new().await;
    let (created, _) = fixture
        .upload(
            &fleet_auth::LanAllowAllAuthorizer,
            "/opt/a.bin",
            false,
            b"x",
        )
        .await
        .unwrap();
    assert_eq!(fixture.staged_files(), 1);
    let mut lease = fixture.leases.get(&fixture.lease_id).await.unwrap();
    lease.state = LeaseState::Releasing;
    fixture.leases.update(&lease).await.unwrap();
    let done = fixture.run(&created).await;
    assert_eq!(done.state, "failed");
    assert_eq!(error_of(&done)["reason"], "lease_not_ready");
    assert!(fixture.guest.requests.lock().unwrap().is_empty());
    assert_eq!(fixture.staged_files(), 0);
}

#[tokio::test]
async fn a_missing_staging_file_fails_the_put_without_touching_the_guest() {
    let fixture = Fixture::new().await;
    let (created, staged) = fixture
        .upload(
            &fleet_auth::LanAllowAllAuthorizer,
            "/opt/a.bin",
            false,
            b"abc",
        )
        .await
        .unwrap();
    std::fs::remove_file(fixture.store.dir().join(&staged.id)).unwrap();
    let done = fixture.run(&created).await;
    assert_eq!(done.state, "failed");
    assert_eq!(error_of(&done)["reason"], "upload_unavailable");
    assert!(fixture.guest.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_staging_file_that_changed_size_is_never_sent() {
    let fixture = Fixture::new().await;
    let (created, staged) = fixture
        .upload(
            &fleet_auth::LanAllowAllAuthorizer,
            "/opt/a.bin",
            false,
            b"abc",
        )
        .await
        .unwrap();
    std::fs::write(fixture.store.dir().join(&staged.id), b"abcdef").unwrap();
    let done = fixture.run(&created).await;
    assert_eq!(done.state, "failed");
    assert_eq!(error_of(&done)["reason"], "upload_unavailable");
    assert!(fixture.guest.requests.lock().unwrap().is_empty());
    assert_eq!(fixture.staged_files(), 0);
}

#[tokio::test]
async fn putting_needs_the_lab_put_permission_on_every_step() {
    let fixture = Fixture::new().await;
    // The use case refuses before any byte is staged.
    let denied = fixture
        .upload(&Deny(Permission::LabPut), "/opt/a.bin", false, b"x")
        .await
        .unwrap_err();
    assert!(matches!(denied, LabUseCaseError::Denied(_)));
    assert_eq!(fixture.staged_files(), 0);

    // Only `lab.put` governs the action: a caller denied the sibling
    // permissions can still put.
    for sibling in [Permission::LabArtifacts, Permission::LabExec] {
        assert!(
            fixture
                .upload(&Deny(sibling), "/opt/a.bin", true, b"x")
                .await
                .is_ok()
        );
    }

    // Queueing is authorized too, and the generic route refuses the kind.
    let new = NewOperation {
        kind: "lab.put".to_owned(),
        idempotency_key: None,
        deadline_at: None,
        correlation_id: None,
        payload_json: Some(
            serde_json::json!({ "leaseId": fixture.lease_id, "guestPath": "/opt/a.bin" })
                .to_string(),
        ),
        review_token: None,
    };
    assert!(
        fixture
            .operations
            .create_lab_put(
                &Deny(Permission::LabPut),
                fleet_auth::LAN_PRINCIPAL_ID,
                &fixture.lease_id,
                &new,
            )
            .await
            .is_err()
    );
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
}

#[tokio::test]
async fn opening_the_store_reclaims_what_a_previous_run_left_behind() {
    let dir = tempfile::tempdir().unwrap();
    let uploads = dir.path().join("uploads");
    std::fs::create_dir_all(&uploads).unwrap();
    std::fs::write(uploads.join("leftover"), b"x").unwrap();
    let store = FsUploadStore::open(dir.path(), 10).unwrap();
    assert_eq!(std::fs::read_dir(store.dir()).unwrap().count(), 0);
}

#[tokio::test]
async fn uploads_in_flight_and_staged_bytes_are_bounded() {
    use fleet_application::lab_artifacts::BlobError;
    use fleet_application::lab_put::UploadStagePort as _;
    let dir = tempfile::tempdir().unwrap();
    let store = FsUploadStore::open(dir.path(), 100).unwrap();
    // Only so many uploads are written at once.
    let mut writers = Vec::new();
    for _ in 0..fleet_controller::lab_put_store::MAX_CONCURRENT_UPLOADS {
        writers.push(store.begin().await.unwrap());
    }
    assert!(matches!(
        store.begin().await.err(),
        Some(BlobError::Busy { .. })
    ));
    // Finished uploads stay staged and count against the total budget
    // (concurrency x cap = 400 bytes).
    let mut staged = Vec::new();
    for mut writer in writers {
        writer.write(&[1_u8; 100]).await.unwrap();
        staged.push(writer.finish().await.unwrap());
    }
    let mut extra = store.begin().await.unwrap();
    assert!(matches!(
        extra.write(b"x").await.err(),
        Some(BlobError::Busy { .. })
    ));
    drop(extra);
    // Discarding frees the budget.
    store.discard(&staged[0].id).await;
    let mut again = store.begin().await.unwrap();
    again.write(&[2_u8; 100]).await.unwrap();
    drop(again);
    assert_eq!(std::fs::read_dir(store.dir()).unwrap().count(), 3);
}

#[tokio::test]
async fn a_windows_lease_takes_windows_paths_and_tells_the_executor_its_os() {
    let fixture = Fixture::with_os(fleet_core::GuestOs::Windows).await;
    let done = fixture
        .put(r"C:\Users\qa\app.msi", false, b"installer-bytes")
        .await;
    assert_eq!(done.state, "succeeded", "{done:?}");
    let payload: serde_json::Value =
        serde_json::from_str(done.payload_json.as_deref().unwrap()).unwrap();
    assert_eq!(payload["guestOs"], "windows");
    let requests = fixture.guest.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].guest_os, fleet_core::GuestOs::Windows);
    assert_eq!(requests[0].path, r"C:\Users\qa\app.msi");
    // Forward slashes name the same place and are accepted too.
    let slash = fixture.put("C:/Users/qa/other.msi", false, b"x").await;
    assert_eq!(slash.state, "succeeded");

    // Every refusal happens before a byte is accepted.
    for bad in [
        "/opt/a.bin",
        r"C:\Users\qa\NUL",
        r"C:\Users\qa\con.txt",
        r"\\server\share\f",
        r"\\?\C:\f",
        r"C:\Users\qa\f.txt:stream",
        r"C:\Users\..\f",
        r"C:\Users\qa\trailing.",
        "C:relative",
    ] {
        assert!(
            fixture
                .upload(&fleet_auth::LanAllowAllAuthorizer, bad, false, b"x")
                .await
                .is_err(),
            "{bad}"
        );
    }
    assert_eq!(fixture.staged_files(), 0);
}

#[tokio::test]
async fn a_linux_lease_refuses_windows_paths() {
    let fixture = Fixture::new().await;
    assert!(
        fixture
            .upload(
                &fleet_auth::LanAllowAllAuthorizer,
                r"C:\Users\qa\app.msi",
                false,
                b"x"
            )
            .await
            .is_err()
    );
    let done = fixture.put("/opt/a.bin", false, b"x").await;
    assert_eq!(done.state, "succeeded");
    assert_eq!(
        fixture.guest.requests.lock().unwrap()[0].guest_os,
        fleet_core::GuestOs::Linux
    );
}
