//! #394: detached Lab commands. Real SQLite repositories, the real
//! detached-exec use cases, the real `lab.exec_detach` dispatch, and the
//! provider's real guest scripts run under local bash against a temporary
//! directory standing in for the guest, so a started command is a genuine
//! detached process: it survives the controller objects that started it,
//! which is what the restart tests rely on.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fleet_application::authz::{
    AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, ReasonId,
};
use fleet_application::lab::{
    LabTemplate, LabTemplatePort, LabTemplateVersion, LabUseCaseError, LeasePort, NewLabTemplate,
    NewLease, NewProvision, ProvisionPort,
};
use fleet_application::lab_exec_detach::{
    DetachedExecPort as _, DetachedState, DetachedStatus, GuestExecPort, GuestProcess,
    LabExecDetach, PreparedStart, StartState,
};
use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_controller::lab_detach_store::{LabDetachDispatch, process_of};
use fleet_core::{CleanupStrategy, LabTemplateContent, LeaseState, ReadinessProbe};
use fleet_provider_ssh::detached::{
    TAIL_WINDOW_BYTES, parse_status, status_metadata, status_script,
};
use fleet_storage_sqlite::{
    AuditSink, DetachedExecRepository, LabRepository, LeaseRepository, MachineRepository,
    OperationRepository, ProxmoxAccountRepository, RecipeRepository, Store,
};

/// Stands in for the SSH exec executor: runs the payload's script and
/// arguments under local bash (the way the SSH session feeds them, with the
/// temporary guest directory appended as the base-directory argument) and
/// completes the operation as the real executor does.
#[derive(Debug)]
struct LocalBash {
    base: PathBuf,
}

#[async_trait]
impl OperationExecutor for LocalBash {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        use std::io::Write as _;
        let payload: serde_json::Value =
            serde_json::from_str(operation.payload_json.as_deref().unwrap()).unwrap();
        assert_eq!(
            operation.kind, "ssh.exec",
            "the dispatch hands over ssh.exec"
        );
        assert_eq!(payload["auth"]["type"], "agent");
        let mut args: Vec<String> = payload["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect();
        args.push(self.base.display().to_string());
        let mut child = std::process::Command::new("bash")
            .arg("-s")
            .arg("--")
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload["script"].as_str().unwrap().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let result = serde_json::json!({
            "exitCode": out.status.code(),
            "stdout": String::from_utf8_lossy(&out.stdout),
            "stderr": String::from_utf8_lossy(&out.stderr),
        })
        .to_string();
        let (state, result_json, error_json) = if out.status.code() == Some(0) {
            ("succeeded", Some(result.as_str()), None)
        } else {
            ("failed", None, Some(result.as_str()))
        };
        operations
            .complete(&operation.id, state, result_json, error_json)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// Reads the temporary guest directory with the provider's real status
/// script, counting its reads.
#[derive(Debug)]
struct LocalGuest {
    base: PathBuf,
    reads: AtomicUsize,
}

#[async_trait]
impl GuestExecPort for LocalGuest {
    async fn probe(&self, _: &str, _: &str, handle: &str) -> Result<GuestProcess, String> {
        use std::io::Write as _;
        self.reads.fetch_add(1, Ordering::SeqCst);
        let mut args = status_metadata(handle, TAIL_WINDOW_BYTES).arguments;
        args.push(self.base.display().to_string());
        let mut child = std::process::Command::new("bash")
            .arg("-s")
            .arg("--")
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(status_script().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(0));
        parse_status(&String::from_utf8(out.stdout).unwrap()).map(process_of)
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

const LAN: &str = fleet_auth::LAN_PRINCIPAL_ID;

fn lan() -> ActingPrincipal {
    ActingPrincipal { id: LAN.to_owned() }
}

/// A scoped credential of owner `ci-a`.
fn credential(owner: &str) -> ActingPrincipal {
    ActingPrincipal {
        id: format!("credential:{owner}:cred-1"),
    }
}

fn scoped() -> fleet_auth::ScopedAuthorizer {
    fleet_auth::ScopedAuthorizer::new(Arc::new(fleet_application::credentials::GrantBook::new()))
}

struct Fixture {
    _store: Store,
    dir: tempfile::TempDir,
    guest_base: PathBuf,
    pool: sqlx::SqlitePool,
    leases: Arc<LeaseRepository>,
    operations: Arc<Operations>,
    detach: LabExecDetach,
    guest: Arc<LocalGuest>,
    dispatch: LabDetachDispatch,
    lease_id: String,
}

impl Fixture {
    /// A ready lease owned by `owner`, whose guest is a registered Lab
    /// machine.
    async fn new(owner: &str) -> Self {
        Self::with_os(owner, fleet_core::GuestOs::Linux).await
    }

    /// The same, for a template that declares the guest OS.
    async fn with_os(owner: &str, guest_os: fleet_core::GuestOs) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let guest_base = dir.path().join("guest-exec");
        let now = fleet_core::SystemClock::now_unix_millis();
        let pool = store.pool().clone();
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
                    purpose: "detached".to_owned(),
                    project_id: None,
                    cleanup: CleanupStrategy::Destroy,
                    ttl_seconds: 3_600,
                },
                owner,
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
        drop(store);
        Self::open(dir, guest_base, lease.id).await
    }

    /// Opens the controller objects over the database in `dir`: a new
    /// controller instance when the database already exists.
    async fn open(dir: tempfile::TempDir, guest_base: PathBuf, lease_id: String) -> Self {
        // The previous instance's lock may take a moment to release.
        let mut attempts = 0;
        let store = loop {
            match Store::open(&dir.path().join("fleet.db")).await {
                Ok(store) => break store,
                Err(_) if attempts < 50 => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => panic!("the store must reopen: {error}"),
            }
        };
        let pool = store.pool().clone();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let leases = Arc::new(LeaseRepository::new(pool.clone()));
        let records = Arc::new(DetachedExecRepository::new(pool.clone()));
        let guest = Arc::new(LocalGuest {
            base: guest_base.clone(),
            reads: AtomicUsize::new(0),
        });
        let detach = LabExecDetach::new(
            records.clone(),
            guest.clone(),
            leases.clone(),
            labs.clone(),
            labs.clone(),
            Arc::new(AuditSink::new(pool.clone())),
        );
        let operations = Arc::new(Operations::new_with_events(
            Arc::new(OperationRepository::new(pool.clone())),
            Arc::new(AuditSink::new(pool.clone())),
            Arc::new(fleet_application::events::EventHub::new(64)),
        ));
        let lab_dispatch = fleet_controller::proxmox_exec::LabDispatch::new(
            Arc::new(LocalBash {
                base: guest_base.clone(),
            }),
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
        );
        let dispatch = LabDetachDispatch::new(
            Arc::new(lab_dispatch),
            records,
            leases.clone(),
            labs.clone(),
            labs.clone(),
        );
        Self {
            _store: store,
            dir,
            guest_base,
            pool,
            leases,
            operations,
            detach,
            guest,
            dispatch,
            lease_id,
        }
    }

    /// A new controller instance over the same database and guest, as after
    /// a restart. Everything the old instance held in memory is dropped.
    async fn restart(self) -> Self {
        let Self {
            _store,
            dir,
            guest_base,
            pool,
            leases,
            operations,
            detach,
            guest,
            dispatch,
            lease_id,
        } = self;
        drop((leases, operations, detach, guest, dispatch));
        pool.close().await;
        drop((pool, _store));
        Self::open(dir, guest_base, lease_id).await
    }

    async fn prepare(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        script: &str,
        timeout: Option<u64>,
        key: Option<&str>,
    ) -> Result<PreparedStart, LabUseCaseError> {
        self.detach
            .prepare_start(
                authorizer,
                principal,
                &self.lease_id,
                script,
                timeout,
                key,
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await
    }

    /// Queues and registers as the route does; answers the handle.
    async fn queue(&self, prepared: &PreparedStart) -> String {
        let created = self
            .operations
            .create_lab_exec_detach(
                &fleet_auth::LanAllowAllAuthorizer,
                LAN,
                &self.lease_id,
                &prepared.operation,
            )
            .await
            .unwrap();
        self.detach
            .register(
                &lan(),
                prepared,
                &created.id,
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await
            .unwrap();
        created.id
    }

    async fn run(&self, handle: &str) -> Operation {
        self.operations
            .claim_only_execute(&self.dispatch, handle, "test")
            .await
            .unwrap();
        self.operations
            .get(&fleet_auth::LanAllowAllAuthorizer, LAN, handle)
            .await
            .unwrap()
    }

    /// Prepares, queues, and runs the start; answers the handle.
    async fn start(&self, script: &str) -> String {
        let prepared = self
            .prepare(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan(),
                script,
                None,
                None,
            )
            .await
            .unwrap();
        let handle = self.queue(&prepared).await;
        let done = self.run(&handle).await;
        assert_eq!(done.state, "succeeded", "{done:?}");
        handle
    }

    async fn status(&self, handle: &str) -> DetachedStatus {
        self.detach
            .status(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan(),
                handle,
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await
            .unwrap()
    }

    async fn wait_for(&self, handle: &str, state: DetachedState) -> DetachedStatus {
        let started = Instant::now();
        loop {
            let status = self.status(handle).await;
            if status.state == state {
                return status;
            }
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "waited for {state:?}, last {status:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn set_lease(&self, change: impl FnOnce(&mut fleet_core::Lease)) {
        let mut lease = self.leases.get(&self.lease_id).await.unwrap();
        change(&mut lease);
        self.leases.update(&lease).await.unwrap();
    }

    async fn audit_events(&self) -> Vec<String> {
        sqlx::query_scalar::<_, String>("SELECT metadata_json FROM audit_events ORDER BY seq")
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default()
    }
}

#[tokio::test]
async fn a_command_runs_detached_polls_as_running_then_exited_with_its_code_and_output() {
    let fixture = Fixture::new("tester").await;
    let handle = fixture
        .start("echo out-line; echo err-line >&2; sleep 1; exit 7")
        .await;
    // The start operation ended long before the command did.
    let running = fixture.status(&handle).await;
    assert_eq!(running.state, DetachedState::Running, "{running:?}");
    assert!(!running.state.is_terminal());
    assert_eq!(running.exit_code, None);

    let exited = fixture.wait_for(&handle, DetachedState::Exited).await;
    assert!(exited.state.is_terminal());
    assert_eq!(exited.exit_code, Some(7));
    assert_eq!(exited.stdout, "out-line\n");
    assert_eq!(exited.stderr, "err-line\n");
    assert!(!exited.truncated_stdout && !exited.truncated_stderr);
    assert_eq!(exited.lease_id, fixture.lease_id);
    // The record turned `started`.
    let record = DetachedExecRepository::new(fixture.pool.clone())
        .get(&handle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.start_state, StartState::Started);
    assert!(record.started_at.is_some());
}

#[tokio::test]
async fn output_tails_are_scrubbed_bounded_and_keep_the_end() {
    let fixture = Fixture::new("tester").await;
    let handle = fixture
        .start(
            "echo 'cloned https://user:hunter2pw@host.invalid/repo'; \
             head -c 60000 /dev/zero | tr '\\0' 'x' | fold -w 80; echo; echo THE-END",
        )
        .await;
    let exited = fixture.wait_for(&handle, DetachedState::Exited).await;
    assert!(exited.stdout_bytes > 60_000);
    assert!(exited.truncated_stdout);
    assert!(exited.stdout.starts_with('…'));
    assert!(
        exited.stdout.trim_end().ends_with("THE-END"),
        "{}",
        exited.stdout
    );
    assert!(exited.stdout.len() <= fleet_core::RESULT_STRING_BOUND + 8);

    // The credential, in a short stream, is masked in the tail.
    let handle = fixture
        .start("echo 'cloned https://user:hunter2pw@host.invalid/repo'")
        .await;
    let exited = fixture.wait_for(&handle, DetachedState::Exited).await;
    assert!(!exited.stdout.contains("hunter2"), "{}", exited.stdout);
    assert!(
        exited.stdout.contains("***@host.invalid"),
        "{}",
        exited.stdout
    );
}

#[tokio::test]
async fn a_retry_with_the_same_key_returns_the_same_handle_and_runs_once() {
    let fixture = Fixture::new("tester").await;
    let marker = fixture.dir.path().join("runs");
    let script = format!("echo x >> {}; sleep 1", marker.display());
    let key = Some("run-7");
    let first = fixture
        .prepare(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &script,
            None,
            key,
        )
        .await
        .unwrap();
    let handle = fixture.queue(&first).await;
    let retry = fixture
        .prepare(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &script,
            None,
            key,
        )
        .await
        .unwrap();
    let again = fixture.queue(&retry).await;
    assert_eq!(
        again, handle,
        "the retry returns the original operation's handle"
    );
    fixture.run(&handle).await;
    fixture.wait_for(&handle, DetachedState::Exited).await;
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "x\n");
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM lab_detached_execs")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
}

#[tokio::test]
async fn the_command_text_is_in_no_record_audit_event_or_result() {
    let fixture = Fixture::new("tester").await;
    let script = "echo COMMAND-MARKER-hunter2";
    let handle = fixture.start(script).await;
    fixture.wait_for(&handle, DetachedState::Exited).await;
    let record: (String, i64, String) = sqlx::query_as(
        "SELECT command_sha256, command_bytes, handle FROM lab_detached_execs WHERE handle = ?1",
    )
    .bind(&handle)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(
        record.0,
        fleet_application::lab_exec_detach::sha256_hex(script.as_bytes())
    );
    assert_eq!(record.1 as usize, script.len());
    let row_text: String = sqlx::query_scalar(
        "SELECT handle || lease_id || owner || command_sha256 || start_state FROM lab_detached_execs",
    )
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert!(!row_text.contains("COMMAND-MARKER"));
    let audit = fixture.audit_events().await;
    assert!(
        audit
            .iter()
            .any(|event| event.contains("lab_exec_detach_requested")
                && event.contains(&record.0)
                && event.contains("commandBytes")),
        "{audit:?}"
    );
    assert!(
        audit
            .iter()
            .any(|event| event.contains("lab_exec_status_read")),
        "{audit:?}"
    );
    for event in &audit {
        assert!(!event.contains("COMMAND-MARKER"), "{event}");
    }
    let done = fixture
        .operations
        .get(&fleet_auth::LanAllowAllAuthorizer, LAN, &handle)
        .await
        .unwrap();
    assert!(!done.result_json.unwrap().contains("COMMAND-MARKER"));
}

#[tokio::test]
async fn a_killed_wrapper_is_lost_without_an_exit_code() {
    let fixture = Fixture::new("tester").await;
    let handle = fixture.start("sleep 29.31").await;
    let pid_text = std::fs::read_to_string(fixture.guest_base.join(&handle).join("pid")).unwrap();
    let pid = pid_text.split_whitespace().next().unwrap();
    std::process::Command::new("kill")
        .args(["-9", pid])
        .status()
        .unwrap();
    let lost = fixture.wait_for(&handle, DetachedState::Lost).await;
    assert_eq!(lost.reason.as_deref(), Some("process_gone"));
    assert_eq!(lost.exit_code, None);
    assert!(lost.state.is_terminal());
    let _ = std::process::Command::new("pkill")
        .args(["-f", "sleep 29.31"])
        .status();

    // A guest that rebooted (a different boot id) reads the same way.
    let handle = fixture.start("sleep 29.32").await;
    std::fs::write(
        fixture.guest_base.join(&handle).join("boot_id"),
        "other-boot\n",
    )
    .unwrap();
    let lost = fixture.status(&handle).await;
    assert_eq!(lost.state, DetachedState::Lost);
    assert_eq!(lost.reason.as_deref(), Some("guest_rebooted"));
    let _ = std::process::Command::new("pkill")
        .args(["-f", "sleep 29.32"])
        .status();
}

#[tokio::test]
async fn releasing_a_lease_while_a_command_runs_answers_lease_ended_without_dialing_the_guest() {
    let fixture = Fixture::new("tester").await;
    let handle = fixture.start("sleep 29.41").await;
    assert_eq!(fixture.status(&handle).await.state, DetachedState::Running);

    for (state, expected) in [
        (LeaseState::Releasing, "releasing"),
        (LeaseState::Released, "released"),
        (LeaseState::CleanupFailed, "cleanup_failed"),
    ] {
        fixture.set_lease(|lease| lease.state = state).await;
        let reads = fixture.guest.reads.load(Ordering::SeqCst);
        let ended = fixture.status(&handle).await;
        assert_eq!(ended.state, DetachedState::LeaseEnded, "{state:?}");
        assert!(ended.state.is_terminal());
        assert_eq!(ended.lease_state.as_deref(), Some(expected));
        assert_eq!(ended.exit_code, None);
        assert_eq!(
            fixture.guest.reads.load(Ordering::SeqCst),
            reads,
            "a ended lease's guest is never dialed"
        );
    }
    // A ready lease past its expiry, not yet swept, is ended too.
    fixture
        .set_lease(|lease| {
            lease.state = LeaseState::Ready;
            lease.expires_at = Some(fleet_core::SystemClock::now_unix_millis() - 1_000);
        })
        .await;
    assert_eq!(
        fixture.status(&handle).await.state,
        DetachedState::LeaseEnded
    );
    // Starting on an ended lease is refused.
    let refused = fixture
        .prepare(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            "true",
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(refused, LabUseCaseError::Invalid { .. }),
        "{refused:?}"
    );
    let _ = std::process::Command::new("pkill")
        .args(["-f", "sleep 29.41"])
        .status();
}

#[tokio::test]
async fn a_controller_restart_while_a_command_runs_loses_no_handle() {
    let fixture = Fixture::new("tester").await;
    let handle = fixture.start("sleep 2; echo survived; exit 3").await;
    assert_eq!(fixture.status(&handle).await.state, DetachedState::Running);

    // A new controller instance over the same database.
    let restarted = fixture.restart().await;
    let status = restarted.status(&handle).await;
    assert!(
        matches!(status.state, DetachedState::Running | DetachedState::Exited),
        "{status:?}"
    );
    let exited = restarted.wait_for(&handle, DetachedState::Exited).await;
    assert_eq!(exited.exit_code, Some(3));
    assert_eq!(exited.stdout, "survived\n");
}

#[tokio::test]
async fn a_restart_before_the_start_ran_or_between_queueing_and_registering() {
    let fixture = Fixture::new("tester").await;
    // Queued and registered, but the controller dies before the worker ran it.
    let prepared = fixture
        .prepare(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            "echo hello",
            None,
            None,
        )
        .await
        .unwrap();
    let queued = fixture.queue(&prepared).await;
    // Queued, but the controller dies before registering: the executor
    // registers it from the payload.
    let unregistered_prepared = fixture
        .prepare(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            "echo unregistered",
            None,
            None,
        )
        .await
        .unwrap();
    let unregistered = fixture
        .operations
        .create_lab_exec_detach(
            &fleet_auth::LanAllowAllAuthorizer,
            LAN,
            &fixture.lease_id,
            &unregistered_prepared.operation,
        )
        .await
        .unwrap()
        .id;
    let restarted = fixture.restart().await;
    let status = restarted.status(&queued).await;
    assert_eq!(status.state, DetachedState::Starting, "{status:?}");
    assert!(!status.state.is_terminal());
    // The unregistered handle is unknown to the record until the executor ran.
    let missing = restarted
        .detach
        .status(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &unregistered,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .unwrap_err();
    assert!(matches!(missing, LabUseCaseError::NotFound { .. }));

    for handle in [&queued, &unregistered] {
        let done = restarted.run(handle).await;
        assert_eq!(done.state, "succeeded", "{done:?}");
        let exited = restarted.wait_for(handle, DetachedState::Exited).await;
        assert_eq!(exited.exit_code, Some(0));
    }
    let exited = restarted.status(&unregistered).await;
    assert_eq!(exited.stdout, "unregistered\n");
}

#[tokio::test]
async fn a_start_that_cannot_run_is_failed_to_start_and_terminal() {
    let fixture = Fixture::new("tester").await;
    let prepared = fixture
        .prepare(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            "true",
            None,
            None,
        )
        .await
        .unwrap();
    let handle = fixture.queue(&prepared).await;
    // The lease ends between queueing and execution.
    fixture
        .set_lease(|lease| lease.state = LeaseState::Releasing)
        .await;
    let done = fixture.run(&handle).await;
    assert_eq!(done.state, "failed", "{done:?}");
    assert!(done.error_json.unwrap().contains("lease_not_ready"));
    // The lease is ready again (a different test of the answer's order).
    fixture
        .set_lease(|lease| lease.state = LeaseState::Ready)
        .await;
    let status = fixture.status(&handle).await;
    assert_eq!(status.state, DetachedState::FailedToStart, "{status:?}");
    assert!(status.state.is_terminal());
    assert_eq!(status.reason.as_deref(), Some("start_failed"));
}

#[tokio::test]
async fn the_bound_never_reaches_past_the_lease() {
    let fixture = Fixture::new("tester").await;
    // An hour left: the default is the rest of the TTL, and a larger ask is capped.
    let default = fixture
        .prepare(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            "true",
            None,
            None,
        )
        .await
        .unwrap();
    assert!((3_590..=3_600).contains(&default.timeout_seconds));
    let capped = fixture
        .prepare(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            "true",
            Some(86_400),
            None,
        )
        .await
        .unwrap();
    assert!(capped.timeout_seconds <= 3_600);
    let short = fixture
        .prepare(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            "true",
            Some(30),
            None,
        )
        .await
        .unwrap();
    assert_eq!(short.timeout_seconds, 30);
    // 0 is refused; a lease about to expire refuses a start.
    assert!(
        fixture
            .prepare(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan(),
                "true",
                Some(0),
                None
            )
            .await
            .is_err()
    );
    let now = fleet_core::SystemClock::now_unix_millis();
    fixture
        .set_lease(|lease| lease.expires_at = Some(now + 120_000))
        .await;
    let nearly = fixture
        .prepare(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            "true",
            Some(900),
            None,
        )
        .await
        .unwrap();
    assert!(nearly.timeout_seconds <= 120, "{}", nearly.timeout_seconds);
    fixture
        .set_lease(|lease| lease.expires_at = Some(now + 2_000))
        .await;
    let error = fixture
        .prepare(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            "true",
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("about to expire"), "{error}");
    // The wrapper receives the capped bound: run one with a 1 second cap.
    fixture
        .set_lease(|lease| lease.expires_at = Some(now + 3_600_000))
        .await;
    let one = fixture
        .prepare(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            "sleep 29.51",
            Some(1),
            None,
        )
        .await
        .unwrap();
    let handle = fixture.queue(&one).await;
    fixture.run(&handle).await;
    let exited = fixture.wait_for(&handle, DetachedState::Exited).await;
    assert_eq!(exited.exit_code, Some(124), "the time bound ended it");
    let _ = std::process::Command::new("pkill")
        .args(["-f", "sleep 29.51"])
        .status();
}

#[tokio::test]
async fn detached_exec_is_refused_for_a_windows_lease_until_its_scripts_exist() {
    let fixture = Fixture::with_os("tester", fleet_core::GuestOs::Windows).await;
    let error = fixture
        .prepare(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            "Get-Date",
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&error, LabUseCaseError::Invalid { detail } if detail.contains("Windows")),
        "{error:?}"
    );
}

#[tokio::test]
async fn invalid_commands_and_handles_are_refused() {
    let fixture = Fixture::new("tester").await;
    for script in ["", "   \n", &"x".repeat(64 * 1024 + 1)] {
        let error = fixture
            .prepare(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan(),
                script,
                None,
                None,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, LabUseCaseError::Invalid { .. }),
            "{error:?}"
        );
    }
    for handle in [
        "",
        "../etc",
        "a b",
        "x;y",
        &"h".repeat(65),
        "unknown-handle",
    ] {
        let error = fixture
            .detach
            .status(&fleet_auth::LanAllowAllAuthorizer, &lan(), handle, 0)
            .await
            .unwrap_err();
        assert!(
            matches!(error, LabUseCaseError::NotFound { .. }),
            "{handle:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn authorization_and_owner_scope_apply_to_start_and_status() {
    let fixture = Fixture::new("credential:ci-a").await;
    // A denied start refuses before anything is audited or queued.
    let audit_before = fixture.audit_events().await.len();
    let denied = fixture
        .prepare(&Deny(Permission::LabExec), &lan(), "true", None, None)
        .await
        .unwrap_err();
    assert!(matches!(denied, LabUseCaseError::Denied(_)));
    assert_eq!(fixture.audit_events().await.len(), audit_before);

    // The owner's own credential starts and reads; the scoped catalog allows both.
    let owner = credential("ci-a");
    let prepared = fixture
        .prepare(&scoped(), &owner, "echo mine", None, None)
        .await
        .unwrap();
    let handle = fixture.queue(&prepared).await;
    fixture.run(&handle).await;
    let record = DetachedExecRepository::new(fixture.pool.clone())
        .get(&handle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.owner, "credential:ci-a");
    let now = fleet_core::SystemClock::now_unix_millis();
    let started = Instant::now();
    loop {
        let status = fixture
            .detach
            .status(&scoped(), &owner, &handle, now)
            .await
            .unwrap();
        if status.state == DetachedState::Exited {
            assert_eq!(status.stdout, "mine\n");
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(20), "{status:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Another owner's credential neither starts on the lease nor reads the
    // handle: both read as not found, like a handle that does not exist.
    let other = credential("ci-b");
    let start = fixture
        .prepare(&scoped(), &other, "true", None, None)
        .await
        .unwrap_err();
    assert!(
        matches!(start, LabUseCaseError::NotFound { .. }),
        "{start:?}"
    );
    let foreign = fixture
        .detach
        .status(&scoped(), &other, &handle, now)
        .await
        .unwrap_err();
    let unknown = fixture
        .detach
        .status(&scoped(), &other, "no-such-handle", now)
        .await
        .unwrap_err();
    assert!(matches!(foreign, LabUseCaseError::NotFound { .. }));
    assert_eq!(
        foreign.to_string().replace(&handle, "H"),
        unknown.to_string().replace("no-such-handle", "H"),
        "a foreign handle is indistinguishable from an unknown one"
    );
    // The same denial on status.
    let denied = fixture
        .detach
        .status(&Deny(Permission::LabExecRead), &lan(), &handle, now)
        .await
        .unwrap_err();
    assert!(matches!(denied, LabUseCaseError::Denied(_)));
    // The generic operation route cannot queue the kind.
    let generic = fixture
        .operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            LAN,
            &fleet_application::operation::NewOperation {
                kind: "lab.exec_detach".to_owned(),
                payload_json: Some("{}".to_owned()),
                ..Default::default()
            },
        )
        .await;
    assert!(generic.is_err());
}

#[tokio::test]
async fn a_start_reported_failed_that_did_start_is_reported_by_the_guest() {
    let fixture = Fixture::new("tester").await;
    let handle = fixture.start("sleep 1; echo ran-anyway").await;
    // The record says failed (a dropped session, a deadline kill), yet the
    // guest ran the command: status follows the guest, not the record.
    DetachedExecRepository::new(fixture.pool.clone())
        .set_start_state(&handle, StartState::Failed, None)
        .await
        .unwrap();
    let running = fixture.status(&handle).await;
    assert_eq!(running.state, DetachedState::Running, "{running:?}");
    let exited = fixture.wait_for(&handle, DetachedState::Exited).await;
    assert_eq!(exited.stdout, "ran-anyway\n");
}

#[tokio::test]
async fn a_terminal_answer_is_kept_and_later_polls_do_not_dial_the_guest() {
    let fixture = Fixture::new("tester").await;
    let handle = fixture.start("echo kept; exit 4").await;
    let first = fixture.wait_for(&handle, DetachedState::Exited).await;
    let reads = fixture.guest.reads.load(Ordering::SeqCst);
    // A restarted controller, too, answers from the record.
    let restarted = fixture.restart().await;
    let again = restarted.status(&handle).await;
    assert_eq!(again, first);
    assert_eq!(restarted.guest.reads.load(Ordering::SeqCst), 0);
    assert!(reads > 0);
}

#[tokio::test]
async fn status_reads_are_audited_once_a_minute_per_handle() {
    let fixture = Fixture::new("tester").await;
    let handle = fixture.start("sleep 29.71").await;
    for _ in 0..5 {
        fixture.status(&handle).await;
    }
    let audit = fixture.audit_events().await;
    let reads = audit
        .iter()
        .filter(|event| event.contains("lab_exec_status_read"))
        .count();
    assert_eq!(reads, 1, "{audit:?}");
    assert!(
        audit
            .iter()
            .any(|event| event.contains("lab_exec_detach_registered") && event.contains(&handle))
    );
    let _ = std::process::Command::new("pkill")
        .args(["-f", "sleep 29.71"])
        .status();
}
