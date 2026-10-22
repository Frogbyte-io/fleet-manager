//! #493 (ADR 0017): agent SSH access to a machine with a Fleet-held key,
//! end to end against a real sshd. A key stored in the encrypted secret
//! store authenticates `machine.exec`, `machine.put` and `machine.collect`
//! through the real executors, the real SQLite repositories, the real
//! upload and artifact stores; the key reaches `ssh` only through a private
//! file that is gone after success, failure, revocation and a deadline kill,
//! and no key, command text or file content reaches an audit event.

use std::sync::Arc;
use std::time::Duration;

use fleet_application::authz::{
    AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, ReasonId,
};
use fleet_application::lab::LabUseCaseError;
use fleet_application::lab_artifacts::ArtifactPolicy;
use fleet_application::machine::{NewEndpoint, RegisterMachine};
use fleet_application::machine_access::{
    AccessTarget, EndpointAuth, ExecCommand, ExecRequest, MachineAccess, PutRequestTarget,
};
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_controller::exec::ScriptExecutor;
use fleet_controller::lab_artifacts_store::{FsArtifactStore, SshGuestFiles};
use fleet_controller::lab_put_store::FsUploadStore;
use fleet_controller::machine_access::{
    MachineAccessDispatch, SecretBackedMachineKeys, SshAuthResolver,
};
use fleet_core::{EndpointKind, GuestOs};
use fleet_provider_ssh::ExecutionLimiter;
use fleet_storage_sqlite::{
    AuditSink, EndpointAuthRepository, MachineFileRepository, MachineRepository,
    OperationRepository, Store,
};

mod common;
use common::{start_sshd, whoami};

const MAX_BYTES: u64 = 64 * 1024;

fn lan() -> ActingPrincipal {
    ActingPrincipal {
        id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
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

struct World {
    dir: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    sshd: common::TestSshd,
    secrets: Arc<fleet_secrets::SecretStore>,
    operations: Arc<Operations>,
    access: Arc<MachineAccess>,
    dispatch: MachineAccessDispatch,
    machine_id: String,
    endpoint_id: String,
    key_ref: String,
    key_text: String,
}

impl World {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        std::mem::forget(store);
        let sshd = start_sshd();

        let key_file = dir.path().join("master.key");
        std::fs::write(
            &key_file,
            "1 0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let secrets = Arc::new(fleet_secrets::SecretStore::open(pool.clone(), &key_file).unwrap());
        let keys = Arc::new(SecretBackedMachineKeys::new(secrets.clone()));
        let resolver =
            Arc::new(SshAuthResolver::new(keys.clone()).protecting(vec![dir.path().to_path_buf()]));

        let machines: Arc<dyn fleet_application::machine::MachinePort> =
            Arc::new(MachineRepository::new(pool.clone()));
        let limiter = ExecutionLimiter::new(4);
        let ssh_exec: Arc<dyn OperationExecutor> = Arc::new(
            ScriptExecutor::new(machines.clone(), dir.path().join("ssh"), limiter.clone())
                .with_resolver(resolver.clone()),
        );
        let artifacts = dir.path().join("artifacts");
        let uploads = Arc::new(FsUploadStore::open(&artifacts, MAX_BYTES).unwrap());
        let blobs = Arc::new(FsArtifactStore::open(&artifacts, MAX_BYTES).unwrap());
        let access = Arc::new(
            MachineAccess::new(
                machines.clone(),
                Arc::new(EndpointAuthRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )
            .with_keys(keys)
            .with_uploads(uploads.clone())
            .with_files(
                Arc::new(MachineFileRepository::new(pool.clone())),
                blobs.clone(),
                ArtifactPolicy {
                    retention_seconds: 3_600,
                    max_bytes: MAX_BYTES,
                },
            ),
        );
        let files = Arc::new(
            SshGuestFiles::new(machines.clone(), dir.path().join("ssh"), limiter)
                .unwrap()
                .with_resolver(resolver),
        );
        let dispatch =
            MachineAccessDispatch::new(ssh_exec, access.clone(), Some(uploads), Some(blobs), files);
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            Arc::new(AuditSink::new(pool.clone())),
        ));

        // The machine, with its host key confirmed through the real trust
        // flow.
        let machine = machines
            .register(&RegisterMachine {
                name: "agent-box".to_owned(),
                description: String::new(),
                endpoints: vec![NewEndpoint {
                    kind: EndpointKind::Ssh,
                    reference: format!("{}@127.0.0.1:{}", whoami(), sshd.port),
                }],
                tags: vec![],
                groups: vec![],
            })
            .await
            .unwrap();
        let endpoint_id = machine.endpoints[0].id.clone();
        let provider = fleet_provider_ssh::SshProvider::new(dir.path().join("ssh")).unwrap();
        let observation = provider
            .probe_host_key("127.0.0.1", sshd.port, Duration::from_secs(10))
            .unwrap();
        provider.pin(&observation).unwrap();
        machines
            .confirm_fingerprint(&endpoint_id, &observation.fingerprint, 0)
            .await
            .unwrap();

        // The sshd's authorized key, stored as a Fleet secret.
        let key_text = std::fs::read_to_string(sshd.keys_dir.path().join("user_ed25519")).unwrap();
        let key_ref = access
            .store_key(&fleet_auth::LanAllowAllAuthorizer, &lan(), &key_text, None)
            .await
            .unwrap();
        Self {
            dir,
            pool,
            sshd,
            secrets,
            operations,
            access,
            dispatch,
            machine_id: machine.id,
            endpoint_id,
            key_ref,
            key_text,
        }
    }

    async fn use_stored_key_by_default(&self) {
        self.access
            .set_default_auth(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan(),
                &self.machine_id,
                &self.endpoint_id,
                Some(&EndpointAuth::Secret {
                    credential: self.key_ref.clone(),
                }),
            )
            .await
            .unwrap();
    }

    fn target(&self) -> AccessTarget<'_> {
        AccessTarget {
            machine_id: &self.machine_id,
            endpoint_id: None,
            auth: None,
            guest_os: GuestOs::Linux,
        }
    }

    /// Queues and runs one exec, answering the finished operation.
    async fn exec(&self, command: ExecCommand, timeout: u64) -> Operation {
        let new = self
            .access
            .request_exec(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan(),
                &ExecRequest {
                    target: self.target(),
                    command,
                    timeout_seconds: Some(timeout),
                    idempotency_key: None,
                },
            )
            .await
            .unwrap();
        let queued = self
            .operations
            .create_machine_access(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan().id,
                &self.machine_id,
                &new,
            )
            .await
            .unwrap();
        self.run(&queued).await
    }

    async fn run(&self, queued: &Operation) -> Operation {
        let report = self
            .operations
            .tick(
                &self.dispatch,
                "worker-a",
                fleet_core::SystemClock::now_unix_millis(),
                60_000,
            )
            .await
            .unwrap();
        assert!(report.claimed && report.completed, "{report:?}");
        self.operations
            .get(&fleet_auth::LanAllowAllAuthorizer, &lan().id, &queued.id)
            .await
            .unwrap()
    }

    /// Key files currently on disk under the provider's work directory.
    fn key_files(&self) -> usize {
        std::fs::read_dir(self.dir.path().join("ssh").join("keys"))
            .map(|entries| entries.count())
            .unwrap_or(0)
    }

    async fn audit_text(&self) -> String {
        sqlx::query_scalar::<_, String>(
            "SELECT group_concat(action || ' ' || coalesce(resource, '') || ' ' || metadata_json, char(10)) FROM audit_events",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }
}

fn result_of(done: &Operation) -> serde_json::Value {
    serde_json::from_str(done.result_json.as_deref().expect("a result")).unwrap()
}

fn error_of(done: &Operation) -> serde_json::Value {
    serde_json::from_str(done.error_json.as_deref().expect("an error")).unwrap()
}

#[tokio::test]
async fn a_stored_key_runs_a_command_and_leaves_no_key_file() {
    let world = World::new().await;
    world.use_stored_key_by_default().await;
    let done = world
        .exec(
            ExecCommand::Script("echo from-the-machine; exit 0".to_owned()),
            15,
        )
        .await;
    assert_eq!(done.state, "succeeded", "{:?}", done.error_json);
    let result = result_of(&done);
    assert_eq!(result["exitCode"], 0);
    assert_eq!(result["stdout"], "from-the-machine\n");
    assert_eq!(world.key_files(), 0, "the key file outlived the session");
}

#[tokio::test]
async fn an_argv_command_passes_its_arguments_as_data() {
    let world = World::new().await;
    world.use_stored_key_by_default().await;
    // A shell would expand `$(id)` and split the spaces; argv is data.
    let done = world
        .exec(
            ExecCommand::Argv(
                ["printf", "%s|", "a b", "$(id)", ";echo injected"]
                    .map(str::to_owned)
                    .to_vec(),
            ),
            15,
        )
        .await;
    assert_eq!(done.state, "succeeded", "{:?}", done.error_json);
    assert_eq!(result_of(&done)["stdout"], "a b|$(id)|;echo injected|");
}

#[tokio::test]
async fn a_failing_command_reports_its_exit_code_and_truncation_is_flagged() {
    let world = World::new().await;
    world.use_stored_key_by_default().await;
    let failed = world
        .exec(ExecCommand::Script("echo oops >&2; exit 3".to_owned()), 15)
        .await;
    assert_eq!(failed.state, "failed");
    let error = error_of(&failed);
    assert_eq!(error["exitCode"], 3);
    assert_eq!(error["stderr"], "oops\n");

    let big = world
        .exec(
            ExecCommand::Script("head -c 1500000 /dev/zero | tr '\\0' a".to_owned()),
            30,
        )
        .await;
    assert_eq!(big.state, "succeeded", "{:?}", big.error_json);
    assert_eq!(result_of(&big)["truncatedStdout"], true);
}

#[tokio::test]
async fn the_key_file_is_gone_after_a_deadline_kill_and_after_revocation() {
    let world = World::new().await;
    world.use_stored_key_by_default().await;
    let killed = world
        .exec(ExecCommand::Script("sleep 30".to_owned()), 1)
        .await;
    assert_eq!(killed.state, "failed");
    assert_eq!(error_of(&killed)["reason"], "deadline_killed");
    assert_eq!(world.key_files(), 0, "a deadline kill left the key behind");

    // Revocation is immediate: the next command has no key to use.
    world.secrets.delete(&world.key_ref).await.unwrap();
    let new = world
        .access
        .request_exec(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &ExecRequest {
                target: world.target(),
                command: ExecCommand::Script("true".to_owned()),
                timeout_seconds: None,
                idempotency_key: None,
            },
        )
        .await;
    match new {
        Err(LabUseCaseError::Invalid { detail }) => {
            assert!(
                detail.contains("does not name a stored SSH key"),
                "{detail}"
            );
        }
        other => panic!("a revoked key must be refused at request time: {other:?}"),
    }
    assert_eq!(world.key_files(), 0);
}

#[tokio::test]
async fn a_key_revoked_after_queueing_fails_the_operation_without_a_key_file() {
    let world = World::new().await;
    world.use_stored_key_by_default().await;
    let new = world
        .access
        .request_exec(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &ExecRequest {
                target: world.target(),
                command: ExecCommand::Script("echo should-not-run".to_owned()),
                timeout_seconds: Some(10),
                idempotency_key: None,
            },
        )
        .await
        .unwrap();
    let queued = world
        .operations
        .create_machine_access(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan().id,
            &world.machine_id,
            &new,
        )
        .await
        .unwrap();
    world.secrets.delete(&world.key_ref).await.unwrap();
    let done = world.run(&queued).await;
    assert_eq!(done.state, "failed");
    let text = format!("{:?}{:?}", done.error_json, done.result_json);
    assert!(!text.contains("should-not-run"), "{text}");
    assert_eq!(world.key_files(), 0);
}

#[tokio::test]
async fn a_wrong_key_fails_authentication_and_leaves_no_key_file() {
    let world = World::new().await;
    // A different, valid key the sshd does not know.
    let other = world.dir.path().join("other_ed25519");
    let generated = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f"])
        .arg(&other)
        .output()
        .unwrap();
    assert!(generated.status.success());
    let other_ref = world
        .access
        .store_key(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &std::fs::read_to_string(&other).unwrap(),
            None,
        )
        .await
        .unwrap();
    world
        .access
        .set_default_auth(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &world.machine_id,
            &world.endpoint_id,
            Some(&EndpointAuth::Secret {
                credential: other_ref,
            }),
        )
        .await
        .unwrap();
    let done = world
        .exec(ExecCommand::Script("echo nope".to_owned()), 10)
        .await;
    assert_eq!(done.state, "failed");
    // ssh itself exits 255 on a failed login; the refusal is reported, and
    // no key file is left whatever the outcome.
    let error = error_of(&done);
    assert_eq!(error["exitCode"], 255, "{error}");
    assert!(
        error["stderr"]
            .as_str()
            .unwrap()
            .contains("Permission denied"),
        "{error}"
    );
    assert_eq!(world.key_files(), 0);
}

#[tokio::test]
async fn no_default_auth_and_no_explicit_auth_is_refused() {
    let world = World::new().await;
    let refused = world
        .access
        .request_exec(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &ExecRequest {
                target: world.target(),
                command: ExecCommand::Script("true".to_owned()),
                timeout_seconds: None,
                idempotency_key: None,
            },
        )
        .await;
    match refused {
        Err(LabUseCaseError::Invalid { detail }) => {
            assert!(detail.contains("no default auth"), "{detail}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn setting_a_default_auth_validates_the_reference_and_is_audited_without_the_key() {
    let world = World::new().await;
    let refused = world
        .access
        .set_default_auth(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &world.machine_id,
            &world.endpoint_id,
            Some(&EndpointAuth::Secret {
                credential: "no-such-record".to_owned(),
            }),
        )
        .await;
    assert!(
        matches!(refused, Err(LabUseCaseError::Invalid { .. })),
        "{refused:?}"
    );
    let malformed = world
        .access
        .set_default_auth(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &world.machine_id,
            &world.endpoint_id,
            Some(&EndpointAuth::Secret {
                credential: "has spaces".to_owned(),
            }),
        )
        .await;
    assert!(matches!(malformed, Err(LabUseCaseError::Invalid { .. })));

    world.use_stored_key_by_default().await;
    let read = world
        .access
        .default_auth(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &world.machine_id,
            &world.endpoint_id,
        )
        .await
        .unwrap();
    assert_eq!(
        read,
        Some(EndpointAuth::Secret {
            credential: world.key_ref.clone()
        })
    );
    world
        .access
        .set_default_auth(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &world.machine_id,
            &world.endpoint_id,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        world
            .access
            .default_auth(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan(),
                &world.machine_id,
                &world.endpoint_id,
            )
            .await
            .unwrap(),
        None
    );
    let audit = world.audit_text().await;
    assert!(audit.contains("machine_endpoint_auth_set"), "{audit}");
    assert!(audit.contains(&world.key_ref), "{audit}");
    assert!(!audit.contains("BEGIN OPENSSH"), "{audit}");
    assert!(
        !audit.contains(world.key_text.lines().nth(1).unwrap()),
        "the key body reached an audit event"
    );
}

#[tokio::test]
async fn a_principal_without_the_permission_is_refused_at_the_application_layer() {
    let world = World::new().await;
    world.use_stored_key_by_default().await;
    for (denied, label) in [
        (Permission::MachineExec, "exec"),
        (Permission::MachinePut, "put"),
        (Permission::MachineCollect, "collect"),
        (Permission::MachineUpdate, "set-auth"),
    ] {
        let authorizer = Deny(denied);
        let refused = match label {
            "exec" => world
                .access
                .request_exec(
                    &authorizer,
                    &lan(),
                    &ExecRequest {
                        target: world.target(),
                        command: ExecCommand::Script("true".to_owned()),
                        timeout_seconds: None,
                        idempotency_key: None,
                    },
                )
                .await
                .map(|_| ()),
            "put" => world
                .access
                .begin_upload(
                    &authorizer,
                    &lan(),
                    &PutRequestTarget {
                        target: world.target(),
                        guest_path: "/tmp/x",
                        overwrite: false,
                    },
                )
                .await
                .map(|_| ()),
            "collect" => world
                .access
                .request_collect(&authorizer, &lan(), &world.target(), &["/tmp/x".to_owned()])
                .await
                .map(|_| ()),
            _ => {
                world
                    .access
                    .set_default_auth(
                        &authorizer,
                        &lan(),
                        &world.machine_id,
                        &world.endpoint_id,
                        None,
                    )
                    .await
            }
        };
        assert!(
            matches!(refused, Err(LabUseCaseError::Denied(_))),
            "{label}: {refused:?}"
        );
    }
    // The dedicated queue route re-checks: a validated request still cannot
    // be queued by a principal that lost the permission.
    let new = world
        .access
        .request_exec(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &ExecRequest {
                target: world.target(),
                command: ExecCommand::Script("true".to_owned()),
                timeout_seconds: None,
                idempotency_key: None,
            },
        )
        .await
        .unwrap();
    let queue = world
        .operations
        .create_machine_access(
            &Deny(Permission::MachineExec),
            &lan().id,
            &world.machine_id,
            &new,
        )
        .await;
    assert!(queue.is_err());
    // And the generic route never creates the kind at all.
    let generic = world
        .operations
        .create(&fleet_auth::LanAllowAllAuthorizer, &lan().id, &new)
        .await;
    assert!(generic.is_err(), "machine.exec must use its machine route");
}

#[tokio::test]
async fn a_command_that_prints_a_key_is_scrubbed_from_the_result_and_the_audit() {
    let world = World::new().await;
    world.use_stored_key_by_default().await;
    let marker = "AAAAC3NzaC1lZDI1NTE5AAAAIMARKERMARKERMARKERMARKERMARKERMARKER";
    let script = format!(
        "printf '%s\\n' '-----BEGIN OPENSSH PRIVATE KEY-----' '{marker}' '-----END OPENSSH PRIVATE KEY-----'"
    );
    let done = world.exec(ExecCommand::Script(script.clone()), 15).await;
    assert_eq!(done.state, "succeeded", "{:?}", done.error_json);
    let output = result_of(&done)["stdout"].as_str().unwrap().to_owned();
    assert!(!output.contains(marker), "the key body survived: {output}");
    assert!(!output.contains("BEGIN OPENSSH PRIVATE KEY"), "{output}");

    let audit = world.audit_text().await;
    assert!(audit.contains("machine_exec_requested"), "{audit}");
    assert!(audit.contains("commandSha256"), "{audit}");
    assert!(
        !audit.contains(marker),
        "the command reached the audit: {audit}"
    );
    assert!(
        !audit.contains("printf"),
        "the command reached the audit: {audit}"
    );
}

#[tokio::test]
async fn put_and_collect_move_files_with_the_stored_key() {
    let world = World::new().await;
    world.use_stored_key_by_default().await;
    let remote = world.dir.path().join("remote-file.bin");
    let remote_path = remote.display().to_string();
    let content = b"payload \x00\x01\x02 bytes for the machine".to_vec();

    // put: stage the bytes, queue, run.
    let request = PutRequestTarget {
        target: world.target(),
        guest_path: &remote_path,
        overwrite: false,
    };
    let mut writer = world
        .access
        .begin_upload(&fleet_auth::LanAllowAllAuthorizer, &lan(), &request)
        .await
        .unwrap();
    writer.write(&content).await.unwrap();
    let staged = writer.finish().await.unwrap();
    let new = world
        .access
        .request_put(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &request,
            &staged,
        )
        .await
        .unwrap();
    let queued = world
        .operations
        .create_machine_access(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan().id,
            &world.machine_id,
            &new,
        )
        .await
        .unwrap();
    let done = world.run(&queued).await;
    assert_eq!(done.state, "succeeded", "{:?}", done.error_json);
    assert_eq!(std::fs::read(&remote).unwrap(), content);
    assert_eq!(world.key_files(), 0);
    // Nothing of the content is in the operation's payload or result.
    let recorded = format!("{:?}{:?}", queued.payload_json, done.result_json);
    assert!(!recorded.contains("payload"), "{recorded}");

    // A second put without overwrite refuses and leaves the first intact.
    let mut writer = world
        .access
        .begin_upload(&fleet_auth::LanAllowAllAuthorizer, &lan(), &request)
        .await
        .unwrap();
    writer.write(b"different").await.unwrap();
    let staged = writer.finish().await.unwrap();
    let new = world
        .access
        .request_put(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &request,
            &staged,
        )
        .await
        .unwrap();
    let queued = world
        .operations
        .create_machine_access(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan().id,
            &world.machine_id,
            &new,
        )
        .await
        .unwrap();
    let refused = world.run(&queued).await;
    assert_eq!(refused.state, "failed");
    assert_eq!(error_of(&refused)["reason"], "target_exists");
    assert_eq!(std::fs::read(&remote).unwrap(), content);

    // collect: the file comes back as a recorded, verified blob.
    let new = world
        .access
        .request_collect(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &world.target(),
            &[remote_path.clone(), "/nonexistent/for/sure".to_owned()],
        )
        .await
        .unwrap();
    let queued = world
        .operations
        .create_machine_access(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan().id,
            &world.machine_id,
            &new,
        )
        .await
        .unwrap();
    let done = world.run(&queued).await;
    // One path is missing: the operation fails, the good file stays stored.
    assert_eq!(done.state, "failed");
    let error = error_of(&done);
    assert_eq!(error["reason"], "collection_partial");
    assert_eq!(error["failures"][0]["reason"], "missing");
    let file_id = error["files"][0]["fileId"].as_str().unwrap().to_owned();
    let listed = world
        .access
        .list_files(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &world.machine_id,
            10,
        )
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, file_id);
    assert_eq!(listed[0].name, remote_path);
    assert_eq!(listed[0].size_bytes, content.len() as u64);
    let (_, mut reader) = world
        .access
        .open_file(&fleet_auth::LanAllowAllAuthorizer, &lan(), &file_id)
        .await
        .unwrap();
    let mut bytes = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut bytes)
        .await
        .unwrap();
    assert_eq!(bytes, content);

    // Reading a collected file needs machines.collect.
    let denied = world
        .access
        .open_file(&Deny(Permission::MachineCollect), &lan(), &file_id)
        .await;
    assert!(matches!(denied, Err(LabUseCaseError::Denied(_))));

    // Retention removes the record and, once unreferenced, the blob.
    let later = fleet_core::SystemClock::now_unix_millis() + 2 * 3_600_000;
    assert_eq!(world.access.sweep_expired_files(later).await.unwrap(), 1);
    assert!(
        world
            .access
            .list_files(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan(),
                &world.machine_id,
                10
            )
            .await
            .unwrap()
            .is_empty()
    );

    // Put and collect audit paths, sizes and digests, never content.
    let audit = world.audit_text().await;
    assert!(audit.contains("machine_put_requested"), "{audit}");
    assert!(audit.contains("machine_collect_requested"), "{audit}");
    assert!(!audit.contains("bytes for the machine"), "{audit}");
    let _ = &world.sshd;
}

/// Registers a second SSH machine whose host key is confirmed.
async fn second_machine(world: &World) -> (String, String) {
    use fleet_application::machine::MachinePort as _;
    let machines = MachineRepository::new(world.pool.clone());
    let machine = machines
        .register(&RegisterMachine {
            name: "other-box".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: format!("{}@127.0.0.1:{}", whoami(), world.sshd.port),
            }],
            tags: vec![],
            groups: vec![],
        })
        .await
        .unwrap();
    let endpoint = machine.endpoints[0].id.clone();
    machines
        .confirm_fingerprint(&endpoint, "SHA256:x", 0)
        .await
        .unwrap();
    (machine.id, endpoint)
}

fn request<'a>(world: &'a World, auth: Option<&'a EndpointAuth>) -> ExecRequest<'a> {
    ExecRequest {
        target: AccessTarget {
            machine_id: &world.machine_id,
            endpoint_id: None,
            auth,
            guest_os: GuestOs::Linux,
        },
        command: ExecCommand::Script("true".to_owned()),
        timeout_seconds: Some(10),
        idempotency_key: None,
    }
}

#[tokio::test]
async fn an_explicit_auth_needs_machine_update_but_the_default_needs_only_exec() {
    let world = World::new().await;
    world.use_stored_key_by_default().await;
    let only_exec = Deny(Permission::MachineUpdate);
    let explicit = EndpointAuth::Secret {
        credential: world.key_ref.clone(),
    };
    for auth in [
        EndpointAuth::Agent,
        EndpointAuth::IdentityFile {
            path: "/somewhere/key".to_owned(),
        },
        explicit,
    ] {
        let refused = world
            .access
            .request_exec(&only_exec, &lan(), &request(&world, Some(&auth)))
            .await;
        assert!(
            matches!(refused, Err(LabUseCaseError::Denied(_))),
            "{auth:?}: {refused:?}"
        );
    }
    // The endpoint's default is what a caller with only machines.exec uses.
    world
        .access
        .request_exec(&only_exec, &lan(), &request(&world, None))
        .await
        .expect("the default needs no machine.update");
}

#[tokio::test]
async fn an_identity_file_inside_the_controllers_data_is_refused_at_execution() {
    let world = World::new().await;
    // The SSH work directory holds other sessions' key files.
    let inside = world.dir.path().join("ssh").join("known_hosts");
    let auth = EndpointAuth::IdentityFile {
        path: inside.display().to_string(),
    };
    let new = world
        .access
        .request_exec(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &request(&world, Some(&auth)),
        )
        .await
        .unwrap();
    let queued = world
        .operations
        .create_machine_access(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan().id,
            &world.machine_id,
            &new,
        )
        .await
        .unwrap();
    let done = world.run(&queued).await;
    assert_eq!(done.state, "failed");
    let text = format!("{:?}", done.error_json);
    assert!(text.contains("inside the controller"), "{text}");
}

#[tokio::test]
async fn a_key_bound_to_a_machine_resolves_for_that_machine_only() {
    use fleet_application::machine_access::MachineKeyPort as _;
    let world = World::new().await;
    let (other_machine, other_endpoint) = second_machine(&world).await;
    let bound = world
        .access
        .store_key(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &world.key_text,
            Some(&world.machine_id),
        )
        .await
        .unwrap();
    // Usable on its own machine.
    world
        .access
        .set_default_auth(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &world.machine_id,
            &world.endpoint_id,
            Some(&EndpointAuth::Secret {
                credential: bound.clone(),
            }),
        )
        .await
        .unwrap();
    let done = world
        .exec(ExecCommand::Script("echo bound".to_owned()), 15)
        .await;
    assert_eq!(done.state, "succeeded", "{:?}", done.error_json);
    // Refused on another machine, when set and when resolved.
    let refused = world
        .access
        .set_default_auth(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &other_machine,
            &other_endpoint,
            Some(&EndpointAuth::Secret {
                credential: bound.clone(),
            }),
        )
        .await;
    assert!(
        matches!(refused, Err(LabUseCaseError::Invalid { .. })),
        "{refused:?}"
    );
    let keys = SecretBackedMachineKeys::new(world.secrets.clone());
    assert!(keys.exists(&bound, &world.machine_id).await.unwrap());
    assert!(!keys.exists(&bound, &other_machine).await.unwrap());
    assert_eq!(keys.resolve(&bound, &other_machine).await.unwrap(), None);
    // A key bound to a machine that does not exist cannot be stored.
    let missing = world
        .access
        .store_key(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &world.key_text,
            Some("no-such-machine"),
        )
        .await;
    assert!(matches!(missing, Err(LabUseCaseError::NotFound { .. })));
    // The storing event names the reference, never the key.
    let audit = world.audit_text().await;
    assert!(audit.contains("machine_ssh_key_stored"), "{audit}");
    assert!(audit.contains(&bound), "{audit}");
    assert!(!audit.contains(world.key_text.lines().nth(1).unwrap()));
}

#[tokio::test]
async fn only_the_key_namespaces_resolve_and_a_repository_ssh_key_works() {
    let world = World::new().await;
    let value = fleet_secrets::SecretValue::new(world.key_text.trim().as_bytes().to_vec());
    let set = |credential: String| {
        let world = &world;
        async move {
            world
                .access
                .set_default_auth(
                    &fleet_auth::LanAllowAllAuthorizer,
                    &lan(),
                    &world.machine_id,
                    &world.endpoint_id,
                    Some(&EndpointAuth::Secret { credential }),
                )
                .await
        }
    };
    // A valid key under another integration's namespace never resolves.
    let foreign = world
        .secrets
        .create("images/build-key", value.clone())
        .await
        .unwrap();
    let refused = set(foreign.id).await;
    assert!(
        matches!(refused, Err(LabUseCaseError::Invalid { .. })),
        "{refused:?}"
    );
    // A token in the repository-credential namespace is not a key.
    let token = world
        .secrets
        .create(
            "git/token-1",
            fleet_secrets::SecretValue::new(b"ghp_notakey".to_vec()),
        )
        .await
        .unwrap();
    let refused = set(token.id).await;
    assert!(
        matches!(refused, Err(LabUseCaseError::Invalid { .. })),
        "{refused:?}"
    );
    // An SSH key kept as a repository credential does work.
    let repo_key = world.secrets.create("git/deploy-key", value).await.unwrap();
    set(repo_key.id).await.unwrap();
    let done = world
        .exec(
            ExecCommand::Script("echo via-repository-key".to_owned()),
            15,
        )
        .await;
    assert_eq!(done.state, "succeeded", "{:?}", done.error_json);
    assert_eq!(result_of(&done)["stdout"], "via-repository-key\n");
}

#[tokio::test]
async fn reading_a_machine_operation_needs_that_kinds_permission_on_its_machine() {
    let world = World::new().await;
    world.use_stored_key_by_default().await;
    let done = world
        .exec(ExecCommand::Script("echo hidden".to_owned()), 15)
        .await;
    let hidden = world
        .operations
        .get(&Deny(Permission::MachineExec), &lan().id, &done.id)
        .await;
    assert!(hidden.is_err(), "the command and output were readable");
    let listed = world
        .operations
        .list(&Deny(Permission::MachineExec), &lan().id, 50)
        .await
        .unwrap();
    assert!(listed.iter().all(|operation| operation.id != done.id));
    // Another kind's permission is not this kind's.
    assert!(
        world
            .operations
            .get(&Deny(Permission::MachineCollect), &lan().id, &done.id)
            .await
            .is_ok()
    );
    let visible = world
        .operations
        .list(&fleet_auth::LanAllowAllAuthorizer, &lan().id, 50)
        .await
        .unwrap();
    assert!(visible.iter().any(|operation| operation.id == done.id));
}

#[tokio::test]
async fn the_generic_route_never_queues_a_machine_kind_or_a_stored_key_auth() {
    let world = World::new().await;
    world.use_stored_key_by_default().await;
    let machine_kind = world
        .operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan().id,
            &fleet_application::operation::NewOperation {
                kind: "machine.exec".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: Some(serde_json::json!({"machineId": world.machine_id}).to_string()),
                review_token: None,
            },
        )
        .await;
    assert!(machine_kind.is_err());
    for kind in ["ssh.exec", "agentless.inventory"] {
        let bypass = world
            .operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan().id,
                &fleet_application::operation::NewOperation {
                    kind: kind.to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(
                        serde_json::json!({
                            "machineId": world.machine_id,
                            "endpointId": world.endpoint_id,
                            "script": "id",
                            "timeoutSeconds": 10,
                            "auth": {"type": "secret", "credential": world.key_ref},
                        })
                        .to_string(),
                    ),
                    review_token: None,
                },
            )
            .await;
        assert!(bypass.is_err(), "{kind} accepted a stored-key auth");
    }
}

#[tokio::test]
async fn cancelling_a_running_exec_leaves_no_key_file_once_the_session_ends() {
    let world = World::new().await;
    world.use_stored_key_by_default().await;
    let new = world
        .access
        .request_exec(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan(),
            &ExecRequest {
                target: world.target(),
                command: ExecCommand::Script("sleep 30".to_owned()),
                timeout_seconds: Some(3),
                idempotency_key: None,
            },
        )
        .await
        .unwrap();
    world
        .operations
        .create_machine_access(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan().id,
            &world.machine_id,
            &new,
        )
        .await
        .unwrap();
    // Run the worker tick and drop it while the session is open: this is
    // what a cancelled or shut-down worker does to the future.
    let tick = world.operations.tick(
        &world.dispatch,
        "worker-a",
        fleet_core::SystemClock::now_unix_millis(),
        60_000,
    );
    let _ = tokio::time::timeout(Duration::from_millis(1500), tick).await;
    // The session's deadline ends the ssh child; its guard removes the key.
    for _ in 0..80 {
        if world.key_files() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the key file outlived a cancelled session");
}

#[tokio::test]
async fn reading_an_endpoints_default_needs_machine_read_on_that_machine() {
    let world = World::new().await;
    let refused = world
        .access
        .default_auth(
            &Deny(Permission::MachineRead),
            &lan(),
            &world.machine_id,
            &world.endpoint_id,
        )
        .await;
    assert!(matches!(refused, Err(LabUseCaseError::Denied(_))));
}
