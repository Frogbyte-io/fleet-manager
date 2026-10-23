//! #493 (ADR 0017): `fleetctl machines exec|put|collect|files|file-get|
//! endpoint-auth|ssh-key` against a real controller router over real SQLite
//! repositories, the real key store, upload and artifact stores and the real
//! machine access dispatch; only the SSH hop is replaced (an exec stand-in
//! and a recording guest). The CLI is the real binary. The contract pinned
//! here: JSON output, the command's exit code as the CLI's exit code, the
//! truncation flags, and that no answer, audit event or operation payload
//! ever carries the key.

#![allow(clippy::too_many_lines)]

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::process::{Command as Process, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use fleet_application::lab::{ImagePinValidator, Lab, RecipeVersion};
use fleet_application::lab_artifacts::ArtifactPolicy;
use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::machine_access::MachineAccess;
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_controller::lab_artifacts_store::{FsArtifactStore, GuestFiles, StagingFile};
use fleet_controller::lab_put_store::FsUploadStore;
use fleet_controller::machine_access::{MachineAccessDispatch, SecretBackedMachineKeys};
use fleet_provider_ssh::FetchOutcome;
use fleet_storage_sqlite::{
    AuditSink, EndpointAuthRepository, LabRepository, LeaseRepository, MachineFileRepository,
    MachineRepository, OperationRepository, ProjectRepository, Store,
};
use serde_json::{Value, json};

const KEY_BODY: &str = "b3BlbnNzaC1rZXktdjEAAAAAMARKERMARKERMARKERMARKERMARKER";
const FIXTURE_FILE: &str = "/home/agent/report.json";
const FIXTURE_BYTES: &[u8] = b"{\"verdict\":\"pass\"}\n";

fn key() -> String {
    format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{KEY_BODY}\n-----END OPENSSH PRIVATE KEY-----\n")
}

#[derive(Debug)]
struct NoPins;

#[async_trait]
impl ImagePinValidator for NoPins {
    async fn promoted_version(&self, _version_id: &str) -> Result<Option<RecipeVersion>, String> {
        Ok(None)
    }
}

/// Stands in for the SSH exec executor: the payload's first argument picks
/// the outcome, the way a real command's exit code would.
#[derive(Debug)]
struct StubSsh;

#[async_trait]
impl OperationExecutor for StubSsh {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        assert_eq!(operation.kind, "ssh.exec", "machine.exec runs as ssh.exec");
        let payload: Value = serde_json::from_str(operation.payload_json.as_deref().unwrap())
            .map_err(|error| error.to_string())?;
        assert_eq!(payload["auth"]["type"], "secret", "{payload}");
        let first = payload["arguments"][0]
            .as_str()
            .or_else(|| payload["script"].as_str())
            .unwrap_or_default()
            .to_owned();
        let (state, result, error): (&str, Option<Value>, Option<Value>) = match first.as_str() {
            "fail3" => (
                "failed",
                None,
                Some(json!({
                    "exitCode": 3, "stdout": "", "stderr": "went wrong\n",
                    "truncatedStdout": false, "truncatedStderr": false,
                })),
            ),
            "trunc" => (
                "succeeded",
                Some(json!({
                    "exitCode": 0, "stdout": "aaaa", "stderr": "",
                    "truncatedStdout": true, "truncatedStderr": false,
                })),
                None,
            ),
            "kill" => (
                "failed",
                None,
                Some(json!({
                    "reason": "deadline_killed",
                    "detail": "the local ssh process was killed at the deadline",
                })),
            ),
            _ => (
                "succeeded",
                Some(json!({
                    "exitCode": 0, "stdout": format!("ran {first}\n"), "stderr": "",
                    "truncatedStdout": false, "truncatedStderr": false,
                })),
                None,
            ),
        };
        operations
            .complete(
                &operation.id,
                state,
                result.map(|value| value.to_string()).as_deref(),
                error.map(|value| value.to_string()).as_deref(),
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// The machine's files. The stand-in honours any auth: no connection is made.
#[derive(Debug, Default)]
struct Guest {
    files: Mutex<HashMap<String, Vec<u8>>>,
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
        let bytes = self.files.lock().unwrap().get(path).cloned();
        let outcome = match bytes {
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

    async fn fetch_with_auth(
        &self,
        machine_id: &str,
        endpoint_id: &str,
        _auth: Option<&fleet_application::machine_access::EndpointAuth>,
        guest_os: fleet_core::GuestOs,
        path: &str,
        max_bytes: u64,
        deadline: Duration,
        sink: StagingFile,
    ) -> (Result<FetchOutcome, String>, StagingFile) {
        self.fetch(
            machine_id,
            endpoint_id,
            guest_os,
            path,
            max_bytes,
            deadline,
            sink,
        )
        .await
    }

    async fn put_with_auth(
        &self,
        machine_id: &str,
        endpoint_id: &str,
        _auth: Option<&fleet_application::machine_access::EndpointAuth>,
        request: fleet_controller::lab_artifacts_store::GuestPut,
        deadline: Duration,
        source: std::fs::File,
    ) -> Result<fleet_provider_ssh::PutOutcome, String> {
        self.put(machine_id, endpoint_id, request, deadline, source)
            .await
    }

    async fn put(
        &self,
        _machine_id: &str,
        _endpoint_id: &str,
        request: fleet_controller::lab_artifacts_store::GuestPut,
        _deadline: Duration,
        mut source: std::fs::File,
    ) -> Result<fleet_provider_ssh::PutOutcome, String> {
        let mut bytes = Vec::new();
        source.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        let mut files = self.files.lock().unwrap();
        if files.contains_key(&request.path) && !request.overwrite {
            return Ok(fleet_provider_ssh::PutOutcome::TargetExists);
        }
        let size = bytes.len() as u64;
        files.insert(request.path, bytes);
        Ok(fleet_provider_ssh::PutOutcome::Put { bytes: size })
    }
}

/// An operation's kind, payload, result and error.
type OperationRow = (String, Option<String>, Option<String>, Option<String>);

struct Cli {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Cli {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|error| panic!("not JSON ({error}): {} / {}", self.stdout, self.stderr))
    }
}

struct World {
    address: std::net::SocketAddr,
    pool: sqlx::SqlitePool,
    machine_id: String,
    endpoint_id: String,
    work: tempfile::TempDir,
    _store: Store,
    _server: tokio::task::JoinHandle<()>,
    _worker: tokio::task::JoinHandle<()>,
}

impl World {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
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
        let artifacts = dir.path().join("artifacts");
        let uploads = Arc::new(FsUploadStore::open(&artifacts, 1 << 20).unwrap());
        let blobs = Arc::new(FsArtifactStore::open(&artifacts, 1 << 20).unwrap());
        let machines = Arc::new(MachineRepository::new(pool.clone()));
        let access = Arc::new(
            MachineAccess::new(
                machines.clone(),
                Arc::new(EndpointAuthRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )
            .with_keys(Arc::new(SecretBackedMachineKeys::new(secrets)))
            .with_uploads(uploads.clone())
            .with_files(
                Arc::new(MachineFileRepository::new(pool.clone())),
                blobs.clone(),
                ArtifactPolicy {
                    retention_seconds: 3_600,
                    max_bytes: 1 << 20,
                },
            ),
        );
        let machine = machines
            .register(&RegisterMachine {
                name: "agent-box".to_owned(),
                description: String::new(),
                endpoints: vec![NewEndpoint {
                    kind: fleet_core::EndpointKind::Ssh,
                    reference: "agent@192.0.2.20:22".to_owned(),
                }],
                tags: vec![],
                groups: vec![],
            })
            .await
            .unwrap();
        let endpoint_id = machine.endpoints[0].id.clone();
        machines
            .confirm_fingerprint(&endpoint_id, "SHA256:fixture", 0)
            .await
            .unwrap();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let lab = Arc::new(
            Lab::new(
                labs.clone(),
                labs.clone(),
                Arc::new(LeaseRepository::new(pool.clone())),
                Arc::new(NoPins),
                Arc::new(ProjectRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )
            .with_machine_access(access.clone()),
        );
        let settings = fleet_controller::Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            web_dist: dir.path().to_path_buf(),
            artifacts_dir: None,
            tailscale_serve_listen: None,
        };
        let router = fleet_controller::build_router(
            &settings,
            Some(pool.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&lab),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            Arc::new(AuditSink::new(pool.clone())),
        ));
        let guest = Arc::new(Guest::default());
        guest
            .files
            .lock()
            .unwrap()
            .insert(FIXTURE_FILE.to_owned(), FIXTURE_BYTES.to_vec());
        let dispatch = MachineAccessDispatch::new(
            Arc::new(StubSsh),
            access,
            Some(uploads),
            Some(blobs),
            guest,
        );
        let worker = tokio::spawn(async move {
            loop {
                let listed = operations
                    .list(
                        &fleet_auth::LanAllowAllAuthorizer,
                        fleet_auth::LAN_PRINCIPAL_ID,
                        100,
                    )
                    .await
                    .unwrap();
                for operation in listed
                    .iter()
                    .filter(|operation| operation.state == "pending")
                {
                    let _ = operations
                        .claim_only_execute(&dispatch, &operation.id, "test-worker")
                        .await;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        Self {
            address,
            pool,
            machine_id: machine.id,
            endpoint_id,
            work: dir,
            _store: store,
            _server: server,
            _worker: worker,
        }
    }

    /// Runs the real `fleetctl` binary with only the given environment.
    async fn cli(&self, token: Option<&str>, stdin: Option<&str>, words: &[&str]) -> Cli {
        let address = self.address;
        let token = token.map(str::to_owned);
        let stdin = stdin.map(str::to_owned);
        let words: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
        tokio::task::spawn_blocking(move || {
            let mut process = Process::new(env!("CARGO_BIN_EXE_fleetctl"));
            process
                .args(["--url", &format!("http://{address}"), "--output", "json"])
                .args(&words)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some(token) = &token {
                process.env("FLEET_TOKEN", token);
            }
            let mut child = process.spawn().expect("fleetctl must run");
            if let Some(stdin) = &stdin {
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(stdin.as_bytes())
                    .unwrap();
            }
            let output = child.wait_with_output().unwrap();
            Cli {
                code: output.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
        })
        .await
        .unwrap()
    }

    async fn store_key_and_make_default(&self) -> String {
        let stored = self
            .cli(None, Some(&key()), &["machines", "ssh-key", "store"])
            .await;
        assert_eq!(stored.code, 0, "{}", stored.stderr);
        let reference = stored.json()["credentialRef"].as_str().unwrap().to_owned();
        let set = self
            .cli(
                None,
                None,
                &[
                    "machines",
                    "endpoint-auth",
                    "set",
                    &self.machine_id,
                    &self.endpoint_id,
                    "--auth",
                    "secret",
                    "--credential",
                    &reference,
                ],
            )
            .await;
        assert_eq!(set.code, 0, "{}", set.stderr);
        reference
    }

    /// Everything the audit ledger and the operation payloads hold.
    async fn stored_text(&self) -> String {
        let audit: Vec<(String, String, Option<String>)> =
            sqlx::query_as("SELECT action, metadata_json, resource FROM audit_events")
                .fetch_all(&self.pool)
                .await
                .unwrap();
        let operations: Vec<OperationRow> =
            sqlx::query_as("SELECT kind, payload_json, result_json, error_json FROM operations")
                .fetch_all(&self.pool)
                .await
                .unwrap();
        format!("{audit:?}{operations:?}")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_reports_json_the_exit_code_and_truncation_and_never_the_key() {
    let world = World::start().await;
    let reference = world.store_key_and_make_default().await;

    let get = world
        .cli(
            None,
            None,
            &[
                "machines",
                "endpoint-auth",
                "get",
                &world.machine_id,
                &world.endpoint_id,
            ],
        )
        .await;
    assert_eq!(get.code, 0, "{}", get.stderr);
    assert_eq!(get.json()["auth"]["credential"], reference);

    // Success: stdout, exit 0, the operation id.
    let ok = world
        .cli(
            None,
            None,
            &[
                "machines",
                "exec",
                &world.machine_id,
                "--",
                "hello",
                "world",
            ],
        )
        .await;
    assert_eq!(ok.code, 0, "{}", ok.stderr);
    let payload = ok.json();
    assert_eq!(payload["state"], "succeeded");
    assert_eq!(payload["exitCode"], 0);
    assert_eq!(payload["stdout"], "ran hello\n");
    assert_eq!(payload["truncatedStdout"], false);
    assert!(payload["operationId"].as_str().is_some());

    // The command's own exit code is the CLI's exit code.
    let failed = world
        .cli(
            None,
            None,
            &["machines", "exec", &world.machine_id, "--", "fail3"],
        )
        .await;
    assert_eq!(failed.code, 3, "{}", failed.stderr);
    let payload = failed.json();
    assert_eq!(payload["state"], "failed");
    assert_eq!(payload["exitCode"], 3);
    assert_eq!(payload["stderr"], "went wrong\n");

    // Truncation is reported, not hidden.
    let truncated = world
        .cli(
            None,
            None,
            &["machines", "exec", &world.machine_id, "--", "trunc"],
        )
        .await;
    assert_eq!(truncated.code, 0, "{}", truncated.stderr);
    assert_eq!(truncated.json()["truncatedStdout"], true);

    // A command that never reached an exit code is a plain failure.
    let killed = world
        .cli(
            None,
            None,
            &["machines", "exec", &world.machine_id, "--", "kill"],
        )
        .await;
    assert_eq!(killed.code, 1, "{}", killed.stderr);
    assert_eq!(killed.json()["reason"], "deadline_killed");

    // --script sends one word untouched.
    let script = world
        .cli(
            None,
            None,
            &[
                "machines",
                "exec",
                &world.machine_id,
                "--script",
                "--",
                "echo a | wc -c",
            ],
        )
        .await;
    assert_eq!(script.code, 0, "{}", script.stderr);
    assert_eq!(script.json()["stdout"], "ran echo a | wc -c\n");

    // An explicit auth overrides the default; the queue-only form answers
    // the operation.
    let queued = world
        .cli(
            None,
            None,
            &[
                "machines",
                "exec",
                &world.machine_id,
                "--no-wait",
                "--auth",
                "secret",
                "--credential",
                &reference,
                "--",
                "later",
            ],
        )
        .await;
    assert_eq!(queued.code, 0, "{}", queued.stderr);
    assert_eq!(queued.json()["kind"], "machine.exec");

    // Nothing the CLI printed or the controller stored carries the key.
    for text in [&ok.stdout, &failed.stdout, &queued.stdout, &get.stdout] {
        assert!(!text.contains(KEY_BODY), "{text}");
    }
    let stored = world.stored_text().await;
    assert!(!stored.contains(KEY_BODY), "{stored}");
    assert!(stored.contains("machine_exec_requested"), "{stored}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_is_refused_without_auth_and_for_a_machine_that_does_not_exist() {
    let world = World::start().await;
    let no_auth = world
        .cli(
            None,
            None,
            &["machines", "exec", &world.machine_id, "--", "id"],
        )
        .await;
    assert_ne!(no_auth.code, 0);
    assert!(
        no_auth.stderr.contains("no default auth"),
        "{}",
        no_auth.stderr
    );
    let missing = world
        .cli(
            None,
            None,
            &[
                "machines",
                "exec",
                "no-such-machine",
                "--auth",
                "agent",
                "--",
                "id",
            ],
        )
        .await;
    assert_ne!(missing.code, 0);
    assert!(missing.stderr.contains("not_found"), "{}", missing.stderr);
    let bad_key = world
        .cli(None, Some("ghp_notakey"), &["machines", "ssh-key", "store"])
        .await;
    assert_ne!(bad_key.code, 0);
    assert!(
        !bad_key.stderr.contains("ghp_notakey"),
        "{}",
        bad_key.stderr
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_collect_files_and_file_get_round_trip_through_the_cli() {
    let world = World::start().await;
    world.store_key_and_make_default().await;
    let local = world.work.path().join("upload.txt");
    std::fs::write(&local, b"agent uploaded bytes").unwrap();
    let local = local.display().to_string();

    let put = world
        .cli(
            None,
            None,
            &[
                "machines",
                "put",
                &world.machine_id,
                &local,
                "/home/agent/up.txt",
            ],
        )
        .await;
    assert_eq!(put.code, 0, "{}", put.stderr);
    let payload = put.json();
    assert_eq!(payload["state"], "succeeded");
    assert_eq!(payload["guestPath"], "/home/agent/up.txt");
    assert_eq!(payload["sizeBytes"], 20);

    // A second put without --overwrite is refused by the guest policy.
    let again = world
        .cli(
            None,
            None,
            &[
                "machines",
                "put",
                &world.machine_id,
                &local,
                "/home/agent/up.txt",
            ],
        )
        .await;
    assert_eq!(again.code, 1, "{}", again.stderr);
    assert_eq!(again.json()["reason"], "target_exists");
    let overwritten = world
        .cli(
            None,
            None,
            &[
                "machines",
                "put",
                &world.machine_id,
                &local,
                "/home/agent/up.txt",
                "--overwrite",
            ],
        )
        .await;
    assert_eq!(overwritten.code, 0, "{}", overwritten.stderr);

    // Collect what the guest holds and read it back.
    let collected = world
        .cli(
            None,
            None,
            &["machines", "collect", &world.machine_id, FIXTURE_FILE],
        )
        .await;
    assert_eq!(collected.code, 0, "{}", collected.stderr);
    let payload = collected.json();
    assert_eq!(payload["state"], "succeeded");
    let file_id = payload["files"][0]["fileId"].as_str().unwrap().to_owned();
    assert_eq!(payload["files"][0]["path"], FIXTURE_FILE);

    let listed = world
        .cli(None, None, &["machines", "files", &world.machine_id])
        .await;
    assert_eq!(listed.code, 0, "{}", listed.stderr);
    assert_eq!(listed.json()["items"][0]["id"], file_id);

    let out = world.work.path().join("fetched.json");
    let out_text = out.display().to_string();
    let got = world
        .cli(
            None,
            None,
            &["machines", "file-get", &file_id, "--out", &out_text],
        )
        .await;
    assert_eq!(got.code, 0, "{}", got.stderr);
    assert_eq!(got.json()["verified"], true);
    assert_eq!(std::fs::read(&out).unwrap(), FIXTURE_BYTES);

    // A path the machine does not have fails the collection, honestly.
    let missing = world
        .cli(
            None,
            None,
            &["machines", "collect", &world.machine_id, "/home/agent/nope"],
        )
        .await;
    assert_eq!(missing.code, 1, "{}", missing.stderr);
    assert_eq!(missing.json()["reason"], "collection_failed");
    assert_eq!(missing.json()["failures"][0]["reason"], "missing");

    let stored = world.stored_text().await;
    assert!(!stored.contains("agent uploaded bytes"), "{stored}");
    assert!(stored.contains("machine_put_requested"), "{stored}");
    assert!(stored.contains("machine_collect_requested"), "{stored}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delegated_lab_credential_cannot_use_machine_access() {
    let world = World::start().await;
    world.store_key_and_make_default().await;
    // The operator issues a Lab credential through the public API.
    let http = reqwest::Client::new();
    let issued: Value = http
        .post(format!("http://{}/api/v1/credentials", world.address))
        .json(&json!({
            "owner": "ci-a", "ttlSeconds": 3600, "templates": ["any"], "versions": [],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = issued["data"]["token"].as_str().unwrap().to_owned();
    let queued_before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM operations WHERE kind LIKE 'machine.%'")
            .fetch_one(&world.pool)
            .await
            .unwrap();
    let local = world.work.path().join("x.txt");
    std::fs::write(&local, b"x").unwrap();
    let local = local.display().to_string();
    for words in [
        vec!["machines", "exec", &world.machine_id, "--", "id"],
        vec!["machines", "put", &world.machine_id, &local, "/tmp/x"],
        vec!["machines", "collect", &world.machine_id, "/tmp/x"],
        vec!["machines", "files", &world.machine_id],
        vec!["machines", "ssh-key", "store"],
        vec![
            "machines",
            "endpoint-auth",
            "clear",
            &world.machine_id,
            &world.endpoint_id,
        ],
    ] {
        let refused = world.cli(Some(&token), Some(&key()), &words).await;
        assert_ne!(refused.code, 0, "{words:?} was allowed: {}", refused.stdout);
        assert!(
            refused.stderr.contains("denied") || refused.stderr.contains("403"),
            "{words:?}: {}",
            refused.stderr
        );
    }
    let queued_after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM operations WHERE kind LIKE 'machine.%'")
            .fetch_one(&world.pool)
            .await
            .unwrap();
    assert_eq!(queued_before, queued_after, "a refused command was queued");
}

#[test]
fn the_documented_grammar_parses_and_the_undocumented_does_not() {
    let parse = |words: &[&str]| {
        let owned: Vec<String> = words.iter().map(ToString::to_string).collect();
        fleetctl::parse(&owned)
    };
    for good in [
        &["machines", "exec", "m-1", "--", "uname", "-a"][..],
        &[
            "machines",
            "exec",
            "m-1",
            "--endpoint",
            "e-1",
            "--auth",
            "secret",
            "--credential",
            "r-1",
            "--timeout",
            "30",
            "--",
            "ls",
        ],
        &[
            "machines", "exec", "m-1", "--os", "windows", "--script", "--", "Get-Date",
        ],
        &[
            "machines",
            "put",
            "m-1",
            "./a.bin",
            "/tmp/a.bin",
            "--overwrite",
        ],
        &[
            "machines",
            "put",
            "m-1",
            "./a.bin",
            "C:\\tmp\\a.bin",
            "--os",
            "windows",
            "--no-wait",
        ],
        &["machines", "collect", "m-1", "/a", "/b", "--timeout", "30"],
        &["machines", "files", "m-1", "--limit", "5"],
        &["machines", "file-get", "f-1", "--out", "./out"],
        &[
            "machines",
            "endpoint-auth",
            "set",
            "m-1",
            "e-1",
            "--auth",
            "identity-file",
            "--identity",
            "/k",
        ],
        &["machines", "endpoint-auth", "get", "m-1", "e-1"],
        &["machines", "endpoint-auth", "clear", "m-1", "e-1"],
        &["machines", "ssh-key", "store"],
    ] {
        parse(good).unwrap_or_else(|error| panic!("{good:?} must parse: {error}"));
    }
    for bad in [
        &["machines", "exec", "m-1"][..],
        &["machines", "exec", "m-1", "--"],
        &["machines", "exec", "m-1", "--auth", "password", "--", "ls"],
        &["machines", "exec", "m-1", "--auth", "secret", "--", "ls"],
        &["machines", "exec", "m-1", "--credential", "r", "--", "ls"],
        &["machines", "exec", "m-1", "--script", "--", "a", "b"],
        &["machines", "exec", "m-1", "--os", "plan9", "--", "ls"],
        &["machines", "exec", "m-1", "--bogus", "--", "ls"],
        &["machines", "put", "m-1", "./a.bin"],
        &["machines", "collect", "m-1"],
        &["machines", "file-get", "f-1"],
        &["machines", "endpoint-auth", "set", "m-1", "e-1"],
        &["machines", "endpoint-auth", "frob", "m-1", "e-1"],
        &["machines", "ssh-key", "show"],
    ] {
        assert!(parse(bad).is_err(), "{bad:?} must not parse");
    }
}
