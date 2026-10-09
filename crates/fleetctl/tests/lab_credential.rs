//! #392 (ADR 0011): a delegated credential runs the whole Lab loop through
//! `fleetctl`, and nothing else. The controller is the real router over real
//! SQLite repositories, the Lab use cases, and the artifact store; only the
//! guest is replaced (a worker task completes the queued operations the way
//! the SSH and Proxmox executors would). The CLI is the real binary, run
//! with only `FLEET_TOKEN` set.

#![allow(clippy::too_many_lines)]

use std::collections::HashMap;
use std::io::Write as _;
use std::process::Command as Process;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use fleet_application::credentials::{CredentialStore as _, IssueCredential};
use fleet_application::lab::{
    ImagePinValidator, Lab, LabTemplate, LabTemplatePort, LabTemplateVersion, LeasePort,
    NewLabTemplate, NewLease, NewProvision, ProvisionPort, RecipeVersion,
};
use fleet_application::lab_artifacts::{ArtifactPolicy, LabArtifacts};
use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_controller::lab_artifacts_store::{
    FsArtifactStore, GuestFiles, LabArtifactDispatch, StagingFile,
};
use fleet_core::{CleanupStrategy, LabTemplateContent, LeaseState, ReadinessProbe};
use fleet_provider_ssh::FetchOutcome;
use fleet_storage_sqlite::{
    AuditSink, CredentialRepository, LabArtifactRepository, LabRepository, LeaseRepository,
    MachineRepository, OperationRepository, ProjectRepository, Store,
};
use serde_json::{Value, json};

const FIXTURE_FILE: &str = "/home/ci/evidence/report.json";
const FIXTURE_BYTES: &[u8] = b"{\"verdict\":\"pass\"}\n";

#[derive(Debug)]
struct NoPins;

#[async_trait]
impl ImagePinValidator for NoPins {
    async fn promoted_version(&self, version_id: &str) -> Result<Option<RecipeVersion>, String> {
        Ok(Some(RecipeVersion {
            id: version_id.to_owned(),
            recipe_id: "rcp-1".to_owned(),
            name: "ubuntu-base".to_owned(),
            description: String::new(),
            content_digest: "sha256:abc".to_owned(),
            content: "{}".to_owned(),
            source: fleet_core::RecipeSource::Iso,
            node: "pve".to_owned(),
            storage_pool: "local-lvm".to_owned(),
            published_at: 0,
            promoted_at: Some(0),
            promoted_by: Some("tester".to_owned()),
            promoted_build_id: Some("build-1".to_owned()),
            allow_insecure_tls: false,
        }))
    }
}

/// The guest's files.
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
}

/// Stands in for the Proxmox, SSH, and cleanup executors.
#[derive(Debug)]
struct GuestWorld {
    leases: Arc<LeaseRepository>,
    labs: Arc<LabRepository>,
    machine_id: String,
    endpoint_id: String,
}

#[async_trait]
impl OperationExecutor for GuestWorld {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: Value =
            serde_json::from_str(operation.payload_json.as_deref().unwrap_or("{}")).unwrap();
        let lease_id = payload["leaseId"].as_str().unwrap_or_default().to_owned();
        let result = match operation.kind.as_str() {
            "lab.provision" => {
                let now = fleet_core::SystemClock::now_unix_millis();
                let lease = self.leases.get(&lease_id).await?;
                let provision_id = lease.provision_id.clone().ok_or("no provision")?;
                let mut record = ProvisionPort::get(self.labs.as_ref(), &provision_id).await?;
                record.machine_id = Some(self.machine_id.clone());
                record.endpoint_id = Some(self.endpoint_id.clone());
                ProvisionPort::update(self.labs.as_ref(), &record).await?;
                let mut ready = lease;
                ready.state = LeaseState::Ready;
                ready.ready_at = Some(now);
                ready.expires_at = Some(now + 3_600_000);
                self.leases.update(&ready).await?;
                json!({})
            }
            "lab.exec" => json!({
                "exitCode": 0, "stdout": "hello from the guest\n", "stderr": "",
                "truncatedStdout": false, "truncatedStderr": false
            }),
            "lab.cleanup" => {
                let mut lease = self.leases.get(&lease_id).await?;
                lease.state = LeaseState::Released;
                self.leases.update(&lease).await?;
                json!({})
            }
            other => return Err(format!("the test guest does not run {other}")),
        };
        operations
            .complete(&operation.id, "succeeded", Some(&result.to_string()), None)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

struct World {
    address: std::net::SocketAddr,
    http: reqwest::Client,
    credentials: fleet_application::credentials::Credentials,
    credential_store: Arc<CredentialRepository>,
    leases: Arc<LeaseRepository>,
    labs: Arc<LabRepository>,
    pool: sqlx::SqlitePool,
    _store: Store,
    /// The allowed template and its version.
    template_id: String,
    version_id: String,
    /// A second template, never on an allow-list unless a test says so.
    other_version_id: String,
    /// A template whose cleanup retains the VM.
    keep_version_id: String,
    _dir: tempfile::TempDir,
    _server: tokio::task::JoinHandle<()>,
    _worker: tokio::task::JoinHandle<()>,
}

async fn publish(labs: &LabRepository, name: &str, cleanup: CleanupStrategy) -> (String, String) {
    let now = fleet_core::SystemClock::now_unix_millis();
    let content = LabTemplateContent {
        name: name.to_owned(),
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
        cleanup,
    };
    let template: LabTemplate = LabTemplatePort::create(
        labs,
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
                id: format!("version-{name}"),
                template_id: template.id.clone(),
                name: name.to_owned(),
                content,
                image_digest: "sha256:abc".to_owned(),
                published_by: "tester".to_owned(),
                published_at: now,
            },
        )
        .await
        .unwrap();
    (template.id, version.id)
}

impl World {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let leases = Arc::new(LeaseRepository::new(pool.clone()));
        let (template_id, version_id) = publish(&labs, "ci-base", CleanupStrategy::Destroy).await;
        let (_, other_version_id) = publish(&labs, "other", CleanupStrategy::Destroy).await;
        let (_, keep_version_id) = publish(&labs, "keeper", CleanupStrategy::Keep).await;
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
        let endpoint_id = machine.endpoints[0].id.clone();
        let artifact_store =
            Arc::new(FsArtifactStore::open(&dir.path().join("lab-artifacts"), 4096).unwrap());
        let artifacts = Arc::new(LabArtifacts::new(
            Arc::new(LabArtifactRepository::new(pool.clone())),
            artifact_store.clone(),
            leases.clone(),
            labs.clone(),
            Arc::new(AuditSink::new(pool.clone())),
            ArtifactPolicy {
                retention_seconds: 3_600,
                max_bytes: 4096,
            },
        ));
        let lab = Arc::new(
            Lab::new(
                labs.clone(),
                labs.clone(),
                leases.clone(),
                Arc::new(NoPins),
                Arc::new(ProjectRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )
            .with_artifacts(artifacts.clone()),
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
        // The worker: claims queued operations and runs them against the
        // stand-in guest, with the real artifact dispatch around it.
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
        let dispatch = LabArtifactDispatch::new(
            Arc::new(GuestWorld {
                leases: leases.clone(),
                labs: labs.clone(),
                machine_id: machine.id.clone(),
                endpoint_id: endpoint_id.clone(),
            }),
            artifacts,
            artifact_store,
            leases.clone(),
            labs.clone(),
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
        let grants = Arc::new(fleet_application::credentials::GrantBook::new());
        let credential_store = Arc::new(CredentialRepository::new(pool.clone()));
        let credentials = fleet_application::credentials::Credentials::new(
            credential_store.clone(),
            Arc::new(AuditSink::new(pool.clone())),
            Arc::new(fleet_auth::DelegatedTokenCrypto::new()),
            grants,
        );
        Self {
            address,
            http: reqwest::Client::new(),
            credentials,
            credential_store,
            leases,
            labs,
            pool,
            _store: store,
            template_id,
            version_id,
            other_version_id,
            keep_version_id,
            _dir: dir,
            _server: server,
            _worker: worker,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    /// One HTTP call as the trusted-LAN administrator (no credential).
    async fn admin(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        self.call(method, path, None, body).await
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut request = self.http.request(method, self.url(path));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let bytes = response.bytes().await.unwrap_or_default();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Issues a credential through the public API, as an administrator.
    async fn issue(&self, owner: &str, templates: &[&str], versions: &[&str]) -> (String, String) {
        let (status, body) = self
            .admin(
                reqwest::Method::POST,
                "/api/v1/credentials",
                Some(json!({
                    "owner": owner, "ttlSeconds": 3600,
                    "templates": templates, "versions": versions,
                })),
            )
            .await;
        assert_eq!(status, 201, "{body}");
        (
            body["data"]["id"].as_str().unwrap().to_owned(),
            body["data"]["token"].as_str().unwrap().to_owned(),
        )
    }

    /// A ready lease owned by `owner` whose guest is the registered machine.
    async fn ready_lease(&self, owner: &str, version_id: &str) -> String {
        let now = fleet_core::SystemClock::now_unix_millis();
        let lease = self
            .leases
            .create(
                &NewLease {
                    template_version_id: version_id.to_owned(),
                    purpose: "seeded".to_owned(),
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
            self.labs.as_ref(),
            &NewProvision {
                template_version_id: version_id.to_owned(),
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
        // Each guest is its own Lab machine.
        let machine = MachineRepository::new(self.pool.clone())
            .register(&RegisterMachine {
                name: format!("guest-{}", lease.id),
                description: String::new(),
                endpoints: vec![NewEndpoint {
                    kind: fleet_core::EndpointKind::Ssh,
                    reference: "root@192.0.2.11:22".to_owned(),
                }],
                tags: vec!["lab".to_owned()],
                groups: vec![],
            })
            .await
            .unwrap();
        record.machine_id = Some(machine.id.clone());
        record.endpoint_id = Some(machine.endpoints[0].id.clone());
        ProvisionPort::update(self.labs.as_ref(), &record)
            .await
            .unwrap();
        let mut ready = self.leases.get(&lease.id).await.unwrap();
        ready.state = LeaseState::Ready;
        ready.ready_at = Some(now);
        ready.expires_at = Some(now + 3_600_000);
        self.leases.update(&ready).await.unwrap();
        lease.id
    }

    /// Everything the credential and audit tables hold, as one text.
    async fn stored_text(&self) -> String {
        let credentials: Vec<(String, String, String)> =
            sqlx::query_as("SELECT token_hash, owner, label FROM delegated_credentials")
                .fetch_all(&self.pool)
                .await
                .unwrap();
        let audit: Vec<(String, String, Option<String>)> =
            sqlx::query_as("SELECT actor, metadata_json, resource FROM audit_events")
                .fetch_all(&self.pool)
                .await
                .unwrap();
        format!("{credentials:?}{audit:?}")
    }

    /// Runs the real `fleetctl` binary with only the given environment.
    async fn cli(&self, token: Option<&str>, words: &[&str]) -> Cli {
        let address = self.address;
        let token = token.map(str::to_owned);
        let words: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
        tokio::task::spawn_blocking(move || {
            let mut process = Process::new(env!("CARGO_BIN_EXE_fleetctl"));
            process
                .args(["--url", &format!("http://{address}"), "--output", "json"])
                .args(&words)
                .env_clear();
            if let Some(token) = &token {
                process.env("FLEET_TOKEN", token);
            }
            let output = process.output().expect("fleetctl must run");
            Cli {
                code: output.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
        })
        .await
        .unwrap()
    }
}

fn sha256_hex(text: &str) -> String {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    Sha256::digest(text.as_bytes())
        .iter()
        .fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_scoped_credential_runs_the_whole_lab_loop_through_fleetctl_and_nothing_else() {
    let world = World::start().await;
    let work = tempfile::tempdir().unwrap();

    // The operator issues the credential; the token is shown exactly once.
    let issued = world
        .cli(
            None,
            &[
                "credentials",
                "issue",
                "--owner",
                "release-qa",
                "--ttl",
                "3600",
                "--template",
                &world.template_id,
                "--label",
                "ci run",
            ],
        )
        .await;
    assert_eq!(issued.code, 0, "{}", issued.stderr);
    let issued = issued.json();
    let token = issued["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("fmdc1."), "{token}");
    let credential_id = issued["id"].as_str().unwrap().to_owned();
    let listed = world.cli(None, &["credentials", "list"]).await;
    assert!(
        !listed.stdout.contains(&token),
        "the token is never listed again"
    );
    assert_eq!(listed.json()["items"][0]["status"], "active");

    // With only the credential: create.
    let created = world
        .cli(
            Some(&token),
            &[
                "lab",
                "create",
                &world.version_id,
                "--purpose",
                "release-qa candidate=c1 run=r9",
                "--wait",
                "--timeout",
                "60",
            ],
        )
        .await;
    assert_eq!(created.code, 0, "{} {}", created.stdout, created.stderr);
    let lease = created.json();
    assert_eq!(lease["state"], "ready");
    assert_eq!(lease["owner"], "credential:release-qa");
    let lease_id = lease["id"].as_str().unwrap().to_owned();

    // status
    let status = world.cli(Some(&token), &["lab", "status", &lease_id]).await;
    assert_eq!(status.code, 0, "{}", status.stderr);
    assert_eq!(status.json()["state"], "ready");

    // exec
    let exec = world
        .cli(
            Some(&token),
            &["lab", "exec", &lease_id, "--wait", "--", "echo", "hi"],
        )
        .await;
    assert_eq!(exec.code, 0, "{} {}", exec.stdout, exec.stderr);
    assert_eq!(exec.json()["stdout"], "hello from the guest\n");

    // collect
    let collect = world
        .cli(
            Some(&token),
            &["lab", "collect", &lease_id, FIXTURE_FILE, "--wait"],
        )
        .await;
    assert_eq!(collect.code, 0, "{} {}", collect.stdout, collect.stderr);
    let collected = collect.json();
    assert_eq!(collected["state"], "succeeded");

    // artifacts, artifact-get
    let artifacts = world
        .cli(Some(&token), &["lab", "artifacts", "--lease", &lease_id])
        .await;
    assert_eq!(artifacts.code, 0, "{}", artifacts.stderr);
    let artifacts = artifacts.json();
    let items = artifacts["items"].as_array().unwrap();
    assert!(items.len() >= 2, "{artifacts}");
    assert!(
        items
            .iter()
            .all(|item| item["owner"] == "credential:release-qa")
    );
    let file = items
        .iter()
        .find(|item| {
            item["name"]
                .as_str()
                .is_some_and(|name| name.ends_with("report.json"))
        })
        .expect("the collected file is listed");
    let out = work.path().join("report.json");
    let got = world
        .cli(
            Some(&token),
            &[
                "lab",
                "artifact-get",
                file["id"].as_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
            ],
        )
        .await;
    assert_eq!(got.code, 0, "{} {}", got.stdout, got.stderr);
    assert_eq!(std::fs::read(&out).unwrap(), FIXTURE_BYTES);

    // extend
    let extended = world
        .cli(
            Some(&token),
            &["lab", "extend", &lease_id, "--seconds", "600"],
        )
        .await;
    assert_eq!(extended.code, 0, "{} {}", extended.stdout, extended.stderr);

    // The credential sees its own leases only.
    let admin_lease = world
        .ready_lease(fleet_auth::LAN_PRINCIPAL_ID, &world.version_id)
        .await;
    let leases = world.cli(Some(&token), &["lab", "leases"]).await;
    let ids: Vec<String> = leases.json()["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        ids,
        vec![lease_id.clone()],
        "{admin_lease} must stay invisible"
    );

    // destroy
    let destroyed = world
        .cli(
            Some(&token),
            &["lab", "destroy", &lease_id, "--wait", "--timeout", "60"],
        )
        .await;
    assert_eq!(
        destroyed.code, 0,
        "{} {}",
        destroyed.stdout, destroyed.stderr
    );
    assert_eq!(destroyed.json()["state"], "released");

    // What the credential cannot do, through the same CLI.
    let second = world
        .ready_lease("credential:release-qa", &world.version_id)
        .await;
    for words in [
        vec!["lab", "destroy", &second, "--keep"],
        vec!["lab", "templates"],
        vec!["lab", "provisions"],
        vec!["lab", "pool", "list"],
        vec!["lab", "sweep"],
        vec!["lab", "status", &admin_lease],
        vec!["lab", "exec", &admin_lease, "--wait", "--", "id"],
        vec!["lab", "extend", &admin_lease, "--seconds", "60"],
        vec!["lab", "destroy", &admin_lease],
        vec!["lab", "create", &world.other_version_id, "--purpose", "no"],
        vec!["lab", "create", &world.keep_version_id, "--purpose", "no"],
        vec!["proxmox", "accounts"],
        vec!["machines", "list"],
        vec!["images", "recipes"],
        vec!["audit", "list"],
        vec!["operations", "list"],
        vec!["credentials", "list"],
        vec![
            "credentials",
            "issue",
            "--owner",
            "x",
            "--ttl",
            "60",
            "--template",
            "t",
        ],
        vec!["credentials", "revoke", &credential_id],
        vec!["tailnet", "status"],
    ] {
        let refused = world.cli(Some(&token), &words).await;
        assert_ne!(
            refused.code, 0,
            "{words:?} must be refused: {}",
            refused.stdout
        );
        assert!(
            refused.stderr.contains("403")
                || refused.stderr.contains("404")
                || refused.stderr.contains("503"),
            "{words:?}: {}",
            refused.stderr
        );
    }
    // The second lease was only refused `keep`; it is still releasable.
    let released = world.cli(Some(&token), &["lab", "destroy", &second]).await;
    assert_eq!(released.code, 0, "{}", released.stderr);

    // The token is shown once and never again: not in any output, not in
    // the audit ledger, not in the database (only its hash is).
    let everything = [
        &created, &status, &exec, &collect, &got, &extended, &destroyed,
    ]
    .iter()
    .fold(String::new(), |mut all, cli| {
        all.push_str(&cli.stdout);
        all.push_str(&cli.stderr);
        all
    });
    assert!(!everything.contains(&token));
    let (_, audit) = world
        .admin(reqwest::Method::GET, "/api/v1/audit?limit=200", None)
        .await;
    assert!(!audit.to_string().contains(&token));
    let rows = world.stored_text().await;
    assert!(!rows.contains(&token), "the token must not be stored");
    assert!(
        rows.contains(&sha256_hex(&token)),
        "only its hash is stored"
    );

    // Every use is audited under the owner.
    let (_, uses) = world
        .admin(
            reqwest::Method::GET,
            "/api/v1/audit?action=credential.use&limit=200",
            None,
        )
        .await;
    let uses = uses["items"].as_array().unwrap();
    assert!(uses.len() >= 20, "{} uses audited", uses.len());
    assert!(uses.iter().all(|event| {
        event["actor"]
            .as_str()
            .is_some_and(|actor| actor.starts_with("credential:release-qa:"))
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fleetctl_never_prints_the_token_and_refuses_a_malformed_one() {
    let world = World::start().await;
    let (_, token) = world.issue("release-qa", &[&world.template_id], &[]).await;
    let ok = world.cli(Some(&token), &["lab", "leases"]).await;
    assert_eq!(ok.code, 0);
    assert!(!ok.stdout.contains(&token) && !ok.stderr.contains(&token));
    let bad = world.cli(Some("not-a-token"), &["lab", "leases"]).await;
    assert_ne!(bad.code, 0);
    assert!(bad.stderr.contains("FLEET_TOKEN"));
    assert!(!bad.stderr.contains("not-a-token"));
    // A well-formed token that nobody issued is a 401, not an admin call.
    let forged = format!("fmdc1.{}", "ab".repeat(32));
    let refused = world.cli(Some(&forged), &["lab", "leases"]).await;
    assert_ne!(refused.code, 0);
    assert!(refused.stderr.contains("401"), "{}", refused.stderr);
    assert!(!refused.stderr.contains(&forged));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_and_revocation_take_effect_on_the_next_request() {
    let world = World::start().await;
    let (id, token) = world.issue("release-qa", &[&world.template_id], &[]).await;
    let (status, _) = world
        .call(
            reqwest::Method::GET,
            "/api/v1/lab/leases",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200);

    // Revocation.
    let (status, _) = world
        .admin(
            reqwest::Method::POST,
            &format!("/api/v1/credentials/{id}/revoke"),
            None,
        )
        .await;
    assert_eq!(status, 200);
    let (status, body) = world
        .call(
            reqwest::Method::GET,
            "/api/v1/lab/leases",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("authentication_required"))
    );
    // Revoking again keeps the first revocation.
    let (status, _) = world
        .admin(
            reqwest::Method::POST,
            &format!("/api/v1/credentials/{id}/revoke"),
            None,
        )
        .await;
    assert_eq!(status, 200);

    // Expiry: a credential issued in the past is expired when presented.
    let now = fleet_core::SystemClock::now_unix_millis();
    let issued = world
        .credentials
        .issue(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            IssueCredential {
                owner: "release-qa".to_owned(),
                ttl_seconds: 60,
                templates: vec![world.template_id.clone()],
                versions: vec![],
                label: String::new(),
            },
            now - 120_000,
        )
        .await
        .unwrap();
    let (status, _) = world
        .call(
            reqwest::Method::GET,
            "/api/v1/lab/leases",
            Some(&issued.token),
            None,
        )
        .await;
    assert_eq!(status, 401);
    // The denied attempts are audited under the credential's owner.
    let (_, denied) = world
        .admin(
            reqwest::Method::GET,
            "/api/v1/audit?action=credential.use&outcome=denied&limit=50",
            None,
        )
        .await;
    let denied = denied["items"].as_array().unwrap();
    assert!(denied.len() >= 2, "{denied:?}");
    assert!(
        denied
            .iter()
            .all(|event| event["reason"] == "policy.credential_inactive")
    );
    // Unknown ids are 404 for the operator.
    let (status, _) = world
        .admin(
            reqwest::Method::POST,
            "/api/v1/credentials/nope/revoke",
            None,
        )
        .await;
    assert_eq!(status, 404);
    let _ = world.credential_store.list().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_presented_credential_never_falls_back_to_administrator() {
    let world = World::start().await;
    let (_, token) = world.issue("release-qa", &[&world.template_id], &[]).await;
    // The administrator surface is open without a credential...
    let (status, _) = world
        .admin(reqwest::Method::GET, "/api/v1/credentials", None)
        .await;
    assert_eq!(status, 200);
    // ...and closed to the credential.
    let (status, body) = world
        .call(
            reqwest::Method::GET,
            "/api/v1/credentials",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 403, "{body}");
    // A tampered token is not that credential and not an administrator.
    let mut tampered = token.clone();
    tampered.pop();
    tampered.push(if token.ends_with('0') { '1' } else { '0' });
    let (status, _) = world
        .call(
            reqwest::Method::GET,
            "/api/v1/credentials",
            Some(&tampered),
            None,
        )
        .await;
    assert_eq!(status, 401);
    // A malformed token of the delegated scheme is refused too.
    let (status, _) = world
        .call(
            reqwest::Method::GET,
            "/api/v1/credentials",
            Some("fmdc1.short"),
            None,
        )
        .await;
    assert_eq!(status, 401);
    // Another bearer scheme is not ours: the listener decides as before.
    let (status, _) = world
        .call(
            reqwest::Method::GET,
            "/api/v1/credentials",
            Some("some-other-bearer"),
            None,
        )
        .await;
    assert_eq!(status, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_template_allow_list_and_keep_are_enforced() {
    let world = World::start().await;
    let (_, by_template) = world.issue("ci-a", &[&world.template_id], &[]).await;
    let (_, by_version) = world.issue("ci-b", &[], &[&world.version_id]).await;
    let lease = |version: &str| json!({ "templateVersionId": version, "purpose": "allow-list" });

    for token in [&by_template, &by_version] {
        let (status, body) = world
            .call(
                reqwest::Method::POST,
                "/api/v1/lab/leases",
                Some(token),
                Some(lease(&world.version_id)),
            )
            .await;
        assert_eq!(status, 201, "{body}");
    }
    // A template outside the allow-list, a template that keeps its VM, an
    // explicit project, and a version that does not exist are all refused
    // the same way.
    for (token, body) in [
        (&by_template, lease(&world.other_version_id)),
        (&by_version, lease(&world.other_version_id)),
        (&by_template, lease(&world.keep_version_id)),
        (&by_template, lease("no-such-version")),
        (
            &by_template,
            json!({ "templateVersionId": world.version_id, "purpose": "p", "projectId": "project-1" }),
        ),
    ] {
        let (status, response) = world
            .call(
                reqwest::Method::POST,
                "/api/v1/lab/leases",
                Some(token),
                Some(body.clone()),
            )
            .await;
        assert_eq!(status, 403, "{body}: {response}");
    }
    // The administrator is unaffected by the allow-lists.
    let (status, _) = world
        .admin(
            reqwest::Method::POST,
            "/api/v1/lab/leases",
            Some(lease(&world.keep_version_id)),
        )
        .await;
    assert_eq!(status, 201);

    // keep, even of its own lease.
    let own = world
        .ready_lease("credential:ci-a", &world.version_id)
        .await;
    let (status, _) = world
        .call(
            reqwest::Method::POST,
            &format!("/api/v1/lab/leases/{own}/release"),
            Some(&by_template),
            Some(json!({ "keep": true })),
        )
        .await;
    assert_eq!(status, 403);
    let (status, _) = world
        .call(
            reqwest::Method::POST,
            &format!("/api/v1/lab/leases/{own}/release"),
            Some(&by_template),
            Some(json!({ "keep": false })),
        )
        .await;
    assert_eq!(status, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leases_artifacts_and_operations_are_scoped_to_their_owner() {
    let world = World::start().await;
    let (_, mine) = world.issue("ci-a", &[&world.template_id], &[]).await;
    let (_, theirs) = world.issue("ci-b", &[&world.template_id], &[]).await;
    let (_, rotated) = world.issue("ci-a", &[&world.template_id], &[]).await;

    let lease = world
        .ready_lease("credential:ci-a", &world.version_id)
        .await;
    let (status, exec) = world
        .call(
            reqwest::Method::POST,
            &format!("/api/v1/lab/leases/{lease}/exec"),
            Some(&mine),
            Some(json!({ "script": "true" })),
        )
        .await;
    assert_eq!(status, 202, "{exec}");
    let operation = exec["data"]["id"].as_str().unwrap().to_owned();
    let (status, collect) = world
        .call(
            reqwest::Method::POST,
            &format!("/api/v1/lab/leases/{lease}/artifacts/collect"),
            Some(&mine),
            Some(json!({ "paths": [FIXTURE_FILE] })),
        )
        .await;
    assert_eq!(status, 202, "{collect}");
    // Wait for the worker to store the artifacts.
    let mut artifact = Value::Null;
    for _ in 0..100 {
        let (_, listed) = world
            .call(
                reqwest::Method::GET,
                "/api/v1/lab/artifacts",
                Some(&mine),
                None,
            )
            .await;
        if let Some(item) = listed["items"].as_array().and_then(|items| items.first()) {
            artifact = item.clone();
            if listed["items"].as_array().unwrap().len() >= 2 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let artifact_id = artifact["id"]
        .as_str()
        .expect("an artifact was stored")
        .to_owned();

    // The owner's other credential (rotation) sees the same things.
    let (status, _) = world
        .call(
            reqwest::Method::GET,
            &format!("/api/v1/lab/leases/{lease}"),
            Some(&rotated),
            None,
        )
        .await;
    assert_eq!(status, 200);

    // Another owner sees none of it.
    let lease_path = format!("/api/v1/lab/leases/{lease}");
    for (method, path, body) in [
        (reqwest::Method::GET, lease_path.clone(), None),
        (
            reqwest::Method::POST,
            format!("{lease_path}/exec"),
            Some(json!({ "script": "id" })),
        ),
        (
            reqwest::Method::POST,
            format!("{lease_path}/release"),
            Some(json!({ "keep": false })),
        ),
        (
            reqwest::Method::POST,
            format!("{lease_path}/extend"),
            Some(json!({ "bySeconds": 60 })),
        ),
        (
            reqwest::Method::POST,
            format!("{lease_path}/provision"),
            Some(json!({})),
        ),
        (
            reqwest::Method::POST,
            format!("{lease_path}/cleanup/retry"),
            None,
        ),
        (
            reqwest::Method::POST,
            format!("{lease_path}/artifacts/collect"),
            Some(json!({ "paths": [FIXTURE_FILE] })),
        ),
        (
            reqwest::Method::GET,
            format!("/api/v1/lab/artifacts/{artifact_id}"),
            None,
        ),
        (
            reqwest::Method::GET,
            format!("/api/v1/lab/artifacts/{artifact_id}/content"),
            None,
        ),
        (
            reqwest::Method::GET,
            format!("/api/v1/operations/{operation}"),
            None,
        ),
    ] {
        let (status, response) = world.call(method.clone(), &path, Some(&theirs), body).await;
        assert_eq!(
            status, 404,
            "{method} {path} must not reveal another owner's resource: {response}"
        );
        // The same call by the owner is not refused for scope.
        let owner_token = &mine;
        let (owner_status, _) = world
            .call(method.clone(), &path, Some(owner_token), None)
            .await;
        assert_ne!(owner_status, 404, "{method} {path} for its owner");
    }
    let (status, listed) = world
        .call(
            reqwest::Method::GET,
            "/api/v1/lab/artifacts",
            Some(&theirs),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert!(listed["items"].as_array().unwrap().is_empty());
    let (_, listed) = world
        .call(
            reqwest::Method::GET,
            "/api/v1/lab/leases",
            Some(&theirs),
            None,
        )
        .await;
    assert!(listed["items"].as_array().unwrap().is_empty());
    // Artifacts record the owner.
    assert_eq!(artifact["owner"], "credential:ci-a");
    // The owner's own operation reads; a non-Lab operation does not.
    let (status, _) = world
        .call(
            reqwest::Method::GET,
            &format!("/api/v1/operations/{operation}"),
            Some(&mine),
            None,
        )
        .await;
    assert_eq!(status, 200);
    let (status, _) = world
        .call(
            reqwest::Method::GET,
            "/api/v1/operations",
            Some(&mine),
            None,
        )
        .await;
    assert_eq!(status, 403);
}

/// Every API route, classified for the delegated principal. The allowed
/// routes are the Lab loop; every other route must never succeed for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_route_is_allowed_refused_or_unreachable_for_the_credential() {
    const ALLOWED: &[(&str, &str)] = &[
        ("GET", "/api/v1/lab/leases"),
        ("POST", "/api/v1/lab/leases"),
        ("GET", "/api/v1/lab/leases/{leaseId}"),
        ("POST", "/api/v1/lab/leases/{leaseId}/provision"),
        ("POST", "/api/v1/lab/leases/{leaseId}/release"),
        ("POST", "/api/v1/lab/leases/{leaseId}/cleanup/retry"),
        ("POST", "/api/v1/lab/leases/{leaseId}/extend"),
        ("POST", "/api/v1/lab/leases/{leaseId}/exec"),
        ("POST", "/api/v1/lab/leases/{leaseId}/artifacts/collect"),
        ("GET", "/api/v1/lab/artifacts"),
        ("GET", "/api/v1/lab/artifacts/{artifactId}"),
        ("GET", "/api/v1/lab/artifacts/{artifactId}/content"),
        ("GET", "/api/v1/operations/{operationId}"),
    ];
    const FILTERED: &[&str] = &["/api/v1/desired/drift", "/api/v1/skills/matrix"];
    let world = World::start().await;
    // Something to filter: a machine the credential may not see.
    let (_, token) = world.issue("ci-a", &[&world.template_id], &[]).await;
    let document: Value = serde_json::from_str(&fleet_api::openapi_json()).unwrap();
    let mut swept = 0;
    let mut leaked: Vec<String> = Vec::new();
    for (path, item) in document["paths"].as_object().unwrap() {
        for method in item.as_object().unwrap().keys() {
            let method = method.to_uppercase();
            if ALLOWED.contains(&(method.as_str(), path.as_str())) {
                continue;
            }
            // Public metadata: no principal is needed to read it.
            if method == "GET" && path == "/api/v1/meta" {
                let (status, _) = world
                    .call(reqwest::Method::GET, path, Some(&token), None)
                    .await;
                assert_eq!(status, 200);
                swept += 1;
                continue;
            }
            // Fleet-wide listings whose rows the use case authorizes one
            // by one: the credential is answered with an empty page.
            if method == "GET" && FILTERED.contains(&path.as_str()) {
                let (status, response) = world
                    .call(reqwest::Method::GET, path, Some(&token), None)
                    .await;
                assert_eq!(status, 200, "{path}");
                assert!(response["items"].as_array().unwrap().is_empty(), "{path}");
                swept += 1;
                continue;
            }
            // Fill every path parameter with an id that exists nowhere.
            let mut concrete = String::new();
            let mut rest = path.as_str();
            while let Some(start) = rest.find('{') {
                concrete.push_str(&rest[..start]);
                concrete.push_str("unknown-id");
                rest = &rest[rest[start..]
                    .find('}')
                    .map_or(rest.len(), |end| start + end + 1)..];
            }
            concrete.push_str(rest);
            let body = (method != "GET" && method != "DELETE").then(|| json!({}));
            let (status, response) = world
                .call(method.parse().unwrap(), &concrete, Some(&token), body)
                .await;
            if !((400..500).contains(&status) || status == 503) {
                leaked.push(format!("{method} {path} -> {status}: {response}"));
            }
            swept += 1;
        }
    }
    assert!(
        leaked.is_empty(),
        "routes open to a delegated credential:\n{}",
        leaked.join("\n")
    );
    assert!(swept >= 100, "only {swept} routes swept");
    // The allowed routes are reachable: not refused for the principal.
    for (method, path) in ALLOWED {
        let concrete = path
            .replace("{leaseId}", "unknown-id")
            .replace("{artifactId}", "unknown-id")
            .replace("{operationId}", "unknown-id");
        let body = (*method != "GET").then(|| json!({}));
        let (status, response) = world
            .call(method.parse().unwrap(), &concrete, Some(&token), body)
            .await;
        assert_ne!(
            response["message"]
                .as_str()
                .map(|m| m.contains("policy.action_not_delegated")),
            Some(true),
            "{method} {path} ({status}) must not be refused as not delegated"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keyed_creation_and_lease_filters_stay_inside_the_owner() {
    let world = World::start().await;
    let (_, mine) = world.issue("ci-a", &[&world.template_id], &[]).await;
    let (_, rotated) = world.issue("ci-a", &[&world.template_id], &[]).await;
    let (_, theirs) = world.issue("ci-b", &[&world.template_id], &[]).await;
    let create = |token: String, key: &'static str| {
        let http = world.http.clone();
        let url = world.url("/api/v1/lab/leases");
        async move {
            let response = http
                .post(url)
                .bearer_auth(token)
                .header("idempotency-key", key)
                .json(&json!({ "templateVersionId": "version-ci-base", "purpose": "keyed" }))
                .send()
                .await
                .unwrap();
            let status = response.status().as_u16();
            (status, response.json::<Value>().await.unwrap())
        }
    };
    let (first, body) = create(mine.clone(), "run-1").await;
    assert_eq!(first, 201, "{body}");
    let lease_id = body["data"]["id"].as_str().unwrap().to_owned();
    // A retry, even with the owner's rotated token, replays the lease.
    let (again, body) = create(rotated.clone(), "run-1").await;
    assert_eq!(again, 200, "{body}");
    assert_eq!(body["data"]["id"], lease_id.as_str());
    // Another owner with the same key gets its own lease.
    let (other, body) = create(theirs.clone(), "run-1").await;
    assert_eq!(other, 201, "{body}");
    assert_ne!(body["data"]["id"], lease_id.as_str());

    // The filters, including an explicit owner, never widen the scope.
    for query in [
        "",
        "?purpose=keyed",
        "?purposePrefix=key",
        "?owner=credential:ci-b",
        "?owner=anonymous-lan-admin",
    ] {
        let (status, listed) = world
            .call(
                reqwest::Method::GET,
                &format!("/api/v1/lab/leases{query}"),
                Some(&mine),
                None,
            )
            .await;
        assert_eq!(status, 200, "{query}: {listed}");
        let ids: Vec<&str> = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect();
        let expected: Vec<&str> = if query.starts_with("?owner") {
            vec![]
        } else {
            vec![lease_id.as_str()]
        };
        assert_eq!(ids, expected, "{query}");
    }
    // Through the CLI too.
    let listed = world
        .cli(Some(&mine), &["lab", "leases", "--purpose", "keyed"])
        .await;
    assert_eq!(listed.code, 0, "{}", listed.stderr);
    assert_eq!(listed.json()["items"].as_array().unwrap().len(), 1);
}
