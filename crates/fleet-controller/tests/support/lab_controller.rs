//! A restartable Lab controller for the failure-injection suite (FM-741).
//!
//! [`Controller::start`] composes the production Lab executors the way
//! `main.rs` does: `LabDispatch` over the provision executor, the FM-713
//! cleanup executor with its reviewed destroy executor, and the FM-716
//! sweeper with the real Proxmox guest inventory. Everything runs over a
//! [`Store`] opened on the world's one SQLite file and the shared
//! [`FakePve`]. [`Controller::kill`] drops the in-flight work at its crash
//! point together with the store, and a new `start` over the same file is
//! the restarted controller: nothing survives in memory.
//!
//! The operation queue is driven one claim at a time through the same
//! `Operations::tick` the worker host composes, so a run is deterministic.
//! SSH trust and the bootstrap project run through a scripted readiness
//! port (the production one needs SSH to a real guest).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision};
use fleet_application::lab::{
    AttachProvisionOutcome, CloneTargetReservation, ImageArtifactPort, ImagePinValidator, Lab,
    LabReadinessPort, LabTemplatePort, LabTemplateVersion, LeasePort, NewLabTemplate, NewLease,
    NewProvision, ProvisionPort, ProvisionRecord, guest_owned,
};
use fleet_application::operation::{NewOperation, Operation, Operations};
use fleet_application::project::{NewProject, ProjectPort as _};
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccountPort, ProxmoxCredentialStore,
};
use fleet_application::worker::OperationExecutor;
use fleet_controller::lab_cleanup::LabCleanupExecutor;
use fleet_controller::lab_sweeper::{LabSweeper, ProxmoxLabGuests, TickReport};
use fleet_controller::proxmox_exec::{
    LabDispatch, ProvisionExecutor, ProxmoxDestructiveExecutor, ProxmoxDispatch,
    ProxmoxLifecycleExecutor,
};
use fleet_core::{
    CleanupStrategy, GuestState, LabTemplateContent, Lease, LeaseState, ReadinessProbe,
};
use fleet_provider_proxmox::ProxmoxClient;
use fleet_storage_sqlite::{
    AuditSink, LabRepository, LeaseRepository, MachineRepository, OperationRepository,
    ProjectRepository, ProxmoxAccountRepository, Store,
};

use super::fake_pve::{
    API_HOST, FINGERPRINT, FakePve, Fault, Faults, Step, TEMPLATE_NODE, TEMPLATE_VMID,
};

/// The claim lease the worker maintenance applies (the host's default).
pub const LEASE_MS: i64 = fleet_controller::worker::LEASE_MS;
/// The template's ready TTL: a day, so the hour the suite lets pass after a
/// restart never expires a lease by accident.
pub const TTL_SECONDS: u32 = 86_400;
/// One hour in milliseconds.
pub const HOUR_MS: i64 = 3_600_000;
/// The pinned image version.
const IMAGE_VERSION: &str = "image-version-1";
const PRINCIPAL: &str = fleet_auth::LAN_PRINCIPAL_ID;

/// Allows everything: the trusted-LAN mode the controller runs in.
#[derive(Debug)]
pub struct AllowAll;

impl Authorizer for AllowAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

/// The world a controller runs in. It outlives every controller: the one
/// SQLite file, the Proxmox host, and the fault script.
#[derive(Debug)]
pub struct World {
    _dir: tempfile::TempDir,
    /// The controller's database file.
    pub database: PathBuf,
    /// The fault script shared by the host and the controller wrappers.
    pub faults: Arc<Faults>,
    /// The fake Proxmox host.
    pub pve: Arc<FakePve>,
    /// The trusted Proxmox account.
    pub account_id: String,
    /// The published Lab template version every lease uses.
    pub version_id: String,
}

impl World {
    /// A fresh world whose template allows `readiness_seconds` from boot to
    /// ready, prepares a bootstrap project, and keeps leases for a day.
    pub async fn new(readiness_seconds: u32) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("fleet.db");
        let faults = Arc::new(Faults::default());
        let pve = FakePve::new(faults.clone());
        let store = Store::open(&database).await.unwrap();
        let pool = store.pool().clone();
        let accounts = ProxmoxAccountRepository::new(pool.clone());
        let account = accounts
            .create(&NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: API_HOST.to_owned(),
                port: None,
                token_id: "fleet@pve!lab".to_owned(),
            })
            .await
            .unwrap();
        accounts
            .set_fingerprint(&account.id, Some(FINGERPRINT.to_owned()))
            .await
            .unwrap();
        let project = ProjectRepository::new(pool.clone())
            .create(&NewProject {
                fetch: fleet_core::RemoteFetch::default(),
                remote: "example.org/demo".to_owned(),
                idempotency_key: None,
                name: "demo".to_owned(),
                description: String::new(),
            })
            .await
            .unwrap();
        let labs = LabRepository::new(pool.clone());
        let now = fleet_core::SystemClock::now_unix_millis();
        let content = LabTemplateContent {
            name: "lab-base".to_owned(),
            description: String::new(),
            image_version_id: IMAGE_VERSION.to_owned(),
            cores: 2,
            memory_mib: 2048,
            disk_gib: 20,
            bootstrap_project_id: Some(project.id.clone()),
            readiness_probe: ReadinessProbe::GuestAgent,
            readiness_command: None,
            ssh_user: "root".to_owned(),
            ssh_port: 22,
            ssh_trust_mode: "tofu".to_owned(),
            ssh_fingerprint: None,
            readiness_deadline_seconds: readiness_seconds,
            ttl_seconds: TTL_SECONDS,
            cleanup: CleanupStrategy::Destroy,
        };
        let template = LabTemplatePort::create(
            &labs,
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
                    published_by: PRINCIPAL.to_owned(),
                    published_at: now,
                },
            )
            .await
            .unwrap();
        pool.close().await;
        drop(store);
        Self {
            _dir: dir,
            database,
            faults,
            pve,
            account_id: account.id,
            version_id: version.id,
        }
    }
}

/// The promoted image the template pins.
#[derive(Debug)]
struct Promoted;

#[async_trait]
impl ImagePinValidator for Promoted {
    async fn promoted_version(
        &self,
        version_id: &str,
    ) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok(
            (version_id == IMAGE_VERSION).then(|| fleet_core::RecipeVersion {
                id: IMAGE_VERSION.to_owned(),
                recipe_id: "recipe-1".to_owned(),
                name: "lab-image".to_owned(),
                content_digest: "sha256:abc".to_owned(),
                description: String::new(),
                content: "{}".to_owned(),
                source: fleet_core::RecipeSource::Clone,
                node: TEMPLATE_NODE.to_owned(),
                storage_pool: "local-lvm".to_owned(),
                published_at: 0,
                promoted_at: Some(0),
                promoted_by: Some(PRINCIPAL.to_owned()),
                promoted_build_id: Some("build-1".to_owned()),
                allow_insecure_tls: false,
            }),
        )
    }
}

/// The promoted build's recorded template.
#[derive(Debug)]
struct Artifacts;

#[async_trait]
impl ImageArtifactPort for Artifacts {
    async fn template_vmid(&self, image_version_id: &str) -> Result<Option<u32>, String> {
        Ok((image_version_id == IMAGE_VERSION).then_some(TEMPLATE_VMID))
    }

    async fn promoted_template_vmids(&self) -> Result<Vec<u32>, String> {
        Ok(vec![TEMPLATE_VMID])
    }
}

/// The account's token, from the secret store. Never real material.
#[derive(Debug)]
struct OneSecret;

#[async_trait]
impl ProxmoxCredentialStore for OneSecret {
    async fn load(&self, _account_id: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(Some("fake-token-material".to_owned()))
    }
    async fn store(&self, _account_id: &str, _secret: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("the Lab never stores credentials")
    }
    async fn clear(&self, _account_id: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("the Lab never clears credentials")
    }
}

/// The provision store, with crash points after its commits: the
/// reservation, the machine registration, and the readiness transaction.
#[derive(Debug)]
struct Interruptible {
    inner: Arc<LabRepository>,
    faults: Arc<Faults>,
}

impl Interruptible {
    async fn after(&self, step: Step) {
        if matches!(self.faults.take(step), Some(Fault::CrashAfter)) {
            self.faults.crash::<()>().await;
        }
    }
}

#[async_trait]
impl ProvisionPort for Interruptible {
    async fn create(&self, new: &NewProvision, now: i64) -> Result<ProvisionRecord, String> {
        ProvisionPort::create(self.inner.as_ref(), new, now).await
    }
    async fn find_by_idempotency_key(&self, key: &str) -> Result<Option<ProvisionRecord>, String> {
        self.inner.find_by_idempotency_key(key).await
    }
    async fn get(&self, id: &str) -> Result<ProvisionRecord, String> {
        ProvisionPort::get(self.inner.as_ref(), id).await
    }
    async fn update(&self, record: &ProvisionRecord) -> Result<(), String> {
        ProvisionPort::update(self.inner.as_ref(), record).await
    }
    async fn abandon(&self, id: &str) -> Result<Option<ProvisionRecord>, String> {
        self.inner.abandon(id).await
    }
    async fn complete_ready(
        &self,
        record: &ProvisionRecord,
        lease_expires_at: Option<i64>,
    ) -> Result<(), String> {
        self.inner.complete_ready(record, lease_expires_at).await?;
        self.after(Step::Ready).await;
        Ok(())
    }
    async fn ensure_guest_machine(
        &self,
        record_id: &str,
        reference: &str,
    ) -> Result<ProvisionRecord, String> {
        let record = self
            .inner
            .ensure_guest_machine(record_id, reference)
            .await?;
        self.after(Step::MachineRegistered).await;
        Ok(record)
    }
    async fn find_by_machine_id(
        &self,
        machine_id: &str,
    ) -> Result<Option<ProvisionRecord>, String> {
        self.inner.find_by_machine_id(machine_id).await
    }
    async fn list(&self) -> Result<Vec<ProvisionRecord>, String> {
        ProvisionPort::list(self.inner.as_ref()).await
    }
    async fn reserve_clone_target(
        &self,
        record_id: &str,
        node: &str,
        vmid: u32,
    ) -> Result<CloneTargetReservation, String> {
        let reserved = self
            .inner
            .reserve_clone_target(record_id, node, vmid)
            .await?;
        self.after(Step::Reserved).await;
        Ok(reserved)
    }
}

/// The sweeper's lease store, with a crash point right after the tick's
/// expiry step committed (its first listing follows the expiry).
#[derive(Debug)]
struct SweeperLeases {
    inner: Arc<LeaseRepository>,
    faults: Arc<Faults>,
}

#[async_trait]
impl LeasePort for SweeperLeases {
    async fn create(&self, lease: &NewLease, owner: &str, now: i64) -> Result<Lease, String> {
        self.inner.create(lease, owner, now).await
    }
    async fn get(&self, id: &str) -> Result<Lease, String> {
        self.inner.get(id).await
    }
    async fn update(&self, lease: &Lease) -> Result<(), String> {
        self.inner.update(lease).await
    }
    async fn list(&self, project_id: Option<&str>) -> Result<Vec<Lease>, String> {
        if matches!(self.faults.take(Step::Expired), Some(Fault::CrashAfter)) {
            self.faults.crash::<()>().await;
        }
        self.inner.list(project_id).await
    }
    async fn expired(&self, now: i64) -> Result<Vec<Lease>, String> {
        self.inner.expired(now).await
    }
    async fn extend_ready(
        &self,
        id: &str,
        observed_expires_at: i64,
        now: i64,
        new_expires_at: i64,
    ) -> Result<bool, String> {
        self.inner
            .extend_ready(id, observed_expires_at, now, new_expires_at)
            .await
    }
    async fn attach_provision(
        &self,
        id: &str,
        provision_id: &str,
    ) -> Result<AttachProvisionOutcome, String> {
        self.inner.attach_provision(id, provision_id).await
    }
    async fn claim_for_release(
        &self,
        id: &str,
        observed: LeaseState,
        observed_expires_at: i64,
        now: i64,
    ) -> Result<bool, String> {
        self.inner
            .claim_for_release(id, observed, observed_expires_at, now)
            .await
    }
    async fn transition(
        &self,
        id: &str,
        observed: LeaseState,
        provision_id: Option<&str>,
        to: LeaseState,
    ) -> Result<bool, String> {
        self.inner.transition(id, observed, provision_id, to).await
    }
    async fn rearm_cleanup(
        &self,
        id: &str,
        observed_attempts: u32,
        attempts: u32,
    ) -> Result<bool, String> {
        self.inner
            .rearm_cleanup(id, observed_attempts, attempts)
            .await
    }
    async fn record_failed_cleanup(
        &self,
        observed_attempts: u32,
        failed: &Lease,
    ) -> Result<bool, String> {
        self.inner
            .record_failed_cleanup(observed_attempts, failed)
            .await
    }
}

/// The scripted SSH trust and bootstrap project. The project child is the
/// durable `ready.workflow` operation the production adapter creates, with
/// the provision-scoped key, and it succeeds with its verify step.
#[derive(Debug)]
struct Readiness {
    faults: Arc<Faults>,
}

#[async_trait]
impl LabReadinessPort for Readiness {
    async fn trust(
        &self,
        _record: &ProvisionRecord,
        _content: &LabTemplateContent,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        match self.faults.take(Step::Trust) {
            Some(Fault::CrashBefore | Fault::CrashAfter) => self.faults.crash().await,
            Some(_) => Err("the injected host key refusal".to_owned()),
            None => Ok(true),
        }
    }

    async fn ssh_probe(
        &self,
        _operations: &Operations,
        _parent_id: &str,
        _record: &ProvisionRecord,
        _command: &str,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        Ok(true)
    }

    async fn create_project(
        &self,
        operations: &Operations,
        _parent_id: &str,
        record: &ProvisionRecord,
        _project_id: &str,
        _remaining: std::time::Duration,
    ) -> Result<String, String> {
        let child = operations
            .create(
                &AllowAll,
                PRINCIPAL,
                &NewOperation {
                    kind: "ready.workflow".to_owned(),
                    idempotency_key: Some(format!("lab-ready:{}", record.id)),
                    deadline_at: record.readiness_deadline_at,
                    correlation_id: Some(record.id.clone()),
                    review_token: None,
                    payload_json: Some(
                        serde_json::json!({
                            "machineId": record.machine_id, "endpointId": record.endpoint_id,
                            "auth": {"type": "agent"}, "remote": "example.org/demo",
                            "root": "/tmp/fleet-projects/demo", "timeoutSeconds": 30
                        })
                        .to_string(),
                    ),
                },
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(child.id)
    }

    async fn project_verified(
        &self,
        operations: &Operations,
        child_id: &str,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        if operations
            .get_state(child_id)
            .await
            .map_err(|e| e.to_string())?
            == "pending"
        {
            operations
                .claim_only_execute(&Rest, child_id, "lab-ready")
                .await?;
        }
        let verified = operations
            .get_state(child_id)
            .await
            .map_err(|e| e.to_string())?
            == "succeeded";
        if matches!(
            self.faults.take(Step::ProjectSetUp),
            Some(Fault::CrashAfter)
        ) {
            self.faults.crash::<()>().await;
        }
        Ok(verified)
    }
}

/// The end of the executor chain: the project workflow succeeds with its
/// verify step; nothing else is expected here.
#[derive(Debug)]
struct Rest;

#[async_trait]
impl OperationExecutor for Rest {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        if operation.kind != "ready.workflow" {
            return Err(format!("unexpected operation kind {}", operation.kind));
        }
        operations
            .complete(
                &operation.id,
                "succeeded",
                Some(r#"{"ready":true,"completed":["verify"]}"#),
                None,
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// The parts of one controller run that its work needs.
#[derive(Debug)]
struct Parts {
    operations: Arc<Operations>,
    executor: Arc<dyn OperationExecutor>,
    sweeper: LabSweeper,
}

impl Parts {
    /// Claims and runs pending operations until none is left. Answers how
    /// many ran.
    async fn drain(&self) -> usize {
        for ran in 0..200 {
            let report = self
                .operations
                .tick(
                    self.executor.as_ref(),
                    "lab-suite-worker",
                    fleet_core::SystemClock::now_unix_millis(),
                    LEASE_MS,
                )
                .await
                .unwrap();
            if !report.claimed {
                return ran;
            }
        }
        panic!("the operation queue never drained");
    }
}

/// One controller run over the world.
pub struct Controller {
    store: Store,
    /// The run's connection pool, for assertions.
    pub pool: sqlx::SqlitePool,
    parts: Arc<Parts>,
    /// The Lab use cases.
    pub lab: Arc<Lab>,
    /// The lease rows.
    pub leases: Arc<LeaseRepository>,
    /// The provision rows.
    pub labs: Arc<LabRepository>,
    account_id: String,
    /// The latest time the Lab was settled at: a ready lease must not be
    /// past its TTL then.
    settled_at: std::sync::Mutex<Option<i64>>,
    version_id: String,
}

/// How a run of controller work ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Run<T> {
    /// It finished.
    Done(T),
    /// The controller died at a crash point.
    Crashed,
}

impl Controller {
    /// Starts a controller over the world's database and host.
    pub async fn start(world: &World) -> Self {
        let store = Store::open(&world.database)
            .await
            .expect("the previous controller released the database");
        let pool = store.pool().clone();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let leases = Arc::new(LeaseRepository::new(pool.clone()));
        let audit = Arc::new(AuditSink::new(pool.clone()));
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            audit.clone(),
        ));
        let accounts: Arc<dyn ProxmoxAccountPort> =
            Arc::new(ProxmoxAccountRepository::new(pool.clone()));
        let credentials: Arc<dyn ProxmoxCredentialStore> = Arc::new(OneSecret);
        let client = ProxmoxClient::new(world.pve.transport());
        let destroyer = Arc::new(
            ProxmoxDestructiveExecutor::new(accounts.clone(), credentials.clone(), client.clone())
                .with_image_artifacts(Arc::new(Artifacts)),
        );
        let cleanup = Arc::new(LabCleanupExecutor::new(
            leases.clone(),
            labs.clone(),
            Arc::new(MachineRepository::new(pool.clone())),
            audit.clone(),
            destroyer.clone(),
        ));
        let provision = Arc::new(
            ProvisionExecutor::new(
                accounts.clone(),
                credentials.clone(),
                Arc::new(Interruptible {
                    inner: labs.clone(),
                    faults: world.faults.clone(),
                }),
                leases.clone(),
                labs.clone(),
                Arc::new(Artifacts),
                client.clone(),
            )
            .with_readiness(
                Arc::new(Readiness {
                    faults: world.faults.clone(),
                }),
                audit.clone(),
            ),
        );
        let executor: Arc<dyn OperationExecutor> = Arc::new(
            LabDispatch::new(
                Arc::new(ProxmoxDispatch::new(
                    Arc::new(Rest),
                    Arc::new(ProxmoxLifecycleExecutor::new(
                        accounts.clone(),
                        credentials.clone(),
                        client.clone(),
                    )),
                    destroyer,
                )),
                provision,
            )
            .with_cleanup(cleanup, leases.clone(), labs.clone()),
        );
        let lab = Arc::new(Lab::new(
            labs.clone(),
            labs.clone(),
            leases.clone(),
            Arc::new(Promoted),
            Arc::new(ProjectRepository::new(pool.clone())),
            audit.clone(),
        ));
        let sweeper = LabSweeper::new(
            lab.clone(),
            Arc::new(SweeperLeases {
                inner: leases.clone(),
                faults: world.faults.clone(),
            }),
            labs.clone(),
            operations.clone(),
            audit,
        )
        .with_inventory(Arc::new(ProxmoxLabGuests::new(
            accounts,
            credentials,
            client,
        )));
        Self {
            store,
            pool,
            parts: Arc::new(Parts {
                operations,
                executor,
                sweeper,
            }),
            lab,
            leases,
            labs,
            account_id: world.account_id.clone(),
            settled_at: std::sync::Mutex::new(None),
            version_id: world.version_id.clone(),
        }
    }

    /// The controller dies: in-flight work is already gone (see [`run`]);
    /// the store and every connection close. Nothing in memory survives.
    ///
    /// [`run`]: Self::run
    pub async fn kill(self) {
        self.pool.close().await;
        drop(self.store);
    }

    /// The restarted controller's worker maintenance once the dead run's
    /// claim lease has run out: its interrupted operations fail honestly
    /// (`worker_lease_expired`), never retried.
    pub async fn recover(&self) -> usize {
        self.parts
            .operations
            .maintain(
                fleet_core::SystemClock::now_unix_millis() + LEASE_MS + 1,
                LEASE_MS,
            )
            .await
            .unwrap()
            .recovered
    }

    /// Runs `work` against this controller until it finishes or the
    /// controller reaches a crash point. A crash drops the work right
    /// there, as a dying process would.
    async fn run<T, F>(&self, world: &World, work: F) -> Run<T>
    where
        T: Send + 'static,
        F: std::future::Future<Output = T> + Send + 'static,
    {
        let mut task = tokio::spawn(work);
        tokio::select! {
            biased;
            () = world.faults.crashed() => {
                task.abort();
                let _ = task.await;
                Run::Crashed
            }
            done = tokio::time::timeout(std::time::Duration::from_secs(60), &mut task) => {
                Run::Done(done.expect("controller work finishes or crashes").unwrap())
            }
        }
    }

    /// Requests a lease and its provision the way the API does
    /// (`POST /lab/leases`, then `POST /lab/leases/{id}/provision`). Answers
    /// the lease.
    pub async fn request_lease(&self) -> String {
        let principal = ActingPrincipal {
            id: PRINCIPAL.to_owned(),
        };
        let now = fleet_core::SystemClock::now_unix_millis();
        let lease = self
            .lab
            .create_lease(
                &AllowAll,
                &principal,
                NewLease {
                    template_version_id: self.version_id.clone(),
                    purpose: "failure injection".to_owned(),
                    project_id: None,
                    cleanup: CleanupStrategy::Destroy,
                    ttl_seconds: TTL_SECONDS,
                },
                now,
            )
            .await
            .unwrap();
        let (record, _) = self
            .lab
            .start_lease_provision(&AllowAll, &principal, &lease.id, None, now)
            .await
            .unwrap();
        self.parts
            .operations
            .create_lab_provision(
                &AllowAll,
                PRINCIPAL,
                &lease.id,
                &NewOperation {
                    kind: "lab.provision".to_owned(),
                    idempotency_key: Some(format!("{PRINCIPAL}:lab-lease-provision:{}", lease.id)),
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(
                        serde_json::json!({
                            "recordId": record.id,
                            "leaseId": lease.id,
                            "accountId": self.account_id,
                        })
                        .to_string(),
                    ),
                    review_token: None,
                },
            )
            .await
            .unwrap();
        lease.id
    }

    /// Releases a lease the way the API does (`POST .../release`): the
    /// lease enters `releasing` and its cleanup is queued.
    pub async fn release(&self, lease_id: &str) {
        let principal = ActingPrincipal {
            id: PRINCIPAL.to_owned(),
        };
        let lease = self
            .lab
            .release_lease(
                &AllowAll,
                &principal,
                lease_id,
                false,
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await
            .unwrap();
        self.parts
            .operations
            .create_lab_cleanup(
                &AllowAll,
                PRINCIPAL,
                lease_id,
                &fleet_application::lab::cleanup_operation(&lease, None),
            )
            .await
            .unwrap();
    }

    /// Releases a lease with `keep` (`POST .../release?keep=true`): its
    /// cleanup leaves the guest in place.
    pub async fn release_keeping(&self, lease_id: &str) {
        let principal = ActingPrincipal {
            id: PRINCIPAL.to_owned(),
        };
        let lease = self
            .lab
            .release_lease(
                &AllowAll,
                &principal,
                lease_id,
                true,
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await
            .unwrap();
        self.parts
            .operations
            .create_lab_cleanup(
                &AllowAll,
                PRINCIPAL,
                lease_id,
                &fleet_application::lab::cleanup_operation(&lease, None),
            )
            .await
            .unwrap();
    }

    /// The provision read model's view of a lease's record, as
    /// `GET /lab/provisions` reports it: its saga state, what became of the
    /// guest, and the linked lease's state.
    pub async fn provision_view(&self, lease_id: &str) -> (String, String, Option<String>) {
        let principal = ActingPrincipal {
            id: PRINCIPAL.to_owned(),
        };
        let record = self.record(lease_id).await;
        let view = self
            .lab
            .list_provision_views(&AllowAll, &principal)
            .await
            .unwrap()
            .into_iter()
            .find(|view| view.record.id == record.id)
            .expect("the record is listed");
        (
            view.record.state.id().to_owned(),
            view.guest.id().to_owned(),
            view.lease_state.map(|state| state.id().to_owned()),
        )
    }

    /// Runs the queued operations to completion, or until a crash point.
    pub async fn drain(&self, world: &World) -> Run<usize> {
        let parts = self.parts.clone();
        self.run(world, async move { parts.drain().await }).await
    }

    /// One sweeper tick at `now`, or until a crash point.
    pub async fn sweep(&self, world: &World, now: i64) -> Run<TickReport> {
        let parts = self.parts.clone();
        self.run(world, async move { parts.sweeper.tick(now).await.unwrap() })
            .await
    }

    /// Lets the sweeper and the worker converge at `now`: ticks and drains
    /// until a round changes nothing. Panics on a crash: settling runs on a
    /// healthy controller.
    pub async fn settle(&self, world: &World, now: i64) -> Vec<TickReport> {
        {
            let mut settled = self.settled_at.lock().unwrap();
            *settled = Some(settled.map_or(now, |before| before.max(now)));
        }
        let mut reports = Vec::new();
        for _ in 0..20 {
            let Run::Done(report) = self.sweep(world, now).await else {
                panic!("the controller crashed while settling");
            };
            let Run::Done(ran) = self.drain(world).await else {
                panic!("the controller crashed while settling");
            };
            let idle = report.expired == 0
                && report.compensated == 0
                && report.cleanups_queued == 0
                && report.cleanups_abandoned == 0
                && ran == 0;
            reports.push(report);
            if idle {
                return reports;
            }
        }
        panic!("the Lab never settled: {reports:?}");
    }

    /// The lease row.
    pub async fn lease(&self, id: &str) -> Lease {
        self.leases.get(id).await.unwrap()
    }

    /// The lease's provision record.
    pub async fn record(&self, lease_id: &str) -> ProvisionRecord {
        let lease = self.lease(lease_id).await;
        ProvisionPort::get(self.labs.as_ref(), lease.provision_id.as_deref().unwrap())
            .await
            .unwrap()
    }

    /// The number of audit events naming `event`.
    pub async fn audit_events(&self, event: &str) -> usize {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE metadata_json LIKE ?1")
                .bind(format!("%\"{event}\"%"))
                .fetch_one(&self.pool)
                .await
                .unwrap();
        usize::try_from(count).unwrap()
    }

    /// Whether the Lab-owned machine of `record_id` still exists. Looked up
    /// by its Fleet name: deleting the machine clears the record's link.
    pub async fn lab_machine_exists(&self, record_id: &str) -> bool {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM machines WHERE name = ?1")
            .bind(format!("fm-lab-{record_id}"))
            .fetch_one(&self.pool)
            .await
            .unwrap();
        count > 0
    }

    /// The rows and the host, read together.
    async fn snapshot(
        &self,
        world: &World,
    ) -> (
        BTreeMap<u32, super::fake_pve::Guest>,
        Vec<Lease>,
        BTreeMap<String, ProvisionRecord>,
    ) {
        let guests = world.pve.lab_guests();
        let leases = self.leases.list(None).await.unwrap();
        let records = ProvisionPort::list(self.labs.as_ref())
            .await
            .unwrap()
            .into_iter()
            .map(|record| (record.id.clone(), record))
            .collect();
        (guests, leases, records)
    }

    /// Checks every lab.md invariant over the stored rows and the host, and
    /// answers each violation (empty when they all hold): the allowed
    /// outcomes ([`Self::outcome_violations`]) and ownership
    /// ([`Self::ownership_violations`]).
    pub async fn violations(&self, world: &World) -> Vec<String> {
        let mut violations = self.outcome_violations(world).await;
        violations.extend(self.ownership_violations(world).await);
        violations
    }

    /// Every lease is in one of the three allowed outcomes: a valid owned
    /// ready lease; a failed (or released) lease with no external
    /// allocation; or a `cleanup_failed` lease that visibly names the guest
    /// it owns.
    pub async fn outcome_violations(&self, world: &World) -> Vec<String> {
        let (guests, leases, records) = self.snapshot(world).await;
        let mut violations = Vec::new();
        let named = |record: &ProvisionRecord| {
            guests
                .iter()
                .find(|(_, guest)| guest.name == format!("fm-lab-{}", record.id))
                .map(|(vmid, guest)| (*vmid, guest.clone()))
        };
        for lease in &leases {
            let record = lease.provision_id.as_ref().and_then(|id| records.get(id));
            let guest = record.and_then(named);
            match lease.state {
                LeaseState::Ready => {
                    let Some(record) = record else {
                        violations.push(format!("ready lease {} has no record", lease.id));
                        continue;
                    };
                    let owned = guest.as_ref().is_some_and(|(vmid, guest)| {
                        Some(*vmid) == record.vmid
                            && guest.running
                            && record.node.as_deref() == Some(guest.node.as_str())
                    });
                    if record.state != GuestState::Ready
                        || !owned
                        || !self.lab_machine_exists(&record.id).await
                    {
                        violations.push(format!(
                            "ready lease {} does not own a running guest and machine: record {:?}, guest {guest:?}",
                            lease.id, record.state
                        ));
                    }
                    match (lease.expires_at, *self.settled_at.lock().unwrap()) {
                        (None, _) => {
                            violations.push(format!("ready lease {} has no TTL", lease.id));
                        }
                        (Some(expires), Some(settled)) if expires <= settled => {
                            violations.push(format!(
                                "ready lease {} expired at {expires} but was still ready when \
                                 the Lab settled at {settled}",
                                lease.id
                            ));
                        }
                        _ => {}
                    }
                }
                LeaseState::Released | LeaseState::Failed => {
                    if lease.cleanup == CleanupStrategy::Keep {
                        continue;
                    }
                    if let Some((vmid, _)) = guest {
                        violations.push(format!(
                            "{} lease {} still has its guest {vmid}",
                            lease.state.id(),
                            lease.id
                        ));
                    }
                    if let Some(record) = record
                        && self.lab_machine_exists(&record.id).await
                    {
                        violations.push(format!(
                            "{} lease {} still has its Lab machine",
                            lease.state.id(),
                            lease.id
                        ));
                    }
                }
                LeaseState::CleanupFailed => {
                    let visible = record.is_some_and(|record| {
                        record.lease_id.as_deref() == Some(lease.id.as_str())
                            && record.vmid.is_some()
                            && record.node.is_some()
                            && record.account_id.is_some()
                    });
                    if !visible {
                        violations.push(format!(
                            "cleanup_failed lease {} does not name the guest it owns",
                            lease.id
                        ));
                    }
                }
                other => violations.push(format!(
                    "lease {} is stuck in {}: no allowed outcome",
                    lease.id,
                    other.id()
                )),
            }
        }
        violations
    }

    /// No Fleet guest exists that Lab state does not own (the sweeper's own
    /// rule, `guest_owned`, over the stored rows), and no VMID is held by
    /// two live leases.
    pub async fn ownership_violations(&self, world: &World) -> Vec<String> {
        let (guests, leases, records) = self.snapshot(world).await;
        let mut violations = Vec::new();
        let by_id: BTreeMap<&str, &Lease> = leases
            .iter()
            .map(|lease| (lease.id.as_str(), lease))
            .collect();
        for (vmid, guest) in &guests {
            let record = guest
                .name
                .strip_prefix("fm-lab-")
                .and_then(|id| records.get(id));
            let lease = record
                .and_then(|record| record.lease_id.as_deref())
                .and_then(|id| by_id.get(id).copied());
            if !guest_owned(record, lease, &self.account_id, *vmid) {
                violations.push(format!(
                    "guest {vmid} ({}) is not owned by any Lab record",
                    guest.name
                ));
            }
        }
        let mut holders: BTreeMap<u32, Vec<&str>> = BTreeMap::new();
        for lease in &leases {
            if matches!(lease.state, LeaseState::Released | LeaseState::Failed) {
                continue;
            }
            if let Some(vmid) = lease
                .provision_id
                .as_ref()
                .and_then(|id| records.get(id))
                .and_then(|record| record.vmid)
            {
                holders.entry(vmid).or_default().push(&lease.id);
            }
        }
        for (vmid, holders) in holders {
            if holders.len() > 1 {
                violations.push(format!("VMID {vmid} is held by live leases {holders:?}"));
            }
        }
        violations
    }
}
