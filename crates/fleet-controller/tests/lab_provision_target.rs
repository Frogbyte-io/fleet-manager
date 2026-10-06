//! Issue #220: the Lab provision executor clones the pinned image's
//! template on the node that holds it, into a VMID reserved and recorded
//! before the clone, and never falls back to a hard-coded source or the
//! template's own VMID. The cleanup guard refuses templates and image
//! artifacts. Real SQLite repositories and a real worker; a scripted PVE
//! transport that records every request.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::authz::{AccessRequest, Authorizer, Decision};
use fleet_application::lab::{
    CloneTargetReservation, ImageArtifactPort, LabTemplate, LabTemplatePort, LabTemplateVersion,
    LeasePort, NewLabTemplate, NewLease, NewProvision, ProvisionPort, ProvisionRecord,
};
use fleet_application::operation::{NewOperation, Operations};
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccountPort, ProxmoxCredentialStore,
};
use fleet_core::{CleanupStrategy, GuestState, LabTemplateContent, ReadinessProbe};
use fleet_provider_proxmox::{
    ProxmoxClient, PveHttpRequest, PveHttpResponse, PveTransport, PveTransportError,
};
use fleet_storage_sqlite::{
    AuditSink, LabRepository, LeaseRepository, OperationRepository, ProxmoxAccountRepository, Store,
};

const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";
/// The account's API host: deliberately not a node name.
const API_HOST: &str = "pve-api.example.test";
/// The node that holds the image template.
const TEMPLATE_NODE: &str = "pve-b";
/// The image template's VMID (the recorded build artifact).
const TEMPLATE_VMID: u32 = 120;
/// Another recorded image artifact that is no longer a template.
const OTHER_ARTIFACT_VMID: u32 = 130;
/// A promoted image's recorded template that no longer exists.
const GONE_ARTIFACT_VMID: u32 = 140;
/// What `/cluster/nextid` answers.
const NEXT_VMID: u32 = 9000;
/// The UPID PVE answers for the clone: `qmclone` carries the *source*.
const CLONE_UPID: &str = "UPID:pve-b:0015523F:0C6DF532:6AAFE1EC:qmclone:120:fleet@pve!lab:";
const START_UPID: &str = "UPID:pve-b:00155300:0C6DF600:6AAFE1F0:qmstart:9000:fleet@pve!lab:";

/// One request the transport saw.
#[derive(Clone, Debug)]
struct Seen {
    path: String,
    body: Option<serde_json::Value>,
    /// The record's stored (node, VMID) when a clone or start request
    /// arrived.
    stored_target: Option<(Option<String>, Option<u32>)>,
}

#[derive(Debug)]
struct Pve {
    /// Extra guests in `/cluster/resources`, beside the node and template.
    guests: Vec<serde_json::Value>,
    clone_upid: String,
    /// What `/cluster/nextid` answers.
    next_vmid: u32,
    seen: Mutex<Vec<Seen>>,
    /// The repository and record whose target the clone request observes.
    observe: Mutex<Option<(Arc<LabRepository>, String)>>,
    ready_ip: bool,
}

impl Pve {
    fn new(guests: Vec<serde_json::Value>) -> Arc<Self> {
        Self::scripted(guests, CLONE_UPID, NEXT_VMID)
    }

    fn with_clone_upid(guests: Vec<serde_json::Value>, upid: &str) -> Arc<Self> {
        Self::scripted(guests, upid, NEXT_VMID)
    }

    fn scripted(guests: Vec<serde_json::Value>, upid: &str, next_vmid: u32) -> Arc<Self> {
        Arc::new(Self {
            guests,
            clone_upid: upid.to_owned(),
            next_vmid,
            seen: Mutex::new(Vec::new()),
            observe: Mutex::new(None),
            ready_ip: false,
        })
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn paths(&self) -> Vec<String> {
        self.seen().into_iter().map(|seen| seen.path).collect()
    }

    fn clones(&self) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|seen| seen.path.ends_with("/clone"))
            .collect()
    }

    fn resources(&self) -> String {
        let mut entries = vec![
            serde_json::json!({"id": "node/pve-a", "type": "node", "node": "pve-a"}),
            serde_json::json!({"id": "node/pve-b", "type": "node", "node": "pve-b"}),
            serde_json::json!({
                "id": format!("qemu/{TEMPLATE_VMID}"), "type": "qemu", "node": TEMPLATE_NODE,
                "vmid": TEMPLATE_VMID, "name": "ubuntu-base", "template": 1
            }),
            serde_json::json!({
                "id": format!("qemu/{OTHER_ARTIFACT_VMID}"), "type": "qemu", "node": "pve-a",
                "vmid": OTHER_ARTIFACT_VMID, "name": "converted-back", "template": 0
            }),
        ];
        entries.extend(self.guests.iter().cloned());
        serde_json::json!({ "data": entries }).to_string()
    }
}

#[derive(Debug)]
struct Transport(Arc<Pve>);

#[async_trait]
impl PveTransport for Transport {
    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        self.respond(request, Some(serde_json::from_slice(&body).unwrap()))
            .await
    }

    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        self.respond(request, None).await
    }
}

impl Transport {
    async fn respond(
        &self,
        request: PveHttpRequest,
        body: Option<serde_json::Value>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        assert_eq!(request.host, API_HOST, "every call goes to the API host");
        let path = request.path.clone();
        let stored_target = if path.ends_with("/clone") || path.ends_with("/status/start") {
            let observe = self.0.observe.lock().unwrap().clone();
            match observe {
                Some((labs, record_id)) => {
                    let record = ProvisionPort::get(labs.as_ref(), &record_id).await.unwrap();
                    Some((record.node, record.vmid))
                }
                None => None,
            }
        } else {
            None
        };
        self.0.seen.lock().unwrap().push(Seen {
            path: path.clone(),
            body,
            stored_target,
        });
        let answer = if path == "/api2/json/version" {
            r#"{"data":{"version":"9.0.3"}}"#.to_owned()
        } else if path == "/api2/json/cluster/resources" {
            self.0.resources()
        } else if path == "/api2/json/cluster/nextid" {
            // PVE's JSON formatter answers the integer as a string.
            format!(r#"{{"data":"{}"}}"#, self.0.next_vmid)
        } else if path.ends_with("/clone") {
            format!(r#"{{"data":"{}"}}"#, self.0.clone_upid)
        } else if path.ends_with("/status/start") {
            format!(r#"{{"data":"{START_UPID}"}}"#)
        } else if self.0.ready_ip && path.ends_with("/agent/info") {
            r#"{"data":{"result":{"version":"9"}}}"#.to_owned()
        } else if self.0.ready_ip && path.ends_with("/agent/network-get-interfaces") {
            r#"{"data":{"result":[{"name":"ens18","ip-addresses":[{"ip-address":"192.0.2.42","ip-address-type":"ipv4","prefix":24}]}]}}"#.to_owned()
        } else {
            // The agent probe: refused, so the zero readiness deadline
            // ends the saga as never_ready right after the start.
            return Err(PveTransportError::Connect {
                detail: format!("unexpected path {path}"),
            });
        };
        Ok(PveHttpResponse {
            status: 200,
            body: answer.into_bytes(),
        })
    }
}

#[derive(Debug)]
struct OneSecret;

#[async_trait]
impl ProxmoxCredentialStore for OneSecret {
    async fn load(&self, _account_id: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(Some("the-token-secret-material".to_owned()))
    }
    async fn store(&self, _account_id: &str, _secret: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("the executor never stores credentials")
    }
    async fn clear(&self, _account_id: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("the executor never clears credentials")
    }
}

/// The recorded build artifacts.
#[derive(Debug)]
struct Artifacts {
    pinned: Option<u32>,
}

#[async_trait]
impl ImageArtifactPort for Artifacts {
    async fn template_vmid(&self, image_version_id: &str) -> Result<Option<u32>, String> {
        assert_eq!(image_version_id, "image-version-1");
        Ok(self.pinned)
    }
    async fn promoted_template_vmids(&self) -> Result<Vec<u32>, String> {
        Ok(vec![TEMPLATE_VMID, OTHER_ARTIFACT_VMID, GONE_ARTIFACT_VMID])
    }
}

#[derive(Debug)]
struct AllowAll;

impl Authorizer for AllowAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    labs: Arc<LabRepository>,
    leases: Arc<LeaseRepository>,
    accounts: Arc<ProxmoxAccountRepository>,
    operations: Arc<Operations>,
    account_id: String,
    version_id: String,
    pool: sqlx::SqlitePool,
}

impl Harness {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        let now = fleet_core::SystemClock::now_unix_millis();
        let accounts = Arc::new(ProxmoxAccountRepository::new(pool.clone()));
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
            .set_fingerprint(&account.id, Some(FP.to_owned()))
            .await
            .unwrap();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let leases = Arc::new(LeaseRepository::new(pool.clone()));
        let content = LabTemplateContent {
            name: "lab-base".to_owned(),
            description: "the lab base".to_owned(),
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
            leases,
            accounts,
            operations,
            account_id: account.id,
            version_id: version.id,
            pool,
        }
    }

    /// A requested lease with its linked, freshly created record.
    async fn record(&self) -> (String, ProvisionRecord) {
        let now = fleet_core::SystemClock::now_unix_millis();
        let lease = self
            .leases
            .create(
                &NewLease {
                    template_version_id: self.version_id.clone(),
                    purpose: "clone target".to_owned(),
                    project_id: None,
                    cleanup: CleanupStrategy::Destroy,
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
        (lease.id, record)
    }

    fn executor(
        &self,
        pve: &Arc<Pve>,
        pinned: Option<u32>,
    ) -> fleet_controller::proxmox_exec::ProvisionExecutor {
        fleet_controller::proxmox_exec::ProvisionExecutor::new(
            self.accounts.clone(),
            Arc::new(OneSecret),
            self.labs.clone(),
            self.leases.clone(),
            self.labs.clone(),
            Arc::new(Artifacts { pinned }),
            ProxmoxClient::new(Arc::new(Transport(pve.clone()))),
        )
    }

    /// Runs one `lab.provision` operation to its terminal state; returns
    /// the state, the error's reason and detail, and the stored record.
    async fn run(
        &self,
        pve: &Arc<Pve>,
        pinned: Option<u32>,
        lease_id: &str,
        record_id: &str,
    ) -> (String, Option<(String, String)>, ProvisionRecord) {
        self.run_executor(pve, self.executor(pve, pinned), lease_id, record_id)
            .await
    }

    async fn run_executor(
        &self,
        pve: &Arc<Pve>,
        executor: fleet_controller::proxmox_exec::ProvisionExecutor,
        lease_id: &str,
        record_id: &str,
    ) -> (String, Option<(String, String)>, ProvisionRecord) {
        *pve.observe.lock().unwrap() = Some((self.labs.clone(), record_id.to_owned()));
        let operation = self
            .operations
            .create_lab_provision(
                &AllowAll,
                "tester",
                lease_id,
                &NewOperation {
                    kind: "lab.provision".to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(
                        serde_json::json!({
                            "recordId": record_id,
                            "accountId": self.account_id,
                            "leaseId": lease_id
                        })
                        .to_string(),
                    ),
                    review_token: None,
                },
            )
            .await
            .unwrap();
        let worker = fleet_controller::worker::WorkerHost::new(
            self.operations.clone(),
            Arc::new(fleet_controller::proxmox_exec::LabDispatch::new(
                Arc::new(fleet_application::worker::NoopExecutor),
                Arc::new(executor),
            )),
            2,
        );
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let running = tokio::spawn(async move {
            worker
                .run(async {
                    let _ = stopped.await;
                })
                .await;
        });
        let mut state = String::new();
        for _ in 0..200 {
            state = self.operations.get_state(&operation.id).await.unwrap();
            if matches!(state.as_str(), "succeeded" | "failed" | "cancelled") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let _ = stop.send(());
        tokio::time::timeout(std::time::Duration::from_secs(10), running)
            .await
            .expect("the worker stops within its bound")
            .expect("the worker task does not panic");
        assert!(
            matches!(state.as_str(), "succeeded" | "failed" | "cancelled"),
            "the operation never reached a terminal state: {state}"
        );
        let finished = self
            .operations
            .get(&AllowAll, "tester", &operation.id)
            .await
            .unwrap();
        let error = finished.error_json.as_deref().map(|error| {
            let error: serde_json::Value = serde_json::from_str(error).unwrap();
            (
                error["reason"].as_str().unwrap_or_default().to_owned(),
                error["detail"].as_str().unwrap_or_default().to_owned(),
            )
        });
        let record = ProvisionPort::get(self.labs.as_ref(), record_id)
            .await
            .unwrap();
        (state, error, record)
    }
}

fn guest(vmid: u32, name: &str) -> serde_json::Value {
    serde_json::json!({
        "id": format!("qemu/{vmid}"), "type": "qemu", "node": TEMPLATE_NODE,
        "vmid": vmid, "name": name, "template": 0
    })
}

#[tokio::test]
async fn the_clone_targets_the_template_node_and_a_reserved_vmid() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());

    let (state, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    // The guest never answers the agent probe: a recorded never_ready.
    assert_eq!(state, "failed");
    assert_eq!(error.unwrap().0, "never_ready");
    let clones = pve.clones();
    assert_eq!(clones.len(), 1, "{:?}", pve.paths());
    let clone = &clones[0];
    // The exact node, source, newid, and name sent to PVE.
    assert_eq!(
        clone.path,
        format!("/api2/json/nodes/{TEMPLATE_NODE}/qemu/{TEMPLATE_VMID}/clone")
    );
    assert_eq!(
        clone.body,
        Some(serde_json::json!({
            "newid": NEXT_VMID,
            "name": format!("fm-lab-{}", record.id),
            "full": true,
        }))
    );
    // The target was reserved and persisted before the clone call.
    assert_eq!(
        clone.stored_target,
        Some((Some(TEMPLATE_NODE.to_owned()), Some(NEXT_VMID)))
    );
    let paths = pve.paths();
    let nextid = paths
        .iter()
        .position(|path| path == "/api2/json/cluster/nextid")
        .expect("the VMID comes from /cluster/nextid");
    let cloned = paths
        .iter()
        .position(|path| path.ends_with("/clone"))
        .unwrap();
    assert!(nextid < cloned, "{paths:?}");
    // The start goes to the reserved guest on the template's node.
    assert!(
        paths.contains(&format!(
            "/api2/json/nodes/{TEMPLATE_NODE}/qemu/{NEXT_VMID}/status/start"
        )),
        "{paths:?}"
    );
    assert!(
        paths.iter().all(|path| !path.contains(API_HOST)),
        "the account host is never a node: {paths:?}"
    );
    // The record keeps the reserved target, never the template's VMID.
    assert_eq!(stored.state, GuestState::NeverReady);
    assert_eq!(stored.node.as_deref(), Some(TEMPLATE_NODE));
    assert_eq!(stored.vmid, Some(NEXT_VMID));
    assert_eq!(stored.clone_upid.as_deref(), Some(CLONE_UPID));
}

#[tokio::test]
async fn a_rerun_resumes_with_the_reserved_vmid() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    // A previous run reserved 9005 and stopped before its clone.
    let reserved = harness
        .labs
        .reserve_clone_target(&record.id, TEMPLATE_NODE, 9005)
        .await
        .unwrap();
    assert!(matches!(reserved, CloneTargetReservation::Reserved(_)));
    let pve = Pve::new(Vec::new());

    let (_, _, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    let paths = pve.paths();
    assert!(
        !paths.contains(&"/api2/json/cluster/nextid".to_owned()),
        "a reservation is reused, not replaced: {paths:?}"
    );
    let clones = pve.clones();
    assert_eq!(clones.len(), 1, "{paths:?}");
    assert_eq!(clones[0].body.as_ref().unwrap()["newid"], 9005);
    assert_eq!(stored.vmid, Some(9005));
    assert_eq!(stored.clone_upid.as_deref(), Some(CLONE_UPID));
}

#[tokio::test]
async fn a_rerun_after_the_clone_started_does_not_clone_again() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());
    harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    // Simulate an interruption after the clone was recorded: the record is
    // back in `provisioning` with its target and clone UPID stored.
    let mut resumable = ProvisionPort::get(harness.labs.as_ref(), &record.id)
        .await
        .unwrap();
    // The simulated interruption precedes terminal readiness failure on
    // both rows; an actual failed lease is intentionally not resumable.
    let mut resumable_lease = harness.leases.get(&lease_id).await.unwrap();
    resumable_lease.state = fleet_core::LeaseState::Provisioning;
    harness.leases.update(&resumable_lease).await.unwrap();
    resumable.failed_step = None;
    resumable.state = GuestState::Provisioning;
    ProvisionPort::update(harness.labs.as_ref(), &resumable)
        .await
        .unwrap();
    let second = Pve::new(vec![guest(NEXT_VMID, &format!("fm-lab-{}", record.id))]);

    let (_, _, stored) = harness
        .run(&second, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert!(second.clones().is_empty(), "{:?}", second.paths());
    assert!(
        second.paths().contains(&format!(
            "/api2/json/nodes/{TEMPLATE_NODE}/qemu/{NEXT_VMID}/status/start"
        )),
        "{:?}",
        second.paths()
    );
    assert_eq!(stored.vmid, Some(NEXT_VMID));
}

#[tokio::test]
async fn a_reserved_target_that_already_holds_our_clone_is_adopted() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    harness
        .labs
        .reserve_clone_target(&record.id, TEMPLATE_NODE, 9005)
        .await
        .unwrap();
    // The clone landed but the UPID was never recorded.
    let pve = Pve::new(vec![guest(9005, &format!("fm-lab-{}", record.id))]);

    let (_, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert!(pve.clones().is_empty(), "{:?}", pve.paths());
    assert_eq!(error.unwrap().0, "never_ready");
    assert!(pve.paths().contains(&format!(
        "/api2/json/nodes/{TEMPLATE_NODE}/qemu/9005/status/start"
    )));
    assert_eq!(stored.vmid, Some(9005));
}

#[tokio::test]
async fn a_foreign_guest_at_the_reserved_target_is_a_conflict() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    harness
        .labs
        .reserve_clone_target(&record.id, TEMPLATE_NODE, 9005)
        .await
        .unwrap();
    let pve = Pve::new(vec![guest(9005, "someone-elses-vm")]);

    let (state, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "conflict");
    assert!(detail.contains("9005"), "{detail}");
    assert!(pve.clones().is_empty());
    assert!(
        !pve.paths()
            .iter()
            .any(|path| path.ends_with("/status/start"))
    );
    // The reservation is kept, never silently swapped.
    assert_eq!(stored.vmid, Some(9005));
    assert_eq!(stored.clone_upid, None);
}

#[tokio::test]
async fn a_vmid_held_by_another_in_flight_record_is_a_conflict() {
    let harness = Harness::new().await;
    let (_, other) = harness.record().await;
    harness
        .labs
        .reserve_clone_target(&other.id, TEMPLATE_NODE, NEXT_VMID)
        .await
        .unwrap();
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());

    let (state, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "conflict");
    assert!(detail.contains(&other.id), "{detail}");
    assert!(pve.clones().is_empty());
    assert_eq!(stored.vmid, None);
}

#[tokio::test]
async fn a_missing_artifact_is_an_honest_failure() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());

    let (state, error, stored) = harness.run(&pve, None, &lease_id, &record.id).await;

    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "artifact_missing");
    assert!(detail.contains("image-version-1"), "{detail}");
    // Nothing was read or cloned: no fallback source exists.
    assert!(pve.paths().is_empty(), "{:?}", pve.paths());
    assert_eq!((stored.node, stored.vmid), (None, None));
}

#[tokio::test]
async fn an_artifact_that_is_not_a_template_is_refused() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());

    let (state, error, _) = harness
        .run(&pve, Some(OTHER_ARTIFACT_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(state, "failed");
    assert_eq!(error.unwrap().0, "template_missing");
    assert!(pve.clones().is_empty());

    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());
    let (_, error, _) = harness.run(&pve, Some(777), &lease_id, &record.id).await;
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "template_missing");
    assert!(detail.contains("VM.Audit"), "{detail}");
    assert!(pve.clones().is_empty());
}

#[tokio::test]
async fn a_clone_task_that_does_not_match_the_request_is_an_error() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    // A task for the target instead of the source: not what PVE forks for
    // the requested clone.
    let pve = Pve::with_clone_upid(
        Vec::new(),
        "UPID:pve-b:0015523F:0C6DF532:6AAFE1EC:qmclone:9000:fleet@pve!lab:",
    );

    let (state, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert_eq!(state, "failed");
    assert_eq!(error.unwrap().0, "task_mismatch");
    assert!(
        !pve.paths()
            .iter()
            .any(|path| path.ends_with("/status/start"))
    );
    // The recorded VMID is the reserved target, never parsed from the task.
    assert_eq!(stored.vmid, Some(NEXT_VMID));
    assert_eq!(stored.clone_upid, None);
}

/// A record whose clone was recorded, ready to be resumed.
async fn cloned_record(harness: &Harness) -> (String, ProvisionRecord) {
    let (lease_id, record) = harness.record().await;
    let mut cloned = record.clone();
    cloned.node = Some(TEMPLATE_NODE.to_owned());
    cloned.vmid = Some(NEXT_VMID);
    cloned.clone_upid = Some(CLONE_UPID.to_owned());
    ProvisionPort::update(harness.labs.as_ref(), &cloned)
        .await
        .unwrap();
    (lease_id, cloned)
}

#[tokio::test]
async fn a_resumed_guest_is_revalidated_before_it_is_started() {
    let harness = Harness::new().await;
    let starts = |pve: &Pve| {
        pve.paths()
            .iter()
            .filter(|path| path.ends_with("/status/start"))
            .count()
    };

    // The recorded guest is gone.
    let (lease_id, record) = cloned_record(&harness).await;
    let pve = Pve::new(Vec::new());
    let (state, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(state, "failed");
    assert_eq!(error.unwrap().0, "target_missing");
    assert_eq!(starts(&pve), 0);

    // The VMID was reused by someone else's guest.
    let (lease_id, record) = cloned_record(&harness).await;
    let pve = Pve::new(vec![guest(NEXT_VMID, "someone-elses-vm")]);
    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "conflict");
    assert!(detail.contains("someone-elses-vm"), "{detail}");
    assert_eq!(starts(&pve), 0);

    // PVE names a clone only when it finishes: unverifiable, not started.
    let (lease_id, record) = cloned_record(&harness).await;
    let pve = Pve::new(vec![serde_json::json!({
        "id": format!("qemu/{NEXT_VMID}"), "type": "qemu", "node": TEMPLATE_NODE,
        "vmid": NEXT_VMID, "template": 0
    })]);
    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "target_unverified");
    assert_eq!(starts(&pve), 0);

    // Live PVE reports an unnamed guest as `VM <vmid>`: the same case, not
    // a conflict.
    let (lease_id, record) = cloned_record(&harness).await;
    let pve = Pve::new(vec![guest(NEXT_VMID, &format!("VM {NEXT_VMID}"))]);
    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "target_unverified");
    assert_eq!(starts(&pve), 0);
}

#[tokio::test]
async fn a_resumed_guest_that_moved_is_recorded_on_its_live_node() {
    let harness = Harness::new().await;
    let (lease_id, record) = cloned_record(&harness).await;
    let mut moved = guest(NEXT_VMID, &format!("fm-lab-{}", record.id));
    moved["node"] = serde_json::json!("pve-c");
    let pve = Pve::new(vec![moved]);

    let (_, _, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert!(
        pve.paths().contains(&format!(
            "/api2/json/nodes/pve-c/qemu/{NEXT_VMID}/status/start"
        )),
        "{:?}",
        pve.paths()
    );
    // Recorded before the start, so a run that stops before readiness
    // still leaves cleanup the live node.
    let start = pve
        .seen()
        .into_iter()
        .find(|seen| seen.path.ends_with("/status/start"))
        .unwrap();
    assert_eq!(
        start.stored_target,
        Some((Some("pve-c".to_owned()), Some(NEXT_VMID)))
    );
    assert_eq!(stored.node.as_deref(), Some("pve-c"));
}

#[tokio::test]
async fn a_promoted_artifact_vmid_is_never_reserved() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    // A promoted artifact is gone from the cluster, so nextid hands its
    // VMID out again.
    let pve = Pve::scripted(Vec::new(), CLONE_UPID, GONE_ARTIFACT_VMID);

    let (state, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "conflict");
    assert!(detail.contains(&GONE_ARTIFACT_VMID.to_string()), "{detail}");
    assert!(pve.clones().is_empty());
    assert_eq!(stored.vmid, None);
}

#[tokio::test]
async fn a_record_that_names_the_template_is_never_started() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    // What the pre-#220 source fallback recorded.
    let mut legacy = record.clone();
    legacy.node = Some(TEMPLATE_NODE.to_owned());
    legacy.vmid = Some(TEMPLATE_VMID);
    legacy.clone_upid = Some(CLONE_UPID.to_owned());
    ProvisionPort::update(harness.labs.as_ref(), &legacy)
        .await
        .unwrap();
    let pve = Pve::new(Vec::new());

    let (state, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert_eq!(state, "failed");
    assert_eq!(error.unwrap().0, "protected_target");
    assert!(
        !pve.paths()
            .iter()
            .any(|path| path.ends_with("/status/start") || path.ends_with("/clone")),
        "{:?}",
        pve.paths()
    );
}

#[tokio::test]
async fn the_cleanup_guard_refuses_templates_and_image_artifacts() {
    let harness = Harness::new().await;
    let pve = Pve::new(vec![guest(NEXT_VMID, "fm-lab-a-lease")]);
    let executor = harness.executor(&pve, Some(TEMPLATE_VMID));

    let refusal = executor
        .guard_destroy_target(&harness.account_id, TEMPLATE_VMID)
        .await
        .unwrap_err();
    assert!(refusal.contains("is a template"), "{refusal}");
    let refusal = executor
        .guard_destroy_target(&harness.account_id, OTHER_ARTIFACT_VMID)
        .await
        .unwrap_err();
    assert!(refusal.contains("build artifact"), "{refusal}");
    executor
        .guard_destroy_target(&harness.account_id, NEXT_VMID)
        .await
        .expect("a Lab clone may be destroyed");
}

#[derive(Debug)]
struct ReadyPorts {
    labs: Arc<LabRepository>,
    fail: Option<&'static str>,
    calls: Mutex<Vec<&'static str>>,
}

#[async_trait]
impl fleet_application::lab::LabReadinessPort for ReadyPorts {
    async fn trust(
        &self,
        record: &ProvisionRecord,
        _content: &LabTemplateContent,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        self.calls.lock().unwrap().push("trust");
        let stored = ProvisionPort::get(self.labs.as_ref(), &record.id)
            .await
            .unwrap();
        assert_eq!(stored.state, GuestState::Bootstrapping);
        assert!(stored.machine_id.is_some());
        if self.fail == Some("trust") {
            Err("unsafe provider diagnostic".to_owned())
        } else {
            Ok(true)
        }
    }
    async fn ssh_probe(
        &self,
        _operations: &Operations,
        _parent_id: &str,
        _record: &ProvisionRecord,
        command: &str,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        self.calls.lock().unwrap().push("ssh");
        assert_eq!(command, "test -f /tmp/ready");
        if self.fail == Some("ssh") {
            Err("unsafe SSH diagnostic".to_owned())
        } else {
            Ok(true)
        }
    }
    async fn create_project(
        &self,
        operations: &Operations,
        _parent_id: &str,
        record: &ProvisionRecord,
        project_id: &str,
        _remaining: std::time::Duration,
    ) -> Result<String, String> {
        self.calls.lock().unwrap().push("create_project");
        assert_eq!(project_id, "project-1");
        if self.fail == Some("project") {
            return Err("unsafe project diagnostic".to_owned());
        }
        let child = operations.create(&AllowAll, "tester", &NewOperation {
            kind: "ready.workflow".to_owned(), idempotency_key: Some(format!("lab-ready:{}", record.id)),
            deadline_at: record.readiness_deadline_at, correlation_id: Some(record.id.clone()), review_token: None,
            payload_json: Some(serde_json::json!({"machineId": record.machine_id, "endpointId": record.endpoint_id, "auth":{"type":"agent"}, "remote":"example.org/demo", "root":"/tmp/demo", "timeoutSeconds":30}).to_string()),
        }).await.map_err(|error| error.to_string())?;
        Ok(child.id)
    }
    async fn project_verified(
        &self,
        operations: &Operations,
        child_id: &str,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        self.calls.lock().unwrap().push("verify");
        let provisions = ProvisionPort::list(self.labs.as_ref()).await.unwrap();
        assert!(
            provisions
                .iter()
                .any(|record| record.ready_project_operation_id.as_deref() == Some(child_id)),
            "child identity must be committed before execution"
        );
        if self.fail == Some("verify") {
            return Err("unsafe verify diagnostic".to_owned());
        }
        if operations.get_state(child_id).await.unwrap() == "pending" {
            operations
                .claim_only_execute(&ProjectVerify, child_id, "test-project")
                .await?;
        }
        Ok(operations.get_state(child_id).await.unwrap() == "succeeded")
    }
}

#[derive(Debug)]
struct ProjectVerify;
#[async_trait]
impl fleet_application::worker::OperationExecutor for ProjectVerify {
    async fn execute(
        &self,
        operations: &Operations,
        operation: &fleet_application::operation::Operation,
    ) -> Result<(), String> {
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

async fn ready_harness(
    probe: ReadinessProbe,
    project: bool,
    fail: Option<&'static str>,
) -> (Harness, String, ProvisionRecord, Arc<Pve>, Arc<ReadyPorts>) {
    let harness = Harness::new().await;
    let mut version = harness.labs.get_version(&harness.version_id).await.unwrap();
    version.content.readiness_deadline_seconds = 30;
    version.content.readiness_probe = probe;
    version.content.readiness_command = Some("test -f /tmp/ready".to_owned());
    version.content.bootstrap_project_id = project.then(|| "project-1".to_owned());
    sqlx::query("UPDATE lab_template_versions SET content = ?2 WHERE id = ?1")
        .bind(&version.id)
        .bind(serde_json::to_string(&version.content).unwrap())
        .execute(&harness.pool)
        .await
        .unwrap();
    let (lease_id, mut record) = harness.record().await;
    record.vmid = Some(NEXT_VMID);
    record.node = Some(TEMPLATE_NODE.to_owned());
    record.clone_upid = Some(CLONE_UPID.to_owned());
    ProvisionPort::update(harness.labs.as_ref(), &record)
        .await
        .unwrap();
    let mut pve = Pve::new(vec![guest(NEXT_VMID, &format!("fm-lab-{}", record.id))]);
    Arc::get_mut(&mut pve).unwrap().ready_ip = true;
    let ports = Arc::new(ReadyPorts {
        labs: harness.labs.clone(),
        fail,
        calls: Mutex::new(Vec::new()),
    });
    (harness, lease_id, record, pve, ports)
}

#[tokio::test]
async fn every_probe_registers_a_lab_machine_and_starts_ttl_only_after_bootstrap() {
    for (probe, project, expected) in [
        (ReadinessProbe::GuestAgent, false, vec!["trust"]),
        (ReadinessProbe::SshExec, false, vec!["trust", "ssh"]),
        (
            ReadinessProbe::ProjectReady,
            true,
            vec!["trust", "create_project", "verify"],
        ),
        (
            ReadinessProbe::GuestAgent,
            true,
            vec!["trust", "create_project", "verify"],
        ),
    ] {
        let (harness, lease_id, record, pve, ports) = ready_harness(probe, project, None).await;
        let executor = harness.executor(&pve, Some(TEMPLATE_VMID)).with_readiness(
            ports.clone(),
            Arc::new(AuditSink::new(harness.pool.clone())),
        );
        let (state, error, stored) = harness
            .run_executor(&pve, executor, &lease_id, &record.id)
            .await;
        assert_eq!(state, "succeeded", "{error:?}");
        assert_eq!(stored.state, GuestState::Ready);
        assert_eq!(stored.guest_ipv4.as_deref(), Some("192.0.2.42"));
        assert!(stored.machine_id.is_some());
        assert!(stored.endpoint_id.is_some());
        assert_eq!(*ports.calls.lock().unwrap(), expected);
        let lease = harness.leases.get(&lease_id).await.unwrap();
        assert_eq!(lease.state, fleet_core::LeaseState::Ready);
        assert_eq!(lease.ready_at, stored.ready_at);
        assert_eq!(
            lease.expires_at,
            stored.ready_at.map(|ready| ready + 3_600_000)
        );
        let executor = harness.executor(&pve, Some(TEMPLATE_VMID)).with_readiness(
            ports.clone(),
            Arc::new(AuditSink::new(harness.pool.clone())),
        );
        let (state, _, resumed) = harness
            .run_executor(&pve, executor, &lease_id, &record.id)
            .await;
        assert_eq!(state, "succeeded");
        assert_eq!(resumed.machine_id, stored.machine_id);
        assert_eq!(
            resumed.ready_project_operation_id,
            stored.ready_project_operation_id
        );
        assert_eq!(
            harness.leases.get(&lease_id).await.unwrap().expires_at,
            lease.expires_at
        );
        assert_eq!(
            *ports.calls.lock().unwrap(),
            expected,
            "a ready resume does no remote work"
        );
        assert!(pve.clones().is_empty());
    }
}

#[tokio::test]
async fn each_readiness_failure_names_the_step_and_retains_allocations() {
    for (fail, step) in [
        ("trust", "ssh_trust"),
        ("ssh", "ssh_exec"),
        ("project", "project_setup"),
        ("verify", "project_ready"),
    ] {
        let (harness, lease_id, record, pve, ports) =
            ready_harness(ReadinessProbe::SshExec, true, Some(fail)).await;
        let executor = harness
            .executor(&pve, Some(TEMPLATE_VMID))
            .with_readiness(ports, Arc::new(AuditSink::new(harness.pool.clone())));
        let (state, error, stored) = harness
            .run_executor(&pve, executor, &lease_id, &record.id)
            .await;
        assert_eq!(state, "failed");
        assert_eq!(stored.state, GuestState::NeverReady);
        assert_eq!(stored.failed_step.as_deref(), Some(step));
        assert_eq!(stored.vmid, Some(NEXT_VMID));
        assert_eq!(stored.clone_upid.as_deref(), Some(CLONE_UPID));
        assert!(stored.machine_id.is_some());
        assert!(stored.endpoint_id.is_some());
        assert!(stored.ready_at.is_none());
        assert_eq!(
            harness.leases.get(&lease_id).await.unwrap().state,
            fleet_core::LeaseState::Failed
        );
        assert!(!error.unwrap().1.contains("unsafe"));
        assert_eq!(
            stored.ready_project_operation_id.is_some(),
            fail == "verify"
        );
    }
}

#[derive(Debug, Default)]
struct BudgetStep(Mutex<Vec<u64>>);

#[async_trait]
impl fleet_application::worker::OperationExecutor for BudgetStep {
    async fn execute(
        &self,
        operations: &Operations,
        operation: &fleet_application::operation::Operation,
    ) -> Result<(), String> {
        let payload: serde_json::Value =
            serde_json::from_str(operation.payload_json.as_deref().unwrap()).unwrap();
        self.0
            .lock()
            .unwrap()
            .push(payload["timeoutSeconds"].as_u64().unwrap());
        operations
            .complete(&operation.id, "succeeded", Some("{}"), None)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[tokio::test]
async fn production_readiness_adapter_bounds_children_and_refuses_stopped_parents() {
    let harness = Harness::new().await;
    let step = Arc::new(BudgetStep::default());
    let executor = fleet_controller::proxmox_exec::LabReadinessExecutor::new(
        step.clone(),
        step.clone(),
        Arc::new(fleet_storage_sqlite::MachineRepository::new(
            harness.pool.clone(),
        )),
        harness.operations.clone(),
        harness._dir.path().join("ssh"),
        fleet_provider_ssh::ExecutionLimiter::new(2),
    );
    for stopped in [false, true] {
        let parent = harness
            .operations
            .create(
                &AllowAll,
                "tester",
                &NewOperation {
                    kind: "ssh.exec".to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    review_token: None,
                    payload_json: Some(serde_json::json!({"machineId":"machine", "endpointId":"endpoint", "auth":{"type":"agent"}, "script":"true", "timeoutSeconds":30}).to_string()),
                },
            )
            .await
            .unwrap();
        if stopped {
            harness
                .operations
                .cancel(&AllowAll, "tester", &parent.id)
                .await
                .unwrap();
        }
        let child = harness.operations.create(&AllowAll, "tester", &NewOperation {
            kind: "ssh.exec".to_owned(), idempotency_key: None,
            deadline_at: Some(fleet_core::SystemClock::now_unix_millis() + 5_000),
            correlation_id: None, review_token: None,
            payload_json: Some(serde_json::json!({"machineId":"machine", "endpointId":"endpoint", "auth":{"type":"agent"}, "script":"true", "timeoutSeconds":900, "labParentOperationId":parent.id}).to_string()),
        }).await.unwrap();
        harness
            .operations
            .claim_only_execute(&executor, &child.id, "tester")
            .await
            .unwrap();
        assert_eq!(
            harness.operations.get_state(&child.id).await.unwrap(),
            if stopped { "failed" } else { "succeeded" }
        );
    }
    let budgets = step.0.lock().unwrap();
    assert_eq!(
        budgets.len(),
        1,
        "a cancelled parent must never reach the executor"
    );
    assert!(
        (1..=5).contains(&budgets[0]),
        "nested CLI timeout must fit inside the Lab deadline"
    );
}

#[derive(Debug)]
struct CancelAfterClone {
    parent: String,
    calls: Mutex<Vec<(String, u64)>>,
}

#[async_trait]
impl fleet_application::worker::OperationExecutor for CancelAfterClone {
    async fn execute(
        &self,
        operations: &Operations,
        operation: &fleet_application::operation::Operation,
    ) -> Result<(), String> {
        let payload: serde_json::Value =
            serde_json::from_str(operation.payload_json.as_deref().unwrap()).unwrap();
        self.calls.lock().unwrap().push((
            operation.kind.clone(),
            payload["timeoutSeconds"].as_u64().unwrap(),
        ));
        operations
            .complete(&operation.id, "succeeded", Some("{}"), None)
            .await
            .map_err(|e| e.to_string())?;
        if operation.kind == "projects.clone" {
            operations
                .cancel(&AllowAll, "tester", &self.parent)
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

async fn readiness_parent(operations: &Operations) -> fleet_application::operation::Operation {
    operations.create(&AllowAll, "tester", &NewOperation {
        kind: "ssh.exec".to_owned(), idempotency_key: None, deadline_at: None,
        correlation_id: None, review_token: None,
        payload_json: Some(serde_json::json!({"machineId":"machine", "endpointId":"endpoint", "auth":{"type":"agent"}, "script":"true", "timeoutSeconds":30}).to_string()),
    }).await.unwrap()
}

#[tokio::test]
async fn production_m3_child_bounds_nested_steps_and_stops_after_parent_cancellation() {
    let harness = Harness::new().await;
    let parent = readiness_parent(&harness.operations).await;
    let steps = Arc::new(CancelAfterClone {
        parent: parent.id.clone(),
        calls: Mutex::new(Vec::new()),
    });
    let executor = fleet_controller::proxmox_exec::LabReadinessExecutor::new(
        steps.clone(),
        steps.clone(),
        Arc::new(fleet_storage_sqlite::MachineRepository::new(
            harness.pool.clone(),
        )),
        harness.operations.clone(),
        harness._dir.path().join("ssh"),
        fleet_provider_ssh::ExecutionLimiter::new(2),
    );
    let child = harness.operations.create(&AllowAll, "tester", &NewOperation {
        kind:"ready.workflow".to_owned(), idempotency_key:None,
        deadline_at:Some(fleet_core::SystemClock::now_unix_millis()+10_000), correlation_id:None, review_token:None,
        payload_json:Some(serde_json::json!({"machineId":"machine", "endpointId":"endpoint", "auth":{"type":"agent"}, "remote":"https://example.test/demo.git", "root":"/tmp/demo", "timeoutSeconds":900, "labParentOperationId":parent.id}).to_string()),
    }).await.unwrap();
    harness
        .operations
        .claim_only_execute(&executor, &child.id, "tester")
        .await
        .unwrap();
    assert_eq!(
        harness.operations.get_state(&child.id).await.unwrap(),
        "failed"
    );
    let calls = steps.calls.lock().unwrap();
    assert!(calls.iter().any(|(kind, _)| kind == "projects.clone"));
    assert!(
        !calls
            .iter()
            .any(|(kind, _)| kind == "frogenv.setup" || kind == "tools.inventory")
    );
    assert!(calls.iter().all(|(_, seconds)| (1..=10).contains(seconds)));
}

#[derive(Debug)]
struct SlowChild;
#[async_trait]
impl fleet_application::worker::OperationExecutor for SlowChild {
    async fn execute(
        &self,
        _: &Operations,
        _: &fleet_application::operation::Operation,
    ) -> Result<(), String> {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Err("bounded test child ended".to_owned())
    }
}

#[tokio::test]
async fn production_child_watchdog_survives_the_callers_timeout() {
    use fleet_application::lab::LabReadinessPort as _;
    let harness = Harness::new().await;
    let parent = readiness_parent(&harness.operations).await;
    let (_, mut record) = harness.record().await;
    record.machine_id = Some("machine".to_owned());
    record.endpoint_id = Some("endpoint".to_owned());
    record.readiness_deadline_at = Some(fleet_core::SystemClock::now_unix_millis() + 250);
    let readiness = fleet_controller::proxmox_exec::ProvisionReadiness::new(
        Arc::new(fleet_storage_sqlite::MachineRepository::new(
            harness.pool.clone(),
        )),
        Arc::new(fleet_storage_sqlite::ProjectRepository::new(
            harness.pool.clone(),
        )),
        Arc::new(AuditSink::new(harness.pool.clone())),
        Arc::new(SlowChild),
        harness.operations.clone(),
        harness._dir.path().join("ssh"),
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            readiness.ssh_probe(
                &harness.operations,
                &parent.id,
                &record,
                "true",
                std::time::Duration::from_millis(250)
            )
        )
        .await
        .is_err()
    );
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let children = harness
        .operations
        .list(&AllowAll, "tester", 100)
        .await
        .unwrap();
    let child = children
        .iter()
        .find(|child| child.correlation_id.as_deref() == Some(&record.id))
        .unwrap();
    assert!(
        child.cancel_requested,
        "dropping the caller must not drop child cancellation"
    );
}

#[tokio::test]
async fn queue_claimed_m3_steps_inherit_the_persisted_lab_workflows_bound() {
    let harness = Harness::new().await;
    let parent = readiness_parent(&harness.operations).await;
    let workflow = harness.operations.create(&AllowAll, "tester", &NewOperation {
        kind: "ready.workflow".to_owned(), idempotency_key:None,
        deadline_at: Some(fleet_core::SystemClock::now_unix_millis()+10_000), correlation_id: None, review_token:None,
        payload_json:Some(serde_json::json!({"machineId":"machine", "endpointId":"endpoint", "auth":{"type":"agent"}, "remote":"https://example.test/demo.git", "root":"/tmp/demo", "timeoutSeconds":10, "labParentOperationId":parent.id}).to_string()),
    }).await.unwrap();
    let (_, record) = harness.record().await;
    let mut record = harness
        .labs
        .ensure_guest_machine(&record.id, "root@192.0.2.20:22")
        .await
        .unwrap();
    record.state = GuestState::Bootstrapping;
    record.ready_project_operation_id = Some(workflow.id.clone());
    record.readiness_deadline_at = Some(fleet_core::SystemClock::now_unix_millis() + 10_000);
    ProvisionPort::update(harness.labs.as_ref(), &record)
        .await
        .unwrap();
    let steps = Arc::new(BudgetStep::default());
    let executor = fleet_controller::proxmox_exec::LabReadinessExecutor::new(
        steps.clone(),
        steps.clone(),
        Arc::new(fleet_storage_sqlite::MachineRepository::new(
            harness.pool.clone(),
        )),
        harness.operations.clone(),
        harness._dir.path().join("ssh"),
        fleet_provider_ssh::ExecutionLimiter::new(2),
    )
    .with_provisions(harness.labs.clone());
    for stopped in [false, true] {
        if stopped {
            harness
                .operations
                .cancel(&AllowAll, "tester", &parent.id)
                .await
                .unwrap();
        }
        let child = harness.operations.create(&AllowAll, "tester", &NewOperation {
            kind:"projects.clone".to_owned(), idempotency_key:None, deadline_at:None, correlation_id:None, review_token:None,
            payload_json:Some(serde_json::json!({"machineId":record.machine_id, "endpointId":record.endpoint_id, "auth":{"type":"agent"}, "remote":"https://example.test/demo.git", "root":"/tmp/demo", "timeoutSeconds":600}).to_string()),
        }).await.unwrap();
        if stopped {
            record.state = GuestState::NeverReady;
            ProvisionPort::update(harness.labs.as_ref(), &record)
                .await
                .unwrap();
        }
        harness
            .operations
            .claim_only_execute(&executor, &child.id, "other-worker")
            .await
            .unwrap();
        assert_eq!(
            harness.operations.get_state(&child.id).await.unwrap(),
            if stopped { "failed" } else { "succeeded" }
        );
    }
    let calls = steps.0.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert!((1..=10).contains(&calls[0]));
}
