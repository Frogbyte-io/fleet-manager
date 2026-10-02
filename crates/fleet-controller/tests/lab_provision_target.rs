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
    /// The record's stored (node, VMID) when the clone request arrived.
    stored_target: Option<(Option<String>, Option<u32>)>,
}

#[derive(Debug)]
struct Pve {
    /// Extra guests in `/cluster/resources`, beside the node and template.
    guests: Vec<serde_json::Value>,
    clone_upid: String,
    seen: Mutex<Vec<Seen>>,
    /// The repository and record whose target the clone request observes.
    observe: Mutex<Option<(Arc<LabRepository>, String)>>,
}

impl Pve {
    fn new(guests: Vec<serde_json::Value>) -> Arc<Self> {
        Arc::new(Self {
            guests,
            clone_upid: CLONE_UPID.to_owned(),
            seen: Mutex::new(Vec::new()),
            observe: Mutex::new(None),
        })
    }

    fn with_clone_upid(guests: Vec<serde_json::Value>, upid: &str) -> Arc<Self> {
        Arc::new(Self {
            guests,
            clone_upid: upid.to_owned(),
            seen: Mutex::new(Vec::new()),
            observe: Mutex::new(None),
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
        let stored_target = if path.ends_with("/clone") {
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
            format!(r#"{{"data":"{NEXT_VMID}"}}"#)
        } else if path.ends_with("/clone") {
            format!(r#"{{"data":"{}"}}"#, self.0.clone_upid)
        } else if path.ends_with("/status/start") {
            format!(r#"{{"data":"{START_UPID}"}}"#)
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
    async fn image_template_vmids(&self) -> Result<Vec<u32>, String> {
        Ok(vec![TEMPLATE_VMID, OTHER_ARTIFACT_VMID])
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
            Arc::new(AuditSink::new(pool)),
        ));
        Self {
            _dir: dir,
            labs,
            leases,
            accounts,
            operations,
            account_id: account.id,
            version_id: version.id,
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
                Arc::new(self.executor(pve, pinned)),
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
        let _ = running.await;
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
    resumable.state = GuestState::Provisioning;
    ProvisionPort::update(harness.labs.as_ref(), &resumable)
        .await
        .unwrap();
    let second = Pve::new(Vec::new());

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
    assert!(refusal.contains("image build artifact"), "{refusal}");
    executor
        .guard_destroy_target(&harness.account_id, NEXT_VMID)
        .await
        .expect("a Lab clone may be destroyed");
}
