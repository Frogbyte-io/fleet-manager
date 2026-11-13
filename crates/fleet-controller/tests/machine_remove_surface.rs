//! #616: removing a machine at the HTTP surface, over the real router and
//! SQLite store. The SSH trust store and the fleetd uninstall are fakes that
//! remember what they were asked; everything else is the composition the
//! controller serves: the review token, `machine.delete` authorization, the
//! holds that refuse a removal (Lab provision, persistent marker, USB
//! reservation, unfinished operation), what the delete removes and keeps,
//! host-key unpinning with and without a shared host (also when the host
//! becomes shared during the removal), holds taken after the review or
//! during the uninstall, stored secrets (counted, bound, revoked, and refused
//! without a secret store), the install layout an uninstall uses, and an
//! uninstall that fails before anything is deleted.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::hardware::{DeviceObservation, HardwareStore as _, NewHardwareReservation};
use fleet_application::lab::Lab;
use fleet_application::machine::{
    GuestLink, GuestLinkPort as _, MachinePort as _, NewEndpoint, RegisterMachine,
};
use fleet_application::machine_access::{EndpointAuth, EndpointAuthPort as _, MachineKeyPort};
use fleet_application::machine_remove::{
    FleetdUninstall, FleetdUninstallPort, MachineRemoval, NodeSessionPort,
};
use fleet_application::machine_usb::StoreMachineHardwareGate;
use fleet_application::onboarding::{OnboardHostKey, OnboardTrustPort};
use fleet_application::operation::PortFailure;
use fleet_application::persistent::{
    PersistentGuest, PersistentGuestPort as _, PersistentState, REGISTERED_SOURCE,
};
use fleet_core::{
    CapabilityFact, CapabilityStatus, DeviceNodeEntry, DeviceStatus, EndpointKind, HardwareKind,
    ReservationOwnerKind,
};
use fleet_storage_sqlite::{
    AuditSink, EndpointAuthRepository, GuestLinkRepository, HardwareRepository, LabRepository,
    LeaseRepository, MachineRemovalRepository, MachineRepository, PersistentGuestRepository,
    ProjectRepository, Store,
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const ACCOUNT: &str = "acct";

#[derive(Debug)]
struct Permit;

impl Authorizer for Permit {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

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

/// Remembers which hosts were unpinned.
#[derive(Debug, Default)]
struct FakeTrust {
    unpinned: Mutex<Vec<String>>,
}

#[async_trait]
impl OnboardTrustPort for FakeTrust {
    async fn pin(&self, _host: &str, _key: &OnboardHostKey) -> Result<(), PortFailure> {
        Ok(())
    }

    async fn unpin(&self, host: &str) -> Result<(), PortFailure> {
        self.unpinned.lock().unwrap().push(host.to_owned());
        Ok(())
    }

    async fn unpin_key(&self, _host: &str, _key: &OnboardHostKey) -> Result<(), PortFailure> {
        panic!("a removal never takes back a single confirmation's pin")
    }
}

/// Answers what the test scripted and remembers what it was asked. The
/// statements in `during` run while the uninstall "runs" (with `?1` = the
/// machine), to take a hold or share a host in the middle of a removal.
#[derive(Debug)]
struct FakeUninstall {
    pool: sqlx::SqlitePool,
    answer: Mutex<Result<String, String>>,
    seen: Mutex<Vec<FleetdUninstall>>,
    during: Mutex<Vec<&'static str>>,
    /// Signals `.0` when the uninstall starts and waits for `.1`.
    pause: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
}

#[async_trait]
impl FleetdUninstallPort for FakeUninstall {
    async fn uninstall(&self, request: &FleetdUninstall) -> Result<String, String> {
        self.seen.lock().unwrap().push(request.clone());
        let pause = self.pause.lock().unwrap().take();
        if let Some((entered, release)) = pause {
            entered.notify_one();
            release.notified().await;
        }
        let statements: Vec<&'static str> = std::mem::take(&mut *self.during.lock().unwrap());
        for statement in statements {
            sqlx::query(statement)
                .bind(&request.machine_id)
                .execute(&self.pool)
                .await
                .unwrap_or_else(|error| panic!("{statement}: {error}"));
        }
        self.answer.lock().unwrap().clone()
    }
}

/// The key store's revocation, scripted.
#[derive(Debug, Default)]
struct FakeKeys {
    fail: Mutex<Option<String>>,
    revoked: Mutex<Vec<String>>,
}

#[async_trait]
impl MachineKeyPort for FakeKeys {
    async fn create(&self, _key: &str, _machine: Option<&str>) -> Result<String, String> {
        Err("unused".to_owned())
    }

    async fn exists(&self, _reference: &str, _machine: &str) -> Result<bool, String> {
        Ok(false)
    }

    async fn resolve(&self, _reference: &str, _machine: &str) -> Result<Option<String>, String> {
        Ok(None)
    }

    async fn revoke_for_machine(&self, machine_id: &str) -> Result<usize, String> {
        if let Some(error) = self.fail.lock().unwrap().clone() {
            return Err(error);
        }
        self.revoked.lock().unwrap().push(machine_id.to_owned());
        Ok(2)
    }
}

/// A gateway that has a live session for every machine.
#[derive(Debug, Default)]
struct FakeSessions {
    closed: Mutex<Vec<String>>,
}

#[async_trait]
impl NodeSessionPort for FakeSessions {
    async fn close(&self, machine_id: &str) -> bool {
        self.closed.lock().unwrap().push(machine_id.to_owned());
        true
    }
}

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

/// The audit sink, failing the writes of one event when told to.
#[derive(Debug)]
struct FlakyAudit {
    inner: Arc<AuditSink>,
    fail_event: Mutex<Option<&'static str>>,
}

#[async_trait]
impl fleet_application::operation::AuditPort for FlakyAudit {
    async fn record_intent(
        &self,
        intent: &fleet_application::audit::AuditIntent,
    ) -> Result<(), String> {
        let event = intent
            .metadata
            .entries()
            .find(|(key, _)| *key == "event")
            .map(|(_, value)| value.to_owned());
        if event.is_some() && event.as_deref() == *self.fail_event.lock().unwrap() {
            return Err("the audit store is full".to_owned());
        }
        self.inner.record_intent(intent).await
    }

    async fn record_outcome(
        &self,
        operation_id: &str,
        outcome: fleet_application::audit::AuditOutcome,
    ) -> Result<(), String> {
        self.inner.record_outcome(operation_id, outcome).await
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    state: Arc<ApiState>,
    trust: Arc<FakeTrust>,
    uninstall: Arc<FakeUninstall>,
    keys: Arc<FakeKeys>,
    sessions: Arc<FakeSessions>,
    flaky: Arc<FlakyAudit>,
    machines: Arc<MachineRepository>,
    hardware: Arc<HardwareRepository>,
}

impl Harness {
    async fn new(authorizer: Arc<dyn Authorizer>) -> Self {
        Self::with(authorizer, true, true).await
    }

    /// `wired`: the controller composed removal; `secrets`: it has its
    /// secret store (the key revocation).
    async fn with(authorizer: Arc<dyn Authorizer>, wired: bool, secrets: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        std::mem::forget(store);
        sqlx::query(
            "INSERT INTO proxmox_accounts (id, name, host, port, token_id, created_at) \
             VALUES (?1, ?1, 'pve.example.test', 8006, 'fleet@pve!lab', 1)",
        )
        .bind(ACCOUNT)
        .execute(&pool)
        .await
        .unwrap();
        let machines = Arc::new(MachineRepository::new(pool.clone()));
        let hardware = Arc::new(HardwareRepository::new(pool.clone()));
        let audit = Arc::new(AuditSink::new(pool.clone()));
        let trust = Arc::new(FakeTrust::default());
        let uninstall = Arc::new(FakeUninstall {
            pool: pool.clone(),
            answer: Mutex::new(Ok(
                "uninstall: service removed and state purged; the next install enrolls fresh"
                    .to_owned(),
            )),
            seen: Mutex::new(Vec::new()),
            during: Mutex::new(Vec::new()),
            pause: Mutex::new(None),
        });
        let keys = Arc::new(FakeKeys::default());
        let sessions = Arc::new(FakeSessions::default());
        let flaky = Arc::new(FlakyAudit {
            inner: audit.clone(),
            fail_event: Mutex::new(None),
        });
        let removal = MachineRemoval::new(
            machines.clone(),
            Arc::new(MachineRemovalRepository::new(pool.clone())),
            Arc::new(StoreMachineHardwareGate::new(hardware.clone())),
            trust.clone(),
            flaky.clone(),
        )
        .with_endpoint_auth(Arc::new(EndpointAuthRepository::new(pool.clone())))
        .with_uninstaller(uninstall.clone())
        .with_sessions(sessions.clone());
        let removal = if secrets {
            removal.with_key_revocation(keys.clone())
        } else {
            removal
        };
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let lab = Lab::new(
            labs.clone(),
            labs,
            Arc::new(LeaseRepository::new(pool.clone())),
            Arc::new(NoPins),
            Arc::new(ProjectRepository::new(pool.clone())),
            audit,
        );
        let lab = if wired {
            lab.with_machine_removal(Arc::new(removal))
        } else {
            lab
        };
        let state = Arc::new(ApiState {
            authorizer,
            lab: Some(Arc::new(lab)),
            ..ApiState::for_document()
        });
        Self {
            _dir: dir,
            pool,
            state,
            trust,
            uninstall,
            keys,
            sessions,
            flaky,
            machines,
            hardware,
        }
    }

    async fn machine(&self, name: &str, references: &[&str]) -> String {
        let mut endpoints: Vec<NewEndpoint> = references
            .iter()
            .map(|reference| NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: (*reference).to_owned(),
            })
            .collect();
        endpoints.push(NewEndpoint {
            kind: EndpointKind::Fleetd,
            reference: format!("node-{name}"),
        });
        self.machines
            .register(&RegisterMachine {
                name: name.to_owned(),
                description: String::new(),
                endpoints,
                tags: vec!["pilot".to_owned()],
                groups: vec![],
            })
            .await
            .unwrap()
            .id
    }

    async fn endpoint(&self, machine: &str, kind: EndpointKind) -> String {
        self.machines
            .get(machine)
            .await
            .unwrap()
            .endpoints
            .into_iter()
            .find(|endpoint| endpoint.kind == kind)
            .unwrap()
            .id
    }

    async fn sql(&self, statement: &'static str, machine: &str) {
        sqlx::query(statement)
            .bind(machine)
            .execute(&self.pool)
            .await
            .unwrap_or_else(|error| panic!("{statement}: {error}"));
    }

    async fn count(&self, statement: &'static str, machine: &str) -> i64 {
        sqlx::query_scalar(statement)
            .bind(machine)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn call_as(&self, principal: &str, path: &str, body: &Value) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri(format!("{API_BASE_PATH}{path}"))
            .header("content-type", "application/json")
            .header(
                CORRELATION_ID_HEADER,
                "01900000-0000-7000-8000-000000000000",
            )
            .body(Body::from(body.to_string()))
            .unwrap();
        let app = router(self.state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
            id: principal.to_owned(),
        }));
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    async fn review(&self, machine: &str, body: Value) -> (StatusCode, Value) {
        self.call_as(
            fleet_auth::LAN_PRINCIPAL_ID,
            &format!("/machines/{machine}/remove/review"),
            &body,
        )
        .await
    }

    async fn remove(&self, machine: &str, body: Value) -> (StatusCode, Value) {
        self.call_as(
            fleet_auth::LAN_PRINCIPAL_ID,
            &format!("/machines/{machine}/remove"),
            &body,
        )
        .await
    }

    /// Reviews and answers the token, asserting there is one.
    async fn token(&self, machine: &str, body: Value) -> String {
        let (status, review) = self.review(machine, body).await;
        assert_eq!(status, StatusCode::OK, "{review}");
        review["data"]["reviewToken"]
            .as_str()
            .unwrap_or_else(|| panic!("no token: {review}"))
            .to_owned()
    }

    fn unpinned(&self) -> Vec<String> {
        self.trust.unpinned.lock().unwrap().clone()
    }

    async fn audit_events(&self, machine: &str) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT json_extract(metadata_json, '$.event') FROM audit_events \
             WHERE resource = ?1 AND action = 'machine.delete' ORDER BY seq",
        )
        .bind(machine)
        .fetch_all(&self.pool)
        .await
        .unwrap()
        .into_iter()
        .map(|event: Option<String>| event.unwrap_or_else(|| "delete".to_owned()))
        .collect()
    }

    async fn exists(&self, machine: &str) -> bool {
        self.machines.get(machine).await.is_ok()
    }
}

#[tokio::test]
async fn a_removal_deletes_the_facts_keeps_the_history_and_unpins_its_own_host() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine("box", &["root@box.lan:22"]).await;
    let ssh = harness.endpoint(&machine, EndpointKind::Ssh).await;
    harness
        .machines
        .record_capabilities(
            &machine,
            &[CapabilityFact {
                namespace: "os".to_owned(),
                name: "family".to_owned(),
                value: Some("linux".to_owned()),
                status: CapabilityStatus::Known,
                observed_at: fleet_core::Timestamp::from_unix_millis(1),
                source: "agentless/1".to_owned(),
            }],
        )
        .await
        .unwrap();
    harness
        .machines
        .record_snapshot(&machine, "agentless/1", "{}", 1)
        .await
        .unwrap();
    EndpointAuthRepository::new(harness.pool.clone())
        .set(&ssh, Some(&EndpointAuth::Agent))
        .await
        .unwrap();
    GuestLinkRepository::new(harness.pool.clone())
        .confirm(
            &machine,
            &GuestLink {
                account_id: ACCOUNT.to_owned(),
                guest_kind: "qemu".to_owned(),
                node: "pve".to_owned(),
                vmid: 4242,
            },
        )
        .await
        .unwrap();
    harness
        .sql(
            "INSERT INTO node_identities (machine_id, public_key, key_version, status, enrolled_at) \
             VALUES (?1, 'abcd', 1, 'active', 1)",
            &machine,
        )
        .await;
    harness
        .sql(
            "INSERT INTO catalog_skill_installs (machine_id, catalog_id, agent, version_id, skill_name, installed_at) \
             VALUES (?1, 'builtin-fleet', 'claude_code', 'v1', 'fleet', 1)",
            &machine,
        )
        .await;
    harness
        .sql(
            "INSERT INTO skills_snapshots (machine_id, availability, data_json, update_check, observed_at) \
             VALUES (?1, 'available', '{}', 'complete', 1)",
            &machine,
        )
        .await;
    // History: a finished operation on the machine and a collected file.
    harness
        .sql(
            "INSERT INTO operations (id, kind, state, cancel_requested, created_at, updated_at, payload_json) \
             VALUES ('op-done', 'machine.exec', 'succeeded', 0, 1, 1, json_object('machineId', ?1))",
            &machine,
        )
        .await;
    harness
        .sql(
            "INSERT INTO machine_files (id, machine_id, owner, name, size_bytes, sha256, location, created_at, retain_until) \
             VALUES ('file-1', ?1, 'lan', 'log.txt', 1, \
                     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
                     'sha256/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 9999999999999)",
            &machine,
        )
        .await;

    let (status, review) = harness.review(&machine, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{review}");
    let data = &review["data"];
    assert_eq!(data["name"], "box");
    assert_eq!(data["blockers"], json!([]));
    assert_eq!(data["unpinHosts"], json!(["box.lan"]));
    assert_eq!(data["keptHosts"], json!([]));
    assert_eq!(data["uninstall"], Value::Null);
    assert_eq!(data["nodeIdentity"], "active");
    assert_eq!(data["footprint"]["endpoints"], 2);
    assert_eq!(data["footprint"]["endpointAuth"], 1);
    assert_eq!(data["footprint"]["capabilities"], 1);
    assert_eq!(data["footprint"]["inventorySnapshots"], 1);
    assert_eq!(data["footprint"]["nodeIdentity"], 1);
    assert_eq!(data["footprint"]["catalogSkillInstalls"], 1);
    assert_eq!(data["footprint"]["skillsSnapshot"], 1);
    assert_eq!(data["footprint"]["guestLink"], 1);
    assert_eq!(data["footprint"]["collectedFilesKept"], 1);
    // A review writes nothing.
    assert!(harness.exists(&machine).await);
    assert!(harness.unpinned().is_empty());

    let token = data["reviewToken"].as_str().unwrap().to_owned();
    let (status, removed) = harness
        .remove(&machine, json!({ "reviewToken": token }))
        .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    let removed = &removed["data"];
    assert_eq!(removed["removed"], true);
    assert_eq!(removed["uninstalled"], false);
    assert_eq!(removed["nodeIdentityRemoved"], true);
    assert_eq!(removed["unpinnedHosts"], json!(["box.lan"]));
    assert_eq!(harness.unpinned(), ["box.lan"]);
    assert!(
        harness.uninstall.seen.lock().unwrap().is_empty(),
        "nothing on the machine is touched without --uninstall"
    );

    // Gone: the record and every fact about it.
    assert!(!harness.exists(&machine).await);
    for table in [
        "machine_endpoints",
        "machine_capabilities",
        "inventory_snapshots",
        "machine_tags",
        "node_identities",
        "catalog_skill_installs",
        "skills_snapshots",
        "confirmed_guest_links",
    ] {
        let statement = format!("SELECT COUNT(*) FROM {table} WHERE machine_id = ?1");
        let statement: &'static str = Box::leak(statement.into_boxed_str());
        assert_eq!(harness.count(statement, &machine).await, 0, "{table}");
    }
    assert_eq!(
        harness
            .count(
                "SELECT COUNT(*) FROM machine_endpoint_auth WHERE endpoint_id = ?1",
                &ssh
            )
            .await,
        0
    );
    // Kept: the finished operation, the collected file and the audit trail.
    assert_eq!(
        harness
            .count(
                "SELECT COUNT(*) FROM operations WHERE json_extract(payload_json, '$.machineId') = ?1",
                &machine
            )
            .await,
        1
    );
    assert_eq!(
        harness
            .count(
                "SELECT COUNT(*) FROM machine_files WHERE machine_id = ?1",
                &machine
            )
            .await,
        1
    );
    let events = harness.audit_events(&machine).await;
    assert_eq!(events, ["machine_deleted", "machine_removed"], "{events:?}");
    let summary: String = sqlx::query_scalar(
        "SELECT metadata_json FROM audit_events WHERE resource = ?1 \
         AND json_extract(metadata_json, '$.event') = 'machine_removed'",
    )
    .bind(&machine)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    let summary: Value = serde_json::from_str(&summary).unwrap();
    assert_eq!(summary["skillInstallsDropped"], "1");
    assert_eq!(summary["hostsUnpinned"], "1");
    assert_eq!(summary["nodeIdentity"], "active");

    // A second removal finds nothing.
    let (status, _) = harness.review(&machine, json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_host_another_machine_or_a_draft_uses_keeps_its_pins() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness
        .machine(
            "box",
            &[
                "root@Shared.lan:22",
                "root@own.lan:22",
                "root@drafted.lan:22",
            ],
        )
        .await;
    // Another machine reaches the same host on another port and login.
    harness
        .machine("neighbor", &["admin@shared.lan:2222"])
        .await;
    // An onboarding draft is staged for another host of the machine.
    harness
        .sql(
            "INSERT INTO onboarding_drafts (id, endpoint_user, endpoint_host, endpoint_port, auth_type, name, created_at, updated_at) \
             VALUES ('draft-1', 'root', 'drafted.lan', 22, 'agent', ?1, 1, 1)",
            "staged",
        )
        .await;

    let token = harness.token(&machine, json!({})).await;
    let (_, review) = harness.review(&machine, json!({})).await;
    assert_eq!(review["data"]["unpinHosts"], json!(["own.lan"]));
    assert_eq!(
        review["data"]["keptHosts"],
        json!(["drafted.lan", "shared.lan"])
    );

    let (status, removed) = harness
        .remove(&machine, json!({ "reviewToken": token }))
        .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(harness.unpinned(), ["own.lan"]);
    assert_eq!(
        removed["data"]["keptHosts"],
        json!(["drafted.lan", "shared.lan"])
    );
}

#[tokio::test]
async fn the_token_binds_the_endpoints_and_the_uninstall() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine("box", &["root@box.lan:22"]).await;
    let ssh = harness.endpoint(&machine, EndpointKind::Ssh).await;

    // A made-up token is refused, and nothing is deleted.
    let (status, error) = harness
        .remove(&machine, json!({ "reviewToken": "0".repeat(64) }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["code"], "invalid_request");

    // A token reviewed without the uninstall does not cover one.
    let plain = harness.token(&machine, json!({})).await;
    let uninstall = json!({ "endpointId": ssh });
    let (status, _) = harness
        .remove(
            &machine,
            json!({ "reviewToken": plain, "uninstall": uninstall }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(harness.uninstall.seen.lock().unwrap().is_empty());

    // The machine changed after the review: the token is stale.
    let reviewed = harness
        .token(&machine, json!({ "uninstall": uninstall }))
        .await;
    assert_ne!(reviewed, plain);
    harness
        .machines
        .set_endpoints(
            &machine,
            &[
                NewEndpoint {
                    kind: EndpointKind::Ssh,
                    reference: "root@box.lan:22".to_owned(),
                },
                NewEndpoint {
                    kind: EndpointKind::Ssh,
                    reference: "root@box-2.lan:22".to_owned(),
                },
            ],
        )
        .await
        .unwrap();
    let ssh = harness.endpoint(&machine, EndpointKind::Ssh).await;
    let (status, error) = harness
        .remove(
            &machine,
            json!({ "reviewToken": reviewed, "uninstall": { "endpointId": ssh } }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("review the removal again")
    );
    assert!(harness.exists(&machine).await);
    assert!(harness.unpinned().is_empty());
    assert!(harness.uninstall.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn every_hold_refuses_the_removal_with_what_to_do() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine("box", &["root@box.lan:22"]).await;
    let token = harness.token(&machine, json!({})).await;

    // A Lab guest: its lease owns its lifecycle.
    harness
        .sql(
            "INSERT INTO lab_leases (id, template_version_id, owner, purpose, state, provision_id, cleanup, created_at) \
             VALUES ('lease-1', 'tv-1', 'lan', 'test', 'ready', 'provision-1', 'destroy', 1)",
            "",
        )
        .await;
    harness
        .sql(
            "INSERT INTO lab_provisions (id, template_version_id, state, created_at, updated_at, lease_id, machine_id) \
             VALUES ('provision-1', 'tv-1', 'ready', 1, 1, 'lease-1', ?1)",
            &machine,
        )
        .await;
    // A registered persistent machine: the persistent flow owns its marker.
    PersistentGuestRepository::new(harness.pool.clone())
        .reserve(&PersistentGuest {
            account_id: ACCOUNT.to_owned(),
            vmid: 8100,
            name: "box".to_owned(),
            node: "pve".to_owned(),
            image_version_id: REGISTERED_SOURCE.to_owned(),
            machine_id: Some(machine.clone()),
            cloned: true,
            state: PersistentState::Ready,
            step: None,
            operation_id: None,
            created_at: 1,
            updated_at: 1,
        })
        .await
        .unwrap();
    // A USB device the machine holds.
    let now = fleet_core::SystemClock::now_unix_millis();
    harness
        .hardware
        .upsert_device(
            &DeviceObservation {
                id: "device-1".to_owned(),
                account_id: ACCOUNT.to_owned(),
                mapping_id: "fm-test-reader-a".to_owned(),
                kind: HardwareKind::Usb,
                entries: vec![DeviceNodeEntry {
                    node: "pve".to_owned(),
                    vendor_id: "aaaa".to_owned(),
                    product_id: "0001".to_owned(),
                    usbpath: Some("1-1".to_owned()),
                    manufacturer: None,
                    product: None,
                    last_seen_at: now,
                }],
                status: DeviceStatus::Available,
                status_detail: None,
            },
            now,
        )
        .await
        .unwrap();
    harness
        .hardware
        .insert_reservation(
            &NewHardwareReservation {
                id: "reservation-1".to_owned(),
                device_id: "device-1".to_owned(),
                owner_kind: ReservationOwnerKind::Machine,
                owner_id: machine.clone(),
                guest: None,
            },
            now,
        )
        .await
        .unwrap();
    // An operation still running on the machine.
    harness
        .sql(
            "INSERT INTO operations (id, kind, state, cancel_requested, created_at, updated_at, payload_json) \
             VALUES ('op-running', 'skills.probe', 'running', 0, 1, 1, json_object('machineId', ?1))",
            &machine,
        )
        .await;

    let (status, review) = harness.review(&machine, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{review}");
    assert_eq!(review["data"]["reviewToken"], Value::Null);
    let blockers = review["data"]["blockers"].as_array().unwrap();
    let kinds: Vec<&str> = blockers
        .iter()
        .map(|blocker| blocker["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "lab_provision",
            "persistent_marker",
            "hardware_reservation",
            "active_operation"
        ]
    );
    let detail = |kind: &str| -> String {
        blockers
            .iter()
            .find(|blocker| blocker["kind"] == kind)
            .unwrap()["detail"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert!(
        detail("lab_provision").contains("fleetctl lab destroy lease-1"),
        "{}",
        detail("lab_provision")
    );
    assert!(
        detail("persistent_marker")
            .contains("fleetctl machines persistent unregister --account acct --vmid 8100"),
        "{}",
        detail("persistent_marker")
    );
    assert!(
        detail("hardware_reservation").contains("fleetctl machines usb detach"),
        "{}",
        detail("hardware_reservation")
    );
    assert!(
        detail("active_operation").contains("op-running"),
        "{}",
        detail("active_operation")
    );

    // The token reviewed before the holds no longer removes anything.
    let (status, error) = harness
        .remove(&machine, json!({ "reviewToken": token }))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert_eq!(error["code"], "machine_removal_blocked");
    assert!(harness.exists(&machine).await);
    assert!(harness.unpinned().is_empty());

    // Each hold refuses on its own.
    harness
        .sql("DELETE FROM lab_provisions WHERE machine_id = ?1", &machine)
        .await;
    harness
        .sql(
            "DELETE FROM persistent_guests WHERE machine_id = ?1",
            &machine,
        )
        .await;
    harness
        .sql(
            "UPDATE operations SET state = 'succeeded' WHERE json_extract(payload_json, '$.machineId') = ?1",
            &machine,
        )
        .await;
    let (_, review) = harness.review(&machine, json!({})).await;
    assert_eq!(
        review["data"]["blockers"].as_array().unwrap().len(),
        1,
        "{review}"
    );
    harness
        .sql(
            "UPDATE hardware_reservations SET state = 'released', released_at = 2 WHERE owner_id = ?1",
            &machine,
        )
        .await;
    let token = harness.token(&machine, json!({})).await;
    let (status, removed) = harness
        .remove(&machine, json!({ "reviewToken": token }))
        .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    // The released reservation is history and stays.
    assert_eq!(
        harness
            .count(
                "SELECT COUNT(*) FROM hardware_reservations WHERE owner_id = ?1",
                &machine
            )
            .await,
        1
    );
}

#[tokio::test]
async fn a_failed_uninstall_leaves_the_machine_and_a_clean_one_runs_first() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine("box", &["root@box.lan:22"]).await;
    let ssh = harness.endpoint(&machine, EndpointKind::Ssh).await;
    // The endpoint's stored default authentication is what the uninstall
    // uses when the request names none.
    EndpointAuthRepository::new(harness.pool.clone())
        .set(
            &ssh,
            Some(&EndpointAuth::IdentityFile {
                path: "/etc/fleet/keys/box".to_owned(),
            }),
        )
        .await
        .unwrap();
    let uninstall = json!({ "uninstall": { "endpointId": ssh } });
    let (status, review) = harness.review(&machine, uninstall.clone()).await;
    assert_eq!(status, StatusCode::OK, "{review}");
    assert_eq!(
        review["data"]["uninstall"],
        json!({ "endpointId": ssh, "auth": { "type": "identityFile", "path": "/etc/fleet/keys/box" }, "layout": {} })
    );
    let token = review["data"]["reviewToken"].as_str().unwrap().to_owned();

    *harness.uninstall.answer.lock().unwrap() =
        Err("the uninstall script exited 1: uninstall: cannot remove /etc/systemd/system/fleetd.service".to_owned());
    let mut body = uninstall.clone();
    body["reviewToken"] = json!(token);
    let (status, error) = harness.remove(&machine, body.clone()).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{error}");
    assert_eq!(error["code"], "fleetd_uninstall_failed");
    assert!(
        harness.exists(&machine).await,
        "a failed uninstall leaves the machine"
    );
    assert!(harness.unpinned().is_empty());
    assert_eq!(
        harness.audit_events(&machine).await,
        ["fleetd_uninstall_started", "fleetd_uninstall_failed"]
    );

    *harness.uninstall.answer.lock().unwrap() = Ok("uninstall: service removed".to_owned());
    let (status, removed) = harness.remove(&machine, body).await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["data"]["uninstalled"], true);
    assert_eq!(
        removed["data"]["uninstallSummary"],
        "uninstall: service removed"
    );
    let seen = harness.uninstall.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].machine_id, machine);
    assert_eq!(seen[1].plan.endpoint_id, ssh);
    assert_eq!(
        seen[1].plan.auth,
        EndpointAuth::IdentityFile {
            path: "/etc/fleet/keys/box".to_owned()
        }
    );
    assert!(!harness.exists(&machine).await);
    assert_eq!(
        harness.audit_events(&machine).await,
        [
            "fleetd_uninstall_started",
            "fleetd_uninstall_failed",
            "fleetd_uninstall_started",
            "fleetd_uninstalled",
            "machine_deleted",
            "machine_removed"
        ]
    );
}

#[tokio::test]
async fn the_uninstall_runs_only_over_one_of_the_machines_ssh_endpoints() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine("box", &["root@box.lan:22"]).await;
    let other = harness.machine("other", &["root@other.lan:22"]).await;
    let node = harness.endpoint(&machine, EndpointKind::Fleetd).await;
    let foreign = harness.endpoint(&other, EndpointKind::Ssh).await;
    for endpoint in [node, foreign, "missing".to_owned()] {
        let (status, error) = harness
            .review(&machine, json!({ "uninstall": { "endpointId": endpoint } }))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    }
    let (status, _) = harness
        .review(&machine, json!({ "unexpected": true }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn removal_needs_machine_delete_and_a_wired_controller() {
    let harness = Harness::new(Arc::new(Deny(Permission::MachineDelete))).await;
    let machine = harness.machine("box", &["root@box.lan:22"]).await;
    let (status, error) = harness.review(&machine, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{error}");
    let (status, _) = harness
        .remove(&machine, json!({ "reviewToken": "0".repeat(64) }))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(harness.exists(&machine).await);
    assert!(harness.audit_events(&machine).await.is_empty());

    let unwired = Harness::with(Arc::new(Permit), false, true).await;
    let machine = unwired.machine("box", &["root@box.lan:22"]).await;
    let (status, error) = unwired.review(&machine, json!({})).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{error}");
    assert_eq!(error["code"], "machine_removal_unavailable");
}

#[test]
fn machine_delete_is_risky_and_never_delegated() {
    assert!(Permission::MachineDelete.is_risky());
    assert_eq!(Permission::MachineDelete.id(), "machine.delete");
}

#[tokio::test]
async fn a_hold_taken_during_the_uninstall_refuses_the_delete() {
    for (hold, named) in [
        (
            "INSERT INTO lab_provisions (id, template_version_id, state, created_at, updated_at, machine_id) \
             VALUES ('provision-late', 'tv-1', 'ready', 1, 1, ?1)",
            "Lab provision provision-late",
        ),
        (
            "INSERT INTO persistent_guests (account_id, vmid, name, node, image_version_id, machine_id, cloned, state, created_at, updated_at) \
             VALUES ('acct', 8200, 'late', 'pve', 'registered', ?1, 1, 'ready', 1, 1)",
            "persistent marker acct/8200",
        ),
        (
            "INSERT INTO operations (id, kind, state, cancel_requested, created_at, updated_at, payload_json) \
             VALUES ('op-late', 'machine.exec', 'pending', 0, 1, 1, json_object('machineId', ?1))",
            "operation op-late",
        ),
    ] {
        let harness = Harness::new(Arc::new(Permit)).await;
        let machine = harness.machine("box", &["root@box.lan:22"]).await;
        let ssh = harness.endpoint(&machine, EndpointKind::Ssh).await;
        let body = json!({ "uninstall": { "endpointId": ssh } });
        let token = harness.token(&machine, body.clone()).await;
        harness.uninstall.during.lock().unwrap().push(hold);
        let mut body = body;
        body["reviewToken"] = json!(token);
        let (status, error) = harness.remove(&machine, body).await;
        assert_eq!(status, StatusCode::CONFLICT, "{error}");
        assert_eq!(error["code"], "conflict");
        let message = error["message"].as_str().unwrap();
        assert!(message.contains(named), "{message}");
        assert!(harness.exists(&machine).await, "the guarded delete refused");
        assert!(harness.unpinned().is_empty());
        assert!(harness.keys.revoked.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn a_hold_taken_after_the_review_refuses_the_removal() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine("box", &["root@box.lan:22"]).await;
    let token = harness.token(&machine, json!({})).await;
    harness
        .sql(
            "INSERT INTO operations (id, kind, state, cancel_requested, created_at, updated_at, payload_json) \
             VALUES ('op-late', 'machine.exec', 'cancelling', 0, 1, 1, json_object('machineId', ?1))",
            &machine,
        )
        .await;
    let (status, error) = harness
        .remove(&machine, json!({ "reviewToken": token }))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert_eq!(error["code"], "machine_removal_blocked");
    assert!(harness.exists(&machine).await);
}

#[tokio::test]
async fn an_operation_blocked_for_manual_approval_does_not_hold_the_machine() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine("box", &["root@box.lan:22"]).await;
    // `blocked_manual_approval` is terminal: nothing moves it on, and cancel
    // cannot clear it, so it must not keep the machine forever.
    harness
        .sql(
            "INSERT INTO operations (id, kind, state, cancel_requested, created_at, updated_at, payload_json) \
             VALUES ('op-blocked', 'frogenv.request', 'blocked_manual_approval', 0, 1, 1, json_object('machineId', ?1))",
            &machine,
        )
        .await;
    let (_, review) = harness.review(&machine, json!({})).await;
    assert_eq!(review["data"]["blockers"], json!([]), "{review}");
    let token = review["data"]["reviewToken"].as_str().unwrap().to_owned();
    let (status, removed) = harness
        .remove(&machine, json!({ "reviewToken": token }))
        .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
}

#[tokio::test]
async fn a_lease_that_does_not_link_back_is_not_offered_as_the_way_out() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine("box", &["root@box.lan:22"]).await;
    harness
        .sql(
            "INSERT INTO lab_leases (id, template_version_id, owner, purpose, state, provision_id, cleanup, created_at) \
             VALUES ('lease-other', 'tv-1', 'lan', 'test', 'ready', 'provision-other', 'destroy', 1)",
            "",
        )
        .await;
    harness
        .sql(
            "INSERT INTO lab_provisions (id, template_version_id, state, created_at, updated_at, lease_id, machine_id) \
             VALUES ('provision-1', 'tv-1', 'ready', 1, 1, 'lease-other', ?1)",
            &machine,
        )
        .await;
    let (_, review) = harness.review(&machine, json!({})).await;
    let detail = review["data"]["blockers"][0]["detail"].as_str().unwrap();
    assert!(!detail.contains("lease-other"), "{detail}");
    assert!(detail.contains("lab pool drain"), "{detail}");
}

#[tokio::test]
async fn a_host_shared_during_the_removal_keeps_its_pins() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness
        .machine("box", &["root@box.lan:22", "root@own.lan:22"])
        .await;
    let ssh = harness.endpoint(&machine, EndpointKind::Ssh).await;
    let body = json!({ "uninstall": { "endpointId": ssh } });
    let (_, review) = harness.review(&machine, body.clone()).await;
    assert_eq!(review["data"]["unpinHosts"], json!(["box.lan", "own.lan"]));
    // While the uninstall runs, an onboarding draft starts using box.lan.
    harness.uninstall.during.lock().unwrap().push(
        "INSERT INTO onboarding_drafts (id, endpoint_user, endpoint_host, endpoint_port, auth_type, name, created_at, updated_at) \
         VALUES ('draft-late', 'root', 'BOX.lan', 22, 'agent', 'late-' || ?1, 1, 1)",
    );
    let mut body = body;
    body["reviewToken"] = review["data"]["reviewToken"].clone();
    let (status, removed) = harness.remove(&machine, body).await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(harness.unpinned(), ["own.lan"]);
    assert_eq!(removed["data"]["unpinnedHosts"], json!(["own.lan"]));
    assert_eq!(removed["data"]["keptHosts"], json!(["box.lan"]));
}

async fn store_secret(harness: &Harness, name: String) {
    sqlx::query(
        "INSERT INTO secret_records (id, name, value, key_version, record_version, created_at, updated_at) \
         VALUES (?1, ?2, x'00', 1, 1, 1, 1)",
    )
    .bind(format!("secret-{}", name.replace('/', "-")))
    .bind(name)
    .execute(&harness.pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn stored_secrets_are_counted_bound_revoked_and_their_revocation_failure_reported() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine("box", &["root@box.lan:22"]).await;
    store_secret(&harness, format!("machines/ssh/{machine}/key")).await;
    let before = harness.token(&machine, json!({})).await;
    store_secret(
        &harness,
        format!("machines/windows-admin/{machine}/administrator"),
    )
    .await;

    let (_, review) = harness.review(&machine, json!({})).await;
    let data = &review["data"];
    assert_eq!(data["footprint"]["storedSshKeys"], 1);
    assert_eq!(data["footprint"]["adminPasswords"], 1);
    let warning = data["warnings"][0].as_str().unwrap();
    assert!(warning.contains("administrator password"), "{warning}");
    // The token reviewed before the password was stored no longer applies.
    let (status, _) = harness
        .remove(&machine, json!({ "reviewToken": before }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The revocation fails after the delete: the machine is still removed,
    // the delete is audited first, the pins still go, and the failure is
    // reported and audited.
    *harness.keys.fail.lock().unwrap() = Some("the secret store is unreadable".to_owned());
    let token = data["reviewToken"].as_str().unwrap().to_owned();
    let (status, removed) = harness
        .remove(&machine, json!({ "reviewToken": token }))
        .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert!(!harness.exists(&machine).await);
    assert_eq!(
        removed["data"]["secretRevocationError"],
        "the secret store is unreadable"
    );
    assert_eq!(removed["data"]["secretsRevoked"], 0);
    assert_eq!(removed["data"]["sessionClosed"], true);
    assert_eq!(
        *harness.sessions.closed.lock().unwrap(),
        std::slice::from_ref(&machine)
    );
    assert_eq!(harness.unpinned(), ["box.lan"]);
    assert_eq!(
        harness.audit_events(&machine).await,
        [
            "machine_deleted",
            "machine_secret_revocation_failed",
            "machine_removed"
        ]
    );
    let correlations: Vec<Option<String>> =
        sqlx::query_scalar("SELECT correlation_id FROM audit_events WHERE resource = ?1")
            .bind(&machine)
            .fetch_all(&harness.pool)
            .await
            .unwrap();
    assert!(
        correlations
            .iter()
            .all(|id| id.as_deref() == Some("01900000-0000-7000-8000-000000000000")),
        "{correlations:?}"
    );
}

#[tokio::test]
async fn without_a_secret_store_only_a_machine_without_stored_secrets_is_removed() {
    let harness = Harness::with(Arc::new(Permit), true, false).await;
    let plain = harness.machine("plain", &["root@plain.lan:22"]).await;
    let keyed = harness.machine("keyed", &["root@keyed.lan:22"]).await;
    let ssh = harness.endpoint(&keyed, EndpointKind::Ssh).await;
    EndpointAuthRepository::new(harness.pool.clone())
        .set(
            &ssh,
            Some(&EndpointAuth::Secret {
                credential: "machines/ssh/shared".to_owned(),
            }),
        )
        .await
        .unwrap();

    // A reference to a key is not a key bound to this machine: the removal
    // never revokes it, so it does not block.
    let (_, review) = harness.review(&keyed, json!({})).await;
    assert_eq!(review["data"]["blockers"], json!([]), "{review}");
    assert_eq!(review["data"]["footprint"]["endpointAuthSecrets"], 1);
    // A key bound to the machine would be left behind: it blocks.
    store_secret(&harness, format!("machines/ssh/{keyed}/key")).await;
    let (_, review) = harness.review(&keyed, json!({})).await;
    assert_eq!(review["data"]["reviewToken"], Value::Null);
    assert_eq!(review["data"]["blockers"][0]["kind"], "stored_secret");
    let detail = review["data"]["blockers"][0]["detail"].as_str().unwrap();
    assert!(detail.contains("1 SSH keys"), "{detail}");

    let token = harness.token(&plain, json!({})).await;
    let (status, removed) = harness
        .remove(&plain, json!({ "reviewToken": token }))
        .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert!(harness.keys.revoked.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_uninstall_uses_the_layout_the_machine_was_installed_with() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine("box", &["root@box.lan:22"]).await;
    let ssh = harness.endpoint(&machine, EndpointKind::Ssh).await;
    harness
        .sql(
            "INSERT INTO operations (id, kind, state, cancel_requested, created_at, updated_at, payload_json) \
             VALUES ('op-install', 'machine.install-fleetd', 'succeeded', 0, 1, 1, \
                     json_object('machineId', ?1, 'installerEnv', \
                         json_array(json_array('FLEETD_UNIT_DIR', '/opt/units'), \
                                    json_array('FLEETD_USER_ADD', '/bin/true'))))",
            &machine,
        )
        .await;
    let body = json!({ "uninstall": { "endpointId": ssh, "auth": { "type": "agent" } } });
    let (_, review) = harness.review(&machine, body.clone()).await;
    assert_eq!(
        review["data"]["uninstall"]["layout"],
        json!({ "FLEETD_UNIT_DIR": "/opt/units" }),
        "only layout names are carried over"
    );
    let mut body = body;
    body["reviewToken"] = review["data"]["reviewToken"].clone();
    let (status, removed) = harness.remove(&machine, body).await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    let seen = harness.uninstall.seen.lock().unwrap().clone();
    assert_eq!(
        seen[0]
            .plan
            .layout
            .get("FLEETD_UNIT_DIR")
            .map(String::as_str),
        Some("/opt/units")
    );
    assert_eq!(seen[0].plan.layout.len(), 1);
}

#[tokio::test]
async fn an_unsafe_recorded_layout_refuses_the_uninstall_and_runs_nothing() {
    for (name, value) in [
        ("FLEETD_STATE_DIR", "/etc"),
        ("FLEETD_STATE_DIR", "/var/lib/../../etc/x"),
        ("FLEETD_STATE_DIR", "/var/lib/fleetd\u{0}x"),
        ("FLEETD_UNIT_DIR", "units"),
        ("FLEETD_SERVICE", "fleetd;reboot"),
        ("FLEETD_SYSTEMCTL", "systemctl"),
    ] {
        let harness = Harness::new(Arc::new(Permit)).await;
        let machine = harness.machine("box", &["root@box.lan:22"]).await;
        let ssh = harness.endpoint(&machine, EndpointKind::Ssh).await;
        // Recorded before the install-time check existed.
        let payload = json!({
            "machineId": machine,
            "installerEnv": [[name, value]],
        })
        .to_string();
        sqlx::query(
            "INSERT INTO operations (id, kind, state, cancel_requested, created_at, updated_at, payload_json) \
             VALUES ('op-install', 'machine.install-fleetd', 'succeeded', 0, 1, 1, ?1)",
        )
        .bind(payload)
        .execute(&harness.pool)
        .await
        .unwrap();
        let (status, error) = harness
            .review(&machine, json!({ "uninstall": { "endpointId": ssh } }))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{name}={value}: {error}");
        let message = error["message"].as_str().unwrap();
        assert!(message.contains("not safe to uninstall with"), "{message}");
        assert!(message.contains(name), "{message}");
        assert!(harness.uninstall.seen.lock().unwrap().is_empty());
        // Without the uninstall the machine can still be removed.
        let token = harness.token(&machine, json!({})).await;
        let (status, _) = harness
            .remove(&machine, json!({ "reviewToken": token }))
            .await;
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn a_second_removal_of_the_same_machine_is_refused_while_one_runs() {
    let harness = Arc::new(Harness::new(Arc::new(Permit)).await);
    let machine = harness.machine("box", &["root@box.lan:22"]).await;
    let ssh = harness.endpoint(&machine, EndpointKind::Ssh).await;
    let body = json!({ "uninstall": { "endpointId": ssh } });
    let token = harness.token(&machine, body.clone()).await;
    let mut body = body;
    body["reviewToken"] = json!(token);
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    *harness.uninstall.pause.lock().unwrap() = Some((entered.clone(), release.clone()));

    let first = {
        let harness = harness.clone();
        let machine = machine.clone();
        let body = body.clone();
        tokio::spawn(async move { harness.remove(&machine, body).await })
    };
    entered.notified().await;
    let (status, error) = harness.remove(&machine, body).await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert_eq!(error["code"], "machine_removal_busy");
    assert_eq!(error["retry"], "backoff");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("already in progress"),
        "{error}"
    );
    release.notify_one();
    let (status, removed) = first.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(harness.uninstall.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_failed_delete_audit_does_not_stop_the_removal() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine("box", &["root@box.lan:22"]).await;
    let token = harness.token(&machine, json!({})).await;
    *harness.flaky.fail_event.lock().unwrap() = Some("machine_deleted");
    let (status, removed) = harness
        .remove(&machine, json!({ "reviewToken": token }))
        .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["data"]["auditGaps"], json!(["machine_deleted"]));
    assert!(!harness.exists(&machine).await);
    assert_eq!(harness.unpinned(), ["box.lan"]);
    assert_eq!(harness.keys.revoked.lock().unwrap().len(), 1);
    assert_eq!(harness.audit_events(&machine).await, ["machine_removed"]);
    let summary: String = sqlx::query_scalar(
        "SELECT metadata_json FROM audit_events WHERE resource = ?1 \
         AND json_extract(metadata_json, '$.event') = 'machine_removed'",
    )
    .bind(&machine)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    let summary: Value = serde_json::from_str(&summary).unwrap();
    assert_eq!(summary["auditGaps"], "machine_deleted");
}

#[tokio::test]
async fn a_usb_hold_taken_during_the_uninstall_refuses_the_delete() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine("box", &["root@box.lan:22"]).await;
    let ssh = harness.endpoint(&machine, EndpointKind::Ssh).await;
    let now = fleet_core::SystemClock::now_unix_millis();
    harness
        .hardware
        .upsert_device(
            &DeviceObservation {
                id: "device-1".to_owned(),
                account_id: ACCOUNT.to_owned(),
                mapping_id: "fm-test-reader-a".to_owned(),
                kind: HardwareKind::Usb,
                entries: vec![DeviceNodeEntry {
                    node: "pve".to_owned(),
                    vendor_id: "aaaa".to_owned(),
                    product_id: "0001".to_owned(),
                    usbpath: Some("1-1".to_owned()),
                    manufacturer: None,
                    product: None,
                    last_seen_at: now,
                }],
                status: DeviceStatus::Available,
                status_detail: None,
            },
            now,
        )
        .await
        .unwrap();
    let body = json!({ "uninstall": { "endpointId": ssh } });
    let token = harness.token(&machine, body.clone()).await;
    harness.uninstall.during.lock().unwrap().push(
        "INSERT INTO hardware_reservations (id, device_id, owner_kind, owner_id, state, created_at, updated_at) \
         VALUES ('reservation-late', 'device-1', 'machine', ?1, 'held', 1, 1)",
    );
    let mut body = body;
    body["reviewToken"] = json!(token);
    let (status, error) = harness.remove(&machine, body).await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert_eq!(error["code"], "conflict");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("USB reservation reservation-late"),
        "{error}"
    );
    assert!(harness.exists(&machine).await);
}
