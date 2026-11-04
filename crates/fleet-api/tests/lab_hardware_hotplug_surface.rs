//! FM-1126: `POST /lab/leases/{id}/hardware/attach` and `.../detach`. The
//! routes are adapters: authorization (the lease-bound catalog entries and
//! the owner scope), the lease checks and the error mapping are exercised
//! here with the real SQLite repositories and the real router; the saga
//! behind the port is the controller's (`fleet-controller`'s
//! `lab_hardware_hotplug` tests), so the port is scripted.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::lab::{
    ImagePinValidator, Lab, LabTemplate, LabTemplatePort, LabTemplateVersion, LeasePort,
    NewLabTemplate, NewLease, NewProvision, ProvisionPort,
};
use fleet_application::lab_hardware_hotplug::{
    HotplugAction, HotplugError, HotplugOutcome, HotplugPort, HotplugRequest, HotplugResult,
    LabHardwareHotplug,
};
use fleet_application::operation::Operations;
use fleet_core::{
    CleanupStrategy, HardwareReservationState, LabTemplateContent, LeaseState, ReadinessProbe,
};
use fleet_storage_sqlite::{
    AuditSink, LabRepository, LeaseRepository, OperationRepository, ProjectRepository, Store,
};
use tower::ServiceExt as _;

const MAPPING: &str = "fm-test-reader-a";

#[derive(Debug)]
struct Permit;
impl Authorizer for Permit {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

/// Denies one permission, allows the rest.
#[derive(Debug)]
struct Without(Permission);
impl Authorizer for Without {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.action == self.0 {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

#[derive(Debug)]
struct NoPins;
#[async_trait]
impl ImagePinValidator for NoPins {
    async fn promoted_version(
        &self,
        _version_id: &str,
    ) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok(None)
    }
}

/// A port that answers what the test scripted and remembers what it was asked.
#[derive(Debug)]
struct Scripted {
    answer: Mutex<Result<HotplugOutcome, HotplugError>>,
    seen: Mutex<Vec<HotplugRequest>>,
}

impl Scripted {
    fn new(answer: Result<HotplugOutcome, HotplugError>) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(answer),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<HotplugRequest> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait]
impl HotplugPort for Scripted {
    async fn carry_out(&self, request: &HotplugRequest) -> Result<HotplugOutcome, HotplugError> {
        self.seen.lock().unwrap().push(request.clone());
        self.answer.lock().unwrap().clone()
    }
}

fn outcome(result: HotplugResult, state: HardwareReservationState) -> HotplugOutcome {
    HotplugOutcome {
        lease_id: "ignored".to_owned(),
        mapping_id: MAPPING.to_owned(),
        result,
        reservation_id: "reservation-1".to_owned(),
        reservation_state: state,
        usb_slot: matches!(
            state,
            HardwareReservationState::Attached | HardwareReservationState::Detaching
        )
        .then_some(1),
        released: state == HardwareReservationState::Released,
    }
}

struct World {
    _dir: tempfile::TempDir,
    leases: Arc<LeaseRepository>,
    labs: Arc<LabRepository>,
    audit: Arc<AuditSink>,
    projects: Arc<ProjectRepository>,
    operations: Arc<OperationRepository>,
    version_id: String,
}

impl World {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        // The pool outlives the store handle for the test's duration.
        std::mem::forget(store);
        let now = fleet_core::SystemClock::now_unix_millis();
        let labs = Arc::new(LabRepository::new(pool.clone()));
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
            interactive_user: None,
            hardware: Vec::new(),
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
        Self {
            _dir: dir,
            leases: Arc::new(LeaseRepository::new(pool.clone())),
            labs,
            audit: Arc::new(AuditSink::new(pool.clone())),
            projects: Arc::new(ProjectRepository::new(pool.clone())),
            operations: Arc::new(OperationRepository::new(pool)),
            version_id: version.id,
        }
    }

    /// A ready lease owned by `owner`, whose guest is recorded.
    async fn lease(&self, owner: &str, state: LeaseState, guest_recorded: bool) -> String {
        let now = fleet_core::SystemClock::now_unix_millis();
        let lease = self
            .leases
            .create(
                &NewLease {
                    template_version_id: self.version_id.clone(),
                    purpose: "hotplug".to_owned(),
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
                template_version_id: self.version_id.clone(),
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
        if guest_recorded {
            record.account_id = Some("account-1".to_owned());
            record.node = Some("pve-a".to_owned());
            record.vmid = Some(9100);
            ProvisionPort::update(self.labs.as_ref(), &record)
                .await
                .unwrap();
        }
        let mut leased = self.leases.get(&lease.id).await.unwrap();
        leased.state = state;
        leased.ready_at = Some(now);
        leased.expires_at = Some(now + 3_600_000);
        self.leases.update(&leased).await.unwrap();
        lease.id
    }

    fn state(&self, authorizer: Arc<dyn Authorizer>, port: Option<Arc<Scripted>>) -> Arc<ApiState> {
        let audit = self.audit.clone();
        let mut lab = Lab::new(
            self.labs.clone(),
            self.labs.clone(),
            self.leases.clone(),
            Arc::new(NoPins),
            self.projects.clone(),
            audit.clone(),
        );
        if let Some(port) = port {
            lab = lab.with_hotplug(Arc::new(LabHardwareHotplug::new(
                self.leases.clone(),
                self.labs.clone(),
                port,
            )));
        }
        Arc::new(ApiState {
            authorizer,
            operations: Arc::new(Operations::new(self.operations.clone(), audit)),
            lab: Some(Arc::new(lab)),
            ..ApiState::for_document()
        })
    }
}

async fn post(
    state: &Arc<ApiState>,
    principal: &str,
    path: &str,
    body: &str,
) -> (StatusCode, serde_json::Value) {
    let router = router(state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
        id: principal.to_owned(),
    }));
    let request = Request::builder()
        .method("POST")
        .uri(format!("{API_BASE_PATH}{path}"))
        .header("content-type", "application/json")
        .header(
            CORRELATION_ID_HEADER,
            "01900000-0000-7000-8000-000000000000",
        )
        .body(Body::from(body.to_owned()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn attach_path(lease: &str) -> String {
    format!("/lab/leases/{lease}/hardware/attach")
}

fn detach_path(lease: &str) -> String {
    format!("/lab/leases/{lease}/hardware/detach")
}

fn body(mapping: &str) -> String {
    serde_json::json!({ "mapping": mapping }).to_string()
}

#[tokio::test]
async fn an_attach_answers_what_the_guest_has_and_hands_the_port_the_leases_guest() {
    let world = World::new().await;
    let lease = world.lease("tester", LeaseState::Ready, true).await;
    let port = Scripted::new(Ok(outcome(
        HotplugResult::Attached,
        HardwareReservationState::Attached,
    )));
    let state = world.state(Arc::new(Permit), Some(port.clone()));

    let (status, answer) = post(&state, "tester", &attach_path(&lease), &body(MAPPING)).await;

    assert_eq!(status, StatusCode::OK, "{answer}");
    let data = &answer["data"];
    assert_eq!(data["outcome"], "attached");
    assert_eq!(data["onGuest"], true);
    assert_eq!(data["reservationState"], "attached");
    assert_eq!(data["usbSlot"], "usb1");
    assert_eq!(data["released"], false);
    assert_eq!(data["mapping"], MAPPING);
    let seen = port.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].principal_id, "tester");
    assert_eq!(seen[0].lease_id, lease);
    assert_eq!(seen[0].mapping_id, MAPPING);
    assert_eq!(seen[0].guest.account_id, "account-1");
    assert_eq!(seen[0].guest.node, "pve-a");
    assert_eq!(seen[0].guest.vmid, 9100);
    assert_eq!(seen[0].action, HotplugAction::Attach);
}

#[tokio::test]
async fn a_detach_forwards_the_release_flag_and_a_pending_removal_is_accepted_not_done() {
    let world = World::new().await;
    let lease = world.lease("tester", LeaseState::Ready, true).await;
    let port = Scripted::new(Ok(outcome(
        HotplugResult::Detached,
        HardwareReservationState::Released,
    )));
    let state = world.state(Arc::new(Permit), Some(port.clone()));

    let released = serde_json::json!({ "mapping": MAPPING, "release": true }).to_string();
    let (status, answer) = post(&state, "tester", &detach_path(&lease), &released).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["data"]["outcome"], "detached");
    assert_eq!(answer["data"]["onGuest"], false);
    assert_eq!(answer["data"]["released"], true);
    // The default keeps the device reserved by the lease.
    let (status, _) = post(&state, "tester", &detach_path(&lease), &body(MAPPING)).await;
    assert_eq!(status, StatusCode::OK);
    let seen = port.seen();
    assert_eq!(seen[0].action, HotplugAction::Detach { release: true });
    assert_eq!(seen[1].action, HotplugAction::Detach { release: false });

    // A removal PVE keeps pending: 202, and the device is still on the guest.
    *port.answer.lock().unwrap() = Ok(outcome(
        HotplugResult::DetachPending,
        HardwareReservationState::Detaching,
    ));
    let (status, answer) = post(&state, "tester", &detach_path(&lease), &body(MAPPING)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{answer}");
    assert_eq!(answer["data"]["outcome"], "detach_pending");
    assert_eq!(answer["data"]["onGuest"], true);
    assert_eq!(answer["data"]["reservationState"], "detaching");
}

#[tokio::test]
async fn a_refusal_carries_its_reason_as_the_error_code() {
    let world = World::new().await;
    let lease = world.lease("tester", LeaseState::Ready, true).await;
    let port = Scripted::new(Err(HotplugError::refused(
        "hardware_attach_pending",
        "PVE would keep the attach pending until the guest restarts",
    )));
    let state = world.state(Arc::new(Permit), Some(port.clone()));

    let (status, answer) = post(&state, "tester", &attach_path(&lease), &body(MAPPING)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "hardware_attach_pending");
    assert!(
        answer["message"]
            .as_str()
            .unwrap()
            .contains("pending until the guest restarts")
    );

    *port.answer.lock().unwrap() = Err(HotplugError::refused(
        "hardware_not_reserved",
        "not a device this lease reserved",
    ));
    let (status, answer) = post(&state, "tester", &detach_path(&lease), &body(MAPPING)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(answer["code"], "hardware_not_reserved");

    // A failure of a backend is not shown.
    *port.answer.lock().unwrap() = Err(HotplugError::Backend {
        detail: "sqlite said something private".to_owned(),
    });
    let (status, answer) = post(&state, "tester", &attach_path(&lease), &body(MAPPING)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!answer.to_string().contains("private"), "{answer}");
}

#[tokio::test]
async fn only_the_lease_holder_or_an_administrator_reaches_the_port() {
    let world = World::new().await;
    let lease = world
        .lease("credential:ci-a", LeaseState::Ready, true)
        .await;
    let port = Scripted::new(Ok(outcome(
        HotplugResult::Detached,
        HardwareReservationState::Held,
    )));
    let authorizer: Arc<dyn Authorizer> = Arc::new(fleet_auth::delegated::ScopedAuthorizer::new(
        Arc::new(fleet_application::credentials::GrantBook::new()),
    ));
    let state = world.state(authorizer, Some(port.clone()));

    // Another owner's credential does not even find the lease.
    for path in [attach_path(&lease), detach_path(&lease)] {
        let (status, answer) = post(&state, "credential:ci-b:cred-1", &path, &body(MAPPING)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
        assert_eq!(answer["code"], "not_found");
    }
    assert!(port.seen().is_empty(), "the port was never reached");
    // The holder's credential (another token of the same owner), and an
    // administrator, do.
    for principal in ["credential:ci-a:cred-2", "tailscale:alice@example.com"] {
        let (status, answer) = post(&state, principal, &detach_path(&lease), &body(MAPPING)).await;
        assert_eq!(status, StatusCode::OK, "{principal}: {answer}");
    }
    assert_eq!(port.seen().len(), 2);

    // A caller the catalog does not allow is refused before the lease is
    // read: 403, whoever owns the lease.
    for (denied, path) in [
        (Permission::LabHardwareAttach, attach_path(&lease)),
        (Permission::LabHardwareDetach, detach_path(&lease)),
    ] {
        let state = world.state(Arc::new(Without(denied)), Some(port.clone()));
        let (status, answer) = post(&state, "tester", &path, &body(MAPPING)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{denied}: {answer}");
        assert_eq!(answer["code"], "denied");
    }
    // Attach is not authorized by the detach entry, nor the reverse.
    let state = world.state(
        Arc::new(Without(Permission::LabHardwareDetach)),
        Some(port.clone()),
    );
    let (status, _) = post(&state, "tester", &attach_path(&lease), &body(MAPPING)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(port.seen().len(), 3);
}

#[tokio::test]
async fn the_lease_must_be_ready_and_know_its_guest_and_the_request_must_be_well_formed() {
    let world = World::new().await;
    let port = Scripted::new(Ok(outcome(
        HotplugResult::Attached,
        HardwareReservationState::Attached,
    )));
    let state = world.state(Arc::new(Permit), Some(port.clone()));

    let releasing = world.lease("tester", LeaseState::Releasing, true).await;
    let (status, answer) = post(&state, "tester", &attach_path(&releasing), &body(MAPPING)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(answer["code"], "lease_not_ready");

    let no_guest = world.lease("tester", LeaseState::Ready, false).await;
    let (status, answer) = post(&state, "tester", &detach_path(&no_guest), &body(MAPPING)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(answer["code"], "lease_has_no_guest");

    let ready = world.lease("tester", LeaseState::Ready, true).await;
    let (status, answer) = post(
        &state,
        "tester",
        &attach_path("no-such-lease"),
        &body(MAPPING),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    for bad in ["", "1abc", "a,host=1-7", "a b"] {
        let (status, answer) = post(&state, "tester", &attach_path(&ready), &body(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?}: {answer}");
        assert_eq!(answer["code"], "invalid_request");
    }
    for malformed in [
        "not json",
        "{}",
        r#"{"mapping":"a","host":"1-7"}"#,
        r#"{"mapping":5}"#,
    ] {
        let (status, answer) = post(&state, "tester", &attach_path(&ready), malformed).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{malformed:?}: {answer}");
    }
    assert!(port.seen().is_empty(), "nothing malformed reached the port");
}

#[tokio::test]
async fn a_controller_without_hotplug_answers_unavailable() {
    let world = World::new().await;
    let lease = world.lease("tester", LeaseState::Ready, true).await;
    let state = world.state(Arc::new(Permit), None);
    let (status, answer) = post(&state, "tester", &attach_path(&lease), &body(MAPPING)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    assert_eq!(answer["code"], "machine_unavailable");
}
