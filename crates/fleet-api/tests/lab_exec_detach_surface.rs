//! #394: `POST /lab/leases/{id}/exec-detached` and
//! `GET /lab/detached-execs/{handle}`. Real SQLite repositories behind the
//! real router; the guest is a stub that answers canned process states.

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
use fleet_application::lab_exec_detach::{
    DetachedExecPort as _, GuestExecPort, GuestProcess, GuestProcessState, LabExecDetach,
};
use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::operation::Operations;
use fleet_core::{CleanupStrategy, LabTemplateContent, LeaseState, ReadinessProbe};
use fleet_storage_sqlite::{
    AuditSink, DetachedExecRepository, LabRepository, LeaseRepository, MachineRepository,
    OperationRepository, ProjectRepository, Store,
};
use tower::ServiceExt as _;

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

/// Answers whatever the test set.
#[derive(Debug)]
struct Guest {
    answer: Mutex<Result<GuestProcess, String>>,
}

#[async_trait]
impl GuestExecPort for Guest {
    async fn probe(&self, _: &str, _: &str, _: &str) -> Result<GuestProcess, String> {
        self.answer.lock().unwrap().clone()
    }
}

fn process(state: GuestProcessState) -> GuestProcess {
    GuestProcess {
        state,
        reason: None,
        exit_code: None,
        started_at: Some(100),
        finished_at: None,
        stdout_bytes: 0,
        stderr_bytes: 0,
        stdout_tail: Vec::new(),
        stderr_tail: Vec::new(),
    }
}

struct World {
    _dir: tempfile::TempDir,
    records: Arc<DetachedExecRepository>,
    guest: Arc<Guest>,
    leases: Arc<LeaseRepository>,
    lab: Arc<Lab>,
    operations: Arc<Operations>,
    lease_id: String,
}

impl World {
    #[allow(clippy::too_many_lines)]
    async fn new() -> Self {
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
                "anonymous-lan-admin",
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

        let guest = Arc::new(Guest {
            answer: Mutex::new(Ok(process(GuestProcessState::Running))),
        });
        let audit = Arc::new(AuditSink::new(pool.clone()));
        let records = Arc::new(DetachedExecRepository::new(pool.clone()));
        let detached = Arc::new(LabExecDetach::new(
            records.clone(),
            guest.clone(),
            leases.clone(),
            labs.clone(),
            audit.clone(),
        ));
        let lab = Lab::new(
            labs.clone(),
            labs.clone(),
            leases.clone(),
            Arc::new(NoPins),
            Arc::new(ProjectRepository::new(pool.clone())),
            audit.clone(),
        )
        .with_detached(detached);
        Self {
            operations: Arc::new(Operations::new(
                Arc::new(OperationRepository::new(pool.clone())),
                audit,
            )),
            lab: Arc::new(lab),
            lease_id: lease.id,
            leases,
            guest,
            records,
            _dir: dir,
        }
    }

    fn state(&self, authorizer: Arc<dyn Authorizer>) -> Arc<ApiState> {
        Arc::new(ApiState {
            authorizer,
            operations: self.operations.clone(),
            lab: Some(self.lab.clone()),
            ..ApiState::for_document()
        })
    }
}

async fn call(
    state: &Arc<ApiState>,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let router = router(state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }));
    let mut request = Request::builder()
        .method(method)
        .uri(format!("{API_BASE_PATH}{path}"))
        .header("content-type", "application/json")
        .header(
            CORRELATION_ID_HEADER,
            "01900000-0000-7000-8000-000000000000",
        );
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    let body = body.map_or_else(Body::empty, |value| Body::from(value.to_string()));
    let response = router.oneshot(request.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn start_returns_a_handle_and_a_keyed_retry_returns_the_same_one() {
    let world = World::new().await;
    let state = world.state(Arc::new(Permit));
    let path = format!("/lab/leases/{}/exec-detached", world.lease_id);
    let request = serde_json::json!({"script": "echo SCRIPT-MARKER", "timeoutSeconds": 1_800});
    let (status, body) = call(&state, "POST", &path, Some("run-1"), Some(request.clone())).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let data = &body["data"];
    let handle = data["handle"].as_str().unwrap().to_owned();
    assert_eq!(data["leaseId"], world.lease_id.as_str());
    assert_eq!(data["timeoutSeconds"], 1_800);
    assert_eq!(data["operation"]["id"], handle.as_str());
    assert_eq!(data["operation"]["kind"], "lab.exec_detach");
    assert!(!body.to_string().contains("SCRIPT-MARKER"));

    let (status, again) = call(&state, "POST", &path, Some("run-1"), Some(request.clone())).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{again}");
    assert_eq!(again["data"]["handle"], handle.as_str());
    // Another key is another command.
    let (_, other) = call(&state, "POST", &path, Some("run-2"), Some(request)).await;
    assert_ne!(other["data"]["handle"], handle.as_str());

    let record = world.records.get(&handle).await.unwrap().unwrap();
    assert_eq!(record.command_sha256.len(), 64);
    assert_eq!(record.command_bytes, "echo SCRIPT-MARKER".len() as u64);
    assert!(
        world
            .records
            .get(other["data"]["handle"].as_str().unwrap())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn status_reports_each_state_and_a_released_lease_is_a_terminal_answer() {
    let world = World::new().await;
    let state = world.state(Arc::new(Permit));
    let (_, started) = call(
        &state,
        "POST",
        &format!("/lab/leases/{}/exec-detached", world.lease_id),
        None,
        Some(serde_json::json!({"script": "true"})),
    )
    .await;
    let handle = started["data"]["handle"].as_str().unwrap().to_owned();
    let path = format!("/lab/detached-execs/{handle}");

    let (status, body) = call(&state, "GET", &path, None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["state"], "running");
    assert_eq!(body["data"]["terminal"], false);

    *world.guest.answer.lock().unwrap() = Ok(GuestProcess {
        exit_code: Some(3),
        finished_at: Some(160),
        stdout_bytes: 40,
        stdout_tail: b"cloned https://user:hunter2pw@host.invalid/r\n".to_vec(),
        ..process(GuestProcessState::Exited)
    });
    let (_, body) = call(&state, "GET", &path, None, None).await;
    assert_eq!(body["data"]["state"], "exited");
    assert_eq!(body["data"]["terminal"], true);
    assert_eq!(body["data"]["exitCode"], 3);
    assert!(!body.to_string().contains("hunter2"), "{body}");

    *world.guest.answer.lock().unwrap() = Ok(GuestProcess {
        reason: Some("process_gone".to_owned()),
        ..process(GuestProcessState::Lost)
    });
    let (_, body) = call(&state, "GET", &path, None, None).await;
    assert_eq!(body["data"]["state"], "lost");
    assert_eq!(body["data"]["reason"], "process_gone");
    assert_eq!(body["data"]["terminal"], true);

    // An unreadable guest is an answer to poll again, not an error.
    *world.guest.answer.lock().unwrap() = Err("ssh: connection refused".to_owned());
    let (status, body) = call(&state, "GET", &path, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["state"], "unreachable");
    assert_eq!(body["data"]["terminal"], false);
    assert!(!body.to_string().contains("refused"), "{body}");

    // Release: a terminal answer, not an SSH error.
    let mut lease = world.leases.get(&world.lease_id).await.unwrap();
    lease.state = LeaseState::Released;
    world.leases.update(&lease).await.unwrap();
    let (status, body) = call(&state, "GET", &path, None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["state"], "lease_ended");
    assert_eq!(body["data"]["terminal"], true);
    assert_eq!(body["data"]["leaseState"], "released");
}

#[tokio::test]
async fn refusals_use_the_public_error_envelope() {
    let world = World::new().await;
    let state = world.state(Arc::new(Permit));
    let path = format!("/lab/leases/{}/exec-detached", world.lease_id);
    let (status, _) = call(&state, "GET", "/lab/detached-execs/nothing", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(&state, "GET", "/lab/detached-execs/a%20b", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &state,
        "POST",
        "/lab/leases/missing/exec-detached",
        None,
        Some(serde_json::json!({"script": "true"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    for body in [
        serde_json::json!({"script": ""}),
        serde_json::json!({"script": "true", "timeoutSeconds": 0}),
        serde_json::json!({"nothing": 1}),
    ] {
        let (status, _) = call(&state, "POST", &path, None, Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    // The generic operation route cannot queue the kind.
    let (status, _) = call(
        &state,
        "POST",
        "/operations",
        None,
        Some(serde_json::json!({"kind": "lab.exec_detach", "payload": {}})),
    )
    .await;
    assert!(status.is_client_error(), "{status}");

    // A denied caller gets 403 and nothing is queued or recorded.
    let denied = world.state(Arc::new(Without(Permission::LabExec)));
    let (status, _) = call(
        &denied,
        "POST",
        &path,
        None,
        Some(serde_json::json!({"script": "true"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, started) = call(
        &state,
        "POST",
        &path,
        None,
        Some(serde_json::json!({"script": "true"})),
    )
    .await;
    let handle = started["data"]["handle"].as_str().unwrap();
    let denied = world.state(Arc::new(Without(Permission::LabExecRead)));
    let (status, _) = call(
        &denied,
        "GET",
        &format!("/lab/detached-execs/{handle}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
