//! The FM-301 project checkout surface: discovery starts a durable
//! operation with machine-scoped authorization, and recording observations
//! refuses remotes that do not match the project's identity.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::operation::Operations;
use fleet_application::operation::PortFailure;
use fleet_application::project::{NewProject, ProjectFilter, ProjectPort, Projects};
use fleet_core::{CheckoutFact, Project};
use std::sync::{Arc, Mutex};
use tower::ServiceExt as _;

/// A project port that answers one known project and records observations.
#[derive(Debug)]
struct FakeProjects {
    project: Mutex<Option<Project>>,
    checkouts: Mutex<Vec<CheckoutFact>>,
}

impl FakeProjects {
    fn with(project: Project) -> Arc<Self> {
        Arc::new(Self {
            project: Mutex::new(Some(project)),
            checkouts: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait::async_trait]
impl ProjectPort for FakeProjects {
    async fn create(&self, _project: &NewProject) -> Result<Project, PortFailure> {
        unimplemented!("the tests only observe")
    }
    async fn get(&self, _id: &str) -> Result<Project, PortFailure> {
        self.project
            .lock()
            .unwrap()
            .clone()
            .ok_or(PortFailure::NotFound {
                what: "project".to_owned(),
            })
    }
    async fn list(
        &self,
        _filter: &ProjectFilter,
        _limit: u32,
    ) -> Result<Vec<Project>, PortFailure> {
        Ok(self.project.lock().unwrap().iter().cloned().collect())
    }
    async fn update(
        &self,
        _id: &str,
        _name: &str,
        _description: &str,
    ) -> Result<Project, PortFailure> {
        unimplemented!("the tests only observe")
    }
    async fn delete(&self, _id: &str) -> Result<(), PortFailure> {
        unimplemented!("the tests only observe")
    }
    async fn record_checkout(&self, fact: &CheckoutFact) -> Result<(), PortFailure> {
        self.checkouts.lock().unwrap().push(fact.clone());
        Ok(())
    }
    async fn find_by_idempotency_key(&self, _key: &str) -> Result<Option<Project>, PortFailure> {
        Ok(None)
    }
    async fn find_by_remote(&self, _remote: &str) -> Result<Option<Project>, PortFailure> {
        Ok(None)
    }
    async fn checkouts(&self, _project_id: &str) -> Result<Vec<CheckoutFact>, PortFailure> {
        Ok(self.checkouts.lock().unwrap().clone())
    }
}

#[derive(Debug)]
struct PermitAll;
impl fleet_application::authz::Authorizer for PermitAll {
    fn decide(
        &self,
        _request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        fleet_application::authz::Decision::allow()
    }
}

#[derive(Debug)]
struct DenyDiscover;
impl fleet_application::authz::Authorizer for DenyDiscover {
    fn decide(
        &self,
        request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        if request.action == fleet_application::authz::Permission::ProjectsDiscover {
            fleet_application::authz::Decision::deny(
                fleet_application::authz::ReasonId::UnknownPrincipal,
            )
        } else {
            fleet_application::authz::Decision::allow()
        }
    }
}

#[derive(Debug)]
struct FakeAudit;
#[async_trait::async_trait]
impl fleet_application::operation::AuditPort for FakeAudit {
    async fn record_intent(
        &self,
        _intent: &fleet_application::audit::AuditIntent,
    ) -> Result<(), String> {
        Ok(())
    }
    async fn record_outcome(
        &self,
        _operation_id: &str,
        _outcome: fleet_application::audit::AuditOutcome,
    ) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug)]
struct FakeOperations;
#[async_trait::async_trait]
impl fleet_application::operation::OperationPort for FakeOperations {
    async fn create(
        &self,
        kind: &str,
        _idempotency_key: Option<&str>,
        _deadline_at: Option<i64>,
        correlation_id: Option<&str>,
        payload_json: Option<&str>,
    ) -> Result<fleet_application::operation::Operation, PortFailure> {
        Ok(fleet_application::operation::Operation {
            id: "op-1".to_owned(),
            kind: kind.to_owned(),
            state: "pending".to_owned(),
            idempotency_key: None,
            progress_current: None,
            progress_total: None,
            progress_message: None,
            deadline_at: None,
            cancel_requested: false,
            payload_json: payload_json.map(str::to_owned),
            result_json: None,
            error_json: None,
            correlation_id: correlation_id.map(str::to_owned),
            claimed_at: None,
            worker_id: None,
            created_at: 0,
            updated_at: 0,
        })
    }
    async fn get(&self, _id: &str) -> Result<fleet_application::operation::Operation, PortFailure> {
        unimplemented!()
    }
    async fn list(
        &self,
        _limit: u32,
    ) -> Result<Vec<fleet_application::operation::Operation>, PortFailure> {
        unimplemented!()
    }
    async fn request_cancel(
        &self,
        _id: &str,
    ) -> Result<fleet_application::operation::Operation, PortFailure> {
        unimplemented!()
    }
    async fn transition(
        &self,
        _id: &str,
        _state: &str,
    ) -> Result<fleet_application::operation::Operation, PortFailure> {
        unimplemented!()
    }
    async fn complete(
        &self,
        _id: &str,
        _state: &str,
        _result_json: Option<&str>,
        _error_json: Option<&str>,
    ) -> Result<fleet_application::operation::Operation, PortFailure> {
        unimplemented!()
    }
    async fn record_progress(
        &self,
        _id: &str,
        _current: Option<i64>,
        _total: Option<i64>,
        _message: Option<&str>,
    ) -> Result<(), PortFailure> {
        unimplemented!()
    }
    async fn claim_pending(
        &self,
        _worker_id: &str,
        _now: i64,
    ) -> Result<Option<fleet_application::operation::Operation>, PortFailure> {
        unimplemented!()
    }
    async fn claim_pending_by_id(
        &self,
        _id: &str,
        _worker_id: &str,
        _now: i64,
    ) -> Result<Option<fleet_application::operation::Operation>, PortFailure> {
        unimplemented!()
    }
    async fn expired_claims(
        &self,
        _now: i64,
        _lease_ms: i64,
    ) -> Result<Vec<fleet_application::operation::Operation>, PortFailure> {
        unimplemented!()
    }
    async fn renew_lease(
        &self,
        _id: &str,
        _worker_id: &str,
        _now: i64,
        _lease_ms: i64,
    ) -> Result<bool, PortFailure> {
        unimplemented!()
    }
    async fn fail_expired_claim(
        &self,
        _id: &str,
        _expected_claimed_at: i64,
        _now: i64,
        _error_json: &str,
    ) -> Result<bool, PortFailure> {
        unimplemented!()
    }
    async fn sweep_deadlines(&self, _now: i64) -> Result<Vec<String>, PortFailure> {
        unimplemented!()
    }
    async fn queue_depths(&self) -> Result<fleet_application::operation::QueueDepths, PortFailure> {
        unimplemented!()
    }
}

fn project() -> Project {
    let remote =
        fleet_core::NormalizedRemote::parse("https://github.com/Frogbyte-io/fleet-manager.git")
            .unwrap();
    Project {
        id: "p-1".to_owned(),
        remote: remote.as_str().to_owned(),
        name: "fleet-manager".to_owned(),
        description: String::new(),
        created_at: 0,
        updated_at: 0,
    }
}

fn state_for(
    projects: Option<Arc<Projects>>,
    authorizer: Arc<dyn fleet_application::authz::Authorizer>,
) -> Arc<ApiState> {
    Arc::new(ApiState {
        operations: Arc::new(Operations::new(
            Arc::new(FakeOperations),
            Arc::new(FakeAudit),
        )),
        authorizer,
        system: Arc::new(FakeSystemInfo),
        nodes: None,
        machines: None,
        onboarding: None,
        tailnet: None,
        projects,
        proxmox: None,
        images: None,
        lab: None,
    })
}

#[derive(Debug)]
struct FakeSystemInfo;
#[async_trait::async_trait]
impl fleet_api::system::SystemInfoSource for FakeSystemInfo {
    async fn info(&self) -> Result<fleet_api::system::SystemInfo, String> {
        unimplemented!("the tests never read the system surface")
    }
}

async fn call(
    state: Arc<ApiState>,
    method: &str,
    path: &str,
    body: Option<String>,
) -> (StatusCode, serde_json::Value) {
    let router = router(state).layer(axum::Extension(fleet_api::ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }));
    let request = Request::builder()
        .method(method)
        .uri(format!("{API_BASE_PATH}{path}"))
        .header(
            CORRELATION_ID_HEADER,
            "01900000-0000-7000-8000-000000000000",
        );
    let request = if let Some(body) = body {
        request
            .header("content-type", "application/json")
            .body(Body::from(body))
    } else {
        request.body(Body::empty())
    }
    .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[tokio::test]
async fn discovery_starts_a_durable_operation_with_machine_scoped_authorization() {
    let port = FakeProjects::with(project());
    let projects = Arc::new(Projects::new(port.clone(), Arc::new(FakeAudit)));
    let state = state_for(Some(projects), Arc::new(PermitAll));
    let body = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "timeoutSeconds": 60,
    })
    .to_string();
    let (status, value) = call(state, "POST", "/projects/p-1/discoveries", Some(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    assert_eq!(value["data"]["kind"], "projects.discover");
    assert_eq!(value["data"]["state"], "pending");
}

#[tokio::test]
async fn discovery_denial_is_a_machine_scoped_403() {
    let port = FakeProjects::with(project());
    let projects = Arc::new(Projects::new(port.clone(), Arc::new(FakeAudit)));
    let state = state_for(Some(projects), Arc::new(DenyDiscover));
    let body = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "timeoutSeconds": 60,
    })
    .to_string();
    let (status, value) = call(state, "POST", "/projects/p-1/discoveries", Some(body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{value}");
    assert_eq!(value["code"], "denied");
}

#[tokio::test]
async fn recording_observations_refuses_a_mismatched_remote() {
    let port = FakeProjects::with(project());
    let projects = Arc::new(Projects::new(port.clone(), Arc::new(FakeAudit)));
    let state = state_for(Some(projects), Arc::new(PermitAll));
    let body = serde_json::json!({
        "machineId": "m-1",
        "checkouts": [
            {"root": "/home/dev/other", "branch": "main", "head": "abc", "dirty": false,
             "remote": "https://github.com/Frogbyte-io/other.git", "status": "known"}
        ],
    })
    .to_string();
    let (status, value) = call(state, "POST", "/projects/p-1/checkouts", Some(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
    assert!(
        value["message"]
            .as_str()
            .unwrap()
            .contains("is not this project"),
        "{value}"
    );
    assert!(
        port.checkouts.lock().unwrap().is_empty(),
        "a refused batch records nothing"
    );
}

#[tokio::test]
async fn recording_matching_observations_stores_the_facts() {
    let port = FakeProjects::with(project());
    let projects = Arc::new(Projects::new(port.clone(), Arc::new(FakeAudit)));
    let state = state_for(Some(projects), Arc::new(PermitAll));
    let body = serde_json::json!({
        "machineId": "m-1",
        "checkouts": [
            {"root": "/home/dev/code/fleet-manager", "branch": "main", "head": "abc",
             "dirty": false,
             "remote": "git@github.com:Frogbyte-io/fleet-manager.git", "status": "known"},
            {"root": "/srv/broken", "status": "unavailable"}
        ],
    })
    .to_string();
    let (status, value) = call(state, "POST", "/projects/p-1/checkouts", Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let checkouts = port.checkouts.lock().unwrap();
    assert_eq!(checkouts.len(), 2);
    assert_eq!(checkouts[0].machine_id, "m-1");
    assert_eq!(checkouts[0].source, "checkout-discovery/1");
    assert_eq!(
        checkouts[1].branch, None,
        "the unreadable checkout is honest"
    );
}

#[tokio::test]
async fn the_unwired_surface_answers_the_standard_envelope() {
    let state = state_for(None, Arc::new(PermitAll));
    let body = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "timeoutSeconds": 60,
    })
    .to_string();
    let (status, value) = call(state, "POST", "/projects/p-1/discoveries", Some(body)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{value}");
    assert_eq!(value["code"], "project_unavailable");
}
