//! The Frogenv surface (FM-303): actions authorize machine-scoped, the
//! machine must exist, env run requires its root and command, and the
//! generic /operations surface enforces the same catalog entry.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::machine::{
    Endpoint, Machine, MachineFilter, MachinePort, NewEndpoint, RegisterMachine,
};
use fleet_application::operation::Operations;
use fleet_application::operation::PortFailure;
use fleet_core::EndpointKind;
use std::sync::{Arc, Mutex};
use tower::ServiceExt as _;

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

#[derive(Debug, Default)]
struct Recording {
    resources: Mutex<Vec<(String, Option<String>)>>,
}
impl fleet_application::authz::Authorizer for Recording {
    fn decide(
        &self,
        request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        self.resources.lock().unwrap().push((
            request.action.id().to_owned(),
            request.resource.map(str::to_owned),
        ));
        fleet_application::authz::Decision::allow()
    }
}

#[derive(Debug)]
struct DenyFrogenv;
impl fleet_application::authz::Authorizer for DenyFrogenv {
    fn decide(
        &self,
        request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        if matches!(
            request.action,
            fleet_application::authz::Permission::FrogenvRead
                | fleet_application::authz::Permission::FrogenvOperate
        ) {
            fleet_application::authz::Decision::deny(
                fleet_application::authz::ReasonId::UnknownPrincipal,
            )
        } else {
            fleet_application::authz::Decision::allow()
        }
    }
}

#[derive(Debug, Default)]
struct FakeOperations {
    payloads: Mutex<Vec<String>>,
}

impl FakeOperations {
    fn payloads(&self) -> Vec<String> {
        self.payloads.lock().unwrap().clone()
    }
}

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
        self.payloads
            .lock()
            .unwrap()
            .push(payload_json.unwrap_or_default().to_owned());
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
struct FakeMachines;

#[async_trait::async_trait]
impl MachinePort for FakeMachines {
    async fn register(&self, _registration: &RegisterMachine) -> Result<Machine, PortFailure> {
        unimplemented!()
    }
    async fn get(&self, id: &str) -> Result<Machine, PortFailure> {
        if id != "m-1" {
            return Err(PortFailure::NotFound {
                what: "machine".to_owned(),
            });
        }
        Ok(Machine {
            id: id.to_owned(),
            name: "box".to_owned(),
            description: String::new(),
            endpoints: vec![Endpoint {
                id: "e-1".to_owned(),
                kind: EndpointKind::Ssh,
                reference: "user@host:22".to_owned(),
            }],
            tags: vec![],
            groups: vec![],
            capabilities: vec![],
            last_observation: None,
            node: None,
            created_at: 0,
            updated_at: 0,
        })
    }
    async fn list(
        &self,
        _filter: &MachineFilter,
        _limit: u32,
    ) -> Result<Vec<Machine>, PortFailure> {
        unimplemented!()
    }
    async fn update(
        &self,
        _id: &str,
        _name: &str,
        _description: &str,
    ) -> Result<Machine, PortFailure> {
        unimplemented!()
    }
    async fn set_endpoints(
        &self,
        _id: &str,
        _endpoints: &[NewEndpoint],
    ) -> Result<Machine, PortFailure> {
        unimplemented!()
    }
    async fn add_tag(&self, _id: &str, _tag: &str) -> Result<Machine, PortFailure> {
        unimplemented!()
    }
    async fn remove_tag(&self, _id: &str, _tag: &str) -> Result<Machine, PortFailure> {
        unimplemented!()
    }
    async fn add_group(&self, _id: &str, _group: &str) -> Result<Machine, PortFailure> {
        unimplemented!()
    }
    async fn remove_group(&self, _id: &str, _group: &str) -> Result<Machine, PortFailure> {
        unimplemented!()
    }
    async fn record_snapshot(
        &self,
        _id: &str,
        _source: &str,
        _payload_json: &str,
        _collected_at: i64,
    ) -> Result<(), PortFailure> {
        unimplemented!()
    }
    async fn record_capabilities(
        &self,
        _id: &str,
        _facts: &[fleet_core::CapabilityFact],
    ) -> Result<(), PortFailure> {
        unimplemented!()
    }
    async fn delete(&self, _id: &str) -> Result<(), PortFailure> {
        unimplemented!()
    }
    async fn confirm_fingerprint(
        &self,
        _endpoint_id: &str,
        _fingerprint: &str,
        _confirmed_at: i64,
    ) -> Result<(), PortFailure> {
        unimplemented!()
    }
    async fn verified_fingerprint(
        &self,
        _endpoint_id: &str,
    ) -> Result<Option<String>, PortFailure> {
        Ok(None)
    }
    async fn latest_inventory_revision(&self, _id: &str) -> Result<Option<u64>, PortFailure> {
        Ok(None)
    }
}

#[derive(Debug)]
struct FakeSystemInfo;
#[async_trait::async_trait]
impl fleet_api::system::SystemInfoSource for FakeSystemInfo {
    async fn info(&self) -> Result<fleet_api::system::SystemInfo, String> {
        unimplemented!("the tests never read the system surface")
    }
}

fn state_for(authorizer: Arc<dyn fleet_application::authz::Authorizer>) -> Arc<ApiState> {
    Arc::new(ApiState {
        operations: Arc::new(Operations::new(
            Arc::new(FakeOperations::default()),
            Arc::new(FakeAudit),
        )),
        authorizer,
        system: Arc::new(FakeSystemInfo),
        nodes: None,
        machines: Some(Arc::new(fleet_application::machine::Machines::new(
            Arc::new(FakeMachines),
            Arc::new(FakeAudit),
        ))),
        onboarding: None,
        tailnet: None,
        projects: None,
    })
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

fn body_for(action: &str) -> serde_json::Value {
    serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "action": action,
        "timeoutSeconds": 30,
    })
}

#[tokio::test]
async fn each_action_starts_its_own_kind() {
    for (action, kind) in [
        ("status", "frogenv.status"),
        ("setup", "frogenv.setup"),
        ("login", "frogenv.login"),
        ("request", "frogenv.request"),
        ("sync", "frogenv.sync"),
    ] {
        let state = state_for(Arc::new(PermitAll));
        let (status, value) = call(
            state,
            "POST",
            "/machines/m-1/frogenv/operations",
            Some(body_for(action).to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{action}: {value}");
        assert_eq!(value["data"]["kind"], kind, "{action}");
    }
}

#[tokio::test]
async fn an_env_run_carries_its_root_and_command() {
    let port = Arc::new(FakeOperations::default());
    let state = Arc::new(ApiState {
        operations: Arc::new(Operations::new(port.clone(), Arc::new(FakeAudit))),
        authorizer: Arc::new(PermitAll),
        system: Arc::new(FakeSystemInfo),
        nodes: None,
        machines: Some(Arc::new(fleet_application::machine::Machines::new(
            Arc::new(FakeMachines),
            Arc::new(FakeAudit),
        ))),
        onboarding: None,
        tailnet: None,
        projects: None,
    });
    let mut body = body_for("envRun");
    body["root"] = serde_json::json!("/srv/repo");
    body["command"] = serde_json::json!(["pytest", "-q"]);
    let (status, value) = call(
        state,
        "POST",
        "/machines/m-1/frogenv/operations",
        Some(body.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    assert_eq!(value["data"]["kind"], "frogenv.env-run");
    let payloads = port.payloads();
    assert_eq!(payloads.len(), 1);
    let payload: serde_json::Value = serde_json::from_str(&payloads[0]).unwrap();
    assert_eq!(payload["root"], "/srv/repo");
    assert_eq!(payload["command"], serde_json::json!(["pytest", "-q"]));
}

#[tokio::test]
async fn an_env_run_without_its_root_is_malformed() {
    let state = state_for(Arc::new(PermitAll));
    let mut body = body_for("envRun");
    body["command"] = serde_json::json!(["pytest"]);
    let (status, value) = call(
        state,
        "POST",
        "/machines/m-1/frogenv/operations",
        Some(body.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
}

#[tokio::test]
async fn an_env_run_without_a_command_is_malformed() {
    let state = state_for(Arc::new(PermitAll));
    let mut body = body_for("envRun");
    body["root"] = serde_json::json!("/srv/repo");
    let (status, value) = call(
        state,
        "POST",
        "/machines/m-1/frogenv/operations",
        Some(body.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
}

#[tokio::test]
async fn an_env_run_with_a_hostile_root_is_malformed() {
    let state = state_for(Arc::new(PermitAll));
    let mut body = body_for("envRun");
    body["root"] = serde_json::json!("/tmp/../../etc");
    body["command"] = serde_json::json!(["ls"]);
    let (status, value) = call(
        state,
        "POST",
        "/machines/m-1/frogenv/operations",
        Some(body.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
}

#[tokio::test]
async fn the_authorization_names_the_machine_and_the_right_action() {
    let authorizer = Arc::new(Recording::default());
    let state = state_for(authorizer.clone());
    for action in ["status", "setup"] {
        let (status, value) = call(
            state.clone(),
            "POST",
            "/machines/m-1/frogenv/operations",
            Some(body_for(action).to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{action}: {value}");
    }
    let resources = authorizer.resources.lock().unwrap();
    let frogenv: Vec<_> = resources
        .iter()
        .filter(|(action, _)| action.starts_with("frogenv."))
        .cloned()
        .collect();
    // Each action is authorized twice by design: once at the endpoint and
    // once inside the operation use case. The status pair is frogenv.read;
    // the setup pair is frogenv.operate.
    assert_eq!(frogenv.len(), 4);
    for (index, (action, resource)) in frogenv.iter().enumerate() {
        let expected = if index < 2 {
            "frogenv.read"
        } else {
            "frogenv.operate"
        };
        assert_eq!(
            action, expected,
            "operation {index} authorizes the right action"
        );
        assert_eq!(
            resource.as_deref(),
            Some("m-1"),
            "{action} is machine-scoped"
        );
    }
}

#[tokio::test]
async fn a_frogenv_denial_is_a_machine_scoped_403() {
    let state = state_for(Arc::new(DenyFrogenv));
    let (status, value) = call(
        state,
        "POST",
        "/machines/m-1/frogenv/operations",
        Some(body_for("status").to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{value}");
}

#[tokio::test]
async fn an_unknown_machine_is_a_404() {
    let state = state_for(Arc::new(PermitAll));
    let (status, value) = call(
        state,
        "POST",
        "/machines/nope/frogenv/operations",
        Some(
            serde_json::json!({
                "machineId": "nope",
                "endpointId": "e-1",
                "auth": {"type": "agent"},
                "action": "status",
                "timeoutSeconds": 30,
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{value}");
}

#[tokio::test]
async fn the_generic_operations_surface_denies_a_frogenv_denied_caller() {
    let state = state_for(Arc::new(DenyFrogenv));
    let body = serde_json::json!({
        "kind": "frogenv.status",
        "payloadJson": r#"{"machineId":"m-1","endpointId":"e-1","auth":{"type":"agent"},"timeoutSeconds":30}"#,
    })
    .to_string();
    let (status, value) = call(state, "POST", "/operations", Some(body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{value}");
}

#[tokio::test]
async fn the_generic_operations_surface_enforces_the_frogenv_catalog() {
    let authorizer = Arc::new(Recording::default());
    let state = state_for(authorizer.clone());
    let body = serde_json::json!({
        "kind": "frogenv.status",
        "payloadJson": r#"{"machineId":"m-1","endpointId":"e-1","auth":{"type":"agent"},"timeoutSeconds":30}"#,
    })
    .to_string();
    let (status, value) = call(state, "POST", "/operations", Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    // The generic surface authorized frogenv.read with the machine as its
    // resource, exactly like the dedicated endpoint.
    let resources = authorizer.resources.lock().unwrap();
    let frogenv: Vec<_> = resources
        .iter()
        .filter(|(action, _)| action.starts_with("frogenv."))
        .cloned()
        .collect();
    assert_eq!(frogenv.len(), 1);
    assert_eq!(frogenv[0].0, "frogenv.read");
    assert_eq!(frogenv[0].1.as_deref(), Some("m-1"));
}
