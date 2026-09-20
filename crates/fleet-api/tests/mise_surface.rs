//! The mise surface (FM-304): actions authorize machine-scoped, the
//! machine must exist, install/exec carry their requirements, and the
//! generic /operations surface enforces the same catalog entry.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::machine::{
    Endpoint, Machine, MachineFilter, MachinePort, NewEndpoint, RegisterMachine,
};
use fleet_application::operation::{Operations, PortFailure};
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
struct DenyMise;
impl fleet_application::authz::Authorizer for DenyMise {
    fn decide(
        &self,
        request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        if matches!(
            request.action,
            fleet_application::authz::Permission::ToolsRead
                | fleet_application::authz::Permission::MiseOperate
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

fn state_for(
    authorizer: Arc<dyn fleet_application::authz::Authorizer>,
    operations: Option<Arc<FakeOperations>>,
) -> (Arc<ApiState>, Option<Arc<FakeOperations>>) {
    let operations = operations.unwrap_or_default();
    let handle = Some(operations.clone());
    (
        Arc::new(ApiState {
            operations: Arc::new(Operations::new(operations, Arc::new(FakeAudit))),
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
            proxmox: None,
        }),
        handle,
    )
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
        ("inventory", "tools.inventory"),
        ("status", "mise.status"),
        ("install", "mise.install"),
        ("exec", "mise.exec"),
    ] {
        let mut body = body_for(action);
        if action == "install" {
            body["tool"] = serde_json::json!("node");
            body["version"] = serde_json::json!("20.11.0");
        }
        if action == "exec" {
            body["root"] = serde_json::json!("/srv/repo");
            body["command"] = serde_json::json!(["npm", "test"]);
        }
        let (state, _) = state_for(Arc::new(PermitAll), None);
        let (status, value) = call(
            state,
            "POST",
            "/machines/m-1/mise/operations",
            Some(body.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{action}: {value}");
        assert_eq!(value["data"]["kind"], kind, "{action}");
    }
}

#[tokio::test]
async fn an_install_requires_its_tool_and_version() {
    let (state, _) = state_for(Arc::new(PermitAll), None);
    let (status, value) = call(
        state,
        "POST",
        "/machines/m-1/mise/operations",
        Some(body_for("install").to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
}

#[tokio::test]
async fn an_exec_requires_its_root_and_command() {
    let (state, _) = state_for(Arc::new(PermitAll), None);
    let (status, value) = call(
        state,
        "POST",
        "/machines/m-1/mise/operations",
        Some(body_for("exec").to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
}

#[tokio::test]
async fn an_install_pin_travels_as_data() {
    let (state, port) = state_for(Arc::new(PermitAll), Some(Arc::default()));
    let mut body = body_for("install");
    body["tool"] = serde_json::json!("node");
    body["version"] = serde_json::json!("20.11.0");
    let (status, _value) = call(
        state,
        "POST",
        "/machines/m-1/mise/operations",
        Some(body.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let payloads = port.unwrap().payloads();
    let payload: serde_json::Value = serde_json::from_str(&payloads[0]).unwrap();
    assert_eq!(payload["tool"], "node");
    assert_eq!(payload["version"], "20.11.0");
}

#[tokio::test]
async fn the_authorization_names_the_machine_and_the_right_action() {
    let authorizer = Arc::new(Recording::default());
    let (state, _) = state_for(authorizer.clone(), None);
    for (action, tool, version) in [
        ("status", None, None),
        ("install", Some("node"), Some("20.11.0")),
    ] {
        let mut body = body_for(action);
        if let Some(tool) = tool {
            body["tool"] = serde_json::json!(tool);
            body["version"] = serde_json::json!(version.unwrap());
        }
        let (status, value) = call(
            state.clone(),
            "POST",
            "/machines/m-1/mise/operations",
            Some(body.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{action}: {value}");
    }
    let resources = authorizer.resources.lock().unwrap();
    let mise: Vec<_> = resources
        .iter()
        .filter(|(action, _)| action.starts_with("mise.") || action.starts_with("tools."))
        .cloned()
        .collect();
    // Each action is authorized twice by design: once at the endpoint and
    // once inside the operation use case. The status pair is tools.read;
    // the install pair is mise.operate. Every one names the machine.
    assert_eq!(mise.len(), 4);
    for (index, (action, resource)) in mise.iter().enumerate() {
        let expected = if index < 2 {
            "tools.read"
        } else {
            "mise.operate"
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
async fn a_mise_denial_is_a_machine_scoped_403() {
    let (state, _) = state_for(Arc::new(DenyMise), None);
    let (status, value) = call(
        state,
        "POST",
        "/machines/m-1/mise/operations",
        Some(body_for("status").to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{value}");
}

#[tokio::test]
async fn an_unknown_machine_is_a_404() {
    let (state, _) = state_for(Arc::new(PermitAll), None);
    let mut body = body_for("status");
    body["machineId"] = serde_json::json!("nope");
    let (status, value) = call(
        state,
        "POST",
        "/machines/nope/mise/operations",
        Some(body.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{value}");
}

#[tokio::test]
async fn the_generic_operations_surface_enforces_the_mise_catalog() {
    let (state, _) = state_for(Arc::new(DenyMise), None);
    let body = serde_json::json!({
        "kind": "mise.status",
        "payloadJson": r#"{"machineId":"m-1","endpointId":"e-1","auth":{"type":"agent"},"timeoutSeconds":30}"#,
    })
    .to_string();
    let (status, value) = call(state, "POST", "/operations", Some(body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{value}");
}
