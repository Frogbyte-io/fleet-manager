//! The Skills Manager surface (FM-302): probe/deploy/undeploy authorize
//! machine-scoped, and the machine must exist before the operation is
//! created.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::operation::Operations;
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
struct DenySkills;
impl fleet_application::authz::Authorizer for DenySkills {
    fn decide(
        &self,
        request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        if matches!(
            request.action,
            fleet_application::authz::Permission::SkillsRead
                | fleet_application::authz::Permission::SkillsDeploy
                | fleet_application::authz::Permission::SkillsModify
        ) {
            fleet_application::authz::Decision::deny(
                fleet_application::authz::ReasonId::UnknownPrincipal,
            )
        } else {
            fleet_application::authz::Decision::allow()
        }
    }
}

#[derive(Debug)]
struct DenySkillsModify;
impl fleet_application::authz::Authorizer for DenySkillsModify {
    fn decide(
        &self,
        request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        if request.action == fleet_application::authz::Permission::SkillsModify {
            fleet_application::authz::Decision::deny(
                fleet_application::authz::ReasonId::UnknownPrincipal,
            )
        } else {
            fleet_application::authz::Decision::allow()
        }
    }
}

#[derive(Debug)]
struct DenySecondMachine;
impl fleet_application::authz::Authorizer for DenySecondMachine {
    fn decide(
        &self,
        request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        if request.action == fleet_application::authz::Permission::SkillsRead
            && request.resource == Some("m-2")
        {
            fleet_application::authz::Decision::deny(
                fleet_application::authz::ReasonId::UnknownPrincipal,
            )
        } else {
            fleet_application::authz::Decision::allow()
        }
    }
}

#[derive(Debug)]
struct DenyFirstMachine;
impl fleet_application::authz::Authorizer for DenyFirstMachine {
    fn decide(
        &self,
        request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        if request.action == fleet_application::authz::Permission::SkillsRead
            && request.resource == Some("m-1")
        {
            fleet_application::authz::Decision::deny(
                fleet_application::authz::ReasonId::UnknownPrincipal,
            )
        } else {
            fleet_application::authz::Decision::allow()
        }
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

#[derive(Debug)]
struct FakeSkills;
#[async_trait::async_trait]
impl fleet_application::skills::SkillsPort for FakeSkills {
    async fn get(
        &self,
        machine_id: &str,
    ) -> Result<Option<fleet_application::skills::SkillsSnapshot>, PortFailure> {
        Ok((machine_id == "m-1").then(|| snapshot("m-1")))
    }
    async fn list(
        &self,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Vec<fleet_application::skills::SkillsSnapshot>, PortFailure> {
        Ok(vec![snapshot("m-1"), snapshot("m-2"), snapshot("m-3")]
            .into_iter()
            .filter(|row| after.is_none_or(|cursor| row.machine_id.as_str() > cursor))
            .take(limit as usize)
            .collect())
    }
    async fn record(
        &self,
        _snapshot: &fleet_application::skills::SkillsSnapshot,
    ) -> Result<(), PortFailure> {
        Ok(())
    }
}

fn snapshot(machine_id: &str) -> fleet_application::skills::SkillsSnapshot {
    fleet_application::skills::SkillsSnapshot {
        machine_id: machine_id.to_owned(),
        availability: fleet_application::skills::SkillsAvailability::Available,
        cli_version: Some("1.40.0".into()),
        data: serde_json::json!({"skills": [], "agents": [], "presets": []}),
        update_check: "complete".into(),
        observed_at: 0,
    }
}

use fleet_application::machine::{
    Endpoint, Machine, MachineFilter, MachinePort, NewEndpoint, RegisterMachine,
};
use fleet_application::operation::PortFailure;
use fleet_core::EndpointKind;

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

fn state_for(authorizer: Arc<dyn fleet_application::authz::Authorizer>) -> Arc<ApiState> {
    Arc::new(ApiState {
        operations: Arc::new(Operations::new(
            Arc::new(FakeOperations),
            Arc::new(FakeAudit),
        )),
        authorizer,
        system: Arc::new(FakeSystemInfo),
        audit: None,
        events: Arc::new(fleet_application::events::Events::new(Arc::new(
            fleet_application::events::EventHub::new(8),
        ))),
        nodes: None,
        machines: Some(Arc::new(fleet_application::machine::Machines::new(
            Arc::new(FakeMachines),
            Arc::new(FakeAudit),
        ))),
        onboarding: None,
        tailnet: None,
        projects: None,
        skills: Some(Arc::new(fleet_application::skills::Skills::new(Arc::new(
            FakeSkills,
        )))),
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
async fn a_probe_starts_a_durable_operation() {
    let state = state_for(Arc::new(PermitAll));
    let body = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "timeoutSeconds": 30,
    })
    .to_string();
    let (status, value) = call(
        state.clone(),
        "POST",
        "/machines/m-1/skills/operations",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    assert_eq!(value["data"]["kind"], "skills.probe");
}

#[tokio::test]
async fn skills_read_endpoints_use_machine_scoped_skills_permission() {
    let authorizer = Arc::new(Recording::default());
    let state = state_for(authorizer.clone());
    let (status, value) = call(state.clone(), "GET", "/machines/m-1/skills", None).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["data"]["availability"], "available");
    assert_eq!(value["data"]["stale"], true);
    let (status, rows) = call(state, "GET", "/skills/matrix", None).await;
    assert_eq!(status, StatusCode::OK, "{rows}");
    assert_eq!(rows["items"].as_array().unwrap().len(), 3);
    let checks = authorizer.resources.lock().unwrap();
    assert!(checks.iter().any(|(action, resource)| action == "skills.read" && resource.as_deref() == Some("m-1")));
    assert!(checks.iter().any(|(action, resource)| action == "skills.read" && resource.as_deref() == Some("m-2")));
}

#[tokio::test]
async fn the_matrix_omits_each_machine_denied_by_skills_read() {
    let state = state_for(Arc::new(DenySecondMachine));
    let (status, page) = call(state, "GET", "/skills/matrix", None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    assert_eq!(page["items"][0]["machineId"], "m-1");
    assert_eq!(page["items"][1]["machineId"], "m-3");
}

#[tokio::test]
async fn the_matrix_cursor_skips_denied_rows_without_exposing_their_ids() {
    let state = state_for(Arc::new(DenyFirstMachine));
    let (status, first) = call(state.clone(), "GET", "/skills/matrix?limit=1", None).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    assert_eq!(first["items"][0]["machineId"], "m-2");
    assert_eq!(first["page"]["nextCursor"], "m-2");
    assert_ne!(first["page"]["nextCursor"], "m-1");

    let (status, second) = call(state, "GET", "/skills/matrix?cursor=m-2&limit=1", None).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert_eq!(second["items"][0]["machineId"], "m-3");
    assert!(second["page"]["nextCursor"].is_null());
}

#[tokio::test]
async fn skills_read_denial_does_not_fall_back_to_machine_read() {
    let state = state_for(Arc::new(DenySkills));
    let (status, value) = call(state, "GET", "/machines/m-1/skills", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{value}");
}

#[tokio::test]
async fn a_deploy_starts_the_deploy_kind() {
    let state = state_for(Arc::new(PermitAll));
    let body = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "skillId": "db",
        "agents": ["claude_code"],
        "direction": "deploy",
        "timeoutSeconds": 30,
    })
    .to_string();
    let (status, value) = call(state, "POST", "/machines/m-1/skills/operations", Some(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    assert_eq!(value["data"]["kind"], "skills.deploy");
}

#[tokio::test]
async fn an_explicit_library_install_starts_a_durable_install_operation() {
    let state = state_for(Arc::new(PermitAll));
    let body = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "operation": "install",
        "reference": "org/repo/skill",
        "timeoutSeconds": 30,
    })
    .to_string();
    let (status, value) = call(state, "POST", "/machines/m-1/skills/operations", Some(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    assert_eq!(value["data"]["kind"], "skills.install");
}

#[tokio::test]
async fn skill_removal_requires_explicit_confirmation() {
    let state = state_for(Arc::new(PermitAll));
    let body = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "operation": "remove",
        "reference": "db",
        "timeoutSeconds": 30,
    })
    .to_string();
    let (status, value) = call(
        state.clone(),
        "POST",
        "/machines/m-1/skills/operations",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["code"], "invalid_request");

    let body = serde_json::json!({
        "machineId": "m-1", "endpointId": "e-1", "auth": {"type":"agent"},
        "operation": "remove", "reference": "db", "confirm": true, "timeoutSeconds": 30
    })
    .to_string();
    let (status, value) = call(state, "POST", "/machines/m-1/skills/operations", Some(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    assert_eq!(value["data"]["kind"], "skills.remove");
}

#[tokio::test]
async fn library_mutation_is_denied_without_skills_modify() {
    let state = state_for(Arc::new(DenySkillsModify));
    let body = serde_json::json!({
        "machineId": "m-1", "endpointId": "e-1", "auth": {"type":"agent"},
        "operation": "install", "reference": "org/repo/skill", "timeoutSeconds": 30
    })
    .to_string();
    let (status, _) = call(state, "POST", "/machines/m-1/skills/operations", Some(body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn credential_bearing_source_urls_are_rejected_before_operation_creation() {
    let state = state_for(Arc::new(PermitAll));
    let body = serde_json::json!({
        "machineId": "m-1", "endpointId": "e-1", "auth": {"type":"agent"},
        "operation": "install", "reference": "https://user:secret@example.invalid/org/skill", "timeoutSeconds": 30
    }).to_string();
    let (status, value) = call(
        state.clone(),
        "POST",
        "/machines/m-1/skills/operations",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
    assert!(!value.to_string().contains("secret"));

    let body = serde_json::json!({
        "machineId": "m-1", "endpointId": "e-1", "auth": {"type":"agent"},
        "operation": "adopt", "path": "./skill", "sourceUrl": "https://example.invalid/repo#access_token=secret", "timeoutSeconds": 30
    }).to_string();
    let (status, value) = call(
        state.clone(),
        "POST",
        "/machines/m-1/skills/operations",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
    assert!(!value.to_string().contains("secret"));

    let body = serde_json::json!({
        "machineId": "m-1", "endpointId": "e-1", "auth": {"type":"agent"},
        "operation": "adopt", "path": "./skill", "sourceUrl": "ssh://git@github.com/org/repo.git", "timeoutSeconds": 30
    }).to_string();
    let (status, value) = call(state, "POST", "/machines/m-1/skills/operations", Some(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
}

#[tokio::test]
async fn an_undeploy_starts_the_undeploy_kind() {
    let state = state_for(Arc::new(PermitAll));
    let body = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "skillId": "db",
        "agents": ["claude_code"],
        "direction": "undeploy",
        "timeoutSeconds": 30,
    })
    .to_string();
    let (status, value) = call(state, "POST", "/machines/m-1/skills/operations", Some(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    assert_eq!(value["data"]["kind"], "skills.undeploy");
}

#[tokio::test]
async fn the_authorization_names_the_machine_as_its_resource() {
    let authorizer = Arc::new(Recording::default());
    let state = state_for(authorizer.clone());
    for direction in ["probe", "deploy", "undeploy"] {
        let mut body = serde_json::json!({
            "machineId": "m-1",
            "endpointId": "e-1",
            "auth": {"type": "agent"},
            "timeoutSeconds": 30,
        });
        if direction != "probe" {
            body["skillId"] = serde_json::json!("db");
            body["agents"] = serde_json::json!(["claude_code"]);
            body["direction"] = serde_json::json!(direction);
        }
        let (status, value) = call(
            state.clone(),
            "POST",
            "/machines/m-1/skills/operations",
            Some(body.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    }
    let body = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "operation": "install",
        "reference": "org/repo/skill",
        "timeoutSeconds": 30,
    });
    let (status, value) = call(
        state,
        "POST",
        "/machines/m-1/skills/operations",
        Some(body.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    assert_eq!(value["data"]["kind"], "skills.install");
    let resources = authorizer.resources.lock().unwrap();
    let skills: Vec<_> = resources
        .iter()
        .filter(|(action, _)| action.starts_with("skills."))
        .collect();
    // The skills action is authorized twice by design: once at the
    // endpoint and once inside the operation use case (the generic
    // /operations surface enforces the same catalog entry). Every one of
    // them names the machine as its resource.
    assert!(skills.len() >= 3);
    for (action, resource) in skills {
        assert_eq!(
            resource.as_deref(),
            Some("m-1"),
            "{action} is machine-scoped"
        );
    }
    assert!(resources.iter().any(|(action, resource)| {
        action == "skills.modify" && resource.as_deref() == Some("m-1")
    }));
}

#[tokio::test]
async fn a_skills_denial_is_a_machine_scoped_403() {
    let state = state_for(Arc::new(DenySkills));
    let body = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "timeoutSeconds": 30,
    })
    .to_string();
    let (status, value) = call(state, "POST", "/machines/m-1/skills/operations", Some(body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{value}");
    assert_eq!(value["code"], "denied");
}

#[tokio::test]
async fn a_deploy_denial_is_also_a_403() {
    let state = state_for(Arc::new(DenySkills));
    let body = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "skillId": "db",
        "agents": ["claude_code"],
        "direction": "deploy",
        "timeoutSeconds": 30,
    })
    .to_string();
    let (status, value) = call(state, "POST", "/machines/m-1/skills/operations", Some(body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{value}");
}

#[tokio::test]
async fn an_unknown_machine_is_a_404() {
    let state = state_for(Arc::new(PermitAll));
    let body = serde_json::json!({
        "machineId": "nope",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "timeoutSeconds": 30,
    })
    .to_string();
    let (status, value) = call(
        state,
        "POST",
        "/machines/nope/skills/operations",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{value}");
}

#[tokio::test]
async fn the_generic_operations_surface_enforces_the_skills_catalog() {
    // A caller with operation.create but without skills permissions cannot
    // route around the skills endpoint through the generic surface.
    let state = state_for(Arc::new(DenySkills));
    let body = serde_json::json!({
        "kind": "skills.probe",
        "payloadJson": r#"{"machineId":"m-1","endpointId":"e-1","auth":{"type":"agent"},"timeoutSeconds":30}"#,
    })
    .to_string();
    let (status, value) = call(state, "POST", "/operations", Some(body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{value}");
}
