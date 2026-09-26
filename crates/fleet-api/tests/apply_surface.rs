//! The apply surface (FM-402): authorization, validation, and idempotent
//! creation at the boundary.

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

#[derive(Debug)]
struct DenyApply;
impl fleet_application::authz::Authorizer for DenyApply {
    fn decide(
        &self,
        request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        if request.action == fleet_application::authz::Permission::ApplyExecute {
            fleet_application::authz::Decision::deny(
                fleet_application::authz::ReasonId::UnknownPrincipal,
            )
        } else {
            fleet_application::authz::Decision::allow()
        }
    }
}

/// Allows `ApplyExecute` for exactly one machine: the authorizer that
/// proves machine scoping, since an unconditional denial cannot
/// distinguish a machine-aware check from a resource-blind one.
#[derive(Debug)]
struct MachineScoped {
    allowed_machine: String,
}
impl fleet_application::authz::Authorizer for MachineScoped {
    fn decide(
        &self,
        request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        if request.action == fleet_application::authz::Permission::OperationCreate {
            // A catalog-level action: no resource, no machine scoping to
            // prove here.
            fleet_application::authz::Decision::allow()
        } else if request
            .resource
            .is_some_and(|resource| resource == self.allowed_machine)
            && matches!(
                request.action,
                fleet_application::authz::Permission::ApplyExecute
                    | fleet_application::authz::Permission::MachineRead
                    | fleet_application::authz::Permission::MachineReadSensitive
            )
        {
            fleet_application::authz::Decision::allow()
        } else {
            fleet_application::authz::Decision::deny(
                fleet_application::authz::ReasonId::UnknownPrincipal,
            )
        }
    }
}

#[derive(Debug, Default)]
struct FakeOperations {
    payloads: Mutex<Vec<String>>,
    idempotency_keys: Mutex<Vec<Option<String>>>,
}

#[async_trait::async_trait]
impl fleet_application::operation::OperationPort for FakeOperations {
    async fn create(
        &self,
        kind: &str,
        idempotency_key: Option<&str>,
        _deadline_at: Option<i64>,
        correlation_id: Option<&str>,
        payload_json: Option<&str>,
    ) -> Result<fleet_application::operation::Operation, PortFailure> {
        self.payloads
            .lock()
            .unwrap()
            .push(payload_json.unwrap_or_default().to_owned());
        self.idempotency_keys
            .lock()
            .unwrap()
            .push(idempotency_key.map(str::to_owned));
        Ok(fleet_application::operation::Operation {
            id: "op-1".to_owned(),
            kind: kind.to_owned(),
            state: "pending".to_owned(),
            idempotency_key: idempotency_key.map(str::to_owned),
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

fn state_for(authorizer: Arc<dyn fleet_application::authz::Authorizer>) -> Arc<ApiState> {
    Arc::new(ApiState {
        operations: Arc::new(Operations::new(
            Arc::new(FakeOperations::default()),
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
        skills: None,
        skill_catalog: None,
        proxmox: None,
        images: None,
        lab: None,
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

fn body_for(machine: &str) -> serde_json::Value {
    serde_json::json!({
        "machineId": machine,
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "planId": "plan-1",
        "actions": [
            {"order": 1, "kind": "mise.install",
             "difference": {"identity": "tool:node", "state": "missing",
                            "desired": "20.11.0", "observed": null, "reason": null}},
        ],
        "approvals": [
            {"planId": "plan-1", "actionOrder": 1, "kind": "mise.install"},
        ],
        "timeoutSeconds": 600,
    })
}

#[tokio::test]
async fn a_valid_plan_is_accepted() {
    let state = state_for(Arc::new(PermitAll));
    let (status, value) = call(
        state,
        "POST",
        "/machines/m-1/apply",
        Some(body_for("m-1").to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    assert_eq!(value["data"]["kind"], "apply.workflow");
}

#[tokio::test]
async fn an_unknown_kind_is_refused_at_the_boundary() {
    let state = state_for(Arc::new(PermitAll));
    let mut body = body_for("m-1");
    body["actions"] = serde_json::json!([
        {"order": 1, "kind": "demolish",
         "difference": {"identity": "x", "state": "missing",
                        "desired": "y", "observed": null, "reason": null}},
    ]);
    let (status, value) = call(state, "POST", "/machines/m-1/apply", Some(body.to_string())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
}

#[tokio::test]
async fn an_undocumented_state_is_refused_at_the_boundary() {
    let state = state_for(Arc::new(PermitAll));
    let mut body = body_for("m-1");
    body["actions"] = serde_json::json!([
        {"order": 1, "kind": "mise.install",
         "difference": {"identity": "tool:node", "state": "demolished",
                        "desired": "20.11.0", "observed": null, "reason": null}},
    ]);
    let (status, value) = call(state, "POST", "/machines/m-1/apply", Some(body.to_string())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
}

#[tokio::test]
async fn duplicate_or_non_increasing_orders_are_refused() {
    let state = state_for(Arc::new(PermitAll));
    let mut body = body_for("m-1");
    body["actions"] = serde_json::json!([
        {"order": 1, "kind": "mise.install",
         "difference": {"identity": "tool:node", "state": "missing",
                        "desired": "20.11.0", "observed": null, "reason": null}},
        {"order": 1, "kind": "skills.deploy",
         "difference": {"identity": "skill:db/claude_code", "state": "missing",
                        "desired": "deployed", "observed": null, "reason": null}},
    ]);
    let (status, value) = call(state, "POST", "/machines/m-1/apply", Some(body.to_string())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
}

#[tokio::test]
async fn a_body_machine_disagreeing_with_the_path_is_malformed() {
    let state = state_for(Arc::new(PermitAll));
    let (status, value) = call(
        state,
        "POST",
        "/machines/m-1/apply",
        Some(body_for("other").to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
}

#[tokio::test]
async fn an_apply_denial_is_a_machine_scoped_403() {
    let state = state_for(Arc::new(DenyApply));
    let (status, value) = call(
        state,
        "POST",
        "/machines/m-1/apply",
        Some(body_for("m-1").to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{value}");
}

#[tokio::test]
async fn the_apply_permission_is_machine_scoped() {
    // The authorizer allows apply only on m-1: a request against m-2 is
    // denied, proving the endpoint names the machine as its resource.
    let state = state_for(Arc::new(MachineScoped {
        allowed_machine: "m-1".to_owned(),
    }));
    let (status, _) = call(
        state.clone(),
        "POST",
        "/machines/m-1/apply",
        Some(body_for("m-1").to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let state = state_for(Arc::new(MachineScoped {
        allowed_machine: "m-1".to_owned(),
    }));
    let (status, value) = call(
        state,
        "POST",
        "/machines/m-2/apply",
        Some(body_for("m-2").to_string()),
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
        "/machines/nope/apply",
        Some(body_for("nope").to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{value}");
}
