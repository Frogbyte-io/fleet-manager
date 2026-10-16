//! FM-1040: the action broker routes over real SQLite repositories behind
//! the real router: create, list, get, approve, and deny; the status codes
//! for refusal, conflict, and unwired states; and that approval starts the
//! operation through the normal operation path.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::broker::test_support::{NOOP_ACTION_ID, NoopAction};
use fleet_application::broker::{ActionRegistry, Broker, BrokerSettings};
use fleet_application::operation::Operations;
use fleet_core::RiskClass;
use fleet_storage_sqlite::{ActionRequestRepository, AuditSink, OperationRepository, Store};
use tower::ServiceExt as _;

#[derive(Debug)]
struct Permit;
impl Authorizer for Permit {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

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

async fn state(
    risk: RiskClass,
    authorizer: Arc<dyn Authorizer>,
) -> (tempfile::TempDir, Arc<ApiState>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool = store.pool().clone();
    let operations = Arc::new(
        Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            Arc::new(AuditSink::new(pool.clone())),
        )
        .with_brokered_kinds(["noop".to_owned()]),
    );
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(NoopAction { risk })).unwrap();
    let broker = Broker::new(
        Arc::new(ActionRequestRepository::new(pool)),
        Arc::new(registry),
        operations.clone(),
        BrokerSettings::default(),
    );
    (
        dir,
        Arc::new(ApiState {
            operations,
            authorizer,
            requests: Some(Arc::new(broker)),
            ..ApiState::for_document()
        }),
    )
}

async fn call(
    state: &Arc<ApiState>,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let router = router(state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }));
    let request = Request::builder()
        .method(method)
        .uri(format!("{API_BASE_PATH}{path}"))
        .header("content-type", "application/json")
        .header(
            CORRELATION_ID_HEADER,
            "01900000-0000-7000-8000-000000000000",
        )
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
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

fn create_body() -> serde_json::Value {
    serde_json::json!({
        "actionId": NOOP_ACTION_ID,
        "target": "app-1",
        "parameters": { "service": "web" },
        "reason": "the deploy looks stale",
    })
}

#[tokio::test]
async fn a_request_is_created_listed_approved_and_runs_as_an_operation() {
    let (_dir, state) = state(RiskClass::Approve, Arc::new(Permit)).await;
    let (status, body) = call(&state, "POST", "/requests", Some(create_body())).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let data = &body["data"];
    assert_eq!(data["state"], "pending");
    assert_eq!(data["riskClass"], "approve");
    assert_eq!(data["requester"], "anonymous-lan-admin");
    assert_eq!(data["origin"], "api");
    assert_eq!(data["terminal"], false);
    assert_eq!(data["parameters"], serde_json::json!({ "service": "web" }));
    let id = data["id"].as_str().unwrap().to_owned();

    let (status, body) = call(&state, "GET", "/requests?state=pending", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    let (status, body) = call(&state, "GET", "/requests?state=executing", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["items"].as_array().unwrap().is_empty());
    let (status, _) = call(&state, "GET", "/requests?state=bogus", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = call(&state, "GET", &format!("/requests/{id}"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["id"], id);

    let (status, body) = call(&state, "POST", &format!("/requests/{id}/approve"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["state"], "executing");
    assert_eq!(body["data"]["decidedBy"], "anonymous-lan-admin");
    let operation_id = body["data"]["operationId"].as_str().unwrap().to_owned();
    let (status, operation) =
        call(&state, "GET", &format!("/operations/{operation_id}"), None).await;
    assert_eq!(status, StatusCode::OK, "{operation}");
    assert_eq!(operation["data"]["kind"], "noop");

    // A second decision is a conflict, not a second execution.
    let (status, body) = call(&state, "POST", &format!("/requests/{id}/approve"), None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, _) = call(&state, "POST", &format!("/requests/{id}/deny"), None).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn deny_takes_an_optional_note() {
    let (_dir, state) = state(RiskClass::Approve, Arc::new(Permit)).await;
    let (_, body) = call(&state, "POST", "/requests", Some(create_body())).await;
    let id = body["data"]["id"].as_str().unwrap().to_owned();
    let (status, body) = call(
        &state,
        "POST",
        &format!("/requests/{id}/deny"),
        Some(serde_json::json!({ "note": "not today" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["state"], "denied");
    assert_eq!(body["data"]["decisionNote"], "not today");
    assert!(body["data"]["operationId"].is_null());

    let (_, body) = call(&state, "POST", "/requests", Some(create_body())).await;
    let id = body["data"]["id"].as_str().unwrap().to_owned();
    let (status, body) = call(&state, "POST", &format!("/requests/{id}/deny"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["state"], "denied");
}

#[tokio::test]
async fn auto_and_deny_classes_answer_what_policy_did() {
    let (_dir, auto) = state(RiskClass::Auto, Arc::new(Permit)).await;
    let (status, body) = call(&auto, "POST", "/requests", Some(create_body())).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["data"]["state"], "executing");
    assert_eq!(body["data"]["decidedBy"], "policy:auto");
    assert!(body["data"]["operationId"].is_string());

    let (_dir, deny) = state(RiskClass::Deny, Arc::new(Permit)).await;
    let (status, body) = call(&deny, "POST", "/requests", Some(create_body())).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "policy_denied");
    // Nothing was stored.
    let (status, body) = call(&deny, "GET", "/requests", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["items"].as_array().unwrap().is_empty(), "{body}");
}

#[tokio::test]
async fn an_idempotency_key_returns_the_same_request_and_brokered_kinds_leave_the_generic_route() {
    let (_dir, state) = state(RiskClass::Approve, Arc::new(Permit)).await;
    let mut body = create_body();
    body["idempotencyKey"] = serde_json::json!("retry-1");
    let (status, first) = call(&state, "POST", "/requests", Some(body.clone())).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let (status, again) = call(&state, "POST", "/requests", Some(body.clone())).await;
    assert_eq!(status, StatusCode::CREATED, "{again}");
    assert_eq!(first["data"]["id"], again["data"]["id"]);
    body["target"] = serde_json::json!("another-target");
    let (status, _) = call(&state, "POST", "/requests", Some(body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    // An unknown state filter is refused without being echoed.
    let (status, error) = call(&state, "GET", "/requests?state=echo-me", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!error.to_string().contains("echo-me"), "{error}");
    // The noop kind belongs to the registered action: the generic surface
    // refuses it.
    let (status, error) = call(
        &state,
        "POST",
        "/operations",
        Some(serde_json::json!({ "kind": "noop" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert!(error.to_string().contains("POST /requests"), "{error}");
}

#[tokio::test]
async fn refusals_use_the_public_error_envelope() {
    let (_dir, state) = state(RiskClass::Approve, Arc::new(Permit)).await;
    for (body, needle) in [
        (
            serde_json::json!({ "actionId": "x.y.z", "target": "t", "reason": "r" }),
            "not offered",
        ),
        (
            serde_json::json!({
                "actionId": NOOP_ACTION_ID, "target": "t", "reason": "r",
                "parameters": { "apiToken": "fakepw1" }
            }),
            "credential",
        ),
    ] {
        let (status, error) = call(&state, "POST", "/requests", Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
        assert_eq!(error["code"], "invalid_request");
        let text = error.to_string();
        assert!(text.contains(needle), "{text}");
        assert!(!text.contains("fakepw1"));
    }
    let (status, _) = call(&state, "POST", "/requests", Some(serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(&state, "GET", "/requests/missing", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(&state, "POST", "/requests/missing/approve", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn request_approve_deny_and_read_are_separate_permissions() {
    for (permission, method, path_suffix, expect_body) in [
        (Permission::ActionRequest, "POST", "", true),
        (Permission::ActionRead, "GET", "", false),
    ] {
        let (_dir, state) = state(RiskClass::Approve, Arc::new(Without(permission))).await;
        let (status, error) = call(
            &state,
            method,
            &format!("/requests{path_suffix}"),
            expect_body.then(create_body),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{permission}: {error}");
    }
    // Make a request with full rights, then try to decide it without the
    // matching permission.
    let (_dir, allowed) = state(RiskClass::Approve, Arc::new(Permit)).await;
    let (_, body) = call(&allowed, "POST", "/requests", Some(create_body())).await;
    let id = body["data"]["id"].as_str().unwrap().to_owned();
    for (permission, action) in [
        (Permission::ActionApprove, "approve"),
        (Permission::ActionDeny, "deny"),
    ] {
        let restricted = Arc::new(ApiState {
            authorizer: Arc::new(Without(permission)),
            ..(*allowed).clone()
        });
        let (status, error) = call(
            &restricted,
            "POST",
            &format!("/requests/{id}/{action}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{action}: {error}");
    }
    let (_, body) = call(&allowed, "GET", &format!("/requests/{id}"), None).await;
    assert_eq!(body["data"]["state"], "pending");
}

#[tokio::test]
async fn an_unwired_controller_answers_with_the_envelope() {
    let unwired = Arc::new(ApiState {
        authorizer: Arc::new(Permit),
        ..ApiState::for_document()
    });
    let (status, error) = call(&unwired, "GET", "/requests", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{error}");
}
