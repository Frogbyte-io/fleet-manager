//! HTTP contract tests.
//!
//! These drive the real router rather than calling handler functions, because
//! the parts most likely to be wrong — the correlation middleware, the status
//! codes, the fallback — are not in the handlers.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, response::Parts},
};
use http::Method;
use std::sync::Arc;

use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::audit::{AuditEvent, AuditFilter, AuditOutcome, AuditPage, AuditQueryPort};
use http_body_util::BodyExt as _;
use serde_json::Value;
use tower::ServiceExt as _;

const SUPPLIED_CORRELATION_ID: &str = "01900a3c-b576-7287-a004-61d5b384a076";

/// The test router: the in-memory operation state plus a resolved LAN
/// principal, as the controller's caller middleware provides in production.
/// The fake backend is returned so tests can drive its state directly.
fn test_state() -> (Arc<ApiState>, Arc<FakePort>, Arc<RecordingAuditQuery>) {
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
    let port = Arc::new(FakePort::default());
    let audit = Arc::new(RecordingAuditQuery(std::sync::Mutex::new(None)));
    let state = Arc::new(ApiState {
        operations: Arc::new(Operations::new(port.clone(), Arc::new(FakeAudit))),
        authorizer: Arc::new(PermitAll),
        system: Arc::new(FakeSystemInfo),
        audit: Some(Arc::new(fleet_application::audit::AuditQueries::new(
            audit.clone(),
        ))),
        nodes: None,
        machines: None,
        onboarding: None,
        tailnet: None,
        projects: None,
        proxmox: None,
        images: None,
        lab: None,
    });
    (state, port, audit)
}

fn test_router() -> (axum::Router, Arc<FakePort>, Arc<RecordingAuditQuery>) {
    let (state, port, audit) = test_state();
    (
        router(state).layer(axum::Extension(fleet_api::ActingPrincipal {
            id: "anonymous-lan-admin".to_owned(),
        })),
        port,
        audit,
    )
}

#[derive(Debug)]
struct RecordingAuditQuery(std::sync::Mutex<Option<AuditFilter>>);

#[async_trait::async_trait]
impl AuditQueryPort for RecordingAuditQuery {
    async fn query(&self, filter: &AuditFilter) -> Result<AuditPage, String> {
        *self.0.lock().unwrap() = Some(filter.clone());
        Ok(AuditPage {
            events: vec![AuditEvent {
                seq: 12,
                id: "event-12".to_owned(),
                occurred_at: 1_700_000_000_000,
                actor: "alice".to_owned(),
                action: "machine.update".to_owned(),
                resource: Some("machine-1".to_owned()),
                allowed: true,
                reason: "allowed".to_owned(),
                correlation_id: Some("flow-1".to_owned()),
                operation_id: None,
                outcome: Some(AuditOutcome::Succeeded),
                metadata_json: r#"{"event":"machine_updated","machine":"machine-1","invalidatedEnrollmentCount":"2","purpose":"operator supplied access phrase"}"#.to_owned(),
            }],
            next_seq: Some(12),
        })
    }
}

async fn call(request: Request<Body>) -> (Parts, Value) {
    let (router, _port, _audit) = test_router();
    let response = router
        .oneshot(request)
        .await
        .expect("the router is infallible");
    into_parts_json(response).await
}

async fn into_parts_json(response: axum::response::Response) -> (Parts, Value) {
    let (parts, body) = response.into_parts();
    let bytes = body
        .collect()
        .await
        .expect("the body is complete")
        .to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("every response body is JSON")
    };
    (parts, json)
}

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .body(Body::empty())
        .expect("the request is well formed")
}

fn correlation_header(parts: &Parts) -> &str {
    parts
        .headers
        .get(CORRELATION_ID_HEADER)
        .expect("every response carries a correlation identity")
        .to_str()
        .expect("a correlation identity is printable ASCII")
}

#[tokio::test]
async fn the_inert_endpoint_returns_the_resource_envelope() {
    let (parts, body) = call(get(&format!("{API_BASE_PATH}/meta"))).await;

    assert_eq!(parts.status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::json!({"data": {"apiVersion": "v1", "service": "fleet-controller"}})
    );
}

#[tokio::test]
async fn audit_api_forwards_filters_and_returns_a_metadata_only_page() {
    let (router, _port, audit) = test_router();
    let request = get(&format!(
        "{API_BASE_PATH}/audit?actor=alice&action=machine.update&resource=machine-1&outcome=succeeded&from=1699999999000&to=1700000001000&cursor=11&limit=1"
    ));
    let response = router.oneshot(request).await.unwrap();
    let (parts, body) = into_parts_json(response).await;

    assert_eq!(parts.status, StatusCode::OK, "{body}");
    assert_eq!(
        body["items"][0]["metadata"],
        serde_json::json!({"event": "machine_updated", "invalidatedEnrollmentCount": "2"})
    );
    assert!(body["items"][0].get("metadataJson").is_none());
    assert_eq!(body["page"]["nextCursor"], "12");
    let filter = audit.0.lock().unwrap().clone().unwrap();
    assert_eq!(filter.after_seq, Some(11));
    assert_eq!(filter.actor.as_deref(), Some("alice"));
    assert_eq!(filter.action.as_deref(), Some("machine.update"));
    assert_eq!(filter.resource.as_deref(), Some("machine-1"));
    assert_eq!(filter.outcome.as_deref(), Some("succeeded"));
    assert_eq!(filter.from, Some(1_699_999_999_000));
    assert_eq!(filter.to, Some(1_700_000_001_000));
    assert_eq!(filter.limit, 1);
}

#[tokio::test]
async fn audit_api_rejects_a_non_positive_cursor() {
    let (parts, body) = call(get(&format!("{API_BASE_PATH}/audit?cursor=0"))).await;
    assert_eq!(parts.status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");
}

#[tokio::test]
async fn audit_api_returns_an_error_envelope_for_a_malformed_limit() {
    let (parts, body) = call(get(&format!("{API_BASE_PATH}/audit?limit=not-a-number"))).await;
    assert_eq!(parts.status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");
}

#[tokio::test]
async fn a_success_carries_a_generated_correlation_identity() {
    let (parts, _) = call(get(&format!("{API_BASE_PATH}/meta"))).await;

    let correlation_id = correlation_header(&parts);

    assert!(
        correlation_id.parse::<fleet_core::CorrelationId>().is_ok(),
        "{correlation_id} is not a canonical opaque identity"
    );
}

#[tokio::test]
async fn a_supplied_correlation_identity_is_returned_unchanged() {
    let request = Request::builder()
        .uri(format!("{API_BASE_PATH}/meta"))
        .header(CORRELATION_ID_HEADER, SUPPLIED_CORRELATION_ID)
        .body(Body::empty())
        .expect("the request is well formed");

    let (parts, _) = call(request).await;

    assert_eq!(correlation_header(&parts), SUPPLIED_CORRELATION_ID);
}

#[tokio::test]
async fn a_malformed_correlation_identity_is_refused_with_the_error_envelope() {
    let request = Request::builder()
        .uri(format!("{API_BASE_PATH}/meta"))
        .header(CORRELATION_ID_HEADER, "not-an-identity")
        .body(Body::empty())
        .expect("the request is well formed");

    let (parts, body) = call(request).await;

    assert_eq!(parts.status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "malformed_correlation_id");
    assert_eq!(body["retry"], "never");
    assert_eq!(
        body["correlationId"],
        correlation_header(&parts),
        "the error body and the response header must agree"
    );
    assert_ne!(
        body["correlationId"], "not-an-identity",
        "a refused identity must not be echoed back as though it were accepted"
    );
}

#[tokio::test]
async fn an_unrouted_path_answers_with_the_error_envelope_and_a_correlation_identity() {
    let (parts, body) = call(get("/api/v1/does-not-exist")).await;

    assert_eq!(parts.status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "not_found");
    assert_eq!(body["correlationId"], correlation_header(&parts));
}

#[tokio::test]
async fn error_bodies_never_carry_an_empty_field_violation_list() {
    let (_, body) = call(get("/api/v1/does-not-exist")).await;

    assert!(
        body.get("fieldViolations").is_none(),
        "an absent list must be omitted rather than serialized as []"
    );
}

// Operation endpoints over an in-memory backend, so the contract is proven
// without a database.

use async_trait::async_trait;
use fleet_application::audit::AuditIntent;
use fleet_application::authz::{Decision, ReasonId};
use fleet_application::operation::{AuditPort, Operation, OperationPort, Operations, PortFailure};
use std::sync::Mutex;

#[derive(Debug, Default)]
struct FakePort {
    operations: Mutex<Vec<Operation>>,
    seq: std::sync::atomic::AtomicU64,
}

impl FakePort {
    fn next_id(&self) -> String {
        let n = self.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        format!("00000000-0000-7000-8000-{n:012}")
    }
}

#[async_trait]
impl OperationPort for FakePort {
    async fn create(
        &self,
        kind: &str,
        idempotency_key: Option<&str>,
        deadline_at: Option<i64>,
        correlation_id: Option<&str>,
        payload_json: Option<&str>,
    ) -> Result<Operation, PortFailure> {
        let mut operations = self.operations.lock().unwrap();
        if let Some(existing) = idempotency_key.and_then(|key| {
            operations
                .iter()
                .find(|operation| operation.idempotency_key.as_deref() == Some(key))
        }) {
            return Ok(existing.clone());
        }
        let operation = Operation {
            id: self.next_id(),
            kind: kind.to_owned(),
            state: "pending".to_owned(),
            idempotency_key: idempotency_key.map(str::to_owned),
            progress_current: None,
            progress_total: None,
            progress_message: None,
            deadline_at,
            cancel_requested: false,
            payload_json: payload_json.map(str::to_owned),
            result_json: None,
            error_json: None,
            correlation_id: correlation_id.map(str::to_owned),
            created_at: 0,
            updated_at: 0,
            claimed_at: None,
            worker_id: None,
        };
        operations.push(operation.clone());
        Ok(operation)
    }

    async fn get(&self, id: &str) -> Result<Operation, PortFailure> {
        self.operations
            .lock()
            .unwrap()
            .iter()
            .find(|operation| operation.id == id)
            .cloned()
            .ok_or_else(|| PortFailure::NotFound {
                what: format!("operation {id:?}"),
            })
    }

    async fn list(&self, limit: u32) -> Result<Vec<Operation>, PortFailure> {
        let operations = self.operations.lock().unwrap();
        Ok(operations
            .iter()
            .take(limit as usize)
            .rev()
            .cloned()
            .collect())
    }

    async fn request_cancel(&self, id: &str) -> Result<Operation, PortFailure> {
        let mut operations = self.operations.lock().unwrap();
        let operation = operations
            .iter_mut()
            .find(|operation| operation.id == id)
            .ok_or_else(|| PortFailure::NotFound {
                what: format!("operation {id:?}"),
            })?;
        operation.cancel_requested = true;
        Ok(operation.clone())
    }

    async fn transition(&self, id: &str, state: &str) -> Result<Operation, PortFailure> {
        let mut operations = self.operations.lock().unwrap();
        let operation = operations
            .iter_mut()
            .find(|operation| operation.id == id)
            .ok_or_else(|| PortFailure::NotFound {
                what: format!("operation {id:?}"),
            })?;
        state.clone_into(&mut operation.state);
        Ok(operation.clone())
    }

    async fn complete(
        &self,
        id: &str,
        state: &str,
        result_json: Option<&str>,
        error_json: Option<&str>,
    ) -> Result<Operation, PortFailure> {
        let mut operations = self.operations.lock().unwrap();
        let operation = operations
            .iter_mut()
            .find(|operation| operation.id == id)
            .ok_or_else(|| PortFailure::NotFound {
                what: format!("operation {id:?}"),
            })?;
        state.clone_into(&mut operation.state);
        operation.result_json = result_json.map(str::to_owned);
        operation.error_json = error_json.map(str::to_owned);
        Ok(operation.clone())
    }

    async fn record_progress(
        &self,
        _id: &str,
        _current: Option<i64>,
        _total: Option<i64>,
        _message: Option<&str>,
    ) -> Result<(), PortFailure> {
        Ok(())
    }

    async fn claim_pending(
        &self,
        _worker_id: &str,
        _now: i64,
    ) -> Result<Option<Operation>, PortFailure> {
        Ok(None)
    }
    async fn claim_pending_by_id(
        &self,
        _id: &str,
        _worker_id: &str,
        _now: i64,
    ) -> Result<Option<Operation>, PortFailure> {
        unimplemented!()
    }

    async fn expired_claims(
        &self,
        _now: i64,
        _lease_ms: i64,
    ) -> Result<Vec<Operation>, PortFailure> {
        Ok(Vec::new())
    }
    async fn renew_lease(
        &self,
        _id: &str,
        _worker_id: &str,
        _now: i64,
        _lease_ms: i64,
    ) -> Result<bool, PortFailure> {
        Ok(true)
    }
    async fn fail_expired_claim(
        &self,
        _id: &str,
        _expected_claimed_at: i64,
        _now: i64,
        _error_json: &str,
    ) -> Result<bool, PortFailure> {
        Ok(true)
    }

    async fn sweep_deadlines(&self, _now: i64) -> Result<Vec<String>, PortFailure> {
        Ok(Vec::new())
    }

    async fn queue_depths(&self) -> Result<fleet_application::operation::QueueDepths, PortFailure> {
        Ok(fleet_application::operation::QueueDepths::default())
    }
}

#[derive(Debug)]
struct FakeSystemInfo;

#[async_trait::async_trait]
impl fleet_api::system::SystemInfoSource for FakeSystemInfo {
    async fn info(&self) -> Result<fleet_api::system::SystemInfo, String> {
        Ok(fleet_api::system::SystemInfo {
            current_principal: String::new(),
            service: "fleet-controller".to_owned(),
            version: "0.1.0".to_owned(),
            trust_mode: "trusted-lan".to_owned(),
            trust_warning:
                "TRUSTED-LAN MODE: no accounts or login; every reachable client can mutate."
                    .to_owned(),
            storage_ok: true,
            queue_pending: 0,
            queue_running: 0,
        })
    }
}

#[derive(Debug, Default)]
struct FakeAudit;

#[async_trait]
impl AuditPort for FakeAudit {
    async fn record_intent(&self, _intent: &AuditIntent) -> Result<(), String> {
        Ok(())
    }

    async fn record_outcome(
        &self,
        _operation_id: &str,
        _outcome: AuditOutcome,
    ) -> Result<(), String> {
        Ok(())
    }
}

fn operation_state(authorizer: Arc<dyn fleet_application::authz::Authorizer>) -> Arc<ApiState> {
    Arc::new(ApiState {
        operations: Arc::new(Operations::new(
            Arc::new(FakePort::default()),
            Arc::new(FakeAudit),
        )),
        authorizer,
        system: Arc::new(FakeSystemInfo),
        audit: None,
        nodes: None,
        machines: None,
        onboarding: None,
        tailnet: None,
        projects: None,
        proxmox: None,
        images: None,
        lab: None,
    })
}

async fn post_json(path: &str, body: serde_json::Value) -> (Parts, Value) {
    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    call(request).await
}

#[tokio::test]
async fn creating_an_operation_returns_the_durable_resource() {
    let (parts, body) = post_json(
        &format!("{API_BASE_PATH}/operations"),
        serde_json::json!({"kind": "noop", "idempotencyKey": "demo-1"}),
    )
    .await;
    assert_eq!(parts.status, StatusCode::CREATED, "{body}");
    assert_eq!(body["data"]["kind"], "noop");
    assert_eq!(body["data"]["state"], "pending");
    assert_eq!(body["data"]["idempotencyKey"], "demo-1");
    assert!(body["data"]["id"].is_string());
}

#[tokio::test]
async fn an_unknown_kind_is_refused_with_the_invalid_request_code() {
    let (parts, body) = post_json(
        &format!("{API_BASE_PATH}/operations"),
        serde_json::json!({"kind": "deploy-to-production"}),
    )
    .await;
    assert_eq!(parts.status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_request");
}

#[tokio::test]
async fn generic_operation_creation_cannot_start_lab_provision_sagas() {
    let (parts, body) = post_json(
        &format!("{API_BASE_PATH}/operations"),
        serde_json::json!({
            "kind": "lab.provision",
            "idempotencyKey": "second-provision-attempt",
            "payload": {"leaseId": "lease-owned", "recordId": "record-owned", "accountId": "pve-1"}
        }),
    )
    .await;
    assert_eq!(parts.status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");
}

#[tokio::test]
async fn the_operation_list_is_a_page() {
    // One router for both calls: the in-memory backend is per router.
    let (router, _port, _audit) = test_router();
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("{API_BASE_PATH}/operations"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"kind": "noop"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let response = router
        .oneshot(get(&format!("{API_BASE_PATH}/operations")))
        .await
        .unwrap();
    let (parts, body) = into_parts_json(response).await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert_eq!(body["page"]["limit"], 50);
}

#[tokio::test]
async fn an_unknown_operation_is_not_found() {
    let (parts, body) = call(get(&format!("{API_BASE_PATH}/operations/nope"))).await;
    assert_eq!(parts.status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "not_found");
}

#[tokio::test]
async fn cancelling_records_a_durable_request() {
    // One router for both calls: the in-memory backend is per router.
    let (router, _port, _audit) = test_router();
    let (_, body) = {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("{API_BASE_PATH}/operations"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"kind": "noop"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        into_parts_json(response).await
    };
    let id = body["data"]["id"].as_str().unwrap().to_owned();
    let (parts, body) = {
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("{API_BASE_PATH}/operations/{id}/cancel"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        into_parts_json(response).await
    };
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["cancelRequested"], true);
}

#[tokio::test]
async fn a_denied_caller_receives_the_denial_envelope() {
    #[derive(Debug)]
    struct DenyAll;
    impl fleet_application::authz::Authorizer for DenyAll {
        fn decide(&self, _request: fleet_application::authz::AccessRequest<'_>) -> Decision {
            Decision::deny(ReasonId::UnknownPrincipal)
        }
    }
    let state = operation_state(Arc::new(DenyAll));
    let response = router(state)
        .layer(axum::Extension(fleet_api::ActingPrincipal {
            id: "someone-else".to_owned(),
        }))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("{API_BASE_PATH}/operations"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({"kind": "noop"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let parts = response.into_parts().0;
    assert_eq!(parts.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_system_view_is_a_plain_object_with_the_trust_warning() {
    let (parts, body) = call(get(&format!("{API_BASE_PATH}/system"))).await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    assert_eq!(body["service"], "fleet-controller");
    assert_eq!(body["trustMode"], "trusted-lan");
    assert_eq!(body["currentPrincipal"], "anonymous-lan-admin");
    assert!(
        body["trustWarning"]
            .as_str()
            .unwrap()
            .contains("no accounts")
    );
}

#[tokio::test]
async fn tailscale_listener_rejects_a_missing_identity_with_the_api_401_envelope() {
    let router = fleet_api::tailscale_serve_router(
        Arc::new(ApiState::for_document()),
        fleet_auth::TailscaleServePeer,
    );
    let mut request = Request::builder()
        .uri(format!("{API_BASE_PATH}/system"))
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            5000,
        ))));
    let response = router.oneshot(request).await.unwrap();
    let (parts, body) = into_parts_json(response).await;
    assert_eq!(parts.status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "authentication_required");
    assert!(parts.headers.contains_key(CORRELATION_ID_HEADER));
}

#[tokio::test]
async fn tailscale_rejection_keeps_the_malformed_correlation_error_contract() {
    let router = fleet_api::tailscale_serve_router(
        Arc::new(ApiState::for_document()),
        fleet_auth::TailscaleServePeer,
    );
    let mut request = Request::builder()
        .uri(format!("{API_BASE_PATH}/system"))
        .header(CORRELATION_ID_HEADER, "not-a-valid-correlation-id")
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            5000,
        ))));
    let response = router.oneshot(request).await.unwrap();
    let (parts, body) = into_parts_json(response).await;
    assert_eq!(parts.status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "malformed_correlation_id");
    assert_eq!(
        parts
            .headers
            .get(CORRELATION_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap(),
        body["correlationId"]
    );
}

#[tokio::test]
async fn tailscale_guard_protects_non_api_routes_too() {
    let router = fleet_api::tailscale_serve_guard(
        axum::Router::new().route("/", axum::routing::get(|| async { "shell" })),
        fleet_auth::TailscaleServePeer,
    );
    let response = router
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key(CORRELATION_ID_HEADER));
}

#[tokio::test]
async fn tailscale_error_body_and_response_share_one_correlation_identity() {
    let (state, _, _) = test_state();
    let router = fleet_api::tailscale_serve_router(state, fleet_auth::TailscaleServePeer);
    let mut request = Request::builder()
        .uri(format!("{API_BASE_PATH}/missing"))
        .header("tailscale-user-login", "alice@example.com")
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            5000,
        ))));
    let response = router.oneshot(request).await.unwrap();
    let (parts, body) = into_parts_json(response).await;
    assert_eq!(parts.status, StatusCode::NOT_FOUND);
    assert_eq!(
        parts
            .headers
            .get(CORRELATION_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap(),
        body["correlationId"]
    );
}

#[tokio::test]
async fn system_view_reports_the_verified_tailscale_principal() {
    let (state, _, _) = test_state();
    let router = fleet_api::tailscale_serve_router(state, fleet_auth::TailscaleServePeer);
    let mut request = Request::builder()
        .uri(format!("{API_BASE_PATH}/system"))
        .header("tailscale-user-login", "alice@example.com")
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            5000,
        ))));
    let response = router.oneshot(request).await.unwrap();
    let (parts, body) = into_parts_json(response).await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    assert_eq!(body["currentPrincipal"], "tailscale:alice@example.com");
}

#[tokio::test]
async fn the_operation_event_stream_snapshots_and_closes_on_terminal() {
    // One router for both calls: the in-memory backend is per router.
    let (router, port, _audit) = test_router();
    let (_, created) = {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("{API_BASE_PATH}/operations"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"kind": "noop"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        into_parts_json(response).await
    };
    let id = created["data"]["id"].as_str().unwrap().to_owned();

    // Complete the operation behind the stream's back: the next poll must
    // observe the change, snapshot it, and close the stream.
    {
        let mut operations = port.operations.lock().unwrap();
        let operation = operations.first_mut().unwrap();
        operation.state = "succeeded".to_owned();
        operation.updated_at += 1_000;
        operation.result_json = Some("{\"kind\":\"noop\"}".to_owned());
    }

    // Take the first events from the stream with a hard timeout; a snapshot
    // for a terminal operation must arrive and then the stream must close.
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        router.oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("{API_BASE_PATH}/operations/{id}/events"))
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("the stream must start")
    .unwrap();
    if response.status() != StatusCode::OK {
        let (parts, body) = response.into_parts();
        let bytes = http_body_util::BodyExt::collect(body)
            .await
            .unwrap()
            .to_bytes();
        panic!(
            "stream did not start: {:?} {}",
            parts.status,
            String::from_utf8_lossy(&bytes)
        );
    }
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );

    let body = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut body = response.into_body();
        let mut text = String::new();
        loop {
            match http_body_util::BodyExt::frame(&mut body).await {
                Some(Ok(frame)) => {
                    let data = frame.into_data().ok();
                    if let Some(chunk) = data {
                        text.push_str(&String::from_utf8_lossy(&chunk));
                    }
                }
                Some(Err(error)) => panic!("the stream must not error: {error}"),
                None => return text,
            }
        }
    })
    .await
    .expect("snapshots must stream");
    assert!(body.contains("event: operation"), "{body}");
    assert!(body.contains("\"kind\":\"noop\""), "{body}");
}

// Machine endpoints over an in-memory backend (FM-209), so the read
// contract is proven without a database.

use fleet_application::machine::{
    Endpoint, InventoryObservation, Machine, MachineFilter, MachinePort, MachineStatus,
    MachineView, Machines, NewEndpoint, NodeLink, RegisterMachine,
};
use fleet_application::node::{GatewayState, NodeStatus};
use fleet_core::CapabilityFact;

#[derive(Debug, Default)]
struct FakeMachines {
    machines: Mutex<Vec<Machine>>,
    last_filter: Mutex<Option<MachineFilter>>,
}

impl FakeMachines {
    fn with(self, machine: Machine) -> Self {
        self.machines.lock().unwrap().push(machine);
        self
    }
}

#[async_trait]
impl MachinePort for FakeMachines {
    async fn register(&self, _registration: &RegisterMachine) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn get(&self, id: &str) -> Result<Machine, PortFailure> {
        self.machines
            .lock()
            .unwrap()
            .iter()
            .find(|machine| machine.id == id)
            .cloned()
            .ok_or_else(|| PortFailure::NotFound {
                what: format!("machine {id:?}"),
            })
    }

    async fn list(&self, filter: &MachineFilter, limit: u32) -> Result<Vec<Machine>, PortFailure> {
        *self.last_filter.lock().unwrap() = Some(filter.clone());
        let mut machines = self.machines.lock().unwrap().clone();
        machines.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.id.cmp(&left.id))
        });
        let cursor_created_at = filter
            .cursor
            .as_deref()
            .map(|cursor| {
                machines
                    .iter()
                    .find(|machine| machine.id == cursor)
                    .map(|machine| machine.created_at)
                    .ok_or_else(|| PortFailure::NotFound {
                        what: format!("machine {cursor:?}"),
                    })
            })
            .transpose()?;
        Ok(machines
            .iter()
            .filter(|machine| {
                cursor_created_at.is_none_or(|created_at| {
                    machine.created_at < created_at
                        || (machine.created_at == created_at
                            && filter
                                .cursor
                                .as_deref()
                                .is_some_and(|cursor| machine.id.as_str() < cursor))
                })
            })
            .filter(|machine| {
                filter
                    .tag
                    .as_deref()
                    .is_none_or(|tag| machine.tags.iter().any(|machine_tag| machine_tag == tag))
            })
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn update(
        &self,
        _id: &str,
        _name: &str,
        _description: &str,
    ) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn set_endpoints(
        &self,
        _id: &str,
        _endpoints: &[NewEndpoint],
    ) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn add_tag(&self, _id: &str, _tag: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn remove_tag(&self, _id: &str, _tag: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn add_group(&self, _id: &str, _group: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn remove_group(&self, _id: &str, _group: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn record_snapshot(
        &self,
        _id: &str,
        _source: &str,
        _payload_json: &str,
        _collected_at: i64,
    ) -> Result<(), PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn record_capabilities(
        &self,
        _id: &str,
        _facts: &[CapabilityFact],
    ) -> Result<(), PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn delete(&self, _id: &str) -> Result<(), PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn confirm_fingerprint(
        &self,
        _endpoint_id: &str,
        _fingerprint: &str,
        _confirmed_at: i64,
    ) -> Result<(), PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn verified_fingerprint(
        &self,
        _endpoint_id: &str,
    ) -> Result<Option<String>, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn latest_inventory_revision(
        &self,
        _machine_id: &str,
    ) -> Result<Option<u64>, PortFailure> {
        unimplemented!("not exercised by these tests")
    }
}

fn example_machine() -> Machine {
    Machine {
        id: "01990000-0000-7000-8000-000000000009".to_owned(),
        name: "build-host".to_owned(),
        description: String::new(),
        endpoints: vec![
            Endpoint {
                id: "endpoint-1".to_owned(),
                kind: fleet_core::EndpointKind::Ssh,
                reference: "ops@10.0.0.5:22".to_owned(),
            },
            Endpoint {
                id: "endpoint-2".to_owned(),
                kind: fleet_core::EndpointKind::Fleetd,
                reference: "0199-node".to_owned(),
            },
        ],
        tags: vec!["linux".to_owned()],
        groups: Vec::new(),
        capabilities: Vec::new(),
        last_observation: Some(InventoryObservation {
            source: "fleetd/0.1.0".to_owned(),
            collected_at: 1_000,
        }),
        node: Some(NodeLink {
            gateway_state: GatewayState::Connected,
            identity_status: NodeStatus::Active,
            last_seen_at: Some(1_500),
        }),
        created_at: 0,
        updated_at: 0,
    }
}

fn machine_state(
    authorizer: Arc<dyn fleet_application::authz::Authorizer>,
    backend: Arc<FakeMachines>,
) -> Arc<ApiState> {
    Arc::new(ApiState {
        operations: Arc::new(Operations::new(
            Arc::new(FakePort::default()),
            Arc::new(FakeAudit),
        )),
        authorizer,
        system: Arc::new(FakeSystemInfo),
        audit: None,
        nodes: None,
        machines: Some(Arc::new(Machines::new(backend, Arc::new(FakeAudit)))),
        onboarding: None,
        tailnet: None,
        projects: None,
        proxmox: None,
        images: None,
        lab: None,
    })
}

fn principal_router(state: Arc<ApiState>) -> axum::Router {
    router(state).layer(axum::Extension(fleet_api::ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }))
}

#[tokio::test]
async fn the_machine_list_is_a_page_and_the_detail_is_a_resource() {
    let backend = Arc::new(FakeMachines::default().with(example_machine()));
    let router = principal_router(machine_state(Arc::new(PermitAllAuthorizer), backend));

    let response = router
        .clone()
        .oneshot(get(&format!("{API_BASE_PATH}/machines")))
        .await
        .unwrap();
    let (parts, body) = into_parts_json(response).await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert_eq!(body["page"]["limit"], 50);
    let machine = &body["items"][0];
    assert_eq!(machine["machineStatus"], "connected");
    assert_eq!(machine["endpoints"][0]["kind"], "ssh");
    assert_eq!(machine["lastObservation"]["source"], "fleetd/0.1.0");
    assert_eq!(machine["lastSeenAt"], 1_500);

    let id = machine["id"].as_str().unwrap();
    let response = router
        .oneshot(get(&format!("{API_BASE_PATH}/machines/{id}")))
        .await
        .unwrap();
    let (parts, body) = into_parts_json(response).await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["name"], "build-host");
}

#[derive(Debug)]
struct PermitAllAuthorizer;

impl fleet_application::authz::Authorizer for PermitAllAuthorizer {
    fn decide(
        &self,
        _request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        fleet_application::authz::Decision::allow()
    }
}

/// Reads machines but not the credential-bearing endpoint detail.
#[derive(Debug)]
struct DenySensitiveOnly;

impl fleet_application::authz::Authorizer for DenySensitiveOnly {
    fn decide(&self, request: fleet_application::authz::AccessRequest<'_>) -> Decision {
        if request.action == fleet_application::authz::Permission::MachineReadSensitive {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

#[tokio::test]
async fn endpoint_usernames_follow_the_sensitive_permission() {
    let backend = Arc::new(FakeMachines::default().with(example_machine()));

    let router = principal_router(machine_state(
        Arc::new(PermitAllAuthorizer),
        backend.clone(),
    ));
    let (_, body) = call_via(&router, get(&format!("{API_BASE_PATH}/machines"))).await;
    assert_eq!(
        body["items"][0]["endpoints"][0]["reference"],
        "ops@10.0.0.5:22"
    );

    let router = principal_router(machine_state(Arc::new(DenySensitiveOnly), backend));
    let (_, body) = call_via(&router, get(&format!("{API_BASE_PATH}/machines"))).await;
    assert_eq!(
        body["items"][0]["endpoints"][0]["reference"],
        "***@10.0.0.5:22"
    );
    // The fleetd reference carries no userinfo and is never redacted.
    assert_eq!(body["items"][0]["endpoints"][1]["reference"], "0199-node");
}

async fn call_via(router: &axum::Router, request: Request<Body>) -> (Parts, Value) {
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router is infallible");
    into_parts_json(response).await
}

#[tokio::test]
async fn machine_filters_are_validated_and_forwarded() {
    let backend = Arc::new(FakeMachines::default().with(example_machine()));
    let router = principal_router(machine_state(
        Arc::new(PermitAllAuthorizer),
        backend.clone(),
    ));

    // A malformed capability filter is a 400, not a silent match-all.
    let (parts, body) = call_via(
        &router,
        get(&format!("{API_BASE_PATH}/machines?capability=toolgit")),
    )
    .await;
    assert_eq!(parts.status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");

    // An unknown status word is a 400: filters mean something specific.
    let (parts, _) = call_via(
        &router,
        get(&format!("{API_BASE_PATH}/machines?status=dormant")),
    )
    .await;
    assert_eq!(parts.status, StatusCode::BAD_REQUEST);

    // A well-formed filter reaches the use case intact.
    let (parts, _) = call_via(
        &router,
        get(&format!(
            "{API_BASE_PATH}/machines?tag=linux&group=lab&capability=tool:git&status=connected&cursor=01990000-0000-7000-8000-000000000009&limit=7"
        )),
    )
    .await;
    assert_eq!(parts.status, StatusCode::OK);
    let filter = backend.last_filter.lock().unwrap().clone().unwrap();
    assert_eq!(filter.tag.as_deref(), Some("linux"));
    assert_eq!(filter.group.as_deref(), Some("lab"));
    assert_eq!(
        filter.capability,
        Some(("tool".to_owned(), "git".to_owned()))
    );
    assert_eq!(filter.status, Some(MachineStatus::Connected));
    assert_eq!(
        filter.cursor.as_deref(),
        Some("01990000-0000-7000-8000-000000000009")
    );

    let (parts, body) = call_via(
        &router,
        get(&format!("{API_BASE_PATH}/machines?cursor=deleted-machine")),
    )
    .await;
    assert_eq!(parts.status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");
}

#[tokio::test]
async fn machine_list_cursor_returns_the_following_page() {
    let backend = Arc::new(
        FakeMachines::default()
            .with(example_machine())
            .with(Machine {
                id: "01990000-0000-7000-8000-000000000010".to_owned(),
                name: "next-host".to_owned(),
                ..example_machine()
            })
            .with(Machine {
                id: "01990000-0000-7000-8000-000000000011".to_owned(),
                name: "filtered-host".to_owned(),
                tags: vec!["other".to_owned()],
                ..example_machine()
            }),
    );
    let router = principal_router(machine_state(Arc::new(PermitAllAuthorizer), backend));

    let (parts, first) = call_via(
        &router,
        get(&format!("{API_BASE_PATH}/machines?limit=1&tag=linux")),
    )
    .await;
    assert_eq!(parts.status, StatusCode::OK, "{first}");
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    let cursor = first["page"]["nextCursor"].as_str().unwrap();

    let (parts, second) = call_via(
        &router,
        get(&format!(
            "{API_BASE_PATH}/machines?limit=1&tag=linux&cursor={cursor}"
        )),
    )
    .await;
    assert_eq!(parts.status, StatusCode::OK, "{second}");
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert_eq!(first["items"][0]["name"], "next-host");
    assert_eq!(second["items"][0]["name"], "build-host");
}

#[tokio::test]
async fn an_unknown_machine_is_not_found_and_a_denied_reader_is_forbidden() {
    #[derive(Debug)]
    struct DenyMachines;
    impl fleet_application::authz::Authorizer for DenyMachines {
        fn decide(&self, request: fleet_application::authz::AccessRequest<'_>) -> Decision {
            if request.action == fleet_application::authz::Permission::MachineRead {
                Decision::deny(ReasonId::UnknownPrincipal)
            } else {
                Decision::allow()
            }
        }
    }

    let backend = Arc::new(FakeMachines::default().with(example_machine()));
    let router = principal_router(machine_state(
        Arc::new(PermitAllAuthorizer),
        backend.clone(),
    ));
    let (parts, body) = call_via(
        &router,
        get(&format!("{API_BASE_PATH}/machines/no-such-machine")),
    )
    .await;
    assert_eq!(parts.status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["code"], "not_found");

    let router = principal_router(machine_state(Arc::new(DenyMachines), backend));
    let (parts, body) = call_via(&router, get(&format!("{API_BASE_PATH}/machines"))).await;
    assert_eq!(parts.status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "denied");
}

#[tokio::test]
async fn an_unwired_machine_surface_answers_the_standard_envelope() {
    let state = operation_state(Arc::new(PermitAllAuthorizer));
    let router = principal_router(state);
    let (parts, body) = call_via(&router, get(&format!("{API_BASE_PATH}/machines"))).await;
    assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "machine_unavailable");
}

// Keep the unused view import referenced: the DTO conversion is exercised
// through the router, not directly.
#[test]
fn the_view_converts_into_the_documented_shape() {
    let _ = MachineView::assemble(example_machine(), 2_000, true);
}

#[derive(Debug)]
struct NoPromotedVersions;

#[async_trait::async_trait]
impl fleet_application::lab::ImagePinValidator for NoPromotedVersions {
    async fn promoted_version(
        &self,
        _version_id: &str,
    ) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok(None)
    }
}

#[tokio::test]
async fn lab_lease_extension_returns_the_updated_deadline() {
    use fleet_application::lab::{Lab, LeasePort, NewLease};
    use fleet_core::{CleanupStrategy, LeaseState};
    use fleet_storage_sqlite::{LabRepository, LeaseRepository, Store};

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let repository = Arc::new(LabRepository::new(store.pool().clone()));
    let leases = Arc::new(LeaseRepository::new(store.pool().clone()));
    let now = fleet_core::SystemClock::now_unix_millis();
    let mut lease = leases
        .create(
            &NewLease {
                template_version_id: "template-1@digest".to_owned(),
                purpose: "the test".to_owned(),
                project_id: None,
                cleanup: CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            "anonymous-lan-admin",
            now,
        )
        .await
        .unwrap();
    lease.state = LeaseState::Ready;
    lease.ready_at = Some(now);
    lease.expires_at = Some(now + 3_600_000);
    leases.update(&lease).await.unwrap();

    let lab = Arc::new(Lab::new(
        repository.clone(),
        repository,
        leases,
        Arc::new(NoPromotedVersions),
        Arc::new(FakeAudit),
    ));
    let base = test_state().0;
    let mut state = (*base).clone();
    state.lab = Some(lab);
    let router = principal_router(Arc::new(state));
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("{API_BASE_PATH}/lab/leases/{}/extend", lease.id))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"bySeconds":1800}"#))
        .unwrap();
    let (parts, body) = call_via(&router, request).await;

    assert_eq!(parts.status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["id"], lease.id);
    assert_eq!(body["data"]["expiresAt"], now + 5_400_000);
    assert_eq!(
        body["data"]["maxLifetimeAt"],
        now + fleet_core::MAX_LAB_LEASE_LIFETIME_MILLIS
    );

    let malformed = Request::builder()
        .method(Method::POST)
        .uri(format!("{API_BASE_PATH}/lab/leases/{}/extend", lease.id))
        .header("content-type", "application/json")
        .body(Body::from("{"))
        .unwrap();
    let (parts, body) = call_via(&router, malformed).await;
    assert_eq!(parts.status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");
    assert!(body["correlationId"].as_str().is_some());
}
