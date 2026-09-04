//! HTTP contract tests.
//!
//! These drive the real router rather than calling handler functions, because
//! the parts most likely to be wrong — the correlation middleware, the status
//! codes, the fallback — are not in the handlers.

use axum::{
    body::Body,
    http::{Request, StatusCode, response::Parts},
};
use http::Method;
use std::sync::Arc;

use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use http_body_util::BodyExt as _;
use serde_json::Value;
use tower::ServiceExt as _;

const SUPPLIED_CORRELATION_ID: &str = "01900a3c-b576-7287-a004-61d5b384a076";

/// The test router: the in-memory operation state plus a resolved LAN
/// principal, as the controller's caller middleware provides in production.
/// The fake backend is returned so tests can drive its state directly.
fn test_router() -> (axum::Router, Arc<FakePort>) {
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
    let state = Arc::new(ApiState {
        operations: Arc::new(Operations::new(port.clone(), Arc::new(FakeAudit))),
        authorizer: Arc::new(PermitAll),
        system: Arc::new(FakeSystemInfo),
        nodes: None,
    });
    (
        router(state).layer(axum::Extension(fleet_api::ActingPrincipal {
            id: "anonymous-lan-admin".to_owned(),
        })),
        port,
    )
}

async fn call(request: Request<Body>) -> (Parts, Value) {
    let (router, _port) = test_router();
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
use fleet_application::audit::{AuditIntent, AuditOutcome};
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

    async fn expired_claims(
        &self,
        _now: i64,
        _lease_ms: i64,
    ) -> Result<Vec<Operation>, PortFailure> {
        Ok(Vec::new())
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
        nodes: None,
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
async fn the_operation_list_is_a_page() {
    // One router for both calls: the in-memory backend is per router.
    let (router, _port) = test_router();
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
    let (router, _port) = test_router();
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
    assert!(
        body["trustWarning"]
            .as_str()
            .unwrap()
            .contains("no accounts")
    );
}

#[tokio::test]
async fn the_operation_event_stream_snapshots_and_closes_on_terminal() {
    // One router for both calls: the in-memory backend is per router.
    let (router, port) = test_router();
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
