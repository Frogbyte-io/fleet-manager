//! HTTP contract tests.
//!
//! These drive the real router rather than calling handler functions, because
//! the parts most likely to be wrong — the correlation middleware, the status
//! codes, the fallback — are not in the handlers.

use axum::{
    body::Body,
    http::{Request, StatusCode, response::Parts},
};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, router};
use http_body_util::BodyExt as _;
use serde_json::Value;
use tower::ServiceExt as _;

const SUPPLIED_CORRELATION_ID: &str = "01900a3c-b576-7287-a004-61d5b384a076";

async fn call(request: Request<Body>) -> (Parts, Value) {
    let response = router()
        .oneshot(request)
        .await
        .expect("the router is infallible");
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
