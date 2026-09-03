//! The browser-protection matrix: cross-site mutations fail, same-origin
//! web/API use works, CLI calls without an Origin pass, proxy headers cannot
//! forge same-origin, and the security headers are on every response.

use axum::{
    body::Body,
    http::{Request, StatusCode, response::Parts},
};
use fleet_controller::build_router;
use http_body_util::BodyExt as _;
use serde_json::Value;
use sqlx::SqlitePool;
use std::path::Path;
use tower::ServiceExt as _;

const HOST: &str = "box.lan:8080";

fn settings(web_dist: &Path) -> fleet_controller::Settings {
    fleet_controller::Settings {
        listen: "127.0.0.1:0".parse().unwrap(),
        web_dist: web_dist.to_path_buf(),
    }
}

fn shell_dist() -> tempfile::TempDir {
    let dist = tempfile::tempdir().unwrap();
    std::fs::write(dist.path().join("index.html"), "<html>fleet</html>").unwrap();
    dist
}

/// The router plus the directories it needs: both must outlive the router,
/// so they are returned to the test body.
async fn router_with_db() -> (axum::Router, Vec<tempfile::TempDir>) {
    let dist = shell_dist();
    let dir = tempfile::tempdir().unwrap();
    let store = fleet_storage_sqlite::Store::open(&dir.path().join("fleet.db"))
        .await
        .unwrap();
    let router = build_router(&settings(dist.path()), Some(store.pool().clone()));
    (router, vec![dist, dir])
}

async fn send(router: axum::Router, request: Request<Body>) -> (Parts, Value) {
    let response = router
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
        serde_json::from_slice(&bytes).expect("every API response body is JSON")
    };
    (parts, json)
}

fn post(path: &str, host: &str, origin: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("host", host)
        .header("content-type", "application/json");
    if let Some(origin) = origin {
        builder = builder.header("origin", origin);
    }
    builder.body(Body::from("{\"kind\":\"noop\"}")).unwrap()
}

#[tokio::test]
async fn a_cross_site_mutation_is_refused_with_the_error_envelope() {
    let (router, _dirs) = router_with_db().await;
    let (parts, body) = send(
        router,
        post("/api/v1/operations", HOST, Some("http://evil.example")),
    )
    .await;
    assert_eq!(parts.status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "cross_origin_mutation");
}

#[tokio::test]
async fn a_same_origin_browser_mutation_is_allowed() {
    let (router, _dirs) = router_with_db().await;
    let (parts, body) = send(
        router,
        post("/api/v1/operations", HOST, Some(&format!("http://{HOST}"))),
    )
    .await;
    assert_eq!(parts.status, StatusCode::CREATED, "{body}");
    assert_eq!(body["data"]["kind"], "noop");
}

#[tokio::test]
async fn a_cli_mutation_without_an_origin_is_allowed() {
    let (router, _dirs) = router_with_db().await;
    let (parts, body) = send(router, post("/api/v1/operations", HOST, None)).await;
    assert_eq!(parts.status, StatusCode::CREATED, "{body}");
    assert_eq!(body["data"]["kind"], "noop");
}

#[tokio::test]
async fn a_forged_proxy_header_cannot_make_a_foreign_origin_same_origin() {
    let (router, _dirs) = router_with_db().await;
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/operations")
        .header("host", "evil.example")
        .header("origin", "http://box.lan:8080")
        .header("x-forwarded-host", HOST)
        .header("content-type", "application/json")
        .body(Body::from("{\"kind\":\"noop\"}"))
        .unwrap();
    let (parts, body) = send(router, request).await;
    assert_eq!(parts.status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn reads_are_not_guarded_and_carry_the_security_headers() {
    let (router, _dirs) = router_with_db().await;
    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/meta")
        .header("host", HOST)
        .header("origin", "http://evil.example")
        .body(Body::empty())
        .unwrap();
    let (parts, _) = send(router, request).await;
    assert_eq!(parts.status, StatusCode::OK);
    assert_eq!(
        parts.headers.get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(parts.headers.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(parts.headers.get("referrer-policy").unwrap(), "no-referrer");
    let csp = parts.headers.get("content-security-policy").unwrap();
    assert!(csp.to_str().unwrap().contains("default-src 'self'"));
}

#[tokio::test]
async fn the_web_shell_carries_the_security_headers_too() {
    let (router, _dirs) = router_with_db().await;
    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/")
                .header("host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
}

#[tokio::test]
async fn a_cross_origin_preflight_is_not_approved() {
    let (router, _dirs) = router_with_db().await;
    let request = Request::builder()
        .method("OPTIONS")
        .uri("/api/v1/operations")
        .header("host", HOST)
        .header("origin", "http://evil.example")
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    // No CORS approval headers exist anywhere in this deployment; a foreign
    // browser's preflight therefore fails on its own.
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
    let _ = response.into_parts().0.status;
    let _: Option<SqlitePool> = None;
}
