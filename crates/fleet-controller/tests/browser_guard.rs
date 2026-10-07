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
        artifacts_dir: None,
        tailscale_serve_listen: None,
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
    let router = build_router(
        &settings(dist.path()),
        Some(store.pool().clone()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
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

/// A shell built with Vite's `html.cspNonce` placeholder, as `apps/web` is.
fn nonce_shell_dist() -> tempfile::TempDir {
    let dist = tempfile::tempdir().unwrap();
    std::fs::write(
        dist.path().join("index.html"),
        format!(
            "<html><head><meta property=\"csp-nonce\" nonce=\"{0}\">\
             <link rel=\"stylesheet\" nonce=\"{0}\" href=\"/assets/app.css\"></head></html>",
            fleet_controller::browser::CSP_NONCE_PLACEHOLDER
        ),
    )
    .unwrap();
    dist
}

async fn get_shell(router: axum::Router, uri: &str) -> (Parts, String) {
    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("host", HOST)
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    (parts, String::from_utf8(body.to_vec()).unwrap())
}

/// The nonce the policy allows, read back from a response's CSP.
fn policy_nonce(parts: &Parts) -> String {
    let csp = parts
        .headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(!csp.contains("unsafe-inline"), "{csp}");
    let (_, rest) = csp
        .split_once("style-src 'self' 'nonce-")
        .unwrap_or_else(|| panic!("no style nonce in {csp}"));
    rest.split_once('\'').unwrap().0.to_owned()
}

#[tokio::test]
async fn the_shell_gets_a_fresh_style_nonce_on_every_response() {
    let dist = nonce_shell_dist();
    let router = build_router(
        &settings(dist.path()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let mut nonces = Vec::new();
    // The static index, the explicit file, and an SPA deep link (served from
    // the cached shell) all carry the placeholder.
    for uri in ["/", "/index.html", "/images", "/"] {
        let (parts, body) = get_shell(router.clone(), uri).await;
        assert_eq!(parts.status, StatusCode::OK, "{uri}");
        let nonce = policy_nonce(&parts);
        assert!(
            !body.contains(fleet_controller::browser::CSP_NONCE_PLACEHOLDER),
            "{uri}: {body}"
        );
        // The meta tag and the stylesheet link both carry the policy's nonce.
        assert_eq!(
            body.matches(&format!("nonce=\"{nonce}\"")).count(),
            2,
            "{uri}: {body}"
        );
        assert_eq!(
            parts.headers.get("content-length").unwrap(),
            &body.len().to_string(),
            "{uri}"
        );
        assert_eq!(
            parts.headers.get("cache-control").unwrap(),
            "no-store",
            "{uri}"
        );
        assert!(parts.headers.get("etag").is_none(), "{uri}");
        assert!(parts.headers.get("last-modified").is_none(), "{uri}");
        assert_eq!(parts.headers.get("x-frame-options").unwrap(), "DENY");
        nonces.push(nonce);
    }
    nonces.sort();
    nonces.dedup();
    assert_eq!(nonces.len(), 4, "every response must get its own nonce");
}

#[tokio::test]
async fn responses_without_the_placeholder_keep_the_static_policy() {
    let (router, _dirs) = router_with_db().await;
    for uri in ["/", "/api/v1/meta"] {
        let (parts, _) = get_shell(router.clone(), uri).await;
        assert_eq!(parts.status, StatusCode::OK, "{uri}");
        assert_eq!(
            parts.headers.get("content-security-policy").unwrap(),
            "default-src 'self'; img-src 'self' data:; style-src 'self'",
            "{uri}"
        );
    }

    // The placeholder-less shell is passed through byte for byte, with the
    // static service's length and validators intact.
    let (parts, body) = get_shell(router, "/").await;
    assert_eq!(body, "<html>fleet</html>");
    assert_eq!(
        parts.headers.get("content-length").unwrap(),
        &body.len().to_string()
    );
    assert!(parts.headers.get("cache-control").is_none());
    assert!(parts.headers.get("etag").is_some());
    assert!(parts.headers.get("last-modified").is_some());
}

#[tokio::test]
async fn a_head_of_the_shell_describes_the_rewritten_page() {
    let dist = nonce_shell_dist();
    let router = build_router(
        &settings(dist.path()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let (_, get_body) = get_shell(router.clone(), "/").await;
    for uri in ["/", "/images"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri(uri)
                    .header("host", HOST)
                    .header("accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::OK, "{uri}");
        policy_nonce(&parts);
        assert_eq!(
            parts.headers.get("content-length").unwrap(),
            &get_body.len().to_string(),
            "{uri}"
        );
        assert_eq!(
            parts.headers.get("cache-control").unwrap(),
            "no-store",
            "{uri}"
        );
        assert!(parts.headers.get("etag").is_none(), "{uri}");
        assert!(parts.headers.get("last-modified").is_none(), "{uri}");
        assert!(body.collect().await.unwrap().to_bytes().is_empty(), "{uri}");
    }
}

#[tokio::test]
async fn html_too_large_to_be_the_shell_passes_through_untouched() {
    let dist = tempfile::tempdir().unwrap();
    let big = format!(
        "<html>{}{}</html>",
        fleet_controller::browser::CSP_NONCE_PLACEHOLDER,
        "x".repeat(2 * 1024 * 1024)
    );
    std::fs::write(dist.path().join("index.html"), &big).unwrap();
    let router = build_router(
        &settings(dist.path()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let (parts, body) = get_shell(router, "/").await;
    assert_eq!(parts.status, StatusCode::OK);
    assert_eq!(body, big);
    assert_eq!(
        parts.headers.get("content-security-policy").unwrap(),
        "default-src 'self'; img-src 'self' data:; style-src 'self'"
    );
}
