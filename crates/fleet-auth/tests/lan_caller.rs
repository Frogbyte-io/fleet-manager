//! Exercises the trusted-LAN caller resolution: every request resolves to the
//! anonymous LAN principal, network facts stay evidence, and the trust mode
//! carries its warning.

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Request},
    http::Request as HttpRequest,
    middleware::{self as axum_middleware, Next},
    routing::get,
};
use fleet_auth::{LAN_PRINCIPAL_ID, Principal, TrustMode, caller_of, resolve_lan_caller};
use tower::{Service, ServiceExt as _};

const PROXY_VALUES: [(&str, &str); 2] = [
    ("x-forwarded-for", "203.0.113.9"),
    ("x-real-ip", "198.51.100.7"),
];

async fn caller_handler(request: Request) -> String {
    let caller = caller_of(request.extensions()).expect("the middleware resolved a caller");
    format!(
        "{}|{:?}|{:?}",
        caller.principal().id(),
        caller.evidence().remote_addr(),
        caller.evidence().proxy_headers()
    )
}

fn app() -> Router {
    Router::new()
        .route("/whoami", get(caller_handler))
        .layer(axum_middleware::from_fn(resolve_lan_caller))
}

async fn respond(request: HttpRequest<Body>) -> String {
    let response = app()
        .oneshot(request)
        .await
        .expect("the router is infallible");
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("the body is complete");
    String::from_utf8(body.to_vec()).expect("the handler wrote UTF-8")
}

#[tokio::test]
async fn every_request_resolves_to_the_anonymous_lan_admin() {
    let request = HttpRequest::builder()
        .uri("/whoami")
        .body(Body::empty())
        .unwrap();
    let body = respond(request).await;
    let principal = body.split('|').next().unwrap();
    assert_eq!(principal, LAN_PRINCIPAL_ID);
    assert_eq!(principal, "anonymous-lan-admin");
    assert_eq!(Principal::ANONYMOUS_LAN_ADMIN, Principal::AnonymousLanAdmin);
}

#[tokio::test]
async fn proxy_headers_are_evidence_never_identity() {
    let mut request = HttpRequest::builder()
        .uri("/whoami")
        .body(Body::empty())
        .unwrap();
    for (name, value) in PROXY_VALUES {
        request.headers_mut().insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
    }
    let body = respond(request).await;
    let mut parts = body.split('|');
    let principal = parts.next().unwrap();
    let remote = parts.next().unwrap();
    let evidence = parts.next().unwrap();

    // The principal is unchanged by the forged proxy headers.
    assert_eq!(principal, LAN_PRINCIPAL_ID);
    // The headers are recorded, with values, as evidence.
    assert!(evidence.contains("x-forwarded-for"), "{evidence}");
    assert!(evidence.contains("203.0.113.9"), "{evidence}");
    // No peer address was provided, so none is claimed.
    assert_eq!(remote, "None");
}

#[tokio::test]
async fn the_connected_peer_is_evidence_but_still_not_identity() {
    let request = HttpRequest::builder()
        .uri("/whoami")
        .body(Body::empty())
        .unwrap();
    let response = app()
        .oneshot(request)
        .await
        .expect("the router is infallible");
    // Drive the middleware with ConnectInfo present, as axum's
    // into_make_service_with_connect_info would.
    let mut request = HttpRequest::builder()
        .uri("/whoami")
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(std::net::SocketAddr::from((
            [10, 0, 0, 42],
            55555,
        ))));
    let _ = response;
    let body = respond(request).await;
    assert!(body.contains("10.0.0.42:55555"), "{body}");
    assert!(body.starts_with(LAN_PRINCIPAL_ID), "{body}");
}

#[test]
fn the_trust_mode_carries_a_loud_warning() {
    let warning = TrustMode::TrustedLan.warning();
    assert!(warning.contains("no accounts or login"));
    assert!(warning.contains("Do not expose"));
    assert_eq!(TrustMode::TrustedLan.id(), "trusted-lan");
}

#[test]
fn a_very_long_proxy_value_is_bounded() {
    let long_value = "x".repeat(10_000);
    let mut request = HttpRequest::builder()
        .uri("/whoami")
        .body(Body::empty())
        .unwrap();
    request.headers_mut().insert(
        axum::http::HeaderName::from_static("x-forwarded-for"),
        axum::http::HeaderValue::from_str(&long_value).unwrap(),
    );
    // The evidence recording happens inside the middleware; a handler reading
    // it must see a bounded value, so drive the full stack.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let body = runtime.block_on(respond(request));
    // 256 characters plus the ellipsis, per header value.
    let bounded = "x".repeat(256);
    assert!(body.contains(&bounded), "the value is recorded");
    assert!(body.matches('x').count() <= 257, "the value is bounded");
}
