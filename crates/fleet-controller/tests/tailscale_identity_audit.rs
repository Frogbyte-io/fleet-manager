use axum::{body::Body, extract::ConnectInfo, http::Request};
use fleet_controller::{Settings, build_router};
use fleet_storage_sqlite::Store;
use sqlx::Row as _;
use tower::ServiceExt as _;

#[tokio::test]
async fn a_spoofed_identity_header_is_audited_without_its_value() {
    let dist = tempfile::tempdir().unwrap();
    std::fs::write(dist.path().join("index.html"), "<html>fleet</html>").unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(&store_dir.path().join("fleet.db"))
        .await
        .unwrap();
    let settings = Settings {
        listen: "127.0.0.1:0".parse().unwrap(),
        tailscale_serve_listen: None,
        web_dist: dist.path().to_path_buf(),
        artifacts_dir: None,
    };
    let router = build_router(
        &settings,
        Some(store.pool().clone()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let mut request = Request::builder()
        .uri("/api/v1/system")
        .header("tailscale-user-login", "spoofed-person@example.invalid")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "10.20.30.40:45678".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let row = sqlx::query(
        "SELECT actor, action, allowed, metadata_json FROM audit_events \
         WHERE action = 'auth.identity_header_ignored'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("actor"), "anonymous-lan-admin");
    assert_eq!(row.get::<bool, _>("allowed"), false);
    let metadata = row.get::<String, _>("metadata_json");
    assert!(metadata.contains("tailscale-user-login"));
    assert!(metadata.contains(r#""peerLoopback":false"#));
    assert!(!metadata.contains("spoofed-person@example.invalid"));
}
