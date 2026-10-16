//! FM-1030: the Coolify discovery routes end to end over a real controller
//! router, a real secret store and SQLite, and a local stub Coolify: status
//! mapping, the unwired 503, the DTO shape, and no token anywhere.

use std::collections::HashMap;
use std::sync::Arc;

use fleet_controller::{Settings, build_router, compose_node_services};
use fleet_secrets::SecretStore;
use fleet_storage_sqlite::Store;
use serde_json::{Value, json};
use sqlx::Row as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const TOKEN: &str = "coolify-end-to-end-read-token-0001";

/// A stub Coolify: a few canned routes, the token required.
async fn stub_coolify(routes: HashMap<&'static str, &'static str>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let routes = routes.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0_u8; 4096];
                let read = socket.read(&mut buffer).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buffer[..read]).to_string();
                let target = head.split_whitespace().nth(1).unwrap_or_default();
                let path = target.split('?').next().unwrap_or_default();
                let (status, body) = if !head.contains(&format!("Bearer {TOKEN}")) {
                    (401, r#"{"message":"Unauthenticated."}"#)
                } else {
                    routes
                        .get(path)
                        .map_or((404, r#"{"message":"Not found."}"#), |body| (200, *body))
                };
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    base
}

async fn raw(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: test\r\n");
    if let Some(body) = &body {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.to_string().len()
        ));
    }
    head.push_str("Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    if let Some(body) = &body {
        stream.write_all(body.to_string().as_bytes()).await.unwrap();
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    let (head, rest) = text.split_once("\r\n\r\n").expect("an HTTP response");
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap();
    (status, serde_json::from_str(rest).unwrap_or(Value::Null))
}

struct Rig {
    address: std::net::SocketAddr,
    store: Store,
    _dirs: Vec<tempfile::TempDir>,
}

async fn rig(with_discovery: bool) -> Rig {
    let dist = tempfile::tempdir().unwrap();
    std::fs::write(dist.path().join("index.html"), "<html>fleet</html>").unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(&store_dir.path().join("fleet.db"))
        .await
        .unwrap();
    let key_dir = tempfile::tempdir().unwrap();
    let key_path = key_dir.path().join("master.key");
    std::fs::write(
        &key_path,
        "1 0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let secrets = Arc::new(SecretStore::open(store.pool().clone(), &key_path).unwrap());
    let crypto = fleet_controller::node_crypto::NodeCryptoService::open(&secrets)
        .await
        .unwrap();
    let mut services = compose_node_services(store.pool(), Arc::new(crypto));
    services.external_accounts = Some(
        fleet_controller::external_accounts_store::compose_external_accounts(
            store.pool(),
            secrets.clone(),
        ),
    );
    if with_discovery {
        services.coolify_discovery = Some(
            fleet_controller::external_accounts_store::compose_coolify_discovery(
                store.pool(),
                secrets.clone(),
            ),
        );
    }
    let settings = Settings {
        listen: "127.0.0.1:0".parse().unwrap(),
        web_dist: dist.path().to_path_buf(),
        artifacts_dir: None,
        tailscale_serve_listen: None,
    };
    let router = build_router(
        &settings,
        Some(store.pool().clone()),
        Some(&services),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    Rig {
        address,
        store,
        _dirs: vec![dist, store_dir, key_dir],
    }
}

async fn create_account(address: std::net::SocketAddr, kind: &str, base: &str) -> String {
    let (status, body) = raw(
        address,
        "POST",
        "/api/v1/external-accounts",
        Some(json!({"kind": kind, "label": format!("{kind}-1"), "baseUrl": base, "token": TOKEN})),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    body["data"]["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn discovery_routes_map_statuses_and_shape_the_snapshot_without_the_token() {
    let coolify = stub_coolify(HashMap::from([
        ("/api/v1/version", "4.4.6"),
        (
            "/api/v1/servers",
            r#"[{"uuid":"srv1","name":"edge","ip":"192.0.2.1","settings":{"is_reachable":true,"is_usable":true}}]"#,
        ),
        ("/api/v1/projects", "[]"),
        ("/api/v1/applications", "[]"),
        ("/api/v1/services", "[]"),
        ("/api/v1/databases", "[]"),
        ("/api/v1/deployments", "[]"),
    ]))
    .await;
    let rig = rig(true).await;
    let address = rig.address;
    let id = create_account(address, "coolify", &coolify).await;

    // No discovery yet: the cached read is a 404, not an empty success.
    let (status, body) = raw(
        address,
        "GET",
        &format!("/api/v1/external-accounts/{id}/coolify/observations"),
        None,
    )
    .await;
    assert_eq!(status, 404, "{body}");

    // Discover: a stamped, camelCase snapshot with six class states.
    let (status, body) = raw(
        address,
        "POST",
        &format!("/api/v1/external-accounts/{id}/coolify/discover"),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let data = &body["data"];
    assert_eq!(data["accountId"], id);
    assert_eq!(data["version"], "4.4.6");
    assert!(data["recordedAt"].as_i64().unwrap() > 0);
    assert!(data["warnings"].as_array().unwrap().is_empty());
    let classes = data["classes"].as_array().unwrap();
    assert_eq!(classes.len(), 6);
    assert!(classes.iter().all(|class| class["stale"] == false));
    assert!(classes.iter().all(|class| class["failure"].is_null()));
    assert_eq!(data["servers"][0]["uuid"], "srv1");
    assert_eq!(data["servers"][0]["address"], "192.0.2.1");
    assert_eq!(data["servers"][0]["reachable"], true);
    assert!(data["projects"].as_array().unwrap().is_empty());
    assert!(!body.to_string().contains(TOKEN));

    // The cached read returns the same snapshot.
    let (status, again) = raw(
        address,
        "GET",
        &format!("/api/v1/external-accounts/{id}/coolify/observations"),
        None,
    )
    .await;
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["data"]["servers"], data["servers"]);

    // Unknown account: 404. A Cloudflare account: 400.
    for path in ["discover", "observations"] {
        let method = if path == "discover" { "POST" } else { "GET" };
        let (status, _) = raw(
            address,
            method,
            &format!("/api/v1/external-accounts/nope/coolify/{path}"),
            None,
        )
        .await;
        assert_eq!(status, 404, "{path}");
    }
    let cloudflare = create_account(address, "cloudflare", "http://127.0.0.1:9").await;
    let (status, body) = raw(
        address,
        "POST",
        &format!("/api/v1/external-accounts/{cloudflare}/coolify/discover"),
        None,
    )
    .await;
    assert_eq!(status, 400, "{body}");

    // A refusing Coolify is a successful run whose classes say so.
    let refusing = stub_coolify(HashMap::new()).await;
    let other = {
        let (status, body) = raw(
            address,
            "POST",
            "/api/v1/external-accounts",
            Some(json!({"kind": "coolify", "label": "refusing", "baseUrl": refusing, "token": "another-token-that-the-stub-refuses"})),
        )
        .await;
        assert_eq!(status, 201, "{body}");
        body["data"]["id"].as_str().unwrap().to_owned()
    };
    let (status, body) = raw(
        address,
        "POST",
        &format!("/api/v1/external-accounts/{other}/coolify/discover"),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let first = &body["data"]["classes"][0];
    assert_eq!(first["failure"]["kind"], "unauthorized");
    assert_eq!(first["stale"], true);

    // Audited without the token or any response text.
    let rows = sqlx::query(
        "SELECT action, metadata_json FROM audit_events WHERE action = 'external_account.config'",
    )
    .fetch_all(rig.store.pool())
    .await
    .unwrap();
    let ledger: String = rows
        .iter()
        .map(|row| row.get::<String, _>("metadata_json"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(ledger.contains("coolify_discovering"), "{ledger}");
    assert!(ledger.contains("coolify_discovered"), "{ledger}");
    assert!(!ledger.contains(TOKEN));
}

#[tokio::test]
async fn an_unwired_discovery_surface_answers_503() {
    let rig = rig(false).await;
    for (method, path) in [
        ("POST", "/api/v1/external-accounts/x/coolify/discover"),
        ("GET", "/api/v1/external-accounts/x/coolify/observations"),
    ] {
        let (status, body) = raw(rig.address, method, path, None).await;
        assert_eq!(status, 503, "{path}: {body}");
    }
}

#[tokio::test]
async fn a_legacy_http_account_reports_the_policy_violation_and_is_neither_probed_nor_discovered() {
    let rig = rig(true).await;
    let address = rig.address;
    // An account stored before the https rule.
    sqlx::query(
        "INSERT INTO external_accounts (id, kind, label, base_url, scope_id, notes, last_probe, created_at, updated_at) \
         VALUES ('legacy-1', 'coolify', 'legacy', 'http://coolify.example.test', '', '', NULL, 1, 1)",
    )
    .execute(rig.store.pool())
    .await
    .unwrap();
    let (status, body) = raw(address, "GET", "/api/v1/external-accounts/legacy-1", None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["policyViolation"], "https_required");
    for path in ["coolify/discover", "probe"] {
        let (status, body) = raw(
            address,
            "POST",
            &format!("/api/v1/external-accounts/legacy-1/{path}"),
            None,
        )
        .await;
        assert_eq!(status, 400, "{path}: {body}");
        assert!(body.to_string().contains("https"), "{body}");
    }
    // A healthy account has none.
    let ok = create_account(address, "coolify", "http://127.0.0.1:9").await;
    let (_, body) = raw(
        address,
        "GET",
        &format!("/api/v1/external-accounts/{ok}"),
        None,
    )
    .await;
    assert!(body["data"]["policyViolation"].is_null(), "{body}");
}
