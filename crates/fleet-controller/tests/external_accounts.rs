//! The external accounts surface end to end: a real controller router, a
//! real secret store and SQLite, and a local stub provider. The token must
//! never come back from the API or reach the audit ledger or the database
//! outside the encrypted secret store.

use std::sync::Arc;

use fleet_controller::{Settings, build_router, compose_node_services};
use fleet_secrets::SecretStore;
use fleet_storage_sqlite::Store;
use serde_json::{Value, json};
use sqlx::Row as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const TOKEN: &str = "cf-end-to-end-secret-token-0001";

/// A stub Cloudflare answering the user verify endpoint.
async fn stub_cloudflare() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = vec![0_u8; 4096];
                let read = socket.read(&mut buffer).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buffer[..read]).to_string();
                let authorized = head.contains(&format!("Bearer {TOKEN}"));
                let (status, body) = if authorized {
                    (
                        200,
                        r#"{"success":true,"errors":[],"result":{"id":"x","status":"active"}}"#,
                    )
                } else {
                    (
                        401,
                        r#"{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}"#,
                    )
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

#[tokio::test]
async fn accounts_walk_create_probe_update_delete_without_ever_echoing_the_token() {
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
    let cloudflare = stub_cloudflare().await;

    let (status, body) = raw(
        address,
        "POST",
        "/api/v1/external-accounts",
        Some(json!({
            "kind": "cloudflare",
            "label": "dns",
            "baseUrl": cloudflare,
            "notes": "zones for client x",
            "token": TOKEN
        })),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert!(!body.to_string().contains(TOKEN));
    assert_eq!(body["data"]["kind"], "cloudflare");
    assert!(body["data"]["lastProbe"].is_null());
    let id = body["data"]["id"].as_str().unwrap().to_owned();

    // A bad request is a 400, a duplicate label a 409.
    let (status, _) = raw(
        address,
        "POST",
        "/api/v1/external-accounts",
        Some(json!({"kind": "coolify", "label": "c", "token": TOKEN})),
    )
    .await;
    assert_eq!(status, 400);
    let (status, body) = raw(
        address,
        "POST",
        "/api/v1/external-accounts",
        Some(json!({"kind": "cloudflare", "label": "dns", "token": TOKEN})),
    )
    .await;
    assert_eq!(status, 409, "{body}");

    // Probe: classified, stored, listed.
    let (status, body) = raw(
        address,
        "POST",
        &format!("/api/v1/external-accounts/{id}/probe"),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["lastProbe"]["status"], "ok");
    assert!(!body.to_string().contains(TOKEN));
    let (status, body) = raw(
        address,
        "GET",
        "/api/v1/external-accounts?kind=cloudflare",
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert!(!body.to_string().contains(TOKEN));

    // Replacing the token with a wrong one flips the probe to unauthorized.
    let (status, body) = raw(
        address,
        "PATCH",
        &format!("/api/v1/external-accounts/{id}"),
        Some(json!({"token": "a-wrong-token-value", "label": "dns-2"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["label"], "dns-2");
    assert!(body["data"]["lastProbe"].is_null());
    let (_, body) = raw(
        address,
        "POST",
        &format!("/api/v1/external-accounts/{id}/probe"),
        None,
    )
    .await;
    assert_eq!(body["data"]["lastProbe"]["status"], "unauthorized");

    // The token exists only as an encrypted record.
    let names: Vec<String> = secrets
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|record| record.name)
        .collect();
    assert_eq!(
        names.iter().filter(|n| n.starts_with("external/")).count(),
        1
    );

    let (status, _) = raw(
        address,
        "DELETE",
        &format!("/api/v1/external-accounts/{id}"),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _) = raw(
        address,
        "GET",
        &format!("/api/v1/external-accounts/{id}"),
        None,
    )
    .await;
    assert_eq!(status, 404);
    assert!(
        !secrets
            .list()
            .await
            .unwrap()
            .iter()
            .any(|record| record.name.starts_with("external/"))
    );

    // The audit ledger recorded every mutation and none of it holds a token.
    let rows = sqlx::query(
        "SELECT action, metadata_json FROM audit_events WHERE action = 'external_account.config'",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert!(rows.len() >= 10, "two-phase events for each mutation");
    for row in rows {
        let metadata: String = row.get("metadata_json");
        assert!(!metadata.contains(TOKEN));
        assert!(!metadata.contains("a-wrong-token-value"));
    }
}
