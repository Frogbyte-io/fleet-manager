//! Probe classification against a local stub server.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use fleet_core::ProbeStatus;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const TOKEN: &str = "3|coolify-secret-token-value";

type Routes = HashMap<&'static str, (u16, &'static str)>;

/// Serves canned answers by path; records `path authorization` per request.
async fn stub(routes: Routes) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let routes = routes.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0_u8; 4096];
                let read = socket.read(&mut buffer).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buffer[..read]).to_string();
                let path = head
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_owned();
                let auth = head
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
                    .unwrap_or_default()
                    .to_owned();
                log.lock().expect("log").push(format!("{path} {auth}"));
                let (status, body) = routes.get(path.as_str()).copied().unwrap_or((404, ""));
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (base, seen)
}

fn routes(read: u16, write: u16, deploy: u16) -> Routes {
    HashMap::from([
        ("/api/v1/version", (read, "{\"message\":\"gate\"}")),
        ("/api/v1/enable", (write, "{\"message\":\"POST required\"}")),
        (
            "/api/v1/deploy",
            (deploy, "{\"message\":\"POST required\"}"),
        ),
    ])
}

#[tokio::test]
async fn a_token_with_every_ability_is_ok_and_is_sent_as_a_bearer() {
    let (base, seen) = stub(routes(200, 400, 400)).await;
    let report = fleet_provider_coolify::probe(&base, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::Ok, "{report:?}");
    assert_eq!(report.granted, ["read", "write", "deploy"]);
    assert!(report.missing.is_empty());
    let seen = seen.lock().expect("log");
    assert_eq!(seen.len(), 3);
    assert!(seen.iter().all(|line| line.contains("Bearer 3|coolify")));
    // The credential is never part of the returned report.
    assert!(!format!("{report:?}").contains(TOKEN));
}

#[tokio::test]
async fn a_read_only_token_is_insufficient_and_names_what_is_missing() {
    let (base, _) = stub(routes(200, 403, 403)).await;
    let report = fleet_provider_coolify::probe(&base, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::InsufficientPermission);
    assert_eq!(report.granted, ["read"]);
    assert_eq!(report.missing, ["write", "deploy"]);
}

#[tokio::test]
async fn a_refused_token_is_unauthorized() {
    let (base, _) = stub(routes(401, 401, 401)).await;
    let report = fleet_provider_coolify::probe(&base, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::Unauthorized);
    assert!(report.granted.is_empty());
}

#[tokio::test]
async fn nothing_listening_is_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);
    let report = fleet_provider_coolify::probe(&base, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::Unreachable);
    assert!(!report.detail.contains(TOKEN));
}

#[tokio::test]
async fn an_undeterminable_ability_is_reported_missing_not_guessed() {
    let (base, _) = stub(routes(200, 404, 400)).await;
    let report = fleet_provider_coolify::probe(&base, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::InsufficientPermission);
    assert_eq!(report.missing, ["write"]);
    assert!(report.detail.contains("could not verify"));
}
