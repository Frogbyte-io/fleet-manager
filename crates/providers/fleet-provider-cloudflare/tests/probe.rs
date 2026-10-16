//! Verify-token classification against a local stub server.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use fleet_core::ProbeStatus;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const TOKEN: &str = "cf-secret-token-value-123";

type Routes = HashMap<&'static str, (u16, &'static str)>;

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

const ACTIVE: &str =
    r#"{"success":true,"errors":[],"messages":[],"result":{"id":"abc","status":"active"}}"#;
const EXPIRED: &str =
    r#"{"success":true,"errors":[],"messages":[],"result":{"id":"abc","status":"expired"}}"#;
const BAD: &str =
    r#"{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"result":null}"#;

#[tokio::test]
async fn an_active_user_token_is_ok() {
    let (base, seen) = stub(HashMap::from([("/user/tokens/verify", (200, ACTIVE))])).await;
    let report = fleet_provider_cloudflare::probe(&base, None, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::Ok, "{report:?}");
    assert!(seen.lock().expect("log")[0].contains("Bearer cf-secret"));
}

#[tokio::test]
async fn an_account_token_uses_the_account_endpoint() {
    let (base, _) = stub(HashMap::from([(
        "/accounts/acc123/tokens/verify",
        (200, ACTIVE),
    )]))
    .await;
    let report = fleet_provider_cloudflare::probe(&base, Some("acc123"), TOKEN).await;
    assert_eq!(report.status, ProbeStatus::Ok);
}

#[tokio::test]
async fn expired_and_refused_tokens_are_unauthorized() {
    let (base, _) = stub(HashMap::from([("/user/tokens/verify", (200, EXPIRED))])).await;
    let report = fleet_provider_cloudflare::probe(&base, None, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::Unauthorized);
    let (base, _) = stub(HashMap::from([("/user/tokens/verify", (401, BAD))])).await;
    let report = fleet_provider_cloudflare::probe(&base, None, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::Unauthorized);
    assert!(report.detail.contains("Invalid API Token"));
}

#[tokio::test]
async fn a_token_for_another_account_lacks_permission() {
    let (base, _) = stub(HashMap::from([(
        "/accounts/acc123/tokens/verify",
        (403, BAD),
    )]))
    .await;
    let report = fleet_provider_cloudflare::probe(&base, Some("acc123"), TOKEN).await;
    assert_eq!(report.status, ProbeStatus::InsufficientPermission);
}

#[tokio::test]
async fn nothing_listening_is_unreachable_and_a_foreign_answer_is_flagged() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);
    let report = fleet_provider_cloudflare::probe(&base, None, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::Unreachable);
    assert!(!report.detail.contains(TOKEN));

    let (base, _) = stub(HashMap::from([("/user/tokens/verify", (200, "<html>"))])).await;
    let report = fleet_provider_cloudflare::probe(&base, None, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::Unreachable);
}
