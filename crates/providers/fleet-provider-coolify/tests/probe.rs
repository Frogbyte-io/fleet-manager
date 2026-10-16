//! Probe classification against a local stub server. The stub records every
//! request line: the probe must only ever send `GET /api/v1/version`.

use std::sync::{Arc, Mutex};

use fleet_core::ProbeStatus;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const TOKEN: &str = "3|coolify-secret-token-value";

/// One canned answer: status, extra header lines, body.
#[derive(Clone)]
struct Canned {
    status: u16,
    headers: &'static str,
    body: &'static str,
}

fn canned(status: u16, body: &'static str) -> Canned {
    Canned {
        status,
        headers: "",
        body,
    }
}

/// Serves the same answer to every request; records `METHOD target auth`.
async fn stub(answer: Canned) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let answer = answer.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0_u8; 4096];
                let read = socket.read(&mut buffer).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buffer[..read]).to_string();
                let mut words = head.split_whitespace();
                let method = words.next().unwrap_or_default().to_owned();
                let target = words.next().unwrap_or_default().to_owned();
                let auth = head
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
                    .unwrap_or_default()
                    .to_owned();
                log.lock()
                    .expect("log")
                    .push(format!("{method} {target} {auth}"));
                let response = format!(
                    "HTTP/1.1 {} X\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    answer.status,
                    answer.headers,
                    answer.body.len(),
                    answer.body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (base, seen)
}

/// Every recorded request is a bare GET of the one allow-listed path.
fn assert_only_the_version_get(seen: &Arc<Mutex<Vec<String>>>) {
    let seen = seen.lock().expect("log");
    assert!(!seen.is_empty());
    for line in seen.iter() {
        assert!(
            line.starts_with("GET /api/v1/version "),
            "the probe sent something other than GET /api/v1/version without a query: {line}"
        );
    }
}

#[tokio::test]
async fn a_version_answer_verifies_read_and_leaves_write_and_deploy_unverified() {
    let (base, seen) = stub(canned(200, "4.0.0-beta.123")).await;
    let report = fleet_provider_coolify::probe(&base, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::Ok, "{report:?}");
    assert_eq!(report.granted, ["read"]);
    assert!(report.missing.is_empty());
    assert_eq!(report.unverified, ["write", "deploy"]);
    assert_only_the_version_get(&seen);
    assert_eq!(seen.lock().unwrap().len(), 1, "exactly one request");
    assert!(seen.lock().unwrap()[0].contains("Bearer 3|coolify"));
    assert!(!format!("{report:?}").contains(TOKEN));
}

#[tokio::test]
async fn only_the_ability_denied_body_means_a_missing_ability() {
    let (base, seen) = stub(canned(
        403,
        r#"{"message":"Missing required permissions: read"}"#,
    ))
    .await;
    let report = fleet_provider_coolify::probe(&base, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::InsufficientPermission);
    assert_eq!(report.missing, ["read"]);
    assert_only_the_version_get(&seen);
}

#[tokio::test]
async fn an_api_disabled_or_ip_blocked_403_is_unauthorized_with_the_message() {
    for body in [
        r#"{"message":"You are not allowed to use the API."}"#,
        r#"{"message":"Your IP is not allowed to access this API."}"#,
    ] {
        let (base, _) = stub(canned(403, body)).await;
        let report = fleet_provider_coolify::probe(&base, TOKEN).await;
        assert_eq!(report.status, ProbeStatus::Unauthorized, "{body}");
        assert!(report.missing.is_empty());
        assert!(report.detail.contains("not allowed"), "{}", report.detail);
    }
}

#[tokio::test]
async fn a_refused_token_is_unauthorized() {
    let (base, _) = stub(canned(401, r#"{"message":"Unauthenticated."}"#)).await;
    let report = fleet_provider_coolify::probe(&base, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::Unauthorized);
    assert!(report.granted.is_empty());
}

#[tokio::test]
async fn an_answer_that_is_not_coolify_is_unreachable() {
    for answer in [
        canned(404, "<html>nope</html>"),
        canned(200, "<html>hello</html>"),
        canned(200, "{\"not\":\"a version\"}"),
        canned(200, ""),
    ] {
        let (base, _) = stub(answer).await;
        let report = fleet_provider_coolify::probe(&base, TOKEN).await;
        assert_eq!(report.status, ProbeStatus::Unreachable);
        assert!(
            report.detail.contains("not a Coolify API"),
            "{}",
            report.detail
        );
    }
}

#[tokio::test]
async fn a_redirect_stops_the_probe_and_names_only_the_target_host() {
    let (base, seen) = stub(Canned {
        status: 301,
        headers: "Location: https://other.example:8443/secret/path?token=zzz\r\n",
        body: "",
    })
    .await;
    let report = fleet_provider_coolify::probe(&base, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::Unreachable);
    assert!(report.detail.contains("redirected"), "{}", report.detail);
    // The stub is http, so switching to https is the useful hint.
    assert!(report.detail.contains("use the https base URL"));
    assert!(report.detail.contains("other.example:8443"));
    assert!(!report.detail.contains("secret/path"));
    assert!(!report.detail.contains("zzz"));
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "the redirect is not followed"
    );
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
async fn a_tls_failure_has_its_own_category() {
    // A plain-HTTP server answering an https URL fails the handshake.
    let (base, _) = stub(canned(200, "4.0.0")).await;
    let https = base.replace("http://", "https://");
    let report = fleet_provider_coolify::probe(&https, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::Unreachable);
    assert!(report.detail.contains("TLS"), "{}", report.detail);
}

#[tokio::test]
async fn pretty_printed_json_bodies_classify_the_same() {
    let (base, _) = stub(canned(
        403,
        "{ \"message\": \"Missing required permissions: read\" }",
    ))
    .await;
    let report = fleet_provider_coolify::probe(&base, TOKEN).await;
    assert_eq!(report.status, ProbeStatus::InsufficientPermission);
}
