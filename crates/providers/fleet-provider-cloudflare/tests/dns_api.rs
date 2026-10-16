//! The zones and DNS records client against a local stub, with payloads
//! adapted from Cloudflare's documented examples (not a live account).

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleet_application::dns::{DnsCredentials, DnsFailureClass, DnsGateway as _, DnsRecord};
use fleet_core::SensitiveString;
use fleet_provider_cloudflare::CloudflareDns;
use fleet_provider_cloudflare::api::{CloudflareClient, ErrorClass, RecordInput};
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const TOKEN: &str = "cf-secret-token-value-123";
const ZONE: &str = "023e105f4ecef8ad9ca31a8372d0c353";
const RECORD: &str = "372e67954025e0ba6aaa6d586b9e0b59";

fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/documented-examples.json")).expect("fixtures")
}

fn fixture(name: &str) -> String {
    fixtures()[name].to_string()
}

/// One canned answer.
struct Answer {
    status: u16,
    headers: Vec<(&'static str, &'static str)>,
    body: String,
}

fn ok(body: String) -> Answer {
    Answer {
        status: 200,
        headers: Vec::new(),
        body,
    }
}

fn status(status: u16, body: String) -> Answer {
    Answer {
        status,
        headers: Vec::new(),
        body,
    }
}

/// What the stub saw.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    auth: String,
    body: String,
}

/// A stub that answers requests from a queue, in order, and records them.
async fn stub(answers: Vec<Answer>) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}/client/v4", listener.local_addr().expect("addr"));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let queue = Arc::new(Mutex::new(VecDeque::from(answers)));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let queue = queue.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let mut data = Vec::new();
                let mut buffer = vec![0_u8; 8192];
                let (head, body_start) = loop {
                    let read = socket.read(&mut buffer).await.unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    data.extend_from_slice(&buffer[..read]);
                    if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        break (String::from_utf8_lossy(&data[..at]).to_string(), at + 4);
                    }
                };
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while data.len() < body_start + length {
                    let read = socket.read(&mut buffer).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    data.extend_from_slice(&buffer[..read]);
                }
                let body = String::from_utf8_lossy(&data[body_start..]).to_string();
                let mut first = head.lines().next().unwrap_or_default().split_whitespace();
                let method = first.next().unwrap_or_default().to_owned();
                let target = first.next().unwrap_or_default().to_owned();
                let auth = head
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
                    .unwrap_or_default()
                    .to_owned();
                log.lock().expect("log").push(Seen {
                    method,
                    target,
                    auth,
                    body,
                });
                let answer = queue
                    .lock()
                    .expect("queue")
                    .pop_front()
                    .unwrap_or_else(|| status(500, "{}".to_owned()));
                let mut response = format!(
                    "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                    answer.status,
                    answer.body.len()
                );
                for (name, value) in answer.headers {
                    let _ = write!(response, "{name}: {value}\r\n");
                }
                response.push_str("\r\n");
                response.push_str(&answer.body);
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (base, seen)
}

fn client(base: &str) -> CloudflareClient {
    CloudflareClient::new(base, TOKEN)
        .expect("client")
        .with_retry_wait_cap(Duration::from_secs(2))
}

fn input(record_type: &str, content: &str) -> RecordInput {
    RecordInput {
        record_type: record_type.to_owned(),
        name: "www.example.com".to_owned(),
        content: content.to_owned(),
        ttl: 300,
        proxied: false,
        priority: None,
    }
}

#[tokio::test]
async fn zones_are_paginated_and_sent_with_the_bearer_token() {
    let (base, seen) = stub(vec![ok(fixture("zonesPage1")), ok(fixture("zonesPage2"))]).await;
    let zones = client(&base).list_zones(None).await.expect("zones");
    assert_eq!(zones.len(), 2);
    assert_eq!(zones[0].name, "example.com");
    assert_eq!(zones[1].status, "pending");
    let seen = seen.lock().expect("seen");
    assert_eq!(seen.len(), 2);
    assert!(seen[0].target.starts_with("/client/v4/zones?"));
    assert!(seen[0].target.contains("page=1"));
    assert!(seen[1].target.contains("page=2"));
    assert!(
        seen.iter()
            .all(|s| s.auth.contains(&format!("Bearer {TOKEN}")))
    );
}

#[tokio::test]
async fn a_zone_lookup_filters_by_name() {
    let (base, seen) = stub(vec![ok(fixture("zonesList"))]).await;
    let zones = client(&base)
        .list_zones(Some("example.com"))
        .await
        .expect("zones");
    assert_eq!(zones[0].id, ZONE);
    assert!(
        seen.lock().expect("seen")[0]
            .target
            .contains("name=example.com")
    );
}

#[tokio::test]
async fn records_are_listed_by_name_and_type() {
    let (base, seen) = stub(vec![ok(fixture("recordsList"))]).await;
    let records = client(&base)
        .list_records(ZONE, Some("www.example.com"), Some("A"))
        .await
        .expect("records");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].content, "198.51.100.4");
    assert_eq!(records[0].proxied, Some(false));
    assert_eq!(records[0].ttl, 300);
    let target = seen.lock().expect("seen")[0].target.clone();
    assert!(target.starts_with(&format!("/client/v4/zones/{ZONE}/dns_records?")));
    assert!(target.contains("name.exact=www.example.com"), "{target}");
    assert!(target.contains("type=A"));
}

#[tokio::test]
async fn mixed_records_keep_their_priority_and_quoted_text() {
    let (base, _) = stub(vec![ok(fixture("recordsMixed"))]).await;
    let records = client(&base)
        .list_records(ZONE, None, None)
        .await
        .expect("records");
    assert_eq!(records[0].priority, Some(10));
    assert_eq!(
        records[1].content,
        "\"v=spf1 include:_spf.example.net ~all\""
    );
    assert_eq!(records[2].proxied, Some(true));
}

#[tokio::test]
async fn create_update_and_delete_use_the_documented_methods_and_bodies() {
    let (base, seen) = stub(vec![
        ok(fixture("recordSingle")),
        ok(fixture("recordSingle")),
        ok(fixture("recordDeleted")),
    ])
    .await;
    let cloudflare = client(&base);
    let created = cloudflare
        .create_record(ZONE, &input("A", "198.51.100.9"))
        .await
        .expect("create");
    assert_eq!(created.id, RECORD);
    let mut mx = input("MX", "mail.example.com");
    mx.priority = Some(10);
    cloudflare
        .update_record(ZONE, RECORD, &mx)
        .await
        .expect("update");
    cloudflare
        .delete_record(ZONE, RECORD)
        .await
        .expect("delete");

    let seen = seen.lock().expect("seen");
    assert_eq!(seen[0].method, "POST");
    assert_eq!(
        seen[0].target,
        format!("/client/v4/zones/{ZONE}/dns_records")
    );
    let body: Value = serde_json::from_str(&seen[0].body).expect("json body");
    assert_eq!(body["type"], "A");
    assert_eq!(body["content"], "198.51.100.9");
    assert_eq!(body["ttl"], 300);
    assert_eq!(body["proxied"], false);
    assert_eq!(seen[1].method, "PATCH");
    assert_eq!(
        seen[1].target,
        format!("/client/v4/zones/{ZONE}/dns_records/{RECORD}")
    );
    let body: Value = serde_json::from_str(&seen[1].body).expect("json body");
    assert_eq!(body["priority"], 10);
    assert!(body.get("proxied").is_none(), "MX is never proxied");
    // A PATCH names only what changes, so a record's comment, tags, and
    // settings are left as they are.
    for untouched in ["comment", "tags", "settings"] {
        assert!(
            body.get(untouched).is_none(),
            "{untouched} must not be sent"
        );
    }
    assert_eq!(seen[2].method, "DELETE");
    // No request body or response ever carries the token.
    assert!(seen.iter().all(|s| !s.body.contains(TOKEN)));
}

#[tokio::test]
async fn failures_are_classified() {
    let cases = [
        (401, "error401", ErrorClass::Auth),
        (403, "error403", ErrorClass::Permission),
        (404, "error404", ErrorClass::NotFound),
        (409, "errorDuplicate", ErrorClass::Conflict),
        (400, "errorDuplicate", ErrorClass::Conflict),
        (400, "errorInvalid", ErrorClass::Invalid),
        (500, "error401", ErrorClass::Unavailable),
        (503, "error401", ErrorClass::Unavailable),
    ];
    for (code, name, expected) in cases {
        let (base, _) = stub(vec![status(code, fixture(name))]).await;
        let error = client(&base)
            .create_record(ZONE, &input("A", "198.51.100.9"))
            .await
            .expect_err("a refusal");
        assert_eq!(error.class, expected, "{code} {name}: {error:?}");
        assert!(!error.detail.contains(TOKEN));
    }
    // A 200 that says success:false is Cloudflare refusing the value.
    let (base, _) = stub(vec![ok(fixture("errorInvalid"))]).await;
    let error = client(&base)
        .create_record(ZONE, &input("A", "198.51.100.9"))
        .await
        .expect_err("refused");
    assert_eq!(error.class, ErrorClass::Invalid);
    // Not Cloudflare's answer at all.
    let (base, _) = stub(vec![ok("<html>proxy</html>".to_owned())]).await;
    let error = client(&base).list_zones(None).await.expect_err("not json");
    assert_eq!(error.class, ErrorClass::Unavailable);
}

#[tokio::test]
async fn a_rate_limit_is_retried_within_bounds_then_reported() {
    // One 429 with Retry-After: 0, then success: the retry is invisible.
    let limited = Answer {
        status: 429,
        headers: vec![("Retry-After", "0")],
        body: fixture("errorRateLimit"),
    };
    let (base, seen) = stub(vec![limited, ok(fixture("zonesList"))]).await;
    let zones = client(&base).list_zones(None).await.expect("retried");
    assert_eq!(zones.len(), 1);
    assert_eq!(seen.lock().expect("seen").len(), 2);

    // Three in a row exhaust the two retries.
    let again = || Answer {
        status: 429,
        headers: vec![("Retry-After", "0")],
        body: fixture("errorRateLimit"),
    };
    let (base, seen) = stub(vec![again(), again(), again()]).await;
    let error = client(&base).list_zones(None).await.expect_err("limited");
    assert_eq!(error.class, ErrorClass::RateLimited);
    assert_eq!(seen.lock().expect("seen").len(), 3);

    // A Retry-After beyond the cap is not waited out.
    let long = Answer {
        status: 429,
        headers: vec![("Retry-After", "3600")],
        body: fixture("errorRateLimit"),
    };
    let (base, seen) = stub(vec![long]).await;
    let error = client(&base).list_zones(None).await.expect_err("limited");
    assert_eq!(error.class, ErrorClass::RateLimited);
    assert_eq!(seen.lock().expect("seen").len(), 1);
}

#[tokio::test]
async fn a_redirect_is_never_followed() {
    let redirect = Answer {
        status: 302,
        headers: vec![("Location", "http://127.0.0.1:1/elsewhere")],
        body: String::new(),
    };
    let (base, seen) = stub(vec![redirect]).await;
    let error = client(&base).list_zones(None).await.expect_err("redirect");
    assert_eq!(error.class, ErrorClass::Unavailable);
    assert_eq!(seen.lock().expect("seen").len(), 1);
}

#[tokio::test]
async fn an_id_that_is_not_a_plain_id_never_reaches_a_path() {
    let (base, seen) = stub(vec![]).await;
    let error = client(&base)
        .list_records("../zones", None, None)
        .await
        .expect_err("refused");
    assert_eq!(error.class, ErrorClass::Invalid);
    let error = client(&base)
        .delete_record(ZONE, "a/b")
        .await
        .expect_err("refused");
    assert_eq!(error.class, ErrorClass::Invalid);
    assert!(seen.lock().expect("seen").is_empty());
}

#[tokio::test]
async fn pagination_past_the_cap_is_refused_not_truncated() {
    let huge = serde_json::json!({
        "result": [{"id": "z1", "name": "example.com", "status": "active"}],
        "result_info": {"total_pages": 51},
        "success": true, "errors": [], "messages": []
    })
    .to_string();
    let (base, _) = stub(vec![ok(huge)]).await;
    let error = client(&base).list_zones(None).await.expect_err("too many");
    assert_eq!(error.class, ErrorClass::Invalid);
}

#[tokio::test]
async fn the_gateway_translates_to_the_application_model() {
    let credentials = |base: &str| DnsCredentials {
        base_url: base.to_owned(),
        token: SensitiveString::new(TOKEN),
    };
    let (base, _) = stub(vec![ok(fixture("zonesPage1")), ok(fixture("zonesPage2"))]).await;
    let zones = CloudflareDns
        .list_zones(&credentials(&base), None)
        .await
        .expect("zones");
    // Zone names are lower-cased at the boundary.
    assert_eq!(zones[1].name, "example.org");

    let (base, _) = stub(vec![ok(fixture("recordsMixed"))]).await;
    let records: Vec<DnsRecord> = CloudflareDns
        .list_records(&credentials(&base), ZONE, None, None)
        .await
        .expect("records");
    assert_eq!(records[0].record_type, "MX");
    assert_eq!(records[0].priority, Some(10));
    assert!(records[2].proxied);
    assert_eq!(records[0].id.as_deref(), Some("aa11"));

    let (base, _) = stub(vec![status(403, fixture("error403"))]).await;
    let failure = CloudflareDns
        .list_records(&credentials(&base), ZONE, None, None)
        .await
        .expect_err("refused");
    assert_eq!(failure.class, DnsFailureClass::Permission);
    assert!(!failure.detail.contains(TOKEN));
}
