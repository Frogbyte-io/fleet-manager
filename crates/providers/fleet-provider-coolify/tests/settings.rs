//! Contract tests for the settings client (FM-1034) against a local stub.
//!
//! The routes and methods are those of Coolify v4.4.6 `routes/api.php`; the
//! bodies are synthetic, written from the controllers' documented shapes.
//! The stub records every request (line and body) so the tests can assert
//! the exact routes, the bearer header, and that a value is carried only in
//! the body of its own write.

use std::sync::{Arc, Mutex};

use fleet_application::coolify::lifecycle::{LifecycleFailureClass, LifecycleResource};
use fleet_application::coolify::settings::{
    ApplicationPatch, CoolifySettingsPort as _, EnvFlags, EnvWrite, HealthPatch,
};
use fleet_core::SensitiveString;
use fleet_provider_coolify::CoolifyHttpSettings;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const TOKEN: &str = "3|coolify-write-token-value";
const VALUE: &str = "Zq9-contract-test-value-0042";

type Canned = Arc<Mutex<(u16, String)>>;
type Seen = Arc<Mutex<Vec<(String, String, String)>>>;

/// Answers every request with the canned (status, body) and records the
/// method and target, the authorization header, and the request body.
async fn stub(canned: Canned) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let canned = canned.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = vec![0_u8; 8192];
                let split = loop {
                    let read = socket.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                        break at + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buffer[..split]).to_string();
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while buffer.len() < split + length {
                    let read = socket.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                }
                let body = String::from_utf8_lossy(&buffer[split..]).to_string();
                let mut words = head.split_whitespace();
                let method = words.next().unwrap_or_default().to_owned();
                let target = words.next().unwrap_or_default().to_owned();
                let auth = head
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
                    .unwrap_or_default()
                    .to_owned();
                log.lock()
                    .unwrap()
                    .push((format!("{method} {target}"), auth, body));
                let (status, answer) = canned.lock().unwrap().clone();
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                    answer.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (base, seen)
}

fn canned(status: u16, body: &str) -> Canned {
    Arc::new(Mutex::new((status, body.to_owned())))
}

fn token() -> SensitiveString {
    SensitiveString::new(TOKEN.to_owned())
}

#[tokio::test]
async fn listing_returns_keys_and_flags_and_drops_values() {
    let answer = canned(
        200,
        &serde_json::json!([
            {"uuid": "e1", "key": "DATABASE_URL", "value": VALUE, "real_value": VALUE,
             "is_preview": false, "is_buildtime": true, "is_runtime": true,
             "is_multiline": false, "is_literal": true, "is_shown_once": false, "is_shared": false},
            {"uuid": "e2", "key": "DATABASE_URL", "is_preview": true, "is_buildtime": false,
             "is_runtime": true}
        ])
        .to_string(),
    );
    let (base, seen) = stub(answer).await;
    let envs = CoolifyHttpSettings
        .read_envs(&base, &token(), LifecycleResource::Application, "app001")
        .await
        .unwrap();
    assert_eq!(envs.len(), 2);
    assert!(envs[0].flags.is_literal && !envs[1].flags.is_buildtime && envs[1].is_preview);
    assert!(!format!("{envs:?}").contains(VALUE));
    let seen = seen.lock().unwrap();
    assert_eq!(seen[0].0, "GET /api/v1/applications/app001/envs");
    assert!(seen[0].1.contains(&format!("Bearer {TOKEN}")));
    assert!(seen[0].2.is_empty());
}

#[tokio::test]
async fn writes_use_the_documented_routes_and_the_value_is_only_in_its_body() {
    let answer = canned(201, r#"{"uuid":"e9"}"#);
    let (base, seen) = stub(answer).await;
    let value = SensitiveString::new(VALUE.to_owned());
    let write = EnvWrite {
        key: "API_URL",
        value: &value,
        is_preview: false,
        flags: EnvFlags::default(),
    };
    let client = CoolifyHttpSettings;
    let app = LifecycleResource::Application;
    client
        .create_env(&base, &token(), app, "app001", &write)
        .await
        .unwrap();
    client
        .update_env(
            &base,
            &token(),
            LifecycleResource::Service,
            "svc001",
            &write,
        )
        .await
        .unwrap();
    client
        .delete_env(&base, &token(), app, "app001", "e9")
        .await
        .unwrap();
    client
        .patch_application(
            &base,
            &token(),
            "app001",
            &ApplicationPatch {
                domains: Some(vec!["https://a.example.test".to_owned()]),
                health: Some(HealthPatch {
                    path: Some("/up".to_owned()),
                    ..HealthPatch::default()
                }),
            },
        )
        .await
        .unwrap();
    let seen: Vec<_> = seen.lock().unwrap().clone();
    let lines: Vec<&str> = seen.iter().map(|(line, _, _)| line.as_str()).collect();
    assert_eq!(
        lines,
        [
            "POST /api/v1/applications/app001/envs",
            "PATCH /api/v1/services/svc001/envs",
            "DELETE /api/v1/applications/app001/envs/e9",
            "PATCH /api/v1/applications/app001",
        ]
    );
    assert!(seen.iter().all(|(_, auth, _)| auth.contains(TOKEN)));
    assert!(seen[0].2.contains(VALUE) && seen[1].2.contains(VALUE));
    assert!(seen[2].2.is_empty());
    assert!(!seen[3].2.contains(VALUE));
    assert!(seen[3].2.contains("health_check_path"));
    // A path never reaches a database or an odd id.
    let refused = client
        .read_envs(&base, &token(), LifecycleResource::Database, "db001")
        .await
        .unwrap_err();
    assert_eq!(refused.class, LifecycleFailureClass::Invalid);
    let refused = client
        .delete_env(&base, &token(), app, "app001", "../x")
        .await
        .unwrap_err();
    assert_eq!(refused.class, LifecycleFailureClass::Invalid);
}

#[tokio::test]
async fn a_failed_value_write_reports_the_status_and_never_quotes_coolify() {
    let answer = canned(
        422,
        &format!(
            r#"{{"message":"The value {VALUE} is invalid.","errors":{{"value":["{VALUE}"]}}}}"#
        ),
    );
    let (base, _seen) = stub(answer.clone()).await;
    let value = SensitiveString::new(VALUE.to_owned());
    let write = EnvWrite {
        key: "API_URL",
        value: &value,
        is_preview: false,
        flags: EnvFlags::default(),
    };
    let failure = CoolifyHttpSettings
        .create_env(
            &base,
            &token(),
            LifecycleResource::Application,
            "app001",
            &write,
        )
        .await
        .unwrap_err();
    assert_eq!(failure.class, LifecycleFailureClass::Invalid);
    assert!(failure.detail.contains("422"));
    assert!(!failure.to_string().contains(VALUE));
    // The missing-ability answer still says what to grant.
    *answer.lock().unwrap() = (
        403,
        r#"{"message":"You are not allowed to perform this action. Missing required permissions: write"}"#
            .to_owned(),
    );
    let failure = CoolifyHttpSettings
        .create_env(
            &base,
            &token(),
            LifecycleResource::Application,
            "app001",
            &write,
        )
        .await
        .unwrap_err();
    assert_eq!(failure.class, LifecycleFailureClass::Permission);
    assert!(failure.detail.contains("write ability"));
}

#[tokio::test]
async fn the_application_read_translates_domains_and_health() {
    let answer = canned(
        200,
        &serde_json::json!({
            "uuid": "app001", "build_pack": "nixpacks",
            "fqdn": "https://a.example.test, https://b.example.test",
            "health_check_enabled": true, "health_check_path": "/up",
            "health_check_port": "8080", "health_check_return_code": 204,
            "health_check_interval": 30
        })
        .to_string(),
    );
    let (base, _seen) = stub(answer).await;
    let app = CoolifyHttpSettings
        .read_application(&base, &token(), "app001")
        .await
        .unwrap();
    assert_eq!(
        app.domains,
        ["https://a.example.test", "https://b.example.test"]
    );
    assert!(app.health.enabled);
    assert_eq!(app.health.port, Some(8080));
    assert_eq!(app.health.return_code, 204);
    assert_eq!(app.health.interval, 30);
}

#[tokio::test]
async fn the_token_is_not_sent_over_plain_http_to_a_remote_host() {
    let refused = CoolifyHttpSettings
        .read_application("http://coolify.example.test", &token(), "app001")
        .await
        .unwrap_err();
    assert_eq!(refused.class, LifecycleFailureClass::Unavailable);
    assert!(refused.detail.contains("https"));
}
