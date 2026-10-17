//! Contract tests for the creation client (FM-1035) against a local stub.
//!
//! The routes and methods are those of Coolify v4.4.6 `routes/api.php`; the
//! answers are synthetic, written from the controllers' documented shapes
//! (`{"uuid", "domains"}` with status 201). The stub records every request.

use std::sync::{Arc, Mutex};

use fleet_application::coolify::lifecycle::{LifecycleFailureClass, LifecycleResource};
use fleet_application::site_templates::{ApplicationCreate, CoolifyCreatePort as _, ServiceCreate};
use fleet_core::SensitiveString;
use fleet_provider_coolify::CoolifyHttpCreate;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const TOKEN: &str = "3|coolify-write-token-value";

type Canned = Arc<Mutex<(u16, String)>>;
type Seen = Arc<Mutex<Vec<(String, String, String)>>>;

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

fn service() -> ServiceCreate {
    ServiceCreate {
        service_type: "ghost".to_owned(),
        name: "blog".to_owned(),
        description: "fleet-deploy:req1".to_owned(),
        project_uuid: "proj1".to_owned(),
        environment_name: "production".to_owned(),
        server_uuid: "srv1".to_owned(),
        destination_uuid: None,
        url: ("ghost".to_owned(), "https://blog.example.test".to_owned()),
    }
}

fn application() -> ApplicationCreate {
    ApplicationCreate {
        git_repository: "https://example.test/owner/repo".to_owned(),
        git_branch: "main".to_owned(),
        build_pack: "nixpacks".to_owned(),
        ports_exposes: 3000,
        is_static: false,
        name: "site".to_owned(),
        description: "fleet-deploy:req1".to_owned(),
        project_uuid: "proj1".to_owned(),
        environment_name: "production".to_owned(),
        server_uuid: "srv1".to_owned(),
        destination_uuid: None,
        domain: "https://site.example.test".to_owned(),
    }
}

#[tokio::test]
async fn a_service_is_created_with_post_services_and_its_uuid_returned() {
    let (base, seen) = stub(canned(
        201,
        r#"{"uuid":"svc001","domains":["blog.example.test"]}"#,
    ))
    .await;
    let uuid = CoolifyHttpCreate
        .create_service(&base, &token(), &service())
        .await
        .unwrap();
    assert_eq!(uuid, "svc001");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "POST /api/v1/services");
    assert!(seen[0].1.contains(TOKEN));
    let body: serde_json::Value = serde_json::from_str(&seen[0].2).unwrap();
    assert_eq!(body["type"], "ghost");
    assert_eq!(body["urls"][0]["url"], "https://blog.example.test");
    assert_eq!(body["instant_deploy"], false);
}

#[tokio::test]
async fn an_application_is_created_with_post_applications_public() {
    let (base, seen) = stub(canned(
        201,
        r#"{"uuid":"app001","domains":"https://site.example.test"}"#,
    ))
    .await;
    let uuid = CoolifyHttpCreate
        .create_application(&base, &token(), &application())
        .await
        .unwrap();
    assert_eq!(uuid, "app001");
    let seen = seen.lock().unwrap();
    assert_eq!(seen[0].0, "POST /api/v1/applications/public");
    let body: serde_json::Value = serde_json::from_str(&seen[0].2).unwrap();
    assert_eq!(body["build_pack"], "nixpacks");
    assert_eq!(body["domains"], "https://site.example.test");
    assert!(!seen[0].2.contains(TOKEN));
}

#[tokio::test]
async fn the_marker_lookup_reads_the_list_with_get() {
    let (base, seen) = stub(canned(
        200,
        r#"[{"uuid":"a","description":"x"},{"uuid":"svc009","description":"fleet-deploy:req1"}]"#,
    ))
    .await;
    let found = CoolifyHttpCreate
        .find_by_marker(
            &base,
            &token(),
            LifecycleResource::Service,
            "fleet-deploy:req1",
        )
        .await
        .unwrap();
    assert_eq!(found.as_deref(), Some("svc009"));
    assert_eq!(seen.lock().unwrap()[0].0, "GET /api/v1/services");
    let (base, seen) = stub(canned(200, "[]")).await;
    let found = CoolifyHttpCreate
        .find_by_marker(
            &base,
            &token(),
            LifecycleResource::Application,
            "fleet-deploy:req1",
        )
        .await
        .unwrap();
    assert_eq!(found, None);
    assert_eq!(seen.lock().unwrap()[0].0, "GET /api/v1/applications");
}

#[tokio::test]
async fn refusals_are_classified() {
    let (base, _) = stub(canned(401, r#"{"message":"Unauthenticated."}"#)).await;
    let failure = CoolifyHttpCreate
        .create_service(&base, &token(), &service())
        .await
        .unwrap_err();
    assert_eq!(failure.class, LifecycleFailureClass::Auth);
    let (base, _) = stub(canned(
        403,
        r#"{"message":"You are not allowed to perform this action. Missing required permissions: write"}"#,
    ))
    .await;
    let failure = CoolifyHttpCreate
        .create_application(&base, &token(), &application())
        .await
        .unwrap_err();
    assert_eq!(failure.class, LifecycleFailureClass::Permission);
    let (base, _) = stub(canned(422, r#"{"message":"Validation failed."}"#)).await;
    let failure = CoolifyHttpCreate
        .create_application(&base, &token(), &application())
        .await
        .unwrap_err();
    assert!(!failure.detail.contains(TOKEN));
}
