//! Contract tests for the lifecycle client (FM-1033) against a local stub.
//!
//! The routes and methods are those of Coolify v4.4.6 `routes/api.php`; the
//! bodies are synthetic, written from the controllers' documented shapes.
//! The stub records every request line, so the tests can assert that every
//! mutating call is a `POST` to one of the documented routes.

use std::sync::{Arc, Mutex};

use fleet_application::coolify::lifecycle::{
    CoolifyLifecyclePort as _, LifecycleFailureClass, LifecycleResource, LifecycleVerb,
};
use fleet_core::SensitiveString;
use fleet_provider_coolify::CoolifyHttpLifecycle;
use fleet_provider_coolify::lifecycle::Route;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const TOKEN: &str = "3|coolify-deploy-token-value";

type Canned = Arc<Mutex<(u16, String, String)>>;
type Seen = Arc<Mutex<Vec<String>>>;

/// Answers every request with the canned (status, extra headers, body).
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
                let mut buffer = vec![0_u8; 8192];
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
                    .unwrap()
                    .push(format!("{method} {target} {auth}"));
                let (status, headers, body) = canned.lock().unwrap().clone();
                let response = format!(
                    "HTTP/1.1 {status} X\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (base, seen)
}

fn canned(status: u16, headers: &str, body: &str) -> Canned {
    Arc::new(Mutex::new((status, headers.to_owned(), body.to_owned())))
}

fn token() -> SensitiveString {
    SensitiveString::new(TOKEN.to_owned())
}

#[test]
fn the_route_set_is_closed_and_lifecycle_routes_are_post() {
    let app = LifecycleResource::Application;
    for (verb, tail) in [
        (LifecycleVerb::Start, "start"),
        (LifecycleVerb::Stop, "stop"),
        (LifecycleVerb::Restart, "restart"),
    ] {
        for (resource, family) in [
            (app, "applications"),
            (LifecycleResource::Service, "services"),
            (LifecycleResource::Database, "databases"),
        ] {
            let route = Route::Lifecycle(resource, "abc123", verb);
            assert_eq!(route.method(), reqwest::Method::POST);
            assert_eq!(
                route.path().as_deref(),
                Some(format!("/api/v1/{family}/abc123/{tail}").as_str())
            );
        }
    }
    // Redeploy is the /deploy route, not a lifecycle path of its own.
    assert!(
        Route::Lifecycle(app, "abc123", LifecycleVerb::Redeploy)
            .path()
            .is_none()
    );
    let deploy = Route::Deploy("abc123");
    assert_eq!(deploy.method(), reqwest::Method::POST);
    assert_eq!(
        deploy.path().as_deref(),
        Some("/api/v1/deploy?uuid=abc123&force=false")
    );
    for read in [
        Route::Version,
        Route::Status(app, "abc123"),
        Route::LatestDeployment("abc123"),
        Route::Deployment("abc123"),
    ] {
        assert_eq!(read.method(), reqwest::Method::GET);
    }
    // An identifier is never interpolated unchecked.
    for bad in ["", "a/b", "a?b", "a b", "..", "a%2fb", &"x".repeat(65)] {
        assert!(Route::Status(app, bad).path().is_none(), "{bad:?}");
        assert!(Route::Deploy(bad).path().is_none(), "{bad:?}");
        assert!(
            Route::Lifecycle(app, bad, LifecycleVerb::Stop)
                .path()
                .is_none(),
            "{bad:?}"
        );
    }
}

#[tokio::test]
async fn each_verb_sends_one_post_with_the_bearer_and_reads_the_deployment() {
    let canned = canned(
        200,
        "Content-Type: application/json\r\n",
        r#"{"message":"Deployment request queued.","deployment_uuid":"dep001"}"#,
    );
    let (base, seen) = stub(canned.clone()).await;
    let client = CoolifyHttpLifecycle;
    let ack = client
        .run(
            &base,
            &token(),
            LifecycleResource::Application,
            "app001",
            LifecycleVerb::Start,
        )
        .await
        .unwrap();
    assert_eq!(ack.deployment_uuid.as_deref(), Some("dep001"));
    // The deploy route nests the deployment.
    *canned.lock().unwrap() = (
        200,
        String::new(),
        r#"{"deployments":[{"message":"queued","resource_uuid":"app001","deployment_uuid":"dep002"}]}"#
            .to_owned(),
    );
    let ack = client
        .run(
            &base,
            &token(),
            LifecycleResource::Application,
            "app001",
            LifecycleVerb::Redeploy,
        )
        .await
        .unwrap();
    assert_eq!(ack.deployment_uuid.as_deref(), Some("dep002"));
    // A service answers without a deployment.
    *canned.lock().unwrap() = (
        200,
        String::new(),
        r#"{"message":"Service stopping."}"#.to_owned(),
    );
    let ack = client
        .run(
            &base,
            &token(),
            LifecycleResource::Service,
            "svc001",
            LifecycleVerb::Stop,
        )
        .await
        .unwrap();
    assert!(ack.deployment_uuid.is_none());
    // Redeploy is for applications.
    let refused = client
        .run(
            &base,
            &token(),
            LifecycleResource::Database,
            "db001",
            LifecycleVerb::Redeploy,
        )
        .await
        .unwrap_err();
    assert_eq!(refused.class, LifecycleFailureClass::Invalid);

    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert!(seen[0].starts_with("POST /api/v1/applications/app001/start "));
    assert!(seen[1].starts_with("POST /api/v1/deploy?uuid=app001&force=false "));
    assert!(seen[2].starts_with("POST /api/v1/services/svc001/stop "));
    assert!(seen.iter().all(|line| {
        line.to_ascii_lowercase()
            .contains(&format!("bearer {TOKEN}").to_ascii_lowercase())
    }));
}

#[tokio::test]
async fn refusals_are_classified_and_say_what_is_missing() {
    let run = |status: u16, headers: &'static str, body: &'static str| async move {
        let (base, _) = stub(canned(status, headers, body)).await;
        CoolifyHttpLifecycle
            .run(
                &base,
                &token(),
                LifecycleResource::Application,
                "app001",
                LifecycleVerb::Restart,
            )
            .await
            .unwrap_err()
    };
    let forbidden = run(
        403,
        "",
        r#"{"message":"You are not allowed to perform this action. Missing required permissions: deploy"}"#,
    )
    .await;
    assert_eq!(forbidden.class, LifecycleFailureClass::Permission);
    assert!(
        forbidden.detail.contains("deploy ability"),
        "{}",
        forbidden.detail
    );
    assert_eq!(run(401, "", "{}").await.class, LifecycleFailureClass::Auth);
    assert_eq!(
        run(404, "", r#"{"message":"Application not found."}"#)
            .await
            .class,
        LifecycleFailureClass::NotFound
    );
    let method = run(
        405,
        "",
        r#"{"message":"This endpoint has changed to a POST request."}"#,
    )
    .await;
    assert_eq!(method.class, LifecycleFailureClass::Unsupported);
    let limited = run(429, "Retry-After: 42\r\n", "{}").await;
    assert_eq!(limited.class, LifecycleFailureClass::RateLimited);
    assert!(limited.detail.contains("42"), "{}", limited.detail);
    assert_eq!(
        run(500, "", "<html>boom</html>").await.class,
        LifecycleFailureClass::Unavailable
    );
    // A redirect is reported and never followed.
    let redirected = run(302, "Location: https://elsewhere.example.test/x\r\n", "").await;
    assert_eq!(redirected.class, LifecycleFailureClass::Unavailable);
    assert!(redirected.detail.contains("elsewhere.example.test"));
    for failure in [&forbidden, &limited, &redirected] {
        assert!(!failure.detail.contains(TOKEN));
    }
}

#[tokio::test]
async fn the_token_is_not_sent_over_plain_http_to_a_remote_host() {
    let refused = CoolifyHttpLifecycle
        .version("http://coolify.example.test", &token())
        .await
        .unwrap_err();
    assert_eq!(refused.class, LifecycleFailureClass::Unavailable);
    assert!(refused.detail.contains("https"));
}

#[tokio::test]
async fn version_status_and_deployment_reads() {
    let canned = canned(200, "", "4.4.6");
    let (base, seen) = stub(canned.clone()).await;
    let client = CoolifyHttpLifecycle;
    assert_eq!(client.version(&base, &token()).await.unwrap(), "4.4.6");
    *canned.lock().unwrap() = (200, String::new(), "<html>not coolify</html>".to_owned());
    assert!(client.version(&base, &token()).await.is_err());

    *canned.lock().unwrap() = (
        200,
        String::new(),
        r#"{"uuid":"app001","status":"running:healthy","env":"SENTINEL"}"#.to_owned(),
    );
    assert_eq!(
        client
            .status(&base, &token(), LifecycleResource::Application, "app001")
            .await
            .unwrap(),
        "running:healthy"
    );

    *canned.lock().unwrap() = (
        200,
        String::new(),
        r#"{"count":2,"deployments":[{"deployment_uuid":"dep009"},{"deployment_uuid":"dep008"}]}"#
            .to_owned(),
    );
    assert_eq!(
        client
            .latest_deployment(&base, &token(), "app001")
            .await
            .unwrap()
            .as_deref(),
        Some("dep009")
    );
    *canned.lock().unwrap() = (
        200,
        String::new(),
        r#"{"count":0,"deployments":[]}"#.to_owned(),
    );
    assert!(
        client
            .latest_deployment(&base, &token(), "app001")
            .await
            .unwrap()
            .is_none()
    );

    // The logs key is absent for a token without read:sensitive.
    *canned.lock().unwrap() = (
        200,
        String::new(),
        r#"{"deployment_uuid":"dep009","status":"finished"}"#.to_owned(),
    );
    let hidden = client.deployment(&base, &token(), "dep009").await.unwrap();
    assert_eq!(hidden.status, "finished");
    assert!(hidden.logs.is_none());
    *canned.lock().unwrap() = (
        200,
        String::new(),
        r#"{"deployment_uuid":"dep009","status":"failed","logs":"[{\"output\":\"boom\",\"hidden\":false}]"}"#
            .to_owned(),
    );
    let shown = client.deployment(&base, &token(), "dep009").await.unwrap();
    assert!(shown.logs.unwrap().contains("boom"));

    // Every one of those was a GET.
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .all(|line| line.starts_with("GET "))
    );
}
