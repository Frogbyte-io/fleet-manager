//! Contract tests for read discovery over recorded fixtures.
//!
//! The fixtures under `tests/fixtures/v4.4.6/` are SYNTHETIC: they were
//! written from the response schemas in Coolify v4.4.6's `openapi.json` and
//! the Api controllers (`ServersController`, `ProjectController`,
//! `ApplicationsController`, `ServicesController`, `DatabasesController`,
//! `DeployController`), with invented, `example.test` data. Real-instance
//! fixtures are pending: an operator records them with the ignored
//! `capture` test (`tests/capture.rs`), which scrubs on the way out.
//! `tests/fixtures/v4.4.6-read-sensitive/` is the same data with the
//! extra fields Coolify returns to a `read:sensitive` token, each carrying a
//! `SENTINEL-` marker that must never come out of discovery.
//!
//! The stub server records every request line; discovery may only send
//! `GET` requests to the documented read routes.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fleet_application::coolify::{ClassResult, FailureKind, RawCoolifyDiscovery};
use fleet_provider_coolify::discover;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const TOKEN: &str = "3|coolify-read-token-value";

type Routes = HashMap<String, (u16, String, String)>;
type Seen = Arc<Mutex<Vec<String>>>;

fn fixture_dir(version: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(version)
}

/// Routes serving a fixture set: path (with query) -> (status, headers, body).
fn fixture_routes(version: &str) -> Routes {
    let read = |name: &str| {
        std::fs::read_to_string(fixture_dir(version).join(name)).expect("fixture readable")
    };
    let mut routes = Routes::new();
    let mut ok = |path: &str, body: String| {
        routes.insert(format!("/api/v1{path}"), (200, String::new(), body));
    };
    ok("/version", read("version.txt"));
    ok("/servers", read("servers.json"));
    ok("/projects", read("projects.json"));
    ok(
        "/projects/prjshop0000000000001/environments",
        read("project-environments-prjshop0000000000001.json"),
    );
    ok(
        "/projects/prjtools000000000002/environments",
        read("project-environments-prjtools000000000002.json"),
    );
    ok("/applications", read("applications.json"));
    ok("/services", read("services.json"));
    ok(
        "/services/svcplausible000000001/applications",
        read("service-applications-svcplausible000000001.json"),
    );
    ok(
        "/services/svcminio0000000000002/applications",
        read("service-applications-svcminio0000000000002.json"),
    );
    ok("/databases", read("databases.json"));
    ok("/deployments", read("deployments-active.json"));
    let deployments = read("application-deployments.json");
    // The fixture is recorded for the first application; the others have none.
    ok(
        "/deployments/applications/appweb000000000001?skip=0&take=5",
        deployments,
    );
    ok(
        "/deployments/applications/appstack0000000002?skip=0&take=5",
        r#"{"count":0,"deployments":[]}"#.to_owned(),
    );
    ok(
        "/deployments/applications/applegacy000000003?skip=0&take=5",
        r#"{"count":0,"deployments":[]}"#.to_owned(),
    );
    routes
}

/// Serves `routes`; anything else is a Coolify-style 404. Records
/// `METHOD target authorization` for every request.
async fn stub(routes: Routes) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let routes = Arc::new(routes);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let routes = routes.clone();
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
                    .expect("log")
                    .push(format!("{method} {target} {auth}"));
                let (status, headers, body) = routes.get(&target).cloned().unwrap_or((
                    404,
                    String::new(),
                    r#"{"message":"Not found."}"#.to_owned(),
                ));
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

fn items<T: Clone>(result: &ClassResult<T>) -> Vec<T> {
    match result {
        ClassResult::Complete(items) | ClassResult::Partial(items, _) => items.clone(),
        ClassResult::Failed(failure) => panic!("the class failed: {failure:?}"),
    }
}

fn failed_kind<T>(result: &ClassResult<T>) -> FailureKind {
    match result {
        ClassResult::Failed(failure) => failure.kind,
        _ => panic!("the class did not fail"),
    }
}

fn assert_read_only_requests(seen: &Seen) {
    let seen = seen.lock().expect("log");
    assert!(!seen.is_empty());
    for line in seen.iter() {
        let mut words = line.split_whitespace();
        assert_eq!(words.next(), Some("GET"), "{line}");
        let target = words.next().expect("target");
        assert!(target.starts_with("/api/v1/"), "{line}");
        for forbidden in [
            "/envs", "/enable", "/disable", "/deploy?", "/start", "/stop", "/restart",
        ] {
            assert!(!target.contains(forbidden), "forbidden route: {line}");
        }
        assert!(
            line.to_ascii_lowercase()
                .ends_with(&format!("authorization: bearer {TOKEN}").to_ascii_lowercase()),
            "bearer token missing: {line}"
        );
    }
}

fn rendered(discovery: &RawCoolifyDiscovery) -> String {
    let mut out = String::new();
    out.push_str(&serde_json::to_string(&items(&discovery.servers)).unwrap());
    out.push_str(&serde_json::to_string(&items(&discovery.projects)).unwrap());
    out.push_str(&serde_json::to_string(&items(&discovery.applications)).unwrap());
    out.push_str(&serde_json::to_string(&items(&discovery.services)).unwrap());
    out.push_str(&serde_json::to_string(&items(&discovery.databases)).unwrap());
    out.push_str(&serde_json::to_string(&items(&discovery.deployments)).unwrap());
    out
}

#[tokio::test]
async fn every_class_is_translated_from_the_recorded_fixtures() {
    let (base, seen) = stub(fixture_routes("v4.4.6")).await;
    let found = discover(&base, TOKEN).await;
    assert_eq!(found.version.as_deref(), Some("4.4.6"));

    let servers = items(&found.servers);
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0].name, "localhost");
    assert_eq!(servers[0].proxy_type.as_deref(), Some("TRAEFIK"));
    assert_eq!(servers[0].reachable, Some(true));
    assert_eq!(servers[1].address, "198.51.100.7");
    assert_eq!(servers[1].reachable, Some(false));

    let projects = items(&found.projects);
    assert!(matches!(found.projects, ClassResult::Complete(_)));
    assert_eq!(projects[0].name, "shop");
    let environments: Vec<_> = projects[0]
        .environments
        .iter()
        .map(|e| (e.id, e.name.as_str()))
        .collect();
    assert_eq!(environments, [(1, "production"), (2, "staging")]);
    assert_eq!(projects[1].environments.len(), 1);

    let applications = items(&found.applications);
    assert_eq!(applications.len(), 3);
    assert_eq!(applications[0].status, "running:healthy");
    assert_eq!(
        applications[0].fqdns,
        ["https://shop.example.test", "https://www.shop.example.test"]
    );
    assert_eq!(applications[0].environment_id, Some(1));
    assert_eq!(
        applications[0].git_repository.as_deref(),
        Some("example-org/shop")
    );
    assert_eq!(
        applications[1].fqdns,
        [
            "https://admin.stack.example.test",
            "https://stack.example.test"
        ],
        "Compose domains come from docker_compose_domains"
    );
    assert_eq!(
        applications[2].docker_image.as_deref(),
        Some("ghcr.io/example-org/legacy:1.4.2")
    );
    assert_eq!(applications[2].status, "exited:unhealthy");

    let services = items(&found.services);
    assert_eq!(services[0].fqdns, ["https://stats.example.test"]);
    assert_eq!(services[0].status.as_deref(), Some("running:healthy"));
    assert_eq!(
        services[1].fqdns,
        ["https://s3.example.test", "https://console.s3.example.test"]
    );
    assert_eq!(services[1].status, None);

    let databases = items(&found.databases);
    assert_eq!(databases[0].engine.as_deref(), Some("postgres"));
    assert_eq!(databases[1].engine.as_deref(), Some("redis"));
    assert_eq!(databases[1].public_port, Some(6380));
    assert_eq!(databases[1].is_public, Some(true));

    let deployments = items(&found.deployments);
    assert_eq!(deployments.len(), 2, "the active deployment is not doubled");
    assert_eq!(deployments[0].deployment_uuid, "depactive00000000011");
    assert_eq!(
        deployments[0].application_uuid.as_deref(),
        Some("appweb000000000001"),
        "the per-application listing supplies the application uuid"
    );
    assert_eq!(
        deployments[0].commit_message.as_deref(),
        Some("Fix checkout rounding"),
        "only the first line of the message is kept"
    );
    assert_eq!(deployments[1].status, "finished");

    assert_read_only_requests(&seen);
}

#[tokio::test]
async fn a_read_sensitive_token_still_yields_no_secret_values() {
    let (plain_base, _) = stub(fixture_routes("v4.4.6")).await;
    let (sensitive_base, seen) = stub(fixture_routes("v4.4.6-read-sensitive")).await;
    let plain = discover(&plain_base, TOKEN).await;
    let sensitive = discover(&sensitive_base, TOKEN).await;
    let text = rendered(&sensitive);
    assert!(!text.contains("SENTINEL"), "a secret value leaked: {text}");
    assert!(!text.contains("PRIVATE KEY"));
    assert!(!text.contains("x-access-token"));
    assert_eq!(
        text,
        rendered(&plain),
        "sensitive-only fields must not change the translation"
    );
    assert_read_only_requests(&seen);
}

#[tokio::test]
async fn an_insufficient_permission_token_fails_every_class_after_one_request() {
    let mut routes = Routes::new();
    routes.insert(
        "/api/v1/version".to_owned(),
        (
            403,
            String::new(),
            r#"{"message":"You are not allowed to perform this action. Missing required permissions: read"}"#
                .to_owned(),
        ),
    );
    let (base, seen) = stub(routes).await;
    let found = discover(&base, TOKEN).await;
    assert_eq!(found.version, None);
    assert_eq!(
        failed_kind(&found.servers),
        FailureKind::InsufficientPermission
    );
    assert_eq!(
        failed_kind(&found.deployments),
        FailureKind::InsufficientPermission
    );
    assert_eq!(seen.lock().expect("log").len(), 1);
}

#[tokio::test]
async fn a_refused_token_is_unauthorized_and_an_api_disabled_403_is_too() {
    for (status, body) in [
        (401, r#"{"message":"Unauthenticated."}"#),
        (403, r#"{"message":"You are not allowed to use the API."}"#),
    ] {
        let mut routes = Routes::new();
        routes.insert(
            "/api/v1/version".to_owned(),
            (status, String::new(), body.to_owned()),
        );
        let (base, seen) = stub(routes).await;
        let found = discover(&base, TOKEN).await;
        assert_eq!(failed_kind(&found.applications), FailureKind::Unauthorized);
        assert_eq!(seen.lock().expect("log").len(), 1);
    }
}

#[tokio::test]
async fn an_answer_that_is_not_coolify_fails_every_class() {
    let mut routes = Routes::new();
    routes.insert(
        "/api/v1/version".to_owned(),
        (200, String::new(), "<html>hello</html>".to_owned()),
    );
    let (base, _) = stub(routes).await;
    let found = discover(&base, TOKEN).await;
    assert_eq!(failed_kind(&found.servers), FailureKind::Unreachable);
}

#[tokio::test]
async fn one_failing_class_does_not_stop_the_others() {
    let mut routes = fixture_routes("v4.4.6");
    routes.insert(
        "/api/v1/applications".to_owned(),
        (
            500,
            String::new(),
            "<html>boom with a secret</html>".to_owned(),
        ),
    );
    routes.remove("/api/v1/databases");
    routes.insert(
        "/api/v1/servers".to_owned(),
        (
            301,
            "Location: https://elsewhere.example.test/x?token=abc\r\n".to_owned(),
            String::new(),
        ),
    );
    routes.insert(
        "/api/v1/services".to_owned(),
        (200, String::new(), r#"{"not":"an array"}"#.to_owned()),
    );
    let (base, seen) = stub(routes).await;
    let found = discover(&base, TOKEN).await;

    assert_eq!(
        failed_kind(&found.applications),
        FailureKind::InvalidResponse
    );
    assert_eq!(failed_kind(&found.databases), FailureKind::NotFound);
    assert_eq!(failed_kind(&found.services), FailureKind::InvalidResponse);
    let ClassResult::Failed(redirect) = &found.servers else {
        panic!("servers should fail");
    };
    assert_eq!(redirect.kind, FailureKind::Unreachable);
    assert!(redirect.detail.contains("elsewhere.example.test"));
    assert!(!redirect.detail.contains("token=abc"), "{redirect:?}");
    let ClassResult::Failed(applications) = &found.applications else {
        panic!("applications should fail");
    };
    assert!(!applications.detail.contains("secret"), "{applications:?}");

    // Projects are unaffected, and deployments degrade to the active list.
    assert!(matches!(found.projects, ClassResult::Complete(_)));
    let ClassResult::Partial(deployments, reasons) = &found.deployments else {
        panic!("deployments should be partial: {:?}", found.deployments);
    };
    assert_eq!(deployments.len(), 1);
    assert!(!reasons.is_empty());
    assert_read_only_requests(&seen);
}

#[tokio::test]
async fn a_failed_environment_fetch_makes_projects_partial() {
    let mut routes = fixture_routes("v4.4.6");
    routes.remove("/api/v1/projects/prjtools000000000002/environments");
    let (base, _) = stub(routes).await;
    let found = discover(&base, TOKEN).await;
    let ClassResult::Partial(projects, reasons) = &found.projects else {
        panic!("projects should be partial");
    };
    assert_eq!(projects.len(), 2);
    assert_eq!(projects[0].environments.len(), 2);
    assert!(projects[1].environments.is_empty());
    assert_eq!(reasons[0].kind, FailureKind::NotFound);
}

#[tokio::test]
async fn an_identifier_with_an_unexpected_shape_is_never_interpolated() {
    let mut routes = fixture_routes("v4.4.6");
    routes.insert(
        "/api/v1/projects".to_owned(),
        (
            200,
            String::new(),
            r#"[{"uuid":"../../servers","name":"evil"},{"uuid":"prjshop0000000000001","name":"shop"}]"#
                .to_owned(),
        ),
    );
    let (base, seen) = stub(routes).await;
    let found = discover(&base, TOKEN).await;
    let ClassResult::Partial(projects, _) = &found.projects else {
        panic!("projects should be partial");
    };
    assert!(projects[0].environments.is_empty());
    assert_eq!(projects[1].environments.len(), 2);
    assert!(
        seen.lock()
            .expect("log")
            .iter()
            .all(|line| !line.contains("..")),
        "an unsafe id reached the wire"
    );
}

#[tokio::test]
async fn nothing_listening_fails_every_class_as_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);
    let found = discover(&base, TOKEN).await;
    assert_eq!(failed_kind(&found.servers), FailureKind::Unreachable);
    assert_eq!(failed_kind(&found.deployments), FailureKind::Unreachable);
}

#[tokio::test]
async fn capture_records_scrubbed_fixtures_without_the_token_or_real_names() {
    let (base, seen) = stub(fixture_routes("v4.4.6-read-sensitive")).await;
    let files = fleet_provider_coolify::scrub::capture(&base, TOKEN)
        .await
        .expect("capture");
    let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
    for expected in [
        "version.txt",
        "servers.json",
        "applications.json",
        "databases.json",
        "project-environments.json",
        "service-applications.json",
        "application-deployments.json",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
    for (name, body) in &files {
        for leak in [
            "SENTINEL",
            TOKEN,
            "shop.example.test",
            "localhost",
            "198.51.100.7",
            "appweb0000",
            "PRIVATE KEY",
        ] {
            assert!(!body.contains(leak), "{name} still has {leak}: {body}");
        }
    }
    assert_read_only_requests(&seen);
}
