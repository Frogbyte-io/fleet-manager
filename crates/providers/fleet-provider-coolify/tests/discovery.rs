//! Contract tests for read discovery over recorded fixtures.
//!
//! The fixtures under `tests/fixtures/v4.4.6/` are SYNTHETIC: they were
//! written from the response schemas in Coolify v4.4.6's `openapi.json` and
//! the Api controllers (`ServersController`, `ProjectController`,
//! `ApplicationsController`, `ServicesController`, `DatabasesController`,
//! `DeployController`), with invented, `example.test` data. Real-instance
//! fixtures are pending: an operator records them with the ignored
//! `capture` test (`tests/capture.rs`), which scrubs on the way out and
//! names the files the way `fixture_routes` reads them.
//! `tests/fixtures/v4.4.6-read-sensitive/` is the same data with the
//! extra fields Coolify returns to a `read:sensitive` token, each carrying a
//! `SENTINEL-` marker that must never come out of discovery.
//!
//! The stub server records every request line; discovery may only send
//! `GET` requests to the documented read routes (an allow-list of exact
//! route patterns).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleet_application::coolify::{ClassResult, FailureKind, RawCoolifyDiscovery};
use fleet_provider_coolify::scrub::check_fixture_dir;
use fleet_provider_coolify::{Limits, discover, discover_with};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const TOKEN: &str = "3|coolify-read-token-value";

type Routes = HashMap<String, (u16, String, String)>;
type Seen = Arc<Mutex<Vec<String>>>;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Routes serving a fixture directory, by file name: `version.txt`,
/// `servers.json`, `projects.json`, `applications.json`, `services.json`,
/// `databases.json`, `deployments-active.json`, and
/// `project-environments-<uuid>.json`, `service-applications-<uuid>.json`,
/// `application-deployments-<uuid>.json`. Path (with query) -> (status,
/// headers, body).
fn dir_routes(dir: &Path) -> Routes {
    let mut routes = Routes::new();
    for entry in std::fs::read_dir(dir).expect("fixture directory") {
        let path = entry.expect("entry").path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let body = std::fs::read_to_string(&path).expect("fixture readable");
        let route = match name.as_str() {
            "version.txt" => "/version".to_owned(),
            "servers.json" => "/servers".to_owned(),
            "projects.json" => "/projects".to_owned(),
            "applications.json" => "/applications".to_owned(),
            "services.json" => "/services".to_owned(),
            "databases.json" => "/databases".to_owned(),
            "deployments-active.json" => "/deployments".to_owned(),
            other => {
                let Some(stem) = other.strip_suffix(".json") else {
                    continue;
                };
                if let Some(uuid) = stem.strip_prefix("project-environments-") {
                    format!("/projects/{uuid}/environments")
                } else if let Some(uuid) = stem.strip_prefix("service-applications-") {
                    format!("/services/{uuid}/applications")
                } else if let Some(uuid) = stem.strip_prefix("application-deployments-") {
                    format!("/deployments/applications/{uuid}?skip=0&take=5")
                } else {
                    continue; // an alternative shape used by a dedicated test
                }
            }
        };
        routes.insert(format!("/api/v1{route}"), (200, String::new(), body));
    }
    routes
}

fn fixture_routes(version: &str) -> Routes {
    dir_routes(&fixtures_root().join(version))
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

/// Accepts connections and never answers.
async fn hanging_stub() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    base
}

fn items<T: Clone>(result: &ClassResult<T>) -> Vec<T> {
    match result {
        ClassResult::Complete(items) | ClassResult::Partial(items, _) => items.clone(),
        ClassResult::Failed(failure) => panic!("the class failed: {failure:?}"),
    }
}

fn failed<T>(result: &ClassResult<T>) -> (FailureKind, String) {
    match result {
        ClassResult::Failed(failure) => (failure.kind, failure.detail.clone()),
        _ => panic!("the class did not fail"),
    }
}

fn failed_kind<T>(result: &ClassResult<T>) -> FailureKind {
    failed(result).0
}

fn assert_complete<T>(result: &ClassResult<T>, class: &str) {
    assert!(
        matches!(result, ClassResult::Complete(_)),
        "{class} should be complete"
    );
}

/// The exact route patterns discovery may request. Segments starting with
/// `{` match one safe identifier.
const ALLOWED: [&str; 10] = [
    "/api/v1/version",
    "/api/v1/servers",
    "/api/v1/projects",
    "/api/v1/projects/{id}/environments",
    "/api/v1/applications",
    "/api/v1/services",
    "/api/v1/services/{id}/applications",
    "/api/v1/databases",
    "/api/v1/deployments",
    "/api/v1/deployments/applications/{id}?skip=0&take=5",
];

fn matches_pattern(target: &str, pattern: &str) -> bool {
    let (path, query) = target.split_once('?').map_or((target, ""), |(p, q)| (p, q));
    let (pattern_path, pattern_query) = pattern
        .split_once('?')
        .map_or((pattern, ""), |(p, q)| (p, q));
    let segments: Vec<&str> = path.split('/').collect();
    let pattern_segments: Vec<&str> = pattern_path.split('/').collect();
    query == pattern_query
        && segments.len() == pattern_segments.len()
        && segments.iter().zip(&pattern_segments).all(|(s, p)| {
            if p.starts_with('{') {
                !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            } else {
                s == p
            }
        })
}

fn assert_read_only_requests(seen: &Seen) {
    let seen = seen.lock().expect("log");
    assert!(!seen.is_empty());
    for line in seen.iter() {
        let mut words = line.split_whitespace();
        assert_eq!(words.next(), Some("GET"), "{line}");
        let target = words.next().expect("target");
        assert!(
            ALLOWED
                .iter()
                .any(|pattern| matches_pattern(target, pattern)),
            "a route outside the allow-list: {line}"
        );
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

#[test]
fn the_route_allow_list_matches_exactly() {
    assert!(matches_pattern(
        "/api/v1/projects/abc-1/environments",
        "/api/v1/projects/{id}/environments"
    ));
    for bad in [
        "/api/v1/projects/abc/envs",
        "/api/v1/projects/../environments",
        "/api/v1/deployments/applications/x?skip=0&take=50",
        "/api/v1/enable",
        "/api/v1/deploy?uuid=x",
        "/api/v1/applications/x/start",
    ] {
        assert!(
            !ALLOWED.iter().any(|pattern| matches_pattern(bad, pattern)),
            "{bad}"
        );
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn every_class_is_translated_from_the_recorded_fixtures() {
    let (base, seen) = stub(fixture_routes("v4.4.6")).await;
    let found = discover(&base, TOKEN).await;
    assert_eq!(found.version.as_deref(), Some("4.4.6"));
    assert!(
        found.warnings.is_empty(),
        "a read-only token warns of nothing"
    );

    for (class, complete) in [
        ("servers", matches!(found.servers, ClassResult::Complete(_))),
        (
            "projects",
            matches!(found.projects, ClassResult::Complete(_)),
        ),
        (
            "applications",
            matches!(found.applications, ClassResult::Complete(_)),
        ),
        (
            "services",
            matches!(found.services, ClassResult::Complete(_)),
        ),
        (
            "databases",
            matches!(found.databases, ClassResult::Complete(_)),
        ),
        (
            "deployments",
            matches!(found.deployments, ClassResult::Complete(_)),
        ),
    ] {
        assert!(complete, "{class} should be complete");
    }

    let servers = items(&found.servers);
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0].name, "localhost");
    assert_eq!(servers[0].reachable, Some(true));
    assert_eq!(servers[1].address, "192.0.2.7");
    assert_eq!(servers[1].reachable, Some(false));

    let projects = items(&found.projects);
    assert_eq!(projects[0].name, "shop");
    let environments: Vec<_> = projects[0]
        .environments
        .iter()
        .map(|e| (e.id, e.name.as_str()))
        .collect();
    assert_eq!(environments, [(1, "production"), (2, "staging")]);
    assert_eq!(projects[1].environments.len(), 1);
    assert!(!projects[0].details_stale);

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
        Some("registry.example.test/example-org/legacy:1.4.2")
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
    assert_eq!(
        databases[0].engine.as_deref(),
        Some("postgresql"),
        "database_type is preferred over the image name"
    );
    assert_eq!(databases[1].engine.as_deref(), Some("redis"));
    assert_eq!(databases[1].public_port, Some(6380));
    assert_eq!(databases[1].is_public, Some(true));
    assert!(
        !serde_json::to_string(&databases)
            .unwrap()
            .contains("BACKUP-MARKER"),
        "backup configs are dropped"
    );

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
async fn a_read_sensitive_token_still_yields_no_secret_values_and_warns() {
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
    assert_eq!(sensitive.warnings.len(), 1, "{:?}", sensitive.warnings);
    assert!(sensitive.warnings[0].contains("read-only token"));
    assert_read_only_requests(&seen);
}

#[tokio::test]
async fn a_deployments_object_keyed_by_position_is_read_as_its_values() {
    let mut routes = fixture_routes("v4.4.6");
    let object =
        std::fs::read_to_string(fixtures_root().join("v4.4.6/deployments-active-object.json"))
            .expect("fixture");
    assert!(object.trim_start().starts_with('{'));
    routes.insert(
        "/api/v1/deployments".to_owned(),
        (200, String::new(), object),
    );
    let (base, _) = stub(routes).await;
    let found = discover(&base, TOKEN).await;
    assert_complete(&found.deployments, "deployments");
    let uuids: Vec<String> = items(&found.deployments)
        .into_iter()
        .map(|d| d.deployment_uuid)
        .collect();
    assert!(
        uuids.contains(&"depqueued000000000010".to_owned()),
        "{uuids:?}"
    );
    assert!(uuids.contains(&"depactive00000000011".to_owned()));
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
async fn refused_tokens_are_unauthorized_with_scrubbed_detail() {
    for (status, body) in [
        (401, r#"{"message":"Unauthenticated."}"#),
        (400, r#"{"message":"Invalid token."}"#),
        (403, r#"{"message":"You are not allowed to use the API."}"#),
    ] {
        let mut routes = Routes::new();
        routes.insert(
            "/api/v1/version".to_owned(),
            (status, String::new(), body.to_owned()),
        );
        let (base, seen) = stub(routes).await;
        let found = discover(&base, TOKEN).await;
        assert_eq!(
            failed_kind(&found.applications),
            FailureKind::Unauthorized,
            "{status}"
        );
        assert_eq!(seen.lock().expect("log").len(), 1);
    }
    // The stored 403 detail passes the shared scrubber.
    let mut routes = Routes::new();
    routes.insert(
        "/api/v1/version".to_owned(),
        (
            403,
            String::new(),
            r#"{"message":"blocked https://admin:hunter2secret@proxy.example.test/x password=hunter2secret"}"#
                .to_owned(),
        ),
    );
    let (base, _) = stub(routes).await;
    let found = discover(&base, TOKEN).await;
    let (kind, detail) = failed(&found.servers);
    assert_eq!(kind, FailureKind::Unauthorized);
    assert!(!detail.contains("hunter2secret"), "{detail}");
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
    let (kind, detail) = failed(&found.servers);
    assert_eq!(kind, FailureKind::Unreachable);
    assert!(detail.contains("elsewhere.example.test"));
    assert!(!detail.contains("token=abc"), "{detail}");
    let (_, applications) = failed(&found.applications);
    assert!(!applications.contains("secret"), "{applications}");

    // Projects are unaffected, and deployments degrade to the active list.
    assert_complete(&found.projects, "projects");
    let ClassResult::Partial(deployments, reasons) = &found.deployments else {
        panic!("deployments should be partial: {:?}", found.deployments);
    };
    assert_eq!(deployments.len(), 1);
    assert!(!reasons.is_empty());
    assert_read_only_requests(&seen);
}

#[tokio::test]
async fn a_failed_environment_fetch_makes_projects_partial_and_flags_the_item() {
    let mut routes = fixture_routes("v4.4.6");
    routes.remove("/api/v1/projects/prjtools000000000002/environments");
    let (base, _) = stub(routes).await;
    let found = discover(&base, TOKEN).await;
    let ClassResult::Partial(projects, reasons) = &found.projects else {
        panic!("projects should be partial");
    };
    assert_eq!(projects.len(), 2);
    assert_eq!(projects[0].environments.len(), 2);
    assert!(!projects[0].details_stale);
    assert!(projects[1].environments.is_empty());
    assert!(projects[1].details_stale);
    assert_eq!(reasons[0].kind, FailureKind::NotFound);
}

#[tokio::test]
async fn a_follow_up_route_that_answers_not_found_is_not_asked_again() {
    // Before Coolify v4.2.0 there is no /services/{uuid}/applications.
    let mut routes = fixture_routes("v4.4.6");
    routes.remove("/api/v1/services/svcplausible000000001/applications");
    routes.remove("/api/v1/services/svcminio0000000000002/applications");
    let (base, seen) = stub(routes).await;
    let found = discover(&base, TOKEN).await;
    let ClassResult::Partial(services, reasons) = &found.services else {
        panic!("services should be partial");
    };
    assert!(services.iter().all(|s| s.details_stale));
    assert_eq!(reasons[0].kind, FailureKind::NotFound);
    let asked = seen
        .lock()
        .expect("log")
        .iter()
        .filter(|line| line.contains("/services/") && line.contains("/applications"))
        .count();
    assert_eq!(asked, 1, "the route family was asked once, then remembered");
}

#[tokio::test]
async fn top_level_lists_are_fetched_before_any_follow_up() {
    let (base, seen) = stub(fixture_routes("v4.4.6")).await;
    let _ = discover(&base, TOKEN).await;
    let seen = seen.lock().expect("log");
    let first_follow_up = seen
        .iter()
        .position(|line| {
            line.contains("/environments")
                || line.contains("/services/")
                || line.contains("/deployments/applications/")
        })
        .expect("follow-ups ran");
    let last_list = seen
        .iter()
        .rposition(|line| {
            [
                " /api/v1/servers ",
                " /api/v1/projects ",
                " /api/v1/applications ",
                " /api/v1/services ",
                " /api/v1/databases ",
                " /api/v1/deployments ",
            ]
            .iter()
            .any(|list| line.contains(list))
        })
        .expect("lists ran");
    assert!(last_list < first_follow_up, "{seen:?}");
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
async fn the_first_429_stops_every_later_request_and_reports_retry_after() {
    let mut routes = fixture_routes("v4.4.6");
    routes.insert(
        "/api/v1/applications".to_owned(),
        (
            429,
            "Retry-After: 7\r\n".to_owned(),
            r#"{"message":"Too Many Attempts."}"#.to_owned(),
        ),
    );
    let (base, seen) = stub(routes).await;
    let started = std::time::Instant::now();
    let found = discover(&base, TOKEN).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the run must not wait out Retry-After"
    );
    assert_complete(&found.servers, "servers");
    let (kind, detail) = failed(&found.applications);
    assert_eq!(kind, FailureKind::RateLimited);
    assert!(detail.contains("7s"), "{detail}");
    assert_eq!(failed_kind(&found.services), FailureKind::RateLimited);
    assert_eq!(failed_kind(&found.databases), FailureKind::RateLimited);
    let ClassResult::Partial(projects, reasons) = &found.projects else {
        panic!("projects should be partial: {:?}", found.projects);
    };
    assert!(projects.iter().all(|p| p.details_stale));
    assert_eq!(reasons[0].kind, FailureKind::RateLimited);
    // version, servers, projects, applications: nothing after the 429.
    assert_eq!(seen.lock().expect("log").len(), 4);
    assert_read_only_requests(&seen);
}

#[tokio::test]
async fn the_request_budget_bounds_a_run() {
    let (base, seen) = stub(fixture_routes("v4.4.6")).await;
    let limits = Limits {
        max_requests: 8,
        ..Limits::default()
    };
    let found = discover_with(&base, TOKEN, limits).await;
    assert_eq!(seen.lock().expect("log").len(), 8);
    assert!(
        matches!(
            found.deployments,
            ClassResult::Partial(..) | ClassResult::Failed(_)
        ),
        "the budget leaves later work undone"
    );
    let ClassResult::Partial(_, reasons) = &found.deployments else {
        return;
    };
    assert!(reasons.iter().any(|r| r.kind == FailureKind::RateLimited));
}

#[tokio::test]
async fn an_oversized_response_is_refused_at_the_body_limit() {
    let (base, _) = stub(fixture_routes("v4.4.6")).await;
    let limits = Limits {
        body_limit: 120,
        ..Limits::default()
    };
    let found = discover_with(&base, TOKEN, limits).await;
    let (kind, detail) = failed(&found.servers);
    assert_eq!(kind, FailureKind::InvalidResponse);
    assert!(detail.contains("larger"), "{detail}");
}

#[tokio::test]
async fn a_silent_server_times_out_per_request_and_per_run() {
    let base = hanging_stub().await;
    let per_request = Limits {
        request_timeout: Duration::from_millis(150),
        ..Limits::default()
    };
    let found = discover_with(&base, TOKEN, per_request).await;
    assert_eq!(failed_kind(&found.servers), FailureKind::Timeout);
    let per_run = Limits {
        run_budget: Duration::from_millis(150),
        ..Limits::default()
    };
    let found = discover_with(&base, TOKEN, per_run).await;
    assert_eq!(failed_kind(&found.deployments), FailureKind::Timeout);
}

#[test]
fn every_committed_fixture_directory_is_clean() {
    let mut checked = 0;
    for entry in std::fs::read_dir(fixtures_root()).expect("fixtures") {
        let path = entry.expect("entry").path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        // The read-sensitive variant is poisoned on purpose.
        if name.ends_with("read-sensitive") {
            continue;
        }
        check_fixture_dir(&path).unwrap_or_else(|error| panic!("{name}: {error}"));
        checked += 1;
    }
    assert!(checked >= 1);
}

#[tokio::test]
async fn committed_fixture_directories_discover_without_failure_and_the_synthetic_ones_completely()
{
    for entry in std::fs::read_dir(fixtures_root()).expect("fixtures") {
        let path = entry.expect("entry").path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let (base, _) = stub(dir_routes(&path)).await;
        let found = discover(&base, TOKEN).await;
        assert!(found.version.is_some(), "{name}");
        // No class failed (`items` panics on a failed class).
        rendered(&found);
        // The synthetic sets serve every route, so nothing is partial.
        if name.starts_with("v4.4.6") {
            assert_complete(&found.servers, &name);
            assert_complete(&found.projects, &name);
            assert_complete(&found.applications, &name);
            assert_complete(&found.services, &name);
            assert_complete(&found.databases, &name);
            assert_complete(&found.deployments, &name);
        }
    }
}

#[tokio::test]
async fn capture_records_scrubbed_fixtures_the_contract_tests_can_read() {
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
        "deployments-active.json",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
    for prefix in [
        "project-environments-uuid",
        "service-applications-uuid",
        "application-deployments-uuid",
    ] {
        assert!(
            names.iter().any(|name| name.starts_with(prefix)),
            "{prefix} missing from {names:?}"
        );
    }
    for (name, body) in &files {
        for leak in [
            "SENTINEL",
            TOKEN,
            "shop.example.test",
            "localhost",
            "192.0.2.7",
            "appweb0000",
            "PRIVATE KEY",
            "BACKUP-MARKER",
            "127.0.0.1",
        ] {
            // The scrubber may legitimately emit 192.0.2.x addresses; only
            // the real fixture address and identities must be gone.
            if leak == "192.0.2.7" {
                continue;
            }
            assert!(!body.contains(leak), "{name} still has {leak}: {body}");
        }
    }
    assert_read_only_requests(&seen);

    // The recorded set loads as a fixture directory and discovers cleanly.
    let dir = tempfile::tempdir().expect("temp dir");
    for (name, body) in &files {
        std::fs::write(dir.path().join(name), body).expect("write");
    }
    check_fixture_dir(dir.path()).expect("the recorded set is clean");
    let (recorded_base, _) = stub(dir_routes(dir.path())).await;
    let found = discover(&recorded_base, TOKEN).await;
    assert_eq!(found.version.as_deref(), Some("4.4.6"));
    assert_complete(&found.projects, "projects");
    assert_eq!(
        items(&found.projects)
            .iter()
            .filter(|p| !p.details_stale)
            .count(),
        items(&found.projects).len().min(3),
        "the expanded projects carry their environments"
    );
    assert!(!items(&found.deployments).is_empty());
}

#[tokio::test]
async fn only_the_catch_all_404_makes_a_route_family_missing() {
    // A resource-specific 404 ("Project not found.") says nothing about the
    // route: the next project still gets its environments.
    let mut routes = fixture_routes("v4.4.6");
    routes.insert(
        "/api/v1/projects/prjshop0000000000001/environments".to_owned(),
        (
            404,
            String::new(),
            r#"{"message":"Project not found."}"#.to_owned(),
        ),
    );
    let (base, seen) = stub(routes).await;
    let found = discover(&base, TOKEN).await;
    let ClassResult::Partial(projects, reasons) = &found.projects else {
        panic!("projects should be partial");
    };
    assert!(projects[0].details_stale && projects[0].environments.is_empty());
    assert!(!projects[1].details_stale);
    assert_eq!(projects[1].environments.len(), 1);
    assert_eq!(reasons[0].kind, FailureKind::NotFound);
    let asked = seen
        .lock()
        .expect("log")
        .iter()
        .filter(|line| line.contains("/environments"))
        .count();
    assert_eq!(asked, 2);
}

#[tokio::test]
async fn only_integer_keyed_objects_of_objects_are_lists() {
    for (body, valid) in [
        (r#"{"1":{"uuid":"srv1"},"0":{"uuid":"srv2"}}"#, true),
        (r#"[{"uuid":"srv1"}]"#, true),
        (r"[]", true),
        (r"{}", false),
        (r#"{"data":[{"uuid":"srv1"}]}"#, false),
        (r#"{"error":{"message":"x"}}"#, false),
        (r#"{"1":[{"uuid":"srv1"}]}"#, false),
        (r#"{"a":{"uuid":"srv1"}}"#, false),
    ] {
        let mut routes = fixture_routes("v4.4.6");
        routes.insert(
            "/api/v1/servers".to_owned(),
            (200, String::new(), body.to_owned()),
        );
        let (base, _) = stub(routes).await;
        let found = discover(&base, TOKEN).await;
        match (&found.servers, valid) {
            (ClassResult::Failed(failure), false) => {
                assert_eq!(failure.kind, FailureKind::InvalidResponse, "{body}");
            }
            (ClassResult::Complete(_) | ClassResult::Partial(..), true) => {}
            (other, _) => panic!("{body}: unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn an_object_shaped_service_answer_is_read_and_a_bad_shape_marks_the_item_stale() {
    let mut routes = fixture_routes("v4.4.6");
    routes.insert(
        "/api/v1/services/svcplausible000000001/applications".to_owned(),
        (
            200,
            String::new(),
            r#"{"0":{"fqdn":"https://obj.example.test"}}"#.to_owned(),
        ),
    );
    routes.insert(
        "/api/v1/services/svcminio0000000000002/applications".to_owned(),
        (
            200,
            String::new(),
            r#"{"data":[{"fqdn":"https://hidden.example.test"}]}"#.to_owned(),
        ),
    );
    let (base, _) = stub(routes).await;
    let found = discover(&base, TOKEN).await;
    let ClassResult::Partial(services, reasons) = &found.services else {
        panic!("services should be partial");
    };
    assert_eq!(services[0].fqdns, ["https://obj.example.test"]);
    assert!(!services[0].details_stale);
    assert!(services[1].fqdns.is_empty() && services[1].details_stale);
    assert_eq!(reasons[0].kind, FailureKind::InvalidResponse);
}
