//! The desired-source management surface (FM-405) end to end over the real
//! router and store: configure the remote, fetch and activate through
//! durable operations, and roll back from the stored snapshot.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::operation::Operations;
use fleet_application::source::DesiredSource;
use fleet_controller::source::SourceExecutor;
use fleet_storage_sqlite::{SourceRepository, Store};
use tower::ServiceExt as _;

const CONFIG: &str = "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: FleetConfig\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58f2a1\n  name: local-fleet\nspec: {}\n";
const SECOND: &str = "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: FleetConfig\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58f2a2\n  name: second-fleet\nspec: {}\n";

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.test"])
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn commit(repo: &Path, body: &str) -> String {
    if !repo.join(".git").exists() {
        std::fs::create_dir_all(repo).unwrap();
        git(repo, &["init", "--quiet"]);
    }
    std::fs::write(repo.join("fleet.yaml"), body).unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "--quiet", "-m", "desired"]);
    git(repo, &["rev-parse", "HEAD"])
}

struct Harness {
    state: Arc<ApiState>,
    operations: Arc<Operations>,
    executor: SourceExecutor,
    _store: Store,
}

async fn harness(dir: &Path) -> Harness {
    let store = Store::open(&dir.join("fleet.db")).await.unwrap();
    let audit = || Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone()));
    let source = Arc::new(DesiredSource::new(
        Arc::new(SourceRepository::new(store.pool().clone())),
        audit(),
    ));
    let operations = Arc::new(Operations::new(
        Arc::new(fleet_storage_sqlite::OperationRepository::new(
            store.pool().clone(),
        )),
        audit(),
    ));
    let state = Arc::new(ApiState {
        operations: operations.clone(),
        desired: Some(source.clone()),
        authorizer: Arc::new(fleet_auth::LanAllowAllAuthorizer),
        ..ApiState::for_document()
    });
    Harness {
        state,
        operations,
        executor: SourceExecutor::new(dir.join("git-source"), source),
        _store: store,
    }
}

impl Harness {
    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let app = router(self.state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
            id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        }));
        let builder = Request::builder()
            .method(method)
            .uri(format!("{API_BASE_PATH}{path}"))
            .header(
                CORRELATION_ID_HEADER,
                "01900000-0000-7000-8000-000000000000",
            );
        let request = match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        }
        .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    /// Runs the accepted operation the way the worker would and returns it.
    async fn run(&self, accepted: &serde_json::Value) -> serde_json::Value {
        let id = accepted["data"]["id"].as_str().unwrap();
        self.operations
            .claim_only_execute(&self.executor, id, "test-worker")
            .await
            .ok();
        let (_, done) = self.call("GET", &format!("/operations/{id}"), None).await;
        let mut operation = done["data"].clone();
        // The DTO carries the recorded result as JSON text.
        if let Some(result) = operation["resultJson"].as_str() {
            operation["result"] = serde_json::from_str(result).unwrap();
        }
        operation
    }
}

#[tokio::test]
async fn the_remote_refuses_credentials_and_is_readable_once_set() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path()).await;
    let (status, body) = harness.call("GET", "/desired/source", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["data"]["remote"].is_null());
    let (status, _) = harness
        .call(
            "PUT",
            "/desired/source",
            Some(serde_json::json!({"remote": "https://u:secret@example.test/r.git"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, body) = harness.call("GET", "/desired/source", None).await;
    assert!(body["data"]["remote"].is_null(), "a refusal stores nothing");
    let (status, body) = harness
        .call(
            "PUT",
            "/desired/source",
            Some(serde_json::json!({"remote": "ssh://git@example.test/r.git"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["remote"], "ssh://git@example.test/r.git");
}

#[tokio::test]
async fn fetch_needs_a_configured_remote_and_a_full_commit_sha() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path()).await;
    let sha = "a".repeat(40);
    let (status, body) = harness
        .call(
            "POST",
            "/desired/fetch",
            Some(serde_json::json!({"commitSha": sha})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("no desired-source remote")
    );
    harness
        .call(
            "PUT",
            "/desired/source",
            Some(serde_json::json!({"remote": "https://example.test/r.git"})),
        )
        .await;
    let (status, _) = harness
        .call(
            "POST",
            "/desired/fetch",
            Some(serde_json::json!({"commitSha": "HEAD"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = harness
        .call(
            "POST",
            "/desired/activate",
            Some(serde_json::json!({"commitSha": sha, "contentDigest": "short"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn fetch_activate_and_rollback_run_as_operations() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("desired");
    let first = commit(&repo, CONFIG);
    let harness = harness(dir.path()).await;
    harness
        .call(
            "PUT",
            "/desired/source",
            Some(serde_json::json!({"remote": repo.to_str().unwrap()})),
        )
        .await;

    // The fetch remote is the configured one: the payload never carries a caller's.
    let (status, accepted) = harness
        .call(
            "POST",
            "/desired/fetch",
            Some(serde_json::json!({"commitSha": first})),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    let done = harness.run(&accepted).await;
    assert_eq!(done["state"], "succeeded", "{done}");
    let digest_one = done["result"]["contentDigest"].as_str().unwrap().to_owned();
    let (_, accepted) = harness
        .call(
            "POST",
            "/desired/activate",
            Some(serde_json::json!({"commitSha": first, "contentDigest": digest_one})),
        )
        .await;
    assert_eq!(harness.run(&accepted).await["state"], "succeeded");

    let second = commit(&repo, SECOND);
    let (_, accepted) = harness
        .call(
            "POST",
            "/desired/fetch",
            Some(serde_json::json!({"commitSha": second})),
        )
        .await;
    let digest_two = harness.run(&accepted).await["result"]["contentDigest"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, accepted) = harness
        .call(
            "POST",
            "/desired/activate",
            Some(serde_json::json!({"commitSha": second, "contentDigest": digest_two})),
        )
        .await;
    assert_eq!(harness.run(&accepted).await["state"], "succeeded");
    let (_, revision) = harness.call("GET", "/desired/revision", None).await;
    assert_eq!(revision["data"]["active"]["commitSha"], second);

    let (_, history) = harness.call("GET", "/desired/history", None).await;
    let entries = history["items"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries.iter().filter(|e| e["active"] == true).count(), 1);

    // The worktrees are gone: a rollback needs only the stored snapshot.
    std::fs::remove_dir_all(dir.path().join("git-source")).unwrap();
    let (status, accepted) = harness
        .call(
            "POST",
            "/desired/rollback",
            Some(serde_json::json!({"commitSha": first, "contentDigest": digest_one})),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    let done = harness.run(&accepted).await;
    assert_eq!(done["state"], "succeeded", "{done}");
    let (_, revision) = harness.call("GET", "/desired/revision", None).await;
    assert_eq!(revision["data"]["active"]["commitSha"], first);
    let (_, resources) = harness.call("GET", "/desired/resources", None).await;
    assert_eq!(resources["items"][0]["name"], "local-fleet");

    // An unrecorded revision is refused by the operation.
    let (_, accepted) = harness
        .call(
            "POST",
            "/desired/rollback",
            Some(serde_json::json!({"commitSha": "b".repeat(40), "contentDigest": "c".repeat(64)})),
        )
        .await;
    assert_eq!(harness.run(&accepted).await["state"], "failed");
}
