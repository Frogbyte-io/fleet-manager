//! The Registry read surface (FM-1012) end to end: a Fleet Git repository
//! holding Registry resources is fetched, activated, replaced, and rolled
//! back through the real router and store, and `/registry/*` follows the
//! active revision. The cache is rebuildable: deleting it changes nothing.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::operation::Operations;
use fleet_controller::source::SourceExecutor;
use fleet_storage_sqlite::Store;
use tower::ServiceExt as _;

const TYPE: &str = "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryType\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58d001\n  name: vendor\nspec:\n  displayName: Vendor\n  key: slug\n  fields:\n    slug: { type: string, required: true }\n    plan: { type: string }\n  relations: [used-by, hosted-on]\n";

fn entry(suffix: &str, slug: &str, extra: &str) -> String {
    format!(
        "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryEntry\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58d{suffix}\n  name: vendor-{slug}\nspec:\n  type: vendor\n  fields: {{ slug: {slug}, plan: Pro }}\n{extra}"
    )
}

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

/// Replaces the repository's files with `files` and commits.
fn commit(repo: &Path, files: &[(&str, String)]) -> String {
    if !repo.join(".git").exists() {
        std::fs::create_dir_all(repo).unwrap();
        git(repo, &["init", "--quiet"]);
    }
    let _ = std::fs::remove_dir_all(repo.join("fleet"));
    for (path, body) in files {
        let full = repo.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, body).unwrap();
    }
    git(repo, &["add", "-A"]);
    git(
        repo,
        &["commit", "--quiet", "--allow-empty", "-m", "registry"],
    );
    git(repo, &["rev-parse", "HEAD"])
}

#[derive(Debug)]
struct Without(Permission);
impl Authorizer for Without {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.action == self.0 {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

struct Harness {
    state: Arc<ApiState>,
    operations: Arc<Operations>,
    executor: SourceExecutor,
    store: Store,
}

async fn harness(dir: &Path, authorizer: Arc<dyn Authorizer>) -> Harness {
    let store = Store::open(&dir.join("fleet.db")).await.unwrap();
    let source = Arc::new(fleet_controller::compose_desired_source(store.pool()));
    let operations = Arc::new(Operations::new(
        Arc::new(fleet_storage_sqlite::OperationRepository::new(
            store.pool().clone(),
        )),
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    ));
    let state = Arc::new(ApiState {
        operations: operations.clone(),
        desired: Some(source.clone()),
        authorizer,
        ..ApiState::for_document()
    });
    Harness {
        state,
        operations,
        executor: SourceExecutor::new(dir.join("git-source"), source),
        store,
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

    async fn get(&self, path: &str) -> serde_json::Value {
        let (status, body) = self.call("GET", path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        body
    }

    async fn run(&self, accepted: &serde_json::Value) -> serde_json::Value {
        let id = accepted["data"]["id"].as_str().unwrap();
        self.operations
            .claim_only_execute(&self.executor, id, "test-worker")
            .await
            .ok();
        let (_, done) = self.call("GET", &format!("/operations/{id}"), None).await;
        let mut operation = done["data"].clone();
        if let Some(result) = operation["resultJson"].as_str() {
            operation["result"] = serde_json::from_str(result).unwrap();
        }
        operation
    }

    /// Fetches and activates a commit; returns its content digest.
    async fn publish(&self, sha: &str) -> String {
        let (_, accepted) = self
            .call(
                "POST",
                "/desired/fetch",
                Some(serde_json::json!({"commitSha": sha})),
            )
            .await;
        let done = self.run(&accepted).await;
        assert_eq!(done["state"], "succeeded", "{done}");
        let digest = done["result"]["contentDigest"].as_str().unwrap().to_owned();
        let (_, accepted) = self
            .call(
                "POST",
                "/desired/activate",
                Some(serde_json::json!({"commitSha": sha, "contentDigest": digest})),
            )
            .await;
        assert_eq!(self.run(&accepted).await["state"], "succeeded");
        digest
    }
}

fn keys(page: &serde_json::Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            format!(
                "{}/{}",
                item["type"].as_str().unwrap(),
                item["key"].as_str().unwrap()
            )
        })
        .collect()
}

fn revision_one() -> Vec<(&'static str, String)> {
    vec![
        ("fleet/registry/types/vendor.yaml", TYPE.to_owned()),
        (
            "fleet/registry/vendor/aptabase.yaml",
            entry(
                "101",
                "aptabase",
                "  tags: [analytics, eu]\n  notes: Self-hosted analytics\n  relations:\n    - { type: hosted-on, target: { machine: build-1 } }\n    - { type: used-by, target: { registry: vendor/posthog } }\n",
            ),
        ),
        (
            "fleet/registry/vendor/posthog.yaml",
            entry("102", "posthog", "  tags: [analytics]\n"),
        ),
        (
            "fleet/registry/vendor/resend.yaml",
            entry(
                "103",
                "resend",
                "  relations:\n    - { type: used-by, target: { registry: vendor/posthog } }\n",
            ),
        ),
    ]
}

#[tokio::test]
async fn the_registry_follows_activation_replacement_and_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("desired");
    let harness = harness(dir.path(), Arc::new(fleet_auth::LanAllowAllAuthorizer)).await;

    // No revision yet: empty, honest, and not an error.
    let empty = harness.get("/registry/types").await;
    assert!(empty["revision"].is_null());
    assert_eq!(empty["items"].as_array().unwrap().len(), 0);
    let (status, _) = harness
        .call("GET", "/registry/entries/vendor/aptabase", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let first = commit(&repo, &revision_one());
    harness
        .call(
            "PUT",
            "/desired/source",
            Some(serde_json::json!({"remote": repo.to_str().unwrap()})),
        )
        .await;
    let digest_one = harness.publish(&first).await;

    // Types carry counts; entries carry the revision and their file path.
    let types = harness.get("/registry/types").await;
    assert_eq!(types["revision"]["commitSha"], first);
    assert_eq!(types["items"][0]["name"], "vendor");
    assert_eq!(types["items"][0]["origin"], "repository");
    assert_eq!(types["items"][0]["entryCount"], 3);
    assert_eq!(
        types["items"][0]["sourcePath"],
        "fleet/registry/types/vendor.yaml"
    );
    let all = harness.get("/registry/entries").await;
    assert_eq!(all["revision"]["commitSha"], first);
    assert_eq!(
        keys(&all),
        ["vendor/aptabase", "vendor/posthog", "vendor/resend"]
    );
    assert_eq!(
        all["items"][0]["sourcePath"],
        "fleet/registry/vendor/aptabase.yaml"
    );

    // Filters.
    assert_eq!(
        keys(&harness.get("/registry/entries?tag=analytics").await),
        ["vendor/aptabase", "vendor/posthog"]
    );
    assert_eq!(
        keys(&harness.get("/registry/entries?tag=eu").await),
        ["vendor/aptabase"]
    );
    assert_eq!(
        keys(&harness.get("/registry/entries?q=SELF-HOSTED").await),
        ["vendor/aptabase"]
    );
    assert_eq!(
        keys(&harness.get("/registry/entries?q=%25").await),
        Vec::<String>::new(),
        "a percent sign is a literal, not a wildcard"
    );
    assert_eq!(
        keys(&harness.get("/registry/entries?type=vendor&q=pro").await).len(),
        3
    );
    assert_eq!(
        keys(&harness.get("/registry/entries?type=nothing").await).len(),
        0
    );
    assert_eq!(
        keys(
            &harness
                .get("/registry/entries?target=registry:vendor/posthog")
                .await
        ),
        ["vendor/aptabase", "vendor/resend"]
    );
    assert_eq!(
        keys(
            &harness
                .get("/registry/entries?target=registry:vendor/posthog&relation=hosted-on")
                .await
        )
        .len(),
        0
    );
    assert_eq!(
        keys(
            &harness
                .get("/registry/entries?target=machine:build-1")
                .await
        ),
        ["vendor/aptabase"]
    );

    // Cursor pagination walks the whole set without repeats.
    let page_one = harness.get("/registry/entries?limit=2").await;
    assert_eq!(keys(&page_one), ["vendor/aptabase", "vendor/posthog"]);
    let cursor = page_one["page"]["nextCursor"].as_str().unwrap().to_owned();
    let page_two = harness
        .get(&format!("/registry/entries?limit=2&cursor={cursor}"))
        .await;
    assert_eq!(keys(&page_two), ["vendor/resend"]);
    assert!(page_two["page"]["nextCursor"].is_null());

    // One entry, with its relations and the revision.
    let one = harness.get("/registry/entries/vendor/aptabase").await;
    assert_eq!(one["revision"]["commitSha"], first);
    assert_eq!(one["data"]["fields"]["slug"], "aptabase");
    assert_eq!(one["data"]["relations"][0]["type"], "hosted-on");
    assert_eq!(one["data"]["relations"][0]["target"]["class"], "machine");
    let (status, _) = harness
        .call("GET", "/registry/entries/vendor/ghost", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Reverse relations: for an entry and for a Fleet resource.
    let pointing = harness
        .get("/registry/entries/vendor/posthog/referenced-by")
        .await;
    assert_eq!(pointing["revision"]["commitSha"], first);
    let pointing_keys: Vec<_> = pointing["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["entryKey"].as_str().unwrap(),
                item["relation"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        pointing_keys,
        [("aptabase", "used-by"), ("resend", "used-by")]
    );
    let by_machine = harness
        .get("/registry/references?target=machine:build-1")
        .await;
    assert_eq!(by_machine["items"][0]["entryKey"], "aptabase");
    assert_eq!(by_machine["items"][0]["relation"], "hosted-on");
    assert_eq!(
        by_machine["items"][0]["sourcePath"],
        "fleet/registry/vendor/aptabase.yaml"
    );
    let first_ref = harness
        .get("/registry/references?target=registry:vendor/posthog&limit=1")
        .await;
    assert_eq!(first_ref["items"].as_array().unwrap().len(), 1);
    let ref_cursor = first_ref["page"]["nextCursor"].as_str().unwrap();
    let second_ref = harness
        .get(&format!(
            "/registry/references?target=registry:vendor/posthog&limit=1&cursor={ref_cursor}"
        ))
        .await;
    assert_eq!(second_ref["items"][0]["entryKey"], "resend");
    assert!(second_ref["page"]["nextCursor"].is_null());

    // Malformed input is a 400, not a 500 or an empty answer.
    for path in [
        "/registry/references",
        "/registry/references?target=nothing",
        "/registry/references?target=bogus:x",
        "/registry/entries?target=registry:nokey",
        "/registry/entries?relation=used-by",
        "/registry/entries?cursor=nonsense",
        "/registry/references?target=machine:x&cursor=a/b",
    ] {
        let (status, body) = harness.call("GET", path, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
    }

    // The cache is never an authority: dropping it changes nothing.
    sqlx::query("DELETE FROM registry_cache_state")
        .execute(harness.store.pool())
        .await
        .unwrap();
    assert_eq!(keys(&harness.get("/registry/entries").await).len(), 3);

    // A new activation replaces the cache: aptabase is gone, a new entry is in.
    let second = commit(
        &repo,
        &[
            ("fleet/registry/types/vendor.yaml", TYPE.to_owned()),
            (
                "fleet/registry/vendor/neon.yaml",
                entry("104", "neon", "  tags: [database]\n"),
            ),
        ],
    );
    harness.publish(&second).await;
    let replaced = harness.get("/registry/entries").await;
    assert_eq!(replaced["revision"]["commitSha"], second);
    assert_eq!(keys(&replaced), ["vendor/neon"]);
    let (status, _) = harness
        .call("GET", "/registry/entries/vendor/aptabase", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        harness
            .get("/registry/references?target=machine:build-1")
            .await["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // Rolling back restores the earlier revision from its snapshot alone.
    std::fs::remove_dir_all(dir.path().join("git-source")).unwrap();
    let (_, accepted) = harness
        .call(
            "POST",
            "/desired/rollback",
            Some(serde_json::json!({"commitSha": first, "contentDigest": digest_one})),
        )
        .await;
    assert_eq!(harness.run(&accepted).await["state"], "succeeded");
    let restored = harness.get("/registry/entries").await;
    assert_eq!(restored["revision"]["commitSha"], first);
    assert_eq!(keys(&restored).len(), 3);
}

#[tokio::test]
async fn reading_the_registry_needs_the_registry_read_permission() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path(), Arc::new(Without(Permission::RegistryRead))).await;
    for path in [
        "/registry/types",
        "/registry/entries",
        "/registry/entries/vendor/aptabase",
        "/registry/entries/vendor/aptabase/referenced-by",
        "/registry/references?target=machine:build-1",
    ] {
        let (status, body) = harness.call("GET", path, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
    }
}
