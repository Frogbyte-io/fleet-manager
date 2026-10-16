//! Registry-only auto-activation, the Registry settings, and the periodic
//! fetch (FM-1014), end to end over the real router, store, and a real
//! local repository.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::operation::Operations;
use fleet_application::source::DesiredSource;
use fleet_controller::source::{GitRevisionComparer, SourceExecutor};
use fleet_controller::source_poller::{HeadResolver, PollOutcome, SourcePoller};
use fleet_storage_sqlite::{SourceRepository, Store};
use tower::ServiceExt as _;

const CONFIG: &str = "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: FleetConfig\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58f2a1\n  name: local-fleet\nspec: {}\n";
const CONFIG_CHANGED: &str = "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: FleetConfig\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58f2a1\n  name: renamed-fleet\nspec: {}\n";
const TYPE: &str = "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryType\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58d001\n  name: vendor\nspec:\n  displayName: Vendor\n  key: slug\n  fields:\n    slug: { type: string, required: true }\n    note: { type: string }\n";

fn entry(note: &str) -> String {
    format!(
        "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryEntry\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58d101\n  name: entry-one\nspec:\n  type: vendor\n  fields:\n    slug: acme\n    note: {note}\n"
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

/// Commits the given files (replacing the tree) and returns the new SHA.
fn commit(repo: &Path, files: &[(&str, &str)]) -> String {
    if !repo.join(".git").exists() {
        std::fs::create_dir_all(repo).unwrap();
        git(repo, &["init", "--quiet"]);
    }
    for (name, body) in files {
        std::fs::write(repo.join(name), body).unwrap();
    }
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "--quiet", "-m", "desired"]);
    git(repo, &["rev-parse", "HEAD"])
}

struct Harness {
    state: Arc<ApiState>,
    operations: Arc<Operations>,
    desired: Arc<DesiredSource>,
    executor: SourceExecutor,
    store: Store,
    repo: std::path::PathBuf,
}

async fn harness(dir: &Path) -> Harness {
    let store = Store::open(&dir.join("fleet.db")).await.unwrap();
    let audit = || Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone()));
    let desired = Arc::new(
        DesiredSource::new(
            Arc::new(SourceRepository::new(store.pool().clone())),
            audit(),
        )
        .with_settings(Arc::new(SourceRepository::new(store.pool().clone())))
        .with_comparer(Arc::new(GitRevisionComparer::new(dir.join("git-source")))),
    );
    let operations = Arc::new(Operations::new(
        Arc::new(fleet_storage_sqlite::OperationRepository::new(
            store.pool().clone(),
        )),
        audit(),
    ));
    let state = Arc::new(ApiState {
        operations: operations.clone(),
        desired: Some(desired.clone()),
        authorizer: Arc::new(fleet_auth::LanAllowAllAuthorizer),
        ..ApiState::for_document()
    });
    let repo = dir.join("desired");
    let harness = Harness {
        state,
        operations,
        desired: desired.clone(),
        executor: SourceExecutor::new(dir.join("git-source"), desired),
        store,
        repo,
    };
    // The remote is the local repository once it exists.
    std::fs::create_dir_all(&harness.repo).unwrap();
    git(&harness.repo, &["init", "--quiet"]);
    harness
}

impl Harness {
    fn activity(&self) -> Arc<dyn fleet_application::source::FetchActivityPort> {
        Arc::new(SourceRepository::new(self.store.pool().clone()))
    }

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

    async fn configure(&self) {
        let (status, body) = self
            .call(
                "PUT",
                "/desired/source",
                Some(serde_json::json!({"remote": self.repo.to_str().unwrap()})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// Runs the accepted operation the way the worker would.
    async fn run(&self, accepted: &serde_json::Value) -> serde_json::Value {
        let id = accepted["data"]["id"].as_str().unwrap();
        self.run_id(id).await
    }

    async fn run_id(&self, id: &str) -> serde_json::Value {
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

    /// The fetch-now endpoint, run to completion.
    async fn fetch(&self, sha: &str) -> serde_json::Value {
        let (status, accepted) = self
            .call(
                "POST",
                "/desired/fetch",
                Some(serde_json::json!({"commitSha": sha})),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
        let done = self.run(&accepted).await;
        assert_eq!(done["state"], "succeeded", "{done}");
        done
    }

    async fn activate_manually(&self, fetched: &serde_json::Value) {
        let result = &fetched["result"];
        let (_, accepted) = self
            .call(
                "POST",
                "/desired/activate",
                Some(serde_json::json!({
                    "commitSha": result["commitSha"],
                    "contentDigest": result["contentDigest"],
                })),
            )
            .await;
        assert_eq!(self.run(&accepted).await["state"], "succeeded");
    }

    async fn active_sha(&self) -> Option<String> {
        let (_, revision) = self.call("GET", "/desired/revision", None).await;
        revision["data"]["active"]["commitSha"]
            .as_str()
            .map(str::to_owned)
    }

    async fn activation_audit(&self) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT actor, metadata_json FROM audit_events WHERE metadata_json LIKE '%source_activation%' AND outcome IS NULL ORDER BY seq",
        )
        .fetch_all(self.store.pool())
        .await
        .unwrap()
    }
}

/// A repository with the first revision manually activated.
async fn activated(dir: &Path) -> Harness {
    let harness = harness(dir).await;
    harness.configure().await;
    let first = commit(
        &harness.repo,
        &[
            ("fleet.yaml", CONFIG),
            ("type.yaml", TYPE),
            ("entry.yaml", &entry("one")),
        ],
    );
    let fetched = harness.fetch(&first).await;
    assert_eq!(
        fetched["result"]["autoActivation"]["activated"], false,
        "the first activation is always manual: {fetched}"
    );
    assert_eq!(harness.active_sha().await, None);
    harness.activate_manually(&fetched).await;
    assert_eq!(harness.active_sha().await.as_deref(), Some(first.as_str()));
    harness
}

#[tokio::test]
async fn a_registry_only_push_activates_itself_and_is_audited_with_the_system_actor() {
    let dir = tempfile::tempdir().unwrap();
    let harness = activated(dir.path()).await;
    let second = commit(&harness.repo, &[("entry.yaml", &entry("two"))]);
    let fetched = harness.fetch(&second).await;
    assert_eq!(
        fetched["result"]["autoActivation"]["activated"], true,
        "{fetched}"
    );
    assert_eq!(harness.active_sha().await.as_deref(), Some(second.as_str()));
    let audit = harness.activation_audit().await;
    assert_eq!(
        audit.len(),
        2,
        "the manual and the automatic activation: {audit:?}"
    );
    let (actor, metadata) = &audit[1];
    assert_eq!(actor, "system:fleet-controller");
    assert!(metadata.contains(&second), "{metadata}");
    assert!(metadata.contains("RegistryEntry:+0/-0/~1"), "{metadata}");
    assert!(
        !metadata.contains("two"),
        "the audit event carries counts, never contents: {metadata}"
    );
}

#[tokio::test]
async fn a_mixed_revision_waits_for_manual_activation() {
    let dir = tempfile::tempdir().unwrap();
    let harness = activated(dir.path()).await;
    let first = harness.active_sha().await.unwrap();
    let mixed = commit(
        &harness.repo,
        &[
            ("fleet.yaml", CONFIG_CHANGED),
            ("entry.yaml", &entry("two")),
        ],
    );
    let fetched = harness.fetch(&mixed).await;
    assert_eq!(fetched["result"]["valid"], true);
    assert_eq!(fetched["result"]["autoActivation"]["activated"], false);
    assert_eq!(harness.active_sha().await, Some(first));
    // Manual activation still works for it.
    harness.activate_manually(&fetched).await;
    assert_eq!(harness.active_sha().await.as_deref(), Some(mixed.as_str()));
}

#[tokio::test]
async fn an_invalid_registry_revision_never_activates() {
    let dir = tempfile::tempdir().unwrap();
    let harness = activated(dir.path()).await;
    let first = harness.active_sha().await.unwrap();
    // The entry names a type that does not exist.
    let broken = entry("two").replace("type: vendor", "type: no-such-type");
    let bad = commit(&harness.repo, &[("entry.yaml", &broken)]);
    let fetched = harness.fetch(&bad).await;
    assert_eq!(fetched["result"]["valid"], false, "{fetched}");
    assert_eq!(fetched["result"]["autoActivation"]["activated"], false);
    assert_eq!(harness.active_sha().await, Some(first));
    assert_eq!(harness.activation_audit().await.len(), 1);
}

#[tokio::test]
async fn the_settings_are_readable_changeable_audited_and_gate_auto_activation() {
    let dir = tempfile::tempdir().unwrap();
    let harness = activated(dir.path()).await;
    let (status, body) = harness.call("GET", "/desired/settings", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["autoActivate"], true);
    assert_eq!(body["data"]["changeMode"], "pull-request");

    let (status, body) = harness
        .call(
            "PUT",
            "/desired/settings",
            Some(serde_json::json!({"autoActivate": false, "changeMode": "direct"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["autoActivate"], false);
    assert_eq!(body["data"]["changeMode"], "direct");
    let (_, body) = harness.call("GET", "/desired/settings", None).await;
    assert_eq!(body["data"]["changeMode"], "direct");

    for rejected in [
        serde_json::json!({}),
        serde_json::json!({"changeMode": "push"}),
    ] {
        let (status, _) = harness
            .call("PUT", "/desired/settings", Some(rejected))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    let (status, _) = harness
        .call(
            "PUT",
            "/desired/settings",
            Some(serde_json::json!({"nope": true})),
        )
        .await;
    assert!(status.is_client_error(), "unknown fields are refused");

    let events: Vec<(String, String)> = sqlx::query_as(
        "SELECT actor, metadata_json FROM audit_events WHERE metadata_json LIKE '%registry_settings_update%'",
    )
    .fetch_all(harness.store.pool())
    .await
    .unwrap();
    assert_eq!(
        events.len(),
        2,
        "one audited change (intent and outcome); rejects write nothing"
    );
    assert_eq!(events[0].0, fleet_auth::LAN_PRINCIPAL_ID);
    assert!(events[0].1.contains("registry.autoActivate"));

    // With auto-activation off a Registry-only push waits.
    let first = harness.active_sha().await.unwrap();
    let second = commit(&harness.repo, &[("entry.yaml", &entry("two"))]);
    let fetched = harness.fetch(&second).await;
    assert_eq!(fetched["result"]["autoActivation"]["activated"], false);
    assert_eq!(harness.active_sha().await, Some(first));
}

#[derive(Debug)]
struct FixedHead(std::sync::Mutex<String>);

#[async_trait::async_trait]
impl HeadResolver for FixedHead {
    async fn head(&self, _remote: &str, _credential_ref: Option<&str>) -> Result<String, String> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[tokio::test]
async fn the_poller_queues_one_fetch_never_overlaps_and_follows_new_commits() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path()).await;
    let head = Arc::new(FixedHead(std::sync::Mutex::new("a".repeat(40))));
    let poller = SourcePoller::new(
        harness.desired.clone(),
        harness.operations.clone(),
        harness.activity(),
        head.clone(),
    );

    assert_eq!(poller.tick().await, PollOutcome::NoRemote);
    harness.configure().await;

    // The head does not exist in the repository, so the fetch fails: the
    // poller retries it rather than treating it as settled.
    let PollOutcome::Queued {
        operation_id,
        commit_sha,
    } = poller.tick().await
    else {
        panic!("the first tick queues a fetch");
    };
    assert_eq!(commit_sha, "a".repeat(40));
    // Serialization: while the operation is pending, nothing else queues.
    assert_eq!(poller.tick().await, PollOutcome::Busy);
    assert_eq!(poller.tick().await, PollOutcome::Busy);
    let failed = harness.run_id(&operation_id).await;
    assert_eq!(failed["state"], "failed", "{failed}");
    assert!(matches!(poller.tick().await, PollOutcome::Queued { .. }));

    // A real commit: fetched once, then unchanged until the head moves.
    let sha = commit(&harness.repo, &[("fleet.yaml", CONFIG)]);
    *head.0.lock().unwrap() = sha.clone();
    assert_eq!(
        poller.tick().await,
        PollOutcome::Busy,
        "the retry is pending"
    );
    let pending = harness
        .operations
        .list(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            10,
        )
        .await
        .unwrap();
    for operation in pending.iter().filter(|o| o.state == "pending") {
        harness.run_id(&operation.id).await;
    }
    let PollOutcome::Queued { operation_id, .. } = poller.tick().await else {
        panic!("the moved head queues a fetch");
    };
    let done = harness.run_id(&operation_id).await;
    assert_eq!(done["state"], "succeeded", "{done}");
    assert_eq!(poller.tick().await, PollOutcome::Unchanged);
    assert_eq!(poller.tick().await, PollOutcome::Unchanged);
}

#[derive(Debug)]
struct BrokenHead;

#[async_trait::async_trait]
impl HeadResolver for BrokenHead {
    async fn head(&self, _remote: &str, _credential_ref: Option<&str>) -> Result<String, String> {
        Err("the remote is unreachable".to_owned())
    }
}

#[tokio::test]
async fn an_unreachable_remote_queues_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path()).await;
    harness.configure().await;
    let poller = SourcePoller::new(
        harness.desired.clone(),
        harness.operations.clone(),
        harness.activity(),
        Arc::new(BrokenHead),
    );
    assert_eq!(
        poller.tick().await,
        PollOutcome::ResolveFailed("the remote is unreachable".to_owned())
    );
}

#[test]
fn the_example_workflow_validates_on_pull_requests_and_holds_no_secret() {
    let guides = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/guides");
    let workflow = std::fs::read_to_string(guides.join("registry-validate.workflow.yml")).unwrap();
    assert!(workflow.contains("\non:\n  pull_request:"));
    assert!(workflow.contains("\npermissions:\n  contents: read\n"));
    assert!(workflow.contains("run: fleetctl registry validate"));
    // The job is offline: no controller token or URL reaches it.
    assert!(!workflow.contains("secrets."));
    assert!(!workflow.contains("FLEET_TOKEN"));
    // The guide names the planned command and where the workflow lives.
    let guide = std::fs::read_to_string(guides.join("registry-workflow.md")).unwrap();
    assert!(guide.contains("FM-1013"));
    assert!(guide.contains("registry-validate.workflow.yml"));
    assert!(guide.contains("POST /api/v1/desired/fetch"));
}

#[test]
fn the_git_head_resolver_reads_a_real_head() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("r");
    let sha = commit(&repo, &[("fleet.yaml", CONFIG)]);
    let source = fleet_provider_git::GitSource::new(dir.path().join("work"));
    assert_eq!(
        source.resolve_head(repo.to_str().unwrap(), None).unwrap(),
        sha
    );
    assert!(
        source
            .resolve_head(dir.path().join("missing").to_str().unwrap(), None)
            .is_err()
    );
}

#[tokio::test]
async fn an_older_registry_only_commit_never_moves_active_backwards() {
    let dir = tempfile::tempdir().unwrap();
    let harness = activated(dir.path()).await;
    let older = commit(&harness.repo, &[("entry.yaml", &entry("two"))]);
    let newer = commit(&harness.repo, &[("entry.yaml", &entry("three"))]);
    let fetched = harness.fetch(&newer).await;
    assert_eq!(fetched["result"]["autoActivation"]["activated"], true);
    // The older commit differs from the active one only in a Registry entry,
    // but it is not a descendant: it waits.
    let fetched = harness.fetch(&older).await;
    assert_eq!(fetched["result"]["autoActivation"]["activated"], false);
    assert!(
        fetched["result"]["autoActivation"]["reason"]
            .as_str()
            .unwrap()
            .contains("not a descendant"),
        "{fetched}"
    );
    assert_eq!(harness.active_sha().await.as_deref(), Some(newer.as_str()));
}

#[tokio::test]
async fn non_registry_content_riding_along_is_manual() {
    let dir = tempfile::tempdir().unwrap();
    let harness = activated(dir.path()).await;
    let first = harness.active_sha().await.unwrap();
    // A Registry change plus a non-YAML file.
    let with_text = commit(
        &harness.repo,
        &[("entry.yaml", &entry("two")), ("notes.txt", "hello")],
    );
    let fetched = harness.fetch(&with_text).await;
    assert_eq!(fetched["result"]["autoActivation"]["activated"], false);
    assert_eq!(harness.active_sha().await, Some(first.clone()));
    // A Registry change plus a changed non-Registry file whose resources do
    // not differ (only its metadata label).
    let relabelled = commit(
        &harness.repo,
        &[
            ("entry.yaml", &entry("three")),
            ("fleet.yaml", CONFIG_CHANGED),
        ],
    );
    let fetched = harness.fetch(&relabelled).await;
    assert_eq!(fetched["result"]["autoActivation"]["activated"], false);
    assert_eq!(harness.active_sha().await, Some(first));
}

#[tokio::test]
async fn the_compare_and_set_refuses_a_changed_active_and_a_setting_turned_off() {
    use fleet_application::source::{ActiveRevision, CasOutcome, SourcePort};
    let dir = tempfile::tempdir().unwrap();
    let harness = activated(dir.path()).await;
    let port = SourceRepository::new(harness.store.pool().clone());
    let active = port.active_revision().await.unwrap().unwrap();
    let other = ActiveRevision {
        commit_sha: "f".repeat(40),
        content_digest: "e".repeat(64),
    };
    // A stale expectation changes nothing, even though the revision is
    // otherwise valid input.
    let stale = ActiveRevision {
        commit_sha: "1".repeat(40),
        content_digest: "2".repeat(64),
    };
    assert_eq!(
        port.activate_if_active(Some(&stale), &other, true)
            .await
            .unwrap(),
        CasOutcome::ActiveChanged
    );
    assert_eq!(
        port.activate_if_active(None, &other, true).await.unwrap(),
        CasOutcome::ActiveChanged,
        "none-active expectation against an active revision"
    );
    assert_eq!(port.active_revision().await.unwrap(), Some(active.clone()));
    // The setting is re-read inside the serialized write.
    let (status, _) = harness
        .call(
            "PUT",
            "/desired/settings",
            Some(serde_json::json!({"autoActivate": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        port.activate_if_active(Some(&active), &other, true)
            .await
            .unwrap(),
        CasOutcome::AutoActivateOff
    );
    assert_eq!(port.active_revision().await.unwrap(), Some(active.clone()));
    // Without the setting requirement the matching expectation writes.
    assert_eq!(
        port.activate_if_active(Some(&active), &other, false)
            .await
            .unwrap(),
        CasOutcome::Activated
    );
}

#[tokio::test]
async fn a_settings_change_is_audited_under_its_own_action_with_an_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path()).await;
    let (status, _) = harness
        .call(
            "PUT",
            "/desired/settings",
            Some(serde_json::json!({"changeMode": "direct"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let events: Vec<(String, String)> = sqlx::query_as(
        "SELECT action, metadata_json FROM audit_events WHERE action = 'source.settings' ORDER BY seq",
    )
    .fetch_all(harness.store.pool())
    .await
    .unwrap();
    assert_eq!(events.len(), 2, "{events:?}");
    assert!(events[0].1.contains("registry_settings_update"));
    assert!(events[1].1.contains("registry_settings_updated"));
}

#[tokio::test]
async fn the_poller_backs_off_after_repeated_failures() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path()).await;
    harness.configure().await;
    let poller = SourcePoller::new(
        harness.desired.clone(),
        harness.operations.clone(),
        harness.activity(),
        Arc::new(BrokenHead),
    );
    assert!(matches!(poller.tick().await, PollOutcome::ResolveFailed(_)));
    assert_eq!(poller.tick().await, PollOutcome::BackingOff);
    assert!(matches!(poller.tick().await, PollOutcome::ResolveFailed(_)));
    assert_eq!(poller.tick().await, PollOutcome::BackingOff);
    assert_eq!(poller.tick().await, PollOutcome::BackingOff);
}
