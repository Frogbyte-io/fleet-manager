//! The desired-state snapshot (FM-404) end to end: a real local Git
//! repository is fetched through the source executor, its validated
//! resources are stored, and they survive a reopen. An invalid revision
//! stores nothing and can never become active.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use fleet_application::operation::{NewOperation, Operations};
use fleet_application::source::DesiredSource;
use fleet_controller::source::SourceExecutor;
use fleet_storage_sqlite::{SourceRepository, Store};

const MACHINE: &str = "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: FleetConfig\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58f2a1\n  name: local-fleet\nspec: {}\n";

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

/// Commits the files and returns the commit SHA.
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
    store: Store,
    operations: Arc<Operations>,
    executor: SourceExecutor,
    source: Arc<DesiredSource>,
}

async fn harness(dir: &Path) -> Harness {
    let store = Store::open(&dir.join("fleet.db")).await.unwrap();
    let source = Arc::new(DesiredSource::new(
        Arc::new(SourceRepository::new(store.pool().clone())),
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    ));
    let operations = Arc::new(Operations::new(
        Arc::new(fleet_storage_sqlite::OperationRepository::new(
            store.pool().clone(),
        )),
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    ));
    let executor = SourceExecutor::new(dir.join("git-source"), source.clone());
    Harness {
        store,
        operations,
        executor,
        source,
    }
}

impl Harness {
    async fn run(&self, kind: &str, payload: serde_json::Value) -> serde_json::Value {
        let operation = self
            .operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &NewOperation {
                    kind: kind.to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(payload.to_string()),
                    review_token: None,
                },
            )
            .await
            .unwrap();
        // The same path the ready workflow takes: claim, execute, and let
        // the executor record the terminal state.
        let _ = self
            .operations
            .claim_only_execute(&self.executor, &operation.id, "test-worker")
            .await;
        let done = self
            .operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &operation.id,
            )
            .await
            .unwrap();
        serde_json::json!({
            "state": done.state,
            "result": done.result_json.as_deref().and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok()),
            "error": done.error_json,
        })
    }

    async fn fetch(&self, repo: &Path, sha: &str) -> serde_json::Value {
        self.run(
            "source.fetch",
            serde_json::json!({ "remote": repo.to_str().unwrap(), "commitSha": sha }),
        )
        .await
    }

    async fn activate(&self, sha: &str, digest: &str) -> serde_json::Value {
        self.run(
            "source.activate",
            serde_json::json!({ "commitSha": sha, "contentDigest": digest }),
        )
        .await
    }
}

fn digest_of(outcome: &serde_json::Value) -> String {
    outcome["result"]["contentDigest"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn a_fetched_and_activated_revision_serves_its_resources_after_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("desired");
    let sha = commit(&repo, &[("fleet.yaml", MACHINE)]);
    let digest = {
        let harness = harness(dir.path()).await;
        let fetched = harness.fetch(&repo, &sha).await;
        assert_eq!(fetched["state"], "succeeded", "{fetched}");
        assert_eq!(fetched["result"]["valid"], true);
        assert_eq!(fetched["result"]["resourceCount"], 1);
        let digest = digest_of(&fetched);
        let activated = harness.activate(&sha, &digest).await;
        assert_eq!(activated["state"], "succeeded", "{activated}");
        // Close every pooled connection before the reopen, as a stopping
        // controller would.
        harness.store.pool().close().await;
        digest
    };

    // A restart: a fresh store and service over the same database file.
    let reopened = harness(dir.path()).await;
    let auth = fleet_auth::LanAllowAllAuthorizer;
    let summary = reopened
        .source
        .status(&auth, fleet_auth::LAN_PRINCIPAL_ID)
        .await
        .unwrap()
        .expect("the revision is still active");
    assert_eq!(summary.revision.commit_sha, sha);
    assert_eq!(summary.revision.content_digest, digest);
    assert!(summary.snapshot_held);
    assert_eq!(summary.kind_counts["FleetConfig"], 1);
    let resources = reopened
        .source
        .resources(&auth, fleet_auth::LAN_PRINCIPAL_ID, None, None, 10)
        .await
        .unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].name, "local-fleet");
}

#[tokio::test]
async fn an_invalid_revision_stores_nothing_and_never_becomes_active() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("desired");
    let good = commit(&repo, &[("fleet.yaml", MACHINE)]);
    let harness = harness(dir.path()).await;
    let good_digest = digest_of(&harness.fetch(&repo, &good).await);
    assert_eq!(
        harness.activate(&good, &good_digest).await["state"],
        "succeeded"
    );

    let bad = commit(
        &repo,
        &[(
            "broken.yaml",
            "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: Nope\n",
        )],
    );
    let fetched = harness.fetch(&repo, &bad).await;
    assert_eq!(fetched["result"]["valid"], false, "{fetched}");
    let bad_digest = digest_of(&fetched);
    let refused = harness.activate(&bad, &bad_digest).await;
    assert_eq!(refused["state"], "failed", "{refused}");

    let auth = fleet_auth::LanAllowAllAuthorizer;
    let summary = harness
        .source
        .status(&auth, fleet_auth::LAN_PRINCIPAL_ID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        summary.revision.commit_sha, good,
        "the last valid revision stays active"
    );
    let stored: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM source_revision_snapshots WHERE commit_sha = ?1")
            .bind(&bad)
            .fetch_one(harness.store.pool())
            .await
            .unwrap();
    assert_eq!(stored, 0, "an invalid candidate is never stored");
}
