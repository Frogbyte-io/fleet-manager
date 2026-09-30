//! Git credential references for the desired source (FM-412) end to end
//! over the real router, store, and encrypted secret store: the operation
//! payload carries the reference id only, a revoked reference fails the
//! fetch with a stable redacted reason, and only Git-namespace records can
//! be referenced.

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::operation::Operations;
use fleet_application::source::DesiredSource;
use fleet_controller::git_credentials::SecretBackedGitCredentials;
use fleet_controller::source::{CREDENTIAL_UNAVAILABLE, SourceExecutor};
use fleet_secrets::{SecretStore, SecretValue};
use fleet_storage_sqlite::{SourceRepository, Store};
use tower::ServiceExt as _;

const SECRET: &str = "ghp_CONTROLLER_TEST_SECRET_9x";

/// Wraps the real store and counts how often a value is resolved.
#[derive(Debug)]
struct Recording {
    inner: SecretBackedGitCredentials,
    resolves: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl fleet_application::source::GitCredentialStore for Recording {
    async fn create(&self, value: &str) -> Result<String, String> {
        self.inner.create(value).await
    }
    async fn exists(&self, reference: &str) -> Result<bool, String> {
        self.inner.exists(reference).await
    }
    async fn resolve(&self, reference: &str) -> Result<Option<String>, String> {
        self.resolves
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.resolve(reference).await
    }
}

struct Harness {
    resolves: Arc<std::sync::atomic::AtomicUsize>,
    state: Arc<ApiState>,
    operations: Arc<Operations>,
    executor: SourceExecutor,
    secrets: Arc<SecretStore>,
    pool: sqlx::SqlitePool,
    _store: Store,
}

async fn harness(dir: &Path) -> Harness {
    let store = Store::open(&dir.join("fleet.db")).await.unwrap();
    let key_path = dir.join("master.key");
    std::fs::write(
        &key_path,
        "1 0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let secrets = Arc::new(SecretStore::open(store.pool().clone(), &key_path).unwrap());
    let resolves = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let credentials = Arc::new(Recording {
        inner: SecretBackedGitCredentials::new(secrets.clone()),
        resolves: resolves.clone(),
    });
    let audit = || Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone()));
    let source = Arc::new(
        DesiredSource::new(
            Arc::new(SourceRepository::new(store.pool().clone())),
            audit(),
        )
        .with_credentials(credentials.clone()),
    );
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
        resolves,
        state,
        operations,
        executor: SourceExecutor::new(dir.join("git-source"), source).with_credentials(credentials),
        secrets,
        pool: store.pool().clone(),
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

    async fn store_and_configure(&self, remote: &str) -> String {
        let (status, stored) = self
            .call(
                "POST",
                "/desired/source/credential",
                Some(serde_json::json!({ "value": SECRET })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{stored}");
        let reference = stored["data"]["credentialRef"].as_str().unwrap().to_owned();
        let (status, body) = self
            .call(
                "PUT",
                "/desired/source",
                Some(serde_json::json!({ "remote": remote, "credentialRef": reference })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        reference
    }

    async fn fetch(&self) -> (String, fleet_application::operation::Operation) {
        let (status, accepted) = self
            .call(
                "POST",
                "/desired/fetch",
                Some(serde_json::json!({ "commitSha": "a".repeat(40) })),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
        let id = accepted["data"]["id"].as_str().unwrap().to_owned();
        self.operations
            .claim_only_execute(&self.executor, &id, "test-worker")
            .await
            .ok();
        let operation = self
            .operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &id,
            )
            .await
            .unwrap();
        (id, operation)
    }
}

#[tokio::test]
async fn the_payload_carries_the_reference_and_the_secret_is_encrypted_at_rest() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path()).await;
    let reference = harness
        .store_and_configure("https://127.0.0.1:1/fleet.git")
        .await;
    let (_, operation) = harness.fetch().await;
    let payload = operation.payload_json.clone().unwrap();
    assert!(!payload.contains(&reference), "{payload}");
    assert!(!payload.contains(SECRET), "{payload}");
    // The configured remote still resolves and uses the credential.
    assert_eq!(
        harness.resolves.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    // The live credential reaches git (the connection is refused), and the
    // failure names no secret.
    assert_eq!(operation.state, "failed", "{operation:?}");
    let error = operation.error_json.clone().unwrap_or_default();
    assert!(!error.contains(SECRET), "{error}");
    assert!(!format!("{operation:?}").contains(SECRET));

    // Nothing in the database holds the plaintext.
    let (rows,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM secret_records WHERE instr(CAST(value AS TEXT), ?1) > 0",
    )
    .bind(SECRET)
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    assert_eq!(rows, 0, "the value is sealed");
    // The audit ledger names the reference and never the value.
    let audit: Vec<(String,)> =
        sqlx::query_as("SELECT CAST(metadata_json AS TEXT) FROM audit_events")
            .fetch_all(&harness.pool)
            .await
            .unwrap_or_default();
    let all = audit
        .into_iter()
        .map(|row| row.0)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!all.contains(SECRET), "{all}");
}

#[tokio::test]
async fn a_generic_operation_for_another_remote_never_resolves_the_credential() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path()).await;
    let reference = harness
        .store_and_configure("https://127.0.0.1:1/fleet.git")
        .await;
    // A caller-chosen payload naming another remote, even smuggling the
    // reference, must fetch without credentials.
    for remote in [
        "https://attacker.invalid/x.git",
        "https://127.0.0.1:1/fleet.git/",
    ] {
        let operation = harness
            .operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &fleet_application::operation::NewOperation {
                    kind: "source.fetch".to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(
                        serde_json::json!({
                            "remote": remote,
                            "commitSha": "a".repeat(40),
                            "credentialRef": reference,
                        })
                        .to_string(),
                    ),
                    review_token: None,
                },
            )
            .await
            .unwrap();
        harness
            .operations
            .claim_only_execute(&harness.executor, &operation.id, "test-worker")
            .await
            .ok();
        let done = harness
            .operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &operation.id,
            )
            .await
            .unwrap();
        assert_eq!(done.state, "failed");
        assert!(!done.error_json.unwrap_or_default().contains(SECRET));
    }
    assert_eq!(
        harness.resolves.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the credential is never read for a remote that is not the configured one"
    );
}

#[tokio::test]
async fn a_revoked_reference_fails_the_fetch_with_a_stable_redacted_reason() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path()).await;
    let reference = harness
        .store_and_configure("https://127.0.0.1:1/fleet.git")
        .await;
    harness.secrets.delete(&reference).await.unwrap();
    let (_, operation) = harness.fetch().await;
    assert_eq!(operation.state, "failed", "{operation:?}");
    let error = operation.error_json.unwrap();
    assert!(error.contains(CREDENTIAL_UNAVAILABLE), "{error}");
    assert!(
        !error.contains(SECRET) && !error.contains(&reference),
        "{error}"
    );
}

#[tokio::test]
async fn only_git_credentials_can_be_referenced() {
    let dir = tempfile::tempdir().unwrap();
    let harness = harness(dir.path()).await;
    // Another integration's secret is not a Git credential.
    let foreign = harness
        .secrets
        .create("proxmox/account-1", SecretValue::new(b"pve-token".to_vec()))
        .await
        .unwrap();
    let (status, body) = harness
        .call(
            "PUT",
            "/desired/source",
            Some(serde_json::json!({
                "remote": "https://example.test/fleet.git",
                "credentialRef": foreign.id,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}
