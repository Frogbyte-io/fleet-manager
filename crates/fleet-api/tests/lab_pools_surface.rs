//! FM-717: the Lab pool routes. Pools are created only for a template
//! version that reverts, every mutation is authorized against `lab.config`
//! and audited before it is made, fill queues the dedicated
//! `lab.pool.fill` operation, and drain reports what left. Real SQLite
//! repositories behind the real router.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::lab::{
    ImagePinValidator, Lab, LabTemplate, LabTemplatePort as _, LabTemplateVersion, NewLabTemplate,
};
use fleet_application::lab_pool::{FillResult, LabPoolPort as _, LabPools};
use fleet_application::operation::Operations;
use fleet_application::proxmox::{NewProxmoxAccount, ProxmoxAccountPort as _};
use fleet_core::{CleanupStrategy, LabTemplateContent, ReadinessProbe};
use fleet_storage_sqlite::{
    AuditSink, LabPoolRepository, LabRepository, LeaseRepository, OperationRepository,
    ProjectRepository, ProxmoxAccountRepository, Store,
};
use tower::ServiceExt as _;

#[derive(Debug)]
struct Permit;
impl Authorizer for Permit {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

/// Denies one permission, allows the rest.
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

#[derive(Debug)]
struct NoPins;
#[async_trait::async_trait]
impl ImagePinValidator for NoPins {
    async fn promoted_version(
        &self,
        _version_id: &str,
    ) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok(None)
    }
}

/// The real audit sink, recording each intent's event as it passes.
#[derive(Debug)]
struct Recorder {
    inner: AuditSink,
    events: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl fleet_application::operation::AuditPort for Recorder {
    async fn record_intent(
        &self,
        intent: &fleet_application::audit::AuditIntent,
    ) -> Result<(), String> {
        if let Some((_, event)) = intent.metadata.entries().find(|(key, _)| *key == "event") {
            self.events.lock().unwrap().push(event.to_owned());
        }
        self.inner.record_intent(intent).await
    }
    async fn record_outcome(
        &self,
        operation_id: &str,
        outcome: fleet_application::audit::AuditOutcome,
    ) -> Result<(), String> {
        self.inner.record_outcome(operation_id, outcome).await
    }
}

struct World {
    _dir: tempfile::TempDir,
    audit: Arc<Recorder>,
    lab: Arc<Lab>,
    operations: Arc<Operations>,
    account_id: String,
    pools: Arc<LabPoolRepository>,
}

impl World {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        let now = fleet_core::SystemClock::now_unix_millis();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        for (id, cleanup) in [
            ("version-revert", CleanupStrategy::Revert),
            ("version-destroy", CleanupStrategy::Destroy),
        ] {
            let content = LabTemplateContent {
                name: id.to_owned(),
                description: String::new(),
                image_version_id: "image-version-1".to_owned(),
                cores: 2,
                memory_mib: 2048,
                disk_gib: 20,
                bootstrap_project_id: None,
                readiness_probe: ReadinessProbe::GuestAgent,
                readiness_command: None,
                ssh_user: "root".to_owned(),
                ssh_port: 22,
                ssh_trust_mode: "tofu".to_owned(),
                ssh_fingerprint: None,
                readiness_deadline_seconds: 300,
                ttl_seconds: 3_600,
                cleanup,
                audio: None,
            };
            let template: LabTemplate = labs
                .create(
                    &NewLabTemplate {
                        content: content.clone(),
                    },
                    now,
                )
                .await
                .unwrap();
            labs.publish(
                &template.id,
                &LabTemplateVersion {
                    id: id.to_owned(),
                    template_id: template.id.clone(),
                    name: content.name.clone(),
                    content,
                    image_digest: "sha256:abc".to_owned(),
                    published_by: "tester".to_owned(),
                    published_at: now,
                },
            )
            .await
            .unwrap();
        }
        let accounts = Arc::new(ProxmoxAccountRepository::new(pool.clone()));
        let account = accounts
            .create(&NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: "pve-api.example.test".to_owned(),
                port: None,
                token_id: "fleet@pve!lab".to_owned(),
            })
            .await
            .unwrap();
        let audit = Arc::new(Recorder {
            inner: AuditSink::new(pool.clone()),
            events: std::sync::Mutex::new(Vec::new()),
        });
        let lab = Lab::new(
            labs.clone(),
            labs.clone(),
            Arc::new(LeaseRepository::new(pool.clone())),
            Arc::new(NoPins),
            Arc::new(ProjectRepository::new(pool.clone())),
            audit.clone(),
        )
        .with_pools(Arc::new(LabPools::new(
            Arc::new(LabPoolRepository::new(pool.clone())),
            labs,
            accounts,
            audit.clone(),
        )));
        Self {
            _dir: dir,
            operations: Arc::new(
                Operations::new(
                    Arc::new(OperationRepository::new(pool.clone())),
                    audit.clone(),
                )
                .with_pool_members(Arc::new(
                    fleet_application::operation::PoolMembership(Arc::new(LabPoolRepository::new(
                        pool.clone(),
                    ))),
                )),
            ),
            pools: Arc::new(LabPoolRepository::new(pool.clone())),
            lab: Arc::new(lab),
            account_id: account.id,
            audit: audit.clone(),
        }
    }

    fn state(&self, authorizer: Arc<dyn Authorizer>) -> Arc<ApiState> {
        Arc::new(ApiState {
            authorizer,
            operations: self.operations.clone(),
            lab: Some(self.lab.clone()),
            ..ApiState::for_document()
        })
    }

    fn audit_events(&self, event: &str) -> usize {
        self.audit
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|seen| *seen == event)
            .count()
    }
}

async fn call(
    state: &Arc<ApiState>,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let router = router(state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }));
    let request = Request::builder()
        .method(method)
        .uri(format!("{API_BASE_PATH}{path}"))
        .header("content-type", "application/json")
        .header(
            CORRELATION_ID_HEADER,
            "01900000-0000-7000-8000-000000000000",
        )
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn create_body(version: &str, account: &str) -> serde_json::Value {
    serde_json::json!({
        "templateVersionId": version,
        "accountId": account,
        "baselineSnapshot": "baseline",
        "size": 2,
    })
}

#[tokio::test]
async fn a_pool_is_created_filled_and_drained_with_every_step_audited() {
    let world = World::new().await;
    let state = world.state(Arc::new(Permit));
    let (status, body) = call(
        &state,
        "POST",
        "/lab/pools",
        Some(create_body("version-revert", &world.account_id)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let pool_id = body["data"]["id"].as_str().unwrap().to_owned();
    assert_eq!(body["data"]["baselineSnapshot"], "baseline");
    assert_eq!(world.audit_events("lab_pool_creating"), 1);

    // One pool per template version.
    let (status, _) = call(
        &state,
        "POST",
        "/lab/pools",
        Some(create_body("version-revert", &world.account_id)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, body) = call(
        &state,
        "POST",
        &format!("/lab/pools/{pool_id}/fill"),
        Some(serde_json::json!({ "vmids": [700, 701] })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["data"]["kind"], "lab.pool.fill");
    assert_eq!(world.audit_events("lab_pool_fill_requested"), 1);
    // Beyond the declared size is refused before anything is registered.
    let (status, _) = call(
        &state,
        "POST",
        &format!("/lab/pools/{pool_id}/fill"),
        Some(serde_json::json!({ "vmids": [702] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = call(&state, "GET", &format!("/lab/pools/{pool_id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    let members = body["data"]["members"].as_array().unwrap();
    assert_eq!(members.len(), 2);
    assert!(members.iter().all(|member| member["state"] == "filling"));
    let (_, body) = call(&state, "GET", "/lab/pools", None).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1);

    // A pool with members is not deleted.
    let (status, _) = call(&state, "DELETE", &format!("/lab/pools/{pool_id}"), None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    // A whole-pool drain is never implied by an empty body.
    let (status, _) = call(
        &state,
        "POST",
        &format!("/lab/pools/{pool_id}/drain"),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Filling members leave once their fill ends.
    let (status, body) = call(
        &state,
        "POST",
        &format!("/lab/pools/{pool_id}/drain"),
        Some(serde_json::json!({ "all": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["deferred"], serde_json::json!([700, 701]));
    assert_eq!(world.audit_events("lab_pool_draining"), 1);
}

#[tokio::test]
async fn a_pool_needs_a_reverting_version_and_a_known_account() {
    let world = World::new().await;
    let state = world.state(Arc::new(Permit));
    let (status, body) = call(
        &state,
        "POST",
        "/lab/pools",
        Some(create_body("version-destroy", &world.account_id)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, _) = call(
        &state,
        "POST",
        "/lab/pools",
        Some(create_body("version-revert", "no-such-account")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &state,
        "POST",
        "/lab/pools",
        Some(serde_json::json!({
            "templateVersionId": "version-revert",
            "accountId": world.account_id,
            "baselineSnapshot": "current",
            "size": 2,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(world.audit_events("lab_pool_creating"), 0);
}

#[tokio::test]
async fn pool_mutations_are_authorized_before_anything_changes() {
    let world = World::new().await;
    let permitted = world.state(Arc::new(Permit));
    let (_, body) = call(
        &permitted,
        "POST",
        "/lab/pools",
        Some(create_body("version-revert", &world.account_id)),
    )
    .await;
    let pool_id = body["data"]["id"].as_str().unwrap().to_owned();

    let no_config = world.state(Arc::new(Without(Permission::LabConfig)));
    let (status, _) = call(
        &no_config,
        "POST",
        "/lab/pools",
        Some(create_body("version-revert", &world.account_id)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    for (method, path, body) in [
        (
            "POST",
            format!("/lab/pools/{pool_id}/fill"),
            Some(serde_json::json!({ "vmids": [700] })),
        ),
        (
            "POST",
            format!("/lab/pools/{pool_id}/drain"),
            Some(serde_json::json!({ "all": true })),
        ),
        ("DELETE", format!("/lab/pools/{pool_id}"), None),
    ] {
        let (status, _) = call(&no_config, method, &path, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
    }
    // Fill queues an operation: without operation.create nothing is
    // registered.
    let no_operations = world.state(Arc::new(Without(Permission::OperationCreate)));
    let (status, _) = call(
        &no_operations,
        "POST",
        &format!("/lab/pools/{pool_id}/fill"),
        Some(serde_json::json!({ "vmids": [700] })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, body) = call(&permitted, "GET", &format!("/lab/pools/{pool_id}"), None).await;
    assert!(body["data"]["members"].as_array().unwrap().is_empty());
    assert_eq!(world.audit_events("lab_pool_fill_requested"), 0);
    assert_eq!(world.audit_events("lab_pool_draining"), 0);
    assert_eq!(world.audit_events("lab_pool_deleting"), 0);
    // Reading needs lab.read.
    let no_read = world.state(Arc::new(Without(Permission::LabRead)));
    let (status, _) = call(&no_read, "GET", "/lab/pools", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Reviews and runs one destructive Proxmox action through the real routes.
async fn run_destructive(
    state: &Arc<ApiState>,
    account_id: &str,
    vmid: u32,
    action: &str,
    params: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let base = format!("/proxmox/accounts/{account_id}/guests/{vmid}/{action}");
    let (status, review) = call(
        state,
        "POST",
        &format!("{base}/review"),
        Some(serde_json::json!({ "node": "pve1", "params": params })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{review}");
    call(
        state,
        "POST",
        &format!("{base}/run"),
        Some(serde_json::json!({
            "node": "pve1",
            "reviewToken": review["data"]["reviewToken"],
            "params": params,
            "timeoutSeconds": 300,
        })),
    )
    .await
}

#[tokio::test]
async fn operator_destroy_and_snapshot_delete_refuse_a_pool_member_until_it_is_drained() {
    let world = World::new().await;
    let state = world.state(Arc::new(Permit));
    let (_, body) = call(
        &state,
        "POST",
        "/lab/pools",
        Some(create_body("version-revert", &world.account_id)),
    )
    .await;
    let pool_id = body["data"]["id"].as_str().unwrap().to_owned();
    let (status, _) = call(
        &state,
        "POST",
        &format!("/lab/pools/{pool_id}/fill"),
        Some(serde_json::json!({ "vmids": [700] })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    // Make the member settled, so a drain removes it at once.
    let member = &world.pools.members(&pool_id).await.unwrap()[0];
    world
        .pools
        .finish_fill(
            &member.id,
            &FillResult::Available {
                node: "pve1".to_owned(),
                name: "fm-lab-pool-700".to_owned(),
            },
            1,
        )
        .await
        .unwrap();

    let destroy = serde_json::json!({});
    let snapshot = serde_json::json!({ "snapshot": "baseline" });
    for (action, params) in [("destroy", &destroy), ("snapshot-delete", &snapshot)] {
        let (status, body) = run_destructive(&state, &world.account_id, 700, action, params).await;
        assert_eq!(status, StatusCode::CONFLICT, "{action}: {body}");
        assert_eq!(body["code"], "pool_member", "{action}: {body}");
    }
    assert_eq!(world.audit_events("proxmox_pool_member_refused"), 2);
    // Another guest on the account is not affected.
    let (status, body) = run_destructive(&state, &world.account_id, 701, "destroy", &destroy).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    let (status, body) = call(
        &state,
        "POST",
        &format!("/lab/pools/{pool_id}/drain"),
        Some(serde_json::json!({ "vmids": [700] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for (action, params) in [("destroy", &destroy), ("snapshot-delete", &snapshot)] {
        let (status, body) = run_destructive(&state, &world.account_id, 700, action, params).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{action} after drain: {body}");
    }
}
