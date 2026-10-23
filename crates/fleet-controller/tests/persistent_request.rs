//! #496: an agent asks for a persistent VM through the action broker, over
//! the real router and SQLite store. The agent cannot call the direct create;
//! its request carries the spec by reference, waits for a person by default
//! (or runs by policy when operator bounds admit it), and the operation that
//! results is the one #489's executor runs, stamped with the requester and
//! the purpose. A rejection creates nothing.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::broker::{ActionRegistry, Broker, BrokerSettings};
use fleet_application::lab::Lab;
use fleet_application::machine_access::MachineAccess;
use fleet_application::operation::Operations;
use fleet_application::persistent::PersistentMachines;
use fleet_application::persistent_request::{PersistentBounds, persistent_actions};
use fleet_storage_sqlite::{
    ActionRequestRepository, AuditSink, EndpointAuthRepository, LabRepository, LeaseRepository,
    MachineRepository, OperationRepository, ProjectRepository, Store,
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const AGENT: &str = "credential:ci:cred-1";
const OPERATOR: &str = "operator";
const LITE: &str = "operator-lite";

/// A restricted agent may ask and read but never provision, approve or
/// create operations; `operator-lite` approves but cannot provision.
#[derive(Debug)]
struct Roles;

impl Authorizer for Roles {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        let denied = Decision::deny(ReasonId::UnknownPrincipal);
        match request.principal_id {
            AGENT => match request.action {
                Permission::ActionRequest | Permission::ActionRead => Decision::allow(),
                _ => denied,
            },
            LITE if request.action == Permission::MachineProvision => denied,
            _ => Decision::allow(),
        }
    }
}

#[derive(Debug)]
struct Promoted;

#[async_trait::async_trait]
impl fleet_application::lab::ImagePinValidator for Promoted {
    async fn promoted_version(
        &self,
        version_id: &str,
    ) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok((version_id == "ver-1").then(|| fleet_core::RecipeVersion {
            id: version_id.to_owned(),
            recipe_id: "recipe-1".to_owned(),
            name: "image".to_owned(),
            content_digest: "sha256:abc".to_owned(),
            description: String::new(),
            content: "{}".to_owned(),
            source: fleet_core::RecipeSource::Clone,
            node: "pve".to_owned(),
            storage_pool: "local-lvm".to_owned(),
            published_at: 0,
            promoted_at: Some(0),
            promoted_by: Some("tester".to_owned()),
            promoted_build_id: Some("build-1".to_owned()),
            allow_insecure_tls: false,
        }))
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    state: Arc<ApiState>,
    operations: Arc<OperationRepository>,
    pool: sqlx::SqlitePool,
}

impl Harness {
    async fn new(bounds: PersistentBounds, overrides: &[(&str, fleet_core::RiskClass)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        std::mem::forget(store);
        let access = Arc::new(
            MachineAccess::new(
                Arc::new(MachineRepository::new(pool.clone())),
                Arc::new(EndpointAuthRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )
            .with_persistent(Arc::new(PersistentMachines::new(
                Arc::new(Promoted),
                Arc::new(AuditSink::new(pool.clone())),
            ))),
        );
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let lab = Arc::new(
            Lab::new(
                labs.clone(),
                labs,
                Arc::new(LeaseRepository::new(pool.clone())),
                Arc::new(Promoted),
                Arc::new(ProjectRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )
            .with_machine_access(access),
        );
        let operation_repo = Arc::new(OperationRepository::new(pool.clone()));
        let operations = Arc::new(
            Operations::new(
                operation_repo.clone(),
                Arc::new(AuditSink::new(pool.clone())),
            )
            .with_brokered_kinds(["machine.create".to_owned()]),
        );
        let request_store = Arc::new(ActionRequestRepository::new(pool.clone()));
        let mut registry = ActionRegistry::new();
        for action in persistent_actions(bounds, Some(request_store.clone())) {
            registry.register(action).unwrap();
        }
        let settings = BrokerSettings::new(
            86_400,
            overrides
                .iter()
                .map(|(id, class)| ((*id).to_owned(), *class))
                .collect(),
        )
        .unwrap();
        let broker = Broker::new(
            request_store,
            Arc::new(registry),
            operations.clone(),
            settings,
        );
        let state = Arc::new(ApiState {
            operations,
            authorizer: Arc::new(Roles),
            lab: Some(lab),
            requests: Some(Arc::new(broker)),
            ..ApiState::for_document()
        });
        Self {
            _dir: dir,
            state,
            operations: operation_repo,
            pool,
        }
    }

    async fn call(&self, who: &str, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(format!("{API_BASE_PATH}{path}"))
            .header("content-type", "application/json")
            .header(
                CORRELATION_ID_HEADER,
                "01900000-0000-7000-8000-000000000000",
            )
            .body(Body::from(body.to_string()))
            .unwrap();
        let app = router(self.state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
            id: who.to_owned(),
        }));
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    async fn ask(&self, who: &str, spec: Value, purpose: &str) -> (StatusCode, Value) {
        self.call(
            who,
            "POST",
            "/machines/create/request",
            json!({ "spec": spec, "purpose": purpose }),
        )
        .await
    }

    async fn operation_count(&self) -> usize {
        use fleet_application::operation::OperationPort as _;
        self.operations
            .list(10)
            .await
            .map(|operations| operations.len())
            .unwrap_or(usize::MAX)
    }
}

fn spec(name: &str) -> Value {
    json!({
        "accountId": "acct-1",
        "imageVersionId": "ver-1",
        "name": name,
        "cores": 2,
        "memoryMib": 2048,
        "diskGib": 20,
        "credential": { "type": "reference", "credential": "machines/ssh/not-checked" },
    })
}

fn bounded() -> PersistentBounds {
    PersistentBounds {
        max_cores: Some(4),
        max_memory_mib: Some(4096),
        max_disk_gib: Some(40),
        max_per_principal: Some(1),
        ..PersistentBounds::default()
    }
}

#[tokio::test]
async fn an_agent_cannot_create_directly_but_can_ask() {
    let harness = Harness::new(PersistentBounds::default(), &[]).await;
    for path in ["/machines/create/review", "/machines/create"] {
        let (status, _) = harness
            .call(
                AGENT,
                "POST",
                path,
                json!({ "spec": spec("direct"), "reviewToken": "x" }),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
    }
    // A reference that names no key is refused at request time, with no
    // key store wired here; use a public key so the request is complete.
    let mut with_key = spec("agent-box");
    with_key["credential"] = json!({
        "type": "publicKey",
        "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl a@b",
    });
    let (status, body) = harness.ask(AGENT, with_key, "nightly build host").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let data = &body["data"];
    assert_eq!(data["state"], "pending", "default policy needs a person");
    assert_eq!(data["requester"], AGENT);
    assert_eq!(data["actionId"], "proxmox.machine.create");
    assert_eq!(data["target"], "machine:acct-1:agent-box");
    assert_eq!(data["reason"], "nightly build host");
    assert!(data["operationId"].is_null());
    // The parameters carry references and public keys only, never a stamp.
    assert!(data["parameters"]["requestedBy"].is_null());
    assert_eq!(harness.operation_count().await, 0);
}

fn key_spec(name: &str) -> Value {
    let mut value = spec(name);
    value["credential"] = json!({
        "type": "publicKey",
        "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl a@b",
    });
    value
}

#[tokio::test]
async fn approval_runs_the_direct_creates_operation_stamped_with_owner_and_purpose() {
    let harness = Harness::new(PersistentBounds::default(), &[]).await;
    let (_, body) = harness.ask(AGENT, key_spec("agent-box"), "ci runner").await;
    let id = body["data"]["id"].as_str().unwrap().to_owned();

    // The agent cannot approve its own request.
    let (status, _) = harness
        .call(AGENT, "POST", &format!("/requests/{id}/approve"), json!({}))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // An approver who may not provision cannot approve it either, and the
    // request keeps waiting.
    let (status, _) = harness
        .call(LITE, "POST", &format!("/requests/{id}/approve"), json!({}))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(harness.operation_count().await, 0);

    let (status, body) = harness
        .call(
            OPERATOR,
            "POST",
            &format!("/requests/{id}/approve"),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["state"], "executing");
    assert_eq!(body["data"]["decidedBy"], OPERATOR);
    let operation_id = body["data"]["operationId"].as_str().unwrap();

    use fleet_application::operation::OperationPort as _;
    let operation = harness.operations.get(operation_id).await.unwrap();
    assert_eq!(operation.kind, "machine.create");
    let payload: Value = serde_json::from_str(operation.payload_json.as_deref().unwrap()).unwrap();
    assert_eq!(payload["name"], "agent-box");
    assert_eq!(payload["requestedBy"]["principal"], AGENT);
    assert_eq!(payload["requestedBy"]["purpose"], "ci runner");
    assert_eq!(payload["requestedBy"]["requestId"], id);
    assert_eq!(harness.operation_count().await, 1);

    // Request, approval and start are linked audit events: the request id
    // is the resource of all three, and the start names the operation.
    let events: Vec<(String, String)> = sqlx::query_as(
        "SELECT action, metadata_json FROM audit_events WHERE resource = ?1 ORDER BY seq",
    )
    .bind(&id)
    .fetch_all(&harness.pool)
    .await
    .unwrap();
    let actions: Vec<&str> = events.iter().map(|(action, _)| action.as_str()).collect();
    assert_eq!(
        actions,
        ["action.request", "action.approve", "action.execute"]
    );
    assert!(events[2].1.contains(operation_id), "{}", events[2].1);
}

#[tokio::test]
async fn a_multi_line_purpose_is_filed_and_stamped_as_one_line() {
    let harness = Harness::new(PersistentBounds::default(), &[]).await;
    let (status, body) = harness
        .ask(
            AGENT,
            key_spec("agent-box"),
            "line one\nline two\r\n  three",
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["data"]["reason"], "line one line two three");
}

#[tokio::test]
async fn a_rejection_creates_nothing() {
    let harness = Harness::new(PersistentBounds::default(), &[]).await;
    let (_, body) = harness.ask(AGENT, key_spec("agent-box"), "ci runner").await;
    let id = body["data"]["id"].as_str().unwrap().to_owned();
    let (status, body) = harness
        .call(
            OPERATOR,
            "POST",
            &format!("/requests/{id}/deny"),
            json!({ "note": "use a lab lease" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["state"], "denied");
    assert_eq!(harness.operation_count().await, 0);
    let (status, _) = harness
        .call(
            OPERATOR,
            "POST",
            &format!("/requests/{id}/approve"),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(harness.operation_count().await, 0);
}

#[tokio::test]
async fn bounds_auto_approve_what_they_admit_and_everything_else_waits() {
    let harness = Harness::new(bounded(), &[]).await;
    // Inside every bound: approved by policy, the operation starts at once.
    let (status, body) = harness.ask(AGENT, key_spec("small-box"), "fits").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["data"]["state"], "executing", "{body}");
    assert_eq!(body["data"]["decidedBy"], "policy:auto");
    assert!(body["data"]["operationId"].is_string());
    assert_eq!(harness.operation_count().await, 1);

    // The per-principal count is spent: the next one, though inside the
    // bounds, needs a person.
    let (_, body) = harness.ask(AGENT, key_spec("second-box"), "again").await;
    assert_eq!(body["data"]["state"], "pending", "{body}");
    assert_eq!(harness.operation_count().await, 1);

    // Another principal is counted on its own, and an oversized one waits.
    let mut big = key_spec("big-box");
    big["cores"] = json!(16);
    let (_, body) = harness.ask("credential:ci:cred-2", big, "too big").await;
    assert_eq!(body["data"]["state"], "pending", "{body}");
    // A bound the request leaves to the template default cannot be shown.
    let mut open = key_spec("open-box");
    open.as_object_mut().unwrap().remove("diskGib");
    let (_, body) = harness.ask("credential:ci:cred-3", open, "no disk").await;
    assert_eq!(body["data"]["state"], "pending", "{body}");
}

#[tokio::test]
async fn policy_deny_refuses_the_request_and_stores_nothing() {
    let harness = Harness::new(
        bounded(),
        &[("proxmox.machine.create", fleet_core::RiskClass::Deny)],
    )
    .await;
    let (status, body) = harness.ask(AGENT, key_spec("any"), "x").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(harness.operation_count().await, 0);
}

#[tokio::test]
async fn a_request_that_forges_the_stamp_or_omits_the_purpose_is_refused() {
    let harness = Harness::new(PersistentBounds::default(), &[]).await;
    let mut forged = key_spec("forged");
    forged["requestedBy"] = json!({ "principal": "operator", "purpose": "x", "requestId": "r" });
    let (status, _) = harness.ask(AGENT, forged, "x").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = harness.ask(AGENT, key_spec("no-purpose"), "  ").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // An image version that is not promoted is refused at request time.
    let mut unpromoted = key_spec("unpromoted");
    unpromoted["imageVersionId"] = json!("ver-9");
    let (status, _) = harness.ask(AGENT, unpromoted, "x").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // The direct review refuses a stamp too.
    let mut stamped = key_spec("stamped");
    stamped["requestedBy"] = json!({ "principal": "operator", "purpose": "x", "requestId": "r" });
    let (status, _) = harness
        .call(
            OPERATOR,
            "POST",
            "/machines/create/review",
            json!({ "spec": stamped }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // The generic operations surface refuses the kind.
    let (status, _) = harness
        .call(
            OPERATOR,
            "POST",
            "/operations",
            json!({ "kind": "machine.create", "payload": {} }),
        )
        .await;
    assert_ne!(status, StatusCode::ACCEPTED);
    assert_eq!(harness.operation_count().await, 0);
}
