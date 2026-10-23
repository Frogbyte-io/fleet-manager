//! #494: the terminal session HTTP surface over the real router and SQLite
//! store. Creating a session needs `machines.terminal` (not `machines.exec`),
//! answers a single-use token once, and leaves an audit event that never
//! carries the token.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::lab::Lab;
use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::machine_access::MachineAccess;
use fleet_application::machine_terminal::{
    TerminalChannel, TerminalLimits, TerminalOpen, TerminalPort, TerminalSessions,
};
use fleet_application::operation::Operations;
use fleet_core::EndpointKind;
use fleet_storage_sqlite::{
    AuditSink, EndpointAuthRepository, LabRepository, LeaseRepository, MachineRepository,
    OperationRepository, ProjectRepository, Store,
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

/// Denies exactly one permission.
#[derive(Debug)]
struct Deny(Permission);

impl Authorizer for Deny {
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

#[async_trait]
impl fleet_application::lab::ImagePinValidator for NoPins {
    async fn promoted_version(
        &self,
        _version_id: &str,
    ) -> Result<Option<fleet_application::images::RecipeVersion>, String> {
        Ok(None)
    }
}

/// Never opens a shell: this file tests only session creation.
#[derive(Debug, Default)]
struct TokensOnly(std::sync::atomic::AtomicU64);

#[async_trait]
impl TerminalPort for TokensOnly {
    fn new_session_token(&self) -> String {
        format!(
            "surface-token-{:08}",
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }

    async fn open(&self, _request: &TerminalOpen) -> Result<Box<dyn TerminalChannel>, String> {
        Err("not opened in this test".to_owned())
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    store: Store,
    state: Arc<ApiState>,
    machine_id: String,
    unconfirmed_machine_id: String,
}

impl Harness {
    async fn new(authorizer: Arc<dyn Authorizer>, terminals: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        let machines = Arc::new(MachineRepository::new(pool.clone()));
        let mut access = MachineAccess::new(
            machines.clone(),
            Arc::new(EndpointAuthRepository::new(pool.clone())),
            Arc::new(AuditSink::new(pool.clone())),
        );
        if terminals {
            access = access.with_terminals(TerminalSessions::new(
                Arc::new(TokensOnly::default()),
                TerminalLimits {
                    max_sessions: 2,
                    max_per_principal: 2,
                    ..TerminalLimits::default()
                },
            ));
        }
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let lab = Arc::new(
            Lab::new(
                labs.clone(),
                labs,
                Arc::new(LeaseRepository::new(pool.clone())),
                Arc::new(NoPins),
                Arc::new(ProjectRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )
            .with_machine_access(Arc::new(access)),
        );
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            Arc::new(AuditSink::new(pool.clone())),
        ));
        let mut ids = Vec::new();
        for (name, confirm) in [("terminal-box", true), ("unconfirmed-box", false)] {
            let machine = machines
                .register(&RegisterMachine {
                    name: name.to_owned(),
                    description: String::new(),
                    endpoints: vec![NewEndpoint {
                        kind: EndpointKind::Ssh,
                        reference: "agent@192.0.2.20:22".to_owned(),
                    }],
                    tags: vec![],
                    groups: vec![],
                })
                .await
                .unwrap();
            if confirm {
                machines
                    .confirm_fingerprint(&machine.endpoints[0].id, "SHA256:fixture", 0)
                    .await
                    .unwrap();
            }
            ids.push(machine.id);
        }
        let state = Arc::new(ApiState {
            operations,
            authorizer,
            lab: Some(lab),
            ..ApiState::for_document()
        });
        Self {
            _dir: dir,
            store,
            state,
            machine_id: ids[0].clone(),
            unconfirmed_machine_id: ids[1].clone(),
        }
    }

    async fn create(&self, machine_id: &str, body: Value) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "{API_BASE_PATH}/machines/{machine_id}/terminal-sessions"
            ))
            .header("content-type", "application/json")
            .header(CORRELATION_ID_HEADER, "01900000-0000-7000-8000-000000000000")
            .body(Body::from(body.to_string()))
            .unwrap();
        let app = router(self.state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
            id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        }));
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    async fn audit(&self) -> String {
        sqlx::query_scalar::<_, String>(
            "SELECT coalesce(group_concat(action || ' ' || metadata_json, char(10)), '') FROM audit_events",
        )
        .fetch_one(self.store.pool())
        .await
        .unwrap()
    }
}

/// A body that names an explicit auth, so a request needs no recorded
/// default (the fixture machines have none).
fn agent_auth() -> Value {
    json!({ "auth": { "type": "agent" } })
}

#[tokio::test]
async fn a_session_is_created_with_a_single_use_token_shown_once() {
    let harness = Harness::new(Arc::new(fleet_auth::LanAllowAllAuthorizer), true).await;
    let (status, body) = harness
        .create(
            &harness.machine_id,
            json!({ "cols": 120, "rows": 40, "auth": { "type": "agent" } }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let data = &body["data"];
    let token = data["token"].as_str().unwrap();
    assert!(token.starts_with("surface-token-"));
    assert_eq!(data["socketPath"], "/api/v1/terminal/socket");
    assert_eq!(
        data["subprotocols"],
        json!(["fleet-terminal", format!("fleet-terminal-token.{token}")])
    );
    assert_eq!(data["machineId"], harness.machine_id.as_str());
    assert_eq!(data["idleTimeoutSeconds"], 600);
    assert_eq!(data["maxDurationSeconds"], 3600);
    assert!(data["sessionId"].as_str().unwrap().starts_with("terminal-"));

    let audit = harness.audit().await;
    assert!(audit.contains("terminal_session_created"), "{audit}");
    assert!(audit.contains("machines.terminal"), "{audit}");
    assert!(!audit.contains(token), "the token reached the audit");
}

#[tokio::test]
async fn creating_needs_machines_terminal_and_exec_is_no_substitute() {
    let harness = Harness::new(Arc::new(Deny(Permission::MachineTerminal)), true).await;
    let (status, _) = harness.create(&harness.machine_id, agent_auth()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        !harness.audit().await.contains("terminal_session_created"),
        "a refused request must not leave a created event"
    );
    // Denying exec does not stop a terminal: the permissions are separate.
    let harness = Harness::new(Arc::new(Deny(Permission::MachineExec)), true).await;
    let (status, body) = harness.create(&harness.machine_id, agent_auth()).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn bad_requests_are_refused_before_any_session_exists() {
    let harness = Harness::new(Arc::new(fleet_auth::LanAllowAllAuthorizer), true).await;
    let (status, _) = harness
        .create(
            &harness.machine_id,
            json!({ "cols": 0, "auth": { "type": "agent" } }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = harness
        .create(
            &harness.machine_id,
            json!({ "cols": 5000, "rows": 5, "auth": { "type": "agent" } }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // No explicit auth and no recorded default.
    let (status, _) = harness.create(&harness.machine_id, json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // A host key that was never confirmed.
    let (status, body) = harness
        .create(&harness.unconfirmed_machine_id, agent_auth())
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|message| message.contains("host key")),
        "{body}"
    );
    let (status, _) = harness.create("no-such-machine", agent_auth()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_session_cap_is_reported_as_busy() {
    let harness = Harness::new(Arc::new(fleet_auth::LanAllowAllAuthorizer), true).await;
    for _ in 0..2 {
        let (status, answer) = harness.create(&harness.machine_id, agent_auth()).await;
        assert_eq!(status, StatusCode::CREATED, "{answer}");
    }
    let (status, _) = harness.create(&harness.machine_id, agent_auth()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn a_controller_without_terminals_says_so() {
    let harness = Harness::new(Arc::new(fleet_auth::LanAllowAllAuthorizer), false).await;
    let (status, body) = harness.create(&harness.machine_id, agent_auth()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|message| message.contains("terminals are not available")),
        "{body}"
    );
}
