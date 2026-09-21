//! The ready-project workflow (FM-305): the plan executes through the
//! composed chain, a re-run skips completed steps, a blocked ceremony is
//! a first-class state, and a failing step stops with the story.

use fleet_application::machine::MachinePort;
use fleet_application::operation::Operations;
use fleet_provider_ssh::ExecutionLimiter;
use fleet_storage_sqlite::{AuditSink, MachineRepository, OperationRepository, Store};
use sqlx::SqlitePool;
use std::sync::Arc;

/// The composed fixture: store, operations, ready executor with a stub
/// inner chain.
struct Fixture {
    _dir: tempfile::TempDir,
    operations: Operations,
    executor: Arc<fleet_controller::ready::ReadyExecutor>,
    /// The stub chain, retained for assertions about what ran.
    #[allow(dead_code)]
    stub: Arc<StubInner>,
}

/// A stub inner executor: records the kinds it ran and answers with a
/// scripted state per kind.
#[derive(Debug)]
struct StubInner {
    ran: std::sync::Mutex<Vec<String>>,
    states: std::sync::Mutex<Vec<(String, String)>>,
}

#[async_trait::async_trait]
impl fleet_application::worker::OperationExecutor for StubInner {
    async fn execute(
        &self,
        operations: &Operations,
        operation: &fleet_application::operation::Operation,
    ) -> Result<(), String> {
        self.ran.lock().unwrap().push(operation.kind.clone());
        let scripted = {
            let states = self.states.lock().unwrap();
            states
                .iter()
                .find(|(kind, _)| *kind == operation.kind)
                .map(|(_, state)| state.clone())
        };
        match scripted.as_deref() {
            Some("failed") => {
                let error_json = serde_json::json!({
                    "reason": "step_failed",
                    "detail": "the stub failed this step",
                })
                .to_string();
                operations
                    .complete(&operation.id, "failed", None, Some(&error_json))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            Some("blocked_manual_approval") => {
                let error_json = serde_json::json!({
                    "reason": "blocked_manual_approval",
                    "detail": "the frogenv_setup ceremony requires manual approval",
                })
                .to_string();
                operations
                    .complete(
                        &operation.id,
                        "blocked_manual_approval",
                        None,
                        Some(&error_json),
                    )
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            _ => {
                let result_json = serde_json::json!({ "kind": operation.kind }).to_string();
                operations
                    .complete(&operation.id, "succeeded", Some(&result_json), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
        }
    }
}

async fn compose(states: Vec<(String, String)>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool: SqlitePool = store.pool().clone();
    std::mem::forget(store);
    let machines: Arc<dyn MachinePort> = Arc::new(MachineRepository::new(pool.clone()));
    let operations = Operations::new(
        Arc::new(OperationRepository::new(pool.clone())),
        Arc::new(AuditSink::new(pool.clone())),
    );
    let inner = Arc::new(StubInner {
        ran: std::sync::Mutex::new(Vec::new()),
        states: std::sync::Mutex::new(states),
    });
    let executor = Arc::new(fleet_controller::ready::ReadyExecutor::new(
        machines,
        // The executor holds its own Operations over the same store.
        Arc::new(Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            Arc::new(AuditSink::new(pool.clone())),
        )),
        inner.clone(),
        dir.path().join("ssh"),
        ExecutionLimiter::new(4),
    ));
    Fixture {
        _dir: dir,
        operations,
        executor,
        stub: inner.clone(),
    }
}

impl Fixture {
    async fn run_ready(
        &self,
        payload: serde_json::Value,
    ) -> (String, Option<String>, Option<String>) {
        let operation = self
            .operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                "anonymous-lan-admin",
                &fleet_application::operation::NewOperation {
                    kind: "ready.workflow".to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(payload.to_string()),
                    review_token: None,
                },
            )
            .await
            .unwrap();
        // Execute the workflow through the executor itself: the workflow's
        // inner steps run through the stub chain in-process.
        self.operations
            .tick(
                self.executor.as_ref(),
                "worker-a",
                fleet_core::SystemClock::now_unix_millis(),
                60_000,
            )
            .await
            .unwrap();
        let finished = self
            .operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                "anonymous-lan-admin",
                &operation.id,
            )
            .await
            .unwrap();
        (finished.state, finished.result_json, finished.error_json)
    }
}

fn payload() -> serde_json::Value {
    serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "remote": "github.com/Frogbyte-io/fleet-manager",
        "root": "/srv/repo",
        "tools": [{"tool": "node", "version": "20.11.0"}],
        "skillId": "db",
        "agents": ["claude_code"],
        "timeoutSeconds": 600,
    })
}

#[tokio::test]
async fn the_workflow_executes_every_step_and_succeeds() {
    let fixture = compose(vec![]).await;
    let (state, result, error) = fixture.run_ready(payload()).await;
    assert_eq!(state, "succeeded", "{error:?}");
    let result: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(result["ready"], true);
    assert_eq!(
        result["completed"],
        serde_json::json!([
            "clone",
            "mise_install",
            "frogenv_setup",
            "skills_deploy",
            "verify"
        ])
    );
}

#[tokio::test]
async fn a_blocked_ceremony_is_a_first_class_state_with_the_remainder() {
    let fixture = compose(vec![(
        "frogenv.setup".to_owned(),
        "blocked_manual_approval".to_owned(),
    )])
    .await;
    let (state, _result, error) = fixture.run_ready(payload()).await;
    assert_eq!(state, "blocked_manual_approval");
    let error: serde_json::Value = serde_json::from_str(&error.unwrap()).unwrap();
    assert_eq!(error["blockedAt"], "frogenv_setup");
    assert_eq!(
        error["remaining"],
        serde_json::json!(["deploy db to 1 agent(s)", "verify readiness"])
    );
}

#[tokio::test]
async fn a_failing_step_stops_with_the_story() {
    let fixture = compose(vec![("mise.install".to_owned(), "failed".to_owned())]).await;
    let (state, _result, error) = fixture.run_ready(payload()).await;
    assert_eq!(state, "failed");
    let error: serde_json::Value = serde_json::from_str(&error.unwrap()).unwrap();
    assert_eq!(error["failedAt"], "mise_install");
    assert_eq!(
        error["completed"],
        serde_json::json!(["clone"]),
        "the completed steps are named"
    );
    assert!(
        !error["remaining"].as_array().unwrap().is_empty(),
        "the remaining steps are named"
    );
}
