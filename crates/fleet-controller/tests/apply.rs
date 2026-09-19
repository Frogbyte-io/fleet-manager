//! The apply engine (FM-402): the approval gate, compensations, and
//! restart-truth through the composed chain.

use fleet_application::apply::{Approval, Compensation, unapproved_actions};
use fleet_application::operation::Operations;
use fleet_application::planner::PlannedAction;
use fleet_core::{DifferenceState, FieldDifference};
use std::sync::Arc;

/// A stub inner executor: answers with a scripted state per kind.
#[derive(Debug)]
struct StubInner {
    states: std::sync::Mutex<Vec<(String, String)>>,
}

#[async_trait::async_trait]
impl fleet_application::worker::OperationExecutor for StubInner {
    async fn execute(
        &self,
        operations: &Operations,
        operation: &fleet_application::operation::Operation,
    ) -> Result<(), String> {
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

#[test]
fn the_approval_gate_binds_to_the_plan_identity() {
    let actions = vec![PlannedAction {
        order: 1,
        kind: "mise.install".to_owned(),
        difference: FieldDifference::missing("tool:node", "20.11.0"),
        reason: String::new(),
    }];
    // No approvals: blocked.
    assert_eq!(unapproved_actions("plan-1", &actions, &[]).len(), 1);
    // A foreign plan's approval: still blocked.
    let foreign = vec![Approval {
        plan_id: "plan-2".to_owned(),
        action_order: 1,
        kind: "mise.install".to_owned(),
    }];
    assert_eq!(unapproved_actions("plan-1", &actions, &foreign).len(), 1);
    // The right plan, right order, right kind: allowed.
    let ours = vec![Approval {
        plan_id: "plan-1".to_owned(),
        action_order: 1,
        kind: "mise.install".to_owned(),
    }];
    assert!(unapproved_actions("plan-1", &actions, &ours).is_empty());
}

#[test]
fn compensations_match_the_step_semantics() {
    assert_eq!(
        Compensation::for_step(
            "mise.install",
            &FieldDifference::missing("tool:node", "20.11.0")
        ),
        Compensation::Idempotent
    );
    assert_eq!(
        Compensation::for_step(
            "skills.deploy",
            &FieldDifference::missing("skill:db/claude_code", "deployed")
        ),
        Compensation::Undeploy {
            skill_id: "db".to_owned(),
            agent: "claude_code".to_owned(),
        }
    );
    assert_eq!(
        Compensation::for_step("mystery.kind", &FieldDifference::missing("mystery:x", "y")),
        Compensation::None
    );
}

#[test]
fn post_apply_verification_requires_no_actionable_or_unknown_fields() {
    let mut set = fleet_core::DifferenceSet::new();
    set.push(FieldDifference::unsupported(
        "tool:node",
        Some("20.11.0"),
        "no path",
    ));
    assert!(fleet_application::apply::verified(&set).is_ok());
    // The same identity carrying an honest unknown: canonicalization
    // keeps the terminal state.
    set.push(FieldDifference::unknown(
        "tool:node",
        Some("20.11.0"),
        "no answer",
    ));
    assert!(fleet_application::apply::verified(&set).is_err());
    set.canonicalize();
    assert_eq!(set.fields.len(), 1);
    assert_eq!(set.fields[0].state, DifferenceState::Unknown);
}

#[tokio::test]
async fn an_unapproved_plan_completes_blocked_naming_the_steps() {
    let dir = tempfile::tempdir().unwrap();
    let store = fleet_storage_sqlite::Store::open(&dir.path().join("fleet.db"))
        .await
        .unwrap();
    let pool = store.pool().clone();
    std::mem::forget(store);
    let operations = Arc::new(Operations::new(
        Arc::new(fleet_storage_sqlite::OperationRepository::new(pool.clone())),
        Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone())),
    ));
    let executor = fleet_controller::apply::ApplyExecutor::new(
        operations.clone(),
        Arc::new(StubInner {
            states: std::sync::Mutex::new(vec![]),
        }),
    );
    let payload = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "planId": "plan-1",
        "actions": [
            {"order": 1, "kind": "mise.install",
             "difference": {"identity": "tool:node", "state": "missing",
                            "desired": "20.11.0", "observed": null, "reason": null}},
        ],
        "approvals": [],
        "timeoutSeconds": 600,
    });
    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &fleet_application::operation::NewOperation {
                kind: "apply.workflow".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: Some(payload.to_string()),
            },
        )
        .await
        .unwrap();
    operations
        .tick(
            &executor,
            "worker-a",
            fleet_core::SystemClock::now_unix_millis(),
            60_000,
        )
        .await
        .unwrap();
    let finished = operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &operation.id,
        )
        .await
        .unwrap();
    assert_eq!(finished.state, "blocked_manual_approval");
    let error = finished.error_json.unwrap();
    assert!(error.contains("approval"), "{error}");
    assert!(error.contains("mise.install"), "{error}");
}

#[tokio::test]
async fn a_kind_state_mismatched_payload_fails_honestly() {
    // The generic /operations surface authorizes machine-scoped creation
    // but does not run the plan's boundary checks; the executor is the
    // last line of defense and refuses a kind/state/identity mismatch.
    let dir = tempfile::tempdir().unwrap();
    let store = fleet_storage_sqlite::Store::open(&dir.path().join("fleet.db"))
        .await
        .unwrap();
    let pool = store.pool().clone();
    std::mem::forget(store);
    let operations = Arc::new(Operations::new(
        Arc::new(fleet_storage_sqlite::OperationRepository::new(pool.clone())),
        Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone())),
    ));
    let executor = fleet_controller::apply::ApplyExecutor::new(
        operations.clone(),
        Arc::new(StubInner {
            states: std::sync::Mutex::new(vec![]),
        }),
    );
    let payload = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "planId": "plan-1",
        "actions": [
            {"order": 1, "kind": "mise.install",
             "difference": {"identity": "skill:db/claude_code", "state": "missing",
                            "desired": "deployed", "observed": null, "reason": null}},
        ],
        "approvals": [],
        "timeoutSeconds": 600,
    });
    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &fleet_application::operation::NewOperation {
                kind: "apply.workflow".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: Some(payload.to_string()),
            },
        )
        .await
        .unwrap();
    operations
        .tick(
            &executor,
            "worker-a",
            fleet_core::SystemClock::now_unix_millis(),
            60_000,
        )
        .await
        .unwrap();
    let finished = operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &operation.id,
        )
        .await
        .unwrap();
    assert_eq!(finished.state, "failed");
    let error: serde_json::Value = serde_json::from_str(&finished.error_json.unwrap()).unwrap();
    assert!(
        error["detail"].as_str().unwrap().contains("identity"),
        "{error}"
    );
}

#[tokio::test]
async fn an_approved_plan_executes_every_action_and_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let store = fleet_storage_sqlite::Store::open(&dir.path().join("fleet.db"))
        .await
        .unwrap();
    let pool = store.pool().clone();
    std::mem::forget(store);
    let operations = Arc::new(Operations::new(
        Arc::new(fleet_storage_sqlite::OperationRepository::new(pool.clone())),
        Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone())),
    ));
    let executor = fleet_controller::apply::ApplyExecutor::new(
        operations.clone(),
        Arc::new(StubInner {
            states: std::sync::Mutex::new(vec![]),
        }),
    );
    let payload = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "planId": "plan-1",
        "actions": [
            {"order": 1, "kind": "mise.install",
             "difference": {"identity": "tool:node", "state": "missing",
                            "desired": "20.11.0", "observed": null, "reason": null}},
        ],
        "approvals": [
            {"planId": "plan-1", "actionOrder": 1, "kind": "mise.install"},
        ],
        "timeoutSeconds": 600,
    });
    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &fleet_application::operation::NewOperation {
                kind: "apply.workflow".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: Some(payload.to_string()),
            },
        )
        .await
        .unwrap();
    operations
        .tick(
            &executor,
            "worker-a",
            fleet_core::SystemClock::now_unix_millis(),
            60_000,
        )
        .await
        .unwrap();
    let finished = operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &operation.id,
        )
        .await
        .unwrap();
    assert_eq!(finished.state, "succeeded", "{:?}", finished.error_json);
    let result: serde_json::Value = serde_json::from_str(&finished.result_json.unwrap()).unwrap();
    assert_eq!(result["applied"], true);
    assert_eq!(result["completed"], serde_json::json!(["tool:node"]));
    assert_eq!(
        result["compensations"],
        serde_json::json!([{"kind": "idempotent"}])
    );
}

#[tokio::test]
async fn a_failing_step_stops_with_compensations_and_remainder() {
    let dir = tempfile::tempdir().unwrap();
    let store = fleet_storage_sqlite::Store::open(&dir.path().join("fleet.db"))
        .await
        .unwrap();
    let pool = store.pool().clone();
    std::mem::forget(store);
    let operations = Arc::new(Operations::new(
        Arc::new(fleet_storage_sqlite::OperationRepository::new(pool.clone())),
        Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone())),
    ));
    let executor = fleet_controller::apply::ApplyExecutor::new(
        operations.clone(),
        Arc::new(StubInner {
            states: std::sync::Mutex::new(vec![("mise.install".to_owned(), "failed".to_owned())]),
        }),
    );
    let payload = serde_json::json!({
        "machineId": "m-1",
        "endpointId": "e-1",
        "auth": {"type": "agent"},
        "planId": "plan-1",
        "actions": [
            {"order": 1, "kind": "mise.install",
             "difference": {"identity": "tool:node", "state": "missing",
                            "desired": "20.11.0", "observed": null, "reason": null}},
            {"order": 2, "kind": "skills.deploy",
             "difference": {"identity": "skill:db/claude_code", "state": "missing",
                            "desired": "deployed", "observed": null, "reason": null}},
        ],
        "approvals": [
            {"planId": "plan-1", "actionOrder": 1, "kind": "mise.install"},
            {"planId": "plan-1", "actionOrder": 2, "kind": "skills.deploy"},
        ],
        "timeoutSeconds": 600,
    });
    let operation = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &fleet_application::operation::NewOperation {
                kind: "apply.workflow".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: Some(payload.to_string()),
            },
        )
        .await
        .unwrap();
    operations
        .tick(
            &executor,
            "worker-a",
            fleet_core::SystemClock::now_unix_millis(),
            60_000,
        )
        .await
        .unwrap();
    let finished = operations
        .get(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &operation.id,
        )
        .await
        .unwrap();
    assert_eq!(finished.state, "failed");
    let error: serde_json::Value = serde_json::from_str(&finished.error_json.unwrap()).unwrap();
    assert_eq!(error["failedAt"], "tool:node");
    assert!(
        !error["remaining"].as_array().unwrap().is_empty(),
        "the remaining steps are named"
    );
}
