//! #496: policy bounds and execution-time re-authorization in the action
//! broker, over real SQLite. An action's auto-approval bounds move a request
//! between `approve` and `auto` (never past `deny`), and what made a request
//! runnable is checked again when it runs.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditMetadata};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::broker::{
    ActionRegistry, ActionRequest, ActionRequestPort as _, AutoGuard, Bounds, Broker, BrokerError,
    BrokerSettings, NewActionRequest, ProviderAction, TransitionUpdate,
};
use fleet_application::operation::{NewOperation, Operations};
use fleet_core::{ActionRequestState, RiskClass};
use fleet_storage_sqlite::{ActionRequestRepository, AuditSink, OperationRepository, Store};

const NOW: i64 = 1_800_000_000_000;
const ACTION: &str = "test.bounded.run";

#[derive(Debug)]
struct Permit;
impl Authorizer for Permit {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

/// Allows everything except the permission, for the named principal only.
#[derive(Debug)]
struct WithoutFor(&'static str, Permission);
impl Authorizer for WithoutFor {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.principal_id == self.0 && request.action == self.1 {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

/// Denies a permission after it was allowed `allowed` times.
#[derive(Debug)]
struct Revoked {
    permission: Permission,
    allowed: usize,
    seen: AtomicUsize,
}
impl Authorizer for Revoked {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.action == self.permission
            && self.seen.fetch_add(1, Ordering::SeqCst) >= self.allowed
        {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

/// A bounded action whose bounds answer from a script, one answer per
/// assessment (the last repeats).
#[derive(Debug)]
struct Bounded {
    answers: Vec<Bounds>,
    calls: AtomicUsize,
    approver: Option<Permission>,
}

#[async_trait]
impl AutoGuard for Bounded {
    async fn assess(
        &self,
        _requester: &str,
        _parameters: &serde_json::Value,
        _except: Option<&str>,
    ) -> Result<Bounds, String> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.answers[call.min(self.answers.len() - 1)])
    }
}

impl ProviderAction for Bounded {
    fn id(&self) -> &'static str {
        ACTION
    }
    fn operation_kind(&self) -> &'static str {
        "noop"
    }
    fn risk_class(&self) -> RiskClass {
        RiskClass::Approve
    }
    fn validate(&self, _target: &str, _parameters: &serde_json::Value) -> Result<(), String> {
        Ok(())
    }
    fn operation(&self, request: &ActionRequest) -> Result<NewOperation, String> {
        Ok(NewOperation {
            kind: "noop".to_owned(),
            idempotency_key: None,
            deadline_at: None,
            correlation_id: None,
            payload_json: Some(format!("{{\"request\":\"{}\"}}", request.id)),
            review_token: None,
        })
    }
    fn auto_guard(&self) -> Option<&dyn AutoGuard> {
        Some(self)
    }
    fn approver_permission(&self) -> Option<Permission> {
        self.approver
    }
}

struct World {
    _dir: tempfile::TempDir,
    broker: Broker,
    operations: Arc<Operations>,
    requests: Arc<ActionRequestRepository>,
}

impl World {
    async fn new(
        answers: Vec<Bounds>,
        approver: Option<Permission>,
        overrides: BTreeMap<String, RiskClass>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let operations = Arc::new(
            Operations::new(
                Arc::new(OperationRepository::new(store.pool().clone())),
                Arc::new(AuditSink::new(store.pool().clone())),
            )
            .with_brokered_kinds(["noop".to_owned()]),
        );
        let mut registry = ActionRegistry::new();
        registry
            .register(Arc::new(Bounded {
                answers,
                calls: AtomicUsize::new(0),
                approver,
            }))
            .unwrap();
        let requests = Arc::new(ActionRequestRepository::new(store.pool().clone()));
        let broker = Broker::new(
            requests.clone(),
            Arc::new(registry),
            operations.clone(),
            BrokerSettings::new(86_400, overrides).unwrap(),
        );
        std::mem::forget(store);
        Self {
            _dir: dir,
            broker,
            operations,
            requests,
        }
    }

    async fn ask(&self, authorizer: &dyn Authorizer) -> Result<ActionRequest, BrokerError> {
        self.broker
            .create(
                authorizer,
                "agent-1",
                NewActionRequest {
                    action_id: ACTION.to_owned(),
                    target: "t".to_owned(),
                    parameters: serde_json::json!({}),
                    reason: "needed".to_owned(),
                    origin: "api".to_owned(),
                    correlation_id: None,
                    idempotency_key: None,
                },
                NOW,
            )
            .await
    }
}

fn none() -> BTreeMap<String, RiskClass> {
    BTreeMap::new()
}

#[tokio::test]
async fn within_bounds_is_auto_outside_and_unconfigured_wait_for_a_person() {
    let within = World::new(vec![Bounds::Within], None, none()).await;
    let request = within.ask(&Permit).await.unwrap();
    assert_eq!(request.state, ActionRequestState::Executing);
    assert_eq!(request.risk_class, RiskClass::Auto);
    assert_eq!(request.decided_by.as_deref(), Some("policy:auto"));

    for answer in [Bounds::Outside, Bounds::Unconfigured] {
        let world = World::new(vec![answer], None, none()).await;
        let request = world.ask(&Permit).await.unwrap();
        assert_eq!(request.state, ActionRequestState::Pending, "{answer:?}");
        assert_eq!(request.risk_class, RiskClass::Approve);
        assert!(request.operation_id.is_none());
    }
}

#[tokio::test]
async fn an_operator_override_wins_over_the_bounds() {
    // `deny` stays deny, even for a request inside the bounds.
    let denied = World::new(
        vec![Bounds::Within],
        None,
        BTreeMap::from([(ACTION.to_owned(), RiskClass::Deny)]),
    )
    .await;
    assert!(matches!(
        denied.ask(&Permit).await,
        Err(BrokerError::PolicyDenied { .. })
    ));
    // A pinned `approve` is not widened by bounds.
    let pinned = World::new(
        vec![Bounds::Within],
        None,
        BTreeMap::from([(ACTION.to_owned(), RiskClass::Approve)]),
    )
    .await;
    assert_eq!(
        pinned.ask(&Permit).await.unwrap().state,
        ActionRequestState::Pending
    );
    // A pinned `auto` is narrowed by bounds the request is outside.
    let narrowed = World::new(
        vec![Bounds::Outside],
        None,
        BTreeMap::from([(ACTION.to_owned(), RiskClass::Auto)]),
    )
    .await;
    assert_eq!(
        narrowed.ask(&Permit).await.unwrap().state,
        ActionRequestState::Pending
    );
}

#[tokio::test]
async fn a_policy_approval_that_no_longer_holds_when_it_runs_fails_the_request() {
    // Within when asked, outside by the time the operation would start.
    let world = World::new(vec![Bounds::Within, Bounds::Outside], None, none()).await;
    let request = world.ask(&Permit).await.unwrap();
    assert_eq!(request.state, ActionRequestState::Failed);
    assert!(request.operation_id.is_none());
    assert!(
        request
            .failure
            .as_deref()
            .is_some_and(|failure| failure.contains("policy no longer approves"))
    );
}

#[tokio::test]
async fn a_requester_who_lost_the_right_to_ask_does_not_run_by_policy() {
    // Asked while allowed; the requester's permission is gone when the
    // operation would start (the third check: the use case's, the broker's,
    // then the re-check).
    let world = World::new(vec![Bounds::Within], None, none()).await;
    let authorizer = Revoked {
        permission: Permission::ActionRequest,
        allowed: 1,
        seen: AtomicUsize::new(0),
    };
    let request = world.ask(&authorizer).await.unwrap();
    assert_eq!(request.state, ActionRequestState::Failed);
    assert!(
        request
            .failure
            .as_deref()
            .is_some_and(|failure| failure.contains("may no longer ask"))
    );
}

#[tokio::test]
async fn an_approver_without_the_actions_permission_cannot_approve_and_the_request_waits() {
    let world = World::new(
        vec![Bounds::Outside],
        Some(Permission::MachineProvision),
        none(),
    )
    .await;
    let request = world.ask(&Permit).await.unwrap();
    assert_eq!(request.state, ActionRequestState::Pending);
    let refused = world
        .broker
        .approve(
            &WithoutFor("human-1", Permission::MachineProvision),
            "human-1",
            &request.id,
            NOW,
        )
        .await;
    assert!(matches!(refused, Err(BrokerError::Denied(_))));
    let still = world
        .broker
        .get(&Permit, "human-1", &request.id, NOW)
        .await
        .unwrap();
    assert_eq!(still.state, ActionRequestState::Pending);
    // Another approver who holds it can decide.
    let approved = world
        .broker
        .approve(&Permit, "human-2", &request.id, NOW)
        .await
        .unwrap();
    assert_eq!(approved.state, ActionRequestState::Executing);
    assert!(approved.operation_id.is_some());
}

#[tokio::test]
async fn an_approver_who_lost_the_permission_before_it_runs_fails_the_request() {
    let world = World::new(
        vec![Bounds::Outside],
        Some(Permission::MachineProvision),
        none(),
    )
    .await;
    let request = world.ask(&Permit).await.unwrap();
    // Held at approval (the up-front check), gone at execution.
    let authorizer = Revoked {
        permission: Permission::MachineProvision,
        allowed: 1,
        seen: AtomicUsize::new(0),
    };
    let ended = world
        .broker
        .approve(&authorizer, "human-1", &request.id, NOW)
        .await
        .unwrap();
    assert_eq!(ended.state, ActionRequestState::Failed);
    assert!(ended.operation_id.is_none());
    assert!(
        ended
            .failure
            .as_deref()
            .is_some_and(|failure| failure.contains("no longer holds"))
    );
}

#[tokio::test]
async fn a_rejected_request_never_creates_an_operation() {
    let world = World::new(vec![Bounds::Outside], None, none()).await;
    let request = world.ask(&Permit).await.unwrap();
    let denied = world
        .broker
        .deny(&Permit, "human-1", &request.id, Some("not now"), NOW)
        .await
        .unwrap();
    assert_eq!(denied.state, ActionRequestState::Denied);
    assert!(denied.operation_id.is_none());
    let late = world
        .broker
        .approve(&Permit, "human-1", &request.id, NOW)
        .await;
    assert!(
        matches!(late, Err(BrokerError::Conflict { .. })),
        "{late:?}"
    );
}

#[tokio::test]
async fn a_requester_who_lost_the_right_to_ask_after_a_human_approved_fails_the_request() {
    let world = World::new(vec![Bounds::Outside], None, none()).await;
    let request = world.ask(&Permit).await.unwrap();
    // The approver is fine; the requester's `action.request` was revoked.
    let ended = world
        .broker
        .approve(
            &WithoutFor("agent-1", Permission::ActionRequest),
            "human-1",
            &request.id,
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(ended.state, ActionRequestState::Failed);
    assert!(ended.operation_id.is_none());
    assert!(
        ended
            .failure
            .as_deref()
            .is_some_and(|failure| failure.contains("may no longer ask"))
    );
}

#[tokio::test]
async fn an_operation_already_created_is_linked_even_when_the_recheck_would_now_fail() {
    // The crash this models: the operation was created on the brokered
    // route, then the process died before the request was linked to it.
    let world = World::new(vec![Bounds::Outside], None, none()).await;
    let request = world.ask(&Permit).await.unwrap();
    let approved = world
        .requests
        .transition(
            &request.id,
            &TransitionUpdate {
                from: ActionRequestState::Pending,
                to: ActionRequestState::Approved,
                decided_by: Some("human-1".to_owned()),
                decision_note: None,
                operation_id: None,
                failure: None,
                at: NOW,
                require_unexpired: true,
            },
            &AuditIntent {
                actor: "human-1".to_owned(),
                action: "action.approve".to_owned(),
                resource: Some(request.id.clone()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata: AuditMetadata::default(),
            },
        )
        .await
        .unwrap()
        .unwrap();
    let orphan = world
        .operations
        .create_brokered(
            &Permit,
            "human-1",
            &NewOperation {
                kind: "noop".to_owned(),
                idempotency_key: Some(format!("action-request:{}", request.id)),
                deadline_at: None,
                correlation_id: None,
                payload_json: Some(format!("{{\"request\":\"{}\"}}", request.id)),
                review_token: None,
            },
        )
        .await
        .unwrap();
    // Recovery, after the grace, by someone for whom the approver's
    // approval no longer holds: the existing operation is still linked.
    let later = NOW + 5 * 60_000;
    let recovered = world
        .broker
        .get(
            &WithoutFor("human-1", Permission::ActionApprove),
            "reader",
            &approved.id,
            later,
        )
        .await
        .unwrap();
    assert_eq!(recovered.state, ActionRequestState::Executing);
    assert_eq!(recovered.operation_id.as_deref(), Some(orphan.id.as_str()));
}
