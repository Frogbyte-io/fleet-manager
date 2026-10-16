//! FM-1040: the action broker over real SQLite. Policy resolution, the
//! request lifecycle, lazy expiry, exactly-once execution under concurrent
//! approvals, authorization on approve and execute, the credential refusal,
//! and one audit event per transition.

use std::sync::Arc;

use fleet_application::audit::AuditFilter;
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::broker::test_support::{NOOP_ACTION_ID, NoopAction};
use fleet_application::broker::{
    ActionRegistry, ActionRequest, ActionRequestPort as _, Broker, BrokerError, BrokerSettings,
    NewActionRequest, ProviderAction, TransitionUpdate,
};
use fleet_application::operation::{
    NewOperation, OperationPort as _, OperationUseCaseError, Operations,
};
use fleet_core::{ActionRequestState, RiskClass};
use fleet_storage_sqlite::{
    ActionRequestRepository, AuditLedger, AuditSink, OperationRepository, Store,
};

const NOW: i64 = 1_800_000_000_000;
const REQUESTER: &str = "agent-1";
const APPROVER: &str = "human-1";

#[derive(Debug)]
struct Permit;
impl Authorizer for Permit {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

/// Denies the listed permissions, allows the rest.
#[derive(Debug)]
struct Without(Vec<Permission>);
impl Authorizer for Without {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if self.0.contains(&request.action) {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

/// Allows approving only the named action id.
#[derive(Debug)]
struct ApproveOnly(&'static str);
impl Authorizer for ApproveOnly {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.action == Permission::ActionApprove && request.resource != Some(self.0) {
            Decision::deny(ReasonId::OutOfScope)
        } else {
            Decision::allow()
        }
    }
}

/// An action whose operation can never be built.
#[derive(Debug)]
struct Unbuildable;
impl ProviderAction for Unbuildable {
    fn id(&self) -> &'static str {
        "test.unbuildable.run"
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
    fn operation(&self, _request: &ActionRequest) -> Result<NewOperation, String> {
        Err("the provider is unreachable".to_owned())
    }
}

struct World {
    _dir: tempfile::TempDir,
    store: Store,
    broker: Arc<Broker>,
    requests: Arc<ActionRequestRepository>,
    operations: Arc<OperationRepository>,
    use_cases: Arc<Operations>,
}

impl World {
    async fn new(risk: RiskClass) -> Self {
        Self::with_settings(risk, BrokerSettings::default()).await
    }

    async fn with_settings(risk: RiskClass, settings: BrokerSettings) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let operations = Arc::new(OperationRepository::new(store.pool().clone()));
        let use_cases = Arc::new(
            Operations::new(
                operations.clone(),
                Arc::new(AuditSink::new(store.pool().clone())),
            )
            .with_brokered_kinds(["noop".to_owned()]),
        );
        let requests = Arc::new(ActionRequestRepository::new(store.pool().clone()));
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(NoopAction { risk })).unwrap();
        let broker = Arc::new(Broker::new(
            requests.clone(),
            Arc::new(registry),
            use_cases.clone(),
            settings,
        ));
        Self {
            _dir: dir,
            store,
            broker,
            requests,
            operations,
            use_cases,
        }
    }

    fn new_request() -> NewActionRequest {
        NewActionRequest {
            action_id: NOOP_ACTION_ID.to_owned(),
            target: "app-1".to_owned(),
            parameters: serde_json::json!({ "service": "web" }),
            reason: "the deploy looks stale".to_owned(),
            origin: "api".to_owned(),
            correlation_id: Some("corr-1".to_owned()),
            idempotency_key: None,
        }
    }

    async fn create(&self, now: i64) -> ActionRequest {
        self.broker
            .create(&Permit, REQUESTER, Self::new_request(), now)
            .await
            .unwrap()
    }

    /// The transitions audited for one request, in order, as `action from>to`.
    async fn audited(&self, id: &str) -> Vec<String> {
        let ledger = AuditLedger::new(self.store.pool());
        let page = ledger
            .query(&AuditFilter {
                limit: 100,
                resource: Some(id.to_owned()),
                ..AuditFilter::default()
            })
            .await
            .unwrap();
        page.events
            .iter()
            .map(|event| {
                let metadata: serde_json::Value =
                    serde_json::from_str(&event.metadata_json).unwrap();
                format!(
                    "{} {}>{}",
                    event.action,
                    metadata["from"].as_str().unwrap_or("-"),
                    metadata["to"].as_str().unwrap()
                )
            })
            .collect()
    }

    async fn operation_count(&self) -> usize {
        self.operations.list(100).await.unwrap().len()
    }
}

#[tokio::test]
async fn an_approve_class_request_waits_then_executes_once_approved() {
    let world = World::new(RiskClass::Approve).await;
    let request = world.create(NOW).await;
    assert_eq!(request.state, ActionRequestState::Pending);
    assert_eq!(request.risk_class, RiskClass::Approve);
    assert_eq!(request.requester, REQUESTER);
    assert_eq!(request.origin, "api");
    assert_eq!(request.parameters, serde_json::json!({ "service": "web" }));
    assert_eq!(world.operation_count().await, 0);

    let approved = world
        .broker
        .approve(&Permit, APPROVER, &request.id, NOW + 1000)
        .await
        .unwrap();
    assert_eq!(approved.state, ActionRequestState::Executing);
    assert_eq!(approved.decided_by.as_deref(), Some(APPROVER));
    assert_eq!(approved.decided_at, Some(NOW + 1000));
    let operation_id = approved.operation_id.clone().expect("linked operation");
    let operation = world.operations.get(&operation_id).await.unwrap();
    assert_eq!(operation.kind, "noop");
    assert_eq!(
        operation.idempotency_key.as_deref(),
        Some(format!("action-request:{}", request.id).as_str())
    );
    assert_eq!(operation.correlation_id.as_deref(), Some("corr-1"));

    assert_eq!(
        world.audited(&request.id).await,
        [
            "action.request ->pending",
            "action.approve pending>approved",
            "action.execute approved>executing"
        ]
    );
}

#[tokio::test]
async fn an_auto_class_request_executes_at_once_as_the_requester() {
    let world = World::new(RiskClass::Auto).await;
    let request = world.create(NOW).await;
    assert_eq!(request.state, ActionRequestState::Executing);
    assert_eq!(request.decided_by.as_deref(), Some("policy:auto"));
    assert!(request.operation_id.is_some());
    assert_eq!(world.operation_count().await, 1);
    assert_eq!(
        world.audited(&request.id).await,
        [
            "action.request ->approved",
            "action.execute approved>executing"
        ]
    );
}

#[tokio::test]
async fn a_deny_class_request_is_refused_at_creation_with_an_audit_event_only() {
    let world = World::new(RiskClass::Deny).await;
    let error = world
        .broker
        .create(&Permit, REQUESTER, World::new_request(), NOW)
        .await
        .unwrap_err();
    assert!(matches!(error, BrokerError::PolicyDenied { .. }), "{error}");
    // No row, no operation.
    assert!(
        world
            .broker
            .list(&Permit, APPROVER, None, 50, NOW)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(world.operation_count().await, 0);
    // One refused audit event, naming no request.
    let page = AuditLedger::new(world.store.pool())
        .query(&AuditFilter {
            limit: 100,
            action: Some("action.request".to_owned()),
            ..AuditFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(page.events.len(), 1);
    let event = &page.events[0];
    assert!(!event.allowed);
    assert_eq!(event.reason, "policy.risk_class_deny");
    assert_eq!(event.resource, None);
    assert_eq!(event.actor, REQUESTER);
}

#[tokio::test]
async fn the_operator_override_wins_over_the_declared_class() {
    let settings =
        BrokerSettings::from_env_values(None, Some(&format!("{NOOP_ACTION_ID}=approve"))).unwrap();
    let world = World::with_settings(RiskClass::Auto, settings).await;
    let request = world.create(NOW).await;
    assert_eq!(request.risk_class, RiskClass::Approve);
    assert_eq!(request.state, ActionRequestState::Pending);
}

#[tokio::test]
async fn deny_records_the_decider_and_ends_the_request() {
    let world = World::new(RiskClass::Approve).await;
    let request = world.create(NOW).await;
    let denied = world
        .broker
        .deny(&Permit, APPROVER, &request.id, Some("not today"), NOW + 1)
        .await
        .unwrap();
    assert_eq!(denied.state, ActionRequestState::Denied);
    assert_eq!(denied.decided_by.as_deref(), Some(APPROVER));
    assert_eq!(denied.decision_note.as_deref(), Some("not today"));
    assert_eq!(world.operation_count().await, 0);
    // Illegal transitions: a decided request is final.
    for result in [
        world
            .broker
            .approve(&Permit, APPROVER, &request.id, NOW + 2)
            .await,
        world
            .broker
            .deny(&Permit, APPROVER, &request.id, None, NOW + 2)
            .await,
    ] {
        assert!(matches!(
            result.unwrap_err(),
            BrokerError::Conflict {
                state: ActionRequestState::Denied,
                ..
            }
        ));
    }
    assert_eq!(
        world.audited(&request.id).await,
        ["action.request ->pending", "action.deny pending>denied"]
    );
}

#[tokio::test]
async fn concurrent_approvals_execute_exactly_once() {
    let world = World::new(RiskClass::Approve).await;
    let request = world.create(NOW).await;
    let mut tasks = Vec::new();
    for n in 0..12 {
        let broker = world.broker.clone();
        let id = request.id.clone();
        tasks.push(tokio::spawn(async move {
            broker
                .approve(&Permit, &format!("human-{n}"), &id, NOW + 10)
                .await
        }));
    }
    let mut won = 0;
    let mut lost = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(request) => {
                assert_eq!(request.state, ActionRequestState::Executing);
                won += 1;
            }
            Err(BrokerError::Conflict { .. }) => lost += 1,
            Err(other) => panic!("unexpected: {other}"),
        }
    }
    assert_eq!((won, lost), (1, 11));
    assert_eq!(
        world.operation_count().await,
        1,
        "one operation, not one per approver"
    );
    let audited = world.audited(&request.id).await;
    assert_eq!(
        audited
            .iter()
            .filter(|event| event.starts_with("action.approve"))
            .count(),
        1,
        "{audited:?}"
    );
}

#[tokio::test]
async fn an_approve_and_a_deny_race_has_one_winner() {
    let world = World::new(RiskClass::Approve).await;
    let request = world.create(NOW).await;
    let (approve, deny) = tokio::join!(
        world
            .broker
            .approve(&Permit, APPROVER, &request.id, NOW + 1),
        world
            .broker
            .deny(&Permit, "human-2", &request.id, None, NOW + 1),
    );
    assert_ne!(approve.is_ok(), deny.is_ok());
    let current = world
        .broker
        .get(&Permit, APPROVER, &request.id, NOW + 2)
        .await
        .unwrap();
    assert_eq!(
        world.operation_count().await,
        usize::from(current.state == ActionRequestState::Executing)
    );
}

#[tokio::test]
async fn a_request_expires_lazily_and_can_no_longer_be_decided() {
    let settings = BrokerSettings::new(60, std::collections::BTreeMap::new()).unwrap();
    let world = World::with_settings(RiskClass::Approve, settings).await;
    let request = world.create(NOW).await;
    assert_eq!(request.expires_at, NOW + 60_000);

    // One millisecond before the deadline it is still pending.
    let before = world
        .broker
        .get(&Permit, APPROVER, &request.id, NOW + 59_999)
        .await
        .unwrap();
    assert_eq!(before.state, ActionRequestState::Pending);

    // A read at the deadline expires it, once, with an audit event.
    let at = world
        .broker
        .get(&Permit, APPROVER, &request.id, NOW + 60_000)
        .await
        .unwrap();
    assert_eq!(at.state, ActionRequestState::Expired);
    let again = world
        .broker
        .get(&Permit, APPROVER, &request.id, NOW + 120_000)
        .await
        .unwrap();
    assert_eq!(again.state, ActionRequestState::Expired);

    for result in [
        world
            .broker
            .approve(&Permit, APPROVER, &request.id, NOW + 61_000)
            .await,
        world
            .broker
            .deny(&Permit, APPROVER, &request.id, None, NOW + 61_000)
            .await,
    ] {
        assert!(matches!(
            result.unwrap_err(),
            BrokerError::Conflict {
                state: ActionRequestState::Expired,
                ..
            }
        ));
    }
    assert_eq!(world.operation_count().await, 0);
    assert_eq!(
        world.audited(&request.id).await,
        ["action.request ->pending", "action.expire pending>expired"]
    );
}

#[tokio::test]
async fn the_decision_compare_and_set_itself_refuses_an_expired_deadline() {
    let world = World::new(RiskClass::Approve).await;
    let request = world.create(NOW).await;
    // Bypass the broker's lazy check: the statement must still refuse.
    let update = TransitionUpdate {
        from: ActionRequestState::Pending,
        to: ActionRequestState::Approved,
        decided_by: Some(APPROVER.to_owned()),
        decision_note: None,
        operation_id: None,
        failure: None,
        at: request.expires_at,
        require_unexpired: true,
    };
    let audit = fleet_application::audit::AuditIntent {
        actor: APPROVER.to_owned(),
        action: "action.approve".to_owned(),
        resource: Some(request.id.clone()),
        decision: Decision::allow(),
        correlation_id: None,
        operation_id: None,
        metadata: fleet_application::audit::AuditMetadata::default(),
    };
    assert!(
        world
            .requests
            .transition(&request.id, &update, &audit)
            .await
            .unwrap()
            .is_none()
    );
    // And a lost compare-and-set audits nothing.
    assert_eq!(world.audited(&request.id).await.len(), 1);
}

#[tokio::test]
async fn an_illegal_transition_is_refused_by_the_store() {
    let world = World::new(RiskClass::Approve).await;
    let request = world.create(NOW).await;
    let update = TransitionUpdate {
        from: ActionRequestState::Pending,
        to: ActionRequestState::Succeeded,
        decided_by: None,
        decision_note: None,
        operation_id: None,
        failure: None,
        at: NOW,
        require_unexpired: false,
    };
    let audit = fleet_application::audit::AuditIntent {
        actor: "x".to_owned(),
        action: "action.succeed".to_owned(),
        resource: Some(request.id.clone()),
        decision: Decision::allow(),
        correlation_id: None,
        operation_id: None,
        metadata: fleet_application::audit::AuditMetadata::default(),
    };
    assert!(
        world
            .requests
            .transition(&request.id, &update, &audit)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn approving_requires_its_own_permission_and_changes_nothing_when_refused() {
    let world = World::new(RiskClass::Approve).await;
    let request = world.create(NOW).await;
    let error = world
        .broker
        .approve(
            &Without(vec![Permission::ActionApprove]),
            APPROVER,
            &request.id,
            NOW + 1,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, BrokerError::Denied(_)));
    // Holding approve does not grant deny, and the reverse.
    let error = world
        .broker
        .deny(
            &Without(vec![Permission::ActionDeny]),
            APPROVER,
            &request.id,
            None,
            NOW + 1,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, BrokerError::Denied(_)));
    let still = world
        .broker
        .get(&Permit, APPROVER, &request.id, NOW + 2)
        .await
        .unwrap();
    assert_eq!(still.state, ActionRequestState::Pending);
    assert_eq!(world.operation_count().await, 0);
    // Requesting and reading are separate permissions too.
    assert!(matches!(
        world
            .broker
            .create(
                &Without(vec![Permission::ActionRequest]),
                REQUESTER,
                World::new_request(),
                NOW
            )
            .await
            .unwrap_err(),
        BrokerError::Denied(_)
    ));
    assert!(matches!(
        world
            .broker
            .list(
                &Without(vec![Permission::ActionRead]),
                REQUESTER,
                None,
                10,
                NOW
            )
            .await
            .unwrap_err(),
        BrokerError::Denied(_)
    ));
}

#[tokio::test]
async fn a_delegated_requester_can_request_and_never_approve_or_use_the_generic_route() {
    // No operation.create and no action.approve, like a delegated credential.
    let agent = Without(vec![Permission::OperationCreate, Permission::ActionApprove]);
    let world = World::new(RiskClass::Auto).await;
    let auto = world
        .broker
        .create(&agent, REQUESTER, World::new_request(), NOW)
        .await
        .unwrap();
    assert_eq!(auto.state, ActionRequestState::Executing);
    assert_eq!(world.operation_count().await, 1);
    // The generic route is closed to it ...
    let new = NewOperation {
        kind: "noop".to_owned(),
        ..NewOperation::default()
    };
    assert!(matches!(
        world.use_cases.create(&agent, REQUESTER, &new).await,
        Err(OperationUseCaseError::Denied(_))
    ));
    // ... and to a caller that does hold operation.create: brokered kinds
    // are refused there, whoever asks.
    let error = world
        .use_cases
        .create(&Permit, APPROVER, &new)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("POST /requests"), "{error}");
    assert_eq!(world.operation_count().await, 1);

    // An approve-class request waits for a person; the agent cannot approve
    // it, the approver needs no operation.create to.
    let world = World::new(RiskClass::Approve).await;
    let request = world
        .broker
        .create(&agent, REQUESTER, World::new_request(), NOW)
        .await
        .unwrap();
    assert!(matches!(
        world
            .broker
            .approve(&agent, REQUESTER, &request.id, NOW + 1)
            .await
            .unwrap_err(),
        BrokerError::Denied(_)
    ));
    let deciding_human = Without(vec![Permission::OperationCreate]);
    let approved = world
        .broker
        .approve(&deciding_human, APPROVER, &request.id, NOW + 2)
        .await
        .unwrap();
    assert_eq!(approved.state, ActionRequestState::Executing);
    assert_eq!(world.operation_count().await, 1);
}

#[tokio::test]
async fn the_broker_idempotency_prefix_is_reserved_on_the_generic_route() {
    let world = World::new(RiskClass::Approve).await;
    let new = NewOperation {
        kind: "ssh.exec".to_owned(),
        idempotency_key: Some("action-request:anything".to_owned()),
        ..NewOperation::default()
    };
    let error = world
        .use_cases
        .create(&Permit, APPROVER, &new)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("reserved"), "{error}");
    assert_eq!(world.operation_count().await, 0);
}

#[tokio::test]
async fn an_operation_that_already_holds_the_request_key_must_be_the_same_operation() {
    let world = World::new(RiskClass::Approve).await;
    let request = world.create(NOW).await;
    // Something else (bypassing the use case) took the key first.
    world
        .operations
        .create(
            "noop",
            Some(&format!("action-request:{}", request.id)),
            None,
            None,
            Some(r#"{"target":"somewhere-else"}"#),
        )
        .await
        .unwrap();
    let failed = world
        .broker
        .approve(&Permit, APPROVER, &request.id, NOW + 1)
        .await
        .unwrap();
    assert_eq!(failed.state, ActionRequestState::Failed);
    assert!(
        failed
            .failure
            .as_deref()
            .unwrap()
            .contains("different operation")
    );
    assert_eq!(failed.operation_id, None);
}

#[tokio::test]
async fn approval_is_authorized_against_the_requests_action_id() {
    let world = World::new(RiskClass::Approve).await;
    let request = world.create(NOW).await;
    assert!(matches!(
        world
            .broker
            .approve(
                &ApproveOnly("other.action.id"),
                APPROVER,
                &request.id,
                NOW + 1
            )
            .await
            .unwrap_err(),
        BrokerError::Denied(_)
    ));
    let approved = world
        .broker
        .approve(&ApproveOnly(NOOP_ACTION_ID), APPROVER, &request.id, NOW + 2)
        .await
        .unwrap();
    assert_eq!(approved.state, ActionRequestState::Executing);
}

#[tokio::test]
async fn a_changed_policy_that_now_denies_ends_the_request_denied_by_policy() {
    let world = World::new(RiskClass::Approve).await;
    let request = world.create(NOW).await;
    // Rebuild the broker over the same database with a deny override.
    let settings =
        BrokerSettings::from_env_values(None, Some(&format!("{NOOP_ACTION_ID}=deny"))).unwrap();
    let mut registry = ActionRegistry::new();
    registry
        .register(Arc::new(NoopAction {
            risk: RiskClass::Approve,
        }))
        .unwrap();
    let broker = Broker::new(
        world.requests.clone(),
        Arc::new(registry),
        world.use_cases.clone(),
        settings,
    );
    assert!(matches!(
        broker
            .approve(&Permit, APPROVER, &request.id, NOW + 1)
            .await
            .unwrap_err(),
        BrokerError::PolicyDenied { .. }
    ));
    let after = broker
        .get(&Permit, APPROVER, &request.id, NOW + 2)
        .await
        .unwrap();
    assert_eq!(after.state, ActionRequestState::Denied);
    assert_eq!(after.decided_by.as_deref(), Some("policy:deny"));
    assert_eq!(world.operation_count().await, 0);
    assert_eq!(
        world.audited(&request.id).await,
        [
            "action.request ->pending",
            "action.policy_deny pending>denied"
        ]
    );
}

#[tokio::test]
async fn the_request_follows_its_operation_to_a_terminal_state() {
    for (end, expected) in [
        ("succeeded", ActionRequestState::Succeeded),
        ("failed", ActionRequestState::Failed),
    ] {
        let world = World::new(RiskClass::Auto).await;
        let request = world.create(NOW).await;
        let operation_id = request.operation_id.clone().unwrap();
        // Still running: nothing changes.
        let running = world
            .broker
            .get(&Permit, APPROVER, &request.id, NOW + 1)
            .await
            .unwrap();
        assert_eq!(running.state, ActionRequestState::Executing);
        world
            .operations
            .transition(&operation_id, "running")
            .await
            .unwrap();
        let (result, error) = if end == "succeeded" {
            (Some("{}"), None)
        } else {
            (None, Some(r#"{"message":"boom"}"#))
        };
        world
            .operations
            .complete(&operation_id, end, result, error)
            .await
            .unwrap();
        let listed = world
            .broker
            .list(
                &Permit,
                APPROVER,
                Some(ActionRequestState::Executing),
                10,
                NOW + 2,
            )
            .await
            .unwrap();
        assert!(listed.is_empty(), "the request left the filtered state");
        let done = world
            .broker
            .get(&Permit, APPROVER, &request.id, NOW + 3)
            .await
            .unwrap();
        assert_eq!(done.state, expected);
        assert_eq!(done.operation_id.as_deref(), Some(operation_id.as_str()));
        if expected == ActionRequestState::Failed {
            assert!(done.failure.as_deref().unwrap().contains("ended failed"));
        }
        // A terminal request is not touched again.
        let audited = world.audited(&request.id).await;
        let again = world
            .broker
            .get(&Permit, APPROVER, &request.id, NOW + 4)
            .await
            .unwrap();
        assert_eq!(again.state, expected);
        assert_eq!(world.audited(&request.id).await, audited);
        assert_eq!(audited.len(), 3, "{audited:?}");
    }
}

/// Leaves a request `approved` with no operation, as a controller stopped
/// between the decision and execution would.
async fn strand_approved(world: &World, request: &ActionRequest) {
    let update = TransitionUpdate {
        from: ActionRequestState::Pending,
        to: ActionRequestState::Approved,
        decided_by: Some(APPROVER.to_owned()),
        decision_note: None,
        operation_id: None,
        failure: None,
        at: NOW + 1,
        require_unexpired: true,
    };
    let audit = fleet_application::audit::AuditIntent {
        actor: APPROVER.to_owned(),
        action: "action.approve".to_owned(),
        resource: Some(request.id.clone()),
        decision: Decision::allow(),
        correlation_id: None,
        operation_id: None,
        metadata: fleet_application::audit::AuditMetadata::default(),
    };
    world
        .requests
        .transition(&request.id, &update, &audit)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_stuck_approved_request_is_recovered_by_creating_its_operation() {
    let world = World::new(RiskClass::Approve).await;
    let request = world.create(NOW).await;
    strand_approved(&world, &request).await;
    let soon = world
        .broker
        .get(&Permit, APPROVER, &request.id, NOW + 2)
        .await
        .unwrap();
    assert_eq!(soon.state, ActionRequestState::Approved);
    let later = world
        .broker
        .get(&Permit, APPROVER, &request.id, NOW + 120_000)
        .await
        .unwrap();
    assert_eq!(later.state, ActionRequestState::Executing);
    assert_eq!(world.operation_count().await, 1);
    assert_eq!(later.decided_by.as_deref(), Some(APPROVER));
}

#[tokio::test]
async fn a_stuck_approved_request_with_a_created_but_unlinked_operation_links_it() {
    let world = World::new(RiskClass::Approve).await;
    let request = world.create(NOW).await;
    strand_approved(&world, &request).await;
    // The slow start created the operation but never linked it.
    let action = NoopAction {
        risk: RiskClass::Approve,
    };
    let mut new = action.operation(&request).unwrap();
    new.idempotency_key = Some(format!("action-request:{}", request.id));
    let existing = world
        .use_cases
        .create_brokered(&Permit, APPROVER, &new)
        .await
        .unwrap();
    let later = world
        .broker
        .get(&Permit, APPROVER, &request.id, NOW + 120_000)
        .await
        .unwrap();
    assert_eq!(later.state, ActionRequestState::Executing);
    assert_eq!(later.operation_id.as_deref(), Some(existing.id.as_str()));
    // Still one operation: the live one was linked, not orphaned.
    assert_eq!(world.operation_count().await, 1);
}

#[tokio::test]
async fn a_stuck_approved_request_that_cannot_start_fails_with_an_audit_event() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let operations = Arc::new(OperationRepository::new(store.pool().clone()));
    let use_cases = Arc::new(
        Operations::new(
            operations.clone(),
            Arc::new(AuditSink::new(store.pool().clone())),
        )
        .with_brokered_kinds(["noop".to_owned()]),
    );
    let requests = Arc::new(ActionRequestRepository::new(store.pool().clone()));
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(Unbuildable)).unwrap();
    let broker = Broker::new(
        requests.clone(),
        Arc::new(registry),
        use_cases,
        BrokerSettings::default(),
    );
    let mut new = World::new_request();
    new.action_id = "test.unbuildable.run".to_owned();
    let request = broker.create(&Permit, REQUESTER, new, NOW).await.unwrap();
    let update = TransitionUpdate {
        from: ActionRequestState::Pending,
        to: ActionRequestState::Approved,
        decided_by: Some(APPROVER.to_owned()),
        decision_note: None,
        operation_id: None,
        failure: None,
        at: NOW + 1,
        require_unexpired: true,
    };
    let audit = fleet_application::audit::AuditIntent {
        actor: APPROVER.to_owned(),
        action: "action.approve".to_owned(),
        resource: Some(request.id.clone()),
        decision: Decision::allow(),
        correlation_id: None,
        operation_id: None,
        metadata: fleet_application::audit::AuditMetadata::default(),
    };
    requests
        .transition(&request.id, &update, &audit)
        .await
        .unwrap()
        .unwrap();
    let later = broker
        .get(&Permit, APPROVER, &request.id, NOW + 120_000)
        .await
        .unwrap();
    assert_eq!(later.state, ActionRequestState::Failed);
    assert!(
        later
            .failure
            .as_deref()
            .unwrap()
            .contains("could not start")
    );
    let page = AuditLedger::new(store.pool())
        .query(&AuditFilter {
            limit: 100,
            resource: Some(request.id.clone()),
            action: Some("action.fail".to_owned()),
            ..AuditFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(page.events.len(), 1);
}

#[tokio::test]
async fn an_executing_request_whose_operation_vanished_fails_after_a_grace() {
    let world = World::new(RiskClass::Auto).await;
    let request = world.create(NOW).await;
    let operation_id = request.operation_id.clone().unwrap();
    sqlx::query("DELETE FROM operations WHERE id = ?1")
        .bind(&operation_id)
        .execute(world.store.pool())
        .await
        .unwrap();
    let soon = world
        .broker
        .get(&Permit, APPROVER, &request.id, NOW + 1_000)
        .await
        .unwrap();
    assert_eq!(soon.state, ActionRequestState::Executing);
    let later = world
        .broker
        .get(&Permit, APPROVER, &request.id, NOW + 120_000)
        .await
        .unwrap();
    assert_eq!(later.state, ActionRequestState::Failed);
    assert!(
        later
            .failure
            .as_deref()
            .unwrap()
            .contains("could not be found")
    );
}

#[tokio::test]
async fn an_idempotency_key_makes_a_retry_return_the_same_request_per_requester() {
    let world = World::new(RiskClass::Approve).await;
    let mut new = World::new_request();
    new.idempotency_key = Some("retry-1".to_owned());
    let first = world
        .broker
        .create(&Permit, REQUESTER, new.clone(), NOW)
        .await
        .unwrap();
    let again = world
        .broker
        .create(&Permit, REQUESTER, new.clone(), NOW + 5)
        .await
        .unwrap();
    assert_eq!(first.id, again.id);
    assert_eq!(
        world
            .broker
            .list(&Permit, APPROVER, None, 50, NOW + 6)
            .await
            .unwrap()
            .len(),
        1
    );
    // Different content under the same key conflicts.
    let mut other = new.clone();
    other.target = "app-2".to_owned();
    assert!(matches!(
        world
            .broker
            .create(&Permit, REQUESTER, other, NOW + 7)
            .await
            .unwrap_err(),
        BrokerError::Conflict { .. }
    ));
    // The key is scoped to the requester.
    let theirs = world
        .broker
        .create(&Permit, "agent-2", new, NOW + 8)
        .await
        .unwrap();
    assert_ne!(theirs.id, first.id);
    // A malformed key is refused without echoing it.
    let mut bad = World::new_request();
    bad.idempotency_key = Some("has space".to_owned());
    let error = world
        .broker
        .create(&Permit, REQUESTER, bad, NOW)
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("has space"));
}

#[tokio::test]
async fn errors_do_not_echo_caller_input() {
    let world = World::new(RiskClass::Approve).await;
    let mut unknown = World::new_request();
    unknown.action_id = "echo.me.back".to_owned();
    let error = world
        .broker
        .create(&Permit, REQUESTER, unknown, NOW)
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("echo.me.back"), "{error}");
    let mut malformed = World::new_request();
    malformed.action_id = "Not A Valid Id".to_owned();
    let error = world
        .broker
        .create(&Permit, REQUESTER, malformed, NOW)
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("Not A Valid Id"), "{error}");
    let error = world
        .broker
        .get(&Permit, APPROVER, "echo-path-id", NOW)
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("echo-path-id"), "{error}");
    let mut target = World::new_request();
    target.target = "app\n1".to_owned();
    assert!(matches!(
        world
            .broker
            .create(&Permit, REQUESTER, target, NOW)
            .await
            .unwrap_err(),
        BrokerError::Invalid { .. }
    ));
}

#[tokio::test]
async fn bad_requests_are_refused_and_nothing_is_stored() {
    let world = World::new(RiskClass::Approve).await;
    let mut cases = Vec::new();
    for (mutate, needle) in [
        (
            Box::new(|r: &mut NewActionRequest| r.action_id = "nope.nothing.here".to_owned())
                as Box<dyn Fn(&mut NewActionRequest)>,
            "not offered",
        ),
        (
            Box::new(|r| r.parameters = serde_json::json!({ "password": "fakepw1" })),
            "credential",
        ),
        (
            Box::new(|r| r.parameters = serde_json::json!({ "url": "https://u:fakepw1@h/x" })),
            "credential",
        ),
        (
            Box::new(|r| r.reason = "token=fakevalue1234".to_owned()),
            "credential",
        ),
        (
            Box::new(|r| r.parameters = serde_json::json!([1, 2])),
            "object",
        ),
        (Box::new(|r| r.target = String::new()), "empty"),
        (
            Box::new(|r| r.target = "bad-target".to_owned()),
            "not accepted",
        ),
        (
            Box::new(|r| r.parameters = serde_json::json!({ "unexpected": 1 })),
            "not accepted",
        ),
    ] {
        let mut request = World::new_request();
        mutate(&mut request);
        let error = world
            .broker
            .create(&Permit, REQUESTER, request, NOW)
            .await
            .unwrap_err();
        let text = error.to_string();
        assert!(matches!(error, BrokerError::Invalid { .. }), "{text}");
        assert!(text.contains(needle), "{needle}: {text}");
        assert!(!text.contains("fakepw1") && !text.contains("fakevalue1234"));
        cases.push(text);
    }
    assert_eq!(cases.len(), 8);
    let stored = world
        .broker
        .list(&Permit, APPROVER, None, 50, NOW)
        .await
        .unwrap();
    assert!(stored.is_empty());
}

#[tokio::test]
async fn parameters_and_secrets_never_reach_the_audit_ledger() {
    let world = World::new(RiskClass::Approve).await;
    let mut new = World::new_request();
    new.parameters = serde_json::json!({ "service": "needle-param-value" });
    new.reason = "needle-reason-text".to_owned();
    let request = world
        .broker
        .create(&Permit, REQUESTER, new, NOW)
        .await
        .unwrap();
    world
        .broker
        .approve(&Permit, APPROVER, &request.id, NOW + 1)
        .await
        .unwrap();
    let ledger = AuditLedger::new(world.store.pool());
    let page = ledger
        .query(&AuditFilter {
            limit: 100,
            ..AuditFilter::default()
        })
        .await
        .unwrap();
    for event in page.events {
        assert!(!event.metadata_json.contains("needle-param-value"));
        assert!(!event.metadata_json.contains("needle-reason-text"));
    }
}

#[tokio::test]
async fn lists_are_newest_first_filtered_and_bounded() {
    let world = World::new(RiskClass::Approve).await;
    let first = world.create(NOW).await;
    let second = world.create(NOW + 10).await;
    let third = world.create(NOW + 20).await;
    world
        .broker
        .deny(&Permit, APPROVER, &first.id, None, NOW + 30)
        .await
        .unwrap();
    let all = world
        .broker
        .list(&Permit, APPROVER, None, 50, NOW + 40)
        .await
        .unwrap();
    assert_eq!(
        all.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        [third.id.as_str(), second.id.as_str(), first.id.as_str()]
    );
    let pending = world
        .broker
        .list(
            &Permit,
            APPROVER,
            Some(ActionRequestState::Pending),
            50,
            NOW + 40,
        )
        .await
        .unwrap();
    assert_eq!(pending.len(), 2);
    let one = world
        .broker
        .list(&Permit, APPROVER, None, 1, NOW + 40)
        .await
        .unwrap();
    assert_eq!(one.len(), 1);
    let missing = world
        .broker
        .get(&Permit, APPROVER, "nope", NOW)
        .await
        .unwrap_err();
    assert!(matches!(missing, BrokerError::NotFound { .. }));
}
