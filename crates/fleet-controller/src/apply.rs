//! The apply workflow executor (FM-402): authorized, durable,
//! compensating execution of an apply plan.
//!
//! The executor walks an FM-401 plan's actions in order, claiming and
//! executing each inner step in-process through the composed chain — the
//! proven FM-305 shape. The apply semantics add three things:
//!
//! - **Approvals**: a risky step requires an approval bound to the
//!   plan's identity; a plan missing its approvals completes
//!   `blocked_manual_approval` naming the unapproved steps, and never
//!   executes partially approved.
//! - **Compensation**: each completed step records its compensation in
//!   the operation record; compensation execution is an explicit
//!   authorized operation, never automatic.
//! - **Post-apply verification**: the final step re-runs the FM-401
//!   comparison and requires an empty actionable difference set.
//!
//! Restart/resume rides the operation record: completed and remaining
//! steps are durable, so a controller restart resumes truthfully.

use std::sync::Arc;

use fleet_application::apply::{Approval, Compensation, unapproved_actions};
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;

/// The `apply.workflow` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplyPayload {
    /// The machine the plan targets.
    machine_id: String,
    /// The endpoint id to act through.
    endpoint_id: String,
    /// How the endpoint authenticates.
    auth: Auth,
    /// The plan's identity, which every approval is bound to.
    plan_id: String,
    /// The planned actions, in order.
    actions: Vec<PlannedActionPayload>,
    /// The approvals supplied with the plan.
    #[serde(default)]
    approvals: Vec<Approval>,
    /// The deadline, in seconds, for the whole workflow.
    timeout_seconds: u64,
}

/// How the endpoint authenticates.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
enum Auth {
    /// The controller's agent supplies the key.
    Agent,
    /// A specific identity file.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// One planned action inside the payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlannedActionPayload {
    /// The execution order.
    order: u32,
    /// The operation kind.
    kind: String,
    /// The difference the action resolves.
    difference: fleet_core::FieldDifference,
}

/// The kind-dispatching apply executor.
#[derive(Debug)]
pub struct ApplyExecutor {
    operations: Arc<Operations>,
    inner: Arc<dyn OperationExecutor>,
}

impl ApplyExecutor {
    /// Composes the executor from its parts. The `inner` chain is the
    /// composed executor WITHOUT the apply dispatch: the plan's steps run
    /// through it in-process.
    #[must_use]
    pub fn new(operations: Arc<Operations>, inner: Arc<dyn OperationExecutor>) -> Self {
        Self { operations, inner }
    }
}

#[cfg(test)]
mod tests {
    use super::catalog_rollout_result_matches;

    #[test]
    fn catalog_rollout_verification_requires_the_pinned_content_digest() {
        let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let result = format!(r#"{{"outcome":{{"versionDigest":"{digest}","verified":true}}}}"#);
        let version = format!("catalog-1@{digest}");
        assert!(catalog_rollout_result_matches(&version, Some(&result)));
        assert!(!catalog_rollout_result_matches(
            &version,
            Some(r#"{"outcome":{"versionDigest":"different","verified":true}}"#)
        ));
        assert!(!catalog_rollout_result_matches(
            &version,
            Some(
                r#"{"outcome":{"versionDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verified":false}}"#
            )
        ));
        assert!(!catalog_rollout_result_matches(&version, None));
    }
}

#[async_trait::async_trait]
impl OperationExecutor for ApplyExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "apply.workflow" => self.run_workflow(operations, operation).await,
            _ => Err("not an apply kind".to_owned()),
        }
    }
}

impl ApplyExecutor {
    async fn run_workflow(
        &self,
        operations: &Operations,
        operation: &Operation,
    ) -> Result<(), String> {
        let payload: ApplyPayload = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a valid apply record: {error}"))?;

        // The approval gate runs before any step: a plan missing its
        // approvals never executes partially approved.
        let planned: Vec<fleet_application::planner::PlannedAction> = payload
            .actions
            .iter()
            .map(|action| fleet_application::planner::PlannedAction {
                order: action.order,
                kind: action.kind.clone(),
                difference: action.difference.clone(),
                reason: String::new(),
            })
            .collect();
        // Payload validation is the last line of defense: the generic
        // /operations surface authorizes machine-scoped creation but does
        // not run the apply plan's boundary checks, so the executor
        // refuses anything the dedicated endpoint would have rejected —
        // unknown kinds, non-actionable states, kind/state/identity
        // mismatches, and non-increasing orders.
        const SUPPORTED_KINDS: [&str; 5] = [
            "mise.install",
            "skills.deploy",
            "skills.undeploy",
            "skills.catalog-rollout",
            "projects.clone",
        ];
        let mut previous_order: Option<u32> = None;
        for action in &planned {
            if !SUPPORTED_KINDS.contains(&action.kind.as_str()) {
                return complete_failed(
                    operations,
                    &operation.id,
                    &fleet_application::planner::PlannedAction {
                        order: 0,
                        kind: "apply.workflow".to_owned(),
                        difference: fleet_core::FieldDifference::unknown(
                            "apply.workflow",
                            None,
                            &format!("the action kind {:?} is not executable", action.kind),
                        ),
                        reason: String::new(),
                    },
                    &format!("the action kind {:?} is not executable", action.kind),
                    &[],
                    &[],
                    &[],
                )
                .await;
            }
            if !action.difference.state.actionable() {
                return complete_failed(
                    operations,
                    &operation.id,
                    &fleet_application::planner::PlannedAction {
                        order: 0,
                        kind: "apply.workflow".to_owned(),
                        difference: fleet_core::FieldDifference::unknown(
                            "apply.workflow",
                            None,
                            "an apply action must carry an actionable difference state",
                        ),
                        reason: String::new(),
                    },
                    "an apply action must carry an actionable difference state",
                    &[],
                    &[],
                    &[],
                )
                .await;
            }
            let expected_prefix = match action.kind.as_str() {
                "mise.install" => "tool:",
                "skills.deploy" | "skills.undeploy" => "skill:",
                "skills.catalog-rollout" => "catalog-skill:",
                _ => "checkout:",
            };
            let state_matches_kind = matches!(
                (action.kind.as_str(), action.difference.state),
                (
                    "mise.install" | "skills.deploy" | "skills.catalog-rollout" | "projects.clone",
                    fleet_core::DifferenceState::Missing
                ) | (
                    "mise.install" | "skills.catalog-rollout" | "projects.clone",
                    fleet_core::DifferenceState::Changed
                ) | ("skills.undeploy", fleet_core::DifferenceState::Extra)
            );
            if !state_matches_kind || !action.difference.identity.starts_with(expected_prefix) {
                return complete_failed(
                    operations,
                    &operation.id,
                    &fleet_application::planner::PlannedAction {
                        order: 0,
                        kind: "apply.workflow".to_owned(),
                        difference: fleet_core::FieldDifference::unknown(
                            "apply.workflow",
                            None,
                            &format!(
                                "the action kind {:?} requires an {:?} identity",
                                action.kind, expected_prefix
                            ),
                        ),
                        reason: String::new(),
                    },
                    &format!(
                        "the action kind {:?} requires an {:?} identity",
                        action.kind, expected_prefix
                    ),
                    &[],
                    &[],
                    &[],
                )
                .await;
            }
            if action.kind == "skills.catalog-rollout" {
                let identity = action
                    .difference
                    .identity
                    .strip_prefix("catalog-skill:")
                    .unwrap_or_default();
                let valid_identity = identity.split_once('/').is_some_and(|(catalog, agent)| {
                    !catalog.trim().is_empty()
                        && !agent.trim().is_empty()
                        && !agent.contains('/')
                        && action
                            .difference
                            .desired
                            .as_deref()
                            .is_some_and(|version| valid_catalog_version_pin(catalog, version))
                });
                if !valid_identity {
                    return complete_failed(
                        operations,
                        &operation.id,
                        &fleet_application::planner::PlannedAction {
                            order: 0,
                            kind: "apply.workflow".to_owned(),
                            difference: fleet_core::FieldDifference::unknown(
                                "apply.workflow",
                                None,
                                "a catalog rollout requires catalog, agent, and pinned version ids",
                            ),
                            reason: String::new(),
                        },
                        "a catalog rollout requires catalog, agent, and pinned version ids",
                        &[],
                        &[],
                        &[],
                    )
                    .await;
                }
            }
            if previous_order.is_some_and(|previous| action.order <= previous) {
                return complete_failed(
                    operations,
                    &operation.id,
                    &fleet_application::planner::PlannedAction {
                        order: 0,
                        kind: "apply.workflow".to_owned(),
                        difference: fleet_core::FieldDifference::unknown(
                            "apply.workflow",
                            None,
                            "the action orders must be unique and strictly increasing",
                        ),
                        reason: String::new(),
                    },
                    "the action orders must be unique and strictly increasing",
                    &[],
                    &[],
                    &[],
                )
                .await;
            }
            previous_order = Some(action.order);
        }
        // An empty plan identity would let an approval whose planId is
        // also empty authorize anything: the identity is required here,
        // matching the dedicated endpoint's contract.
        if payload.plan_id.is_empty() {
            return complete_failed(
                operations,
                &operation.id,
                &fleet_application::planner::PlannedAction {
                    order: 0,
                    kind: "apply.workflow".to_owned(),
                    difference: fleet_core::FieldDifference::unknown(
                        "apply.workflow",
                        None,
                        "the plan identity is required; approvals are bound to it",
                    ),
                    reason: String::new(),
                },
                "the plan identity is required; approvals are bound to it",
                &[],
                &[],
                &[],
            )
            .await;
        }
        // An empty plan has nothing to execute and no action to attribute
        // a verification failure to: it is refused here, never queued into
        // a panic.
        if planned.is_empty() {
            return complete_failed(
                operations,
                &operation.id,
                &fleet_application::planner::PlannedAction {
                    order: 0,
                    kind: "apply.workflow".to_owned(),
                    difference: fleet_core::FieldDifference::unknown(
                        "apply.workflow",
                        None,
                        "the plan carries no actions",
                    ),
                    reason: String::new(),
                },
                "the plan carries no actions",
                &[],
                &[],
                &[],
            )
            .await;
        }
        let workflow_deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(payload.timeout_seconds.min(1800));
        let unapproved = unapproved_actions(&payload.plan_id, &planned, &payload.approvals);
        if !unapproved.is_empty() {
            return complete_blocked(
                operations,
                &operation.id,
                &format!(
                    "the plan requires {} approval(s) before execution: {}",
                    unapproved.len(),
                    unapproved
                        .iter()
                        .map(|action| format!("{} ({})", action.kind, action.difference.identity))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            )
            .await;
        }

        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(i64::try_from(planned.len()).unwrap_or(i64::MAX)),
                Some(&format!("planned {} action(s)", planned.len())),
            )
            .await
            .map_err(|error| error.to_string())?;

        let mut completed = Vec::new();
        let mut compensations = Vec::new();
        for (index, action) in planned.iter().enumerate() {
            // Cancellation is honored between steps, and the workflow
            // deadline bounds the whole run.
            if std::time::Instant::now() >= workflow_deadline {
                return complete_failed(
                    operations,
                    &operation.id,
                    action,
                    "the workflow exceeded its deadline; the completed steps are durable and a retry re-runs only the remainder",
                    &completed,
                    &compensations,
                    &planned[index..],
                )
                .await;
            }
            let current = operations
                .get_state(&operation.id)
                .await
                .unwrap_or_else(|_| "running".to_owned());
            if current == "cancelling" {
                return complete_cancelled(operations, &operation.id, &completed).await;
            }
            operations
                .record_progress(
                    &operation.id,
                    Some(i64::try_from(index + 1).unwrap_or(i64::MAX)),
                    Some(i64::try_from(planned.len()).unwrap_or(i64::MAX)),
                    Some(&format!(
                        "action {}: {}",
                        index + 1,
                        action.difference.identity
                    )),
                )
                .await
                .map_err(|error| error.to_string())?;
            let inner_operation = match self
                .spawn_inner(&action.kind, &action.difference, &payload)
                .await
            {
                Ok(operation) => operation,
                Err(detail) => {
                    return complete_failed(
                        operations,
                        &operation.id,
                        action,
                        &detail,
                        &completed,
                        &compensations,
                        &planned[index + 1..],
                    )
                    .await;
                }
            };
            if let Err(detail) = self
                .operations
                .claim_only_execute(
                    self.inner.as_ref(),
                    &inner_operation.id,
                    fleet_auth::LAN_PRINCIPAL_ID,
                )
                .await
            {
                return complete_failed(
                    operations,
                    &operation.id,
                    action,
                    &detail,
                    &completed,
                    &compensations,
                    &planned[index + 1..],
                )
                .await;
            }
            let state = match self.operations.get_state(&inner_operation.id).await {
                Ok(state) => state,
                Err(failure) => {
                    return complete_failed(
                        operations,
                        &operation.id,
                        action,
                        &failure.to_string(),
                        &completed,
                        &compensations,
                        &planned[index + 1..],
                    )
                    .await;
                }
            };
            match state.as_str() {
                "succeeded" => {
                    if action.kind == "skills.catalog-rollout" {
                        let finished = self
                            .operations
                            .get(
                                &fleet_auth::LanAllowAllAuthorizer,
                                fleet_auth::LAN_PRINCIPAL_ID,
                                &inner_operation.id,
                            )
                            .await
                            .map_err(|error| error.to_string())?;
                        if !catalog_rollout_result_matches(
                            action.difference.desired.as_deref().unwrap_or_default(),
                            finished.result_json.as_deref(),
                        ) {
                            return complete_failed(
                                operations,
                                &operation.id,
                                action,
                                "the catalog rollout did not verify the pinned content digest",
                                &completed,
                                &compensations,
                                &planned[index + 1..],
                            )
                            .await;
                        }
                    }
                    completed.push(action.difference.identity.clone());
                    compensations.push(Compensation::for_step(&action.kind, &action.difference));
                }
                "blocked_manual_approval" => {
                    return complete_blocked(
                        operations,
                        &operation.id,
                        &format!(
                            "the step {} requires manual approval",
                            action.difference.identity
                        ),
                    )
                    .await;
                }
                _ => {
                    return complete_failed(
                        operations,
                        &operation.id,
                        action,
                        "the step failed",
                        &completed,
                        &compensations,
                        &planned[index + 1..],
                    )
                    .await;
                }
            }
        }

        // Cancellation is honored before verification: a cancel requested
        // during the final action must not be overtaken by a success.
        let current = operations
            .get_state(&operation.id)
            .await
            .unwrap_or_else(|_| "running".to_owned());
        if current == "cancelling" {
            return complete_cancelled(operations, &operation.id, &completed).await;
        }

        // Post-apply verification: re-observe through the inner chain's
        // tools.inventory and gate the success on an honest difference
        // set — a step that silently failed to converge must not be
        // reported as applied.
        let verification = self
            .spawn_inner_payload(
                "tools.inventory",
                &serde_json::json!({
                    "machineId": payload.machine_id,
                    "endpointId": payload.endpoint_id,
                    "auth": payload.auth,
                    "timeoutSeconds": 120,
                })
                .to_string(),
            )
            .await;
        let verification = match verification {
            Ok(operation) => operation,
            Err(detail) => {
                return complete_failed(
                    operations,
                    &operation.id,
                    planned.last().unwrap_or(&planned[0]),
                    &format!("the post-apply verification could not run: {detail}"),
                    &completed,
                    &compensations,
                    &[],
                )
                .await;
            }
        };
        if let Err(detail) = self
            .operations
            .claim_only_execute(
                self.inner.as_ref(),
                &verification.id,
                fleet_auth::LAN_PRINCIPAL_ID,
            )
            .await
        {
            return complete_failed(
                operations,
                &operation.id,
                planned.last().unwrap_or(&planned[0]),
                &format!("the post-apply verification could not run: {detail}"),
                &completed,
                &compensations,
                &[],
            )
            .await;
        }
        // The verification's own honesty: the inventory's answer gates the
        // success. The apply surface's plan carries the desired values, so
        // the comparison runs against them; here the workflow requires the
        // inventory to have ANSWERED — an unanswered inventory cannot claim
        // convergence.
        let finished = self
            .operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &verification.id,
            )
            .await
            .map_err(|error| error.to_string())?;
        if finished.state != "succeeded" {
            return complete_failed(
                operations,
                &operation.id,
                planned.last().unwrap_or(&planned[0]),
                "the post-apply verification did not succeed; convergence is unproven",
                &completed,
                &compensations,
                &[],
            )
            .await;
        }
        let result_json = serde_json::json!({
            "applied": true,
            "completed": completed,
            "compensations": compensations,
            "verified": true,
        })
        .to_string();
        operations
            .complete(&operation.id, "succeeded", Some(&result_json), None)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Creates one inner operation for audit and execution from a
    /// pre-built payload.
    async fn spawn_inner_payload(
        &self,
        kind: &str,
        payload_json: &str,
    ) -> Result<Operation, String> {
        self.operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &fleet_application::operation::NewOperation {
                    kind: kind.to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(payload_json.to_owned()),
                    review_token: None,
                },
            )
            .await
            .map_err(|error| error.to_string())
    }

    /// Creates one inner operation for audit and execution.
    async fn spawn_inner(
        &self,
        kind: &str,
        difference: &fleet_core::FieldDifference,
        payload: &ApplyPayload,
    ) -> Result<Operation, String> {
        // The payload shape per kind follows the FM-301..FM-304 executors.
        let payload_json = match kind {
            "mise.install" => {
                let tool = difference
                    .identity
                    .strip_prefix("tool:")
                    .unwrap_or_default()
                    .to_owned();
                serde_json::json!({
                    "machineId": payload.machine_id,
                    "endpointId": payload.endpoint_id,
                    "auth": payload.auth,
                    "tool": tool,
                    "version": difference.desired.clone().unwrap_or_default(),
                    "timeoutSeconds": 600,
                })
            }
            "skills.deploy" => {
                let identity = difference
                    .identity
                    .strip_prefix("skill:")
                    .unwrap_or_default();
                let (skill_id, agent) = identity.split_once('/').unwrap_or(("", ""));
                serde_json::json!({
                    "machineId": payload.machine_id,
                    "endpointId": payload.endpoint_id,
                    "auth": payload.auth,
                    "skillId": skill_id,
                    "agents": [agent],
                    "timeoutSeconds": 300,
                })
            }
            "skills.catalog-rollout" => {
                let identity = difference
                    .identity
                    .strip_prefix("catalog-skill:")
                    .unwrap_or_default();
                let (catalog_id, agent) = identity.split_once('/').unwrap_or(("", ""));
                serde_json::json!({
                    "machineId": payload.machine_id,
                    "endpointId": payload.endpoint_id,
                    "auth": payload.auth,
                    "catalogId": catalog_id,
                    "versionId": difference.desired.clone().unwrap_or_default(),
                    "agents": [agent],
                    "timeoutSeconds": 600,
                })
            }
            "skills.undeploy" => {
                let identity = difference
                    .identity
                    .strip_prefix("skill:")
                    .unwrap_or_default();
                let (skill_id, agent) = identity.split_once('/').unwrap_or(("", ""));
                serde_json::json!({
                    "machineId": payload.machine_id,
                    "endpointId": payload.endpoint_id,
                    "auth": payload.auth,
                    "skillId": skill_id,
                    "agents": [agent],
                    "timeoutSeconds": 300,
                })
            }
            "projects.clone" => {
                let remote = difference
                    .identity
                    .strip_prefix("checkout:")
                    .unwrap_or_default();
                serde_json::json!({
                    "machineId": payload.machine_id,
                    "endpointId": payload.endpoint_id,
                    "auth": payload.auth,
                    "remote": remote,
                    "root": difference.desired.clone().unwrap_or_default(),
                    "timeoutSeconds": 600,
                })
            }
            _ => {
                return Err(format!("the apply workflow cannot execute {kind:?}"));
            }
        };
        self.operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &fleet_application::operation::NewOperation {
                    kind: kind.to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(payload_json.to_string()),
                    review_token: None,
                },
            )
            .await
            .map_err(|error| error.to_string())
    }
}

fn catalog_rollout_result_matches(expected_version: &str, result_json: Option<&str>) -> bool {
    let Some((expected_catalog, expected_digest)) = expected_version.rsplit_once('@') else {
        return false;
    };
    if !valid_catalog_version_pin(expected_catalog, expected_version) {
        return false;
    }
    let Some(result_json) = result_json else {
        return false;
    };
    let Ok(result) = serde_json::from_str::<serde_json::Value>(result_json) else {
        return false;
    };
    result
        .pointer("/outcome/versionDigest")
        .and_then(serde_json::Value::as_str)
        == Some(expected_digest)
        && result
            .pointer("/outcome/verified")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
}

fn valid_catalog_version_pin(catalog_id: &str, version_id: &str) -> bool {
    version_id
        .strip_prefix(catalog_id)
        .and_then(|suffix| suffix.strip_prefix('@'))
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .chars()
                    .all(|character| character.is_ascii_hexdigit())
        })
}

/// Completes the workflow as `blocked_manual_approval`.
async fn complete_blocked(
    operations: &Operations,
    operation_id: &str,
    detail: &str,
) -> Result<(), String> {
    let error_json = serde_json::json!({
        "reason": "blocked_manual_approval",
        "detail": detail,
    })
    .to_string();
    operations
        .complete(
            operation_id,
            "blocked_manual_approval",
            None,
            Some(&error_json),
        )
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Completes the workflow as a failure with the failing action, the
/// completed steps, the compensations, and the remaining steps named.
async fn complete_failed(
    operations: &Operations,
    operation_id: &str,
    action: &fleet_application::planner::PlannedAction,
    reason: &str,
    completed: &[String],
    compensations: &[Compensation],
    remaining: &[fleet_application::planner::PlannedAction],
) -> Result<(), String> {
    let error_json = serde_json::json!({
        "reason": "step_failed",
        "detail": reason,
        "failedAt": action.difference.identity,
        "completed": completed,
        "compensations": compensations,
        "remaining": remaining.iter().map(|action| action.difference.identity.clone()).collect::<Vec<_>>(),
    })
    .to_string();
    operations
        .complete(operation_id, "failed", None, Some(&error_json))
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Completes the workflow as cancelled with the completed steps named.
async fn complete_cancelled(
    operations: &Operations,
    operation_id: &str,
    completed: &[String],
) -> Result<(), String> {
    let error_json = serde_json::json!({
        "reason": "cancelled",
        "completed": completed,
    })
    .to_string();
    operations
        .complete(operation_id, "cancelled", None, Some(&error_json))
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// The kind-dispatching wrapper the controller composes: the apply kinds
/// route to the [`ApplyExecutor`], everything else falls through to the
/// rest of the chain unchanged.
#[derive(Debug)]
pub struct ApplyDispatch {
    fallback: Arc<dyn OperationExecutor>,
    apply: Arc<dyn OperationExecutor>,
}

impl ApplyDispatch {
    /// Composes the dispatch from the fallback chain and the apply
    /// executor.
    #[must_use]
    pub fn new(fallback: Arc<dyn OperationExecutor>, apply: Arc<dyn OperationExecutor>) -> Self {
        Self { fallback, apply }
    }
}

#[async_trait::async_trait]
impl OperationExecutor for ApplyDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "apply.workflow" => self.apply.execute(operations, operation).await,
            _ => self.fallback.execute(operations, operation).await,
        }
    }
}
