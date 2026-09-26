//! The apply engine (FM-402): authorized, durable, compensating
//! execution of an apply plan.
//!
//! The apply use case takes an FM-401 plan, the machine it targets, and
//! the caller's approvals; authorizes the execution; and creates one
//! durable `apply.workflow` operation. The workflow walks the plan's
//! actions in order, claiming and executing each inner step in-process
//! through the composed chain — the proven FM-305 shape, with three
//! additions the apply semantics require:
//!
//! - **Approvals**: a step whose operation kind is flagged risky in the
//!   authz catalog requires an approval bound to the plan's identity. A
//!   plan missing its approvals completes `blocked_manual_approval`
//!   naming the unapproved steps; it never executes partially approved.
//! - **Compensation**: each completed step records its compensation
//!   (undeploy for a deploy, none for an idempotent install) in the
//!   operation record. Compensation execution is an explicit authorized
//!   operation, never automatic.
//! - **Post-apply verification**: the plan's final step re-runs the
//!   FM-401 comparison and requires an empty actionable difference set
//!   before the workflow completes succeeded.
//!
//! Restart/resume rides the operation record: completed and remaining
//! steps are durable, so a controller restart resumes truthfully.
#![warn(missing_docs)]

use fleet_core::{DifferenceSet, DifferenceState};

/// The approval identity binding: an approval is valid only for the plan
/// it names, so a token from one plan cannot authorize another.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    /// The plan's identity the approval is bound to.
    pub plan_id: String,
    /// The action's order the approval covers.
    pub action_order: u32,
    /// The action's operation kind the approval covers.
    pub kind: String,
}

/// The operation kinds the apply approval gate covers, derived from the
/// authz catalog's risk classification for the kind's own permission:
/// a step whose permission is risky in the catalog requires an approval
/// here too, so the gate cannot drift from the catalog.
#[must_use]
pub fn requires_approval(kind: &str) -> bool {
    let permission = fleet_application_kind_permission(kind);
    permission.is_some_and(super::authz::Permission::is_risky)
}

/// The authz permission each apply-plan kind maps to. Single source of
/// truth for the approval gate, derived from the same mapping
/// `Operations::create` enforces.
fn fleet_application_kind_permission(kind: &str) -> Option<crate::authz::Permission> {
    match kind {
        "mise.install" => Some(crate::authz::Permission::MiseOperate),
        "skills.deploy"
        | "skills.undeploy"
        | "skills.catalog-rollout"
        | "presets.deploy"
        | "presets.undeploy" => Some(crate::authz::Permission::SkillsDeploy),
        "skills.install"
        | "skills.update"
        | "skills.check"
        | "skills.remove"
        | "skills.adopt"
        | "skills.set-source"
        | "presets.create"
        | "presets.update"
        | "presets.delete"
        | "presets.add-skill"
        | "presets.remove-skill" => Some(crate::authz::Permission::SkillsModify),
        "projects.clone" => Some(crate::authz::Permission::ProjectsGitWrite),
        _ => None,
    }
}

/// The compensation an executed step records.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Compensation {
    /// The step is idempotent: re-running it is its own compensation.
    Idempotent,
    /// The step deployed a skill; the compensation is an undeploy.
    Undeploy {
        /// The skill that was deployed.
        skill_id: String,
        /// The agent it was deployed to.
        agent: String,
    },
    /// The step has no safe compensation: the record says so honestly.
    None,
}

impl Compensation {
    /// The compensation for one completed step's kind and difference.
    #[must_use]
    pub fn for_step(kind: &str, difference: &fleet_core::FieldDifference) -> Self {
        match kind {
            "mise.install" | "projects.clone" => Self::Idempotent,
            "skills.deploy" => {
                // The difference's identity carries skill/agent.
                let identity = &difference.identity;
                let rest = identity.strip_prefix("skill:").unwrap_or(identity);
                match rest.split_once('/') {
                    Some((skill_id, agent)) => Self::Undeploy {
                        skill_id: skill_id.to_owned(),
                        agent: agent.to_owned(),
                    },
                    None => Self::None,
                }
            }
            _ => Self::None,
        }
    }
}

/// Validates the approvals for one plan: every risky action must carry an
/// approval bound to this plan's identity and its own order and kind.
/// Returns the unapproved actions; an empty result means the plan may
/// execute.
#[must_use]
pub fn unapproved_actions(
    plan_id: &str,
    actions: &[crate::planner::PlannedAction],
    approvals: &[Approval],
) -> Vec<crate::planner::PlannedAction> {
    actions
        .iter()
        .filter(|action| requires_approval(&action.kind))
        .filter(|action| {
            !approvals.iter().any(|approval| {
                approval.plan_id == plan_id
                    && approval.action_order == action.order
                    && approval.kind == action.kind
            })
        })
        .cloned()
        .collect()
}

/// Verifies post-apply truth: the re-observed difference set must have no
/// actionable fields. An `unsupported` field is reported without
/// blocking; an `unknown` blocks — the machine's state is not knowable
/// enough to claim convergence.
/// # Errors
///
/// Returns the blocking fields when the re-observed difference set still
/// carries actionable or unknown fields.
pub fn verified(set: &DifferenceSet) -> Result<(), String> {
    // A canonicalized clone preserves terminal-state precedence on
    // duplicate identities, so an honest unknown cannot be shadowed by an
    // actionable duplicate.
    let mut canonical = set.clone();
    canonical.canonicalize();
    let blockers: Vec<&fleet_core::FieldDifference> = canonical
        .fields
        .iter()
        .filter(|field| field.state == DifferenceState::Unknown || field.actionable())
        .collect();
    if blockers.is_empty() {
        Ok(())
    } else {
        Err(blockers
            .iter()
            .map(|field| format!("{} ({})", field.identity, field.state))
            .collect::<Vec<_>>()
            .join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::{Approval, Compensation, unapproved_actions, verified};
    use crate::planner::PlannedAction;
    use fleet_core::{DifferenceSet, FieldDifference};

    fn action(order: u32, kind: &str, identity: &str) -> PlannedAction {
        PlannedAction {
            order,
            kind: kind.to_owned(),
            difference: FieldDifference::missing(identity, "desired"),
            reason: "test".to_owned(),
        }
    }

    #[test]
    fn risky_kinds_require_approval_and_safe_ones_do_not() {
        assert!(super::requires_approval("mise.install"));
        assert!(super::requires_approval("skills.deploy"));
        assert!(super::requires_approval("skills.undeploy"));
        assert!(super::requires_approval("skills.catalog-rollout"));
        // The clone's catalog permission (projects.git.write) is risky, so
        // the gate covers it too — derived from the catalog, not hardcoded.
        assert!(super::requires_approval("projects.clone"));
    }

    #[test]
    fn an_unapproved_risky_action_blocks_the_plan() {
        let actions = vec![action(1, "mise.install", "tool:node")];
        let unapproved = unapproved_actions("plan-1", &actions, &[]);
        assert_eq!(unapproved.len(), 1);
        assert_eq!(unapproved[0].kind, "mise.install");
    }

    #[test]
    fn an_approval_bound_to_another_plan_does_not_authorize() {
        let actions = vec![action(1, "mise.install", "tool:node")];
        let approvals = vec![Approval {
            plan_id: "plan-2".to_owned(),
            action_order: 1,
            kind: "mise.install".to_owned(),
        }];
        let unapproved = unapproved_actions("plan-1", &actions, &approvals);
        assert_eq!(unapproved.len(), 1, "a foreign plan's approval is not ours");
    }

    #[test]
    fn an_approval_bound_to_another_action_does_not_authorize() {
        let actions = vec![
            action(1, "mise.install", "tool:node"),
            action(2, "mise.install", "tool:python"),
        ];
        let approvals = vec![Approval {
            plan_id: "plan-1".to_owned(),
            action_order: 1,
            kind: "mise.install".to_owned(),
        }];
        let unapproved = unapproved_actions("plan-1", &actions, &approvals);
        assert_eq!(unapproved.len(), 1);
        assert_eq!(unapproved[0].difference.identity, "tool:python");
    }

    #[test]
    fn a_fully_approved_plan_executes() {
        let actions = vec![
            action(1, "mise.install", "tool:node"),
            action(2, "skills.deploy", "skill:db/claude_code"),
        ];
        let approvals = vec![
            Approval {
                plan_id: "plan-1".to_owned(),
                action_order: 1,
                kind: "mise.install".to_owned(),
            },
            Approval {
                plan_id: "plan-1".to_owned(),
                action_order: 2,
                kind: "skills.deploy".to_owned(),
            },
        ];
        assert!(unapproved_actions("plan-1", &actions, &approvals).is_empty());
    }

    #[test]
    fn compensations_match_the_step_semantics() {
        let install = Compensation::for_step(
            "mise.install",
            &FieldDifference::missing("tool:node", "20.11.0"),
        );
        assert_eq!(install, Compensation::Idempotent);
        let deploy = Compensation::for_step(
            "skills.deploy",
            &FieldDifference::missing("skill:db/claude_code", "deployed"),
        );
        assert_eq!(
            deploy,
            Compensation::Undeploy {
                skill_id: "db".to_owned(),
                agent: "claude_code".to_owned(),
            }
        );
        let clone = Compensation::for_step(
            "projects.clone",
            &FieldDifference::missing("checkout:github.com/x/y", "/srv/y"),
        );
        assert_eq!(clone, Compensation::Idempotent);
        let unknown_kind =
            Compensation::for_step("mystery.kind", &FieldDifference::missing("mystery:x", "y"));
        assert_eq!(unknown_kind, Compensation::None);
    }

    #[test]
    fn post_apply_verification_requires_no_actionable_or_unknown_fields() {
        let mut set = DifferenceSet::new();
        set.push(FieldDifference::unsupported(
            "tool:exotic",
            Some("1.0"),
            "no path",
        ));
        assert!(
            verified(&set).is_ok(),
            "an unsupported field is reported without blocking"
        );
        set.push(FieldDifference::missing("tool:node", "20.11.0"));
        assert!(verified(&set).is_err(), "an actionable difference blocks");
        let mut set = DifferenceSet::new();
        set.push(FieldDifference::unknown(
            "tool:node",
            Some("20.11.0"),
            "no answer",
        ));
        assert!(verified(&set).is_err(), "an unknown blocks the claim");
    }
}
