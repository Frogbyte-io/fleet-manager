//! The apply planner (FM-401): a pure function from a difference set to
//! dependency-ordered actions.
//!
//! The plan is a document, not a side effect: nothing here creates an
//! operation or touches a machine. Each planned action names the
//! operation kind and payload shape the FM-301..FM-304 executors
//! established, ordered by the dependency matrix — install before exec,
//! clone before everything project-scoped, skills after tools. `unknown`
//! and `unsupported` differences are never planned: the planner refuses
//! to act on what it does not know.
//!
//! The dry-run rendering is one serializer shared by the API, the web,
//! and `fleetctl --output json`, so the three surfaces cannot drift.
#![warn(missing_docs)]

use fleet_core::{DifferenceSet, DifferenceState, FieldDifference};
use serde::{Deserialize, Serialize};

/// One planned action: the operation kind, its payload shape, and the
/// difference it resolves.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedAction {
    /// The execution order, starting at 1.
    pub order: u32,
    /// The operation kind that resolves the difference.
    pub kind: String,
    /// The difference this action resolves.
    pub difference: FieldDifference,
    /// Why this action sits at this position in the plan.
    pub reason: String,
}

/// The complete plan for one machine: ordered actions plus the honest
/// states the planner refused to act on.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    /// The ordered actions.
    pub actions: Vec<PlannedAction>,
    /// The differences the planner refused to act on (`unknown` and
    /// `unsupported`), carried so the surfaces can report them.
    pub unactionable: Vec<FieldDifference>,
}

impl Plan {
    /// Whether the plan carries any action.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

/// The dependency ranks an action's kind maps to. Lower runs first.
fn rank(kind: &str) -> u8 {
    match kind {
        // The checkout is the root everything project-scoped sits in.
        "projects.clone" => 0,
        // Tools install before anything uses them.
        "mise.install" => 1,
        // Skills deploy after tools exist; Frogenv setup is independent
        // of tools/skills.
        "skills.deploy" | "frogenv.setup" => 2,
        // Exec uses the checkout and the tools.
        "mise.exec" => 3,
        // Everything else runs last.
        _ => 4,
    }
}

/// The operation kind that resolves one actionable difference, derived
/// from the difference's identity.
#[must_use]
fn resolving_kind(difference: &FieldDifference) -> Option<&'static str> {
    let identity = &difference.identity;
    if let Some(tool) = identity.strip_prefix("tool:") {
        let _ = tool;
        return Some("mise.install");
    }
    if let Some(rest) = identity.strip_prefix("skill:") {
        let skill_id = rest.split('/').next()?;
        let _ = skill_id;
        return Some("skills.deploy");
    }
    if identity.starts_with("checkout:") {
        return Some("projects.clone");
    }
    None
}

/// Plans the actions that resolve the actionable differences, in
/// dependency order. `unknown` and `unsupported` differences are carried
/// in the plan's `unactionable` list — reported, never acted on.
#[must_use]
pub fn plan(set: &DifferenceSet) -> Plan {
    let mut actionable: Vec<&FieldDifference> = set.actionable();
    // Stable ordering: dependency rank first, then identity, so the same
    // difference set always yields the same plan.
    actionable.sort_by(|a, b| {
        let rank_a = resolving_kind(a).map_or(u8::MAX, rank);
        let rank_b = resolving_kind(b).map_or(u8::MAX, rank);
        rank_a
            .cmp(&rank_b)
            .then_with(|| a.identity.cmp(&b.identity))
    });

    let mut actions = Vec::new();
    let mut unactionable = Vec::new();
    // The sorted actionable list drives the plan; the canonical set order
    // is only the input.
    let mut sorted_unactionable: Vec<&FieldDifference> = set
        .fields
        .iter()
        .filter(|difference| !difference.actionable())
        .collect();
    sorted_unactionable.sort_by(|a, b| a.identity.cmp(&b.identity));
    for difference in actionable {
        match difference.state {
            DifferenceState::Unknown | DifferenceState::Unsupported => {
                unactionable.push(difference.clone());
            }
            _ => {
                if let Some(kind) = resolving_kind(difference) {
                    actions.push(PlannedAction {
                        order: 0,
                        kind: kind.to_owned(),
                        difference: difference.clone(),
                        reason: reason_for(kind).to_owned(),
                    });
                }
            }
        }
    }
    for difference in sorted_unactionable {
        unactionable.push(difference.clone());
    }
    // Renumber contiguously: the order field is the plan's own sequence,
    // not the difference set's index.
    for (position, action) in actions.iter_mut().enumerate() {
        action.order = u32::try_from(position + 1).unwrap_or(u32::MAX);
    }
    Plan {
        actions,
        unactionable,
    }
}

fn reason_for(kind: &str) -> &'static str {
    match kind {
        "projects.clone" => "the checkout is the root every project-scoped step sits in",
        "mise.install" => "tools install before anything uses them",
        "skills.deploy" => "skills deploy after the tools they need exist",
        "frogenv.setup" => "the environment configures independently of tools",
        _ => "runs after its dependencies",
    }
}

/// The canonical dry-run rendering: one serializer shared by the API,
/// the web, and `fleetctl --output json`, so the surfaces cannot drift.
#[must_use]
pub fn render_dry_run(plan: &Plan) -> serde_json::Value {
    serde_json::to_value(plan).unwrap_or_else(|_| {
        serde_json::json!({
            "actions": [],
            "unactionable": [],
        })
    })
}

#[cfg(test)]
mod tests {
    use super::{plan, render_dry_run};
    use fleet_core::{DifferenceSet, FieldDifference};

    fn set_with(fields: Vec<FieldDifference>) -> DifferenceSet {
        let mut set = DifferenceSet::new();
        for field in fields {
            set.push(field);
        }
        set.canonicalize();
        set
    }

    #[test]
    fn a_fresh_machine_plans_in_dependency_order() {
        let set = set_with(vec![
            FieldDifference::missing("skill:db/claude_code", "deployed"),
            FieldDifference::missing("tool:node", "20.11.0"),
            FieldDifference::missing("checkout:github.com/x/y", "/srv/y"),
        ]);
        let plan = plan(&set);
        let kinds: Vec<&str> = plan
            .actions
            .iter()
            .map(|action| action.kind.as_str())
            .collect();
        assert_eq!(
            kinds,
            ["projects.clone", "mise.install", "skills.deploy"],
            "clone before install before skills"
        );
        assert!(plan.unactionable.is_empty());
    }

    #[test]
    fn the_plan_orders_are_contiguous_from_one() {
        let set = set_with(vec![
            FieldDifference::missing("skill:db/claude_code", "deployed"),
            FieldDifference::missing("tool:node", "20.11.0"),
        ]);
        let plan = plan(&set);
        let orders: Vec<u32> = plan.actions.iter().map(|action| action.order).collect();
        assert_eq!(orders, [1, 2]);
    }

    #[test]
    fn unknown_and_unsupported_are_never_planned() {
        let set = set_with(vec![
            FieldDifference::unknown("tool:node", "the inventory did not answer"),
            FieldDifference::unsupported("tool:exotic", "no path"),
            FieldDifference::missing("tool:git", "2.43.0"),
        ]);
        let plan = plan(&set);
        assert_eq!(plan.actions.len(), 1);
        assert_eq!(plan.actions[0].kind, "mise.install");
        assert_eq!(plan.unactionable.len(), 2);
        assert!(
            plan.unactionable
                .iter()
                .all(|difference| !difference.actionable()),
            "the unactionable list carries only honest states"
        );
    }

    #[test]
    fn a_converged_machine_yields_an_empty_plan() {
        let set = DifferenceSet::new();
        let plan = plan(&set);
        assert!(plan.is_empty());
        assert!(plan.unactionable.is_empty());
    }

    #[test]
    fn the_same_set_always_yields_the_same_plan() {
        let build = || {
            set_with(vec![
                FieldDifference::missing("tool:node", "20.11.0"),
                FieldDifference::missing("skill:db/claude_code", "deployed"),
                FieldDifference::extra("checkout:github.com/x/y", "/elsewhere"),
            ])
        };
        let first = plan(&build());
        let second = plan(&build());
        assert_eq!(first, second, "planning is a pure function");
    }

    #[test]
    fn the_dry_run_rendering_is_the_plan_itself() {
        let set = set_with(vec![FieldDifference::missing("tool:node", "20.11.0")]);
        let plan = plan(&set);
        let rendered = render_dry_run(&plan);
        assert_eq!(rendered["actions"][0]["kind"], "mise.install");
        assert_eq!(rendered["actions"][0]["order"], 1);
        // The rendering round-trips through the plan type: one serializer,
        // three surfaces.
        let back: super::Plan = serde_json::from_value(rendered).unwrap();
        assert_eq!(back, plan);
    }

    #[test]
    fn an_extra_checkout_plans_a_clone() {
        let set = set_with(vec![FieldDifference::extra(
            "checkout:github.com/x/y",
            "/elsewhere",
        )]);
        let plan = plan(&set);
        assert_eq!(plan.actions[0].kind, "projects.clone");
    }
}
