//! Per-machine observed-state assembly (FM-406): the normalized
//! [`ObservedState`] the planner compares against, built from the stores
//! that already hold the observations.
//!
//! Assembly adds no comparison rules. It maps each store's freshness and
//! availability onto the answered flags and availability the FM-401
//! comparison already understands, so a stale, missing, or unsupported
//! observation is reported as such and never as absent-and-fine:
//!
//! - Tools come from the machine's `tool` / `tool-version` capability
//!   facts. A tool with any fact past the freshness window is `Unknown`,
//!   and the inventory counts as answered only when a fresh fact exists.
//! - Skills come from the latest Skills Manager snapshot: none or a stale
//!   one is `Stale`, an unreachable machine is `Offline`, and a fresh
//!   `Absent`/`Unsupported` snapshot passes through.
//! - Checkouts are the machine's project checkouts. Nothing is recorded
//!   when discovery finds nothing, so the desired checkout is `unknown`
//!   (not assumed missing) unless a fresh observation exists.
//! - Fleet catalog versions come from Fleet's own verified installation
//!   records (FM-411), kept only while the fresh skills snapshot still shows
//!   the skill deployed to that agent. The observation is answered only with
//!   a fresh, available snapshot and a readable record store; otherwise
//!   catalog differences stay `unknown` (or `unsupported`), never in-sync.
//!
//! The assembler is an internal composition step: callers authorize the
//! request (the planner does), the assembler only reads.
#![warn(missing_docs)]

use std::sync::Arc;

use fleet_core::{CapabilityFact, CapabilityStatus, CheckoutFact, Timestamp};

use crate::catalog_installs::{CatalogInstall, CatalogInstallPort, install_holds};
use crate::machine::{CAPABILITY_FRESHNESS_MS, Machine, MachinePort, MachineStatus};
use crate::observed::{
    CheckoutObservation, ObservedSkill, ObservedState, SkillsObservationAvailability,
    normalize_checkouts, normalize_tools,
};
use crate::operation::PortFailure;
use crate::project::{ProjectFilter, ProjectPort};
use crate::skills::{SKILLS_FRESHNESS_MS, SkillsAvailability, SkillsPort, SkillsSnapshot};

/// How long a checkout observation remains fresh.
pub const CHECKOUT_FRESHNESS_MS: i64 = 24 * 60 * 60 * 1000;

/// The projects are read in pages of this size.
const PROJECT_PAGE: u32 = 200;
/// A fleet with more projects than this many pages leaves the checkout
/// observation unanswered rather than partially read.
const MAX_PROJECT_PAGES: usize = 100;

/// One checkout observation with its project's normalized remote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckoutInput {
    /// The observed checkout.
    pub fact: CheckoutFact,
    /// The owning project's normalized remote.
    pub project_remote: String,
}

/// Assembles one machine's observed state from its stored observations at
/// `now` (epoch milliseconds).
#[must_use]
pub fn assemble_observed_state(
    machine: &Machine,
    skills: Option<&SkillsSnapshot>,
    checkouts: Option<&[CheckoutInput]>,
    installs: Option<&[CatalogInstall]>,
    now: i64,
) -> ObservedState {
    let (tool_facts, mise_ran) = tool_facts(&machine.capabilities, now);
    let (skill_pairs, availability) = skills_observation(machine, skills, now);
    let (observed_checkouts, checkouts_ran) = checkout_observations(checkouts, now);
    let (catalog_skills, catalog_answered) = catalog_observation(installs, skills, availability);
    ObservedState::from_observations_with_catalog_versions(
        normalize_tools(&tool_facts),
        skill_pairs,
        catalog_skills,
        observed_checkouts,
        mise_ran,
        availability,
        catalog_answered,
        checkouts_ran,
    )
}

/// The catalog versions Fleet installed and the fresh snapshot still
/// confirms, and whether that observation answered. Without a readable
/// record store, or without a fresh available snapshot to confirm the
/// records against, the version cannot be determined.
fn catalog_observation(
    installs: Option<&[CatalogInstall]>,
    snapshot: Option<&SkillsSnapshot>,
    availability: SkillsObservationAvailability,
) -> (Vec<(String, String, String)>, bool) {
    let (Some(installs), Some(snapshot), SkillsObservationAvailability::Available) =
        (installs, snapshot, availability)
    else {
        return (Vec::new(), false);
    };
    let confirmed = installs
        .iter()
        .filter(|install| install_holds(install, snapshot))
        .map(|install| {
            (
                install.catalog_id.clone(),
                install.version_id.clone(),
                install.agent.clone(),
            )
        })
        .collect();
    (confirmed, true)
}

/// The tool facts with the freshness rule applied, and whether the tool
/// inventory answered at all.
fn tool_facts(facts: &[CapabilityFact], now: i64) -> (Vec<CapabilityFact>, bool) {
    let at = Timestamp::from_unix_millis(now);
    let is_tool =
        |fact: &&CapabilityFact| matches!(fact.namespace.as_str(), "tool" | "tool-version");
    let effective = |fact: &CapabilityFact| fact.effective_status(at, CAPABILITY_FRESHNESS_MS);
    let mut stale_names = std::collections::BTreeSet::new();
    let mut answered = false;
    for fact in facts.iter().filter(is_tool) {
        if effective(fact) == CapabilityStatus::Stale {
            stale_names.insert(fact.name.clone());
        } else if effective(fact) != CapabilityStatus::Unknown {
            answered = true;
        }
    }
    let mut assembled: Vec<CapabilityFact> = facts
        .iter()
        .filter(is_tool)
        .filter(|fact| !stale_names.contains(&fact.name))
        .cloned()
        .collect();
    // A tool with any stale fact is one unknown fact: neither its
    // presence nor its version can be trusted.
    for name in stale_names {
        assembled.push(CapabilityFact {
            namespace: "tool".to_owned(),
            name,
            value: None,
            status: CapabilityStatus::Stale,
            observed_at: at,
            source: "assembly".to_owned(),
        });
    }
    (assembled, answered)
}

/// The skills observation and its availability for drift handling.
fn skills_observation(
    machine: &Machine,
    snapshot: Option<&SkillsSnapshot>,
    now: i64,
) -> (Vec<ObservedSkill>, SkillsObservationAvailability) {
    if MachineStatus::derive(machine.node.as_ref()) == MachineStatus::Offline {
        return (Vec::new(), SkillsObservationAvailability::Offline);
    }
    let Some(snapshot) = snapshot else {
        return (Vec::new(), SkillsObservationAvailability::Stale);
    };
    if now.saturating_sub(snapshot.observed_at) > SKILLS_FRESHNESS_MS {
        return (Vec::new(), SkillsObservationAvailability::Stale);
    }
    match snapshot.availability {
        SkillsAvailability::Absent => (Vec::new(), SkillsObservationAvailability::Absent),
        SkillsAvailability::Unsupported => (Vec::new(), SkillsObservationAvailability::Unsupported),
        SkillsAvailability::Available => {
            let mut pairs = Vec::new();
            for skill in snapshot
                .data
                .get("skills")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(id) = skill.get("id").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let agents: Vec<&str> = skill
                    .get("deployedTo")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                    .collect();
                pairs.extend(crate::observed::normalize_skills(id, &agents));
            }
            (pairs, SkillsObservationAvailability::Available)
        }
    }
}

/// The fresh checkouts, and whether the observation answered. `None`
/// means the checkouts could not be read at all.
fn checkout_observations(
    checkouts: Option<&[CheckoutInput]>,
    now: i64,
) -> (Vec<crate::observed::ObservedCheckout>, bool) {
    let Some(checkouts) = checkouts else {
        return (Vec::new(), false);
    };
    let observations: Vec<CheckoutObservation> = checkouts
        .iter()
        .filter(|input| now.saturating_sub(input.fact.observed_at) <= CHECKOUT_FRESHNESS_MS)
        .map(|input| CheckoutObservation {
            root: input.fact.root.clone(),
            remote: Some(input.project_remote.clone()),
            branch: input.fact.branch.clone(),
            status: "known".to_owned(),
        })
        .collect();
    let answered = !observations.is_empty();
    (normalize_checkouts(&observations), answered)
}

/// A failure to read the stores an observation is assembled from.
#[derive(Debug)]
pub enum ObservedAssemblyError {
    /// The machine does not exist.
    UnknownMachine,
    /// A store failed.
    Backend {
        /// Which store.
        context: &'static str,
        /// The failure detail.
        detail: String,
    },
}

impl std::fmt::Display for ObservedAssemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownMachine => write!(f, "the machine is not registered"),
            Self::Backend { context, detail } => {
                write!(f, "reading the {context} observations failed: {detail}")
            }
        }
    }
}

impl std::error::Error for ObservedAssemblyError {}

/// Gathers a machine's observations from the stores and assembles its
/// [`ObservedState`].
#[derive(Clone)]
pub struct ObservedStateAssembler {
    machines: Arc<dyn MachinePort>,
    skills: Arc<dyn SkillsPort>,
    projects: Arc<dyn ProjectPort>,
    installs: Option<Arc<dyn CatalogInstallPort>>,
}

impl ObservedStateAssembler {
    /// Composes the assembler from the stores it reads.
    #[must_use]
    pub fn new(
        machines: Arc<dyn MachinePort>,
        skills: Arc<dyn SkillsPort>,
        projects: Arc<dyn ProjectPort>,
    ) -> Self {
        Self {
            machines,
            skills,
            projects,
            installs: None,
        }
    }

    /// Adds Fleet's catalog installation records as the source of the
    /// installed catalog versions. Without it those stay `unknown`.
    #[must_use]
    pub fn with_catalog_installs(mut self, installs: Arc<dyn CatalogInstallPort>) -> Self {
        self.installs = Some(installs);
        self
    }

    /// Assembles the machine's observed state at `now`. A store that fails
    /// to answer fails the assembly: a partial read must not look like a
    /// clean machine.
    ///
    /// # Errors
    ///
    /// Fails for an unknown machine or a failing store.
    pub async fn assemble(
        &self,
        machine_id: &str,
        now: i64,
    ) -> Result<ObservedState, ObservedAssemblyError> {
        let backend = |context| {
            move |failure: PortFailure| ObservedAssemblyError::Backend {
                context,
                detail: match failure {
                    PortFailure::NotFound { what } => what,
                    PortFailure::Conflict { detail } | PortFailure::Backend { detail } => detail,
                },
            }
        };
        let machine = self.machines.get(machine_id).await.map_err(|failure| {
            if matches!(failure, PortFailure::NotFound { .. }) {
                ObservedAssemblyError::UnknownMachine
            } else {
                backend("machine")(failure)
            }
        })?;
        let snapshot = self
            .skills
            .get(machine_id)
            .await
            .map_err(backend("skills"))?;
        let checkouts = self.checkouts(machine_id).await?;
        let installs = match &self.installs {
            Some(port) => Some(
                port.list_installs(machine_id)
                    .await
                    .map_err(backend("catalog install"))?,
            ),
            None => None,
        };
        Ok(assemble_observed_state(
            &machine,
            snapshot.as_ref(),
            checkouts.as_deref(),
            installs.as_deref(),
            now,
        ))
    }

    /// The machine's checkouts across all projects, or `None` when the
    /// project list is too large to read completely.
    async fn checkouts(
        &self,
        machine_id: &str,
    ) -> Result<Option<Vec<CheckoutInput>>, ObservedAssemblyError> {
        let backend = |failure: PortFailure| ObservedAssemblyError::Backend {
            context: "checkout",
            detail: match failure {
                PortFailure::NotFound { what } => what,
                PortFailure::Conflict { detail } | PortFailure::Backend { detail } => detail,
            },
        };
        let mut inputs = Vec::new();
        let mut after_id = None;
        for _ in 0..MAX_PROJECT_PAGES {
            let page = self
                .projects
                .list(
                    &ProjectFilter {
                        after_id: after_id.clone(),
                        ..ProjectFilter::default()
                    },
                    PROJECT_PAGE,
                )
                .await
                .map_err(backend)?;
            let Some(last) = page.last() else {
                return Ok(Some(inputs));
            };
            after_id = Some(last.id.clone());
            for project in &page {
                for fact in self
                    .projects
                    .checkouts(&project.id)
                    .await
                    .map_err(backend)?
                {
                    if fact.machine_id == machine_id {
                        inputs.push(CheckoutInput {
                            fact,
                            project_remote: project.remote.clone(),
                        });
                    }
                }
            }
        }
        Ok(None)
    }
}

impl std::fmt::Debug for ObservedStateAssembler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservedStateAssembler")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{CheckoutInput, assemble_observed_state};
    use crate::catalog_installs::CatalogInstall;
    use crate::machine::{Machine, NodeLink};
    use crate::node::{GatewayState, NodeStatus};
    use crate::observed::{DesiredState, SkillsObservationAvailability, ToolAvailability, compare};
    use crate::skills::{SKILLS_FRESHNESS_MS, SkillsAvailability, SkillsSnapshot};
    use fleet_core::{CapabilityFact, CapabilityStatus, CheckoutFact, DifferenceState, Timestamp};

    const NOW: i64 = 10_000_000_000;
    const DAY: i64 = 24 * 60 * 60 * 1000;

    fn machine(capabilities: Vec<CapabilityFact>, node: Option<NodeLink>) -> Machine {
        Machine {
            id: "m-1".into(),
            name: "box".into(),
            description: String::new(),
            endpoints: vec![],
            tags: vec![],
            groups: vec![],
            capabilities,
            last_observation: None,
            node,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn fact(
        namespace: &str,
        name: &str,
        value: Option<&str>,
        status: CapabilityStatus,
        age: i64,
    ) -> CapabilityFact {
        CapabilityFact {
            namespace: namespace.into(),
            name: name.into(),
            value: value.map(str::to_owned),
            status,
            observed_at: Timestamp::from_unix_millis(NOW - age),
            source: "test".into(),
        }
    }

    fn snapshot(availability: SkillsAvailability, age: i64) -> SkillsSnapshot {
        SkillsSnapshot {
            machine_id: "m-1".into(),
            availability,
            cli_version: None,
            data: serde_json::json!({"skills": [
                {"id": "fleet", "deployedTo": ["codex"]},
                {"id": "extra", "deployedTo": []},
                {"noId": true},
            ]}),
            update_check: "ok".into(),
            observed_at: NOW - age,
        }
    }

    fn checkout(age: i64) -> CheckoutInput {
        CheckoutInput {
            fact: CheckoutFact {
                project_id: "p-1".into(),
                machine_id: "m-1".into(),
                root: "/srv/app".into(),
                branch: Some("main".into()),
                dirty: Some(false),
                source: "agentless/1".into(),
                observed_at: NOW - age,
            },
            project_remote: "github.com/acme/app".into(),
        }
    }

    fn node(status: NodeStatus, gateway: GatewayState) -> NodeLink {
        NodeLink {
            gateway_state: gateway,
            identity_status: status,
            last_seen_at: Some(NOW),
        }
    }

    #[test]
    fn fresh_tool_facts_answer_the_inventory_with_versions() {
        let m = machine(
            vec![
                fact("tool", "node", None, CapabilityStatus::Known, 1000),
                fact(
                    "tool-version",
                    "node",
                    Some("node 22.1.0"),
                    CapabilityStatus::Known,
                    1000,
                ),
                fact("tool", "go", None, CapabilityStatus::Unavailable, 1000),
                fact("os", "family", Some("linux"), CapabilityStatus::Known, 1000),
            ],
            None,
        );
        let observed = assemble_observed_state(&m, None, None, None, NOW);
        assert_eq!(observed.mise_answered, Some(true));
        let node = observed.tools.iter().find(|t| t.tool == "node").unwrap();
        assert_eq!(node.version.as_deref(), Some("22.1.0"));
        assert_eq!(node.availability, ToolAvailability::Present);
        let go = observed.tools.iter().find(|t| t.tool == "go").unwrap();
        assert_eq!(go.availability, ToolAvailability::Absent);
        assert!(observed.tools.iter().all(|t| t.tool != "family"));
    }

    #[test]
    fn a_stale_tool_is_unknown_and_all_stale_facts_leave_the_inventory_unanswered() {
        let stale = |name: &str| fact("tool", name, None, CapabilityStatus::Known, DAY + 1);
        let m = machine(
            vec![
                stale("node"),
                fact(
                    "tool-version",
                    "node",
                    Some("22.1.0"),
                    CapabilityStatus::Known,
                    DAY + 1,
                ),
                fact("tool", "go", None, CapabilityStatus::Known, 5),
            ],
            None,
        );
        let observed = assemble_observed_state(&m, None, None, None, NOW);
        assert_eq!(
            observed.mise_answered,
            Some(true),
            "the fresh go fact answered"
        );
        let node = observed.tools.iter().find(|t| t.tool == "node").unwrap();
        assert_eq!(node.availability, ToolAvailability::Unknown);
        assert_eq!(node.version, None, "a stale version is not trusted");

        let all_stale = machine(vec![stale("node")], None);
        assert_eq!(
            assemble_observed_state(&all_stale, None, None, None, NOW).mise_answered,
            Some(false)
        );
        let empty = machine(vec![], None);
        assert_eq!(
            assemble_observed_state(&empty, None, None, None, NOW).mise_answered,
            Some(false)
        );
    }

    #[test]
    fn skills_availability_follows_freshness_support_and_reachability() {
        let m = machine(vec![], None);
        let fresh = assemble_observed_state(
            &m,
            Some(&snapshot(SkillsAvailability::Available, 10)),
            None,
            None,
            NOW,
        );
        assert_eq!(
            fresh.skills_availability,
            Some(SkillsObservationAvailability::Available)
        );
        assert_eq!(fresh.skills_answered, Some(true));
        assert_eq!(
            fresh.skills.len(),
            1,
            "only deployed pairs, and entries without an id are skipped"
        );
        assert_eq!(fresh.skills[0].skill_id, "fleet");
        assert_eq!(
            fresh.catalog_skills_answered,
            Some(false),
            "no install records are supplied, so no catalog version is known"
        );

        let old = assemble_observed_state(
            &m,
            Some(&snapshot(
                SkillsAvailability::Available,
                SKILLS_FRESHNESS_MS + 1,
            )),
            None,
            None,
            NOW,
        );
        assert_eq!(
            old.skills_availability,
            Some(SkillsObservationAvailability::Stale)
        );
        assert!(old.skills.is_empty());
        let never = assemble_observed_state(&m, None, None, None, NOW);
        assert_eq!(
            never.skills_availability,
            Some(SkillsObservationAvailability::Stale)
        );
        for (availability, expected) in [
            (
                SkillsAvailability::Absent,
                SkillsObservationAvailability::Absent,
            ),
            (
                SkillsAvailability::Unsupported,
                SkillsObservationAvailability::Unsupported,
            ),
        ] {
            let observed =
                assemble_observed_state(&m, Some(&snapshot(availability, 10)), None, None, NOW);
            assert_eq!(observed.skills_availability, Some(expected));
        }
        let offline = machine(
            vec![],
            Some(node(NodeStatus::Active, GatewayState::Offline)),
        );
        let observed = assemble_observed_state(
            &offline,
            Some(&snapshot(SkillsAvailability::Available, 10)),
            None,
            None,
            NOW,
        );
        assert_eq!(
            observed.skills_availability,
            Some(SkillsObservationAvailability::Offline)
        );
        let revoked = machine(
            vec![],
            Some(node(NodeStatus::Revoked, GatewayState::Connected)),
        );
        assert_eq!(
            assemble_observed_state(&revoked, None, None, None, NOW).skills_availability,
            Some(SkillsObservationAvailability::Offline)
        );
    }

    #[test]
    fn checkouts_carry_the_project_remote_and_only_fresh_ones_answer() {
        let m = machine(vec![], None);
        let fresh = assemble_observed_state(&m, None, Some(&[checkout(10)]), None, NOW);
        assert_eq!(fresh.checkouts_answered, Some(true));
        assert_eq!(
            fresh.checkouts[0].remote.as_deref(),
            Some("github.com/acme/app")
        );
        assert_eq!(fresh.checkouts[0].root, "/srv/app");
        let stale = assemble_observed_state(&m, None, Some(&[checkout(DAY + 1)]), None, NOW);
        assert_eq!(stale.checkouts_answered, Some(false));
        assert!(stale.checkouts.is_empty());
        let none = assemble_observed_state(&m, None, Some(&[]), None, NOW);
        assert_eq!(
            none.checkouts_answered,
            Some(false),
            "nothing recorded is not a clean machine"
        );
        let unread = assemble_observed_state(&m, None, None, None, NOW);
        assert_eq!(unread.checkouts_answered, Some(false));
    }

    #[test]
    fn an_unobserved_machine_yields_unknowns_never_actionable_absences() {
        let m = machine(vec![], None);
        let observed = assemble_observed_state(&m, None, None, None, NOW);
        let desired = DesiredState {
            tools: vec![("node".into(), "22.1.0".into())],
            skills: vec![("fleet".into(), "codex".into())],
            catalog_skills: vec![],
            checkout: Some(("github.com/acme/app".into(), "/srv/app".into())),
        };
        let differences = compare(&desired, &observed);
        assert!(!differences.fields.is_empty());
        assert!(
            differences
                .fields
                .iter()
                .all(|f| f.state == DifferenceState::Unknown),
            "{differences:?}"
        );
    }

    fn install(agent: &str, skill: &str, age: i64) -> CatalogInstall {
        CatalogInstall {
            machine_id: "m-1".into(),
            catalog_id: "builtin-fleet".into(),
            version_id: "builtin-fleet@abc".into(),
            agent: agent.into(),
            skill_name: skill.into(),
            installed_at: NOW - age,
        }
    }

    fn catalog_tuple(agent: &str) -> (String, String, String) {
        (
            "builtin-fleet".into(),
            "builtin-fleet@abc".into(),
            agent.into(),
        )
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn catalog_versions_come_from_installs_the_fresh_snapshot_confirms() {
        let m = machine(vec![], None);
        let fresh = snapshot(SkillsAvailability::Available, 10);
        // (installs, snapshot, expected answered, expected tuples)
        let cases: Vec<(
            &str,
            Option<Vec<CatalogInstall>>,
            Option<SkillsSnapshot>,
            bool,
            Vec<_>,
        )> = vec![
            (
                "deployed skill",
                Some(vec![install("codex", "fleet", 100)]),
                Some(fresh.clone()),
                true,
                vec![catalog_tuple("codex")],
            ),
            (
                "undeployed from that agent",
                Some(vec![install("claude_code", "fleet", 100)]),
                Some(fresh.clone()),
                true,
                vec![],
            ),
            (
                "removed skill",
                Some(vec![install("codex", "gone", 100)]),
                Some(fresh.clone()),
                true,
                vec![],
            ),
            (
                "no records",
                Some(vec![]),
                Some(fresh.clone()),
                true,
                vec![],
            ),
            (
                "stale snapshot",
                Some(vec![install("codex", "fleet", 100)]),
                Some(snapshot(
                    SkillsAvailability::Available,
                    SKILLS_FRESHNESS_MS + 1,
                )),
                false,
                vec![],
            ),
            (
                "no snapshot",
                Some(vec![install("codex", "fleet", 100)]),
                None,
                false,
                vec![],
            ),
            (
                "unsupported cli",
                Some(vec![install("codex", "fleet", 100)]),
                Some(snapshot(SkillsAvailability::Unsupported, 10)),
                false,
                vec![],
            ),
            (
                "absent cli",
                Some(vec![install("codex", "fleet", 100)]),
                Some(snapshot(SkillsAvailability::Absent, 10)),
                false,
                vec![],
            ),
            ("no record store", None, Some(fresh.clone()), false, vec![]),
        ];
        for (name, installs, snapshot, answered, expected) in cases {
            let observed =
                assemble_observed_state(&m, snapshot.as_ref(), None, installs.as_deref(), NOW);
            assert_eq!(observed.catalog_skills_answered, Some(answered), "{name}");
            assert_eq!(observed.catalog_skills, expected, "{name}");
        }
    }

    #[test]
    fn an_offline_machine_leaves_catalog_versions_unanswered() {
        let offline = machine(
            vec![],
            Some(node(NodeStatus::Active, GatewayState::Offline)),
        );
        let observed = assemble_observed_state(
            &offline,
            Some(&snapshot(SkillsAvailability::Available, 10)),
            None,
            Some(&[install("codex", "fleet", 100)]),
            NOW,
        );
        assert_eq!(observed.catalog_skills_answered, Some(false));
    }

    #[test]
    fn catalog_versions_compare_as_in_sync_changed_missing_and_unknown() {
        let m = machine(vec![], None);
        let desired = |version: &str| DesiredState {
            catalog_skills: vec![("builtin-fleet".into(), version.into(), "codex".into())],
            ..DesiredState::default()
        };
        let fresh = snapshot(SkillsAvailability::Available, 10);
        let installs = [install("codex", "fleet", 100)];
        let observed = assemble_observed_state(&m, Some(&fresh), None, Some(&installs), NOW);
        assert!(
            compare(&desired("builtin-fleet@abc"), &observed)
                .fields
                .iter()
                .all(|d| !d.identity.starts_with("catalog-skill:")),
            "the pinned version installed is in sync"
        );
        let changed = compare(&desired("builtin-fleet@def"), &observed)
            .fields
            .remove(0);
        assert_eq!(changed.state, DifferenceState::Changed);
        let none = assemble_observed_state(&m, Some(&fresh), None, Some(&[]), NOW);
        let missing = compare(&desired("builtin-fleet@abc"), &none)
            .fields
            .remove(0);
        assert_eq!(missing.state, DifferenceState::Missing);
        let unread = assemble_observed_state(&m, Some(&fresh), None, None, NOW);
        let unknown = compare(&desired("builtin-fleet@abc"), &unread)
            .fields
            .remove(0);
        assert_eq!(unknown.state, DifferenceState::Unknown);
    }
}
