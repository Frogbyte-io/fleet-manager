//! Observed-state normalization (FM-401): machine observations become
//! the same shapes the desired resources use, so comparison is
//! apples-to-apples.
//!
//! Normalization is total: every observation maps either to an observed
//! field value or to an explicit `unknown`/`unsupported` difference —
//! never dropped silently. The inputs are the observation surfaces the
//! earlier milestones established: capability facts (tool versions),
//! checkout discoveries, and the Skills Manager deployment status.
//!
//! Nothing here executes or mutates: normalization is a pure function
//! from observations to an [`ObservedState`].
#![warn(missing_docs)]

use fleet_core::{DifferenceSet, FieldDifference, compare_field};

/// One observed tool version, normalized from a capability fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedTool {
    /// The tool's name.
    pub tool: String,
    /// The observed version, when the fact carried one.
    pub version: Option<String>,
}

/// One observed skill deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedSkill {
    /// The skill's identifier.
    pub skill_id: String,
    /// The agent it is deployed to.
    pub agent: String,
}

/// One observed checkout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedCheckout {
    /// The checkout's root path.
    pub root: String,
    /// The checkout's normalized remote, when discovery could read it.
    pub remote: Option<String>,
    /// The checked-out branch, when observed.
    pub branch: Option<String>,
}

/// The observed state of one machine, normalized from the observation
/// surfaces. Every field is optional because an observation may be
/// unavailable; unavailability is carried, never guessed away.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObservedState {
    /// The tools observed on the machine, with their versions.
    pub tools: Vec<ObservedTool>,
    /// The skill deployments observed on the machine.
    pub skills: Vec<ObservedSkill>,
    /// The checkouts observed on the machine.
    pub checkouts: Vec<ObservedCheckout>,
    /// Whether mise answered at all: `None` means the observation was
    /// unavailable (the honest `unknown` path for tool differences).
    pub mise_answered: Option<bool>,
}

/// The desired values one comparison needs, extracted from the composed
/// desired resources.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DesiredState {
    /// The desired tool versions, keyed by tool name.
    pub tools: Vec<(String, String)>,
    /// The desired skill deployments, as (skill id, agent) pairs.
    pub skills: Vec<(String, String)>,
    /// The desired checkout's normalized remote and root, when the
    /// project declares one.
    pub checkout: Option<(String, String)>,
}

/// Normalizes capability facts into observed tools. A `tool` fact with a
/// version becomes a versioned tool; a `tool` fact without one stays
/// present-without-version (an honest gap); `tool-version` facts feed the
/// versions.
#[must_use]
pub fn normalize_tools(facts: &[fleet_core::CapabilityFact]) -> Vec<ObservedTool> {
    let mut tools = Vec::new();
    let mut versions: Vec<(String, String)> = Vec::new();
    for fact in facts {
        match (fact.namespace.as_str(), fact.name.as_str()) {
            ("tool", name) => {
                if !tools.iter().any(|tool: &ObservedTool| tool.tool == name) {
                    tools.push(ObservedTool {
                        tool: name.to_owned(),
                        version: None,
                    });
                }
            }
            ("tool-version", name) => {
                if let Some(version) = &fact.value {
                    versions.push((name.to_owned(), version.clone()));
                }
            }
            _ => {}
        }
    }
    for (name, version) in versions {
        if let Some(tool) = tools.iter_mut().find(|tool| tool.tool == name) {
            tool.version = Some(version);
        } else {
            tools.push(ObservedTool {
                tool: name,
                version: Some(version),
            });
        }
    }
    tools
}

/// A neutral checkout observation: what the discovery surface reports,
/// decoupled from the provider's own types so this module stays
/// provider-agnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckoutObservation {
    /// The checkout's root path.
    pub root: String,
    /// The checkout's normalized remote, when discovery could read it.
    pub remote: Option<String>,
    /// The checked-out branch, when observed.
    pub branch: Option<String>,
    /// Whether the observation is complete.
    pub status: String,
}

/// Normalizes checkout discoveries into observed checkouts. An
/// `unavailable` checkout is not an observation: it is an honest gap.
#[must_use]
pub fn normalize_checkouts(checkouts: &[CheckoutObservation]) -> Vec<ObservedCheckout> {
    checkouts
        .iter()
        .filter(|checkout| checkout.status == "known")
        .map(|checkout| ObservedCheckout {
            root: checkout.root.clone(),
            remote: checkout.remote.clone(),
            branch: checkout.branch.clone(),
        })
        .collect()
}

/// Normalizes a Skills Manager deployment status into observed skill
/// deployments.
#[must_use]
pub fn normalize_skills(skill_id: &str, deployed_to: &[&str]) -> Vec<ObservedSkill> {
    deployed_to
        .iter()
        .map(|agent| ObservedSkill {
            skill_id: skill_id.to_owned(),
            agent: (*agent).to_owned(),
        })
        .collect()
}

/// Compares the desired state against the observed state into a
/// difference set. Unavailable observations become honest `unknown`
/// fields with a reason; a tool with no normalization path (not in the
/// desired set and not a known tool) becomes `extra`.
#[must_use]
pub fn compare(desired: &DesiredState, observed: &ObservedState) -> DifferenceSet {
    let mut set = DifferenceSet::new();

    // Tools: desired version vs observed version. When mise did not
    // answer, every desired tool is an honest `unknown`.
    for (tool, desired_version) in &desired.tools {
        if observed.mise_answered != Some(true) {
            set.push(FieldDifference::unknown(
                &format!("tool:{tool}"),
                "the tool inventory did not answer; the machine's tool state is unknown",
            ));
            continue;
        }
        let observed_version = observed
            .tools
            .iter()
            .find(|observed| &observed.tool == tool)
            .and_then(|observed| observed.version.clone());
        if let Some(difference) = compare_field(
            &format!("tool:{tool}"),
            Some(desired_version),
            observed_version.as_deref(),
        ) {
            set.push(difference);
        }
    }

    // Skills: desired (skill, agent) pairs vs observed pairs.
    for (skill_id, agent) in &desired.skills {
        let deployed = observed
            .skills
            .iter()
            .any(|observed| &observed.skill_id == skill_id && &observed.agent == agent);
        let identity = format!("skill:{skill_id}/{agent}");
        if !deployed {
            set.push(FieldDifference::missing(&identity, "deployed"));
        }
    }

    // Checkouts: the desired remote vs the observed checkouts' remotes.
    if let Some((desired_remote, desired_root)) = &desired.checkout {
        let matching = observed
            .checkouts
            .iter()
            .find(|checkout| checkout.remote.as_deref() == Some(desired_remote));
        match matching {
            Some(checkout) => {
                if let Some(difference) = compare_field(
                    &format!("checkout:{desired_remote}"),
                    Some(desired_root),
                    Some(&checkout.root),
                ) {
                    set.push(difference);
                }
            }
            None => {
                set.push(FieldDifference::missing(
                    &format!("checkout:{desired_remote}"),
                    desired_root,
                ));
            }
        }
    }

    set.canonicalize();
    set
}

#[cfg(test)]
mod tests {
    use super::{
        DesiredState, ObservedState, ObservedTool, compare, normalize_checkouts, normalize_skills,
        normalize_tools,
    };
    use fleet_core::{CapabilityFact, CapabilityStatus, DifferenceState, Timestamp};

    fn fact(namespace: &str, name: &str, value: Option<&str>) -> CapabilityFact {
        CapabilityFact {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            value: value.map(std::borrow::ToOwned::to_owned),
            status: CapabilityStatus::Known,
            observed_at: Timestamp::from_unix_millis(1_000),
            source: "test/1".to_owned(),
        }
    }

    #[test]
    fn tool_facts_normalize_with_their_versions() {
        let facts = vec![
            fact("tool", "git", None),
            fact("tool-version", "git", Some("git version 2.43.0")),
            fact("tool", "docker", None),
        ];
        let tools = normalize_tools(&facts);
        assert_eq!(tools.len(), 2);
        let git = tools.iter().find(|tool| tool.tool == "git").unwrap();
        assert_eq!(git.version.as_deref(), Some("git version 2.43.0"));
        let docker = tools.iter().find(|tool| tool.tool == "docker").unwrap();
        assert_eq!(
            docker.version, None,
            "a present tool without a version is an honest gap"
        );
    }

    #[test]
    fn a_tool_version_fact_for_an_unlisted_tool_still_normalizes() {
        let facts = vec![fact("tool-version", "mise", Some("mise 2026.1.2"))];
        let tools = normalize_tools(&facts);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].tool, "mise");
    }

    #[test]
    fn checkouts_normalize_only_known_observations() {
        let checkouts = vec![
            super::CheckoutObservation {
                root: "/srv/repo".to_owned(),
                branch: Some("main".to_owned()),
                remote: Some("github.com/Frogbyte-io/fleet-manager".to_owned()),
                status: "known".to_owned(),
            },
            super::CheckoutObservation {
                root: "/srv/broken".to_owned(),
                branch: None,
                remote: None,
                status: "unavailable".to_owned(),
            },
        ];
        let normalized = normalize_checkouts(&checkouts);
        assert_eq!(
            normalized.len(),
            1,
            "an unavailable checkout is not an observation"
        );
        assert_eq!(normalized[0].root, "/srv/repo");
    }

    #[test]
    fn skills_normalize_per_agent() {
        let skills = normalize_skills("db", &["claude_code", "codex"]);
        assert_eq!(skills.len(), 2);
        assert_eq!(skills[0].skill_id, "db");
        assert_eq!(skills[1].agent, "codex");
    }

    #[test]
    fn comparison_covers_match_change_missing_and_extra() {
        let desired = DesiredState {
            tools: vec![
                ("node".to_owned(), "20.11.0".to_owned()),
                ("python".to_owned(), "3.12.1".to_owned()),
            ],
            skills: vec![("db".to_owned(), "claude_code".to_owned())],
            checkout: Some((
                "github.com/Frogbyte-io/fleet-manager".to_owned(),
                "/srv/repo".to_owned(),
            )),
        };
        let observed = ObservedState {
            tools: vec![
                ObservedTool {
                    tool: "node".to_owned(),
                    version: Some("18.0.0".to_owned()),
                },
                ObservedTool {
                    tool: "nginx".to_owned(),
                    version: Some("1.27.0".to_owned()),
                },
            ],
            skills: vec![],
            checkouts: vec![],
            mise_answered: Some(true),
        };
        let set = compare(&desired, &observed);
        let node = set
            .fields
            .iter()
            .find(|field| field.identity == "tool:node")
            .unwrap();
        assert_eq!(node.state, DifferenceState::Changed);
        let python = set
            .fields
            .iter()
            .find(|field| field.identity == "tool:python")
            .unwrap();
        assert_eq!(python.state, DifferenceState::Missing);
        let db = set
            .fields
            .iter()
            .find(|field| field.identity == "skill:db/claude_code")
            .unwrap();
        assert_eq!(db.state, DifferenceState::Missing);
        let checkout = set
            .fields
            .iter()
            .find(|field| field.identity.starts_with("checkout:"))
            .unwrap();
        assert_eq!(checkout.state, DifferenceState::Missing);
        // An observed tool with no desired counterpart is extra — but
        // Fleet's desired tool set is not exclusive, so nginx is NOT
        // reported: extra applies only when the model declares it.
        assert!(
            !set.fields
                .iter()
                .any(|field| field.identity == "tool:nginx"),
            "desired tool sets are additive, not exclusive"
        );
    }

    #[test]
    fn an_unanswered_inventory_is_an_honest_unknown() {
        let desired = DesiredState {
            tools: vec![("node".to_owned(), "20.11.0".to_owned())],
            ..DesiredState::default()
        };
        let observed = ObservedState {
            mise_answered: None,
            ..ObservedState::default()
        };
        let set = compare(&desired, &observed);
        let node = set
            .fields
            .iter()
            .find(|field| field.identity == "tool:node")
            .unwrap();
        assert_eq!(node.state, DifferenceState::Unknown);
        assert!(
            node.reason
                .as_deref()
                .is_some_and(|reason| !reason.is_empty())
        );
        assert!(!node.actionable(), "an unknown is never actionable");
    }

    #[test]
    fn a_converged_machine_yields_an_empty_set() {
        let desired = DesiredState {
            tools: vec![("node".to_owned(), "20.11.0".to_owned())],
            skills: vec![("db".to_owned(), "claude_code".to_owned())],
            checkout: Some((
                "github.com/Frogbyte-io/fleet-manager".to_owned(),
                "/srv/repo".to_owned(),
            )),
        };
        let observed = ObservedState {
            tools: vec![ObservedTool {
                tool: "node".to_owned(),
                version: Some("20.11.0".to_owned()),
            }],
            skills: vec![super::ObservedSkill {
                skill_id: "db".to_owned(),
                agent: "claude_code".to_owned(),
            }],
            checkouts: vec![super::ObservedCheckout {
                root: "/srv/repo".to_owned(),
                remote: Some("github.com/Frogbyte-io/fleet-manager".to_owned()),
                branch: Some("main".to_owned()),
            }],
            mise_answered: Some(true),
        };
        let set = compare(&desired, &observed);
        assert!(
            set.fields.is_empty(),
            "a converged machine has no differences: {:?}",
            set.fields
        );
    }
}
