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
    /// The fact's availability.
    pub availability: ToolAvailability,
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
    /// Whether mise answered at all: `None`/`Some(false)` means the
    /// observation was unavailable (the honest `unknown` path for tool
    /// differences).
    pub mise_answered: Option<bool>,
    /// Whether the Skills Manager deployment status answered: `None`/
    /// `Some(false)` makes every desired skill an honest `unknown`.
    pub skills_answered: Option<bool>,
    /// Whether checkout discovery answered: `None`/`Some(false)` makes
    /// the desired checkout an honest `unknown`.
    pub checkouts_answered: Option<bool>,
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

/// An observed tool's availability, preserving the fact's own honesty: a
/// fact with `unknown` status means the probe did not answer, not that
/// the tool is absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolAvailability {
    /// The fact answered and the tool is present.
    Present,
    /// The fact answered and the tool is absent.
    Absent,
    /// The fact did not answer: the tool's state is unknown.
    Unknown,
}

/// Normalizes capability facts into observed tools with their
/// availability. A fact with `unknown` status preserves that honesty so
/// comparison can emit an `unknown` instead of an actionable absence.
/// Provider version output is canonicalized to the bare version so an
/// already-installed tool does not stay `changed` because of a prefix.
#[must_use]
pub fn normalize_tools(facts: &[fleet_core::CapabilityFact]) -> Vec<ObservedTool> {
    let mut tools: Vec<ObservedTool> = Vec::new();
    let mut versions: Vec<(String, String)> = Vec::new();
    for fact in facts {
        match (fact.namespace.as_str(), fact.name.as_str()) {
            ("tool", name) => {
                let availability = match fact.status {
                    fleet_core::CapabilityStatus::Known => ToolAvailability::Present,
                    fleet_core::CapabilityStatus::Unavailable => ToolAvailability::Absent,
                    // A stale or never-answered fact is an honest unknown.
                    fleet_core::CapabilityStatus::Unknown | fleet_core::CapabilityStatus::Stale => {
                        ToolAvailability::Unknown
                    }
                };
                if let Some(existing) = tools.iter_mut().find(|tool| tool.tool == name) {
                    existing.availability = availability;
                } else {
                    tools.push(ObservedTool {
                        tool: name.to_owned(),
                        version: None,
                        availability,
                    });
                }
            }
            ("tool-version", name) => {
                if let Some(version) = &fact.value {
                    versions.push((name.to_owned(), canonicalize_version(version)));
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
                availability: ToolAvailability::Present,
            });
        }
    }
    tools
}

/// Canonicalizes a provider's version output to the bare version: a
/// command-formatted line (`git version 2.43.0`, `mise 2026.1.2`) loses
/// its prefix, so an already-installed tool compares equal to its pin.
#[must_use]
pub fn canonicalize_version(raw: &str) -> String {
    let trimmed = raw.trim();
    let candidate = trimmed.rsplit(' ').next().unwrap_or(trimmed);
    // The last whitespace token must look like a version to be taken as
    // one; otherwise the whole trimmed line is the version.
    let looks_like_version = {
        let parts: Vec<&str> = candidate.split('.').collect();
        (2..=4).contains(&parts.len())
            && parts
                .iter()
                .all(|part| part.chars().next().is_some_and(|c| c.is_ascii_digit()))
    };
    if looks_like_version {
        candidate.to_owned()
    } else {
        trimmed.to_owned()
    }
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

impl ObservedState {
    /// Builds the observed state from its observations, setting every
    /// answered flag from whether the corresponding observation actually
    /// ran — the production composition path, so callers can never forget
    /// the flags and leave the planner refusing to act.
    #[must_use]
    pub fn from_observations(
        tools: Vec<ObservedTool>,
        skills: Vec<ObservedSkill>,
        checkouts: Vec<ObservedCheckout>,
        mise_ran: bool,
        skills_ran: bool,
        checkouts_ran: bool,
    ) -> Self {
        Self {
            tools,
            skills,
            checkouts,
            mise_answered: Some(mise_ran),
            skills_answered: Some(skills_ran),
            checkouts_answered: Some(checkouts_ran),
        }
    }
}

/// Compares the desired state against the observed state into a
/// difference set. Availability is honest end to end: an unanswered
/// inventory makes every desired tool an `unknown`; an unavailable
/// deployment status makes every desired skill an `unknown`; an
/// unanswered discovery makes the desired checkout an `unknown` (and a
/// known checkout with no readable remote is `unknown` too — cloning a
/// duplicate would be worse). Desired tool sets are additive, not
/// exclusive; observed-only skills and checkouts are `extra` so stale
/// deployments and abandoned checkouts can be undeployed or reported.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn compare(desired: &DesiredState, observed: &ObservedState) -> DifferenceSet {
    let mut set = DifferenceSet::new();

    // Tools: desired version vs observed version. When mise did not
    // answer, every desired tool is an honest `unknown` carrying its
    // desired value. A tool whose fact is unknown-status is `unknown` too.
    for (tool, desired_version) in &desired.tools {
        if observed.mise_answered != Some(true) {
            set.push(FieldDifference::unknown(
                &format!("tool:{}", fleet_core::redact_schemeless_credentials(tool)),
                Some(desired_version),
                "the tool inventory did not answer; the machine's tool state is unknown",
            ));
            continue;
        }
        let observed_tool = observed
            .tools
            .iter()
            .find(|observed| &observed.tool == tool);
        // Absent is handled before any version is read: an absent tool is
        // missing regardless of what version string the fact carried.
        if observed_tool.map(|observed| observed.availability) == Some(ToolAvailability::Absent) {
            set.push(FieldDifference::missing(
                &format!("tool:{}", fleet_core::redact_schemeless_credentials(tool)),
                desired_version,
            ));
            continue;
        }
        if observed_tool.map(|observed| observed.availability) == Some(ToolAvailability::Unknown) {
            set.push(FieldDifference::unknown(
                &format!("tool:{}", fleet_core::redact_schemeless_credentials(tool)),
                Some(desired_version),
                "the tool's fact did not answer; its state is unknown",
            ));
            continue;
        }
        let observed_version = observed_tool.and_then(|observed| observed.version.clone());
        if let Some(difference) = compare_field(
            &format!("tool:{}", fleet_core::redact_schemeless_credentials(tool)),
            Some(desired_version),
            observed_version.as_deref(),
        ) {
            set.push(difference);
        }
    }

    // Skills: desired (skill, agent) pairs vs observed pairs, in BOTH
    // directions — a deployment of a no-longer-desired skill is `extra`.
    if observed.skills_answered.is_none_or(|answered| !answered) {
        for (skill_id, agent) in &desired.skills {
            set.push(FieldDifference::unknown(
                &format!(
                    "skill:{}/{}",
                    fleet_core::redact_schemeless_credentials(skill_id),
                    fleet_core::redact_schemeless_credentials(agent)
                ),
                Some("deployed"),
                "the deployment status did not answer; the machine's skill state is unknown",
            ));
        }
    } else {
        for (skill_id, agent) in &desired.skills {
            let deployed = observed
                .skills
                .iter()
                .any(|observed| &observed.skill_id == skill_id && &observed.agent == agent);
            let identity = format!(
                "skill:{}/{}",
                fleet_core::redact_schemeless_credentials(skill_id),
                fleet_core::redact_schemeless_credentials(agent)
            );
            if !deployed {
                set.push(FieldDifference::missing(&identity, "deployed"));
            }
        }
        for observed_skill in &observed.skills {
            let desired_pair = desired.skills.iter().any(|(skill_id, agent)| {
                skill_id == &observed_skill.skill_id && agent == &observed_skill.agent
            });
            if !desired_pair {
                set.push(FieldDifference::extra(
                    &format!(
                        "skill:{}/{}",
                        fleet_core::redact_schemeless_credentials(&observed_skill.skill_id),
                        fleet_core::redact_schemeless_credentials(&observed_skill.agent)
                    ),
                    "deployed",
                ));
            }
        }
    }

    // Checkouts: the desired remote vs the observed checkouts' remotes,
    // in both directions. An unanswered discovery or a known checkout
    // with no readable remote is an honest `unknown` — cloning a
    // duplicate would be worse than reporting.
    if let Some((desired_remote, desired_root)) = &desired.checkout {
        if observed.checkouts_answered.is_none_or(|answered| !answered) {
            set.push(FieldDifference::unknown(
                &format!(
                    "checkout:{}",
                    fleet_core::redact_schemeless_credentials(desired_remote)
                ),
                Some(desired_root),
                "the checkout discovery did not answer; the machine's checkout state is unknown",
            ));
        } else {
            let matching = observed
                .checkouts
                .iter()
                .find(|checkout| checkout.remote.as_deref() == Some(desired_remote));
            if let Some(checkout) = matching {
                if let Some(difference) = compare_field(
                    &format!(
                        "checkout:{}",
                        fleet_core::redact_schemeless_credentials(desired_remote)
                    ),
                    Some(desired_root),
                    Some(&checkout.root),
                ) {
                    set.push(difference);
                }
            } else {
                let unknown_checkout = observed
                    .checkouts
                    .iter()
                    .any(|checkout| checkout.remote.is_none());
                if unknown_checkout {
                    set.push(FieldDifference::unknown(
                        &format!(
                            "checkout:{}",
                            fleet_core::redact_schemeless_credentials(desired_remote)
                        ),
                        Some(desired_root),
                        "a known checkout has no readable remote; whether it matches is unknown",
                    ));
                } else {
                    set.push(FieldDifference::missing(
                        &format!(
                            "checkout:{}",
                            fleet_core::redact_schemeless_credentials(desired_remote)
                        ),
                        desired_root,
                    ));
                }
            }
        }
    }

    // Observed checkouts with no desired remote are `extra` so abandoned
    // checkouts can be reported — regardless of whether a checkout is
    // desired at all.
    if observed.checkouts_answered == Some(true) {
        let desired_remote = desired.checkout.as_ref().map(|(remote, _)| remote);
        for checkout in &observed.checkouts {
            if let Some(remote) = &checkout.remote
                && desired_remote != Some(remote)
            {
                set.push(FieldDifference::extra(
                    &format!(
                        "checkout:{}",
                        fleet_core::redact_schemeless_credentials(remote)
                    ),
                    &checkout.root,
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
        CheckoutObservation, DesiredState, ObservedState, ObservedTool, ToolAvailability,
        canonicalize_version, compare, normalize_checkouts, normalize_skills, normalize_tools,
    };
    use fleet_core::{CapabilityFact, CapabilityStatus, DifferenceState, Timestamp};

    fn fact(
        namespace: &str,
        name: &str,
        status: CapabilityStatus,
        value: Option<&str>,
    ) -> CapabilityFact {
        CapabilityFact {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            value: value.map(std::borrow::ToOwned::to_owned),
            status,
            observed_at: Timestamp::from_unix_millis(1_000),
            source: "test/1".to_owned(),
        }
    }

    #[test]
    fn tool_facts_normalize_with_their_versions() {
        let facts = vec![
            fact("tool", "git", CapabilityStatus::Known, None),
            fact(
                "tool-version",
                "git",
                CapabilityStatus::Known,
                Some("git version 2.43.0"),
            ),
            fact("tool", "docker", CapabilityStatus::Known, None),
        ];
        let tools = normalize_tools(&facts);
        assert_eq!(tools.len(), 2);
        let git = tools.iter().find(|tool| tool.tool == "git").unwrap();
        assert_eq!(
            git.version.as_deref(),
            Some("2.43.0"),
            "the prefix is canonicalized away"
        );
        let docker = tools.iter().find(|tool| tool.tool == "docker").unwrap();
        assert_eq!(
            docker.version, None,
            "a present tool without a version is an honest gap"
        );
    }

    #[test]
    fn a_tool_version_fact_for_an_unlisted_tool_still_normalizes() {
        let facts = vec![fact(
            "tool-version",
            "mise",
            CapabilityStatus::Known,
            Some("mise 2026.1.2"),
        )];
        let tools = normalize_tools(&facts);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].tool, "mise");
        assert_eq!(tools[0].version.as_deref(), Some("2026.1.2"));
    }

    #[test]
    fn an_unknown_status_fact_preserves_its_honesty() {
        let facts = vec![fact("tool", "node", CapabilityStatus::Unknown, None)];
        let tools = normalize_tools(&facts);
        assert_eq!(tools[0].availability, ToolAvailability::Unknown);
    }

    #[test]
    fn a_stale_status_fact_is_an_honest_unknown() {
        let facts = vec![fact("tool", "node", CapabilityStatus::Stale, None)];
        let tools = normalize_tools(&facts);
        assert_eq!(tools[0].availability, ToolAvailability::Unknown);
    }

    #[test]
    fn version_canonicalization_handles_bare_versions_and_prose() {
        assert_eq!(canonicalize_version("git version 2.43.0"), "2.43.0");
        assert_eq!(canonicalize_version("mise 2026.1.2"), "2026.1.2");
        assert_eq!(canonicalize_version("20.11.0"), "20.11.0");
        assert_eq!(canonicalize_version("1.27.0"), "1.27.0");
    }

    #[test]
    fn checkouts_normalize_only_known_observations() {
        let checkouts = vec![
            CheckoutObservation {
                root: "/srv/repo".to_owned(),
                branch: Some("main".to_owned()),
                remote: Some("github.com/Frogbyte-io/fleet-manager".to_owned()),
                status: "known".to_owned(),
            },
            CheckoutObservation {
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
            tools: vec![ObservedTool {
                tool: "node".to_owned(),
                version: Some("18.0.0".to_owned()),
                availability: ToolAvailability::Present,
            }],
            skills: vec![],
            checkouts: vec![],
            mise_answered: Some(true),
            skills_answered: Some(true),
            checkouts_answered: Some(true),
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
    }

    #[test]
    fn a_stale_observed_tool_is_an_honest_unknown() {
        let desired = DesiredState {
            tools: vec![("node".to_owned(), "20.11.0".to_owned())],
            ..DesiredState::default()
        };
        let observed = ObservedState {
            tools: vec![ObservedTool {
                tool: "node".to_owned(),
                version: None,
                availability: ToolAvailability::Unknown,
            }],
            mise_answered: Some(true),
            ..ObservedState::default()
        };
        let set = compare(&desired, &observed);
        let node = set
            .fields
            .iter()
            .find(|field| field.identity == "tool:node")
            .unwrap();
        assert_eq!(node.state, DifferenceState::Unknown);
        assert_eq!(
            node.desired.as_deref(),
            Some("20.11.0"),
            "the desired value survives the unknown"
        );
        assert!(!node.actionable());
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
    fn an_unanswered_deployment_status_makes_skills_unknown() {
        let desired = DesiredState {
            skills: vec![("db".to_owned(), "claude_code".to_owned())],
            ..DesiredState::default()
        };
        let observed = ObservedState {
            skills_answered: None,
            ..ObservedState::default()
        };
        let set = compare(&desired, &observed);
        let skill = set
            .fields
            .iter()
            .find(|field| field.identity == "skill:db/claude_code")
            .unwrap();
        assert_eq!(skill.state, DifferenceState::Unknown);
        assert!(!skill.actionable());
    }

    #[test]
    fn an_unanswered_discovery_makes_the_checkout_unknown() {
        let desired = DesiredState {
            checkout: Some((
                "github.com/Frogbyte-io/fleet-manager".to_owned(),
                "/srv/repo".to_owned(),
            )),
            ..DesiredState::default()
        };
        let observed = ObservedState {
            checkouts_answered: None,
            ..ObservedState::default()
        };
        let set = compare(&desired, &observed);
        let checkout = set
            .fields
            .iter()
            .find(|field| field.identity.starts_with("checkout:"))
            .unwrap();
        assert_eq!(checkout.state, DifferenceState::Unknown);
    }

    #[test]
    fn a_known_checkout_with_no_readable_remote_is_unknown() {
        let desired = DesiredState {
            checkout: Some((
                "github.com/Frogbyte-io/fleet-manager".to_owned(),
                "/srv/repo".to_owned(),
            )),
            ..DesiredState::default()
        };
        let observed = ObservedState {
            checkouts: vec![super::ObservedCheckout {
                root: "/srv/maybe".to_owned(),
                remote: None,
                branch: Some("main".to_owned()),
            }],
            checkouts_answered: Some(true),
            ..ObservedState::default()
        };
        let set = compare(&desired, &observed);
        let checkout = set
            .fields
            .iter()
            .find(|field| field.identity.starts_with("checkout:"))
            .unwrap();
        assert_eq!(checkout.state, DifferenceState::Unknown);
        assert!(
            !checkout.actionable(),
            "cloning a duplicate would be worse than reporting"
        );
    }

    #[test]
    fn observed_only_skills_and_checkouts_are_extra() {
        let desired = DesiredState::default();
        let observed = ObservedState {
            skills: vec![super::ObservedSkill {
                skill_id: "stale".to_owned(),
                agent: "claude_code".to_owned(),
            }],
            checkouts: vec![super::ObservedCheckout {
                root: "/srv/abandoned".to_owned(),
                remote: Some("github.com/other/abandoned".to_owned()),
                branch: None,
            }],
            skills_answered: Some(true),
            checkouts_answered: Some(true),
            ..ObservedState::default()
        };
        let set = compare(&desired, &observed);
        let skill = set
            .fields
            .iter()
            .find(|field| field.identity == "skill:stale/claude_code")
            .unwrap();
        assert_eq!(skill.state, DifferenceState::Extra);
        let checkout = set
            .fields
            .iter()
            .find(|field| field.identity == "checkout:github.com/other/abandoned")
            .unwrap();
        assert_eq!(checkout.state, DifferenceState::Extra);
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
                availability: ToolAvailability::Present,
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
            skills_answered: Some(true),
            checkouts_answered: Some(true),
        };
        let set = compare(&desired, &observed);
        assert!(
            set.fields.is_empty(),
            "a converged machine has no differences: {:?}",
            set.fields
        );
    }
}
