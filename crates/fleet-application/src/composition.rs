//! Deterministic profile composition (FM-400): the resolved requirements
//! of a desired-state collection, with provenance for every field.
//!
//! Composition is a pure function of the resource set: profiles apply in
//! a documented order (extends first, depth-first, then the profile's own
//! requirements), set-valued requirements carry stable identity with
//! explicit deny-wins-over-include semantics, and conflicting scalar
//! requirements are rejected — never last-write-wins. Cycles and
//! unresolved references fail with stable diagnostics.
//!
//! Every resolved value records which resource and path contributed it,
//! so the UI can explain why something is desired.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One composed requirement in the resolved profile: the requirement plus
/// the provenance of the profile that contributed it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComposedRequirement {
    /// The requirement itself.
    pub requirement: RequirementValue,
    /// Which profile contributed it, and where in that profile it sits.
    pub provenance: ProvenanceRecord,
}

/// The resolved value of one requirement, keyed for identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "type"
)]
pub enum RequirementValue {
    /// A pinned tool version.
    Tool {
        /// The tool's name.
        tool: String,
        /// The pinned version.
        version: String,
    },
    /// A skill deployment.
    Skill {
        /// The skill's identifier.
        skill_id: String,
        /// The agents the skill deploys to. Deny operates at the whole-
        /// requirement level: a denied skill is removed entirely.
        deploy_to: Vec<String>,
    },
    /// A capability requirement.
    Capability {
        /// The capability's namespace.
        namespace: String,
        /// The capability's name.
        name: String,
    },
}

/// Percent-encodes the identity delimiters so a component containing
/// `:` or `/` cannot collide with another requirement's key.
fn escape_identity(component: &str) -> String {
    component
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}

impl RequirementValue {
    /// The requirement's stable identity key: the same key from two
    /// resources is the same requirement, and a conflict is a rejection —
    /// never last-write-wins.
    #[must_use]
    pub fn identity(&self) -> String {
        match self {
            Self::Tool { tool, .. } => format!("tool:{}", escape_identity(tool)),
            Self::Skill { skill_id, .. } => {
                format!("skill:{}", escape_identity(skill_id))
            }
            Self::Capability { namespace, name } => format!(
                "capability:{}%2F{}",
                escape_identity(namespace),
                escape_identity(name)
            ),
        }
    }
}

/// The provenance of one composed value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvenanceRecord {
    /// The contributing resource's metadata.id.
    pub resource_id: String,
    /// The contributing resource's metadata.name.
    pub resource_name: String,
    /// The path within the resource the value came from.
    pub path: String,
}

/// A profile resource as composition sees it: identity plus the spec.
#[derive(Clone, Debug)]
pub struct ProfileResource {
    /// The profile's metadata.id.
    pub id: String,
    /// The profile's metadata.name.
    pub name: String,
    /// The profiles this profile extends, in application order.
    pub extends: Vec<String>,
    /// The requirements this profile contributes.
    pub requirements: Vec<RequirementValue>,
    /// The requirement identities this profile denies: deny wins over
    /// include, always.
    pub deny: Vec<String>,
}

/// A composition failure: stable diagnostics, never a guess.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompositionError {
    /// A profile's `extends` chain cycles.
    Cycle {
        /// The chain that cycled, in order.
        chain: Vec<String>,
    },
    /// A profile extends or references an unknown profile.
    UnknownProfile {
        /// The name that does not resolve.
        name: String,
        /// The profile that referenced it, when the reference did not
        /// come from the composition root.
        referenced_by: Option<String>,
    },
    /// Two profiles require different values for the same identity.
    Conflict {
        /// The requirement identity in conflict.
        identity: String,
        /// The first contributing profile.
        first: String,
        /// The second contributing profile.
        second: String,
    },
}

impl std::fmt::Display for CompositionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cycle { chain } => {
                write!(formatter, "profile extends cycle: {}", chain.join(" -> "))
            }
            Self::UnknownProfile {
                name,
                referenced_by,
            } => match referenced_by {
                Some(referenced_by) => write!(
                    formatter,
                    "unknown profile {name:?} referenced by {referenced_by:?}"
                ),
                None => write!(formatter, "unknown profile {name:?}"),
            },
            Self::Conflict {
                identity,
                first,
                second,
            } => write!(
                formatter,
                "conflicting requirement {identity}: {first:?} and {second:?} require different values"
            ),
        }
    }
}

impl std::error::Error for CompositionError {}

/// The composed result: requirements keyed by identity with provenance.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComposedProfile {
    /// The composed requirements, keyed by stable identity.
    pub requirements: BTreeMap<String, ComposedRequirement>,
}

/// Composes one profile's requirements: extends chains resolve
/// depth-first with cycle refusal, deny wins over include, and a scalar
/// conflict between two profiles is a rejection — never last-write-wins.
///
/// # Errors
///
/// Fails on a cycle, an unknown reference, or a conflicting requirement.
pub fn compose_profile(
    name: &str,
    profiles: &BTreeMap<String, ProfileResource>,
) -> Result<ComposedProfile, CompositionError> {
    let mut composed = ComposedProfile::default();
    let mut visiting = Vec::new();
    let mut denied = std::collections::BTreeSet::new();
    compose_into(name, profiles, &mut composed, &mut visiting, &mut denied)?;
    Ok(composed)
}

fn compose_into(
    name: &str,
    profiles: &BTreeMap<String, ProfileResource>,
    composed: &mut ComposedProfile,
    visiting: &mut Vec<String>,
    denied: &mut std::collections::BTreeSet<String>,
) -> Result<(), CompositionError> {
    if visiting.contains(&name.to_owned()) {
        let mut chain = visiting.clone();
        chain.push(name.to_owned());
        // Trim to the actual cycle for a readable diagnostic.
        let start = chain
            .iter()
            .position(|entry| entry == name)
            .unwrap_or_default();
        return Err(CompositionError::Cycle {
            chain: chain[start..].to_vec(),
        });
    }
    let Some(profile) = profiles.get(name) else {
        return Err(CompositionError::UnknownProfile {
            name: name.to_owned(),
            referenced_by: visiting.last().cloned(),
        });
    };
    visiting.push(name.to_owned());

    // Extends resolve depth-first: the parents' requirements compose
    // before this profile's own.
    for parent in &profile.extends {
        compose_into(parent, profiles, composed, visiting, denied)?;
    }

    // Deny is carried through the whole traversal: a denied identity
    // stays denied no matter which later profile re-includes it, making
    // the result independent of branch order.
    for identity in &profile.deny {
        denied.insert(identity.clone());
    }

    for (index, requirement) in profile.requirements.iter().enumerate() {
        let mut requirement = requirement.clone();
        if let RequirementValue::Skill { deploy_to, .. } = &mut requirement {
            // The agent set is canonicalized: two skill requirements with
            // the same agents in a different order are the same
            // requirement, not a conflict.
            deploy_to.sort();
            deploy_to.dedup();
        }
        let identity = requirement.identity();
        if denied.contains(&identity) {
            continue;
        }
        match composed.requirements.get(&identity) {
            Some(existing) if existing.requirement != requirement => {
                return Err(CompositionError::Conflict {
                    identity,
                    first: existing.provenance.resource_name.clone(),
                    second: profile.name.clone(),
                });
            }
            Some(_) => {}
            None => {
                composed.requirements.insert(
                    identity,
                    ComposedRequirement {
                        requirement,
                        provenance: ProvenanceRecord {
                            resource_id: profile.id.clone(),
                            resource_name: profile.name.clone(),
                            path: format!("/spec/requirements/{index}"),
                        },
                    },
                );
            }
        }
    }

    // The accumulated deny set filters the composed result after ALL
    // includes, so a later include cannot reintroduce a denied identity.
    composed
        .requirements
        .retain(|identity, _| !denied.contains(identity));

    visiting.pop();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ComposedProfile, CompositionError, ProfileResource, RequirementValue, compose_profile,
    };
    use std::collections::BTreeMap;

    fn profile(
        name: &str,
        extends: &[&str],
        requirements: Vec<RequirementValue>,
        deny: &[&str],
    ) -> ProfileResource {
        ProfileResource {
            id: format!("01890f3e-9b4a-7cc2-98c3-d24e8f58f2{name:0>4}"),
            name: name.to_owned(),
            extends: extends.iter().map(|entry| (*entry).to_owned()).collect(),
            requirements,
            deny: deny.iter().map(|entry| (*entry).to_owned()).collect(),
        }
    }

    fn tool(name: &str, version: &str) -> RequirementValue {
        RequirementValue::Tool {
            tool: name.to_owned(),
            version: version.to_owned(),
        }
    }

    fn skill(id: &str, agents: &[&str]) -> RequirementValue {
        RequirementValue::Skill {
            skill_id: id.to_owned(),
            deploy_to: agents.iter().map(|agent| (*agent).to_owned()).collect(),
        }
    }

    fn capability(namespace: &str, name: &str) -> RequirementValue {
        RequirementValue::Capability {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
        }
    }

    fn registry(entries: Vec<ProfileResource>) -> BTreeMap<String, ProfileResource> {
        entries
            .into_iter()
            .map(|profile| (profile.name.clone(), profile))
            .collect()
    }

    #[test]
    fn composition_is_deterministic_and_records_provenance() {
        let profiles = registry(vec![profile(
            "rust-dev",
            &[],
            vec![tool("node", "20.11.0")],
            &[],
        )]);
        let composed = compose_profile("rust-dev", &profiles).unwrap();
        let entry = &composed.requirements["tool:node"];
        assert_eq!(entry.provenance.resource_name, "rust-dev");
        assert_eq!(entry.provenance.path, "/spec/requirements/0");
        // The same input composes identically.
        let again = compose_profile("rust-dev", &profiles).unwrap();
        assert_eq!(composed, again);
    }

    #[test]
    fn extends_compose_depth_first() {
        let profiles = registry(vec![
            profile("base", &[], vec![tool("git", "2.43.0")], &[]),
            profile("rust-dev", &["base"], vec![tool("node", "20.11.0")], &[]),
        ]);
        let composed = compose_profile("rust-dev", &profiles).unwrap();
        assert_eq!(composed.requirements.len(), 2);
        assert_eq!(
            composed.requirements["tool:git"].provenance.resource_name,
            "base"
        );
        assert_eq!(
            composed.requirements["tool:node"].provenance.resource_name,
            "rust-dev"
        );
    }

    #[test]
    fn a_cycle_fails_with_the_chain() {
        let profiles = registry(vec![
            profile("a", &["b"], vec![], &[]),
            profile("b", &["a"], vec![], &[]),
        ]);
        let error = compose_profile("a", &profiles).unwrap_err();
        assert!(
            matches!(error, CompositionError::Cycle { ref chain } if chain.len() == 3),
            "{error}"
        );
    }

    #[test]
    fn an_unknown_reference_fails_with_both_names() {
        let profiles = registry(vec![profile("a", &["ghost"], vec![], &[])]);
        let error = compose_profile("a", &profiles).unwrap_err();
        assert!(
            matches!(error, CompositionError::UnknownProfile { ref name, ref referenced_by }
                if name == "ghost" && referenced_by.as_deref() == Some("a")),
            "{error}"
        );
    }

    #[test]
    fn a_conflicting_requirement_is_rejected_not_last_write_wins() {
        let profiles = registry(vec![
            profile("base", &[], vec![tool("node", "20.11.0")], &[]),
            profile("other", &[], vec![tool("node", "22.0.0")], &[]),
            profile("combined", &["base", "other"], vec![], &[]),
        ]);
        let error = compose_profile("combined", &profiles).unwrap_err();
        assert!(
            matches!(error, CompositionError::Conflict { ref identity, .. } if identity == "tool:node"),
            "{error}"
        );
    }

    #[test]
    fn an_identical_requirement_from_two_profiles_is_not_a_conflict() {
        let profiles = registry(vec![
            profile("base", &[], vec![tool("node", "20.11.0")], &[]),
            profile("other", &[], vec![tool("node", "20.11.0")], &[]),
            profile("combined", &["base", "other"], vec![], &[]),
        ]);
        let composed = compose_profile("combined", &profiles).unwrap();
        assert_eq!(composed.requirements.len(), 1);
    }

    #[test]
    fn deny_wins_over_include() {
        let profiles = registry(vec![
            profile("base", &[], vec![skill("db", &["claude_code"])], &[]),
            profile("trimmed", &["base"], vec![], &["skill:db"]),
        ]);
        let composed = compose_profile("trimmed", &profiles).unwrap();
        assert!(
            !composed.requirements.contains_key("skill:db"),
            "deny removes the requirement"
        );
    }

    #[test]
    fn a_later_include_cannot_reintroduce_a_denied_identity() {
        // Deny is carried through the whole traversal: the result is
        // independent of branch order.
        let profiles = registry(vec![
            profile("denier", &[], vec![], &["tool:node"]),
            profile("includer", &[], vec![tool("node", "20.11.0")], &[]),
            profile("combined", &["includer", "denier"], vec![], &[]),
        ]);
        let composed = compose_profile("combined", &profiles).unwrap();
        assert!(
            !composed.requirements.contains_key("tool:node"),
            "deny survives a later include"
        );
        // The mirror order composes identically.
        let mirrored = registry(vec![
            profile("denier", &[], vec![], &["tool:node"]),
            profile("includer", &[], vec![tool("node", "20.11.0")], &[]),
            profile("combined", &["denier", "includer"], vec![], &[]),
        ]);
        let composed_mirrored = compose_profile("combined", &mirrored).unwrap();
        assert_eq!(composed, composed_mirrored);
    }

    #[test]
    fn skill_requirements_compare_as_sets() {
        let profiles = registry(vec![
            profile(
                "base",
                &[],
                vec![skill("db", &["claude_code", "codex"])],
                &[],
            ),
            profile(
                "other",
                &[],
                vec![skill("db", &["codex", "claude_code"])],
                &[],
            ),
            profile("combined", &["base", "other"], vec![], &[]),
        ]);
        let composed = compose_profile("combined", &profiles).unwrap();
        assert_eq!(
            composed.requirements.len(),
            1,
            "the same agent set in a different order is one requirement"
        );
    }

    #[test]
    fn a_profile_cannot_deny_its_own_requirement_into_existence() {
        // Denying an identity the same profile also contributes removes
        // it: deny is unconditional.
        let profiles = registry(vec![profile(
            "mixed",
            &[],
            vec![tool("node", "20.11.0")],
            &["tool:node"],
        )]);
        let composed = compose_profile("mixed", &profiles).unwrap();
        assert!(composed.requirements.is_empty());
    }

    #[test]
    fn capabilities_compose_with_their_own_identity() {
        let profiles = registry(vec![profile(
            "observing",
            &[],
            vec![capability("tool", "git")],
            &[],
        )]);
        let composed = compose_profile("observing", &profiles).unwrap();
        assert!(composed.requirements.contains_key("capability:tool%2Fgit"));
    }

    #[test]
    fn the_composed_result_is_serializable_for_the_api() {
        let profiles = registry(vec![profile(
            "rust-dev",
            &[],
            vec![skill("db", &["claude_code"])],
            &[],
        )]);
        let composed = compose_profile("rust-dev", &profiles).unwrap();
        let json = serde_json::to_string(&composed).unwrap();
        assert!(
            json.contains("skillId") && json.contains("deployTo"),
            "the composed payload matches the published camelCase contract: {json}"
        );
        let back: ComposedProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(composed, back);
    }
}
