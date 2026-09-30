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

use std::collections::{BTreeMap, BTreeSet};

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

/// The target selected by one Fleet-managed skill assignment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type", content = "value")]
pub enum SkillAssignmentScope {
    /// Assign to every current and future machine.
    All,
    /// Assign to machines in this group.
    Group(String),
    /// Assign to machines carrying this tag.
    Tag(String),
    /// Assign to this stable machine identity.
    Machine(String),
}

/// Fleet identity and selectors used to match skill assignments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineSkillTarget {
    /// The stable Fleet machine identity.
    pub machine_id: String,
    /// The machine's desired groups.
    pub groups: Vec<String>,
    /// The machine's desired tags.
    pub tags: Vec<String>,
}

/// One Fleet-managed assignment from a catalog skill to agents and scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillAssignment {
    /// The stable catalog or Skills Manager skill identity.
    pub skill_id: String,
    /// Agents receiving the skill.
    pub deploy_to: Vec<String>,
    /// Agents this assignment explicitly excludes; deny wins over include.
    pub deny_agents: Vec<String>,
    /// Catalog identity and immutable version when the assignment is
    /// backed by a Fleet catalog entry.
    pub catalog_version: Option<(String, String)>,
    /// The assignment's machine scope.
    pub scope: SkillAssignmentScope,
    /// The desired resource that contributed this assignment.
    pub provenance: ProvenanceRecord,
}

/// Deterministically composed skills for one machine with source provenance.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ComposedSkillAssignments {
    /// Skill/agent pairs to deploy.
    pub skills: Vec<(String, String)>,
    /// Catalog version/agent triples requiring an install or update.
    pub catalog_skills: Vec<(String, String, String)>,
    /// Provenance by stable `skill:<id>/<agent>` or
    /// `catalog-skill:<catalog_id>/<agent>` identity.
    pub provenance: BTreeMap<String, ProvenanceRecord>,
}

type ResolvedSkillAssignment = (String, String, ProvenanceRecord, Option<(String, String)>);

/// Assignment composition can fail on ambiguous IDs or conflicting pins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SkillAssignmentCompositionError {
    /// A value used in the slash-delimited stable identity contains `/`.
    InvalidIdentityComponent {
        /// Name of the invalid input component.
        component: &'static str,
    },
    /// Matching assignments for one catalog/agent pair pin different versions.
    ConflictingCatalogVersions {
        /// Stable catalog/agent identity in conflict.
        identity: String,
        /// The first pinned version in the input order.
        first_version: String,
        /// The incompatible version encountered next.
        second_version: String,
    },
}

/// A skill the controller ships and assigns to every machine by default
/// (the official `fleet` skill, FM-924).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltinSkillAssignment {
    /// The Skills Manager skill identity.
    pub skill_id: String,
    /// The reserved built-in catalog identity.
    pub catalog_id: String,
    /// The immutable version this controller release ships.
    pub catalog_version_id: String,
    /// The agents the implicit assignment deploys to.
    pub deploy_to: Vec<String>,
}

/// The agents a built-in skill deploys to when Fleet Git has not taken it
/// over. Fleet Git overrides this with its own `SkillPreset`.
pub const DEFAULT_BUILTIN_SKILL_AGENTS: &[&str] = &["claude_code", "codex"];

/// Adds each built-in skill's implicit global assignment, unless Fleet Git
/// already assigns that skill (by skill id or catalog id). Once Git names
/// the skill, Git owns it completely: its presets replace the default,
/// and a preset with no `deployTo` agents removes the skill everywhere.
/// The controller never writes Git, so a new release cannot re-add a
/// built-in skill that Git has removed.
#[must_use]
pub fn with_builtin_assignments(
    assignments: &[SkillAssignment],
    builtins: &[BuiltinSkillAssignment],
) -> Vec<SkillAssignment> {
    let mut out = assignments.to_vec();
    for builtin in builtins {
        let owned_by_git = assignments.iter().any(|assignment| {
            assignment.skill_id == builtin.skill_id
                || assignment
                    .catalog_version
                    .as_ref()
                    .is_some_and(|(catalog_id, _)| catalog_id == &builtin.catalog_id)
        });
        if owned_by_git {
            continue;
        }
        out.push(SkillAssignment {
            skill_id: builtin.skill_id.clone(),
            deploy_to: builtin.deploy_to.clone(),
            deny_agents: Vec::new(),
            catalog_version: Some((
                builtin.catalog_id.clone(),
                builtin.catalog_version_id.clone(),
            )),
            scope: SkillAssignmentScope::All,
            provenance: ProvenanceRecord {
                resource_id: format!("builtin:{}", builtin.catalog_id),
                resource_name: builtin.skill_id.clone(),
                path: "controller release default".to_owned(),
            },
        });
    }
    out
}

/// Composes global, group, tag, and machine assignments for one machine.
/// Duplicate skill/agent pairs collapse to one entry, choosing provenance
/// deterministically by resource name, id, and path.
///
/// # Errors
///
/// Returns a conflict for ambiguous slash-delimited IDs or incompatible
/// catalog versions assigned to the same catalog/agent pair.
pub fn compose_skill_assignments(
    target: &MachineSkillTarget,
    assignments: &[SkillAssignment],
) -> Result<ComposedSkillAssignments, SkillAssignmentCompositionError> {
    let applies = |scope: &SkillAssignmentScope| match scope {
        SkillAssignmentScope::All => true,
        SkillAssignmentScope::Group(group) => target.groups.contains(group),
        SkillAssignmentScope::Tag(tag) => target.tags.contains(tag),
        SkillAssignmentScope::Machine(machine_id) => machine_id == &target.machine_id,
    };
    let mut resolved: BTreeMap<String, ResolvedSkillAssignment> = BTreeMap::new();
    let mut denied = BTreeSet::new();
    for assignment in assignments
        .iter()
        .filter(|assignment| applies(&assignment.scope))
    {
        for agent in &assignment.deny_agents {
            denied.insert((assignment.skill_id.clone(), agent.clone()));
        }
    }
    for assignment in assignments
        .iter()
        .filter(|assignment| applies(&assignment.scope))
    {
        if assignment.skill_id.contains('/') {
            return Err(SkillAssignmentCompositionError::InvalidIdentityComponent {
                component: "skill id",
            });
        }
        for agent in &assignment.deploy_to {
            if agent.contains('/') {
                return Err(SkillAssignmentCompositionError::InvalidIdentityComponent {
                    component: "agent id",
                });
            }
            if assignment
                .catalog_version
                .as_ref()
                .is_some_and(|(catalog_id, version_id)| {
                    catalog_id.contains('/') || version_id.contains('/')
                })
            {
                return Err(SkillAssignmentCompositionError::InvalidIdentityComponent {
                    component: "catalog or version id",
                });
            }
            if denied.contains(&(assignment.skill_id.clone(), agent.clone())) {
                continue;
            }
            let identity = assignment.catalog_version.as_ref().map_or_else(
                || format!("skill:{}/{agent}", assignment.skill_id),
                |(catalog_id, _)| format!("catalog-skill:{catalog_id}/{agent}"),
            );
            let candidate = (
                assignment.skill_id.clone(),
                agent.clone(),
                assignment.provenance.clone(),
                assignment.catalog_version.clone(),
            );
            if let Some(existing) = resolved.get(&identity)
                && let (Some((_, first)), Some((_, second))) = (&existing.3, &candidate.3)
                && first != second
            {
                return Err(
                    SkillAssignmentCompositionError::ConflictingCatalogVersions {
                        identity,
                        first_version: first.clone(),
                        second_version: second.clone(),
                    },
                );
            }
            let replace = resolved
                .get(&identity)
                .is_none_or(|existing| provenance_key(&candidate.2) < provenance_key(&existing.2));
            if replace {
                resolved.insert(identity, candidate);
            }
        }
    }
    let mut result = ComposedSkillAssignments::default();
    for (identity, (skill_id, agent, provenance, catalog_version)) in resolved {
        if denied.contains(&(skill_id.clone(), agent.clone())) {
            continue;
        }
        if let Some((_, version_id)) = catalog_version {
            let catalog_id = identity
                .strip_prefix("catalog-skill:")
                .and_then(|identity| identity.split_once('/'))
                .map_or_else(String::new, |(catalog_id, _)| catalog_id.to_owned());
            result.catalog_skills.push((catalog_id, version_id, agent));
        } else {
            result.skills.push((skill_id, agent));
        }
        result.provenance.insert(identity, provenance);
    }
    Ok(result)
}

fn provenance_key(provenance: &ProvenanceRecord) -> (&str, &str, &str) {
    (
        &provenance.resource_name,
        &provenance.resource_id,
        &provenance.path,
    )
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
    /// A machine binds a project that does not exist.
    UnknownProject {
        /// The name that does not resolve.
        name: String,
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
            Self::UnknownProject { name } => write!(formatter, "unknown project {name:?}"),
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

/// A project resource as binding composition sees it (ADR 0014).
#[derive(Clone, Debug)]
pub struct ProjectResource {
    /// The project's metadata.id.
    pub id: String,
    /// The project's metadata.name.
    pub name: String,
    /// The project's normalized remote.
    pub remote: String,
    /// The checkout root; a project without one contributes no checkout.
    pub root: Option<String>,
    /// The tool versions the project declares.
    pub tools: Vec<(String, String)>,
}

/// What one machine's profile and project bindings ask of it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BoundDesired {
    /// Tool versions, sorted by tool name.
    pub tools: Vec<(String, String)>,
    /// Skill deployments as `(skill id, agents)`, sorted by skill id.
    pub skills: Vec<(String, Vec<String>)>,
    /// Checkouts as `(normalized remote, root)`, sorted by remote.
    pub checkouts: Vec<(String, String)>,
    /// Capability requirements as `(namespace, name)`, sorted. Report-only.
    pub capabilities: Vec<(String, String)>,
    /// Which resource contributed each value, by requirement identity
    /// (`tool:<name>`, `skill:<id>`, `checkout:<remote>`, `capability:..`).
    pub provenance: BTreeMap<String, ProvenanceRecord>,
}

/// The reserved name of the synthetic profile that roots a machine's
/// bindings. It contains a character no slug can, so it cannot collide.
const BINDING_ROOT: &str = "\u{0}machine-bindings";

/// Composes the profiles and projects a machine binds (ADR 0014).
///
/// The bound profiles compose as one synthetic profile that extends them
/// in binding order, so `extends`, deny-wins-over-include, and conflict
/// refusal apply across the whole binding exactly as they do within one
/// profile. Project tools and checkouts are added under the same rule:
/// an identical requirement is shared, a different one is a conflict, and
/// two projects may not claim one remote at different roots or one root
/// for different remotes. Output is sorted and independent of binding
/// order.
///
/// # Errors
///
/// Fails on an unknown profile or project, a profile cycle, or a conflict.
#[allow(clippy::too_many_lines)]
pub fn compose_binding(
    profile_names: &[String],
    project_names: &[String],
    profiles: &BTreeMap<String, ProfileResource>,
    projects: &BTreeMap<String, ProjectResource>,
) -> Result<BoundDesired, CompositionError> {
    let mut out = BoundDesired::default();
    let mut tools: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut skills: BTreeMap<String, Vec<String>> = BTreeMap::new();

    if !profile_names.is_empty() {
        let mut scoped = profiles.clone();
        scoped.insert(
            BINDING_ROOT.to_owned(),
            ProfileResource {
                id: String::new(),
                name: BINDING_ROOT.to_owned(),
                extends: profile_names.to_vec(),
                requirements: Vec::new(),
                deny: Vec::new(),
            },
        );
        let composed = compose_profile(BINDING_ROOT, &scoped)?;
        for (identity, entry) in composed.requirements {
            match entry.requirement {
                RequirementValue::Tool { tool, version } => {
                    tools.insert(tool, (version, entry.provenance.resource_name.clone()));
                }
                RequirementValue::Skill {
                    skill_id,
                    deploy_to,
                } => {
                    skills.insert(skill_id, deploy_to);
                }
                RequirementValue::Capability { namespace, name } => {
                    out.capabilities.push((namespace, name));
                }
            }
            out.provenance.insert(identity, entry.provenance);
        }
    }

    // Projects, in name order so the first contributor is deterministic.
    let mut names: Vec<&String> = project_names.iter().collect();
    names.sort();
    names.dedup();
    let mut roots: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut checkouts: BTreeMap<String, (String, String)> = BTreeMap::new();
    for name in names {
        let project = projects
            .get(name)
            .ok_or_else(|| CompositionError::UnknownProject { name: name.clone() })?;
        let provenance = |path: String| ProvenanceRecord {
            resource_id: project.id.clone(),
            resource_name: project.name.clone(),
            path,
        };
        for (index, (tool, version)) in project.tools.iter().enumerate() {
            match tools.get(tool) {
                Some((existing, owner)) if existing != version => {
                    return Err(CompositionError::Conflict {
                        identity: format!("tool:{}", escape_identity(tool)),
                        first: owner.clone(),
                        second: project.name.clone(),
                    });
                }
                Some(_) => {}
                None => {
                    tools.insert(tool.clone(), (version.clone(), project.name.clone()));
                    out.provenance.insert(
                        format!("tool:{}", escape_identity(tool)),
                        provenance(format!("/spec/tools/{index}")),
                    );
                }
            }
        }
        let Some(root) = &project.root else { continue };
        let identity = format!("checkout:{}", project.remote);
        match checkouts.get(&project.remote) {
            Some((existing_root, owner)) if existing_root != root => {
                return Err(CompositionError::Conflict {
                    identity,
                    first: owner.clone(),
                    second: project.name.clone(),
                });
            }
            Some(_) => continue,
            None => {}
        }
        if let Some((other_remote, owner)) = roots.get(root)
            && other_remote != &project.remote
        {
            return Err(CompositionError::Conflict {
                identity: format!("checkout-root:{root}"),
                first: owner.clone(),
                second: project.name.clone(),
            });
        }
        checkouts.insert(project.remote.clone(), (root.clone(), project.name.clone()));
        roots.insert(root.clone(), (project.remote.clone(), project.name.clone()));
        out.provenance
            .insert(identity, provenance("/spec/root".to_owned()));
    }

    out.tools = tools
        .into_iter()
        .map(|(tool, (version, _))| (tool, version))
        .collect();
    out.skills = skills.into_iter().collect();
    out.checkouts = checkouts
        .into_iter()
        .map(|(remote, (root, _))| (remote, root))
        .collect();
    out.capabilities.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        ComposedProfile, CompositionError, MachineSkillTarget, ProfileResource, ProvenanceRecord,
        RequirementValue, SkillAssignment, SkillAssignmentScope, compose_profile,
        compose_skill_assignments,
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

    fn builtin() -> super::BuiltinSkillAssignment {
        super::BuiltinSkillAssignment {
            skill_id: "fleet".to_owned(),
            catalog_id: "builtin-fleet".to_owned(),
            catalog_version_id: format!("builtin-fleet@{}", "a".repeat(64)),
            deploy_to: vec!["claude_code".to_owned(), "codex".to_owned()],
        }
    }

    fn builtin_target() -> MachineSkillTarget {
        MachineSkillTarget {
            machine_id: "m-1".to_owned(),
            groups: vec![],
            tags: vec![],
        }
    }

    fn git_preset(
        skill_id: &str,
        deploy_to: &[&str],
        scope: SkillAssignmentScope,
    ) -> SkillAssignment {
        SkillAssignment {
            skill_id: skill_id.to_owned(),
            deploy_to: deploy_to.iter().map(|agent| (*agent).to_owned()).collect(),
            deny_agents: vec![],
            catalog_version: None,
            scope,
            provenance: ProvenanceRecord {
                resource_id: format!("git-{skill_id}"),
                resource_name: skill_id.to_owned(),
                path: "spec".to_owned(),
            },
        }
    }

    #[test]
    fn the_builtin_fleet_skill_is_assigned_globally_by_default() {
        let assignments = super::with_builtin_assignments(&[], &[builtin()]);
        let composed = compose_skill_assignments(&builtin_target(), &assignments).unwrap();
        let version = format!("builtin-fleet@{}", "a".repeat(64));
        assert_eq!(
            composed.catalog_skills,
            vec![
                (
                    "builtin-fleet".to_owned(),
                    version.clone(),
                    "claude_code".to_owned()
                ),
                ("builtin-fleet".to_owned(), version, "codex".to_owned()),
            ]
        );
        assert_eq!(
            composed.provenance["catalog-skill:builtin-fleet/codex"].resource_id,
            "builtin:builtin-fleet"
        );
    }

    #[test]
    fn fleet_git_takes_over_the_builtin_skill_once_it_names_it() {
        // Git narrows the skill to one agent: the default is not added.
        let narrowed = super::with_builtin_assignments(
            &[git_preset("fleet", &["codex"], SkillAssignmentScope::All)],
            &[builtin()],
        );
        let composed = compose_skill_assignments(&builtin_target(), &narrowed).unwrap();
        assert_eq!(
            composed.skills,
            vec![("fleet".to_owned(), "codex".to_owned())]
        );
        assert!(composed.catalog_skills.is_empty());

        // A preset with no agents removes it everywhere, and stays removed.
        let removed = super::with_builtin_assignments(
            &[git_preset("fleet", &[], SkillAssignmentScope::All)],
            &[builtin()],
        );
        let composed = compose_skill_assignments(&builtin_target(), &removed).unwrap();
        assert!(composed.skills.is_empty());
        assert!(composed.catalog_skills.is_empty());

        // An unrelated preset leaves the default in place.
        let unrelated = super::with_builtin_assignments(
            &[git_preset(
                "rust-style",
                &["codex"],
                SkillAssignmentScope::All,
            )],
            &[builtin()],
        );
        assert_eq!(unrelated.len(), 2);
    }

    #[test]
    fn skill_assignments_compose_global_group_tag_and_machine_scopes_deterministically() {
        let assignments = vec![
            SkillAssignment {
                skill_id: "fleet-basics".into(),
                deploy_to: vec!["codex".into(), "claude_code".into()],
                deny_agents: vec![],
                catalog_version: None,
                scope: SkillAssignmentScope::All,
                provenance: super::ProvenanceRecord {
                    resource_id: "global-id".into(),
                    resource_name: "global".into(),
                    path: "/spec".into(),
                },
            },
            SkillAssignment {
                skill_id: "rust-style".into(),
                deploy_to: vec!["codex".into()],
                deny_agents: vec![],
                catalog_version: None,
                scope: SkillAssignmentScope::Group("engineering".into()),
                provenance: super::ProvenanceRecord {
                    resource_id: "group-id".into(),
                    resource_name: "engineering".into(),
                    path: "/spec".into(),
                },
            },
            SkillAssignment {
                skill_id: "oncall".into(),
                deploy_to: vec!["claude_code".into()],
                deny_agents: vec![],
                catalog_version: None,
                scope: SkillAssignmentScope::Tag("oncall".into()),
                provenance: super::ProvenanceRecord {
                    resource_id: "tag-id".into(),
                    resource_name: "oncall".into(),
                    path: "/spec".into(),
                },
            },
            SkillAssignment {
                skill_id: "local-only".into(),
                deploy_to: vec!["codex".into()],
                deny_agents: vec![],
                catalog_version: None,
                scope: SkillAssignmentScope::Machine("machine-1".into()),
                provenance: super::ProvenanceRecord {
                    resource_id: "machine-id".into(),
                    resource_name: "machine-1".into(),
                    path: "/spec".into(),
                },
            },
        ];
        let target = MachineSkillTarget {
            machine_id: "machine-1".into(),
            groups: vec!["engineering".into()],
            tags: vec!["oncall".into()],
        };

        let first = compose_skill_assignments(&target, &assignments).unwrap();
        let second = compose_skill_assignments(&target, &assignments).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.skills,
            vec![
                ("fleet-basics".into(), "claude_code".into()),
                ("fleet-basics".into(), "codex".into()),
                ("local-only".into(), "codex".into()),
                ("oncall".into(), "claude_code".into()),
                ("rust-style".into(), "codex".into()),
            ]
        );
        assert_eq!(first.provenance.len(), 5);
    }

    #[test]
    fn skill_assignments_are_deduplicated_and_nonmatching_scopes_are_excluded() {
        let assignment = |scope, name: &str| SkillAssignment {
            skill_id: "same".into(),
            deploy_to: vec!["codex".into(), "codex".into()],
            deny_agents: vec![],
            catalog_version: None,
            scope,
            provenance: super::ProvenanceRecord {
                resource_id: name.into(),
                resource_name: name.into(),
                path: "/spec".into(),
            },
        };
        let target = MachineSkillTarget {
            machine_id: "m1".into(),
            groups: vec!["g1".into()],
            tags: vec!["t1".into()],
        };
        let result = compose_skill_assignments(
            &target,
            &[
                assignment(SkillAssignmentScope::All, "global"),
                assignment(SkillAssignmentScope::Group("g2".into()), "other-group"),
            ],
        )
        .unwrap();
        assert_eq!(result.skills, vec![("same".into(), "codex".into())]);
        assert_eq!(
            result.provenance["skill:same/codex"].resource_name,
            "global"
        );
    }

    #[test]
    fn catalog_assignments_retain_catalog_and_version_pins_for_rollout_planning() {
        let assignment = SkillAssignment {
            skill_id: "fleet-help".into(),
            deploy_to: vec!["codex".into()],
            deny_agents: vec![],
            catalog_version: Some(("catalog-1".into(), "version-4".into())),
            scope: SkillAssignmentScope::All,
            provenance: super::ProvenanceRecord {
                resource_id: "global-id".into(),
                resource_name: "global-help".into(),
                path: "/spec".into(),
            },
        };
        let result = compose_skill_assignments(
            &MachineSkillTarget {
                machine_id: "m1".into(),
                groups: vec![],
                tags: vec![],
            },
            &[assignment],
        )
        .unwrap();
        assert!(result.skills.is_empty());
        assert_eq!(
            result.catalog_skills,
            vec![("catalog-1".into(), "version-4".into(), "codex".into())]
        );
    }

    #[test]
    fn conflicting_catalog_versions_for_one_agent_fail_composition() {
        let assignment = |version: &str, name: &str| SkillAssignment {
            skill_id: "fleet-help".into(),
            deploy_to: vec!["codex".into()],
            deny_agents: vec![],
            catalog_version: Some(("catalog-1".into(), version.into())),
            scope: SkillAssignmentScope::All,
            provenance: super::ProvenanceRecord {
                resource_id: name.into(),
                resource_name: name.into(),
                path: "/spec".into(),
            },
        };
        let error = compose_skill_assignments(
            &MachineSkillTarget {
                machine_id: "m1".into(),
                groups: vec![],
                tags: vec![],
            },
            &[
                assignment("version-1", "first"),
                assignment("version-2", "second"),
            ],
        )
        .unwrap_err();
        assert_eq!(
            error,
            super::SkillAssignmentCompositionError::ConflictingCatalogVersions {
                identity: "catalog-skill:catalog-1/codex".into(),
                first_version: "version-1".into(),
                second_version: "version-2".into(),
            }
        );
    }

    #[test]
    fn an_explicit_deny_suppresses_conflicting_catalog_pins() {
        let assignment = |version: &str, name: &str| SkillAssignment {
            skill_id: "skill-1".into(),
            deploy_to: vec!["codex".into()],
            deny_agents: vec![],
            scope: SkillAssignmentScope::All,
            provenance: super::ProvenanceRecord {
                resource_id: name.into(),
                resource_name: name.into(),
                path: "/spec".into(),
            },
            catalog_version: Some(("catalog-1".into(), version.into())),
        };
        let assignments = vec![
            assignment(
                "catalog-1@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "preset-a",
            ),
            assignment(
                "catalog-1@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "preset-b",
            ),
            SkillAssignment {
                skill_id: "skill-1".into(),
                deploy_to: vec![],
                deny_agents: vec!["codex".into()],
                scope: SkillAssignmentScope::All,
                provenance: super::ProvenanceRecord {
                    resource_id: "deny".into(),
                    resource_name: "deny".into(),
                    path: "/spec".into(),
                },
                catalog_version: None,
            },
        ];

        let composed = compose_skill_assignments(
            &MachineSkillTarget {
                machine_id: "m1".into(),
                groups: vec![],
                tags: vec![],
            },
            &assignments,
        )
        .unwrap();
        assert!(composed.catalog_skills.is_empty());
        assert!(composed.skills.is_empty());
        assert!(composed.provenance.is_empty());
    }

    #[test]
    fn explicit_agent_denies_win_over_matching_skill_includes() {
        let included = SkillAssignment {
            skill_id: "db".into(),
            deploy_to: vec!["codex".into()],
            deny_agents: vec![],
            catalog_version: None,
            scope: SkillAssignmentScope::All,
            provenance: super::ProvenanceRecord {
                resource_id: "include".into(),
                resource_name: "include".into(),
                path: "/spec".into(),
            },
        };
        let denied = SkillAssignment {
            skill_id: "db".into(),
            deploy_to: vec!["codex".into()],
            deny_agents: vec!["codex".into()],
            catalog_version: None,
            scope: SkillAssignmentScope::Machine("m1".into()),
            provenance: super::ProvenanceRecord {
                resource_id: "deny".into(),
                resource_name: "deny".into(),
                path: "/spec".into(),
            },
        };
        let result = compose_skill_assignments(
            &MachineSkillTarget {
                machine_id: "m1".into(),
                groups: vec![],
                tags: vec![],
            },
            &[included, denied],
        )
        .unwrap();
        assert!(result.skills.is_empty());
    }

    #[test]
    fn slash_delimited_identity_components_are_rejected() {
        let assignment = SkillAssignment {
            skill_id: "bad/skill".into(),
            deploy_to: vec!["codex".into()],
            deny_agents: vec![],
            catalog_version: None,
            scope: SkillAssignmentScope::All,
            provenance: super::ProvenanceRecord {
                resource_id: "bad-id".into(),
                resource_name: "bad".into(),
                path: "/spec".into(),
            },
        };
        let error = compose_skill_assignments(
            &MachineSkillTarget {
                machine_id: "m1".into(),
                groups: vec![],
                tags: vec![],
            },
            &[assignment],
        )
        .unwrap_err();
        assert_eq!(
            error,
            super::SkillAssignmentCompositionError::InvalidIdentityComponent {
                component: "skill id",
            }
        );
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

    fn project(
        name: &str,
        remote: &str,
        root: Option<&str>,
        tools: &[(&str, &str)],
    ) -> super::ProjectResource {
        super::ProjectResource {
            id: format!("proj-{name}"),
            name: name.to_owned(),
            remote: remote.to_owned(),
            root: root.map(str::to_owned),
            tools: tools
                .iter()
                .map(|(tool, version)| ((*tool).to_owned(), (*version).to_owned()))
                .collect(),
        }
    }

    fn projects(list: Vec<super::ProjectResource>) -> BTreeMap<String, super::ProjectResource> {
        list.into_iter().map(|p| (p.name.clone(), p)).collect()
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn a_binding_unions_profiles_and_projects_deterministically() {
        let profiles = registry(vec![
            profile(
                "base",
                &[],
                vec![tool("node", "20.11.0"), capability("os", "linux")],
                &[],
            ),
            profile(
                "rust",
                &["base"],
                vec![tool("rust", "1.85.0"), skill("db", &["codex"])],
                &[],
            ),
        ]);
        let projects = projects(vec![
            project(
                "app",
                "github.com/acme/app",
                Some("/srv/app"),
                &[("node", "20.11.0"), ("go", "1.22.0")],
            ),
            project("lib", "github.com/acme/lib", Some("/srv/lib"), &[]),
            project(
                "no-root",
                "github.com/acme/none",
                None,
                &[("zig", "0.13.0")],
            ),
        ]);
        let forward = super::compose_binding(
            &names(&["rust"]),
            &names(&["app", "lib", "no-root"]),
            &profiles,
            &projects,
        )
        .unwrap();
        let reverse = super::compose_binding(
            &names(&["rust", "base"]),
            &names(&["no-root", "lib", "app"]),
            &profiles,
            &projects,
        )
        .unwrap();
        assert_eq!(forward, reverse, "binding order does not change the result");
        assert_eq!(
            forward.tools,
            vec![
                ("go".to_owned(), "1.22.0".to_owned()),
                ("node".to_owned(), "20.11.0".to_owned()),
                ("rust".to_owned(), "1.85.0".to_owned()),
                ("zig".to_owned(), "0.13.0".to_owned()),
            ]
        );
        assert_eq!(
            forward.checkouts,
            vec![
                ("github.com/acme/app".to_owned(), "/srv/app".to_owned()),
                ("github.com/acme/lib".to_owned(), "/srv/lib".to_owned()),
            ],
            "a project without a root contributes tools but no checkout"
        );
        assert_eq!(
            forward.skills,
            vec![("db".to_owned(), vec!["codex".to_owned()])]
        );
        assert_eq!(
            forward.capabilities,
            vec![("os".to_owned(), "linux".to_owned())]
        );
        assert_eq!(forward.provenance["tool:rust"].resource_name, "rust");
        assert_eq!(forward.provenance["tool:go"].resource_name, "app");
    }

    #[test]
    fn a_binding_refuses_conflicts_cycles_and_unknown_names() {
        let profiles = registry(vec![
            profile("a", &[], vec![tool("node", "18.0.0")], &[]),
            profile("b", &[], vec![tool("node", "20.0.0")], &[]),
            profile("loop-x", &["loop-y"], vec![], &[]),
            profile("loop-y", &["loop-x"], vec![], &[]),
        ]);
        let projects = projects(vec![
            project(
                "app",
                "github.com/acme/app",
                Some("/srv/app"),
                &[("node", "22.0.0")],
            ),
            project(
                "app-elsewhere",
                "github.com/acme/app",
                Some("/opt/app"),
                &[],
            ),
            project("other", "github.com/acme/other", Some("/srv/app"), &[]),
        ]);
        let compose = |profile_names: &[&str], project_names: &[&str]| {
            super::compose_binding(
                &names(profile_names),
                &names(project_names),
                &profiles,
                &projects,
            )
        };
        assert!(matches!(
            compose(&["a", "b"], &[]),
            Err(CompositionError::Conflict { .. })
        ));
        assert!(
            matches!(
                compose(&["a"], &["app"]),
                Err(CompositionError::Conflict { .. })
            ),
            "a project tool disagreeing with a profile"
        );
        assert!(
            matches!(
                compose(&[], &["app", "app-elsewhere"]),
                Err(CompositionError::Conflict { .. })
            ),
            "one remote, two roots"
        );
        assert!(
            matches!(
                compose(&[], &["app", "other"]),
                Err(CompositionError::Conflict { .. })
            ),
            "one root, two remotes"
        );
        assert!(matches!(
            compose(&["loop-x"], &[]),
            Err(CompositionError::Cycle { .. })
        ));
        assert!(matches!(
            compose(&["missing"], &[]),
            Err(CompositionError::UnknownProfile { .. })
        ));
        assert!(matches!(
            compose(&[], &["missing"]),
            Err(CompositionError::UnknownProject { .. })
        ));
    }

    #[test]
    fn a_deny_in_one_bound_profile_removes_the_requirement_from_the_binding() {
        let profiles = registry(vec![
            profile("wants-node", &[], vec![tool("node", "20.0.0")], &[]),
            profile("no-node", &[], vec![], &["tool:node"]),
        ]);
        let composed = super::compose_binding(
            &names(&["wants-node", "no-node"]),
            &[],
            &profiles,
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(composed.tools.is_empty(), "deny wins over include");
    }
}
