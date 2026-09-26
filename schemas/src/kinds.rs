//! The M4 desired-resource kinds (FM-400): versioned specs for machine,
//! profile, project, tool requirement, skill preset, recipe/action, Lab
//! template, and policy binding.
//!
//! Every kind is a typed spec under the FM-005 envelope, with `JsonSchema`
//! derives so the published schema grows mechanically. ADR-0004 holds in
//! each spec: no observed, status, or secret values — secret fields carry
//! secret-reference IDs only. Set-valued requirements carry stable
//! identity with explicit include/deny semantics; there is no silent
//! last-write-wins anywhere.
#![warn(missing_docs)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A secret reference: the ID of an encrypted secret record, never a
/// value. ADR-0004 forbids inline secrets in desired resources.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SecretRef {
    /// The stable ID of the encrypted secret record.
    #[schemars(length(min = 1, max = 64))]
    pub secret_id: String,
}

/// A tool requirement: a tool name and its pinned version.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ToolRequirementSpec {
    /// The tool's name as the provider's CLI names it.
    #[schemars(
        length(min = 1, max = 63),
        regex(pattern = r"^[a-z0-9]+(?:[-_][a-z0-9]+)*$")
    )]
    pub tool: String,
    /// The pinned version, exactly as mise or the tool's own CLI reports it.
    #[schemars(length(min = 1, max = 63))]
    pub version: String,
}

/// One skill to deploy to named agents, with explicit removal semantics.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SkillRequirementSpec {
    /// The skill's identifier in the Skills Manager library.
    #[schemars(length(min = 1, max = 63))]
    pub skill_id: String,
    /// The agents the skill deploys to.
    #[schemars(length(min = 1, max = 16))]
    pub deploy_to: Vec<String>,
    /// Explicitly undeploy from these agents even if an earlier profile
    /// included the skill for them: deny wins over include.
    #[serde(default)]
    #[schemars(length(max = 16))]
    pub deny_agents: Vec<String>,
}

/// The machine selector for a Fleet-managed skill assignment.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "camelCase",
    tag = "type",
    content = "value"
)]
pub enum SkillAssignmentScope {
    /// Apply to every current and future machine.
    All,
    /// Apply to machines in a group.
    Group(String),
    /// Apply to machines carrying a tag.
    Tag(String),
    /// Apply to one stable Fleet machine identity.
    Machine(String),
}

/// A Fleet-managed skill assignment from a catalog version to agents.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SkillPresetSpec {
    /// The stable skill identity used by the Skills Manager CLI.
    #[schemars(length(min = 1, max = 63))]
    pub skill_id: String,
    /// The catalog identity for a Fleet-authored or referenced skill.
    #[serde(default)]
    #[schemars(length(max = 63))]
    pub catalog_id: Option<String>,
    /// The Fleet catalog version this assignment pins, when Fleet owns the
    /// skill content. External Skills Manager entries may omit it.
    #[serde(default)]
    #[schemars(length(max = 80))]
    pub catalog_version_id: Option<String>,
    /// The target selector. Omitting it preserves the global assignment
    /// behavior of early `SkillPreset` resources.
    #[serde(default = "global_skill_scope")]
    pub scope: SkillAssignmentScope,
    /// The coding agents receiving the skill.
    #[schemars(length(min = 1, max = 16))]
    pub deploy_to: Vec<String>,
}

fn global_skill_scope() -> SkillAssignmentScope {
    SkillAssignmentScope::All
}

/// An endpoint a machine exposes, as desired identity. Observed
/// connectivity lives in capability facts, never here.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DesiredEndpoint {
    /// The endpoint kind's stable id (e.g. `ssh`, `node`).
    #[schemars(length(min = 1, max = 16))]
    pub kind: String,
    /// The user@host:port reference or node id. Never carries a secret:
    /// semantic validation refuses credential-bearing userinfo before
    /// activation.
    #[schemars(length(min = 1, max = 255))]
    pub reference: String,
}

/// The `Machine` spec: desired identity facts for one machine.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MachineSpec {
    /// The endpoints the machine is reached through.
    #[serde(default)]
    #[schemars(length(max = 8))]
    pub endpoints: Vec<DesiredEndpoint>,
    /// Tags for filtering.
    #[serde(default)]
    #[schemars(length(max = 16))]
    pub tags: Vec<String>,
    /// Groups for filtering.
    #[serde(default)]
    #[schemars(length(max = 16))]
    pub groups: Vec<String>,
    /// Desired SSH trust posture: the fingerprint the machine's host key
    /// must match, when pinning is declared. Observed fingerprints live
    /// in the trust workflow.
    #[serde(default)]
    #[schemars(length(max = 128))]
    pub pinned_host_key: Option<String>,
}

/// The `Project` spec: declared tools and skill requirements for a
/// project. The normalized remote is the project's identity in Fleet's
/// runtime; desired resources reference it by name.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProjectSpec {
    /// The normalized Git remote the project is keyed by at runtime.
    /// Required: the remote is the project's runtime identity.
    #[schemars(length(min = 1, max = 255))]
    pub remote: String,
    /// The checkout root the ready workflow targets.
    #[serde(default)]
    #[schemars(length(max = 400))]
    pub root: Option<String>,
    /// Tool versions the project declares.
    #[serde(default)]
    #[schemars(length(max = 32))]
    pub tools: Vec<ToolRequirementSpec>,
    /// Skills the project deploys.
    #[serde(default)]
    #[schemars(length(max = 32))]
    pub skills: Vec<SkillRequirementSpec>,
}

/// The `Recipe` spec: a bounded, reviewed command contract executed
/// through the same durable operation kernel as every other action.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecipeSpec {
    /// The command executed through the bounded transport, as an argument
    /// array. Never a shell string.
    #[schemars(length(min = 1, max = 32))]
    pub command: Vec<String>,
    /// The working directory the command runs in, when one is required.
    #[serde(default)]
    #[schemars(length(max = 400))]
    pub working_directory: Option<String>,
    /// The deadline, in seconds.
    #[schemars(range(min = 1, max = 3600))]
    pub timeout_seconds: u64,
}

/// The `Action` spec: a named, parametrized recipe invocation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActionSpec {
    /// The recipe this action invokes.
    #[schemars(length(min = 1, max = 63))]
    pub recipe: String,
    /// The positional arguments passed to the recipe's command.
    #[serde(default)]
    #[schemars(length(max = 16))]
    pub arguments: Vec<String>,
}

/// The `LabTemplate` spec: M7's minimal versioned contract — the image
/// and shape a Lab instance clones. Detailed semantics arrive with M7;
/// the schema reserves the shape now.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LabTemplateSpec {
    /// The promoted image version the template pins.
    #[serde(default)]
    #[schemars(length(max = 63))]
    pub image_version: Option<String>,
    /// The number of vCPUs.
    #[serde(default)]
    #[schemars(range(min = 1, max = 128))]
    pub cores: Option<u32>,
    /// The memory, in MiB.
    #[serde(default)]
    #[schemars(range(min = 128, max = 1_048_576))]
    pub memory_mib: Option<u32>,
}

/// The `PolicyBinding` spec: non-secret bindings between principals and
/// permission sets. The policy engine's semantics live in fleet-auth;
/// this carries only the declared binding.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyBindingSpec {
    /// The principal the binding names.
    #[schemars(length(min = 1, max = 63))]
    pub principal: String,
    /// The permission ids granted, from the authz catalog.
    #[schemars(length(min = 1, max = 64))]
    pub permissions: Vec<String>,
}

/// One profile requirement: a tool, skill, or capability the profile
/// asks machines to satisfy. Set-valued with explicit deny semantics.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "type"
)]
pub enum ProfileRequirement {
    /// A tool version requirement.
    Tool {
        /// The tool's name.
        #[schemars(length(min = 1, max = 63))]
        tool: String,
        /// The pinned version.
        #[schemars(length(min = 1, max = 63))]
        version: String,
    },
    /// A skill deployment requirement.
    Skill {
        /// The skill's identifier.
        #[schemars(length(min = 1, max = 63))]
        skill_id: String,
        /// The agents the skill deploys to.
        #[schemars(length(min = 1, max = 16))]
        deploy_to: Vec<String>,
    },
    /// A capability requirement selecting compatible machines.
    Capability {
        /// The capability's namespace. The identity delimiters `:` and `/`
        /// are refused so distinct requirements cannot collide.
        #[schemars(length(min = 1, max = 63), regex(pattern = r"^[a-z0-9_-]+$"))]
        namespace: String,
        /// The capability's name. The identity delimiters `:` and `/` are
        /// refused so distinct requirements cannot collide.
        #[schemars(length(min = 1, max = 63), regex(pattern = r"^[a-z0-9_-]+$"))]
        name: String,
    },
}

/// The `Profile` spec: the composition unit. `extends` chains resolve
/// depth-first with cycle refusal; resolved fields record which profile
/// contributed them.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProfileSpec {
    /// The other profiles this profile extends, in application order.
    /// Cycles fail semantic validation.
    #[serde(default)]
    #[schemars(length(max = 16))]
    pub extends: Vec<String>,
    /// The requirements this profile contributes.
    #[serde(default)]
    #[schemars(length(max = 64))]
    pub requirements: Vec<ProfileRequirement>,
    /// Requirements explicitly removed, overriding any extended profile's
    /// contribution: deny wins over include.
    #[serde(default)]
    #[schemars(length(max = 64))]
    pub deny: Vec<ProfileRequirement>,
}

/// The resolved provenance of one composed field: which resource and path
/// contributed it.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Provenance {
    /// The contributing resource's metadata.id.
    #[schemars(length(min = 1, max = 64))]
    pub resource_id: String,
    /// The contributing resource's metadata.name.
    #[schemars(length(min = 1, max = 63))]
    pub resource_name: String,
    /// The path within the resource the value came from.
    #[schemars(length(min = 1, max = 255))]
    pub path: String,
}
