//! The centralized authorization port and permission catalog.
//!
//! Every read and mutation answers one question in one place: may this
//! principal perform this action on this resource? The port below is that
//! place. Handlers, providers, and adapters never decide permission
//! themselves — they construct an [`AccessRequest`] and obey the
//! [`Decision`] — because a permission check scattered across an adapter is a
//! check no review can find and no policy engine can replace.
//!
//! The catalog is the complete action vocabulary of the running system, not a
//! sample: an action that is not in it cannot be named, so it cannot be
//! permitted by accident. Adding an entry is a reviewed decision that states
//! the action's risk.
//!
//! The initial trusted-LAN deployment supplies one implementation — the
//! explicit allow-all adapter for `anonymous-lan-admin` (see `fleet-auth`) —
//! and keeps the port, so the later authenticated mode is a swap, not a
//! rewrite.
#![warn(missing_docs)]

use std::fmt;

/// One action in the permission catalog.
///
/// The id is stable and appears in audit events and decisions; renaming one
/// is a breaking change to the audit trail, not a refactor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Permission {
    /// Read system-level facts: build metadata, configuration summary,
    /// trust mode, storage health.
    SystemRead,
    /// List and read operations and their progress.
    OperationRead,
    /// Create a durable operation. A mutation.
    OperationCreate,
    /// Request cancellation of a running operation. A mutation.
    OperationCancel,
    /// List secret record metadata (names and key versions, never values).
    SecretList,
    /// Resolve a secret value. The most sensitive read in the system.
    SecretRead,
    /// Create or replace a secret value. A mutation.
    SecretWrite,
    /// Delete a secret record. A mutation.
    SecretDelete,
    /// Query the audit ledger. A read, but a sensitive one: it reveals who
    /// did what.
    AuditRead,
    /// List and read machines, endpoints, capabilities, and observations.
    /// Endpoint references are delivered with credential-bearing detail
    /// (SSH login names) redacted unless this principal also holds
    /// [`Permission::MachineReadSensitive`].
    MachineRead,
    /// Read the unredacted credential-bearing detail of machine endpoints,
    /// such as SSH login names. A read, but a sensitive one: login names
    /// are half of a credential.
    MachineReadSensitive,
    /// Register a machine. A mutation.
    MachineCreate,
    /// Change a machine's mutable facts: name, description, endpoints,
    /// tags, groups. A mutation.
    MachineUpdate,
    /// Remove a machine and its facts. A mutation.
    MachineDelete,
    /// Create a single-use enrollment token for a machine. A mutation: it
    /// hands whoever holds the token the ability to bind a node key.
    NodeEnroll,
    /// View a machine's node identity, credentials, sessions, and tokens.
    NodeRead,
    /// Revoke a machine's node identity and every credential and session
    /// under it. A mutation.
    NodeRevoke,
    /// List tailnet devices and correlate them with Fleet machines.
    /// A read, but a topology-revealing one.
    TailnetRead,
    /// Configure or clear the Tailscale OAuth integration. A mutation:
    /// it stores or removes a credential.
    TailnetConfig,
    /// List and read projects and their observed checkouts.
    ProjectsRead,
    /// Register a project. A mutation.
    ProjectsCreate,
    /// Change a project's mutable display facts. A mutation.
    ProjectsUpdate,
    /// Remove a project and its facts. A mutation.
    ProjectsDelete,
    /// Discover checkouts on a machine by probing its standard roots over
    /// the SSH transport. A read, but a filesystem-topology-revealing one.
    ProjectsDiscover,
    /// Clone, pull, or read the status of a project checkout on a machine.
    /// A mutation: it changes remote state through the Git CLI.
    ProjectsGitWrite,
    /// Write guarded agent configuration files under a checkout root.
    /// A mutation: it writes files on a managed machine.
    ProjectsFileWrite,
    /// Probe and read the Skills Manager CLI's state on a machine: the
    /// library, agents, and deployments. A read, but an
    /// agent-topology-revealing one.
    SkillsRead,
    /// Deploy or undeploy skills through the Skills Manager CLI. A
    /// mutation: it changes agent state on a managed machine.
    SkillsDeploy,
    /// Probe and read the Frogenv CLI's status on a machine. A read, but
    /// a secrets-infrastructure-revealing one.
    FrogenvRead,
    /// Run Frogenv ceremonies and environment-bound commands: setup,
    /// login, machine request, sync, and env run. A mutation: it changes
    /// the machine's secrets infrastructure or executes with decrypted
    /// environment values in a child process.
    FrogenvOperate,
    /// Probe and read the tool/coding-agent inventory on a machine. A
    /// read, but a toolchain-topology-revealing one.
    ToolsRead,
    /// Install tools or run project tasks through the mise CLI. A
    /// mutation: it changes the machine's tool versions or executes a
    /// project command.
    MiseOperate,
    /// Plan and execute the ready-project workflow on a machine: clone,
    /// install prerequisites, configure the environment, deploy skills,
    /// and verify. A mutation: it composes every mutation the workflow
    /// may run.
    ProjectsReady,
}

impl Permission {
    /// Every action in the catalog. The trusted-LAN adapter's allow-all
    /// behavior is defined over exactly this list, so "all" means this
    /// catalog and nothing outside it.
    pub const ALL: &'static [Permission] = &[
        Permission::SystemRead,
        Permission::OperationRead,
        Permission::OperationCreate,
        Permission::OperationCancel,
        Permission::SecretList,
        Permission::SecretRead,
        Permission::SecretWrite,
        Permission::SecretDelete,
        Permission::AuditRead,
        Permission::MachineRead,
        Permission::MachineReadSensitive,
        Permission::MachineCreate,
        Permission::MachineUpdate,
        Permission::MachineDelete,
        Permission::NodeEnroll,
        Permission::NodeRead,
        Permission::NodeRevoke,
        Permission::TailnetRead,
        Permission::TailnetConfig,
        Permission::ProjectsRead,
        Permission::ProjectsCreate,
        Permission::ProjectsUpdate,
        Permission::ProjectsDelete,
        Permission::ProjectsDiscover,
        Permission::ProjectsGitWrite,
        Permission::ProjectsFileWrite,
        Permission::SkillsRead,
        Permission::SkillsDeploy,
        Permission::FrogenvRead,
        Permission::FrogenvOperate,
        Permission::ToolsRead,
        Permission::MiseOperate,
        Permission::ProjectsReady,
    ];

    /// The stable action id, as recorded in decisions and audit events.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Permission::SystemRead => "system.read",
            Permission::OperationRead => "operation.read",
            Permission::OperationCreate => "operation.create",
            Permission::OperationCancel => "operation.cancel",
            Permission::SecretList => "secret.list",
            Permission::SecretRead => "secret.read",
            Permission::SecretWrite => "secret.write",
            Permission::SecretDelete => "secret.delete",
            Permission::AuditRead => "audit.read",
            Permission::MachineRead => "machine.read",
            Permission::MachineReadSensitive => "machine.read.sensitive",
            Permission::MachineCreate => "machine.create",
            Permission::MachineUpdate => "machine.update",
            Permission::MachineDelete => "machine.delete",
            Permission::NodeEnroll => "node.enroll",
            Permission::NodeRead => "node.read",
            Permission::NodeRevoke => "node.revoke",
            Permission::TailnetRead => "tailscale.read",
            Permission::TailnetConfig => "tailscale.config",
            Permission::ProjectsRead => "projects.read",
            Permission::ProjectsCreate => "projects.create",
            Permission::ProjectsUpdate => "projects.update",
            Permission::ProjectsDelete => "projects.delete",
            Permission::ProjectsDiscover => "projects.discover",
            Permission::ProjectsGitWrite => "projects.git.write",
            Permission::ProjectsFileWrite => "projects.file.write",
            Permission::SkillsRead => "skills.read",
            Permission::SkillsDeploy => "skills.deploy",
            Permission::FrogenvRead => "frogenv.read",
            Permission::FrogenvOperate => "frogenv.operate",
            Permission::ToolsRead => "tools.read",
            Permission::MiseOperate => "mise.operate",
            Permission::ProjectsReady => "projects.ready",
        }
    }

    /// Whether performing the action changes state or reveals sensitive
    /// material. Every mutation is true; the reads that expose
    /// high-value information are true as well.
    #[must_use]
    pub fn is_risky(self) -> bool {
        match self {
            Permission::SystemRead
            | Permission::OperationRead
            | Permission::SecretList
            | Permission::AuditRead
            | Permission::MachineRead
            | Permission::NodeRead
            | Permission::ProjectsRead => false,
            Permission::MachineReadSensitive
            | Permission::OperationCreate
            | Permission::OperationCancel
            | Permission::SecretRead
            | Permission::SecretWrite
            | Permission::SecretDelete
            | Permission::MachineCreate
            | Permission::MachineUpdate
            | Permission::MachineDelete
            | Permission::NodeEnroll
            | Permission::NodeRevoke
            | Permission::TailnetConfig
            | Permission::TailnetRead
            | Permission::ProjectsCreate
            | Permission::ProjectsUpdate
            | Permission::ProjectsDelete
            | Permission::ProjectsDiscover
            | Permission::ProjectsGitWrite
            | Permission::ProjectsFileWrite
            | Permission::SkillsRead
            | Permission::SkillsDeploy
            | Permission::FrogenvRead
            | Permission::FrogenvOperate
            | Permission::ToolsRead
            | Permission::MiseOperate
            | Permission::ProjectsReady => true,
        }
    }

    /// Whether the action names a specific resource and therefore requires
    /// one in the request. A catalog-level action without a resource is a
    /// malformed request, not an implicit wildcard.
    #[must_use]
    pub fn requires_resource(self) -> bool {
        match self {
            Permission::SystemRead
            | Permission::OperationRead
            | Permission::OperationCreate
            | Permission::SecretList
            | Permission::SecretWrite
            | Permission::AuditRead
            | Permission::MachineRead
            | Permission::MachineCreate
            | Permission::TailnetRead
            | Permission::TailnetConfig
            | Permission::ProjectsRead
            | Permission::ProjectsCreate => false,
            Permission::MachineReadSensitive
            | Permission::OperationCancel
            | Permission::SecretRead
            | Permission::SecretDelete
            | Permission::MachineUpdate
            | Permission::MachineDelete
            | Permission::NodeEnroll
            | Permission::NodeRead
            | Permission::NodeRevoke
            | Permission::ProjectsUpdate
            | Permission::ProjectsDelete
            | Permission::ProjectsDiscover
            | Permission::ProjectsGitWrite
            | Permission::ProjectsFileWrite
            | Permission::SkillsRead
            | Permission::SkillsDeploy
            | Permission::FrogenvRead
            | Permission::FrogenvOperate
            | Permission::ToolsRead
            | Permission::MiseOperate
            | Permission::ProjectsReady => true,
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// Stable reason identifiers. A decision's reason is part of the audit
/// surface: these strings persist in logs and events, so they change only by
/// adding new ones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReasonId {
    /// The policy explicitly allows the action.
    PolicyAllow,
    /// Nothing allows the action for this principal. The default when the
    /// policy is deny-by-default; the trusted-LAN adapter also answers this
    /// for principals it does not recognize.
    UnknownPrincipal,
    /// The action requires a resource and the request named none.
    MissingResource,
    /// The request is malformed: it names an action outside the catalog.
    UnknownAction,
}

impl ReasonId {
    /// The stable string recorded in decisions and audit events.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            ReasonId::PolicyAllow => "policy.allow",
            ReasonId::UnknownPrincipal => "policy.unknown_principal",
            ReasonId::MissingResource => "policy.missing_resource",
            ReasonId::UnknownAction => "policy.unknown_action",
        }
    }
}

impl fmt::Display for ReasonId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// What the caller wants to do.
#[derive(Clone, Copy, Debug)]
pub struct AccessRequest<'a> {
    /// The acting principal's stable id, as resolved by caller resolution.
    pub principal_id: &'a str,
    /// The catalog action.
    pub action: Permission,
    /// The specific resource, when the action names one.
    pub resource: Option<&'a str>,
}

/// The answer to one access request. This is a record to keep, not a signal
/// to branch on alone: audit events carry the reason, so denials are
/// explainable after the fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    /// Whether the action may proceed.
    pub allowed: bool,
    /// Why, in stable identifier form.
    pub reason: ReasonId,
}

impl Decision {
    /// The allow decision with [`ReasonId::PolicyAllow`].
    #[must_use]
    pub const fn allow() -> Self {
        Self {
            allowed: true,
            reason: ReasonId::PolicyAllow,
        }
    }

    /// A denial with the given reason.
    #[must_use]
    pub const fn deny(reason: ReasonId) -> Self {
        Self {
            allowed: false,
            reason,
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}",
            self.reason,
            if self.allowed { "allowed" } else { "denied" }
        )
    }
}

/// The acting principal as use cases see it: the resolved caller's stable
/// id. Caller resolution creates it; authorization consumes it; handlers
/// extract it as an extension without knowing how resolution works.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActingPrincipal {
    /// The stable principal id.
    pub id: String,
}

/// The authorization port. Exactly one implementation is active in a
/// deployment; handlers and use cases call it through the application helper,
/// never around it.
pub trait Authorizer: fmt::Debug + Send + Sync {
    /// Answers one access request. Must be cheap, side-effect free, and
    /// secret-free: it runs on every call.
    fn decide(&self, request: AccessRequest<'_>) -> Decision;
}

/// The application-side helper every use case calls.
///
/// This is the single funnel: it enforces the catalog's resource rule and
/// routes through the active [`Authorizer`]. A use case that checks
/// permission by any other path is a defect; a handler that decides
/// permission itself is one too.
///
/// # Errors
///
/// Returns the decision when it is a denial so the caller can map it to a
/// public error; the decision carries the stable reason.
pub fn authorize(
    authorizer: &dyn Authorizer,
    request: AccessRequest<'_>,
) -> Result<Decision, Decision> {
    if request.action.requires_resource() && request.resource.is_none() {
        return Err(Decision::deny(ReasonId::MissingResource));
    }
    let decision = authorizer.decide(request);
    if decision.allowed {
        Ok(decision)
    } else {
        Err(decision)
    }
}
