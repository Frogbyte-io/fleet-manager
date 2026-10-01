//! Proxmox token privilege diagnostics (FM-604).
//!
//! Fleet reports, per account, which of its capability tiers the configured
//! API token can perform — before an operation hits a 403. The answer comes
//! from one place: [`PROXMOX_PRIVILEGE_TABLE`], the Fleet-owned map from
//! every PVE call an executor kind or read makes to the privileges it needs
//! and the ACL path they are checked on, keyed by PVE major where 8.x and
//! 9.x differ. The FM-605 token guide documents this table and its
//! consistency check reads it; nothing else may restate it.
//!
//! The evaluation input is the token's own effective permission map
//! (`GET /access/permissions`): ACL path → privilege → propagate flag, with
//! PVE's propagation, `NoAccess`, pool membership, and the
//! privilege-separation intersection already applied. Fleet does not
//! recompute PVE's ACL model; it answers one question per requirement:
//! *is there a path in the requirement's scope where the token holds the
//! privileges?* The inheritance rules it does apply follow
//! `PVE/RPCEnvironment.pm` (`compile_acl_path`), identical on 8.x and 9.x:
//!
//! - a concrete path in scope (`/vms/101`, `/storage/local-lvm`,
//!   `/nodes/pve`, `/sdn/zones/localnetwork/vmbr0`) counts with every
//!   privilege PVE lists there;
//! - a scope root or `/` (`/vms`, `/storage`, `/nodes`, `/sdn`, `/`)
//!   counts only with its *propagating* privileges, because only those
//!   reach paths below it (including a clone target that does not exist
//!   yet);
//! - `/pool/{name}` counts for guests and storage with every privilege:
//!   PVE applies pool roles to members regardless of propagation. A clone
//!   target is never a pool member — Fleet's clone call does not pass
//!   `pool` — so pools do not count for it.
//!
//! Known limit: a path that PVE omits because the token holds nothing there
//! (for example an explicit `NoAccess` on one VM) is invisible in the map,
//! so a tier granted "somewhere in scope" can still be refused for that one
//! guest. The report names the paths each requirement was satisfied on so
//! an operator can see the scope. A refused permissions read (403) makes
//! every tier `unknown`, never `missing`.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{ProxmoxAccount, ProxmoxAccounts, ProxmoxSourceError, ProxmoxUseCaseError};
use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Permission, authorize};
use fleet_core::SensitiveString;

/// The PVE majors the table carries rules for, oldest first.
pub const SUPPORTED_PVE_MAJORS: [u8; 2] = [8, 9];

/// ACL path → privilege → propagate flag, as PVE reports it.
pub type EffectivePermissions = BTreeMap<String, BTreeMap<String, bool>>;

/// The most paths one requirement reports it was granted on.
const MAX_GRANTED_PATHS: usize = 16;

/// A Fleet capability tier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivilegeTier {
    /// Read-only discovery: cluster, nodes, guests, guest observation.
    Discover,
    /// Guest lifecycle: start, stop, shutdown, reboot.
    Operate,
    /// Snapshot, rollback, snapshot delete, clone, template, task cancel.
    Destructive,
    /// Lab leases: clone a pinned image, start it, probe readiness.
    Lab,
}

impl PrivilegeTier {
    /// Every tier, in report order.
    pub const ALL: [Self; 4] = [Self::Discover, Self::Operate, Self::Destructive, Self::Lab];

    /// The stable identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Operate => "operate",
            Self::Destructive => "destructive",
            Self::Lab => "lab",
        }
    }
}

/// The ACL path a requirement is checked on.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivilegeScope {
    /// `/` itself.
    Root,
    /// One node: `/nodes/{node}`.
    Node,
    /// One existing guest: `/vms/{vmid}` (pool members inherit pool ACLs).
    Guest,
    /// A clone target that does not exist yet: `/vms/{newid}`. Pool ACLs
    /// do not apply, because Fleet's clone call does not pass `pool`.
    NewGuest,
    /// One storage: `/storage/{storage}` (pool members inherit pool ACLs).
    Storage,
    /// One pool: `/pool/{pool}`.
    Pool,
    /// One bridge in an SDN zone: `/sdn/zones/{zone}/{bridge}` (VLAN tag
    /// paths below it count too).
    SdnBridge,
}

impl PrivilegeScope {
    /// The path template an operator grants on.
    #[must_use]
    pub const fn template(self) -> &'static str {
        match self {
            Self::Root => "/",
            Self::Node => "/nodes/{node}",
            Self::Guest => "/vms/{vmid}",
            Self::NewGuest => "/vms/{newid}",
            Self::Storage => "/storage/{storage}",
            Self::Pool => "/pool/{pool}",
            Self::SdnBridge => "/sdn/zones/{zone}/{bridge}",
        }
    }

    /// How a path entry in the effective map relates to this scope.
    fn relation(self, path: &str) -> Option<Relation> {
        if path == "/" {
            return Some(if self == Self::Root {
                Relation::Exact
            } else {
                Relation::Propagated
            });
        }
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        match (self, segments.as_slice()) {
            (Self::Node, ["nodes", _])
            | (Self::Guest | Self::NewGuest, ["vms", _])
            | (Self::Storage, ["storage", _])
            | (Self::Pool, ["pool", _, ..])
            | (Self::SdnBridge, ["sdn", "zones", _, _, ..]) => Some(Relation::Exact),
            (Self::Node, ["nodes"])
            | (Self::Guest | Self::NewGuest, ["vms"])
            | (Self::Storage, ["storage"])
            | (Self::Pool, ["pool"])
            | (Self::SdnBridge, ["sdn"] | ["sdn", "zones"] | ["sdn", "zones", _]) => {
                Some(Relation::Propagated)
            }
            (Self::Guest | Self::Storage, ["pool", _, ..]) => Some(Relation::PoolMember),
            _ => None,
        }
    }
}

/// How one effective-map path applies to a scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Relation {
    /// A concrete path in scope: every listed privilege counts.
    Exact,
    /// An ancestor: only propagating privileges reach the scope.
    Propagated,
    /// A pool: its roles apply to member guests and storage regardless of
    /// propagation.
    PoolMember,
}

/// Whether a requirement needs all of its privileges or any one of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivilegeMatch {
    /// Every listed privilege on the same path.
    All,
    /// Any one listed privilege (PVE's `any => 1`).
    Any,
}

/// One row of the Fleet-owned privilege table: one PVE call (or one check
/// inside a call) made by an executor kind or a read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivilegeRequirement {
    /// The row's stable identifier; unique per PVE major.
    pub id: &'static str,
    /// The executor kind (`proxmox.guest.clone`, `lab.provision`) or read
    /// (`read.cluster-resources`) the call belongs to.
    pub capability: &'static str,
    /// The tier the capability belongs to.
    pub tier: PrivilegeTier,
    /// The PVE method and path, as the API viewer names it.
    pub endpoint: &'static str,
    /// The PVE majors the row applies to.
    pub majors: &'static [u8],
    /// The ACL path the privileges are checked on.
    pub scope: PrivilegeScope,
    /// The PVE privileges; empty when the call needs none.
    pub privileges: &'static [&'static str],
    /// All of them, or any one.
    pub matching: PrivilegeMatch,
    /// Whether the tier needs it. `false` marks an opt-in sub-capability
    /// that degrades honestly without it (8.x guest-agent reads).
    pub required: bool,
    /// Why, in one sentence, with the upstream evidence where it matters.
    pub note: &'static str,
}

impl PrivilegeRequirement {
    /// Whether the row applies to a PVE major.
    #[must_use]
    pub fn applies_to(&self, major: u8) -> bool {
        self.majors.contains(&major)
    }
}

const BOTH: &[u8] = &[8, 9];
const PVE8: &[u8] = &[8];
const PVE9: &[u8] = &[9];
const AGENT_ENDPOINT: &str =
    "GET /nodes/{node}/qemu/{vmid}/agent/{info|network-get-interfaces|get-osinfo}";
const CLONE_ENDPOINT: &str = "POST /nodes/{node}/qemu/{vmid}/clone";

/// The Fleet-owned privilege table: the single source of truth for which
/// PVE privileges each Proxmox executor kind and read needs, on which path,
/// per PVE major. Researched from the upstream `permissions` blocks and
/// method code (qemu-server, pve-manager, pve-storage, pve-container,
/// pve-access-control) on 8.x and 9.x; the FM-605 guide's appendix quotes
/// the evidence.
pub const PROXMOX_PRIVILEGE_TABLE: &[PrivilegeRequirement] = &[
    // ── discover ────────────────────────────────────────────────────────
    PrivilegeRequirement {
        id: "read.version",
        capability: "read.version",
        tier: PrivilegeTier::Discover,
        endpoint: "GET /version",
        majors: BOTH,
        scope: PrivilegeScope::Root,
        privileges: &[],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Every authenticated principal may read the version.",
    },
    PrivilegeRequirement {
        id: "read.cluster-resources.guests",
        capability: "read.cluster-resources",
        tier: PrivilegeTier::Discover,
        endpoint: "GET /cluster/resources",
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.Audit"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Answers 200 but omits every guest without VM.Audit on /vms/{vmid}.",
    },
    PrivilegeRequirement {
        id: "read.cluster-resources.storage",
        capability: "read.cluster-resources",
        tier: PrivilegeTier::Discover,
        endpoint: "GET /cluster/resources",
        majors: BOTH,
        scope: PrivilegeScope::Storage,
        privileges: &["Datastore.Audit"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Answers 200 but omits every storage without Datastore.Audit on /storage/{storage}.",
    },
    PrivilegeRequirement {
        id: "read.cluster-resources.pools",
        capability: "read.cluster-resources",
        tier: PrivilegeTier::Discover,
        endpoint: "GET /cluster/resources",
        majors: BOTH,
        scope: PrivilegeScope::Pool,
        privileges: &["Pool.Audit"],
        matching: PrivilegeMatch::All,
        required: false,
        note: "Pool rows appear only with Pool.Audit; Fleet's discovery does not use them today.",
    },
    PrivilegeRequirement {
        id: "read.node-status",
        capability: "read.node-status",
        tier: PrivilegeTier::Discover,
        endpoint: "GET /nodes/{node}/status",
        majors: BOTH,
        scope: PrivilegeScope::Node,
        privileges: &["Sys.Audit"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Node capacity; without it /cluster/resources also strips node statistics.",
    },
    PrivilegeRequirement {
        id: "read.node-storage",
        capability: "read.node-storage",
        tier: PrivilegeTier::Discover,
        endpoint: "GET /nodes/{node}/storage",
        majors: BOTH,
        scope: PrivilegeScope::Storage,
        privileges: &["Datastore.Audit", "Datastore.AllocateSpace"],
        matching: PrivilegeMatch::Any,
        required: true,
        note: "Answers 200 but lists only storages with either privilege.",
    },
    PrivilegeRequirement {
        id: "read.guest-config",
        capability: "read.guest-config",
        tier: PrivilegeTier::Discover,
        endpoint: "GET /nodes/{node}/{qemu|lxc}/{vmid}/config",
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.Audit"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Config MACs for machine association.",
    },
    PrivilegeRequirement {
        id: "read.guest-agent",
        capability: "read.guest-agent",
        tier: PrivilegeTier::Discover,
        endpoint: AGENT_ENDPOINT,
        majors: PVE9,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.GuestAgent.Audit", "VM.GuestAgent.Unrestricted"],
        matching: PrivilegeMatch::Any,
        required: true,
        note: "PVE 9 split VM.Monitor; informational agent commands need VM.GuestAgent.Audit (grant it, not Unrestricted).",
    },
    PrivilegeRequirement {
        id: "read.guest-agent",
        capability: "read.guest-agent",
        tier: PrivilegeTier::Discover,
        endpoint: AGENT_ENDPOINT,
        majors: PVE8,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.Monitor"],
        matching: PrivilegeMatch::All,
        required: false,
        note: "Opt-in on 8.x: VM.Monitor also permits agent exec and file-write (root inside the guest); without it agent facts are unavailable.",
    },
    PrivilegeRequirement {
        id: "read.task-status",
        capability: "read.task-status",
        tier: PrivilegeTier::Discover,
        endpoint: "GET /nodes/{node}/tasks/{upid}/status",
        majors: BOTH,
        scope: PrivilegeScope::Node,
        privileges: &[],
        matching: PrivilegeMatch::All,
        required: true,
        note: "No privilege for tasks the token started; another principal's task needs Sys.Audit on /nodes/{node}.",
    },
    // ── operate ─────────────────────────────────────────────────────────
    PrivilegeRequirement {
        id: "proxmox.guest.start",
        capability: "proxmox.guest.start",
        tier: PrivilegeTier::Operate,
        endpoint: "POST /nodes/{node}/qemu/{vmid}/status/start",
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.PowerMgmt"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Guest lifecycle.",
    },
    PrivilegeRequirement {
        id: "proxmox.guest.stop",
        capability: "proxmox.guest.stop",
        tier: PrivilegeTier::Operate,
        endpoint: "POST /nodes/{node}/qemu/{vmid}/status/stop",
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.PowerMgmt"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Guest lifecycle.",
    },
    PrivilegeRequirement {
        id: "proxmox.guest.shutdown",
        capability: "proxmox.guest.shutdown",
        tier: PrivilegeTier::Operate,
        endpoint: "POST /nodes/{node}/qemu/{vmid}/status/shutdown",
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.PowerMgmt"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Guest lifecycle.",
    },
    PrivilegeRequirement {
        id: "proxmox.guest.reboot",
        capability: "proxmox.guest.reboot",
        tier: PrivilegeTier::Operate,
        endpoint: "POST /nodes/{node}/qemu/{vmid}/status/reboot",
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.PowerMgmt"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Guest lifecycle.",
    },
    // ── destructive ─────────────────────────────────────────────────────
    PrivilegeRequirement {
        id: "proxmox.guest.snapshot.list",
        capability: "proxmox.guest.snapshot",
        tier: PrivilegeTier::Destructive,
        endpoint: "GET /nodes/{node}/qemu/{vmid}/snapshot",
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.Audit"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "The executor's idempotency check reads the snapshot list first.",
    },
    PrivilegeRequirement {
        id: "proxmox.guest.snapshot",
        capability: "proxmox.guest.snapshot",
        tier: PrivilegeTier::Destructive,
        endpoint: "POST /nodes/{node}/qemu/{vmid}/snapshot",
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.Snapshot"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Also with vmstate.",
    },
    PrivilegeRequirement {
        id: "proxmox.guest.snapshot-revert",
        capability: "proxmox.guest.snapshot-revert",
        tier: PrivilegeTier::Destructive,
        endpoint: "POST /nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback",
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.Snapshot", "VM.Snapshot.Rollback"],
        matching: PrivilegeMatch::Any,
        required: true,
        note: "Either privilege suffices (any => 1).",
    },
    PrivilegeRequirement {
        id: "proxmox.guest.snapshot-delete",
        capability: "proxmox.guest.snapshot-delete",
        tier: PrivilegeTier::Destructive,
        endpoint: "DELETE /nodes/{node}/qemu/{vmid}/snapshot/{snapname}",
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.Snapshot"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Snapshot removal.",
    },
    PrivilegeRequirement {
        id: "proxmox.guest.clone.list",
        capability: "proxmox.guest.clone",
        tier: PrivilegeTier::Destructive,
        endpoint: "GET /cluster/resources",
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.Audit"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "The executor's idempotency check lists guests before cloning.",
    },
    PrivilegeRequirement {
        id: "proxmox.guest.clone.source",
        capability: "proxmox.guest.clone",
        tier: PrivilegeTier::Destructive,
        endpoint: CLONE_ENDPOINT,
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.Clone"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Checked on the source guest.",
    },
    PrivilegeRequirement {
        id: "proxmox.guest.clone.target",
        capability: "proxmox.guest.clone",
        tier: PrivilegeTier::Destructive,
        endpoint: CLONE_ENDPOINT,
        majors: BOTH,
        scope: PrivilegeScope::NewGuest,
        privileges: &["VM.Allocate"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Checked on the new VMID; Fleet does not pass pool, so a pool ACL cannot authorize it.",
    },
    PrivilegeRequirement {
        id: "proxmox.guest.clone.storage",
        capability: "proxmox.guest.clone",
        tier: PrivilegeTier::Destructive,
        endpoint: CLONE_ENDPOINT,
        majors: BOTH,
        scope: PrivilegeScope::Storage,
        privileges: &["Datastore.AllocateSpace"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Checked on every non-CD-ROM disk's storage and on vmstatestorage.",
    },
    PrivilegeRequirement {
        id: "proxmox.guest.clone.bridge",
        capability: "proxmox.guest.clone",
        tier: PrivilegeTier::Destructive,
        endpoint: CLONE_ENDPOINT,
        majors: BOTH,
        scope: PrivilegeScope::SdnBridge,
        privileges: &["SDN.Use"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Checked for every netN bridge (and VLAN tag path) of the source.",
    },
    PrivilegeRequirement {
        id: "proxmox.guest.template.list",
        capability: "proxmox.guest.template",
        tier: PrivilegeTier::Destructive,
        endpoint: "GET /cluster/resources",
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.Audit"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "The executor's idempotency check lists guests before converting.",
    },
    PrivilegeRequirement {
        id: "proxmox.guest.template",
        capability: "proxmox.guest.template",
        tier: PrivilegeTier::Destructive,
        endpoint: "POST /nodes/{node}/qemu/{vmid}/template",
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.Allocate"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "VM.Allocate also permits deleting that guest; scope it to a pool.",
    },
    PrivilegeRequirement {
        id: "proxmox.task-cancel",
        capability: "proxmox.task-cancel",
        tier: PrivilegeTier::Destructive,
        endpoint: "DELETE /nodes/{node}/tasks/{upid}",
        majors: BOTH,
        scope: PrivilegeScope::Node,
        privileges: &[],
        matching: PrivilegeMatch::All,
        required: true,
        note: "No privilege for tasks the token started; another principal's task needs Sys.Modify, which Fleet does not request.",
    },
    // ── lab ─────────────────────────────────────────────────────────────
    PrivilegeRequirement {
        id: "lab.provision.template-lookup",
        capability: "lab.provision",
        tier: PrivilegeTier::Lab,
        endpoint: "GET /cluster/resources",
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.Audit"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "The provision executor finds the template by name in /cluster/resources, which hides guests without VM.Audit.",
    },
    PrivilegeRequirement {
        id: "lab.provision.clone-source",
        capability: "lab.provision",
        tier: PrivilegeTier::Lab,
        endpoint: CLONE_ENDPOINT,
        majors: BOTH,
        scope: PrivilegeScope::Guest,
        privileges: &["VM.Clone"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Checked on the pinned image's template.",
    },
    PrivilegeRequirement {
        id: "lab.provision.clone-target",
        capability: "lab.provision",
        tier: PrivilegeTier::Lab,
        endpoint: CLONE_ENDPOINT,
        majors: BOTH,
        scope: PrivilegeScope::NewGuest,
        privileges: &["VM.Allocate"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Checked on the lease guest's new VMID; a pool ACL cannot authorize it.",
    },
    PrivilegeRequirement {
        id: "lab.provision.clone-storage",
        capability: "lab.provision",
        tier: PrivilegeTier::Lab,
        endpoint: CLONE_ENDPOINT,
        majors: BOTH,
        scope: PrivilegeScope::Storage,
        privileges: &["Datastore.AllocateSpace"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Checked on every non-CD-ROM disk's storage of the template.",
    },
    PrivilegeRequirement {
        id: "lab.provision.clone-bridge",
        capability: "lab.provision",
        tier: PrivilegeTier::Lab,
        endpoint: CLONE_ENDPOINT,
        majors: BOTH,
        scope: PrivilegeScope::SdnBridge,
        privileges: &["SDN.Use"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Checked for every netN bridge of the template.",
    },
    PrivilegeRequirement {
        id: "lab.provision.start",
        capability: "lab.provision",
        tier: PrivilegeTier::Lab,
        endpoint: "POST /nodes/{node}/qemu/{vmid}/status/start",
        majors: BOTH,
        scope: PrivilegeScope::NewGuest,
        privileges: &["VM.PowerMgmt"],
        matching: PrivilegeMatch::All,
        required: true,
        note: "Starts the new lease guest, which is not a pool member.",
    },
    PrivilegeRequirement {
        id: "lab.provision.readiness-agent",
        capability: "lab.provision",
        tier: PrivilegeTier::Lab,
        endpoint: "GET /nodes/{node}/qemu/{vmid}/agent/info",
        majors: PVE9,
        scope: PrivilegeScope::NewGuest,
        privileges: &["VM.GuestAgent.Audit", "VM.GuestAgent.Unrestricted"],
        matching: PrivilegeMatch::Any,
        required: true,
        note: "The guest_agent readiness probe on the new guest.",
    },
    PrivilegeRequirement {
        id: "lab.provision.readiness-agent",
        capability: "lab.provision",
        tier: PrivilegeTier::Lab,
        endpoint: "GET /nodes/{node}/qemu/{vmid}/agent/info",
        majors: PVE8,
        scope: PrivilegeScope::NewGuest,
        privileges: &["VM.Monitor"],
        matching: PrivilegeMatch::All,
        required: false,
        note: "Opt-in on 8.x (VM.Monitor also permits agent exec); templates can use ssh_exec readiness instead.",
    },
];

/// The table rows that apply to one PVE major (8 or 9), in table order.
pub fn requirements_for_major(major: u8) -> impl Iterator<Item = &'static PrivilegeRequirement> {
    PROXMOX_PRIVILEGE_TABLE
        .iter()
        .filter(move |requirement| requirement.applies_to(major))
}

/// The table major to evaluate a PVE version with, plus a warning when the
/// version is outside [`SUPPORTED_PVE_MAJORS`]. `None` when the version has
/// no leading major number.
#[must_use]
pub fn rules_major_for(version: &str) -> Option<(u8, Option<String>)> {
    let major: u32 = version
        .split(['.', '-'])
        .next()
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))?
        .parse()
        .ok()?;
    let (oldest, newest) = (SUPPORTED_PVE_MAJORS[0], SUPPORTED_PVE_MAJORS[1]);
    if major > u32::from(newest) {
        Some((
            newest,
            Some(format!(
                "PVE {version} is newer than the privilege table; evaluated with the {newest}.x rules"
            )),
        ))
    } else if major < u32::from(oldest) {
        Some((
            oldest,
            Some(format!(
                "PVE {version} is older than the privilege table supports; evaluated with the {oldest}.x rules"
            )),
        ))
    } else {
        u8::try_from(major).ok().map(|major| (major, None))
    }
}

/// A tier's or check's outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivilegeStatus {
    /// The token holds what is needed somewhere in scope.
    Granted,
    /// The token lacks a needed privilege.
    Missing,
    /// Fleet could not determine the status; the report's reason says why.
    Unknown,
}

/// One requirement's outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivilegeCheck {
    /// The table row's id.
    pub requirement: String,
    /// The executor kind or read.
    pub capability: String,
    /// The PVE method and path.
    pub endpoint: String,
    /// Whether the tier needs it.
    pub required: bool,
    /// The outcome.
    pub status: PrivilegeStatus,
    /// The privileges the row names.
    pub privileges: Vec<String>,
    /// Whether any one of them suffices.
    pub any_of: bool,
    /// The ACL path template the privileges are checked on.
    pub path: String,
    /// The effective-map paths the requirement is satisfied on (bounded).
    pub granted_on: Vec<String>,
    /// Whether more paths satisfied the requirement than `granted_on` keeps.
    pub granted_on_truncated: bool,
    /// The privileges still missing on the closest path in scope.
    pub missing: Vec<String>,
    /// Why the row exists.
    pub note: String,
}

/// A missing privilege set and where to grant it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MissingPrivileges {
    /// The privileges to grant.
    pub privileges: Vec<String>,
    /// Whether any one of them suffices.
    pub any_of: bool,
    /// The ACL path template to grant them on.
    pub path: String,
    /// The capabilities that need them.
    pub capabilities: Vec<String>,
}

/// One tier's outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TierPrivileges {
    /// The tier.
    pub tier: PrivilegeTier,
    /// `granted` when every required check is granted.
    pub status: PrivilegeStatus,
    /// The required privileges the token lacks, merged per path.
    pub missing: Vec<MissingPrivileges>,
    /// Every check of the tier, required and opt-in.
    pub checks: Vec<PrivilegeCheck>,
}

/// The per-account privilege report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivilegeReport {
    /// The account evaluated.
    pub account_id: String,
    /// The PVE version read, when the read succeeded.
    pub pve_version: Option<String>,
    /// The table major the report was evaluated with.
    pub rules_major: Option<u8>,
    /// The four tiers, in order.
    pub tiers: Vec<TierPrivileges>,
    /// Why every tier is unknown, when the permissions read was refused.
    pub unknown_reason: Option<String>,
    /// The token's effective permissions as PVE reported them.
    pub effective_permissions: EffectivePermissions,
    /// Normalization and evaluation warnings.
    pub warnings: Vec<String>,
    /// When the report was taken (epoch millis).
    pub observed_at: i64,
}

/// Evaluates one requirement against the effective map, treating every
/// concrete `/vms/{id}` as a free clone target. A live report goes through
/// [`evaluate_requirement_with_vmids`] instead.
#[must_use]
pub fn evaluate_requirement(
    requirement: &PrivilegeRequirement,
    permissions: &EffectivePermissions,
) -> PrivilegeCheck {
    evaluate_requirement_with_vmids(requirement, permissions, None)
}

/// Evaluates one requirement. With `vmids_in_use`, a concrete `/vms/{id}`
/// counts toward a [`PrivilegeScope::NewGuest`] row only when that VMID was
/// checked and is free: a clone cannot target an existing VMID, so a grant
/// there is not a usable clone target.
#[must_use]
pub fn evaluate_requirement_with_vmids(
    requirement: &PrivilegeRequirement,
    permissions: &EffectivePermissions,
    vmids_in_use: Option<&BTreeMap<u32, bool>>,
) -> PrivilegeCheck {
    let mut check = PrivilegeCheck {
        requirement: requirement.id.to_owned(),
        capability: requirement.capability.to_owned(),
        endpoint: requirement.endpoint.to_owned(),
        required: requirement.required,
        status: PrivilegeStatus::Granted,
        privileges: requirement
            .privileges
            .iter()
            .map(|p| (*p).to_owned())
            .collect(),
        any_of: requirement.matching == PrivilegeMatch::Any,
        path: requirement.scope.template().to_owned(),
        granted_on: Vec::new(),
        granted_on_truncated: false,
        missing: Vec::new(),
        note: requirement.note.to_owned(),
    };
    if requirement.privileges.is_empty() {
        return check;
    }
    // The closest candidate: the in-scope path holding the most of the
    // row's privileges, for an actionable "missing" list.
    let mut best: Option<Vec<&str>> = None;
    for (path, privileges) in permissions {
        let Some(relation) = requirement.scope.relation(path) else {
            continue;
        };
        if requirement.scope == PrivilegeScope::NewGuest
            && relation == Relation::Exact
            && let Some(vmids_in_use) = vmids_in_use
            && path
                .strip_prefix("/vms/")
                .and_then(|id| id.parse::<u32>().ok())
                .is_none_or(|vmid| vmids_in_use.get(&vmid) != Some(&false))
        {
            continue;
        }
        let held: Vec<&str> = requirement
            .privileges
            .iter()
            .copied()
            .filter(|privilege| {
                privileges
                    .get(*privilege)
                    .is_some_and(|propagate| *propagate || relation != Relation::Propagated)
            })
            .collect();
        let satisfied = match requirement.matching {
            PrivilegeMatch::All => held.len() == requirement.privileges.len(),
            PrivilegeMatch::Any => !held.is_empty(),
        };
        if satisfied {
            if check.granted_on.len() < MAX_GRANTED_PATHS {
                check.granted_on.push(path.clone());
            } else {
                check.granted_on_truncated = true;
            }
        } else if best.as_ref().is_none_or(|best| held.len() > best.len()) {
            best = Some(held);
        }
    }
    if check.granted_on.is_empty() {
        check.status = PrivilegeStatus::Missing;
        let held = best.unwrap_or_default();
        check.missing = match requirement.matching {
            PrivilegeMatch::Any => check.privileges.clone(),
            PrivilegeMatch::All => requirement
                .privileges
                .iter()
                .filter(|privilege| !held.contains(privilege))
                .map(|privilege| (*privilege).to_owned())
                .collect(),
        };
    }
    check
}

/// Evaluates every tier for one table major, treating every concrete
/// `/vms/{id}` as a free clone target (see [`evaluate_tiers_with_vmids`]).
#[must_use]
pub fn evaluate_tiers(major: u8, permissions: &EffectivePermissions) -> Vec<TierPrivileges> {
    evaluate_tiers_with_vmids(major, permissions, None)
}

/// Evaluates every tier for one table major; `vmids_in_use` as for
/// [`evaluate_requirement_with_vmids`].
#[must_use]
pub fn evaluate_tiers_with_vmids(
    major: u8,
    permissions: &EffectivePermissions,
    vmids_in_use: Option<&BTreeMap<u32, bool>>,
) -> Vec<TierPrivileges> {
    PrivilegeTier::ALL
        .iter()
        .map(|tier| {
            let checks: Vec<PrivilegeCheck> = requirements_for_major(major)
                .filter(|requirement| requirement.tier == *tier)
                .map(|requirement| {
                    evaluate_requirement_with_vmids(requirement, permissions, vmids_in_use)
                })
                .collect();
            let mut missing: Vec<MissingPrivileges> = Vec::new();
            for check in checks
                .iter()
                .filter(|check| check.required && check.status == PrivilegeStatus::Missing)
            {
                if let Some(entry) = missing.iter_mut().find(|entry| {
                    entry.path == check.path
                        && entry.any_of == check.any_of
                        && entry.privileges == check.missing
                }) {
                    if !entry.capabilities.contains(&check.capability) {
                        entry.capabilities.push(check.capability.clone());
                    }
                } else {
                    missing.push(MissingPrivileges {
                        privileges: check.missing.clone(),
                        any_of: check.any_of,
                        path: check.path.clone(),
                        capabilities: vec![check.capability.clone()],
                    });
                }
            }
            TierPrivileges {
                tier: *tier,
                status: if missing.is_empty() {
                    PrivilegeStatus::Granted
                } else {
                    PrivilegeStatus::Missing
                },
                missing,
                checks,
            }
        })
        .collect()
}

/// Every tier `unknown`, carrying the checks the table would have run, so
/// a refused read still says what Fleet needs.
#[must_use]
pub fn unknown_tiers(major: Option<u8>) -> Vec<TierPrivileges> {
    PrivilegeTier::ALL
        .iter()
        .map(|tier| TierPrivileges {
            tier: *tier,
            status: PrivilegeStatus::Unknown,
            missing: Vec::new(),
            checks: major
                .map(|major| {
                    requirements_for_major(major)
                        .filter(|requirement| requirement.tier == *tier)
                        .map(|requirement| PrivilegeCheck {
                            status: PrivilegeStatus::Unknown,
                            ..evaluate_requirement(requirement, &EffectivePermissions::new())
                        })
                        .map(|check| PrivilegeCheck {
                            missing: Vec::new(),
                            ..check
                        })
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect()
}

/// The token-permissions port over one trusted account. The composition
/// implements it over the provider's `token_permissions` read.
#[async_trait]
pub trait ProxmoxPermissionsPort: std::fmt::Debug + Send + Sync {
    /// Reads the account token's own effective permissions and the PVE
    /// version.
    ///
    /// # Errors
    ///
    /// Fails with [`ProxmoxSourceError`]; a refused read is
    /// [`ProxmoxSourceError::Forbidden`].
    async fn token_permissions(
        &self,
        account: &ProxmoxAccount,
        secret: &SensitiveString,
    ) -> Result<RawTokenPermissions, ProxmoxSourceError>;
}

/// The provider's permissions read, translated at the boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawTokenPermissions {
    /// The PVE version string.
    pub version: String,
    /// The effective map.
    pub paths: EffectivePermissions,
    /// Normalization warnings.
    pub warnings: Vec<String>,
    /// Whether the provider's bounds dropped entries.
    pub truncated: bool,
    /// Concrete `/vms/{id}` VMIDs checked for being free: `true` when in
    /// use. Unchecked VMIDs are absent.
    pub vmids_in_use: BTreeMap<u32, bool>,
}

impl ProxmoxAccounts {
    /// Attaches the token-permissions port that [`Self::privileges`] reads
    /// through.
    #[must_use]
    pub fn with_permissions(mut self, permissions: Arc<dyn ProxmoxPermissionsPort>) -> Self {
        self.permissions = Some(permissions);
        self
    }

    /// Reports which capability tiers the account's token can perform. A
    /// read: `proxmox.read` on the account, no audit event, no mutation on
    /// either side. The explicit-trust gate applies as for every other
    /// credential-carrying call.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown or unconfirmed account, a missing
    /// secret, or a source failure other than a refused permissions read
    /// (which is the `unknown` report, not an error).
    pub async fn privileges(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
        now: i64,
    ) -> Result<PrivilegeReport, ProxmoxUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProxmoxRead,
                resource: Some(account_id),
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)?;
        let account = self.trusted_account(account_id).await?;
        let Some(port) = self.permissions.as_ref() else {
            return Err(ProxmoxUseCaseError::Backend {
                context: "privileges",
                detail: "the token-permissions read is not composed".to_owned(),
            });
        };
        let secret = self.require_secret(&account).await?;
        let raw = match port
            .token_permissions(&account, &SensitiveString::new(secret))
            .await
        {
            Ok(raw) => raw,
            Err(ProxmoxSourceError::Forbidden { detail }) => {
                return Ok(PrivilegeReport {
                    account_id: account.id,
                    pve_version: None,
                    rules_major: None,
                    tiers: unknown_tiers(None),
                    unknown_reason: Some(format!(
                        "the permissions read was refused (403): {detail}"
                    )),
                    effective_permissions: EffectivePermissions::new(),
                    warnings: Vec::new(),
                    observed_at: now,
                });
            }
            Err(error) => return Err(ProxmoxUseCaseError::Source(error)),
        };
        Ok(evaluate_report(account.id, raw, now))
    }
}

/// Builds the report from one permissions read.
#[must_use]
pub fn evaluate_report(account_id: String, raw: RawTokenPermissions, now: i64) -> PrivilegeReport {
    let mut warnings = raw.warnings;
    if raw.truncated {
        warnings.push(
            "the permissions map was truncated at the provider's bounds; a missing result may be incomplete"
                .to_owned(),
        );
    }
    let Some((major, version_warning)) = rules_major_for(&raw.version) else {
        return PrivilegeReport {
            account_id,
            pve_version: Some(raw.version.clone()),
            rules_major: None,
            tiers: unknown_tiers(None),
            unknown_reason: Some(format!(
                "the PVE version {:?} has no major number, so the privilege table cannot be keyed",
                raw.version
            )),
            effective_permissions: raw.paths,
            warnings,
            observed_at: now,
        };
    };
    warnings.extend(version_warning);
    let tiers = evaluate_tiers_with_vmids(major, &raw.paths, Some(&raw.vmids_in_use));
    // Say why a clone-target row is missing when the only VM.Allocate
    // grants sit on VMIDs that already exist.
    let new_guest_missing = tiers.iter().flat_map(|tier| &tier.checks).any(|check| {
        check.required
            && check.status == PrivilegeStatus::Missing
            && check.path == PrivilegeScope::NewGuest.template()
    });
    let taken: Vec<String> = raw
        .vmids_in_use
        .iter()
        .filter(|(vmid, in_use)| {
            **in_use
                && raw
                    .paths
                    .get(&format!("/vms/{vmid}"))
                    .is_some_and(|privileges| privileges.contains_key("VM.Allocate"))
        })
        .map(|(vmid, _)| vmid.to_string())
        .take(8)
        .collect();
    if new_guest_missing && !taken.is_empty() {
        warnings.push(format!(
            "VM.Allocate is granted on existing VMIDs ({}), which can't be clone targets; grant it on a free, reserved VMID",
            taken.join(", ")
        ));
    }
    PrivilegeReport {
        account_id,
        pve_version: Some(raw.version),
        rules_major: Some(major),
        tiers,
        unknown_reason: None,
        effective_permissions: raw.paths,
        warnings,
        observed_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: &[(&str, &[(&str, bool)])]) -> EffectivePermissions {
        entries
            .iter()
            .map(|(path, privileges)| {
                (
                    (*path).to_owned(),
                    privileges
                        .iter()
                        .map(|(name, propagate)| ((*name).to_owned(), *propagate))
                        .collect(),
                )
            })
            .collect()
    }

    fn tier(tiers: &[TierPrivileges], tier: PrivilegeTier) -> &TierPrivileges {
        tiers.iter().find(|entry| entry.tier == tier).unwrap()
    }

    fn check<'a>(tier: &'a TierPrivileges, id: &str) -> &'a PrivilegeCheck {
        tier.checks
            .iter()
            .find(|check| check.requirement == id)
            .unwrap()
    }

    const DISCOVER_9: &[(&str, bool)] = &[
        ("Sys.Audit", true),
        ("VM.Audit", true),
        ("Datastore.Audit", true),
        ("Pool.Audit", true),
        ("VM.GuestAgent.Audit", true),
    ];

    #[test]
    fn the_table_is_well_formed() {
        for major in SUPPORTED_PVE_MAJORS {
            let mut ids = std::collections::BTreeSet::new();
            for requirement in requirements_for_major(major) {
                assert!(
                    ids.insert(requirement.id),
                    "{} is duplicated for {major}.x",
                    requirement.id
                );
                assert!(
                    requirement.matching == PrivilegeMatch::All || requirement.privileges.len() > 1,
                    "{}: `any` needs alternatives",
                    requirement.id
                );
                assert!(!requirement.note.is_empty());
            }
            for tier in PrivilegeTier::ALL {
                assert!(
                    requirements_for_major(major).any(|r| r.tier == tier && r.required),
                    "{tier:?} has no required row for {major}.x"
                );
            }
        }
        // VM.Monitor exists only on 8.x; the guest-agent split only on 9.x.
        assert!(requirements_for_major(9).all(|r| !r.privileges.contains(&"VM.Monitor")));
        assert!(requirements_for_major(8).all(|r| {
            r.privileges
                .iter()
                .all(|p| !p.starts_with("VM.GuestAgent."))
        }));
        // Every executor kind the tiers name is in the table.
        for kind in [
            "proxmox.guest.start",
            "proxmox.guest.stop",
            "proxmox.guest.shutdown",
            "proxmox.guest.reboot",
            "proxmox.guest.snapshot",
            "proxmox.guest.snapshot-revert",
            "proxmox.guest.snapshot-delete",
            "proxmox.guest.clone",
            "proxmox.guest.template",
            "proxmox.task-cancel",
            "lab.provision",
        ] {
            assert!(
                PROXMOX_PRIVILEGE_TABLE.iter().any(|r| r.capability == kind),
                "{kind} is missing from the table"
            );
        }
    }

    #[test]
    fn versions_key_the_table_by_major() {
        assert_eq!(rules_major_for("9.2.2"), Some((9, None)));
        assert_eq!(rules_major_for("8.4.1"), Some((8, None)));
        assert_eq!(
            rules_major_for("10.0.1").map(|(m, w)| (m, w.is_some())),
            Some((9, true))
        );
        assert_eq!(
            rules_major_for("7.4-3").map(|(m, w)| (m, w.is_some())),
            Some((8, true))
        );
        assert_eq!(rules_major_for("unknown"), None);
        assert_eq!(rules_major_for(""), None);
    }

    #[test]
    fn a_root_grant_with_propagation_reaches_every_scope() {
        let all: Vec<(&str, bool)> = PROXMOX_PRIVILEGE_TABLE
            .iter()
            .flat_map(|r| r.privileges.iter().map(|p| (*p, true)))
            .collect();
        let permissions = map(&[("/", &all)]);
        for major in SUPPORTED_PVE_MAJORS {
            let tiers = evaluate_tiers(major, &permissions);
            for entry in &tiers {
                assert_eq!(entry.status, PrivilegeStatus::Granted, "{major}: {entry:?}");
                assert!(
                    entry
                        .checks
                        .iter()
                        .all(|c| c.status == PrivilegeStatus::Granted)
                );
            }
        }
    }

    #[test]
    fn a_non_propagating_root_grant_covers_only_root() {
        let permissions = map(&[("/", &[("VM.PowerMgmt", false), ("Sys.Audit", false)])]);
        let tiers = evaluate_tiers(9, &permissions);
        let operate = tier(&tiers, PrivilegeTier::Operate);
        assert_eq!(operate.status, PrivilegeStatus::Missing);
        assert_eq!(
            operate.missing,
            vec![MissingPrivileges {
                privileges: vec!["VM.PowerMgmt".to_owned()],
                any_of: false,
                path: "/vms/{vmid}".to_owned(),
                capabilities: vec![
                    "proxmox.guest.start".to_owned(),
                    "proxmox.guest.stop".to_owned(),
                    "proxmox.guest.shutdown".to_owned(),
                    "proxmox.guest.reboot".to_owned(),
                ],
            }]
        );
    }

    #[test]
    fn a_concrete_clone_target_counts_only_while_its_vmid_is_free() {
        let permissions = map(&[("/vms/9000", &[("VM.Allocate", false)])]);
        let clone_target = |vmids_in_use: Option<&BTreeMap<u32, bool>>| {
            let tiers = evaluate_tiers_with_vmids(9, &permissions, vmids_in_use);
            check(
                tier(&tiers, PrivilegeTier::Lab),
                "lab.provision.clone-target",
            )
            .status
        };
        // Pure evaluation (no live check) keeps treating it as free.
        assert_eq!(clone_target(None), PrivilegeStatus::Granted);
        assert_eq!(
            clone_target(Some(&[(9000, false)].into())),
            PrivilegeStatus::Granted
        );
        // In use, or never checked: not a usable target.
        assert_eq!(
            clone_target(Some(&[(9000, true)].into())),
            PrivilegeStatus::Missing
        );
        assert_eq!(
            clone_target(Some(&BTreeMap::new())),
            PrivilegeStatus::Missing
        );
        // A propagating grant on /vms reaches any new VMID regardless.
        let parent = map(&[("/vms", &[("VM.Allocate", true)])]);
        let tiers = evaluate_tiers_with_vmids(9, &parent, Some(&BTreeMap::new()));
        assert_eq!(
            check(
                tier(&tiers, PrivilegeTier::Lab),
                "lab.provision.clone-target"
            )
            .status,
            PrivilegeStatus::Granted
        );
    }

    #[test]
    fn granted_on_reports_when_paths_were_dropped() {
        let vms: Vec<String> = (0..MAX_GRANTED_PATHS + 4)
            .map(|vmid| format!("/vms/{}", 100 + vmid))
            .collect();
        let rows: Vec<(&str, &[(&str, bool)])> = vms
            .iter()
            .map(|path| (path.as_str(), &[("VM.PowerMgmt", false)][..]))
            .collect();
        let tiers = evaluate_tiers(9, &map(&rows));
        let start = check(tier(&tiers, PrivilegeTier::Operate), "proxmox.guest.start");
        assert_eq!(start.granted_on.len(), MAX_GRANTED_PATHS);
        assert!(start.granted_on_truncated);

        let one = map(&[("/vms/100", &[("VM.PowerMgmt", false)])]);
        let tiers = evaluate_tiers(9, &one);
        let start = check(tier(&tiers, PrivilegeTier::Operate), "proxmox.guest.start");
        assert!(!start.granted_on_truncated);
    }

    #[test]
    fn a_vm_grant_is_exact_and_needs_no_propagation() {
        let permissions = map(&[("/vms/100", &[("VM.PowerMgmt", false)])]);
        let tiers = evaluate_tiers(9, &permissions);
        let operate = tier(&tiers, PrivilegeTier::Operate);
        assert_eq!(operate.status, PrivilegeStatus::Granted);
        assert_eq!(
            check(operate, "proxmox.guest.start").granted_on,
            ["/vms/100"]
        );
    }

    #[test]
    fn lab_provision_needs_vm_audit_to_find_its_template() {
        // Every lab privilege except VM.Audit, propagated from the root:
        // /cluster/resources would hide the template, so lab is missing.
        let without_audit: Vec<(&str, bool)> = PROXMOX_PRIVILEGE_TABLE
            .iter()
            .filter(|r| r.tier == PrivilegeTier::Lab)
            .flat_map(|r| r.privileges.iter().copied())
            .filter(|p| *p != "VM.Audit")
            .map(|p| (p, true))
            .collect();
        for major in SUPPORTED_PVE_MAJORS {
            let tiers = evaluate_tiers(major, &map(&[("/", &without_audit)]));
            let lab = tier(&tiers, PrivilegeTier::Lab);
            assert_eq!(lab.status, PrivilegeStatus::Missing, "{major}.x");
            assert_eq!(
                lab.missing,
                vec![MissingPrivileges {
                    privileges: vec!["VM.Audit".to_owned()],
                    any_of: false,
                    path: "/vms/{vmid}".to_owned(),
                    capabilities: vec!["lab.provision".to_owned()],
                }],
                "{major}.x"
            );

            // VM.Audit on the template itself makes it visible.
            let tiers = evaluate_tiers(
                major,
                &map(&[("/", &without_audit), ("/vms/9000", &[("VM.Audit", false)])]),
            );
            let lab = tier(&tiers, PrivilegeTier::Lab);
            assert_eq!(lab.status, PrivilegeStatus::Granted, "{major}.x");
            assert_eq!(
                check(lab, "lab.provision.template-lookup").granted_on,
                ["/vms/9000"]
            );
        }
    }

    #[test]
    fn a_pool_grant_reaches_members_but_never_a_clone_target() {
        let pool: Vec<(&str, bool)> = [
            "VM.Audit",
            "VM.PowerMgmt",
            "VM.Snapshot",
            "VM.Clone",
            "VM.Allocate",
            "Datastore.AllocateSpace",
            "SDN.Use",
        ]
        .iter()
        .map(|p| (*p, false))
        .collect();
        let permissions = map(&[("/pool/fleet", &pool)]);
        let tiers = evaluate_tiers(9, &permissions);
        assert_eq!(
            tier(&tiers, PrivilegeTier::Operate).status,
            PrivilegeStatus::Granted
        );
        let destructive = tier(&tiers, PrivilegeTier::Destructive);
        assert_eq!(destructive.status, PrivilegeStatus::Missing);
        assert_eq!(
            check(destructive, "proxmox.guest.snapshot").granted_on,
            ["/pool/fleet"]
        );
        assert_eq!(
            check(destructive, "proxmox.guest.clone.storage").status,
            PrivilegeStatus::Granted,
            "pool storage members inherit"
        );
        // The bridge is not a pool member, and the new VMID is not either.
        let missing_paths: Vec<&str> = destructive
            .missing
            .iter()
            .map(|m| m.path.as_str())
            .collect();
        assert_eq!(
            missing_paths,
            ["/vms/{newid}", "/sdn/zones/{zone}/{bridge}"]
        );
    }

    #[test]
    fn a_clone_target_is_authorized_by_a_reserved_vmid_or_a_propagating_vms_grant() {
        for permissions in [
            map(&[("/vms/9000", &[("VM.Allocate", true)])]),
            map(&[("/vms", &[("VM.Allocate", true)])]),
        ] {
            let result = evaluate_requirement(
                PROXMOX_PRIVILEGE_TABLE
                    .iter()
                    .find(|r| r.id == "proxmox.guest.clone.target")
                    .unwrap(),
                &permissions,
            );
            assert_eq!(result.status, PrivilegeStatus::Granted, "{permissions:?}");
        }
        let not_propagating = map(&[("/vms", &[("VM.Allocate", false)])]);
        let result = evaluate_requirement(
            PROXMOX_PRIVILEGE_TABLE
                .iter()
                .find(|r| r.id == "proxmox.guest.clone.target")
                .unwrap(),
            &not_propagating,
        );
        assert_eq!(result.status, PrivilegeStatus::Missing);
    }

    #[test]
    fn storage_and_bridge_paths_inherit_from_their_roots_and_tags_count() {
        let permissions = map(&[
            ("/storage/local-lvm", &[("Datastore.AllocateSpace", false)]),
            ("/sdn/zones/localnetwork", &[("SDN.Use", true)]),
        ]);
        for id in ["proxmox.guest.clone.storage", "proxmox.guest.clone.bridge"] {
            let result = evaluate_requirement(
                PROXMOX_PRIVILEGE_TABLE.iter().find(|r| r.id == id).unwrap(),
                &permissions,
            );
            assert_eq!(result.status, PrivilegeStatus::Granted, "{id}");
        }
        let tagged = map(&[("/sdn/zones/localnetwork/vmbr0/20", &[("SDN.Use", false)])]);
        let result = evaluate_requirement(
            PROXMOX_PRIVILEGE_TABLE
                .iter()
                .find(|r| r.id == "proxmox.guest.clone.bridge")
                .unwrap(),
            &tagged,
        );
        assert_eq!(result.status, PrivilegeStatus::Granted);
    }

    #[test]
    fn any_of_rows_accept_either_privilege_and_report_both_when_missing() {
        let revert = PROXMOX_PRIVILEGE_TABLE
            .iter()
            .find(|r| r.id == "proxmox.guest.snapshot-revert")
            .unwrap();
        let rollback_only = map(&[("/vms/100", &[("VM.Snapshot.Rollback", false)])]);
        assert_eq!(
            evaluate_requirement(revert, &rollback_only).status,
            PrivilegeStatus::Granted
        );
        let none = map(&[("/vms/100", &[("VM.Audit", false)])]);
        let result = evaluate_requirement(revert, &none);
        assert_eq!(result.status, PrivilegeStatus::Missing);
        assert!(result.any_of);
        assert_eq!(result.missing, ["VM.Snapshot", "VM.Snapshot.Rollback"]);
    }

    #[test]
    fn all_rows_name_only_the_privileges_missing_on_the_closest_path() {
        let requirement = PrivilegeRequirement {
            id: "test.two",
            capability: "test",
            tier: PrivilegeTier::Destructive,
            endpoint: "GET /test",
            majors: BOTH,
            scope: PrivilegeScope::Guest,
            privileges: &["VM.Audit", "VM.Snapshot"],
            matching: PrivilegeMatch::All,
            required: true,
            note: "test",
        };
        let permissions = map(&[
            ("/vms/100", &[("VM.Audit", false)]),
            ("/vms/101", &[("VM.Clone", false)]),
        ]);
        let result = evaluate_requirement(&requirement, &permissions);
        assert_eq!(result.missing, ["VM.Snapshot"]);
    }

    #[test]
    fn the_guest_agent_privilege_differs_between_majors() {
        // A 9.x-style role: the guest-agent audit privilege, no VM.Monitor.
        let nine = map(&[("/", DISCOVER_9)]);
        let tiers = evaluate_tiers(9, &nine);
        let discover = tier(&tiers, PrivilegeTier::Discover);
        assert_eq!(discover.status, PrivilegeStatus::Granted);
        assert_eq!(
            check(discover, "read.guest-agent").privileges,
            ["VM.GuestAgent.Audit", "VM.GuestAgent.Unrestricted"]
        );

        // Without the agent privilege, 9.x discover is missing it…
        let no_agent = map(&[(
            "/",
            &[
                ("Sys.Audit", true),
                ("VM.Audit", true),
                ("Datastore.Audit", true),
                ("Pool.Audit", true),
            ],
        )]);
        let tiers = evaluate_tiers(9, &no_agent);
        let discover = tier(&tiers, PrivilegeTier::Discover);
        assert_eq!(discover.status, PrivilegeStatus::Missing);
        assert_eq!(discover.missing.len(), 1);
        assert_eq!(discover.missing[0].path, "/vms/{vmid}");
        assert!(discover.missing[0].any_of);
        assert_eq!(discover.missing[0].capabilities, ["read.guest-agent"]);

        // …while on 8.x the same token is granted: VM.Monitor is opt-in, and
        // its absence is reported on the check without gating the tier.
        let tiers = evaluate_tiers(8, &no_agent);
        let discover = tier(&tiers, PrivilegeTier::Discover);
        assert_eq!(discover.status, PrivilegeStatus::Granted);
        let agent = check(discover, "read.guest-agent");
        assert!(!agent.required);
        assert_eq!(agent.status, PrivilegeStatus::Missing);
        assert_eq!(agent.missing, ["VM.Monitor"]);
    }

    #[test]
    fn an_empty_map_misses_every_tier_with_named_paths() {
        let tiers = evaluate_tiers(9, &EffectivePermissions::new());
        for entry in &tiers {
            assert_eq!(entry.status, PrivilegeStatus::Missing, "{entry:?}");
            assert!(!entry.missing.is_empty());
        }
        let discover = tier(&tiers, PrivilegeTier::Discover);
        assert!(
            discover
                .missing
                .iter()
                .any(|m| m.path == "/nodes/{node}" && m.privileges == ["Sys.Audit"])
        );
        // The rows that need no privilege stay granted even then.
        assert_eq!(
            check(discover, "read.version").status,
            PrivilegeStatus::Granted
        );
    }

    #[test]
    fn reports_are_unknown_without_a_parsable_version() {
        let report = evaluate_report(
            "acc-1".to_owned(),
            RawTokenPermissions {
                version: "garbage".to_owned(),
                ..RawTokenPermissions::default()
            },
            7,
        );
        assert_eq!(report.rules_major, None);
        assert!(report.unknown_reason.is_some());
        assert!(
            report
                .tiers
                .iter()
                .all(|t| t.status == PrivilegeStatus::Unknown)
        );
    }

    #[test]
    fn unknown_tiers_still_name_their_checks_when_the_major_is_known() {
        let tiers = unknown_tiers(Some(9));
        assert!(tiers.iter().all(|t| !t.checks.is_empty()));
        assert!(
            tiers
                .iter()
                .flat_map(|t| &t.checks)
                .all(|c| c.status == PrivilegeStatus::Unknown && c.missing.is_empty())
        );
    }
}
