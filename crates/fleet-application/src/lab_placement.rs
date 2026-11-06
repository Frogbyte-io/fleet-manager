//! Lab placement and capacity reservation (FM-715).
//!
//! Provisioning a lease picks a Proxmox target and reserves the template's
//! CPU, memory, and disk on it in one SQLite transaction before the clone
//! (the only mutating external call) is requested. The rules live here;
//! the storage adapter runs [`check_capacity`] inside its transaction, so
//! two concurrent reservations can never both pass against the same free
//! capacity.
//!
//! The capacity model is deliberately conservative:
//!
//! - **Memory**: `total × memory_overcommit − used − reserved`. The observed
//!   `used` already includes running guests, Lab guests among them, so a
//!   running Lab guest is counted twice (as used and as reserved). That can
//!   refuse a lease that would have fit; it never admits one that does not.
//! - **CPU**: `cpu_count × cpu_overcommit − reserved cores`. Node CPU usage
//!   is a momentary ratio, not an allocation, so it is not subtracted.
//! - **Disk**: `storage total − storage used − reserved disk` on the storage
//!   pool the clone lands on, without overcommit.
//!
//! An observation older than the policy's maximum age refuses placement
//! rather than guessing; so does a node or storage pool with no observed
//! capacity.
//!
//! Selection follows the clone constraint: a full clone runs on the node
//! that holds the pinned template, so a candidate is an account whose
//! cluster reports the image's template VMID as a template. More than one
//! candidate is refused as ambiguous instead of ranked: two clusters can
//! each hold an unrelated template under the same VMID, and choosing
//! between them would risk cloning the wrong image.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use fleet_core::{
    DeviceStatus, HardwareDevice, HardwareReservation, HardwareReservationState, LabHardware,
    ReservationOwnerKind,
};
use serde::{Deserialize, Serialize};

use crate::hardware::{HardwareStore, HardwareStoreError};
use crate::hardware_inventory::view;
use crate::hardware_reservation::{
    AuditContext, HardwareReservations, ReserveDecision, ReserveRefusal, ReserveRequest,
};
use crate::proxmox::ProxmoxNodeCapacity;

const MIB: f64 = 1_048_576.0;
const GIB: u64 = 1_073_741_824;

/// The operator-configured placement policy.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PlacementPolicy {
    /// The memory overcommit ratio applied to a node's total memory.
    pub memory_overcommit: f64,
    /// The CPU overcommit ratio applied to a node's logical CPU count.
    pub cpu_overcommit: f64,
    /// How old (milliseconds) a capacity observation may be before
    /// placement refuses it.
    pub max_observation_age_ms: i64,
}

/// The default memory and CPU overcommit ratio: none.
pub const DEFAULT_OVERCOMMIT: f64 = 1.0;
/// The default maximum capacity observation age: five minutes.
pub const DEFAULT_MAX_OBSERVATION_AGE_SECONDS: u64 = 300;

impl Default for PlacementPolicy {
    fn default() -> Self {
        Self {
            memory_overcommit: DEFAULT_OVERCOMMIT,
            cpu_overcommit: DEFAULT_OVERCOMMIT,
            max_observation_age_ms: i64::try_from(DEFAULT_MAX_OBSERVATION_AGE_SECONDS * 1_000)
                .unwrap_or(i64::MAX),
        }
    }
}

/// The largest overcommit ratio the policy accepts.
pub const MAX_OVERCOMMIT: f64 = 16.0;

impl PlacementPolicy {
    /// Validates the ratios and the age bound.
    ///
    /// # Errors
    ///
    /// Fails when a ratio is not a finite number in `(0, 16]` or the age is
    /// not positive.
    pub fn validate(&self) -> Result<(), String> {
        for (name, ratio) in [
            ("memory overcommit", self.memory_overcommit),
            ("CPU overcommit", self.cpu_overcommit),
        ] {
            if !ratio.is_finite() || ratio <= 0.0 || ratio > MAX_OVERCOMMIT {
                return Err(format!(
                    "the {name} ratio must be greater than 0 and at most {MAX_OVERCOMMIT}"
                ));
            }
        }
        if self.max_observation_age_ms <= 0 {
            return Err("the maximum capacity observation age must be positive".to_owned());
        }
        Ok(())
    }
}

/// What one lease needs on its target: the template's resources, on the
/// storage pool its clone lands on.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapacityDemand {
    /// vCPU cores.
    pub cores: u32,
    /// Memory in MiB.
    pub memory_mib: u32,
    /// Disk in GiB.
    pub disk_gib: u32,
    /// The storage pool the disk is allocated on.
    pub storage: String,
}

impl CapacityDemand {
    /// The demand of a template's content on `storage`.
    #[must_use]
    pub fn for_template(content: &fleet_core::LabTemplateContent, storage: &str) -> Self {
        Self {
            cores: content.cores,
            memory_mib: content.memory_mib,
            disk_gib: content.disk_gib,
            storage: storage.to_owned(),
        }
    }
}

/// The live reservations already held against a node (and, for disk, the
/// demanded storage pool on it).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReservedTotals {
    /// Reserved cores on the node.
    pub cores: u64,
    /// Reserved memory on the node, in MiB.
    pub memory_mib: u64,
    /// Reserved disk on the demanded storage pool of the node, in GiB.
    pub disk_gib: u64,
}

/// Why a lease cannot be placed. The display text is the explanation the
/// caller sees; [`PlacementRefusal::reason`] is its stable id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlacementRefusal {
    /// No account can reach a node that holds the pinned template.
    NoCandidate {
        /// Why each configured account was not a candidate.
        detail: String,
    },
    /// More than one account reaches a template with the image's VMID.
    Ambiguous {
        /// The candidate accounts' names, with the node each reaches.
        candidates: Vec<String>,
    },
    /// A trusted account's cluster could not be read, so the candidates
    /// cannot be known to be unique.
    Unresolved {
        /// Each unresolved account with why.
        accounts: Vec<String>,
    },
    /// No capacity observation exists for the node.
    NotObserved {
        /// The node.
        node: String,
    },
    /// The node's latest capacity observation is older than the policy
    /// allows.
    Stale {
        /// The node.
        node: String,
        /// The observation's age in seconds.
        age_seconds: i64,
        /// The policy's maximum age in seconds.
        max_age_seconds: i64,
    },
    /// The node's latest observation is dated after now (the clock moved
    /// backwards), so its age is unknown.
    FutureDated {
        /// The node.
        node: String,
    },
    /// The observation lacks a figure the check needs.
    CapacityUnknown {
        /// The node.
        node: String,
        /// The missing figure.
        what: &'static str,
    },
    /// The demanded storage pool was not observed on the node.
    StorageNotObserved {
        /// The node.
        node: String,
        /// The storage pool.
        storage: String,
    },
    /// Not enough memory.
    InsufficientMemory {
        /// The node.
        node: String,
        /// The template's memory.
        need_mib: u64,
        /// The free memory after overcommit, usage, and reservations.
        free_mib: u64,
    },
    /// Not enough CPU.
    InsufficientCpu {
        /// The node.
        node: String,
        /// The template's cores.
        need_cores: u64,
        /// The unreserved cores after overcommit.
        free_cores: u64,
    },
    /// Not enough disk.
    InsufficientDisk {
        /// The node.
        node: String,
        /// The storage pool.
        storage: String,
        /// The template's disk.
        need_gib: u64,
        /// The free disk after usage and reservations.
        free_gib: u64,
    },
    /// The lease already holds a reservation for another target or demand
    /// (the template moved, or a re-promotion changed the pinned build's
    /// storage pool).
    ReservationMismatch {
        /// The held reservation's target and demand.
        held: String,
        /// The requested target and demand.
        requested: String,
    },
    /// The template declares hardware the account's inventory has no
    /// device for (FM-1121).
    HardwareNotInventoried {
        /// The declared PVE mapping id.
        mapping: String,
        /// The account whose inventory was searched.
        account_id: String,
    },
    /// The declared device's mapping has no entry for any node, so no node
    /// can host it.
    HardwareNoNodeEntry {
        /// The declared PVE mapping id.
        mapping: String,
    },
    /// The declared device is not on the node the clone runs on. Lab clones
    /// on the node that holds the pinned template (its clone call sends no
    /// `target`, though Proxmox could clone onto another node on shared
    /// storage), and a path-based mapping entry is bound to one node, so the
    /// two constraints do not meet.
    HardwareNodeConflict {
        /// The declared PVE mapping id.
        mapping: String,
        /// The node the clone runs on.
        clone_node: String,
        /// The nodes the device is on.
        device_nodes: Vec<String>,
        /// Whether the device was recently seen on those nodes (`true`), or
        /// they are only the nodes the mapping has entries for.
        seen: bool,
    },
    /// The device was not seen on the clone's node recently enough to
    /// reserve it on that observation.
    HardwareStale {
        /// The declared PVE mapping id.
        mapping: String,
        /// The node the clone runs on.
        node: String,
        /// The policy's maximum observation age in seconds.
        max_age_seconds: i64,
    },
    /// The device exists but cannot be reserved: not allocatable in its
    /// status, or held by another owner (`hardware_busy`, naming the
    /// holder). Queueing is a later decision; a conflict fails fast.
    HardwareRefused {
        /// The declared PVE mapping id.
        mapping: String,
        /// Why the reservation was refused.
        refusal: ReserveRefusal,
        /// The cause in words, when the device is `unsupported` for an
        /// account-level reason its fixed text cannot carry (#596).
        detail: Option<String>,
    },
}

impl PlacementRefusal {
    /// The stable reason id the provision operation fails with.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NoCandidate { .. } => "placement_no_candidate",
            Self::Ambiguous { .. } => "placement_ambiguous",
            Self::Unresolved { .. } => "placement_unresolved",
            Self::NotObserved { .. } | Self::CapacityUnknown { .. } => "capacity_unknown",
            Self::StorageNotObserved { .. } => "storage_unknown",
            Self::Stale { .. } | Self::FutureDated { .. } => "capacity_stale",
            Self::InsufficientMemory { .. } => "insufficient_memory",
            Self::InsufficientCpu { .. } => "insufficient_cpu",
            Self::InsufficientDisk { .. } => "insufficient_disk",
            Self::ReservationMismatch { .. } => "reservation_mismatch",
            Self::HardwareNotInventoried { .. } => "hardware_unknown",
            Self::HardwareNoNodeEntry { .. } => "hardware_no_node_entry",
            Self::HardwareNodeConflict { .. } => "hardware_wrong_node",
            Self::HardwareStale { .. } => "hardware_stale",
            Self::HardwareRefused { refusal, .. } => refusal.reason(),
        }
    }
}

impl PlacementRefusal {
    /// The extra audit facts of a hardware refusal: the declared mapping and,
    /// for a busy device, who holds it. Ids and states only; empty for every
    /// other refusal.
    #[must_use]
    pub fn hardware_audit_facts(&self) -> Vec<(&'static str, String)> {
        let (Self::HardwareNotInventoried { mapping, .. }
        | Self::HardwareNoNodeEntry { mapping }
        | Self::HardwareNodeConflict { mapping, .. }
        | Self::HardwareStale { mapping, .. }
        | Self::HardwareRefused { mapping, .. }) = self
        else {
            return Vec::new();
        };
        let mut facts = vec![("mapping", mapping.clone())];
        if let Self::HardwareRefused { refusal, .. } = self {
            match refusal {
                ReserveRefusal::Busy { holder } => {
                    facts.push(("holder_kind", holder.owner_kind.id().to_owned()));
                    facts.push(("holder_id", holder.owner_id.clone()));
                    facts.push(("holder_reservation_id", holder.id.clone()));
                    facts.push(("holder_state", holder.state.id().to_owned()));
                }
                ReserveRefusal::NotAllocatable { status } => {
                    facts.push(("device_status", status.id().to_owned()));
                    if let Some(reason) = status.reason() {
                        facts.push(("unsupported_reason", reason.id().to_owned()));
                    }
                }
                _ => {}
            }
        }
        facts
    }
}

impl fmt::Display for PlacementRefusal {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCandidate { detail } => write!(
                f,
                "no configured Proxmox account reaches the pinned image's template: {detail}"
            ),
            Self::Ambiguous { candidates } => write!(
                f,
                "more than one account reaches a template with the pinned image's VMID ({}); pass --account to choose",
                candidates.join(", ")
            ),
            Self::Unresolved { accounts } => write!(
                f,
                "cannot place automatically while a trusted account's cluster is unreadable ({}); retry, or pass --account to choose",
                accounts.join("; ")
            ),
            Self::NotObserved { node } => {
                write!(f, "no capacity observation exists for {node}")
            }
            Self::Stale {
                node,
                age_seconds,
                max_age_seconds,
            } => write!(
                f,
                "the capacity observation for {node} is {age_seconds}s old (the limit is {max_age_seconds}s); refusing to place on stale capacity"
            ),
            Self::FutureDated { node } => write!(
                f,
                "the capacity observation for {node} is dated in the future; refusing to place until it is refreshed"
            ),
            Self::CapacityUnknown { node, what } => {
                write!(f, "the {what} of {node} was not observed")
            }
            Self::StorageNotObserved { node, storage } => {
                write!(f, "storage {storage} was not observed on {node}")
            }
            Self::InsufficientMemory {
                node,
                need_mib,
                free_mib,
            } => write!(
                f,
                "insufficient memory on {node}: need {need_mib} MiB, {free_mib} free"
            ),
            Self::InsufficientCpu {
                node,
                need_cores,
                free_cores,
            } => write!(
                f,
                "insufficient CPU on {node}: need {need_cores} cores, {free_cores} unreserved"
            ),
            Self::InsufficientDisk {
                node,
                storage,
                need_gib,
                free_gib,
            } => write!(
                f,
                "insufficient disk on {node} storage {storage}: need {need_gib} GiB, {free_gib} free"
            ),
            Self::ReservationMismatch { held, requested } => write!(
                f,
                "the lease holds capacity for {held}, but this provision requests {requested}; release the lease and request a new one"
            ),
            Self::HardwareNotInventoried {
                mapping,
                account_id,
            } => write!(
                f,
                "hardware {mapping} is not in the inventory of account {account_id}; an operator creates the Proxmox USB mapping and refreshes the inventory (fleetctl hardware refresh --account {account_id})"
            ),
            Self::HardwareNoNodeEntry { mapping } => write!(
                f,
                "hardware {mapping} has no entry for any node, so no node can host it; an operator adds a node entry to the Proxmox mapping and refreshes the inventory"
            ),
            Self::HardwareNodeConflict {
                mapping,
                clone_node,
                device_nodes,
                seen,
            } => {
                let nodes = device_nodes.join(", ");
                write!(
                    f,
                    "hardware {mapping} {} node {nodes}, but the pinned image's template, and so Lab's clone, is on node {clone_node} (Lab clones on the template's node); the template needs an image whose template is on {nodes} or the mapping an entry for {clone_node}",
                    if *seen {
                        "is present on"
                    } else {
                        "is mapped only on"
                    },
                )
            }
            Self::HardwareStale {
                mapping,
                node,
                max_age_seconds,
            } => write!(
                f,
                "hardware {mapping} was not seen on node {node} within the last {max_age_seconds}s; refusing to reserve it on a stale observation (refresh the inventory and retry)"
            ),
            Self::HardwareRefused {
                mapping,
                refusal,
                detail,
            } => match refusal {
                ReserveRefusal::NotAllocatable {
                    status: DeviceStatus::Unsupported(reason),
                } => write!(
                    f,
                    "hardware {mapping} is unsupported ({}): {}",
                    reason.id(),
                    detail
                        .as_deref()
                        .unwrap_or_else(|| crate::hardware_inventory::reason_text(*reason))
                ),
                other => write!(f, "hardware {mapping} cannot be reserved: {other}"),
            },
        }
    }
}

impl std::error::Error for PlacementRefusal {}

#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn scaled_floor(value: u64, ratio: f64) -> i128 {
    (value as f64 * ratio).floor() as i128
}

fn non_negative(value: i128) -> u64 {
    u64::try_from(value.max(0)).unwrap_or(u64::MAX)
}

/// Checks one demand against a node's observation and its live
/// reservations. Storage runs this inside the reservation transaction.
///
/// # Errors
///
/// Returns the refusal explaining the first constraint that fails: a
/// missing or stale observation, then memory, CPU, and disk.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
pub fn check_capacity(
    node: &str,
    observation: Option<&ProxmoxNodeCapacity>,
    reserved: ReservedTotals,
    demand: &CapacityDemand,
    policy: &PlacementPolicy,
    now: i64,
) -> Result<(), PlacementRefusal> {
    let Some(observation) = observation else {
        return Err(PlacementRefusal::NotObserved {
            node: node.to_owned(),
        });
    };
    let age = now.saturating_sub(observation.observed_at);
    if age < 0 {
        // Dated after `now`: the clock moved backwards since it was taken,
        // so its real age is unknown.
        return Err(PlacementRefusal::FutureDated {
            node: node.to_owned(),
        });
    }
    if age > policy.max_observation_age_ms {
        return Err(PlacementRefusal::Stale {
            node: node.to_owned(),
            age_seconds: age.saturating_add(999) / 1_000,
            max_age_seconds: policy.max_observation_age_ms / 1_000,
        });
    }
    let unknown = |what| PlacementRefusal::CapacityUnknown {
        node: node.to_owned(),
        what,
    };
    let total = observation
        .memory_total_bytes
        .ok_or_else(|| unknown("total memory"))?;
    let used = observation
        .memory_used_bytes
        .ok_or_else(|| unknown("used memory"))?;
    let capacity_mib = ((total as f64 * policy.memory_overcommit) / MIB).floor() as i128;
    let used_mib = (used as f64 / MIB).ceil() as i128;
    let free_mib = capacity_mib - used_mib - i128::from(reserved.memory_mib);
    if free_mib < i128::from(demand.memory_mib) {
        return Err(PlacementRefusal::InsufficientMemory {
            node: node.to_owned(),
            need_mib: u64::from(demand.memory_mib),
            free_mib: non_negative(free_mib),
        });
    }
    let cpus = observation.cpu_count.ok_or_else(|| unknown("CPU count"))?;
    let free_cores = scaled_floor(cpus, policy.cpu_overcommit) - i128::from(reserved.cores);
    if free_cores < i128::from(demand.cores) {
        return Err(PlacementRefusal::InsufficientCpu {
            node: node.to_owned(),
            need_cores: u64::from(demand.cores),
            free_cores: non_negative(free_cores),
        });
    }
    let Some(storage) = observation
        .storages
        .iter()
        .find(|storage| storage.storage == demand.storage)
    else {
        return Err(PlacementRefusal::StorageNotObserved {
            node: node.to_owned(),
            storage: demand.storage.clone(),
        });
    };
    let disk_free = i128::from(storage.total_bytes.saturating_sub(storage.used_bytes) / GIB)
        - i128::from(reserved.disk_gib);
    if disk_free < i128::from(demand.disk_gib) {
        return Err(PlacementRefusal::InsufficientDisk {
            node: node.to_owned(),
            storage: demand.storage.clone(),
            need_gib: u64::from(demand.disk_gib),
            free_gib: non_negative(disk_free),
        });
    }
    Ok(())
}

/// One placement candidate: an account and the node it would clone on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementCandidate {
    /// The account's identity.
    pub account_id: String,
    /// The account's display name, for explanations.
    pub account_name: String,
    /// The node that holds the pinned template in that account's cluster.
    pub node: String,
}

/// Selects the target among the accounts that can reach the pinned
/// template. `skipped` explains each trusted-or-not account confirmed not to
/// be a candidate; `unresolved` names each trusted account whose cluster
/// could not be read. Any unresolved account refuses: it could hold a
/// same-VMID template, so a sole visible match is not proof of uniqueness.
///
/// # Errors
///
/// No candidate, or more than one (see the module docs).
pub fn select_candidate(
    mut candidates: Vec<PlacementCandidate>,
    skipped: &[String],
    unresolved: &[String],
) -> Result<PlacementCandidate, PlacementRefusal> {
    if !unresolved.is_empty() {
        return Err(PlacementRefusal::Unresolved {
            accounts: unresolved.to_vec(),
        });
    }
    match candidates.len() {
        0 => Err(PlacementRefusal::NoCandidate {
            detail: if skipped.is_empty() {
                "no Proxmox account is configured".to_owned()
            } else {
                skipped.join("; ")
            },
        }),
        1 => Ok(candidates.remove(0)),
        _ => {
            candidates.sort_by(|left, right| left.account_name.cmp(&right.account_name));
            Err(PlacementRefusal::Ambiguous {
                candidates: candidates
                    .iter()
                    .map(|candidate| format!("{} on {}", candidate.account_name, candidate.node))
                    .collect(),
            })
        }
    }
}

/// A reservation's lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    /// Counts against the node's capacity.
    Held,
    /// No longer counts; kept as history.
    Released,
}

impl ReservationState {
    /// The stable storage id.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Released => "released",
        }
    }
}

/// One lease's capacity reservation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapacityReservation {
    /// The reservation's identity.
    pub id: String,
    /// The lease it belongs to (one reservation per lease).
    pub lease_id: String,
    /// The account the guest is cloned through.
    pub account_id: String,
    /// The node it reserves on.
    pub node: String,
    /// What it reserves.
    pub demand: CapacityDemand,
    /// Whether it still counts.
    pub state: ReservationState,
    /// When it was reserved (epoch millis).
    pub created_at: i64,
    /// When it was released (epoch millis), once it was.
    pub released_at: Option<i64>,
}

/// A reservation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationRequest {
    /// The lease the reservation belongs to.
    pub lease_id: String,
    /// The account the guest will be cloned through.
    pub account_id: String,
    /// The node the clone runs on.
    pub node: String,
    /// What the lease needs.
    pub demand: CapacityDemand,
}

impl ReservationRequest {
    /// Checks that `held`, the lease's existing reservation, covers this
    /// request: the same account, node, and demand (cores, memory, disk, and
    /// storage pool). A held reservation is never silently reused for
    /// another target, since its counted capacity would not be where the
    /// clone lands.
    ///
    /// # Errors
    ///
    /// Returns [`PlacementRefusal::ReservationMismatch`] naming both.
    pub fn covered_by(&self, held: &CapacityReservation) -> Result<(), PlacementRefusal> {
        if held.account_id == self.account_id
            && held.node == self.node
            && held.demand == self.demand
        {
            return Ok(());
        }
        let describe = |account: &str, node: &str, demand: &CapacityDemand| {
            format!(
                "node {node} of account {account} ({} cores, {} MiB, {} GiB on {})",
                demand.cores, demand.memory_mib, demand.disk_gib, demand.storage
            )
        };
        Err(PlacementRefusal::ReservationMismatch {
            held: describe(&held.account_id, &held.node, &held.demand),
            requested: describe(&self.account_id, &self.node, &self.demand),
        })
    }
}

/// The outcome of [`CapacityReservationPort::reserve`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReserveOutcome {
    /// The lease holds this reservation (new, or the one it already held).
    Reserved(CapacityReservation),
    /// The capacity check refused it; nothing was written.
    Refused(PlacementRefusal),
}

/// The capacity observation and reservation storage port.
#[async_trait]
pub trait CapacityReservationPort: fmt::Debug + Send + Sync {
    /// Records (replaces) the latest capacity observation of a node as seen
    /// through an account.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn record_observation(
        &self,
        account_id: &str,
        observation: &ProxmoxNodeCapacity,
    ) -> Result<(), String>;

    /// Reserves the demand for a lease in one transaction: reads the node's
    /// latest observation through the request's account and the node's held
    /// reservations, applies [`check_capacity`], and inserts only when it
    /// passes. A lease that already holds a reservation gets it back
    /// unchanged, so a resumed provision does not reserve twice.
    ///
    /// # Errors
    ///
    /// Fails when the lease's reservation was already released (the lease is
    /// over) or the backend errors.
    async fn reserve(
        &self,
        request: &ReservationRequest,
        policy: &PlacementPolicy,
        now: i64,
    ) -> Result<ReserveOutcome, String>;

    /// Releases the lease's held reservation. Answers whether one was held.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn release_for_lease(&self, lease_id: &str, now: i64) -> Result<bool, String>;

    /// The lease's reservation, held or released, when it has one.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn for_lease(&self, lease_id: &str) -> Result<Option<CapacityReservation>, String>;
}

/// Where a promoted image's template disk lives: the storage pool a full
/// clone of it lands on, so the reservation checks that pool's capacity.
#[async_trait]
pub trait ImageStoragePort: fmt::Debug + Send + Sync {
    /// The storage pool of the image version's latest successful build,
    /// when one is recorded.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read.
    async fn template_storage(&self, image_version_id: &str) -> Result<Option<String>, String>;
}

// ── hardware (FM-1121, ADR 0019) ────────────────────────────────────────

/// A declared device as the account's inventory has it.
#[derive(Clone, Debug)]
pub struct DeclaredDevice {
    /// The declared PVE mapping id.
    pub mapping: String,
    /// The inventoried device and its live reservation, when the account's
    /// inventory has the mapping.
    pub found: Option<(HardwareDevice, Option<HardwareReservation>)>,
}

/// What the hardware rule checks a lease's declared devices against.
#[derive(Clone, Copy, Debug)]
pub struct HardwareCheck<'a> {
    /// The account the clone is made through.
    pub account_id: &'a str,
    /// The node the clone runs on: the node that holds the pinned template.
    /// It is fixed before hardware is considered: Lab does not move it.
    pub clone_node: &'a str,
    /// The clock, in epoch milliseconds.
    pub now: i64,
    /// How old (milliseconds) a device observation may be.
    pub max_age_ms: i64,
}

/// Checks the declared devices against the clone's node and the devices'
/// states, without reserving anything, and answers the device ids in
/// declaration order. The first constraint that fails refuses, and its
/// message names it.
///
/// The node comes from the mapping: a mapping entry is bound to one node (a
/// path-based entry names a physical port on it), so a device can serve a
/// clone only on a node it has an entry for, and where it was seen recently
/// when it was seen anywhere. The clone's node is already fixed (the full
/// clone runs on the template's node), so this intersects the two and
/// refuses when they do not meet. The rest are status refusals, in the
/// order of how permanent they are: not inventoried, no node entry, wrong
/// node, not allocatable (unsupported, externally attached, quarantined,
/// missing), stale. A device a live reservation holds is not refused here,
/// whoever holds it: that is the reservation store's decision (`hardware_busy`
/// naming the holder), made inside its transaction against the owner's
/// current state.
///
/// # Errors
///
/// The refusal for the first declared device that cannot be used.
pub fn check_hardware(
    declared: &[DeclaredDevice],
    check: &HardwareCheck<'_>,
) -> Result<Vec<String>, PlacementRefusal> {
    let mut ids = Vec::with_capacity(declared.len());
    for declared_device in declared {
        let mapping = declared_device.mapping.clone();
        let Some((device, holder)) = &declared_device.found else {
            return Err(PlacementRefusal::HardwareNotInventoried {
                mapping,
                account_id: check.account_id.to_owned(),
            });
        };
        check_device_node(device, check, &mapping)?;
        let seen = view(device.clone(), holder.clone(), check.now, check.max_age_ms);
        let refuse = |refusal| PlacementRefusal::HardwareRefused {
            mapping: mapping.clone(),
            refusal,
            detail: device.status_detail.clone(),
        };
        match seen.status {
            // `reserved` means a live row holds it: this lease's own (a
            // resumed provision), or another owner's, possibly in an unknown
            // state (`quarantined`, from that row). Whether another owner's
            // hold still counts (its lease may be over, which frees it) is
            // the reservation store's call inside its transaction, so a held
            // device is refused there, naming the holder, and not guessed
            // at here.
            DeviceStatus::Available | DeviceStatus::Reserved => {}
            DeviceStatus::Quarantined if holder.is_some() => {}
            // A stored `available` (or a derived `reserved` whose row is
            // gone) that outlived the bound was not seen recently: that is
            // a stale observation, not a device known to be absent.
            DeviceStatus::Missing
                if seen.stale
                    && matches!(
                        device.status,
                        DeviceStatus::Available | DeviceStatus::Reserved
                    ) =>
            {
                return Err(PlacementRefusal::HardwareStale {
                    mapping: mapping.clone(),
                    node: check.clone_node.to_owned(),
                    max_age_seconds: check.max_age_ms / 1_000,
                });
            }
            status @ (DeviceStatus::Missing
            | DeviceStatus::Unsupported(_)
            | DeviceStatus::ExternallyAttached
            | DeviceStatus::Quarantined) => {
                return Err(refuse(ReserveRefusal::NotAllocatable { status }));
            }
        }
        ids.push(device.id.clone());
    }
    Ok(ids)
}

/// Whether an observation time is within the bound (a time in the future,
/// from a clock step, is as untrustworthy as an old one; never seen is 0).
fn seen_recently(last_seen_at: i64, check: &HardwareCheck<'_>) -> bool {
    last_seen_at > 0 && check.now.saturating_sub(last_seen_at).abs() <= check.max_age_ms
}

/// Whether the device was seen on the clone's node within the bound.
fn observed_on_node(device: &HardwareDevice, check: &HardwareCheck<'_>) -> bool {
    device
        .entries
        .iter()
        .any(|entry| entry.node == check.clone_node && seen_recently(entry.last_seen_at, check))
}

/// The node half of [`check_hardware`] for one device.
fn check_device_node(
    device: &HardwareDevice,
    check: &HardwareCheck<'_>,
    mapping: &str,
) -> Result<(), PlacementRefusal> {
    if device.entries.is_empty() {
        return Err(PlacementRefusal::HardwareNoNodeEntry {
            mapping: mapping.to_owned(),
        });
    }
    let recent = |last_seen_at: i64| seen_recently(last_seen_at, check);
    let seen_nodes: Vec<String> = device
        .entries
        .iter()
        .filter(|entry| recent(entry.last_seen_at))
        .map(|entry| entry.node.clone())
        .collect();
    let conflict = |device_nodes: Vec<String>, seen: bool| PlacementRefusal::HardwareNodeConflict {
        mapping: mapping.to_owned(),
        clone_node: check.clone_node.to_owned(),
        device_nodes,
        seen,
    };
    match device
        .entries
        .iter()
        .find(|entry| entry.node == check.clone_node)
    {
        None if seen_nodes.is_empty() => Err(conflict(
            device
                .entries
                .iter()
                .map(|entry| entry.node.clone())
                .collect(),
            false,
        )),
        None => Err(conflict(seen_nodes, true)),
        Some(entry) if !recent(entry.last_seen_at) && !seen_nodes.is_empty() => {
            Err(conflict(seen_nodes, true))
        }
        Some(_) => Ok(()),
    }
}

/// A lease's declared devices and where they must go.
#[derive(Clone, Copy, Debug)]
pub struct HardwareDemand<'a> {
    /// The lease the devices are reserved for.
    pub lease_id: &'a str,
    /// The account the clone is made through; devices are looked up in its
    /// inventory.
    pub account_id: &'a str,
    /// The node the clone runs on.
    pub clone_node: &'a str,
    /// The template's declared devices.
    pub declared: &'a [LabHardware],
    /// The provision operation the step belongs to, for the audit trail.
    pub operation_id: Option<&'a str>,
}

/// The hardware part of Lab placement: looks the declared devices up,
/// applies [`check_hardware`], and reserves them for the lease in the
/// placement step, before any VMID is taken or anything is cloned. Nothing
/// here calls Proxmox: the attach is the saga's (FM-1123), which re-observes
/// and verifies right before it writes.
///
/// The compensation matches capacity's. A device reserved here is released
/// again when a later device in the same step refuses, when the lease fails
/// without allocating a guest ([`Self::release_unattached`] is what the
/// provision executor calls then), and when its cleanup completes; and the
/// reservation store itself stops honouring a `held` row whose lease no
/// longer counts, so a lost release write never strands a device.
#[derive(Debug)]
pub struct HardwarePlacement {
    store: Arc<dyn HardwareStore>,
    reservations: Arc<HardwareReservations>,
    max_age_ms: i64,
}

impl HardwarePlacement {
    /// Composes the hardware placement over the inventory store and the
    /// reservation use cases. `max_age_ms` is how old a device observation
    /// may be.
    #[must_use]
    pub fn new(
        store: Arc<dyn HardwareStore>,
        reservations: Arc<HardwareReservations>,
        max_age_ms: i64,
    ) -> Self {
        Self {
            store,
            reservations,
            max_age_ms: max_age_ms.max(1),
        }
    }

    /// Reserves every declared device for the lease, or none: a refusal
    /// releases what this call reserved before it. A declaration of nothing
    /// touches nothing, so a lease without hardware is unchanged. A repeat
    /// for the same lease (a resumed provision) gets its existing rows.
    ///
    /// The outer error is a store failure; the inner one the refusal the
    /// provision fails with.
    ///
    /// # Errors
    ///
    /// Fails when the hardware store fails.
    pub async fn reserve(
        &self,
        actor: &str,
        demand: &HardwareDemand<'_>,
        now: i64,
    ) -> Result<Result<Vec<HardwareReservation>, PlacementRefusal>, HardwareStoreError> {
        if demand.declared.is_empty() {
            return Ok(Ok(Vec::new()));
        }
        // Acquired in mapping order, so two leases that want the same pair
        // collide on the first device instead of each taking one.
        let mut mappings: Vec<&str> = demand
            .declared
            .iter()
            .map(|device| device.mapping.as_str())
            .collect();
        mappings.sort_unstable();
        mappings.dedup();
        let mut declared = Vec::with_capacity(mappings.len());
        for mapping in mappings {
            let found = match self
                .store
                .device_by_mapping(demand.account_id, mapping)
                .await?
            {
                Some(device) => {
                    let holder = self.store.live_reservation_for_device(&device.id).await?;
                    Some((device, holder))
                }
                None => None,
            };
            declared.push(DeclaredDevice {
                mapping: mapping.to_owned(),
                found,
            });
        }
        let check = HardwareCheck {
            account_id: demand.account_id,
            clone_node: demand.clone_node,
            now,
            max_age_ms: self.max_age_ms,
        };
        let device_ids = match check_hardware(&declared, &check) {
            Ok(ids) => ids,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let context = AuditContext {
            actor: actor.to_owned(),
            operation_id: demand.operation_id.map(str::to_owned),
        };
        let mut held = Vec::with_capacity(device_ids.len());
        let mut created = Vec::new();
        for (device_id, declared_device) in device_ids.into_iter().zip(&declared) {
            let request = ReserveRequest {
                device_id,
                owner_kind: ReservationOwnerKind::Lease,
                owner_id: demand.lease_id.to_owned(),
            };
            match self.reservations.reserve(&context, &request, now).await {
                Ok(ReserveDecision::Reserved {
                    reservation,
                    created: new,
                }) => {
                    if new {
                        created.push(reservation.id.clone());
                        // A live row held the device when it was looked up,
                        // so the pre-check left it to the store, and the
                        // store has now freed it because its owner no longer
                        // counts: a takeover. It still owes the freshness an
                        // available device owes (the store checks the stored
                        // status, not how old the observation is).
                        let taken_over = declared_device
                            .found
                            .as_ref()
                            .filter(|(_, holder)| holder.is_some());
                        if let Some((device, _)) = taken_over
                            && !observed_on_node(device, &check)
                        {
                            self.release_ids(&context, &created, now).await;
                            return Ok(Err(PlacementRefusal::HardwareStale {
                                mapping: declared_device.mapping.clone(),
                                node: demand.clone_node.to_owned(),
                                max_age_seconds: self.max_age_ms / 1_000,
                            }));
                        }
                    }
                    held.push(reservation);
                }
                Ok(ReserveDecision::Refused(refusal)) => {
                    self.release_ids(&context, &created, now).await;
                    return Ok(Err(PlacementRefusal::HardwareRefused {
                        mapping: declared_device.mapping.clone(),
                        refusal,
                        detail: declared_device
                            .found
                            .as_ref()
                            .and_then(|(device, _)| device.status_detail.clone()),
                    }));
                }
                Err(error) => {
                    self.release_ids(&context, &created, now).await;
                    return Err(error);
                }
            }
        }
        Ok(Ok(held))
    }

    /// Releases the reservations this step made when a later one failed.
    /// Best effort, like every capacity release: a row left behind belongs
    /// to a lease that is about to fail, and the store stops honouring it.
    async fn release_ids(&self, context: &AuditContext, ids: &[String], now: i64) {
        for id in ids {
            let _ = self.reservations.release(context, id, now).await;
        }
    }

    /// Releases the lease's reservations that never started an attach: a
    /// `held` row with no `usbN` slot. A row that attached, or whose attach
    /// or detach outcome is unknown, is left for the detach path that owns
    /// it (FM-1123): it is never released on the lease's word. Answers how
    /// many were released.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read. A release that loses a race (the
    /// row moved first) is not an error.
    pub async fn release_unattached(
        &self,
        actor: &str,
        lease_id: &str,
        operation_id: Option<&str>,
        now: i64,
    ) -> Result<usize, HardwareStoreError> {
        let context = AuditContext {
            actor: actor.to_owned(),
            operation_id: operation_id.map(str::to_owned),
        };
        let mut released = 0;
        for reservation in self
            .store
            .live_reservations_for_owner(ReservationOwnerKind::Lease, lease_id)
            .await?
        {
            let attached = reservation
                .guest
                .as_ref()
                .is_some_and(|guest| guest.usb_slot.is_some());
            if reservation.state != HardwareReservationState::Held || attached {
                continue;
            }
            if self
                .reservations
                .release(&context, &reservation.id, now)
                .await
                .is_ok()
            {
                released += 1;
            }
        }
        Ok(released)
    }
}

/// The audit event for a reservation transition (`lab_capacity_reserved`,
/// `lab_capacity_released`, or `lab_placement_refused`), attributed to the
/// controller acting for the authorized operation. Facts are node, storage,
/// and resource figures only; never provider output.
#[must_use]
pub fn reservation_audit(
    actor: &str,
    lease_id: &str,
    operation_id: Option<&str>,
    event: &str,
    facts: &[(&str, String)],
) -> crate::audit::AuditIntent {
    let mut metadata = crate::audit::AuditMetadata::default();
    let _ = metadata.insert("event", event);
    for (key, value) in facts {
        let _ = metadata.insert(key, value);
    }
    crate::audit::AuditIntent {
        actor: actor.to_owned(),
        action: crate::authz::Permission::LabProvision.id().to_owned(),
        resource: Some(lease_id.to_owned()),
        decision: crate::authz::Decision::allow(),
        correlation_id: None,
        operation_id: operation_id.map(str::to_owned),
        metadata,
    }
}

/// The audit facts describing a reservation.
#[must_use]
pub fn reservation_facts(reservation: &CapacityReservation) -> Vec<(&'static str, String)> {
    vec![
        ("node", reservation.node.clone()),
        ("storage", reservation.demand.storage.clone()),
        ("cores", reservation.demand.cores.to_string()),
        ("memory_mib", reservation.demand.memory_mib.to_string()),
        ("disk_gib", reservation.demand.disk_gib.to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxmox::ProxmoxStorageCapacity;

    const NOW: i64 = 1_800_000_000_000;
    const GIB_BYTES: u64 = 1 << 30;

    fn observation(memory_total_gib: u64, memory_used_gib: u64) -> ProxmoxNodeCapacity {
        ProxmoxNodeCapacity {
            node: "pve1".to_owned(),
            cpu_usage_ratio: Some(0.5),
            cpu_count: Some(8),
            memory_used_bytes: Some(memory_used_gib * GIB_BYTES),
            memory_total_bytes: Some(memory_total_gib * GIB_BYTES),
            storages: vec![ProxmoxStorageCapacity {
                storage: "local-lvm".to_owned(),
                used_bytes: 100 * GIB_BYTES,
                total_bytes: 200 * GIB_BYTES,
            }],
            observed_at: NOW - 1_000,
        }
    }

    fn demand(memory_mib: u32) -> CapacityDemand {
        CapacityDemand {
            cores: 2,
            memory_mib,
            disk_gib: 20,
            storage: "local-lvm".to_owned(),
        }
    }

    fn check(
        observation: Option<&ProxmoxNodeCapacity>,
        reserved: ReservedTotals,
        demand: &CapacityDemand,
        policy: &PlacementPolicy,
    ) -> Result<(), PlacementRefusal> {
        check_capacity("pve1", observation, reserved, demand, policy, NOW)
    }

    #[test]
    fn a_demand_that_fits_passes() {
        let policy = PlacementPolicy::default();
        assert_eq!(
            check(
                Some(&observation(16, 8)),
                ReservedTotals::default(),
                &demand(4096),
                &policy
            ),
            Ok(())
        );
    }

    #[test]
    fn insufficient_memory_explains_need_and_free() {
        let policy = PlacementPolicy::default();
        let refusal = check(
            Some(&observation(16, 8)),
            ReservedTotals {
                memory_mib: 6 * 1024,
                ..ReservedTotals::default()
            },
            &demand(4096),
            &policy,
        )
        .unwrap_err();
        assert_eq!(refusal.reason(), "insufficient_memory");
        assert_eq!(
            refusal.to_string(),
            "insufficient memory on pve1: need 4096 MiB, 2048 free"
        );
    }

    #[test]
    fn memory_overcommit_scales_the_total() {
        let mut policy = PlacementPolicy::default();
        assert!(
            check(
                Some(&observation(16, 14)),
                ReservedTotals::default(),
                &demand(4096),
                &policy
            )
            .is_err()
        );
        policy.memory_overcommit = 1.5;
        assert_eq!(
            check(
                Some(&observation(16, 14)),
                ReservedTotals::default(),
                &demand(4096),
                &policy
            ),
            Ok(())
        );
    }

    #[test]
    fn reserved_cores_and_disk_count() {
        let policy = PlacementPolicy::default();
        let cpu = check(
            Some(&observation(64, 0)),
            ReservedTotals {
                cores: 7,
                ..ReservedTotals::default()
            },
            &demand(1024),
            &policy,
        )
        .unwrap_err();
        assert_eq!(
            cpu.to_string(),
            "insufficient CPU on pve1: need 2 cores, 1 unreserved"
        );
        let disk = check(
            Some(&observation(64, 0)),
            ReservedTotals {
                disk_gib: 90,
                ..ReservedTotals::default()
            },
            &demand(1024),
            &policy,
        )
        .unwrap_err();
        assert_eq!(
            disk.to_string(),
            "insufficient disk on pve1 storage local-lvm: need 20 GiB, 10 free"
        );
    }

    #[test]
    fn stale_missing_and_partial_observations_refuse() {
        let policy = PlacementPolicy::default();
        let mut stale = observation(16, 0);
        stale.observed_at = NOW - 301_000;
        let refusal = check(
            Some(&stale),
            ReservedTotals::default(),
            &demand(1024),
            &policy,
        )
        .unwrap_err();
        assert_eq!(refusal.reason(), "capacity_stale");
        assert!(refusal.to_string().contains("301s old"), "{refusal}");
        // Just past the limit is reported past it, never "300s old".
        stale.observed_at = NOW - 300_001;
        let refusal = check(
            Some(&stale),
            ReservedTotals::default(),
            &demand(1024),
            &policy,
        )
        .unwrap_err();
        assert!(refusal.to_string().contains("301s old"), "{refusal}");
        // A future-dated observation (clock rollback) is refused too.
        stale.observed_at = NOW + 60_000;
        let refusal = check(
            Some(&stale),
            ReservedTotals::default(),
            &demand(1024),
            &policy,
        )
        .unwrap_err();
        assert_eq!(refusal.reason(), "capacity_stale");
        assert!(refusal.to_string().contains("in the future"), "{refusal}");

        assert_eq!(
            check(None, ReservedTotals::default(), &demand(1024), &policy)
                .unwrap_err()
                .reason(),
            "capacity_unknown"
        );
        let mut partial = observation(16, 0);
        partial.memory_total_bytes = None;
        assert_eq!(
            check(
                Some(&partial),
                ReservedTotals::default(),
                &demand(1024),
                &policy
            )
            .unwrap_err()
            .to_string(),
            "the total memory of pve1 was not observed"
        );
        let mut other = demand(1024);
        other.storage = "ceph".to_owned();
        assert_eq!(
            check(
                Some(&observation(16, 0)),
                ReservedTotals::default(),
                &other,
                &policy
            )
            .unwrap_err()
            .reason(),
            "storage_unknown"
        );
    }

    #[test]
    fn selection_needs_exactly_one_candidate() {
        let candidate = |name: &str| PlacementCandidate {
            account_id: format!("id-{name}"),
            account_name: name.to_owned(),
            node: "pve1".to_owned(),
        };
        assert_eq!(
            select_candidate(vec![candidate("a")], &[], &[]).unwrap(),
            candidate("a")
        );
        let none =
            select_candidate(Vec::new(), &["b: no template qemu/120".to_owned()], &[]).unwrap_err();
        assert_eq!(none.reason(), "placement_no_candidate");
        assert!(none.to_string().contains("b: no template qemu/120"));
        let many = select_candidate(vec![candidate("b"), candidate("a")], &[], &[]).unwrap_err();
        assert_eq!(
            many.to_string(),
            "more than one account reaches a template with the pinned image's VMID (a on pve1, b on pve1); pass --account to choose"
        );
        // A sole visible match with an unreadable trusted cluster refuses.
        let unresolved = select_candidate(
            vec![candidate("a")],
            &[],
            &["c: the cluster's resources are unreadable".to_owned()],
        )
        .unwrap_err();
        assert_eq!(unresolved.reason(), "placement_unresolved");
        assert!(
            unresolved.to_string().contains("c: the cluster"),
            "{unresolved}"
        );
    }

    #[test]
    fn policy_validation_bounds_the_ratios() {
        assert!(PlacementPolicy::default().validate().is_ok());
        for ratio in [0.0, -1.0, f64::NAN, 17.0] {
            let policy = PlacementPolicy {
                memory_overcommit: ratio,
                ..PlacementPolicy::default()
            };
            assert!(policy.validate().is_err(), "{ratio}");
        }
        let policy = PlacementPolicy {
            max_observation_age_ms: 0,
            ..PlacementPolicy::default()
        };
        assert!(policy.validate().is_err());
    }

    // ── hardware (FM-1121) ──────────────────────────────────────────────

    use fleet_core::{DeviceNodeEntry, HardwareKind, UnsupportedReason};

    const MAX_AGE: i64 = 900_000;

    fn node_entry(node: &str, last_seen_at: i64) -> DeviceNodeEntry {
        DeviceNodeEntry {
            node: node.to_owned(),
            vendor_id: "05ac".to_owned(),
            product_id: "1500".to_owned(),
            usbpath: Some("1-10".to_owned()),
            manufacturer: None,
            product: None,
            last_seen_at,
        }
    }

    fn device(
        mapping: &str,
        status: DeviceStatus,
        entries: Vec<DeviceNodeEntry>,
    ) -> HardwareDevice {
        HardwareDevice {
            id: format!("dev-{mapping}"),
            account_id: "acct".to_owned(),
            mapping_id: mapping.to_owned(),
            kind: HardwareKind::Usb,
            entries,
            status,
            note: None,
            status_detail: None,
            created_at: NOW - 1_000_000,
            updated_at: NOW - 1_000,
        }
    }

    fn fresh_on(node: &str) -> Vec<DeviceNodeEntry> {
        vec![node_entry(node, NOW - 1_000)]
    }

    fn holder(owner_id: &str, state: HardwareReservationState) -> HardwareReservation {
        HardwareReservation {
            id: "res-held".to_owned(),
            device_id: "dev-usb-a".to_owned(),
            owner_kind: ReservationOwnerKind::Lease,
            owner_id: owner_id.to_owned(),
            state,
            guest: None,
            created_at: NOW - 500,
            updated_at: NOW - 500,
            released_at: None,
        }
    }

    fn declared(
        mapping: &str,
        found: Option<(HardwareDevice, Option<HardwareReservation>)>,
    ) -> DeclaredDevice {
        DeclaredDevice {
            mapping: mapping.to_owned(),
            found,
        }
    }

    fn hardware_check(declared: &[DeclaredDevice]) -> Result<Vec<String>, PlacementRefusal> {
        check_hardware(
            declared,
            &HardwareCheck {
                account_id: "acct",
                clone_node: "pve-a",
                now: NOW,
                max_age_ms: MAX_AGE,
            },
        )
    }

    fn usable() -> DeclaredDevice {
        declared(
            "usb-a",
            Some((
                device("usb-a", DeviceStatus::Available, fresh_on("pve-a")),
                None,
            )),
        )
    }

    #[test]
    fn a_usable_device_on_the_clones_node_is_accepted_in_order() {
        let second = declared(
            "usb-b",
            Some((
                device("usb-b", DeviceStatus::Available, fresh_on("pve-a")),
                None,
            )),
        );
        assert_eq!(
            hardware_check(&[usable(), second]).unwrap(),
            vec!["dev-usb-a".to_owned(), "dev-usb-b".to_owned()]
        );
        assert_eq!(hardware_check(&[]).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn a_device_the_inventory_does_not_have_is_refused_naming_the_account() {
        let refusal = hardware_check(&[declared("usb-a", None)]).unwrap_err();
        assert_eq!(refusal.reason(), "hardware_unknown");
        let text = refusal.to_string();
        assert!(text.contains("hardware usb-a is not in the inventory of account acct"));
        assert!(
            text.contains("fleetctl hardware refresh --account acct"),
            "{text}"
        );
    }

    #[test]
    fn a_mapping_without_a_node_entry_is_refused() {
        let no_entry = device(
            "usb-a",
            DeviceStatus::Unsupported(UnsupportedReason::NoNodeEntry),
            Vec::new(),
        );
        let refusal = hardware_check(&[declared("usb-a", Some((no_entry, None)))]).unwrap_err();
        assert_eq!(refusal.reason(), "hardware_no_node_entry");
        assert!(
            refusal.to_string().contains("no entry for any node"),
            "{refusal}"
        );
    }

    #[test]
    fn a_device_on_another_node_is_refused_naming_both_constraints() {
        // Present on pve-b, the clone is on pve-a.
        let there = device("usb-a", DeviceStatus::Available, fresh_on("pve-b"));
        let refusal = hardware_check(&[declared("usb-a", Some((there, None)))]).unwrap_err();
        assert_eq!(refusal.reason(), "hardware_wrong_node");
        assert_eq!(
            refusal.to_string(),
            "hardware usb-a is present on node pve-b, but the pinned image's template, and so Lab's clone, is on node pve-a (Lab clones on the template's node); the template needs an image whose template is on pve-b or the mapping an entry for pve-a"
        );
        // Mapped on pve-b only and not seen anywhere recently: the message
        // says mapped, not present.
        let mapped = device(
            "usb-a",
            DeviceStatus::Missing,
            vec![node_entry("pve-b", NOW - 2 * MAX_AGE)],
        );
        let refusal = hardware_check(&[declared("usb-a", Some((mapped, None)))]).unwrap_err();
        assert_eq!(refusal.reason(), "hardware_wrong_node");
        assert!(
            refusal.to_string().contains("is mapped only on node pve-b"),
            "{refusal}"
        );
    }

    #[test]
    fn a_device_mapped_on_two_nodes_is_placed_where_it_was_seen() {
        // Entries for both nodes, but the device is on pve-b now: the clone
        // on pve-a cannot have it, though the mapping names pve-a.
        let moved = device(
            "usb-a",
            DeviceStatus::Available,
            vec![
                node_entry("pve-a", NOW - 2 * MAX_AGE),
                node_entry("pve-b", NOW - 1_000),
            ],
        );
        let refusal = hardware_check(&[declared("usb-a", Some((moved, None)))]).unwrap_err();
        assert_eq!(refusal.reason(), "hardware_wrong_node");
        assert!(refusal.to_string().contains("is present on node pve-b"));
        // Seen on both: the clone's node is one of them.
        let both = device(
            "usb-a",
            DeviceStatus::Available,
            vec![node_entry("pve-a", NOW - 10), node_entry("pve-b", NOW - 10)],
        );
        assert!(hardware_check(&[declared("usb-a", Some((both, None)))]).is_ok());
    }

    #[test]
    fn a_busy_refusal_names_the_holder_and_is_audited_with_it() {
        // `hardware_busy` is decided by the reservation store, which hands
        // placement the holder; the refusal says who has the device.
        let refusal = PlacementRefusal::HardwareRefused {
            mapping: "usb-a".to_owned(),
            refusal: ReserveRefusal::Busy {
                holder: Box::new(holder("lease-2", HardwareReservationState::Attached)),
            },
            detail: None,
        };
        assert_eq!(refusal.reason(), "hardware_busy");
        assert_eq!(
            refusal.to_string(),
            "hardware usb-a cannot be reserved: the device is reserved by lease lease-2 (reservation res-held, attached)"
        );
        assert_eq!(
            refusal.hardware_audit_facts(),
            vec![
                ("mapping", "usb-a".to_owned()),
                ("holder_kind", "lease".to_owned()),
                ("holder_id", "lease-2".to_owned()),
                ("holder_reservation_id", "res-held".to_owned()),
                ("holder_state", "attached".to_owned()),
            ]
        );
        assert!(
            PlacementRefusal::InsufficientCpu {
                node: "pve-a".to_owned(),
                need_cores: 2,
                free_cores: 1
            }
            .hardware_audit_facts()
            .is_empty()
        );
    }

    #[test]
    fn a_held_device_is_left_to_the_reservation_store() {
        // This lease's own row (a resumed provision), another lease's (the
        // store decides busy, or frees it if that lease is over) and an
        // unknown-state row all pass the pre-check on the node rule alone.
        for (owner, state) in [
            ("lease-1", HardwareReservationState::Held),
            ("lease-2", HardwareReservationState::Attached),
            ("lease-2", HardwareReservationState::AttachUnknown),
        ] {
            let held = device("usb-a", DeviceStatus::Reserved, fresh_on("pve-a"));
            assert_eq!(
                hardware_check(&[declared("usb-a", Some((held, Some(holder(owner, state)))))])
                    .unwrap(),
                vec!["dev-usb-a".to_owned()],
                "{owner} {state:?}"
            );
        }
        // The pre-check does not judge a held device's freshness: whether the
        // row survives is the store's call. A device the store frees from a
        // dead owner is checked for freshness right after (`HardwarePlacement`,
        // tests in `lab_hardware_placement`), exactly like an available one.
        let old = device(
            "usb-a",
            DeviceStatus::Reserved,
            vec![node_entry("pve-a", NOW - 5 * MAX_AGE)],
        );
        let own = holder("lease-1", HardwareReservationState::Held);
        assert!(hardware_check(&[declared("usb-a", Some((old, Some(own))))]).is_ok());
        // The node rule still applies to a held device.
        let elsewhere = device("usb-a", DeviceStatus::Reserved, fresh_on("pve-b"));
        let own = holder("lease-1", HardwareReservationState::Held);
        assert_eq!(
            hardware_check(&[declared("usb-a", Some((elsewhere, Some(own))))])
                .unwrap_err()
                .reason(),
            "hardware_wrong_node"
        );
    }

    #[test]
    fn unsupported_and_unallocatable_devices_are_refused_with_their_reason() {
        let unsupported = device(
            "usb-a",
            DeviceStatus::Unsupported(UnsupportedReason::TokenLacksMappingUse),
            fresh_on("pve-a"),
        );
        let refusal = hardware_check(&[declared("usb-a", Some((unsupported, None)))]).unwrap_err();
        assert_eq!(refusal.reason(), "hardware_unsupported");
        assert_eq!(
            refusal.to_string(),
            "hardware usb-a is unsupported (token_lacks_mapping_use): the token lacks Mapping.Use on the mapping (the opt-in FleetUsb role)"
        );
        for (status, reason) in [
            (
                DeviceStatus::ExternallyAttached,
                "hardware_externally_attached",
            ),
            (DeviceStatus::Quarantined, "hardware_quarantined"),
            (DeviceStatus::Missing, "hardware_missing"),
        ] {
            let device = device("usb-a", status, fresh_on("pve-a"));
            let refusal = hardware_check(&[declared("usb-a", Some((device, None)))]).unwrap_err();
            assert_eq!(refusal.reason(), reason);
            assert!(
                refusal.to_string().contains("cannot be reserved"),
                "{refusal}"
            );
        }
    }

    #[test]
    fn an_old_observation_is_stale_not_available() {
        let stale = device(
            "usb-a",
            DeviceStatus::Available,
            vec![node_entry("pve-a", NOW - MAX_AGE - 1)],
        );
        let refusal = hardware_check(&[declared("usb-a", Some((stale, None)))]).unwrap_err();
        assert_eq!(refusal.reason(), "hardware_stale");
        assert_eq!(
            refusal.to_string(),
            "hardware usb-a was not seen on node pve-a within the last 900s; refusing to reserve it on a stale observation (refresh the inventory and retry)"
        );
        // Never seen at all (last_seen_at 0) is the same, not "available".
        let never = device(
            "usb-a",
            DeviceStatus::Available,
            vec![node_entry("pve-a", 0)],
        );
        assert_eq!(
            hardware_check(&[declared("usb-a", Some((never, None)))])
                .unwrap_err()
                .reason(),
            "hardware_stale"
        );
    }

    #[test]
    fn the_first_failing_device_refuses_the_whole_declaration() {
        let missing = device("usb-b", DeviceStatus::Missing, fresh_on("pve-a"));
        let refusal =
            hardware_check(&[usable(), declared("usb-b", Some((missing, None)))]).unwrap_err();
        assert!(
            refusal.to_string().starts_with("hardware usb-b "),
            "{refusal}"
        );
    }
}
