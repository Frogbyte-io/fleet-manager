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

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

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
}

impl PlacementRefusal {
    /// The stable reason id the provision operation fails with.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::NoCandidate { .. } => "placement_no_candidate",
            Self::Ambiguous { .. } => "placement_ambiguous",
            Self::NotObserved { .. } | Self::CapacityUnknown { .. } => "capacity_unknown",
            Self::StorageNotObserved { .. } => "storage_unknown",
            Self::Stale { .. } | Self::FutureDated { .. } => "capacity_stale",
            Self::InsufficientMemory { .. } => "insufficient_memory",
            Self::InsufficientCpu { .. } => "insufficient_cpu",
            Self::InsufficientDisk { .. } => "insufficient_disk",
        }
    }
}

impl fmt::Display for PlacementRefusal {
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
/// template. `skipped` explains each account that was not a candidate.
///
/// # Errors
///
/// No candidate, or more than one (see the module docs).
pub fn select_candidate(
    mut candidates: Vec<PlacementCandidate>,
    skipped: &[String],
) -> Result<PlacementCandidate, PlacementRefusal> {
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
            select_candidate(vec![candidate("a")], &[]).unwrap(),
            candidate("a")
        );
        let none =
            select_candidate(Vec::new(), &["b: no template qemu/120".to_owned()]).unwrap_err();
        assert_eq!(none.reason(), "placement_no_candidate");
        assert!(none.to_string().contains("b: no template qemu/120"));
        let many = select_candidate(vec![candidate("b"), candidate("a")], &[]).unwrap_err();
        assert_eq!(
            many.to_string(),
            "more than one account reaches a template with the pinned image's VMID (a on pve1, b on pve1); pass --account to choose"
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
}
