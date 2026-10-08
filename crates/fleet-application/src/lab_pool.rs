//! Pooled Lab guests (FM-717): a small set of preallocated QEMU guests bound
//! to one published template version, leased exclusively and reverted to a
//! baseline snapshot instead of destroyed.
//!
//! The rules live here; storage, the provision and cleanup executors, the
//! HTTP routes, and `fleetctl` are adapters.
//!
//! - **Pool.** One per template version, whose cleanup strategy must be
//!   `revert`, so every lease from it inherits `revert`. It names the
//!   Proxmox account its members are reached through, the baseline snapshot
//!   name, and a declared size (at most [`MAX_POOL_SIZE`]).
//! - **Members.** Operator-supplied guests, keyed by account and VMID across
//!   every pool. Fleet never creates or destroys them: fill registers them,
//!   drain releases them from Lab, and cleanup only reverts them.
//! - **Fill.** New members start `filling`. The fill executor checks each
//!   guest's identity ([`member_identity`]), reverts it to the baseline
//!   through the reviewed snapshot-revert path, verifies the result
//!   ([`verify_reverted`]), and marks it `available`, or `quarantined` with
//!   the reason.
//! - **Claim.** Leasing from a pooled template version binds one
//!   `available`, non-draining member to the lease in one storage
//!   transaction, together with the provision record's account, node, and
//!   VMID. A unique index on the member's lease makes a shared member
//!   impossible.
//! - **Cleanup.** A lease bound to a member always reverts ([`cleanup_plan`]),
//!   whatever its recorded strategy, except `keep`. A verified revert
//!   returns the member and releases the lease in one transaction. A failed
//!   revert quarantines the member at once, while it stays bound to the
//!   lease. `keep` releases the lease and quarantines the member out of the
//!   pool.
//! - **Drain.** Removes unbound members at once. A bound or filling member
//!   is flagged and removed when its cleanup or fill finishes, instead of
//!   returning to the pool.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use fleet_core::CleanupStrategy;

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::lab::{LabTemplatePort, LabUseCaseError};
use crate::operation::{AuditPort, NewOperation};
use crate::proxmox::ProxmoxAccountPort;

/// The largest pool Fleet accepts: pools are small and declared by hand.
pub const MAX_POOL_SIZE: u32 = 16;
/// The smallest VMID PVE assigns.
pub const MIN_VMID: u32 = 100;
/// The largest VMID PVE assigns.
pub const MAX_VMID: u32 = 999_999_999;
/// The operation kind that verifies and reverts newly filled members.
pub const FILL_KIND: &str = "lab.pool.fill";
/// The name prefix of Fleet's own Lab clones, which are never pool members.
pub const LAB_CLONE_PREFIX: &str = "fm-lab-";

/// A pool member's state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MemberState {
    /// Registered by a fill; not yet verified and reverted.
    Filling,
    /// At its baseline and free to lease.
    Available,
    /// Bound to one lease.
    Leased,
    /// Out of rotation: its fill or a revert failed, or a lease kept it.
    Quarantined,
}

impl MemberState {
    /// The stable id stored and served.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Filling => "filling",
            Self::Available => "available",
            Self::Leased => "leased",
            Self::Quarantined => "quarantined",
        }
    }

    /// Parses a stored id.
    ///
    /// # Errors
    ///
    /// Fails on an unknown id.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "filling" => Ok(Self::Filling),
            "available" => Ok(Self::Available),
            "leased" => Ok(Self::Leased),
            "quarantined" => Ok(Self::Quarantined),
            other => Err(format!("unknown pool member state {other:?}")),
        }
    }
}

/// A pool of preallocated guests for one template version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabPool {
    /// The pool's identity.
    pub id: String,
    /// The published template version leases take members for.
    pub template_version_id: String,
    /// The Proxmox account the members are reached through.
    pub account_id: String,
    /// The snapshot every member is reverted to.
    pub baseline_snapshot: String,
    /// The declared number of members.
    pub size: u32,
    /// Who created the pool.
    pub created_by: String,
    /// When the pool was created (epoch millis).
    pub created_at: i64,
}

/// One preallocated guest in a pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolMember {
    /// The member's identity; a refill after a drain gets a new one.
    pub id: String,
    /// The pool it belongs to.
    pub pool_id: String,
    /// The account it is reached through (the pool's).
    pub account_id: String,
    /// The guest's VMID.
    pub vmid: u32,
    /// The node the guest was last seen on, once verified.
    pub node: Option<String>,
    /// The guest's name when it was verified; a different guest at the same
    /// VMID is refused by it.
    pub name: Option<String>,
    /// The member's state.
    pub state: MemberState,
    /// The lease it is bound to, when any.
    pub lease_id: Option<String>,
    /// Whether a drain asked for it to leave once its lease or fill ends.
    pub draining: bool,
    /// Why it is quarantined, when it is.
    pub detail: Option<String>,
    /// When it was registered (epoch millis).
    pub created_at: i64,
    /// When it last changed (epoch millis).
    pub updated_at: i64,
}

impl PoolMember {
    /// Whether a claim may bind this member.
    #[must_use]
    pub fn claimable(&self) -> bool {
        self.state == MemberState::Available && self.lease_id.is_none() && !self.draining
    }
}

/// A pool creation request.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NewLabPool {
    /// The published template version.
    pub template_version_id: String,
    /// The Proxmox account the members are reached through.
    pub account_id: String,
    /// The baseline snapshot name.
    pub baseline_snapshot: String,
    /// The declared size.
    pub size: u32,
}

/// The outcome of a claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimOutcome {
    /// The member now bound to the lease (or already bound to it).
    Claimed(PoolMember),
    /// No member is free; nothing was written.
    Exhausted,
}

/// How a pooled lease's cleanup leaves its member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemberRelease {
    /// The revert was verified: back to the pool (or removed if draining).
    Return,
    /// The lease kept the guest: quarantined out of rotation (or removed if
    /// draining).
    Keep,
}

/// What a lease release did to its member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberReleased {
    /// The member is available again.
    Returned,
    /// The member was draining and left the pool.
    Removed,
    /// The member is quarantined.
    Quarantined,
}

impl MemberReleased {
    /// The stable id audited and reported.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Returned => "returned",
            Self::Removed => "removed",
            Self::Quarantined => "quarantined",
        }
    }
}

/// How a fill's verification ended for one member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FillResult {
    /// Verified and reverted.
    Available {
        /// The node the guest lives on.
        node: String,
        /// The guest's name.
        name: String,
    },
    /// Refused or failed; the reason is recorded.
    Quarantined {
        /// Why.
        detail: String,
    },
}

/// What a drain did.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DrainReport {
    /// The VMIDs that left the pool.
    pub removed: Vec<u32>,
    /// The VMIDs that leave once their lease's cleanup or their fill ends.
    pub deferred: Vec<u32>,
}

/// A pool storage failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PoolStoreError {
    /// The addressed pool, member, lease, or record does not exist.
    NotFound(String),
    /// A uniqueness or state rule refused the write.
    Conflict(String),
    /// The backend failed.
    Backend(String),
}

impl fmt::Display for PoolStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(what) => write!(f, "not found: {what}"),
            Self::Conflict(detail) => write!(f, "conflict: {detail}"),
            Self::Backend(detail) => write!(f, "backend: {detail}"),
        }
    }
}

impl std::error::Error for PoolStoreError {}

impl From<PoolStoreError> for String {
    fn from(error: PoolStoreError) -> Self {
        error.to_string()
    }
}

/// The pool storage port. Every method that changes a member's binding is
/// one transaction.
#[async_trait]
pub trait LabPoolPort: fmt::Debug + Send + Sync {
    /// Creates a pool. A template version holds at most one.
    ///
    /// # Errors
    ///
    /// `Conflict` when the version already has a pool.
    async fn create(
        &self,
        new: &NewLabPool,
        created_by: &str,
        now: i64,
    ) -> Result<LabPool, PoolStoreError>;
    /// Reads one pool.
    ///
    /// # Errors
    ///
    /// `NotFound` when unknown.
    async fn get(&self, id: &str) -> Result<LabPool, PoolStoreError>;
    /// Lists pools, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list(&self) -> Result<Vec<LabPool>, PoolStoreError>;
    /// Deletes a pool that holds no members.
    ///
    /// # Errors
    ///
    /// `Conflict` while it holds members, `NotFound` when unknown.
    async fn delete(&self, id: &str) -> Result<(), PoolStoreError>;
    /// The pool of a template version, when it has one.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn for_template_version(
        &self,
        template_version_id: &str,
    ) -> Result<Option<LabPool>, PoolStoreError>;
    /// A pool's members, by VMID.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn members(&self, pool_id: &str) -> Result<Vec<PoolMember>, PoolStoreError>;
    /// Registers new members as `filling`, refusing to exceed the pool's
    /// size or to register a guest (account and VMID) any pool already has.
    ///
    /// # Errors
    ///
    /// `Conflict` on either refusal, `NotFound` for an unknown pool.
    async fn add_members(
        &self,
        pool_id: &str,
        vmids: &[u32],
        now: i64,
    ) -> Result<Vec<PoolMember>, PoolStoreError>;
    /// Records a fill's verification for a `filling` member; a draining one
    /// is removed instead. A member that is no longer `filling` (another
    /// fill finished it) is left alone.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn finish_fill(
        &self,
        member_id: &str,
        result: &FillResult,
        now: i64,
    ) -> Result<(), PoolStoreError>;
    /// Drains the named members (every member when `None`): unbound,
    /// settled members are removed; bound or filling ones are flagged.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown pool or a VMID the pool does not hold.
    async fn drain(
        &self,
        pool_id: &str,
        vmids: Option<&[u32]>,
        now: i64,
    ) -> Result<DrainReport, PoolStoreError>;
    /// Binds one claimable member to the lease, and records its account,
    /// node, and VMID on the lease's provision record, in one transaction.
    /// The member already bound to the lease is answered again.
    ///
    /// # Errors
    ///
    /// `Conflict` when the lease is not provisioning that record, or the
    /// record already holds another guest.
    async fn claim(
        &self,
        pool_id: &str,
        lease_id: &str,
        record_id: &str,
        now: i64,
    ) -> Result<ClaimOutcome, PoolStoreError>;
    /// The member bound to a lease, when any.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn member_for_lease(&self, lease_id: &str) -> Result<Option<PoolMember>, PoolStoreError>;
    /// The member registered for a guest, in any pool and state.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn member_by_vmid(
        &self,
        account_id: &str,
        vmid: u32,
    ) -> Result<Option<PoolMember>, PoolStoreError>;
    /// Records the node a member's guest now lives on.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn set_member_node(
        &self,
        member_id: &str,
        node: &str,
        now: i64,
    ) -> Result<(), PoolStoreError>;
    /// Quarantines the member bound to a lease, keeping the binding.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn quarantine_bound(
        &self,
        lease_id: &str,
        detail: &str,
        now: i64,
    ) -> Result<(), PoolStoreError>;
    /// Marks a `releasing` lease `released` and unbinds its member as
    /// `how` says, in one transaction.
    ///
    /// # Errors
    ///
    /// `Conflict` when the lease is no longer `releasing` or holds no
    /// member.
    async fn release_lease(
        &self,
        lease_id: &str,
        how: &MemberRelease,
        now: i64,
    ) -> Result<MemberReleased, PoolStoreError>;
}

/// Validates a baseline snapshot name: a PVE `pve-snapshot-name`
/// (`pve-configid`, at most 40 characters), and never `current`, which
/// PVE's snapshot list uses for the live state.
///
/// # Errors
///
/// Answers why the name is refused.
pub fn validate_baseline_snapshot(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let valid = name.len() >= 2
        && name.len() <= 40
        && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !valid {
        return Err(format!(
            "the baseline snapshot must be a PVE snapshot name (a letter, then 1..=39 of [A-Za-z0-9_-]), not {name:?}"
        ));
    }
    if name.eq_ignore_ascii_case("current") {
        return Err("the baseline snapshot cannot be named current".to_owned());
    }
    Ok(())
}

/// Validates a declared pool size.
///
/// # Errors
///
/// Answers why the size is refused.
pub fn validate_size(size: u32) -> Result<(), String> {
    if size == 0 || size > MAX_POOL_SIZE {
        return Err(format!(
            "the pool size must be 1..={MAX_POOL_SIZE}, not {size}"
        ));
    }
    Ok(())
}

/// Validates the VMIDs one fill registers against the pool's size and its
/// current member count.
///
/// # Errors
///
/// Answers why the VMIDs are refused.
pub fn validate_fill(vmids: &[u32], members: usize, size: u32) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for vmid in vmids {
        if !(MIN_VMID..=MAX_VMID).contains(vmid) {
            return Err(format!(
                "VMID {vmid} is outside PVE's range {MIN_VMID}..={MAX_VMID}"
            ));
        }
        if !seen.insert(*vmid) {
            return Err(format!("VMID {vmid} is named twice"));
        }
    }
    let total = members.saturating_add(vmids.len());
    if total > usize::try_from(size).unwrap_or(usize::MAX) {
        return Err(format!(
            "the pool holds {members} of {size} members; {} more would exceed its size",
            vmids.len()
        ));
    }
    Ok(())
}

/// What the cluster reports about a candidate or member guest, gathered by
/// the controller right before it reverts the guest.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GuestObservation {
    /// The `/cluster/resources` kind (`qemu`, `qemu-template`, `lxc`), or
    /// `None` when no guest has the VMID.
    pub kind: Option<String>,
    /// The node the guest lives on.
    pub node: Option<String>,
    /// The guest's name.
    pub name: Option<String>,
    /// Whether the guest's snapshot list holds the baseline.
    pub baseline_present: bool,
    /// Whether the VMID is a protected image build artifact.
    pub protected_artifact: bool,
}

/// The identity check before Fleet reverts a guest (fill or cleanup). The
/// guest must exist as a QEMU guest (never a template or a container), must
/// not be a protected image artifact or one of Lab's own `fm-lab-*` clones,
/// must carry the baseline snapshot, and, once a fill recorded its name,
/// must still carry that name: a different guest at a reused VMID is never
/// rolled back. Answers the guest's node and name.
///
/// # Errors
///
/// Answers why the guest must not be reverted.
pub fn member_identity(
    observed: &GuestObservation,
    vmid: u32,
    recorded_name: Option<&str>,
    baseline: &str,
) -> Result<(String, String), String> {
    let Some(kind) = observed.kind.as_deref() else {
        return Err(format!("no guest has VMID {vmid}"));
    };
    if kind != "qemu" {
        return Err(format!(
            "VMID {vmid} is a {kind}; a pool member must be a QEMU guest, never a template or a container"
        ));
    }
    if observed.protected_artifact {
        return Err(format!(
            "VMID {vmid} is a protected image build artifact; it can never be a pool member"
        ));
    }
    let name = observed.name.clone().unwrap_or_default();
    if name.starts_with(LAB_CLONE_PREFIX) {
        return Err(format!(
            "VMID {vmid} is named {name}, a Lab clone that Lab cleanup owns; it can never be a pool member"
        ));
    }
    if let Some(recorded) = recorded_name
        && recorded != name
    {
        return Err(format!(
            "VMID {vmid} is now named {name:?}, not the member {recorded:?} the fill verified; it may be another guest"
        ));
    }
    let Some(node) = observed.node.clone() else {
        return Err(format!("the cluster reports no node for VMID {vmid}"));
    };
    if !observed.baseline_present {
        return Err(format!("VMID {vmid} has no snapshot named {baseline}"));
    }
    Ok((node, name))
}

/// The guest config facts read after a rollback.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevertedConfig {
    /// Whether the guest is a template.
    pub template: bool,
    /// The config lock, when any (`rollback` after an interrupted one).
    pub lock: Option<String>,
    /// The snapshot the current state derives from (the config's `parent`,
    /// which PVE sets to the snapshot a rollback restored).
    pub parent: Option<String>,
}

/// Whether a rollback left the guest at its baseline: not a template, no
/// config lock left behind, and the current state's parent is the baseline.
///
/// # Errors
///
/// Answers why the revert is not verified.
pub fn verify_reverted(config: &RevertedConfig, baseline: &str) -> Result<(), String> {
    if config.template {
        return Err("the guest became a template".to_owned());
    }
    if let Some(lock) = &config.lock {
        return Err(format!("the guest's config is still locked ({lock})"));
    }
    match config.parent.as_deref() {
        Some(parent) if parent == baseline => Ok(()),
        Some(parent) => Err(format!(
            "the guest's current state derives from {parent}, not the baseline {baseline}"
        )),
        None => Err(format!(
            "the guest's current state derives from no snapshot, not the baseline {baseline}"
        )),
    }
}

/// The cluster reads the pool executors take before and after a revert.
/// The controller implements it over the Proxmox provider.
#[async_trait]
pub trait PoolGuestPort: fmt::Debug + Send + Sync {
    /// Observes the guest at `vmid` through `account_id`: its resource
    /// entry, whether it carries `baseline`, and whether the VMID is a
    /// protected image artifact.
    ///
    /// # Errors
    ///
    /// Fails when the account, the cluster, or the artifact store cannot
    /// be read; an undecided observation is never a pass.
    async fn observe(
        &self,
        account_id: &str,
        vmid: u32,
        baseline: &str,
    ) -> Result<GuestObservation, String>;
    /// Reads the guest's config facts after a rollback.
    ///
    /// # Errors
    ///
    /// Fails when the account or the config cannot be read.
    async fn reverted_config(
        &self,
        account_id: &str,
        node: &str,
        vmid: u32,
    ) -> Result<RevertedConfig, String>;
}

/// What a releasing lease's cleanup does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupPlan {
    /// Destroy the lease's clone (FM-713).
    Destroy,
    /// Release the lease and keep its clone.
    Keep,
    /// Revert the lease's pool member and return it.
    Revert,
    /// Release the lease and quarantine its pool member.
    KeepPooled,
    /// A `revert` lease without a pool member: refused, nothing changes.
    NotPooled,
}

/// The cleanup a lease gets. A lease bound to a pool member is never
/// destroyed, whatever its recorded strategy: it reverts unless it keeps.
#[must_use]
pub fn cleanup_plan(strategy: CleanupStrategy, pooled: bool) -> CleanupPlan {
    match (strategy, pooled) {
        (CleanupStrategy::Keep, true) => CleanupPlan::KeepPooled,
        (CleanupStrategy::Keep, false) => CleanupPlan::Keep,
        (CleanupStrategy::Destroy | CleanupStrategy::Revert, true) => CleanupPlan::Revert,
        (CleanupStrategy::Destroy, false) => CleanupPlan::Destroy,
        (CleanupStrategy::Revert, false) => CleanupPlan::NotPooled,
    }
}

/// The best-effort audit intent the pool executors record for a member.
/// The operation that made the change is named in the metadata, never as
/// the intent's `operation_id`: the ledger attaches an operation's outcome
/// to its latest open intent, which must stay the operation's own.
#[must_use]
pub fn member_audit(
    actor: &str,
    pool_id: &str,
    operation_id: Option<&str>,
    event: &str,
    facts: &[(&str, String)],
) -> crate::audit::AuditIntent {
    let mut metadata = crate::audit::AuditMetadata::default();
    let _ = metadata.insert("event", event);
    if let Some(operation_id) = operation_id {
        let _ = metadata.insert("operationId", operation_id);
    }
    for (key, value) in facts {
        let _ = metadata.insert(key, value);
    }
    crate::audit::AuditIntent {
        actor: actor.to_owned(),
        action: Permission::LabConfig.id().to_owned(),
        resource: Some(pool_id.to_owned()),
        decision: Decision::allow(),
        correlation_id: None,
        operation_id: None,
        metadata,
    }
}

/// The `lab.pool.fill` operation for a pool.
#[must_use]
pub fn fill_operation(pool_id: &str, correlation_id: Option<String>) -> NewOperation {
    NewOperation {
        kind: FILL_KIND.to_owned(),
        idempotency_key: None,
        deadline_at: None,
        correlation_id,
        payload_json: Some(serde_json::json!({ "poolId": pool_id }).to_string()),
        review_token: None,
    }
}

/// The pool use cases. Every mutation is authorized against `lab.config`
/// and audited before it is made.
#[derive(Debug)]
pub struct LabPools {
    pools: Arc<dyn LabPoolPort>,
    templates: Arc<dyn LabTemplatePort>,
    accounts: Arc<dyn ProxmoxAccountPort>,
    audit: Arc<dyn AuditPort>,
}

impl LabPools {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(
        pools: Arc<dyn LabPoolPort>,
        templates: Arc<dyn LabTemplatePort>,
        accounts: Arc<dyn ProxmoxAccountPort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            pools,
            templates,
            accounts,
            audit,
        }
    }

    /// Lists pools.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<Vec<(LabPool, Vec<PoolMember>)>, LabUseCaseError> {
        allow(authorizer, principal, Permission::LabRead, None)?;
        let pools = self.pools.list().await.map_err(store_error)?;
        let mut out = Vec::with_capacity(pools.len());
        for pool in pools {
            let members = self.pools.members(&pool.id).await.map_err(store_error)?;
            out.push((pool, members));
        }
        Ok(out)
    }

    /// Reads one pool and its members.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown pool, or a backend failure.
    pub async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<(LabPool, Vec<PoolMember>), LabUseCaseError> {
        allow(authorizer, principal, Permission::LabRead, Some(id))?;
        let pool = self.pools.get(id).await.map_err(store_error)?;
        let members = self.pools.members(id).await.map_err(store_error)?;
        Ok((pool, members))
    }

    /// Creates a pool for a published template version whose cleanup
    /// strategy is `revert`, reached through a known Proxmox account.
    ///
    /// # Errors
    ///
    /// Fails on denial, invalid input, an unknown version or account, a
    /// version that does not revert, a version that already has a pool,
    /// or a backend failure.
    pub async fn create(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        new: NewLabPool,
        now: i64,
    ) -> Result<LabPool, LabUseCaseError> {
        allow(
            authorizer,
            principal,
            Permission::LabConfig,
            Some(&new.template_version_id),
        )?;
        validate_baseline_snapshot(&new.baseline_snapshot).map_err(invalid)?;
        validate_size(new.size).map_err(invalid)?;
        let version = self
            .templates
            .get_version(&new.template_version_id)
            .await
            .map_err(|detail| {
                not_found_or_backend(detail, "template version", &new.template_version_id)
            })?;
        if version.content.cleanup != CleanupStrategy::Revert {
            return Err(invalid(format!(
                "the template version {} cleans up with {}; a pool needs a template version whose cleanup is revert",
                version.id,
                version.content.cleanup.id()
            )));
        }
        self.accounts
            .get(&new.account_id)
            .await
            .map_err(|detail| not_found_or_backend(detail, "Proxmox account", &new.account_id))?;
        if self
            .pools
            .for_template_version(&new.template_version_id)
            .await
            .map_err(store_error)?
            .is_some()
        {
            return Err(LabUseCaseError::Conflict {
                detail: format!(
                    "the template version {} already has a pool",
                    new.template_version_id
                ),
            });
        }
        self.audit_event(
            principal,
            Some(&new.template_version_id),
            "lab_pool_creating",
            &[
                ("accountId", new.account_id.clone()),
                ("baselineSnapshot", new.baseline_snapshot.clone()),
                ("size", new.size.to_string()),
            ],
        )
        .await?;
        self.pools
            .create(&new, &principal.id, now)
            .await
            .map_err(store_error)
    }

    /// Deletes a pool that holds no members (drain it first).
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown pool, a pool with members, or a backend
    /// failure.
    pub async fn delete(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<(), LabUseCaseError> {
        allow(authorizer, principal, Permission::LabConfig, Some(id))?;
        self.pools.get(id).await.map_err(store_error)?;
        if !self
            .pools
            .members(id)
            .await
            .map_err(store_error)?
            .is_empty()
        {
            return Err(LabUseCaseError::Conflict {
                detail: format!("the pool {id} still holds members; drain it first"),
            });
        }
        self.audit_event(principal, Some(id), "lab_pool_deleting", &[])
            .await?;
        self.pools.delete(id).await.map_err(store_error)
    }

    /// Registers guests as new `filling` members and answers the
    /// `lab.pool.fill` operation that verifies and reverts them. An empty
    /// list registers nothing and re-queues the verification of members
    /// still `filling` (after a lost or failed fill operation).
    ///
    /// # Errors
    ///
    /// Fails on denial, invalid VMIDs, an unknown pool, a guest another
    /// pool member already is, or a backend failure.
    pub async fn request_fill(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        vmids: &[u32],
        now: i64,
    ) -> Result<(Vec<PoolMember>, NewOperation), LabUseCaseError> {
        allow(authorizer, principal, Permission::LabConfig, Some(id))?;
        // Fill queues an operation: the caller must be allowed to create
        // one, checked before anything is registered.
        allow(authorizer, principal, Permission::OperationCreate, None)?;
        let pool = self.pools.get(id).await.map_err(store_error)?;
        let members = self.pools.members(id).await.map_err(store_error)?;
        validate_fill(vmids, members.len(), pool.size).map_err(invalid)?;
        if vmids.is_empty() && !members.iter().any(|m| m.state == MemberState::Filling) {
            return Err(invalid(
                "name at least one VMID to fill; no member is waiting for verification".to_owned(),
            ));
        }
        let listed = vmids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        self.audit_event(
            principal,
            Some(id),
            "lab_pool_fill_requested",
            &[("vmids", listed)],
        )
        .await?;
        let added = if vmids.is_empty() {
            Vec::new()
        } else {
            self.pools
                .add_members(id, vmids, now)
                .await
                .map_err(store_error)?
        };
        Ok((added, fill_operation(id, None)))
    }

    /// Drains the named members (every member when `None`). Unbound
    /// members leave the pool at once; a member bound to a lease, or still
    /// filling, leaves when that finishes. The guests themselves stay.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown pool or VMID, or a backend failure.
    pub async fn drain(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        vmids: Option<&[u32]>,
        now: i64,
    ) -> Result<DrainReport, LabUseCaseError> {
        allow(authorizer, principal, Permission::LabConfig, Some(id))?;
        self.pools.get(id).await.map_err(store_error)?;
        let listed = vmids.map_or_else(
            || "all".to_owned(),
            |vmids| {
                vmids
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            },
        );
        self.audit_event(
            principal,
            Some(id),
            "lab_pool_draining",
            &[("vmids", listed)],
        )
        .await?;
        self.pools.drain(id, vmids, now).await.map_err(store_error)
    }

    async fn audit_event(
        &self,
        principal: &ActingPrincipal,
        resource: Option<&str>,
        event: &str,
        facts: &[(&str, String)],
    ) -> Result<(), LabUseCaseError> {
        let mut metadata = crate::audit::AuditMetadata::default();
        let mut insert = |key: &str, value: &str| {
            metadata
                .insert(key, value)
                .map_err(|error| LabUseCaseError::Backend {
                    context: "audit",
                    detail: error.to_string(),
                })
        };
        insert("event", event)?;
        for (key, value) in facts {
            insert(key, value)?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: Permission::LabConfig.id().to_owned(),
                resource: resource.map(str::to_owned),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "audit",
                detail,
            })
    }
}

fn allow(
    authorizer: &dyn Authorizer,
    principal: &ActingPrincipal,
    action: Permission,
    resource: Option<&str>,
) -> Result<(), LabUseCaseError> {
    authorize(
        authorizer,
        AccessRequest {
            principal_id: &principal.id,
            action,
            resource,
        },
    )
    .map(|_| ())
    .map_err(LabUseCaseError::Denied)
}

fn invalid(detail: String) -> LabUseCaseError {
    LabUseCaseError::Invalid { detail }
}

fn store_error(error: PoolStoreError) -> LabUseCaseError {
    match error {
        PoolStoreError::NotFound(what) => LabUseCaseError::NotFound { what },
        PoolStoreError::Conflict(detail) => LabUseCaseError::Conflict { detail },
        PoolStoreError::Backend(detail) => LabUseCaseError::Backend {
            context: "pools",
            detail,
        },
    }
}

fn not_found_or_backend(detail: String, what: &str, id: &str) -> LabUseCaseError {
    if detail.contains("not found") {
        LabUseCaseError::NotFound {
            what: format!("{what} {id}"),
        }
    } else {
        LabUseCaseError::Backend {
            context: "pools",
            detail,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed() -> GuestObservation {
        GuestObservation {
            kind: Some("qemu".to_owned()),
            node: Some("pve1".to_owned()),
            name: Some("pool-win11-a".to_owned()),
            baseline_present: true,
            protected_artifact: false,
        }
    }

    #[test]
    fn baseline_names_follow_pve() {
        assert!(validate_baseline_snapshot("baseline").is_ok());
        assert!(validate_baseline_snapshot("Base_line-1").is_ok());
        for bad in [
            "",
            "b",
            "1base",
            "base line",
            "base/x",
            "current",
            "CURRENT",
        ] {
            assert!(validate_baseline_snapshot(bad).is_err(), "{bad:?}");
        }
        assert!(validate_baseline_snapshot(&"a".repeat(40)).is_ok());
        assert!(validate_baseline_snapshot(&"a".repeat(41)).is_err());
    }

    #[test]
    fn sizes_and_fills_are_bounded() {
        assert!(validate_size(0).is_err());
        assert!(validate_size(1).is_ok());
        assert!(validate_size(MAX_POOL_SIZE).is_ok());
        assert!(validate_size(MAX_POOL_SIZE + 1).is_err());
        assert!(validate_fill(&[100, 101], 0, 2).is_ok());
        assert!(
            validate_fill(&[100, 101], 1, 2).is_err(),
            "exceeds the size"
        );
        assert!(validate_fill(&[100, 100], 0, 4).is_err(), "duplicate");
        assert!(validate_fill(&[99], 0, 4).is_err(), "below PVE's range");
        assert!(validate_fill(&[], 0, 4).is_ok());
    }

    #[test]
    fn identity_refuses_anything_but_the_verified_qemu_guest() {
        assert_eq!(
            member_identity(&observed(), 200, None, "baseline"),
            Ok(("pve1".to_owned(), "pool-win11-a".to_owned()))
        );
        assert!(member_identity(&observed(), 200, Some("pool-win11-a"), "baseline").is_ok());
        let cases = [
            GuestObservation {
                kind: None,
                ..observed()
            },
            GuestObservation {
                kind: Some("qemu-template".to_owned()),
                ..observed()
            },
            GuestObservation {
                kind: Some("lxc".to_owned()),
                ..observed()
            },
            GuestObservation {
                protected_artifact: true,
                ..observed()
            },
            GuestObservation {
                name: Some("fm-lab-record".to_owned()),
                ..observed()
            },
            GuestObservation {
                node: None,
                ..observed()
            },
            GuestObservation {
                baseline_present: false,
                ..observed()
            },
        ];
        for case in cases {
            assert!(
                member_identity(&case, 200, None, "baseline").is_err(),
                "{case:?}"
            );
        }
        assert!(
            member_identity(&observed(), 200, Some("another-guest"), "baseline").is_err(),
            "a renamed or replaced guest at the VMID is never reverted"
        );
    }

    #[test]
    fn a_revert_is_verified_by_the_parent_without_a_lock() {
        let at = |parent: Option<&str>| RevertedConfig {
            template: false,
            lock: None,
            parent: parent.map(str::to_owned),
        };
        assert!(verify_reverted(&at(Some("baseline")), "baseline").is_ok());
        assert!(verify_reverted(&at(Some("other")), "baseline").is_err());
        assert!(verify_reverted(&at(None), "baseline").is_err());
        let locked = RevertedConfig {
            lock: Some("rollback".to_owned()),
            ..at(Some("baseline"))
        };
        assert!(verify_reverted(&locked, "baseline").is_err());
        let template = RevertedConfig {
            template: true,
            ..at(Some("baseline"))
        };
        assert!(verify_reverted(&template, "baseline").is_err());
    }

    #[test]
    fn a_pooled_lease_is_never_destroyed() {
        use CleanupStrategy::{Destroy, Keep, Revert};
        assert_eq!(cleanup_plan(Destroy, true), CleanupPlan::Revert);
        assert_eq!(cleanup_plan(Revert, true), CleanupPlan::Revert);
        assert_eq!(cleanup_plan(Keep, true), CleanupPlan::KeepPooled);
        assert_eq!(cleanup_plan(Destroy, false), CleanupPlan::Destroy);
        assert_eq!(cleanup_plan(Keep, false), CleanupPlan::Keep);
        assert_eq!(cleanup_plan(Revert, false), CleanupPlan::NotPooled);
    }

    #[test]
    fn only_free_settled_members_are_claimable() {
        let member = PoolMember {
            id: "m".to_owned(),
            pool_id: "p".to_owned(),
            account_id: "a".to_owned(),
            vmid: 200,
            node: Some("pve1".to_owned()),
            name: Some("n".to_owned()),
            state: MemberState::Available,
            lease_id: None,
            draining: false,
            detail: None,
            created_at: 0,
            updated_at: 0,
        };
        assert!(member.claimable());
        for state in [
            MemberState::Filling,
            MemberState::Leased,
            MemberState::Quarantined,
        ] {
            assert!(
                !PoolMember {
                    state,
                    ..member.clone()
                }
                .claimable()
            );
        }
        assert!(
            !PoolMember {
                draining: true,
                ..member.clone()
            }
            .claimable()
        );
        assert!(
            !PoolMember {
                lease_id: Some("l".to_owned()),
                ..member
            }
            .claimable()
        );
        for state in ["filling", "available", "leased", "quarantined"] {
            assert_eq!(MemberState::from_id(state).unwrap().id(), state);
        }
    }
}
