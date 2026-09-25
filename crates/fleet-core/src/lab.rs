//! The Lab template primitives (FM-710): versioned provisioning
//! definitions pinning a promoted image version, their readiness
//! policies, and the guest states the provisioning saga records.
//!
//! A template pins an **image version id** — the promoted, immutable one
//! from FM-701 — and validates that pin against the version's promotion
//! state at the application boundary. TTL begins at ready, never at
//! provisioning start (the architecture rule).

use serde::{Deserialize, Serialize};

/// The maximum age of a Lab lease, measured from its creation request.
/// This matches the largest allowed template TTL and bounds all extensions.
pub const MAX_LAB_LEASE_LIFETIME_MILLIS: i64 = 30 * 24 * 3_600_000;

/// The readiness probe kinds a template can pin.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessProbe {
    /// The QEMU Guest Agent answers (FM-601's agent data).
    #[default]
    GuestAgent,
    /// An SSH exec probe runs the template's command over the FM-202
    /// transport.
    SshExec,
    /// The M3 ready-project verify step passes.
    ProjectReady,
}

impl ReadinessProbe {
    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::GuestAgent => "guest_agent",
            Self::SshExec => "ssh_exec",
            Self::ProjectReady => "project_ready",
        }
    }

    /// Parses the stable string.
    ///
    /// # Errors
    ///
    /// Fails on an unrecognized probe id.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "guest_agent" => Ok(Self::GuestAgent),
            "ssh_exec" => Ok(Self::SshExec),
            "project_ready" => Ok(Self::ProjectReady),
            other => Err(format!("unrecognized readiness probe {other:?}")),
        }
    }
}

/// The cleanup strategy a template declares. `destroy` is the default;
/// `revert` applies only to explicitly pooled guests; `keep` is gated at
/// lease time in FM-711 and recorded here as data.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStrategy {
    /// Delete the allocated clone (the default).
    #[default]
    Destroy,
    /// Revert to the template's base state; only for explicitly pooled
    /// guests whose reservation prevents concurrent use.
    Revert,
    /// Detach the guest from automatic cleanup; requires elevated
    /// permission at lease time.
    Keep,
}

impl CleanupStrategy {
    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Destroy => "destroy",
            Self::Revert => "revert",
            Self::Keep => "keep",
        }
    }

    /// Parses the stable string.
    ///
    /// # Errors
    ///
    /// Fails on an unrecognized strategy id.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "destroy" => Ok(Self::Destroy),
            "revert" => Ok(Self::Revert),
            "keep" => Ok(Self::Keep),
            other => Err(format!("unrecognized cleanup strategy {other:?}")),
        }
    }
}

/// The guest states the provisioning saga records. `provisioned` and
/// `ready` are distinct by design: a cloned, booted guest is not ready
/// until its probe passes, and TTL begins only at ready.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestState {
    /// The saga is running: clone/boot/bootstrap in progress.
    #[default]
    Provisioning,
    /// The clone completed and the guest started (verified through the
    /// FM-601 agent data), but the readiness probe has not passed.
    Provisioned,
    /// The readiness probe passed; the TTL clock starts here.
    Ready,
    /// The readiness deadline expired without the probe passing: an
    /// explicit failure, never a silent hang.
    NeverReady,
}

impl GuestState {
    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Provisioned => "provisioned",
            Self::Ready => "ready",
            Self::NeverReady => "never_ready",
        }
    }

    /// Parses the stable string.
    ///
    /// # Errors
    ///
    /// Fails on an unrecognized state id.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "provisioning" => Ok(Self::Provisioning),
            "provisioned" => Ok(Self::Provisioned),
            "ready" => Ok(Self::Ready),
            "never_ready" => Ok(Self::NeverReady),
            other => Err(format!("unrecognized guest state {other:?}")),
        }
    }
}

/// A Lab template's content: the pinned image version, runtime
/// constraints, the bootstrap profile, and the policies.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabTemplateContent {
    /// The operator-facing template name.
    pub name: String,
    /// The operator-facing description.
    pub description: String,
    /// The pinned image version id: the promoted, immutable one.
    pub image_version_id: String,
    /// The vCPU count for the provisioned guest.
    pub cores: u32,
    /// The memory in MiB.
    pub memory_mib: u32,
    /// The disk size in GiB.
    pub disk_gib: u32,
    /// The bootstrap profile reference: the project id the M3
    /// ready-project operation applies.
    pub bootstrap_project_id: Option<String>,
    /// The readiness probe the template pins.
    pub readiness_probe: ReadinessProbe,
    /// The SSH probe command, for the `ssh_exec` probe.
    pub readiness_command: Option<String>,
    /// The readiness deadline in seconds; expiry is `never_ready`.
    pub readiness_deadline_seconds: u32,
    /// The default TTL in seconds, beginning at ready.
    pub ttl_seconds: u32,
    /// The cleanup strategy.
    pub cleanup: CleanupStrategy,
}

impl LabTemplateContent {
    /// Validates the Fleet-owned fields. Bounds keep every field honest;
    /// the image pin's *promotion* is validated at the application
    /// boundary where the image use cases live.
    ///
    /// # Errors
    ///
    /// Fails on a malformed field.
    pub fn validate(&self) -> Result<(), String> {
        let count = self.name.chars().count();
        if count == 0 || count > 128 {
            return Err("the name must be 1..=128 characters".to_owned());
        }
        if self.description.chars().count() > 512 {
            return Err("the description must be at most 512 characters".to_owned());
        }
        if self.image_version_id.is_empty() || self.image_version_id.len() > 128 {
            return Err("the image version pin must be 1..=128 characters".to_owned());
        }
        if self.cores == 0 || self.cores > 64 {
            return Err("the cores must be 1..=64".to_owned());
        }
        if self.memory_mib == 0 || self.memory_mib > 262_144 {
            return Err("the memory must be 1..=262144 MiB".to_owned());
        }
        if self.disk_gib == 0 || self.disk_gib > 4096 {
            return Err("the disk must be 1..=4096 GiB".to_owned());
        }
        if self.readiness_deadline_seconds == 0 || self.readiness_deadline_seconds > 3_600 {
            return Err("the readiness deadline must be 1..=3600 seconds".to_owned());
        }
        if self.ttl_seconds == 0 || self.ttl_seconds > 30 * 24 * 3_600 {
            return Err("the TTL must be 1..=2592000 seconds".to_owned());
        }
        if self.readiness_probe == ReadinessProbe::SshExec
            && self.readiness_command.as_deref().is_none_or(str::is_empty)
        {
            return Err("the ssh_exec probe requires a readiness command".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content() -> LabTemplateContent {
        LabTemplateContent {
            name: "ubuntu-lab".to_owned(),
            description: "the lab base".to_owned(),
            image_version_id: "rcp-1@abc".to_owned(),
            cores: 2,
            memory_mib: 2048,
            disk_gib: 20,
            bootstrap_project_id: None,
            readiness_probe: ReadinessProbe::GuestAgent,
            readiness_command: None,
            readiness_deadline_seconds: 300,
            ttl_seconds: 3_600,
            cleanup: CleanupStrategy::Destroy,
        }
    }

    #[test]
    fn valid_content_passes_and_bounds_hold() {
        assert!(content().validate().is_ok());
        let mut bad = content();
        bad.cores = 0;
        assert!(bad.validate().is_err());
        bad.cores = 2;
        bad.readiness_deadline_seconds = 0;
        assert!(bad.validate().is_err());
        bad.readiness_deadline_seconds = 300;
        bad.ttl_seconds = 0;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn upper_bounds_and_empty_fields_are_enforced() {
        let mut bad = content();
        bad.name = "x".repeat(129);
        assert!(bad.validate().is_err());
        bad.name = String::new();
        assert!(bad.validate().is_err());
        bad.name = "ok".to_owned();
        bad.description = "x".repeat(513);
        assert!(bad.validate().is_err());
        bad.description = String::new();
        bad.image_version_id = "x".repeat(129);
        assert!(bad.validate().is_err());
        bad.image_version_id = String::new();
        bad.cores = 65;
        assert!(bad.validate().is_err());
        bad.cores = 2;
        bad.memory_mib = 262_145;
        assert!(bad.validate().is_err());
        bad.memory_mib = 2048;
        bad.disk_gib = 4097;
        assert!(bad.validate().is_err());
        bad.disk_gib = 20;
        bad.readiness_deadline_seconds = 3601;
        assert!(bad.validate().is_err());
        bad.readiness_deadline_seconds = 300;
        bad.ttl_seconds = 2_592_001;
        assert!(bad.validate().is_err());
        bad.ttl_seconds = 3_600;
        bad.readiness_command = Some("   ".to_owned());
        bad.readiness_probe = ReadinessProbe::SshExec;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn the_ssh_probe_requires_a_command() {
        let mut bad = content();
        bad.readiness_probe = ReadinessProbe::SshExec;
        assert!(bad.validate().is_err());
        bad.readiness_command = Some("systemctl is-active fleetd".to_owned());
        assert!(bad.validate().is_ok());
    }

    #[test]
    fn enums_round_trip_their_ids() {
        for id in ["guest_agent", "ssh_exec", "project_ready"] {
            assert_eq!(ReadinessProbe::from_id(id).unwrap().id(), id);
        }
        assert!(ReadinessProbe::from_id("mystery").is_err());
        for id in ["destroy", "revert", "keep"] {
            assert_eq!(CleanupStrategy::from_id(id).unwrap().id(), id);
        }
        assert!(CleanupStrategy::from_id("mystery").is_err());
        for id in ["provisioning", "provisioned", "ready", "never_ready"] {
            assert_eq!(GuestState::from_id(id).unwrap().id(), id);
        }
        assert!(GuestState::from_id("mystery").is_err());
    }
}

/// The lease states, per the architecture's lease state machine. A
/// running VM never implies a ready lease; cancellation and expiry
/// transition any non-terminal state into release.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    /// Created, not yet queued.
    #[default]
    Requested,
    /// Queued for provisioning.
    Queued,
    /// Reserving capacity.
    Reserving,
    /// The provisioning saga is running (FM-710).
    Provisioning,
    /// The guest is booting.
    Booting,
    /// The guest is bootstrapping (the profile/project setup runs).
    Bootstrapping,
    /// The readiness probe passed; the TTL clock is running.
    Ready,
    /// Release is running (cleanup in progress).
    Releasing,
    /// Released: the cleanup completed and nothing is owed.
    Released,
    /// Provisioning failed before ready. The linked provision record retains
    /// any allocated guest identifiers for later cleanup or reconciliation.
    Failed,
    /// The cleanup failed: the lease visibly owns the remaining resource
    /// and retries with backoff until an operator intervenes.
    CleanupFailed,
}

impl LeaseState {
    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Queued => "queued",
            Self::Reserving => "reserving",
            Self::Provisioning => "provisioning",
            Self::Booting => "booting",
            Self::Bootstrapping => "bootstrapping",
            Self::Ready => "ready",
            Self::Releasing => "releasing",
            Self::Released => "released",
            Self::Failed => "failed",
            Self::CleanupFailed => "cleanup_failed",
        }
    }

    /// Whether the lease is terminal: no further transition is expected.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Released | Self::Failed | Self::CleanupFailed)
    }

    /// Parses the stable string.
    ///
    /// # Errors
    ///
    /// Fails on an unrecognized state id.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "requested" => Ok(Self::Requested),
            "queued" => Ok(Self::Queued),
            "reserving" => Ok(Self::Reserving),
            "provisioning" => Ok(Self::Provisioning),
            "booting" => Ok(Self::Booting),
            "bootstrapping" => Ok(Self::Bootstrapping),
            "ready" => Ok(Self::Ready),
            "releasing" => Ok(Self::Releasing),
            "released" => Ok(Self::Released),
            "failed" => Ok(Self::Failed),
            "cleanup_failed" => Ok(Self::CleanupFailed),
            other => Err(format!("unrecognized lease state {other:?}")),
        }
    }
}

/// A lease: the owner/purpose/project-scoped request and lifecycle, with
/// the public handle the CLI/API use.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lease {
    /// The lease's identity.
    pub id: String,
    /// The template version the lease was created from.
    pub template_version_id: String,
    /// The owner's principal id.
    pub owner: String,
    /// The purpose the lease records (free text, bounded).
    pub purpose: String,
    /// The project the lease is scoped to, when any.
    pub project_id: Option<String>,
    /// The current state.
    pub state: LeaseState,
    /// The provisioning record the lease owns, once provisioned.
    pub provision_id: Option<String>,
    /// The cleanup strategy inherited from the template.
    pub cleanup: CleanupStrategy,
    /// The ready TTL inherited from the template, in seconds.
    pub ttl_seconds: u32,
    /// When the lease was created (epoch millis).
    pub created_at: i64,
    /// Absolute lifetime deadline measured from creation, regardless of
    /// when the guest reaches ready.
    pub max_lifetime_at: i64,
    /// When the lease reached ready (epoch millis), when it did — the TTL
    /// clock's start.
    pub ready_at: Option<i64>,
    /// When the lease's TTL expires (epoch millis), once ready.
    pub expires_at: Option<i64>,
    /// The cleanup attempts so far, for the backoff.
    pub cleanup_attempts: u32,
}

impl Lease {
    /// Marks a provisioning lease ready and starts its TTL, capped by the
    /// creation-relative absolute lifetime.
    ///
    /// # Errors
    ///
    /// Fails if the lease is not provisioning, has no provision record, has
    /// an invalid TTL, or the deadline arithmetic overflows.
    pub fn mark_ready(&mut self, now: i64) -> Result<(), String> {
        if self.state != LeaseState::Provisioning {
            return Err("only provisioning leases can become ready".to_owned());
        }
        if self.provision_id.is_none() {
            return Err("a ready lease must be linked to a provision record".to_owned());
        }
        if self.ttl_seconds == 0 {
            return Err("the lease TTL must be greater than zero".to_owned());
        }
        let ttl_millis = i64::from(self.ttl_seconds)
            .checked_mul(1_000)
            .ok_or_else(|| "the lease TTL deadline overflows".to_owned())?;
        let ttl_deadline = now
            .checked_add(ttl_millis)
            .ok_or_else(|| "the lease TTL deadline overflows".to_owned())?;
        self.state = LeaseState::Ready;
        self.ready_at = Some(now);
        self.expires_at = Some(ttl_deadline.min(self.max_lifetime_at));
        Ok(())
    }

    /// Whether the lease's TTL has expired at `now`. Only a ready lease
    /// with a deadline can expire.
    #[must_use]
    pub fn ttl_expired(&self, now: i64) -> bool {
        self.state == LeaseState::Ready
            && self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }

    /// Computes a new expiry by adding seconds to the existing deadline.
    /// Extending is limited to live ready leases and the fixed absolute
    /// lifetime deadline.
    ///
    /// # Errors
    ///
    /// Fails when the lease is not ready, expired, has no expiry, the
    /// extension is zero, arithmetic overflows, or the absolute cap would
    /// be exceeded.
    pub fn extend_expiry(&self, now: i64, by_seconds: u32) -> Result<i64, String> {
        if self.state != LeaseState::Ready {
            return Err("only ready leases can be extended".to_owned());
        }
        let current_expiry = self
            .expires_at
            .ok_or_else(|| "the ready lease has no expiry deadline".to_owned())?;
        if current_expiry <= now {
            return Err("the lease TTL has already expired".to_owned());
        }
        if by_seconds == 0 {
            return Err("the extension must be greater than zero seconds".to_owned());
        }
        let extension_millis = i64::from(by_seconds)
            .checked_mul(1_000)
            .ok_or_else(|| "the extension is too large".to_owned())?;
        let new_expiry = current_expiry
            .checked_add(extension_millis)
            .ok_or_else(|| "the extension deadline overflows".to_owned())?;
        if new_expiry > self.max_lifetime_at {
            return Err("the extension exceeds the lease's maximum lifetime".to_owned());
        }
        Ok(new_expiry)
    }
}

#[cfg(test)]
mod lease_tests {
    use super::*;

    fn lease(state: LeaseState, expires_at: Option<i64>) -> Lease {
        Lease {
            id: "lease-1".to_owned(),
            template_version_id: "tpl-1@abc".to_owned(),
            owner: "tester".to_owned(),
            purpose: "the demo".to_owned(),
            project_id: None,
            state,
            provision_id: None,
            cleanup: CleanupStrategy::Destroy,
            ttl_seconds: 3_600,
            created_at: 1_800_000_000_000,
            max_lifetime_at: 1_800_000_000_000 + 30 * 24 * 3_600_000,
            ready_at: None,
            expires_at,
            cleanup_attempts: 0,
        }
    }

    #[test]
    fn only_a_ready_lease_with_a_deadline_expires() {
        let now = 1_800_000_100_000;
        assert!(lease(LeaseState::Ready, Some(1_800_000_050_000)).ttl_expired(now));
        // Not yet expired.
        assert!(!lease(LeaseState::Ready, Some(1_800_000_200_000)).ttl_expired(now));
        // No deadline: never expires.
        assert!(!lease(LeaseState::Ready, None).ttl_expired(now));
        // A non-ready lease never expires (the TTL starts at ready).
        assert!(!lease(LeaseState::Provisioning, Some(1_800_000_050_000)).ttl_expired(now));
    }

    #[test]
    fn extending_a_lease_is_ready_unexpired_positive_and_within_its_absolute_cap() {
        let created_at = 1_800_000_000_000;
        let ready = lease(LeaseState::Ready, Some(created_at + 3_600_000));

        assert_eq!(
            ready.extend_expiry(created_at + 600_000, 3_600),
            Ok(created_at + 7_200_000)
        );
        assert!(ready.extend_expiry(created_at + 3_600_000, 1).is_err());
        assert!(ready.extend_expiry(created_at + 600_000, 0).is_err());

        let mut too_close_to_cap = ready.clone();
        too_close_to_cap.expires_at = Some(too_close_to_cap.max_lifetime_at - 1_000);
        assert!(too_close_to_cap.extend_expiry(created_at, 2).is_err());

        let mut provisioning = ready;
        provisioning.state = LeaseState::Provisioning;
        assert!(provisioning.extend_expiry(created_at, 1).is_err());
    }

    #[test]
    fn becoming_ready_starts_ttl_and_honors_the_creation_cap() {
        let created_at = 1_800_000_000_000;
        let mut provisioning = lease(LeaseState::Provisioning, None);
        provisioning.provision_id = Some("provision-1".to_owned());
        provisioning.ttl_seconds = 3_600;
        provisioning.mark_ready(created_at + 500).unwrap();
        assert_eq!(provisioning.state, LeaseState::Ready);
        assert_eq!(provisioning.ready_at, Some(created_at + 500));
        assert_eq!(provisioning.expires_at, Some(created_at + 3_600_500));

        let mut nearly_expired = lease(LeaseState::Provisioning, None);
        nearly_expired.provision_id = Some("provision-2".to_owned());
        nearly_expired.ttl_seconds = 3_600;
        nearly_expired
            .mark_ready(nearly_expired.max_lifetime_at - 1_000)
            .unwrap();
        assert_eq!(
            nearly_expired.expires_at,
            Some(nearly_expired.max_lifetime_at)
        );

        let mut requested = lease(LeaseState::Requested, None);
        requested.provision_id = Some("provision-3".to_owned());
        assert!(requested.mark_ready(created_at).is_err());
    }

    #[test]
    fn terminal_states_are_recorded() {
        assert!(LeaseState::Released.is_terminal());
        assert!(LeaseState::Failed.is_terminal());
        assert!(LeaseState::CleanupFailed.is_terminal());
        assert!(!LeaseState::Ready.is_terminal());
        assert!(!LeaseState::Releasing.is_terminal());
    }

    #[test]
    fn lease_states_round_trip_their_ids() {
        for id in [
            "requested",
            "queued",
            "reserving",
            "provisioning",
            "booting",
            "ready",
            "releasing",
            "released",
            "failed",
            "cleanup_failed",
        ] {
            assert_eq!(LeaseState::from_id(id).unwrap().id(), id);
        }
        assert!(LeaseState::from_id("mystery").is_err());
    }
}
