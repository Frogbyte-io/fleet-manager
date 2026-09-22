//! The Lab template primitives (FM-710): versioned provisioning
//! definitions pinning a promoted image version, their readiness
//! policies, and the guest states the provisioning saga records.
//!
//! A template pins an **image version id** — the promoted, immutable one
//! from FM-701 — and validates that pin against the version's promotion
//! state at the application boundary. TTL begins at ready, never at
//! provisioning start (the architecture rule).

use serde::{Deserialize, Serialize};

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
