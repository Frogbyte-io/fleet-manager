//! Permanent, Fleet-managed VMs (#489): the request a `machine.create`
//! carries, its validation, the persistent marker that keeps Lab away from
//! the guest, and the allow-listed guest config change.
//!
//! The rules live here; the API, `fleetctl` and the controller's executor
//! are adapters. A spec holds **references and public material only**: the
//! SSH key a machine gets is a `machines/ssh/` reference or a public key,
//! a Windows product key is a `machines/product-key/` reference, and
//! nothing in it is a secret value. That is what lets the spec travel as an
//! operation payload and be bound to a review token.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Permission, authorize};
use crate::lab::LabUseCaseError;
use crate::machine_access::{EndpointAuth, MachineKeyPort};
use fleet_core::GuestOs;

/// The `image_version_id` of a marker for a VM that existed before Fleet
/// kept it (registered, not cloned from an image).
pub const REGISTERED_SOURCE: &str = "registered";

/// The Fleet name prefix Lab owns; a persistent guest never uses it.
pub const LAB_NAME_PREFIX: &str = "fm-lab-";
/// The tag every persistent guest carries, so an operator can see in
/// Proxmox which guests Fleet keeps. It is a label, never the marker: the
/// marker is the `persistent_guests` record.
pub const PERSISTENT_TAG: &str = "fleet-persistent";
/// The longest computer name Windows accepts (`NetBIOS`).
pub const MAX_WINDOWS_NAME: usize = 15;
/// The secret-record name prefix of Windows product keys.
pub const PRODUCT_KEY_PREFIX: &str = "machines/product-key/";
/// The secret-record name prefix of rotated Windows administrator passwords.
pub const ADMIN_PASSWORD_PREFIX: &str = "machines/windows-admin/";
/// The default operation deadline, in seconds.
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 1_800;
/// The longest operation deadline, in seconds.
pub const MAX_TIMEOUT_SECONDS: u64 = 7_200;
/// The tags a persistent guest may never be given: they mark guests the
/// fixture scripts or Lab treat as theirs to act on, including destroying.
const RESERVED_TAG_PREFIXES: [&str; 3] = ["fleet-pve-test", "fleet-lab", "fm-lab"];

/// How the guest's SSH host key is trusted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "mode")]
pub enum HostKeyTrust {
    /// Trust on first use: record what the guest presents and audit it, as
    /// the Lab does for its own guests.
    Tofu,
    /// The operator pinned the fingerprint out of band; any other key fails
    /// the operation.
    #[serde(rename_all = "camelCase")]
    Pinned {
        /// The OpenSSH `SHA256:` fingerprint.
        fingerprint: String,
    },
}

/// The SSH key the machine ends up with.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum CredentialChoice {
    /// Fleet generates a per-machine ed25519 key pair and keeps the private
    /// key in its secret store.
    Generate,
    /// An existing Fleet SSH credential reference.
    #[serde(rename_all = "camelCase")]
    Reference {
        /// The `machines/ssh/` or `git/` secret-record reference.
        credential: String,
    },
    /// A public key whose private half lives outside Fleet. Fleet cannot
    /// log in with it, so it keeps the bootstrap credential and says so.
    #[serde(rename_all = "camelCase")]
    PublicKey {
        /// The OpenSSH public key line.
        public_key: String,
    },
}

/// What happens to the Windows administrator password.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdminPasswordPolicy {
    /// Leave the image's password.
    #[default]
    None,
    /// Rotate to a random value generated on the guest and keep it as a
    /// Fleet secret.
    Store,
    /// Rotate to a random value generated on the guest and keep it nowhere,
    /// so only key login remains.
    Discard,
}

/// How a Windows guest is activated.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum Activation {
    /// Leave the guest unactivated: a valid, documented choice.
    #[default]
    None,
    /// A retail or MAK key held as a Fleet secret, by reference.
    #[serde(rename_all = "camelCase")]
    ProductKey {
        /// The `machines/product-key/` reference.
        secret: String,
    },
    /// A volume-licensing KMS host.
    #[serde(rename_all = "camelCase")]
    Kms {
        /// The KMS host (`host` or `host:port`).
        host: String,
    },
}

/// The Windows-only options.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsOptions {
    /// What to do with the local administrator password.
    #[serde(default)]
    pub admin_password: AdminPasswordPolicy,
    /// How to activate the guest.
    #[serde(default)]
    pub activation: Activation,
}

/// The credential Fleet uses to log in before it has installed its own key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bootstrap {
    /// The image's login user. Absent means the OS default (`root` on
    /// Linux, `fleetadmin` on Windows).
    #[serde(default)]
    pub user: Option<String>,
    /// The SSH port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// The credential the image accepts. The controller's agent by default,
    /// as for Lab guests.
    #[serde(default = "default_bootstrap_auth")]
    pub auth: EndpointAuth,
}

impl Default for Bootstrap {
    fn default() -> Self {
        Self {
            user: None,
            port: default_port(),
            auth: default_bootstrap_auth(),
        }
    }
}

const fn default_port() -> u16 {
    22
}
fn default_bootstrap_auth() -> EndpointAuth {
    EndpointAuth::Agent
}
const fn default_true() -> bool {
    true
}
const fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECONDS
}
fn default_credential() -> CredentialChoice {
    CredentialChoice::Generate
}
fn default_trust() -> HostKeyTrust {
    HostKeyTrust::Tofu
}

/// Who asked for a machine through the action broker (#496), stamped by the
/// broker's action when it builds the operation. A direct create never
/// carries it: the review refuses a spec that does.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestedBy {
    /// The requesting principal.
    pub principal: String,
    /// Why the machine is needed (the request's reason).
    pub purpose: String,
    /// The action request that asked for it.
    pub request_id: String,
    /// Who decided it: a person, or `policy:auto`. Stamped by the broker's
    /// action; recorded in the creation's audit event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
}

/// An unattended install from an ISO (#542). The ISO and the answer media are
/// existing volumes on Proxmox storage, named by volume id; Fleet carries
/// no answer-file content, so no password or product key travels in a
/// payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallSource {
    /// The installer ISO, e.g. `local:iso/ubuntu-24.04-live-server-amd64.iso`.
    pub iso: String,
    /// A second ISO holding the answer file, e.g. a `NoCloud` seed (volume
    /// label `cidata`, `user-data` and `meta-data`). It is attached as a
    /// second CD-ROM and removed with the installer once the install ends.
    #[serde(default)]
    pub answer_iso: Option<String>,
    /// Boot with OVMF (UEFI) and an EFI disk.
    #[serde(default)]
    pub efi: bool,
    /// Add a v2.0 virtual TPM (needs a storage; implies nothing else).
    #[serde(default)]
    pub tpm: bool,
    /// Answer media Fleet builds, uploads to the installer ISO's storage,
    /// attaches and deletes after the install (#549), instead of an
    /// operator-prepared `answerIso`. The payload carries options only: no
    /// file content, key or password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<GeneratedAnswer>,
    /// The virtio-win drivers ISO, attached as a CD-ROM for a Windows
    /// install. Operator-provided (Fleet does not carry Microsoft or Red Hat
    /// binaries); it also supplies the QEMU guest agent Fleet needs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drivers_iso: Option<String>,
}

/// The answer media Fleet generates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type", deny_unknown_fields)]
pub enum GeneratedAnswer {
    /// A `NoCloud` seed (`cidata`: `user-data`, `meta-data`) for an Ubuntu
    /// Server autoinstall: key-only login, no password.
    Nocloud,
    /// An `autounattend.xml` for Windows 11 on UEFI with a TPM.
    #[serde(rename_all = "camelCase")]
    Autounattend {
        /// The edition's image name; `Windows 11 Pro` when absent.
        #[serde(default)]
        edition: Option<String>,
    },
}

impl InstallSource {
    /// Whether the guest boots with OVMF: asked for, or a Windows answer.
    #[must_use]
    pub fn uses_efi(&self) -> bool {
        self.efi || matches!(self.answer, Some(GeneratedAnswer::Autounattend { .. }))
    }

    /// Whether the guest gets a vTPM: asked for, or a Windows answer.
    #[must_use]
    pub fn uses_tpm(&self) -> bool {
        self.tpm || matches!(self.answer, Some(GeneratedAnswer::Autounattend { .. }))
    }
}

/// Whether a value is a Proxmox ISO volume id (`storage:iso/name.iso`).
///
/// # Errors
///
/// Answers which rule the volume id broke.
pub fn validate_iso_volume(volume: &str, what: &str) -> Result<(), String> {
    let ok = volume.len() <= 200
        && volume.split_once(":iso/").is_some_and(|(storage, file)| {
            !storage.is_empty()
                && storage
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                && file.to_ascii_lowercase().ends_with(".iso")
                && file.len() > 4
                && file
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
        });
    if ok {
        Ok(())
    } else {
        Err(format!(
            "the {what} must be a Proxmox ISO volume id such as local:iso/name.iso"
        ))
    }
}

/// Everything a `machine.create` needs. The wire shape of the review and
/// create calls and of the operation payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateMachineSpec {
    /// The Proxmox account that holds the template and receives the guest.
    pub account_id: String,
    /// The promoted image version to clone. Empty (absent) when the guest is
    /// installed from an ISO (`install`); exactly one of the two is given.
    #[serde(default)]
    pub image_version_id: String,
    /// Install from an ISO with an unattended answer file instead of cloning
    /// an image (Linux only for now).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install: Option<InstallSource>,
    /// The VM and machine name.
    pub name: String,
    /// The target VMID; the next free one when absent.
    #[serde(default)]
    pub vmid: Option<u32>,
    /// The target node; the template's node when absent.
    #[serde(default)]
    pub node: Option<String>,
    /// The storage the clone's disks land on; the template's when absent.
    #[serde(default)]
    pub storage: Option<String>,
    /// vCPU cores; the template's when absent.
    #[serde(default)]
    pub cores: Option<u32>,
    /// Memory in MiB; the template's when absent.
    #[serde(default)]
    pub memory_mib: Option<u32>,
    /// The boot disk size in GiB, grown to this; the template's when absent.
    #[serde(default)]
    pub disk_gib: Option<u32>,
    /// The bridge of `net0`; the template's when absent.
    #[serde(default)]
    pub bridge: Option<String>,
    /// The virtual audio device; the template's when absent.
    #[serde(default)]
    pub audio: Option<String>,
    /// Tags. The template's tags are never inherited.
    #[serde(default)]
    pub tags: Vec<String>,
    /// The Proxmox description.
    #[serde(default)]
    pub description: String,
    /// Start the guest when the node boots.
    #[serde(default = "default_true")]
    pub onboot: bool,
    /// Refuse deletion in Proxmox until protection is lifted.
    #[serde(default = "default_true")]
    pub protection: bool,
    /// The guest's OS.
    #[serde(default)]
    pub guest_os: GuestOs,
    /// How Fleet logs in first.
    #[serde(default)]
    pub bootstrap: Bootstrap,
    /// How the host key is trusted.
    #[serde(default = "default_trust")]
    pub host_key: HostKeyTrust,
    /// The key the machine ends up with.
    #[serde(default = "default_credential")]
    pub credential: CredentialChoice,
    /// A login user other than the image default, created if missing.
    #[serde(default)]
    pub login_user: Option<String>,
    /// The Windows-only options.
    #[serde(default)]
    pub windows: Option<WindowsOptions>,
    /// The operation deadline, in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Who asked for it through the action broker; absent for a direct
    /// create. Set only by the broker's action, never by a caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<RequestedBy>,
}

fn identifier(value: &str, what: &str, max: usize) -> Result<(), String> {
    let ok = !value.is_empty()
        && value.len() <= max
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && value.starts_with(|c: char| c.is_ascii_alphanumeric());
    if ok {
        Ok(())
    } else {
        Err(format!(
            "the {what} must be 1 to {max} characters of letters, digits, `-`, `_` or `.`, starting with a letter or digit"
        ))
    }
}

/// Validates a VM and machine name: a DNS-style label, never a Lab name.
///
/// # Errors
///
/// Answers which rule the name broke.
pub fn validate_name(name: &str, os: GuestOs) -> Result<(), String> {
    let label = !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !label {
        return Err(
            "the name must be 1 to 63 letters, digits or `-`, not starting or ending with `-`"
                .to_owned(),
        );
    }
    if name.to_ascii_lowercase().starts_with(LAB_NAME_PREFIX) {
        return Err(format!(
            "the name must not start with {LAB_NAME_PREFIX}: that prefix belongs to Lab guests"
        ));
    }
    if os == GuestOs::Windows {
        if name.len() > MAX_WINDOWS_NAME {
            return Err(format!(
                "a Windows computer name is at most {MAX_WINDOWS_NAME} characters; the name has {}",
                name.len()
            ));
        }
        if name.chars().all(|c| c.is_ascii_digit()) {
            return Err("a Windows computer name cannot be only digits".to_owned());
        }
    }
    Ok(())
}

/// Validates one tag: PVE's tag alphabet, and never a fixture or Lab tag.
///
/// # Errors
///
/// Answers which rule the tag broke.
pub fn validate_tag(tag: &str) -> Result<(), String> {
    let ok = !tag.is_empty()
        && tag.len() <= 32
        && tag.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && tag.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '+' | '.')
        });
    if !ok {
        return Err(format!(
            "the tag {tag:?} must be 1 to 32 characters of lower-case letters, digits, `_`, `-`, `+` or `.`"
        ));
    }
    if let Some(prefix) = RESERVED_TAG_PREFIXES
        .iter()
        .find(|prefix| tag.starts_with(**prefix))
    {
        return Err(format!(
            "the tag {tag:?} is reserved ({prefix}*): fixture and Lab tags mark guests other tools act on and destroy"
        ));
    }
    Ok(())
}

/// Whether a tag is one fixture or Lab tooling acts on (so a guest carrying
/// it must not be registered as persistent).
#[must_use]
pub fn is_reserved_tag(tag: &str) -> bool {
    RESERVED_TAG_PREFIXES
        .iter()
        .any(|prefix| tag.starts_with(*prefix))
}

fn validate_tags(tags: &[String]) -> Result<(), String> {
    if tags.len() > 16 {
        return Err("at most 16 tags".to_owned());
    }
    tags.iter().try_for_each(|tag| validate_tag(tag))
}

fn validate_description(description: &str) -> Result<(), String> {
    if description.chars().count() > 1_024 || description.chars().any(char::is_control) {
        return Err(
            "the description must be at most 1024 characters without control characters".to_owned(),
        );
    }
    Ok(())
}

/// The tags a persistent guest carries: the operator's, plus the label.
/// The template's tags are dropped by construction, because the write
/// replaces the whole tag list.
#[must_use]
pub fn persistent_tags(operator: &[String]) -> Vec<String> {
    let mut tags: Vec<String> = operator.to_vec();
    tags.push(PERSISTENT_TAG.to_owned());
    tags.sort();
    tags.dedup();
    tags
}

/// Checks an OpenSSH public key line: one line, a known type, base64.
///
/// # Errors
///
/// Answers which rule the key broke.
pub fn validate_public_key(key: &str) -> Result<(), String> {
    let key = key.trim();
    let mut parts = key.split_whitespace();
    let kind = parts.next().unwrap_or_default();
    let body = parts.next().unwrap_or_default();
    let known = matches!(
        kind,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "sk-ssh-ed25519@openssh.com"
    );
    let base64 = !body.is_empty()
        && body.len() <= 1_024
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='));
    let comment = parts.collect::<Vec<_>>().join(" ");
    if !known
        || !base64
        || key.contains(['\n', '\r'])
        || comment.len() > 128
        || comment.chars().any(char::is_control)
        || key.len() > 2_048
    {
        return Err(
            "the public key must be one OpenSSH public key line (type, base64 body, optional comment)"
                .to_owned(),
        );
    }
    Ok(())
}

impl CreateMachineSpec {
    /// The rules of an install's answer media and guest OS.
    fn validate_install_answer(&self, install: &InstallSource) -> Result<(), String> {
        if install.answer.is_some() && install.answer_iso.is_some() {
            return Err(
                "give either answer (Fleet builds the media) or answerIso, not both".to_owned(),
            );
        }
        match (&install.answer, self.guest_os) {
            (None, GuestOs::Linux) => {
                if install.drivers_iso.is_some() {
                    return Err("driversIso belongs to a Windows install".to_owned());
                }
                return Ok(());
            }
            (None, GuestOs::Windows) => {
                return Err(
                    "a Windows install needs answer {type: autounattend}; or clone the generalized base image"
                        .to_owned(),
                );
            }
            (Some(GeneratedAnswer::Nocloud), GuestOs::Windows) => {
                return Err("a NoCloud seed is for a Linux guest".to_owned());
            }
            (Some(GeneratedAnswer::Autounattend { .. }), GuestOs::Linux) => {
                return Err("autounattend is for a Windows guest".to_owned());
            }
            _ => {}
        }
        // Both generated kinds: Fleet's own bootstrap key is the way in.
        if !matches!(self.bootstrap.auth, EndpointAuth::Agent) {
            return Err(
                "generated answer media installs a Fleet-generated bootstrap key; leave bootstrap.auth at its default"
                    .to_owned(),
            );
        }
        if matches!(self.credential, CredentialChoice::PublicKey { .. }) {
            return Err(
                "generated answer media needs Fleet to hold the final key: use credential generate or a stored reference, not an operator-held public key"
                    .to_owned(),
            );
        }
        crate::answer_media::check_hostname(&self.name)?;
        match &install.answer {
            Some(GeneratedAnswer::Nocloud) => {
                if self.bootstrap_user() == "root" {
                    return Err(
                        "the generated seed creates a regular sudo user: set bootstrap.user (not root)"
                            .to_owned(),
                    );
                }
                if install.drivers_iso.is_some() {
                    return Err("driversIso belongs to a Windows install".to_owned());
                }
            }
            Some(GeneratedAnswer::Autounattend { edition }) => {
                let Some(drivers) = &install.drivers_iso else {
                    return Err(
                        "a Windows install needs driversIso (the virtio-win ISO): it carries the disk and network drivers and the guest agent Fleet reaches the guest through"
                            .to_owned(),
                    );
                };
                validate_iso_volume(drivers, "drivers ISO")?;
                if *drivers == install.iso {
                    return Err("the drivers ISO must differ from the installer ISO".to_owned());
                }
                if let Some(edition) = edition {
                    crate::answer_media::check_image_name(edition)?;
                }
                if self.disk_gib.is_some_and(|gib| gib < 64) {
                    return Err("Windows 11 needs a disk of at least 64 GiB".to_owned());
                }
                let policy = self
                    .windows
                    .as_ref()
                    .map(|options| options.admin_password)
                    .unwrap_or_default();
                if policy == AdminPasswordPolicy::None {
                    return Err(
                        "the answer file sets a throwaway administrator password: set windows.adminPassword to store or discard so Fleet rotates it"
                            .to_owned(),
                    );
                }
            }
            None => {}
        }
        Ok(())
    }

    /// Checks every rule that needs no I/O.
    ///
    /// # Errors
    ///
    /// Answers the first rule the spec breaks, naming the field.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), String> {
        identifier(&self.account_id, "account id", 128)?;
        match &self.install {
            None => identifier(&self.image_version_id, "image version id", 128)?,
            Some(install) => {
                if !self.image_version_id.is_empty() {
                    return Err(
                        "give either an imageVersionId or an install source, not both".to_owned(),
                    );
                }
                validate_iso_volume(&install.iso, "installer ISO")?;
                if let Some(answer) = &install.answer_iso {
                    validate_iso_volume(answer, "answer ISO")?;
                    if *answer == install.iso {
                        return Err("the answer ISO must differ from the installer ISO".to_owned());
                    }
                }
                self.validate_install_answer(install)?;
                if self.node.is_none() || self.storage.is_none() || self.disk_gib.is_none() {
                    return Err(
                        "an install needs node, storage and diskGib: there is no template to take them from"
                            .to_owned(),
                    );
                }
            }
        }
        validate_name(&self.name, self.guest_os)?;
        if let Some(vmid) = self.vmid
            && !(100..=999_999_999).contains(&vmid)
        {
            return Err("the VMID must be between 100 and 999999999".to_owned());
        }
        for (value, what) in [(&self.node, "node"), (&self.storage, "storage")] {
            if let Some(value) = value {
                identifier(value, what, 64)?;
            }
        }
        if let Some(cores) = self.cores
            && !(1..=128).contains(&cores)
        {
            return Err("cores must be between 1 and 128".to_owned());
        }
        if let Some(memory) = self.memory_mib
            && !(128..=1_048_576).contains(&memory)
        {
            return Err("memory must be between 128 and 1048576 MiB".to_owned());
        }
        if let Some(disk) = self.disk_gib
            && !(1..=65_536).contains(&disk)
        {
            return Err("the disk must be between 1 and 65536 GiB".to_owned());
        }
        if let Some(bridge) = &self.bridge {
            identifier(bridge, "bridge", 16)?;
        }
        if let Some(audio) = &self.audio
            && !matches!(audio.as_str(), "ich9-intel-hda" | "intel-hda" | "AC97")
        {
            return Err("the audio device must be ich9-intel-hda, intel-hda or AC97".to_owned());
        }
        validate_tags(&self.tags)?;
        validate_description(&self.description)?;
        if let Some(user) = &self.bootstrap.user {
            validate_login_user(user, self.guest_os)?;
        }
        if self.bootstrap.port == 0 {
            return Err("the bootstrap port must be positive".to_owned());
        }
        self.bootstrap.auth.validate()?;
        if let HostKeyTrust::Pinned { fingerprint } = &self.host_key
            && (!fingerprint.starts_with("SHA256:") || fingerprint.len() > 128)
        {
            return Err("the pinned fingerprint must be an OpenSSH SHA256 fingerprint".to_owned());
        }
        match &self.credential {
            CredentialChoice::Generate => {}
            CredentialChoice::Reference { credential } => EndpointAuth::Secret {
                credential: credential.clone(),
            }
            .validate()?,
            CredentialChoice::PublicKey { public_key } => {
                validate_public_key(public_key)?;
                // Fleet cannot log in with a key it does not hold, so it would
                // have no way to use the endpoint of another user.
                if self.login_user.is_some() {
                    return Err(
                        "a loginUser cannot be combined with a publicKey: Fleet cannot log in with that key, so the endpoint would not be reachable"
                            .to_owned(),
                    );
                }
            }
        }
        if let Some(user) = &self.login_user {
            validate_login_user(user, self.guest_os)?;
        }
        match (&self.windows, self.guest_os) {
            (Some(_), GuestOs::Linux) => {
                return Err("the windows options need guestOs windows".to_owned());
            }
            (Some(options), GuestOs::Windows) => match &options.activation {
                Activation::None => {}
                Activation::ProductKey { secret } => {
                    EndpointAuth::Secret {
                        credential: secret.clone(),
                    }
                    .validate()
                    .map_err(|_| "the product key reference is malformed".to_owned())?;
                }
                Activation::Kms { host } => validate_kms_host(host)?,
            },
            (None, _) => {}
        }
        if !(60..=MAX_TIMEOUT_SECONDS).contains(&self.timeout_seconds) {
            return Err(format!(
                "the timeout must be between 60 and {MAX_TIMEOUT_SECONDS} seconds"
            ));
        }
        if let Some(by) = &self.requested_by
            && (by.principal.is_empty()
                || by.principal.len() > 256
                || by.purpose.trim().is_empty()
                || by.purpose.chars().count() > 1_000
                || by.request_id.is_empty()
                || by.request_id.len() > 96
                || [&by.principal, &by.purpose, &by.request_id]
                    .iter()
                    .any(|text| text.chars().any(char::is_control)))
        {
            return Err("the requestedBy stamp is malformed".to_owned());
        }
        Ok(())
    }

    /// What the guest comes from, as recorded on its marker: the image
    /// version, or `install:<iso volume>`.
    #[must_use]
    pub fn source_id(&self) -> String {
        match &self.install {
            Some(install) => format!("install:{}", install.iso),
            None => self.image_version_id.clone(),
        }
    }

    /// The user Fleet logs in with before it installs its key.
    #[must_use]
    pub fn bootstrap_user(&self) -> &str {
        self.bootstrap
            .user
            .as_deref()
            .unwrap_or(match self.guest_os {
                GuestOs::Linux => "root",
                GuestOs::Windows => "fleetadmin",
            })
    }

    /// The user the machine's endpoint ends up with.
    #[must_use]
    pub fn endpoint_user(&self) -> &str {
        self.login_user
            .as_deref()
            .unwrap_or_else(|| self.bootstrap_user())
    }

    /// The operation payload: the spec itself, in a fixed field order, so
    /// the review and create calls bind the same bytes.
    ///
    /// # Errors
    ///
    /// Fails only if the spec cannot be serialized, which it always can.
    pub fn to_payload(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|error| error.to_string())
    }
}

fn validate_login_user(user: &str, os: GuestOs) -> Result<(), String> {
    let (max, linux) = match os {
        GuestOs::Linux => (32, true),
        GuestOs::Windows => (20, false),
    };
    let ok = !user.is_empty()
        && user.len() <= max
        && !user.starts_with('-')
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-') || (!linux && c == '.'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "the login user must be 1 to {max} characters of letters, digits, `_` or `-`, not starting with `-`"
        ))
    }
}

fn validate_kms_host(host: &str) -> Result<(), String> {
    let (name, port) = host
        .rsplit_once(':')
        .map_or((host, None), |(n, p)| (n, Some(p)));
    let name_ok = !name.is_empty()
        && name.len() <= 253
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'));
    let port_ok = port.is_none_or(|port| port.parse::<u16>().is_ok_and(|port| port > 0));
    if name_ok && port_ok {
        Ok(())
    } else {
        Err("the KMS host must be a host name or address, optionally with `:port`".to_owned())
    }
}

/// The settings of a guest the `proxmox.guest.config` action may change.
/// Anything else is refused: the allow-list is the contract.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestConfigChange {
    /// Replace the tag list; an empty list clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Replace the description; empty clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Start the guest when the node boots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onboot: Option<bool>,
    /// Refuse (or allow) deletion in Proxmox.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection: Option<bool>,
    /// vCPU cores.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cores: Option<u32>,
    /// Memory in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<u32>,
}

impl GuestConfigChange {
    /// Reads the reviewed parameters, refusing any key outside the
    /// allow-list.
    ///
    /// # Errors
    ///
    /// Answers which key or value is not allowed.
    pub fn from_params(params: &serde_json::Value) -> Result<Self, String> {
        let change: Self = serde_json::from_value(params.clone()).map_err(|error| {
            format!(
                "the config parameters allow only tags, description, onboot, protection, cores and memoryMib: {error}"
            )
        })?;
        change.validate()?;
        Ok(change)
    }

    /// Checks the values.
    ///
    /// # Errors
    ///
    /// Answers which value is out of bounds, or that nothing changes.
    pub fn validate(&self) -> Result<(), String> {
        if *self == Self::default() {
            return Err("the config change sets nothing".to_owned());
        }
        if let Some(tags) = &self.tags {
            validate_tags(tags)?;
        }
        if let Some(description) = &self.description {
            validate_description(description)?;
        }
        if let Some(cores) = self.cores
            && !(1..=128).contains(&cores)
        {
            return Err("cores must be between 1 and 128".to_owned());
        }
        if let Some(memory) = self.memory_mib
            && !(128..=1_048_576).contains(&memory)
        {
            return Err("memory must be between 128 and 1048576 MiB".to_owned());
        }
        Ok(())
    }
}

/// How far a persistent guest's creation got.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistentState {
    /// The creation is running or stopped part-way; the guest may exist.
    Creating,
    /// The guest was created, reached, registered and linked.
    Ready,
}

impl PersistentState {
    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Ready => "ready",
        }
    }

    /// Parses the stable string.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "creating" => Some(Self::Creating),
            "ready" => Some(Self::Ready),
            _ => None,
        }
    }
}

/// The persistent marker: Fleet keeps this guest, and Lab never selects it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistentGuest {
    /// The Proxmox account.
    pub account_id: String,
    /// The guest's VMID.
    pub vmid: u32,
    /// The VM and machine name.
    pub name: String,
    /// The node the guest was created on.
    pub node: String,
    /// The image version it was cloned from.
    pub image_version_id: String,
    /// The machine record, once registered.
    pub machine_id: Option<String>,
    /// Whether the clone completed. Until it has, the marker guards a VMID
    /// only while the live guest there still carries the marked name: a
    /// clone that failed leaves a marker that must never shield whatever
    /// guest later takes the VMID.
    pub cloned: bool,
    /// How far the creation got.
    pub state: PersistentState,
    /// The step the creation last completed or failed at.
    pub step: Option<String>,
    /// The operation that created it.
    pub operation_id: Option<String>,
    /// Creation time (epoch milliseconds).
    pub created_at: i64,
    /// Last update (epoch milliseconds).
    pub updated_at: i64,
}

impl PersistentGuest {
    /// Whether this marker protects the guest now at its VMID: the clone
    /// completed, or the live guest still has the marked name. `live_name`
    /// is the name the cluster reports at the VMID (`None` when nothing is
    /// there). A stale marker (failed clone, another guest on the VMID)
    /// protects nothing.
    #[must_use]
    pub fn guards(&self, live_name: Option<&str>) -> bool {
        if self.is_registered() {
            // A registered VM was never cloned by Fleet: it is guarded only
            // while the guest at the VMID still has the registered name, so
            // a marker whose VM is gone or renamed expires by itself.
            return live_name == Some(self.name.as_str());
        }
        match live_name {
            Some(name) => self.cloned || name == self.name,
            None => self.cloned,
        }
    }

    /// Whether the marker was written by registering an existing VM, not by
    /// creating one.
    #[must_use]
    pub fn is_registered(&self) -> bool {
        self.image_version_id == REGISTERED_SOURCE
    }
}

/// What stops a marker from being abandoned: the controller checks the live
/// world (a creation still running, a guest that has the marked name).
#[async_trait]
pub trait AbandonGuard: fmt::Debug + Send + Sync {
    /// Why this marker must not be abandoned now, or `None` when it may.
    ///
    /// # Errors
    ///
    /// Fails when the world cannot be read; the abandon is refused then.
    async fn blocking_reason(&self, marker: &PersistentGuest) -> Result<Option<String>, String>;
}

/// What the live world says about a guest that may be registered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveGuest {
    /// The guest's name.
    pub name: String,
    /// The node it runs on.
    pub node: String,
}

/// The answer of [`RegisterGuard::inspect`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestCheck {
    /// A QEMU VM that is not a template, image artifact, Lab clone or pool
    /// member.
    Eligible(LiveGuest),
    /// Why the guest cannot be registered.
    Refused(String),
}

/// The live checks of registering an existing VM as persistent: the
/// controller reads the cluster and Lab's own records.
#[async_trait]
pub trait RegisterGuard: fmt::Debug + Send + Sync {
    /// Looks at the guest at a VMID.
    ///
    /// # Errors
    ///
    /// Fails when the world cannot be read; the registration is refused then.
    async fn inspect(&self, account_id: &str, vmid: u32) -> Result<GuestCheck, String>;
}

/// What a reviewed registration will record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterReview {
    /// The token the register call must present.
    pub review_token: String,
    /// The live guest's name.
    pub name: String,
    /// The live guest's node.
    pub node: String,
}

/// The persistent marker store.
#[async_trait]
pub trait PersistentGuestPort: fmt::Debug + Send + Sync {
    /// Records the marker before anything is cloned. Idempotent for the
    /// same account, VMID and name; a different name at the same VMID is a
    /// conflict, never an overwrite.
    ///
    /// # Errors
    ///
    /// Fails on a conflict or a backend error.
    async fn reserve(&self, guest: &PersistentGuest) -> Result<PersistentGuest, String>;
    /// The marker of one guest, when it has one.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read.
    async fn get(&self, account_id: &str, vmid: u32) -> Result<Option<PersistentGuest>, String>;
    /// Replaces a marker's progress fields.
    ///
    /// # Errors
    ///
    /// Fails when the marker is unknown or the store errors.
    async fn update(&self, guest: &PersistentGuest) -> Result<(), String>;
    /// Every marker, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read.
    async fn list(&self) -> Result<Vec<PersistentGuest>, String>;
    /// Removes a marker (after its guest was destroyed).
    ///
    /// # Errors
    ///
    /// Fails when the store errors.
    async fn remove(&self, account_id: &str, vmid: u32) -> Result<(), String>;
    /// Records who asked for a guest and why. Only the create executor calls
    /// this, from the broker's stamp on the reviewed payload.
    ///
    /// # Errors
    ///
    /// Fails when the marker is unknown or the store errors.
    async fn record_owner(
        &self,
        account_id: &str,
        vmid: u32,
        owner: &RequestedBy,
    ) -> Result<(), String>;
    /// Who asked for the guest at a VMID, when it was requested (recorded
    /// when the marker is reserved, so a half-made creation has it too).
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read.
    async fn owner_of(&self, account_id: &str, vmid: u32) -> Result<Option<RequestedBy>, String>;
    /// Who asked for the guest behind a machine, when it was requested.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read.
    async fn owner_of_machine(&self, machine_id: &str) -> Result<Option<RequestedBy>, String>;
}

/// Windows product keys, held as encrypted secret records. The value is
/// readable only by the create executor, never returned by any API.
#[async_trait]
pub trait ProductKeyPort: fmt::Debug + Send + Sync {
    /// Stores a product key and answers its reference.
    ///
    /// # Errors
    ///
    /// Fails, without echoing the value, when it is not a product key or
    /// the store errors.
    async fn create(&self, product_key: &str) -> Result<String, String>;
    /// Whether the reference names a live product key.
    ///
    /// # Errors
    ///
    /// Fails when the store errors.
    async fn exists(&self, reference: &str) -> Result<bool, String>;
}

/// Checks the shape of a Windows product key: five groups of five
/// letters and digits. The value is never echoed.
///
/// # Errors
///
/// Answers that the value is not a product key.
pub fn validate_product_key(key: &str) -> Result<(), String> {
    let groups: Vec<&str> = key.trim().split('-').collect();
    let ok = groups.len() == 5
        && groups
            .iter()
            .all(|group| group.len() == 5 && group.chars().all(|c| c.is_ascii_alphanumeric()));
    if ok {
        Ok(())
    } else {
        Err("the value is not a product key (five groups of five letters and digits)".to_owned())
    }
}

/// What a reviewed `machine.create` is: the exact payload and the token that
/// binds the create call to it.
#[derive(Clone, Debug)]
pub struct Prepared {
    /// The operation payload.
    pub payload_json: String,
    /// The review token over the kind and the payload.
    pub review_token: String,
}

/// The authorized `machine.create` request use case. It validates and
/// checks references; the operation itself is queued by the API through
/// [`crate::operation::Operations`], which re-checks the token.
#[derive(Debug)]
pub struct PersistentMachines {
    images: Arc<dyn crate::lab::ImagePinValidator>,
    keys: Option<Arc<dyn MachineKeyPort>>,
    product_keys: Option<Arc<dyn ProductKeyPort>>,
    markers: Option<Arc<dyn PersistentGuestPort>>,
    abandon_guard: Option<Arc<dyn AbandonGuard>>,
    register_guard: Option<Arc<dyn RegisterGuard>>,
    machines: Option<Arc<dyn crate::machine::MachinePort>>,
    guest_links: Option<Arc<dyn crate::machine::GuestLinkPort>>,
    audit: Arc<dyn crate::operation::AuditPort>,
}

fn backend(detail: String) -> LabUseCaseError {
    LabUseCaseError::Backend {
        context: "persistent machines",
        detail,
    }
}

fn invalid(detail: String) -> LabUseCaseError {
    LabUseCaseError::Invalid { detail }
}

impl PersistentMachines {
    /// Composes the use case.
    #[must_use]
    pub fn new(
        images: Arc<dyn crate::lab::ImagePinValidator>,
        audit: Arc<dyn crate::operation::AuditPort>,
    ) -> Self {
        Self {
            images,
            keys: None,
            product_keys: None,
            markers: None,
            abandon_guard: None,
            register_guard: None,
            machines: None,
            guest_links: None,
            audit,
        }
    }

    /// Wires the live checks an abandon needs: without them an abandon is
    /// refused.
    #[must_use]
    pub fn with_abandon_guard(mut self, guard: Arc<dyn AbandonGuard>) -> Self {
        self.abandon_guard = Some(guard);
        self
    }

    /// Wires the marker store, for the guards the API applies before it
    /// queues a destroy and for abandoning a stale marker.
    #[must_use]
    pub fn with_markers(mut self, markers: Arc<dyn PersistentGuestPort>) -> Self {
        self.markers = Some(markers);
        self
    }

    /// The marker of one guest, when it has one.
    ///
    /// # Errors
    ///
    /// Fails when the marker store cannot be read.
    pub async fn marker(
        &self,
        account_id: &str,
        vmid: u32,
    ) -> Result<Option<PersistentGuest>, LabUseCaseError> {
        match &self.markers {
            Some(markers) => markers.get(account_id, vmid).await.map_err(backend),
            None => Ok(None),
        }
    }

    /// Who asked for a machine and why, when it was created from a request.
    ///
    /// # Errors
    ///
    /// Fails when the marker store cannot be read.
    pub async fn ownership(
        &self,
        machine_id: &str,
    ) -> Result<Option<RequestedBy>, LabUseCaseError> {
        match &self.markers {
            Some(markers) => markers.owner_of_machine(machine_id).await.map_err(backend),
            None => Ok(None),
        }
    }

    /// Wires the live checks a registration needs: without them a
    /// registration is refused.
    #[must_use]
    pub fn with_register_guard(mut self, guard: Arc<dyn RegisterGuard>) -> Self {
        self.register_guard = Some(guard);
        self
    }

    /// Wires the machine records, so a registration can name its machine.
    #[must_use]
    pub fn with_machines(mut self, machines: Arc<dyn crate::machine::MachinePort>) -> Self {
        self.machines = Some(machines);
        self
    }

    /// Wires the guest links, so a registration can refuse a machine whose
    /// guest link points at another guest.
    #[must_use]
    pub fn with_guest_links(mut self, links: Arc<dyn crate::machine::GuestLinkPort>) -> Self {
        self.guest_links = Some(links);
        self
    }

    /// Every persistent marker, newest first.
    ///
    /// # Errors
    ///
    /// Fails on denial or when the marker store cannot be read.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<Vec<PersistentGuest>, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineRead,
                resource: None,
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        match &self.markers {
            Some(markers) => markers.list().await.map_err(backend),
            None => Ok(Vec::new()),
        }
    }

    /// The review token of registering one existing guest: it binds the call
    /// to the exact account, VMID and machine that were reviewed.
    #[must_use]
    pub fn register_payload(
        account_id: &str,
        vmid: u32,
        machine_id: Option<&str>,
    ) -> (String, String) {
        let payload = serde_json::json!({
            "accountId": account_id,
            "vmid": vmid,
            "machineId": machine_id,
        })
        .to_string();
        let token = crate::operation::review_token_for("persistent.register", &payload);
        (payload, token)
    }

    /// Everything a registration needs to hold, short of writing it.
    async fn check_register(
        &self,
        account_id: &str,
        vmid: u32,
        machine_id: Option<&str>,
    ) -> Result<LiveGuest, LabUseCaseError> {
        if account_id.is_empty() || vmid == 0 {
            return Err(invalid(
                "an account and a positive VMID are required".to_owned(),
            ));
        }
        let markers = self
            .markers
            .as_ref()
            .ok_or_else(|| backend("no marker store is wired".to_owned()))?;
        let guard = self
            .register_guard
            .as_ref()
            .ok_or_else(|| backend("no register guard is wired".to_owned()))?;
        if let Some(marker) = markers.get(account_id, vmid).await.map_err(backend)? {
            return Err(LabUseCaseError::Conflict {
                detail: format!("VMID {vmid} is already marked persistent ({})", marker.name),
            });
        }
        let live = match guard.inspect(account_id, vmid).await.map_err(backend)? {
            GuestCheck::Eligible(live) => live,
            GuestCheck::Refused(reason) => return Err(invalid(reason)),
        };
        if live.name.to_ascii_lowercase().starts_with(LAB_NAME_PREFIX) {
            return Err(invalid(format!(
                "a guest named {} is a Lab clone, not a persistent machine",
                live.name
            )));
        }
        let all = markers.list().await.map_err(backend)?;
        if let Some(other) = all
            .iter()
            .find(|other| other.account_id == account_id && other.name == live.name)
        {
            return Err(LabUseCaseError::Conflict {
                detail: format!(
                    "the name {} is already a persistent guest (VMID {})",
                    live.name, other.vmid
                ),
            });
        }
        if let Some(machine_id) = machine_id {
            let machines = self
                .machines
                .as_ref()
                .ok_or_else(|| backend("no machine store is wired".to_owned()))?;
            match machines.get(machine_id).await {
                Ok(_) => {}
                Err(crate::operation::PortFailure::NotFound { .. }) => {
                    return Err(LabUseCaseError::NotFound {
                        what: format!("machine {machine_id}"),
                    });
                }
                Err(failure) => return Err(backend(failure.to_string())),
            }
            let links = self
                .guest_links
                .as_ref()
                .ok_or_else(|| backend("no guest link store is wired".to_owned()))?;
            if let Some(link) = links
                .get(machine_id)
                .await
                .map_err(|failure| backend(failure.to_string()))?
                && (link.account_id != account_id || link.vmid != vmid)
            {
                return Err(LabUseCaseError::Conflict {
                    detail: format!(
                        "machine {machine_id} is linked to {} {}/{}, not to this guest",
                        link.guest_kind, link.account_id, link.vmid
                    ),
                });
            }
            if all
                .iter()
                .any(|other| other.machine_id.as_deref() == Some(machine_id))
            {
                return Err(LabUseCaseError::Conflict {
                    detail: format!("machine {machine_id} is already linked to a persistent guest"),
                });
            }
        }
        Ok(live)
    }

    /// Reviews registering an existing VM as persistent: checks the guest
    /// live and answers what will be recorded with the token that binds the
    /// register call to it. Nothing is written.
    ///
    /// # Errors
    ///
    /// Fails on denial, an ineligible guest, a marked guest, or an unknown
    /// or already linked machine.
    pub async fn review_register(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
        vmid: u32,
        machine_id: Option<&str>,
    ) -> Result<RegisterReview, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineProvision,
                resource: None,
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        if let Some(machine_id) = machine_id {
            authorize(
                authorizer,
                AccessRequest {
                    principal_id: &principal.id,
                    action: Permission::MachineLinkGuest,
                    resource: Some(machine_id),
                },
            )
            .map_err(LabUseCaseError::Denied)?;
        }
        let live = self.check_register(account_id, vmid, machine_id).await?;
        let (_, review_token) = Self::register_payload(account_id, vmid, machine_id);
        Ok(RegisterReview {
            review_token,
            name: live.name,
            node: live.node,
        })
    }

    /// Registers an existing VM as persistent: after the same checks as the
    /// review it writes a marker for the guest (clone complete, state ready),
    /// so Lab sweeps, pools and cleanup never select it, optionally naming
    /// its Fleet machine. Nothing on the guest changes. The registration is
    /// audited.
    ///
    /// # Errors
    ///
    /// Fails on denial, a review token that does not match, an ineligible
    /// guest, a marked guest, or an unknown or already linked machine.
    #[allow(clippy::too_many_arguments)]
    pub async fn register(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
        vmid: u32,
        machine_id: Option<&str>,
        review_token: &str,
        correlation_id: Option<&str>,
    ) -> Result<PersistentGuest, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineProvision,
                resource: None,
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let (_, expected) = Self::register_payload(account_id, vmid, machine_id);
        if expected != review_token {
            return Err(invalid(
                "the review token does not match this account, VMID and machine; review the registration first"
                    .to_owned(),
            ));
        }
        if let Some(machine_id) = machine_id {
            authorize(
                authorizer,
                AccessRequest {
                    principal_id: &principal.id,
                    action: Permission::MachineLinkGuest,
                    resource: Some(machine_id),
                },
            )
            .map_err(LabUseCaseError::Denied)?;
        }
        let live = self.check_register(account_id, vmid, machine_id).await?;
        let markers = self
            .markers
            .as_ref()
            .ok_or_else(|| backend("no marker store is wired".to_owned()))?;
        let now = fleet_core::SystemClock::now_unix_millis();
        let guest = PersistentGuest {
            account_id: account_id.to_owned(),
            vmid,
            name: live.name,
            node: live.node,
            image_version_id: REGISTERED_SOURCE.to_owned(),
            machine_id: machine_id.map(str::to_owned),
            cloned: true,
            state: PersistentState::Ready,
            step: Some("registered".to_owned()),
            operation_id: None,
            created_at: now,
            updated_at: now,
        };
        let stored = markers
            .reserve(&guest)
            .await
            .map_err(|detail| LabUseCaseError::Conflict { detail })?;
        // The audit event follows a successful write. A marker that cannot
        // be audited is removed again: no unaudited registration stays.
        if let Err(error) = self
            .audit_marker(
                principal,
                "persistent_guest_registered",
                &stored,
                correlation_id,
            )
            .await
        {
            let _ = markers.remove(account_id, vmid).await;
            return Err(error);
        }
        Ok(stored)
    }

    async fn audit_marker(
        &self,
        principal: &ActingPrincipal,
        event: &str,
        marker: &PersistentGuest,
        correlation_id: Option<&str>,
    ) -> Result<(), LabUseCaseError> {
        let mut metadata = crate::audit::AuditMetadata::default();
        for (key, value) in [
            ("event", event),
            ("accountId", marker.account_id.as_str()),
            ("vmid", &marker.vmid.to_string()),
            ("name", marker.name.as_str()),
            ("node", marker.node.as_str()),
            ("machineId", marker.machine_id.as_deref().unwrap_or("none")),
        ] {
            metadata
                .insert(key, value)
                .map_err(|error| backend(error.to_string()))?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: Permission::MachineProvision.id().to_owned(),
                resource: Some(format!("{}/{}", marker.account_id, marker.vmid)),
                decision: crate::authz::Decision::allow(),
                correlation_id: correlation_id.map(str::to_owned),
                operation_id: None,
                metadata,
            })
            .await
            .map_err(backend)
    }

    /// The review token of unregistering one marker.
    #[must_use]
    pub fn unregister_payload(account_id: &str, vmid: u32) -> (String, String) {
        let payload = serde_json::json!({ "accountId": account_id, "vmid": vmid }).to_string();
        let token = crate::operation::review_token_for("persistent.unregister", &payload);
        (payload, token)
    }

    async fn registered_marker(
        &self,
        account_id: &str,
        vmid: u32,
    ) -> Result<PersistentGuest, LabUseCaseError> {
        let markers = self
            .markers
            .as_ref()
            .ok_or_else(|| backend("no marker store is wired".to_owned()))?;
        let marker = markers
            .get(account_id, vmid)
            .await
            .map_err(backend)?
            .ok_or_else(|| LabUseCaseError::NotFound {
                what: format!("a persistent marker for {account_id}/{vmid}"),
            })?;
        if !marker.is_registered() {
            return Err(LabUseCaseError::Conflict {
                detail: format!(
                    "{} was created by Fleet; destroy it with the reviewed destroy, or abandon an unfinished creation",
                    marker.name
                ),
            });
        }
        Ok(marker)
    }

    /// Reviews unregistering a registered marker (the undo of a
    /// registration). It needs no live check: the guest is not touched.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown marker, or a marker Fleet created.
    pub async fn review_unregister(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
        vmid: u32,
    ) -> Result<(PersistentGuest, String), LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineProvision,
                resource: None,
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let marker = self.registered_marker(account_id, vmid).await?;
        let (_, token) = Self::unregister_payload(account_id, vmid);
        Ok((marker, token))
    }

    /// Removes the marker of a registered VM. The guest is left as it is
    /// (still protected, still running); Lab may select it again when it
    /// qualifies. Audited.
    ///
    /// # Errors
    ///
    /// Fails on denial, a review token that does not match, an unknown
    /// marker, or a marker Fleet created.
    pub async fn unregister(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
        vmid: u32,
        review_token: &str,
        correlation_id: Option<&str>,
    ) -> Result<(), LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineProvision,
                resource: None,
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let (_, expected) = Self::unregister_payload(account_id, vmid);
        if expected != review_token {
            return Err(invalid(
                "the review token does not match this account and VMID; review the unregistration first"
                    .to_owned(),
            ));
        }
        let marker = self.registered_marker(account_id, vmid).await?;
        self.audit_marker(
            principal,
            "persistent_guest_unregistered",
            &marker,
            correlation_id,
        )
        .await?;
        let markers = self
            .markers
            .as_ref()
            .ok_or_else(|| backend("no marker store is wired".to_owned()))?;
        markers.remove(account_id, vmid).await.map_err(backend)
    }

    /// The review token of abandoning one marker: it binds the call to the
    /// exact account and VMID that were reviewed.
    #[must_use]
    pub fn abandon_payload(account_id: &str, vmid: u32) -> (String, String) {
        let payload = serde_json::json!({ "accountId": account_id, "vmid": vmid }).to_string();
        let token = crate::operation::review_token_for("persistent.abandon", &payload);
        (payload, token)
    }

    /// Abandons a marker whose creation never completed (a failed clone, a
    /// guest the operator removed by hand): the marker goes, and the VMID
    /// and name are free again. A marker of a finished machine (state
    /// `ready`, or a completed clone) is refused: that guest is destroyed
    /// through the reviewed destroy, which removes the marker itself. The
    /// event is audited with the marker's facts.
    ///
    /// # Errors
    ///
    /// Fails on denial, a review token that does not match, an unknown
    /// marker, or a marker of a guest that exists.
    pub async fn abandon(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
        vmid: u32,
        review_token: &str,
    ) -> Result<(), LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineProvision,
                resource: None,
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let (_, expected) = Self::abandon_payload(account_id, vmid);
        if expected != review_token {
            return Err(invalid(
                "the review token does not match this account and VMID; review the abandon first"
                    .to_owned(),
            ));
        }
        let markers = self
            .markers
            .as_ref()
            .ok_or_else(|| backend("no marker store is wired".to_owned()))?;
        let marker = markers
            .get(account_id, vmid)
            .await
            .map_err(backend)?
            .ok_or_else(|| LabUseCaseError::NotFound {
                what: format!("a persistent marker for {account_id}/{vmid}"),
            })?;
        if marker.cloned || marker.state == PersistentState::Ready {
            return Err(LabUseCaseError::Conflict {
                detail: format!(
                    "{} is a created machine, not an abandoned creation; destroy it with the reviewed destroy",
                    marker.name
                ),
            });
        }
        // An abandon needs the live checks: a creation still running, or a
        // guest with the marked name anywhere, means the marker is not stale.
        let guard = self
            .abandon_guard
            .as_ref()
            .ok_or_else(|| backend("no abandon guard is wired".to_owned()))?;
        if let Some(reason) = guard.blocking_reason(&marker).await.map_err(backend)? {
            return Err(LabUseCaseError::Conflict { detail: reason });
        }
        let mut metadata = crate::audit::AuditMetadata::default();
        for (key, value) in [
            ("event", "persistent_marker_abandoned"),
            ("accountId", account_id),
            ("vmid", &vmid.to_string()),
            ("name", marker.name.as_str()),
            ("step", marker.step.as_deref().unwrap_or("none")),
        ] {
            metadata
                .insert(key, value)
                .map_err(|error| backend(error.to_string()))?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: Permission::MachineProvision.id().to_owned(),
                resource: Some(format!("{account_id}/{vmid}")),
                decision: crate::authz::Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(backend)?;
        markers.remove(account_id, vmid).await.map_err(backend)
    }

    /// Wires the SSH key store, so a credential reference can be checked.
    #[must_use]
    pub fn with_keys(mut self, keys: Arc<dyn MachineKeyPort>) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Wires the product-key store.
    #[must_use]
    pub fn with_product_keys(mut self, product_keys: Arc<dyn ProductKeyPort>) -> Self {
        self.product_keys = Some(product_keys);
        self
    }

    /// Whether product keys can be stored.
    #[must_use]
    pub fn has_product_keys(&self) -> bool {
        self.product_keys.is_some()
    }

    /// Validates a create request and answers the payload and review token.
    ///
    /// # Errors
    ///
    /// Fails on denial, a broken rule, an image version that is not
    /// promoted, or a credential or product-key reference that does not
    /// exist.
    pub async fn prepare(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        spec: &CreateMachineSpec,
    ) -> Result<Prepared, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineProvision,
                resource: None,
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        if spec.requested_by.is_some() {
            return Err(invalid(
                "requestedBy is set by the action broker; a direct create cannot carry it"
                    .to_owned(),
            ));
        }
        self.check_spec(spec).await
    }

    /// The checks of a create that need no permission of the caller: every
    /// rule, the promoted image, and the references. The request path runs
    /// them at request time with `action.request` as the permission; the
    /// executor re-verifies at run time.
    ///
    /// # Errors
    ///
    /// Fails on a broken rule, an image version that is not promoted, or a
    /// credential or product-key reference that does not exist.
    pub async fn check_spec(&self, spec: &CreateMachineSpec) -> Result<Prepared, LabUseCaseError> {
        spec.validate()
            .map_err(|detail| LabUseCaseError::Invalid { detail })?;
        if spec.install.is_none() {
            let version = self
                .images
                .promoted_version(&spec.image_version_id)
                .await
                .map_err(backend)?;
            if version.is_none_or(|version| version.promoted_build_id.is_none()) {
                return Err(invalid(format!(
                    "the image version {} does not exist or is not promoted with a pinned build",
                    spec.image_version_id
                )));
            }
        }
        if let CredentialChoice::Reference { credential } = &spec.credential {
            let keys = self
                .keys
                .as_ref()
                .ok_or_else(|| backend("no SSH key store is wired".to_owned()))?;
            // The machine does not exist yet, so only a key not bound to a
            // machine can be named here (an empty machine id matches none).
            if !keys.is_machine_key(credential).await.map_err(backend)? {
                return Err(invalid(
                    "a repository (git/) credential cannot be a persistent machine's SSH key; store a machine key"
                        .to_owned(),
                ));
            }
            if !keys.exists(credential, "").await.map_err(backend)? {
                return Err(invalid(
                    "the SSH credential reference names no usable key".to_owned(),
                ));
            }
        }
        if let Some(WindowsOptions {
            activation: Activation::ProductKey { secret },
            ..
        }) = &spec.windows
        {
            let store = self
                .product_keys
                .as_ref()
                .ok_or_else(|| backend("no product-key store is wired".to_owned()))?;
            if !store.exists(secret).await.map_err(backend)? {
                return Err(invalid(
                    "the product key reference names no stored key".to_owned(),
                ));
            }
        }
        let payload_json = spec.to_payload().map_err(backend)?;
        let review_token = crate::operation::review_token_for("machine.create", &payload_json);
        Ok(Prepared {
            payload_json,
            review_token,
        })
    }

    /// Stores a Windows product key and answers its reference. The audit
    /// event records that a key was stored, never the key.
    ///
    /// # Errors
    ///
    /// Fails on denial, a value that is not a product key, or no store.
    pub async fn store_product_key(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        product_key: &str,
    ) -> Result<String, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::SecretWrite,
                resource: None,
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        validate_product_key(product_key).map_err(|detail| LabUseCaseError::Invalid { detail })?;
        let store = self
            .product_keys
            .as_ref()
            .ok_or_else(|| backend("no product-key store is wired".to_owned()))?;
        let mut metadata = crate::audit::AuditMetadata::default();
        metadata
            .insert("event", "machine_product_key_stored")
            .map_err(|error| backend(error.to_string()))?;
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: Permission::SecretWrite.id().to_owned(),
                resource: None,
                decision: crate::authz::Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(backend)?;
        store
            .create(product_key)
            .await
            .map_err(|detail| LabUseCaseError::Invalid { detail })
    }

    /// Records that a creation was requested, with facts and no secrets.
    ///
    /// # Errors
    ///
    /// Fails when the audit record cannot be written.
    pub async fn record_requested(
        &self,
        principal: &ActingPrincipal,
        operation_id: &str,
        spec: &CreateMachineSpec,
    ) -> Result<(), LabUseCaseError> {
        let intent = requested_intent(&principal.id, operation_id, spec)
            .map_err(|error| backend(error.to_string()))?;
        self.audit.record_intent(&intent).await.map_err(backend)
    }
}

/// The `machine_provision_requested` audit event of a creation: facts and
/// no secrets. A direct create records it when it queues the operation; a
/// brokered one records it when the executor starts, carrying the request id
/// that links it to the request's own events.
///
/// # Errors
///
/// Fails when a value is not valid audit metadata.
pub fn requested_intent(
    actor: &str,
    operation_id: &str,
    spec: &CreateMachineSpec,
) -> Result<crate::audit::AuditIntent, crate::audit::MetadataError> {
    let source = spec.source_id();
    let mut metadata = crate::audit::AuditMetadata::default();
    let credential = match &spec.credential {
        CredentialChoice::Generate => "generate",
        CredentialChoice::Reference { .. } => "reference",
        CredentialChoice::PublicKey { .. } => "publicKey",
    };
    let activation = match spec.windows.as_ref().map(|options| &options.activation) {
        Some(Activation::ProductKey { .. }) => "productKey",
        Some(Activation::Kms { .. }) => "kms",
        _ => "none",
    };
    let mut pairs = vec![
        ("event", "machine_provision_requested"),
        ("accountId", spec.account_id.as_str()),
        ("source", source.as_str()),
        ("name", spec.name.as_str()),
        ("guestOs", spec.guest_os.id()),
        ("credential", credential),
        ("activation", activation),
    ];
    if let Some(by) = &spec.requested_by {
        pairs.push(("requestId", by.request_id.as_str()));
        pairs.push(("requester", by.principal.as_str()));
        pairs.push(("approver", by.approved_by.as_deref().unwrap_or("unknown")));
    }
    for (key, value) in pairs {
        metadata.insert(key, value)?;
    }
    Ok(crate::audit::AuditIntent {
        actor: actor.to_owned(),
        action: Permission::MachineProvision.id().to_owned(),
        resource: Some(operation_id.to_owned()),
        decision: crate::authz::Decision::allow(),
        correlation_id: None,
        operation_id: Some(operation_id.to_owned()),
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> CreateMachineSpec {
        serde_json::from_value(serde_json::json!({
            "accountId": "acct-1",
            "imageVersionId": "ver-1",
            "name": "build-box",
        }))
        .unwrap()
    }

    #[test]
    fn a_minimal_spec_takes_the_safe_defaults() {
        let spec = spec();
        spec.validate().unwrap();
        assert!(spec.onboot && spec.protection);
        assert_eq!(spec.credential, CredentialChoice::Generate);
        assert_eq!(spec.host_key, HostKeyTrust::Tofu);
        assert_eq!(spec.bootstrap.auth, EndpointAuth::Agent);
        assert_eq!(spec.bootstrap_user(), "root");
        assert_eq!(spec.timeout_seconds, DEFAULT_TIMEOUT_SECONDS);
    }

    #[test]
    fn unknown_fields_are_refused() {
        let error = serde_json::from_value::<CreateMachineSpec>(serde_json::json!({
            "accountId": "a", "imageVersionId": "v", "name": "x", "password": "hunter2"
        }))
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn names_follow_dns_rules_and_never_use_the_lab_prefix() {
        for bad in [
            "",
            "-a",
            "a-",
            "a_b",
            "a b",
            &"x".repeat(64),
            "fm-lab-123",
            "FM-LAB-x",
        ] {
            assert!(validate_name(bad, GuestOs::Linux).is_err(), "{bad:?}");
        }
        validate_name("build-box-01", GuestOs::Linux).unwrap();
    }

    #[test]
    fn a_windows_name_is_at_most_fifteen_characters_and_not_all_digits() {
        validate_name("win-gh-runner", GuestOs::Windows).unwrap();
        validate_name(&"a".repeat(15), GuestOs::Windows).unwrap();
        assert!(validate_name(&"a".repeat(16), GuestOs::Windows).is_err());
        assert!(validate_name("123456", GuestOs::Windows).is_err());
        // The same name is fine on Linux.
        validate_name(&"a".repeat(16), GuestOs::Linux).unwrap();
    }

    #[test]
    fn fixture_and_lab_tags_are_refused_and_template_tags_are_never_inherited() {
        for bad in [
            "fleet-pve-test",
            "fleet-lab",
            "fm-lab-x",
            "UPPER",
            "a;b",
            "",
        ] {
            assert!(validate_tag(bad).is_err(), "{bad:?}");
        }
        validate_tag("prod").unwrap();
        // The write replaces the whole list, so nothing is inherited, and the
        // label is always present, once.
        assert_eq!(
            persistent_tags(&["web".to_owned(), PERSISTENT_TAG.to_owned()]),
            vec![PERSISTENT_TAG.to_owned(), "web".to_owned()]
        );
    }

    #[test]
    fn hardware_is_bounded() {
        let mut spec = spec();
        spec.cores = Some(0);
        assert!(spec.validate().is_err());
        spec.cores = Some(4);
        spec.memory_mib = Some(64);
        assert!(spec.validate().is_err());
        spec.memory_mib = Some(4096);
        spec.vmid = Some(99);
        assert!(spec.validate().is_err());
        spec.vmid = Some(7150);
        spec.bridge = Some("vmbr0".to_owned());
        spec.audio = Some("ich9-intel-hda".to_owned());
        spec.validate().unwrap();
        spec.audio = Some("sb16".to_owned());
        assert!(spec.validate().is_err());
    }

    #[test]
    fn windows_options_need_a_windows_guest_and_a_sane_activation() {
        let mut spec = spec();
        spec.windows = Some(WindowsOptions::default());
        assert!(spec.validate().is_err());
        spec.guest_os = GuestOs::Windows;
        spec.validate().unwrap();
        spec.windows = Some(WindowsOptions {
            admin_password: AdminPasswordPolicy::Store,
            activation: Activation::Kms {
                host: "kms.example.test:1688".to_owned(),
            },
        });
        spec.validate().unwrap();
        spec.windows = Some(WindowsOptions {
            admin_password: AdminPasswordPolicy::None,
            activation: Activation::Kms {
                host: "kms host;rm".to_owned(),
            },
        });
        assert!(spec.validate().is_err());
    }

    #[test]
    fn a_public_key_is_one_openssh_line() {
        validate_public_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMq comment").unwrap();
        for bad in [
            "",
            "ssh-ed25519",
            "ssh-dss AAAA",
            "command=\"rm -rf /\" ssh-ed25519 AAAA",
            "ssh-ed25519 AAAA\nssh-ed25519 BBBB",
            "ssh-ed25519 no!t",
        ] {
            assert!(validate_public_key(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_payload_is_stable_and_carries_no_secret_field() {
        let payload = spec().to_payload().unwrap();
        assert_eq!(payload, spec().to_payload().unwrap());
        let round: CreateMachineSpec = serde_json::from_str(&payload).unwrap();
        assert_eq!(round, spec());
        assert!(!payload.contains("privateKey"));
    }

    #[test]
    fn the_config_allow_list_refuses_every_other_key() {
        let ok = GuestConfigChange::from_params(&serde_json::json!({
            "tags": ["a"], "description": "d", "onboot": true, "protection": false,
            "cores": 2, "memoryMib": 2048
        }))
        .unwrap();
        assert_eq!(ok.protection, Some(false));
        for bad in [
            serde_json::json!({}),
            serde_json::json!({"name": "x"}),
            serde_json::json!({"net0": "virtio,bridge=vmbr0"}),
            serde_json::json!({"delete": "protection"}),
            serde_json::json!({"tags": ["fleet-pve-test"]}),
            serde_json::json!({"cores": 0}),
            serde_json::json!({"hookscript": "local:snippets/x.sh"}),
        ] {
            assert!(GuestConfigChange::from_params(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_public_key_cannot_be_combined_with_another_login_user() {
        let mut spec = spec();
        spec.credential = CredentialChoice::PublicKey {
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMq c".to_owned(),
        };
        spec.validate().unwrap();
        spec.login_user = Some("ops".to_owned());
        assert!(spec.validate().unwrap_err().contains("loginUser"));
        // A Fleet-held key may name another login user.
        spec.credential = CredentialChoice::Generate;
        spec.validate().unwrap();
    }

    #[test]
    fn a_marker_guards_only_a_completed_clone_or_a_guest_with_its_name() {
        let mut marker = PersistentGuest {
            account_id: "a".to_owned(),
            vmid: 7100,
            name: "box".to_owned(),
            node: "pve".to_owned(),
            image_version_id: "v".to_owned(),
            machine_id: None,
            cloned: false,
            state: PersistentState::Creating,
            step: None,
            operation_id: None,
            created_at: 0,
            updated_at: 0,
        };
        // A failed clone: nothing there, or another guest there.
        assert!(!marker.guards(None));
        assert!(!marker.guards(Some("fm-lab-x")));
        assert!(marker.guards(Some("box")));
        // A completed clone guards whatever the guest is called now.
        marker.cloned = true;
        assert!(marker.guards(Some("renamed")));
        assert!(marker.guards(None));
    }

    #[test]
    fn a_product_key_has_five_groups_and_is_never_echoed() {
        validate_product_key("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE").unwrap();
        let error = validate_product_key("not-a-key-HUNTER2").unwrap_err();
        assert!(!error.contains("HUNTER2"));
    }

    #[test]
    fn a_registered_marker_guards_only_while_the_name_matches() {
        let registered = PersistentGuest {
            account_id: "a".to_owned(),
            vmid: 7,
            name: "reg".to_owned(),
            node: "pve".to_owned(),
            image_version_id: REGISTERED_SOURCE.to_owned(),
            machine_id: None,
            cloned: true,
            state: PersistentState::Ready,
            step: None,
            operation_id: None,
            created_at: 0,
            updated_at: 0,
        };
        assert!(registered.guards(Some("reg")));
        assert!(!registered.guards(Some("renamed")));
        assert!(!registered.guards(None));
    }

    fn install_spec() -> CreateMachineSpec {
        serde_json::from_value(serde_json::json!({
            "accountId": "acct-1",
            "name": "ci-linux",
            "node": "pve",
            "storage": "local-lvm",
            "diskGib": 32,
            "install": { "iso": "local:iso/ubuntu.iso", "answerIso": "local:iso/seed.iso" },
        }))
        .unwrap()
    }

    #[test]
    fn an_install_spec_needs_its_placement_and_excludes_an_image() {
        let spec = install_spec();
        spec.validate().unwrap();
        assert_eq!(spec.source_id(), "install:local:iso/ubuntu.iso");

        let mut both = install_spec();
        both.image_version_id = "ver-1".to_owned();
        assert!(both.validate().unwrap_err().contains("not both"));

        for strip in ["node", "storage", "diskGib"] {
            let mut value = serde_json::to_value(install_spec()).unwrap();
            value.as_object_mut().unwrap().remove(strip);
            let spec: CreateMachineSpec = serde_json::from_value(value).unwrap();
            assert!(
                spec.validate().unwrap_err().contains("needs node"),
                "{strip}"
            );
        }

        let mut windows = install_spec();
        windows.guest_os = GuestOs::Windows;
        assert!(windows.validate().unwrap_err().contains("needs answer"));

        let mut same = install_spec();
        same.install.as_mut().unwrap().answer_iso = Some("local:iso/ubuntu.iso".to_owned());
        assert!(same.validate().is_err());
    }

    fn generated(kind: &serde_json::Value) -> CreateMachineSpec {
        serde_json::from_value(serde_json::json!({
            "accountId": "acct-1",
            "name": "ci-linux",
            "node": "pve",
            "storage": "local-lvm",
            "diskGib": 32,
            "install": { "iso": "local:iso/ubuntu.iso", "answer": kind },
            "bootstrap": { "user": "fleetadmin" },
        }))
        .unwrap()
    }

    fn windows_generated() -> CreateMachineSpec {
        serde_json::from_value(serde_json::json!({
            "accountId": "acct-1",
            "name": "win-ci",
            "node": "pve",
            "storage": "local-lvm",
            "diskGib": 80,
            "guestOs": "windows",
            "install": {
                "iso": "local:iso/win11.iso",
                "answer": { "type": "autounattend" },
                "driversIso": "local:iso/virtio-win.iso",
            },
            "windows": { "adminPassword": "discard" },
        }))
        .unwrap()
    }

    #[test]
    fn a_generated_nocloud_answer_needs_a_regular_user_and_fleets_own_key() {
        let spec = generated(&serde_json::json!({ "type": "nocloud" }));
        spec.validate().unwrap();
        // The payload names the kind only: no content, key or password.
        let payload = spec.to_payload().unwrap();
        assert!(payload.contains(r#""answer":{"type":"nocloud"}"#));
        assert!(payload.contains(r#""answerIso":null"#));

        let mut root = generated(&serde_json::json!({ "type": "nocloud" }));
        root.bootstrap.user = None;
        assert!(root.validate().unwrap_err().contains("not root"));

        let mut both = generated(&serde_json::json!({ "type": "nocloud" }));
        both.install.as_mut().unwrap().answer_iso = Some("local:iso/seed.iso".to_owned());
        assert!(both.validate().unwrap_err().contains("not both"));

        let mut held = generated(&serde_json::json!({ "type": "nocloud" }));
        held.credential = CredentialChoice::PublicKey {
            public_key: "ssh-ed25519 AAAA x".to_owned(),
        };
        assert!(held.validate().unwrap_err().contains("operator-held"));

        let mut name = generated(&serde_json::json!({ "type": "nocloud" }));
        name.name = "ci_linux".to_owned();
        assert!(name.validate().is_err());

        let mut drivers = generated(&serde_json::json!({ "type": "nocloud" }));
        drivers.install.as_mut().unwrap().drivers_iso = Some("local:iso/v.iso".to_owned());
        assert!(drivers.validate().is_err());

        let mut wrong = generated(&serde_json::json!({ "type": "autounattend" }));
        assert!(wrong.validate().unwrap_err().contains("Windows guest"));
        wrong.guest_os = GuestOs::Windows;
        assert!(wrong.validate().is_err());
    }

    #[test]
    fn a_windows_install_needs_drivers_a_big_disk_and_a_rotated_password() {
        let spec = windows_generated();
        spec.validate().unwrap();
        let install = spec.install.as_ref().unwrap();
        assert!(
            install.uses_efi() && install.uses_tpm(),
            "Windows 11 defaults"
        );

        let mut none = windows_generated();
        none.install.as_mut().unwrap().drivers_iso = None;
        assert!(none.validate().unwrap_err().contains("driversIso"));

        let mut small = windows_generated();
        small.disk_gib = Some(40);
        assert!(small.validate().unwrap_err().contains("64 GiB"));

        let mut kept = windows_generated();
        kept.windows = None;
        assert!(kept.validate().unwrap_err().contains("adminPassword"));

        let mut edition = windows_generated();
        edition.install.as_mut().unwrap().answer = Some(GeneratedAnswer::Autounattend {
            edition: Some("Pro</Value>".to_owned()),
        });
        assert!(edition.validate().is_err());

        let mut same = windows_generated();
        same.install.as_mut().unwrap().drivers_iso = Some("local:iso/win11.iso".to_owned());
        assert!(same.validate().is_err());

        // Linux without generated media keeps the explicit choice.
        assert!(!install_spec().install.unwrap().uses_efi());
    }

    #[test]
    fn iso_volume_ids_are_storage_iso_file() {
        for good in ["local:iso/a.iso", "nfs-1:iso/Ubuntu-24.04.iso"] {
            validate_iso_volume(good, "iso").unwrap();
        }
        for bad in [
            "a.iso",
            "local:vztmpl/a.iso",
            "local:iso/a.img",
            "local:iso/../a.iso",
            "local:iso/a b.iso",
            "local:iso/.iso",
        ] {
            assert!(validate_iso_volume(bad, "iso").is_err(), "{bad}");
        }
    }
}
