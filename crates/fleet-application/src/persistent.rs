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

/// The Fleet name prefix Lab owns; a persistent guest never uses it.
pub const LAB_NAME_PREFIX: &str = "fm-lab-";
/// The tag every persistent guest carries, so an operator can see in
/// Proxmox which guests Fleet keeps. It is a label, never the marker: the
/// marker is the `persistent_guests` record.
pub const PERSISTENT_TAG: &str = "fleet-persistent";
/// The longest computer name Windows accepts (NetBIOS).
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

/// Everything a `machine.create` needs. The wire shape of the review and
/// create calls and of the operation payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateMachineSpec {
    /// The Proxmox account that holds the template and receives the guest.
    pub account_id: String,
    /// The promoted image version to clone.
    pub image_version_id: String,
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
    /// Checks every rule that needs no I/O.
    ///
    /// # Errors
    ///
    /// Answers the first rule the spec breaks, naming the field.
    pub fn validate(&self) -> Result<(), String> {
        identifier(&self.account_id, "account id", 128)?;
        identifier(&self.image_version_id, "image version id", 128)?;
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
            CredentialChoice::PublicKey { public_key } => validate_public_key(public_key)?,
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
        Ok(())
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
            audit,
        }
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
        spec.validate()
            .map_err(|detail| LabUseCaseError::Invalid { detail })?;
        let version = self
            .images
            .promoted_version(&spec.image_version_id)
            .await
            .map_err(backend)?;
        if version.is_none() {
            return Err(invalid(format!(
                "the image version {} does not exist or is not promoted",
                spec.image_version_id
            )));
        }
        if let CredentialChoice::Reference { credential } = &spec.credential {
            let keys = self
                .keys
                .as_ref()
                .ok_or_else(|| backend("no SSH key store is wired".to_owned()))?;
            if !keys.exists(credential).await.map_err(backend)? {
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
        for (key, value) in [
            ("event", "machine_provision_requested"),
            ("accountId", spec.account_id.as_str()),
            ("imageVersionId", spec.image_version_id.as_str()),
            ("name", spec.name.as_str()),
            ("guestOs", spec.guest_os.id()),
            ("credential", credential),
            ("activation", activation),
        ] {
            metadata
                .insert(key, value)
                .map_err(|error| backend(error.to_string()))?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: Permission::MachineProvision.id().to_owned(),
                resource: Some(operation_id.to_owned()),
                decision: crate::authz::Decision::allow(),
                correlation_id: None,
                operation_id: Some(operation_id.to_owned()),
                metadata,
            })
            .await
            .map_err(backend)
    }
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
    fn a_product_key_has_five_groups_and_is_never_echoed() {
        validate_product_key("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE").unwrap();
        let error = validate_product_key("not-a-key-HUNTER2").unwrap_err();
        assert!(!error.contains("HUNTER2"));
    }
}
