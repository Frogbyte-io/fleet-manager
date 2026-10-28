//! Permanent, Fleet-managed VMs (#489): the `machine.create` saga, the
//! `proxmox.guest.config` executor, and the product-key store.
//!
//! `machine.create` clones the promoted image's template, applies the
//! reviewed hardware and metadata in one allow-listed write, starts the
//! guest, waits for its agent address and its SSH host key, registers the
//! machine and links the guest, and then hands the machine its own SSH key
//! and, on Windows, its computer name, administrator password and
//! activation. The steps run in a fixed order, each is idempotent, and the
//! persistent marker written before the clone lets a re-run adopt the guest
//! instead of cloning twice. Nothing is ever deleted automatically: a
//! failure leaves the guest and names the step that failed.
//!
//! The order of the credential steps is the safety property: the new key is
//! installed while the image's bootstrap credential still works, a login
//! with the new key is verified, the endpoint is switched to it, and only
//! then is the bootstrap key removed (over the new key, and verified again).
//! A failure before the switch leaves the bootstrap key working.
//!
//! No secret is in a payload, a result, an audit event or a log line: the
//! spec holds references and public keys, the private key goes from
//! `ssh-keygen` straight into the secret store, the product key travels on
//! the SSH session's stdin only, and every failure detail is scrubbed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditMetadata};
use fleet_application::authz::{ActingPrincipal, Decision, Permission};
use fleet_application::lab::ImageArtifactPort;
use fleet_application::machine::{
    GuestLink, GuestLinkPort, MachinePort, Machines, NewEndpoint, RegisterMachine,
};
use fleet_application::machine_access::{
    EndpointAuth, EndpointAuthPort, MachineAccess, MachineKeyPort,
};
use fleet_application::operation::{AuditPort, Operation, Operations, PoolMemberLookup};
use fleet_application::persistent::{
    ADMIN_PASSWORD_PREFIX, Activation, AdminPasswordPolicy, CreateMachineSpec, CredentialChoice,
    GuestConfigChange, HostKeyTrust, PERSISTENT_TAG, PRODUCT_KEY_PREFIX, PersistentGuest,
    PersistentGuestPort, PersistentState, ProductKeyPort, persistent_tags, validate_product_key,
};
use fleet_application::proxmox::{ProxmoxAccountPort, ProxmoxCredentialStore};
use fleet_application::worker::OperationExecutor;
use fleet_core::{CapabilityFact, CapabilityStatus, EndpointKind, GuestOs, Timestamp};
use fleet_provider_proxmox::{
    LifecycleAction, ProxmoxClient, ProxmoxSource as _, PveQemuWrite, TaskStatus, Upid, with_bridge,
};
use fleet_provider_ssh::persistent as guest;
use fleet_provider_ssh::{
    ExecutionLimiter, PrivateKey, ScriptMetadata, SshAuth, SshConnectionSpec, SshProvider,
};
use fleet_secrets::{SecretError, SecretStore, SecretValue};

use crate::machine_access::SshAuthResolver;

/// The `machine.create` kind.
pub const CREATE_KIND: &str = "machine.create";
/// The `proxmox.guest.config` kind.
pub const CONFIG_KIND: &str = "proxmox.guest.config";
/// How long a fresh clone may hold its config lock (a full clone copies
/// every disk).
const CLONE_SETTLE: Duration = Duration::from_secs(3_600);
/// The deadline of one short guest session.
const SESSION: Duration = Duration::from_secs(120);
/// The deadline of the activation session: `/ato` talks to Microsoft or KMS.
const ACTIVATION_SESSION: Duration = Duration::from_secs(300);

fn lan() -> ActingPrincipal {
    ActingPrincipal {
        id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
    }
}

/// A saga failure: a stable reason, the step, and a scrubbed detail.
#[derive(Debug)]
struct Failure {
    reason: &'static str,
    step: &'static str,
    detail: String,
}

fn failure(step: &'static str, reason: &'static str, detail: impl Into<String>) -> Failure {
    Failure {
        reason,
        step,
        detail: fleet_core::scrub_failure_detail(&detail.into()),
    }
}

type Step<T> = Result<T, Failure>;

/// Windows product keys over the encrypted secret store, as records named
/// `machines/product-key/<id>`. The value is readable only through
/// [`Self::resolve`], which the create executor calls; no API returns it.
#[derive(Debug)]
pub struct SecretBackedProductKeys {
    secrets: Arc<SecretStore>,
}

impl SecretBackedProductKeys {
    /// Composes the store over the controller's secret store.
    #[must_use]
    pub fn new(secrets: Arc<SecretStore>) -> Self {
        Self { secrets }
    }

    async fn live(&self, reference: &str) -> Result<bool, String> {
        Ok(self
            .secrets
            .list()
            .await
            .map_err(|error| format!("the secret store is unreadable: {error}"))?
            .iter()
            .any(|record| record.id == reference && record.name.starts_with(PRODUCT_KEY_PREFIX)))
    }

    /// The key text, when the reference names a live product key.
    ///
    /// # Errors
    ///
    /// Fails with a secret-free detail when the store errors.
    pub async fn resolve(&self, reference: &str) -> Result<Option<String>, String> {
        if !self.live(reference).await? {
            return Ok(None);
        }
        match self.secrets.resolve(reference).await {
            Ok(value) => String::from_utf8(value.expose().to_vec())
                .map(Some)
                .map_err(|_| "the stored product key is unreadable".to_owned()),
            Err(SecretError::NotFound { .. }) => Ok(None),
            Err(error) => Err(format!("the stored product key is unreadable: {error}")),
        }
    }
}

#[async_trait]
impl ProductKeyPort for SecretBackedProductKeys {
    async fn create(&self, product_key: &str) -> Result<String, String> {
        validate_product_key(product_key)?;
        let name = format!("{PRODUCT_KEY_PREFIX}{}", uuid::Uuid::now_v7());
        self.secrets
            .create(
                &name,
                SecretValue::new(product_key.trim().as_bytes().to_vec()),
            )
            .await
            .map(|record| record.id)
            .map_err(|error| format!("the product key could not be stored: {error}"))
    }

    async fn exists(&self, reference: &str) -> Result<bool, String> {
        self.live(reference).await
    }
}

/// The live checks of abandoning a marker: its creation must not still be
/// running, and no guest with the marked name may exist at any VMID.
#[derive(Debug)]
pub struct ProxmoxAbandonGuard {
    operations: Arc<dyn fleet_application::operation::OperationPort>,
    pve: Pve,
}

impl ProxmoxAbandonGuard {
    /// Composes the guard.
    #[must_use]
    pub fn new(
        operations: Arc<dyn fleet_application::operation::OperationPort>,
        accounts: Arc<dyn ProxmoxAccountPort>,
        credentials: Arc<dyn ProxmoxCredentialStore>,
        client: ProxmoxClient,
    ) -> Self {
        Self {
            operations,
            pve: Pve {
                accounts,
                credentials,
                client,
            },
        }
    }
}

#[async_trait]
impl fleet_application::persistent::AbandonGuard for ProxmoxAbandonGuard {
    async fn blocking_reason(&self, marker: &PersistentGuest) -> Result<Option<String>, String> {
        if let Some(operation_id) = &marker.operation_id
            && let Ok(operation) = self.operations.get(operation_id).await
            && matches!(
                operation.state.as_str(),
                "pending" | "running" | "cancelling"
            )
        {
            return Ok(Some(format!(
                "the creation operation {operation_id} is still {}; cancel it or wait for it to finish",
                operation.state
            )));
        }
        let request = self.pve.bound(&marker.account_id).await?;
        let resources = self
            .pve
            .client
            .list_guest_resources(request)
            .await
            .map_err(|error| format!("the resource listing failed: {error}"))?;
        Ok(resources
            .iter()
            .find(|resource| {
                resource.kind == "qemu" && resource.name.as_deref() == Some(marker.name.as_str())
            })
            .map(|resource| {
                format!(
                    "a guest named {} exists as VMID {}; destroy it instead of abandoning its marker",
                    marker.name,
                    resource.vmid.unwrap_or_default()
                )
            }))
    }
}

fn node_of(resource: &fleet_provider_proxmox::PveResource) -> Result<String, String> {
    resource
        .node
        .clone()
        .ok_or_else(|| "the guest has no current node".to_owned())
}

/// The live checks of registering an existing VM as persistent: it must
/// exist as a QEMU VM that is not a template, a promoted image artifact, a
/// Lab clone or a Lab pool member.
#[derive(Debug)]
pub struct ProxmoxRegisterGuard {
    pve: Pve,
    artifacts: Arc<dyn ImageArtifactPort>,
    pool_members: Option<Arc<dyn PoolMemberLookup>>,
}

impl ProxmoxRegisterGuard {
    /// Composes the guard.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn ProxmoxAccountPort>,
        credentials: Arc<dyn ProxmoxCredentialStore>,
        client: ProxmoxClient,
        artifacts: Arc<dyn ImageArtifactPort>,
    ) -> Self {
        Self {
            pve: Pve {
                accounts,
                credentials,
                client,
            },
            artifacts,
            pool_members: None,
        }
    }

    /// Refuses guests that are Lab pool members.
    #[must_use]
    pub fn with_pool_members(mut self, lookup: Arc<dyn PoolMemberLookup>) -> Self {
        self.pool_members = Some(lookup);
        self
    }
}

#[async_trait]
impl fleet_application::persistent::RegisterGuard for ProxmoxRegisterGuard {
    async fn inspect(
        &self,
        account_id: &str,
        vmid: u32,
    ) -> Result<fleet_application::persistent::GuestCheck, String> {
        use fleet_application::persistent::{GuestCheck, LiveGuest};
        let request = self.pve.bound(account_id).await?;
        let resources = self
            .pve
            .client
            .list_guest_resources(request.clone())
            .await
            .map_err(|error| format!("the resource listing failed: {error}"))?;
        let Some(resource) = resources.iter().find(|resource| {
            resource.vmid == Some(vmid)
                && matches!(resource.kind.as_str(), "qemu" | "qemu-template" | "lxc")
        }) else {
            return Ok(GuestCheck::Refused(format!(
                "no guest with VMID {vmid} exists on this account"
            )));
        };
        let refuse = |reason: String| Ok(GuestCheck::Refused(reason));
        if resource.kind == "lxc" {
            return refuse("only QEMU VMs can be registered as persistent".to_owned());
        }
        if resource.kind == "qemu-template" {
            return refuse("a template is never a persistent machine".to_owned());
        }
        let promoted = self
            .artifacts
            .promoted_template_vmids()
            .await
            .map_err(|detail| format!("the image artifacts are unreadable: {detail}"))?;
        if promoted.contains(&vmid) {
            return refuse("a promoted image artifact is never a persistent machine".to_owned());
        }
        let name = resource.name.clone().unwrap_or_default();
        if name.is_empty() {
            return refuse("the guest has no name".to_owned());
        }
        // Fail closed: without the pool lookup a pool member cannot be told
        // from any other guest.
        let Some(pools) = &self.pool_members else {
            return Err(
                "the Lab pool membership is not wired, so a registration is refused".to_owned(),
            );
        };
        if let Some(pool) = pools
            .pool_of(account_id, vmid)
            .await
            .map_err(|_| "the Lab pool membership could not be read".to_owned())?
        {
            return refuse(format!("the guest is a member of Lab pool {pool}"));
        }
        let settings = self
            .pve
            .client
            .qemu_settings(request, &node_of(resource)?, vmid)
            .await
            .map_err(|error| format!("the guest config is unreadable: {error}"))?;
        if let Some(tag) = settings
            .tags
            .iter()
            .find(|tag| fleet_application::persistent::is_reserved_tag(tag))
        {
            return refuse(format!(
                "the guest carries the reserved tag {tag}, which fixture and Lab tooling act on; remove it first (proxmox config)"
            ));
        }
        let node = resource
            .node
            .clone()
            .ok_or_else(|| "the guest has no current node".to_owned())?;
        Ok(GuestCheck::Eligible(LiveGuest { name, node }))
    }
}

/// The ports and clients both executors share.
#[derive(Debug, Clone)]
struct Pve {
    accounts: Arc<dyn ProxmoxAccountPort>,
    credentials: Arc<dyn ProxmoxCredentialStore>,
    client: ProxmoxClient,
}

impl Pve {
    async fn bound(
        &self,
        account_id: &str,
    ) -> Result<fleet_provider_proxmox::PveHttpRequest, String> {
        let account = self
            .accounts
            .get(account_id)
            .await
            .map_err(|detail| format!("the account is unreadable: {detail}"))?;
        if account.fingerprint.is_none() {
            return Err(format!(
                "the account {} has no confirmed fingerprint; confirm the host's trust first",
                account.name
            ));
        }
        let secret = self
            .credentials
            .load(account_id)
            .await
            .map_err(|error| format!("the credential store failed: {error}"))?
            .ok_or_else(|| {
                format!(
                    "the API token for account {} is not in the secret store",
                    account.name
                )
            })?;
        Ok(crate::proxmox_exec::pve_request(&account, secret))
    }
}

async fn complete_failed(
    operations: &Operations,
    operation_id: &str,
    error: &serde_json::Value,
) -> Result<(), String> {
    operations
        .complete(operation_id, "failed", None, Some(&error.to_string()))
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn audit_intent(
    permission: Permission,
    resource: &str,
    operation_id: &str,
    facts: &[(&str, &str)],
) -> Result<AuditIntent, String> {
    let mut metadata = AuditMetadata::default();
    for (key, value) in facts {
        metadata
            .insert(key, value)
            .map_err(|error| error.to_string())?;
    }
    Ok(AuditIntent {
        actor: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        action: permission.id().to_owned(),
        resource: Some(resource.to_owned()),
        decision: Decision::allow(),
        correlation_id: None,
        operation_id: Some(operation_id.to_owned()),
        metadata,
    })
}

/// The `proxmox.guest.config` executor: an allow-listed settings write on a
/// guest that is not a Lab guest.
#[derive(Debug)]
pub struct GuestConfigExecutor {
    pve: Pve,
    artifacts: Arc<dyn ImageArtifactPort>,
    audit: Arc<dyn AuditPort>,
    pool_members: Option<Arc<dyn PoolMemberLookup>>,
}

impl GuestConfigExecutor {
    /// Composes the executor.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn ProxmoxAccountPort>,
        credentials: Arc<dyn ProxmoxCredentialStore>,
        client: ProxmoxClient,
        artifacts: Arc<dyn ImageArtifactPort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            pve: Pve {
                accounts,
                credentials,
                client,
            },
            artifacts,
            audit,
            pool_members: None,
        }
    }

    /// Refuses guests that are Lab pool members.
    #[must_use]
    pub fn with_pool_members(mut self, lookup: Arc<dyn PoolMemberLookup>) -> Self {
        self.pool_members = Some(lookup);
        self
    }

    async fn run(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Payload {
            account_id: String,
            node: String,
            vmid: u32,
            #[serde(default)]
            params: serde_json::Value,
        }
        let payload: Payload = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a valid config record: {error}"))?;
        let refuse = |reason: &'static str, detail: String| serde_json::json!({ "reason": reason, "detail": fleet_core::scrub_failure_detail(&detail) });
        let change = match GuestConfigChange::from_params(&payload.params) {
            Ok(change) => change,
            Err(detail) => {
                return complete_failed(
                    operations,
                    &operation.id,
                    &refuse("invalid_params", detail),
                )
                .await;
            }
        };
        let request = self.pve.bound(&payload.account_id).await?;
        let settings = self
            .pve
            .client
            .qemu_settings(request.clone(), &payload.node, payload.vmid)
            .await
            .map_err(|error| format!("the guest config is unreadable: {error}"))?;
        // The allow-list's other half: which guests may be changed at all.
        let name = settings.name.clone().unwrap_or_default();
        let promoted = self
            .artifacts
            .promoted_template_vmids()
            .await
            .map_err(|detail| format!("the image artifacts are unreadable: {detail}"))?;
        let mut why = None;
        if settings.template || promoted.contains(&payload.vmid) {
            why = Some("a template or promoted image artifact is never reconfigured".to_owned());
        } else if name
            .to_ascii_lowercase()
            .starts_with(fleet_application::persistent::LAB_NAME_PREFIX)
        {
            why = Some("a Lab guest is configured by Lab, not by this action".to_owned());
        } else if let Some(pools) = &self.pool_members {
            match pools.pool_of(&payload.account_id, payload.vmid).await {
                Ok(Some(pool)) => why = Some(format!("the guest is a member of Lab pool {pool}")),
                Ok(None) => {}
                Err(_) => {
                    return complete_failed(
                        operations,
                        &operation.id,
                        &refuse(
                            "pool_membership_unreadable",
                            "the Lab pool membership could not be read".to_owned(),
                        ),
                    )
                    .await;
                }
            }
        }
        if let Some(detail) = why {
            return complete_failed(operations, &operation.id, &refuse("refused", detail)).await;
        }
        let Some(digest) = settings.digest.clone() else {
            return complete_failed(
                operations,
                &operation.id,
                &refuse(
                    "no_digest",
                    "the guest config carries no digest, so the write cannot be conditional"
                        .to_owned(),
                ),
            )
            .await;
        };
        if settings.memory_has_options && change.memory_mib.is_some() {
            return complete_failed(
                operations,
                &operation.id,
                &refuse(
                    "unsupported",
                    "the guest's memory has ballooning options a plain write would drop".to_owned(),
                ),
            )
            .await;
        }
        let write = PveQemuWrite {
            tags: change.tags.clone(),
            description: change.description.clone(),
            onboot: change.onboot,
            protection: change.protection,
            cores: change.cores,
            memory_mib: change.memory_mib,
            ..PveQemuWrite::default()
        };
        let keys = changed_keys(&change);
        self.audit
            .record_intent(&audit_intent(
                Permission::ProxmoxGuestConfig,
                &format!("{}/{}", payload.account_id, payload.vmid),
                &operation.id,
                &[
                    ("event", "proxmox_guest_config_applied"),
                    ("accountId", payload.account_id.as_str()),
                    ("vmid", &payload.vmid.to_string()),
                    ("keys", &keys.join(",")),
                ],
            )?)
            .await?;
        self.pve
            .client
            .qemu_write_settings(
                request.clone(),
                &payload.node,
                payload.vmid,
                &write,
                &digest,
            )
            .await
            .map_err(|error| format!("PVE refused the config write: {error}"))?;
        // Read it back: the result reports what PVE now says, not what was
        // asked.
        let after = self
            .pve
            .client
            .qemu_settings(request, &payload.node, payload.vmid)
            .await
            .map_err(|error| format!("the config readback failed: {error}"))?;
        let mismatch = (change
            .protection
            .is_some_and(|value| value != after.protection))
            || (change.onboot.is_some_and(|value| value != after.onboot))
            || (change.cores.is_some_and(|value| after.cores != Some(value)))
            || (change
                .memory_mib
                .is_some_and(|value| after.memory_mib != Some(value)))
            || (change.tags.as_ref().is_some_and(|tags| {
                let mut want = tags.clone();
                want.sort();
                let mut have = after.tags.clone();
                have.sort();
                want != have
            }));
        if mismatch {
            return complete_failed(
                operations,
                &operation.id,
                &refuse(
                    "readback_mismatch",
                    "PVE accepted the write but the config does not show it".to_owned(),
                ),
            )
            .await;
        }
        operations
            .complete(
                &operation.id,
                "succeeded",
                Some(
                    &serde_json::json!({
                        "vmid": payload.vmid,
                        "applied": keys,
                        "protection": after.protection,
                        "onboot": after.onboot,
                        "tags": after.tags,
                    })
                    .to_string(),
                ),
                None,
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

fn changed_keys(change: &GuestConfigChange) -> Vec<&'static str> {
    let mut keys = Vec::new();
    for (set, key) in [
        (change.tags.is_some(), "tags"),
        (change.description.is_some(), "description"),
        (change.onboot.is_some(), "onboot"),
        (change.protection.is_some(), "protection"),
        (change.cores.is_some(), "cores"),
        (change.memory_mib.is_some(), "memoryMib"),
    ] {
        if set {
            keys.push(key);
        }
    }
    keys
}

#[async_trait]
impl OperationExecutor for GuestConfigExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        self.run(operations, operation).await
    }
}

/// The `machine.create` executor.
#[derive(Debug)]
pub struct MachineCreateExecutor {
    pve: Pve,
    links: Option<Arc<dyn fleet_application::proxmox::tasks::ProxmoxTaskLinkPort>>,
    artifacts: Arc<dyn ImageArtifactPort>,
    images: Arc<dyn fleet_application::lab::ImagePinValidator>,
    persistent: Arc<dyn PersistentGuestPort>,
    machines: Arc<dyn MachinePort>,
    guest_links: Arc<dyn GuestLinkPort>,
    endpoint_auths: Arc<dyn EndpointAuthPort>,
    access: Arc<MachineAccess>,
    keys: Arc<dyn MachineKeyPort>,
    resolver: Arc<SshAuthResolver>,
    secrets: Arc<SecretStore>,
    product_keys: Arc<SecretBackedProductKeys>,
    audit: Arc<dyn AuditPort>,
    provider: SshProvider,
    limiter: Arc<ExecutionLimiter>,
    poll: Duration,
    address_override: Option<String>,
}

/// What the executor composes from.
#[derive(Debug)]
pub struct MachineCreateParts {
    /// Proxmox accounts.
    pub accounts: Arc<dyn ProxmoxAccountPort>,
    /// Proxmox API tokens.
    pub credentials: Arc<dyn ProxmoxCredentialStore>,
    /// The provider client.
    pub client: ProxmoxClient,
    /// Image artifacts (the template of a promoted version).
    pub artifacts: Arc<dyn ImageArtifactPort>,
    /// The promoted-version check: the executor re-verifies promotion, the
    /// API's check at review time may be stale by now.
    pub images: Arc<dyn fleet_application::lab::ImagePinValidator>,
    /// The persistent marker store.
    pub persistent: Arc<dyn PersistentGuestPort>,
    /// Machines.
    pub machines: Arc<dyn MachinePort>,
    /// Guest links.
    pub guest_links: Arc<dyn GuestLinkPort>,
    /// Endpoint default auth.
    pub endpoint_auths: Arc<dyn EndpointAuthPort>,
    /// The machine access use case (`set_default_auth`).
    pub access: Arc<MachineAccess>,
    /// The SSH key store.
    pub keys: Arc<dyn MachineKeyPort>,
    /// Stored-key resolution.
    pub resolver: Arc<SshAuthResolver>,
    /// The secret store (rotated Windows passwords).
    pub secrets: Arc<SecretStore>,
    /// Product keys.
    pub product_keys: Arc<SecretBackedProductKeys>,
    /// The audit sink.
    pub audit: Arc<dyn AuditPort>,
    /// The SSH work directory.
    pub work_dir: std::path::PathBuf,
    /// The SSH session limiter.
    pub limiter: Arc<ExecutionLimiter>,
}

impl MachineCreateExecutor {
    /// Composes the executor.
    ///
    /// # Panics
    ///
    /// Panics only if the SSH work directory cannot be prepared, which the
    /// controller's data-directory preparation already ensures.
    #[must_use]
    pub fn new(parts: MachineCreateParts) -> Self {
        Self {
            pve: Pve {
                accounts: parts.accounts,
                credentials: parts.credentials,
                client: parts.client,
            },
            links: None,
            artifacts: parts.artifacts,
            images: parts.images,
            persistent: parts.persistent,
            machines: parts.machines,
            guest_links: parts.guest_links,
            endpoint_auths: parts.endpoint_auths,
            access: parts.access,
            keys: parts.keys,
            resolver: parts.resolver,
            secrets: parts.secrets,
            product_keys: parts.product_keys,
            audit: parts.audit,
            provider: SshProvider::new(parts.work_dir).expect("the SSH work dir must prepare"),
            limiter: parts.limiter,
            poll: Duration::from_secs(2),
            address_override: None,
        }
    }

    /// Records every UPID this executor starts against its operation.
    #[must_use]
    pub fn with_task_links(
        mut self,
        links: Arc<dyn fleet_application::proxmox::tasks::ProxmoxTaskLinkPort>,
    ) -> Self {
        self.links = Some(links);
        self
    }

    /// Reaches the guest at `address` instead of the one its agent reports
    /// (the agent must still report a usable one). For tests, whose sshd
    /// listens on loopback, which a real guest address never is.
    #[doc(hidden)]
    #[must_use]
    pub fn with_address_override(mut self, address: &str) -> Self {
        self.address_override = Some(address.to_owned());
        self
    }

    /// Shortens the poll interval (tests).
    #[must_use]
    pub fn with_poll_interval(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }
}

/// One run's state.
struct Run<'a> {
    exec: &'a MachineCreateExecutor,
    operations: &'a Operations,
    operation: &'a Operation,
    spec: CreateMachineSpec,
    request: fleet_provider_proxmox::PveHttpRequest,
    deadline: Instant,
    marker: Option<PersistentGuest>,
    /// The step an earlier run of this creation reached (the marker's step
    /// when this run adopted it); later checkpoints overwrite the marker's.
    prior_step: Option<String>,
    node: String,
    vmid: u32,
    machine_id: Option<String>,
    endpoint_id: Option<String>,
    host: Option<String>,
    fingerprint: Option<String>,
    /// The credential the machine ends up using, when Fleet holds it.
    credential: Option<String>,
    bootstrap_key_removed: bool,
    /// Whether the generated answer media was deleted from ISO storage
    /// (`None` when this creation generated none).
    answer_deleted: Option<bool>,
}

const STEPS: i64 = 11;

/// The order creation steps are reached in. The marker's step never moves
/// back along it: a re-run passes through the early steps again, and must not
/// forget how far an earlier run got.
fn step_rank(step: &str) -> Option<u8> {
    Some(match step {
        "reserve" => 0,
        "create" | "clone" => 1,
        "config" => 2,
        "installing" => 3,
        "install" => 4,
        "start" => 5,
        "machine" => 6,
        "link" => 7,
        "credential" => 8,
        "ready" => 9,
        _ => return None,
    })
}

/// Whether a marker step is at or past the Fleet-side eject of the install
/// media.
fn passed_install(step: &str) -> bool {
    step_rank(step).is_some_and(|rank| rank >= 4)
}

/// The MAC address of a `net0` property string (`virtio=AA:BB:...,bridge=...`),
/// lower-case and colon-separated, the way the guest agent reports it.
fn net_mac(net0: &str) -> Option<String> {
    let first = net0.split(',').next()?;
    let (_, mac) = first.split_once('=')?;
    fleet_provider_proxmox::normalize_mac(mac)
}

impl Run<'_> {
    async fn progress(&self, index: i64, text: &str) {
        let _ = self
            .operations
            .record_progress(&self.operation.id, Some(index), Some(STEPS), Some(text))
            .await;
    }

    async fn checkpoint(&mut self, step: &'static str) -> Step<()> {
        if self
            .operations
            .cancel_requested(&self.operation.id)
            .await
            .unwrap_or(false)
        {
            return Err(failure(
                step,
                "cancelled",
                "cancelled; the guest and everything created so far are kept",
            ));
        }
        if Instant::now() >= self.deadline {
            return Err(failure(
                step,
                "deadline_expired",
                "the operation deadline expired",
            ));
        }
        self.record_step(step).await
    }

    /// Writes the marker's step, never moving it back along the creation
    /// order, with the node, machine and operation.
    async fn record_step(&mut self, step: &'static str) -> Step<()> {
        if let Some(marker) = self.marker.as_mut() {
            let behind = marker
                .step
                .as_deref()
                .and_then(step_rank)
                .zip(step_rank(step))
                .is_some_and(|(current, new)| current > new);
            if !behind {
                marker.step = Some(step.to_owned());
            }
            marker.node.clone_from(&self.node);
            marker.machine_id.clone_from(&self.machine_id);
            marker.operation_id = Some(self.operation.id.clone());
            self.exec
                .persistent
                .update(marker)
                .await
                .map_err(|detail| failure(step, "marker_failed", detail))?;
        }
        Ok(())
    }

    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    async fn sleep(&self) {
        tokio::time::sleep(self.exec.poll.min(self.remaining())).await;
    }

    async fn wait_task(&self, step: &'static str, upid: &Upid) -> Step<()> {
        if let Some(links) = &self.exec.links {
            let _ = links
                .record(&self.spec.account_id, &upid.raw, &self.operation.id)
                .await;
        }
        loop {
            match self
                .exec
                .pve
                .client
                .task_status(self.request.clone(), upid)
                .await
                .map_err(|error| failure(step, "task_status", error.to_string()))?
            {
                TaskStatus::Ok => return Ok(()),
                TaskStatus::Running => {}
                TaskStatus::Error { detail } => {
                    return Err(failure(step, "task_failed", detail));
                }
                TaskStatus::Unknown => {
                    return Err(failure(
                        step,
                        "task_unknown",
                        "the task's outcome is unknown, not assumed",
                    ));
                }
            }
            if self
                .operations
                .cancel_requested(&self.operation.id)
                .await
                .unwrap_or(false)
            {
                return Err(failure(
                    step,
                    "cancelled",
                    "cancelled while a Proxmox task runs; it keeps running and its outcome is unknown",
                ));
            }
            if Instant::now() >= self.deadline {
                return Err(failure(
                    step,
                    "deadline_expired",
                    "the deadline expired while the task still runs",
                ));
            }
            self.sleep().await;
        }
    }

    // Step 1: the template, the target, the marker.
    async fn reserve(&mut self) -> Step<(u32, String)> {
        let step = "reserve";
        let spec = &self.spec;
        let resources = self
            .exec
            .pve
            .client
            .list_guest_resources(self.request.clone())
            .await
            .map_err(|error| failure(step, "resources", error.to_string()))?;
        let (template_vmid, template_node) = if spec.install.is_some() {
            // An ISO install has no template: the node is the spec's.
            (0, spec.node.clone().unwrap_or_default())
        } else {
            // Promotion is re-checked here, and the version must carry the build
            // its promotion pinned: this kind never falls back to the newest
            // succeeded build of a version.
            let version = self
                .exec
                .images
                .promoted_version(&spec.image_version_id)
                .await
                .map_err(|detail| failure(step, "image_unreadable", detail))?
                .filter(|version| version.promoted_build_id.is_some())
                .ok_or_else(|| {
                    failure(
                        step,
                        "image_not_promoted",
                        format!(
                            "the image version {} is not promoted with a pinned build",
                            spec.image_version_id
                        ),
                    )
                })?;
            drop(version);
            let Some(template_vmid) = self
                .exec
                .artifacts
                .template_vmid(&spec.image_version_id)
                .await
                .map_err(|detail| failure(step, "artifact_unreadable", detail))?
            else {
                return Err(failure(
                    step,
                    "artifact_missing",
                    format!(
                        "the image version {} has no recorded build artifact",
                        spec.image_version_id
                    ),
                ));
            };
            let template = resources
            .iter()
            .find(|resource| resource.vmid == Some(template_vmid))
            .filter(|resource| resource.kind == "qemu-template")
            .ok_or_else(|| {
                failure(
                    step,
                    "template_missing",
                    format!(
                        "the image template qemu/{template_vmid} is not a template in the cluster"
                    ),
                )
            })?;
            let template_node = template.node.clone().ok_or_else(|| {
                failure(
                    step,
                    "template_missing",
                    "the cluster reports no node for the template",
                )
            })?;
            (template_vmid, template_node)
        };
        // A re-run adopts its own marker by name; otherwise the VMID is the
        // requested one or the next free one.
        let existing = self
            .exec
            .persistent
            .list()
            .await
            .map_err(|detail| failure(step, "marker_failed", detail))?
            .into_iter()
            .find(|guest| guest.account_id == spec.account_id && guest.name == spec.name);
        if let Some(found) = &existing {
            if found.state == PersistentState::Ready {
                return Err(failure(
                    step,
                    "conflict",
                    format!(
                        "{} is already a created machine (VMID {}); a re-run only resumes an unfinished creation",
                        spec.name, found.vmid
                    ),
                ));
            }
            if found.image_version_id != spec.source_id() {
                return Err(failure(
                    step,
                    "conflict",
                    format!(
                        "the unfinished creation of {} used source {}, not {}",
                        spec.name,
                        found.image_version_id,
                        spec.source_id()
                    ),
                ));
            }
        }
        let vmid = match (&existing, spec.vmid) {
            (Some(found), requested) => {
                if requested.is_some_and(|vmid| vmid != found.vmid) {
                    return Err(failure(
                        step,
                        "conflict",
                        format!("{} already exists as VMID {}", spec.name, found.vmid),
                    ));
                }
                found.vmid
            }
            (None, Some(vmid)) => vmid,
            (None, None) => self
                .exec
                .pve
                .client
                .next_vmid(self.request.clone())
                .await
                .map_err(|error| failure(step, "next_vmid", error.to_string()))?,
        };
        if self
            .exec
            .artifacts
            .promoted_template_vmids()
            .await
            .map_err(|detail| failure(step, "artifact_unreadable", detail))?
            .contains(&vmid)
        {
            return Err(failure(
                step,
                "conflict",
                format!("VMID {vmid} is a promoted image's recorded template"),
            ));
        }
        // Whatever sits at the target must be this guest, never another.
        if let Some(found) = resources
            .iter()
            .find(|resource| resource.vmid == Some(vmid))
            && !(existing.is_some()
                && found.kind == "qemu"
                && found.name.as_deref() == Some(spec.name.as_str()))
        {
            return Err(failure(
                step,
                "conflict",
                format!(
                    "a guest with VMID {vmid} already exists ({} named {}); it is not this machine",
                    found.kind,
                    found.name.as_deref().unwrap_or("nothing")
                ),
            ));
        }
        // The requested name must not already belong to a guest elsewhere.
        if let Some(other) = resources.iter().find(|resource| {
            resource.kind == "qemu"
                && resource.name.as_deref() == Some(spec.name.as_str())
                && resource.vmid != Some(vmid)
        }) {
            return Err(failure(
                step,
                "conflict",
                format!(
                    "a guest named {} already exists as VMID {}; pick another name",
                    spec.name,
                    other.vmid.unwrap_or_default()
                ),
            ));
        }
        let target_node = spec.node.clone().unwrap_or(template_node.clone());
        let now = fleet_core::SystemClock::now_unix_millis();
        let first = self
            .exec
            .persistent
            .get(&spec.account_id, vmid)
            .await
            .map_err(|detail| failure(step, "conflict", detail))?
            .is_none();
        let marker = self
            .exec
            .persistent
            .reserve(&PersistentGuest {
                account_id: spec.account_id.clone(),
                vmid,
                name: spec.name.clone(),
                node: target_node.clone(),
                image_version_id: spec.source_id(),
                machine_id: None,
                cloned: false,
                state: PersistentState::Creating,
                step: Some(step.to_owned()),
                operation_id: Some(self.operation.id.clone()),
                created_at: now,
                updated_at: now,
            })
            .await
            .map_err(|detail| failure(step, "conflict", detail))?;
        self.prior_step = existing.as_ref().and_then(|found| found.step.clone());
        self.machine_id.clone_from(&marker.machine_id);
        self.marker = Some(marker);
        self.vmid = vmid;
        self.node = target_node;
        self.settle_owner(first).await?;
        // Remember the template's node for the clone call.
        Ok((template_vmid, template_node))
    }

    // Step 2: the clone, unless this guest already exists.
    async fn clone_guest(&mut self, template_vmid: u32, template_node: &str) -> Step<()> {
        let step = "clone";
        let resources = self
            .exec
            .pve
            .client
            .list_guest_resources(self.request.clone())
            .await
            .map_err(|error| failure(step, "resources", error.to_string()))?;
        if let Some(found) = resources
            .iter()
            .find(|resource| resource.vmid == Some(self.vmid))
        {
            // Adopted: the reserve step proved it is this guest.
            if let Some(node) = &found.node {
                self.node.clone_from(node);
            }
            return self.mark_cloned().await;
        }
        let target = (self.node != template_node).then_some(self.node.as_str());
        let started = self
            .exec
            .pve
            .client
            .guest_clone_placed(
                self.request.clone(),
                template_node,
                template_vmid,
                self.vmid,
                &self.spec.name,
                target,
                self.spec.storage.as_deref(),
            )
            .await
            .map_err(|error| failure(step, "clone_failed", error.to_string()));
        let outcome = match started {
            Ok(upid) => self.wait_task(step, &upid).await,
            Err(failure) => Err(failure),
        };
        match outcome {
            Ok(()) => self.mark_cloned().await,
            Err(failure) => {
                // A clone that failed with nothing at the VMID must not leave
                // a marker that would shield the next guest to take it.
                self.release_marker_if_vacant().await;
                Err(failure)
            }
        }
    }

    // Step 2 of an ISO install: create the guest with the installer and the
    // answer media attached, unless this guest already exists.
    async fn create_install_guest(&mut self) -> Step<()> {
        let step = "create";
        let Some(install) = self.spec.install.clone() else {
            return Err(failure(
                step,
                "invalid",
                "this creation has no install source",
            ));
        };
        let resources = self
            .exec
            .pve
            .client
            .list_guest_resources(self.request.clone())
            .await
            .map_err(|error| failure(step, "resources", error.to_string()))?;
        if let Some(found) = resources
            .iter()
            .find(|resource| resource.vmid == Some(self.vmid))
        {
            // Adopted: the reserve step proved it is this guest.
            if let Some(node) = &found.node {
                self.node.clone_from(node);
            }
            return self.mark_cloned().await;
        }
        let answer_volume = match self.generated_answer(&install).await {
            Ok(volume) => volume,
            Err(failure) => {
                self.release_marker_if_vacant().await;
                return Err(failure);
            }
        };
        let create = fleet_provider_proxmox::PveQemuCreate {
            vmid: self.vmid,
            name: self.spec.name.clone(),
            cores: self.spec.cores.unwrap_or(2),
            memory_mib: self.spec.memory_mib.unwrap_or(4_096),
            storage: self.spec.storage.clone().unwrap_or_default(),
            disk_gib: self.spec.disk_gib.unwrap_or(32),
            bridge: self
                .spec
                .bridge
                .clone()
                .unwrap_or_else(|| "vmbr0".to_owned()),
            answer_iso: answer_volume.clone().or_else(|| install.answer_iso.clone()),
            efi: install.uses_efi(),
            tpm: install.uses_tpm(),
            drivers_iso: install.drivers_iso.clone(),
            windows: self.spec.guest_os == GuestOs::Windows,
            iso: install.iso,
        };
        let started = self
            .exec
            .pve
            .client
            .qemu_create(self.request.clone(), &self.node, &create)
            .await
            .map_err(|error| failure(step, "create_failed", error.to_string()));
        let outcome = match started {
            Ok(upid) => self.wait_task(step, &upid).await,
            Err(failure) => Err(failure),
        };
        match outcome {
            Ok(()) => self.mark_cloned().await,
            Err(failure) => {
                self.release_marker_if_vacant().await;
                if answer_volume.is_some() {
                    // The guest was never created, so nothing uses the media.
                    self.delete_answer_media().await;
                }
                Err(failure)
            }
        }
    }

    /// The owner token of the install's bootstrap key: the secret store binds
    /// a key to an owner, and the machine does not exist yet, so the guest
    /// (account and VMID) is the owner until the final key replaces it.
    fn install_owner(&self) -> String {
        format!("install-{}-{}", self.vmid, self.spec.account_id)
    }

    /// The generated answer's volume: `<storage of the installer>:iso/<file>`.
    fn answer_volume(
        &self,
        install: &fleet_application::persistent::InstallSource,
    ) -> Option<(String, String, String)> {
        install.answer.as_ref()?;
        let storage = install.iso.split_once(':')?.0.to_owned();
        let file = format!("fleet-answer-{}.iso", self.vmid);
        Some((format!("{storage}:iso/{file}"), storage, file))
    }

    /// The bootstrap public key of this install: the key an earlier run
    /// stored, or a new Fleet-generated ed25519 key (private half stored as a
    /// secret bound to the install; only the public half goes on the media).
    async fn bootstrap_public_key(&self) -> Step<String> {
        let step = "answer_media";
        let owner = self.install_owner();
        if let Some(existing) = self
            .exec
            .keys
            .list_for_machine(&owner)
            .await
            .map_err(|detail| failure(step, "credential_failed", detail))?
            .into_iter()
            .next()
            && let Some(text) = self
                .exec
                .keys
                .resolve(&existing, &owner)
                .await
                .map_err(|detail| failure(step, "credential_failed", detail))?
        {
            return self.public_of(&text).await;
        }
        let provider = self.exec.provider.clone();
        let comment = format!("fleet-bootstrap-{}", self.spec.name);
        let generated = tokio::task::spawn_blocking(move || provider.generate_ed25519(&comment))
            .await
            .map_err(|error| failure(step, "keygen_failed", error.to_string()))?
            .map_err(|error| failure(step, "keygen_failed", error.to_string()))?;
        self.store_key(&owner, &generated.private)
            .await
            .map_err(|detail| failure(step, "credential_failed", detail))?;
        Ok(generated.public)
    }

    /// Builds the answer media Fleet generates, uploads it to the installer's
    /// storage and answers its volume id (`None` when the spec has no
    /// generated answer). A stale volume of the same name is replaced.
    async fn generated_answer(
        &mut self,
        install: &fleet_application::persistent::InstallSource,
    ) -> Step<Option<String>> {
        use fleet_application::answer_media::{
            Autounattend, NoCloudSeed, autounattend_iso, nocloud_iso,
        };
        use fleet_application::persistent::GeneratedAnswer;
        let step = "answer_media";
        let (Some(answer), Some((volume, storage, file))) =
            (install.answer.as_ref(), self.answer_volume(install))
        else {
            return Ok(None);
        };
        let public_key = self.bootstrap_public_key().await?;
        let created = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
        )
        .unwrap_or(0);
        let user = self.spec.bootstrap_user().to_owned();
        let image = match answer {
            GeneratedAnswer::Nocloud => nocloud_iso(
                &NoCloudSeed {
                    vmid: self.vmid,
                    hostname: &self.spec.name,
                    user: &user,
                    public_key: &public_key,
                },
                created,
            ),
            GeneratedAnswer::Autounattend { edition } => {
                // A throwaway password: it is on this media only and Fleet
                // rotates it right after the install.
                let password = format!(
                    "Fl{}!9",
                    uuid::Uuid::new_v4().simple().to_string().to_uppercase()
                );
                autounattend_iso(
                    &Autounattend {
                        user: &user,
                        password: &password,
                        public_key: &public_key,
                        image_name: edition.as_deref().unwrap_or("Windows 11 Pro"),
                    },
                    created,
                )
            }
        }
        .map_err(|detail| failure(step, "invalid", detail))?;
        let client = &self.exec.pve.client;
        if client
            .storage_iso_exists(self.request.clone(), &self.node, &storage, &volume)
            .await
            .map_err(|error| failure(step, "upload_failed", error.to_string()))?
        {
            self.delete_answer_media().await;
        }
        let upid = self
            .exec
            .pve
            .client
            .storage_upload_iso(self.request.clone(), &self.node, &storage, &file, &image)
            .await
            .map_err(|error| failure(step, "upload_failed", error.to_string()))?;
        self.wait_task(step, &upid).await?;
        Ok(Some(volume))
    }

    /// Deletes the generated answer media from ISO storage, best effort and
    /// idempotent: absent is fine. Records whether it is gone.
    async fn delete_answer_media(&mut self) {
        let Some(install) = self.spec.install.clone() else {
            return;
        };
        let Some((volume, storage, _)) = self.answer_volume(&install) else {
            return;
        };
        let client = self.exec.pve.client.clone();
        let present = client
            .storage_iso_exists(self.request.clone(), &self.node, &storage, &volume)
            .await;
        let gone = match present {
            Ok(false) => true,
            Ok(true) => {
                match client
                    .storage_delete_volume(self.request.clone(), &self.node, &storage, &volume)
                    .await
                {
                    Ok(Some(upid)) => self.wait_task("answer_media", &upid).await.is_ok(),
                    Ok(None) => true,
                    Err(_) => false,
                }
            }
            Err(_) => false,
        };
        self.answer_deleted = Some(gone);
    }

    /// Step 4 of an ISO install: run the installer to its end, then boot the
    /// installed disk. The answer file must power the guest off when it is
    /// done. The end is seen only as running and then stopped by this run (or
    /// by an earlier run that started it, recorded as the marker step
    /// `installing`): a guest that was never seen running is not finished. The
    /// media is then ejected (never deleted: Proxmox refuses a drive removal on
    /// a protected guest) and the marker step `install` is written at once.
    /// Safe to repeat: stopped with media still attached after the installer
    /// started ejects without installing again, and the state an eject leaves
    /// (empty drive, boot order `scsi0`) proves Fleet ejected, whatever step
    /// the marker holds.
    async fn install(&mut self) -> Step<()> {
        let step = "install";
        let earlier = self.prior_step.clone();
        let started_before = earlier
            .as_deref()
            .and_then(step_rank)
            .is_some_and(|rank| rank >= 3);
        let state = self
            .exec
            .pve
            .client
            .qemu_install_state(self.request.clone(), &self.node, self.vmid)
            .await
            .map_err(|error| failure(step, "config_unreadable", error.to_string()))?;
        if state.attached.is_empty() {
            // Fleet's own eject, seen in the config or in the marker: carry
            // on. Anything else means the install never ran here, and a
            // guest nobody installed must not be adopted as an installed one.
            return if state.ejected || earlier.as_deref().is_some_and(passed_install) {
                self.delete_answer_media().await;
                self.record_step("install").await
            } else {
                Err(failure(
                    step,
                    "media_missing",
                    "the guest has no install media attached and Fleet never ran its install; it is not adopted. Destroy it and create the machine again",
                ))
            };
        }
        let media = state.attached;
        let first = self.power_state(step).await?;
        let mut seen_running = first == "running";
        let mut finished = started_before && first == "stopped";
        if !seen_running && !finished {
            self.start().await?;
        }
        if !finished {
            // Durable once the installer is running. Written after a start
            // that succeeded, not before: a start that failed must not look
            // like an install that ran.
            self.record_step("installing").await?;
        }
        while !finished {
            // The deadline is checked first so a run that ran out of time
            // says so, instead of reporting a generic expiry.
            if self.remaining().is_zero() {
                return Err(failure(
                    step,
                    "install_timeout",
                    "the installer did not power the guest off before the deadline; the guest is left as it is (its answer file must power off when the install ends, and a long install needs a longer --timeout)",
                ));
            }
            self.checkpoint("installing").await?;
            let state = self.power_state(step).await?;
            match state.as_str() {
                "running" => seen_running = true,
                "stopped" if seen_running => finished = true,
                _ => {}
            }
            if !finished {
                self.sleep().await;
            }
        }
        self.exec
            .pve
            .client
            .qemu_eject_media(self.request.clone(), &self.node, self.vmid, &media)
            .await
            .map_err(|error| failure(step, "media_not_removed", error.to_string()))?;
        let left = self
            .exec
            .pve
            .client
            .qemu_install_state(self.request.clone(), &self.node, self.vmid)
            .await
            .map_err(|error| failure(step, "config_unreadable", error.to_string()))?;
        if !left.attached.is_empty() {
            return Err(failure(
                step,
                "media_not_removed",
                "PVE accepted the change but the install media is still attached",
            ));
        }
        // The generated media (and any throwaway password on it) is no
        // longer needed: delete it from ISO storage.
        self.delete_answer_media().await;
        // Durable at once: a deadline or a cancel at the next checkpoint must
        // not lose the fact that the media is gone.
        self.record_step("install").await
    }

    /// Records that the clone completed: from here the marker guards the
    /// VMID whatever the guest is called.
    async fn mark_cloned(&mut self) -> Step<()> {
        if let Some(marker) = self.marker.as_mut()
            && !marker.cloned
        {
            marker.cloned = true;
            marker.step = Some("clone".to_owned());
            self.exec
                .persistent
                .update(marker)
                .await
                .map_err(|detail| failure("clone", "marker_failed", detail))?;
        }
        Ok(())
    }

    /// Removes this creation's marker when the cluster shows nothing at its
    /// VMID and the clone never completed. Best effort: a marker that stays
    /// is harmless (it guards only a guest with its name) and can be
    /// abandoned explicitly.
    async fn release_marker_if_vacant(&mut self) {
        let Some(marker) = self.marker.as_ref().filter(|marker| !marker.cloned) else {
            return;
        };
        let vacant = self
            .exec
            .pve
            .client
            .list_guest_resources(self.request.clone())
            .await
            .is_ok_and(|resources| {
                !resources
                    .iter()
                    .any(|resource| resource.vmid == Some(marker.vmid))
            });
        if vacant
            && self
                .exec
                .persistent
                .remove(&marker.account_id, marker.vmid)
                .await
                .is_ok()
        {
            self.marker = None;
        }
    }

    // Step 3: wait for the clone's lock, then grow the disk and write the
    // reviewed settings in one allow-listed write.
    async fn configure(&mut self) -> Step<()> {
        let step = "config";
        let settings = loop {
            let settings = self
                .exec
                .pve
                .client
                .qemu_settings(self.request.clone(), &self.node, self.vmid)
                .await
                .map_err(|error| failure(step, "config_unreadable", error.to_string()))?;
            if settings.lock.is_none() {
                break settings;
            }
            if self.remaining().is_zero() || self.remaining() > CLONE_SETTLE * 4 {
                return Err(failure(
                    step,
                    "deadline_expired",
                    "the clone's config lock never cleared",
                ));
            }
            self.checkpoint(step).await?;
            self.sleep().await;
        };
        if settings.template || settings.name.as_deref() != Some(self.spec.name.as_str()) {
            return Err(failure(
                step,
                "conflict",
                "the guest at the target is not this machine's clone; its config is left unchanged",
            ));
        }
        if let Some(disk_gib) = self.spec.disk_gib {
            let hardware = self
                .exec
                .pve
                .client
                .qemu_hardware(self.request.clone(), &self.node, self.vmid)
                .await
                .map_err(|error| failure(step, "disk", error.to_string()))?;
            let disk = hardware.boot_disk.ok_or_else(|| {
                failure(
                    step,
                    "disk",
                    "the guest has no identifiable boot disk to grow",
                )
            })?;
            let want_mib = u64::from(disk_gib) * 1024;
            match disk.size_mib {
                Some(have) if have >= want_mib => {}
                _ => {
                    let digest = hardware
                        .digest
                        .ok_or_else(|| failure(step, "disk", "the config carries no digest"))?;
                    if let Some(upid) = self
                        .exec
                        .pve
                        .client
                        .qemu_resize_disk(
                            self.request.clone(),
                            &self.node,
                            self.vmid,
                            &disk.key,
                            disk_gib,
                            &digest,
                        )
                        .await
                        .map_err(|error| failure(step, "disk", error.to_string()))?
                    {
                        self.wait_task(step, &upid).await?;
                    }
                }
            }
        }
        // Read again: the resize changed the digest.
        let settings = self
            .exec
            .pve
            .client
            .qemu_settings(self.request.clone(), &self.node, self.vmid)
            .await
            .map_err(|error| failure(step, "config_unreadable", error.to_string()))?;
        let digest = settings
            .digest
            .clone()
            .ok_or_else(|| failure(step, "config", "the config carries no digest"))?;
        let net0 = match (&self.spec.bridge, &settings.net0) {
            (Some(bridge), Some(net0)) => {
                Some(with_bridge(net0, bridge).map_err(|detail| failure(step, "network", detail))?)
            }
            (Some(_), None) => {
                return Err(failure(
                    step,
                    "network",
                    "the template has no net0 to move to the bridge",
                ));
            }
            _ => None,
        };
        let audio = self
            .spec
            .audio
            .as_ref()
            .map(|device| fleet_provider_proxmox::PveAudio {
                device: device.clone(),
                driver: "none".to_owned(),
            });
        // The write replaces the tag list, so the template's tags (a fixture
        // or Lab tag) are never inherited.
        let write = PveQemuWrite {
            tags: Some(persistent_tags(&self.spec.tags)),
            description: Some(self.spec.description.clone()),
            onboot: Some(self.spec.onboot),
            protection: Some(self.spec.protection),
            cores: self.spec.cores,
            memory_mib: self.spec.memory_mib,
            net0,
            audio,
        };
        if settings.memory_has_options && write.memory_mib.is_some() {
            return Err(failure(
                step,
                "config",
                "the template's memory has ballooning options a plain write would drop",
            ));
        }
        self.exec
            .pve
            .client
            .qemu_write_settings(self.request.clone(), &self.node, self.vmid, &write, &digest)
            .await
            .map_err(|error| failure(step, "config_failed", error.to_string()))?;
        let after = self
            .exec
            .pve
            .client
            .qemu_settings(self.request.clone(), &self.node, self.vmid)
            .await
            .map_err(|error| failure(step, "config_unreadable", error.to_string()))?;
        if after.protection != self.spec.protection
            || after.onboot != self.spec.onboot
            || after
                .tags
                .iter()
                .any(|tag| !self.spec.tags.contains(tag) && tag != PERSISTENT_TAG)
        {
            return Err(failure(
                step,
                "readback_mismatch",
                "PVE accepted the write but the config does not show it",
            ));
        }
        Ok(())
    }

    // Step 4: start.
    /// The guest's power state, read from the process (never from the
    /// lagging resources list).
    async fn power_state(&self, step: &'static str) -> Step<String> {
        self.exec
            .pve
            .client
            .qemu_power_state(self.request.clone(), &self.node, self.vmid)
            .await
            .map_err(|error| failure(step, "status_unreadable", error.to_string()))
    }

    async fn start(&self) -> Step<()> {
        let step = "start";
        // `/cluster/resources` lags by seconds: a guest that is running can
        // still be listed as stopped. The status endpoint reads the process.
        let state = self
            .exec
            .pve
            .client
            .qemu_power_state(self.request.clone(), &self.node, self.vmid)
            .await
            .map_err(|error| failure(step, "status_unreadable", error.to_string()))?;
        if state == "running" {
            return Ok(());
        }
        let upid = self
            .exec
            .pve
            .client
            .guest_lifecycle(
                self.request.clone(),
                &self.node,
                self.vmid,
                LifecycleAction::Start,
            )
            .await
            .map_err(|error| failure(step, "start_failed", error.to_string()))?;
        self.wait_task(step, &upid).await
    }

    // Step 5: the agent's address.
    async fn address(&mut self) -> Step<()> {
        let step = "address";
        // The MAC address Proxmox gave the guest's first NIC: the address
        // must come from the interface that carries it, so a stale agent
        // answer or another guest's address can never become this machine's
        // endpoint.
        let mac = self
            .exec
            .pve
            .client
            .qemu_settings(self.request.clone(), &self.node, self.vmid)
            .await
            .map_err(|error| failure(step, "config_unreadable", error.to_string()))?
            .net0
            .as_deref()
            .and_then(net_mac);
        loop {
            self.checkpoint(step).await?;
            let agent = self
                .exec
                .pve
                .client
                .guest_agent_network(self.request.clone(), &self.node, self.vmid)
                .await;
            if let Some(mac) = &mac
                && agent.online
                && !agent.interfaces.is_empty()
                && !agent
                    .interfaces
                    .iter()
                    .any(|interface| interface.mac.as_deref() == Some(mac.as_str()))
            {
                return Err(failure(
                    step,
                    "address_mismatch",
                    "the guest agent reports no interface with the MAC address Proxmox gave this VM; it may be answering for another guest",
                ));
            }
            let ip = agent
                .online
                .then(|| {
                    agent
                        .interfaces
                        .iter()
                        .filter(|interface| {
                            mac.is_none() || interface.mac.as_deref() == mac.as_deref()
                        })
                        .flat_map(|interface| &interface.addresses)
                        .filter_map(|address| address.parse::<std::net::Ipv4Addr>().ok())
                        .find(|ip| {
                            !ip.is_loopback()
                                && !ip.is_link_local()
                                && !ip.is_unspecified()
                                && !ip.is_multicast()
                                && !ip.is_broadcast()
                        })
                })
                .flatten();
            if let Some(ip) = ip {
                self.host = Some(
                    self.exec
                        .address_override
                        .clone()
                        .unwrap_or_else(|| ip.to_string()),
                );
                return Ok(());
            }
            if self.remaining().is_zero() {
                return Err(failure(
                    step,
                    "never_ready",
                    "the guest agent reported no usable IPv4 address before the deadline",
                ));
            }
            self.sleep().await;
        }
    }

    fn connection(&self, user: &str, auth: SshAuth) -> SshConnectionSpec {
        SshConnectionSpec {
            host: self.host.clone().unwrap_or_default(),
            port: self.spec.bootstrap.port,
            user: user.to_owned(),
            auth,
            guest_os: self.spec.guest_os,
        }
    }

    async fn ssh(
        &self,
        step: &'static str,
        spec: SshConnectionSpec,
        script: String,
        deadline: Duration,
    ) -> Step<String> {
        let provider = self.exec.provider.clone();
        let limiter = self.exec.limiter.clone();
        let result = tokio::task::spawn_blocking(move || {
            fleet_provider_ssh::execute_script(
                &provider,
                &limiter,
                &spec,
                &script,
                &ScriptMetadata::default(),
                deadline,
            )
        })
        .await
        .map_err(|error| {
            failure(
                step,
                "ssh_failed",
                format!("the session thread failed: {error}"),
            )
        })?
        .map_err(|error| failure(step, "ssh_failed", error.to_string()))?;
        if result.killed_by_deadline {
            return Err(failure(
                step,
                "ssh_deadline",
                "the session was killed at its deadline; the guest command's fate is unknown",
            ));
        }
        if result.exit_code != Some(0) {
            // The guest's own stderr, scrubbed and bounded; it carries no
            // secret because no script prints one.
            // The activation script holds the product key, so nothing the
            // guest printed is repeated for that step.
            let stderr = if step == "activation" {
                String::new()
            } else {
                result.stderr.chars().take(300).collect::<String>()
            };
            return Err(failure(
                step,
                "guest_failed",
                format!("the guest command exited {:?}: {stderr}", result.exit_code),
            ));
        }
        Ok(result.stdout)
    }

    // Step 6: register the machine and its endpoint.
    async fn register(&mut self) -> Step<()> {
        let step = "machine";
        let host = self.host.clone().unwrap_or_default();
        let reference = format!(
            "{}@{host}:{}",
            self.spec.endpoint_user(),
            self.spec.bootstrap.port
        );
        self.refuse_registered_address(&host).await?;
        let machines = Machines::new(self.exec.machines.clone(), self.exec.audit.clone());
        let machine = if let Some(id) = &self.machine_id {
            self.exec
                .machines
                .get(id)
                .await
                .map_err(|failure_| failure(step, "machine_failed", failure_.to_string()))?
        } else {
            let machine = machines
                .register(
                    &fleet_auth::LanAllowAllAuthorizer,
                    &lan(),
                    &RegisterMachine {
                        name: self.spec.name.clone(),
                        description: self.spec.description.clone(),
                        endpoints: vec![NewEndpoint {
                            kind: EndpointKind::Ssh,
                            reference: reference.clone(),
                        }],
                        tags: Vec::new(),
                        groups: Vec::new(),
                    },
                )
                .await
                .map_err(|error| failure(step, "machine_failed", error.to_string()))?;
            // A label for the console and `machines list --tag`; a machine
            // that already has it is fine.
            let _ = machines
                .add_tag(
                    &fleet_auth::LanAllowAllAuthorizer,
                    &lan(),
                    &machine.id,
                    "persistent",
                )
                .await;
            machine
        };
        let endpoint = machine
            .endpoints
            .iter()
            .find(|endpoint| endpoint.kind == EndpointKind::Ssh)
            .ok_or_else(|| failure(step, "machine_failed", "the machine has no SSH endpoint"))?;
        let recorded_host = endpoint
            .reference
            .rsplit_once('@')
            .and_then(|(_, rest)| rest.rsplit_once(':'))
            .map(|(host, _)| host.to_owned());
        if recorded_host.as_deref() != Some(host.as_str()) {
            return Err(failure(
                step,
                "address_changed",
                "the guest's address differs from the registered endpoint; update the endpoint and re-run",
            ));
        }
        self.machine_id = Some(machine.id.clone());
        self.endpoint_id = Some(endpoint.id.clone());
        Ok(())
    }

    /// Refuses a guest address that is already another machine's SSH
    /// endpoint: registering it would put two machines on one host.
    async fn refuse_registered_address(&self, host: &str) -> Step<()> {
        let step = "machine";
        let port = self.spec.bootstrap.port;
        let mut cursor = None;
        loop {
            let page = self
                .exec
                .machines
                .list(
                    &fleet_application::machine::MachineFilter {
                        cursor: cursor.clone(),
                        ..fleet_application::machine::MachineFilter::default()
                    },
                    200,
                )
                .await
                .map_err(|error| failure(step, "machine_failed", error.to_string()))?;
            for machine in &page {
                if self.machine_id.as_deref() == Some(machine.id.as_str()) {
                    continue;
                }
                if machine.endpoints.iter().any(|endpoint| {
                    endpoint.kind == EndpointKind::Ssh
                        && endpoint
                            .reference
                            .rsplit_once('@')
                            .map_or(endpoint.reference.as_str(), |(_, rest)| rest)
                            == format!("{host}:{port}")
                }) {
                    return Err(failure(
                        step,
                        "address_in_use",
                        format!(
                            "{host}:{port} is already an endpoint of the machine {}; this guest's address is not unique",
                            machine.name
                        ),
                    ));
                }
            }
            if page.len() < 200 {
                return Ok(());
            }
            cursor = page.last().map(|machine| machine.id.clone());
        }
    }

    // Step 7: reachability and the host key.
    async fn host_key(&mut self) -> Step<()> {
        let step = "host_key";
        let host = self.host.clone().unwrap_or_default();
        let port = self.spec.bootstrap.port;
        let observations = loop {
            self.checkpoint(step).await?;
            let provider = self.exec.provider.clone();
            let probe_host = host.clone();
            let probe = tokio::task::spawn_blocking(move || {
                provider.probe_host_keys(&probe_host, port, Duration::from_secs(5))
            })
            .await
            .map_err(|error| failure(step, "ssh_failed", error.to_string()))?;
            match probe {
                Ok(observations) => break observations,
                Err(_) if !self.remaining().is_zero() => self.sleep().await,
                Err(error) => {
                    return Err(failure(
                        step,
                        "never_ready",
                        format!("SSH never answered before the deadline: {error}"),
                    ));
                }
            }
        };
        let endpoint = self.endpoint_id.clone().unwrap_or_default();
        let known = self
            .exec
            .machines
            .verified_fingerprint(&endpoint)
            .await
            .map_err(|error| failure(step, "trust_failed", error.to_string()))?;
        // A guest offers several key types; match the pinned or confirmed
        // fingerprint against any of them, never only the preferred one.
        let pinned = match &self.spec.host_key {
            HostKeyTrust::Pinned { fingerprint } => Some(fingerprint.as_str()),
            _ => None,
        };
        let observation =
            fleet_provider_ssh::choose_observation(&[pinned, known.as_deref()], &observations)
                .cloned()
                .ok_or_else(|| {
                    failure(step, "never_ready", "SSH presented no host key".to_owned())
                })?;
        if let HostKeyTrust::Pinned { fingerprint } = &self.spec.host_key
            && *fingerprint != observation.fingerprint
        {
            return Err(failure(
                step,
                "host_key_mismatch",
                format!(
                    "the guest presents {} instead of the pinned {fingerprint}",
                    observation.fingerprint
                ),
            ));
        }
        match known {
            Some(known) if known != observation.fingerprint => {
                return Err(failure(
                    step,
                    "host_key_changed",
                    format!(
                        "the guest presents {} but the endpoint confirmed {known}; re-confirm it deliberately",
                        observation.fingerprint
                    ),
                ));
            }
            Some(_) => {}
            None => {
                // First use (or an explicit pin that matched): the
                // confirmation is audited by the machine use case.
                Machines::new(self.exec.machines.clone(), self.exec.audit.clone())
                    .confirm_host_key(
                        &fleet_auth::LanAllowAllAuthorizer,
                        &lan(),
                        &endpoint,
                        &observation.fingerprint,
                    )
                    .await
                    .map_err(|error| failure(step, "trust_failed", error.to_string()))?;
            }
        }
        self.exec
            .provider
            .pin(&observation)
            .map_err(|error| failure(step, "trust_failed", error.to_string()))?;
        self.fingerprint = Some(observation.fingerprint);
        Ok(())
    }

    // Step 8: link the guest. The controller created it, so this is stronger
    // evidence than a discovery candidate.
    async fn link(&self) -> Step<()> {
        let step = "link";
        let machine_id = self.machine_id.clone().unwrap_or_default();
        let link = GuestLink {
            account_id: self.spec.account_id.clone(),
            guest_kind: "qemu".to_owned(),
            node: self.node.clone(),
            vmid: self.vmid,
        };
        let current = self
            .exec
            .guest_links
            .get(&machine_id)
            .await
            .map_err(|error| failure(step, "link_failed", error.to_string()))?;
        if current.as_ref() == Some(&link) {
            return Ok(());
        }
        self.exec
            .guest_links
            .confirm(&machine_id, &link)
            .await
            .map_err(|error| failure(step, "link_failed", error.to_string()))?;
        self.exec
            .audit
            .record_intent(
                &audit_intent(
                    Permission::MachineLinkGuest,
                    &machine_id,
                    &self.operation.id,
                    &[
                        ("event", "machine_guest_linked"),
                        ("accountId", self.spec.account_id.as_str()),
                        ("vmid", &self.vmid.to_string()),
                    ],
                )
                .map_err(|detail| failure(step, "link_failed", detail))?,
            )
            .await
            .map_err(|detail| failure(step, "link_failed", detail))
    }

    async fn bootstrap_auth(&self, step: &'static str) -> Step<SshAuth> {
        if self
            .spec
            .install
            .as_ref()
            .is_some_and(|install| install.answer.is_some())
        {
            // The key Fleet put on the generated media. Once the final key has
            // replaced it the record is gone and nothing needs it: a re-run
            // that already switched never uses this value.
            let owner = self.install_owner();
            let existing = self
                .exec
                .keys
                .list_for_machine(&owner)
                .await
                .map_err(|detail| failure(step, "bootstrap_auth", detail))?
                .into_iter()
                .next();
            let Some(reference) = existing else {
                return Ok(SshAuth::Agent);
            };
            let text = self
                .exec
                .keys
                .resolve(&reference, &owner)
                .await
                .map_err(|detail| failure(step, "bootstrap_auth", detail))?
                .ok_or_else(|| {
                    failure(
                        step,
                        "bootstrap_auth",
                        "the install's bootstrap key no longer resolves",
                    )
                })?;
            let key = PrivateKey::parse(&text)
                .map_err(|detail| failure(step, "bootstrap_auth", detail))?;
            return Ok(SshAuth::StoredKey { key });
        }
        self.exec
            .resolver
            .resolve(
                &self.spec.bootstrap.auth,
                self.machine_id.as_deref().unwrap_or_default(),
            )
            .await
            .map_err(|detail| failure(step, "bootstrap_auth", detail))
    }

    // Step 9 (Windows): the computer name, through a fixed post-boot step.
    async fn windows_name(&mut self) -> Step<()> {
        let step = "windows_name";
        // A re-run after the credential switch must not need the image key,
        // which is gone: use the Fleet-held key when the endpoint already
        // has it.
        let (user, auth) = match self.switched_key().await? {
            Some((_, auth)) => (self.spec.endpoint_user().to_owned(), auth),
            None => (
                self.spec.bootstrap_user().to_owned(),
                self.bootstrap_auth(step).await?,
            ),
        };
        let spec = self.connection(&user, auth);
        let out = self
            .ssh(
                step,
                spec.clone(),
                guest::windows_rename_script(&self.spec.name),
                SESSION,
            )
            .await?;
        if out.lines().any(|line| line.trim() == "FLEET_RENAMED=1") {
            // The restart drops the session; a non-zero exit is expected.
            let _ = self
                .ssh(step, spec, guest::windows_restart_script(), SESSION)
                .await;
            self.wait_for_restart().await?;
            self.host_key().await?;
        }
        Ok(())
    }

    /// Waits until SSH stops answering (the guest went down) and fails if it
    /// never does within two minutes: the rename only takes effect after the
    /// restart, so carrying on while the old session is still up would
    /// continue on a guest that never restarted. Coming back up is
    /// [`Self::host_key`]'s wait.
    async fn wait_for_restart(&self) -> Step<()> {
        let step = "windows_name";
        let host = self.host.clone().unwrap_or_default();
        let port = self.spec.bootstrap.port;
        let give_up = Instant::now() + Duration::from_secs(120);
        loop {
            let provider = self.exec.provider.clone();
            let probe_host = host.clone();
            let up = tokio::task::spawn_blocking(move || {
                provider
                    .probe_host_key(&probe_host, port, Duration::from_secs(3))
                    .is_ok()
            })
            .await
            .map_err(|error| failure(step, "ssh_failed", error.to_string()))?;
            if !up {
                return Ok(());
            }
            if Instant::now() >= give_up || self.remaining().is_zero() {
                return Err(failure(
                    step,
                    "restart_failed",
                    "the guest still answers SSH two minutes after the restart was requested; the new computer name is not in effect",
                ));
            }
            self.sleep().await;
        }
    }

    /// Refuses a re-run whose credential choice differs from the key the
    /// endpoint was already switched to.
    async fn require_switched_key_matches(&self, credential: &str) -> Step<()> {
        let step = "credential";
        let machine_id = self.machine_id.clone().unwrap_or_default();
        let matches = match &self.spec.credential {
            CredentialChoice::Generate => self
                .exec
                .keys
                .list_for_machine(&machine_id)
                .await
                .map_err(|detail| failure(step, "credential_failed", detail))?
                .iter()
                .any(|bound| bound == credential),
            CredentialChoice::Reference { credential: asked } => asked == credential,
            CredentialChoice::PublicKey { .. } => false,
        };
        if matches {
            Ok(())
        } else {
            Err(failure(
                step,
                "credential_changed",
                "the endpoint already uses another Fleet-held key than this request asks for; nothing was changed. Re-run with the original credential choice, or change the endpoint's key deliberately",
            ))
        }
    }

    /// The Fleet-held key the endpoint already defaults to, when a login
    /// with it works: the proof that the credential switch of an earlier run
    /// completed. It is never the bootstrap credential.
    async fn switched_key(&self) -> Step<Option<(String, SshAuth)>> {
        let step = "credential";
        let machine_id = self.machine_id.clone().unwrap_or_default();
        let endpoint = self.endpoint_id.clone().unwrap_or_default();
        let Some(EndpointAuth::Secret { credential }) = self
            .exec
            .endpoint_auths
            .get(&endpoint)
            .await
            .map_err(|detail| failure(step, "credential_failed", detail))?
        else {
            return Ok(None);
        };
        if matches!(
            &self.spec.bootstrap.auth,
            EndpointAuth::Secret { credential: bootstrap } if *bootstrap == credential
        ) {
            return Ok(None);
        }
        let Ok(auth) = self
            .exec
            .resolver
            .resolve(
                &EndpointAuth::Secret {
                    credential: credential.clone(),
                },
                &machine_id,
            )
            .await
        else {
            return Ok(None);
        };
        let works = self
            .ssh(
                step,
                self.connection(self.spec.endpoint_user(), auth.clone()),
                "echo FLEET_LOGIN_OK\n".to_owned(),
                SESSION,
            )
            .await
            .is_ok();
        Ok(works.then_some((credential, auth)))
    }

    /// The public key line the machine will accept, and the stored private
    /// key when Fleet holds one.
    async fn key_material(&mut self) -> Step<(String, Option<String>)> {
        let step = "credential";
        let machine_id = self.machine_id.clone().unwrap_or_default();
        match self.spec.credential.clone() {
            CredentialChoice::Generate => {
                // A re-run reuses the key an earlier run of this machine
                // generated (before or after the switch), so keys never pile
                // up in the store.
                if let Some(existing) = self
                    .exec
                    .keys
                    .list_for_machine(&machine_id)
                    .await
                    .map_err(|detail| failure(step, "credential_failed", detail))?
                    .into_iter()
                    .next()
                    && let Some(text) = self
                        .exec
                        .keys
                        .resolve(&existing, &machine_id)
                        .await
                        .map_err(|detail| failure(step, "credential_failed", detail))?
                {
                    return Ok((self.public_of(&text).await?, Some(existing)));
                }
                let provider = self.exec.provider.clone();
                let comment = format!("fleet-{}", self.spec.name);
                let generated =
                    tokio::task::spawn_blocking(move || provider.generate_ed25519(&comment))
                        .await
                        .map_err(|error| failure(step, "keygen_failed", error.to_string()))?
                        .map_err(|error| failure(step, "keygen_failed", error.to_string()))?;
                let reference = self
                    .store_key(&machine_id, &generated.private)
                    .await
                    .map_err(|detail| failure(step, "credential_failed", detail))?;
                Ok((generated.public, Some(reference)))
            }
            CredentialChoice::Reference { credential } => {
                if !self
                    .exec
                    .keys
                    .is_machine_key(&credential)
                    .await
                    .map_err(|detail| failure(step, "credential_failed", detail))?
                {
                    return Err(failure(
                        step,
                        "credential_failed",
                        "a repository (git/) credential cannot be a persistent machine's SSH key",
                    ));
                }
                let text = self
                    .exec
                    .keys
                    .resolve(&credential, &machine_id)
                    .await
                    .map_err(|detail| failure(step, "credential_failed", detail))?
                    .ok_or_else(|| {
                        failure(
                            step,
                            "credential_failed",
                            "the credential reference no longer resolves",
                        )
                    })?;
                Ok((self.public_of(&text).await?, Some(credential)))
            }
            CredentialChoice::PublicKey { public_key } => Ok((public_key.trim().to_owned(), None)),
        }
    }

    /// Stores the generated private key as `machines/ssh/<machine>/<id>`:
    /// bound to the new machine, so it resolves on that machine only.
    async fn store_key(&self, machine_id: &str, key: &PrivateKey) -> Result<String, String> {
        self.exec
            .keys
            .create(key.expose_for_store(), Some(machine_id))
            .await
    }

    async fn public_of(&self, text: &str) -> Step<String> {
        let step = "credential";
        let key =
            PrivateKey::parse(text).map_err(|detail| failure(step, "credential_failed", detail))?;
        let provider = self.exec.provider.clone();
        tokio::task::spawn_blocking(move || provider.public_key_of(&key))
            .await
            .map_err(|error| failure(step, "credential_failed", error.to_string()))?
            .map_err(|error| failure(step, "credential_failed", error.to_string()))
    }

    // Step 10: install, verify, switch, remove, verify. A re-run after the
    // switch skips the install and the first verification (the Fleet-held
    // key already works) and repeats the removal, which is idempotent.
    #[allow(clippy::too_many_lines)]
    async fn rotate_credentials(&mut self) -> Step<()> {
        let step = "credential";
        let machine_id = self.machine_id.clone().unwrap_or_default();
        let endpoint = self.endpoint_id.clone().unwrap_or_default();
        let bootstrap_user = self.spec.bootstrap_user().to_owned();
        let login_user = self.spec.endpoint_user().to_owned();
        let target = (login_user != bootstrap_user).then_some(login_user.as_str());
        let windows = self.spec.guest_os == GuestOs::Windows;
        let switched = self.switched_key().await?;
        let (public, reference) = if let Some((credential, _)) = &switched {
            // An earlier run already switched the endpoint to this key: the
            // spec must still ask for it, and the public key to keep is its
            // own, so a re-run with another choice can never rewrite
            // authorized_keys to a key the endpoint does not use.
            self.require_switched_key_matches(credential).await?;
            let text = self
                .exec
                .keys
                .resolve(credential, &machine_id)
                .await
                .map_err(|detail| failure(step, "credential_failed", detail))?
                .ok_or_else(|| {
                    failure(
                        step,
                        "credential_failed",
                        "the endpoint's stored key no longer resolves",
                    )
                })?;
            (self.public_of(&text).await?, Some(credential.clone()))
        } else {
            self.key_material().await?
        };
        let bootstrap = self.bootstrap_auth(step).await?;
        let resumed = switched.is_some();
        let mut stored = None;
        if let Some((credential, auth)) = switched {
            self.credential = Some(credential);
            stored = Some(auth);
        }
        let stored = if let Some(stored) = stored {
            stored
        } else {
            // 1. Install while the bootstrap credential still works.
            let install = if windows {
                guest::windows_install_key_script(target, &public, false)
            } else {
                guest::linux_install_key_script(target, &public)
            };
            self.ssh(
                step,
                self.connection(&bootstrap_user, bootstrap.clone()),
                install,
                SESSION,
            )
            .await
            .map_err(|f| failure(step, "install_failed", f.detail))?;
            let Some(reference) = reference else {
                // An operator-held key: Fleet cannot log in with it, so it
                // cannot verify it, and it keeps the credential it has.
                // Nothing is removed.
                self.record_default_auth(&machine_id, &endpoint, self.spec.bootstrap.auth.clone())
                    .await?;
                self.bootstrap_key_removed = false;
                return Ok(());
            };
            // 2. Verify a login with the new key before anything is removed.
            let auth = EndpointAuth::Secret {
                credential: reference.clone(),
            };
            let stored = self
                .exec
                .resolver
                .resolve(&auth, &machine_id)
                .await
                .map_err(|detail| failure(step, "verify_failed", detail))?;
            self.ssh(
                step,
                self.connection(&login_user, stored.clone()),
                "echo FLEET_LOGIN_OK\n".to_owned(),
                SESSION,
            )
            .await
            .map_err(|f| {
                failure(
                    step,
                    "verify_failed",
                    format!(
                        "a login with the new key failed, so nothing was removed and the bootstrap credential still works: {}",
                        f.detail
                    ),
                )
            })?;
            // 3. Switch the endpoint to the proven key.
            self.record_default_auth(&machine_id, &endpoint, auth)
                .await?;
            self.credential = Some(reference);
            stored
        };
        // 4. Remove the image's shared key, over the new key.
        let replace = if windows {
            guest::windows_install_key_script(None, &public, true)
        } else {
            guest::linux_replace_keys_script(&public)
        };
        self.ssh(
            step,
            self.connection(&login_user, stored.clone()),
            replace,
            SESSION,
        )
        .await
        .map_err(|f| failure(step, "revoke_failed", f.detail))?;
        // A login user other than the image's leaves the image user's own
        // file behind: empty it over the bootstrap session, which still
        // works because the new key is proven. After a resume the image key
        // may already be gone, which is the goal, not a failure.
        if target.is_some() && !windows {
            let cleared = self
                .ssh(
                    step,
                    self.connection(&bootstrap_user, bootstrap),
                    "set -eu\n: > \"${HOME:?}/.ssh/authorized_keys\"\n".to_owned(),
                    SESSION,
                )
                .await;
            if let Err(f) = cleared
                && !resumed
            {
                return Err(failure(step, "revoke_failed", f.detail));
            }
        }
        // 5. Verify again: the removal must not have cost the new key.
        self.ssh(
            step,
            self.connection(&login_user, stored),
            "echo FLEET_LOGIN_OK\n".to_owned(),
            SESSION,
        )
        .await
        .map_err(|f| failure(step, "verify_failed", f.detail))?;
        self.bootstrap_key_removed = true;
        Ok(())
    }

    /// Deletes the generated install's bootstrap key once the final key is
    /// proven and the bootstrap one is removed from the guest. Best effort.
    async fn delete_bootstrap_key(&self) {
        if !self
            .spec
            .install
            .as_ref()
            .is_some_and(|install| install.answer.is_some())
        {
            return;
        }
        let owner = self.install_owner();
        if let Ok(references) = self.exec.keys.list_for_machine(&owner).await {
            for reference in references {
                let _ = self.exec.secrets.delete(&reference).await;
            }
        }
    }

    async fn record_default_auth(
        &self,
        machine_id: &str,
        endpoint: &str,
        auth: EndpointAuth,
    ) -> Step<()> {
        self.exec
            .access
            .set_default_auth(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan(),
                machine_id,
                endpoint,
                Some(&auth),
            )
            .await
            .map_err(|error| failure("credential", "credential_failed", error.to_string()))
    }

    /// The auth Fleet uses from here on: the new key, or the bootstrap
    /// credential when Fleet does not hold the new key.
    async fn current_auth(&self, step: &'static str) -> Step<(String, SshAuth)> {
        let user = self.spec.endpoint_user().to_owned();
        match &self.credential {
            Some(reference) => {
                let auth = self
                    .exec
                    .resolver
                    .resolve(
                        &EndpointAuth::Secret {
                            credential: reference.clone(),
                        },
                        self.machine_id.as_deref().unwrap_or_default(),
                    )
                    .await
                    .map_err(|detail| failure(step, "credential_failed", detail))?;
                Ok((user, auth))
            }
            None => Ok((
                self.spec.bootstrap_user().to_owned(),
                self.bootstrap_auth(step).await?,
            )),
        }
    }

    // Step 11 (Windows): the administrator password.
    async fn rotate_password(&mut self, policy: AdminPasswordPolicy) -> Step<Option<String>> {
        let step = "admin_password";
        if policy == AdminPasswordPolicy::None {
            return Ok(None);
        }
        let print = policy == AdminPasswordPolicy::Store;
        let (user, auth) = self.current_auth(step).await?;
        let account = self.spec.bootstrap_user().to_owned();
        let out = self
            .ssh(
                step,
                self.connection(&user, auth),
                guest::windows_rotate_password_script(&account, print),
                SESSION,
            )
            .await?;
        if !out.lines().any(|line| line.trim() == "FLEET_ROTATED=1") {
            return Err(failure(
                step,
                "rotate_failed",
                "the guest did not confirm the rotation",
            ));
        }
        if !print {
            let machine_id = self.machine_id.clone().unwrap_or_default();
            self.exec
                .audit
                .record_intent(
                    &audit_intent(
                        Permission::MachineUpdate,
                        &machine_id,
                        &self.operation.id,
                        &[
                            ("event", "machine_admin_password_rotated"),
                            ("stored", "false"),
                        ],
                    )
                    .map_err(|detail| failure(step, "store_failed", detail))?,
                )
                .await
                .map_err(|detail| failure(step, "store_failed", detail))?;
            return Ok(None);
        }
        let password = guest::parse_password(&out).ok_or_else(|| {
            failure(
                step,
                "rotate_failed",
                "the guest rotated the password but printed none to store",
            )
        })?;
        let machine_id = self.machine_id.clone().unwrap_or_default();
        let prefix = format!("{ADMIN_PASSWORD_PREFIX}{machine_id}/");
        let name = format!("{prefix}{}", uuid::Uuid::now_v7());
        let record = self
            .exec
            .secrets
            .create(&name, SecretValue::new(password.into_bytes()))
            .await
            .map_err(|error| failure(step, "store_failed", error.to_string()))?;
        // The guest now holds this password: an earlier one (a re-run) is stale.
        if let Ok(records) = self.exec.secrets.list().await {
            for old in records
                .iter()
                .filter(|old| old.name.starts_with(&prefix) && old.id != record.id)
            {
                let _ = self.exec.secrets.delete(&old.id).await;
            }
        }
        self.exec
            .audit
            .record_intent(
                &audit_intent(
                    Permission::MachineUpdate,
                    &machine_id,
                    &self.operation.id,
                    &[
                        ("event", "machine_admin_password_rotated"),
                        ("credentialRef", record.id.as_str()),
                        ("stored", "true"),
                    ],
                )
                .map_err(|detail| failure(step, "store_failed", detail))?,
            )
            .await
            .map_err(|detail| failure(step, "store_failed", detail))?;
        Ok(Some(record.id))
    }

    // The optional activation step; its failure does not undo the machine.
    async fn activate(&mut self, activation: &Activation) -> Step<guest::ActivationReport> {
        let step = "activation";
        let script = match activation {
            Activation::None => unreachable!("an absent activation is skipped by the caller"),
            Activation::ProductKey { secret } => {
                let key = self
                    .exec
                    .product_keys
                    .resolve(secret)
                    .await
                    .map_err(|detail| failure(step, "product_key", detail))?
                    .ok_or_else(|| {
                        failure(
                            step,
                            "product_key",
                            "the product key secret no longer exists",
                        )
                    })?;
                guest::windows_activation_script(&guest::ActivationMethod::ProductKey(&key))
            }
            Activation::Kms { host } => {
                guest::windows_activation_script(&guest::ActivationMethod::Kms(host))
            }
        };
        let (user, auth) = self.current_auth(step).await?;
        // The script, which holds the product key, goes to the session's
        // stdin and nowhere else.
        let out = self
            .ssh(
                step,
                self.connection(&user, auth),
                script,
                ACTIVATION_SESSION,
            )
            .await?;
        Ok(guest::parse_activation(&out))
    }

    /// Settles who owns the marker (#496), right after it is reserved, so a
    /// half-made creation carries its owner. A marker this run found (a
    /// resume) must belong to the same request, or to no request on both
    /// sides; anything else is a conflict, and nothing is adopted. The first
    /// run of a brokered creation records the owner and its audit event.
    async fn settle_owner(&self, first: bool) -> Step<()> {
        let step = "reserve";
        let stamp = self.spec.requested_by.as_ref();
        let existing = self
            .exec
            .persistent
            .owner_of(&self.spec.account_id, self.vmid)
            .await
            .map_err(|detail| failure(step, "conflict", detail))?;
        let same_run = self.marker.as_ref().is_some_and(|marker| {
            marker.operation_id.as_deref() == Some(self.operation.id.as_str())
        });
        if !first && !same_run {
            let held = existing.as_ref().map(|owner| owner.request_id.as_str());
            if held != stamp.map(|by| by.request_id.as_str()) {
                return Err(failure(
                    step,
                    "conflict",
                    "the guest was started by another request or create; it is not adopted by this one",
                ));
            }
        }
        let Some(by) = stamp else {
            return Ok(());
        };
        self.exec
            .persistent
            .record_owner(&self.spec.account_id, self.vmid, by)
            .await
            .map_err(|detail| failure(step, "owner_failed", detail))?;
        if first {
            // The brokered creation's own event, linked to the request; the
            // actor is the system, the requester and approver are metadata.
            let intent = fleet_application::persistent::requested_intent(
                "system:machine-create",
                &self.operation.id,
                &self.spec,
            )
            .map_err(|error| failure(step, "audit_failed", error.to_string()))?;
            self.exec
                .audit
                .record_intent(&intent)
                .await
                .map_err(|error| failure(step, "audit_failed", error.to_string()))?;
        }
        Ok(())
    }

    async fn record_activation(&self, report: &guest::ActivationReport) {
        let Some(machine_id) = &self.machine_id else {
            return;
        };
        let fact = CapabilityFact {
            namespace: "windows".to_owned(),
            name: "activation".to_owned(),
            value: Some(report.status_name().to_owned()),
            status: CapabilityStatus::Known,
            observed_at: Timestamp::from_unix_millis(fleet_core::SystemClock::now_unix_millis()),
            source: "machine.create/1".to_owned(),
        };
        let machines = Machines::new(self.exec.machines.clone(), self.exec.audit.clone());
        if let Err(error) = machines
            .record_capabilities(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan(),
                machine_id,
                &[fact],
            )
            .await
        {
            eprintln!("machine.create: the activation fact was not recorded: {error}");
        }
    }
}

impl MachineCreateExecutor {
    #[allow(clippy::too_many_lines)]
    async fn run(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let spec: CreateMachineSpec = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a valid machine.create record: {error}"))?;
        spec.validate()?;
        let request = self.pve.bound(&spec.account_id).await?;
        let mut run = Run {
            exec: self,
            operations,
            operation,
            deadline: Instant::now() + Duration::from_secs(spec.timeout_seconds),
            spec,
            request,
            marker: None,
            prior_step: None,
            node: String::new(),
            vmid: 0,
            machine_id: None,
            endpoint_id: None,
            host: None,
            fingerprint: None,
            credential: None,
            bootstrap_key_removed: false,
            answer_deleted: None,
        };
        let mut notes = serde_json::Map::new();
        match run.saga(&mut notes).await {
            Ok(None) => {
                let result = run.result(&notes);
                operations
                    .complete(&operation.id, "succeeded", Some(&result.to_string()), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            Ok(Some(partial)) | Err(partial) => {
                let mut error = serde_json::json!({
                    "reason": partial.reason,
                    "step": partial.step,
                    "detail": partial.detail,
                    "vmid": run.vmid,
                    "machineId": run.machine_id,
                    "note": "the guest and everything created so far are kept; nothing is deleted automatically",
                });
                if let (Some(map), Some(extra)) = (error.as_object_mut(), Some(&notes)) {
                    map.extend(extra.clone());
                }
                complete_failed(operations, &operation.id, &error).await
            }
        }
    }
}

impl Run<'_> {
    /// The steps, in order. `Ok(Some(failure))` is a failure of the optional
    /// activation step only: the machine is complete and marked ready.
    #[allow(clippy::too_many_lines)]
    async fn saga(
        &mut self,
        notes: &mut serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Failure>, Failure> {
        self.progress(0, "reserving the guest").await;
        let (template_vmid, template_node) = self.reserve().await?;
        self.checkpoint("reserve").await?;
        let installing = self.spec.install.is_some();
        if installing {
            self.progress(1, "creating the guest with the installer attached")
                .await;
            self.create_install_guest().await?;
            self.checkpoint("create").await?;
        } else {
            self.progress(1, "cloning the image template").await;
            self.clone_guest(template_vmid, &template_node).await?;
            self.checkpoint("clone").await?;
        }
        self.progress(2, "applying hardware and metadata").await;
        self.configure().await?;
        self.checkpoint("config").await?;
        if installing {
            self.progress(3, "running the unattended install").await;
            self.install().await?;
            self.checkpoint("install").await?;
        }
        self.progress(3, "starting the guest").await;
        self.start().await?;
        self.checkpoint("start").await?;
        self.progress(4, "waiting for the guest agent address")
            .await;
        self.address().await?;
        self.progress(5, "registering the machine").await;
        self.register().await?;
        self.checkpoint("machine").await?;
        self.progress(6, "waiting for SSH and recording the host key")
            .await;
        self.host_key().await?;
        self.progress(7, "linking the guest").await;
        self.link().await?;
        self.checkpoint("link").await?;
        let windows = self.spec.guest_os == GuestOs::Windows;
        if windows {
            self.progress(8, "setting the computer name").await;
            self.windows_name().await?;
        }
        self.progress(9, "installing the SSH key and removing the image key")
            .await;
        self.rotate_credentials().await?;
        self.checkpoint("credential").await?;
        self.delete_bootstrap_key().await;
        let mut activation_failure = None;
        if windows {
            self.progress(10, "finishing the Windows setup").await;
            let options = self.spec.windows.clone().unwrap_or_default();
            match self.rotate_password(options.admin_password).await {
                Ok(Some(secret)) => {
                    notes.insert("adminPasswordSecret".to_owned(), secret.into());
                }
                Ok(None) => {}
                Err(failure) => return Err(failure),
            }
            if options.activation != Activation::None {
                match self.activate(&options.activation).await {
                    Ok(report) => {
                        self.record_activation(&report).await;
                        notes.insert(
                            "activation".to_owned(),
                            serde_json::json!({
                                "status": report.status_name(),
                                "activated": report.activated(),
                                "xpr": report.xpr,
                                "errorCode": report.error_code,
                            }),
                        );
                        if !report.activated() {
                            activation_failure = Some(failure(
                                "activation",
                                "activation_failed",
                                format!(
                                    "Windows is {}{}; the machine is created and registered",
                                    report.status_name(),
                                    report
                                        .error_code
                                        .as_ref()
                                        .map(|code| format!(" (Microsoft error {code})"))
                                        .unwrap_or_default()
                                ),
                            ));
                        }
                    }
                    Err(failure) => activation_failure = Some(failure),
                }
            }
        }
        // Ready: the machine exists, is reached and linked, and holds its key.
        if let Some(marker) = self.marker.as_mut() {
            marker.state = PersistentState::Ready;
            marker.step = Some("ready".to_owned());
            marker.machine_id.clone_from(&self.machine_id);
            self.exec
                .persistent
                .update(marker)
                .await
                .map_err(|detail| failure("ready", "marker_failed", detail))?;
        }
        Ok(activation_failure)
    }

    fn result(&self, notes: &serde_json::Map<String, serde_json::Value>) -> serde_json::Value {
        let mut result = serde_json::json!({
            "machineId": self.machine_id,
            "endpointId": self.endpoint_id,
            "accountId": self.spec.account_id,
            "node": self.node,
            "vmid": self.vmid,
            "address": self.host,
            "hostKeyFingerprint": self.fingerprint,
            "credentialRef": self.credential,
            "bootstrapKeyRemoved": self.bootstrap_key_removed,
            "protection": self.spec.protection,
            "state": "ready",
        });
        if let (Some(deleted), Some(map)) = (self.answer_deleted, result.as_object_mut()) {
            map.insert("answerMediaDeleted".to_owned(), deleted.into());
        }
        if let (Some(by), Some(map)) = (&self.spec.requested_by, result.as_object_mut()) {
            map.insert("requestId".to_owned(), by.request_id.clone().into());
        }
        if let Some(map) = result.as_object_mut() {
            map.extend(notes.clone());
        }
        result
    }
}

#[async_trait]
impl OperationExecutor for MachineCreateExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        self.run(operations, operation).await
    }
}

/// Wraps the executor chain with the persistent-VM kinds.
#[derive(Debug)]
pub struct PersistentDispatch {
    inner: Arc<dyn OperationExecutor>,
    create: Arc<MachineCreateExecutor>,
    config: Arc<GuestConfigExecutor>,
}

impl PersistentDispatch {
    /// Composes the wrapper.
    #[must_use]
    pub fn new(
        inner: Arc<dyn OperationExecutor>,
        create: Arc<MachineCreateExecutor>,
        config: Arc<GuestConfigExecutor>,
    ) -> Self {
        Self {
            inner,
            create,
            config,
        }
    }
}

#[async_trait]
impl OperationExecutor for PersistentDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            CREATE_KIND => self.create.execute(operations, operation).await,
            CONFIG_KIND => self.config.execute(operations, operation).await,
            _ => self.inner.execute(operations, operation).await,
        }
    }
}
