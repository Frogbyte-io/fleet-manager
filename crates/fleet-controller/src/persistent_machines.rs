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
    node: String,
    vmid: u32,
    machine_id: Option<String>,
    endpoint_id: Option<String>,
    host: Option<String>,
    fingerprint: Option<String>,
    /// The credential the machine ends up using, when Fleet holds it.
    credential: Option<String>,
    bootstrap_key_removed: bool,
}

const STEPS: i64 = 11;

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
        if let Some(marker) = self.marker.as_mut() {
            marker.step = Some(step.to_owned());
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
        let resources = self
            .exec
            .pve
            .client
            .list_guest_resources(self.request.clone())
            .await
            .map_err(|error| failure(step, "resources", error.to_string()))?;
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
        let target_node = spec.node.clone().unwrap_or(template_node.clone());
        let now = fleet_core::SystemClock::now_unix_millis();
        let marker = self
            .exec
            .persistent
            .reserve(&PersistentGuest {
                account_id: spec.account_id.clone(),
                vmid,
                name: spec.name.clone(),
                node: target_node.clone(),
                image_version_id: spec.image_version_id.clone(),
                machine_id: None,
                state: PersistentState::Creating,
                step: Some(step.to_owned()),
                operation_id: Some(self.operation.id.clone()),
                created_at: now,
                updated_at: now,
            })
            .await
            .map_err(|detail| failure(step, "conflict", detail))?;
        self.machine_id.clone_from(&marker.machine_id);
        self.marker = Some(marker);
        self.vmid = vmid;
        self.node = target_node;
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
            return Ok(());
        }
        let target = (self.node != template_node).then_some(self.node.as_str());
        let upid = self
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
            .map_err(|error| failure(step, "clone_failed", error.to_string()))?;
        self.wait_task(step, &upid).await
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
    async fn start(&self) -> Step<()> {
        let step = "start";
        let resources = self
            .exec
            .pve
            .client
            .list_guest_resources(self.request.clone())
            .await
            .map_err(|error| failure(step, "resources", error.to_string()))?;
        if resources.iter().any(|resource| {
            resource.vmid == Some(self.vmid) && resource.status.as_deref() == Some("running")
        }) {
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
        loop {
            self.checkpoint(step).await?;
            let agent = self
                .exec
                .pve
                .client
                .guest_agent_network(self.request.clone(), &self.node, self.vmid)
                .await;
            let ip = agent
                .online
                .then(|| {
                    agent
                        .interfaces
                        .iter()
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
            return Err(failure(
                step,
                "guest_failed",
                format!(
                    "the guest command exited {:?}: {}",
                    result.exit_code,
                    result.stderr.chars().take(300).collect::<String>()
                ),
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

    // Step 7: reachability and the host key.
    async fn host_key(&mut self) -> Step<()> {
        let step = "host_key";
        let host = self.host.clone().unwrap_or_default();
        let port = self.spec.bootstrap.port;
        let observation = loop {
            self.checkpoint(step).await?;
            let provider = self.exec.provider.clone();
            let probe_host = host.clone();
            let probe = tokio::task::spawn_blocking(move || {
                provider.probe_host_key(&probe_host, port, Duration::from_secs(5))
            })
            .await
            .map_err(|error| failure(step, "ssh_failed", error.to_string()))?;
            match probe {
                Ok(observation) => break observation,
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
        let auth = self.bootstrap_auth(step).await?;
        let spec = self.connection(self.spec.bootstrap_user(), auth);
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
            // Wait for the guest to go down and come back with the same host key.
            tokio::time::sleep(
                self.exec
                    .poll
                    .max(Duration::from_secs(10))
                    .min(self.remaining()),
            )
            .await;
            self.host_key().await?;
        }
        Ok(())
    }

    /// The public key line the machine will accept, and the stored private
    /// key when Fleet holds one.
    async fn key_material(&mut self) -> Step<(String, Option<String>)> {
        let step = "credential";
        let machine_id = self.machine_id.clone().unwrap_or_default();
        // A re-run after the key was generated and stored reuses it: the
        // endpoint's recorded auth is the proof it was.
        let endpoint = self.endpoint_id.clone().unwrap_or_default();
        let recorded = self
            .exec
            .endpoint_auths
            .get(&endpoint)
            .await
            .map_err(|detail| failure(step, "credential_failed", detail))?;
        if matches!(self.spec.credential, CredentialChoice::Generate)
            && let Some(EndpointAuth::Secret { credential }) = recorded
            && let Some(text) = self
                .exec
                .keys
                .resolve(&credential, &machine_id)
                .await
                .map_err(|detail| failure(step, "credential_failed", detail))?
        {
            let public = self.public_of(&text).await?;
            return Ok((public, Some(credential)));
        }
        match self.spec.credential.clone() {
            CredentialChoice::Generate => {
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

    // Step 10: install, verify, switch, remove, verify.
    async fn rotate_credentials(&mut self) -> Step<()> {
        let step = "credential";
        let (public, reference) = self.key_material().await?;
        let machine_id = self.machine_id.clone().unwrap_or_default();
        let endpoint = self.endpoint_id.clone().unwrap_or_default();
        let bootstrap_user = self.spec.bootstrap_user().to_owned();
        let login_user = self.spec.endpoint_user().to_owned();
        let target = (login_user != bootstrap_user).then_some(login_user.as_str());
        let windows = self.spec.guest_os == GuestOs::Windows;
        let bootstrap = self.bootstrap_auth(step).await?;
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
            // An operator-held key: Fleet cannot log in with it, so it cannot
            // verify it, and it keeps the credential it has. Nothing is removed.
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
        // works because the new key is proven.
        if target.is_some() && !windows {
            self.ssh(
                step,
                self.connection(&bootstrap_user, bootstrap),
                "set -eu\n: > \"${HOME:?}/.ssh/authorized_keys\"\n".to_owned(),
                SESSION,
            )
            .await
            .map_err(|f| failure(step, "revoke_failed", f.detail))?;
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
            return Ok(None);
        }
        let password = guest::parse_password(&out).ok_or_else(|| {
            failure(
                step,
                "rotate_failed",
                "the guest rotated the password but printed none to store",
            )
        })?;
        let name = format!("{ADMIN_PASSWORD_PREFIX}{}", uuid::Uuid::now_v7());
        let record = self
            .exec
            .secrets
            .create(&name, SecretValue::new(password.into_bytes()))
            .await
            .map_err(|error| failure(step, "store_failed", error.to_string()))?;
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
            node: String::new(),
            vmid: 0,
            machine_id: None,
            endpoint_id: None,
            host: None,
            fingerprint: None,
            credential: None,
            bootstrap_key_removed: false,
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
        self.progress(1, "cloning the image template").await;
        self.clone_guest(template_vmid, &template_node).await?;
        self.checkpoint("clone").await?;
        self.progress(2, "applying hardware and metadata").await;
        self.configure().await?;
        self.checkpoint("config").await?;
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
