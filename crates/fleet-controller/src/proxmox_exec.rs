//! The Proxmox lifecycle executor: start/stop/shutdown/reboot as durable
//! operations with Fleet-owned UPID polling (FM-602).
//!
//! The executor resolves the account through the same composition the
//! discovery surfaces use, runs the lifecycle action, and polls the task's
//! status on a fixed interval against a deadline. The polling loop is a
//! sleep between polls, never a wall-clock race — the legacy `waitForTask`
//! flake is exactly what this avoids. Terminal states are honest: task
//! `OK` succeeds, `ERROR` fails with the bounded detail, a deadline expiry
//! fails with the last observed status, and an unreadable status fails
//! naming the uncertainty — never assumed success.
//!
//! Cancellation stops the *waiting*, not the remote task: PVE keeps
//! running the action, and the operation records that honestly. Remote
//! task cancellation is a destructive-adjacent action deferred to epic
//! #12's review.

use std::sync::Arc;
use std::time::Duration;

use fleet_application::operation::{Operation, Operations};
use fleet_application::proxmox::ProxmoxCredentialStore;
use fleet_application::proxmox::tasks::ProxmoxTaskLinkPort;
use fleet_application::worker::OperationExecutor;
use fleet_provider_proxmox::{LifecycleAction, ProxmoxSource as _, TaskStatus, Upid};
use serde::Deserialize;

/// The interval between task-status polls. Fixed, not clock-derived.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// The maximum lifecycle timeout the executor accepts from a payload.
pub const MAX_LIFECYCLE_TIMEOUT: u64 = 600;

/// The payload every lifecycle kind carries: the machine-scoped shape plus
/// the account, the guest, and its node.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecyclePayload {
    /// The Proxmox account running the action.
    pub account_id: String,
    /// The guest's hosting node.
    pub node: String,
    /// The guest's VMID.
    pub vmid: u32,
    /// The deadline, in seconds. Bounded by the executor.
    pub timeout_seconds: u64,
}

/// The kind-dispatching Proxmox lifecycle executor.
#[derive(Debug)]
pub struct ProxmoxLifecycleExecutor {
    accounts: Arc<dyn fleet_application::proxmox::ProxmoxAccountPort>,
    credentials: Arc<dyn ProxmoxCredentialStore>,
    client: fleet_provider_proxmox::ProxmoxClient,
    links: Option<Arc<dyn ProxmoxTaskLinkPort>>,
}

impl ProxmoxLifecycleExecutor {
    /// Composes the executor from its parts.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn fleet_application::proxmox::ProxmoxAccountPort>,
        credentials: Arc<dyn ProxmoxCredentialStore>,
        client: fleet_provider_proxmox::ProxmoxClient,
    ) -> Self {
        Self {
            accounts,
            credentials,
            client,
            links: None,
        }
    }

    /// Records every UPID this executor starts against its operation, so
    /// the task history can link the task back (FM-609).
    #[must_use]
    pub fn with_task_links(mut self, links: Arc<dyn ProxmoxTaskLinkPort>) -> Self {
        self.links = Some(links);
        self
    }

    /// The trusted account and its resolved secret: the same explicit-trust
    /// gate the read surfaces apply, without duplicating their checks.
    async fn bound(
        &self,
        account_id: &str,
    ) -> Result<(fleet_application::proxmox::ProxmoxAccount, String), String> {
        let account = self
            .accounts
            .get(account_id)
            .await
            .map_err(|detail| format!("the account is unreadable: {detail}"))?;
        let Some(pinned) = account.fingerprint.clone() else {
            return Err(format!(
                "the account {} has no confirmed fingerprint; confirm the host's trust first",
                account.name
            ));
        };
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
        Ok((
            fleet_application::proxmox::ProxmoxAccount {
                fingerprint: Some(pinned),
                ..account
            },
            secret,
        ))
    }

    /// The request every provider call in this executor carries.
    fn request(
        &self,
        account: &fleet_application::proxmox::ProxmoxAccount,
        secret: &str,
    ) -> fleet_provider_proxmox::PveHttpRequest {
        fleet_provider_proxmox::PveHttpRequest {
            host: account.host.clone(),
            port: account.port,
            path: "/api2/json/version".to_owned(),
            pinned_fingerprint: account.fingerprint.clone(),
            credentials: Arc::new(fleet_provider_proxmox::PveCredentials {
                token_id: account.token_id.clone(),
                token: fleet_core::SensitiveString::new(secret.to_owned()),
            }),
            method: fleet_provider_proxmox::PveHttpMethod::Get,
        }
    }

    /// Runs one action and polls its task to a terminal state, with the
    /// injected sleep keeping the loop deterministic under test. The
    /// deadline starts before the mutation and bounds every poll; a
    /// cancellation observed mid-poll stops the *waiting* — the remote PVE
    /// task keeps running, and the operation records that honestly.
    async fn run_action(
        &self,
        operations: &Operations,
        params: RunParams,
    ) -> Result<TaskStatus, String> {
        let RunParams {
            operation_id,
            account_id,
            request,
            node,
            vmid,
            action,
            deadline,
            sleep,
        } = params;
        let started = std::time::Instant::now();
        let upid = self
            .client
            .guest_lifecycle(request.clone(), &node, vmid, action)
            .await
            .map_err(|error| format!("the lifecycle action failed: {error}"))?;
        record_task_link(self.links.as_ref(), &account_id, &upid, &operation_id).await;
        loop {
            // Cancellation is honored between polls: the remote task keeps
            // running, and the operation says so.
            let cancelled = operations
                .cancel_requested(&operation_id)
                .await
                .unwrap_or(false);
            if cancelled {
                return Ok(TaskStatus::Error {
                    detail: format!(
                        "cancelled while waiting; the remote task on node {} keeps running and its outcome is unknown",
                        upid.node
                    ),
                });
            }
            let status = self
                .client
                .task_status(request.clone(), &upid)
                .await
                .map_err(|error| {
                    format!(
                        "the task status failed: {error}; the task {} on node {} keeps its outcome unknown",
                        upid.raw, upid.node
                    )
                })?;
            match status {
                TaskStatus::Running => {}
                terminal => return Ok(terminal),
            }
            if started.elapsed() >= deadline {
                // The deadline expired while the task still runs: the last
                // observed status is the honest terminal, and it names the
                // uncertainty.
                return Ok(TaskStatus::Error {
                    detail: format!(
                        "the deadline expired while the task still runs; its final state is unknown (task on node {})",
                        upid.node
                    ),
                });
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    /// Completes the operation from the terminal task status.
    async fn finish(
        &self,
        operations: &Operations,
        operation_id: &str,
        action: LifecycleAction,
        status: TaskStatus,
    ) -> Result<(), String> {
        match status {
            TaskStatus::Ok => operations
                .complete(
                    operation_id,
                    "succeeded",
                    Some(
                        &serde_json::json!({
                            "action": action.id(),
                            "taskState": "ok"
                        })
                        .to_string(),
                    ),
                    None,
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string()),
            TaskStatus::Running => {
                Err("the executor returned while the task still runs".to_owned())
            }
            TaskStatus::Error { detail } => {
                let error_json =
                    serde_json::json!({ "reason": "task_failed", "detail": detail }).to_string();
                operations
                    .complete(operation_id, "failed", None, Some(&error_json))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            TaskStatus::Unknown => {
                let error_json = serde_json::json!({
                    "reason": "task_unknown",
                    "detail": "the task's status could not be read; its outcome is unknown, not assumed"
                })
                .to_string();
                operations
                    .complete(operation_id, "failed", None, Some(&error_json))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
        }
    }

    async fn lifecycle(
        &self,
        operations: &Operations,
        operation: &Operation,
        action: LifecycleAction,
    ) -> Result<(), String> {
        let payload: LifecyclePayload = payload(operation)?;
        if payload.node.is_empty() || payload.node.len() > 128 {
            return Err("the node must be 1..=128 characters".to_owned());
        }
        let (account, secret) = self.bound(&payload.account_id).await?;
        let request = self.request(&account, &secret);
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!("{} on qemu/{}", action.id(), payload.vmid)),
            )
            .await
            .map_err(|error| error.to_string())?;
        let deadline = Duration::from_secs(payload.timeout_seconds.min(MAX_LIFECYCLE_TIMEOUT));
        let status = self
            .run_action(
                operations,
                RunParams {
                    operation_id: operation.id.clone(),
                    account_id: payload.account_id.clone(),
                    request,
                    node: payload.node,
                    vmid: payload.vmid,
                    action,
                    deadline,
                    sleep: Arc::new(|duration| {
                        Box::pin(tokio::time::sleep(duration))
                            as futures_util::future::BoxFuture<'static, ()>
                    }),
                },
            )
            .await?;
        self.finish(operations, &operation.id, action, status).await
    }
}

#[async_trait::async_trait]
impl OperationExecutor for ProxmoxLifecycleExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let action = match operation.kind.as_str() {
            "proxmox.guest.start" => LifecycleAction::Start,
            "proxmox.guest.stop" => LifecycleAction::Stop,
            "proxmox.guest.shutdown" => LifecycleAction::Shutdown,
            "proxmox.guest.reboot" => LifecycleAction::Reboot,
            _ => return Err("not a Proxmox lifecycle kind".to_owned()),
        };
        self.lifecycle(operations, operation, action).await
    }
}

/// The parameters of one lifecycle run, grouped so the poll loop's
/// signature stays readable.
struct RunParams {
    /// The operation whose cancellation is observed between polls.
    operation_id: String,
    /// The account the action runs through, for the task link.
    account_id: String,
    /// The provider request carrying the account and pin.
    request: fleet_provider_proxmox::PveHttpRequest,
    /// The guest's hosting node.
    node: String,
    /// The guest's VMID.
    vmid: u32,
    /// The action to run.
    action: LifecycleAction,
    /// The polling deadline.
    deadline: Duration,
    /// The injected sleep, for deterministic tests.
    sleep: Arc<dyn Fn(Duration) -> futures_util::future::BoxFuture<'static, ()> + Send + Sync>,
}

/// The payload the destructive kinds carry: the lifecycle fields plus the
/// reviewed action parameters.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DestructivePayload {
    /// The Proxmox account running the action.
    pub account_id: String,
    /// The guest's hosting node.
    pub node: String,
    /// The guest's VMID.
    pub vmid: u32,
    /// The deadline, in seconds. Bounded by the executor.
    pub timeout_seconds: u64,
    /// The reviewed action parameters.
    #[serde(default)]
    pub params: serde_json::Value,
}

/// Decodes and validates an operation's payload.
fn payload<T: serde::de::DeserializeOwned>(operation: &Operation) -> Result<T, String> {
    serde_json::from_str(
        operation
            .payload_json
            .as_deref()
            .ok_or("the operation carries no payload")?,
    )
    .map_err(|error| format!("the payload is not a valid lifecycle record: {error}"))
}

/// The kind-dispatching Proxmox executor: destructive kinds route to their
/// own executor, lifecycle kinds to the lifecycle executor, and everything
/// else falls through to the next executor in the chain.
#[derive(Debug)]
pub struct ProxmoxDispatch {
    fallback: Arc<dyn OperationExecutor>,
    lifecycle: Arc<ProxmoxLifecycleExecutor>,
    destructive: Arc<ProxmoxDestructiveExecutor>,
}

impl ProxmoxDispatch {
    /// Composes the dispatch from its parts.
    #[must_use]
    pub fn new(
        fallback: Arc<dyn OperationExecutor>,
        lifecycle: Arc<ProxmoxLifecycleExecutor>,
        destructive: Arc<ProxmoxDestructiveExecutor>,
    ) -> Self {
        Self {
            fallback,
            lifecycle,
            destructive,
        }
    }
}

#[async_trait::async_trait]
impl OperationExecutor for ProxmoxDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        if DESTRUCTIVE_KINDS.contains(&operation.kind.as_str()) {
            self.destructive.execute(operations, operation).await
        } else if operation.kind.starts_with("proxmox.guest.") {
            self.lifecycle.execute(operations, operation).await
        } else {
            self.fallback.execute(operations, operation).await
        }
    }
}

/// The destructive-adjacent kinds; they route to their own executor.
pub const DESTRUCTIVE_KINDS: [&str; 7] = [
    "proxmox.guest.snapshot",
    "proxmox.guest.snapshot-revert",
    "proxmox.guest.snapshot-delete",
    "proxmox.guest.destroy",
    "proxmox.guest.clone",
    "proxmox.guest.template",
    "proxmox.task-cancel",
];

/// The destructive-adjacent executor: snapshot, revert, snapshot-delete,
/// clone, template conversion, guest destruction, and remote task cancellation. Every kind
/// arrived through the reviewed dedicated endpoint (the generic surface
/// refuses them); the executor re-applies the trust gate and classifies
/// idempotency before touching anything.
#[derive(Debug)]
pub struct ProxmoxDestructiveExecutor {
    accounts: Arc<dyn fleet_application::proxmox::ProxmoxAccountPort>,
    credentials: Arc<dyn fleet_application::proxmox::ProxmoxCredentialStore>,
    client: fleet_provider_proxmox::ProxmoxClient,
    links: Option<Arc<dyn ProxmoxTaskLinkPort>>,
    artifacts: Option<Arc<dyn fleet_application::lab::ImageArtifactPort>>,
}

impl ProxmoxDestructiveExecutor {
    /// Composes the executor from its parts.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn fleet_application::proxmox::ProxmoxAccountPort>,
        credentials: Arc<dyn fleet_application::proxmox::ProxmoxCredentialStore>,
        client: fleet_provider_proxmox::ProxmoxClient,
    ) -> Self {
        Self {
            accounts,
            credentials,
            client,
            links: None,
            artifacts: None,
        }
    }

    /// Records every UPID this executor starts against its operation, so
    /// the task history can link the task back (FM-609).
    #[must_use]
    pub fn with_task_links(mut self, links: Arc<dyn ProxmoxTaskLinkPort>) -> Self {
        self.links = Some(links);
        self
    }
    /// Supplies the promoted-image guard. Destroy fails closed without it.
    #[must_use]
    pub fn with_image_artifacts(
        mut self,
        artifacts: Arc<dyn fleet_application::lab::ImageArtifactPort>,
    ) -> Self {
        self.artifacts = Some(artifacts);
        self
    }
}

#[async_trait::async_trait]
impl OperationExecutor for ProxmoxDestructiveExecutor {
    #[allow(clippy::too_many_lines)]
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: DestructivePayload = payload(operation)?;
        let (account, secret) = self.bound(&payload.account_id).await?;
        let request = self.request(&account, &secret);
        let deadline = Duration::from_secs(payload.timeout_seconds.min(MAX_LIFECYCLE_TIMEOUT));
        let kind = operation.kind.as_str();
        let outcome: Result<(), String> = match kind {
            "proxmox.guest.destroy" => {
                let started = std::time::Instant::now();
                tokio::time::timeout(
                    deadline,
                    self.prepare_destroy(operations, operation, &payload, &request),
                )
                .await
                .map_err(|_| {
                    "the destroy stop/guard deadline expired; no delete was submitted".to_owned()
                })??;
                let remaining = deadline
                    .checked_sub(started.elapsed())
                    .ok_or("the destroy deadline expired")?;
                let node = payload.node.clone();
                let vmid = payload.vmid;
                let purge = payload
                    .params
                    .get("purge")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                self.run_to_terminal(
                    operations,
                    &operation.id,
                    &payload.account_id,
                    &request,
                    &payload.node,
                    vmid,
                    remaining,
                    move |client, request| {
                        Box::pin(
                            async move { client.guest_destroy(request, &node, vmid, purge).await },
                        )
                    },
                )
                .await
            }
            "proxmox.guest.snapshot" => {
                let name = payload
                    .params
                    .get("snapshot")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("the reviewed parameters carry no snapshot name")?;
                validate_snapshot_name(name)?;
                let description = payload
                    .params
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let include_ram = payload
                    .params
                    .get("includeRam")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                // Idempotency classification: an existing snapshot with the
                // same name succeeds without an operation; a differing
                // description is a conflict, not a silent overwrite.
                let existing = self
                    .client
                    .guest_snapshots(request.clone(), &payload.node, payload.vmid)
                    .await
                    .map_err(|error| format!("the snapshot listing failed: {error}"))?;
                if let Some(snapshot) = existing.iter().find(|snapshot| snapshot.name == name) {
                    if snapshot.description == description {
                        return self
                            .finish_noop(
                                operations,
                                &operation.id,
                                format!(
                                    "snapshot {name} already exists with the reviewed description"
                                ),
                            )
                            .await;
                    }
                    return complete_failure(
                        operations,
                        &operation.id,
                        "conflict",
                        &format!(
                            "a snapshot named {name} already exists with a different description; pick another name"
                        ),
                    )
                    .await;
                }
                self.run_to_terminal(
                    operations,
                    &operation.id,
                    &payload.account_id,
                    &request,
                    &payload.node,
                    payload.vmid,
                    deadline,
                    {
                        let node = payload.node.clone();
                        let vmid = payload.vmid;
                        let name = name.to_owned();
                        let description = description.to_owned();
                        move |client, request| {
                            Box::pin(async move {
                                client
                                    .guest_snapshot(
                                        request,
                                        &node,
                                        vmid,
                                        &name,
                                        &description,
                                        include_ram,
                                    )
                                    .await
                            })
                                as futures_util::future::BoxFuture<'static, _>
                        }
                    },
                )
                .await
            }
            "proxmox.guest.snapshot-revert" => {
                let name = payload
                    .params
                    .get("snapshot")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("the reviewed parameters carry no snapshot name")?;
                validate_snapshot_name(name)?;
                self.run_to_terminal(
                    operations,
                    &operation.id,
                    &payload.account_id,
                    &request,
                    &payload.node,
                    payload.vmid,
                    deadline,
                    {
                        let node = payload.node.clone();
                        let vmid = payload.vmid;
                        let name = name.to_owned();
                        move |client, request| {
                            Box::pin(async move {
                                client
                                    .guest_snapshot_rollback(request, &node, vmid, &name)
                                    .await
                            })
                                as futures_util::future::BoxFuture<'static, _>
                        }
                    },
                )
                .await
            }
            "proxmox.guest.snapshot-delete" => {
                let name = payload
                    .params
                    .get("snapshot")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("the reviewed parameters carry no snapshot name")?;
                validate_snapshot_name(name)?;
                self.run_to_terminal(
                    operations,
                    &operation.id,
                    &payload.account_id,
                    &request,
                    &payload.node,
                    payload.vmid,
                    deadline,
                    {
                        let node = payload.node.clone();
                        let vmid = payload.vmid;
                        let name = name.to_owned();
                        move |client, request| {
                            Box::pin(async move {
                                client
                                    .guest_snapshot_delete(request, &node, vmid, &name)
                                    .await
                                    .map(|()| None)
                            })
                                as futures_util::future::BoxFuture<'static, _>
                        }
                    },
                )
                .await
            }
            "proxmox.guest.clone" => {
                let new_id = payload
                    .params
                    .get("newId")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or("the reviewed parameters carry no new VMID")?;
                let new_id = u32::try_from(new_id)
                    .map_err(|_| "the new VMID exceeds the u32 bound".to_owned())?;
                let name = payload
                    .params
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("the reviewed parameters carry no target name")?;
                let full_copy = payload
                    .params
                    .get("fullCopy")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                // Idempotency classification: a target VMID that already
                // exists is a conflict (never a duplicate); the cluster
                // resources are the truth.
                let resources = self
                    .client
                    .list_guest_resources(request.clone())
                    .await
                    .map_err(|error| format!("the resource listing failed: {error}"))?;
                if resources
                    .iter()
                    .any(|resource| resource.vmid == Some(new_id))
                {
                    return complete_failure(
                        operations,
                        &operation.id,
                        "conflict",
                        &format!("a guest with VMID {new_id} already exists; pick another target"),
                    )
                    .await;
                }
                self.run_to_terminal(
                    operations,
                    &operation.id,
                    &payload.account_id,
                    &request,
                    &payload.node,
                    payload.vmid,
                    deadline,
                    {
                        let node = payload.node.clone();
                        let vmid = payload.vmid;
                        let name = name.to_owned();
                        move |client, request| {
                            Box::pin(async move {
                                client
                                    .guest_clone(request, &node, vmid, new_id, &name, full_copy)
                                    .await
                                    .map(Some)
                            })
                                as futures_util::future::BoxFuture<'static, _>
                        }
                    },
                )
                .await
            }
            "proxmox.guest.template" => {
                // Idempotency classification: converting a template
                // succeeds without an operation.
                let resources = self
                    .client
                    .list_guest_resources(request.clone())
                    .await
                    .map_err(|error| format!("the resource listing failed: {error}"))?;
                let resource = resources
                    .iter()
                    .find(|resource| resource.vmid == Some(payload.vmid))
                    .ok_or_else(|| format!("guest qemu/{} not found", payload.vmid))?;
                if resource.kind == "qemu-template" {
                    return self
                        .finish_noop(operations, &operation.id, "already a template".to_owned())
                        .await;
                }
                self.run_to_terminal(
                    operations,
                    &operation.id,
                    &payload.account_id,
                    &request,
                    &payload.node,
                    payload.vmid,
                    deadline,
                    {
                        let node = payload.node.clone();
                        let vmid = payload.vmid;
                        move |client, request| {
                            Box::pin(async move {
                                client.guest_convert_template(request, &node, vmid).await
                            })
                                as futures_util::future::BoxFuture<'static, _>
                        }
                    },
                )
                .await
            }
            "proxmox.task-cancel" => {
                let raw = payload
                    .params
                    .get("upid")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("the reviewed parameters carry no UPID")?;
                let upid = Upid::parse(raw)?;
                // The reviewed UPID must belong to the reviewed guest: a
                // task on another node or for another VMID is refused, so
                // the review scope is the cancellation scope.
                if upid.node != payload.node {
                    return complete_failure(
                        operations,
                        &operation.id,
                        "conflict",
                        &format!(
                            "the reviewed task runs on node {}, not the reviewed node {}",
                            upid.node, payload.node
                        ),
                    )
                    .await;
                }
                if upid.target != payload.vmid.to_string() {
                    return complete_failure(
                        operations,
                        &operation.id,
                        "conflict",
                        &format!(
                            "the reviewed task targets {}, not the reviewed guest qemu/{}",
                            upid.target, payload.vmid
                        ),
                    )
                    .await;
                }
                self.client
                    .stop_task(request.clone(), &upid)
                    .await
                    .map_err(|error| format!("the task cancellation failed: {error}"))?;
                // The outcome is read back honestly: the task may have
                // finished between the stop and the status read.
                let status = self
                    .client
                    .task_status(request.clone(), &upid)
                    .await
                    .unwrap_or(TaskStatus::Unknown);
                self.finish(operations, &operation.id, status).await
            }
            other => return Err(format!("not a Proxmox destructive kind: {other}")),
        };
        outcome?;
        Ok(())
    }
}

impl ProxmoxDestructiveExecutor {
    // Stop is a prerequisite task, never the terminal outcome of destroy.
    async fn prepare_destroy(
        &self,
        operations: &Operations,
        operation: &Operation,
        payload: &DestructivePayload,
        request: &fleet_provider_proxmox::PveHttpRequest,
    ) -> Result<(), String> {
        let artifacts = self
            .artifacts
            .as_ref()
            .ok_or("the destroy image guard is not configured")?;
        let image_vmids = artifacts
            .promoted_template_vmids()
            .await
            .map_err(|detail| format!("the image artifacts are unreadable: {detail}"))?;
        let resources = self
            .client
            .list_guest_resources(request.clone())
            .await
            .map_err(|error| format!("the resource listing failed: {error}"))?;
        let resource = resources
            .iter()
            .find(|resource| resource.vmid == Some(payload.vmid));
        fleet_application::lab::guard_destroy_target(
            payload.vmid,
            resource.is_some_and(|resource| resource.kind == "qemu-template"),
            &image_vmids,
        )?;
        if let Some(resource) = resource {
            if resource.kind != "qemu" || resource.node.as_deref() != Some(payload.node.as_str()) {
                return Err(
                    "the destroy target is not a QEMU guest on the reviewed node".to_owned(),
                );
            }
            if resource.status.as_deref() == Some("running") {
                if operations
                    .cancel_requested(&operation.id)
                    .await
                    .map_err(|error| error.to_string())?
                {
                    return Err("destroy cancelled before stop".to_owned());
                }
                let upid = self
                    .client
                    .guest_lifecycle(
                        request.clone(),
                        &payload.node,
                        payload.vmid,
                        LifecycleAction::Stop,
                    )
                    .await
                    .map_err(|error| format!("the pre-destroy stop failed: {error}"))?;
                record_task_link(
                    self.links.as_ref(),
                    &payload.account_id,
                    &upid,
                    &operation.id,
                )
                .await;
                loop {
                    if operations
                        .cancel_requested(&operation.id)
                        .await
                        .map_err(|error| error.to_string())?
                    {
                        return Err(
                            "destroy cancelled while waiting for stop; no delete was submitted"
                                .to_owned(),
                        );
                    }
                    match self
                        .client
                        .task_status(request.clone(), &upid)
                        .await
                        .map_err(|error| error.to_string())?
                    {
                        TaskStatus::Ok => break,
                        TaskStatus::Running => tokio::time::sleep(POLL_INTERVAL).await,
                        status => {
                            return Err(format!(
                                "the pre-destroy stop did not succeed: {status:?}"
                            ));
                        }
                    }
                }
            }
        }
        if operations
            .cancel_requested(&operation.id)
            .await
            .map_err(|error| error.to_string())?
        {
            return Err("destroy cancelled before delete".to_owned());
        }
        // Recheck cluster template state and promotion after waiting.
        let image_vmids = artifacts
            .promoted_template_vmids()
            .await
            .map_err(|detail| format!("the image artifacts are unreadable: {detail}"))?;
        let resources = self
            .client
            .list_guest_resources(request.clone())
            .await
            .map_err(|error| format!("the post-stop resource listing failed: {error}"))?;
        let is_template = resources.iter().any(|resource| {
            resource.vmid == Some(payload.vmid) && resource.kind == "qemu-template"
        });
        if operations
            .cancel_requested(&operation.id)
            .await
            .map_err(|error| error.to_string())?
        {
            return Err("destroy cancelled before delete".to_owned());
        }
        fleet_application::lab::guard_destroy_target(payload.vmid, is_template, &image_vmids)
    }

    /// The trusted account and its resolved secret: the same explicit-trust
    /// gate the other surfaces apply.
    async fn bound(
        &self,
        account_id: &str,
    ) -> Result<(fleet_application::proxmox::ProxmoxAccount, String), String> {
        let account = self
            .accounts
            .get(account_id)
            .await
            .map_err(|detail| format!("the account is unreadable: {detail}"))?;
        let Some(pinned) = account.fingerprint.clone() else {
            return Err(format!(
                "the account {} has no confirmed fingerprint; confirm the host's trust first",
                account.name
            ));
        };
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
        Ok((
            fleet_application::proxmox::ProxmoxAccount {
                fingerprint: Some(pinned),
                ..account
            },
            secret,
        ))
    }

    /// The request every provider call in this executor carries.
    fn request(
        &self,
        account: &fleet_application::proxmox::ProxmoxAccount,
        secret: &str,
    ) -> fleet_provider_proxmox::PveHttpRequest {
        fleet_provider_proxmox::PveHttpRequest {
            host: account.host.clone(),
            port: account.port,
            path: "/api2/json/version".to_owned(),
            pinned_fingerprint: account.fingerprint.clone(),
            credentials: Arc::new(fleet_provider_proxmox::PveCredentials {
                token_id: account.token_id.clone(),
                token: fleet_core::SensitiveString::new(secret.to_owned()),
            }),
            method: fleet_provider_proxmox::PveHttpMethod::Get,
        }
    }

    /// Completes the operation as a no-op success with the reason as the
    /// result: an idempotent hit is a success, not an error.
    async fn finish_noop(
        &self,
        operations: &Operations,
        operation_id: &str,
        note: String,
    ) -> Result<(), String> {
        operations
            .complete(
                operation_id,
                "succeeded",
                Some(&serde_json::json!({ "noop": note }).to_string()),
                None,
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Completes the operation from the terminal task status.
    async fn finish(
        &self,
        operations: &Operations,
        operation_id: &str,
        status: TaskStatus,
    ) -> Result<(), String> {
        match status {
            TaskStatus::Ok => operations
                .complete(
                    operation_id,
                    "succeeded",
                    Some(&serde_json::json!({ "taskState": "ok" }).to_string()),
                    None,
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string()),
            TaskStatus::Running => {
                Err("the executor returned while the task still runs".to_owned())
            }
            TaskStatus::Error { detail } => {
                complete_failure(operations, operation_id, "task_failed", &detail).await
            }
            TaskStatus::Unknown => {
                complete_failure(
                    operations,
                    operation_id,
                    "task_unknown",
                    "the task's status could not be read; its outcome is unknown, not assumed",
                )
                .await
            }
        }
    }

    /// Runs one mutating call and polls its task to a terminal state; a
    /// synchronous outcome completes immediately. Compensation is by
    /// record: the failure detail names what ran so the operator can
    /// reconcile, and nothing is deleted on failure.
    #[allow(clippy::too_many_arguments)]
    async fn run_to_terminal(
        &self,
        operations: &Operations,
        operation_id: &str,
        account_id: &str,
        request: &fleet_provider_proxmox::PveHttpRequest,
        node: &str,
        vmid: u32,
        deadline: Duration,
        call: impl FnOnce(
            fleet_provider_proxmox::ProxmoxClient,
            fleet_provider_proxmox::PveHttpRequest,
        ) -> futures_util::future::BoxFuture<
            'static,
            Result<Option<fleet_provider_proxmox::Upid>, fleet_provider_proxmox::PveApiError>,
        >,
    ) -> Result<(), String> {
        operations
            .record_progress(
                operation_id,
                Some(0),
                Some(1),
                Some(&format!("{node}/qemu/{vmid}")),
            )
            .await
            .map_err(|error| error.to_string())?;
        let upid = call(self.client.clone(), request.clone())
            .await
            .map_err(|error| format!("the operation failed: {error}"))?;
        let Some(upid) = upid else {
            // Synchronous outcome: read the guest state as the
            // verification, not an assumption.
            return self.finish(operations, operation_id, TaskStatus::Ok).await;
        };
        record_task_link(self.links.as_ref(), account_id, &upid, operation_id).await;
        let started = std::time::Instant::now();
        loop {
            let cancelled = operations
                .cancel_requested(operation_id)
                .await
                .unwrap_or(false);
            if cancelled {
                return complete_failure(
                    operations,
                    operation_id,
                    "cancelled",
                    &format!(
                        "cancelled while waiting; the remote task {} on node {} keeps running and its outcome is unknown",
                        upid.raw, upid.node
                    ),
                )
                .await;
            }
            let status = self
                .client
                .task_status(request.clone(), &upid)
                .await
                .map_err(|error| {
                    format!(
                        "the task status failed: {error}; the task {} on node {} keeps its outcome unknown",
                        upid.raw, upid.node
                    )
                })?;
            match status {
                TaskStatus::Running => {}
                terminal => return self.finish(operations, operation_id, terminal).await,
            }
            if started.elapsed() >= deadline {
                return complete_failure(
                    operations,
                    operation_id,
                    "deadline_expired",
                    &format!(
                        "the deadline expired while the task still runs; its final state is unknown (task {} on node {})",
                        upid.raw, upid.node
                    ),
                )
                .await;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

/// Snapshot names are PVE identifiers: bounded, no path material.
fn validate_snapshot_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(format!(
            "the snapshot name must be 1..=64 characters of [a-zA-Z0-9_-], not {name:?}"
        ));
    }
    Ok(())
}

/// Records which operation started a PVE task (FM-609). Best effort on
/// purpose: by now the remote task is already running, and failing the
/// operation over a lost link would misreport the remote state. A lost
/// link only means the task history shows the task without its
/// `fleetOperationId`. The log line carries identifiers, never credentials.
async fn record_task_link(
    links: Option<&Arc<dyn ProxmoxTaskLinkPort>>,
    account_id: &str,
    upid: &Upid,
    operation_id: &str,
) {
    let Some(links) = links else {
        return;
    };
    if let Err(error) = links.record(account_id, &upid.raw, operation_id).await {
        eprintln!(
            "proxmox: could not link task {} to operation {operation_id}: {error}",
            upid.raw
        );
    }
}

/// Completes an operation as a failure with a redacted detail.
async fn complete_failure(
    operations: &Operations,
    operation_id: &str,
    reason: &str,
    detail: &str,
) -> Result<(), String> {
    let error_json = serde_json::json!({ "reason": reason, "detail": detail }).to_string();
    operations
        .complete(operation_id, "failed", None, Some(&error_json))
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// The Lab provisioning executor (FM-710): drives the provisioning saga's
/// external steps for one record — clone from the pinned image version,
/// start, and verify through the guest agent — updating the record's
/// state at each transition. The record carries the external IDs, so a
/// re-run resumes instead of creating a second VM.
#[derive(Debug)]
pub struct ProvisionExecutor {
    accounts: Arc<dyn fleet_application::proxmox::ProxmoxAccountPort>,
    credentials: Arc<dyn fleet_application::proxmox::ProxmoxCredentialStore>,
    provisions: Arc<dyn fleet_application::lab::ProvisionPort>,
    leases: Arc<dyn fleet_application::lab::LeasePort>,
    templates: Arc<dyn fleet_application::lab::LabTemplatePort>,
    artifacts: Arc<dyn fleet_application::lab::ImageArtifactPort>,
    client: fleet_provider_proxmox::ProxmoxClient,
    links: Option<Arc<dyn ProxmoxTaskLinkPort>>,
}

/// A classified provisioning failure: the operation completes as failed
/// with this reason and detail instead of erroring.
struct Refusal {
    reason: &'static str,
    detail: String,
}

impl Refusal {
    fn new(reason: &'static str, detail: String) -> Self {
        Self { reason, detail }
    }
}

impl ProvisionExecutor {
    /// Composes the executor from its parts.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn fleet_application::proxmox::ProxmoxAccountPort>,
        credentials: Arc<dyn fleet_application::proxmox::ProxmoxCredentialStore>,
        provisions: Arc<dyn fleet_application::lab::ProvisionPort>,
        leases: Arc<dyn fleet_application::lab::LeasePort>,
        templates: Arc<dyn fleet_application::lab::LabTemplatePort>,
        artifacts: Arc<dyn fleet_application::lab::ImageArtifactPort>,
        client: fleet_provider_proxmox::ProxmoxClient,
    ) -> Self {
        Self {
            accounts,
            credentials,
            provisions,
            leases,
            templates,
            artifacts,
            client,
            links: None,
        }
    }

    /// Records the clone and start UPIDs this executor obtains against its
    /// operation, so the task history can link them back (FM-609).
    #[must_use]
    pub fn with_task_links(mut self, links: Arc<dyn ProxmoxTaskLinkPort>) -> Self {
        self.links = Some(links);
        self
    }

    async fn bound(
        &self,
        account_id: &str,
    ) -> Result<(fleet_application::proxmox::ProxmoxAccount, String), String> {
        let account = self
            .accounts
            .get(account_id)
            .await
            .map_err(|detail| format!("the account is unreadable: {detail}"))?;
        let Some(pinned) = account.fingerprint.clone() else {
            return Err(format!(
                "the account {} has no confirmed fingerprint; confirm the host's trust first",
                account.name
            ));
        };
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
        Ok((
            fleet_application::proxmox::ProxmoxAccount {
                fingerprint: Some(pinned),
                ..account
            },
            secret,
        ))
    }
}

/// The pinned request every provider call of the Lab executor carries. The
/// account's host is the API endpoint; it is never a PVE node name.
fn pve_request(
    account: &fleet_application::proxmox::ProxmoxAccount,
    secret: String,
) -> fleet_provider_proxmox::PveHttpRequest {
    fleet_provider_proxmox::PveHttpRequest {
        host: account.host.clone(),
        port: account.port,
        path: "/api2/json/version".to_owned(),
        pinned_fingerprint: account.fingerprint.clone(),
        credentials: Arc::new(fleet_provider_proxmox::PveCredentials {
            token_id: account.token_id.clone(),
            token: fleet_core::SensitiveString::new(secret),
        }),
        method: fleet_provider_proxmox::PveHttpMethod::Get,
    }
}

impl ProvisionExecutor {
    /// The Lab cleanup guard over the cluster's live truth (issue #220):
    /// refuses a VMID that `/cluster/resources` reports as a template, or
    /// that matches a promoted image's recorded build artifact. Lab cleanup
    /// (`destroy`, FM-711) must pass this before it deletes a guest; the
    /// provision executor also applies it before it resumes a record.
    ///
    /// # Errors
    ///
    /// The refusal reason, or why the guard could not decide (an
    /// unreadable account, artifact store, or resource listing). An
    /// undecided guard is a refusal too.
    pub async fn guard_destroy_target(&self, account_id: &str, vmid: u32) -> Result<(), String> {
        let (account, secret) = self.bound(account_id).await?;
        self.destroy_guard(pve_request(&account, secret), vmid)
            .await?
            .0
    }

    /// The guard's decision over a fresh resource listing, which it also
    /// returns: the outer error is an undecided guard, the inner one a
    /// refusal.
    async fn destroy_guard(
        &self,
        request: fleet_provider_proxmox::PveHttpRequest,
        vmid: u32,
    ) -> Result<(Result<(), String>, Vec<fleet_provider_proxmox::PveResource>), String> {
        let image_vmids = self
            .artifacts
            .promoted_template_vmids()
            .await
            .map_err(|detail| format!("the image artifacts are unreadable: {detail}"))?;
        let resources = self
            .client
            .list_guest_resources(request)
            .await
            .map_err(|error| format!("the resource listing failed: {error}"))?;
        let is_template = resources
            .iter()
            .any(|resource| resource.vmid == Some(vmid) && resource.kind == "qemu-template");
        Ok((
            fleet_application::lab::guard_destroy_target(vmid, is_template, &image_vmids),
            resources,
        ))
    }

    /// Before a resumed record's guest is started: the recorded VMID must
    /// pass the cleanup guard (the pre-#220 source fallback could record
    /// the template), and the live guest there must still be this
    /// provision's clone, by its Fleet name. Returns the guest's live
    /// node.
    async fn verify_recorded_guest(
        &self,
        request: fleet_provider_proxmox::PveHttpRequest,
        record_id: &str,
        node: &str,
        vmid: u32,
    ) -> Result<Result<String, Refusal>, String> {
        let (decision, resources) = self.destroy_guard(request, vmid).await?;
        if let Err(refusal) = decision {
            return Ok(Err(Refusal::new(
                "protected_target",
                format!(
                    "the provision record names {node}/qemu/{vmid}, which Lab must not use as its guest: {refusal}"
                ),
            )));
        }
        let name = format!("fm-lab-{record_id}");
        let Some(guest) = resources
            .iter()
            .find(|resource| resource.vmid == Some(vmid))
        else {
            return Ok(Err(Refusal::new(
                "target_missing",
                format!(
                    "the recorded guest qemu/{vmid} is not in the cluster's resources; it was removed, or the token lacks VM.Audit on /vms/{vmid}"
                ),
            )));
        };
        if guest.kind == "qemu" && guest.name.as_deref() == Some(name.as_str()) {
            return Ok(Ok(guest.node.clone().unwrap_or_else(|| node.to_owned())));
        }
        // PVE names the clone only when the clone finishes, and reports an
        // unnamed guest as `VM <vmid>` (qemu-server `vmstatus`), not as a
        // missing name.
        let placeholder = format!("VM {vmid}");
        if guest.kind == "qemu" && guest.name.as_deref().is_none_or(|name| name == placeholder) {
            return Ok(Err(Refusal::new(
                "target_unverified",
                format!(
                    "qemu/{vmid} carries no name yet, so it cannot be verified as this provision's clone (the clone may still be running); retry once its task finishes"
                ),
            )));
        }
        Ok(Err(Refusal::new(
            "conflict",
            format!(
                "the recorded VMID {vmid} now holds a {} named {}, not this provision's clone",
                guest.kind,
                guest.name.as_deref().unwrap_or("nothing")
            ),
        )))
    }

    /// Clones the pinned image's template into a VMID reserved on the
    /// record before the clone call, and records the clone's UPID. The
    /// outer error is an infrastructure failure; the inner one a
    /// classified refusal the operation completes with.
    async fn clone_into_reserved_target(
        &self,
        record: &fleet_application::lab::ProvisionRecord,
        image_version_id: &str,
        account_id: &str,
        operation_id: &str,
        request: &fleet_provider_proxmox::PveHttpRequest,
    ) -> Result<Result<(String, u32), Refusal>, String> {
        // The clone source: the template VMID the pinned image version's
        // build recorded. No artifact is an honest failure: the pin was
        // validated as promoted, and promotion requires one.
        let Some(source_vmid) = self
            .artifacts
            .template_vmid(image_version_id)
            .await
            .map_err(|detail| format!("the image artifact is unreadable: {detail}"))?
        else {
            return Ok(Err(Refusal::new(
                "artifact_missing",
                format!(
                    "the pinned image version {image_version_id} has no recorded build artifact; build and promote it before provisioning"
                ),
            )));
        };
        // The template's node comes from the cluster's resources: the
        // clone runs on the node that holds the template.
        let resources = self
            .client
            .list_guest_resources(request.clone())
            .await
            .map_err(|error| format!("the resource listing failed: {error}"))?;
        let Some(template) = resources
            .iter()
            .find(|resource| resource.vmid == Some(source_vmid))
        else {
            return Ok(Err(Refusal::new(
                "template_missing",
                format!(
                    "the image template qemu/{source_vmid} is not in the cluster's resources; it was removed, or the token lacks VM.Audit on /vms/{source_vmid}"
                ),
            )));
        };
        if template.kind != "qemu-template" {
            return Ok(Err(Refusal::new(
                "template_missing",
                format!(
                    "the image artifact qemu/{source_vmid} is a {}, not a template",
                    template.kind
                ),
            )));
        }
        let Some(node) = template.node.clone() else {
            return Ok(Err(Refusal::new(
                "template_missing",
                format!("the cluster reports no node for the image template qemu/{source_vmid}"),
            )));
        };

        // The target: reserved and recorded before the clone call. A
        // record that already holds a reservation resumes with it.
        let mut reserved = if record.vmid.is_some() {
            record.clone()
        } else {
            let candidate = self
                .client
                .next_vmid(request.clone())
                .await
                .map_err(|error| format!("the next free VMID is unreadable: {error}"))?;
            // A promoted image's recorded template VMID is never reused as
            // a lease guest, even after the template is gone: the cleanup
            // guard would refuse to destroy it.
            let protected = self
                .artifacts
                .promoted_template_vmids()
                .await
                .map_err(|detail| format!("the image artifacts are unreadable: {detail}"))?;
            if protected.contains(&candidate) {
                return Ok(Err(Refusal::new(
                    "conflict",
                    format!(
                        "the next free VMID {candidate} is a promoted image's recorded template, which no longer exists in the cluster; rebuild or demote that image, or move the next-id range"
                    ),
                )));
            }
            match self
                .provisions
                .reserve_clone_target(&record.id, &node, candidate)
                .await
                .map_err(|detail| format!("the clone target reservation failed: {detail}"))?
            {
                fleet_application::lab::CloneTargetReservation::Reserved(reserved) => reserved,
                fleet_application::lab::CloneTargetReservation::HeldBy { record_id } => {
                    return Ok(Err(Refusal::new(
                        "conflict",
                        format!(
                            "VMID {candidate} is reserved by provision {record_id}, whose clone has not landed yet; retry once it has"
                        ),
                    )));
                }
            }
        };
        let target = reserved
            .vmid
            .ok_or("the clone target reservation carries no VMID")?;
        if reserved.node.as_deref() != Some(node.as_str()) {
            // The template moved since the reservation: the clone lands
            // on the template's node, and the record says so first.
            reserved.node = Some(node.clone());
            self.provisions
                .update(&reserved)
                .await
                .map_err(|detail| format!("the record update failed: {detail}"))?;
        }

        // FM-603's target-conflict classification against the cluster's
        // truth: our own clone (by its Fleet name) that landed before its
        // UPID was recorded is adopted; anything else at the target is a
        // conflict, never overwritten. The reservation is kept.
        let name = format!("fm-lab-{}", record.id);
        if let Some(existing) = resources
            .iter()
            .find(|resource| resource.vmid == Some(target))
        {
            if existing.kind == "qemu" && existing.name.as_deref() == Some(name.as_str()) {
                let landed = existing.node.clone().unwrap_or(node);
                return Ok(Ok((landed, target)));
            }
            return Ok(Err(Refusal::new(
                "conflict",
                format!(
                    "a guest with the reserved VMID {target} already exists ({} named {}); it is not this provision's clone",
                    existing.kind,
                    existing.name.as_deref().unwrap_or("nothing")
                ),
            )));
        }

        let upid = self
            .client
            .guest_clone(request.clone(), &node, source_vmid, target, &name, true)
            .await
            .map_err(|error| format!("the clone failed: {error}"))?;
        record_task_link(self.links.as_ref(), account_id, &upid, operation_id).await;
        // PVE forks `qmclone` with the *source* VMID as the task id, on the
        // source's node. Anything else is not the clone Fleet requested;
        // the recorded VMID stays the reserved target either way.
        if upid.task_type != "qmclone"
            || upid.node != node
            || upid.target != source_vmid.to_string()
        {
            return Ok(Err(Refusal::new(
                "task_mismatch",
                format!(
                    "the clone answered task {} for {}/{} instead of qmclone for {node}/{source_vmid}; the reserved target {target} must be verified",
                    upid.task_type, upid.node, upid.target
                ),
            )));
        }
        reserved.clone_upid = Some(upid.raw.clone());
        self.provisions
            .update(&reserved)
            .await
            .map_err(|detail| format!("the record update failed: {detail}"))?;
        Ok(Ok((node, target)))
    }
}

impl ProvisionExecutor {
    #[allow(clippy::too_many_lines)]
    async fn execute_linked(
        &self,
        operations: &Operations,
        operation: &Operation,
    ) -> Result<(), String> {
        if operation.kind != "lab.provision" {
            return Err("not a Lab provision kind".to_owned());
        }
        let payload: serde_json::Value = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a valid provision record: {error}"))?;
        let record_id = payload["recordId"]
            .as_str()
            .ok_or("the payload carries no recordId")?
            .to_owned();
        let account_id = payload["accountId"]
            .as_str()
            .ok_or("the payload carries no accountId")?
            .to_owned();
        let lease_id = payload["leaseId"]
            .as_str()
            .ok_or("the payload carries no leaseId")?
            .to_owned();
        let record = self
            .provisions
            .get(&record_id)
            .await
            .map_err(|detail| format!("the provision record is unreadable: {detail}"))?;
        let lease = self
            .leases
            .get(&lease_id)
            .await
            .map_err(|detail| format!("the linked lease is unreadable: {detail}"))?;
        if record.lease_id.as_deref() != Some(lease_id.as_str())
            || lease.provision_id.as_deref() != Some(record.id.as_str())
        {
            return Err("the provision record is not linked to the authorized lease".to_owned());
        }
        if !matches!(
            lease.state,
            fleet_core::LeaseState::Provisioning | fleet_core::LeaseState::Ready
        ) {
            return Err(format!(
                "the linked lease is in {} and cannot be provisioned",
                lease.state.id()
            ));
        }
        let version = self
            .templates
            .get_version(&record.template_version_id)
            .await
            .map_err(|detail| format!("the template version is unreadable: {detail}"))?;

        // The account is the API endpoint only: the PVE node that holds the
        // template comes from the cluster's resources, never from the
        // account's host. FM-711's placement epic owns multi-account
        // selection.
        let (account, secret) = self.bound(&account_id).await?;
        let request = pve_request(&account, secret);

        // Step 1: clone from the pinned image into a reserved VMID, unless
        // the record's clone already started (resume instead of creating a
        // second VM).
        let (node, vmid) = if record.clone_upid.is_some() {
            let (Some(node), Some(vmid)) = (record.node.clone(), record.vmid) else {
                return Err("the provision record started a clone but carries no target".to_owned());
            };
            // The live guest at the recorded target must still be this
            // provision's clone before anything starts it.
            let node = match self
                .verify_recorded_guest(request.clone(), &record.id, &node, vmid)
                .await?
            {
                Ok(live) if record.node.as_deref() == Some(live.as_str()) => live,
                Ok(live) => {
                    // The guest moved since the clone: later cleanup must
                    // find it where it lives now, even if this run stops
                    // before readiness rewrites the record.
                    let mut moved = record.clone();
                    moved.node = Some(live.clone());
                    self.provisions.update(&moved).await.map_err(|detail| {
                        format!("the provision record is unwritable: {detail}")
                    })?;
                    live
                }
                Err(refusal) => {
                    return complete_failure(
                        operations,
                        &operation.id,
                        refusal.reason,
                        &refusal.detail,
                    )
                    .await;
                }
            };
            operations
                .record_progress(
                    &operation.id,
                    Some(1),
                    Some(3),
                    Some(&format!("resuming existing guest {node}/qemu/{vmid}")),
                )
                .await
                .map_err(|error| error.to_string())?;
            (node, vmid)
        } else {
            operations
                .record_progress(
                    &operation.id,
                    Some(0),
                    Some(3),
                    Some("cloning the pinned image"),
                )
                .await
                .map_err(|error| error.to_string())?;
            match self
                .clone_into_reserved_target(
                    &record,
                    &version.content.image_version_id,
                    &account_id,
                    &operation.id,
                    &request,
                )
                .await?
            {
                Ok(target) => target,
                Err(refusal) => {
                    return complete_failure(
                        operations,
                        &operation.id,
                        refusal.reason,
                        &refusal.detail,
                    )
                    .await;
                }
            }
        };
        // Later transitions build on the stored record, so they keep the
        // reservation and the clone UPID step 1 recorded.
        let record = self
            .provisions
            .get(&record.id)
            .await
            .map_err(|detail| format!("the provision record is unreadable: {detail}"))?;

        // Step 2: start the guest (idempotent when already running).
        operations
            .record_progress(
                &operation.id,
                Some(2),
                Some(3),
                Some(&format!("starting {node}/qemu/{vmid}")),
            )
            .await
            .map_err(|error| error.to_string())?;
        let started = self
            .client
            .guest_lifecycle(
                request.clone(),
                &node,
                vmid,
                fleet_provider_proxmox::LifecycleAction::Start,
            )
            .await;
        // A refused start stays tolerated (the guest may already run); an
        // accepted one is linked like every other task Fleet starts.
        if let Ok(upid) = &started {
            record_task_link(self.links.as_ref(), &account_id, upid, &operation.id).await;
        }

        // Step 3: the readiness probe. The guest-agent probe polls the
        // FM-601 agent data; the deadline comes from the template.
        let deadline =
            std::time::Duration::from_secs(u64::from(version.content.readiness_deadline_seconds));
        let started = std::time::Instant::now();
        loop {
            let cancelled = operations
                .cancel_requested(&operation.id)
                .await
                .unwrap_or(false);
            if cancelled {
                return complete_failure(
                    operations,
                    &operation.id,
                    "cancelled",
                    &format!(
                        "cancelled while waiting for readiness; the guest {node}/qemu/{vmid} keeps running and its state is recorded"
                    ),
                )
                .await;
            }
            // The agent probe: the guest answers `agent/info` when ready.
            let agent_ready = self
                .client
                .guest_agent_info(request.clone(), &node, vmid)
                .await
                .is_ok();
            if agent_ready {
                break;
            }
            if started.elapsed() >= deadline {
                // never_ready: an explicit recorded failure, never a hang.
                let mut updated = record.clone();
                updated.state = fleet_core::GuestState::NeverReady;
                updated.node = Some(node.clone());
                updated.vmid = Some(vmid);
                self.provisions
                    .update(&updated)
                    .await
                    .map_err(|detail| format!("the record update failed: {detail}"))?;
                return complete_failure(
                    operations,
                    &operation.id,
                    "never_ready",
                    &format!(
                        "the readiness deadline expired without the probe passing; the guest {node}/qemu/{vmid} is recorded as never_ready"
                    ),
                )
                .await;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }

        // Ready: record the state; the TTL clock starts here.
        let (ready_at, lease_expires_at) = if let Some(lease_id) = record.lease_id.as_deref() {
            let lease = self
                .leases
                .get(lease_id)
                .await
                .map_err(|detail| format!("the linked lease is unreadable: {detail}"))?;
            if lease.provision_id.as_deref() != Some(record.id.as_str()) {
                return Err("the linked lease does not name this provision record".to_owned());
            }
            if lease.state == fleet_core::LeaseState::Ready {
                (
                    lease
                        .ready_at
                        .ok_or_else(|| "the ready lease has no readiness timestamp".to_owned())?,
                    Some(
                        lease
                            .expires_at
                            .ok_or_else(|| "the ready lease has no expiry timestamp".to_owned())?,
                    ),
                )
            } else {
                let mut ready_lease = lease;
                ready_lease
                    .mark_ready(fleet_core::SystemClock::now_unix_millis())
                    .map_err(|detail| format!("the lease could not become ready: {detail}"))?;
                let ready_at = ready_lease
                    .ready_at
                    .ok_or_else(|| "ready transition produced no ready_at".to_owned())?;
                let expires_at = ready_lease
                    .expires_at
                    .ok_or_else(|| "ready transition produced no expires_at".to_owned())?;
                (ready_at, Some(expires_at))
            }
        } else {
            (fleet_core::SystemClock::now_unix_millis(), None)
        };
        let mut updated = record.clone();
        updated.state = fleet_core::GuestState::Ready;
        updated.node = Some(node.clone());
        updated.vmid = Some(vmid);
        updated.ready_at = Some(ready_at);
        self.provisions
            .complete_ready(&updated, lease_expires_at)
            .await
            .map_err(|detail| format!("the readiness transaction failed: {detail}"))?;
        operations
            .complete(
                &operation.id,
                "succeeded",
                Some(
                    &serde_json::json!({
                        "recordId": record.id,
                        "node": node,
                        "vmid": vmid,
                        "state": "ready"
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

#[async_trait::async_trait]
impl OperationExecutor for ProvisionExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        self.execute_linked(operations, operation).await
    }
}

/// The kind-dispatching Lab executor: `lab.provision` routes to the
/// provision executor, everything else falls through.
#[derive(Debug)]
pub struct LabDispatch {
    fallback: Arc<dyn OperationExecutor>,
    provision: Arc<ProvisionExecutor>,
}

impl LabDispatch {
    /// Composes the dispatch from its parts.
    #[must_use]
    pub fn new(fallback: Arc<dyn OperationExecutor>, provision: Arc<ProvisionExecutor>) -> Self {
        Self {
            fallback,
            provision,
        }
    }
}

#[async_trait::async_trait]
impl OperationExecutor for LabDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        if operation.kind == "lab.provision" {
            self.provision.execute(operations, operation).await
        } else {
            self.fallback.execute(operations, operation).await
        }
    }
}

#[cfg(test)]
mod destroy_tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
    use fleet_application::proxmox::{CredentialStoreError, NewProxmoxAccount, ProxmoxAccountPort};
    use fleet_provider_proxmox::{
        PveHttpMethod, PveHttpRequest, PveHttpResponse, PveTransport, PveTransportError,
    };
    use fleet_storage_sqlite::{
        AuditSink, OperationRepository, ProxmoxAccountRepository, ProxmoxTaskLinkRepository, Store,
    };
    use serde_json::{Value, json};
    use std::sync::Mutex;
    use tower::ServiceExt;

    const STOP: &str = "UPID:pve:0015523F:0C6DF532:6AAFE1EC:qmstop:101:fleet@pve!test:";
    const DESTROY: &str = "UPID:pve:0015523F:0C6DF532:6AAFE1EC:qmdestroy:101:fleet@pve!test:";
    #[derive(Debug)]
    struct Transport {
        template: bool,
        template_after_stop: std::sync::atomic::AtomicBool,
        absent: bool,
        task_error: bool,
        stop_error: bool,
        stop_running: bool,
        seen: Mutex<Vec<String>>,
        cancel_on_recheck: Mutex<Option<(Arc<Operations>, String)>>,
    }
    #[async_trait::async_trait]
    impl PveTransport for Transport {
        async fn execute(
            &self,
            request: PveHttpRequest,
        ) -> Result<PveHttpResponse, PveTransportError> {
            let path = request.path;
            self.seen.lock().unwrap().push(path.clone());
            let recheck = path == "/api2/json/cluster/resources"
                && self
                    .seen
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|path| path.as_str() == "/api2/json/cluster/resources")
                    .count()
                    == 2;
            if recheck {
                let cancellation = self.cancel_on_recheck.lock().unwrap().take();
                if let Some((operations, id)) = cancellation {
                    operations
                        .cancel(&Policy(false), "anonymous-lan-admin", &id)
                        .await
                        .unwrap();
                }
            }
            let mut status = 200;
            let body = if path == "/api2/json/version" {
                json!({"data":{"version":"9.0.3"}})
            } else if path == "/api2/json/cluster/resources" {
                if self.absent {
                    json!({"data":[]})
                } else {
                    json!({"data":[{"id":"qemu/101","type":"qemu","vmid":101,"node":"pve","status":"running","template":u8::from(self.template || (self.template_after_stop.load(std::sync::atomic::Ordering::Relaxed) && self.seen.lock().unwrap().iter().any(|path| path.ends_with("/status/stop"))))}]})
                }
            } else if path.ends_with("/status/stop") {
                assert_eq!(request.method, PveHttpMethod::Post);
                json!({"data":STOP})
            } else if path.ends_with("/config") {
                if self.absent {
                    status = 500;
                    json!({"message":"Configuration file 'nodes/pve/qemu-server/101.conf' does not exist\n"})
                } else {
                    json!({"data":{"template":0}})
                }
            } else if request.method == PveHttpMethod::Delete {
                assert_eq!(path, "/api2/json/nodes/pve/qemu/101?purge=0");
                json!({"data":DESTROY})
            } else if path.contains("/tasks/") {
                let stop = path.contains("qmstop");
                if stop && self.stop_running {
                    json!({"data":{"status":"running"}})
                } else {
                    json!({"data":{"status":"stopped","exitstatus":if (stop && self.stop_error) || (!stop && self.task_error) {"ERROR: disk locked"} else {"OK"}}})
                }
            } else {
                panic!("unexpected path {path}")
            };
            Ok(PveHttpResponse {
                status,
                body: body.to_string().into_bytes(),
            })
        }
        async fn execute_with_body(
            &self,
            request: PveHttpRequest,
            _: Vec<u8>,
        ) -> Result<PveHttpResponse, PveTransportError> {
            self.execute(request).await
        }
    }
    #[derive(Debug)]
    struct Secret;
    #[async_trait::async_trait]
    impl ProxmoxCredentialStore for Secret {
        async fn load(&self, _: &str) -> Result<Option<String>, CredentialStoreError> {
            Ok(Some("fixture-secret".into()))
        }
        async fn store(&self, _: &str, _: &str) -> Result<(), CredentialStoreError> {
            unreachable!()
        }
        async fn clear(&self, _: &str) -> Result<(), CredentialStoreError> {
            unreachable!()
        }
    }
    #[derive(Debug)]
    struct Artifacts(bool);
    #[async_trait::async_trait]
    impl fleet_application::lab::ImageArtifactPort for Artifacts {
        async fn template_vmid(&self, _: &str) -> Result<Option<u32>, String> {
            unreachable!()
        }
        async fn promoted_template_vmids(&self) -> Result<Vec<u32>, String> {
            Ok(if self.0 { vec![101] } else { vec![] })
        }
    }
    #[derive(Debug)]
    struct Policy(bool);
    impl Authorizer for Policy {
        fn decide(&self, request: AccessRequest<'_>) -> Decision {
            if self.0 && request.action == Permission::ProxmoxDestructive {
                Decision::deny(ReasonId::UnknownAction)
            } else {
                Decision::allow()
            }
        }
    }
    struct Harness {
        _dir: tempfile::TempDir,
        operations: Arc<Operations>,
        account: String,
        executor: ProxmoxDestructiveExecutor,
        links: Arc<ProxmoxTaskLinkRepository>,
        transport: Arc<Transport>,
    }
    impl Harness {
        async fn new(
            template: bool,
            promoted: bool,
            absent: bool,
            task_error: bool,
            stop_error: bool,
            stop_running: bool,
        ) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
            let pool = store.pool().clone();
            let accounts = Arc::new(ProxmoxAccountRepository::new(pool.clone()));
            let account = accounts
                .create(&NewProxmoxAccount {
                    name: "fixture".into(),
                    host: "pve.test".into(),
                    port: None,
                    token_id: "fleet@pve!test".into(),
                })
                .await
                .unwrap();
            accounts
                .set_fingerprint(&account.id, Some("fixture-pin".into()))
                .await
                .unwrap();
            let operations = Arc::new(Operations::new(
                Arc::new(OperationRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            ));
            let links = Arc::new(ProxmoxTaskLinkRepository::new(pool));
            let transport = Arc::new(Transport {
                template,
                template_after_stop: std::sync::atomic::AtomicBool::new(false),
                absent,
                task_error,
                stop_error,
                stop_running,
                seen: Mutex::new(vec![]),
                cancel_on_recheck: Mutex::new(None),
            });
            let executor = ProxmoxDestructiveExecutor::new(
                accounts,
                Arc::new(Secret),
                fleet_provider_proxmox::ProxmoxClient::new(transport.clone()),
            )
            .with_image_artifacts(Arc::new(Artifacts(promoted)))
            .with_task_links(links.clone());
            Self {
                _dir: dir,
                operations,
                account: account.id,
                executor,
                links,
                transport,
            }
        }
        fn app(&self, deny: bool) -> axum::Router {
            let mut state = fleet_api::operations::ApiState::for_document();
            state.operations = self.operations.clone();
            state.authorizer = Arc::new(Policy(deny));
            fleet_api::router(Arc::new(state)).layer(axum::Extension(fleet_api::ActingPrincipal {
                id: "anonymous-lan-admin".into(),
            }))
        }
        async fn post(&self, suffix: &str, body: Value, deny: bool) -> (u16, Value) {
            let request = Request::post(format!(
                "/api/v1/proxmox/accounts/{}/guests/101/destroy/{suffix}",
                self.account
            ))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
            let response = self.app(deny).oneshot(request).await.unwrap();
            let status = response.status().as_u16();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, serde_json::from_slice(&bytes).unwrap())
        }
        async fn create_operation(&self, timeout: u64) -> Operation {
            let payload = json!({"accountId":self.account,"node":"pve","vmid":101,"timeoutSeconds":timeout,"params":{"purge":false}}).to_string();
            let new = fleet_application::operation::NewOperation {
                kind: "proxmox.guest.destroy".into(),
                payload_json: Some(payload.clone()),
                review_token: Some(fleet_application::operation::review_token_for(
                    "proxmox.guest.destroy",
                    &payload,
                )),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
            };
            self.operations
                .create(&Policy(false), "anonymous-lan-admin", &new)
                .await
                .unwrap()
        }
        async fn run(&self, timeout: u64) -> Operation {
            let operation = self.create_operation(timeout).await;
            self.operations
                .claim_only_execute(&self.executor, &operation.id, "destroy-test")
                .await
                .unwrap();
            self.operations
                .get(&Policy(false), "anonymous-lan-admin", &operation.id)
                .await
                .unwrap()
        }
    }
    #[tokio::test]
    async fn destroy_review_gate_permission_and_changed_params() {
        let h = Harness::new(false, false, false, false, false, false).await;
        let generic = Request::post("/api/v1/operations")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"kind":"proxmox.guest.destroy","payloadJson":"{}"}).to_string(),
            ))
            .unwrap();
        assert_eq!(
            h.app(false)
                .oneshot(generic)
                .await
                .unwrap()
                .status()
                .as_u16(),
            400
        );
        let body = json!({"node":"pve","params":{"purge":false}});
        assert_eq!(h.post("review", body.clone(), true).await.0, 403);
        assert_eq!(
            h.post(
                "review",
                json!({"node":"pve","params":{"skiplock":true}}),
                false
            )
            .await
            .0,
            400
        );
        let (status, review) = h.post("review", body, false).await;
        assert_eq!(status, 200);
        let run = json!({"node":"pve","params":{"purge":false},"timeoutSeconds":300,"reviewToken":review["data"]["reviewToken"]});
        let mut bad = run.clone();
        bad["reviewToken"] = json!("wrong");
        assert_eq!(h.post("run", bad, false).await.0, 400);
        let mut changed = run.clone();
        changed["params"]["purge"] = json!(true);
        assert_eq!(h.post("run", changed, false).await.0, 400);
        assert_eq!(h.post("run", run.clone(), true).await.0, 403);
        let (status, accepted) = h.post("run", run, false).await;
        assert_eq!(status, 202);
        assert!(h.transport.seen.lock().unwrap().is_empty());
        let id = accepted["data"]["id"].as_str().unwrap();
        h.operations
            .claim_only_execute(&h.executor, id, "api-test")
            .await
            .unwrap();
        assert_eq!(
            h.operations
                .get(&Policy(false), "anonymous-lan-admin", id)
                .await
                .unwrap()
                .state,
            "succeeded"
        );
    }
    #[tokio::test]
    async fn destroy_stops_first_and_links_both_tasks() {
        let h = Harness::new(false, false, false, false, false, false).await;
        let operation = h.run(30).await;
        assert_eq!(operation.state, "succeeded");
        {
            let seen = h.transport.seen.lock().unwrap();
            assert!(
                seen.iter()
                    .position(|p| p.ends_with("/status/stop"))
                    .unwrap()
                    < seen.iter().position(|p| p.contains("?purge=")).unwrap()
            );
        }
        let links = h
            .links
            .operations_for(&h.account, &[STOP.into(), DESTROY.into()])
            .await
            .unwrap();
        assert_eq!(links.len(), 2);
        assert!(links.values().all(|id| id == &operation.id));
    }
    #[tokio::test]
    async fn destroy_refuses_templates_and_promoted_artifacts_before_stop() {
        for (template, promoted) in [(true, false), (false, true)] {
            let h = Harness::new(template, promoted, false, false, false, false).await;
            assert_eq!(h.run(30).await.state, "failed");
            assert!(
                !h.transport
                    .seen
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|p| p.ends_with("/status/stop") || p.contains("?purge="))
            );
        }
    }
    #[tokio::test]
    async fn destroy_absence_succeeds_and_task_error_fails() {
        let h = Harness::new(false, false, true, false, false, false).await;
        assert_eq!(h.run(30).await.state, "succeeded");
        assert!(
            !h.transport
                .seen
                .lock()
                .unwrap()
                .iter()
                .any(|p| p.contains("?purge="))
        );
        let h = Harness::new(false, false, false, true, false, false).await;
        assert_eq!(h.run(30).await.state, "failed");
    }
    #[tokio::test]
    async fn destroy_review_accepts_omitted_options() {
        let h = Harness::new(false, false, true, false, false, false).await;
        let (status, review) = h.post("review", json!({"node":"pve"}), false).await;
        assert_eq!(status, 200);
        let (status, accepted) = h.post("run", json!({"node":"pve","reviewToken":review["data"]["reviewToken"],"timeoutSeconds":300}), false).await;
        assert_eq!(status, 202);
        let id = accepted["data"]["id"].as_str().unwrap();
        h.operations
            .claim_only_execute(&h.executor, id, "omitted-options-test")
            .await
            .unwrap();
        assert_eq!(
            h.operations
                .get(&Policy(false), "anonymous-lan-admin", id)
                .await
                .unwrap()
                .state,
            "succeeded"
        );
    }
    #[tokio::test]
    async fn destroy_rechecks_cluster_template_state_after_stop() {
        let h = Harness::new(false, false, false, false, false, false).await;
        h.transport
            .template_after_stop
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let operation = h.run(30).await;
        assert_eq!(operation.state, "failed");
        assert!(
            !h.transport
                .seen
                .lock()
                .unwrap()
                .iter()
                .any(|path| path.contains("?purge="))
        );
    }
    #[tokio::test]
    async fn destroy_honors_cancellation_during_post_stop_lookup() {
        let h = Harness::new(false, false, false, false, false, false).await;
        let operation = h.create_operation(30).await;
        *h.transport.cancel_on_recheck.lock().unwrap() =
            Some((h.operations.clone(), operation.id.clone()));
        h.operations
            .claim_only_execute(&h.executor, &operation.id, "cancel-test")
            .await
            .unwrap();
        assert!(
            !h.transport
                .seen
                .lock()
                .unwrap()
                .iter()
                .any(|path| path.contains("?purge=")),
            "a cancellation during the final resource lookup must prevent DELETE"
        );
        assert!(h.operations.cancel_requested(&operation.id).await.unwrap());
    }
    #[tokio::test]
    async fn destroy_never_deletes_after_failed_or_timed_out_stop() {
        for (error, running) in [(true, false), (false, true)] {
            let h = Harness::new(false, false, false, false, error, running).await;
            assert_eq!(h.run(1).await.state, "failed");
            assert!(
                !h.transport
                    .seen
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|p| p.contains("?purge="))
            );
        }
    }
}
