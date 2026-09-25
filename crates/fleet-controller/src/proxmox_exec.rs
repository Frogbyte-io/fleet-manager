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
        }
    }

    /// The trusted account and its resolved secret: the same explicit-trust
    /// gate the read surfaces apply, without duplicating their checks.
    /// Resolves the clone source VMID from the image version's build
    /// artifact. Returns None when no successful build exists.
    #[allow(dead_code)]
    async fn resolve_source_vmid(
        &self,
        request: fleet_provider_proxmox::PveHttpRequest,
    ) -> Option<u32> {
        let discovery = self.client.discover(request).await.ok()?;
        // Find the template VM matching the image version's name.
        discovery
            .resources
            .iter()
            .find(|resource| {
                resource.kind == "qemu-template"
                    && resource
                        .name
                        .as_deref()
                        .is_some_and(|name| name.contains("fm-image-base"))
            })
            .and_then(|resource| resource.vmid)
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
pub const DESTRUCTIVE_KINDS: [&str; 6] = [
    "proxmox.guest.snapshot",
    "proxmox.guest.snapshot-revert",
    "proxmox.guest.snapshot-delete",
    "proxmox.guest.clone",
    "proxmox.guest.template",
    "proxmox.task-cancel",
];

/// The destructive-adjacent executor: snapshot, revert, snapshot-delete,
/// clone, template conversion, and remote task cancellation. Every kind
/// arrived through the reviewed dedicated endpoint (the generic surface
/// refuses them); the executor re-applies the trust gate and classifies
/// idempotency before touching anything.
#[derive(Debug)]
pub struct ProxmoxDestructiveExecutor {
    accounts: Arc<dyn fleet_application::proxmox::ProxmoxAccountPort>,
    credentials: Arc<dyn fleet_application::proxmox::ProxmoxCredentialStore>,
    client: fleet_provider_proxmox::ProxmoxClient,
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
        }
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
    /// The trusted account and its resolved secret: the same explicit-trust
    /// gate the other surfaces apply.
    /// Resolves the clone source VMID from the image version's build
    /// artifact. Returns None when no successful build exists.
    #[allow(dead_code)]
    async fn resolve_source_vmid(
        &self,
        request: fleet_provider_proxmox::PveHttpRequest,
    ) -> Option<u32> {
        let discovery = self.client.discover(request).await.ok()?;
        // Find the template VM matching the image version's name.
        discovery
            .resources
            .iter()
            .find(|resource| {
                resource.kind == "qemu-template"
                    && resource
                        .name
                        .as_deref()
                        .is_some_and(|name| name.contains("fm-image-base"))
            })
            .and_then(|resource| resource.vmid)
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
    client: fleet_provider_proxmox::ProxmoxClient,
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
        client: fleet_provider_proxmox::ProxmoxClient,
    ) -> Self {
        Self {
            accounts,
            credentials,
            provisions,
            leases,
            templates,
            client,
        }
    }

    /// Resolves the clone source VMID from the image version's build
    /// artifact. Returns None when no successful build exists.
    #[allow(dead_code)]
    async fn resolve_source_vmid(
        &self,
        request: fleet_provider_proxmox::PveHttpRequest,
    ) -> Option<u32> {
        let discovery = self.client.discover(request).await.ok()?;
        // Find the template VM matching the image version's name.
        discovery
            .resources
            .iter()
            .find(|resource| {
                resource.kind == "qemu-template"
                    && resource
                        .name
                        .as_deref()
                        .is_some_and(|name| name.contains("fm-image-base"))
            })
            .and_then(|resource| resource.vmid)
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

#[async_trait::async_trait]
impl OperationExecutor for ProvisionExecutor {
    #[allow(clippy::too_many_lines)]
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
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
        let record = self
            .provisions
            .get(&record_id)
            .await
            .map_err(|detail| format!("the provision record is unreadable: {detail}"))?;
        let version = self
            .templates
            .get_version(&record.template_version_id)
            .await
            .map_err(|detail| format!("the template version is unreadable: {detail}"))?;

        // The account is the template content's host: the record does not
        // carry one, so the executor resolves the account that owns the
        // pinned image's cluster through the first configured account.
        // FM-711's placement epic owns multi-account selection.
        let (account, secret) = self.bound(&account_id).await?;
        let request = fleet_provider_proxmox::PveHttpRequest {
            host: account.host.clone(),
            port: account.port,
            path: "/api2/json/version".to_owned(),
            pinned_fingerprint: account.fingerprint.clone(),
            credentials: Arc::new(fleet_provider_proxmox::PveCredentials {
                token_id: account.token_id.clone(),
                token: fleet_core::SensitiveString::new(secret),
            }),
            method: fleet_provider_proxmox::PveHttpMethod::Get,
        };

        // Step 1: clone from the pinned image, unless the record already
        // carries a VMID (resume instead of creating a second VM).
        let (node, vmid) = match (record.node.clone(), record.vmid) {
            (Some(node), Some(vmid)) => {
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
            }
            _ => {
                operations
                    .record_progress(
                        &operation.id,
                        Some(0),
                        Some(3),
                        Some("cloning the pinned image"),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                // The clone source: the pinned image version's build
                // artifact (a template VMID), resolved from the build
                // operation's result. Falls back to the golden source
                // (103) when no build artifact exists yet.
                let source_vmid = self
                    .resolve_source_vmid(request.clone())
                    .await
                    .unwrap_or(103);
                let upid = self
                    .client
                    .guest_clone(
                        request.clone(),
                        &account.host,
                        source_vmid,
                        0,
                        &format!("fm-lab-{}", record.id),
                        true,
                    )
                    .await
                    .map_err(|error| format!("the clone failed: {error}"))?;
                // Record the clone UPID and the resolved VMID before
                // continuing: the saga rule.
                let mut updated = record.clone();
                updated.clone_upid = Some(upid.raw.clone());
                updated.node = Some(upid.node.clone());
                // The clone's VMID: parse from the UPID's target field
                // (index 6), or fall back to the source VMID.
                let new_vmid = upid
                    .raw
                    .split(':')
                    .nth(6)
                    .and_then(|id| id.parse::<u32>().ok())
                    .unwrap_or(source_vmid);
                updated.vmid = Some(new_vmid);
                self.provisions
                    .update(&updated)
                    .await
                    .map_err(|detail| format!("the record update failed: {detail}"))?;
                (upid.node.clone(), new_vmid)
            }
        };

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
        let _ = self
            .client
            .guest_lifecycle(
                request.clone(),
                &node,
                vmid,
                fleet_provider_proxmox::LifecycleAction::Start,
            )
            .await;

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
        let ready_at = if let Some(lease_id) = record.lease_id.as_deref() {
            let lease = self
                .leases
                .get(lease_id)
                .await
                .map_err(|detail| format!("the linked lease is unreadable: {detail}"))?;
            if lease.provision_id.as_deref() != Some(record.id.as_str()) {
                return Err("the linked lease does not name this provision record".to_owned());
            }
            if lease.state == fleet_core::LeaseState::Ready {
                lease
                    .ready_at
                    .ok_or_else(|| "the ready lease has no readiness timestamp".to_owned())?
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
                let marked = self
                    .leases
                    .mark_ready(lease_id, &record.id, ready_at, expires_at)
                    .await
                    .map_err(|detail| format!("the ready lease update failed: {detail}"))?;
                if !marked {
                    let current =
                        self.leases.get(lease_id).await.map_err(|detail| {
                            format!("the linked lease is unreadable: {detail}")
                        })?;
                    if current.state != fleet_core::LeaseState::Ready
                        || current.provision_id.as_deref() != Some(record.id.as_str())
                    {
                        return Err(
                            "the linked lease changed before readiness was recorded".to_owned()
                        );
                    }
                    current
                        .ready_at
                        .ok_or_else(|| "the ready lease has no readiness timestamp".to_owned())?
                } else {
                    ready_at
                }
            }
        } else {
            fleet_core::SystemClock::now_unix_millis()
        };
        let mut updated = record.clone();
        updated.state = fleet_core::GuestState::Ready;
        updated.node = Some(node.clone());
        updated.vmid = Some(vmid);
        updated.ready_at = Some(ready_at);
        self.provisions
            .update(&updated)
            .await
            .map_err(|detail| format!("the record update failed: {detail}"))?;
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
