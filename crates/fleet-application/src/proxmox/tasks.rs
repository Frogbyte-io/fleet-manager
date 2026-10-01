//! Proxmox task history (FM-609): a bounded, read-only view of an
//! account's recent PVE tasks, joined to the Fleet operations that started
//! them.
//!
//! The read goes through the same explicit-trust gate as discovery. Without
//! a confirmed fingerprint, no credential-carrying call leaves Fleet. The
//! provider reads each node independently, so a node that cannot be read
//! becomes a warning instead of a failed read.
//!
//! The UPID-to-operation join lives here, not in an adapter. Executors
//! record each UPID they start through [`ProxmoxTaskLinkPort::record`],
//! and this use case looks the page's UPIDs up in one call. A caller who
//! may not read operations gets the tasks without the link, along with a
//! warning that says why. Nothing here mutates PVE or Fleet state, so
//! there is no audit event to write.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{ProxmoxAccount, ProxmoxAccounts, ProxmoxSourceError, ProxmoxUseCaseError};
use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Permission, authorize};
use crate::operation::PortFailure;
use fleet_core::SensitiveString;

/// How many tasks the use case asks each node for. The snapshot is bounded
/// by this times the cluster's node count.
pub const TASKS_PER_NODE: u32 = 200;

/// The status of one task, in the provider's `TaskStatus` taxonomy as the
/// application sees it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxmoxTaskState {
    /// The task is still running.
    Running,
    /// The task finished with `OK`.
    Ok,
    /// The task finished with any other exit status (the exit status is
    /// carried alongside it, `WARNINGS: n` included).
    Error,
    /// PVE reported no usable status. This is honest uncertainty, never
    /// assumed success.
    Unknown,
}

impl ProxmoxTaskState {
    /// The stable string used in the API and the CLI.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Unknown => "unknown",
        }
    }

    /// Parses the stable string.
    ///
    /// # Errors
    ///
    /// Fails on an unrecognized status, naming the accepted values.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "running" => Ok(Self::Running),
            "ok" => Ok(Self::Ok),
            "error" => Ok(Self::Error),
            "unknown" => Ok(Self::Unknown),
            other => Err(format!(
                "the status filter must be running, ok, error, or unknown, not {other:?}"
            )),
        }
    }
}

/// The provider-side query the task port receives.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RawTaskQuery {
    /// Read only this node's tasks.
    pub node: Option<String>,
    /// Read only this guest's tasks.
    pub vmid: Option<u32>,
    /// Read only running tasks (PVE's `source=active`).
    pub running_only: bool,
    /// Read only finished tasks in this status (`ok`, `error`, or
    /// `unknown`), filtered by PVE before its per-node limit. Unset for
    /// `running`, which `running_only` covers.
    pub finished_status: Option<ProxmoxTaskState>,
    /// The most tasks one node returns.
    pub limit_per_node: u32,
}

/// One task as the provider reported it, already translated out of the
/// provider's own model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawTask {
    /// The raw UPID string.
    pub upid: String,
    /// The node the task runs on, parsed from the UPID.
    pub node: String,
    /// The task type, e.g. `qmstart`.
    pub task_type: String,
    /// The task's target id (the VMID for guest tasks), when it has one.
    pub target_id: Option<String>,
    /// The user, as PVE reports it.
    pub user: String,
    /// The API token name, when PVE reports the task as a token's.
    pub token_id: Option<String>,
    /// When the task started (Unix seconds, as PVE reports it).
    pub started_at_seconds: i64,
    /// When the task ended (Unix seconds), once it has.
    pub ended_at_seconds: Option<i64>,
    /// The status.
    pub state: ProxmoxTaskState,
    /// PVE's exit status string, once the task has one.
    pub exit_status: Option<String>,
}

/// The provider's task-history read, before the operation join.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RawTaskHistory {
    /// The PVE version seen.
    pub version: String,
    /// The tasks, newest first.
    pub tasks: Vec<RawTask>,
    /// The per-node and per-entry warnings.
    pub warnings: Vec<String>,
}

/// The task-history port over one trusted account. The provider implements
/// it over the PVE API, and tests implement it over fixtures.
#[async_trait]
pub trait ProxmoxTaskHistoryPort: fmt::Debug + Send + Sync {
    /// Reads the account's recent tasks.
    ///
    /// # Errors
    ///
    /// Fails with [`ProxmoxSourceError`] only when the whole read fails.
    /// A node that fails is reported in the warnings instead.
    async fn task_history(
        &self,
        account: &ProxmoxAccount,
        secret: &SensitiveString,
        query: &RawTaskQuery,
    ) -> Result<RawTaskHistory, ProxmoxSourceError>;
}

/// The durable UPID-to-operation record. Executors write it as soon as PVE
/// returns a UPID, and the task history reads it back.
#[async_trait]
pub trait ProxmoxTaskLinkPort: fmt::Debug + Send + Sync {
    /// Records that `operation_id` started the task `upid` through
    /// `account_id`. Idempotent: recording the same UPID again is a no-op.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn record(
        &self,
        account_id: &str,
        upid: &str,
        operation_id: &str,
    ) -> Result<(), PortFailure>;

    /// Looks up the operations that started any of `upids` through
    /// `account_id`. UPIDs without a record are absent from the map.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn operations_for(
        &self,
        account_id: &str,
        upids: &[String],
    ) -> Result<HashMap<String, String>, PortFailure>;
}

/// The ports the task history composes over.
#[derive(Clone, Debug)]
pub(crate) struct TaskHistoryPorts {
    source: Arc<dyn ProxmoxTaskHistoryPort>,
    links: Arc<dyn ProxmoxTaskLinkPort>,
}

/// The caller's filters. Every filter is optional.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TaskHistoryQuery {
    /// Only this node's tasks.
    pub node: Option<String>,
    /// Only this guest's tasks.
    pub vmid: Option<u32>,
    /// Only tasks in this status: `running`, `ok`, `error`, or `unknown`.
    pub status: Option<String>,
}

/// One task in the history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxTask {
    /// The raw UPID: the task's identity, and the history's cursor.
    pub upid: String,
    /// The node the task runs on.
    pub node: String,
    /// The task type, e.g. `qmstart`.
    pub task_type: String,
    /// The target id (the VMID for guest tasks), when the task has one.
    pub target_id: Option<String>,
    /// The user, as PVE reports it.
    pub user: String,
    /// The API token name, when the task ran under a token. This is the
    /// token's name, never its secret.
    pub token_id: Option<String>,
    /// When the task started (epoch millis).
    pub started_at: i64,
    /// When the task ended (epoch millis), once it has.
    pub ended_at: Option<i64>,
    /// The status.
    pub status: ProxmoxTaskState,
    /// PVE's exit status string, once the task has one.
    pub exit_status: Option<String>,
    /// The Fleet operation that started this task, when Fleet started it
    /// and the caller may read operations.
    pub fleet_operation_id: Option<String>,
}

/// The task-history snapshot, newest first.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskHistorySnapshot {
    /// The account that produced the snapshot.
    pub account_id: String,
    /// The PVE version seen.
    pub pve_version: String,
    /// The tasks, newest first.
    pub tasks: Vec<ProxmoxTask>,
    /// What is missing and why: unreadable nodes, malformed entries, and
    /// a withheld operation link.
    pub warnings: Vec<String>,
    /// When the snapshot was taken (epoch millis).
    pub observed_at: i64,
}

impl ProxmoxAccounts {
    /// Attaches the task-history ports. Without them,
    /// [`ProxmoxAccounts::task_history`] reports a backend failure instead
    /// of guessing.
    #[must_use]
    pub fn with_task_history(
        mut self,
        source: Arc<dyn ProxmoxTaskHistoryPort>,
        links: Arc<dyn ProxmoxTaskLinkPort>,
    ) -> Self {
        self.task_history = Some(TaskHistoryPorts { source, links });
        self
    }

    /// Reads the account's recent task history, filtered and joined to the
    /// Fleet operations that started each task.
    ///
    /// # Errors
    ///
    /// Fails on denial, a malformed filter, an unknown or unconfirmed
    /// account, a missing secret, or a whole-read source failure.
    pub async fn task_history(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
        query: &TaskHistoryQuery,
        now: i64,
    ) -> Result<TaskHistorySnapshot, ProxmoxUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProxmoxRead,
                resource: Some(account_id),
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)?;
        let status = validate_query(query)?;
        let ports = self
            .task_history
            .as_ref()
            .ok_or_else(|| ProxmoxUseCaseError::Backend {
                context: "task history",
                detail: "the task-history ports are not composed".to_owned(),
            })?;
        let account = self.trusted_account(account_id).await?;
        let secret = self.require_secret(&account).await?;
        let raw = ports
            .source
            .task_history(
                &account,
                &SensitiveString::new(secret),
                &RawTaskQuery {
                    node: query.node.clone(),
                    vmid: query.vmid,
                    running_only: status == Some(ProxmoxTaskState::Running),
                    finished_status: status.filter(|wanted| *wanted != ProxmoxTaskState::Running),
                    limit_per_node: TASKS_PER_NODE,
                },
            )
            .await
            .map_err(ProxmoxUseCaseError::Source)?;
        let mut warnings = raw.warnings;
        let tasks: Vec<RawTask> = raw
            .tasks
            .into_iter()
            // A safety net: PVE already filtered, but its status vocabulary
            // is not Fleet's, so the exact Fleet status is enforced here.
            .filter(|task| status.is_none_or(|wanted| task.state == wanted))
            .collect();
        // The join: one lookup for the whole snapshot. The operation link
        // follows operation-read authorization. Without it, the tasks still
        // list, the link is withheld, and a warning explains the gap.
        let may_read_operations = authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::OperationRead,
                resource: None,
            },
        )
        .is_ok();
        let links = if may_read_operations && !tasks.is_empty() {
            let upids: Vec<String> = tasks.iter().map(|task| task.upid.clone()).collect();
            ports
                .links
                .operations_for(&account.id, &upids)
                .await
                .map_err(|error| ProxmoxUseCaseError::Backend {
                    context: "task links",
                    detail: error.to_string(),
                })?
        } else {
            if !may_read_operations {
                warnings.push(
                    "fleetOperationId is withheld: the caller may not read operations".to_owned(),
                );
            }
            HashMap::new()
        };
        let tasks = tasks
            .into_iter()
            .map(|task| {
                let fleet_operation_id = links.get(&task.upid).cloned();
                linked_task(task, fleet_operation_id)
            })
            .collect();
        Ok(TaskHistorySnapshot {
            account_id: account.id,
            pve_version: raw.version,
            tasks,
            warnings,
            observed_at: now,
        })
    }
}

/// Validates the caller's filters before any network work, returning the
/// parsed status filter.
fn validate_query(
    query: &TaskHistoryQuery,
) -> Result<Option<ProxmoxTaskState>, ProxmoxUseCaseError> {
    let status = query
        .status
        .as_deref()
        .map(ProxmoxTaskState::from_id)
        .transpose()
        .map_err(|detail| ProxmoxUseCaseError::Invalid { detail })?;
    if let Some(node) = &query.node {
        validate_node(node)?;
    }
    if let Some(vmid) = query.vmid
        && !(100..=999_999_999).contains(&vmid)
    {
        return Err(ProxmoxUseCaseError::Invalid {
            detail: format!("the VMID must be within 100..=999999999, not {vmid}"),
        });
    }
    Ok(status)
}

/// One provider task with its operation link, in Fleet's units (epoch
/// millis).
fn linked_task(task: RawTask, fleet_operation_id: Option<String>) -> ProxmoxTask {
    ProxmoxTask {
        fleet_operation_id,
        upid: task.upid,
        node: task.node,
        task_type: task.task_type,
        target_id: task.target_id,
        user: task.user,
        token_id: task.token_id,
        started_at: task.started_at_seconds.saturating_mul(1000),
        ended_at: task
            .ended_at_seconds
            .map(|seconds| seconds.saturating_mul(1000)),
        status: task.state,
        exit_status: task.exit_status,
    }
}

/// Node names become API path segments. This is the same rule the provider
/// applies, checked before any network work.
fn validate_node(node: &str) -> Result<(), ProxmoxUseCaseError> {
    let safe = !node.is_empty()
        && node.len() <= 128
        && node != "."
        && node != ".."
        && node
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if safe {
        Ok(())
    } else {
        Err(ProxmoxUseCaseError::Invalid {
            detail: format!("the node must be 1..=128 characters of [A-Za-z0-9._-], not {node:?}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_ids_round_trip_and_refuse_unknown_values() {
        for state in [
            ProxmoxTaskState::Running,
            ProxmoxTaskState::Ok,
            ProxmoxTaskState::Error,
            ProxmoxTaskState::Unknown,
        ] {
            assert_eq!(ProxmoxTaskState::from_id(state.id()), Ok(state));
        }
        assert!(ProxmoxTaskState::from_id("warning").is_err());
    }

    #[test]
    fn node_names_must_be_safe_path_segments() {
        assert!(validate_node("pve-1.lab").is_ok());
        assert!(validate_node("").is_err());
        assert!(validate_node("..").is_err());
        assert!(validate_node("pve/../x").is_err());
    }
}
