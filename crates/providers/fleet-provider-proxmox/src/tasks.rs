//! The bounded, read-only task-history read (FM-609).
//!
//! The read goes per node through `GET /nodes/{node}/tasks` rather than the
//! cluster-wide `GET /cluster/tasks`. Both shapes are the same on PVE 8.x
//! and 9.x (`pve-manager` `PVE/API2/Tasks.pm` and `PVE/API2/Cluster.pm`),
//! but they behave differently:
//!
//! - `/cluster/tasks` takes no parameters. It returns the
//!   pmxcfs-replicated recent-task list, with no `vmid`, status, or limit
//!   filter. A node that is down simply contributes stale or missing
//!   entries, so a partial answer looks the same as a complete one.
//! - `/nodes/{node}/tasks` is proxied to the node. It takes `vmid`,
//!   `statusfilter`, `since`/`until`, `start`/`limit`, and
//!   `source=archive|active|all`, and each node either answers or fails
//!   on its own.
//!
//! So the cluster's nodes come from `/cluster/resources`. Each online node
//! is read with `source=all` and a bounded `limit`, and any node that is
//! offline, unreachable, or refusing becomes a per-node warning instead of
//! a failed read. Only the prologue (version and cluster resources) can
//! fail the whole read. That is the same honesty rule discovery applies.
//!
//! The UPID is parsed with the one [`Upid::parse`]. The status maps onto
//! the existing [`TaskStatus`] taxonomy the same way the FM-602 status poll
//! does: `OK` is ok, any other exit status is an error carrying the bounded
//! exit string (including `WARNINGS: n`, which the detail preserves), and
//! a task without a status is unknown. The user is the string PVE reports.
//! PVE splits an API-token user into `user` and `tokenid`, and both carry
//! through unchanged. A token id names the token and is not the secret.

use futures_util::StreamExt as _;

use super::{
    ProxmoxClient, PveApiError, PveHttpRequest, TaskStatus, Upid, bounded_str, loose_number,
    normalize_resource, safe_node_path_segment, type_name_of, urlencode,
};

/// The largest number of tasks one node is asked for. A read is bounded by
/// this times the cluster's node count.
pub const MAX_TASKS_PER_NODE: u32 = 500;

/// The bound on a user or token-id string.
const MAX_USER_CHARS: usize = 128;
/// The bound on a task's exit-status detail.
const MAX_EXIT_STATUS_CHARS: usize = 256;
/// How many malformed cluster-resource rows are named before the rest are
/// only counted.
const MAX_RESOURCE_WARNINGS: usize = 5;
/// The bound on a resource id quoted in a warning.
const MAX_RESOURCE_NAME_CHARS: usize = 64;
/// How many nodes are read at once.
const NODE_CONCURRENCY: usize = 8;

/// Which of a node's tasks to list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PveTaskSource {
    /// Both the running tasks and the archived (finished) ones.
    #[default]
    All,
    /// Only the running tasks.
    Active,
}

impl PveTaskSource {
    const fn query_value(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Active => "active",
        }
    }
}

/// A finished-task outcome PVE can filter on (`statusfilter`). Fleet maps
/// PVE's `OK` to ok, `WARNINGS: n` and every other exit status to error,
/// and a task without a status to unknown, so each Fleet outcome names the
/// PVE categories that normalize into it (`normalize_status_type` in
/// `pve-common`, identical on 8.x and 9.x).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PveTaskOutcome {
    /// Finished with `OK`.
    Ok,
    /// Finished with a warning or an error.
    Error,
    /// No usable status.
    Unknown,
}

impl PveTaskOutcome {
    const fn query_value(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "warning,error",
            Self::Unknown => "unknown",
        }
    }
}

/// The task-history query. Every filter is optional. The per-node limit
/// is clamped to [`MAX_TASKS_PER_NODE`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PveTaskQuery {
    /// Read only this node's tasks.
    pub node: Option<String>,
    /// Read only this guest's tasks (PVE filters on its side).
    pub vmid: Option<u32>,
    /// Running tasks only, or everything.
    pub source: PveTaskSource,
    /// Finished tasks with this outcome only, filtered by PVE before its
    /// per-node limit so older matches are not crowded out.
    pub outcome: Option<PveTaskOutcome>,
    /// The most tasks one node returns.
    pub limit_per_node: u32,
}

/// One task as PVE lists it, normalized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PveTaskSummary {
    /// The parsed UPID. Its node, type, and target come from the UPID
    /// itself.
    pub upid: Upid,
    /// The user that ran the task, exactly as PVE reports it (without
    /// the token name when the task ran under an API token).
    pub user: String,
    /// The API token name, when PVE reports the task as a token's.
    pub token_id: Option<String>,
    /// When the task started (Unix seconds).
    pub started_at: i64,
    /// When the task ended (Unix seconds), once it has.
    pub ended_at: Option<i64>,
    /// The status in the existing taxonomy.
    pub status: TaskStatus,
}

/// The task-history read: the tasks across the cluster's nodes, plus the
/// per-node warnings that explain what is missing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PveTaskHistory {
    /// The PVE version seen.
    pub version: String,
    /// The tasks, newest first.
    pub tasks: Vec<PveTaskSummary>,
    /// The per-node and per-entry warnings. A node that could not be read
    /// is named here; it never fails the whole read.
    pub warnings: Vec<String>,
}

impl ProxmoxClient {
    /// Reads the recent task history across the cluster's nodes.
    /// Read-only and bounded: each node returns at most
    /// [`MAX_TASKS_PER_NODE`] tasks.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`] only when the version or
    /// cluster-resources prologue fails (auth, trust, transport). A node
    /// that fails is reported in the warnings instead.
    pub async fn task_history(
        &self,
        request: PveHttpRequest,
        query: &PveTaskQuery,
    ) -> Result<PveTaskHistory, PveApiError> {
        let (version, entries) = self.version_and_resources(&request).await?;
        let mut warnings = Vec::new();
        let mut nodes = cluster_nodes(&entries, &mut warnings);
        nodes.sort();
        nodes.dedup_by(|left, right| left.0 == right.0);
        if let Some(wanted) = &query.node {
            if nodes.iter().any(|(name, _)| name == wanted) {
                nodes.retain(|(name, _)| name == wanted);
            } else {
                warnings.push(format!(
                    "node {wanted:?} is not a member of the cluster; no tasks were read"
                ));
                nodes.clear();
            }
        }
        let limit = query.limit_per_node.clamp(1, MAX_TASKS_PER_NODE);
        let mut readable = Vec::new();
        for (node, status) in nodes {
            if !safe_node_path_segment(&node) {
                warnings.push(format!(
                    "node {node:?} tasks: the node name is not a safe API path segment"
                ));
            } else if status.as_deref() == Some("offline") {
                warnings.push(format!(
                    "node {node} is offline in the cluster status; its task history is unavailable"
                ));
            } else {
                readable.push(node);
            }
        }
        let mut per_node = futures_util::stream::iter(
            readable
                .into_iter()
                .map(|node| self.node_tasks(&request, node, query, limit)),
        )
        .buffer_unordered(NODE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
        // Deterministic warning order whatever order the nodes answered in.
        per_node.sort_by(|left, right| left.0.cmp(&right.0));
        let mut tasks = Vec::new();
        for (_, mut node_tasks, mut node_warnings) in per_node {
            tasks.append(&mut node_tasks);
            warnings.append(&mut node_warnings);
        }
        tasks.sort_by(|left, right| {
            right
                .started_at
                .cmp(&left.started_at)
                .then_with(|| right.upid.raw.cmp(&left.upid.raw))
        });
        // Two nodes never list the same UPID; dedup defensively so a
        // cursor names exactly one task.
        tasks.dedup_by(|left, right| left.upid.raw == right.upid.raw);
        Ok(PveTaskHistory {
            version,
            tasks,
            warnings,
        })
    }

    /// Reads one node's task list. Every failure is a warning naming the
    /// node.
    async fn node_tasks(
        &self,
        request: &PveHttpRequest,
        node: String,
        query: &PveTaskQuery,
        limit: u32,
    ) -> (String, Vec<PveTaskSummary>, Vec<String>) {
        let mut warnings = Vec::new();
        let vmid = query
            .vmid
            .map(|vmid| format!("&vmid={vmid}"))
            .unwrap_or_default();
        let statusfilter = query
            .outcome
            .map(|outcome| format!("&statusfilter={}", outcome.query_value()))
            .unwrap_or_default();
        let path = format!(
            "/api2/json/nodes/{}/tasks?source={}&limit={limit}{vmid}{statusfilter}",
            urlencode(&node),
            query.source.query_value()
        );
        let node_request = PveHttpRequest {
            path,
            ..request.clone()
        };
        let entries = match self.call(node_request).await {
            Ok(serde_json::Value::Array(entries)) => entries,
            Ok(serde_json::Value::Null) => Vec::new(),
            Ok(other) => {
                warnings.push(format!(
                    "node {node} tasks: the payload is not a list (it is a {})",
                    type_name_of(&other)
                ));
                return (node, Vec::new(), warnings);
            }
            Err(error) => {
                warnings.push(format!("node {node} tasks are unavailable: {error}"));
                return (node, Vec::new(), warnings);
            }
        };
        let returned = entries.len();
        let mut tasks = Vec::with_capacity(returned);
        for (index, entry) in entries.iter().enumerate() {
            match normalize_task(entry) {
                Ok(task) => {
                    if task.upid.node == node {
                        tasks.push(task);
                    } else {
                        warnings.push(format!(
                            "node {node} task #{index}: the UPID names node {}, not the node that listed it",
                            task.upid.node
                        ));
                    }
                }
                Err(detail) => warnings.push(format!("node {node} task #{index}: {detail}")),
            }
        }
        if u32::try_from(returned).is_ok_and(|count| count >= limit) {
            warnings.push(format!(
                "node {node} returned {returned} tasks, the per-node bound; older tasks are not listed"
            ));
        }
        (node, tasks, warnings)
    }
}

/// The cluster's nodes (name and status) from `/cluster/resources`. A row
/// that cannot be read is named in a bounded warning, never dropped
/// silently.
fn cluster_nodes(
    entries: &[serde_json::Value],
    warnings: &mut Vec<String>,
) -> Vec<(String, Option<String>)> {
    let mut nodes: Vec<(String, Option<String>)> = Vec::new();
    let mut skipped_rows = 0_usize;
    for entry in entries {
        match normalize_resource(entry) {
            Ok(Some(resource)) if resource.kind == "node" => {
                match resource
                    .node
                    .clone()
                    .or_else(|| resource.id.strip_prefix("node/").map(str::to_owned))
                {
                    Some(name) => nodes.push((name, resource.status)),
                    None => warnings.push(format!(
                        "cluster resource {:?} names no node; its tasks were not read",
                        resource.id
                    )),
                }
            }
            Ok(_) => {}
            Err(detail) => {
                // A malformed row may have been a node, so its tasks
                // would vanish without a trace. Say so, bounded. A row
                // that plainly is another resource type (say, a type
                // this version does not know yet) is not a node.
                let plainly_not_a_node = entry
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|kind| kind != "node")
                    && !entry
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|id| id.starts_with("node/"));
                if plainly_not_a_node {
                    continue;
                }
                skipped_rows += 1;
                if skipped_rows <= MAX_RESOURCE_WARNINGS {
                    let name = entry
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .map_or_else(
                            || "(no id)".to_owned(),
                            |id| id.chars().take(MAX_RESOURCE_NAME_CHARS).collect(),
                        );
                    warnings.push(format!(
                        "cluster resource {name:?} could not be read ({detail}); if it is a node, its tasks are missing"
                    ));
                }
            }
        }
    }
    if skipped_rows > MAX_RESOURCE_WARNINGS {
        warnings.push(format!(
            "{} more cluster resources could not be read",
            skipped_rows - MAX_RESOURCE_WARNINGS
        ));
    }
    nodes
}

/// Normalizes one `/nodes/{node}/tasks` entry. The UPID is required and
/// parsed with the one parser. Bounded fields are refused when they run
/// over, never silently truncated.
fn normalize_task(entry: &serde_json::Value) -> Result<PveTaskSummary, String> {
    let raw = entry
        .get("upid")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "the entry carries no UPID".to_owned())?;
    let upid = Upid::parse(raw)?;
    let user = bounded_str(entry, "user", MAX_USER_CHARS)?.unwrap_or_else(|| upid.user.clone());
    let token_id = bounded_str(entry, "tokenid", MAX_USER_CHARS)?;
    let started_at = loose_number(entry, "starttime")
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| format!("task {} carries no start time", upid.raw))?;
    let ended_at = loose_number(entry, "endtime").and_then(|value| i64::try_from(value).ok());
    let status = match bounded_str(entry, "status", MAX_EXIT_STATUS_CHARS)? {
        Some(status) if status == "RUNNING" => TaskStatus::Running,
        Some(status) if status == "OK" => TaskStatus::Ok,
        Some(status) if !status.is_empty() => TaskStatus::Error {
            detail: fleet_core::redact_url_credentials(&fleet_core::flatten_control_characters(
                &status,
            )),
        },
        // No exit status at all is honest uncertainty, never assumed
        // success or failure. PVE marks its running tasks `RUNNING`.
        _ => TaskStatus::Unknown,
    };
    Ok(PveTaskSummary {
        upid,
        user,
        token_id,
        started_at,
        ended_at,
        status,
    })
}
