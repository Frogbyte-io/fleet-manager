//! The Proxmox task-history surface (FM-609): a paginated, read-only view
//! of an account's recent PVE tasks.
//!
//! This adapter only translates. The application layer authorizes the
//! read, applies the explicit-trust gate, validates the filters, and joins
//! each UPID to the Fleet operation that started it. Pagination follows
//! the guests endpoint's convention: the snapshot is bounded by the
//! provider, the page bound applies on the way out, the cursor is the last
//! item's identity (here the UPID), and a cursor that names no task in the
//! snapshot is refused instead of silently restarting from the first page.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use fleet_application::proxmox::tasks::{ProxmoxTask, ProxmoxTaskState, TaskHistoryQuery};
use fleet_core::CorrelationId;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, PageInfo};
use crate::error::ApiErrorResponse;
use crate::proxmox::{map_proxmox_error, proxmox_or_error};

/// A task's status, in the provider's task-status taxonomy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProxmoxTaskStatusDto {
    /// The task is still running.
    Running,
    /// The task finished with `OK`.
    Ok,
    /// The task finished with any other exit status (see `exitStatus`,
    /// which includes `WARNINGS: n`).
    Error,
    /// PVE reported no usable status. This is honest uncertainty.
    Unknown,
}

impl From<ProxmoxTaskState> for ProxmoxTaskStatusDto {
    fn from(state: ProxmoxTaskState) -> Self {
        match state {
            ProxmoxTaskState::Running => Self::Running,
            ProxmoxTaskState::Ok => Self::Ok,
            ProxmoxTaskState::Error => Self::Error,
            ProxmoxTaskState::Unknown => Self::Unknown,
        }
    }
}

/// One PVE task.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxTaskDto {
    /// The raw UPID: the task's identity, and the page cursor.
    pub upid: String,
    /// The node the task runs on.
    pub node: String,
    /// The task type, e.g. `qmstart`, `vzdump`.
    pub task_type: String,
    /// The target id (the VMID for guest tasks), or null for node-level
    /// tasks.
    pub target_id: Option<String>,
    /// The user, exactly as PVE reports it.
    pub user: String,
    /// The API token name when the task ran under a token (its name, never
    /// its secret).
    pub token_id: Option<String>,
    /// When the task started (epoch millis).
    pub started_at: i64,
    /// When the task ended (epoch millis), or null while it runs.
    pub ended_at: Option<i64>,
    /// The status.
    pub status: ProxmoxTaskStatusDto,
    /// PVE's exit status string (`OK`, `WARNINGS: 2`, an error message),
    /// once the task has one.
    pub exit_status: Option<String>,
    /// The Fleet operation that started this task, or null when Fleet did
    /// not start it or the caller may not read operations.
    pub fleet_operation_id: Option<String>,
}

impl From<ProxmoxTask> for ProxmoxTaskDto {
    fn from(task: ProxmoxTask) -> Self {
        Self {
            upid: task.upid,
            node: task.node,
            task_type: task.task_type,
            target_id: task.target_id,
            user: task.user,
            token_id: task.token_id,
            started_at: task.started_at,
            ended_at: task.ended_at,
            status: task.status.into(),
            exit_status: task.exit_status,
            fleet_operation_id: task.fleet_operation_id,
        }
    }
}

/// One page of an account's task history, newest first. The page shape
/// (`items`, `page`) is the standard one; the snapshot facts ride along.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxTaskPage {
    /// The tasks on this page.
    pub items: Vec<ProxmoxTaskDto>,
    /// Where this page sits in the snapshot.
    pub page: PageInfo,
    /// The account that produced the snapshot.
    pub account_id: String,
    /// The PVE version seen.
    pub pve_version: String,
    /// What the snapshot is missing and why: unreadable or offline nodes,
    /// malformed entries, a per-node bound reached, a withheld operation
    /// link. These describe the whole snapshot, so every page repeats them.
    pub warnings: Vec<String>,
    /// When the snapshot was taken (epoch millis).
    pub observed_at: i64,
}

/// The task-history query parameters.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListProxmoxTasksParams {
    /// Only this node's tasks.
    pub node: Option<String>,
    /// Only this guest's tasks.
    pub vmid: Option<u32>,
    /// Only tasks in this status: `running`, `ok`, `error`, or `unknown`.
    pub status: Option<String>,
    /// The maximum number of tasks to return.
    pub limit: Option<u32>,
    /// The opaque cursor: the last task's UPID from the previous page.
    pub cursor: Option<String>,
}

/// Lists the account's recent PVE tasks, newest first, each linked to the
/// Fleet operation that started it.
///
/// # Errors
///
/// Returns the public error envelope on refusal, a malformed filter or
/// stale cursor, an unconfirmed account, or a whole-read source failure.
/// A node that cannot be read is a warning, not an error.
#[utoipa::path(
    get,
    path = "/proxmox/accounts/{accountId}/tasks",
    tag = "proxmox",
    operation_id = "listProxmoxTasks",
    params(
        ("accountId" = String, Path, description = "The account's identity."),
        ("node" = Option<String>, Query, description = "Only this node's tasks."),
        ("vmid" = Option<u32>, Query, description = "Only this guest's tasks."),
        (
            "status" = Option<String>,
            Query,
            description = "Only tasks in this status: running, ok, error, or unknown."
        ),
        ("limit" = Option<u32>, Query, description = "The maximum number of tasks to return."),
        (
            "cursor" = Option<String>,
            Query,
            description = "The opaque cursor: the last task's UPID from the previous page."
        ),
    ),
    responses(
        (
            status = 200,
            description = "One page of the task history, with per-node warnings.",
            body = ProxmoxTaskPage
        ),
        (
            status = 400,
            description = "A filter is malformed, or the cursor names no task in the snapshot.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not read the Proxmox surface.",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "The account does not exist.",
            body = crate::error::ApiError
        ),
        (
            status = 409,
            description = "The account's trust is unconfirmed or the host fingerprint was refused.",
            body = crate::error::ApiError
        ),
        (
            status = 502,
            description = "The PVE API refused the token or failed before any node was read.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn list_proxmox_tasks(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(account_id): Path<String>,
    Query(params): Query<ListProxmoxTasksParams>,
) -> Result<Json<ProxmoxTaskPage>, ApiErrorResponse> {
    let proxmox = proxmox_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let snapshot = proxmox
        .task_history(
            state.authorizer.as_ref(),
            &principal,
            &account_id,
            &TaskHistoryQuery {
                node: params.node,
                vmid: params.vmid,
                status: params.status,
            },
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_proxmox_error(&error, correlation_id))?;
    let limit = params
        .limit
        .filter(|limit| *limit > 0)
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .min(MAX_PAGE_LIMIT);
    let start = match &params.cursor {
        Some(cursor) => {
            let Some(position) = snapshot.tasks.iter().position(|task| task.upid == *cursor) else {
                // A stale or malformed cursor is a client error, not a
                // silent restart from the first page.
                return Err(crate::machines::invalid_request(
                    "the cursor names no task in the snapshot",
                    correlation_id,
                ));
            };
            position + 1
        }
        None => 0,
    };
    let take = usize::try_from(limit).unwrap_or(usize::MAX);
    // A cursor only when tasks remain after this page, so a page that
    // exactly consumed the snapshot does not advertise an empty one.
    let has_more = snapshot.tasks.len() > start.saturating_add(take);
    let page: Vec<ProxmoxTask> = snapshot.tasks.into_iter().skip(start).take(take).collect();
    let next_cursor = has_more
        .then(|| page.last().map(|task| task.upid.clone()))
        .flatten();
    Ok(Json(ProxmoxTaskPage {
        items: page.into_iter().map(Into::into).collect(),
        page: PageInfo { next_cursor, limit },
        account_id: snapshot.account_id,
        pve_version: snapshot.pve_version,
        warnings: snapshot.warnings,
        observed_at: snapshot.observed_at,
    }))
}
