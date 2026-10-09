//! Detached Lab commands (#394): `POST /lab/leases/{leaseId}/exec-detached`
//! starts a command that outlives one exec, and
//! `GET /lab/detached-execs/{handle}` reads its state.
//!
//! The handlers are adapters: authorization, owner scope, audit, the lease
//! checks, the scrubber and the bounds live in the application's
//! `LabExecDetach`.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use fleet_application::lab::LabUseCaseError;
use fleet_application::lab_exec_detach::{DetachedStatus, LabExecDetach};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::{ApiError, ApiErrorResponse};
use crate::lab::{lab_or_error, map_lab_error};

/// A command to start detached on a ready lease's guest.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExecDetachedRequest {
    /// The shell script to run (at most 64 KiB). It is never audited and
    /// never stored; only its SHA-256 and size are recorded.
    pub script: String,
    /// The bound in seconds, enforced in the guest. It defaults to, and can
    /// never exceed, what is left of the lease's TTL: a detached command
    /// cannot outlive its lease or extend it.
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

/// A started detached command.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DetachedExecStartedDto {
    /// The handle to poll: the id of the start operation.
    pub handle: String,
    /// The lease.
    pub lease_id: String,
    /// The bound the guest enforces, in seconds.
    pub timeout_seconds: u64,
    /// The `lab.exec_detach` operation that starts the command. It ends
    /// when the guest has started the command, not when the command ends.
    pub operation: crate::operations::OperationDto,
}

/// The state of a detached command.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DetachedExecStatusDto {
    /// The handle.
    pub handle: String,
    /// The lease.
    pub lease_id: String,
    /// `starting`, `running`, `exited`, `lost`, `failed_to_start`,
    /// `lease_ended`, or `unreachable`.
    pub state: String,
    /// Whether the answer will never change: `exited`, `lost`,
    /// `failed_to_start`, and `lease_ended`. `unreachable` and `starting`
    /// are not terminal; poll again.
    pub terminal: bool,
    /// The exit code, once `exited`. `124` means the command's time bound
    /// ended it.
    pub exit_code: Option<i32>,
    /// A stable reason for `lost` (`guest_rebooted`, `process_gone`,
    /// `never_started`, `guest_has_no_record`), `failed_to_start`
    /// (`start_failed`; see the operation), `lease_ended`, and
    /// `unreachable` (`guest_unreachable`, `no_lab_machine`).
    pub reason: Option<String>,
    /// The lease's state, when `lease_ended`.
    pub lease_state: Option<String>,
    /// The bound the guest enforces, in seconds.
    pub timeout_seconds: u64,
    /// When the command started (the guest's clock, epoch seconds).
    pub started_at: Option<i64>,
    /// When the command finished (the guest's clock, epoch seconds).
    pub finished_at: Option<i64>,
    /// The last of stdout, scrubbed of credentials and bounded like `lab
    /// exec` output.
    pub stdout: String,
    /// The last of stderr, scrubbed and bounded likewise.
    pub stderr: String,
    /// Whether output was dropped from the front of stdout.
    pub truncated_stdout: bool,
    /// Whether output was dropped from the front of stderr.
    pub truncated_stderr: bool,
    /// The size of stdout in the guest, in bytes.
    pub stdout_bytes: u64,
    /// The size of stderr in the guest, in bytes.
    pub stderr_bytes: u64,
}

impl From<DetachedStatus> for DetachedExecStatusDto {
    fn from(status: DetachedStatus) -> Self {
        Self {
            handle: status.handle,
            lease_id: status.lease_id,
            state: status.state.id().to_owned(),
            terminal: status.state.is_terminal(),
            exit_code: status.exit_code,
            reason: status.reason,
            lease_state: status.lease_state,
            timeout_seconds: status.timeout_seconds,
            started_at: status.started_at,
            finished_at: status.finished_at,
            stdout: status.stdout,
            stderr: status.stderr,
            truncated_stdout: status.truncated_stdout,
            truncated_stderr: status.truncated_stderr,
            stdout_bytes: status.stdout_bytes,
            stderr_bytes: status.stderr_bytes,
        }
    }
}

fn detached_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<LabExecDetach>, ApiErrorResponse> {
    let lab = lab_or_error(state, correlation_id)?;
    lab.detached().cloned().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "detached exec is not wired; the controller needs its database",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// Starts a command on a ready lease's guest and returns at once with a
/// handle. The command runs in the guest, outside the SSH session, until it
/// exits, hits its bound, or the lease ends. Poll
/// `GET /lab/detached-execs/{handle}`. A retry with the same
/// `Idempotency-Key` returns the same handle and starts nothing twice.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown lease, a lease
/// that is not ready or about to expire, or an invalid command.
#[utoipa::path(
    post,
    path = "/lab/leases/{leaseId}/exec-detached",
    tag = "lab",
    operation_id = "execDetachedLabLease",
    params(("leaseId" = String, Path, description = "The lease's identity.")),
    request_body = ExecDetachedRequest,
    responses(
        (status = 202, description = "The command is being started as a `lab.exec_detach` operation; poll its handle.", body = Resource<DetachedExecStartedDto>),
        (status = 400, description = "The lease is not ready, has expired or is about to, its guest has no Lab machine, or the command is invalid.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not run commands on Lab leases.", body = crate::error::ApiError),
        (status = 404, description = "The lease does not exist (or is another owner's).", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn exec_detached_lab_lease(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(lease_id): Path<String>,
    headers: axum::http::HeaderMap,
    request: Result<Json<ExecDetachedRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<DetachedExecStartedDto>>), ApiErrorResponse> {
    let detached = detached_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        map_lab_error(
            &LabUseCaseError::Invalid {
                detail: "the request body must be valid JSON with a script".to_owned(),
            },
            correlation_id,
        )
    })?;
    let now = fleet_core::SystemClock::now_unix_millis();
    let mut prepared = detached
        .prepare_start(
            state.authorizer.as_ref(),
            &principal,
            &lease_id,
            &request.script,
            request.timeout_seconds,
            headers
                .get(crate::IDEMPOTENCY_KEY_HEADER)
                .and_then(|value| value.to_str().ok()),
            now,
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    prepared.operation.correlation_id = Some(correlation_id.to_string());
    let operation = state
        .operations
        .create_lab_exec_detach(
            state.authorizer.as_ref(),
            &principal.id,
            &lease_id,
            &prepared.operation,
        )
        .await
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
    detached
        .register(&prepared, &operation.id, now)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(Resource::new(DetachedExecStartedDto {
            handle: operation.id.clone(),
            lease_id,
            timeout_seconds: prepared.timeout_seconds,
            operation: operation.into(),
        })),
    ))
}

/// Reads a detached command's state, exit code, and bounded output tails.
/// A read of the guest, not an operation. A handle whose lease has been
/// released or has expired answers `lease_ended`, a terminal state, rather
/// than an error. A handle of another owner reads as not found.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown handle.
#[utoipa::path(
    get,
    path = "/lab/detached-execs/{handle}",
    tag = "lab",
    operation_id = "getDetachedExec",
    params(("handle" = String, Path, description = "The handle `exec-detached` returned.")),
    responses(
        (status = 200, description = "The command's state.", body = Resource<DetachedExecStatusDto>),
        (status = 403, description = "The caller may not read detached commands.", body = crate::error::ApiError),
        (status = 404, description = "The handle does not exist (or is another owner's).", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn get_detached_exec(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(handle): Path<String>,
) -> Result<Json<Resource<DetachedExecStatusDto>>, ApiErrorResponse> {
    let detached = detached_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let status = detached
        .status(
            state.authorizer.as_ref(),
            &principal,
            &handle,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(Json(Resource::new(status.into())))
}
