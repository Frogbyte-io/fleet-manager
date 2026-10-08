//! The Lab pool surface (FM-717): pools of preallocated guests for one
//! template version, and their explicit, audited fill and drain. The rules
//! and the authorization are `fleet_application::lab_pool`'s.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use fleet_application::lab_pool::{DrainReport, LabPool, LabPools, NewLabPool, PoolMember};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};
use crate::lab::{lab_or_error, map_lab_error};

fn pools_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<LabPools>, ApiErrorResponse> {
    let lab = lab_or_error(state, correlation_id)?;
    lab.pools().cloned().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "Lab pools are not wired; the controller needs its database",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// One pool member.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LabPoolMemberDto {
    /// The member's identity; a refill after a drain gets a new one.
    pub id: String,
    /// The guest's VMID.
    pub vmid: u32,
    /// The node the guest was last seen on, once verified.
    pub node: Option<String>,
    /// The guest's name when its fill verified it.
    pub name: Option<String>,
    /// `filling`, `available`, `leased`, or `quarantined`.
    pub state: String,
    /// The lease it is bound to, when any. A quarantined member can still
    /// be bound: its lease's cleanup still owes the revert.
    pub lease_id: Option<String>,
    /// Whether it leaves the pool once its lease's cleanup or its fill ends.
    pub draining: bool,
    /// Why it is quarantined, when it is.
    pub detail: Option<String>,
    /// When it last changed (epoch millis).
    pub updated_at: i64,
}

impl From<PoolMember> for LabPoolMemberDto {
    fn from(member: PoolMember) -> Self {
        Self {
            id: member.id,
            vmid: member.vmid,
            node: member.node,
            name: member.name,
            state: member.state.id().to_owned(),
            lease_id: member.lease_id,
            draining: member.draining,
            detail: member.detail,
            updated_at: member.updated_at,
        }
    }
}

/// One pool and its members.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LabPoolDto {
    /// The pool's identity.
    pub id: String,
    /// The published template version leases take members for.
    pub template_version_id: String,
    /// The Proxmox account the members are reached through.
    pub account_id: String,
    /// The snapshot every member is reverted to.
    pub baseline_snapshot: String,
    /// The declared number of members.
    pub size: u32,
    /// Who created the pool.
    pub created_by: String,
    /// When the pool was created (epoch millis).
    pub created_at: i64,
    /// The members, by VMID.
    pub members: Vec<LabPoolMemberDto>,
}

impl From<(LabPool, Vec<PoolMember>)> for LabPoolDto {
    fn from((pool, members): (LabPool, Vec<PoolMember>)) -> Self {
        Self {
            id: pool.id,
            template_version_id: pool.template_version_id,
            account_id: pool.account_id,
            baseline_snapshot: pool.baseline_snapshot,
            size: pool.size,
            created_by: pool.created_by,
            created_at: pool.created_at,
            members: members.into_iter().map(Into::into).collect(),
        }
    }
}

/// A pool creation request.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateLabPoolRequest {
    /// A published template version whose cleanup strategy is `revert`.
    pub template_version_id: String,
    /// The Proxmox account the members are reached through.
    pub account_id: String,
    /// The snapshot every member carries and is reverted to (a PVE
    /// snapshot name, at most 40 characters).
    pub baseline_snapshot: String,
    /// The declared number of members, 1 to 16.
    pub size: u32,
}

/// A fill request.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FillLabPoolRequest {
    /// The VMIDs of existing QEMU guests that carry the baseline snapshot.
    /// Empty re-queues the verification of members still filling.
    pub vmids: Vec<u32>,
}

/// A drain request.
#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DrainLabPoolRequest {
    /// The VMIDs to drain; every member when absent.
    #[serde(default)]
    pub vmids: Option<Vec<u32>>,
}

/// What a drain did.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LabPoolDrainDto {
    /// The VMIDs that left the pool. The guests themselves stay.
    pub removed: Vec<u32>,
    /// The VMIDs that leave once their lease's cleanup or their fill ends.
    pub deferred: Vec<u32>,
}

impl From<DrainReport> for LabPoolDrainDto {
    fn from(report: DrainReport) -> Self {
        Self {
            removed: report.removed,
            deferred: report.deferred,
        }
    }
}

/// Lists the pools and their members.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/lab/pools",
    tag = "lab",
    operation_id = "listLabPools",
    responses(
        (status = 200, description = "The pools, newest first.", body = Page<LabPoolDto>),
        (status = 403, description = "The caller may not read the Lab surface.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
    )
)]
pub async fn list_lab_pools(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<Page<LabPoolDto>>, ApiErrorResponse> {
    let pools = pools_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let items: Vec<LabPoolDto> = pools
        .list(state.authorizer.as_ref(), &principal)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(Json(Page {
        page: PageInfo {
            next_cursor: None,
            limit: items.len().try_into().unwrap_or(u32::MAX),
        },
        items,
    }))
}

/// Creates a pool for a published template version whose cleanup strategy
/// is `revert`. Leases from that version then take a pool member instead of
/// a clone.
///
/// # Errors
///
/// Returns the public error envelope on refusal, malformed input, an
/// unknown version or account, or a version that already has a pool.
#[utoipa::path(
    post,
    path = "/lab/pools",
    tag = "lab",
    operation_id = "createLabPool",
    request_body = CreateLabPoolRequest,
    responses(
        (status = 201, description = "The pool was created, empty.", body = Resource<LabPoolDto>),
        (status = 400, description = "The request is malformed, or the version does not revert.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not configure the Lab surface.", body = crate::error::ApiError),
        (status = 404, description = "The template version or account does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The template version already has a pool.", body = crate::error::ApiError),
    )
)]
pub async fn create_lab_pool(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Json(request): Json<CreateLabPoolRequest>,
) -> Result<(StatusCode, Json<Resource<LabPoolDto>>), ApiErrorResponse> {
    let pools = pools_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let pool = pools
        .create(
            state.authorizer.as_ref(),
            &principal,
            NewLabPool {
                template_version_id: request.template_version_id,
                account_id: request.account_id,
                baseline_snapshot: request.baseline_snapshot,
                size: request.size,
            },
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok((
        StatusCode::CREATED,
        Json(Resource::new((pool, Vec::new()).into())),
    ))
}

/// Reads one pool and its members.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown pool.
#[utoipa::path(
    get,
    path = "/lab/pools/{poolId}",
    tag = "lab",
    operation_id = "getLabPool",
    params(("poolId" = String, Path, description = "The pool's identity.")),
    responses(
        (status = 200, description = "The pool.", body = Resource<LabPoolDto>),
        (status = 403, description = "The caller may not read the Lab surface.", body = crate::error::ApiError),
        (status = 404, description = "The pool does not exist.", body = crate::error::ApiError),
    )
)]
pub async fn get_lab_pool(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(pool_id): Path<String>,
) -> Result<Json<Resource<LabPoolDto>>, ApiErrorResponse> {
    let pools = pools_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let pool = pools
        .get(state.authorizer.as_ref(), &principal, &pool_id)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(Json(Resource::new(pool.into())))
}

/// Deletes an empty pool (drain it first). Leases from its template version
/// then clone again.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown pool, or a pool
/// that still holds members.
#[utoipa::path(
    delete,
    path = "/lab/pools/{poolId}",
    tag = "lab",
    operation_id = "deleteLabPool",
    params(("poolId" = String, Path, description = "The pool's identity.")),
    responses(
        (status = 204, description = "The pool was deleted."),
        (status = 403, description = "The caller may not configure the Lab surface.", body = crate::error::ApiError),
        (status = 404, description = "The pool does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The pool still holds members.", body = crate::error::ApiError),
    )
)]
pub async fn delete_lab_pool(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(pool_id): Path<String>,
) -> Result<StatusCode, ApiErrorResponse> {
    let pools = pools_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    pools
        .delete(state.authorizer.as_ref(), &principal, &pool_id)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Registers existing QEMU guests as pool members and queues the
/// `lab.pool.fill` operation that checks each one, reverts it to the
/// baseline snapshot through the reviewed revert, and verifies it. A
/// member becomes `available` only once verified; otherwise it is
/// `quarantined` with the reason.
///
/// # Errors
///
/// Returns the public error envelope on refusal, invalid VMIDs, an unknown
/// pool, a full pool, or a guest that already is a pool member.
#[utoipa::path(
    post,
    path = "/lab/pools/{poolId}/fill",
    tag = "lab",
    operation_id = "fillLabPool",
    params(("poolId" = String, Path, description = "The pool's identity.")),
    request_body = FillLabPoolRequest,
    responses(
        (status = 202, description = "The members were registered and their verification queued.", body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The VMIDs are invalid or exceed the pool's size.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not configure the Lab surface or create operations.", body = crate::error::ApiError),
        (status = 404, description = "The pool does not exist.", body = crate::error::ApiError),
        (status = 409, description = "A guest already is a pool member, or the pool is full.", body = crate::error::ApiError),
    )
)]
pub async fn fill_lab_pool(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(pool_id): Path<String>,
    Json(request): Json<FillLabPoolRequest>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let pools = pools_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let (_added, mut new) = pools
        .request_fill(
            state.authorizer.as_ref(),
            &principal,
            &pool_id,
            &request.vmids,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    new.correlation_id = Some(correlation_id.to_string());
    let operation = state
        .operations
        .create_lab_pool_fill(state.authorizer.as_ref(), &principal.id, &pool_id, &new)
        .await
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
    Ok((StatusCode::ACCEPTED, Json(Resource::new(operation.into()))))
}

/// Drains members from a pool (every member when no VMIDs are named).
/// Unbound members leave at once; a member bound to a lease, or still
/// filling, leaves once that finishes instead of returning to the pool.
/// Fleet never destroys a pool guest: drained guests stay where they are.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown pool or VMID.
#[utoipa::path(
    post,
    path = "/lab/pools/{poolId}/drain",
    tag = "lab",
    operation_id = "drainLabPool",
    params(("poolId" = String, Path, description = "The pool's identity.")),
    request_body = DrainLabPoolRequest,
    responses(
        (status = 200, description = "What the drain did.", body = Resource<LabPoolDrainDto>),
        (status = 403, description = "The caller may not configure the Lab surface.", body = crate::error::ApiError),
        (status = 404, description = "The pool, or a named VMID in it, does not exist.", body = crate::error::ApiError),
    )
)]
pub async fn drain_lab_pool(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(pool_id): Path<String>,
    Json(request): Json<DrainLabPoolRequest>,
) -> Result<Json<Resource<LabPoolDrainDto>>, ApiErrorResponse> {
    let pools = pools_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let report = pools
        .drain(
            state.authorizer.as_ref(),
            &principal,
            &pool_id,
            request.vmids.as_deref(),
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(Json(Resource::new(report.into())))
}
