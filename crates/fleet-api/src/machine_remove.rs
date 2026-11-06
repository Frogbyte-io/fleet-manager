//! Removing a machine (#616): `POST /machines/{machineId}/remove/review` and
//! `POST /machines/{machineId}/remove`.
//!
//! The handlers are adapters. Authorization (`machine.delete`, resource = the
//! machine id), the holds that refuse a removal, the review token that binds
//! the removal to the reviewed request, the optional fleetd uninstall, the
//! host-key unpinning and the audit all live in
//! `fleet_application::machine_remove`. The removal is synchronous: the
//! answer says what was deleted, what was unpinned, and whether fleetd was
//! uninstalled. It runs on its own task, so a caller that disconnects does
//! not cancel it half-way: an uninstall that started is always followed by
//! the delete (or its refusal) and the audit.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use fleet_application::machine_remove::{
    MachineRemoval, MachineRemovalError, RemovalBlocker, RemovalFootprint, RemovalOutcome,
    RemovalReview, ReviewedEndpoint, UninstallPlan, UninstallRequest,
};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::{ApiError, ApiErrorResponse};
use crate::machine_access::EndpointAuthDto;

/// The fleetd uninstall a removal runs first.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineUninstallDto {
    /// The machine's SSH endpoint the uninstall runs over.
    pub endpoint_id: String,
    /// How to authenticate. In a request, absent means the endpoint's stored
    /// default, or the controller's agent when it has none; a review answers
    /// the resolved value.
    pub auth: Option<EndpointAuthDto>,
}

impl From<MachineUninstallDto> for UninstallRequest {
    fn from(dto: MachineUninstallDto) -> Self {
        Self {
            endpoint_id: dto.endpoint_id,
            auth: dto.auth.map(Into::into),
        }
    }
}

/// The fleetd uninstall a removal will run, as the review resolved it.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineUninstallPlanDto {
    /// The SSH endpoint the uninstall runs over.
    pub endpoint_id: String,
    /// The authentication it uses.
    pub auth: EndpointAuthDto,
    /// The installer layout overrides (`FLEETD_BIN_DIR`, `FLEETD_UNIT_DIR`,
    /// `FLEETD_ENV_FILE`, `FLEETD_STATE_DIR`, `FLEETD_SERVICE`,
    /// `FLEETD_SYSTEMCTL`) of the machine's last successful fleetd install;
    /// empty for the default layout. The uninstall fails when no fleetd unit
    /// or binary is found in this layout.
    pub layout: std::collections::BTreeMap<String, String>,
}

impl From<UninstallPlan> for MachineUninstallPlanDto {
    fn from(plan: UninstallPlan) -> Self {
        Self {
            endpoint_id: plan.endpoint_id,
            auth: plan.auth.into(),
            layout: plan.layout,
        }
    }
}

/// What to review.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewMachineRemovalRequest {
    /// Run the fleetd uninstall over SSH before the removal. Without it,
    /// nothing on the machine is touched.
    pub uninstall: Option<MachineUninstallDto>,
}

/// What to remove, and the review it was reviewed in.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoveMachineRequest {
    /// The same uninstall the review was asked for, when any.
    pub uninstall: Option<MachineUninstallDto>,
    /// The token the review answered.
    pub review_token: String,
}

/// One endpoint of the machine.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RemovalEndpointDto {
    /// The endpoint.
    pub id: String,
    /// `ssh` or `fleetd`.
    pub kind: String,
    /// The SSH host, for an SSH endpoint.
    pub host: Option<String>,
}

impl From<ReviewedEndpoint> for RemovalEndpointDto {
    fn from(endpoint: ReviewedEndpoint) -> Self {
        Self {
            id: endpoint.id,
            kind: endpoint.kind,
            host: endpoint.host,
        }
    }
}

/// Something that refuses the removal, and what to do about it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RemovalBlockerDto {
    /// `lab_provision`, `persistent_marker`, `hardware_reservation` or
    /// `active_operation`.
    pub kind: String,
    /// The holding record.
    pub id: String,
    /// Its state.
    pub state: String,
    /// The refusal and what to do.
    pub detail: String,
}

impl From<RemovalBlocker> for RemovalBlockerDto {
    fn from(blocker: RemovalBlocker) -> Self {
        Self {
            kind: blocker.kind,
            id: blocker.id,
            state: blocker.state,
            detail: blocker.detail,
        }
    }
}

/// The records a removal deletes, and the collected files it keeps. The
/// stored-secret counts are bound by the review token.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RemovalFootprintDto {
    /// Endpoints.
    pub endpoints: u64,
    /// Stored default endpoint authentication records.
    pub endpoint_auth: u64,
    /// Endpoints whose stored default authentication is a stored key.
    pub endpoint_auth_secrets: u64,
    /// Capability facts.
    pub capabilities: u64,
    /// Inventory snapshots.
    pub inventory_snapshots: u64,
    /// Tag and group memberships.
    pub tags_and_groups: u64,
    /// Node identity records (0 or 1).
    pub node_identity: u64,
    /// Node credentials, sessions, challenges and enrollment tokens.
    pub node_credentials: u64,
    /// Project checkout observations.
    pub project_checkouts: u64,
    /// Skills Manager snapshots (0 or 1).
    pub skills_snapshot: u64,
    /// Recorded catalog skill installs.
    pub catalog_skill_installs: u64,
    /// Confirmed Proxmox guest links (0 or 1).
    pub guest_link: u64,
    /// SSH private keys Fleet holds for this machine; revoked.
    pub stored_ssh_keys: u64,
    /// Rotated Windows administrator passwords Fleet holds for this machine;
    /// destroyed, so nobody can read them afterwards.
    pub admin_passwords: u64,
    /// Collected files, kept until their retention pass.
    pub collected_files_kept: u64,
}

impl From<RemovalFootprint> for RemovalFootprintDto {
    fn from(footprint: RemovalFootprint) -> Self {
        Self {
            endpoints: footprint.endpoints,
            endpoint_auth: footprint.endpoint_auth,
            endpoint_auth_secrets: footprint.endpoint_auth_secrets,
            capabilities: footprint.capabilities,
            inventory_snapshots: footprint.inventory_snapshots,
            tags_and_groups: footprint.tags_and_groups,
            node_identity: footprint.node_identity,
            node_credentials: footprint.node_credentials,
            project_checkouts: footprint.project_checkouts,
            skills_snapshot: footprint.skills_snapshot,
            catalog_skill_installs: footprint.catalog_skill_installs,
            guest_link: footprint.guest_link,
            stored_ssh_keys: footprint.stored_ssh_keys,
            admin_passwords: footprint.admin_passwords,
            collected_files_kept: footprint.collected_files_kept,
        }
    }
}

/// What a removal would do, and the token that binds the removal to it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineRemovalReviewDto {
    /// The token the removal must present; null while `blockers` is not
    /// empty.
    pub review_token: Option<String>,
    /// The machine.
    pub machine_id: String,
    /// Its name.
    pub name: String,
    /// Its endpoints.
    pub endpoints: Vec<RemovalEndpointDto>,
    /// The node identity's status (`active` or `revoked`), when it has one;
    /// the identity is deleted with the machine.
    pub node_identity: Option<String>,
    /// The hosts whose pinned SSH host keys are removed.
    pub unpin_hosts: Vec<String>,
    /// The hosts whose pins stay because another machine or an onboarding
    /// draft uses them.
    pub kept_hosts: Vec<String>,
    /// The fleetd uninstall that runs first, with its resolved
    /// authentication and layout, when asked.
    pub uninstall: Option<MachineUninstallPlanDto>,
    /// What is deleted, and the collected files that are kept.
    pub footprint: RemovalFootprintDto,
    /// What to know before confirming, for example that a stored Windows
    /// administrator password is destroyed.
    pub warnings: Vec<String>,
    /// What refuses the removal now, each with what to do: a Lab provision,
    /// a persistent marker, a USB reservation, an unfinished operation, or
    /// (on a controller without its secret store) stored secrets it could
    /// not revoke.
    pub blockers: Vec<RemovalBlockerDto>,
}

impl From<RemovalReview> for MachineRemovalReviewDto {
    fn from(review: RemovalReview) -> Self {
        Self {
            review_token: review.review_token,
            machine_id: review.machine_id,
            name: review.name,
            endpoints: review.endpoints.into_iter().map(Into::into).collect(),
            node_identity: review.node_identity,
            unpin_hosts: review.unpin_hosts,
            kept_hosts: review.kept_hosts,
            uninstall: review.uninstall.map(Into::into),
            footprint: review.footprint.into(),
            warnings: review.warnings,
            blockers: review.blockers.into_iter().map(Into::into).collect(),
        }
    }
}

/// What a removal did.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineRemovedDto {
    /// The removed machine.
    pub machine_id: String,
    /// Its name.
    pub name: String,
    /// Always true: the machine record is gone.
    pub removed: bool,
    /// Whether fleetd was uninstalled first.
    pub uninstalled: bool,
    /// The uninstall's last line of output, when it ran.
    pub uninstall_summary: Option<String>,
    /// Whether a node identity was deleted with the machine.
    pub node_identity_removed: bool,
    /// Whether a live node gateway session was closed.
    pub session_closed: bool,
    /// The stored secrets bound to the machine that were revoked.
    pub secrets_revoked: u64,
    /// Why revoking the machine's stored secrets failed, when it did; the
    /// machine is removed and the secrets must be deleted by hand.
    pub secret_revocation_error: Option<String>,
    /// The hosts whose pinned keys were removed.
    pub unpinned_hosts: Vec<String>,
    /// The hosts whose pins stayed because they are shared, including hosts
    /// another machine or draft started using during the removal.
    pub kept_hosts: Vec<String>,
    /// The hosts whose pins could not be removed; remove them from the
    /// controller's known-hosts file by hand.
    pub unpin_failed_hosts: Vec<String>,
    /// What was deleted.
    pub footprint: RemovalFootprintDto,
}

impl From<RemovalOutcome> for MachineRemovedDto {
    fn from(outcome: RemovalOutcome) -> Self {
        Self {
            machine_id: outcome.machine_id,
            name: outcome.name,
            removed: true,
            uninstalled: outcome.uninstalled,
            uninstall_summary: outcome.uninstall_summary,
            node_identity_removed: outcome.node_identity_removed,
            session_closed: outcome.session_closed,
            secrets_revoked: outcome.secrets_revoked,
            secret_revocation_error: outcome.secret_revocation_error,
            unpinned_hosts: outcome.unpinned_hosts,
            kept_hosts: outcome.kept_hosts,
            unpin_failed_hosts: outcome.unpin_failed_hosts,
            footprint: outcome.footprint.into(),
        }
    }
}

fn error(
    status: StatusCode,
    code: &str,
    message: impl Into<String>,
    retry: RetryClass,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    let public = PublicError::new(
        ErrorCode::from_str(code).expect("the literal is valid error code syntax"),
        message.into(),
        retry,
    );
    ApiError::new(&public, correlation_id).with_status(status)
}

fn removal_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<MachineRemoval>, ApiErrorResponse> {
    state
        .lab
        .as_ref()
        .and_then(|lab| lab.machine_removal().cloned())
        .ok_or_else(|| {
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "machine_removal_unavailable",
                "machine removal is not wired; the controller needs its database",
                RetryClass::Backoff,
                correlation_id,
            )
        })
}

/// Maps a removal refusal onto the public envelope.
pub(crate) fn map_removal_error(
    failure: &MachineRemovalError,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    let message = failure.to_string();
    match failure {
        MachineRemovalError::Denied(_) => error(
            StatusCode::FORBIDDEN,
            "denied",
            message,
            RetryClass::Never,
            correlation_id,
        ),
        MachineRemovalError::NotFound { .. } => error(
            StatusCode::NOT_FOUND,
            "not_found",
            message,
            RetryClass::Never,
            correlation_id,
        ),
        MachineRemovalError::Invalid { .. } => error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            message,
            RetryClass::Never,
            correlation_id,
        ),
        MachineRemovalError::Blocked { .. } => error(
            StatusCode::CONFLICT,
            "machine_removal_blocked",
            message,
            RetryClass::Never,
            correlation_id,
        ),
        MachineRemovalError::Conflict { .. } => error(
            StatusCode::CONFLICT,
            "conflict",
            message,
            RetryClass::Never,
            correlation_id,
        ),
        MachineRemovalError::UninstallUnavailable => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "machine_uninstall_unavailable",
            message,
            RetryClass::Never,
            correlation_id,
        ),
        MachineRemovalError::UninstallFailed { .. } => error(
            StatusCode::BAD_GATEWAY,
            "fleetd_uninstall_failed",
            message,
            RetryClass::Backoff,
            correlation_id,
        ),
        MachineRemovalError::Backend { .. } => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "the request could not be completed; the detail is in the controller log",
            RetryClass::Backoff,
            correlation_id,
        ),
    }
}

/// Reviews removing a machine: what is deleted (endpoints, facts, node
/// identity, project checkouts, Skills Manager snapshot, recorded skill
/// installs, guest link), which pinned host keys are removed and which stay
/// because another machine or an onboarding draft shares the host, the
/// fleetd uninstall when asked for, and every record that refuses the
/// removal now (a Lab provision, a persistent marker, a USB reservation, an
/// unfinished operation), each with what to do. Nothing is written.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown machine, or an
/// uninstall endpoint that is not one of the machine's SSH endpoints.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/remove/review",
    tag = "machines",
    operation_id = "reviewMachineRemoval",
    params(("machineId" = String, Path, description = "The machine's identity.")),
    request_body = ReviewMachineRemovalRequest,
    responses(
        (status = 200, description = "The review; present its token to the removal. The token is null while blockers remain.", body = Resource<MachineRemovalReviewDto>),
        (status = 400, description = "The body is malformed, or the uninstall endpoint is not one of the machine's SSH endpoints.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not delete machines (`machine.delete`).", body = crate::error::ApiError),
        (status = 404, description = "The machine does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Machine removal, or the uninstall, is not wired (`machine_removal_unavailable`, `machine_uninstall_unavailable`).", body = crate::error::ApiError),
    )
)]
pub async fn review_machine_removal(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
    request: Result<Json<ReviewMachineRemovalRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Resource<MachineRemovalReviewDto>>, ApiErrorResponse> {
    let removal = removal_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request body must be a JSON object, with an optional uninstall",
            RetryClass::Never,
            correlation_id,
        )
    })?;
    let uninstall = request.uninstall.map(UninstallRequest::from);
    removal
        .review(
            state.authorizer.as_ref(),
            &principal,
            &machine_id,
            uninstall.as_ref(),
        )
        .await
        .map(|review| Json(Resource::new(review.into())))
        .map_err(|failure| map_removal_error(&failure, correlation_id))
}

/// Removes a reviewed machine. Every hold is checked again; then, when
/// asked, the fleetd uninstall runs over SSH (`uninstall.sh --purge`) and a
/// failure leaves the machine registered; then the record and every fact
/// about it are deleted, the keys bound to it are revoked, and the pinned
/// host keys of hosts nobody else uses are removed. The audit trail,
/// finished operations and collected files stay. Without an uninstall,
/// nothing on the machine is touched. Audited.
///
/// # Errors
///
/// Returns the public error envelope on refusal, a review token that does
/// not match, a hold, or a failed uninstall.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/remove",
    tag = "machines",
    operation_id = "removeMachine",
    params(("machineId" = String, Path, description = "The machine's identity.")),
    request_body = RemoveMachineRequest,
    responses(
        (status = 200, description = "The machine is removed.", body = Resource<MachineRemovedDto>),
        (status = 400, description = "The body is malformed, or the review token does not match the machine as it is now.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not delete machines (`machine.delete`).", body = crate::error::ApiError),
        (status = 404, description = "The machine does not exist.", body = crate::error::ApiError),
        (status = 409, description = "Refused: `machine_removal_blocked` (a Lab provision, persistent marker, USB reservation, unfinished operation, or stored secrets a controller without its secret store cannot revoke; the message says what to do) or `conflict` (a hold appeared after the review, or during the uninstall, and the guarded delete refused it; nothing was deleted).", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 502, description = "The fleetd uninstall failed (`fleetd_uninstall_failed`); the machine was not removed.", body = crate::error::ApiError),
        (status = 503, description = "Machine removal, or the uninstall, is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn remove_machine(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
    request: Result<Json<RemoveMachineRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Resource<MachineRemovedDto>>, ApiErrorResponse> {
    let removal = removal_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request body must be valid JSON with a reviewToken and an optional uninstall",
            RetryClass::Never,
            correlation_id,
        )
    })?;
    let uninstall = request.uninstall.map(UninstallRequest::from);
    let correlation = correlation_id.to_string();
    let authorizer = state.authorizer.clone();
    // The removal runs to completion on its own task: if the caller goes
    // away, an uninstall that started is still followed by the delete (or
    // its refusal) and the audit, never left running unobserved.
    let outcome = tokio::spawn(async move {
        removal
            .remove(
                authorizer.as_ref(),
                &principal,
                &machine_id,
                uninstall.as_ref(),
                &request.review_token,
                Some(&correlation),
            )
            .await
    })
    .await
    .map_err(|join| {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("the removal task failed: {join}"),
            RetryClass::Backoff,
            correlation_id,
        )
    })?
    .map_err(|failure| map_removal_error(&failure, correlation_id))?;
    state
        .events
        .publish(fleet_application::events::EventKind::MachineChanged);
    Ok(Json(Resource::new(outcome.into())))
}
