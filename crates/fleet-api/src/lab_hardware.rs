//! Mid-run hardware hotplug on a Lab lease (FM-1126, ADR 0019):
//! `POST /lab/leases/{leaseId}/hardware/attach` and
//! `POST /lab/leases/{leaseId}/hardware/detach`.
//!
//! The handlers are adapters. Authorization (`lab.hardware.attach` and
//! `lab.hardware.detach`, resource = the lease id), the owner scope that
//! limits a delegated credential to its own leases, the lease checks, the
//! reservation rules and the audit all live in
//! `fleet_application::lab_hardware_hotplug` and the Lab hardware saga behind
//! it. Both routes are synchronous: the answer says what PVE did, and
//! `pending` is reported as pending, never as done.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use fleet_application::lab_hardware_hotplug::{
    HotplugError, HotplugOutcome, HotplugResult, LabHardwareHotplug,
};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::{ApiError, ApiErrorResponse};
use crate::lab::lab_or_error;

/// Which device to attach to the lease's running guest.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttachLabHardwareRequest {
    /// The Proxmox USB resource mapping id of a device the lease reserved
    /// (the mapping its template declared).
    pub mapping: String,
}

/// Which device to detach from the lease's running guest.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetachLabHardwareRequest {
    /// The Proxmox USB resource mapping id of a device the lease reserved.
    pub mapping: String,
    /// Also give the device up once the read-back confirms it is off the
    /// guest. By default the lease keeps it reserved until the lease is
    /// released, so it can be attached again.
    #[serde(default)]
    pub release: bool,
}

/// What a hotplug request came to.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LabHardwareHotplugDto {
    /// The lease.
    pub lease_id: String,
    /// The mapping id.
    pub mapping: String,
    /// `attached` and `already_attached` (the guest has the device),
    /// `detached` and `already_detached` (it does not), or `detach_pending`:
    /// PVE stored the removal but the guest keeps the device until it
    /// restarts (its `hotplug` option lacks `usb`), so the device is still
    /// attached and the reservation stays `detaching`. An attach PVE would
    /// leave pending is refused instead (`hardware_attach_pending`); it is
    /// never reported as attached.
    pub outcome: String,
    /// Whether the guest has the device once the request is answered.
    pub on_guest: bool,
    /// The lease's reservation of the device.
    pub reservation_id: String,
    /// The reservation's state after the request: `attached`, `held` (the
    /// lease keeps a detached device), `detaching` (a pending detach) or
    /// `released`.
    pub reservation_state: String,
    /// The `usbN` slot the guest holds the device in, when it does.
    pub usb_slot: Option<String>,
    /// Whether the request released the reservation.
    pub released: bool,
}

impl From<HotplugOutcome> for LabHardwareHotplugDto {
    fn from(outcome: HotplugOutcome) -> Self {
        Self {
            lease_id: outcome.lease_id,
            mapping: outcome.mapping_id,
            outcome: outcome.result.id().to_owned(),
            on_guest: outcome.result.on_guest(),
            reservation_id: outcome.reservation_id,
            reservation_state: outcome.reservation_state.id().to_owned(),
            usb_slot: outcome.usb_slot.map(|slot| format!("usb{slot}")),
            released: outcome.released,
        }
    }
}

fn hotplug_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<LabHardwareHotplug>, ApiErrorResponse> {
    let lab = lab_or_error(state, correlation_id)?;
    lab.hotplug().cloned().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "Lab hardware hotplug is not wired; the controller needs its database and a Proxmox secret store",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// Maps a hotplug refusal onto the public error envelope, once. A refusal
/// carries its stable reason as the error code.
pub(crate) fn map_hotplug_error(
    error: &HotplugError,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    let (status, code, retry, message): (StatusCode, String, RetryClass, String) = match error {
        HotplugError::Denied(_) => (
            StatusCode::FORBIDDEN,
            "denied".to_owned(),
            RetryClass::Never,
            error.to_string(),
        ),
        HotplugError::NotFound { .. } => (
            StatusCode::NOT_FOUND,
            "not_found".to_owned(),
            RetryClass::Never,
            error.to_string(),
        ),
        HotplugError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request".to_owned(),
            RetryClass::Never,
            error.to_string(),
        ),
        HotplugError::Refused { reason, detail } => (
            StatusCode::CONFLICT,
            reason.clone(),
            if reason == "hardware_in_progress" {
                RetryClass::Backoff
            } else {
                RetryClass::Never
            },
            detail.clone(),
        ),
        HotplugError::Unavailable { detail } => (
            StatusCode::SERVICE_UNAVAILABLE,
            "machine_unavailable".to_owned(),
            RetryClass::Backoff,
            detail.clone(),
        ),
        HotplugError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal".to_owned(),
            RetryClass::Backoff,
            "the request could not be completed; the detail is in the controller log".to_owned(),
        ),
    };
    let code = ErrorCode::from_str(&code)
        .or_else(|_| ErrorCode::from_str("conflict"))
        .expect("the literal is valid error code syntax");
    ApiError::new(&PublicError::new(code, message, retry), correlation_id).with_status(status)
}

fn respond(
    result: Result<HotplugOutcome, HotplugError>,
    correlation_id: CorrelationId,
) -> Result<(StatusCode, Json<Resource<LabHardwareHotplugDto>>), ApiErrorResponse> {
    let outcome = result.map_err(|error| map_hotplug_error(&error, correlation_id))?;
    // A pending removal is accepted, not done: 202, not 200.
    let status = if outcome.result == HotplugResult::DetachPending {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(Resource::new(outcome.into()))))
}

fn invalid_body(correlation_id: CorrelationId) -> ApiErrorResponse {
    map_hotplug_error(
        &HotplugError::Invalid {
            detail: "the request body must be valid JSON with a mapping".to_owned(),
        },
        correlation_id,
    )
}

/// Attaches a device the lease reserved to the lease's running guest: a
/// digest-conditional write of the mapping into a free `usbN` slot, read back
/// before it is reported. Only the lease's holder (or an administrator) may
/// act, only for a device the lease reserved, and only on a ready lease. An
/// attach PVE would leave pending (the guest's `hotplug` option lacks `usb`)
/// is removed again and refused as `hardware_attach_pending`: it is never
/// reported as attached. The attach is audited before the write.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown lease (or
/// another owner's), a lease that is not ready, a device the lease did not
/// reserve, a failed verification of the device, or a failed write.
#[utoipa::path(
    post,
    path = "/lab/leases/{leaseId}/hardware/attach",
    tag = "lab",
    operation_id = "attachLabLeaseHardware",
    params(("leaseId" = String, Path, description = "The lease's identity.")),
    request_body = AttachLabHardwareRequest,
    responses(
        (status = 200, description = "The device is on the guest and the read-back confirmed it (`attached`), or the reservation already said so (`already_attached`).", body = Resource<LabHardwareHotplugDto>),
        (status = 400, description = "The mapping id is malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not hotplug hardware on Lab leases (`lab.hardware.attach`).", body = crate::error::ApiError),
        (status = 404, description = "The lease does not exist (or is another owner's).", body = crate::error::ApiError),
        (status = 409, description = "Refused, with the reason as the error code: `lease_not_ready`, `lease_has_no_guest`, `hardware_not_reserved` (not a device this lease reserved), `hardware_not_detached`, `hardware_in_progress`, `hardware_attach_unknown`, `hardware_detach_unconfirmed`, `hardware_attach_pending` (PVE would keep the attach pending until the guest restarts; nothing is attached and the entry was removed), `hardware_externally_attached`, `hardware_fingerprint_changed`, `hardware_missing`, `hardware_no_free_slot`, `hardware_attach_failed`, `hardware_attach_unrecorded` and the other `hardware_*` verification reasons.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Lab hardware hotplug is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn attach_lab_lease_hardware(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(lease_id): Path<String>,
    request: Result<Json<AttachLabHardwareRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<LabHardwareHotplugDto>>), ApiErrorResponse> {
    let hotplug = hotplug_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| invalid_body(correlation_id))?;
    respond(
        hotplug
            .attach(
                state.authorizer.as_ref(),
                &principal,
                &lease_id,
                &request.mapping,
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await,
        correlation_id,
    )
}

/// Detaches a device the lease reserved from the lease's running guest: the
/// recorded `usbN` entry is deleted only when it holds exactly what Fleet
/// wrote, and every `usbN` entry is read back before the answer. The lease
/// keeps the device reserved (it can attach it again) unless the request
/// sets `release`, which gives it up after the read-back confirmed it is
/// gone. A removal PVE leaves pending (the guest's `hotplug` option lacks
/// `usb`) answers `detach_pending` with the device still attached. Cleanup
/// still detaches whatever the lease holds before it decides the guest's
/// fate. Audited before the delete.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown lease (or
/// another owner's), a lease that is not ready, a device the lease did not
/// reserve, or a detach that failed or could not be confirmed (the
/// reservation stays with the lease and its cleanup retries).
#[utoipa::path(
    post,
    path = "/lab/leases/{leaseId}/hardware/detach",
    tag = "lab",
    operation_id = "detachLabLeaseHardware",
    params(("leaseId" = String, Path, description = "The lease's identity.")),
    request_body = DetachLabHardwareRequest,
    responses(
        (status = 200, description = "The device is off the guest and the read-back confirmed it (`detached`), or it already was (`already_detached`).", body = Resource<LabHardwareHotplugDto>),
        (status = 202, description = "PVE stored the removal but the guest keeps the device until it restarts (`detach_pending`): the device is still attached.", body = Resource<LabHardwareHotplugDto>),
        (status = 400, description = "The mapping id is malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not hotplug hardware on Lab leases (`lab.hardware.detach`).", body = crate::error::ApiError),
        (status = 404, description = "The lease does not exist (or is another owner's).", body = crate::error::ApiError),
        (status = 409, description = "Refused, with the reason as the error code: `lease_not_ready`, `lease_has_no_guest`, `hardware_not_reserved` (not a device this lease reserved), `hardware_in_progress`, `hardware_attach_unknown`, `hardware_detach_failed` (PVE refused, the entry is not one Fleet wrote, or the read-back could not confirm it; the lease's cleanup retries) and `hardware_guest_mismatch`.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Lab hardware hotplug is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn detach_lab_lease_hardware(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(lease_id): Path<String>,
    request: Result<Json<DetachLabHardwareRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<LabHardwareHotplugDto>>), ApiErrorResponse> {
    let hotplug = hotplug_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| invalid_body(correlation_id))?;
    respond(
        hotplug
            .detach(
                state.authorizer.as_ref(),
                &principal,
                &lease_id,
                &request.mapping,
                request.release,
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await,
        correlation_id,
    )
}
