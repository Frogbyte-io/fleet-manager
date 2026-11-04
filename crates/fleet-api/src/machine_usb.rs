//! USB devices on persistent machines (FM-1125, ADR 0018 and ADR 0019):
//! `POST /machines/{machineId}/usb/attach/review`, `.../usb/attach`,
//! `.../usb/detach/review` and `.../usb/detach`.
//!
//! The handlers are adapters. Authorization (`machines.usb.attach` and
//! `machines.usb.detach`, resource = the machine id), the checks of the
//! machine and its guest, the review token that binds the execute call to the
//! reviewed request, the reservation rules and the audit all live in
//! `fleet_application::machine_usb` and the hardware saga behind it. The
//! execute routes are synchronous: the answer says what PVE did, and
//! `pending` is reported as pending, never as done.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use fleet_application::lab_hardware_hotplug::{HotplugError, HotplugResult};
use fleet_application::machine_usb::{MachineUsb, MachineUsbOutcome, MachineUsbReview};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::{ApiError, ApiErrorResponse};
use crate::lab_hardware::map_hotplug_error;

/// Which device to review.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewMachineUsbRequest {
    /// The Proxmox USB resource mapping id of the device.
    pub mapping: String,
}

/// Which device to attach or detach, and the review it was reviewed in.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecuteMachineUsbRequest {
    /// The Proxmox USB resource mapping id of the device.
    pub mapping: String,
    /// The token the review answered; it binds this call to the reviewed
    /// machine, device and guest.
    pub review_token: String,
}

/// The guest an attach writes to, as the review found it live.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineUsbGuestDto {
    /// The Proxmox account.
    pub account_id: String,
    /// The node the guest is on.
    pub node: String,
    /// The guest's VMID.
    pub vmid: u32,
    /// The guest's name.
    pub name: String,
}

/// The machine's reservation of the device, when it has one.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineUsbReservationDto {
    /// The reservation.
    pub id: String,
    /// Its state: `held`, `attaching`, `attached`, `detaching`,
    /// `attach_unknown` or `detach_failed`.
    pub state: String,
    /// The VMID of the guest it records, when it does.
    pub guest_vmid: Option<u32>,
    /// The `usbN` slot it records, when it does.
    pub usb_slot: Option<String>,
}

/// What a review found, and the token that binds the execute call to it.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineUsbReviewDto {
    /// The token the execute call must present.
    pub review_token: String,
    /// `attach` or `detach`.
    pub action: String,
    /// The machine.
    pub machine_id: String,
    /// The mapping id.
    pub mapping: String,
    /// The guest an attach writes to (a detach acts on the reservation's
    /// guest and names none).
    pub guest: Option<MachineUsbGuestDto>,
    /// The machine's reservation of the device, when it has one.
    pub reservation: Option<MachineUsbReservationDto>,
}

impl From<MachineUsbReview> for MachineUsbReviewDto {
    fn from(review: MachineUsbReview) -> Self {
        Self {
            review_token: review.review_token,
            action: review.action.id().to_owned(),
            machine_id: review.machine_id,
            mapping: review.mapping_id,
            guest: review.guest.map(|guest| MachineUsbGuestDto {
                account_id: guest.account_id,
                node: guest.node,
                vmid: guest.vmid,
                name: guest.name,
            }),
            reservation: review
                .reservation
                .map(|reservation| MachineUsbReservationDto {
                    id: reservation.id,
                    state: reservation.state.id().to_owned(),
                    guest_vmid: reservation.guest.as_ref().map(|guest| guest.vmid),
                    usb_slot: reservation
                        .guest
                        .as_ref()
                        .and_then(|guest| guest.usb_slot)
                        .map(|slot| format!("usb{slot}")),
                }),
        }
    }
}

/// What an attach or detach came to.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineUsbDto {
    /// The machine.
    pub machine_id: String,
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
    /// The machine's reservation of the device.
    pub reservation_id: String,
    /// The reservation's state after the request: `attached`, `detaching`
    /// (a pending detach) or `released`.
    pub reservation_state: String,
    /// The `usbN` slot the guest holds the device in, when it does.
    pub usb_slot: Option<String>,
    /// Whether the request released the reservation.
    pub released: bool,
}

impl From<MachineUsbOutcome> for MachineUsbDto {
    fn from(outcome: MachineUsbOutcome) -> Self {
        Self {
            machine_id: outcome.machine_id,
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

fn machine_usb_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<MachineUsb>, ApiErrorResponse> {
    state
        .lab
        .as_ref()
        .and_then(|lab| lab.machine_usb().cloned())
        .ok_or_else(|| {
            let public = PublicError::new(
                ErrorCode::from_str("machine_unavailable")
                    .expect("the literal is valid error code syntax"),
                "machine USB attach and detach are not wired; the controller needs its database and a Proxmox secret store",
                RetryClass::Backoff,
            );
            ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
        })
}

fn invalid_body(detail: &str, correlation_id: CorrelationId) -> ApiErrorResponse {
    map_hotplug_error(
        &HotplugError::Invalid {
            detail: detail.to_owned(),
        },
        correlation_id,
    )
}

fn respond(
    result: Result<MachineUsbOutcome, HotplugError>,
    correlation_id: CorrelationId,
) -> Result<(StatusCode, Json<Resource<MachineUsbDto>>), ApiErrorResponse> {
    let outcome = result.map_err(|error| map_hotplug_error(&error, correlation_id))?;
    // A pending removal is accepted, not done: 202, not 200.
    let status = if outcome.result == HotplugResult::DetachPending {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(Resource::new(outcome.into()))))
}

fn review_or_error(
    result: Result<MachineUsbReview, HotplugError>,
    correlation_id: CorrelationId,
) -> Result<Json<Resource<MachineUsbReviewDto>>, ApiErrorResponse> {
    result
        .map(|review| Json(Resource::new(review.into())))
        .map_err(|error| map_hotplug_error(&error, correlation_id))
}

/// Reviews attaching a USB device to a persistent machine: the machine must
/// be linked to a QEMU guest that carries a ready persistent marker (not a
/// Lab clone, template, image artifact or pool member), and the device must
/// be inventoried and not held by another owner. Answers the guest the
/// attach will write to and the token that binds the attach call to this
/// review. Nothing is written.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown machine, a
/// machine without an eligible persistent guest, an unknown device or a
/// device another owner holds (`hardware_busy`).
#[utoipa::path(
    post,
    path = "/machines/{machineId}/usb/attach/review",
    tag = "machines",
    operation_id = "reviewMachineUsbAttach",
    params(("machineId" = String, Path, description = "The machine's identity.")),
    request_body = ReviewMachineUsbRequest,
    responses(
        (status = 200, description = "The review record; present its token to the attach call.", body = Resource<MachineUsbReviewDto>),
        (status = 400, description = "The mapping id is malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not attach hardware to machines (`machines.usb.attach`).", body = crate::error::ApiError),
        (status = 404, description = "The machine does not exist.", body = crate::error::ApiError),
        (status = 409, description = "Refused, with the reason as the error code: `machine_has_no_guest`, `machine_guest_not_qemu`, `machine_not_persistent`, `machine_not_ready`, `machine_guest_mismatch` (the guest's marker names no machine or another one), `guest_not_eligible` (a Lab clone, template, image artifact or pool member), `hardware_unknown` and `hardware_busy` (another owner holds the device; nothing is queued).", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Machine USB is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn review_machine_usb_attach(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
    request: Result<Json<ReviewMachineUsbRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Resource<MachineUsbReviewDto>>, ApiErrorResponse> {
    let usb = machine_usb_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        invalid_body(
            "the request body must be valid JSON with a mapping",
            correlation_id,
        )
    })?;
    review_or_error(
        usb.review_attach(
            state.authorizer.as_ref(),
            &principal,
            &machine_id,
            &request.mapping,
        )
        .await,
        correlation_id,
    )
}

/// Attaches a reviewed device to the machine's guest and reserves it for the
/// machine until it is explicitly detached: a digest-conditional write of the
/// mapping into a free `usbN` slot, read back before it is reported. The
/// device is reserved first, fail fast (`hardware_busy`, never queued), and
/// verified against the pinned fingerprint. An attach PVE would leave pending
/// (the running guest's `hotplug` option lacks `usb`) is removed again and
/// refused as `hardware_attach_pending`: it is never reported as attached.
/// Audited before the write.
///
/// # Errors
///
/// Returns the public error envelope on refusal, a review token that does
/// not match, an unknown machine, an ineligible guest, a device another owner
/// holds, a failed verification of the device, or a failed write.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/usb/attach",
    tag = "machines",
    operation_id = "attachMachineUsb",
    params(("machineId" = String, Path, description = "The machine's identity.")),
    request_body = ExecuteMachineUsbRequest,
    responses(
        (status = 200, description = "The device is on the guest and the read-back confirmed it (`attached`), or the reservation already said so (`already_attached`).", body = Resource<MachineUsbDto>),
        (status = 400, description = "The mapping id is malformed, or the review token does not match.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not attach hardware to machines (`machines.usb.attach`).", body = crate::error::ApiError),
        (status = 404, description = "The machine does not exist.", body = crate::error::ApiError),
        (status = 409, description = "Refused, with the reason as the error code: every review refusal, and `hardware_busy`, `hardware_guest_busy` (a destroy, revert, template or clone is running on the guest), `hardware_in_progress`, `hardware_attach_unknown`, `hardware_detach_unconfirmed`, `hardware_guest_mismatch`, `hardware_attach_pending` (PVE would keep the attach pending until the guest restarts; nothing is attached and the entry was removed), `hardware_externally_attached`, `hardware_fingerprint_changed`, `hardware_missing`, `hardware_no_free_slot`, `hardware_attach_failed`, `hardware_attach_unrecorded` and the other `hardware_*` verification reasons.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Machine USB is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn attach_machine_usb(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
    request: Result<Json<ExecuteMachineUsbRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<MachineUsbDto>>), ApiErrorResponse> {
    let usb = machine_usb_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        invalid_body(
            "the request body must be valid JSON with a mapping and a reviewToken",
            correlation_id,
        )
    })?;
    respond(
        usb.attach(
            state.authorizer.as_ref(),
            &principal,
            &machine_id,
            &request.mapping,
            &request.review_token,
        )
        .await,
        correlation_id,
    )
}

/// Reviews detaching a USB device from a persistent machine: the machine must
/// hold the device. The answer names the reservation and the guest and slot
/// it records, and the token that binds the detach call to this review.
/// Nothing is written.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown machine, or a
/// device the machine does not hold (`hardware_not_reserved`).
#[utoipa::path(
    post,
    path = "/machines/{machineId}/usb/detach/review",
    tag = "machines",
    operation_id = "reviewMachineUsbDetach",
    params(("machineId" = String, Path, description = "The machine's identity.")),
    request_body = ReviewMachineUsbRequest,
    responses(
        (status = 200, description = "The review record; present its token to the detach call.", body = Resource<MachineUsbReviewDto>),
        (status = 400, description = "The mapping id is malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not detach hardware from machines (`machines.usb.detach`).", body = crate::error::ApiError),
        (status = 404, description = "The machine does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The machine does not hold the device (`hardware_not_reserved`).", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Machine USB is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn review_machine_usb_detach(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
    request: Result<Json<ReviewMachineUsbRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Resource<MachineUsbReviewDto>>, ApiErrorResponse> {
    let usb = machine_usb_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        invalid_body(
            "the request body must be valid JSON with a mapping",
            correlation_id,
        )
    })?;
    review_or_error(
        usb.review_detach(
            state.authorizer.as_ref(),
            &principal,
            &machine_id,
            &request.mapping,
        )
        .await,
        correlation_id,
    )
}

/// Detaches a reviewed device from the guest the machine's reservation
/// recorded and releases the reservation after the read-back confirmed the
/// device is gone. The recorded `usbN` entry is deleted only when it holds
/// exactly what Fleet wrote, and every `usbN` entry is read back before the
/// answer. A removal PVE leaves pending (the guest's `hotplug` option lacks
/// `usb`) answers `detach_pending` with the device still attached and the
/// reservation still held; repeat the detach once the guest restarted.
/// Audited before the delete.
///
/// # Errors
///
/// Returns the public error envelope on refusal, a review token that does
/// not match, an unknown machine, a device the machine does not hold, or a
/// detach that failed or could not be confirmed (the machine keeps the
/// reservation).
#[utoipa::path(
    post,
    path = "/machines/{machineId}/usb/detach",
    tag = "machines",
    operation_id = "detachMachineUsb",
    params(("machineId" = String, Path, description = "The machine's identity.")),
    request_body = ExecuteMachineUsbRequest,
    responses(
        (status = 200, description = "The device is off the guest, the read-back confirmed it and the reservation is released (`detached`), or it already was (`already_detached`).", body = Resource<MachineUsbDto>),
        (status = 202, description = "PVE stored the removal but the guest keeps the device until it restarts (`detach_pending`): the device is still attached and still reserved by the machine.", body = Resource<MachineUsbDto>),
        (status = 400, description = "The mapping id is malformed, or the review token does not match.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not detach hardware from machines (`machines.usb.detach`).", body = crate::error::ApiError),
        (status = 404, description = "The machine does not exist.", body = crate::error::ApiError),
        (status = 409, description = "Refused, with the reason as the error code: `hardware_not_reserved`, `hardware_ambiguous` (the machine holds that mapping id in several accounts), `hardware_attach_unknown`, `hardware_detach_failed` (PVE refused, the entry is not one Fleet wrote, or the read-back could not confirm it; the machine keeps the reservation) and `hardware_detach_unconfirmed`.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Machine USB is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn detach_machine_usb(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
    request: Result<Json<ExecuteMachineUsbRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<MachineUsbDto>>), ApiErrorResponse> {
    let usb = machine_usb_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        invalid_body(
            "the request body must be valid JSON with a mapping and a reviewToken",
            correlation_id,
        )
    })?;
    respond(
        usb.detach(
            state.authorizer.as_ref(),
            &principal,
            &machine_id,
            &request.mapping,
            &request.review_token,
        )
        .await,
        correlation_id,
    )
}
