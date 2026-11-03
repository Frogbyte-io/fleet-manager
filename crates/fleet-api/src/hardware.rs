//! The hardware inventory surface (FM-1111, M11, ADR 0019):
//! `GET /hardware/devices` and `POST /hardware/refresh`.
//!
//! Handlers only translate. What a status means, which privileges a refresh
//! needs and how the observation becomes a status live in
//! `fleet_application::hardware_inventory`. Listing is a read of Fleet's own
//! records (`hardware.read`, no Proxmox call); refresh is an authorized,
//! audited mutation (`hardware.refresh`) that reads Proxmox through the
//! account's token and records what it saw.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Query, State},
    http::StatusCode,
};
use fleet_application::hardware_inventory::{
    DeviceFilter, DeviceView, ExternalReference, HardwareInventory, RefreshReport, RefreshedDevice,
    reason_text,
};
use fleet_core::{
    CorrelationId, DeviceNodeEntry, DeviceStatus, ErrorCode, GuestTarget, HardwareReservation,
    PublicError, RetryClass, UnsupportedReason,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};
use crate::proxmox::{map_proxmox_error, proxmox_or_error};

/// A device's status. `unsupported` always carries a `reason`.
#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HardwareStatusDto {
    /// Mapping valid, seen recently, nothing references it.
    Available,
    /// A live Fleet reservation holds it.
    Reserved,
    /// A guest references the mapping and Fleet has no reservation for it.
    ExternallyAttached,
    /// The mapping exists but the device was not seen on the node, or was
    /// not seen recently (`stale`).
    Missing,
    /// Cannot be allocated, for the stated reason.
    Unsupported,
    /// A failed or unknown attach or detach needs the reconciler or an
    /// operator.
    Quarantined,
}

impl From<DeviceStatus> for HardwareStatusDto {
    fn from(status: DeviceStatus) -> Self {
        match status {
            DeviceStatus::Available => Self::Available,
            DeviceStatus::Reserved => Self::Reserved,
            DeviceStatus::ExternallyAttached => Self::ExternallyAttached,
            DeviceStatus::Missing => Self::Missing,
            DeviceStatus::Unsupported(_) => Self::Unsupported,
            DeviceStatus::Quarantined => Self::Quarantined,
        }
    }
}

/// Why an `unsupported` device cannot be allocated.
#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HardwareUnsupportedReasonDto {
    /// The mapping has no usable entry for any node.
    NoNodeEntry,
    /// The device cannot be told apart.
    AmbiguousMapping,
    /// The token lacks `Mapping.Use` on the mapping.
    TokenLacksMappingUse,
    /// The token lacks `VM.Config.HWType` on any guest.
    TokenLacksGuestHwtype,
    /// The PVE predates USB resource mappings.
    PveTooOld,
    /// Whether the device is present could not be determined.
    UsbInventoryUnreadable,
}

impl From<UnsupportedReason> for HardwareUnsupportedReasonDto {
    fn from(reason: UnsupportedReason) -> Self {
        match reason {
            UnsupportedReason::NoNodeEntry => Self::NoNodeEntry,
            UnsupportedReason::AmbiguousMapping => Self::AmbiguousMapping,
            UnsupportedReason::TokenLacksMappingUse => Self::TokenLacksMappingUse,
            UnsupportedReason::TokenLacksGuestHwtype => Self::TokenLacksGuestHwtype,
            UnsupportedReason::PveTooOld => Self::PveTooOld,
            UnsupportedReason::UsbInventoryUnreadable => Self::UsbInventoryUnreadable,
        }
    }
}

/// What one node last observed for a device. There is no serial: the PVE
/// node inventory does not return one.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HardwareEntryDto {
    /// The PVE node.
    pub node: String,
    /// The USB vendor id (four hex digits).
    pub vendor_id: String,
    /// The USB product id (four hex digits).
    pub product_id: String,
    /// The bus-port path of the mapping or of the device seen, such as `1-10`.
    pub usbpath: Option<String>,
    /// The manufacturer string, when the node inventory was readable.
    pub manufacturer: Option<String>,
    /// The product string, when the node inventory was readable.
    pub product: Option<String>,
    /// When the device was last seen on this node (epoch milliseconds; `0`
    /// when never).
    pub last_seen_at: i64,
}

impl From<DeviceNodeEntry> for HardwareEntryDto {
    fn from(entry: DeviceNodeEntry) -> Self {
        Self {
            node: entry.node,
            vendor_id: entry.vendor_id,
            product_id: entry.product_id,
            usbpath: entry.usbpath,
            manufacturer: entry.manufacturer,
            product: entry.product,
            last_seen_at: entry.last_seen_at,
        }
    }
}

/// The guest a reservation targets.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HardwareGuestDto {
    /// The Proxmox account.
    pub account_id: String,
    /// The guest's node.
    pub node: String,
    /// The guest's VMID.
    pub vmid: u32,
    /// The `usbN` slot, once known.
    pub usb_slot: Option<u8>,
}

impl From<GuestTarget> for HardwareGuestDto {
    fn from(guest: GuestTarget) -> Self {
        Self {
            account_id: guest.account_id,
            node: guest.node,
            vmid: guest.vmid,
            usb_slot: guest.usb_slot,
        }
    }
}

/// The live reservation that holds a device.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HardwareHolderDto {
    /// The reservation's id.
    pub reservation_id: String,
    /// `lease` or `machine`.
    pub owner_kind: String,
    /// The owner's id.
    pub owner_id: String,
    /// The reservation's state (`held`, `attaching`, `attached`, `detaching`,
    /// `attach_unknown`, `detach_failed`).
    pub state: String,
    /// The guest, once known.
    pub guest: Option<HardwareGuestDto>,
    /// When the reservation was made (epoch milliseconds).
    pub reserved_at: i64,
}

impl From<HardwareReservation> for HardwareHolderDto {
    fn from(reservation: HardwareReservation) -> Self {
        Self {
            reservation_id: reservation.id,
            owner_kind: reservation.owner_kind.id().to_owned(),
            owner_id: reservation.owner_id,
            state: reservation.state.id().to_owned(),
            guest: reservation.guest.map(Into::into),
            reserved_at: reservation.created_at,
        }
    }
}

/// A guest that references a device and is not the reservation's own guest.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HardwareExternalReferenceDto {
    /// The guest's node.
    pub node: String,
    /// The guest's VMID.
    pub vmid: u32,
    /// The guest's name, when known.
    pub guest_name: Option<String>,
    /// The `usbN` slot.
    pub slot: String,
    /// Whether the guest is a template (it holds no device; its clones
    /// inherit the entry).
    pub template: bool,
    /// `add` or `remove` when only one of the stored and applied configs of
    /// a running guest has the entry.
    pub pending: Option<String>,
}

impl From<ExternalReference> for HardwareExternalReferenceDto {
    fn from(reference: ExternalReference) -> Self {
        Self {
            node: reference.node,
            vmid: reference.vmid,
            guest_name: reference.guest_name,
            slot: reference.slot,
            template: reference.template,
            pending: reference.pending.map(|pending| pending.id().to_owned()),
        }
    }
}

/// What a refresh observed beyond the stored record. Present in the refresh
/// answer; `null` in the list, which makes no Proxmox call.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HardwareObservationDto {
    /// The guests that reference the mapping.
    pub external_references: Vec<HardwareExternalReferenceDto>,
    /// Explanatory notes (the finding behind `missing`, an id-only entry
    /// that cannot be told apart, a partly read mapping).
    pub notes: Vec<String>,
}

/// One inventoried device: a PVE USB resource mapping.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HardwareDeviceDto {
    /// The Fleet id.
    pub id: String,
    /// The Proxmox account whose cluster owns the mapping.
    pub account_id: String,
    /// The PVE resource mapping id; this is the device's identity.
    pub mapping_id: String,
    /// The device kind (`usb`).
    pub kind: String,
    /// The status to act on: a live reservation decides `reserved` and
    /// `quarantined`, and an available device whose observation is stale
    /// reads `missing`.
    pub status: HardwareStatusDto,
    /// Why, when `status` is `unsupported`.
    pub reason: Option<HardwareUnsupportedReasonDto>,
    /// The reason in words, when `status` is `unsupported`.
    pub reason_text: Option<String>,
    /// Whether the device was last seen longer ago than the controller's
    /// bound (a device that was never seen is stale).
    pub stale: bool,
    /// When the device was last seen on any node (epoch milliseconds; `0`
    /// when it never was, which also reads as stale). For a device with no
    /// entry it is when the record last changed.
    pub observed_at: i64,
    /// The per-node entries.
    pub entries: Vec<HardwareEntryDto>,
    /// The live reservation, when one holds the device.
    pub holder: Option<HardwareHolderDto>,
    /// The operator's note.
    pub note: Option<String>,
    /// What the last refresh added; `null` in the list.
    pub observation: Option<HardwareObservationDto>,
    /// When the record was created (epoch milliseconds).
    pub created_at: i64,
    /// When the record last changed (epoch milliseconds).
    pub updated_at: i64,
}

impl From<DeviceView> for HardwareDeviceDto {
    fn from(view: DeviceView) -> Self {
        let reason = view.status.reason();
        Self {
            id: view.device.id,
            account_id: view.device.account_id,
            mapping_id: view.device.mapping_id,
            kind: view.device.kind.id().to_owned(),
            status: view.status.into(),
            reason: reason.map(Into::into),
            reason_text: reason.map(|reason| reason_text(reason).to_owned()),
            stale: view.stale,
            observed_at: view.observed_at,
            entries: view.device.entries.into_iter().map(Into::into).collect(),
            holder: view.holder.map(Into::into),
            note: view.device.note,
            observation: None,
            created_at: view.device.created_at,
            updated_at: view.device.updated_at,
        }
    }
}

impl From<RefreshedDevice> for HardwareDeviceDto {
    fn from(refreshed: RefreshedDevice) -> Self {
        let mut dto = Self::from(refreshed.view);
        dto.observation = Some(HardwareObservationDto {
            external_references: refreshed
                .external_references
                .into_iter()
                .map(Into::into)
                .collect(),
            notes: refreshed.notes,
        });
        dto
    }
}

/// Whether the account could be inventoried.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HardwareSupportDto {
    /// `supported`, `unsupported` (the account cannot be inventoried) or
    /// `unverified` (the list could not be verified; no device was changed).
    pub state: String,
    /// `pve_too_old`, `no_mapping_audit`, `permissions_unreadable` or
    /// `mapping_list_unreadable`, unless
    /// supported.
    pub reason: Option<String>,
    /// The reason in words, unless supported.
    pub detail: Option<String>,
}

/// What the guest scan covered.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HardwareGuestScanDto {
    /// How many QEMU guests the cluster listed.
    pub listed: usize,
    /// How many configs were read.
    pub read: usize,
    /// How many could not be read.
    pub unreadable: usize,
    /// Whether the bound dropped guests. A scan with unreadable or dropped
    /// guests is incomplete: a device that would be available is reported
    /// `unsupported` (`usb_inventory_unreadable`) instead, since a guest may reference it
    /// that was not read.
    pub truncated: bool,
}

/// The outcome of one refresh.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HardwareRefreshDto {
    /// The account refreshed.
    pub account_id: String,
    /// When the observation was taken (epoch milliseconds).
    pub observed_at: i64,
    /// The PVE version, when it could be read.
    pub pve_version: Option<String>,
    /// Whether the account could be inventoried.
    pub support: HardwareSupportDto,
    /// What the guest scan covered; `null` when the mapping list was not
    /// usable.
    pub guest_scan: Option<HardwareGuestScanDto>,
    /// The account's devices after the refresh, ordered by mapping id.
    pub devices: Vec<HardwareDeviceDto>,
    /// Warnings, bounded.
    pub warnings: Vec<String>,
}

impl From<RefreshReport> for HardwareRefreshDto {
    fn from(report: RefreshReport) -> Self {
        let reason = report.support.reason();
        Self {
            account_id: report.account_id,
            observed_at: report.observed_at,
            pve_version: report.pve_version,
            support: HardwareSupportDto {
                state: report.support.state().to_owned(),
                reason: reason.map(|reason| reason.id().to_owned()),
                detail: reason.map(|reason| reason.text().to_owned()),
            },
            guest_scan: report.guest_scan.map(|scan| HardwareGuestScanDto {
                listed: scan.listed,
                read: scan.read,
                unreadable: scan.unreadable,
                truncated: scan.truncated,
            }),
            devices: report.devices.into_iter().map(Into::into).collect(),
            warnings: report.warnings,
        }
    }
}

/// The refresh request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RefreshHardwareRequest {
    /// The Proxmox account to refresh.
    pub account_id: String,
}

/// The list-devices query parameters.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListHardwareDevicesParams {
    /// Only this account's devices.
    pub account_id: Option<String>,
    /// The maximum number of devices to return.
    pub limit: Option<u32>,
    /// The opaque cursor: the last device id of the previous page.
    pub cursor: Option<String>,
}

fn hardware_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<HardwareInventory>, ApiErrorResponse> {
    let unwired = || {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "the hardware surface is not wired; the controller needs its database, secret store and the Proxmox provider",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    };
    let proxmox = proxmox_or_error(state, correlation_id)?;
    proxmox.hardware().cloned().ok_or_else(unwired)
}

/// Lists the inventoried hardware devices with their status and the reason
/// for it. A read of Fleet's own records: it makes no Proxmox call, so a
/// device is as fresh as the last `POST /hardware/refresh` (`stale` says when
/// that is too old to trust).
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown account, an
/// unknown cursor, an unwired surface or a backend failure.
#[utoipa::path(
    get,
    path = "/hardware/devices",
    tag = "hardware",
    operation_id = "listHardwareDevices",
    params(
        (
            "accountId" = Option<String>,
            Query,
            description = "Only this account's devices."
        ),
        (
            "limit" = Option<u32>,
            Query,
            description = "The maximum number of devices to return."
        ),
        (
            "cursor" = Option<String>,
            Query,
            description = "The opaque cursor: the last device id of the previous page."
        ),
    ),
    responses(
        (
            status = 200,
            description = "The devices ordered by account then mapping id, each with its status and, when unsupported, its reason.",
            body = Page<HardwareDeviceDto>
        ),
        (
            status = 400,
            description = "The cursor names no device in the list.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not read the hardware inventory (`hardware.read`).",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "The account does not exist.",
            body = crate::error::ApiError
        ),
        (
            status = 500,
            description = "The controller's storage failed.",
            body = crate::error::ApiError
        ),
        (
            status = 503,
            description = "The hardware surface is not wired.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn list_hardware_devices(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<ListHardwareDevicesParams>,
) -> Result<Json<Page<HardwareDeviceDto>>, ApiErrorResponse> {
    let hardware = hardware_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let limit = params
        .limit
        .filter(|limit| *limit > 0)
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .min(MAX_PAGE_LIMIT);
    let views = hardware
        .list(
            state.authorizer.as_ref(),
            &principal,
            &DeviceFilter {
                account_id: params.account_id,
            },
            usize::try_from(limit).unwrap_or(usize::MAX),
            params.cursor.as_deref(),
        )
        .await
        .map_err(|error| map_proxmox_error(&error, correlation_id))?;
    let next_cursor = (views.len() == usize::try_from(limit).unwrap_or(0))
        .then(|| views.last().map(|view| view.device.id.clone()))
        .flatten();
    Ok(Json(Page {
        page: PageInfo { next_cursor, limit },
        items: views.into_iter().map(Into::into).collect(),
    }))
}

/// Refreshes one account's hardware inventory: reads its USB mappings, the
/// nodes they name, every guest config and the token's own permissions
/// through the account's API token, and records the derived status of each
/// mapping. An authorized, audited mutation (`hardware.refresh`); it changes
/// nothing on Proxmox.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown or unconfirmed
/// account, a missing token secret, an unwired surface, a failed audit write
/// or a Proxmox failure that makes the observation meaningless.
#[utoipa::path(
    post,
    path = "/hardware/refresh",
    tag = "hardware",
    operation_id = "refreshHardware",
    request_body = RefreshHardwareRequest,
    responses(
        (
            status = 200,
            description = "The account's devices after the refresh, with the support state of the account, what the guest scan covered and what each device's observation added.",
            body = Resource<HardwareRefreshDto>
        ),
        (
            status = 403,
            description = "The caller may not refresh the hardware inventory (`hardware.refresh`).",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "The account does not exist.",
            body = crate::error::ApiError
        ),
        (
            status = 409,
            description = "The account's trust is unconfirmed (`proxmox_unconfirmed`), its pinned fingerprint no longer matches (`proxmox_fingerprint_mismatch`), or its token secret is unavailable (`proxmox_no_secret`).",
            body = crate::error::ApiError
        ),
        (
            status = 500,
            description = "The controller's storage, secret store or audit sink failed.",
            body = crate::error::ApiError
        ),
        (
            status = 502,
            description = "The PVE API failed or refused the token.",
            body = crate::error::ApiError
        ),
        (
            status = 503,
            description = "The hardware surface is not wired.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn refresh_hardware(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Json(request): Json<RefreshHardwareRequest>,
) -> Result<Json<Resource<HardwareRefreshDto>>, ApiErrorResponse> {
    let hardware = hardware_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let correlation = correlation_id.to_string();
    let report = hardware
        .refresh(
            state.authorizer.as_ref(),
            &principal,
            Some(&correlation),
            &request.account_id,
        )
        .await
        .map_err(|error| map_proxmox_error(&error, correlation_id))?;
    Ok(Json(Resource::new(report.into())))
}
