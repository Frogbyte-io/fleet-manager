//! The Proxmox token privilege diagnostics surface (FM-604).
//!
//! A read: `proxmox.read` on the account, no audit event. The handler only
//! translates the application's [`PrivilegeReport`] into public DTOs; the
//! privilege table and the tier evaluation live in
//! `fleet_application::proxmox::privileges`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
};
use fleet_application::proxmox::privileges::{
    MissingPrivileges, PrivilegeCheck, PrivilegeReport, PrivilegeStatus, PrivilegeTier,
    TierPrivileges,
};
use fleet_core::CorrelationId;
use serde::Serialize;
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::ApiErrorResponse;
use crate::proxmox::{map_proxmox_error, proxmox_or_error};

/// A Fleet capability tier.
#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProxmoxPrivilegeTierDto {
    /// Read-only discovery.
    Discover,
    /// Guest lifecycle.
    Operate,
    /// Snapshot, rollback, clone, template, task cancel.
    Destructive,
    /// Lab lease provisioning.
    Lab,
}

impl From<PrivilegeTier> for ProxmoxPrivilegeTierDto {
    fn from(tier: PrivilegeTier) -> Self {
        match tier {
            PrivilegeTier::Discover => Self::Discover,
            PrivilegeTier::Operate => Self::Operate,
            PrivilegeTier::Destructive => Self::Destructive,
            PrivilegeTier::Lab => Self::Lab,
        }
    }
}

/// A tier's or check's outcome.
#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProxmoxPrivilegeStatusDto {
    /// The token holds what is needed somewhere in scope.
    Granted,
    /// The token lacks a needed privilege.
    Missing,
    /// Fleet could not determine the status; `unknownReason` says why.
    Unknown,
}

impl From<PrivilegeStatus> for ProxmoxPrivilegeStatusDto {
    fn from(status: PrivilegeStatus) -> Self {
        match status {
            PrivilegeStatus::Granted => Self::Granted,
            PrivilegeStatus::Missing => Self::Missing,
            PrivilegeStatus::Unknown => Self::Unknown,
        }
    }
}

/// Privileges to grant, and where.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxMissingPrivilegesDto {
    /// The PVE privileges to grant.
    pub privileges: Vec<String>,
    /// Whether any one of them suffices.
    pub any_of: bool,
    /// The ACL path template to grant them on, e.g. `/vms/{vmid}`.
    pub path: String,
    /// The executor kinds or reads that need them.
    pub capabilities: Vec<String>,
}

impl From<MissingPrivileges> for ProxmoxMissingPrivilegesDto {
    fn from(missing: MissingPrivileges) -> Self {
        Self {
            privileges: missing.privileges,
            any_of: missing.any_of,
            path: missing.path,
            capabilities: missing.capabilities,
        }
    }
}

/// One row of Fleet's privilege table, evaluated.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxPrivilegeCheckDto {
    /// The table row's id (unique per PVE major).
    pub requirement: String,
    /// The executor kind or read.
    pub capability: String,
    /// The PVE method and path.
    pub endpoint: String,
    /// Whether the tier needs it; `false` marks an opt-in sub-capability.
    pub required: bool,
    /// The outcome.
    pub status: ProxmoxPrivilegeStatusDto,
    /// The PVE privileges the row names.
    pub privileges: Vec<String>,
    /// Whether any one of them suffices.
    pub any_of: bool,
    /// The ACL path template they are checked on.
    pub path: String,
    /// The token's effective-permission paths the row is satisfied on.
    pub granted_on: Vec<String>,
    /// Whether more paths satisfied the row than `grantedOn` lists.
    pub granted_on_truncated: bool,
    /// The privileges still missing on the closest path in scope.
    pub missing: Vec<String>,
    /// Why the row exists.
    pub note: String,
}

impl From<PrivilegeCheck> for ProxmoxPrivilegeCheckDto {
    fn from(check: PrivilegeCheck) -> Self {
        Self {
            requirement: check.requirement,
            capability: check.capability,
            endpoint: check.endpoint,
            required: check.required,
            status: check.status.into(),
            privileges: check.privileges,
            any_of: check.any_of,
            path: check.path,
            granted_on: check.granted_on,
            granted_on_truncated: check.granted_on_truncated,
            missing: check.missing,
            note: check.note,
        }
    }
}

/// One tier's outcome.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxTierPrivilegesDto {
    /// The tier.
    pub tier: ProxmoxPrivilegeTierDto,
    /// `granted` when every required check is granted.
    pub status: ProxmoxPrivilegeStatusDto,
    /// The required privileges the token lacks, merged per path.
    pub missing: Vec<ProxmoxMissingPrivilegesDto>,
    /// Every check of the tier, required and opt-in.
    pub checks: Vec<ProxmoxPrivilegeCheckDto>,
}

impl From<TierPrivileges> for ProxmoxTierPrivilegesDto {
    fn from(tier: TierPrivileges) -> Self {
        Self {
            tier: tier.tier.into(),
            status: tier.status.into(),
            missing: tier.missing.into_iter().map(Into::into).collect(),
            checks: tier.checks.into_iter().map(Into::into).collect(),
        }
    }
}

/// Which Fleet capability tiers the account's API token can perform.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxPrivilegesDto {
    /// The account evaluated.
    pub account_id: String,
    /// The PVE version read, when the read succeeded.
    pub pve_version: Option<String>,
    /// The PVE major whose rules were applied (8 or 9).
    pub rules_major: Option<u8>,
    /// The four tiers: discover, operate, destructive, lab.
    pub tiers: Vec<ProxmoxTierPrivilegesDto>,
    /// Why every tier is unknown, when the permissions read was refused.
    pub unknown_reason: Option<String>,
    /// The token's effective permissions as PVE reported them: ACL path →
    /// privilege → propagate flag.
    pub effective_permissions: BTreeMap<String, BTreeMap<String, bool>>,
    /// Normalization and evaluation warnings.
    pub warnings: Vec<String>,
    /// When the report was taken (epoch millis).
    pub observed_at: i64,
}

impl From<PrivilegeReport> for ProxmoxPrivilegesDto {
    fn from(report: PrivilegeReport) -> Self {
        Self {
            account_id: report.account_id,
            pve_version: report.pve_version,
            rules_major: report.rules_major,
            tiers: report.tiers.into_iter().map(Into::into).collect(),
            unknown_reason: report.unknown_reason,
            effective_permissions: report.effective_permissions,
            warnings: report.warnings,
            observed_at: report.observed_at,
        }
    }
}

/// Reports which capability tiers the account's API token can perform.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown or unconfirmed
/// account, or a source failure. A refused permissions read is not an
/// error: every tier reports `unknown`.
#[utoipa::path(
    get,
    path = "/proxmox/accounts/{accountId}/privileges",
    tag = "proxmox",
    operation_id = "getProxmoxPrivileges",
    params(
        (
            "accountId" = String,
            Path,
            description = "The account's identity."
        ),
    ),
    responses(
        (
            status = 200,
            description = "The per-tier privilege report; `unknown` tiers when the permissions read was refused.",
            body = Resource<ProxmoxPrivilegesDto>
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
            description = "The account's trust is unconfirmed or its fingerprint was refused.",
            body = crate::error::ApiError
        ),
        (
            status = 502,
            description = "The PVE API failed or refused the token.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn get_proxmox_privileges(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(account_id): Path<String>,
) -> Result<Json<Resource<ProxmoxPrivilegesDto>>, ApiErrorResponse> {
    let proxmox = proxmox_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let report = proxmox
        .privileges(
            state.authorizer.as_ref(),
            &principal,
            &account_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_proxmox_error(&error, correlation_id))?;
    Ok(Json(Resource::new(report.into())))
}
