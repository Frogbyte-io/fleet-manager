//! The DNS surface (FM-1042): read zones and records through a Cloudflare
//! account, and ask for record changes through the action broker.
//!
//! The handlers are adapters. Authorization (`dns.read`, then the broker's
//! `action.request`), the preview, the credential refusal, and audit belong
//! to the application's [`Dns`] and `Broker`. The use cases come from a
//! request extension set by the controller, so the shared API state is not
//! widened for them. Cloudflare's token is never in any request or answer.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Query, State},
    http::StatusCode,
};
use fleet_application::dns::{
    AccountZones, ChangeKind, ChangeRequest, Dns, DnsError, DnsFailureClass, DnsObservation,
    DnsRecord, DnsZone, RecordsView,
};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::{ApiError, ApiErrorResponse};
use crate::requests::ActionRequestDto;

/// The origin recorded for a change that arrived over this HTTP API.
const API_ORIGIN: &str = "api";

fn dns_or_error(
    extension: Option<Extension<Arc<Dns>>>,
    correlation_id: CorrelationId,
) -> Result<Arc<Dns>, ApiErrorResponse> {
    extension.map(|Extension(dns)| dns).ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("dns_unavailable").expect("the literal is valid error code syntax"),
            "the DNS surface is not wired; the controller needs its database and secret store",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

fn map_error(error: &DnsError, correlation_id: CorrelationId) -> ApiErrorResponse {
    if let DnsError::Broker(broker) = error {
        return crate::requests::map_broker_error(broker, correlation_id);
    }
    let (status, code, retry): (StatusCode, &str, RetryClass) = match error {
        DnsError::Denied(_) => (StatusCode::FORBIDDEN, "denied", RetryClass::Never),
        DnsError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
        ),
        DnsError::NotFound { .. } => (StatusCode::NOT_FOUND, "not_found", RetryClass::Never),
        DnsError::Conflict { .. } => (StatusCode::CONFLICT, "conflict", RetryClass::Never),
        // A refused token or a provider outage is the controller's
        // upstream problem, not the caller's: a gateway failure.
        DnsError::Provider(failure) => match failure.class {
            DnsFailureClass::Auth => (
                StatusCode::BAD_GATEWAY,
                "dns_provider_auth",
                RetryClass::Never,
            ),
            DnsFailureClass::Permission => (
                StatusCode::BAD_GATEWAY,
                "dns_provider_permission",
                RetryClass::Never,
            ),
            DnsFailureClass::NotFound => (
                StatusCode::NOT_FOUND,
                "dns_provider_not_found",
                RetryClass::Never,
            ),
            DnsFailureClass::Conflict => (
                StatusCode::CONFLICT,
                "dns_provider_conflict",
                RetryClass::Never,
            ),
            DnsFailureClass::RateLimited => (
                StatusCode::SERVICE_UNAVAILABLE,
                "dns_provider_rate_limited",
                RetryClass::Backoff,
            ),
            DnsFailureClass::Invalid => (
                StatusCode::BAD_REQUEST,
                "dns_provider_invalid",
                RetryClass::Never,
            ),
            DnsFailureClass::Unavailable => (
                StatusCode::BAD_GATEWAY,
                "dns_provider_unavailable",
                RetryClass::Backoff,
            ),
        },
        DnsError::Backend { .. } | DnsError::Broker(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    let message = match error {
        DnsError::Backend { .. } => {
            "the request could not be completed; the detail is in the controller log".to_owned()
        }
        other => other.to_string(),
    };
    let public = PublicError::new(
        ErrorCode::from_str(code).expect("the literal is valid error code syntax"),
        message,
        retry,
    );
    ApiError::new(&public, correlation_id).with_status(status)
}

/// One DNS record.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsRecordDto {
    /// The provider's record id.
    pub id: Option<String>,
    /// The record type.
    #[serde(rename = "type")]
    pub record_type: String,
    /// The fully qualified name.
    pub name: String,
    /// The value, normalized per type.
    pub content: String,
    /// The TTL in seconds; 1 is automatic.
    pub ttl: u32,
    /// Whether traffic is proxied through the provider.
    pub proxied: bool,
    /// The MX preference.
    pub priority: Option<u16>,
}

impl From<DnsRecord> for DnsRecordDto {
    fn from(record: DnsRecord) -> Self {
        Self {
            id: record.id,
            record_type: record.record_type,
            name: record.name,
            content: record.content,
            ttl: record.ttl,
            proxied: record.proxied,
            priority: record.priority,
        }
    }
}

/// One DNS zone.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsZoneDto {
    /// The provider's zone id.
    pub id: String,
    /// The zone's apex name.
    pub name: String,
    /// The provider's status for the zone.
    pub status: String,
}

impl From<DnsZone> for DnsZoneDto {
    fn from(zone: DnsZone) -> Self {
        Self {
            id: zone.id,
            name: zone.name,
            status: zone.status,
        }
    }
}

/// The zones one Cloudflare account's token can see.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountZonesDto {
    /// The account's id.
    pub account_id: String,
    /// The account's label.
    pub account_label: String,
    /// The zones.
    pub zones: Vec<DnsZoneDto>,
    /// The failure class when the zones could not be read (`auth`,
    /// `permission`, `rate_limited`, `unavailable`, ...).
    pub failure: Option<String>,
    /// What went wrong, when it did.
    pub failure_detail: Option<String>,
}

impl From<AccountZones> for AccountZonesDto {
    fn from(zones: AccountZones) -> Self {
        Self {
            account_id: zones.account_id,
            account_label: zones.account_label,
            zones: zones.zones.into_iter().map(Into::into).collect(),
            failure: zones.failure,
            failure_detail: zones.failure_detail,
        }
    }
}

/// The zones of every Cloudflare account.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsZonesDto {
    /// One entry per account.
    pub accounts: Vec<AccountZonesDto>,
}

/// The records at one name.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsRecordsDto {
    /// The account that answered.
    pub account_id: String,
    /// Its label.
    pub account_label: String,
    /// The zone the name belongs to.
    pub zone: DnsZoneDto,
    /// The name asked about.
    pub name: String,
    /// The records.
    pub records: Vec<DnsRecordDto>,
    /// The `domain/<key>` Registry entry the observation attached to, when
    /// the Registry has one.
    pub registry_entry: Option<String>,
    /// When the records were read (epoch milliseconds).
    pub observed_at: i64,
}

impl From<RecordsView> for DnsRecordsDto {
    fn from(view: RecordsView) -> Self {
        Self {
            account_id: view.account_id,
            account_label: view.account_label,
            zone: view.zone.into(),
            name: view.name,
            records: view.records.into_iter().map(Into::into).collect(),
            registry_entry: view.registry_entry,
            observed_at: view.observed_at,
        }
    }
}

/// Query parameters of the zones list.
#[derive(Debug, Deserialize)]
pub struct ListZonesParams {
    account: Option<String>,
}

/// Lists the zones each Cloudflare account's token can see. One account's
/// failure is reported on that account, not as a failure of the rest.
///
/// # Errors
///
/// Returns the public error envelope on refusal or when no Cloudflare
/// account exists.
#[utoipa::path(
    get,
    path = "/dns/zones",
    tag = "dns",
    operation_id = "listDnsZones",
    params(("account" = Option<String>, Query, description = "Only this Cloudflare account (id or label).")),
    responses(
        (status = 200, description = "The zones per account.", body = Resource<DnsZonesDto>),
        (status = 403, description = "The caller may not read DNS.", body = crate::error::ApiError),
        (status = 404, description = "No Cloudflare account is configured.", body = crate::error::ApiError),
        (status = 503, description = "The DNS surface is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn list_dns_zones(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    dns: Option<Extension<Arc<Dns>>>,
    Query(params): Query<ListZonesParams>,
) -> Result<Json<Resource<DnsZonesDto>>, ApiErrorResponse> {
    let dns = dns_or_error(dns, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let accounts = dns
        .zones(
            state.authorizer.as_ref(),
            &principal.id,
            params.account.as_deref(),
        )
        .await
        .map_err(|error| map_error(&error, correlation_id))?;
    Ok(Json(Resource::new(DnsZonesDto {
        accounts: accounts.into_iter().map(Into::into).collect(),
    })))
}

/// Query parameters of the records read.
#[derive(Debug, Deserialize)]
pub struct ListRecordsParams {
    name: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
    account: Option<String>,
}

/// Reads the records at a fully qualified name through the Cloudflare
/// account whose zone contains it, and records them as an observation beside
/// the matching `domain` Registry entry.
///
/// # Errors
///
/// Returns the public error envelope on refusal, a missing name, an unknown
/// zone, or a provider failure.
#[utoipa::path(
    get,
    path = "/dns/records",
    tag = "dns",
    operation_id = "listDnsRecords",
    params(
        ("name" = String, Query, description = "The fully qualified name."),
        ("type" = Option<String>, Query, description = "Only records of this type."),
        ("account" = Option<String>, Query, description = "The Cloudflare account (id or label), when several hold the zone.")
    ),
    responses(
        (status = 200, description = "The records at the name.", body = Resource<DnsRecordsDto>),
        (status = 400, description = "The name or type is malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not read DNS.", body = crate::error::ApiError),
        (status = 404, description = "No Cloudflare account or zone matches the name.", body = crate::error::ApiError),
        (status = 409, description = "Several accounts hold the zone; name one.", body = crate::error::ApiError),
        (status = 502, description = "Cloudflare refused the token or could not be reached.", body = crate::error::ApiError),
        (status = 503, description = "The DNS surface is not wired, or Cloudflare's rate limit applies.", body = crate::error::ApiError),
    )
)]
pub async fn list_dns_records(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    dns: Option<Extension<Arc<Dns>>>,
    Query(params): Query<ListRecordsParams>,
) -> Result<Json<Resource<DnsRecordsDto>>, ApiErrorResponse> {
    let dns = dns_or_error(dns, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let name = params.name.as_deref().ok_or_else(|| {
        map_error(
            &DnsError::Invalid {
                detail: "the name query parameter is required".to_owned(),
            },
            correlation_id,
        )
    })?;
    let view = dns
        .records(
            state.authorizer.as_ref(),
            &principal.id,
            name,
            params.record_type.as_deref(),
            params.account.as_deref(),
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_error(&error, correlation_id))?;
    Ok(Json(Resource::new(view.into())))
}

/// The records last observed at a name through one Cloudflare account.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsObservationDto {
    /// The account that answered.
    pub account_id: String,
    /// The zone's provider id.
    pub zone_id: String,
    /// The zone's apex name.
    pub zone_name: String,
    /// The name the records are at.
    pub name: String,
    /// The `domain/<key>` Registry entry the records attached to, when the
    /// Registry had one when they were read.
    pub registry_entry: Option<String>,
    /// The records.
    pub records: Vec<DnsRecordDto>,
    /// When they were read (epoch milliseconds).
    pub observed_at: i64,
}

impl From<DnsObservation> for DnsObservationDto {
    fn from(observation: DnsObservation) -> Self {
        Self {
            account_id: observation.account_id,
            zone_id: observation.zone_id,
            zone_name: observation.zone_name,
            name: observation.name,
            registry_entry: observation.registry_entry,
            records: observation.records.into_iter().map(Into::into).collect(),
            observed_at: observation.observed_at,
        }
    }
}

/// The stored observations of one name.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsObservationsDto {
    /// The name asked about.
    pub name: String,
    /// One entry per account and zone that was read, newest first.
    pub observations: Vec<DnsObservationDto>,
}

/// Query parameters of the observations read.
#[derive(Debug, Deserialize)]
pub struct ListObservationsParams {
    name: Option<String>,
}

/// Reads the records last observed at a name through Cloudflare, without
/// calling Cloudflare. These are the zone's own records as Fleet last read
/// them (what a change would act on); the public resolver observations of
/// the domain enricher are kept apart under `/registry`.
///
/// # Errors
///
/// Returns the public error envelope on refusal or a missing or malformed
/// name.
#[utoipa::path(
    get,
    path = "/dns/observations",
    tag = "dns",
    operation_id = "listDnsObservations",
    params(("name" = String, Query, description = "The fully qualified name.")),
    responses(
        (status = 200, description = "The stored observations of the name.", body = Resource<DnsObservationsDto>),
        (status = 400, description = "The name is missing or malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not read DNS.", body = crate::error::ApiError),
        (status = 503, description = "The DNS surface is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn list_dns_observations(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    dns: Option<Extension<Arc<Dns>>>,
    Query(params): Query<ListObservationsParams>,
) -> Result<Json<Resource<DnsObservationsDto>>, ApiErrorResponse> {
    let dns = dns_or_error(dns, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let name = params.name.as_deref().ok_or_else(|| {
        map_error(
            &DnsError::Invalid {
                detail: "the name query parameter is required".to_owned(),
            },
            correlation_id,
        )
    })?;
    let observations = dns
        .observations(state.authorizer.as_ref(), &principal.id, name)
        .await
        .map_err(|error| map_error(&error, correlation_id))?;
    Ok(Json(Resource::new(DnsObservationsDto {
        name: name.trim().trim_end_matches('.').to_ascii_lowercase(),
        observations: observations.into_iter().map(Into::into).collect(),
    })))
}

/// Which change.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsChangeKind {
    /// Create or update a record.
    Upsert,
    /// Delete a record.
    Delete,
}

/// A record change to request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateDnsChangeRequest {
    /// `upsert` or `delete`.
    pub operation: DnsChangeKind,
    /// The fully qualified record name.
    pub name: String,
    /// The record type: A, AAAA, CNAME, TXT, or MX.
    #[serde(rename = "type")]
    pub record_type: String,
    /// The record value. For a delete, the value of the record to remove.
    pub content: String,
    /// The TTL in seconds: 1 (automatic) or 60 to 86400. Upsert only.
    #[serde(default)]
    pub ttl: Option<u32>,
    /// Proxy through Cloudflare (A, AAAA, CNAME). Upsert only.
    #[serde(default)]
    pub proxied: Option<bool>,
    /// The MX preference. Upsert only.
    #[serde(default)]
    pub priority: Option<u16>,
    /// The existing value an upsert replaces. A CNAME replaces its single
    /// value without it.
    #[serde(default)]
    pub replaces: Option<String>,
    /// Add another value beside the records already at the name (A, AAAA,
    /// TXT, MX). Without `replaces` or `add`, an upsert of a multi-value
    /// type is refused while the name already has records of that type.
    #[serde(default)]
    pub add: bool,
    /// The Cloudflare account (id or label), when several hold the zone.
    #[serde(default)]
    pub account: Option<String>,
    /// Why, for the approver (at most 1000 characters).
    pub reason: String,
    /// A key making a retry return the request already made.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// Requests a record change. The controller reads the zone, computes the
/// preview (current record against proposed), and files an action request
/// (`dns.record.upsert` or `dns.record.delete`) whose parameters carry that
/// preview. The default risk class is `approve`: a person approves it in the
/// console or with `fleetctl requests approve`. When the request executes,
/// the zone is read again; a zone that changed since the preview fails the
/// operation instead of being overwritten.
///
/// # Errors
///
/// Returns the public error envelope on refusal, invalid values, an unknown
/// zone, a change that would do nothing, a credential-like TXT value, or a
/// provider failure.
#[utoipa::path(
    post,
    path = "/dns/changes",
    tag = "dns",
    operation_id = "createDnsChange",
    request_body = CreateDnsChangeRequest,
    responses(
        (status = 201, description = "The action request was recorded; its parameters carry the preview.", body = Resource<ActionRequestDto>),
        (status = 400, description = "A value is invalid, the change would do nothing, or a value looks like a credential.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not read DNS or request actions, or policy denies the action.", body = crate::error::ApiError),
        (status = 404, description = "No Cloudflare account or zone matches the name, or the record to delete does not exist.", body = crate::error::ApiError),
        (status = 409, description = "Several accounts hold the zone, or the idempotency key was used for a different request.", body = crate::error::ApiError),
        (status = 502, description = "Cloudflare refused the token or could not be reached.", body = crate::error::ApiError),
        (status = 503, description = "The DNS surface or the broker is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn create_dns_change(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    dns: Option<Extension<Arc<Dns>>>,
    request: Result<Json<CreateDnsChangeRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<ActionRequestDto>>), ApiErrorResponse> {
    let dns = dns_or_error(dns, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        map_error(
            &DnsError::Invalid {
                detail:
                    "the body must be valid JSON with operation, name, type, content, and reason"
                        .to_owned(),
            },
            correlation_id,
        )
    })?;
    let broker = crate::requests::broker_or_error(&state, correlation_id)?;
    let created = dns
        .request_change(
            &broker,
            state.authorizer.as_ref(),
            &principal.id,
            ChangeRequest {
                kind: match request.operation {
                    DnsChangeKind::Upsert => ChangeKind::Upsert,
                    DnsChangeKind::Delete => ChangeKind::Delete,
                },
                name: request.name,
                record_type: request.record_type,
                content: request.content,
                ttl: request.ttl,
                proxied: request.proxied,
                priority: request.priority,
                replaces: request.replaces,
                add: request.add,
                account: request.account,
                reason: request.reason,
                origin: API_ORIGIN.to_owned(),
                correlation_id: Some(correlation_id.to_string()),
                idempotency_key: request.idempotency_key,
            },
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(created.into()))))
}
