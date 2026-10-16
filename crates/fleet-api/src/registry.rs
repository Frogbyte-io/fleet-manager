//! The Registry read surface (FM-1012, ADR 0016): types, entries,
//! entries by type/tag/text/relation target, and reverse relations.
//!
//! Read-only. The data is the active revision's descriptive Registry
//! resources, served from a cache that is rebuilt from the revision's
//! snapshot; every answer names the revision commit it came from, and each
//! entry carries its repository path so a console can build edit links.
//! Authorization is the catalog's `registry.read`, checked in the
//! application use cases.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use fleet_application::project::ProjectUseCaseError;
use fleet_application::registry::enrich::{
    DOMAIN_TYPE, DnsRecords, DnsStatus, DomainEnricher, DomainObservation, DomainView, FieldState,
    RdapStatus, Severity, WarningCode,
};
use fleet_application::registry::{
    Answered, EntryCursor, ReferenceCursor, RegistryEntryFilter, RegistryEntryRecord,
    RegistryReadModel, RegistryReference, RegistryTarget, RegistryTypeRecord, TARGET_CLASSES,
};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, PageInfo};
use crate::error::{ApiError, ApiErrorResponse};
use crate::operations::ApiState;

const MAX_QUERY_TEXT: usize = 200;
const MAX_FILTER_TOKEN: usize = 128;

fn service(
    state: &ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<RegistryReadModel>, ApiErrorResponse> {
    state
        .desired
        .as_ref()
        .and_then(|desired| desired.registry().cloned())
        .ok_or_else(|| {
            let public = PublicError::new(
                ErrorCode::from_str("registry_unavailable").expect("valid error code"),
                "the Registry surface is not wired; the controller needs its database",
                RetryClass::Backoff,
            );
            ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
        })
}

fn invalid(detail: impl Into<String>, correlation_id: CorrelationId) -> ApiErrorResponse {
    crate::projects::map_project_error(
        &ProjectUseCaseError::Invalid {
            detail: detail.into(),
        },
        correlation_id,
    )
}

/// The desired revision a Registry answer was read at.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRevisionDto {
    /// The Fleet Git commit SHA the data came from.
    pub commit_sha: String,
    /// The content digest of the revision.
    pub content_digest: String,
}

/// One Registry type.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistryTypeDto {
    /// The type's name, as entries reference it.
    pub name: String,
    /// `builtin` (shipped with Fleet) or `repository` (a `RegistryType`
    /// resource in Fleet Git).
    pub origin: String,
    /// The resource identity, for repository types.
    pub resource_id: Option<String>,
    /// The human-facing name.
    pub display_name: String,
    /// The field holding an entry's natural key.
    pub key_field: String,
    /// The relation names entries of this type may declare.
    pub relations: Vec<String>,
    /// The type's spec: declared fields and their value types.
    pub spec: serde_json::Value,
    /// The defining document's repository path, for repository types, when
    /// the snapshot recorded it.
    pub source_path: Option<String>,
    /// How many entries of this type the revision holds.
    pub entry_count: i64,
}

/// What a relation points at.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistryTargetDto {
    /// `registry`, `machine`, `project`, `coolify`, or `proxmoxGuest`.
    pub class: String,
    /// The reference within the class: `<type>/<key>` for `registry`, a
    /// name for `machine` and `project`, the recorded reference otherwise.
    pub reference: String,
}

/// One relation of an entry.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRelationDto {
    /// The relation type, for example `used-by`.
    #[serde(rename = "type")]
    pub relation_type: String,
    /// What it points at.
    pub target: RegistryTargetDto,
}

/// One Registry entry.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistryEntryDto {
    /// The entry's type.
    #[serde(rename = "type")]
    pub entry_type: String,
    /// The natural key, unique per type: the entry is `<type>/<key>`.
    pub key: String,
    /// The stable resource identity.
    pub id: String,
    /// The resource's slug name.
    pub name: String,
    /// The field values, as declared by the type.
    pub fields: serde_json::Value,
    /// The tags.
    pub tags: Vec<String>,
    /// Links to dashboards and documents.
    pub links: serde_json::Value,
    /// Free-form notes.
    pub notes: Option<String>,
    /// The entry's outgoing relations.
    pub relations: Vec<RegistryRelationDto>,
    /// The entry's repository-relative file path in the revision, when the
    /// snapshot recorded it. Null for a revision fetched before paths were
    /// recorded.
    pub source_path: Option<String>,
}

/// An entry that points at the queried target.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistryReferenceDto {
    /// The relation type the entry declares.
    pub relation: String,
    /// The pointing entry's type.
    pub entry_type: String,
    /// The pointing entry's key.
    pub entry_key: String,
    /// The pointing entry's slug name.
    pub entry_name: String,
    /// The pointing entry's repository path, when recorded.
    pub source_path: Option<String>,
}

/// A page of Registry data and the revision it was read at.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistryPage<T> {
    /// The active revision, or null while none has been activated (the
    /// list is then empty).
    pub revision: Option<RegistryRevisionDto>,
    /// The items, in the endpoint's documented order.
    pub items: Vec<T>,
    /// Where this page sits in the result set.
    pub page: PageInfo,
}

/// One Registry resource and the revision it was read at.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistryOne<T> {
    /// The active revision.
    pub revision: RegistryRevisionDto,
    /// The resource.
    pub data: T,
}

/// The type list: all types of the active revision.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistryTypeList {
    /// The active revision, or null while none has been activated.
    pub revision: Option<RegistryRevisionDto>,
    /// The types, ordered by name.
    pub items: Vec<RegistryTypeDto>,
}

/// Filters, cursor, and bound for the entry list.
#[derive(Clone, Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct RegistryEntriesParams {
    /// Only entries of this type.
    #[serde(rename = "type")]
    #[param(rename = "type")]
    pub entry_type: Option<String>,
    /// Only entries carrying this tag (exact match).
    pub tag: Option<String>,
    /// Only entries whose key, name, field values, tags, or notes contain
    /// this text (case-insensitive substring).
    pub q: Option<String>,
    /// Only entries with a relation to this target, as `<class>:<reference>`
    /// (for example `machine:build-1` or `registry:service/aptabase`).
    pub target: Option<String>,
    /// With `target`, only relations of this type.
    pub relation: Option<String>,
    /// Opaque cursor returned as the previous page's `nextCursor`.
    pub cursor: Option<String>,
    /// Requested page size, clamped to the API maximum.
    pub limit: Option<u32>,
}

/// Target, cursor, and bound for reverse-relation lookups.
#[derive(Clone, Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct RegistryReferencesParams {
    /// The target, as `<class>:<reference>`: `registry:<type>/<key>`,
    /// `machine:<name>`, `project:<name>`, `coolify:<reference>`, or
    /// `proxmoxGuest:<reference>`.
    pub target: String,
    /// Only relations of this type.
    pub relation: Option<String>,
    /// Opaque cursor returned as the previous page's `nextCursor`.
    pub cursor: Option<String>,
    /// Requested page size, clamped to the API maximum.
    pub limit: Option<u32>,
}

/// Cursor and bound for the per-entry reverse-relation lookup.
#[derive(Clone, Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct RegistryEntryReferencesParams {
    /// Only relations of this type.
    pub relation: Option<String>,
    /// Opaque cursor returned as the previous page's `nextCursor`.
    pub cursor: Option<String>,
    /// Requested page size, clamped to the API maximum.
    pub limit: Option<u32>,
}

fn principal(
    principal: Option<Extension<crate::ActingPrincipal>>,
    correlation_id: CorrelationId,
) -> Result<crate::ActingPrincipal, ApiErrorResponse> {
    crate::operations::principal_or_error(principal, correlation_id)
}

fn revision_dto(
    revision: Option<fleet_application::source::ActiveRevision>,
) -> Option<RegistryRevisionDto> {
    revision.map(|revision| RegistryRevisionDto {
        commit_sha: revision.commit_sha,
        content_digest: revision.content_digest,
    })
}

fn type_dto(record: RegistryTypeRecord) -> RegistryTypeDto {
    RegistryTypeDto {
        name: record.name,
        origin: record.origin.as_str().to_owned(),
        resource_id: record.resource_id,
        display_name: record.display_name,
        key_field: record.key_field,
        relations: record.relations,
        spec: record.spec,
        source_path: record.source_path,
        entry_count: record.entry_count,
    }
}

fn entry_dto(record: RegistryEntryRecord) -> RegistryEntryDto {
    RegistryEntryDto {
        entry_type: record.entry_type,
        key: record.key,
        id: record.resource_id,
        name: record.name,
        fields: record.fields,
        tags: record.tags,
        links: record.links,
        notes: record.notes,
        relations: record
            .relations
            .into_iter()
            .map(|relation| RegistryRelationDto {
                relation_type: relation.relation_type,
                target: RegistryTargetDto {
                    class: relation.target.class,
                    reference: relation.target.reference,
                },
            })
            .collect(),
        source_path: record.source_path,
    }
}

fn reference_dto(record: RegistryReference) -> RegistryReferenceDto {
    RegistryReferenceDto {
        relation: record.relation_type,
        entry_type: record.entry_type,
        entry_key: record.entry_key,
        entry_name: record.entry_name,
        source_path: record.source_path,
    }
}

fn page_limit(limit: Option<u32>) -> u32 {
    limit.unwrap_or(DEFAULT_PAGE_LIMIT).clamp(1, MAX_PAGE_LIMIT)
}

/// Trims a page fetched with one extra row and derives the next cursor.
fn paginate<T, C>(
    mut found: Vec<T>,
    limit: u32,
    cursor_of: impl Fn(&T) -> C,
) -> (Vec<T>, Option<C>) {
    let bound = usize::try_from(limit).unwrap_or(usize::MAX);
    let more = found.len() > bound;
    found.truncate(bound);
    let next = more.then(|| found.last().map(cursor_of)).flatten();
    (found, next)
}

fn token(
    name: &str,
    value: Option<String>,
    correlation_id: CorrelationId,
) -> Result<Option<String>, ApiErrorResponse> {
    match value {
        None => Ok(None),
        Some(value) => {
            let value = value.trim().to_owned();
            if value.is_empty()
                || value.len() > MAX_FILTER_TOKEN
                || value.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(invalid(
                    format!("the {name} filter is empty or malformed"),
                    correlation_id,
                ));
            }
            Ok(Some(value))
        }
    }
}

fn target(text: &str, correlation_id: CorrelationId) -> Result<RegistryTarget, ApiErrorResponse> {
    RegistryTarget::parse(text).map_err(|detail| {
        invalid(
            format!("{detail} (classes: {})", TARGET_CLASSES.join(", ")),
            correlation_id,
        )
    })
}

fn entry_cursor(
    cursor: Option<&str>,
    correlation_id: CorrelationId,
) -> Result<Option<EntryCursor>, ApiErrorResponse> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    fleet_application::registry::split_entry_ref(cursor)
        .map(|(entry_type, key)| {
            Some(EntryCursor {
                entry_type: entry_type.to_owned(),
                key: key.to_owned(),
            })
        })
        .ok_or_else(|| {
            invalid(
                "the cursor is not one this endpoint returned",
                correlation_id,
            )
        })
}

fn reference_cursor(
    cursor: Option<&str>,
    correlation_id: CorrelationId,
) -> Result<Option<ReferenceCursor>, ApiErrorResponse> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let mut parts = cursor.splitn(3, '/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(entry_type), Some(key), Some(relation))
            if !entry_type.is_empty() && !key.is_empty() && !relation.is_empty() =>
        {
            Ok(Some(ReferenceCursor {
                entry_type: entry_type.to_owned(),
                key: key.to_owned(),
                relation_type: relation.to_owned(),
            }))
        }
        _ => Err(invalid(
            "the cursor is not one this endpoint returned",
            correlation_id,
        )),
    }
}

/// Lists the Registry types of the active revision.
///
/// # Errors
///
/// Returns an API error when authentication, authorization, or storage fails.
#[utoipa::path(get, path = "/registry/types", tag = "registry", operation_id = "listRegistryTypes", responses(
        (status = 200, body = RegistryTypeList),
        (status = 403, description = "The caller may not read the Registry.", body = ApiError),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The Registry surface is not wired.", body = ApiError),
    ))]
pub async fn list_registry_types(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<RegistryTypeList>, ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    let Answered { revision, value } = service(&state, correlation_id)?
        .list_types(state.authorizer.as_ref(), &acting.id)
        .await
        .map_err(|error| crate::projects::map_project_error(&error, correlation_id))?;
    Ok(Json(RegistryTypeList {
        revision: revision_dto(revision),
        items: value.into_iter().map(type_dto).collect(),
    }))
}

/// Lists Registry entries, filtered by type, tag, text, and relation
/// target, ordered by type then key.
///
/// # Errors
///
/// Returns an API error when a filter is malformed, or authentication,
/// authorization, or storage fails.
#[utoipa::path(get, path = "/registry/entries", tag = "registry", operation_id = "listRegistryEntries", params(RegistryEntriesParams), responses(
        (status = 200, body = RegistryPage<RegistryEntryDto>),
        (status = 400, description = "A filter or the cursor is malformed.", body = ApiError),
        (status = 403, description = "The caller may not read the Registry.", body = ApiError),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The Registry surface is not wired.", body = ApiError),
    ))]
pub async fn list_registry_entries(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<RegistryEntriesParams>,
) -> Result<Json<RegistryPage<RegistryEntryDto>>, ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    let limit = page_limit(params.limit);
    let query = match params.q {
        None => None,
        Some(text) => {
            let text = text.trim().to_owned();
            if text.is_empty() || text.len() > MAX_QUERY_TEXT {
                return Err(invalid(
                    "the q filter is empty or longer than 200 bytes",
                    correlation_id,
                ));
            }
            Some(text)
        }
    };
    let target = params
        .target
        .as_deref()
        .map(|text| target(text, correlation_id))
        .transpose()?;
    let relation = token("relation", params.relation, correlation_id)?;
    if relation.is_some() && target.is_none() {
        return Err(invalid(
            "the relation filter needs a target",
            correlation_id,
        ));
    }
    let filter = RegistryEntryFilter {
        entry_type: token("type", params.entry_type, correlation_id)?,
        tag: token("tag", params.tag, correlation_id)?,
        query,
        target,
        relation,
    };
    let after = entry_cursor(params.cursor.as_deref(), correlation_id)?;
    let Answered { revision, value } = service(&state, correlation_id)?
        .list_entries(
            state.authorizer.as_ref(),
            &acting.id,
            &filter,
            after.as_ref(),
            i64::from(limit),
        )
        .await
        .map_err(|error| crate::projects::map_project_error(&error, correlation_id))?;
    let (items, next_cursor) = paginate(value, limit, |entry| {
        format!("{}/{}", entry.entry_type, entry.key)
    });
    Ok(Json(RegistryPage {
        revision: revision_dto(revision),
        items: items.into_iter().map(entry_dto).collect(),
        page: PageInfo { next_cursor, limit },
    }))
}

/// Reads one Registry entry by its `<type>/<key>` address.
///
/// # Errors
///
/// Returns an API error when the entry does not exist, or authentication,
/// authorization, or storage fails.
#[utoipa::path(get, path = "/registry/entries/{type}/{key}", tag = "registry", operation_id = "getRegistryEntry", params(
        ("type" = String, Path, description = "The entry's type name."),
        ("key" = String, Path, description = "The entry's natural key."),
    ), responses(
        (status = 200, body = RegistryOne<RegistryEntryDto>),
        (status = 403, description = "The caller may not read the Registry.", body = ApiError),
        (status = 404, description = "No such entry in the active revision.", body = ApiError),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The Registry surface is not wired.", body = ApiError),
    ))]
pub async fn get_registry_entry(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path((entry_type, key)): Path<(String, String)>,
) -> Result<Json<RegistryOne<RegistryEntryDto>>, ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    let Answered { revision, value } = service(&state, correlation_id)?
        .get_entry(state.authorizer.as_ref(), &acting.id, &entry_type, &key)
        .await
        .map_err(|error| crate::projects::map_project_error(&error, correlation_id))?;
    let revision = revision_dto(revision).ok_or_else(|| {
        crate::projects::map_project_error(
            &ProjectUseCaseError::NotFound {
                what: "registry entry".to_owned(),
            },
            correlation_id,
        )
    })?;
    Ok(Json(RegistryOne {
        revision,
        data: entry_dto(value),
    }))
}

/// Lists the entries that point at one entry ("what uses
/// `service/aptabase`?"), ordered by type, key, then relation.
///
/// # Errors
///
/// Returns an API error when the cursor is malformed, or authentication,
/// authorization, or storage fails.
#[utoipa::path(get, path = "/registry/entries/{type}/{key}/referenced-by", tag = "registry", operation_id = "listRegistryEntryReferences", params(
        ("type" = String, Path, description = "The entry's type name."),
        ("key" = String, Path, description = "The entry's natural key."),
        RegistryEntryReferencesParams,
    ), responses(
        (status = 200, body = RegistryPage<RegistryReferenceDto>),
        (status = 400, description = "A filter or the cursor is malformed.", body = ApiError),
        (status = 403, description = "The caller may not read the Registry.", body = ApiError),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The Registry surface is not wired.", body = ApiError),
    ))]
pub async fn list_registry_entry_references(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path((entry_type, key)): Path<(String, String)>,
    Query(params): Query<RegistryEntryReferencesParams>,
) -> Result<Json<RegistryPage<RegistryReferenceDto>>, ApiErrorResponse> {
    let target = target(&format!("registry:{entry_type}/{key}"), correlation_id)?;
    references(
        &state,
        acting,
        correlation_id,
        &target,
        params.relation,
        params.cursor,
        params.limit,
    )
    .await
}

/// Lists the entries that point at a target: a Registry entry, a machine,
/// a project, a Coolify resource, or a Proxmox guest ("what points at
/// machine X?"), ordered by type, key, then relation.
///
/// # Errors
///
/// Returns an API error when the target or cursor is malformed, or
/// authentication, authorization, or storage fails.
#[utoipa::path(get, path = "/registry/references", tag = "registry", operation_id = "listRegistryReferences", params(RegistryReferencesParams), responses(
        (status = 200, body = RegistryPage<RegistryReferenceDto>),
        (status = 400, description = "The target, a filter, or the cursor is malformed.", body = ApiError),
        (status = 403, description = "The caller may not read the Registry.", body = ApiError),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The Registry surface is not wired.", body = ApiError),
    ))]
pub async fn list_registry_references(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<RegistryReferencesParams>,
) -> Result<Json<RegistryPage<RegistryReferenceDto>>, ApiErrorResponse> {
    let target = target(&params.target, correlation_id)?;
    references(
        &state,
        acting,
        correlation_id,
        &target,
        params.relation,
        params.cursor,
        params.limit,
    )
    .await
}

async fn references(
    state: &ApiState,
    acting: Option<Extension<crate::ActingPrincipal>>,
    correlation_id: CorrelationId,
    target: &RegistryTarget,
    relation: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
) -> Result<Json<RegistryPage<RegistryReferenceDto>>, ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    let limit = page_limit(limit);
    let relation = token("relation", relation, correlation_id)?;
    let after = reference_cursor(cursor.as_deref(), correlation_id)?;
    let Answered { revision, value } = service(state, correlation_id)?
        .list_references(
            state.authorizer.as_ref(),
            &acting.id,
            target,
            relation.as_deref(),
            after.as_ref(),
            i64::from(limit),
        )
        .await
        .map_err(|error| crate::projects::map_project_error(&error, correlation_id))?;
    let (items, next_cursor) = paginate(value, limit, |reference| {
        format!(
            "{}/{}/{}",
            reference.entry_type, reference.entry_key, reference.relation_type
        )
    });
    Ok(Json(RegistryPage {
        revision: revision_dto(revision),
        items: items.into_iter().map(reference_dto).collect(),
        page: PageInfo { next_cursor, limit },
    }))
}

// ---------------------------------------------------------------------------
// Domain observations (FM-1020)

fn enricher(
    state: &ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<DomainEnricher>, ApiErrorResponse> {
    state
        .desired
        .as_ref()
        .and_then(|desired| desired.domain_enricher().cloned())
        .ok_or_else(|| {
            let public = PublicError::new(
                ErrorCode::from_str("registry_unavailable").expect("valid error code"),
                "the domain lookup enricher is not wired; the controller needs its database",
                RetryClass::Backoff,
            );
            ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
        })
}

/// The status of the RDAP half of an observation.
#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RdapStatusDto {
    /// A server answered with a domain object.
    Ok,
    /// No RDAP service covers the TLD. A normal answer, not a failure.
    Unavailable,
    /// The registry reports the domain is not registered.
    NotFound,
    /// The lookup failed.
    Error,
}

/// The RDAP half of a domain observation.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RdapObservationDto {
    /// How the lookup ended.
    pub status: RdapStatusDto,
    /// The RDAP server's base URL, when one was resolved.
    pub server: Option<String>,
    /// The registrar's name as the registry reports it.
    pub registrar: Option<String>,
    /// The expiry as a calendar date (`YYYY-MM-DD`). Some ccTLD registries
    /// do not publish one.
    pub expires: Option<String>,
    /// The EPP status values.
    pub statuses: Vec<String>,
    /// The nameservers the registry lists.
    pub nameservers: Vec<String>,
    /// Why, for `unavailable`, `not_found`, and `error`.
    pub detail: Option<String>,
}

/// Records of each type at one DNS name.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsRecordsDto {
    /// NS values (meaningful at the apex).
    pub ns: Vec<String>,
    /// A values.
    pub a: Vec<String>,
    /// AAAA values.
    pub aaaa: Vec<String>,
    /// CNAME values.
    pub cname: Vec<String>,
}

/// The status of the DNS half of an observation.
#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsStatusDto {
    /// Every query answered (possibly with no records).
    Ok,
    /// The apex does not exist.
    NotFound,
    /// At least one query failed; the answers that arrived are kept.
    Error,
}

/// The DNS half of a domain observation.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DnsObservationDto {
    /// How the lookup ended.
    pub status: DnsStatusDto,
    /// Records at the apex.
    pub apex: DnsRecordsDto,
    /// Records at `www.<apex>`.
    pub www: DnsRecordsDto,
    /// Why, for `not_found` and `error`.
    pub detail: Option<String>,
}

/// One public lookup result for a domain entry. Recorded in the
/// controller's database; never written to Fleet Git.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DomainObservationDto {
    /// When the lookups finished (epoch milliseconds).
    pub observed_at: i64,
    /// The public registration data.
    pub rdap: RdapObservationDto,
    /// The public DNS data.
    pub dns: DnsObservationDto,
}

/// How a field's recorded value compares with the observation.
#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FieldStateDto {
    /// Both sides have a value and they agree.
    InSync,
    /// The observation differs from the recorded value or supplies one the
    /// entry lacks.
    Changed,
    /// Nothing to compare: no observation of the field, or no value on
    /// either side.
    Unknown,
}

/// The difference for one entry field.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FieldDiffDto {
    /// `registrar`, `expires`, `nameservers`, or `dnsHost`.
    pub field: String,
    /// The comparison.
    pub state: FieldStateDto,
    /// What the entry (Fleet Git) records.
    #[schema(value_type = Option<Object>)]
    pub recorded: Option<serde_json::Value>,
    /// What the lookups saw.
    #[schema(value_type = Option<Object>)]
    pub observed: Option<serde_json::Value>,
}

/// How serious a warning is.
#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SeverityDto {
    /// Worth knowing.
    Info,
    /// Needs a person soon.
    Warn,
    /// Needs a person now.
    Err,
}

/// The derived warning rules.
#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WarningCodeDto {
    /// The registry's registrar is not the recorded one.
    RegistrarMismatch,
    /// The delegated nameservers are not the recorded ones.
    NameserversMismatch,
    /// The nameservers do not belong to the recorded `dnsHost`.
    DnsHostMismatch,
    /// The registry's expiry is not the recorded one.
    ExpiryChanged,
    /// The domain expires within the window, or already has.
    Expiring,
    /// The domain expires within the window and auto-renew is off.
    AutoRenewOffExpiring,
}

/// One derived warning.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DomainWarningDto {
    /// Which rule fired.
    pub code: WarningCodeDto,
    /// How serious it is.
    pub severity: SeverityDto,
    /// A sentence for people.
    pub message: String,
}

/// One suggested field value.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SuggestedFieldDto {
    /// The entry field.
    pub field: String,
    /// The suggested value, in the field's type (a string, or a list of
    /// strings for `nameservers`).
    #[schema(value_type = Object)]
    pub value: serde_json::Value,
}

/// A domain entry's latest observation compared with the entry.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DomainObservationViewDto {
    /// The entry's key (`domain/<key>`).
    pub key: String,
    /// The latest observation, or null before the first lookup.
    pub observation: Option<DomainObservationDto>,
    /// Per-field comparison, in a stable order.
    pub diffs: Vec<FieldDiffDto>,
    /// Derived warnings, most serious first. These feed the Overview's
    /// needs-attention queue.
    pub warnings: Vec<DomainWarningDto>,
    /// The field changes that would bring the entry in line with the
    /// observation. A person or agent applies them with
    /// `fleetctl registry set` and publishes through Git; Fleet never
    /// writes them.
    pub suggestion: Vec<SuggestedFieldDto>,
}

/// A page of domain observation views.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DomainObservationPage {
    /// The views, ordered by key.
    pub items: Vec<DomainObservationViewDto>,
    /// Where this page sits in the result set.
    pub page: PageInfo,
}

/// Filters, cursor, and bound for the observation list.
#[derive(Clone, Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct DomainObservationsParams {
    /// Only domains with at least one warning.
    pub attention: Option<bool>,
    /// Opaque cursor returned as the previous page's `nextCursor`.
    pub cursor: Option<String>,
    /// Requested page size, clamped to the API maximum.
    pub limit: Option<u32>,
}

fn observation_dto(observation: DomainObservation) -> DomainObservationDto {
    let records = |records: DnsRecords| DnsRecordsDto {
        ns: records.ns,
        a: records.a,
        aaaa: records.aaaa,
        cname: records.cname,
    };
    DomainObservationDto {
        observed_at: observation.observed_at,
        rdap: RdapObservationDto {
            status: match observation.rdap.status {
                RdapStatus::Ok => RdapStatusDto::Ok,
                RdapStatus::Unavailable => RdapStatusDto::Unavailable,
                RdapStatus::NotFound => RdapStatusDto::NotFound,
                RdapStatus::Error => RdapStatusDto::Error,
            },
            server: observation.rdap.server,
            registrar: observation.rdap.registrar,
            expires: observation.rdap.expires,
            statuses: observation.rdap.statuses,
            nameservers: observation.rdap.nameservers,
            detail: observation.rdap.detail,
        },
        dns: DnsObservationDto {
            status: match observation.dns.status {
                DnsStatus::Ok => DnsStatusDto::Ok,
                DnsStatus::NotFound => DnsStatusDto::NotFound,
                DnsStatus::Error => DnsStatusDto::Error,
            },
            apex: records(observation.dns.apex),
            www: records(observation.dns.www),
            detail: observation.dns.detail,
        },
    }
}

fn view_dto(view: DomainView) -> DomainObservationViewDto {
    DomainObservationViewDto {
        key: view.key,
        observation: view.observation.map(observation_dto),
        diffs: view
            .assessment
            .diffs
            .into_iter()
            .map(|diff| FieldDiffDto {
                field: diff.field.to_owned(),
                state: match diff.state {
                    FieldState::InSync => FieldStateDto::InSync,
                    FieldState::Changed => FieldStateDto::Changed,
                    FieldState::Unknown => FieldStateDto::Unknown,
                },
                recorded: diff.recorded,
                observed: diff.observed,
            })
            .collect(),
        warnings: view
            .assessment
            .warnings
            .into_iter()
            .map(|warning| DomainWarningDto {
                code: match warning.code {
                    WarningCode::RegistrarMismatch => WarningCodeDto::RegistrarMismatch,
                    WarningCode::NameserversMismatch => WarningCodeDto::NameserversMismatch,
                    WarningCode::DnsHostMismatch => WarningCodeDto::DnsHostMismatch,
                    WarningCode::ExpiryChanged => WarningCodeDto::ExpiryChanged,
                    WarningCode::Expiring => WarningCodeDto::Expiring,
                    WarningCode::AutoRenewOffExpiring => WarningCodeDto::AutoRenewOffExpiring,
                },
                severity: match warning.severity {
                    Severity::Info => SeverityDto::Info,
                    Severity::Warn => SeverityDto::Warn,
                    Severity::Err => SeverityDto::Err,
                },
                message: warning.message,
            })
            .collect(),
        suggestion: view
            .assessment
            .suggestion
            .into_iter()
            .map(|field| SuggestedFieldDto {
                field: field.field.to_owned(),
                value: field.value,
            })
            .collect(),
    }
}

/// Only `domain` entries are observed.
fn domain_only(entry_type: &str, correlation_id: CorrelationId) -> Result<(), ApiErrorResponse> {
    if entry_type == DOMAIN_TYPE {
        Ok(())
    } else {
        Err(invalid(
            "observations exist only for domain entries",
            correlation_id,
        ))
    }
}

/// Maps an enrichment failure; a refused rate-limit slot is a 429 with the
/// reason, any other backend failure stays generic.
fn map_enrich_error(
    error: &ProjectUseCaseError,
    correlation_id: CorrelationId,
) -> ApiErrorResponse {
    if let ProjectUseCaseError::Backend {
        context: "registry_observe_rate_limited",
        detail,
    } = error
    {
        let public = PublicError::new(
            ErrorCode::from_str("rate_limited").expect("valid error code"),
            detail.clone(),
            RetryClass::Backoff,
        );
        return ApiError::new(&public, correlation_id).with_status(StatusCode::TOO_MANY_REQUESTS);
    }
    crate::projects::map_project_error(error, correlation_id)
}

/// Lists the observations of domain entries, compared with the entries,
/// ordered by key. With `attention=true`, only domains with a warning:
/// the feed of the Overview's needs-attention queue.
///
/// # Errors
///
/// Returns an API error when the cursor is malformed, or authentication,
/// authorization, or storage fails.
#[utoipa::path(get, path = "/registry/observations", tag = "registry", operation_id = "listDomainObservations", params(DomainObservationsParams), responses(
        (status = 200, body = DomainObservationPage),
        (status = 400, description = "The cursor is malformed.", body = ApiError),
        (status = 403, description = "The caller may not read the Registry.", body = ApiError),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The enricher is not wired.", body = ApiError),
    ))]
pub async fn list_domain_observations(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<DomainObservationsParams>,
) -> Result<Json<DomainObservationPage>, ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    let limit = page_limit(params.limit);
    let after = params
        .cursor
        .as_deref()
        .map(|cursor| {
            fleet_application::registry::split_entry_ref(cursor)
                .filter(|(entry_type, _)| *entry_type == DOMAIN_TYPE)
                .map(|(_, key)| key.to_owned())
                .ok_or_else(|| {
                    invalid(
                        "the cursor is not one this endpoint returned",
                        correlation_id,
                    )
                })
        })
        .transpose()?;
    let bound = usize::try_from(limit).unwrap_or(usize::MAX);
    let found = enricher(&state, correlation_id)?
        .list(
            state.authorizer.as_ref(),
            &acting.id,
            params.attention.unwrap_or(false),
            after.as_deref(),
            bound.saturating_add(1),
        )
        .await
        .map_err(|error| map_enrich_error(&error, correlation_id))?;
    let (items, next_cursor) = paginate(found, limit, |view| format!("{DOMAIN_TYPE}/{}", view.key));
    Ok(Json(DomainObservationPage {
        items: items.into_iter().map(view_dto).collect(),
        page: PageInfo { next_cursor, limit },
    }))
}

/// Reads one domain entry's latest observation and its comparison with the
/// entry.
///
/// # Errors
///
/// Returns an API error when the entry does not exist or is not a domain,
/// or authentication, authorization, or storage fails.
#[utoipa::path(get, path = "/registry/entries/{type}/{key}/observations", tag = "registry", operation_id = "getDomainObservation", params(
        ("type" = String, Path, description = "The entry's type name; only `domain`."),
        ("key" = String, Path, description = "The entry's natural key."),
    ), responses(
        (status = 200, body = DomainObservationViewDto),
        (status = 400, description = "The entry is not a domain.", body = ApiError),
        (status = 403, description = "The caller may not read the Registry.", body = ApiError),
        (status = 404, description = "No such entry in the active revision.", body = ApiError),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The enricher is not wired.", body = ApiError),
    ))]
pub async fn get_domain_observation(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path((entry_type, key)): Path<(String, String)>,
) -> Result<Json<DomainObservationViewDto>, ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    domain_only(&entry_type, correlation_id)?;
    let view = enricher(&state, correlation_id)?
        .get(state.authorizer.as_ref(), &acting.id, &key)
        .await
        .map_err(|error| map_enrich_error(&error, correlation_id))?;
    Ok(Json(view_dto(view)))
}

/// Looks the domain up now (RDAP and DNS) and records the observation. A
/// mutation of observations, never of Fleet Git: authorized as
/// `registry.observe` and audited.
///
/// # Errors
///
/// Returns an API error when the entry does not exist or is not a domain,
/// the caller may not observe, the RDAP server's rate-limit slot is not
/// available soon (429), or storage fails. A lookup that fails is recorded
/// in the returned observation, not reported as an error.
#[utoipa::path(post, path = "/registry/entries/{type}/{key}/observations/refresh", tag = "registry", operation_id = "refreshDomainObservation", params(
        ("type" = String, Path, description = "The entry's type name; only `domain`."),
        ("key" = String, Path, description = "The entry's natural key."),
    ), responses(
        (status = 200, body = DomainObservationViewDto),
        (status = 400, description = "The entry is not a domain.", body = ApiError),
        (status = 403, description = "The caller may not observe.", body = ApiError),
        (status = 404, description = "No such entry in the active revision.", body = ApiError),
        (status = 429, description = "The RDAP server is being queried at its rate limit.", body = ApiError),
        (status = 500, description = "The request could not be completed.", body = ApiError),
        (status = 503, description = "The enricher is not wired.", body = ApiError),
    ))]
pub async fn refresh_domain_observation(
    State(state): State<Arc<ApiState>>,
    acting: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path((entry_type, key)): Path<(String, String)>,
) -> Result<Json<DomainObservationViewDto>, ApiErrorResponse> {
    let acting = principal(acting, correlation_id)?;
    domain_only(&entry_type, correlation_id)?;
    let view = enricher(&state, correlation_id)?
        .refresh(
            state.authorizer.as_ref(),
            &acting.id,
            Some(&correlation_id.to_string()),
            &key,
        )
        .await
        .map_err(|error| map_enrich_error(&error, correlation_id))?;
    Ok(Json(view_dto(view)))
}
