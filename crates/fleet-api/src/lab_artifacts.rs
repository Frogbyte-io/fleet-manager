//! The Lab artifact surface (FM-721): exec logs and collected guest files
//! that outlive their lease. Metadata comes from SQLite; the download
//! streams the verified bytes from the controller's artifact store with
//! their digest in `Repr-Digest` (RFC 9530) and `ETag`.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use fleet_application::lab_artifacts::{CollectionFailure, LabArtifact, LabArtifacts};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};
use crate::lab::{lab_or_error, map_lab_error};

/// One stored Lab artifact's metadata.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LabArtifactDto {
    /// The artifact's identity.
    pub id: String,
    /// The lease it came from.
    pub lease_id: String,
    /// The project that lease served, when it recorded one.
    pub project_id: Option<String>,
    /// The lease's owner.
    pub owner: String,
    /// `exec-log` or `file`.
    pub kind: String,
    /// `exec-<operation>.log` for an exec log; the guest path for a file.
    pub name: String,
    /// The size in bytes.
    pub size_bytes: u64,
    /// The lowercase hex sha256 of the bytes.
    pub sha256: String,
    /// Where the bytes live, relative to the controller's artifact store.
    pub location: String,
    /// The `lab.exec` or `lab.collect` operation that produced it.
    pub operation_id: Option<String>,
    /// When it was stored (epoch milliseconds).
    pub created_at: i64,
    /// When the retention sweep deletes it (epoch milliseconds).
    pub retain_until: i64,
}

impl From<LabArtifact> for LabArtifactDto {
    fn from(artifact: LabArtifact) -> Self {
        Self {
            id: artifact.id,
            lease_id: artifact.lease_id,
            project_id: artifact.project_id,
            owner: artifact.owner,
            kind: artifact.kind.id().to_owned(),
            name: artifact.name,
            size_bytes: artifact.size_bytes,
            sha256: artifact.sha256,
            location: artifact.location,
            operation_id: artifact.operation_id,
            created_at: artifact.created_at,
            retain_until: artifact.retain_until,
        }
    }
}

/// A lease's last failed artifact collection.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CollectionFailureDto {
    /// The `lab.collect` operation that failed.
    pub operation_id: String,
    /// A stable reason id, such as `collection_partial`, `collection_failed`,
    /// or `lease_not_ready`.
    pub reason: String,
    /// A bounded detail naming the paths and why each failed.
    pub detail: String,
    /// When it failed (epoch milliseconds).
    pub failed_at: i64,
}

impl From<CollectionFailure> for CollectionFailureDto {
    fn from(failure: CollectionFailure) -> Self {
        Self {
            operation_id: failure.operation_id,
            reason: failure.reason,
            detail: failure.detail,
            failed_at: failure.failed_at,
        }
    }
}

/// The artifact use cases, or the standard envelope when the controller
/// was composed without an artifact store.
fn artifacts_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<LabArtifacts>, ApiErrorResponse> {
    let lab = lab_or_error(state, correlation_id)?;
    lab.artifacts().cloned().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "Lab artifacts are not wired; the controller needs its artifact directory",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// A lease's last failed collection, for the lease detail; `None` when the
/// controller has no artifact store. A backend failure degrades to `None`
/// (logged): the lease read must not fail on auxiliary metadata.
pub(crate) async fn lease_collection_failure(
    state: &crate::operations::ApiState,
    principal: &crate::ActingPrincipal,
    lease_id: &str,
    correlation_id: CorrelationId,
) -> Result<Option<CollectionFailureDto>, ApiErrorResponse> {
    let Some(artifacts) = state.lab.as_ref().and_then(|lab| lab.artifacts().cloned()) else {
        return Ok(None);
    };
    match artifacts
        .collection_failure(state.authorizer.as_ref(), principal, lease_id)
        .await
    {
        Ok(failure) => Ok(failure.map(Into::into)),
        Err(fleet_application::lab::LabUseCaseError::Backend { context, detail }) => {
            eprintln!(
                "lab artifacts: the collection failure of lease {lease_id} is unreadable ({context}): {detail}"
            );
            Ok(None)
        }
        Err(error) => Err(map_lab_error(&error, correlation_id)),
    }
}

/// Guest paths to copy from a ready lease.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CollectArtifactsRequest {
    /// 1 to 16 distinct absolute guest paths of regular files, each at most
    /// 1024 bytes, without `.`, `..`, or empty components or control
    /// characters. Each file must fit the controller's artifact size cap.
    pub paths: Vec<String>,
}

/// Copies declared guest files from a ready lease into the artifact store
/// as a `lab.collect` operation. A path that cannot be copied fails the
/// operation and is recorded on the lease (`collectionFailure`); the paths
/// that were copied stay stored. Collection never changes the lease or its
/// cleanup.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown lease, a lease
/// that is not ready, or invalid paths.
#[utoipa::path(
    post,
    path = "/lab/leases/{leaseId}/artifacts/collect",
    tag = "lab",
    operation_id = "collectLabArtifacts",
    params(("leaseId" = String, Path, description = "The lease's identity.")),
    request_body = CollectArtifactsRequest,
    responses(
        (status = 202, description = "The copy is queued as a `lab.collect` operation; its result lists the stored artifacts.", body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The lease is not ready or has expired, its guest has no Lab machine, or the paths are invalid.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not collect Lab artifacts.", body = crate::error::ApiError),
        (status = 404, description = "The lease does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "The controller has no artifact store.", body = crate::error::ApiError),
    )
)]
pub async fn collect_lab_artifacts(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: axum::http::HeaderMap,
    Path(lease_id): Path<String>,
    request: Result<Json<CollectArtifactsRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let artifacts = artifacts_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        crate::machines::invalid_request(
            "the request body must be valid JSON with a paths array",
            correlation_id,
        )
    })?;
    let mut new = artifacts
        .request_collect(
            state.authorizer.as_ref(),
            &principal,
            &lease_id,
            &request.paths,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    new.correlation_id = Some(correlation_id.to_string());
    // A caller-scoped idempotency key makes a retry return the operation it
    // already queued instead of copying again.
    new.idempotency_key = headers
        .get(crate::IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|key| format!("{}:lab-collect:{lease_id}:{key}", principal.id));
    let operation = state
        .operations
        .create_lab_collect(state.authorizer.as_ref(), &principal.id, &lease_id, &new)
        .await
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
    Ok((StatusCode::ACCEPTED, Json(Resource::new(operation.into()))))
}

/// The list-artifacts query parameters.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListArtifactsParams {
    /// Only artifacts from this lease.
    pub lease_id: Option<String>,
    /// Only artifacts from leases serving this project.
    pub project_id: Option<String>,
    /// The `nextCursor` of the previous page.
    pub cursor: Option<String>,
    /// The page size (1–200; default 50).
    pub limit: Option<u32>,
}

/// Lists the stored Lab artifacts, newest first, one page at a time.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/lab/artifacts",
    tag = "lab",
    operation_id = "listLabArtifacts",
    params(
        ("leaseId" = Option<String>, Query, description = "Only artifacts from this lease."),
        ("projectId" = Option<String>, Query, description = "Only artifacts from leases serving this project."),
        ("cursor" = Option<String>, Query, description = "The `nextCursor` of the previous page."),
        ("limit" = Option<u32>, Query, description = "The page size (1–200; default 50)."),
    ),
    responses(
        (status = 200, description = "The artifacts, newest first.", body = Page<LabArtifactDto>),
        (status = 400, description = "The query parameters are malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not read the Lab surface.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "The controller has no artifact store.", body = crate::error::ApiError),
    )
)]
pub async fn list_lab_artifacts(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    params: Result<
        axum::extract::Query<ListArtifactsParams>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<Page<LabArtifactDto>>, ApiErrorResponse> {
    let params = params.map_err(|rejection| {
        crate::machines::invalid_request(
            &format!("the artifacts list query is malformed: {rejection}"),
            correlation_id,
        )
    })?;
    let artifacts = artifacts_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let limit = params
        .limit
        .unwrap_or(crate::envelope::DEFAULT_PAGE_LIMIT)
        .clamp(1, crate::envelope::MAX_PAGE_LIMIT);
    let mut listed = artifacts
        .list(
            state.authorizer.as_ref(),
            &principal,
            fleet_application::lab_artifacts::ArtifactFilter {
                lease_id: params.lease_id.as_deref(),
                project_id: params.project_id.as_deref(),
                cursor: params.cursor.as_deref(),
            },
            limit + 1,
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    let has_more = listed.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    listed.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    let next_cursor = has_more
        .then(|| listed.last().map(|artifact| artifact.id.clone()))
        .flatten();
    Ok(Json(Page {
        page: PageInfo { next_cursor, limit },
        items: listed.into_iter().map(Into::into).collect(),
    }))
}

/// Reads one Lab artifact's metadata.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown artifact.
#[utoipa::path(
    get,
    path = "/lab/artifacts/{artifactId}",
    tag = "lab",
    operation_id = "getLabArtifact",
    params(("artifactId" = String, Path, description = "The artifact's identity.")),
    responses(
        (status = 200, description = "The artifact's metadata.", body = Resource<LabArtifactDto>),
        (status = 403, description = "The caller may not read the Lab surface.", body = crate::error::ApiError),
        (status = 404, description = "The artifact does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "The controller has no artifact store.", body = crate::error::ApiError),
    )
)]
pub async fn get_lab_artifact(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(artifact_id): Path<String>,
) -> Result<Json<Resource<LabArtifactDto>>, ApiErrorResponse> {
    let artifacts = artifacts_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let artifact = artifacts
        .get(state.authorizer.as_ref(), &principal, &artifact_id)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(Json(Resource::new(artifact.into())))
}

/// An artifact's raw bytes, as the download route streams them.
#[derive(ToSchema)]
#[schema(value_type = String, format = Binary)]
pub struct ArtifactBytes(pub Vec<u8>);

/// How much of an artifact one body chunk carries.
const DOWNLOAD_CHUNK: usize = 64 * 1024;

/// Streams one Lab artifact's bytes. The controller re-hashes them first
/// and refuses (409) bytes that no longer match the recorded size and
/// sha256; the response carries the digest as `Repr-Digest`
/// (`sha-256=:<base64>:`) and `ETag` (`"sha256:<hex>"`) so the client can
/// verify what it received.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown artifact, or
/// bytes that are missing or corrupt.
#[utoipa::path(
    get,
    path = "/lab/artifacts/{artifactId}/content",
    tag = "lab",
    operation_id = "downloadLabArtifact",
    params(("artifactId" = String, Path, description = "The artifact's identity.")),
    responses(
        (status = 200, description = "The artifact's verified bytes.", body = ArtifactBytes, content_type = "application/octet-stream",
            headers(
                ("Repr-Digest" = String, description = "The bytes' sha256, as `sha-256=:<base64>:` (RFC 9530)."),
                ("ETag" = String, description = "The bytes' sha256, as `\"sha256:<hex>\"`."),
            )
        ),
        (status = 403, description = "The caller may not download Lab artifacts.", body = crate::error::ApiError),
        (status = 404, description = "The artifact does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The stored bytes are missing or no longer match their digest.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "The controller has no artifact store.", body = crate::error::ApiError),
    )
)]
pub async fn download_lab_artifact(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(artifact_id): Path<String>,
) -> Result<Response, ApiErrorResponse> {
    let artifacts = artifacts_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let (artifact, reader) = artifacts
        .open(state.authorizer.as_ref(), &principal, &artifact_id)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    let stream = futures_util::stream::unfold(Some(reader), |reader| async move {
        let mut reader = reader?;
        let mut chunk = vec![0_u8; DOWNLOAD_CHUNK];
        match tokio::io::AsyncReadExt::read(&mut reader, &mut chunk).await {
            Ok(0) => None,
            Ok(read) => {
                chunk.truncate(read);
                Some((Ok(Bytes::from(chunk)), Some(reader)))
            }
            Err(error) => Some((Err(error), None)),
        }
    });
    let mut response = Body::from_stream(stream).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(length) = HeaderValue::from_str(&artifact.size_bytes.to_string()) {
        headers.insert(header::CONTENT_LENGTH, length);
    }
    if let Some(digest) =
        repr_digest(&artifact.sha256).and_then(|digest| HeaderValue::from_str(&digest).ok())
    {
        headers.insert("repr-digest", digest);
    }
    if let Ok(etag) = HeaderValue::from_str(&format!("\"sha256:{}\"", artifact.sha256)) {
        headers.insert(header::ETAG, etag);
    }
    if let Ok(disposition) = HeaderValue::from_str(&format!(
        "attachment; filename=\"{}\"",
        download_name(&artifact.name)
    )) {
        headers.insert(header::CONTENT_DISPOSITION, disposition);
    }
    Ok(response)
}

/// The RFC 9530 `Repr-Digest` value for a hex sha256.
fn repr_digest(sha256_hex: &str) -> Option<String> {
    let bytes = (0..sha256_hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(sha256_hex.get(index..index + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    Some(format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

/// A header-safe file name: the artifact name's last path segment, with
/// everything outside `[A-Za-z0-9._-]` replaced.
fn download_name(name: &str) -> String {
    let base = name.rsplit('/').next().unwrap_or_default();
    let safe: String = base
        .chars()
        .take(128)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.trim_matches('.').is_empty() {
        "artifact".to_owned()
    } else {
        safe
    }
}

#[cfg(test)]
mod tests {
    use super::{download_name, repr_digest};

    #[test]
    fn the_digest_header_is_rfc_9530_base64() {
        assert_eq!(
            repr_digest("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
                .as_deref(),
            Some("sha-256=:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=:")
        );
        assert_eq!(repr_digest("zz"), None);
    }

    #[test]
    fn download_names_are_header_safe() {
        assert_eq!(download_name("/var/log/syslog"), "syslog");
        assert_eq!(download_name("/tmp/a \"b\";\r\nx.txt"), "a__b____x.txt");
        assert_eq!(download_name("/tmp/.."), "artifact");
        assert_eq!(download_name("exec-1.log"), "exec-1.log");
    }
}
