//! `POST /lab/leases/{id}/files` (#393): copy one file into a ready lease.
//!
//! The request body is the raw file. It is streamed chunk by chunk into a
//! controller-owned staging file; the cap is enforced while streaming, so an
//! oversized upload is refused as soon as it passes the cap and the body is
//! never buffered. Authorization and the lease checks run before the first
//! byte is read. The queued `lab.put` operation carries the staging id,
//! size, and SHA-256, never the bytes.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
};
use fleet_application::lab::LabUseCaseError;
use fleet_application::lab_artifacts::{BlobError, is_sha256_hex};
use fleet_application::lab_put::{LabPuts, PutTarget, StagedUpload, UploadWriter};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use futures_util::StreamExt as _;
use serde::Deserialize;
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::{ApiError, ApiErrorResponse};
use crate::lab::{lab_or_error, map_lab_error};

/// The longest the controller waits for the next piece of an upload body.
const UPLOAD_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(1);

/// The header a caller may use to declare the file's SHA-256; the controller
/// refuses the upload when what it received hashes differently.
pub const CONTENT_SHA256_HEADER: &str = "x-content-sha256";

/// Where in the guest to put the uploaded file.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PutLabFileParams {
    /// The absolute guest path of the file to create: no `.`, `..`, or empty
    /// components, no control characters, at most 1024 bytes. Its directory
    /// must already exist.
    pub path: String,
    /// Replace an existing regular file at the path. By default an existing
    /// file at the path is refused. A directory or symlink is never replaced.
    #[serde(default)]
    pub overwrite: bool,
}

fn puts_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<LabPuts>, ApiErrorResponse> {
    let lab = lab_or_error(state, correlation_id)?;
    lab.puts().cloned().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "Lab put is not wired; the controller needs its artifact directory",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

fn too_large(max_bytes: u64, correlation_id: CorrelationId) -> ApiErrorResponse {
    let public = PublicError::new(
        ErrorCode::from_str("payload_too_large").expect("the literal is valid error code syntax"),
        format!("the file exceeds the {max_bytes}-byte upload cap"),
        RetryClass::Never,
    );
    ApiError::new(&public, correlation_id).with_status(StatusCode::PAYLOAD_TOO_LARGE)
}

/// Streams the request body into the staging writer, chunk by chunk. A
/// refusal (cap exceeded, unreadable body) drops the writer, which removes
/// the partial file, and stops reading.
async fn stream_upload(
    mut writer: Box<dyn UploadWriter>,
    body: Body,
    correlation_id: CorrelationId,
) -> Result<StagedUpload, ApiErrorResponse> {
    let mut stream = body.into_data_stream();
    loop {
        let next = tokio::time::timeout(UPLOAD_IDLE_TIMEOUT, stream.next())
            .await
            .map_err(|_| {
                let public = PublicError::new(
                    ErrorCode::from_str("request_timeout")
                        .expect("the literal is valid error code syntax"),
                    "the upload stalled",
                    RetryClass::Backoff,
                );
                ApiError::new(&public, correlation_id).with_status(StatusCode::REQUEST_TIMEOUT)
            })?;
        let Some(chunk) = next else { break };
        let chunk = chunk.map_err(|_| {
            crate::machines::invalid_request("the upload body could not be read", correlation_id)
        })?;
        writer.write(&chunk).await.map_err(|error| match error {
            BlobError::TooLarge { max_bytes } => too_large(max_bytes, correlation_id),
            BlobError::Busy { detail } => {
                map_lab_error(&LabUseCaseError::Busy { detail }, correlation_id)
            }
            other => map_lab_error(
                &LabUseCaseError::Backend {
                    context: "uploads",
                    detail: other.to_string(),
                },
                correlation_id,
            ),
        })?;
    }
    writer.finish().await.map_err(|error| {
        map_lab_error(
            &LabUseCaseError::Backend {
                context: "uploads",
                detail: error.to_string(),
            },
            correlation_id,
        )
    })
}

/// What the hand-off needs once the body is staged.
struct QueuedPut {
    lease_id: String,
    guest_path: String,
    overwrite: bool,
    declared: Option<String>,
    idempotency_key: Option<String>,
    staged: StagedUpload,
}

/// Checks the declared digest, validates and audits the request, and queues
/// the `lab.put` operation. The staged file is discarded on every refusal.
async fn queue_put(
    state: Arc<crate::operations::ApiState>,
    puts: Arc<LabPuts>,
    principal: crate::ActingPrincipal,
    put: QueuedPut,
    correlation_id: CorrelationId,
) -> Result<fleet_application::operation::Operation, ApiErrorResponse> {
    let QueuedPut {
        lease_id,
        guest_path,
        overwrite,
        declared,
        idempotency_key,
        staged,
    } = put;
    let target = PutTarget {
        lease_id: &lease_id,
        guest_path: &guest_path,
        overwrite,
    };
    if declared.as_deref().is_some_and(|sha| sha != staged.sha256) {
        puts.discard(&staged.id).await;
        return Err(crate::machines::invalid_request(
            "the SHA-256 of the received file does not match X-Content-SHA256",
            correlation_id,
        ));
    }
    let mut new = puts
        .request_put(
            state.authorizer.as_ref(),
            &principal,
            &target,
            &staged,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    new.correlation_id = Some(correlation_id.to_string());
    // A caller-scoped idempotency key makes a retry return the operation it
    // already queued instead of copying again.
    // The key is bound to the target and the file's digest, so reusing it
    // for a different file queues a different operation.
    new.idempotency_key = idempotency_key.map(|key| {
        let binding =
            sha256_hex(format!("{guest_path}\0{overwrite}\0{}", staged.sha256).as_bytes());
        format!("{}:lab-put:{lease_id}:{binding}:{key}", principal.id)
    });
    let operation = match state
        .operations
        .create_lab_put(state.authorizer.as_ref(), &principal.id, &lease_id, &new)
        .await
    {
        Ok(operation) => operation,
        Err(error) => {
            puts.discard(&staged.id).await;
            return Err(crate::operations::map_use_case_error(
                &error,
                correlation_id,
            ));
        }
    };
    // A replayed key returns the earlier operation, which owns its own
    // staging file; this upload's copy is redundant.
    let owns_upload = operation
        .payload_json
        .as_deref()
        .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
        .is_some_and(|payload| payload["uploadId"].as_str() == Some(staged.id.as_str()));
    if !owns_upload {
        puts.discard(&staged.id).await;
    }
    Ok(operation)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// Copies one file into a ready lease as a `lab.put` operation. The body is
/// the file's bytes (`application/octet-stream`). The operation's result
/// records the guest path, size, and SHA-256; the controller verifies the
/// SHA-256 inside the guest and moves the file into place only after it
/// matches, so a failed put leaves nothing at the path.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown lease, a lease
/// that is not ready, an invalid path, or an upload over the cap.
#[utoipa::path(
    post,
    path = "/lab/leases/{leaseId}/files",
    tag = "lab",
    operation_id = "putLabFile",
    params(
        ("leaseId" = String, Path, description = "The lease's identity."),
        ("path" = String, Query, description = "The absolute guest path of the file to create."),
        ("overwrite" = Option<bool>, Query, description = "Replace an existing regular file at the path (default false)."),
        ("X-Content-SHA256" = Option<String>, Header, description = "The file's lowercase hex SHA-256; the upload is refused when what arrives hashes differently."),
        ("Idempotency-Key" = Option<String>, Header, description = "A caller-chosen key: a retry with the same key, while the lease can still take the file, returns the operation already queued."),
    ),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The file's raw bytes."),
    responses(
        (status = 202, description = "The copy is queued as a `lab.put` operation; its result records the guest path, size, and SHA-256.", body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The lease is not ready or has expired, its guest has no Lab machine, the path is invalid, or the declared SHA-256 does not match the body.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not put files into this lease.", body = crate::error::ApiError),
        (status = 404, description = "The lease does not exist.", body = crate::error::ApiError),
        (status = 408, description = "The upload body stalled for a minute.", body = crate::error::ApiError),
        (status = 413, description = "The file exceeds the controller's upload cap.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "The controller has no upload staging area, or too many uploads are in flight (code `busy`).", body = crate::error::ApiError),
    )
)]
pub async fn put_lab_file(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: HeaderMap,
    Path(lease_id): Path<String>,
    Query(params): Query<PutLabFileParams>,
    body: Body,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let puts = puts_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let declared = match headers.get(CONTENT_SHA256_HEADER) {
        None => None,
        Some(value) => Some(
            value
                .to_str()
                .ok()
                .filter(|value| is_sha256_hex(value))
                .ok_or_else(|| {
                    crate::machines::invalid_request(
                        "X-Content-SHA256 must be a lowercase hex SHA-256",
                        correlation_id,
                    )
                })?
                .to_owned(),
        ),
    };
    let target = PutTarget {
        lease_id: &lease_id,
        guest_path: &params.path,
        overwrite: params.overwrite,
    };
    // Authorization, the path, and the lease are checked before any byte is
    // read.
    let writer = puts
        .begin_upload(
            state.authorizer.as_ref(),
            &principal,
            &target,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    let max_bytes = puts.max_bytes();
    let announced = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if announced.is_some_and(|length| length > max_bytes) {
        return Err(too_large(max_bytes, correlation_id));
    }
    let staged = stream_upload(writer, body, correlation_id).await?;
    // From here the staging file is owned by a detached task, so a client
    // that disconnects cannot cancel the hand-off halfway and orphan it.
    let idempotency_key = headers
        .get(crate::IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let staged_id = staged.id.clone();
    let queued = tokio::spawn(queue_put(
        state,
        puts.clone(),
        principal,
        QueuedPut {
            lease_id,
            guest_path: params.path,
            overwrite: params.overwrite,
            declared,
            idempotency_key,
            staged,
        },
        correlation_id,
    ))
    .await;
    let Ok(result) = queued else {
        puts.discard(&staged_id).await;
        return Err(map_lab_error(
            &LabUseCaseError::Backend {
                context: "uploads",
                detail: "the queueing task failed".to_owned(),
            },
            correlation_id,
        ));
    };
    let operation = result?;
    Ok((StatusCode::ACCEPTED, Json(Resource::new(operation.into()))))
}
