//! Copying one file into a ready Lab lease (#393).
//!
//! The bytes never pass through a job payload, log, audit event, or
//! operation result. A caller streams the file to the controller, which
//! writes it to a controller-owned staging file through [`UploadStagePort`]
//! (hashing as it goes and refusing bytes past the configured cap); the
//! queued `lab.put` operation carries only the lease, the guest path, the
//! staging id, and the file's size and SHA-256. The executor verifies the
//! digest again inside the guest, and the staging file is removed when the
//! operation finishes.
//!
//! Authorization (`lab.put`, scoped to the lease) and the lease checks run
//! before any byte is accepted, and again when the operation is queued.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::lab::{LabUseCaseError, LeasePort, ProvisionPort};
use crate::lab_artifacts::{BlobError, is_sha256_hex, require_guest_machine, validate_guest_path};
use crate::operation::{AuditPort, NewOperation};

/// The default cap on one uploaded file: 2 GiB, enough for packaged desktop
/// installers.
pub const DEFAULT_LAB_PUT_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// A completed upload in controller staging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedUpload {
    /// The staging handle; it means nothing outside the staging store.
    pub id: String,
    /// The size in bytes.
    pub size_bytes: u64,
    /// The lowercase hex SHA-256.
    pub sha256: String,
}

/// An upload being written. Dropping it unfinished removes the partial file.
#[async_trait]
pub trait UploadWriter: Send {
    /// Appends a chunk.
    ///
    /// # Errors
    ///
    /// Fails with [`BlobError::Busy`] when the staging area is full, and
    /// with [`BlobError::TooLarge`] once the total passes the cap (the
    /// partial file is removed), or on a filesystem failure.
    async fn write(&mut self, chunk: &[u8]) -> Result<(), BlobError>;

    /// Finishes the upload, answering its size and digest.
    ///
    /// # Errors
    ///
    /// Fails when the bytes cannot be flushed; the file is removed then.
    async fn finish(self: Box<Self>) -> Result<StagedUpload, BlobError>;
}

/// The controller's upload staging area.
#[async_trait]
pub trait UploadStagePort: fmt::Debug + Send + Sync {
    /// The cap on one upload, in bytes.
    fn max_bytes(&self) -> u64;

    /// Starts an upload.
    ///
    /// # Errors
    ///
    /// Fails when the staging file cannot be created.
    async fn begin(&self) -> Result<Box<dyn UploadWriter>, BlobError>;

    /// Removes a staged upload; an absent one is already removed. Never
    /// fails: a leftover file is reclaimed when the controller starts.
    async fn discard(&self, id: &str);
}

/// What a caller asks to put.
#[derive(Clone, Copy, Debug)]
pub struct PutTarget<'a> {
    /// The lease.
    pub lease_id: &'a str,
    /// The absolute guest path of the file to create.
    pub guest_path: &'a str,
    /// Whether an existing regular file at that path may be replaced.
    pub overwrite: bool,
}

/// The Lab put use cases.
#[derive(Debug)]
pub struct LabPuts {
    stage: Arc<dyn UploadStagePort>,
    leases: Arc<dyn LeasePort>,
    provisions: Arc<dyn ProvisionPort>,
    audit: Arc<dyn AuditPort>,
}

impl LabPuts {
    /// Composes the use cases.
    #[must_use]
    pub fn new(
        stage: Arc<dyn UploadStagePort>,
        leases: Arc<dyn LeasePort>,
        provisions: Arc<dyn ProvisionPort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            stage,
            leases,
            provisions,
            audit,
        }
    }

    /// The cap on one upload, in bytes.
    #[must_use]
    pub fn max_bytes(&self) -> u64 {
        self.stage.max_bytes()
    }

    /// Checks the caller, the path, and the lease, then opens a staging
    /// file. Nothing is accepted from an unauthorized caller or for a lease
    /// that cannot take the file.
    ///
    /// # Errors
    ///
    /// Fails on denial, an invalid path, an unknown lease, a lease that is
    /// not ready, or a staging failure.
    pub async fn begin_upload(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        target: &PutTarget<'_>,
        now: i64,
    ) -> Result<Box<dyn UploadWriter>, LabUseCaseError> {
        self.check(authorizer, principal, target, now).await?;
        self.stage.begin().await.map_err(|error| match error {
            BlobError::TooLarge { .. } => LabUseCaseError::Invalid {
                detail: error.to_string(),
            },
            BlobError::Busy { detail } => LabUseCaseError::Busy { detail },
            other => backend(other.to_string()),
        })
    }

    /// Validates a finished upload and answers the `lab.put` operation to
    /// queue, after recording the audit intent. The staged file is
    /// discarded when this refuses.
    ///
    /// # Errors
    ///
    /// Fails on denial, an invalid path or digest, an upload over the cap,
    /// a lease that is no longer ready, or a backend failure.
    pub async fn request_put(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        target: &PutTarget<'_>,
        staged: &StagedUpload,
        now: i64,
    ) -> Result<NewOperation, LabUseCaseError> {
        let queued = self
            .request_inner(authorizer, principal, target, staged, now)
            .await;
        if queued.is_err() {
            self.stage.discard(&staged.id).await;
        }
        queued
    }

    /// Discards a staged upload that will not be queued.
    pub async fn discard(&self, id: &str) {
        self.stage.discard(id).await;
    }

    async fn request_inner(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        target: &PutTarget<'_>,
        staged: &StagedUpload,
        now: i64,
    ) -> Result<NewOperation, LabUseCaseError> {
        self.check(authorizer, principal, target, now).await?;
        if !is_sha256_hex(&staged.sha256) {
            return Err(LabUseCaseError::Invalid {
                detail: "the upload's SHA-256 is not a lowercase hex digest".to_owned(),
            });
        }
        if staged.size_bytes > self.stage.max_bytes() {
            return Err(LabUseCaseError::Invalid {
                detail: BlobError::TooLarge {
                    max_bytes: self.stage.max_bytes(),
                }
                .to_string(),
            });
        }
        // The audit intent precedes the mutation. It records what was sent
        // (size, digest, target), never the bytes.
        let mut metadata = crate::audit::AuditMetadata::default();
        let audit_error = |error: crate::audit::MetadataError| LabUseCaseError::Backend {
            context: "audit",
            detail: error.to_string(),
        };
        for (key, value) in [
            ("event", "lab_put_requested".to_owned()),
            ("guestPath", target.guest_path.to_owned()),
            ("sizeBytes", staged.size_bytes.to_string()),
            ("sha256", staged.sha256.clone()),
            ("overwrite", target.overwrite.to_string()),
        ] {
            metadata.insert(key, &value).map_err(audit_error)?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: Permission::LabPut.id().to_owned(),
                resource: Some(target.lease_id.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "audit",
                detail,
            })?;
        Ok(NewOperation {
            kind: "lab.put".to_owned(),
            idempotency_key: None,
            deadline_at: None,
            correlation_id: None,
            payload_json: Some(
                serde_json::json!({
                    "leaseId": target.lease_id,
                    "guestPath": target.guest_path,
                    "uploadId": staged.id,
                    "sizeBytes": staged.size_bytes,
                    "sha256": staged.sha256,
                    "overwrite": target.overwrite,
                })
                .to_string(),
            ),
            review_token: None,
        })
    }

    async fn check(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        target: &PutTarget<'_>,
        now: i64,
    ) -> Result<(), LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabPut,
                resource: Some(target.lease_id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        validate_guest_path(target.guest_path).map_err(|detail| LabUseCaseError::Invalid {
            detail: format!("guest path: {detail}"),
        })?;
        require_guest_machine(
            self.leases.as_ref(),
            self.provisions.as_ref(),
            principal,
            target.lease_id,
            now,
            "put into",
        )
        .await
        .map(|_| ())
    }
}

fn backend(detail: String) -> LabUseCaseError {
    LabUseCaseError::Backend {
        context: "uploads",
        detail,
    }
}
