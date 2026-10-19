//! The controller side of `lab put` (#393): the upload staging store and the
//! `lab.put` executor.
//!
//! [`FsUploadStore`] keeps in-flight uploads under `<lab_artifacts_dir>/uploads`
//! (owner-only). An upload is written chunk by chunk, hashed as it goes, and
//! refused the moment it passes the cap, so the body is never buffered whole.
//! A staging file is removed when its writer is dropped unfinished, by the
//! executor when the operation ends (success or failure), when the store is
//! opened (what a previous run left behind), and when it has outlived any
//! plausible operation.
//!
//! [`LabPutDispatch`] wraps the Lab executor and runs `lab.put`: it
//! re-checks that the lease is ready, streams the staged file over the lease
//! machine's verified SSH endpoint, and records the outcome. The guest
//! verifies the SHA-256 and renames the file into place; a failed put leaves
//! nothing at the target. File content appears in no log, audit event,
//! payload, or result.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;

use fleet_application::lab::{LeasePort, ProvisionPort};
use fleet_application::lab_artifacts::{BlobError, is_sha256_hex, validate_guest_path_for};
use fleet_application::lab_put::{StagedUpload, UploadStagePort, UploadWriter};
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_provider_ssh::PutOutcome;

use crate::lab_artifacts_store::{GuestFiles, GuestPut, payload_lease, resolve_lab_machine};

/// The upload directory under the artifact store root.
const UPLOAD_DIR: &str = "uploads";
/// How long a staging file may sit before a new upload reclaims it. A put
/// that never ran (cancelled, timed out in the queue) leaves its file until
/// then; one still running keeps its open handle, and one queued longer than
/// this fails `upload_unavailable`.
const STALE_AFTER: Duration = Duration::from_hours(2);
/// The base time a put may take, before the size allowance.
const PUT_DEADLINE_BASE: Duration = Duration::from_mins(5);
/// The slowest transfer a put is expected to survive, in bytes per second.
const PUT_MIN_BYTES_PER_SECOND: u64 = 1024 * 1024;
/// The longest any put may run.
const PUT_DEADLINE_MAX: Duration = Duration::from_hours(6);

/// The deadline of a put of `size` bytes: a base plus one second per MiB.
#[must_use]
pub fn put_deadline(size: u64) -> Duration {
    (PUT_DEADLINE_BASE + Duration::from_secs(size / PUT_MIN_BYTES_PER_SECOND)).min(PUT_DEADLINE_MAX)
}

/// How many uploads may be written at once.
pub const MAX_CONCURRENT_UPLOADS: usize = 4;

/// The upload staging area over one directory. At most
/// [`MAX_CONCURRENT_UPLOADS`] uploads are written at once, and everything
/// staged (written or queued) together may not exceed
/// `MAX_CONCURRENT_UPLOADS` times the per-file cap, so a few callers cannot
/// fill the controller's disk.
#[derive(Clone, Debug)]
pub struct FsUploadStore {
    dir: PathBuf,
    max_bytes: u64,
    writers: Arc<tokio::sync::Semaphore>,
    staged: Arc<std::sync::atomic::AtomicU64>,
}

impl FsUploadStore {
    /// Opens (creating) the staging directory under `root`, owner-only, and
    /// removes staging files a previous run left behind.
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be prepared.
    pub fn open(root: &Path, max_bytes: u64) -> std::io::Result<Self> {
        let dir = root.join(UPLOAD_DIR);
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let dir = dir.canonicalize()?;
        let store = Self {
            dir,
            max_bytes,
            writers: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_UPLOADS)),
            staged: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        store.reclaim(Duration::ZERO);
        Ok(store)
    }

    /// The staging directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Removes staging files older than `age`, best effort.
    fn reclaim(&self, age: Duration) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let old_enough = age.is_zero()
                || entry
                    .metadata()
                    .and_then(|meta| meta.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|elapsed| elapsed >= age);
            if !old_enough {
                continue;
            }
            let len = entry.metadata().map_or(0, |meta| meta.len());
            match std::fs::remove_file(entry.path()) {
                Ok(()) => self.release(len),
                Err(error) => eprintln!("lab put: cannot remove a stale staging file: {error}"),
            }
        }
    }

    fn release(&self, bytes: u64) {
        let _ = self.staged.fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |current| Some(current.saturating_sub(bytes)),
        );
    }

    fn budget(&self) -> u64 {
        self.max_bytes.saturating_mul(MAX_CONCURRENT_UPLOADS as u64)
    }

    fn path_for(&self, id: &str) -> Result<PathBuf, BlobError> {
        if uuid::Uuid::parse_str(id).map(|parsed| parsed.hyphenated().to_string())
            != Ok(id.to_owned())
        {
            return Err(BlobError::InvalidLocation);
        }
        Ok(self.dir.join(id))
    }

    /// Opens a staged upload for reading, after checking it is a regular
    /// file of the recorded size.
    ///
    /// # Errors
    ///
    /// Fails on an invalid id, a missing file, or a size mismatch.
    pub fn open_staged(&self, id: &str, size: u64) -> Result<std::fs::File, BlobError> {
        let path = self.path_for(id)?;
        let file = std::fs::File::open(&path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => BlobError::Missing,
            _ => BlobError::Io(format!("cannot open a staged upload: {error}")),
        })?;
        let meta = file
            .metadata()
            .map_err(|error| BlobError::Io(format!("cannot stat a staged upload: {error}")))?;
        if !meta.is_file() || meta.len() != size {
            return Err(BlobError::Corrupt {
                detail: "the staged upload does not match its recorded size".to_owned(),
            });
        }
        Ok(file)
    }

    /// Removes a staged upload; an absent one is already removed.
    pub fn remove(&self, id: &str) {
        if let Ok(path) = self.path_for(id) {
            let len = std::fs::metadata(&path).map_or(0, |meta| meta.len());
            match std::fs::remove_file(path) {
                Ok(()) => self.release(len),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => eprintln!("lab put: cannot remove a staged upload: {error}"),
            }
        }
    }
}

#[async_trait]
impl UploadStagePort for FsUploadStore {
    fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    async fn begin(&self) -> Result<Box<dyn UploadWriter>, BlobError> {
        self.reclaim(STALE_AFTER);
        let permit = self
            .writers
            .clone()
            .try_acquire_owned()
            .map_err(|_| BlobError::Busy {
                detail: format!("{MAX_CONCURRENT_UPLOADS} uploads are already in flight"),
            })?;
        let id = uuid::Uuid::now_v7().to_string();
        let path = self.dir.join(&id);
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(&path)
            .await
            .map_err(|error| BlobError::Io(format!("cannot stage an upload: {error}")))?;
        Ok(Box::new(FsUploadWriter {
            file: Some(file),
            path,
            id,
            hasher: Sha256::new(),
            size: 0,
            max_bytes: self.max_bytes,
            keep: false,
            budget: self.budget(),
            staged: self.staged.clone(),
            _permit: permit,
        }))
    }

    async fn discard(&self, id: &str) {
        self.remove(id);
    }
}

/// One upload being written; removes its file when dropped unfinished.
#[derive(Debug)]
struct FsUploadWriter {
    file: Option<tokio::fs::File>,
    path: PathBuf,
    id: String,
    hasher: Sha256,
    size: u64,
    max_bytes: u64,
    keep: bool,
    budget: u64,
    staged: Arc<std::sync::atomic::AtomicU64>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

#[async_trait]
impl UploadWriter for FsUploadWriter {
    async fn write(&mut self, chunk: &[u8]) -> Result<(), BlobError> {
        if self.size.saturating_add(chunk.len() as u64) > self.max_bytes {
            // Dropping the writer removes the partial file.
            return Err(BlobError::TooLarge {
                max_bytes: self.max_bytes,
            });
        }
        let reserved = self
            .staged
            .fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::SeqCst)
            + chunk.len() as u64;
        self.size += chunk.len() as u64;
        if reserved > self.budget {
            return Err(BlobError::Busy {
                detail: "the staging area is full".to_owned(),
            });
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| BlobError::Io("the upload is finished".to_owned()))?;
        file.write_all(chunk)
            .await
            .map_err(|error| BlobError::Io(format!("cannot stage an upload: {error}")))?;
        self.hasher.update(chunk);
        Ok(())
    }

    async fn finish(mut self: Box<Self>) -> Result<StagedUpload, BlobError> {
        let mut file = self
            .file
            .take()
            .ok_or_else(|| BlobError::Io("the upload is finished".to_owned()))?;
        file.flush()
            .await
            .map_err(|error| BlobError::Io(format!("cannot flush an upload: {error}")))?;
        file.sync_all()
            .await
            .map_err(|error| BlobError::Io(format!("cannot flush an upload: {error}")))?;
        drop(file);
        self.keep = true;
        Ok(StagedUpload {
            id: self.id.clone(),
            size_bytes: self.size,
            sha256: hex(&self.hasher.clone().finalize()),
        })
    }
}

impl Drop for FsUploadWriter {
    fn drop(&mut self) {
        if !self.keep {
            drop(self.file.take());
            let _ = std::fs::remove_file(&self.path);
            let size = self.size;
            let _ = self.staged.fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |current| Some(current.saturating_sub(size)),
            );
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// Removes the staged upload when the executor is done with it, whatever
/// path it took out.
struct StagedGuard<'a> {
    store: &'a FsUploadStore,
    id: String,
}

impl Drop for StagedGuard<'_> {
    fn drop(&mut self) {
        self.store.remove(&self.id);
    }
}

/// What a `lab.put` operation's payload carries.
struct PutPayload {
    guest_os: fleet_core::GuestOs,
    guest_path: String,
    upload_id: String,
    size: u64,
    sha256: String,
    overwrite: bool,
}

fn parse_payload(operation: &Operation) -> Result<PutPayload, String> {
    let value: serde_json::Value = operation
        .payload_json
        .as_deref()
        .and_then(|payload| serde_json::from_str(payload).ok())
        .ok_or("the payload is not valid JSON")?;
    let guest_path = value["guestPath"]
        .as_str()
        .ok_or("no guest path")?
        .to_owned();
    let guest_os = match value.get("guestOs") {
        None | Some(serde_json::Value::Null) => fleet_core::GuestOs::Linux,
        Some(serde_json::Value::String(id)) => fleet_core::GuestOs::from_id(id)?,
        Some(_) => return Err("the payload's guestOs is not a string".to_owned()),
    };
    validate_guest_path_for(guest_os, &guest_path)?;
    let sha256 = value["sha256"].as_str().ok_or("no sha256")?.to_owned();
    if !is_sha256_hex(&sha256) {
        return Err("the sha256 is not a lowercase hex digest".to_owned());
    }
    Ok(PutPayload {
        guest_os,
        guest_path,
        upload_id: value["uploadId"].as_str().ok_or("no upload id")?.to_owned(),
        size: value["sizeBytes"].as_u64().ok_or("no size")?,
        sha256,
        overwrite: value["overwrite"].as_bool().unwrap_or(false),
    })
}

/// Wraps the Lab executor with `lab.put` (see the module docs).
#[derive(Debug)]
pub struct LabPutDispatch {
    inner: Arc<dyn OperationExecutor>,
    store: Arc<FsUploadStore>,
    leases: Arc<dyn LeasePort>,
    provisions: Arc<dyn ProvisionPort>,
    templates: Arc<dyn fleet_application::lab::LabTemplatePort>,
    files: Arc<dyn GuestFiles>,
}

impl LabPutDispatch {
    /// Composes the wrapper.
    #[must_use]
    pub fn new(
        inner: Arc<dyn OperationExecutor>,
        store: Arc<FsUploadStore>,
        leases: Arc<dyn LeasePort>,
        provisions: Arc<dyn ProvisionPort>,
        templates: Arc<dyn fleet_application::lab::LabTemplatePort>,
        files: Arc<dyn GuestFiles>,
    ) -> Self {
        Self {
            inner,
            store,
            leases,
            provisions,
            templates,
            files,
        }
    }

    async fn put(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let lease_id = payload_lease(operation);
        let payload = match parse_payload(operation) {
            Ok(payload) => payload,
            Err(detail) => {
                // Without a parsed payload the staging id is unknown; the
                // sweep reclaims the file.
                return self
                    .finish_failed(
                        operations,
                        operation,
                        &lease_id,
                        "",
                        "invalid_payload",
                        &detail,
                    )
                    .await;
            }
        };
        // The staged file goes whichever way this returns.
        let _staged = StagedGuard {
            store: &self.store,
            id: payload.upload_id.clone(),
        };
        let guest_path = payload.guest_path.clone();
        let fail = |reason: &'static str, detail: String| {
            let (lease_id, guest_path) = (lease_id.clone(), guest_path.clone());
            async move {
                self.finish_failed(
                    operations,
                    operation,
                    &lease_id,
                    &guest_path,
                    reason,
                    &detail,
                )
                .await
            }
        };
        let (machine_id, endpoint_id) = match resolve_lab_machine(
            self.leases.as_ref(),
            self.provisions.as_ref(),
            self.templates.as_ref(),
            payload.guest_os,
            &lease_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        {
            Ok(found) => found,
            Err((reason, detail)) => return fail(reason, detail).await,
        };
        let source = match self.store.open_staged(&payload.upload_id, payload.size) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("lab put: lease {lease_id}: the staged upload is unusable: {error}");
                return fail(
                    "upload_unavailable",
                    "the staged upload is missing or changed; upload the file again".to_owned(),
                )
                .await;
            }
        };
        if let Err(error) = operations
            .record_progress(&operation.id, Some(0), Some(1), Some("sending the file"))
            .await
        {
            eprintln!(
                "lab put: progress of operation {} not recorded: {error}",
                operation.id
            );
        }
        let outcome = self
            .files
            .put(
                &machine_id,
                &endpoint_id,
                GuestPut {
                    guest_os: payload.guest_os,
                    path: payload.guest_path.clone(),
                    size: payload.size,
                    sha256: payload.sha256.clone(),
                    overwrite: payload.overwrite,
                },
                put_deadline(payload.size),
                source,
            )
            .await;
        let (reason, detail): (&'static str, &'static str) = match outcome {
            Ok(PutOutcome::Put { .. }) => {
                let result = serde_json::json!({
                    "leaseId": lease_id,
                    "guestPath": payload.guest_path,
                    "sizeBytes": payload.size,
                    "sha256": payload.sha256,
                    "overwrite": payload.overwrite,
                });
                return operations
                    .complete(&operation.id, "succeeded", Some(&result.to_string()), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string());
            }
            Ok(PutOutcome::TargetExists) => (
                "target_exists",
                "a file already exists at the guest path; set overwrite to replace it",
            ),
            Ok(PutOutcome::TargetNotFile) => (
                "target_not_file",
                "the guest path exists and is not a regular file; it is never replaced",
            ),
            Ok(PutOutcome::TargetReadOnly) => (
                "target_read_only",
                "the guest path is a read-only file; it is never replaced",
            ),
            Ok(PutOutcome::PathRejected) => (
                "path_rejected",
                "the guest refused the path (for example it is longer than the platform allows)",
            ),
            Ok(PutOutcome::NoDirectory) => {
                ("no_directory", "the guest path's directory does not exist")
            }
            Ok(PutOutcome::DirectoryNotWritable) => (
                "directory_not_writable",
                "the guest user cannot create files in the guest path's directory",
            ),
            Ok(PutOutcome::HashMismatch) => (
                "hash_mismatch",
                "the SHA-256 computed inside the guest did not match; nothing was left at the guest path",
            ),
            Ok(PutOutcome::SizeMismatch) => (
                "size_mismatch",
                "the byte count that reached the guest did not match; nothing was left at the guest path",
            ),
            Ok(PutOutcome::DeadlineKilled) => (
                "deadline_exceeded",
                "the transfer did not finish before its deadline; nothing was left at the guest path",
            ),
            Ok(PutOutcome::SourceFailed { detail }) => {
                eprintln!("lab put: lease {lease_id}: reading the staged upload failed: {detail}");
                (
                    "upload_unavailable",
                    "the staged upload could not be read; upload the file again",
                )
            }
            Ok(PutOutcome::Failed { exit_code }) => {
                eprintln!("lab put: lease {lease_id}: the guest copy failed (exit {exit_code:?})");
                (
                    "copy_failed",
                    "the copy failed inside the guest; nothing was left at the guest path",
                )
            }
            Err(error) => {
                // The transport's error can carry node or tool text.
                let error = fleet_core::scrub_failure_detail(&error);
                eprintln!("lab put: lease {lease_id}: the transfer failed: {error}");
                (
                    "transfer_failed",
                    "the transfer to the guest failed; the detail is in the controller log",
                )
            }
        };
        fail(reason, detail.to_owned()).await
    }

    async fn finish_failed(
        &self,
        operations: &Operations,
        operation: &Operation,
        lease_id: &str,
        guest_path: &str,
        reason: &str,
        detail: &str,
    ) -> Result<(), String> {
        let error = serde_json::json!({
            "reason": reason,
            "detail": fleet_core::scrub_failure_detail(detail),
            "leaseId": lease_id,
            "guestPath": guest_path,
        })
        .to_string();
        operations
            .complete(&operation.id, "failed", None, Some(&error))
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

#[async_trait]
impl OperationExecutor for LabPutDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "lab.put" => self.put(operations, operation).await,
            _ => self.inner.execute(operations, operation).await,
        }
    }
}
