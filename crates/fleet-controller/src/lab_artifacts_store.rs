//! Lab artifact bytes and the executor side of Lab artifacts (FM-721).
//!
//! [`FsArtifactStore`] keeps artifact bytes in the configured
//! `lab_artifacts_dir`, content-addressed: a blob lives at
//! `sha256/<first two hex digits>/<64 hex digits>`, and that relative
//! location is all SQLite records. Writes land in `tmp/` first and are
//! renamed into place, so a reader never sees half a blob. Every location
//! is checked twice before it is touched: it must have exactly the
//! content-addressed shape, and its canonical path must stay inside the
//! store's canonical root (a symlink planted in the store cannot lead out
//! of it). A download re-hashes the blob and refuses bytes that no longer
//! match their recorded size and digest.
//!
//! [`LabArtifactDispatch`] wraps the Lab executor: after every `lab.exec`
//! it keeps the command's bounded, redacted output as an `exec-log`
//! artifact, and it runs `lab.collect`, copying declared guest files over
//! the lease machine's verified SSH endpoint. Collection never changes the
//! lease: a failure is recorded beside it and cleanup proceeds regardless.

use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};

use fleet_application::authz::ActingPrincipal;
use fleet_application::lab::{LeasePort, ProvisionPort, lease_exec_ready};
use fleet_application::lab_artifacts::{
    ArtifactBlobPort, ArtifactReader, BlobError, LabArtifacts, StagedBlob, StoredBlob,
    exec_log_text, is_sha256_hex, validate_collect_paths,
};
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_provider_ssh::FetchOutcome;

/// The staging directory under the store root.
const STAGING_DIR: &str = "tmp";
/// The blob directory under the store root.
const BLOB_DIR: &str = "sha256";

/// The content-addressed artifact byte store over one directory.
#[derive(Clone, Debug)]
pub struct FsArtifactStore {
    root: PathBuf,
    max_bytes: u64,
}

impl FsArtifactStore {
    /// Opens (creating) the store under `root`, owner-only, and removes
    /// staging files a previous run left behind.
    ///
    /// # Errors
    ///
    /// Fails when the directories cannot be prepared.
    pub fn open(root: &Path, max_bytes: u64) -> std::io::Result<Self> {
        for dir in [
            root.to_path_buf(),
            root.join(STAGING_DIR),
            root.join(BLOB_DIR),
        ] {
            std::fs::create_dir_all(&dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        let root = root.canonicalize()?;
        // Stale staging files are reclaimed best-effort: one unreadable
        // entry must not take the whole artifact store down.
        for leftover in std::fs::read_dir(root.join(STAGING_DIR))? {
            match leftover {
                Ok(entry) => {
                    if let Err(error) = std::fs::remove_file(entry.path()) {
                        eprintln!(
                            "lab artifacts: cannot remove stale staging file {}: {error}",
                            entry.path().display()
                        );
                    }
                }
                Err(error) => eprintln!("lab artifacts: cannot read a staging entry: {error}"),
            }
        }
        Ok(Self { root, max_bytes })
    }

    /// The canonical store root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The per-artifact size cap.
    #[must_use]
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// The store-relative location of a blob with this digest.
    #[must_use]
    pub fn location_for(sha256: &str) -> String {
        format!("{BLOB_DIR}/{}/{sha256}", &sha256[..2])
    }

    /// Starts a staging file. Writes past the cap fail; the file is removed
    /// when the handle drops unless it was finished.
    ///
    /// # Errors
    ///
    /// Fails when the staging file cannot be created.
    pub fn stage(&self) -> std::io::Result<StagingFile> {
        let token = uuid::Uuid::now_v7().to_string();
        let path = self.root.join(STAGING_DIR).join(&token);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(StagingFile {
            file: Some(file),
            path,
            token,
            hasher: Sha256::new(),
            size: 0,
            max_bytes: self.max_bytes,
            overflowed: false,
            keep: false,
        })
    }

    /// Finishes a staging file: flushes it and answers its size and digest.
    ///
    /// # Errors
    ///
    /// Fails when the bytes exceeded the cap or could not be flushed; the
    /// staging file is removed then.
    pub fn finish(&self, mut staging: StagingFile) -> Result<StagedBlob, BlobError> {
        if staging.overflowed {
            return Err(BlobError::TooLarge {
                max_bytes: self.max_bytes,
            });
        }
        let file = staging.file.take().ok_or(BlobError::Missing)?;
        file.sync_all()
            .map_err(|error| BlobError::Io(format!("cannot flush a staged artifact: {error}")))?;
        drop(file);
        staging.keep = true;
        Ok(StagedBlob {
            token: staging.token.clone(),
            size_bytes: staging.size,
            sha256: hex(&staging.hasher.clone().finalize()),
        })
    }

    /// Resolves a store-relative location to its path, refusing anything
    /// that is not exactly a content-addressed blob location inside the
    /// root.
    ///
    /// # Errors
    ///
    /// Fails with [`BlobError::InvalidLocation`] on any other location.
    pub fn resolve(&self, location: &str) -> Result<PathBuf, BlobError> {
        let mut parts = location.split('/');
        let (Some(BLOB_DIR), Some(prefix), Some(digest), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(BlobError::InvalidLocation);
        };
        if !is_sha256_hex(digest) || prefix != &digest[..2] {
            return Err(BlobError::InvalidLocation);
        }
        let relative = Path::new(location);
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(BlobError::InvalidLocation);
        }
        let path = self.root.join(relative);
        // The deepest existing ancestor (the path itself, its prefix
        // directory, or `sha256/`) must canonicalize inside the root, so a
        // symlink planted anywhere in the store cannot lead out of it. A
        // dangling symlink exists for this check and fails to canonicalize.
        let existing = path
            .ancestors()
            .find(|ancestor| std::fs::symlink_metadata(ancestor).is_ok())
            .ok_or(BlobError::InvalidLocation)?;
        let canonical = existing
            .canonicalize()
            .map_err(|_| BlobError::InvalidLocation)?;
        if !canonical.starts_with(&self.root) {
            return Err(BlobError::InvalidLocation);
        }
        Ok(path)
    }

    fn staged_path(&self, token: &str) -> Result<PathBuf, BlobError> {
        if uuid::Uuid::parse_str(token).map(|id| id.hyphenated().to_string())
            != Ok(token.to_owned())
        {
            return Err(BlobError::InvalidLocation);
        }
        Ok(self.root.join(STAGING_DIR).join(token))
    }

    fn commit_blocking(&self, staged: &StagedBlob) -> Result<StoredBlob, BlobError> {
        if !is_sha256_hex(&staged.sha256) {
            return Err(BlobError::InvalidLocation);
        }
        if staged.size_bytes > self.max_bytes {
            return Err(BlobError::TooLarge {
                max_bytes: self.max_bytes,
            });
        }
        let source = self.staged_path(&staged.token)?;
        // The staged bytes must still be what was hashed, or the metadata
        // would reference unusable bytes.
        if let Err(error) = verify_blob(&source, &staged.sha256, staged.size_bytes) {
            let _ = std::fs::remove_file(&source);
            return Err(match error {
                BlobError::Corrupt { detail } => BlobError::Corrupt {
                    detail: format!("the staged bytes changed before their commit: {detail}"),
                },
                other => other,
            });
        }
        let location = Self::location_for(&staged.sha256);
        let target = self.resolve(&location)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                BlobError::Io(format!("cannot create a blob directory: {error}"))
            })?;
        }
        // Identical content already stored, and still intact: the staged
        // copy is redundant. A damaged blob is replaced by the staged copy.
        if target.is_file() && verify_blob(&target, &staged.sha256, staged.size_bytes).is_ok() {
            let _ = std::fs::remove_file(&source);
        } else {
            std::fs::rename(&source, &target)
                .map_err(|error| BlobError::Io(format!("cannot commit a blob: {error}")))?;
        }
        // The blob directory must still resolve inside the root.
        self.resolve(&location)?;
        Ok(StoredBlob {
            location,
            size_bytes: staged.size_bytes,
            sha256: staged.sha256.clone(),
        })
    }

    fn put_blocking(&self, bytes: &[u8]) -> Result<StoredBlob, BlobError> {
        if bytes.len() as u64 > self.max_bytes {
            return Err(BlobError::TooLarge {
                max_bytes: self.max_bytes,
            });
        }
        let mut staging = self
            .stage()
            .map_err(|error| BlobError::Io(format!("cannot stage an artifact: {error}")))?;
        staging
            .write_all(bytes)
            .map_err(|error| BlobError::Io(format!("cannot stage an artifact: {error}")))?;
        let staged = self.finish(staging)?;
        self.commit_blocking(&staged).inspect_err(|_| {
            // A failed commit leaves no staging file behind.
            if let Ok(path) = self.staged_path(&staged.token) {
                let _ = std::fs::remove_file(path);
            }
        })
    }
}

/// Re-hashes a stored blob against its recorded size and digest, and
/// answers the same open handle rewound, so what is served is exactly what
/// was verified.
fn verify_blob(path: &Path, sha256: &str, size_bytes: u64) -> Result<std::fs::File, BlobError> {
    use std::io::Seek as _;
    let mut file = std::fs::File::open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => BlobError::Missing,
        _ => BlobError::Io(format!("cannot open a blob: {error}")),
    })?;
    let mut hasher = Sha256::new();
    let copied = std::io::copy(&mut file, &mut hasher)
        .map_err(|error| BlobError::Io(format!("cannot read a blob: {error}")))?;
    if copied != size_bytes {
        return Err(BlobError::Corrupt {
            detail: format!("{copied} bytes stored, {size_bytes} recorded"),
        });
    }
    if hex(&hasher.finalize()) != sha256 {
        return Err(BlobError::Corrupt {
            detail: "the stored bytes do not match the recorded sha256".to_owned(),
        });
    }
    file.rewind()
        .map_err(|error| BlobError::Io(format!("cannot rewind a blob: {error}")))?;
    Ok(file)
}

#[async_trait]
impl ArtifactBlobPort for FsArtifactStore {
    async fn put(&self, bytes: &[u8]) -> Result<StoredBlob, BlobError> {
        let store = self.clone();
        let bytes = bytes.to_vec();
        tokio::task::spawn_blocking(move || store.put_blocking(&bytes))
            .await
            .map_err(|error| BlobError::Io(format!("the store thread failed: {error}")))?
    }

    async fn commit(&self, staged: &StagedBlob) -> Result<StoredBlob, BlobError> {
        let store = self.clone();
        let staged = staged.clone();
        tokio::task::spawn_blocking(move || store.commit_blocking(&staged))
            .await
            .map_err(|error| BlobError::Io(format!("the store thread failed: {error}")))?
    }

    async fn discard(&self, staged: &StagedBlob) {
        if let Ok(path) = self.staged_path(&staged.token) {
            let _ = std::fs::remove_file(path);
        }
    }

    async fn open(
        &self,
        location: &str,
        sha256: &str,
        size_bytes: u64,
    ) -> Result<ArtifactReader, BlobError> {
        let path = self.resolve(location)?;
        let sha256 = sha256.to_owned();
        let file = tokio::task::spawn_blocking(move || verify_blob(&path, &sha256, size_bytes))
            .await
            .map_err(|error| BlobError::Io(format!("the verification thread failed: {error}")))??;
        // The location must still resolve inside the root after the open.
        self.resolve(location)?;
        Ok(Box::new(tokio::fs::File::from_std(file)))
    }

    async fn remove(&self, location: &str) -> Result<(), BlobError> {
        let path = self.resolve(location)?;
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(BlobError::Io(format!("cannot remove a blob: {error}"))),
        }
        // An emptied prefix directory goes too; a non-empty one stays.
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
        Ok(())
    }
}

/// One staging file being written: hashes as it goes, refuses writes past
/// the cap, and removes itself when dropped unfinished.
#[derive(Debug)]
pub struct StagingFile {
    file: Option<std::fs::File>,
    path: PathBuf,
    token: String,
    hasher: Sha256,
    size: u64,
    max_bytes: u64,
    overflowed: bool,
    keep: bool,
}

impl Write for StagingFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.size.saturating_add(buf.len() as u64) > self.max_bytes {
            self.overflowed = true;
            return Err(std::io::Error::other("the artifact exceeds the size cap"));
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("the staging file is finished"))?;
        let written = file.write(buf)?;
        self.hasher.update(&buf[..written]);
        self.size += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.as_mut().map_or(Ok(()), Write::flush)
    }
}

impl Drop for StagingFile {
    fn drop(&mut self) {
        if !self.keep {
            drop(self.file.take());
            let _ = std::fs::remove_file(&self.path);
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

/// Copies files off a Lab guest.
#[async_trait]
pub trait GuestFiles: std::fmt::Debug + Send + Sync {
    /// Copies `path` from the machine's endpoint into `sink`, bounded by
    /// `max_bytes` and `deadline`, and hands the sink back.
    async fn fetch(
        &self,
        machine_id: &str,
        endpoint_id: &str,
        path: &str,
        max_bytes: u64,
        deadline: Duration,
        sink: StagingFile,
    ) -> (Result<FetchOutcome, String>, StagingFile);

    /// Copies `source` into the guest file `request.path`, verifying its
    /// SHA-256 inside the guest, bounded by `deadline` (#393).
    async fn put(
        &self,
        _machine_id: &str,
        _endpoint_id: &str,
        _request: GuestPut,
        _deadline: Duration,
        _source: std::fs::File,
    ) -> Result<fleet_provider_ssh::PutOutcome, String> {
        Err("guest file puts are unavailable".to_owned())
    }
}

/// What to put into a guest.
#[derive(Clone, Debug)]
pub struct GuestPut {
    /// The absolute guest path of the file to create.
    pub path: String,
    /// The exact size in bytes.
    pub size: u64,
    /// The expected lowercase hex SHA-256.
    pub sha256: String,
    /// Whether an existing regular file may be replaced.
    pub overwrite: bool,
}

/// [`GuestFiles`] over the controller's OpenSSH trust store: the endpoint's
/// host key must already be verified (the same gate as machine exec).
#[derive(Debug)]
pub struct SshGuestFiles {
    machines: Arc<dyn fleet_application::machine::MachinePort>,
    provider: fleet_provider_ssh::SshProvider,
    limiter: Arc<fleet_provider_ssh::ExecutionLimiter>,
}

impl SshGuestFiles {
    /// Composes the copier over the controller's SSH work directory.
    ///
    /// # Errors
    ///
    /// Fails when the SSH work directory cannot be prepared.
    pub fn new(
        machines: Arc<dyn fleet_application::machine::MachinePort>,
        work_dir: PathBuf,
        limiter: Arc<fleet_provider_ssh::ExecutionLimiter>,
    ) -> Result<Self, String> {
        Ok(Self {
            machines,
            provider: fleet_provider_ssh::SshProvider::new(work_dir)
                .map_err(|error| error.to_string())?,
            limiter,
        })
    }
}

#[async_trait]
impl GuestFiles for SshGuestFiles {
    async fn fetch(
        &self,
        machine_id: &str,
        endpoint_id: &str,
        path: &str,
        max_bytes: u64,
        deadline: Duration,
        mut sink: StagingFile,
    ) -> (Result<FetchOutcome, String>, StagingFile) {
        let spec = match crate::exec::resolve_ssh_endpoint(
            self.machines.as_ref(),
            machine_id,
            endpoint_id,
            fleet_provider_ssh::SshAuth::Agent,
        )
        .await
        {
            Ok((spec, _, _)) => spec,
            Err(error) => return (Err(error), sink),
        };
        let provider = self.provider.clone();
        let limiter = self.limiter.clone();
        let path = path.to_owned();
        let joined = tokio::task::spawn_blocking(move || {
            let outcome = fleet_provider_ssh::fetch_file(
                &provider, &limiter, &spec, &path, max_bytes, deadline, &mut sink,
            )
            .map_err(|error| error.to_string());
            (outcome, sink)
        })
        .await;
        match joined {
            Ok(done) => done,
            // The sink moved into the panicked thread; a fresh handle stands
            // in so the caller's discard path still runs.
            Err(error) => (
                Err(format!("the copy thread failed: {error}")),
                StagingFile {
                    file: None,
                    path: PathBuf::new(),
                    token: String::new(),
                    hasher: Sha256::new(),
                    size: 0,
                    max_bytes: 0,
                    overflowed: false,
                    keep: true,
                },
            ),
        }
    }

    async fn put(
        &self,
        machine_id: &str,
        endpoint_id: &str,
        request: GuestPut,
        deadline: Duration,
        mut source: std::fs::File,
    ) -> Result<fleet_provider_ssh::PutOutcome, String> {
        let (spec, _, _) = crate::exec::resolve_ssh_endpoint(
            self.machines.as_ref(),
            machine_id,
            endpoint_id,
            fleet_provider_ssh::SshAuth::Agent,
        )
        .await?;
        let provider = self.provider.clone();
        let limiter = self.limiter.clone();
        tokio::task::spawn_blocking(move || {
            fleet_provider_ssh::put_file(
                &provider,
                &limiter,
                &spec,
                &fleet_provider_ssh::PutRequest {
                    path: &request.path,
                    size: request.size,
                    sha256: &request.sha256,
                    overwrite: request.overwrite,
                },
                deadline,
                &mut source,
            )
            .map_err(|error| error.to_string())
        })
        .await
        .map_err(|error| format!("the copy thread failed: {error}"))?
    }
}

/// [`GuestFiles`] when the controller could not prepare its SSH work
/// directory: every copy fails honestly (`transfer_failed`), while exec logs
/// keep being recorded.
#[derive(Debug)]
pub struct UnavailableGuestFiles {
    /// Why copies are unavailable.
    pub reason: String,
}

#[async_trait]
impl GuestFiles for UnavailableGuestFiles {
    async fn fetch(
        &self,
        _machine_id: &str,
        _endpoint_id: &str,
        _path: &str,
        _max_bytes: u64,
        _deadline: Duration,
        sink: StagingFile,
    ) -> (Result<FetchOutcome, String>, StagingFile) {
        (
            Err(format!(
                "guest file copies are unavailable: {}",
                self.reason
            )),
            sink,
        )
    }

    async fn put(
        &self,
        _machine_id: &str,
        _endpoint_id: &str,
        _request: GuestPut,
        _deadline: Duration,
        _source: std::fs::File,
    ) -> Result<fleet_provider_ssh::PutOutcome, String> {
        Err(format!(
            "guest file copies are unavailable: {}",
            self.reason
        ))
    }
}

/// The longest one collection may take, across all its paths.
pub const COLLECT_DEADLINE: Duration = Duration::from_secs(600);

/// Wraps the Lab executor with artifact recording (see the module docs).
#[derive(Debug)]
pub struct LabArtifactDispatch {
    inner: Arc<dyn OperationExecutor>,
    artifacts: Arc<LabArtifacts>,
    store: Arc<FsArtifactStore>,
    leases: Arc<dyn LeasePort>,
    provisions: Arc<dyn ProvisionPort>,
    files: Arc<dyn GuestFiles>,
}

impl LabArtifactDispatch {
    /// Composes the wrapper.
    #[must_use]
    pub fn new(
        inner: Arc<dyn OperationExecutor>,
        artifacts: Arc<LabArtifacts>,
        store: Arc<FsArtifactStore>,
        leases: Arc<dyn LeasePort>,
        provisions: Arc<dyn ProvisionPort>,
        files: Arc<dyn GuestFiles>,
    ) -> Self {
        Self {
            inner,
            artifacts,
            store,
            leases,
            provisions,
            files,
        }
    }

    /// Keeps a finished `lab.exec`'s output as an `exec-log` artifact. The
    /// exec's own outcome is already committed; a failure here is logged and
    /// never changes it.
    async fn record_exec_log(&self, operations: &Operations, operation: &Operation) {
        let Ok(done) = operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &operation.id,
            )
            .await
        else {
            return;
        };
        if !matches!(done.state.as_str(), "succeeded" | "failed" | "cancelled") {
            return;
        }
        let lease_id = payload_lease(operation);
        let Some(log) = exec_log_text(
            &done.id,
            &lease_id,
            &done.state,
            done.result_json.as_deref(),
            done.error_json.as_deref(),
        ) else {
            return;
        };
        if let Err(error) = self
            .artifacts
            .record_exec_log(
                &fleet_auth::LanAllowAllAuthorizer,
                &system_principal(),
                &lease_id,
                &done.id,
                &log,
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await
        {
            eprintln!(
                "lab artifacts: the exec log of operation {} was not stored: {error}",
                done.id
            );
        }
    }

    /// Runs a `lab.collect`.
    async fn collect(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let lease_id = payload_lease(operation);
        let paths: Vec<String> = operation
            .payload_json
            .as_deref()
            .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
            .and_then(|payload| serde_json::from_value(payload["paths"].clone()).ok())
            .unwrap_or_default();
        if let Err(detail) = validate_collect_paths(&paths) {
            return self
                .refuse(operations, operation, &lease_id, "invalid_paths", &detail)
                .await;
        }
        let (machine_id, endpoint_id) = match resolve_lab_machine(
            self.leases.as_ref(),
            self.provisions.as_ref(),
            &lease_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        {
            Ok(found) => found,
            Err((reason, detail)) => {
                return self
                    .refuse(operations, operation, &lease_id, reason, &detail)
                    .await;
            }
        };

        let started = std::time::Instant::now();
        let total = i64::try_from(paths.len()).unwrap_or(i64::MAX);
        let mut collected = Vec::new();
        let mut failures: Vec<(String, &'static str)> = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            // Progress is advisory: a failed write must not skip the
            // remaining paths or their failure record.
            if let Err(error) = operations
                .record_progress(
                    &operation.id,
                    Some(i64::try_from(index).unwrap_or(i64::MAX)),
                    Some(total),
                    Some(&format!("copying {} of {total}", index + 1)),
                )
                .await
            {
                eprintln!(
                    "lab artifacts: progress of collection {} not recorded: {error}",
                    operation.id
                );
            }
            let remaining = COLLECT_DEADLINE.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                failures.push((path.clone(), "deadline_exceeded"));
                continue;
            }
            match self
                .collect_one(
                    &lease_id,
                    &operation.id,
                    &machine_id,
                    &endpoint_id,
                    path,
                    remaining,
                )
                .await
            {
                Ok(artifact) => collected.push(serde_json::json!({
                    "path": path,
                    "artifactId": artifact.id,
                    "sizeBytes": artifact.size_bytes,
                    "sha256": artifact.sha256,
                })),
                Err(reason) => failures.push((path.clone(), reason)),
            }
        }

        if failures.is_empty() {
            let result = serde_json::json!({ "leaseId": lease_id, "artifacts": collected });
            return operations
                .complete(&operation.id, "succeeded", Some(&result.to_string()), None)
                .await
                .map(|_| ())
                .map_err(|error| error.to_string());
        }
        let detail = format!(
            "{} of {} paths were not collected: {}",
            failures.len(),
            paths.len(),
            failures
                .iter()
                .map(|(path, reason)| format!("{path} ({reason})"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let reason = if collected.is_empty() {
            "collection_failed"
        } else {
            "collection_partial"
        };
        self.record_failure(&lease_id, &operation.id, reason, &detail)
            .await;
        let error = serde_json::json!({
            "reason": reason,
            "detail": detail,
            "leaseId": lease_id,
            "artifacts": collected,
            "failures": failures
                .iter()
                .map(|(path, reason)| serde_json::json!({ "path": path, "reason": reason }))
                .collect::<Vec<_>>(),
        });
        operations
            .complete(&operation.id, "failed", None, Some(&error.to_string()))
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Copies one path and records it; answers a stable reason on failure.
    async fn collect_one(
        &self,
        lease_id: &str,
        operation_id: &str,
        machine_id: &str,
        endpoint_id: &str,
        path: &str,
        remaining: Duration,
    ) -> Result<fleet_application::lab_artifacts::LabArtifact, &'static str> {
        let staging = self.store.stage().map_err(|error| {
            eprintln!("lab artifacts: cannot stage a collected file: {error}");
            "store_failed"
        })?;
        let (outcome, staging) = self
            .files
            .fetch(
                machine_id,
                endpoint_id,
                path,
                self.store.max_bytes(),
                remaining,
                staging,
            )
            .await;
        let reason = match outcome {
            Ok(FetchOutcome::Fetched { .. }) => None,
            Ok(FetchOutcome::Missing) => Some("missing"),
            Ok(FetchOutcome::NotAFile) => Some("not_a_file"),
            Ok(FetchOutcome::Unreadable) => Some("unreadable"),
            Ok(FetchOutcome::TooLarge) => Some("too_large"),
            Ok(FetchOutcome::DeadlineKilled) => Some("deadline_exceeded"),
            Ok(FetchOutcome::Failed { .. }) => Some("copy_failed"),
            Ok(FetchOutcome::SinkFailed { detail }) => {
                eprintln!(
                    "lab artifacts: storing a file copied from lease {lease_id} failed: {detail}"
                );
                Some("store_failed")
            }
            Err(error) => {
                // The transport's error can carry node or tool text.
                let error = fleet_core::scrub_failure_detail(&error.to_string());
                eprintln!("lab artifacts: copying from lease {lease_id} failed: {error}");
                Some("transfer_failed")
            }
        };
        if let Some(reason) = reason {
            // Dropping the staging handle removes the partial copy.
            drop(staging);
            return Err(reason);
        }
        let staged = self.store.finish(staging).map_err(|error| match error {
            BlobError::TooLarge { .. } => "too_large",
            _ => "store_failed",
        })?;
        self.artifacts
            .record_file(
                &fleet_auth::LanAllowAllAuthorizer,
                &system_principal(),
                lease_id,
                operation_id,
                path,
                &staged,
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await
            .map_err(|error| {
                eprintln!("lab artifacts: a collected file was not recorded: {error}");
                "store_failed"
            })
    }

    async fn refuse(
        &self,
        operations: &Operations,
        operation: &Operation,
        lease_id: &str,
        reason: &str,
        detail: &str,
    ) -> Result<(), String> {
        if !lease_id.is_empty() {
            self.record_failure(lease_id, &operation.id, reason, detail)
                .await;
        }
        let error = serde_json::json!({ "reason": reason, "detail": detail }).to_string();
        operations
            .complete(&operation.id, "failed", None, Some(&error))
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Records a failed collection beside the lease. The lease itself is
    /// never touched, so its cleanup proceeds whatever happens here.
    async fn record_failure(&self, lease_id: &str, operation_id: &str, reason: &str, detail: &str) {
        let detail = fleet_core::scrub_failure_detail(detail);
        let detail = detail.as_str();
        if let Err(error) = self
            .artifacts
            .record_collection_failure(
                &fleet_auth::LanAllowAllAuthorizer,
                &system_principal(),
                lease_id,
                operation_id,
                reason,
                detail,
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await
        {
            eprintln!(
                "lab artifacts: the failed collection {operation_id} of lease {lease_id} was not recorded: {error}"
            );
        }
    }
}

#[async_trait]
impl OperationExecutor for LabArtifactDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "lab.exec" => {
                let result = self.inner.execute(operations, operation).await;
                self.record_exec_log(operations, operation).await;
                result
            }
            "lab.collect" => self.collect(operations, operation).await,
            _ => self.inner.execute(operations, operation).await,
        }
    }
}

/// Finds the machine and endpoint of a ready lease's guest, for the
/// executors that copy files over SSH (`lab.collect`, `lab.put`); answers a
/// stable reason and a bounded detail when the lease cannot take the copy.
/// The provision record must link back to this lease: a stale link must
/// never copy to or from another lease's guest.
pub(crate) async fn resolve_lab_machine(
    leases: &dyn LeasePort,
    provisions: &dyn ProvisionPort,
    lease_id: &str,
    now: i64,
) -> Result<(String, String), (&'static str, String)> {
    let lease = leases
        .get(lease_id)
        .await
        .map_err(|detail| ("lease_unavailable", logged(lease_id, "the lease", &detail)))?;
    lease_exec_ready(&lease, now).map_err(|detail| ("lease_not_ready", detail))?;
    let record = match &lease.provision_id {
        Some(id) => Some(provisions.get(id).await.map_err(|detail| {
            (
                "provision_unavailable",
                logged(lease_id, "the lease's provision record", &detail),
            )
        })?),
        None => None,
    };
    record
        .filter(|record| record.lease_id.as_deref() == Some(lease.id.as_str()))
        .and_then(|record| record.machine_id.zip(record.endpoint_id))
        .ok_or((
            "no_lab_machine",
            "the lease's guest has no registered Lab machine".to_owned(),
        ))
}

/// Logs a store failure's raw detail and answers the fixed message that is
/// recorded and served instead: backend text never reaches `lab.read`.
fn logged(lease_id: &str, what: &str, detail: &str) -> String {
    let detail = fleet_core::scrub_failure_detail(detail);
    eprintln!("lab artifacts: collecting from lease {lease_id}: reading {what} failed: {detail}");
    format!("{what} could not be read; the detail is in the controller log")
}

pub(crate) fn payload_lease(operation: &Operation) -> String {
    operation
        .payload_json
        .as_deref()
        .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
        .and_then(|payload| payload["leaseId"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

pub(crate) fn system_principal() -> ActingPrincipal {
    ActingPrincipal {
        id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::FsArtifactStore;
    use fleet_application::lab_artifacts::{ArtifactBlobPort as _, BlobError};
    use std::io::Write as _;

    const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    #[tokio::test]
    async fn blobs_are_content_addressed_deduplicated_and_verified() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsArtifactStore::open(&dir.path().join("artifacts"), 1024).unwrap();
        let first = store.put(b"test").await.unwrap();
        assert_eq!(first.sha256, DIGEST);
        assert_eq!(first.location, format!("sha256/9f/{DIGEST}"));
        assert_eq!(first.size_bytes, 4);
        // Identical bytes share the blob.
        assert_eq!(store.put(b"test").await.unwrap(), first);
        assert!(
            std::fs::read_dir(store.root().join("tmp"))
                .unwrap()
                .next()
                .is_none()
        );

        let mut reader = store.open(&first.location, DIGEST, 4).await.unwrap();
        let mut bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut bytes)
            .await
            .unwrap();
        assert_eq!(bytes, b"test");

        // A tampered blob is refused, never served.
        std::fs::write(store.root().join(&first.location), b"tset").unwrap();
        assert!(matches!(
            store.open(&first.location, DIGEST, 4).await.err(),
            Some(BlobError::Corrupt { .. })
        ));
        std::fs::write(store.root().join(&first.location), b"test!").unwrap();
        assert!(matches!(
            store.open(&first.location, DIGEST, 4).await.err(),
            Some(BlobError::Corrupt { .. })
        ));

        // Storing the same content again repairs the damaged blob instead of
        // trusting it.
        assert_eq!(store.put(b"test").await.unwrap(), first);
        assert!(store.open(&first.location, DIGEST, 4).await.is_ok());

        store.remove(&first.location).await.unwrap();
        assert!(matches!(
            store.open(&first.location, DIGEST, 4).await.err(),
            Some(BlobError::Missing)
        ));
        // Removing again is not an error.
        store.remove(&first.location).await.unwrap();
    }

    #[tokio::test]
    async fn locations_outside_the_content_addressed_shape_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsArtifactStore::open(&dir.path().join("artifacts"), 1024).unwrap();
        for location in [
            "../fleet.db".to_owned(),
            "/etc/passwd".to_owned(),
            format!("sha256/9f/../../{DIGEST}"),
            format!("sha256/00/{DIGEST}"),
            format!("sha256/9f/{DIGEST}/x"),
            format!("tmp/{DIGEST}"),
            format!("sha256//{DIGEST}"),
            format!("sha256/9F/{}", DIGEST.to_uppercase()),
            String::new(),
        ] {
            assert_eq!(
                store.resolve(&location).err(),
                Some(BlobError::InvalidLocation),
                "{location:?}"
            );
            assert!(store.remove(&location).await.is_err(), "{location:?}");
        }

        // A symlink planted in the store cannot lead out of it.
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().unwrap();
            std::fs::write(outside.path().join(DIGEST), b"test").unwrap();
            std::os::unix::fs::symlink(outside.path(), store.root().join("sha256/9f")).unwrap();
            assert_eq!(
                store.resolve(&format!("sha256/9f/{DIGEST}")).err(),
                Some(BlobError::InvalidLocation)
            );
            // A symlink for the whole blob directory, before any prefix
            // directory exists, is refused before anything is written.
            let other = tempfile::tempdir().unwrap();
            let store2 = FsArtifactStore::open(&other.path().join("artifacts"), 1024).unwrap();
            std::fs::remove_dir(store2.root().join("sha256")).unwrap();
            std::os::unix::fs::symlink(outside.path(), store2.root().join("sha256")).unwrap();
            assert_eq!(
                store2.resolve(&format!("sha256/9f/{DIGEST}")).err(),
                Some(BlobError::InvalidLocation)
            );
            assert!(store2.put(b"test").await.is_err());
            assert!(!outside.path().join("9f").exists());
        }
    }

    #[tokio::test]
    async fn the_size_cap_holds_for_puts_and_staged_writes() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsArtifactStore::open(&dir.path().join("artifacts"), 8).unwrap();
        assert!(matches!(
            store.put(b"123456789").await,
            Err(BlobError::TooLarge { max_bytes: 8 })
        ));
        let mut staging = store.stage().unwrap();
        staging.write_all(b"12345678").unwrap();
        assert!(staging.write_all(b"9").is_err());
        assert!(matches!(
            store.finish(staging),
            Err(BlobError::TooLarge { .. })
        ));
        // A refused or abandoned staging file leaves nothing behind.
        drop(store.stage().unwrap());
        assert!(
            std::fs::read_dir(store.root().join("tmp"))
                .unwrap()
                .next()
                .is_none()
        );
        assert!(
            std::fs::read_dir(store.root().join("sha256"))
                .unwrap()
                .next()
                .is_none()
        );
    }
}
