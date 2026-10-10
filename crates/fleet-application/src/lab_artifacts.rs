//! Lab artifacts (FM-721): exec logs and collected guest files that outlive
//! their lease.
//!
//! SQLite keeps the metadata — lease, project, owner, kind, name, size,
//! sha256, the store-relative location, and the retention deadline — and
//! never the bytes. The bytes live in a configured controller directory
//! behind [`ArtifactBlobPort`], content-addressed by their sha256, so two
//! artifacts with identical content share one blob.
//!
//! Every mutation is authorized here against `lab.artifacts` and audited:
//! a collection request, each recorded artifact, each recorded collection
//! failure, and each retention deletion. Collection never changes a lease's
//! state, so a failed or slow collection can neither block nor skip the
//! lease's cleanup; its failure is recorded beside the lease instead.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use fleet_core::GuestOs;

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::lab::{LabUseCaseError, LeasePort, ProvisionPort, lease_exec_ready};
use crate::operation::{AuditPort, NewOperation};

/// What an artifact holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    /// The bounded, redacted stdout/stderr of one `lab exec`.
    ExecLog,
    /// A file copied from the guest by an explicit collection.
    File,
}

impl ArtifactKind {
    /// The stable id stored and served.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::ExecLog => "exec-log",
            Self::File => "file",
        }
    }

    /// Parses a stored id.
    ///
    /// # Errors
    ///
    /// Fails on an unknown id.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "exec-log" => Ok(Self::ExecLog),
            "file" => Ok(Self::File),
            other => Err(format!("unknown artifact kind {other:?}")),
        }
    }
}

/// One stored artifact's metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabArtifact {
    /// The artifact's identity.
    pub id: String,
    /// The lease it came from.
    pub lease_id: String,
    /// The project that lease served, when it recorded one.
    pub project_id: Option<String>,
    /// The lease's owner.
    pub owner: String,
    /// What it holds.
    pub kind: ArtifactKind,
    /// Its name: `exec-<operation>.log` for an exec log, the guest path for
    /// a collected file.
    pub name: String,
    /// Its size in bytes.
    pub size_bytes: u64,
    /// The lowercase hex sha256 of its bytes.
    pub sha256: String,
    /// Where its bytes live, relative to the artifact store's root.
    pub location: String,
    /// The `lab.exec` or `lab.collect` operation that produced it.
    pub operation_id: Option<String>,
    /// When it was stored (epoch milliseconds).
    pub created_at: i64,
    /// When the retention sweep deletes it (epoch milliseconds).
    pub retain_until: i64,
}

/// An artifact to record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewArtifact {
    /// The lease it came from.
    pub lease_id: String,
    /// The project that lease served.
    pub project_id: Option<String>,
    /// The lease's owner.
    pub owner: String,
    /// What it holds.
    pub kind: ArtifactKind,
    /// Its name.
    pub name: String,
    /// Its stored bytes.
    pub blob: StoredBlob,
    /// The operation that produced it.
    pub operation_id: Option<String>,
    /// When it was stored.
    pub created_at: i64,
    /// When the retention sweep deletes it.
    pub retain_until: i64,
}

/// The last failed collection of one lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionFailure {
    /// The lease.
    pub lease_id: String,
    /// The `lab.collect` operation that failed.
    pub operation_id: String,
    /// A stable reason id.
    pub reason: String,
    /// A bounded, human-readable detail. Never guest output.
    pub detail: String,
    /// When it failed (epoch milliseconds).
    pub failed_at: i64,
}

/// Bytes committed to the artifact store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredBlob {
    /// The store-relative location.
    pub location: String,
    /// The size in bytes.
    pub size_bytes: u64,
    /// The lowercase hex sha256.
    pub sha256: String,
}

/// Bytes written to the store's staging area, not yet committed. The token
/// is the store's own handle for them; it means nothing elsewhere.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedBlob {
    /// The store's handle.
    pub token: String,
    /// The size in bytes.
    pub size_bytes: u64,
    /// The lowercase hex sha256.
    pub sha256: String,
}

/// An artifact store failure.
#[derive(Debug, Eq, PartialEq)]
pub enum BlobError {
    /// The bytes exceed the configured size cap.
    TooLarge {
        /// The cap, in bytes.
        max_bytes: u64,
    },
    /// The stored bytes no longer match the recorded digest or size.
    Corrupt {
        /// What did not match.
        detail: String,
    },
    /// The staging area is full or has too many uploads in flight.
    Busy {
        /// Why.
        detail: String,
    },
    /// No bytes exist at the location.
    Missing,
    /// The location is not a store location.
    InvalidLocation,
    /// The filesystem failed.
    Io(String),
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { max_bytes } => {
                write!(f, "the artifact exceeds the {max_bytes}-byte cap")
            }
            Self::Corrupt { detail } => write!(f, "the stored artifact is corrupt: {detail}"),
            Self::Busy { detail } => write!(f, "the upload staging area is busy: {detail}"),
            Self::Missing => f.write_str("the artifact's bytes are missing from the store"),
            Self::InvalidLocation => f.write_str("the location is not inside the artifact store"),
            Self::Io(detail) => write!(f, "the artifact store failed: {detail}"),
        }
    }
}

impl std::error::Error for BlobError {}

/// A verified artifact's bytes, ready to stream.
pub type ArtifactReader = Box<dyn tokio::io::AsyncRead + Send + Unpin>;

/// Artifact metadata persistence.
#[async_trait]
pub trait LabArtifactPort: fmt::Debug + Send + Sync {
    /// Records an artifact.
    ///
    /// # Errors
    ///
    /// Fails on a backend failure or an unknown lease.
    async fn insert(&self, new: &NewArtifact) -> Result<LabArtifact, String>;

    /// Reads one artifact.
    ///
    /// # Errors
    ///
    /// Fails on a backend failure.
    async fn get(&self, id: &str) -> Result<Option<LabArtifact>, String>;

    /// Lists up to `limit` artifacts, newest first, narrowed by lease
    /// and/or project, after the artifact `cursor` names when given (an
    /// unknown cursor answers nothing).
    ///
    /// # Errors
    ///
    /// Fails on a backend failure.
    async fn list(
        &self,
        lease_id: Option<&str>,
        project_id: Option<&str>,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Vec<LabArtifact>, String>;

    /// As [`LabArtifactPort::list`], narrowed to the artifacts recorded
    /// under `owner`.
    ///
    /// # Errors
    ///
    /// Fails on a backend failure.
    async fn list_for_owner(
        &self,
        owner: &str,
        lease_id: Option<&str>,
        project_id: Option<&str>,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Vec<LabArtifact>, String>;

    /// Up to `limit` artifacts whose retention deadline is at or before
    /// `now`, oldest deadline first.
    ///
    /// # Errors
    ///
    /// Fails on a backend failure.
    async fn expired(&self, now: i64, limit: u32) -> Result<Vec<LabArtifact>, String>;

    /// Deletes one artifact's metadata; answers whether it existed.
    ///
    /// # Errors
    ///
    /// Fails on a backend failure.
    async fn delete(&self, id: &str) -> Result<bool, String>;

    /// How many artifacts name this location.
    ///
    /// # Errors
    ///
    /// Fails on a backend failure.
    async fn location_references(&self, location: &str) -> Result<u64, String>;

    /// Records (replacing any earlier one) a lease's last failed collection.
    ///
    /// # Errors
    ///
    /// Fails on a backend failure or an unknown lease.
    async fn record_collection_failure(&self, failure: &CollectionFailure) -> Result<(), String>;

    /// A lease's last failed collection, when any.
    ///
    /// # Errors
    ///
    /// Fails on a backend failure.
    async fn collection_failure(&self, lease_id: &str)
    -> Result<Option<CollectionFailure>, String>;
}

/// The artifact byte store.
#[async_trait]
pub trait ArtifactBlobPort: fmt::Debug + Send + Sync {
    /// Stores bytes, content-addressed.
    ///
    /// # Errors
    ///
    /// Fails when the bytes exceed the cap or the store fails.
    async fn put(&self, bytes: &[u8]) -> Result<StoredBlob, BlobError>;

    /// Commits staged bytes, content-addressed.
    ///
    /// # Errors
    ///
    /// Fails on an unknown token or a store failure.
    async fn commit(&self, staged: &StagedBlob) -> Result<StoredBlob, BlobError>;

    /// Discards staged bytes. Never fails: a leftover staging file is
    /// reclaimed when the store next starts.
    async fn discard(&self, staged: &StagedBlob);

    /// Opens a location for reading after verifying its size and sha256.
    ///
    /// # Errors
    ///
    /// Fails on an invalid location, missing bytes, or a digest mismatch.
    async fn open(
        &self,
        location: &str,
        sha256: &str,
        size_bytes: u64,
    ) -> Result<ArtifactReader, BlobError>;

    /// Removes a location's bytes; an absent location is already removed.
    ///
    /// # Errors
    ///
    /// Fails on an invalid location or a store failure.
    async fn remove(&self, location: &str) -> Result<(), BlobError>;
}

/// The configured artifact bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactPolicy {
    /// How long an artifact is kept, in seconds.
    pub retention_seconds: u64,
    /// The largest artifact the store accepts, in bytes.
    pub max_bytes: u64,
}

/// The default retention: seven days.
pub const DEFAULT_ARTIFACT_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;
/// The default per-artifact size cap: 64 MiB.
pub const DEFAULT_ARTIFACT_MAX_BYTES: u64 = 64 * 1024 * 1024;

impl Default for ArtifactPolicy {
    fn default() -> Self {
        Self {
            retention_seconds: DEFAULT_ARTIFACT_RETENTION_SECONDS,
            max_bytes: DEFAULT_ARTIFACT_MAX_BYTES,
        }
    }
}

impl ArtifactPolicy {
    /// The retention deadline of an artifact stored at `now`.
    #[must_use]
    pub fn retain_until(&self, now: i64) -> i64 {
        let millis = i64::try_from(self.retention_seconds.saturating_mul(1000)).unwrap_or(i64::MAX);
        now.saturating_add(millis)
    }
}

/// The most paths one collection may name.
pub const MAX_COLLECT_PATHS: usize = 16;
/// The longest guest path a collection accepts, in bytes.
pub const MAX_COLLECT_PATH_BYTES: usize = 1024;
/// The longest a collection detail may be, in characters.
pub const MAX_FAILURE_DETAIL_CHARS: usize = 1024;
/// How many expired artifacts one retention pass deletes at most.
pub const RETENTION_BATCH: u32 = 500;

/// Validates a collection's guest paths: 1 to [`MAX_COLLECT_PATHS`]
/// distinct absolute paths, each at most [`MAX_COLLECT_PATH_BYTES`] bytes,
/// with no `.` or `..` component, no empty component other than the root,
/// and no control character. This is the Linux rule set; see
/// [`validate_collect_paths_for`].
///
/// # Errors
///
/// Answers which rule a path broke.
pub fn validate_collect_paths(paths: &[String]) -> Result<(), String> {
    validate_collect_paths_for(GuestOs::Linux, paths)
}

/// [`validate_collect_paths`] for a guest OS. On Windows two paths that name
/// the same file under case-insensitive, separator-insensitive comparison
/// count as one path named twice.
///
/// # Errors
///
/// Answers which rule a path broke.
pub fn validate_collect_paths_for(os: GuestOs, paths: &[String]) -> Result<(), String> {
    if paths.is_empty() || paths.len() > MAX_COLLECT_PATHS {
        return Err(format!(
            "a collection names 1 to {MAX_COLLECT_PATHS} guest paths"
        ));
    }
    for (index, path) in paths.iter().enumerate() {
        validate_guest_path_for(os, path)
            .map_err(|detail| format!("guest path {index}: {detail}"))?;
        let key = dedup_key(os, path);
        if paths[..index]
            .iter()
            .any(|earlier| dedup_key(os, earlier) == key)
        {
            return Err(format!("guest path {path:?} is named twice"));
        }
    }
    Ok(())
}

/// The key under which two guest paths are the same file: the path itself on
/// Linux, the lowercased path with `\` separators on Windows.
fn dedup_key(os: GuestOs, path: &str) -> String {
    match os {
        GuestOs::Linux => path.to_owned(),
        GuestOs::Windows => path.replace('/', "\\").to_lowercase(),
    }
}

/// Validates one Linux guest file path: absolute, at most
/// [`MAX_COLLECT_PATH_BYTES`] bytes, no `.` or `..` component, no empty
/// component other than the root, and no control character. Shared by
/// `lab.collect` and `lab.put`; see [`validate_guest_path_for`].
///
/// # Errors
///
/// Answers which rule the path broke.
pub fn validate_guest_path(path: &str) -> Result<(), String> {
    validate_guest_path_for(GuestOs::Linux, path)
}

/// Validates one guest file path under the rules of the guest's OS.
///
/// Linux: see [`validate_guest_path`]. Windows (ADR 0015): a drive-absolute
/// path (`C:\...` or `C:/...`), no UNC or device prefix (`\\server`,
/// `\\?\`, `\\.\`), no `.`, `..` or empty component, no control
/// character, none of `<>:"|?*` (so no alternate data stream), no trailing
/// dot or space in a component, no reserved device name (`CON`, `NUL`,
/// `COM1`, ... with or without an extension), and components of at most 255
/// UTF-16 units. The path must name something under the drive root.
///
/// # Errors
///
/// Answers which rule the path broke.
pub fn validate_guest_path_for(os: GuestOs, path: &str) -> Result<(), String> {
    match os {
        GuestOs::Linux => validate_posix_path(path),
        GuestOs::Windows => validate_windows_path(path),
    }
}

fn validate_posix_path(path: &str) -> Result<(), String> {
    if path.len() > MAX_COLLECT_PATH_BYTES {
        return Err(format!(
            "the path is longer than {MAX_COLLECT_PATH_BYTES} bytes"
        ));
    }
    if !path.starts_with('/') || path.len() < 2 {
        return Err("the path must be an absolute file path".to_owned());
    }
    if path.chars().any(char::is_control) {
        return Err("the path contains a control character".to_owned());
    }
    if path[1..]
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err("the path must not contain empty, `.`, or `..` components".to_owned());
    }
    Ok(())
}

/// Device names Windows reserves in every directory, with or without an
/// extension and in any case.
const WINDOWS_RESERVED_STEMS: [&str; 6] = ["con", "prn", "aux", "nul", "conin$", "conout$"];

fn is_windows_reserved_stem(stem: &str) -> bool {
    // `NUL.txt` and `nul .txt` are the device too: the name up to the first
    // dot, without trailing spaces, is what counts.
    let stem = stem
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ')
        .to_lowercase();
    if WINDOWS_RESERVED_STEMS.contains(&stem.as_str()) {
        return true;
    }
    // COM0-9 and LPT0-9, including the superscript digits Windows also
    // reserves.
    let mut chars = stem.chars();
    let prefix: String = chars.by_ref().take(3).collect();
    matches!(prefix.as_str(), "com" | "lpt")
        && matches!(
            chars.next(),
            Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}')
        )
        && chars.next().is_none()
}

fn validate_windows_path(path: &str) -> Result<(), String> {
    if path.len() > MAX_COLLECT_PATH_BYTES {
        return Err(format!(
            "the path is longer than {MAX_COLLECT_PATH_BYTES} bytes"
        ));
    }
    if path.chars().any(char::is_control) {
        return Err("the path contains a control character".to_owned());
    }
    let bytes = path.as_bytes();
    if bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'\\' | b'/')
    {
        return Err(
            "the path must be an absolute drive path such as C:\\dir\\file (UNC and device paths are refused)"
                .to_owned(),
        );
    }
    for component in path[3..].split(['\\', '/']) {
        if component.is_empty() || component == "." || component == ".." {
            return Err("the path must not contain empty, `.`, or `..` components".to_owned());
        }
        if component.chars().any(|c| "<>:\"|?*".contains(c)) {
            return Err(
                "a path component contains a character Windows reserves (one of <>:\"|?*; alternate data streams are refused)"
                    .to_owned(),
            );
        }
        if component.ends_with('.') || component.ends_with(' ') {
            return Err("a path component must not end with a dot or a space".to_owned());
        }
        if component.encode_utf16().count() > 255 {
            return Err("a path component is longer than 255 characters".to_owned());
        }
        if is_windows_reserved_stem(component) {
            return Err("a path component is a reserved Windows device name".to_owned());
        }
    }
    Ok(())
}

/// Whether a string is a lowercase hex sha256.
#[must_use]
pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The exec log of a finished `lab.exec` operation: its exit code and its
/// bounded stdout/stderr, scrubbed of URL and `user:password@` credentials.
/// Answers `None` when the operation carries no output (it was refused
/// before anything ran).
#[must_use]
pub fn exec_log_text(
    operation_id: &str,
    lease_id: &str,
    state: &str,
    result_json: Option<&str>,
    error_json: Option<&str>,
) -> Option<String> {
    use std::fmt::Write as _;
    let parse =
        |raw: Option<&str>| raw.and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok());
    let output = parse(result_json).or_else(|| parse(error_json))?;
    // A deadline kill reports its partial output beside the reason.
    let streams = if output.get("stdout").is_some() || output.get("stderr").is_some() {
        &output
    } else {
        output.get("partialOutput")?
    };
    let scrub = fleet_core::redact_credentials;
    let stream = |name: &str| scrub(streams[name].as_str().unwrap_or_default());
    let exit = output["exitCode"]
        .as_i64()
        .map_or_else(|| "none".to_owned(), |code| code.to_string());
    let mut text = format!(
        "# lab exec {operation_id} on lease {lease_id}\n# state: {state}\n# exit code: {exit}\n"
    );
    if let Some(reason) = output["reason"].as_str() {
        let _ = writeln!(text, "# reason: {}", scrub(reason));
    }
    for (name, truncated) in [("stdout", "truncatedStdout"), ("stderr", "truncatedStderr")] {
        let _ = write!(text, "--- {name}");
        // The flags sit beside the streams (a deadline kill records them in
        // `partialOutput`); older records carry them on the outer object.
        if streams[truncated].as_bool() == Some(true) || output[truncated].as_bool() == Some(true) {
            text.push_str(" (truncated)");
        }
        text.push_str(" ---\n");
        let body = stream(name);
        text.push_str(&body);
        if !body.is_empty() && !body.ends_with('\n') {
            text.push('\n');
        }
    }
    Some(text)
}

/// Narrows an artifact listing.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArtifactFilter<'a> {
    /// Only artifacts from this lease.
    pub lease_id: Option<&'a str>,
    /// Only artifacts from leases serving this project.
    pub project_id: Option<&'a str>,
    /// Only artifacts listed after this one.
    pub cursor: Option<&'a str>,
}

/// What one retention pass did.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct RetentionReport {
    /// Artifacts deleted.
    pub deleted: usize,
    /// Per-artifact failures; the rest of the pass still ran.
    pub failures: Vec<String>,
}

/// The Lab artifact use cases.
#[derive(Debug)]
pub struct LabArtifacts {
    artifacts: Arc<dyn LabArtifactPort>,
    blobs: Arc<dyn ArtifactBlobPort>,
    leases: Arc<dyn LeasePort>,
    provisions: Arc<dyn ProvisionPort>,
    audit: Arc<dyn AuditPort>,
    policy: ArtifactPolicy,
    /// Serializes blob commits with blob removals: content addressing lets
    /// two artifacts share one blob, so a removal must not race a commit
    /// that is about to reference the same bytes.
    blob_lock: tokio::sync::Mutex<()>,
}

impl LabArtifacts {
    /// Composes the use cases.
    #[must_use]
    pub fn new(
        artifacts: Arc<dyn LabArtifactPort>,
        blobs: Arc<dyn ArtifactBlobPort>,
        leases: Arc<dyn LeasePort>,
        provisions: Arc<dyn ProvisionPort>,
        audit: Arc<dyn AuditPort>,
        policy: ArtifactPolicy,
    ) -> Self {
        Self {
            artifacts,
            blobs,
            leases,
            provisions,
            audit,
            policy,
            blob_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// The configured bounds.
    #[must_use]
    pub fn policy(&self) -> ArtifactPolicy {
        self.policy
    }

    /// Lists up to `limit` artifacts, newest first, narrowed by lease
    /// and/or project, after the `cursor` artifact when given.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        filter: ArtifactFilter<'_>,
        limit: u32,
    ) -> Result<Vec<LabArtifact>, LabUseCaseError> {
        allow(authorizer, principal, Permission::LabArtifactRead, None)?;
        // A delegated credential lists its own owner's artifacts only.
        if let Some(owner) = crate::authz::delegated_owner_identity(&principal.id) {
            return self
                .artifacts
                .list_for_owner(
                    owner,
                    filter.lease_id,
                    filter.project_id,
                    filter.cursor,
                    limit,
                )
                .await
                .map_err(backend);
        }
        self.artifacts
            .list(filter.lease_id, filter.project_id, filter.cursor, limit)
            .await
            .map_err(backend)
    }

    /// Reads one artifact's metadata.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown artifact, or a backend failure.
    pub async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<LabArtifact, LabUseCaseError> {
        allow(authorizer, principal, Permission::LabArtifactRead, None)?;
        let artifact = self.require(id).await?;
        scope_artifact(principal, &artifact)?;
        Ok(artifact)
    }

    /// Opens an artifact's bytes for download, after the store verified
    /// them against the recorded size and sha256. Downloading needs
    /// `lab.artifacts`: an exec log or a collected file can be sensitive.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown artifact, or bytes that are missing or
    /// no longer match their digest (a conflict, never served).
    pub async fn open(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<(LabArtifact, ArtifactReader), LabUseCaseError> {
        // Authorize on the artifact's lease, as every other artifact check
        // does, so a lease-scoped policy covers its downloads.
        let artifact = self.require(id).await?;
        allow(
            authorizer,
            principal,
            Permission::LabArtifacts,
            Some(&artifact.lease_id),
        )?;
        scope_artifact(principal, &artifact)?;
        let reader = self
            .blobs
            .open(&artifact.location, &artifact.sha256, artifact.size_bytes)
            .await
            .map_err(|error| match error {
                BlobError::Corrupt { .. } | BlobError::Missing | BlobError::InvalidLocation => {
                    LabUseCaseError::Conflict {
                        detail: format!("artifact {id}: {error}"),
                    }
                }
                other => backend(other.to_string()),
            })?;
        Ok((artifact, reader))
    }

    /// A lease's last failed collection, when any.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn collection_failure(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        lease_id: &str,
    ) -> Result<Option<CollectionFailure>, LabUseCaseError> {
        allow(
            authorizer,
            principal,
            Permission::LabLeaseRead,
            Some(lease_id),
        )?;
        if crate::authz::is_delegated_principal(&principal.id) {
            let lease = self.lease(lease_id).await?;
            scope_lease(principal, &lease)?;
        }
        self.artifacts
            .collection_failure(lease_id)
            .await
            .map_err(backend)
    }

    /// Validates a collection of guest paths from a ready lease and answers
    /// the `lab.collect` operation to queue. The lease must be ready and
    /// unexpired with a registered Lab machine; the executor re-checks
    /// that when it runs.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown lease, a lease that cannot run commands,
    /// or invalid paths.
    pub async fn request_collect(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        lease_id: &str,
        paths: &[String],
        now: i64,
    ) -> Result<NewOperation, LabUseCaseError> {
        allow(
            authorizer,
            principal,
            Permission::LabArtifacts,
            Some(lease_id),
        )?;
        validate_collect_paths(paths).map_err(|detail| LabUseCaseError::Invalid { detail })?;
        require_guest_machine(
            self.leases.as_ref(),
            self.provisions.as_ref(),
            principal,
            lease_id,
            now,
            "collect from",
        )
        .await?;
        self.audit_event(
            principal,
            lease_id,
            "lab_artifacts_collect_requested",
            &[("paths", paths.len().to_string())],
        )
        .await?;
        Ok(NewOperation {
            kind: "lab.collect".to_owned(),
            idempotency_key: None,
            deadline_at: None,
            correlation_id: None,
            payload_json: Some(
                serde_json::json!({ "leaseId": lease_id, "paths": paths }).to_string(),
            ),
            review_token: None,
        })
    }

    /// Stores a finished `lab.exec`'s log as an `exec-log` artifact.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown lease, an oversized log, or a backend
    /// failure.
    pub async fn record_exec_log(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        lease_id: &str,
        operation_id: &str,
        log: &str,
        now: i64,
    ) -> Result<LabArtifact, LabUseCaseError> {
        allow(
            authorizer,
            principal,
            Permission::LabArtifacts,
            Some(lease_id),
        )?;
        let lease = self.lease(lease_id).await?;
        // The audit intent precedes every mutation.
        let digest = {
            use sha2::Digest as _;
            sha2::Sha256::digest(log.as_bytes()).iter().fold(
                String::with_capacity(64),
                |mut text, byte| {
                    use std::fmt::Write as _;
                    let _ = write!(text, "{byte:02x}");
                    text
                },
            )
        };
        self.audit_recording(
            principal,
            lease_id,
            operation_id,
            ArtifactKind::ExecLog,
            log.len() as u64,
            &digest,
        )
        .await?;
        let artifact = {
            let _guard = self.blob_lock.lock().await;
            let blob = self.blobs.put(log.as_bytes()).await.map_err(blob_refused)?;
            let location = blob.location.clone();
            let inserted = self
                .artifacts
                .insert(&NewArtifact {
                    lease_id: lease.id.clone(),
                    project_id: lease.project_id.clone(),
                    owner: lease.owner.clone(),
                    kind: ArtifactKind::ExecLog,
                    name: format!("exec-{operation_id}.log"),
                    blob,
                    operation_id: Some(operation_id.to_owned()),
                    created_at: now,
                    retain_until: self.policy.retain_until(now),
                })
                .await;
            match inserted {
                Ok(artifact) => artifact,
                Err(detail) => {
                    let cleanup = self.release_unreferenced(&location).await;
                    return Err(backend(format!("{detail}{cleanup}")));
                }
            }
        };
        Ok(artifact)
    }

    /// Commits a file a collection staged and records it as a `file`
    /// artifact named by its guest path.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown lease, or a backend failure; the staged
    /// bytes are discarded on any failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_file(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        lease_id: &str,
        operation_id: &str,
        guest_path: &str,
        staged: &StagedBlob,
        now: i64,
    ) -> Result<LabArtifact, LabUseCaseError> {
        let recorded = async {
            allow(
                authorizer,
                principal,
                Permission::LabArtifacts,
                Some(lease_id),
            )?;
            if staged.size_bytes > self.policy.max_bytes {
                return Err(blob_refused(BlobError::TooLarge {
                    max_bytes: self.policy.max_bytes,
                }));
            }
            let lease = self.lease(lease_id).await?;
            // The audit intent precedes every mutation.
            self.audit_recording(
                principal,
                lease_id,
                operation_id,
                ArtifactKind::File,
                staged.size_bytes,
                &staged.sha256,
            )
            .await?;
            let _guard = self.blob_lock.lock().await;
            let blob = self.blobs.commit(staged).await.map_err(blob_refused)?;
            let location = blob.location.clone();
            let inserted = self
                .artifacts
                .insert(&NewArtifact {
                    lease_id: lease.id.clone(),
                    project_id: lease.project_id.clone(),
                    owner: lease.owner.clone(),
                    kind: ArtifactKind::File,
                    name: guest_path.to_owned(),
                    blob,
                    operation_id: Some(operation_id.to_owned()),
                    created_at: now,
                    retain_until: self.policy.retain_until(now),
                })
                .await;
            match inserted {
                Ok(artifact) => Ok(artifact),
                Err(detail) => {
                    let cleanup = self.release_unreferenced(&location).await;
                    Err(backend(format!("{detail}{cleanup}")))
                }
            }
        }
        .await;
        if recorded.is_err() {
            self.blobs.discard(staged).await;
        }
        recorded
    }

    /// Discards staged bytes that will not be recorded.
    pub async fn discard(&self, staged: &StagedBlob) {
        self.blobs.discard(staged).await;
    }

    /// Records a lease's failed collection, replacing the earlier one.
    /// The lease's state is never touched: cleanup proceeds regardless.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_collection_failure(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        lease_id: &str,
        operation_id: &str,
        reason: &str,
        detail: &str,
        now: i64,
    ) -> Result<CollectionFailure, LabUseCaseError> {
        allow(
            authorizer,
            principal,
            Permission::LabArtifacts,
            Some(lease_id),
        )?;
        let failure = CollectionFailure {
            lease_id: lease_id.to_owned(),
            operation_id: operation_id.to_owned(),
            reason: reason.to_owned(),
            detail: detail.chars().take(MAX_FAILURE_DETAIL_CHARS).collect(),
            failed_at: now,
        };
        // The audit intent precedes the mutation.
        self.audit_event(
            principal,
            lease_id,
            "lab_artifacts_collection_failed",
            &[
                ("operationId", operation_id.to_owned()),
                ("reason", reason.to_owned()),
            ],
        )
        .await?;
        self.artifacts
            .record_collection_failure(&failure)
            .await
            .map_err(backend)?;
        Ok(failure)
    }

    /// Deletes every artifact whose retention deadline has passed: its
    /// metadata, then its bytes once no other artifact shares them. Each
    /// deletion is audited; a failure confined to one artifact is reported
    /// and retried on the next pass.
    ///
    /// # Errors
    ///
    /// Fails on denial or when the expired artifacts cannot be listed.
    pub async fn sweep_retention(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        now: i64,
    ) -> Result<RetentionReport, LabUseCaseError> {
        allow(
            authorizer,
            principal,
            Permission::LabArtifacts,
            Some("retention"),
        )?;
        let mut report = RetentionReport::default();
        let expired = self
            .artifacts
            .expired(now, RETENTION_BATCH)
            .await
            .map_err(backend)?;
        for artifact in expired {
            match self.delete_expired(principal, &artifact).await {
                Ok(true) => report.deleted += 1,
                Ok(false) => {}
                Err(error) => report
                    .failures
                    .push(format!("deleting artifact {}: {error}", artifact.id)),
            }
        }
        Ok(report)
    }

    async fn delete_expired(
        &self,
        principal: &ActingPrincipal,
        artifact: &LabArtifact,
    ) -> Result<bool, String> {
        // The audit intent precedes the deletion: a refused audit deletes
        // nothing and the next pass retries.
        self.audit_event(
            principal,
            &artifact.id,
            "lab_artifact_expired",
            &[
                ("leaseId", artifact.lease_id.clone()),
                ("kind", artifact.kind.id().to_owned()),
                ("sha256", artifact.sha256.clone()),
            ],
        )
        .await
        .map_err(|error| error.to_string())?;
        let _guard = self.blob_lock.lock().await;
        // The bytes go first and the metadata last: a failure in between
        // leaves the row, so the next pass retries, and removing bytes that
        // are already gone succeeds.
        if self
            .artifacts
            .location_references(&artifact.location)
            .await?
            <= 1
        {
            self.blobs
                .remove(&artifact.location)
                .await
                .map_err(|error| format!("its bytes were not removed: {error}"))?;
        }
        self.artifacts.delete(&artifact.id).await
    }

    /// Removes committed bytes that no artifact references, after their
    /// metadata insert failed; the caller holds the blob lock. Answers a
    /// suffix for the caller's error naming any cleanup that failed, so the
    /// leftover bytes (never servable) are visible to the operator.
    async fn release_unreferenced(&self, location: &str) -> String {
        match self.artifacts.location_references(location).await {
            Ok(0) => match self.blobs.remove(location).await {
                Ok(()) => String::new(),
                Err(error) => {
                    format!("; its unreferenced bytes at {location} were not removed: {error}")
                }
            },
            Ok(_) => String::new(),
            Err(error) => format!(
                "; whether the bytes at {location} are still referenced is unknown: {error}"
            ),
        }
    }

    async fn require(&self, id: &str) -> Result<LabArtifact, LabUseCaseError> {
        self.artifacts
            .get(id)
            .await
            .map_err(backend)?
            .ok_or_else(|| LabUseCaseError::NotFound {
                what: format!("artifact {id}"),
            })
    }

    async fn lease(&self, id: &str) -> Result<fleet_core::Lease, LabUseCaseError> {
        self.leases.get(id).await.map_err(|detail| {
            if detail.contains("not found") {
                LabUseCaseError::NotFound {
                    what: format!("lease {id}"),
                }
            } else {
                backend(detail)
            }
        })
    }

    async fn audit_recording(
        &self,
        principal: &ActingPrincipal,
        lease_id: &str,
        operation_id: &str,
        kind: ArtifactKind,
        size_bytes: u64,
        sha256: &str,
    ) -> Result<(), LabUseCaseError> {
        self.audit_event(
            principal,
            lease_id,
            "lab_artifact_recording",
            &[
                ("operationId", operation_id.to_owned()),
                ("kind", kind.id().to_owned()),
                ("sizeBytes", size_bytes.to_string()),
                ("sha256", sha256.to_owned()),
            ],
        )
        .await
    }

    async fn audit_event(
        &self,
        principal: &ActingPrincipal,
        resource: &str,
        event: &str,
        facts: &[(&str, String)],
    ) -> Result<(), LabUseCaseError> {
        let mut metadata = crate::audit::AuditMetadata::default();
        let audit_error = |error: crate::audit::MetadataError| LabUseCaseError::Backend {
            context: "audit",
            detail: error.to_string(),
        };
        metadata.insert("event", event).map_err(audit_error)?;
        for (key, value) in facts {
            metadata.insert(key, value).map_err(audit_error)?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: Permission::LabArtifacts.id().to_owned(),
                resource: Some(resource.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "audit",
                detail,
            })
    }
}

/// An artifact the principal may not see is reported as not found.
fn scope_artifact(
    principal: &ActingPrincipal,
    artifact: &LabArtifact,
) -> Result<(), LabUseCaseError> {
    if crate::authz::owner_scope_permits(&principal.id, &artifact.owner) {
        Ok(())
    } else {
        Err(LabUseCaseError::NotFound {
            what: format!("artifact {}", artifact.id),
        })
    }
}

/// A lease the principal may not see is reported as not found.
pub(crate) fn scope_lease(
    principal: &ActingPrincipal,
    lease: &fleet_core::Lease,
) -> Result<(), LabUseCaseError> {
    if crate::authz::owner_scope_permits(&principal.id, &lease.owner) {
        Ok(())
    } else {
        Err(LabUseCaseError::NotFound {
            what: format!("lease {}", lease.id),
        })
    }
}

/// Requires a ready, unexpired lease whose guest has a registered Lab
/// machine and endpoint; shared by the requests that act on that guest
/// over SSH (`lab.collect`, `lab.put`). The executors re-check at run time.
///
/// # Errors
///
/// Fails on an unknown lease, a lease that cannot run commands, or a guest
/// with no registered Lab machine.
pub(crate) async fn require_guest_machine(
    leases: &dyn LeasePort,
    provisions: &dyn ProvisionPort,
    principal: &ActingPrincipal,
    lease_id: &str,
    now: i64,
    verb: &str,
) -> Result<fleet_core::Lease, LabUseCaseError> {
    let lease = leases.get(lease_id).await.map_err(|detail| {
        if detail.contains("not found") {
            LabUseCaseError::NotFound {
                what: format!("lease {lease_id}"),
            }
        } else {
            backend(detail)
        }
    })?;
    scope_lease(principal, &lease)?;
    lease_exec_ready(&lease, now).map_err(|detail| LabUseCaseError::Invalid { detail })?;
    let record = match &lease.provision_id {
        Some(id) => Some(provisions.get(id).await.map_err(backend)?),
        None => None,
    };
    if record.as_ref().is_none_or(|record| {
        record.lease_id.as_deref() != Some(lease.id.as_str())
            || record.machine_id.is_none()
            || record.endpoint_id.is_none()
    }) {
        return Err(LabUseCaseError::Invalid {
            detail: format!("the lease's guest has no registered Lab machine to {verb}"),
        });
    }
    Ok(lease)
}

fn allow(
    authorizer: &dyn Authorizer,
    principal: &ActingPrincipal,
    action: Permission,
    resource: Option<&str>,
) -> Result<(), LabUseCaseError> {
    authorize(
        authorizer,
        AccessRequest {
            principal_id: &principal.id,
            action,
            resource,
        },
    )
    .map(|_| ())
    .map_err(LabUseCaseError::Denied)
}

fn backend(detail: String) -> LabUseCaseError {
    LabUseCaseError::Backend {
        context: "artifacts",
        detail,
    }
}

fn blob_refused(error: BlobError) -> LabUseCaseError {
    match error {
        BlobError::TooLarge { .. } => LabUseCaseError::Invalid {
            detail: error.to_string(),
        },
        other => backend(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GuestOs, exec_log_text, is_sha256_hex, validate_collect_paths, validate_collect_paths_for,
        validate_guest_path_for,
    };

    fn paths(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn collect_paths_must_be_absolute_plain_and_bounded() {
        assert!(validate_collect_paths(&paths(&["/var/log/syslog", "/tmp/a b.txt"])).is_ok());
        for bad in [
            vec![],
            paths(&["relative/file"]),
            paths(&["/"]),
            paths(&["/tmp/../etc/shadow"]),
            paths(&["/tmp/./x"]),
            paths(&["/tmp//x"]),
            paths(&["/tmp/x/"]),
            paths(&["/tmp/x\ny"]),
            paths(&["/tmp/x\0"]),
            paths(&["/tmp/x", "/tmp/x"]),
            vec![format!("/{}", "a".repeat(1024))],
            (0..17).map(|n| format!("/tmp/{n}")).collect(),
        ] {
            assert!(
                validate_collect_paths(&bad).is_err(),
                "{bad:?} was accepted"
            );
        }
    }

    fn windows(path: &str) -> Result<(), String> {
        validate_guest_path_for(GuestOs::Windows, path)
    }

    #[test]
    fn windows_paths_are_drive_absolute_and_plain() {
        for good in [
            r"C:\Users\tester\app.exe",
            "C:/Users/tester/app.exe",
            r"d:\a b\c.d.e",
            r"C:\Program Files (x86)\x\y.msi",
            "C:\\Users\\caf\u{e9}\\\u{4e2d}.txt",
            r"C:\x\console.txt",
            r"C:\x\com10.txt",
            r"C:\x\.hidden",
            r"C:\x\a b",
        ] {
            assert!(windows(good).is_ok(), "{good:?}: {:?}", windows(good));
        }
        for bad in [
            "",
            "C:",
            r"C:\",
            "C:/",
            r"C:foo",
            r"C:foo\bar",
            "relative\\file",
            "/unix/path",
            r"\\server\share\file",
            "//server/share/file",
            r"\\?\C:\file",
            r"\\.\C:\file",
            r"\\.\pipe\x",
            r"\Users\x",
            r"C:\a\..\b",
            r"C:\a\.\b",
            r"C:\a\\b",
            r"C:\a//b",
            r"C:\a\b\",
            r"C:\file.txt:stream",
            r"C:\file.txt::$DATA",
            r"C:\a\C:\b",
            r"C:\a\b.",
            r"C:\a\b ",
            r"C:\a \b",
            r"C:\a.\b",
            r"C:\a\b<c",
            r"C:\a\b>c",
            "C:\\a\\b\"c",
            r"C:\a\b|c",
            r"C:\a\b?c",
            r"C:\a\b*c",
            "C:\\a\\b\nc",
            "C:\\a\\b\0",
            "C:\\a\\b\u{7f}",
            r"C:\x\CON",
            r"C:\x\con.txt",
            r"C:\x\NUL",
            r"C:\x\nul.tar.gz",
            r"C:\x\Prn",
            r"C:\x\AUX.log",
            r"C:\x\COM1",
            r"C:\x\com9.txt",
            r"C:\x\LPT1",
            r"C:\x\lpt0.dat",
            "C:\\x\\COM\u{b9}",
            "C:\\x\\lpt\u{b2}.txt",
            r"C:\x\CONIN$",
            r"C:\x\conout$",
            r"C:\x\nul .txt",
            r"C:\CON\file",
            r"C:\x\NUL\file",
        ] {
            assert!(windows(bad).is_err(), "{bad:?} was accepted");
        }
        // Bounds: overall bytes and one component.
        assert!(windows(&format!("C:\\{}", "a".repeat(1024))).is_err());
        assert!(windows(&format!("C:\\{}", "a".repeat(256))).is_err());
        assert!(windows(&format!("C:\\{}", "a".repeat(255))).is_ok());
    }

    #[test]
    fn windows_collections_deduplicate_case_and_separator_insensitively() {
        let check = |items: &[&str]| validate_collect_paths_for(GuestOs::Windows, &paths(items));
        assert!(check(&[r"C:\a\b.txt", r"C:\a\c.txt", r"D:\a\b.txt"]).is_ok());
        for twice in [
            vec![r"C:\a\b.txt", r"C:\a\b.txt"],
            vec![r"C:\a\b.txt", r"c:\A\B.TXT"],
            vec![r"C:\a\b.txt", "C:/a/b.txt"],
            vec!["C:/Users/X/f", r"c:\users\x\F"],
        ] {
            assert!(check(&twice).is_err(), "{twice:?}");
        }
        // Linux stays case-sensitive and separator-exact.
        assert!(validate_collect_paths(&paths(&["/tmp/a", "/tmp/A"])).is_ok());
        // A Windows path is not a Linux path and the reverse.
        assert!(validate_collect_paths(&paths(&[r"C:\a\b"])).is_err());
        assert!(check(&["/tmp/a"]).is_err());
    }

    #[test]
    fn digests_are_lowercase_hex_sha256() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"A".repeat(64)));
        assert!(!is_sha256_hex(&"a".repeat(63)));
        assert!(!is_sha256_hex(&format!("{}g", "a".repeat(63))));
    }

    #[test]
    fn the_exec_log_carries_bounded_output_with_credentials_scrubbed() {
        let log = exec_log_text(
            "op-1",
            "lease-1",
            "failed",
            None,
            Some(
                r#"{"exitCode":2,"stdout":"cloning https://bob:hunter2@git.example.test/x\n","stderr":"oops","truncatedStdout":true,"truncatedStderr":false}"#,
            ),
        )
        .unwrap();
        assert!(log.contains("# exit code: 2"));
        assert!(log.contains("--- stdout (truncated) ---"));
        assert!(log.contains("https://***@git.example.test/x"));
        assert!(!log.contains("hunter2"));
        assert!(log.ends_with("oops\n"));

        let killed = exec_log_text(
            "op-2",
            "lease-1",
            "failed",
            None,
            Some(r#"{"reason":"deadline_killed","partialOutput":{"stdout":"half","stderr":""}}"#),
        )
        .unwrap();
        assert!(killed.contains("# reason: deadline_killed"));
        assert!(killed.contains("half"));

        // A deadline kill records its truncation flags beside its streams.
        let truncated = exec_log_text(
            "op-2",
            "lease-1",
            "failed",
            None,
            Some(
                r#"{"reason":"deadline_killed","partialOutput":{"stdout":"half","stderr":"","truncatedStdout":true,"truncatedStderr":false}}"#,
            ),
        )
        .unwrap();
        assert!(
            truncated.contains("--- stdout (truncated) ---"),
            "{truncated}"
        );
        assert!(truncated.contains("--- stderr ---"), "{truncated}");

        // Refused before anything ran: nothing to keep.
        assert!(
            exec_log_text(
                "op-3",
                "lease-1",
                "failed",
                None,
                Some(r#"{"reason":"lease_not_ready","detail":"expired"}"#),
            )
            .is_none()
        );
    }
}
