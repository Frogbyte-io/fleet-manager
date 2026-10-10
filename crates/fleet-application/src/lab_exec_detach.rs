//! Detached Lab commands (#394): a command that outlives one exec.
//!
//! `lab exec` is bounded at [`crate::lab::MAX_LAB_EXEC_TIMEOUT_SECONDS`]. A detached
//! command is started by a `lab.exec_detach` operation, which runs it in
//! the guest under a Fleet-owned directory and returns at once. Its handle
//! is the operation's id, so an `Idempotency-Key` retry that returns the
//! same operation returns the same handle. A caller then polls
//! [`LabExecDetach::status`], which reads the guest directly.
//!
//! # Why status is a direct read, not an operation
//!
//! Status changes nothing, is polled often, and its answer is not worth
//! storing. A durable operation per poll would fill the operations table
//! and the worker queue for no benefit. It still passes the same
//! controls: `lab.exec.read` authorization on the handle, owner scope (a
//! handle of another owner is not found), an audit event, and the
//! scrubber and bounds of normal exec output, behind [`GuestExecPort`].
//!
//! # Lifecycle
//!
//! A detached command cannot outlive its lease. Release and TTL expiry
//! destroy or revert the guest, which ends the process, and the wrapper's
//! own bound is the lease's remaining TTL at start (a later `lab extend`
//! does not extend it). Once the lease is no longer `ready`, status answers
//! [`DetachedState::LeaseEnded`] without touching the guest.
//!
//! The command text is never stored here or audited. The record keeps its
//! SHA-256 and size.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::lab::{
    LabUseCaseError, LeasePort, MAX_LAB_EXEC_SCRIPT_BYTES, ProvisionPort, lease_exec_ready,
};
use crate::operation::{AuditPort, NewOperation};

/// The operation kind that starts a detached command.
pub const DETACH_KIND: &str = "lab.exec_detach";

/// The bytes of each stream a status keeps: the same bound as normal exec.
pub const STATUS_TAIL_BYTES: usize = fleet_core::RESULT_STRING_BOUND;

/// The shortest TTL a lease may have left for a command to be started.
pub const MIN_DETACH_SECONDS: u64 = 5;

/// How long a record may stay `starting` before a guest that has no trace
/// of it is called lost: far longer than a queued start plus its session.
pub const START_GRACE_MS: i64 = 15 * 60 * 1000;

/// How the start operation ended, as far as the record knows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartState {
    /// The operation is queued or running.
    Starting,
    /// The operation succeeded: the guest ran the wrapper.
    Started,
    /// The operation failed or was cancelled before the command started.
    Failed,
}

impl StartState {
    /// The stable id stored and served.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Started => "started",
            Self::Failed => "failed",
        }
    }

    /// Parses a stored id.
    ///
    /// # Errors
    ///
    /// Fails on an unknown id.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "starting" => Ok(Self::Starting),
            "started" => Ok(Self::Started),
            "failed" => Ok(Self::Failed),
            other => Err(format!("unknown detached start state {other:?}")),
        }
    }
}

/// The durable record of one detached command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetachedExec {
    /// The handle: the id of the start operation.
    pub handle: String,
    /// The lease it runs on.
    pub lease_id: String,
    /// The lease's owner.
    pub owner: String,
    /// The lowercase hex SHA-256 of the command text.
    pub command_sha256: String,
    /// The size of the command text in bytes.
    pub command_bytes: u64,
    /// The bound the guest enforces, in seconds.
    pub timeout_seconds: u64,
    /// How the start went.
    pub start_state: StartState,
    /// When the record was made (epoch milliseconds).
    pub created_at: i64,
    /// When the start succeeded (epoch milliseconds).
    pub started_at: Option<i64>,
    /// The scrubbed, bounded terminal answer (exited or lost), kept so
    /// later polls do not dial the guest.
    pub final_json: Option<String>,
}

/// Storage for detached-command records.
#[async_trait]
pub trait DetachedExecPort: fmt::Debug + Send + Sync {
    /// Inserts a record unless its handle exists (retries and the executor
    /// both register). Answers whether this call inserted it.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn insert_if_absent(&self, record: &DetachedExec) -> Result<bool, String>;

    /// The record of a handle.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn get(&self, handle: &str) -> Result<Option<DetachedExec>, String>;

    /// Keeps the terminal answer of a handle.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn set_final(&self, handle: &str, final_json: &str) -> Result<(), String>;

    /// Records how the start ended.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn set_start_state(
        &self,
        handle: &str,
        state: StartState,
        started_at: Option<i64>,
    ) -> Result<(), String>;
}

/// What the guest says about a handle (a provider's answer, translated).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestProcessState {
    /// The guest has no directory for the handle.
    Absent,
    /// The directory exists and the wrapper has not recorded its process.
    Starting,
    /// The process is alive.
    Running,
    /// The wrapper wrote an exit status.
    Exited,
    /// The process is gone and wrote no exit status.
    Lost,
}

/// The guest's answer, before any scrubbing or bounding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestProcess {
    /// The state.
    pub state: GuestProcessState,
    /// Why a lost process is lost.
    pub reason: Option<String>,
    /// The exit status, once exited.
    pub exit_code: Option<i32>,
    /// When the command started (guest epoch seconds).
    pub started_at: Option<i64>,
    /// When the command finished (guest epoch seconds).
    pub finished_at: Option<i64>,
    /// The size of stdout in the guest.
    pub stdout_bytes: u64,
    /// The size of stderr in the guest.
    pub stderr_bytes: u64,
    /// The last bytes of stdout the guest returned.
    pub stdout_tail: Vec<u8>,
    /// The last bytes of stderr the guest returned.
    pub stderr_tail: Vec<u8>,
}

/// Reads a detached command's state from the guest.
#[async_trait]
pub trait GuestExecPort: fmt::Debug + Send + Sync {
    /// Reads the handle's state on the machine's endpoint.
    ///
    /// # Errors
    ///
    /// Fails when the guest cannot be reached or does not answer. The
    /// error text must not carry command output.
    async fn probe(
        &self,
        machine_id: &str,
        endpoint_id: &str,
        handle: &str,
    ) -> Result<GuestProcess, String>;
}

/// The state a status answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetachedState {
    /// The start is queued or running; the guest has no trace yet.
    Starting,
    /// The command is running.
    Running,
    /// The command exited; the exit code is set.
    Exited,
    /// The command is gone without an exit code: the guest rebooted, or the
    /// wrapper died. Terminal.
    Lost,
    /// The start operation failed before the command ran. Terminal.
    FailedToStart,
    /// The lease is released, expired, or otherwise no longer ready, so the
    /// guest and the command are gone (or going). Terminal.
    LeaseEnded,
    /// The guest could not be read; retry. Not terminal.
    Unreachable,
}

impl DetachedState {
    /// The stable id served.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Exited => "exited",
            Self::Lost => "lost",
            Self::FailedToStart => "failed_to_start",
            Self::LeaseEnded => "lease_ended",
            Self::Unreachable => "unreachable",
        }
    }

    /// Whether the answer will never change.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Exited | Self::Lost | Self::FailedToStart | Self::LeaseEnded
        )
    }
}

/// One status answer. Output is scrubbed and bounded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetachedStatus {
    /// The handle.
    pub handle: String,
    /// The lease.
    pub lease_id: String,
    /// The state.
    pub state: DetachedState,
    /// The exit code, once exited.
    pub exit_code: Option<i32>,
    /// A stable reason for `lost`, `failed_to_start`, `lease_ended`, or
    /// `unreachable`.
    pub reason: Option<String>,
    /// The lease's state, when the answer is `lease_ended`.
    pub lease_state: Option<String>,
    /// The bound the guest enforces, in seconds.
    pub timeout_seconds: u64,
    /// When the command started (guest clock, epoch seconds).
    pub started_at: Option<i64>,
    /// When the command finished (guest clock, epoch seconds).
    pub finished_at: Option<i64>,
    /// The last of stdout, scrubbed and bounded.
    pub stdout: String,
    /// The last of stderr, scrubbed and bounded.
    pub stderr: String,
    /// Whether output was dropped from stdout.
    pub truncated_stdout: bool,
    /// Whether output was dropped from stderr.
    pub truncated_stderr: bool,
    /// The total size of stdout in the guest, in bytes.
    pub stdout_bytes: u64,
    /// The total size of stderr in the guest, in bytes.
    pub stderr_bytes: u64,
}

/// A start request that passed authorization and every check, ready to
/// queue. [`LabExecDetach::register`] records it once the operation exists.
#[derive(Clone, Debug)]
pub struct PreparedStart {
    /// The operation to queue.
    pub operation: NewOperation,
    /// The lease.
    pub lease_id: String,
    /// The lease's owner.
    pub owner: String,
    /// The command's SHA-256.
    pub command_sha256: String,
    /// The command's size.
    pub command_bytes: u64,
    /// The bound the guest will enforce, in seconds.
    pub timeout_seconds: u64,
}

/// The detached-command use cases.
#[derive(Debug)]
pub struct LabExecDetach {
    records: Arc<dyn DetachedExecPort>,
    guest: Arc<dyn GuestExecPort>,
    leases: Arc<dyn LeasePort>,
    provisions: Arc<dyn ProvisionPort>,
    templates: Arc<dyn crate::lab::LabTemplatePort>,
    audit: Arc<dyn AuditPort>,
    /// When each handle's status read was last audited.
    status_audited: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
}

/// How often one handle's status reads are audited: polling with `--wait`
/// would otherwise write a row every few seconds.
const STATUS_AUDIT_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

impl LabExecDetach {
    /// Composes the use cases.
    #[must_use]
    pub fn new(
        records: Arc<dyn DetachedExecPort>,
        guest: Arc<dyn GuestExecPort>,
        leases: Arc<dyn LeasePort>,
        provisions: Arc<dyn ProvisionPort>,
        templates: Arc<dyn crate::lab::LabTemplatePort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            records,
            guest,
            leases,
            provisions,
            templates,
            audit,
            status_audited: std::sync::Mutex::default(),
        }
    }

    /// Validates a command for a ready lease and answers the
    /// `lab.exec_detach` operation to queue. The bound is the caller's
    /// `timeout_seconds` (default and maximum: what is left of the lease's
    /// TTL), so the command cannot outlive its lease.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown or foreign lease, a lease that is not
    /// ready or is about to expire, a guest without a Lab machine, or an
    /// invalid command.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_start(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        lease_id: &str,
        script: &str,
        timeout_seconds: Option<u64>,
        idempotency_key: Option<&str>,
        now: i64,
    ) -> Result<PreparedStart, LabUseCaseError> {
        allow(authorizer, principal, Permission::LabExec, lease_id)?;
        if script.trim().is_empty() || script.len() > MAX_LAB_EXEC_SCRIPT_BYTES {
            return Err(LabUseCaseError::Invalid {
                detail: format!(
                    "the command must be non-empty and at most {MAX_LAB_EXEC_SCRIPT_BYTES} bytes"
                ),
            });
        }
        if timeout_seconds == Some(0) {
            return Err(LabUseCaseError::Invalid {
                detail: "timeoutSeconds must be at least 1".to_owned(),
            });
        }
        let lease = self.leases.get(lease_id).await.map_err(|detail| {
            if detail.contains("not found") {
                LabUseCaseError::NotFound {
                    what: format!("lease {lease_id}"),
                }
            } else {
                backend("leases", detail)
            }
        })?;
        scope(principal, &lease.owner, || format!("lease {lease_id}"))?;
        lease_exec_ready(&lease, now).map_err(|detail| LabUseCaseError::Invalid { detail })?;
        self.require_machine(&lease).await?;
        // The detached scripts are Bash. A Windows guest must not be handed
        // them (PowerShell would pass them to whatever `bash` it finds).
        let guest_os = self
            .templates
            .get_version(&lease.template_version_id)
            .await
            .map(|version| version.content.guest_os)
            .map_err(|detail| backend("templates", detail))?;
        if guest_os != fleet_core::GuestOs::Linux {
            return Err(LabUseCaseError::Invalid {
                detail: "detached exec is not available on Windows guests yet".to_owned(),
            });
        }
        let remaining = lease.expires_at.map_or(0, |expires| {
            u64::try_from((expires - now) / 1000).unwrap_or(0)
        });
        if remaining < MIN_DETACH_SECONDS {
            return Err(LabUseCaseError::Invalid {
                detail: "the lease is about to expire; a detached command cannot outlive it"
                    .to_owned(),
            });
        }
        let timeout = timeout_seconds.map_or(remaining, |asked| asked.min(remaining));
        let command_sha256 = sha256_hex(script.as_bytes());
        let command_bytes = script.len() as u64;
        // The audit intent precedes the mutation. It records what was
        // asked (size, digest, bound), never the command.
        self.audit(
            principal,
            Permission::LabExec,
            lease_id,
            &[
                ("event", "lab_exec_detach_requested"),
                ("commandSha256", &command_sha256),
                ("commandBytes", &command_bytes.to_string()),
                ("timeoutSeconds", &timeout.to_string()),
            ],
        )
        .await?;
        Ok(PreparedStart {
            operation: NewOperation {
                kind: DETACH_KIND.to_owned(),
                idempotency_key: idempotency_key
                    .map(|key| format!("{}:lab-exec-detach:{lease_id}:{key}", principal.id)),
                deadline_at: None,
                correlation_id: None,
                payload_json: Some(
                    serde_json::json!({
                        "leaseId": lease_id,
                        "script": script,
                        "timeoutSeconds": timeout,
                        "owner": lease.owner,
                        "commandSha256": command_sha256,
                        "commandBytes": command_bytes,
                    })
                    .to_string(),
                ),
                review_token: None,
            },
            lease_id: lease_id.to_owned(),
            owner: lease.owner,
            command_sha256,
            command_bytes,
            timeout_seconds: timeout,
        })
    }

    /// Records the handle of a queued start. Idempotent: a retry that
    /// returned the same operation registers the same handle once.
    ///
    /// # Errors
    ///
    /// Fails when the record cannot be stored.
    pub async fn register(
        &self,
        principal: &ActingPrincipal,
        prepared: &PreparedStart,
        handle: &str,
        now: i64,
    ) -> Result<(), LabUseCaseError> {
        self.audit(
            principal,
            Permission::LabExec,
            &prepared.lease_id,
            &[
                ("event", "lab_exec_detach_registered"),
                ("handle", handle),
                ("commandSha256", &prepared.command_sha256),
            ],
        )
        .await?;
        self.records
            .insert_if_absent(&DetachedExec {
                handle: handle.to_owned(),
                lease_id: prepared.lease_id.clone(),
                owner: prepared.owner.clone(),
                command_sha256: prepared.command_sha256.clone(),
                command_bytes: prepared.command_bytes,
                timeout_seconds: prepared.timeout_seconds,
                start_state: StartState::Starting,
                created_at: now,
                started_at: None,
                final_json: None,
            })
            .await
            .map(|_| ())
            .map_err(|detail| backend("detached records", detail))
    }

    /// The status of a detached command.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown handle or one of another owner (not
    /// found), or a store failure. A guest that cannot be read is an
    /// answer ([`DetachedState::Unreachable`]), not an error.
    #[allow(clippy::too_many_lines)]
    pub async fn status(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        handle: &str,
        now: i64,
    ) -> Result<DetachedStatus, LabUseCaseError> {
        allow(authorizer, principal, Permission::LabExecRead, handle)?;
        let not_found = || LabUseCaseError::NotFound {
            what: format!("detached exec {handle}"),
        };
        if !valid_handle(handle) {
            return Err(not_found());
        }
        let record = self
            .records
            .get(handle)
            .await
            .map_err(|detail| backend("detached records", detail))?
            .ok_or_else(not_found)?;
        scope(principal, &record.owner, || {
            format!("detached exec {handle}")
        })?;
        let due = {
            let mut seen = self
                .status_audited
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let now = std::time::Instant::now();
            seen.retain(|_, at| now.duration_since(*at) < STATUS_AUDIT_EVERY);
            seen.insert(handle.to_owned(), now).is_none()
        };
        if due {
            self.audit(
                principal,
                Permission::LabExecRead,
                handle,
                &[("event", "lab_exec_status_read")],
            )
            .await?;
        }
        let mut status = DetachedStatus {
            handle: record.handle.clone(),
            lease_id: record.lease_id.clone(),
            state: DetachedState::Starting,
            exit_code: None,
            reason: None,
            lease_state: None,
            timeout_seconds: record.timeout_seconds,
            started_at: None,
            finished_at: None,
            stdout: String::new(),
            stderr: String::new(),
            truncated_stdout: false,
            truncated_stderr: false,
            stdout_bytes: 0,
            stderr_bytes: 0,
        };
        let lease = self.leases.get(&record.lease_id).await.map_err(|detail| {
            if detail.contains("not found") {
                not_found()
            } else {
                backend("leases", detail)
            }
        })?;
        // A lease that is not ready is releasing or released (or expired and
        // awaiting its sweep): the guest is gone or going, so the command
        // is too. Say so, instead of dialing a guest that may not exist.
        if lease_exec_ready(&lease, now).is_err() {
            status.state = DetachedState::LeaseEnded;
            status.lease_state = Some(lease.state.id().to_owned());
            status.reason = Some("lease_ended".to_owned());
            return Ok(status);
        }
        if let Some(kept) = record
            .final_json
            .as_deref()
            .and_then(|raw| restore(&status, raw))
        {
            return Ok(kept);
        }
        let failed = record.start_state == StartState::Failed;
        let Some((machine_id, endpoint_id)) = self.machine_of(&lease).await? else {
            if failed {
                status.state = DetachedState::FailedToStart;
                status.reason = Some("start_failed".to_owned());
                return Ok(status);
            }
            status.state = DetachedState::Unreachable;
            status.reason = Some("no_lab_machine".to_owned());
            return Ok(status);
        };
        let process = match self.guest.probe(&machine_id, &endpoint_id, handle).await {
            Ok(process) => process,
            Err(detail) => {
                // The text names a tool failure, never output; it is logged
                // scrubbed and the caller gets a fixed reason.
                eprintln!(
                    "detached exec {handle}: reading the guest failed: {}",
                    fleet_core::scrub_failure_detail(&detail)
                );
                status.state = DetachedState::Unreachable;
                status.reason = Some("guest_unreachable".to_owned());
                return Ok(status);
            }
        };
        apply_process(&mut status, process, &record, now);
        // A start that reported failure may still have started the command
        // (a dropped session, a slow wrapper): the guest decides. Only a
        // guest with no trace of it is `failed_to_start`.
        let no_trace = matches!(status.state, DetachedState::Starting)
            || matches!(
                status.reason.as_deref(),
                Some("guest_has_no_record" | "never_started")
            );
        if failed && no_trace {
            status.state = DetachedState::FailedToStart;
            status.reason = Some("start_failed".to_owned());
            return Ok(status);
        }
        if matches!(status.state, DetachedState::Exited | DetachedState::Lost)
            && let Err(error) = self.records.set_final(handle, &freeze(&status)).await
        {
            eprintln!("detached exec {handle}: terminal answer not kept: {error}");
        }
        Ok(status)
    }

    async fn require_machine(&self, lease: &fleet_core::Lease) -> Result<(), LabUseCaseError> {
        if self.machine_of(lease).await?.is_none() {
            return Err(LabUseCaseError::Invalid {
                detail: "the lease's guest has no registered Lab machine to run on".to_owned(),
            });
        }
        Ok(())
    }

    async fn machine_of(
        &self,
        lease: &fleet_core::Lease,
    ) -> Result<Option<(String, String)>, LabUseCaseError> {
        let Some(provision) = &lease.provision_id else {
            return Ok(None);
        };
        let record = self
            .provisions
            .get(provision)
            .await
            .map_err(|detail| backend("provisions", detail))?;
        if record.lease_id.as_deref() != Some(lease.id.as_str()) {
            return Ok(None);
        }
        Ok(record.machine_id.zip(record.endpoint_id))
    }

    async fn audit(
        &self,
        principal: &ActingPrincipal,
        action: Permission,
        resource: &str,
        facts: &[(&str, &str)],
    ) -> Result<(), LabUseCaseError> {
        let mut metadata = crate::audit::AuditMetadata::default();
        for (key, value) in facts {
            metadata
                .insert(key, value)
                .map_err(|error| backend("audit", error.to_string()))?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: action.id().to_owned(),
                resource: Some(resource.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| backend("audit", detail))
    }
}

/// The terminal answer as stored.
fn freeze(status: &DetachedStatus) -> String {
    serde_json::json!({
        "state": status.state.id(),
        "exitCode": status.exit_code,
        "reason": status.reason,
        "startedAt": status.started_at,
        "finishedAt": status.finished_at,
        "stdout": status.stdout,
        "stderr": status.stderr,
        "truncatedStdout": status.truncated_stdout,
        "truncatedStderr": status.truncated_stderr,
        "stdoutBytes": status.stdout_bytes,
        "stderrBytes": status.stderr_bytes,
    })
    .to_string()
}

/// A stored terminal answer laid over `base`; `None` when it does not read.
fn restore(base: &DetachedStatus, raw: &str) -> Option<DetachedStatus> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let mut status = base.clone();
    status.state = match value["state"].as_str()? {
        "exited" => DetachedState::Exited,
        "lost" => DetachedState::Lost,
        _ => return None,
    };
    status.exit_code = value["exitCode"]
        .as_i64()
        .and_then(|code| i32::try_from(code).ok());
    status.reason = value["reason"].as_str().map(str::to_owned);
    status.started_at = value["startedAt"].as_i64();
    status.finished_at = value["finishedAt"].as_i64();
    value["stdout"].as_str()?.clone_into(&mut status.stdout);
    value["stderr"].as_str()?.clone_into(&mut status.stderr);
    status.truncated_stdout = value["truncatedStdout"].as_bool()?;
    status.truncated_stderr = value["truncatedStderr"].as_bool()?;
    status.stdout_bytes = value["stdoutBytes"].as_u64()?;
    status.stderr_bytes = value["stderrBytes"].as_u64()?;
    Some(status)
}

/// Folds the guest's answer into the status.
fn apply_process(
    status: &mut DetachedStatus,
    process: GuestProcess,
    record: &DetachedExec,
    now: i64,
) {
    status.started_at = process.started_at;
    status.finished_at = process.finished_at;
    status.stdout_bytes = process.stdout_bytes;
    status.stderr_bytes = process.stderr_bytes;
    (status.stdout, status.truncated_stdout) = tail(&process.stdout_tail, process.stdout_bytes);
    (status.stderr, status.truncated_stderr) = tail(&process.stderr_tail, process.stderr_bytes);
    match process.state {
        GuestProcessState::Running => status.state = DetachedState::Running,
        GuestProcessState::Exited => {
            status.state = DetachedState::Exited;
            status.exit_code = process.exit_code;
        }
        GuestProcessState::Lost => {
            status.state = DetachedState::Lost;
            status.reason = Some(process.reason.unwrap_or_else(|| "unknown".to_owned()));
        }
        GuestProcessState::Starting => status.state = DetachedState::Starting,
        GuestProcessState::Absent => {
            if record.start_state == StartState::Starting
                && now - record.created_at < START_GRACE_MS
            {
                status.state = DetachedState::Starting;
            } else {
                // The start succeeded (or was lost for good) but the guest
                // has no directory: it was reverted or replaced.
                status.state = DetachedState::Lost;
                status.reason = Some("guest_has_no_record".to_owned());
            }
        }
    }
}

/// The record the executor registers from a start operation's payload, when
/// the API did not get to (a crash between queueing and registering).
/// `None` when the payload is not a detached start.
#[must_use]
pub fn record_from_payload(handle: &str, payload: &str, now: i64) -> Option<DetachedExec> {
    let payload: serde_json::Value = serde_json::from_str(payload).ok()?;
    Some(DetachedExec {
        handle: handle.to_owned(),
        lease_id: payload["leaseId"].as_str()?.to_owned(),
        owner: payload["owner"].as_str()?.to_owned(),
        command_sha256: payload["commandSha256"].as_str()?.to_owned(),
        command_bytes: payload["commandBytes"].as_u64()?,
        timeout_seconds: payload["timeoutSeconds"].as_u64()?,
        start_state: StartState::Starting,
        created_at: now,
        started_at: None,
        final_json: None,
    })
}

/// The SHA-256 of `bytes`, lowercase hex.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// Whether `handle` can name a guest directory: 1 to 64 characters of
/// `[A-Za-z0-9_-]`. The guest checks it again.
#[must_use]
pub fn valid_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= 64
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// Scrubs and bounds one stream's tail. `total` is the stream's size in the
/// guest: when it exceeds the bytes returned, the front was cut.
fn tail(bytes: &[u8], total: u64) -> (String, bool) {
    fleet_core::scrub_tail(bytes, total > bytes.len() as u64)
}

fn allow(
    authorizer: &dyn Authorizer,
    principal: &ActingPrincipal,
    action: Permission,
    resource: &str,
) -> Result<(), LabUseCaseError> {
    authorize(
        authorizer,
        AccessRequest {
            principal_id: &principal.id,
            action,
            resource: Some(resource),
        },
    )
    .map(|_| ())
    .map_err(LabUseCaseError::Denied)
}

/// A delegated credential sees only its own owner's resources; anything
/// else reads as not found.
fn scope(
    principal: &ActingPrincipal,
    owner: &str,
    what: impl FnOnce() -> String,
) -> Result<(), LabUseCaseError> {
    if crate::authz::owner_scope_permits(&principal.id, owner) {
        Ok(())
    } else {
        Err(LabUseCaseError::NotFound { what: what() })
    }
}

fn backend(context: &'static str, detail: String) -> LabUseCaseError {
    LabUseCaseError::Backend { context, detail }
}
