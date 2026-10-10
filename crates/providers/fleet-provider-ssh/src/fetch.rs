//! Bounded file copy from a verified SSH endpoint (FM-721).
//!
//! The copy rides the same transport as [`crate::execute_script`]: the
//! remote shell parses only `bash -s --` and the shell-inert metadata blob;
//! the guest path and the size cap travel inside that blob as `$1`/`$2`, and
//! a fixed script on stdin checks the path and writes the file's raw bytes
//! to stdout. Nothing the caller supplies is ever parsed by a remote shell.
//!
//! Bounds: the file must be a regular file no larger than the cap when it
//! is checked, and the local reader stops (and kills the session) as soon
//! as more than the cap arrives, so a file that grows mid-copy is refused
//! rather than truncated. The deadline kills the local `ssh` process.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::exec::ExecutionLimiter;
use crate::shell::{arguments_only, spawn_script_session};
use crate::{SshConnectionSpec, SshProvider, SshProviderError};

/// Why the guest refused a file, or how a copy ended without one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FetchOutcome {
    /// The file's bytes were written to the sink.
    Fetched {
        /// How many bytes.
        bytes: u64,
    },
    /// Nothing exists at the path.
    Missing,
    /// The path is not a regular file (a directory, device, or socket).
    NotAFile,
    /// The remote user cannot read the file.
    Unreadable,
    /// The file is larger than the cap.
    TooLarge,
    /// The local `ssh` process was killed at the deadline.
    DeadlineKilled,
    /// The sink refused the bytes (for example, a full disk); the session
    /// was killed at once.
    SinkFailed {
        /// The sink's error.
        detail: String,
    },
    /// The remote copy failed some other way.
    Failed {
        /// The remote exit code, when there was one.
        exit_code: Option<i32>,
    },
}

/// The fixed remote script: `$1` is the path, `$2` the cap in bytes.
/// GNU `stat` and `head` are part of the supported Linux guest baseline.
const FETCH_SCRIPT: &str = "fleet_path=$1\n\
fleet_max=$2\n\
[ -e \"$fleet_path\" ] || exit 66\n\
[ -f \"$fleet_path\" ] || exit 65\n\
[ -r \"$fleet_path\" ] || exit 67\n\
fleet_size=$(stat -L -c %s -- \"$fleet_path\") || exit 70\n\
[ \"$fleet_size\" -le \"$fleet_max\" ] || exit 68\n\
exec head -c \"$((fleet_max + 1))\" -- \"$fleet_path\"\n";

/// How much of a stream to read at once.
const READ_CHUNK: usize = 64 * 1024;

/// How often the deadline is polled while the copy runs.
pub(crate) const POLL: Duration = Duration::from_millis(50);

/// The stderr kept from `ssh` itself, to explain a connection failure.
const STDERR_CAP: usize = 4 * 1024;

/// Copies one guest file's bytes into `sink`, bounded by `max_bytes` and
/// `deadline`. The sink may hold a partial copy whenever the outcome is
/// not [`FetchOutcome::Fetched`]; the caller discards it.
///
/// # Errors
///
/// Fails on setup/tool errors, a connection failure, or a sink write
/// failure. A refusal by the guest is an outcome, not an error.
pub fn fetch_file(
    provider: &SshProvider,
    limiter: &ExecutionLimiter,
    endpoint: &SshConnectionSpec,
    path: &str,
    max_bytes: u64,
    deadline: Duration,
    sink: &mut (dyn Write + Send),
) -> Result<FetchOutcome, SshProviderError> {
    // The remote script compares and adds in Bash's signed 64-bit
    // arithmetic; a larger cap would wrap.
    if max_bytes >= i64::MAX as u64 {
        return Err(SshProviderError::Setup {
            detail: format!("the copy cap {max_bytes} exceeds the supported range"),
        });
    }
    if !limiter.acquire() {
        return Err(SshProviderError::Tool {
            tool: "ssh",
            detail: format!(
                "the concurrency limit ({}) is saturated; no session slot is free",
                limiter.capacity()
            ),
        });
    }
    let result = fetch_inner(provider, endpoint, path, max_bytes, deadline, sink);
    limiter.release();
    result
}

fn fetch_inner(
    provider: &SshProvider,
    endpoint: &SshConnectionSpec,
    path: &str,
    max_bytes: u64,
    deadline: Duration,
    sink: &mut (dyn Write + Send),
) -> Result<FetchOutcome, SshProviderError> {
    let started = Instant::now();
    let mut child = spawn_copy(provider, endpoint, path, max_bytes, deadline)?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let overflow = AtomicBool::new(false);
    let sink_failed = AtomicBool::new(false);
    let (status, killed, copied, stderr) = std::thread::scope(|scope| {
        let overflow = &overflow;
        let sink_failed = &sink_failed;
        let reader = scope.spawn(move || {
            let copied = copy_bounded(stdout, sink, max_bytes, overflow);
            if copied.is_err() {
                sink_failed.store(true, Ordering::Release);
            }
            copied
        });
        let errors = scope.spawn(move || drain_stderr(stderr));
        let mut killed = false;
        let status = loop {
            if started.elapsed() >= deadline {
                // A session that already finished is not a deadline kill.
                if let Ok(Some(status)) = child.try_wait() {
                    break Some(status);
                }
                killed = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            if overflow.load(Ordering::Acquire) {
                let _ = child.kill();
                break child.wait().ok();
            }
            // The sink refused the bytes: nothing drains the pipe any more,
            // so the remote side would block until the deadline holding a
            // session slot. Kill it now.
            if sink_failed.load(Ordering::Acquire) {
                let _ = child.kill();
                break child.wait().ok();
            }
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => std::thread::sleep(POLL),
                Err(_) => {
                    let _ = child.kill();
                    break child.wait().ok();
                }
            }
        };
        let copied = reader
            .join()
            .unwrap_or_else(|_| Err(std::io::Error::other("the copy thread panicked")));
        let stderr = errors.join().unwrap_or_default();
        (status, killed, copied, stderr)
    });

    if killed {
        return Ok(FetchOutcome::DeadlineKilled);
    }
    if overflow.load(Ordering::Acquire) {
        return Ok(FetchOutcome::TooLarge);
    }
    let bytes = match copied {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok(FetchOutcome::SinkFailed {
                detail: error.to_string(),
            });
        }
    };
    outcome_for(status.and_then(|status| status.code()), bytes, &stderr)
}

/// Starts the copy session: the fixed script on stdin, the path and cap in
/// the shell-inert metadata blob.
fn spawn_copy(
    provider: &SshProvider,
    endpoint: &SshConnectionSpec,
    path: &str,
    max_bytes: u64,
    deadline: Duration,
) -> Result<std::process::Child, SshProviderError> {
    let mut child = spawn_script_session(
        provider,
        endpoint,
        &arguments_only(vec![path.to_owned(), max_bytes.to_string()]),
        FETCH_SCRIPT,
        deadline,
    )?;
    // The script is all this session reads: close stdin.
    drop(child.stdin.take());
    Ok(child)
}

/// Maps the remote script's exit code (see [`FETCH_SCRIPT`]) to an outcome;
/// 255 is `ssh`'s own connection failure.
fn outcome_for(
    code: Option<i32>,
    bytes: u64,
    stderr: &[u8],
) -> Result<FetchOutcome, SshProviderError> {
    Ok(match code {
        Some(0) => FetchOutcome::Fetched { bytes },
        Some(65) => FetchOutcome::NotAFile,
        Some(66) => FetchOutcome::Missing,
        Some(67) => FetchOutcome::Unreadable,
        Some(68) => FetchOutcome::TooLarge,
        Some(255) => {
            return Err(SshProviderError::Connect {
                detail: crate::redact_failure(&String::from_utf8_lossy(stderr)),
            });
        }
        other => FetchOutcome::Failed { exit_code: other },
    })
}

/// Copies a pipe into the sink until EOF; sets `overflow` and stops as soon
/// as more than `max_bytes` arrive.
fn copy_bounded<R: Read>(
    pipe: Option<R>,
    sink: &mut (dyn Write + Send),
    max_bytes: u64,
    overflow: &AtomicBool,
) -> std::io::Result<u64> {
    let Some(mut pipe) = pipe else {
        return Ok(0);
    };
    let mut total: u64 = 0;
    let mut chunk = vec![0_u8; READ_CHUNK];
    loop {
        let read = match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            overflow.store(true, Ordering::Release);
            return Ok(total);
        }
        sink.write_all(&chunk[..read])?;
    }
    sink.flush()?;
    Ok(total)
}

/// Drains `ssh`'s stderr, keeping the first [`STDERR_CAP`] bytes.
pub(crate) fn drain_stderr<R: Read>(pipe: Option<R>) -> Vec<u8> {
    let Some(mut pipe) = pipe else {
        return Vec::new();
    };
    let mut kept = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                let room = STDERR_CAP.saturating_sub(kept.len());
                kept.extend_from_slice(&chunk[..read.min(room)]);
            }
        }
    }
    kept
}
