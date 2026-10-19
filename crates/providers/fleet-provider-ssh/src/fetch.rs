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
use crate::shell::{GuestShell, arguments_only, spawn_script_session};
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

/// The Windows PowerShell twin of [`FETCH_SCRIPT`]; `$args[0]` is the path,
/// `$args[1]` the cap, and the exit codes are the same. The bytes go to the
/// raw standard-output stream, never through the PowerShell pipeline, which
/// would re-encode them. Path shape is checked here too (defence in depth;
/// the application validates first): no UNC/device prefix, wildcard or
/// alternate data stream, and the path must be rooted.
const WINDOWS_FETCH_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$fleetPath = $args[0]
$fleetMaxText = $args[1]
$fleetWindows = [Environment]::OSVersion.Platform -eq 'Win32NT'
if ($fleetMaxText -cnotmatch '^[0-9]{1,19}\z') { exit 64 }
try { $fleetMax = [int64]$fleetMaxText } catch { exit 64 }
if ([string]::IsNullOrEmpty($fleetPath) -or $fleetPath.StartsWith('\\') -or $fleetPath.StartsWith('//') `
    -or $fleetPath.IndexOfAny([char[]]'<>"|?*') -ge 0 -or ($fleetPath.Length -gt 2 -and $fleetPath.IndexOf(':', 2) -ge 0) `
    -or -not [IO.Path]::IsPathRooted($fleetPath) -or ($fleetWindows -and $fleetPath -notmatch '^[A-Za-z]:[\\/]')) { exit 64 }
try { $fleetFull = [IO.Path]::GetFullPath($fleetPath) } catch { exit 64 }
if ($fleetFull.StartsWith('\\')) { exit 64 }
if ([IO.Directory]::Exists($fleetFull)) { exit 65 }
if (-not [IO.File]::Exists($fleetFull)) { exit 66 }
try { $fleetLen = (New-Object IO.FileInfo $fleetFull).Length } catch { exit 70 }
if ($fleetLen -gt $fleetMax) { exit 68 }
try {
  $fleetFs = [IO.File]::Open($fleetFull, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite,Delete')
} catch [UnauthorizedAccessException] { exit 67 } catch [IO.IOException] { exit 67 } catch { exit 70 }
try {
  $fleetOut = [Console]::OpenStandardOutput()
  $fleetBuf = New-Object byte[] 65536
  $fleetTotal = [int64]0
  while ($fleetTotal -le $fleetMax) {
    $fleetWant = [int][Math]::Min([int64]$fleetBuf.Length, $fleetMax + 1 - $fleetTotal)
    $fleetN = $fleetFs.Read($fleetBuf, 0, $fleetWant)
    if ($fleetN -le 0) { break }
    $fleetOut.Write($fleetBuf, 0, $fleetN)
    $fleetTotal += $fleetN
  }
  $fleetOut.Flush()
} catch { exit 70 } finally { $fleetFs.Dispose() }
exit 0
"#;

/// The fetch script for a guest shell.
fn fetch_script_for(shell: GuestShell) -> &'static str {
    match shell {
        GuestShell::Posix => FETCH_SCRIPT,
        GuestShell::PowerShell => WINDOWS_FETCH_SCRIPT,
    }
}

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
        fetch_script_for(GuestShell::for_os(endpoint.guest_os)?),
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

#[cfg(test)]
mod tests {
    use super::WINDOWS_FETCH_SCRIPT;
    use crate::exec::ScriptMetadata;
    use crate::pwsh_support::{require_pwsh, run_ps};

    fn fetch(pwsh: &str, path: &str, max: u64) -> std::process::Output {
        let metadata = ScriptMetadata {
            arguments: vec![path.to_owned(), max.to_string()],
            ..ScriptMetadata::default()
        };
        run_ps(pwsh, WINDOWS_FETCH_SCRIPT, &metadata, b"", None)
    }

    #[test]
    fn windows_fetch_streams_binary_bytes_untouched() {
        let Some(pwsh) = require_pwsh() else { return };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dir with $x & 'q'/f.bin");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Every byte value several times over, CRLF, ^Z, NUL, a UTF-8 BOM, and
        // invalid UTF-8: anything a text pipeline would mangle.
        let mut payload: Vec<u8> = (0..=255_u8).cycle().take(300_000).collect();
        payload.extend_from_slice(b"\r\n\x1a\0\xef\xbb\xbf\xff\xfe\r\n");
        std::fs::write(&path, &payload).unwrap();
        let out = fetch(&pwsh, &path.display().to_string(), 10_000_000);
        assert_eq!(out.status.code(), Some(0), "{:?}", out.stderr);
        assert_eq!(out.stdout, payload);
        // An empty file is a successful, empty copy.
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        let out = fetch(&pwsh, &empty.display().to_string(), 10);
        assert_eq!(out.status.code(), Some(0));
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn windows_fetch_refuses_missing_directories_and_oversize_files_with_the_linux_codes() {
        let Some(pwsh) = require_pwsh() else { return };
        let dir = tempfile::tempdir().unwrap();
        let code = |path: &str, max: u64| fetch(&pwsh, path, max).status.code();
        assert_eq!(
            code(&dir.path().join("nope").display().to_string(), 10),
            Some(66)
        );
        assert_eq!(code(&dir.path().display().to_string(), 10), Some(65));
        let big = dir.path().join("big");
        std::fs::write(&big, vec![0_u8; 100]).unwrap();
        let out = fetch(&pwsh, &big.display().to_string(), 99);
        assert_eq!(out.status.code(), Some(68));
        assert!(out.stdout.is_empty(), "a refused copy writes no bytes");
        assert_eq!(code(&big.display().to_string(), 100), Some(0));
        // A symlink to a regular file is followed, as `stat -L` does.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&big, &link).unwrap();
        assert_eq!(code(&link.display().to_string(), 100), Some(0));
        // Unsafe or relative paths are refused before anything is opened.
        let ads = format!("{}:stream", big.display());
        for bad in [ads.as_str(), "//server/share/f", "relative", "/tmp/a*b"] {
            assert_eq!(code(bad, 100), Some(64), "{bad}");
        }
    }

    #[test]
    fn windows_fetch_of_a_file_exactly_at_the_cap_returns_all_of_it() {
        let Some(pwsh) = require_pwsh() else { return };
        // A file that grew after the size check is cut at cap + 1 so the
        // controller can tell it overflowed; here the size check would refuse
        // it, so the bound is exercised through a cap equal to the size.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, vec![1_u8; 70_000]).unwrap();
        let out = fetch(&pwsh, &file.display().to_string(), 70_000);
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(out.stdout.len(), 70_000);
    }
}
