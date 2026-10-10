//! Bounded file copy into a verified SSH endpoint (#393).
//!
//! Mirrors [`crate::fetch`]: the remote shell parses only `bash -s --` and
//! the shell-inert metadata blob. The guest path, the declared size, the
//! expected SHA-256, and the overwrite flag ride in that blob as `$1..$4`; a
//! fixed script follows on stdin, and the file's raw bytes follow the script.
//! Nothing the caller supplies is parsed by a remote shell, and no file
//! content reaches an argument list, log, or error.
//!
//! The guest side never leaves a partial file at the target: it writes a
//! temporary file in the target's own directory, checks the byte count and
//! `sha256sum` of what arrived, and only then moves it into place. The
//! temporary file is removed on every exit path.
//!
//! Policy for an existing target: refused (`TargetExists`) unless the caller
//! passed `overwrite`, and even then only a regular file is replaced (a
//! directory or symlink is `TargetNotFile`). The target's directory must
//! already exist.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::exec::ExecutionLimiter;
use crate::fetch::{POLL, drain_stderr};
use crate::shell::{GuestShell, arguments_only, spawn_script_session};
use crate::{SshConnectionSpec, SshProvider, SshProviderError};

/// How a copy into the guest ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PutOutcome {
    /// The file is in place and its size and SHA-256 were verified in the guest.
    Put {
        /// How many bytes were sent.
        bytes: u64,
    },
    /// The target exists and overwriting was not requested.
    TargetExists,
    /// The target exists and is not a regular file (or is a symlink).
    TargetNotFile,
    /// The target's directory does not exist.
    NoDirectory,
    /// The remote user cannot create files in the target's directory.
    DirectoryNotWritable,
    /// The bytes that arrived do not match the expected SHA-256.
    HashMismatch,
    /// The byte count that arrived differs from the declared size.
    SizeMismatch,
    /// The target is read-only (Windows); it is not replaced.
    TargetReadOnly,
    /// The guest refused the path or the arguments' shape (for example a
    /// Windows path over the platform's length limit).
    PathRejected,
    /// The local `ssh` process was killed at the deadline.
    DeadlineKilled,
    /// The local source could not be read (shorter than declared, or an I/O
    /// failure); the session was killed.
    SourceFailed {
        /// The source's error.
        detail: String,
    },
    /// The remote copy failed some other way.
    Failed {
        /// The remote exit code, when there was one.
        exit_code: Option<i32>,
    },
}

/// The fixed remote script: `$1` path, `$2` size, `$3` sha256, `$4` `1` to
/// overwrite. The whole body is one function and the call is the last line,
/// so bash has parsed every script line before `head` reads the payload that
/// follows it on stdin.
const PUT_SCRIPT: &str = "fleet_put() {\n\
fleet_path=$1; fleet_size=$2; fleet_sha=$3; fleet_over=$4\n\
fleet_dir=${fleet_path%/*}; [ -n \"$fleet_dir\" ] || fleet_dir=/\n\
[ -d \"$fleet_dir\" ] || exit 69\n\
[ -w \"$fleet_dir\" ] && [ -x \"$fleet_dir\" ] || exit 71\n\
if [ -e \"$fleet_path\" ] || [ -L \"$fleet_path\" ]; then\n\
[ \"$fleet_over\" = 1 ] || exit 73\n\
[ -f \"$fleet_path\" ] && [ ! -L \"$fleet_path\" ] || exit 65\n\
fi\n\
umask 077\n\
fleet_tmp=$(mktemp -p \"$fleet_dir\" .fleet-put.XXXXXXXXXX) || exit 79\n\
trap 'rm -f -- \"$fleet_tmp\"' EXIT\n\
head -c \"$fleet_size\" > \"$fleet_tmp\" || exit 70\n\
fleet_have=$(stat -c %s -- \"$fleet_tmp\") || exit 70\n\
[ \"$fleet_have\" = \"$fleet_size\" ] || exit 76\n\
fleet_actual=$(sha256sum -- \"$fleet_tmp\") || exit 78\n\
[ \"${fleet_actual%% *}\" = \"$fleet_sha\" ] || exit 75\n\
if [ \"$fleet_over\" = 1 ]; then\n\
if [ -L \"$fleet_path\" ] || { [ -e \"$fleet_path\" ] && [ ! -f \"$fleet_path\" ]; }; then exit 65; fi\n\
mv -T -f -- \"$fleet_tmp\" \"$fleet_path\" || exit 77\n\
else\n\
if ! ln -- \"$fleet_tmp\" \"$fleet_path\" 2>/dev/null; then\n\
if [ -e \"$fleet_path\" ] || [ -L \"$fleet_path\" ]; then exit 73; fi\n\
exit 77\n\
fi\n\
fi\n\
exit 0\n\
}\n\
fleet_put \"$@\"; exit $?\n";

/// The Windows PowerShell twin of [`PUT_SCRIPT`]; `$args` are the path, the
/// size, the SHA-256, and `1` to overwrite, with the same exit codes. The
/// payload is read from the raw standard-input stream (right after the two
/// header lines the bootstrap consumed), written to a temporary file in the
/// target's own directory, checked for size and `Get-FileHash`, and only then
/// moved into place: `File.Move` refuses to clobber, and an overwrite uses
/// `File.Replace`. The temporary file is deleted on every path that runs
/// `finally`; if the guest kills the process outright a `.fleet-put.*` file
/// can remain, never a partial target.
const WINDOWS_PUT_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$fleetPath = $args[0]
$fleetSizeText = $args[1]
$fleetSha = $args[2]
$fleetOver = $args[3]
# The application validated all of this; it is checked again here because the
# values are data from a caller. On Windows the path must be drive-absolute
# (the rooted check stands in on other platforms, where the tests run).
$fleetWindows = [Environment]::OSVersion.Platform -eq 'Win32NT'
if ($fleetSizeText -cnotmatch '^[0-9]{1,19}\z' -or $fleetSha -cnotmatch '^[0-9a-f]{64}\z' -or ($fleetOver -ne '0' -and $fleetOver -ne '1')) { exit 64 }
try { $fleetSize = [int64]$fleetSizeText } catch { exit 64 }
if ([string]::IsNullOrEmpty($fleetPath) -or $fleetPath.StartsWith('\\') -or $fleetPath.StartsWith('//') `
    -or $fleetPath.IndexOfAny([char[]]'<>"|?*') -ge 0 -or ($fleetPath.Length -gt 2 -and $fleetPath.IndexOf(':', 2) -ge 0) `
    -or -not [IO.Path]::IsPathRooted($fleetPath) -or ($fleetWindows -and $fleetPath -notmatch '^[A-Za-z]:[\\/]')) { exit 64 }
try { $fleetFull = [IO.Path]::GetFullPath($fleetPath) } catch { exit 64 }
if ($fleetFull.StartsWith('\\')) { exit 64 }
$fleetDir = [IO.Path]::GetDirectoryName($fleetFull)
if ([string]::IsNullOrEmpty($fleetDir) -or -not [IO.Directory]::Exists($fleetDir)) { exit 69 }
$fleetCode = 70
$fleetTmp = $null
$fleetFs = $null
try {
  do {
    if ([IO.File]::Exists($fleetFull) -or [IO.Directory]::Exists($fleetFull)) {
      if ($fleetOver -ne '1') { $fleetCode = 73; break }
      $fleetItem = Get-Item -LiteralPath $fleetFull -Force
      if ($fleetItem.PSIsContainer -or ($fleetItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $fleetCode = 65; break }
      if ($fleetItem.Attributes -band [IO.FileAttributes]::ReadOnly) { $fleetCode = 74; break }
    }
    # Partial files a killed copy left behind, ours by name. The threshold is
    # longer than the longest put deadline (6 hours) plus a margin, so a
    # stalled concurrent put never loses its live temporary file. It runs only
    # after the refusals above, so a refused put touches nothing.
    try {
      foreach ($fleetOld in [IO.Directory]::GetFiles($fleetDir, '.fleet-put.*')) {
        if (([DateTime]::UtcNow - [IO.File]::GetLastWriteTimeUtc($fleetOld)).TotalHours -gt 7) { try { [IO.File]::Delete($fleetOld) } catch { } }
      }
    } catch { }
    # The temporary name adds 44 characters to the directory; keep the whole
    # path inside MAX_PATH instead of failing later as a copy error.
    if ($fleetWindows -and ($fleetDir.Length + 44) -gt 259) { $fleetCode = 64; break }
    $fleetTmp = [IO.Path]::Combine($fleetDir, '.fleet-put.' + [Guid]::NewGuid().ToString('N'))
    try {
      # Read and Delete sharing, no writer: nobody can change the bytes while
      # they are written, hashed and renamed (the handle stays open across the
      # rename, so the bytes that were hashed are the bytes published). File.Replace
      # opens the replacement for read and delete, so it needs both. A
      # same-privilege process could still swap the file through Delete
      # sharing; the directory's ACL is the boundary.
      $fleetFs = New-Object IO.FileStream($fleetTmp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]'Read,Delete', 65536)
    } catch [UnauthorizedAccessException] { $fleetTmp = $null; $fleetCode = 71; break
    } catch [IO.PathTooLongException] { $fleetTmp = $null; $fleetCode = 64; break
    } catch { $fleetTmp = $null; $fleetCode = 79; break }
    try { [IO.File]::SetAttributes($fleetTmp, [IO.FileAttributes]'Hidden,Temporary') } catch { }
    $fleetHasher = [Security.Cryptography.SHA256]::Create()
    $fleetIn = [Console]::OpenStandardInput()
    $fleetBuf = New-Object byte[] 65536
    $fleetLeft = $fleetSize
    $fleetGot = [int64]0
    $fleetIdle = $false
    while ($fleetLeft -gt 0) {
      # A client that disappeared (a deadline kill) leaves this read blocked
      # for ever on a Windows guest: give up after two minutes without data so
      # the temporary file is removed and the process ends.
      $fleetTask = $fleetIn.ReadAsync($fleetBuf, 0, [int][Math]::Min([int64]$fleetBuf.Length, $fleetLeft))
      if (-not $fleetTask.Wait(120000)) { $fleetIdle = $true; break }
      $fleetN = $fleetTask.Result
      if ($fleetN -le 0) { break }
      $fleetFs.Write($fleetBuf, 0, $fleetN)
      # Windows OpenSSH (in-box 9.5) stalls its stdin pipe for a reader that
      # drains it with no pause between reads (a transfer of a few hundred KB
      # never finishes). One millisecond between reads avoids it and still
      # moves tens of MB per second.
      [Threading.Thread]::Sleep(1)
      [void]$fleetHasher.TransformBlock($fleetBuf, 0, $fleetN, $null, 0)
      $fleetLeft -= $fleetN
      $fleetGot += $fleetN
    }
    if ($fleetIdle) { $fleetCode = 70; break }
    [void]$fleetHasher.TransformFinalBlock([byte[]]@(), 0, 0)
    $fleetFs.Flush($true)
    if ($fleetGot -ne $fleetSize) { $fleetCode = 76; break }
    $fleetHave = ([BitConverter]::ToString($fleetHasher.Hash)).Replace('-', '').ToLowerInvariant()
    if ($fleetHave -ne $fleetSha) { $fleetCode = 75; break }
    $fleetReplaced = $false
    if ($fleetOver -eq '1' -and [IO.File]::Exists($fleetFull)) {
      $fleetItem = Get-Item -LiteralPath $fleetFull -Force
      if ($fleetItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { $fleetCode = 65; break }
      if ($fleetItem.Attributes -band [IO.FileAttributes]::ReadOnly) { $fleetCode = 74; break }
      $fleetOldAttr = $fleetItem.Attributes
      # File.Replace opens the replacement itself, so it fails (77) while this
      # handle is open, even with read and delete sharing (seen on the live
      # Windows run). Close it, re-verify what is on disk, then replace.
      $fleetFs.Dispose()
      $fleetFs = $null
      $fleetAgain = (Get-FileHash -LiteralPath $fleetTmp -Algorithm SHA256).Hash.ToLowerInvariant()
      if ($fleetAgain -ne $fleetSha) { $fleetCode = 75; break }
      try { [IO.File]::Replace($fleetTmp, $fleetFull, [NullString]::Value) } catch { $fleetCode = 77; break }
      $fleetReplaced = $true
    } else {
      try { [IO.File]::Move($fleetTmp, $fleetFull) } catch {
        if ([IO.File]::Exists($fleetFull) -or [IO.Directory]::Exists($fleetFull)) { $fleetCode = 73 } else { $fleetCode = 77 }
        break
      }
    }
    if ($null -ne $fleetFs) { $fleetFs.Dispose(); $fleetFs = $null }
    # The published file is not hidden or temporary, and a replaced file keeps
    # its own other attributes except Hidden (it was not read-only) but not the old file's
    # Zone.Identifier stream.
    try {
      $fleetAttr = [IO.FileAttributes]::Normal
      if ($fleetReplaced) { $fleetAttr = $fleetOldAttr -band (-bnot [IO.FileAttributes]'Hidden,Temporary,ReadOnly') }
      if ($fleetAttr -eq 0) { $fleetAttr = [IO.FileAttributes]::Normal }
      [IO.File]::SetAttributes($fleetFull, $fleetAttr)
    } catch { [Console]::Error.WriteLine('fleet: the published file kept its temporary attributes') }
    if ($fleetReplaced -and $fleetWindows) { try { Remove-Item -LiteralPath $fleetFull -Stream Zone.Identifier -ErrorAction Stop } catch { } }
    $fleetCode = 0
  } while ($false)
} catch { $fleetCode = 70 } finally {
  if ($null -ne $fleetFs) { try { $fleetFs.Dispose() } catch { } }
  if ($null -ne $fleetTmp -and [IO.File]::Exists($fleetTmp)) { try { [IO.File]::Delete($fleetTmp) } catch { } }
}
exit $fleetCode
"#;

/// The put script for a guest shell.
fn put_script_for(shell: GuestShell) -> &'static str {
    match shell {
        GuestShell::Posix => PUT_SCRIPT,
        GuestShell::PowerShell => WINDOWS_PUT_SCRIPT,
    }
}

/// How much of the source to read at once.
const WRITE_CHUNK: usize = 64 * 1024;

/// Copies exactly `size` bytes from `source` into the guest file `path`,
/// verifying `sha256` (lowercase hex) there, bounded by `deadline`.
///
/// # Errors
///
/// Fails on setup/tool errors or a connection failure. A refusal by the
/// guest is an outcome, not an error.
pub fn put_file(
    provider: &SshProvider,
    limiter: &ExecutionLimiter,
    endpoint: &SshConnectionSpec,
    request: &PutRequest<'_>,
    deadline: Duration,
    source: &mut (dyn Read + Send),
) -> Result<PutOutcome, SshProviderError> {
    // A busy session pool is waited out (bounded) before any byte is read.
    let waited = Instant::now();
    let wait = (deadline / 4).min(Duration::from_secs(120));
    let mut acquired = limiter.acquire();
    while !acquired && waited.elapsed() < wait {
        std::thread::sleep(Duration::from_millis(250));
        acquired = limiter.acquire();
    }
    if !acquired {
        return Err(SshProviderError::Tool {
            tool: "ssh",
            detail: format!(
                "the concurrency limit ({}) is saturated; no session slot is free",
                limiter.capacity()
            ),
        });
    }
    let result = put_inner(provider, endpoint, request, deadline, source);
    limiter.release();
    result
}

/// What to copy and where.
#[derive(Clone, Copy, Debug)]
pub struct PutRequest<'a> {
    /// The absolute guest path of the target file.
    pub path: &'a str,
    /// The exact size in bytes.
    pub size: u64,
    /// The expected lowercase hex SHA-256.
    pub sha256: &'a str,
    /// Whether an existing regular file may be replaced.
    pub overwrite: bool,
}

fn put_inner(
    provider: &SshProvider,
    endpoint: &SshConnectionSpec,
    request: &PutRequest<'_>,
    deadline: Duration,
    source: &mut (dyn Read + Send),
) -> Result<PutOutcome, SshProviderError> {
    let started = Instant::now();
    let mut child = spawn_script_session(
        provider,
        endpoint,
        &arguments_only(vec![
            request.path.to_owned(),
            request.size.to_string(),
            request.sha256.to_owned(),
            if request.overwrite { "1" } else { "0" }.to_owned(),
        ]),
        put_script_for(GuestShell::for_os(endpoint.guest_os)?),
        deadline,
    )?;
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let source_failed = AtomicBool::new(false);
    let size = request.size;
    let (status, killed, sent, stderr) = std::thread::scope(|scope| {
        let source_failed = &source_failed;
        let writer = scope.spawn(move || {
            let sent = send_payload(stdin, source, size);
            if matches!(&sent, Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe) {
                source_failed.store(true, Ordering::Release);
            }
            sent
        });
        // Nothing is expected on stdout; drain it so the session never blocks.
        let output = scope.spawn(move || drain_stderr(stdout));
        let errors = scope.spawn(move || drain_stderr(stderr));
        let mut killed = false;
        let status = loop {
            if started.elapsed() >= deadline {
                if let Ok(Some(status)) = child.try_wait() {
                    break Some(status);
                }
                killed = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            if source_failed.load(Ordering::Acquire) {
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
        let sent = writer
            .join()
            .unwrap_or_else(|_| Err(std::io::Error::other("the copy thread panicked")));
        let _ = output.join();
        let stderr = errors.join().unwrap_or_default();
        (status, killed, sent, stderr)
    });

    if killed {
        return Ok(PutOutcome::DeadlineKilled);
    }
    if source_failed.load(Ordering::Acquire) {
        return Ok(PutOutcome::SourceFailed {
            detail: sent
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default(),
        });
    }
    let bytes = sent.unwrap_or(0);
    Ok(match status.and_then(|status| status.code()) {
        Some(0) => PutOutcome::Put { bytes },
        Some(64) => PutOutcome::PathRejected,
        Some(65) => PutOutcome::TargetNotFile,
        Some(69) => PutOutcome::NoDirectory,
        Some(71) => PutOutcome::DirectoryNotWritable,
        Some(73) => PutOutcome::TargetExists,
        Some(75) => PutOutcome::HashMismatch,
        Some(74) => PutOutcome::TargetReadOnly,
        Some(76) => PutOutcome::SizeMismatch,
        Some(255) => {
            return Err(SshProviderError::Connect {
                detail: crate::redact_failure(&String::from_utf8_lossy(&stderr)),
            });
        }
        other => PutOutcome::Failed { exit_code: other },
    })
}

/// Streams exactly `size` bytes of `source` into the session, then closes
/// stdin. A shorter source is an error; a remote that exited early (a
/// refusal before it read anything) surfaces as `BrokenPipe`.
fn send_payload(
    stdin: Option<std::process::ChildStdin>,
    source: &mut (dyn Read + Send),
    size: u64,
) -> std::io::Result<u64> {
    let Some(mut stdin) = stdin else {
        return Ok(0);
    };
    let mut chunk = vec![0_u8; WRITE_CHUNK];
    let mut sent: u64 = 0;
    while sent < size {
        let want = usize::try_from((size - sent).min(WRITE_CHUNK as u64)).unwrap_or(WRITE_CHUNK);
        let read = match source.read(&mut chunk[..want]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the staged file is shorter than its recorded size",
                ));
            }
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        stdin.write_all(&chunk[..read])?;
        sent += read as u64;
    }
    stdin.flush()?;
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::PUT_SCRIPT;

    /// Runs the real script under local bash, with the payload after it,
    /// the way the SSH session feeds it.
    fn run(
        dir: &std::path::Path,
        target: &str,
        payload: &[u8],
        sha: &str,
        over: &str,
    ) -> std::process::Output {
        use std::io::Write as _;
        let mut child = std::process::Command::new("bash")
            .arg("-s")
            .arg("--")
            .arg(target)
            .arg(payload.len().to_string())
            .arg(sha)
            .arg(over)
            .current_dir(dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let _ = stdin.write_all(PUT_SCRIPT.as_bytes());
        let _ = stdin.write_all(payload);
        drop(stdin);
        child.wait_with_output().unwrap()
    }

    fn sha(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        sha2::Sha256::digest(bytes)
            .iter()
            .fold(String::new(), |mut text, byte| {
                use std::fmt::Write as _;
                let _ = write!(text, "{byte:02x}");
                text
            })
    }

    #[test]
    fn script_puts_verifies_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("dir with 'quotes' $x");
        std::fs::create_dir(&target).unwrap();
        let path = target.join("file;name").display().to_string();
        let payload = b"line one\nfleet_put \"$@\"\nexit 3\n";
        let out = run(dir.path(), &path, payload, &sha(payload), "0");
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert_eq!(std::fs::read(&path).unwrap(), payload);
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 1);
    }

    #[test]
    fn script_refuses_wrong_hash_without_touching_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin").display().to_string();
        let out = run(dir.path(), &path, b"abc", &sha(b"other"), "0");
        assert_eq!(out.status.code(), Some(75));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn script_overwrite_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        std::fs::write(&path, b"old").unwrap();
        let name = path.display().to_string();
        assert_eq!(
            run(dir.path(), &name, b"new", &sha(b"new"), "0")
                .status
                .code(),
            Some(73)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
        assert_eq!(
            run(dir.path(), &name, b"new", &sha(b"new"), "1")
                .status
                .code(),
            Some(0)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        // A directory or symlink is never replaced.
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let sub_name = sub.display().to_string();
        assert_eq!(
            run(dir.path(), &sub_name, b"x", &sha(b"x"), "1")
                .status
                .code(),
            Some(65)
        );
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let link_name = link.display().to_string();
        assert_eq!(
            run(dir.path(), &link_name, b"x", &sha(b"x"), "1")
                .status
                .code(),
            Some(65)
        );
        assert_eq!(
            run(dir.path(), &link_name, b"x", &sha(b"x"), "0")
                .status
                .code(),
            Some(73)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        // Only the target, the directory, and the link remain.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3);
    }

    #[test]
    fn script_refuses_a_missing_directory_and_a_short_payload() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope/out.bin").display().to_string();
        assert_eq!(
            run(dir.path(), &missing, b"x", &sha(b"x"), "0")
                .status
                .code(),
            Some(69)
        );
        // Declared 4 bytes, sent 2: the size check catches it.
        let path = dir.path().join("short.bin").display().to_string();
        let mut payload = b"ab".to_vec();
        let out = {
            use std::io::Write as _;
            let mut child = std::process::Command::new("bash")
                .args(["-s", "--", &path, "4", &sha(b"abcd"), "0"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(PUT_SCRIPT.as_bytes()).unwrap();
            stdin.write_all(&payload).unwrap();
            drop(stdin);
            payload.clear();
            child.wait_with_output().unwrap()
        };
        assert_eq!(out.status.code(), Some(76));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    mod windows {
        use super::super::WINDOWS_PUT_SCRIPT;
        use super::sha;
        use crate::exec::ScriptMetadata;
        use crate::pwsh_support::{require_pwsh, run_ps};

        fn put(
            pwsh: &str,
            dir: &std::path::Path,
            target: &str,
            payload: &[u8],
            declared: usize,
            sha: &str,
            over: &str,
        ) -> std::process::Output {
            let metadata = ScriptMetadata {
                arguments: vec![
                    target.to_owned(),
                    declared.to_string(),
                    sha.to_owned(),
                    over.to_owned(),
                ],
                ..ScriptMetadata::default()
            };
            run_ps(pwsh, WINDOWS_PUT_SCRIPT, &metadata, payload, Some(dir))
        }

        fn entries(dir: &std::path::Path) -> usize {
            std::fs::read_dir(dir).unwrap().count()
        }

        #[test]
        fn puts_binary_bytes_verifies_and_leaves_no_temp_file() {
            let Some(pwsh) = require_pwsh() else { return };
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("dir with 'quotes' $x & (y)");
            std::fs::create_dir(&target).unwrap();
            let path = target.join("file;name `x`.bin").display().to_string();
            // Every byte value, CRLF, ^Z, NUL, and a PowerShell-looking tail,
            // large enough to cross several read chunks.
            let mut payload: Vec<u8> = (0..=255_u8).cycle().take(3 * 1024 * 1024 + 17).collect();
            payload.extend_from_slice(b"\r\n\x1a\0Write-Output pwned\r\nexit 3\r\n");
            let out = put(
                &pwsh,
                dir.path(),
                &path,
                &payload,
                payload.len(),
                &sha(&payload),
                "0",
            );
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            assert_eq!(std::fs::read(&path).unwrap(), payload);
            assert_eq!(entries(&target), 1);
        }

        #[test]
        fn refuses_a_wrong_hash_or_short_payload_without_touching_the_target() {
            let Some(pwsh) = require_pwsh() else { return };
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("out.bin").display().to_string();
            let out = put(&pwsh, dir.path(), &path, b"abc", 3, &sha(b"other"), "0");
            assert_eq!(out.status.code(), Some(75), "{out:?}");
            assert_eq!(entries(dir.path()), 0);
            // Declared 4 bytes, sent 2.
            let out = put(&pwsh, dir.path(), &path, b"ab", 4, &sha(b"abcd"), "0");
            assert_eq!(out.status.code(), Some(76), "{out:?}");
            assert_eq!(entries(dir.path()), 0);
            // Existing content is not harmed by a refused overwrite.
            std::fs::write(&path, b"old").unwrap();
            let out = put(&pwsh, dir.path(), &path, b"new", 3, &sha(b"zzz"), "1");
            assert_eq!(out.status.code(), Some(75));
            assert_eq!(std::fs::read(&path).unwrap(), b"old");
            assert_eq!(entries(dir.path()), 1);
        }

        #[test]
        fn overwrite_policy_matches_linux() {
            let Some(pwsh) = require_pwsh() else { return };
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("out.bin");
            std::fs::write(&path, b"old").unwrap();
            let name = path.display().to_string();
            let code = |target: &str, payload: &[u8], over: &str| {
                put(
                    &pwsh,
                    dir.path(),
                    target,
                    payload,
                    payload.len(),
                    &sha(payload),
                    over,
                )
                .status
                .code()
            };
            assert_eq!(code(&name, b"new", "0"), Some(73));
            assert_eq!(std::fs::read(&path).unwrap(), b"old");
            assert_eq!(code(&name, b"new", "1"), Some(0));
            assert_eq!(std::fs::read(&path).unwrap(), b"new");
            // A directory or symlink is never replaced.
            let sub = dir.path().join("sub");
            std::fs::create_dir(&sub).unwrap();
            assert_eq!(code(&sub.display().to_string(), b"x", "1"), Some(65));
            assert_eq!(code(&sub.display().to_string(), b"x", "0"), Some(73));
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            let link_name = link.display().to_string();
            assert_eq!(code(&link_name, b"x", "1"), Some(65));
            assert_eq!(code(&link_name, b"x", "0"), Some(73));
            assert_eq!(std::fs::read(&path).unwrap(), b"new");
            assert_eq!(entries(dir.path()), 3);
        }

        #[test]
        fn a_read_only_target_is_refused_and_stale_temp_files_are_swept() {
            let Some(pwsh) = require_pwsh() else { return };
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("out.bin");
            std::fs::write(&path, b"old").unwrap();
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_readonly(true);
            std::fs::set_permissions(&path, perms).unwrap();
            let name = path.display().to_string();
            let out = put(&pwsh, dir.path(), &name, b"new", 3, &sha(b"new"), "1");
            // Unix has no ReadOnly attribute for a root-writable file, so the
            // guard is only observable where the platform reports one.
            if out.status.code() == Some(74) {
                assert_eq!(std::fs::read(&path).unwrap(), b"old");
            }
            // An old `.fleet-put.*` file is removed; a fresh one is left.
            let stale = dir.path().join(".fleet-put.stale");
            let fresh = dir.path().join(".fleet-put.fresh");
            std::fs::write(&stale, b"x").unwrap();
            std::fs::write(&fresh, b"x").unwrap();
            let old = std::time::SystemTime::now() - std::time::Duration::from_hours(8);
            std::fs::File::options()
                .write(true)
                .open(&stale)
                .unwrap()
                .set_modified(old)
                .unwrap();
            let other = dir.path().join("other.bin").display().to_string();
            let out = put(&pwsh, dir.path(), &other, b"z", 1, &sha(b"z"), "0");
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            assert!(!stale.exists() && fresh.exists());
        }

        #[test]
        fn hostile_size_and_hash_arguments_are_refused_before_anything_is_written() {
            let Some(pwsh) = require_pwsh() else { return };
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("f").display().to_string();
            let run = |size: &str, sha_text: &str, over: &str| {
                let metadata = ScriptMetadata {
                    arguments: vec![
                        path.clone(),
                        size.to_owned(),
                        sha_text.to_owned(),
                        over.to_owned(),
                    ],
                    ..ScriptMetadata::default()
                };
                run_ps(&pwsh, WINDOWS_PUT_SCRIPT, &metadata, b"x", Some(dir.path()))
                    .status
                    .code()
            };
            let good = sha(b"x");
            assert_eq!(run("1", &good, "0"), Some(0));
            std::fs::remove_file(&path).unwrap();
            for (size, hash, over) in [
                ("-1", good.as_str(), "0"),
                ("1e3", &good, "0"),
                ("9999999999999999999", &good, "0"),
                ("12345678901234567890", &good, "0"),
                ("0x10", &good, "0"),
                ("1", "ABC", "0"),
                ("1", &good.to_uppercase(), "0"),
                ("1", &good, "yes"),
            ] {
                assert_eq!(run(size, hash, over), Some(64), "{size} {hash} {over}");
            }
            assert_eq!(entries(dir.path()), 0);
        }

        #[test]
        fn the_windows_reader_paces_itself_and_gives_up_on_a_vanished_client() {
            // Live findings: Windows OpenSSH stalls a stdin reader that has no
            // pause between reads, and a killed client leaves the read blocked
            // for ever. Both are properties of the script text; the live run
            // is what proves them (see docs/operations/lab.md).
            assert!(WINDOWS_PUT_SCRIPT.contains("[Threading.Thread]::Sleep(1)"));
            assert!(
                WINDOWS_PUT_SCRIPT.contains("ReadAsync")
                    && WINDOWS_PUT_SCRIPT.contains(".Wait(120000)")
            );
            // File.Replace needs the temporary file closed, and re-verified.
            let replace = WINDOWS_PUT_SCRIPT.find("[IO.File]::Replace").unwrap();
            let close = WINDOWS_PUT_SCRIPT[..replace]
                .rfind("$fleetFs.Dispose()")
                .unwrap();
            let rehash = WINDOWS_PUT_SCRIPT[..replace].rfind("Get-FileHash").unwrap();
            assert!(close < rehash && rehash < replace);
        }

        #[test]
        fn refuses_a_missing_directory_and_unsafe_paths() {
            let Some(pwsh) = require_pwsh() else { return };
            let dir = tempfile::tempdir().unwrap();
            let missing = dir.path().join("nope/out.bin").display().to_string();
            let code = |target: &str| {
                put(&pwsh, dir.path(), target, b"x", 1, &sha(b"x"), "0")
                    .status
                    .code()
            };
            assert_eq!(code(&missing), Some(69));
            // Alternate data streams, wildcards, UNC and relative paths are
            // refused in the guest too, before anything is written.
            let ads = format!("{}:stream", dir.path().join("f").display());
            for bad in [
                ads.as_str(),
                "//server/share/f",
                "relative/path",
                "/tmp/a*b",
                "/tmp/a?b",
            ] {
                assert_eq!(code(bad), Some(64), "{bad}");
            }
            assert_eq!(entries(dir.path()), 0);
        }

        #[test]
        fn a_killed_copy_never_leaves_a_partial_target() {
            use std::io::Write as _;
            let Some(pwsh) = require_pwsh() else { return };
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("out.bin");
            let payload = vec![7_u8; 1024 * 1024];
            let shell = crate::shell::GuestShell::PowerShell;
            let metadata = ScriptMetadata {
                arguments: vec![
                    path.display().to_string(),
                    payload.len().to_string(),
                    sha(&payload),
                    "0".to_owned(),
                ],
                ..ScriptMetadata::default()
            };
            let mut child = std::process::Command::new(&pwsh)
                .args(["-NoProfile", "-NonInteractive", "-Command"])
                .arg(shell.command_line(&metadata))
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let mut stdin = child.stdin.take().unwrap();
            stdin
                .write_all(&shell.session_input(WINDOWS_PUT_SCRIPT, &metadata))
                .unwrap();
            // Half the payload, then the process is killed outright.
            stdin.write_all(&payload[..payload.len() / 2]).unwrap();
            stdin.flush().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1500));
            child.kill().unwrap();
            let _ = child.wait();
            assert!(!path.exists());
            // Only the documented temporary name can be left behind.
            for entry in std::fs::read_dir(dir.path()).unwrap() {
                let name = entry.unwrap().file_name().to_string_lossy().into_owned();
                assert!(name.starts_with(".fleet-put."), "{name}");
            }
        }
    }
}
