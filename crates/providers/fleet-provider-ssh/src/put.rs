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
use crate::shell::{arguments_only, spawn_script_session};
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
        PUT_SCRIPT,
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
        Some(65) => PutOutcome::TargetNotFile,
        Some(69) => PutOutcome::NoDirectory,
        Some(71) => PutOutcome::DirectoryNotWritable,
        Some(73) => PutOutcome::TargetExists,
        Some(75) => PutOutcome::HashMismatch,
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
}
