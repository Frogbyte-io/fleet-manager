//! Detached commands on a Lab guest (#394): start one so it outlives the
//! SSH session, and read its state later.
//!
//! The transport rule is the one [`crate::exec`] states: **caller data never
//! reaches a remote shell as shell text.** The scripts here are fixed text
//! owned by this crate. The command rides as base64 inside a quoted heredoc
//! (its alphabet cannot contain a shell metacharacter or the heredoc's
//! delimiter), and the handle, the timeout, and the tail window ride in the
//! metadata blob as `$1..$3`. Both are validated again in the guest.
//!
//! # Guest layout
//!
//! One directory per handle, `<base>/<handle>/`, mode 0700, where `<base>` is
//! `/var/lib/fleet-lab/exec` for root and `$HOME/.local/state/fleet-lab/exec`
//! for any other SSH user:
//!
//! - `cmd.sh` the command, run by `bash`; `run.sh` the fixed wrapper.
//! - `pid` (`<pid> <start time>`), `boot_id`, `started`, written by the
//!   wrapper once it runs. `start` returns only after `pid` exists.
//! - `stdout`, `stderr` the command's output.
//! - `exit`, `finished` written last and atomically (temporary file, then
//!   rename). `exit` is the command's exit status; `124` means the
//!   `timeout` bound ended it.
//!
//! The command runs in its own session (`setsid`) with stdio detached, so
//! the SSH session ends as soon as it has started. Like `lab exec`, it
//! starts in the SSH user's login directory. Only coreutils and
//! util-linux are used (`setsid`, `timeout`, `base64`, `tail`, `stat`).
//!
//! # States
//!
//! The status script reports `absent` (no directory), `starting` (directory
//! without a `pid` yet), `running` (`pid` names a live process with the
//! recorded start time and the same boot id), `exited` (`exit` exists), or
//! `lost` with a reason: `guest_rebooted` (boot id differs), `process_gone`
//! (the wrapper died without writing `exit`, for example it was killed),
//! `never_started` (the directory never got a `pid`, or the start gave up
//! and wrote `abandoned`, which makes a late wrapper exit without running).
//! Status reads only regular files, never symlinks, and bounds each read.

use std::time::Duration;

use base64::Engine as _;

use crate::exec::{ExecutionLimiter, ScriptMetadata, execute_script};
use crate::{SshConnectionSpec, SshProvider, SshProviderError};

/// How much of each stream the status script returns, before Fleet scrubs
/// the text and keeps its own last bytes. It is larger than the bytes Fleet
/// keeps so that a credential straddling the cut is scrubbed whole.
pub const TAIL_WINDOW_BYTES: usize = 16 * 1024;

/// How long the start session may take.
pub const SESSION_DEADLINE: Duration = Duration::from_secs(60);

/// How long a status read may take. The guest script bounds each file read
/// with `timeout 5`, so a command that swaps its output for a FIFO cannot
/// hold the session.
pub const STATUS_DEADLINE: Duration = Duration::from_secs(15);

/// The longest handle the guest accepts.
pub const MAX_HANDLE_LEN: usize = 64;

/// Whether `handle` is safe to name a guest directory: 1 to
/// [`MAX_HANDLE_LEN`] characters of `[A-Za-z0-9_-]`.
#[must_use]
pub fn is_valid_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= MAX_HANDLE_LEN
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// The guest-side wrapper (`run.sh`), written verbatim by the start script.
/// `$1` the handle directory, `$2` the timeout in seconds.
const WRAPPER: &str = r#"umask 077
fleet_dir=$1; fleet_secs=$2
[ ! -e "$fleet_dir/abandoned" ] || exit 0
fleet_stat=$(cat /proc/$$/stat) || exit 1
fleet_rest=${fleet_stat##*) }
set -- $fleet_rest
fleet_start=${20}
cat /proc/sys/kernel/random/boot_id > "$fleet_dir/boot_id" 2>/dev/null
date +%s > "$fleet_dir/started"
printf '%s %s\n' "$$" "$fleet_start" > "$fleet_dir/pid.tmp" && mv -f "$fleet_dir/pid.tmp" "$fleet_dir/pid"
timeout -k 10 "$fleet_secs" bash "$fleet_dir/cmd.sh" > "$fleet_dir/stdout" 2> "$fleet_dir/stderr" < /dev/null
fleet_code=$?
date +%s > "$fleet_dir/finished"
printf '%s\n' "$fleet_code" > "$fleet_dir/exit.tmp" && mv -f "$fleet_dir/exit.tmp" "$fleet_dir/exit"
"#;

/// The guest-side shared prologue: validates the handle and resolves the
/// directory. `$1` handle, `$2` number, optional `$3` base directory
/// override (tests only; Fleet never sets it).
const RESOLVE: &str = r#"fleet_handle=$1; fleet_num=$2; fleet_base=${3:-}
case $fleet_handle in ''|*[!A-Za-z0-9_-]*) exit 64;; esac
[ "${#fleet_handle}" -le 64 ] || exit 64
case $fleet_num in ''|*[!0-9]*) exit 64;; esac
if [ -z "$fleet_base" ]; then
  if [ "$(id -u)" = 0 ]; then
    fleet_base=/var/lib/fleet-lab/exec
  else
    [ -n "${HOME:-}" ] || exit 71
    fleet_base=$HOME/.local/state/fleet-lab/exec
  fi
fi
fleet_dir=$fleet_base/$fleet_handle
"#;

const START_BODY: &str = r#"umask 077
mkdir -p -- "$fleet_base" || exit 71
if ! mkdir -- "$fleet_dir" 2>/dev/null; then
  [ -d "$fleet_dir" ] && [ ! -L "$fleet_dir" ] || exit 71
  echo exists
  exit 0
fi
printf '%s' "$fleet_cmd_b64" | base64 -d > "$fleet_dir/cmd.sh" || exit 72
cat > "$fleet_dir/run.sh" <<'FLEET_RUN_END'
"#;

const START_TAIL: &str = r#"FLEET_RUN_END
setsid bash "$fleet_dir/run.sh" "$fleet_dir" "$fleet_num" </dev/null >/dev/null 2>&1 &
fleet_n=0
while [ ! -f "$fleet_dir/pid" ] && [ "$fleet_n" -lt 100 ]; do
  sleep 0.1
  fleet_n=$((fleet_n + 1))
done
[ -f "$fleet_dir/pid" ] || { : > "$fleet_dir/abandoned"; exit 75; }
echo started
exit 0
"#;

/// The script that starts `command` detached. Run it with the metadata
/// arguments `[handle, timeout_seconds]` (see [`start_metadata`]).
///
/// Starting is idempotent: when the handle's directory already exists the
/// script prints `exists` and exits 0 without starting anything, so a
/// retried operation never runs the command twice. Exit codes: 64 invalid
/// handle or timeout, 71 the directory cannot be prepared, 72 the command
/// cannot be written, 75 the wrapper never started.
#[must_use]
pub fn start_script(command: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(command.as_bytes());
    format!(
        "fleet_cmd_b64=$(cat <<'FLEET_CMD_END'\n{encoded}\nFLEET_CMD_END\n)\n{RESOLVE}{START_BODY}{WRAPPER}{START_TAIL}"
    )
}

/// The metadata for [`start_script`].
#[must_use]
pub fn start_metadata(handle: &str, timeout_seconds: u64) -> ScriptMetadata {
    ScriptMetadata {
        working_directory: String::new(),
        environment: Vec::new(),
        arguments: vec![handle.to_owned(), timeout_seconds.to_string()],
    }
}

const STATUS_BODY: &str = r#"[ -d "$fleet_dir" ] && [ ! -L "$fleet_dir" ] || { echo state=absent; exit 0; }
fleet_reg() { [ -f "$1" ] && [ ! -L "$1" ]; }
fleet_alive() {
  local pid start stat rest
  fleet_reg "$fleet_dir/pid" || return 1
  read -r pid start < "$fleet_dir/pid" 2>/dev/null || return 1
  case $pid in ''|*[!0-9]*) return 1;; esac
  stat=$(timeout 5 cat "/proc/$pid/stat" 2>/dev/null) || return 1
  rest=${stat##*) }
  set -- $rest
  [ "$1" != Z ] && [ "${20}" = "$start" ]
}
fleet_state=; fleet_reason=
if fleet_reg "$fleet_dir/exit"; then
  fleet_state=exited
elif fleet_reg "$fleet_dir/pid"; then
  fleet_boot=$(fleet_reg "$fleet_dir/boot_id" && timeout 5 cat "$fleet_dir/boot_id" 2>/dev/null)
  fleet_now=$(timeout 5 cat /proc/sys/kernel/random/boot_id 2>/dev/null)
  if [ "$fleet_boot" != "$fleet_now" ]; then
    fleet_state=lost; fleet_reason=guest_rebooted
  elif fleet_alive; then
    fleet_state=running
  elif fleet_reg "$fleet_dir/exit"; then
    fleet_state=exited
  else
    fleet_state=lost; fleet_reason=process_gone
  fi
elif [ -e "$fleet_dir/abandoned" ]; then
  fleet_state=lost; fleet_reason=never_started
elif [ -n "$(find "$fleet_dir" -maxdepth 0 -mmin -1 2>/dev/null)" ]; then
  fleet_state=starting
else
  fleet_state=lost; fleet_reason=never_started
fi
fleet_num_of() {
  local value
  fleet_reg "$1" || return 0
  value=$(timeout 5 head -c 20 "$1" 2>/dev/null)
  case $value in ''|*[!0-9]*) ;; *) printf '%s' "$value";; esac
}
echo "state=$fleet_state"
[ -z "$fleet_reason" ] || echo "reason=$fleet_reason"
[ "$fleet_state" != exited ] || echo "exit=$(fleet_num_of "$fleet_dir/exit")"
echo "started=$(fleet_num_of "$fleet_dir/started")"
[ "$fleet_state" != exited ] || echo "finished=$(fleet_num_of "$fleet_dir/finished")"
for fleet_stream in stdout stderr; do
  if fleet_reg "$fleet_dir/$fleet_stream"; then
    echo "${fleet_stream}_bytes=$(timeout 5 stat -c %s -- "$fleet_dir/$fleet_stream" 2>/dev/null || echo 0)"
    echo "${fleet_stream}_b64=$(timeout 5 tail -c "$fleet_num" -- "$fleet_dir/$fleet_stream" 2>/dev/null | base64 -w0)"
  else
    echo "${fleet_stream}_bytes=0"
    echo "${fleet_stream}_b64="
  fi
done
exit 0
"#;

/// The script that reads a handle's state. Run it with the metadata
/// arguments `[handle, tail_window_bytes]` (see [`status_metadata`]); it
/// prints `key=value` lines that [`parse_status`] reads. Exit 64 means an
/// invalid handle or number.
#[must_use]
pub fn status_script() -> String {
    format!("{RESOLVE}{STATUS_BODY}")
}

/// The metadata for [`status_script`].
#[must_use]
pub fn status_metadata(handle: &str, tail_window: usize) -> ScriptMetadata {
    ScriptMetadata {
        working_directory: String::new(),
        environment: Vec::new(),
        arguments: vec![handle.to_owned(), tail_window.to_string()],
    }
}

/// What the guest says about one handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestState {
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

/// The status script's answer, before any scrubbing or bounding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestReport {
    /// The state.
    pub state: GuestState,
    /// Why a lost process is lost (`guest_rebooted`, `process_gone`,
    /// `never_started`).
    pub reason: Option<String>,
    /// The exit status, once exited.
    pub exit_code: Option<i32>,
    /// When the wrapper started (guest epoch seconds).
    pub started_at: Option<i64>,
    /// When the command finished (guest epoch seconds).
    pub finished_at: Option<i64>,
    /// The size of stdout in the guest, in bytes.
    pub stdout_bytes: u64,
    /// The size of stderr in the guest, in bytes.
    pub stderr_bytes: u64,
    /// The last bytes of stdout, at most [`TAIL_WINDOW_BYTES`].
    pub stdout_tail: Vec<u8>,
    /// The last bytes of stderr, at most [`TAIL_WINDOW_BYTES`].
    pub stderr_tail: Vec<u8>,
}

/// Parses the status script's output.
///
/// # Errors
///
/// Fails when the output names no known state, or a tail is not base64 or
/// exceeds [`TAIL_WINDOW_BYTES`].
pub fn parse_status(output: &str) -> Result<GuestReport, String> {
    let mut report = GuestReport {
        state: GuestState::Absent,
        reason: None,
        exit_code: None,
        started_at: None,
        finished_at: None,
        stdout_bytes: 0,
        stderr_bytes: 0,
        stdout_tail: Vec::new(),
        stderr_tail: Vec::new(),
    };
    let mut state = None;
    let decode = |value: &str| -> Result<Vec<u8>, String> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .map_err(|_| "a stream tail is not base64".to_owned())?;
        if bytes.len() > TAIL_WINDOW_BYTES {
            return Err("a stream tail is larger than the window".to_owned());
        }
        Ok(bytes)
    };
    for line in output.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "state" => {
                state = Some(match value.trim() {
                    "absent" => GuestState::Absent,
                    "starting" => GuestState::Starting,
                    "running" => GuestState::Running,
                    "exited" => GuestState::Exited,
                    "lost" => GuestState::Lost,
                    other => return Err(format!("the guest reported an unknown state {other:?}")),
                });
            }
            "reason" => {
                report.reason = Some(
                    match value.trim() {
                        reason @ ("guest_rebooted" | "process_gone" | "never_started") => reason,
                        _ => "unknown",
                    }
                    .to_owned(),
                );
            }
            "exit" => report.exit_code = value.trim().parse().ok(),
            "started" => report.started_at = value.trim().parse().ok(),
            "finished" => report.finished_at = value.trim().parse().ok(),
            "stdout_bytes" => report.stdout_bytes = value.trim().parse().unwrap_or(0),
            "stderr_bytes" => report.stderr_bytes = value.trim().parse().unwrap_or(0),
            "stdout_b64" => report.stdout_tail = decode(value)?,
            "stderr_b64" => report.stderr_tail = decode(value)?,
            _ => {}
        }
    }
    report.state = state.ok_or_else(|| "the guest reported no state".to_owned())?;
    Ok(report)
}

/// Reads one handle's state from the guest.
///
/// # Errors
///
/// Fails on setup/tool errors, a connection failure, a deadline kill, a
/// script refusal, or output that does not parse. The error text is safe to
/// log: it names no command output.
pub fn probe_detached(
    provider: &SshProvider,
    limiter: &ExecutionLimiter,
    endpoint: &SshConnectionSpec,
    handle: &str,
) -> Result<GuestReport, SshProviderError> {
    if !is_valid_handle(handle) {
        return Err(SshProviderError::Setup {
            detail: "the handle is not a valid detached-exec handle".to_owned(),
        });
    }
    let result = execute_script(
        provider,
        limiter,
        endpoint,
        &status_script(),
        &status_metadata(handle, TAIL_WINDOW_BYTES),
        STATUS_DEADLINE,
    )?;
    if result.killed_by_deadline {
        return Err(SshProviderError::Tool {
            tool: "ssh",
            detail: "the status read hit its deadline".to_owned(),
        });
    }
    if result.exit_code != Some(0) {
        return Err(SshProviderError::Tool {
            tool: "ssh",
            detail: format!(
                "the status read failed (exit {})",
                result
                    .exit_code
                    .map_or_else(|| "none".to_owned(), |code| code.to_string())
            ),
        });
    }
    parse_status(&result.stdout).map_err(|detail| SshProviderError::Tool {
        tool: "ssh",
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;
    use std::process::{Command, Output, Stdio};
    use std::time::Instant;

    /// Runs a script under real bash the way the SSH session feeds it: the
    /// script on stdin, the metadata arguments after `--`.
    fn bash(script: &str, args: &[&str]) -> Output {
        // The session's directory is the guest base directory (the last
        // argument, when it is one), so a test never writes to the crate.
        let mut command = Command::new("bash");
        if let Some(dir) = args.last().filter(|last| Path::new(last).is_dir()) {
            command.current_dir(dir);
        }
        let mut child = command
            .arg("-s")
            .arg("--")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(script.as_bytes()).unwrap();
        drop(stdin);
        child.wait_with_output().unwrap()
    }

    fn start(base: &Path, handle: &str, secs: u64, command: &str) -> Output {
        bash(
            &start_script(command),
            &[handle, &secs.to_string(), &base.display().to_string()],
        )
    }

    fn status(base: &Path, handle: &str) -> GuestReport {
        let out = bash(
            &status_script(),
            &[
                handle,
                &TAIL_WINDOW_BYTES.to_string(),
                &base.display().to_string(),
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        parse_status(&String::from_utf8(out.stdout).unwrap()).unwrap()
    }

    fn wait_for(base: &Path, handle: &str, state: GuestState) -> GuestReport {
        let started = Instant::now();
        loop {
            let report = status(base, handle);
            if report.state == state {
                return report;
            }
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "waited for {state:?}, last {report:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[test]
    fn handles_are_validated() {
        assert!(is_valid_handle("0199-abc_DEF"));
        for bad in ["", "a/b", "../x", "a b", "a;b", "é", &"x".repeat(65)] {
            assert!(!is_valid_handle(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_command_runs_detached_and_exits_with_its_code_and_output() {
        let base = tempfile::tempdir().unwrap();
        let out = start(
            base.path(),
            "h1",
            60,
            "echo out-line; echo err-line >&2; sleep 1; exit 7",
        );
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "started");
        // The start returned while the command still ran.
        let running = status(base.path(), "h1");
        assert_eq!(running.state, GuestState::Running, "{running:?}");
        assert!(running.exit_code.is_none());
        let exited = wait_for(base.path(), "h1", GuestState::Exited);
        assert_eq!(exited.exit_code, Some(7));
        assert_eq!(exited.stdout_tail, b"out-line\n");
        assert_eq!(exited.stderr_tail, b"err-line\n");
        assert!(exited.started_at.is_some() && exited.finished_at.is_some());
        // The directory is private.
        let mode = std::fs::metadata(base.path().join("h1"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn the_command_starts_where_the_session_started() {
        let base = tempfile::tempdir().unwrap();
        start(base.path(), "cwd1", 60, "pwd -P");
        let exited = wait_for(base.path(), "cwd1", GuestState::Exited);
        let here = base.path().canonicalize().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&exited.stdout_tail).trim(),
            here.display().to_string()
        );
    }

    #[test]
    fn the_command_is_data_never_shell_text_of_the_start_script() {
        let base = tempfile::tempdir().unwrap();
        // Text that would break out of a heredoc, a quote, or a command
        // substitution if it were ever interpolated.
        let command = "cat <<'FLEET_CMD_END'\nFLEET_CMD_END\necho '\"'\"$(touch pwned)`touch pwned2`\"; echo $0; exit 0\n";
        let out = start(base.path(), "h2", 60, command);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let exited = wait_for(base.path(), "h2", GuestState::Exited);
        assert_eq!(exited.exit_code, Some(0));
        let written = std::fs::read_to_string(base.path().join("h2/cmd.sh")).unwrap();
        assert_eq!(written, command, "the command is stored byte for byte");
        let stdout = String::from_utf8_lossy(&exited.stdout_tail).into_owned();
        assert!(stdout.contains("cmd.sh"), "{stdout}");
        // The command itself ran, in the session's directory, and the start
        // script never expanded it.
        assert!(base.path().join("pwned").exists());
        assert!(base.path().join("pwned2").exists());
    }

    #[test]
    fn a_bad_handle_or_number_is_refused_before_anything_is_created() {
        let base = tempfile::tempdir().unwrap();
        for (handle, secs) in [
            ("../escape", "60"),
            ("a b", "60"),
            ("ok", "6x"),
            ("ok", ""),
            ("", "60"),
        ] {
            let out = bash(
                &start_script("true"),
                &[handle, secs, &base.path().display().to_string()],
            );
            assert_eq!(out.status.code(), Some(64), "{handle:?} {secs:?}: {out:?}");
        }
        assert_eq!(std::fs::read_dir(base.path()).unwrap().count(), 0);
        let out = bash(
            &status_script(),
            &["../x", "10", &base.path().display().to_string()],
        );
        assert_eq!(out.status.code(), Some(64));
    }

    #[test]
    fn starting_twice_runs_the_command_once() {
        let base = tempfile::tempdir().unwrap();
        let marker = base.path().join("runs");
        let command = format!("echo x >> {}; sleep 1", marker.display());
        assert_eq!(
            start(base.path(), "h3", 60, &command).status.code(),
            Some(0)
        );
        let again = start(base.path(), "h3", 60, &command);
        assert_eq!(again.status.code(), Some(0));
        assert_eq!(String::from_utf8_lossy(&again.stdout).trim(), "exists");
        wait_for(base.path(), "h3", GuestState::Exited);
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "x\n");
    }

    #[test]
    fn an_unknown_handle_is_absent() {
        let base = tempfile::tempdir().unwrap();
        assert_eq!(status(base.path(), "nothing").state, GuestState::Absent);
    }

    #[test]
    fn the_timeout_ends_the_command_with_124() {
        let base = tempfile::tempdir().unwrap();
        start(base.path(), "h4", 1, "sleep 30");
        let exited = wait_for(base.path(), "h4", GuestState::Exited);
        assert_eq!(exited.exit_code, Some(124));
    }

    #[test]
    fn a_killed_wrapper_is_lost_and_a_reboot_is_lost_too() {
        let base = tempfile::tempdir().unwrap();
        start(base.path(), "h5", 60, "sleep 29.17");
        let pid_text = std::fs::read_to_string(base.path().join("h5/pid")).unwrap();
        let pid = pid_text.split_whitespace().next().unwrap().to_owned();
        // Kill the wrapper and everything under it before it writes `exit`.
        Command::new("kill").args(["-9", &pid]).status().unwrap();
        let lost = wait_for(base.path(), "h5", GuestState::Lost);
        assert_eq!(lost.reason.as_deref(), Some("process_gone"));
        // Kill the orphaned `sleep` too so the test leaves nothing behind.
        let _ = Command::new("pkill").args(["-f", "sleep 29.17"]).status();

        // A different boot id reads as a reboot, even though the pid lives.
        start(base.path(), "h6", 60, "sleep 30");
        std::fs::write(base.path().join("h6/boot_id"), "not-this-boot\n").unwrap();
        let lost = status(base.path(), "h6");
        assert_eq!(lost.state, GuestState::Lost);
        assert_eq!(lost.reason.as_deref(), Some("guest_rebooted"));
        let pid_text = std::fs::read_to_string(base.path().join("h6/pid")).unwrap();
        let pid = pid_text.split_whitespace().next().unwrap().to_owned();
        Command::new("pkill").args(["-P", &pid]).status().unwrap();
        wait_for_exit_file(base.path(), "h6");
    }

    fn wait_for_exit_file(base: &Path, handle: &str) {
        let started = Instant::now();
        while !base.join(handle).join("exit").exists() {
            assert!(started.elapsed() < Duration::from_secs(20));
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[test]
    fn a_command_cannot_hang_status_by_swapping_its_files_for_a_fifo() {
        let base = tempfile::tempdir().unwrap();
        start(base.path(), "f1", 60, "sleep 29.61");
        let dir = base.path().join("f1");
        std::fs::remove_file(dir.join("stdout")).unwrap();
        Command::new("mkfifo")
            .arg(dir.join("stdout"))
            .status()
            .unwrap();
        std::fs::remove_file(dir.join("stderr")).unwrap();
        std::os::unix::fs::symlink("/dev/zero", dir.join("stderr")).unwrap();
        let begun = Instant::now();
        let report = status(base.path(), "f1");
        assert!(
            begun.elapsed() < Duration::from_secs(5),
            "{:?}",
            begun.elapsed()
        );
        assert_eq!(report.state, GuestState::Running);
        assert!(report.stdout_tail.is_empty() && report.stderr_tail.is_empty());
        let pid_text = std::fs::read_to_string(dir.join("pid")).unwrap();
        let pid = pid_text.split_whitespace().next().unwrap();
        Command::new("pkill").args(["-P", pid]).status().unwrap();
    }

    #[test]
    fn an_abandoned_start_never_runs_late() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("ab");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("abandoned"), "").unwrap();
        std::fs::write(dir.join("cmd.sh"), "touch ran\n").unwrap();
        let wrapper = dir.join("run.sh");
        std::fs::write(&wrapper, WRAPPER).unwrap();
        let out = Command::new("bash")
            .arg(&wrapper)
            .arg(&dir)
            .arg("60")
            .current_dir(base.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert!(!dir.join("ran").exists() && !dir.join("pid").exists());
        let lost = status(base.path(), "ab");
        assert_eq!(lost.state, GuestState::Lost);
        assert_eq!(lost.reason.as_deref(), Some("never_started"));
    }

    #[test]
    fn a_reused_pid_is_not_mistaken_for_the_wrapper() {
        let base = tempfile::tempdir().unwrap();
        start(base.path(), "h7", 60, "sleep 30");
        let pid_path = base.path().join("h7/pid");
        let pid_text = std::fs::read_to_string(&pid_path).unwrap();
        let (pid, _) = pid_text.trim().split_once(' ').unwrap();
        // The same pid with another start time is another process.
        std::fs::write(&pid_path, format!("{pid} 1\n")).unwrap();
        let lost = status(base.path(), "h7");
        assert_eq!(lost.state, GuestState::Lost, "{lost:?}");
        std::fs::write(&pid_path, &pid_text).unwrap();
        Command::new("pkill").args(["-P", pid]).status().unwrap();
        wait_for(base.path(), "h7", GuestState::Exited);
    }

    #[test]
    fn a_directory_that_never_got_a_pid_is_starting_then_lost() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("h8");
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(status(base.path(), "h8").state, GuestState::Starting);
        // Age it past the starting grace.
        Command::new("touch")
            .args(["-d", "10 minutes ago"])
            .arg(&dir)
            .status()
            .unwrap();
        let lost = status(base.path(), "h8");
        assert_eq!(lost.state, GuestState::Lost);
        assert_eq!(lost.reason.as_deref(), Some("never_started"));
    }

    #[test]
    fn the_status_returns_a_bounded_tail_and_the_true_size() {
        let base = tempfile::tempdir().unwrap();
        start(
            base.path(),
            "h9",
            60,
            "head -c 100000 /dev/zero | tr '\\0' 'a'; printf 'THE-END'",
        );
        let exited = wait_for(base.path(), "h9", GuestState::Exited);
        assert_eq!(exited.stdout_bytes, 100_007);
        assert_eq!(exited.stdout_tail.len(), TAIL_WINDOW_BYTES);
        assert!(exited.stdout_tail.ends_with(b"THE-END"));
    }

    #[test]
    fn binary_output_survives_the_transport() {
        let base = tempfile::tempdir().unwrap();
        start(
            base.path(),
            "h10",
            60,
            "printf '\\000\\033[1m\\377\\n=x\\n'",
        );
        let exited = wait_for(base.path(), "h10", GuestState::Exited);
        assert_eq!(exited.stdout_tail, b"\0\x1b[1m\xff\n=x\n");
    }

    #[test]
    fn parse_status_refuses_nonsense() {
        assert!(parse_status("").is_err());
        assert!(parse_status("state=maybe\n").is_err());
        assert!(parse_status("state=exited\nstdout_b64=!!!\n").is_err());
        let huge =
            base64::engine::general_purpose::STANDARD.encode(vec![0_u8; TAIL_WINDOW_BYTES + 1]);
        assert!(parse_status(&format!("state=running\nstdout_b64={huge}\n")).is_err());
        let ok = parse_status("state=lost\nreason=anything else\n").unwrap();
        assert_eq!(ok.reason.as_deref(), Some("unknown"));
    }
}
