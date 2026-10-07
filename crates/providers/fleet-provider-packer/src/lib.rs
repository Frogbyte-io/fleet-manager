//! The Packer provider: image builds over the operator-installed `packer`
//! CLI (FM-700; FM-S09).
//!
//! FM-S09 pinned the contract: `packer >= 1.15 < 2`, the plugin
//! `proxmox >= 1.2.4 < 2`, `-machine-readable` output, and the
//! `/api2/json` URL shape. Fleet never bundles the binary (Packer is
//! BUSL 1.1; the operator installs it) and degrades honestly when it is
//! absent.
//!
//! The machine-readable format is a line-oriented
//! `timestamp,target,type,data…` stream on stdout with `%!(PACKER_COMMA)`
//! escaping for commas and `\n`/`\r` escapes for newlines. This crate
//! parses that stream into bounded progress events; it never re-validates
//! Packer's own template fields — `packer validate` is the authority.
//!
//! The binary is never invoked through a shell: every call is an argument
//! array, the recipe file travels as a file path inside a private work
//! directory, and secrets ride `-var-file` resolved just in time — never
//! argv, logs, or audit metadata.
#![warn(missing_docs)]

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;

/// The pinned CLI name.
pub const CLI_NAME: &str = "packer";
/// The minimum supported CLI major version.
pub const MIN_CLI_MAJOR: u64 = 1;
/// The minimum supported CLI minor version.
pub const MIN_CLI_MINOR: u16 = 15;
/// The bound on the head of each output stream. A stoppable run keeps, past
/// it, the last [`OUTPUT_TAIL_BYTES`] joined by a short truncation line, so
/// one stream is at most [`MAX_STREAM_BYTES`]; a plain run keeps the head
/// only.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// The most one stream of a stoppable run can hold: the head, the
/// truncation line, and the tail.
pub const MAX_STREAM_BYTES: usize = MAX_OUTPUT_BYTES + 64 + OUTPUT_TAIL_BYTES;

/// One CLI invocation: an argument array, never a shell string.
#[derive(Clone, Debug)]
pub struct PackerCommand {
    /// The argument array, starting with the subcommand.
    pub args: Vec<String>,
    /// The working directory the command runs in.
    pub work_dir: PathBuf,
}

/// A CLI outcome: bounded stdout/stderr and the exit code.
#[derive(Clone, Debug)]
pub struct CliOutcome {
    /// The bounded stdout.
    pub stdout: String,
    /// The bounded stderr.
    pub stderr: String,
    /// The exit code, when the process ran to completion.
    pub exit_code: Option<i32>,
    /// Whether the deadline killed the process; the remote outcome is
    /// then unknown, not failed.
    pub killed_by_deadline: bool,
}

/// The transport contract: run one CLI command, bounded.
#[async_trait]
pub trait PackerTransport: fmt::Debug + Send + Sync {
    /// Runs one command over the documented CLI contract.
    ///
    /// # Errors
    ///
    /// Fails when the CLI cannot be started at all (absent binary); a
    /// command that runs and fails by its own contract is a
    /// [`CliOutcome`], not an error.
    async fn run(&self, command: &PackerCommand, deadline: Duration) -> Result<CliOutcome, String>;

    /// Runs one command that can be stopped gracefully (#271): when `stop`
    /// turns true, or the deadline passes, the CLI is interrupted the way
    /// Ctrl-C interrupts it, so the Proxmox plugin can remove its
    /// in-progress VM, and is killed only if it outlives [`STOP_GRACE`].
    ///
    /// The default implementation ignores `stop` (scripted transports).
    ///
    /// # Errors
    ///
    /// As [`PackerTransport::run`].
    async fn run_stoppable(
        &self,
        command: &PackerCommand,
        deadline: Duration,
        stop: tokio::sync::watch::Receiver<bool>,
    ) -> Result<StoppableOutcome, String> {
        let _ = stop;
        self.run(command, deadline)
            .await
            .map(|outcome| StoppableOutcome {
                stopped: outcome.killed_by_deadline.then_some(Stopped::Killed),
                cleanly_cancelled: false,
                outcome,
            })
    }
}

/// How long an interrupted CLI may take to clean up before it is killed.
/// The plugin stops and deletes its VM in this window.
pub const STOP_GRACE: Duration = Duration::from_secs(180);

/// How long the output pipes may stay open after the CLI exits (a plugin
/// process still holding them) before the CLI's process group is killed.
pub const PIPE_DRAIN: Duration = Duration::from_secs(5);

/// What Packer prints (`ui,say`) when an interrupt cancelled its builds and
/// their cleanup completed.
pub const CLEAN_CANCEL_MESSAGE: &str = "Cleanly cancelled builds after being interrupted";

/// How a stoppable run was stopped, when it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stopped {
    /// Interrupted, and the CLI exited on its own within the grace period.
    /// That gave the plugin its chance to clean up; whether it did is
    /// [`StoppableOutcome::cleanly_cancelled`], not this.
    Interrupted,
    /// Killed after the grace period (or by a transport without graceful
    /// stop): any remote cleanup is unknown.
    Killed,
}

/// A stoppable run's outcome.
#[derive(Clone, Debug)]
pub struct StoppableOutcome {
    /// What the CLI produced. `killed_by_deadline` is set when the deadline,
    /// rather than a stop request, ended the run.
    pub outcome: CliOutcome,
    /// Whether, and how, the run was stopped early.
    pub stopped: Option<Stopped>,
    /// Whether Packer itself reported that the interrupt cancelled its
    /// builds cleanly ([`CLEAN_CANCEL_MESSAGE`]). The remote host is not
    /// re-checked here.
    pub cleanly_cancelled: bool,
}

/// The CLI's version answer, parsed from the machine-readable stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackerVersion {
    /// The version string, e.g. `1.16.1`.
    pub version: String,
}

/// A version-gate failure: the CLI is absent or outside the pinned range.
#[derive(Debug)]
pub enum VersionGateError {
    /// The binary is not installed. The operator-installed contract
    /// degrades honestly here.
    Absent,
    /// The binary answered but its version is outside the pinned range.
    OutsideRange {
        /// The version the CLI reported.
        reported: String,
        /// The pinned range, as text.
        required: String,
    },
    /// The version answer was not parseable.
    Unparseable {
        /// The bounded detail.
        detail: String,
    },
    /// The binary exists but cannot be started (permissions, broken
    /// install). The operator must repair the install, not install it.
    Unstartable {
        /// The bounded detail.
        detail: String,
    },
}

impl fmt::Display for VersionGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => write!(
                f,
                "the packer CLI is not installed; the operator must install it (pinned packer >= {MIN_CLI_MAJOR}.{MIN_CLI_MINOR} < 2)"
            ),
            Self::OutsideRange { reported, required } => {
                write!(
                    f,
                    "the packer CLI is {reported}, outside the pinned range {required}"
                )
            }
            Self::Unparseable { detail } => {
                write!(
                    f,
                    "the packer CLI's version answer is not parseable: {detail}"
                )
            }
            Self::Unstartable { detail } => {
                write!(f, "the packer CLI cannot be started: {detail}")
            }
        }
    }
}

impl std::error::Error for VersionGateError {}

/// Parses one machine-readable line into `(timestamp, target, type,
/// data…)`, unescaping the documented `%!(PACKER_COMMA)` and `\n`/`\r`
/// forms. Lines that do not parse (e.g. Go log lines on stderr) are
/// skipped, not errors: the format is stdout-only.
#[must_use]
pub fn parse_machine_readable_line(line: &str) -> Option<MachineReadableEvent> {
    let parts: Vec<&str> = line.splitn(4, ',').collect();
    if parts.len() < 3 {
        return None;
    }
    let timestamp: i64 = parts[0].trim().parse().ok()?;
    let target = parts[1].to_owned();
    let event_type = parts[2].to_owned();
    let data = parts.get(3).copied().unwrap_or_default();
    MachineReadableEvent {
        timestamp,
        target,
        event_type,
        data: unescape_data(data),
    }
    .into()
}

/// One machine-readable event, bounded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineReadableEvent {
    /// The Unix timestamp the event was emitted at.
    pub timestamp: i64,
    /// The build target, empty for global events.
    pub target: String,
    /// The event type: `ui`, `artifact`, `version`, …
    pub event_type: String,
    /// The unescaped event data.
    pub data: String,
}

/// Unescapes the documented data forms.
fn unescape_data(data: &str) -> String {
    data.replace("%!(PACKER_COMMA)", ",")
        .replace("\\n", "\n")
        .replace("\\r", "\r")
}

/// The classified summary of one build's machine-readable stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuildStream {
    /// The `ui,say` messages: build-step announcements.
    pub says: Vec<String>,
    /// The `ui,message` messages: progress detail.
    pub messages: Vec<String>,
    /// The `ui,error` messages: failure detail.
    pub errors: Vec<String>,
    /// The artifact entries as `(key, value)` pairs, in order.
    pub artifacts: Vec<(String, String)>,
}

impl BuildStream {
    /// Classifies a bounded machine-readable stream.
    #[must_use]
    pub fn parse(stdout: &str) -> Self {
        let mut stream = Self::default();
        for line in stdout.lines() {
            let Some(event) = parse_machine_readable_line(line) else {
                continue;
            };
            match event.event_type.as_str() {
                "ui" => {
                    let subtype = event.data.split(',').next().unwrap_or_default();
                    match subtype {
                        "say" => stream.says.push(rest_of(&event.data)),
                        "message" => stream.messages.push(rest_of(&event.data)),
                        "error" => stream.errors.push(rest_of(&event.data)),
                        _ => {}
                    }
                }
                "artifact" => {
                    // `target,artifact,index,key,value`
                    let parts: Vec<&str> = event.data.splitn(3, ',').collect();
                    if parts.len() == 3 {
                        stream
                            .artifacts
                            .push((parts[1].to_owned(), parts[2].to_owned()));
                    }
                }
                _ => {}
            }
        }
        stream
    }

    /// The artifact's id, when the build produced one.
    #[must_use]
    pub fn artifact_id(&self) -> Option<&str> {
        self.artifacts
            .iter()
            .find(|(key, _)| key == "id")
            .map(|(_, value)| value.as_str())
    }
}

/// The data after the first `subtype,` segment.
fn rest_of(data: &str) -> String {
    data.split_once(',')
        .map(|(_, rest)| rest)
        .unwrap_or_default()
        .chars()
        .take(512)
        .collect()
}

/// The client over the transport: version gate, validate, and build.
pub struct PackerClient {
    transport: std::sync::Arc<dyn PackerTransport>,
}

impl fmt::Debug for PackerClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackerClient")
            .field("transport", &self.transport)
            .finish()
    }
}

impl PackerClient {
    /// Composes the client over a transport.
    #[must_use]
    pub fn new(transport: std::sync::Arc<dyn PackerTransport>) -> Self {
        Self { transport }
    }

    /// Runs the version gate: the CLI must be installed and inside the
    /// pinned range.
    ///
    /// # Errors
    ///
    /// Fails with [`VersionGateError`] when absent, outside the range, or
    /// unparseable.
    pub async fn version(&self, work_dir: PathBuf) -> Result<PackerVersion, VersionGateError> {
        let outcome = self
            .transport
            .run(
                &PackerCommand {
                    args: vec!["-machine-readable".to_owned(), "version".to_owned()],
                    work_dir,
                },
                Duration::from_secs(30),
            )
            .await
            .map_err(|detail| {
                // A spawn failure is preserved: "absent" and "unstartable"
                // are different operator actions.
                if detail.contains("cannot be started") {
                    // The transport's own wording distinguishes an absent
                    // binary (PATH lookup failed) from a broken install.
                    if detail.contains("No such file or directory") || detail.contains("not found")
                    {
                        VersionGateError::Absent
                    } else {
                        VersionGateError::Unstartable { detail }
                    }
                } else {
                    VersionGateError::Unstartable { detail }
                }
            })?;
        if outcome.exit_code.is_none() && outcome.killed_by_deadline {
            return Err(VersionGateError::Unparseable {
                detail: "the version call was killed at its deadline".to_owned(),
            });
        }
        let stream = BuildStream::parse(&outcome.stdout);
        let version = stream
            .messages
            .first()
            .cloned()
            .or_else(|| {
                // The machine-readable `version` event rides the raw
                // stream; parse it directly.
                outcome.stdout.lines().find_map(|line| {
                    let event = parse_machine_readable_line(line)?;
                    (event.event_type == "version").then_some(event.data)
                })
            })
            .ok_or_else(|| VersionGateError::Unparseable {
                detail: "the version stream carried no version".to_owned(),
            })?;
        let (major, minor) =
            parse_version(&version).ok_or_else(|| VersionGateError::Unparseable {
                detail: format!("the version {version:?} is not semver-shaped"),
            })?;
        // Outside the range: any major other than 1, or a pre-1.15 one.
        // The pinned range is `>= 1.15 < 2`.
        if !(major == MIN_CLI_MAJOR && minor >= MIN_CLI_MINOR) {
            return Err(VersionGateError::OutsideRange {
                reported: version,
                required: format!(">= {MIN_CLI_MAJOR}.{MIN_CLI_MINOR} < 2"),
            });
        }
        Ok(PackerVersion { version })
    }
}

/// Parses `major.minor.patch` into `(major, minor)`.
fn parse_version(version: &str) -> Option<(u64, u16)> {
    let mut parts = version.split('.');
    let major: u64 = parts.next()?.trim().parse().ok()?;
    let minor: u16 = parts.next()?.trim().parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_readable_lines_parse_and_unescape() {
        let event = parse_machine_readable_line("1790065165,,version,1.16.1").expect("parses");
        assert_eq!(event.event_type, "version");
        assert_eq!(event.data, "1.16.1");

        let event = parse_machine_readable_line(
            "1790065165,build,ui,say,step one%!(PACKER_COMMA) step two\\nnext",
        )
        .expect("parses");
        assert_eq!(event.target, "build");
        // The ui subtype rides the data segment; BuildStream::parse
        // strips it.
        assert_eq!(event.data, "say,step one, step two\nnext");

        // Non-format lines (Go logs) are skipped.
        assert!(parse_machine_readable_line("2026/09/22 08:22:46 [TRACE] …").is_none());
        assert!(parse_machine_readable_line("").is_none());
    }

    #[test]
    fn build_streams_classify_and_extract_artifacts() {
        let stdout = "\
1790065165,,ui,say,==> build started
1790065165,proxmox-clone.test,artifact-count,1
1790065165,proxmox-clone.test,artifact,0,builder-id,proxmox
1790065165,proxmox-clone.test,artifact,0,id,pve:102
1790065165,proxmox-clone.test,artifact,0,end
1790065165,,ui,error,build failed";
        let stream = BuildStream::parse(stdout);
        assert_eq!(stream.says, vec!["==> build started".to_owned()]);
        assert_eq!(stream.errors, vec!["build failed".to_owned()]);
        assert_eq!(stream.artifact_id(), Some("pve:102"));
    }

    #[test]
    fn versions_parse_semver_shapes() {
        assert_eq!(parse_version("1.16.1"), Some((1, 16)));
        assert_eq!(parse_version("1.15"), Some((1, 15)));
        assert_eq!(parse_version("abc"), None);
    }
}

/// The real transport: the operator-installed `packer` binary, run as an
/// argument array with bounded output and deadline kills reported
/// honestly.
#[derive(Debug)]
pub struct ProcessTransport {
    /// The binary path; the default is the PATH lookup for `packer`.
    binary: PathBuf,
    /// How long an interrupted CLI may clean up before it is killed.
    stop_grace: Duration,
}

impl ProcessTransport {
    /// Builds the transport over the PATH-resolved `packer`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            binary: PathBuf::from(CLI_NAME),
            stop_grace: STOP_GRACE,
        }
    }

    /// Builds the transport over an explicit binary path (tests, and
    /// operators with a non-PATH install).
    #[must_use]
    pub fn with_binary(binary: PathBuf) -> Self {
        Self {
            binary,
            stop_grace: STOP_GRACE,
        }
    }

    /// Overrides the cleanup grace period after an interrupt (tests).
    #[must_use]
    pub fn with_stop_grace(mut self, stop_grace: Duration) -> Self {
        self.stop_grace = stop_grace;
        self
    }
}

impl Default for ProcessTransport {
    fn default() -> Self {
        Self::new()
    }
}

/// Waits until the stop flag is true; never returns when its sender is gone
/// while the flag is still false.
async fn stop_requested(stop: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *stop.borrow_and_update() {
            return;
        }
        if stop.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Sends `signal` to the CLI's whole process group (the CLI and its plugin
/// processes), as a terminal's Ctrl-C does. Best effort.
#[cfg(unix)]
async fn signal_group(pgid: u32, signal: &str) {
    let _ = tokio::process::Command::new("kill")
        .arg(format!("-{signal}"))
        .arg("--")
        .arg(format!("-{pgid}"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
}

/// How much of the end of an over-limit stream is kept: Packer reports its
/// final outcome (including [`CLEAN_CANCEL_MESSAGE`]) last.
pub const OUTPUT_TAIL_BYTES: usize = 64 * 1024;

/// Drains one pipe to its end, so a verbose CLI never blocks on a full
/// pipe, keeping the first [`MAX_OUTPUT_BYTES`] and, past that, the last
/// [`OUTPUT_TAIL_BYTES`] joined by a truncation line. Memory stays bounded.
async fn read_bounded<R: tokio::io::AsyncRead + Unpin>(pipe: Option<R>) -> String {
    use tokio::io::AsyncReadExt as _;
    let mut head = Vec::new();
    let mut tail: std::collections::VecDeque<u8> = std::collections::VecDeque::new();
    let mut truncated = false;
    if let Some(mut pipe) = pipe {
        let mut chunk = [0_u8; 8192];
        while let Ok(read) = pipe.read(&mut chunk).await {
            if read == 0 {
                break;
            }
            let room = MAX_OUTPUT_BYTES.saturating_sub(head.len());
            head.extend_from_slice(&chunk[..read.min(room)]);
            if read > room {
                truncated = true;
                tail.extend(&chunk[room..read]);
                while tail.len() > OUTPUT_TAIL_BYTES {
                    tail.pop_front();
                }
            }
        }
    }
    let mut text = String::from_utf8_lossy(&head).into_owned();
    if truncated {
        let tail: Vec<u8> = tail.into_iter().collect();
        text.push_str("\n[... output truncated ...]\n");
        text.push_str(&String::from_utf8_lossy(&tail));
    }
    text
}

#[async_trait]
impl PackerTransport for ProcessTransport {
    #[cfg(unix)]
    async fn run_stoppable(
        &self,
        command: &PackerCommand,
        deadline: Duration,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) -> Result<StoppableOutcome, String> {
        let mut cmd = tokio::process::Command::new(&self.binary);
        cmd.kill_on_drop(true)
            // Its own process group, so an interrupt reaches the plugin
            // processes too, exactly as Ctrl-C would.
            .process_group(0)
            .args(&command.args)
            .current_dir(&command.work_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null());
        let mut child = cmd
            .spawn()
            .map_err(|error| format!("the packer CLI cannot be started: {error}"))?;
        let pgid = child
            .id()
            .ok_or("the packer CLI exited before it could be tracked")?;
        let stdout = tokio::spawn(read_bounded(child.stdout.take()));
        let stderr = tokio::spawn(read_bounded(child.stderr.take()));
        let deadline_sleep = tokio::time::sleep(deadline);
        tokio::pin!(deadline_sleep);
        // `Some(true)`: the deadline ended the run; `Some(false)`: a stop
        // request did. An exit that is ready at the same moment wins: a
        // finished build is never reported as interrupted.
        let (mut status, mut by_deadline) = tokio::select! {
            biased;
            status = child.wait() => (status.ok(), None),
            () = &mut deadline_sleep => (None, Some(true)),
            () = stop_requested(&mut stop) => (None, Some(false)),
        };
        if by_deadline.is_some()
            && let Ok(Some(exit)) = child.try_wait()
        {
            status = Some(exit);
            by_deadline = None;
        }
        let mut stopped = None;
        if by_deadline.is_some() {
            signal_group(pgid, "INT").await;
            if let Ok(Ok(exit)) = tokio::time::timeout(self.stop_grace, child.wait()).await {
                status = Some(exit);
                stopped = Some(Stopped::Interrupted);
            } else {
                signal_group(pgid, "KILL").await;
                let _ = child.kill().await;
                stopped = Some(Stopped::Killed);
            }
        }
        // A plugin process that outlives the CLI can hold the pipes open:
        // give the readers a moment, then kill whatever is left of the group
        // so the reads end.
        let mut readers = tokio::spawn(async move {
            (
                stdout.await.unwrap_or_default(),
                stderr.await.unwrap_or_default(),
            )
        });
        let (stdout, stderr) =
            if let Ok(output) = tokio::time::timeout(PIPE_DRAIN, &mut readers).await {
                output.unwrap_or_default()
            } else {
                signal_group(pgid, "KILL").await;
                tokio::time::timeout(PIPE_DRAIN, readers)
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or_default()
            };
        let cleanly_cancelled =
            stopped == Some(Stopped::Interrupted) && stdout.contains(CLEAN_CANCEL_MESSAGE);
        Ok(StoppableOutcome {
            cleanly_cancelled,
            outcome: CliOutcome {
                stdout,
                stderr,
                exit_code: if stopped == Some(Stopped::Killed) {
                    None
                } else {
                    status.and_then(|exit| exit.code())
                },
                killed_by_deadline: by_deadline == Some(true),
            },
            stopped,
        })
    }

    async fn run(&self, command: &PackerCommand, deadline: Duration) -> Result<CliOutcome, String> {
        let mut cmd = tokio::process::Command::new(&self.binary);
        // kill_on_drop: a deadline kill must actually kill the packer
        // process, not orphan it while the caller records the kill.
        cmd.kill_on_drop(true);
        cmd.args(&command.args)
            .current_dir(&command.work_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null());
        let child = cmd
            .spawn()
            .map_err(|error| format!("the packer CLI cannot be started: {error}"))?;
        match tokio::time::timeout(deadline, child.wait_with_output()).await {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                Ok(CliOutcome {
                    stdout: stdout.chars().take(MAX_OUTPUT_BYTES).collect(),
                    stderr: stderr.chars().take(MAX_OUTPUT_BYTES).collect(),
                    exit_code: output.status.code(),
                    killed_by_deadline: false,
                })
            }
            Ok(Err(error)) => Err(format!("the packer CLI failed: {error}")),
            Err(_) => {
                // The deadline expired and the process was killed: the
                // remote outcome is unknown. The plugin's cleanup cannot
                // be assumed from a kill — the caller must verify host
                // state, and this outcome says so.
                Ok(CliOutcome {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: None,
                    killed_by_deadline: true,
                })
            }
        }
    }
}
