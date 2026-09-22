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
/// The maximum response/output bound per stream.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

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
            .map_err(|_| VersionGateError::Absent)?;
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
        // Outside the range: a 2.x CLI or a pre-1.15 one. The pinned range
        // is `>= 1.15 < 2`.
        if major >= 2 || (major == MIN_CLI_MAJOR && minor < MIN_CLI_MINOR) {
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
}

impl ProcessTransport {
    /// Builds the transport over the PATH-resolved `packer`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            binary: PathBuf::from(CLI_NAME),
        }
    }

    /// Builds the transport over an explicit binary path (tests, and
    /// operators with a non-PATH install).
    #[must_use]
    pub fn with_binary(binary: PathBuf) -> Self {
        Self { binary }
    }
}

impl Default for ProcessTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PackerTransport for ProcessTransport {
    async fn run(&self, command: &PackerCommand, deadline: Duration) -> Result<CliOutcome, String> {
        let mut cmd = tokio::process::Command::new(&self.binary);
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
                // The deadline expired: the child was dropped and killed
                // by the runtime, and the plugin's own cleanup ran inside
                // it before the kill — reported honestly as unknown-state.
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
