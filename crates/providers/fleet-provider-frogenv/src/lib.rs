//! The Frogenv provider (FM-303): a machine-readable CLI contract over
//! `frogenv`, never the upstream private files.
//!
//! Fleet invokes Frogenv's public CLI and records status — it never
//! decrypts, lists, or stores environment values, and never edits
//! `frogenv.yaml`, `.sops.yaml`, `keys/`, its local config, or encrypted
//! files. Only `frogenv status` is documented JSON today; the other
//! commands are human text and are never parsed into facts — they degrade
//! honestly to `unknown`. The upstream gaps (`--json` for check/machine
//! list/request/sync, non-interactive error codes, a valueless listing
//! command) are documented for contribution in the research ledger, not
//! worked around by reading private files.
//!
//! Redaction is structural: age keys, SOPS payloads, and credential-shaped
//! tokens are scrubbed from any decoded value before it becomes an
//! observation, a public result, or an audit detail.
#![warn(missing_docs)]

use std::fmt;
use std::time::Duration;

use serde::Deserialize;

/// The documented CLI binary name. Fixed: Fleet never guesses an alias.
pub const CLI_NAME: &str = "frogenv";

/// What observed the facts: a probe name and version, recorded on every
/// observation.
pub const PROBE_SOURCE: &str = "frogenv-cli";

/// How long one CLI command may run before the deadline kills it.
pub const COMMAND_DEADLINE: Duration = Duration::from_secs(60);

/// The bound for one decoded JSON document.
pub const MAX_DOCUMENT_BYTES: usize = 256 * 1024;

/// One command invocation over the CLI contract.
#[derive(Clone, Debug)]
pub struct CliCommand {
    /// The subcommand, e.g. `["status"]`.
    pub arguments: Vec<String>,
}

impl CliCommand {
    /// A command with fixed subcommand words.
    #[must_use]
    pub fn new(arguments: &[&str]) -> Self {
        Self {
            arguments: arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
        }
    }

    /// The full argument array: the fixed binary name plus the
    /// subcommand words, verbatim. Fleet never adds flags the CLI has not
    /// documented for a command.
    #[must_use]
    pub fn argv(&self) -> Vec<String> {
        let mut argv = vec![CLI_NAME.to_owned()];
        argv.extend(self.arguments.iter().cloned());
        argv
    }
}

impl fmt::Display for CliCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.argv().join(" "))
    }
}

/// The outcome of one CLI invocation.
#[derive(Clone, Debug)]
pub struct CliOutcome {
    /// The process exit code, when the process survived the deadline.
    pub exit_code: Option<i32>,
    /// The capped stdout.
    pub stdout: String,
    /// The capped stderr.
    pub stderr: String,
    /// Whether the deadline killed the invocation; the remote state is
    /// unknown and callers must not claim success.
    pub killed_by_deadline: bool,
}

impl CliOutcome {
    /// Whether the invocation succeeded by the CLI's own contract: exit 0.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// The transport contract: run one CLI command, bounded.
#[async_trait::async_trait]
pub trait CliTransport: fmt::Debug + Send + Sync {
    /// Runs one command over the CLI contract.
    ///
    /// # Errors
    ///
    /// Fails when the CLI cannot be started at all (absent binary); a
    /// command that runs and fails by its own contract is an
    /// [`CliOutcome`], not an error.
    async fn run(&self, command: &CliCommand, deadline: Duration) -> Result<CliOutcome, String>;
}

/// The CLI's `status` document: configuration and machine registration
/// fields, as documented. Field presence is the contract; a missing field
/// is a shape change, not an empty answer.
#[derive(Debug, Deserialize)]
pub struct StatusDocument {
    /// Whether Frogenv is configured on this machine.
    pub configured: bool,
    /// The machine's Frogenv registration state, when the document
    /// carries one.
    #[serde(default, alias = "machineState")]
    pub machine_state: Option<String>,
    /// The machine's Frogenv id, when registered. Metadata only: Fleet's
    /// machine id is a different identity and the two are mapped, never
    /// equated.
    #[serde(default, alias = "machineId")]
    pub machine_id: Option<String>,
    /// The configured Git transport remote, when the document carries
    /// one. Redacted before it is exposed: a remote can carry credentials.
    #[serde(default, alias = "remote", alias = "gitRemote")]
    pub git_remote: Option<String>,
}

/// A parsed probe result: what the CLI answered, degraded honestly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Probe {
    /// The CLI answered: its version.
    Present {
        /// The CLI's reported version.
        version: String,
    },
    /// The CLI is absent: the machine answered, the tool is not there.
    Absent,
    /// The CLI answered but not in the documented shape: an upgrade
    /// Fleet has not been taught.
    Unsupported,
}

/// Probes the CLI's presence and version over the transport.
///
/// # Errors
///
/// Fails on transport errors; an absent or shape-changed CLI is an
/// answer, not an error.
pub async fn probe(transport: &dyn CliTransport, deadline: Duration) -> Result<Probe, String> {
    let outcome = transport
        .run(&CliCommand::new(&["--version"]), deadline)
        .await?;
    if outcome.killed_by_deadline {
        return Err("the version probe was killed at its deadline".to_owned());
    }
    if !outcome.succeeded() {
        return Ok(Probe::Absent);
    }
    Ok(parse_version(&outcome.stdout))
}

/// Parses the version document; non-conforming output is `Unsupported`.
#[must_use]
pub fn parse_version(stdout: &str) -> Probe {
    let trimmed = stdout.trim();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed)
        && let Some(version) = value["version"].as_str()
        && !version.is_empty()
    {
        return Probe::Present {
            version: redact(version),
        };
    }
    let first = trimmed.lines().next().unwrap_or_default().trim();
    if let Some(version) = first.strip_prefix(&format!("{CLI_NAME} ")) {
        return Probe::Present {
            version: redact(version),
        };
    }
    let parts: Vec<&str> = first.split('.').collect();
    if (2..=3).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    {
        return Probe::Present {
            version: redact(first),
        };
    }
    Probe::Unsupported
}

/// Reads the machine's Frogenv status. The status document is the only
/// documented JSON surface; a non-conforming answer degrades explicitly.
///
/// # Errors
///
/// Fails on transport errors; a shape-changed status is an
/// [`unsupported_version`] answer.
pub async fn status(
    transport: &dyn CliTransport,
    deadline: Duration,
) -> Result<StatusDocument, String> {
    let outcome = transport
        .run(&CliCommand::new(&["status"]), deadline)
        .await?;
    if outcome.killed_by_deadline {
        return Err("the status command was killed at its deadline".to_owned());
    }
    if !outcome.succeeded() {
        return Err(format!(
            "the status command failed: {}",
            redact(&failure_detail(&outcome))
        ));
    }
    if outcome.stdout.len() > MAX_DOCUMENT_BYTES {
        return Err("the status document exceeds its bound".to_owned());
    }
    serde_json::from_str::<StatusDocument>(outcome.stdout.trim())
        .map(|mut document| {
            // Every decoded string field is sanitized before it is
            // exposed: a remote can carry credentials, and an id could
            // quote value-shaped material.
            document.machine_state = document.machine_state.take().map(|state| redact(&state));
            document.machine_id = document.machine_id.take().map(|id| redact(&id));
            document.git_remote = document.git_remote.take().map(|remote| redact(&remote));
            document
        })
        .map_err(|_| {
            "the status output is not in the documented shape; the CLI version is untested (code: unsupported_version)"
                .to_owned()
        })
}

/// The bounded, redacted failure detail from an outcome.
#[must_use]
pub fn failure_detail(outcome: &CliOutcome) -> String {
    let text = if outcome.stderr.trim().is_empty() {
        outcome.stdout.trim()
    } else {
        outcome.stderr.trim()
    };
    redact(text)
}

/// Scrubs value-shaped material from CLI output before it becomes an
/// observation, a public result, or an audit detail: age/SOPS key
/// material, credential-shaped userinfo, and control noise.
#[must_use]
pub fn redact(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect();
    let with_urls = redact_url_credentials(&cleaned);
    let with_schemeless = redact_schemeless_credentials(&with_urls);
    redact_value_shaped(&with_schemeless)
}

/// Redacts `user:password@` patterns anywhere in the text — scp-style
/// remotes and error text the URL pass cannot see. The `'@'` is consumed
/// with the userinfo so the loop always advances.
fn redact_schemeless_credentials(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut search = 0;
    while let Some(offset) = text[search..].find('@') {
        let at = search + offset;
        let token_start = text[..at]
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace() || *c == '/' || *c == '"' || *c == '\'')
            .map_or(0, |(index, c)| index + c.len_utf8());
        let token = &text[token_start..at];
        let has_password = token
            .split_once(':')
            .is_some_and(|(user, password)| !user.is_empty() && !password.is_empty());
        if has_password {
            let flush_start = search.min(token_start);
            result.push_str(&text[flush_start..token_start]);
            result.push_str("***@");
            search = at + 1;
        } else {
            result.push_str(&text[search..=at]);
            search = at + 1;
        }
    }
    result.push_str(&text[search..]);
    result
}

/// Replaces `user:password@` userinfo in URLs with a marker.
fn redact_url_credentials(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(position) = rest.find("://") {
        let (before, after) = rest.split_at(position + 3);
        result.push_str(before);
        let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
        let authority = &after[..authority_end];
        let tail = &after[authority_end..];
        match authority.split_once('@') {
            Some((_userinfo, host)) => {
                result.push_str("***@");
                result.push_str(host);
            }
            None => result.push_str(authority),
        }
        rest = tail;
    }
    result.push_str(rest);
    result
}

/// Scrubs value-shaped material: age secret keys, SOPS encrypted payloads
/// (`ENC[...]`), and long base64/hex runs that could be key material.
/// The patterns are conservative: readable config and ids survive.
fn redact_value_shaped(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            result.push('\n');
        }
        result.push_str(&redact_line(line));
    }
    result
}

fn redact_line(line: &str) -> String {
    let trimmed = line.trim_start();
    let is_age_secret = trimmed.starts_with("AGE-SECRET-KEY-");
    let is_sops_payload = trimmed.contains("ENC[") || trimmed.contains("sops:");
    let is_key_assignment = trimmed.starts_with("age1")
        || trimmed.starts_with("SSH_KEY=")
        || trimmed.starts_with("SOPS_AGE_KEY");
    if is_age_secret || is_sops_payload || is_key_assignment {
        return "[redacted value-shaped material]".to_owned();
    }
    // A key marker anywhere in the line (an error message quoting it) is
    // scrubbed with the material that follows it.
    if let Some(position) = line.find("AGE-SECRET-KEY-") {
        let (before, _after) = line.split_at(position);
        return format!("{before}[redacted value-shaped material]");
    }
    // A long unbroken base64/hex run inside the line is key material
    // shaped enough to scrub; the surrounding text survives.
    scrub_long_runs(line)
}

/// Replaces runs of 40+ base64/hex characters with a marker.
fn scrub_long_runs(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    let mut run = String::new();
    for character in line.chars() {
        if character.is_ascii_alphanumeric()
            || character == '/'
            || character == '+'
            || character == '='
        {
            run.push(character);
        } else {
            if run.len() >= 40 {
                result.push_str("[redacted]");
            } else {
                result.push_str(&run);
            }
            run.clear();
            result.push(character);
        }
    }
    if run.len() >= 40 {
        result.push_str("[redacted]");
    } else {
        result.push_str(&run);
    }
    result
}
