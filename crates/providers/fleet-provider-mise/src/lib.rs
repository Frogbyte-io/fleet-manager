//! The mise provider (FM-304): a machine-readable CLI contract over
//! `mise`, with the native project files as the only authority.
//!
//! Fleet observes what `mise` itself reports and optionally drives
//! install/exec through its documented CLI. It never reads or translates
//! `.mise.toml`/`mise.toml` into a second tool-version model: the project
//! files stay authoritative, and every fact here is an observation of
//! mise's own output.
//!
//! The documented surfaces: `mise ls --json` (an object keyed by tool
//! name, or an array of version records for one tool), `mise install`
//! (idempotent), and `mise exec … -- COMMAND` (argument array after the
//! separator). Anything non-conforming degrades to `unsupported_version`.
#![warn(missing_docs)]

use std::fmt;
use std::time::Duration;

use serde::Deserialize;

/// The documented CLI binary name. Fixed: Fleet never guesses an alias.
pub const CLI_NAME: &str = "mise";

/// What observed the facts: a probe name and version, recorded on every
/// observation.
pub const PROBE_SOURCE: &str = "mise-cli";

/// How long one CLI command may run before the deadline kills it.
pub const COMMAND_DEADLINE: Duration = Duration::from_secs(120);

/// The bound for one decoded JSON document.
pub const MAX_DOCUMENT_BYTES: usize = 256 * 1024;

/// One command invocation over the CLI contract.
#[derive(Clone, Debug)]
pub struct CliCommand {
    /// The subcommand and its arguments.
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

    /// The full argument array, verbatim.
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

/// One version record from `mise ls --json` for a single tool.
#[derive(Debug, Deserialize)]
pub struct ToolVersion {
    /// The installed version string, when the record carries one.
    #[serde(default)]
    pub version: Option<String>,
    /// The version the active configuration requests, when any.
    #[serde(default, alias = "requestedVersion")]
    pub requested: Option<String>,
    /// Whether the requested version is installed.
    #[serde(default)]
    pub installed: Option<bool>,
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
        return Ok(Probe::Unsupported);
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
            version: version.to_owned(),
        };
    }
    let first = trimmed.lines().next().unwrap_or_default().trim();
    if let Some(version) = first.strip_prefix(&format!("{CLI_NAME} ")) {
        return Probe::Present {
            version: version.to_owned(),
        };
    }
    let parts: Vec<&str> = first.split('.').collect();
    if (2..=3).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    {
        return Probe::Present {
            version: first.to_owned(),
        };
    }
    Probe::Unsupported
}

/// The tool inventory from `mise ls --json`: an object keyed by tool
/// name, each carrying that tool's version records.
///
/// # Errors
///
/// Fails on a document that is not in the documented shape.
pub fn parse_ls(stdout: &str) -> Result<Vec<(String, Vec<ToolVersion>)>, String> {
    if stdout.len() > MAX_DOCUMENT_BYTES {
        return Err("the mise ls document exceeds its bound".to_owned());
    }
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).map_err(|_| {
        "the mise ls output is not in the documented shape; the CLI version is untested (code: unsupported_version)"
            .to_owned()
    })?;
    let Some(object) = value.as_object() else {
        return Err(
            "the mise ls output is not in the documented shape; the CLI version is untested (code: unsupported_version)"
                .to_owned(),
        );
    };
    let mut inventory = Vec::new();
    for (tool, records) in object {
        let records: Vec<ToolVersion> = serde_json::from_value(records.clone()).map_err(|_| {
            format!(
                "the mise ls records for {tool} are not in the documented shape (code: unsupported_version)"
            )
        })?;
        inventory.push((tool.clone(), records));
    }
    Ok(inventory)
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

/// Scrubs credential-shaped `user:password@` userinfo and control noise
/// from CLI output before it becomes an observation or audit detail.
#[must_use]
pub fn redact(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect();
    let with_urls = redact_url_credentials(&cleaned);
    redact_schemeless_credentials(&with_urls)
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
