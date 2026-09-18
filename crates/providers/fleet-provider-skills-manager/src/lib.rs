//! The Skills Manager provider (FM-302): a machine-readable CLI contract
//! over `skills-manager-cli --json`, never the upstream SQLite database and
//! never Tauri internals.
//!
//! The transport rule mirrors the tailscale provider: the caller's inputs
//! are fixed command shapes plus bounded argument values; the CLI's stdout
//! is one JSON document, and its stderr carries the documented failure
//! shape `{"ok": false, "code": …, "message": …}` with a non-zero exit. A
//! response that does not conform to the documented shape degrades
//! explicitly — an `unsupported_version` state, never a guessed fact.
//!
//! Secrets never ride CLI arguments, output, or audit metadata: the
//! commands here take identifiers and paths only, and every decoded value
//! passes through [`redact`] before it becomes an observation.
#![warn(missing_docs)]

use std::fmt;
use std::time::Duration;

use serde::Deserialize;

/// The documented CLI binary name. Fixed: Fleet never guesses an alias.
pub const CLI_NAME: &str = "skills-manager-cli";

/// What observed the facts: a probe name and version, recorded on every
/// observation. The CLI's own version replaces the placeholder when the
/// probe answers.
pub const PROBE_SOURCE: &str = "skills-manager-cli";

/// How long one CLI command may run before the deadline kills it.
pub const COMMAND_DEADLINE: Duration = Duration::from_secs(60);

/// The bound for one decoded JSON document.
pub const MAX_DOCUMENT_BYTES: usize = 512 * 1024;

/// One command invocation over the CLI contract.
#[derive(Clone, Debug)]
pub struct CliCommand {
    /// The subcommand, e.g. `["skills", "list"]`.
    pub arguments: Vec<String>,
    /// The skills root, when the command targets an external workspace.
    pub skills_root: Option<String>,
}

impl CliCommand {
    /// A command against the machine's default library.
    #[must_use]
    pub fn new(arguments: &[&str]) -> Self {
        Self {
            arguments: arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
            skills_root: None,
        }
    }

    /// A command against an external skills root.
    #[must_use]
    pub fn at_root(mut self, root: &str) -> Self {
        self.skills_root = Some(root.to_owned());
        self
    }

    /// The full argument array, `--json` last so it always applies.
    #[must_use]
    pub fn argv(&self) -> Vec<String> {
        let mut argv = vec![CLI_NAME.to_owned()];
        if let Some(root) = &self.skills_root {
            argv.push("--skills-root".to_owned());
            argv.push(root.clone());
        }
        argv.extend(self.arguments.iter().cloned());
        argv.push("--json".to_owned());
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

    /// The documented failure shape, when the CLI printed one.
    #[must_use]
    pub fn failure_code(&self) -> Option<String> {
        let value = serde_json::from_str::<serde_json::Value>(self.stderr.trim()).ok()?;
        let ok = value["ok"].as_bool()?;
        if ok {
            return None;
        }
        value["code"].as_str().map(str::to_owned)
    }
}

/// The transport contract: run one CLI command, bounded.
#[async_trait::async_trait]
pub trait CliTransport: fmt::Debug + Send + Sync {
    /// Runs one command over the documented CLI contract.
    ///
    /// # Errors
    ///
    /// Fails when the CLI cannot be started at all (absent binary); a
    /// command that runs and fails by its own contract is an
    /// [`CliOutcome`], not an error.
    async fn run(&self, command: &CliCommand, deadline: Duration) -> Result<CliOutcome, String>;
}

/// The CLI's `--version` line, e.g. `skills-manager-cli 1.34.2`.
#[derive(Debug, Deserialize)]
struct VersionDocument {
    #[serde(default)]
    version: Option<String>,
}

/// The CLI's agent listing: each entry names an agent and its global
/// skills directory.
#[derive(Debug, Deserialize)]
pub struct AgentEntry {
    /// The agent's identifier, e.g. `claude_code`.
    pub id: String,
    /// The agent's display name, when the CLI carries one.
    #[serde(default, alias = "displayName")]
    pub name: Option<String>,
    /// The agent's global skills directory, when the CLI carries one.
    #[serde(default, alias = "skillsDir", alias = "skillsPath")]
    pub skills_dir: Option<String>,
}

/// The CLI's skill listing entry.
#[derive(Debug, Deserialize)]
pub struct SkillEntry {
    /// The skill's identifier in the library.
    pub id: String,
    /// The skill's display name.
    #[serde(default, alias = "displayName")]
    pub name: Option<String>,
    /// The skill's version, when tracked.
    #[serde(default, alias = "skillVersion")]
    pub version: Option<String>,
    /// Whether the skill has upstream updates, when tracked.
    #[serde(default, alias = "hasUpdate", alias = "updateAvailable")]
    pub has_update: Option<bool>,
}

/// The CLI's deployment status for one skill.
#[derive(Debug, Deserialize)]
pub struct DeploymentStatus {
    /// The skill the status describes.
    #[serde(alias = "skillId", alias = "id")]
    pub skill_id: String,
    /// The agents the skill is deployed to, as documented ids. Required:
    /// an omitted field is a shape change, not an empty deployment.
    #[serde(alias = "deployedTo", alias = "agents")]
    pub deployed_to: Vec<String>,
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
        // Exit non-zero on `--version` means the binary did not answer as
        // itself: treat as absent, not unsupported.
        return Ok(Probe::Absent);
    }
    Ok(parse_version(&outcome.stdout))
}

/// Parses the version document; non-conforming output is `Unsupported`.
#[must_use]
pub fn parse_version(stdout: &str) -> Probe {
    // The CLI may print a bare version line or a JSON document; both are
    // documented shapes.
    let trimmed = stdout.trim();
    if let Ok(document) = serde_json::from_str::<VersionDocument>(trimmed)
        && let Some(version) = document.version
        && !version.is_empty()
    {
        return Probe::Present { version };
    }
    let first = trimmed.lines().next().unwrap_or_default().trim();
    if let Some(version) = first.strip_prefix(&format!("{CLI_NAME} ")) {
        return Probe::Present {
            version: version.to_owned(),
        };
    }
    if is_semverish(first) {
        return Probe::Present {
            version: first.to_owned(),
        };
    }
    Probe::Unsupported
}

fn is_semverish(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    (2..=3).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

/// Lists the agents the CLI knows, degraded honestly.
///
/// # Errors
///
/// Fails on transport errors; a shape-changed listing is an
/// [`unsupported_version`] answer.
pub async fn list_agents(
    transport: &dyn CliTransport,
    deadline: Duration,
) -> Result<Vec<AgentEntry>, String> {
    let outcome = transport
        .run(&CliCommand::new(&["agents", "list"]), deadline)
        .await?;
    parse_list(&outcome, "agents")
}

/// Lists the library's skills, degraded honestly.
///
/// # Errors
///
/// Fails on transport errors; a shape-changed listing is an
/// [`unsupported_version`] answer.
pub async fn list_skills(
    transport: &dyn CliTransport,
    deadline: Duration,
) -> Result<Vec<SkillEntry>, String> {
    let outcome = transport
        .run(&CliCommand::new(&["skills", "list"]), deadline)
        .await?;
    parse_list(&outcome, "skills")
}

/// Reads one skill's deployment status.
///
/// # Errors
///
/// Fails on transport errors; a shape-changed status is an
/// [`unsupported_version`] answer.
pub async fn skill_status(
    transport: &dyn CliTransport,
    skill_id: &str,
    deadline: Duration,
) -> Result<DeploymentStatus, String> {
    // A leading dash or control character would be an option or smuggle a
    // field, never an identifier.
    if skill_id.is_empty()
        || skill_id.len() > 255
        || skill_id.starts_with('-')
        || skill_id.chars().any(char::is_control)
    {
        return Err(
            "the skill id must be 1..=255 characters with no leading dash or control characters"
                .to_owned(),
        );
    }
    let command = CliCommand::new(&["skills", "status", skill_id]);
    let outcome = transport.run(&command, deadline).await?;
    if outcome.killed_by_deadline {
        return Err("the status command was killed at its deadline".to_owned());
    }
    if !outcome.succeeded() {
        return Err(format!(
            "the status command failed: {}",
            redact(&failure_detail(&outcome))
        ));
    }
    let status = parse_document::<DeploymentStatus>(&outcome.stdout).map_err(|()| {
        "the skills status output is not in the documented shape; the CLI version is untested (code: unsupported_version)".to_owned()
    })?;
    // The CLI must answer for the requested skill: relabeling a response
    // for a different skill would expose the wrong deployment state.
    if status.skill_id != skill_id {
        return Err(format!(
            "the CLI answered a status for {} when {} was requested (code: unsupported_version)",
            redact(&status.skill_id),
            redact(skill_id)
        ));
    }
    Ok(status)
}

fn parse_list<T: for<'de> Deserialize<'de>>(
    outcome: &CliOutcome,
    what: &str,
) -> Result<Vec<T>, String> {
    if outcome.killed_by_deadline {
        return Err(format!("the {what} command was killed at its deadline"));
    }
    if !outcome.succeeded() {
        return Err(format!(
            "the {what} command failed: {}",
            redact(&failure_detail(outcome))
        ));
    }
    parse_document::<Vec<T>>(&outcome.stdout).map_err(|()| {
        format!("the {what} listing is not in the documented shape; the CLI version is untested (code: unsupported_version)")
    })
}

fn parse_document<T: for<'de> Deserialize<'de>>(stdout: &str) -> Result<T, ()> {
    if stdout.len() > MAX_DOCUMENT_BYTES {
        return Err(());
    }
    serde_json::from_str(stdout.trim()).map_err(|_| ())
}

/// The bounded, redacted failure detail from an outcome. The documented
/// failure shape's `message` field wins when the stderr carries it; raw
/// text is the fallback.
#[must_use]
pub fn failure_detail(outcome: &CliOutcome) -> String {
    let text = if outcome.stderr.trim().is_empty() {
        outcome.stdout.trim()
    } else {
        outcome.stderr.trim()
    };
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text)
        && value["ok"].as_bool() == Some(false)
        && let Some(message) = value["message"].as_str()
    {
        return redact(message);
    }
    let bounded = if text.len() > 300 { &text[..300] } else { text };
    redact(bounded)
}

/// Scrubs credential-shaped `user:password@` userinfo and control noise
/// from CLI output before it becomes an observation or audit detail.
#[must_use]
pub fn redact(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect();
    redact_credentials(&cleaned)
}

fn redact_credentials(text: &str) -> String {
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
    redact_schemeless_credentials(&result)
}

/// Redacts `user:password@` patterns anywhere in the text — scp-style
/// remotes and error text the URL pass cannot see.
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
            // The flush clamps to the current search position: a token
            // already consumed by an earlier redaction must not be sliced
            // backwards.
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
