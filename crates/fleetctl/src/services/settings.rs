//! `fleetctl services settings|env|domains|health` (FM-1034): the settings
//! of a Coolify resource, from the command line. An adapter over
//! `/api/v1/services/{id}/settings`; the preview, the policy, and the audit
//! are the controller's.
//!
//! Environment variable values are write-only and never travel in argv: a
//! `set` reads them from standard input (`--stdin`) or a file (`--file
//! <path>`). With `--key NAME` the whole input is that one variable's value
//! (one trailing newline is dropped; the value may span lines); without it
//! the input is `KEY=VALUE` lines (`#` comments and blank lines ignored, an
//! optional `export ` prefix, one pair of matching quotes around a value
//! stripped). A value is never printed, in text or JSON, and the answer
//! lists key names only.

use std::fmt::Write as _;
use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::requests::parse_wait_approval;
use crate::{CliError, Output, RequestShape, usage};

/// Which part of the settings a read shows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Part {
    /// Everything.
    All,
    /// Environment variable names and flags only.
    Env,
}

/// The fields every filing command shares.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Filing {
    /// Why, for the approver.
    pub reason: Option<String>,
    /// A key making a retry return the request already made.
    pub idempotency_key: Option<String>,
    /// Redeploy (an application) or restart (a service) after the change.
    pub redeploy: bool,
    /// Wait this long for the request to reach an outcome.
    pub wait: Option<Duration>,
}

/// Where an environment value is read from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueSource {
    /// Standard input.
    Stdin,
    /// A file.
    File(String),
}

/// Flag overrides of an environment `set`; absent keeps the current flag.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EnvFlags {
    /// Build-time availability (applications).
    pub buildtime: Option<bool>,
    /// Runtime availability (applications).
    pub runtime: Option<bool>,
    /// A multiline value.
    pub multiline: Option<bool>,
    /// A literal value.
    pub literal: Option<bool>,
    /// Hide the value after saving.
    pub shown_once: Option<bool>,
}

/// The health-check fields to change.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HealthArgs {
    /// On or off.
    pub enabled: Option<bool>,
    /// The request path.
    pub path: Option<String>,
    /// The port.
    pub port: Option<u16>,
    /// The host header.
    pub host: Option<String>,
    /// The HTTP method.
    pub method: Option<String>,
    /// `http` or `https`.
    pub scheme: Option<String>,
    /// The healthy status code.
    pub return_code: Option<u16>,
    /// Text the response must contain.
    pub response_text: Option<String>,
    /// Seconds between checks.
    pub interval: Option<u32>,
    /// Seconds a check may take.
    pub timeout: Option<u32>,
    /// Failures before unhealthy.
    pub retries: Option<u32>,
    /// Seconds before the first check.
    pub start_period: Option<u32>,
}

/// One settings subcommand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SettingsAction {
    /// Read the settings (`settings <id>`, `env list <id>`).
    Show {
        /// The service id.
        id: String,
        /// What to show.
        part: Part,
    },
    /// Set variables from stdin or a file.
    EnvSet {
        /// The service id.
        id: String,
        /// Where the values are read from.
        source: ValueSource,
        /// The one variable the whole input is the value of.
        key: Option<String>,
        /// The preview-deployment variable.
        preview: bool,
        /// Flag overrides.
        flags: EnvFlags,
        /// The shared fields.
        filing: Filing,
    },
    /// Unset variables by name.
    EnvUnset {
        /// The service id.
        id: String,
        /// The names.
        keys: Vec<String>,
        /// The preview-deployment variables.
        preview: bool,
        /// The shared fields.
        filing: Filing,
    },
    /// Replace an application's domains.
    Domains {
        /// The service id.
        id: String,
        /// The complete new list; empty clears.
        domains: Vec<String>,
        /// The shared fields.
        filing: Filing,
    },
    /// Change an application's health check.
    Health {
        /// The service id.
        id: String,
        /// The fields to change.
        args: HealthArgs,
        /// The shared fields.
        filing: Filing,
    },
}

impl SettingsAction {
    /// The wait of a filing command: `Some(wait)` for a command that files a
    /// request, `None` for a read.
    #[must_use]
    pub fn filing_wait(&self) -> Option<Option<Duration>> {
        match self {
            Self::Show { .. } => None,
            Self::EnvSet { filing, .. }
            | Self::EnvUnset { filing, .. }
            | Self::Domains { filing, .. }
            | Self::Health { filing, .. } => Some(filing.wait),
        }
    }
}

fn bad(message: impl Into<String>) -> CliError {
    CliError {
        message: format!("{}\n\n{}", message.into(), usage()),
    }
}

fn number<T: std::str::FromStr>(name: &str, raw: &str) -> Result<T, CliError> {
    raw.parse().map_err(|_| CliError {
        message: format!("--{name} must be a number, not {raw:?}"),
    })
}

/// Parses `settings <id>`, `env list|set|unset <id> ...`, `domains set <id>
/// ...`, and `health set <id> ...` (the words after `services`).
#[allow(clippy::too_many_lines)]
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<SettingsAction, CliError> {
    let (word, rest) = rest.split_first().ok_or_else(|| bad("missing command"))?;
    let (sub, args) = if *word == "settings" {
        ("show", rest)
    } else {
        let (sub, args) = rest
            .split_first()
            .ok_or_else(|| bad(format!("{word} needs a subcommand")))?;
        (*sub, args)
    };
    let kind = match (*word, sub) {
        ("settings", _) => "show",
        ("env", "list") => "env-list",
        ("env", "set") => "env-set",
        ("env", "unset") => "env-unset",
        ("domains", "set") => "domains",
        ("health", "set") => "health",
        _ => return Err(bad(format!("unknown command: services {word} {sub}"))),
    };
    let (id, flags) = args
        .split_first()
        .ok_or_else(|| bad("missing service id"))?;
    // An empty id or a leading `-` is a flag or a typo, never an id.
    if id.is_empty() || id.starts_with('-') {
        return Err(bad("missing service id"));
    }
    let mut filing = Filing::default();
    let mut positional: Vec<String> = Vec::new();
    let mut source = None;
    let mut key = None;
    let mut preview = false;
    let mut clear = false;
    let mut env_flags = EnvFlags::default();
    let mut health = HealthArgs::default();
    let mut flags = flags.iter().copied();
    while let Some(flag) = flags.next() {
        if let Some(duration) = parse_wait_approval("--wait-approval", flag)? {
            filing.wait = Some(duration);
            continue;
        }
        let mut value = |name: &str| {
            flags
                .next()
                .filter(|candidate| !candidate.starts_with("--"))
                .map(str::to_owned)
                .ok_or_else(|| CliError {
                    message: format!("--{name} requires a value"),
                })
        };
        match flag {
            "--output" => {
                *output = match value("output")?.as_str() {
                    "json" => Output::Json,
                    "text" => Output::Text,
                    other => {
                        return Err(CliError {
                            message: format!("--output must be json or text, not {other:?}"),
                        });
                    }
                };
            }
            "--reason" if kind != "show" && kind != "env-list" => {
                filing.reason = Some(value("reason")?);
            }
            "--idempotency-key" if kind != "show" && kind != "env-list" => {
                filing.idempotency_key = Some(value("idempotency-key")?);
            }
            "--redeploy" if kind != "show" && kind != "env-list" => filing.redeploy = true,
            "--stdin" if kind == "env-set" => {
                if source.is_some() {
                    return Err(bad("use one of --stdin or --file"));
                }
                source = Some(ValueSource::Stdin);
            }
            "--file" if kind == "env-set" => {
                if source.is_some() {
                    return Err(bad("use one of --stdin or --file"));
                }
                source = Some(ValueSource::File(value("file")?));
            }
            "--key" if kind == "env-set" => key = Some(value("key")?),
            "--preview" if kind == "env-set" || kind == "env-unset" => preview = true,
            "--buildtime" if kind == "env-set" => env_flags.buildtime = Some(true),
            "--no-buildtime" if kind == "env-set" => env_flags.buildtime = Some(false),
            "--runtime" if kind == "env-set" => env_flags.runtime = Some(true),
            "--no-runtime" if kind == "env-set" => env_flags.runtime = Some(false),
            "--multiline" if kind == "env-set" => env_flags.multiline = Some(true),
            "--no-multiline" if kind == "env-set" => env_flags.multiline = Some(false),
            "--literal" if kind == "env-set" => env_flags.literal = Some(true),
            "--no-literal" if kind == "env-set" => env_flags.literal = Some(false),
            "--shown-once" if kind == "env-set" => env_flags.shown_once = Some(true),
            "--no-shown-once" if kind == "env-set" => env_flags.shown_once = Some(false),
            "--clear" if kind == "domains" => clear = true,
            "--enabled" if kind == "health" => health.enabled = Some(true),
            "--disabled" if kind == "health" => health.enabled = Some(false),
            "--path" if kind == "health" => health.path = Some(value("path")?),
            "--port" if kind == "health" => health.port = Some(number("port", &value("port")?)?),
            "--host" if kind == "health" => health.host = Some(value("host")?),
            "--method" if kind == "health" => health.method = Some(value("method")?),
            "--scheme" if kind == "health" => health.scheme = Some(value("scheme")?),
            "--return-code" if kind == "health" => {
                health.return_code = Some(number("return-code", &value("return-code")?)?);
            }
            "--response-text" if kind == "health" => {
                health.response_text = Some(value("response-text")?);
            }
            "--interval" if kind == "health" => {
                health.interval = Some(number("interval", &value("interval")?)?);
            }
            "--timeout" if kind == "health" => {
                health.timeout = Some(number("timeout", &value("timeout")?)?);
            }
            "--retries" if kind == "health" => {
                health.retries = Some(number("retries", &value("retries")?)?);
            }
            "--start-period" if kind == "health" => {
                health.start_period = Some(number("start-period", &value("start-period")?)?);
            }
            other if other.starts_with("--") => {
                return Err(bad(format!("unknown flag {other:?}")));
            }
            other => positional.push(other.to_owned()),
        }
    }
    let id = (*id).to_owned();
    Ok(match kind {
        "show" | "env-list" => {
            if !positional.is_empty() {
                return Err(bad("unexpected argument"));
            }
            SettingsAction::Show {
                id,
                part: if kind == "show" { Part::All } else { Part::Env },
            }
        }
        "env-set" => {
            if !positional.is_empty() {
                return Err(bad(
                    "a value is never an argument: use --stdin or --file <path>",
                ));
            }
            SettingsAction::EnvSet {
                id,
                source: source.ok_or_else(|| {
                    bad("env set reads the value from --stdin or --file <path>, never from an argument")
                })?,
                key,
                preview,
                flags: env_flags,
                filing,
            }
        }
        "env-unset" => {
            if positional.is_empty() {
                return Err(bad("env unset needs at least one variable name"));
            }
            SettingsAction::EnvUnset {
                id,
                keys: positional,
                preview,
                filing,
            }
        }
        "domains" => {
            if clear != positional.is_empty() {
                return Err(bad("domains set needs URLs, or --clear to remove them all"));
            }
            SettingsAction::Domains {
                id,
                domains: positional,
                filing,
            }
        }
        _ => {
            if !positional.is_empty() {
                return Err(bad("unexpected argument"));
            }
            if health == HealthArgs::default() {
                return Err(bad("health set needs at least one field to change"));
            }
            SettingsAction::Health {
                id,
                args: health,
                filing,
            }
        }
    })
}

/// Percent-encodes one path segment: only unreserved characters pass.
fn encode(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

fn filing_body(filing: &Filing, id: &str, what: &str) -> Map<String, Value> {
    let mut body = Map::new();
    body.insert(
        "reason".to_owned(),
        json!(
            filing
                .reason
                .clone()
                .unwrap_or_else(|| format!("change {what} of {id}"))
        ),
    );
    if let Some(key) = &filing.idempotency_key {
        body.insert("idempotencyKey".to_owned(), json!(key));
    }
    if filing.redeploy {
        body.insert("redeploy".to_owned(), json!(true));
    }
    body
}

/// Reads all of standard input as raw text. The value is not trimmed beyond
/// one trailing newline by the caller.
fn read_stdin() -> Result<String, CliError> {
    use std::io::Read as _;
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .map_err(|error| CliError {
            message: format!("cannot read the values from stdin: {error}"),
        })?;
    Ok(text)
}

fn read_source(
    source: &ValueSource,
    stdin: impl FnOnce() -> Result<String, CliError>,
) -> Result<String, CliError> {
    match source {
        ValueSource::Stdin => stdin(),
        ValueSource::File(path) => std::fs::read_to_string(path).map_err(|error| CliError {
            message: format!("cannot read {path}: {error}"),
        }),
    }
}

/// Parses `KEY=VALUE` lines: comments and blank lines are ignored, an
/// optional `export ` prefix and one pair of matching quotes around a value
/// are dropped.
///
/// # Errors
///
/// Fails on a line with no `=` or an empty name. The error names the line
/// number only, never the line.
pub fn parse_dotenv(text: &str) -> Result<Vec<(String, String)>, CliError> {
    let mut pairs = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let trimmed = trimmed
            .strip_prefix("export ")
            .unwrap_or(trimmed)
            .trim_start();
        let Some((name, value)) = trimmed.split_once('=') else {
            return Err(CliError {
                message: format!("line {} is not KEY=VALUE", number + 1),
            });
        };
        let name = name.trim();
        if name.is_empty() {
            return Err(CliError {
                message: format!("line {} has an empty name", number + 1),
            });
        }
        let value = value.trim();
        let value = ["\"", "'"]
            .iter()
            .find_map(|quote| {
                value
                    .strip_prefix(quote)
                    .and_then(|rest| rest.strip_suffix(quote))
            })
            .unwrap_or(value);
        pairs.push((name.to_owned(), value.to_owned()));
    }
    if pairs.is_empty() {
        return Err(CliError {
            message: "the input holds no KEY=VALUE lines".to_owned(),
        });
    }
    Ok(pairs)
}

fn flag_fields(change: &mut Value, flags: EnvFlags) {
    for (name, value) in [
        ("isBuildtime", flags.buildtime),
        ("isRuntime", flags.runtime),
        ("isMultiline", flags.multiline),
        ("isLiteral", flags.literal),
        ("isShownOnce", flags.shown_once),
    ] {
        if let Some(value) = value {
            change[name] = json!(value);
        }
    }
}

/// The controller request for one subcommand. `stdin` supplies the values of
/// an `env set --stdin`.
///
/// # Errors
///
/// Fails when the values cannot be read or parsed.
#[allow(clippy::too_many_lines)]
pub(crate) fn request_with(
    action: &SettingsAction,
    stdin: impl FnOnce() -> Result<String, CliError>,
) -> Result<RequestShape, CliError> {
    let post = |id: &str, what: &str, body: Value| -> RequestShape {
        (
            reqwest::Method::POST,
            format!("/api/v1/services/{}/settings/{what}", encode(id)),
            Vec::new(),
            Some(body),
        )
    };
    Ok(match action {
        SettingsAction::Show { id, .. } => (
            reqwest::Method::GET,
            format!("/api/v1/services/{}/settings", encode(id)),
            Vec::new(),
            None,
        ),
        SettingsAction::EnvSet {
            id,
            source,
            key,
            preview,
            flags,
            filing,
        } => {
            let text = read_source(source, stdin)?;
            let pairs = match key {
                Some(key) => {
                    let value = text
                        .strip_suffix("\r\n")
                        .or_else(|| text.strip_suffix('\n'))
                        .unwrap_or(&text)
                        .to_owned();
                    if value.is_empty() {
                        return Err(CliError {
                            message:
                                "the value must not be empty; use env unset to remove a variable"
                                    .to_owned(),
                        });
                    }
                    vec![(key.clone(), value)]
                }
                None => parse_dotenv(&text)?,
            };
            let changes: Vec<Value> = pairs
                .into_iter()
                .map(|(key, value)| {
                    let mut change = json!({
                        "op": "set", "key": key, "value": value, "isPreview": preview,
                    });
                    flag_fields(&mut change, *flags);
                    change
                })
                .collect();
            let mut body = filing_body(filing, id, "environment variables");
            body.insert("changes".to_owned(), Value::Array(changes));
            post(id, "env", Value::Object(body))
        }
        SettingsAction::EnvUnset {
            id,
            keys,
            preview,
            filing,
        } => {
            let changes: Vec<Value> = keys
                .iter()
                .map(|key| json!({"op": "unset", "key": key, "isPreview": preview}))
                .collect();
            let mut body = filing_body(filing, id, "environment variables");
            body.insert("changes".to_owned(), Value::Array(changes));
            post(id, "env", Value::Object(body))
        }
        SettingsAction::Domains {
            id,
            domains,
            filing,
        } => {
            let mut body = filing_body(filing, id, "domains");
            body.insert("domains".to_owned(), json!(domains));
            post(id, "domains", Value::Object(body))
        }
        SettingsAction::Health { id, args, filing } => {
            let mut body = filing_body(filing, id, "health check");
            let mut put = |name: &str, value: Option<Value>| {
                if let Some(value) = value {
                    body.insert(name.to_owned(), value);
                }
            };
            put("enabled", args.enabled.map(|v| json!(v)));
            put("path", args.path.as_ref().map(|v| json!(v)));
            put("port", args.port.map(|v| json!(v)));
            put("host", args.host.as_ref().map(|v| json!(v)));
            put("method", args.method.as_ref().map(|v| json!(v)));
            put("scheme", args.scheme.as_ref().map(|v| json!(v)));
            put("returnCode", args.return_code.map(|v| json!(v)));
            put(
                "responseText",
                args.response_text.as_ref().map(|v| json!(v)),
            );
            put("interval", args.interval.map(|v| json!(v)));
            put("timeout", args.timeout.map(|v| json!(v)));
            put("retries", args.retries.map(|v| json!(v)));
            put("startPeriod", args.start_period.map(|v| json!(v)));
            post(id, "health", Value::Object(body))
        }
    })
}

/// The controller request, reading values from the real standard input.
///
/// # Errors
///
/// Fails when the values cannot be read or parsed.
pub(crate) fn request(action: &SettingsAction) -> Result<RequestShape, CliError> {
    request_with(action, read_stdin)
}

/// Server-supplied text for a terminal: control characters become spaces.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn text_of(value: &Value) -> String {
    clean(value.as_str().unwrap_or("-"))
}

fn flags_of(env: &Value) -> String {
    let mut flags = Vec::new();
    for (name, label) in [
        ("isBuildtime", "build"),
        ("isRuntime", "runtime"),
        ("isMultiline", "multiline"),
        ("isLiteral", "literal"),
        ("isShownOnce", "shown-once"),
        ("isPreview", "preview"),
        ("isShared", "shared"),
    ] {
        if env[name].as_bool() == Some(true) {
            flags.push(label);
        }
    }
    flags.join(",")
}

fn health_line(health: &Value) -> String {
    let port = health["port"]
        .as_u64()
        .map_or_else(String::new, |port| format!(":{port}"));
    format!(
        "{} {} {}://{}{}{} -> {}, every {}s, timeout {}s, {} retries, start {}s",
        if health["enabled"].as_bool() == Some(true) {
            "enabled"
        } else {
            "disabled"
        },
        text_of(&health["method"]),
        text_of(&health["scheme"]),
        health["host"]
            .as_str()
            .map_or_else(|| "<app>".to_owned(), clean),
        port,
        text_of(&health["path"]),
        health["returnCode"],
        health["interval"],
        health["timeout"],
        health["retries"],
        health["startPeriod"],
    )
}

/// Renders the settings: names and flags, domains, and the health check.
fn render_settings(value: &Value, part: Part) -> String {
    let data = value.get("data").unwrap_or(value);
    let mut lines = vec![format!(
        "{} ({}) {}",
        text_of(&data["name"]),
        text_of(&data["resourceKind"]),
        text_of(&data["serviceId"])
    )];
    if let Some(envs) = data["env"].as_array() {
        lines.push(format!("  environment variables: {}", envs.len()));
        for env in envs {
            lines.push(format!(
                "    {:<36} {}",
                text_of(&env["key"]),
                flags_of(env)
            ));
        }
    }
    if part == Part::All {
        if let Some(domains) = data["domains"].as_array() {
            if domains.is_empty() {
                lines.push("  domains: (none)".to_owned());
            } else {
                lines.push("  domains:".to_owned());
                for domain in domains {
                    lines.push(format!("    {}", text_of(domain)));
                }
            }
        }
        if data["health"].is_object() {
            lines.push(format!("  health: {}", health_line(&data["health"])));
        }
    }
    for note in data["notes"].as_array().into_iter().flatten() {
        lines.push(format!("  note: {}", text_of(note)));
    }
    lines.join("\n")
}

fn show(value: &Value) -> String {
    match value {
        Value::Null => "-".to_owned(),
        Value::String(text) => clean(text),
        Value::Array(items) => items.iter().map(show).collect::<Vec<_>>().join(", "),
        other => clean(&other.to_string()),
    }
}

/// The preview an approver reads: per variable (names and flags, a value
/// is write-only), or before and after of the domains and the health check.
fn preview_lines(parameters: &Value) -> Vec<String> {
    let preview = &parameters["preview"];
    let mut lines = Vec::new();
    if let Some(entries) = preview.as_array() {
        for entry in entries {
            let mut line = format!(
                "  {} {}{}",
                text_of(&entry["operation"]),
                text_of(&entry["key"]),
                if entry["isPreview"].as_bool() == Some(true) {
                    " (preview)"
                } else {
                    ""
                }
            );
            if let Some(changes) = entry["changes"].as_array() {
                let fields: Vec<String> = changes
                    .iter()
                    .map(|change| match change["field"].as_str() {
                        Some("value") => "value (write-only)".to_owned(),
                        Some(field) => format!(
                            "{field}: {} -> {}",
                            show(&change["from"]),
                            show(&change["to"])
                        ),
                        None => String::new(),
                    })
                    .filter(|text| !text.is_empty())
                    .collect();
                if !fields.is_empty() && entry["operation"].as_str() != Some("create") {
                    let _ = write!(line, " [{}]", fields.join("; "));
                }
            }
            lines.push(line);
        }
    } else if let Some(changes) = preview["changes"].as_array() {
        lines.push("  preview:".to_owned());
        for change in changes {
            lines.push(format!(
                "    {}: {} -> {}",
                text_of(&change["field"]),
                show(&change["from"]),
                show(&change["to"])
            ));
        }
    }
    if parameters["redeploy"].as_bool() == Some(true) {
        lines.push("  then: redeploy (restart for a service)".to_owned());
    }
    lines
}

/// Renders a filed request or a wait's answer: the request, the preview,
/// and the operation result when there is one.
fn render_change(value: &Value) -> String {
    let mut text = crate::requests::render(value);
    let request = if value.get("outcome").is_some() {
        &value["request"]
    } else {
        value.get("data").unwrap_or(value)
    };
    for line in preview_lines(&request["parameters"]) {
        let _ = write!(text, "\n{line}");
    }
    if let Some(warning) = value["resultWarning"].as_str() {
        let _ = write!(text, "\n  warning: {}", clean(warning));
    }
    let result = &value["result"];
    if result.is_object() {
        let _ = write!(
            text,
            "\n  result: {}{}",
            text_of(&result["outcome"]),
            if result["verified"].as_bool() == Some(true) {
                " (verified)"
            } else {
                ""
            }
        );
        for changed in result["changed"].as_array().into_iter().flatten() {
            let _ = write!(text, "\n    {}", text_of(changed));
        }
        if let Some(follow) = result["followUp"]["verb"].as_str() {
            let _ = write!(text, "\n  then: {} queued", clean(follow));
            if let Some(deployment) = result["followUp"]["deploymentUuid"].as_str() {
                let _ = write!(text, " (deployment {})", clean(deployment));
            }
        }
    }
    text
}

/// Renders the answer to `action`.
pub(crate) fn render_for(action: &SettingsAction, value: &Value) -> String {
    match action {
        SettingsAction::Show { part, .. } => render_settings(value, *part),
        _ => render_change(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(words: &[&str]) -> SettingsAction {
        let args: Vec<String> = words.iter().map(ToString::to_string).collect();
        match crate::parse(&args).expect("parses").command {
            crate::Command::Services(crate::services::ServicesAction::Settings(action)) => action,
            other => panic!("not a settings command: {other:?}"),
        }
    }

    fn fails(words: &[&str]) -> bool {
        let args: Vec<String> = words.iter().map(ToString::to_string).collect();
        crate::parse(&args).is_err()
    }

    #[test]
    fn the_grammar_covers_every_subcommand() {
        assert_eq!(
            action(&["services", "settings", "coolify:a:b"]),
            SettingsAction::Show {
                id: "coolify:a:b".to_owned(),
                part: Part::All
            }
        );
        assert_eq!(
            action(&["services", "env", "list", "coolify:a:b"]),
            SettingsAction::Show {
                id: "coolify:a:b".to_owned(),
                part: Part::Env
            }
        );
        let SettingsAction::EnvSet {
            source,
            key,
            preview,
            flags,
            filing,
            ..
        } = action(&[
            "services",
            "env",
            "set",
            "coolify:a:b",
            "--stdin",
            "--key",
            "API_URL",
            "--preview",
            "--literal",
            "--no-buildtime",
            "--redeploy",
            "--reason",
            "rotate",
            "--wait-approval=30s",
        ])
        else {
            panic!("not an env set");
        };
        assert_eq!(source, ValueSource::Stdin);
        assert_eq!(key.as_deref(), Some("API_URL"));
        assert!(preview && filing.redeploy);
        assert_eq!(flags.literal, Some(true));
        assert_eq!(flags.buildtime, Some(false));
        assert_eq!(filing.wait, Some(Duration::from_secs(30)));
        assert_eq!(filing.reason.as_deref(), Some("rotate"));
        assert!(matches!(
            action(&["services", "env", "unset", "x", "A", "B", "--preview"]),
            SettingsAction::EnvUnset { keys, preview: true, .. } if keys == ["A", "B"]
        ));
        assert!(matches!(
            action(&["services", "domains", "set", "x", "https://a.example.test"]),
            SettingsAction::Domains { domains, .. } if domains == ["https://a.example.test"]
        ));
        assert!(matches!(
            action(&["services", "domains", "set", "x", "--clear"]),
            SettingsAction::Domains { domains, .. } if domains.is_empty()
        ));
        let SettingsAction::Health { args, .. } = action(&[
            "services",
            "health",
            "set",
            "x",
            "--enabled",
            "--path",
            "/up",
            "--interval",
            "30",
            "--port",
            "8080",
        ]) else {
            panic!("not a health set");
        };
        assert_eq!(args.enabled, Some(true));
        assert_eq!(args.path.as_deref(), Some("/up"));
        assert_eq!((args.interval, args.port), (Some(30), Some(8080)));
    }

    #[test]
    fn malformed_commands_are_refused() {
        for bad in [
            vec!["services", "settings"],
            vec!["services", "settings", "-x"],
            vec!["services", "env"],
            vec!["services", "env", "show", "x"],
            vec!["services", "env", "set", "x"],
            vec!["services", "env", "set", "x", "--stdin", "--file", "f"],
            vec!["services", "env", "set", "x", "--stdin", "SECRET=hunter2"],
            vec![
                "services", "env", "set", "x", "--value", "hunter2", "--stdin",
            ],
            vec!["services", "env", "unset", "x"],
            vec!["services", "domains", "set", "x"],
            vec![
                "services",
                "domains",
                "set",
                "x",
                "--clear",
                "https://a.test",
            ],
            vec!["services", "health", "set", "x"],
            vec!["services", "health", "set", "x", "--interval", "soon"],
            vec!["services", "settings", "x", "--redeploy"],
            vec!["services", "env", "list", "x", "--reason", "why"],
        ] {
            assert!(fails(&bad), "{bad:?}");
        }
    }

    #[test]
    fn values_come_from_input_and_never_from_arguments() {
        let set = action(&[
            "services", "env", "set", "x", "--stdin", "--key", "TLS_CERT",
        ]);
        let (method, path, query, body) =
            request_with(&set, || Ok("line one\nline two\n".to_owned())).unwrap();
        assert_eq!(method, reqwest::Method::POST);
        assert_eq!(path, "/api/v1/services/x/settings/env");
        assert!(query.is_empty());
        let body = body.unwrap();
        assert_eq!(body["changes"][0]["key"], "TLS_CERT");
        // One trailing newline goes; the value keeps its own lines.
        assert_eq!(body["changes"][0]["value"], "line one\nline two");
        assert_eq!(body["changes"][0]["isPreview"], false);

        // dotenv input: several variables, comments, quotes, export.
        let set = action(&["services", "env", "set", "x", "--stdin", "--literal"]);
        let (_, _, _, body) = request_with(&set, || {
            Ok("# a comment\n\nA=1\nexport B=\"two words\"\nC=a=b\n".to_owned())
        })
        .unwrap();
        let changes = body.unwrap()["changes"].clone();
        assert_eq!(changes.as_array().unwrap().len(), 3);
        assert_eq!(changes[1]["value"], "two words");
        assert_eq!(changes[2]["value"], "a=b");
        assert_eq!(changes[0]["isLiteral"], true);

        // The bad line is named by number, never quoted.
        let set = action(&["services", "env", "set", "x", "--stdin"]);
        let error = request_with(&set, || Ok("A=1\nhunter2-no-equals\n".to_owned()))
            .unwrap_err()
            .message;
        assert!(
            error.contains("line 2") && !error.contains("hunter2"),
            "{error}"
        );
        assert!(request_with(&set, || Ok("\n# nothing\n".to_owned())).is_err());
        let keyed = action(&["services", "env", "set", "x", "--stdin", "--key", "K"]);
        assert!(request_with(&keyed, || Ok("\n".to_owned())).is_err());

        // A file is read from disk.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("values.env");
        std::fs::write(&path, "FROM_FILE=yes\n").unwrap();
        let from_file = action(&[
            "services",
            "env",
            "set",
            "x",
            "--file",
            path.to_str().unwrap(),
        ]);
        let (_, _, _, body) = request_with(&from_file, || panic!("stdin is not read")).unwrap();
        assert_eq!(body.unwrap()["changes"][0]["key"], "FROM_FILE");
    }

    #[test]
    fn other_requests_have_the_documented_shape() {
        let (method, path, _, body) = request_with(
            &action(&[
                "services",
                "env",
                "unset",
                "coolify:a:b",
                "OLD",
                "--redeploy",
            ]),
            || unreachable!(),
        )
        .unwrap();
        assert_eq!(method, reqwest::Method::POST);
        assert_eq!(path, "/api/v1/services/coolify%3Aa%3Ab/settings/env");
        let body = body.unwrap();
        assert_eq!(
            body["changes"][0],
            json!({"op": "unset", "key": "OLD", "isPreview": false})
        );
        assert_eq!(body["redeploy"], true);
        let (_, path, _, body) = request_with(
            &action(&[
                "services",
                "health",
                "set",
                "x",
                "--path",
                "/up",
                "--retries",
                "3",
            ]),
            || unreachable!(),
        )
        .unwrap();
        assert_eq!(path, "/api/v1/services/x/settings/health");
        let body = body.unwrap();
        assert_eq!(body["path"], "/up");
        assert_eq!(body["retries"], 3);
        assert!(body.get("interval").is_none());
        let (method, path, _, body) =
            request_with(&action(&["services", "settings", "x"]), || unreachable!()).unwrap();
        assert_eq!(method, reqwest::Method::GET);
        assert_eq!(path, "/api/v1/services/x/settings");
        assert!(body.is_none());
    }

    #[test]
    fn text_output_shows_names_and_previews_never_values() {
        let view = json!({"data": {
            "serviceId": "coolify:a:b", "name": "web", "resourceKind": "application",
            "env": [{"key": "DATABASE_URL", "isBuildtime": true, "isRuntime": true,
                     "isMultiline": false, "isLiteral": true, "isShownOnce": false,
                     "isPreview": false, "isShared": false}],
            "domains": ["https://shop.example.test"],
            "health": {"enabled": true, "path": "/up", "port": null, "host": null,
                       "method": "GET", "scheme": "http", "returnCode": 200,
                       "interval": 5, "timeout": 5, "retries": 10, "startPeriod": 5},
            "notes": []
        }});
        let text = render_settings(&view, Part::All);
        assert!(
            text.contains("DATABASE_URL") && text.contains("build,runtime,literal"),
            "{text}"
        );
        assert!(text.contains("https://shop.example.test"), "{text}");
        assert!(
            text.contains("enabled GET http://<app>/up -> 200"),
            "{text}"
        );
        assert!(!render_settings(&view, Part::Env).contains("domains"));

        let filed = json!({"data": {
            "id": "r1", "state": "pending", "riskClass": "approve",
            "actionId": "coolify.env.update", "target": "coolify:a:b", "requester": "me",
            "reason": "rotate",
            "parameters": {"redeploy": true, "preview": [
                {"key": "API_URL", "isPreview": false, "operation": "update",
                 "changes": [{"field": "isLiteral", "from": false, "to": true},
                             {"field": "value", "from": "(write-only)", "to": "(write-only, digest ab12)"}]},
                {"key": "OLD", "isPreview": true, "operation": "delete", "changes": []}
            ]}
        }});
        let text = render_change(&filed);
        assert!(
            text.contains("update API_URL [isLiteral: false -> true; value (write-only)]"),
            "{text}"
        );
        assert!(text.contains("delete OLD (preview)"), "{text}");
        assert!(text.contains("then: redeploy"), "{text}");
        let domains = json!({"data": {
            "id": "r2", "state": "pending", "riskClass": "approve",
            "actionId": "coolify.application.domains.set", "target": "t", "requester": "me",
            "reason": "x",
            "parameters": {"preview": {"before": ["a"], "after": ["a", "b"],
                "changes": [{"field": "domains", "from": ["a"], "to": ["a", "b"]}]}}
        }});
        assert!(render_change(&domains).contains("domains: a -> a, b"));
        let waited = json!({"outcome": "executed", "request": filed["data"].clone(),
            "result": {"outcome": "applied", "verified": true, "changed": ["set API_URL"],
                       "followUp": {"verb": "redeploy", "deploymentUuid": "d1"}}});
        let text = render_change(&waited);
        assert!(
            text.contains("result: applied (verified)") && text.contains("set API_URL"),
            "{text}"
        );
        assert!(text.contains("redeploy queued (deployment d1)"), "{text}");
    }
}
