//! `fleetctl services` (FM-1031): the running-service read model from the
//! command line. An adapter over `/api/v1/services`; the join, the
//! per-input authorization, and the staleness rules are the controller's.
//! `--output json` prints the controller's answer unchanged.

use std::fmt::Write as _;
use std::time::Duration;

use serde_json::{Value, json};

pub mod settings;

use crate::requests::parse_wait_approval;
use crate::{CliError, Command, Output, RequestShape, usage};

/// One `services` subcommand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServicesAction {
    /// List running services.
    List {
        /// Only this source: `coolify` or `docker`.
        source: Option<String>,
        /// Only services placed on this machine id.
        machine: Option<String>,
        /// Only services whose name or hostname contains this text.
        query: Option<String>,
        /// The page size.
        limit: Option<u32>,
        /// The `nextCursor` of the previous page.
        cursor: Option<String>,
    },
    /// Read one service.
    Get {
        /// The service id, as `list` prints it.
        id: String,
    },
    /// File a lifecycle action on a Coolify service (FM-1033).
    Action {
        /// `start`, `stop`, `restart`, or `redeploy`.
        verb: String,
        /// The service id.
        id: String,
        /// Why, for the approver.
        reason: Option<String>,
        /// A key making a retry return the request already made.
        idempotency_key: Option<String>,
        /// Wait this long for the request to reach an outcome.
        wait: Option<Duration>,
    },
    /// Settings of a Coolify resource (FM-1034): environment variables,
    /// domains, and health checks.
    Settings(settings::SettingsAction),
    /// Tail a Coolify application's deployment log (FM-1033).
    Logs {
        /// The service id.
        id: String,
        /// A deployment uuid; the newest when absent.
        deployment: Option<String>,
        /// How many trailing lines.
        lines: Option<u32>,
    },
}

/// Parses `services list|get ...`.
#[allow(clippy::too_many_lines)]
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let Some((verb, args)) = rest.split_first() else {
        return Err(CliError { message: usage() });
    };
    if matches!(*verb, "settings" | "env" | "domains" | "health") {
        return settings::parse(rest, output)
            .map(|action| Command::Services(ServicesAction::Settings(action)));
    }
    let (id, flags) = match *verb {
        "get" | "start" | "stop" | "restart" | "redeploy" | "logs" => {
            let Some((id, flags)) = args.split_first() else {
                return Err(CliError { message: usage() });
            };
            // An empty id or a leading `-` is a flag or a typo, never an id.
            if id.is_empty() || id.starts_with('-') {
                return Err(CliError { message: usage() });
            }
            (Some((*id).to_owned()), flags)
        }
        "list" => (None, args),
        _ => return Err(CliError { message: usage() }),
    };
    let mut source = None;
    let mut machine = None;
    let mut query = None;
    let mut limit = None;
    let mut cursor = None;
    let mut reason = None;
    let mut idempotency_key = None;
    let mut wait = None;
    let mut deployment = None;
    let mut lines = None;
    let lifecycle = matches!(*verb, "start" | "stop" | "restart" | "redeploy");
    let mut flags = flags.iter().copied();
    while let Some(flag) = flags.next() {
        if lifecycle && let Some(duration) = parse_wait_approval("--wait-approval", flag)? {
            wait = Some(duration);
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
        match (*verb, flag) {
            (_, "--output") => {
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
            ("list", "--source") => source = Some(value("source")?),
            ("list", "--machine") => machine = Some(value("machine")?),
            ("list", "--query") => query = Some(value("query")?),
            ("list", "--cursor") => cursor = Some(value("cursor")?),
            ("list", "--limit") => {
                let raw = value("limit")?;
                limit = Some(raw.parse().map_err(|_| CliError {
                    message: format!("--limit must be a number, not {raw:?}"),
                })?);
            }
            ("start" | "stop" | "restart" | "redeploy", "--reason") => {
                reason = Some(value("reason")?);
            }
            ("start" | "stop" | "restart" | "redeploy", "--idempotency-key") => {
                idempotency_key = Some(value("idempotency-key")?);
            }
            ("logs", "--deployment") => deployment = Some(value("deployment")?),
            ("logs", "--lines") => {
                let raw = value("lines")?;
                lines = Some(raw.parse().map_err(|_| CliError {
                    message: format!("--lines must be a number, not {raw:?}"),
                })?);
            }
            (_, other) => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let action = match (*verb, id) {
        ("list", _) => ServicesAction::List {
            source,
            machine,
            query,
            limit,
            cursor,
        },
        ("get", Some(id)) => ServicesAction::Get { id },
        ("start" | "stop" | "restart" | "redeploy", Some(id)) => ServicesAction::Action {
            verb: (*verb).to_owned(),
            id,
            reason,
            idempotency_key,
            wait,
        },
        ("logs", Some(id)) => ServicesAction::Logs {
            id,
            deployment,
            lines,
        },
        _ => return Err(CliError { message: usage() }),
    };
    Ok(Command::Services(action))
}

impl ServicesAction {
    /// The wait of a command that files an action request: `Some(wait)` for
    /// a lifecycle or settings change, `None` for a read.
    #[must_use]
    pub fn filing_wait(&self) -> Option<Option<Duration>> {
        match self {
            Self::Action { wait, .. } => Some(*wait),
            Self::Settings(action) => action.filing_wait(),
            _ => None,
        }
    }
}

/// The controller request for one subcommand.
///
/// # Errors
///
/// Fails when a settings command cannot read its input.
pub(crate) fn request(action: &ServicesAction) -> Result<RequestShape, CliError> {
    if let ServicesAction::Settings(action) = action {
        return settings::request(action);
    }
    Ok(request_of(action))
}

fn request_of(action: &ServicesAction) -> RequestShape {
    match action {
        ServicesAction::List {
            source,
            machine,
            query,
            limit,
            cursor,
        } => (
            reqwest::Method::GET,
            "/api/v1/services".to_owned(),
            source
                .iter()
                .map(|v| ("source", v.clone()))
                .chain(machine.iter().map(|v| ("machine", v.clone())))
                .chain(query.iter().map(|v| ("q", v.clone())))
                .chain(limit.iter().map(|v| ("limit", v.to_string())))
                .chain(cursor.iter().map(|v| ("cursor", v.clone())))
                .collect(),
            None,
        ),
        ServicesAction::Get { id } => (
            reqwest::Method::GET,
            format!("/api/v1/services/{}", encode(id)),
            Vec::new(),
            None,
        ),
        ServicesAction::Action {
            verb,
            id,
            reason,
            idempotency_key,
            ..
        } => {
            let mut body = json!({ "reason": reason.clone().unwrap_or_default() });
            if let Some(key) = idempotency_key {
                body["idempotencyKey"] = json!(key);
            }
            (
                reqwest::Method::POST,
                format!("/api/v1/services/{}/actions/{}", encode(id), encode(verb)),
                Vec::new(),
                Some(body),
            )
        }
        ServicesAction::Settings(_) => unreachable!("handled by request"),
        ServicesAction::Logs {
            id,
            deployment,
            lines,
        } => (
            reqwest::Method::GET,
            format!("/api/v1/services/{}/logs", encode(id)),
            deployment
                .iter()
                .map(|v| ("deployment", v.clone()))
                .chain(lines.iter().map(|v| ("lines", v.to_string())))
                .collect(),
            None,
        ),
    }
}

/// Percent-encodes one path segment: only unreserved characters pass.
fn encode(segment: &str) -> String {
    use std::fmt::Write as _;
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

/// Server-supplied text for a terminal: control characters become spaces.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn text_of(value: &Value) -> String {
    clean(value.as_str().unwrap_or("-"))
}

fn row(service: &Value) -> String {
    let placement = &service["placement"];
    let place = match placement["state"].as_str() {
        Some("matched") => text_of(&placement["machine"]["name"]),
        Some(other) => other.to_owned(),
        None => "-".to_owned(),
    };
    let sources = service["sources"]
        .as_array()
        .map(|sources| {
            sources
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("+")
        })
        .unwrap_or_default();
    let stale = if service["stale"].as_bool().unwrap_or(false) {
        " (stale)"
    } else {
        ""
    };
    format!(
        "{:<28} {:<11} {:<14} {:<10} {:<20} {}{stale}",
        text_of(&service["name"]),
        text_of(&service["kind"]),
        clean(&sources),
        text_of(&service["state"]),
        clean(&place),
        service["fqdns"]
            .as_array()
            .map(|f| f
                .iter()
                .filter_map(Value::as_str)
                .map(clean)
                .collect::<Vec<_>>()
                .join(","))
            .unwrap_or_default(),
    )
}

fn coverage_lines(coverage: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    for input in ["coolify", "machines", "containers", "registry"] {
        let state = coverage[input]["state"].as_str().unwrap_or("-");
        if state != "available" {
            lines.push(format!("  {input}: {}", clean(state)));
        }
    }
    lines
}

/// Renders the answer to `action`; a Docker-only listing against a
/// controller with no container observations says why it is empty.
pub(crate) fn render_for(action: &ServicesAction, value: &Value) -> String {
    match action {
        ServicesAction::Action { .. } => return render_action(value),
        ServicesAction::Logs { .. } => return render_logs(value),
        ServicesAction::Settings(action) => return settings::render_for(action, value),
        _ => {}
    }
    let mut text = render(value);
    let docker_only = matches!(
        action,
        ServicesAction::List { source: Some(source), .. } if source == "docker"
    );
    if docker_only && value["coverage"]["containers"]["state"].as_str() == Some("not_configured") {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(
            "hint: this controller stores no Docker container observations yet, so --source docker lists nothing",
        );
    }
    text
}

/// Renders a filed request or a wait's answer, with the operation result
/// (status before and after) when there is one.
fn render_action(value: &Value) -> String {
    let mut text = crate::requests::render(value);
    if let Some(warning) = value["resultWarning"].as_str() {
        let _ = write!(text, "\n  warning: {}", clean(warning));
    }
    let result = &value["result"];
    if result.is_object() {
        let field = |name: &str| text_of(&result[name]);
        let _ = write!(
            text,
            "\n  result: {} ({} -> {}{})",
            field("outcome"),
            field("previousStatus"),
            field("observedStatus"),
            if result["settled"].as_bool() == Some(false) {
                ", not settled yet"
            } else {
                ""
            }
        );
        if let Some(deployment) = result["deploymentUuid"].as_str() {
            let _ = write!(
                text,
                "\n  deployment: {} (fleetctl services logs <id> --deployment {})",
                clean(deployment),
                clean(deployment)
            );
        }
    }
    text
}

/// Renders a log tail: the lines, then one note when anything was cut or
/// redacted. The lines are server text, so control characters are flattened.
fn render_logs(value: &Value) -> String {
    let data = value.get("data").unwrap_or(value);
    let mut lines: Vec<String> = data["lines"]
        .as_array()
        .map(|lines| lines.iter().filter_map(Value::as_str).map(clean).collect())
        .unwrap_or_default();
    let mut notes = Vec::new();
    if data["truncated"].as_bool() == Some(true) {
        notes.push("earlier lines were cut");
    }
    if data["redacted"].as_bool() == Some(true) {
        notes.push("credentials were redacted");
    }
    if lines.is_empty() {
        lines.push("(no log lines)".to_owned());
    }
    lines.push(format!(
        "-- deployment {} ({}){}",
        text_of(&data["deploymentUuid"]),
        text_of(&data["deploymentStatus"]),
        if notes.is_empty() {
            String::new()
        } else {
            format!("; {}", notes.join(", "))
        }
    ));
    lines.join("\n")
}

/// Renders a list page or one service as human text.
pub(crate) fn render(value: &Value) -> String {
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        let mut lines = Vec::new();
        if items.is_empty() {
            lines.push("(no services)".to_owned());
        } else {
            lines.push(format!(
                "{:<28} {:<11} {:<14} {:<10} {:<20} FQDNS",
                "NAME", "KIND", "SOURCE", "STATE", "MACHINE"
            ));
            lines.extend(items.iter().map(row));
        }
        if let Some(ambiguous) = value["ambiguousServers"].as_array() {
            for server in ambiguous {
                lines.push(format!(
                    "ambiguous: Coolify server {} matches {} machines",
                    text_of(&server["server"]["name"]),
                    server["candidates"].as_array().map_or(0, Vec::len)
                ));
            }
        }
        let coverage = coverage_lines(&value["coverage"]);
        if !coverage.is_empty() {
            lines.push("not fully covered:".to_owned());
            lines.extend(coverage);
        }
        if let Some(cursor) = value["page"]["nextCursor"].as_str() {
            lines.push(format!(
                "next page: --cursor '{}'",
                clean(cursor).replace('\'', "'\\''")
            ));
        }
        return lines.join("\n");
    }
    let data = value.get("data").unwrap_or(value);
    let service = &data["service"];
    if service.get("id").is_none() {
        return String::new();
    }
    let mut lines = vec![row(service), format!("  id: {}", text_of(&service["id"]))];
    if let Some(link) = service["deepLink"].as_str() {
        lines.push(format!("  coolify: {}", clean(link)));
    }
    if let Some(reasons) = service["staleReasons"].as_array()
        && !reasons.is_empty()
    {
        lines.push(format!(
            "  stale: {}",
            reasons
                .iter()
                .filter_map(Value::as_str)
                .map(clean)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(links) = service["registry"].as_array() {
        for link in links {
            lines.push(format!(
                "  registry: {}/{} ({})",
                text_of(&link["type"]),
                text_of(&link["key"]),
                text_of(&link["link"])
            ));
        }
    }
    lines.extend(coverage_lines(&data["coverage"]));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn action(words: &[&str]) -> ServicesAction {
        let args: Vec<String> = words.iter().map(ToString::to_string).collect();
        match crate::parse(&args).expect("parses").command {
            Command::Services(action) => action,
            other => panic!("not a services command: {other:?}"),
        }
    }

    #[test]
    fn the_grammar_covers_list_and_get() {
        assert_eq!(
            action(&["services", "list", "--source", "coolify", "--limit", "5"]),
            ServicesAction::List {
                source: Some("coolify".to_owned()),
                machine: None,
                query: None,
                limit: Some(5),
                cursor: None,
            }
        );
        assert_eq!(
            action(&["services", "get", "coolify:a:b"]),
            ServicesAction::Get {
                id: "coolify:a:b".to_owned()
            }
        );
        for bad in [
            vec!["services"],
            vec!["services", "get"],
            vec!["services", "get", "-x"],
            vec!["services", "list", "--bogus"],
            vec!["services", "get", "a", "--source", "docker"],
        ] {
            let args: Vec<String> = bad.iter().map(ToString::to_string).collect();
            assert!(crate::parse(&args).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn requests_are_reads_with_encoded_ids() {
        let (method, path, query, body) = request_of(&ServicesAction::Get {
            id: "docker:m 1:redis/x".to_owned(),
        });
        assert_eq!(method, reqwest::Method::GET);
        assert_eq!(path, "/api/v1/services/docker%3Am%201%3Aredis%2Fx");
        assert!(query.is_empty() && body.is_none());
        let (_, path, query, _) = request_of(&ServicesAction::List {
            source: Some("docker".to_owned()),
            machine: None,
            query: Some("web".to_owned()),
            limit: None,
            cursor: None,
        });
        assert_eq!(path, "/api/v1/services");
        assert_eq!(
            query,
            vec![("source", "docker".to_owned()), ("q", "web".to_owned())]
        );
    }

    #[test]
    fn text_output_shows_placement_staleness_and_gaps() {
        let page = json!({
            "items": [{
                "id": "coolify:a:b", "name": "web", "kind": "application",
                "sources": ["coolify", "docker"], "state": "running",
                "placement": {"state": "matched", "machine": {"id": "m", "name": "box"}},
                "fqdns": ["https://shop.example.test"], "stale": true
            }],
            "page": {"nextCursor": null, "limit": 50},
            "ambiguousServers": [{"server": {"name": "edge"}, "candidates": [{}, {}]}],
            "coverage": {"coolify": {"state": "available"}, "machines": {"state": "available"},
                "containers": {"state": "not_configured"}, "registry": {"state": "denied"}}
        });
        let text = render(&page);
        assert!(
            text.contains("box") && text.contains("coolify+docker"),
            "{text}"
        );
        assert!(text.contains("(stale)"), "{text}");
        assert!(
            text.contains("Coolify server edge matches 2 machines"),
            "{text}"
        );
        assert!(text.contains("containers: not_configured"), "{text}");
        assert!(text.contains("registry: denied"), "{text}");
    }

    #[test]
    fn a_docker_listing_without_container_observations_says_why() {
        let page = json!({
            "items": [], "page": {"nextCursor": null, "limit": 50},
            "coverage": {"containers": {"state": "not_configured"}}
        });
        let docker = ServicesAction::List {
            source: Some("docker".to_owned()),
            machine: None,
            query: None,
            limit: None,
            cursor: None,
        };
        assert!(render_for(&docker, &page).contains("hint: this controller stores no Docker"));
        let all = ServicesAction::List {
            source: None,
            machine: None,
            query: None,
            limit: None,
            cursor: None,
        };
        assert!(!render_for(&all, &page).contains("hint:"));
    }
}
