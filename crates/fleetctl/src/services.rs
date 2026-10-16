//! `fleetctl services` (FM-1031): the running-service read model from the
//! command line. An adapter over `/api/v1/services`; the join, the
//! per-input authorization, and the staleness rules are the controller's.
//! `--output json` prints the controller's answer unchanged.

use serde_json::Value;

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
}

/// Parses `services list|get ...`.
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let Some((verb, args)) = rest.split_first() else {
        return Err(CliError { message: usage() });
    };
    let (id, flags) = match *verb {
        "get" => {
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
    let mut flags = flags.iter().copied();
    while let Some(flag) = flags.next() {
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
        _ => return Err(CliError { message: usage() }),
    };
    Ok(Command::Services(action))
}

/// The controller request for one subcommand.
pub(crate) fn request(action: &ServicesAction) -> RequestShape {
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
        let (method, path, query, body) = request(&ServicesAction::Get {
            id: "docker:m 1:redis/x".to_owned(),
        });
        assert_eq!(method, reqwest::Method::GET);
        assert_eq!(path, "/api/v1/services/docker%3Am%201%3Aredis%2Fx");
        assert!(query.is_empty() && body.is_none());
        let (_, path, query, _) = request(&ServicesAction::List {
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
}
