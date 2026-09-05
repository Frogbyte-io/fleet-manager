//! The `fleetctl` command line: the human and agent surface over the same
//! public API the web app uses.
//!
//! There is no second authority here and no private transport: every command
//! is one HTTP call to the controller's `/api/v1`, so the CLI sees exactly
//! what the web sees — the same envelopes, the same error codes, the same
//! correlation identity. Output is either aligned human text or stable JSON
//! (`--output json`), which is the mode Fleet skills consume.
//!
//! The implementation is a library plus a thin binary so the contract can be
//! exercised in tests against a real controller.

use std::fmt;

use serde_json::Value;

/// The controller address used when `--url` is absent: the safe default, the
/// controller's own documented loopback listener.
pub const DEFAULT_URL: &str = "http://127.0.0.1:8080";

/// The state directory `fleetctl status` consults when `--socket` is absent,
/// the same default `fleetd` uses.
pub const DEFAULT_SOCKET: &str = "fleetd-state/local.sock";

/// A CLI failure: what went wrong and where the message belongs.
#[derive(Debug)]
pub struct CliError {
    /// Caller-safe message, printed to stderr.
    pub message: String,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// The parsed command line.
#[derive(Clone, Debug, PartialEq)]
pub struct Invocation {
    /// The controller base URL.
    pub url: String,
    /// Whether `--url` was given: the explicit direct-controller override
    /// for the `status` command's route selection.
    pub url_explicit: bool,
    /// The local socket path for the `status` command.
    pub socket: String,
    /// The output mode.
    pub output: Output,
    /// The command and its arguments.
    pub command: Command,
}

/// The output mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Output {
    /// Aligned human-readable text (the default).
    Text,
    /// Stable JSON for scripts and Fleet skills.
    Json,
}

/// The commands `fleetctl` knows.
#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    /// The node and Fleet read status. Prefers the node's local socket
    /// unless `--url` names the controller explicitly.
    Status,
    /// The system view.
    System,
    /// List operations.
    OperationsList {
        /// Maximum entries to request.
        limit: Option<u32>,
    },
    /// Read one operation.
    OperationsGet {
        /// The operation id.
        id: String,
    },
    /// Request cancellation of an operation.
    OperationsCancel {
        /// The operation id.
        id: String,
    },
    /// List machines with optional filters.
    MachinesList {
        /// Only machines carrying this tag.
        tag: Option<String>,
        /// Only machines in this group.
        group: Option<String>,
        /// Only machines carrying this capability, as `namespace:name`.
        capability: Option<String>,
        /// Only machines in this state.
        status: Option<String>,
        /// Maximum entries to request.
        limit: Option<u32>,
    },
    /// Read one machine.
    MachinesGet {
        /// The machine id.
        id: String,
    },
}

/// Parses the command line.
///
/// # Errors
///
/// Fails with a caller-safe usage message on anything unexpected.
pub fn parse(args: &[String]) -> Result<Invocation, CliError> {
    let mut url = DEFAULT_URL.to_owned();
    let mut url_explicit = false;
    let mut socket = DEFAULT_SOCKET.to_owned();
    let mut output = Output::Text;
    let mut rest = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--help" | "-h" | "--version" | "-V" => {
                // Handled by the binary before parsing; treat as usage here.
                return Err(CliError { message: usage() });
            }
            "--url" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| CliError {
                    message: "--url requires a value".to_owned(),
                })?;
                value.trim_end_matches('/').clone_into(&mut url);
                url_explicit = true;
            }
            "--socket" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| CliError {
                    message: "--socket requires a path".to_owned(),
                })?;
                value.clone_into(&mut socket);
            }
            "--output" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| CliError {
                    message: "--output requires json or text".to_owned(),
                })?;
                output = match value.as_str() {
                    "json" => Output::Json,
                    "text" => Output::Text,
                    other => {
                        return Err(CliError {
                            message: format!("--output must be json or text, not {other:?}"),
                        });
                    }
                };
            }
            _ => rest.push(args[index].clone()),
        }
        index += 1;
    }

    let words: Vec<&str> = rest.iter().map(String::as_str).collect();
    let command = match words.as_slice() {
        ["status"] => Command::Status,
        ["system"] => Command::System,
        ["operations", "list"] => Command::OperationsList { limit: None },
        ["operations", "list", "--limit", value] => Command::OperationsList {
            limit: Some(value.parse().map_err(|_| CliError {
                message: format!("--limit must be a number, not {value:?}"),
            })?),
        },
        ["operations", "get", id] => Command::OperationsGet {
            id: (*id).to_owned(),
        },
        ["operations", "cancel", id] => Command::OperationsCancel {
            id: (*id).to_owned(),
        },
        ["machines", "list", rest @ ..] => parse_machines_list(rest)?,
        ["machines", "get", id] => Command::MachinesGet {
            id: (*id).to_owned(),
        },
        _ => return Err(CliError { message: usage() }),
    };
    Ok(Invocation {
        url,
        url_explicit,
        socket,
        output,
        command,
    })
}

/// Parses the flags of `machines list`; each takes one value.
fn parse_machines_list(rest: &[&str]) -> Result<Command, CliError> {
    let mut tag: Option<String> = None;
    let mut group: Option<String> = None;
    let mut capability: Option<String> = None;
    let mut status: Option<String> = None;
    let mut limit = None;
    let mut flags = rest.iter().copied();
    while let Some(flag) = flags.next() {
        let mut value = |name: &str| {
            flags.next().ok_or_else(|| CliError {
                message: format!("--{name} requires a value"),
            })
        };
        match flag {
            "--tag" => tag = Some(value("tag")?.to_owned()),
            "--group" => group = Some(value("group")?.to_owned()),
            "--capability" => capability = Some(value("capability")?.to_owned()),
            "--status" => status = Some(value("status")?.to_owned()),
            "--limit" => {
                let parsed = value("limit")?;
                limit = Some(parsed.parse().map_err(|_| CliError {
                    message: format!("--limit must be a number, not {parsed:?}"),
                })?);
            }
            other => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    Ok(Command::MachinesList {
        tag,
        group,
        capability,
        status,
        limit,
    })
}

fn usage() -> String {
    format!(
        "Usage: fleetctl [--url <controller>] [--socket <path>] [--output json|text] <command>\n\nCommands:\n  status\n  system\n  operations list [--limit <n>]\n  operations get <id>\n  operations cancel <id>\n  machines list [--tag <tag>] [--group <group>] [--capability <ns:name>] [--status <state>] [--limit <n>]\n  machines get <id>\n\n`status` prefers the node's local socket (default {DEFAULT_SOCKET}); `--url` is the explicit direct-controller override. Other commands talk to the controller, which defaults to {DEFAULT_URL}."
    )
}

/// Runs one invocation, returning the text for stdout.
///
/// # Errors
///
/// Fails with a message for stderr on any refused or failed request; the
/// error's envelope code, when the controller produced one, is included so
/// scripts can branch on it.
pub fn run(invocation: &Invocation) -> Result<String, CliError> {
    if invocation.command == Command::Status && !invocation.url_explicit {
        // The local route: the daemon's constrained status surface, reached
        // without controller credentials. The override is explicit --url.
        let body = local_status(&invocation.socket)?;
        return render_routed(invocation, &body, "local");
    }
    if invocation.command == Command::Status {
        // The explicit direct-controller override.
        let client = http_client()?;
        let response = client
            .get(format!("{}/api/v1/system", invocation.url))
            .header("x-correlation-id", uuid::Uuid::now_v7().to_string())
            .send()
            .map_err(|error| CliError {
                message: format!("the controller did not answer: {error}"),
            })?;
        let status = reqwest::StatusCode::as_u16(&response.status());
        let body: Value = response.json().map_err(|error| CliError {
            message: format!("the controller's answer was not JSON: {error}"),
        })?;
        if !(200..300).contains(&status) {
            let code = body["code"].as_str().unwrap_or("unknown");
            let message = body["message"].as_str().unwrap_or("no detail");
            return Err(CliError {
                message: format!("the controller refused ({status}, {code}): {message}"),
            });
        }
        return render_routed(invocation, &body, "controller");
    }

    let correlation_id = uuid::Uuid::now_v7().to_string();
    let client = http_client()?;

    let (method, path, query) = match &invocation.command {
        // `status` took one of the two routes above.
        Command::Status => unreachable!("the status command returned before dispatch"),
        Command::System => (
            reqwest::Method::GET,
            "/api/v1/system".to_owned(),
            Vec::new(),
        ),
        Command::OperationsList { .. } => {
            let limit = match invocation.command {
                Command::OperationsList { limit: Some(limit) } => format!("?limit={limit}"),
                _ => String::new(),
            };
            (
                reqwest::Method::GET,
                format!("/api/v1/operations{limit}"),
                Vec::new(),
            )
        }
        Command::OperationsGet { id } => (
            reqwest::Method::GET,
            format!("/api/v1/operations/{id}"),
            Vec::new(),
        ),
        Command::OperationsCancel { id } => (
            reqwest::Method::POST,
            format!("/api/v1/operations/{id}/cancel"),
            Vec::new(),
        ),
        Command::MachinesList {
            tag,
            group,
            capability,
            status,
            limit,
        } => (
            reqwest::Method::GET,
            "/api/v1/machines".to_owned(),
            machines_list_query(
                tag.as_ref(),
                group.as_ref(),
                capability.as_ref(),
                status.as_ref(),
                *limit,
            ),
        ),
        Command::MachinesGet { id } => (
            reqwest::Method::GET,
            format!("/api/v1/machines/{id}"),
            Vec::new(),
        ),
    };

    let body = send(&client, invocation, method, &path, &query, correlation_id)?;

    let is_page = body.get("items").is_some();
    let payload = if is_page {
        body.clone()
    } else {
        body.get("data").cloned().unwrap_or(body)
    };
    Ok(match invocation.output {
        Output::Json => serde_json::to_string_pretty(&payload).map_err(|error| CliError {
            message: format!("cannot render the answer: {error}"),
        })?,
        Output::Text => match invocation.command {
            // The machine surface has its own renderer: an empty page must
            // say "no machines", not borrow the operations table.
            Command::MachinesList { .. } | Command::MachinesGet { .. } => {
                render_machines(Some(&payload))
            }
            _ => render_text(Some(&payload)),
        },
    })
}

/// The machines-list query parameters, in API order.
fn machines_list_query(
    tag: Option<&String>,
    group: Option<&String>,
    capability: Option<&String>,
    status: Option<&String>,
    limit: Option<u32>,
) -> Vec<(&'static str, String)> {
    let mut query: Vec<(&'static str, String)> = Vec::new();
    for (name, value) in [
        ("tag", tag),
        ("group", group),
        ("capability", capability),
        ("status", status),
    ] {
        if let Some(value) = value {
            query.push((name, value.clone()));
        }
    }
    if let Some(limit) = limit {
        query.push(("limit", limit.to_string()));
    }
    query
}

/// Sends one controller request and answers the decoded body, refusing
/// non-2xx answers with the envelope's code and message.
fn send(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    method: reqwest::Method,
    path: &str,
    query: &[(&'static str, String)],
    correlation_id: String,
) -> Result<Value, CliError> {
    let mut request = client
        .request(method, format!("{}{}", invocation.url, path))
        .header("x-correlation-id", correlation_id);
    if !query.is_empty() {
        request = request.query(query);
    }
    let response = request.send().map_err(|error| CliError {
        message: format!("the controller did not answer: {error}"),
    })?;
    let status = reqwest::StatusCode::as_u16(&response.status());
    let body: Value = response.json().map_err(|error| CliError {
        message: format!("the controller's answer was not JSON: {error}"),
    })?;
    if !(200..300).contains(&status) {
        let code = body["code"].as_str().unwrap_or("unknown");
        let message = body["message"].as_str().unwrap_or("no detail");
        return Err(CliError {
            message: format!("the controller refused ({status}, {code}): {message}"),
        });
    }
    Ok(body)
}

fn http_client() -> Result<reqwest::blocking::Client, CliError> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|error| CliError {
            message: format!("cannot build an HTTP client: {error}"),
        })
}

/// Reads the node's local status surface over the Unix socket, without any
/// controller credential.
fn local_status(socket: &str) -> Result<Value, CliError> {
    use std::io::{Read as _, Write as _};
    let mut stream = std::os::unix::net::UnixStream::connect(socket).map_err(|error| CliError {
        message: format!(
            "the node's local surface at {socket} is unreachable: {error}; \
                 is `fleetd run` active, or pass --url to talk to the controller directly?"
        ),
    })?;
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
    stream
        .write_all(b"GET /local/status HTTP/1.1\r\nHost: fleetd-local\r\nConnection: close\r\n\r\n")
        .map_err(|error| CliError {
            message: format!("the local request failed: {error}"),
        })?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| CliError {
            message: format!("the local response failed: {error}"),
        })?;
    let text = String::from_utf8_lossy(&response);
    let (_head, body) = text.split_once("\r\n\r\n").ok_or_else(|| CliError {
        message: "the local answer has no body separator".to_owned(),
    })?;
    serde_json::from_str(body.trim()).map_err(|error| CliError {
        message: format!("the local answer is not JSON: {error}"),
    })
}

/// Wraps a status body with its route and renders it.
fn render_routed(
    invocation: &Invocation,
    body: &Value,
    route: &'static str,
) -> Result<String, CliError> {
    let payload = serde_json::json!({ "route": route, "status": body });
    Ok(match invocation.output {
        Output::Json => serde_json::to_string_pretty(&payload).map_err(|error| CliError {
            message: format!("cannot render the answer: {error}"),
        })?,
        Output::Text => render_for_test(&payload),
    })
}

/// Renders one JSON value (or a page) as aligned human text.
/// Renders a JSON payload as human text; exposed for contract tests.
#[doc(hidden)]
#[must_use]
pub fn render_for_test(value: &Value) -> String {
    render_text(Some(value))
}

/// Renders the machine surface as human text; exposed for contract tests.
#[doc(hidden)]
#[must_use]
pub fn render_machines_for_test(value: &Value) -> String {
    render_machines(Some(value))
}

fn render_machines(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        let mut lines = vec![format!(
            "{:<24} {:<10} {:<32} {}",
            "NAME", "STATUS", "ENDPOINT", "TAGS"
        )];
        for item in items {
            lines.push(machine_line(item));
        }
        if items.is_empty() {
            lines.push("(no machines)".to_owned());
        }
        lines.join("\n")
    } else {
        machine_detail(value)
    }
}

fn render_text(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        let mut lines = vec![format!("{:<38} {:<10} {:<12}", "ID", "KIND", "STATE")];
        for item in items {
            lines.push(operation_line(item));
        }
        if items.is_empty() {
            lines.push("(no operations)".to_owned());
        }
        lines.join("\n")
    } else if value.get("kind").is_some() && value.get("state").is_some() {
        operation_detail(value)
    } else {
        // System view.
        let mut lines = Vec::new();
        for (key, val) in value.as_object().into_iter().flatten() {
            let rendered = match val {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            lines.push(format!("{key}: {rendered}"));
        }
        lines.join("\n")
    }
}

fn operation_line(operation: &Value) -> String {
    format!(
        "{:<38} {:<10} {:<12}",
        operation["id"].as_str().unwrap_or("-"),
        operation["kind"].as_str().unwrap_or("-"),
        operation["state"].as_str().unwrap_or("-")
    )
}

fn machine_line(machine: &Value) -> String {
    let endpoint = machine["endpoints"]
        .as_array()
        .and_then(|endpoints| endpoints.first())
        .and_then(|endpoint| endpoint["reference"].as_str())
        .unwrap_or("-");
    let tags = machine["tags"]
        .as_array()
        .map(|tags| {
            tags.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    format!(
        "{:<24} {:<10} {:<32} {}",
        machine["name"].as_str().unwrap_or("-"),
        machine["machineStatus"].as_str().unwrap_or("-"),
        endpoint,
        tags
    )
}

fn machine_detail(machine: &Value) -> String {
    let mut lines = Vec::new();
    for key in [
        "id",
        "name",
        "description",
        "machineStatus",
        "lastSeenAt",
        "createdAt",
        "updatedAt",
    ] {
        if let Some(value) = machine.get(key) {
            let rendered = match value {
                Value::String(text) => text.clone(),
                Value::Null => continue,
                other => other.to_string(),
            };
            lines.push(format!("{key}: {rendered}"));
        }
    }
    for (label, key) in [
        ("endpoints", "endpoints"),
        ("tags", "tags"),
        ("groups", "groups"),
    ] {
        if let Some(items) = machine.get(key).and_then(Value::as_array) {
            let rendered = items
                .iter()
                .map(|item| match (key, item) {
                    ("endpoints", endpoint) => format!(
                        "  {} {}",
                        endpoint["kind"].as_str().unwrap_or("-"),
                        endpoint["reference"].as_str().unwrap_or("-")
                    ),
                    (_, tag) => format!("  {}", tag.as_str().unwrap_or("-")),
                })
                .collect::<Vec<_>>()
                .join("\n");
            lines.push(format!(
                "{label}:{}{}",
                if rendered.is_empty() { " (none)" } else { "" },
                if rendered.is_empty() {
                    String::new()
                } else {
                    format!("\n{rendered}")
                }
            ));
        }
    }
    if let Some(observation) = machine.get("lastObservation")
        && !observation.is_null()
    {
        lines.push(format!(
            "lastObservation: {} at {}",
            observation["source"].as_str().unwrap_or("-"),
            observation["collectedAt"]
        ));
    }
    if let Some(capabilities) = machine.get("capabilities").and_then(Value::as_array) {
        if capabilities.is_empty() {
            lines.push("capabilities: (none observed)".to_owned());
        } else {
            lines.push("capabilities:".to_owned());
            for fact in capabilities {
                lines.push(format!(
                    "  {}.{} = {} ({}, {}) at {}",
                    fact["namespace"].as_str().unwrap_or("-"),
                    fact["name"].as_str().unwrap_or("-"),
                    fact["value"].as_str().unwrap_or("–"),
                    fact["status"].as_str().unwrap_or("-"),
                    fact["source"].as_str().unwrap_or("-"),
                    fact["observedAt"]
                ));
            }
        }
    }
    lines.join("\n")
}

fn operation_detail(operation: &Value) -> String {
    let mut lines = Vec::new();
    for (key, val) in operation.as_object().into_iter().flatten() {
        let rendered = match val {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        lines.push(format!("{key}: {rendered}"));
    }
    lines.join("\n")
}
