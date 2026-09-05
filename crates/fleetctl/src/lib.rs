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
    /// Create an Add Machine onboarding draft from address and auth mode.
    MachinesOnboardCreate {
        /// The remote login user.
        user: String,
        /// The host or address.
        host: String,
        /// The TCP port; 22 when omitted.
        port: Option<u16>,
        /// The proposed machine name; derived from the host when omitted.
        name: Option<String>,
        /// Operator notes carried onto the machine.
        description: Option<String>,
        /// Tags carried onto the machine.
        tags: Vec<String>,
        /// Groups carried onto the machine.
        groups: Vec<String>,
        /// How the controller would authenticate.
        auth: OnboardAuthArg,
    },
    /// List onboarding drafts.
    MachinesOnboardList {
        /// Maximum entries to request.
        limit: Option<u32>,
    },
    /// Read one draft in full: the review surface.
    MachinesOnboardGet {
        /// The draft id.
        id: String,
    },
    /// Run the test stage: probe the host key, and once confirmed, test
    /// authentication. With `--wait`, poll the operation and print the
    /// refreshed draft.
    MachinesOnboardTest {
        /// The draft id.
        id: String,
        /// Poll the operation to a terminal state, then print the draft.
        wait: bool,
        /// The poll bound, in seconds (with `--wait`).
        timeout: u64,
    },
    /// Run the discover stage: the agentless inventory probe into the
    /// draft, only against a confirmed fingerprint.
    MachinesOnboardDiscover {
        /// The draft id.
        id: String,
        /// Poll the operation to a terminal state, then print the draft.
        wait: bool,
        /// The poll bound, in seconds (with `--wait`).
        timeout: u64,
    },
    /// Confirm the observed fingerprint explicitly (trust-on-first-use).
    MachinesOnboardConfirm {
        /// The draft id.
        id: String,
        /// The OpenSSH `SHA256:` fingerprint to confirm.
        fingerprint: String,
    },
    /// Complete onboarding: register the machine from the draft.
    MachinesOnboardAdd {
        /// The draft id.
        id: String,
    },
    /// Cancel a draft: the row is deleted and an unregistered host's pins
    /// are removed.
    MachinesOnboardCancel {
        /// The draft id.
        id: String,
    },
}

/// How the CLI spells the draft's authentication mode.
#[derive(Clone, Debug, PartialEq)]
pub enum OnboardAuthArg {
    /// The controller's running agent supplies the key.
    Agent,
    /// An identity file, by path.
    IdentityFile(String),
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
        ["machines", "onboard", verb, rest @ ..] => parse_onboard_command(verb, rest)?,
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
        "Usage: fleetctl [--url <controller>] [--socket <path>] [--output json|text] <command>\n\nCommands:\n  status\n  system\n  operations list [--limit <n>]\n  operations get <id>\n  operations cancel <id>\n  machines list [--tag <tag>] [--group <group>] [--capability <ns:name>] [--status <state>] [--limit <n>]\n  machines get <id>\n  machines onboard create --user <user> --host <host> [--port <n>] [--name <name>] [--description <text>] [--tag <tag>]... [--group <group>]... --auth agent|identity-file [--identity <path>]\n  machines onboard list [--limit <n>]\n  machines onboard get <draft-id>\n  machines onboard test <draft-id> [--wait] [--timeout <seconds>]\n  machines onboard discover <draft-id> [--wait] [--timeout <seconds>]\n  machines onboard confirm <draft-id> --fingerprint <SHA256:...>\n  machines onboard add <draft-id>\n  machines onboard cancel <draft-id>\n\n`status` prefers the node's local socket (default {DEFAULT_SOCKET}); `--url` is the explicit direct-controller override. Other commands talk to the controller, which defaults to {DEFAULT_URL}."
    )
}

/// Parses one `machines onboard` subcommand.
fn parse_onboard_command(verb: &str, rest: &[&str]) -> Result<Command, CliError> {
    match verb {
        "create" => parse_onboard_create(rest),
        "list" => {
            let mut limit = None;
            let mut flags = rest.iter().copied();
            while let Some(flag) = flags.next() {
                match flag {
                    "--limit" => {
                        let value = flags.next().ok_or_else(|| CliError {
                            message: "--limit requires a value".to_owned(),
                        })?;
                        limit = Some(value.parse().map_err(|_| CliError {
                            message: format!("--limit must be a number, not {value:?}"),
                        })?);
                    }
                    other => {
                        return Err(CliError {
                            message: format!(
                                "unknown flag {other:?}; see the usage below\n\n{}",
                                usage()
                            ),
                        });
                    }
                }
            }
            Ok(Command::MachinesOnboardList { limit })
        }
        "get" => match rest {
            [id] => Ok(Command::MachinesOnboardGet {
                id: (*id).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "test" => match rest {
            [id, flags @ ..] => parse_onboard_stage(id, flags, false),
            _ => Err(CliError { message: usage() }),
        },
        "discover" => match rest {
            [id, flags @ ..] => parse_onboard_stage(id, flags, true),
            _ => Err(CliError { message: usage() }),
        },
        "confirm" => match rest {
            [id, "--fingerprint", fingerprint] => Ok(Command::MachinesOnboardConfirm {
                id: (*id).to_owned(),
                fingerprint: (*fingerprint).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "add" => match rest {
            [id] => Ok(Command::MachinesOnboardAdd {
                id: (*id).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "cancel" => match rest {
            [id] => Ok(Command::MachinesOnboardCancel {
                id: (*id).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        _ => Err(CliError { message: usage() }),
    }
}

/// Parses the flags of `machines onboard create`; tags and groups repeat.
fn parse_onboard_create(rest: &[&str]) -> Result<Command, CliError> {
    let mut user: Option<String> = None;
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut name: Option<String> = None;
    let mut description: Option<String> = None;
    let mut tags = Vec::new();
    let mut groups = Vec::new();
    let mut auth: Option<String> = None;
    let mut identity: Option<String> = None;
    let mut flags = rest.iter().copied();
    while let Some(flag) = flags.next() {
        let mut value = |name: &str| {
            flags.next().ok_or_else(|| CliError {
                message: format!("--{name} requires a value"),
            })
        };
        match flag {
            "--user" => user = Some(value("user")?.to_owned()),
            "--host" => host = Some(value("host")?.to_owned()),
            "--port" => {
                let parsed = value("port")?;
                port = Some(parsed.parse().map_err(|_| CliError {
                    message: format!("--port must be a number, not {parsed:?}"),
                })?);
            }
            "--name" => name = Some(value("name")?.to_owned()),
            "--description" => description = Some(value("description")?.to_owned()),
            "--tag" => tags.push(value("tag")?.to_owned()),
            "--group" => groups.push(value("group")?.to_owned()),
            "--auth" => auth = Some(value("auth")?.to_owned()),
            "--identity" => identity = Some(value("identity")?.to_owned()),
            other => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let auth = match (auth.as_deref(), identity) {
        (Some("agent"), None) => OnboardAuthArg::Agent,
        (Some("identity-file"), Some(path)) => OnboardAuthArg::IdentityFile(path),
        (Some("identity-file"), None) => {
            return Err(CliError {
                message: "--auth identity-file requires --identity <path>".to_owned(),
            });
        }
        (Some(other), _) => {
            return Err(CliError {
                message: format!("--auth must be agent or identity-file, not {other:?}"),
            });
        }
        (None, _) => {
            return Err(CliError {
                message: "--auth is required: agent or identity-file".to_owned(),
            });
        }
    };
    let user = user.ok_or_else(|| CliError {
        message: "--user is required".to_owned(),
    })?;
    let host = host.ok_or_else(|| CliError {
        message: "--host is required".to_owned(),
    })?;
    Ok(Command::MachinesOnboardCreate {
        user,
        host,
        port,
        name,
        description,
        tags,
        groups,
        auth,
    })
}

/// Parses the flags of the `test` and `discover` stages.
fn parse_onboard_stage(id: &str, rest: &[&str], discover: bool) -> Result<Command, CliError> {
    let mut wait = false;
    let mut timeout: u64 = if discover { 300 } else { 60 };
    let mut flags = rest.iter().copied();
    while let Some(flag) = flags.next() {
        match flag {
            "--wait" => wait = true,
            "--timeout" => {
                let value = flags.next().ok_or_else(|| CliError {
                    message: "--timeout requires a value".to_owned(),
                })?;
                timeout = value.parse().map_err(|_| CliError {
                    message: format!("--timeout must be a number, not {value:?}"),
                })?;
            }
            other => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let id = id.to_owned();
    if discover {
        Ok(Command::MachinesOnboardDiscover { id, wait, timeout })
    } else {
        Ok(Command::MachinesOnboardTest { id, wait, timeout })
    }
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

    let (method, path, query, request_body) = request_for(&invocation.command);

    let body = send(
        &client,
        invocation,
        method,
        &path,
        &query,
        request_body.as_ref(),
        correlation_id,
    )?;
    let body = follow_wait_stage(&client, invocation, body)?;
    let payload = if body.get("items").is_some() {
        body
    } else {
        body.get("data").cloned().unwrap_or(body)
    };
    Ok(render(invocation, &payload))
}

/// The `--wait` stages chase their own operation to a terminal state and
/// then answer with the refreshed draft: the review surface, not the
/// operation.
fn follow_wait_stage(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    body: Value,
) -> Result<Value, CliError> {
    let (Command::MachinesOnboardTest {
        id,
        wait: true,
        timeout,
    }
    | Command::MachinesOnboardDiscover {
        id,
        wait: true,
        timeout,
    }) = &invocation.command
    else {
        return Ok(body);
    };
    let operation_id = body["data"]["id"].as_str().unwrap_or_default().to_owned();
    wait_for_operation(client, invocation, &operation_id, *timeout)?;
    send(
        client,
        invocation,
        reqwest::Method::GET,
        &format!("/api/v1/machines/onboarding/drafts/{id}"),
        &[],
        None,
        uuid::Uuid::now_v7().to_string(),
    )
}

/// Renders one decoded payload for the invocation's output mode.
fn render(invocation: &Invocation, payload: &Value) -> String {
    match invocation.output {
        Output::Json => serde_json::to_string_pretty(payload)
            .unwrap_or_else(|error| format!("{{\"code\":\"internal\",\"message\":\"{error}\"}}")),
        Output::Text => match invocation.command {
            // The machine surface has its own renderer: an empty page must
            // say "no machines", not borrow the operations table.
            Command::MachinesList { .. } | Command::MachinesGet { .. } => {
                render_machines(Some(payload))
            }
            Command::MachinesOnboardList { .. }
            | Command::MachinesOnboardGet { .. }
            | Command::MachinesOnboardCreate { .. }
            | Command::MachinesOnboardConfirm { .. }
            | Command::MachinesOnboardTest { .. }
            | Command::MachinesOnboardDiscover { .. }
            | Command::MachinesOnboardAdd { .. }
            | Command::MachinesOnboardCancel { .. } => render_onboarding(Some(payload)),
            _ => render_text(Some(payload)),
        },
    }
}

/// The controller request for one command: method, path, query, and body,
/// in API order.
fn request_for(
    command: &Command,
) -> (
    reqwest::Method,
    String,
    Vec<(&'static str, String)>,
    Option<Value>,
) {
    match command {
        // `status` took one of the two routes above.
        Command::Status => unreachable!("the status command returned before dispatch"),
        Command::System => (
            reqwest::Method::GET,
            "/api/v1/system".to_owned(),
            Vec::new(),
            None,
        ),
        Command::OperationsList { .. } => {
            let limit = match command {
                Command::OperationsList { limit: Some(limit) } => format!("?limit={limit}"),
                _ => String::new(),
            };
            (
                reqwest::Method::GET,
                format!("/api/v1/operations{limit}"),
                Vec::new(),
                None,
            )
        }
        Command::OperationsGet { id } => (
            reqwest::Method::GET,
            format!("/api/v1/operations/{id}"),
            Vec::new(),
            None,
        ),
        Command::OperationsCancel { id } => (
            reqwest::Method::POST,
            format!("/api/v1/operations/{id}/cancel"),
            Vec::new(),
            None,
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
            None,
        ),
        Command::MachinesGet { id } => (
            reqwest::Method::GET,
            format!("/api/v1/machines/{id}"),
            Vec::new(),
            None,
        ),
        command @ (Command::MachinesOnboardCreate { .. }
        | Command::MachinesOnboardList { .. }
        | Command::MachinesOnboardGet { .. }
        | Command::MachinesOnboardTest { .. }
        | Command::MachinesOnboardDiscover { .. }
        | Command::MachinesOnboardConfirm { .. }
        | Command::MachinesOnboardAdd { .. }
        | Command::MachinesOnboardCancel { .. }) => onboard_request(command),
    }
}
/// The onboarding requests: one dispatch, in API order. The create body
/// carries only what was supplied, so the controller's defaults apply.
fn onboard_request(
    command: &Command,
) -> (
    reqwest::Method,
    String,
    Vec<(&'static str, String)>,
    Option<Value>,
) {
    match command {
        Command::MachinesOnboardCreate {
            user,
            host,
            port,
            name,
            description,
            tags,
            groups,
            auth,
        } => {
            let auth_value = match auth {
                OnboardAuthArg::Agent => serde_json::json!({ "type": "agent" }),
                OnboardAuthArg::IdentityFile(path) => {
                    serde_json::json!({ "type": "identityFile", "path": path })
                }
            };
            let mut body = serde_json::json!({
                "user": user,
                "host": host,
                "auth": auth_value,
            });
            if let Some(port) = port {
                body["port"] = serde_json::json!(port);
            }
            if let Some(name) = name {
                body["name"] = serde_json::json!(name);
            }
            if let Some(description) = description {
                body["description"] = serde_json::json!(description);
            }
            if !tags.is_empty() {
                body["tags"] = serde_json::json!(tags);
            }
            if !groups.is_empty() {
                body["groups"] = serde_json::json!(groups);
            }
            (
                reqwest::Method::POST,
                "/api/v1/machines/onboarding/drafts".to_owned(),
                Vec::new(),
                Some(body),
            )
        }
        Command::MachinesOnboardList { limit } => (
            reqwest::Method::GET,
            "/api/v1/machines/onboarding/drafts".to_owned(),
            limit
                .map(|limit| vec![("limit", limit.to_string())])
                .unwrap_or_default(),
            None,
        ),
        Command::MachinesOnboardGet { id } => (
            reqwest::Method::GET,
            format!("/api/v1/machines/onboarding/drafts/{id}"),
            Vec::new(),
            None,
        ),
        Command::MachinesOnboardTest { id, .. } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/onboarding/drafts/{id}/test"),
            Vec::new(),
            None,
        ),
        Command::MachinesOnboardDiscover { id, .. } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/onboarding/drafts/{id}/discover"),
            Vec::new(),
            None,
        ),
        Command::MachinesOnboardConfirm { id, fingerprint } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/onboarding/drafts/{id}/confirm-host-key"),
            Vec::new(),
            Some(serde_json::json!({ "fingerprint": fingerprint })),
        ),
        Command::MachinesOnboardAdd { id } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/onboarding/drafts/{id}/add"),
            Vec::new(),
            None,
        ),
        Command::MachinesOnboardCancel { id } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/onboarding/drafts/{id}/cancel"),
            Vec::new(),
            None,
        ),
        _ => unreachable!("onboard_request serves onboarding commands only"),
    }
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
/// non-2xx answers with the envelope's code and message. An empty 204 body
/// decodes as `null`.
fn send(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    method: reqwest::Method,
    path: &str,
    query: &[(&'static str, String)],
    body: Option<&Value>,
    correlation_id: String,
) -> Result<Value, CliError> {
    let mut request = client
        .request(method, format!("{}{}", invocation.url, path))
        .header("x-correlation-id", correlation_id);
    if !query.is_empty() {
        request = request.query(query);
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request.send().map_err(|error| CliError {
        message: format!("the controller did not answer: {error}"),
    })?;
    let status = reqwest::StatusCode::as_u16(&response.status());
    if status == 204 {
        return Ok(Value::Null);
    }
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

/// Polls one operation to a terminal state, answering its body. Polling
/// ends at the caller's bound; a still-running operation is an error, not a
/// hang.
fn wait_for_operation(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    operation_id: &str,
    timeout_secs: u64,
) -> Result<Value, CliError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        let body = send(
            client,
            invocation,
            reqwest::Method::GET,
            &format!("/api/v1/operations/{operation_id}"),
            &[],
            None,
            uuid::Uuid::now_v7().to_string(),
        )?;
        let state = body["data"]["state"].as_str().unwrap_or("");
        if !["pending", "running", "cancelling"].contains(&state) {
            return Ok(body);
        }
        if std::time::Instant::now() >= deadline {
            return Err(CliError {
                message: format!(
                    "the operation {operation_id} did not reach a terminal state within {timeout_secs}s; it is still durable — check `fleetctl operations get {operation_id}`"
                ),
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
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

/// Renders the onboarding surface as human text; exposed for contract tests.
#[doc(hidden)]
#[must_use]
pub fn render_onboarding_for_test(value: &Value) -> String {
    render_onboarding(Some(value))
}

fn render_onboarding(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        let mut lines = vec![format!(
            "{:<38} {:<10} {:<28} {}",
            "ID", "STAGE", "ENDPOINT", "NAME"
        )];
        for item in items {
            let endpoint = format!(
                "***@{}:{}",
                item["endpoint"]["host"].as_str().unwrap_or("-"),
                item["endpoint"]["port"]
            );
            lines.push(format!(
                "{:<38} {:<10} {:<28} {}",
                item["id"].as_str().unwrap_or("-"),
                item["stage"].as_str().unwrap_or("-"),
                endpoint,
                item["name"].as_str().unwrap_or("-"),
            ));
        }
        if items.is_empty() {
            lines.push("(no onboarding drafts)".to_owned());
        }
        return lines.join("\n");
    }
    if value.get("machine").is_some() {
        // The add answer: the new machine plus the duplicates that were
        // warned about, never merged.
        let machine = &value["machine"];
        let mut lines = vec![format!(
            "machine registered: {} ({})",
            machine["id"].as_str().unwrap_or("-"),
            machine["name"].as_str().unwrap_or("-")
        )];
        for endpoint in machine["endpoints"].as_array().into_iter().flatten() {
            lines.push(format!(
                "  endpoint: {} {}",
                endpoint["kind"].as_str().unwrap_or("-"),
                endpoint["reference"].as_str().unwrap_or("-")
            ));
        }
        match value["duplicates"].as_array() {
            Some(candidates) if !candidates.is_empty() => {
                lines.push("duplicates (warned, not merged):".to_owned());
                for candidate in candidates {
                    lines.push(format!(
                        "  {} {} ({})",
                        candidate["machineId"].as_str().unwrap_or("-"),
                        candidate["reference"].as_str().unwrap_or("-"),
                        candidate["machineStatus"].as_str().unwrap_or("-"),
                    ));
                }
            }
            _ => lines.push("duplicates: (none)".to_owned()),
        }
        return lines.join("\n");
    }
    draft_detail(value)
}

fn draft_detail(draft: &Value) -> String {
    let mut lines = Vec::new();
    for key in ["id", "name", "description", "stage", "hostKeyStage"] {
        if let Some(value) = draft.get(key) {
            let rendered = match value {
                Value::String(text) => text.clone(),
                Value::Null => continue,
                other => other.to_string(),
            };
            lines.push(format!("{key}: {rendered}"));
        }
    }
    lines.push(format!(
        "endpoint: {}@{}:{}",
        draft["endpoint"]["user"].as_str().unwrap_or("-"),
        draft["endpoint"]["host"].as_str().unwrap_or("-"),
        draft["endpoint"]["port"]
    ));
    match &draft["auth"] {
        auth if auth["type"] == "identityFile" => lines.push(format!(
            "auth: identity file {}",
            auth["path"].as_str().unwrap_or("-")
        )),
        auth if auth["type"] == "agent" => lines.push("auth: ssh agent".to_owned()),
        _ => {}
    }
    if let Some(key) = draft.get("hostKey")
        && !key.is_null()
    {
        lines.push(format!(
            "hostKey: {} {}",
            key["keyType"].as_str().unwrap_or("-"),
            key["fingerprint"].as_str().unwrap_or("-")
        ));
    }
    if let Some(fingerprint) = draft.get("confirmedFingerprint")
        && !fingerprint.is_null()
    {
        lines.push(format!("confirmedFingerprint: {fingerprint}"));
    }
    if let Some(test) = draft.get("lastTest")
        && !test.is_null()
    {
        let outcome = if test["connectAttempted"] == true && test["connected"] == true {
            "connected"
        } else if test["connectAttempted"] == true {
            "failed"
        } else {
            "not attempted (fingerprint unconfirmed)"
        };
        lines.push(format!(
            "lastTest: {outcome}{}",
            test["detail"]
                .as_str()
                .map(|detail| format!(" ({detail})"))
                .unwrap_or_default()
        ));
    }
    if let Some(hint) = draft.get("profileHint")
        && !hint.is_null()
    {
        lines.push(format!("profileHint: {hint}"));
    }
    match draft["facts"].as_array() {
        Some(facts) if !facts.is_empty() => {
            lines.push(format!("facts: {}", facts.len()));
            for fact in facts {
                lines.push(format!(
                    "  {}.{} = {} ({})",
                    fact["namespace"].as_str().unwrap_or("-"),
                    fact["name"].as_str().unwrap_or("-"),
                    fact["value"].as_str().unwrap_or("–"),
                    fact["status"].as_str().unwrap_or("-"),
                ));
            }
        }
        _ => lines.push("facts: (none discovered)".to_owned()),
    }
    match draft["duplicates"].as_array() {
        Some(candidates) if !candidates.is_empty() => {
            lines.push("duplicates (warned, not merged):".to_owned());
            for candidate in candidates {
                lines.push(format!(
                    "  {} {} ({})",
                    candidate["machineId"].as_str().unwrap_or("-"),
                    candidate["reference"].as_str().unwrap_or("-"),
                    candidate["machineStatus"].as_str().unwrap_or("-"),
                ));
            }
        }
        _ => {}
    }
    lines.join("\n")
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
