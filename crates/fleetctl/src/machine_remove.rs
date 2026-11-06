//! `fleetctl machines remove` and `fleetctl nodes revoke` (#616).
//!
//! - `machines remove <machine-id> [--uninstall --endpoint <endpoint-id>
//!   [--auth agent|identity-file|secret] [--identity <path>]
//!   [--credential <ref>]] [--yes] [--review-only] [--output json|text]`
//!   reviews the removal (`POST /api/v1/machines/{id}/remove/review`), stops
//!   with the blockers when anything holds the machine, asks for
//!   confirmation (`--yes` skips it) and removes it with the review token
//!   (`POST /api/v1/machines/{id}/remove`). Without `--uninstall` nothing on
//!   the machine is touched; with it the controller runs the fleetd uninstall
//!   over the endpoint first, and a failed uninstall leaves the machine.
//! - `nodes revoke <machine-id> [--yes] [--output json|text]` revokes the
//!   machine's node identity, credentials and sessions
//!   (`POST /api/v1/machines/{id}/node/revoke`), as the console's Connections
//!   tab does. The machine stays; fleetd stops being able to connect until it
//!   is enrolled again.
//!
//! The controller decides everything; with `--output json` this adapter
//! prints the controller's `data` unchanged.

use serde_json::{Value, json};

use crate::machine_access::AuthArgs;
use crate::{CliError, Command, Invocation, Output, RequestShape, usage};

/// How long the removal may take: the uninstall is bounded at 120 seconds on
/// the controller, plus the connection and the delete.
const REMOVE_TIMEOUT_SECONDS: u64 = 180;

/// The arguments of `machines remove`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MachineRemoveArgs {
    /// The machine.
    pub machine_id: String,
    /// Run the fleetd uninstall over this SSH endpoint first.
    pub uninstall_endpoint: Option<String>,
    /// The uninstall's authentication; the endpoint's default when absent.
    pub auth: AuthArgs,
    /// Skip the confirmation.
    pub yes: bool,
    /// Print the review and stop.
    pub review_only: bool,
}

impl MachineRemoveArgs {
    /// The request body both calls share (the removal adds the token).
    ///
    /// # Errors
    ///
    /// Fails on an incomplete `--auth`.
    pub fn body(&self) -> Result<Value, CliError> {
        let mut body = serde_json::Map::new();
        if let Some(endpoint) = &self.uninstall_endpoint {
            let mut uninstall = serde_json::Map::new();
            uninstall.insert("endpointId".to_owned(), json!(endpoint));
            if let Some(auth) = self.auth.to_json()? {
                uninstall.insert("auth".to_owned(), auth);
            }
            body.insert("uninstall".to_owned(), Value::Object(uninstall));
        }
        Ok(Value::Object(body))
    }
}

fn value<'a>(flags: &mut impl Iterator<Item = &'a str>, name: &str) -> Result<String, CliError> {
    flags
        .next()
        .filter(|candidate| !candidate.starts_with("--"))
        .map(str::to_owned)
        .ok_or_else(|| CliError {
            message: format!("{name} requires a value"),
        })
}

fn output_flag<'a>(
    flags: &mut impl Iterator<Item = &'a str>,
    output: &mut Output,
) -> Result<(), CliError> {
    *output = match value(flags, "--output")?.as_str() {
        "json" => Output::Json,
        "text" => Output::Text,
        other => {
            return Err(CliError {
                message: format!("--output must be json or text, not {other:?}"),
            });
        }
    };
    Ok(())
}

fn unknown(flag: &str) -> CliError {
    CliError {
        message: format!("unknown flag {flag:?}; see the usage below\n\n{}", usage()),
    }
}

/// Parses `machines remove ...` (the words after `machines remove`).
pub(crate) fn parse_remove(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let mut positional: Vec<&str> = Vec::new();
    let mut args = MachineRemoveArgs::default();
    let mut uninstall = false;
    let mut endpoint = None;
    let mut flags = rest.iter().copied();
    while let Some(arg) = flags.next() {
        match arg {
            "--yes" => args.yes = true,
            "--review-only" => args.review_only = true,
            "--uninstall" => uninstall = true,
            "--endpoint" => endpoint = Some(value(&mut flags, "--endpoint")?),
            "--auth" => args.auth.kind = Some(value(&mut flags, "--auth")?),
            "--identity" => args.auth.identity = Some(value(&mut flags, "--identity")?),
            "--credential" => args.auth.credential = Some(value(&mut flags, "--credential")?),
            "--output" => output_flag(&mut flags, output)?,
            flag if flag.starts_with("--") => return Err(unknown(flag)),
            word => positional.push(word),
        }
    }
    let [machine_id] = positional.as_slice() else {
        return Err(CliError {
            message: format!(
                "machines remove needs exactly one <machine-id>; see the usage below\n\n{}",
                usage()
            ),
        });
    };
    (*machine_id).clone_into(&mut args.machine_id);
    match (uninstall, endpoint) {
        (true, Some(endpoint)) => args.uninstall_endpoint = Some(endpoint),
        (true, None) => {
            return Err(CliError {
                message: "--uninstall needs --endpoint <endpoint-id>: the SSH endpoint the fleetd uninstall runs over".to_owned(),
            });
        }
        (false, Some(_)) => {
            return Err(CliError {
                message: "--endpoint is only for --uninstall; without it nothing on the machine is touched".to_owned(),
            });
        }
        (false, None) => {
            if args.auth != AuthArgs::default() {
                return Err(CliError {
                    message: "--auth, --identity and --credential are only for --uninstall"
                        .to_owned(),
                });
            }
        }
    }
    // An incomplete --auth fails at parse time, not after the review.
    args.body()?;
    Ok(Command::MachineRemove(args))
}

/// Parses `nodes revoke <machine-id> [--yes]` (the words after `nodes`).
pub(crate) fn parse_nodes(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let Some((&"revoke", rest)) = rest.split_first() else {
        return Err(CliError { message: usage() });
    };
    let mut positional: Vec<&str> = Vec::new();
    let mut yes = false;
    let mut flags = rest.iter().copied();
    while let Some(arg) = flags.next() {
        match arg {
            "--yes" => yes = true,
            "--output" => output_flag(&mut flags, output)?,
            flag if flag.starts_with("--") => return Err(unknown(flag)),
            word => positional.push(word),
        }
    }
    let [machine_id] = positional.as_slice() else {
        return Err(CliError {
            message: format!(
                "nodes revoke needs exactly one <machine-id>; see the usage below\n\n{}",
                usage()
            ),
        });
    };
    Ok(Command::NodesRevoke {
        machine_id: (*machine_id).to_owned(),
        yes,
    })
}

/// The first controller request of `machines remove`: its review.
pub(crate) fn request(args: &MachineRemoveArgs) -> Result<RequestShape, CliError> {
    Ok((
        reqwest::Method::POST,
        format!("/api/v1/machines/{}/remove/review", args.machine_id),
        Vec::new(),
        Some(args.body()?),
    ))
}

/// The controller request of `nodes revoke`.
pub(crate) fn revoke_request(machine_id: &str) -> RequestShape {
    (
        reqwest::Method::POST,
        format!("/api/v1/machines/{machine_id}/node/revoke"),
        Vec::new(),
        None,
    )
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("-")
}

fn list(value: &Value) -> String {
    let items: Vec<&str> = value
        .as_array()
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join(", ")
    }
}

fn question(review: &Value) -> String {
    let warnings: String = review["warnings"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .fold(String::new(), |mut out, warning| {
                    use std::fmt::Write as _;
                    let _ = writeln!(out, "Warning: {warning}");
                    out
                })
        })
        .unwrap_or_default();
    let uninstall = if review["uninstall"].is_object() {
        format!(
            "uninstall fleetd over endpoint {} first, then ",
            text(&review["uninstall"]["endpointId"])
        )
    } else {
        String::new()
    };
    format!(
        "{warnings}Remove machine {} ({}): {uninstall}delete its record, node identity, recorded facts and stored secrets, and unpin host keys for {}?",
        text(&review["name"]),
        text(&review["machineId"]),
        list(&review["unpinHosts"]),
    )
}

/// Reviews, confirms and runs `machines remove`.
pub(crate) fn run(
    invocation: &Invocation,
    args: &MachineRemoveArgs,
) -> Result<(String, u8), CliError> {
    let client = crate::http_client()?;
    let body = args.body()?;
    let base = format!("/api/v1/machines/{}/remove", args.machine_id);
    let reviewed = crate::send(
        &client,
        invocation,
        reqwest::Method::POST,
        &format!("{base}/review"),
        &[],
        Some(&body),
        uuid::Uuid::now_v7().to_string(),
    )?;
    let review = &reviewed["data"];
    if args.review_only {
        return Ok((crate::render(invocation, review), 0));
    }
    let Some(token) = review["reviewToken"].as_str() else {
        let blockers: Vec<&str> = review["blockers"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["detail"].as_str())
                    .collect()
            })
            .unwrap_or_default();
        return Err(CliError {
            message: if blockers.is_empty() {
                "the review did not answer with a token".to_owned()
            } else {
                format!(
                    "the machine cannot be removed yet:\n  - {}",
                    blockers.join("\n  - ")
                )
            },
        });
    };
    crate::persistent::confirm(args.yes, &question(review))?;
    let mut body = body;
    body["reviewToken"] = json!(token);
    let client = crate::http_client_with_timeout(REMOVE_TIMEOUT_SECONDS)?;
    let done = crate::send(
        &client,
        invocation,
        reqwest::Method::POST,
        &base,
        &[],
        Some(&body),
        uuid::Uuid::now_v7().to_string(),
    )?;
    Ok((crate::render(invocation, &done["data"]), 0))
}

/// Confirms and runs `nodes revoke`.
pub(crate) fn run_revoke(
    invocation: &Invocation,
    machine_id: &str,
    yes: bool,
) -> Result<(String, u8), CliError> {
    crate::persistent::confirm(
        yes,
        &format!(
            "Revoke the node identity of machine {machine_id}, with every credential and session? fleetd cannot connect again until it is enrolled again"
        ),
    )?;
    let client = crate::http_client()?;
    let (method, path, query, body) = revoke_request(machine_id);
    let done = crate::send(
        &client,
        invocation,
        method,
        &path,
        &query,
        body.as_ref(),
        uuid::Uuid::now_v7().to_string(),
    )?;
    Ok((crate::render(invocation, &done["data"]), 0))
}

/// Renders a review, a removal or a revocation as human text.
pub(crate) fn render(payload: &Value) -> String {
    if payload.get("status").is_some() && payload.get("removed").is_none() {
        return format!(
            "node of machine {} is {}",
            text(&payload["machineId"]),
            text(&payload["status"])
        );
    }
    if payload.get("removed").is_some() {
        return render_removed(payload);
    }
    let mut lines = vec![format!(
        "review of removing machine {} ({})",
        text(&payload["name"]),
        text(&payload["machineId"])
    )];
    let footprint = &payload["footprint"];
    lines.push(format!(
        "  deletes {} endpoints, {} facts, {} snapshots, node identity: {}, {} recorded skill installs",
        footprint["endpoints"],
        footprint["capabilities"],
        footprint["inventorySnapshots"],
        payload["nodeIdentity"].as_str().unwrap_or("none"),
        footprint["catalogSkillInstalls"],
    ));
    lines.push(format!(
        "  unpins host keys for: {}",
        list(&payload["unpinHosts"])
    ));
    lines.push(format!(
        "  keeps host keys (shared): {}",
        list(&payload["keptHosts"])
    ));
    lines.push(format!(
        "  revokes {} stored SSH keys and destroys {} stored Windows administrator passwords",
        footprint["storedSshKeys"], footprint["adminPasswords"],
    ));
    for warning in payload["warnings"].as_array().into_iter().flatten() {
        lines.push(format!("  warning: {}", text(warning)));
    }
    if payload["uninstall"].is_object() {
        lines.push(format!(
            "  uninstalls fleetd first over endpoint {} ({})",
            text(&payload["uninstall"]["endpointId"]),
            text(&payload["uninstall"]["auth"]["type"])
        ));
    } else {
        lines.push("  touches nothing on the machine".to_owned());
    }
    if let Some(blockers) = payload["blockers"].as_array()
        && !blockers.is_empty()
    {
        lines.push("  blocked:".to_owned());
        for blocker in blockers {
            lines.push(format!("    - {}", text(&blocker["detail"])));
        }
    } else {
        lines.push(format!("  review token {}", text(&payload["reviewToken"])));
    }
    lines.join("\n")
}

/// Renders what a removal did.
fn render_removed(payload: &Value) -> String {
    let mut lines = vec![format!(
        "removed machine {} ({})",
        text(&payload["name"]),
        text(&payload["machineId"])
    )];
    if let Some(error) = payload["secretRevocationError"].as_str() {
        lines.push(format!(
            "  stored secrets were NOT revoked (delete them by hand): {error}"
        ));
    } else {
        lines.push(format!(
            "  stored secrets revoked: {}",
            payload["secretsRevoked"]
        ));
    }
    if payload["sessionClosed"] == true {
        lines.push("  the live node session was closed".to_owned());
    }
    if payload["uninstalled"] == true {
        lines.push(format!(
            "  fleetd uninstalled: {}",
            text(&payload["uninstallSummary"])
        ));
    } else {
        lines.push("  nothing on the machine was touched".to_owned());
    }
    lines.push(format!(
        "  host keys unpinned: {}",
        list(&payload["unpinnedHosts"])
    ));
    lines.push(format!(
        "  host keys kept (shared): {}",
        list(&payload["keptHosts"])
    ));
    if payload["unpinFailedHosts"]
        .as_array()
        .is_some_and(|hosts| !hosts.is_empty())
    {
        lines.push(format!(
            "  host keys that could not be unpinned (remove them by hand): {}",
            list(&payload["unpinFailedHosts"])
        ));
    }
    lines.join("\n")
}
