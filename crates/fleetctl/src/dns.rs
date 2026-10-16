//! `fleetctl dns` (FM-1042): DNS zones and records through a Cloudflare
//! account Fleet holds, and record changes through the action broker.
//!
//! The commands are adapters over `/api/v1/dns/*`. Fleet holds the token and
//! never returns it; authorization, the preview, policy, and audit are the
//! controller's. `dns set` and `dns delete` file an action request (default
//! risk class `approve`) and print it. With `--wait-approval[=<duration>]`
//! they wait, through the shared [`crate::requests::wait_for_outcome`]
//! helper, for a person to decide and for the change to run, and answer a
//! JSON outcome: `{ outcome, request, result }`, where `result` is what the
//! operation did (`created`, `updated`, `deleted`, `unchanged`,
//! `already_absent`) once the request executed.

use std::time::Duration;

use serde_json::{Value, json};

use crate::requests::{Outcome, outcome_body, parse_wait_approval, wait_for_outcome};
use crate::{CliError, Command, Invocation, Output, RequestShape, usage};

/// The reason recorded when `--reason` is not given.
const DEFAULT_REASON: &str = "requested with fleetctl dns";

/// Which change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    /// `dns set`: create or update.
    Set,
    /// `dns delete`.
    Delete,
}

/// One `dns` subcommand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsAction {
    /// List the zones each Cloudflare account can see.
    Zones {
        /// Only this account (id or label).
        account: Option<String>,
    },
    /// Read the records at a name.
    Records {
        /// The fully qualified name.
        name: String,
        /// Only this record type.
        record_type: Option<String>,
        /// The account (id or label), when several hold the zone.
        account: Option<String>,
    },
    /// Request a change.
    Change {
        /// Set or delete.
        kind: ChangeKind,
        /// The fully qualified name.
        name: String,
        /// The record type.
        record_type: String,
        /// The record value.
        content: String,
        /// The TTL in seconds (set).
        ttl: Option<u32>,
        /// Proxied (set).
        proxied: Option<bool>,
        /// The MX preference (set).
        priority: Option<u16>,
        /// The existing value a set replaces.
        replaces: Option<String>,
        /// The account (id or label).
        account: Option<String>,
        /// Why, for the approver.
        reason: String,
        /// A key making a retry return the request already made.
        idempotency_key: Option<String>,
        /// Wait at most this long for the decision and the outcome.
        wait: Option<Duration>,
    },
}

/// Parses `dns zones|records|set|delete ...`.
#[allow(clippy::too_many_lines)]
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let Some((verb, args)) = rest.split_first() else {
        return Err(CliError { message: usage() });
    };
    let (name, flags): (Option<String>, &[&str]) = match *verb {
        "zones" => (None, args),
        "records" | "set" | "delete" => {
            let Some((name, flags)) = args.split_first() else {
                return Err(CliError { message: usage() });
            };
            // An empty name or a leading `-` is a flag or a typo, never a name.
            if name.is_empty() || name.starts_with('-') {
                return Err(CliError { message: usage() });
            }
            (Some((*name).to_owned()), flags)
        }
        _ => return Err(CliError { message: usage() }),
    };
    let mut record_type = None;
    let mut content = None;
    let mut ttl = None;
    let mut proxied = None;
    let mut priority = None;
    let mut replaces = None;
    let mut account = None;
    let mut reason = None;
    let mut idempotency_key = None;
    let mut wait = None;
    let mut flags = flags.iter().copied();
    while let Some(flag) = flags.next() {
        if matches!(*verb, "set" | "delete")
            && let Some(duration) = parse_wait_approval("--wait-approval", flag)?
        {
            wait = Some(duration);
            continue;
        }
        if *verb == "set" && flag == "--proxied" {
            proxied = Some(true);
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
        let number = |name: &str, raw: String| -> Result<u32, CliError> {
            raw.parse().map_err(|_| CliError {
                message: format!("--{name} must be a number, not {raw:?}"),
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
            (_, "--account") => account = Some(value("account")?),
            ("records" | "set" | "delete", "--type") => record_type = Some(value("type")?),
            ("set" | "delete", "--content") => content = Some(value("content")?),
            ("set", "--ttl") => ttl = Some(number("ttl", value("ttl")?)?),
            ("set", "--priority") => {
                let raw = value("priority")?;
                priority = Some(
                    u16::try_from(number("priority", raw)?).map_err(|_| CliError {
                        message: "--priority must be 0 to 65535".to_owned(),
                    })?,
                );
            }
            ("set", "--replaces") => replaces = Some(value("replaces")?),
            ("set" | "delete", "--reason") => reason = Some(value("reason")?),
            ("set" | "delete", "--idempotency-key") => {
                idempotency_key = Some(value("idempotency-key")?);
            }
            (_, other) => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let action = match (*verb, name) {
        ("zones", _) => DnsAction::Zones { account },
        ("records", Some(name)) => DnsAction::Records {
            name,
            record_type,
            account,
        },
        ("set" | "delete", Some(name)) => {
            let missing = |flag: &str| CliError {
                message: format!("dns {verb} needs {flag}"),
            };
            DnsAction::Change {
                kind: if *verb == "set" {
                    ChangeKind::Set
                } else {
                    ChangeKind::Delete
                },
                name,
                record_type: record_type.ok_or_else(|| missing("--type"))?,
                content: content.ok_or_else(|| missing("--content"))?,
                ttl,
                proxied,
                priority,
                replaces,
                account,
                reason: reason.unwrap_or_else(|| DEFAULT_REASON.to_owned()),
                idempotency_key,
                wait,
            }
        }
        _ => return Err(CliError { message: usage() }),
    };
    Ok(Command::Dns(action))
}

/// The controller request for one subcommand.
pub(crate) fn request(action: &DnsAction) -> RequestShape {
    match action {
        DnsAction::Zones { account } => (
            reqwest::Method::GET,
            "/api/v1/dns/zones".to_owned(),
            account
                .iter()
                .map(|account| ("account", account.clone()))
                .collect(),
            None,
        ),
        DnsAction::Records {
            name,
            record_type,
            account,
        } => (
            reqwest::Method::GET,
            "/api/v1/dns/records".to_owned(),
            std::iter::once(("name", name.clone()))
                .chain(record_type.iter().map(|value| ("type", value.clone())))
                .chain(account.iter().map(|value| ("account", value.clone())))
                .collect(),
            None,
        ),
        DnsAction::Change {
            kind,
            name,
            record_type,
            content,
            ttl,
            proxied,
            priority,
            replaces,
            account,
            reason,
            idempotency_key,
            ..
        } => {
            let mut body = json!({
                "operation": match kind {
                    ChangeKind::Set => "upsert",
                    ChangeKind::Delete => "delete",
                },
                "name": name,
                "type": record_type,
                "content": content,
                "reason": reason,
            });
            for (key, value) in [
                ("ttl", ttl.map(|value| json!(value))),
                ("proxied", proxied.map(|value| json!(value))),
                ("priority", priority.map(|value| json!(value))),
                ("replaces", replaces.as_ref().map(|value| json!(value))),
                ("account", account.as_ref().map(|value| json!(value))),
                (
                    "idempotencyKey",
                    idempotency_key.as_ref().map(|value| json!(value)),
                ),
            ] {
                if let Some(value) = value {
                    body[key] = value;
                }
            }
            (
                reqwest::Method::POST,
                "/api/v1/dns/changes".to_owned(),
                Vec::new(),
                Some(body),
            )
        }
    }
}

/// After a change request was filed, waits for its outcome when asked and
/// answers the value to render and the exit code. Without a wait the filed
/// request is the answer (exit 0): it is durable, and `requests get <id>
/// --wait` follows it later.
///
/// # Errors
///
/// Fails when a read is refused or the controller keeps not answering.
pub(crate) fn finish_change(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    created: &Value,
    wait: Option<Duration>,
) -> Result<(Value, u8), CliError> {
    let request = created.get("data").unwrap_or(created);
    let Some(bound) = wait else {
        return Ok((request.clone(), 0));
    };
    let id = request["id"].as_str().ok_or_else(|| CliError {
        message: "the controller's answer carried no request id".to_owned(),
    })?;
    let (outcome, request) = wait_for_outcome(client, invocation, id, bound)?;
    let mut answer = outcome_body(outcome, &request);
    if outcome == Outcome::Executed
        && let Some(operation_id) = request["operationId"].as_str()
    {
        // What the operation did: created, updated, deleted, unchanged, or
        // already_absent, with the record read back.
        let read = crate::send_classified(
            client,
            invocation,
            reqwest::Method::GET,
            &format!("/api/v1/operations/{operation_id}"),
            &[],
            None,
            uuid::Uuid::now_v7().to_string(),
            None,
            Some(Duration::from_secs(30)),
        );
        if let Ok(operation) = read {
            let data = operation.get("data").unwrap_or(&operation);
            if let Some(result) = data["resultJson"]
                .as_str()
                .and_then(|text| serde_json::from_str::<Value>(text).ok())
            {
                answer["result"] = result;
            }
        }
    }
    Ok((answer, outcome.exit_code()))
}

/// Server-supplied text for a terminal: control characters become spaces.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn text_of(value: &Value) -> String {
    match value {
        Value::String(text) => clean(text),
        Value::Null => "-".to_owned(),
        other => clean(&other.to_string()),
    }
}

fn record_line(record: &Value) -> String {
    let priority = record["priority"]
        .as_u64()
        .map_or_else(String::new, |priority| format!(" prio {priority}"));
    format!(
        "{:<6} {:<40} {}{} (ttl {}{})",
        text_of(&record["type"]),
        text_of(&record["name"]),
        text_of(&record["content"]),
        priority,
        text_of(&record["ttl"]),
        if record["proxied"].as_bool() == Some(true) {
            ", proxied"
        } else {
            ""
        },
    )
}

fn preview_lines(preview: &Value) -> Vec<String> {
    let mut lines = vec![format!("  preview: {}", text_of(&preview["operation"]))];
    if !preview["before"].is_null() {
        lines.push(format!("    now:  {}", record_line(&preview["before"])));
    }
    if !preview["after"].is_null() {
        lines.push(format!("    then: {}", record_line(&preview["after"])));
    }
    lines
}

/// Renders a zones list, a records answer, a filed request, or a wait's
/// answer as human text.
pub(crate) fn render(value: &Value) -> String {
    let value = value.get("data").unwrap_or(value);
    if let Some(accounts) = value["accounts"].as_array() {
        let mut lines = Vec::new();
        for account in accounts {
            lines.push(format!("account {}", text_of(&account["accountLabel"])));
            if let Some(failure) = account["failure"].as_str() {
                lines.push(format!(
                    "  failed ({}): {}",
                    clean(failure),
                    text_of(&account["failureDetail"])
                ));
            }
            for zone in account["zones"].as_array().into_iter().flatten() {
                lines.push(format!(
                    "  {:<40} {}",
                    text_of(&zone["name"]),
                    text_of(&zone["status"])
                ));
            }
        }
        if lines.is_empty() {
            return "(no Cloudflare accounts)".to_owned();
        }
        return lines.join("\n");
    }
    if let Some(records) = value["records"].as_array() {
        let mut lines = vec![format!(
            "{} (zone {}, account {})",
            text_of(&value["name"]),
            text_of(&value["zone"]["name"]),
            text_of(&value["accountLabel"])
        )];
        if let Some(entry) = value["registryEntry"].as_str() {
            lines.push(format!("registry: {}", clean(entry)));
        }
        if records.is_empty() {
            lines.push("(no records)".to_owned());
        }
        lines.extend(
            records
                .iter()
                .map(|record| format!("  {}", record_line(record))),
        );
        return lines.join("\n");
    }
    if let Some(outcome) = value["outcome"].as_str() {
        let mut lines = vec![format!("outcome: {}", clean(outcome))];
        lines.extend(request_lines(&value["request"]));
        if let Some(result) = value.get("result") {
            lines.push(format!("  result: {}", text_of(&result["outcome"])));
            if !result["record"].is_null() {
                lines.push(format!("    {}", record_line(&result["record"])));
            }
        }
        return lines.join("\n");
    }
    request_lines(value).join("\n")
}

fn request_lines(request: &Value) -> Vec<String> {
    if request.get("id").is_none() {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "request {}: {} {} ({})",
        text_of(&request["id"]),
        text_of(&request["actionId"]),
        text_of(&request["target"]),
        text_of(&request["state"]),
    )];
    lines.extend(preview_lines(&request["parameters"]["preview"]));
    if let Some(failure) = request["failure"].as_str() {
        lines.push(format!("  failure: {}", clean(failure)));
    }
    if request["state"].as_str() == Some("pending") {
        lines.push("  waiting for approval: fleetctl requests approve <id>".to_owned());
    }
    lines
}
