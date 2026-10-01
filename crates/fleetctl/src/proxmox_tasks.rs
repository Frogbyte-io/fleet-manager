//! `fleetctl proxmox tasks` (FM-609): an account's recent PVE task history,
//! with each task linked to the Fleet operation that started it.

use serde_json::Value;

use crate::{CliError, Command, Output, RequestShape, usage};

/// Parses `proxmox tasks <account-id> [--node <node>] [--vmid <vmid>]
/// [--status running|ok|error|unknown] [--cursor <upid>] [--limit <n>]
/// [--output json|text]`. The controller validates the values; the CLI
/// only checks that numbers are numbers.
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let Some((account_id, flags)) = rest.split_first() else {
        return Err(CliError { message: usage() });
    };
    if account_id.starts_with("--") {
        return Err(CliError { message: usage() });
    }
    let mut node = None;
    let mut vmid = None;
    let mut status = None;
    let mut cursor = None;
    let mut limit = None;
    let mut flags = flags.iter().copied();
    while let Some(flag) = flags.next() {
        let mut value = |name: &str| {
            flags.next().ok_or_else(|| CliError {
                message: format!("--{name} requires a value"),
            })
        };
        match flag {
            "--node" => node = Some(value("node")?.to_owned()),
            "--status" => status = Some(value("status")?.to_owned()),
            "--cursor" => cursor = Some(value("cursor")?.to_owned()),
            "--vmid" => {
                let raw = value("vmid")?;
                vmid = Some(raw.parse().map_err(|_| CliError {
                    message: format!("--vmid must be a number, not {raw:?}"),
                })?);
            }
            "--limit" => {
                let raw = value("limit")?;
                limit = Some(raw.parse().map_err(|_| CliError {
                    message: format!("--limit must be a number, not {raw:?}"),
                })?);
            }
            "--output" => {
                *output = match value("output")? {
                    "json" => Output::Json,
                    "text" => Output::Text,
                    other => {
                        return Err(CliError {
                            message: format!("--output must be json or text, not {other:?}"),
                        });
                    }
                };
            }
            other => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    Ok(Command::ProxmoxTasks {
        account_id: (*account_id).to_owned(),
        node,
        vmid,
        status,
        cursor,
        limit,
    })
}

/// The controller request for the task history.
pub(crate) fn request(
    account_id: &str,
    node: Option<&String>,
    vmid: Option<u32>,
    status: Option<&String>,
    cursor: Option<&String>,
    limit: Option<u32>,
) -> RequestShape {
    let mut query = Vec::new();
    if let Some(node) = node {
        query.push(("node", node.clone()));
    }
    if let Some(vmid) = vmid {
        query.push(("vmid", vmid.to_string()));
    }
    if let Some(status) = status {
        query.push(("status", status.clone()));
    }
    if let Some(cursor) = cursor {
        query.push(("cursor", cursor.clone()));
    }
    if let Some(limit) = limit {
        query.push(("limit", limit.to_string()));
    }
    (
        reqwest::Method::GET,
        format!("/api/v1/proxmox/accounts/{account_id}/tasks"),
        query,
        None,
    )
}

/// Renders one task-history page as human text: one row per task, then
/// the next cursor and the snapshot's warnings.
pub(crate) fn render(value: &Value) -> String {
    let Some(items) = value.get("items").and_then(Value::as_array) else {
        return String::new();
    };
    let mut lines = Vec::new();
    if let Some(version) = value.get("pveVersion").and_then(Value::as_str) {
        lines.push(format!("PVE {version}"));
    }
    lines.push(format!(
        "{:<10} {:<12} {:<12} {:<8} {:<24} {:<14} {:<14} {}",
        "STATUS", "NODE", "TYPE", "TARGET", "USER", "STARTED", "ENDED", "FLEET OPERATION"
    ));
    for task in items {
        let user = match (task["user"].as_str(), task["tokenId"].as_str()) {
            (Some(user), Some(token)) => format!("{user}!{token}"),
            (Some(user), None) => user.to_owned(),
            _ => "-".to_owned(),
        };
        let millis = |key: &str| {
            task[key]
                .as_i64()
                .map_or_else(|| "-".to_owned(), |value| value.to_string())
        };
        lines.push(format!(
            "{:<10} {:<12} {:<12} {:<8} {:<24} {:<14} {:<14} {}",
            task["status"].as_str().unwrap_or("-"),
            task["node"].as_str().unwrap_or("-"),
            task["taskType"].as_str().unwrap_or("-"),
            task["targetId"].as_str().unwrap_or("-"),
            user,
            millis("startedAt"),
            millis("endedAt"),
            task["fleetOperationId"].as_str().unwrap_or("-"),
        ));
        if task["status"] == "error"
            && let Some(exit) = task["exitStatus"].as_str()
        {
            lines.push(format!("  exit: {exit}"));
        }
    }
    if items.is_empty() {
        lines.push("(no tasks reported)".to_owned());
    }
    lines.push("times are epoch milliseconds".to_owned());
    if let Some(cursor) = value["page"]["nextCursor"].as_str() {
        lines.push(format!("next page: --cursor {cursor}"));
    }
    if let Some(warnings) = value.get("warnings").and_then(Value::as_array)
        && !warnings.is_empty()
    {
        lines.push(String::new());
        lines.push("warnings:".to_owned());
        for warning in warnings.iter().filter_map(Value::as_str) {
            lines.push(format!("  {warning}"));
        }
    }
    lines.join("\n")
}
