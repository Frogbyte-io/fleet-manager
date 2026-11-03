//! `fleetctl hardware` (FM-1111, M11): the USB hardware inventory.
//!
//! - `hardware list [--account <id>] [--limit <n>] [--cursor <id>]
//!   [--output json|text]` reads `GET /api/v1/hardware/devices`. It reads
//!   Fleet's own records and makes no Proxmox call, so a device is as fresh as
//!   the last refresh (`stale` says when that is too old to trust).
//! - `hardware refresh --account <id> [--output json|text]` posts
//!   `POST /api/v1/hardware/refresh`, which reads Proxmox through the
//!   account's token and records what it saw. It is an authorized, audited
//!   mutation of Fleet's records; it changes nothing on Proxmox.
//!
//! The controller decides every status and reason; with `--output json` this
//! adapter prints the controller's answer unchanged, so `hardware list` is
//! the API's page and `hardware refresh` is the API's `data`.

use serde_json::{Value, json};

use crate::{CliError, Command, Output, RequestShape, usage};

/// One `hardware` subcommand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HardwareAction {
    /// List the inventoried devices.
    List {
        /// Only this account's devices.
        account: Option<String>,
        /// The page size.
        limit: Option<u32>,
        /// The last device id of the previous page.
        cursor: Option<String>,
    },
    /// Refresh one account's inventory.
    Refresh {
        /// The Proxmox account.
        account: String,
    },
}

/// Parses `hardware list|refresh ...`.
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let Some((verb, flags)) = rest.split_first() else {
        return Err(CliError { message: usage() });
    };
    if !matches!(*verb, "list" | "refresh") {
        return Err(CliError { message: usage() });
    }
    let mut account = None;
    let mut limit = None;
    let mut cursor = None;
    let mut flags = flags.iter().copied();
    while let Some(flag) = flags.next() {
        let mut value = |name: &str| {
            // Another option is not a value: `--account --output` means the
            // account's value is missing.
            flags
                .next()
                .filter(|candidate| !candidate.starts_with("--"))
                .ok_or_else(|| CliError {
                    message: format!("--{name} requires a value"),
                })
        };
        match (*verb, flag) {
            (_, "--account") => account = Some(value("account")?.to_owned()),
            ("list", "--cursor") => cursor = Some(value("cursor")?.to_owned()),
            ("list", "--limit") => {
                let raw = value("limit")?;
                limit = Some(raw.parse().map_err(|_| CliError {
                    message: format!("--limit must be a number, not {raw:?}"),
                })?);
            }
            (_, "--output") => {
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
            (_, other) => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let action = match *verb {
        "list" => HardwareAction::List {
            account,
            limit,
            cursor,
        },
        _ => HardwareAction::Refresh {
            account: account.ok_or_else(|| CliError {
                message: "hardware refresh needs --account <account-id>".to_owned(),
            })?,
        },
    };
    Ok(Command::Hardware(action))
}

/// The controller request for one subcommand.
pub(crate) fn request(action: &HardwareAction) -> RequestShape {
    match action {
        HardwareAction::List {
            account,
            limit,
            cursor,
        } => {
            let mut query = Vec::new();
            if let Some(account) = account {
                query.push(("accountId", account.clone()));
            }
            if let Some(limit) = limit {
                query.push(("limit", limit.to_string()));
            }
            if let Some(cursor) = cursor {
                query.push(("cursor", cursor.clone()));
            }
            (
                reqwest::Method::GET,
                "/api/v1/hardware/devices".to_owned(),
                query,
                None,
            )
        }
        HardwareAction::Refresh { account } => (
            reqwest::Method::POST,
            "/api/v1/hardware/refresh".to_owned(),
            Vec::new(),
            Some(json!({ "accountId": account })),
        ),
    }
}

/// Renders an answer as human text: the list page or the refresh report.
pub(crate) fn render(payload: &Value) -> String {
    if payload.get("items").is_some() {
        render_devices(
            payload["items"].as_array().map_or(&[][..], Vec::as_slice),
            payload,
        )
    } else {
        render_refresh(payload)
    }
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("-")
}

fn status_cell(device: &Value) -> String {
    let status = text(&device["status"]);
    match device["reason"].as_str() {
        Some(reason) => format!("{status} ({reason})"),
        None => status.to_owned(),
    }
}

fn node_cell(device: &Value) -> String {
    let nodes: Vec<String> = device["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| {
            let id = format!("{}:{}", text(&entry["vendorId"]), text(&entry["productId"]));
            match entry["usbpath"].as_str() {
                Some(path) => format!("{}/{id}@{path}", text(&entry["node"])),
                None => format!("{}/{id}", text(&entry["node"])),
            }
        })
        .collect();
    if nodes.is_empty() {
        "-".to_owned()
    } else {
        nodes.join(",")
    }
}

fn holder_cell(device: &Value) -> String {
    let holder = &device["holder"];
    if holder.is_null() {
        return "-".to_owned();
    }
    format!(
        "{} {} ({})",
        text(&holder["ownerKind"]),
        text(&holder["ownerId"]),
        text(&holder["state"])
    )
}

fn push_device_rows(lines: &mut Vec<String>, devices: &[Value]) {
    lines.push(format!(
        "{:<24} {:<44} {:<30} {:<6} {}",
        "MAPPING", "STATUS", "NODE/ID@PORT", "STALE", "HOLDER"
    ));
    for device in devices {
        lines.push(format!(
            "{:<24} {:<44} {:<30} {:<6} {}",
            text(&device["mappingId"]),
            status_cell(device),
            node_cell(device),
            if device["stale"].as_bool() == Some(true) {
                "stale"
            } else {
                "-"
            },
            holder_cell(device),
        ));
        if let Some(reason) = device["reasonText"].as_str() {
            lines.push(format!("  {reason}"));
        }
        if let Some(observation) = device.get("observation").filter(|value| !value.is_null()) {
            for reference in observation["externalReferences"]
                .as_array()
                .into_iter()
                .flatten()
            {
                let name = reference["guestName"]
                    .as_str()
                    .map_or(String::new(), |name| format!(" ({name})"));
                lines.push(format!(
                    "  referenced by qemu/{} on {}{name}, {}{}{}",
                    reference["vmid"],
                    text(&reference["node"]),
                    text(&reference["slot"]),
                    if reference["template"].as_bool() == Some(true) {
                        ", a template"
                    } else {
                        ""
                    },
                    reference["pending"]
                        .as_str()
                        .map_or(String::new(), |pending| format!(", pending {pending}")),
                ));
            }
            for note in observation["notes"].as_array().into_iter().flatten() {
                lines.push(format!("  note: {}", text(note)));
            }
        }
    }
}

fn render_devices(devices: &[Value], page: &Value) -> String {
    let mut lines = Vec::new();
    if devices.is_empty() {
        lines.push("(no devices; run `fleetctl hardware refresh --account <id>`)".to_owned());
    } else {
        push_device_rows(&mut lines, devices);
        lines.push("a list reads Fleet's own records; refresh to observe Proxmox again".to_owned());
    }
    if let Some(cursor) = page["page"]["nextCursor"].as_str() {
        lines.push(format!("next page: --cursor '{cursor}'"));
    }
    lines.join("\n")
}

fn render_refresh(report: &Value) -> String {
    let mut lines = Vec::new();
    let version = report["pveVersion"].as_str().unwrap_or("unknown");
    lines.push(format!(
        "account {}  PVE {version}  {}",
        text(&report["accountId"]),
        text(&report["support"]["state"])
    ));
    if let Some(reason) = report["support"]["reason"].as_str() {
        lines.push(format!(
            "  {reason}: {}",
            report["support"]["detail"].as_str().unwrap_or("-")
        ));
    }
    if let Some(scan) = report.get("guestScan").filter(|scan| !scan.is_null()) {
        lines.push(format!(
            "guest scan: {} listed, {} read, {} unreadable{}",
            scan["listed"],
            scan["read"],
            scan["unreadable"],
            if scan["truncated"].as_bool() == Some(true) {
                ", truncated"
            } else {
                ""
            }
        ));
    }
    let devices = report["devices"].as_array().map_or(&[][..], Vec::as_slice);
    if devices.is_empty() {
        lines.push("(no devices)".to_owned());
    } else {
        push_device_rows(&mut lines, devices);
    }
    let warnings: Vec<&str> = report["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !warnings.is_empty() {
        lines.push(String::new());
        lines.push("warnings:".to_owned());
        for warning in warnings {
            lines.push(format!("  {warning}"));
        }
    }
    lines.join("\n")
}
