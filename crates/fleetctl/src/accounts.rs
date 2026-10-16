//! `fleetctl accounts` (FM-1001): external provider accounts for the
//! API-token providers Coolify and Cloudflare.
//!
//! The token is write-only. It is read from standard input (never a
//! process argument) on `create` and on `update --rotate-token`, and no
//! command prints it: the controller never returns it.

use serde_json::{Value, json};

use crate::{CliError, Command, Output, RequestShape, usage};

/// One `accounts` subcommand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountsAction {
    /// List accounts, optionally of one kind.
    List {
        /// Restrict to `coolify` or `cloudflare`.
        kind: Option<String>,
    },
    /// Read one account.
    Get {
        /// The account's identity.
        id: String,
    },
    /// Create an account; the token is read from stdin.
    Create {
        /// `coolify` or `cloudflare`.
        kind: String,
        /// The label, unique within the kind.
        label: String,
        /// The API base URL.
        base_url: Option<String>,
        /// The Cloudflare account id for account-owned tokens.
        account_id: Option<String>,
        /// Free-form notes.
        notes: Option<String>,
    },
    /// Update an account; with `rotate_token` the new token is read from
    /// stdin.
    Update {
        /// The account's identity.
        id: String,
        /// A new label.
        label: Option<String>,
        /// A new base URL.
        base_url: Option<String>,
        /// A new Cloudflare account id; empty clears it.
        account_id: Option<String>,
        /// New notes.
        notes: Option<String>,
        /// Replace the stored token with one read from stdin.
        rotate_token: bool,
    },
    /// Remove an account and its token.
    Delete {
        /// The account's identity.
        id: String,
    },
    /// Probe an account's health and permissions.
    Probe {
        /// The account's identity.
        id: String,
    },
}

/// Parses `accounts list|get|create|update|delete|probe ...`.
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let Some((verb, args)) = rest.split_first() else {
        return Err(CliError { message: usage() });
    };
    let (positional, flags) = match *verb {
        "get" | "delete" | "probe" | "update" => {
            let Some((id, flags)) = args.split_first() else {
                return Err(CliError { message: usage() });
            };
            // An empty id or a leading `-` is a flag or a typo, never an id.
            if id.is_empty() || id.starts_with('-') {
                return Err(CliError { message: usage() });
            }
            (Some((*id).to_owned()), flags)
        }
        "list" | "create" => (None, args),
        _ => return Err(CliError { message: usage() }),
    };
    let mut kind = None;
    let mut label = None;
    let mut base_url = None;
    let mut account_id = None;
    let mut notes = None;
    let mut rotate_token = false;
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
            ("list" | "create", "--kind") => kind = Some(value("kind")?),
            ("create" | "update", "--label") => label = Some(value("label")?),
            ("create" | "update", "--base-url") => base_url = Some(value("base-url")?),
            ("create" | "update", "--account-id") => account_id = Some(value("account-id")?),
            ("create" | "update", "--notes") => notes = Some(value("notes")?),
            ("update", "--rotate-token") => rotate_token = true,
            (_, other) => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let missing = |name: &str| CliError {
        message: format!("--{name} is required"),
    };
    let action = match (*verb, positional) {
        ("list", _) => AccountsAction::List { kind },
        ("get", Some(id)) => AccountsAction::Get { id },
        ("delete", Some(id)) => AccountsAction::Delete { id },
        ("probe", Some(id)) => AccountsAction::Probe { id },
        ("create", _) => AccountsAction::Create {
            kind: kind.ok_or_else(|| missing("kind"))?,
            label: label.ok_or_else(|| missing("label"))?,
            base_url,
            account_id,
            notes,
        },
        ("update", Some(id)) => AccountsAction::Update {
            id,
            label,
            base_url,
            account_id,
            notes,
            rotate_token,
        },
        _ => return Err(CliError { message: usage() }),
    };
    Ok(Command::Accounts(action))
}

/// The controller request for one subcommand. `token` supplies the secret
/// on demand, so commands that carry none never touch standard input.
pub(crate) fn request(
    action: &AccountsAction,
    token: impl FnOnce() -> Result<String, CliError>,
) -> Result<RequestShape, CliError> {
    let base = "/api/v1/external-accounts";
    Ok(match action {
        AccountsAction::List { kind } => (
            reqwest::Method::GET,
            base.to_owned(),
            kind.iter().map(|kind| ("kind", kind.clone())).collect(),
            None,
        ),
        AccountsAction::Get { id } => (
            reqwest::Method::GET,
            format!("{base}/{id}"),
            Vec::new(),
            None,
        ),
        AccountsAction::Create {
            kind,
            label,
            base_url,
            account_id,
            notes,
        } => {
            let mut body = json!({"kind": kind, "label": label, "token": token()?});
            set(&mut body, "baseUrl", base_url.as_ref());
            set(&mut body, "accountId", account_id.as_ref());
            set(&mut body, "notes", notes.as_ref());
            (
                reqwest::Method::POST,
                base.to_owned(),
                Vec::new(),
                Some(body),
            )
        }
        AccountsAction::Update {
            id,
            label,
            base_url,
            account_id,
            notes,
            rotate_token,
        } => {
            let mut body = json!({});
            set(&mut body, "label", label.as_ref());
            set(&mut body, "baseUrl", base_url.as_ref());
            set(&mut body, "accountId", account_id.as_ref());
            set(&mut body, "notes", notes.as_ref());
            if *rotate_token {
                body["token"] = Value::String(token()?);
            }
            (
                reqwest::Method::PATCH,
                format!("{base}/{id}"),
                Vec::new(),
                Some(body),
            )
        }
        AccountsAction::Delete { id } => (
            reqwest::Method::DELETE,
            format!("{base}/{id}"),
            Vec::new(),
            None,
        ),
        AccountsAction::Probe { id } => (
            reqwest::Method::POST,
            format!("{base}/{id}/probe"),
            Vec::new(),
            None,
        ),
    })
}

fn set(body: &mut Value, key: &str, value: Option<&String>) {
    if let Some(value) = value {
        body[key] = Value::String(value.clone());
    }
}

/// Renders a list page or one account as human text.
pub(crate) fn render(value: &Value) -> String {
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        if items.is_empty() {
            return "(no accounts)".to_owned();
        }
        let mut lines = vec![format!(
            "{:<38} {:<11} {:<20} {:<24} {}",
            "ID", "KIND", "LABEL", "PROBE", "BASE URL"
        )];
        lines.extend(items.iter().map(row));
        if let Some(cursor) = value["page"]["nextCursor"].as_str() {
            lines.push(format!("next page: --cursor '{cursor}'"));
        }
        return lines.join("\n");
    }
    let account = value.get("data").unwrap_or(value);
    if account.get("id").is_none() {
        return String::new();
    }
    let mut lines = vec![
        row(account),
        format!("  notes: {}", account["notes"].as_str().unwrap_or("")),
    ];
    if let Some(probe) = account.get("lastProbe").filter(|probe| !probe.is_null()) {
        lines.push(format!(
            "  probe: {} ({})",
            probe["status"].as_str().unwrap_or("-"),
            probe["detail"].as_str().unwrap_or("")
        ));
        for (key, label) in [("granted", "granted"), ("missing", "missing")] {
            let names = probe[key]
                .as_array()
                .map(|names| {
                    names
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            if !names.is_empty() {
                lines.push(format!("  {label}: {names}"));
            }
        }
    }
    lines.join("\n")
}

fn row(account: &Value) -> String {
    format!(
        "{:<38} {:<11} {:<20} {:<24} {}",
        account["id"].as_str().unwrap_or("-"),
        account["kind"].as_str().unwrap_or("-"),
        account["label"].as_str().unwrap_or("-"),
        account["lastProbe"]["status"]
            .as_str()
            .unwrap_or("not probed"),
        account["baseUrl"].as_str().unwrap_or("-"),
    )
}
