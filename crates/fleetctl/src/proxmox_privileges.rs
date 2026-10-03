//! `fleetctl proxmox privileges <account-id> [--output json|text]` (FM-604):
//! which Fleet capability tiers the account's API token can perform. The
//! controller evaluates; this adapter only parses and renders.

use serde_json::Value;

use crate::{CliError, Command, Output};

/// The controller route for one account's privilege report.
pub(crate) fn path(account_id: &str) -> String {
    format!("/api/v1/proxmox/accounts/{account_id}/privileges")
}

/// Parses the words after `proxmox privileges`. A trailing
/// `--output json|text` is accepted, as the issue documents the command
/// with it after the account.
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let account_id = match rest {
        [account_id] => account_id,
        [account_id, "--output", format] => {
            *output = match *format {
                "json" => Output::Json,
                "text" => Output::Text,
                other => {
                    return Err(CliError {
                        message: format!("--output must be json or text, not {other:?}"),
                    });
                }
            };
            account_id
        }
        _ => {
            return Err(CliError {
                message: "usage: fleetctl proxmox privileges <account-id> [--output json|text]"
                    .to_owned(),
            });
        }
    };
    if account_id.starts_with('-') || account_id.is_empty() {
        return Err(CliError {
            message: "proxmox privileges needs an account id".to_owned(),
        });
    }
    Ok(Command::ProxmoxPrivileges {
        account_id: (*account_id).to_owned(),
    })
}

/// Renders the privilege report as human text.
pub(crate) fn render(value: &Value) -> String {
    let mut lines = Vec::new();
    let version = value["pveVersion"].as_str().unwrap_or("unknown");
    let rules = value["rulesMajor"]
        .as_u64()
        .map_or_else(|| "-".to_owned(), |major| format!("{major}.x"));
    lines.push(format!(
        "account {}  PVE {version}  rules {rules}",
        value["accountId"].as_str().unwrap_or("-")
    ));
    if let Some(reason) = value["unknownReason"].as_str() {
        lines.push(format!("unknown: {reason}"));
    }
    lines.push(format!("{:<12} {}", "TIER", "STATUS"));
    for tier in value["tiers"].as_array().into_iter().flatten() {
        lines.push(format!(
            "{:<12} {}",
            tier["tier"].as_str().unwrap_or("-"),
            tier["status"].as_str().unwrap_or("-")
        ));
        for missing in tier["missing"].as_array().into_iter().flatten() {
            let privileges = words(&missing["privileges"]);
            let joiner = if missing["anyOf"].as_bool() == Some(true) {
                " or "
            } else {
                ", "
            };
            lines.push(format!(
                "  missing {} on {}  (needed by {})",
                privileges.join(joiner),
                missing["path"].as_str().unwrap_or("-"),
                words(&missing["capabilities"]).join(", ")
            ));
        }
        for check in tier["checks"].as_array().into_iter().flatten() {
            if check["required"].as_bool() == Some(false)
                && check["status"].as_str() == Some("missing")
            {
                lines.push(format!(
                    "  opt-in {} not granted: {} on {}",
                    check["capability"].as_str().unwrap_or("-"),
                    words(&check["missing"]).join(", "),
                    check["path"].as_str().unwrap_or("-")
                ));
            }
        }
    }
    let warnings = words(&value["warnings"]);
    if !warnings.is_empty() {
        lines.push(String::new());
        lines.push("warnings:".to_owned());
        for warning in warnings {
            lines.push(format!("  {warning}"));
        }
    }
    lines.join("\n")
}

fn words(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}
