//! `fleetctl proxmox console --account <id> --node <node> --vmid <vmid>`
//! (FM-495): opens a console session for one Proxmox guest and prints the
//! URL a person opens in the browser. The CLI never renders the screen and
//! never holds a Proxmox credential; the controller authorizes, audits, and
//! relays. The URL carries the single-use session token in its fragment, so
//! it expires after two minutes unattached and works once.

use serde_json::Value;

use crate::{CliError, Command, Output};

/// The controller route that creates a console session.
pub(crate) fn path(account_id: &str) -> String {
    format!("/api/v1/proxmox/accounts/{account_id}/console-sessions")
}

/// The request body for one guest.
pub(crate) fn body(node: &str, vmid: u32) -> Value {
    serde_json::json!({ "node": node, "vmid": vmid })
}

const USAGE: &str =
    "usage: fleetctl proxmox console --account <account-id> --node <node> --vmid <vmid>";

/// Parses the words after `proxmox console`.
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let mut account_id = None;
    let mut node = None;
    let mut vmid = None;
    let mut words = rest.iter().copied();
    while let Some(flag) = words.next() {
        let mut value = |name: &str| {
            words
                .next()
                .map(str::to_owned)
                .filter(|value| !value.starts_with("--"))
                .ok_or_else(|| CliError {
                    message: format!("{name} requires a value"),
                })
        };
        match flag {
            "--account" => account_id = Some(value("--account")?),
            "--node" => node = Some(value("--node")?),
            "--output" => {
                *output = match value("--output")?.as_str() {
                    "json" => Output::Json,
                    "text" => Output::Text,
                    other => {
                        return Err(CliError {
                            message: format!("--output must be json or text, not {other:?}"),
                        });
                    }
                };
            }
            "--vmid" => {
                let raw = value("--vmid")?;
                vmid = Some(raw.parse::<u32>().map_err(|_| CliError {
                    message: format!("--vmid must be a number, not {raw:?}"),
                })?);
            }
            other => {
                return Err(CliError {
                    message: format!("unknown option {other:?}; {USAGE}"),
                });
            }
        }
    }
    match (account_id, node, vmid) {
        (Some(account_id), Some(node), Some(vmid)) => Ok(Command::ProxmoxConsole {
            account_id,
            node,
            vmid,
        }),
        _ => Err(CliError {
            message: USAGE.to_owned(),
        }),
    }
}

/// Adds the absolute `consoleUrl` to the created session. The controller
/// answers a path relative to its own origin; the CLI knows which origin it
/// reached.
pub(crate) fn decorate(base_url: &str, mut body: Value) -> Value {
    let Some(path) = body["data"]["consolePath"].as_str().map(str::to_owned) else {
        return body;
    };
    let url = format!("{}{path}", base_url.trim_end_matches('/'));
    if let Some(data) = body["data"].as_object_mut() {
        // The URL is the one place the single-use token is printed; the
        // bare token and the socket subprotocols are for the web app.
        data.remove("token");
        data.remove("subprotocols");
        data.remove("consolePath");
        data.insert("consoleUrl".to_owned(), Value::String(url));
    }
    body
}

/// Renders the session as human text: the URL and its limits.
pub(crate) fn render(value: &Value) -> String {
    let url = value["consoleUrl"].as_str().unwrap_or("-");
    format!(
        "console for VM {} on {} (account {})\n  open: {url}\n  the link works once and expires in two minutes if unused; the console closes after {} s without input or {} s in total",
        value["vmid"],
        value["node"].as_str().unwrap_or("-"),
        value["accountId"].as_str().unwrap_or("-"),
        value["idleTimeoutSeconds"],
        value["maxDurationSeconds"],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_needs_account_node_and_vmid() {
        assert_eq!(
            parse(
                &["--account", "a1", "--node", "pve", "--vmid", "101"],
                &mut Output::Text
            )
            .unwrap(),
            Command::ProxmoxConsole {
                account_id: "a1".to_owned(),
                node: "pve".to_owned(),
                vmid: 101
            }
        );
        let mut output = Output::Text;
        assert!(parse(&["--account", "a1", "--node", "pve"], &mut output).is_err());
        assert!(
            parse(
                &["--account", "a1", "--node", "pve", "--vmid", "x"],
                &mut output
            )
            .is_err()
        );
        assert!(parse(&["--account", "a1", "--node", "--vmid", "1"], &mut output).is_err());
        assert!(parse(&["--bogus"], &mut output).is_err());
        parse(
            &[
                "--account",
                "a",
                "--node",
                "n",
                "--vmid",
                "100",
                "--output",
                "json",
            ],
            &mut output,
        )
        .unwrap();
        assert_eq!(output, Output::Json);
    }

    #[test]
    fn the_url_is_absolute_and_keeps_the_token_in_the_fragment() {
        let body = decorate(
            "https://fleet.example.test/",
            serde_json::json!({"data": {"consolePath": "/proxmox/console#session=abc"}}),
        );
        assert_eq!(
            body["data"]["consoleUrl"],
            "https://fleet.example.test/proxmox/console#session=abc"
        );
    }
}
