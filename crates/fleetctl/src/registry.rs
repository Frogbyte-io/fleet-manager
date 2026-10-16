//! `fleetctl registry` (FM-1020 starts it; FM-1013 extends it): the
//! Registry commands. This module is deliberately self-contained so the
//! rest of the command set (`find`, `get`, `set`, `publish`, ...) can be
//! added beside `suggest` without touching it.
//!
//! `suggest domain/<fqdn>` reads the controller's latest RDAP/DNS
//! observation of one domain entry and prints the `fleetctl registry set`
//! patch that would bring the entry in line. It never writes: the patch is
//! for a person or agent to apply in a Fleet Git checkout and publish.

use std::fmt::Write as _;

use serde_json::Value;

use crate::{CliError, Command, Output, RequestShape, usage};

/// One `registry` subcommand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryAction {
    /// Print the suggested `set` patch for a domain entry.
    Suggest {
        /// The domain's natural key (its fqdn).
        key: String,
    },
}

/// Parses `registry suggest domain/<fqdn> [--output json|text]`.
pub(crate) fn parse(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let Some((verb, args)) = rest.split_first() else {
        return Err(CliError { message: usage() });
    };
    if *verb != "suggest" {
        return Err(CliError { message: usage() });
    }
    let Some((target, flags)) = args.split_first() else {
        return Err(CliError { message: usage() });
    };
    let Some(key) = target.strip_prefix("domain/") else {
        return Err(CliError {
            message: "suggest takes a domain entry: domain/<fqdn>".to_owned(),
        });
    };
    // A hostname is the whole key space: this also keeps the path safe.
    if key.is_empty()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(CliError {
            message: format!("{target:?} is not a domain entry address"),
        });
    }
    let mut flags = flags.iter().copied();
    while let Some(flag) = flags.next() {
        match flag {
            "--output" => {
                *output = match flags.next() {
                    Some("json") => Output::Json,
                    Some("text") => Output::Text,
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
    Ok(Command::Registry(RegistryAction::Suggest {
        key: key.to_owned(),
    }))
}

/// The controller request for one subcommand.
pub(crate) fn request(action: &RegistryAction) -> RequestShape {
    match action {
        RegistryAction::Suggest { key } => (
            reqwest::Method::GET,
            format!("/api/v1/registry/entries/domain/{key}/observations"),
            Vec::new(),
            None,
        ),
    }
}

/// Single-quotes a value for a POSIX shell when it needs it.
fn shell_word(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._,/:@".contains(&b))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// A field value as `--field` text: lists are comma-separated.
fn field_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    }
}

/// Renders the observation view: the warnings, the per-field comparison,
/// and the `set` command, or a note that nothing needs changing.
pub(crate) fn render(value: &Value) -> String {
    let key = value["key"].as_str().unwrap_or("?");
    let mut lines = Vec::new();
    match value["observation"].as_object() {
        None => lines.push(format!(
            "domain/{key}: never observed; refresh it first (POST /api/v1/registry/entries/domain/{key}/observations/refresh)"
        )),
        Some(observation) => {
            let rdap = &observation["rdap"];
            lines.push(format!(
                "domain/{key}: RDAP {}, DNS {}",
                rdap["status"].as_str().unwrap_or("?"),
                observation["dns"]["status"].as_str().unwrap_or("?"),
            ));
            if let Some(detail) = rdap["detail"].as_str() {
                lines.push(format!("  RDAP: {detail}"));
            }
        }
    }
    if let Some(warnings) = value["warnings"].as_array() {
        for warning in warnings {
            lines.push(format!(
                "  [{}] {}",
                warning["severity"].as_str().unwrap_or("?"),
                warning["message"].as_str().unwrap_or("")
            ));
        }
    }
    if let Some(diffs) = value["diffs"].as_array() {
        for diff in diffs {
            lines.push(format!(
                "  {:<12} {}",
                diff["field"].as_str().unwrap_or("?"),
                diff["state"].as_str().unwrap_or("?")
            ));
        }
    }
    let suggestion = value["suggestion"].as_array().cloned().unwrap_or_default();
    if suggestion.is_empty() {
        lines.push("nothing to change".to_owned());
    } else {
        let mut command = format!("fleetctl registry set domain/{key}");
        for field in &suggestion {
            let _ = write!(
                command,
                " --field {}={}",
                field["field"].as_str().unwrap_or("?"),
                shell_word(&field_text(&field["value"]))
            );
        }
        lines.push(String::new());
        lines.push("apply in a Fleet Git checkout, then publish:".to_owned());
        lines.push(command);
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parses_a_domain_address_and_output() {
        let mut output = Output::Text;
        let command = parse(
            &["suggest", "domain/example.com", "--output", "json"],
            &mut output,
        )
        .unwrap();
        assert_eq!(
            command,
            Command::Registry(RegistryAction::Suggest {
                key: "example.com".to_owned()
            })
        );
        assert!(matches!(output, Output::Json));
    }

    #[test]
    fn refuses_other_verbs_types_and_odd_keys() {
        let mut output = Output::Text;
        for bad in [
            vec![],
            vec!["find"],
            vec!["suggest"],
            vec!["suggest", "service/aptabase"],
            vec!["suggest", "domain/"],
            vec!["suggest", "domain/a/b"],
            vec!["suggest", "domain/a b.com"],
            vec!["suggest", "domain/a.com", "--bogus"],
        ] {
            assert!(parse(&bad, &mut output).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn requests_the_observation_view() {
        let (method, path, query, body) = request(&RegistryAction::Suggest {
            key: "example.com".to_owned(),
        });
        assert_eq!(method, reqwest::Method::GET);
        assert_eq!(
            path,
            "/api/v1/registry/entries/domain/example.com/observations"
        );
        assert!(query.is_empty() && body.is_none());
    }

    #[test]
    fn prints_the_set_patch_with_lists_comma_joined_and_values_quoted() {
        let view = json!({
            "key": "example.com",
            "observation": {"rdap": {"status": "ok"}, "dns": {"status": "ok"}},
            "warnings": [{"severity": "warn", "message": "The registry lists the registrar as Namecheap, Inc."}],
            "diffs": [{"field": "registrar", "state": "changed"}],
            "suggestion": [
                {"field": "registrar", "value": "Namecheap, Inc."},
                {"field": "expires", "value": "2027-08-13"},
                {"field": "nameservers", "value": ["a.ns.net", "b.ns.net"]},
            ],
        });
        let text = render(&view);
        assert!(text.contains(
            "fleetctl registry set domain/example.com --field registrar='Namecheap, Inc.' --field expires=2027-08-13 --field nameservers=a.ns.net,b.ns.net"
        ), "{text}");
        assert!(text.contains("[warn]"));
    }

    #[test]
    fn says_so_when_nothing_changes_or_nothing_was_observed() {
        let in_sync = json!({"key": "a.com", "observation": {"rdap": {"status": "ok"}, "dns": {"status": "ok"}},
            "warnings": [], "diffs": [], "suggestion": []});
        assert!(render(&in_sync).contains("nothing to change"));
        let never = json!({"key": "a.com", "observation": null, "warnings": [], "diffs": [], "suggestion": []});
        assert!(render(&never).contains("never observed"));
    }
}
