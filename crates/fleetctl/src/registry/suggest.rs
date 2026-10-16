//! `fleetctl registry suggest domain/<fqdn>` (FM-1020): the controller's
//! latest RDAP/DNS observation of one domain entry, as the `registry set`
//! patch that would bring the entry in line. It never writes: the patch is
//! for a person or agent to apply in a Fleet Git checkout and publish.
//!
//! The read is `GET /api/v1/registry/entries/domain/<fqdn>/observations`;
//! `--output json` prints that view, whose `suggestion` array is the patch.

use std::fmt::Write as _;

use serde_json::Value;

/// The observation view's path for a domain key (a hostname, so it needs
/// no encoding; the parser admits only hostname characters).
pub(super) fn path(key: &str) -> String {
    format!("/api/v1/registry/entries/domain/{key}/observations")
}

/// Whether a key is a hostname: the whole key space of `domain` entries,
/// which also keeps the request path safe.
pub(super) fn is_hostname(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
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

/// Whether a payload is an observation view.
pub(super) fn is_view(payload: &Value) -> bool {
    payload.get("diffs").is_some() && payload.get("suggestion").is_some()
}

/// Renders the observation view: the warnings, the per-field comparison,
/// and the `set` command, or a note that nothing needs changing.
pub(super) fn render(value: &Value) -> String {
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
    for warning in value["warnings"].as_array().into_iter().flatten() {
        lines.push(format!(
            "  [{}] {}",
            warning["severity"].as_str().unwrap_or("?"),
            warning["message"].as_str().unwrap_or("")
        ));
    }
    for diff in value["diffs"].as_array().into_iter().flatten() {
        lines.push(format!(
            "  {:<12} {}",
            diff["field"].as_str().unwrap_or("?"),
            diff["state"].as_str().unwrap_or("?")
        ));
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
    fn hostnames_only() {
        assert!(is_hostname("example.com"));
        for bad in ["", "a/b", "a b.com", "a?b"] {
            assert!(!is_hostname(bad), "{bad:?}");
        }
        assert_eq!(
            path("example.com"),
            "/api/v1/registry/entries/domain/example.com/observations"
        );
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
        assert!(is_view(&view));
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
