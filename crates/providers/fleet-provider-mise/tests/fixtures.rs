//! Contract fixtures for the documented CLI shapes (FM-304): version
//! shapes, the `mise ls --json` inventory, and redaction.

use fleet_provider_mise::{
    CliCommand, CliOutcome, Probe, ToolVersion, failure_detail, parse_ls, parse_version, redact,
};

fn ok(stdout: &str) -> CliOutcome {
    CliOutcome {
        exit_code: Some(0),
        stdout: stdout.to_owned(),
        stderr: String::new(),
        killed_by_deadline: false,
    }
}

#[test]
fn the_version_shapes_parse() {
    assert_eq!(
        parse_version(&ok(r#"{"version":"2026.1.2"}"#).stdout),
        Probe::Present {
            version: "2026.1.2".to_owned()
        }
    );
    assert_eq!(
        parse_version("mise 2026.1.2\n"),
        Probe::Present {
            version: "2026.1.2".to_owned()
        }
    );
    assert_eq!(
        parse_version("the stars are bright tonight\n"),
        Probe::Unsupported
    );
}

#[test]
fn the_ls_inventory_parses() {
    let document = r#"{
        "node": [{"version": "20.11.0", "requested": "20", "installed": true}],
        "python": [{"version": "3.12.1", "installed": false}]
    }"#;
    let inventory = parse_ls(document).unwrap();
    assert_eq!(inventory.len(), 2);
    let (node, records) = &inventory[0];
    assert_eq!(node, "node");
    assert_eq!(records[0].version.as_deref(), Some("20.11.0"));
    assert_eq!(records[0].installed, Some(true));
}

#[test]
fn a_shape_changed_ls_degrades_explicitly() {
    assert!(parse_ls("not json at all").is_err());
    assert!(parse_ls(r"[1,2,3]").is_err());
    assert!(parse_ls(r#"{"node": "20.11.0"}"#).is_err());
}

#[test]
fn the_argv_is_verbatim() {
    assert_eq!(
        CliCommand::new(&["ls", "--json"]).argv(),
        vec!["mise", "ls", "--json"]
    );
}

#[test]
fn credential_shaped_urls_are_scrubbed() {
    let redacted = redact("cannot reach https://user:secret@host.invalid/tool.tar.gz");
    assert!(!redacted.contains("secret"), "{redacted}");
    assert!(redacted.contains("***@host.invalid"), "{redacted}");
}

#[test]
fn the_failure_detail_is_redacted() {
    let outcome = CliOutcome {
        exit_code: Some(2),
        stdout: String::new(),
        stderr: "mise install failed: https://user:secret@host.invalid/x".to_owned(),
        killed_by_deadline: false,
    };
    let detail = failure_detail(&outcome);
    assert!(!detail.contains("secret"), "{detail}");
}

#[test]
fn a_deadline_kill_is_not_success() {
    let outcome = CliOutcome {
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        killed_by_deadline: true,
    };
    assert!(!outcome.succeeded());
}

#[test]
fn the_tool_version_record_defaults_are_honest() {
    let record: ToolVersion = serde_json::from_str(r"{}").unwrap();
    assert_eq!(record.version, None);
    assert_eq!(record.requested, None);
    assert_eq!(record.installed, None);
}
