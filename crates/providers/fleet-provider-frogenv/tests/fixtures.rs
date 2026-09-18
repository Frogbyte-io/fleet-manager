//! Contract fixtures for the documented CLI shapes (FM-303): the status
//! JSON document, version shapes, ceremony failure states, and the
//! redaction of value-shaped material.

use fleet_provider_frogenv::{
    CliCommand, CliOutcome, Probe, failure_detail, parse_version, redact,
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
fn the_status_document_parses() {
    let document: serde_json::Value =
        serde_json::from_str(r#"{"configured":true,"machineState":"approved","machineId":"host-abc123","gitRemote":"git@github.com:example/fleet-secrets.git"}"#).unwrap();
    assert_eq!(document["configured"], true);
    assert_eq!(document["machineState"], "approved");
    assert_eq!(document["machineId"], "host-abc123");
}

#[test]
fn the_status_document_survives_missing_optional_fields() {
    let document: serde_json::Value = serde_json::from_str(r#"{"configured":false}"#).unwrap();
    assert_eq!(document["configured"], false);
    assert_eq!(document["machineState"], serde_json::Value::Null);
}

#[test]
fn the_version_shapes_parse() {
    assert_eq!(
        parse_version(&ok(r#"{"version":"0.2.0"}"#).stdout),
        Probe::Present {
            version: "0.2.0".to_owned()
        }
    );
    assert_eq!(
        parse_version("frogenv 0.2.0\n"),
        Probe::Present {
            version: "0.2.0".to_owned()
        }
    );
    assert_eq!(
        parse_version("the stars are bright tonight\n"),
        Probe::Unsupported
    );
}

#[test]
fn the_argv_never_adds_json_to_human_text_commands() {
    // Only `status` is documented JSON; check and machine list are human
    // text and must not be pretended machine-readable.
    assert_eq!(
        CliCommand::new(&["status"]).argv(),
        vec!["frogenv", "status"]
    );
    assert_eq!(CliCommand::new(&["check"]).argv(), vec!["frogenv", "check"]);
}

#[test]
fn age_secret_keys_are_scrubbed() {
    let redacted = redact("AGE-SECRET-KEY-1QQQQQEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEQQ");
    assert!(!redacted.contains("AGE-SECRET-KEY"), "{redacted}");
    assert!(redacted.contains("[redacted"), "{redacted}");
}

#[test]
fn sops_payloads_are_scrubbed() {
    let redacted = redact("data: ENC[AES256_GCM,data:example,iv:aaa,tag:bbb,type:str]");
    assert!(!redacted.contains("AES256"), "{redacted}");
    let sops_marker = redact("sops: version 3.9");
    assert!(sops_marker.contains("[redacted"), "{sops_marker}");
}

#[test]
fn long_key_shaped_runs_are_scrubbed_but_config_survives() {
    let key = "a".repeat(64);
    let redacted = redact(&format!("key: {key}"));
    assert!(!redacted.contains(&key), "{redacted}");
    let config =
        redact("recipient: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq");
    assert!(config.contains("recipient:"), "{config}");
    assert!(
        !config.contains("age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"),
        "{config}"
    );
}

#[test]
fn credential_shaped_urls_are_scrubbed() {
    let redacted = redact("remote https://user:secret@host.invalid/repo.git");
    assert!(!redacted.contains("secret"), "{redacted}");
    assert!(redacted.contains("***@host.invalid"), "{redacted}");
}

#[test]
fn the_failure_detail_is_redacted() {
    let outcome = CliOutcome {
        exit_code: Some(2),
        stdout: String::new(),
        stderr: "AGE-SECRET-KEY-1QQQQQEXAMPLEQQ leaked in the message".to_owned(),
        killed_by_deadline: false,
    };
    let detail = failure_detail(&outcome);
    assert!(!detail.contains("AGE-SECRET-KEY"), "{detail}");
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
