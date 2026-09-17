//! Fixture tests for the discovery probe's output protocol (FM-301):
//! multi-root scans, dirty and detached-HEAD checkouts, unreadable
//! checkouts, hostile output, and the observation bound. Values are base64,
//! so the fixtures encode them the way the remote side does.

use base64::Engine as _;
use fleet_provider_ssh::{DISCOVERY_SOURCE, MAX_CHECKOUTS, parse_discovery_output};

fn value64(value: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
}

fn line(root: &str, branch: &str, head: &str, dirty: &str, remote: &str, status: &str) -> String {
    format!(
        "{{\"root64\":\"{}\",\"branch64\":\"{}\",\"head64\":\"{}\",\"dirty\":\"{dirty}\",\"remote64\":\"{}\",\"status\":\"{status}\",\"at\":1000}}",
        value64(root),
        value64(branch),
        value64(head),
        value64(remote),
    )
}

#[test]
fn a_multi_root_scan_parses_into_observations() {
    let stdout = [
        line(
            "/home/dev/code/fleet-manager",
            "main",
            "abc123",
            "false",
            "git@github.com:Frogbyte-io/fleet-manager.git",
            "known",
        ),
        line(
            "/home/dev/work/tools",
            "feat/x",
            "def456",
            "true",
            "https://example.com/tools.git",
            "known",
        ),
    ]
    .join("\n");

    let found = parse_discovery_output(&stdout);
    assert_eq!(found.len(), 2);
    let first = &found[0];
    assert_eq!(first.root, "/home/dev/code/fleet-manager");
    assert_eq!(first.branch.as_deref(), Some("main"));
    assert_eq!(first.head.as_deref(), Some("abc123"));
    assert_eq!(first.dirty, Some(false));
    assert_eq!(
        first.remote.as_deref(),
        Some("git@github.com:Frogbyte-io/fleet-manager.git")
    );
    assert_eq!(first.status, "known");
    assert_eq!(found[1].dirty, Some(true));
}

#[test]
fn an_unreadable_checkout_is_an_honest_unavailable() {
    let stdout = line("/srv/broken", "", "", "", "", "unavailable");
    let found = parse_discovery_output(&stdout);
    assert_eq!(found.len(), 1);
    let checkout = &found[0];
    assert_eq!(checkout.root, "/srv/broken");
    assert_eq!(checkout.branch, None);
    assert_eq!(checkout.head, None);
    assert_eq!(checkout.dirty, None);
    assert_eq!(checkout.status, "unavailable");
}

#[test]
fn a_detached_head_still_reports_its_commit() {
    // `rev-parse --abbrev-ref HEAD` answers `HEAD` in a detached state;
    // that is data, not an error.
    let stdout = line("/repo", "HEAD", "deadbee", "false", "", "known");
    let found = parse_discovery_output(&stdout);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].branch.as_deref(), Some("HEAD"));
    assert_eq!(found[0].head.as_deref(), Some("deadbee"));
    assert_eq!(found[0].remote, None, "no origin is an absent field");
}

#[test]
fn hostile_output_is_bounded_and_never_corrupts_the_stream() {
    // ANSI escapes, prompt strings, newlines-in-values: all survive as
    // opaque base64 and stay data on decode.
    let hostile_root = "\x1b]0;prompt\x07/tmp/evil";
    let hostile_remote = "https://user:pass@example.com/x\nrm -rf /";
    let stdout = [
        line(
            hostile_root,
            "main",
            "abc123",
            "false",
            hostile_remote,
            "known",
        ),
        line(
            "/clean",
            "main",
            "abc123",
            "false",
            "https://example.com/clean.git",
            "known",
        ),
    ]
    .join("\n");

    let found = parse_discovery_output(&stdout);
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].root, hostile_root);
    assert_eq!(found[0].remote.as_deref(), Some(hostile_remote));
    assert_eq!(found[1].root, "/clean");
}

#[test]
fn malformed_lines_are_skipped_and_the_rest_survives() {
    let stdout = [
        "not json at all".to_owned(),
        "{\"root64\":\"\",\"status\":\"known\",\"at\":1000}".to_owned(),
        line("/ok", "main", "abc123", "false", "", "known"),
        line("/bad-status", "main", "abc123", "false", "", "maybe"),
        line("/missing-dirty", "main", "abc123", "", "", "known"),
    ]
    .join("\n");
    let found = parse_discovery_output(&stdout);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].root, "/ok");
}

#[test]
fn over_bound_values_drop_their_observation() {
    let long_root = format!("/{}", "a".repeat(500));
    let stdout = [
        line(&long_root, "main", "abc123", "false", "", "known"),
        line("/fits", "main", "abc123", "false", "", "known"),
    ]
    .join("\n");
    let found = parse_discovery_output(&stdout);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].root, "/fits");
}

#[test]
fn the_scan_is_capped_at_the_observation_bound() {
    let flood: Vec<String> = (0..MAX_CHECKOUTS + 10)
        .map(|index| {
            line(
                &format!("/r{index}"),
                "main",
                "abc123",
                "false",
                "",
                "known",
            )
        })
        .collect();
    let found = parse_discovery_output(&flood.join("\n"));
    assert_eq!(found.len(), MAX_CHECKOUTS);
}

#[test]
fn the_source_is_the_discovery_probe() {
    assert_eq!(DISCOVERY_SOURCE, "checkout-discovery/1");
}
