//! Keeps the official `fleet` skill (`skills/fleet/SKILL.md`) honest: every
//! `fleetctl` command in its code blocks must parse with `--output json`,
//! and the controller request each one sends is pinned in a snapshot. A CLI
//! change that breaks or reroutes a documented command fails here until the
//! skill and the snapshot are updated together.
//!
//! Regenerate the snapshot with `UPDATE_SNAPSHOTS=1 cargo test -p fleetctl skill_doc`.

use std::fmt::Write as _;

use super::{Command, EVENTS_PATH, Output, SYSTEM_PATH, parse, request_for};

const SKILL_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../skills/fleet/SKILL.md");
const SNAPSHOT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/snapshots/fleet_skill_commands.txt"
);

/// The `fleetctl` lines inside the skill's fenced code blocks.
fn documented_commands(markdown: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut in_block = false;
    for line in markdown.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_block = !in_block;
            continue;
        }
        if in_block && trimmed.starts_with("fleetctl ") {
            commands.push(trimmed.to_owned());
        }
    }
    commands
}

/// Splits a documented command like a POSIX shell would for the subset the
/// skill uses: whitespace-separated words and double-quoted strings.
fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut has_word = false;
    for character in line.chars() {
        match character {
            '"' => {
                quoted = !quoted;
                has_word = true;
            }
            c if c.is_whitespace() && !quoted => {
                if has_word {
                    words.push(std::mem::take(&mut current));
                    has_word = false;
                }
            }
            c => {
                current.push(c);
                has_word = true;
            }
        }
    }
    assert!(!quoted, "unbalanced quote in documented command: {line}");
    if has_word {
        words.push(current);
    }
    words
}

/// Replaces `<placeholder>` words with representative values.
fn fill_placeholders(word: &str) -> String {
    if !(word.starts_with('<') && word.ends_with('>')) {
        return word.to_owned();
    }
    match word {
        "<path>" => "/home/dev/src".to_owned(),
        "<tag>" => "gpu".to_owned(),
        other => format!("{}-example", other.trim_matches(['<', '>'])),
    }
}

/// One line per documented command: the command, then the request it sends.
fn summarize(line: &str) -> String {
    let words: Vec<String> = shell_words(line)
        .iter()
        .skip(1)
        .map(|word| fill_placeholders(word))
        .collect();
    let invocation = parse(&words)
        .unwrap_or_else(|error| panic!("documented command does not parse: {line}\n{error}"));
    assert_eq!(
        invocation.output,
        Output::Json,
        "documented command must pass --output json before the command word: {line}"
    );
    let request = match &invocation.command {
        // Neither goes through `request_for`; their routes are the constants
        // the real request code uses.
        Command::Status => format!("local fleetd socket (GET {SYSTEM_PATH} only with --url)"),
        Command::Events => format!("GET {EVENTS_PATH} (event stream)"),
        command => {
            let (method, path, query, body) = request_for(command).unwrap_or_else(|error| {
                panic!("documented command has no request: {line}\n{error}")
            });
            let mut out = format!("{method} {path}");
            if !query.is_empty() {
                let pairs: Vec<String> = query.iter().map(|(k, v)| format!("{k}={v}")).collect();
                let _ = write!(out, "?{}", pairs.join("&"));
            }
            if let Some(body) = body.as_ref().and_then(serde_json::Value::as_object) {
                // The whole body (keys sorted), so a wrong value for any
                // field (machine, endpoint, root, timeout, dry run) shows.
                let _ = write!(out, " body {}", serde_json::Value::Object(body.clone()));
            }
            out
        }
    };
    format!("{line}\n  -> {request}\n")
}

#[test]
fn every_documented_fleet_skill_command_parses_and_matches_its_snapshot() {
    let markdown = std::fs::read_to_string(SKILL_PATH).expect("skills/fleet/SKILL.md is readable");
    let commands = documented_commands(&markdown);
    assert!(
        commands.len() >= 10,
        "expected the skill to document its workflows, found {} commands",
        commands.len()
    );
    let actual: String = commands.iter().map(|line| summarize(line)).collect();
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        std::fs::create_dir_all(std::path::Path::new(SNAPSHOT_PATH).parent().unwrap()).unwrap();
        std::fs::write(SNAPSHOT_PATH, &actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(SNAPSHOT_PATH).unwrap_or_default();
    assert_eq!(
        actual, expected,
        "the fleet skill's commands changed; review, then regenerate with UPDATE_SNAPSHOTS=1"
    );
}

#[test]
fn text_mode_commands_are_refused_by_the_coverage_check() {
    // The skill's own rule: `--output json` after the command word is not
    // the global flag, so such a command must not slip through.
    let result = std::panic::catch_unwind(|| summarize("fleetctl machines list --output json"));
    assert!(result.is_err());
}

#[test]
fn shell_words_handle_the_quoting_the_skill_uses() {
    assert_eq!(
        shell_words(r#"fleetctl lab lease v1 --purpose "reproduce flaky test""#),
        vec![
            "fleetctl",
            "lab",
            "lease",
            "v1",
            "--purpose",
            "reproduce flaky test"
        ]
    );
}
