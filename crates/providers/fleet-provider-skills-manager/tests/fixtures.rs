//! Contract fixtures for the documented CLI JSON shapes (FM-302): version,
//! agent and skill listings, deployment status, the documented failure
//! shape, and the explicit degradation when a CLI upgrade changes shapes.

use fleet_provider_skills_manager::{
    AgentEntry, CliCommand, CliOutcome, DeploymentStatus, Probe, SkillEntry, failure_detail,
    parse_version, redact,
};

fn ok(stdout: &str) -> CliOutcome {
    CliOutcome {
        exit_code: Some(0),
        stdout: stdout.to_owned(),
        stderr: String::new(),
        killed_by_deadline: false,
    }
}

fn failed(code: &str, message: &str) -> CliOutcome {
    CliOutcome {
        exit_code: Some(2),
        stdout: String::new(),
        stderr: serde_json::json!({
            "ok": false,
            "code": code,
            "message": message,
        })
        .to_string(),
        killed_by_deadline: false,
    }
}

#[test]
fn the_version_document_parses() {
    let probe = parse_version(&ok(r#"{"version":"1.34.2"}"#).stdout);
    assert_eq!(
        probe,
        Probe::Present {
            version: "1.34.2".to_owned()
        }
    );
}

#[test]
fn the_bare_version_line_parses() {
    assert_eq!(
        parse_version("skills-manager-cli 1.34.2\n"),
        Probe::Present {
            version: "1.34.2".to_owned()
        }
    );
    assert_eq!(
        parse_version("1.34.2\n"),
        Probe::Present {
            version: "1.34.2".to_owned()
        }
    );
}

#[test]
fn a_shape_changed_version_degrades_explicitly() {
    // A future CLI answering poetry instead of a version is not a version.
    assert_eq!(
        parse_version("the stars are bright tonight\n"),
        Probe::Unsupported
    );
    assert_eq!(parse_version(""), Probe::Unsupported);
}

#[test]
fn a_nonzero_version_answer_is_absence() {
    // The binary refused to identify itself: treat as absent, honestly.
    let outcome = CliOutcome {
        exit_code: Some(127),
        stdout: String::new(),
        stderr: "command not found".to_owned(),
        killed_by_deadline: false,
    };
    assert!(!outcome.succeeded());
    assert_eq!(outcome.failure_code(), None);
}

#[test]
fn the_documented_failure_shape_is_recognized() {
    let outcome = failed("TARGET_CONFLICT", "the target directory is not ours");
    assert!(!outcome.succeeded());
    assert_eq!(outcome.failure_code().as_deref(), Some("TARGET_CONFLICT"));
    assert_eq!(failure_detail(&outcome), "the target directory is not ours");
}

#[test]
fn the_agent_listing_parses() {
    let document = r#"[
        {"id":"claude_code","name":"Claude Code","skillsDir":"~/.claude/skills"},
        {"id":"codex","name":"Codex"}
    ]"#;
    let agents: Vec<AgentEntry> = serde_json::from_str(document).unwrap();
    assert_eq!(agents.len(), 2);
    assert_eq!(agents[0].id, "claude_code");
    assert_eq!(agents[0].skills_dir.as_deref(), Some("~/.claude/skills"));
    assert_eq!(agents[1].skills_dir, None);
}

#[test]
fn the_skill_listing_parses() {
    let document = r#"[
        {"id":"db","name":"db","version":"1.2.0","hasUpdate":false},
        {"id":"react-best-practices"}
    ]"#;
    let skills: Vec<SkillEntry> = serde_json::from_str(document).unwrap();
    assert_eq!(skills.len(), 2);
    assert_eq!(skills[0].has_update, Some(false));
    assert_eq!(skills[1].version, None);
}

#[test]
fn the_deployment_status_parses() {
    let document = r#"{"skillId":"db","deployedTo":["claude_code","codex"]}"#;
    let status: DeploymentStatus = serde_json::from_str(document).unwrap();
    assert_eq!(status.skill_id, "db");
    assert_eq!(status.deployed_to, ["claude_code", "codex"]);
}

#[test]
fn the_argv_carries_the_json_flag_and_the_fixed_binary_name() {
    let command = CliCommand::new(&["skills", "deploy", "db"]).at_root("/srv/skills");
    let argv = command.argv();
    assert_eq!(argv[0], "skills-manager-cli");
    assert_eq!(&argv[1..3], &["--skills-root", "/srv/skills"]);
    assert_eq!(argv.last().unwrap(), "--json");
    assert!(argv.contains(&"deploy".to_owned()));
}

#[test]
fn hostile_output_is_redacted_and_control_noise_flattened() {
    let redacted = redact("fatal: cannot reach https://user:secret@host.invalid/repo.git\nx");
    assert!(!redacted.contains("secret"), "{redacted}");
    assert!(redacted.contains("***@host.invalid"), "{redacted}");
    let control = redact("a\u{1b}[31mb");
    assert!(!control.contains('\u{1b}'), "{control}");
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
    assert_eq!(outcome.failure_code(), None);
}
