//! The provider operations over a fake transport: exit-status handling,
//! deadline kills, shape degradation, and the skill-id match check.

use fleet_provider_skills_manager::{
    AgentEntry, CliCommand, CliOutcome, DeploymentStatus, Probe, SkillEntry, list_agents,
    list_skills, probe, skill_status,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone)]
struct FakeCli {
    outcome: CliOutcome,
    seen: Arc<Mutex<Vec<Vec<String>>>>,
}

impl FakeCli {
    fn ok(stdout: &str) -> Arc<Self> {
        Arc::new(Self {
            outcome: CliOutcome {
                exit_code: Some(0),
                stdout: stdout.to_owned(),
                stderr: String::new(),
                killed_by_deadline: false,
            },
            seen: Arc::new(Mutex::new(Vec::new())),
        })
    }
    fn failed(code: &str) -> Arc<Self> {
        Arc::new(Self {
            outcome: CliOutcome {
                exit_code: Some(2),
                stdout: String::new(),
                stderr: serde_json::json!({"ok": false, "code": code, "message": "refused"})
                    .to_string(),
                killed_by_deadline: false,
            },
            seen: Arc::new(Mutex::new(Vec::new())),
        })
    }
    fn killed() -> Arc<Self> {
        Arc::new(Self {
            outcome: CliOutcome {
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                killed_by_deadline: true,
            },
            seen: Arc::new(Mutex::new(Vec::new())),
        })
    }
    fn commands(&self) -> Vec<Vec<String>> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl fleet_provider_skills_manager::CliTransport for FakeCli {
    async fn run(&self, command: &CliCommand, _deadline: Duration) -> Result<CliOutcome, String> {
        self.seen.lock().unwrap().push(command.argv());
        Ok(self.outcome.clone())
    }
}

#[tokio::test]
async fn the_probe_asks_for_the_version_first() {
    let transport = FakeCli::ok("skills-manager-cli 1.34.2\n");
    let answer = probe(transport.as_ref(), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        answer,
        Probe::Present {
            version: "1.34.2".to_owned()
        }
    );
    assert_eq!(transport.commands()[0][0], "skills-manager-cli");
    assert_eq!(transport.commands()[0].last().unwrap(), "--json");
}

#[tokio::test]
async fn a_deadline_kill_is_a_transport_error() {
    let transport = FakeCli::killed();
    let answer = probe(transport.as_ref(), Duration::from_secs(5)).await;
    assert!(answer.is_err(), "a killed probe never answers");
}

#[tokio::test]
async fn the_agent_listing_flows_through_the_transport() {
    let transport = FakeCli::ok(r#"[{"id":"claude_code","skillsDir":"~/.claude/skills"}]"#);
    let agents: Vec<AgentEntry> = list_agents(transport.as_ref(), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].id, "claude_code");
    assert_eq!(transport.commands()[0][1], "agents");
}

#[tokio::test]
async fn a_failed_listing_names_the_documented_code() {
    let transport = FakeCli::failed("REPO_LOCKED");
    let answer = list_skills(transport.as_ref(), Duration::from_secs(5)).await;
    let error = answer.unwrap_err();
    // The detail is the documented message; the code is data the caller
    // reads from the failure shape, not prose.
    assert_eq!(error, "the skills command failed: refused");
}

#[tokio::test]
async fn a_shape_changed_listing_degrades_explicitly() {
    let transport = FakeCli::ok("not json at all");
    let answer = list_skills(transport.as_ref(), Duration::from_secs(5)).await;
    let error = answer.unwrap_err();
    assert!(error.contains("unsupported_version"), "{error}");
}

#[tokio::test]
async fn the_status_flow_requires_the_requested_skill() {
    let transport = FakeCli::ok(r#"{"skillId":"db","deployedTo":["claude_code"]}"#);
    let status: DeploymentStatus = skill_status(transport.as_ref(), "db", Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(status.deployed_to, ["claude_code"]);

    let transport = FakeCli::ok(r#"{"skillId":"other","deployedTo":[]}"#);
    let answer = skill_status(transport.as_ref(), "db", Duration::from_secs(5)).await;
    let error = answer.unwrap_err();
    assert!(error.contains("unsupported_version"), "{error}");
}

#[tokio::test]
async fn a_leading_dash_skill_id_is_refused_locally() {
    let transport = FakeCli::ok("{}");
    let answer = skill_status(transport.as_ref(), "--flag", Duration::from_secs(5)).await;
    assert!(answer.is_err(), "the refusal happens before any transport");
    assert!(transport.commands().is_empty());
}

#[tokio::test]
async fn the_skill_listing_flows_through_the_transport() {
    let transport = FakeCli::ok(r#"[{"id":"db","version":"1.2.0"}]"#);
    let skills: Vec<SkillEntry> = list_skills(transport.as_ref(), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(skills[0].id, "db");
    assert_eq!(transport.commands()[0][1], "skills");
}
