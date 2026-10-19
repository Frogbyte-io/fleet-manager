//! The ready-project workflow (FM-305): plan, execute, and verify, over
//! durable operations.
//!
//! The workflow is a plan-then-execute state machine: the plan is
//! computed from observed state, each step maps to an existing audited
//! operation kind, and progress and compensation live in the operation
//! record. A plan is idempotent by construction — every step carries the
//! predicate that makes it skippable, so a re-run computes the same plan
//! minus the steps already satisfied. Blocked/manual steps (a Frogenv
//! approval) are a first-class outcome: the workflow completes
//! `blocked_manual_approval` with the remaining steps named, never a
//! failure or a hang. No secret ever surfaces: the workflow composes
//! operations whose own redaction rules hold.
//!
//! The plan is inspectable before execution: a dry run computes and
//! returns it without creating anything.
//!
//! Frogenv is a declaration, like tools and skills: its steps are planned
//! only when the workflow declares the project uses Frogenv. A declared
//! project on a machine without the Frogenv CLI is refused with the named
//! reason `frogenv_missing`, never a generic step failure.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The steps a ready plan may contain, in execution order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum ReadyStep {
    /// Clone the project's remote into a checkout root on the machine.
    /// Skipped when a checkout matching the project's normalized remote
    /// already exists.
    Clone {
        /// The checkout root the clone lands in.
        root: String,
    },
    /// Install the project's declared tools through mise. Skipped when
    /// mise itself reports the requested versions installed — read from
    /// mise's own output, never from a Fleet-side model.
    MiseInstall {
        /// The tool to install.
        tool: String,
        /// The pinned version to install.
        version: String,
    },
    /// Run the Frogenv setup ceremony for the checkout. Skipped when
    /// Frogenv is already configured for the machine.
    FrogenvSetup,
    /// Deploy the project's skills to the machine's agents. Skipped when
    /// the deployment status already matches.
    SkillsDeploy {
        /// The skill to deploy.
        skill_id: String,
        /// The agents to deploy to.
        agents: Vec<String>,
    },
    /// Re-observe the machine and report readiness. Always runs.
    Verify,
}

impl ReadyStep {
    /// The step's stable name, as recorded in progress and results.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Clone { .. } => "clone",
            Self::MiseInstall { .. } => "mise_install",
            Self::FrogenvSetup => "frogenv_setup",
            Self::SkillsDeploy { .. } => "skills_deploy",
            Self::Verify => "verify",
        }
    }

    /// The operation kind the step maps to.
    #[must_use]
    pub fn operation_kind(&self) -> &'static str {
        match self {
            Self::Clone { .. } => "projects.clone",
            Self::MiseInstall { .. } => "mise.install",
            Self::FrogenvSetup => "frogenv.setup",
            Self::SkillsDeploy { .. } => "skills.deploy",
            Self::Verify => "tools.inventory",
        }
    }
}

impl fmt::Display for ReadyStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clone { root } => write!(f, "clone into {root}"),
            Self::MiseInstall { tool, version } => write!(f, "install {tool}@{version}"),
            Self::FrogenvSetup => write!(f, "configure Frogenv"),
            Self::SkillsDeploy { skill_id, agents } => {
                write!(f, "deploy {skill_id} to {} agent(s)", agents.len())
            }
            Self::Verify => write!(f, "verify readiness"),
        }
    }
}

/// The observed state a plan is computed from. Every field is optional
/// because an observation may be unavailable; an unavailable observation
/// makes the corresponding step run (it is cheaper to retry an idempotent
/// step than to guess).
#[derive(Clone, Debug, Default)]
pub struct ObservedState {
    /// A checkout root on the machine whose NORMALIZED remote matches the
    /// project, when discovery found one. The observer normalizes both
    /// sides, so a checkout under a different remote spelling still
    /// matches.
    pub matching_checkout: Option<String>,
    /// The tools mise reports installed with their versions, when mise is
    /// present and answered.
    pub mise_installed: Vec<(String, String)>,
    /// Whether Frogenv is configured on the machine, when status answered.
    pub frogenv_configured: Option<bool>,
    /// Whether the Frogenv CLI is installed on the machine: `Some(false)`
    /// only when the status probe positively reported it absent, `None`
    /// when the probe did not answer or was not run.
    pub frogenv_installed: Option<bool>,
    /// The skill deployments the machine's agents already carry, as
    /// (skill id, agent) pairs, when the CLI answered.
    pub skills_deployed: Vec<(String, String)>,
}

/// The tool requests a plan's mise step needs, as declared by the project
/// and read from mise's own output — never translated into a Fleet-side
/// model.
#[derive(Clone, Debug, Default)]
pub struct ToolRequest {
    /// The tool name.
    pub tool: String,
    /// The pinned version.
    pub version: String,
}

/// Whether the project the workflow readies uses Frogenv. Frogenv keeps a
/// project's environment in its own secrets repository, never in the
/// checkout, so this is a declaration the workflow's caller makes — like
/// the tools and the skill — not something Fleet infers from files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrogenvUse {
    /// The project uses Frogenv: setup is planned unless the machine is
    /// already configured, and a machine without the CLI is refused.
    Required,
    /// The project does not use Frogenv: no Frogenv step is planned and
    /// the machine's Frogenv state is irrelevant.
    NotUsed,
}

/// Why a planned step is refused before it runs: the machine cannot
/// satisfy it, so running it would only fail generically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadyRefusal {
    /// The project uses Frogenv but the machine has no Frogenv CLI.
    FrogenvMissing,
}

impl ReadyRefusal {
    /// The stable reason recorded in the workflow's error.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::FrogenvMissing => "frogenv_missing",
        }
    }

    /// The operator-facing detail.
    #[must_use]
    pub fn detail(&self) -> &'static str {
        match self {
            Self::FrogenvMissing => {
                "the project uses Frogenv but the Frogenv CLI is not installed on the machine; install it (or use an image that carries it) and retry"
            }
        }
    }
}

/// Decides whether a planned step must be refused before it runs, given
/// what was observed. Only a positive observation refuses: an unanswered
/// probe lets the step run, as everywhere else in the plan.
#[must_use]
pub fn step_refusal(step: &ReadyStep, observed: &ObservedState) -> Option<ReadyRefusal> {
    match step {
        ReadyStep::FrogenvSetup if observed.frogenv_installed == Some(false) => {
            Some(ReadyRefusal::FrogenvMissing)
        }
        _ => None,
    }
}

/// Computes the plan: the ordered steps still needed to make the project
/// ready, given what was observed. The same observation always yields the
/// same plan; a re-run after partial execution yields only the remainder.
/// Frogenv steps are planned only when the project uses Frogenv.
#[must_use]
pub fn plan_ready(
    checkout_root: &str,
    tools: &[ToolRequest],
    skill: Option<(&str, &[String])>,
    frogenv: FrogenvUse,
    observed: &ObservedState,
) -> Vec<ReadyStep> {
    let mut steps = Vec::new();
    if observed.matching_checkout.is_none() {
        steps.push(ReadyStep::Clone {
            root: checkout_root.to_owned(),
        });
    }
    for request in tools {
        let installed = observed
            .mise_installed
            .iter()
            .any(|(tool, version)| tool == &request.tool && version == &request.version);
        if !installed {
            steps.push(ReadyStep::MiseInstall {
                tool: request.tool.clone(),
                version: request.version.clone(),
            });
        }
    }
    if frogenv == FrogenvUse::Required && observed.frogenv_configured != Some(true) {
        steps.push(ReadyStep::FrogenvSetup);
    }
    if let Some((skill_id, agents)) = skill {
        // The deployment predicate names the skill: an observed
        // deployment of another skill is not a match.
        let deployed = agents.iter().all(|agent| {
            observed
                .skills_deployed
                .iter()
                .any(|(observed_skill, observed_agent)| {
                    observed_skill == skill_id && observed_agent == agent
                })
        });
        if !deployed {
            steps.push(ReadyStep::SkillsDeploy {
                skill_id: skill_id.to_owned(),
                agents: agents.to_vec(),
            });
        }
    }
    steps.push(ReadyStep::Verify);
    steps
}

#[cfg(test)]
mod tests {
    use super::{
        FrogenvUse, ObservedState, ReadyRefusal, ReadyStep, ToolRequest, plan_ready, step_refusal,
    };

    fn tool(tool: &str, version: &str) -> ToolRequest {
        ToolRequest {
            tool: tool.to_owned(),
            version: version.to_owned(),
        }
    }

    #[test]
    fn a_fresh_machine_plans_every_step() {
        let steps = plan_ready(
            "/srv/repo",
            &[tool("node", "20.11.0")],
            Some(("db", &["claude_code".to_owned()])),
            FrogenvUse::Required,
            &ObservedState::default(),
        );
        let names: Vec<&str> = steps.iter().map(ReadyStep::name).collect();
        assert_eq!(
            names,
            [
                "clone",
                "mise_install",
                "frogenv_setup",
                "skills_deploy",
                "verify"
            ]
        );
    }

    #[test]
    fn a_re_run_plans_only_the_remainder() {
        let observed = ObservedState {
            matching_checkout: Some("/srv/repo".to_owned()),
            mise_installed: vec![("node".to_owned(), "20.11.0".to_owned())],
            frogenv_configured: Some(true),
            frogenv_installed: Some(true),
            skills_deployed: vec![("db".to_owned(), "claude_code".to_owned())],
        };
        let steps = plan_ready(
            "/srv/repo",
            &[tool("node", "20.11.0")],
            Some(("db", &["claude_code".to_owned()])),
            FrogenvUse::Required,
            &observed,
        );
        let names: Vec<&str> = steps.iter().map(ReadyStep::name).collect();
        assert_eq!(names, ["verify"], "an already-ready machine only verifies");
    }

    #[test]
    fn a_partially_ready_machine_skips_completed_steps() {
        let observed = ObservedState {
            matching_checkout: Some("/srv/repo".to_owned()),
            mise_installed: vec![],
            frogenv_configured: Some(true),
            frogenv_installed: Some(true),
            skills_deployed: vec![],
        };
        let steps = plan_ready("/srv/repo", &[], None, FrogenvUse::Required, &observed);
        let names: Vec<&str> = steps.iter().map(ReadyStep::name).collect();
        assert_eq!(names, ["verify"], "clone and frogenv are skipped");
    }

    #[test]
    fn a_version_mismatch_installs_but_a_match_skips() {
        let observed = ObservedState {
            mise_installed: vec![("node".to_owned(), "18.0.0".to_owned())],
            ..ObservedState::default()
        };
        let steps = plan_ready(
            "/srv/repo",
            &[tool("node", "20.11.0")],
            None,
            FrogenvUse::Required,
            &observed,
        );
        assert!(steps
            .iter()
            .any(|step| matches!(step, ReadyStep::MiseInstall { version, .. } if version == "20.11.0")),
            "a different installed version is not a match");
    }

    #[test]
    fn a_deployment_of_another_skill_does_not_skip() {
        let observed = ObservedState {
            skills_deployed: vec![("other".to_owned(), "claude_code".to_owned())],
            ..ObservedState::default()
        };
        let steps = plan_ready(
            "/srv/repo",
            &[],
            Some(("db", &["claude_code".to_owned()])),
            FrogenvUse::Required,
            &observed,
        );
        assert!(steps.iter().any(|step| step.name() == "skills_deploy"));
    }

    #[test]
    fn an_unavailable_observation_makes_the_step_run() {
        // frogenv_configured: None (status unanswered) — the setup step
        // runs rather than guessing the machine is configured.
        let observed = ObservedState {
            frogenv_configured: None,
            ..ObservedState::default()
        };
        let steps = plan_ready("/srv/repo", &[], None, FrogenvUse::Required, &observed);
        assert!(steps.iter().any(|step| step.name() == "frogenv_setup"));
    }

    #[test]
    fn the_same_observation_yields_the_same_plan() {
        let observed = ObservedState {
            matching_checkout: Some("/srv/repo".to_owned()),
            ..ObservedState::default()
        };
        let first = plan_ready("/srv/repo", &[], None, FrogenvUse::Required, &observed);
        let second = plan_ready("/srv/repo", &[], None, FrogenvUse::Required, &observed);
        assert_eq!(first, second, "planning is a pure function of observation");
    }

    #[test]
    fn steps_map_to_operation_kinds() {
        let steps = plan_ready(
            "/srv/repo",
            &[],
            None,
            FrogenvUse::Required,
            &ObservedState::default(),
        );
        for step in &steps {
            assert!(!step.operation_kind().is_empty());
        }
        let clone = steps.first().unwrap();
        assert_eq!(clone.operation_kind(), "projects.clone");
        assert_eq!(steps.last().unwrap().operation_kind(), "tools.inventory");
    }

    #[test]
    fn steps_render_human_names() {
        let steps = plan_ready(
            "/srv/repo",
            &[tool("node", "20.11.0")],
            None,
            FrogenvUse::Required,
            &ObservedState::default(),
        );
        assert_eq!(steps[0].to_string(), "clone into /srv/repo");
        assert_eq!(steps[1].to_string(), "install node@20.11.0");
        assert_eq!(steps.last().unwrap().to_string(), "verify readiness");
    }
    #[test]
    fn a_project_without_frogenv_plans_clone_then_verify() {
        // A Lab bootstrap guest: nothing observed, no tools, no skill, and
        // Frogenv not declared — even an unanswered Frogenv probe plans no
        // Frogenv step.
        let steps = plan_ready(
            "/tmp/fleet-projects/p",
            &[],
            None,
            FrogenvUse::NotUsed,
            &ObservedState::default(),
        );
        let names: Vec<&str> = steps.iter().map(ReadyStep::name).collect();
        assert_eq!(names, ["clone", "verify"]);
        assert!(
            steps
                .iter()
                .all(|step| step_refusal(step, &ObservedState::default()).is_none())
        );
    }

    #[test]
    fn a_project_without_frogenv_ignores_a_missing_cli() {
        let observed = ObservedState {
            frogenv_installed: Some(false),
            ..ObservedState::default()
        };
        let steps = plan_ready("/srv/repo", &[], None, FrogenvUse::NotUsed, &observed);
        assert!(steps.iter().all(|step| step.name() != "frogenv_setup"));
        assert!(
            steps
                .iter()
                .all(|step| step_refusal(step, &observed).is_none())
        );
    }

    #[test]
    fn a_frogenv_project_on_a_machine_without_the_cli_is_refused_by_name() {
        let observed = ObservedState {
            frogenv_installed: Some(false),
            ..ObservedState::default()
        };
        let steps = plan_ready("/srv/repo", &[], None, FrogenvUse::Required, &observed);
        let setup = steps
            .iter()
            .find(|step| step.name() == "frogenv_setup")
            .expect("a declared project still plans setup");
        let refusal = step_refusal(setup, &observed);
        assert_eq!(refusal, Some(ReadyRefusal::FrogenvMissing));
        assert_eq!(refusal.unwrap().reason(), "frogenv_missing");
        // Only the Frogenv step is refused: clone and verify still run.
        for step in steps.iter().filter(|step| step.name() != "frogenv_setup") {
            assert!(step_refusal(step, &observed).is_none(), "{step}");
        }
    }

    #[test]
    fn an_unanswered_install_probe_never_refuses() {
        // frogenv_installed: None (the probe did not answer) — setup runs
        // rather than guessing the CLI is absent.
        let observed = ObservedState::default();
        assert!(step_refusal(&ReadyStep::FrogenvSetup, &observed).is_none());
        let installed = ObservedState {
            frogenv_installed: Some(true),
            ..ObservedState::default()
        };
        assert!(step_refusal(&ReadyStep::FrogenvSetup, &installed).is_none());
    }
}
