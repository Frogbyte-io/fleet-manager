//! The ready-project workflow executor (FM-305): walks a plan step by
//! step, creating and awaiting the underlying durable operations.
//!
//! The executor composes the existing kinds — clone, mise install,
//! Frogenv setup, skills deploy, inventory verify — so every step is
//! audited in its own right and the workflow's record carries the whole
//! story: per-step outcomes, the failing step on a failure, and the
//! remaining steps on a block. A step failure stops the workflow with the
//! failing step named; a retry re-runs only the remainder, because the
//! plan is computed from observed state. Cancellation is honored between
//! steps.
//!
//! Blocked/manual steps are a first-class outcome: a Frogenv approval
//! requirement completes the workflow `blocked_manual_approval` with the
//! remaining steps named, never a failure or a hang.
//!
//! Frogenv is declared, not assumed: the payload's `usesFrogenv` (default
//! `true`) decides whether the Frogenv probe runs and its setup is
//! planned. Lab bootstrap declares `false`. A declared project on a
//! machine without the CLI fails `frogenv_missing` at the setup step.

use std::sync::Arc;
use std::time::Duration;

use fleet_application::machine::MachinePort;
use fleet_application::operation::{Operation, Operations};
use fleet_application::ready::{
    FrogenvUse, ObservedState, ReadyStep, ToolRequest, plan_ready, step_refusal,
};
use fleet_application::worker::OperationExecutor;
use fleet_provider_ssh::ExecutionLimiter;

use crate::exec::resolve_ssh_endpoint;

/// The workflow deadline's ceiling: the step deadlines bound the real
/// work, this bounds the whole workflow.
pub const MAX_WORKFLOW_TIMEOUT: u64 = crate::exec::MAX_SCRIPT_TIMEOUT;

/// How the endpoint authenticates.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
enum Auth {
    /// The controller's agent supplies the key.
    Agent,
    /// A specific identity file.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// The `ready.workflow` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadyPayload {
    /// The machine to make ready.
    machine_id: String,
    /// The endpoint id to act through.
    endpoint_id: String,
    /// How the endpoint authenticates.
    auth: Auth,
    /// The project's normalized remote.
    remote: String,
    /// The checkout root the workflow targets.
    root: String,
    /// The tools the project declares, as pinned requests.
    #[serde(default)]
    tools: Vec<PinnedTool>,
    /// The skill to deploy, when the project declares one.
    #[serde(default)]
    skill_id: Option<String>,
    /// The agents the skill deploys to.
    #[serde(default)]
    agents: Vec<String>,
    /// Whether the project uses Frogenv. Absent means `true`, the
    /// behaviour before the declaration existed; Lab bootstrap sends
    /// `false`.
    #[serde(default = "uses_frogenv_by_default")]
    uses_frogenv: bool,
    /// The deadline, in seconds, for the whole workflow. The step
    /// deadlines bound the real work; this one is the caller's ceiling.
    #[allow(dead_code)]
    timeout_seconds: u64,
}

fn uses_frogenv_by_default() -> bool {
    true
}

impl ReadyPayload {
    fn frogenv_use(&self) -> FrogenvUse {
        if self.uses_frogenv {
            FrogenvUse::Required
        } else {
            FrogenvUse::NotUsed
        }
    }
}

/// A pinned tool request inside the payload.
#[derive(Debug, serde::Deserialize)]
struct PinnedTool {
    /// The tool name.
    tool: String,
    /// The pinned version.
    version: String,
}

/// The kind-dispatching ready executor.
#[derive(Debug)]
pub struct ReadyExecutor {
    machines: Arc<dyn MachinePort>,
    operations: Arc<Operations>,
    /// The composed executor chain the plan's steps run through, WITHOUT
    /// the ready dispatch itself: inner steps execute in-process through
    /// the same executors the queue would use, so each step is audited in
    /// its own right and no queue re-entry can deadlock.
    inner: Arc<dyn OperationExecutor>,
    limiter: Arc<ExecutionLimiter>,
    work_dir: std::path::PathBuf,
    lab_readiness: Option<(i64, String, String)>,
}

impl ReadyExecutor {
    /// Composes the executor from its parts. The `inner` chain is the
    /// composed executor WITHOUT the ready dispatch: the plan's steps run
    /// through it in-process, so each step is audited in its own right
    /// and no queue re-entry can deadlock.
    #[must_use]
    pub fn new(
        machines: Arc<dyn MachinePort>,
        operations: Arc<Operations>,
        inner: Arc<dyn OperationExecutor>,
        work_dir: std::path::PathBuf,
        limiter: Arc<ExecutionLimiter>,
    ) -> Self {
        Self {
            machines,
            operations,
            inner,
            limiter,
            work_dir,
            lab_readiness: None,
        }
    }
    /// Bounds Lab checkout observation and checks both parent and workflow
    /// cancellation before starting and while waiting for the scan.
    #[must_use]
    pub fn with_lab_readiness(mut self, deadline: i64, parent: String, workflow: String) -> Self {
        self.lab_readiness = Some((deadline, parent, workflow));
        self
    }

    async fn wait_for_discovery<T>(
        &self,
        mut scan: tokio::task::JoinHandle<T>,
    ) -> Result<T, String> {
        loop {
            tokio::select! {
                result = &mut scan => return result.map_err(|_| "the discovery thread failed".to_owned()),
                () = tokio::time::sleep(Duration::from_millis(50)), if self.lab_readiness.is_some() => {
                    self.check_lab_readiness().await?;
                }
            }
        }
    }

    async fn check_lab_readiness(&self) -> Result<Duration, String> {
        let Some((deadline, parent, workflow)) = &self.lab_readiness else {
            return Ok(fleet_provider_ssh::DISCOVERY_DEADLINE);
        };
        let millis = deadline.saturating_sub(fleet_core::SystemClock::now_unix_millis());
        if millis <= 0 {
            return Err("Lab readiness deadline expired".to_owned());
        }
        for id in [parent, workflow] {
            let operation = self
                .operations
                .get(
                    &fleet_auth::LanAllowAllAuthorizer,
                    fleet_auth::LAN_PRINCIPAL_ID,
                    id,
                )
                .await
                .map_err(|_| "Lab parent unavailable")?;
            if operation.cancel_requested
                || !matches!(operation.state.as_str(), "pending" | "running")
            {
                return Err("Lab readiness was stopped".to_owned());
            }
        }
        Ok(Duration::from_millis(u64::try_from(millis).unwrap_or(0))
            .min(fleet_provider_ssh::DISCOVERY_DEADLINE))
    }
}

#[async_trait::async_trait]
impl OperationExecutor for ReadyExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "ready.workflow" => self.run_workflow(operations, operation).await,
            _ => Err("not a ready kind".to_owned()),
        }
    }
}

impl ReadyExecutor {
    async fn run_workflow(
        &self,
        operations: &Operations,
        operation: &Operation,
    ) -> Result<(), String> {
        let payload: ReadyPayload = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a valid ready record: {error}"))?;

        // The plan is computed from observed state at execution time: a
        // retry after a partial run sees the completed steps satisfied and
        // plans only the remainder.
        let workflow_deadline = std::time::Instant::now()
            + Duration::from_secs(payload.timeout_seconds.min(MAX_WORKFLOW_TIMEOUT));
        let observed = self.observe(&payload).await;
        let tools: Vec<ToolRequest> = payload
            .tools
            .iter()
            .map(|pinned| ToolRequest {
                tool: pinned.tool.clone(),
                version: pinned.version.clone(),
            })
            .collect();
        let skill = payload
            .skill_id
            .as_deref()
            .map(|skill_id| (skill_id, payload.agents.as_slice()));
        let plan = plan_ready(
            &payload.root,
            &tools,
            skill,
            payload.frogenv_use(),
            &observed,
        );
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(i64::try_from(plan.len()).unwrap_or(i64::MAX)),
                Some(&format!(
                    "planned {} step(s): {}",
                    plan.len(),
                    plan.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ")
                )),
            )
            .await
            .map_err(|error| error.to_string())?;

        let mut completed = Vec::new();
        for (index, step) in plan.iter().enumerate() {
            // Cancellation is honored between steps.
            let current = operations
                .get_state(&operation.id)
                .await
                .unwrap_or_else(|_| "running".to_owned());
            if current == "cancelling" {
                return complete_cancelled(operations, &operation.id, &completed, plan.len()).await;
            }
            operations
                .record_progress(
                    &operation.id,
                    Some(i64::try_from(index + 1).unwrap_or(i64::MAX)),
                    Some(i64::try_from(plan.len()).unwrap_or(i64::MAX)),
                    Some(&format!("step {}: {step}", index + 1)),
                )
                .await
                .map_err(|error| error.to_string())?;
            if std::time::Instant::now() >= workflow_deadline {
                return complete_failed(
                    operations,
                    &operation.id,
                    step,
                    STEP_FAILED,
                    "the workflow exceeded its deadline; the completed steps are durable and a retry re-runs only the remainder",
                    &completed,
                    &plan[index..],
                )
                .await;
            }
            // A step the machine positively cannot satisfy is refused by
            // name before it runs, instead of failing generically. The
            // refusal is deliberately at the step, not before the plan:
            // the earlier steps (clone, tools) keep running exactly as
            // they did before the refusal existed, and a retry after
            // installing the CLI re-runs only the remainder.
            if let Some(refusal) = step_refusal(step, &observed) {
                return complete_failed(
                    operations,
                    &operation.id,
                    step,
                    refusal.reason(),
                    refusal.detail(),
                    &completed,
                    &plan[index + 1..],
                )
                .await;
            }
            match self.run_step(&payload, step, workflow_deadline).await {
                StepOutcome::Done => completed.push(step.name().to_owned()),
                StepOutcome::Blocked(reason) => {
                    return complete_blocked(
                        operations,
                        &operation.id,
                        step,
                        &reason,
                        &completed,
                        &plan[index + 1..],
                    )
                    .await;
                }
                StepOutcome::Failed(reason) => {
                    return complete_failed(
                        operations,
                        &operation.id,
                        step,
                        STEP_FAILED,
                        &reason,
                        &completed,
                        &plan[index + 1..],
                    )
                    .await;
                }
            }
        }
        let result_json = serde_json::json!({
            "ready": true,
            "completed": completed,
        })
        .to_string();
        operations
            .complete(&operation.id, "succeeded", Some(&result_json), None)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Observes the machine's state for planning. Every observation is
    /// best-effort: an unavailable observation is `None`, which makes the
    /// corresponding step run rather than guessing.
    async fn observe(&self, payload: &ReadyPayload) -> ObservedState {
        let mut observed = ObservedState::default();
        // The checkout discovery rides the same probe the FM-301 surface
        // uses; a matching remote means the clone step is skippable. Both
        // sides are normalized, so a checkout under a different remote
        // spelling still matches.
        if let Ok(checkouts) = self.discover_checkouts(payload).await {
            let project_remote = fleet_core::NormalizedRemote::parse(&payload.remote)
                .map(|normalized| normalized.as_str().to_owned())
                .unwrap_or_else(|_| payload.remote.clone());
            observed.matching_checkout = checkouts
                .into_iter()
                .find(|checkout| {
                    checkout.remote.as_deref().is_some_and(|remote| {
                        fleet_core::NormalizedRemote::parse(remote)
                            .map(|normalized| normalized.as_str() == project_remote)
                            .unwrap_or(false)
                    })
                })
                .map(|checkout| checkout.root);
        }
        // mise's own inventory, when the CLI answers.
        if let Ok(status) = self.mise_status(payload).await {
            observed.mise_installed = status;
        }
        // Frogenv's own status, only when the project uses Frogenv: a
        // project that does not never probes it, so a machine without the
        // CLI records no failed status operation.
        if payload.uses_frogenv {
            match self.frogenv_configured(payload).await {
                Ok(configured) => {
                    observed.frogenv_installed = Some(true);
                    observed.frogenv_configured = Some(configured);
                }
                Err(FrogenvProbe::NotInstalled) => observed.frogenv_installed = Some(false),
                Err(FrogenvProbe::Unavailable) => {}
            }
        }
        observed
    }

    async fn discover_checkouts(
        &self,
        payload: &ReadyPayload,
    ) -> Result<Vec<DiscoveredCheckout>, String> {
        self.check_lab_readiness().await?;
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        let provider = fleet_provider_ssh::SshProvider::new(self.work_dir.clone())
            .map_err(|error| error.to_string())?;
        let limiter = self.limiter.clone();
        let budget = self.check_lab_readiness().await?;
        let scan = tokio::task::spawn_blocking(move || {
            fleet_provider_ssh::discover(&provider, &limiter, &spec, budget)
        });
        let discovery = self.wait_for_discovery(scan).await?;
        let checkouts = discovery.map_err(|error| error.to_string())?;
        Ok(checkouts
            .into_iter()
            .map(|checkout| DiscoveredCheckout {
                root: checkout.root,
                remote: checkout.remote,
            })
            .collect())
    }

    async fn mise_status(&self, payload: &ReadyPayload) -> Result<Vec<(String, String)>, String> {
        let operation = self
            .spawn_inner(
                "mise.status",
                &serde_json::json!({
                    "machineId": payload.machine_id,
                    "endpointId": payload.endpoint_id,
                    "auth": payload.auth,
                    "timeoutSeconds": 60,
                })
                .to_string(),
            )
            .await?;
        self.operations
            .claim_only_execute(
                self.inner.as_ref(),
                &operation.id,
                fleet_auth::LAN_PRINCIPAL_ID,
            )
            .await?;
        let finished = self
            .operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &operation.id,
            )
            .await
            .map_err(|error| error.to_string())?;
        if finished.state != "succeeded" {
            return Err("the mise status observation did not succeed".to_owned());
        }
        let result: serde_json::Value =
            serde_json::from_str(&finished.result_json.unwrap_or_default())
                .map_err(|error| error.to_string())?;
        let mut installed = Vec::new();
        if let Some(object) = result.get("mise").and_then(|mise| mise.as_object()) {
            for (tool, records) in object {
                for record in records.as_array().unwrap_or(&Vec::new()) {
                    if record["installed"].as_bool() == Some(true)
                        && let Some(version) = record["version"].as_str()
                    {
                        installed.push((tool.clone(), version.to_owned()));
                    }
                }
            }
        }
        Ok(installed)
    }

    async fn frogenv_configured(&self, payload: &ReadyPayload) -> Result<bool, FrogenvProbe> {
        let operation = self
            .spawn_inner(
                "frogenv.status",
                &serde_json::json!({
                    "machineId": payload.machine_id,
                    "endpointId": payload.endpoint_id,
                    "auth": payload.auth,
                    "timeoutSeconds": 60,
                })
                .to_string(),
            )
            .await
            .map_err(|_| FrogenvProbe::Unavailable)?;
        self.operations
            .claim_only_execute(
                self.inner.as_ref(),
                &operation.id,
                fleet_auth::LAN_PRINCIPAL_ID,
            )
            .await
            .map_err(|_| FrogenvProbe::Unavailable)?;
        let finished = self
            .operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &operation.id,
            )
            .await
            .map_err(|_| FrogenvProbe::Unavailable)?;
        if finished.state != "succeeded" {
            // The fixed status script's own "no CLI" report is a positive
            // observation; any other failure leaves the state unknown.
            let error: serde_json::Value =
                serde_json::from_str(finished.error_json.as_deref().unwrap_or("null"))
                    .unwrap_or_default();
            let not_installed = finished.state == "failed"
                && error["reason"] == "status_failed"
                && error["detail"].as_str().is_some_and(|detail| {
                    // Any line: the transport may add its own stderr lines.
                    detail
                        .lines()
                        .any(|line| line.trim() == crate::frogenv::NOT_INSTALLED_DETAIL)
                });
            return Err(if not_installed {
                FrogenvProbe::NotInstalled
            } else {
                FrogenvProbe::Unavailable
            });
        }
        let result: serde_json::Value =
            serde_json::from_str(&finished.result_json.unwrap_or_default())
                .map_err(|_| FrogenvProbe::Unavailable)?;
        Ok(result["status"]["configured"].as_bool() == Some(true))
    }

    /// Runs one step: the inner operation is created for audit (durable
    /// record), claimed, executed in-process through the composed chain,
    /// and completed — the same shape a queue tick would produce.
    async fn run_step(
        &self,
        payload: &ReadyPayload,
        step: &ReadyStep,
        workflow_deadline: std::time::Instant,
    ) -> StepOutcome {
        let (kind, payload_json) = match step {
            ReadyStep::Clone { root } => {
                // The payload carries the normalized identity; git needs a
                // fetchable URL (#329). An unparseable remote is a named
                // refusal, not a git error.
                let remote = match clone_remote(&payload.remote) {
                    Ok(remote) => remote,
                    Err(detail) => return StepOutcome::Failed(detail),
                };
                (
                    "projects.clone",
                    serde_json::json!({
                        "machineId": payload.machine_id,
                        "endpointId": payload.endpoint_id,
                        "auth": payload.auth,
                        "remote": remote,
                        "root": root,
                        "timeoutSeconds": 600,
                    }),
                )
            }
            ReadyStep::MiseInstall { tool, version } => (
                "mise.install",
                serde_json::json!({
                    "machineId": payload.machine_id,
                    "endpointId": payload.endpoint_id,
                    "auth": payload.auth,
                    "tool": tool,
                    "version": version,
                    "timeoutSeconds": 600,
                }),
            ),
            ReadyStep::FrogenvSetup => (
                "frogenv.setup",
                serde_json::json!({
                    "machineId": payload.machine_id,
                    "endpointId": payload.endpoint_id,
                    "auth": payload.auth,
                    "timeoutSeconds": 120,
                }),
            ),
            ReadyStep::SkillsDeploy { skill_id, agents } => (
                "skills.deploy",
                serde_json::json!({
                    "machineId": payload.machine_id,
                    "endpointId": payload.endpoint_id,
                    "auth": payload.auth,
                    "skillId": skill_id,
                    "agents": agents,
                    "timeoutSeconds": 300,
                }),
            ),
            ReadyStep::Verify => (
                "tools.inventory",
                serde_json::json!({
                    "machineId": payload.machine_id,
                    "endpointId": payload.endpoint_id,
                    "auth": payload.auth,
                    "timeoutSeconds": 120,
                }),
            ),
        };
        let _ = workflow_deadline;
        let operation = match self.spawn_inner(kind, &payload_json.to_string()).await {
            Ok(operation) => operation,
            Err(detail) => return StepOutcome::Failed(detail),
        };
        if let Err(detail) = self
            .operations
            .claim_only_execute(
                self.inner.as_ref(),
                &operation.id,
                fleet_auth::LAN_PRINCIPAL_ID,
            )
            .await
        {
            return StepOutcome::Failed(detail);
        }
        let finished = match self.operations.get_state(&operation.id).await {
            Ok(state) => state,
            Err(failure) => return StepOutcome::Failed(failure.to_string()),
        };
        let record = self
            .operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &operation.id,
            )
            .await
            .map_err(|error| error.to_string());
        let Ok(record) = record else {
            return StepOutcome::Failed("the step's record is unreadable".to_owned());
        };
        match finished.as_str() {
            "succeeded" => StepOutcome::Done,
            "blocked_manual_approval" => {
                let error: serde_json::Value =
                    serde_json::from_str(&record.error_json.unwrap_or_default())
                        .unwrap_or(serde_json::Value::Null);
                StepOutcome::Blocked(error["detail"].as_str().unwrap_or_default().to_owned())
            }
            _ => {
                let error: serde_json::Value =
                    serde_json::from_str(&record.error_json.unwrap_or_default())
                        .unwrap_or(serde_json::Value::Null);
                StepOutcome::Failed(
                    error["detail"]
                        .as_str()
                        .unwrap_or("the step failed without a detail")
                        .to_owned(),
                )
            }
        }
    }

    /// Creates one inner operation through the authorized use case.
    async fn spawn_inner(&self, kind: &str, payload_json: &str) -> Result<Operation, String> {
        self.operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &fleet_application::operation::NewOperation {
                    kind: kind.to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(payload_json.to_owned()),
                    review_token: None,
                },
            )
            .await
            .map_err(|error| error.to_string())
    }

    async fn resolve(
        &self,
        machine_id: &str,
        endpoint_id: &str,
        auth: &Auth,
    ) -> Result<fleet_provider_ssh::SshConnectionSpec, String> {
        let ssh_auth = match auth {
            Auth::Agent => fleet_provider_ssh::SshAuth::Agent,
            Auth::IdentityFile { path } => {
                fleet_provider_ssh::SshAuth::IdentityFile { path: path.clone() }
            }
        };
        let (spec, _verified, _host) =
            resolve_ssh_endpoint(self.machines.as_ref(), machine_id, endpoint_id, ssh_auth).await?;
        Ok(spec)
    }
}

/// Why the Frogenv status probe gave no configuration answer.
enum FrogenvProbe {
    /// The fixed status script reported no Frogenv CLI on the machine.
    NotInstalled,
    /// The probe did not answer; the machine's Frogenv state is unknown.
    Unavailable,
}

/// The URL the clone step hands to git, derived from the payload's remote
/// (normally the stored normalized identity; see
/// [`fleet_core::NormalizedRemote::clone_url`]).
fn clone_remote(remote: &str) -> Result<String, String> {
    let normalized = fleet_core::NormalizedRemote::parse(remote)
        .map_err(|detail| format!("invalid_project_remote: {detail}"))?;
    // A query or fragment is never part of a repository path; refuse it
    // rather than let a `?token=` ride into the clone URL.
    if normalized.as_str().contains(['?', '#']) {
        return Err(
            "invalid_project_remote: the remote path carries a query or fragment".to_owned(),
        );
    }
    Ok(normalized.clone_url())
}

/// The workflow's generic failure reason, for a step that ran and failed.
const STEP_FAILED: &str = "step_failed";

/// One checkout observation, mirroring the provider's shape.
struct DiscoveredCheckout {
    root: String,
    remote: Option<String>,
}

/// The outcome of one workflow step.
enum StepOutcome {
    /// The step completed.
    Done,
    /// The step reports that a human must act.
    Blocked(String),
    /// The step failed; a retry re-runs it.
    Failed(String),
}

/// Completes the workflow as `blocked_manual_approval` with the remaining
/// steps named.
async fn complete_blocked(
    operations: &Operations,
    operation_id: &str,
    step: &ReadyStep,
    reason: &str,
    completed: &[String],
    remaining: &[ReadyStep],
) -> Result<(), String> {
    let error_json = serde_json::json!({
        "reason": "blocked_manual_approval",
        "detail": reason,
        "blockedAt": step.name(),
        "completed": completed,
        "remaining": remaining.iter().map(ToString::to_string).collect::<Vec<_>>(),
    })
    .to_string();
    operations
        .complete(
            operation_id,
            "blocked_manual_approval",
            None,
            Some(&error_json),
        )
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Completes the workflow as a failure with the reason, the failing step,
/// the completed steps, and the remaining steps named.
async fn complete_failed(
    operations: &Operations,
    operation_id: &str,
    step: &ReadyStep,
    reason: &str,
    detail: &str,
    completed: &[String],
    remaining: &[ReadyStep],
) -> Result<(), String> {
    let error_json = serde_json::json!({
        "reason": reason,
        "detail": detail,
        "failedAt": step.name(),
        "completed": completed,
        "remaining": remaining.iter().map(ToString::to_string).collect::<Vec<_>>(),
    })
    .to_string();
    operations
        .complete(operation_id, "failed", None, Some(&error_json))
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Completes the workflow as cancelled with the completed steps named.
async fn complete_cancelled(
    operations: &Operations,
    operation_id: &str,
    completed: &[String],
    total: usize,
) -> Result<(), String> {
    let error_json = serde_json::json!({
        "reason": "cancelled",
        "completed": completed,
        "planned": total,
    })
    .to_string();
    operations
        .complete(operation_id, "cancelled", None, Some(&error_json))
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// The kind-dispatching wrapper the controller composes: the ready kinds
/// route to the [`ReadyExecutor`], everything else falls through to the
/// rest of the chain unchanged.
#[derive(Debug)]
pub struct ReadyDispatch {
    fallback: Arc<dyn OperationExecutor>,
    ready: Arc<dyn OperationExecutor>,
}

impl ReadyDispatch {
    /// Composes the dispatch from the fallback chain and the ready
    /// executor.
    #[must_use]
    pub fn new(fallback: Arc<dyn OperationExecutor>, ready: Arc<dyn OperationExecutor>) -> Self {
        Self { fallback, ready }
    }
}

#[async_trait::async_trait]
impl OperationExecutor for ReadyDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "ready.workflow" => self.ready.execute(operations, operation).await,
            _ => self.fallback.execute(operations, operation).await,
        }
    }
}

#[cfg(test)]
mod lab_discovery_tests {
    use super::*;

    #[derive(Debug)]
    struct Noop;
    #[async_trait::async_trait]
    impl OperationExecutor for Noop {
        async fn execute(&self, _: &Operations, _: &Operation) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn clone_step_remote_is_fetchable_and_malformed_is_refused() {
        assert_eq!(
            clone_remote("github.com/Frogbyte-io/fleet-manager").unwrap(),
            "https://github.com/Frogbyte-io/fleet-manager"
        );
        assert_eq!(
            clone_remote("git@github.com:Frogbyte-io/fleet-manager.git").unwrap(),
            "https://github.com/Frogbyte-io/fleet-manager"
        );
        assert!(
            clone_remote("")
                .unwrap_err()
                .starts_with("invalid_project_remote")
        );
    }

    #[tokio::test]
    async fn discovery_uses_remaining_budget_and_stops_for_either_cancellation() {
        let dir = tempfile::tempdir().unwrap();
        let store = fleet_storage_sqlite::Store::open(&dir.path().join("fleet.db"))
            .await
            .unwrap();
        let operations = Arc::new(Operations::new(
            Arc::new(fleet_storage_sqlite::OperationRepository::new(
                store.pool().clone(),
            )),
            Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
        ));
        for cancel_workflow in [false, true] {
            let mut ids = Vec::new();
            for _ in 0..2 {
                ids.push(
                    operations
                        .create(
                            &fleet_auth::LanAllowAllAuthorizer,
                            fleet_auth::LAN_PRINCIPAL_ID,
                            &fleet_application::operation::NewOperation {
                                kind: "noop".to_owned(),
                                idempotency_key: None,
                                deadline_at: None,
                                correlation_id: None,
                                payload_json: None,
                                review_token: None,
                            },
                        )
                        .await
                        .unwrap()
                        .id,
                );
            }
            let executor = ReadyExecutor::new(
                Arc::new(fleet_storage_sqlite::MachineRepository::new(
                    store.pool().clone(),
                )),
                operations.clone(),
                Arc::new(Noop),
                dir.path().join("ssh"),
                ExecutionLimiter::new(1),
            )
            .with_lab_readiness(
                fleet_core::SystemClock::now_unix_millis() + 2_000,
                ids[0].clone(),
                ids[1].clone(),
            );
            let budget = executor.check_lab_readiness().await.unwrap();
            assert!(budget <= Duration::from_secs(2));
            assert!(budget > Duration::ZERO);
            let release = Arc::new(tokio::sync::Notify::new());
            let worker_release = release.clone();
            let scan = tokio::spawn(async move { worker_release.notified().await });
            let cancel_id = ids[usize::from(cancel_workflow)].clone();
            let cancel_operations = operations.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                cancel_operations
                    .cancel(
                        &fleet_auth::LanAllowAllAuthorizer,
                        fleet_auth::LAN_PRINCIPAL_ID,
                        &cancel_id,
                    )
                    .await
                    .unwrap();
            });
            let result =
                tokio::time::timeout(Duration::from_secs(1), executor.wait_for_discovery(scan))
                    .await
                    .unwrap();
            assert!(result.unwrap_err().contains("stopped"));
            release.notify_one();
            assert!(executor.check_lab_readiness().await.is_err());
        }
        let expired = ReadyExecutor::new(
            Arc::new(fleet_storage_sqlite::MachineRepository::new(
                store.pool().clone(),
            )),
            operations,
            Arc::new(Noop),
            dir.path().join("ssh"),
            ExecutionLimiter::new(1),
        )
        .with_lab_readiness(0, "absent".to_owned(), "absent".to_owned());
        assert!(
            expired
                .check_lab_readiness()
                .await
                .unwrap_err()
                .contains("expired")
        );
    }
}
