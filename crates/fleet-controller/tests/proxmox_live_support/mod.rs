//! The real-cluster acceptance harness (FM-611): the env contract, the
//! cleanup guard, the harness's own PVE access, a real controller per
//! scenario, and the result lines `cargo xtask pve-acceptance` collects.
#![allow(dead_code)]

pub mod config;
pub mod controller;
pub mod guard;
pub mod pve;
pub mod redact;

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use config::{Gate, Target, Token};
use controller::Controller;
use guard::{NAME_PREFIX, ScratchGuard, TAG};
use pve::PveAdmin;
use redact::Redactor;

/// The marker that starts every result line.
pub const RESULT_MARKER: &str = "FLEET_PVE_ACCEPTANCE_RESULT";

/// The scenario identifiers, in the order the runner reports them.
pub const SCENARIOS: [&str; 6] = [
    "trust",
    "privilege-failure",
    "task-polling",
    "destructive-gate",
    "association",
    "partial-node-failure",
];

/// Returns early from a scenario with a failure reason when the condition
/// does not hold.
macro_rules! check {
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            return Err(format!($($arg)+));
        }
    };
}

/// A scenario's verdict on one target, short of failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every assertion held.
    Pass,
    /// Not applicable to this target, with the reason.
    Skipped(String),
}

/// One result line: `RESULT_MARKER key=value ... reason=<rest of line>`.
/// The reason is last so it may hold spaces; it is single-line and
/// redacted by the caller.
#[must_use]
pub fn result_line(
    scenario: &str,
    target: Option<&str>,
    result: &Result<Outcome, String>,
    duration: Duration,
) -> String {
    let (status, reason) = match result {
        Ok(Outcome::Pass) => ("pass", String::new()),
        Ok(Outcome::Skipped(reason)) => ("skipped", reason.clone()),
        Err(reason) => ("fail", reason.clone()),
    };
    let reason: String = reason
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    format!(
        "{RESULT_MARKER} scenario={scenario} target={} status={status} duration_ms={} reason={}",
        target.unwrap_or("-"),
        duration.as_millis(),
        reason.trim()
    )
}

/// The redactor for one target's configured values.
#[must_use]
pub fn redactor_for(target: &Target) -> Redactor {
    let mut redactor = Redactor::default();
    let name = &target.name;
    redactor.mask(target.token.secret.expose(), "<secret>");
    redactor.mask(&target.token.id, &format!("<{name}-token-id>"));
    if let Some(ro) = &target.ro_token {
        redactor.mask(ro.secret.expose(), "<secret>");
        redactor.mask(&ro.id, &format!("<{name}-ro-token-id>"));
    }
    redactor.mask(&target.host, &format!("<{name}-host>"));
    redactor.mask(&target.fingerprint, &format!("<{name}-fingerprint>"));
    redactor.mask_word(&target.node, &format!("<{name}-node>"));
    if let Some(down) = &target.down {
        redactor.mask_word(&down.node, &format!("<{name}-down-node>"));
    }
    redactor
}

/// One scenario test across the selected targets.
pub struct Suite {
    scenario: &'static str,
    targets: Vec<Arc<Target>>,
    failures: Vec<String>,
    _lock: std::fs::File,
}

impl Suite {
    /// Loads the gate. Off: prints the skipped line and answers `None`. On
    /// with a broken configuration: panics loudly. On: takes the
    /// cross-process suite lock, so scenarios never overlap on a target.
    ///
    /// # Panics
    ///
    /// When the gate is on and the configuration is incomplete.
    #[must_use]
    pub fn begin(scenario: &'static str) -> Option<Self> {
        let targets = match config::load_process() {
            Ok(Gate::Off(reason)) => {
                println!(
                    "{}",
                    result_line(
                        scenario,
                        None,
                        &Ok(Outcome::Skipped(reason)),
                        Duration::ZERO
                    )
                );
                return None;
            }
            Ok(Gate::On(targets)) => targets,
            Err(problems) => panic!("{problems}"),
        };
        if let Err(detail) = controller::locate_fleetctl() {
            panic!("{}=1 but {detail}", config::LIVE_GATE);
        }
        Some(Self {
            scenario,
            targets: targets.into_iter().map(Arc::new).collect(),
            failures: Vec::new(),
            _lock: suite_lock(),
        })
    }

    /// The selected targets.
    #[must_use]
    pub fn targets(&self) -> Vec<Arc<Target>> {
        self.targets.clone()
    }

    /// Prints one target's result line.
    pub fn record(&mut self, target: &Target, result: &Result<Outcome, String>, started: Instant) {
        let redactor = redactor_for(target);
        let line = result_line(self.scenario, Some(&target.name), result, started.elapsed());
        println!("{}", redactor.line(&line));
        if let Err(reason) = result {
            self.failures
                .push(redactor.line(&format!("{}: {reason}", target.name)));
        }
    }

    /// Fails the test when any target failed.
    ///
    /// # Panics
    ///
    /// When any target failed.
    pub fn conclude(self) {
        assert!(
            self.failures.is_empty(),
            "scenario {} failed:\n  {}",
            self.scenario,
            self.failures.join("\n  ")
        );
    }
}

/// The cross-process lock: one scenario at a time, across test threads
/// and concurrent runs. Released when the file drops, including on panic.
fn suite_lock() -> std::fs::File {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_owned());
    let path = std::env::temp_dir().join(format!("fleet-pve-acceptance-{user}.lock"));
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .unwrap_or_else(|error| panic!("the suite lock {} must open: {error}", path.display()));
    file.lock().expect("the suite lock must acquire");
    file
}

/// One scenario on one target: a swept range, a fresh controller, and the
/// guard that sweeps again at the end (or from `Drop` on a panic).
pub struct TargetRun {
    /// The target.
    pub target: Arc<Target>,
    /// The harness's own PVE access.
    pub pve: Arc<PveAdmin>,
    /// The cleanup guard.
    pub guard: ScratchGuard,
    /// The controller under test.
    pub controller: Controller,
    /// The target's redactor.
    pub redactor: Redactor,
}

impl TargetRun {
    /// Sweeps the range, then starts a controller.
    ///
    /// # Errors
    ///
    /// When the start sweep or the controller fails.
    pub async fn start(target: Arc<Target>, scenario: &str) -> Result<Self, String> {
        let redactor = redactor_for(&target);
        let pve = Arc::new(PveAdmin::new(&target));
        let guard = ScratchGuard::new(
            pve.clone(),
            redactor.clone(),
            format!("{scenario} on {}", target.name),
        );
        let report = guard
            .sweep()
            .await
            .map_err(|detail| format!("the start-of-scenario sweep failed: {detail}"))?;
        log(
            &redactor,
            &format!(
                "{scenario}/{}: start sweep destroyed {:?}",
                target.name, report.destroyed
            ),
        );
        for foreign in &report.foreign {
            log(
                &redactor,
                &format!("{scenario}/{}: warning: {foreign}", target.name),
            );
        }
        let controller = Controller::start(redactor.clone()).await?;
        Ok(Self {
            target,
            pve,
            guard,
            controller,
            redactor,
        })
    }

    /// Runs the end sweep and folds its outcome into the scenario's.
    pub async fn finish(self, result: Result<Outcome, String>) -> Result<Outcome, String> {
        let swept = self.guard.finish().await;
        let result = match (result, swept) {
            (Ok(outcome), Ok(_)) => Ok(outcome),
            (Ok(_), Err(cleanup)) => {
                Err(format!("the scenario passed but cleanup failed: {cleanup}"))
            }
            (Err(reason), Ok(_)) => Err(reason),
            (Err(reason), Err(cleanup)) => Err(format!("{reason}; cleanup also failed: {cleanup}")),
        };
        result
            .map_err(|reason| format!("{reason} [controller log: {}]", self.controller.log_tail()))
    }

    /// Prints one progress line, redacted.
    pub fn log(&self, text: &str) {
        log(&self.redactor, &format!("{}: {text}", self.target.name));
    }

    /// Creates an account through `fleetctl proxmox create`, the secret on
    /// stdin, and checks the answer never echoes it.
    ///
    /// # Errors
    ///
    /// When the create fails or echoes the secret.
    pub async fn create_account(&self, name: &str, token: &Token) -> Result<String, String> {
        let answer = self
            .controller
            .fleetctl(
                &args(&[
                    "proxmox",
                    "create",
                    "--name",
                    name,
                    "--host",
                    &self.target.host,
                    "--port",
                    &self.target.port.to_string(),
                    "--token-id",
                    &token.id,
                ]),
                Some(format!("{}\n", token.secret.expose())),
            )
            .await?;
        check!(
            answer.success,
            "fleetctl proxmox create failed: {}",
            answer.stderr
        );
        check!(
            !answer.json.to_string().contains(token.secret.expose()),
            "the create answer echoed the token secret"
        );
        answer.json["id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| "the create answer carries no account id".to_owned())
    }

    /// Observes the host and confirms exactly what the probe saw, after
    /// checking it is the configured fingerprint.
    ///
    /// # Errors
    ///
    /// When observe or confirm fails or the fingerprint differs.
    pub async fn trust(&self, account: &str) -> Result<(), String> {
        let (status, body) = self
            .controller
            .post(
                &format!("/api/v1/proxmox/accounts/{account}/observe"),
                &json!({}),
            )
            .await?;
        check!(status == 200, "observe answered {status}: {body}");
        let observed = body["data"]["fingerprint"].as_str().unwrap_or_default();
        check!(
            fleet_provider_proxmox::normalize_fingerprint(observed) == self.target.fingerprint,
            "the observed fingerprint is not the configured {}",
            self.target.var("FINGERPRINT")
        );
        let (status, body) = self
            .controller
            .post(
                &format!("/api/v1/proxmox/accounts/{account}/confirm"),
                &json!({ "fingerprint": observed }),
            )
            .await?;
        check!(status == 200, "confirm answered {status}: {body}");
        check!(
            body["data"]["fingerprintState"] == "confirmed",
            "the account is not confirmed: {body}"
        );
        Ok(())
    }

    /// Create + observe + confirm.
    ///
    /// # Errors
    ///
    /// When any step fails.
    pub async fn trusted_account(&self, name: &str, token: &Token) -> Result<String, String> {
        let account = self.create_account(name, token).await?;
        self.trust(&account).await?;
        Ok(account)
    }

    /// Runs one `fleetctl` command that answers an operation (with
    /// `--wait`, a terminal one) and returns its `data`.
    ///
    /// # Errors
    ///
    /// When fleetctl fails or answers no operation.
    pub async fn fleetctl_operation(
        &self,
        words: &[&str],
        stdin: Option<Value>,
    ) -> Result<Value, String> {
        let answer = self
            .controller
            .fleetctl(&args(words), stdin.map(|value| value.to_string()))
            .await?;
        check!(
            answer.success,
            "fleetctl {} failed: {}",
            words.first().copied().unwrap_or_default(),
            answer.stderr
        );
        let data = answer.json.clone();
        check!(
            data["state"].is_string(),
            "fleetctl answered no operation: {}",
            answer.json
        );
        Ok(data)
    }

    /// A lifecycle action through `fleetctl proxmox <action> --wait`.
    ///
    /// # Errors
    ///
    /// When fleetctl fails.
    pub async fn lifecycle(
        &self,
        account: &str,
        action: &str,
        node: &str,
        vmid: u32,
        timeout: u64,
    ) -> Result<Value, String> {
        self.fleetctl_operation(
            &[
                "proxmox",
                action,
                "--account",
                account,
                "--node",
                node,
                "--vmid",
                &vmid.to_string(),
                "--wait",
                "--timeout",
                &timeout.to_string(),
            ],
            None,
        )
        .await
    }

    /// A review-gated action through `fleetctl proxmox <action> --wait`
    /// (fleetctl reviews, then runs with the returned token).
    ///
    /// fleetctl's wait stage runs before its review-run stage, so for these
    /// commands `--wait` currently answers the pending operation (a gap
    /// reported on the PR); the suite then waits through the API.
    ///
    /// # Errors
    ///
    /// When fleetctl fails or the operation never ends.
    pub async fn reviewed(
        &self,
        account: &str,
        action: &str,
        vmid: u32,
        params: Value,
    ) -> Result<Value, String> {
        let data = self.reviewed_once(account, action, vmid, params).await?;
        if matches!(
            data["state"].as_str(),
            Some("pending" | "running" | "cancelling")
        ) {
            let id = data["id"]
                .as_str()
                .filter(|id| !id.is_empty())
                .ok_or_else(|| format!("the pending {action} operation carries no id: {data}"))?
                .to_owned();
            return self.wait_operation(&id, Duration::from_secs(900)).await;
        }
        Ok(data)
    }

    async fn reviewed_once(
        &self,
        account: &str,
        action: &str,
        vmid: u32,
        params: Value,
    ) -> Result<Value, String> {
        self.fleetctl_operation(
            &[
                "proxmox",
                action,
                "--account",
                account,
                "--node",
                &self.target.node,
                "--vmid",
                &vmid.to_string(),
                "--wait",
                "--timeout",
                "900",
            ],
            Some(params),
        )
        .await
    }

    /// Clones a scratch guest from the test template through the review
    /// gate and tags it. The VMID comes from the guard, inside the range.
    ///
    /// # Errors
    ///
    /// When the clone or the tag fails.
    pub async fn clone_scratch(&self, account: &str, label: &str) -> Result<u32, String> {
        let vmid = self.guard.allocate().await?;
        let vmid = self.target.range.check(vmid)?;
        let data = self
            .reviewed(
                account,
                "clone",
                self.target.template_vmid,
                json!({ "newId": vmid, "name": format!("{NAME_PREFIX}{label}-{vmid}") }),
            )
            .await?;
        check!(
            data["state"] == "succeeded",
            "cloning the template into VMID {vmid} ended {}: {}",
            data["state"],
            data["errorJson"]
        );
        self.pve.tag(&self.target.node, vmid, TAG).await?;
        self.log(&format!("cloned scratch guest {vmid} ({label})"));
        Ok(vmid)
    }

    /// Polls one operation until it is terminal.
    ///
    /// # Errors
    ///
    /// When the bound passes or the read fails.
    pub async fn wait_operation(&self, id: &str, bound: Duration) -> Result<Value, String> {
        let started = Instant::now();
        loop {
            let (status, body) = self
                .controller
                .get(&format!("/api/v1/operations/{id}"))
                .await?;
            check!(status == 200, "reading operation {id} answered {status}");
            let state = body["data"]["state"].as_str().unwrap_or_default();
            if !matches!(state, "pending" | "running" | "cancelling") {
                return Ok(body["data"].clone());
            }
            check!(
                started.elapsed() < bound,
                "operation {id} stayed {state} for {}s",
                bound.as_secs()
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

/// The operation's error payload: `(reason, detail)`; the whole payload is
/// the detail when it is not the structured shape.
#[must_use]
pub fn operation_error(data: &Value) -> (String, String) {
    let raw = data["errorJson"].as_str().unwrap_or_default();
    match serde_json::from_str::<Value>(raw) {
        Ok(parsed) => (
            parsed["reason"].as_str().unwrap_or_default().to_owned(),
            parsed["detail"]
                .as_str()
                .map_or_else(|| raw.to_owned(), str::to_owned),
        ),
        Err(_) => (String::new(), raw.to_owned()),
    }
}

/// The operation's result payload.
#[must_use]
pub fn operation_result(data: &Value) -> Value {
    data["resultJson"]
        .as_str()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or(Value::Null)
}

/// Prints one progress line, redacted.
pub fn log(redactor: &Redactor, text: &str) {
    println!("fleet-acceptance: {}", redactor.line(text));
}

/// Owned argument vector.
#[must_use]
pub fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}
