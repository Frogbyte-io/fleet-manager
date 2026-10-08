//! `cargo xtask lab-acceptance [--target NAME]`: runs the live Lab
//! acceptance scenarios (`live_*` in
//! `crates/fleet-controller/tests/lab_failure_injection.rs`, FM-741) and
//! prints a machine-readable JSON summary on stdout: one row per scenario
//! and target, each `pass`, `fail`, or `skipped` with its reason.
//!
//! The scenarios read the FM-611 target contract (`FLEET_PVE_TARGET_<NAME>_*`)
//! behind their own gate, `FLEET_LAB_LIVE=1`. Without it every scenario
//! reports skipped and no PVE is needed. A target whose cluster `next-id`
//! range lies outside its `VMID_RANGE` is not a Lab fixture and is reported
//! skipped with that reason. Every line is redacted by the suite.
//! `cargo xtask verify` never runs the live scenarios.
//!
//! The row format, JSON encoding, and process-tree handling are
//! `pve-acceptance`'s; only the gate, marker, scenarios, and test target
//! differ.

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};

use crate::pve_acceptance::{
    ResultRow, Status, configured_targets, descendants_in, effective_filter, json_string,
    parent_of_stat, resolve_target_dir, valid_target_name,
};

/// The marker the suite prints before every result.
pub const RESULT_MARKER: &str = "FLEET_LAB_ACCEPTANCE_RESULT";

/// The scenarios, in report order. Kept in step with the suite's
/// `live::SCENARIOS`.
pub const SCENARIOS: [&str; 2] = ["lease-exec-destroy", "ttl-expiry-restart"];

/// The Lab live gate.
const LIVE_GATE: &str = "FLEET_LAB_LIVE";
const TARGET_FILTER: &str = "FLEET_PVE_ACCEPTANCE_TARGET";
const FLEETCTL_VAR: &str = "FLEET_PVE_ACCEPTANCE_FLEETCTL";

/// Parses one result line, wherever the marker sits in the line.
#[must_use]
pub fn parse_result_line(line: &str) -> Option<ResultRow> {
    let start = line.find(RESULT_MARKER)?;
    let rest = &line[start + RESULT_MARKER.len()..];
    crate::pve_acceptance::parse_result_line(&format!(
        "{}{rest}",
        crate::pve_acceptance::RESULT_MARKER
    ))
}

/// Parses the subcommand's arguments: `[--target NAME]`.
///
/// # Errors
///
/// On an unknown argument or a missing/invalid target name.
pub fn parse_args(args: &[String]) -> Result<Option<String>, String> {
    let mut target = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--target" => {
                let name = rest
                    .next()
                    .ok_or_else(|| "--target requires a name".to_owned())?;
                if !valid_target_name(name) {
                    return Err(format!(
                        "--target takes the <NAME> of FLEET_PVE_TARGET_<NAME>_* ([A-Za-z0-9_]), not {name:?}"
                    ));
                }
                target = Some(name.clone());
            }
            other => return Err(format!("unknown lab-acceptance argument {other:?}")),
        }
    }
    Ok(target)
}

/// The summary FM-742 records.
#[derive(Clone, Debug)]
pub struct Summary {
    /// Whether the live gate was on.
    pub live: bool,
    /// The `--target` filter, when given.
    pub target_filter: Option<String>,
    /// The targets the matrix covers.
    pub targets: Vec<String>,
    /// One row per scenario and target.
    pub results: Vec<ResultRow>,
    /// Whether the test process itself exited zero.
    pub test_exit_success: bool,
}

impl Summary {
    /// Builds the matrix from the reported rows: every expected
    /// scenario/target pair appears exactly once, and a pair that never
    /// reported is a failure, never a silent pass.
    #[must_use]
    pub fn build(
        live: bool,
        target_filter: Option<String>,
        expected_targets: &[String],
        reported: &[ResultRow],
        test_exit_success: bool,
    ) -> Self {
        let mut targets: Vec<String> = expected_targets.to_vec();
        for row in reported {
            if let Some(target) = &row.target
                && !targets.contains(target)
            {
                targets.push(target.clone());
            }
        }
        let columns: Vec<Option<String>> = if targets.is_empty() {
            vec![None]
        } else {
            targets.iter().cloned().map(Some).collect()
        };
        let mut results = Vec::new();
        for scenario in SCENARIOS {
            for target in &columns {
                let found = reported
                    .iter()
                    .rev()
                    .find(|row| row.scenario == scenario && &row.target == target)
                    .cloned();
                results.push(found.unwrap_or_else(|| {
                    ResultRow {
                        scenario: scenario.to_owned(),
                        target: target.clone(),
                        status: Status::Fail,
                        reason: "no result reported: the scenario failed before reporting this \
                             target (configuration error or panic; see the log)"
                            .to_owned(),
                        duration_ms: 0,
                    }
                }));
            }
        }
        // A scenario the suite reports but this runner does not list is
        // drift, never a silent pass.
        for row in reported {
            if !SCENARIOS.contains(&row.scenario.as_str())
                && !results.iter().any(|seen: &ResultRow| {
                    seen.scenario == row.scenario && seen.target == row.target
                })
            {
                results.push(ResultRow {
                    status: Status::Fail,
                    reason: format!(
                        "the suite reported scenario {:?}, which lab_acceptance::SCENARIOS does not \
                         list; add it there (status reported: {})",
                        row.scenario,
                        status_id(row.status)
                    ),
                    ..row.clone()
                });
            }
        }
        Self {
            live,
            target_filter,
            targets,
            results,
            test_exit_success,
        }
    }

    /// How many rows have this status.
    #[must_use]
    pub fn count(&self, status: Status) -> usize {
        self.results
            .iter()
            .filter(|row| row.status == status)
            .count()
    }

    /// Whether the run passed: no failed row and a clean test exit.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.count(Status::Fail) == 0 && self.test_exit_success
    }

    /// The JSON document, pretty-printed with stable key order.
    #[must_use]
    pub fn to_json(&self) -> String {
        use std::fmt::Write as _;
        let optional = |value: Option<&str>| value.map_or_else(|| "null".to_owned(), json_string);
        let list = |items: &mut dyn Iterator<Item = &str>| {
            items.map(json_string).collect::<Vec<_>>().join(", ")
        };
        let rows: Vec<String> = self
            .results
            .iter()
            .map(|row| {
                format!(
                    "    {{\"scenario\": {}, \"target\": {}, \"status\": {}, \"reason\": {}, \"durationMs\": {}}}",
                    json_string(&row.scenario),
                    optional(row.target.as_deref()),
                    json_string(status_id(row.status)),
                    optional(Some(row.reason.as_str()).filter(|reason| !reason.is_empty())),
                    row.duration_ms
                )
            })
            .collect();
        let mut out = String::from("{\n");
        // Writing to a String cannot fail.
        let _ = writeln!(out, "  \"suite\": \"lab-acceptance\",");
        let _ = writeln!(out, "  \"schemaVersion\": 1,");
        let _ = writeln!(out, "  \"live\": {},", self.live);
        let _ = writeln!(
            out,
            "  \"targetFilter\": {},",
            optional(self.target_filter.as_deref())
        );
        let _ = writeln!(
            out,
            "  \"targets\": [{}],",
            list(&mut self.targets.iter().map(String::as_str))
        );
        let _ = writeln!(
            out,
            "  \"scenarios\": [{}],",
            list(&mut SCENARIOS.iter().copied())
        );
        let _ = writeln!(out, "  \"results\": [\n{}\n  ],", rows.join(",\n"));
        let _ = writeln!(
            out,
            "  \"totals\": {{\"pass\": {}, \"fail\": {}, \"skipped\": {}}},",
            self.count(Status::Pass),
            self.count(Status::Fail),
            self.count(Status::Skipped)
        );
        let _ = writeln!(
            out,
            "  \"testExit\": {},",
            json_string(if self.test_exit_success {
                "success"
            } else {
                "failure"
            })
        );
        let _ = writeln!(out, "  \"ok\": {}", self.ok());
        out.push('}');
        out
    }
}

const fn status_id(status: Status) -> &'static str {
    match status {
        Status::Pass => "pass",
        Status::Fail => "fail",
        Status::Skipped => "skipped",
    }
}

/// The running suite. Unless it is reaped through [`SuiteProcess::wait`],
/// dropping it kills the whole process tree (cargo, the test binary, and
/// the controller it starts), so a live run never keeps creating guests
/// unattended.
struct SuiteProcess {
    child: Option<Child>,
}

impl SuiteProcess {
    fn wait(mut self) -> std::io::Result<ExitStatus> {
        match self.child.take() {
            Some(mut child) => child.wait(),
            None => Err(std::io::Error::other("the suite was already reaped")),
        }
    }
}

impl Drop for SuiteProcess {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let table: Vec<(u32, u32)> = std::fs::read_dir("/proc")
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
                let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
                Some((pid, parent_of_stat(&stat)?))
            })
            .collect();
        let tree = descendants_in(child.id(), &table);
        if !tree.is_empty() {
            let _ = Command::new("kill")
                .arg("-KILL")
                .args(tree.iter().map(u32::to_string))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = child.kill();
        let _ = child.wait();
        eprintln!(
            "==> the runner stopped early: killed the suite and its {} descendant process(es)",
            tree.len()
        );
    }
}

/// Runs the live scenarios and answers their summary. Progress and the
/// suite's own output go to stderr; the caller prints the JSON on stdout.
///
/// # Errors
///
/// When cargo cannot run or the target filter names no configured target.
pub fn run(repo_root: &Path, target: Option<&str>) -> Result<Summary, String> {
    let env: BTreeMap<String, String> = std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect();
    let live = env.get(LIVE_GATE).map(|value| value.trim()) == Some("1");
    let filter = effective_filter(target, &env);
    let expected = if live {
        let names = configured_targets(&env, filter.as_deref());
        if let Some(name) = &filter
            && names.is_empty()
        {
            return Err(format!(
                "target {name}: no FLEET_PVE_TARGET_{name}_HOST is set"
            ));
        }
        names
    } else {
        Vec::new()
    };

    // The runner stops a live suite by killing its process tree, which it
    // finds through /proc. Without /proc it could only kill cargo and leave
    // the test binary and its controller changing guests.
    if live && !Path::new("/proc").is_dir() {
        return Err(
            "a live run needs /proc to stop the suite's whole process tree; run it on Linux"
                .to_owned(),
        );
    }
    // Both cargo commands build into this one directory, set explicitly
    // (CARGO_TARGET_DIR overrides a configured `build.target-dir`), so the
    // fleetctl the suite drives is the one just built.
    let target_dir = resolve_target_dir(repo_root, std::env::var_os("CARGO_TARGET_DIR"));
    let mut command = Command::new("cargo");
    command
        .current_dir(repo_root)
        .env("CARGO_TARGET_DIR", &target_dir);
    if live {
        eprintln!("==> building fleetctl for the live suite");
        let status = Command::new("cargo")
            .current_dir(repo_root)
            .env("CARGO_TARGET_DIR", &target_dir)
            .args(["build", "--locked", "-p", "fleetctl"])
            .status()
            .map_err(|error| format!("cargo build could not run: {error}"))?;
        if !status.success() {
            return Err("building fleetctl failed".to_owned());
        }
        let fleetctl = target_dir
            .join("debug")
            .join(format!("fleetctl{}", std::env::consts::EXE_SUFFIX));
        command.env(FLEETCTL_VAR, fleetctl);
    }
    if let Some(name) = target {
        command.env(TARGET_FILTER, name);
    }
    command
        .args([
            "test",
            "--locked",
            "-p",
            "fleet-controller",
            "--test",
            "lab_failure_injection",
            "--",
            "--test-threads=1",
            "--nocapture",
            "live_",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    eprintln!(
        "==> cargo test -p fleet-controller --test lab_failure_injection -- --test-threads=1 --nocapture live_"
    );
    let mut child = command
        .spawn()
        .map_err(|error| format!("cargo test could not run: {error}"))?;
    let stdout = child.stdout.take();
    // From here every early return drops `suite`, which kills and reaps it.
    let suite = SuiteProcess { child: Some(child) };
    let mut reported = Vec::new();
    if let Some(stdout) = stdout {
        let mut stderr = std::io::stderr();
        let mut reader = BufReader::new(stdout);
        let mut buffer = Vec::new();
        loop {
            buffer.clear();
            match reader.read_until(b'\n', &mut buffer) {
                Ok(0) => break,
                Ok(_) => {
                    let text = String::from_utf8_lossy(&buffer);
                    let text = text.trim_end_matches(['\n', '\r']);
                    let _ = writeln!(stderr, "{text}");
                    if let Some(row) = parse_result_line(text) {
                        reported.push(row);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(format!("reading the suite's output: {error}")),
            }
        }
    }
    let status = suite
        .wait()
        .map_err(|error| format!("cargo test did not finish: {error}"))?;
    Ok(Summary::build(
        live,
        filter,
        &expected,
        &reported,
        status.success(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(scenario: &str, target: Option<&str>, status: Status) -> ResultRow {
        ResultRow {
            scenario: scenario.to_owned(),
            target: target.map(str::to_owned),
            status,
            reason: String::new(),
            duration_ms: 1,
        }
    }

    #[test]
    fn result_lines_parse_under_the_lab_marker_only() {
        let parsed = parse_result_line(
            "test live_x ... FLEET_LAB_ACCEPTANCE_RESULT scenario=lease-exec-destroy target=PVE9 \
             status=skipped duration_ms=12 reason=skipped: not a Lab fixture",
        )
        .unwrap();
        assert_eq!(parsed.scenario, "lease-exec-destroy");
        assert_eq!(parsed.target.as_deref(), Some("PVE9"));
        assert_eq!(parsed.status, Status::Skipped);
        assert_eq!(parsed.reason, "skipped: not a Lab fixture");
        // Another suite's line is not this suite's result.
        assert!(
            parse_result_line(
                "FLEET_PVE_ACCEPTANCE_RESULT scenario=trust target=- status=pass duration_ms=0 reason="
            )
            .is_none()
        );
    }

    #[test]
    fn a_gate_off_run_reports_every_scenario_skipped_once() {
        let reported = [
            row("lease-exec-destroy", None, Status::Skipped),
            row("ttl-expiry-restart", None, Status::Skipped),
        ];
        let summary = Summary::build(false, None, &[], &reported, true);
        assert_eq!(summary.results.len(), SCENARIOS.len());
        assert!(summary.ok());
        let json = summary.to_json();
        assert!(json.contains("\"suite\": \"lab-acceptance\""), "{json}");
        assert!(json.contains("\"skipped\": 2"), "{json}");
    }

    #[test]
    fn a_pair_that_never_reported_fails_the_run() {
        let reported = [row("lease-exec-destroy", Some("PVE9"), Status::Pass)];
        let summary = Summary::build(true, None, &["PVE9".to_owned()], &reported, true);
        assert_eq!(summary.results.len(), 2);
        assert_eq!(summary.count(Status::Fail), 1);
        assert!(!summary.ok());
    }

    #[test]
    fn an_unlisted_scenario_fails_the_run() {
        let reported = [
            row("lease-exec-destroy", None, Status::Pass),
            row("ttl-expiry-restart", None, Status::Pass),
            row("new-scenario", None, Status::Pass),
        ];
        let summary = Summary::build(false, None, &[], &reported, true);
        assert_eq!(summary.results.len(), 3);
        assert_eq!(summary.count(Status::Fail), 1);
        assert!(summary.results[2].reason.contains("SCENARIOS"));
        assert!(!summary.ok());
    }

    #[test]
    fn arguments_take_only_a_valid_target() {
        assert_eq!(parse_args(&[]).unwrap(), None);
        assert_eq!(
            parse_args(&["--target".to_owned(), "PVE9".to_owned()]).unwrap(),
            Some("PVE9".to_owned())
        );
        assert!(parse_args(&["--target".to_owned(), "a b".to_owned()]).is_err());
        assert!(parse_args(&["--live".to_owned()]).is_err());
    }
}
