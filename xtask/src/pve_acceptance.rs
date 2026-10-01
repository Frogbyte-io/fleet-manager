//! `cargo xtask pve-acceptance [--target NAME]`: runs the real-cluster
//! acceptance suite (`crates/fleet-controller/tests/proxmox_live.rs`,
//! FM-611) and prints a machine-readable JSON summary on stdout: one row per
//! scenario and target, each `pass`, `fail`, or `skipped` with its reason.
//!
//! The suite reports through result lines on its stdout (see
//! [`RESULT_MARKER`]); this runner collects them, fills every expected
//! scenario/target pair that never reported as a failure, and exits non-zero
//! when anything failed. Without `FLEET_PVE_LIVE=1` every scenario reports
//! skipped and no PVE is needed. `cargo xtask verify` never runs this.

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The marker the suite prints before every result.
pub const RESULT_MARKER: &str = "FLEET_PVE_ACCEPTANCE_RESULT";

/// The scenarios, in report order. Kept in step with the suite's
/// `SCENARIOS`.
pub const SCENARIOS: [&str; 6] = [
    "trust",
    "privilege-failure",
    "task-polling",
    "destructive-gate",
    "association",
    "partial-node-failure",
];

/// The live gate and the variables the runner reads or sets.
const LIVE_GATE: &str = "FLEET_PVE_LIVE";
const TARGET_PREFIX: &str = "FLEET_PVE_TARGET_";
const TARGET_FILTER: &str = "FLEET_PVE_ACCEPTANCE_TARGET";
const FLEETCTL_VAR: &str = "FLEET_PVE_ACCEPTANCE_FLEETCTL";

/// One scenario/target verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// Every assertion held.
    Pass,
    /// An assertion failed, or the scenario never reported.
    Fail,
    /// Not applicable (gate off, no read-only token, not a cluster).
    Skipped,
}

impl Status {
    fn id(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skipped => "skipped",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "pass" => Some(Self::Pass),
            "fail" => Some(Self::Fail),
            "skipped" => Some(Self::Skipped),
            _ => None,
        }
    }
}

/// One row of the summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultRow {
    /// The scenario id.
    pub scenario: String,
    /// The target name; `None` when the gate is off.
    pub target: Option<String>,
    /// The verdict.
    pub status: Status,
    /// Why it failed or skipped; empty on a pass.
    pub reason: String,
    /// How long it ran.
    pub duration_ms: u64,
}

/// Parses one result line, wherever the marker sits in the line (libtest
/// may prefix it with `test name ... `).
#[must_use]
pub fn parse_result_line(line: &str) -> Option<ResultRow> {
    let start = line.find(RESULT_MARKER)?;
    let rest = line[start + RESULT_MARKER.len()..].trim_start();
    let (fields, reason) = match rest.find("reason=") {
        Some(at) => (&rest[..at], rest[at + "reason=".len()..].trim()),
        None => (rest, ""),
    };
    let mut values = BTreeMap::new();
    for field in fields.split_whitespace() {
        let (key, value) = field.split_once('=')?;
        values.insert(key, value);
    }
    let scenario = (*values.get("scenario")?).to_owned();
    let target = match *values.get("target")? {
        "-" => None,
        name => Some(name.to_owned()),
    };
    Some(ResultRow {
        scenario,
        target,
        status: Status::parse(values.get("status")?)?,
        reason: reason.to_owned(),
        duration_ms: values
            .get("duration_ms")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
    })
}

/// The target names configured in an environment (from
/// `FLEET_PVE_TARGET_<NAME>_HOST`), narrowed by the filter.
#[must_use]
pub fn configured_targets(env: &BTreeMap<String, String>, filter: Option<&str>) -> Vec<String> {
    let mut names: Vec<String> = env
        .keys()
        .filter_map(|key| key.strip_prefix(TARGET_PREFIX)?.strip_suffix("_HOST"))
        .filter(|name| !name.is_empty())
        .filter(|name| filter.is_none_or(|filter| filter == *name))
        .map(str::to_owned)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// The summary FM-613 records.
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
                results.push(found.unwrap_or_else(|| ResultRow {
                    scenario: scenario.to_owned(),
                    target: target.clone(),
                    status: Status::Fail,
                    reason: if live {
                        "no result reported: the scenario failed before reporting this target \
                         (configuration error or panic; see the log)"
                            .to_owned()
                    } else {
                        "no result reported".to_owned()
                    },
                    duration_ms: 0,
                }));
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
                    optional_string(row.target.as_deref()),
                    json_string(row.status.id()),
                    optional_string(Some(row.reason.as_str()).filter(|reason| !reason.is_empty())),
                    row.duration_ms
                )
            })
            .collect();
        let mut out = String::from("{\n");
        // Writing to a String cannot fail.
        let _ = writeln!(out, "  \"suite\": \"pve-acceptance\",");
        let _ = writeln!(out, "  \"schemaVersion\": 1,");
        let _ = writeln!(out, "  \"live\": {},", self.live);
        let _ = writeln!(
            out,
            "  \"targetFilter\": {},",
            optional_string(self.target_filter.as_deref())
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

fn optional_string(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), json_string)
}

/// A JSON string literal.
#[must_use]
pub fn json_string(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
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
                if name.is_empty()
                    || !name
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                {
                    return Err(format!(
                        "--target takes the <NAME> of FLEET_PVE_TARGET_<NAME>_* (upper case), not {name:?}"
                    ));
                }
                target = Some(name.clone());
            }
            other => return Err(format!("unknown pve-acceptance argument {other:?}")),
        }
    }
    Ok(target)
}

/// The cargo target directory.
fn target_dir(repo_root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| repo_root.join("target"), PathBuf::from)
}

/// Runs the suite and answers its summary. Progress and the suite's own
/// output go to stderr; the caller prints the JSON on stdout.
///
/// # Errors
///
/// When cargo cannot run or the target filter names no configured target.
pub fn run(repo_root: &Path, target: Option<String>) -> Result<Summary, String> {
    let env: BTreeMap<String, String> = std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect();
    let live = env.get(LIVE_GATE).map(|value| value.trim()) == Some("1");
    let expected = if live {
        let names = configured_targets(&env, target.as_deref());
        if let Some(name) = &target
            && names.is_empty()
        {
            return Err(format!(
                "--target {name}: no {TARGET_PREFIX}{name}_HOST is set"
            ));
        }
        names
    } else {
        Vec::new()
    };

    let mut command = Command::new("cargo");
    command.current_dir(repo_root);
    if live {
        // The suite drives the real fleetctl binary.
        eprintln!("==> building fleetctl for the live suite");
        let status = Command::new("cargo")
            .current_dir(repo_root)
            .args(["build", "--locked", "-p", "fleetctl"])
            .status()
            .map_err(|error| format!("cargo build could not run: {error}"))?;
        if !status.success() {
            return Err("building fleetctl failed".to_owned());
        }
        let fleetctl = target_dir(repo_root)
            .join("debug")
            .join(format!("fleetctl{}", std::env::consts::EXE_SUFFIX));
        command.env(FLEETCTL_VAR, fleetctl);
    }
    if let Some(name) = &target {
        command.env(TARGET_FILTER, name);
    }
    command
        .args([
            "test",
            "--locked",
            "-p",
            "fleet-controller",
            "--test",
            "proxmox_live",
            "--",
            "--test-threads=1",
            "--nocapture",
            "live_",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    eprintln!(
        "==> cargo test -p fleet-controller --test proxmox_live -- --test-threads=1 --nocapture live_"
    );
    let mut child = command
        .spawn()
        .map_err(|error| format!("cargo test could not run: {error}"))?;
    let mut reported = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let mut stderr = std::io::stderr();
        for read in BufReader::new(stdout).lines() {
            let text = read.map_err(|error| format!("reading the suite's output: {error}"))?;
            let _ = writeln!(stderr, "{text}");
            if let Some(row) = parse_result_line(&text) {
                reported.push(row);
            }
        }
    }
    let status = child
        .wait()
        .map_err(|error| format!("cargo test did not finish: {error}"))?;
    Ok(Summary::build(
        live,
        target,
        &expected,
        &reported,
        status.success(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(scenario: &str, target: Option<&str>, status: Status, reason: &str) -> ResultRow {
        ResultRow {
            scenario: scenario.to_owned(),
            target: target.map(str::to_owned),
            status,
            reason: reason.to_owned(),
            duration_ms: 5,
        }
    }

    #[test]
    fn result_lines_parse_wherever_the_marker_sits() {
        let parsed = parse_result_line(
            "test live_trust ... FLEET_PVE_ACCEPTANCE_RESULT scenario=trust target=PVE9 status=pass duration_ms=1234 reason=",
        )
        .unwrap();
        assert_eq!(
            parsed,
            ResultRow {
                scenario: "trust".to_owned(),
                target: Some("PVE9".to_owned()),
                status: Status::Pass,
                reason: String::new(),
                duration_ms: 1234,
            }
        );
        let parsed = parse_result_line(
            "FLEET_PVE_ACCEPTANCE_RESULT scenario=partial-node-failure target=PVE8 status=skipped duration_ms=0 reason=skipped: no cluster target (x=y)",
        )
        .unwrap();
        assert_eq!(parsed.status, Status::Skipped);
        assert_eq!(parsed.reason, "skipped: no cluster target (x=y)");
        let parsed = parse_result_line(
            "FLEET_PVE_ACCEPTANCE_RESULT scenario=trust target=- status=skipped duration_ms=0 reason=FLEET_PVE_LIVE is not 1",
        )
        .unwrap();
        assert_eq!(parsed.target, None);
        assert!(parse_result_line("test live_trust ... ok").is_none());
        assert!(
            parse_result_line("FLEET_PVE_ACCEPTANCE_RESULT scenario=trust status=bogus").is_none()
        );
    }

    #[test]
    fn the_gate_off_summary_is_all_skipped_and_ok() {
        let reported: Vec<ResultRow> = SCENARIOS
            .iter()
            .map(|scenario| row(scenario, None, Status::Skipped, "FLEET_PVE_LIVE is not 1"))
            .collect();
        let summary = Summary::build(false, None, &[], &reported, true);
        assert_eq!(summary.results.len(), SCENARIOS.len());
        assert_eq!(summary.count(Status::Skipped), SCENARIOS.len());
        assert!(summary.ok());
        let json = summary.to_json();
        assert!(json.contains("\"live\": false"), "{json}");
        assert!(json.contains("\"targets\": []"), "{json}");
        assert!(
            json.contains("{\"scenario\": \"trust\", \"target\": null, \"status\": \"skipped\", \"reason\": \"FLEET_PVE_LIVE is not 1\", \"durationMs\": 5}"),
            "{json}"
        );
        assert!(
            json.contains("\"totals\": {\"pass\": 0, \"fail\": 0, \"skipped\": 6}"),
            "{json}"
        );
        assert!(json.trim_end().ends_with("\"ok\": true\n}"), "{json}");
    }

    #[test]
    fn a_pair_that_never_reported_is_a_failure() {
        let targets = vec!["PVE8".to_owned(), "PVE9".to_owned()];
        let reported = vec![
            row("trust", Some("PVE9"), Status::Pass, ""),
            row(
                "partial-node-failure",
                Some("PVE9"),
                Status::Skipped,
                "skipped: no cluster target",
            ),
        ];
        let summary = Summary::build(true, None, &targets, &reported, false);
        assert_eq!(summary.results.len(), SCENARIOS.len() * 2);
        assert_eq!(summary.count(Status::Pass), 1);
        assert_eq!(summary.count(Status::Skipped), 1);
        assert_eq!(summary.count(Status::Fail), SCENARIOS.len() * 2 - 2);
        let missing = summary
            .results
            .iter()
            .find(|row| row.scenario == "trust" && row.target.as_deref() == Some("PVE8"))
            .unwrap();
        assert_eq!(missing.status, Status::Fail);
        assert!(missing.reason.contains("no result reported"));
        assert!(!summary.ok());
    }

    #[test]
    fn a_failing_test_exit_fails_the_run_even_when_every_row_passed() {
        let reported: Vec<ResultRow> = SCENARIOS
            .iter()
            .map(|scenario| row(scenario, Some("PVE9"), Status::Pass, ""))
            .collect();
        let targets = vec!["PVE9".to_owned()];
        assert!(Summary::build(true, None, &targets, &reported, true).ok());
        assert!(!Summary::build(true, None, &targets, &reported, false).ok());
    }

    #[test]
    fn json_strings_escape_quotes_backslashes_and_controls() {
        assert_eq!(json_string("a\"b\\c\nd\u{1}"), "\"a\\\"b\\\\c\\nd\\u0001\"");
    }

    #[test]
    fn targets_come_from_host_variables_and_the_filter() {
        let env: BTreeMap<String, String> = [
            ("FLEET_PVE_TARGET_PVE9_HOST", "h"),
            ("FLEET_PVE_TARGET_PVE9_NODE", "n"),
            ("FLEET_PVE_TARGET_CLUSTER_HOST", "h"),
            ("FLEET_PVE_TARGET__HOST", "h"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
        assert_eq!(configured_targets(&env, None), vec!["CLUSTER", "PVE9"]);
        assert_eq!(configured_targets(&env, Some("PVE9")), vec!["PVE9"]);
        assert!(configured_targets(&env, Some("PVE8")).is_empty());
    }

    #[test]
    fn arguments_accept_only_a_target_name() {
        assert_eq!(parse_args(&[]), Ok(None));
        assert_eq!(
            parse_args(&["--target".to_owned(), "PVE9".to_owned()]),
            Ok(Some("PVE9".to_owned()))
        );
        assert!(parse_args(&["--target".to_owned()]).is_err());
        assert!(parse_args(&["--target".to_owned(), "pve9".to_owned()]).is_err());
        assert!(parse_args(&["--all".to_owned()]).is_err());
    }
}
