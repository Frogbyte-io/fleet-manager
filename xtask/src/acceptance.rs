//! The shared runner behind the live acceptance suites
//! (`cargo xtask pve-acceptance`, `cargo xtask image-acceptance`): it runs
//! one live `cargo test` target, collects the result lines the suite prints
//! (see [`SuiteSpec::marker`]), and builds a machine-readable JSON summary
//! with one row per scenario and target, each `pass`, `fail`, or `skipped`
//! with its reason.
//!
//! Every expected scenario/target pair that never reported is a failure,
//! never a silent pass, and the run exits non-zero when anything failed.
//! Without `FLEET_PVE_LIVE=1` every scenario reports skipped and no PVE is
//! needed. `cargo xtask verify` never runs a live suite.

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};

/// One live suite: what it is called, how its result lines are marked,
/// the scenarios it must report, and the `cargo test` target that runs it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuiteSpec {
    /// The xtask subcommand and the summary's `suite` field.
    pub suite: &'static str,
    /// The marker the suite prints before every result.
    pub marker: &'static str,
    /// The scenarios, in report order. Kept in step with the suite's own
    /// `SCENARIOS`.
    pub scenarios: &'static [&'static str],
    /// The `fleet-controller` integration test target (`--test <name>`).
    pub test_target: &'static str,
    /// The most wall time the whole run may take, compile included. Past
    /// it the suite's process tree is killed and every unreported pair
    /// fails.
    pub deadline: std::time::Duration,
}

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

/// Parses one result line, wherever `marker` sits in the line (libtest
/// may prefix it with `test name ... `).
#[must_use]
pub fn parse_result_line(marker: &str, line: &str) -> Option<ResultRow> {
    let start = line.find(marker)?;
    let rest = line[start + marker.len()..].trim_start();
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
        // Required: a line without a valid duration is malformed, and a
        // malformed line must leave its pair unreported (a failure).
        duration_ms: values.get("duration_ms")?.parse().ok()?,
    })
}

/// The target names configured in an environment (from
/// `FLEET_PVE_TARGET_<NAME>_HOST`), narrowed by the filter.
#[must_use]
pub fn configured_targets(env: &BTreeMap<String, String>, filter: Option<&str>) -> Vec<String> {
    let mut names: Vec<String> = env
        .keys()
        .filter_map(|key| key.strip_prefix(TARGET_PREFIX)?.strip_suffix("_HOST"))
        // The same alphabet `--target` accepts: the name is one
        // space-separated field of every result line.
        .filter(|name| valid_target_name(name))
        .filter(|name| filter.is_none_or(|filter| filter == *name))
        .map(str::to_owned)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// The summary the acceptance evidence records.
#[derive(Clone, Debug)]
pub struct Summary {
    /// The suite it summarizes.
    pub spec: SuiteSpec,
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
        spec: SuiteSpec,
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
        for &scenario in spec.scenarios {
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
        // A row the matrix has no cell for is drift between the suite and
        // this runner: a scenario the runner does not list, or a row
        // without a target while the matrix has named targets. It is kept,
        // and failed loudly, never dropped.
        let mut unexpected: Vec<ResultRow> = Vec::new();
        for row in reported {
            let known = spec.scenarios.contains(&row.scenario.as_str());
            if (known && columns.contains(&row.target))
                || unexpected
                    .iter()
                    .any(|seen| seen.scenario == row.scenario && seen.target == row.target)
            {
                continue;
            }
            let drift = if known {
                format!(
                    "scenario {:?} reported without a target while the matrix has targets ({}); update the suite to report its target",
                    row.scenario, spec.suite
                )
            } else {
                format!(
                    "scenario {:?} is not in the runner's list ({}); update its SCENARIOS",
                    row.scenario, spec.suite
                )
            };
            unexpected.push(ResultRow {
                status: Status::Fail,
                reason: format!("{drift} (reported {}: {})", row.status.id(), row.reason),
                ..row.clone()
            });
        }
        results.extend(unexpected);
        Self {
            spec,
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
        let _ = writeln!(out, "  \"suite\": {},", json_string(self.spec.suite));
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
            list(&mut self.spec.scenarios.iter().copied())
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

/// Parses a suite subcommand's arguments: `[--target NAME]`.
///
/// # Errors
///
/// On an unknown argument or a missing/invalid target name.
pub fn parse_args(spec: &SuiteSpec, args: &[String]) -> Result<Option<String>, String> {
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
            other => return Err(format!("unknown {} argument {other:?}", spec.suite)),
        }
    }
    Ok(target)
}

/// Whether `name` is a usable `<NAME>`: `[A-Za-z0-9_]+`, as the suite
/// requires (the name is one space-separated field of every result line).
#[must_use]
pub fn valid_target_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The target filter in force: `--target`, else an inherited
/// `FLEET_PVE_ACCEPTANCE_TARGET` (the suite honours either, so the expected
/// matrix must too).
#[must_use]
pub fn effective_filter(cli: Option<&str>, env: &BTreeMap<String, String>) -> Option<String> {
    cli.map(str::to_owned).or_else(|| {
        env.get(TARGET_FILTER)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

/// The cargo target directory: `CARGO_TARGET_DIR` (cargo resolves a
/// relative one against the invocation directory, which is `repo_root`
/// here), else `repo_root/target`.
#[must_use]
pub fn resolve_target_dir(repo_root: &Path, configured: Option<std::ffi::OsString>) -> PathBuf {
    match configured.map(PathBuf::from) {
        Some(path) if path.is_absolute() => path,
        Some(path) => repo_root.join(path),
        None => repo_root.join("target"),
    }
}

/// The parent PID in one `/proc/<pid>/stat` line. The command name may hold
/// spaces and parentheses, so the fields are read after its last `)`.
#[must_use]
pub fn parent_of_stat(stat: &str) -> Option<u32> {
    let after = &stat[stat.rfind(')')? + 1..];
    let mut fields = after.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

/// Every descendant of `root` in a `(pid, parent)` table.
#[must_use]
pub fn descendants_in(root: u32, table: &[(u32, u32)]) -> Vec<u32> {
    let mut found = Vec::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for &(pid, ppid) in table {
            if ppid == parent && pid != root && !found.contains(&pid) {
                found.push(pid);
                frontier.push(pid);
            }
        }
    }
    found
}

/// Refuses a live run on a host whose process table the runner cannot read
/// at `proc_root`: without it an early exit could not stop the suite's
/// process tree, and the test binary and its controller would keep
/// creating and destroying guests unattended.
///
/// # Errors
///
/// When `live` and `proc_root` has no readable process table.
pub fn require_process_table(live: bool, proc_root: &Path) -> Result<(), String> {
    if !live || proc_root.join("self").join("stat").is_file() {
        return Ok(());
    }
    Err(format!(
        "a live run needs the {} process table (Linux) to stop the suite's process tree if \
         the runner exits early; run it on Linux",
        proc_root.display()
    ))
}

/// The live descendants of `root`, from `/proc` (empty where there is none).
fn descendants(root: u32) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let table: Vec<(u32, u32)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
            Some((pid, parent_of_stat(&stat)?))
        })
        .collect();
    descendants_in(root, &table)
}

/// Freezes `root` and every descendant it has, to a fixed point: `snapshot`
/// lists the tree and `stop` sends `SIGSTOP`. A process forked after one
/// snapshot is still found by the next (its stopped parent cannot exit and
/// orphan it), and a stopped process forks nothing more, so the loop ends
/// once a snapshot finds nothing new. `rounds` bounds a tree that somehow
/// keeps growing. Answers every process it stopped, the root first.
pub fn freeze_tree(
    root: u32,
    mut snapshot: impl FnMut() -> Vec<u32>,
    mut stop: impl FnMut(&[u32]),
    rounds: usize,
) -> Vec<u32> {
    let mut frozen = vec![root];
    stop(&frozen);
    for _ in 0..rounds {
        let new: Vec<u32> = snapshot()
            .into_iter()
            .filter(|pid| !frozen.contains(pid))
            .collect();
        if new.is_empty() {
            break;
        }
        stop(&new);
        frozen.extend(new);
    }
    frozen
}

/// Sends `signal` to `pids` through `kill(1)`. Its exit status is not
/// trusted either way: a process that already exited fails it harmlessly,
/// so the caller checks what is still alive afterwards instead.
fn send_signal(signal: &str, pids: &[u32]) -> Result<(), String> {
    if pids.is_empty() {
        return Ok(());
    }
    Command::new("kill")
        .arg(signal)
        .arg("--")
        .args(pids.iter().map(u32::to_string))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|_| ())
        .map_err(|error| format!("kill {signal} could not run: {error}"))
}

/// Whether `pid` is still running (a zombie has already died).
fn is_running(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        !stat
            .rsplit_once(')')
            .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
    })
}

/// The running suite (`cargo test`, the test binary under it, and the
/// `fleet-controller` that binary starts). Unless it is reaped through
/// [`SuiteProcess::wait`], dropping it — on any early return or a panic —
/// kills the whole process tree and reaps the child, so a live run is never
/// left creating and destroying guests unattended. Killing only `cargo`
/// would leave the test binary and its controller running.
struct SuiteProcess {
    child: Option<Child>,
}

impl SuiteProcess {
    /// Waits for the suite. The child stays in `self` until it is reaped,
    /// so a failed wait still kills the tree on drop.
    fn wait(mut self) -> std::io::Result<ExitStatus> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| std::io::Error::other("the suite was already reaped"))?;
        let status = child.wait()?;
        self.child = None;
        Ok(status)
    }
}

impl Drop for SuiteProcess {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let root = child.id();
        // Freeze the whole tree before anything dies (a dead parent's
        // orphans are re-parented and no longer found, and a live one can
        // keep forking), then kill it all at once.
        let mut errors = Vec::new();
        let tree = freeze_tree(
            root,
            || descendants(root),
            |pids| {
                if let Err(error) = send_signal("-STOP", pids) {
                    errors.push(error);
                }
            },
            64,
        );
        if let Err(error) = send_signal("-KILL", &tree) {
            errors.push(error);
        }
        if let Err(error) = child.kill() {
            errors.push(format!("killing the suite failed: {error}"));
        }
        if let Err(error) = child.wait() {
            errors.push(format!("reaping the suite failed: {error}"));
        }
        let started = std::time::Instant::now();
        let mut survivors: Vec<u32> = tree
            .iter()
            .copied()
            .filter(|&pid| is_running(pid))
            .collect();
        while !survivors.is_empty() && started.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::sleep(std::time::Duration::from_millis(50));
            survivors.retain(|&pid| is_running(pid));
        }
        if survivors.is_empty() {
            eprintln!(
                "==> the runner stopped early: killed the suite and its {} descendant process(es)",
                tree.len() - 1
            );
        } else {
            let list: Vec<String> = survivors.iter().map(u32::to_string).collect();
            eprintln!(
                "==> WARNING: the runner stopped early but could not kill process(es) {}; they may \
                 still be creating and destroying guests, so stop them by hand{}",
                list.join(" "),
                if errors.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", errors.join("; "))
                }
            );
        }
    }
}

/// Builds the real `fleetctl` binary the live suite drives and answers its
/// path.
fn build_fleetctl(repo_root: &Path) -> Result<PathBuf, String> {
    eprintln!("==> building fleetctl for the live suite");
    let status = Command::new("cargo")
        .current_dir(repo_root)
        .args(["build", "--locked", "-p", "fleetctl"])
        .status()
        .map_err(|error| format!("cargo build could not run: {error}"))?;
    if !status.success() {
        return Err("building fleetctl failed".to_owned());
    }
    Ok(
        resolve_target_dir(repo_root, std::env::var_os("CARGO_TARGET_DIR"))
            .join("debug")
            .join(format!("fleetctl{}", std::env::consts::EXE_SUFFIX)),
    )
}

/// Runs the suite and answers its summary. Progress and the suite's own
/// output go to stderr; the caller prints the JSON on stdout.
///
/// # Errors
///
/// When cargo cannot run or the target filter names no configured target.
pub fn run(spec: &SuiteSpec, repo_root: &Path, target: Option<&str>) -> Result<Summary, String> {
    let env: BTreeMap<String, String> = std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect();
    let live = env.get(LIVE_GATE).map(|value| value.trim()) == Some("1");
    require_process_table(live, Path::new("/proc"))?;
    let filter = effective_filter(target, &env);
    let expected = if live {
        let names = configured_targets(&env, filter.as_deref());
        if let Some(name) = &filter
            && names.is_empty()
        {
            let source = if target.is_some() {
                "--target".to_owned()
            } else {
                format!("the inherited {TARGET_FILTER}")
            };
            return Err(format!(
                "{source} {name}: no {TARGET_PREFIX}{name}_HOST is set"
            ));
        }
        names
    } else {
        Vec::new()
    };

    let mut command = Command::new("cargo");
    command.current_dir(repo_root);
    if live {
        command.env(FLEETCTL_VAR, build_fleetctl(repo_root)?);
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
            spec.test_target,
            "--",
            "--test-threads=1",
            "--nocapture",
            "live_",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    eprintln!(
        "==> cargo test -p fleet-controller --test {} -- --test-threads=1 --nocapture live_",
        spec.test_target
    );
    let mut child = command
        .spawn()
        .map_err(|error| format!("cargo test could not run: {error}"))?;
    let stdout = child.stdout.take();
    // From here every early return drops `suite`, which kills and reaps it.
    let suite = SuiteProcess { child: Some(child) };
    let (reported, timed_out) = match stdout {
        Some(stdout) => read_rows(spec, stdout)?,
        None => (Vec::new(), false),
    };
    if timed_out {
        let _ = writeln!(
            std::io::stderr(),
            "==> the suite ran past its {}-minute bound; killing it (unreported scenarios fail)",
            spec.deadline.as_secs() / 60
        );
        // Dropping the wrapper freezes, kills and reaps the whole tree.
        drop(suite);
        let mut summary = Summary::build(*spec, live, filter, &expected, &reported, false);
        for row in &mut summary.results {
            if row.reason.starts_with("no result reported") {
                row.reason = format!(
                    "no result reported before the suite's {}-minute bound killed it",
                    spec.deadline.as_secs() / 60
                );
            }
        }
        return Ok(summary);
    }
    let status = suite
        .wait()
        .map_err(|error| format!("cargo test did not finish: {error}"))?;
    Ok(Summary::build(
        *spec,
        live,
        filter,
        &expected,
        &reported,
        status.success(),
    ))
}

/// Echoes the suite's output and collects its result rows until the output
/// ends or the spec's deadline passes; answers whether it timed out.
fn read_rows(
    spec: &SuiteSpec,
    stdout: impl std::io::Read + Send + 'static,
) -> Result<(Vec<ResultRow>, bool), String> {
    let mut reported = Vec::new();
    // The output is read on its own thread so the deadline can end the
    // wait; killing the tree closes the pipe and ends that thread.
    let (lines, rows) = std::sync::mpsc::channel::<std::io::Result<Vec<u8>>>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut buffer = Vec::new();
            match reader.read_until(b'\n', &mut buffer) {
                Ok(0) => break,
                Ok(_) => {
                    if lines.send(Ok(buffer)).is_err() {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => {
                    let _ = lines.send(Err(error));
                    break;
                }
            }
        }
    });
    let deadline = std::time::Instant::now() + spec.deadline;
    let mut stderr = std::io::stderr();
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match rows.recv_timeout(left) {
            Ok(Ok(buffer)) => {
                // Lossy: one invalid UTF-8 byte must not end the read.
                let text = String::from_utf8_lossy(&buffer);
                let text = text.trim_end_matches(['\n', '\r']);
                let _ = writeln!(stderr, "{text}");
                if let Some(row) = parse_result_line(spec.marker, text) {
                    reported.push(row);
                }
            }
            Ok(Err(error)) => return Err(format!("reading the suite's output: {error}")),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok((reported, false)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return Ok((reported, true)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pve_acceptance::SPEC;
    const SCENARIOS: &[&str] = SPEC.scenarios;

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
            SPEC.marker,
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
            SPEC.marker,
            "FLEET_PVE_ACCEPTANCE_RESULT scenario=partial-node-failure target=PVE8 status=skipped duration_ms=0 reason=skipped: no cluster target (x=y)",
        )
        .unwrap();
        assert_eq!(parsed.status, Status::Skipped);
        assert_eq!(parsed.reason, "skipped: no cluster target (x=y)");
        let parsed = parse_result_line(
            SPEC.marker,
            "FLEET_PVE_ACCEPTANCE_RESULT scenario=trust target=- status=skipped duration_ms=0 reason=FLEET_PVE_LIVE is not 1",
        )
        .unwrap();
        assert_eq!(parsed.target, None);
        assert!(parse_result_line(SPEC.marker, "test live_trust ... ok").is_none());
        assert!(
            parse_result_line(
                SPEC.marker,
                "FLEET_PVE_ACCEPTANCE_RESULT scenario=trust status=bogus"
            )
            .is_none()
        );
    }

    #[test]
    fn the_gate_off_summary_is_all_skipped_and_ok() {
        let reported: Vec<ResultRow> = SCENARIOS
            .iter()
            .map(|scenario| row(scenario, None, Status::Skipped, "FLEET_PVE_LIVE is not 1"))
            .collect();
        let summary = Summary::build(SPEC, false, None, &[], &reported, true);
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
        let summary = Summary::build(SPEC, true, None, &targets, &reported, false);
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
        assert!(Summary::build(SPEC, true, None, &targets, &reported, true).ok());
        assert!(!Summary::build(SPEC, true, None, &targets, &reported, false).ok());
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
        assert_eq!(parse_args(&SPEC, &[]), Ok(None));
        assert_eq!(
            parse_args(&SPEC, &["--target".to_owned(), "PVE9".to_owned()]),
            Ok(Some("PVE9".to_owned()))
        );
        assert!(parse_args(&SPEC, &["--target".to_owned()]).is_err());
        // The suite's own name alphabet: [A-Za-z0-9_].
        assert_eq!(
            parse_args(&SPEC, &["--target".to_owned(), "lab_9".to_owned()]),
            Ok(Some("lab_9".to_owned()))
        );
        assert!(parse_args(&SPEC, &["--target".to_owned(), "PVE 9".to_owned()]).is_err());
        assert!(parse_args(&SPEC, &["--target".to_owned(), "PVE-9".to_owned()]).is_err());
        assert!(parse_args(&SPEC, &["--all".to_owned()]).is_err());
    }

    #[test]
    fn an_inherited_target_filter_narrows_the_expected_matrix() {
        let mut env: BTreeMap<String, String> = [
            ("FLEET_PVE_TARGET_PVE9_HOST", "h"),
            ("FLEET_PVE_TARGET_PVE8_HOST", "h"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
        assert_eq!(effective_filter(None, &env), None);
        env.insert(TARGET_FILTER.to_owned(), " PVE9 ".to_owned());
        let filter = effective_filter(None, &env);
        assert_eq!(filter.as_deref(), Some("PVE9"));
        assert_eq!(configured_targets(&env, filter.as_deref()), vec!["PVE9"]);
        // --target wins over the inherited value.
        assert_eq!(
            effective_filter(Some("PVE8"), &env).as_deref(),
            Some("PVE8")
        );
        env.insert(TARGET_FILTER.to_owned(), "  ".to_owned());
        assert_eq!(effective_filter(None, &env), None);
    }

    #[test]
    fn a_relative_target_dir_resolves_against_the_repo_root() {
        let root = Path::new("/repo");
        assert_eq!(resolve_target_dir(root, None), Path::new("/repo/target"));
        assert_eq!(
            resolve_target_dir(root, Some("build/out".into())),
            Path::new("/repo/build/out")
        );
        assert_eq!(
            resolve_target_dir(root, Some("/cache/target".into())),
            Path::new("/cache/target")
        );
    }

    #[test]
    fn a_live_run_needs_a_readable_process_table() {
        let missing = Path::new("/nonexistent-fleet-proc");
        assert!(require_process_table(false, missing).is_ok());
        let refused = require_process_table(true, missing).unwrap_err();
        assert!(refused.contains("process table"), "{refused}");
        if cfg!(target_os = "linux") {
            assert!(require_process_table(true, Path::new("/proc")).is_ok());
        }
    }

    #[test]
    fn the_process_tree_is_read_from_proc_stat() {
        assert_eq!(
            parent_of_stat("4242 (cargo) S 4000 4242 4000 0 -1"),
            Some(4000)
        );
        // A command name with spaces and parentheses.
        assert_eq!(
            parent_of_stat("4243 (proxmox_live (x) y) R 4242 4242 4000"),
            Some(4242)
        );
        assert_eq!(parent_of_stat("garbage"), None);
        let table = [(10, 1), (11, 10), (12, 11), (13, 11), (20, 1), (14, 13)];
        let mut tree = descendants_in(10, &table);
        tree.sort_unstable();
        assert_eq!(tree, vec![11, 12, 13, 14]);
        assert!(descendants_in(20, &table).is_empty());
    }

    #[test]
    fn freezing_finds_processes_forked_after_the_first_snapshot() {
        // Each snapshot reveals one more generation, as a tree forking
        // between snapshots would, until the stopped tree forks no more.
        let generations = [vec![11], vec![11, 12], vec![11, 12, 13], vec![11, 12, 13]];
        let mut round = 0;
        let mut stopped = Vec::new();
        let frozen = freeze_tree(
            10,
            || {
                let tree = generations[round.min(generations.len() - 1)].clone();
                round += 1;
                tree
            },
            |pids| stopped.extend_from_slice(pids),
            64,
        );
        assert_eq!(frozen, vec![10, 11, 12, 13]);
        assert_eq!(stopped, frozen);
        assert_eq!(round, 4);
    }

    #[test]
    fn freezing_a_tree_that_never_settles_is_bounded() {
        let mut next = 100;
        let frozen = freeze_tree(
            10,
            || {
                next += 1;
                (101..=next).collect()
            },
            |_| {},
            5,
        );
        assert_eq!(frozen.len(), 6);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dropping_the_suite_kills_and_reaps_the_whole_tree() {
        // A child that starts a grandchild, as cargo starts the test binary.
        let child = Command::new("sh")
            .args(["-c", "sleep 300 & wait"])
            .spawn()
            .unwrap();
        let root = child.id();
        let started = std::time::Instant::now();
        while descendants(root).is_empty() {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "the grandchild never started"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let grandchildren = descendants(root);
        drop(SuiteProcess { child: Some(child) });
        let started = std::time::Instant::now();
        // The grandchild is gone (or a zombie awaiting its new parent).
        while grandchildren.iter().any(|&pid| is_running(pid)) {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "the grandchild outlived the suite"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // The child itself was reaped.
        assert!(!Path::new(&format!("/proc/{root}")).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dropping_the_suite_kills_a_tree_that_keeps_forking() {
        // A tree that keeps forking while it is being stopped; the marker
        // duration finds its processes even after they are orphaned.
        let marker = "301.7193";
        let running_markers = || {
            std::fs::read_dir("/proc")
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    std::fs::read(entry.path().join("cmdline"))
                        .is_ok_and(|cmdline| cmdline == format!("sleep\0{marker}\0").as_bytes())
                })
                .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
                .filter(|&pid| is_running(pid))
                .count()
        };
        let child = Command::new("sh")
            .args([
                "-c",
                &format!("while :; do sleep {marker} & sleep 0.01; done"),
            ])
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        while running_markers() < 3 {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "the tree never forked"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        drop(SuiteProcess { child: Some(child) });
        assert_eq!(running_markers(), 0, "a forked process outlived the suite");
    }

    #[test]
    fn a_suite_that_stops_talking_is_cut_off_at_the_deadline() {
        let (reader, mut writer) = std::io::pipe().unwrap();
        writeln!(
            writer,
            "{} scenario=trust target=PVE9 status=pass duration_ms=1 reason=",
            SPEC.marker
        )
        .unwrap();
        // The writer stays open: the suite hangs without closing its output.
        let spec = SuiteSpec {
            deadline: std::time::Duration::from_millis(300),
            ..SPEC
        };
        let started = std::time::Instant::now();
        let (rows, timed_out) = read_rows(&spec, reader).unwrap();
        assert!(timed_out);
        assert_eq!(rows.len(), 1, "rows before the deadline are kept");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        drop(writer);
    }

    #[test]
    fn a_result_line_without_a_valid_duration_is_malformed() {
        for line in [
            format!(
                "{} scenario=trust target=PVE9 status=pass reason=",
                SPEC.marker
            ),
            format!(
                "{} scenario=trust target=PVE9 status=pass duration_ms=soon reason=",
                SPEC.marker
            ),
        ] {
            assert_eq!(parse_result_line(SPEC.marker, &line), None, "{line}");
        }
    }

    #[test]
    fn a_targetless_row_in_a_targeted_matrix_fails_loudly() {
        let reported = vec![
            row("trust", Some("PVE9"), Status::Pass, ""),
            row("trust", None, Status::Skipped, "gate off"),
        ];
        let summary = Summary::build(SPEC, true, None, &["PVE9".to_owned()], &reported, true);
        let drift = summary
            .results
            .iter()
            .find(|row| row.scenario == "trust" && row.target.is_none())
            .expect("kept, not dropped");
        assert_eq!(drift.status, Status::Fail);
        assert!(drift.reason.contains("without a target"));
        assert!(drift.reason.contains("gate off"));
    }

    #[test]
    fn a_scenario_the_runner_does_not_list_fails_loudly() {
        let reported = vec![
            row("trust", Some("PVE9"), Status::Pass, ""),
            row("brand-new", Some("PVE9"), Status::Pass, ""),
        ];
        let summary = Summary::build(SPEC, true, None, &["PVE9".to_owned()], &reported, true);
        let unexpected = summary
            .results
            .iter()
            .find(|row| row.scenario == "brand-new")
            .expect("kept, not dropped");
        assert_eq!(unexpected.status, Status::Fail);
        assert!(unexpected.reason.contains("not in the runner's list"));
        assert!(!summary.ok());
    }

    #[test]
    fn host_variables_with_names_outside_the_alphabet_are_ignored() {
        let env: BTreeMap<String, String> = [
            ("FLEET_PVE_TARGET_PVE-9_HOST", "h"),
            ("FLEET_PVE_TARGET_PVE9_HOST", "h"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
        assert_eq!(configured_targets(&env, None), vec!["PVE9"]);
    }

    #[test]
    fn the_summary_names_its_own_suite_and_scenarios() {
        let spec = crate::image_acceptance::SPEC;
        let summary = Summary::build(spec, false, None, &[], &[], true);
        assert_eq!(summary.results.len(), spec.scenarios.len());
        let json = summary.to_json();
        assert!(json.contains("\"suite\": \"image-acceptance\","), "{json}");
        assert!(json.contains("\"version-gate\""), "{json}");
        assert!(!json.contains("\"trust\""), "{json}");
        // A line carrying another suite's marker is not this suite's result.
        assert!(
            parse_result_line(
                spec.marker,
                "FLEET_PVE_ACCEPTANCE_RESULT scenario=trust target=- status=pass duration_ms=0 reason="
            )
            .is_none()
        );
        assert!(
            parse_args(&spec, &["--all".to_owned()])
                .unwrap_err()
                .contains("image-acceptance")
        );
    }
}
