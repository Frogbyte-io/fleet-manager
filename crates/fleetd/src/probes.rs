//! Pluggable local probes: how a node observes itself.
//!
//! A probe is a small, read-only observer with a name, a schema version,
//! and a `collect` that returns capability facts. The runner below is the
//! isolation boundary the inventory contract depends on: each probe runs
//! under its own timeout, a panic in one probe cannot take the collection
//! down, and a failed probe reports *honestly* — its facts come back with
//! `unknown`/`unavailable` status while every other probe's facts survive.
//!
//! Probes never touch project directories, containers, or desired state;
//! they observe the node itself and the tools on its PATH.

use std::sync::Arc;
use std::time::Duration;

use fleet_core::{CapabilityFact, CapabilityStatus};

/// How long one probe may run before the runner gives up on it.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// The bound for any single fact value a probe may report.
pub const MAX_FACT_VALUE_BYTES: usize = 4 * 1024;
/// The bound for the fact set one probe may return.
pub const MAX_FACTS_PER_PROBE: usize = 64;

/// One local probe. Probes are shared across the runner's isolation
/// threads, so implementations must be `Send + Sync`.
pub trait Probe: std::fmt::Debug + Send + Sync {
    /// The probe's name, used as the fact source qualifier and in probe
    /// error lists.
    fn name(&self) -> &'static str;

    /// The probe's schema version; ingestion refuses unknown versions.
    fn schema_version(&self) -> u32 {
        1
    }

    /// Collects the probe's facts. Read-only and bounded; the runner
    /// enforces the timeout and the payload bounds.
    ///
    /// # Errors
    ///
    /// Returns a caller-safe detail when the probe cannot observe at all.
    fn collect(&self) -> Result<Vec<CapabilityFact>, String>;
}

/// The probe set with its isolation boundary.
#[derive(Debug, Default)]
pub struct ProbeRunner {
    probes: Vec<Arc<dyn Probe>>,
}

impl ProbeRunner {
    /// Composes the runner from the probe set. The standard node probes
    /// come from [`standard_probes`]; tests inject their own.
    #[must_use]
    pub fn new(probes: Vec<Arc<dyn Probe>>) -> Self {
        Self { probes }
    }

    /// The names of the composed probes.
    #[must_use]
    pub fn probe_names(&self) -> Vec<String> {
        self.probes
            .iter()
            .map(|probe| probe.name().to_owned())
            .collect()
    }

    /// Runs every probe, isolated: a slow probe times out, a panicking or
    /// failing probe degrades to an error entry, and everything else still
    /// lands. The result pairs the surviving facts with the probe failures.
    #[must_use]
    pub fn collect(&self, now_millis: i64) -> Collected {
        let mut facts = Vec::new();
        let mut probe_errors: Vec<ProbeError> = Vec::new();
        for probe in &self.probes {
            let name = probe.name();
            let schema_version = probe.schema_version();
            // The probe crosses to its own thread through an Arc clone,
            // which is `Send + Sync` by the trait bounds — no lifetime
            // tricks, no unsafe.
            let probe = Arc::clone(probe);
            let outcome = run_isolated(move || probe.collect(), PROBE_TIMEOUT);
            match outcome {
                Ok(Ok(Ok(probe_facts))) => {
                    for mut fact in probe_facts {
                        if fact
                            .value
                            .as_ref()
                            .is_some_and(|value| value.len() > MAX_FACT_VALUE_BYTES)
                        {
                            let value = fact.value.take().unwrap_or_default();
                            fact.value =
                                Some(value[..MAX_FACT_VALUE_BYTES.min(value.len())].to_owned());
                        }
                        fact.source = format!("fleetd/{name}/{schema_version}");
                        fact.observed_at = fleet_core::Timestamp::from_unix_millis(now_millis);
                        facts.push(fact);
                        if facts.len() >= MAX_FACTS_PER_PROBE * 8 {
                            probe_errors.push(ProbeError {
                                probe: name.to_owned(),
                                detail: "the fact bound was reached; later probes are skipped"
                                    .to_owned(),
                            });
                            return Collected {
                                facts,
                                probe_errors,
                            };
                        }
                    }
                }
                // Three failure shapes, one entry: the probe returned an
                // error, the probe panicked (mapped to an error inside the
                // thread), or the thread never answered.
                // Three failure shapes, one entry: the probe returned an
                // error, the probe panicked (mapped to an error inside the
                // thread), or the thread never answered.
                Ok(Ok(Err(detail)) | Err(detail)) | Err(detail) => {
                    probe_errors.push(ProbeError {
                        probe: name.to_owned(),
                        detail,
                    });
                }
            }
        }
        Collected {
            facts,
            probe_errors,
        }
    }
}

/// The outcome of one collection round.
#[derive(Clone, Debug, Default)]
pub struct Collected {
    /// The facts that survived, stamped with source and observation time.
    pub facts: Vec<CapabilityFact>,
    /// What failed, per probe, bounded and safe to report.
    pub probe_errors: Vec<ProbeError>,
}

/// One probe's failure.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeError {
    /// Which probe failed.
    pub probe: String,
    /// The caller-safe detail.
    pub detail: String,
}

/// Runs one blocking probe on its own thread with a hard timeout. A timed
/// out or panicked probe thread is detached — it cannot take the
/// collection, the command, or the daemon down.
fn run_isolated<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
    timeout: Duration,
) -> Result<Result<T, String>, String> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
            .map_err(|_| "the probe panicked; it is isolated from the others".to_owned());
        let _ = sender.send(outcome);
    });
    match receiver.recv_timeout(timeout) {
        Ok(outcome) => Ok(outcome),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            Err(format!("the probe did not answer within {timeout:?}"))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("the probe thread died before answering".to_owned())
        }
    }
}

/// The standard node probe set: the platform, the hostname, this daemon,
/// the hardware facts (virtualization, model, CPU model, disk total), and
/// the tools on PATH.
#[must_use]
pub fn standard_probes() -> Vec<Arc<dyn Probe>> {
    vec![
        Arc::new(OsProbe),
        Arc::new(HostProbe),
        Arc::new(AgentProbe),
        Arc::new(HardwareProbe),
        Arc::new(ToolProbe::git()),
        Arc::new(ToolProbe::docker()),
        Arc::new(ToolProbe::tailscale()),
        Arc::new(ToolProbe::mise()),
    ]
}

/// The platform probe: family and architecture, from the process itself.
#[derive(Debug)]
pub struct OsProbe;

impl Probe for OsProbe {
    fn name(&self) -> &'static str {
        "os"
    }

    fn collect(&self) -> Result<Vec<CapabilityFact>, String> {
        Ok(vec![
            fact("os", "family", Some(std::env::consts::OS.to_owned())),
            fact("os", "arch", Some(std::env::consts::ARCH.to_owned())),
        ])
    }
}

/// The hostname probe: a file or environment read, never a subprocess.
#[derive(Debug)]
pub struct HostProbe;

impl Probe for HostProbe {
    fn name(&self) -> &'static str {
        "host"
    }

    fn collect(&self) -> Result<Vec<CapabilityFact>, String> {
        let hostname = read_hostname();
        Ok(vec![match hostname {
            Some(hostname) => fact("host", "name", Some(hostname)),
            None => CapabilityFact {
                namespace: "host".to_owned(),
                name: "name".to_owned(),
                value: None,
                status: CapabilityStatus::Unavailable,
                observed_at: fleet_core::Timestamp::from_unix_millis(0),
                source: String::new(),
            },
        }])
    }
}

/// This daemon's own version.
#[derive(Debug)]
pub struct AgentProbe;

impl Probe for AgentProbe {
    fn name(&self) -> &'static str {
        "agent"
    }

    fn collect(&self) -> Result<Vec<CapabilityFact>, String> {
        Ok(vec![fact(
            "agent",
            "fleetd",
            Some(env!("CARGO_PKG_VERSION").to_owned()),
        )])
    }
}

/// The hardware probe: virtualization kind, board or product model, CPU
/// model, and the root disk's total size. Read-only file and command
/// observation with honest unavailable states; serial numbers are never
/// read (FM-914).
#[derive(Debug)]
pub struct HardwareProbe;

impl Probe for HardwareProbe {
    fn name(&self) -> &'static str {
        "hardware"
    }

    fn collect(&self) -> Result<Vec<CapabilityFact>, String> {
        Ok(vec![
            Self::virtualization(),
            Self::model(),
            Self::cpu_model(),
            Self::disk_total(),
        ])
    }
}

impl HardwareProbe {
    fn virtualization() -> CapabilityFact {
        // The bare-metal answer is exit 1 with "none" on stdout, so judge
        // the text, not the status (matching the agentless probe).
        match std::process::Command::new("systemd-detect-virt").output() {
            Ok(output) => match virtualization_kind(&String::from_utf8_lossy(&output.stdout)) {
                Some(kind) => fact("host", "virtualization", Some(kind)),
                None => unavailable("host", "virtualization"),
            },
            Err(_) => unavailable("host", "virtualization"),
        }
    }

    fn model() -> CapabilityFact {
        if let Ok(model) = std::fs::read_to_string("/proc/device-tree/model") {
            let model = model.trim_end_matches('\0').trim().to_owned();
            if !model.is_empty() {
                return fact("hardware", "model", Some(model));
            }
        }
        if let Ok(model) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
            let model = model.trim().to_owned();
            if !model.is_empty() {
                return fact("hardware", "model", Some(model));
            }
        }
        unavailable("hardware", "model")
    }

    fn cpu_model() -> CapabilityFact {
        match std::fs::read_to_string("/proc/cpuinfo") {
            Ok(cpuinfo) => {
                let model = cpuinfo
                    .lines()
                    .find_map(|line| line.strip_prefix("model name"))
                    .and_then(|rest| rest.split_once(':'))
                    .map(|(_, model)| model.trim().to_owned())
                    .filter(|model| !model.is_empty());
                match model {
                    Some(model) => fact("hardware", "cpu_model", Some(model)),
                    None => unavailable("hardware", "cpu_model"),
                }
            }
            Err(_) => unavailable("hardware", "cpu_model"),
        }
    }

    fn disk_total() -> CapabilityFact {
        match std::process::Command::new("df").args(["-kP", "/"]).output() {
            Ok(output) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout);
                match root_disk_total_bytes(&text) {
                    Some(bytes) => fact("hardware", "disk_total_bytes", Some(bytes.to_string())),
                    None => unavailable("hardware", "disk_total_bytes"),
                }
            }
            _ => unavailable("hardware", "disk_total_bytes"),
        }
    }
}

/// The root filesystem's total size in bytes from POSIX `df -kP` output:
/// the last line's second field, in 1 KiB blocks; a missing, malformed, or
/// zero total is no fact (unavailable, not an invented zero).
fn root_disk_total_bytes(df_output: &str) -> Option<u64> {
    df_output
        .lines()
        .last()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|field| field.parse::<u64>().ok())
        .filter(|kb| *kb > 0)
        .map(|kb| kb * 1024)
}

/// The virtualization kind from `systemd-detect-virt` stdout: non-empty
/// text is the answer ("none" for bare metal included); empty or missing
/// output is no fact.
fn virtualization_kind(stdout: &str) -> Option<String> {
    let kind = stdout.trim();
    if kind.is_empty() {
        None
    } else {
        Some(kind.to_owned())
    }
}

fn unavailable(namespace: &str, name: &str) -> CapabilityFact {
    CapabilityFact {
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        value: None,
        status: CapabilityStatus::Unavailable,
        observed_at: fleet_core::Timestamp::from_unix_millis(0),
        source: String::new(),
    }
}

/// A tool on PATH: presence plus `--version`, bounded and isolated.
#[derive(Debug)]
pub struct ToolProbe {
    tool: &'static str,
    binary: &'static str,
}

impl ToolProbe {
    /// The git probe.
    #[must_use]
    pub fn git() -> Self {
        Self {
            tool: "git",
            binary: "git",
        }
    }

    /// The docker probe.
    #[must_use]
    pub fn docker() -> Self {
        Self {
            tool: "docker",
            binary: "docker",
        }
    }

    /// The tailscale probe.
    #[must_use]
    pub fn tailscale() -> Self {
        Self {
            tool: "tailscale",
            binary: "tailscale",
        }
    }

    /// The mise probe.
    #[must_use]
    pub fn mise() -> Self {
        Self {
            tool: "mise",
            binary: "mise",
        }
    }
}

impl Probe for ToolProbe {
    fn name(&self) -> &'static str {
        self.tool
    }

    fn collect(&self) -> Result<Vec<CapabilityFact>, String> {
        let version = tool_version(self.binary)?;
        Ok(vec![match version {
            Some(version) => fact("tool", self.tool, Some(version)),
            None => CapabilityFact {
                namespace: "tool".to_owned(),
                name: self.tool.to_owned(),
                value: None,
                status: CapabilityStatus::Unavailable,
                observed_at: fleet_core::Timestamp::from_unix_millis(0),
                source: String::new(),
            },
        }])
    }
}

/// The hostname from the OS without a subprocess.
fn read_hostname() -> Option<String> {
    #[cfg(unix)]
    {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME")
            .ok()
            .filter(|text| !text.is_empty())
    }
}

/// One `--version` probe: bounded output, no shell.
fn tool_version(binary: &str) -> Result<Option<String>, String> {
    let attempt = std::process::Command::new(binary).arg("--version").output();
    match attempt {
        Ok(output) => {
            if !output.status.success() {
                return Ok(None);
            }
            let text = String::from_utf8_lossy(&output.stdout);
            let first_line = text.lines().next().unwrap_or("").trim();
            if first_line.is_empty() {
                return Ok(None);
            }
            let bounded: String = first_line.chars().take(MAX_FACT_VALUE_BYTES).collect();
            Ok(Some(bounded))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("the version probe for {binary} failed: {error}")),
    }
}

fn fact(namespace: &str, name: &str, value: Option<String>) -> CapabilityFact {
    CapabilityFact {
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        value,
        status: CapabilityStatus::Known,
        observed_at: fleet_core::Timestamp::from_unix_millis(0),
        source: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A probe that sleeps past the timeout.
    #[derive(Debug)]
    struct SlowProbe;

    impl Probe for SlowProbe {
        fn name(&self) -> &'static str {
            "slow"
        }

        fn collect(&self) -> Result<Vec<CapabilityFact>, String> {
            std::thread::sleep(Duration::from_secs(5));
            Ok(vec![fact("slow", "value", Some("late".to_owned()))])
        }
    }

    /// A probe that fails with a detail.
    #[derive(Debug)]
    struct FailingProbe;

    impl Probe for FailingProbe {
        fn name(&self) -> &'static str {
            "failing"
        }

        fn collect(&self) -> Result<Vec<CapabilityFact>, String> {
            Err("the observation source is gone".to_owned())
        }
    }

    /// A probe that panics.
    #[derive(Debug)]
    struct PanickingProbe;

    impl Probe for PanickingProbe {
        fn name(&self) -> &'static str {
            "panicking"
        }

        fn collect(&self) -> Result<Vec<CapabilityFact>, String> {
            panic!("the probe is buggy");
        }
    }

    /// A healthy probe.
    #[derive(Debug)]
    struct HealthyProbe;

    impl Probe for HealthyProbe {
        fn name(&self) -> &'static str {
            "healthy"
        }

        fn collect(&self) -> Result<Vec<CapabilityFact>, String> {
            Ok(vec![fact("healthy", "value", Some("present".to_owned()))])
        }
    }

    #[test]
    fn a_failing_or_panicking_probe_is_isolated_from_the_others() {
        let runner = ProbeRunner::new(vec![
            Arc::new(FailingProbe),
            Arc::new(PanickingProbe),
            Arc::new(HealthyProbe),
        ]);
        let collected = runner.collect(1_000);
        let names: Vec<&str> = collected
            .facts
            .iter()
            .map(|f| f.namespace.as_str())
            .collect();
        assert!(names.contains(&"healthy"), "{names:?}");
        assert_eq!(
            collected.probe_errors.len(),
            2,
            "{:?}",
            collected.probe_errors
        );
        for error in &collected.probe_errors {
            assert!(
                error.detail.contains("gone") || error.detail.contains("panicked"),
                "{error:?}"
            );
        }
        // Facts carry provenance.
        for fact in &collected.facts {
            assert_eq!(fact.source, "fleetd/healthy/1");
            assert_eq!(fact.observed_at.unix_millis(), 1_000);
        }
    }

    #[test]
    fn a_slow_probe_times_out_without_blocking_the_rest() {
        let runner = ProbeRunner::new(vec![Arc::new(HealthyProbe), Arc::new(SlowProbe)]);
        let collected = runner.collect(0);
        assert!(
            collected
                .probe_errors
                .iter()
                .any(|error| error.probe == "slow" && error.detail.contains("did not answer")),
            "{:?}",
            collected.probe_errors
        );
        assert!(collected.facts.iter().any(|f| f.namespace == "healthy"));
    }

    #[test]
    fn the_standard_probes_report_the_platform() {
        let runner = ProbeRunner::new(standard_probes());
        let collected = runner.collect(0);
        let os_family = collected
            .facts
            .iter()
            .find(|f| f.namespace == "os" && f.name == "family")
            .expect("the os family fact");
        assert_eq!(os_family.value.as_deref(), Some(std::env::consts::OS));
        let agent = collected
            .facts
            .iter()
            .find(|f| f.namespace == "agent" && f.name == "fleetd")
            .expect("the agent fact");
        assert_eq!(agent.value.as_deref(), Some(env!("CARGO_PKG_VERSION")));
        // Tool probes that cannot run report honestly unavailable rather
        // than vanishing.
        for tool in ["git", "docker", "tailscale", "mise"] {
            let fact = collected
                .facts
                .iter()
                .find(|f| f.namespace == "tool" && f.name == tool);
            assert!(fact.is_some(), "the {tool} fact must exist");
        }
    }

    #[test]
    fn the_hardware_probe_reports_its_facts_honestly() {
        // FM-914: the four hardware facts always exist, with a value when
        // this host can answer and an honest unavailable when it cannot.
        let probe = HardwareProbe;
        let facts = probe.collect().expect("the hardware probe collects");
        let names: Vec<(&str, &str)> = facts
            .iter()
            .map(|fact| (fact.namespace.as_str(), fact.name.as_str()))
            .collect();
        for expected in [
            ("host", "virtualization"),
            ("hardware", "model"),
            ("hardware", "cpu_model"),
            ("hardware", "disk_total_bytes"),
        ] {
            assert!(
                names.contains(&expected),
                "missing {expected:?} in {names:?}"
            );
        }
        for fact in &facts {
            assert!(
                fact.status == CapabilityStatus::Known
                    || fact.status == CapabilityStatus::Unavailable,
                "{fact:?} must be known or unavailable, not a guess"
            );
        }
        // The disk total is a byte count when known.
        if let Some(disk) = facts
            .iter()
            .find(|fact| fact.namespace == "hardware" && fact.name == "disk_total_bytes")
            .filter(|disk| disk.status == CapabilityStatus::Known)
        {
            let value = disk
                .value
                .as_deref()
                .expect("a known disk total has a value");
            assert!(
                value.parse::<u64>().is_ok(),
                "the disk total is a byte count, got {value:?}"
            );
        }
        // The CPU model parses from "model name : ..." without the label
        // or the colon.
        if let Some(cpu) = facts
            .iter()
            .find(|fact| fact.namespace == "hardware" && fact.name == "cpu_model")
            .filter(|cpu| cpu.status == CapabilityStatus::Known)
        {
            let value = cpu.value.as_deref().expect("a known cpu model has a value");
            assert!(
                !value.contains("model name") && !value.starts_with(':'),
                "the cpu model is the bare string, got {value:?}"
            );
        }
    }

    #[test]
    fn the_bare_metal_none_output_is_a_known_fact() {
        // systemd-detect-virt exits 1 on bare metal but still prints
        // "none"; the text, not the exit status, is the answer.
        assert_eq!(
            virtualization_kind("none\n"),
            Some("none".to_owned()),
            "exit-1 bare metal is known, not unavailable"
        );
        assert_eq!(virtualization_kind("kvm\n"), Some("kvm".to_owned()));
        assert_eq!(virtualization_kind(""), None);
        assert_eq!(virtualization_kind("   \n"), None);
    }

    #[test]
    fn a_zero_or_malformed_df_total_is_not_a_fact() {
        let header = "Filesystem 1024-blocks Used Available Capacity Mounted on\n";
        assert_eq!(
            root_disk_total_bytes(&format!("{header}/dev/sda1 500000000 100 200 1% /")),
            Some(500_000_000 * 1024)
        );
        assert_eq!(
            root_disk_total_bytes(&format!("{header}/dev/sda1 0 0 0 0% /")),
            None
        );
        assert_eq!(
            root_disk_total_bytes(&format!("{header}/dev/sda1 junk 0 0 0% /")),
            None
        );
        assert_eq!(root_disk_total_bytes(""), None);
    }

    #[test]
    fn oversized_fact_values_are_bounded() {
        #[derive(Debug)]
        struct BigProbe;

        impl Probe for BigProbe {
            fn name(&self) -> &'static str {
                "big"
            }

            fn collect(&self) -> Result<Vec<CapabilityFact>, String> {
                Ok(vec![fact(
                    "big",
                    "value",
                    Some("x".repeat(MAX_FACT_VALUE_BYTES * 4)),
                )])
            }
        }
        let runner = ProbeRunner::new(vec![Arc::new(BigProbe)]);
        let collected = runner.collect(0);
        assert_eq!(collected.facts.len(), 1);
        assert_eq!(
            collected.facts[0].value.as_ref().map(String::len),
            Some(MAX_FACT_VALUE_BYTES)
        );
    }
}
