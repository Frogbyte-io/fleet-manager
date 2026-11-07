//! Fixture tests for the probe's output protocol: sanitized streams per
//! OS shape, locale/spacing variance, partial-failure preservation, and the
//! unsupported-OS baseline with explicit gaps. Values are base64, so the
//! fixtures encode them the way the remote side does.

use base64::Engine as _;
use fleet_provider_ssh::{PROBE_SOURCE, parse_probe_output};
use std::time::{Duration, SystemTime};

fn value64(value: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
}

fn line(namespace: &str, name: &str, value: &str, status: &str, at: i64) -> String {
    format!(
        "{{\"namespace\":\"{namespace}\",\"name\":\"{name}\",\"value64\":\"{}\",\"status\":\"{status}\",\"at\":{at}}}",
        value64(value)
    )
}

#[test]
fn a_linux_baseline_parses_into_facts() {
    let stdout = [
        line("host", "architecture", "x86_64", "known", 1_000),
        line("os", "family", "Linux", "known", 1_000),
        line("os", "distribution", "ubuntu", "known", 1_000),
        line("os", "distribution_version", "24.04", "known", 1_000),
        line("host", "virtualization", "kvm", "known", 1_000),
        line(
            "hardware",
            "model",
            "Raspberry Pi 4 Model B",
            "known",
            1_000,
        ),
        line(
            "hardware",
            "cpu_model",
            "Intel(R) Xeon(R) CPU",
            "known",
            1_000,
        ),
        line("hardware", "disk_total_bytes", "1024", "known", 1_000),
        line("tool", "git", "git version 2.47.1", "known", 1_000),
        line("tool", "docker", "", "unavailable", 1_000),
    ]
    .join("\n");

    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
    let facts = parse_probe_output(&stdout, now);
    assert_eq!(facts.len(), 10);
    let family = facts.iter().find(|fact| fact.name == "family").unwrap();
    assert_eq!(family.value.as_deref(), Some("Linux"));
    assert_eq!(family.source, PROBE_SOURCE);
    assert_eq!(
        family.observed_at.unix_millis(),
        1_000,
        "the remote side's timestamp wins"
    );
    let docker = facts.iter().find(|fact| fact.name == "docker").unwrap();
    assert_eq!(docker.status, fleet_core::CapabilityStatus::Unavailable);
    assert_eq!(docker.value, None);
}

#[test]
fn hardware_facts_carry_honest_states() {
    // FM-914: virtualization, model, CPU model, and disk total parse with
    // their availability states intact — a VM, an SBC, bare metal, and a
    // host that cannot answer all stay distinct.
    let stdout = [
        line("host", "virtualization", "kvm", "known", 5_000),
        line(
            "hardware",
            "model",
            "Raspberry Pi 4 Model B",
            "known",
            5_000,
        ),
        line(
            "hardware",
            "cpu_model",
            "Intel(R) Core(TM) i7",
            "known",
            5_000,
        ),
        line(
            "hardware",
            "disk_total_bytes",
            "512110190592",
            "known",
            5_000,
        ),
        line("host", "virtualization", "", "unavailable", 5_000),
        line("hardware", "model", "", "unavailable", 5_000),
        line("hardware", "cpu_model", "", "unavailable", 5_000),
        line("hardware", "disk_total_bytes", "", "unavailable", 5_000),
    ]
    .join("\n");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
    let facts = parse_probe_output(&stdout, now);
    assert_eq!(facts.len(), 8);
    let virt = facts
        .iter()
        .find(|fact| fact.namespace == "host" && fact.name == "virtualization")
        .unwrap();
    assert_eq!(virt.value.as_deref(), Some("kvm"));
    let model = facts
        .iter()
        .find(|fact| fact.namespace == "hardware" && fact.name == "model")
        .unwrap();
    assert_eq!(model.value.as_deref(), Some("Raspberry Pi 4 Model B"));
    let cpu = facts
        .iter()
        .find(|fact| fact.namespace == "hardware" && fact.name == "cpu_model")
        .unwrap();
    assert_eq!(cpu.value.as_deref(), Some("Intel(R) Core(TM) i7"));
    let disk = facts
        .iter()
        .find(|fact| fact.namespace == "hardware" && fact.name == "disk_total_bytes")
        .unwrap();
    assert_eq!(disk.value.as_deref(), Some("512110190592"));
    // The four unavailable shapes stay honest: unavailable with no value,
    // visibly distinct from the known half of the stream.
    let unavailable = facts
        .iter()
        .filter(|fact| fact.status == fleet_core::CapabilityStatus::Unavailable)
        .count();
    assert_eq!(unavailable, 4, "the unavailable half of the stream");
    for fact in facts.iter().filter(|fact| {
        matches!(
            (fact.namespace.as_str(), fact.name.as_str()),
            ("host", "virtualization") | ("hardware", "model" | "cpu_model" | "disk_total_bytes")
        )
    }) {
        if fact.status == fleet_core::CapabilityStatus::Unavailable {
            assert_eq!(fact.value, None, "{fact:?} carries no invented value");
        }
    }
}

#[test]
fn locale_spacing_and_null_variance_stay_data() {
    // awk/locale noise: padding spaces, a version with an unexpected shape,
    // an empty string for an unprobeable value — none of it corrupts parsing.
    let stdout = [
        line("hardware", "cpu_cores", "  8  ", "known", 2_000),
        line(
            "os",
            "distribution_version",
            "24.04 LTS \"Noble\"",
            "known",
            2_000,
        ),
        line("network", "ipv4", "", "unknown", 2_000),
    ]
    .join("\n");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
    let facts = parse_probe_output(&stdout, now);
    assert_eq!(facts.len(), 3);
    let cores = facts.iter().find(|fact| fact.name == "cpu_cores").unwrap();
    assert_eq!(cores.value.as_deref(), Some("  8  "));
    let version = facts
        .iter()
        .find(|fact| fact.name == "distribution_version")
        .unwrap();
    assert_eq!(version.value.as_deref(), Some("24.04 LTS \"Noble\""));
}

#[test]
fn partial_failure_preserves_the_other_facts() {
    let stdout = [
        line("os", "family", "Linux", "known", 3_000),
        // A probe died mid-JSON: one truncated line, then the stream
        // continues.
        r#"{"namespace":"host","name":"hostname","value64":"x"#.to_owned(),
        line("hardware", "cpu_cores", "4", "known", 3_000),
    ]
    .join("\n");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
    let facts = parse_probe_output(&stdout, now);
    assert_eq!(facts.len(), 2, "the malformed line is skipped, not fatal");
    assert!(facts.iter().any(|fact| fact.name == "cpu_cores"));
}

#[test]
fn malformed_status_or_timestamps_are_skipped() {
    let stdout = [
        line("os", "family", "Linux", "known", 1_000),
        // An invented status is not one of the honest four.
        format!(
            "{{\"namespace\":\"tool\",\"name\":\"git\",\"value64\":\"{}\",\"status\":\"excellent\",\"at\":1000}}",
            value64("git version 2")
        ),
        // A timestamp in the future is replaced, not trusted.
        line("os", "kernel", "6.1.0", "known", i64::MAX / 2),
    ]
    .join("\n");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
    let facts = parse_probe_output(&stdout, now);
    assert_eq!(facts.len(), 2, "the invented status is rejected");
    let kernel = facts.iter().find(|fact| fact.name == "kernel").unwrap();
    assert_eq!(kernel.status, fleet_core::CapabilityStatus::Known);
    let _ = std::time::SystemTime::now();
}

#[test]
fn an_unsupported_os_keeps_its_baseline_with_explicit_gaps() {
    let stdout = [
        line("host", "architecture", "arm64", "known", 4_000),
        line("os", "family", "Darwin", "known", 4_000),
        line("os", "distribution", "", "unknown", 4_000),
        line("tool", "git", "", "unknown", 4_000),
        line("tool", "docker", "", "unknown", 4_000),
    ]
    .join("\n");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
    let facts = parse_probe_output(&stdout, now);
    // The baseline facts stand; the skipped tool set is explicitly unknown,
    // which is visibly different from "the machine says it is missing".
    let git = facts.iter().find(|fact| fact.name == "git").unwrap();
    assert_eq!(git.status, fleet_core::CapabilityStatus::Unknown);
    let arch = facts
        .iter()
        .find(|fact| fact.name == "architecture")
        .unwrap();
    assert_eq!(arch.status, fleet_core::CapabilityStatus::Known);
}

#[test]
fn malformed_namespaces_fail_validation_not_parsing() {
    let stdout = format!(
        "{{\"namespace\":\"Os\",\"name\":\"family\",\"value64\":\"{}\",\"status\":\"known\",\"at\":1000}}\n{}\n",
        value64("Linux"),
        line("os", "family", "Linux", "known", 1_000)
    );
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
    let facts = parse_probe_output(&stdout, now);
    assert_eq!(facts.len(), 1, "the malformed namespace fails validation");
}

#[test]
fn a_tool_reports_its_version_as_a_separate_fact() {
    // FM-304: presence and version are separate facts; a present tool
    // that does not answer --version stays known with an absent version.
    let stdout = [
        line("tool", "git", "", "known", 1_000),
        line("tool-version", "git", "git version 2.47.1", "known", 1_000),
        line("tool", "docker", "", "unavailable", 1_000),
        line("tool", "mysterious-agent", "", "known", 1_000),
    ]
    .join("\n");

    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
    let facts = parse_probe_output(&stdout, now);
    let git = facts.iter().find(|fact| fact.name == "git").unwrap();
    assert_eq!(git.status, fleet_core::CapabilityStatus::Known);
    let git_version = facts
        .iter()
        .find(|fact| fact.namespace == "tool-version" && fact.name == "git")
        .unwrap();
    assert_eq!(git_version.value.as_deref(), Some("git version 2.47.1"));
    let mysterious = facts
        .iter()
        .find(|fact| fact.name == "mysterious-agent")
        .unwrap();
    assert_eq!(mysterious.status, fleet_core::CapabilityStatus::Known);
    assert_eq!(mysterious.value, None, "no version is an honest gap");
    // The version surface is the separate namespace: a tool whose version
    // probe failed has no version fact at all.
    assert!(
        !facts
            .iter()
            .any(|fact| { fact.namespace == "tool-version" && fact.name == "mysterious-agent" }),
        "a version-less tool has no version fact"
    );
    assert!(
        !facts
            .iter()
            .any(|fact| fact.namespace == "tool-version" && fact.name == "docker"),
        "an unavailable tool has no version fact"
    );
}

/// A sanitized Windows probe stream (ADR 0021): the shared fact set plus the
/// release, edition, session and shell facts. Placeholder values only.
fn windows_stream(release: &str, edition: &str, architecture: &str, admin: &str) -> String {
    [
        line("host", "architecture", architecture, "known", 7_000),
        line("host", "hostname", "WORKSTATION-01", "known", 7_000),
        line("os", "kernel", "10.0.22631", "known", 7_000),
        line("os", "family", "Windows", "known", 7_000),
        line("os", "distribution", "windows", "known", 7_000),
        line("os", "windows_release", release, "known", 7_000),
        line("os", "distribution_version", release, "known", 7_000),
        line(
            "os",
            "product_name",
            "Microsoft Windows 11 Pro",
            "known",
            7_000,
        ),
        line("os", "product_type", "workstation", "known", 7_000),
        line("os", "edition", edition, "known", 7_000),
        line("os", "display_version", "23H2", "known", 7_000),
        line("os", "build", "22631.4460", "known", 7_000),
        line("session", "user", "developer", "known", 7_000),
        line("session", "administrator", admin, "known", 7_000),
        line(
            "shell",
            "powershell_version",
            "5.1.22621.4391",
            "known",
            7_000,
        ),
        line("shell", "language_mode", "FullLanguage", "known", 7_000),
        line(
            "shell",
            "default_shell",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "known",
            7_000,
        ),
        line("tool", "git", "", "known", 7_000),
        line(
            "tool-version",
            "git",
            "git version 2.47.1.windows.1",
            "known",
            7_000,
        ),
        line("tool", "claude", "", "known", 7_000),
        line("tool-version", "claude", "", "known", 7_000),
        line("tool", "docker", "", "unavailable", 7_000),
        line("tool", "skills-manager-cli", "", "unavailable", 7_000),
    ]
    .join("\r\n")
}

fn value_of<'a>(facts: &'a [fleet_core::CapabilityFact], namespace: &str, name: &str) -> &'a str {
    facts
        .iter()
        .find(|fact| fact.namespace == namespace && fact.name == name)
        .and_then(|fact| fact.value.as_deref())
        .unwrap_or_else(|| panic!("no {namespace}/{name}"))
}

#[test]
fn a_windows_11_workstation_parses_into_facts_and_is_supported() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
    let stdout = windows_stream("11", "Professional", "x86_64", "false");
    let facts = parse_probe_output(&stdout, now);
    // Every line parses (CRLF included), plus the derived support tier.
    assert_eq!(facts.len(), stdout.lines().count() + 1);
    assert_eq!(value_of(&facts, "os", "family"), "Windows");
    assert_eq!(value_of(&facts, "os", "windows_release"), "11");
    assert_eq!(value_of(&facts, "os", "edition"), "Professional");
    assert_eq!(value_of(&facts, "host", "architecture"), "x86_64");
    assert_eq!(value_of(&facts, "host", "hostname"), "WORKSTATION-01");
    assert_eq!(value_of(&facts, "session", "user"), "developer");
    assert_eq!(value_of(&facts, "session", "administrator"), "false");
    assert_eq!(value_of(&facts, "shell", "language_mode"), "FullLanguage");
    assert_eq!(
        value_of(&facts, "tool-version", "git"),
        "git version 2.47.1.windows.1"
    );
    assert_eq!(value_of(&facts, "os", "support"), "supported");
    let docker = facts.iter().find(|fact| fact.name == "docker").unwrap();
    assert_eq!(docker.status, fleet_core::CapabilityStatus::Unavailable);
}

#[test]
fn windows_10_home_and_arm64_are_flagged_untested_not_refused() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
    for (release, edition, architecture) in [
        ("10", "Professional", "x86_64"),
        ("11", "Core", "x86_64"),
        ("11", "Enterprise", "aarch64"),
    ] {
        let facts =
            parse_probe_output(&windows_stream(release, edition, architecture, "true"), now);
        assert_eq!(
            value_of(&facts, "os", "support"),
            "untested",
            "{release} {edition} {architecture}"
        );
        // An administrator session is reported, as a fact, not a refusal.
        assert_eq!(value_of(&facts, "session", "administrator"), "true");
    }
}

#[test]
fn no_support_tier_is_invented_without_a_windows_release() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
    // A Linux stream, and a Windows stream whose release query failed.
    let linux = line("os", "family", "Linux", "known", 1_000);
    let windows = [
        line("os", "family", "Windows", "known", 1_000),
        line("os", "windows_release", "", "unavailable", 1_000),
    ]
    .join("\n");
    for stdout in [linux, windows] {
        let facts = parse_probe_output(&stdout, now);
        assert!(facts.iter().all(|fact| fact.name != "support"), "{facts:?}");
    }
}
