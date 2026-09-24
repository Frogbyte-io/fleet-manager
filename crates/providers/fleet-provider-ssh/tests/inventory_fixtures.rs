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
