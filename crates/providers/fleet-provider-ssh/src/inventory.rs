//! The agentless inventory probe: one read-only script, one capability set.
//!
//! The probe runs over the same bounded transport as any remote script (see
//! the execution module's transport rule — caller data never passes through a
//! remote shell), and its output protocol is designed for hostile values:
//! each fact is one JSON line whose value is base64-encoded by the remote
//! side, so versions with quotes, spaces, or newlines cannot corrupt the
//! stream. The remote side never emits anything but these lines.
//!
//! The fact set is deliberately read-only and bounded: OS, kernel,
//! architecture, hostname, CPU/RAM/disk sizes, the primary IPv4, and the
//! presence/version of the tools the plan names — Git, Docker, Tailscale,
//! mise, Skills Manager, Frogenv, and the major coding agents. Nothing is
//! installed, updated, or recursively scanned here; that is later work.
//!
//! Honesty about absence: a tool that is missing reports `unavailable` (the
//! machine answered: it is not there); a probe that could not run reports
//! `unknown` (no probe ever answered); an unsupported OS keeps its raw
//! baseline facts and marks the skipped tool set `unknown` — explicit gaps,
//! not invented ones. A probe whose command fails mid-run never loses the
//! other facts: every emission is independent, and the parser skips
//! malformed lines rather than abandoning the collection.
#![warn(missing_docs)]

use std::time::{Duration, SystemTime};

use base64::Engine as _;

use crate::{ExecutionLimiter, SshConnectionSpec, SshProvider, SshProviderError, execute_script};

/// What observed the facts: a probe name and version, recorded on every fact.
pub const PROBE_SOURCE: &str = "agentless/1";

/// How long the collection script may run before the deadline kills it.
pub const COLLECTION_DEADLINE: Duration = Duration::from_secs(120);

/// The fixed probe script. Values are base64'd on the remote side
/// (`base64 -w0`), so the JSON stays one clean line per fact.
#[must_use]
pub fn probe_script() -> String {
    r#"fleet_t=$(date +%s%3N 2>/dev/null) || fleet_t=0
fleet_emit() {
  # namespace name value64 status
  printf '{"namespace":"%s","name":"%s","value64":"%s","status":"%s","at":%s}\n' "$1" "$2" "$3" "$4" "$fleet_t"
}
fleet_value64() { printf '%s' "$("$1" 2>/dev/null | head -n 1)" | base64 -w0; }
fleet_tool() {
  # name: present-and-versioned, or the honest gap
  if command -v "$1" >/dev/null 2>&1; then
    fleet_emit tool "$1" "$(fleet_value64 "$1")" known
  else
    fleet_emit tool "$1" "" unavailable
  fi
}
fleet_guard() {
  # command-if-present, value64, name, namespace: emit known or unavailable
  if command -v "$1" >/dev/null 2>&1; then
    fleet_emit "$4" "$3" "$2" known
  else
    fleet_emit "$4" "$3" "" unavailable
  fi
}

fleet_emit host architecture "$(printf '%s' "$(uname -m 2>/dev/null)" | base64 -w0)" known
fleet_emit host hostname "$(printf '%s' "$(hostname 2>/dev/null)" | base64 -w0)" known
fleet_emit os kernel "$(printf '%s' "$(uname -r 2>/dev/null)" | base64 -w0)" known
fleet_family=$(uname -s 2>/dev/null)
fleet_emit os family "$(printf '%s' "$fleet_family" | base64 -w0)" known

if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release 2>/dev/null
  fleet_emit os distribution "$(printf '%s' "${ID:-}" | base64 -w0)" known
  fleet_emit os distribution_version "$(printf '%s' "${VERSION_ID:-}" | base64 -w0)" known
else
  fleet_emit os distribution "" unknown
  fleet_emit os distribution_version "" unknown
fi

fleet_guard nproc "$(printf '%s' "$(nproc 2>/dev/null)" | tr -d '[:space:]' | base64 -w0)" cpu_cores hardware
if grep -q MemTotal /proc/meminfo 2>/dev/null; then
  fleet_emit hardware memory_bytes "$(printf '%s' "$(grep MemTotal /proc/meminfo | awk '{print $2 * 1024}')" | base64 -w0)" known
else
  fleet_emit hardware memory_bytes "" unavailable
fi
if command -v df >/dev/null 2>&1; then
  fleet_emit hardware disk_free_bytes "$(printf '%s' "$(df -kP / 2>/dev/null | tail -n 1 | awk '{print $4 * 1024}')" | base64 -w0)" known
else
  fleet_emit hardware disk_free_bytes "" unavailable
fi
if hostname -I >/dev/null 2>&1; then
  fleet_emit network ipv4 "$(printf '%s' "$(hostname -I 2>/dev/null | awk '{print $1}')" | base64 -w0)" known
else
  fleet_emit network ipv4 "" unknown
fi

# Tools the plan names; on an unsupported OS the set is skipped explicitly,
# recorded as unknown rather than pretended-missing.
if [ "$fleet_family" = "Linux" ]; then
  fleet_tool git
  fleet_tool docker
  fleet_tool tailscale
  fleet_tool mise
  fleet_tool frogenv
  fleet_tool skills-manager-cli
  fleet_tool claude
  fleet_tool codex
else
  for skipped in git docker tailscale mise frogenv skills-manager-cli claude codex; do
    fleet_emit tool "$skipped" "" unknown
  done
fi
"#
    .to_owned()
}

/// Runs the probe over a verified endpoint and returns its facts.
///
/// # Errors
///
/// Fails on transport errors; probe-level gaps are facts, not errors.
pub fn collect(
    provider: &SshProvider,
    limiter: &ExecutionLimiter,
    endpoint: &SshConnectionSpec,
    deadline: Duration,
) -> Result<Vec<fleet_core::CapabilityFact>, SshProviderError> {
    let result = execute_script(
        provider,
        limiter,
        endpoint,
        &probe_script(),
        &crate::ScriptMetadata::default(),
        deadline,
    )?;
    if result.killed_by_deadline {
        return Err(SshProviderError::Tool {
            tool: "ssh",
            detail: "the collection was killed at its deadline; the fact set is incomplete"
                .to_owned(),
        });
    }
    let mut facts = parse_probe_output(&result.stdout, SystemTime::now());
    for fact in &mut facts {
        PROBE_SOURCE.clone_into(&mut fact.source);
    }
    Ok(facts)
}

/// Parses the probe's JSON-line stream into facts. Malformed lines are
/// skipped, never fatal: partial failure must preserve the other facts.
#[must_use]
pub fn parse_probe_output(
    stdout: &str,
    now: std::time::SystemTime,
) -> Vec<fleet_core::CapabilityFact> {
    use fleet_core::{CapabilityFact, CapabilityStatus, Timestamp};
    let now_ms = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let mut facts = Vec::new();
    for line in stdout.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(namespace) = value["namespace"].as_str() else {
            continue;
        };
        let Some(name) = value["name"].as_str() else {
            continue;
        };
        let Some(status_id) = value["status"].as_str() else {
            continue;
        };
        let Some(at) = value["at"].as_i64() else {
            continue;
        };
        let Some(status) = CapabilityStatus::from_id(status_id) else {
            continue;
        };
        // A value may be empty (absence); base64 keeps hostile text data.
        let value64 = value["value64"].as_str().unwrap_or_default();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value64.as_bytes())
            .ok()
            .map(|raw| String::from_utf8_lossy(&raw).into_owned())
            .filter(|decoded| !decoded.is_empty());

        let observed_at = if at > 0 && at <= i64::try_from(now_ms).unwrap_or(i64::MAX) {
            Timestamp::from_unix_millis(at)
        } else {
            Timestamp::from_unix_millis(i64::try_from(now_ms).unwrap_or(i64::MAX))
        };

        let fact = CapabilityFact {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            value: decoded,
            status,
            observed_at,
            source: PROBE_SOURCE.to_owned(),
        };
        if fact.validate().is_ok() {
            facts.push(fact);
        }
    }
    facts
}
