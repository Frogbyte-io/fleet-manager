//! The agentless checkout discovery probe (FM-301): one read-only script,
//! one set of checkout observations.
//!
//! The probe rides the same bounded transport as the inventory probe (see
//! the execution module's transport rule — caller data never passes through
//! a remote shell), and its output protocol is the same hostile-value-safe
//! shape: each observation is one JSON line whose every value is
//! base64-encoded by the remote side. The remote side never emits anything
//! but these lines.
//!
//! Discovery is deliberately shallow and bounded: it scans a fixed list of
//! standard roots with a depth-capped `find` for `.git` directories, and for
//! each candidate reads only what `git` can answer without network access —
//! the HEAD branch, the HEAD commit, whether the worktree is dirty, and the
//! origin remote URL. Git hooks are never run by discovery (`git` is invoked
//! with `-c core.hooksPath=` pointing nowhere), because hook execution is
//! remote code execution by another name.
//!
//! Honesty about absence: a directory whose facts cannot be read reports
//! `unavailable` (the machine answered: the checkout is unreadable); a scan
//! that could not run at all reports nothing — the transport error carries
//! that truth. Hostile values (ANSI escapes, prompt strings, control
//! characters) survive as opaque base64 on the wire and are bounded on
//! decode; a fact that exceeds its bound is dropped, not truncated into a
//! lie.
#![warn(missing_docs)]

use std::time::Duration;

use base64::Engine as _;

use crate::{ExecutionLimiter, SshConnectionSpec, SshProvider, SshProviderError, execute_script};

/// What observed the checkouts: a probe name and version, recorded on every
/// observation.
pub const DISCOVERY_SOURCE: &str = "checkout-discovery/1";

/// How long the discovery script may run before the deadline kills it.
pub const DISCOVERY_DEADLINE: Duration = Duration::from_secs(120);

/// The bound for one decoded checkout root path.
pub const MAX_ROOT_BYTES: usize = 400;

/// The bound for one decoded remote URL or branch name.
pub const MAX_FIELD_BYTES: usize = 1024;

/// The most checkouts one scan may report; a machine with more has a deeper
/// problem than discovery.
pub const MAX_CHECKOUTS: usize = 256;

/// The fixed discovery script. Roots are fixed here, owned by this crate —
/// caller data never rides the script. Values are base64'd on the remote
/// side (`base64 -w0`), so the JSON stays one clean line per checkout.
#[must_use]
pub fn discovery_script() -> String {
    r#"fleet_t=$(date +%s%3N 2>/dev/null) || fleet_t=0
fleet_emit() {
  # root64 branch64 head64 dirty remote64 status
  printf '{"root64":"%s","branch64":"%s","head64":"%s","dirty":"%s","remote64":"%s","status":"%s","at":%s}\n' "$1" "$2" "$3" "$4" "$5" "$6" "$fleet_t"
}
fleet_b64() { printf '%s' "$1" | base64 -w0; }
# Reads one checkout's facts without network access and without running any
# hook. Every emission is independent: one unreadable checkout never loses
# the others.
fleet_read() {
  fleet_root=$1
  fleet_branch=$(git -C "$fleet_root" -c core.hooksPath=/nonexistent-fleet-hooks rev-parse --abbrev-ref HEAD 2>/dev/null | head -n 1)
  fleet_head=$(git -C "$fleet_root" -c core.hooksPath=/nonexistent-fleet-hooks rev-parse HEAD 2>/dev/null | head -n 1)
  if [ -z "$fleet_branch" ] || [ -z "$fleet_head" ]; then
    fleet_emit "$(fleet_b64 "$fleet_root")" "" "" unknown "" unavailable
    return 0
  fi
  if [ -n "$(git -C "$fleet_root" -c core.hooksPath=/nonexistent-fleet-hooks status --porcelain 2>/dev/null | head -n 1)" ]; then
    fleet_dirty=true
  else
    fleet_dirty=false
  fi
  fleet_remote=$(git -C "$fleet_root" -c core.hooksPath=/nonexistent-fleet-hooks remote get-url origin 2>/dev/null | head -n 1)
  fleet_emit "$(fleet_b64 "$fleet_root")" \
    "$(fleet_b64 "$fleet_branch")" "$(fleet_b64 "$fleet_head")" \
    "$fleet_dirty" "$(fleet_b64 "$fleet_remote")" known
}

# The scan itself: fixed roots, bounded depth, one fact per checkout. The
# roots are literals owned by this crate; nothing the caller controls is
# interpolated here.
for fleet_root in "$HOME" "$HOME/src" "$HOME/code" "$HOME/work" \
                  "$HOME/projects" "$HOME/dev" "${XDG_DATA_HOME:-$HOME/.local/share}/fleet"; do
  [ -d "$fleet_root" ] || continue
  find "$fleet_root" -maxdepth 4 -name .git -type d -print0 2>/dev/null |
    while IFS= read -r -d '' fleet_gitdir; do
      fleet_read "${fleet_gitdir%/.git}"
    done
done
"#
    .to_owned()
}

/// One discovered checkout observation, decoded and bounded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredCheckout {
    /// The checkout's root path on the machine.
    pub root: String,
    /// The checked-out branch, when the checkout could say.
    pub branch: Option<String>,
    /// The HEAD commit, when the checkout could say.
    pub head: Option<String>,
    /// Whether the worktree had uncommitted changes, when observable.
    pub dirty: Option<bool>,
    /// The origin remote URL, when one is configured.
    pub remote: Option<String>,
    /// Whether the observation is complete (`known`) or the checkout was
    /// unreadable (`unavailable`).
    pub status: String,
}

/// Runs the discovery probe over a verified endpoint and returns its
/// observations.
///
/// # Errors
///
/// Fails on transport errors; per-checkout gaps are observations, not
/// errors.
pub fn discover(
    provider: &SshProvider,
    limiter: &ExecutionLimiter,
    endpoint: &SshConnectionSpec,
    deadline: Duration,
) -> Result<Vec<DiscoveredCheckout>, SshProviderError> {
    let result = execute_script(
        provider,
        limiter,
        endpoint,
        &discovery_script(),
        &crate::ScriptMetadata::default(),
        deadline,
    )?;
    if result.killed_by_deadline {
        return Err(SshProviderError::Tool {
            tool: "ssh",
            detail: "the discovery scan was killed at its deadline; the checkout set is incomplete"
                .to_owned(),
        });
    }
    Ok(parse_discovery_output(&result.stdout))
}

/// Parses the discovery script's JSON-line stream into bounded observations.
/// Malformed lines are skipped, never fatal; over-bound values drop the
/// observation rather than truncate it into a lie.
#[must_use]
pub fn parse_discovery_output(stdout: &str) -> Vec<DiscoveredCheckout> {
    let mut found = Vec::new();
    for line in stdout.lines() {
        if found.len() >= MAX_CHECKOUTS {
            break;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(status) = value["status"].as_str() else {
            continue;
        };
        if status != "known" && status != "unavailable" {
            continue;
        }
        let Some(root) = decode_field(&value["root64"], MAX_ROOT_BYTES) else {
            continue;
        };
        if status == "unavailable" {
            found.push(DiscoveredCheckout {
                root,
                branch: None,
                head: None,
                dirty: None,
                remote: None,
                status: status.to_owned(),
            });
            continue;
        }
        let Some(branch) = decode_field(&value["branch64"], MAX_FIELD_BYTES) else {
            continue;
        };
        let Some(head) = decode_field(&value["head64"], MAX_FIELD_BYTES) else {
            continue;
        };
        let Some(dirty) = value["dirty"].as_str().and_then(|flag| match flag {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }) else {
            continue;
        };
        found.push(DiscoveredCheckout {
            root,
            branch: Some(branch),
            head: Some(head),
            dirty: Some(dirty),
            remote: decode_field(&value["remote64"], MAX_FIELD_BYTES),
            status: status.to_owned(),
        });
    }
    found
}

/// Decodes one base64 field with its bound; an over-bound or malformed
/// field is `None`, and the caller drops the observation.
fn decode_field(raw: &serde_json::Value, bound: usize) -> Option<String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw.as_str()?.as_bytes())
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())?;
    if decoded.is_empty() || decoded.len() > bound {
        return None;
    }
    Some(decoded)
}
