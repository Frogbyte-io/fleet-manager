//! The project domain: stable identity over mutable facts (FM-300).
//!
//! A project's identity is its **normalized Git remote** — the same repository
//! reached through `https`, `ssh`, or scp-style syntax is one project, and the
//! normalization grammar makes that decision deterministic. Everything else
//! about where the project lives on a given machine (the checkout root, the
//! branch, whether the worktree is dirty) is an **observed fact** tied to that
//! machine and observation time, never part of the identity: a laptop going
//! offline does not unmake a project, and a checkout moving does not fork one.
//!
//! Remote normalization refuses credential-bearing material (`user:pass@host`)
//! rather than storing or stripping it: a remote with embedded secrets is a
//! malformed request, not a record with a secret in it.
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// A normalized Git remote: the project's stable identity.
///
/// The normalized form folds the common spellings of the same repository —
/// `https://host/path.git`, `ssh://git@host/path.git`, `git@host:path.git` —
/// to `host/path` with a lowercased host, a `.git` suffix stripped, and a
/// default-scheme marker. Ports are preserved. Credential-shaped userinfo is
/// refused, never stored.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct NormalizedRemote {
    /// The normalized remote, e.g. `github.com/Frogbyte-io/fleet-manager`.
    value: String,
}

impl NormalizedRemote {
    /// Parses and normalizes a Git remote URL.
    ///
    /// # Errors
    ///
    /// Returns a caller-safe detail when the remote is empty, oversized,
    /// credential-bearing, or carries no parseable host/path.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let error = |detail: &str| Err(format!("the remote is malformed: {detail}"));
        let raw = raw.trim();
        if raw.is_empty() {
            return error("it is empty");
        }
        if raw.len() > 512 {
            return error("it exceeds 512 characters");
        }
        // Credential-shaped userinfo (user:pass@host) is refused, never
        // stored or silently stripped: the remote belongs in the user's Git
        // config, not in Fleet's records with a secret inside it. A userinfo
        // segment on an https/http remote is always credential-bearing (the
        // scp spelling only appears scheme-less), so any `@` before the
        // first `/` of an https/http remote is refused.
        let (scheme_stripped, is_url) = match raw.split_once("://") {
            Some((scheme, rest)) => (
                rest,
                scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http"),
            ),
            None => (raw, false),
        };
        if is_url {
            let authority = scheme_stripped.split('/').next().unwrap_or_default();
            if authority.contains('@') {
                return error("it carries embedded credentials; use a remote without userinfo");
            }
        }

        // Fold the spellings: scp-style `git@host:path`, `ssh://…`,
        // `https://…`, and bare `host/path` all reduce to `host/path`.
        let (host_part, path) = if let Some(rest) = raw.strip_prefix("ssh://") {
            let rest = rest.strip_prefix("git@").unwrap_or(rest);
            match rest.split_once('/') {
                Some((host, path)) => (host, path),
                None => return error("it carries no path after the host"),
            }
        } else if let Some(rest) = raw
            .strip_prefix("https://")
            .or_else(|| raw.strip_prefix("http://"))
        {
            match rest.split_once('/') {
                Some((host, path)) => (host, path),
                None => return error("it carries no path after the host"),
            }
        } else if let Some((host, path)) = raw.split_once(':') {
            // scp-style `git@host:path` (or bare `host:path`).
            (host, path)
        } else {
            match raw.split_once('/') {
                Some((host, path)) => (host, path),
                None => return error("it carries no path separator"),
            }
        };

        if host_part.is_empty() || path.is_empty() {
            return error("the host or path is empty");
        }
        // A user segment without a colon (e.g. `git@host:path`) is a common
        // spelling, not a credential: fold it away.
        let host = host_part.rsplit('@').next().unwrap_or(host_part);
        if host.is_empty() {
            return error("the host is empty");
        }
        let host = host.to_ascii_lowercase();
        let mut path = path.trim_end_matches('/');
        // The `.git` suffix is a spelling convention, stripped
        // case-insensitively; the path's own case is preserved.
        if path.len() >= 4 {
            let (stem, suffix) = path.split_at(path.len() - 4);
            if suffix.eq_ignore_ascii_case(".git") {
                path = stem;
            }
        }
        let path = path.trim_end_matches('/');
        if path.is_empty() {
            return error("the path is empty after normalization");
        }
        if path.len() > 400 || host.len() > 253 {
            return error("the host or path exceeds the bounds");
        }
        for part in path.split('/') {
            for ch in part.chars() {
                if ch.is_whitespace() || ch == '\0' {
                    return error("the path carries whitespace or NUL");
                }
            }
        }
        Ok(Self {
            value: format!("{host}/{path}"),
        })
    }

    /// The normalized remote value, e.g. `github.com/Frogbyte-io/fleet-manager`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for NormalizedRemote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}

use std::fmt;

/// A project: stable identity (the normalized remote) plus mutable display
/// facts. Checkouts live in the per-machine observations, not here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    /// The project's identity.
    pub id: String,
    /// The normalized remote.
    pub remote: String,
    /// The mutable, unique display name.
    pub name: String,
    /// Operator notes.
    pub description: String,
    /// Creation time (epoch milliseconds).
    pub created_at: i64,
    /// Last mutation (epoch milliseconds).
    pub updated_at: i64,
}

/// One machine's observed checkout of a project: where it lives, what branch
/// it is on, and whether the worktree is dirty — as observed at a time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckoutFact {
    /// The project the checkout belongs to.
    pub project_id: String,
    /// The machine carrying the checkout.
    pub machine_id: String,
    /// The checkout's root path on that machine.
    pub root: String,
    /// The checked-out branch, when the observation could tell.
    pub branch: Option<String>,
    /// Whether the worktree had uncommitted changes at observation.
    pub dirty: Option<bool>,
    /// What observed it, e.g. `agentless/1`.
    pub source: String,
    /// When it was observed (epoch milliseconds).
    pub observed_at: i64,
}

impl CheckoutFact {
    /// Validates the observation's bounds: the root is absolute-shaped and
    /// bounded, the branch is bounded, and the source is present.
    ///
    /// # Errors
    ///
    /// Returns the malformed part when validation fails.
    pub fn validate(&self) -> Result<(), String> {
        if self.project_id.is_empty() || self.project_id.len() > 64 {
            return Err("the project id must be 1..=64 characters".to_owned());
        }
        if !self.root.starts_with('/') || self.root.len() > 400 {
            return Err(
                "the checkout root must be an absolute path of at most 400 characters".to_owned(),
            );
        }
        if let Some(branch) = &self.branch
            && (branch.is_empty() || branch.len() > 255)
        {
            return Err("the branch must be 1..=255 characters".to_owned());
        }
        if self.source.is_empty() || self.source.len() > 64 {
            return Err("the observation source must be 1..=64 characters".to_owned());
        }
        Ok(())
    }
}

/// A project as the read model displays it: the record plus its observed
/// checkouts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectView {
    /// The project's identity.
    pub id: String,
    /// The normalized remote.
    pub remote: String,
    /// The display name.
    pub name: String,
    /// Operator notes.
    pub description: String,
    /// The observed checkouts across machines, newest observation first.
    pub checkouts: Vec<CheckoutFact>,
    /// Creation time (epoch milliseconds).
    pub created_at: i64,
    /// Last mutation (epoch milliseconds).
    pub updated_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_folds_the_common_spellings() {
        let cases = [
            (
                "https://github.com/Frogbyte-io/fleet-manager.git",
                "github.com/Frogbyte-io/fleet-manager",
            ),
            (
                "https://github.com/Frogbyte-io/fleet-manager",
                "github.com/Frogbyte-io/fleet-manager",
            ),
            (
                "ssh://git@github.com/Frogbyte-io/fleet-manager.git",
                "github.com/Frogbyte-io/fleet-manager",
            ),
            (
                "git@github.com:Frogbyte-io/fleet-manager.git",
                "github.com/Frogbyte-io/fleet-manager",
            ),
            (
                "GitHub.com/Frogbyte-IO/Fleet-Manager.GIT",
                "github.com/Frogbyte-IO/Fleet-Manager",
            ),
            (
                "ssh://git@github.com:2222/Frogbyte-io/fleet-manager.git",
                "github.com:2222/Frogbyte-io/fleet-manager",
            ),
        ];
        for (raw, expected) in cases {
            let normalized = NormalizedRemote::parse(raw)
                .unwrap_or_else(|error| panic!("{raw:?} must normalize: {error}"));
            assert_eq!(normalized.as_str(), expected, "{raw:?}");
        }
    }

    #[test]
    fn distinct_repositories_normalize_distinctly() {
        let a =
            NormalizedRemote::parse("https://github.com/Frogbyte-io/fleet-manager.git").unwrap();
        let b = NormalizedRemote::parse("https://github.com/Frogbyte-io/other.git").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn credential_bearing_remotes_are_refused_not_stored() {
        let refused = [
            "https://user:password@github.com/Frogbyte-io/fleet-manager.git",
            "https://token@github.com/Frogbyte-io/fleet-manager.git",
        ];
        for raw in refused {
            let error = NormalizedRemote::parse(raw).unwrap_err();
            assert!(
                error.contains("embedded credentials"),
                "{raw:?} must be refused with the credential reason: {error}"
            );
        }
        // A user segment without a colon is the scp spelling, not a secret.
        let scp = NormalizedRemote::parse("git@github.com:Frogbyte-io/fleet-manager.git").unwrap();
        assert_eq!(
            scp.as_str(),
            "github.com/Frogbyte-io/fleet-manager",
            "scp-style user without a colon is a spelling, not a credential"
        );
    }

    #[test]
    fn malformed_remotes_are_refused_with_caller_safe_details() {
        let refused = [
            "",
            "   ",
            "https://",
            "https://host-only",
            "git@host-only:",
            "host",
            &format!("https://host/{}", "x".repeat(500)),
        ];
        for raw in refused {
            assert!(
                NormalizedRemote::parse(raw).is_err(),
                "{raw:?} must be refused"
            );
        }
    }
}
