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
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

        // Step 1: fold the scheme case-insensitively to a canonical lowercase
        // form (or none), so dispatch below is case-insensitive by
        // construction.
        let (scheme, rest) = match raw.split_once("://") {
            Some((scheme, rest)) => {
                if !scheme.eq_ignore_ascii_case("https")
                    && !scheme.eq_ignore_ascii_case("http")
                    && !scheme.eq_ignore_ascii_case("ssh")
                    && !scheme.eq_ignore_ascii_case("git")
                {
                    return error("it carries an unrecognized scheme");
                }
                (Some(scheme), rest)
            }
            None => (None, raw),
        };

        // Step 2: split the authority (user@host[:port]) from the path, and
        // refuse credential-bearing userinfo. The standard `git@host`
        // spelling (user without a password separator) stays legal;
        // `user:pass@` is refused in every form.
        //
        // The scheme-less scp spelling (`git@host:path`) splits at the COLON
        // before the first slash, so it is handled before the generic
        // slash-split below.
        let (authority, path) = if scheme.is_none() {
            // The scp spelling's host/path separator is the colon AFTER the
            // userinfo: `user@host:path`. The authority ends at the LAST `@`
            // before the first `/` (credentials can contain `@` in the
            // password), so the host/path colon is found after it.
            let first_slash = rest.find('/');
            let authority_end = rest[..first_slash.unwrap_or(rest.len())]
                .rfind('@')
                .map_or(0, |at| at + 1);
            match rest[authority_end..].split_once(':') {
                Some((host, path)) => (&rest[..authority_end + host.len()], Some(path)),
                None => match rest.split_once('/') {
                    Some((authority, path)) => (authority, Some(path)),
                    None => return error("it carries no path separator"),
                },
            }
        } else {
            match rest.split_once('/') {
                Some((authority, path)) => (authority, Some(path)),
                None => return error("it carries no path after the host"),
            }
        };
        // On scheme-qualified https/http remotes, ANY userinfo is
        // credential-bearing (basic-auth user, token, or user:password).
        // On scheme-less/scp/ssh spellings, only `user:pass@` is a
        // credential — the bare `git@` user is a spelling.
        let credential_bearing = match scheme {
            Some(s) if s.eq_ignore_ascii_case("https") || s.eq_ignore_ascii_case("http") => {
                authority.contains('@')
            }
            Some(_) => {
                matches!(authority.rsplit_once('@'), Some((user, _)) if user.contains(':'))
            }
            None => matches!(authority.rsplit_once('@'), Some((user, _)) if user.contains(':')),
        };
        if credential_bearing {
            return error("it carries embedded credentials; use a remote without userinfo");
        }

        // Step 3: extract the host and path per spelling.
        let (host, path) = match scheme {
            // URL forms: `authority/path` — the authority is the host (with
            // an optional port), the path is what follows the first slash.
            Some(_) => {
                let Some(path) = path else {
                    return error("it carries no path after the host");
                };
                (authority, path)
            }
            // Scheme-less: scp-style `user@host:path` or bare `host/path`.
            // When the slash split set a path, it is used; the scp branch's
            // colon split set it too.
            None => match (authority.split_once(':'), path) {
                (Some((host, path)), _) => (host, path),
                (None, Some(path)) => (authority, path),
                (None, None) => return error("it carries no path separator"),
            },
        };

        if host.is_empty() || path.is_empty() {
            return error("the host or path is empty");
        }
        // A user segment without a colon (e.g. `git@host:path`) is a common
        // spelling, not a credential: fold it away.
        let host = host.rsplit('@').next().unwrap_or(host);
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
        if self.machine_id.is_empty() || self.machine_id.len() > 64 {
            return Err("the machine id must be 1..=64 characters".to_owned());
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
    fn scheme_case_is_folded_before_dispatch() {
        let upper =
            NormalizedRemote::parse("HTTPS://GitHub.com/Frogbyte-io/fleet-manager").unwrap();
        let lower =
            NormalizedRemote::parse("https://github.com/Frogbyte-io/fleet-manager").unwrap();
        assert_eq!(upper, lower, "an uppercase scheme is the same identity");
        let ssh =
            NormalizedRemote::parse("SSH://git@GitHub.com/Frogbyte-io/fleet-manager.git").unwrap();
        assert_eq!(ssh, lower, "an uppercase ssh scheme folds too");
    }

    #[test]
    fn credential_guards_cover_every_spelling() {
        let refused = [
            // https with password
            "https://user:password@github.com/Frogbyte-io/secret.git",
            // ssh URL with password
            "ssh://user:password@github.com/Frogbyte-io/secret.git",
            // scheme-less scp-style with password
            "user:password@github.com:Frogbyte-io/secret.git",
        ];
        for raw in refused {
            let error = NormalizedRemote::parse(raw).unwrap_err();
            assert!(
                error.contains("embedded credentials") || error.contains("unrecognized scheme"),
                "{raw:?} must be refused as credential-bearing: {error}"
            );
        }
    }

    #[test]
    fn machine_id_bounds_are_validated() {
        let fact = |machine_id: &str| CheckoutFact {
            project_id: "project-1".to_owned(),
            machine_id: machine_id.to_owned(),
            root: "/home/dev/code/x".to_owned(),
            branch: None,
            dirty: None,
            source: "agentless/1".to_owned(),
            observed_at: 0,
        };
        assert!(fact("machine-a").validate().is_ok());
        assert!(fact("").validate().is_err());
        assert!(fact(&"m".repeat(65)).validate().is_err());
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
