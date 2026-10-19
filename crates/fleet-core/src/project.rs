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
        Self::parse_inner(raw, false).map(|(identity, _)| identity)
    }

    /// Parses a Git remote into its identity and its fetch form.
    ///
    /// The identity is what [`NormalizedRemote::parse`] returns. The
    /// [`RemoteFetch`] records how the remote was spelled so a clone can
    /// reach it again: `https`, `http`, `ssh://` (with its login user), or
    /// scp-style `user@host:path`. A `git://` remote folds to `https`: the
    /// unauthenticated Git protocol is never used to fetch. A scheme-less
    /// remote with no user (`host/path`) is `https`. Credential-shaped
    /// userinfo is refused, so the form can never carry a secret.
    ///
    /// # Errors
    ///
    /// The same refusals as [`NormalizedRemote::parse`], plus a login user
    /// that is not a plain login name.
    pub fn parse_with_fetch(raw: &str) -> Result<(Self, RemoteFetch), String> {
        Self::parse_inner(raw, true)
    }

    /// The shared parser. `strict` adds the checks a remote must pass to be
    /// fetched (a plain login name, a host that cannot read as an option,
    /// a numeric port); identity-only callers (`parse`) accept what they
    /// always accepted, so matching an observed checkout never starts
    /// failing.
    fn parse_inner(raw: &str, strict: bool) -> Result<(Self, RemoteFetch), String> {
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
        let fetch = match fetch_form(scheme, authority, strict) {
            Ok(fetch) => fetch,
            Err(detail) => return error(detail),
        };

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
        if strict && !fetchable_host(&host) {
            return error("the host cannot be fetched from (an option-like or non-numeric port)");
        }
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
        if let Err(detail) = check_bounds(&host, path) {
            return error(detail);
        }
        Ok((
            Self {
                value: format!("{host}/{path}"),
            },
            fetch,
        ))
    }

    /// The normalized remote value, e.g. `github.com/Frogbyte-io/fleet-manager`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// The URL a `git clone` can fetch: the identity (`host[:port]/path`)
    /// in the spelling `fetch` records.
    ///
    /// The identity drops the scheme and an scp-style user, so it is not a
    /// fetchable address; git would read it as a local path. No credential
    /// can appear, because credential-shaped userinfo is refused at parse
    /// time and the user is a validated login name.
    #[must_use]
    pub fn clone_url(&self, fetch: &RemoteFetch) -> String {
        let user = fetch
            .user
            .as_deref()
            .map(|user| format!("{user}@"))
            .unwrap_or_default();
        match fetch.scheme {
            FetchScheme::Https => format!("https://{}", self.value),
            FetchScheme::Http => format!("http://{}", self.value),
            FetchScheme::Ssh => format!("ssh://{user}{}", self.value),
            FetchScheme::Scp => match self.value.split_once('/') {
                Some((host, path)) => format!("{user}{host}:{path}"),
                None => format!("https://{}", self.value),
            },
        }
    }
}

/// How a project's remote is fetched.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FetchScheme {
    /// `https://host[:port]/path`.
    #[default]
    Https,
    /// `http://host[:port]/path`.
    Http,
    /// `ssh://[user@]host[:port]/path`.
    Ssh,
    /// scp-style `user@host:path`.
    Scp,
}

impl FetchScheme {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http => "http",
            Self::Ssh => "ssh",
            Self::Scp => "scp",
        }
    }

    /// Reads the stored spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "https" => Some(Self::Https),
            "http" => Some(Self::Http),
            "ssh" => Some(Self::Ssh),
            "scp" => Some(Self::Scp),
            _ => None,
        }
    }
}

/// The fetch form of a project's remote: the scheme and, for ssh, the login
/// user. Never a credential. The default is `https` with no user, which is
/// what every project registered before the form was stored uses.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteFetch {
    /// How the remote is reached.
    #[serde(default)]
    pub scheme: FetchScheme,
    /// The ssh login user (`git` in `git@host:path`); `None` for http(s).
    #[serde(default)]
    pub user: Option<String>,
}

/// The size and character bounds of a normalized host and path.
fn check_bounds(host: &str, path: &str) -> Result<(), &'static str> {
    if path.len() > 400 || host.len() > 253 {
        return Err("the host or path exceeds the bounds");
    }
    if path.chars().any(|ch| ch.is_whitespace() || ch == '\0') {
        return Err("the path carries whitespace or NUL");
    }
    Ok(())
}

/// The fetch form a remote's scheme and authority spell. The credential
/// check has already run, so any `user` here has no password part.
fn fetch_form(
    scheme: Option<&str>,
    authority: &str,
    strict: bool,
) -> Result<RemoteFetch, &'static str> {
    let user = authority.rsplit_once('@').map(|(user, _)| user.to_owned());
    let scheme = match scheme {
        Some(s) if s.eq_ignore_ascii_case("http") => FetchScheme::Http,
        Some(s) if s.eq_ignore_ascii_case("ssh") => FetchScheme::Ssh,
        None if user.is_some() => FetchScheme::Scp,
        // https, a bare `host/path`, and `git://` (unauthenticated and
        // unencrypted, so never used to fetch).
        Some(_) | None => FetchScheme::Https,
    };
    let user = match scheme {
        FetchScheme::Ssh | FetchScheme::Scp => user,
        FetchScheme::Https | FetchScheme::Http => None,
    };
    if user.as_deref().is_some_and(|user| !valid_login(user)) {
        if strict {
            return Err("the login user is not a plain login name");
        }
        return Ok(RemoteFetch::default());
    }
    Ok(RemoteFetch { scheme, user })
}

/// Whether a normalized `host[:port]` is safe to hand to git: no leading
/// dash (an option), no whitespace or control characters, and a port, when
/// present, of one to five digits.
fn fetchable_host(host: &str) -> bool {
    if host.starts_with('-') || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    match host.rsplit_once(':') {
        Some((_, port)) => {
            (1..=5).contains(&port.len()) && port.chars().all(|c| c.is_ascii_digit())
        }
        None => true,
    }
}

impl RemoteFetch {
    /// Checks a form that did not come from [`NormalizedRemote::parse_with_fetch`]
    /// (an operation payload, a stored row): a user belongs only to ssh and
    /// scp and must be a plain login name, and scp needs one.
    ///
    /// # Errors
    ///
    /// Returns a caller-safe detail when the form is not one the parser
    /// could have produced.
    pub fn validate(&self) -> Result<(), &'static str> {
        match (self.scheme, self.user.as_deref()) {
            (FetchScheme::Https | FetchScheme::Http, Some(_)) => {
                Err("an http(s) fetch form carries no user")
            }
            (FetchScheme::Scp, None) => Err("an scp fetch form needs a login user"),
            (FetchScheme::Ssh | FetchScheme::Scp, Some(user)) if !valid_login(user) => {
                Err("the login user is not a plain login name")
            }
            (FetchScheme::Https | FetchScheme::Http, None)
            | (FetchScheme::Ssh | FetchScheme::Scp, _) => Ok(()),
        }
    }
}

/// A plain login name: at most 32 of `[A-Za-z0-9._-]`, starting
/// alphanumeric, so it can neither carry a credential nor be read as an
/// option.
fn valid_login(user: &str) -> bool {
    user.len() <= 32
        && user
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
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
    /// How the remote is fetched (scheme and ssh user, never a credential).
    #[serde(default)]
    pub fetch: RemoteFetch,
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
    /// How the remote is fetched.
    #[serde(default)]
    pub fetch: RemoteFetch,
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

    fn clone_url_of(raw: &str) -> String {
        let (identity, fetch) = NormalizedRemote::parse_with_fetch(raw)
            .unwrap_or_else(|error| panic!("{raw:?} must parse: {error}"));
        identity.clone_url(&fetch)
    }

    #[test]
    fn clone_url_keeps_the_spelling_the_remote_was_registered_with() {
        for (raw, expected) in [
            (
                "https://github.com/Frogbyte-io/fleet-manager.git",
                "https://github.com/Frogbyte-io/fleet-manager",
            ),
            (
                "git@github.com:Frogbyte-io/fleet-manager.git",
                "git@github.com:Frogbyte-io/fleet-manager",
            ),
            (
                "ssh://git@GitHub.com/Frogbyte-io/fleet-manager",
                "ssh://git@github.com/Frogbyte-io/fleet-manager",
            ),
            (
                "ssh://git@git.example.test:2222/a/b.git",
                "ssh://git@git.example.test:2222/a/b",
            ),
            ("ssh://git.example.test/a/b", "ssh://git.example.test/a/b"),
            (
                "http://git.example.test:3000/a/b.git",
                "http://git.example.test:3000/a/b",
            ),
            (
                "https://git.example.test:8443/a/b.git",
                "https://git.example.test:8443/a/b",
            ),
            // Bare and `git://` spellings stay https.
            (
                "github.com/Frogbyte-io/fleet-manager",
                "https://github.com/Frogbyte-io/fleet-manager",
            ),
            ("git://git.example.test/a/b", "https://git.example.test/a/b"),
        ] {
            assert_eq!(clone_url_of(raw), expected, "{raw}");
        }
    }

    #[test]
    fn the_default_fetch_form_is_https_for_rows_that_predate_it() {
        let identity = NormalizedRemote::parse("git@github.com:a/b.git").unwrap();
        assert_eq!(
            identity.clone_url(&RemoteFetch::default()),
            "https://github.com/a/b"
        );
        let decoded: RemoteFetch = serde_json::from_str("{}").unwrap();
        assert_eq!(decoded, RemoteFetch::default());
    }

    #[test]
    fn the_fetch_form_never_carries_a_credential_or_an_option_lookalike() {
        for raw in [
            "https://user:token@github.com/a/b.git",
            "https://token@github.com/a/b.git",
            "ssh://git:secret@github.com/a/b.git",
            "git:secret@github.com:a/b.git",
            "-oProxyCommand=x@github.com:a/b.git",
            "ssh://-oProxyCommand=x@github.com/a/b.git",
            "a b@github.com:a/b.git",
            "ssh://git@-oProxyCommand=x/a/b",
            "ssh://git@host:-oProxyCommand=x/a/b",
            "ssh://git@host:99999999/a/b",
            "ssh://git@ho st/a/b",
        ] {
            assert!(NormalizedRemote::parse_with_fetch(raw).is_err(), "{raw}");
        }
        let (_, fetch) = NormalizedRemote::parse_with_fetch("git@github.com:a/b.git").unwrap();
        assert_eq!(fetch.scheme, FetchScheme::Scp);
        assert_eq!(fetch.user.as_deref(), Some("git"));
        let (_, https) = NormalizedRemote::parse_with_fetch("https://github.com/a/b.git").unwrap();
        assert_eq!(https, RemoteFetch::default());
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

    #[test]
    fn identity_parsing_keeps_accepting_what_it_always_accepted() {
        // Only a fetchable remote is registered, but an observed checkout's
        // remote is matched by identity and must never start failing.
        for raw in [
            "ssh://first.last+ci@host.example.test/a/b",
            "ssh://@host.example.test/a/b",
            "ssh://git@host.example.test:abc/a/b",
        ] {
            assert!(NormalizedRemote::parse(raw).is_ok(), "{raw}");
            assert!(NormalizedRemote::parse_with_fetch(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn a_fetch_form_from_outside_the_parser_is_validated() {
        let form = |scheme, user: Option<&str>| RemoteFetch {
            scheme,
            user: user.map(str::to_owned),
        };
        assert!(RemoteFetch::default().validate().is_ok());
        assert!(form(FetchScheme::Scp, Some("git")).validate().is_ok());
        assert!(form(FetchScheme::Ssh, None).validate().is_ok());
        for bad in [
            form(FetchScheme::Scp, None),
            form(FetchScheme::Https, Some("git")),
            form(FetchScheme::Ssh, Some("x@evil:22/y")),
            form(FetchScheme::Ssh, Some("-oProxyCommand=x")),
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }
}
