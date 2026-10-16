//! External provider accounts: the closed set of API-token providers
//! Fleet holds credentials for (FM-1001), and the vocabulary of their
//! health and permission probes.
//!
//! Provider-specific API models never appear here. A provider crate turns
//! its own responses into a [`ProbeReport`] at its boundary.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The longest operator-facing label.
pub const MAX_ACCOUNT_LABEL_LEN: usize = 80;
/// The longest free-form note.
pub const MAX_ACCOUNT_NOTES_LEN: usize = 2000;
/// The longest base URL.
pub const MAX_BASE_URL_LEN: usize = 300;
/// The longest accepted token secret.
pub const MAX_TOKEN_SECRET_LEN: usize = 512;
/// The longest bounded probe detail.
pub const MAX_PROBE_DETAIL_LEN: usize = 300;

/// The provider kinds an external account may belong to. A closed enum:
/// adding a provider is a code change with its own contract tests.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalProviderKind {
    /// A Coolify instance (self-hosted PaaS).
    Coolify,
    /// Cloudflare (DNS, account-scoped API tokens).
    Cloudflare,
}

impl ExternalProviderKind {
    /// Every kind, in a stable order.
    pub const ALL: [Self; 2] = [Self::Coolify, Self::Cloudflare];

    /// The stable wire id.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Coolify => "coolify",
            Self::Cloudflare => "cloudflare",
        }
    }

    /// The base URL used when the operator supplies none; Coolify is
    /// self-hosted, so it has none.
    #[must_use]
    pub fn default_base_url(self) -> Option<&'static str> {
        match self {
            Self::Coolify => None,
            Self::Cloudflare => Some("https://api.cloudflare.com/client/v4"),
        }
    }
}

impl fmt::Display for ExternalProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// An unknown provider kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseProviderKindError(pub String);

impl fmt::Display for ParseProviderKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown provider kind {:?}; expected one of: coolify, cloudflare",
            self.0
        )
    }
}

impl std::error::Error for ParseProviderKindError {}

impl FromStr for ExternalProviderKind {
    type Err = ParseProviderKindError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.id() == value)
            .ok_or_else(|| ParseProviderKindError(value.chars().take(40).collect()))
    }
}

/// The classified outcome of a probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    /// The service answered and the token has every permission Fleet needs.
    Ok,
    /// The service could not be reached (DNS, TCP, TLS, timeout).
    Unreachable,
    /// The service refused the token: wrong, revoked, expired, or disabled.
    Unauthorized,
    /// The token is valid but lacks permissions Fleet needs.
    InsufficientPermission,
}

impl ProbeStatus {
    /// The stable wire id.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Unreachable => "unreachable",
            Self::Unauthorized => "unauthorized",
            Self::InsufficientPermission => "insufficient_permission",
        }
    }
}

/// What one probe found. The detail is bounded and carries no secret.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeReport {
    /// The classification.
    pub status: ProbeStatus,
    /// A short, redacted explanation.
    pub detail: String,
    /// Permissions the token was seen to hold.
    pub granted: Vec<String>,
    /// Permissions Fleet needs that the token lacks.
    pub missing: Vec<String>,
}

impl ProbeReport {
    /// A report without permission lists.
    #[must_use]
    pub fn simple(status: ProbeStatus, detail: &str) -> Self {
        Self {
            status,
            detail: bound_detail(detail),
            granted: Vec::new(),
            missing: Vec::new(),
        }
    }
}

/// Flattens control characters, scrubs credential-looking text, and
/// bounds a provider-supplied detail.
#[must_use]
pub fn bound_detail(detail: &str) -> String {
    let scrubbed = crate::redact_credentials(&crate::flatten_control_characters(detail));
    scrubbed.chars().take(MAX_PROBE_DETAIL_LEN).collect()
}

/// An invalid account field, with the reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountFieldError(pub String);

impl fmt::Display for AccountFieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AccountFieldError {}

fn invalid(message: &str) -> AccountFieldError {
    AccountFieldError(message.to_owned())
}

/// Validates an account label: 1..=80 printable characters.
///
/// # Errors
///
/// Fails when empty, too long, or containing control characters.
pub fn validate_label(label: &str) -> Result<(), AccountFieldError> {
    if label.trim().is_empty() || label.chars().count() > MAX_ACCOUNT_LABEL_LEN {
        return Err(invalid("the label must be 1..=80 characters"));
    }
    if label.chars().any(char::is_control) || label != label.trim() {
        return Err(invalid(
            "the label must not have control characters or surrounding spaces",
        ));
    }
    Ok(())
}

/// Validates notes: bounded, no NUL.
///
/// # Errors
///
/// Fails when too long or containing NUL.
pub fn validate_notes(notes: &str) -> Result<(), AccountFieldError> {
    if notes.chars().count() > MAX_ACCOUNT_NOTES_LEN || notes.contains('\0') {
        return Err(invalid("the notes must be at most 2000 characters"));
    }
    Ok(())
}

/// Validates and normalizes a base URL: `http` or `https`, a host, no
/// userinfo, query, or fragment; the trailing slash is dropped.
///
/// # Errors
///
/// Fails on any other shape.
pub fn normalize_base_url(raw: &str) -> Result<String, AccountFieldError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_BASE_URL_LEN {
        return Err(invalid("the base URL must be 1..=300 characters"));
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(invalid("the base URL must not contain whitespace"));
    }
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .ok_or_else(|| invalid("the base URL must start with http:// or https://"))?;
    let (authority, _path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid(
            "the base URL needs a host and must not embed credentials",
        ));
    }
    if trimmed.contains('?') || trimmed.contains('#') {
        return Err(invalid(
            "the base URL must not have a query string or fragment",
        ));
    }
    Ok(trimmed.trim_end_matches('/').to_owned())
}

/// Validates a provider-side scope id (a Cloudflare account id).
///
/// # Errors
///
/// Fails unless 1..=64 ASCII alphanumerics, `-`, or `_`.
pub fn validate_scope_id(scope: &str) -> Result<(), AccountFieldError> {
    if scope.is_empty()
        || scope.len() > 64
        || !scope
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(invalid(
            "the account id must be 1..=64 letters, digits, '-' or '_'",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_round_trip() {
        for kind in ExternalProviderKind::ALL {
            assert_eq!(kind.id().parse::<ExternalProviderKind>(), Ok(kind));
        }
        assert!("github".parse::<ExternalProviderKind>().is_err());
    }

    #[test]
    fn base_urls_normalize_and_refuse_credentials() {
        assert_eq!(
            normalize_base_url("https://coolify.example.com/").as_deref(),
            Ok("https://coolify.example.com")
        );
        assert!(normalize_base_url("ftp://x").is_err());
        assert!(normalize_base_url("https://user:pw@host").is_err());
        assert!(normalize_base_url("https://host/?token=abc").is_err());
        assert!(normalize_base_url("https://").is_err());
    }

    #[test]
    fn labels_are_bounded() {
        assert!(validate_label("prod").is_ok());
        assert!(validate_label(" ").is_err());
        assert!(validate_label(&"x".repeat(81)).is_err());
    }
}
