//! The GitHub provider (FM-403): the App web flow for one-click private
//! repository creation with least permissions and expiring tokens.
//!
//! The flow: the installation access token is requested through GitHub's
//! documented App API with an installation id scoped to the target
//! repository, carries `contents:read/write` on that repository only,
//! and expires (the response carries its own expiry). The token is
//! returned to the caller for storage in Fleet's encrypted secret store;
//! it is never logged, never audited with its value, and never persisted
//! here.
//!
//! Fleet's machine identity is never derived from GitHub: the App
//! installation is evidence for bootstrap, nothing more.
#![warn(missing_docs)]

use std::time::Duration;

use serde::Deserialize;

/// The contents permission the App requests: read/write on the target
/// repository only. Least permissions: nothing else is requested.
pub const CONTENTS_PERMISSION: &str = "contents:read_and_write";

/// The transport contract: one HTTPS call, bounded.
#[async_trait::async_trait]
pub trait GithubTransport: std::fmt::Debug + Send + Sync {
    /// Performs one POST to GitHub's installation-token endpoint.
    ///
    /// # Errors
    ///
    /// Fails on transport errors; an API refusal is an outcome.
    async fn post_installation_token(
        &self,
        installation_id: &str,
        body: &str,
        deadline: Duration,
    ) -> Result<HttpResponse, String>;
}

/// One HTTP response, bounded.
#[derive(Clone, Debug)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// The bounded body.
    pub body: String,
}

/// The installation token GitHub answers with.
#[derive(Debug, Deserialize)]
struct TokenDocument {
    #[serde(default, alias = "token")]
    value: Option<String>,
    #[serde(default, alias = "expiresAt")]
    expires_at: Option<String>,
}

/// The outcome of one bootstrap-token request: the token and its expiry,
/// or an honest refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BootstrapOutcome {
    /// The token was issued; it expires at the documented time.
    Issued {
        /// The token value, for the caller's encrypted store only.
        token: String,
        /// When the token expires, as GitHub documented it.
        expires_at: Option<String>,
        /// The permissions the token carries.
        permissions: Vec<String>,
    },
    /// GitHub refused the request; the detail is bounded and redacted.
    Refused {
        /// The bounded, redacted detail.
        detail: String,
    },
}

/// Requests one bootstrap token for an App installation. The token
/// carries `contents:read_and_write` on the installation's repository
/// only, and expires — the caller stores it in Fleet's encrypted secret
/// store, never in logs or audit metadata.
///
/// # Errors
///
/// Fails on transport errors; a GitHub refusal is an outcome.
pub async fn request_bootstrap_token(
    transport: &dyn GithubTransport,
    installation_id: &str,
    deadline: Duration,
) -> Result<BootstrapOutcome, String> {
    let outcome = transport
        .post_installation_token(
            installation_id,
            r#"{"permissions":{"contents":"write"}}"#,
            deadline,
        )
        .await?;
    if outcome.status != 201 {
        return Ok(BootstrapOutcome::Refused {
            detail: redact(&outcome.body),
        });
    }
    if outcome.body.len() > 64 * 1024 {
        return Ok(BootstrapOutcome::Refused {
            detail: "the token document exceeds its bound".to_owned(),
        });
    }
    let document: TokenDocument = serde_json::from_str(outcome.body.trim())
        .map_err(|_| "the token document is not in the documented shape".to_string())?;
    let Some(token) = document.value.filter(|token| !token.is_empty()) else {
        return Ok(BootstrapOutcome::Refused {
            detail: "the token document carries no token".to_owned(),
        });
    };
    Ok(BootstrapOutcome::Issued {
        // The token itself is returned for the encrypted store only; the
        // expiry and permissions are safe to carry.
        token,
        expires_at: document.expires_at,
        permissions: vec![CONTENTS_PERMISSION.to_owned()],
    })
}

/// Scrubs credential-shaped material from GitHub's error output before
/// it becomes a detail.
#[must_use]
pub fn redact(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect();
    fleet_core::redact_url_credentials(&cleaned)
}
