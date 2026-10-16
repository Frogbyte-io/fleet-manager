//! The Coolify provider: a token health probe (FM-1001) and read-only
//! resource discovery (FM-1030, see [`discovery`]).
//!
//! Coolify's API tokens carry abilities (`read`, `write`, `deploy`,
//! `read:sensitive`, `root`; see <https://coolify.io/docs/api-reference/permissions>),
//! but the documented API has no endpoint that returns the calling token's
//! abilities. This probe therefore never guesses at them with a request
//! that could change state: on Coolify before v4.2.0, `GET /api/v1/enable`
//! and `GET /api/v1/deploy` reach handlers that re-enable the API or start
//! a deployment, so the probe never calls them (or any route other than the
//! one below), on any version.
//!
//! The probe sends exactly one request, `GET /api/v1/version` with no
//! query. The route is gated by the `read` ability (`routes/api.php` in the
//! Coolify repository), so an answer verifies `read`:
//!
//! * `2xx` with a version string: the answer is Coolify and the token holds
//!   `read`;
//! * `2xx` with anything else, or `404`: not a Coolify API (`unreachable`);
//! * `401`: the token is refused (`unauthorized`);
//! * `403` with Coolify's "Missing required permissions" body: the token is
//!   valid but lacks `read` (`insufficient_permission`); any other `403`
//!   (API access disabled, caller IP not allowed) is `unauthorized` and
//!   carries Coolify's message;
//! * any `3xx`: the probe stops and reports the redirect (naming only the
//!   target host), because following it could carry the bearer token to
//!   another origin or scheme.
//!
//! `write` and `deploy` are reported as `unverified`, a distinct list from
//! `missing`: Fleet has no side-effect-free way to learn them. The
//! `read:sensitive` and `root` abilities are not probed either. The token
//! is sent only as a bearer header and never appears in any returned value.
#![warn(missing_docs)]

pub mod discovery;
pub mod scrub;
mod translate;

pub use discovery::{CoolifyHttpSource, Limits, discover, discover_with};

use std::error::Error as _;
use std::time::Duration;

use fleet_core::{ProbeReport, ProbeStatus};

/// How long the request may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// The only path the probe ever requests.
pub const PROBE_PATH: &str = "/api/v1/version";
/// The most response body bytes read.
const BODY_BOUND: usize = 512;
/// The abilities this probe cannot verify without a mutating request.
const UNVERIFIED: [&str; 2] = ["write", "deploy"];

/// Probes one Coolify instance with one API token.
///
/// `base_url` is the instance root without a trailing slash, for example
/// `https://coolify.example.com`.
pub async fn probe(base_url: &str, token: &str) -> ProbeReport {
    // The bearer token never travels over plain http, except to a literal
    // loopback address (a local stub).
    if base_url.starts_with("http://") && !fleet_core::base_url_is_loopback(base_url) {
        return ProbeReport::simple(
            ProbeStatus::Unreachable,
            "the base URL uses http; the token is only sent over https (edit the account to use https)",
        );
    }
    let Ok(client) = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return ProbeReport::simple(ProbeStatus::Unreachable, "the HTTP client could not start");
    };
    let response = match client
        .get(format!("{base_url}{PROBE_PATH}"))
        .bearer_auth(token)
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return ProbeReport::simple(ProbeStatus::Unreachable, transport_category(&error));
        }
    };
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        let host = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .and_then(location_host);
        let hint = redirect_hint(base_url);
        let detail = match host {
            Some(host) => format!("redirected to {host}; {hint}"),
            None => format!("redirected; {hint}"),
        };
        return ProbeReport::simple(ProbeStatus::Unreachable, &detail);
    }
    let body = body_text(response).await;
    classify(status, &body)
}

/// Only an http base URL is helped by switching to https.
fn redirect_hint(base_url: &str) -> &'static str {
    if base_url.starts_with("http://") {
        "use the https base URL"
    } else {
        "check the base URL"
    }
}

fn classify(status: u16, body: &str) -> ProbeReport {
    match status {
        200..=299 if looks_like_version(body) => {
            let mut report = ProbeReport::simple(
                ProbeStatus::Ok,
                "the token is accepted (read); write and deploy are not verified",
            );
            report.granted = vec!["read".to_owned()];
            report.unverified = UNVERIFIED.map(str::to_owned).to_vec();
            report
        }
        200..=299 | 404 => ProbeReport::simple(
            ProbeStatus::Unreachable,
            "the answer is not a Coolify API; check the base URL",
        ),
        401 => ProbeReport::simple(
            ProbeStatus::Unauthorized,
            "the token was refused (HTTP 401)",
        ),
        403 if message_of(body)
            .to_ascii_lowercase()
            .contains("missing required permissions") =>
        {
            let mut report = ProbeReport::simple(
                ProbeStatus::InsufficientPermission,
                "the token is valid but lacks the read ability",
            );
            report.missing = vec!["read".to_owned()];
            report.unverified = UNVERIFIED.map(str::to_owned).to_vec();
            report
        }
        403 => ProbeReport::simple(
            ProbeStatus::Unauthorized,
            &format!("the request was refused (HTTP 403): {}", message_of(body)),
        ),
        other => ProbeReport::simple(
            ProbeStatus::Unreachable,
            &format!("unexpected HTTP status {other}"),
        ),
    }
}

/// A Coolify version string: optionally `v`, then a digit, then letters, digits,
/// `.`, `-`, or `+`, at most 40 characters. `/version` answers plain text.
fn looks_like_version(body: &str) -> bool {
    // Coolify's OpenAPI example for `/version` is `v4.0.0`; the running
    // service answers without the `v`. Both are versions.
    let text = body.trim().trim_matches('"');
    let text = text.strip_prefix('v').unwrap_or(text);
    !text.is_empty()
        && text.len() <= 40
        && text.starts_with(|c: char| c.is_ascii_digit())
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

/// The `message` sentence of a JSON error body, empty when there is none
/// (HTML error pages are dropped).
fn message_of(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("message")?.as_str().map(str::to_owned))
        .map(|message| translate::clean(&message, 120))
        .unwrap_or_default()
}

/// The host of a `Location` header value, nothing else (the path and query
/// can carry anything).
fn location_host(location: &str) -> Option<String> {
    let rest = location.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    (!host.is_empty()
        && host.len() <= 100
        && host.chars().all(|c| !c.is_control() && !c.is_whitespace()))
    .then(|| host.to_owned())
}

/// A category for a transport failure; never the URL or any server text.
fn transport_category(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        return "the request timed out";
    }
    let mut chain = String::new();
    let mut source = error.source();
    while let Some(cause) = source {
        chain.push_str(&cause.to_string().to_ascii_lowercase());
        chain.push(' ');
        source = cause.source();
    }
    if [
        "certificate",
        "tls",
        "ssl",
        "handshake",
        "corrupt message",
        "unknownissuer",
    ]
    .iter()
    .any(|needle| chain.contains(needle))
    {
        "the TLS handshake failed (certificate or protocol); check the base URL scheme and certificate"
    } else if error.is_connect() {
        "the connection failed"
    } else {
        "the request failed"
    }
}

async fn body_text(mut response: reqwest::Response) -> String {
    let mut buffer = Vec::new();
    while buffer.len() < BODY_BOUND {
        match response.chunk().await {
            Ok(Some(chunk)) => buffer.extend_from_slice(&chunk),
            _ => break,
        }
    }
    buffer.truncate(BODY_BOUND);
    String::from_utf8_lossy(&buffer).into_owned()
}

#[cfg(test)]
mod tests {
    use super::redirect_hint;

    #[test]
    fn the_https_hint_is_only_for_http_base_urls() {
        assert_eq!(
            redirect_hint("http://c.example.test"),
            "use the https base URL"
        );
        assert_eq!(
            redirect_hint("https://c.example.test"),
            "check the base URL"
        );
    }
}
