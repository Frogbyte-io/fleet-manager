//! The Coolify provider: a token health and permission probe (FM-1001).
//!
//! Coolify's API tokens carry abilities (`read`, `write`, `deploy`,
//! `read:sensitive`, `root`; see <https://coolify.io/docs/api-reference/permissions>),
//! but the documented API has no endpoint that returns the calling token's
//! abilities. The probe therefore uses only non-mutating `GET` requests
//! against routes that the API gates behind exactly one ability
//! (`routes/api.php` in the Coolify repository), and reads the answer:
//!
//! * `GET /api/v1/version` is gated by `read`;
//! * `GET /api/v1/enable` is gated by `write` (the route only answers
//!   "POST required");
//! * `GET /api/v1/deploy` is gated by `deploy` (likewise).
//!
//! `401` means the token is refused; `403` means the ability is missing;
//! `2xx`, `400`, and `405` mean the ability gate let the request through. A
//! `root` token passes every gate. `read:sensitive` has no side-effect-free
//! GET route that is gated by it alone, so it is not probed. Any other
//! status (for example `404`) leaves that ability undetermined, which is
//! reported as missing with that detail rather than guessed.
//!
//! This is an inference from route middleware, not a documented contract.
//! If Coolify later documents a token-abilities endpoint, replace the
//! write and deploy probes with it. The token is sent only as a bearer
//! header and never appears in any returned value.
#![warn(missing_docs)]

use std::time::Duration;

use fleet_core::{ProbeReport, ProbeStatus};

/// How long one request may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// The most response body bytes read for a detail.
const BODY_BOUND: usize = 512;

/// The abilities Fleet needs, each with the GET route that is gated by it.
const ABILITY_PROBES: [(&str, &str); 3] = [
    ("read", "/api/v1/version"),
    ("write", "/api/v1/enable"),
    ("deploy", "/api/v1/deploy"),
];

enum Gate {
    Granted,
    Missing(String),
    Undetermined(u16),
    Unauthorized(String),
    Unreachable(String),
}

/// Probes one Coolify instance with one API token.
///
/// `base_url` is the instance root without a trailing slash, for example
/// `https://coolify.example.com`.
pub async fn probe(base_url: &str, token: &str) -> ProbeReport {
    let client = match reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return ProbeReport::simple(
                ProbeStatus::Unreachable,
                "the HTTP client could not start",
            );
        }
    };
    let mut granted = Vec::new();
    let mut missing = Vec::new();
    let mut notes = Vec::new();
    for (ability, path) in ABILITY_PROBES {
        match gate(&client, base_url, path, token).await {
            Gate::Granted => granted.push(ability.to_owned()),
            Gate::Missing(detail) => {
                missing.push(ability.to_owned());
                notes.push(format!("{ability}: {detail}"));
            }
            Gate::Undetermined(status) => {
                missing.push(ability.to_owned());
                notes.push(format!("{ability}: could not verify (HTTP {status})"));
            }
            Gate::Unauthorized(detail) => {
                return ProbeReport::simple(ProbeStatus::Unauthorized, &detail);
            }
            Gate::Unreachable(detail) => {
                return ProbeReport::simple(ProbeStatus::Unreachable, &detail);
            }
        }
    }
    let mut report = if missing.is_empty() {
        ProbeReport::simple(ProbeStatus::Ok, "the token holds read, write, and deploy")
    } else {
        ProbeReport::simple(
            ProbeStatus::InsufficientPermission,
            &format!("missing: {}", notes.join("; ")),
        )
    };
    report.granted = granted;
    report.missing = missing;
    report
}

async fn gate(client: &reqwest::Client, base_url: &str, path: &str, token: &str) -> Gate {
    let response = match client
        .get(format!("{base_url}{path}"))
        .bearer_auth(token)
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            // reqwest errors can embed the URL; the base URL carries no
            // credentials (validated at the boundary), but keep the detail
            // to a category.
            let category = if error.is_timeout() {
                "the request timed out"
            } else if error.is_connect() {
                "the connection failed"
            } else {
                "the request failed"
            };
            return Gate::Unreachable(category.to_owned());
        }
    };
    let status = response.status().as_u16();
    let detail = body_text(response).await;
    match status {
        401 => Gate::Unauthorized(format!(
            "the token was refused (HTTP 401){}",
            suffix(&detail)
        )),
        403 => Gate::Missing(format!("HTTP 403{}", suffix(&detail))),
        200..=299 | 400 | 405 => Gate::Granted,
        other => Gate::Undetermined(other),
    }
}

fn suffix(detail: &str) -> String {
    if detail.is_empty() {
        String::new()
    } else {
        format!(": {detail}")
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
    // Only a plain `message` sentence is worth showing; anything else
    // (HTML error pages) is dropped.
    let text = String::from_utf8_lossy(&buffer);
    let message = text
        .split("\"message\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or("");
    message.chars().take(120).collect()
}
