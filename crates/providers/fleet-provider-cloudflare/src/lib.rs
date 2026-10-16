//! The Cloudflare provider: an API token verify probe (FM-1001).
//!
//! Primary sources:
//! <https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify/>
//! (`GET /user/tokens/verify`, user-owned tokens) and
//! <https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/verify/>
//! (`GET /accounts/{account_id}/tokens/verify`, account-owned tokens).
//! Both answer `{ success, errors, result: { id, status, expires_on,
//! not_before } }` with `status` one of `active`, `disabled`, `expired`.
//!
//! Classification:
//!
//! * transport failure: `unreachable`;
//! * `401`, or `success: false` with a refusal, or a `disabled`/`expired`
//!   token: `unauthorized`;
//! * `403` on the account-owned endpoint: `insufficient_permission`, the
//!   token is valid but not for that account;
//! * `active` and inside its validity window: `ok`.
//!
//! The verify endpoint does not list the token's policies, so a token that
//! verifies is reported `ok`; per-zone permissions are checked by the DNS
//! features that use them (FM-1042). The token is sent as a bearer header
//! only and never appears in any returned value.
#![warn(missing_docs)]

use std::time::Duration;

use fleet_core::{ProbeReport, ProbeStatus};
use serde::Deserialize;

/// The production API root.
pub const DEFAULT_BASE_URL: &str = "https://api.cloudflare.com/client/v4";
/// How long one request may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// The most response bytes read.
const BODY_BOUND: usize = 8 * 1024;

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<ApiMessage>,
    result: Option<VerifyResult>,
}

#[derive(Deserialize)]
struct ApiMessage {
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct VerifyResult {
    #[serde(default)]
    status: String,
}

/// Probes one Cloudflare token. With `account_id` the account-owned
/// endpoint is used, otherwise the user-owned one.
pub async fn probe(base_url: &str, account_id: Option<&str>, token: &str) -> ProbeReport {
    let url = match account_id {
        Some(account) => format!("{base_url}/accounts/{account}/tokens/verify"),
        None => format!("{base_url}/user/tokens/verify"),
    };
    let Ok(client) = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return ProbeReport::simple(ProbeStatus::Unreachable, "the HTTP client could not start");
    };
    let mut response = match client
        .get(url)
        .bearer_auth(token)
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            let category = if error.is_timeout() {
                "the request timed out"
            } else if error.is_connect() {
                "the connection failed"
            } else {
                "the request failed"
            };
            return ProbeReport::simple(ProbeStatus::Unreachable, category);
        }
    };
    let status = response.status().as_u16();
    let mut body = Vec::new();
    while body.len() < BODY_BOUND {
        match response.chunk().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk),
            _ => break,
        }
    }
    classify(status, &body, account_id.is_some())
}

fn classify(status: u16, body: &[u8], account_owned: bool) -> ProbeReport {
    let envelope: Option<Envelope> = serde_json::from_slice(body).ok();
    let first_error = envelope
        .as_ref()
        .and_then(|envelope| envelope.errors.first())
        .map_or("", |error| error.message.as_str());
    match status {
        401 => ProbeReport::simple(
            ProbeStatus::Unauthorized,
            &format!("the token was refused (HTTP 401) {first_error}"),
        ),
        403 if account_owned => ProbeReport::simple(
            ProbeStatus::InsufficientPermission,
            &format!("the token is not valid for that account (HTTP 403) {first_error}"),
        ),
        403 => ProbeReport::simple(
            ProbeStatus::Unauthorized,
            &format!("the token was refused (HTTP 403) {first_error}"),
        ),
        200..=299 => match envelope {
            Some(Envelope {
                success: true,
                result: Some(result),
                ..
            }) => match result.status.as_str() {
                "active" => ProbeReport::simple(ProbeStatus::Ok, "the token is active"),
                other => ProbeReport::simple(
                    ProbeStatus::Unauthorized,
                    &format!("the token is {other:?}, not active"),
                ),
            },
            Some(_) => ProbeReport::simple(
                ProbeStatus::Unauthorized,
                &format!("verify did not succeed {first_error}"),
            ),
            None => ProbeReport::simple(
                ProbeStatus::Unreachable,
                "the answer was not Cloudflare's verify response; check the base URL",
            ),
        },
        // Cloudflare answers a malformed or unknown bearer with 400.
        400 => ProbeReport::simple(
            ProbeStatus::Unauthorized,
            &format!("the token was refused (HTTP 400) {first_error}"),
        ),
        other => ProbeReport::simple(
            ProbeStatus::Unreachable,
            &format!("unexpected HTTP status {other}"),
        ),
    }
}
