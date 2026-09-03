//! Browser-facing HTTP protections for the trusted-LAN deployment.
//!
//! An open LAN API is still exposed to one specific attacker: a malicious
//! public webpage driving a visitor's browser against the controller. The
//! browser supplies credentials automatically (here: network reachability),
//! so the defenses are structural:
//!
//! - **Origin verification on mutations.** Browsers attach an `Origin`
//!   header to cross-site and same-site non-GET requests; a mutation whose
//!   origin does not match the request's host is refused before any handler
//!   runs. Non-browser clients (CLI, skills, curl) send no `Origin` at all
//!   and pass untouched — this is not authentication, and it never claims to
//!   be: it fences browsers, which is the only thing that can be fenced
//!   without accounts.
//! - **No CORS.** The API is served same-origin only; no cross-origin reads
//!   are approved, so a browser on another origin can neither read responses
//!   nor preflight a JSON mutation.
//! - **Proxy headers are never trusted here.** A forged `X-Forwarded-Host`
//!   cannot make a foreign origin look same-origin (see FM-103: proxy data
//!   is evidence, not authority).
//! - **Security headers** on every response keep the web shell from being
//!   framed, MIME-sniffed, or leaking referrers.
#![warn(missing_docs)]

use std::str::FromStr as _;

use axum::{
    extract::Request,
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use fleet_core::{ErrorCode, IdGenerator as _, PublicError, RetryClass, UuidV7Generator};

use fleet_api::ApiError;

/// Methods the guard treats as mutations. Everything else (safe methods) is
/// readable cross-origin in the sense that the request proceeds; CORS is
/// absent, so foreign browsers still cannot read the responses.
const GUARDED_METHODS: [Method; 5] = [
    Method::POST,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
    Method::TRACE,
];

/// Verifies browser-supplied `Origin` against the request's `Host` on
/// mutations, refusing foreign origins before handlers run.
///
/// Requests without an `Origin` (CLI, `fleetctl`, curl, server-to-server) are
/// allowed through: the guard fences browsers, the only clients that can be
/// fenced without accounts. Requests with a foreign `Origin` get the standard
/// error envelope.
pub async fn browser_mutation_guard(request: Request, next: Next) -> Response {
    if !GUARDED_METHODS.contains(request.method()) {
        return next.run(request).await;
    }

    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let Some(origin) = origin else {
        // Not a browser-driven mutation; the CLI path.
        return next.run(request).await;
    };

    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    if same_origin(&origin, host.as_deref()) {
        return next.run(request).await;
    }

    let mut generator = UuidV7Generator;
    let correlation_id = generator.next_correlation_id();
    let public = PublicError::new(
        ErrorCode::from_str("cross_origin_mutation")
            .expect("the literal is valid error code syntax"),
        "this mutation was sent from a different origin than the controller; \
         use the controller's own address, or the CLI",
        RetryClass::Never,
    );
    let response = ApiError::new(&public, correlation_id)
        .with_status(StatusCode::FORBIDDEN)
        .into_response();
    response
}

/// Whether an `Origin` value and a `Host` value name the same authority.
/// Scheme-insensitive on purpose: a LAN controller is reached as
/// `http://host:port` by browsers but the `Host` header carries no scheme.
fn same_origin(origin: &str, host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    let origin_authority = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or(origin);
    origin_authority.eq_ignore_ascii_case(host)
}

/// Adds the security headers the web shell and the API should always carry.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    // The shell loads nothing but its own assets; scripts from anywhere else
    // are an attack, not a feature.
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; img-src 'self' data:; style-src 'self'"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_origin_ignores_the_scheme_but_not_the_authority() {
        assert!(same_origin("http://box.lan:8080", Some("box.lan:8080")));
        assert!(same_origin("https://box.lan:8080", Some("box.lan:8080")));
        assert!(!same_origin("http://evil.example", Some("box.lan:8080")));
        // A port difference is a different authority.
        assert!(!same_origin("http://box.lan:9090", Some("box.lan:8080")));
        // A missing Host can never be same-origin.
        assert!(!same_origin("http://box.lan:8080", None));
        // A proxy header is not a Host.
        assert!(!same_origin("http://box.lan:8080", Some("evil.example")));
    }
}
