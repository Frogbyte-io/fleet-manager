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
//! - **Style nonces, never `'unsafe-inline'`.** Some web dependencies
//!   (CodeMirror) inject `<style>` elements at runtime. The shell's
//!   `index.html` carries [`CSP_NONCE_PLACEHOLDER`] (Vite's `html.cspNonce`);
//!   each HTML response gets a fresh random nonce substituted for it and
//!   allowed in `style-src`, so only styles the shell's own code creates
//!   apply. Scripts get no nonce: they stay `'self'`-only.
#![warn(missing_docs)]

use std::str::FromStr as _;

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use base64::Engine as _;
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
///
/// # Panics
///
/// Panics only if the pinned literal error code stops being valid syntax,
/// which is a constant path a test pins.
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
    ApiError::new(&public, correlation_id)
        .with_status(StatusCode::FORBIDDEN)
        .into_response()
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

/// The token the built web shell carries wherever a per-response CSP nonce
/// belongs (Vite's `html.cspNonce`, set in `apps/web/vite.config.ts`). It is
/// not secret: it only marks where the controller writes the real nonce.
pub const CSP_NONCE_PLACEHOLDER: &str = "__FLEET_CSP_NONCE__";

/// The policy for every response that does not carry a nonce.
const CSP: &str = "default-src 'self'; img-src 'self' data:; style-src 'self'";

/// The largest HTML body the nonce rewrite will buffer. The shell's
/// `index.html` is about a kilobyte; anything near this is not the shell.
const MAX_HTML_REWRITE: usize = 1024 * 1024;

/// Adds the security headers the web shell and the API should always carry.
///
/// An HTML response that contains [`CSP_NONCE_PLACEHOLDER`] gets a fresh
/// nonce written over the placeholder and allowed in `style-src`, and is
/// marked `no-store` so a cached copy can never pair an old nonce with a new
/// policy. Every other response gets the static policy.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    let mut response = if is_html(&response) {
        with_style_nonce(response).await
    } else {
        response
    };
    let headers = response.headers_mut();
    if !headers.contains_key(header::CONTENT_SECURITY_POLICY) {
        // The shell loads nothing but its own assets; scripts from anywhere
        // else are an attack, not a feature.
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        );
    }
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

fn is_html(response: &Response) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/html"))
}

/// Writes a fresh nonce over the placeholder in an HTML body and sets the
/// matching policy. A body without the placeholder is passed through
/// unchanged (and gets the static policy from the caller).
async fn with_style_nonce(response: Response) -> Response {
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_HTML_REWRITE).await else {
        // The body is gone; an oversized or failed HTML body is not the shell.
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let rewritten = std::str::from_utf8(&bytes)
        .ok()
        .filter(|html| html.contains(CSP_NONCE_PLACEHOLDER))
        .and_then(|html| Some((html, style_nonce()?)));
    let Some((html, nonce)) = rewritten else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    let html = html.replace(CSP_NONCE_PLACEHOLDER, &nonce);
    let policy =
        format!("default-src 'self'; img-src 'self' data:; style-src 'self' 'nonce-{nonce}'");
    let headers = &mut parts.headers;
    // Base64 is header-safe; the conversion cannot fail.
    if let Ok(policy) = HeaderValue::from_str(&policy) {
        headers.insert(header::CONTENT_SECURITY_POLICY, policy);
    }
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(html.len()));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.remove(header::ETAG);
    headers.remove(header::LAST_MODIFIED);
    Response::from_parts(parts, Body::from(html))
}

/// 128 random bits, base64-encoded, as CSP nonces should be. `None` when the
/// OS has no randomness to give; the caller then serves the nonce-free
/// policy, which blocks injected styles rather than allowing them.
fn style_nonce() -> Option<String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).ok()?;
    Some(base64::engine::general_purpose::STANDARD.encode(bytes))
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

    #[test]
    fn style_nonces_are_fresh_and_header_safe() {
        let first = style_nonce().unwrap();
        let second = style_nonce().unwrap();
        assert_ne!(first, second);
        // 16 bytes of base64: long enough to be unguessable.
        assert_eq!(first.len(), 24);
        assert!(HeaderValue::from_str(&format!("'nonce-{first}'")).is_ok());
    }
}
