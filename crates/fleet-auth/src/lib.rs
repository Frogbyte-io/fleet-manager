//! Caller resolution and authorization vocabulary for the trusted-LAN
//! deployment.
//!
//! The first release has no accounts and no login: every caller that can
//! reach the controller's local-network listener operates with full control.
//! That trust must be explicit, not accidental, so this crate makes the
//! deployment mode a type — [`TrustMode`] — and resolves every request to the
//! one principal the mode defines, [`Principal::ANONYMOUS_LAN_ADMIN`].
//!
//! Two rules are structural here rather than advisory:
//!
//! - **Identity never derives from the network.** A request's address and any
//!   proxy headers are recorded as [`CallerEvidence`] for audit; nothing in
//!   authorization may read them. Reachability is not identity.
//! - **The trust mode is loud.** [`TrustMode::TrustedLan`] carries the warning
//!   text the controller prints at startup and serves alongside its API
//!   metadata, so an operator cannot discover the exposure only after it
//!   matters.
//!
//! Authentication (M8) replaces the principal resolution, not this crate's
//! shape: callers keep flowing through one resolution point with evidence.
#![warn(missing_docs)]

pub mod adapter;

pub use adapter::LanAllowAllAuthorizer;

use std::fmt;
use std::net::SocketAddr;

use axum::{extract::Request, http::header::HeaderName, middleware::Next, response::Response};

/// The stable principal id of the anonymous LAN administrator.
pub const LAN_PRINCIPAL_ID: &str = "anonymous-lan-admin";

/// Proxy headers whose presence is recorded as evidence. Their values never
/// influence identity or authorization; a reverse proxy could claim anything,
/// and the trusted-LAN mode has no authenticated identity for them to claim.
pub const PROXY_EVIDENCE_HEADERS: [HeaderName; 4] = [
    HeaderName::from_static("forwarded"),
    HeaderName::from_static("x-forwarded-for"),
    HeaderName::from_static("x-forwarded-proto"),
    HeaderName::from_static("x-real-ip"),
];

/// The deployment's trust mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustMode {
    /// No accounts; every reachable caller operates with full control.
    TrustedLan,
}

impl TrustMode {
    /// The stable identifier used in configuration and API metadata.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::TrustedLan => "trusted-lan",
        }
    }

    /// The warning an operator must see at startup and in the UI.
    #[must_use]
    pub fn warning(self) -> &'static str {
        match self {
            Self::TrustedLan => {
                "TRUSTED-LAN MODE: the controller has no accounts or login. Every \
                 client that can reach this listener can read and mutate \
                 everything. Do not expose this port beyond the local network."
            }
        }
    }
}

/// A caller's identity. Authentication introduces variants; the trusted-LAN
/// deployment has exactly one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Principal {
    /// Every request the trusted-LAN listener accepts.
    AnonymousLanAdmin,
}

impl Principal {
    /// The one principal of the initial deployment.
    pub const ANONYMOUS_LAN_ADMIN: Self = Self::AnonymousLanAdmin;

    /// The stable principal id, as recorded in audit events.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::AnonymousLanAdmin => LAN_PRINCIPAL_ID,
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// Facts observed about a request. Evidence, never identity: authorization
/// must not read this, audit may record it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallerEvidence {
    /// The connected peer's address, when the listener provides one. This is
    /// where the connection came from, nothing more.
    remote_addr: Option<SocketAddr>,
    /// Proxy headers present on the request, with bounded values. Presence is
    /// evidence that a proxy — or a forger — is involved; the values carry no
    /// authority.
    proxy_headers: Vec<(String, String)>,
}

impl CallerEvidence {
    /// The peer address, when known.
    #[must_use]
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// The proxy headers seen on the request, with values bounded to 256
    /// characters. Recorded for audit, ignored for decisions.
    #[must_use]
    pub fn proxy_headers(&self) -> &[(String, String)] {
        &self.proxy_headers
    }
}

/// A resolved caller: who the deployment says is acting, plus the evidence
/// observed about the request.
#[derive(Clone, Debug)]
pub struct Caller {
    principal: Principal,
    evidence: CallerEvidence,
}

impl Caller {
    /// The principal acting on this request.
    #[must_use]
    pub fn principal(&self) -> Principal {
        self.principal
    }

    /// The request's evidence.
    #[must_use]
    pub fn evidence(&self) -> &CallerEvidence {
        &self.evidence
    }
}

/// Resolves every request to the anonymous LAN principal with the request's
/// evidence attached as an extension.
///
/// This is the one place callers come into existence in trusted-LAN mode; a
/// handler or provider that needs "the caller" reads the [`Caller`]
/// extension, and authorization downstream decides what the principal may do.
pub async fn resolve_lan_caller(mut request: Request, next: Next) -> Response {
    let remote_addr = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0);
    let proxy_headers = PROXY_EVIDENCE_HEADERS
        .iter()
        .filter_map(|header| {
            request
                .headers()
                .get(header)
                .and_then(|value| value.to_str().ok())
                .map(|value| (header.as_str().to_owned(), truncate(value, 256)))
        })
        .collect();

    let caller = Caller {
        principal: Principal::ANONYMOUS_LAN_ADMIN,
        evidence: CallerEvidence {
            remote_addr,
            proxy_headers,
        },
    };
    request.extensions_mut().insert(caller);
    next.run(request).await
}

/// Extracts the resolved caller from request extensions.
///
/// Handlers read this through `Extension<Caller>`; it lives here as a function
/// so the resolution contract has one description.
#[must_use]
pub fn caller_of(extensions: &axum::http::Extensions) -> Option<Caller> {
    extensions.get::<Caller>().cloned()
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_owned()
    } else {
        let mut end = max;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &value[..end])
    }
}
