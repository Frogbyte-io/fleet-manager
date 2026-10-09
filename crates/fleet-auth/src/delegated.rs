//! Delegated credentials as a request principal (ADR 0011).
//!
//! This module is the `fleet-auth` half of the delegated credential model:
//!
//! - [`DelegatedTokenCrypto`] mints and hashes the opaque bearer token
//!   `fmdc1.<64 hex>` (32 CSPRNG bytes) and compares hashes in constant time.
//! - [`resolve_delegated_caller`] turns a presented token into a request
//!   principal, next to the trusted-LAN and Tailscale Serve resolvers. A
//!   valid token narrows the caller to `credential:<owner>:<id>`; an invalid
//!   one is refused and never falls back to administrator.
//! - [`ScopedAuthorizer`] is the one authorizer of a deployment: it keeps the
//!   explicit allow-all policy for the LAN and Tailscale principals and
//!   decides a delegated principal from [`DELEGATED_LAB_LOOP`], a
//!   deny-by-default table with one row per allowed catalog action.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use fleet_application::authz::{
    AccessRequest, Authorizer, Decision, Permission, ReasonId, is_delegated_principal,
};
use fleet_application::credentials::{
    AuthenticationFailure, CredentialCrypto, Credentials, GrantBook,
};
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

use crate::adapter::LanAllowAllAuthorizer;
use crate::{Caller, CallerEvidence, Principal};

/// The token's format tag.
pub const TOKEN_PREFIX: &str = "fmdc1";
const TOKEN_BYTES: usize = 32;

/// Mints and hashes delegated credential tokens.
#[derive(Debug)]
pub struct DelegatedTokenCrypto {
    rng: SystemRandom,
}

impl DelegatedTokenCrypto {
    /// A crypto adapter over the system CSPRNG.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }
}

impl Default for DelegatedTokenCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialCrypto for DelegatedTokenCrypto {
    fn generate_token(&self) -> String {
        let mut bytes = [0_u8; TOKEN_BYTES];
        self.rng
            .fill(&mut bytes)
            .expect("the system random source must not fail");
        format!("{TOKEN_PREFIX}.{}", hex(&bytes))
    }

    fn hash_token(&self, token: &str) -> String {
        hex(digest::digest(&digest::SHA256, token.as_bytes()).as_ref())
    }

    fn hashes_equal(&self, left: &str, right: &str) -> bool {
        let (left, right) = (left.as_bytes(), right.as_bytes());
        if left.len() != right.len() {
            return false;
        }
        left.iter()
            .zip(right)
            .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
            == 0
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// Whether text has the exact shape of a delegated token.
#[must_use]
pub fn is_token_shaped(token: &str) -> bool {
    token
        .strip_prefix(TOKEN_PREFIX)
        .and_then(|rest| rest.strip_prefix('.'))
        .is_some_and(|hex| {
            hex.len() == TOKEN_BYTES * 2
                && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// How a resource must look for a catalog row to apply.
#[derive(Clone, Copy, Debug)]
pub enum ResourceRule {
    /// Any resource, or none (a listing).
    Any,
    /// A resource must be named. The use case then applies owner scope.
    Named,
    /// A resource must be named and not be one of these reserved names.
    NamedNot(&'static [&'static str]),
    /// The resource must be exactly one of these.
    OneOf(&'static [&'static str]),
    /// The resource is `<templateId>/<versionId>` and the credential's
    /// allow-list must include the template or the version.
    TemplateGrant,
}

/// One allowed action of a delegated credential.
#[derive(Clone, Copy, Debug)]
pub struct DelegatedAction {
    /// The catalog action.
    pub action: Permission,
    /// What it may be done to.
    pub resource: ResourceRule,
}

/// The Lab lease loop: everything a delegated CI or agent credential may do,
/// and nothing else. Adding an action to the loop is one row here and one
/// test in `tests/delegated_catalog.rs`.
pub const DELEGATED_LAB_LOOP: &[DelegatedAction] = &[
    // lab create / lease: the template allow-list, then the lease itself.
    DelegatedAction {
        action: Permission::LabTemplateUse,
        resource: ResourceRule::TemplateGrant,
    },
    // Create from a version, release (destroy) and cleanup retry of a lease.
    // A resourceless use (the expiry sweep) is refused.
    DelegatedAction {
        action: Permission::LabLease,
        resource: ResourceRule::Named,
    },
    DelegatedAction {
        action: Permission::LabLeaseProvision,
        resource: ResourceRule::Named,
    },
    // lab status / show, lab leases: the use case limits these to the owner.
    DelegatedAction {
        action: Permission::LabLeaseRead,
        resource: ResourceRule::Any,
    },
    DelegatedAction {
        action: Permission::LabExtend,
        resource: ResourceRule::Named,
    },
    DelegatedAction {
        action: Permission::LabExec,
        resource: ResourceRule::Named,
    },
    // lab collect and artifact-get (download).
    DelegatedAction {
        action: Permission::LabArtifacts,
        resource: ResourceRule::NamedNot(&["retention"]),
    },
    // lab artifacts (list and metadata).
    DelegatedAction {
        action: Permission::LabArtifactRead,
        resource: ResourceRule::Any,
    },
    // The operations a Lab route queues for the caller, and reading one.
    DelegatedAction {
        action: Permission::OperationCreate,
        resource: ResourceRule::OneOf(&["lab.provision", "lab.exec", "lab.collect", "lab.cleanup"]),
    },
    DelegatedAction {
        action: Permission::OperationRead,
        resource: ResourceRule::Named,
    },
];

/// The deployment's authorizer: allow-all for the LAN and Tailscale
/// principals, the [`DELEGATED_LAB_LOOP`] table for delegated credentials.
#[derive(Debug)]
pub struct ScopedAuthorizer {
    grants: Arc<GrantBook>,
    catalog: &'static [DelegatedAction],
    administrators: LanAllowAllAuthorizer,
}

impl ScopedAuthorizer {
    /// An authorizer deciding delegated principals on the Lab loop and the
    /// given grants.
    #[must_use]
    pub fn new(grants: Arc<GrantBook>) -> Self {
        Self::with_catalog(grants, DELEGATED_LAB_LOOP)
    }

    /// An authorizer over an explicit catalog table.
    #[must_use]
    pub fn with_catalog(grants: Arc<GrantBook>, catalog: &'static [DelegatedAction]) -> Self {
        Self {
            grants,
            catalog,
            administrators: LanAllowAllAuthorizer,
        }
    }

    fn decide_delegated(&self, request: &AccessRequest<'_>) -> Decision {
        let Some(row) = self.catalog.iter().find(|row| row.action == request.action) else {
            return Decision::deny(ReasonId::ActionNotDelegated);
        };
        let in_scope =
            match (row.resource, request.resource) {
                (ResourceRule::Any, _) => true,
                (ResourceRule::Named, Some(resource)) => !resource.is_empty(),
                (ResourceRule::NamedNot(reserved), Some(resource)) => {
                    !resource.is_empty() && !reserved.contains(&resource)
                }
                (ResourceRule::OneOf(allowed), Some(resource)) => allowed.contains(&resource),
                (ResourceRule::TemplateGrant, Some(resource)) => resource
                    .split_once('/')
                    .is_some_and(|(template_id, version_id)| {
                        self.grants
                            .get(request.principal_id)
                            .is_some_and(|grant| grant.allows_version(template_id, version_id))
                    }),
                (_, None) => false,
            };
        if in_scope {
            Decision::allow()
        } else {
            Decision::deny(ReasonId::OutOfScope)
        }
    }
}

impl Authorizer for ScopedAuthorizer {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if is_delegated_principal(request.principal_id) {
            self.decide_delegated(&request)
        } else {
            self.administrators.decide(request)
        }
    }
}

/// Why a presented credential was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRejection {
    /// Not a well-formed token, or presented from an untrusted peer.
    Malformed,
    /// No such credential.
    Unknown,
    /// Expired or revoked.
    Inactive,
    /// The credential check could not complete; the request is refused.
    Unavailable,
}

/// Marker attached when a request presented a delegated token that did not
/// authenticate. The API adapter turns it into its error envelope. A
/// presented token never falls back to another principal.
#[derive(Clone, Copy, Debug)]
pub struct RejectedCredential(pub CredentialRejection);

/// The state of the delegated caller resolver.
#[derive(Clone, Debug)]
pub struct DelegatedCallerResolver {
    /// The credential use cases.
    pub credentials: Arc<Credentials>,
    /// Whether the TCP peer must be the loopback peer (the Tailscale Serve
    /// listener).
    pub require_loopback_peer: bool,
}

/// Resolves `Authorization: Bearer fmdc1.…` into the delegated principal.
///
/// Requests without a delegated token pass through untouched, so the
/// listener's own resolver decides them as before.
pub async fn resolve_delegated_caller(
    State(resolver): State<DelegatedCallerResolver>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(token) = presented_token(&request) else {
        return next.run(request).await;
    };
    let remote_addr = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0);
    let reject = |mut request: Request, reason: CredentialRejection| {
        request.extensions_mut().insert(RejectedCredential(reason));
        request
    };
    let trusted_peer = !resolver.require_loopback_peer
        || remote_addr.is_some_and(|address| address.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST));
    if !is_token_shaped(&token) || !trusted_peer {
        return next
            .run(reject(request, CredentialRejection::Malformed))
            .await;
    }
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let now = fleet_core::SystemClock::now_unix_millis();
    match resolver
        .credentials
        .authenticate(&token, &method, &path, now)
        .await
    {
        Ok(authenticated) => {
            let principal_id = authenticated.principal_id;
            request.extensions_mut().insert(Caller {
                principal: Principal::DelegatedCredential,
                principal_id: principal_id.clone(),
                evidence: CallerEvidence {
                    remote_addr,
                    proxy_headers: Vec::new(),
                    identity_headers_present: Vec::new(),
                },
            });
            request
                .extensions_mut()
                .insert(fleet_application::authz::ActingPrincipal { id: principal_id });
            next.run(request).await
        }
        Err(failure) => {
            let reason = match failure {
                AuthenticationFailure::Unknown => CredentialRejection::Unknown,
                AuthenticationFailure::Inactive(_) => CredentialRejection::Inactive,
                AuthenticationFailure::Backend(_) => CredentialRejection::Unavailable,
            };
            next.run(reject(request, reason)).await
        }
    }
}

/// The bearer token of a request when it presents one of this scheme: the
/// request has exactly one `Authorization` header, `Bearer`, whose token
/// starts with the delegated tag. Anything else is not for this resolver.
fn presented_token(request: &Request) -> Option<String> {
    let mut values = request.headers().get_all(AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && token.starts_with(&format!("{TOKEN_PREFIX}.")))
        .then(|| token.trim().to_owned())
}
