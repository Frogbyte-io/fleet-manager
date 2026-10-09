//! Delegated credentials: scoped, short-lived bearer tokens for CI and
//! agents (ADR 0011).
//!
//! A credential has an owner, an expiry, and an allow-list of Lab templates
//! or template versions. The token is shown once at issue time and stored
//! only as a hash. The use cases here are the operator's issue, list, and
//! revoke; resolving a presented token into a request principal is the
//! caller-resolution adapter's job (`fleet-auth`), using [`CredentialStore`]
//! and the [`GrantBook`] so the authorizer can decide on the credential's
//! allow-list.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use fleet_core::IdGenerator as _;

use crate::audit::{AuditIntent, AuditMetadata};
use crate::authz::{
    AccessRequest, Authorizer, Decision, Permission, authorize, delegated_principal_id,
};
use crate::operation::AuditPort;

/// The longest lifetime a credential may be issued for: a day. Short-lived
/// is part of the model; a longer-running need issues a new credential.
pub const MAX_TTL_SECONDS: u64 = 86_400;
/// The shortest lifetime, so a typo cannot issue an unusable credential.
pub const MIN_TTL_SECONDS: u64 = 60;
/// The most allow-list entries one credential may carry.
pub const MAX_ALLOW_ENTRIES: usize = 32;
/// The longest owner label.
pub const MAX_OWNER_LEN: usize = 63;
/// The longest free-text label.
pub const MAX_LABEL_LEN: usize = 128;
/// The longest allow-list entry.
pub const MAX_ENTRY_LEN: usize = 128;

/// The stored shape of a delegated credential. It never contains the token
/// or its hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegatedCredential {
    /// The credential's identity.
    pub id: String,
    /// The owner label: the ownership identity of the leases it creates.
    pub owner: String,
    /// An operator's free-text label.
    pub label: String,
    /// Allowed template ids: every published version of each.
    pub templates: Vec<String>,
    /// Allowed template version ids.
    pub versions: Vec<String>,
    /// The administrator that issued it.
    pub issued_by: String,
    /// When it was issued (epoch milliseconds).
    pub issued_at: i64,
    /// When it expires (epoch milliseconds).
    pub expires_at: i64,
    /// When it was revoked, when it was.
    pub revoked_at: Option<i64>,
    /// Who revoked it.
    pub revoked_by: Option<String>,
}

/// Where a credential is in its life.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialStatus {
    /// Usable now.
    Active,
    /// Past its expiry.
    Expired,
    /// Revoked by an operator.
    Revoked,
}

impl CredentialStatus {
    /// The stable id shown in the API.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

impl DelegatedCredential {
    /// The credential's status at `now`. Revocation wins over expiry.
    #[must_use]
    pub fn status(&self, now: i64) -> CredentialStatus {
        if self.revoked_at.is_some() {
            CredentialStatus::Revoked
        } else if now >= self.expires_at {
            CredentialStatus::Expired
        } else {
            CredentialStatus::Active
        }
    }

    /// The principal id requests under this credential act as.
    #[must_use]
    pub fn principal_id(&self) -> String {
        delegated_principal_id(&self.owner, &self.id)
    }

    /// The grant the authorizer decides the template allow-list on.
    #[must_use]
    pub fn grant(&self) -> DelegatedGrant {
        DelegatedGrant {
            templates: self.templates.clone(),
            versions: self.versions.clone(),
        }
    }
}

/// A credential's allow-list, as the authorizer sees it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DelegatedGrant {
    /// Allowed template ids.
    pub templates: Vec<String>,
    /// Allowed template version ids.
    pub versions: Vec<String>,
}

impl DelegatedGrant {
    /// Whether a template version is on the allow-list.
    #[must_use]
    pub fn allows_version(&self, template_id: &str, version_id: &str) -> bool {
        self.templates.iter().any(|entry| entry == template_id)
            || self.versions.iter().any(|entry| entry == version_id)
    }
}

/// The resource string `lab.template.use` is decided on.
#[must_use]
pub fn template_use_resource(template_id: &str, version_id: &str) -> String {
    format!("{template_id}/{version_id}")
}

/// The grants of the credentials that authenticated recently, keyed by
/// principal id.
///
/// The caller resolver validates the presented token against the store on
/// every request and then registers the grant here, so the authorizer (which
/// is synchronous and has no storage) decides on the allow-list that
/// request was authenticated with. An unregistered principal has no grant,
/// which the authorizer treats as no access.
#[derive(Debug, Default)]
pub struct GrantBook {
    grants: RwLock<HashMap<String, Arc<DelegatedGrant>>>,
}

impl GrantBook {
    /// An empty book.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the grant for a principal, replacing an earlier one.
    ///
    /// # Panics
    ///
    /// Panics only if a writer panicked while holding the lock.
    pub fn register(&self, principal_id: &str, grant: DelegatedGrant) {
        self.grants
            .write()
            .expect("the grant book lock must not be poisoned")
            .insert(principal_id.to_owned(), Arc::new(grant));
    }

    /// Forgets a principal's grant.
    ///
    /// # Panics
    ///
    /// Panics only if a writer panicked while holding the lock.
    pub fn forget(&self, principal_id: &str) {
        self.grants
            .write()
            .expect("the grant book lock must not be poisoned")
            .remove(principal_id);
    }

    /// The registered grant of a principal.
    ///
    /// # Panics
    ///
    /// Panics only if a writer panicked while holding the lock.
    #[must_use]
    pub fn get(&self, principal_id: &str) -> Option<Arc<DelegatedGrant>> {
        self.grants
            .read()
            .expect("the grant book lock must not be poisoned")
            .get(principal_id)
            .cloned()
    }
}

/// A stored credential with the hash of its token.
#[derive(Clone, Debug)]
pub struct StoredCredential {
    /// The credential.
    pub credential: DelegatedCredential,
    /// The lowercase hex SHA-256 of the token.
    pub token_hash: String,
}

/// The credential persistence port.
#[async_trait]
pub trait CredentialStore: fmt::Debug + Send + Sync {
    /// Stores a new credential with its token hash.
    ///
    /// # Errors
    ///
    /// Fails when the store refuses.
    async fn insert(
        &self,
        credential: &DelegatedCredential,
        token_hash: &str,
    ) -> Result<(), String>;
    /// Lists credentials, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the store refuses.
    async fn list(&self) -> Result<Vec<DelegatedCredential>, String>;
    /// Reads one credential.
    ///
    /// # Errors
    ///
    /// Fails when the store refuses.
    async fn get(&self, id: &str) -> Result<Option<DelegatedCredential>, String>;
    /// Finds a credential by the hash of its token.
    ///
    /// # Errors
    ///
    /// Fails when the store refuses.
    async fn find_by_hash(&self, token_hash: &str) -> Result<Option<StoredCredential>, String>;
    /// Marks a credential revoked. Revoking a revoked credential keeps its
    /// first revocation. Answers the credential, or `None` when unknown.
    ///
    /// # Errors
    ///
    /// Fails when the store refuses.
    async fn revoke(
        &self,
        id: &str,
        revoked_by: &str,
        now: i64,
    ) -> Result<Option<DelegatedCredential>, String>;
}

/// The cryptographic port for tokens: randomness and hashing.
pub trait CredentialCrypto: fmt::Debug + Send + Sync {
    /// Generates a token. Shown once; never stored.
    fn generate_token(&self) -> String;
    /// The durable form of a token (the lowercase hex of its SHA-256).
    fn hash_token(&self, token: &str) -> String;
    /// Compares two token hashes in constant time.
    fn hashes_equal(&self, left: &str, right: &str) -> bool;
}

/// What an operator asks for.
#[derive(Clone, Debug)]
pub struct IssueCredential {
    /// The owner label.
    pub owner: String,
    /// The lifetime in seconds.
    pub ttl_seconds: u64,
    /// Allowed template ids.
    pub templates: Vec<String>,
    /// Allowed template version ids.
    pub versions: Vec<String>,
    /// A free-text label (may be empty).
    pub label: String,
}

/// A freshly issued credential: the only place the token ever exists.
#[derive(Clone)]
pub struct IssuedCredential {
    /// The stored record.
    pub credential: DelegatedCredential,
    /// The token, to be shown once.
    pub token: String,
}

impl fmt::Debug for IssuedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedCredential")
            .field("credential", &self.credential)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// A credential use-case failure.
#[derive(Debug)]
pub enum CredentialError {
    /// The caller may not do this.
    Denied(Decision),
    /// The request is malformed.
    Invalid {
        /// What is wrong.
        detail: String,
    },
    /// The credential does not exist.
    NotFound {
        /// What was looked up.
        what: String,
    },
    /// A port failed.
    Backend {
        /// The failed step.
        context: &'static str,
        /// The failure.
        detail: String,
    },
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::Invalid { detail } => write!(f, "invalid: {detail}"),
            Self::NotFound { what } => write!(f, "{what} was not found"),
            Self::Backend { context, detail } => write!(f, "{context} failed: {detail}"),
        }
    }
}

impl std::error::Error for CredentialError {}

/// The operator's credential use cases.
#[derive(Debug)]
pub struct Credentials {
    store: Arc<dyn CredentialStore>,
    audit: Arc<dyn AuditPort>,
    crypto: Arc<dyn CredentialCrypto>,
    grants: Arc<GrantBook>,
}

/// Why a presented token did not authenticate.
#[derive(Debug)]
pub enum AuthenticationFailure {
    /// No credential has this token. Nothing identifies the caller, so
    /// nothing is audited.
    Unknown,
    /// The credential exists but is expired or revoked; the attempt is
    /// audited under its owner.
    Inactive(CredentialStatus),
    /// The store or the ledger failed; the request is refused.
    Backend(String),
}

/// A request authenticated by a delegated credential.
#[derive(Clone, Debug)]
pub struct Authenticated {
    /// The credential.
    pub credential: DelegatedCredential,
    /// The principal id the request acts as.
    pub principal_id: String,
}

fn valid_owner(owner: &str) -> bool {
    let mut chars = owner.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && owner.len() <= MAX_OWNER_LEN
        && owner
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

fn valid_entry(entry: &str) -> bool {
    !entry.is_empty()
        && entry.len() <= MAX_ENTRY_LEN
        && entry
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
}

/// Validates an issue request and answers its lifetime in milliseconds.
fn validate_issue(request: &IssueCredential) -> Result<i64, CredentialError> {
    if !valid_owner(&request.owner) {
        return Err(CredentialError::Invalid {
            detail: format!(
                "the owner must be 1..={MAX_OWNER_LEN} characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit"
            ),
        });
    }
    if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&request.ttl_seconds) {
        return Err(CredentialError::Invalid {
            detail: format!("the ttl must be {MIN_TTL_SECONDS}..={MAX_TTL_SECONDS} seconds"),
        });
    }
    if request.templates.is_empty() && request.versions.is_empty() {
        return Err(CredentialError::Invalid {
            detail: "the allow-list needs at least one template or template version".to_owned(),
        });
    }
    if request.templates.len() + request.versions.len() > MAX_ALLOW_ENTRIES
        || request
            .templates
            .iter()
            .chain(&request.versions)
            .any(|entry| !valid_entry(entry))
    {
        return Err(CredentialError::Invalid {
            detail: format!(
                "the allow-list takes at most {MAX_ALLOW_ENTRIES} ids of 1..={MAX_ENTRY_LEN} letters, digits, '.', '_', '-' or '@'"
            ),
        });
    }
    if request.label.chars().count() > MAX_LABEL_LEN || request.label.chars().any(char::is_control)
    {
        return Err(CredentialError::Invalid {
            detail: format!("the label must be at most {MAX_LABEL_LEN} printable characters"),
        });
    }
    let ttl_millis = i64::try_from(request.ttl_seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .ok_or_else(|| CredentialError::Invalid {
            detail: "the ttl is out of range".to_owned(),
        })?;
    Ok(ttl_millis)
}

impl Credentials {
    /// Composes the use cases.
    #[must_use]
    pub fn new(
        store: Arc<dyn CredentialStore>,
        audit: Arc<dyn AuditPort>,
        crypto: Arc<dyn CredentialCrypto>,
        grants: Arc<GrantBook>,
    ) -> Self {
        Self {
            store,
            audit,
            crypto,
            grants,
        }
    }

    /// Validates a request and issues the credential.
    ///
    /// # Errors
    ///
    /// Fails on denial, an invalid request, or a backend failure.
    pub async fn issue(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        request: IssueCredential,
        now: i64,
    ) -> Result<IssuedCredential, CredentialError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::CredentialIssue,
                resource: None,
            },
        )
        .map_err(CredentialError::Denied)?;
        let ttl_millis = validate_issue(&request)?;
        let mut templates = request.templates;
        let mut versions = request.versions;
        templates.sort();
        templates.dedup();
        versions.sort();
        versions.dedup();
        let credential = DelegatedCredential {
            id: fleet_core::UuidV7Generator.next_resource_id().to_string(),
            owner: request.owner,
            label: request.label,
            templates,
            versions,
            issued_by: principal_id.to_owned(),
            issued_at: now,
            expires_at: now.saturating_add(ttl_millis),
            revoked_at: None,
            revoked_by: None,
        };
        let token = self.crypto.generate_token();
        let token_hash = self.crypto.hash_token(&token);
        // The audit intent names the credential, never the token or hash.
        let mut metadata = AuditMetadata::default();
        for (key, value) in [
            ("owner", credential.owner.clone()),
            ("expiresAt", credential.expires_at.to_string()),
            ("templates", credential.templates.join(",")),
            ("versions", credential.versions.join(",")),
        ] {
            metadata
                .insert(key, &value)
                .map_err(|error| CredentialError::Backend {
                    context: "audit",
                    detail: error.to_string(),
                })?;
        }
        self.audit
            .record_intent(&AuditIntent {
                actor: principal_id.to_owned(),
                action: Permission::CredentialIssue.id().to_owned(),
                resource: Some(credential.id.clone()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| CredentialError::Backend {
                context: "audit",
                detail,
            })?;
        self.store
            .insert(&credential, &token_hash)
            .await
            .map_err(|detail| CredentialError::Backend {
                context: "credentials",
                detail,
            })?;
        Ok(IssuedCredential { credential, token })
    }

    /// Authenticates a presented token for one request: looks it up by
    /// hash, compares the stored hash in constant time, checks expiry and
    /// revocation against `now`, registers the grant for the authorizer, and
    /// appends a `credential.use` audit intent under the credential's
    /// principal. The ledger refusing the append refuses the request.
    ///
    /// `route` is the method and path only: never the query, a header, or
    /// the token.
    ///
    /// # Errors
    ///
    /// Fails when the token is unknown, expired, or revoked, or when a port
    /// fails.
    pub async fn authenticate(
        &self,
        token: &str,
        method: &str,
        path: &str,
        now: i64,
    ) -> Result<Authenticated, AuthenticationFailure> {
        let presented_hash = self.crypto.hash_token(token);
        let stored = self
            .store
            .find_by_hash(&presented_hash)
            .await
            .map_err(AuthenticationFailure::Backend)?
            .filter(|stored| {
                self.crypto
                    .hashes_equal(&stored.token_hash, &presented_hash)
            })
            .ok_or(AuthenticationFailure::Unknown)?;
        let credential = stored.credential;
        let principal_id = credential.principal_id();
        let status = credential.status(now);
        let mut metadata = AuditMetadata::default();
        for (key, value) in [
            ("method", method.chars().take(16).collect::<String>()),
            ("path", path.chars().take(256).collect::<String>()),
            ("credentialId", credential.id.clone()),
        ] {
            metadata
                .insert(key, &value)
                .map_err(|error| AuthenticationFailure::Backend(error.to_string()))?;
        }
        let active = status == CredentialStatus::Active;
        self.audit
            .record_intent(&AuditIntent {
                actor: principal_id.clone(),
                action: "credential.use".to_owned(),
                resource: Some(credential.id.clone()),
                decision: if active {
                    Decision::allow()
                } else {
                    Decision::deny(crate::authz::ReasonId::CredentialInactive)
                },
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(AuthenticationFailure::Backend)?;
        if !active {
            self.grants.forget(&principal_id);
            return Err(AuthenticationFailure::Inactive(status));
        }
        self.grants.register(&principal_id, credential.grant());
        Ok(Authenticated {
            credential,
            principal_id,
        })
    }

    /// Lists the credentials' metadata.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
    ) -> Result<Vec<DelegatedCredential>, CredentialError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::CredentialRead,
                resource: None,
            },
        )
        .map_err(CredentialError::Denied)?;
        self.store
            .list()
            .await
            .map_err(|detail| CredentialError::Backend {
                context: "credentials",
                detail,
            })
    }

    /// Revokes a credential. The next request it authenticates is refused.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown credential, or a backend failure.
    pub async fn revoke(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        id: &str,
        now: i64,
    ) -> Result<DelegatedCredential, CredentialError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::CredentialRevoke,
                resource: Some(id),
            },
        )
        .map_err(CredentialError::Denied)?;
        let existing = self
            .store
            .get(id)
            .await
            .map_err(|detail| CredentialError::Backend {
                context: "credentials",
                detail,
            })?
            .ok_or_else(|| CredentialError::NotFound {
                what: format!("credential {id}"),
            })?;
        let mut metadata = AuditMetadata::default();
        metadata
            .insert("owner", &existing.owner)
            .map_err(|error| CredentialError::Backend {
                context: "audit",
                detail: error.to_string(),
            })?;
        self.audit
            .record_intent(&AuditIntent {
                actor: principal_id.to_owned(),
                action: Permission::CredentialRevoke.id().to_owned(),
                resource: Some(id.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| CredentialError::Backend {
                context: "audit",
                detail,
            })?;
        let revoked = self
            .store
            .revoke(id, principal_id, now)
            .await
            .map_err(|detail| CredentialError::Backend {
                context: "credentials",
                detail,
            })?
            .ok_or_else(|| CredentialError::NotFound {
                what: format!("credential {id}"),
            })?;
        self.grants.forget(&revoked.principal_id());
        Ok(revoked)
    }
}
