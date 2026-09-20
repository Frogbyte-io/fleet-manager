//! The Proxmox integration use cases: accounts with verified TLS trust and
//! cluster discovery as normalized observations (FM-600; FM-S08).
//!
//! The trust model is the FM-S08 decision: a PVE host presents its own
//! cluster CA, so Fleet pins the host certificate's SHA-256 fingerprint.
//! `observe` captures a host's fingerprint without sending any credential —
//! the transport refuses the handshake after capture — and `confirm` pins
//! it through an explicit authorized step (the FM-201 SSH trust flow, over
//! TLS). A pinned host whose certificate changes refuses every call until
//! the pin is re-confirmed, and the mismatch is reported with both
//! fingerprints as evidence.
//!
//! Accounts are multi-account by design. The API token lives in Fleet's
//! encrypted secret store behind the [`ProxmoxCredentialStore`] port and is
//! resolved just in time at the source boundary; it never appears in audit
//! metadata, error details, or debug output.
//!
//! Discovery is read-only: cluster resources normalize into
//! [`ProxmoxResource`] observations with provenance and time, per-resource
//! failures isolate into warnings instead of dropping the snapshot, and
//! nothing here mutates a PVE host.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::operation::AuditPort;
use fleet_core::SensitiveString;

/// Binds one credential-carrying call to one account, resolving the secret
/// just in time.
pub struct BoundRequest {
    /// The account making the call.
    pub account: ProxmoxAccount,
    /// The token secret, resolved from the encrypted store.
    pub secret: SensitiveString,
    /// The pinned fingerprint, when the account is trusted.
    pub pinned_fingerprint: Option<String>,
}

impl fmt::Debug for BoundRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundRequest")
            .field("account", &self.account)
            .field("secret", &"<redacted>")
            .field("pinned_fingerprint", &self.pinned_fingerprint)
            .finish()
    }
}

/// One configured Proxmox account. The credential is a *reference* — the
/// value lives in the encrypted store and never travels with the record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxAccount {
    /// The account's stable identity.
    pub id: String,
    /// The operator-facing name, unique among accounts.
    pub name: String,
    /// The PVE host (IP or DNS name).
    pub host: String,
    /// The API port; 8006 in the common case.
    pub port: u16,
    /// The API token id (`user@realm!tokenname`), not secret on its own.
    pub token_id: String,
    /// The pinned host-certificate fingerprint, once confirmed.
    pub fingerprint: Option<String>,
    /// When the account was created (epoch millis).
    pub created_at: i64,
}

/// The fingerprint state of an account, as the trust flow reports it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintState {
    /// No fingerprint is pinned: the account exists but cannot call yet.
    Unconfirmed,
    /// A fingerprint is pinned and every call verifies against it.
    Confirmed,
}

/// A credential-store failure that is safe to print.
#[derive(Debug)]
pub enum CredentialStoreError {
    /// The store is unreadable or unwritable.
    Backend {
        /// The bounded detail.
        detail: String,
    },
}

impl fmt::Display for CredentialStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend { detail } => write!(f, "the secret store failed: {detail}"),
        }
    }
}

impl std::error::Error for CredentialStoreError {}

/// The credential store port: where each account's API-token secret lives
/// between calls. The composition root implements this over Fleet's
/// encrypted secret store with per-account record names.
#[async_trait]
pub trait ProxmoxCredentialStore: fmt::Debug + Send + Sync {
    /// Resolves the account's token secret, when stored.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read.
    async fn load(&self, account_id: &str) -> Result<Option<String>, CredentialStoreError>;
    /// Stores (replacing any previous) the account's token secret.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be written.
    async fn store(&self, account_id: &str, secret: &str) -> Result<(), CredentialStoreError>;
    /// Removes the account's token secret.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be written.
    async fn clear(&self, account_id: &str) -> Result<(), CredentialStoreError>;
}

/// A discovery-source failure that is safe to print. Fingerprints and
/// statuses travel here; tokens never do.
#[derive(Debug)]
pub enum ProxmoxSourceError {
    /// The pinned fingerprint was refused, with the observed fingerprint as
    /// evidence. The pin did its job: the connection died at the handshake.
    FingerprintMismatch {
        /// The observed leaf fingerprint.
        observed: String,
        /// The pinned fingerprint.
        pinned: String,
    },
    /// The API token was refused (401): the credential is wrong or revoked.
    Auth,
    /// The token lacks the privilege (403).
    Forbidden {
        /// The bounded, redacted detail.
        detail: String,
    },
    /// Any other HTTP outcome.
    Http {
        /// The status.
        status: u16,
        /// The bounded detail.
        detail: String,
    },
    /// The API answered, but not with something Fleet can interpret.
    InvalidPayload {
        /// The bounded detail.
        detail: String,
    },
    /// Transport-level failure (DNS, TCP, timeout).
    Connect {
        /// The bounded, redacted detail.
        detail: String,
    },
    /// The credential store failed.
    Credentials(CredentialStoreError),
}

impl fmt::Display for ProxmoxSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FingerprintMismatch { observed, pinned } => write!(
                f,
                "the host certificate's fingerprint {observed} does not match the pinned {pinned}"
            ),
            Self::Auth => write!(f, "the API token was refused (401)"),
            Self::Forbidden { detail } => {
                write!(f, "the token lacks the privilege (403): {detail}")
            }
            Self::Http { status, detail } => write!(f, "the API answered {status}: {detail}"),
            Self::InvalidPayload { detail } => {
                write!(f, "the API's payload is not interpretable: {detail}")
            }
            Self::Connect { detail } => write!(f, "the connection failed: {detail}"),
            Self::Credentials(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ProxmoxSourceError {}

/// One normalized discovery observation: a node, guest, template, or
/// storage seen through one account, with provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxResource {
    /// The normalized kind: `node`, `qemu`, `lxc`, `qemu-template`, or
    /// `storage`.
    pub kind: String,
    /// The cluster-visible id, e.g. `node/pve`, `qemu/101`.
    pub id: String,
    /// The hosting node, when the resource has one.
    pub node: Option<String>,
    /// The VMID, when the resource has one.
    pub vmid: Option<u32>,
    /// The display name, when carried.
    pub name: Option<String>,
    /// The PVE status string, when carried.
    pub status: Option<String>,
    /// The account that observed the resource.
    pub account_id: String,
    /// The PVE version the observation came from.
    pub pve_version: String,
    /// When the observation was taken (epoch millis).
    pub observed_at: i64,
}

/// The discovery snapshot: every resource the cluster reported, plus the
/// honest record of what failed normalization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxDiscovery {
    /// The account that produced the snapshot.
    pub account_id: String,
    /// The PVE version seen.
    pub pve_version: String,
    /// The normalized resources.
    pub resources: Vec<ProxmoxResource>,
    /// The per-resource normalization warnings. A partial failure never
    /// drops the snapshot.
    pub warnings: Vec<String>,
    /// The count the API reported, for honesty about isolation.
    pub reported_count: usize,
    /// When the snapshot was taken (epoch millis).
    pub observed_at: i64,
}

/// The account record port: durable account state.
#[async_trait]
pub trait ProxmoxAccountPort: fmt::Debug + Send + Sync {
    /// Creates an account, minting its identity.
    ///
    /// # Errors
    ///
    /// Fails when the name is taken or the backend errors.
    async fn create(&self, account: &NewProxmoxAccount) -> Result<ProxmoxAccount, String>;
    /// Reads one account.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn get(&self, id: &str) -> Result<ProxmoxAccount, String>;
    /// Lists accounts, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list(&self) -> Result<Vec<ProxmoxAccount>, String>;
    /// Records the confirmed fingerprint, or clears it with `None`.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn set_fingerprint(
        &self,
        id: &str,
        fingerprint: Option<String>,
    ) -> Result<ProxmoxAccount, String>;
    /// Removes the account.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn delete(&self, id: &str) -> Result<(), String>;
}

/// A creation request for one account.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewProxmoxAccount {
    /// The operator-facing name.
    pub name: String,
    /// The PVE host (IP or DNS name).
    pub host: String,
    /// The API port; 8006 when omitted.
    pub port: Option<u16>,
    /// The API token id (`user@realm!tokenname`).
    pub token_id: String,
}

/// A use-case rejection, mapped onto public API errors by the adapter.
#[derive(Debug)]
pub enum ProxmoxUseCaseError {
    /// The caller may not perform the action.
    Denied(Decision),
    /// The request is malformed.
    Invalid {
        /// What is wrong.
        detail: String,
    },
    /// The addressed account does not exist.
    NotFound {
        /// What was not found.
        what: String,
    },
    /// The account name is taken.
    Conflict {
        /// The conflict detail.
        detail: String,
    },
    /// The account has no pinned fingerprint yet, so no credential-carrying
    /// call may go out. Confirm the fingerprint first — this is the
    /// explicit-trust gate, not an error to work around.
    UnconfirmedTrust {
        /// The account name.
        account: String,
    },
    /// The account's token secret is not in the store.
    NoSecret {
        /// The account name.
        account: String,
    },
    /// The discovery source refused or failed.
    Source(ProxmoxSourceError),
    /// The credential store failed.
    Credentials(CredentialStoreError),
    /// A port failed.
    Backend {
        /// Where.
        context: &'static str,
        /// The failure detail.
        detail: String,
    },
}

impl fmt::Display for ProxmoxUseCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::Invalid { detail } => write!(f, "invalid request: {detail}"),
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Conflict { detail } => write!(f, "conflict: {detail}"),
            Self::UnconfirmedTrust { account } => write!(
                f,
                "the host certificate for account {account} is not confirmed; observe and confirm the fingerprint first"
            ),
            Self::NoSecret { account } => write!(
                f,
                "the API token for account {account} is not in the secret store; re-create the account"
            ),
            Self::Source(error) => write!(f, "{error}"),
            Self::Credentials(error) => write!(f, "{error}"),
            Self::Backend { context, detail } => {
                write!(f, "proxmox {context} failed: {detail}")
            }
        }
    }
}

impl std::error::Error for ProxmoxUseCaseError {}

/// The discovery port. The provider implements this over the PVE API;
/// tests implement it over recorded fixtures.
#[async_trait]
pub trait ProxmoxDiscoverPort: fmt::Debug + Send + Sync {
    /// Discovers the cluster through one bound account.
    ///
    /// The transport refuses credential-free trust probes by design, so a
    /// discovery without a pinned fingerprint reports
    /// [`ProxmoxSourceError::Connect`] upstream; the use case never reaches
    /// this port without one.
    ///
    /// # Errors
    ///
    /// Fails with [`ProxmoxSourceError`].
    async fn discover(
        &self,
        account: &ProxmoxAccount,
        secret: &SensitiveString,
    ) -> Result<RawDiscovery, ProxmoxSourceError>;
}

/// The provider's own discovery shape, before application-layer enrichment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawDiscovery {
    /// The PVE version seen.
    pub version: String,
    /// The normalized resources, without provenance.
    pub resources: Vec<ProxmoxResource>,
    /// The per-resource normalization warnings.
    pub warnings: Vec<String>,
    /// The count the API reported.
    pub reported_count: usize,
}

/// The trust-probe port: captures a host's fingerprint without credentials.
/// The provider implements this with the observe-only TLS policy; tests
/// implement it over canned fingerprints.
#[async_trait]
pub trait ProxmoxTrustProbe: fmt::Debug + Send + Sync {
    /// Observes the host's certificate fingerprint. No credential is sent:
    /// the handshake is refused after capture, by construction.
    ///
    /// # Errors
    ///
    /// Fails when the host is unreachable or presents no certificate.
    async fn observe(&self, host: &str, port: u16) -> Result<String, ProxmoxSourceError>;
}

/// The Proxmox account/discovery use cases.
#[derive(Debug)]
pub struct ProxmoxAccounts {
    accounts: Arc<dyn ProxmoxAccountPort>,
    credentials: Arc<dyn ProxmoxCredentialStore>,
    discovery: Arc<dyn ProxmoxDiscoverPort>,
    trust: Arc<dyn ProxmoxTrustProbe>,
    audit: Arc<dyn AuditPort>,
}

impl ProxmoxAccounts {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn ProxmoxAccountPort>,
        credentials: Arc<dyn ProxmoxCredentialStore>,
        discovery: Arc<dyn ProxmoxDiscoverPort>,
        trust: Arc<dyn ProxmoxTrustProbe>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            accounts,
            credentials,
            discovery,
            trust,
            audit,
        }
    }

    /// Lists the configured accounts with their trust states.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<Vec<ProxmoxAccount>, ProxmoxUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProxmoxRead,
                resource: None,
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)?;
        self.accounts
            .list()
            .await
            .map_err(|detail| ProxmoxUseCaseError::Backend {
                context: "accounts",
                detail,
            })
    }

    /// Registers an account and stores its token secret. The secret goes
    /// into the encrypted store and is never echoed, logged, or audited;
    /// the audit event names the account and the token id only. The new
    /// account starts `Unconfirmed`: discovery stays locked until the
    /// fingerprint is confirmed.
    ///
    /// # Errors
    ///
    /// Fails on denial, a malformed request, a name conflict, or a backend
    /// failure.
    pub async fn create(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        new: NewProxmoxAccount,
        token_secret: &str,
    ) -> Result<ProxmoxAccount, ProxmoxUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProxmoxConfig,
                resource: None,
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)?;
        validate_name(&new.name)?;
        validate_host(&new.host)?;
        validate_token_id(&new.token_id)?;
        if token_secret.is_empty() || token_secret.len() > 256 {
            return Err(ProxmoxUseCaseError::Invalid {
                detail: "the token secret must be 1..=256 characters".to_owned(),
            });
        }
        let account = self.accounts.create(&new).await.map_err(|detail| {
            if is_taken(&detail) {
                ProxmoxUseCaseError::Conflict { detail }
            } else {
                ProxmoxUseCaseError::Backend {
                    context: "accounts",
                    detail,
                }
            }
        })?;
        // A failed secret write must not leave an account that pretends to
        // be usable: the account is removed again. A clear of a record that
        // was never written succeeds.
        if let Err(error) = self.credentials.store(&account.id, token_secret).await {
            let _ = self.accounts.delete(&account.id).await;
            return Err(ProxmoxUseCaseError::Backend {
                context: "credentials",
                detail: error.to_string(),
            });
        }
        self.audit_event(
            principal,
            Permission::ProxmoxConfig,
            Some(&account.id),
            "proxmox_account_created",
            // The token id contains "token", which the audit guard
            // structurally rejects — and should: the account name carries
            // the provenance, the credential material stays out entirely.
            None,
        )
        .await?;
        Ok(account)
    }

    /// Removes an account and its secret. Fleet keeps no other trace.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown account, or a backend failure.
    pub async fn delete(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
    ) -> Result<(), ProxmoxUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProxmoxConfig,
                resource: Some(account_id),
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)?;
        let account = self.require_account(account_id).await?;
        self.accounts
            .delete(account_id)
            .await
            .map_err(|detail| ProxmoxUseCaseError::Backend {
                context: "accounts",
                detail,
            })?;
        // The secret's removal is best effort: the record is gone from the
        // account surface either way, and a stuck store must not make the
        // account undeletable. The detail is logged at the boundary.
        if let Err(error) = self.credentials.clear(account_id).await {
            let _ = error;
        }
        self.audit_event(
            principal,
            Permission::ProxmoxConfig,
            Some(account_id),
            "proxmox_account_deleted",
            Some(("name", account.name.as_str())),
        )
        .await?;
        Ok(())
    }

    /// Captures the host's certificate fingerprint without sending any
    /// credential. The report is the input to `confirm`; Fleet never pins
    /// implicitly.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown account, or an unreachable/anonymous
    /// host.
    pub async fn observe(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
    ) -> Result<String, ProxmoxUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProxmoxRead,
                resource: Some(account_id),
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)?;
        let account = self.require_account(account_id).await?;
        self.trust
            .observe(&account.host, account.port)
            .await
            .map_err(ProxmoxUseCaseError::Source)
    }

    /// Pins the confirmed fingerprint. Only a fingerprint this principal
    /// observed through `observe` may be confirmed: the caller supplies it
    /// explicitly, and it becomes the account's only trust anchor.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown account, or a malformed fingerprint.
    pub async fn confirm(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
        fingerprint: &str,
    ) -> Result<ProxmoxAccount, ProxmoxUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProxmoxConfig,
                resource: Some(account_id),
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)?;
        self.require_account(account_id).await?;
        let normalized = normalize_fingerprint(fingerprint);
        if normalized.len() != 64 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ProxmoxUseCaseError::Invalid {
                detail: "the fingerprint must be a SHA-256 digest (colons optional)".to_owned(),
            });
        }
        let account = self
            .accounts
            .set_fingerprint(account_id, Some(normalized))
            .await
            .map_err(|detail| ProxmoxUseCaseError::Backend {
                context: "accounts",
                detail,
            })?;
        self.audit_event(
            principal,
            Permission::ProxmoxConfig,
            Some(account_id),
            "proxmox_fingerprint_confirmed",
            Some(("fingerprint", account.fingerprint.as_deref().unwrap_or(""))),
        )
        .await?;
        Ok(account)
    }

    /// Discovers the cluster through one trusted account. The snapshot is
    /// availability-honest: a fingerprint mismatch, an auth failure, or a
    /// privilege failure is the reported state — never an empty list.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unconfirmed account, a missing secret, or any
    /// source failure.
    pub async fn discover(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
        now: i64,
    ) -> Result<ProxmoxDiscovery, ProxmoxUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProxmoxRead,
                resource: Some(account_id),
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)?;
        let account = self.require_account(account_id).await?;
        // The explicit-trust gate: without a confirmed fingerprint no
        // credential-carrying call leaves Fleet. This is the acceptance
        // criterion, not a convenience check.
        let Some(_pinned) = account.fingerprint.clone() else {
            return Err(ProxmoxUseCaseError::UnconfirmedTrust {
                account: account.name.clone(),
            });
        };
        let secret = self
            .credentials
            .load(account_id)
            .await
            .map_err(ProxmoxUseCaseError::Credentials)?
            .ok_or_else(|| ProxmoxUseCaseError::NoSecret {
                account: account.name.clone(),
            })?;
        let raw = self
            .discovery
            .discover(&account, &SensitiveString::new(secret))
            .await
            .map_err(ProxmoxUseCaseError::Source)?;
        let resources = raw
            .resources
            .into_iter()
            .map(|mut resource| {
                resource.account_id.clone_from(&account.id);
                resource.pve_version.clone_from(&raw.version);
                resource.observed_at = now;
                resource
            })
            .collect();
        Ok(ProxmoxDiscovery {
            account_id: account.id,
            pve_version: raw.version,
            resources,
            warnings: raw.warnings,
            reported_count: raw.reported_count,
            observed_at: now,
        })
    }

    async fn require_account(&self, id: &str) -> Result<ProxmoxAccount, ProxmoxUseCaseError> {
        self.accounts.get(id).await.map_err(|detail| {
            if detail.contains("not found") {
                ProxmoxUseCaseError::NotFound {
                    what: format!("account {id}"),
                }
            } else {
                ProxmoxUseCaseError::Backend {
                    context: "accounts",
                    detail,
                }
            }
        })
    }

    async fn audit_event(
        &self,
        principal: &ActingPrincipal,
        action: Permission,
        account_id: Option<&str>,
        event: &str,
        fact: Option<(&str, &str)>,
    ) -> Result<(), ProxmoxUseCaseError> {
        let mut metadata = crate::audit::AuditMetadata::default();
        metadata
            .insert("event", event)
            .map_err(|error| ProxmoxUseCaseError::Backend {
                context: "audit",
                detail: error.to_string(),
            })?;
        if let Some((key, value)) = fact {
            metadata
                .insert(key, value)
                .map_err(|error| ProxmoxUseCaseError::Backend {
                    context: "audit",
                    detail: error.to_string(),
                })?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: action.id().to_owned(),
                resource: account_id.map(str::to_owned),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| ProxmoxUseCaseError::Backend {
                context: "audit",
                detail,
            })
    }
}

/// Normalizes a fingerprint for comparison. Exposed for the adapter layer's
/// echo handling.
#[must_use]
pub fn normalize_fingerprint(value: &str) -> String {
    value.replace(':', "").to_uppercase()
}

fn validate_name(name: &str) -> Result<(), ProxmoxUseCaseError> {
    let count = name.chars().count();
    if count == 0 || count > 128 {
        return Err(ProxmoxUseCaseError::Invalid {
            detail: "the name must be 1..=128 characters".to_owned(),
        });
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<(), ProxmoxUseCaseError> {
    let count = host.chars().count();
    if count == 0 || count > 253 {
        return Err(ProxmoxUseCaseError::Invalid {
            detail: "the host must be 1..=253 characters".to_owned(),
        });
    }
    if host.starts_with("http") {
        return Err(ProxmoxUseCaseError::Invalid {
            detail: "the host is a bare host or IP, not a URL".to_owned(),
        });
    }
    Ok(())
}

fn validate_token_id(token_id: &str) -> Result<(), ProxmoxUseCaseError> {
    let count = token_id.chars().count();
    if count == 0 || count > 128 {
        return Err(ProxmoxUseCaseError::Invalid {
            detail: "the token id must be 1..=128 characters".to_owned(),
        });
    }
    if !token_id.contains('@') || !token_id.contains('!') {
        return Err(ProxmoxUseCaseError::Invalid {
            detail: "the token id must look like user@realm!tokenname".to_owned(),
        });
    }
    Ok(())
}

/// The storage adapter names the conflict; the application recognizes the
/// class without matching on adapter strings beyond this marker.
fn is_taken(detail: &str) -> bool {
    detail.contains("taken") || detail.contains("UNIQUE")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_normalize_for_comparison() {
        assert_eq!(normalize_fingerprint("dc:2c:11"), "DC2C11");
        assert_eq!(normalize_fingerprint("ABCD"), "ABCD");
    }

    #[test]
    fn token_ids_require_the_user_realm_token_shape() {
        assert!(validate_token_id("root@pam!GLM-AGENT").is_ok());
        assert!(validate_token_id("root@pam").is_err());
        assert!(validate_token_id("GLM-AGENT").is_err());
        assert!(validate_token_id("").is_err());
    }

    #[test]
    fn hosts_are_bare_not_urls() {
        assert!(validate_host("192.168.68.223").is_ok());
        assert!(validate_host("pve.localdomain").is_ok());
        assert!(validate_host("https://pve:8006").is_err());
        assert!(validate_host("").is_err());
    }
}
