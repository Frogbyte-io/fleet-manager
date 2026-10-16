//! External provider accounts for API-token providers: Coolify and
//! Cloudflare (FM-1001).
//!
//! The shape generalizes the Proxmox account pattern where it fits: one
//! record per account, the token in Fleet's encrypted secret store behind
//! [`ExternalCredentialStore`] (record `external/<account-id>`), and
//! two-phase audit events around every mutation. There is no certificate
//! pinning here: these providers are reached over ordinary TLS.
//!
//! The token is write-only. It arrives on create or update, goes straight
//! to the secret store, and is resolved just in time for a probe. It never
//! appears in a returned record, an error, audit metadata, or a log.
//!
//! A probe classifies the outcome as `ok`, `unreachable`, `unauthorized`,
//! or `insufficient_permission` and stores the latest result on the
//! account. Probe outcomes are results, not errors: an unreachable service
//! is a successful probe that reports `unreachable`.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::audit::{AuditIntent, AuditMetadata};
use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::operation::AuditPort;
use crate::proxmox::CredentialStoreError;
use fleet_core::{
    ExternalProviderKind, MAX_TOKEN_SECRET_LEN, ProbeReport, SensitiveString, normalize_base_url,
    validate_label, validate_notes, validate_scope_id,
};

/// The latest probe result recorded on an account.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredProbe {
    /// What the probe found.
    pub report: ProbeReport,
    /// When the probe ran (epoch millis).
    pub checked_at: i64,
}

/// One configured external provider account. The credential is a
/// reference: the value lives in the encrypted store.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalAccount {
    /// The account's stable identity.
    pub id: String,
    /// The provider kind.
    pub kind: ExternalProviderKind,
    /// The operator-facing label, unique within the kind.
    pub label: String,
    /// The provider's API base URL, normalized without a trailing slash.
    pub base_url: String,
    /// The provider-side account id (Cloudflare account-owned tokens).
    pub scope_id: Option<String>,
    /// Free-form operator notes.
    pub notes: String,
    /// The most recent probe, when one ran since the last credential or
    /// endpoint change.
    pub last_probe: Option<StoredProbe>,
    /// When the account was created (epoch millis).
    pub created_at: i64,
    /// When the account last changed (epoch millis).
    pub updated_at: i64,
}

/// A validated creation record handed to the port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewExternalAccount {
    /// The provider kind.
    pub kind: ExternalProviderKind,
    /// The label.
    pub label: String,
    /// The normalized base URL.
    pub base_url: String,
    /// The provider-side account id, when any.
    pub scope_id: Option<String>,
    /// The notes.
    pub notes: String,
}

/// A request to create an account. Defaults are applied by the use case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateExternalAccount {
    /// The provider kind.
    pub kind: ExternalProviderKind,
    /// The label.
    pub label: String,
    /// The base URL; the kind's default when omitted.
    pub base_url: Option<String>,
    /// The provider-side account id (Cloudflare only).
    pub scope_id: Option<String>,
    /// The notes.
    pub notes: Option<String>,
}

/// A partial update. Absent fields are left alone.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateExternalAccount {
    /// A new label.
    pub label: Option<String>,
    /// A new base URL.
    pub base_url: Option<String>,
    /// A new scope id; `Some("")` clears it.
    pub scope_id: Option<String>,
    /// New notes.
    pub notes: Option<String>,
}

/// The account record port: durable account state.
#[async_trait]
pub trait ExternalAccountPort: fmt::Debug + Send + Sync {
    /// Creates an account, minting its identity.
    ///
    /// # Errors
    ///
    /// Fails when the label is taken for the kind or the backend errors.
    async fn create(&self, account: &NewExternalAccount) -> Result<ExternalAccount, String>;
    /// Reads one account.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn get(&self, id: &str) -> Result<ExternalAccount, String>;
    /// Lists accounts, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list(&self) -> Result<Vec<ExternalAccount>, String>;
    /// Replaces the mutable fields with the given values; `clear_probe`
    /// also drops the stored probe, whose subject changed.
    ///
    /// # Errors
    ///
    /// Fails when unknown, the label is taken, or the backend errors.
    async fn update(
        &self,
        id: &str,
        account: &NewExternalAccount,
        clear_probe: bool,
    ) -> Result<ExternalAccount, String>;
    /// Records the latest probe, or clears it with `None`.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn record_probe(
        &self,
        id: &str,
        probe: Option<&StoredProbe>,
    ) -> Result<ExternalAccount, String>;
    /// Removes the account.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn delete(&self, id: &str) -> Result<(), String>;
}

/// The credential store port: where each account's token lives between
/// calls. The composition root implements it over the encrypted secret
/// store with `external/<account-id>` record names.
#[async_trait]
pub trait ExternalCredentialStore: fmt::Debug + Send + Sync {
    /// Resolves the account's token, when stored.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read.
    async fn load(&self, account_id: &str) -> Result<Option<String>, CredentialStoreError>;
    /// Stores (replacing any previous) the account's token.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be written.
    async fn store(&self, account_id: &str, secret: &str) -> Result<(), CredentialStoreError>;
    /// Removes the account's token.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be written.
    async fn clear(&self, account_id: &str) -> Result<(), CredentialStoreError>;
}

/// The probe port. Provider crates implement it at the composition root;
/// it translates provider responses into a [`ProbeReport`].
#[async_trait]
pub trait ExternalProbePort: fmt::Debug + Send + Sync {
    /// Probes one account's endpoint with its token. Never returns the
    /// token in the report.
    async fn probe(
        &self,
        kind: ExternalProviderKind,
        base_url: &str,
        scope_id: Option<&str>,
        token: &SensitiveString,
    ) -> ProbeReport;
}

/// A use-case rejection, mapped onto public API errors by the adapter.
#[derive(Debug)]
pub enum ExternalAccountError {
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
    /// The label is taken within the kind.
    Conflict {
        /// The conflict detail.
        detail: String,
    },
    /// The account's token is not in the secret store.
    NoSecret {
        /// The account label.
        account: String,
    },
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

impl fmt::Display for ExternalAccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::Invalid { detail } => write!(f, "invalid request: {detail}"),
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Conflict { detail } => write!(f, "conflict: {detail}"),
            Self::NoSecret { account } => write!(
                f,
                "the credential for account {account} is not in the secret store; replace it"
            ),
            Self::Credentials(error) => write!(f, "{error}"),
            Self::Backend { context, detail } => {
                write!(f, "external account {context} failed: {detail}")
            }
        }
    }
}

impl std::error::Error for ExternalAccountError {}

/// The external account use cases.
#[derive(Debug)]
pub struct ExternalAccounts {
    accounts: Arc<dyn ExternalAccountPort>,
    credentials: Arc<dyn ExternalCredentialStore>,
    prober: Arc<dyn ExternalProbePort>,
    audit: Arc<dyn AuditPort>,
}

impl ExternalAccounts {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn ExternalAccountPort>,
        credentials: Arc<dyn ExternalCredentialStore>,
        prober: Arc<dyn ExternalProbePort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            accounts,
            credentials,
            prober,
            audit,
        }
    }

    fn require(
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        action: Permission,
        resource: Option<&str>,
    ) -> Result<(), ExternalAccountError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action,
                resource,
            },
        )
        .map(|_| ())
        .map_err(ExternalAccountError::Denied)
    }

    /// Lists accounts, optionally filtered by kind, bounded by the page
    /// limit. The cursor is the last account id of the previous page.
    ///
    /// # Errors
    ///
    /// Fails on denial, a stale cursor, or a backend failure.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        kind: Option<ExternalProviderKind>,
        limit: u32,
        after_id: Option<&str>,
    ) -> Result<Vec<ExternalAccount>, ExternalAccountError> {
        Self::require(authorizer, principal, Permission::ExternalAccountRead, None)?;
        let mut accounts =
            self.accounts
                .list()
                .await
                .map_err(|detail| ExternalAccountError::Backend {
                    context: "list",
                    detail,
                })?;
        if let Some(kind) = kind {
            accounts.retain(|account| account.kind == kind);
        }
        if let Some(after_id) = after_id {
            let Some(position) = accounts.iter().position(|account| account.id == after_id) else {
                return Err(ExternalAccountError::Invalid {
                    detail: "the cursor names no account in the list".to_owned(),
                });
            };
            accounts.drain(..=position);
        }
        accounts.truncate(usize::try_from(limit).unwrap_or(accounts.len()));
        Ok(accounts)
    }

    /// Reads one account.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown account, or a backend failure.
    pub async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<ExternalAccount, ExternalAccountError> {
        Self::require(authorizer, principal, Permission::ExternalAccountRead, None)?;
        self.require_account(id).await
    }

    /// Registers an account and stores its token. The audit intent lands
    /// before any mutation; the completion event after success.
    ///
    /// # Errors
    ///
    /// Fails on denial, a malformed request, a label conflict, or a
    /// backend failure.
    pub async fn create(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        request: CreateExternalAccount,
        token: &str,
    ) -> Result<ExternalAccount, ExternalAccountError> {
        Self::require(
            authorizer,
            principal,
            Permission::ExternalAccountConfig,
            None,
        )?;
        validate_token(token)?;
        let base_url = match (&request.base_url, request.kind.default_base_url()) {
            (Some(url), _) => url.clone(),
            (None, Some(default)) => default.to_owned(),
            (None, None) => {
                return Err(invalid(format!(
                    "a {} account needs a base URL",
                    request.kind
                )));
            }
        };
        let new = normalized(
            request.kind,
            &request.label,
            &base_url,
            request.scope_id.as_deref(),
            request.notes.as_deref().unwrap_or(""),
        )?;
        self.audit(
            principal,
            None,
            "external_account_creating",
            &[("kind", new.kind.id()), ("label", &new.label)],
        )
        .await?;
        let account = self.accounts.create(&new).await.map_err(backend_or_taken)?;
        if let Err(error) = self.credentials.store(&account.id, token).await {
            if let Err(rollback) = self.accounts.delete(&account.id).await {
                return Err(ExternalAccountError::Backend {
                    context: "credentials",
                    detail: format!(
                        "the secret write failed ({error}) and the rollback failed too: account {} lingers ({rollback})",
                        account.id
                    ),
                });
            }
            return Err(ExternalAccountError::Backend {
                context: "credentials",
                detail: error.to_string(),
            });
        }
        self.audit(
            principal,
            Some(&account.id),
            "external_account_created",
            &[("kind", account.kind.id()), ("label", &account.label)],
        )
        .await?;
        Ok(account)
    }

    /// Updates an account's label, endpoint, scope, or notes, and replaces
    /// its token when one is supplied. A change to the endpoint, scope, or
    /// token clears the stored probe: it no longer describes the account.
    ///
    /// # Errors
    ///
    /// Fails on denial, a malformed request, an unknown account, a label
    /// conflict, or a backend failure.
    pub async fn update(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        patch: UpdateExternalAccount,
        new_token: Option<&str>,
    ) -> Result<ExternalAccount, ExternalAccountError> {
        Self::require(
            authorizer,
            principal,
            Permission::ExternalAccountConfig,
            Some(id),
        )?;
        if let Some(token) = new_token {
            validate_token(token)?;
        }
        let current = self.require_account(id).await?;
        let scope = match patch.scope_id.as_deref() {
            Some("") => None,
            Some(value) => Some(value),
            None => current.scope_id.as_deref(),
        };
        let merged = normalized(
            current.kind,
            patch.label.as_deref().unwrap_or(&current.label),
            patch.base_url.as_deref().unwrap_or(&current.base_url),
            scope,
            patch.notes.as_deref().unwrap_or(&current.notes),
        )?;
        self.audit(
            principal,
            Some(id),
            "external_account_updating",
            &[
                ("kind", current.kind.id()),
                ("label", &merged.label),
                (
                    "credential",
                    if new_token.is_some() {
                        "replaced"
                    } else {
                        "kept"
                    },
                ),
            ],
        )
        .await?;
        if let Some(token) = new_token {
            self.credentials
                .store(id, token)
                .await
                .map_err(ExternalAccountError::Credentials)?;
        }
        let subject_changed = new_token.is_some()
            || merged.base_url != current.base_url
            || merged.scope_id != current.scope_id;
        let updated = self
            .accounts
            .update(id, &merged, subject_changed)
            .await
            .map_err(backend_or_taken)?;
        self.audit(
            principal,
            Some(id),
            "external_account_updated",
            &[("kind", updated.kind.id()), ("label", &updated.label)],
        )
        .await?;
        Ok(updated)
    }

    /// Removes an account and its token.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown account, or a backend failure.
    pub async fn delete(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<(), ExternalAccountError> {
        Self::require(
            authorizer,
            principal,
            Permission::ExternalAccountConfig,
            Some(id),
        )?;
        let account = self.require_account(id).await?;
        self.audit(
            principal,
            Some(id),
            "external_account_deleting",
            &[("kind", account.kind.id()), ("label", &account.label)],
        )
        .await?;
        // The credential goes first: a delete that leaves a token behind
        // is a failure, and a retry stays safe.
        self.credentials
            .clear(id)
            .await
            .map_err(ExternalAccountError::Credentials)?;
        self.accounts
            .delete(id)
            .await
            .map_err(|detail| ExternalAccountError::Backend {
                context: "delete",
                detail,
            })?;
        self.audit(
            principal,
            Some(id),
            "external_account_deleted",
            &[("kind", account.kind.id()), ("label", &account.label)],
        )
        .await?;
        Ok(())
    }

    /// Probes the account's endpoint with its stored token and records the
    /// classified result. Sending the token off-host is privileged, so the
    /// probe needs the config permission and is audited.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown account, a missing secret, or a backend
    /// failure. An unreachable or refusing service is a successful probe
    /// with that status, not an error.
    pub async fn probe(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<ExternalAccount, ExternalAccountError> {
        Self::require(
            authorizer,
            principal,
            Permission::ExternalAccountConfig,
            Some(id),
        )?;
        let account = self.require_account(id).await?;
        let token = self
            .credentials
            .load(id)
            .await
            .map_err(ExternalAccountError::Credentials)?
            .ok_or_else(|| ExternalAccountError::NoSecret {
                account: account.label.clone(),
            })?;
        self.audit(
            principal,
            Some(id),
            "external_account_probing",
            &[("kind", account.kind.id()), ("label", &account.label)],
        )
        .await?;
        let report = self
            .prober
            .probe(
                account.kind,
                &account.base_url,
                account.scope_id.as_deref(),
                &SensitiveString::new(token),
            )
            .await;
        let stored = StoredProbe {
            checked_at: fleet_core::SystemClock::now_unix_millis(),
            report,
        };
        let updated = self
            .accounts
            .record_probe(id, Some(&stored))
            .await
            .map_err(|detail| ExternalAccountError::Backend {
                context: "probe",
                detail,
            })?;
        self.audit(
            principal,
            Some(id),
            "external_account_probed",
            &[
                ("kind", account.kind.id()),
                ("label", &account.label),
                ("status", stored.report.status.id()),
            ],
        )
        .await?;
        Ok(updated)
    }

    async fn require_account(&self, id: &str) -> Result<ExternalAccount, ExternalAccountError> {
        self.accounts.get(id).await.map_err(|detail| {
            if detail.contains("not found") {
                ExternalAccountError::NotFound {
                    what: format!("account {id}"),
                }
            } else {
                ExternalAccountError::Backend {
                    context: "get",
                    detail,
                }
            }
        })
    }

    async fn audit(
        &self,
        principal: &ActingPrincipal,
        account_id: Option<&str>,
        event: &str,
        facts: &[(&str, &str)],
    ) -> Result<(), ExternalAccountError> {
        let backend = |error: String| ExternalAccountError::Backend {
            context: "audit",
            detail: error,
        };
        let mut metadata = AuditMetadata::default();
        metadata
            .insert("event", event)
            .map_err(|error| backend(error.to_string()))?;
        for (key, value) in facts {
            metadata
                .insert(key, value)
                .map_err(|error| backend(error.to_string()))?;
        }
        self.audit
            .record_intent(&AuditIntent {
                actor: principal.id.clone(),
                action: Permission::ExternalAccountConfig.id().to_owned(),
                resource: account_id.map(str::to_owned),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(backend)
    }
}

fn invalid(detail: impl Into<String>) -> ExternalAccountError {
    ExternalAccountError::Invalid {
        detail: detail.into(),
    }
}

fn validate_token(token: &str) -> Result<(), ExternalAccountError> {
    if token.is_empty()
        || token.len() > MAX_TOKEN_SECRET_LEN
        || token.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(invalid(
            "the token must be 1..=512 characters without whitespace",
        ));
    }
    Ok(())
}

fn normalized(
    kind: ExternalProviderKind,
    label: &str,
    base_url: &str,
    scope_id: Option<&str>,
    notes: &str,
) -> Result<NewExternalAccount, ExternalAccountError> {
    validate_label(label).map_err(|error| invalid(error.to_string()))?;
    validate_notes(notes).map_err(|error| invalid(error.to_string()))?;
    let base_url = normalize_base_url(base_url).map_err(|error| invalid(error.to_string()))?;
    if let Some(scope) = scope_id {
        if kind != ExternalProviderKind::Cloudflare {
            return Err(invalid(format!(
                "a {kind} account has no provider account id"
            )));
        }
        validate_scope_id(scope).map_err(|error| invalid(error.to_string()))?;
    }
    Ok(NewExternalAccount {
        kind,
        label: label.to_owned(),
        base_url,
        scope_id: scope_id.map(str::to_owned),
        notes: notes.to_owned(),
    })
}

fn backend_or_taken(detail: String) -> ExternalAccountError {
    if detail.contains("taken") {
        ExternalAccountError::Conflict { detail }
    } else if detail.contains("not found") {
        ExternalAccountError::NotFound { what: detail }
    } else {
        ExternalAccountError::Backend {
            context: "accounts",
            detail,
        }
    }
}
