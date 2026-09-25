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
use crate::machine::{MachineFilter, MachineUseCaseError, MachineView, Machines};
use crate::operation::AuditPort;
use fleet_core::{CapabilityFact, CapabilityStatus, SensitiveString, Timestamp};

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
    /// The fingerprint the trust probe last observed, not yet confirmed.
    /// `confirm` must match this; a caller cannot pin a digest it never
    /// observed through the probe.
    pub observed_fingerprint: Option<String>,
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
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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

/// One discovered guest with its Fleet-machine association candidates
/// (evidence only). The guest's provider facts ride along with the
/// account/version/time provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssociatedGuest {
    /// The guest's provider facts.
    pub guest: ProviderGuest,
    /// The PVE version the observation came from.
    pub pve_version: String,
    /// When the observation was taken (epoch millis).
    pub observed_at: i64,
    /// The Fleet machines this guest may be — evidence, never merged.
    pub candidates: Vec<AssociationCandidate>,
}

/// The application's view of one guest: the provider shape plus the
/// provenance the discovery call attached.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderGuest {
    /// The normalized kind: `qemu` or `lxc`.
    pub kind: String,
    /// The cluster-visible id, e.g. `qemu/101`.
    pub id: String,
    /// The hosting node.
    pub node: Option<String>,
    /// The VMID.
    pub vmid: Option<u32>,
    /// The display name, when carried.
    pub name: Option<String>,
    /// The PVE status string, when carried.
    pub status: Option<String>,
    /// The config's MAC addresses, normalized.
    pub macs: Vec<String>,
    /// The guest-agent view, when the guest has one (QEMU only).
    pub agent: Option<ProviderAgent>,
    /// The bounded per-surface warnings.
    pub warnings: Vec<String>,
}

/// The guest-agent view as the application sees it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAgent {
    /// The agent answered `info`: installed and reachable.
    pub online: bool,
    /// The agent version, when carried.
    pub version: Option<String>,
    /// The guest's OS name, when `get-osinfo` answered.
    pub os_name: Option<String>,
    /// The guest's kernel release, when carried.
    pub kernel: Option<String>,
    /// The network interfaces the agent saw.
    pub interfaces: Vec<ProviderInterface>,
}

/// One guest network interface as the application sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInterface {
    /// The interface name inside the guest.
    pub name: String,
    /// The normalized MAC, when carried.
    pub mac: Option<String>,
    /// The interface's addresses.
    pub addresses: Vec<String>,
}

/// Why a guest may be one Fleet machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssociationKind {
    /// A guest MAC matches a machine's recorded network fact.
    MacMatch,
    /// A guest-agent address matches a machine endpoint's host.
    AddressMatch,
    /// The guest's name matches the machine's name.
    NameMatch,
}

impl AssociationKind {
    /// The stable string used in the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::MacMatch => "mac_match",
            Self::AddressMatch => "address_match",
            Self::NameMatch => "name_match",
        }
    }
}

/// One Fleet machine a guest may be, with the evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssociationCandidate {
    /// The existing machine's identity.
    pub machine_id: String,
    /// The existing machine's name.
    pub machine_name: String,
    /// The machine's derived connectivity state.
    pub machine_status: String,
    /// Why: the association kind's stable id.
    pub kind: String,
    /// The evidence value that matched (the MAC, address, or name).
    pub evidence: String,
}

/// The guest-discovery port over one trusted account. The provider
/// implements this over the PVE API; tests implement it over fixtures.
#[async_trait]
pub trait ProxmoxGuestDiscoverPort: fmt::Debug + Send + Sync {
    /// Discovers the account's guests with their config MACs and agent
    /// views.
    ///
    /// # Errors
    ///
    /// Fails with [`ProxmoxSourceError`].
    async fn guest_discover(
        &self,
        account: &ProxmoxAccount,
        secret: &SensitiveString,
    ) -> Result<RawGuestDiscovery, ProxmoxSourceError>;
}

/// The provider's own guest-discovery shape, before application-layer
/// enrichment. Provenance is attached by [`ProxmoxAccounts::guests`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawGuestDiscovery {
    /// The PVE version seen.
    pub version: String,
    /// The guests, provenance pending.
    pub guests: Vec<ProviderGuest>,
    /// The cluster-level warnings.
    pub warnings: Vec<String>,
}

/// The guest-discovery snapshot: the associated guests plus the honest
/// record of what the cluster reported but could not be turned into a
/// guest (entries missing a node or VMID, malformed rows).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestSnapshot {
    /// The account that produced the snapshot.
    pub account_id: String,
    /// The PVE version seen.
    pub pve_version: String,
    /// The discovered guests with their association candidates.
    pub guests: Vec<AssociatedGuest>,
    /// The cluster-level warnings, per isolated entry.
    pub warnings: Vec<String>,
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
    /// Records the fingerprint the trust probe observed, for the confirm
    /// step to match against. `None` clears the observation.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn set_observed_fingerprint(
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
/// The resources' provenance fields (`account_id`, `pve_version`,
/// `observed_at`) are placeholders here; [`ProxmoxAccounts::discover`]
/// overwrites all three with authoritative values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawDiscovery {
    /// The PVE version seen.
    pub version: String,
    /// The normalized resources, provenance pending.
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
    guests: Arc<dyn ProxmoxGuestDiscoverPort>,
    trust: Arc<dyn ProxmoxTrustProbe>,
    machines: Arc<Machines>,
    audit: Arc<dyn AuditPort>,
    events: Option<Arc<crate::events::EventHub>>,
}

impl ProxmoxAccounts {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn ProxmoxAccountPort>,
        credentials: Arc<dyn ProxmoxCredentialStore>,
        discovery: Arc<dyn ProxmoxDiscoverPort>,
        guests: Arc<dyn ProxmoxGuestDiscoverPort>,
        trust: Arc<dyn ProxmoxTrustProbe>,
        machines: Arc<Machines>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            accounts,
            credentials,
            discovery,
            guests,
            trust,
            machines,
            audit,
            events: None,
        }
    }

    /// Attaches the process event hub so notifications follow durable commits,
    /// even when a later completion audit fails.
    #[must_use]
    pub fn with_events(mut self, events: Arc<crate::events::EventHub>) -> Self {
        self.events = Some(events);
        self
    }

    fn publish_changed(&self) {
        if let Some(events) = &self.events {
            events.publish(crate::events::EventKind::ProxmoxChanged);
        }
    }

    /// Lists the configured accounts with their trust states, bounded by
    /// the page limit. The cursor is the last account id of the previous
    /// page; the list is ordered newest first, so a following page really
    /// advances.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        limit: u32,
        after_id: Option<&str>,
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
        let mut accounts =
            self.accounts
                .list()
                .await
                .map_err(|detail| ProxmoxUseCaseError::Backend {
                    context: "accounts",
                    detail,
                })?;
        if let Some(after_id) = after_id {
            let Some(position) = accounts.iter().position(|account| account.id == after_id) else {
                return Err(ProxmoxUseCaseError::Invalid {
                    detail: "the cursor names no account in the list".to_owned(),
                });
            };
            accounts.drain(..=position);
        }
        accounts.truncate(usize::try_from(limit).unwrap_or(accounts.len()));
        Ok(accounts)
    }

    /// Registers an account and stores its token secret. The secret goes
    /// into the encrypted store and is never echoed, logged, or audited;
    /// the audit intent lands before any mutation, carrying the account
    /// name as provenance (the token id contains "token", which the audit
    /// guard structurally rejects — and should). The new account starts
    /// `Unconfirmed`: discovery stays locked until the fingerprint is
    /// confirmed.
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
        if let Some(port) = new.port
            && port == 0
        {
            return Err(ProxmoxUseCaseError::Invalid {
                detail: "the port must be 1..=65535".to_owned(),
            });
        }
        if token_secret.is_empty() || token_secret.len() > 256 {
            return Err(ProxmoxUseCaseError::Invalid {
                detail: "the token secret must be 1..=256 characters".to_owned(),
            });
        }
        // The audit intent lands BEFORE any mutation: a failure to audit
        // prevents the mutation, so durable state can never exist without
        // its intent.
        self.audit_event(
            principal,
            Permission::ProxmoxConfig,
            None,
            "proxmox_account_creating",
            Some(("name", new.name.as_str())),
        )
        .await?;
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
        // be usable: the account is removed again. If even the rollback
        // fails, the orphan is named — the name stays unusable until an
        // operator removes it, which is honest rather than silent.
        if let Err(error) = self.credentials.store(&account.id, token_secret).await {
            if let Err(rollback) = self.accounts.delete(&account.id).await {
                return Err(ProxmoxUseCaseError::Backend {
                    context: "credentials",
                    detail: format!(
                        "the secret write failed ({error}) and the rollback failed too: account {} lingers ({rollback})",
                        account.id
                    ),
                });
            }
            return Err(ProxmoxUseCaseError::Backend {
                context: "credentials",
                detail: error.to_string(),
            });
        }
        self.publish_changed();
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
        self.audit_event(
            principal,
            Permission::ProxmoxConfig,
            Some(account_id),
            "proxmox_account_deleting",
            Some(("name", account.name.as_str())),
        )
        .await?;
        // The secret is removed first: a delete that leaves the credential
        // behind is a failure, not a success with a footnote. The account
        // row is only removed once the credential is gone, so a retry is
        // always safe and a half-deleted state cannot hold a secret.
        self.credentials
            .clear(account_id)
            .await
            .map_err(ProxmoxUseCaseError::Credentials)?;
        self.accounts
            .delete(account_id)
            .await
            .map_err(|detail| ProxmoxUseCaseError::Backend {
                context: "accounts",
                detail,
            })?;
        self.publish_changed();
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
        let observed = self
            .trust
            .observe(&account.host, account.port)
            .await
            .map_err(ProxmoxUseCaseError::Source)?;
        // The observation is persisted before it is reported, so `confirm`
        // can only pin what this probe actually saw.
        self.accounts
            .set_observed_fingerprint(account_id, Some(observed.clone()))
            .await
            .map_err(|detail| ProxmoxUseCaseError::Backend {
                context: "accounts",
                detail,
            })?;
        self.publish_changed();
        Ok(observed)
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
        let account = self.require_account(account_id).await?;
        let normalized = normalize_fingerprint(fingerprint);
        if normalized.len() != 64 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ProxmoxUseCaseError::Invalid {
                detail: "the fingerprint must be a SHA-256 digest (colons optional)".to_owned(),
            });
        }
        // Only a fingerprint this probe observed may be pinned: a digest
        // typed from memory or copied from elsewhere is refused, so trust
        // always flows through the observe step.
        let Some(observed) = account.observed_fingerprint.as_deref() else {
            return Err(ProxmoxUseCaseError::Invalid {
                detail:
                    "observe the host's fingerprint first; confirm pins only what the probe saw"
                        .to_owned(),
            });
        };
        if normalize_fingerprint(observed) != normalized {
            return Err(ProxmoxUseCaseError::Invalid {
                detail:
                    "the supplied fingerprint does not match the observed one; observe again if the host changed"
                        .to_owned(),
            });
        }
        // The audit intent lands BEFORE the mutation, per the two-phase
        // audit rule; the completion event follows success, so an intent
        // without its completion is itself evidence of an aborted flow.
        self.audit_event(
            principal,
            Permission::ProxmoxConfig,
            Some(account_id),
            "proxmox_fingerprint_confirming",
            Some(("fingerprint", normalized.as_str())),
        )
        .await?;
        let account = self
            .accounts
            .set_fingerprint(account_id, Some(normalized))
            .await
            .map_err(|detail| ProxmoxUseCaseError::Backend {
                context: "accounts",
                detail,
            })?;
        self.publish_changed();
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
        let account = self.trusted_account(account_id).await?;
        let secret = self.require_secret(&account).await?;
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

    /// Lists the account's guests with their Fleet-machine association
    /// candidates. Correlation needs the machine surface, so it degrades
    /// honestly: guests still list, candidates come back empty when the
    /// caller may not read machine detail — the FM-213 rule.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unconfirmed account, a missing secret, or any
    /// source failure.
    pub async fn guests(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
        now: i64,
    ) -> Result<GuestSnapshot, ProxmoxUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProxmoxRead,
                resource: Some(account_id),
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)?;
        let account = self.trusted_account(account_id).await?;
        let secret = self.require_secret(&account).await?;
        let raw = self
            .guests
            .guest_discover(&account, &SensitiveString::new(secret))
            .await
            .map_err(ProxmoxUseCaseError::Source)?;
        // The machine surface: a degraded answer is empty candidates, not a
        // failure. Correlation needs sensitive endpoint detail; without it
        // the candidates are empty rather than half-redacted lies.
        let machine_read = authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineRead,
                resource: None,
            },
        )
        .is_ok();
        let views = if machine_read {
            self.machines
                .list(authorizer, principal, &MachineFilter::default(), 200, now)
                .await
                .map_err(|error| ProxmoxUseCaseError::Backend {
                    context: "association",
                    detail: error.to_string(),
                })?
        } else {
            Vec::new()
        };
        let associated = raw
            .guests
            .into_iter()
            .map(|guest| {
                let candidates = views
                    .iter()
                    .filter_map(|view| {
                        // Association evidence lives in endpoint hosts and
                        // recorded network facts: without the sensitive
                        // read the candidates are empty rather than
                        // half-redacted lies (the FM-213 rule).
                        let sensitive = authorize(
                            authorizer,
                            AccessRequest {
                                principal_id: &principal.id,
                                action: Permission::MachineReadSensitive,
                                resource: Some(view.id.as_str()),
                            },
                        )
                        .is_ok();
                        if !sensitive {
                            return None;
                        }
                        association_candidate(&guest, view)
                    })
                    .collect();
                AssociatedGuest {
                    guest,
                    pve_version: raw.version.clone(),
                    observed_at: now,
                    candidates,
                }
            })
            .collect();
        Ok(GuestSnapshot {
            account_id: account.id,
            pve_version: raw.version,
            guests: associated,
            warnings: raw.warnings,
            observed_at: now,
        })
    }

    /// Records one guest's facts onto a confirmed Fleet machine as
    /// capability facts through the machine funnel. The association is the
    /// caller's confirmed claim — the candidates are evidence, and this
    /// mutation turns the evidence into recorded observations under the
    /// machine's own authorization and audit.
    ///
    /// # Errors
    ///
    /// Fails on denial (either surface), an unknown account or machine, an
    /// unconfirmed account, or a source failure.
    pub async fn observe_guest(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        account_id: &str,
        vmid: u32,
        machine_id: &str,
        now: i64,
    ) -> Result<(), ProxmoxUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProxmoxRead,
                resource: Some(account_id),
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)?;
        // The machine funnel's authorization is checked BEFORE any network
        // work: a caller who may read Proxmox but not write the machine's
        // facts never causes a credential-bearing request.
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineUpdate,
                resource: Some(machine_id),
            },
        )
        .map_err(ProxmoxUseCaseError::Denied)?;
        let account = self.trusted_account(account_id).await?;
        let secret = self.require_secret(&account).await?;
        let raw = self
            .guests
            .guest_discover(&account, &SensitiveString::new(secret))
            .await
            .map_err(ProxmoxUseCaseError::Source)?;
        let guest = raw
            .guests
            .into_iter()
            .find(|guest| guest.vmid == Some(vmid))
            .ok_or_else(|| ProxmoxUseCaseError::NotFound {
                what: format!("guest {vmid}"),
            })?;
        // The machine funnel authorizes and audits the capability write;
        // the Proxmox read is audited here.
        self.audit_event(
            principal,
            Permission::ProxmoxRead,
            Some(account_id),
            "proxmox_guest_observed",
            Some(("vmid", &vmid.to_string())),
        )
        .await?;
        let facts = guest_facts(&guest, &raw.version, now);
        self.machines
            .record_capabilities(authorizer, principal, machine_id, &facts)
            .await
            .map_err(|error| match error {
                MachineUseCaseError::Denied(decision) => ProxmoxUseCaseError::Denied(decision),
                MachineUseCaseError::NotFound { what } => ProxmoxUseCaseError::NotFound { what },
                MachineUseCaseError::Conflict { detail }
                | MachineUseCaseError::Invalid { detail } => {
                    ProxmoxUseCaseError::Invalid { detail }
                }
                MachineUseCaseError::Backend { context, detail } => {
                    ProxmoxUseCaseError::Backend { context, detail }
                }
            })
    }

    /// The account with the explicit-trust gate applied: without a
    /// confirmed fingerprint no credential-carrying call leaves Fleet.
    async fn trusted_account(
        &self,
        account_id: &str,
    ) -> Result<ProxmoxAccount, ProxmoxUseCaseError> {
        let account = self.require_account(account_id).await?;
        if account.fingerprint.is_none() {
            return Err(ProxmoxUseCaseError::UnconfirmedTrust {
                account: account.name.clone(),
            });
        }
        Ok(account)
    }

    /// The account's token secret, resolved just in time.
    async fn require_secret(
        &self,
        account: &ProxmoxAccount,
    ) -> Result<String, ProxmoxUseCaseError> {
        self.credentials
            .load(&account.id)
            .await
            .map_err(ProxmoxUseCaseError::Credentials)?
            .ok_or_else(|| ProxmoxUseCaseError::NoSecret {
                account: account.name.clone(),
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

/// The association evidence between one guest and one machine view, when
/// any. MAC evidence outranks address evidence outranks name evidence; the
/// first match wins so a candidate reports its strongest reason.
#[must_use]
fn association_candidate(
    guest: &ProviderGuest,
    view: &MachineView,
) -> Option<AssociationCandidate> {
    // The machine's recorded network facts, when the view carries them.
    let machine_macs: Vec<&str> = view
        .capabilities
        .iter()
        .filter(|fact| fact.namespace == "net" && fact.name.starts_with("mac"))
        .filter_map(|fact| fact.value.as_deref())
        .collect();
    // MAC evidence: the agent's interfaces for QEMU, the config's `netN`
    // MACs for every guest kind (LXC has no agent but has config MACs).
    let guest_macs = guest
        .agent
        .iter()
        .flat_map(|agent| &agent.interfaces)
        .filter_map(|interface| interface.mac.as_deref())
        .chain(guest.macs.iter().map(String::as_str));
    for mac in guest_macs {
        if machine_macs
            .iter()
            .any(|machine_mac| machine_mac.eq_ignore_ascii_case(mac))
        {
            return Some(AssociationCandidate {
                machine_id: view.id.clone(),
                machine_name: view.name.clone(),
                machine_status: view.machine_status.id().to_owned(),
                kind: AssociationKind::MacMatch.id().to_owned(),
                evidence: mac.to_owned(),
            });
        }
    }
    // The guest-agent addresses against the machine endpoints' hosts. The
    // shared reference parser strips userinfo and IPv6 brackets, so
    // bracketed IPv6 evidence compares bare.
    let endpoint_hosts: Vec<&str> = view
        .endpoints
        .iter()
        .filter_map(|endpoint| crate::onboarding::reference_host(&endpoint.reference))
        .collect();
    for interface in guest.agent.iter().flat_map(|agent| &agent.interfaces) {
        for address in &interface.addresses {
            if endpoint_hosts
                .iter()
                .any(|host| host.eq_ignore_ascii_case(address))
            {
                return Some(AssociationCandidate {
                    machine_id: view.id.clone(),
                    machine_name: view.name.clone(),
                    machine_status: view.machine_status.id().to_owned(),
                    kind: AssociationKind::AddressMatch.id().to_owned(),
                    evidence: address.clone(),
                });
            }
        }
    }
    // The name match: the guest's display name against the machine's name,
    // case-insensitive, when both carry one.
    if let Some(name) = &guest.name
        && view.name.eq_ignore_ascii_case(name)
    {
        return Some(AssociationCandidate {
            machine_id: view.id.clone(),
            machine_name: view.name.clone(),
            machine_status: view.machine_status.id().to_owned(),
            kind: AssociationKind::NameMatch.id().to_owned(),
            evidence: name.clone(),
        });
    }
    None
}

/// The capability facts one guest contributes to its confirmed machine:
/// the guest identity, the agent's availability and version, the OS and
/// kernel when the agent answered, and the MACs. Provenance is the
/// account's observation path; every fact carries the observation time.
#[must_use]
fn guest_facts(guest: &ProviderGuest, pve_version: &str, now: i64) -> Vec<CapabilityFact> {
    let source = format!("proxmox/{pve_version}");
    let mut facts = Vec::new();
    let mut push = |name: &str, value: Option<String>, status: CapabilityStatus| {
        facts.push(CapabilityFact {
            namespace: "pve".to_owned(),
            name: name.to_owned(),
            value,
            status,
            observed_at: Timestamp::from_unix_millis(now),
            source: source.clone(),
        });
    };
    push("guest", Some(guest.id.clone()), CapabilityStatus::Known);
    if let Some(vmid) = guest.vmid {
        push("vmid", Some(vmid.to_string()), CapabilityStatus::Known);
    }
    if let Some(node) = &guest.node {
        push("node", Some(node.clone()), CapabilityStatus::Known);
    }
    match &guest.agent {
        Some(agent) if agent.online => {
            push("agent", agent.version.clone(), CapabilityStatus::Known);
            if let Some(os) = &agent.os_name {
                push("os", Some(os.clone()), CapabilityStatus::Known);
            }
            if let Some(kernel) = &agent.kernel {
                push("kernel", Some(kernel.clone()), CapabilityStatus::Known);
            }
        }
        // A QEMU guest whose agent did not answer: unavailable is honest —
        // the guest may be off, not agentless.
        Some(_) => push("agent", None, CapabilityStatus::Unavailable),
        // LXC has no qemu-guest-agent by design: the absence is known.
        None => push("agent", None, CapabilityStatus::Unknown),
    }
    for (index, mac) in guest.macs.iter().enumerate() {
        facts.push(CapabilityFact {
            namespace: "net".to_owned(),
            name: format!("mac{index}"),
            value: Some(mac.clone()),
            status: CapabilityStatus::Known,
            observed_at: Timestamp::from_unix_millis(now),
            source: source.clone(),
        });
    }
    facts
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
    if host.contains("://") {
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
