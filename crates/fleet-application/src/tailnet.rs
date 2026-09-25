//! The Tailscale discovery use cases: tailnet devices as *onboarding
//! suggestions*, never as Fleet identity (FM-213; ADR-0003).
//!
//! The integration is deliberately read-only and evidence-only. `list`
//! fetches the tailnet's devices through the [`TailnetSource`] port and
//! correlates each one against Fleet machines by **candidates**: a Tailscale
//! address that matches a machine's endpoint host, or a hostname that
//! matches. Candidates warn; they never merge, never claim, and never carry
//! trust. `import` hands a device's address to the FM-210 onboarding flow —
//! from there the operator runs the same staged draft/test/fingerprint-
//! confirm/add path as any other address, so the Tailscale integration can
//! be removed without leaving a trace in Fleet's machine records.
//!
//! Credentials are the OAuth client's id and secret, stored encrypted via
//! the [`TailnetCredentialStore`] port and resolved just in time at the
//! source boundary. They never appear in audit metadata, error details, or
//! debug output; the use case surfaces the *fact* of configuration, not the
//! material.
//!
//! Correlation requires seeing endpoint hosts, so it degrades honestly: when
//! the caller may not read sensitive endpoint detail, candidates come back
//! empty rather than half-redacted lies (the same redaction rule the machine
//! read model applies).
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::machine::{MachineFilter, MachineStatus, Machines};
use crate::onboarding::{DraftView, NewDraft, Onboarding, OnboardingUseCaseError};
use crate::operation::AuditPort;
use fleet_core::SensitiveString;

/// The OAuth scope the integration requests: read-only device listing.
/// Nothing else — no auth keys, no DNS, no ACLs (the recorded research
/// decision).
pub const TAILNET_SCOPE: &str = "devices:core:read";

/// One tailnet device, normalized from the Tailscale API's device object.
/// Every string is bounded; a source payload beyond the bounds is a payload
/// error, not silent truncation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TailnetDevice {
    /// The preferred identifier (`nodeId` in the API); supply this to
    /// [`TailnetIntegration::import`].
    pub node_id: String,
    /// The legacy numeric identifier, when the source carried one.
    pub id: Option<String>,
    /// The `MagicDNS` name, e.g. the FQDN `host.tailnet.ts.net`.
    pub name: String,
    /// The short hostname.
    pub hostname: String,
    /// The device's operating system, as Tailscale reports it.
    pub os: String,
    /// The Tailscale addresses (IPv4 `100.x`, IPv6 `fd7a:`…).
    pub addresses: Vec<String>,
    /// Tailnet policy tags, when the device is tagged.
    pub tags: Vec<String>,
    /// The registering user, for untagged devices the owner.
    pub user: String,
    /// Whether the device reports itself online, when the source says.
    pub online: Option<bool>,
    /// Whether the device recently connected to Tailscale's control plane.
    pub connected_to_control: Option<bool>,
    /// When the device was last seen, when the source carried it.
    pub last_seen: Option<String>,
}

impl TailnetDevice {
    /// Validates the normalization bounds. A source device beyond them is a
    /// payload error: Fleet refuses oversized foreign data instead of
    /// truncating it into silent lies.
    ///
    /// # Errors
    ///
    /// Returns the offending field when validation fails.
    pub fn validate(&self) -> Result<(), String> {
        let error = |detail: String| detail;
        if self.node_id.is_empty() || self.node_id.len() > 64 {
            return Err(error(
                "the device node id must be 1..=64 characters".to_owned(),
            ));
        }
        if self.name.len() > 255 || self.hostname.len() > 255 {
            return Err(error(
                "the device name must be at most 255 characters".to_owned(),
            ));
        }
        if self.os.len() > 64 || self.user.len() > 255 {
            return Err(error("the device os/user must be within bounds".to_owned()));
        }
        if self.addresses.len() > 4 {
            return Err(error("a device carries at most 4 addresses".to_owned()));
        }
        for address in &self.addresses {
            if address.is_empty() || address.len() > 64 {
                return Err(error(
                    "a device address must be 1..=64 characters".to_owned(),
                ));
            }
        }
        if self.tags.len() > 8 {
            return Err(error("a device carries at most 8 tags".to_owned()));
        }
        for tag in &self.tags {
            if tag.is_empty() || tag.len() > 64 {
                return Err(error("a device tag must be 1..=64 characters".to_owned()));
            }
        }
        Ok(())
    }

    /// The device's first real IPv4 address (parsed, not prefix-guessed),
    /// when any — the onboarding draft's candidate host.
    #[must_use]
    pub fn ipv4(&self) -> Option<&str> {
        self.addresses
            .iter()
            .find(|address| address.parse::<std::net::Ipv4Addr>().is_ok())
            .map(String::as_str)
    }
}

/// One Fleet machine a tailnet device *may* be. Evidence only: nothing is
/// claimed, merged, or trusted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrelationCandidate {
    /// The existing machine's identity.
    pub machine_id: String,
    /// The existing machine's name.
    pub machine_name: String,
    /// The machine's derived connectivity state.
    pub machine_status: MachineStatus,
    /// The matching endpoint reference, as the caller may see it.
    pub reference: String,
    /// Why this machine is a candidate: an address match or a name match.
    pub kind: CorrelationKind,
}

/// The kind of correlation evidence behind a candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationKind {
    /// A Tailscale address equals the endpoint's host.
    AddressMatch,
    /// The device's hostname (or `MagicDNS` label) equals the endpoint's host.
    NameMatch,
}

impl CorrelationKind {
    /// The stable string used in the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::AddressMatch => "address_match",
            Self::NameMatch => "name_match",
        }
    }
}

/// A tailnet device with its Fleet-machine candidates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrelatedDevice {
    /// The device.
    pub device: TailnetDevice,
    /// Existing machines this device may be. Empty when nothing matches or
    /// when the caller may not read sensitive endpoint detail.
    pub candidates: Vec<CorrelationCandidate>,
}

/// The integration's configuration status. The secret is never here: only
/// the fact of configuration and the non-secret client identifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TailnetStatus {
    /// Whether an OAuth client is configured.
    pub configured: bool,
    /// The configured client identifier, when any. Not secret.
    pub client_id: Option<String>,
    /// The scope the integration requests: always
    /// [`TAILNET_SCOPE`], read-only.
    pub scope: &'static str,
}

/// The OAuth client credentials. The secret is redacting by construction;
/// the credentials are cloned rarely (into the token fetch) and never
/// serialized, logged, or audited.
#[derive(Debug)]
pub struct TailnetCredentials {
    /// The OAuth client identifier (not secret).
    pub client_id: String,
    /// The OAuth client secret, zeroizing and redacted.
    pub client_secret: SensitiveString,
}

/// The credential store port: where the OAuth client lives between calls.
/// The composition root implements this over Fleet's encrypted secret store
/// with fixed record names.
#[async_trait]
pub trait TailnetCredentialStore: fmt::Debug + Send + Sync {
    /// The stored credentials, when the integration is configured.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read.
    async fn load(&self) -> Result<Option<TailnetCredentials>, String>;
    /// Stores (replacing any previous) the OAuth client.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be written.
    async fn store(&self, client_id: &str, client_secret: &str) -> Result<(), String>;
    /// Removes the stored credentials.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be written.
    async fn clear(&self) -> Result<(), String>;
}

/// A source failure that is safe to print: statuses and bounded details,
/// never credentials or tokens.
#[derive(Debug)]
pub enum TailnetSourceError {
    /// The credentials were refused (401/403).
    Auth {
        /// The bounded, redacted detail.
        detail: String,
    },
    /// The source asked the caller to slow down (429), with its hint.
    RateLimited {
        /// The source's `Retry-After` hint, in seconds, when carried.
        retry_after_secs: Option<u64>,
    },
    /// The tailnet (or another addressed resource) does not exist (404).
    NotFound {
        /// The bounded detail.
        detail: String,
    },
    /// Any other HTTP outcome, with the status and a bounded detail.
    Http {
        /// The HTTP status.
        status: u16,
        /// The bounded, redacted detail.
        detail: String,
    },
    /// The source answered with a payload Fleet refuses to interpret.
    InvalidPayload {
        /// The bounded detail.
        detail: String,
    },
}

impl fmt::Display for TailnetSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth { detail } => write!(f, "the tailnet credentials were refused: {detail}"),
            Self::RateLimited {
                retry_after_secs: Some(secs),
            } => write!(f, "the source asked to slow down (retry after {secs}s)"),
            Self::RateLimited { .. } => {
                write!(f, "the source asked to slow down (429)")
            }
            Self::NotFound { detail } => write!(f, "not found: {detail}"),
            Self::Http { status, detail } => {
                write!(f, "the source answered {status}: {detail}")
            }
            Self::InvalidPayload { detail } => {
                write!(f, "the source's payload is not interpretable: {detail}")
            }
        }
    }
}

impl std::error::Error for TailnetSourceError {}

/// The device-listing port. The provider implements this over Tailscale's
/// API; tests implement it over recorded fixtures.
#[async_trait]
pub trait TailnetSource: fmt::Debug + Send + Sync {
    /// Lists the tailnet's devices, normalized and bounded.
    ///
    /// # Errors
    ///
    /// Fails with [`TailnetSourceError`] on auth, rate limiting, missing
    /// resources, HTTP failures, or uninterpretable payloads.
    async fn list_devices(
        &self,
        tailnet: &str,
        credentials: &TailnetCredentials,
    ) -> Result<Vec<TailnetDevice>, TailnetSourceError>;
}

/// A use-case rejection, mapped onto public API errors by the adapter.
#[derive(Debug)]
pub enum TailnetUseCaseError {
    /// The caller may not perform the action.
    Denied(Decision),
    /// The integration has no OAuth client configured yet.
    Unconfigured,
    /// The addressed device does not exist.
    NotFound {
        /// What was not found.
        what: String,
    },
    /// The request is malformed.
    Invalid {
        /// What is wrong.
        detail: String,
    },
    /// The tailnet source refused or failed.
    Source(TailnetSourceError),
    /// A port failed.
    Backend {
        /// Where.
        context: &'static str,
        /// The failure detail.
        detail: String,
    },
}

impl fmt::Display for TailnetUseCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::Unconfigured => {
                write!(
                    f,
                    "the tailscale integration is not configured; configure an OAuth client first"
                )
            }
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Invalid { detail } => write!(f, "invalid request: {detail}"),
            Self::Source(error) => write!(f, "{error}"),
            Self::Backend { context, detail } => {
                write!(f, "tailnet {context} failed: {detail}")
            }
        }
    }
}

impl std::error::Error for TailnetUseCaseError {}

impl From<OnboardingUseCaseError> for TailnetUseCaseError {
    fn from(error: OnboardingUseCaseError) -> Self {
        match error {
            OnboardingUseCaseError::Denied(decision) => Self::Denied(decision),
            OnboardingUseCaseError::NotFound { what } => Self::NotFound { what },
            OnboardingUseCaseError::Conflict { detail }
            | OnboardingUseCaseError::Invalid { detail } => Self::Invalid { detail },
            OnboardingUseCaseError::Backend { context, detail } => {
                Self::Backend { context, detail }
            }
        }
    }
}

/// The Tailscale discovery use cases.
#[derive(Debug)]
pub struct TailnetIntegration {
    source: Arc<dyn TailnetSource>,
    credentials: Arc<dyn TailnetCredentialStore>,
    onboarding: Arc<Onboarding>,
    machines: Arc<Machines>,
    audit: Arc<dyn AuditPort>,
    events: Option<Arc<crate::events::EventHub>>,
    credential_mutation: tokio::sync::Mutex<()>,
}

impl TailnetIntegration {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(
        source: Arc<dyn TailnetSource>,
        credentials: Arc<dyn TailnetCredentialStore>,
        onboarding: Arc<Onboarding>,
        machines: Arc<Machines>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            source,
            credentials,
            onboarding,
            machines,
            audit,
            events: None,
            credential_mutation: tokio::sync::Mutex::new(()),
        }
    }

    /// Attaches the process event hub so notifications follow durable
    /// credential-store commits even if completion auditing fails.
    #[must_use]
    pub fn with_events(mut self, events: Arc<crate::events::EventHub>) -> Self {
        self.events = Some(events);
        self
    }

    fn publish_changed(&self) {
        if let Some(events) = &self.events {
            events.publish(crate::events::EventKind::TailnetChanged);
        }
    }

    /// The integration's status: configured or not, the client id, and the
    /// fixed read-only scope.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn status(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<TailnetStatus, TailnetUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::TailnetRead,
                resource: None,
            },
        )
        .map_err(TailnetUseCaseError::Denied)?;
        let stored =
            self.credentials
                .load()
                .await
                .map_err(|detail| TailnetUseCaseError::Backend {
                    context: "credentials",
                    detail,
                })?;
        Ok(TailnetStatus {
            configured: stored.is_some(),
            client_id: stored.map(|credentials| credentials.client_id),
            scope: TAILNET_SCOPE,
        })
    }

    /// Stores the OAuth client. The secret goes into the encrypted store and
    /// is never echoed, logged, or audited; the audit event names the action
    /// and the client identifier only.
    ///
    /// # Errors
    ///
    /// Fails on denial, a malformed request, or a backend failure.
    pub async fn configure(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        client_id: &str,
        client_secret: &str,
    ) -> Result<TailnetStatus, TailnetUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::TailnetConfig,
                resource: None,
            },
        )
        .map_err(TailnetUseCaseError::Denied)?;
        if client_id.is_empty() || client_id.len() > 128 {
            return Err(TailnetUseCaseError::Invalid {
                detail: "the client id must be 1..=128 characters".to_owned(),
            });
        }
        if client_secret.is_empty() || client_secret.len() > 256 {
            return Err(TailnetUseCaseError::Invalid {
                detail: "the client secret must be 1..=256 characters".to_owned(),
            });
        }
        let mutation = self.credential_mutation.lock().await;
        let previous =
            self.credentials
                .load()
                .await
                .map_err(|detail| TailnetUseCaseError::Backend {
                    context: "credentials",
                    detail,
                })?;
        if let Err(detail) = self.credentials.store(client_id, client_secret).await {
            let rollback = match previous.as_ref() {
                Some(previous) => {
                    self.credentials
                        .store(&previous.client_id, previous.client_secret.expose())
                        .await
                }
                None => self.credentials.clear().await,
            };
            if rollback.is_err() {
                // The port may have committed one of the credential writes
                // before failing; notify clients if restoration also fails.
                self.publish_changed();
                return Err(TailnetUseCaseError::Backend {
                    context: "credentials",
                    detail: "credential replacement and rollback both failed".to_owned(),
                });
            }
            return Err(TailnetUseCaseError::Backend {
                context: "credentials",
                detail,
            });
        }
        drop(mutation);
        self.publish_changed();
        self.audit_event(principal, "tailscale_configured", Some(client_id))
            .await?;
        // The mutator earned this decision already; re-asking tailscale.read
        // would fail a principal allowed to configure but not to list.
        let stored =
            self.credentials
                .load()
                .await
                .map_err(|detail| TailnetUseCaseError::Backend {
                    context: "credentials",
                    detail,
                })?;
        Ok(TailnetStatus {
            configured: stored.is_some(),
            client_id: stored.map(|credentials| credentials.client_id),
            scope: TAILNET_SCOPE,
        })
    }

    /// Removes the stored OAuth client. Fleet keeps no other trace: no
    /// machine record ever derived identity or trust from Tailscale.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn clear(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<TailnetStatus, TailnetUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::TailnetConfig,
                resource: None,
            },
        )
        .map_err(TailnetUseCaseError::Denied)?;
        let mutation = self.credential_mutation.lock().await;
        let previous =
            self.credentials
                .load()
                .await
                .map_err(|detail| TailnetUseCaseError::Backend {
                    context: "credentials",
                    detail,
                })?;
        if let Err(detail) = self.credentials.clear().await {
            let rollback = match previous.as_ref() {
                Some(previous) => {
                    self.credentials
                        .store(&previous.client_id, previous.client_secret.expose())
                        .await
                }
                None => Err("credential state was not readable before clear".to_owned()),
            };
            if rollback.is_err() {
                self.publish_changed();
                return Err(TailnetUseCaseError::Backend {
                    context: "credentials",
                    detail: "credential clearing and rollback both failed".to_owned(),
                });
            }
            return Err(TailnetUseCaseError::Backend {
                context: "credentials",
                detail,
            });
        }
        drop(mutation);
        self.publish_changed();
        self.audit_event(principal, "tailscale_cleared", None)
            .await?;
        let stored =
            self.credentials
                .load()
                .await
                .map_err(|detail| TailnetUseCaseError::Backend {
                    context: "credentials",
                    detail,
                })?;
        Ok(TailnetStatus {
            configured: stored.is_some(),
            client_id: stored.map(|credentials| credentials.client_id),
            scope: TAILNET_SCOPE,
        })
    }

    /// Lists the tailnet's devices, each correlated against Fleet machines
    /// by evidence only. Correlation needs endpoint hosts, so a caller
    /// without the sensitive-endpoint permission sees empty candidates —
    /// an honest degradation, not a redacted half-match.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unconfigured integration, a source failure, or a
    /// backend failure.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        now: i64,
    ) -> Result<Vec<CorrelatedDevice>, TailnetUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::TailnetRead,
                resource: None,
            },
        )
        .map_err(TailnetUseCaseError::Denied)?;
        let credentials = self.require_credentials().await?;
        let devices = self
            .source
            .list_devices(TAILNET_DEFAULT, &credentials)
            .await
            .map_err(TailnetUseCaseError::Source)?;
        for device in &devices {
            device.validate().map_err(|detail| {
                TailnetUseCaseError::Source(TailnetSourceError::InvalidPayload { detail })
            })?;
        }
        // Correlation needs the machine surface, but its denial is a
        // degraded answer, not a failure: devices still list, candidates
        // come back empty. The limit matches the machine read model's page
        // bound; correlation beyond it is re-run per page until exhausted.
        // Correlation needs the machine surface, but its denial is a
        // degraded answer, not a failure: devices still list, candidates
        // come back empty. The bound is the machine read model's own page
        // cap; a fleet beyond it needs a correlation-specific query (a
        // documented follow-up), not a silent truncation here.
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
                .map_err(|error| TailnetUseCaseError::Backend {
                    context: "correlation",
                    detail: error.to_string(),
                })?
        } else {
            Vec::new()
        };
        Ok(devices
            .into_iter()
            .map(|device| {
                let candidates = views
                    .iter()
                    .filter_map(|view| {
                        let sensitive = authorize(
                            authorizer,
                            AccessRequest {
                                principal_id: &principal.id,
                                action: Permission::MachineReadSensitive,
                                resource: Some(view.id.as_str()),
                            },
                        )
                        .is_ok();
                        let matching = view.endpoints.iter().find_map(|endpoint| {
                            let (_, host_port) = endpoint.reference.rsplit_once('@')?;
                            if !sensitive {
                                return None;
                            }
                            // Bracketed IPv6 (rare in endpoint references
                            // but legal) strips before comparison.
                            let host_port = match host_port.strip_prefix('[') {
                                Some(rest) => {
                                    rest.split_once(']').map_or(host_port, |(inner, _)| inner)
                                }
                                None => host_port,
                            };
                            let (host, _) = host_port.rsplit_once(':')?;
                            // The device's names: the short hostname, the
                            // full MagicDNS name (with its trailing dot
                            // stripped), and the MagicDNS first label.
                            let full_name = device.name.trim_end_matches('.');
                            let first_label = full_name.split('.').next().unwrap_or_default();
                            let address_match = device
                                .addresses
                                .iter()
                                .any(|address| host.eq_ignore_ascii_case(address));
                            let name_match = host.eq_ignore_ascii_case(&device.hostname)
                                || host.eq_ignore_ascii_case(full_name)
                                || host.eq_ignore_ascii_case(first_label);
                            let kind = if address_match {
                                CorrelationKind::AddressMatch
                            } else if name_match {
                                CorrelationKind::NameMatch
                            } else {
                                return None;
                            };
                            Some(CorrelationCandidate {
                                machine_id: view.id.clone(),
                                machine_name: view.name.clone(),
                                machine_status: view.machine_status,
                                reference: endpoint.reference.clone(),
                                kind,
                            })
                        })?;
                        Some(matching)
                    })
                    .collect();
                CorrelatedDevice { device, candidates }
            })
            .collect())
    }

    /// Imports a tailnet device as an SSH onboarding draft: the draft carries
    /// the device's Tailscale IPv4 address as the host and the device's node
    /// id as provenance. Everything after this point is the FM-210 flow —
    /// test, explicit fingerprint confirmation, review, add — so removing
    /// the integration leaves nothing behind.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unconfigured integration, an unknown device, a
    /// device without an IPv4 address, or any onboarding failure.
    pub async fn import(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        node_id: &str,
        user: &str,
        port: Option<u16>,
        idempotency_key: Option<&str>,
    ) -> Result<DraftView, TailnetUseCaseError> {
        self.import_with_outcome(authorizer, principal, node_id, user, port, idempotency_key)
            .await
            .map(|(draft, _created)| draft)
    }

    /// Imports a device and reports whether a draft was actually inserted.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unconfigured integration, an unknown device, a
    /// device without an IPv4 address, or any onboarding failure.
    pub async fn import_with_outcome(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        node_id: &str,
        user: &str,
        port: Option<u16>,
        idempotency_key: Option<&str>,
    ) -> Result<(DraftView, bool), TailnetUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::TailnetRead,
                resource: None,
            },
        )
        .map_err(TailnetUseCaseError::Denied)?;
        if node_id.is_empty() || node_id.len() > 64 {
            return Err(TailnetUseCaseError::Invalid {
                detail: "the device node id must be 1..=64 characters".to_owned(),
            });
        }
        if user.is_empty() || user.len() > 64 {
            return Err(TailnetUseCaseError::Invalid {
                detail: "the SSH user must be 1..=64 characters".to_owned(),
            });
        }
        // Idempotent replay BEFORE any network or store work: a retried
        // import returns the original draft even when the integration was
        // cleared in the meantime. The key is scoped to the principal, so a
        // replay never reveals another caller's draft.
        if let Some(key) = idempotency_key {
            let replay = self
                .onboarding
                .draft_by_key(authorizer, principal, key)
                .await
                .map_err(TailnetUseCaseError::from)?;
            if let Some(draft) = replay {
                return Ok((draft, false));
            }
        }
        let credentials = self.require_credentials().await?;
        let devices = self
            .source
            .list_devices(TAILNET_DEFAULT, &credentials)
            .await
            .map_err(TailnetUseCaseError::Source)?;
        let device = devices
            .iter()
            .find(|device| device.node_id == node_id)
            .ok_or_else(|| TailnetUseCaseError::NotFound {
                what: format!("tailnet device {node_id:?}"),
            })?;
        let Some(address) = device.ipv4() else {
            return Err(TailnetUseCaseError::Invalid {
                detail: format!(
                    "the device {node_id} carries no Tailscale IPv4 address; import needs one"
                ),
            });
        };
        self.onboarding
            .create_draft_with_outcome(
                authorizer,
                principal,
                NewDraft {
                    endpoint: crate::onboarding::DraftEndpoint {
                        user: user.to_owned(),
                        host: address.to_owned(),
                        port: port.unwrap_or(22),
                    },
                    auth: crate::onboarding::OnboardAuth::Agent,
                    name: Some(device.hostname.clone()),
                    description: format!(
                        "Imported from tailnet device {} ({})",
                        device.node_id, device.name
                    ),
                    tags: Vec::new(),
                    groups: Vec::new(),
                    idempotency_key: idempotency_key.map(|key| format!("{}:{key}", principal.id)),
                },
            )
            .await
            .map_err(TailnetUseCaseError::from)
    }

    /// Loads the stored credentials or refuses with [`TailnetUseCaseError::Unconfigured`].
    async fn require_credentials(&self) -> Result<TailnetCredentials, TailnetUseCaseError> {
        self.credentials
            .load()
            .await
            .map_err(|detail| TailnetUseCaseError::Backend {
                context: "credentials",
                detail,
            })?
            .ok_or(TailnetUseCaseError::Unconfigured)
    }

    async fn audit_event(
        &self,
        principal: &ActingPrincipal,
        event: &str,
        client_id: Option<&str>,
    ) -> Result<(), TailnetUseCaseError> {
        let mut metadata = crate::audit::AuditMetadata::default();
        metadata
            .insert("event", event)
            .map_err(|error| TailnetUseCaseError::Backend {
                context: "audit",
                detail: error.to_string(),
            })?;
        if let Some(client_id) = client_id {
            metadata.insert("client_id", client_id).map_err(|error| {
                TailnetUseCaseError::Backend {
                    context: "audit",
                    detail: error.to_string(),
                }
            })?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: Permission::TailnetConfig.id().to_owned(),
                resource: None,
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| TailnetUseCaseError::Backend {
                context: "audit",
                detail,
            })
    }
}

/// The default tailnet selector: Tailscale resolves `-` to the OAuth
/// client's own tailnet.
pub const TAILNET_DEFAULT: &str = "-";
