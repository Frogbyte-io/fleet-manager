//! The domain lookup enricher (FM-1020, ADR 0016 point 9): public RDAP and
//! DNS observations recorded against `domain` Registry entries.
//!
//! Observations attach beside an entry in SQLite and never overwrite Fleet
//! Git. What the lookups saw is compared with what the entry records at
//! read time ([`diff::assess`]): per-field `in_sync`/`changed`/`unknown`,
//! derived warnings (registrar mismatch, nameservers against `dnsHost`,
//! expiry inside a window, auto-renew off while expiring), and a suggested
//! `set` patch that a person or agent may apply and publish through Git.
//!
//! No registrar credential is involved: RDAP and DNS are public. The
//! lookups are outbound requests to third parties, so they are a
//! mutation of observations behind the catalog's `registry.observe`
//! permission, audited, rate limited per RDAP server, and scheduled
//! conservatively (see [`EnrichSettings`]). Reads stay under
//! `registry.read`.
#![warn(missing_docs)]

pub mod diff;
mod limiter;
pub mod model;

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;

use crate::audit::{AuditIntent, AuditMetadata};
use crate::authz::{AccessRequest, Authorizer, Permission, authorize};
use crate::operation::AuditPort;
use crate::project::ProjectUseCaseError;
use crate::registry::{
    Answered, EntryCursor, RegistryEntryFilter, RegistryEntryRecord, RegistryReadModel,
};

pub use limiter::RateLimiter;
pub use model::{
    Assessment, DnsObservation, DnsRecords, DnsStatus, DomainObservation, FieldDiff, FieldState,
    RdapObservation, RdapStatus, Severity, SuggestedField, Warning, WarningCode,
};

/// The registry type the enricher observes.
pub const DOMAIN_TYPE: &str = "domain";

/// The environment variable holding the sweep interval in seconds
/// (`0` turns the scheduled sweep off).
pub const INTERVAL_VAR: &str = "FLEET_REGISTRY_ENRICH_INTERVAL_SECONDS";
/// The environment variable holding the expiry window in days.
pub const WINDOW_VAR: &str = "FLEET_REGISTRY_EXPIRY_WINDOW_DAYS";
/// The default sweep interval: once a day. Registration data changes on the
/// scale of days, public RDAP servers are shared, and a day is frequent
/// enough to see a lapse coming with the default 30-day window.
pub const DEFAULT_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
/// The shortest non-zero sweep interval; anything shorter hammers public
/// servers for no gain.
pub const MIN_INTERVAL_SECONDS: u64 = 15 * 60;
/// The default expiry window in days.
pub const DEFAULT_WINDOW_DAYS: u32 = 30;
/// The longest expiry window in days.
pub const MAX_WINDOW_DAYS: u32 = 365;
/// The default gap between two queries to one RDAP server.
pub const DEFAULT_RDAP_GAP: Duration = Duration::from_secs(2);
/// The longest an on-demand lookup waits for its rate-limit slot before it
/// is refused instead.
const MAX_SLOT_WAIT: Duration = Duration::from_secs(30);
/// Entries read per directory page.
const DIRECTORY_PAGE: i64 = 200;
/// The longest detail text recorded in an observation.
const MAX_DETAIL: usize = 200;

/// The enricher's settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrichSettings {
    /// How often the scheduled sweep runs; zero is off.
    pub interval: Duration,
    /// Domains expiring within this many days are flagged.
    pub expiry_window_days: u32,
    /// The minimum gap between two queries to one RDAP server.
    pub rdap_gap: Duration,
}

impl Default for EnrichSettings {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(DEFAULT_INTERVAL_SECONDS),
            expiry_window_days: DEFAULT_WINDOW_DAYS,
            rdap_gap: DEFAULT_RDAP_GAP,
        }
    }
}

impl EnrichSettings {
    /// Parses the environment values; `None` or empty means the default.
    ///
    /// # Errors
    ///
    /// Fails on a malformed or out-of-range value, naming the variable: a
    /// typo must stop startup, not silently change how often third parties
    /// are queried.
    pub fn from_env_values(interval: Option<&str>, window: Option<&str>) -> Result<Self, String> {
        let interval = match present_value(interval) {
            None => DEFAULT_INTERVAL_SECONDS,
            Some(value) => value.parse::<u64>().map_err(|_| {
                format!("{INTERVAL_VAR} must be a number of seconds (0 turns it off)")
            })?,
        };
        if interval != 0 && interval < MIN_INTERVAL_SECONDS {
            return Err(format!(
                "{INTERVAL_VAR} must be 0 (off) or at least {MIN_INTERVAL_SECONDS} seconds"
            ));
        }
        let window = match present_value(window) {
            None => DEFAULT_WINDOW_DAYS,
            Some(value) => value
                .parse::<u32>()
                .map_err(|_| format!("{WINDOW_VAR} must be a number of days"))?,
        };
        if window == 0 || window > MAX_WINDOW_DAYS {
            return Err(format!(
                "{WINDOW_VAR} must be between 1 and {MAX_WINDOW_DAYS}"
            ));
        }
        Ok(Self {
            interval: Duration::from_secs(interval),
            expiry_window_days: window,
            rdap_gap: DEFAULT_RDAP_GAP,
        })
    }
}

/// What an RDAP server said about a domain, as the application sees it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RdapAnswer {
    /// The registrar's name.
    pub registrar: Option<String>,
    /// The expiration event's timestamp, as the server wrote it.
    pub expires: Option<String>,
    /// The EPP statuses.
    pub statuses: Vec<String>,
    /// The listed nameservers.
    pub nameservers: Vec<String>,
}

/// Why an RDAP query produced no answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RdapFailure {
    /// The registry reports the domain is not registered.
    NotFound,
    /// Any other failure, as a short credential-free category.
    Failed(String),
}

/// The RDAP port. The adapter owns bootstrap resolution and HTTP.
#[async_trait]
pub trait RdapPort: std::fmt::Debug + Send + Sync {
    /// The RDAP server that answers for the domain's TLD, or `None` when
    /// the TLD has no RDAP service.
    ///
    /// # Errors
    ///
    /// Fails (with a short category) when the bootstrap data is
    /// unavailable.
    async fn server_for(&self, fqdn: &str) -> Result<Option<String>, String>;

    /// Queries one server.
    ///
    /// # Errors
    ///
    /// [`RdapFailure::NotFound`] when the domain is unregistered, else
    /// [`RdapFailure::Failed`].
    async fn lookup(&self, server: &str, fqdn: &str) -> Result<RdapAnswer, RdapFailure>;
}

/// The DNS record types the enricher reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsKind {
    /// Nameservers.
    Ns,
    /// IPv4 addresses.
    A,
    /// IPv6 addresses.
    Aaaa,
    /// Canonical name aliases.
    Cname,
}

/// Why a DNS query produced no answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsFailure {
    /// NXDOMAIN.
    NameDoesNotExist,
    /// Any other failure, as a short category.
    Failed(String),
}

/// The DNS port.
#[async_trait]
pub trait DnsPort: std::fmt::Debug + Send + Sync {
    /// The values of `kind` records at `name`; empty when there are none.
    ///
    /// # Errors
    ///
    /// See [`DnsFailure`].
    async fn resolve(&self, name: &str, kind: DnsKind) -> Result<Vec<String>, DnsFailure>;
}

/// Where observations are kept. Implementations hold only what the
/// enricher recorded; deleting every row is always safe.
#[async_trait]
pub trait ObservationStore: std::fmt::Debug + Send + Sync {
    /// Replaces the entry's observation.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn save(&self, key: &str, observation: &DomainObservation) -> Result<(), String>;
    /// The entry's observation, if any.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn get(&self, key: &str) -> Result<Option<DomainObservation>, String>;
    /// Every observation, keyed by the entry key as it was saved.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list(&self) -> Result<Vec<(String, DomainObservation)>, String>;
    /// Deletes the observations of entries that no longer exist: every
    /// row whose key is not in `keep` (compared case-insensitively).
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn retain(&self, keep: &[String]) -> Result<(), String>;
}

/// One `domain` entry, as the enricher needs it.
#[derive(Clone, Debug, PartialEq)]
pub struct DomainEntry {
    /// The natural key (the fqdn).
    pub key: String,
    /// The entry's field values.
    pub fields: Value,
}

impl From<RegistryEntryRecord> for DomainEntry {
    fn from(entry: RegistryEntryRecord) -> Self {
        Self {
            key: entry.key,
            fields: entry.fields,
        }
    }
}

/// Where the enricher reads domain entries: the Registry read model,
/// authorized as `registry.read`.
#[async_trait]
pub trait DomainDirectory: std::fmt::Debug + Send + Sync {
    /// One domain entry of the active revision.
    ///
    /// # Errors
    ///
    /// Denial, [`ProjectUseCaseError::NotFound`], or a backend failure.
    async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        key: &str,
    ) -> Result<DomainEntry, ProjectUseCaseError>;

    /// Up to `limit` domain entries after `after`, ordered by key.
    ///
    /// # Errors
    ///
    /// Denial or a backend failure.
    async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<DomainEntry>, ProjectUseCaseError>;
}

#[async_trait]
impl DomainDirectory for RegistryReadModel {
    async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        key: &str,
    ) -> Result<DomainEntry, ProjectUseCaseError> {
        let Answered { value, .. } = self
            .get_entry(authorizer, principal_id, DOMAIN_TYPE, key)
            .await?;
        Ok(value.into())
    }

    async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<DomainEntry>, ProjectUseCaseError> {
        let filter = RegistryEntryFilter {
            entry_type: Some(DOMAIN_TYPE.to_owned()),
            ..RegistryEntryFilter::default()
        };
        let after = after.map(|key| EntryCursor {
            entry_type: DOMAIN_TYPE.to_owned(),
            key: key.to_owned(),
        });
        let Answered { value, .. } = self
            .list_entries(authorizer, principal_id, &filter, after.as_ref(), limit)
            .await?;
        Ok(value
            .into_iter()
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .map(DomainEntry::from)
            .collect())
    }
}

/// A domain entry with its latest observation and the assessment of the
/// two.
#[derive(Clone, Debug, Serialize)]
pub struct DomainView {
    /// The entry's key.
    pub key: String,
    /// The latest observation, when one was ever recorded.
    pub observation: Option<DomainObservation>,
    /// The comparison, warnings, and suggestion.
    pub assessment: Assessment,
}

/// What one sweep did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SweepReport {
    /// Entries looked up.
    pub observed: u32,
    /// Entries skipped because their observation was recent.
    pub fresh: u32,
    /// Entries whose observation could not be stored.
    pub failed: u32,
}

fn present_value(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

fn backend(context: &'static str) -> impl Fn(String) -> ProjectUseCaseError {
    move |detail| ProjectUseCaseError::Backend { context, detail }
}

fn bounded(text: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    flat.chars().take(MAX_DETAIL).collect()
}

/// A rate limiter that several enrichers of one process share.
pub type SharedLimiter = Arc<tokio::sync::Mutex<RateLimiter>>;

/// A fresh shared limiter spacing each RDAP server's queries by `gap`.
#[must_use]
pub fn shared_limiter(gap: Duration) -> SharedLimiter {
    Arc::new(tokio::sync::Mutex::new(RateLimiter::new(gap)))
}

/// The enricher use cases.
pub struct DomainEnricher {
    directory: Arc<dyn DomainDirectory>,
    rdap: Arc<dyn RdapPort>,
    dns: Arc<dyn DnsPort>,
    store: Arc<dyn ObservationStore>,
    audit: Arc<dyn AuditPort>,
    settings: EnrichSettings,
    limiter: SharedLimiter,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl std::fmt::Debug for DomainEnricher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainEnricher")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl DomainEnricher {
    /// Composes the enricher over its ports.
    #[must_use]
    pub fn new(
        directory: Arc<dyn DomainDirectory>,
        rdap: Arc<dyn RdapPort>,
        dns: Arc<dyn DnsPort>,
        store: Arc<dyn ObservationStore>,
        audit: Arc<dyn AuditPort>,
        settings: EnrichSettings,
    ) -> Self {
        Self {
            directory,
            rdap,
            dns,
            store,
            audit,
            limiter: shared_limiter(settings.rdap_gap),
            settings,
            clock: Arc::new(fleet_core::SystemClock::now_unix_millis),
        }
    }

    /// Uses a limiter shared with other enrichers of the process, so the
    /// per-server spacing holds across every caller.
    #[must_use]
    pub fn with_limiter(mut self, limiter: SharedLimiter) -> Self {
        self.limiter = limiter;
        self
    }

    /// Replaces the clock (tests).
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// The settings in force.
    #[must_use]
    pub fn settings(&self) -> &EnrichSettings {
        &self.settings
    }

    fn view(&self, entry: &DomainEntry, observation: Option<DomainObservation>) -> DomainView {
        let today = diff::days_from_millis((self.clock)());
        let assessment = diff::assess(
            &entry.fields,
            observation.as_ref(),
            today,
            i64::from(self.settings.expiry_window_days),
        );
        DomainView {
            key: entry.key.clone(),
            observation,
            assessment,
        }
    }

    /// One domain's observation and assessment (`registry.read`).
    ///
    /// # Errors
    ///
    /// Denial, an unknown entry, or a backend failure.
    pub async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        key: &str,
    ) -> Result<DomainView, ProjectUseCaseError> {
        let entry = self.directory.get(authorizer, principal_id, key).await?;
        let observation = self
            .store
            .get(&entry.key)
            .await
            .map_err(backend("registry_observation"))?;
        Ok(self.view(&entry, observation))
    }

    /// Up to `limit` domain views after the cursor, ordered by key
    /// (`registry.read`). With `attention_only`, only domains with at least
    /// one warning count and are returned.
    ///
    /// # Errors
    ///
    /// Denial or a backend failure.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        attention_only: bool,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<DomainView>, ProjectUseCaseError> {
        let observations: std::collections::HashMap<String, DomainObservation> = self
            .store
            .list()
            .await
            .map_err(backend("registry_observation"))?
            .into_iter()
            .map(|(key, observation)| (crate::registry::normalize_key(&key), observation))
            .collect();
        let mut views = Vec::new();
        let mut cursor = after.map(str::to_owned);
        loop {
            let page = self
                .directory
                .list(authorizer, principal_id, cursor.as_deref(), DIRECTORY_PAGE)
                .await?;
            let last = page.last().map(|entry| entry.key.clone());
            let full = i64::try_from(page.len()).unwrap_or(i64::MAX) >= DIRECTORY_PAGE;
            for entry in &page {
                let observation = observations
                    .get(&crate::registry::normalize_key(&entry.key))
                    .cloned();
                let view = self.view(entry, observation);
                if attention_only && view.assessment.warnings.is_empty() {
                    continue;
                }
                views.push(view);
                if views.len() >= limit {
                    return Ok(views);
                }
            }
            match (full, last) {
                (true, Some(last)) => cursor = Some(last),
                _ => return Ok(views),
            }
        }
    }

    fn audit_metadata(
        event: &str,
        facts: &[(&str, &str)],
    ) -> Result<AuditMetadata, ProjectUseCaseError> {
        let mut metadata = AuditMetadata::default();
        metadata
            .insert("event", event)
            .map_err(|error| backend("registry_observe_audit")(error.to_string()))?;
        for (key, value) in facts {
            metadata
                .insert(key, value)
                .map_err(|error| backend("registry_observe_audit")(error.to_string()))?;
        }
        Ok(metadata)
    }

    /// Looks one domain up now and records the observation
    /// (`registry.observe`, audited). The intent is recorded before any
    /// outbound request.
    ///
    /// # Errors
    ///
    /// Denial, an unknown entry, an unreachable limiter slot, or a backend
    /// failure. A failed lookup is not an error: it is recorded as an
    /// observation with `error` status.
    pub async fn refresh(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        correlation_id: Option<&str>,
        key: &str,
    ) -> Result<DomainView, ProjectUseCaseError> {
        let entry = self.directory.get(authorizer, principal_id, key).await?;
        let resource = format!("{DOMAIN_TYPE}/{}", entry.key);
        let decision = authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::RegistryObserve,
                resource: Some(&resource),
            },
        )
        .map_err(ProjectUseCaseError::Denied)?;
        self.audit
            .record_intent(&AuditIntent {
                actor: principal_id.to_owned(),
                action: Permission::RegistryObserve.id().to_owned(),
                resource: Some(resource),
                decision,
                correlation_id: correlation_id.map(str::to_owned),
                operation_id: None,
                metadata: Self::audit_metadata("registry_observe", &[("trigger", "on_demand")])?,
            })
            .await
            .map_err(backend("registry_observe_audit"))?;
        let fqdn = entry_fqdn(&entry);
        let observation = self.observe(&fqdn, true).await?;
        self.store
            .save(&entry.key, &observation)
            .await
            .map_err(backend("registry_observation"))?;
        Ok(self.view(&entry, Some(observation)))
    }

    /// Looks up every domain entry whose observation is older than
    /// `max_age` (all of them when `None`), spacing queries per RDAP
    /// server, and forgets observations of entries that no longer exist
    /// (`registry.observe`, audited once for the sweep).
    ///
    /// # Errors
    ///
    /// Denial or a backend failure listing the entries. A failure storing
    /// one observation is counted, not fatal.
    pub async fn sweep(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        max_age: Option<Duration>,
    ) -> Result<SweepReport, ProjectUseCaseError> {
        let decision = authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::RegistryObserve,
                resource: None,
            },
        )
        .map_err(ProjectUseCaseError::Denied)?;
        let mut entries = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .directory
                .list(authorizer, principal_id, cursor.as_deref(), DIRECTORY_PAGE)
                .await?;
            let full = i64::try_from(page.len()).unwrap_or(i64::MAX) >= DIRECTORY_PAGE;
            cursor = page.last().map(|entry| entry.key.clone());
            entries.extend(page);
            if !full || cursor.is_none() {
                break;
            }
        }
        let existing: std::collections::HashMap<String, i64> = self
            .store
            .list()
            .await
            .map_err(backend("registry_observation"))?
            .into_iter()
            .map(|(key, observation)| {
                (
                    crate::registry::normalize_key(&key),
                    observation.observed_at,
                )
            })
            .collect();
        let now = (self.clock)();
        let due: Vec<&DomainEntry> = entries
            .iter()
            .filter(|entry| {
                let age = existing
                    .get(&crate::registry::normalize_key(&entry.key))
                    .map(|at| now.saturating_sub(*at));
                match (max_age, age) {
                    (Some(max), Some(age)) => {
                        i64::try_from(max.as_millis()).unwrap_or(i64::MAX) <= age
                    }
                    _ => true,
                }
            })
            .collect();
        let mut report = SweepReport {
            fresh: u32::try_from(entries.len() - due.len()).unwrap_or(u32::MAX),
            ..SweepReport::default()
        };
        if due.is_empty() {
            self.prune(&entries).await;
            return Ok(report);
        }
        self.audit
            .record_intent(&AuditIntent {
                actor: principal_id.to_owned(),
                action: Permission::RegistryObserve.id().to_owned(),
                resource: None,
                decision,
                correlation_id: None,
                operation_id: None,
                metadata: Self::audit_metadata(
                    "registry_observe_sweep",
                    &[("domains", &due.len().to_string())],
                )?,
            })
            .await
            .map_err(backend("registry_observe_audit"))?;
        for entry in due {
            // A scheduled sweep waits for its slots; it has all day.
            let Ok(observation) = self.observe(&entry_fqdn(entry), false).await else {
                report.failed += 1;
                continue;
            };
            if self.store.save(&entry.key, &observation).await.is_ok() {
                report.observed += 1;
            } else {
                report.failed += 1;
            }
        }
        self.prune(&entries).await;
        Ok(report)
    }

    async fn prune(&self, entries: &[DomainEntry]) {
        let keep: Vec<String> = entries.iter().map(|entry| entry.key.clone()).collect();
        // Best effort: a stale row is ignored on read and pruned next time.
        let _ = self.store.retain(&keep).await;
    }

    async fn observe(
        &self,
        fqdn: &str,
        refuse_long_waits: bool,
    ) -> Result<DomainObservation, ProjectUseCaseError> {
        let rdap = self.observe_rdap(fqdn, refuse_long_waits).await?;
        let dns = self.observe_dns(fqdn).await;
        Ok(DomainObservation {
            observed_at: (self.clock)(),
            rdap,
            dns,
        })
    }

    async fn observe_rdap(
        &self,
        fqdn: &str,
        refuse_long_waits: bool,
    ) -> Result<RdapObservation, ProjectUseCaseError> {
        let server = match self.rdap.server_for(fqdn).await {
            Ok(Some(server)) => server,
            Ok(None) => {
                let tld = fqdn.rsplit('.').next().unwrap_or_default();
                return Ok(RdapObservation::empty(
                    RdapStatus::Unavailable,
                    format!("no RDAP service is registered for .{tld}"),
                ));
            }
            Err(detail) => {
                return Ok(RdapObservation::empty(RdapStatus::Error, bounded(&detail)));
            }
        };
        let wait = self.limiter.lock().await.reserve(&server, Instant::now());
        if refuse_long_waits && wait > MAX_SLOT_WAIT {
            return Err(ProjectUseCaseError::Backend {
                context: "registry_observe_rate_limited",
                detail: format!(
                    "the RDAP server {server} is being queried at its rate limit; retry shortly"
                ),
            });
        }
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        Ok(match self.rdap.lookup(&server, fqdn).await {
            Ok(answer) => RdapObservation {
                status: RdapStatus::Ok,
                server: Some(server),
                registrar: answer.registrar,
                expires: answer.expires.as_deref().and_then(diff::date_part),
                statuses: answer.statuses,
                nameservers: answer.nameservers,
                detail: None,
            },
            Err(RdapFailure::NotFound) => RdapObservation {
                server: Some(server),
                ..RdapObservation::empty(
                    RdapStatus::NotFound,
                    "the registry reports the domain is not registered",
                )
            },
            Err(RdapFailure::Failed(detail)) => RdapObservation {
                server: Some(server),
                ..RdapObservation::empty(RdapStatus::Error, bounded(&detail))
            },
        })
    }

    /// The records of the given kinds at one name; whether the name does
    /// not exist; and the first failure.
    async fn records_at(
        &self,
        name: &str,
        kinds: &[DnsKind],
    ) -> (DnsRecords, bool, Option<String>) {
        let mut records = DnsRecords::default();
        let mut failure = None;
        for kind in kinds {
            match self.dns.resolve(name, *kind).await {
                Ok(values) => match kind {
                    DnsKind::Ns => records.ns = values,
                    DnsKind::A => records.a = values,
                    DnsKind::Aaaa => records.aaaa = values,
                    DnsKind::Cname => records.cname = values,
                },
                Err(DnsFailure::NameDoesNotExist) => return (records, true, failure),
                Err(DnsFailure::Failed(detail)) => {
                    failure.get_or_insert_with(|| bounded(&detail));
                }
            }
        }
        (records, false, failure)
    }

    async fn observe_dns(&self, fqdn: &str) -> DnsObservation {
        let (apex, apex_missing, apex_failure) = self
            .records_at(
                fqdn,
                &[DnsKind::Ns, DnsKind::A, DnsKind::Aaaa, DnsKind::Cname],
            )
            .await;
        // A missing www is an ordinary answer; only the apex decides
        // whether the name exists.
        let (www, _, www_failure) = self
            .records_at(
                &format!("www.{fqdn}"),
                &[DnsKind::A, DnsKind::Aaaa, DnsKind::Cname],
            )
            .await;
        let (status, detail) = if apex_missing {
            (
                DnsStatus::NotFound,
                Some("the name does not exist in DNS".to_owned()),
            )
        } else if let Some(detail) = apex_failure.or(www_failure) {
            (DnsStatus::Error, Some(detail))
        } else {
            (DnsStatus::Ok, None)
        };
        DnsObservation {
            status,
            apex,
            www,
            detail,
        }
    }
}

fn entry_fqdn(entry: &DomainEntry) -> String {
    entry
        .fields
        .get("fqdn")
        .and_then(Value::as_str)
        .map_or_else(|| entry.key.clone(), str::to_owned)
}

#[cfg(test)]
mod tests;
