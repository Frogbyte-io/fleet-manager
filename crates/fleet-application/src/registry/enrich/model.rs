//! What an enrichment run records: the observation itself, and the
//! assessment derived from it at read time.

use serde::{Deserialize, Serialize};

/// How an RDAP lookup ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RdapStatus {
    /// A server answered with a domain object.
    Ok,
    /// No RDAP service covers the TLD. A normal answer, not a failure.
    Unavailable,
    /// The registry reports the domain is not registered.
    NotFound,
    /// The lookup failed (transport, refusal, rate limit, bad answer).
    Error,
}

/// Where the registration data came from.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationSource {
    /// An RDAP server (the default; older observations carry no source).
    #[default]
    Rdap,
    /// The TLD's registry WHOIS server, for a TLD with no RDAP service.
    Whois,
}

impl RegistrationSource {
    // serde's `skip_serializing_if` passes a reference.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn is_rdap(&self) -> bool {
        *self == Self::Rdap
    }
}

/// The registration half of an observation (RDAP, or WHOIS when the TLD
/// has no RDAP service).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RdapObservation {
    /// How the lookup ended.
    pub status: RdapStatus,
    /// Which protocol answered.
    #[serde(default, skip_serializing_if = "RegistrationSource::is_rdap")]
    pub source: RegistrationSource,
    /// The RDAP server's base URL, when one was resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// The registrar's name, as the registry reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registrar: Option<String>,
    /// The expiry as a calendar date (`YYYY-MM-DD`). Several ccTLD
    /// registries do not publish one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// The EPP status values.
    #[serde(default)]
    pub statuses: Vec<String>,
    /// The nameservers the registry lists.
    #[serde(default)]
    pub nameservers: Vec<String>,
    /// A short, credential-free explanation for `unavailable`, `not_found`,
    /// and `error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl RdapObservation {
    /// An observation that carries no data, only a status and why.
    #[must_use]
    pub fn empty(status: RdapStatus, detail: impl Into<String>) -> Self {
        Self {
            status,
            source: RegistrationSource::Rdap,
            server: None,
            registrar: None,
            expires: None,
            statuses: Vec::new(),
            nameservers: Vec::new(),
            detail: Some(detail.into()),
        }
    }
}

/// The values of each record type at one name.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DnsRecords {
    /// NS values (meaningful at the apex).
    #[serde(default)]
    pub ns: Vec<String>,
    /// A values.
    #[serde(default)]
    pub a: Vec<String>,
    /// AAAA values.
    #[serde(default)]
    pub aaaa: Vec<String>,
    /// CNAME values.
    #[serde(default)]
    pub cname: Vec<String>,
}

/// How a DNS lookup ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsStatus {
    /// Every query answered (possibly with no records).
    Ok,
    /// The apex does not exist (NXDOMAIN).
    NotFound,
    /// At least one query failed; the records that did answer are kept.
    Error,
}

/// The DNS half of an observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DnsObservation {
    /// How the lookup ended.
    pub status: DnsStatus,
    /// Records at the apex.
    pub apex: DnsRecords,
    /// Records at `www.<apex>`.
    pub www: DnsRecords,
    /// A short explanation for `not_found` and `error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// One enrichment result for a domain entry. Observations attach beside
/// the entry in SQLite; they never rewrite Fleet Git (ADR 0016).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DomainObservation {
    /// When the latest lookup attempt finished, in epoch milliseconds.
    pub observed_at: i64,
    /// The latest attempt's failure, when a half failed. The half itself
    /// keeps the last good data when there was any (see `stale_since`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// When the data of a half that now fails to refresh was last good
    /// (epoch milliseconds). Set only while old data is being kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_since: Option<i64>,
    /// Consecutive attempts with a failed half; zero after a clean one.
    #[serde(default)]
    pub failures: u32,
    /// The public registration data.
    pub rdap: RdapObservation,
    /// The public DNS data.
    pub dns: DnsObservation,
}

impl DomainObservation {
    /// Whether the latest attempt succeeded in both halves and shows no
    /// kept-over data. Only a settled observation counts as fresh for the
    /// sweep; anything else is retried at the next one.
    #[must_use]
    pub fn is_settled(&self) -> bool {
        self.stale_since.is_none()
            && self.failures == 0
            && self.rdap.status != RdapStatus::Error
            && self.dns.status != DnsStatus::Error
    }

    /// Combines a fresh attempt with the previous observation. A half that
    /// failed this time keeps the previous half's data when that was good,
    /// so one outage does not erase what was known; the observation is then
    /// marked stale (`stale_since` is when the kept data was last good) and
    /// carries the error. A half that failed with nothing good to keep is
    /// recorded as the failure it is.
    #[must_use]
    pub fn merged_with(mut self, previous: Option<&Self>) -> Self {
        let mut errors = Vec::new();
        if self.rdap.status == RdapStatus::Error {
            errors.push(
                self.rdap
                    .detail
                    .clone()
                    .unwrap_or_else(|| "the RDAP lookup failed".to_owned()),
            );
        }
        if self.dns.status == DnsStatus::Error {
            errors.push(
                self.dns
                    .detail
                    .clone()
                    .unwrap_or_else(|| "the DNS lookup failed".to_owned()),
            );
        }
        if errors.is_empty() {
            return self;
        }
        self.failures = previous.map_or(0, |p| p.failures).saturating_add(1);
        self.last_error = Some(errors.join("; "));
        if let Some(previous) = previous {
            // `stale_since` is when the kept data was last good: the
            // earlier marker when the data was already being kept.
            let good_at = previous.stale_since.unwrap_or(previous.observed_at);
            let mut kept = false;
            if self.rdap.status == RdapStatus::Error && previous.rdap.status == RdapStatus::Ok {
                self.rdap = previous.rdap.clone();
                kept = true;
            }
            if self.dns.status == DnsStatus::Error && previous.dns.status == DnsStatus::Ok {
                self.dns = previous.dns.clone();
                kept = true;
            }
            if kept {
                self.stale_since = Some(good_at);
            }
        }
        self
    }
}

/// How one field's recorded value compares with the observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldState {
    /// Both sides have a value and they agree.
    InSync,
    /// The observation differs from the recorded value, or supplies one the
    /// entry lacks.
    Changed,
    /// There is nothing to compare: no observation of the field, or no
    /// value on either side.
    Unknown,
}

/// The difference for one field.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FieldDiff {
    /// The entry field (`registrar`, `expires`, `nameservers`, `dnsHost`).
    pub field: &'static str,
    /// The comparison.
    pub state: FieldState,
    /// What the entry (Fleet Git) records.
    pub recorded: Option<serde_json::Value>,
    /// What the lookups saw.
    pub observed: Option<serde_json::Value>,
}

/// How serious a warning is.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Worth knowing.
    Info,
    /// Needs a person soon.
    Warn,
    /// Needs a person now.
    Err,
}

/// The derived warnings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    /// The registry's registrar is not the recorded one.
    RegistrarMismatch,
    /// The delegated nameservers are not the recorded ones.
    NameserversMismatch,
    /// The nameservers do not belong to the recorded `dnsHost`.
    DnsHostMismatch,
    /// The registry's expiry is not the recorded one.
    ExpiryChanged,
    /// The domain expires within the configured window (or already has).
    Expiring,
    /// The domain expires within the window and auto-renew is off.
    AutoRenewOffExpiring,
    /// The data shown is old: the latest lookup failed, or no lookup
    /// succeeded for more than twice the sweep interval.
    StaleObservation,
    /// The registry reports the domain is not registered.
    RdapNotFound,
    /// Lookups have failed several times in a row.
    LookupFailing,
}

/// One derived warning.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Warning {
    /// Which rule fired.
    pub code: WarningCode,
    /// How serious it is.
    pub severity: Severity,
    /// A sentence for people.
    pub message: String,
}

/// One suggested field value: what the entry would say if it followed the
/// observation.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SuggestedField {
    /// The entry field.
    pub field: &'static str,
    /// The suggested value, in the field's type.
    pub value: serde_json::Value,
}

/// The assessment of one entry against its latest observation.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Assessment {
    /// Per-field comparison, in a stable order.
    pub diffs: Vec<FieldDiff>,
    /// Derived warnings, most serious first.
    pub warnings: Vec<Warning>,
    /// The field changes that would bring the entry in line.
    pub suggestion: Vec<SuggestedField>,
}
