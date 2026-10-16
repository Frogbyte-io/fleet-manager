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

/// The RDAP half of an observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RdapObservation {
    /// How the lookup ended.
    pub status: RdapStatus,
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
    /// When the lookups finished, in epoch milliseconds.
    pub observed_at: i64,
    /// The public registration data.
    pub rdap: RdapObservation,
    /// The public DNS data.
    pub dns: DnsObservation,
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
