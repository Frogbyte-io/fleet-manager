//! DNS records through the action broker (FM-1042, ADR 0016).
//!
//! Fleet holds a scoped Cloudflare token as an external provider account
//! (FM-1001) and never returns it. This module is the provider-neutral half
//! of the feature:
//!
//! - the [`DnsGateway`] port, implemented at the provider boundary (the
//!   Cloudflare crate translates its own model into [`DnsRecord`]);
//! - the pure rules: which record types may be changed, how a name and a
//!   value are validated and normalized, how a desired record is compared
//!   with what the zone holds ([`plan_upsert`], [`plan_delete`]), and the
//!   preview diff the approver reads;
//! - the [`Dns`] use cases: zone resolution across Cloudflare accounts,
//!   record reads (which are also recorded as observations beside the
//!   matching `domain` Registry entry), and change requests;
//! - the `dns.record.upsert` and `dns.record.delete` [`ProviderAction`]s,
//!   whose default risk class is `approve`;
//! - the apply routine the operation executor runs ([`Dns::execute`]).
//!
//! # Safe record set
//!
//! `A`, `AAAA`, `CNAME`, `TXT`, and `MX` may be changed. `CAA` is left out
//! because it controls which authorities may issue certificates and needs a
//! structured value; `NS` because it delegates the whole name to another
//! operator; `SRV`, `SOA`, and the rest because they need structured data a
//! plain content string cannot validate. Reading is not limited: only
//! changes are.
//!
//! # Preview and staleness
//!
//! The preview is computed when the request is made and stored inside the
//! request parameters, so the approver sees exactly the change the
//! requester saw. [`Dns::execute`] re-reads the zone and recomputes the plan.
//! When the zone no longer holds what the preview said, the operation fails
//! with a stale-preview reason rather than overwriting whatever is there
//! now. An effect that is already in place (an `upsert` whose record now
//! matches, a `delete` whose record is gone) succeeds as `unchanged` or
//! `already_absent`, so a replay after a crash is harmless. A successful
//! write is verified by reading the record back.
//!
//! # Idempotency
//!
//! A record is identified by zone, name, and type, plus its content for the
//! multi-value types (`A`, `AAAA`, `TXT`, `MX`). An upsert whose content
//! already exists updates that record in place; `replaces` names the
//! existing value a new content replaces; otherwise a new value is added.
//! `CNAME` holds one value, so an upsert replaces it.
//!
//! # Secrets
//!
//! No token is in any parameter, payload, result, audit event, or error.
//! Parameters pass the broker's credential refusal: a `TXT` value shaped
//! like an API key (a long opaque token, a `key=value` secret pair) is
//! refused at request time, the same as any other parameter. Public DKIM
//! keys and SPF or DMARC policies are ordinary text and pass.
#![warn(missing_docs)]

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use async_trait::async_trait;
use fleet_core::{ExternalProviderKind, RiskClass, SensitiveString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::authz::{AccessRequest, Authorizer, Decision, Permission, authorize};
use crate::broker::{ActionRequest, Broker, BrokerError, NewActionRequest, ProviderAction};
use crate::external_accounts::{ExternalAccount, ExternalAccountPort, ExternalCredentialStore};
use crate::operation::NewOperation;
use crate::registry::RegistryReadModel;

/// The action id (and operation kind) that creates or updates a record.
pub const UPSERT_ACTION: &str = "dns.record.upsert";
/// The action id (and operation kind) that deletes a record.
pub const DELETE_ACTION: &str = "dns.record.delete";
/// The record types a change may name. See the module docs for why this set.
pub const CHANGEABLE_TYPES: [&str; 5] = ["A", "AAAA", "CNAME", "TXT", "MX"];
/// The shortest explicit TTL, in seconds. `1` means automatic.
pub const MIN_TTL: u32 = 60;
/// The longest TTL, in seconds: one day.
pub const MAX_TTL: u32 = 86_400;
/// The longest `TXT` content, in bytes. Parameters are bounded to 8 KiB by
/// the broker and carry the content more than once (the request, the
/// preview's before and after), so this stays well inside that.
pub const MAX_TXT_BYTES: usize = 1024;
/// The longest record name, in bytes.
pub const MAX_NAME_LEN: usize = 253;
/// The most records read for one name and type; more is refused rather than
/// silently truncated.
pub const MAX_RECORDS: usize = 500;

/// One DNS record, in Fleet's provider-neutral shape.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsRecord {
    /// The provider's record id, when it has one. Absent in a desired record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The record type, upper case.
    #[serde(rename = "type")]
    pub record_type: String,
    /// The fully qualified name, lower case, without a trailing dot.
    pub name: String,
    /// The value, normalized per type.
    pub content: String,
    /// The TTL in seconds; `1` is automatic.
    pub ttl: u32,
    /// Whether traffic is proxied through the provider.
    #[serde(default)]
    pub proxied: bool,
    /// The MX preference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
}

impl DnsRecord {
    /// Whether two records agree on everything a change controls, ignoring
    /// ids.
    #[must_use]
    pub fn same_attributes(&self, other: &Self) -> bool {
        self.record_type == other.record_type
            && self.name == other.name
            && self.content == other.content
            && self.ttl == other.ttl
            && self.proxied == other.proxied
            && self.priority == other.priority
    }
}

/// One DNS zone.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsZone {
    /// The provider's zone id.
    pub id: String,
    /// The zone's apex name, lower case.
    pub name: String,
    /// The provider's status for the zone (`active`, `pending`, ...).
    pub status: String,
}

/// What a provider refusal means to Fleet.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsFailureClass {
    /// The token was refused.
    Auth,
    /// The token is valid but not allowed to do this.
    Permission,
    /// The zone or record does not exist.
    NotFound,
    /// The change conflicts with what exists (a duplicate, or a CNAME beside
    /// other records).
    Conflict,
    /// The provider's rate limit applies and the bounded retries ran out.
    RateLimited,
    /// The provider refused the value.
    Invalid,
    /// The provider could not be reached or answered something unusable.
    Unavailable,
}

impl DnsFailureClass {
    /// The stable name.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Permission => "permission",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited => "rate_limited",
            Self::Invalid => "invalid",
            Self::Unavailable => "unavailable",
        }
    }
}

/// A classified provider failure. The detail is bounded, control characters
/// are flattened, and it never carries the token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsFailure {
    /// What kind of failure.
    pub class: DnsFailureClass,
    /// What happened, safe to print.
    pub detail: String,
}

impl DnsFailure {
    /// A failure of one class.
    #[must_use]
    pub fn new(class: DnsFailureClass, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: fleet_core::scrub_failure_detail(&detail.into()),
        }
    }
}

impl fmt::Display for DnsFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.class.id(), self.detail)
    }
}

impl std::error::Error for DnsFailure {}

/// What the gateway needs to call the provider as one account.
#[derive(Debug)]
pub struct DnsCredentials {
    /// The API root.
    pub base_url: String,
    /// The token. Redacted in `Debug`.
    pub token: SensitiveString,
}

/// The provider port. The provider crate implements it and translates its
/// own model at this boundary.
#[async_trait]
pub trait DnsGateway: fmt::Debug + Send + Sync {
    /// Lists the zones the token can see, optionally only the zone named
    /// `name`. Every page is read.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn list_zones(
        &self,
        credentials: &DnsCredentials,
        name: Option<&str>,
    ) -> Result<Vec<DnsZone>, DnsFailure>;

    /// Lists a zone's records, optionally only those of one name and type.
    /// Every page is read.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn list_records(
        &self,
        credentials: &DnsCredentials,
        zone_id: &str,
        name: Option<&str>,
        record_type: Option<&str>,
    ) -> Result<Vec<DnsRecord>, DnsFailure>;

    /// Creates a record and answers it as stored.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn create_record(
        &self,
        credentials: &DnsCredentials,
        zone_id: &str,
        record: &DnsRecord,
    ) -> Result<DnsRecord, DnsFailure>;

    /// Replaces a record and answers it as stored.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn update_record(
        &self,
        credentials: &DnsCredentials,
        zone_id: &str,
        record_id: &str,
        record: &DnsRecord,
    ) -> Result<DnsRecord, DnsFailure>;

    /// Deletes a record.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn delete_record(
        &self,
        credentials: &DnsCredentials,
        zone_id: &str,
        record_id: &str,
    ) -> Result<(), DnsFailure>;
}

/// The records Fleet last saw for one name, as an observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsObservation {
    /// The external account that answered.
    pub account_id: String,
    /// The zone's provider id.
    pub zone_id: String,
    /// The zone's apex name.
    pub zone_name: String,
    /// The name the records are at.
    pub name: String,
    /// The Registry entry (`domain/<key>`) the observation attaches to,
    /// when the Registry has one.
    pub registry_entry: Option<String>,
    /// The records.
    pub records: Vec<DnsRecord>,
    /// When they were read (epoch milliseconds).
    pub observed_at: i64,
}

/// Observation storage. Separate from every other enricher's storage:
/// observations attach to a Registry entry and never change it.
#[async_trait]
pub trait DnsObservationPort: fmt::Debug + Send + Sync {
    /// Replaces the stored records for one account, zone, and name (and
    /// record type, when the read was filtered by one) with `observation`.
    ///
    /// # Errors
    ///
    /// Fails when the store errors.
    async fn replace(
        &self,
        observation: &DnsObservation,
        record_type: Option<&str>,
    ) -> Result<(), String>;

    /// The stored observation for a name, across accounts, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the store errors.
    async fn for_name(&self, name: &str) -> Result<Vec<DnsObservation>, String>;
}

// ---------------------------------------------------------------------
// Pure rules.
// ---------------------------------------------------------------------

/// Normalizes a DNS name: lower case, no trailing dot.
fn lower_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn valid_label(label: &str, allow_wildcard: bool) -> bool {
    if allow_wildcard && label == "*" {
        return true;
    }
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Validates and normalizes a host name used as a record name or a CNAME or
/// MX target. A `*` is allowed only as the whole leftmost label of a name.
///
/// # Errors
///
/// Returns a caller-safe reason.
pub fn normalize_hostname(raw: &str, allow_wildcard: bool) -> Result<String, String> {
    let name = lower_name(raw);
    if name.is_empty() {
        return Err("the name is empty".to_owned());
    }
    if name.len() > MAX_NAME_LEN {
        return Err(format!("the name is longer than {MAX_NAME_LEN} bytes"));
    }
    for (index, label) in name.split('.').enumerate() {
        if !valid_label(label, allow_wildcard && index == 0) {
            return Err(
                "the name has an invalid label (letters, digits, '-' and '_', at most 63 bytes each; '*' only as the leftmost label)"
                    .to_owned(),
            );
        }
    }
    Ok(name)
}

/// Validates a record name against its zone and normalizes it. The name must
/// be the zone apex or below it.
///
/// # Errors
///
/// Returns a caller-safe reason.
pub fn normalize_record_name(raw: &str, zone_name: &str) -> Result<String, String> {
    let name = normalize_hostname(raw, true)?;
    let zone = lower_name(zone_name);
    if name == zone || name.ends_with(&format!(".{zone}")) {
        Ok(name)
    } else {
        Err("the name is not inside the zone".to_owned())
    }
}

/// Normalizes a record type to upper case and checks it is one a change may
/// name.
///
/// # Errors
///
/// Returns a caller-safe reason.
pub fn normalize_change_type(raw: &str) -> Result<String, String> {
    let upper = raw.trim().to_ascii_uppercase();
    if CHANGEABLE_TYPES.contains(&upper.as_str()) {
        Ok(upper)
    } else {
        Err(format!(
            "the record type must be one of {}; other types are not changed through Fleet",
            CHANGEABLE_TYPES.join(", ")
        ))
    }
}

/// Normalizes a stored or desired content per type, without failing: an
/// unparseable value is returned as it is (lower-cased where it is a name),
/// so a record Fleet cannot validate can still be compared and shown.
#[must_use]
pub fn normalize_content(record_type: &str, content: &str) -> String {
    match record_type {
        "A" => content
            .trim()
            .parse::<Ipv4Addr>()
            .map_or_else(|_| content.trim().to_owned(), |ip| ip.to_string()),
        "AAAA" => content
            .trim()
            .parse::<Ipv6Addr>()
            .map_or_else(|_| content.trim().to_owned(), |ip| ip.to_string()),
        "CNAME" | "MX" | "NS" => lower_name(content),
        "TXT" => {
            let trimmed = content.trim();
            if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
                trimmed[1..trimmed.len() - 1].to_owned()
            } else {
                trimmed.to_owned()
            }
        }
        _ => content.trim().to_owned(),
    }
}

/// Normalizes a record read from the provider so it compares with a desired
/// one.
#[must_use]
pub fn normalize_remote(mut record: DnsRecord) -> DnsRecord {
    record.record_type = record.record_type.to_ascii_uppercase();
    record.name = lower_name(&record.name);
    record.content = normalize_content(&record.record_type, &record.content);
    record
}

/// A change's values as the caller gave them.
#[derive(Clone, Debug)]
pub struct DesiredRecord {
    /// The record type.
    pub record_type: String,
    /// The name (validated against the zone by the caller).
    pub name: String,
    /// The value.
    pub content: String,
    /// The TTL; `None` means automatic.
    pub ttl: Option<u32>,
    /// Proxy through the provider; `None` means not proxied.
    pub proxied: Option<bool>,
    /// The MX preference.
    pub priority: Option<u16>,
}

/// Validates the values of one record per type and builds the desired
/// record, with a normalized name and content, an explicit TTL, and an
/// explicit proxied flag.
///
/// # Errors
///
/// Returns a caller-safe reason.
pub fn build_desired(desired: &DesiredRecord) -> Result<DnsRecord, String> {
    let record_type = normalize_change_type(&desired.record_type)?;
    let name = normalize_hostname(&desired.name, true)?;
    let proxied = desired.proxied.unwrap_or(false);
    if proxied && !matches!(record_type.as_str(), "A" | "AAAA" | "CNAME") {
        return Err("only A, AAAA, and CNAME records can be proxied".to_owned());
    }
    let ttl = desired.ttl.unwrap_or(1);
    if ttl != 1 && !(MIN_TTL..=MAX_TTL).contains(&ttl) {
        return Err(format!(
            "the TTL must be 1 (automatic) or {MIN_TTL} to {MAX_TTL} seconds"
        ));
    }
    if proxied && ttl != 1 {
        return Err("a proxied record has an automatic TTL; set the TTL to 1".to_owned());
    }
    if desired.priority.is_some() && record_type != "MX" {
        return Err("only an MX record has a priority".to_owned());
    }
    let content = desired.content.trim();
    let (content, priority) = match record_type.as_str() {
        "A" => (
            content
                .parse::<Ipv4Addr>()
                .map_err(|_| "an A record needs an IPv4 address".to_owned())?
                .to_string(),
            None,
        ),
        "AAAA" => (
            content
                .parse::<Ipv6Addr>()
                .map_err(|_| "an AAAA record needs an IPv6 address".to_owned())?
                .to_string(),
            None,
        ),
        "CNAME" => {
            let target = normalize_hostname(content, false)
                .map_err(|reason| format!("the CNAME target: {reason}"))?;
            if target == name {
                return Err("a CNAME cannot point at itself".to_owned());
            }
            (target, None)
        }
        "MX" => {
            let target = normalize_hostname(content, false)
                .map_err(|reason| format!("the MX target: {reason}"))?;
            let priority = desired
                .priority
                .ok_or_else(|| "an MX record needs a priority (0 to 65535)".to_owned())?;
            (target, Some(priority))
        }
        _ => {
            // TXT.
            let text = normalize_content("TXT", content);
            if text.is_empty() {
                return Err("a TXT record needs content".to_owned());
            }
            if text.len() > MAX_TXT_BYTES {
                return Err(format!(
                    "TXT content is limited to {MAX_TXT_BYTES} bytes through Fleet"
                ));
            }
            if text.chars().any(char::is_control) {
                return Err("TXT content must not contain control characters".to_owned());
            }
            (text, None)
        }
    };
    Ok(DnsRecord {
        id: None,
        record_type,
        name,
        content,
        ttl,
        proxied,
        priority,
    })
}

/// What a change would do.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanOp {
    /// Add a record.
    Create,
    /// Change an existing record in place.
    Update,
    /// The desired record already exists as asked.
    Unchanged,
    /// Remove a record.
    Delete,
    /// The record to remove is not there.
    AlreadyAbsent,
}

impl PlanOp {
    /// The stable name.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Unchanged => "unchanged",
            Self::Delete => "delete",
            Self::AlreadyAbsent => "already_absent",
        }
    }
}

/// One field that differs between the current and the proposed record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldChange {
    /// The field name.
    pub field: String,
    /// The current value, when there is a current record.
    #[serde(default)]
    pub from: Option<Value>,
    /// The proposed value, when there is a proposed record.
    #[serde(default)]
    pub to: Option<Value>,
}

/// A computed change: the current record, the proposed one, and the
/// field-level difference. This is the preview the approver reads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    /// What would happen.
    pub operation: PlanOp,
    /// The record as it is now.
    #[serde(default)]
    pub before: Option<DnsRecord>,
    /// The record as it would be.
    #[serde(default)]
    pub after: Option<DnsRecord>,
    /// The fields that differ.
    #[serde(default)]
    pub changes: Vec<FieldChange>,
}

fn diff(before: Option<&DnsRecord>, after: Option<&DnsRecord>) -> Vec<FieldChange> {
    fn fields(record: &DnsRecord) -> [(&'static str, Value); 5] {
        [
            ("content", json!(record.content)),
            ("ttl", json!(record.ttl)),
            ("proxied", json!(record.proxied)),
            ("priority", json!(record.priority)),
            ("name", json!(record.name)),
        ]
    }
    match (before, after) {
        (Some(before), Some(after)) => fields(before)
            .into_iter()
            .zip(fields(after))
            .filter(|((_, from), (_, to))| from != to)
            .map(|((field, from), (_, to))| FieldChange {
                field: field.to_owned(),
                from: Some(from),
                to: Some(to),
            })
            .collect(),
        (None, Some(after)) => fields(after)
            .into_iter()
            .filter(|(field, value)| *field != "name" && !value.is_null())
            .map(|(field, to)| FieldChange {
                field: field.to_owned(),
                from: None,
                to: Some(to),
            })
            .collect(),
        (Some(before), None) => fields(before)
            .into_iter()
            .filter(|(field, value)| *field != "name" && !value.is_null())
            .map(|(field, from)| FieldChange {
                field: field.to_owned(),
                from: Some(from),
                to: None,
            })
            .collect(),
        (None, None) => Vec::new(),
    }
}

/// Plans an upsert against the (normalized) records currently at the
/// desired name and type.
///
/// # Errors
///
/// Returns a caller-safe reason when `replaces` names a record that is not
/// there, or the request is ambiguous.
pub fn plan_upsert(
    current: &[DnsRecord],
    desired: &DnsRecord,
    replaces: Option<&str>,
) -> Result<Plan, String> {
    let same_slot: Vec<&DnsRecord> = current
        .iter()
        .filter(|record| record.record_type == desired.record_type && record.name == desired.name)
        .collect();
    let exact = same_slot
        .iter()
        .find(|record| record.content == desired.content);
    let replaces = replaces
        .map(|value| normalize_content(&desired.record_type, value))
        .filter(|value| !value.is_empty());
    let target: Option<&DnsRecord> = if let Some(exact) = exact {
        if replaces
            .as_ref()
            .is_some_and(|value| *value != exact.content)
        {
            return Err(
                "the desired content already exists as a record, so `replaces` names a different record than the one that matches"
                    .to_owned(),
            );
        }
        Some(*exact)
    } else if let Some(replaces) = &replaces {
        let found = same_slot.iter().find(|record| &record.content == replaces);
        Some(*found.ok_or_else(|| {
            format!(
                "the record to replace ({} {replaces}) is not in the zone",
                desired.record_type
            )
        })?)
    } else if desired.record_type == "CNAME" {
        match same_slot.as_slice() {
            [] => None,
            [only] => Some(*only),
            _ => {
                return Err(
                    "the name has several CNAME records; name the one to replace".to_owned(),
                );
            }
        }
    } else {
        None
    };
    Ok(match target {
        None => {
            let after = desired.clone();
            Plan {
                operation: PlanOp::Create,
                changes: diff(None, Some(&after)),
                before: None,
                after: Some(after),
            }
        }
        Some(found) => {
            let mut after = desired.clone();
            after.id.clone_from(&found.id);
            if found.same_attributes(&after) {
                Plan {
                    operation: PlanOp::Unchanged,
                    before: Some(found.clone()),
                    after: Some(found.clone()),
                    changes: Vec::new(),
                }
            } else {
                Plan {
                    operation: PlanOp::Update,
                    changes: diff(Some(found), Some(&after)),
                    before: Some(found.clone()),
                    after: Some(after),
                }
            }
        }
    })
}

/// Plans a delete of the record with this (normalized) content.
#[must_use]
pub fn plan_delete(current: &[DnsRecord], record_type: &str, name: &str, content: &str) -> Plan {
    let content = normalize_content(record_type, content);
    let found = current.iter().find(|record| {
        record.record_type == record_type && record.name == name && record.content == content
    });
    match found {
        Some(found) => Plan {
            operation: PlanOp::Delete,
            changes: diff(Some(found), None),
            before: Some(found.clone()),
            after: None,
        },
        None => Plan {
            operation: PlanOp::AlreadyAbsent,
            before: None,
            after: None,
            changes: Vec::new(),
        },
    }
}

// ---------------------------------------------------------------------
// Request parameters and the provider actions.
// ---------------------------------------------------------------------

/// The parameters of a `dns.record.upsert` or `dns.record.delete` request,
/// and the payload of its operation. They hold ids and record data, never a
/// token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeParameters {
    /// The external account holding the token.
    pub account_id: String,
    /// The provider's zone id.
    pub zone_id: String,
    /// The zone's apex name.
    pub zone_name: String,
    /// The record name.
    pub name: String,
    /// The record type.
    #[serde(rename = "type")]
    pub record_type: String,
    /// The record value.
    pub content: String,
    /// The TTL (upsert).
    #[serde(default)]
    pub ttl: Option<u32>,
    /// Proxied (upsert).
    #[serde(default)]
    pub proxied: Option<bool>,
    /// The MX preference (upsert).
    #[serde(default)]
    pub priority: Option<u16>,
    /// The existing value an upsert replaces (upsert).
    #[serde(default)]
    pub replaces: Option<String>,
    /// The change as previewed when the request was made.
    pub preview: Plan,
}

impl ChangeParameters {
    /// The canonical target of a change.
    #[must_use]
    pub fn target(&self) -> String {
        format!("{} {}", self.name, self.record_type)
    }

    fn desired(&self) -> Result<DnsRecord, String> {
        build_desired(&DesiredRecord {
            record_type: self.record_type.clone(),
            name: self.name.clone(),
            content: self.content.clone(),
            ttl: self.ttl,
            proxied: self.proxied,
            priority: self.priority,
        })
    }
}

/// The two provider actions.
#[derive(Debug)]
pub struct DnsRecordAction {
    upsert: bool,
}

impl DnsRecordAction {
    /// The upsert action.
    #[must_use]
    pub const fn upsert() -> Self {
        Self { upsert: true }
    }

    /// The delete action.
    #[must_use]
    pub const fn delete() -> Self {
        Self { upsert: false }
    }
}

/// Both DNS actions, for the controller's action registry.
#[must_use]
pub fn dns_actions() -> Vec<Arc<dyn ProviderAction>> {
    vec![
        Arc::new(DnsRecordAction::upsert()),
        Arc::new(DnsRecordAction::delete()),
    ]
}

impl ProviderAction for DnsRecordAction {
    fn id(&self) -> &str {
        if self.upsert {
            UPSERT_ACTION
        } else {
            DELETE_ACTION
        }
    }

    fn operation_kind(&self) -> &str {
        self.id()
    }

    fn risk_class(&self) -> RiskClass {
        // ADR 0016: a DNS change is `approve` by default.
        RiskClass::Approve
    }

    fn validate(&self, target: &str, parameters: &Value) -> Result<(), String> {
        let params: ChangeParameters = serde_json::from_value(parameters.clone()).map_err(|_| {
            "the parameters are not a DNS change; use POST /dns/changes, which computes the preview"
                .to_owned()
        })?;
        validate_parameters(&params, self.upsert)?;
        if params.target() != target {
            return Err(
                "the target must be the record name and type, e.g. `www.example.com A`".to_owned(),
            );
        }
        Ok(())
    }

    fn operation(&self, request: &ActionRequest) -> Result<NewOperation, String> {
        // The payload is the parameters verbatim: deterministic for the
        // same request, and the executor reads the same typed shape.
        Ok(NewOperation {
            kind: self.operation_kind().to_owned(),
            idempotency_key: None,
            deadline_at: None,
            correlation_id: None,
            payload_json: Some(request.parameters.to_string()),
            review_token: None,
        })
    }
}

fn validate_parameters(params: &ChangeParameters, upsert: bool) -> Result<(), String> {
    for (label, value) in [
        ("accountId", &params.account_id),
        ("zoneId", &params.zone_id),
    ] {
        if value.is_empty() || value.len() > 64 || !value.chars().all(|c| c.is_ascii_graphic()) {
            return Err(format!("{label} is not a valid id"));
        }
    }
    let zone = normalize_hostname(&params.zone_name, false)?;
    if zone != params.zone_name {
        return Err("the zoneName must be lower case without a trailing dot".to_owned());
    }
    let name = normalize_record_name(&params.name, &zone)?;
    if name != params.name {
        return Err("the name must be lower case without a trailing dot".to_owned());
    }
    let record_type = normalize_change_type(&params.record_type)?;
    if record_type != params.record_type {
        return Err("the type must be upper case".to_owned());
    }
    let expected_op = if upsert {
        &[PlanOp::Create, PlanOp::Update][..]
    } else {
        &[PlanOp::Delete][..]
    };
    if !expected_op.contains(&params.preview.operation) {
        return Err("the preview does not describe this action".to_owned());
    }
    if upsert {
        let desired = params.desired()?;
        if params.ttl.is_none() || params.proxied.is_none() {
            return Err("an upsert carries an explicit ttl and proxied".to_owned());
        }
        if desired.content != params.content {
            return Err("the content must be in its normalized form".to_owned());
        }
        let after = params
            .preview
            .after
            .as_ref()
            .ok_or_else(|| "the preview has no proposed record".to_owned())?;
        let mut proposed = after.clone();
        proposed.id = None;
        if proposed != desired {
            return Err("the preview does not match the parameters".to_owned());
        }
        match (params.preview.operation, &params.preview.before) {
            (PlanOp::Create, None) | (PlanOp::Update, Some(_)) => {}
            _ => return Err("the preview's current record does not fit its operation".to_owned()),
        }
    } else {
        if params.ttl.is_some()
            || params.proxied.is_some()
            || params.priority.is_some()
            || params.replaces.is_some()
        {
            return Err("a delete carries only the record's name, type, and content".to_owned());
        }
        if normalize_content(&params.record_type, &params.content) != params.content
            || params.content.is_empty()
        {
            return Err("the content must be in its normalized form".to_owned());
        }
        let before = params
            .preview
            .before
            .as_ref()
            .ok_or_else(|| "the preview has no current record".to_owned())?;
        if before.content != params.content
            || before.name != params.name
            || before.record_type != params.record_type
            || params.preview.after.is_some()
        {
            return Err("the preview does not match the parameters".to_owned());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Use cases.
// ---------------------------------------------------------------------

/// A use-case failure, mapped onto API errors by the adapter.
#[derive(Debug)]
pub enum DnsError {
    /// The caller may not do this.
    Denied(Decision),
    /// The request is malformed.
    Invalid {
        /// What is wrong, safe to print.
        detail: String,
    },
    /// Nothing matches: no Cloudflare account, or no zone for the name.
    NotFound {
        /// What was not found.
        what: String,
    },
    /// The name matches more than one account.
    Conflict {
        /// What conflicts.
        detail: String,
    },
    /// The provider refused or failed.
    Provider(DnsFailure),
    /// The broker refused the request.
    Broker(BrokerError),
    /// A port failed.
    Backend {
        /// Where.
        context: &'static str,
        /// The failure.
        detail: String,
    },
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::Invalid { detail } => write!(f, "invalid: {detail}"),
            Self::NotFound { what } => write!(f, "{what} was not found"),
            Self::Conflict { detail } => write!(f, "conflict: {detail}"),
            Self::Provider(failure) => write!(f, "the DNS provider failed: {failure}"),
            Self::Broker(error) => write!(f, "{error}"),
            Self::Backend { context, detail } => write!(f, "{context} failed: {detail}"),
        }
    }
}

impl std::error::Error for DnsError {}

fn invalid(detail: impl Into<String>) -> DnsError {
    DnsError::Invalid {
        detail: detail.into(),
    }
}

/// One Cloudflare account's zones, or why they could not be read.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountZones {
    /// The account's id.
    pub account_id: String,
    /// The account's label.
    pub account_label: String,
    /// The zones the token can see.
    pub zones: Vec<DnsZone>,
    /// The failure class when the zones could not be read.
    pub failure: Option<String>,
    /// What went wrong, when it did.
    pub failure_detail: Option<String>,
}

/// The records at one name.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordsView {
    /// The account that answered.
    pub account_id: String,
    /// Its label.
    pub account_label: String,
    /// The zone the name belongs to.
    pub zone: DnsZone,
    /// The name asked about.
    pub name: String,
    /// The records, with their provider ids.
    pub records: Vec<DnsRecord>,
    /// The `domain/<key>` Registry entry the observation attached to.
    pub registry_entry: Option<String>,
    /// When the records were read (epoch milliseconds).
    pub observed_at: i64,
}

/// Which change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    /// Create or update.
    Upsert,
    /// Delete.
    Delete,
}

/// What a caller asks for.
#[derive(Clone, Debug)]
pub struct ChangeRequest {
    /// Which change.
    pub kind: ChangeKind,
    /// The record name.
    pub name: String,
    /// The record type.
    pub record_type: String,
    /// The record value.
    pub content: String,
    /// The TTL (upsert).
    pub ttl: Option<u32>,
    /// Proxied (upsert).
    pub proxied: Option<bool>,
    /// MX preference (upsert).
    pub priority: Option<u16>,
    /// The existing value to replace (upsert).
    pub replaces: Option<String>,
    /// An account id or label, when several accounts could hold the zone.
    pub account: Option<String>,
    /// Why, for the approver.
    pub reason: String,
    /// Where the request came from.
    pub origin: String,
    /// The correlation identity.
    pub correlation_id: Option<String>,
    /// A key making a retry return the request already made.
    pub idempotency_key: Option<String>,
}

/// How an executed change ended.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsOutcome {
    /// `created`, `updated`, `unchanged`, `deleted`, or `already_absent`.
    pub outcome: String,
    /// The record as read back after the change, when one exists.
    pub record: Option<DnsRecord>,
    /// Whether a read after the change confirmed it.
    pub verified: bool,
}

struct ResolvedZone {
    account: ExternalAccount,
    credentials: DnsCredentials,
    zone: DnsZone,
}

/// The DNS use cases.
#[derive(Debug)]
pub struct Dns {
    accounts: Arc<dyn ExternalAccountPort>,
    credentials: Arc<dyn ExternalCredentialStore>,
    gateway: Arc<dyn DnsGateway>,
    observations: Arc<dyn DnsObservationPort>,
    registry: Option<Arc<RegistryReadModel>>,
}

impl Dns {
    /// Composes the use cases from their ports.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn ExternalAccountPort>,
        credentials: Arc<dyn ExternalCredentialStore>,
        gateway: Arc<dyn DnsGateway>,
        observations: Arc<dyn DnsObservationPort>,
    ) -> Self {
        Self {
            accounts,
            credentials,
            gateway,
            observations,
            registry: None,
        }
    }

    /// Attaches observations to matching `domain` Registry entries.
    #[must_use]
    pub fn with_registry(mut self, registry: Arc<RegistryReadModel>) -> Self {
        self.registry = Some(registry);
        self
    }

    fn require_read(authorizer: &dyn Authorizer, principal_id: &str) -> Result<(), DnsError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::DnsRead,
                resource: None,
            },
        )
        .map(|_| ())
        .map_err(DnsError::Denied)
    }

    async fn cloudflare_accounts(
        &self,
        hint: Option<&str>,
    ) -> Result<Vec<ExternalAccount>, DnsError> {
        let all = self
            .accounts
            .list()
            .await
            .map_err(|detail| DnsError::Backend {
                context: "external accounts",
                detail,
            })?;
        let mut accounts: Vec<ExternalAccount> = all
            .into_iter()
            .filter(|account| account.kind == ExternalProviderKind::Cloudflare)
            .filter(|account| hint.is_none_or(|hint| account.id == hint || account.label == hint))
            .collect();
        accounts.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.id.cmp(&b.id)));
        if accounts.is_empty() {
            return Err(DnsError::NotFound {
                what: hint.map_or_else(
                    || "a Cloudflare account (add one with `fleetctl accounts create --kind cloudflare`)".to_owned(),
                    |hint| format!("the Cloudflare account {hint:?}"),
                ),
            });
        }
        Ok(accounts)
    }

    async fn credentials_for(&self, account: &ExternalAccount) -> Result<DnsCredentials, DnsError> {
        let token = self
            .credentials
            .load(&account.id)
            .await
            .map_err(|error| DnsError::Backend {
                context: "credential store",
                detail: error.to_string(),
            })?
            .ok_or_else(|| {
                invalid(format!(
                    "the token for account {} is not in the secret store; replace it",
                    account.label
                ))
            })?;
        Ok(DnsCredentials {
            base_url: account.base_url.clone(),
            token: SensitiveString::new(token),
        })
    }

    /// Lists the zones every Cloudflare account's token can see. One
    /// account's failure is reported on that account, not as a failure of
    /// the rest.
    ///
    /// # Errors
    ///
    /// Fails on denial, no Cloudflare account, or a backend failure.
    pub async fn zones(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        account: Option<&str>,
    ) -> Result<Vec<AccountZones>, DnsError> {
        Self::require_read(authorizer, principal_id)?;
        let mut out = Vec::new();
        for account in self.cloudflare_accounts(account).await? {
            let credentials = match self.credentials_for(&account).await {
                Ok(credentials) => credentials,
                Err(DnsError::Invalid { detail }) => {
                    out.push(AccountZones {
                        account_id: account.id,
                        account_label: account.label,
                        zones: Vec::new(),
                        failure: Some("auth".to_owned()),
                        failure_detail: Some(detail),
                    });
                    continue;
                }
                Err(other) => return Err(other),
            };
            match self.gateway.list_zones(&credentials, None).await {
                Ok(zones) => out.push(AccountZones {
                    account_id: account.id,
                    account_label: account.label,
                    zones,
                    failure: None,
                    failure_detail: None,
                }),
                Err(failure) => out.push(AccountZones {
                    account_id: account.id,
                    account_label: account.label,
                    zones: Vec::new(),
                    failure: Some(failure.class.id().to_owned()),
                    failure_detail: Some(failure.detail),
                }),
            }
        }
        Ok(out)
    }

    /// Finds the zone a name belongs to: the longest zone name that the name
    /// is at or under, across the Cloudflare accounts.
    async fn resolve_zone(
        &self,
        fqdn: &str,
        account_hint: Option<&str>,
    ) -> Result<ResolvedZone, DnsError> {
        let fqdn = normalize_hostname(fqdn, true).map_err(invalid)?;
        let accounts = self.cloudflare_accounts(account_hint).await?;
        let mut last_failure: Option<DnsFailure> = None;
        let labels: Vec<&str> = fqdn.split('.').collect();
        // The most specific candidate first; a bare TLD is never a zone.
        for start in 0..labels.len().saturating_sub(1) {
            let candidate = labels[start..].join(".");
            let mut hits: Vec<(ExternalAccount, DnsCredentials, DnsZone)> = Vec::new();
            for account in &accounts {
                let credentials = match self.credentials_for(account).await {
                    Ok(credentials) => credentials,
                    Err(DnsError::Invalid { detail }) => {
                        last_failure = Some(DnsFailure::new(DnsFailureClass::Auth, detail));
                        continue;
                    }
                    Err(other) => return Err(other),
                };
                match self
                    .gateway
                    .list_zones(&credentials, Some(&candidate))
                    .await
                {
                    Ok(zones) => {
                        if let Some(zone) = zones
                            .into_iter()
                            .find(|zone| lower_name(&zone.name) == candidate)
                        {
                            hits.push((account.clone(), credentials, zone));
                        }
                    }
                    Err(failure) => last_failure = Some(failure),
                }
            }
            if hits.len() > 1 {
                return Err(DnsError::Conflict {
                    detail: format!(
                        "the zone {candidate} is visible to {} Cloudflare accounts; name one with --account",
                        hits.len()
                    ),
                });
            }
            if let Some((account, credentials, zone)) = hits.pop() {
                return Ok(ResolvedZone {
                    account,
                    credentials,
                    zone,
                });
            }
        }
        match last_failure {
            Some(failure) => Err(DnsError::Provider(failure)),
            None => Err(DnsError::NotFound {
                what: format!("a Cloudflare zone for {fqdn}"),
            }),
        }
    }

    async fn read_records(
        &self,
        resolved: &ResolvedZone,
        name: &str,
        record_type: Option<&str>,
    ) -> Result<Vec<DnsRecord>, DnsFailure> {
        read_records(
            self.gateway.as_ref(),
            &resolved.credentials,
            &resolved.zone.id,
            name,
            record_type,
        )
        .await
    }

    /// Reads the records at a name and records them as an observation beside
    /// the matching `domain` Registry entry, when there is one.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown zone, a provider failure, or a backend
    /// failure.
    pub async fn records(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        fqdn: &str,
        record_type: Option<&str>,
        account: Option<&str>,
        now: i64,
    ) -> Result<RecordsView, DnsError> {
        Self::require_read(authorizer, principal_id)?;
        let record_type = record_type
            .map(|raw| {
                let upper = raw.trim().to_ascii_uppercase();
                if upper.is_empty()
                    || upper.len() > 16
                    || !upper.chars().all(|c| c.is_ascii_alphanumeric())
                {
                    Err(invalid("the record type filter is not a record type"))
                } else {
                    Ok(upper)
                }
            })
            .transpose()?;
        let resolved = self.resolve_zone(fqdn, account).await?;
        let name = normalize_record_name(fqdn, &resolved.zone.name).map_err(invalid)?;
        let records = self
            .read_records(&resolved, &name, record_type.as_deref())
            .await
            .map_err(DnsError::Provider)?;
        let registry_entry = self
            .matching_entry(authorizer, principal_id, &name, &resolved.zone.name)
            .await;
        self.observations
            .replace(
                &DnsObservation {
                    account_id: resolved.account.id.clone(),
                    zone_id: resolved.zone.id.clone(),
                    zone_name: resolved.zone.name.clone(),
                    name: name.clone(),
                    registry_entry: registry_entry.clone(),
                    records: records.clone(),
                    observed_at: now,
                },
                record_type.as_deref(),
            )
            .await
            .map_err(|detail| DnsError::Backend {
                context: "dns observations",
                detail,
            })?;
        Ok(RecordsView {
            account_id: resolved.account.id,
            account_label: resolved.account.label,
            zone: resolved.zone,
            name,
            records,
            registry_entry,
            observed_at: now,
        })
    }

    /// The `domain/<key>` entry that matches the name or its zone, when the
    /// Registry is wired and has one. A caller who may not read the Registry
    /// sees no match, not an error.
    async fn matching_entry(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        name: &str,
        zone_name: &str,
    ) -> Option<String> {
        let registry = self.registry.as_ref()?;
        // The name itself first (a registered subdomain), then the apex.
        let ordered = if name == zone_name {
            vec![zone_name]
        } else {
            vec![name, zone_name]
        };
        for key in ordered {
            if registry
                .get_entry(authorizer, principal_id, "domain", key)
                .await
                .is_ok()
            {
                return Some(format!("domain/{key}"));
            }
        }
        None
    }

    /// Computes the preview of a change and submits it to the broker as an
    /// action request. The preview is stored in the request's parameters, so
    /// the approver and the executor share one account and zone with the
    /// requester.
    ///
    /// # Errors
    ///
    /// Fails on denial, invalid values, an unknown zone, a provider
    /// failure, a change that would do nothing, or a broker refusal.
    #[allow(clippy::too_many_lines)]
    pub async fn request_change(
        &self,
        broker: &Broker,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        change: ChangeRequest,
        now: i64,
    ) -> Result<ActionRequest, DnsError> {
        Self::require_read(authorizer, principal_id)?;
        let record_type = normalize_change_type(&change.record_type).map_err(invalid)?;
        let resolved = self
            .resolve_zone(&change.name, change.account.as_deref())
            .await?;
        let name = normalize_record_name(&change.name, &resolved.zone.name).map_err(invalid)?;
        let current = self
            .read_records(&resolved, &name, Some(&record_type))
            .await
            .map_err(DnsError::Provider)?;
        let (action_id, params) = match change.kind {
            ChangeKind::Upsert => {
                let desired = build_desired(&DesiredRecord {
                    record_type: record_type.clone(),
                    name: name.clone(),
                    content: change.content.clone(),
                    ttl: change.ttl,
                    proxied: change.proxied,
                    priority: change.priority,
                })
                .map_err(invalid)?;
                let replaces = change
                    .replaces
                    .as_deref()
                    .map(|value| normalize_content(&record_type, value));
                let plan = plan_upsert(&current, &desired, replaces.as_deref()).map_err(invalid)?;
                if plan.operation == PlanOp::Unchanged {
                    return Err(invalid(
                        "the record already matches; there is nothing to change",
                    ));
                }
                (
                    UPSERT_ACTION,
                    ChangeParameters {
                        account_id: resolved.account.id.clone(),
                        zone_id: resolved.zone.id.clone(),
                        zone_name: resolved.zone.name.clone(),
                        name: name.clone(),
                        record_type: record_type.clone(),
                        content: desired.content.clone(),
                        ttl: Some(desired.ttl),
                        proxied: Some(desired.proxied),
                        priority: desired.priority,
                        replaces,
                        preview: plan,
                    },
                )
            }
            ChangeKind::Delete => {
                if change.ttl.is_some()
                    || change.proxied.is_some()
                    || change.priority.is_some()
                    || change.replaces.is_some()
                {
                    return Err(invalid(
                        "a delete names only the record's name, type, and content",
                    ));
                }
                let content = normalize_content(&record_type, &change.content);
                if content.is_empty() {
                    return Err(invalid(
                        "a delete names the content of the record to remove",
                    ));
                }
                let plan = plan_delete(&current, &record_type, &name, &content);
                if plan.operation == PlanOp::AlreadyAbsent {
                    return Err(DnsError::NotFound {
                        what: format!("the record {name} {record_type} with that content"),
                    });
                }
                (
                    DELETE_ACTION,
                    ChangeParameters {
                        account_id: resolved.account.id.clone(),
                        zone_id: resolved.zone.id.clone(),
                        zone_name: resolved.zone.name.clone(),
                        name: name.clone(),
                        record_type: record_type.clone(),
                        content,
                        ttl: None,
                        proxied: None,
                        priority: None,
                        replaces: None,
                        preview: plan,
                    },
                )
            }
        };
        let parameters = serde_json::to_value(&params).map_err(|error| DnsError::Backend {
            context: "parameters",
            detail: error.to_string(),
        })?;
        broker
            .create(
                authorizer,
                principal_id,
                NewActionRequest {
                    action_id: action_id.to_owned(),
                    target: params.target(),
                    parameters,
                    reason: change.reason,
                    origin: change.origin,
                    correlation_id: change.correlation_id,
                    idempotency_key: change.idempotency_key,
                },
                now,
            )
            .await
            .map_err(DnsError::Broker)
    }

    /// Runs an approved change: the operation executor calls this with the
    /// operation's kind and payload. It re-reads the zone, refuses a stale
    /// preview, applies the change, and verifies it with a read.
    ///
    /// # Errors
    ///
    /// Fails with a caller-safe reason: a malformed payload, a stale
    /// preview, a provider failure, or a failed verification.
    #[allow(clippy::too_many_lines)]
    pub async fn execute(&self, kind: &str, payload: &str) -> Result<DnsOutcome, String> {
        let upsert = match kind {
            UPSERT_ACTION => true,
            DELETE_ACTION => false,
            other => return Err(format!("{other} is not a DNS operation")),
        };
        let params: ChangeParameters = serde_json::from_str(payload)
            .map_err(|_| "the operation payload is not a DNS change".to_owned())?;
        validate_parameters(&params, upsert)?;
        let account =
            self.accounts.get(&params.account_id).await.map_err(|_| {
                "the Cloudflare account is gone; the change was not applied".to_owned()
            })?;
        if account.kind != ExternalProviderKind::Cloudflare {
            return Err("the account is not a Cloudflare account".to_owned());
        }
        let credentials = self
            .credentials_for(&account)
            .await
            .map_err(|error| error.to_string())?;
        let gateway = self.gateway.as_ref();
        let zone = params.zone_id.as_str();
        let read = || async {
            read_records(
                gateway,
                &credentials,
                zone,
                &params.name,
                Some(&params.record_type),
            )
            .await
            .map_err(|failure| failure.to_string())
        };
        let current = read().await?;
        let (plan, desired) = if upsert {
            let desired = params.desired()?;
            let plan = plan_upsert(&current, &desired, params.replaces.as_deref())
                .map_err(|reason| stale(&format!("the zone no longer allows it: {reason}")))?;
            (plan, Some(desired))
        } else {
            (
                plan_delete(&current, &params.record_type, &params.name, &params.content),
                None,
            )
        };
        // Already in place: an earlier attempt got there, or someone did.
        match plan.operation {
            PlanOp::Unchanged => {
                return Ok(DnsOutcome {
                    outcome: "unchanged".to_owned(),
                    record: plan.after,
                    verified: true,
                });
            }
            PlanOp::AlreadyAbsent => {
                return Ok(DnsOutcome {
                    outcome: "already_absent".to_owned(),
                    record: None,
                    verified: true,
                });
            }
            _ => {}
        }
        if plan.operation != params.preview.operation || plan.before != params.preview.before {
            return Err(stale(&format!(
                "the preview said {} of {}, the zone now says {} of {}",
                params.preview.operation.id(),
                describe(params.preview.before.as_ref()),
                plan.operation.id(),
                describe(plan.before.as_ref()),
            )));
        }
        let applied = match (plan.operation, &plan.before, &desired) {
            (PlanOp::Create, _, Some(desired)) => {
                match gateway.create_record(&credentials, zone, desired).await {
                    Ok(_) => Ok(()),
                    // The provider says an identical record exists: a racing
                    // writer or an earlier attempt. The read below decides.
                    Err(failure) if failure.class == DnsFailureClass::Conflict => {
                        let again = read().await?;
                        if plan_upsert(&again, desired, params.replaces.as_deref())
                            .is_ok_and(|plan| plan.operation == PlanOp::Unchanged)
                        {
                            Ok(())
                        } else {
                            Err(failure)
                        }
                    }
                    Err(failure) => Err(failure),
                }
            }
            (PlanOp::Update, Some(before), Some(desired)) => {
                let id = before
                    .id
                    .as_deref()
                    .ok_or_else(|| "the current record has no provider id".to_owned())?;
                gateway
                    .update_record(&credentials, zone, id, desired)
                    .await
                    .map(|_| ())
            }
            (PlanOp::Delete, Some(before), None) => {
                let id = before
                    .id
                    .as_deref()
                    .ok_or_else(|| "the current record has no provider id".to_owned())?;
                match gateway.delete_record(&credentials, zone, id).await {
                    // Gone between the read and the delete: the goal.
                    Err(failure) if failure.class == DnsFailureClass::NotFound => Ok(()),
                    other => other,
                }
            }
            _ => return Err("the plan does not fit the action".to_owned()),
        };
        applied.map_err(|failure| failure.to_string())?;
        // Verification: read the record back.
        let after = read().await?;
        let (outcome, record) = if let Some(desired) = &desired {
            let found = after
                .iter()
                .find(|record| record.content == desired.content)
                .filter(|record| {
                    let mut with_id = desired.clone();
                    with_id.id.clone_from(&record.id);
                    record.same_attributes(&with_id)
                })
                .cloned()
                .ok_or_else(|| {
                    "verification failed: the record read back does not match the change".to_owned()
                })?;
            (
                if plan.operation == PlanOp::Create {
                    "created"
                } else {
                    "updated"
                },
                Some(found),
            )
        } else {
            if after.iter().any(|record| {
                record.content == normalize_content(&params.record_type, &params.content)
            }) {
                return Err(
                    "verification failed: the record is still present after the delete".to_owned(),
                );
            }
            ("deleted", None)
        };
        Ok(DnsOutcome {
            outcome: outcome.to_owned(),
            record,
            verified: true,
        })
    }
}

fn stale(reason: &str) -> String {
    format!(
        "stale preview: {reason}; nothing was changed, so submit a new request from the current state"
    )
}

fn describe(record: Option<&DnsRecord>) -> String {
    record.map_or_else(
        || "no record".to_owned(),
        |record| {
            format!(
                "{} {} {} (ttl {}, proxied {})",
                record.record_type, record.name, record.content, record.ttl, record.proxied
            )
        },
    )
}

/// Reads and normalizes the records at a name (and type), refusing a result
/// past [`MAX_RECORDS`].
async fn read_records(
    gateway: &dyn DnsGateway,
    credentials: &DnsCredentials,
    zone_id: &str,
    name: &str,
    record_type: Option<&str>,
) -> Result<Vec<DnsRecord>, DnsFailure> {
    let records = gateway
        .list_records(credentials, zone_id, Some(name), record_type)
        .await?;
    if records.len() > MAX_RECORDS {
        return Err(DnsFailure::new(
            DnsFailureClass::Invalid,
            format!("more than {MAX_RECORDS} records at one name"),
        ));
    }
    Ok(records
        .into_iter()
        .map(normalize_remote)
        .filter(|record| record.name == name)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(record_type: &str, content: &str, ttl: u32) -> DnsRecord {
        DnsRecord {
            id: Some(format!("id-{content}")),
            record_type: record_type.to_owned(),
            name: "www.example.com".to_owned(),
            content: content.to_owned(),
            ttl,
            proxied: false,
            priority: None,
        }
    }

    fn desired(record_type: &str, content: &str) -> DnsRecord {
        build_desired(&DesiredRecord {
            record_type: record_type.to_owned(),
            name: "WWW.Example.com.".to_owned(),
            content: content.to_owned(),
            ttl: Some(300),
            proxied: None,
            priority: None,
        })
        .expect("valid")
    }

    #[test]
    fn names_are_normalized_and_confined_to_the_zone() {
        assert_eq!(
            normalize_record_name("WWW.Example.COM.", "example.com").unwrap(),
            "www.example.com"
        );
        assert_eq!(
            normalize_record_name("*.example.com", "example.com").unwrap(),
            "*.example.com"
        );
        assert!(normalize_record_name("example.org", "example.com").is_err());
        assert!(normalize_record_name("evilexample.com", "example.com").is_err());
        assert!(normalize_record_name("a.*.example.com", "example.com").is_err());
        assert!(normalize_record_name("a b.example.com", "example.com").is_err());
        assert!(normalize_record_name("-a.example.com", "example.com").is_err());
    }

    #[test]
    fn only_the_safe_types_may_change() {
        for ok in ["a", "AAAA", "cname", "TXT", "mx"] {
            assert!(normalize_change_type(ok).is_ok(), "{ok}");
        }
        for refused in ["CAA", "NS", "SRV", "SOA", "PTR", ""] {
            assert!(normalize_change_type(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn values_are_validated_per_type() {
        let build = |record_type: &str,
                     content: &str,
                     ttl: Option<u32>,
                     proxied: Option<bool>,
                     priority: Option<u16>| {
            build_desired(&DesiredRecord {
                record_type: record_type.to_owned(),
                name: "www.example.com".to_owned(),
                content: content.to_owned(),
                ttl,
                proxied,
                priority,
            })
        };
        assert!(build("A", "203.0.113.4", None, None, None).is_ok());
        assert!(build("A", "2001:db8::1", None, None, None).is_err());
        assert_eq!(
            build("AAAA", "2001:DB8:0:0::1", None, None, None)
                .unwrap()
                .content,
            "2001:db8::1"
        );
        assert!(build("AAAA", "203.0.113.4", None, None, None).is_err());
        assert_eq!(
            build("CNAME", "Target.Example.net.", None, None, None)
                .unwrap()
                .content,
            "target.example.net"
        );
        assert!(build("CNAME", "www.example.com", None, None, None).is_err());
        assert!(build("CNAME", "203.0.113.4 x", None, None, None).is_err());
        assert!(build("MX", "mail.example.com", None, None, None).is_err());
        assert!(build("MX", "mail.example.com", None, None, Some(10)).is_ok());
        assert!(build("A", "203.0.113.4", None, None, Some(10)).is_err());
        assert_eq!(
            build("TXT", "\"v=spf1 -all\"", None, None, None)
                .unwrap()
                .content,
            "v=spf1 -all"
        );
        assert!(build("TXT", "", None, None, None).is_err());
        assert!(build("TXT", "line\nbreak", None, None, None).is_err());
        assert!(build("TXT", &"x".repeat(MAX_TXT_BYTES + 1), None, None, None).is_err());
        // TTL bounds and the proxied rules.
        assert!(build("A", "203.0.113.4", Some(30), None, None).is_err());
        assert!(build("A", "203.0.113.4", Some(86_401), None, None).is_err());
        assert!(build("A", "203.0.113.4", Some(1), None, None).is_ok());
        assert!(build("A", "203.0.113.4", Some(60), Some(true), None).is_err());
        assert!(build("A", "203.0.113.4", Some(1), Some(true), None).is_ok());
        assert!(build("TXT", "x", Some(1), Some(true), None).is_err());
    }

    #[test]
    fn an_upsert_without_a_match_creates_and_with_one_updates() {
        let current = vec![record("A", "203.0.113.1", 300)];
        let create = plan_upsert(&current, &desired("A", "203.0.113.9"), None).unwrap();
        assert_eq!(create.operation, PlanOp::Create);
        assert!(create.before.is_none());

        let mut changed = desired("A", "203.0.113.1");
        changed.ttl = 600;
        let update = plan_upsert(&current, &changed, None).unwrap();
        assert_eq!(update.operation, PlanOp::Update);
        assert_eq!(
            update.before.as_ref().and_then(|r| r.id.as_deref()),
            Some("id-203.0.113.1")
        );
        assert_eq!(update.changes.len(), 1);
        assert_eq!(update.changes[0].field, "ttl");

        let same = plan_upsert(&current, &desired("A", "203.0.113.1"), None).unwrap();
        assert_eq!(same.operation, PlanOp::Unchanged);
    }

    #[test]
    fn replaces_names_the_value_to_change_and_must_exist() {
        let current = vec![
            record("A", "203.0.113.1", 300),
            record("A", "203.0.113.2", 300),
        ];
        let plan =
            plan_upsert(&current, &desired("A", "203.0.113.9"), Some("203.0.113.2")).unwrap();
        assert_eq!(plan.operation, PlanOp::Update);
        assert_eq!(plan.before.unwrap().content, "203.0.113.2");
        assert!(plan_upsert(&current, &desired("A", "203.0.113.9"), Some("203.0.113.7")).is_err());
        // Desired content exists already, but replaces points elsewhere.
        assert!(plan_upsert(&current, &desired("A", "203.0.113.1"), Some("203.0.113.2")).is_err());
    }

    #[test]
    fn a_cname_upsert_replaces_the_single_value() {
        let current = vec![record("CNAME", "old.example.net", 300)];
        let plan = plan_upsert(&current, &desired("CNAME", "new.example.net"), None).unwrap();
        assert_eq!(plan.operation, PlanOp::Update);
        let none = plan_upsert(&[], &desired("CNAME", "new.example.net"), None).unwrap();
        assert_eq!(none.operation, PlanOp::Create);
    }

    #[test]
    fn a_delete_plans_by_content_and_is_idempotent() {
        let current = vec![record("TXT", "v=spf1 -all", 300)];
        let plan = plan_delete(&current, "TXT", "www.example.com", "\"v=spf1 -all\"");
        assert_eq!(plan.operation, PlanOp::Delete);
        assert_eq!(plan.changes.len(), 3);
        let gone = plan_delete(&[], "TXT", "www.example.com", "v=spf1 -all");
        assert_eq!(gone.operation, PlanOp::AlreadyAbsent);
    }

    #[test]
    fn remote_records_normalize_for_comparison() {
        let remote = normalize_remote(DnsRecord {
            id: Some("r".to_owned()),
            record_type: "txt".to_owned(),
            name: "WWW.Example.com".to_owned(),
            content: "\"hello\"".to_owned(),
            ttl: 1,
            proxied: false,
            priority: None,
        });
        assert_eq!(remote.record_type, "TXT");
        assert_eq!(remote.name, "www.example.com");
        assert_eq!(remote.content, "hello");
    }

    fn upsert_params() -> ChangeParameters {
        let desired = desired("A", "203.0.113.9");
        ChangeParameters {
            account_id: "acc1".to_owned(),
            zone_id: "zone1".to_owned(),
            zone_name: "example.com".to_owned(),
            name: "www.example.com".to_owned(),
            record_type: "A".to_owned(),
            content: "203.0.113.9".to_owned(),
            ttl: Some(300),
            proxied: Some(false),
            priority: None,
            replaces: None,
            preview: Plan {
                operation: PlanOp::Create,
                changes: diff(None, Some(&desired)),
                before: None,
                after: Some(desired),
            },
        }
    }

    #[test]
    fn the_actions_are_approve_by_default_and_check_the_preview() {
        let action = DnsRecordAction::upsert();
        assert_eq!(action.risk_class(), RiskClass::Approve);
        assert_eq!(action.operation_kind(), UPSERT_ACTION);
        let params = upsert_params();
        let value = serde_json::to_value(&params).unwrap();
        assert!(action.validate("www.example.com A", &value).is_ok());
        assert!(action.validate("other A", &value).is_err());
        // The delete action refuses an upsert's parameters.
        assert!(
            DnsRecordAction::delete()
                .validate("www.example.com A", &value)
                .is_err()
        );
        // A preview that does not match the parameters is refused.
        let mut lying = params;
        lying.content = "203.0.113.10".to_owned();
        let value = serde_json::to_value(&lying).unwrap();
        assert!(action.validate("www.example.com A", &value).is_err());
        // Parameters with no preview are not a DNS change.
        let bare = json!({"name": "www.example.com", "type": "A", "content": "203.0.113.9"});
        assert!(action.validate("www.example.com A", &bare).is_err());
    }

    #[test]
    fn the_operation_payload_is_the_parameters_and_deterministic() {
        let action = DnsRecordAction::upsert();
        let params = serde_json::to_value(upsert_params()).unwrap();
        let request = ActionRequest {
            id: "r1".to_owned(),
            requester: "p".to_owned(),
            origin: "api".to_owned(),
            action_id: UPSERT_ACTION.to_owned(),
            target: "www.example.com A".to_owned(),
            parameters: params,
            risk_class: RiskClass::Approve,
            reason: String::new(),
            state: fleet_core::ActionRequestState::Approved,
            decided_by: None,
            decided_at: None,
            decision_note: None,
            operation_id: None,
            failure: None,
            correlation_id: None,
            idempotency_key: None,
            created_at: 0,
            expires_at: 0,
            updated_at: 0,
        };
        let first = action.operation(&request).unwrap();
        let second = action.operation(&request).unwrap();
        assert_eq!(first.payload_json, second.payload_json);
        assert_eq!(first.kind, UPSERT_ACTION);
    }
}
