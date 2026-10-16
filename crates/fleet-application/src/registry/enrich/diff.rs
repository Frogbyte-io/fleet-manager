//! Comparing a domain entry's recorded fields with what the lookups saw.
//!
//! Pure functions: no clock, no I/O. The assessment is computed at read
//! time against the entry as the active revision holds it, so a Git commit
//! that fixes a field clears its drift without any new lookup.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::model::{
    Assessment, DomainObservation, FieldDiff, FieldState, RdapStatus, Severity, SuggestedField,
    Warning, WarningCode,
};

/// Days at or under which an expiring domain is an error, not a warning.
const URGENT_DAYS: i64 = 7;

/// Words that decorate a registrar's legal name without identifying it.
const LEGAL_NOISE: [&str; 14] = [
    "llc", "inc", "ltd", "limited", "as", "ab", "gmbh", "bv", "sa", "oy", "corp", "co", "com",
    "the",
];

/// Well-known DNS hosts and where their nameservers live, for providers
/// whose name is not part of the nameserver name. An entry with a dot is a
/// domain suffix; one without is a nameserver label (or a label prefix
/// before a hyphen, as in `awsdns-12`).
const DNS_HOST_ALIASES: [(&str, &[&str]); 9] = [
    ("hostinger", &["dns-parking.com", "hostinger.com"]),
    ("godaddy", &["domaincontrol.com"]),
    ("namecheap", &["registrar-servers.com"]),
    ("route53", &["awsdns"]),
    ("aws", &["awsdns"]),
    ("google", &["googledomains.com", "google.com"]),
    ("netlify", &["nsone.net"]),
    ("vercel", &["vercel-dns.com"]),
    ("domeneshop", &["hyp.net"]),
];

/// Words that say nothing about who the DNS host is.
const DNS_NOISE: [&str; 12] = [
    "dns",
    "host",
    "hosting",
    "name",
    "names",
    "server",
    "servers",
    "nameserver",
    "nameservers",
    "provider",
    "managed",
    "default",
];

/// `dnsHost` values that mean "not recorded separately".
fn generic_dns_host(text: &str) -> bool {
    let lowered = text.to_lowercase();
    lowered.contains("registrar")
        || lowered.contains("same as")
        || matches!(
            lowered.trim(),
            "" | "-" | "n/a" | "none" | "unknown" | "same"
        )
}

fn label_matches(label: &str, token: &str) -> bool {
    label == token
        || label
            .strip_prefix(token)
            .is_some_and(|rest| rest.starts_with('-'))
}

/// Whether the nameservers belong to the named DNS host, or `None` when
/// the value says nothing checkable (empty, "same as registrar"). Each word
/// of the value (four letters or more, noise words dropped) is compared
/// with whole nameserver labels, never as a substring; a known provider's
/// alias hosts count too.
#[must_use]
pub fn dns_host_matches(dns_host: &str, nameservers: &[String]) -> Option<bool> {
    if generic_dns_host(dns_host) {
        return None;
    }
    let words: Vec<String> = dns_host
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect();
    let joined = words.join("");
    let candidates: Vec<&String> = words
        .iter()
        .filter(|word| word.chars().count() >= 4 && !DNS_NOISE.contains(&word.as_str()))
        .collect();
    let aliases: Vec<&str> = DNS_HOST_ALIASES
        .iter()
        .filter(|(name, _)| words.iter().any(|word| word == name) || joined == *name)
        .flat_map(|(_, hosts)| hosts.iter().copied())
        .collect();
    if candidates.is_empty() && aliases.is_empty() {
        return None;
    }
    let hit = nameservers.iter().any(|ns| {
        let lowered = ns.to_lowercase();
        let name = lowered.trim_end_matches('.');
        let labels: Vec<&str> = name.split('.').collect();
        candidates
            .iter()
            .any(|token| labels.iter().any(|label| label_matches(label, token)))
            || aliases.iter().any(|alias| {
                if alias.contains('.') {
                    name == *alias || name.ends_with(&format!(".{alias}"))
                } else {
                    labels.iter().any(|label| label_matches(label, alias))
                }
            })
    });
    Some(hit)
}

/// The days since 1970-01-01 of an epoch-millisecond instant.
#[must_use]
pub fn days_from_millis(millis: i64) -> i64 {
    millis.div_euclid(86_400_000)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The days since 1970-01-01 of the `YYYY-MM-DD` prefix of a date or
/// RFC 3339 timestamp, or `None` when it is not one.
#[must_use]
pub fn days_from_date(text: &str) -> Option<i64> {
    let head = text.get(..10)?;
    let mut parts = head.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some()
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
    {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// The `YYYY-MM-DD` of an RFC 3339 timestamp or date, when it is one.
#[must_use]
pub fn date_part(text: &str) -> Option<String> {
    days_from_date(text)?;
    text.get(..10).map(str::to_owned)
}

fn tokens_ordered(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty() && !LEGAL_NOISE.contains(token))
        .map(str::to_owned)
        .collect()
}

fn tokens(text: &str) -> BTreeSet<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty() && !LEGAL_NOISE.contains(token))
        .map(str::to_owned)
        .collect()
}

/// Registrars known by more than one name: rebrands and legal entities
/// whose names share no word. Each group is a set of normalized phrases.
const REGISTRAR_ALIASES: [&[&str]; 5] = [
    &["route 53", "amazon registrar", "amazon"],
    &["google domains", "squarespace domains", "squarespace"],
    &["godaddy", "wild west domains"],
    &["hostinger", "hostinger operations"],
    &["domeneshop"],
];

fn normalized(text: &str) -> String {
    format!(" {} ", tokens_ordered(text).join(" "))
}

fn alias_group(text: &str) -> Option<usize> {
    let norm = normalized(text);
    REGISTRAR_ALIASES.iter().position(|group| {
        group
            .iter()
            .any(|phrase| norm.contains(&format!(" {phrase} ")))
    })
}

/// Whether two registrar names plausibly name the same company: after
/// dropping punctuation and legal suffixes, one's words contain the
/// other's (`GoDaddy.com, LLC` and `GoDaddy`), or both belong to one
/// alias group (`Google Domains` and `Squarespace Domains`).
#[must_use]
pub fn registrars_match(recorded: &str, observed: &str) -> bool {
    let (a, b) = (tokens(recorded), tokens(observed));
    if a.is_empty() || b.is_empty() {
        return recorded.trim().eq_ignore_ascii_case(observed.trim());
    }
    if a.is_subset(&b) || b.is_subset(&a) {
        return true;
    }
    matches!((alias_group(recorded), alias_group(observed)), (Some(x), Some(y)) if x == y)
}

fn string_field<'a>(fields: &'a Value, name: &str) -> Option<&'a str> {
    fields
        .get(name)?
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn name_set(values: impl IntoIterator<Item = impl AsRef<str>>) -> BTreeSet<String> {
    values
        .into_iter()
        .map(|value| value.as_ref().trim().trim_end_matches('.').to_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn recorded_nameservers(fields: &Value) -> Option<BTreeSet<String>> {
    let set = name_set(
        fields
            .get("nameservers")?
            .as_array()?
            .iter()
            .filter_map(Value::as_str),
    );
    (!set.is_empty()).then_some(set)
}

/// The nameservers the observation supports: the live DNS delegation when
/// it answered, else what the registry lists.
fn observed_nameservers(observation: &DomainObservation) -> Option<BTreeSet<String>> {
    let live = name_set(&observation.dns.apex.ns);
    if !live.is_empty() {
        return Some(live);
    }
    let registry = name_set(&observation.rdap.nameservers);
    (!registry.is_empty()).then_some(registry)
}

fn observed_expiry(observation: &DomainObservation) -> Option<String> {
    observation.rdap.expires.as_deref().and_then(date_part)
}

fn observed_registrar(observation: &DomainObservation) -> Option<&str> {
    observation
        .rdap
        .registrar
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn state_of(recorded: bool, observed: bool, agrees: impl FnOnce() -> bool) -> FieldState {
    match (recorded, observed) {
        (true, true) if agrees() => FieldState::InSync,
        (_, true) => FieldState::Changed,
        (_, false) => FieldState::Unknown,
    }
}

/// Compares an entry's `fields` with its latest observation.
///
/// * `today` and `window_days` decide "expiring": the domain's effective
///   expiry (the registry's when known, else the recorded one) is at most
///   `window_days` away.
///
/// With no observation the per-field states are all `unknown`, yet the
/// expiry rules still run on the recorded date, so a domain that is about to
/// lapse is reported even before its first lookup.
#[must_use]
pub fn assess(
    fields: &Value,
    observation: Option<&DomainObservation>,
    today: i64,
    window_days: i64,
) -> Assessment {
    assess_with(
        fields,
        observation,
        &AssessContext {
            today,
            window_days,
            now_millis: today * MILLIS_PER_DAY,
            stale_after_millis: None,
        },
    )
}

/// What the assessment needs to know about "now".
#[derive(Clone, Copy, Debug)]
pub struct AssessContext {
    /// Today as days since 1970-01-01.
    pub today: i64,
    /// Domains expiring within this many days are flagged.
    pub window_days: i64,
    /// The current time in epoch milliseconds.
    pub now_millis: i64,
    /// An observation whose last good data is older than this is flagged
    /// stale. `None` when the scheduled sweep is off.
    pub stale_after_millis: Option<i64>,
}

const MILLIS_PER_DAY: i64 = 86_400_000;
/// Consecutive failed lookups after which the failure is a warning.
const PERSISTENT_FAILURES: u32 = 3;

/// [`assess`] with the full context, including staleness.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn assess_with(
    fields: &Value,
    observation: Option<&DomainObservation>,
    context: &AssessContext,
) -> Assessment {
    let today = context.today;
    let window_days = context.window_days;
    let mut diffs = Vec::new();
    let mut warnings = Vec::new();
    let mut suggestion = Vec::new();

    // registrar
    let recorded_registrar = string_field(fields, "registrar");
    let seen_registrar = observation.and_then(observed_registrar);
    let state = state_of(
        recorded_registrar.is_some(),
        seen_registrar.is_some(),
        || {
            registrars_match(
                recorded_registrar.unwrap_or(""),
                seen_registrar.unwrap_or(""),
            )
        },
    );
    diffs.push(FieldDiff {
        field: "registrar",
        state,
        recorded: recorded_registrar.map(|v| json!(v)),
        observed: seen_registrar.map(|v| json!(v)),
    });
    if state == FieldState::Changed {
        if let (Some(recorded), Some(seen)) = (recorded_registrar, seen_registrar) {
            warnings.push(Warning {
                code: WarningCode::RegistrarMismatch,
                severity: Severity::Warn,
                message: format!(
                    "The registry lists the registrar as {seen}, but the entry says {recorded}."
                ),
            });
        }
        if let Some(seen) = seen_registrar {
            suggestion.push(SuggestedField {
                field: "registrar",
                value: json!(seen),
            });
        }
    }

    // expires
    let recorded_expiry = string_field(fields, "expires").and_then(date_part);
    let seen_expiry = observation.and_then(observed_expiry);
    let state = state_of(recorded_expiry.is_some(), seen_expiry.is_some(), || {
        recorded_expiry == seen_expiry
    });
    diffs.push(FieldDiff {
        field: "expires",
        state,
        recorded: recorded_expiry.as_ref().map(|v| json!(v)),
        observed: seen_expiry.as_ref().map(|v| json!(v)),
    });
    if state == FieldState::Changed {
        if let (Some(recorded), Some(seen)) = (&recorded_expiry, &seen_expiry) {
            warnings.push(Warning {
                code: WarningCode::ExpiryChanged,
                severity: Severity::Info,
                message: format!(
                    "The registry lists the expiry as {seen}, but the entry says {recorded}."
                ),
            });
        }
        if let Some(seen) = &seen_expiry {
            suggestion.push(SuggestedField {
                field: "expires",
                value: json!(seen),
            });
        }
    }

    // nameservers
    let recorded_ns = recorded_nameservers(fields);
    let seen_ns = observation.and_then(observed_nameservers);
    let state = state_of(recorded_ns.is_some(), seen_ns.is_some(), || {
        recorded_ns == seen_ns
    });
    diffs.push(FieldDiff {
        field: "nameservers",
        state,
        recorded: recorded_ns.as_ref().map(|set| json!(set)),
        observed: seen_ns.as_ref().map(|set| json!(set)),
    });
    if state == FieldState::Changed {
        if recorded_ns.is_some() {
            warnings.push(Warning {
                code: WarningCode::NameserversMismatch,
                severity: Severity::Warn,
                message: "The delegated nameservers differ from the entry's nameservers."
                    .to_owned(),
            });
        }
        if let Some(seen) = &seen_ns {
            suggestion.push(SuggestedField {
                field: "nameservers",
                value: json!(seen),
            });
        }
    }

    // dnsHost: derived from the nameservers; never suggested, because a
    // provider's name cannot be derived from its servers.
    let dns_host = string_field(fields, "dnsHost");
    let state = match (dns_host, &seen_ns) {
        (Some(host), Some(ns)) => {
            let names: Vec<String> = ns.iter().cloned().collect();
            match dns_host_matches(host, &names) {
                Some(true) => FieldState::InSync,
                Some(false) => FieldState::Changed,
                None => FieldState::Unknown,
            }
        }
        _ => FieldState::Unknown,
    };
    diffs.push(FieldDiff {
        field: "dnsHost",
        state,
        recorded: dns_host.map(|v| json!(v)),
        observed: seen_ns.as_ref().map(|set| json!(set)),
    });
    if state == FieldState::Changed {
        warnings.push(Warning {
            code: WarningCode::DnsHostMismatch,
            // Provider names are free text; a mismatch is a hint.
            severity: Severity::Info,
            message: format!(
                "The nameservers do not look like {}'s.",
                dns_host.unwrap_or_default()
            ),
        });
    }

    // expiry window
    let effective = seen_expiry.as_ref().or(recorded_expiry.as_ref());
    if let Some(days_left) = effective
        .and_then(|date| days_from_date(date))
        .map(|day| day - today)
        .filter(|days| *days <= window_days)
    {
        let when = match days_left.cmp(&0) {
            std::cmp::Ordering::Less => format!("expired {} days ago", -days_left),
            std::cmp::Ordering::Equal => "expires today".to_owned(),
            std::cmp::Ordering::Greater => format!("expires in {days_left} days"),
        };
        let severity = if days_left <= URGENT_DAYS {
            Severity::Err
        } else {
            Severity::Warn
        };
        if fields.get("autoRenew").and_then(Value::as_bool) == Some(false) {
            warnings.push(Warning {
                code: WarningCode::AutoRenewOffExpiring,
                severity,
                message: format!("Auto-renew is off and the domain {when}."),
            });
        } else {
            warnings.push(Warning {
                code: WarningCode::Expiring,
                severity,
                message: format!("The domain {when}."),
            });
        }
    }

    if let Some(observation) = observation {
        observation_health(observation, context, &mut warnings);
    }

    // "Most serious first", stable among equals.
    warnings.sort_by_key(|warning| std::cmp::Reverse(warning.severity.rank()));

    Assessment {
        diffs,
        warnings,
        suggestion,
    }
}

/// Warnings about the observation itself: not registered, lookups
/// failing, data gone stale.
fn observation_health(
    observation: &DomainObservation,
    context: &AssessContext,
    warnings: &mut Vec<Warning>,
) {
    if observation.rdap.status == RdapStatus::NotFound {
        warnings.push(Warning {
            code: WarningCode::RdapNotFound,
            severity: Severity::Warn,
            message: "The registry reports this domain is not registered. Check the entry's fqdn (it should be a registrable domain, not a subdomain).".to_owned(),
        });
    }
    let error = observation.last_error.as_deref().unwrap_or("unknown error");
    if observation.failures >= PERSISTENT_FAILURES {
        warnings.push(Warning {
            code: WarningCode::LookupFailing,
            severity: Severity::Warn,
            message: format!(
                "Lookups have failed {} times in a row: {error}.",
                observation.failures
            ),
        });
    }
    let good_at = observation.stale_since.unwrap_or(observation.observed_at);
    let age_days = (context.now_millis - good_at).max(0) / MILLIS_PER_DAY;
    if observation.stale_since.is_some() {
        warnings.push(Warning {
            code: WarningCode::StaleObservation,
            severity: Severity::Info,
            message: format!(
                "The latest lookup failed ({error}); showing data from {age_days} days ago."
            ),
        });
    } else if context
        .stale_after_millis
        .is_some_and(|limit| context.now_millis - good_at > limit)
    {
        warnings.push(Warning {
            code: WarningCode::StaleObservation,
            severity: Severity::Info,
            message: format!(
                "No lookup has succeeded for {age_days} days; the scheduled sweep may not be reaching this domain."
            ),
        });
    }
}

impl Severity {
    fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Warn => 1,
            Self::Err => 2,
        }
    }
}
