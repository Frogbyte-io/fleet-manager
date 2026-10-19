//! Semantic validation for the Registry kinds (FM-1010, ADR 0016).
//!
//! The Registry is descriptive desired state: nothing here plans or applies
//! anything. Validation runs inside [`crate::validate_sources_report`], the
//! one entry point the controller (activation) and `fleetctl` share, so a
//! revision is judged identically in both places.
//!
//! Every string in a Registry spec runs through the controller's credential
//! scrubber ([`fleet_core::redact_credentials`]); a match is an error that
//! names the field path and never the value.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::{
    Diagnostic,
    kinds::{RegistryEntrySpec, RegistryRelationTarget, RegistryScalarType, RegistryTypeSpec},
};

/// A type Fleet ships (FM-1011 supplies `domain` and `service`). A
/// repository cannot redefine one.
#[derive(Clone, Debug)]
pub struct BuiltinRegistryType {
    /// The type's name, as entries reference it.
    pub name: String,
    /// The type's definition.
    pub spec: RegistryTypeSpec,
}

/// What validation knows beyond the candidate revision. `default()` carries
/// Fleet's built-in types ([`crate::registry_builtin`]), so every caller that
/// does not build a context resolves `domain` and `service`.
#[derive(Clone, Debug)]
pub struct RegistryContext {
    /// Built-in types. Entries may use them; redefining one is an error.
    pub builtin_types: Vec<BuiltinRegistryType>,
    /// Known relation targets by class: `machine`, `project`, `coolify`,
    /// `proxmoxGuest`. A class that is absent is not checked for dangling
    /// targets (the observed side may be unknown to the caller); a present
    /// class warns for targets outside it. For `machine` and `project`, the
    /// `Machine` and `Project` resources in the revision count as known too,
    /// but only when the class is present. Independently of this map, every
    /// target is format-checked: machine and project names must be slugs,
    /// Coolify and Proxmox references must be non-empty, at most 128
    /// characters, with no whitespace or control characters. A registry
    /// target must name a defined or built-in type (an error), and a
    /// missing entry of such a type is a warning.
    pub known_targets: BTreeMap<String, BTreeSet<String>>,
}

impl Default for RegistryContext {
    fn default() -> Self {
        Self {
            builtin_types: crate::registry_builtin::builtin_registry_types(),
            known_targets: BTreeMap::new(),
        }
    }
}

const MAX_STRING: usize = 512;
const MAX_TEXT: usize = 4000;
const MAX_KEY: usize = 128;

fn diagnostic(code: &'static str, location: String, message: impl Into<String>) -> Diagnostic {
    Diagnostic {
        code,
        location,
        message: message.into(),
    }
}

/// A map key that is safe to print: a key that is not a plain field name
/// could itself be a credential, so it is never echoed.
fn safe_key(key: &str) -> &str {
    if is_field_name(key) {
        key
    } else {
        "<invalid-name>"
    }
}

fn is_field_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 63
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_alphanumeric())
}

fn is_slug(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.split('-').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() && !c.is_ascii_uppercase())
        })
}

fn is_key_value(key: &str) -> bool {
    let mut chars = key.chars();
    key.len() <= MAX_KEY
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '+' | '-'))
}

/// A DNS name: dot-separated labels of letters, digits, and hyphens; a
/// label may start with an underscore (`_dmarc.example.com`). A trailing
/// dot is refused, and so is a name whose last label is all digits, so a
/// bare IPv4 address is not a hostname.
fn is_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            let body = label.strip_prefix('_').unwrap_or(label);
            !body.is_empty()
                && label.len() <= 63
                && !body.starts_with('-')
                && !body.ends_with('-')
                && body.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        && !value
            .rsplit('.')
            .next()
            .is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit()))
}

fn is_email(value: &str) -> bool {
    value.len() <= 254
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && local.len() <= 64
                && !local.contains(['@', ',', ';', '<', '>', '(', ')', '[', ']', '"'])
                && !value.chars().any(|c| c.is_whitespace() || c.is_control())
                && is_hostname(domain)
        })
}

fn is_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        value
            .get(range)
            .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))?
            .parse()
            .ok()
    };
    let (Some(year), Some(month), Some(day)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year >= 1 && (1..=days).contains(&day)
}

fn is_money(value: &str) -> bool {
    let Some((amount, code)) = value.split_once(' ') else {
        return false;
    };
    let amount = amount.strip_prefix('-').unwrap_or(amount);
    let (whole, fraction) = amount
        .split_once('.')
        .map_or((amount, None), |(w, f)| (w, Some(f)));
    !whole.is_empty()
        && whole.len() <= 15
        && whole.bytes().all(|b| b.is_ascii_digit())
        && (whole == "0" || !whole.starts_with('0'))
        && fraction
            .is_none_or(|f| (1..=4).contains(&f.len()) && f.bytes().all(|b| b.is_ascii_digit()))
        && code.len() == 3
        && code.bytes().all(|b| b.is_ascii_uppercase())
}

/// `host[:port]`: a bracketed IPv6 literal, an IPv4 address, or a
/// hostname. The host must be non-empty.
fn is_host_port(authority: &str) -> bool {
    let (host_ok, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((inner, after)) = rest.split_once(']') else {
            return false;
        };
        let ok = !inner.is_empty()
            && inner
                .chars()
                .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.'));
        if after.is_empty() {
            (ok, None)
        } else if let Some(port) = after.strip_prefix(':') {
            (ok, Some(port))
        } else {
            return false;
        }
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        (is_hostname(host) || is_ipv4(host), Some(port))
    } else {
        (is_hostname(authority) || is_ipv4(authority), None)
    };
    host_ok
        && port
            .is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()))
}

fn is_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// A URL value: `http`, `https`, or `ssh` with a host and no credentials
/// in the authority. (`mailto:` is not allowed: the credential scrubber reads
/// `mailto:user@host` as userinfo.)
fn is_url(value: &str) -> bool {
    if value.len() > 2048 || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    matches!(scheme, "http" | "https" | "ssh")
        && !authority.contains('@')
        && is_host_port(authority)
}

/// Whether `value` is a legal value of the scalar type.
fn scalar_matches(scalar: RegistryScalarType, value: &Value) -> bool {
    use RegistryScalarType as T;
    match (scalar, value) {
        (T::Boolean, Value::Bool(_)) => true,
        (T::Number, Value::Number(number)) => number.as_f64().is_some_and(f64::is_finite),
        (T::Text, Value::String(text)) => text.len() <= MAX_TEXT,
        (T::String | T::Enum, Value::String(text)) => {
            !text.is_empty() && text.len() <= MAX_STRING && !text.chars().any(char::is_control)
        }
        (T::Date, Value::String(text)) => is_date(text),
        (T::Url, Value::String(text)) => is_url(text),
        (T::Hostname, Value::String(text)) => is_hostname(text),
        (T::Email, Value::String(text)) => is_email(text),
        (T::Money, Value::String(text)) => is_money(text),
        _ => false,
    }
}

fn scalar_name(scalar: RegistryScalarType) -> &'static str {
    use RegistryScalarType as T;
    match scalar {
        T::String => "string",
        T::Text => "text",
        T::Number => "number",
        T::Boolean => "boolean",
        T::Date => "date (YYYY-MM-DD)",
        T::Url => "url",
        T::Hostname => "hostname",
        T::Email => "email",
        T::Money => "money (<amount> <ISO 4217 code>)",
        T::Enum => "enum",
    }
}

/// A JSON pointer that is safe to print: any segment that is neither an
/// array index nor a plain field name could be (or contain) a credential,
/// so it is replaced.
pub(crate) fn sanitize_pointer(pointer: &str) -> String {
    pointer
        .split('/')
        .map(|segment| {
            if segment.is_empty()
                || segment.bytes().all(|b| b.is_ascii_digit())
                || is_field_name(segment)
            {
                segment
            } else {
                "<invalid-name>"
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Every string in a JSON value with its safe pointer, including map keys
/// (a key can carry a credential too).
fn collect_strings<'a>(value: &'a Value, pointer: &str, out: &mut Vec<(String, &'a str)>) {
    match value {
        Value::String(text) => out.push((pointer.to_owned(), text)),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_strings(item, &format!("{pointer}/{index}"), out);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let segment = safe_key(key);
                out.push((format!("{pointer}/{segment}"), key));
                collect_strings(item, &format!("{pointer}/{segment}"), out);
            }
        }
        _ => {}
    }
}

fn credential_error(location: String) -> Diagnostic {
    diagnostic(
        "FM_SCHEMA_SEMANTIC_CREDENTIAL_VALUE",
        location,
        "a Registry value must not carry a credential; keep secrets in Fleet's secret store and describe where they live instead",
    )
}

fn carries_credential(text: &str) -> bool {
    fleet_core::redact_credentials(text) != text
}

/// Scrubs every string and key of the spec, and the name/value pairs the
/// scrubber only recognizes joined (`password: hunter2` split across a
/// field name and its value, or a link's label and URL).
fn scan_credentials(base: &str, spec: &Value, errors: &mut Vec<Diagnostic>) {
    let mut strings = Vec::new();
    collect_strings(spec, &format!("{base}/spec"), &mut strings);
    for (location, text) in strings {
        if carries_credential(text) {
            errors.push(credential_error(location));
        }
    }
    if let Some(fields) = spec.get("fields").and_then(Value::as_object) {
        for (name, value) in fields {
            let at = format!("{base}/spec/fields/{}", safe_key(name));
            let items: Vec<(String, &Value)> = match value {
                Value::Array(list) => list
                    .iter()
                    .enumerate()
                    .map(|(index, item)| (format!("{at}/{index}"), item))
                    .collect(),
                other => vec![(at, other)],
            };
            for (location, item) in items {
                if let Value::String(text) = item
                    && carries_credential(&format!("{name}: {text}"))
                {
                    errors.push(credential_error(location));
                }
            }
        }
    }
    if let Some(links) = spec.get("links").and_then(Value::as_array) {
        for (index, link) in links.iter().enumerate() {
            if let (Some(label), Some(url)) = (
                link.get("label").and_then(Value::as_str),
                link.get("url").and_then(Value::as_str),
            ) && carries_credential(&format!("{label}: {url}"))
            {
                errors.push(credential_error(format!("{base}/spec/links/{index}")));
            }
        }
    }
}

struct TypeEntry {
    spec: RegistryTypeSpec,
}

fn validate_type_definition(
    base: &str,
    name: &str,
    spec: &RegistryTypeSpec,
    errors: &mut Vec<Diagnostic>,
) {
    let invalid = |location: String, message: String| {
        diagnostic("FM_SCHEMA_REGISTRY_INVALID_TYPE", location, message)
    };
    match spec.fields.get(&spec.key) {
        None => errors.push(invalid(
            format!("{base}/spec/key"),
            format!("the key field of type {name:?} is not declared in fields"),
        )),
        Some(field) => {
            if !field.required {
                errors.push(invalid(
                    format!("{base}/spec/fields/{}/required", safe_key(&spec.key)),
                    "the key field must be required".to_owned(),
                ));
            }
            if !matches!(
                field.value_type.scalar(),
                Some(
                    RegistryScalarType::String
                        | RegistryScalarType::Enum
                        | RegistryScalarType::Hostname
                        | RegistryScalarType::Email
                )
            ) {
                errors.push(invalid(
                    format!("{base}/spec/fields/{}/type", safe_key(&spec.key)),
                    "the key field must be a string, enum, hostname, or email".to_owned(),
                ));
            }
        }
    }
    for (field_name, field) in &spec.fields {
        let at = |leaf: &str| format!("{base}/spec/fields/{}{leaf}", safe_key(field_name));
        if !is_field_name(field_name) {
            errors.push(invalid(
                at(""),
                "field names must start with a lowercase letter and contain only letters and digits"
                    .to_owned(),
            ));
        }
        match (field.value_type.scalar(), field.items) {
            (None, None) => errors.push(invalid(
                at("/items"),
                "a list field must declare items".to_owned(),
            )),
            (Some(_), Some(_)) => errors.push(invalid(
                at("/items"),
                "items is only valid on a list field".to_owned(),
            )),
            _ => {}
        }
        let suggestible = matches!(
            field.value_type.scalar(),
            None | Some(RegistryScalarType::String | RegistryScalarType::Enum)
        );
        if !field.suggestions.is_empty() && !suggestible {
            errors.push(invalid(
                at("/suggestions"),
                "suggestions are only valid on string, enum, and list fields".to_owned(),
            ));
        }
        if (field.value_type.scalar() == Some(RegistryScalarType::Enum)
            || field.items == Some(RegistryScalarType::Enum))
            && field.suggestions.is_empty()
        {
            errors.push(invalid(
                at("/suggestions"),
                "an enum field must list its suggestions".to_owned(),
            ));
        }
    }
    let mut seen = BTreeSet::new();
    for (index, relation) in spec.relations.iter().enumerate() {
        if !is_slug(relation) || !seen.insert(relation.as_str()) {
            errors.push(invalid(
                format!("{base}/spec/relations/{index}"),
                "relation types must be unique lowercase slugs".to_owned(),
            ));
        }
    }
}

fn validate_field_value(
    location: &str,
    field: &crate::kinds::RegistryFieldSpec,
    value: &Value,
    errors: &mut Vec<Diagnostic>,
) {
    let mismatch = |at: String, expected: &str| {
        diagnostic(
            "FM_SCHEMA_REGISTRY_FIELD_TYPE",
            at,
            format!("the value does not match the field's type {expected}"),
        )
    };
    match (field.value_type.scalar(), field.items) {
        (Some(scalar), _) => {
            if !scalar_matches(scalar, value) {
                errors.push(mismatch(location.to_owned(), scalar_name(scalar)));
            }
        }
        (None, Some(item)) => match value.as_array() {
            Some(items) if items.len() <= 64 => {
                for (index, element) in items.iter().enumerate() {
                    if !scalar_matches(item, element) {
                        errors.push(mismatch(format!("{location}/{index}"), scalar_name(item)));
                    } else if items[..index].contains(element) {
                        errors.push(diagnostic(
                            "FM_SCHEMA_REGISTRY_DUPLICATE_ITEM",
                            format!("{location}/{index}"),
                            "a list field must not repeat an item",
                        ));
                    }
                }
            }
            _ => errors.push(mismatch(location.to_owned(), "list (at most 64 items)")),
        },
        (None, None) => {}
    }
}

fn entry_key(spec: &RegistryTypeSpec, entry: &RegistryEntrySpec) -> Option<String> {
    match entry.fields.get(&spec.key)? {
        Value::String(text) => Some(text.to_ascii_lowercase()),
        _ => None,
    }
}

/// Validates every Registry resource in the candidate collection. Returns
/// `(errors, warnings)`; warnings never block activation.
#[allow(clippy::too_many_lines)]
pub(crate) fn validate_registry(
    collection: &[(String, Value)],
    context: &RegistryContext,
) -> (Vec<Diagnostic>, Vec<Diagnostic>) {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let builtin: BTreeMap<&str, &RegistryTypeSpec> = context
        .builtin_types
        .iter()
        .map(|b| (b.name.as_str(), &b.spec))
        .collect();
    let mut types: BTreeMap<String, TypeEntry> = BTreeMap::new();
    for built in &context.builtin_types {
        types.insert(
            built.name.clone(),
            TypeEntry {
                spec: built.spec.clone(),
            },
        );
    }
    let mut defined: BTreeMap<String, String> = BTreeMap::new();

    // Pass 1: type definitions.
    for (base, document) in collection {
        if document.get("kind").and_then(Value::as_str) != Some("RegistryType") {
            continue;
        }
        let Some(spec_value) = document.get("spec") else {
            continue;
        };
        scan_credentials(base, spec_value, &mut errors);
        let Ok(spec) = serde_json::from_value::<RegistryTypeSpec>(spec_value.clone()) else {
            continue; // The schema pass reports the malformed spec.
        };
        let Some(name) = document.pointer("/metadata/name").and_then(Value::as_str) else {
            continue;
        };
        if builtin.contains_key(name) {
            errors.push(diagnostic(
                "FM_SCHEMA_REGISTRY_BUILTIN_REDEFINED",
                format!("{base}/metadata/name"),
                format!("{name:?} is a built-in Registry type and cannot be redefined"),
            ));
            continue;
        }
        if let Some(first) = defined.get(name) {
            errors.push(diagnostic(
                "FM_SCHEMA_REGISTRY_DUPLICATE_TYPE",
                format!("{base}/metadata/name"),
                format!("the Registry type {name:?} was first defined at {first}"),
            ));
            continue;
        }
        defined.insert(name.to_owned(), base.clone());
        validate_type_definition(base, name, &spec, &mut errors);
        types.insert(name.to_owned(), TypeEntry { spec });
    }

    // Pass 2: entries.
    let mut keys: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut entries: Vec<(&String, RegistryEntrySpec)> = Vec::new();
    for (base, document) in collection {
        if document.get("kind").and_then(Value::as_str) != Some("RegistryEntry") {
            continue;
        }
        let Some(spec_value) = document.get("spec") else {
            continue;
        };
        scan_credentials(base, spec_value, &mut errors);
        let Ok(entry) = serde_json::from_value::<RegistryEntrySpec>(spec_value.clone()) else {
            continue;
        };
        let Some(type_entry) = types.get(&entry.entry_type) else {
            errors.push(diagnostic(
                "FM_SCHEMA_REGISTRY_UNKNOWN_TYPE",
                format!("{base}/spec/type"),
                format!(
                    "no Registry type named {:?} is defined or built in",
                    if is_slug(&entry.entry_type) {
                        entry.entry_type.as_str()
                    } else {
                        "<invalid-name>"
                    }
                ),
            ));
            continue;
        };
        let type_spec = &type_entry.spec;
        for (name, value) in &entry.fields {
            let location = format!("{base}/spec/fields/{}", safe_key(name));
            match type_spec.fields.get(name) {
                None => errors.push(diagnostic(
                    "FM_SCHEMA_REGISTRY_UNKNOWN_FIELD",
                    location,
                    format!("the type {:?} declares no such field", entry.entry_type),
                )),
                Some(field) => validate_field_value(&location, field, value, &mut errors),
            }
        }
        for (name, field) in &type_spec.fields {
            if field.required && !entry.fields.contains_key(name) {
                errors.push(diagnostic(
                    "FM_SCHEMA_REGISTRY_MISSING_REQUIRED",
                    format!("{base}/spec/fields"),
                    format!("the required field {:?} is missing", safe_key(name)),
                ));
            }
        }
        let mut tags = BTreeSet::new();
        for (index, tag) in entry.tags.iter().enumerate() {
            if !is_slug(tag) {
                errors.push(diagnostic(
                    "FM_SCHEMA_REGISTRY_INVALID_TAG",
                    format!("{base}/spec/tags/{index}"),
                    "a tag must be a lowercase slug of at most 63 characters",
                ));
            } else if !tags.insert(tag.as_str()) {
                errors.push(diagnostic(
                    "FM_SCHEMA_REGISTRY_INVALID_TAG",
                    format!("{base}/spec/tags/{index}"),
                    "a tag must not repeat",
                ));
            }
        }
        for (index, link) in entry.links.iter().enumerate() {
            if !is_url(&link.url) {
                errors.push(diagnostic(
                    "FM_SCHEMA_REGISTRY_INVALID_LINK",
                    format!("{base}/spec/links/{index}/url"),
                    "a link must be an http, https, or ssh URL with a host and no credentials, ",
                ));
            }
            if link.label.trim().is_empty() || link.label.chars().any(char::is_control) {
                errors.push(diagnostic(
                    "FM_SCHEMA_REGISTRY_INVALID_LINK",
                    format!("{base}/spec/links/{index}/label"),
                    "a link label must be non-blank single-line text",
                ));
            }
        }
        if let Some(key) = entry_key(type_spec, &entry) {
            if is_key_value(&key) {
                if let Some(first) = keys.insert((entry.entry_type.clone(), key), base.clone()) {
                    errors.push(diagnostic(
                        "FM_SCHEMA_REGISTRY_DUPLICATE_KEY",
                        format!("{base}/spec/fields/{}", safe_key(&type_spec.key)),
                        format!(
                            "another {:?} entry with this key was first declared at {first}",
                            entry.entry_type
                        ),
                    ));
                }
            } else {
                errors.push(diagnostic(
                    "FM_SCHEMA_REGISTRY_INVALID_KEY",
                    format!("{base}/spec/fields/{}", safe_key(&type_spec.key)),
                    "an entry key must start with a letter or digit and contain only letters, digits, and . _ @ + -, at most 128 characters".to_owned(),
                ));
            }
        }
        entries.push((base, entry));
    }

    // Pass 3: relations.
    let mut known: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for (class, kind) in [("machine", "Machine"), ("project", "Project")] {
        let in_revision = collection
            .iter()
            .filter(|(_, d)| d.get("kind").and_then(Value::as_str) == Some(kind))
            .filter_map(|(_, d)| d.pointer("/metadata/name").and_then(Value::as_str))
            .map(str::to_owned);
        if let Some(provided) = context.known_targets.get(class) {
            known.insert(class, provided.iter().cloned().chain(in_revision).collect());
        }
    }
    for class in ["coolify", "proxmoxGuest"] {
        if let Some(provided) = context.known_targets.get(class) {
            known.insert(class, provided.clone());
        }
    }
    for (base, entry) in &entries {
        let allowed = types.get(&entry.entry_type).map(|t| &t.spec.relations);
        for (index, relation) in entry.relations.iter().enumerate() {
            let at = format!("{base}/spec/relations/{index}");
            if !is_slug(&relation.relation_type) {
                errors.push(diagnostic(
                    "FM_SCHEMA_REGISTRY_INVALID_RELATION_TYPE",
                    format!("{at}/type"),
                    "a relation type must be a lowercase slug",
                ));
            } else if allowed.is_some_and(|list| !list.contains(&relation.relation_type)) {
                errors.push(diagnostic(
                    "FM_SCHEMA_REGISTRY_RELATION_NOT_ALLOWED",
                    format!("{at}/type"),
                    format!(
                        "the type {:?} does not allow this relation type",
                        entry.entry_type
                    ),
                ));
            }
            check_target(
                &at,
                &relation.target,
                &types,
                &keys,
                &known,
                &mut errors,
                &mut warnings,
            );
        }
    }
    (errors, warnings)
}

fn check_target(
    at: &str,
    target: &RegistryRelationTarget,
    types: &BTreeMap<String, TypeEntry>,
    keys: &BTreeMap<(String, String), String>,
    known: &BTreeMap<&str, BTreeSet<String>>,
    errors: &mut Vec<Diagnostic>,
    warnings: &mut Vec<Diagnostic>,
) {
    let location = format!("{at}/target");
    let malformed = |what: &str| {
        diagnostic(
            "FM_SCHEMA_REGISTRY_INVALID_TARGET",
            location.clone(),
            format!("the relation target is not a valid {what}"),
        )
    };
    let dangling = |noun: &str| {
        diagnostic(
            "FM_SCHEMA_WARN_REGISTRY_DANGLING_RELATION",
            location.clone(),
            format!("the relation target is not a known {noun}; the observed side may be offline"),
        )
    };
    match target {
        RegistryRelationTarget::Registry(reference) => match reference.split_once('/') {
            Some((type_name, key)) if is_slug(type_name) && is_key_value(key) => {
                if !types.contains_key(type_name) {
                    errors.push(diagnostic(
                        "FM_SCHEMA_REGISTRY_UNKNOWN_TARGET_TYPE",
                        location.clone(),
                        "the relation target names a Registry type that is neither defined nor built in",
                    ));
                } else if !keys.contains_key(&(type_name.to_owned(), key.to_ascii_lowercase())) {
                    warnings.push(dangling("Registry entry in this revision"));
                }
            }
            _ => errors.push(malformed("Registry reference (<type>/<key>)")),
        },
        RegistryRelationTarget::Machine(name) | RegistryRelationTarget::Project(name) => {
            let class = if matches!(target, RegistryRelationTarget::Machine(_)) {
                "machine"
            } else {
                "project"
            };
            if is_slug(name) {
                if known.get(class).is_some_and(|set| !set.contains(name)) {
                    warnings.push(dangling(class));
                }
            } else {
                errors.push(malformed("resource name"));
            }
        }
        RegistryRelationTarget::Coolify(id) | RegistryRelationTarget::ProxmoxGuest(id) => {
            let class = if matches!(target, RegistryRelationTarget::Coolify(_)) {
                "coolify"
            } else {
                "proxmoxGuest"
            };
            if id.is_empty()
                || id.len() > 128
                || id.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                errors.push(malformed("resource reference"));
            } else if known.get(class).is_some_and(|set| !set.contains(id)) {
                warnings.push(dangling("resource"));
            }
        }
    }
}
