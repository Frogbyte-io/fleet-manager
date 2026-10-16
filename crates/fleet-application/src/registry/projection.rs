//! Derives the Registry cache contents from a revision's resources.
//!
//! Total and tolerant: the revision was validated before it was recorded,
//! so a document that does not fit (an entry of an unknown type, a
//! missing key) is skipped rather than failing the whole rebuild.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::{
    BuiltinRegistryType, RegistryEntryRecord, RegistryProjection, RegistryRelationRecord,
    RegistryTarget, RegistryTypeRecord, TypeOrigin, split_entry_ref,
};
use crate::source::DesiredResourceRecord;

/// Builds the projection from the built-in types and the revision's
/// `RegistryType` and `RegistryEntry` resources.
#[must_use]
pub fn derive(
    builtins: &[BuiltinRegistryType],
    types: &[DesiredResourceRecord],
    entries: &[DesiredResourceRecord],
) -> RegistryProjection {
    let mut by_name: BTreeMap<String, RegistryTypeRecord> = BTreeMap::new();
    // Built-ins first: a repository type may not redefine one.
    for builtin in builtins {
        if let Some(record) = type_record(
            &builtin.name,
            TypeOrigin::Builtin,
            None,
            None,
            &builtin.spec,
        ) {
            by_name.entry(builtin.name.clone()).or_insert(record);
        }
    }
    for resource in types.iter().filter(|r| r.kind == "RegistryType") {
        if let Some(record) = type_record(
            &resource.name,
            TypeOrigin::Repository,
            Some(resource.id.clone()),
            resource.source_path.clone(),
            &resource.spec,
        ) {
            by_name.entry(resource.name.clone()).or_insert(record);
        }
    }
    let mut projected: BTreeMap<(String, String), RegistryEntryRecord> = BTreeMap::new();
    for resource in entries.iter().filter(|r| r.kind == "RegistryEntry") {
        let Some(entry_type) = resource.spec.get("type").and_then(Value::as_str) else {
            continue;
        };
        let Some(definition) = by_name.get(entry_type) else {
            continue;
        };
        let fields = resource
            .spec
            .get("fields")
            .cloned()
            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
        let Some(key) = key_text(fields.get(&definition.key_field)) else {
            continue;
        };
        let record = RegistryEntryRecord {
            entry_type: entry_type.to_owned(),
            key: key.clone(),
            resource_id: resource.id.clone(),
            name: resource.name.clone(),
            fields,
            tags: tags(&resource.spec),
            links: resource
                .spec
                .get("links")
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new())),
            notes: resource
                .spec
                .get("notes")
                .and_then(Value::as_str)
                .map(str::to_owned),
            relations: relations(&resource.spec),
            source_path: resource.source_path.clone(),
        };
        // Keys are unique per type in a valid revision; if one ever
        // repeats, the lowest resource identity wins, deterministically.
        projected
            .entry((entry_type.to_owned(), key))
            .and_modify(|held| {
                if record.resource_id < held.resource_id {
                    *held = record.clone();
                }
            })
            .or_insert(record);
    }
    RegistryProjection {
        types: by_name.into_values().collect(),
        entries: projected.into_values().collect(),
    }
}

fn key_text(value: Option<&Value>) -> Option<String> {
    let text = match value? {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        _ => return None,
    };
    (!text.is_empty() && !text.contains('/')).then_some(text)
}

fn type_record(
    name: &str,
    origin: TypeOrigin,
    resource_id: Option<String>,
    source_path: Option<String>,
    spec: &Value,
) -> Option<RegistryTypeRecord> {
    let key_field = spec.get("key")?.as_str()?.to_owned();
    Some(RegistryTypeRecord {
        name: name.to_owned(),
        origin,
        resource_id,
        display_name: spec
            .get("displayName")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_owned(),
        key_field,
        relations: spec
            .get("relations")
            .and_then(Value::as_array)
            .map(|names| {
                names
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        spec: spec.clone(),
        source_path,
        entry_count: 0,
    })
}

fn tags(spec: &Value) -> Vec<String> {
    let unique: BTreeSet<String> = spec
        .get("tags")
        .and_then(Value::as_array)
        .map(|tags| {
            tags.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    unique.into_iter().collect()
}

fn relations(spec: &Value) -> Vec<RegistryRelationRecord> {
    let mut seen = BTreeSet::new();
    let mut found = Vec::new();
    for relation in spec
        .get("relations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(relation_type) = relation.get("type").and_then(Value::as_str) else {
            continue;
        };
        let Some((class, reference)) = relation
            .get("target")
            .and_then(Value::as_object)
            .and_then(|target| target.iter().next())
            .and_then(|(class, reference)| Some((class.as_str(), reference.as_str()?)))
        else {
            continue;
        };
        let text = format!("{class}:{reference}");
        // Re-validate on the way in: only well-formed targets are
        // indexed, so a query can never be built from an odd one.
        let Ok(target) = RegistryTarget::parse(&text) else {
            continue;
        };
        if class == "registry" && split_entry_ref(reference).is_none() {
            continue;
        }
        if seen.insert((
            relation_type.to_owned(),
            target.clone().class,
            target.reference.clone(),
        )) {
            found.push(RegistryRelationRecord {
                relation_type: relation_type.to_owned(),
                target,
            });
        }
    }
    found
}
