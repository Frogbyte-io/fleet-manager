use serde_json::json;

use super::{BuiltinRegistryType, RegistryTarget, derive};
use crate::source::DesiredResourceRecord;

fn resource(kind: &str, id: &str, name: &str, spec: serde_json::Value) -> DesiredResourceRecord {
    DesiredResourceRecord {
        kind: kind.to_owned(),
        id: id.to_owned(),
        name: name.to_owned(),
        spec,
        source_path: Some(format!("fleet/registry/{name}.yaml")),
    }
}

fn domain_type() -> serde_json::Value {
    json!({
        "displayName": "Domain",
        "key": "fqdn",
        "fields": { "fqdn": { "type": "hostname", "required": true } },
        "relations": ["used-by", "hosted-on"],
    })
}

#[test]
fn derive_keys_entries_by_the_types_key_field_and_sorts_them() {
    let types = [resource("RegistryType", "t1", "domain", domain_type())];
    let entries = [
        resource(
            "RegistryEntry",
            "e2",
            "domain-b",
            json!({"type": "domain", "fields": {"fqdn": "b.example"}, "tags": ["x", "x", "a"]}),
        ),
        resource(
            "RegistryEntry",
            "e1",
            "domain-a",
            json!({"type": "domain", "fields": {"fqdn": "a.example"}, "notes": "n"}),
        ),
    ];
    let projection = derive(&[], &types, &entries);
    let keys: Vec<_> = projection
        .entries
        .iter()
        .map(|entry| entry.key.as_str())
        .collect();
    assert_eq!(keys, ["a.example", "b.example"]);
    assert_eq!(projection.entries[1].tags, ["a", "x"]);
    assert_eq!(projection.entries[0].notes.as_deref(), Some("n"));
    assert_eq!(
        projection.entries[0].source_path.as_deref(),
        Some("fleet/registry/domain-a.yaml")
    );
    assert_eq!(projection.types.len(), 1);
}

#[test]
fn builtin_types_take_precedence_and_serve_entries() {
    let builtin = BuiltinRegistryType {
        name: "domain".to_owned(),
        spec: domain_type(),
    };
    let shadow = resource(
        "RegistryType",
        "t1",
        "domain",
        json!({"displayName": "Shadow", "key": "other", "fields": {}}),
    );
    let entry = resource(
        "RegistryEntry",
        "e1",
        "domain-a",
        json!({"type": "domain", "fields": {"fqdn": "a.example"}}),
    );
    let projection = derive(&[builtin], &[shadow], &[entry]);
    assert_eq!(projection.types.len(), 1);
    assert_eq!(projection.types[0].display_name, "Domain");
    assert_eq!(projection.entries.len(), 1);
}

#[test]
fn derive_skips_entries_it_cannot_key_and_indexes_only_wellformed_relations() {
    let types = [resource("RegistryType", "t1", "domain", domain_type())];
    let entries = [
        resource(
            "RegistryEntry",
            "e1",
            "unknown",
            json!({"type": "nothing", "fields": {"fqdn": "x.example"}}),
        ),
        resource(
            "RegistryEntry",
            "e2",
            "keyless",
            json!({"type": "domain", "fields": {}}),
        ),
        resource(
            "RegistryEntry",
            "e3",
            "ok",
            json!({"type": "domain", "fields": {"fqdn": "ok.example"}, "relations": [
                {"type": "used-by", "target": {"registry": "service/aptabase"}},
                {"type": "used-by", "target": {"registry": "service/aptabase"}},
                {"type": "hosted-on", "target": {"machine": "build-1"}},
                {"type": "hosted-on", "target": {"registry": "no-slash"}},
            ]}),
        ),
    ];
    let projection = derive(&[], &types, &entries);
    assert_eq!(projection.entries.len(), 1);
    let relations = &projection.entries[0].relations;
    assert_eq!(relations.len(), 2);
    assert_eq!(relations[0].target.class, "registry");
    assert_eq!(relations[1].target.reference, "build-1");
}

#[test]
fn search_text_covers_values_tags_and_notes_in_lowercase() {
    let types = [resource("RegistryType", "t1", "domain", domain_type())];
    let entries = [resource(
        "RegistryEntry",
        "e1",
        "domain-a",
        json!({"type": "domain", "fields": {"fqdn": "A.Example", "registrar": "Webhuset"},
               "tags": ["Client-X"], "notes": "Moved from GoDaddy"}),
    )];
    let text = derive(&[], &types, &entries).entries[0].search_text();
    for needle in [
        "a.example",
        "webhuset",
        "client-x",
        "godaddy",
        "domain/a.example",
    ] {
        assert!(text.contains(needle), "{needle} missing from {text}");
    }
}

#[test]
fn targets_parse_and_refuse_malformed_references() {
    assert!(RegistryTarget::parse("machine:build-1").is_ok());
    assert!(RegistryTarget::parse("registry:service/aptabase").is_ok());
    for bad in [
        "machine",
        "bogus:x",
        "machine:",
        "registry:nokey",
        "project:a b",
    ] {
        assert!(RegistryTarget::parse(bad).is_err(), "{bad}");
    }
}
