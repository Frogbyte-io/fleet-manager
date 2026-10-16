//! Registry validation (FM-1010): rules that need a context (built-in
//! types, known targets) or that the CLI goldens cannot express.

use std::collections::{BTreeMap, BTreeSet};

use fleet_schema::{
    SourceDocument, ValidationReport,
    kinds::RegistryTypeSpec,
    registry::{BuiltinRegistryType, RegistryContext},
    validate_sources, validate_sources_report,
};

const TYPE: &str = r"apiVersion: fleet.frogbyte.io/v1alpha1
kind: RegistryType
metadata:
  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58d001
  name: vendor
spec:
  displayName: Vendor
  key: slug
  fields:
    slug: { type: string, required: true }
    renews: { type: date }
  relations: [used-by]
";

fn entry(id_suffix: &str, extra: &str) -> String {
    format!(
        "---\napiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryEntry\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58d{id_suffix}\n  name: entry-{id_suffix}\nspec:\n  type: vendor\n{extra}\n"
    )
}

fn report(yaml: &str, context: &RegistryContext) -> ValidationReport {
    validate_sources_report(
        &[SourceDocument {
            path: "inline.yaml".into(),
            yaml: yaml.to_owned(),
        }],
        context,
    )
}

fn codes(diagnostics: &[fleet_schema::Diagnostic]) -> Vec<&'static str> {
    diagnostics.iter().map(|d| d.code).collect()
}

fn builtin(name: &str) -> BuiltinRegistryType {
    let spec: RegistryTypeSpec = serde_json::from_value(serde_json::json!({
        "displayName": "Built-in",
        "key": "slug",
        "fields": {"slug": {"type": "string", "required": true}},
    }))
    .unwrap();
    BuiltinRegistryType {
        name: name.to_owned(),
        spec,
    }
}

#[test]
fn redefining_a_builtin_type_is_an_error_and_builtins_are_usable() {
    let context = RegistryContext {
        builtin_types: vec![builtin("vendor")],
        ..RegistryContext::default()
    };
    let redefined = report(TYPE, &context);
    assert_eq!(
        codes(&redefined.errors),
        ["FM_SCHEMA_REGISTRY_BUILTIN_REDEFINED"]
    );

    // Without redefining, entries resolve against the built-in type.
    let only_entry = entry("002", "  fields: { slug: aptabase }")
        .trim_start_matches("---\n")
        .to_owned();
    assert_eq!(report(&only_entry, &context).errors, []);
    // The same entry with no built-in is an unknown type.
    assert_eq!(
        codes(&report(&only_entry, &RegistryContext::default()).errors),
        ["FM_SCHEMA_REGISTRY_UNKNOWN_TYPE"]
    );
}

#[test]
fn dangling_relations_warn_and_never_block() {
    let yaml = format!(
        "{TYPE}{}",
        entry(
            "002",
            "  fields: { slug: aptabase }\n  relations:\n    - { type: used-by, target: { registry: vendor/missing } }\n    - { type: used-by, target: { machine: ghost } }\n    - { type: used-by, target: { coolify: abc } }"
        )
    );
    let unchecked = report(&yaml, &RegistryContext::default());
    assert_eq!(unchecked.errors, []);
    assert_eq!(
        codes(&unchecked.warnings),
        ["FM_SCHEMA_WARN_REGISTRY_DANGLING_RELATION"],
        "only the registry target is checked without known-target sets"
    );

    let known = RegistryContext {
        known_targets: BTreeMap::from([
            ("machine".to_owned(), BTreeSet::from(["box".to_owned()])),
            ("coolify".to_owned(), BTreeSet::new()),
        ]),
        ..RegistryContext::default()
    };
    let checked = report(&yaml, &known);
    assert_eq!(checked.errors, []);
    assert_eq!(checked.warnings.len(), 3);
    // `validate_sources` (the activation gate) sees no blocking diagnostics.
    let gate = validate_sources(&[SourceDocument {
        path: "inline.yaml".into(),
        yaml,
    }]);
    assert_eq!(gate, []);
}

#[test]
fn a_resolved_registry_relation_does_not_warn() {
    let yaml = format!(
        "{TYPE}{}{}",
        entry("002", "  fields: { slug: aptabase }"),
        entry(
            "003",
            "  fields: { slug: other }\n  relations:\n    - { type: used-by, target: { registry: vendor/aptabase } }"
        )
    );
    let result = report(&yaml, &RegistryContext::default());
    assert_eq!(result.errors, []);
    assert_eq!(result.warnings, []);
}

#[test]
fn credential_diagnostics_name_the_field_and_never_the_value() {
    let secret = "api_key=0123456789abcdef0123456789abcdef";
    let yaml = format!(
        "{TYPE}{}",
        entry(
            "002",
            &format!("  fields: {{ slug: aptabase, \"{secret}\": x }}\n  notes: \"{secret}\"")
        )
    );
    let result = report(&yaml, &RegistryContext::default());
    assert!(!result.errors.is_empty());
    let rendered = result
        .errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(rendered.contains("/spec/notes [FM_SCHEMA_SEMANTIC_CREDENTIAL_VALUE]"));
    assert!(!rendered.contains("0123456789abcdef"), "{rendered}");
}

#[test]
fn type_definitions_are_checked() {
    let yaml = r"apiVersion: fleet.frogbyte.io/v1alpha1
kind: RegistryType
metadata:
  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58d001
  name: broken
spec:
  displayName: Broken
  key: missing
  fields:
    tags: { type: list }
    flag: { type: boolean, items: string }
    kind: { type: enum }
  relations: [used-by, used-by]
";
    let result = report(yaml, &RegistryContext::default());
    assert!(
        result
            .errors
            .iter()
            .all(|d| d.code == "FM_SCHEMA_REGISTRY_INVALID_TYPE")
    );
    assert_eq!(result.errors.len(), 5, "{:?}", result.errors);
}

#[test]
fn unquoted_dates_and_money_validate() {
    let yaml = format!(
        "{TYPE}{}",
        entry("002", "  fields: { slug: aptabase, renews: 2027-03-01 }")
    );
    assert_eq!(report(&yaml, &RegistryContext::default()).errors, []);
}
