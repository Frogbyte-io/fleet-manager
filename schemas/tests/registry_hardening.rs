//! Registry validation hardening (FM-1010 review): value types, credential
//! shapes, key echo, tags, lists, and relation targets.

use fleet_schema::{
    Diagnostic, SourceDocument, ValidationReport, registry::RegistryContext,
    validate_sources_report,
};

fn run(yaml: &str) -> ValidationReport {
    validate_sources_report(
        &[SourceDocument {
            path: "inline.yaml".into(),
            yaml: yaml.to_owned(),
        }],
        &RegistryContext::default(),
    )
}

/// A `thing` type with one field `v` of the given definition, and an entry
/// carrying `entry_extra` after `fields`.
fn doc(field_def: &str, fields: &str, entry_extra: &str) -> String {
    format!(
        "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryType\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58f001\n  name: thing\nspec:\n  displayName: Thing\n  key: slug\n  fields:\n    slug: {{ type: string, required: true }}\n    v: {field_def}\n    password: {{ type: string }}\n  relations: [rel]\n---\napiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryEntry\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58f002\n  name: thing-a\nspec:\n  type: thing\n  fields: {{ slug: a, {fields} }}\n{entry_extra}"
    )
}

fn codes(diagnostics: &[Diagnostic]) -> Vec<&'static str> {
    diagnostics.iter().map(|d| d.code).collect()
}

fn value_errors(field_def: &str, value: &str) -> Vec<&'static str> {
    codes(&run(&doc(field_def, &format!("v: {value}"), "")).errors)
}

#[test]
fn links_are_validated_and_schemes_allow_listed() {
    let link = |url: &str| {
        codes(
            &run(&doc(
                "{ type: string }",
                "",
                &format!("  links:\n    - {{ label: L, url: \"{url}\" }}\n"),
            ))
            .errors,
        )
    };
    for good in [
        "https://example.com/a?b=1",
        "http://example.com:8080/",
        "ssh://example.com:22",
        "https://[::1]:443/x",
        "https://10.0.0.1/",
    ] {
        assert_eq!(link(good), [] as [&str; 0], "{good}");
    }
    for bad in [
        "https://:80/",
        "https:///path",
        "javascript:alert(1)",
        "data:text/html,x",
        "ftp://example.com/",
        "https://user@example.com/",
        "https://example.com:/",
        "https://[]/",
        "https://example.com:99999999/",
        "not a url",
        "mailto:nobody",
        "mailto:ops@example.com",
    ] {
        assert!(
            link(bad).contains(&"FM_SCHEMA_REGISTRY_INVALID_LINK"),
            "{bad}"
        );
    }
    // The url field type uses the same check.
    assert_eq!(
        value_errors("{ type: url }", "\"javascript:alert(1)\""),
        ["FM_SCHEMA_REGISTRY_FIELD_TYPE"]
    );
}

#[test]
fn credentials_split_across_name_and_value_are_refused() {
    let result = run(&doc("{ type: string }", "password: hunter2hunter2", ""));
    let rendered = result
        .errors
        .iter()
        .map(ToString::to_string)
        .collect::<String>();
    assert!(
        rendered.contains("/spec/fields/password [FM_SCHEMA_SEMANTIC_CREDENTIAL_VALUE]"),
        "{rendered}"
    );
    assert!(!rendered.contains("hunter2"));
    // Inside a list item.
    let list = run(&doc(
        "{ type: list, items: string }",
        "password: hunter2hunter2",
        "",
    ));
    assert!(!list.errors.is_empty());
    // A link label and URL.
    let link = run(&doc(
        "{ type: string }",
        "",
        "  links:\n    - { label: token, url: \"https://example.com/abcdef0123456789\" }\n",
    ));
    assert!(
        codes(&link.errors).contains(&"FM_SCHEMA_SEMANTIC_CREDENTIAL_VALUE"),
        "{:?}",
        link.errors
    );
}

#[test]
fn nested_and_unknown_keys_are_never_echoed() {
    let secret = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    // Nested under a declared type field (schema path) and in an entry value.
    let in_type = format!(
        "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryType\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58f001\n  name: thing\nspec:\n  displayName: Thing\n  key: when\n  fields:\n    when:\n      type: string\n      required: true\n      {secret}: x\n"
    );
    let in_entry = doc(
        "{ type: string }",
        &format!("v: {{ {secret}: 1 }}, {secret}: 2"),
        "  notes: x\n",
    );
    for yaml in [in_type, in_entry] {
        let result = run(&yaml);
        let rendered = result
            .errors
            .iter()
            .chain(&result.warnings)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!rendered.is_empty());
        assert!(!rendered.contains("ghp_"), "{rendered}");
        assert!(!rendered.contains("0123456789abcdef"), "{rendered}");
    }
}

#[test]
fn tags_are_slugs_and_unique() {
    let tags =
        |list: &str| codes(&run(&doc("{ type: string }", "", &format!("  tags: {list}\n"))).errors);
    assert_eq!(tags("[client-x, prod]"), [] as [&str; 0]);
    assert_eq!(tags("[\"\"]"), ["FM_SCHEMA_REGISTRY_INVALID_TAG"]);
    assert_eq!(tags("[\"Has Space\"]"), ["FM_SCHEMA_REGISTRY_INVALID_TAG"]);
    assert_eq!(tags("[a, a]"), ["FM_SCHEMA_REGISTRY_INVALID_TAG"]);
    let long = "a".repeat(64);
    assert_eq!(
        tags(&format!("[{long}]")),
        ["FM_SCHEMA_REGISTRY_INVALID_TAG"]
    );
}

#[test]
fn value_types_are_strict() {
    let no: [&str; 0] = [];
    // email
    for bad in [
        "a@b.com.",
        "a b@c.com",
        "a,b@c.com",
        "a@b.com, c@d.com",
        "@b.com",
        "a@",
    ] {
        assert_eq!(
            value_errors("{ type: email }", &format!("\"{bad}\"")),
            ["FM_SCHEMA_REGISTRY_FIELD_TYPE"],
            "{bad}"
        );
    }
    assert!(
        value_errors("{ type: email }", "\"a\\u0007@b.com\"")
            .contains(&"FM_SCHEMA_REGISTRY_FIELD_TYPE")
    );
    assert_eq!(value_errors("{ type: email }", "ops@example.com"), no);
    // money
    for bad in [
        "\"012.50 USD\"",
        "\"1.5 usd\"",
        "\"1.5 US\"",
        "\"00.5 USD\"",
        "\"1.5 USDX\"",
    ] {
        assert_eq!(
            value_errors("{ type: money }", bad),
            ["FM_SCHEMA_REGISTRY_FIELD_TYPE"],
            "{bad}"
        );
    }
    for good in ["\"0.50 USD\"", "\"0 EUR\"", "\"1200 NOK\"", "\"-3.25 USD\""] {
        assert_eq!(value_errors("{ type: money }", good), no, "{good}");
    }
    // date
    assert_eq!(
        value_errors("{ type: date }", "\"0000-01-01\""),
        ["FM_SCHEMA_REGISTRY_FIELD_TYPE"]
    );
    assert_eq!(value_errors("{ type: date }", "\"2024-02-29\""), no);
    // hostname: underscore-leading labels yes; bare IPv4 and trailing dot no.
    assert_eq!(value_errors("{ type: hostname }", "_dmarc.example.com"), no);
    for bad in ["10.0.0.1", "example.com.", "-a.com", "a_b.com", "a..com"] {
        assert_eq!(
            value_errors("{ type: hostname }", &format!("\"{bad}\"")),
            ["FM_SCHEMA_REGISTRY_FIELD_TYPE"],
            "{bad}"
        );
    }
}

#[test]
fn lists_reject_duplicates_and_enum_items_need_suggestions() {
    assert_eq!(
        value_errors("{ type: list, items: string }", "[a, b, a]"),
        ["FM_SCHEMA_REGISTRY_DUPLICATE_ITEM"]
    );
    assert_eq!(
        value_errors("{ type: list, items: string }", "[a, b]"),
        [] as [&str; 0]
    );
    let result = run(&doc("{ type: list, items: enum }", "v: [a]", ""));
    assert_eq!(codes(&result.errors), ["FM_SCHEMA_REGISTRY_INVALID_TYPE"]);
    let with = run(&doc(
        "{ type: list, items: enum, suggestions: [a, b] }",
        "v: [a]",
        "",
    ));
    assert_eq!(with.errors, []);
}

#[test]
fn relation_targets_and_types_are_checked() {
    let rel = |relation: &str| {
        let result = run(&doc(
            "{ type: string }",
            "",
            &format!("  relations:\n    - {relation}\n"),
        ));
        (codes(&result.errors), codes(&result.warnings))
    };
    // A registry target of an undefined type is an error, not a warning.
    assert_eq!(
        rel("{ type: rel, target: { registry: nothing/x } }"),
        (vec!["FM_SCHEMA_REGISTRY_UNKNOWN_TARGET_TYPE"], vec![])
    );
    // A defined type with a missing entry is a warning.
    assert_eq!(
        rel("{ type: rel, target: { registry: thing/missing } }"),
        (vec![], vec!["FM_SCHEMA_WARN_REGISTRY_DANGLING_RELATION"])
    );
    // A relation type that is not a slug is its own error.
    assert_eq!(
        rel("{ type: \"Not A Slug\", target: { registry: thing/a } }").0,
        ["FM_SCHEMA_REGISTRY_INVALID_RELATION_TYPE"]
    );
    // Malformed coolify id (whitespace) is refused.
    assert_eq!(
        rel("{ type: rel, target: { coolify: \"a b\" } }").0,
        ["FM_SCHEMA_REGISTRY_INVALID_TARGET"]
    );
}
