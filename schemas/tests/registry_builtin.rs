//! Built-in Registry types (FM-1011): `domain` and `service`.

use fleet_schema::{
    SourceDocument, ValidationReport,
    registry::RegistryContext,
    registry_builtin::{BUILTIN_REGISTRY_TYPES_VERSION, builtin_registry_types},
    validate_sources, validate_sources_report,
};
use sha2::{Digest as _, Sha256};

/// The digest of the built-in definitions at `PINNED_VERSION`. A definition
/// change moves the digest; update this pair and the version constant.
const PINNED_VERSION: u32 = 1;
const PINNED_DIGEST: &str = "c2321b8cf792d1488ff096e78b02f79c7b6b9a5d5a3c305e77bccb46a26843b4";

fn digest() -> String {
    let canonical = serde_json::to_vec(
        &builtin_registry_types()
            .iter()
            .map(|built| (&built.name, &built.spec))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    Sha256::digest(canonical)
        .iter()
        .fold(String::new(), |mut out, byte| {
            use std::fmt::Write as _;
            write!(out, "{byte:02x}").unwrap();
            out
        })
}

#[test]
fn builtin_definitions_are_pinned_to_their_version() {
    assert_eq!(
        (BUILTIN_REGISTRY_TYPES_VERSION, digest().as_str()),
        (PINNED_VERSION, PINNED_DIGEST),
        "a built-in Registry type changed: bump BUILTIN_REGISTRY_TYPES_VERSION and re-pin PINNED_VERSION and PINNED_DIGEST"
    );
}

#[test]
fn the_default_context_carries_both_builtins() {
    let names = RegistryContext::default()
        .builtin_types
        .into_iter()
        .map(|built| built.name)
        .collect::<Vec<_>>();
    assert_eq!(names, ["domain", "service"]);
}

fn report(body: &str) -> ValidationReport {
    let yaml = format!(
        "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryEntry\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58c101\n  name: probe\nspec:\n{body}\n"
    );
    validate_sources_report(
        &[SourceDocument {
            path: "probe.yaml".into(),
            yaml,
        }],
        &RegistryContext::default(),
    )
}

fn codes(report: &ValidationReport) -> Vec<&'static str> {
    report.errors.iter().map(|d| d.code).collect()
}

#[test]
fn valid_builtin_entries_pass() {
    assert_eq!(
        report("  type: domain\n  fields: { fqdn: example.org, autoRenew: false }").errors,
        []
    );
    assert_eq!(
        report("  type: service\n  fields: { slug: sentry, name: Sentry, cost: 26 USD, billingPeriod: yearly, url: \"https://sentry.io\" }").errors,
        []
    );
}

#[test]
fn a_missing_key_is_refused() {
    let domain = report("  type: domain\n  fields: { registrar: Porkbun }");
    assert!(!codes(&domain).is_empty(), "{domain:?}");
    let service = report("  type: service\n  fields: { slug: sentry }");
    assert!(!codes(&service).is_empty(), "{service:?}");
}

#[test]
fn a_wrong_value_type_is_refused() {
    for body in [
        "  type: domain\n  fields: { fqdn: example.org, autoRenew: \"yes\" }",
        "  type: domain\n  fields: { fqdn: example.org, expires: soon }",
        "  type: domain\n  fields: { fqdn: example.org, nameservers: ns1.example.org }",
        "  type: service\n  fields: { slug: s, name: S, cost: cheap }",
        "  type: service\n  fields: { slug: s, name: S, url: not-a-url }",
    ] {
        assert!(!codes(&report(body)).is_empty(), "accepted: {body}");
    }
}

#[test]
fn a_repository_cannot_redefine_a_builtin() {
    for name in ["domain", "service"] {
        let yaml = format!(
            "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryType\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58c201\n  name: {name}\nspec:\n  displayName: Mine\n  key: slug\n  fields:\n    slug: {{ type: string, required: true }}\n"
        );
        let errors = validate_sources(&[SourceDocument {
            path: "type.yaml".into(),
            yaml,
        }]);
        assert_eq!(
            errors.iter().map(|d| d.code).collect::<Vec<_>>(),
            ["FM_SCHEMA_REGISTRY_BUILTIN_REDEFINED"]
        );
    }
}
