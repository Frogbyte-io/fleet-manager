//! FM-1121: the `hardware` field of the `LabTemplate` desired resource is
//! validated by the schema, agrees with the controller's own validation of the
//! same declaration, and leaves a template without it unchanged.

use fleet_schema::{Diagnostic, SourceDocument, validate_sources};

fn validate(spec_hardware: &str) -> Vec<Diagnostic> {
    validate_sources(&[SourceDocument {
        path: "inline/lab-template.yaml".into(),
        yaml: format!(
            "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: LabTemplate\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58f2b0\n  name: usb-lab\nspec:\n  imageVersion: \"24.04\"\n{spec_hardware}"
        ),
    }])
}

fn one(mapping: &str) -> Vec<Diagnostic> {
    // JSON string syntax is valid YAML and quotes any character safely.
    validate(&format!(
        "  hardware:\n    - kind: usb\n      mapping: {}\n",
        serde_json::to_string(mapping).unwrap()
    ))
}

#[test]
fn a_template_without_hardware_is_unchanged() {
    assert_eq!(validate(""), []);
    assert_eq!(validate("  hardware: []\n"), []);
}

#[test]
fn declared_usb_mappings_validate() {
    assert_eq!(one("fm-test-superdrive-a"), []);
    assert_eq!(
        validate(
            "  hardware:\n    - { kind: usb, mapping: fm-test-superdrive-a }\n    - { kind: usb, mapping: fm-test-verbatim }\n"
        ),
        []
    );
}

#[test]
fn the_schema_and_the_controller_accept_the_same_mapping_ids() {
    let long_ok = "x".repeat(64);
    let long_bad = "x".repeat(65);
    for mapping in [
        "a",
        "Dev_1.rev-2",
        "fm-test-verbatim",
        long_ok.as_str(),
        "",
        "-lead",
        ".lead",
        "_lead",
        "has space",
        "a,b",
        "a=b",
        "a/b",
        "usb0=mapping",
        "é",
        long_bad.as_str(),
    ] {
        assert_eq!(
            one(mapping).is_empty(),
            fleet_core::is_valid_hardware_mapping_id(mapping),
            "{mapping:?}: the schema and fleet-core disagree"
        );
    }
}

#[test]
fn an_unknown_kind_an_extra_key_and_a_missing_mapping_are_refused() {
    for hardware in [
        "  hardware:\n    - { kind: pci, mapping: gpu-a }\n",
        "  hardware:\n    - { kind: usb, mapping: a, host: \"05ac:1500\" }\n",
        "  hardware:\n    - { kind: usb }\n",
        "  hardware:\n    - { mapping: a }\n",
        "  hardware: usb\n",
    ] {
        assert!(!validate(hardware).is_empty(), "{hardware}");
    }
}

#[test]
fn at_most_four_devices_and_none_twice() {
    let entries = |count: usize| {
        let devices: Vec<String> = (0..count)
            .map(|n| format!("    - {{ kind: usb, mapping: dev-{n} }}"))
            .collect();
        format!("  hardware:\n{}\n", devices.join("\n"))
    };
    assert_eq!(validate(&entries(4)), []);
    assert!(!validate(&entries(5)).is_empty());
    let duplicates = validate(
        "  hardware:\n    - { kind: usb, mapping: dev-a }\n    - { kind: usb, mapping: dev-b }\n    - { kind: usb, mapping: dev-a }\n",
    );
    assert_eq!(duplicates.len(), 1, "{duplicates:?}");
    assert_eq!(duplicates[0].code, "FM_SCHEMA_SEMANTIC_DUPLICATE_HARDWARE");
    assert!(
        duplicates[0].location.ends_with("/spec/hardware/2/mapping"),
        "{}",
        duplicates[0].location
    );
}
