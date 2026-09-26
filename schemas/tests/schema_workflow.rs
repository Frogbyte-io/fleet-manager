use std::{fs, path::Path, process::Command};

use fleet_schema::{SourceDocument, generated_schema_text, validate_sources};

fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("schemas package is below repository root")
}

#[test]
fn checked_in_schema_is_current() {
    let actual = fs::read_to_string(repository_root().join(fleet_schema::GENERATED_SCHEMA_PATH))
        .expect("generated schema exists");
    assert_eq!(actual, generated_schema_text());
}

#[test]
fn generated_schema_compiles_as_draft_2020_12() {
    let schema = fleet_schema::generate_schema();
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("generated schema compiles");
}

#[test]
fn minimal_fixture_validates_on_the_rust_library_path() {
    let path = repository_root().join("schemas/fixtures/valid/minimal.yaml");
    let diagnostics = validate_sources(&[SourceDocument {
        path: path.clone(),
        yaml: fs::read_to_string(path).unwrap(),
    }]);
    assert_eq!(diagnostics, []);
}

#[test]
fn skill_preset_pins_and_identity_components_are_semantically_validated() {
    let diagnostics = validate_sources(&[SourceDocument {
        path: "inline/invalid-skill-assignment.yaml".into(),
        yaml: r#"apiVersion: fleet.frogbyte.io/v1alpha1
kind: SkillPreset
metadata:
  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58a012
  name: bad-assignment
spec:
  skillId: "bad/skill"
  catalogId: " "
  catalogVersionId: version-1
  scope:
    type: all
  deployTo:
    - "bad/agent"
  denyAgents: []
"#
        .to_owned(),
    }]);
    assert_eq!(
        diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "FM_SCHEMA_SEMANTIC_INVALID_SKILL_ASSIGNMENT")
            .count(),
        3,
        "mismatched catalog pins and slash-delimited skill/agent IDs are rejected"
    );
}

#[test]
fn every_valid_fixture_validates() {
    // The fixtures are one candidate revision: they validate in a single
    // call, so identities must be unique across all files and documents.
    let fixtures = repository_root().join("schemas/fixtures/valid");
    let mut yaml_paths = fs::read_dir(fixtures)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "yaml")
        })
        .collect::<Vec<_>>();
    yaml_paths.sort();

    let sources = yaml_paths
        .iter()
        .map(|path| SourceDocument {
            path: path.strip_prefix(repository_root()).unwrap().to_path_buf(),
            yaml: fs::read_to_string(path).unwrap(),
        })
        .collect::<Vec<_>>();
    let diagnostics = validate_sources(&sources);
    assert_eq!(
        diagnostics,
        [],
        "the fixture set must validate: {diagnostics:?}"
    );
}

#[test]
fn invalid_fixtures_match_cli_diagnostic_goldens() {
    let fixtures = repository_root().join("schemas/fixtures/invalid");
    let mut yaml_paths = fs::read_dir(fixtures)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "yaml")
        })
        .collect::<Vec<_>>();
    yaml_paths.sort();

    for yaml_path in yaml_paths {
        let relative = yaml_path.strip_prefix(repository_root()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_fleet-schema"))
            .current_dir(repository_root())
            .args(["validate", relative.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "{} unexpectedly passed",
            relative.display()
        );
        assert!(output.stdout.is_empty());

        let expected = fs::read_to_string(yaml_path.with_extension("stderr"))
            .unwrap_or_else(|error| panic!("missing golden for {}: {error}", relative.display()));
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            expected,
            "{}",
            relative.display()
        );
    }
}
