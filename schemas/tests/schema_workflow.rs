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
