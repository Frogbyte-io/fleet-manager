//! Writes and verifies the checked-in `OpenAPI` document.
//!
//! The document is generated from the same router the controller serves, so it
//! cannot describe an endpoint that does not exist. `--check` regenerates and
//! byte-compares rather than rewriting, so a stale committed document fails the
//! build instead of being silently corrected.

use std::{path::PathBuf, process::ExitCode};

use fleet_api::openapi_json;

const USAGE: &str = "Usage:\n  fleet-openapi generate [--check]";

/// Repository-relative location of the generated document.
const GENERATED_DOCUMENT_PATH: &str = "packages/api-client/openapi.json";

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn run(args: &[String]) -> Result<(), ExitCode> {
    match args {
        [command] if command == "generate" => write_document(false),
        [command, check] if command == "generate" && check == "--check" => write_document(true),
        [help] if help == "--help" || help == "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        _ => {
            eprintln!("{USAGE}");
            Err(ExitCode::from(2))
        }
    }
}

fn document_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the api crate lives two directories below the repository root")
        .join(GENERATED_DOCUMENT_PATH)
}

fn write_document(check: bool) -> Result<(), ExitCode> {
    let path = document_path();
    let expected = openapi_json();

    if check {
        let actual = std::fs::read_to_string(&path).map_err(|error| {
            eprintln!("{} [FM_OPENAPI_GENERATED_MISSING] {error}", path.display());
            ExitCode::FAILURE
        })?;
        if actual == expected {
            println!("{} is up to date", path.display());
            Ok(())
        } else {
            eprintln!(
                "{} [FM_OPENAPI_GENERATED_STALE] run `cargo run -p fleet-api --bin fleet-openapi -- generate`",
                path.display()
            );
            Err(ExitCode::FAILURE)
        }
    } else {
        std::fs::create_dir_all(path.parent().expect("the document has a parent directory"))
            .map_err(|error| {
                eprintln!("{} [FM_OPENAPI_IO] {error}", path.display());
                ExitCode::FAILURE
            })?;
        std::fs::write(&path, expected).map_err(|error| {
            eprintln!("{} [FM_OPENAPI_IO] {error}", path.display());
            ExitCode::FAILURE
        })?;
        println!("wrote {}", path.display());
        Ok(())
    }
}
