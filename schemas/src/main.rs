use std::{path::PathBuf, process::ExitCode};

use fleet_schema::{generated_schema_path, generated_schema_text, validate_paths};

const USAGE: &str =
    "Usage:\n  fleet-schema generate [--check]\n  fleet-schema validate <file.yaml>...";

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn run(args: &[String]) -> Result<(), ExitCode> {
    match args {
        [command] if command == "generate" => write_schema(false),
        [command, check] if command == "generate" && check == "--check" => write_schema(true),
        [command, paths @ ..] if command == "validate" && !paths.is_empty() => {
            let paths = paths.iter().map(PathBuf::from).collect::<Vec<_>>();
            let diagnostics = validate_paths(&paths).map_err(|error| {
                eprintln!("[FM_SCHEMA_IO] {error}");
                ExitCode::FAILURE
            })?;
            if diagnostics.is_empty() {
                Ok(())
            } else {
                for diagnostic in diagnostics {
                    eprintln!("{diagnostic}");
                }
                Err(ExitCode::FAILURE)
            }
        }
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

fn write_schema(check: bool) -> Result<(), ExitCode> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("schemas package must be below the repository root")
        .to_path_buf();
    let path = generated_schema_path(&root);
    let expected = generated_schema_text();
    if check {
        let actual = std::fs::read_to_string(&path).map_err(|error| {
            eprintln!("{} [FM_SCHEMA_GENERATED_MISSING] {error}", path.display());
            ExitCode::FAILURE
        })?;
        if actual == expected {
            println!("{} is up to date", path.display());
            Ok(())
        } else {
            eprintln!(
                "{} [FM_SCHEMA_GENERATED_STALE] run `cargo run -p fleet-schema -- generate`",
                path.display()
            );
            Err(ExitCode::FAILURE)
        }
    } else {
        std::fs::create_dir_all(path.parent().expect("generated schema has a parent")).map_err(
            |error| {
                eprintln!("{} [FM_SCHEMA_IO] {error}", path.display());
                ExitCode::FAILURE
            },
        )?;
        std::fs::write(&path, expected).map_err(|error| {
            eprintln!("{} [FM_SCHEMA_IO] {error}", path.display());
            ExitCode::FAILURE
        })?;
        println!("wrote {}", path.display());
        Ok(())
    }
}
