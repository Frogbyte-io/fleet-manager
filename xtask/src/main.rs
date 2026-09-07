use std::path::PathBuf;
use std::process::ExitCode;

use xtask::{ProcessRunner, package_fleetd, verify_with};

const HELP: &str = "Usage: cargo xtask verify | cargo xtask package-fleetd";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (Some("verify"), None) => {
            let mut runner = ProcessRunner;
            if let Err(error) = verify_with(&mut runner) {
                eprintln!("error: {error}");
                return ExitCode::FAILURE;
            }
            println!("\nRepository verification passed.");
            ExitCode::SUCCESS
        }
        (Some("package-fleetd"), None) => {
            let repo_root = find_repo_root();
            match package_fleetd(&repo_root) {
                Ok((archive, digest)) => {
                    println!("fleetd package: {}", archive.display());
                    println!("sha256: {digest}");
                    ExitCode::SUCCESS
                }
                Err(message) => {
                    eprintln!("error: {message}");
                    ExitCode::FAILURE
                }
            }
        }
        (None | Some("--help" | "-h"), None) => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{HELP}");
            ExitCode::from(2)
        }
    }
}

/// The workspace root: xtask always runs from the repository, but `cargo run
/// -p xtask` may start in a subdirectory, so walk up to the manifest.
fn find_repo_root() -> PathBuf {
    let manifest =
        std::env::var("CARGO_MANIFEST_DIR").map_or_else(|_| PathBuf::from("."), PathBuf::from);
    manifest
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or(manifest)
}
