use std::path::PathBuf;
use std::process::ExitCode;

use xtask::{ProcessRunner, package_fleetd, verify_with};

const HELP: &str = "Usage: cargo xtask verify | cargo xtask package-fleetd | cargo xtask pve-acceptance [--target NAME] | cargo xtask image-acceptance [--target NAME]";

fn main() -> ExitCode {
    let all: Vec<String> = std::env::args().skip(1).collect();
    match all.first().map(String::as_str) {
        Some("pve-acceptance") => return live_suite(&xtask::pve_acceptance::SPEC, &all[1..]),
        Some("image-acceptance") => return live_suite(&xtask::image_acceptance::SPEC, &all[1..]),
        _ => {}
    }
    let mut args = all.into_iter();
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

/// Runs one live acceptance suite and prints its JSON summary on stdout;
/// everything else goes to stderr. Exits non-zero when any scenario/target
/// pair failed.
fn live_suite(spec: &xtask::acceptance::SuiteSpec, args: &[String]) -> ExitCode {
    let target = match xtask::acceptance::parse_args(spec, args) {
        Ok(target) => target,
        Err(message) => {
            eprintln!("error: {message}\n{HELP}");
            return ExitCode::from(2);
        }
    };
    match xtask::acceptance::run(spec, &find_repo_root(), target.as_deref()) {
        Ok(summary) => {
            println!("{}", summary.to_json());
            if summary.ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
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
