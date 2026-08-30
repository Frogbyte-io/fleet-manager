use std::process::ExitCode;

use xtask::{ProcessRunner, verify_with};

const HELP: &str = "Usage: cargo xtask verify";

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
