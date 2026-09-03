//! The `fleetctl` binary: argument dispatch over the library in `lib.rs`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.as_slice(), [x] if x == "--version" || x == "-V") {
        println!("fleetctl {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if matches!(args.as_slice(), [x] if x == "--help" || x == "-h") {
        println!("fleetctl {}", env!("CARGO_PKG_VERSION"));
    }

    match fleetctl::parse(&args) {
        Ok(invocation) => match fleetctl::run(&invocation) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("fleetctl: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            println!("{error}");
            ExitCode::from(2)
        }
    }
}
