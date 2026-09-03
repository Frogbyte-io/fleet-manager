//! The controller binary: argument dispatch over the composition root in the
//! library. The `serve` path is the default and the only one that starts a
//! process that can control machines.

use std::process::ExitCode;

use fleet_controller::{Settings, run_healthcheck, serve, shutdown_signal};

const HELP: &str = "Usage: fleet-controller [--help|--version|serve|healthcheck]";

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => {
            println!("fleet-controller {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        Some("healthcheck") => {
            if run_healthcheck() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        None | Some("serve") => {
            let settings = match Settings::from_env() {
                Ok(settings) => settings,
                Err(error) => {
                    eprintln!("fleet-controller: {error}");
                    return ExitCode::from(2);
                }
            };
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("the async runtime must start");
            match runtime.block_on(serve(settings, shutdown_signal())) {
                Ok(()) => {
                    eprintln!("fleet-controller stopped gracefully");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("fleet-controller: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(other) => {
            eprintln!("unknown argument {other:?}\n{HELP}");
            ExitCode::from(2)
        }
    }
}
