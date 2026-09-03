//! The controller binary: argument dispatch over the composition root in the
//! library. The `serve` path is the default and the only one that starts a
//! process that can control machines. Configuration is loaded, validated, and
//! summarized (redacted) before readiness; an unsafe setting never starts a
//! controller.

use std::path::PathBuf;
use std::process::ExitCode;

use fleet_controller::{Settings, run_healthcheck, serve, shutdown_signal};

const HELP: &str = "Usage: fleet-controller [--config <path>] [--help|--version|serve|healthcheck]";

/// Parses the CLI form: an optional `--config <path>` followed by one command.
/// Precedence is documented in `fleet-config`: defaults < file < environment.
struct Args {
    config: Option<PathBuf>,
    command: Command,
}

enum Command {
    Serve,
    Healthcheck,
}

fn parse_args() -> Result<Args, String> {
    let mut config = None;
    let mut command = Command::Serve;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| "the --config flag requires a path".to_owned())?;
                config = Some(PathBuf::from(value));
            }
            "serve" => command = Command::Serve,
            "healthcheck" => command = Command::Healthcheck,
            other => return Err(format!("unknown argument {other:?}\n{HELP}")),
        }
    }
    Ok(Args { config, command })
}

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => {
            println!("fleet-controller {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h") => {
            println!("{HELP}");
            return ExitCode::SUCCESS;
        }
        _ => {}
    }

    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("fleet-controller: {message}");
            return ExitCode::from(2);
        }
    };

    let config = match fleet_config::load(args.config.as_deref(), fleet_config::process_env()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("fleet-controller: {error}");
            return ExitCode::from(2);
        }
    };
    if let Err(error) = config.validate() {
        eprintln!("fleet-controller: refusing to start: {error}");
        return ExitCode::from(2);
    }
    eprintln!("effective configuration:\n{}", config.summary());

    match args.command {
        Command::Serve => {
            let settings = Settings {
                listen: config.listen,
                web_dist: config.web_dist,
            };
            let database_path = config.data_dir.join("fleet.db");
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("the async runtime must start");
            // The store is opened — and its migrations verified — before the
            // listener binds, so readiness never reports a database that has
            // not finished coming up.
            let outcome = runtime.block_on(async {
                let store = match fleet_storage_sqlite::Store::open(&database_path).await {
                    Ok(store) => store,
                    Err(error) => {
                        eprintln!("fleet-controller: refusing to start: {error}");
                        return None;
                    }
                };
                eprintln!("runtime state at {}", store.database_path().display());
                // The secret store fails closed on a wrong or missing key, so
                // a configured key file is validated here, before readiness;
                // an unset one is a loud pre-secrets state, not an error.
                let mut secrets = None;
                if let Some(key_path) = &config.master_key_file {
                    match fleet_secrets::SecretStore::open(store.pool().clone(), key_path) {
                        Ok(opened) => {
                            eprintln!(
                                "secret store ready (key version {})",
                                opened.current_key_version()
                            );
                            secrets = Some(opened);
                        }
                        Err(error) => {
                            eprintln!("fleet-controller: refusing to start: {error}");
                            return None;
                        }
                    }
                }
                if secrets.is_none() {
                    eprintln!("secret store unavailable: no master key configured");
                }
                let pool = Some(store.pool().clone());
                let served = serve(settings, pool, shutdown_signal()).await;
                store.close().await;
                Some(served)
            });
            match outcome {
                Some(Ok(())) => {
                    eprintln!("fleet-controller stopped gracefully");
                    ExitCode::SUCCESS
                }
                Some(Err(error)) => {
                    eprintln!("fleet-controller: {error}");
                    ExitCode::FAILURE
                }
                None => ExitCode::from(2),
            }
        }
        Command::Healthcheck => {
            if run_healthcheck(config.listen) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
