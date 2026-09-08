//! The controller binary: argument dispatch over the composition root in the
//! library. The `serve` path is the default and the only one that starts a
//! process that can control machines. Configuration is loaded, validated, and
//! summarized (redacted) before readiness; an unsafe setting never starts a
//! controller.

use std::path::PathBuf;
use std::process::ExitCode;

use fleet_controller::exec::ScriptExecutor;
use fleet_controller::worker::run as run_worker;
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

/// The serve command: open the store, open the secret store, start the
/// worker, serve until shutdown, then drain in reverse order.
fn run_serve(config: fleet_config::ControllerConfig) -> ExitCode {
    let settings = Settings {
        listen: config.listen,
        web_dist: config.web_dist,
        artifacts_dir: Some(config.data_dir.join("artifacts")),
    };
    let database_path = config.data_dir.join("fleet.db");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("the async runtime must start");
    // The store is opened — and its migrations verified — before the
    // listener binds, so readiness never reports a database that has not
    // finished coming up.
    let outcome = runtime.block_on(async {
        let store = match fleet_storage_sqlite::Store::open(&database_path).await {
            Ok(store) => store,
            Err(error) => {
                eprintln!("fleet-controller: refusing to start: {error}");
                return None;
            }
        };
        eprintln!("runtime state at {}", store.database_path().display());
        // The secret store fails closed on a wrong or missing key, so a
        // configured key file is validated here, before readiness; an unset
        // one is a loud pre-secrets state, not an error.
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
        // The node-trust services compose only over a store and a secret
        // store; without both, the node surface serves the standard
        // "unavailable" envelope instead of minting credentials it cannot
        // verify.
        let secrets = secrets.map(std::sync::Arc::new);
        let services = match secrets.as_ref() {
            Some(secret_store) => {
                match fleet_controller::node_crypto::NodeCryptoService::open(secret_store).await {
                    Ok(crypto) => Some(fleet_controller::compose_node_services(
                        store.pool(),
                        std::sync::Arc::new(crypto),
                    )),
                    Err(error) => {
                        eprintln!("fleet-controller: refusing to start: {error}");
                        return None;
                    }
                }
            }
            None => None,
        };
        // The worker drives durable operations to their terminal states; it
        // drains when shutdown fires, before the server.
        let worker_operations = std::sync::Arc::new(fleet_application::operation::Operations::new(
            std::sync::Arc::new(fleet_storage_sqlite::OperationRepository::new(
                store.pool().clone(),
            )),
            std::sync::Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
        ));
        let (worker_shutdown, worker_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        // The executor routes by kind: node kinds dispatch through the
        // gateway, onboarding kinds work against the draft record, and
        // everything else is SSH work.
        let executor = {
            let ssh: std::sync::Arc<dyn fleet_application::worker::OperationExecutor> = {
                let machines: std::sync::Arc<dyn fleet_application::machine::MachinePort> =
                    std::sync::Arc::new(fleet_storage_sqlite::MachineRepository::new(
                        store.pool().clone(),
                    ));
                std::sync::Arc::new(ScriptExecutor::new(
                    machines,
                    config.data_dir.join("ssh"),
                    fleet_provider_ssh::ExecutionLimiter::new(4),
                ))
            };
            let limiter = fleet_provider_ssh::ExecutionLimiter::new(4);
            let onboarding: std::sync::Arc<dyn fleet_application::worker::OperationExecutor> =
                std::sync::Arc::new(fleet_controller::onboard::OnboardingExecutor::new(
                    std::sync::Arc::new(fleet_storage_sqlite::OnboardingRepository::new(
                        store.pool().clone(),
                    )),
                    config.data_dir.join("ssh"),
                    limiter.clone(),
                    ssh.clone(),
                ));
            // The install executor composes only over node trust services:
            // it mints enrollment tokens through the authorized use case, so
            // without them the kind fails honestly as undescribable.
            let with_install: std::sync::Arc<dyn fleet_application::worker::OperationExecutor> =
                match &services {
                    Some(services) => {
                        std::sync::Arc::new(fleet_controller::install::InstallExecutor::new(
                            std::sync::Arc::new(fleet_storage_sqlite::MachineRepository::new(
                                store.pool().clone(),
                            )),
                            services.nodes.clone(),
                            services.gateway.clone(),
                            config.data_dir.join("ssh"),
                            limiter.clone(),
                            Some(config.data_dir.join("artifacts")),
                            onboarding,
                        ))
                    }
                    None => onboarding,
                };
            match &services {
                Some(services) => {
                    let node_machines: std::sync::Arc<dyn fleet_application::machine::MachinePort> =
                        std::sync::Arc::new(fleet_storage_sqlite::MachineRepository::new(
                            store.pool().clone(),
                        ));
                    std::sync::Arc::new(fleet_controller::gateway::NodeCommandExecutor::new(
                        services.gateway.clone(),
                        node_machines,
                        with_install,
                    ))
                }
                None => with_install,
            }
        };
        let worker_handle = tokio::spawn(run_worker(worker_operations, executor, async move {
            let _ = worker_shutdown_rx.await;
        }));
        // The Add Machine workflow serves whenever the store is open: it
        // needs the draft repository, the machine use cases, and the SSH
        // trust adapter over the controller's SSH work directory.
        let onboarding = std::sync::Arc::new(fleet_controller::compose_onboarding(
            store.pool(),
            config.data_dir.join("ssh"),
        ));
        // The Tailscale discovery composes only over a secret store: its
        // OAuth client lives there. Without it the surface serves the
        // standard "unavailable" envelope.
        let tailnet = secrets.as_ref().map(|secrets| {
            std::sync::Arc::new(fleet_controller::tailnet_store::compose_tailnet(
                secrets.clone(),
                std::sync::Arc::new(fleet_provider_tailscale::TailscaleClient::new(
                    std::sync::Arc::new(
                        fleet_provider_tailscale::ReqwestTransport::new()
                            .expect("the tailscale transport must build"),
                    ),
                )),
                onboarding.clone(),
                std::sync::Arc::new(fleet_application::machine::Machines::new(
                    std::sync::Arc::new(fleet_storage_sqlite::MachineRepository::new(
                        store.pool().clone(),
                    )),
                    std::sync::Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
                )),
                std::sync::Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
            ))
        });
        let served = serve(
            settings,
            pool,
            services,
            Some(onboarding),
            tailnet,
            shutdown_signal(),
        )
        .await;
        let _ = worker_shutdown.send(());
        let _ = worker_handle.await;
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
        Command::Serve => run_serve(config),
        Command::Healthcheck => {
            if run_healthcheck(config.listen) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
