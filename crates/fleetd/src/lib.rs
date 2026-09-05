//! The node daemon's library: everything the `fleetd` binary does, exposed
//! for integration tests so the real client — journal, commands, and gateway
//! loop — is what gets exercised, not a test double.
//!
//! The binary is a thin argument parser over [`crate::run`]; the composition
//! rules live with the modules.

pub mod commands;
pub mod gateway;
pub mod http;
pub mod inventory;
pub mod journal;
pub mod local;
pub mod probes;
pub mod session;
pub mod state;

use std::process::ExitCode;

/// Runs one command to completion. The binary maps the outcome onto an
/// exit code.
///
/// # Errors
///
/// Returns a caller-safe failure detail.
pub async fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Enroll(args) => {
            let controller = http::Controller::parse(&args.controller)?;
            let node_state = state::NodeState::open(&state_dir(args.state_dir.as_deref()))?;
            session::enroll(&controller, &node_state, &args.token)
        }
        Command::Run(args) => {
            let controller = http::Controller::parse(&args.controller)?;
            let node_state = std::sync::Arc::new(state::NodeState::open(&state_dir(
                args.state_dir.as_deref(),
            ))?);
            if node_state.credential().is_none() {
                return Err("the node is not enrolled: run `fleetd enroll` first".to_owned());
            }
            let journal = std::sync::Arc::new(
                journal::NodeJournal::open(
                    &state_dir(args.state_dir.as_deref()).join("journal.ndjson"),
                )
                .map_err(|error| error.to_string())?,
            );
            let inventory = std::sync::Arc::new(
                inventory::InventoryState::open(
                    &state_dir(args.state_dir.as_deref()).join("inventory.json"),
                )
                .map_err(|error| error.to_string())?,
            );
            // The local status surface runs beside the gateway loop: a
            // same-user (or configured-group) peer gets node and Fleet read
            // facts without controller credentials.
            let connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let server = std::sync::Arc::new(local::LocalServer::new(
                &state_dir(args.state_dir.as_deref()),
                controller.clone(),
                node_state.clone(),
                journal.clone(),
                inventory.clone(),
                connected.clone(),
                args.local_group,
            ));
            let local_shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let server_thread = {
                let server = server.clone();
                let local_shutdown = local_shutdown.clone();
                std::thread::spawn(move || {
                    server.serve_blocking(|| {
                        local_shutdown.load(std::sync::atomic::Ordering::Relaxed)
                    });
                })
            };
            let outcome = run_gateway_connected_with_status(
                controller,
                node_state,
                journal,
                inventory,
                connected,
                shutdown_signal(),
            )
            .await;
            local_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = server_thread.join();
            outcome
        }
    }
}

/// A parsed command line.
pub enum Command {
    /// One-time enrollment against a controller.
    Enroll(EnrollArgs),
    /// The gateway run loop.
    Run(RunArgs),
}

/// The enroll command's arguments.
pub struct EnrollArgs {
    /// The controller base URL.
    pub controller: String,
    /// The operator's single-use enrollment token.
    pub token: String,
    /// An explicit state directory, overriding the environment/default.
    pub state_dir: Option<String>,
}

/// The run command's arguments.
pub struct RunArgs {
    /// The controller base URL.
    pub controller: String,
    /// An explicit state directory, overriding the environment/default.
    pub state_dir: Option<String>,
    /// When set, only local peers whose effective group matches may use
    /// the local status surface; unset allows same-user peers only.
    pub local_group: Option<u32>,
}

/// The state directory for the given explicit path or environment.
#[must_use]
pub fn state_dir(explicit: Option<&str>) -> std::path::PathBuf {
    explicit
        .map(str::to_owned)
        .or_else(|| std::env::var(state::STATE_DIR_VAR).ok())
        .unwrap_or_else(|| state::DEFAULT_STATE_DIR.to_owned())
        .into()
}

/// The run loop: connect, serve, reconnect with bounded jitter, until the
/// shutdown signal or a fatal fault stops it.
///
/// # Errors
///
/// Returns a caller-safe detail when the loop stops on an enrollment or
/// journal problem; reconnectable failures never end it.
pub async fn run_gateway(
    controller: http::Controller,
    node_state: std::sync::Arc<state::NodeState>,
    journal: std::sync::Arc<journal::NodeJournal>,
    inventory: std::sync::Arc<inventory::InventoryState>,
) -> Result<(), String> {
    run_gateway_connected(
        controller,
        node_state,
        journal,
        inventory,
        shutdown_signal(),
    )
    .await
}

/// The run loop with a caller-supplied shutdown, so integration tests can
/// drain a real node without signal plumbing.
///
/// # Errors
///
/// Returns a caller-safe detail when the loop stops on an enrollment or
/// journal problem; reconnectable failures never end it.
pub async fn run_gateway_connected(
    controller: http::Controller,
    node_state: std::sync::Arc<state::NodeState>,
    journal: std::sync::Arc<journal::NodeJournal>,
    inventory: std::sync::Arc<inventory::InventoryState>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<(), String> {
    let connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    run_gateway_connected_with_status(
        controller, node_state, journal, inventory, connected, shutdown,
    )
    .await
}

/// The run loop with a caller-supplied shutdown and an owned connection
/// flag, which the local status surface reads.
///
/// # Errors
///
/// Returns a caller-safe detail when the loop stops on an enrollment or
/// journal problem; reconnectable failures never end it.
pub async fn run_gateway_connected_with_status(
    controller: http::Controller,
    node_state: std::sync::Arc<state::NodeState>,
    journal: std::sync::Arc<journal::NodeJournal>,
    inventory: std::sync::Arc<inventory::InventoryState>,
    connected: std::sync::Arc<std::sync::atomic::AtomicBool>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<(), String> {
    let mut shutdown = Box::pin(shutdown);
    let mut backoff = gateway::Backoff::new(gateway::FIRST_BACKOFF);
    loop {
        let shutdown_ref: &mut (dyn std::future::Future<Output = ()> + Unpin + Send) =
            &mut shutdown;
        match gateway::connect_once_with_status(
            &controller,
            &node_state,
            &journal,
            &inventory,
            &connected,
            shutdown_ref,
        )
        .await
        {
            gateway::Attempt::Stop(reason) => {
                eprintln!("fleetd: {reason}");
                return Ok(());
            }
            gateway::Attempt::Reconnect(reason) => {
                let wait = backoff.wait();
                eprintln!("fleetd: reconnecting in {wait:?}: {reason}");
                tokio::select! {
                    () = &mut shutdown => {
                        eprintln!("fleetd: shutdown signal received; not reconnecting");
                        return Ok(());
                    }
                    () = tokio::time::sleep(wait) => {}
                }
            }
        }
    }
}

/// Completes on SIGTERM or SIGINT so the process drains its session first.
///
/// # Panics
///
/// Panics if the signal handlers cannot be registered, which only happens
/// when the process is misconfigured at the OS level.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate()).expect("SIGTERM handler must register");
        let mut interrupt = signal(SignalKind::interrupt()).expect("SIGINT handler must register");
        tokio::select! {
            _ = terminate.recv() => eprintln!("fleetd: received SIGTERM, draining"),
            _ = interrupt.recv() => eprintln!("fleetd: received SIGINT, draining"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("SIGINT handler must register");
        eprintln!("fleetd: received SIGINT, draining");
    }
}

/// The binary's exit mapping.
///
/// # Panics
///
/// Panics only if the async runtime cannot start, which is a process-level
/// misconfiguration.
#[must_use]
pub fn main_exit(command: Result<Command, String>) -> ExitCode {
    let command = match command {
        Ok(command) => command,
        Err(message) => {
            eprintln!("fleetd: {message}");
            return ExitCode::from(2);
        }
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("the async runtime must start");
    match runtime.block_on(run(command)) {
        Ok(()) => {
            eprintln!("fleetd stopped");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("fleetd: {error}");
            ExitCode::FAILURE
        }
    }
}
