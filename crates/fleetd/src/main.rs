//! `fleetd`: the node daemon.
//!
//! Two commands and the usual housekeeping:
//!
//! - `fleetd enroll --controller <url> --token <token>`: one-time
//!   enrollment. Generates (or reuses) the node's Ed25519 key in the
//!   node-local state directory, presents the public key with the operator's
//!   single-use token, and stores the returned credential. The private key
//!   never leaves this directory.
//! - `fleetd run --controller <url>`: the gateway client. Proves key
//!   possession for a short-lived session over HTTP, opens the outbound
//!   WebSocket with it, negotiates `Hello`/`Welcome`, heartbeats at the
//!   agreed interval, and reconnects with bounded jitter until shutdown.
//! - `--help` / `--version`.
//!
//! The state directory is `$FLEETD_STATE_DIR` or `fleetd-state` next to the
//! working directory; FM-211 owns the packaged service layout.

mod gateway;
mod http;
mod session;
mod state;

use std::process::ExitCode;
const HELP: &str = "Usage:
  fleetd enroll --controller <url> --token <token> [--state-dir <path>]
  fleetd run --controller <url> [--state-dir <path>]
  fleetd [--help|--version]";

struct EnrollArgs {
    controller: String,
    token: String,
    state_dir: Option<String>,
}

struct RunArgs {
    controller: String,
    state_dir: Option<String>,
}

enum Command {
    Enroll(EnrollArgs),
    Run(RunArgs),
}

fn parse_args() -> Result<Command, String> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return Err(HELP.to_owned());
    };
    let mut controller = None;
    let mut token = None;
    let mut state_dir = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--controller" => {
                controller = Some(
                    args.next()
                        .ok_or_else(|| "the --controller flag requires a URL".to_owned())?,
                );
            }
            "--token" => {
                token = Some(
                    args.next()
                        .ok_or_else(|| "the --token flag requires a value".to_owned())?,
                );
            }
            "--state-dir" => {
                state_dir = Some(
                    args.next()
                        .ok_or_else(|| "the --state-dir flag requires a path".to_owned())?,
                );
            }
            other => return Err(format!("unknown argument {other:?}\n{HELP}")),
        }
    }
    match command.as_str() {
        "enroll" => Ok(Command::Enroll(EnrollArgs {
            controller: controller.ok_or("enroll requires --controller <url>")?,
            token: token.ok_or("enroll requires --token <token>")?,
            state_dir,
        })),
        "run" => Ok(Command::Run(RunArgs {
            controller: controller.ok_or("run requires --controller <url>")?,
            state_dir,
        })),
        other => Err(format!("unknown command {other:?}\n{HELP}")),
    }
}

fn state_dir(explicit: Option<&str>) -> std::path::PathBuf {
    explicit
        .map(str::to_owned)
        .or_else(|| std::env::var(state::STATE_DIR_VAR).ok())
        .unwrap_or_else(|| state::DEFAULT_STATE_DIR.to_owned())
        .into()
}

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--version")
        || std::env::args().nth(1).as_deref() == Some("-V")
    {
        println!("fleetd {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if std::env::args().nth(1).as_deref() == Some("--help")
        || std::env::args().nth(1).as_deref() == Some("-h")
    {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }

    let command = match parse_args() {
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
    let outcome = runtime.block_on(run(command));
    match outcome {
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

async fn run(command: Command) -> Result<(), String> {
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
            run_gateway(controller, node_state).await
        }
    }
}

/// The run loop: connect, serve, reconnect with bounded jitter, until the
/// shutdown signal or a fatal fault stops it.
async fn run_gateway(
    controller: http::Controller,
    node_state: std::sync::Arc<state::NodeState>,
) -> Result<(), String> {
    let mut shutdown = Box::pin(shutdown_signal());
    let mut backoff = gateway::Backoff::new(gateway::FIRST_BACKOFF);
    loop {
        let shutdown_ref: &mut (dyn std::future::Future<Output = ()> + Unpin + Send) =
            &mut shutdown;
        match gateway::connect_once(&controller, &node_state, shutdown_ref).await {
            gateway::Attempt::Stop(reason) => {
                eprintln!("fleetd: {reason}");
                return Ok(());
            }
            gateway::Attempt::Reconnect(reason) => {
                let wait = backoff.next();
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
async fn shutdown_signal() {
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
