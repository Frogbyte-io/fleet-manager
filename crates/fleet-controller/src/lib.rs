//! The controller composition root.
//!
//! This crate assembles the always-on control plane process: it wires the
//! public API adapter ([`fleet_api`]) and the static web shell into one HTTP
//! listener, answers container health probes, and shuts down gracefully.
//! Business rules live in the application and domain layers; nothing here
//! decides what an operation means.
//!
//! Configuration is deliberately a pair of environment placeholders until
//! FM-100 introduces typed controller configuration.
#![warn(missing_docs)]

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use tower_http::services::ServeDir;

/// The environment variable holding the listen address, e.g. `127.0.0.1:8080`.
pub const LISTEN_VAR: &str = "FLEET_LISTEN";
/// The environment variable holding the built web shell's directory.
pub const WEB_DIST_VAR: &str = "FLEET_WEB_DIST";
/// The default listen address: loopback only, because the controller is a
/// trusted-LAN service and must not face an untrusted network by accident.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
/// The default web shell directory for development runs beside the workspace.
pub const DEFAULT_WEB_DIST: &str = "./web";

/// The runtime settings the controller process needs before it can serve.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The address the HTTP listener binds.
    pub listen: SocketAddr,
    /// The directory holding the built web shell; served at `/`.
    pub web_dist: PathBuf,
}

impl Settings {
    /// Reads the settings from the process environment, applying the safe
    /// defaults documented on the constants above.
    ///
    /// # Errors
    ///
    /// Fails when `FLEET_LISTEN` is set but not a valid socket address; the
    /// process must not start on a setting it does not understand.
    ///
    /// # Panics
    ///
    /// Panics only if the documented default listen address stops being a
    /// valid socket address, which a test pins.
    pub fn from_env() -> Result<Self, String> {
        let listen = match std::env::var(LISTEN_VAR) {
            Ok(value) => value
                .parse::<SocketAddr>()
                .map_err(|error| format!("{LISTEN_VAR} is not a socket address: {error}"))?,
            Err(_) => DEFAULT_LISTEN
                .parse()
                .expect("the documented default listen address must parse"),
        };
        let web_dist = match std::env::var(WEB_DIST_VAR) {
            Ok(value) => PathBuf::from(value),
            Err(_) => PathBuf::from(DEFAULT_WEB_DIST),
        };
        Ok(Self { listen, web_dist })
    }
}

/// The health probe state shared with the probe handlers.
#[derive(Clone, Copy, Debug)]
pub struct Probe {
    web_dist_ready: bool,
}

/// Serves the web shell directory as an ordinary static file service, with the
/// directory's `index.html` answering bare directory requests.
fn shell(settings: &Settings) -> ServeDir {
    ServeDir::new(&settings.web_dist).append_index_html_on_directories(true)
}

/// Builds the controller's HTTP router.
///
/// Order of authority for an unmatched path, decided once and documented here:
/// the health probes match first, the static shell answers any path that is a
/// file in the web distribution, and the public API adapter answers everything
/// else — including unknown `/api/v1` paths, which therefore keep the JSON
/// error envelope instead of ever falling through to the web shell.
pub fn build_router(settings: &Settings) -> Router {
    let probe = Probe {
        web_dist_ready: settings.web_dist.join("index.html").is_file(),
    };
    let shell = shell(settings).fallback(fleet_api::router());

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .fallback_service(shell)
        .with_state(probe)
}

async fn healthz() -> &'static str {
    "ok\n"
}

async fn readyz(State(probe): State<Probe>) -> (StatusCode, &'static str) {
    // Until FM-101 adds the database whose readiness genuinely matters, the
    // only readiness fact is whether the web shell was found where the
    // settings point. The API serves either way; a missing shell must be
    // visible to the orchestrator, not silent.
    if probe.web_dist_ready {
        (StatusCode::OK, "ok\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "web shell not found\n")
    }
}

/// Binds [`Settings::listen`] and serves the controller until `shutdown`
/// completes, then returns once in-flight requests have drained.
///
/// # Errors
///
/// Fails if the listener cannot be bound or the server stops on an I/O error.
pub async fn serve(
    settings: Settings,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind(settings.listen).await?;
    serve_on(listener, settings, shutdown).await
}

/// Serves the controller on an already bound listener; [`serve`] is this plus
/// the bind. The listener is passed in so tests can bind port 0 and observe
/// the chosen port.
///
/// # Errors
///
/// Fails if the server stops on an I/O error.
pub async fn serve_on(
    listener: tokio::net::TcpListener,
    settings: Settings,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    eprintln!("fleet-controller listening on {}", listener.local_addr()?);
    if settings.web_dist.join("index.html").is_file() {
        eprintln!("serving web shell from {}", settings.web_dist.display());
    } else {
        eprintln!(
            "warning: no web shell at {} (set {}); the API still serves",
            settings.web_dist.display(),
            WEB_DIST_VAR
        );
    }
    axum::serve(listener, build_router(&settings))
        .with_graceful_shutdown(shutdown)
        .await
}

/// Completes on SIGTERM or SIGINT so the process drains before exiting.
///
/// # Panics
///
/// Panics if the signal handlers cannot be registered, which only happens when
/// the process is misconfigured at the OS level.
#[must_use]
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate()).expect("SIGTERM handler must register");
        let mut interrupt = signal(SignalKind::interrupt()).expect("SIGINT handler must register");
        tokio::select! {
            _ = terminate.recv() => eprintln!("received SIGTERM, draining"),
            _ = interrupt.recv() => eprintln!("received SIGINT, draining"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("SIGINT handler must register");
        eprintln!("received SIGINT, draining");
    }
}

/// Returns true when the controller answers `/readyz` on its configured
/// listener, and false otherwise. This is the container healthcheck: it needs
/// no shell, no HTTP client, and no package beyond the binary itself.
///
/// A wildcard listen address is probed on loopback, because the process cannot
/// connect to `0.0.0.0`.
#[must_use]
pub fn run_healthcheck() -> bool {
    let settings = match Settings::from_env() {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("healthcheck: {error}");
            return false;
        }
    };
    let host = match settings.listen.ip() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    let address = SocketAddr::new(host, settings.listen.port());
    let mut stream =
        match std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_secs(2)) {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("healthcheck: cannot reach {address}: {error}");
                return false;
            }
        };
    let request = format!("GET /readyz HTTP/1.0\r\nHost: {address}\r\n\r\n");
    let outcome = std::io::Write::write_all(&mut stream, request.as_bytes()).and_then(|()| {
        let mut response = [0_u8; 32];
        let read = std::io::Read::read(&mut stream, &mut response)?;
        let head = String::from_utf8_lossy(&response[..read]).into_owned();
        if head.starts_with("HTTP/1.0 200") || head.starts_with("HTTP/1.1 200") {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "not ready: {}",
                head.lines().next().unwrap_or("empty response")
            )))
        }
    });
    match outcome {
        Ok(()) => {
            eprintln!("healthcheck: ready");
            true
        }
        Err(error) => {
            eprintln!("healthcheck: {error}");
            false
        }
    }
}
