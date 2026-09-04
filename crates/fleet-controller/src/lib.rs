//! The controller composition root.
//!
//! This crate assembles the always-on control plane process: it wires the
//! public API adapter ([`fleet_api`]) and the static web shell into one HTTP
//! listener, answers container health probes, and shuts down gracefully.
//! Business rules live in the application and domain layers; nothing here
//! decides what an operation means. Typed configuration and startup
//! validation live in [`fleet_config`]; the binary loads, validates, and
//! prints the effective (redacted) configuration before readiness.
#![warn(missing_docs)]

pub mod browser;
pub mod exec;
pub mod node_crypto;
pub mod worker;

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use sqlx::SqlitePool;
use tower_http::services::ServeDir;

/// The runtime settings the controller process needs before it can serve.
///
/// Built from a validated [`fleet_config::ControllerConfig`] by the binary;
/// tests construct it directly.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The address the HTTP listener binds.
    pub listen: SocketAddr,
    /// The directory holding the built web shell; served at `/`.
    pub web_dist: PathBuf,
}

/// Builds the API state over an opened store, or a state whose backends
/// answer nothing when the caller has none (tests). The authorization policy
/// is the trusted-LAN adapter in both cases.
///
/// `nodes` is the node-trust use-case service, composed by the binary when
/// the store and the secret store are both available; without it the node
/// surface answers with the standard envelope.
fn api_state(
    db: Option<SqlitePool>,
    nodes: Option<Arc<fleet_application::node::Nodes>>,
) -> fleet_api::operations::ApiState {
    let authorizer: std::sync::Arc<dyn fleet_application::authz::Authorizer> =
        std::sync::Arc::new(fleet_auth::LanAllowAllAuthorizer);
    if let Some(pool) = db {
        let operations = fleet_application::operation::Operations::new(
            std::sync::Arc::new(fleet_storage_sqlite::OperationRepository::new(pool.clone())),
            std::sync::Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone())),
        );
        let system = ControllerSystemInfo { pool: pool.clone() };
        return fleet_api::operations::ApiState {
            operations: std::sync::Arc::new(operations),
            authorizer,
            system: std::sync::Arc::new(system),
            nodes,
        };
    }
    // Without a store there is nothing to serve: the state's backends answer
    // nothing, and the permissive document policy is replaced so a state that
    // never serves traffic cannot pretend to authorize either.
    let state = fleet_api::operations::ApiState::for_document();
    fleet_api::operations::ApiState {
        operations: state.operations,
        authorizer: std::sync::Arc::new(DenyAllForTests),
        system: state.system,
        nodes: None,
    }
}

/// The system view assembled from this controller's own parts: its build,
/// its trust mode, and a live probe of its store.
#[derive(Debug)]
struct ControllerSystemInfo {
    pool: SqlitePool,
}

#[async_trait::async_trait]
impl fleet_api::system::SystemInfoSource for ControllerSystemInfo {
    async fn info(&self) -> Result<fleet_api::system::SystemInfo, String> {
        let (storage_ok, depths) = probe_pool(&self.pool).await;
        Ok(fleet_api::system::SystemInfo {
            service: "fleet-controller".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            trust_mode: fleet_auth::TrustMode::TrustedLan.id().to_owned(),
            trust_warning: fleet_auth::TrustMode::TrustedLan.warning().to_owned(),
            storage_ok,
            queue_pending: depths.0,
            queue_running: depths.1,
        })
    }
}

/// Probes the store and reads the queue depths on the caller's runtime.
async fn probe_pool(pool: &SqlitePool) -> (bool, (i64, i64)) {
    let probe = sqlx::query("SELECT 1").execute(pool).await.is_ok();
    let depths = sqlx::query(
        "SELECT COUNT(*) FILTER (WHERE state = 'pending') AS pending, \
         COUNT(*) FILTER (WHERE state = 'running') AS running FROM operations",
    )
    .fetch_one(pool)
    .await;
    let depths = match depths {
        Ok(row) => {
            use sqlx::Row as _;
            (row.get::<i64, _>("pending"), row.get::<i64, _>("running"))
        }
        Err(_) => (0, 0),
    };
    (probe, depths)
}

/// Denies everything; only used in states that never serve traffic.
#[derive(Debug)]
struct DenyAllForTests;

impl fleet_application::authz::Authorizer for DenyAllForTests {
    fn decide(
        &self,
        _request: fleet_application::authz::AccessRequest<'_>,
    ) -> fleet_application::authz::Decision {
        fleet_application::authz::Decision::deny(
            fleet_application::authz::ReasonId::UnknownPrincipal,
        )
    }
}

/// The health probe state shared with the probe handlers.
#[derive(Clone, Debug)]
pub struct Probe {
    web_dist_ready: bool,
    db: Option<SqlitePool>,
}

/// Serves the web shell directory as an ordinary static file service, with the
/// directory's `index.html` answering bare directory requests.
fn shell(settings: &Settings) -> ServeDir {
    ServeDir::new(&settings.web_dist)
        .append_index_html_on_directories(true)
        // Mutations and other non-GET methods must reach the API behind the
        // shell, not a 405 from the static file service.
        .call_fallback_on_method_not_allowed(true)
}

/// Builds the controller's HTTP router.
///
/// Order of authority for an unmatched path, decided once and documented here:
/// the health probes match first, the static shell answers any path that is a
/// file in the web distribution, and the public API adapter answers everything
/// else — including unknown `/api/v1` paths, which therefore keep the JSON
/// error envelope instead of ever falling through to the web shell.
///
/// `db` is the store's connection pool once the database is open; readiness
/// probes it live and the operation use cases run over it. Passing `None` is
/// for tests that do not involve storage. `nodes` is the node-trust use-case
/// service (see [`node_crypto`]); when it is present the machine-facing
/// enrollment router is mounted at `/api/node/v1` alongside the public API.
/// Every request through this router resolves to the trusted-LAN principal
/// with its request evidence (see `fleet_auth`); the service must be made
/// with connection info for that evidence to include the peer address.
pub fn build_router(
    settings: &Settings,
    db: Option<SqlitePool>,
    nodes: Option<Arc<fleet_application::node::Nodes>>,
) -> Router {
    let probe = Probe {
        web_dist_ready: settings.web_dist.join("index.html").is_file(),
        db: db.clone(),
    };
    let api_state = Arc::new(api_state(db, nodes));
    let shell = shell(settings).fallback(fleet_api::router(api_state.clone()));
    let router = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .fallback_service(shell)
        .layer(axum::middleware::from_fn(browser::browser_mutation_guard))
        .layer(axum::middleware::from_fn(browser::security_headers))
        .layer(axum::middleware::from_fn(fleet_auth::resolve_lan_caller))
        .with_state(probe);
    if api_state.nodes.is_some() {
        // The machine-facing enrollment endpoints: versioned with the node
        // protocol, documented in proto/README.md, and mounted beside the
        // public API — not under it.
        return router.nest("/api/node/v1", fleet_api::node::node_router(api_state));
    }
    router
}

async fn healthz() -> &'static str {
    "ok\n"
}

async fn readyz(State(probe): State<Probe>) -> (StatusCode, String) {
    // Readiness is the conjunction of the facts an orchestrator needs: the
    // web shell was found where the settings point, and the database answers
    // a live query. A degraded dependency must be visible, not silent.
    if !probe.web_dist_ready {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "web shell not found\n".to_owned(),
        );
    }
    if let Some(db) = &probe.db {
        let reachable = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            sqlx::query("SELECT 1").execute(db).await
        })
        .await;
        match reachable {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("database: {error}\n"),
                );
            }
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "database did not answer within 1s\n".to_owned(),
                );
            }
        }
    }
    (StatusCode::OK, "ok\n".to_owned())
}

/// Binds [`Settings::listen`] and serves the controller until `shutdown`
/// completes, then returns once in-flight requests have drained.
///
/// `db` is the opened store's pool, or `None` in tests; see [`build_router`].
/// `nodes` is the node-trust service, when the composition supports it.
///
/// # Errors
///
/// Fails if the listener cannot be bound or the server stops on an I/O error.
pub async fn serve(
    settings: Settings,
    db: Option<SqlitePool>,
    nodes: Option<Arc<fleet_application::node::Nodes>>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind(settings.listen).await?;
    serve_on(listener, settings, db, nodes, shutdown).await
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
    db: Option<SqlitePool>,
    nodes: Option<Arc<fleet_application::node::Nodes>>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    eprintln!("{}", fleet_auth::TrustMode::TrustedLan.warning());
    eprintln!("fleet-controller listening on {}", listener.local_addr()?);
    if settings.web_dist.join("index.html").is_file() {
        eprintln!("serving web shell from {}", settings.web_dist.display());
    } else {
        eprintln!(
            "warning: no web shell at {} (set {}); the API still serves",
            settings.web_dist.display(),
            fleet_config::WEB_DIST_VAR
        );
    }
    if nodes.is_some() {
        eprintln!("node trust surface mounted at /api/node/v1");
    } else {
        eprintln!("warning: node trust surface unavailable (no database or no master key)");
    }
    axum::serve(
        listener,
        build_router(&settings, db, nodes).into_make_service_with_connect_info::<SocketAddr>(),
    )
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

/// Returns true when the controller answers `/readyz` on the given listener
/// address, and false otherwise. This is the container healthcheck: it needs
/// no shell, no HTTP client, and no package beyond the binary itself. The
/// address comes from the same validated configuration the server uses.
///
/// A wildcard listen address is probed on loopback, because the process cannot
/// connect to `0.0.0.0`.
#[must_use]
pub fn run_healthcheck(listen: SocketAddr) -> bool {
    let host = match listen.ip() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    let address = SocketAddr::new(host, listen.port());
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
