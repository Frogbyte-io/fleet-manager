//! The constrained local API: a Unix-socket status surface for local
//! agents.
//!
//! The local agent path (`controller-node-protocol.md#local-agent-path`)
//! lets `fleetctl` and local agents use a managed node's daemon without
//! controller credentials. The surface is deliberately smaller than the
//! controller API — one read, no mutations:
//!
//! - **Admission is structural.** The socket file is `0660`, so the kernel
//!   refuses a `connect()` from a peer outside the file's group before the
//!   daemon ever sees the connection; the packaged service unit (FM-211)
//!   sets the socket's group. Defense in depth re-checks the peer through
//!   `SO_PEERCRED` (via `rustix`, no unsafe): in the default (unset-group)
//!   mode a same-user peer is allowed — the development shape — and when a
//!   local group is configured, only peers whose effective group matches
//!   are allowed at all, so the daemon's own account is not an implicit
//!   superuser of the surface.
//! - **No secrets, no admin.** The response carries the node's own facts
//!   and the controller's public system view, fetched with the daemon's
//!   ordinary unprivileged read. No controller credential, provider
//!   secret, or admin endpoint is reachable from here, and a mutation is a
//!   `405` before anything else is considered.
//!
//! There is no request forwarding in this surface: forwarding arbitrary
//! reads needs delegation (M8); forwarding mutations is a non-goal.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::http::Controller;
use crate::state::NodeState;

#[cfg(unix)]
use std::io::{Read as _, Write as _};
#[cfg(unix)]
use std::os::unix::net::UnixListener;
#[cfg(unix)]
use std::time::Duration;

/// The socket file name inside the state directory.
pub const LOCAL_SOCKET_NAME: &str = "local.sock";

#[cfg(unix)]
/// The local request deadline: the status answer must arrive fast, so a
/// hung controller read cannot wedge a local agent for long.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The local status surface.
#[derive(Debug)]
pub struct LocalServer {
    socket_path: PathBuf,
    controller: Controller,
    state: Arc<NodeState>,
    journal: Arc<crate::journal::NodeJournal>,
    inventory: Arc<crate::inventory::InventoryState>,
    connected: Arc<AtomicBool>,
    /// When set, only peers whose effective group matches are allowed; the
    /// same-user allowance does not apply. Unset means same-user only.
    local_group: Option<u32>,
}

impl LocalServer {
    /// Composes the local surface from the daemon's own facts.
    #[must_use]
    pub fn new(
        state_dir: &Path,
        controller: Controller,
        state: Arc<NodeState>,
        journal: Arc<crate::journal::NodeJournal>,
        inventory: Arc<crate::inventory::InventoryState>,
        connected: Arc<AtomicBool>,
        local_group: Option<u32>,
    ) -> Self {
        Self {
            socket_path: state_dir.join(LOCAL_SOCKET_NAME),
            controller,
            state,
            journal,
            inventory,
            connected,
            local_group,
        }
    }

    /// The socket path this server listens on.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Binds the socket with the structural permissions and serves until
    /// `shutdown` completes. One request per connection; a failed peer
    /// check answers `403` and closes.
    ///
    /// # Panics
    ///
    /// Panics only if the socket cannot be made non-blocking, which is an
    /// OS-level misconfiguration.
    pub fn serve_blocking(self: Arc<Self>, shutdown: impl Fn() -> bool) {
        #[cfg(unix)]
        {
            self.serve_unix(shutdown);
        }
        #[cfg(not(unix))]
        {
            let _ = shutdown;
            eprintln!("fleetd: the local status surface is not supported on this platform yet");
        }
    }

    /// The Unix-socket serve loop.
    ///
    /// # Panics
    ///
    /// Panics only if the socket cannot be made non-blocking, which is an
    /// OS-level misconfiguration.
    #[cfg(unix)]
    fn serve_unix(self: Arc<Self>, shutdown: impl Fn() -> bool) {
        let _ = std::fs::remove_file(&self.socket_path);
        let listener = match UnixListener::bind(&self.socket_path) {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!(
                    "fleetd: cannot bind the local socket {}: {error}",
                    self.socket_path.display()
                );
                return;
            }
        };
        if let Err(error) = restrict_socket(&self.socket_path) {
            eprintln!("fleetd: the local socket's permissions are unsafe: {error}");
            return;
        }
        eprintln!(
            "fleetd: local status surface at {}",
            self.socket_path.display()
        );

        listener
            .set_nonblocking(true)
            .expect("the socket must go nonblocking");
        loop {
            if shutdown() {
                let _ = std::fs::remove_file(&self.socket_path);
                eprintln!("fleetd: local surface drained");
                return;
            }
            match listener.accept() {
                Ok((stream, _)) => self.handle_connection(stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(error) => {
                    eprintln!("fleetd: local accept failed: {error}");
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        }
    }

    /// Handles one connection: peer check, one request, one answer.
    #[cfg(unix)]
    fn handle_connection(&self, mut stream: std::os::unix::net::UnixStream) {
        let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
        let peer = peer_credentials(&stream);
        if !self.peer_allowed(peer) {
            let body = serde_json::json!({
                "code": "local_peer_denied",
                "message": "this local account is not allowed to use the node's local surface",
            });
            let _ = write_response(&mut stream, 403, &body);
            // The peer's request bytes are still queued: dropping with
            // unread data answers a Unix socket with a reset instead of
            // the response. Drain them, bounded, before the drop.
            drain(&mut stream);
            eprintln!(
                "fleetd: denied a local peer (uid {:?}, gid {:?})",
                peer.as_ref().map(|(uid, _, _)| uid),
                peer.as_ref().map(|(_, gid, _)| gid),
            );
            return;
        }

        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        // One small request; the read timeout bounds a peer that sends
        // nothing.
        match stream.read(&mut buffer) {
            Ok(read) => request.extend_from_slice(&buffer[..read]),
            Err(_) => return,
        }
        let text = String::from_utf8_lossy(&request);
        let mut parts = text.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");
        match (method, path) {
            ("GET", "/local/status") => {
                let body = serde_json::json!({
                    "node": self.node_facts(),
                    "fleet": self.fleet_facts(),
                });
                let _ = write_response(&mut stream, 200, &body);
                drain(&mut stream);
            }
            ("GET", _) => {
                let _ = write_response(
                    &mut stream,
                    404,
                    &serde_json::json!({
                        "code": "not_found",
                        "message": "the local surface only answers GET /local/status",
                    }),
                );
                drain(&mut stream);
            }
            (_, _) => {
                let _ = write_response(
                    &mut stream,
                    405,
                    &serde_json::json!({
                        "code": "method_not_allowed",
                        "message": "the local surface is read-only",
                    }),
                );
                drain(&mut stream);
            }
        }
    }

    #[cfg(unix)]
    fn peer_allowed(&self, peer: Option<(u32, u32, u32)>) -> bool {
        let Some((uid, gid, _)) = peer else {
            return false;
        };
        match self.local_group {
            Some(configured) => gid == configured,
            None => uid == own_uid(),
        }
    }

    fn node_facts(&self) -> serde_json::Value {
        serde_json::json!({
            "machineId": self.state.machine_id().unwrap_or_default(),
            "nodeVersion": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "gatewayState": if self.connected.load(Ordering::Relaxed) { "connected" } else { "disconnected" },
            "journalRecords": self.journal.record_count(),
            "inventoryRevision": self.inventory.revision(),
            "publicKey": self.state.public_key_hex(),
        })
    }

    fn fleet_facts(&self) -> serde_json::Value {
        // The controller's public system view, fetched with the daemon's
        // ordinary unprivileged read. A controller that does not answer is
        // reported honestly instead of cached.
        match blocking_get_json(&self.controller, "/api/v1/system") {
            Ok((status, body)) if (200..300).contains(&status) => serde_json::json!({
                "controller": self.controller.base_url(),
                "reachable": true,
                "system": body,
            }),
            Ok((status, _)) => serde_json::json!({
                "controller": self.controller.base_url(),
                "reachable": false,
                "status": status,
            }),
            Err(error) => serde_json::json!({
                "controller": self.controller.base_url(),
                "reachable": false,
                "error": error,
            }),
        }
    }
}

/// The peer's credentials from `SO_PEERCRED`, when the OS provides them.
///
/// # Panics
///
/// Panics never; every conversion degrades to a bounded value.
#[must_use]
#[cfg(unix)]
pub fn peer_credentials(stream: &std::os::unix::net::UnixStream) -> Option<(u32, u32, u32)> {
    use std::os::fd::AsFd as _;
    let credentials = rustix::net::sockopt::get_socket_peercred(stream.as_fd()).ok()?;
    Some((
        credentials.uid.as_raw(),
        credentials.gid.as_raw(),
        u32::try_from(credentials.pid.as_raw_nonzero().get()).unwrap_or(u32::MAX),
    ))
}

fn own_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Restricts the socket file to owner+group. The group ownership itself is
/// the deployment's doing (the packaged service unit sets it; see FM-211):
/// the daemon never chowns — it cannot assume it has the right.
#[cfg(unix)]
fn restrict_socket(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
            .map_err(|error| format!("cannot restrict {}: {error}", path.display()))?;
    }
    Ok(())
}

/// Reads the connection's remaining bytes until the peer stops sending,
/// so the close is an EOF rather than a reset. Bounded by a short timeout;
/// a peer that keeps writing is cut off.
#[cfg(unix)]
fn drain(stream: &mut std::os::unix::net::UnixStream) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(50)));
    let mut buffer = [0_u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

#[cfg(unix)]
fn write_response(
    stream: &mut std::os::unix::net::UnixStream,
    status: u16,
    body: &serde_json::Value,
) -> Result<(), String> {
    let payload = serde_json::to_string(body).map_err(|error| error.to_string())?;
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| format!("the response failed: {error}"))
}

/// A blocking GET for the daemon's own unprivileged reads.
fn blocking_get_json(
    controller: &Controller,
    path: &str,
) -> Result<(u16, serde_json::Value), String> {
    let mut stream = controller.connect_raw()?;
    stream
        .set_read_timeout(Some(REQUEST_TIMEOUT))
        .map_err(|error| format!("cannot set the read timeout: {error}"))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: fleetd-local\r\nConnection: close\r\n\r\n");
    std::io::Write::write_all(&mut stream, request.as_bytes())
        .map_err(|error| format!("the read failed: {error}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("the read failed: {error}"))?;
    let text = String::from_utf8_lossy(&response);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "the response has no body separator".to_owned())?;
    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| "the response has no status line".to_owned())?;
    let json = serde_json::from_str(body.trim()).unwrap_or(serde_json::Value::Null);
    Ok((status, json))
}
