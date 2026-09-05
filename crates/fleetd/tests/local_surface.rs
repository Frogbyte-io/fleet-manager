//! The local status surface: peer admission, the one-read allowlist, and
//! the socket's structural permissions. Every test runs the real server on
//! a real Unix socket.

use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fleetd::local::LocalServer;

struct Harness {
    _dir: tempfile::TempDir,
    socket: std::path::PathBuf,
    journal: Arc<fleetd::journal::NodeJournal>,
    inventory: Arc<fleetd::inventory::InventoryState>,
    shutdown: Arc<AtomicBool>,
    server_thread: Option<std::thread::JoinHandle<()>>,
}

fn controller_unreachable() -> fleetd::http::Controller {
    // Port 1 is the TCP mux on loopback and refuses everything; the local
    // surface must answer honestly about an unreachable controller.
    fleetd::http::Controller::parse("http://127.0.0.1:1").unwrap()
}

fn harness(local_group: Option<u32>) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(fleetd::state::NodeState::open(dir.path()).unwrap());
    let journal = Arc::new(
        fleetd::journal::NodeJournal::open(&dir.path().join("journal.ndjson"))
            .map_err(|error| error.to_string())
            .unwrap(),
    );
    let inventory = Arc::new(
        fleetd::inventory::InventoryState::open(&dir.path().join("inventory.json"))
            .map_err(|error| error.to_string())
            .unwrap(),
    );
    let connected = Arc::new(AtomicBool::new(false));
    let server = Arc::new(LocalServer::new(
        dir.path(),
        controller_unreachable(),
        state,
        journal.clone(),
        inventory.clone(),
        connected,
        local_group,
    ));
    let socket = server.socket_path().to_path_buf();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = shutdown.clone();
    let server_thread = Some(std::thread::spawn(move || {
        server.serve_blocking(|| shutdown_flag.load(Ordering::Relaxed));
    }));
    // The socket file appears when the server binds.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the local socket must bind"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Harness {
        _dir: dir,
        socket,
        journal,
        inventory,
        shutdown,
        server_thread,
    }
}

/// The current process's effective gid, read from procfs without unsafe:
/// the denial test configures a group the test process does not hold.
fn peer_gid_of_this_process() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("Gid:")?
                    .split_whitespace()
                    .nth(1)?
                    .parse()
                    .ok()
            })
        })
        .unwrap_or(1)
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.server_thread.take() {
            let _ = thread.join();
        }
    }
}

fn request(socket: &std::path::Path, request: &str) -> (u16, serde_json::Value) {
    let mut stream = UnixStream::connect(socket).expect("the socket must connect");
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    stream
        .write_all(request.as_bytes())
        .expect("the request must write");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("the response must read");
    let text = String::from_utf8_lossy(&response);
    let (head, body) = text.split_once("\r\n\r\n").expect("an HTTP response");
    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (
        status,
        serde_json::from_str(body.trim()).unwrap_or(serde_json::Value::Null),
    )
}

#[test]
fn a_same_user_peer_reads_the_node_and_fleet_facts() {
    let harness = harness(None);
    let (status, body) = request(
        &harness.socket,
        "GET /local/status HTTP/1.1\r\nHost: local\r\n\r\n",
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["node"]["nodeVersion"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["node"]["gatewayState"], "disconnected");
    assert_eq!(body["node"]["inventoryRevision"], serde_json::Value::Null);
    // The controller is unreachable by construction; the surface reports
    // that honestly instead of faking a fleet view.
    assert_eq!(body["fleet"]["reachable"], false, "{body}");

    // Journal and inventory activity shows up.
    harness
        .journal
        .record_accepted("op-1", "node.noop")
        .unwrap();
    harness.inventory.collect(&probes(), None, 1).unwrap();
    let (status, body) = request(
        &harness.socket,
        "GET /local/status HTTP/1.1\r\nHost: local\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert_eq!(body["node"]["journalRecords"], 1);
    assert_eq!(body["node"]["inventoryRevision"], 1);
}

fn probes() -> fleetd::probes::ProbeRunner {
    fleetd::probes::ProbeRunner::new(vec![Arc::new(OsProbeOnly)])
}

#[derive(Debug)]
struct OsProbeOnly;

impl fleetd::probes::Probe for OsProbeOnly {
    fn name(&self) -> &'static str {
        "os"
    }

    fn collect(&self) -> Result<Vec<fleet_core::CapabilityFact>, String> {
        Ok(vec![fleet_core::CapabilityFact {
            namespace: "os".to_owned(),
            name: "family".to_owned(),
            value: Some(std::env::consts::OS.to_owned()),
            status: fleet_core::CapabilityStatus::Known,
            observed_at: fleet_core::Timestamp::from_unix_millis(0),
            source: String::new(),
        }])
    }
}

#[test]
fn a_peer_outside_the_configured_group_is_denied() {
    // The configured group is the test process's own gid plus one: nobody
    // in this process has it, so the credential check must refuse.
    let group_nobody_holds = peer_gid_of_this_process() + 1;
    let harness = harness(Some(group_nobody_holds));
    let (status, body) = request(
        &harness.socket,
        "GET /local/status HTTP/1.1\r\nHost: local\r\n\r\n",
    );
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["code"], "local_peer_denied", "{body}");
}

#[test]
fn the_surface_is_read_only_and_single_path() {
    let harness = harness(None);
    let (status, body) = request(
        &harness.socket,
        "POST /local/status HTTP/1.1\r\nHost: local\r\n\r\n",
    );
    assert_eq!(status, 405, "{body}");
    assert_eq!(body["code"], "method_not_allowed");
    let (status, body) = request(
        &harness.socket,
        "GET /api/v1/system HTTP/1.1\r\nHost: local\r\n\r\n",
    );
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["code"], "not_found");
}

#[test]
fn the_socket_file_is_owner_and_group_only() {
    let harness = harness(None);
    let mode = std::fs::metadata(&harness.socket)
        .expect("the socket file exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o660, "the kernel gate is the structural admission");
}
