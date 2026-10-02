//! FM-607 contract tests: the provider's public surface against the
//! recorded, synthetic PVE 8.x and 9.x fixtures in `fixtures/pve{8,9}/`
//! (`contract-*.json`; see `fixtures/README.md` for each upstream source).
//!
//! Every scenario is one function taking a [`Major`]; each test runs it
//! for both majors through [`for_each_major`], so 8.x and 9.x always see
//! the same assertions. The scripted transport answers only the routes a
//! scenario registers and panics on anything else, so an unexpected PVE
//! call fails the test instead of being silently answered.
//!
//! TLS mismatch is not re-tested here: it is client-side and
//! version-independent, and the real `PinningVerifier` is exercised by
//! `tests/pin_live.rs` (`a_wrong_fingerprint_is_refused_at_the_handshake`)
//! and by the FM-611 `trust` scenario in
//! `crates/fleet-controller/tests/proxmox_live.rs`, which passed live on
//! PVE 8.4 and 9.2 (FM-613).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_core::SensitiveString;
use fleet_provider_proxmox::{
    LifecycleAction, ProxmoxClient, ProxmoxSource, PveApiError, PveCredentials, PveGuest,
    PveHttpMethod, PveHttpRequest, PveHttpResponse, PveTransport, PveTransportError, TaskStatus,
    Upid,
};

const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";
const TOKEN_SECRET: &str = "fixture-secret-never-echoed";

/// One supported PVE major and the facts its fixtures encode.
#[derive(Clone, Copy, Debug)]
struct Major {
    dir: &'static str,
    version: &'static str,
    /// The healthy node.
    n1: &'static str,
    /// The node that is down in the partial-node scenarios.
    n2: &'static str,
    /// The guest-agent read privilege the 403 names (9.x split it out of
    /// `VM.Monitor`).
    agent_privilege: &'static str,
    /// The QGA version the Linux fixture reports.
    qga_version: &'static str,
    os_name: &'static str,
    kernel: &'static str,
}

const PVE8: Major = Major {
    dir: "pve8",
    version: "8.4.1",
    n1: "pve8-n1",
    n2: "pve8-n2",
    agent_privilege: "VM.Monitor",
    qga_version: "7.2.0",
    os_name: "Debian GNU/Linux 12 (bookworm)",
    kernel: "6.1.0-25-amd64",
};

const PVE9: Major = Major {
    dir: "pve9",
    version: "9.2.2",
    n1: "pve9-n1",
    n2: "pve9-n2",
    agent_privilege: "VM.GuestAgent.Audit",
    qga_version: "9.2.0",
    os_name: "Debian GNU/Linux 13 (trixie)",
    kernel: "6.12.48+deb13-amd64",
};

/// Runs one scenario once per supported major.
async fn for_each_major<F, Fut>(scenario: F)
where
    F: Fn(Major) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for major in [PVE8, PVE9] {
        scenario(major).await;
    }
}

/// Every fixture both majors carry, by its name without the
/// `contract-` prefix. `include_str!` needs literal paths, so the table
/// lists them once and the major picks its column.
macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        fn fixture(major: Major, name: &str) -> &'static str {
            match (major.dir, name) {
                $(
                    ("pve8", $name) => include_str!(concat!("fixtures/pve8/contract-", $name)),
                    ("pve9", $name) => include_str!(concat!("fixtures/pve9/contract-", $name)),
                )*
                // The FM-915 capacity bodies carry no node name, so the
                // healthy node reuses them instead of a copy.
                ("pve8", "node-status.json") => include_str!("fixtures/pve8/node-status.json"),
                ("pve9", "node-status.json") => include_str!("fixtures/pve9/node-status.json"),
                ("pve8", "node-storage.json") => include_str!("fixtures/pve8/node-storage.json"),
                ("pve9", "node-storage.json") => include_str!("fixtures/pve9/node-storage.json"),
                ("pve8", "version.json") => include_str!("fixtures/pve8/version.json"),
                ("pve9", "version.json") => include_str!("fixtures/pve9/version.json"),
                (dir, name) => panic!("no fixture {dir}/{name}"),
            }
        }
    };
}

fixtures!(
    "cluster-resources.json",
    "cluster-status.json",
    "nodes.json",
    "node-qemu.json",
    "node-lxc.json",
    "qemu-config-101.json",
    "qemu-config-102.json",
    "qemu-config-105.json",
    "qemu-config-106.json",
    "lxc-config-104.json",
    "forbidden-config.json",
    "forbidden-agent.json",
    "agent-info.json",
    "agent-network.json",
    "agent-osinfo.json",
    "agent-info-loose.json",
    "agent-network-loose.json",
    "agent-osinfo-loose.json",
    "agent-not-running.json",
    "status-start.json",
    "status-stop.json",
    "status-shutdown.json",
    "status-reboot.json",
    "malformed-upid.json",
    "task-running.json",
    "task-ok.json",
    "task-error.json",
    "task-stopped-no-exitstatus.json",
    "task-no-such-task.json",
    "snapshot-list.json",
    "snapshot-create.json",
    "snapshot-rollback.json",
    "snapshot-delete.json",
    "clone.json",
    "template.json",
);

fn json(major: Major, name: &str) -> serde_json::Value {
    serde_json::from_str(fixture(major, name))
        .unwrap_or_else(|error| panic!("{}/{name} is not JSON: {error}", major.dir))
}

/// One scripted answer.
#[derive(Clone, Debug)]
enum Reply {
    Http(u16, String),
    /// A transport failure, e.g. the client's own request timeout.
    Transport(String),
}

/// The scripted transport: `(method, path)` → a queue of replies. The last
/// reply of a queue repeats, so a poll loop sees a stable terminal state.
#[derive(Debug, Default)]
struct Scripted {
    routes: Mutex<HashMap<(String, String), VecDeque<Reply>>>,
    log: Mutex<Vec<(PveHttpMethod, String, Option<serde_json::Value>)>>,
}

impl Scripted {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn on(&self, method: PveHttpMethod, path: impl Into<String>, replies: Vec<Reply>) -> &Self {
        assert!(!replies.is_empty());
        self.routes
            .lock()
            .unwrap()
            .insert((format!("{method:?}"), path.into()), replies.into());
        self
    }

    fn get(&self, path: impl Into<String>, status: u16, body: &str) -> &Self {
        self.on(
            PveHttpMethod::Get,
            path,
            vec![Reply::Http(status, body.to_owned())],
        )
    }

    fn post(&self, path: impl Into<String>, status: u16, body: &str) -> &Self {
        self.on(
            PveHttpMethod::Post,
            path,
            vec![Reply::Http(status, body.to_owned())],
        )
    }

    fn calls(&self) -> Vec<(PveHttpMethod, String, Option<serde_json::Value>)> {
        self.log.lock().unwrap().clone()
    }

    fn answer(
        &self,
        request: &PveHttpRequest,
        body: Option<serde_json::Value>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        assert_eq!(request.pinned_fingerprint.as_deref(), Some(FP));
        self.log
            .lock()
            .unwrap()
            .push((request.method, request.path.clone(), body));
        let mut routes = self.routes.lock().unwrap();
        let queue = routes
            .get_mut(&(format!("{:?}", request.method), request.path.clone()))
            .unwrap_or_else(|| {
                panic!("unscripted PVE call: {:?} {}", request.method, request.path)
            });
        let reply = if queue.len() > 1 {
            queue.pop_front().unwrap()
        } else {
            queue.front().unwrap().clone()
        };
        match reply {
            Reply::Http(status, body) => Ok(PveHttpResponse {
                status,
                body: body.into_bytes(),
            }),
            Reply::Transport(detail) => Err(PveTransportError::Connect { detail }),
        }
    }
}

#[async_trait]
impl PveTransport for Scripted {
    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        self.answer(&request, None)
    }

    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        let body = serde_json::from_slice(&body).expect("the provider sends JSON bodies");
        self.answer(&request, Some(body))
    }
}

fn request() -> PveHttpRequest {
    PveHttpRequest {
        host: "pve.test".to_owned(),
        port: 8006,
        path: "/api2/json/version".to_owned(),
        pinned_fingerprint: Some(FP.to_owned()),
        credentials: Arc::new(PveCredentials {
            token_id: "fleet@pve!contract".to_owned(),
            token: SensitiveString::new(TOKEN_SECRET),
        }),
        method: PveHttpMethod::Get,
    }
}

fn client(transport: &Arc<Scripted>) -> ProxmoxClient {
    ProxmoxClient::new(transport.clone())
}

/// How the down node answers in a partial-node scenario.
#[derive(Clone, Copy, Debug)]
enum Down {
    /// The survivor proxies the call and answers 595 with no JSON body,
    /// the reason only in the status line (FM-613, `--mode stop`).
    Proxy595,
    /// The client's own request deadline (15 s) expires first: the
    /// survivor takes about 30 s to give up on an unreachable node
    /// (FM-613, `--mode partition`).
    Timeout,
}

impl Down {
    fn reply(self) -> Reply {
        match self {
            Self::Proxy595 => Reply::Http(595, String::new()),
            Self::Timeout => Reply::Transport("operation timed out".to_owned()),
        }
    }

    /// The text the provider's warning carries for this failure.
    fn marker(self) -> &'static str {
        match self {
            Self::Proxy595 => "595",
            Self::Timeout => "the connection failed",
        }
    }
}

/// The healthy cluster prologue plus the healthy node's capacity reads.
fn script_discovery(transport: &Scripted, major: Major) {
    transport
        .get("/api2/json/version", 200, fixture(major, "version.json"))
        .get(
            "/api2/json/cluster/resources",
            200,
            fixture(major, "cluster-resources.json"),
        )
        .get(
            format!("/api2/json/nodes/{}/status", major.n1),
            200,
            fixture(major, "node-status.json"),
        )
        .get(
            format!("/api2/json/nodes/{}/storage", major.n1),
            200,
            fixture(major, "node-storage.json"),
        );
}

/// The guest reads for every guest on the healthy node: 101 has a full
/// agent, 102's agent is not running, 103's config and agent are
/// forbidden, 104 is LXC, and 106's agent answers loosely.
fn script_guests(transport: &Scripted, major: Major) {
    let n1 = major.n1;
    let qemu = |vmid: u32, tail: &str| format!("/api2/json/nodes/{n1}/qemu/{vmid}/{tail}");
    transport
        .get(
            qemu(101, "config"),
            200,
            fixture(major, "qemu-config-101.json"),
        )
        .get(
            qemu(101, "agent/info"),
            200,
            fixture(major, "agent-info.json"),
        )
        .get(
            qemu(101, "agent/network-get-interfaces"),
            200,
            fixture(major, "agent-network.json"),
        )
        .get(
            qemu(101, "agent/get-osinfo"),
            200,
            fixture(major, "agent-osinfo.json"),
        )
        .get(
            qemu(102, "config"),
            200,
            fixture(major, "qemu-config-102.json"),
        )
        .get(
            qemu(102, "agent/info"),
            500,
            fixture(major, "agent-not-running.json"),
        )
        .get(
            qemu(103, "config"),
            403,
            fixture(major, "forbidden-config.json"),
        )
        .get(
            qemu(103, "agent/info"),
            403,
            fixture(major, "forbidden-agent.json"),
        )
        .get(
            format!("/api2/json/nodes/{n1}/lxc/104/config"),
            200,
            fixture(major, "lxc-config-104.json"),
        )
        .get(
            qemu(106, "config"),
            200,
            fixture(major, "qemu-config-106.json"),
        )
        .get(
            qemu(106, "agent/info"),
            200,
            fixture(major, "agent-info-loose.json"),
        )
        .get(
            qemu(106, "agent/network-get-interfaces"),
            200,
            fixture(major, "agent-network-loose.json"),
        )
        .get(
            qemu(106, "agent/get-osinfo"),
            200,
            fixture(major, "agent-osinfo-loose.json"),
        );
}

/// Every path the down node is asked for answers the same way.
fn script_down_node(transport: &Scripted, major: Major, down: Down) {
    let n2 = major.n2;
    for path in [
        format!("/api2/json/nodes/{n2}/status"),
        format!("/api2/json/nodes/{n2}/storage"),
        format!("/api2/json/nodes/{n2}/qemu/105/config"),
        format!("/api2/json/nodes/{n2}/qemu/105/agent/info"),
    ] {
        transport.on(PveHttpMethod::Get, path, vec![down.reply()]);
    }
}

fn guest(discovery: &[PveGuest], id: &str) -> PveGuest {
    discovery
        .iter()
        .find(|guest| guest.resource.id == id)
        .unwrap_or_else(|| panic!("guest {id} is missing"))
        .clone()
}

fn assert_secret_free(major: Major, texts: &[String]) {
    for text in texts {
        assert!(
            !text.contains(TOKEN_SECRET),
            "{}: a warning echoes the token secret: {text}",
            major.dir
        );
    }
}

// ---- discovery and partial-node failure ----

async fn partial_node_discovery(major: Major, down: Down) {
    let transport = Scripted::new();
    script_discovery(&transport, major);
    script_down_node(&transport, major, down);

    let discovery = client(&transport).discover(request()).await.unwrap();

    assert_eq!(discovery.version, major.version, "{}", major.dir);
    // 9.x adds `network` rows; they are skipped like `sdn` and `pool`,
    // never warned about as an unknown type.
    let kinds = discovery
        .resources
        .iter()
        .map(|resource| resource.kind.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        [
            "qemu",
            "qemu",
            "qemu",
            "lxc",
            "qemu",
            "qemu-template",
            "qemu",
            "node",
            "node",
            "storage",
            "storage"
        ],
        "{}",
        major.dir
    );
    let down_node = discovery
        .resources
        .iter()
        .find(|resource| resource.id == format!("node/{}", major.n2))
        .unwrap();
    assert_eq!(down_node.status.as_deref(), Some("offline"));
    // The guest on the down node is reported with what the cluster knows.
    let orphan = discovery
        .resources
        .iter()
        .find(|resource| resource.id == "qemu/105")
        .unwrap();
    assert_eq!(orphan.node.as_deref(), Some(major.n2));
    assert_eq!(orphan.status.as_deref(), Some("unknown"));
    assert_eq!(orphan.name, None);

    // The healthy node's capacity lands; the down node's is honestly empty.
    assert_eq!(discovery.node_capacities.len(), 2);
    let healthy = &discovery.node_capacities[0];
    assert_eq!(healthy.node, major.n1);
    assert!(healthy.cpu_usage_ratio.is_some());
    assert!(healthy.memory_total_bytes.is_some());
    assert_eq!(healthy.storages.len(), 2);
    let gone = &discovery.node_capacities[1];
    assert_eq!(gone.node, major.n2);
    assert_eq!(gone.cpu_usage_ratio, None);
    assert_eq!(gone.memory_total_bytes, None);
    assert!(gone.storages.is_empty());

    // Exactly the per-node warnings: status and storage of the down node.
    assert_eq!(discovery.warnings.len(), 2, "{:?}", discovery.warnings);
    for (warning, surface) in discovery.warnings.iter().zip(["status", "storage"]) {
        assert!(
            warning.starts_with(&format!("node {} {surface}: ", major.n2)),
            "{}: {warning}",
            major.dir
        );
        assert!(warning.contains(down.marker()), "{}: {warning}", major.dir);
    }
    assert_secret_free(major, &discovery.warnings);
}

#[tokio::test]
async fn partial_node_failure_595_keeps_the_healthy_node() {
    for_each_major(|major| partial_node_discovery(major, Down::Proxy595)).await;
}

#[tokio::test]
async fn partial_node_failure_timeout_keeps_the_healthy_node() {
    for_each_major(|major| partial_node_discovery(major, Down::Timeout)).await;
}

async fn partial_node_guests(major: Major, down: Down) {
    let transport = Scripted::new();
    script_discovery(&transport, major);
    script_guests(&transport, major);
    script_down_node(&transport, major, down);

    let discovery = client(&transport).guest_discover(request()).await.unwrap();

    // Every guest is reported, the template is not (it is not a guest).
    let ids = discovery
        .guests
        .iter()
        .map(|guest| guest.resource.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        [
            "qemu/101", "qemu/102", "qemu/103", "lxc/104", "qemu/106", "qemu/105"
        ],
        "{}",
        major.dir
    );
    // The healthy node's guests carry their evidence.
    let web = guest(&discovery.guests, "qemu/101");
    assert_eq!(web.macs, ["bc:24:11:0a:01:01", "bc:24:11:0a:01:02"]);
    assert!(web.agent.as_ref().unwrap().online);
    assert!(web.warnings.is_empty(), "{:?}", web.warnings);
    // The down node's guest survives without evidence and with warnings
    // that name the failure.
    let orphan = guest(&discovery.guests, "qemu/105");
    assert!(orphan.macs.is_empty());
    assert!(!orphan.agent.as_ref().unwrap().online);
    assert_eq!(orphan.warnings.len(), 1, "{:?}", orphan.warnings);
    let config_warning = discovery
        .warnings
        .iter()
        .find(|warning| warning.starts_with("guest qemu/105: "))
        .unwrap_or_else(|| panic!("{}: no config warning for 105", major.dir));
    assert!(
        config_warning.contains(down.marker()),
        "{}: {config_warning}",
        major.dir
    );
    let mut all = discovery.warnings.clone();
    for guest in &discovery.guests {
        all.extend(guest.warnings.iter().cloned());
    }
    assert_secret_free(major, &all);
}

#[tokio::test]
async fn partial_node_failure_595_keeps_the_healthy_nodes_guests() {
    for_each_major(|major| partial_node_guests(major, Down::Proxy595)).await;
}

#[tokio::test]
async fn partial_node_failure_timeout_keeps_the_healthy_nodes_guests() {
    for_each_major(|major| partial_node_guests(major, Down::Timeout)).await;
}

async fn account_host_unreachable(major: Major) {
    // When the account's own host is the one that is down, there is no
    // survivor to proxy for it: the read fails as a transport error, never
    // as an empty inventory.
    let transport = Scripted::new();
    transport.on(
        PveHttpMethod::Get,
        "/api2/json/version",
        vec![Down::Timeout.reply()],
    );
    let error = client(&transport).discover(request()).await.unwrap_err();
    assert!(
        matches!(
            error,
            PveApiError::Transport(PveTransportError::Connect { .. })
        ),
        "{}: {error:?}",
        major.dir
    );
}

#[tokio::test]
async fn an_unreachable_account_host_fails_the_read() {
    for_each_major(account_host_unreachable).await;
}

/// `cluster/status`, `/nodes`, and the per-node guest lists are not read by
/// the provider today; this keeps their fixtures consistent with the
/// `cluster/resources` they describe, so a future consumer starts from a
/// coherent cluster.
async fn cluster_views_agree(major: Major) {
    let resources = json(major, "cluster-resources.json");
    let resources = resources["data"].as_array().unwrap();
    let status = json(major, "cluster-status.json");
    let status = status["data"].as_array().unwrap();
    let nodes = json(major, "nodes.json");
    let nodes = nodes["data"].as_array().unwrap();

    // A two-node cluster that lost a node is inquorate (FM-613).
    let cluster = status.iter().find(|row| row["type"] == "cluster").unwrap();
    assert_eq!(cluster["quorate"], 0);
    assert_eq!(cluster["nodes"], 2);
    for (node, online) in [(major.n1, 1), (major.n2, 0)] {
        let member = status.iter().find(|row| row["name"] == node).unwrap();
        assert_eq!(member["online"], online, "{}: {node}", major.dir);
        let listed = nodes.iter().find(|row| row["node"] == node).unwrap();
        let resource = resources
            .iter()
            .find(|row| row["id"] == format!("node/{node}"))
            .unwrap();
        assert_eq!(
            listed["status"], resource["status"],
            "{}: {node}",
            major.dir
        );
    }

    // The node's guest lists name the same guests the cluster places there.
    let on_n1 = |kind: &str| {
        let mut vmids = resources
            .iter()
            .filter(|row| row["type"] == kind && row["node"] == major.n1)
            .map(|row| row["vmid"].as_u64().unwrap())
            .collect::<Vec<_>>();
        vmids.sort_unstable();
        vmids
    };
    let listed = |name: &str| {
        let list = json(major, name);
        let mut vmids = list["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["vmid"].as_u64().unwrap())
            .collect::<Vec<_>>();
        vmids.sort_unstable();
        vmids
    };
    assert_eq!(listed("node-qemu.json"), on_n1("qemu"), "{}", major.dir);
    assert_eq!(listed("node-lxc.json"), on_n1("lxc"), "{}", major.dir);

    // The 9.x drift: `network` rows, `memhost`, and `host-arch` exist only
    // on 9.x.
    let has = |predicate: &dyn Fn(&serde_json::Value) -> bool| resources.iter().any(predicate);
    let nine = major.dir == "pve9";
    assert_eq!(has(&|row| row["type"] == "network"), nine, "{}", major.dir);
    assert_eq!(
        has(&|row| row.get("memhost").is_some()),
        nine,
        "{}",
        major.dir
    );
    assert_eq!(
        has(&|row| row.get("host-arch").is_some()),
        nine,
        "{}",
        major.dir
    );
}

#[tokio::test]
async fn cluster_status_nodes_and_guest_lists_agree_with_resources() {
    for_each_major(cluster_views_agree).await;
}

// ---- privilege failure and guest agent ----

async fn guest_scenarios(major: Major) {
    let transport = Scripted::new();
    script_discovery(&transport, major);
    script_guests(&transport, major);
    script_down_node(&transport, major, Down::Proxy595);

    let discovery = client(&transport).guest_discover(request()).await.unwrap();

    // Privilege failure: 103's config and agent are forbidden. The guest is
    // still reported, the 403 is named, and the other guests are whole.
    let forbidden = guest(&discovery.guests, "qemu/103");
    assert!(forbidden.macs.is_empty());
    assert!(!forbidden.agent.as_ref().unwrap().online);
    let warning = discovery
        .warnings
        .iter()
        .find(|warning| warning.starts_with("guest qemu/103: "))
        .unwrap();
    assert!(warning.contains("403"), "{}: {warning}", major.dir);
    assert!(warning.contains("VM.Audit"), "{}: {warning}", major.dir);
    assert!(fixture(major, "forbidden-agent.json").contains(major.agent_privilege));
    assert!(!forbidden.warnings.is_empty());

    // A full Linux agent: version, OS, kernel, and interfaces with
    // normalized MACs. Loopback is excluded; link-local stays (it is the
    // agent's honest report, and it never matches an endpoint host).
    let web = guest(&discovery.guests, "qemu/101");
    let agent = web.agent.unwrap();
    assert!(agent.online);
    assert_eq!(agent.version.as_deref(), Some(major.qga_version));
    assert_eq!(agent.os_name.as_deref(), Some(major.os_name));
    assert_eq!(agent.kernel.as_deref(), Some(major.kernel));
    let names = agent
        .interfaces
        .iter()
        .map(|interface| interface.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, ["ens18", "ens19"], "{}", major.dir);
    assert_eq!(
        agent.interfaces[0].mac.as_deref(),
        Some("bc:24:11:0a:01:01")
    );
    assert_eq!(
        agent.interfaces[0].addresses,
        ["192.0.2.101", "2001:db8::101", "fe80::be24:11ff:fe0a:101"]
    );
    for interface in &agent.interfaces {
        for address in &interface.addresses {
            let ip: std::net::IpAddr = address.parse().unwrap();
            assert!(!ip.is_loopback(), "{}: {address}", major.dir);
        }
    }

    // An agent that is configured but not running: a 500 from `info`. The
    // guest is offline-agent, not dropped, and no other agent surface is
    // asked.
    let db = guest(&discovery.guests, "qemu/102");
    assert_eq!(db.macs, ["bc:24:11:0a:01:11"]);
    let agent = db.agent.unwrap();
    assert_eq!(agent, fleet_provider_proxmox::PveGuestAgent::default());
    assert_eq!(db.warnings.len(), 1, "{:?}", db.warnings);
    let asked = transport
        .calls()
        .iter()
        .filter(|(_, path, _)| path.contains("/qemu/102/agent/"))
        .count();
    assert_eq!(asked, 1, "{}", major.dir);

    // Loose agent fields: no version, no pretty-name, an address without a
    // prefix, a NIC without addresses, a tunnel without a hardware address,
    // and an interface with neither (skipped). Lowercase-insensitive MACs.
    let lab = guest(&discovery.guests, "qemu/106");
    assert_eq!(lab.macs, ["bc:24:11:0a:01:31"]);
    let agent = lab.agent.unwrap();
    assert!(agent.online);
    assert_eq!(agent.version, None);
    assert_eq!(agent.os_name, None);
    assert_eq!(agent.kernel.as_deref(), Some("6.6.58-0-virt"));
    let interfaces = agent
        .interfaces
        .iter()
        .map(|interface| {
            (
                interface.name.as_str(),
                interface.mac.as_deref(),
                interface.addresses.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        interfaces,
        [
            (
                "eth0",
                Some("bc:24:11:0a:01:31"),
                vec!["192.0.2.131".to_owned()]
            ),
            ("eth1", Some("bc:24:11:0a:01:32"), vec![]),
            ("wg0", None, vec!["203.0.113.131".to_owned()]),
        ],
        "{}",
        major.dir
    );
    assert!(lab.warnings.is_empty(), "{:?}", lab.warnings);

    // LXC: config MACs, no agent by design.
    let cache = guest(&discovery.guests, "lxc/104");
    assert_eq!(cache.macs, ["bc:24:11:0a:01:21"]);
    assert_eq!(cache.agent, None);
    assert!(cache.warnings.is_empty(), "{:?}", cache.warnings);
}

#[tokio::test]
async fn privilege_failures_and_agent_states_degrade_per_guest() {
    for_each_major(guest_scenarios).await;
}

// ---- association evidence ----

/// The association itself (MAC > address > name, first match wins) is an
/// application rule: `association_candidate` in
/// `crates/fleet-application/src/proxmox.rs`, tested by
/// `mac_evidence_outranks_address_and_name_evidence` in
/// `crates/fleet-application/tests/proxmox.rs`. The provider's half of the
/// contract is the evidence each tier consumes, decoded from the fixtures:
/// normalized MACs from the agent and the config, bare non-loopback agent
/// addresses, and the display name.
async fn association_evidence(major: Major) {
    let transport = Scripted::new();
    script_discovery(&transport, major);
    script_guests(&transport, major);
    script_down_node(&transport, major, Down::Proxy595);

    let discovery = client(&transport).guest_discover(request()).await.unwrap();

    // (guest, MAC-tier evidence, address-tier evidence, name-tier evidence)
    let tiers = discovery
        .guests
        .iter()
        .map(|guest| {
            let mut macs = guest
                .agent
                .iter()
                .flat_map(|agent| &agent.interfaces)
                .filter_map(|interface| interface.mac.clone())
                .chain(guest.macs.iter().cloned())
                .collect::<Vec<_>>();
            macs.sort();
            macs.dedup();
            let addresses = guest
                .agent
                .iter()
                .flat_map(|agent| &agent.interfaces)
                .flat_map(|interface| interface.addresses.iter().cloned())
                .collect::<Vec<_>>();
            (
                guest.resource.id.clone(),
                macs,
                addresses,
                guest.resource.name.clone(),
            )
        })
        .collect::<Vec<_>>();
    let s = |values: &[&str]| values.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>();
    let name = |value: &str| Some(value.to_owned());
    assert_eq!(
        tiers,
        [
            // All three tiers: MAC must win.
            (
                "qemu/101".to_owned(),
                s(&["bc:24:11:0a:01:01", "bc:24:11:0a:01:02"]),
                s(&[
                    "192.0.2.101",
                    "2001:db8::101",
                    "fe80::be24:11ff:fe0a:101",
                    "198.51.100.101"
                ]),
                name("web-01"),
            ),
            // Agent down: config MAC and name only.
            (
                "qemu/102".to_owned(),
                s(&["bc:24:11:0a:01:11"]),
                vec![],
                name("db-01"),
            ),
            // Forbidden: the name is the only evidence left.
            ("qemu/103".to_owned(), vec![], vec![], name("ci-01")),
            // LXC: config MAC and name.
            (
                "lxc/104".to_owned(),
                s(&["bc:24:11:0a:01:21"]),
                vec![],
                name("cache-01"),
            ),
            // Loose agent: the MACs agree across agent and config.
            (
                "qemu/106".to_owned(),
                s(&["bc:24:11:0a:01:31", "bc:24:11:0a:01:32"]),
                s(&["192.0.2.131", "203.0.113.131"]),
                name("lab-01"),
            ),
            // On the down node: no evidence at all, not even a name.
            ("qemu/105".to_owned(), vec![], vec![], None),
        ],
        "{}",
        major.dir
    );
}

#[tokio::test]
async fn association_evidence_is_decoded_per_tier() {
    for_each_major(association_evidence).await;
}

// ---- lifecycle and task polling ----

fn upid_of(major: Major, name: &str) -> Upid {
    let raw = json(major, name)["data"].as_str().unwrap().to_owned();
    Upid::parse(&raw).unwrap()
}

fn status_path(upid: &Upid) -> String {
    let encoded = upid
        .raw
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect::<String>();
    format!("/api2/json/nodes/{}/tasks/{encoded}/status", upid.node)
}

async fn lifecycle_actions(major: Major) {
    for (action, name, task_type) in [
        (LifecycleAction::Start, "status-start.json", "qmstart"),
        (LifecycleAction::Stop, "status-stop.json", "qmstop"),
        (
            LifecycleAction::Shutdown,
            "status-shutdown.json",
            "qmshutdown",
        ),
        (LifecycleAction::Reboot, "status-reboot.json", "qmreboot"),
    ] {
        let transport = Scripted::new();
        transport.post(
            format!(
                "/api2/json/nodes/{}/qemu/101/status/{}",
                major.n1,
                action.path_segment()
            ),
            200,
            fixture(major, name),
        );
        let upid = client(&transport)
            .guest_lifecycle(request(), major.n1, 101, action)
            .await
            .unwrap();
        assert_eq!(upid.node, major.n1, "{}", major.dir);
        assert_eq!(upid.task_type, task_type);
        assert_eq!(upid.target, "101");
        assert_eq!(upid.user, "fleet@pve!contract");
    }
}

#[tokio::test]
async fn lifecycle_actions_answer_parseable_upids() {
    for_each_major(lifecycle_actions).await;
}

async fn malformed_upid(major: Major) {
    let transport = Scripted::new();
    transport.post(
        format!("/api2/json/nodes/{}/qemu/101/status/start", major.n1),
        200,
        fixture(major, "malformed-upid.json"),
    );
    let error = client(&transport)
        .guest_lifecycle(request(), major.n1, 101, LifecycleAction::Start)
        .await
        .unwrap_err();
    assert!(
        matches!(error, PveApiError::InvalidPayload { .. }),
        "{}: {error:?}",
        major.dir
    );
}

#[tokio::test]
async fn a_upid_that_fails_to_parse_is_an_invalid_payload() {
    for_each_major(malformed_upid).await;
}

/// Polls the scripted status route until a terminal state, returning every
/// observed status.
async fn poll(major: Major, sequence: &[(u16, &str)]) -> Vec<TaskStatus> {
    let upid = upid_of(major, "status-start.json");
    let transport = Scripted::new();
    transport.on(
        PveHttpMethod::Get,
        status_path(&upid),
        sequence
            .iter()
            .map(|(status, name)| Reply::Http(*status, fixture(major, name).to_owned()))
            .collect(),
    );
    let client = client(&transport);
    let mut seen = Vec::new();
    for _ in 0..sequence.len() {
        let status = client.task_status(request(), &upid).await.unwrap();
        let terminal = status != TaskStatus::Running;
        seen.push(status);
        if terminal {
            break;
        }
    }
    // The node polled is the one the UPID names.
    for (_, path, _) in transport.calls() {
        assert!(path.starts_with(&format!("/api2/json/nodes/{}/tasks/", major.n1)));
    }
    seen
}

async fn task_polling(major: Major) {
    // The status bodies belong to the start task.
    let upid = upid_of(major, "status-start.json");
    for name in ["task-running.json", "task-ok.json", "task-error.json"] {
        assert_eq!(json(major, name)["data"]["upid"], upid.raw.as_str());
    }

    assert_eq!(
        poll(major, &[(200, "task-running.json"), (200, "task-ok.json")]).await,
        [TaskStatus::Running, TaskStatus::Ok],
        "{}",
        major.dir
    );
    assert_eq!(
        poll(
            major,
            &[(200, "task-running.json"), (200, "task-error.json")]
        )
        .await,
        [
            TaskStatus::Running,
            TaskStatus::Error {
                detail: "start failed: QEMU exited with code 1".to_owned()
            }
        ],
        "{}",
        major.dir
    );
    assert_eq!(
        poll(major, &[(200, "task-stopped-no-exitstatus.json")]).await,
        [TaskStatus::Unknown],
        "{}",
        major.dir
    );
    // A task the node rotated out answers 400 "no such task": unknown,
    // never an error that reads like a failed task.
    assert_eq!(
        poll(major, &[(400, "task-no-such-task.json")]).await,
        [TaskStatus::Unknown],
        "{}",
        major.dir
    );
}

#[tokio::test]
async fn task_polling_reaches_honest_terminal_states() {
    for_each_major(task_polling).await;
}

async fn task_status_other_400(major: Major) {
    // Only "no such task" means unknown; another 400 stays an error.
    let upid = upid_of(major, "status-start.json");
    let transport = Scripted::new();
    transport.get(
        status_path(&upid),
        400,
        r#"{"data":null,"errors":{"upid":"unable to parse worker upid"}}"#,
    );
    let error = client(&transport)
        .task_status(request(), &upid)
        .await
        .unwrap_err();
    assert!(
        matches!(error, PveApiError::Http { status: 400, .. }),
        "{}: {error:?}",
        major.dir
    );
}

#[tokio::test]
async fn only_no_such_task_reads_as_unknown() {
    for_each_major(task_status_other_400).await;
}

// ---- snapshot, clone, template ----

/// The snapshot, clone, and template routes for guest 101 (and the clone
/// source 9000) on the healthy node.
fn script_snapshots(transport: &Scripted, major: Major) {
    let n1 = major.n1;
    let base = format!("/api2/json/nodes/{n1}/qemu/101");
    transport
        .get(
            format!("{base}/snapshot"),
            200,
            fixture(major, "snapshot-list.json"),
        )
        .post(
            format!("{base}/snapshot"),
            200,
            fixture(major, "snapshot-create.json"),
        )
        .post(
            format!("{base}/snapshot/pre-upgrade/rollback"),
            200,
            fixture(major, "snapshot-rollback.json"),
        )
        .on(
            PveHttpMethod::Delete,
            format!("{base}/snapshot/pre-upgrade"),
            vec![Reply::Http(
                200,
                fixture(major, "snapshot-delete.json").to_owned(),
            )],
        )
        .post(
            format!("/api2/json/nodes/{n1}/qemu/9000/clone"),
            200,
            fixture(major, "clone.json"),
        )
        .post(
            format!("{base}/template"),
            200,
            fixture(major, "template.json"),
        );
}

async fn snapshot_clone_template(major: Major) {
    let n1 = major.n1;
    let base = format!("/api2/json/nodes/{n1}/qemu/101");
    let transport = Scripted::new();
    script_snapshots(&transport, major);
    let client = client(&transport);

    // The list drops the `current` marker and reads `vmstate` as RAM.
    let snapshots = client.guest_snapshots(request(), n1, 101).await.unwrap();
    let listed = snapshots
        .iter()
        .map(|snapshot| (snapshot.name.as_str(), snapshot.includes_ram))
        .collect::<Vec<_>>();
    assert_eq!(
        listed,
        [("pre-upgrade", false), ("with-ram", true)],
        "{}",
        major.dir
    );
    assert_eq!(snapshots[0].description, "before apt full-upgrade\n");

    let created = client
        .guest_snapshot(request(), n1, 101, "with-ram", "", true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(created.task_type, "qmsnapshot");
    let rolled = client
        .guest_snapshot_rollback(request(), n1, 101, "pre-upgrade")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rolled.task_type, "qmrollback");
    // PVE answers the delete with a `qmdelsnapshot` UPID on 8.x and 9.x;
    // the provider's contract is synchronous and does not poll it (a
    // follow-up, not a decoding failure).
    client
        .guest_snapshot_delete(request(), n1, 101, "pre-upgrade")
        .await
        .unwrap();
    let cloned = client
        .guest_clone(request(), n1, 9000, 120, "web-02", true)
        .await
        .unwrap();
    assert_eq!(
        (cloned.task_type.as_str(), cloned.target.as_str()),
        ("qmclone", "9000")
    );
    // Both majors fork a `qmtemplate` worker and answer its UPID.
    let template = client
        .guest_convert_template(request(), n1, 101)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(template.task_type, "qmtemplate");

    // The request bodies use PVE's parameter names.
    let bodies = transport
        .calls()
        .into_iter()
        .filter_map(|(method, path, body)| body.map(|body| (method, path, body)))
        .collect::<Vec<_>>();
    assert_eq!(
        bodies,
        [
            (
                PveHttpMethod::Post,
                format!("{base}/snapshot"),
                serde_json::json!({"snapname": "with-ram", "description": "", "vmstate": 1}),
            ),
            (
                PveHttpMethod::Post,
                format!("{base}/snapshot/pre-upgrade/rollback"),
                serde_json::json!({}),
            ),
            (
                PveHttpMethod::Post,
                format!("/api2/json/nodes/{n1}/qemu/9000/clone"),
                serde_json::json!({"newid": 120, "name": "web-02", "full": true}),
            ),
            (
                PveHttpMethod::Post,
                format!("{base}/template"),
                serde_json::json!({}),
            ),
        ],
        "{}",
        major.dir
    );
}

#[tokio::test]
async fn snapshot_clone_and_template_round_trip() {
    for_each_major(snapshot_clone_template).await;
}

// ---- fixture hygiene ----

async fn fixtures_are_synthetic(major: Major) {
    let names = [
        "cluster-resources.json",
        "cluster-status.json",
        "nodes.json",
        "agent-network.json",
        "agent-network-loose.json",
        "qemu-config-101.json",
        "lxc-config-104.json",
        "task-ok.json",
    ];
    for name in names {
        let value = json(major, name);
        let text = value.to_string();
        // No credentials of any shape.
        for needle in ["PVEAPIToken", "password", "ticket", "CSRF", TOKEN_SECRET] {
            assert!(!text.contains(needle), "{}/{name}: {needle}", major.dir);
        }
        // Only documentation, loopback, and link-local addresses.
        walk(&value, &mut |text| {
            if let Ok(ip) = text.parse::<std::net::IpAddr>() {
                let documentation = match ip {
                    std::net::IpAddr::V4(v4) => {
                        let [a, b, c, _] = v4.octets();
                        matches!((a, b, c), (192, 0, 2) | (198, 51, 100) | (203, 0, 113))
                            || v4.is_loopback()
                    }
                    std::net::IpAddr::V6(v6) => {
                        let segments = v6.segments();
                        (segments[0] == 0x2001 && segments[1] == 0x0db8)
                            || v6.is_loopback()
                            || (segments[0] & 0xffc0) == 0xfe80
                    }
                };
                assert!(documentation, "{}/{name}: {text}", major.dir);
            }
        });
    }
}

fn walk(value: &serde_json::Value, visit: &mut dyn FnMut(&str)) {
    match value {
        serde_json::Value::String(text) => visit(text),
        serde_json::Value::Array(items) => items.iter().for_each(|item| walk(item, visit)),
        serde_json::Value::Object(map) => map.values().for_each(|item| walk(item, visit)),
        _ => {}
    }
}

#[tokio::test]
async fn contract_fixtures_carry_only_synthetic_values() {
    for_each_major(fixtures_are_synthetic).await;
}
