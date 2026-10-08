//! A stateful fake Proxmox VE for the Lab failure-injection suite (FM-741).
//!
//! It speaks the provider's [`PveTransport`] contract with the response
//! shapes real PVE answers: guests, tasks, `/cluster/nextid`, and one image
//! template. Clone, start, stop, and delete change the guest table. A
//! script of [`Fault`]s replaces chosen calls with a crash (the call never
//! returns, before or after its effect lands), HTTP 403, a lost response,
//! or a task that ends in `ERROR`.
//!
//! The fake is the "outside world": it outlives every controller the suite
//! starts and kills, so a restarted controller sees exactly what the
//! interrupted one left on the host. Every name and address is reserved
//! documentation material (`example.test`, `192.0.2.0/24`).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_provider_proxmox::{
    PveHttpMethod, PveHttpRequest, PveHttpResponse, PveTransport, PveTransportError,
};

/// The account's API endpoint: never a node name.
pub const API_HOST: &str = "pve-api.example.test";
/// The node that holds the image template.
pub const TEMPLATE_NODE: &str = "pve-b";
/// The image template's VMID: the promoted build's recorded artifact.
pub const TEMPLATE_VMID: u32 = 120;
/// The lowest VMID `/cluster/nextid` answers (the Fleet `next-id` range).
pub const FIRST_LAB_VMID: u32 = 9000;
/// The pinned certificate fingerprint of the fake host.
pub const FINGERPRINT: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";

/// A call the suite can interrupt or fail. Provider calls are matched by
/// the request; the controller-side steps (`Reserved`, `MachineRegistered`,
/// `Trust`, `ProjectSetUp`, `Ready`) are raised by the suite's wrappers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    /// `GET /cluster/resources`.
    Resources,
    /// `GET /cluster/nextid`.
    NextId,
    /// `POST .../clone`.
    Clone,
    /// `POST .../status/start`.
    Start,
    /// `GET .../agent/info` or `.../agent/network-get-interfaces`.
    Agent,
    /// `POST .../status/stop`.
    Stop,
    /// `GET .../config` (the destroy's existence check).
    DestroyConfig,
    /// `DELETE .../qemu/<vmid>`.
    Delete,
    /// The clone target reservation committed.
    Reserved,
    /// The Lab machine registration committed.
    MachineRegistered,
    /// The SSH trust step.
    Trust,
    /// The bootstrap project was created and verified.
    ProjectSetUp,
    /// The readiness transaction committed.
    Ready,
    /// The sweeper's expiry step committed.
    Expired,
}

/// What happens at a scripted step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    /// The controller dies before the call has any effect.
    CrashBefore,
    /// The call's effect lands, then the controller dies before it sees the
    /// answer.
    CrashAfter,
    /// PVE refuses the call (HTTP 403); nothing changes.
    Forbidden,
    /// The effect lands but the answer is lost (a transport timeout).
    Timeout,
    /// PVE starts the task, and the task ends in `ERROR`; nothing changes.
    TaskError,
}

/// The fault script and the crash signal, shared by the fake host and the
/// controller-side wrappers.
#[derive(Debug, Default)]
pub struct Faults {
    script: Mutex<Vec<(Step, Fault, u32)>>,
    crashed: tokio::sync::Notify,
    crashes: std::sync::atomic::AtomicUsize,
}

impl Faults {
    /// Scripts `fault` for the next `times` calls of `step`.
    pub fn inject(&self, step: Step, fault: Fault, times: u32) {
        self.script.lock().unwrap().push((step, fault, times));
    }

    /// Removes every scripted fault: the host is healthy again.
    pub fn clear(&self) {
        self.script.lock().unwrap().clear();
    }

    /// Takes the fault scripted for this call of `step`, if any.
    pub fn take(&self, step: Step) -> Option<Fault> {
        let mut script = self.script.lock().unwrap();
        let index = script
            .iter()
            .position(|(scripted, _, times)| *scripted == step && *times > 0)?;
        let fault = script[index].1;
        script[index].2 -= 1;
        if script[index].2 == 0 {
            script.remove(index);
        }
        Some(fault)
    }

    /// The controller dies here: signals the suite and never returns. The
    /// suite then aborts the controller's work at this await point.
    pub async fn crash<T>(&self) -> T {
        self.crashes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.crashed.notify_one();
        std::future::pending().await
    }

    /// Waits until a crash point is reached.
    pub async fn crashed(&self) {
        self.crashed.notified().await;
    }

    /// How many crash points were reached.
    pub fn crash_count(&self) -> usize {
        self.crashes.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// One guest on the fake host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Guest {
    /// The node it lives on.
    pub node: String,
    /// Its name.
    pub name: String,
    /// Whether it is a template.
    pub template: bool,
    /// Whether it runs.
    pub running: bool,
}

#[derive(Debug, Default)]
struct State {
    guests: BTreeMap<u32, Guest>,
    /// UPID → exit status (`OK` or an `ERROR` line).
    tasks: BTreeMap<String, String>,
    next_pid: u32,
}

/// The fake host.
#[derive(Debug)]
pub struct FakePve {
    state: Mutex<State>,
    /// The fault script.
    pub faults: Arc<Faults>,
    calls: Mutex<Vec<String>>,
}

impl FakePve {
    /// A host with the two nodes and the image template.
    pub fn new(faults: Arc<Faults>) -> Arc<Self> {
        let mut state = State::default();
        state.guests.insert(
            TEMPLATE_VMID,
            Guest {
                node: TEMPLATE_NODE.to_owned(),
                name: "lab-image".to_owned(),
                template: true,
                running: false,
            },
        );
        Arc::new(Self {
            state: Mutex::new(state),
            faults,
            calls: Mutex::new(Vec::new()),
        })
    }

    /// Every guest but the image template.
    pub fn lab_guests(&self) -> BTreeMap<u32, Guest> {
        self.state
            .lock()
            .unwrap()
            .guests
            .iter()
            .filter(|(_, guest)| !guest.template)
            .map(|(vmid, guest)| (*vmid, guest.clone()))
            .collect()
    }

    /// Every request seen, as `METHOD path`.
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    /// How many requests matched `predicate`.
    pub fn count(&self, predicate: impl Fn(&str) -> bool) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| predicate(call))
            .count()
    }

    /// The transport the controller's Proxmox client speaks through.
    pub fn transport(self: &Arc<Self>) -> Arc<dyn PveTransport> {
        Arc::new(Transport(self.clone()))
    }

    fn task(state: &mut State, node: &str, kind: &str, target: u32, exit: &str) -> String {
        state.next_pid += 1;
        let upid = format!(
            "UPID:{node}:{:08X}:0C6DF532:6AAFE1EC:{kind}:{target}:fleet@pve!lab:",
            0x0015_5000 + state.next_pid
        );
        state.tasks.insert(upid.clone(), exit.to_owned());
        upid
    }

    fn ok(data: &serde_json::Value) -> Result<PveHttpResponse, PveTransportError> {
        Ok(PveHttpResponse {
            status: 200,
            body: serde_json::json!({ "data": data }).to_string().into_bytes(),
        })
    }

    fn error(status: u16, message: &str) -> Result<PveHttpResponse, PveTransportError> {
        Ok(PveHttpResponse {
            status,
            body: serde_json::json!({ "data": null, "message": message })
                .to_string()
                .into_bytes(),
        })
    }

    fn absent(node: &str, vmid: u32) -> Result<PveHttpResponse, PveTransportError> {
        Self::error(
            500,
            &format!("Configuration file 'nodes/{node}/qemu-server/{vmid}.conf' does not exist\n"),
        )
    }

    fn lost() -> Result<PveHttpResponse, PveTransportError> {
        Err(PveTransportError::Connect {
            detail: "operation timed out".to_owned(),
        })
    }

    /// Classifies a request into the step it performs.
    fn step(method: PveHttpMethod, path: &str) -> Option<Step> {
        let path = path.split('?').next().unwrap_or(path);
        match method {
            PveHttpMethod::Get if path == "/api2/json/cluster/resources" => Some(Step::Resources),
            PveHttpMethod::Get if path == "/api2/json/cluster/nextid" => Some(Step::NextId),
            PveHttpMethod::Get if path.contains("/agent/") => Some(Step::Agent),
            PveHttpMethod::Get if path.ends_with("/config") => Some(Step::DestroyConfig),
            PveHttpMethod::Post if path.ends_with("/clone") => Some(Step::Clone),
            PveHttpMethod::Post if path.ends_with("/status/start") => Some(Step::Start),
            PveHttpMethod::Post if path.ends_with("/status/stop") => Some(Step::Stop),
            PveHttpMethod::Delete => Some(Step::Delete),
            _ => None,
        }
    }

    async fn respond(
        &self,
        request: PveHttpRequest,
        body: Option<serde_json::Value>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        assert_eq!(request.host, API_HOST, "every call goes to the API host");
        assert_eq!(
            request.pinned_fingerprint.as_deref(),
            Some(FINGERPRINT),
            "no call reaches an unconfirmed host"
        );
        let method = request.method;
        let path = request.path.clone();
        self.calls
            .lock()
            .unwrap()
            .push(format!("{method:?} {path}"));
        let fault = Self::step(method, &path).and_then(|step| self.faults.take(step));
        match fault {
            Some(Fault::CrashBefore) => self.faults.crash().await,
            Some(Fault::Forbidden) => {
                return Self::error(403, "Permission check failed (injected)");
            }
            _ => {}
        }
        let answer = self.apply(method, &path, body, fault);
        match fault {
            Some(Fault::CrashAfter) => self.faults.crash().await,
            Some(Fault::Timeout) => Self::lost(),
            _ => answer,
        }
    }

    /// Applies one request to the host and answers it. A `TaskError` fault
    /// starts the task without its effect.
    #[allow(clippy::too_many_lines)]
    fn apply(
        &self,
        method: PveHttpMethod,
        path: &str,
        body: Option<serde_json::Value>,
        fault: Option<Fault>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        let failed = fault == Some(Fault::TaskError);
        let exit = if failed {
            "ERROR: injected task failure"
        } else {
            "OK"
        };
        let mut state = self.state.lock().unwrap();
        let rest = path.strip_prefix("/api2/json").unwrap_or(path);
        let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
        let segments: Vec<&str> = rest.trim_start_matches('/').split('/').collect();
        match (method, segments.as_slice()) {
            (PveHttpMethod::Get, ["version"]) => Self::ok(&serde_json::json!({"version": "9.0.3"})),
            (PveHttpMethod::Get, ["cluster", "resources"]) => {
                let mut entries = vec![
                    serde_json::json!({"id": "node/pve-a", "type": "node", "node": "pve-a", "status": "online"}),
                    serde_json::json!({"id": "node/pve-b", "type": "node", "node": "pve-b", "status": "online"}),
                ];
                for (vmid, guest) in &state.guests {
                    entries.push(serde_json::json!({
                        "id": format!("qemu/{vmid}"), "type": "qemu", "node": guest.node,
                        "vmid": vmid, "name": guest.name, "template": u8::from(guest.template),
                        "status": if guest.running { "running" } else { "stopped" },
                    }));
                }
                Self::ok(&serde_json::Value::Array(entries))
            }
            (PveHttpMethod::Get, ["cluster", "nextid"]) => {
                let next = (FIRST_LAB_VMID..)
                    .find(|vmid| !state.guests.contains_key(vmid))
                    .unwrap();
                // PVE's JSON formatter answers the integer as a string.
                Self::ok(&serde_json::Value::String(next.to_string()))
            }
            (PveHttpMethod::Post, ["nodes", node, "qemu", source, "clone"]) => {
                let source: u32 = source.parse().unwrap();
                let body = body.unwrap_or_default();
                let target = u32::try_from(body["newid"].as_u64().unwrap()).unwrap();
                let name = body["name"].as_str().unwrap_or_default().to_owned();
                if !state.guests.contains_key(&source) {
                    return Self::absent(node, source);
                }
                if state.guests.contains_key(&target) {
                    return Self::error(
                        500,
                        &format!("unable to create VM {target}: config file already exists"),
                    );
                }
                if !failed {
                    state.guests.insert(
                        target,
                        Guest {
                            node: (*node).to_owned(),
                            name,
                            template: false,
                            running: false,
                        },
                    );
                }
                let upid = Self::task(&mut state, node, "qmclone", source, exit);
                Self::ok(&serde_json::Value::String(upid))
            }
            (PveHttpMethod::Post, ["nodes", node, "qemu", vmid, "status", action]) => {
                let vmid: u32 = vmid.parse().unwrap();
                let Some(guest) = state
                    .guests
                    .get_mut(&vmid)
                    .filter(|guest| guest.node == *node)
                else {
                    return Self::absent(node, vmid);
                };
                let kind = match *action {
                    "start" => {
                        if !failed {
                            guest.running = true;
                        }
                        "qmstart"
                    }
                    "stop" => {
                        if !failed {
                            guest.running = false;
                        }
                        "qmstop"
                    }
                    other => panic!("the Lab never sends status/{other}"),
                };
                let upid = Self::task(&mut state, node, kind, vmid, exit);
                Self::ok(&serde_json::Value::String(upid))
            }
            (PveHttpMethod::Get, ["nodes", node, "qemu", vmid, "config"]) => {
                let vmid: u32 = vmid.parse().unwrap();
                match state.guests.get(&vmid).filter(|guest| guest.node == *node) {
                    Some(guest) if guest.template => {
                        Self::ok(&serde_json::json!({"name": guest.name, "template": 1}))
                    }
                    Some(guest) => Self::ok(&serde_json::json!({"name": guest.name})),
                    None => Self::absent(node, vmid),
                }
            }
            (PveHttpMethod::Delete, ["nodes", node, "qemu", vmid]) => {
                assert!(query.contains("purge=1"), "Lab cleanup purges");
                let vmid: u32 = vmid.parse().unwrap();
                let Some(guest) = state.guests.get(&vmid).filter(|guest| guest.node == *node)
                else {
                    return Self::absent(node, vmid);
                };
                assert!(
                    !guest.template,
                    "the suite's host never deletes its template"
                );
                if guest.running {
                    return Self::error(500, &format!("VM {vmid} is running - destroy failed"));
                }
                if !failed {
                    state.guests.remove(&vmid);
                }
                let upid = Self::task(&mut state, node, "qmdestroy", vmid, exit);
                Self::ok(&serde_json::Value::String(upid))
            }
            (PveHttpMethod::Get, ["nodes", _node, "tasks", upid, "status"]) => {
                let upid = percent_decode(upid);
                match state.tasks.get(&upid) {
                    Some(exit) => {
                        Self::ok(&serde_json::json!({"status": "stopped", "exitstatus": exit}))
                    }
                    None => Ok(PveHttpResponse {
                        status: 400,
                        body: serde_json::json!({"data": null, "errors": {"upid": "no such task"}})
                            .to_string()
                            .into_bytes(),
                    }),
                }
            }
            (PveHttpMethod::Get, ["nodes", node, "qemu", vmid, "agent", surface]) => {
                let vmid: u32 = vmid.parse().unwrap();
                let running = state
                    .guests
                    .get(&vmid)
                    .is_some_and(|guest| guest.node == *node && guest.running);
                if !running {
                    return Self::error(500, &format!("VM {vmid} is not running"));
                }
                match *surface {
                    "info" => Self::ok(&serde_json::json!({"result": {"version": "9.2.0"}})),
                    "network-get-interfaces" => Self::ok(&serde_json::json!({"result": [
                        {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4", "prefix": 8}]},
                        {"name": "ens18", "ip-addresses": [{"ip-address": guest_ip(vmid), "ip-address-type": "ipv4", "prefix": 24}]},
                    ]})),
                    other => Self::error(501, &format!("agent surface {other} is not faked")),
                }
            }
            (method, other) => panic!("the fake PVE does not serve {method:?} {other:?}"),
        }
    }
}

/// The guest agent's address for `vmid`: stable per guest, inside the
/// documentation range.
#[must_use]
pub fn guest_ip(vmid: u32) -> String {
    format!("192.0.2.{}", 10 + vmid % 200)
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap();
            out.push(u8::from_str_radix(hex, 16).unwrap());
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

#[derive(Debug)]
struct Transport(Arc<FakePve>);

#[async_trait]
impl PveTransport for Transport {
    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        self.0.respond(request, None).await
    }

    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        let body = serde_json::from_slice(&body).expect("the provider sends JSON bodies");
        self.0.respond(request, Some(body)).await
    }
}
