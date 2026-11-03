//! A USB-aware Proxmox VE for the Lab hardware saga tests (FM-1123): the
//! shared [`FakePve`] (guests, clone, start, stop, delete, tasks) wrapped by a
//! layer that adds what the USB mappings need: the mapping list with and
//! without `?check-node=`, the token's permissions, a guest's `usbN` entries
//! with the applied, pending-add and pending-delete views and the config
//! digest, and a script of faults for the attach and detach writes.
//!
//! Behaviour is the FM-S11 spike's (`docs/research/proxmox-usb.md`): a
//! digest-conditional `PUT …/config`, immediate hotplug when the guest's
//! `hotplug` option includes `usb` (or the guest is stopped), `pending` when
//! it does not, and `400 hotplug problem` leaving a pending entry behind.
//! Every name, VMID and address is invented; there is no real device serial.
//!
//! Included with `#[path]` next to `fake_pve.rs` (the saga tests are
//! their own crates): it is test support, not a test.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_provider_proxmox::{
    PveHttpMethod, PveHttpRequest, PveHttpResponse, PveTransport, PveTransportError,
};
use serde_json::{Value, json};

use crate::fake_pve::{FINGERPRINT, FakePve, Faults, TEMPLATE_NODE};

/// A boxed future for a fault hook.
pub type HookFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A hook a test runs at a step (cancel the operation, say).
pub type Hook = Arc<dyn Fn() -> HookFuture + Send + Sync>;

/// A request the layer can fail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsbStep {
    /// A `PUT …/config` that adds a `usbN` entry.
    Attach,
    /// A `PUT …/config` that deletes a `usbN` entry.
    Detach,
    /// `GET …/pending` (only the attach and detach calls read it).
    Pending,
    /// `GET /cluster/mapping/usb?check-node=…` (the re-observation).
    CheckNode,
}

/// What happens at a scripted step.
#[derive(Clone)]
pub enum UsbFault {
    /// The controller dies before the call has any effect.
    CrashBefore,
    /// The effect lands, then the controller dies before it sees the answer.
    CrashAfter,
    /// PVE refuses (403, `Mapping.Use`); nothing changes.
    Forbidden,
    /// PVE fails in a way that proves nothing about the write (500); nothing
    /// changes.
    ServerError,
    /// The effect lands but the answer is lost.
    Lost,
    /// A write is processed and fails to hotplug (`400 hotplug problem`),
    /// leaving its entry behind as a pending value.
    HotplugFails,
    /// Somebody else writes the guest's config first: the digest goes stale
    /// and the write is refused (`checksum mismatch`).
    DigestMismatch,
    /// An operator adds an identical entry (`mapping=<id>` in the first free
    /// slot) to the guest just before the call answers.
    ForeignEntry,
    /// Runs the hook, then lets the call through.
    Hook(Hook),
}

impl std::fmt::Debug for UsbFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::CrashBefore => "CrashBefore",
            Self::CrashAfter => "CrashAfter",
            Self::Forbidden => "Forbidden",
            Self::ServerError => "ServerError",
            Self::Lost => "Lost",
            Self::HotplugFails => "HotplugFails",
            Self::DigestMismatch => "DigestMismatch",
            Self::ForeignEntry => "ForeignEntry",
            Self::Hook(_) => "Hook",
        })
    }
}

/// One USB resource mapping.
#[derive(Clone, Debug)]
struct Mapping {
    entries: Vec<String>,
    present: bool,
}

/// One guest's `usbN` entries.
#[derive(Clone, Debug)]
struct GuestUsb {
    /// What the running guest holds.
    applied: BTreeMap<u8, String>,
    /// A restart adds these.
    pending_add: BTreeMap<u8, String>,
    /// A restart removes these.
    pending_delete: BTreeSet<u8>,
    /// Whether the guest's `hotplug` option includes `usb`.
    hotplug_usb: bool,
    /// Bumped by every write; the config digest derives from it.
    revision: u64,
}

#[derive(Debug, Default)]
struct UsbState {
    mappings: BTreeMap<String, Mapping>,
    guests: BTreeMap<u32, GuestUsb>,
    script: Vec<(UsbStep, UsbFault, u32)>,
    /// What a clone inherits from its template: `(slot, value)`.
    template_entry: Option<(u8, String)>,
    /// Every request, `METHOD path` plus the write's body for a `PUT`.
    log: Vec<String>,
    /// The effects of writes that landed: `attach usb0=mapping=x`,
    /// `detach usb0`.
    writes: Vec<String>,
    /// Whether the node's USB inventory is readable (it needs `Sys.Modify`).
    permissions_read: bool,
}

/// The USB-aware host.
#[derive(Debug)]
pub struct UsbHost {
    inner: Arc<FakePve>,
    transport: Arc<dyn PveTransport>,
    faults: Arc<Faults>,
    state: Mutex<UsbState>,
}

impl UsbHost {
    /// Wraps the fake host.
    pub fn new(pve: Arc<FakePve>) -> Arc<Self> {
        let faults = pve.faults.clone();
        let transport = pve.transport();
        Arc::new(Self {
            inner: pve,
            transport,
            faults,
            state: Mutex::new(UsbState {
                permissions_read: true,
                ..UsbState::default()
            }),
        })
    }

    /// The transport the controller speaks through.
    pub fn transport(self: &Arc<Self>) -> Arc<dyn PveTransport> {
        Arc::new(Layer(self.clone()))
    }

    /// Defines a mapping (`node=pve-b,id=aaaa:0001,path=1-1`, say), present.
    pub fn add_mapping(&self, id: &str, entries: &[&str]) {
        self.state.lock().unwrap().mappings.insert(
            id.to_owned(),
            Mapping {
                entries: entries.iter().map(|entry| (*entry).to_owned()).collect(),
                present: true,
            },
        );
    }

    /// Plugs or unplugs the device behind a mapping.
    pub fn set_present(&self, id: &str, present: bool) {
        self.state
            .lock()
            .unwrap()
            .mappings
            .get_mut(id)
            .expect("a defined mapping")
            .present = present;
    }

    /// Replaces a mapping's entries (an operator moved the cable).
    pub fn set_entries(&self, id: &str, entries: &[&str]) {
        self.state
            .lock()
            .unwrap()
            .mappings
            .get_mut(id)
            .expect("a defined mapping")
            .entries = entries.iter().map(|entry| (*entry).to_owned()).collect();
    }

    /// Scripts `fault` for the next `times` requests of `step`.
    pub fn inject(&self, step: UsbStep, fault: UsbFault, times: u32) {
        self.state.lock().unwrap().script.push((step, fault, times));
    }

    /// Removes every scripted fault.
    pub fn clear(&self) {
        self.state.lock().unwrap().script.clear();
    }

    /// Every clone made after this carries `slot=value` (the template holds
    /// a device entry it must not).
    pub fn template_carries(&self, slot: u8, value: &str) {
        self.state.lock().unwrap().template_entry = Some((slot, value.to_owned()));
    }

    /// An operator's own entry on a guest (applied at once).
    pub fn set_slot(&self, vmid: u32, slot: u8, value: &str) {
        let mut state = self.state.lock().unwrap();
        Self::guest_in(&mut state, vmid)
            .applied
            .insert(slot, value.to_owned());
        Self::guest_in(&mut state, vmid).revision += 1;
    }

    /// The guest's `hotplug` option includes `usb` (the default) or not.
    pub fn set_hotplug_usb(&self, vmid: u32, enabled: bool) {
        let mut state = self.state.lock().unwrap();
        Self::guest_in(&mut state, vmid).hotplug_usb = enabled;
    }

    /// A restart of the guest applies what is pending.
    pub fn apply_pending(&self, vmid: u32) {
        let mut state = self.state.lock().unwrap();
        let guest = Self::guest_in(&mut state, vmid);
        for slot in std::mem::take(&mut guest.pending_delete) {
            guest.applied.remove(&slot);
        }
        let added = std::mem::take(&mut guest.pending_add);
        guest.applied.extend(added);
        guest.revision += 1;
    }

    /// What `GET …/config` shows for the guest's `usbN` entries: the stored
    /// view, with pending changes folded in.
    pub fn stored(&self, vmid: u32) -> BTreeMap<u8, String> {
        let mut state = self.state.lock().unwrap();
        Self::stored_of(Self::guest_in(&mut state, vmid))
    }

    /// What the running guest holds.
    pub fn applied(&self, vmid: u32) -> BTreeMap<u8, String> {
        let mut state = self.state.lock().unwrap();
        Self::guest_in(&mut state, vmid).applied.clone()
    }

    /// Every request, in order.
    pub fn log(&self) -> Vec<String> {
        self.state.lock().unwrap().log.clone()
    }

    /// The effects of the writes that landed, in order.
    pub fn writes(&self) -> Vec<String> {
        self.state.lock().unwrap().writes.clone()
    }

    /// How many logged requests satisfy `predicate`.
    pub fn count(&self, predicate: impl Fn(&str) -> bool) -> usize {
        self.state
            .lock()
            .unwrap()
            .log
            .iter()
            .filter(|line| predicate(line))
            .count()
    }

    /// The position of the first logged request satisfying `predicate`.
    pub fn first(&self, predicate: impl Fn(&str) -> bool) -> Option<usize> {
        self.state
            .lock()
            .unwrap()
            .log
            .iter()
            .position(|line| predicate(line))
    }

    /// Creates a guest on the template's node the way a clone does (a pool
    /// member, say).
    pub async fn create_guest(&self, vmid: u32, name: &str) {
        let request = PveHttpRequest {
            host: crate::fake_pve::API_HOST.to_owned(),
            port: 8006,
            path: format!(
                "/api2/json/nodes/{TEMPLATE_NODE}/qemu/{}/clone",
                crate::fake_pve::TEMPLATE_VMID
            ),
            pinned_fingerprint: Some(FINGERPRINT.to_owned()),
            credentials: Arc::new(fleet_provider_proxmox::PveCredentials {
                token_id: "fleet@pve!lab".to_owned(),
                token: fleet_core::SensitiveString::new("fake-token-material"),
            }),
            method: PveHttpMethod::Post,
        };
        let body = json!({"newid": vmid, "name": name})
            .to_string()
            .into_bytes();
        self.transport
            .execute_with_body(request, body)
            .await
            .expect("the fake clones");
    }

    fn guest_in(state: &mut UsbState, vmid: u32) -> &mut GuestUsb {
        let inherited = state.template_entry.clone();
        state.guests.entry(vmid).or_insert_with(|| GuestUsb {
            applied: inherited.into_iter().collect(),
            pending_add: BTreeMap::new(),
            pending_delete: BTreeSet::new(),
            hotplug_usb: true,
            revision: 1,
        })
    }

    fn stored_of(guest: &GuestUsb) -> BTreeMap<u8, String> {
        let mut stored = guest.applied.clone();
        for slot in &guest.pending_delete {
            stored.remove(slot);
        }
        stored.extend(guest.pending_add.clone());
        stored
    }

    fn digest(vmid: u32, guest: &GuestUsb) -> String {
        format!("{vmid:04x}{:036x}", guest.revision)
    }

    fn take_fault(&self, step: UsbStep) -> Option<UsbFault> {
        let mut state = self.state.lock().unwrap();
        let index = state
            .script
            .iter()
            .position(|(scripted, _, times)| *scripted == step && *times > 0)?;
        let fault = state.script[index].1.clone();
        state.script[index].2 -= 1;
        if state.script[index].2 == 0 {
            state.script.remove(index);
        }
        Some(fault)
    }

    fn ok(data: &Value) -> Result<PveHttpResponse, PveTransportError> {
        Ok(PveHttpResponse {
            status: 200,
            body: json!({ "data": data }).to_string().into_bytes(),
        })
    }

    fn error(status: u16, body: &Value) -> Result<PveHttpResponse, PveTransportError> {
        Ok(PveHttpResponse {
            status,
            body: body.to_string().into_bytes(),
        })
    }

    fn lost() -> Result<PveHttpResponse, PveTransportError> {
        Err(PveTransportError::Connect {
            detail: "operation timed out".to_owned(),
        })
    }

    fn guest_exists(&self, node: &str, vmid: u32) -> Option<crate::fake_pve::Guest> {
        self.inner
            .lab_guests()
            .get(&vmid)
            .filter(|guest| guest.node == node)
            .cloned()
    }

    fn absent(node: &str, vmid: u32) -> Result<PveHttpResponse, PveTransportError> {
        Self::error(
            500,
            &json!({
                "data": null,
                "message": format!(
                    "Configuration file 'nodes/{node}/qemu-server/{vmid}.conf' does not exist\n"
                )
            }),
        )
    }

    fn mapping_list(&self, check_node: Option<&str>) -> Value {
        let state = self.state.lock().unwrap();
        let rows: Vec<Value> = state
            .mappings
            .iter()
            .map(|(id, mapping)| {
                let mut row = json!({
                    "id": id, "type": "usb", "description": "Test device",
                    "digest": "0000000000000000000000000000000000000000",
                    "map": mapping.entries,
                });
                if let Some(node) = check_node {
                    let has_entry = mapping
                        .entries
                        .iter()
                        .any(|entry| entry.starts_with(&format!("node={node},")));
                    row["errors"] = if !has_entry {
                        json!([{"message": format!("No mapping for node {node}."), "severity": "warning"}])
                    } else if mapping.present {
                        json!([])
                    } else {
                        json!([{
                            "message": "Invalid configuration: usb device '1-1' not found\n",
                            "severity": "error"
                        }])
                    };
                }
                row
            })
            .collect();
        Value::Array(rows)
    }

    /// Serves the requests only this layer knows; `None` passes it on.
    #[allow(clippy::too_many_lines)]
    async fn serve(
        &self,
        request: &PveHttpRequest,
        body: Option<&Value>,
    ) -> Option<Result<PveHttpResponse, PveTransportError>> {
        let method = request.method;
        let (path, query) = request
            .path
            .split_once('?')
            .unwrap_or((request.path.as_str(), ""));
        let rest = path.strip_prefix("/api2/json")?;
        let segments: Vec<&str> = rest.trim_start_matches('/').split('/').collect();
        let line = match body {
            Some(body) => format!("{method:?} {} {body}", request.path),
            None => format!("{method:?} {}", request.path),
        };
        match (method, segments.as_slice()) {
            (PveHttpMethod::Get, ["cluster", "mapping", "usb"]) => {
                self.record(line);
                self.assert_pinned(request);
                let check_node = query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix("check-node="));
                if check_node.is_some()
                    && let Some(response) = self.fault(UsbStep::CheckNode, true).await
                {
                    return Some(response);
                }
                Some(Self::ok(&self.mapping_list(check_node)))
            }
            (PveHttpMethod::Get, ["access", "permissions"]) => {
                self.record(line);
                self.assert_pinned(request);
                Some(Self::ok(&json!({
                    "/mapping/usb": {"Mapping.Audit": 1, "Mapping.Use": 1},
                    "/vms": {"VM.Audit": 1, "VM.Config.HWType": 1}
                })))
            }
            (PveHttpMethod::Get, ["nodes", _node, "hardware", "usb"]) => {
                self.record(line);
                self.assert_pinned(request);
                Some(Self::error(
                    403,
                    &json!({"data": null, "message": "Permission check failed (/, Sys.Modify)\n"}),
                ))
            }
            (PveHttpMethod::Get, ["nodes", node, "qemu", vmid, "pending"]) => {
                self.record(line);
                self.assert_pinned(request);
                let vmid: u32 = vmid.parse().unwrap();
                if self.guest_exists(node, vmid).is_none() {
                    return Some(Self::absent(node, vmid));
                }
                if let Some(response) = self.fault(UsbStep::Pending, false).await {
                    return Some(response);
                }
                let mut state = self.state.lock().unwrap();
                let guest = Self::guest_in(&mut state, vmid);
                let mut entries = Vec::new();
                for (slot, value) in &guest.applied {
                    let mut entry = json!({"key": format!("usb{slot}"), "value": value});
                    if guest.pending_delete.contains(slot) {
                        entry["delete"] = json!(1);
                    }
                    entries.push(entry);
                }
                for (slot, value) in &guest.pending_add {
                    entries.push(json!({"key": format!("usb{slot}"), "pending": value}));
                }
                entries.push(json!({"key": "digest", "value": Self::digest(vmid, guest)}));
                Some(Self::ok(&Value::Array(entries)))
            }
            (PveHttpMethod::Get, ["nodes", node, "qemu", vmid, "config"]) => {
                self.record(line);
                let vmid: u32 = vmid.parse().unwrap();
                // The fake host answers (and may fault) first.
                let answer = self.transport.execute(request.clone()).await;
                let Ok(response) = answer else {
                    return Some(answer);
                };
                if response.status != 200 {
                    return Some(Ok(response));
                }
                let Some(guest) = self.guest_exists(node, vmid) else {
                    // The image template (the fake keeps it apart from the
                    // clones): it carries the device entry when a test says so.
                    let template_entry = self.state.lock().unwrap().template_entry.clone();
                    let (true, Some((slot, value))) =
                        (vmid == crate::fake_pve::TEMPLATE_VMID, template_entry)
                    else {
                        return Some(Ok(response));
                    };
                    let mut parsed: Value = serde_json::from_slice(&response.body).ok()?;
                    parsed
                        .get_mut("data")?
                        .as_object_mut()?
                        .insert(format!("usb{slot}"), json!(value));
                    return Some(Ok(PveHttpResponse {
                        status: 200,
                        body: parsed.to_string().into_bytes(),
                    }));
                };
                let _ = guest;
                let mut parsed: Value = serde_json::from_slice(&response.body).ok()?;
                let current = query.split('&').any(|pair| pair == "current=1");
                let mut state = self.state.lock().unwrap();
                let usb = Self::guest_in(&mut state, vmid);
                let view = if current {
                    usb.applied.clone()
                } else {
                    Self::stored_of(usb)
                };
                let data = parsed.get_mut("data")?.as_object_mut()?;
                for (slot, value) in view {
                    data.insert(format!("usb{slot}"), json!(value));
                }
                data.insert("digest".to_owned(), json!(Self::digest(vmid, usb)));
                Some(Ok(PveHttpResponse {
                    status: 200,
                    body: parsed.to_string().into_bytes(),
                }))
            }
            (PveHttpMethod::Put, ["nodes", node, "qemu", vmid, "config"]) => {
                self.record(line);
                self.assert_pinned(request);
                let vmid: u32 = vmid.parse().unwrap();
                Some(self.put_config(node, vmid, body?).await)
            }
            (PveHttpMethod::Delete, ["nodes", _node, "qemu", vmid]) => {
                self.record(line);
                let vmid: u32 = vmid.parse().unwrap();
                let answer = self.transport.execute(request.clone()).await;
                if matches!(&answer, Ok(response) if response.status == 200) {
                    self.state.lock().unwrap().guests.remove(&vmid);
                }
                Some(answer)
            }
            _ => {
                self.record(line);
                None
            }
        }
    }

    fn record(&self, line: String) {
        self.state.lock().unwrap().log.push(line);
    }

    fn assert_pinned(&self, request: &PveHttpRequest) {
        assert_eq!(
            request.pinned_fingerprint.as_deref(),
            Some(FINGERPRINT),
            "no call reaches an unconfirmed host"
        );
    }

    /// Applies a request-level fault. `before_only` faults are the ones that
    /// make sense for a read.
    async fn fault(
        &self,
        step: UsbStep,
        read: bool,
    ) -> Option<Result<PveHttpResponse, PveTransportError>> {
        let fault = self.take_fault(step)?;
        match fault {
            UsbFault::Hook(hook) => {
                hook().await;
                None
            }
            UsbFault::CrashBefore => self.faults.crash().await,
            UsbFault::Forbidden => Some(Self::error(
                403,
                &json!({"data": null, "message": "Permission check failed (/mapping/usb/x, Mapping.Use)\n"}),
            )),
            UsbFault::ServerError => Some(Self::error(
                500,
                &json!({"data": null, "message": "internal error (injected)"}),
            )),
            UsbFault::ForeignEntry if !read => {
                let mut state = self.state.lock().unwrap();
                let mapping = state.mappings.keys().next().cloned().unwrap_or_default();
                let vmid = *state.guests.keys().next_back().unwrap_or(&0);
                let guest = Self::guest_in(&mut state, vmid);
                let slot = (0..5)
                    .find(|slot| !guest.applied.contains_key(slot))
                    .unwrap();
                guest.applied.insert(slot, format!("mapping={mapping}"));
                guest.revision += 1;
                None
            }
            // The write faults are applied in `put_config`.
            _ => None,
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn put_config(
        &self,
        node: &str,
        vmid: u32,
        body: &Value,
    ) -> Result<PveHttpResponse, PveTransportError> {
        let Some(guest) = self.guest_exists(node, vmid) else {
            return Self::absent(node, vmid);
        };
        let deleting = body.get("delete").is_some();
        let step = if deleting {
            UsbStep::Detach
        } else {
            UsbStep::Attach
        };
        let fault = self.take_fault(step);
        let mut after_crash = false;
        let mut lost = false;
        let mut hotplug_fails = false;
        match &fault {
            Some(UsbFault::CrashBefore) => self.faults.crash::<()>().await,
            Some(UsbFault::Forbidden) => {
                return Self::error(
                    403,
                    &json!({"data": null, "message": "Permission check failed (/mapping/usb/x, Mapping.Use)\n"}),
                );
            }
            Some(UsbFault::ServerError) => {
                return Self::error(
                    500,
                    &json!({"data": null, "message": "internal error (injected)"}),
                );
            }
            Some(UsbFault::DigestMismatch) => {
                let mut state = self.state.lock().unwrap();
                Self::guest_in(&mut state, vmid).revision += 1;
                drop(state);
                return Self::error(
                    500,
                    &json!({"data": null, "message": "checksum mismatch (file change by other user?)"}),
                );
            }
            Some(UsbFault::Hook(hook)) => hook().await,
            Some(UsbFault::CrashAfter) => after_crash = true,
            Some(UsbFault::Lost) => lost = true,
            Some(UsbFault::HotplugFails) => hotplug_fails = true,
            Some(UsbFault::ForeignEntry) | None => {}
        }
        if let Some(answer) = self.write_config(vmid, guest.running, body, hotplug_fails) {
            return answer;
        }
        if after_crash {
            self.faults.crash::<()>().await;
        }
        if lost {
            return Self::lost();
        }
        Self::ok(&Value::Null)
    }

    /// Applies one write to the guest's entries; `Some` is the answer of a
    /// write that was refused or failed, `None` a write that landed.
    fn write_config(
        &self,
        vmid: u32,
        running: bool,
        body: &Value,
        hotplug_fails: bool,
    ) -> Option<Result<PveHttpResponse, PveTransportError>> {
        let mut state = self.state.lock().unwrap();
        let usb = Self::guest_in(&mut state, vmid);
        if body["digest"].as_str() != Some(Self::digest(vmid, usb).as_str()) {
            return Some(Self::error(
                500,
                &json!({"data": null, "message": "checksum mismatch (file change by other user?)"}),
            ));
        }
        let pending_only = running && !usb.hotplug_usb;
        let effect;
        if let Some(slot) = body.get("delete").and_then(Value::as_str) {
            let index: u8 = slot.trim_start_matches("usb").parse().unwrap();
            if pending_only && usb.applied.contains_key(&index) {
                usb.pending_delete.insert(index);
            } else {
                usb.applied.remove(&index);
                usb.pending_add.remove(&index);
                usb.pending_delete.remove(&index);
            }
            effect = format!("detach {slot}");
        } else {
            let (slot, value) = body
                .as_object()
                .unwrap()
                .iter()
                .find(|(key, _)| key.starts_with("usb"))
                .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_owned()))
                .expect("an attach carries a usbN value");
            let index: u8 = slot.trim_start_matches("usb").parse().unwrap();
            if hotplug_fails {
                usb.pending_add.insert(index, value.clone());
                usb.revision += 1;
                state
                    .writes
                    .push(format!("attach {slot}={value} (hotplug failed)"));
                return Some(Self::error(
                    400,
                    &json!({
                        "errors": {slot: "hotplug problem - USB Mapping invalid (hardware probably changed): usb device '1-1' not found"},
                        "message": "Parameter verification failed."
                    }),
                ));
            }
            if pending_only {
                usb.pending_add.insert(index, value.clone());
            } else {
                usb.applied.insert(index, value.clone());
            }
            effect = format!("attach {slot}={value}");
        }
        usb.revision += 1;
        state.writes.push(effect);
        None
    }
}

/// The transport the controller speaks through.
#[derive(Debug)]
struct Layer(Arc<UsbHost>);

#[async_trait]
impl PveTransport for Layer {
    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        match self.0.serve(&request, None).await {
            Some(answer) => answer,
            None => self.0.transport.execute(request).await,
        }
    }

    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        let parsed: Value = serde_json::from_slice(&body).expect("the provider sends JSON bodies");
        match self.0.serve(&request, Some(&parsed)).await {
            Some(answer) => answer,
            None => self.0.transport.execute_with_body(request, body).await,
        }
    }
}
