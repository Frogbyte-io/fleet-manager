//! Issue #220: the Lab provision executor clones the pinned image's
//! template on the node that holds it, into a VMID reserved and recorded
//! before the clone, and never falls back to a hard-coded source or the
//! template's own VMID. The cleanup guard refuses templates and image
//! artifacts. Real SQLite repositories and a real worker; a scripted PVE
//! transport that records every request.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::authz::{AccessRequest, Authorizer, Decision};
use fleet_application::lab::{
    CloneTargetReservation, ImageArtifactPort, LabTemplate, LabTemplatePort, LabTemplateVersion,
    LeasePort, NewLabTemplate, NewLease, NewProvision, ProvisionPort, ProvisionRecord,
};
use fleet_application::lab_placement::{
    CapacityReservationPort, ImageStoragePort, PlacementPolicy, ReservationState,
};
use fleet_application::operation::{NewOperation, Operations};
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccountPort, ProxmoxCredentialStore,
};
use fleet_core::{CleanupStrategy, GuestState, LabTemplateContent, ReadinessProbe};
use fleet_provider_proxmox::{
    ProxmoxClient, PveHttpMethod, PveHttpRequest, PveHttpResponse, PveTransport, PveTransportError,
};
use fleet_storage_sqlite::{
    AuditSink, CapacityRepository, LabRepository, LeaseRepository, OperationRepository,
    ProxmoxAccountRepository, Store,
};

const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";
/// The account's API host: deliberately not a node name.
const API_HOST: &str = "pve-api.example.test";
/// FM-715: a second trusted account's API host that never answers.
const UNREACHABLE_HOST: &str = "pve-unreachable.example.test";
/// The node that holds the image template.
const TEMPLATE_NODE: &str = "pve-b";
/// The image template's VMID (the recorded build artifact).
const TEMPLATE_VMID: u32 = 120;
/// Another recorded image artifact that is no longer a template.
const OTHER_ARTIFACT_VMID: u32 = 130;
/// A promoted image's recorded template that no longer exists.
const GONE_ARTIFACT_VMID: u32 = 140;
/// What `/cluster/nextid` answers.
const NEXT_VMID: u32 = 9000;
/// The UPID PVE answers for the clone: `qmclone` carries the *source*.
const CLONE_UPID: &str = "UPID:pve-b:0015523F:0C6DF532:6AAFE1EC:qmclone:120:fleet@pve!lab:";
const START_UPID: &str = "UPID:pve-b:00155300:0C6DF600:6AAFE1F0:qmstart:9000:fleet@pve!lab:";

/// One request the transport saw.
#[derive(Clone, Debug)]
struct Seen {
    path: String,
    method: PveHttpMethod,
    body: Option<serde_json::Value>,
    /// The record's stored (node, VMID) when a clone or start request
    /// arrived.
    stored_target: Option<(Option<String>, Option<u32>)>,
}

#[derive(Debug)]
struct Pve {
    /// Extra guests in `/cluster/resources`, beside the node and template.
    guests: Vec<serde_json::Value>,
    clone_upid: String,
    /// What `/cluster/nextid` answers.
    next_vmid: u32,
    seen: Mutex<Vec<Seen>>,
    /// The repository and record whose target the clone request observes.
    observe: Mutex<Option<(Arc<LabRepository>, String)>>,
    ready_ip: bool,
    /// The clone's config: whether it carries the inherited `protection`
    /// flag (cleared by a PUT), how many more reads still report the
    /// clone lock, and the name the clone request gave it.
    clone_config: Mutex<CloneConfig>,
    /// FM-715: the free memory (GiB of 32) node status reports, when the
    /// capacity endpoints answer at all.
    capacity: Mutex<Option<u64>>,
    /// FM-715: the lease whose reservation state is recorded when the
    /// `nextid` and clone requests arrive.
    watch_reservation: Mutex<Option<(sqlx::SqlitePool, String)>>,
    /// The (path, reservation held?) pairs those requests saw.
    held_at: Mutex<Vec<(String, bool)>>,
    /// #310: the clone task's scripted status answers, one per poll; the
    /// last one repeats. Empty: the node answers nothing for the task.
    clone_task: Mutex<Vec<&'static str>>,
}

#[derive(Debug, Default)]
struct CloneConfig {
    protected: bool,
    refuse_unprotect: bool,
    locked_reads: usize,
    missing_reads: usize,
    /// Reads that fail with a transient 503.
    flaky_reads: usize,
    forbid_read: bool,
    no_digest: bool,
    stale_puts: usize,
    update_status: Option<u16>,
    cloned: Option<(u32, String)>,
    /// The settled config answers this name instead of the requested one.
    foreign_name: Option<String>,
    /// The settled config carries `template: 1`.
    as_template: bool,
    /// #372: the clone's hardware as the image template left it. `None`
    /// means the template's own (2 cores, 2048 MiB, 20 GiB).
    hardware: Option<Hardware>,
    /// The clone's memory is a property string with a maximum.
    memory_options: bool,
    /// The config names no boot disk.
    no_boot_disk: bool,
    /// The config states no size for its boot disk.
    no_disk_size: bool,
    /// PVE answers every cores/memory update with this status.
    set_status: Option<u16>,
    /// PVE answers every resize with this status.
    resize_status: Option<u16>,
    /// A resize is accepted but changes nothing.
    resize_ignored: bool,
    /// The digest every write must carry; each write moves it on.
    digest_moves: u32,
    /// Writes PVE accepted: `(kind, body)`.
    writes: Vec<(String, serde_json::Value)>,
}

/// The hardware the suite's template asks for (`Harness` publishes 2 cores,
/// 2048 MiB, and a 20 GiB disk): a clone that has it needs no update.
const TEMPLATE_HARDWARE: Hardware = Hardware {
    cores: 2,
    memory_mib: 2048,
    disk_gib: 20,
};

impl CloneConfig {
    /// The digest the config answers and every write must carry.
    fn digest(&self) -> String {
        if self.digest_moves == 0 {
            "0123abcd".to_owned()
        } else {
            format!("0123abcd{}", self.digest_moves)
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Hardware {
    cores: u32,
    memory_mib: u32,
    disk_gib: u32,
}

impl Pve {
    fn new(guests: Vec<serde_json::Value>) -> Arc<Self> {
        Self::scripted(guests, CLONE_UPID, NEXT_VMID)
    }

    fn with_clone_upid(guests: Vec<serde_json::Value>, upid: &str) -> Arc<Self> {
        Self::scripted(guests, upid, NEXT_VMID)
    }

    fn scripted(guests: Vec<serde_json::Value>, upid: &str, next_vmid: u32) -> Arc<Self> {
        Arc::new(Self {
            guests,
            clone_upid: upid.to_owned(),
            next_vmid,
            seen: Mutex::new(Vec::new()),
            observe: Mutex::new(None),
            ready_ip: false,
            clone_config: Mutex::new(CloneConfig::default()),
            capacity: Mutex::new(None),
            watch_reservation: Mutex::new(None),
            held_at: Mutex::new(Vec::new()),
            clone_task: Mutex::new(Vec::new()),
        })
    }

    /// The template is protected, so its clone inherits the flag.
    fn protected(self: Arc<Self>) -> Arc<Self> {
        self.clone_config.lock().unwrap().protected = true;
        self
    }

    /// The token lacks `VM.Config.Options` on the clone target.
    fn refusing_unprotect(self: Arc<Self>) -> Arc<Self> {
        self.clone_config.lock().unwrap().refuse_unprotect = true;
        self
    }

    /// The clone's config does not exist yet for this many reads (PVE
    /// writes it inside the forked qmclone worker).
    fn missing_for(self: Arc<Self>, reads: usize) -> Arc<Self> {
        self.clone_config.lock().unwrap().missing_reads = reads;
        self
    }

    /// The config read fails with a transient 503 this many times.
    fn flaky_for(self: Arc<Self>, reads: usize) -> Arc<Self> {
        self.clone_config.lock().unwrap().flaky_reads = reads;
        self
    }

    /// The clone task's status answers (`running`, `ok`, `error`,
    /// `unknown`), one per poll; the last repeats.
    fn clone_task(self: Arc<Self>, answers: &[&'static str]) -> Arc<Self> {
        *self.clone_task.lock().unwrap() = answers.to_vec();
        self
    }

    fn task_polls(&self) -> usize {
        self.seen()
            .iter()
            .filter(|seen| seen.path.contains("/tasks/") && seen.path.ends_with("/status"))
            .count()
    }

    fn config_reads(&self) -> usize {
        self.seen()
            .iter()
            .filter(|seen| seen.path == CLONE_CONFIG && seen.method == PveHttpMethod::Get)
            .count()
    }

    fn task_answer(&self) -> Option<String> {
        let mut script = self.clone_task.lock().unwrap();
        let next = if script.len() > 1 {
            script.remove(0)
        } else {
            *script.first()?
        };
        Some(match next {
            "running" => r#"{"data":{"status":"running"}}"#.to_owned(),
            "ok" => r#"{"data":{"status":"stopped","exitstatus":"OK"}}"#.to_owned(),
            "error" => {
                r#"{"data":{"status":"stopped","exitstatus":"ERROR: storage full"}}"#.to_owned()
            }
            _ => r#"{"data":null}"#.to_owned(),
        })
    }

    /// PVE answers every update with this HTTP status.
    fn update_status(self: Arc<Self>, status: u16) -> Arc<Self> {
        self.clone_config.lock().unwrap().update_status = Some(status);
        self
    }

    /// PVE refuses this many digest-bound updates as stale.
    fn stale_for(self: Arc<Self>, puts: usize) -> Arc<Self> {
        self.clone_config.lock().unwrap().stale_puts = puts;
        self
    }

    /// The clone's config carries no digest.
    fn without_digest(self: Arc<Self>) -> Arc<Self> {
        self.clone_config.lock().unwrap().no_digest = true;
        self
    }

    /// The token lacks `VM.Audit` on the clone target.
    fn forbidding_config_reads(self: Arc<Self>) -> Arc<Self> {
        self.clone_config.lock().unwrap().forbid_read = true;
        self
    }

    /// The settled config names another guest than the one requested.
    fn named(self: Arc<Self>, name: &str) -> Arc<Self> {
        self.clone_config.lock().unwrap().foreign_name = Some(name.to_owned());
        self
    }

    /// The settled config is a template's.
    fn as_template(self: Arc<Self>) -> Arc<Self> {
        self.clone_config.lock().unwrap().as_template = true;
        self
    }

    /// #372: the clone keeps this hardware from the image template.
    fn imaged(self: Arc<Self>, cores: u32, memory_mib: u32, disk_gib: u32) -> Arc<Self> {
        self.clone_config.lock().unwrap().hardware = Some(Hardware {
            cores,
            memory_mib,
            disk_gib,
        });
        self
    }

    fn configure(self: Arc<Self>, change: impl FnOnce(&mut CloneConfig)) -> Arc<Self> {
        change(&mut self.clone_config.lock().unwrap());
        self
    }

    /// The hardware writes PVE accepted.
    fn hardware_writes(&self) -> Vec<(String, serde_json::Value)> {
        self.clone_config.lock().unwrap().writes.clone()
    }

    /// The clone's config stays locked for this many reads.
    fn locked_for(self: Arc<Self>, reads: usize) -> Arc<Self> {
        self.clone_config.lock().unwrap().locked_reads = reads;
        self
    }

    /// The config updates (PUTs) PVE received, with their bodies.
    fn config_updates(&self) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|seen| seen.method == PveHttpMethod::Put)
            .collect()
    }

    /// `PUT …/config` with cores and/or memory (#372).
    fn hardware_update(
        config: &mut CloneConfig,
        vmid: u32,
        body: &serde_json::Value,
    ) -> (u16, String) {
        for key in body.as_object().unwrap().keys() {
            assert!(
                ["cores", "memory", "digest"].contains(&key.as_str()),
                "only cores and memory are set: {body}"
            );
        }
        if body["digest"] != config.digest().as_str() {
            return (
                500,
                r#"{"data":null,"message":"checksum mismatch (file change by other user?)\n"}"#
                    .to_owned(),
            );
        }
        if let Some(status) = config.set_status {
            return (
                status,
                format!(
                    r#"{{"data":null,"message":"Permission check failed (/vms/{vmid}, VM.Config.CPU)\n"}}"#
                ),
            );
        }
        let mut hardware = config.hardware.unwrap_or(TEMPLATE_HARDWARE);
        if let Some(cores) = body.get("cores") {
            hardware.cores = u32::try_from(cores.as_u64().unwrap()).unwrap();
        }
        if let Some(memory) = body.get("memory") {
            hardware.memory_mib = u32::try_from(memory.as_u64().unwrap()).unwrap();
        }
        config.hardware = Some(hardware);
        config.digest_moves += 1;
        config.writes.push(("config".to_owned(), body.clone()));
        (200, r#"{"data":null}"#.to_owned())
    }

    /// `PUT …/resize` (#372).
    fn resize(&self, vmid: u32, body: &serde_json::Value) -> (u16, String) {
        let mut config = self.clone_config.lock().unwrap();
        assert_eq!(body["disk"], "scsi0", "{body}");
        if body["digest"] != config.digest().as_str() {
            return (
                500,
                r#"{"data":null,"message":"checksum mismatch (file change by other user?)\n"}"#
                    .to_owned(),
            );
        }
        if let Some(status) = config.resize_status {
            return (
                status,
                format!(
                    r#"{{"data":null,"message":"Permission check failed (/vms/{vmid}, VM.Config.Disk)\n"}}"#
                ),
            );
        }
        let gib: u32 = body["size"]
            .as_str()
            .and_then(|size| size.strip_suffix('G'))
            .and_then(|size| size.parse().ok())
            .expect("an absolute size in GiB");
        let mut hardware = config.hardware.unwrap_or(TEMPLATE_HARDWARE);
        assert!(gib >= hardware.disk_gib, "PVE refuses to shrink a disk");
        if !config.resize_ignored {
            hardware.disk_gib = gib;
            config.hardware = Some(hardware);
        }
        config.digest_moves += 1;
        config.writes.push(("resize".to_owned(), body.clone()));
        (200, r#"{"data":null}"#.to_owned())
    }

    /// `GET`/`PUT …/qemu/{vmid}/config`: the scripted clone config.
    fn config(
        &self,
        vmid: u32,
        method: PveHttpMethod,
        body: Option<&serde_json::Value>,
    ) -> (u16, String) {
        assert_ne!(
            vmid, TEMPLATE_VMID,
            "the template's config is never read or changed"
        );
        let mut config = self.clone_config.lock().unwrap();
        if method == PveHttpMethod::Put && body.is_some_and(|body| body.get("protection").is_none())
        {
            return Self::hardware_update(&mut config, vmid, body.unwrap());
        }
        if method == PveHttpMethod::Put {
            let body = body.expect("a config update carries a body");
            assert_eq!(
                body["protection"], 0,
                "only the protection flag is cleared: {body}"
            );
            assert_eq!(
                body["digest"], "0123abcd",
                "the update is conditional: {body}"
            );
            assert_eq!(body.as_object().unwrap().len(), 2, "{body}");
            if config.refuse_unprotect {
                return (
                    403,
                    format!(
                        r#"{{"data":null,"message":"Permission check failed (/vms/{vmid}, VM.Config.Options)\n"}}"#
                    ),
                );
            }
            if let Some(status) = config.update_status {
                return (status, r#"{"data":null}"#.to_owned());
            }
            if config.stale_puts > 0 {
                config.stale_puts -= 1;
                return (
                    500,
                    r#"{"data":null,"message":"checksum mismatch (file change by other user?)\n"}"#
                        .to_owned(),
                );
            }
            config.protected = false;
            config.digest_moves += 1;
            return (200, r#"{"data":null}"#.to_owned());
        }
        if config.forbid_read {
            return (
                403,
                format!(
                    r#"{{"data":null,"message":"Permission check failed (/vms/{vmid}, VM.Audit)\n"}}"#
                ),
            );
        }
        if config.flaky_reads > 0 {
            config.flaky_reads -= 1;
            return (503, r#"{"data":null,"message":"unavailable"}"#.to_owned());
        }
        if config.missing_reads > 0 {
            config.missing_reads -= 1;
            return (
                500,
                format!(
                    r#"{{"data":null,"message":"Configuration file 'nodes/{TEMPLATE_NODE}/qemu-server/{vmid}.conf' does not exist\n"}}"#
                ),
            );
        }
        let listed = self
            .guests
            .iter()
            .find(|guest| guest["vmid"] == vmid)
            .and_then(|guest| guest["name"].as_str().map(str::to_owned));
        let cloned = config
            .cloned
            .as_ref()
            .filter(|(id, _)| *id == vmid)
            .map(|(_, name)| name.clone());
        let Some(name) = listed.or(cloned) else {
            return (
                500,
                format!(
                    r#"{{"data":null,"message":"Configuration file 'nodes/{TEMPLATE_NODE}/qemu-server/{vmid}.conf' does not exist\n"}}"#
                ),
            );
        };
        if config.locked_reads > 0 {
            config.locked_reads -= 1;
            // While PVE clones, the target's config holds the lock (and,
            // between disks, the name).
            return (
                200,
                format!(r#"{{"data":{{"lock":"clone","name":"{name}","digest":"0000"}}}}"#),
            );
        }
        let name = config.foreign_name.clone().unwrap_or(name);
        let hardware = config.hardware.unwrap_or(TEMPLATE_HARDWARE);
        let mut answer = serde_json::json!({
            "name": name, "cores": hardware.cores, "digest": config.digest(),
            "memory": if config.memory_options {
                format!("current={},max=65536", hardware.memory_mib)
            } else {
                hardware.memory_mib.to_string()
            },
        });
        if !config.no_boot_disk {
            let size = if config.no_disk_size {
                String::new()
            } else {
                format!(",size={}G", hardware.disk_gib)
            };
            answer["scsi0"] = serde_json::json!(format!("local-lvm:vm-{vmid}-disk-0{size}"));
            answer["boot"] = serde_json::json!("order=scsi0;net0");
        }
        if config.protected {
            answer["protection"] = serde_json::json!(1);
        }
        if config.no_digest {
            answer.as_object_mut().unwrap().remove("digest");
        }
        if config.as_template {
            answer["template"] = serde_json::json!(1);
        }
        (200, serde_json::json!({ "data": answer }).to_string())
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn paths(&self) -> Vec<String> {
        self.seen().into_iter().map(|seen| seen.path).collect()
    }

    fn clones(&self) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|seen| seen.path.ends_with("/clone"))
            .collect()
    }

    fn resources(&self) -> String {
        let mut entries = vec![
            serde_json::json!({"id": "node/pve-a", "type": "node", "node": "pve-a"}),
            serde_json::json!({"id": "node/pve-b", "type": "node", "node": "pve-b"}),
            serde_json::json!({
                "id": format!("qemu/{TEMPLATE_VMID}"), "type": "qemu", "node": TEMPLATE_NODE,
                "vmid": TEMPLATE_VMID, "name": "ubuntu-base", "template": 1
            }),
            serde_json::json!({
                "id": format!("qemu/{OTHER_ARTIFACT_VMID}"), "type": "qemu", "node": "pve-a",
                "vmid": OTHER_ARTIFACT_VMID, "name": "converted-back", "template": 0
            }),
        ];
        entries.extend(self.guests.iter().cloned());
        serde_json::json!({ "data": entries }).to_string()
    }
}

#[derive(Debug)]
struct Transport(Arc<Pve>);

#[async_trait]
impl PveTransport for Transport {
    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        self.respond(request, Some(serde_json::from_slice(&body).unwrap()))
            .await
    }

    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        self.respond(request, None).await
    }
}

impl Transport {
    /// FM-715: the node status and storage endpoints, when scripted.
    fn capacity_answer(&self, path: &str) -> Option<String> {
        let free_gib = (*self.0.capacity.lock().unwrap())?;
        let node = path.strip_prefix("/api2/json/nodes/")?;
        let gib: u64 = 1 << 30;
        if node
            .strip_suffix("/status")
            .is_some_and(|node| !node.contains('/'))
        {
            return Some(
                serde_json::json!({"data": {
                    "cpu": 0.1, "cpuinfo": {"cpus": 8},
                    "memory": {"total": 32 * gib, "used": (32 - free_gib) * gib}
                }})
                .to_string(),
            );
        }
        if node
            .strip_suffix("/storage")
            .is_some_and(|node| !node.contains('/'))
        {
            return Some(
                serde_json::json!({"data": [
                    {"storage": "local-lvm", "used": 0, "total": 500 * gib}
                ]})
                .to_string(),
            );
        }
        None
    }

    async fn respond(
        &self,
        request: PveHttpRequest,
        body: Option<serde_json::Value>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        if request.host == UNREACHABLE_HOST {
            return Err(PveTransportError::Connect {
                detail: "unreachable".to_owned(),
            });
        }
        assert_eq!(request.host, API_HOST, "every call goes to the API host");
        let path = request.path.clone();
        let stored_target = if path.ends_with("/clone") || path.ends_with("/status/start") {
            let observe = self.0.observe.lock().unwrap().clone();
            match observe {
                Some((labs, record_id)) => {
                    let record = ProvisionPort::get(labs.as_ref(), &record_id).await.unwrap();
                    Some((record.node, record.vmid))
                }
                None => None,
            }
        } else {
            None
        };
        if path.ends_with("/clone")
            && let Some(body) = &body
        {
            self.0.clone_config.lock().unwrap().cloned = Some((
                u32::try_from(body["newid"].as_u64().unwrap()).unwrap(),
                body["name"].as_str().unwrap().to_owned(),
            ));
        }
        if path == "/api2/json/cluster/nextid" || path.ends_with("/clone") {
            let watch = self.0.watch_reservation.lock().unwrap().clone();
            if let Some((pool, lease_id)) = watch {
                let held = CapacityRepository::new(pool)
                    .for_lease(&lease_id)
                    .await
                    .unwrap()
                    .is_some_and(|reservation| reservation.state == ReservationState::Held);
                self.0.held_at.lock().unwrap().push((path.clone(), held));
            }
        }
        self.0.seen.lock().unwrap().push(Seen {
            path: path.clone(),
            method: request.method,
            body: body.clone(),
            stored_target,
        });
        if let Some(vmid) = path
            .strip_suffix("/resize")
            .and_then(|rest| rest.rsplit_once("/qemu/"))
            .and_then(|(_, vmid)| vmid.parse::<u32>().ok())
        {
            let (status, answer) = self.0.resize(vmid, body.as_ref().expect("a resize body"));
            return Ok(PveHttpResponse {
                status,
                body: answer.into_bytes(),
            });
        }
        if let Some(vmid) = path
            .strip_suffix("/config")
            .and_then(|rest| rest.rsplit_once("/qemu/"))
            .and_then(|(_, vmid)| vmid.parse::<u32>().ok())
        {
            let (status, answer) = self.0.config(vmid, request.method, body.as_ref());
            return Ok(PveHttpResponse {
                status,
                body: answer.into_bytes(),
            });
        }
        let task_status = path.contains("/tasks/") && path.ends_with("/status");
        let answer = if task_status && let Some(answer) = self.0.task_answer() {
            answer
        } else if path == "/api2/json/version" {
            r#"{"data":{"version":"9.0.3"}}"#.to_owned()
        } else if path == "/api2/json/cluster/resources" {
            self.0.resources()
        } else if let Some(answer) = self.capacity_answer(&path) {
            answer
        } else if path == "/api2/json/cluster/nextid" {
            // PVE's JSON formatter answers the integer as a string.
            format!(r#"{{"data":"{}"}}"#, self.0.next_vmid)
        } else if path.ends_with("/clone") {
            format!(r#"{{"data":"{}"}}"#, self.0.clone_upid)
        } else if path.ends_with("/status/start") {
            format!(r#"{{"data":"{START_UPID}"}}"#)
        } else if self.0.ready_ip && path.ends_with("/agent/info") {
            r#"{"data":{"result":{"version":"9"}}}"#.to_owned()
        } else if self.0.ready_ip && path.ends_with("/agent/network-get-interfaces") {
            r#"{"data":{"result":[{"name":"ens18","ip-addresses":[{"ip-address":"192.0.2.42","ip-address-type":"ipv4","prefix":24}]}]}}"#.to_owned()
        } else {
            // The agent probe: refused, so the zero readiness deadline
            // ends the saga as never_ready right after the start.
            return Err(PveTransportError::Connect {
                detail: format!("unexpected path {path}"),
            });
        };
        Ok(PveHttpResponse {
            status: 200,
            body: answer.into_bytes(),
        })
    }
}

#[derive(Debug)]
struct OneSecret;

#[async_trait]
impl ProxmoxCredentialStore for OneSecret {
    async fn load(&self, _account_id: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(Some("the-token-secret-material".to_owned()))
    }
    async fn store(&self, _account_id: &str, _secret: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("the executor never stores credentials")
    }
    async fn clear(&self, _account_id: &str) -> Result<(), CredentialStoreError> {
        unimplemented!("the executor never clears credentials")
    }
}

/// The recorded build artifacts.
#[derive(Debug)]
struct Artifacts {
    pinned: Option<u32>,
}

#[async_trait]
impl ImageArtifactPort for Artifacts {
    async fn template_vmid(&self, image_version_id: &str) -> Result<Option<u32>, String> {
        assert_eq!(image_version_id, "image-version-1");
        Ok(self.pinned)
    }
    async fn promoted_template_vmids(&self) -> Result<Vec<u32>, String> {
        Ok(vec![TEMPLATE_VMID, OTHER_ARTIFACT_VMID, GONE_ARTIFACT_VMID])
    }
}

/// FM-715: every pinned image's template disk lives on `local-lvm`.
#[derive(Debug)]
struct LocalLvm;

/// An image whose storage pool Fleet does not know.
#[derive(Debug)]
struct NoStorage;

#[async_trait]
impl ImageStoragePort for NoStorage {
    async fn template_storage(&self, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
}

#[async_trait]
impl ImageStoragePort for LocalLvm {
    async fn template_storage(&self, _: &str) -> Result<Option<String>, String> {
        Ok(Some("local-lvm".to_owned()))
    }
}

#[derive(Debug)]
struct AllowAll;

impl Authorizer for AllowAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    labs: Arc<LabRepository>,
    leases: Arc<LeaseRepository>,
    accounts: Arc<ProxmoxAccountRepository>,
    operations: Arc<Operations>,
    account_id: String,
    version_id: String,
    pool: sqlx::SqlitePool,
}

impl Harness {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        let now = fleet_core::SystemClock::now_unix_millis();
        let accounts = Arc::new(ProxmoxAccountRepository::new(pool.clone()));
        let account = accounts
            .create(&NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: API_HOST.to_owned(),
                port: None,
                token_id: "fleet@pve!lab".to_owned(),
            })
            .await
            .unwrap();
        accounts
            .set_fingerprint(&account.id, Some(FP.to_owned()))
            .await
            .unwrap();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let leases = Arc::new(LeaseRepository::new(pool.clone()));
        let content = LabTemplateContent {
            name: "lab-base".to_owned(),
            description: "the lab base".to_owned(),
            image_version_id: "image-version-1".to_owned(),
            cores: 2,
            memory_mib: 2048,
            disk_gib: 20,
            bootstrap_project_id: None,
            readiness_probe: ReadinessProbe::GuestAgent,
            readiness_command: None,
            ssh_user: "root".to_owned(),
            ssh_port: 22,
            ssh_trust_mode: "tofu".to_owned(),
            ssh_fingerprint: None,
            readiness_deadline_seconds: 0,
            ttl_seconds: 3_600,
            cleanup: CleanupStrategy::Destroy,
        };
        let template: LabTemplate = LabTemplatePort::create(
            labs.as_ref(),
            &NewLabTemplate {
                content: content.clone(),
            },
            now,
        )
        .await
        .unwrap();
        let version = labs
            .publish(
                &template.id,
                &LabTemplateVersion {
                    id: "template-version-1".to_owned(),
                    template_id: template.id.clone(),
                    name: content.name.clone(),
                    content,
                    image_digest: "sha256:abc".to_owned(),
                    published_by: "tester".to_owned(),
                    published_at: now,
                },
            )
            .await
            .unwrap();
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            Arc::new(AuditSink::new(pool.clone())),
        ));
        Self {
            _dir: dir,
            labs,
            leases,
            accounts,
            operations,
            account_id: account.id,
            version_id: version.id,
            pool,
        }
    }

    /// A requested lease with its linked, freshly created record.
    async fn record(&self) -> (String, ProvisionRecord) {
        let now = fleet_core::SystemClock::now_unix_millis();
        let lease = self
            .leases
            .create(
                &NewLease {
                    template_version_id: self.version_id.clone(),
                    purpose: "clone target".to_owned(),
                    project_id: None,
                    cleanup: CleanupStrategy::Destroy,
                    ttl_seconds: 3_600,
                },
                "tester",
                now,
            )
            .await
            .unwrap();
        let record = ProvisionPort::create(
            self.labs.as_ref(),
            &NewProvision {
                template_version_id: self.version_id.clone(),
                lease_id: Some(lease.id.clone()),
                idempotency_key: None,
                readiness_deadline_at: None,
            },
            now,
        )
        .await
        .unwrap();
        self.leases
            .attach_provision(&lease.id, &record.id)
            .await
            .unwrap();
        (lease.id, record)
    }

    fn executor(
        &self,
        pve: &Arc<Pve>,
        pinned: Option<u32>,
    ) -> fleet_controller::proxmox_exec::ProvisionExecutor {
        fleet_controller::proxmox_exec::ProvisionExecutor::new(
            self.accounts.clone(),
            Arc::new(OneSecret),
            self.labs.clone(),
            self.leases.clone(),
            self.labs.clone(),
            Arc::new(Artifacts { pinned }),
            ProxmoxClient::new(Arc::new(Transport(pve.clone()))),
        )
    }

    /// Runs one `lab.provision` operation to its terminal state; returns
    /// the state, the error's reason and detail, and the stored record.
    async fn run(
        &self,
        pve: &Arc<Pve>,
        pinned: Option<u32>,
        lease_id: &str,
        record_id: &str,
    ) -> (String, Option<(String, String)>, ProvisionRecord) {
        self.run_executor(pve, self.executor(pve, pinned), lease_id, record_id)
            .await
    }

    async fn run_executor(
        &self,
        pve: &Arc<Pve>,
        executor: fleet_controller::proxmox_exec::ProvisionExecutor,
        lease_id: &str,
        record_id: &str,
    ) -> (String, Option<(String, String)>, ProvisionRecord) {
        let account = self.account_id.clone();
        self.run_with_account(pve, executor, lease_id, record_id, Some(&account))
            .await
    }

    /// How many audit intents carry `event` in their metadata. The
    /// operation's completion appends an outcome row to its latest intent,
    /// so outcome rows are not counted.
    async fn audit_events(&self, event: &str) -> usize {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE outcome IS NULL AND metadata_json LIKE ?1",
        )
        .bind(format!("%\"{event}\"%"))
        .fetch_one(&self.pool)
        .await
        .unwrap();
        usize::try_from(count).unwrap()
    }

    /// FM-715: the executor with placement enabled over the real capacity
    /// repository.
    fn placed_executor(
        &self,
        pve: &Arc<Pve>,
        policy: PlacementPolicy,
    ) -> fleet_controller::proxmox_exec::ProvisionExecutor {
        self.executor(pve, Some(TEMPLATE_VMID)).with_placement(
            Arc::new(CapacityRepository::new(self.pool.clone())),
            Arc::new(LocalLvm),
            Arc::new(AuditSink::new(self.pool.clone())),
            policy,
        )
    }

    async fn run_with_account(
        &self,
        pve: &Arc<Pve>,
        executor: fleet_controller::proxmox_exec::ProvisionExecutor,
        lease_id: &str,
        record_id: &str,
        account: Option<&str>,
    ) -> (String, Option<(String, String)>, ProvisionRecord) {
        *pve.observe.lock().unwrap() = Some((self.labs.clone(), record_id.to_owned()));
        let mut payload = serde_json::json!({ "recordId": record_id, "leaseId": lease_id });
        if let Some(account) = account {
            payload["accountId"] = serde_json::Value::String(account.to_owned());
        }
        let operation = self
            .operations
            .create_lab_provision(
                &AllowAll,
                "tester",
                lease_id,
                &NewOperation {
                    kind: "lab.provision".to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(payload.to_string()),
                    review_token: None,
                },
            )
            .await
            .unwrap();
        let worker = fleet_controller::worker::WorkerHost::new(
            self.operations.clone(),
            Arc::new(fleet_controller::proxmox_exec::LabDispatch::new(
                Arc::new(fleet_application::worker::NoopExecutor),
                Arc::new(executor),
            )),
            2,
        );
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let running = tokio::spawn(async move {
            worker
                .run(async {
                    let _ = stopped.await;
                })
                .await;
        });
        let mut state = String::new();
        for _ in 0..200 {
            state = self.operations.get_state(&operation.id).await.unwrap();
            if matches!(state.as_str(), "succeeded" | "failed" | "cancelled") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let _ = stop.send(());
        tokio::time::timeout(std::time::Duration::from_secs(10), running)
            .await
            .expect("the worker stops within its bound")
            .expect("the worker task does not panic");
        assert!(
            matches!(state.as_str(), "succeeded" | "failed" | "cancelled"),
            "the operation never reached a terminal state: {state}"
        );
        let finished = self
            .operations
            .get(&AllowAll, "tester", &operation.id)
            .await
            .unwrap();
        let error = finished.error_json.as_deref().map(|error| {
            let error: serde_json::Value = serde_json::from_str(error).unwrap();
            (
                error["reason"].as_str().unwrap_or_default().to_owned(),
                error["detail"].as_str().unwrap_or_default().to_owned(),
            )
        });
        let record = ProvisionPort::get(self.labs.as_ref(), record_id)
            .await
            .unwrap();
        (state, error, record)
    }
}

fn guest(vmid: u32, name: &str) -> serde_json::Value {
    serde_json::json!({
        "id": format!("qemu/{vmid}"), "type": "qemu", "node": TEMPLATE_NODE,
        "vmid": vmid, "name": name, "template": 0
    })
}

#[tokio::test]
async fn the_clone_targets_the_template_node_and_a_reserved_vmid() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());

    let (state, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    // The guest never answers the agent probe: a recorded never_ready.
    assert_eq!(state, "failed");
    assert_eq!(error.unwrap().0, "never_ready");
    let clones = pve.clones();
    assert_eq!(clones.len(), 1, "{:?}", pve.paths());
    let clone = &clones[0];
    // The exact node, source, newid, and name sent to PVE.
    assert_eq!(
        clone.path,
        format!("/api2/json/nodes/{TEMPLATE_NODE}/qemu/{TEMPLATE_VMID}/clone")
    );
    assert_eq!(
        clone.body,
        Some(serde_json::json!({
            "newid": NEXT_VMID,
            "name": format!("fm-lab-{}", record.id),
            "full": true,
        }))
    );
    // The target was reserved and persisted before the clone call.
    assert_eq!(
        clone.stored_target,
        Some((Some(TEMPLATE_NODE.to_owned()), Some(NEXT_VMID)))
    );
    let paths = pve.paths();
    let nextid = paths
        .iter()
        .position(|path| path == "/api2/json/cluster/nextid")
        .expect("the VMID comes from /cluster/nextid");
    let cloned = paths
        .iter()
        .position(|path| path.ends_with("/clone"))
        .unwrap();
    assert!(nextid < cloned, "{paths:?}");
    // The start goes to the reserved guest on the template's node.
    assert!(
        paths.contains(&format!(
            "/api2/json/nodes/{TEMPLATE_NODE}/qemu/{NEXT_VMID}/status/start"
        )),
        "{paths:?}"
    );
    assert!(
        paths.iter().all(|path| !path.contains(API_HOST)),
        "the account host is never a node: {paths:?}"
    );
    // The record keeps the reserved target, never the template's VMID.
    assert_eq!(stored.state, GuestState::NeverReady);
    assert_eq!(stored.node.as_deref(), Some(TEMPLATE_NODE));
    assert_eq!(stored.vmid, Some(NEXT_VMID));
    assert_eq!(stored.clone_upid.as_deref(), Some(CLONE_UPID));
}

#[tokio::test]
async fn a_rerun_resumes_with_the_reserved_vmid() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    // A previous run reserved 9005 and stopped before its clone.
    let reserved = harness
        .labs
        .reserve_clone_target(&record.id, TEMPLATE_NODE, 9005)
        .await
        .unwrap();
    assert!(matches!(reserved, CloneTargetReservation::Reserved(_)));
    let pve = Pve::new(Vec::new());

    let (_, _, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    let paths = pve.paths();
    assert!(
        !paths.contains(&"/api2/json/cluster/nextid".to_owned()),
        "a reservation is reused, not replaced: {paths:?}"
    );
    let clones = pve.clones();
    assert_eq!(clones.len(), 1, "{paths:?}");
    assert_eq!(clones[0].body.as_ref().unwrap()["newid"], 9005);
    assert_eq!(stored.vmid, Some(9005));
    assert_eq!(stored.clone_upid.as_deref(), Some(CLONE_UPID));
}

#[tokio::test]
async fn a_rerun_after_the_clone_started_does_not_clone_again() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());
    harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    // Simulate an interruption after the clone was recorded: the record is
    // back in `provisioning` with its target and clone UPID stored.
    let mut resumable = ProvisionPort::get(harness.labs.as_ref(), &record.id)
        .await
        .unwrap();
    // The simulated interruption precedes terminal readiness failure on
    // both rows; an actual failed lease is intentionally not resumable.
    let mut resumable_lease = harness.leases.get(&lease_id).await.unwrap();
    resumable_lease.state = fleet_core::LeaseState::Provisioning;
    harness.leases.update(&resumable_lease).await.unwrap();
    reopen(&harness, &record.id).await;
    resumable.failed_step = None;
    resumable.state = GuestState::Provisioning;
    ProvisionPort::update(harness.labs.as_ref(), &resumable)
        .await
        .unwrap();
    let second = Pve::new(vec![guest(NEXT_VMID, &format!("fm-lab-{}", record.id))]);

    let (_, _, stored) = harness
        .run(&second, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert!(second.clones().is_empty(), "{:?}", second.paths());
    assert!(
        second.paths().contains(&format!(
            "/api2/json/nodes/{TEMPLATE_NODE}/qemu/{NEXT_VMID}/status/start"
        )),
        "{:?}",
        second.paths()
    );
    assert_eq!(stored.vmid, Some(NEXT_VMID));
}

#[tokio::test]
async fn a_reserved_target_that_already_holds_our_clone_is_adopted() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    harness
        .labs
        .reserve_clone_target(&record.id, TEMPLATE_NODE, 9005)
        .await
        .unwrap();
    // The clone landed but the UPID was never recorded.
    let pve = Pve::new(vec![guest(9005, &format!("fm-lab-{}", record.id))]);

    let (_, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert!(pve.clones().is_empty(), "{:?}", pve.paths());
    assert_eq!(error.unwrap().0, "never_ready");
    assert!(pve.paths().contains(&format!(
        "/api2/json/nodes/{TEMPLATE_NODE}/qemu/9005/status/start"
    )));
    assert_eq!(stored.vmid, Some(9005));
}

#[tokio::test]
async fn a_foreign_guest_at_the_reserved_target_is_a_conflict() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    harness
        .labs
        .reserve_clone_target(&record.id, TEMPLATE_NODE, 9005)
        .await
        .unwrap();
    let pve = Pve::new(vec![guest(9005, "someone-elses-vm")]);

    let (state, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "conflict");
    assert!(detail.contains("9005"), "{detail}");
    assert!(pve.clones().is_empty());
    assert!(
        !pve.paths()
            .iter()
            .any(|path| path.ends_with("/status/start"))
    );
    // The reservation is kept, never silently swapped.
    assert_eq!(stored.vmid, Some(9005));
    assert_eq!(stored.clone_upid, None);
}

#[tokio::test]
async fn a_vmid_held_by_another_in_flight_record_is_a_conflict() {
    let harness = Harness::new().await;
    let (_, other) = harness.record().await;
    harness
        .labs
        .reserve_clone_target(&other.id, TEMPLATE_NODE, NEXT_VMID)
        .await
        .unwrap();
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());

    let (state, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "conflict");
    assert!(detail.contains(&other.id), "{detail}");
    assert!(pve.clones().is_empty());
    assert_eq!(stored.vmid, None);
}

#[tokio::test]
async fn a_missing_artifact_is_an_honest_failure() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());

    let (state, error, stored) = harness.run(&pve, None, &lease_id, &record.id).await;

    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "artifact_missing");
    assert!(detail.contains("image-version-1"), "{detail}");
    // Nothing was read or cloned: no fallback source exists.
    assert!(pve.paths().is_empty(), "{:?}", pve.paths());
    assert_eq!((stored.node, stored.vmid), (None, None));
}

#[tokio::test]
async fn an_artifact_that_is_not_a_template_is_refused() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());

    let (state, error, _) = harness
        .run(&pve, Some(OTHER_ARTIFACT_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(state, "failed");
    assert_eq!(error.unwrap().0, "template_missing");
    assert!(pve.clones().is_empty());

    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());
    let (_, error, _) = harness.run(&pve, Some(777), &lease_id, &record.id).await;
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "template_missing");
    assert!(detail.contains("VM.Audit"), "{detail}");
    assert!(pve.clones().is_empty());
}

#[tokio::test]
async fn a_clone_task_that_does_not_match_the_request_is_an_error() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    // A task for the target instead of the source: not what PVE forks for
    // the requested clone.
    let pve = Pve::with_clone_upid(
        Vec::new(),
        "UPID:pve-b:0015523F:0C6DF532:6AAFE1EC:qmclone:9000:fleet@pve!lab:",
    );

    let (state, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert_eq!(state, "failed");
    assert_eq!(error.unwrap().0, "task_mismatch");
    assert!(
        !pve.paths()
            .iter()
            .any(|path| path.ends_with("/status/start"))
    );
    // The recorded VMID is the reserved target, never parsed from the task.
    assert_eq!(stored.vmid, Some(NEXT_VMID));
    assert_eq!(stored.clone_upid, None);
}

/// A record whose clone was recorded, ready to be resumed.
async fn cloned_record(harness: &Harness) -> (String, ProvisionRecord) {
    let (lease_id, record) = harness.record().await;
    let mut cloned = record.clone();
    cloned.node = Some(TEMPLATE_NODE.to_owned());
    cloned.vmid = Some(NEXT_VMID);
    cloned.clone_upid = Some(CLONE_UPID.to_owned());
    ProvisionPort::update(harness.labs.as_ref(), &cloned)
        .await
        .unwrap();
    (lease_id, cloned)
}

#[tokio::test]
async fn a_resumed_guest_is_revalidated_before_it_is_started() {
    let harness = Harness::new().await;
    let starts = |pve: &Pve| {
        pve.paths()
            .iter()
            .filter(|path| path.ends_with("/status/start"))
            .count()
    };

    // The recorded guest is gone.
    let (lease_id, record) = cloned_record(&harness).await;
    let pve = Pve::new(Vec::new());
    let (state, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(state, "failed");
    assert_eq!(error.unwrap().0, "target_missing");
    assert_eq!(starts(&pve), 0);

    // The VMID was reused by someone else's guest.
    let (lease_id, record) = cloned_record(&harness).await;
    let pve = Pve::new(vec![guest(NEXT_VMID, "someone-elses-vm")]);
    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "conflict");
    assert!(detail.contains("someone-elses-vm"), "{detail}");
    assert_eq!(starts(&pve), 0);

    // PVE names a clone only when it finishes: unverifiable, not started.
    let (lease_id, record) = cloned_record(&harness).await;
    let pve = Pve::new(vec![serde_json::json!({
        "id": format!("qemu/{NEXT_VMID}"), "type": "qemu", "node": TEMPLATE_NODE,
        "vmid": NEXT_VMID, "template": 0
    })]);
    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "target_unverified");
    assert_eq!(starts(&pve), 0);

    // Live PVE reports an unnamed guest as `VM <vmid>`: the same case, not
    // a conflict.
    let (lease_id, record) = cloned_record(&harness).await;
    let pve = Pve::new(vec![guest(NEXT_VMID, &format!("VM {NEXT_VMID}"))]);
    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "target_unverified");
    assert_eq!(starts(&pve), 0);
}

#[tokio::test]
async fn a_resumed_guest_that_moved_is_recorded_on_its_live_node() {
    let harness = Harness::new().await;
    let (lease_id, record) = cloned_record(&harness).await;
    let mut moved = guest(NEXT_VMID, &format!("fm-lab-{}", record.id));
    moved["node"] = serde_json::json!("pve-c");
    let pve = Pve::new(vec![moved]);

    let (_, _, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert!(
        pve.paths().contains(&format!(
            "/api2/json/nodes/pve-c/qemu/{NEXT_VMID}/status/start"
        )),
        "{:?}",
        pve.paths()
    );
    // Recorded before the start, so a run that stops before readiness
    // still leaves cleanup the live node.
    let start = pve
        .seen()
        .into_iter()
        .find(|seen| seen.path.ends_with("/status/start"))
        .unwrap();
    assert_eq!(
        start.stored_target,
        Some((Some("pve-c".to_owned()), Some(NEXT_VMID)))
    );
    assert_eq!(stored.node.as_deref(), Some("pve-c"));
}

#[tokio::test]
async fn a_promoted_artifact_vmid_is_never_reserved() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    // A promoted artifact is gone from the cluster, so nextid hands its
    // VMID out again.
    let pve = Pve::scripted(Vec::new(), CLONE_UPID, GONE_ARTIFACT_VMID);

    let (state, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "conflict");
    assert!(detail.contains(&GONE_ARTIFACT_VMID.to_string()), "{detail}");
    assert!(pve.clones().is_empty());
    assert_eq!(stored.vmid, None);
}

#[tokio::test]
async fn a_record_that_names_the_template_is_never_started() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    // What the pre-#220 source fallback recorded.
    let mut legacy = record.clone();
    legacy.node = Some(TEMPLATE_NODE.to_owned());
    legacy.vmid = Some(TEMPLATE_VMID);
    legacy.clone_upid = Some(CLONE_UPID.to_owned());
    ProvisionPort::update(harness.labs.as_ref(), &legacy)
        .await
        .unwrap();
    let pve = Pve::new(Vec::new());

    let (state, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert_eq!(state, "failed");
    assert_eq!(error.unwrap().0, "protected_target");
    assert!(
        !pve.paths()
            .iter()
            .any(|path| path.ends_with("/status/start") || path.ends_with("/clone")),
        "{:?}",
        pve.paths()
    );
}

#[tokio::test]
async fn the_cleanup_guard_refuses_templates_and_image_artifacts() {
    let harness = Harness::new().await;
    let pve = Pve::new(vec![guest(NEXT_VMID, "fm-lab-a-lease")]);
    let executor = harness.executor(&pve, Some(TEMPLATE_VMID));

    let refusal = executor
        .guard_destroy_target(&harness.account_id, TEMPLATE_VMID)
        .await
        .unwrap_err();
    assert!(refusal.contains("is a template"), "{refusal}");
    let refusal = executor
        .guard_destroy_target(&harness.account_id, OTHER_ARTIFACT_VMID)
        .await
        .unwrap_err();
    assert!(refusal.contains("build artifact"), "{refusal}");
    executor
        .guard_destroy_target(&harness.account_id, NEXT_VMID)
        .await
        .expect("a Lab clone may be destroyed");
}

#[derive(Debug)]
struct ReadyPorts {
    labs: Arc<LabRepository>,
    fail: Option<&'static str>,
    calls: Mutex<Vec<&'static str>>,
}

#[async_trait]
impl fleet_application::lab::LabReadinessPort for ReadyPorts {
    async fn trust(
        &self,
        record: &ProvisionRecord,
        _content: &LabTemplateContent,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        self.calls.lock().unwrap().push("trust");
        let stored = ProvisionPort::get(self.labs.as_ref(), &record.id)
            .await
            .unwrap();
        assert_eq!(stored.state, GuestState::Bootstrapping);
        assert!(stored.machine_id.is_some());
        if self.fail == Some("trust") {
            Err("unsafe provider diagnostic".to_owned())
        } else {
            Ok(true)
        }
    }
    async fn ssh_probe(
        &self,
        _operations: &Operations,
        _parent_id: &str,
        _record: &ProvisionRecord,
        command: &str,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        self.calls.lock().unwrap().push("ssh");
        assert_eq!(command, "test -f /tmp/ready");
        if self.fail == Some("ssh") {
            Err("unsafe SSH diagnostic".to_owned())
        } else {
            Ok(true)
        }
    }
    async fn create_project(
        &self,
        operations: &Operations,
        _parent_id: &str,
        record: &ProvisionRecord,
        project_id: &str,
        _remaining: std::time::Duration,
    ) -> Result<String, String> {
        self.calls.lock().unwrap().push("create_project");
        assert_eq!(project_id, "project-1");
        if self.fail == Some("project") {
            return Err("unsafe project diagnostic".to_owned());
        }
        let child = operations.create(&AllowAll, "tester", &NewOperation {
            kind: "ready.workflow".to_owned(), idempotency_key: Some(format!("lab-ready:{}", record.id)),
            deadline_at: record.readiness_deadline_at, correlation_id: Some(record.id.clone()), review_token: None,
            payload_json: Some(serde_json::json!({"machineId": record.machine_id, "endpointId": record.endpoint_id, "auth":{"type":"agent"}, "remote":"example.org/demo", "root":"/tmp/demo", "timeoutSeconds":30}).to_string()),
        }).await.map_err(|error| error.to_string())?;
        Ok(child.id)
    }
    async fn project_verified(
        &self,
        operations: &Operations,
        child_id: &str,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        self.calls.lock().unwrap().push("verify");
        let provisions = ProvisionPort::list(self.labs.as_ref()).await.unwrap();
        assert!(
            provisions
                .iter()
                .any(|record| record.ready_project_operation_id.as_deref() == Some(child_id)),
            "child identity must be committed before execution"
        );
        if self.fail == Some("verify") {
            return Err("unsafe verify diagnostic".to_owned());
        }
        if operations.get_state(child_id).await.unwrap() == "pending" {
            operations
                .claim_only_execute(&ProjectVerify, child_id, "test-project")
                .await?;
        }
        Ok(operations.get_state(child_id).await.unwrap() == "succeeded")
    }
}

#[derive(Debug)]
struct ProjectVerify;
#[async_trait]
impl fleet_application::worker::OperationExecutor for ProjectVerify {
    async fn execute(
        &self,
        operations: &Operations,
        operation: &fleet_application::operation::Operation,
    ) -> Result<(), String> {
        operations
            .complete(
                &operation.id,
                "succeeded",
                Some(r#"{"ready":true,"completed":["verify"]}"#),
                None,
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

async fn ready_harness(
    probe: ReadinessProbe,
    project: bool,
    fail: Option<&'static str>,
) -> (Harness, String, ProvisionRecord, Arc<Pve>, Arc<ReadyPorts>) {
    let harness = Harness::new().await;
    let mut version = harness.labs.get_version(&harness.version_id).await.unwrap();
    version.content.readiness_deadline_seconds = 30;
    version.content.readiness_probe = probe;
    version.content.readiness_command = Some("test -f /tmp/ready".to_owned());
    version.content.bootstrap_project_id = project.then(|| "project-1".to_owned());
    sqlx::query("UPDATE lab_template_versions SET content = ?2 WHERE id = ?1")
        .bind(&version.id)
        .bind(serde_json::to_string(&version.content).unwrap())
        .execute(&harness.pool)
        .await
        .unwrap();
    let (lease_id, mut record) = harness.record().await;
    record.vmid = Some(NEXT_VMID);
    record.node = Some(TEMPLATE_NODE.to_owned());
    record.clone_upid = Some(CLONE_UPID.to_owned());
    ProvisionPort::update(harness.labs.as_ref(), &record)
        .await
        .unwrap();
    let mut pve = Pve::new(vec![guest(NEXT_VMID, &format!("fm-lab-{}", record.id))]);
    Arc::get_mut(&mut pve).unwrap().ready_ip = true;
    let ports = Arc::new(ReadyPorts {
        labs: harness.labs.clone(),
        fail,
        calls: Mutex::new(Vec::new()),
    });
    (harness, lease_id, record, pve, ports)
}

#[tokio::test]
async fn every_probe_registers_a_lab_machine_and_starts_ttl_only_after_bootstrap() {
    for (probe, project, expected) in [
        (ReadinessProbe::GuestAgent, false, vec!["trust"]),
        (ReadinessProbe::SshExec, false, vec!["trust", "ssh"]),
        (
            ReadinessProbe::ProjectReady,
            true,
            vec!["trust", "create_project", "verify"],
        ),
        (
            ReadinessProbe::GuestAgent,
            true,
            vec!["trust", "create_project", "verify"],
        ),
    ] {
        let (harness, lease_id, record, pve, ports) = ready_harness(probe, project, None).await;
        let executor = harness.executor(&pve, Some(TEMPLATE_VMID)).with_readiness(
            ports.clone(),
            Arc::new(AuditSink::new(harness.pool.clone())),
        );
        let (state, error, stored) = harness
            .run_executor(&pve, executor, &lease_id, &record.id)
            .await;
        assert_eq!(state, "succeeded", "{error:?}");
        assert_eq!(stored.state, GuestState::Ready);
        assert_eq!(stored.guest_ipv4.as_deref(), Some("192.0.2.42"));
        assert!(stored.machine_id.is_some());
        assert!(stored.endpoint_id.is_some());
        assert_eq!(*ports.calls.lock().unwrap(), expected);
        let lease = harness.leases.get(&lease_id).await.unwrap();
        assert_eq!(lease.state, fleet_core::LeaseState::Ready);
        assert_eq!(lease.ready_at, stored.ready_at);
        assert_eq!(
            lease.expires_at,
            stored.ready_at.map(|ready| ready + 3_600_000)
        );
        let executor = harness.executor(&pve, Some(TEMPLATE_VMID)).with_readiness(
            ports.clone(),
            Arc::new(AuditSink::new(harness.pool.clone())),
        );
        let (state, _, resumed) = harness
            .run_executor(&pve, executor, &lease_id, &record.id)
            .await;
        assert_eq!(state, "succeeded");
        assert_eq!(resumed.machine_id, stored.machine_id);
        assert_eq!(
            resumed.ready_project_operation_id,
            stored.ready_project_operation_id
        );
        assert_eq!(
            harness.leases.get(&lease_id).await.unwrap().expires_at,
            lease.expires_at
        );
        assert_eq!(
            *ports.calls.lock().unwrap(),
            expected,
            "a ready resume does no remote work"
        );
        assert!(pve.clones().is_empty());
    }
}

#[tokio::test]
async fn each_readiness_failure_names_the_step_and_retains_allocations() {
    for (fail, step) in [
        ("trust", "ssh_trust"),
        ("ssh", "ssh_exec"),
        ("project", "project_setup"),
        ("verify", "project_ready"),
    ] {
        let (harness, lease_id, record, pve, ports) =
            ready_harness(ReadinessProbe::SshExec, true, Some(fail)).await;
        let executor = harness
            .executor(&pve, Some(TEMPLATE_VMID))
            .with_readiness(ports, Arc::new(AuditSink::new(harness.pool.clone())));
        let (state, error, stored) = harness
            .run_executor(&pve, executor, &lease_id, &record.id)
            .await;
        assert_eq!(state, "failed");
        assert_eq!(stored.state, GuestState::NeverReady);
        assert_eq!(stored.failed_step.as_deref(), Some(step));
        assert_eq!(stored.vmid, Some(NEXT_VMID));
        assert_eq!(stored.clone_upid.as_deref(), Some(CLONE_UPID));
        assert!(stored.machine_id.is_some());
        assert!(stored.endpoint_id.is_some());
        assert!(stored.ready_at.is_none());
        assert_eq!(
            harness.leases.get(&lease_id).await.unwrap().state,
            fleet_core::LeaseState::Failed
        );
        assert!(!error.unwrap().1.contains("unsafe"));
        assert_eq!(
            stored.ready_project_operation_id.is_some(),
            fail == "verify"
        );
    }
}

#[derive(Debug, Default)]
struct BudgetStep(Mutex<Vec<u64>>);

#[async_trait]
impl fleet_application::worker::OperationExecutor for BudgetStep {
    async fn execute(
        &self,
        operations: &Operations,
        operation: &fleet_application::operation::Operation,
    ) -> Result<(), String> {
        let payload: serde_json::Value =
            serde_json::from_str(operation.payload_json.as_deref().unwrap()).unwrap();
        self.0
            .lock()
            .unwrap()
            .push(payload["timeoutSeconds"].as_u64().unwrap());
        operations
            .complete(&operation.id, "succeeded", Some("{}"), None)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[tokio::test]
async fn production_readiness_adapter_bounds_children_and_refuses_stopped_parents() {
    let harness = Harness::new().await;
    let step = Arc::new(BudgetStep::default());
    let executor = fleet_controller::proxmox_exec::LabReadinessExecutor::new(
        step.clone(),
        step.clone(),
        Arc::new(fleet_storage_sqlite::MachineRepository::new(
            harness.pool.clone(),
        )),
        harness.operations.clone(),
        harness._dir.path().join("ssh"),
        fleet_provider_ssh::ExecutionLimiter::new(2),
    );
    for stopped in [false, true] {
        let parent = harness
            .operations
            .create(
                &AllowAll,
                "tester",
                &NewOperation {
                    kind: "ssh.exec".to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    review_token: None,
                    payload_json: Some(serde_json::json!({"machineId":"machine", "endpointId":"endpoint", "auth":{"type":"agent"}, "script":"true", "timeoutSeconds":30}).to_string()),
                },
            )
            .await
            .unwrap();
        if stopped {
            harness
                .operations
                .cancel(&AllowAll, "tester", &parent.id)
                .await
                .unwrap();
        }
        let child = harness.operations.create(&AllowAll, "tester", &NewOperation {
            kind: "ssh.exec".to_owned(), idempotency_key: None,
            deadline_at: Some(fleet_core::SystemClock::now_unix_millis() + 5_000),
            correlation_id: None, review_token: None,
            payload_json: Some(serde_json::json!({"machineId":"machine", "endpointId":"endpoint", "auth":{"type":"agent"}, "script":"true", "timeoutSeconds":900, "labParentOperationId":parent.id}).to_string()),
        }).await.unwrap();
        harness
            .operations
            .claim_only_execute(&executor, &child.id, "tester")
            .await
            .unwrap();
        assert_eq!(
            harness.operations.get_state(&child.id).await.unwrap(),
            if stopped { "failed" } else { "succeeded" }
        );
    }
    let budgets = step.0.lock().unwrap();
    assert_eq!(
        budgets.len(),
        1,
        "a cancelled parent must never reach the executor"
    );
    assert!(
        (1..=5).contains(&budgets[0]),
        "nested CLI timeout must fit inside the Lab deadline"
    );
}

#[derive(Debug)]
struct CancelAfterClone {
    parent: String,
    calls: Mutex<Vec<(String, u64)>>,
}

#[async_trait]
impl fleet_application::worker::OperationExecutor for CancelAfterClone {
    async fn execute(
        &self,
        operations: &Operations,
        operation: &fleet_application::operation::Operation,
    ) -> Result<(), String> {
        let payload: serde_json::Value =
            serde_json::from_str(operation.payload_json.as_deref().unwrap()).unwrap();
        self.calls.lock().unwrap().push((
            operation.kind.clone(),
            payload["timeoutSeconds"].as_u64().unwrap(),
        ));
        operations
            .complete(&operation.id, "succeeded", Some("{}"), None)
            .await
            .map_err(|e| e.to_string())?;
        if operation.kind == "projects.clone" {
            operations
                .cancel(&AllowAll, "tester", &self.parent)
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

async fn readiness_parent(operations: &Operations) -> fleet_application::operation::Operation {
    operations.create(&AllowAll, "tester", &NewOperation {
        kind: "ssh.exec".to_owned(), idempotency_key: None, deadline_at: None,
        correlation_id: None, review_token: None,
        payload_json: Some(serde_json::json!({"machineId":"machine", "endpointId":"endpoint", "auth":{"type":"agent"}, "script":"true", "timeoutSeconds":30}).to_string()),
    }).await.unwrap()
}

#[tokio::test]
async fn production_m3_child_bounds_nested_steps_and_stops_after_parent_cancellation() {
    let harness = Harness::new().await;
    let parent = readiness_parent(&harness.operations).await;
    let steps = Arc::new(CancelAfterClone {
        parent: parent.id.clone(),
        calls: Mutex::new(Vec::new()),
    });
    let executor = fleet_controller::proxmox_exec::LabReadinessExecutor::new(
        steps.clone(),
        steps.clone(),
        Arc::new(fleet_storage_sqlite::MachineRepository::new(
            harness.pool.clone(),
        )),
        harness.operations.clone(),
        harness._dir.path().join("ssh"),
        fleet_provider_ssh::ExecutionLimiter::new(2),
    );
    let child = harness.operations.create(&AllowAll, "tester", &NewOperation {
        kind:"ready.workflow".to_owned(), idempotency_key:None,
        deadline_at:Some(fleet_core::SystemClock::now_unix_millis()+10_000), correlation_id:None, review_token:None,
        payload_json:Some(serde_json::json!({"machineId":"machine", "endpointId":"endpoint", "auth":{"type":"agent"}, "remote":"https://example.test/demo.git", "root":"/tmp/demo", "timeoutSeconds":900, "labParentOperationId":parent.id}).to_string()),
    }).await.unwrap();
    harness
        .operations
        .claim_only_execute(&executor, &child.id, "tester")
        .await
        .unwrap();
    assert_eq!(
        harness.operations.get_state(&child.id).await.unwrap(),
        "failed"
    );
    let calls = steps.calls.lock().unwrap();
    assert!(calls.iter().any(|(kind, _)| kind == "projects.clone"));
    assert!(
        !calls
            .iter()
            .any(|(kind, _)| kind == "frogenv.setup" || kind == "tools.inventory")
    );
    assert!(calls.iter().all(|(_, seconds)| (1..=10).contains(seconds)));
}

#[derive(Debug)]
struct SlowChild;
#[async_trait]
impl fleet_application::worker::OperationExecutor for SlowChild {
    async fn execute(
        &self,
        _: &Operations,
        _: &fleet_application::operation::Operation,
    ) -> Result<(), String> {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Err("bounded test child ended".to_owned())
    }
}

#[tokio::test]
async fn production_child_watchdog_survives_the_callers_timeout() {
    use fleet_application::lab::LabReadinessPort as _;
    let harness = Harness::new().await;
    let parent = readiness_parent(&harness.operations).await;
    let (_, mut record) = harness.record().await;
    record.machine_id = Some("machine".to_owned());
    record.endpoint_id = Some("endpoint".to_owned());
    record.readiness_deadline_at = Some(fleet_core::SystemClock::now_unix_millis() + 250);
    let readiness = fleet_controller::proxmox_exec::ProvisionReadiness::new(
        Arc::new(fleet_storage_sqlite::MachineRepository::new(
            harness.pool.clone(),
        )),
        Arc::new(fleet_storage_sqlite::ProjectRepository::new(
            harness.pool.clone(),
        )),
        Arc::new(AuditSink::new(harness.pool.clone())),
        Arc::new(SlowChild),
        harness.operations.clone(),
        harness._dir.path().join("ssh"),
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            readiness.ssh_probe(
                &harness.operations,
                &parent.id,
                &record,
                "true",
                std::time::Duration::from_millis(250)
            )
        )
        .await
        .is_err()
    );
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let children = harness
        .operations
        .list(&AllowAll, "tester", 100)
        .await
        .unwrap();
    let child = children
        .iter()
        .find(|child| child.correlation_id.as_deref() == Some(&record.id))
        .unwrap();
    assert!(
        child.cancel_requested,
        "dropping the caller must not drop child cancellation"
    );
}

#[tokio::test]
async fn queue_claimed_m3_steps_inherit_the_persisted_lab_workflows_bound() {
    let harness = Harness::new().await;
    let parent = readiness_parent(&harness.operations).await;
    let workflow = harness.operations.create(&AllowAll, "tester", &NewOperation {
        kind: "ready.workflow".to_owned(), idempotency_key:None,
        deadline_at: Some(fleet_core::SystemClock::now_unix_millis()+10_000), correlation_id: None, review_token:None,
        payload_json:Some(serde_json::json!({"machineId":"machine", "endpointId":"endpoint", "auth":{"type":"agent"}, "remote":"https://example.test/demo.git", "root":"/tmp/demo", "timeoutSeconds":10, "labParentOperationId":parent.id}).to_string()),
    }).await.unwrap();
    let (_, record) = harness.record().await;
    let mut record = harness
        .labs
        .ensure_guest_machine(&record.id, "root@192.0.2.20:22")
        .await
        .unwrap();
    record.state = GuestState::Bootstrapping;
    record.ready_project_operation_id = Some(workflow.id.clone());
    record.readiness_deadline_at = Some(fleet_core::SystemClock::now_unix_millis() + 10_000);
    ProvisionPort::update(harness.labs.as_ref(), &record)
        .await
        .unwrap();
    let steps = Arc::new(BudgetStep::default());
    let executor = fleet_controller::proxmox_exec::LabReadinessExecutor::new(
        steps.clone(),
        steps.clone(),
        Arc::new(fleet_storage_sqlite::MachineRepository::new(
            harness.pool.clone(),
        )),
        harness.operations.clone(),
        harness._dir.path().join("ssh"),
        fleet_provider_ssh::ExecutionLimiter::new(2),
    )
    .with_provisions(harness.labs.clone());
    for stopped in [false, true] {
        if stopped {
            harness
                .operations
                .cancel(&AllowAll, "tester", &parent.id)
                .await
                .unwrap();
        }
        let child = harness.operations.create(&AllowAll, "tester", &NewOperation {
            kind:"projects.clone".to_owned(), idempotency_key:None, deadline_at:None, correlation_id:None, review_token:None,
            payload_json:Some(serde_json::json!({"machineId":record.machine_id, "endpointId":record.endpoint_id, "auth":{"type":"agent"}, "remote":"https://example.test/demo.git", "root":"/tmp/demo", "timeoutSeconds":600}).to_string()),
        }).await.unwrap();
        if stopped {
            record.state = GuestState::NeverReady;
            ProvisionPort::update(harness.labs.as_ref(), &record)
                .await
                .unwrap();
        }
        harness
            .operations
            .claim_only_execute(&executor, &child.id, "other-worker")
            .await
            .unwrap();
        assert_eq!(
            harness.operations.get_state(&child.id).await.unwrap(),
            if stopped { "failed" } else { "succeeded" }
        );
    }
    let calls = steps.0.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert!((1..=10).contains(&calls[0]));
}

// ── Issue #290: a clone of a protected template is unprotected ──────────

/// The index of the first request whose path ends with `suffix`.
fn first(pve: &Pve, suffix: &str) -> Option<usize> {
    pve.paths().iter().position(|path| path.ends_with(suffix))
}

const CLONE_CONFIG: &str = "/api2/json/nodes/pve-b/qemu/9000/config";

#[tokio::test]
async fn a_clone_of_a_protected_template_is_unprotected_before_it_starts() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).protected();

    let (state, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    // The saga goes on past the unprotect step (to the never-answering
    // agent probe).
    assert_eq!(state, "failed");
    assert_eq!(error.unwrap().0, "never_ready");
    let updates = pve.config_updates();
    assert_eq!(updates.len(), 1, "{:?}", pve.paths());
    // Only the new guest's config, never the template's.
    assert_eq!(updates[0].path, CLONE_CONFIG);
    let paths = pve.paths();
    let cloned = first(&pve, "/clone").unwrap();
    let read = paths.iter().position(|path| path == CLONE_CONFIG).unwrap();
    let put = pve
        .seen()
        .iter()
        .position(|seen| seen.method == PveHttpMethod::Put)
        .unwrap();
    let started = first(&pve, "/status/start").unwrap();
    assert!(cloned < read && read < put && put < started, "{paths:?}");
    assert!(
        !paths
            .iter()
            .any(|path| path.contains(&format!("/qemu/{TEMPLATE_VMID}/config"))),
        "{paths:?}"
    );
    assert_eq!(stored.vmid, Some(NEXT_VMID));
    assert_eq!(stored.failed_step.as_deref(), Some("guest_ip"));
}

#[tokio::test]
async fn a_clone_without_the_flag_is_read_but_not_changed() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());

    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert_eq!(error.unwrap().0, "never_ready");
    assert!(pve.config_updates().is_empty(), "{:?}", pve.paths());
    let read = first(&pve, "/qemu/9000/config").unwrap();
    assert!(read < first(&pve, "/status/start").unwrap());
}

#[tokio::test]
async fn the_clone_lock_is_waited_out_before_the_flag_is_cleared() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).protected().locked_for(1);

    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert_eq!(error.unwrap().0, "never_ready");
    let reads = pve
        .seen()
        .iter()
        .filter(|seen| seen.path == CLONE_CONFIG && seen.method == PveHttpMethod::Get)
        .count();
    assert_eq!(reads, 3, "the locked read is retried: {:?}", pve.paths()); // two settle reads, then the hardware check (#372)
    assert_eq!(pve.config_updates().len(), 1);
    let put = pve
        .seen()
        .iter()
        .position(|seen| seen.method == PveHttpMethod::Put)
        .unwrap();
    assert!(put < first(&pve, "/status/start").unwrap());
}

#[tokio::test]
async fn a_refused_unprotect_fails_the_provision_before_the_start() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).protected().refusing_unprotect();

    let (state, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "unprotect_failed");
    assert!(
        detail.contains("VM.Config.Options on /vms/9000"),
        "{detail}"
    );
    assert_eq!(
        step_of(&harness, &record.id).await.as_deref(),
        Some("unprotect")
    );
    assert!(first(&pve, "/status/start").is_none(), "{:?}", pve.paths());
    // The guest stays recorded, so cleanup still owns it.
    assert_eq!(stored.state, GuestState::NeverReady);
    assert_eq!(stored.failed_step.as_deref(), Some("unprotect"));
    assert_eq!(stored.vmid, Some(NEXT_VMID));
    assert_eq!(stored.clone_upid.as_deref(), Some(CLONE_UPID));
}

#[tokio::test]
async fn a_settled_config_that_is_not_our_clone_is_never_updated_or_started() {
    // The mock otherwise echoes the requested clone name, so these cases
    // prove the identity check runs before the protection update.
    let harness = Harness::new().await;
    for pve in [
        Pve::new(Vec::new()).protected().named("someone-else"),
        Pve::new(Vec::new()).protected().as_template(),
    ] {
        let (lease_id, record) = harness.record().await;
        let (state, error, stored) = harness
            .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
            .await;

        assert_eq!(state, "failed");
        let (reason, detail) = error.unwrap();
        assert_eq!(reason, "conflict", "{detail}");
        assert!(detail.contains("left unchanged"), "{detail}");
        assert_eq!(pve.clones().len(), 1, "{:?}", pve.paths());
        assert!(first(&pve, CLONE_CONFIG).is_some(), "{:?}", pve.paths());
        assert!(pve.config_updates().is_empty(), "{:?}", pve.paths());
        assert!(first(&pve, "/status/start").is_none(), "{:?}", pve.paths());
        assert_eq!(
            step_of(&harness, &record.id).await.as_deref(),
            Some("clone")
        );
        assert_eq!(stored.failed_step.as_deref(), Some("clone"));
        assert_eq!(stored.vmid, Some(NEXT_VMID));
    }
}

/// Reopens an ended record, which the port refuses to do (#303): the
/// simulated interruption precedes the failure the run recorded.
async fn reopen(harness: &Harness, record_id: &str) {
    sqlx::query(
        "UPDATE lab_provisions SET state = 'provisioning', failed_step = NULL WHERE id = ?1",
    )
    .bind(record_id)
    .execute(&harness.pool)
    .await
    .unwrap();
}

/// Puts a run's record and lease back to `provisioning`, as if the
/// controller had stopped after the clone was recorded.
async fn interrupt(harness: &Harness, lease_id: &str, record_id: &str) {
    let mut lease = harness.leases.get(lease_id).await.unwrap();
    lease.state = fleet_core::LeaseState::Provisioning;
    harness.leases.update(&lease).await.unwrap();
    let mut record = ProvisionPort::get(harness.labs.as_ref(), record_id)
        .await
        .unwrap();
    reopen(harness, record_id).await;
    record.failed_step = None;
    record.state = GuestState::Provisioning;
    ProvisionPort::update(harness.labs.as_ref(), &record)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_resumed_clone_is_neither_cloned_nor_unprotected_again() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).protected();
    harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(pve.config_updates().len(), 1);
    interrupt(&harness, &lease_id, &record.id).await;

    // The flag was cleared before the interruption: nothing to repeat.
    let name = format!("fm-lab-{}", record.id);
    let second = Pve::new(vec![guest(NEXT_VMID, &name)]);
    let (_, error, stored) = harness
        .run(&second, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "never_ready");
    assert!(second.clones().is_empty(), "{:?}", second.paths());
    assert!(second.config_updates().is_empty(), "{:?}", second.paths());
    assert!(first(&second, "/status/start").is_some());
    assert_eq!(stored.vmid, Some(NEXT_VMID));

    // Interrupted between the clone and the unprotect: the resume clears
    // the flag once, still without a second clone.
    interrupt(&harness, &lease_id, &record.id).await;
    let third = Pve::new(vec![guest(NEXT_VMID, &name)]).protected();
    harness
        .run(&third, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert!(third.clones().is_empty(), "{:?}", third.paths());
    let updates = third.config_updates();
    assert_eq!(updates.len(), 1, "{:?}", third.paths());
    assert_eq!(updates[0].path, CLONE_CONFIG);
}

#[tokio::test]
async fn a_config_not_written_yet_is_retried_but_a_refused_read_fails_at_once() {
    // PVE writes the clone's config inside the forked worker: an early read
    // finds none yet, and the executor retries it.
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).protected().missing_for(1);
    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "never_ready");
    let reads = pve
        .seen()
        .iter()
        .filter(|seen| seen.path == CLONE_CONFIG && seen.method == PveHttpMethod::Get)
        .count();
    assert_eq!(reads, 3, "{:?}", pve.paths());
    assert_eq!(pve.config_updates().len(), 1);

    // Without VM.Audit on the clone target, no polling and no start.
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).forbidding_config_reads();
    let (state, _, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(state, "failed");
    let reads = pve
        .seen()
        .iter()
        .filter(|seen| seen.path == CLONE_CONFIG)
        .count();
    assert_eq!(reads, 1, "{:?}", pve.paths());
    assert!(first(&pve, "/status/start").is_none(), "{:?}", pve.paths());
    assert_eq!(stored.state, GuestState::NeverReady);
    assert_eq!(stored.vmid, Some(NEXT_VMID));
}

#[tokio::test]
async fn a_protected_clone_without_a_config_digest_is_never_updated_unconditionally() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).protected().without_digest();

    let (state, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;

    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "unprotect_failed");
    assert!(detail.contains("digest"), "{detail}");
    assert!(pve.config_updates().is_empty(), "{:?}", pve.paths());
    assert!(first(&pve, "/status/start").is_none(), "{:?}", pve.paths());
    assert_eq!(stored.failed_step.as_deref(), Some("unprotect"));
}

#[tokio::test]
async fn a_stale_digest_is_reread_and_retried_once() {
    // One stale refusal: the config is re-read and re-checked, and the
    // second, digest-bound update lands before the start.
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).protected().stale_for(1);
    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "never_ready");
    assert_eq!(pve.config_updates().len(), 2, "{:?}", pve.paths());
    let reads = pve
        .seen()
        .iter()
        .filter(|seen| seen.path == CLONE_CONFIG && seen.method == PveHttpMethod::Get)
        .count();
    assert_eq!(reads, 3, "{:?}", pve.paths());
    assert!(first(&pve, "/status/start").is_some());

    // Refused twice: the provision fails before the start.
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).protected().stale_for(2);
    let (_, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "unprotect_failed");
    // A server-side refusal, not a missing privilege.
    assert!(!detail.contains("VM.Config.Options"), "{detail}");
    assert!(detail.contains("locked or changing"), "{detail}");
    assert_eq!(pve.config_updates().len(), 2, "{:?}", pve.paths());
    assert!(first(&pve, "/status/start").is_none());
    assert_eq!(stored.failed_step.as_deref(), Some("unprotect"));
}

/// The `step` of the latest failed `lab.provision` operation for a record.
async fn step_of(harness: &Harness, record_id: &str) -> Option<String> {
    let error: String = sqlx::query_scalar(
        "SELECT error_json FROM operations WHERE kind = 'lab.provision' AND payload_json LIKE ? ORDER BY rowid DESC LIMIT 1",
    )
    .bind(format!("%{record_id}%"))
    .fetch_one(&harness.pool)
    .await
    .unwrap();
    serde_json::from_str::<serde_json::Value>(&error).unwrap()["step"]
        .as_str()
        .map(str::to_owned)
}

#[tokio::test]
async fn a_permanent_client_error_on_the_update_is_not_retried() {
    // A 404 (the guest went away between the read and the update) is not a
    // stale digest: no re-read, no second update.
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).protected().update_status(404);
    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "unprotect_failed");
    assert_eq!(pve.config_updates().len(), 1, "{:?}", pve.paths());
    assert_eq!(
        step_of(&harness, &record.id).await.as_deref(),
        Some("unprotect")
    );
}

// FM-715: placement and capacity reservation ---------------------------------

#[tokio::test]
async fn placement_selects_the_account_and_reserves_before_any_vmid_or_clone() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());
    *pve.capacity.lock().unwrap() = Some(16);
    *pve.watch_reservation.lock().unwrap() = Some((harness.pool.clone(), lease_id.clone()));

    let (_, error, stored) = harness
        .run_with_account(
            &pve,
            harness.placed_executor(&pve, PlacementPolicy::default()),
            &lease_id,
            &record.id,
            None,
        )
        .await;

    // The reservation was already held when the VMID was requested and
    // when the clone was.
    let held_at = pve.held_at.lock().unwrap().clone();
    assert_eq!(held_at.len(), 2, "{held_at:?}");
    assert!(held_at.iter().all(|(_, held)| *held), "{held_at:?}");

    // The saga ran to the agent probe as before (never_ready), through the
    // one account that reaches the template.
    assert_eq!(error.unwrap().0, "never_ready");
    assert_eq!(
        stored.account_id.as_deref(),
        Some(harness.account_id.as_str())
    );
    assert_eq!(pve.clones().len(), 1);
    let paths = pve.paths();
    let observed = paths
        .iter()
        .position(|path| path == &format!("/api2/json/nodes/{TEMPLATE_NODE}/status"))
        .expect("the template node's capacity is refreshed");
    let nextid = paths
        .iter()
        .position(|path| path == "/api2/json/cluster/nextid")
        .unwrap();
    assert!(observed < nextid, "{paths:?}");
    let reservation = CapacityRepository::new(harness.pool.clone())
        .for_lease(&lease_id)
        .await
        .unwrap()
        .expect("the lease holds a reservation");
    assert_eq!(reservation.node, TEMPLATE_NODE);
    assert_eq!(reservation.account_id, harness.account_id);
    assert_eq!(
        (
            reservation.demand.cores,
            reservation.demand.memory_mib,
            reservation.demand.disk_gib,
            reservation.demand.storage.as_str()
        ),
        (2, 2048, 20, "local-lvm")
    );
    // The guest was allocated: never_ready keeps the reservation for
    // cleanup to release after the destroy.
    assert_eq!(reservation.state, ReservationState::Held);
}

#[tokio::test]
async fn insufficient_capacity_refuses_with_an_explanation_and_allocates_nothing() {
    let harness = Harness::new().await;
    let (first_lease, first) = harness.record().await;
    let (second_lease, second) = harness.record().await;
    let pve = Pve::new(Vec::new());
    // 3 GiB free; the template wants 2 GiB.
    *pve.capacity.lock().unwrap() = Some(3);

    let (_, error, _) = harness
        .run_with_account(
            &pve,
            harness.placed_executor(&pve, PlacementPolicy::default()),
            &first_lease,
            &first.id,
            None,
        )
        .await;
    assert_eq!(error.unwrap().0, "never_ready");
    let clones_before = pve.clones().len();

    // The first lease's reservation holds 2 GiB: 1 GiB is left.
    let (state, error, stored) = harness
        .run_with_account(
            &pve,
            harness.placed_executor(&pve, PlacementPolicy::default()),
            &second_lease,
            &second.id,
            None,
        )
        .await;
    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "insufficient_memory");
    assert_eq!(
        detail,
        format!("insufficient memory on {TEMPLATE_NODE}: need 2048 MiB, 1024 free")
    );
    assert_eq!(pve.clones().len(), clones_before, "no clone was requested");
    assert_eq!(stored.vmid, None, "no VMID was reserved");
    // The refused lease never allocated a guest and holds nothing.
    assert!(
        CapacityRepository::new(harness.pool.clone())
            .for_lease(&second_lease)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn an_unrefreshable_stale_observation_refuses_placement() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    // The node status and storage endpoints fail, so the refresh is
    // partial and replaces nothing; the stored observation is an hour old.
    let pve = Pve::new(Vec::new());
    CapacityRepository::new(harness.pool.clone())
        .record_observation(
            &harness.account_id,
            &fleet_application::proxmox::ProxmoxNodeCapacity {
                node: TEMPLATE_NODE.to_owned(),
                cpu_usage_ratio: None,
                cpu_count: Some(8),
                memory_used_bytes: Some(0),
                memory_total_bytes: Some(32 << 30),
                storages: vec![fleet_application::proxmox::ProxmoxStorageCapacity {
                    storage: "local-lvm".to_owned(),
                    used_bytes: 0,
                    total_bytes: 500 << 30,
                }],
                observed_at: fleet_core::SystemClock::now_unix_millis() - 3_600_000,
            },
        )
        .await
        .unwrap();

    let (state, error, stored) = harness
        .run_with_account(
            &pve,
            harness.placed_executor(&pve, PlacementPolicy::default()),
            &lease_id,
            &record.id,
            Some(&harness.account_id),
        )
        .await;
    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "capacity_stale", "{detail}");
    assert!(
        detail.contains("refusing to place on stale capacity"),
        "{detail}"
    );
    assert!(pve.clones().is_empty());
    assert_eq!(stored.vmid, None);

    // A longer configured age accepts the same observation.
    let (lease_id, record) = harness.record().await;
    let (_, error, _) = harness
        .run_with_account(
            &pve,
            harness.placed_executor(
                &pve,
                PlacementPolicy {
                    max_observation_age_ms: 7_200_000,
                    ..PlacementPolicy::default()
                },
            ),
            &lease_id,
            &record.id,
            Some(&harness.account_id),
        )
        .await;
    assert_eq!(error.unwrap().0, "never_ready");
}

#[tokio::test]
async fn several_accounts_reaching_the_template_are_ambiguous() {
    let harness = Harness::new().await;
    let second = harness
        .accounts
        .create(&NewProxmoxAccount {
            name: "pve-second".to_owned(),
            host: API_HOST.to_owned(),
            port: None,
            token_id: "fleet@pve!lab2".to_owned(),
        })
        .await
        .unwrap();
    harness
        .accounts
        .set_fingerprint(&second.id, Some(FP.to_owned()))
        .await
        .unwrap();
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());
    *pve.capacity.lock().unwrap() = Some(16);

    let (state, error, stored) = harness
        .run_with_account(
            &pve,
            harness.placed_executor(&pve, PlacementPolicy::default()),
            &lease_id,
            &record.id,
            None,
        )
        .await;
    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "placement_ambiguous");
    assert!(
        detail.contains("pve-main on pve-b, pve-second on pve-b"),
        "{detail}"
    );
    assert!(pve.clones().is_empty());
    assert_eq!(stored.account_id, None);
}

#[tokio::test]
async fn a_failure_after_the_reservation_but_before_allocation_releases_it() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    // Capacity fits, so the reservation is taken; then nextid hands out a
    // promoted artifact's VMID and the provision fails before any guest
    // is allocated.
    let pve = Pve::scripted(Vec::new(), CLONE_UPID, GONE_ARTIFACT_VMID);
    *pve.capacity.lock().unwrap() = Some(16);

    let (state, error, stored) = harness
        .run_with_account(
            &pve,
            harness.placed_executor(&pve, PlacementPolicy::default()),
            &lease_id,
            &record.id,
            None,
        )
        .await;
    assert_eq!(state, "failed");
    assert_eq!(error.unwrap().0, "conflict");
    assert_eq!(stored.vmid, None);
    assert_eq!(
        harness.leases.get(&lease_id).await.unwrap().state,
        fleet_core::LeaseState::Failed
    );
    let reservation = CapacityRepository::new(harness.pool.clone())
        .for_lease(&lease_id)
        .await
        .unwrap()
        .expect("the reservation was taken before the failure");
    assert_eq!(reservation.state, ReservationState::Released);
    assert!(reservation.released_at.is_some());
}

#[tokio::test]
async fn a_resumed_pending_clone_without_a_reservation_reserves_before_cloning() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    // A run before FM-715 reserved the VMID and stopped before its clone.
    harness
        .labs
        .reserve_clone_target(&record.id, TEMPLATE_NODE, 9005)
        .await
        .unwrap();
    let pve = Pve::new(Vec::new());
    *pve.capacity.lock().unwrap() = Some(16);
    *pve.watch_reservation.lock().unwrap() = Some((harness.pool.clone(), lease_id.clone()));

    let (_, error, stored) = harness
        .run_with_account(
            &pve,
            harness.placed_executor(&pve, PlacementPolicy::default()),
            &lease_id,
            &record.id,
            Some(&harness.account_id.clone()),
        )
        .await;
    assert_eq!(error.unwrap().0, "never_ready");
    assert_eq!(stored.vmid, Some(9005));
    let held_at = pve.held_at.lock().unwrap().clone();
    assert_eq!(held_at.len(), 1, "only the clone, no nextid: {held_at:?}");
    assert!(
        held_at[0].0.ends_with("/clone") && held_at[0].1,
        "{held_at:?}"
    );
}

#[tokio::test]
async fn a_reservation_on_another_node_refuses_the_resumed_clone() {
    use fleet_application::lab_placement::{CapacityDemand, ReservationRequest, ReserveOutcome};
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let capacity = CapacityRepository::new(harness.pool.clone());
    let now = fleet_core::SystemClock::now_unix_millis();
    // An earlier run reserved on pve-a; the template is now on pve-b.
    capacity
        .record_observation(
            &harness.account_id,
            &fleet_application::proxmox::ProxmoxNodeCapacity {
                node: "pve-a".to_owned(),
                cpu_usage_ratio: None,
                cpu_count: Some(8),
                memory_used_bytes: Some(0),
                memory_total_bytes: Some(32 << 30),
                storages: vec![fleet_application::proxmox::ProxmoxStorageCapacity {
                    storage: "local-lvm".to_owned(),
                    used_bytes: 0,
                    total_bytes: 500 << 30,
                }],
                observed_at: now,
            },
        )
        .await
        .unwrap();
    let outcome = capacity
        .reserve(
            &ReservationRequest {
                lease_id: lease_id.clone(),
                account_id: harness.account_id.clone(),
                node: "pve-a".to_owned(),
                demand: CapacityDemand {
                    cores: 2,
                    memory_mib: 2048,
                    disk_gib: 20,
                    storage: "local-lvm".to_owned(),
                },
            },
            &PlacementPolicy::default(),
            now,
        )
        .await
        .unwrap();
    assert!(matches!(outcome, ReserveOutcome::Reserved(_)));
    let pve = Pve::new(Vec::new());
    *pve.capacity.lock().unwrap() = Some(16);

    let (state, error, stored) = harness
        .run_with_account(
            &pve,
            harness.placed_executor(&pve, PlacementPolicy::default()),
            &lease_id,
            &record.id,
            Some(&harness.account_id.clone()),
        )
        .await;
    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "reservation_mismatch", "{detail}");
    assert!(
        detail.contains("node pve-a of account")
            && detail.contains(&format!("node pve-b of account {}", harness.account_id)),
        "the detail names the held and the requested node and account: {detail}"
    );
    assert!(pve.clones().is_empty());
    assert_eq!(stored.vmid, None);
    assert_eq!(harness.audit_events("lab_placement_refused").await, 1);
}

#[tokio::test]
async fn a_reservation_on_another_storage_pool_refuses_the_resumed_clone() {
    use fleet_application::lab_placement::{CapacityDemand, ReservationRequest, ReserveOutcome};
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let capacity = CapacityRepository::new(harness.pool.clone());
    let now = fleet_core::SystemClock::now_unix_millis();
    // An earlier run reserved on the template's node, but on the pool of a
    // build that a re-promotion has since replaced.
    capacity
        .record_observation(
            &harness.account_id,
            &fleet_application::proxmox::ProxmoxNodeCapacity {
                node: "pve-b".to_owned(),
                cpu_usage_ratio: None,
                cpu_count: Some(8),
                memory_used_bytes: Some(0),
                memory_total_bytes: Some(32 << 30),
                storages: vec![fleet_application::proxmox::ProxmoxStorageCapacity {
                    storage: "old-pool".to_owned(),
                    used_bytes: 0,
                    total_bytes: 500 << 30,
                }],
                observed_at: now,
            },
        )
        .await
        .unwrap();
    let outcome = capacity
        .reserve(
            &ReservationRequest {
                lease_id: lease_id.clone(),
                account_id: harness.account_id.clone(),
                node: "pve-b".to_owned(),
                demand: CapacityDemand {
                    cores: 2,
                    memory_mib: 2048,
                    disk_gib: 20,
                    storage: "old-pool".to_owned(),
                },
            },
            &PlacementPolicy::default(),
            now,
        )
        .await
        .unwrap();
    assert!(matches!(outcome, ReserveOutcome::Reserved(_)));
    let pve = Pve::new(Vec::new());
    *pve.capacity.lock().unwrap() = Some(16);

    let (state, error, stored) = harness
        .run_with_account(
            &pve,
            harness.placed_executor(&pve, PlacementPolicy::default()),
            &lease_id,
            &record.id,
            Some(&harness.account_id.clone()),
        )
        .await;
    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "reservation_mismatch", "{detail}");
    assert!(
        detail.contains("on old-pool") && detail.contains("on local-lvm"),
        "{detail}"
    );
    assert!(pve.clones().is_empty());
    assert_eq!(stored.vmid, None);
    assert_eq!(harness.audit_events("lab_placement_refused").await, 1);
}

#[tokio::test]
async fn an_unknown_storage_pool_refuses_and_is_audited() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());
    *pve.capacity.lock().unwrap() = Some(16);
    let executor = harness.executor(&pve, Some(TEMPLATE_VMID)).with_placement(
        Arc::new(CapacityRepository::new(harness.pool.clone())),
        Arc::new(NoStorage),
        Arc::new(AuditSink::new(harness.pool.clone())),
        PlacementPolicy::default(),
    );

    let (state, error, stored) = harness
        .run_with_account(
            &pve,
            executor,
            &lease_id,
            &record.id,
            Some(&harness.account_id.clone()),
        )
        .await;
    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "storage_unknown", "{detail}");
    assert!(pve.clones().is_empty());
    assert_eq!(stored.vmid, None);
    assert!(
        CapacityRepository::new(harness.pool.clone())
            .for_lease(&lease_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(harness.audit_events("lab_placement_refused").await, 1);
}

#[tokio::test]
async fn an_unreadable_trusted_cluster_refuses_automatic_selection() {
    let harness = Harness::new().await;
    let other = harness
        .accounts
        .create(&NewProxmoxAccount {
            name: "pve-dark".to_owned(),
            host: UNREACHABLE_HOST.to_owned(),
            port: None,
            token_id: "fleet@pve!lab3".to_owned(),
        })
        .await
        .unwrap();
    harness
        .accounts
        .set_fingerprint(&other.id, Some(FP.to_owned()))
        .await
        .unwrap();
    // An untrusted account (no fingerprint) is a confirmed non-candidate
    // and does not block selection on its own.
    harness
        .accounts
        .create(&NewProxmoxAccount {
            name: "pve-untrusted".to_owned(),
            host: UNREACHABLE_HOST.to_owned(),
            port: None,
            token_id: "fleet@pve!lab4".to_owned(),
        })
        .await
        .unwrap();
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());
    *pve.capacity.lock().unwrap() = Some(16);

    let (state, error, _) = harness
        .run_with_account(
            &pve,
            harness.placed_executor(&pve, PlacementPolicy::default()),
            &lease_id,
            &record.id,
            None,
        )
        .await;
    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "placement_unresolved", "{detail}");
    assert!(detail.contains("pve-dark"), "{detail}");
    assert!(!detail.contains("pve-untrusted"), "{detail}");
    assert!(pve.clones().is_empty());
}

/// #310: a clone task that failed, or finished with no config, fails the
/// provision at `clone` without waiting; transient trouble and a config that
/// lands late do not.
#[tokio::test]
async fn a_failed_clone_task_fails_at_clone_without_waiting() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new())
        .missing_for(1_000)
        .clone_task(&["error"]);
    let (state, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(state, "failed");
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "clone_task_failed");
    assert!(detail.contains("storage full"), "{detail}");
    assert_eq!(pve.config_reads(), 1, "{:?}", pve.paths());
    assert_eq!(pve.task_polls(), 1);
    assert!(first(&pve, "/status/start").is_none());
    assert_eq!(stored.state, GuestState::NeverReady);
    assert_eq!(stored.failed_step.as_deref(), Some("clone"));
    // The reserved target and the clone task stay recorded for cleanup.
    assert_eq!(stored.vmid, Some(NEXT_VMID));
    assert_eq!(stored.clone_upid.as_deref(), Some(CLONE_UPID));
}

#[tokio::test]
async fn a_clean_clone_task_with_no_config_fails_after_a_second_read() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).missing_for(1_000).clone_task(&["ok"]);
    let (_, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "clone_task_failed");
    // The first read may predate the task's end; the second does not.
    assert_eq!(pve.config_reads(), 2, "{:?}", pve.paths());
    assert_eq!(stored.failed_step.as_deref(), Some("clone"));
    assert_eq!(stored.vmid, Some(NEXT_VMID));
}

#[tokio::test]
async fn a_config_that_lands_after_the_first_read_is_used() {
    // The task finished between the read and the status poll.
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).missing_for(1).clone_task(&["ok"]);
    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "never_ready");
    assert!(first(&pve, "/status/start").is_some());
    assert_eq!(pve.config_reads(), 3);
}

#[tokio::test]
async fn a_transient_read_error_after_a_clean_task_is_not_a_missing_guest() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).flaky_for(2).clone_task(&["ok"]);
    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "never_ready");
    assert!(first(&pve, "/status/start").is_some());

    // Only a second consecutive miss refuses, and the guest is kept for
    // cleanup.
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).flaky_for(1_000).clone_task(&["ok"]);
    let (_, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    let (reason, detail) = error.unwrap();
    assert_eq!(reason, "clone_task_failed");
    assert!(
        detail.contains("removes the guest if one exists"),
        "{detail}"
    );
    assert_eq!(pve.config_reads(), 3, "{:?}", pve.paths());
    assert_eq!(stored.vmid, Some(NEXT_VMID));
}

#[tokio::test]
async fn a_running_or_unknown_clone_task_keeps_waiting() {
    // One 2 s poll each, inside the harness's 5 s bound.
    for status in ["running", "unknown"] {
        let harness = Harness::new().await;
        let (lease_id, record) = harness.record().await;
        let pve = Pve::new(Vec::new()).missing_for(1).clone_task(&[status]);
        let (_, error, _) = harness
            .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
            .await;
        assert_eq!(error.unwrap().0, "never_ready", "{status}");
        assert_eq!(pve.config_reads(), 3, "{status}: {:?}", pve.paths());
        assert!(first(&pve, "/status/start").is_some(), "{status}");
    }
}

#[tokio::test]
async fn a_resumed_record_reads_its_recorded_clone_task() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());
    harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    interrupt(&harness, &lease_id, &record.id).await;

    // The guest exists but its config never settles and the recorded task
    // failed: the resume fails at clone and clones nothing again.
    let name = format!("fm-lab-{}", record.id);
    let second = Pve::new(vec![guest(NEXT_VMID, &name)])
        .missing_for(1_000)
        .clone_task(&["error"]);
    let (_, error, stored) = harness
        .run(&second, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "clone_task_failed");
    assert!(second.clones().is_empty());
    assert_eq!(stored.failed_step.as_deref(), Some("clone"));
}

#[tokio::test]
async fn a_malformed_recorded_clone_task_id_is_not_polled() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());
    harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    interrupt(&harness, &lease_id, &record.id).await;
    let mut stored = ProvisionPort::get(harness.labs.as_ref(), &record.id)
        .await
        .unwrap();
    stored.clone_upid = Some("not-a-upid".to_owned());
    ProvisionPort::update(harness.labs.as_ref(), &stored)
        .await
        .unwrap();

    let name = format!("fm-lab-{}", record.id);
    let second = Pve::new(vec![guest(NEXT_VMID, &name)])
        .missing_for(1)
        .clone_task(&["error"]);
    let (_, error, _) = harness
        .run(&second, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    // The unparsable id is reported on stderr and the config alone settles.
    assert_eq!(error.unwrap().0, "never_ready");
    assert_eq!(second.task_polls(), 0, "{:?}", second.paths());
}

/// #372: the clone gets the template's cores, memory, and disk.
#[tokio::test]
async fn a_clone_that_already_has_the_templates_hardware_is_not_changed() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new());
    let (_, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "never_ready");
    assert!(pve.hardware_writes().is_empty(), "{:?}", pve.paths());
    assert!(first(&pve, "/resize").is_none());
    assert!(first(&pve, "/status/start").is_some());
    assert_eq!(stored.vmid, Some(NEXT_VMID));
    // One read settles the config, one checks the hardware: nothing more.
    assert_eq!(pve.config_reads(), 2, "{:?}", pve.paths());
}

#[tokio::test]
async fn the_templates_cores_memory_and_disk_are_applied_before_the_start() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).imaged(1, 1024, 8);
    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "never_ready");
    let writes = pve.hardware_writes();
    assert_eq!(writes.len(), 2, "{writes:?}");
    // One conditional config update for cores and memory, then one resize
    // to an absolute size, each at the digest the previous write left.
    assert_eq!(writes[0].0, "config");
    assert_eq!(
        writes[0].1,
        serde_json::json!({"cores": 2, "memory": 2048, "digest": "0123abcd"})
    );
    assert_eq!(writes[1].0, "resize");
    assert_eq!(
        writes[1].1,
        serde_json::json!({"disk": "scsi0", "size": "20G", "digest": "0123abcd1"})
    );
    // Both landed before the guest started.
    let paths = pve.paths();
    let start = paths
        .iter()
        .position(|path| path.ends_with("/status/start"));
    let resize = paths.iter().position(|path| path.ends_with("/resize"));
    assert!(resize.unwrap() < start.unwrap(), "{paths:?}");
}

#[tokio::test]
async fn only_what_differs_is_written_and_a_bigger_disk_is_never_shrunk() {
    let harness = Harness::new().await;
    // More cores than the template: set down; memory and disk match.
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).imaged(4, 2048, 20);
    harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    let writes = pve.hardware_writes();
    assert_eq!(writes.len(), 1, "{writes:?}");
    assert_eq!(
        writes[0].1,
        serde_json::json!({"cores": 2, "digest": "0123abcd"})
    );

    // A disk already over the template's size stays as it is.
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).imaged(2, 2048, 40);
    harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert!(pve.hardware_writes().is_empty(), "{:?}", pve.paths());
    assert!(first(&pve, "/resize").is_none());
}

#[tokio::test]
async fn a_refused_hardware_update_fails_the_provision_at_hardware_before_the_start() {
    let harness = Harness::new().await;
    for (privilege, pve) in [
        (
            "VM.Config.CPU",
            Pve::new(Vec::new())
                .imaged(1, 2048, 20)
                .configure(|config| config.set_status = Some(403)),
        ),
        (
            "VM.Config.Disk",
            Pve::new(Vec::new())
                .imaged(2, 2048, 8)
                .configure(|config| config.resize_status = Some(403)),
        ),
    ] {
        let (lease_id, record) = harness.record().await;
        let (state, error, stored) = harness
            .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
            .await;
        assert_eq!(state, "failed", "{privilege}");
        let (reason, detail) = error.unwrap();
        assert_eq!(reason, "hardware_failed", "{privilege}");
        assert!(detail.contains(privilege), "{detail}");
        assert!(first(&pve, "/status/start").is_none(), "{privilege}");
        // The guest stays recorded for cleanup, at the named step.
        assert_eq!(stored.state, GuestState::NeverReady);
        assert_eq!(stored.failed_step.as_deref(), Some("hardware"));
        assert_eq!(stored.vmid, Some(NEXT_VMID));
    }
}

#[tokio::test]
async fn a_server_error_is_retried_once_and_then_refused() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new())
        .imaged(1, 2048, 20)
        .configure(|config| config.set_status = Some(500));
    let (_, error, stored) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "hardware_failed");
    // The settle read, then one hardware read per try.
    assert_eq!(pve.config_reads(), 3, "{:?}", pve.paths());
    assert_eq!(stored.failed_step.as_deref(), Some("hardware"));
}

#[tokio::test]
async fn a_guest_fleet_cannot_read_is_refused_rather_than_guessed_at() {
    let harness = Harness::new().await;
    for (what, pve) in [
        (
            "memory options",
            Pve::new(Vec::new())
                .imaged(2, 1024, 20)
                .configure(|config| config.memory_options = true),
        ),
        (
            "no boot disk",
            Pve::new(Vec::new()).configure(|config| config.no_boot_disk = true),
        ),
        (
            "no disk size",
            Pve::new(Vec::new()).configure(|config| config.no_disk_size = true),
        ),
    ] {
        let (lease_id, record) = harness.record().await;
        let (state, error, stored) = harness
            .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
            .await;
        assert_eq!(state, "failed", "{what}");
        assert_eq!(error.unwrap().0, "hardware_unsupported", "{what}");
        assert!(pve.hardware_writes().is_empty(), "{what}");
        assert!(first(&pve, "/status/start").is_none(), "{what}");
        assert_eq!(stored.failed_step.as_deref(), Some("hardware"), "{what}");
    }

    // A memory property string that already has the template's size is
    // fine: nothing needs rewriting.
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).configure(|config| config.memory_options = true);
    let (_, error, _) = harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(error.unwrap().0, "never_ready");
}

#[tokio::test]
async fn a_resumed_provision_repeats_no_hardware_write() {
    let harness = Harness::new().await;
    let (lease_id, record) = harness.record().await;
    let pve = Pve::new(Vec::new()).imaged(1, 1024, 8);
    harness
        .run(&pve, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert_eq!(pve.hardware_writes().len(), 2);
    interrupt(&harness, &lease_id, &record.id).await;

    // The guest now has what the first run gave it.
    let name = format!("fm-lab-{}", record.id);
    let second = Pve::new(vec![guest(NEXT_VMID, &name)]);
    harness
        .run(&second, Some(TEMPLATE_VMID), &lease_id, &record.id)
        .await;
    assert!(second.clones().is_empty());
    assert!(second.hardware_writes().is_empty(), "{:?}", second.paths());
}
