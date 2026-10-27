//! #489: permanent, Fleet-managed VMs, end to end. The real `machine.create`
//! executor runs against a stateful fake Proxmox (guests, tasks, config with
//! digests, the guest agent) and a real sshd whose only `authorized_keys` is
//! the "guest's" own file, so installing and removing keys changes who can
//! log in. The real SQLite repositories, secret store and key store are used.
//!
//! What is pinned: the clone, config, protection and start ordering; that the
//! template's tags are never inherited; the credential rotation order (the
//! new key is installed and verified before the image key is removed, and a
//! failure leaves the image key working); the marker that keeps Lab away; the
//! guest config allow-list; and that no key or secret reaches an operation
//! record or an audit event.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use fleet_application::authz::ActingPrincipal;
use fleet_application::lab::ImageArtifactPort;
use fleet_application::machine::{GuestLinkPort as _, MachinePort};
use fleet_application::machine_access::{
    EndpointAuth, EndpointAuthPort as _, MachineAccess, MachineKeyPort as _,
};
use fleet_application::operation::{NewOperation, Operation, Operations, review_token_for};
use fleet_application::persistent::{PersistentGuestPort as _, PersistentState};
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccountPort as _, ProxmoxCredentialStore,
};
use fleet_application::worker::OperationExecutor;
use fleet_controller::machine_access::{SecretBackedMachineKeys, SshAuthResolver};
use fleet_controller::persistent_machines::{
    GuestConfigExecutor, MachineCreateExecutor, MachineCreateParts, SecretBackedProductKeys,
};
use fleet_controller::proxmox_exec::ProxmoxDestructiveExecutor;
use fleet_provider_proxmox::{
    PveHttpMethod, PveHttpRequest, PveHttpResponse, PveTransport, PveTransportError,
};
use fleet_provider_ssh::{ExecutionLimiter, PrivateKey, SshAuth, SshConnectionSpec, SshProvider};
use fleet_storage_sqlite::{
    AuditSink, EndpointAuthRepository, GuestLinkRepository, MachineRepository, OperationRepository,
    PersistentGuestRepository, ProxmoxAccountRepository, Store,
};
use serde_json::{Value, json};

mod common;
use common::{start_sshd_with_home_keys, whoami};

const TEMPLATE_VMID: u32 = 7000;
const FINGERPRINT: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";

fn lan() -> ActingPrincipal {
    ActingPrincipal {
        id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
    }
}

/// One guest of the fake host.
#[derive(Clone, Debug)]
struct Guest {
    name: String,
    template: bool,
    running: bool,
    config: serde_json::Map<String, Value>,
    /// Config reads that still report the clone lock.
    locked_reads: u32,
}

#[derive(Debug, Default)]
struct HostState {
    /// Polls of a running guest that still holds install media.
    install_polls: BTreeMap<u32, u32>,
    /// The first power read of an installer says stopped (a lagging view).
    stale_first_stopped: bool,
    guests: BTreeMap<u32, Guest>,
    calls: Vec<String>,
    bodies: Vec<(String, Value)>,
    digest: u32,
    /// How many `start` calls still fail with a server error.
    fail_starts: u32,
    /// How many `clone` calls still fail with a server error.
    fail_clones: u32,
    /// The MAC address the guest agent reports.
    agent_mac: String,
}

/// A stateful fake Proxmox VE.
#[derive(Debug)]
struct FakePve {
    state: Mutex<HostState>,
}

impl FakePve {
    fn new() -> Arc<Self> {
        let mut state = HostState {
            agent_mac: "aa:bb:cc:dd:ee:01".to_owned(),
            ..HostState::default()
        };
        let config = json!({
            "name": "fleet-image",
            "tags": "fleet-pve-test;image",
            "protection": 1,
            "onboot": 0,
            "cores": 2,
            "memory": 2048,
            "net0": "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0",
            "description": "the template",
        })
        .as_object()
        .unwrap()
        .clone();
        state.guests.insert(
            TEMPLATE_VMID,
            Guest {
                name: "fleet-image".to_owned(),
                template: true,
                running: false,
                config,
                locked_reads: 0,
            },
        );
        Arc::new(Self {
            state: Mutex::new(state),
        })
    }

    fn fail_next_clones(&self, times: u32) {
        self.state.lock().unwrap().fail_clones = times;
    }

    fn set_agent_mac(&self, mac: &str) {
        self.state.lock().unwrap().agent_mac = mac.to_owned();
    }

    fn fail_next_starts(&self, times: u32) {
        self.state.lock().unwrap().fail_starts = times;
    }

    fn calls(&self) -> Vec<String> {
        self.state.lock().unwrap().calls.clone()
    }

    fn guest(&self, vmid: u32) -> Option<Guest> {
        self.state.lock().unwrap().guests.get(&vmid).cloned()
    }

    fn body_of(&self, call: &str) -> Option<Value> {
        self.state
            .lock()
            .unwrap()
            .bodies
            .iter()
            .find(|(name, _)| name == call)
            .map(|(_, body)| body.clone())
    }

    fn respond(&self, request: &PveHttpRequest, body: Option<Value>) -> (u16, Value) {
        let path = request
            .path
            .strip_prefix("/api2/json")
            .unwrap_or(&request.path)
            .split('?')
            .next()
            .unwrap_or_default()
            .to_owned();
        let method = match request.method {
            PveHttpMethod::Get => "GET",
            PveHttpMethod::Post => "POST",
            PveHttpMethod::Put => "PUT",
            PveHttpMethod::Delete => "DELETE",
        };
        let mut state = self.state.lock().unwrap();
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let ok = |data: Value| (200, json!({ "data": data }));
        match (method, parts.as_slice()) {
            ("GET", ["version"]) => {
                ok(json!({ "release": "9.2", "version": "9.2.2", "repoid": "b9984c6d90a4bd80" }))
            }
            ("GET", ["cluster", "resources"]) => {
                let entries: Vec<Value> = state
                    .guests
                    .iter()
                    .map(|(vmid, guest)| {
                        json!({
                            "id": format!("qemu/{vmid}"),
                            "type": "qemu",
                            "node": "pve",
                            "vmid": vmid,
                            "name": guest.name,
                            "status": if guest.running { "running" } else { "stopped" },
                            "template": u8::from(guest.template),
                        })
                    })
                    .collect();
                ok(Value::Array(entries))
            }
            ("GET", ["cluster", "nextid"]) => {
                let next = (7100..).find(|id| !state.guests.contains_key(id)).unwrap();
                ok(json!(next.to_string()))
            }
            ("POST", ["nodes", node, "qemu"]) => {
                state.calls.push("create".to_owned());
                let body = body.unwrap_or_default();
                state.bodies.push(("create".to_owned(), body.clone()));
                let vmid = body["vmid"].as_u64().unwrap() as u32;
                let mut config = serde_json::Map::new();
                for key in ["name", "cores", "memory", "ide2", "ide3", "boot", "agent"] {
                    if let Some(value) = body.get(key) {
                        config.insert(key.to_owned(), value.clone());
                    }
                }
                let bridge = body["net0"]
                    .as_str()
                    .and_then(|net| net.split("bridge=").nth(1))
                    .unwrap_or("vmbr0")
                    .to_owned();
                config.insert(
                    "net0".to_owned(),
                    json!(format!("virtio=AA:BB:CC:DD:EE:01,bridge={bridge}")),
                );
                config.insert(
                    "scsi0".to_owned(),
                    json!(format!("local-lvm:vm-{vmid}-disk-0,size=32G")),
                );
                state.guests.insert(
                    vmid,
                    Guest {
                        name: body["name"].as_str().unwrap().to_owned(),
                        template: false,
                        running: false,
                        config,
                        locked_reads: 0,
                    },
                );
                ok(json!(format!(
                    "UPID:{node}:0000AAAB:00000001:65000000:qmcreate:{vmid}:root@pam:"
                )))
            }
            ("POST", ["nodes", node, "qemu", source, "clone"]) => {
                state.calls.push(format!("clone {source}"));
                if state.fail_clones > 0 {
                    state.fail_clones -= 1;
                    return (500, json!({ "data": null }));
                }
                let body = body.unwrap_or_default();
                state.bodies.push(("clone".to_owned(), body.clone()));
                let new_id = body["newid"].as_u64().unwrap() as u32;
                let mut config = state.guests[&source.parse::<u32>().unwrap()].config.clone();
                config.insert("name".to_owned(), body["name"].clone());
                state.guests.insert(
                    new_id,
                    Guest {
                        name: body["name"].as_str().unwrap().to_owned(),
                        template: false,
                        running: false,
                        config,
                        locked_reads: 2,
                    },
                );
                ok(json!(format!(
                    "UPID:{node}:0000AAAA:00000001:65000000:qmclone:{source}:root@pam:"
                )))
            }
            ("GET", ["nodes", _, "qemu", vmid, "status", "current"]) => {
                let vmid: u32 = vmid.parse().unwrap();
                let stale = state.stale_first_stopped;
                let Some(guest) = state.guests.get(&vmid) else {
                    return (500, json!({ "data": null }));
                };
                let installing = guest.running
                    && guest.config.values().any(|value| {
                        value.as_str().is_some_and(|text| {
                            text.contains("media=cdrom") && !text.starts_with("none")
                        })
                    });
                let mut running = guest.running;
                if installing {
                    // The installer: running for two reads, then it powers
                    // the guest off. With `stale`, the very first read still
                    // says stopped, as a lagging listing would.
                    let polls = state.install_polls.entry(vmid).or_insert(0);
                    *polls += 1;
                    let polls = *polls;
                    if stale && polls == 1 {
                        running = false;
                    } else if polls >= 3 {
                        running = false;
                        state.guests.get_mut(&vmid).unwrap().running = false;
                    }
                }
                ok(json!({ "status": if running { "running" } else { "stopped" } }))
            }
            ("GET", ["nodes", _, "tasks", _, "status"]) => {
                ok(json!({ "status": "stopped", "exitstatus": "OK" }))
            }
            ("GET", ["nodes", _, "qemu", vmid, "config"]) => {
                let vmid: u32 = vmid.parse().unwrap();
                let digest = state.digest;
                let Some(guest) = state.guests.get_mut(&vmid) else {
                    return (500, json!({ "data": null }));
                };
                let mut config = guest.config.clone();
                config.insert("digest".to_owned(), json!(format!("d{digest}")));
                if guest.template {
                    config.insert("template".to_owned(), json!(1));
                }
                if guest.locked_reads > 0 {
                    guest.locked_reads -= 1;
                    config.insert("lock".to_owned(), json!("clone"));
                }
                ok(Value::Object(config))
            }
            ("PUT", ["nodes", _, "qemu", vmid, "config"]) => {
                let body = body.unwrap_or_default();
                state.calls.push(format!("config {vmid}"));
                state.bodies.push(("config".to_owned(), body.clone()));
                if body.get("digest").is_some()
                    && body["digest"] != json!(format!("d{}", state.digest))
                {
                    return (500, json!({ "data": null }));
                }
                state.digest += 1;
                let id = vmid.parse::<u32>().unwrap();
                let protected = state.guests[&id].config.get("protection") == Some(&json!(1));
                if protected
                    && body["delete"]
                        .as_str()
                        .unwrap_or_default()
                        .split(',')
                        .any(|key| {
                            key.starts_with("ide")
                                || key.starts_with("scsi")
                                || key.starts_with("sata")
                        })
                {
                    return (
                        500,
                        json!({ "data": null, "message": "can't remove drive - protection mode enabled" }),
                    );
                }
                if body.get("boot").is_some() {
                    let polls = state.install_polls.get(&id).copied().unwrap_or(0);
                    state.calls.push(format!("eject polls={polls}"));
                }
                let guest = state.guests.get_mut(&id).unwrap();
                for key in ["ide2", "ide3"] {
                    if let Some(value) = body.get(key) {
                        guest.config.insert(key.to_owned(), value.clone());
                    }
                }
                for key in [
                    "tags",
                    "description",
                    "onboot",
                    "protection",
                    "cores",
                    "memory",
                    "net0",
                    "boot",
                ] {
                    if let Some(value) = body.get(key) {
                        guest.config.insert(key.to_owned(), value.clone());
                    }
                }
                for key in body["delete"].as_str().unwrap_or_default().split(',') {
                    guest.config.remove(key);
                }
                ok(Value::Null)
            }
            ("POST", ["nodes", node, "qemu", vmid, "status", "start"]) => {
                state.calls.push(format!("start {vmid}"));
                if state.fail_starts > 0 {
                    state.fail_starts -= 1;
                    return (500, json!({ "data": null }));
                }
                state
                    .guests
                    .get_mut(&vmid.parse::<u32>().unwrap())
                    .unwrap()
                    .running = true;
                ok(json!(format!(
                    "UPID:{node}:0000BBBB:00000002:65000001:qmstart:{vmid}:root@pam:"
                )))
            }
            ("POST", ["nodes", node, "qemu", vmid, "status", "stop"]) => {
                state.calls.push(format!("stop {vmid}"));
                state
                    .guests
                    .get_mut(&vmid.parse::<u32>().unwrap())
                    .unwrap()
                    .running = false;
                ok(json!(format!(
                    "UPID:{node}:0000CCCC:00000003:65000002:qmstop:{vmid}:root@pam:"
                )))
            }
            ("DELETE", ["nodes", node, "qemu", vmid]) => {
                state.calls.push(format!("delete {vmid}"));
                let id = vmid.parse::<u32>().unwrap();
                if state.guests[&id].config.get("protection") == Some(&json!(1)) {
                    return (
                        500,
                        json!({ "data": null, "message": "unable to remove VM - protection mode enabled" }),
                    );
                }
                state.guests.remove(&id);
                ok(json!(format!(
                    "UPID:{node}:0000DDDD:00000004:65000003:qmdestroy:{vmid}:root@pam:"
                )))
            }
            ("GET", ["nodes", _, "qemu", vmid, "agent", "info"]) => {
                let running = state
                    .guests
                    .get(&vmid.parse::<u32>().unwrap())
                    .is_some_and(|guest| guest.running);
                if running {
                    ok(json!({ "result": { "version": "9.0" } }))
                } else {
                    (500, json!({ "data": null }))
                }
            }
            ("GET", ["nodes", _, "qemu", _, "agent", "network-get-interfaces"]) => {
                ok(json!({ "result": [{
                    "name": "ens18",
                    "hardware-address": state.agent_mac,
                    "ip-addresses": [{
                        "ip-address": "192.0.2.77",
                        "ip-address-type": "ipv4",
                        "prefix": 24
                    }]
                }] }))
            }
            ("GET", ["nodes", _, "qemu", _, "agent", _]) => ok(json!({ "result": {} })),
            _ => (404, json!({ "data": null })),
        }
    }
}

#[async_trait]
impl PveTransport for FakePve {
    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        let parsed = serde_json::from_slice(&body).ok();
        let (status, body) = self.respond(&request, parsed);
        Ok(PveHttpResponse {
            status,
            body: body.to_string().into_bytes(),
        })
    }

    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        let (status, body) = self.respond(&request, None);
        Ok(PveHttpResponse {
            status,
            body: body.to_string().into_bytes(),
        })
    }
}

#[derive(Debug)]
struct Credentials;

#[async_trait]
impl ProxmoxCredentialStore for Credentials {
    async fn load(&self, _account_id: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(Some("token-secret".to_owned()))
    }
    async fn store(&self, _: &str, _: &str) -> Result<(), CredentialStoreError> {
        Ok(())
    }
    async fn clear(&self, _: &str) -> Result<(), CredentialStoreError> {
        Ok(())
    }
}

#[derive(Debug)]
struct Artifacts;

#[async_trait]
impl ImageArtifactPort for Artifacts {
    async fn template_vmid(&self, _version: &str) -> Result<Option<u32>, String> {
        Ok(Some(TEMPLATE_VMID))
    }
    async fn promoted_template_vmids(&self) -> Result<Vec<u32>, String> {
        Ok(vec![TEMPLATE_VMID])
    }
}

#[derive(Debug)]
struct Promoted(bool);

#[async_trait]
impl fleet_application::lab::ImagePinValidator for Promoted {
    async fn promoted_version(
        &self,
        version_id: &str,
    ) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok(self.0.then(|| fleet_core::RecipeVersion {
            id: version_id.to_owned(),
            recipe_id: "recipe-1".to_owned(),
            name: "image".to_owned(),
            content_digest: "sha256:abc".to_owned(),
            description: String::new(),
            content: "{}".to_owned(),
            source: fleet_core::RecipeSource::Clone,
            node: "pve".to_owned(),
            storage_pool: "local-lvm".to_owned(),
            published_at: 0,
            promoted_at: Some(0),
            promoted_by: Some("tester".to_owned()),
            promoted_build_id: Some("build-1".to_owned()),
            allow_insecure_tls: false,
        }))
    }
}

struct World {
    dir: tempfile::TempDir,
    home: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    sshd: common::TestSshd,
    pve: Arc<FakePve>,
    operations: Arc<Operations>,
    executor: Arc<MachineCreateExecutor>,
    config: Arc<GuestConfigExecutor>,
    destroy: Arc<ProxmoxDestructiveExecutor>,
    accounts: Arc<ProxmoxAccountRepository>,
    account_id: String,
    bootstrap_ref: String,
    bootstrap_pub: String,
    keys: Arc<SecretBackedMachineKeys>,
    resolver: Arc<SshAuthResolver>,
    secrets: Arc<fleet_secrets::SecretStore>,
}

impl World {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        std::mem::forget(store);
        let sshd = start_sshd_with_home_keys(home.path());

        let key_file = dir.path().join("master.key");
        std::fs::write(
            &key_file,
            "1 0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let secrets = Arc::new(fleet_secrets::SecretStore::open(pool.clone(), &key_file).unwrap());
        let keys = Arc::new(SecretBackedMachineKeys::new(secrets.clone()));
        let resolver = Arc::new(SshAuthResolver::new(keys.clone()));
        let product_keys = Arc::new(SecretBackedProductKeys::new(secrets.clone()));

        let accounts = Arc::new(ProxmoxAccountRepository::new(pool.clone()));
        let account = accounts
            .create(&NewProxmoxAccount {
                name: "pve".to_owned(),
                host: "pve-api.example.test".to_owned(),
                port: None,
                token_id: "fleet@pve!t".to_owned(),
            })
            .await
            .unwrap();
        accounts
            .set_fingerprint(&account.id, Some(FINGERPRINT.to_owned()))
            .await
            .unwrap();

        // The image's shared bootstrap key: the harness user's key, which
        // the guest's authorized_keys holds at the start.
        let bootstrap_text =
            std::fs::read_to_string(sshd.keys_dir.path().join("user_ed25519")).unwrap();
        let bootstrap_pub = std::fs::read_to_string(sshd.keys_dir.path().join("user_ed25519.pub"))
            .unwrap()
            .trim()
            .to_owned();
        let bootstrap_ref = keys.create(&bootstrap_text, None).await.unwrap();

        let machines: Arc<dyn MachinePort> = Arc::new(MachineRepository::new(pool.clone()));
        let audit = Arc::new(AuditSink::new(pool.clone()));
        let access = Arc::new(
            MachineAccess::new(
                machines.clone(),
                Arc::new(EndpointAuthRepository::new(pool.clone())),
                audit.clone(),
            )
            .with_keys(keys.clone()),
        );
        let pve = FakePve::new();
        let client = fleet_provider_proxmox::ProxmoxClient::new(pve.clone());
        let executor = Arc::new(
            MachineCreateExecutor::new(MachineCreateParts {
                accounts: accounts.clone(),
                credentials: Arc::new(Credentials),
                client: client.clone(),
                artifacts: Arc::new(Artifacts),
                images: Arc::new(Promoted(true)),
                persistent: Arc::new(PersistentGuestRepository::new(pool.clone())),
                machines,
                guest_links: Arc::new(GuestLinkRepository::new(pool.clone())),
                endpoint_auths: Arc::new(EndpointAuthRepository::new(pool.clone())),
                access,
                keys: keys.clone(),
                resolver: resolver.clone(),
                secrets: secrets.clone(),
                product_keys,
                audit: audit.clone(),
                work_dir: dir.path().join("ssh"),
                limiter: ExecutionLimiter::new(4),
            })
            .with_address_override("127.0.0.1")
            .with_poll_interval(Duration::from_millis(5)),
        );
        let config = Arc::new(GuestConfigExecutor::new(
            accounts.clone(),
            Arc::new(Credentials),
            client.clone(),
            Arc::new(Artifacts),
            audit,
        ));
        let destroy = Arc::new(
            ProxmoxDestructiveExecutor::new(accounts.clone(), Arc::new(Credentials), client)
                .with_image_artifacts(Arc::new(Artifacts))
                .with_audit(Arc::new(AuditSink::new(pool.clone())))
                .with_persistent(Arc::new(PersistentGuestRepository::new(pool.clone()))),
        );
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            Arc::new(AuditSink::new(pool.clone())),
        ));
        Self {
            dir,
            home,
            pool,
            sshd,
            pve,
            operations,
            executor,
            config,
            destroy,
            accounts,
            account_id: account.id,
            bootstrap_ref,
            bootstrap_pub,
            keys,
            resolver,
            secrets,
        }
    }

    /// The executor's parts over this world, with another image validator.
    fn parts_with_images(
        &self,
        images: Arc<dyn fleet_application::lab::ImagePinValidator>,
    ) -> MachineCreateParts {
        let pool = self.pool.clone();
        let machines: Arc<dyn MachinePort> = Arc::new(MachineRepository::new(pool.clone()));
        let audit = Arc::new(AuditSink::new(pool.clone()));
        let secrets = self.secrets.clone();
        MachineCreateParts {
            accounts: self.accounts.clone(),
            credentials: Arc::new(Credentials),
            client: fleet_provider_proxmox::ProxmoxClient::new(self.pve.clone()),
            artifacts: Arc::new(Artifacts),
            images,
            persistent: Arc::new(PersistentGuestRepository::new(pool.clone())),
            machines: machines.clone(),
            guest_links: Arc::new(GuestLinkRepository::new(pool.clone())),
            endpoint_auths: Arc::new(EndpointAuthRepository::new(pool.clone())),
            access: Arc::new(
                MachineAccess::new(
                    machines,
                    Arc::new(EndpointAuthRepository::new(pool)),
                    audit.clone(),
                )
                .with_keys(self.keys.clone()),
            ),
            keys: self.keys.clone(),
            resolver: self.resolver.clone(),
            secrets: secrets.clone(),
            product_keys: Arc::new(SecretBackedProductKeys::new(secrets)),
            audit,
            work_dir: self.dir.path().join("ssh"),
            limiter: ExecutionLimiter::new(4),
        }
    }

    fn spec(&self, name: &str) -> Value {
        json!({
            "accountId": self.account_id,
            "imageVersionId": "ver-1",
            "name": name,
            "description": "a permanent box",
            "tags": ["ci"],
            "cores": 4,
            "memoryMib": 4096,
            "bootstrap": {
                "user": whoami(),
                "port": self.sshd.port,
                "auth": { "type": "secret", "credential": self.bootstrap_ref },
            },
            "credential": { "type": "generate" },
            "timeoutSeconds": 120,
        })
    }

    async fn run(
        &self,
        executor: &dyn OperationExecutor,
        kind: &str,
        payload: &Value,
    ) -> Operation {
        let payload = payload.to_string();
        let new = NewOperation {
            kind: kind.to_owned(),
            idempotency_key: None,
            deadline_at: None,
            correlation_id: None,
            review_token: Some(review_token_for(kind, &payload)),
            payload_json: Some(payload),
        };
        let operation = if kind == "machine.create" {
            // Only the dedicated route may queue it (see the generic-route
            // test below).
            self.operations
                .create_machine_create(&fleet_auth::LanAllowAllAuthorizer, &lan().id, &new)
                .await
                .unwrap()
        } else {
            self.operations
                .create(&fleet_auth::LanAllowAllAuthorizer, &lan().id, &new)
                .await
                .unwrap()
        };
        self.operations
            .claim_only_execute(executor, &operation.id, "worker")
            .await
            .unwrap();
        self.operations
            .get(&fleet_auth::LanAllowAllAuthorizer, &lan().id, &operation.id)
            .await
            .unwrap()
    }

    async fn create(&self, spec: &Value) -> Operation {
        self.run(self.executor.as_ref(), "machine.create", spec)
            .await
    }

    fn authorized_keys(&self) -> Vec<String> {
        std::fs::read_to_string(self.home.path().join(".ssh").join("authorized_keys"))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Whether a login with `auth` works on the "guest".
    fn can_log_in(&self, auth: SshAuth) -> bool {
        let provider = SshProvider::new(self.dir.path().join("probe")).unwrap();
        let observation = provider
            .probe_host_key("127.0.0.1", self.sshd.port, Duration::from_secs(10))
            .unwrap();
        provider.pin(&observation).unwrap();
        provider
            .test_connect(
                &SshConnectionSpec {
                    host: "127.0.0.1".to_owned(),
                    port: self.sshd.port,
                    user: whoami(),
                    auth,
                    guest_os: fleet_core::GuestOs::Linux,
                },
                Duration::from_secs(10),
            )
            .is_ok()
    }

    async fn stored_text(&self) -> String {
        let mut text = String::new();
        for sql in [
            "SELECT payload_json, result_json, error_json FROM operations",
            "SELECT metadata_json, action, resource FROM audit_events",
        ] {
            let rows = sqlx::query(sql).fetch_all(&self.pool).await.unwrap();
            for row in rows {
                use sqlx::Row as _;
                for index in 0..3 {
                    if let Ok(Some(value)) = row.try_get::<Option<String>, _>(index) {
                        text.push_str(&value);
                    }
                }
            }
        }
        text
    }
}

fn result_of(operation: &Operation) -> Value {
    serde_json::from_str(operation.result_json.as_deref().unwrap_or("null")).unwrap_or(Value::Null)
}

fn error_of(operation: &Operation) -> Value {
    serde_json::from_str(operation.error_json.as_deref().unwrap_or("null")).unwrap_or(Value::Null)
}

fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|output| output.stdout == b"0\n")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_persistent_vm_is_created_registered_and_rekeyed_in_order() {
    let world = World::new().await;
    let operation = world.create(&world.spec("persist-1")).await;
    assert_eq!(operation.state, "succeeded", "{:?}", error_of(&operation));
    let result = result_of(&operation);
    assert_eq!(result["state"], "ready");
    assert_eq!(result["bootstrapKeyRemoved"], true);
    let vmid = result["vmid"].as_u64().unwrap() as u32;
    assert_eq!(vmid, 7100);

    // Clone, then config (with protection), then start: in that order.
    assert_eq!(
        world.pve.calls(),
        vec![
            format!("clone {TEMPLATE_VMID}"),
            format!("config {vmid}"),
            format!("start {vmid}"),
        ]
    );
    let clone_body = world.pve.body_of("clone").unwrap();
    assert_eq!(clone_body["full"], true);
    assert_eq!(clone_body["name"], "persist-1");

    // The template's fixture tag is never inherited; protection and onboot
    // are set; hardware is applied.
    let guest = world.pve.guest(vmid).unwrap();
    assert_eq!(guest.config["tags"], "ci;fleet-persistent");
    assert_eq!(guest.config["protection"], 1);
    assert_eq!(guest.config["onboot"], 1);
    assert_eq!(guest.config["cores"], 4);
    assert_eq!(guest.config["memory"], 4096);
    assert_eq!(guest.config["description"], "a permanent box");
    assert!(guest.running);
    // The template itself is untouched.
    assert_eq!(
        world.pve.guest(TEMPLATE_VMID).unwrap().config["tags"],
        "fleet-pve-test;image"
    );

    // The marker exists, is ready, and names the machine.
    let pool = world.pool.clone();
    let marker = PersistentGuestRepository::new(pool.clone())
        .get(&world.account_id, vmid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(marker.state, PersistentState::Ready);
    let machine_id = result["machineId"].as_str().unwrap().to_owned();
    assert_eq!(marker.machine_id.as_deref(), Some(machine_id.as_str()));

    // The guest is linked to the machine.
    let link = GuestLinkRepository::new(pool.clone())
        .get(&machine_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((link.vmid, link.guest_kind.as_str()), (vmid, "qemu"));

    // The endpoint now authenticates with a generated key that is not the
    // image's, and the image key no longer logs in.
    let endpoint_id = result["endpointId"].as_str().unwrap();
    let auth = EndpointAuthRepository::new(pool)
        .get(endpoint_id)
        .await
        .unwrap();
    let Some(EndpointAuth::Secret { credential }) = auth else {
        panic!("the endpoint must default to the stored key, got {auth:?}");
    };
    assert_ne!(credential, world.bootstrap_ref);
    assert_eq!(result["credentialRef"], credential.as_str());
    let new_key = world
        .keys
        .resolve(&credential, &machine_id)
        .await
        .unwrap()
        .unwrap();
    assert!(world.can_log_in(SshAuth::StoredKey {
        key: PrivateKey::parse(&new_key).unwrap()
    }));
    let bootstrap_text = world
        .keys
        .resolve(&world.bootstrap_ref, &machine_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !world.can_log_in(SshAuth::StoredKey {
            key: PrivateKey::parse(&bootstrap_text).unwrap()
        }),
        "the image's shared key must be gone"
    );
    let installed = world.authorized_keys();
    assert_eq!(installed.len(), 1);
    assert!(installed[0].starts_with("ssh-ed25519 "));
    assert_ne!(installed[0], world.bootstrap_pub);

    // The host key was confirmed with an audit event.
    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE metadata_json LIKE '%host_key_confirmed%'",
    )
    .fetch_one(&world.pool)
    .await
    .unwrap();
    assert!(audited >= 1);

    // No key reaches an operation record or an audit event.
    let stored = world.stored_text().await;
    assert!(!stored.contains("PRIVATE KEY"));
    for text in [&new_key, &bootstrap_text] {
        let body = text.lines().nth(1).unwrap();
        assert!(!stored.contains(body), "a private key body was stored");
    }
    drop(world.resolver.clone());
}

/// #496: a machine created from a brokered request records who asked and why
/// (the same executor, one extra fact write); a direct create records nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_requested_machine_records_its_owner_and_purpose_and_a_direct_one_does_not() {
    let world = World::new().await;
    let mut spec = world.spec("requested-1");
    spec["requestedBy"] = json!({
        "principal": "credential:ci:cred-1",
        "purpose": "nightly build host",
        "requestId": "req-1",
    });
    let operation = world.create(&spec).await;
    assert_eq!(operation.state, "succeeded", "{:?}", error_of(&operation));
    let result = result_of(&operation);
    assert_eq!(result["requestId"], "req-1");
    // Recorded on the controller's own marker, not as a machine fact.
    let machine_id = result["machineId"].as_str().unwrap().to_owned();
    let markers = PersistentGuestRepository::new(world.pool.clone());
    let owner = markers
        .owner_of_machine(&machine_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.principal, "credential:ci:cred-1");
    assert_eq!(owner.purpose, "nightly build host");
    assert_eq!(owner.request_id, "req-1");
    let count_facts = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM machine_capabilities WHERE namespace = 'fleet'",
        )
        .fetch_one(&world.pool)
        .await
        .unwrap()
    };
    assert_eq!(count_facts().await, 0);

    // A report (fleetd or an SSH inventory) cannot set or replace it.
    let forged = |name: &str, value: &str| fleet_core::CapabilityFact {
        namespace: "fleet".to_owned(),
        name: name.to_owned(),
        value: Some(value.to_owned()),
        status: fleet_core::CapabilityStatus::Known,
        observed_at: fleet_core::Timestamp::from_unix_millis(1),
        source: "fleetd/9".to_owned(),
    };
    fleet_application::machine::MachinePort::record_capabilities(
        &MachineRepository::new(world.pool.clone()),
        &machine_id,
        &[forged("owner", "someone-else"), forged("purpose", "x")],
    )
    .await
    .unwrap();
    assert_eq!(
        count_facts().await,
        0,
        "the fleet namespace is never written from a report"
    );
    assert_eq!(
        markers
            .owner_of_machine(&machine_id)
            .await
            .unwrap()
            .unwrap()
            .principal,
        "credential:ci:cred-1"
    );

    // The use case drops fleet facts and records the rest of the batch.
    let machines = fleet_application::machine::Machines::new(
        Arc::new(MachineRepository::new(world.pool.clone())),
        Arc::new(AuditSink::new(world.pool.clone())),
    );
    let mut os_fact = forged("distribution", "ubuntu");
    os_fact.namespace = "os".to_owned();
    machines
        .record_capabilities(
            &fleet_auth::LanAllowAllAuthorizer,
            &fleet_application::authz::ActingPrincipal {
                id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
            },
            &machine_id,
            &[forged("owner", "x"), os_fact],
        )
        .await
        .unwrap();
    assert_eq!(count_facts().await, 0);
    let os_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM machine_capabilities WHERE namespace = 'os' AND name = 'distribution'",
    )
    .fetch_one(&world.pool)
    .await
    .unwrap();
    assert_eq!(os_rows, 1);

    // The brokered creation's audit event carries the request id and the
    // operation, linking it to the request's own events.
    let linked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE operation_id = ?1 \
         AND metadata_json LIKE '%machine_provision_requested%' \
         AND metadata_json LIKE '%\"requestId\":\"req-1\"%'",
    )
    .bind(&operation.id)
    .fetch_one(&world.pool)
    .await
    .unwrap();
    assert_eq!(linked, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_direct_machine_records_no_owner_facts() {
    let world = World::new().await;
    let operation = world.create(&world.spec("direct-1")).await;
    assert_eq!(operation.state, "succeeded", "{:?}", error_of(&operation));
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM machine_capabilities WHERE namespace = 'fleet'")
            .fetch_one(&world.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_install_leaves_the_image_key_working_and_nothing_removed() {
    if is_root() {
        // Root can create the user, so the injected failure would not occur.
        eprintln!(
            "SKIPPED a_failed_install_leaves_the_image_key_working_and_nothing_removed: running as root, where the failure injection (a login user that needs root to create) cannot fail"
        );
        return;
    }
    let world = World::new().await;
    // A login user other than the image's needs root to create: the install
    // step fails before it changes anything.
    let mut spec = world.spec("persist-2");
    spec["loginUser"] = json!("someone-else");
    let failed = world.create(&spec).await;
    assert_eq!(failed.state, "failed");
    let error = error_of(&failed);
    assert_eq!(error["step"], "credential");
    assert_eq!(error["reason"], "install_failed");
    // The VM and the machine are kept; nothing was installed or removed; the
    // image key still works and no default auth was recorded.
    assert!(world.pve.guest(7100).is_some());
    assert_eq!(world.authorized_keys(), vec![world.bootstrap_pub.clone()]);
    let bootstrap_text = world
        .keys
        .resolve(&world.bootstrap_ref, "")
        .await
        .unwrap()
        .unwrap();
    assert!(world.can_log_in(SshAuth::StoredKey {
        key: PrivateKey::parse(&bootstrap_text).unwrap()
    }));
    let machine = MachineRepository::new(world.pool.clone())
        .get(error["machineId"].as_str().unwrap())
        .await
        .unwrap();
    assert!(
        EndpointAuthRepository::new(world.pool.clone())
            .get(&machine.endpoints[0].id)
            .await
            .unwrap()
            .is_none()
    );
    let marker = PersistentGuestRepository::new(world.pool.clone())
        .get(&world.account_id, 7100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(marker.state, PersistentState::Creating);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rerun_after_a_failure_adopts_the_guest_instead_of_cloning_again() {
    let world = World::new().await;
    let spec = world.spec("persist-7");
    world.pve.fail_next_starts(1);
    let failed = world.create(&spec).await;
    assert_eq!(failed.state, "failed");
    assert_eq!(error_of(&failed)["step"], "start");
    assert_eq!(error_of(&failed)["vmid"], 7100);
    let resumed = world.create(&spec).await;
    assert_eq!(resumed.state, "succeeded", "{:?}", error_of(&resumed));
    let calls = world.pve.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.starts_with("clone"))
            .count(),
        1,
        "a re-run must not clone twice: {calls:?}"
    );
    assert_eq!(result_of(&resumed)["vmid"], 7100);
    assert_eq!(
        PersistentGuestRepository::new(world.pool.clone())
            .get(&world.account_id, 7100)
            .await
            .unwrap()
            .unwrap()
            .state,
        PersistentState::Ready
    );
}

fn stamped(mut spec: Value, request: &str) -> Value {
    spec["requestedBy"] = json!({
        "principal": "credential:ci:cred-1",
        "purpose": "nightly build host",
        "requestId": request,
        "approvedBy": "operator",
    });
    spec
}

/// #496: a half-made guest is resumed only by the request (or the direct
/// create) that started it; nothing else adopts it.
#[tokio::test(flavor = "multi_thread")]
async fn a_half_made_guest_is_not_adopted_by_another_request_or_a_direct_create() {
    // Request A fails part-way; request B for the same name is refused.
    let world = World::new().await;
    let a = stamped(world.spec("persist-9"), "req-a");
    world.pve.fail_next_starts(1);
    let a1 = world.create(&a).await;
    assert_eq!(a1.state, "failed");
    let b = world
        .create(&stamped(world.spec("persist-9"), "req-b"))
        .await;
    assert_eq!(b.state, "failed");
    assert_eq!(error_of(&b)["reason"], "conflict", "{:?}", error_of(&b));
    // A direct create does not adopt a brokered marker either.
    let direct = world.create(&world.spec("persist-9")).await;
    assert_eq!(error_of(&direct)["reason"], "conflict");
    let owner = PersistentGuestRepository::new(world.pool.clone())
        .owner_of(&world.account_id, 7100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.request_id, "req-a", "the owner is never replaced");
    // The request that started it resumes it, and the creation's audit event
    // was written once, on the first run only.
    let resumed = world.create(&a).await;
    assert_eq!(resumed.state, "succeeded", "{:?}", error_of(&resumed));
    let events: Vec<(String, String)> = sqlx::query_as(
        "SELECT actor, metadata_json FROM audit_events \
         WHERE intent_seq IS NULL AND metadata_json LIKE '%machine_provision_requested%'",
    )
    .fetch_all(&world.pool)
    .await
    .unwrap();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].0, "system:machine-create");
    for needle in [
        "\"requestId\":\"req-a\"",
        "\"requester\":\"credential:ci:cred-1\"",
        "\"approver\":\"operator\"",
    ] {
        assert!(events[0].1.contains(needle), "{needle} in {}", events[0].1);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_brokered_request_does_not_adopt_a_half_made_direct_guest() {
    let world = World::new().await;
    world.pve.fail_next_starts(1);
    assert_eq!(world.create(&world.spec("persist-8")).await.state, "failed");
    let brokered = world
        .create(&stamped(world.spec("persist-8"), "req-a"))
        .await;
    assert_eq!(brokered.state, "failed");
    assert_eq!(error_of(&brokered)["reason"], "conflict");
    assert!(
        PersistentGuestRepository::new(world.pool.clone())
            .owner_of(&world.account_id, 7100)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_public_key_is_installed_and_the_image_key_is_kept() {
    let world = World::new().await;
    let provider = SshProvider::new(world.dir.path().join("keygen")).unwrap();
    let operator = provider.generate_ed25519("operator").unwrap();
    let mut spec = world.spec("persist-3");
    spec["credential"] = json!({ "type": "publicKey", "publicKey": operator.public });
    let operation = world.create(&spec).await;
    assert_eq!(operation.state, "succeeded", "{:?}", error_of(&operation));
    let result = result_of(&operation);
    // Fleet cannot verify a key it does not hold, so it removes nothing and
    // keeps the credential it has.
    assert_eq!(result["bootstrapKeyRemoved"], false);
    assert!(result["credentialRef"].is_null());
    assert_eq!(
        world.authorized_keys(),
        vec![world.bootstrap_pub.clone(), operator.public.clone()]
    );
    let auth = EndpointAuthRepository::new(world.pool.clone())
        .get(result["endpointId"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        auth,
        Some(EndpointAuth::Secret {
            credential: world.bootstrap_ref.clone()
        })
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_fingerprint_that_does_not_match_stops_before_any_login() {
    let world = World::new().await;
    let mut spec = world.spec("persist-4");
    spec["hostKey"] = json!({ "mode": "pinned", "fingerprint": "SHA256:notthekey" });
    let operation = world.create(&spec).await;
    assert_eq!(operation.state, "failed");
    assert_eq!(error_of(&operation)["reason"], "host_key_mismatch");
    // The guest is kept, the authorized keys are untouched.
    assert_eq!(world.authorized_keys(), vec![world.bootstrap_pub.clone()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_name_or_vmid_that_is_not_ours_is_a_conflict_and_nothing_is_cloned() {
    let world = World::new().await;
    let mut spec = world.spec("persist-5");
    spec["vmid"] = json!(TEMPLATE_VMID);
    let operation = world.create(&spec).await;
    assert_eq!(operation.state, "failed");
    assert_eq!(error_of(&operation)["reason"], "conflict");
    assert!(world.pve.calls().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_guest_config_action_is_an_allow_list_that_refuses_templates_and_lab_guests() {
    let world = World::new().await;
    let created = world.create(&world.spec("persist-6")).await;
    assert_eq!(created.state, "succeeded", "{:?}", error_of(&created));
    let vmid = result_of(&created)["vmid"].as_u64().unwrap();
    let config = |vmid: u64, params: Value| {
        json!({
            "accountId": world.account_id,
            "node": "pve",
            "vmid": vmid,
            "timeoutSeconds": 300,
            "params": params,
        })
    };

    // Lifting protection is the first step of destroying it.
    let lifted = world
        .run(
            world.config.as_ref(),
            "proxmox.guest.config",
            &config(vmid, json!({ "protection": false })),
        )
        .await;
    assert_eq!(lifted.state, "succeeded", "{:?}", error_of(&lifted));
    assert_eq!(
        world.pve.guest(vmid as u32).unwrap().config["protection"],
        0
    );
    assert_eq!(result_of(&lifted)["applied"], json!(["protection"]));

    // A key outside the allow-list is refused with no write.
    let writes = world.pve.calls().len();
    let refused = world
        .run(
            world.config.as_ref(),
            "proxmox.guest.config",
            &config(vmid, json!({ "net0": "virtio,bridge=vmbr9" })),
        )
        .await;
    assert_eq!(refused.state, "failed");
    assert_eq!(error_of(&refused)["reason"], "invalid_params");
    assert_eq!(world.pve.calls().len(), writes);

    // The image template is never reconfigured.
    let template = world
        .run(
            world.config.as_ref(),
            "proxmox.guest.config",
            &config(u64::from(TEMPLATE_VMID), json!({ "protection": false })),
        )
        .await;
    assert_eq!(template.state, "failed");
    assert_eq!(error_of(&template)["reason"], "refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn destroying_a_persistent_vm_is_a_separate_confirmed_act_that_lifts_protection_first() {
    let world = World::new().await;
    let created = world.create(&world.spec("persist-8")).await;
    assert_eq!(created.state, "succeeded", "{:?}", error_of(&created));
    let vmid = result_of(&created)["vmid"].as_u64().unwrap();
    let destroy = |params: Value| {
        json!({
            "accountId": world.account_id,
            "node": "pve",
            "vmid": vmid,
            "timeoutSeconds": 300,
            "params": params,
        })
    };

    // The plain destroy a Lab or an operator reflex would send is refused
    // before any Proxmox call.
    let calls = world.pve.calls().len();
    let plain = world
        .run(
            world.destroy.as_ref(),
            "proxmox.guest.destroy",
            &destroy(json!({ "purge": false })),
        )
        .await;
    assert_eq!(plain.state, "failed");
    assert_eq!(error_of(&plain)["reason"], "persistent_guest");
    assert_eq!(world.pve.calls().len(), calls);

    assert_eq!(
        world.pve.guest(vmid as u32).unwrap().config["protection"],
        1
    );
    let markers = PersistentGuestRepository::new(world.pool.clone());
    assert!(
        markers
            .get(&world.account_id, vmid as u32)
            .await
            .unwrap()
            .is_some()
    );

    // The confirmed destroy lifts the protection itself, audited, then
    // deletes: no separate config step is needed.
    let destroyed = world
        .run(
            world.destroy.as_ref(),
            "proxmox.guest.destroy",
            &destroy(json!({ "purge": false, "confirmPersistent": true })),
        )
        .await;
    assert_eq!(destroyed.state, "succeeded", "{:?}", error_of(&destroyed));
    assert!(world.pve.guest(vmid as u32).is_none());
    let lifted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE metadata_json LIKE '%persistent_protection_lifted%'",
    )
    .fetch_one(&world.pool)
    .await
    .unwrap();
    assert!(lifted >= 1);
    // The marker goes with the guest, so the VMID and name are free again.
    assert!(
        markers
            .get(&world.account_id, vmid as u32)
            .await
            .unwrap()
            .is_none()
    );
    let _ = &world.accounts;
}

#[tokio::test(flavor = "multi_thread")]
async fn lab_never_selects_a_persistent_guest_whatever_its_name() {
    use fleet_application::lab_pool::PoolGuestPort as _;
    use fleet_controller::lab_pool::ProxmoxPoolGuests;
    use fleet_controller::lab_sweeper::{LabGuestInventory as _, ProxmoxLabGuests};

    let world = World::new().await;
    // A guest that carries the Lab name prefix but was made persistent: the
    // marker, not the name, decides.
    {
        let mut state = world.pve.state.lock().unwrap();
        for (vmid, name) in [(7200_u32, "fm-lab-orphan"), (7201, "fm-lab-kept")] {
            state.guests.insert(
                vmid,
                Guest {
                    name: name.to_owned(),
                    template: false,
                    running: false,
                    config: serde_json::Map::new(),
                    locked_reads: 0,
                },
            );
        }
    }
    let markers = Arc::new(PersistentGuestRepository::new(world.pool.clone()));
    markers
        .reserve(&fleet_application::persistent::PersistentGuest {
            account_id: world.account_id.clone(),
            vmid: 7201,
            name: "fm-lab-kept".to_owned(),
            node: "pve".to_owned(),
            image_version_id: "ver-1".to_owned(),
            machine_id: None,
            cloned: true,
            state: PersistentState::Ready,
            step: None,
            operation_id: None,
            created_at: 1,
            updated_at: 1,
        })
        .await
        .unwrap();
    let client = fleet_provider_proxmox::ProxmoxClient::new(world.pve.clone());

    // The sweeper's inventory reports the orphan and leaves the persistent
    // guest out.
    let inventory = ProxmoxLabGuests::new(
        world.accounts.clone(),
        Arc::new(Credentials),
        client.clone(),
    )
    .with_persistent(markers.clone());
    let vmids: Vec<u32> = inventory
        .lab_guests()
        .await
        .iter()
        .map(|g| g.vmid)
        .collect();
    assert_eq!(vmids, vec![7200]);

    // A pool never takes it, and the refusal says why.
    let pools = ProxmoxPoolGuests::new(
        world.accounts.clone(),
        Arc::new(Credentials),
        client,
        Arc::new(Artifacts),
    )
    .with_persistent(markers);
    let refused = pools.observe(&world.account_id, 7201, "baseline").await;
    assert!(refused.unwrap_err().contains("persistent"));
    // Any other guest is not refused for that reason (the fake host has no
    // snapshot listing, so the read may fail for its own).
    if let Err(other) = pools.observe(&world.account_id, 7200, "baseline").await {
        assert!(!other.contains("persistent"), "{other}");
    }
}

fn marker(
    account: &str,
    vmid: u32,
    name: &str,
    cloned: bool,
) -> fleet_application::persistent::PersistentGuest {
    fleet_application::persistent::PersistentGuest {
        account_id: account.to_owned(),
        vmid,
        name: name.to_owned(),
        node: "pve".to_owned(),
        image_version_id: "ver-1".to_owned(),
        machine_id: None,
        cloned,
        state: PersistentState::Creating,
        step: None,
        operation_id: None,
        created_at: 1,
        updated_at: 1,
    }
}

fn plain_guest(name: &str) -> Guest {
    Guest {
        name: name.to_owned(),
        template: false,
        running: false,
        config: serde_json::Map::new(),
        locked_reads: 0,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_clone_with_nothing_at_the_vmid_leaves_no_marker() {
    let world = World::new().await;
    world.pve.fail_next_clones(1);
    let failed = world.create(&world.spec("persist-9")).await;
    assert_eq!(failed.state, "failed");
    assert_eq!(error_of(&failed)["step"], "clone");
    let markers = PersistentGuestRepository::new(world.pool.clone());
    assert!(
        markers.list().await.unwrap().is_empty(),
        "a stale marker was left"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_marker_shields_no_other_guest_but_a_completed_clone_always_does() {
    use fleet_application::lab_pool::PoolGuestPort as _;
    use fleet_controller::lab_pool::ProxmoxPoolGuests;
    use fleet_controller::lab_sweeper::LabGuestInventory as _;

    let world = World::new().await;
    {
        let mut state = world.pve.state.lock().unwrap();
        // 7300: a stale marker (clone never completed) over an unrelated
        // Lab guest; 7301: a completed clone, renamed by hand.
        state.guests.insert(7300, plain_guest("fm-lab-real-lease"));
        state.guests.insert(7301, plain_guest("fm-lab-renamed"));
    }
    let markers = Arc::new(PersistentGuestRepository::new(world.pool.clone()));
    markers
        .reserve(&marker(&world.account_id, 7300, "build-box", false))
        .await
        .unwrap();
    markers
        .reserve(&marker(&world.account_id, 7301, "build-box-2", true))
        .await
        .unwrap();
    let client = fleet_provider_proxmox::ProxmoxClient::new(world.pve.clone());

    // The sweeper still sees the Lab guest under the stale marker, and not
    // the completed clone.
    let inventory = fleet_controller::lab_sweeper::ProxmoxLabGuests::new(
        world.accounts.clone(),
        Arc::new(Credentials),
        client.clone(),
    )
    .with_persistent(markers.clone());
    let vmids: Vec<u32> = inventory
        .lab_guests()
        .await
        .iter()
        .map(|g| g.vmid)
        .collect();
    assert_eq!(vmids, vec![7300]);

    let pools = ProxmoxPoolGuests::new(
        world.accounts.clone(),
        Arc::new(Credentials),
        client,
        Arc::new(Artifacts),
    )
    .with_persistent(markers.clone());
    if let Err(error) = pools.observe(&world.account_id, 7300, "baseline").await {
        assert!(!error.contains("persistent"), "{error}");
    }
    assert!(
        pools
            .observe(&world.account_id, 7301, "baseline")
            .await
            .unwrap_err()
            .contains("persistent")
    );

    // The destroy executor honours only the guarding marker: the stale one
    // does not ask for the confirmation, the completed one does.
    let destroy = |vmid: u32| {
        json!({
            "accountId": world.account_id, "node": "pve", "vmid": vmid,
            "timeoutSeconds": 300, "params": { "purge": false },
        })
    };
    let stale = world
        .run(
            world.destroy.as_ref(),
            "proxmox.guest.destroy",
            &destroy(7300),
        )
        .await;
    assert_ne!(error_of(&stale)["reason"], "persistent_guest");
    let guarded = world
        .run(
            world.destroy.as_ref(),
            "proxmox.guest.destroy",
            &destroy(7301),
        )
        .await;
    assert_eq!(error_of(&guarded)["reason"], "persistent_guest");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_abandon_is_reviewed_audited_and_refuses_a_created_machine() {
    use fleet_application::persistent::PersistentMachines;

    let world = World::new().await;
    let markers = Arc::new(PersistentGuestRepository::new(world.pool.clone()));
    markers
        .reserve(&marker(&world.account_id, 7400, "never-made", false))
        .await
        .unwrap();
    markers
        .reserve(&marker(&world.account_id, 7401, "made", true))
        .await
        .unwrap();
    let access = PersistentMachines::new(
        Arc::new(Promoted(true)),
        Arc::new(AuditSink::new(world.pool.clone())),
    )
    .with_markers(markers.clone())
    .with_abandon_guard(Arc::new(
        fleet_controller::persistent_machines::ProxmoxAbandonGuard::new(
            Arc::new(OperationRepository::new(world.pool.clone())),
            world.accounts.clone(),
            Arc::new(Credentials),
            fleet_provider_proxmox::ProxmoxClient::new(world.pve.clone()),
        ),
    ));
    let allow = fleet_auth::LanAllowAllAuthorizer;

    // Not stale yet: a guest with the marked name exists at another VMID, or
    // the creation operation is still queued.
    world
        .pve
        .state
        .lock()
        .unwrap()
        .guests
        .insert(7410, plain_guest("named-elsewhere"));
    markers
        .reserve(&marker(&world.account_id, 7402, "named-elsewhere", false))
        .await
        .unwrap();
    let (_, token) = PersistentMachines::abandon_payload(&world.account_id, 7402);
    let refused = access
        .abandon(&allow, &lan(), &world.account_id, 7402, &token)
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("7410"), "{refused}");
    let queued = world
        .operations
        .create(
            &allow,
            &lan().id,
            &NewOperation {
                kind: "noop".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                review_token: None,
                payload_json: None,
            },
        )
        .await
        .unwrap();
    let mut running = marker(&world.account_id, 7403, "still-running", false);
    running.operation_id = Some(queued.id.clone());
    markers.reserve(&running).await.unwrap();
    let (_, token) = PersistentMachines::abandon_payload(&world.account_id, 7403);
    let refused = access
        .abandon(&allow, &lan(), &world.account_id, 7403, &token)
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("still"), "{refused}");
    assert!(
        markers
            .get(&world.account_id, 7403)
            .await
            .unwrap()
            .is_some()
    );

    // A token for another VMID does not abandon.
    let (_, other) = PersistentMachines::abandon_payload(&world.account_id, 7401);
    assert!(
        access
            .abandon(&allow, &lan(), &world.account_id, 7400, &other)
            .await
            .is_err()
    );
    assert!(
        markers
            .get(&world.account_id, 7400)
            .await
            .unwrap()
            .is_some()
    );
    // A created machine is destroyed, not abandoned, even with its token.
    assert!(
        access
            .abandon(&allow, &lan(), &world.account_id, 7401, &other)
            .await
            .is_err()
    );
    assert!(
        markers
            .get(&world.account_id, 7401)
            .await
            .unwrap()
            .is_some()
    );

    let (_, token) = PersistentMachines::abandon_payload(&world.account_id, 7400);
    access
        .abandon(&allow, &lan(), &world.account_id, 7400, &token)
        .await
        .unwrap();
    assert!(
        markers
            .get(&world.account_id, 7400)
            .await
            .unwrap()
            .is_none()
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE metadata_json LIKE '%persistent_marker_abandoned%'",
    )
    .fetch_one(&world.pool)
    .await
    .unwrap();
    assert_eq!(audited, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn machine_create_is_refused_on_the_generic_route_and_needs_a_promoted_pinned_image() {
    let world = World::new().await;
    let payload = world.spec("persist-10").to_string();
    let new = |token: String| NewOperation {
        kind: "machine.create".to_owned(),
        idempotency_key: None,
        deadline_at: None,
        correlation_id: None,
        review_token: Some(token),
        payload_json: Some(payload.clone()),
    };
    let generic = world
        .operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan().id,
            &new(review_token_for("machine.create", &payload)),
        )
        .await;
    assert!(
        generic
            .unwrap_err()
            .to_string()
            .contains("machine create route")
    );
    // The dedicated route still demands the review token.
    let unreviewed = world
        .operations
        .create_machine_create(
            &fleet_auth::LanAllowAllAuthorizer,
            &lan().id,
            &new("0".repeat(64)),
        )
        .await;
    assert!(unreviewed.is_err());

    // The executor re-checks promotion: a version demoted since the review
    // does not clone.
    let demoted = Arc::new(MachineCreateExecutor::new(
        world.parts_with_images(Arc::new(Promoted(false))),
    ));
    let operation = world
        .run(
            demoted.as_ref(),
            "machine.create",
            &world.spec("persist-10"),
        )
        .await;
    assert_eq!(operation.state, "failed");
    assert_eq!(error_of(&operation)["reason"], "image_not_promoted");
    assert!(world.pve.calls().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_finished_machine_is_not_adopted_and_a_rerun_must_use_the_same_image() {
    let world = World::new().await;
    let spec = world.spec("persist-11");
    let created = world.create(&spec).await;
    assert_eq!(created.state, "succeeded", "{:?}", error_of(&created));
    let again = world.create(&spec).await;
    assert_eq!(again.state, "failed");
    assert_eq!(error_of(&again)["reason"], "conflict");

    // An unfinished creation resumes only with the image it started from.
    world.pve.fail_next_starts(1);
    let mut second = world.spec("persist-12");
    let failed = world.create(&second).await;
    assert_eq!(failed.state, "failed");
    second["imageVersionId"] = json!("ver-2");
    let mismatched = world.create(&second).await;
    assert_eq!(mismatched.state, "failed");
    assert_eq!(error_of(&mismatched)["reason"], "conflict");
    assert!(
        error_of(&mismatched)["detail"]
            .as_str()
            .unwrap()
            .contains("ver-1")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_address_that_is_another_machines_endpoint_or_not_this_vms_nic_is_refused() {
    let world = World::new().await;
    // Another machine already owns 127.0.0.1:<port>.
    MachineRepository::new(world.pool.clone())
        .register(&fleet_application::machine::RegisterMachine {
            name: "squatter".to_owned(),
            description: String::new(),
            endpoints: vec![fleet_application::machine::NewEndpoint {
                kind: fleet_core::EndpointKind::Ssh,
                reference: format!("root@127.0.0.1:{}", world.sshd.port),
            }],
            tags: vec![],
            groups: vec![],
        })
        .await
        .unwrap();
    let operation = world.create(&world.spec("persist-13")).await;
    assert_eq!(operation.state, "failed");
    assert_eq!(error_of(&operation)["reason"], "address_in_use");
    assert!(
        error_of(&operation)["detail"]
            .as_str()
            .unwrap()
            .contains("squatter")
    );

    // An agent that reports no interface with the VM's MAC is not trusted.
    let world = World::new().await;
    world.pve.set_agent_mac("de:ad:be:ef:00:99");
    let operation = world.create(&world.spec("persist-14")).await;
    assert_eq!(operation.state, "failed");
    assert_eq!(error_of(&operation)["reason"], "address_mismatch");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failure_after_the_switch_resumes_without_a_second_key() {
    let world = World::new().await;
    // The removal writes a temporary file next to authorized_keys: a
    // directory in its place makes the removal fail after the switch.
    let blocker = world
        .home
        .path()
        .join(".ssh")
        .join("authorized_keys.fleet-new");
    std::fs::create_dir_all(&blocker).unwrap();
    let spec = world.spec("persist-15");
    let failed = world.create(&spec).await;
    assert_eq!(failed.state, "failed");
    let error = error_of(&failed);
    assert_eq!(error["reason"], "revoke_failed");
    let machine_id = error["machineId"].as_str().unwrap().to_owned();
    // Switched already, both keys still accepted.
    let machine = MachineRepository::new(world.pool.clone())
        .get(&machine_id)
        .await
        .unwrap();
    let auth = EndpointAuthRepository::new(world.pool.clone())
        .get(&machine.endpoints[0].id)
        .await
        .unwrap();
    assert!(
        matches!(auth, Some(EndpointAuth::Secret { ref credential }) if *credential != world.bootstrap_ref)
    );
    assert_eq!(world.authorized_keys().len(), 2);

    // The blocker goes; the same command resumes without the image key.
    std::fs::remove_dir(&blocker).unwrap();
    let resumed = world.create(&spec).await;
    assert_eq!(resumed.state, "succeeded", "{:?}", error_of(&resumed));
    assert_eq!(result_of(&resumed)["bootstrapKeyRemoved"], true);
    assert_eq!(world.authorized_keys().len(), 1);
    // One generated key for the machine, no pile-up.
    assert_eq!(
        world
            .keys
            .list_for_machine(&machine_id)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_machine_deletes_its_bound_keys() {
    let world = World::new().await;
    let created = world.create(&world.spec("persist-16")).await;
    assert_eq!(created.state, "succeeded", "{:?}", error_of(&created));
    let machine_id = result_of(&created)["machineId"]
        .as_str()
        .unwrap()
        .to_owned();
    let bound = world.keys.list_for_machine(&machine_id).await.unwrap();
    assert_eq!(bound.len(), 1);
    let machines = fleet_application::machine::Machines::new(
        Arc::new(MachineRepository::new(world.pool.clone())),
        Arc::new(AuditSink::new(world.pool.clone())),
    )
    .with_key_revocation(world.keys.clone());
    machines
        .delete(&fleet_auth::LanAllowAllAuthorizer, &lan(), &machine_id)
        .await
        .unwrap();
    assert!(
        world
            .keys
            .list_for_machine(&machine_id)
            .await
            .unwrap()
            .is_empty()
    );
    // The shared bootstrap key is not bound to the machine and stays.
    assert!(
        world
            .keys
            .resolve(&world.bootstrap_ref, "")
            .await
            .unwrap()
            .is_some()
    );
}

const PRODUCT_KEY: &str = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE";

/// Runs inside a child process whose `ssh` is a recording fake that answers
/// every Windows session with the result lines the real scripts print.
async fn windows_with_the_product_key(root: &std::path::Path, license: &str) {
    use fleet_application::persistent::ProductKeyPort as _;
    let world = World::new().await;
    let product_key = SecretBackedProductKeys::new(world.secrets.clone())
        .create(PRODUCT_KEY)
        .await
        .unwrap();
    let mut spec = world.spec("win-box");
    spec["guestOs"] = json!("windows");
    spec["bootstrap"]["user"] = json!("fleetadmin");
    spec["windows"] = json!({
        "adminPassword": "store",
        "activation": { "type": "productKey", "secret": product_key },
    });
    let operation = world.create(&spec).await;
    let expect_activated = license == "1";
    assert_eq!(
        operation.state,
        if expect_activated {
            "succeeded"
        } else {
            "failed"
        },
        "{:?}",
        error_of(&operation)
    );
    if !expect_activated {
        assert_eq!(error_of(&operation)["step"], "activation");
    }

    // The key is in no operation record and no audit event, and neither is
    // the administrator password the guest printed.
    let stored = world.stored_text().await;
    assert!(!stored.contains(PRODUCT_KEY), "the product key was stored");
    assert!(
        !stored.contains("FLEETPASSWORD0123456789"),
        "a password leaked"
    );
    assert!(!stored.contains("PRIVATE KEY"));

    // It reached the guest on stdin only, in exactly one session, and not in
    // any argument list or environment.
    use base64::Engine as _;
    let log = root.join("log");
    let args = std::fs::read_to_string(log.join("args")).unwrap();
    let env = std::fs::read_to_string(log.join("env")).unwrap();
    assert!(!args.contains(PRODUCT_KEY) && !env.contains(PRODUCT_KEY));
    let sessions = std::fs::read_to_string(log.join("stdin")).unwrap();
    let with_key = sessions
        .lines()
        .filter_map(|line| base64::engine::general_purpose::STANDARD.decode(line).ok())
        .filter(|script| String::from_utf8_lossy(script).contains(PRODUCT_KEY))
        .count();
    assert_eq!(
        with_key, 1,
        "the key must be in exactly one session's script"
    );
    assert!(!sessions.contains(PRODUCT_KEY));
    // The activation outcome is a machine fact either way.
    let fact: Option<String> = sqlx::query_scalar(
        "SELECT value FROM machine_capabilities WHERE namespace = 'windows' AND name = 'activation'",
    )
    .fetch_optional(&world.pool)
    .await
    .unwrap();
    assert_eq!(
        fact.as_deref(),
        Some(if expect_activated {
            "licensed"
        } else {
            "notification"
        })
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_product_key_reaches_the_guest_on_stdin_only_and_no_record_holds_it() {
    use std::os::unix::fs::PermissionsExt as _;
    if let Ok(root) = std::env::var("FLEET_PRODUCT_KEY_CHILD") {
        let license = std::env::var("FLEET_FAKE_LICENSE").unwrap();
        windows_with_the_product_key(std::path::Path::new(&root), &license).await;
        return;
    }
    // The parent prepares the fake `ssh` and re-runs this test in a child
    // whose PATH starts with it (the environment of a running process
    // cannot be changed safely), once for a successful activation and once
    // for a failed one.
    for license in ["1", "5"] {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        let log = root.path().join("log");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&log).unwrap();
        let fake = bin.join("ssh");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" >> {log}/args\nenv >> {log}/env\ncat >> {log}/stdin\nprintf 'FLEET_RENAMED=0\\nFLEET_AUTHORIZED_KEYS=x\\nFLEET_LOGIN_OK\\nFLEET_ROTATED=1\\nFLEET_PASSWORD=FLEETPASSWORD0123456789\\nFLEET_ATO=ok\\nFLEET_LICENSE_STATUS={license}\\nFLEET_XPR=x\\n'\n",
                log = log.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "the_product_key_reaches_the_guest_on_stdin_only_and_no_record_holds_it",
                "--nocapture",
            ])
            .env("PATH", path)
            .env("FLEET_PRODUCT_KEY_CHILD", root.path())
            .env("FLEET_FAKE_LICENSE", license)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "the child run failed for license {license}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repository_credential_is_not_a_persistent_machines_ssh_key() {
    use fleet_application::persistent::{CredentialChoice, PersistentMachines};
    let world = World::new().await;
    let key_text =
        std::fs::read_to_string(world.sshd.keys_dir.path().join("user_ed25519")).unwrap();
    let git = world
        .secrets
        .create(
            "git/some-repo",
            fleet_secrets::SecretValue::new(key_text.trim().as_bytes().to_vec()),
        )
        .await
        .unwrap();
    let access = PersistentMachines::new(
        Arc::new(Promoted(true)),
        Arc::new(AuditSink::new(world.pool.clone())),
    )
    .with_keys(world.keys.clone());
    let mut spec: fleet_application::persistent::CreateMachineSpec =
        serde_json::from_value(world.spec("persist-17")).unwrap();
    spec.credential = CredentialChoice::Reference {
        credential: git.id.clone(),
    };
    let refused = access
        .prepare(&fleet_auth::LanAllowAllAuthorizer, &lan(), &spec)
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("repository"), "{refused}");
    // A key stored as a machine key is accepted.
    spec.credential = CredentialChoice::Reference {
        credential: world.bootstrap_ref.clone(),
    };
    access
        .prepare(&fleet_auth::LanAllowAllAuthorizer, &lan(), &spec)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rerun_with_another_credential_choice_is_refused_and_rewrites_nothing() {
    let world = World::new().await;
    // A Fleet-held key B the operator names; the removal is blocked so the
    // first run fails after the switch to B.
    let provider = SshProvider::new(world.dir.path().join("keygen")).unwrap();
    let other = provider.generate_ed25519("other").unwrap();
    let other_ref = world
        .keys
        .create(other.private.expose_for_store(), None)
        .await
        .unwrap();
    let blocker = world
        .home
        .path()
        .join(".ssh")
        .join("authorized_keys.fleet-new");
    std::fs::create_dir_all(&blocker).unwrap();
    let mut spec = world.spec("persist-19");
    spec["credential"] = json!({ "type": "reference", "credential": other_ref });
    let failed = world.create(&spec).await;
    assert_eq!(error_of(&failed)["reason"], "revoke_failed");
    assert_eq!(world.authorized_keys().len(), 2);
    let before = world.authorized_keys();

    // The same machine, asked for a generated key this time: refused before
    // any session, and authorized_keys is untouched.
    std::fs::remove_dir(&blocker).unwrap();
    spec["credential"] = json!({ "type": "generate" });
    let refused = world.create(&spec).await;
    assert_eq!(refused.state, "failed");
    assert_eq!(error_of(&refused)["reason"], "credential_changed");
    assert_eq!(world.authorized_keys(), before);
    // And the original choice still resumes.
    spec["credential"] = json!({ "type": "reference", "credential": other_ref });
    let resumed = world.create(&spec).await;
    assert_eq!(resumed.state, "succeeded", "{:?}", error_of(&resumed));
    assert_eq!(world.authorized_keys(), vec![other.public.clone()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_guard_refusal_leaves_a_persistent_guests_protection_on() {
    let world = World::new().await;
    // A marker over the image template: the guards refuse to destroy a
    // template, and that refusal must come before protection is touched.
    let markers = PersistentGuestRepository::new(world.pool.clone());
    markers
        .reserve(&marker(
            &world.account_id,
            TEMPLATE_VMID,
            "fleet-image",
            true,
        ))
        .await
        .unwrap();
    assert_eq!(
        world.pve.guest(TEMPLATE_VMID).unwrap().config["protection"],
        1
    );
    let refused = world
        .run(
            world.destroy.as_ref(),
            "proxmox.guest.destroy",
            &json!({
                "accountId": world.account_id, "node": "pve", "vmid": TEMPLATE_VMID,
                "timeoutSeconds": 300,
                "params": { "purge": false, "confirmPersistent": true },
            }),
        )
        .await;
    assert_eq!(refused.state, "failed");
    assert_eq!(
        world.pve.guest(TEMPLATE_VMID).unwrap().config["protection"],
        1,
        "protection was lifted before the guard refused"
    );
    assert!(
        !world
            .pve
            .calls()
            .iter()
            .any(|call| call.starts_with("config"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_name_that_already_belongs_to_a_guest_elsewhere_is_refused() {
    let world = World::new().await;
    world
        .pve
        .state
        .lock()
        .unwrap()
        .guests
        .insert(7500, plain_guest("persist-18"));
    let operation = world.create(&world.spec("persist-18")).await;
    assert_eq!(operation.state, "failed");
    assert_eq!(error_of(&operation)["reason"], "conflict");
    assert!(
        error_of(&operation)["detail"]
            .as_str()
            .unwrap()
            .contains("7500")
    );
    assert!(world.pve.calls().is_empty());
}

#[derive(Debug)]
struct OnePool(&'static str, u32);

#[async_trait]
impl fleet_application::operation::PoolMemberLookup for OnePool {
    async fn pool_of(&self, _account_id: &str, vmid: u32) -> Result<Option<String>, String> {
        Ok((vmid == self.1).then(|| self.0.to_owned()))
    }
}

fn register_guard(
    world: &World,
    pools: Option<Arc<dyn fleet_application::operation::PoolMemberLookup>>,
) -> fleet_controller::persistent_machines::ProxmoxRegisterGuard {
    let guard = fleet_controller::persistent_machines::ProxmoxRegisterGuard::new(
        world.accounts.clone(),
        Arc::new(Credentials),
        fleet_provider_proxmox::ProxmoxClient::new(world.pve.clone()),
        Arc::new(Artifacts),
    );
    match pools {
        Some(pools) => guard.with_pool_members(pools),
        None => guard,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_register_guard_admits_only_a_plain_guest_and_fails_closed() {
    use fleet_application::persistent::{GuestCheck, RegisterGuard as _};

    let world = World::new().await;
    {
        let mut state = world.pve.state.lock().unwrap();
        state.guests.insert(7500, plain_guest("win-box"));
        let mut tagged = plain_guest("tagged-box");
        tagged
            .config
            .insert("tags".to_owned(), json!("fleet-pve-test;ci"));
        state.guests.insert(7501, tagged);
        let mut template = plain_guest("a-template");
        template.template = true;
        state.guests.insert(7502, template);
        state.guests.insert(7503, plain_guest("pooled"));
    }
    let guard = register_guard(&world, Some(Arc::new(OnePool("pool-1", 7503))));
    let refused = |check: GuestCheck, needle: &str| match check {
        GuestCheck::Refused(reason) => assert!(reason.contains(needle), "{reason}"),
        GuestCheck::Eligible(live) => panic!("{live:?} was admitted, wanted {needle}"),
    };

    match guard.inspect(&world.account_id, 7500).await.unwrap() {
        GuestCheck::Eligible(live) => {
            assert_eq!(live.name, "win-box");
            assert_eq!(live.node, "pve");
        }
        GuestCheck::Refused(reason) => panic!("{reason}"),
    }
    refused(
        guard.inspect(&world.account_id, 7501).await.unwrap(),
        "reserved tag",
    );
    refused(
        guard.inspect(&world.account_id, 7502).await.unwrap(),
        "template",
    );
    refused(
        guard.inspect(&world.account_id, 7503).await.unwrap(),
        "pool-1",
    );
    refused(
        guard
            .inspect(&world.account_id, TEMPLATE_VMID)
            .await
            .unwrap(),
        "template",
    );
    refused(
        guard.inspect(&world.account_id, 7999).await.unwrap(),
        "no guest",
    );

    // Without the pool lookup a pool member cannot be told apart: refused.
    let unwired = register_guard(&world, None);
    let error = unwired.inspect(&world.account_id, 7500).await.unwrap_err();
    assert!(error.contains("not wired"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn destroying_a_registered_vm_never_lifts_its_protection() {
    let world = World::new().await;
    {
        let mut state = world.pve.state.lock().unwrap();
        let mut guest = plain_guest("reg-box");
        guest.config.insert("protection".to_owned(), json!(1));
        state.guests.insert(7600, guest);
    }
    let markers = Arc::new(PersistentGuestRepository::new(world.pool.clone()));
    let mut registered = marker(&world.account_id, 7600, "reg-box", true);
    registered.image_version_id = "registered".to_owned();
    registered.state = PersistentState::Ready;
    markers.reserve(&registered).await.unwrap();
    let destroy = json!({
        "accountId": world.account_id, "node": "pve", "vmid": 7600,
        "timeoutSeconds": 300, "params": { "purge": false, "confirmPersistent": true },
    });
    let refused = world
        .run(world.destroy.as_ref(), "proxmox.guest.destroy", &destroy)
        .await;
    assert_eq!(error_of(&refused)["reason"], "protection_on");
    assert!(
        world.pve.guest(7600).is_some(),
        "the guest must still exist"
    );
    assert_eq!(world.pve.guest(7600).unwrap().config["protection"], 1);

    // The operator lifts it, then the confirmed destroy goes through.
    world
        .pve
        .state
        .lock()
        .unwrap()
        .guests
        .get_mut(&7600)
        .unwrap()
        .config
        .insert("protection".to_owned(), json!(0));
    let done = world
        .run(world.destroy.as_ref(), "proxmox.guest.destroy", &destroy)
        .await;
    assert_eq!(done.state, "succeeded", "{:?}", done.error_json);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_iso_install_creates_the_guest_waits_for_the_installer_and_detaches_the_media() {
    let world = World::new().await;
    let spec = install_spec(&world, "iso-box");
    let operation = world.create(&spec).await;
    assert_eq!(operation.state, "succeeded", "{:?}", operation.error_json);

    let calls = world.pve.calls();
    assert!(
        !calls.iter().any(|call| call.starts_with("clone")),
        "{calls:?}"
    );
    let created = calls.iter().position(|call| call == "create").unwrap();
    let started = calls
        .iter()
        .position(|call| call.starts_with("start"))
        .unwrap();
    assert!(created < started, "{calls:?}");
    let body = world.pve.body_of("create").unwrap();
    assert_eq!(body["ide2"], "local:iso/ubuntu.iso,media=cdrom");
    assert_eq!(body["ide3"], "local:iso/seed.iso,media=cdrom");
    assert_eq!(body["boot"], "order=ide2;scsi0");
    assert!(!body.to_string().contains("password"));

    let markers = PersistentGuestRepository::new(world.pool.clone());
    let marker = markers.list().await.unwrap().remove(0);
    assert_eq!(marker.image_version_id, "install:local:iso/ubuntu.iso");
    assert!(marker.cloned);
    assert_eq!(marker.state, PersistentState::Ready);
    let guest = world.pve.guest(marker.vmid).unwrap();
    assert!(guest.running, "the installed disk is booted");
    // Ejected, not deleted: the guest is protected, and PVE refuses a drive
    // removal then.
    assert_eq!(guest.config["ide2"], "none,media=cdrom");
    assert_eq!(guest.config["ide3"], "none,media=cdrom");
    assert_eq!(guest.config["boot"], "order=scsi0");
    // The same metadata as a cloned machine: persistent label, no fixture tag.
    assert_eq!(guest.config["tags"], "ci;fleet-persistent");
    assert_eq!(guest.config["protection"], 1);
}

fn install_spec(world: &World, name: &str) -> Value {
    let mut spec = world.spec(name);
    let object = spec.as_object_mut().unwrap();
    object.remove("imageVersionId");
    object.insert(
        "install".to_owned(),
        json!({ "iso": "local:iso/ubuntu.iso", "answerIso": "local:iso/seed.iso" }),
    );
    object.insert("node".to_owned(), json!("pve"));
    object.insert("storage".to_owned(), json!("local-lvm"));
    object.insert("diskGib".to_owned(), json!(32));
    spec
}

/// A guest as an interrupted install leaves it: stopped, protected, with the
/// installer and answer media still attached.
fn installed_guest(name: &str, with_media: bool) -> Guest {
    let mut guest = plain_guest(name);
    for (key, value) in [
        ("name", json!(name)),
        ("protection", json!(1)),
        ("boot", json!("order=ide2;scsi0")),
        ("net0", json!("virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0")),
        ("scsi0", json!("local-lvm:vm-7100-disk-0,size=32G")),
    ] {
        guest.config.insert(key.to_owned(), value);
    }
    if with_media {
        guest
            .config
            .insert("ide2".to_owned(), json!("local:iso/ubuntu.iso,media=cdrom"));
        guest
            .config
            .insert("ide3".to_owned(), json!("local:iso/seed.iso,media=cdrom"));
    }
    guest
}

async fn install_marker(world: &World, vmid: u32, name: &str, step: &str) {
    let mut marker = marker(&world.account_id, vmid, name, true);
    marker.image_version_id = "install:local:iso/ubuntu.iso".to_owned();
    marker.step = Some(step.to_owned());
    PersistentGuestRepository::new(world.pool.clone())
        .reserve(&marker)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_first_stopped_read_is_not_the_end_of_the_install() {
    let world = World::new().await;
    world.pve.state.lock().unwrap().stale_first_stopped = true;
    let operation = world.create(&install_spec(&world, "iso-stale")).await;
    assert_eq!(operation.state, "succeeded", "{:?}", operation.error_json);
    let calls = world.pve.calls();
    // The eject waited for the installer to run and then stop: at least the
    // stale read, a running read and the stopping read.
    let eject = calls.iter().find(|call| call.starts_with("eject")).unwrap();
    let polls: u32 = eject.trim_start_matches("eject polls=").parse().unwrap();
    assert!(polls >= 3, "{calls:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rerun_after_the_installer_stopped_ejects_without_installing_again() {
    let world = World::new().await;
    world
        .pve
        .state
        .lock()
        .unwrap()
        .guests
        .insert(7100, installed_guest("iso-resume", true));
    install_marker(&world, 7100, "iso-resume", "installing").await;
    let operation = world.create(&install_spec(&world, "iso-resume")).await;
    assert_eq!(operation.state, "succeeded", "{:?}", operation.error_json);
    let calls = world.pve.calls();
    let eject = calls
        .iter()
        .position(|call| call.starts_with("eject"))
        .unwrap();
    // Nothing was started before the media went: no second install.
    assert!(
        calls[..eject].iter().all(|call| !call.starts_with("start")),
        "{calls:?}"
    );
    assert_eq!(
        world.pve.guest(7100).unwrap().config["ide2"],
        "none,media=cdrom"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_guest_without_media_that_fleet_never_installed_is_not_adopted() {
    let world = World::new().await;
    world
        .pve
        .state
        .lock()
        .unwrap()
        .guests
        .insert(7100, installed_guest("iso-bare", false));
    install_marker(&world, 7100, "iso-bare", "config").await;
    let operation = world.create(&install_spec(&world, "iso-bare")).await;
    assert_eq!(operation.state, "failed");
    assert_eq!(error_of(&operation)["reason"], "media_missing");
    assert!(
        !world
            .pve
            .calls()
            .iter()
            .any(|call| call.starts_with("start")),
        "an unverified guest must not be started"
    );
}
