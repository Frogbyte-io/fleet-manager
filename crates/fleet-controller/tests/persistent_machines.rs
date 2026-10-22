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
use fleet_controller::proxmox_exec::ProxmoxDestructiveExecutor;
use fleet_controller::persistent_machines::{
    GuestConfigExecutor, MachineCreateExecutor, MachineCreateParts, SecretBackedProductKeys,
};
use fleet_provider_proxmox::{
    PveHttpMethod, PveHttpRequest, PveHttpResponse, PveTransport, PveTransportError,
};
use fleet_provider_ssh::{ExecutionLimiter, PrivateKey, SshAuth, SshConnectionSpec, SshProvider};
use fleet_storage_sqlite::{
    AuditSink, EndpointAuthRepository, GuestLinkRepository, MachineRepository,
    OperationRepository, PersistentGuestRepository, ProxmoxAccountRepository, Store,
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
    guests: BTreeMap<u32, Guest>,
    calls: Vec<String>,
    bodies: Vec<(String, Value)>,
    digest: u32,
    /// How many `start` calls still fail with a server error.
    fail_starts: u32,
}

/// A stateful fake Proxmox VE.
#[derive(Debug)]
struct FakePve {
    state: Mutex<HostState>,
}

impl FakePve {
    fn new() -> Arc<Self> {
        let mut state = HostState::default();
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
            ("POST", ["nodes", node, "qemu", source, "clone"]) => {
                state.calls.push(format!("clone {source}"));
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
                if body["digest"] != json!(format!("d{}", state.digest)) {
                    return (500, json!({ "data": null }));
                }
                state.digest += 1;
                let guest = state.guests.get_mut(&vmid.parse::<u32>().unwrap()).unwrap();
                for key in ["tags", "description", "onboot", "protection", "cores", "memory", "net0"] {
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
                state.guests.get_mut(&vmid.parse::<u32>().unwrap()).unwrap().running = true;
                ok(json!(format!(
                    "UPID:{node}:0000BBBB:00000002:65000001:qmstart:{vmid}:root@pam:"
                )))
            }
            ("POST", ["nodes", node, "qemu", vmid, "status", "stop"]) => {
                state.calls.push(format!("stop {vmid}"));
                state.guests.get_mut(&vmid.parse::<u32>().unwrap()).unwrap().running = false;
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
                    "hardware-address": "aa:bb:cc:dd:ee:01",
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
        let bootstrap_pub =
            std::fs::read_to_string(sshd.keys_dir.path().join("user_ed25519.pub"))
                .unwrap()
                .trim()
                .to_owned();
        let bootstrap_ref = keys.create(&bootstrap_text).await.unwrap();

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
                persistent: Arc::new(PersistentGuestRepository::new(pool.clone())),
                machines,
                guest_links: Arc::new(GuestLinkRepository::new(pool.clone())),
                endpoint_auths: Arc::new(EndpointAuthRepository::new(pool.clone())),
                access,
                keys: keys.clone(),
                resolver: resolver.clone(),
                secrets,
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
        let operation = self
            .operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                &lan().id,
                &NewOperation {
                    kind: kind.to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    review_token: Some(review_token_for(kind, &payload)),
                    payload_json: Some(payload),
                },
            )
            .await
            .unwrap();
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
        self.run(self.executor.as_ref(), "machine.create", spec).await
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
    let new_key = world.keys.resolve(&credential).await.unwrap().unwrap();
    assert!(world.can_log_in(SshAuth::StoredKey {
        key: PrivateKey::parse(&new_key).unwrap()
    }));
    let bootstrap_text = world.keys.resolve(&world.bootstrap_ref).await.unwrap().unwrap();
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

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_install_leaves_the_image_key_working_and_nothing_removed() {
    if is_root() {
        // Root can create the user, so the injected failure would not occur.
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
        .resolve(&world.bootstrap_ref)
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
    assert_eq!(world.pve.guest(vmid as u32).unwrap().config["protection"], 0);
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

    // Confirmed, but still protected: Proxmox refuses the delete, the guest
    // and its marker stay.
    let protected = world
        .run(
            world.destroy.as_ref(),
            "proxmox.guest.destroy",
            &destroy(json!({ "purge": false, "confirmPersistent": true })),
        )
        .await;
    assert_eq!(protected.state, "failed");
    assert!(world.pve.guest(vmid as u32).is_some());
    let markers = PersistentGuestRepository::new(world.pool.clone());
    assert!(markers.get(&world.account_id, vmid as u32).await.unwrap().is_some());

    // Lift protection (a reviewed config action), then the confirmed destroy.
    let lifted = world
        .run(
            world.config.as_ref(),
            "proxmox.guest.config",
            &json!({
                "accountId": world.account_id,
                "node": "pve",
                "vmid": vmid,
                "timeoutSeconds": 300,
                "params": { "protection": false },
            }),
        )
        .await;
    assert_eq!(lifted.state, "succeeded", "{:?}", error_of(&lifted));
    let destroyed = world
        .run(
            world.destroy.as_ref(),
            "proxmox.guest.destroy",
            &destroy(json!({ "purge": false, "confirmPersistent": true })),
        )
        .await;
    assert_eq!(destroyed.state, "succeeded", "{:?}", error_of(&destroyed));
    assert!(world.pve.guest(vmid as u32).is_none());
    // The marker goes with the guest, so the VMID and name are free again.
    assert!(markers.get(&world.account_id, vmid as u32).await.unwrap().is_none());
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
    let vmids: Vec<u32> = inventory.lab_guests().await.iter().map(|g| g.vmid).collect();
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
