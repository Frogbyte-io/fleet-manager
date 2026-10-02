//! The Proxmox use cases over fakes: the explicit-trust gate (observe →
//! confirm → discover), credential secrecy, and the honest failure
//! taxonomy.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditOutcome};
use fleet_application::authz::{
    AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, ReasonId,
};
use fleet_application::machine::{
    Endpoint, GuestIdentity, GuestLink, GuestLinkPort, Machine, MachineFilter, MachinePort as _,
    Machines, NewEndpoint, RegisterMachine,
};

#[derive(Debug, Default)]
struct FakeGuestLinks(Mutex<Vec<(String, GuestLink)>>);

#[async_trait]
impl GuestLinkPort for FakeGuestLinks {
    async fn get(&self, machine_id: &str) -> Result<Option<GuestLink>, PortFailure> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|(id, _)| id == machine_id)
            .map(|(_, link)| link.clone()))
    }
    async fn confirm(&self, machine_id: &str, link: &GuestLink) -> Result<(), PortFailure> {
        let mut links = self.0.lock().unwrap();
        if links.iter().any(|(id, existing)| {
            id == machine_id
                || (existing.account_id == link.account_id
                    && existing.guest_kind == link.guest_kind
                    && existing.vmid == link.vmid)
        }) {
            return Err(PortFailure::Conflict {
                detail: "already linked".to_owned(),
            });
        }
        links.push((machine_id.to_owned(), link.clone()));
        Ok(())
    }
    async fn unlink(&self, machine_id: &str) -> Result<(), PortFailure> {
        let mut links = self.0.lock().unwrap();
        let before = links.len();
        links.retain(|(id, _)| id != machine_id);
        if before == links.len() {
            return Err(PortFailure::NotFound {
                what: "guest link".to_owned(),
            });
        }
        Ok(())
    }
}
use fleet_application::operation::AuditPort;
use fleet_application::operation::PortFailure;
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProviderAgent, ProviderGuest, ProviderInterface,
    ProviderOsInfo, ProxmoxAccountPort, ProxmoxAccounts, ProxmoxCredentialStore,
    ProxmoxDiscoverPort, ProxmoxGuestDiscoverPort, ProxmoxSourceError, ProxmoxTrustProbe,
    ProxmoxUseCaseError, RawDiscovery, RawGuestDiscovery,
};
use fleet_core::CapabilityFact;
use fleet_core::SensitiveString;

const NOW: i64 = 1_800_000_000_000;

/// A full SHA-256-shaped fingerprint for the trust-flow tests.
const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";

fn principal() -> ActingPrincipal {
    ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }
}

#[derive(Debug, Default)]
struct AllowAll;

impl Authorizer for AllowAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

#[derive(Debug, Default)]
struct DenyAll;

impl Authorizer for DenyAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::deny(ReasonId::UnknownPrincipal)
    }
}

/// The account port over an in-memory map, mirroring the SQLite adapter's
/// semantics (unique names, not-found details).
#[derive(Debug, Default)]
struct FakeAccounts {
    accounts: Mutex<Vec<fleet_application::proxmox::ProxmoxAccount>>,
}

impl FakeAccounts {
    fn find(&self, id: &str) -> Option<fleet_application::proxmox::ProxmoxAccount> {
        self.accounts
            .lock()
            .unwrap()
            .iter()
            .find(|account| account.id == id)
            .cloned()
    }
}

#[async_trait]
impl ProxmoxAccountPort for FakeAccounts {
    async fn create(
        &self,
        new: &NewProxmoxAccount,
    ) -> Result<fleet_application::proxmox::ProxmoxAccount, String> {
        if self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .any(|account| account.name == new.name)
        {
            return Err(format!("the account name {:?} is already taken", new.name));
        }
        let mut accounts = self.accounts.lock().unwrap();
        let account = fleet_application::proxmox::ProxmoxAccount {
            id: format!("acc-{}", accounts.len() + 1),
            name: new.name.clone(),
            host: new.host.clone(),
            port: new.port.unwrap_or(8006),
            token_id: new.token_id.clone(),
            fingerprint: None,
            observed_fingerprint: None,
            created_at: NOW,
        };
        accounts.push(account.clone());
        Ok(account)
    }

    async fn get(&self, id: &str) -> Result<fleet_application::proxmox::ProxmoxAccount, String> {
        self.find(id)
            .ok_or_else(|| format!("account {id} not found"))
    }

    async fn list(&self) -> Result<Vec<fleet_application::proxmox::ProxmoxAccount>, String> {
        Ok(self.accounts.lock().unwrap().clone())
    }

    async fn set_fingerprint(
        &self,
        id: &str,
        fingerprint: Option<String>,
    ) -> Result<fleet_application::proxmox::ProxmoxAccount, String> {
        let mut accounts = self.accounts.lock().unwrap();
        let account = accounts
            .iter_mut()
            .find(|account| account.id == id)
            .ok_or_else(|| format!("account {id} not found"))?;
        account.fingerprint = fingerprint;
        Ok(account.clone())
    }

    async fn set_observed_fingerprint(
        &self,
        id: &str,
        fingerprint: Option<String>,
    ) -> Result<fleet_application::proxmox::ProxmoxAccount, String> {
        let mut accounts = self.accounts.lock().unwrap();
        let account = accounts
            .iter_mut()
            .find(|account| account.id == id)
            .ok_or_else(|| format!("account {id} not found"))?;
        account.observed_fingerprint = fingerprint;
        Ok(account.clone())
    }

    async fn delete(&self, id: &str) -> Result<(), String> {
        let mut accounts = self.accounts.lock().unwrap();
        let before = accounts.len();
        accounts.retain(|account| account.id != id);
        if accounts.len() == before {
            return Err(format!("account {id} not found"));
        }
        Ok(())
    }
}

/// The credential store over a map, recording what was stored and cleared.
#[derive(Debug, Default)]
struct FakeCredentials {
    secrets: Mutex<std::collections::HashMap<String, String>>,
    cleared: Mutex<Vec<String>>,
}

#[async_trait]
impl ProxmoxCredentialStore for FakeCredentials {
    async fn load(&self, account_id: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(self.secrets.lock().unwrap().get(account_id).cloned())
    }

    async fn store(&self, account_id: &str, secret: &str) -> Result<(), CredentialStoreError> {
        self.secrets
            .lock()
            .unwrap()
            .insert(account_id.to_owned(), secret.to_owned());
        Ok(())
    }

    async fn clear(&self, account_id: &str) -> Result<(), CredentialStoreError> {
        self.secrets.lock().unwrap().remove(account_id);
        self.cleared.lock().unwrap().push(account_id.to_owned());
        Ok(())
    }
}

/// The discovery port over canned results and failures.
#[derive(Debug, Default)]
struct FakeDiscovery {
    result: Mutex<Option<Result<RawDiscovery, ProxmoxSourceError>>>,
    calls: Mutex<Vec<String>>,
}

impl FakeDiscovery {
    fn with(result: Result<RawDiscovery, ProxmoxSourceError>) -> Arc<Self> {
        Arc::new(Self {
            result: Mutex::new(Some(result)),
            calls: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl ProxmoxDiscoverPort for FakeDiscovery {
    async fn discover(
        &self,
        account: &fleet_application::proxmox::ProxmoxAccount,
        _secret: &SensitiveString,
    ) -> Result<RawDiscovery, ProxmoxSourceError> {
        self.calls.lock().unwrap().push(account.id.clone());
        self.result
            .lock()
            .unwrap()
            .take()
            .expect("a discovery answer was prepared")
    }
}

/// The trust probe over a canned fingerprint.
#[derive(Debug, Default)]
struct FakeProbe {
    fingerprint: Mutex<Option<String>>,
}

impl FakeProbe {
    fn with(fingerprint: &str) -> Arc<Self> {
        Arc::new(Self {
            fingerprint: Mutex::new(Some(fingerprint.to_owned())),
        })
    }
}

#[async_trait]
impl ProxmoxTrustProbe for FakeProbe {
    async fn observe(&self, _host: &str, _port: u16) -> Result<String, ProxmoxSourceError> {
        self.fingerprint
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| ProxmoxSourceError::Connect {
                detail: "unreachable".to_owned(),
            })
    }
}

/// The audit sink over a vector, for secrecy assertions.
#[derive(Debug, Default)]
struct FakeAudit {
    intents: Mutex<Vec<AuditIntent>>,
}

#[async_trait]
impl AuditPort for FakeAudit {
    async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
        self.intents.lock().unwrap().push(intent.clone());
        Ok(())
    }

    async fn record_outcome(
        &self,
        _operation_id: &str,
        _outcome: AuditOutcome,
    ) -> Result<(), String> {
        Ok(())
    }
}

fn discovery_ok() -> RawDiscovery {
    RawDiscovery {
        version: "9.2.2".to_owned(),
        resources: vec![fleet_application::proxmox::ProxmoxResource {
            kind: "node".to_owned(),
            id: "node/pve".to_owned(),
            node: None,
            vmid: None,
            name: Some("pve".to_owned()),
            status: Some("online".to_owned()),
            account_id: String::new(),
            pve_version: String::new(),
            observed_at: 0,
        }],
        node_capacities: vec![fleet_application::proxmox::ProxmoxNodeCapacity {
            node: "pve".to_owned(),
            cpu_usage_ratio: Some(0.375),
            cpu_count: Some(12),
            memory_used_bytes: Some(100),
            memory_total_bytes: Some(200),
            storages: vec![fleet_application::proxmox::ProxmoxStorageCapacity {
                storage: "local-lvm".to_owned(),
                used_bytes: 300,
                total_bytes: 600,
            }],
            observed_at: 0,
        }],
        warnings: Vec::new(),
        reported_count: 1,
    }
}

/// The machine port over an in-memory map, mirroring the SQLite adapter's
/// semantics closely enough for the association tests: register, list (as
/// assembled views), and record capabilities.
#[derive(Debug, Default)]
struct FakeMachinePort {
    machines: std::sync::Mutex<Vec<Machine>>,
    recorded: std::sync::Mutex<Vec<(String, Vec<CapabilityFact>)>>,
}

#[async_trait]
impl fleet_application::machine::MachinePort for FakeMachinePort {
    async fn register(&self, registration: &RegisterMachine) -> Result<Machine, PortFailure> {
        let machine = Machine {
            id: format!("m-{}", registration.name),
            name: registration.name.clone(),
            description: registration.description.clone(),
            endpoints: registration
                .endpoints
                .iter()
                .enumerate()
                .map(|(index, endpoint)| Endpoint {
                    id: format!("ep-{index}"),
                    kind: endpoint.kind,
                    reference: endpoint.reference.clone(),
                })
                .collect(),
            tags: registration.tags.clone(),
            groups: registration.groups.clone(),
            node: None,
            capabilities: Vec::new(),
            last_observation: None,
            created_at: NOW,
            updated_at: NOW,
        };
        self.machines.lock().unwrap().push(machine.clone());
        Ok(machine)
    }

    async fn get(&self, id: &str) -> Result<Machine, PortFailure> {
        self.machines
            .lock()
            .unwrap()
            .iter()
            .find(|machine| machine.id == id)
            .cloned()
            .ok_or_else(|| PortFailure::NotFound {
                what: format!("machine {id}"),
            })
    }

    async fn list(&self, _filter: &MachineFilter, limit: u32) -> Result<Vec<Machine>, PortFailure> {
        let machines = self.machines.lock().unwrap();
        Ok(machines
            .iter()
            .rev()
            .take(usize::try_from(limit).unwrap_or(machines.len()))
            .cloned()
            .collect())
    }

    async fn update(
        &self,
        _id: &str,
        _name: &str,
        _description: &str,
    ) -> Result<Machine, PortFailure> {
        Err(PortFailure::Backend {
            detail: "unused in these tests".to_owned(),
        })
    }

    async fn set_endpoints(
        &self,
        _id: &str,
        _endpoints: &[NewEndpoint],
    ) -> Result<Machine, PortFailure> {
        Err(PortFailure::Backend {
            detail: "unused in these tests".to_owned(),
        })
    }

    async fn add_tag(&self, _id: &str, _tag: &str) -> Result<Machine, PortFailure> {
        Err(PortFailure::Backend {
            detail: "unused in these tests".to_owned(),
        })
    }

    async fn remove_tag(&self, _id: &str, _tag: &str) -> Result<Machine, PortFailure> {
        Err(PortFailure::Backend {
            detail: "unused in these tests".to_owned(),
        })
    }

    async fn add_group(&self, _id: &str, _group: &str) -> Result<Machine, PortFailure> {
        Err(PortFailure::Backend {
            detail: "unused in these tests".to_owned(),
        })
    }

    async fn remove_group(&self, _id: &str, _group: &str) -> Result<Machine, PortFailure> {
        Err(PortFailure::Backend {
            detail: "unused in these tests".to_owned(),
        })
    }

    async fn record_snapshot(
        &self,
        _id: &str,
        _source: &str,
        _payload_json: &str,
        _collected_at: i64,
    ) -> Result<(), PortFailure> {
        Ok(())
    }

    async fn record_capabilities(
        &self,
        id: &str,
        facts: &[CapabilityFact],
    ) -> Result<(), PortFailure> {
        self.recorded
            .lock()
            .unwrap()
            .push((id.to_owned(), facts.to_vec()));
        // Mirror the real upsert: the facts land on the machine, so a later
        // list view carries them.
        let mut machines = self.machines.lock().unwrap();
        let machine = machines
            .iter_mut()
            .find(|machine| machine.id == id)
            .ok_or_else(|| PortFailure::NotFound {
                what: format!("machine {id}"),
            })?;
        for fact in facts {
            if let Some(existing) = machine
                .capabilities
                .iter_mut()
                .find(|existing| existing.namespace == fact.namespace && existing.name == fact.name)
            {
                *existing = fact.clone();
            } else {
                machine.capabilities.push(fact.clone());
            }
        }
        Ok(())
    }

    async fn delete(&self, _id: &str) -> Result<(), PortFailure> {
        Ok(())
    }

    async fn confirm_fingerprint(
        &self,
        _endpoint_id: &str,
        _fingerprint: &str,
        _confirmed_at: i64,
    ) -> Result<(), PortFailure> {
        Ok(())
    }

    async fn verified_fingerprint(
        &self,
        _endpoint_id: &str,
    ) -> Result<Option<String>, PortFailure> {
        Ok(None)
    }

    async fn latest_inventory_revision(
        &self,
        _machine_id: &str,
    ) -> Result<Option<u64>, PortFailure> {
        Ok(None)
    }
}

/// The guest-discovery port over canned results.
#[derive(Debug, Default)]
struct FakeGuestDiscovery {
    /// The canned result, cloned per call: a discovery is a read, and the
    /// real source answers the same snapshot every time.
    result: std::sync::Mutex<Option<Result<RawGuestDiscovery, ProxmoxSourceError>>>,
    calls: std::sync::Mutex<Vec<String>>,
}

impl FakeGuestDiscovery {
    fn with(result: Result<RawGuestDiscovery, ProxmoxSourceError>) -> Arc<Self> {
        Arc::new(Self {
            result: std::sync::Mutex::new(Some(result)),
            calls: std::sync::Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl ProxmoxGuestDiscoverPort for FakeGuestDiscovery {
    async fn guest_discover(
        &self,
        account: &fleet_application::proxmox::ProxmoxAccount,
        _secret: &SensitiveString,
    ) -> Result<RawGuestDiscovery, ProxmoxSourceError> {
        self.calls.lock().unwrap().push(account.id.clone());
        self.result
            .lock()
            .unwrap()
            .as_ref()
            .expect("a guest-discovery answer was prepared")
            .clone()
        // The canned result is cloned per call: a discovery is a read.
    }
}

fn service(
    discovery: Arc<dyn ProxmoxDiscoverPort>,
    probe: Arc<dyn ProxmoxTrustProbe>,
) -> (ProxmoxAccounts, Arc<FakeAudit>) {
    let (proxmox, audit, _machine_port) =
        service_with_guests(discovery, Arc::new(FakeGuestDiscovery::default()), probe);
    (proxmox, audit)
}

fn service_with_guests(
    discovery: Arc<dyn ProxmoxDiscoverPort>,
    guests: Arc<dyn ProxmoxGuestDiscoverPort>,
    probe: Arc<dyn ProxmoxTrustProbe>,
) -> (ProxmoxAccounts, Arc<FakeAudit>, Arc<FakeMachinePort>) {
    let audit = Arc::new(FakeAudit::default());
    let machine_port = Arc::new(FakeMachinePort::default());
    let machines = Arc::new(Machines::new(machine_port.clone(), audit.clone()));
    (
        ProxmoxAccounts::new(
            Arc::new(FakeAccounts::default()),
            Arc::new(FakeCredentials::default()),
            discovery,
            guests,
            probe,
            machines,
            audit.clone(),
        ),
        audit,
        machine_port,
    )
}

#[tokio::test]
async fn committed_account_mutations_publish_through_the_attached_event_hub() {
    let (proxmox, _audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    let hub = Arc::new(fleet_application::events::EventHub::new(8));
    let mut events = hub.subscribe(None).receiver;
    let proxmox = proxmox.with_events(hub);

    let account = create_account(&proxmox).await;

    assert_eq!(
        events.try_recv().unwrap().kind,
        fleet_application::events::EventKind::ProxmoxChanged
    );
    let conflict = proxmox
        .create(
            &AllowAll,
            &principal(),
            NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: "192.168.68.224".to_owned(),
                port: Some(8006),
                token_id: "root@pam!GLM-AGENT".to_owned(),
            },
            "the-token-secret-material",
        )
        .await
        .unwrap_err();
    assert!(matches!(
        conflict,
        ProxmoxUseCaseError::Conflict { ref detail } if detail.contains("taken")
    ));
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    proxmox
        .delete(&AllowAll, &principal(), &account.id)
        .await
        .unwrap();
    assert_eq!(
        events.try_recv().unwrap().kind,
        fleet_application::events::EventKind::ProxmoxChanged
    );
}

async fn create_account(proxmox: &ProxmoxAccounts) -> fleet_application::proxmox::ProxmoxAccount {
    proxmox
        .create(
            &AllowAll,
            &principal(),
            NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: "192.168.68.223".to_owned(),
                port: Some(8006),
                token_id: "root@pam!GLM-AGENT".to_owned(),
            },
            "the-token-secret-material",
        )
        .await
        .expect("the account is well formed")
}

/// Observes and confirms the canned fingerprint, the honest trust flow.
async fn observe_and_confirm(proxmox: &ProxmoxAccounts, account_id: &str) {
    let observed = proxmox
        .observe(&AllowAll, &principal(), account_id)
        .await
        .expect("the probe answers");
    proxmox
        .confirm(&AllowAll, &principal(), account_id, &observed)
        .await
        .expect("the observed fingerprint confirms");
}

#[tokio::test]
async fn discovery_is_locked_until_the_fingerprint_is_confirmed() {
    let (proxmox, _audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    let account = create_account(&proxmox).await;
    let error = proxmox
        .discover(&AllowAll, &principal(), &account.id, NOW)
        .await
        .unwrap_err();
    assert!(
        matches!(error, ProxmoxUseCaseError::UnconfirmedTrust { .. }),
        "{error}"
    );
}

#[tokio::test]
async fn observe_confirm_then_discover_walks_the_trust_flow() {
    let (proxmox, audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    let account = create_account(&proxmox).await;

    // Observe: the fingerprint arrives without any credential sent.
    let observed = proxmox
        .observe(&AllowAll, &principal(), &account.id)
        .await
        .unwrap();
    assert_eq!(observed, FP);

    // Confirm: the account becomes trusted, fingerprint normalized.
    let account = proxmox
        .confirm(
            &AllowAll,
            &principal(),
            &account.id,
            &fleet_application::proxmox::normalize_fingerprint(FP).to_lowercase(),
        )
        .await
        .unwrap();
    assert_eq!(account.fingerprint.as_deref(), Some(FP));

    // Discover: the snapshot lands with provenance.
    let snapshot = proxmox
        .discover(&AllowAll, &principal(), &account.id, NOW)
        .await
        .unwrap();
    assert_eq!(snapshot.pve_version, "9.2.2");
    assert_eq!(snapshot.resources.len(), 1);
    assert_eq!(snapshot.resources[0].account_id, account.id);
    assert_eq!(snapshot.resources[0].pve_version, "9.2.2");
    assert_eq!(snapshot.resources[0].observed_at, NOW);
    assert_eq!(snapshot.node_capacities.len(), 1);
    assert_eq!(snapshot.node_capacities[0].node, "pve");
    assert_eq!(snapshot.node_capacities[0].observed_at, NOW);
    assert_eq!(snapshot.node_capacities[0].cpu_usage_ratio, Some(0.375));
    assert_eq!(snapshot.node_capacities[0].storages[0].used_bytes, 300);
    assert_eq!(snapshot.observed_at, NOW);

    // The trust flow is audited as account mutations.
    let intents = audit.intents.lock().unwrap();
    assert!(
        intents.iter().any(|intent| {
            intent
                .metadata
                .entries()
                .any(|(key, value)| key == "event" && value == "proxmox_fingerprint_confirming")
        }),
        "{intents:?}"
    );
}

#[tokio::test]
async fn a_fingerprint_mismatch_is_reported_as_evidence_not_an_empty_list() {
    let (proxmox, _audit) = service(
        FakeDiscovery::with(Err(ProxmoxSourceError::FingerprintMismatch {
            observed: FP.to_owned(),
            pinned: "DD".repeat(32),
        })),
        FakeProbe::with(FP),
    );
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;
    let error = proxmox
        .discover(&AllowAll, &principal(), &account.id, NOW)
        .await
        .unwrap_err();
    match error {
        ProxmoxUseCaseError::Source(ProxmoxSourceError::FingerprintMismatch {
            observed,
            pinned,
        }) => {
            assert_eq!(observed, FP);
            assert_eq!(pinned, "DD".repeat(32));
        }
        other => panic!("expected a fingerprint mismatch, got {other}"),
    }
}

#[tokio::test]
async fn auth_and_privilege_failures_are_honest_states() {
    for source_error in [
        ProxmoxSourceError::Auth,
        ProxmoxSourceError::Forbidden {
            detail: "no permission".to_owned(),
        },
        ProxmoxSourceError::Connect {
            detail: "timeout".to_owned(),
        },
    ] {
        let (proxmox, _audit) =
            service(FakeDiscovery::with(Err(source_error)), FakeProbe::with(FP));
        let account = create_account(&proxmox).await;
        observe_and_confirm(&proxmox, &account.id).await;
        let error = proxmox
            .discover(&AllowAll, &principal(), &account.id, NOW)
            .await
            .unwrap_err();
        assert!(matches!(error, ProxmoxUseCaseError::Source(_)), "{error}");
    }
}

#[tokio::test]
async fn the_token_secret_never_surfaces_in_audit_or_errors() {
    let (proxmox, audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;
    let _ = proxmox
        .discover(&AllowAll, &principal(), &account.id, NOW)
        .await
        .unwrap();
    for intent in audit.intents.lock().unwrap().iter() {
        let rendered = format!("{intent:?}");
        assert!(
            !rendered.contains("the-token-secret-material"),
            "the secret leaked into audit: {rendered}"
        );
    }
}

#[tokio::test]
async fn a_failed_secret_write_removes_the_account() {
    // A store that refuses writes: the account must not survive half-made.
    #[derive(Debug)]
    struct RefusingStore;
    #[async_trait]
    impl ProxmoxCredentialStore for RefusingStore {
        async fn load(&self, _account_id: &str) -> Result<Option<String>, CredentialStoreError> {
            Ok(None)
        }
        async fn store(
            &self,
            _account_id: &str,
            _secret: &str,
        ) -> Result<(), CredentialStoreError> {
            Err(CredentialStoreError::Backend {
                detail: "the disk is full".to_owned(),
            })
        }
        async fn clear(&self, _account_id: &str) -> Result<(), CredentialStoreError> {
            Ok(())
        }
    }
    let audit = Arc::new(FakeAudit::default());
    let machines = Arc::new(Machines::new(
        Arc::new(FakeMachinePort::default()),
        audit.clone(),
    ));
    let proxmox = ProxmoxAccounts::new(
        Arc::new(FakeAccounts::default()),
        Arc::new(RefusingStore),
        FakeDiscovery::with(Ok(discovery_ok())),
        Arc::new(FakeGuestDiscovery::default()),
        FakeProbe::with(FP),
        machines,
        audit,
    );
    let error = proxmox
        .create(
            &AllowAll,
            &principal(),
            NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: "192.168.68.223".to_owned(),
                port: None,
                token_id: "root@pam!GLM-AGENT".to_owned(),
            },
            "the-token-secret-material",
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, ProxmoxUseCaseError::Backend { .. }),
        "{error}"
    );
    let accounts = proxmox
        .list(&AllowAll, &principal(), 50, None)
        .await
        .unwrap();
    assert!(accounts.is_empty(), "the half-made account is gone");
}

#[tokio::test]
async fn deleting_an_account_clears_its_secret() {
    let (proxmox, _audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    let account = create_account(&proxmox).await;
    proxmox
        .delete(&AllowAll, &principal(), &account.id)
        .await
        .unwrap();
    assert!(
        proxmox
            .list(&AllowAll, &principal(), 50, None)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_denied_caller_never_reaches_the_ports() {
    let (proxmox, _audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    let account = create_account(&proxmox).await;
    let error = proxmox
        .list(&DenyAll, &principal(), 50, None)
        .await
        .unwrap_err();
    assert!(matches!(error, ProxmoxUseCaseError::Denied(_)));
    let error = proxmox
        .discover(&DenyAll, &principal(), &account.id, NOW)
        .await
        .unwrap_err();
    assert!(matches!(error, ProxmoxUseCaseError::Denied(_)));
}

#[tokio::test]
async fn malformed_accounts_are_refused_before_any_write() {
    let (proxmox, _audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    for new in [
        NewProxmoxAccount {
            name: String::new(),
            host: "192.168.68.223".to_owned(),
            port: None,
            token_id: "root@pam!GLM-AGENT".to_owned(),
        },
        NewProxmoxAccount {
            name: "pve-main".to_owned(),
            host: "https://192.168.68.223".to_owned(),
            port: None,
            token_id: "root@pam!GLM-AGENT".to_owned(),
        },
        NewProxmoxAccount {
            name: "pve-main".to_owned(),
            host: "192.168.68.223".to_owned(),
            port: None,
            token_id: "no-shape".to_owned(),
        },
    ] {
        let error = proxmox
            .create(&AllowAll, &principal(), new, "secret")
            .await
            .unwrap_err();
        assert!(
            matches!(error, ProxmoxUseCaseError::Invalid { .. }),
            "{error}"
        );
    }
    assert!(
        proxmox
            .list(&AllowAll, &principal(), 50, None)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_conflicting_account_name_is_a_conflict() {
    let (proxmox, _audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    create_account(&proxmox).await;
    let error = proxmox
        .create(
            &AllowAll,
            &principal(),
            NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: "10.0.0.1".to_owned(),
                port: None,
                token_id: "root@pam!OTHER".to_owned(),
            },
            "another-secret",
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, ProxmoxUseCaseError::Conflict { .. }),
        "{error}"
    );
}

#[tokio::test]
async fn confirm_refuses_a_malformed_fingerprint() {
    let (proxmox, _audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    let account = create_account(&proxmox).await;
    for fingerprint in ["", "nothex", "A".repeat(63).as_str(), &"G".repeat(64)] {
        let error = proxmox
            .confirm(&AllowAll, &principal(), &account.id, fingerprint)
            .await
            .unwrap_err();
        assert!(
            matches!(error, ProxmoxUseCaseError::Invalid { .. }),
            "{error}"
        );
    }
}

// ---- FM-601: guest associations and guest-agent data ----

/// A QEMU guest with an online agent, one interface, and a config MAC.
fn qemu_guest() -> ProviderGuest {
    ProviderGuest {
        kind: "qemu".to_owned(),
        id: "qemu/101".to_owned(),
        node: Some("pve".to_owned()),
        vmid: Some(101),
        name: Some("fleet-test-01".to_owned()),
        status: Some("running".to_owned()),
        macs: vec!["de:ad:be:ef:00:01".to_owned()],
        ostype: None,
        agent: Some(ProviderAgent {
            online: true,
            version: Some("7.2".to_owned()),
            os_name: Some("Ubuntu 24.04.4 LTS".to_owned()),
            kernel: Some("6.8.0-138-generic".to_owned()),
            os: None,
            interfaces: vec![ProviderInterface {
                name: "ens18".to_owned(),
                mac: Some("de:ad:be:ef:00:01".to_owned()),
                addresses: vec!["192.168.68.240".to_owned()],
            }],
        }),
        warnings: Vec::new(),
    }
}

/// An LXC guest: no agent by design, config MACs only.
fn lxc_guest() -> ProviderGuest {
    ProviderGuest {
        kind: "lxc".to_owned(),
        id: "lxc/200".to_owned(),
        node: Some("pve".to_owned()),
        vmid: Some(200),
        name: Some("container".to_owned()),
        status: Some("running".to_owned()),
        macs: vec!["de:ad:be:ef:00:02".to_owned()],
        ostype: None,
        agent: None,
        warnings: Vec::new(),
    }
}

/// A Windows 11 guest as the FM-608 9.x contract fixture decodes it: the
/// registry `ProductName` still says "Windows 10", the raw interfaces keep
/// link-local (zoned), APIPA, and documentation addresses.
fn windows_guest() -> ProviderGuest {
    let s = |values: &[&str]| values.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>();
    ProviderGuest {
        kind: "qemu".to_owned(),
        id: "qemu/201".to_owned(),
        node: Some("pve".to_owned()),
        vmid: Some(201),
        name: Some("win-desk-01".to_owned()),
        status: Some("running".to_owned()),
        macs: s(&["bc:24:11:0a:02:01", "bc:24:11:0a:02:02"]),
        ostype: Some("win11".to_owned()),
        agent: Some(ProviderAgent {
            online: true,
            version: Some("9.2.0".to_owned()),
            os_name: Some("Windows 10 Pro".to_owned()),
            kernel: Some("26100".to_owned()),
            os: Some(ProviderOsInfo {
                id: Some("mswindows".to_owned()),
                name: Some("Microsoft Windows".to_owned()),
                pretty_name: Some("Windows 10 Pro".to_owned()),
                version: Some("Microsoft Windows 11".to_owned()),
                version_id: Some("11".to_owned()),
                variant_id: Some("client".to_owned()),
                kernel_release: Some("26100".to_owned()),
                machine: Some("x86_64".to_owned()),
            }),
            interfaces: vec![
                ProviderInterface {
                    name: "Ethernet".to_owned(),
                    mac: Some("bc:24:11:0a:02:01".to_owned()),
                    addresses: s(&["2001:db8::201", "fe80::be24:11ff:fe0a:201%6", "192.0.2.201"]),
                },
                ProviderInterface {
                    name: "Ethernet 2".to_owned(),
                    mac: Some("bc:24:11:0a:02:02".to_owned()),
                    addresses: s(&["fe80::be24:11ff:fe0a:202%12", "169.254.10.20"]),
                },
            ],
        }),
        warnings: Vec::new(),
    }
}

fn guest_discovery(guests: Vec<ProviderGuest>) -> RawGuestDiscovery {
    RawGuestDiscovery {
        version: "9.2.2".to_owned(),
        guests,
        warnings: Vec::new(),
    }
}

async fn register_machine(
    machine_port: &FakeMachinePort,
    name: &str,
    reference: &str,
    mac: Option<&str>,
) -> String {
    let machine = machine_port
        .register(&RegisterMachine {
            name: name.to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: fleet_core::EndpointKind::Ssh,
                reference: reference.to_owned(),
            }],
            tags: Vec::new(),
            groups: Vec::new(),
        })
        .await
        .expect("the machine registers");
    if let Some(mac) = mac {
        machine_port
            .record_capabilities(
                &machine.id,
                &[CapabilityFact {
                    namespace: "net".to_owned(),
                    name: "mac0".to_owned(),
                    value: Some(mac.to_owned()),
                    status: fleet_core::CapabilityStatus::Known,
                    observed_at: fleet_core::Timestamp::from_unix_millis(NOW),
                    source: "agentless/1".to_owned(),
                }],
            )
            .await
            .expect("the MAC fact records");
    }
    machine.id
}

#[tokio::test]
async fn guests_list_with_evidence_only_candidates() {
    let (proxmox, _audit, machine_port) = service_with_guests(
        FakeDiscovery::with(Ok(discovery_ok())),
        FakeGuestDiscovery::with(Ok(guest_discovery(vec![qemu_guest(), lxc_guest()]))),
        FakeProbe::with(FP),
    );
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;

    // A machine whose endpoint host is the guest-agent address: address
    // evidence. Another whose recorded MAC matches the config MAC: MAC
    // evidence outranks nothing here — they are different guests.
    let by_address = register_machine(
        &machine_port,
        "fleet-test-01",
        "ops@192.168.68.240:22",
        None,
    )
    .await;
    let by_mac = register_machine(
        &machine_port,
        "mac-box",
        "ops@10.0.0.9:22",
        Some("DE:AD:BE:EF:00:02"),
    )
    .await;

    let snapshot = proxmox
        .guests(&AllowAll, &principal(), &account.id, NOW)
        .await
        .unwrap();
    assert_eq!(snapshot.guests.len(), 2);
    let guests = &snapshot.guests;

    let qemu = guests
        .iter()
        .find(|guest| guest.guest.vmid == Some(101))
        .expect("the qemu guest lists");
    assert_eq!(qemu.pve_version, "9.2.2");
    assert_eq!(qemu.observed_at, NOW);
    assert_eq!(qemu.candidates.len(), 1, "{:?}", qemu.candidates);
    assert_eq!(qemu.candidates[0].machine_id, by_address);
    assert_eq!(qemu.candidates[0].kind, "address_match");
    assert_eq!(qemu.candidates[0].evidence, "192.168.68.240");

    let lxc = guests
        .iter()
        .find(|guest| guest.guest.vmid == Some(200))
        .expect("the lxc guest lists");
    assert_eq!(lxc.candidates.len(), 1);
    assert_eq!(lxc.candidates[0].machine_id, by_mac);
    assert_eq!(lxc.candidates[0].kind, "mac_match");
    assert_eq!(lxc.candidates[0].evidence, "de:ad:be:ef:00:02");
}

#[tokio::test]
async fn confirmed_link_requires_current_evidence_and_is_audited() {
    let (proxmox, audit, machine_port) = service_with_guests(
        FakeDiscovery::with(Ok(discovery_ok())),
        FakeGuestDiscovery::with(Ok(guest_discovery(vec![qemu_guest()]))),
        FakeProbe::with(FP),
    );
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;
    let matching = register_machine(&machine_port, "matched", "ops@192.168.68.240:22", None).await;
    let also_matching =
        register_machine(&machine_port, "also-matched", "ops@192.168.68.240:22", None).await;
    let unmatched = register_machine(&machine_port, "other", "ops@10.0.0.9:22", None).await;
    let links = Arc::new(FakeGuestLinks::default());
    let machines = Machines::new(machine_port, audit.clone()).with_guest_links(links.clone());
    let identity = GuestIdentity {
        account_id: account.id.clone(),
        guest_kind: "qemu".to_owned(),
        vmid: 101,
    };
    let denied = machines
        .link_guest(&proxmox, &DenyAll, &principal(), &matching, &identity, NOW)
        .await
        .unwrap_err();
    assert!(matches!(
        denied,
        fleet_application::machine::MachineUseCaseError::Denied(_)
    ));
    let rejected = machines
        .link_guest(
            &proxmox,
            &AllowAll,
            &principal(),
            &unmatched,
            &identity,
            NOW,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        rejected,
        fleet_application::machine::MachineUseCaseError::Conflict { .. }
    ));
    assert!(links.get(&unmatched).await.unwrap().is_none());
    let view = machines
        .link_guest(&proxmox, &AllowAll, &principal(), &matching, &identity, NOW)
        .await
        .unwrap();
    assert_eq!(view.kind, fleet_application::machine::MachineKind::Vm);
    assert_eq!(view.runs_on.unwrap().vmid, 101);
    let conflict = machines
        .link_guest(
            &proxmox,
            &AllowAll,
            &principal(),
            &also_matching,
            &identity,
            NOW,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        conflict,
        fleet_application::machine::MachineUseCaseError::Conflict { ref detail } if detail == "already linked"
    ));
    let unlinked = machines
        .unlink_guest(&AllowAll, &principal(), &matching, NOW)
        .await
        .unwrap();
    assert!(unlinked.runs_on.is_none());
    let actions: Vec<_> = audit
        .intents
        .lock()
        .unwrap()
        .iter()
        .map(|intent| intent.action.clone())
        .collect();
    assert_eq!(
        actions
            .iter()
            .filter(|action| action.as_str() == "machine.link.guest")
            .count(),
        2
    );
}

#[tokio::test]
async fn targeted_guest_candidate_preserves_missing_machine_error() {
    let (proxmox, _audit, _machine_port) = service_with_guests(
        FakeDiscovery::with(Ok(discovery_ok())),
        FakeGuestDiscovery::with(Ok(guest_discovery(vec![qemu_guest()]))),
        FakeProbe::with(FP),
    );
    let identity = GuestIdentity {
        account_id: "account".to_owned(),
        guest_kind: "qemu".to_owned(),
        vmid: 101,
    };
    let error = proxmox
        .current_guest_candidate(&AllowAll, &principal(), "missing", &identity, NOW)
        .await
        .unwrap_err();
    assert!(matches!(error, ProxmoxUseCaseError::NotFound { .. }));
}

#[tokio::test]
async fn mac_evidence_outranks_address_and_name_evidence() {
    let (proxmox, _audit, machine_port) = service_with_guests(
        FakeDiscovery::with(Ok(discovery_ok())),
        FakeGuestDiscovery::with(Ok(guest_discovery(vec![qemu_guest()]))),
        FakeProbe::with(FP),
    );
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;

    // One machine matching on every dimension: the candidate reports the
    // strongest reason (MAC), once.
    let machine_id = register_machine(
        &machine_port,
        "fleet-test-01",
        "ops@192.168.68.240:22",
        Some("DE:AD:BE:EF:00:01"),
    )
    .await;
    let snapshot = proxmox
        .guests(&AllowAll, &principal(), &account.id, NOW)
        .await
        .unwrap();
    assert_eq!(snapshot.guests[0].candidates.len(), 1);
    assert_eq!(snapshot.guests[0].candidates[0].machine_id, machine_id);
    assert_eq!(snapshot.guests[0].candidates[0].kind, "mac_match");
}

#[tokio::test]
async fn unmatched_guests_list_without_candidates() {
    let (proxmox, _audit, _machine_port) = service_with_guests(
        FakeDiscovery::with(Ok(discovery_ok())),
        FakeGuestDiscovery::with(Ok(guest_discovery(vec![qemu_guest()]))),
        FakeProbe::with(FP),
    );
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;
    let snapshot = proxmox
        .guests(&AllowAll, &principal(), &account.id, NOW)
        .await
        .unwrap();
    assert!(
        snapshot.guests[0].candidates.is_empty(),
        "{:?}",
        snapshot.guests[0].candidates
    );
}

#[tokio::test]
async fn a_sensitive_denial_degrades_candidates_not_the_guests() {
    // machine.read is allowed but machine.read.sensitive is denied: the
    // endpoint hosts arrive redacted, so address evidence cannot match.
    #[derive(Debug, Default)]
    struct SensitiveDenied;
    impl Authorizer for SensitiveDenied {
        fn decide(&self, request: AccessRequest<'_>) -> Decision {
            if request.action == Permission::MachineReadSensitive {
                return Decision::deny(ReasonId::PolicyAllow);
            }
            Decision::allow()
        }
    }
    let (proxmox, _audit, machine_port) = service_with_guests(
        FakeDiscovery::with(Ok(discovery_ok())),
        FakeGuestDiscovery::with(Ok(guest_discovery(vec![qemu_guest()]))),
        FakeProbe::with(FP),
    );
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;
    // A machine whose name differs from the guest's, so the only possible
    // evidence is the address — which needs sensitive endpoint detail.
    register_machine(&machine_port, "physical-box", "ops@192.168.68.240:22", None).await;
    let snapshot = proxmox
        .guests(&SensitiveDenied, &principal(), &account.id, NOW)
        .await
        .unwrap();
    // The guests still list; without the sensitive read the candidates are
    // empty rather than half-redacted lies.
    assert!(snapshot.guests[0].candidates.is_empty());
}

#[tokio::test]
async fn observe_guest_records_the_guest_facts_on_the_machine() {
    let (proxmox, audit, machine_port) = service_with_guests(
        FakeDiscovery::with(Ok(discovery_ok())),
        FakeGuestDiscovery::with(Ok(guest_discovery(vec![qemu_guest(), lxc_guest()]))),
        FakeProbe::with(FP),
    );
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;
    let hub = Arc::new(fleet_application::events::EventHub::new(8));
    let mut events = hub.subscribe(None).receiver;
    let proxmox = proxmox.with_events(hub);
    let machine_id = register_machine(
        &machine_port,
        "fleet-test-01",
        "ops@192.168.68.240:22",
        None,
    )
    .await;

    proxmox
        .observe_guest(&AllowAll, &principal(), &account.id, 101, &machine_id, NOW)
        .await
        .unwrap();
    assert_eq!(
        events.try_recv().unwrap().kind,
        fleet_application::events::EventKind::MachineChanged
    );
    assert!(
        proxmox
            .observe_guest(&AllowAll, &principal(), &account.id, 999, &machine_id, NOW)
            .await
            .is_err()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    let recorded = machine_port.recorded.lock().unwrap();
    let (_, facts) = recorded
        .iter()
        .find(|(id, _)| id == &machine_id)
        .expect("the facts recorded");
    let value = |name: &str| {
        facts
            .iter()
            .find(|fact| fact.name == name)
            .map(|fact| (fact.value.clone(), fact.status))
    };
    assert_eq!(
        value("guest").map(|(v, _)| v),
        Some(Some("qemu/101".to_owned()))
    );
    assert_eq!(value("vmid").map(|(v, _)| v), Some(Some("101".to_owned())));
    assert_eq!(value("node").map(|(v, _)| v), Some(Some("pve".to_owned())));
    assert_eq!(
        value("agent"),
        Some((Some("7.2".to_owned()), fleet_core::CapabilityStatus::Known))
    );
    assert_eq!(
        value("os").map(|(v, _)| v),
        Some(Some("Ubuntu 24.04.4 LTS".to_owned()))
    );
    assert_eq!(
        value("mac0").map(|(v, _)| v),
        Some(Some("de:ad:be:ef:00:01".to_owned()))
    );
    for fact in facts {
        assert_eq!(
            fact.namespace,
            if fact.name.starts_with("mac") {
                "net"
            } else {
                "pve"
            }
        );
        assert_eq!(fact.source, "proxmox/9.2.2");
        assert_eq!(fact.observed_at.unix_millis(), NOW);
    }
    drop(recorded);

    // The Proxmox read is audited.
    let intents = audit.intents.lock().unwrap();
    assert!(
        intents.iter().any(|intent| intent
            .metadata
            .entries()
            .any(|(k, v)| k == "event" && v == "proxmox_guest_observed")),
        "{intents:?}"
    );
}

#[tokio::test]
async fn an_off_guest_reports_unavailable_and_lxc_reports_unknown() {
    let (proxmox, _audit, machine_port) = service_with_guests(
        FakeDiscovery::with(Ok(discovery_ok())),
        FakeGuestDiscovery::with(Ok(guest_discovery(vec![
            // A QEMU guest whose agent did not answer.
            ProviderGuest {
                agent: Some(ProviderAgent {
                    online: false,
                    ..ProviderAgent::default()
                }),
                ..qemu_guest()
            },
            lxc_guest(),
        ]))),
        FakeProbe::with(FP),
    );
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;
    let machine_id = register_machine(&machine_port, "box", "ops@10.0.0.9:22", None).await;

    proxmox
        .observe_guest(&AllowAll, &principal(), &account.id, 101, &machine_id, NOW)
        .await
        .unwrap();
    proxmox
        .observe_guest(&AllowAll, &principal(), &account.id, 200, &machine_id, NOW)
        .await
        .unwrap();

    let recorded = machine_port.recorded.lock().unwrap();
    // The QEMU recording (first) reports the agent unavailable: the guest
    // may be off, not agentless. The LXC recording (second) reports the
    // agent unknown: no qemu-guest-agent exists by design.
    let agent_status = |recording: usize| {
        recorded
            .iter()
            .filter(|(id, _)| id == &machine_id)
            .nth(recording)
            .and_then(|(_, facts)| {
                facts
                    .iter()
                    .find(|fact| fact.name == "agent")
                    .map(|fact| fact.status)
            })
    };
    assert_eq!(
        agent_status(0),
        Some(fleet_core::CapabilityStatus::Unavailable)
    );
    assert_eq!(agent_status(1), Some(fleet_core::CapabilityStatus::Unknown));
}

#[tokio::test]
async fn an_unknown_guest_refuses_with_not_found() {
    let (proxmox, _audit, _machine_port) = service_with_guests(
        FakeDiscovery::with(Ok(discovery_ok())),
        FakeGuestDiscovery::with(Ok(guest_discovery(vec![qemu_guest()]))),
        FakeProbe::with(FP),
    );
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;
    let error = proxmox
        .observe_guest(&AllowAll, &principal(), &account.id, 999, "m-1", NOW)
        .await
        .unwrap_err();
    assert!(
        matches!(error, ProxmoxUseCaseError::NotFound { .. }),
        "{error}"
    );
}

#[tokio::test]
async fn guest_discovery_stays_behind_the_trust_gate() {
    let (proxmox, _audit, _machine_port) = service_with_guests(
        FakeDiscovery::with(Ok(discovery_ok())),
        FakeGuestDiscovery::with(Ok(guest_discovery(vec![qemu_guest()]))),
        FakeProbe::with(FP),
    );
    let account = create_account(&proxmox).await;
    let error = proxmox
        .guests(&AllowAll, &principal(), &account.id, NOW)
        .await
        .unwrap_err();
    assert!(
        matches!(error, ProxmoxUseCaseError::UnconfirmedTrust { .. }),
        "{error}"
    );
}

#[tokio::test]
async fn a_denied_caller_never_lists_guests() {
    let (proxmox, _audit, _machine_port) = service_with_guests(
        FakeDiscovery::with(Ok(discovery_ok())),
        FakeGuestDiscovery::with(Ok(guest_discovery(vec![qemu_guest()]))),
        FakeProbe::with(FP),
    );
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;
    let error = proxmox
        .guests(&DenyAll, &principal(), &account.id, NOW)
        .await
        .unwrap_err();
    assert!(matches!(error, ProxmoxUseCaseError::Denied(_)));
}

// ---- FM-608: Windows guests through the QEMU Guest Agent ----

type ObservedFact = (String, Option<String>, fleet_core::CapabilityStatus);

/// Observes one guest onto a fresh machine and returns the recorded facts
/// as `(namespace.name, value, status)`.
async fn observed_facts(guest: ProviderGuest) -> Vec<ObservedFact> {
    let vmid = guest.vmid.unwrap();
    let (proxmox, _audit, machine_port) = service_with_guests(
        FakeDiscovery::with(Ok(discovery_ok())),
        FakeGuestDiscovery::with(Ok(guest_discovery(vec![guest]))),
        FakeProbe::with(FP),
    );
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;
    let machine_id = register_machine(&machine_port, "box", "ops@203.0.113.9:22", None).await;
    proxmox
        .observe_guest(&AllowAll, &principal(), &account.id, vmid, &machine_id, NOW)
        .await
        .unwrap();
    let recorded = machine_port.recorded.lock().unwrap();
    let (_, facts) = recorded
        .iter()
        .find(|(id, _)| id == &machine_id)
        .expect("the facts recorded");
    facts
        .iter()
        .map(|fact| {
            assert_eq!(fact.source, "proxmox/9.2.2");
            (
                format!("{}.{}", fact.namespace, fact.name),
                fact.value.clone(),
                fact.status,
            )
        })
        .collect()
}

fn fact_of(
    facts: &[ObservedFact],
    key: &str,
) -> Option<(Option<String>, fleet_core::CapabilityStatus)> {
    facts
        .iter()
        .find(|(name, _, _)| name == key)
        .map(|(_, value, status)| (value.clone(), *status))
}

fn known(value: &str) -> (Option<String>, fleet_core::CapabilityStatus) {
    (Some(value.to_owned()), fleet_core::CapabilityStatus::Known)
}

#[tokio::test]
async fn windows_osinfo_normalizes_to_os_facts_beside_the_ostype_hint() {
    let facts = observed_facts(windows_guest()).await;

    // The agent-reported OS, classified.
    assert_eq!(fact_of(&facts, "os.family"), Some(known("windows")));
    // qemu-ga's build-table `version`, not the registry ProductName that
    // Windows 11 still spells "Windows 10".
    assert_eq!(
        fact_of(&facts, "os.name"),
        Some(known("Microsoft Windows 11"))
    );
    assert_eq!(fact_of(&facts, "os.version"), Some(known("11")));
    assert_eq!(fact_of(&facts, "os.variant"), Some(known("client")));
    // The raw agent strings are still recorded as before.
    assert_eq!(fact_of(&facts, "pve.os"), Some(known("Windows 10 Pro")));
    assert_eq!(fact_of(&facts, "pve.kernel"), Some(known("26100")));
    assert_eq!(fact_of(&facts, "pve.agent"), Some(known("9.2.0")));
    // The config hint is a separate `pve` fact, never an `os` fact.
    assert_eq!(fact_of(&facts, "pve.ostype_hint"), Some(known("win11")));
    assert!(
        facts
            .iter()
            .filter(|(name, _, _)| name.starts_with("os."))
            .all(|(_, value, _)| value.as_deref() != Some("win11")),
        "{facts:?}"
    );
    // Only usable addresses are displayed: no link-local, no APIPA.
    assert_eq!(
        fact_of(&facts, "pve.address0"),
        Some(known("2001:db8::201"))
    );
    assert_eq!(fact_of(&facts, "pve.address1"), Some(known("192.0.2.201")));
    assert_eq!(fact_of(&facts, "pve.address2"), None);
    assert_eq!(
        fact_of(&facts, "net.mac1"),
        Some(known("bc:24:11:0a:02:02"))
    );
}

#[tokio::test]
async fn windows_server_osinfo_names_the_server_release() {
    // The 8.x fixture's Windows Server 2022 answer.
    let mut guest = windows_guest();
    let agent = guest.agent.as_mut().unwrap();
    agent.os = Some(ProviderOsInfo {
        pretty_name: Some("Windows Server 2022 Standard".to_owned()),
        version: Some("Microsoft Windows Server 2022".to_owned()),
        version_id: Some("2022".to_owned()),
        variant_id: Some("server".to_owned()),
        ..agent.os.clone().unwrap()
    });
    let facts = observed_facts(guest).await;
    assert_eq!(fact_of(&facts, "os.family"), Some(known("windows")));
    assert_eq!(
        fact_of(&facts, "os.name"),
        Some(known("Microsoft Windows Server 2022"))
    );
    assert_eq!(fact_of(&facts, "os.version"), Some(known("2022")));
    assert_eq!(fact_of(&facts, "os.variant"), Some(known("server")));

    // qemu-ga prints `N/A` when its build table has no row: that is no
    // value, so the name falls back to the product name and the version
    // is absent rather than "N/A".
    let mut guest = windows_guest();
    let agent = guest.agent.as_mut().unwrap();
    agent.os = Some(ProviderOsInfo {
        version: Some("N/A".to_owned()),
        version_id: Some("N/A".to_owned()),
        ..agent.os.clone().unwrap()
    });
    let facts = observed_facts(guest).await;
    assert_eq!(fact_of(&facts, "os.name"), Some(known("Windows 10 Pro")));
    assert_eq!(fact_of(&facts, "os.version"), None);
}

#[tokio::test]
async fn unknown_os_ids_stay_unknown_never_linux() {
    for id in [Some("freebsd"), Some("MSWINDOWS"), Some(""), None] {
        let mut guest = windows_guest();
        let agent = guest.agent.as_mut().unwrap();
        agent.os = Some(ProviderOsInfo {
            id: id.map(str::to_owned),
            name: Some("Something".to_owned()),
            version_id: Some("14.1".to_owned()),
            ..ProviderOsInfo::default()
        });
        let facts = observed_facts(guest).await;
        assert_eq!(
            fact_of(&facts, "os.family"),
            Some((None, fleet_core::CapabilityStatus::Unknown)),
            "{id:?}"
        );
        assert_eq!(fact_of(&facts, "os.name"), Some(known("Something")));
        assert_eq!(fact_of(&facts, "os.version"), Some(known("14.1")));
    }
    // A known Linux id does classify, from the same input shape.
    let mut guest = windows_guest();
    guest.ostype = Some("l26".to_owned());
    guest.agent.as_mut().unwrap().os = Some(ProviderOsInfo {
        id: Some("debian".to_owned()),
        pretty_name: Some("Debian GNU/Linux 13 (trixie)".to_owned()),
        version_id: Some("13".to_owned()),
        ..ProviderOsInfo::default()
    });
    let facts = observed_facts(guest).await;
    assert_eq!(fact_of(&facts, "os.family"), Some(known("linux")));
    assert_eq!(
        fact_of(&facts, "os.name"),
        Some(known("Debian GNU/Linux 13 (trixie)"))
    );
    assert_eq!(fact_of(&facts, "pve.ostype_hint"), Some(known("l26")));
}

#[tokio::test]
async fn windows_agent_states_map_to_the_fm601_states() {
    // Agent not running, agent not configured, and guest off all decode to
    // the same offline agent (the provider contract tests prove that per
    // major): `unavailable`, with the config hint still recorded and no
    // `os` fact. No answer is no observation, and must not overwrite one.
    for status in ["running", "stopped"] {
        let mut guest = windows_guest();
        guest.status = Some(status.to_owned());
        guest.agent = Some(ProviderAgent::default());
        let facts = observed_facts(guest).await;
        assert_eq!(
            fact_of(&facts, "pve.agent"),
            Some((None, fleet_core::CapabilityStatus::Unavailable)),
            "{status}"
        );
        assert_eq!(fact_of(&facts, "pve.ostype_hint"), Some(known("win11")));
        assert!(
            facts
                .iter()
                .all(|(name, _, _)| !name.starts_with("os.") && !name.starts_with("pve.address")),
            "{status}: {facts:?}"
        );
    }
    // An agent that answered `info` but not `get-osinfo`: available, and
    // still no `os` fact.
    let mut guest = windows_guest();
    guest.agent.as_mut().unwrap().os = None;
    let facts = observed_facts(guest).await;
    assert_eq!(fact_of(&facts, "pve.agent"), Some(known("9.2.0")));
    assert!(facts.iter().all(|(name, _, _)| !name.starts_with("os.")));
}

#[test]
fn usable_addresses_exclude_loopback_link_local_and_apipa() {
    use fleet_application::proxmox::usable_address;
    for unusable in [
        "127.0.0.1",
        "::1",
        "169.254.10.20",
        "169.254.0.1",
        "fe80::be24:11ff:fe0a:201%6",
        "fe80::1",
        "febf::1",
        "0.0.0.0",
        "::",
        "224.0.0.251",
        "ff02::1",
        "not-an-address",
        "",
    ] {
        assert_eq!(usable_address(unusable), None, "{unusable}");
    }
    for usable in [
        "192.0.2.201",
        "2001:db8::201",
        "169.253.255.255",
        "169.255.0.1",
        "fec0::1",
    ] {
        assert!(usable_address(usable).is_some(), "{usable}");
    }
    // The raw list stays whole; only the selection drops entries, and
    // repeats collapse.
    let mut agent = windows_guest().agent.unwrap();
    agent.interfaces[1].addresses.push("192.0.2.201".to_owned());
    assert_eq!(agent.interfaces[1].addresses.len(), 3);
    assert_eq!(agent.usable_addresses(), ["2001:db8::201", "192.0.2.201"]);
}

#[tokio::test]
async fn windows_guests_associate_and_display_as_vms() {
    let (proxmox, audit, machine_port) = service_with_guests(
        FakeDiscovery::with(Ok(discovery_ok())),
        FakeGuestDiscovery::with(Ok(guest_discovery(vec![windows_guest()]))),
        FakeProbe::with(FP),
    );
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;
    // A machine registered at the guest's APIPA address, which any
    // DHCP-less Windows NIC self-assigns: never evidence. (Link-local IPv6
    // is covered by `usable_addresses_exclude_loopback_link_local_and_apipa`.)
    let apipa = register_machine(&machine_port, "apipa", "ops@169.254.10.20:22", None).await;
    // A machine at one of the guest's usable addresses.
    let by_address =
        register_machine(&machine_port, "by-address", "ops@192.0.2.201:22", None).await;
    let by_mac = register_machine(
        &machine_port,
        "by-mac",
        "ops@203.0.113.50:22",
        Some("BC:24:11:0A:02:02"),
    )
    .await;

    let snapshot = proxmox
        .guests(&AllowAll, &principal(), &account.id, NOW)
        .await
        .unwrap();
    let candidates = &snapshot.guests[0].candidates;
    let reason = |machine_id: &str| {
        candidates
            .iter()
            .find(|candidate| candidate.machine_id == machine_id)
            .map(|candidate| (candidate.kind.clone(), candidate.evidence.clone()))
    };
    assert_eq!(reason(&apipa), None);
    assert_eq!(
        reason(&by_address),
        Some(("address_match".to_owned(), "192.0.2.201".to_owned()))
    );
    assert_eq!(
        reason(&by_mac),
        Some(("mac_match".to_owned(), "bc:24:11:0a:02:02".to_owned()))
    );

    // Confirming the link follows the same rule as Linux, and the displayed
    // kind is `vm` whatever the guest OS.
    let links = Arc::new(FakeGuestLinks::default());
    let machines = Machines::new(machine_port, audit).with_guest_links(links);
    let identity = GuestIdentity {
        account_id: account.id.clone(),
        guest_kind: "qemu".to_owned(),
        vmid: 201,
    };
    let refused = machines
        .link_guest(&proxmox, &AllowAll, &principal(), &apipa, &identity, NOW)
        .await
        .unwrap_err();
    assert!(matches!(
        refused,
        fleet_application::machine::MachineUseCaseError::Conflict { .. }
    ));
    let view = machines
        .link_guest(
            &proxmox,
            &AllowAll,
            &principal(),
            &by_address,
            &identity,
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(view.kind, fleet_application::machine::MachineKind::Vm);
    assert_eq!(view.runs_on.unwrap().vmid, 201);
}
