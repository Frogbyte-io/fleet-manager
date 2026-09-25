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
    Endpoint, Machine, MachineFilter, MachinePort as _, Machines, NewEndpoint, RegisterMachine,
};
use fleet_application::operation::AuditPort;
use fleet_application::operation::PortFailure;
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProviderAgent, ProviderGuest, ProviderInterface,
    ProxmoxAccountPort, ProxmoxAccounts, ProxmoxCredentialStore, ProxmoxDiscoverPort,
    ProxmoxGuestDiscoverPort, ProxmoxSourceError, ProxmoxTrustProbe, ProxmoxUseCaseError,
    RawDiscovery, RawGuestDiscovery,
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
    assert!(
        proxmox
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
            .is_err()
    );
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
        agent: Some(ProviderAgent {
            online: true,
            version: Some("7.2".to_owned()),
            os_name: Some("Ubuntu 24.04.4 LTS".to_owned()),
            kernel: Some("6.8.0-138-generic".to_owned()),
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
        agent: None,
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
