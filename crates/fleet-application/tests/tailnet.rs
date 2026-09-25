//! The tailnet use cases over fakes: correlation is evidence only, import
//! walks the onboarding flow, and the credentials never surface.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditOutcome};
use fleet_application::authz::{
    AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, ReasonId,
};
use fleet_application::machine::{
    Endpoint, Machine, MachineFilter, MachinePort, Machines, NewEndpoint, RegisterMachine,
};
use fleet_application::onboarding::{Onboarding, OnboardingPort};
use fleet_application::operation::AuditPort;
use fleet_application::operation::PortFailure;
use fleet_application::tailnet::TailnetUseCaseError;
use fleet_application::tailnet::{
    TailnetCredentialStore as _, TailnetCredentials, TailnetDevice, TailnetIntegration,
    TailnetSource, TailnetSourceError,
};
use fleet_core::{CapabilityFact, EndpointKind};

const NOW: i64 = 1_800_000_000_000;

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

/// Permits everything but the sensitive read, so correlation degradation
/// can be observed.
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

#[derive(Debug, Default)]
struct DenyAll;

impl Authorizer for DenyAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::deny(ReasonId::UnknownPrincipal)
    }
}

fn device(node_id: &str, hostname: &str, address: &str) -> TailnetDevice {
    TailnetDevice {
        node_id: node_id.to_owned(),
        id: Some("1503".to_owned()),
        name: format!("{hostname}.tail-example.ts.net."),
        hostname: hostname.to_owned(),
        os: "linux".to_owned(),
        addresses: vec![address.to_owned()],
        tags: vec![],
        user: "amelie@example.com".to_owned(),
        online: Some(true),
        connected_to_control: Some(true),
        last_seen: None,
    }
}

/// The source over recorded devices; a switch makes it fail like the real
/// API would.
#[derive(Debug, Default)]
struct FakeSource {
    devices: Mutex<Vec<TailnetDevice>>,
    failure: Mutex<Option<TailnetSourceError>>,
    calls: Mutex<usize>,
}

impl FakeSource {
    fn fail_with(&self, error: TailnetSourceError) {
        *self.failure.lock().unwrap() = Some(error);
    }

    fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

#[async_trait]
impl TailnetSource for FakeSource {
    async fn list_devices(
        &self,
        _tailnet: &str,
        _credentials: &TailnetCredentials,
    ) -> Result<Vec<TailnetDevice>, TailnetSourceError> {
        *self.calls.lock().unwrap() += 1;
        if let Some(error) = self.failure.lock().unwrap().take() {
            return Err(error);
        }
        Ok(self.devices.lock().unwrap().clone())
    }
}

/// The credential store as an in-memory stand-in.
#[derive(Debug, Default)]
struct FakeCredentialStore {
    stored: Mutex<Option<(String, String)>>,
    reads: Mutex<usize>,
    fail_next_store: Mutex<bool>,
    fail_next_clear: Mutex<bool>,
}

#[async_trait]
impl fleet_application::tailnet::TailnetCredentialStore for FakeCredentialStore {
    async fn load(&self) -> Result<Option<TailnetCredentials>, String> {
        *self.reads.lock().unwrap() += 1;
        Ok(self
            .stored
            .lock()
            .unwrap()
            .clone()
            .map(|(client_id, secret)| TailnetCredentials {
                client_id,
                client_secret: fleet_core::SensitiveString::new(secret),
            }))
    }

    async fn store(&self, client_id: &str, client_secret: &str) -> Result<(), String> {
        *self.stored.lock().unwrap() = Some((client_id.to_owned(), client_secret.to_owned()));
        if std::mem::take(&mut *self.fail_next_store.lock().unwrap()) {
            return Err("simulated partial store failure".to_owned());
        }
        Ok(())
    }

    async fn clear(&self) -> Result<(), String> {
        if std::mem::take(&mut *self.fail_next_clear.lock().unwrap()) {
            return Err("simulated clear failure".to_owned());
        }
        *self.stored.lock().unwrap() = None;
        Ok(())
    }
}

/// The machine store, planted and observed through the surface correlation
/// and import touch.
#[derive(Debug, Default)]
struct FakeMachines {
    machines: Mutex<Vec<Machine>>,
}

impl FakeMachines {
    fn plant(self, machine: Machine) -> Self {
        self.machines.lock().unwrap().push(machine);
        self
    }
}

fn machine_record(id: &str, reference: &str) -> Machine {
    Machine {
        id: id.to_owned(),
        name: id.to_owned(),
        description: String::new(),
        endpoints: vec![Endpoint {
            id: format!("{id}-endpoint"),
            kind: EndpointKind::Ssh,
            reference: reference.to_owned(),
        }],
        tags: Vec::new(),
        groups: Vec::new(),
        capabilities: Vec::new(),
        last_observation: None,
        node: None,
        created_at: 0,
        updated_at: 0,
    }
}

#[async_trait]
impl MachinePort for FakeMachines {
    async fn register(&self, registration: &RegisterMachine) -> Result<Machine, PortFailure> {
        let machine = Machine {
            id: registration.name.clone(),
            name: registration.name.clone(),
            description: registration.description.clone(),
            endpoints: registration
                .endpoints
                .iter()
                .enumerate()
                .map(|(index, new)| Endpoint {
                    id: format!("{}-endpoint-{index}", registration.name),
                    kind: new.kind,
                    reference: new.reference.clone(),
                })
                .collect(),
            tags: registration.tags.clone(),
            groups: registration.groups.clone(),
            capabilities: Vec::new(),
            last_observation: None,
            node: None,
            created_at: 0,
            updated_at: 0,
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
                what: format!("machine {id:?}"),
            })
    }

    async fn list(&self, _filter: &MachineFilter, limit: u32) -> Result<Vec<Machine>, PortFailure> {
        let machines = self.machines.lock().unwrap();
        Ok(machines.iter().take(limit as usize).cloned().collect())
    }

    async fn update(&self, _: &str, _: &str, _: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by the tailnet use cases")
    }

    async fn set_endpoints(&self, _: &str, _: &[NewEndpoint]) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by the tailnet use cases")
    }

    async fn add_tag(&self, _: &str, _: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by the tailnet use cases")
    }

    async fn remove_tag(&self, _: &str, _: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by the tailnet use cases")
    }

    async fn add_group(&self, _: &str, _: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by the tailnet use cases")
    }

    async fn remove_group(&self, _: &str, _: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by the tailnet use cases")
    }

    async fn record_snapshot(&self, _: &str, _: &str, _: &str, _: i64) -> Result<(), PortFailure> {
        unimplemented!("not exercised by the tailnet use cases")
    }

    async fn record_capabilities(
        &self,
        _id: &str,
        _facts: &[CapabilityFact],
    ) -> Result<(), PortFailure> {
        unimplemented!("not exercised by the tailnet use cases")
    }

    async fn delete(&self, _: &str) -> Result<(), PortFailure> {
        unimplemented!("not exercised by the tailnet use cases")
    }

    async fn confirm_fingerprint(&self, _: &str, _: &str, _: i64) -> Result<(), PortFailure> {
        unimplemented!("not exercised by the tailnet use cases")
    }

    async fn verified_fingerprint(&self, _: &str) -> Result<Option<String>, PortFailure> {
        Ok(None)
    }

    async fn latest_inventory_revision(&self, _: &str) -> Result<Option<u64>, PortFailure> {
        Ok(None)
    }
}

#[derive(Debug, Default)]
struct FakeOnboarding {
    drafts: Mutex<Vec<fleet_application::onboarding::OnboardingDraft>>,
}

#[async_trait]
impl OnboardingPort for FakeOnboarding {
    async fn create(
        &self,
        draft: &fleet_application::onboarding::NewDraft,
    ) -> Result<fleet_application::onboarding::OnboardingDraft, PortFailure> {
        let now = fleet_core::SystemClock::now_unix_millis();
        let created = fleet_application::onboarding::OnboardingDraft {
            id: format!("draft-{}", self.drafts.lock().unwrap().len() + 1),
            endpoint: draft.endpoint.clone(),
            auth: draft.auth.clone(),
            name: draft
                .name
                .clone()
                .unwrap_or_else(|| draft.endpoint.host.clone()),
            description: draft.description.clone(),
            tags: draft.tags.clone(),
            groups: draft.groups.clone(),
            host_key: None,
            host_key_stage: fleet_application::onboarding::HostKeyStage::Unseen,
            confirmed_fingerprint: None,
            last_test: None,
            facts: Vec::new(),
            discovery_source: None,
            discovered_at: None,
            idempotency_key: draft.idempotency_key.clone(),
            created_at: now,
            updated_at: now,
        };
        self.drafts.lock().unwrap().push(created.clone());
        Ok(created)
    }

    async fn find_by_idempotency_key(
        &self,
        key: &str,
    ) -> Result<Option<fleet_application::onboarding::OnboardingDraft>, PortFailure> {
        Ok(self
            .drafts
            .lock()
            .unwrap()
            .iter()
            .find(|draft| draft.idempotency_key.as_deref() == Some(key))
            .cloned())
    }

    async fn get(
        &self,
        _id: &str,
    ) -> Result<fleet_application::onboarding::OnboardingDraft, PortFailure> {
        unimplemented!("not exercised by the tailnet use cases")
    }

    async fn list(
        &self,
        _limit: u32,
    ) -> Result<Vec<fleet_application::onboarding::OnboardingDraft>, PortFailure> {
        unimplemented!("not exercised by the tailnet use cases")
    }

    async fn update(
        &self,
        _draft: &fleet_application::onboarding::OnboardingDraft,
    ) -> Result<fleet_application::onboarding::OnboardingDraft, PortFailure> {
        unimplemented!("not exercised by the tailnet use cases")
    }

    async fn delete(&self, _id: &str) -> Result<(), PortFailure> {
        unimplemented!("not exercised by the tailnet use cases")
    }
}

#[derive(Debug, Default)]
struct FakeAudit {
    events: Mutex<Vec<AuditIntent>>,
}

#[async_trait]
impl AuditPort for FakeAudit {
    async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
        self.events.lock().unwrap().push(intent.clone());
        Ok(())
    }

    async fn record_outcome(&self, _: &str, _: AuditOutcome) -> Result<(), String> {
        Ok(())
    }
}

struct Fixture {
    source: Arc<FakeSource>,
    credentials: Arc<FakeCredentialStore>,
    onboarding: Arc<FakeOnboarding>,
    machines: Arc<FakeMachines>,
    audit: Arc<FakeAudit>,
    events: Arc<fleet_application::events::EventHub>,
    tailnet: TailnetIntegration,
}

fn compose(machines: FakeMachines, devices: Vec<TailnetDevice>) -> Fixture {
    let source = Arc::new(FakeSource {
        devices: Mutex::new(devices),
        ..Default::default()
    });
    let credentials = Arc::new(FakeCredentialStore::default());
    let onboarding = Arc::new(FakeOnboarding::default());
    let machines = Arc::new(machines);
    let audit = Arc::new(FakeAudit::default());
    let events = Arc::new(fleet_application::events::EventHub::new(8));
    let tailnet = TailnetIntegration::new(
        source.clone(),
        credentials.clone(),
        Arc::new(Onboarding::new(
            onboarding.clone(),
            // The trust port is never touched before add: the import stops
            // at the draft.
            Arc::new(FakeTrust),
            Arc::new(Machines::new(machines.clone(), audit.clone())),
            audit.clone(),
        )),
        Arc::new(Machines::new(machines.clone(), audit.clone())),
        audit.clone(),
    )
    .with_events(events.clone());
    Fixture {
        source,
        credentials,
        onboarding,
        machines,
        audit,
        events,
        tailnet,
    }
}

/// The onboarding's trust port is never reached by the import (which stops
/// at the draft); a panicking stand-in proves that.
#[derive(Debug, Default)]
struct FakeTrust;

#[async_trait]
impl fleet_application::onboarding::OnboardTrustPort for FakeTrust {
    async fn pin(
        &self,
        _host: &str,
        _key: &fleet_application::onboarding::OnboardHostKey,
    ) -> Result<(), PortFailure> {
        panic!("the import must not pin anything")
    }

    async fn unpin(&self, _host: &str) -> Result<(), PortFailure> {
        panic!("the import must not unpin anything")
    }
}

#[tokio::test]
async fn configure_stores_and_reports_without_the_secret() {
    let fixture = compose(FakeMachines::default(), Vec::new());
    let mut changes = fixture.events.subscribe(None).receiver;
    let unconfigured = fixture
        .tailnet
        .status(&AllowAll, &principal())
        .await
        .unwrap();
    assert!(!unconfigured.configured);
    assert!(unconfigured.client_id.is_none());
    assert_eq!(unconfigured.scope, "devices:core:read");

    let configured = fixture
        .tailnet
        .configure(&AllowAll, &principal(), "k-client", "tskey-client-secret")
        .await
        .unwrap();
    assert!(configured.configured);
    assert_eq!(configured.client_id.as_deref(), Some("k-client"));
    assert_eq!(
        changes.try_recv().unwrap().kind,
        fleet_application::events::EventKind::TailnetChanged
    );
    // The stored credential keeps the secret; the status carries only the id.
    let stored = fixture.credentials.stored.lock().unwrap().clone().unwrap();
    assert_eq!(stored.1, "tskey-client-secret");

    // The audit names the action and the client id, never the secret.
    let events = fixture.audit.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    let metadata_json = events[0].metadata.to_json();
    assert!(metadata_json.contains("k-client"));
    assert!(
        !metadata_json.contains("tskey-client-secret"),
        "{metadata_json}"
    );
}

#[tokio::test]
async fn clear_removes_the_credentials_and_audits() {
    let fixture = compose(FakeMachines::default(), Vec::new());
    let mut changes = fixture.events.subscribe(None).receiver;
    fixture
        .tailnet
        .configure(&AllowAll, &principal(), "k-client", "tskey-client-secret")
        .await
        .unwrap();
    assert_eq!(
        changes.try_recv().unwrap().kind,
        fleet_application::events::EventKind::TailnetChanged
    );
    let cleared = fixture
        .tailnet
        .clear(&AllowAll, &principal())
        .await
        .unwrap();
    assert_eq!(
        changes.try_recv().unwrap().kind,
        fleet_application::events::EventKind::TailnetChanged
    );
    assert!(!cleared.configured);
    assert!(fixture.credentials.stored.lock().unwrap().is_none());
    let events = fixture.audit.events.lock().unwrap();
    assert_eq!(events.len(), 2, "configured then cleared");
    assert!(events[1].metadata.to_json().contains("tailscale_cleared"));
}

#[tokio::test]
async fn partially_committed_tailnet_credentials_are_invalidated_on_rollback_failure() {
    let fixture = compose(FakeMachines::default(), Vec::new());
    let mut changes = fixture.events.subscribe(None).receiver;
    *fixture.credentials.fail_next_store.lock().unwrap() = true;
    *fixture.credentials.fail_next_clear.lock().unwrap() = true;

    let error = fixture
        .tailnet
        .configure(&AllowAll, &principal(), "k-client", "tskey-client-secret")
        .await
        .unwrap_err();

    assert!(matches!(error, TailnetUseCaseError::Backend { .. }));
    assert_eq!(
        changes.try_recv().unwrap().kind,
        fleet_application::events::EventKind::TailnetChanged
    );
    assert!(fixture.credentials.stored.lock().unwrap().is_some());
}

#[tokio::test]
async fn listing_correlates_by_address_and_name_but_never_merges() {
    let fixture = compose(
        FakeMachines::default()
            .plant(machine_record("by-address", "ops@100.64.0.10:22"))
            .plant(machine_record("by-name", "ops@build-host:22")),
        vec![
            device("n1", "build-host", "100.64.0.10"),
            device("n2", "unknown-box", "100.99.99.99"),
        ],
    );
    fixture
        .credentials
        .store("k-client", "tskey-client-secret")
        .await
        .unwrap();

    let correlated = fixture
        .tailnet
        .list(&AllowAll, &principal(), NOW)
        .await
        .unwrap();
    assert_eq!(correlated.len(), 2);

    let first = &correlated[0];
    assert_eq!(first.candidates.len(), 2, "both machines are candidates");
    let address_candidate = first
        .candidates
        .iter()
        .find(|candidate| candidate.machine_id == "by-address")
        .unwrap();
    assert_eq!(address_candidate.kind.id(), "address_match");
    let name_candidate = first
        .candidates
        .iter()
        .find(|candidate| candidate.machine_id == "by-name")
        .unwrap();
    assert_eq!(name_candidate.kind.id(), "name_match");

    let second = &correlated[1];
    assert!(second.candidates.is_empty(), "no match, no claim");

    // The machines record is untouched: correlation is evidence only.
    assert_eq!(fixture.machines.machines.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn correlation_degrades_honestly_without_the_sensitive_permission() {
    let fixture = compose(
        FakeMachines::default().plant(machine_record("by-address", "ops@100.64.0.10:22")),
        vec![device("n1", "build-host", "100.64.0.10")],
    );
    fixture
        .credentials
        .store("k-client", "tskey-client-secret")
        .await
        .unwrap();

    let correlated = fixture
        .tailnet
        .list(&SensitiveDenied, &principal(), NOW)
        .await
        .unwrap();
    assert!(
        correlated[0].candidates.is_empty(),
        "no hosts, no half-redacted lies"
    );
}

#[tokio::test]
async fn import_hands_the_device_to_the_onboarding_flow() {
    let fixture = compose(
        FakeMachines::default(),
        vec![device("nABC", "build-host", "100.64.0.10")],
    );
    fixture
        .credentials
        .store("k-client", "tskey-client-secret")
        .await
        .unwrap();

    let draft = fixture
        .tailnet
        .import(&AllowAll, &principal(), "nABC", "ops", Some(2222), None)
        .await
        .unwrap();
    assert_eq!(draft.endpoint.host, "100.64.0.10");
    assert_eq!(draft.endpoint.user, "ops");
    assert_eq!(draft.endpoint.port, 2222);
    assert_eq!(draft.name, "build-host");
    assert!(
        draft.description.contains("nABC"),
        "the draft carries the device provenance: {}",
        draft.description
    );

    // The draft is a real onboarding draft: the trust flow takes it from
    // here (and nothing was pinned by the import).
    let stored = fixture.onboarding.drafts.lock().unwrap();
    assert_eq!(stored.len(), 1);
    assert!(stored[0].host_key.is_none());
}

#[tokio::test]
async fn tailnet_import_reports_idempotent_replays_without_a_new_draft() {
    let fixture = compose(
        FakeMachines::default(),
        vec![device("nABC", "build-host", "100.64.0.10")],
    );
    fixture
        .credentials
        .store("k-client", "tskey-client-secret")
        .await
        .unwrap();

    let (created, inserted) = fixture
        .tailnet
        .import_with_outcome(
            &AllowAll,
            &principal(),
            "nABC",
            "ops",
            None,
            Some("retry-key"),
        )
        .await
        .unwrap();
    assert!(inserted);
    let (replayed, inserted) = fixture
        .tailnet
        .import_with_outcome(
            &AllowAll,
            &principal(),
            "nABC",
            "ops",
            None,
            Some("retry-key"),
        )
        .await
        .unwrap();
    assert!(!inserted);
    assert_eq!(replayed.id, created.id);
    assert_eq!(fixture.onboarding.drafts.lock().unwrap().len(), 1);
    assert_eq!(
        fixture.source.calls(),
        1,
        "the replay skips a second import"
    );
}

#[tokio::test]
async fn import_refuses_an_unknown_device_or_a_device_without_an_ipv4() {
    let fixture = compose(
        FakeMachines::default(),
        vec![device("nABC", "build-host", "fd7a:115c:a1e0::1")],
    );
    fixture
        .credentials
        .store("k-client", "tskey-client-secret")
        .await
        .unwrap();

    let unknown = fixture
        .tailnet
        .import(&AllowAll, &principal(), "nMISSING", "ops", None, None)
        .await
        .unwrap_err();
    assert!(
        matches!(unknown, TailnetUseCaseError::NotFound { .. }),
        "{unknown:?}"
    );

    let no_ipv4 = fixture
        .tailnet
        .import(&AllowAll, &principal(), "nABC", "ops", None, None)
        .await
        .unwrap_err();
    assert!(
        no_ipv4.to_string().contains("no Tailscale IPv4 address"),
        "{no_ipv4}"
    );
}

#[tokio::test]
async fn an_unconfigured_integration_refuses_listing_and_import() {
    let fixture = compose(
        FakeMachines::default(),
        vec![device("n1", "h", "100.0.0.1")],
    );
    let listing = fixture
        .tailnet
        .list(&AllowAll, &principal(), NOW)
        .await
        .unwrap_err();
    assert!(matches!(listing, TailnetUseCaseError::Unconfigured));
    let import = fixture
        .tailnet
        .import(&AllowAll, &principal(), "n1", "ops", None, None)
        .await
        .unwrap_err();
    assert!(matches!(import, TailnetUseCaseError::Unconfigured));
}

#[tokio::test]
async fn source_failures_surface_with_their_taxonomy() {
    let fixture = compose(FakeMachines::default(), vec![]);
    fixture
        .credentials
        .store("k-client", "tskey-client-secret")
        .await
        .unwrap();
    fixture.source.fail_with(TailnetSourceError::RateLimited {
        retry_after_secs: Some(9),
    });

    let error = fixture
        .tailnet
        .list(&AllowAll, &principal(), NOW)
        .await
        .unwrap_err();
    match error {
        TailnetUseCaseError::Source(TailnetSourceError::RateLimited { retry_after_secs }) => {
            assert_eq!(retry_after_secs, Some(9));
        }
        other => panic!("expected the rate limit to surface, got {other:?}"),
    }
}

#[tokio::test]
async fn denied_callers_are_refused_before_any_network_or_store_touch() {
    let fixture = compose(FakeMachines::default(), vec![]);
    let deny = DenyAll;
    assert!(matches!(
        fixture.tailnet.status(&deny, &principal()).await,
        Err(TailnetUseCaseError::Denied(_))
    ));
    assert!(matches!(
        fixture
            .tailnet
            .configure(&deny, &principal(), "k", "s")
            .await,
        Err(TailnetUseCaseError::Denied(_))
    ));
    assert!(matches!(
        fixture.tailnet.list(&deny, &principal(), NOW).await,
        Err(TailnetUseCaseError::Denied(_))
    ));
    assert!(fixture.credentials.stored.lock().unwrap().is_none());
    assert!(fixture.source.calls() == 0, "no source call on denial");
}

#[tokio::test]
async fn a_malformed_configure_request_is_refused() {
    let fixture = compose(FakeMachines::default(), Vec::new());
    let too_long = "x".repeat(300);
    let error = fixture
        .tailnet
        .configure(&AllowAll, &principal(), "k-client", &too_long)
        .await
        .unwrap_err();
    assert!(
        matches!(error, TailnetUseCaseError::Invalid { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn the_use_case_error_maps_the_onboarding_denial() {
    #[derive(Debug, Default)]
    struct MachineCreateDenied;
    impl Authorizer for MachineCreateDenied {
        fn decide(&self, request: AccessRequest<'_>) -> Decision {
            if request.action == Permission::MachineCreate {
                return Decision::deny(ReasonId::PolicyAllow);
            }
            Decision::allow()
        }
    }

    // An import by a caller without machine.create surfaces as a denial.
    let fixture = compose(
        FakeMachines::default(),
        vec![device("nABC", "build-host", "100.64.0.10")],
    );
    fixture
        .credentials
        .store("k-client", "tskey-client-secret")
        .await
        .unwrap();

    // DenyAll denies both tailscale.read and machine.create; the first
    // check fires.
    let denied = fixture
        .tailnet
        .import(&DenyAll, &principal(), "nABC", "ops", None, None)
        .await
        .unwrap_err();
    assert!(matches!(denied, TailnetUseCaseError::Denied(_)));

    // With the tailnet read allowed but machine.create denied, the
    // onboarding's own funnel refuses.
    let machine_create_denied = MachineCreateDenied;
    let denied = fixture
        .tailnet
        .import(
            &machine_create_denied,
            &principal(),
            "nABC",
            "ops",
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            denied,
            TailnetUseCaseError::Denied(_) | TailnetUseCaseError::Invalid { .. }
        ),
        "the onboarding funnel's decision is honored: {denied:?}"
    );
}
