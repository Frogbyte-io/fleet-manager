//! The onboarding use cases: staged trust, reviewable facts, duplicate
//! warnings, and the draft lifecycle — with no network and no database, so
//! the rules themselves are what the tests see.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::AuditIntent;
use fleet_application::authz::{
    AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, ReasonId,
};
use fleet_application::machine::{
    Endpoint, Machine, MachineFilter, MachinePort, Machines, NewEndpoint, RegisterMachine,
};
use fleet_application::onboarding::{
    DraftEndpoint, DraftStage, HostKeyStage, NewDraft, OnboardAuth, OnboardHostKey,
    OnboardTrustPort, Onboarding, OnboardingDraft, OnboardingPort, OnboardingUseCaseError,
    endpoint_reference_matches, profile_hint,
};
use fleet_application::operation::PortFailure;
use fleet_core::{CapabilityFact, CapabilityStatus, EndpointKind, Timestamp};

const NOW: i64 = 1_800_000_000_000;
const FINGERPRINT: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OTHER_FINGERPRINT: &str = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

fn principal() -> ActingPrincipal {
    ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }
}

fn new_draft() -> NewDraft {
    NewDraft {
        endpoint: DraftEndpoint {
            user: "deploy".to_owned(),
            host: "host-one".to_owned(),
            port: 22,
        },
        auth: OnboardAuth::Agent,
        name: Some("target".to_owned()),
        description: String::new(),
        tags: vec![],
        groups: vec![],
        idempotency_key: None,
    }
}

fn observed_host_key(fingerprint: &str) -> OnboardHostKey {
    OnboardHostKey {
        key_type: "ED25519".to_owned(),
        fingerprint: fingerprint.to_owned(),
        raw_line: format!("[host-one]:22 ssh-ed25519 {fingerprint}"),
    }
}

fn fact(namespace: &str, name: &str, value: &str) -> CapabilityFact {
    CapabilityFact {
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        value: Some(value.to_owned()),
        status: CapabilityStatus::Known,
        observed_at: Timestamp::from_unix_millis(NOW),
        source: "agentless/1".to_owned(),
    }
}

/// The trust port as a recording stand-in: pins and unpins are counted, and
/// a switch makes the store unwritable so the use case's failure path shows.
#[derive(Debug, Default)]
struct FakeTrust {
    pins: Mutex<Vec<(String, String)>>,
    unpins: Mutex<Vec<String>>,
    broken: Mutex<bool>,
}

impl FakeTrust {
    fn pin_count(&self) -> usize {
        self.pins.lock().unwrap().len()
    }

    fn unpin_count(&self) -> usize {
        self.unpins.lock().unwrap().len()
    }
}

#[async_trait]
impl OnboardTrustPort for FakeTrust {
    async fn pin(&self, host: &str, key: &OnboardHostKey) -> Result<(), PortFailure> {
        if *self.broken.lock().unwrap() {
            return Err(PortFailure::Backend {
                detail: "the trust store is unwritable".to_owned(),
            });
        }
        self.pins
            .lock()
            .unwrap()
            .push((host.to_owned(), key.raw_line.clone()));
        Ok(())
    }

    async fn unpin(&self, host: &str) -> Result<(), PortFailure> {
        if *self.broken.lock().unwrap() {
            return Err(PortFailure::Backend {
                detail: "the trust store is unwritable".to_owned(),
            });
        }
        self.unpins.lock().unwrap().push(host.to_owned());
        Ok(())
    }
}

/// The draft store as an in-memory stand-in, with a mutation hook so tests
/// can play the executor's role (record an observation, flip a stage).
#[derive(Debug, Default)]
struct FakeDrafts {
    drafts: Mutex<Vec<OnboardingDraft>>,
}

impl FakeDrafts {
    fn mutate<F: FnOnce(&mut OnboardingDraft)>(&self, id: &str, change: F) {
        let mut drafts = self.drafts.lock().unwrap();
        let draft = drafts
            .iter_mut()
            .find(|draft| draft.id == id)
            .expect("the draft exists");
        change(draft);
    }

    fn get_raw(&self, id: &str) -> Option<OnboardingDraft> {
        self.drafts
            .lock()
            .unwrap()
            .iter()
            .find(|draft| draft.id == id)
            .cloned()
    }
}

#[async_trait]
impl OnboardingPort for FakeDrafts {
    async fn create(&self, draft: &NewDraft) -> Result<OnboardingDraft, PortFailure> {
        let now = fleet_core::SystemClock::now_unix_millis();
        let created = OnboardingDraft {
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
            host_key_stage: HostKeyStage::Unseen,
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

    async fn get(&self, id: &str) -> Result<OnboardingDraft, PortFailure> {
        self.get_raw(id).ok_or_else(|| PortFailure::NotFound {
            what: format!("onboarding draft {id:?}"),
        })
    }

    async fn list(&self, limit: u32) -> Result<Vec<OnboardingDraft>, PortFailure> {
        let drafts = self.drafts.lock().unwrap();
        Ok(drafts.iter().take(limit as usize).cloned().collect())
    }

    async fn update(&self, draft: &OnboardingDraft) -> Result<OnboardingDraft, PortFailure> {
        let mut drafts = self.drafts.lock().unwrap();
        let slot = drafts
            .iter_mut()
            .find(|existing| existing.id == draft.id)
            .ok_or_else(|| PortFailure::NotFound {
                what: format!("onboarding draft {:?}", draft.id),
            })?;
        *slot = draft.clone();
        Ok(draft.clone())
    }

    async fn delete(&self, id: &str) -> Result<(), PortFailure> {
        let mut drafts = self.drafts.lock().unwrap();
        let before = drafts.len();
        drafts.retain(|draft| draft.id != id);
        if drafts.len() == before {
            return Err(PortFailure::NotFound {
                what: format!("onboarding draft {id:?}"),
            });
        }
        Ok(())
    }

    async fn find_by_idempotency_key(
        &self,
        key: &str,
    ) -> Result<Option<OnboardingDraft>, PortFailure> {
        Ok(self
            .drafts
            .lock()
            .unwrap()
            .iter()
            .find(|draft| draft.idempotency_key.as_deref() == Some(key))
            .cloned())
    }
}

/// The machine store, planted and observed through the same narrow surface
/// the onboarding use case touches.
#[derive(Debug, Default)]
struct FakeMachines {
    machines: Mutex<Vec<Machine>>,
    confirmed: Mutex<Vec<(String, String)>>,
    capabilities: Mutex<Vec<(String, Vec<CapabilityFact>)>>,
    snapshots: Mutex<Vec<(String, String, String, i64)>>,
}

impl FakeMachines {
    fn plant(self, machine: Machine) -> Self {
        self.machines.lock().unwrap().push(machine);
        self
    }

    fn machine_count(&self) -> usize {
        self.machines.lock().unwrap().len()
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
        let mut machines = self.machines.lock().unwrap();
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
        machines.push(machine.clone());
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

    async fn update(
        &self,
        _id: &str,
        _name: &str,
        _description: &str,
    ) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by onboarding")
    }

    async fn set_endpoints(
        &self,
        _id: &str,
        _endpoints: &[NewEndpoint],
    ) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by onboarding")
    }

    async fn add_tag(&self, _id: &str, _tag: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by onboarding")
    }

    async fn remove_tag(&self, _id: &str, _tag: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by onboarding")
    }

    async fn add_group(&self, _id: &str, _group: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by onboarding")
    }

    async fn remove_group(&self, _id: &str, _group: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by onboarding")
    }

    async fn record_snapshot(
        &self,
        id: &str,
        source: &str,
        payload_json: &str,
        collected_at: i64,
    ) -> Result<(), PortFailure> {
        self.snapshots.lock().unwrap().push((
            id.to_owned(),
            source.to_owned(),
            payload_json.to_owned(),
            collected_at,
        ));
        Ok(())
    }

    async fn record_capabilities(
        &self,
        id: &str,
        facts: &[CapabilityFact],
    ) -> Result<(), PortFailure> {
        self.capabilities
            .lock()
            .unwrap()
            .push((id.to_owned(), facts.to_vec()));
        Ok(())
    }

    async fn delete(&self, _id: &str) -> Result<(), PortFailure> {
        unimplemented!("not exercised by onboarding")
    }

    async fn confirm_fingerprint(
        &self,
        endpoint_id: &str,
        fingerprint: &str,
        _confirmed_at: i64,
    ) -> Result<(), PortFailure> {
        self.confirmed
            .lock()
            .unwrap()
            .push((endpoint_id.to_owned(), fingerprint.to_owned()));
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

/// The audit port as a recorder.
#[derive(Debug, Default)]
struct FakeAudit {
    events: Mutex<Vec<AuditIntent>>,
}

#[async_trait]
impl fleet_application::operation::AuditPort for FakeAudit {
    async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
        self.events.lock().unwrap().push(intent.clone());
        Ok(())
    }

    async fn record_outcome(
        &self,
        _operation_id: &str,
        _outcome: fleet_application::audit::AuditOutcome,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// Permits everything but the sensitive read, so redaction can be observed
/// without denials elsewhere.
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

struct Fixture {
    drafts: Arc<FakeDrafts>,
    trust: Arc<FakeTrust>,
    machines: Arc<FakeMachines>,
    audit: Arc<FakeAudit>,
    onboarding: Onboarding,
}

fn compose(machines: FakeMachines) -> Fixture {
    let drafts = Arc::new(FakeDrafts::default());
    let trust = Arc::new(FakeTrust::default());
    let machines = Arc::new(machines);
    let audit = Arc::new(FakeAudit::default());
    let onboarding = Onboarding::new(
        drafts.clone(),
        trust.clone(),
        Arc::new(Machines::new(machines.clone(), audit.clone())),
        audit.clone(),
    );
    Fixture {
        drafts,
        trust,
        machines,
        audit,
        onboarding,
    }
}

#[tokio::test]
async fn a_fresh_draft_is_untested_and_made_no_machine() {
    let fixture = compose(FakeMachines::default());
    let draft = fixture
        .onboarding
        .create_draft(&fleet_auth_allow_all(), &principal(), new_draft())
        .await
        .unwrap();
    assert_eq!(draft.stage, DraftStage::Untested);
    assert_eq!(draft.host_key_stage, HostKeyStage::Unseen);
    assert_eq!(fixture.machines.machine_count(), 0);
}

#[tokio::test]
async fn draft_creation_rejects_option_like_ssh_users_and_hosts() {
    let fixture = compose(FakeMachines::default());
    for (user, host) in [("-oProxyCommand=bad", "host-one"), ("deploy", "-Fbad")] {
        let mut draft = new_draft();
        draft.endpoint.user = user.to_owned();
        draft.endpoint.host = host.to_owned();
        assert!(matches!(
            fixture
                .onboarding
                .create_draft(&AllowAll, &principal(), draft)
                .await,
            Err(OnboardingUseCaseError::Invalid { .. })
        ));
    }
    assert!(fixture.drafts.drafts.lock().unwrap().is_empty());
}

/// The trusted-LAN policy: the same allow-all the controller serves with.
fn fleet_auth_allow_all() -> impl Authorizer {
    AllowAll
}

#[derive(Debug, Default)]
struct AllowAll;

impl Authorizer for AllowAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

#[tokio::test]
async fn confirming_requires_the_observed_fingerprint_and_pins_it() {
    let fixture = compose(FakeMachines::default());
    let draft = fixture
        .onboarding
        .create_draft(&AllowAll, &principal(), new_draft())
        .await
        .unwrap();

    // Confirming without a test is refused.
    let refused = fixture
        .onboarding
        .confirm_host_key(&AllowAll, &principal(), &draft.id, FINGERPRINT)
        .await
        .unwrap_err();
    assert!(matches!(refused, OnboardingUseCaseError::Conflict { .. }));

    // The executor's role: stage the observation.
    fixture.drafts.mutate(&draft.id, |draft| {
        draft.host_key = Some(observed_host_key(FINGERPRINT));
        draft.host_key_stage = HostKeyStage::Observed;
    });

    // A mismatched fingerprint is refused and pins nothing.
    let mismatch = fixture
        .onboarding
        .confirm_host_key(&AllowAll, &principal(), &draft.id, OTHER_FINGERPRINT)
        .await
        .unwrap_err();
    assert!(matches!(mismatch, OnboardingUseCaseError::Invalid { .. }));
    assert_eq!(fixture.trust.pin_count(), 0);

    let confirmed = fixture
        .onboarding
        .confirm_host_key(&AllowAll, &principal(), &draft.id, FINGERPRINT)
        .await
        .unwrap();
    assert_eq!(confirmed.stage, DraftStage::Ready);
    assert_eq!(fixture.trust.pin_count(), 1);
    assert_eq!(
        fixture.trust.pins.lock().unwrap()[0].1,
        observed_host_key(FINGERPRINT).raw_line
    );
}

#[tokio::test]
async fn a_changed_key_blocks_add_until_the_new_fingerprint_is_reconfirmed() {
    let fixture = compose(FakeMachines::default());
    let draft = fixture
        .onboarding
        .create_draft(&AllowAll, &principal(), new_draft())
        .await
        .unwrap();
    fixture.drafts.mutate(&draft.id, |draft| {
        draft.host_key = Some(observed_host_key(FINGERPRINT));
        draft.host_key_stage = HostKeyStage::Observed;
    });
    fixture
        .onboarding
        .confirm_host_key(&AllowAll, &principal(), &draft.id, FINGERPRINT)
        .await
        .unwrap();
    let pins_after_confirm = fixture.trust.pin_count();

    // The hostile case, played by the executor: the host now presents a
    // different key. The confirmed fingerprint is kept as evidence.
    fixture.drafts.mutate(&draft.id, |draft| {
        draft.host_key = Some(observed_host_key(OTHER_FINGERPRINT));
        draft.host_key_stage = HostKeyStage::Changed;
    });
    let blocked = fixture
        .onboarding
        .add(&AllowAll, &principal(), &draft.id, NOW)
        .await
        .unwrap_err();
    assert!(matches!(blocked, OnboardingUseCaseError::Conflict { .. }));

    // Re-confirming the new fingerprint clears the stale pins first.
    let reconfirmed = fixture
        .onboarding
        .confirm_host_key(&AllowAll, &principal(), &draft.id, OTHER_FINGERPRINT)
        .await
        .unwrap();
    assert_eq!(reconfirmed.stage, DraftStage::Ready);
    assert_eq!(fixture.trust.unpin_count(), 1);
    assert_eq!(fixture.trust.pin_count(), pins_after_confirm + 1);

    // And the add proceeds on the new trust.
    let added = fixture
        .onboarding
        .add(&AllowAll, &principal(), &draft.id, NOW)
        .await
        .unwrap();
    assert_eq!(added.machine.name, "target");
}

#[tokio::test]
async fn add_registers_the_machine_and_ingests_the_reviewed_facts() {
    let fixture = compose(FakeMachines::default());
    let mut draft_new = new_draft();
    draft_new.tags = vec!["lab".to_owned()];
    draft_new.groups = vec!["bench".to_owned()];
    let draft = fixture
        .onboarding
        .create_draft(&AllowAll, &principal(), draft_new)
        .await
        .unwrap();
    fixture.drafts.mutate(&draft.id, |draft| {
        draft.host_key = Some(observed_host_key(FINGERPRINT));
        draft.host_key_stage = HostKeyStage::Confirmed;
        draft.confirmed_fingerprint = Some(FINGERPRINT.to_owned());
        draft.facts = vec![fact("os", "family", "linux"), fact("tool", "git", "2.47")];
        draft.discovery_source = Some("agentless/1".to_owned());
        draft.discovered_at = Some(NOW - 1_000);
    });

    let added = fixture
        .onboarding
        .add(&AllowAll, &principal(), &draft.id, NOW)
        .await
        .unwrap();
    assert!(added.duplicates.is_empty());
    assert_eq!(added.machine.name, "target");
    assert_eq!(added.machine.tags, vec!["lab".to_owned()]);
    assert_eq!(added.machine.groups, vec!["bench".to_owned()]);
    assert_eq!(added.machine.endpoints[0].reference, "deploy@host-one:22");
    assert_eq!(
        added.machine.machine_status,
        fleet_application::machine::MachineStatus::Agentless
    );

    // The draft's fingerprint became the endpoint's verified one.
    let confirmed = fixture.machines.confirmed.lock().unwrap();
    assert_eq!(
        confirmed[0],
        (
            added.machine.endpoints[0].id.clone(),
            FINGERPRINT.to_owned()
        )
    );
    // The facts and the snapshot carry the discovery's provenance.
    let capabilities = fixture.machines.capabilities.lock().unwrap();
    assert_eq!(capabilities[0].1.len(), 2);
    let snapshots = fixture.machines.snapshots.lock().unwrap();
    assert_eq!(snapshots[0].1, "agentless/1");
    assert_eq!(snapshots[0].3, NOW - 1_000);
    // The draft is gone: the defined cleanup.
    assert!(fixture.drafts.get_raw(&draft.id).is_none());
}

#[tokio::test]
async fn partial_or_missing_facts_do_not_block_a_basic_add() {
    let fixture = compose(FakeMachines::default());
    for facts in [
        Vec::new(),
        vec![fact("os", "family", "linux"), {
            let mut unavailable = fact("tool", "docker", "docker");
            unavailable.status = CapabilityStatus::Unavailable;
            unavailable
        }],
    ] {
        let draft = fixture
            .onboarding
            .create_draft(&AllowAll, &principal(), new_draft())
            .await
            .unwrap();
        fixture.drafts.mutate(&draft.id, |draft| {
            draft.host_key = Some(observed_host_key(FINGERPRINT));
            draft.host_key_stage = HostKeyStage::Confirmed;
            draft.confirmed_fingerprint = Some(FINGERPRINT.to_owned());
            draft.facts = facts.clone();
        });
        let added = fixture
            .onboarding
            .add(&AllowAll, &principal(), &draft.id, NOW)
            .await
            .unwrap();
        assert_eq!(added.machine.name, "target");
        assert!(fixture.drafts.get_raw(&draft.id).is_none());
    }
    assert_eq!(fixture.machines.machine_count(), 2);
}

#[tokio::test]
async fn duplicates_are_warned_but_the_add_proceeds() {
    let fixture = compose(
        FakeMachines::default()
            .plant(machine_record("existing", "root@host-one:22"))
            .plant(machine_record("elsewhere", "root@host-two:22")),
    );
    let draft = fixture
        .onboarding
        .create_draft(&AllowAll, &principal(), new_draft())
        .await
        .unwrap();
    let view = fixture
        .onboarding
        .get_draft(&AllowAll, &principal(), &draft.id, NOW)
        .await
        .unwrap();
    assert_eq!(view.duplicates.len(), 1);
    assert_eq!(view.duplicates[0].machine_id, "existing");

    fixture.drafts.mutate(&draft.id, |draft| {
        draft.host_key = Some(observed_host_key(FINGERPRINT));
        draft.host_key_stage = HostKeyStage::Confirmed;
        draft.confirmed_fingerprint = Some(FINGERPRINT.to_owned());
    });
    let added = fixture
        .onboarding
        .add(&AllowAll, &principal(), &draft.id, NOW)
        .await
        .unwrap();
    assert_eq!(added.duplicates.len(), 1);
    assert_eq!(added.duplicates[0].machine_id, "existing");
    assert_eq!(fixture.machines.machine_count(), 3, "warned, not merged");
}

#[tokio::test]
async fn cancel_deletes_the_draft_and_unpins_only_unregistered_hosts() {
    // Unpinning is host-scoped (the provider removes every pin for a host
    // across ports), so the guard is host-scoped too: a draft on a port
    // nobody registers still must not strip another machine's pins.
    let fixture = compose(
        FakeMachines::default()
            .plant(machine_record("registered", "deploy@host-one:22"))
            .plant(machine_record(
                "registered-other-port",
                "deploy@host-one:2222",
            )),
    );

    // This draft's host is already registered by other machines: its pins
    // must survive the cancel, whatever the port.
    let shared = fixture
        .onboarding
        .create_draft(&AllowAll, &principal(), new_draft())
        .await
        .unwrap();
    fixture
        .onboarding
        .cancel_draft(&AllowAll, &principal(), &shared.id, NOW)
        .await
        .unwrap();
    assert_eq!(fixture.trust.unpin_count(), 0);
    assert!(fixture.drafts.get_raw(&shared.id).is_none());

    // This draft's host is unknown: the pin goes with it.
    let mut lone = new_draft();
    lone.endpoint.host = "host-three".to_owned();
    let lone = fixture
        .onboarding
        .create_draft(&AllowAll, &principal(), lone)
        .await
        .unwrap();
    fixture
        .onboarding
        .cancel_draft(&AllowAll, &principal(), &lone.id, NOW)
        .await
        .unwrap();
    assert_eq!(fixture.trust.unpin_count(), 1);
    assert_eq!(fixture.trust.unpins.lock().unwrap()[0], "host-three");
}

#[tokio::test]
async fn denied_callers_are_refused_without_touching_anything() {
    let fixture = compose(FakeMachines::default());
    let deny = DenyAll;
    let refused_create = fixture
        .onboarding
        .create_draft(&deny, &principal(), new_draft())
        .await
        .unwrap_err();
    assert!(matches!(refused_create, OnboardingUseCaseError::Denied(_)));
    assert!(fixture.drafts.get_raw("draft-1").is_none());
    assert!(fixture.trust.pins.lock().unwrap().is_empty());
    assert!(fixture.audit.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_sensitive_question_redacts_only_the_userinfo() {
    let fixture = compose(FakeMachines::default());
    let draft = fixture
        .onboarding
        .create_draft(&SensitiveDenied, &principal(), new_draft())
        .await
        .unwrap();
    let view = fixture
        .onboarding
        .get_draft(&SensitiveDenied, &principal(), &draft.id, NOW)
        .await
        .unwrap();
    assert_eq!(view.endpoint.user, "***");
    assert_eq!(view.endpoint.host, "host-one");
}

#[test]
fn the_profile_hint_is_a_display_string_from_the_facts() {
    let hint = profile_hint(&[
        fact("os", "family", "linux"),
        fact("os", "distribution", "debian"),
        fact("os", "distribution_version", "12"),
        fact("host", "architecture", "x86_64"),
    ]);
    assert_eq!(hint.as_deref(), Some("linux/debian-12/x86_64"));

    let partial = profile_hint(&[fact("os", "family", "linux")]);
    assert_eq!(partial.as_deref(), Some("linux"));

    assert_eq!(profile_hint(&[]), None);
    let unknown = profile_hint(&[{
        let mut unknown = fact("os", "family", "linux");
        unknown.status = CapabilityStatus::Unknown;
        unknown
    }]);
    assert_eq!(unknown, None);
}

#[test]
fn duplicate_matching_ignores_the_userinfo_and_case() {
    let endpoint = DraftEndpoint {
        user: "deploy".to_owned(),
        host: "Host-One".to_owned(),
        port: 2222,
    };
    assert!(endpoint_reference_matches("***@host-one:2222", &endpoint));
    assert!(endpoint_reference_matches("root@HOST-one:2222", &endpoint));
    assert!(!endpoint_reference_matches("deploy@host-one:22", &endpoint));
    assert!(!endpoint_reference_matches("deploy@other:2222", &endpoint));
}
