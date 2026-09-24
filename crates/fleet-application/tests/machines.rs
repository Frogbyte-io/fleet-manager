//! The machine read model: view assembly, staleness at the read time, and
//! permission-aware endpoint redaction.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::authz::{
    AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, ReasonId,
};
use fleet_application::machine::{
    CapabilityFactView, Endpoint, Machine, MachineFilter, MachinePort, MachineStatus,
    MachineUseCaseError, Machines, NewEndpoint, NodeLink, RegisterMachine,
};
use fleet_application::node::{GatewayState, NodeStatus};
use fleet_application::operation::PortFailure;
use fleet_core::{CapabilityFact, CapabilityStatus, EndpointKind, Timestamp};

const NOW: i64 = 1_800_000_000_000;
const FRESHNESS: i64 = 24 * 60 * 60 * 1000;

fn principal() -> ActingPrincipal {
    ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }
}

fn fact(namespace: &str, name: &str, status: CapabilityStatus, observed_at: i64) -> CapabilityFact {
    CapabilityFact {
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        value: Some("value".to_owned()),
        status,
        observed_at: Timestamp::from_unix_millis(observed_at),
        source: "agentless/1".to_owned(),
    }
}

fn machine_record(id: &str, endpoints: Vec<NewEndpoint>) -> Machine {
    Machine {
        id: id.to_owned(),
        name: id.to_owned(),
        description: String::new(),
        endpoints: endpoints
            .into_iter()
            .enumerate()
            .map(|(index, new)| Endpoint {
                id: format!("endpoint-{index}"),
                kind: new.kind,
                reference: new.reference,
            })
            .collect(),
        tags: Vec::new(),
        groups: Vec::new(),
        capabilities: Vec::new(),
        last_observation: None,
        node: None,
        created_at: 0,
        updated_at: 0,
    }
}

/// The storage contract as an in-memory stand-in: records are planted
/// directly, the filter is recorded so tests can assert what the use case
/// sent, and no read-time rule is applied here — that is the use case's
/// work, and these tests prove it.
#[derive(Debug, Default)]
struct FakePort {
    machines: Mutex<Vec<Machine>>,
    last_filter: Mutex<Option<MachineFilter>>,
}

impl FakePort {
    fn with(self, machine: Machine) -> Self {
        self.machines.lock().unwrap().push(machine);
        self
    }
}

#[async_trait]
impl MachinePort for FakePort {
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
                    id: format!("endpoint-{index}"),
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

    async fn list(&self, filter: &MachineFilter, limit: u32) -> Result<Vec<Machine>, PortFailure> {
        *self.last_filter.lock().unwrap() = Some(filter.clone());
        let machines = self.machines.lock().unwrap();
        Ok(machines.iter().take(limit as usize).cloned().collect())
    }

    async fn update(
        &self,
        _id: &str,
        _name: &str,
        _description: &str,
    ) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn set_endpoints(
        &self,
        _id: &str,
        _endpoints: &[NewEndpoint],
    ) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn add_tag(&self, _id: &str, _tag: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn remove_tag(&self, _id: &str, _tag: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn add_group(&self, _id: &str, _group: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn remove_group(&self, _id: &str, _group: &str) -> Result<Machine, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn record_snapshot(
        &self,
        _id: &str,
        _source: &str,
        _payload_json: &str,
        _collected_at: i64,
    ) -> Result<(), PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn record_capabilities(
        &self,
        _id: &str,
        _facts: &[CapabilityFact],
    ) -> Result<(), PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn delete(&self, _id: &str) -> Result<(), PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn confirm_fingerprint(
        &self,
        _endpoint_id: &str,
        _fingerprint: &str,
        _confirmed_at: i64,
    ) -> Result<(), PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn verified_fingerprint(
        &self,
        _endpoint_id: &str,
    ) -> Result<Option<String>, PortFailure> {
        unimplemented!("not exercised by these tests")
    }

    async fn latest_inventory_revision(
        &self,
        _machine_id: &str,
    ) -> Result<Option<u64>, PortFailure> {
        unimplemented!("not exercised by these tests")
    }
}

#[derive(Debug)]
struct PermitAll;

impl Authorizer for PermitAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

/// Reads machines but not the credential-bearing detail of their endpoints.
#[derive(Debug)]
struct DenySensitiveOnly;

impl Authorizer for DenySensitiveOnly {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.action == Permission::MachineReadSensitive {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

#[derive(Debug)]
struct DenyAll;

impl Authorizer for DenyAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::deny(ReasonId::UnknownPrincipal)
    }
}

fn machines(port: FakePort) -> (Arc<FakePort>, Machines) {
    let port = Arc::new(port);
    let service = Machines::new(port.clone(), Arc::new(NoopAudit));
    (port, service)
}

#[derive(Debug, Default)]
struct NoopAudit;

#[async_trait]
impl fleet_application::operation::AuditPort for NoopAudit {
    async fn record_intent(
        &self,
        _intent: &fleet_application::audit::AuditIntent,
    ) -> Result<(), String> {
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

#[tokio::test]
async fn the_view_applies_the_staleness_rule_at_the_read_time() {
    let fresh_observed = NOW - 60 * 60 * 1000;
    let aged_observed = NOW - FRESHNESS - 60 * 60 * 1000;
    let mut machine = machine_record(
        "probed",
        vec![NewEndpoint {
            kind: EndpointKind::Ssh,
            reference: "ops@host:22".to_owned(),
        }],
    );
    machine.capabilities = vec![
        fact("os", "family", CapabilityStatus::Known, fresh_observed),
        fact("os", "kernel", CapabilityStatus::Known, aged_observed),
        fact("tool", "git", CapabilityStatus::Unavailable, aged_observed),
        fact("tool", "mise", CapabilityStatus::Unknown, aged_observed),
    ];

    let (_, machines) = machines(FakePort::default().with(machine));
    let view = machines
        .get(&PermitAll, &principal(), "probed", NOW)
        .await
        .expect("the machine must read");

    // Stale/unknown/unavailable each stay their own honest state; only
    // recorded `known` ages into `stale`.
    let statuses: Vec<(&str, CapabilityStatus)> = view
        .capabilities
        .iter()
        .map(|fact: &CapabilityFactView| (fact.name.as_str(), fact.status))
        .collect();
    assert_eq!(
        statuses,
        vec![
            ("family", CapabilityStatus::Known),
            ("kernel", CapabilityStatus::Stale),
            ("git", CapabilityStatus::Unavailable),
            ("mise", CapabilityStatus::Unknown),
        ]
    );
}

#[tokio::test]
async fn the_machine_status_is_derived_from_the_node_link() {
    let link = |gateway_state, identity_status| NodeLink {
        gateway_state,
        identity_status,
        last_seen_at: Some(1),
    };
    let cases: [(Option<NodeLink>, MachineStatus); 5] = [
        (None, MachineStatus::Agentless),
        (
            Some(link(GatewayState::Connected, NodeStatus::Active)),
            MachineStatus::Connected,
        ),
        (
            Some(link(GatewayState::Stale, NodeStatus::Active)),
            MachineStatus::Stale,
        ),
        (
            Some(link(GatewayState::Offline, NodeStatus::Active)),
            MachineStatus::Offline,
        ),
        (
            // A revoked identity cannot reconnect, whatever the last
            // persisted gateway state says.
            Some(link(GatewayState::Connected, NodeStatus::Revoked)),
            MachineStatus::Offline,
        ),
    ];
    for (node, expected) in cases {
        let mut machine = machine_record("machine", Vec::new());
        machine.node = node;
        let (_, machines) = machines(FakePort::default().with(machine));
        let view = machines
            .get(&PermitAll, &principal(), "machine", NOW)
            .await
            .expect("the machine must read");
        assert_eq!(view.machine_status, expected);
    }
}

#[tokio::test]
async fn a_denied_sensitive_question_redacts_only_the_userinfo() {
    let machine = machine_record(
        "host",
        vec![
            NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: "ops@10.0.0.5:22".to_owned(),
            },
            NewEndpoint {
                kind: EndpointKind::Fleetd,
                reference: "0199-node-id".to_owned(),
            },
        ],
    );
    let (_, machines) = machines(FakePort::default().with(machine));

    // The trusted-LAN admin sees the full references.
    let view = machines
        .get(&PermitAll, &principal(), "host", NOW)
        .await
        .expect("the machine must read");
    assert_eq!(view.endpoints[0].reference, "ops@10.0.0.5:22");
    assert_eq!(view.endpoints[1].reference, "0199-node-id");

    // A reader without the sensitive question sees the login name redacted;
    // the host is not sensitive.
    let view = machines
        .get(&DenySensitiveOnly, &principal(), "host", NOW)
        .await
        .expect("the machine must read");
    assert_eq!(view.endpoints[0].reference, "***@10.0.0.5:22");
    assert_eq!(view.endpoints[1].reference, "0199-node-id");

    // The list view carries the same rule.
    let views = machines
        .list(
            &DenySensitiveOnly,
            &principal(),
            &MachineFilter::default(),
            10,
            NOW,
        )
        .await
        .expect("the list must read");
    assert_eq!(views[0].endpoints[0].reference, "***@10.0.0.5:22");
}

#[tokio::test]
async fn a_denied_reader_is_refused_without_touching_the_port() {
    let (_, machines) = machines(FakePort::default());
    let error = machines
        .get(&DenyAll, &principal(), "anything", NOW)
        .await
        .expect_err("the read must be refused");
    assert!(matches!(error, MachineUseCaseError::Denied(_)));
    let error = machines
        .list(&DenyAll, &principal(), &MachineFilter::default(), 10, NOW)
        .await
        .expect_err("the list must be refused");
    assert!(matches!(error, MachineUseCaseError::Denied(_)));
}

#[tokio::test]
async fn the_use_case_sends_the_filter_to_the_port() {
    let (port, machines) = machines(FakePort::default());
    let filter = MachineFilter {
        tag: Some("linux".to_owned()),
        group: Some("build".to_owned()),
        capability: Some(("tool".to_owned(), "git".to_owned())),
        status: Some(MachineStatus::Connected),
        cursor: None,
    };
    machines
        .list(&PermitAll, &principal(), &filter, 10, NOW)
        .await
        .expect("the list must read");
    assert_eq!(port.last_filter.lock().unwrap().as_ref(), Some(&filter));
}
