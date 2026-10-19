//! The observed-state assembler (FM-406) over the real repositories: the
//! machine's tool facts, skills snapshot, and project checkouts come
//! together, and each store's gaps show up as unknowns.

use std::sync::Arc;

use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::observed::{
    DesiredState, SkillsObservationAvailability, ToolAvailability, compare,
};
use fleet_application::observed_assembly::ObservedStateAssembler;
use fleet_application::project::{NewProject, ProjectPort as _};
use fleet_application::skills::{SkillsAvailability, SkillsPort as _, SkillsSnapshot};
use fleet_core::{
    CapabilityFact, CapabilityStatus, CheckoutFact, DifferenceState, EndpointKind, Timestamp,
};
use fleet_storage_sqlite::{MachineRepository, ProjectRepository, SkillsRepository, Store};

const NOW: i64 = 5_000_000_000;

async fn setup() -> (tempfile::TempDir, Store, ObservedStateAssembler, String) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let machines = MachineRepository::new(store.pool().clone());
    let machine = machines
        .register(&RegisterMachine {
            name: "box".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: "ops@box.lan:22".to_owned(),
            }],
            tags: vec![],
            groups: vec![],
        })
        .await
        .unwrap();
    let assembler = ObservedStateAssembler::new(
        Arc::new(machines),
        Arc::new(SkillsRepository::new(store.pool().clone())),
        Arc::new(ProjectRepository::new(store.pool().clone())),
    );
    (dir, store, assembler, machine.id)
}

fn tool_fact(name: &str, value: Option<&str>, namespace: &str) -> CapabilityFact {
    CapabilityFact {
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        value: value.map(str::to_owned),
        status: CapabilityStatus::Known,
        observed_at: Timestamp::from_unix_millis(NOW - 1000),
        source: "mise/1".to_owned(),
    }
}

#[tokio::test]
async fn a_machine_with_no_observations_is_entirely_unknown() {
    let (_dir, _store, assembler, machine_id) = setup().await;
    let observed = assembler.assemble(&machine_id, NOW).await.unwrap();
    assert_eq!(observed.mise_answered, Some(false));
    assert_eq!(observed.checkouts_answered, Some(false));
    assert_eq!(
        observed.skills_availability,
        Some(SkillsObservationAvailability::Stale)
    );
    let desired = DesiredState {
        tools: vec![("node".into(), "22.1.0".into())],
        skills: vec![("fleet".into(), "codex".into())],
        ..DesiredState::default()
    };
    assert!(
        compare(&desired, &observed)
            .fields
            .iter()
            .all(|f| f.state == DifferenceState::Unknown)
    );
}

#[tokio::test]
async fn tools_skills_and_checkouts_are_read_from_their_stores() {
    let (_dir, store, assembler, machine_id) = setup().await;
    let machines = MachineRepository::new(store.pool().clone());
    machines
        .record_capabilities(
            &machine_id,
            &[
                tool_fact("node", None, "tool"),
                tool_fact("node", Some("node 22.1.0"), "tool-version"),
            ],
        )
        .await
        .unwrap();
    SkillsRepository::new(store.pool().clone())
        .record(&SkillsSnapshot {
            machine_id: machine_id.clone(),
            availability: SkillsAvailability::Available,
            cli_version: None,
            data: serde_json::json!({"skills": [{"id": "fleet", "deployedTo": ["codex"]}]}),
            update_check: "complete".to_owned(),
            observed_at: NOW - 1000,
        })
        .await
        .unwrap();
    let projects = ProjectRepository::new(store.pool().clone());
    // More projects than one checkout-bearing entry: only this machine's
    // checkouts count, and other machines' are ignored.
    let app = projects
        .create(&NewProject {
            fetch: fleet_core::RemoteFetch::default(),
            remote: "github.com/acme/app".to_owned(),
            idempotency_key: None,
            name: "app".to_owned(),
            description: String::new(),
        })
        .await
        .unwrap();
    let other = projects
        .create(&NewProject {
            fetch: fleet_core::RemoteFetch::default(),
            remote: "github.com/acme/other".to_owned(),
            idempotency_key: None,
            name: "other".to_owned(),
            description: String::new(),
        })
        .await
        .unwrap();
    let fact = |project: &str, machine: &str, root: &str| CheckoutFact {
        project_id: project.to_owned(),
        machine_id: machine.to_owned(),
        root: root.to_owned(),
        branch: Some("main".to_owned()),
        dirty: Some(false),
        source: "agentless/1".to_owned(),
        observed_at: NOW - 1000,
    };
    projects
        .record_checkout(&fact(&app.id, &machine_id, "/srv/app"))
        .await
        .unwrap();
    projects
        .record_checkout(&fact(&other.id, "some-other-machine", "/srv/other"))
        .await
        .ok();

    let observed = assembler.assemble(&machine_id, NOW).await.unwrap();
    assert_eq!(observed.mise_answered, Some(true));
    let node = observed.tools.iter().find(|t| t.tool == "node").unwrap();
    assert_eq!(node.version.as_deref(), Some("22.1.0"));
    assert_eq!(node.availability, ToolAvailability::Present);
    assert_eq!(
        observed.skills_availability,
        Some(SkillsObservationAvailability::Available)
    );
    assert_eq!(observed.skills.len(), 1);
    assert_eq!(observed.checkouts_answered, Some(true));
    assert_eq!(observed.checkouts.len(), 1);
    assert_eq!(
        observed.checkouts[0].remote.as_deref(),
        Some("github.com/acme/app")
    );
}

#[tokio::test]
async fn an_unknown_machine_is_refused() {
    let (_dir, _store, assembler, _) = setup().await;
    let error = assembler
        .assemble("no-such-machine", NOW)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("not registered"), "{error}");
}
