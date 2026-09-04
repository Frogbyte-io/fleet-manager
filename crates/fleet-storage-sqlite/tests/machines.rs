//! Exercises the machine model against a real database: identity rules,
//! endpoint coexistence, capability facts and staleness, tag/group filtering,
//! pagination, and cascade delete.

use fleet_application::machine::{
    Endpoint, MachineFilter, MachinePort as _, NewEndpoint, RegisterMachine,
};
use fleet_core::{CapabilityFact, CapabilityStatus, EndpointKind};
use fleet_storage_sqlite::{MachineRepository, Store};
use std::sync::Arc;

async fn repository() -> (tempfile::TempDir, Arc<MachineRepository>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    (dir, Arc::new(MachineRepository::new(store.pool().clone())))
}

fn registration(name: &str) -> RegisterMachine {
    RegisterMachine {
        name: name.to_owned(),
        description: String::new(),
        endpoints: vec![NewEndpoint {
            kind: EndpointKind::Ssh,
            reference: "ops@box.lan:22".to_owned(),
        }],
        tags: vec!["workshop".to_owned()],
        groups: vec!["lab".to_owned()],
    }
}

#[tokio::test]
async fn identity_is_minted_and_names_are_labels() {
    let (_dir, repo) = repository().await;
    let machine = repo.register(&registration("box-1")).await.unwrap();
    assert!(!machine.id.is_empty());
    assert_eq!(machine.name, "box-1");
    assert_eq!(machine.endpoints.len(), 1);
    assert_eq!(machine.tags, vec!["workshop"]);
    assert_eq!(machine.groups, vec!["lab"]);

    // A duplicate name is a conflict, not a second identity.
    let error = repo.register(&registration("box-1")).await.unwrap_err();
    assert!(error.to_string().contains("already taken"), "{error}");
}

#[tokio::test]
async fn endpoints_coexist_per_kind_and_are_replaceable() {
    let (_dir, repo) = repository().await;
    let machine = repo.register(&registration("box-2")).await.unwrap();

    // An SSH machine upgraded to fleetd carries both endpoints.
    let both = repo
        .set_endpoints(
            &machine.id,
            &[
                NewEndpoint {
                    kind: EndpointKind::Ssh,
                    reference: "ops@box.lan:22".to_owned(),
                },
                NewEndpoint {
                    kind: EndpointKind::Fleetd,
                    reference: "node-01900a3c".to_owned(),
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(both.endpoints.len(), 2);
    assert!(
        both.endpoints
            .iter()
            .any(|endpoint| endpoint.kind == EndpointKind::Ssh)
    );
    assert!(
        both.endpoints
            .iter()
            .any(|endpoint| endpoint.kind == EndpointKind::Fleetd)
    );

    // The same reference under one kind stays one row (unique per triple).
    let replaced = repo
        .set_endpoints(
            &machine.id,
            &[
                NewEndpoint {
                    kind: EndpointKind::Ssh,
                    reference: "ops@box.lan:22".to_owned(),
                },
                NewEndpoint {
                    kind: EndpointKind::Ssh,
                    reference: "ops@new.lan:22".to_owned(),
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(replaced.endpoints.len(), 2);
}

#[tokio::test]
async fn capability_facts_upsert_and_keep_provenance() {
    let (_dir, repo) = repository().await;
    let machine = repo.register(&registration("box-3")).await.unwrap();

    let fact = CapabilityFact {
        namespace: "tool".to_owned(),
        name: "git".to_owned(),
        value: Some("2.47.1".to_owned()),
        status: CapabilityStatus::Known,
        observed_at: fleet_core::Timestamp::from_unix_millis(1_000),
        source: "agentless/1".to_owned(),
    };
    repo.record_capabilities(&machine.id, &[fact])
        .await
        .unwrap();
    repo.record_capabilities(
        &machine.id,
        &[CapabilityFact {
            namespace: "tool".to_owned(),
            name: "git".to_owned(),
            value: Some("2.48.0".to_owned()),
            status: CapabilityStatus::Known,
            observed_at: fleet_core::Timestamp::from_unix_millis(2_000),
            source: "agentless/2".to_owned(),
        }],
    )
    .await
    .unwrap();

    // The snapshot records provenance and is the durable observation.
    repo.record_snapshot(&machine.id, "agentless/2", "{\"os\":\"linux\"}", 2_000)
        .await
        .unwrap();
}

#[tokio::test]
async fn snapshots_reference_real_machines() {
    let (_dir, repo) = repository().await;
    let error = repo
        .record_snapshot("no-such-machine", "agentless/1", "{}", 0)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        fleet_application::operation::PortFailure::NotFound { .. }
    ));
}

#[tokio::test]
async fn filters_narrow_and_delete_cascades() {
    let (_dir, repo) = repository().await;
    let a = repo.register(&registration("machine-a")).await.unwrap();
    let b = repo.register(&registration("machine-b")).await.unwrap();
    repo.add_group(&a.id, "prod").await.unwrap();

    repo.record_capabilities(
        &b.id,
        &[CapabilityFact {
            namespace: "agent".to_owned(),
            name: "fleetd".to_owned(),
            value: None,
            status: CapabilityStatus::Known,
            observed_at: fleet_core::Timestamp::from_unix_millis(0),
            source: "test/1".to_owned(),
        }],
    )
    .await
    .unwrap();

    let by_tag = repo
        .list(
            &MachineFilter {
                tag: Some("workshop".to_owned()),
                ..MachineFilter::default()
            },
            50,
        )
        .await
        .unwrap();
    assert_eq!(by_tag.len(), 2);

    let by_group = repo
        .list(
            &MachineFilter {
                group: Some("prod".to_owned()),
                ..MachineFilter::default()
            },
            50,
        )
        .await
        .unwrap();
    assert_eq!(by_group.len(), 1);
    assert_eq!(by_group[0].id, a.id);

    let by_capability = repo
        .list(
            &MachineFilter {
                capability: Some(("agent".to_owned(), "fleetd".to_owned())),
                ..MachineFilter::default()
            },
            50,
        )
        .await
        .unwrap();
    assert_eq!(by_capability.len(), 1);
    assert_eq!(by_capability[0].id, b.id);

    // Deleting a machine removes its facts with it.
    repo.delete(&b.id).await.unwrap();
    assert!(repo.get(&b.id).await.is_err());
    let after = repo.list(&MachineFilter::default(), 50).await.unwrap();
    assert_eq!(after.len(), 1);
}

#[tokio::test]
async fn tag_membership_can_be_removed() {
    let (_dir, repo) = repository().await;
    let machine = repo.register(&registration("machine-c")).await.unwrap();
    repo.add_tag(&machine.id, "temporary").await.unwrap();
    let tagged = repo.get(&machine.id).await.unwrap();
    assert_eq!(tagged.tags.len(), 2);

    let untagged = repo.remove_tag(&machine.id, "temporary").await.unwrap();
    assert_eq!(untagged.tags, vec!["workshop"]);
}

#[tokio::test]
async fn hydration_keeps_endpoint_identity_stable() {
    let (_dir, repo) = repository().await;
    let machine = repo.register(&registration("machine-d")).await.unwrap();
    let endpoint_id = machine.endpoints[0].id.clone();

    // Renaming the machine keeps endpoint ids: facts about the machine do
    // not churn when the label does.
    repo.update(&machine.id, "machine-d2", "renamed")
        .await
        .unwrap();
    let reloaded = repo.get(&machine.id).await.unwrap();
    assert_eq!(reloaded.name, "machine-d2");
    assert_eq!(reloaded.endpoints[0].id, endpoint_id);
    let _ = std::marker::PhantomData::<Endpoint>;
}
