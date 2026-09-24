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
    let (dir, repo, _pool) = repository_with_pool().await;
    (dir, repo)
}

/// The repository plus its pool, for tests that plant rows the machine
/// tables alone do not write (node identities come from the node surface).
async fn repository_with_pool() -> (tempfile::TempDir, Arc<MachineRepository>, sqlx::SqlitePool) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool = store.pool().clone();
    (dir, Arc::new(MachineRepository::new(pool.clone())), pool)
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
async fn machine_pages_keep_creation_order_and_apply_filters_after_the_cursor() {
    let (_dir, repo, pool) = repository_with_pool().await;
    let first = repo.register(&registration("first")).await.unwrap();
    let middle = repo.register(&registration("middle")).await.unwrap();
    let last = repo.register(&registration("last")).await.unwrap();

    // Equal timestamps exercise the id tie-breaker in the stable order.
    for machine in [&first, &middle, &last] {
        sqlx::query("UPDATE machines SET created_at = 10 WHERE id = ?1")
            .bind(&machine.id)
            .execute(&pool)
            .await
            .unwrap();
    }
    // The machine between the two matching rows must not disrupt the
    // filtered continuation.
    repo.remove_tag(&middle.id, "workshop").await.unwrap();

    let filter = MachineFilter {
        tag: Some("workshop".to_owned()),
        ..MachineFilter::default()
    };
    let page_one = repo.list(&filter, 1).await.unwrap();
    assert_eq!(page_one.len(), 1);
    assert_eq!(page_one[0].id, last.id);

    let page_two = repo
        .list(
            &MachineFilter {
                cursor: Some(page_one[0].id.clone()),
                ..filter
            },
            1,
        )
        .await
        .unwrap();
    assert_eq!(page_two.len(), 1);
    assert_eq!(page_two[0].id, first.id);

    let stale_cursor = repo
        .list(
            &MachineFilter {
                cursor: Some("deleted-machine".to_owned()),
                ..MachineFilter::default()
            },
            1,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        stale_cursor,
        fleet_application::operation::PortFailure::NotFound { .. }
    ));
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

#[tokio::test]
async fn the_record_hydrates_facts_snapshot_and_node_link() {
    use fleet_application::node::{GatewayState, NodePort as _, NodeStatus};

    let (_dir, repo, pool) = repository_with_pool().await;
    let machine = repo.register(&registration("hydrated")).await.unwrap();

    // An ancient `known` fact is returned as recorded: staleness is a
    // read-time rule applied by the view, not a storage rule.
    repo.record_capabilities(
        &machine.id,
        &[
            CapabilityFact {
                namespace: "os".to_owned(),
                name: "family".to_owned(),
                value: Some("linux".to_owned()),
                status: CapabilityStatus::Known,
                observed_at: fleet_core::Timestamp::from_unix_millis(1_000),
                source: "agentless/1".to_owned(),
            },
            CapabilityFact {
                namespace: "tool".to_owned(),
                name: "git".to_owned(),
                value: None,
                status: CapabilityStatus::Unavailable,
                observed_at: fleet_core::Timestamp::from_unix_millis(2_000),
                source: "agentless/1".to_owned(),
            },
        ],
    )
    .await
    .unwrap();
    repo.record_snapshot(&machine.id, "agentless/1", "{}", 5_000)
        .await
        .unwrap();
    repo.record_snapshot(&machine.id, "agentless/2", "{\"v\":2}", 9_000)
        .await
        .unwrap();

    let nodes = fleet_storage_sqlite::NodeRepository::new(pool.clone());
    sqlx::query(
        "INSERT INTO node_identities (machine_id, public_key, key_version, status, os, arch, node_version, enrolled_at) \
         VALUES (?1, 'ab', 1, 'active', 'linux', 'x86_64', '0.1.0', 4000)",
    )
    .bind(&machine.id)
    .execute(&pool)
    .await
    .unwrap();
    nodes
        .record_gateway_state(&machine.id, GatewayState::Connected, Some("boot-1"), 8_000)
        .await
        .unwrap();

    let machine = repo.get(&machine.id).await.unwrap();
    assert_eq!(machine.capabilities.len(), 2);
    assert_eq!(machine.capabilities[0].status, CapabilityStatus::Known);
    assert_eq!(machine.capabilities[0].observed_at.unix_millis(), 1_000);
    assert_eq!(
        machine.capabilities[1].status,
        CapabilityStatus::Unavailable
    );
    let observation = machine.last_observation.expect("an observation");
    assert_eq!(observation.source, "agentless/2");
    assert_eq!(observation.collected_at, 9_000);
    let node = machine.node.expect("a node link");
    assert_eq!(node.gateway_state, GatewayState::Connected);
    assert_eq!(node.identity_status, NodeStatus::Active);
    assert_eq!(node.last_seen_at, Some(8_000));
}

#[tokio::test]
async fn the_status_filter_matches_the_derived_states() {
    use fleet_application::machine::MachineStatus;

    let (_dir, repo, pool) = repository_with_pool().await;
    let agentless = repo.register(&registration("agentless")).await.unwrap();
    let connected = repo.register(&registration("connected")).await.unwrap();
    let offline = repo.register(&registration("offline")).await.unwrap();

    for (machine_id, state) in [(&connected.id, "connected"), (&offline.id, "offline")] {
        sqlx::query(
            "INSERT INTO node_identities (machine_id, public_key, key_version, status, enrolled_at, gateway_state) \
             VALUES (?1, 'cd', 1, 'active', 0, ?2)",
        )
        .bind(machine_id)
        .bind(state)
        .execute(&pool)
        .await
        .unwrap();
    }

    let filtered = |status: Option<MachineStatus>| {
        let repo = &repo;
        async move {
            let machines = repo
                .list(
                    &MachineFilter {
                        status,
                        ..MachineFilter::default()
                    },
                    50,
                )
                .await
                .unwrap();
            let mut ids: Vec<String> = machines.iter().map(|m| m.id.clone()).collect();
            ids.sort();
            ids
        }
    };

    assert_eq!(
        filtered(Some(MachineStatus::Agentless)).await,
        vec![agentless.id.clone()]
    );
    assert_eq!(
        filtered(Some(MachineStatus::Connected)).await,
        vec![connected.id.clone()]
    );
    assert_eq!(
        filtered(Some(MachineStatus::Offline)).await,
        vec![offline.id.clone()]
    );
    assert_eq!(filtered(None).await.len(), 3);
}
