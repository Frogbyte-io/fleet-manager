//! #493 (ADR 0017): endpoint default auth and collected files (migration
//! 0060). Kinds and references only; a default goes away with its endpoint,
//! and a blob shared by a Lab artifact and a machine file is referenced from
//! both tables.

use fleet_application::lab_artifacts::{LabArtifactPort as _, StoredBlob};
use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::machine_access::{
    EndpointAuth, EndpointAuthPort as _, MachineFilePort as _, NewMachineFile,
};
use fleet_core::EndpointKind;
use fleet_storage_sqlite::{
    EndpointAuthRepository, MachineFileRepository, MachineRepository, Store,
};

async fn setup() -> (
    tempfile::TempDir,
    Store,
    MachineRepository,
    fleet_application::machine::Machine,
) {
    let dir = tempfile::tempdir().expect("a temp directory");
    let store = Store::open(&dir.path().join("fleet.db"))
        .await
        .expect("the store must open");
    let machines = MachineRepository::new(store.pool().clone());
    let machine = machines
        .register(&RegisterMachine {
            name: "box".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: "agent@192.0.2.1:22".to_owned(),
            }],
            tags: vec![],
            groups: vec![],
        })
        .await
        .expect("the machine registers");
    (dir, store, machines, machine)
}

fn blob(sha: &str) -> StoredBlob {
    StoredBlob {
        location: format!("sha256/{}/{sha}", &sha[..2]),
        size_bytes: 4,
        sha256: sha.to_owned(),
    }
}

#[tokio::test]
async fn a_default_auth_round_trips_replaces_clears_and_goes_with_its_endpoint() {
    let (_dir, store, machines, machine) = setup().await;
    let endpoint = machine.endpoints[0].id.clone();
    let auths = EndpointAuthRepository::new(store.pool().clone());
    assert_eq!(auths.get(&endpoint).await.unwrap(), None);

    for auth in [
        EndpointAuth::Agent,
        EndpointAuth::IdentityFile {
            path: "/home/ops/.ssh/id".to_owned(),
        },
        EndpointAuth::Secret {
            credential: "01890f3e-9b4a-7cc2-98c3-d24e8f58f2a1".to_owned(),
        },
    ] {
        auths.set(&endpoint, Some(&auth)).await.unwrap();
        assert_eq!(auths.get(&endpoint).await.unwrap(), Some(auth));
    }
    auths.set(&endpoint, None).await.unwrap();
    assert_eq!(auths.get(&endpoint).await.unwrap(), None);

    // An endpoint that does not exist cannot hold a default.
    assert!(
        auths
            .set("no-such-endpoint", Some(&EndpointAuth::Agent))
            .await
            .is_err()
    );

    // Replacing the machine's endpoints mints new ones; the default of the
    // old endpoint is gone with it.
    auths
        .set(
            &endpoint,
            Some(&EndpointAuth::Secret {
                credential: "abc".to_owned(),
            }),
        )
        .await
        .unwrap();
    machines
        .set_endpoints(
            &machine.id,
            &[NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: "agent@192.0.2.2:22".to_owned(),
            }],
        )
        .await
        .unwrap();
    assert_eq!(auths.get(&endpoint).await.unwrap(), None);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM machine_endpoint_auth")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn the_table_refuses_a_credential_less_secret_and_an_unknown_kind() {
    let (_dir, store, _machines, machine) = setup().await;
    let endpoint = machine.endpoints[0].id.clone();
    for (kind, reference) in [
        ("secret", None),
        ("agent", Some("x")),
        ("password", Some("x")),
    ] {
        let refused = sqlx::query(
            "INSERT INTO machine_endpoint_auth (endpoint_id, kind, reference, updated_at) VALUES (?1, ?2, ?3, 0)",
        )
        .bind(&endpoint)
        .bind(kind)
        .bind(reference)
        .execute(store.pool())
        .await;
        assert!(refused.is_err(), "{kind} {reference:?}");
    }
}

#[tokio::test]
async fn collected_files_list_expire_and_count_references_across_both_tables() {
    let (_dir, store, _machines, machine) = setup().await;
    let files = MachineFileRepository::new(store.pool().clone());
    let shared = "ab".repeat(32);
    let other = "cd".repeat(32);
    let insert = |name: &str, sha: &str, at: i64, retain: i64| NewMachineFile {
        machine_id: machine.id.clone(),
        owner: "tester".to_owned(),
        name: name.to_owned(),
        blob: blob(sha),
        operation_id: Some("op-1".to_owned()),
        created_at: at,
        retain_until: retain,
    };
    let first = files.insert(&insert("/a", &shared, 1, 100)).await.unwrap();
    let second = files.insert(&insert("/b", &shared, 2, 300)).await.unwrap();
    let third = files.insert(&insert("/c", &other, 3, 300)).await.unwrap();

    assert_eq!(
        files.get(&first.id).await.unwrap().map(|file| file.name),
        Some("/a".to_owned())
    );
    assert_eq!(files.get("missing").await.unwrap(), None);
    let listed = files.list(&machine.id, 10).await.unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|file| file.name.as_str())
            .collect::<Vec<_>>(),
        ["/c", "/b", "/a"],
        "newest first"
    );
    assert!(files.list("another-machine", 10).await.unwrap().is_empty());
    assert_eq!(files.list(&machine.id, 2).await.unwrap().len(), 2);

    // Two records share one blob; both count.
    assert_eq!(
        files
            .location_references(&blob(&shared).location)
            .await
            .unwrap(),
        2
    );
    let expired = files.expired(100, 10).await.unwrap();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].id, first.id);
    assert!(files.delete(&first.id).await.unwrap());
    assert!(!files.delete(&first.id).await.unwrap());
    assert_eq!(
        files
            .location_references(&blob(&shared).location)
            .await
            .unwrap(),
        1,
        "the other record still needs the blob"
    );
    let _ = (second, third);
}

#[tokio::test]
async fn a_lab_artifact_and_a_machine_file_both_hold_a_blob() {
    let (_dir, store, _machines, machine) = setup().await;
    let sha = "ef".repeat(32);
    let location = blob(&sha).location;
    // A Lab artifact row needs a lease; the reference check only reads the
    // location column, so seed the minimum the foreign key allows.
    let labs = fleet_storage_sqlite::LabArtifactRepository::new(store.pool().clone());
    let files = MachineFileRepository::new(store.pool().clone());
    files
        .insert(&NewMachineFile {
            machine_id: machine.id.clone(),
            owner: "tester".to_owned(),
            name: "/x".to_owned(),
            blob: blob(&sha),
            operation_id: None,
            created_at: 1,
            retain_until: 10,
        })
        .await
        .unwrap();
    // The Lab repository counts the machine file too, so a Lab retention pass
    // never deletes bytes a machine file still needs.
    assert_eq!(labs.location_references(&location).await.unwrap(), 1);
    assert_eq!(files.location_references(&location).await.unwrap(), 1);
}
