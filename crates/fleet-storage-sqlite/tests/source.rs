use fleet_application::source::{ActiveRevision, DesiredResourceRecord, SourcePort};
use fleet_storage_sqlite::{SourceRepository, Store};

fn revision(sha: &str, digest: &str) -> ActiveRevision {
    ActiveRevision {
        commit_sha: sha.to_owned(),
        content_digest: digest.to_owned(),
    }
}

fn resource(kind: &str, id: &str) -> DesiredResourceRecord {
    DesiredResourceRecord {
        kind: kind.to_owned(),
        id: id.to_owned(),
        name: format!("{id}-name"),
        spec: serde_json::json!({ "note": id }),
    }
}

async fn repository(directory: &tempfile::TempDir) -> (Store, SourceRepository) {
    let store = Store::open(&directory.path().join("controller.sqlite"))
        .await
        .unwrap();
    let repository = SourceRepository::new(store.pool().clone());
    (store, repository)
}

#[tokio::test]
async fn a_recorded_revision_holds_its_resources_and_survives_a_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let (store, repository) = repository(&directory).await;
    let one = revision("aaaa", "d1");
    repository
        .record_valid_revision(
            &one,
            &[resource("Machine", "m-1"), resource("Profile", "p-1")],
        )
        .await
        .unwrap();
    assert!(repository.snapshot_held(&one).await.unwrap());
    assert!(
        !repository
            .snapshot_held(&revision("aaaa", "other"))
            .await
            .unwrap()
    );
    repository.activate_serialized(&one).await.unwrap();
    drop(store);

    // A restart resumes on the same revision with the same resources.
    let (_store, repository) = self::repository(&directory).await;
    let summary = repository.active_summary().await.unwrap().unwrap();
    assert_eq!(summary.revision, one);
    assert!(summary.snapshot_held);
    assert_eq!(summary.kind_counts["Machine"], 1);
    assert_eq!(summary.kind_counts["Profile"], 1);
    let resources = repository.active_resources(None, None, 10).await.unwrap();
    assert_eq!(
        resources.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["m-1", "p-1"]
    );
    assert_eq!(resources[0].spec["note"], "m-1");
}

#[tokio::test]
async fn resources_filter_by_kind_and_page_by_identity() {
    let directory = tempfile::tempdir().unwrap();
    let (_store, repository) = repository(&directory).await;
    let one = revision("aaaa", "d1");
    repository
        .record_valid_revision(
            &one,
            &[
                resource("Machine", "m-1"),
                resource("Machine", "m-2"),
                resource("Profile", "p-1"),
            ],
        )
        .await
        .unwrap();
    repository.activate_serialized(&one).await.unwrap();
    let machines = repository
        .active_resources(Some("Machine"), None, 10)
        .await
        .unwrap();
    assert_eq!(machines.len(), 2);
    let after = repository
        .active_resources(None, Some("m-1"), 10)
        .await
        .unwrap();
    assert_eq!(
        after.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["m-2", "p-1"]
    );
    assert_eq!(
        repository
            .active_resources(None, None, 1)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn only_the_active_revisions_resources_are_served() {
    let directory = tempfile::tempdir().unwrap();
    let (_store, repository) = repository(&directory).await;
    let (one, two) = (revision("aaaa", "d1"), revision("bbbb", "d2"));
    repository
        .record_valid_revision(&one, &[resource("Machine", "m-1")])
        .await
        .unwrap();
    repository
        .record_valid_revision(&two, &[resource("Machine", "m-2")])
        .await
        .unwrap();
    assert!(
        repository
            .active_resources(None, None, 10)
            .await
            .unwrap()
            .is_empty()
    );
    repository.activate_serialized(&two).await.unwrap();
    let served = repository.active_resources(None, None, 10).await.unwrap();
    assert_eq!(
        served.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["m-2"]
    );
}

#[tokio::test]
async fn recording_a_revision_again_keeps_the_first_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let (_store, repository) = repository(&directory).await;
    let one = revision("aaaa", "d1");
    repository
        .record_valid_revision(&one, &[resource("Machine", "m-1")])
        .await
        .unwrap();
    repository
        .record_valid_revision(&one, &[resource("Machine", "m-other")])
        .await
        .unwrap();
    repository.activate_serialized(&one).await.unwrap();
    let served = repository.active_resources(None, None, 10).await.unwrap();
    assert_eq!(
        served.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["m-1"]
    );
}

#[tokio::test]
async fn an_empty_repository_is_a_held_snapshot_and_a_revision_without_one_is_reported() {
    let directory = tempfile::tempdir().unwrap();
    let (_store, repository) = repository(&directory).await;
    let empty = revision("aaaa", "d0");
    repository.record_valid_revision(&empty, &[]).await.unwrap();
    assert!(repository.snapshot_held(&empty).await.unwrap());
    // Activated by a controller from before snapshots existed.
    let legacy = revision("cccc", "old");
    repository.activate_serialized(&legacy).await.unwrap();
    let summary = repository.active_summary().await.unwrap().unwrap();
    assert!(!summary.snapshot_held);
    assert!(summary.kind_counts.is_empty());
}

#[tokio::test]
async fn the_remote_is_stored_replaced_and_survives_a_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let (store, repository) = repository(&directory).await;
    assert!(repository.remote().await.unwrap().is_none());
    assert!(repository.credential_ref().await.unwrap().is_none());
    repository
        .set_remote("ssh://git@example.test/a.git", Some("cred-1"))
        .await
        .unwrap();
    repository
        .set_remote("ssh://git@example.test/b.git", None)
        .await
        .unwrap();
    drop(store);
    let (_store, repository) = self::repository(&directory).await;
    assert_eq!(
        repository.remote().await.unwrap().as_deref(),
        Some("ssh://git@example.test/b.git")
    );
    // Replacing the remote replaces the reference with it.
    assert!(repository.credential_ref().await.unwrap().is_none());
    repository
        .set_remote("ssh://git@example.test/b.git", Some("cred-2"))
        .await
        .unwrap();
    assert_eq!(
        repository.credential_ref().await.unwrap().as_deref(),
        Some("cred-2")
    );
}
