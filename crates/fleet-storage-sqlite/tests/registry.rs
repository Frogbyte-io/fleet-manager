use fleet_application::registry::{CacheState, RegistryCachePort, RegistryProjection};
use fleet_application::source::{ActiveRevision, DesiredResourceRecord, SourcePort};
use fleet_storage_sqlite::{RegistryRepository, SourceRepository, Store};

fn revision(sha: &str) -> ActiveRevision {
    ActiveRevision {
        commit_sha: sha.to_owned(),
        content_digest: "d1".to_owned(),
    }
}

#[tokio::test]
async fn the_cache_mirrors_only_the_revision_that_is_active_when_it_is_written() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(&directory.path().join("controller.sqlite"))
        .await
        .unwrap();
    let source = SourceRepository::new(store.pool().clone());
    let cache = RegistryRepository::new(store.pool().clone());
    let active = revision("aaaa");
    source.record_valid_revision(&active, &[]).await.unwrap();
    source.activate_serialized(&active).await.unwrap();
    assert!(cache.cache_state().await.unwrap().is_none());

    let stale = CacheState {
        revision: revision("bbbb"),
        builtin_fingerprint: "f".to_owned(),
    };
    assert!(
        !cache
            .replace_cache(&stale, &RegistryProjection::default())
            .await
            .unwrap(),
        "a derivation from a revision that is no longer active is refused"
    );
    assert!(cache.cache_state().await.unwrap().is_none());

    let current = CacheState {
        revision: active,
        builtin_fingerprint: "f".to_owned(),
    };
    assert!(
        cache
            .replace_cache(&current, &RegistryProjection::default())
            .await
            .unwrap()
    );
    assert_eq!(cache.cache_state().await.unwrap(), Some(current));
}

#[tokio::test]
async fn snapshot_resources_record_and_return_their_source_path() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(&directory.path().join("controller.sqlite"))
        .await
        .unwrap();
    let source = SourceRepository::new(store.pool().clone());
    let active = revision("cccc");
    source
        .record_valid_revision(
            &active,
            &[
                DesiredResourceRecord {
                    kind: "RegistryEntry".to_owned(),
                    id: "e-1".to_owned(),
                    name: "one".to_owned(),
                    spec: serde_json::json!({}),
                    source_path: Some("fleet/registry/vendor/one.yaml".to_owned()),
                },
                DesiredResourceRecord {
                    kind: "RegistryEntry".to_owned(),
                    id: "e-2".to_owned(),
                    name: "two".to_owned(),
                    spec: serde_json::json!({}),
                    source_path: None,
                },
            ],
        )
        .await
        .unwrap();
    source.activate_serialized(&active).await.unwrap();
    let resources = source.active_resources(None, None, 10).await.unwrap();
    assert_eq!(
        resources[0].source_path.as_deref(),
        Some("fleet/registry/vendor/one.yaml")
    );
    assert_eq!(resources[1].source_path, None);
}
