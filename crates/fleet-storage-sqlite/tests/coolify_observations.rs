//! FM-1030: the Coolify observation table (migration 0057).

use fleet_application::coolify::{
    ClassFailure, ClassObservation, CoolifyObservationPort as _, CoolifyServer, CoolifySnapshot,
    FailureKind,
};
use fleet_application::external_accounts::{ExternalAccountPort as _, NewExternalAccount};
use fleet_core::ExternalProviderKind;
use fleet_storage_sqlite::{CoolifyObservationRepository, ExternalAccountRepository, Store};

fn account(base_url: &str) -> NewExternalAccount {
    NewExternalAccount {
        kind: ExternalProviderKind::Coolify,
        label: "prod".to_owned(),
        base_url: base_url.to_owned(),
        scope_id: None,
        notes: String::new(),
    }
}

fn snapshot() -> CoolifySnapshot {
    CoolifySnapshot {
        version: Some("4.4.6".to_owned()),
        servers: ClassObservation {
            attempted_at: 20,
            observed_at: Some(10),
            failure: Some(ClassFailure {
                kind: FailureKind::Timeout,
                detail: "the request timed out".to_owned(),
            }),
            partial: Vec::new(),
            items: vec![CoolifyServer {
                uuid: "s1".to_owned(),
                name: "edge".to_owned(),
                ..CoolifyServer::default()
            }],
            truncated: false,
        },
        warnings: vec!["use a read-only token".to_owned()],
        ..CoolifySnapshot::default()
    }
}

async fn rig() -> (
    tempfile::TempDir,
    ExternalAccountRepository,
    CoolifyObservationRepository,
) {
    let dir = tempfile::tempdir().expect("a temp directory");
    let store = Store::open(&dir.path().join("fleet.db"))
        .await
        .expect("the store must open");
    (
        dir,
        ExternalAccountRepository::new(store.pool().clone()),
        CoolifyObservationRepository::new(store.pool().clone()),
    )
}

#[tokio::test]
async fn a_snapshot_round_trips_and_is_replaced_in_place() {
    let (_dir, accounts, repo) = rig().await;
    let created = accounts
        .create(&account("https://c.example.test"))
        .await
        .expect("account");

    assert!(repo.load(&created.id).await.expect("load").is_none());
    assert!(
        repo.save(&created.id, &snapshot(), 100, created.updated_at)
            .await
            .expect("save")
    );
    let (loaded, recorded_at) = repo.load(&created.id).await.expect("load").expect("row");
    assert_eq!(loaded, snapshot());
    assert_eq!(recorded_at, 100);

    let mut newer = snapshot();
    newer.version = Some("4.5.0".to_owned());
    assert!(
        repo.save(&created.id, &newer, 200, created.updated_at)
            .await
            .expect("replace")
    );
    let (loaded, recorded_at) = repo.load(&created.id).await.expect("load").expect("row");
    assert_eq!(loaded.version.as_deref(), Some("4.5.0"));
    assert_eq!(recorded_at, 200);
}

#[tokio::test]
async fn the_snapshot_goes_with_the_account_and_with_a_changed_origin() {
    let (_dir, accounts, repo) = rig().await;
    let created = accounts
        .create(&account("https://c.example.test"))
        .await
        .expect("account");
    repo.save(&created.id, &snapshot(), 100, created.updated_at)
        .await
        .expect("save");

    // An edit that keeps the subject keeps the cache.
    accounts
        .update(&created.id, &account("https://c.example.test"), false)
        .await
        .expect("update");
    assert!(repo.load(&created.id).await.expect("load").is_some());

    // A subject change drops it.
    let moved = accounts
        .update(&created.id, &account("https://other.example.test"), true)
        .await
        .expect("move");
    assert!(repo.load(&created.id).await.expect("load").is_none());

    assert!(
        repo.save(&created.id, &snapshot(), 100, moved.updated_at)
            .await
            .expect("save")
    );
    accounts.delete(&created.id).await.expect("delete");
    assert!(repo.load(&created.id).await.expect("load").is_none());
    assert!(
        !repo
            .save(&created.id, &snapshot(), 100, moved.updated_at)
            .await
            .expect("a gone account is not an error"),
        "a snapshot cannot outlive its account"
    );
}

#[tokio::test]
async fn a_run_started_before_an_account_change_cannot_store_its_result() {
    let (_dir, accounts, repo) = rig().await;
    let created = accounts
        .create(&account("https://c.example.test"))
        .await
        .expect("account");
    // The account is edited (a new origin) while a run that started from
    // `created` is still in flight.
    std::thread::sleep(std::time::Duration::from_millis(5));
    let moved = accounts
        .update(&created.id, &account("https://other.example.test"), true)
        .await
        .expect("move");
    assert_ne!(moved.updated_at, created.updated_at);
    assert!(
        !repo
            .save(&created.id, &snapshot(), 100, created.updated_at)
            .await
            .expect("save"),
        "the stale run's result must be discarded"
    );
    assert!(repo.load(&created.id).await.expect("load").is_none());
}
