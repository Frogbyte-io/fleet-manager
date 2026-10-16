//! FM-1001: the external account table (migration 0052).

use fleet_application::external_accounts::{
    ExternalAccountPort as _, NewExternalAccount, StoredProbe,
};
use fleet_core::{ExternalProviderKind, ProbeReport, ProbeStatus};
use fleet_storage_sqlite::{ExternalAccountRepository, Store};

fn new(kind: ExternalProviderKind, label: &str) -> NewExternalAccount {
    NewExternalAccount {
        kind,
        label: label.to_owned(),
        base_url: "https://example.test".to_owned(),
        scope_id: None,
        notes: String::new(),
    }
}

async fn repo() -> (tempfile::TempDir, ExternalAccountRepository) {
    let dir = tempfile::tempdir().expect("a temp directory");
    let store = Store::open(&dir.path().join("fleet.db"))
        .await
        .expect("the store must open");
    (dir, ExternalAccountRepository::new(store.pool().clone()))
}

#[tokio::test]
async fn labels_are_unique_per_kind_and_several_accounts_per_kind_coexist() {
    let (_dir, repo) = repo().await;
    repo.create(&new(ExternalProviderKind::Coolify, "prod"))
        .await
        .expect("first");
    repo.create(&new(ExternalProviderKind::Coolify, "staging"))
        .await
        .expect("second of the same kind");
    repo.create(&new(ExternalProviderKind::Cloudflare, "prod"))
        .await
        .expect("same label, other kind");
    let error = repo
        .create(&new(ExternalProviderKind::Coolify, "prod"))
        .await
        .expect_err("duplicate label");
    assert!(error.contains("taken"), "{error}");
    assert_eq!(repo.list().await.expect("list").len(), 3);
}

#[tokio::test]
async fn probes_round_trip_and_clear_on_request() {
    let (_dir, repo) = repo().await;
    let account = repo
        .create(&new(ExternalProviderKind::Cloudflare, "dns"))
        .await
        .expect("create");
    let probe = StoredProbe {
        checked_at: 42,
        report: ProbeReport::simple(ProbeStatus::Unauthorized, "token refused"),
    };
    let recorded = repo
        .record_probe(&account.id, Some(&probe))
        .await
        .expect("record");
    assert_eq!(recorded.last_probe, Some(probe.clone()));
    let kept = repo
        .update(
            &account.id,
            &new(ExternalProviderKind::Cloudflare, "dns2"),
            false,
        )
        .await
        .expect("update");
    assert_eq!(kept.label, "dns2");
    assert_eq!(kept.last_probe, Some(probe));
    let cleared = repo
        .update(
            &account.id,
            &new(ExternalProviderKind::Cloudflare, "dns2"),
            true,
        )
        .await
        .expect("update");
    assert_eq!(cleared.last_probe, None);
    repo.delete(&account.id).await.expect("delete");
    assert!(
        repo.get(&account.id)
            .await
            .expect_err("gone")
            .contains("not found")
    );
}
