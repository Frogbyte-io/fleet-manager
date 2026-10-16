//! FM-1042: DNS record observations (migration 0059).

use fleet_application::dns::{DnsObservation, DnsObservationPort as _, DnsRecord};
use fleet_application::external_accounts::{ExternalAccountPort as _, NewExternalAccount};
use fleet_core::ExternalProviderKind;
use fleet_storage_sqlite::{DnsObservationRepository, ExternalAccountRepository, Store};

fn record(id: &str, record_type: &str, content: &str) -> DnsRecord {
    DnsRecord {
        id: Some(id.to_owned()),
        record_type: record_type.to_owned(),
        name: "www.example.com".to_owned(),
        content: content.to_owned(),
        ttl: 300,
        proxied: false,
        priority: None,
    }
}

fn observation(account_id: &str, records: Vec<DnsRecord>, at: i64) -> DnsObservation {
    DnsObservation {
        account_id: account_id.to_owned(),
        zone_id: "zone1".to_owned(),
        zone_name: "example.com".to_owned(),
        name: "www.example.com".to_owned(),
        registry_entry: Some("domain/example.com".to_owned()),
        records,
        observed_at: at,
    }
}

async fn setup() -> (
    tempfile::TempDir,
    DnsObservationRepository,
    ExternalAccountRepository,
    String,
) {
    let dir = tempfile::tempdir().expect("a temp directory");
    let store = Store::open(&dir.path().join("fleet.db"))
        .await
        .expect("the store must open");
    let accounts = ExternalAccountRepository::new(store.pool().clone());
    let account = accounts
        .create(&NewExternalAccount {
            kind: ExternalProviderKind::Cloudflare,
            label: "dns".to_owned(),
            base_url: "https://api.cloudflare.com/client/v4".to_owned(),
            scope_id: None,
            notes: String::new(),
        })
        .await
        .expect("an account");
    (
        dir,
        DnsObservationRepository::new(store.pool().clone()),
        accounts,
        account.id,
    )
}

#[tokio::test]
async fn a_read_replaces_what_was_observed_for_the_name() {
    let (_dir, repo, _accounts, account) = setup().await;
    repo.replace(
        &observation(
            &account,
            vec![
                record("r1", "A", "203.0.113.1"),
                record("r2", "TXT", "hello"),
            ],
            10,
        ),
        None,
    )
    .await
    .expect("first read");
    // A later read without the TXT replaces the whole name.
    repo.replace(
        &observation(&account, vec![record("r1", "A", "203.0.113.2")], 20),
        None,
    )
    .await
    .expect("second read");
    let seen = repo.for_name("www.example.com").await.expect("read");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].records.len(), 1);
    assert_eq!(seen[0].records[0].content, "203.0.113.2");
    assert_eq!(seen[0].observed_at, 20);
    assert_eq!(
        seen[0].registry_entry.as_deref(),
        Some("domain/example.com")
    );
}

#[tokio::test]
async fn a_type_filtered_read_replaces_only_that_type() {
    let (_dir, repo, _accounts, account) = setup().await;
    repo.replace(
        &observation(
            &account,
            vec![
                record("r1", "A", "203.0.113.1"),
                record("r2", "TXT", "hello"),
            ],
            10,
        ),
        None,
    )
    .await
    .expect("full read");
    repo.replace(&observation(&account, Vec::new(), 30), Some("A"))
        .await
        .expect("the A records are gone");
    let seen = repo.for_name("www.example.com").await.expect("read");
    assert_eq!(seen[0].records.len(), 1);
    assert_eq!(seen[0].records[0].record_type, "TXT");
}

#[tokio::test]
async fn deleting_the_account_removes_its_observations() {
    let (_dir, repo, accounts, account) = setup().await;
    repo.replace(
        &observation(&account, vec![record("r1", "A", "203.0.113.1")], 10),
        None,
    )
    .await
    .expect("read");
    accounts.delete(&account).await.expect("delete the account");
    assert!(
        repo.for_name("www.example.com")
            .await
            .expect("read")
            .is_empty()
    );
}
