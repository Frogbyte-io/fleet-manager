use fleet_application::registry::enrich::{
    DnsObservation, DnsRecords, DnsStatus, DomainObservation, ObservationStore, RdapObservation,
    RdapStatus,
};
use fleet_storage_sqlite::{ObservationRepository, Store};

fn observation(at: i64, registrar: &str) -> DomainObservation {
    DomainObservation {
        observed_at: at,
        rdap: RdapObservation {
            status: RdapStatus::Ok,
            server: Some("https://rdap.example/".to_owned()),
            registrar: Some(registrar.to_owned()),
            expires: Some("2027-08-13".to_owned()),
            statuses: vec!["ok".to_owned()],
            nameservers: vec!["ns1.example.net".to_owned()],
            detail: None,
        },
        dns: DnsObservation {
            status: DnsStatus::Ok,
            apex: DnsRecords::default(),
            www: DnsRecords::default(),
            detail: None,
        },
    }
}

async fn repository() -> (tempfile::TempDir, Store, ObservationRepository) {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(&directory.path().join("controller.sqlite"))
        .await
        .unwrap();
    let repository = ObservationRepository::new(store.pool().clone());
    (directory, store, repository)
}

#[tokio::test]
async fn an_observation_round_trips_and_is_replaced_by_the_next_one() {
    let (_directory, _store, repository) = repository().await;
    assert_eq!(repository.get("Example.com").await.unwrap(), None);
    repository
        .save("Example.com", &observation(1, "Porkbun"))
        .await
        .unwrap();
    // The key is case-insensitive, like entry keys (FM-1010).
    let stored = repository.get("example.COM").await.unwrap().unwrap();
    assert_eq!(stored, observation(1, "Porkbun"));
    repository
        .save("example.com", &observation(2, "Namecheap"))
        .await
        .unwrap();
    let all = repository.list().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, "example.com");
    assert_eq!(all[0].1.observed_at, 2);
}

#[tokio::test]
async fn retain_forgets_observations_of_removed_entries() {
    let (_directory, _store, repository) = repository().await;
    for key in ["a.com", "b.com", "c.com"] {
        repository
            .save(key, &observation(1, "Porkbun"))
            .await
            .unwrap();
    }
    repository
        .retain(&["A.com".to_owned(), "c.com".to_owned()])
        .await
        .unwrap();
    let keys: Vec<String> = repository
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    assert_eq!(keys, ["a.com", "c.com"]);
    repository.retain(&[]).await.unwrap();
    assert!(repository.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn an_unreadable_row_is_reported_not_guessed() {
    let (_directory, store, repository) = repository().await;
    sqlx::query(
        "INSERT INTO registry_observations \
         (entry_type, entry_key_norm, entry_key, observed_at, observation_json) \
         VALUES ('domain', 'x.com', 'x.com', 1, '{\"nope\":1}')",
    )
    .execute(store.pool())
    .await
    .unwrap();
    assert!(repository.get("x.com").await.is_err());
}
