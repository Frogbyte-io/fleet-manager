//! Issue #649: an onboarding draft write is a compare-and-set on the row's
//! revision (migration 0072), so a test or discover that read the draft
//! before a host-key confirmation cannot write its snapshot back over it.

use fleet_application::onboarding::{
    DraftEndpoint, HostKeyStage, NewDraft, OnboardAuth, OnboardHostKey, OnboardingPort as _,
    ShellCheck,
};
use fleet_application::operation::PortFailure;
use fleet_core::GuestOs;
use fleet_storage_sqlite::{OnboardingRepository, Store};

const OLD_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

async fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    (dir, store)
}

fn new_draft() -> NewDraft {
    NewDraft {
        endpoint: DraftEndpoint {
            user: "developer".to_owned(),
            host: "workstation.example".to_owned(),
            port: 22,
        },
        auth: OnboardAuth::Agent,
        name: None,
        description: String::new(),
        tags: Vec::new(),
        groups: Vec::new(),
        idempotency_key: None,
    }
}

#[tokio::test]
async fn a_stale_writer_is_refused_and_the_newer_confirmation_stands() {
    let (_dir, store) = store().await;
    let drafts = OnboardingRepository::new(store.pool().clone());
    let mut draft = drafts.create(&new_draft()).await.unwrap();
    assert_eq!(draft.revision, 0);
    draft.host_key = Some(OnboardHostKey {
        key_type: "ED25519".to_owned(),
        fingerprint: OLD_KEY.to_owned(),
        raw_line: "workstation.example ssh-ed25519 old".to_owned(),
    });
    draft.host_key_stage = HostKeyStage::Observed;
    let observed = drafts.update(&draft).await.unwrap();
    assert_eq!(observed.revision, 1, "every write bumps the revision");

    // Two readers of the same row: a test about to probe, and the
    // operator's confirmation.
    let mut in_flight_test = drafts.get(&observed.id).await.unwrap();
    let mut confirmation = drafts.get(&observed.id).await.unwrap();
    confirmation.host_key_stage = HostKeyStage::Confirmed;
    confirmation.confirmed_fingerprint = Some(OLD_KEY.to_owned());
    confirmation.host_key_confirmed_at = Some(5_000);
    confirmation.updated_at = 5_000;
    let confirmed = drafts.update(&confirmation).await.unwrap();
    assert_eq!(confirmed.revision, 2);

    // The test lands late, from its pre-confirmation snapshot.
    in_flight_test.shell_check = Some(ShellCheck {
        shell: "windows_powershell".to_owned(),
        guest_os: Some(GuestOs::Windows),
        refusal_reason: None,
        refusal_detail: None,
        at: 9_000,
    });
    in_flight_test.discovered_at = Some(9_000);
    in_flight_test.updated_at = 9_000;
    let refused = drafts.update(&in_flight_test).await.unwrap_err();
    assert!(matches!(refused, PortFailure::Conflict { .. }), "{refused}");

    let stored = drafts.get(&observed.id).await.unwrap();
    assert_eq!(stored.revision, 2, "nothing of the stale write applied");
    assert_eq!(stored.host_key_stage, HostKeyStage::Confirmed);
    assert_eq!(stored.confirmed_fingerprint.as_deref(), Some(OLD_KEY));
    assert_eq!(stored.host_key_confirmed_at, Some(5_000));
    assert_eq!(stored.shell_check, None);
    assert_eq!(stored.discovered_at, None);
}

#[tokio::test]
async fn a_writer_chains_from_its_own_write_and_unknown_drafts_are_not_found() {
    let (_dir, store) = store().await;
    let drafts = OnboardingRepository::new(store.pool().clone());
    let draft = drafts.create(&new_draft()).await.unwrap();

    // Discover's two writes: the shell check, then the facts, each from the
    // row the previous write answered with.
    let mut first = draft.clone();
    first.discovery_source = Some("agentless/1".to_owned());
    let mut second = drafts.update(&first).await.unwrap();
    second.discovered_at = Some(2_000);
    let stored = drafts.update(&second).await.unwrap();
    assert_eq!(stored.revision, 2);
    assert_eq!(stored.discovered_at, Some(2_000));

    // Replaying the first snapshot is refused.
    let refused = drafts.update(&first).await.unwrap_err();
    assert!(matches!(refused, PortFailure::Conflict { .. }), "{refused}");

    drafts.delete(&draft.id).await.unwrap();
    let missing = drafts.update(&stored).await.unwrap_err();
    assert!(matches!(missing, PortFailure::NotFound { .. }), "{missing}");
}
