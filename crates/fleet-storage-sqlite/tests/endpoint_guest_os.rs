//! Issue #608 / ADR 0021 decision 4: migration 0071 records the guest OS on
//! an SSH endpoint (per endpoint, unknown by default) and the newest
//! login-shell check on an onboarding draft.

use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::onboarding::{
    DraftEndpoint, NewDraft, OnboardAuth, OnboardingPort as _, ShellCheck,
};
use fleet_application::operation::PortFailure;
use fleet_core::{EndpointKind, GuestOs};
use fleet_storage_sqlite::{MachineRepository, OnboardingRepository, Store};

async fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    (dir, store)
}

/// A workstation with two SSH endpoints: Windows OpenSSH and a WSL sshd.
fn workstation() -> RegisterMachine {
    RegisterMachine {
        name: "workstation-1".to_owned(),
        description: String::new(),
        endpoints: vec![
            NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: "developer@workstation.example:22".to_owned(),
            },
            NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: "developer@workstation.example:2222".to_owned(),
            },
        ],
        tags: Vec::new(),
        groups: Vec::new(),
    }
}

#[tokio::test]
async fn an_endpoint_is_unknown_until_its_os_is_recorded_per_endpoint() {
    let (_dir, store) = store().await;
    let machines = MachineRepository::new(store.pool().clone());
    let machine = machines.register(&workstation()).await.unwrap();
    assert!(
        machine
            .endpoints
            .iter()
            .all(|endpoint| endpoint.guest_os.is_none()),
        "a new endpoint is unknown, not linux"
    );
    let (windows, wsl) = (&machine.endpoints[0], &machine.endpoints[1]);
    machines
        .record_endpoint_os(&windows.id, GuestOs::Windows)
        .await
        .unwrap();
    machines
        .record_endpoint_os(&wsl.id, GuestOs::Linux)
        .await
        .unwrap();
    let read = machines.get(&machine.id).await.unwrap();
    let os_of = |id: &str| {
        read.endpoints
            .iter()
            .find(|endpoint| endpoint.id == id)
            .unwrap()
            .guest_os
    };
    assert_eq!(os_of(&windows.id), Some(GuestOs::Windows));
    assert_eq!(os_of(&wsl.id), Some(GuestOs::Linux));

    let missing = machines
        .record_endpoint_os("no-such-endpoint", GuestOs::Windows)
        .await
        .unwrap_err();
    assert!(matches!(missing, PortFailure::NotFound { .. }), "{missing}");
}

#[tokio::test]
async fn a_pre_migration_endpoint_row_reads_unknown_and_bad_values_are_refused() {
    let (_dir, store) = store().await;
    let pool = store.pool().clone();
    let machines = MachineRepository::new(pool.clone());
    let machine = machines.register(&workstation()).await.unwrap();
    // An insert in the pre-0071 shape names no guest_os column.
    sqlx::query(
        "INSERT INTO machine_endpoints (id, machine_id, kind, reference, created_at) \
         VALUES ('legacy-endpoint', ?1, 'ssh', 'ops@legacy.example:22', 1)",
    )
    .bind(&machine.id)
    .execute(&pool)
    .await
    .unwrap();
    let read = machines.get(&machine.id).await.unwrap();
    let legacy = read
        .endpoints
        .iter()
        .find(|endpoint| endpoint.id == "legacy-endpoint")
        .unwrap();
    assert_eq!(legacy.guest_os, None);

    for bad in ["macos", "Windows", ""] {
        let refused =
            sqlx::query("UPDATE machine_endpoints SET guest_os = ?1 WHERE id = 'legacy-endpoint'")
                .bind(bad)
                .execute(&pool)
                .await;
        assert!(refused.is_err(), "{bad:?} must fail the CHECK");
    }
}

#[tokio::test]
async fn a_draft_keeps_its_shell_check() {
    let (_dir, store) = store().await;
    let drafts = OnboardingRepository::new(store.pool().clone());
    let mut draft = drafts
        .create(&NewDraft {
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
        })
        .await
        .unwrap();
    assert_eq!(draft.shell_check, None);
    let refused = ShellCheck {
        shell: "cmd".to_owned(),
        guest_os: None,
        refusal_reason: Some("unsupported_shell".to_owned()),
        refusal_detail: Some("set the OpenSSH DefaultShell".to_owned()),
        at: 1_000,
    };
    draft.shell_check = Some(refused.clone());
    let stored = drafts.update(&draft).await.unwrap();
    assert_eq!(stored.shell_check, Some(refused));

    draft.shell_check = Some(ShellCheck {
        shell: "windows_powershell".to_owned(),
        guest_os: Some(GuestOs::Windows),
        refusal_reason: None,
        refusal_detail: None,
        at: 2_000,
    });
    let stored = drafts.update(&draft).await.unwrap();
    let check = drafts.get(&stored.id).await.unwrap().shell_check.unwrap();
    assert_eq!(check.guest_os, Some(GuestOs::Windows));
    assert_eq!(check.refusal_reason, None);
}
