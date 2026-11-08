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

/// A database migrated up to 0070, seeded, then opened by the real store
/// (which runs 0071): the existing endpoint and draft read as unknown.
#[tokio::test]
async fn rows_from_before_0071_read_unknown_after_the_real_migration() {
    let dir = tempfile::tempdir().unwrap();
    let held = dir.path().join("migrations");
    std::fs::create_dir(&held).unwrap();
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    for entry in std::fs::read_dir(&source).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        let number: u32 = name[..4].parse().unwrap();
        if number <= 70 {
            std::fs::copy(entry.path(), held.join(&name)).unwrap();
        }
    }
    let path = dir.path().join("fleet.db");
    {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&path)
                    .create_if_missing(true)
                    .foreign_keys(true),
            )
            .await
            .unwrap();
        sqlx::migrate::Migrator::new(held.as_path())
            .await
            .unwrap()
            .run(&pool)
            .await
            .unwrap();
        for statement in [
            "INSERT INTO machines (id, name, description, created_at, updated_at) \
             VALUES ('legacy', 'legacy', '', 1, 1)",
            "INSERT INTO machine_endpoints (id, machine_id, kind, reference, created_at, \
             verified_fingerprint, verified_at) VALUES ('legacy-endpoint', 'legacy', 'ssh', \
             'ops@legacy.example:22', 1, 'SHA256:legacy', 1)",
            "INSERT INTO onboarding_drafts (id, endpoint_user, endpoint_host, endpoint_port, \
             auth_type, name, created_at, updated_at) VALUES ('legacy-draft', 'ops', \
             'legacy.example', 22, 'agent', 'legacy-draft', 1, 1)",
        ] {
            sqlx::query(statement).execute(&pool).await.unwrap();
        }
        pool.close().await;
    }

    let store = Store::open(&path).await.unwrap();
    let machines = MachineRepository::new(store.pool().clone());
    let machine = machines.get("legacy").await.unwrap();
    assert_eq!(machine.endpoints[0].guest_os, None, "unknown, not linux");
    let drafts = OnboardingRepository::new(store.pool().clone());
    let draft = drafts.get("legacy-draft").await.unwrap();
    assert_eq!(draft.shell_check, None);
    assert_eq!(draft.host_key_confirmed_at, None);
}

/// A (re)confirmed host key may be another machine behind the address: the
/// recorded OS is cleared with it.
#[tokio::test]
async fn confirming_a_host_key_clears_the_recorded_os() {
    let (_dir, store) = store().await;
    let machines = MachineRepository::new(store.pool().clone());
    let machine = machines.register(&workstation()).await.unwrap();
    let endpoint = &machine.endpoints[0].id;
    machines
        .record_endpoint_os(endpoint, GuestOs::Windows)
        .await
        .unwrap();
    machines
        .confirm_fingerprint(endpoint, "SHA256:another", 2)
        .await
        .unwrap();
    let read = machines.get(&machine.id).await.unwrap();
    assert_eq!(read.endpoints[0].guest_os, None);
    // Clearing directly works too, and only SSH endpoints carry an OS.
    machines
        .record_endpoint_os(endpoint, GuestOs::Linux)
        .await
        .unwrap();
    machines.clear_endpoint_os(endpoint).await.unwrap();
    assert_eq!(
        machines.get(&machine.id).await.unwrap().endpoints[0].guest_os,
        None
    );
}

/// A detected OS is written with its audit event in one transaction, and
/// only under the fingerprint the detection ran with.
#[tokio::test]
async fn a_detected_os_is_bound_to_the_fingerprint_and_audited_atomically() {
    let (_dir, store) = store().await;
    let pool = store.pool().clone();
    let machines = MachineRepository::new(pool.clone());
    let machine = machines.register(&workstation()).await.unwrap();
    let endpoint = &machine.endpoints[0].id;
    machines
        .confirm_fingerprint(endpoint, "SHA256:current", 1)
        .await
        .unwrap();
    let event = fleet_application::audit::AuditIntent {
        actor: "operator".to_owned(),
        action: "machine.update".to_owned(),
        resource: Some(machine.id.clone()),
        decision: fleet_application::authz::Decision::allow(),
        correlation_id: None,
        operation_id: Some("operation-1".to_owned()),
        metadata: fleet_application::audit::AuditMetadata::default(),
    };
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    // A fingerprint confirmed after the detection started: nothing written.
    let stale = machines
        .record_detected_endpoint_os(endpoint, GuestOs::Linux, "SHA256:previous", &event)
        .await
        .unwrap();
    assert!(!stale);
    assert_eq!(
        machines.get(&machine.id).await.unwrap().endpoints[0].guest_os,
        None
    );
    assert_eq!(count().await, 0);
    // The current one: the OS and one resolved event.
    let recorded = machines
        .record_detected_endpoint_os(endpoint, GuestOs::Linux, "SHA256:current", &event)
        .await
        .unwrap();
    assert!(recorded);
    assert_eq!(
        machines.get(&machine.id).await.unwrap().endpoints[0].guest_os,
        Some(GuestOs::Linux)
    );
    let outcome: Option<String> =
        sqlx::query_scalar("SELECT outcome FROM audit_events WHERE operation_id = 'operation-1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        outcome.as_deref(),
        Some("succeeded"),
        "never an open intent"
    );
}

/// When the audit append fails, the endpoint OS is rolled back with it.
#[tokio::test]
async fn a_failed_audit_append_records_no_os() {
    let (_dir, store) = store().await;
    let pool = store.pool().clone();
    let machines = MachineRepository::new(pool.clone());
    let machine = machines.register(&workstation()).await.unwrap();
    let endpoint = &machine.endpoints[0].id;
    machines
        .confirm_fingerprint(endpoint, "SHA256:current", 1)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TRIGGER refuse_endpoint_os_audit BEFORE INSERT ON audit_events \
         WHEN NEW.metadata_json LIKE '%endpoint_os_recorded%' \
         BEGIN SELECT RAISE(ABORT, 'audit refused'); END",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut metadata = fleet_application::audit::AuditMetadata::default();
    metadata.insert("event", "endpoint_os_recorded").unwrap();
    let event = fleet_application::audit::AuditIntent {
        actor: "operator".to_owned(),
        action: "machine.update".to_owned(),
        resource: Some(machine.id.clone()),
        decision: fleet_application::authz::Decision::allow(),
        correlation_id: None,
        operation_id: Some("operation-1".to_owned()),
        metadata,
    };
    let failed = machines
        .record_detected_endpoint_os(endpoint, GuestOs::Windows, "SHA256:current", &event)
        .await
        .unwrap_err();
    assert!(matches!(failed, PortFailure::Backend { .. }), "{failed}");
    assert_eq!(
        machines.get(&machine.id).await.unwrap().endpoints[0].guest_os,
        None,
        "the OS rolled back with the audit row"
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE operation_id = 'operation-1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 0);
}

#[tokio::test]
async fn a_fleetd_endpoint_never_carries_an_os() {
    let (_dir, store) = store().await;
    let machines = MachineRepository::new(store.pool().clone());
    let machine = machines
        .register(&RegisterMachine {
            name: "node-1".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: EndpointKind::Fleetd,
                reference: "node-identity".to_owned(),
            }],
            tags: Vec::new(),
            groups: Vec::new(),
        })
        .await
        .unwrap();
    let refused = machines
        .record_endpoint_os(&machine.endpoints[0].id, GuestOs::Linux)
        .await
        .unwrap_err();
    assert!(matches!(refused, PortFailure::NotFound { .. }), "{refused}");
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
