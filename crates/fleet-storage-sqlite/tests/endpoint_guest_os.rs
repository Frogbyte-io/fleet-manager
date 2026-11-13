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

/// The facts an SSH inventory observed through the address may describe the
/// other machine too: confirming a host key turns them stale until the next
/// inventory (#624). Facts from other sources and other machines stay.
#[tokio::test]
async fn confirming_a_host_key_marks_the_ssh_observed_facts_stale() {
    use fleet_core::{CapabilityFact, CapabilityStatus, Timestamp};
    let fact = |name: &str, status: CapabilityStatus, source: &str| CapabilityFact {
        namespace: "tool".to_owned(),
        name: name.to_owned(),
        value: Some("1.0".to_owned()),
        status,
        observed_at: Timestamp::from_unix_millis(1_000),
        source: source.to_owned(),
    };
    let (_dir, store) = store().await;
    let machines = MachineRepository::new(store.pool().clone());
    let machine = machines.register(&workstation()).await.unwrap();
    let mut other = workstation();
    other.name = "workstation-2".to_owned();
    let other = machines.register(&other).await.unwrap();
    machines
        .record_capabilities(
            &machine.id,
            &[
                fact("git", CapabilityStatus::Known, "agentless/1"),
                fact("docker", CapabilityStatus::Unavailable, "agentless/1"),
                fact("node", CapabilityStatus::Known, "fleetd/tools/1"),
                fact("qemu-agent", CapabilityStatus::Known, "proxmox/8.3.0"),
            ],
        )
        .await
        .unwrap();
    machines
        .record_capabilities(
            &other.id,
            &[fact("git", CapabilityStatus::Known, "agentless/1")],
        )
        .await
        .unwrap();

    machines
        .confirm_fingerprint(&machine.endpoints[1].id, "SHA256:another", 2)
        .await
        .unwrap();
    let status_of = |machine: &fleet_application::machine::Machine, name: &str| {
        let fact = machine
            .capabilities
            .iter()
            .find(|fact| fact.name == name)
            .unwrap();
        (
            fact.status,
            fact.value.clone(),
            fact.observed_at.unix_millis(),
        )
    };
    let read = machines.get(&machine.id).await.unwrap();
    assert_eq!(
        status_of(&read, "git"),
        (CapabilityStatus::Stale, Some("1.0".to_owned()), 1_000),
        "what was seen, and when, stays"
    );
    assert_eq!(status_of(&read, "docker").0, CapabilityStatus::Unavailable);
    assert_eq!(status_of(&read, "node").0, CapabilityStatus::Known);
    assert_eq!(status_of(&read, "qemu-agent").0, CapabilityStatus::Known);
    let other_read = machines.get(&other.id).await.unwrap();
    assert_eq!(status_of(&other_read, "git").0, CapabilityStatus::Known);

    // The next inventory observes it again.
    machines
        .record_capabilities(
            &machine.id,
            &[fact("git", CapabilityStatus::Known, "agentless/1")],
        )
        .await
        .unwrap();
    let read = machines.get(&machine.id).await.unwrap();
    assert_eq!(status_of(&read, "git").0, CapabilityStatus::Known);

    // An unknown endpoint changes nothing.
    let missing = machines
        .confirm_fingerprint("no-such-endpoint", "SHA256:another", 3)
        .await
        .unwrap_err();
    assert!(matches!(missing, PortFailure::NotFound { .. }), "{missing}");
}

/// An inventory that verified the old key cannot write its facts back after
/// a confirmation marked them stale (#624).
#[tokio::test]
async fn facts_are_recorded_only_under_the_fingerprint_the_inventory_verified() {
    use fleet_application::machine::VerifiedWrite;
    use fleet_core::{CapabilityFact, CapabilityStatus, Timestamp};
    let git = CapabilityFact {
        namespace: "tool".to_owned(),
        name: "git".to_owned(),
        value: Some("2.0".to_owned()),
        status: CapabilityStatus::Known,
        observed_at: Timestamp::from_unix_millis(5_000),
        source: "agentless/1".to_owned(),
    };
    let (_dir, store) = store().await;
    let machines = MachineRepository::new(store.pool().clone());
    let machine = machines.register(&workstation()).await.unwrap();
    let endpoint = &machine.endpoints[0].id;
    machines
        .confirm_fingerprint(endpoint, "SHA256:current", 1)
        .await
        .unwrap();
    let stale = machines
        .record_verified_capabilities(
            &machine.id,
            endpoint,
            "SHA256:previous",
            std::slice::from_ref(&git),
        )
        .await
        .unwrap();
    assert_eq!(
        stale,
        VerifiedWrite::KeyChanged,
        "a key confirmed meanwhile wins"
    );
    assert!(
        machines
            .get(&machine.id)
            .await
            .unwrap()
            .capabilities
            .is_empty()
    );
    // Another machine's endpoint does not count either.
    let mut other = workstation();
    other.name = "workstation-2".to_owned();
    let other = machines.register(&other).await.unwrap();
    machines
        .confirm_fingerprint(&other.endpoints[0].id, "SHA256:current", 1)
        .await
        .unwrap();
    assert_eq!(
        machines
            .record_verified_capabilities(
                &machine.id,
                &other.endpoints[0].id,
                "SHA256:current",
                std::slice::from_ref(&git),
            )
            .await
            .unwrap(),
        VerifiedWrite::EndpointGone
    );
    // Nor does an endpoint that no longer exists.
    assert_eq!(
        machines
            .record_verified_capabilities(
                &machine.id,
                "no-such-endpoint",
                "SHA256:current",
                std::slice::from_ref(&git),
            )
            .await
            .unwrap(),
        VerifiedWrite::EndpointGone
    );
    let current = machines
        .record_verified_capabilities(&machine.id, endpoint, "SHA256:current", &[git])
        .await
        .unwrap();
    assert_eq!(current, VerifiedWrite::Recorded);
    let read = machines.get(&machine.id).await.unwrap();
    assert_eq!(read.capabilities.len(), 1);
    assert_eq!(read.capabilities[0].status, CapabilityStatus::Known);
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
    // #649: a detection that started before that record (it looked the OS
    // up as unknown) does not overwrite it: the recorded OS is newer.
    let late = machines
        .record_detected_endpoint_os(endpoint, GuestOs::Windows, "SHA256:current", &event)
        .await
        .unwrap();
    assert!(!late);
    assert_eq!(
        machines.get(&machine.id).await.unwrap().endpoints[0].guest_os,
        Some(GuestOs::Linux)
    );
    assert_eq!(count().await, 1, "no event for a write that did not apply");
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

/// #649: a fleetd endpoint has no host key to confirm. The confirmation is
/// not found and changes nothing — the machine's agentless facts stay known.
#[tokio::test]
async fn a_fleetd_endpoint_has_no_host_key_to_confirm() {
    use fleet_core::{CapabilityFact, CapabilityStatus, Timestamp};
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
    machines
        .record_capabilities(
            &machine.id,
            &[CapabilityFact {
                namespace: "tool".to_owned(),
                name: "git".to_owned(),
                value: Some("1.0".to_owned()),
                status: CapabilityStatus::Known,
                observed_at: Timestamp::from_unix_millis(1_000),
                source: "agentless/1".to_owned(),
            }],
        )
        .await
        .unwrap();
    let refused = machines
        .confirm_fingerprint(&machine.endpoints[0].id, "SHA256:another", 2)
        .await
        .unwrap_err();
    assert!(matches!(refused, PortFailure::NotFound { .. }), "{refused}");
    let read = machines.get(&machine.id).await.unwrap();
    assert_eq!(read.capabilities[0].status, CapabilityStatus::Known);
    assert_eq!(
        machines
            .verified_fingerprint(&machine.endpoints[0].id)
            .await
            .unwrap(),
        None
    );
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

    let mut draft = stored;
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
