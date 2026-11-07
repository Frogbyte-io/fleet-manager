//! The Skills Manager setup follow-up (#600): after a machine is set up,
//! the controller queues a pinned `skills.probe` chosen from the machine's
//! platform facts, through the authorized, audited operation path. A
//! platform without a pin is skipped with a reason; a denied or failed
//! queue answers `failed` instead of raising; and the queued probe leaves an
//! already-installed CLI alone.

use std::sync::Arc;
use std::time::Duration;

use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::machine::{MachinePort, NewEndpoint, RegisterMachine};
use fleet_application::machine_setup::{MachineSetup, MachineSetupPort, SetupFollowUp, SetupKind};
use fleet_application::onboarding::OnboardAuth;
use fleet_application::operation::{
    NewOperation, OperationPort as _, Operations, SETUP_FOLLOW_UP_IDEMPOTENCY_PREFIX,
};
use fleet_application::skills::{SkillsAvailability, SkillsPort as _, SkillsSnapshot};
use fleet_controller::skills_setup::SkillsManagerSetup;
use fleet_core::{CapabilityFact, CapabilityStatus, Timestamp};
use fleet_provider_ssh::ExecutionLimiter;
use fleet_storage_sqlite::{AuditSink, MachineRepository, OperationRepository, Store};
use sqlx::SqlitePool;

mod common;
use common::{start_sshd_with_home, whoami};

const PRINCIPAL: &str = "anonymous-lan-admin";

struct Fixture {
    _dir: tempfile::TempDir,
    pool: SqlitePool,
    operations: Arc<Operations>,
    hook: SkillsManagerSetup,
    machine_id: String,
    endpoint_id: String,
}

async fn compose(reference: &str) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool: SqlitePool = store.pool().clone();
    std::mem::forget(store);
    let machine = MachineRepository::new(pool.clone())
        .register(&RegisterMachine {
            name: "box".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: fleet_core::EndpointKind::Ssh,
                reference: reference.to_owned(),
            }],
            tags: vec![],
            groups: vec![],
        })
        .await
        .unwrap();
    let operations = Arc::new(Operations::new(
        Arc::new(OperationRepository::new(pool.clone())),
        Arc::new(AuditSink::new(pool.clone())),
    ));
    let hook = SkillsManagerSetup::new(
        Arc::new(MachineRepository::new(pool.clone())),
        operations.clone(),
    )
    .with_snapshots(Arc::new(fleet_storage_sqlite::SkillsRepository::new(
        pool.clone(),
    )));
    Fixture {
        _dir: dir,
        pool,
        operations,
        hook,
        endpoint_id: machine.endpoints[0].id.clone(),
        machine_id: machine.id,
    }
}

impl Fixture {
    async fn plant_facts(&self, facts: &[(&str, &str, &str)]) {
        let facts: Vec<(&str, &str, &str, CapabilityStatus, i64)> = facts
            .iter()
            .map(|(namespace, name, value)| {
                (
                    *namespace,
                    *name,
                    *value,
                    CapabilityStatus::Known,
                    fleet_core::SystemClock::now_unix_millis(),
                )
            })
            .collect();
        self.plant_observed(&facts).await;
    }

    async fn plant_observed(&self, facts: &[(&str, &str, &str, CapabilityStatus, i64)]) {
        let facts: Vec<CapabilityFact> = facts
            .iter()
            .map(|(namespace, name, value, status, at)| CapabilityFact {
                namespace: (*namespace).to_owned(),
                name: (*name).to_owned(),
                value: Some((*value).to_owned()),
                status: *status,
                observed_at: Timestamp::from_unix_millis(*at),
                source: "agentless/1".to_owned(),
            })
            .collect();
        MachineRepository::new(self.pool.clone())
            .record_capabilities(&self.machine_id, &facts)
            .await
            .unwrap();
    }

    fn setup(&self, auth: OnboardAuth) -> MachineSetup {
        MachineSetup {
            machine_id: self.machine_id.clone(),
            endpoint_id: self.endpoint_id.clone(),
            auth,
            trigger: "install-op-1".to_owned(),
            correlation_id: Some("install-op-1".to_owned()),
            kind: SetupKind::Initial,
        }
    }

    async fn set_up_upgrade(&self) -> SetupFollowUp {
        let mut setup = self.setup(OnboardAuth::Agent);
        setup.kind = SetupKind::Upgrade;
        setup.trigger = "upgrade-op-1".to_owned();
        self.hook
            .machine_set_up(&fleet_auth::LanAllowAllAuthorizer, PRINCIPAL, &setup)
            .await
    }

    async fn set_up(&self, authorizer: &dyn Authorizer) -> SetupFollowUp {
        self.hook
            .machine_set_up(authorizer, PRINCIPAL, &self.setup(OnboardAuth::Agent))
            .await
    }

    async fn probe_count(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM operations WHERE kind = 'skills.probe'")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

/// Allows everything except one permission.
#[derive(Debug)]
struct Deny(Permission);

impl Authorizer for Deny {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.action == self.0 {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

#[tokio::test]
async fn a_linux_machine_gets_the_pinned_probe_queued_once() {
    let fixture = compose("deploy@host-one:22").await;
    fixture
        .plant_facts(&[
            ("os", "family", "Linux"),
            ("host", "architecture", "aarch64"),
        ])
        .await;

    let outcome = fixture.set_up(&fleet_auth::LanAllowAllAuthorizer).await;
    let SetupFollowUp::Queued {
        operation_id,
        version,
    } = &outcome
    else {
        panic!("expected a queued follow-up, got {outcome:?}");
    };
    assert_eq!(version, fleet_controller::skills::TESTED_CLI_VERSION);
    let operation = OperationRepository::new(fixture.pool.clone())
        .get(operation_id)
        .await
        .unwrap();
    assert_eq!(operation.kind, "skills.probe");
    assert_eq!(operation.state, "pending");
    let payload: serde_json::Value =
        serde_json::from_str(operation.payload_json.as_deref().unwrap()).unwrap();
    assert_eq!(payload["machineId"], fixture.machine_id.as_str());
    assert_eq!(payload["endpointId"], fixture.endpoint_id.as_str());
    assert_eq!(payload["auth"], serde_json::json!({"type": "agent"}));
    assert_eq!(
        payload["artifactUrl"],
        "https://github.com/xingkongliang/skills-manager/releases/download/v1.40.0/skills-manager-cli-Linux-arm64"
    );
    assert_eq!(
        payload["artifactSha256"],
        "377e3538ce74a13118ba0c30ebaaff597c7be4f0bb2bec2598ea0da27064a187"
    );

    // The same setup event never queues a second probe.
    let again = fixture.set_up(&fleet_auth::LanAllowAllAuthorizer).await;
    assert_eq!(again, outcome);
    assert_eq!(fixture.probe_count().await, 1);

    // The outcome serializes in the shape the install result carries.
    assert_eq!(
        serde_json::to_value(&outcome).unwrap(),
        serde_json::json!({"status": "queued", "operationId": operation_id, "version": "1.40.0"})
    );
}

/// The probe's audit row names the principal that queued it, the setup that
/// triggered it, and the setup's correlation id, so it traces back to the
/// install.
#[tokio::test]
async fn the_follow_up_audit_names_its_actor_and_trigger() {
    let fixture = compose("deploy@host-one:22").await;
    fixture
        .plant_facts(&[
            ("os", "family", "Linux"),
            ("host", "architecture", "x86_64"),
        ])
        .await;
    let outcome = fixture
        .hook
        .machine_set_up(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &fixture.setup(OnboardAuth::Agent),
        )
        .await;
    let SetupFollowUp::Queued { operation_id, .. } = outcome else {
        panic!("expected a queued follow-up, got {outcome:?}");
    };
    let operation = OperationRepository::new(fixture.pool.clone())
        .get(&operation_id)
        .await
        .unwrap();
    assert_eq!(operation.correlation_id.as_deref(), Some("install-op-1"));
    let (actor, correlation, metadata): (String, Option<String>, String) = sqlx::query_as(
        "SELECT actor, correlation_id, metadata_json FROM audit_events \
         WHERE action = 'operation.create' AND operation_id = ?",
    )
    .bind(&operation_id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(actor, fleet_auth::LAN_PRINCIPAL_ID);
    assert_eq!(correlation.as_deref(), Some("install-op-1"));
    let metadata: serde_json::Value = serde_json::from_str(&metadata).unwrap();
    assert_eq!(metadata["kind"], "skills.probe", "{metadata}");
    assert_eq!(metadata["setup_trigger"], "install-op-1", "{metadata}");
}

/// The setup prefix is reserved: the generic route refuses it, so no caller
/// can occupy the key a setup follow-up will use.
#[tokio::test]
async fn the_generic_route_cannot_take_a_setup_key() {
    let fixture = compose("deploy@host-one:22").await;
    let error = fixture
        .operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            PRINCIPAL,
            &NewOperation {
                kind: "noop".to_owned(),
                idempotency_key: Some(format!("{SETUP_FOLLOW_UP_IDEMPOTENCY_PREFIX}install-op-1")),
                deadline_at: None,
                correlation_id: None,
                payload_json: None,
                review_token: None,
            },
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("reserved"), "{error}");
}

/// A setup key held by an operation that is not this follow-up (another
/// machine's probe here) answers `failed`, never `queued` with a stranger.
#[tokio::test]
async fn a_setup_key_held_by_another_operation_is_not_reported_as_queued() {
    let fixture = compose("deploy@host-one:22").await;
    fixture
        .plant_facts(&[
            ("os", "family", "Linux"),
            ("host", "architecture", "x86_64"),
        ])
        .await;
    fixture
        .operations
        .create_setup_follow_up(
            &fleet_auth::LanAllowAllAuthorizer,
            PRINCIPAL,
            &NewOperation {
                kind: "skills.probe".to_owned(),
                idempotency_key: Some(format!("{SETUP_FOLLOW_UP_IDEMPOTENCY_PREFIX}install-op-1")),
                deadline_at: None,
                correlation_id: None,
                payload_json: Some(
                    serde_json::json!({
                        "machineId": "someone-else",
                        "endpointId": "endpoint",
                        "auth": {"type": "agent"},
                        "artifactUrl": "https://example.invalid/other",
                        "artifactSha256": "0".repeat(64),
                        "timeoutSeconds": 30,
                    })
                    .to_string(),
                ),
                review_token: None,
            },
        )
        .await
        .unwrap();
    let outcome = fixture.set_up(&fleet_auth::LanAllowAllAuthorizer).await;
    let SetupFollowUp::Failed { reason } = &outcome else {
        panic!("expected a failure, got {outcome:?}");
    };
    assert!(reason.contains("held by another operation"), "{reason}");
}

/// The setup route creates only setup-keyed, pinned `skills.probe`
/// operations, and refuses a trigger the audit could not record, before
/// anything persists.
#[tokio::test]
async fn the_setup_route_refuses_other_kinds_keys_and_unpinned_probes() {
    let fixture = compose("deploy@host-one:22").await;
    let pinned = || {
        serde_json::json!({
            "machineId": "m",
            "endpointId": "endpoint",
            "auth": {"type": "agent"},
            "artifactUrl": "https://example.invalid/cli",
            "artifactSha256": "0".repeat(64),
            "timeoutSeconds": 30,
        })
    };
    let mut unpinned = pinned();
    unpinned.as_object_mut().unwrap().remove("artifactUrl");
    let mut blank = pinned();
    blank["artifactSha256"] = serde_json::json!("");
    let key = |trigger: &str| Some(format!("{SETUP_FOLLOW_UP_IDEMPOTENCY_PREFIX}{trigger}"));
    for (kind, key, payload) in [
        ("noop", key("x"), Some(pinned())),
        ("skills.probe", Some("other-key".to_owned()), Some(pinned())),
        ("skills.probe", key(""), Some(pinned())),
        ("skills.probe", None, Some(pinned())),
        ("skills.probe", key(&"t".repeat(2049)), Some(pinned())),
        ("skills.probe", key("unpinned"), Some(unpinned)),
        ("skills.probe", key("blank"), Some(blank)),
        ("skills.probe", key("none"), None),
    ] {
        let result = fixture
            .operations
            .create_setup_follow_up(
                &fleet_auth::LanAllowAllAuthorizer,
                PRINCIPAL,
                &NewOperation {
                    kind: kind.to_owned(),
                    idempotency_key: key.clone(),
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: payload.map(|payload| payload.to_string()),
                    review_token: None,
                },
            )
            .await;
        assert!(
            matches!(
                result,
                Err(fleet_application::operation::OperationUseCaseError::Invalid { .. })
            ),
            "{kind} key of {} bytes",
            key.as_deref().map_or(0, str::len)
        );
    }
    // No refusal persisted anything.
    let all: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operations")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(all, 0);
}

/// With both architecture facts, the best observation wins, ranked by the
/// effective status at read time: a fresh known fact beats a newer stale
/// one, and a known fact older than a day reads as stale, so it does not
/// beat a newer one.
#[tokio::test]
async fn the_freshest_known_architecture_fact_selects_the_pin() {
    let now = fleet_core::SystemClock::now_unix_millis();
    let minute = 60_000;
    let day = 24 * 60 * minute;
    let cases = [
        (
            vec![
                ("os", "family", "Linux", CapabilityStatus::Known, now),
                (
                    "host",
                    "architecture",
                    "x86_64",
                    CapabilityStatus::Known,
                    now - 2 * minute,
                ),
                (
                    "os",
                    "arch",
                    "aarch64",
                    CapabilityStatus::Known,
                    now - minute,
                ),
            ],
            "arm64",
        ),
        (
            vec![
                ("os", "family", "Linux", CapabilityStatus::Known, now),
                (
                    "host",
                    "architecture",
                    "aarch64",
                    CapabilityStatus::Known,
                    now - minute,
                ),
                (
                    "os",
                    "arch",
                    "x86_64",
                    CapabilityStatus::Known,
                    now - 2 * minute,
                ),
            ],
            "arm64",
        ),
        // A fresh known fact beats a newer recorded-stale one.
        (
            vec![
                ("os", "family", "Linux", CapabilityStatus::Known, now),
                (
                    "host",
                    "architecture",
                    "x86_64",
                    CapabilityStatus::Known,
                    now - 2 * minute,
                ),
                (
                    "os",
                    "arch",
                    "aarch64",
                    CapabilityStatus::Stale,
                    now - minute,
                ),
            ],
            "x64",
        ),
        // A recorded-known fact three days old is stale at read time, so the
        // newer stale observation wins.
        (
            vec![
                ("os", "family", "Linux", CapabilityStatus::Known, now),
                (
                    "host",
                    "architecture",
                    "x86_64",
                    CapabilityStatus::Known,
                    now - 3 * day,
                ),
                (
                    "os",
                    "arch",
                    "aarch64",
                    CapabilityStatus::Stale,
                    now - day - minute,
                ),
            ],
            "arm64",
        ),
    ];
    for (facts, asset) in cases {
        let fixture = compose("deploy@host-one:22").await;
        fixture.plant_observed(&facts).await;
        let SetupFollowUp::Queued { operation_id, .. } =
            fixture.set_up(&fleet_auth::LanAllowAllAuthorizer).await
        else {
            panic!("expected a queued follow-up for {facts:?}");
        };
        let operation = OperationRepository::new(fixture.pool.clone())
            .get(&operation_id)
            .await
            .unwrap();
        let payload: serde_json::Value =
            serde_json::from_str(operation.payload_json.as_deref().unwrap()).unwrap();
        assert!(
            payload["artifactUrl"]
                .as_str()
                .unwrap()
                .ends_with(&format!("-Linux-{asset}")),
            "{facts:?}: {payload}"
        );
    }
}

/// An upgrade (a fleetd install over a live identity) queues only when the
/// machine was never observed by Skills Manager: an enrolling install that
/// failed before its follow-up still gets it on the retry, while an
/// operator's removal (an `absent` observation) is respected.
#[tokio::test]
async fn an_upgrade_queues_only_without_any_skills_observation() {
    let fixture = compose("deploy@host-one:22").await;
    fixture
        .plant_facts(&[
            ("os", "family", "Linux"),
            ("host", "architecture", "x86_64"),
        ])
        .await;
    let outcome = fixture.set_up_upgrade().await;
    assert!(
        matches!(outcome, SetupFollowUp::Queued { .. }),
        "{outcome:?}"
    );

    fleet_storage_sqlite::SkillsRepository::new(fixture.pool.clone())
        .record(&SkillsSnapshot {
            machine_id: fixture.machine_id.clone(),
            availability: SkillsAvailability::Absent,
            cli_version: None,
            data: serde_json::json!({}),
            update_check: "unavailable".to_owned(),
            observed_at: fleet_core::SystemClock::now_unix_millis(),
        })
        .await
        .unwrap();
    let mut setup = fixture.setup(OnboardAuth::Agent);
    setup.kind = SetupKind::Upgrade;
    setup.trigger = "upgrade-op-2".to_owned();
    let outcome = fixture
        .hook
        .machine_set_up(&fleet_auth::LanAllowAllAuthorizer, PRINCIPAL, &setup)
        .await;
    let SetupFollowUp::Skipped { reason } = &outcome else {
        panic!("expected a skip, got {outcome:?}");
    };
    assert!(reason.contains("upgrade"), "{reason}");
    assert_eq!(fixture.probe_count().await, 1);
}

/// Without the observation port an upgrade never queues.
#[tokio::test]
async fn an_upgrade_without_the_observation_port_is_skipped() {
    let fixture = compose("deploy@host-one:22").await;
    fixture
        .plant_facts(&[
            ("os", "family", "Linux"),
            ("host", "architecture", "x86_64"),
        ])
        .await;
    let hook = SkillsManagerSetup::new(
        Arc::new(MachineRepository::new(fixture.pool.clone())),
        fixture.operations.clone(),
    );
    let mut setup = fixture.setup(OnboardAuth::Agent);
    setup.kind = SetupKind::Upgrade;
    let outcome = hook
        .machine_set_up(&fleet_auth::LanAllowAllAuthorizer, PRINCIPAL, &setup)
        .await;
    assert!(
        matches!(outcome, SetupFollowUp::Skipped { .. }),
        "{outcome:?}"
    );
    assert_eq!(fixture.probe_count().await, 0);
}

#[test]
fn the_pinned_version_is_the_tested_contract_version() {
    assert_eq!(
        fleet_provider_skills_manager::PINNED_CLI_VERSION,
        fleet_controller::skills::TESTED_CLI_VERSION
    );
}

#[tokio::test]
async fn fleetd_facts_select_the_pin_too() {
    let fixture = compose("deploy@host-one:22").await;
    fixture
        .plant_facts(&[("os", "family", "linux"), ("os", "arch", "x86_64")])
        .await;
    let outcome = fixture.set_up(&fleet_auth::LanAllowAllAuthorizer).await;
    assert!(
        matches!(outcome, SetupFollowUp::Queued { .. }),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn platforms_without_a_pin_are_skipped_with_a_reason() {
    for (facts, needle) in [
        (
            vec![
                ("os", "family", "Windows"),
                ("host", "architecture", "x86_64"),
            ],
            "only Linux is pinned",
        ),
        (
            vec![
                ("os", "family", "Linux"),
                ("host", "architecture", "riscv64"),
            ],
            "riscv64",
        ),
        (vec![("os", "family", "Linux")], "unknown"),
        (vec![], "unknown"),
    ] {
        let fixture = compose("deploy@host-one:22").await;
        fixture.plant_facts(&facts).await;
        let outcome = fixture.set_up(&fleet_auth::LanAllowAllAuthorizer).await;
        let SetupFollowUp::Skipped { reason } = &outcome else {
            panic!("expected a skip for {facts:?}, got {outcome:?}");
        };
        assert!(reason.contains(needle), "{reason}");
        assert_eq!(fixture.probe_count().await, 0, "{facts:?}");
    }
}

#[tokio::test]
async fn a_denied_queue_answers_failed_and_creates_nothing() {
    let fixture = compose("deploy@host-one:22").await;
    fixture
        .plant_facts(&[
            ("os", "family", "Linux"),
            ("host", "architecture", "x86_64"),
        ])
        .await;
    // A pinned probe installs a binary, so it needs the deploy permission.
    let outcome = fixture.set_up(&Deny(Permission::SkillsDeploy)).await;
    let SetupFollowUp::Failed { reason } = &outcome else {
        panic!("expected a failure, got {outcome:?}");
    };
    assert!(reason.contains("denied"), "{reason}");
    assert_eq!(fixture.probe_count().await, 0);
}

/// The queued probe installs only when the CLI is absent: a machine that
/// already has a CLI keeps it, byte for byte, even though the pinned URL is
/// never reachable from the test.
#[tokio::test]
async fn the_queued_probe_leaves_an_installed_cli_alone() {
    let home_dir = tempfile::tempdir().unwrap();
    let sshd = start_sshd_with_home(home_dir.path());
    let fixture = compose(&format!("{}@127.0.0.1:{}", whoami(), sshd.port)).await;
    fixture
        .plant_facts(&[
            ("os", "family", "Linux"),
            ("host", "architecture", "x86_64"),
        ])
        .await;

    let ssh_dir = home_dir.path().join("controller-ssh");
    let provider = fleet_provider_ssh::SshProvider::new(ssh_dir.clone()).unwrap();
    let observation = provider
        .probe_host_key("127.0.0.1", sshd.port, Duration::from_secs(10))
        .unwrap();
    provider.pin(&observation).unwrap();
    MachineRepository::new(fixture.pool.clone())
        .confirm_fingerprint(&fixture.endpoint_id, &observation.fingerprint, 0)
        .await
        .unwrap();

    // A tested CLI is already installed.
    let bin_dir = home_dir.path().join(".local/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let cli = bin_dir.join("skills-manager-cli");
    let stub = "#!/usr/bin/env bash\n[ \"$1\" = --json ] && shift\ncase \"$1\" in\n  --version) echo '{\"version\":\"1.40.0\"}' ;;\n  *) echo '[]' ;;\nesac\n";
    std::fs::write(&cli, stub).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let identity = format!("{}/user_ed25519", sshd.keys_dir.path().display());
    let outcome = fixture
        .hook
        .machine_set_up(
            &fleet_auth::LanAllowAllAuthorizer,
            PRINCIPAL,
            &fixture.setup(OnboardAuth::IdentityFile { path: identity }),
        )
        .await;
    let SetupFollowUp::Queued { operation_id, .. } = outcome else {
        panic!("expected a queued follow-up, got {outcome:?}");
    };

    let executor = fleet_controller::skills::SkillsExecutor::new(
        Arc::new(MachineRepository::new(fixture.pool.clone())) as Arc<dyn MachinePort>,
        ssh_dir,
        ExecutionLimiter::new(2),
    );
    fixture
        .operations
        .tick(
            &executor,
            "worker-a",
            fleet_core::SystemClock::now_unix_millis(),
            60_000,
        )
        .await
        .unwrap();
    let finished = OperationRepository::new(fixture.pool.clone())
        .get(&operation_id)
        .await
        .unwrap();
    assert_eq!(finished.state, "succeeded", "{:?}", finished.error_json);
    let result: serde_json::Value =
        serde_json::from_str(finished.result_json.as_deref().unwrap()).unwrap();
    assert_eq!(result["availability"], "available", "{result}");
    assert_eq!(std::fs::read_to_string(&cli).unwrap(), stub);
}
