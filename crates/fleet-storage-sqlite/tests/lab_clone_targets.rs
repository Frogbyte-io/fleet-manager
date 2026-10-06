//! Issue #220: the Lab clone target is reserved on the provision record
//! before the clone, at most one in-flight record holds a VMID, and the
//! image build artifacts the executor clones from (and the cleanup guard
//! protects) are read from the recorded `image.build` results.

use fleet_application::lab::{
    CloneTargetReservation, ImageArtifactPort as _, NewProvision, ProvisionPort as _,
};
use fleet_application::operation::OperationPort as _;
use fleet_core::GuestState;
use fleet_storage_sqlite::{LabRepository, OperationRepository, RecipeRepository, Store};

const NOW: i64 = 1_800_000_000_000;

async fn setup() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().expect("a temp directory");
    let store = Store::open(&dir.path().join("fleet.db"))
        .await
        .expect("the store must open");
    (dir, store)
}

async fn record(labs: &LabRepository) -> fleet_application::lab::ProvisionRecord {
    labs.create(
        &NewProvision {
            template_version_id: "template-1@digest".to_owned(),
            lease_id: None,
            idempotency_key: None,
        },
        NOW,
    )
    .await
    .expect("the record must be created")
}

fn reserved(outcome: CloneTargetReservation) -> fleet_application::lab::ProvisionRecord {
    match outcome {
        CloneTargetReservation::Reserved(record) => record,
        CloneTargetReservation::HeldBy { record_id } => {
            panic!("expected a reservation, the VMID is held by {record_id}")
        }
    }
}

#[tokio::test]
async fn a_reservation_is_persisted_and_kept_on_a_rerun() {
    let (_dir, store) = setup().await;
    let labs = LabRepository::new(store.pool().clone());
    let first = record(&labs).await;

    let held = reserved(
        labs.reserve_clone_target(&first.id, "pve-b", 9000)
            .await
            .unwrap(),
    );
    assert_eq!(held.node.as_deref(), Some("pve-b"));
    assert_eq!(held.vmid, Some(9000));
    assert_eq!(held.clone_upid, None);
    let stored = labs.get(&first.id).await.unwrap();
    assert_eq!(
        (stored.node.as_deref(), stored.vmid),
        (Some("pve-b"), Some(9000))
    );

    // A re-run that proposes another VMID resumes with the stored one.
    let again = reserved(
        labs.reserve_clone_target(&first.id, "pve-b", 9001)
            .await
            .unwrap(),
    );
    assert_eq!(again.vmid, Some(9000));
}

#[tokio::test]
async fn an_in_flight_reservation_holds_its_vmid_against_other_records() {
    let (_dir, store) = setup().await;
    let labs = LabRepository::new(store.pool().clone());
    let first = record(&labs).await;
    let second = record(&labs).await;
    reserved(
        labs.reserve_clone_target(&first.id, "pve", 9000)
            .await
            .unwrap(),
    );

    let outcome = labs
        .reserve_clone_target(&second.id, "pve", 9000)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        CloneTargetReservation::HeldBy {
            record_id: first.id.clone()
        }
    );
    assert_eq!(labs.get(&second.id).await.unwrap().vmid, None);

    // A record that left `provisioning` no longer holds the VMID: its
    // guest exists in the cluster, which is what nextid consults.
    let mut finished = labs.get(&first.id).await.unwrap();
    finished.state = GuestState::NeverReady;
    labs.update(&finished).await.unwrap();
    let taken = reserved(
        labs.reserve_clone_target(&second.id, "pve", 9000)
            .await
            .unwrap(),
    );
    assert_eq!(taken.vmid, Some(9000));
}

#[tokio::test]
async fn a_started_clone_or_finished_record_cannot_reserve() {
    let (_dir, store) = setup().await;
    let labs = LabRepository::new(store.pool().clone());
    let started = record(&labs).await;
    let mut with_upid = started.clone();
    with_upid.clone_upid =
        Some("UPID:pve:0015523F:0C6DF532:6AAFE1EC:qmclone:120:fleet@pve!lab:".to_owned());
    labs.update(&with_upid).await.unwrap();
    let error = labs
        .reserve_clone_target(&started.id, "pve", 9000)
        .await
        .unwrap_err();
    assert!(error.contains("already started its clone"), "{error}");

    let finished = record(&labs).await;
    let mut never_ready = finished.clone();
    never_ready.state = GuestState::NeverReady;
    labs.update(&never_ready).await.unwrap();
    let error = labs
        .reserve_clone_target(&finished.id, "pve", 9000)
        .await
        .unwrap_err();
    assert!(error.contains("never_ready"), "{error}");

    let error = labs
        .reserve_clone_target("no-such-record", "pve", 9000)
        .await
        .unwrap_err();
    assert!(error.contains("not found"), "{error}");
}

async fn build(
    operations: &OperationRepository,
    version_id: &str,
    state: &str,
    result: Option<serde_json::Value>,
) {
    let payload = serde_json::json!({ "versionId": version_id }).to_string();
    let operation = operations
        .create("image.build", None, None, None, Some(&payload))
        .await
        .expect("the build operation must be created");
    operations
        .transition(&operation.id, "running")
        .await
        .expect("the build must start");
    let result = result.map(|result| result.to_string());
    let error = (state != "succeeded").then(|| r#"{"reason":"build_failed"}"#.to_owned());
    operations
        .complete(&operation.id, state, result.as_deref(), error.as_deref())
        .await
        .expect("the build must complete");
}

#[tokio::test]
async fn the_template_artifact_is_the_latest_successful_builds_vmid() {
    let (_dir, store) = setup().await;
    let operations = OperationRepository::new(store.pool().clone());
    let artifacts = RecipeRepository::new(store.pool().clone());

    assert_eq!(artifacts.template_vmid("rcp-1@a").await.unwrap(), None);
    assert!(
        artifacts
            .promoted_template_vmids()
            .await
            .unwrap()
            .is_empty()
    );

    build(
        &operations,
        "rcp-1@a",
        "succeeded",
        Some(serde_json::json!({ "artifactId": "120", "recipeVersion": "rcp-1@a" })),
    )
    .await;
    // A failed build records nothing, and another version's build does
    // not count for this one.
    build(&operations, "rcp-1@a", "failed", None).await;
    build(
        &operations,
        "rcp-2@b",
        "succeeded",
        Some(serde_json::json!({ "artifactId": "130", "recipeVersion": "rcp-2@b" })),
    )
    .await;
    assert_eq!(artifacts.template_vmid("rcp-1@a").await.unwrap(), Some(120));
    assert_eq!(artifacts.template_vmid("rcp-2@b").await.unwrap(), Some(130));
    assert_eq!(artifacts.template_vmid("rcp-3@c").await.unwrap(), None);

    // The `<node>:<vmid>` shape the Packer stream also carries.
    build(
        &operations,
        "rcp-3@c",
        "succeeded",
        Some(serde_json::json!({ "artifactId": "pve:102" })),
    )
    .await;
    assert_eq!(artifacts.template_vmid("rcp-3@c").await.unwrap(), Some(102));

    // An artifact that is not a VMID is an honest error, not a guess.
    build(
        &operations,
        "rcp-4@d",
        "succeeded",
        Some(serde_json::json!({ "artifactId": "local:vztmpl/base.tar" })),
    )
    .await;
    let error = artifacts.template_vmid("rcp-4@d").await.unwrap_err();
    assert!(error.contains("not a Proxmox template VMID"), "{error}");

    // The latest successful build counts alone: when it recorded no
    // artifact, an older build's VMID is not a fallback.
    build(
        &operations,
        "rcp-1@a",
        "succeeded",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(artifacts.template_vmid("rcp-1@a").await.unwrap(), None);
}

async fn promote(store: &Store, version_id: &str, recipe_id: &str) {
    sqlx::query(
        "INSERT INTO image_recipe_versions (id, recipe_id, name, description, content_digest, content, source, node, storage_pool, published_at, promoted_at, promoted_by) \
         VALUES (?1, ?2, ?2, '', ?1, '{}', 'iso', 'pve', 'local-lvm', ?3, ?3, 'operator')",
    )
    .bind(version_id)
    .bind(recipe_id)
    .bind(NOW)
    .execute(store.pool())
    .await
    .expect("the promoted version must insert");
}

#[tokio::test]
async fn the_protected_artifacts_are_the_promoted_versions_templates() {
    let (_dir, store) = setup().await;
    let operations = OperationRepository::new(store.pool().clone());
    let artifacts = RecipeRepository::new(store.pool().clone());
    build(
        &operations,
        "rcp-1@a",
        "succeeded",
        Some(serde_json::json!({ "artifactId": "120" })),
    )
    .await;
    build(
        &operations,
        "rcp-1@a",
        "succeeded",
        Some(serde_json::json!({ "artifactId": "pve:121" })),
    )
    .await;
    build(
        &operations,
        "rcp-2@b",
        "succeeded",
        Some(serde_json::json!({ "artifactId": "130" })),
    )
    .await;
    assert!(
        artifacts
            .promoted_template_vmids()
            .await
            .unwrap()
            .is_empty()
    );

    promote(&store, "rcp-1@a", "rcp-1").await;
    // Every successful build of a promoted version is protected; an
    // unpromoted version's template is protected by the live template
    // check instead.
    assert_eq!(
        artifacts.promoted_template_vmids().await.unwrap(),
        vec![120, 121]
    );
    promote(&store, "rcp-2@b", "rcp-2").await;
    assert_eq!(
        artifacts.promoted_template_vmids().await.unwrap(),
        vec![120, 121, 130]
    );
}

#[tokio::test]
async fn readiness_associations_and_bootstrap_state_survive_storage_round_trip() {
    let (_dir, store) = setup().await;
    let labs = LabRepository::new(store.pool().clone());
    let mut provision = record(&labs).await;
    provision.state = GuestState::from_id("bootstrapping").expect("bootstrap is a durable state");
    provision.readiness_deadline_at = Some(NOW + 300_000);
    provision.failed_step = Some("ssh_trust".to_owned());
    labs.update(&provision).await.unwrap();
    let loaded = labs.get(&provision.id).await.unwrap();
    assert_eq!(loaded.state.id(), "bootstrapping");
    assert_eq!(loaded.readiness_deadline_at, Some(NOW + 300_000));
    assert_eq!(loaded.failed_step.as_deref(), Some("ssh_trust"));
}

#[tokio::test]
async fn guest_registration_atomically_links_one_lab_machine_and_endpoint() {
    use fleet_application::machine::MachinePort as _;
    let (_dir, store) = setup().await;
    let labs = LabRepository::new(store.pool().clone());
    let provision = record(&labs).await;
    let linked = labs
        .ensure_guest_machine(&provision.id, "root@192.0.2.42:22")
        .await
        .unwrap();
    let again = labs
        .ensure_guest_machine(&provision.id, "root@192.0.2.42:22")
        .await
        .unwrap();
    assert_eq!(linked.machine_id, again.machine_id);
    assert_eq!(linked.endpoint_id, again.endpoint_id);
    let machines = fleet_storage_sqlite::MachineRepository::new(store.pool().clone());
    let machine = machines
        .get(linked.machine_id.as_deref().unwrap())
        .await
        .unwrap();
    assert!(machine.tags.iter().any(|tag| tag == "lab"));
    assert!(
        machine
            .groups
            .iter()
            .any(|group| group == &format!("lab-provision:{}", provision.id))
    );
    assert_eq!(machine.endpoints.len(), 1);
    assert_eq!(machine.endpoints[0].id, linked.endpoint_id.unwrap());
    assert_eq!(machine.endpoints[0].reference, "root@192.0.2.42:22");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM machines")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[derive(Debug, Default)]
struct Readiness {
    fail: Option<&'static str>,
    calls: std::sync::Mutex<Vec<&'static str>>,
}

#[async_trait::async_trait]
impl fleet_application::lab::LabReadinessPort for Readiness {
    async fn trust(
        &self,
        _record: &fleet_application::lab::ProvisionRecord,
        _content: &fleet_core::LabTemplateContent,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        self.calls.lock().unwrap().push("trust");
        if self.fail == Some("trust") {
            Err("secret-shaped provider error must not escape".to_owned())
        } else {
            Ok(true)
        }
    }
    async fn ssh_probe(
        &self,
        _operations: &fleet_application::operation::Operations,
        _parent_id: &str,
        _record: &fleet_application::lab::ProvisionRecord,
        command: &str,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        assert_eq!(command, "test -f /tmp/ready");
        self.calls.lock().unwrap().push("ssh");
        if self.fail == Some("ssh") {
            Err("probe refused".to_owned())
        } else {
            Ok(true)
        }
    }
    async fn create_project(
        &self,
        operations: &fleet_application::operation::Operations,
        _parent_id: &str,
        record: &fleet_application::lab::ProvisionRecord,
        project_id: &str,
        _remaining: std::time::Duration,
    ) -> Result<String, String> {
        assert_eq!(project_id, "project-1");
        self.calls.lock().unwrap().push("project_create");
        if self.fail == Some("project_create") {
            return Err("project missing".to_owned());
        }
        let operation = operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &fleet_application::operation::NewOperation {
                    kind: "noop".to_owned(),
                    idempotency_key: Some(format!("lab-test:{}", record.id)),
                    deadline_at: record.readiness_deadline_at,
                    correlation_id: Some(record.id.clone()),
                    payload_json: None,
                    review_token: None,
                },
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(operation.id)
    }
    async fn project_verified(
        &self,
        operations: &fleet_application::operation::Operations,
        child_id: &str,
        _remaining: std::time::Duration,
    ) -> Result<bool, String> {
        self.calls.lock().unwrap().push("verify");
        if self.fail == Some("verify") {
            return Err("verify failed".to_owned());
        }
        if operations.get_state(child_id).await.unwrap() != "succeeded" {
            operations
                .claim_only_execute(&fleet_application::worker::NoopExecutor, child_id, "test")
                .await?;
        }
        Ok(true)
    }
}

async fn bootstrap_record(labs: &LabRepository) -> fleet_application::lab::ProvisionRecord {
    let mut provision = record(labs).await;
    provision.state = fleet_core::GuestState::Booting;
    provision.guest_ipv4 = Some("192.0.2.42".to_owned());
    provision.readiness_deadline_at = Some(fleet_core::SystemClock::now_unix_millis() + 30_000);
    provision.node = Some("pve".to_owned());
    provision.vmid = Some(9000);
    provision.clone_upid = Some("recorded-clone".to_owned());
    labs.update(&provision).await.unwrap();
    provision
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn bootstrap_dispatches_each_probe_and_prepares_projects_before_ready() {
    use fleet_application::lab::LabBootstrap;
    use fleet_application::operation::Operations;
    for (probe, project, expected) in [
        (fleet_core::ReadinessProbe::GuestAgent, None, vec!["trust"]),
        (
            fleet_core::ReadinessProbe::SshExec,
            None,
            vec!["trust", "ssh"],
        ),
        (
            fleet_core::ReadinessProbe::ProjectReady,
            Some("project-1"),
            vec!["trust", "project_create", "verify"],
        ),
        (
            fleet_core::ReadinessProbe::GuestAgent,
            Some("project-1"),
            vec!["trust", "project_create", "verify"],
        ),
    ] {
        let (_dir, store) = setup().await;
        let labs = LabRepository::new(store.pool().clone());
        let provision = bootstrap_record(&labs).await;
        let audit = std::sync::Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone()));
        let operations = Operations::new(
            std::sync::Arc::new(OperationRepository::new(store.pool().clone())),
            audit.clone(),
        );
        let parent = operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &fleet_application::operation::NewOperation {
                    kind: "noop".to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: None,
                    review_token: None,
                },
            )
            .await
            .unwrap();
        let readiness = Readiness::default();
        let principal = fleet_application::authz::ActingPrincipal {
            id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        };
        let bootstrap = LabBootstrap {
            provisions: &labs,
            readiness: &readiness,
            audit: audit.as_ref(),
            authorizer: &fleet_auth::LanAllowAllAuthorizer,
            principal: &principal,
        };
        let content = fleet_core::LabTemplateContent {
            readiness_probe: probe,
            bootstrap_project_id: project.map(str::to_owned),
            readiness_command: Some("test -f /tmp/ready".to_owned()),
            ..Default::default()
        };
        let finished = bootstrap
            .run(&operations, &parent.id, provision, &content)
            .await
            .unwrap();
        assert_eq!(*readiness.calls.lock().unwrap(), expected);
        assert_eq!(finished.state, fleet_core::GuestState::Bootstrapping);
        assert!(
            finished.ready_at.is_none(),
            "the caller must commit TTL after all probes pass"
        );
        assert!(finished.machine_id.is_some());
        assert_eq!(
            finished.ready_project_operation_id.is_some(),
            project.is_some()
        );
        assert_eq!(
            labs.get(&finished.id).await.unwrap().machine_id,
            finished.machine_id
        );
        // Re-running bootstrap keeps the machine and persisted child identity.
        if project.is_some() {
            let resumed = bootstrap
                .run(
                    &operations,
                    &parent.id,
                    labs.get(&finished.id).await.unwrap(),
                    &content,
                )
                .await
                .unwrap();
            assert_eq!(resumed.machine_id, finished.machine_id);
            assert_eq!(
                resumed.ready_project_operation_id,
                finished.ready_project_operation_id
            );
            assert_eq!(
                readiness
                    .calls
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|call| **call == "project_create")
                    .count(),
                1
            );
        }
    }
}

#[tokio::test]
async fn bootstrap_names_failures_and_preserves_machine_and_external_ids() {
    for (fail, step) in [
        ("trust", "ssh_trust"),
        ("ssh", "ssh_exec"),
        ("project_create", "project_setup"),
        ("verify", "project_ready"),
    ] {
        let (_dir, store) = setup().await;
        let labs = LabRepository::new(store.pool().clone());
        let provision = bootstrap_record(&labs).await;
        let audit = std::sync::Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone()));
        let operations = fleet_application::operation::Operations::new(
            std::sync::Arc::new(OperationRepository::new(store.pool().clone())),
            audit.clone(),
        );
        let parent = operations
            .create(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &fleet_application::operation::NewOperation {
                    kind: "noop".to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: None,
                    review_token: None,
                },
            )
            .await
            .unwrap();
        let readiness = Readiness {
            fail: Some(fail),
            ..Default::default()
        };
        let principal = fleet_application::authz::ActingPrincipal {
            id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        };
        let bootstrap = fleet_application::lab::LabBootstrap {
            provisions: &labs,
            readiness: &readiness,
            audit: audit.as_ref(),
            authorizer: &fleet_auth::LanAllowAllAuthorizer,
            principal: &principal,
        };
        let content = fleet_core::LabTemplateContent {
            readiness_probe: fleet_core::ReadinessProbe::SshExec,
            readiness_command: Some("test -f /tmp/ready".to_owned()),
            bootstrap_project_id: Some("project-1".to_owned()),
            ..Default::default()
        };
        let error = bootstrap
            .run(&operations, &parent.id, provision.clone(), &content)
            .await
            .unwrap_err();
        assert_eq!(error.step, step);
        let stored = labs.get(&provision.id).await.unwrap();
        assert_eq!(stored.node, provision.node);
        assert_eq!(stored.vmid, provision.vmid);
        assert_eq!(stored.clone_upid, provision.clone_upid);
        assert!(stored.machine_id.is_some());
        assert!(stored.ready_at.is_none());
        assert_eq!(
            stored.ready_project_operation_id.is_some(),
            fail == "verify"
        );
    }
}

#[tokio::test]
async fn an_expired_readiness_record_does_not_register_or_restart_its_deadline() {
    let (_dir, store) = setup().await;
    let labs = LabRepository::new(store.pool().clone());
    let mut provision = bootstrap_record(&labs).await;
    provision.readiness_deadline_at = Some(fleet_core::SystemClock::now_unix_millis() - 1);
    labs.update(&provision).await.unwrap();
    let audit = std::sync::Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone()));
    let operations = fleet_application::operation::Operations::new(
        std::sync::Arc::new(OperationRepository::new(store.pool().clone())),
        audit.clone(),
    );
    let parent = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &fleet_application::operation::NewOperation {
                kind: "noop".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: None,
                review_token: None,
            },
        )
        .await
        .unwrap();
    let readiness = Readiness::default();
    let principal = fleet_application::authz::ActingPrincipal {
        id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
    };
    let bootstrap = fleet_application::lab::LabBootstrap {
        provisions: &labs,
        readiness: &readiness,
        audit: audit.as_ref(),
        authorizer: &fleet_auth::LanAllowAllAuthorizer,
        principal: &principal,
    };
    assert!(
        bootstrap
            .run(
                &operations,
                &parent.id,
                provision.clone(),
                &fleet_core::LabTemplateContent::default()
            )
            .await
            .is_err()
    );
    let stored = labs.get(&provision.id).await.unwrap();
    assert_eq!(stored.machine_id, None);
    assert_eq!(
        stored.readiness_deadline_at,
        provision.readiness_deadline_at
    );
    assert!(readiness.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn readiness_migration_preserves_existing_provision_and_lease_identifiers() {
    let dir = tempfile::tempdir().unwrap();
    let migrations_dir = dir.path().join("migrations");
    std::fs::create_dir(&migrations_dir).unwrap();
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    for entry in std::fs::read_dir(&source).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name() != "0035_lab_readiness.sql" {
            std::fs::copy(entry.path(), migrations_dir.join(entry.file_name())).unwrap();
        }
    }
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate::Migrator::new(migrations_dir.as_path())
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO lab_leases (id, template_version_id, owner, purpose, state, provision_id, cleanup, created_at) VALUES ('old-lease', 'version-1', 'tester', '', 'provisioning', 'old-record', 'destroy', 1800000000000)")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO lab_provisions (id, template_version_id, state, node, vmid, clone_upid, guest_ipv4, idempotency_key, created_at, updated_at, lease_id) VALUES ('old-record', 'version-1', 'provisioning', 'pve', 9000, 'old-upid', '192.0.2.42', 'old-key', 1800000000000, 1800000000000, 'old-lease')")
        .execute(&pool).await.unwrap();
    std::fs::copy(
        source.join("0035_lab_readiness.sql"),
        migrations_dir.join("0035_lab_readiness.sql"),
    )
    .unwrap();
    sqlx::migrate::Migrator::new(migrations_dir.as_path())
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();
    let labs = LabRepository::new(pool.clone());
    let record = labs.get("old-record").await.unwrap();
    assert_eq!(record.lease_id.as_deref(), Some("old-lease"));
    assert_eq!(record.node.as_deref(), Some("pve"));
    assert_eq!(record.vmid, Some(9000));
    assert_eq!(record.clone_upid.as_deref(), Some("old-upid"));
    assert_eq!(record.guest_ipv4.as_deref(), Some("192.0.2.42"));
    assert_eq!(record.idempotency_key.as_deref(), Some("old-key"));
    assert_eq!(record.machine_id, None);
    assert_eq!(record.readiness_deadline_at, None);
    let linked = labs
        .ensure_guest_machine(&record.id, "root@192.0.2.42:22")
        .await
        .unwrap();
    let machines = fleet_storage_sqlite::MachineRepository::new(pool);
    let machine = fleet_application::machine::MachinePort::get(
        &machines,
        linked.machine_id.as_deref().unwrap(),
    )
    .await
    .unwrap();
    let view = fleet_application::machine::MachineView::assemble(machine, NOW, true);
    assert!(view.tags.iter().any(|tag| tag == "lab"));
    assert!(
        view.groups
            .iter()
            .any(|group| group == "lab-lease:old-lease")
    );
}

#[tokio::test]
async fn booting_and_bootstrapping_lease_links_resume_and_commit_ready_atomically() {
    use fleet_application::lab::{AttachProvisionOutcome, LeasePort as _, NewLease};
    for state in [
        fleet_core::LeaseState::Booting,
        fleet_core::LeaseState::Bootstrapping,
    ] {
        let (_dir, store) = setup().await;
        let labs = LabRepository::new(store.pool().clone());
        let leases = fleet_storage_sqlite::LeaseRepository::new(store.pool().clone());
        let mut lease = leases
            .create(
                &NewLease {
                    template_version_id: "version-1".to_owned(),
                    purpose: String::new(),
                    project_id: None,
                    cleanup: fleet_core::CleanupStrategy::Destroy,
                    ttl_seconds: 60,
                },
                "tester",
                NOW,
            )
            .await
            .unwrap();
        let mut provision = labs
            .create(
                &NewProvision {
                    template_version_id: "version-1".to_owned(),
                    lease_id: Some(lease.id.clone()),
                    idempotency_key: None,
                },
                NOW,
            )
            .await
            .unwrap();
        leases
            .attach_provision(&lease.id, &provision.id)
            .await
            .unwrap();
        lease.provision_id = Some(provision.id.clone());
        lease.state = state;
        leases.update(&lease).await.unwrap();
        assert_eq!(
            leases
                .attach_provision(&lease.id, &provision.id)
                .await
                .unwrap(),
            AttachProvisionOutcome::AlreadyAttached
        );
        provision.state = if state == fleet_core::LeaseState::Booting {
            GuestState::Booting
        } else {
            GuestState::Bootstrapping
        };
        labs.update(&provision).await.unwrap();
        lease.mark_ready(NOW + 500).unwrap();
        provision.state = GuestState::Ready;
        provision.ready_at = lease.ready_at;
        labs.complete_ready(&provision, lease.expires_at)
            .await
            .unwrap();
        let stored = leases.get(&lease.id).await.unwrap();
        assert_eq!(stored.state, fleet_core::LeaseState::Ready);
        assert_eq!(stored.ready_at, Some(NOW + 500));
        assert_eq!(stored.expires_at, Some(NOW + 60_500));
        assert_eq!(
            labs.get(&provision.id).await.unwrap().state,
            GuestState::Ready
        );
    }
}

#[tokio::test]
async fn a_failed_project_association_write_cancels_the_durable_child() {
    let (_dir, store) = setup().await;
    let labs = LabRepository::new(store.pool().clone());
    let provision = bootstrap_record(&labs).await;
    sqlx::query("CREATE TRIGGER reject_project_link BEFORE UPDATE OF ready_project_operation_id ON lab_provisions WHEN NEW.ready_project_operation_id IS NOT NULL BEGIN SELECT RAISE(ABORT, 'test association failure'); END")
        .execute(store.pool()).await.unwrap();
    let audit = std::sync::Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone()));
    let operations = fleet_application::operation::Operations::new(
        std::sync::Arc::new(OperationRepository::new(store.pool().clone())),
        audit.clone(),
    );
    let parent = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &fleet_application::operation::NewOperation {
                kind: "noop".to_owned(),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                payload_json: None,
                review_token: None,
            },
        )
        .await
        .unwrap();
    let readiness = Readiness::default();
    let principal = fleet_application::authz::ActingPrincipal {
        id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
    };
    let bootstrap = fleet_application::lab::LabBootstrap {
        provisions: &labs,
        readiness: &readiness,
        audit: audit.as_ref(),
        authorizer: &fleet_auth::LanAllowAllAuthorizer,
        principal: &principal,
    };
    let content = fleet_core::LabTemplateContent {
        bootstrap_project_id: Some("project-1".to_owned()),
        ..fleet_core::LabTemplateContent::default()
    };
    assert_eq!(
        bootstrap
            .run(&operations, &parent.id, provision.clone(), &content)
            .await
            .unwrap_err()
            .step,
        "project_setup"
    );
    assert!(
        labs.get(&provision.id)
            .await
            .unwrap()
            .ready_project_operation_id
            .is_none()
    );
    let children = operations
        .list(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            100,
        )
        .await
        .unwrap();
    let child = children
        .iter()
        .find(|child| child.correlation_id.as_deref() == Some(&provision.id))
        .unwrap();
    assert!(
        child.cancel_requested,
        "cancelling must not depend on the failed association write"
    );
    assert_eq!(
        *readiness.calls.lock().unwrap(),
        vec!["trust", "project_create"]
    );
    let machine = labs.get(&provision.id).await.unwrap().machine_id.unwrap();
    assert_eq!(
        labs.find_by_machine_id(&machine).await.unwrap().unwrap().id,
        provision.id
    );
    assert!(
        labs.find_by_machine_id("ordinary-machine")
            .await
            .unwrap()
            .is_none()
    );
}
