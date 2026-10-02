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
