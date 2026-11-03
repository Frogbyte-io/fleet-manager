//! FM-1121: a Lab template draft keeps its declared hardware through create,
//! update, and the published version, and a template stored before the column
//! existed reads as asking for none (migration 0068).

use fleet_application::lab::{LabTemplatePort as _, LabTemplateVersion, NewLabTemplate};
use fleet_core::{CleanupStrategy, HardwareKind, LabHardware, LabTemplateContent, ReadinessProbe};
use fleet_storage_sqlite::{LabRepository, Store};

const NOW: i64 = 1_800_000_000_000;

fn usb(mapping: &str) -> LabHardware {
    LabHardware {
        kind: HardwareKind::Usb,
        mapping: mapping.to_owned(),
    }
}

fn content(hardware: Vec<LabHardware>) -> LabTemplateContent {
    LabTemplateContent {
        name: "hardware-lab".to_owned(),
        image_version_id: "image-version-1".to_owned(),
        cores: 2,
        memory_mib: 2048,
        disk_gib: 20,
        readiness_probe: ReadinessProbe::GuestAgent,
        readiness_deadline_seconds: 300,
        ttl_seconds: 3_600,
        cleanup: CleanupStrategy::Destroy,
        hardware,
        ..LabTemplateContent::default()
    }
}

#[tokio::test]
async fn hardware_survives_create_update_and_publish() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let labs = LabRepository::new(store.pool().clone());
    let declared = vec![usb("fm-test-superdrive-a"), usb("fm-test-verbatim")];
    let created = labs
        .create(
            &NewLabTemplate {
                content: content(declared.clone()),
            },
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(created.content.hardware, declared);
    // A template with none stays none, and an update replaces the list.
    let plain = labs
        .update(&created.id, &content(Vec::new()), NOW)
        .await
        .unwrap();
    assert!(plain.content.hardware.is_empty());
    let one = vec![usb("fm-test-superdrive-b")];
    let again = labs
        .update(&created.id, &content(one.clone()), NOW)
        .await
        .unwrap();
    assert_eq!(labs.get(&created.id).await.unwrap().content.hardware, one);
    let version = labs
        .publish(
            &created.id,
            &LabTemplateVersion {
                id: "version-1".to_owned(),
                template_id: created.id.clone(),
                name: again.content.name.clone(),
                content: again.content.clone(),
                image_digest: "sha256:fixture".to_owned(),
                published_by: "tester".to_owned(),
                published_at: NOW,
            },
        )
        .await
        .unwrap();
    assert_eq!(version.content.hardware, one);
    assert_eq!(
        labs.get_version("version-1")
            .await
            .unwrap()
            .content
            .hardware,
        one
    );
    // Editing the draft afterwards never changes the frozen version.
    labs.update(&created.id, &content(Vec::new()), NOW)
        .await
        .unwrap();
    assert_eq!(
        labs.get_version("version-1")
            .await
            .unwrap()
            .content
            .hardware,
        one
    );
}

#[tokio::test]
async fn a_template_row_that_predates_the_column_reads_as_no_hardware() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let labs = LabRepository::new(store.pool().clone());
    let created = labs
        .create(
            &NewLabTemplate {
                content: content(Vec::new()),
            },
            NOW,
        )
        .await
        .unwrap();
    // The migration's default is what an existing row carries.
    let stored: String = sqlx::query_scalar("SELECT hardware FROM lab_templates WHERE id = ?1")
        .bind(&created.id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(stored, "[]");
    // The column refuses anything that is not a JSON array.
    for bad in ["{}", "not json", "\"usb\""] {
        let refused = sqlx::query("UPDATE lab_templates SET hardware = ?2 WHERE id = ?1")
            .bind(&created.id)
            .bind(bad)
            .execute(store.pool())
            .await;
        assert!(refused.is_err(), "{bad}");
    }
}
