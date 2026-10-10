//! Issue #441: a Lab template keeps its guest OS through create, update, and
//! the published version; an existing row reads as Linux.

use fleet_application::lab::{LabTemplatePort as _, NewLabTemplate};
use fleet_core::{CleanupStrategy, GuestOs, LabTemplateContent, ReadinessProbe};
use fleet_storage_sqlite::{LabRepository, Store};

const NOW: i64 = 1_800_000_000_000;

fn content(guest_os: GuestOs) -> LabTemplateContent {
    LabTemplateContent {
        name: "os-lab".to_owned(),
        image_version_id: "image-version-1".to_owned(),
        cores: 2,
        memory_mib: 2048,
        disk_gib: 20,
        readiness_probe: ReadinessProbe::GuestAgent,
        readiness_deadline_seconds: 300,
        ttl_seconds: 3_600,
        cleanup: CleanupStrategy::Destroy,
        guest_os,
        ..LabTemplateContent::default()
    }
}

#[tokio::test]
async fn guest_os_survives_create_update_and_publish() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let labs = LabRepository::new(store.pool().clone());
    let created = labs
        .create(
            &NewLabTemplate {
                content: content(GuestOs::Windows),
            },
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(created.content.guest_os, GuestOs::Windows);
    let linux = labs
        .update(&created.id, &content(GuestOs::Linux), NOW)
        .await
        .unwrap();
    assert_eq!(linux.content.guest_os, GuestOs::Linux);
    let windows = labs
        .update(&created.id, &content(GuestOs::Windows), NOW)
        .await
        .unwrap();
    let version = labs
        .publish(
            &created.id,
            &fleet_application::lab::LabTemplateVersion {
                id: "version-1".to_owned(),
                template_id: created.id.clone(),
                name: windows.content.name.clone(),
                content: windows.content.clone(),
                image_digest: "sha256:fixture".to_owned(),
                published_by: "tester".to_owned(),
                published_at: NOW,
            },
        )
        .await
        .unwrap();
    assert_eq!(version.content.guest_os, GuestOs::Windows);
    assert_eq!(
        labs.get_version("version-1")
            .await
            .unwrap()
            .content
            .guest_os,
        GuestOs::Windows
    );
}

#[tokio::test]
async fn a_row_without_a_declared_guest_os_reads_as_linux_and_bad_values_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let labs = LabRepository::new(store.pool().clone());
    let created = labs
        .create(
            &NewLabTemplate {
                content: LabTemplateContent {
                    guest_os: GuestOs::default(),
                    ..content(GuestOs::Linux)
                },
            },
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(created.content.guest_os, GuestOs::Linux);
    // The table's CHECK keeps stored rows inside the allow-list.
    let refused = sqlx::query("UPDATE lab_templates SET guest_os = 'plan9' WHERE id = ?1")
        .bind(&created.id)
        .execute(store.pool())
        .await;
    assert!(refused.is_err());
}
