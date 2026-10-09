//! Issue #398: a Lab template draft keeps its optional audio device through
//! create, update, and the published version.

use fleet_application::lab::{LabTemplatePort as _, NewLabTemplate};
use fleet_core::{CleanupStrategy, LabAudio, LabTemplateContent, ReadinessProbe};
use fleet_storage_sqlite::{LabRepository, Store};

const NOW: i64 = 1_800_000_000_000;

fn content(audio: Option<LabAudio>) -> LabTemplateContent {
    LabTemplateContent {
        name: "audio-lab".to_owned(),
        image_version_id: "image-version-1".to_owned(),
        cores: 2,
        memory_mib: 2048,
        disk_gib: 20,
        readiness_probe: ReadinessProbe::GuestAgent,
        readiness_deadline_seconds: 300,
        ttl_seconds: 3_600,
        cleanup: CleanupStrategy::Destroy,
        audio,
        ..LabTemplateContent::default()
    }
}

#[tokio::test]
async fn audio_survives_create_update_and_publish() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let labs = LabRepository::new(store.pool().clone());
    let audio = LabAudio {
        device: "ich9-intel-hda".to_owned(),
        driver: "none".to_owned(),
    };
    let created = labs
        .create(
            &NewLabTemplate {
                content: content(Some(audio.clone())),
            },
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(created.content.audio, Some(audio.clone()));
    // A template with none stays none.
    let plain = labs.update(&created.id, &content(None), NOW).await.unwrap();
    assert_eq!(plain.content.audio, None);
    let again = labs
        .update(&created.id, &content(Some(audio.clone())), NOW)
        .await
        .unwrap();
    assert_eq!(
        labs.get(&created.id).await.unwrap().content.audio,
        Some(audio.clone())
    );
    let version = labs
        .publish(
            &created.id,
            &fleet_application::lab::LabTemplateVersion {
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
    assert_eq!(version.content.audio, Some(audio.clone()));
    assert_eq!(
        labs.get_version("version-1").await.unwrap().content.audio,
        Some(audio)
    );
}
