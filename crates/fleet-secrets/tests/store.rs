//! Exercises the secret store against a real database and key files:
//! round-trips, redaction, tamper behavior, wrong/missing keys, and rotation.

use fleet_secrets::{SecretError, SecretStore, SecretValue};
use sqlx::{Row, SqlitePool};

const KEY_V1: &str = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0";
const KEY_V2: &str = "f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1";

async fn pool() -> SqlitePool {
    // The migrations live in fleet-storage-sqlite; this test only needs the
    // table shape, applied by the same embedded migrator.
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    fleet_storage_sqlite::MIGRATOR.run(&pool).await.unwrap();
    pool
}

fn write_key_file(dir: &Path, lines: &[&str]) -> std::path::PathBuf {
    let path = dir.join("master_key");
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

use std::path::Path;

#[tokio::test]
async fn values_round_trip_and_never_touch_the_database_in_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key_file(dir.path(), &[&format!("1 {KEY_V1}")]);
    let pool = pool().await;
    let store = SecretStore::open(pool.clone(), &key).unwrap();

    let record = store
        .create("github/token", SecretValue::from("ghp-plain-text-value"))
        .await
        .unwrap();
    let resolved = store.resolve(&record.id).await.unwrap();
    assert_eq!(resolved.expose(), b"ghp-plain-text-value");

    // Raw database inspection: no column contains the plaintext.
    let row = sqlx::query("SELECT value FROM secret_records WHERE id = ?1")
        .bind(&record.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let blob: Vec<u8> = row.get(0);
    let blob_text = blob.iter().map(|&b| b as char).collect::<String>();
    assert!(
        !blob
            .windows(b"ghp-plain-text-value".len())
            .any(|w| w == b"ghp-plain-text-value")
    );
    assert!(!blob_text.contains("ghp-plain-text-value"));
    // The envelope is identifiable and the key version is recorded.
    assert_eq!(&blob[..4], b"FSEK");
    assert_eq!(record.key_version, 1);
}

#[tokio::test]
async fn create_rejects_duplicate_names_and_update_bumps_versions() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key_file(dir.path(), &[&format!("1 {KEY_V1}")]);
    let store = SecretStore::open(pool().await, &key).unwrap();

    let record = store
        .create("provider/key", SecretValue::from("first"))
        .await
        .unwrap();
    let error = store
        .create("provider/key", SecretValue::from("second"))
        .await
        .unwrap_err();
    assert!(
        matches!(error, SecretError::DuplicateName { .. }),
        "{error}"
    );

    let updated = store
        .update(&record.id, SecretValue::from("second"))
        .await
        .unwrap();
    assert_eq!(updated.record_version, record.record_version + 1);
    assert_eq!(store.resolve(&record.id).await.unwrap().expose(), b"second");

    assert_eq!(store.list().await.unwrap().len(), 1);
    store.delete(&record.id).await.unwrap();
    let error = store.resolve(&record.id).await.unwrap_err();
    assert!(matches!(error, SecretError::NotFound { .. }));
}

#[tokio::test]
async fn a_tampered_value_fails_authentication() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key_file(dir.path(), &[&format!("1 {KEY_V1}")]);
    let pool = pool().await;
    let store = SecretStore::open(pool.clone(), &key).unwrap();
    let record = store
        .create("tamper/target", SecretValue::from("do-not-touch"))
        .await
        .unwrap();

    let blob: Vec<u8> = sqlx::query("SELECT value FROM secret_records WHERE id = ?1")
        .bind(&record.id)
        .fetch_one(&pool)
        .await
        .unwrap()
        .get(0);
    let mut tampered = blob.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    sqlx::query("UPDATE secret_records SET value = ?2 WHERE id = ?1")
        .bind(&record.id)
        .bind(&tampered)
        .execute(&pool)
        .await
        .unwrap();

    let error = store.resolve(&record.id).await.unwrap_err();
    assert!(
        matches!(error, SecretError::DecryptFailed { .. }),
        "{error}"
    );
    // The diagnostic names the record without the value.
    assert!(error.to_string().contains("tamper/target") || error.to_string().contains(&record.id));
    assert!(!error.to_string().contains("do-not-touch"));
}

#[tokio::test]
async fn a_wrong_key_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let correct = write_key_file(dir.path(), &[&format!("1 {KEY_V1}")]);
    let pool = pool().await;
    let store = SecretStore::open(pool.clone(), &correct).unwrap();
    let record = store
        .create("cross/key", SecretValue::from("secret-under-v1"))
        .await
        .unwrap();

    let wrong = write_key_file(dir.path(), &[&format!("1 {KEY_V2}")]);
    let other = SecretStore::open(pool, &wrong).unwrap();
    let error = other.resolve(&record.id).await.unwrap_err();
    assert!(
        matches!(error, SecretError::DecryptFailed { .. }),
        "{error}"
    );
}

#[tokio::test]
async fn a_missing_or_malformed_key_file_fails_closed() {
    let pool = pool().await;

    let error = SecretStore::open(pool.clone(), Path::new("/nonexistent/key")).unwrap_err();
    assert!(matches!(error, SecretError::MasterKey { .. }));

    let dir = tempfile::tempdir().unwrap();
    let short = write_key_file(dir.path(), &["1 aabb"]);
    let error = SecretStore::open(pool.clone(), &short).unwrap_err();
    assert!(matches!(error, SecretError::MasterKey { .. }));
    assert!(error.to_string().contains("bytes, expected 32"));

    let not_hex = write_key_file(dir.path(), &[&format!("1 {}", "zz".repeat(32))]);
    let error = SecretStore::open(pool.clone(), &not_hex).unwrap_err();
    assert!(matches!(error, SecretError::MasterKey { .. }));

    let empty = write_key_file(dir.path(), &["# only a comment"]);
    let error = SecretStore::open(pool.clone(), &empty).unwrap_err();
    assert!(matches!(error, SecretError::MasterKey { .. }));
    assert!(error.to_string().contains("no key material"));
}

#[tokio::test]
async fn rotation_rewraps_old_records_without_external_help() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pool().await;

    // v1 only: a record is sealed under key version 1.
    let key = write_key_file(dir.path(), &[&format!("1 {KEY_V1}")]);
    let store = SecretStore::open(pool.clone(), &key).unwrap();
    let record = store
        .create("rotate/me", SecretValue::from("value-under-v1"))
        .await
        .unwrap();
    drop(store);

    // The operator rotates: the file now carries the new current key and the
    // retained old one.
    let rotated = write_key_file(
        dir.path(),
        &[&format!("2 {KEY_V2}"), &format!("1 {KEY_V1}")],
    );
    let store = SecretStore::open(pool.clone(), &rotated).unwrap();
    assert_eq!(store.current_key_version(), 2);

    // The old record still resolves through the retained key...
    assert_eq!(
        store.resolve(&record.id).await.unwrap().expose(),
        b"value-under-v1"
    );
    // ...and rewrap moves it onto the current version.
    let rewrapped = store.rewrap().await.unwrap();
    assert_eq!(rewrapped, 1);
    let listed = &store.list().await.unwrap()[0];
    assert_eq!(listed.key_version, 2);
    assert_eq!(
        store.resolve(&record.id).await.unwrap().expose(),
        b"value-under-v1"
    );

    // Rewrap is idempotent once everything is current.
    assert_eq!(store.rewrap().await.unwrap(), 0);
}

#[tokio::test]
async fn diagnostics_never_render_key_material() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key_file(dir.path(), &[&format!("1 {KEY_V1}")]);
    let store = SecretStore::open(pool().await, &key).unwrap();
    let record = store
        .create("debug/me", SecretValue::from("must-not-render"))
        .await
        .unwrap();

    let value = store.resolve(&record.id).await.unwrap();
    assert!(!format!("{value:?}").contains("must-not-render"));

    let renderings = format!("{store:?}");
    assert!(
        renderings.contains("version: 1"),
        "key versions render: {renderings}"
    );
    assert!(
        !renderings.contains("a1a2a3a4"),
        "key material leaked: {renderings}"
    );
}
