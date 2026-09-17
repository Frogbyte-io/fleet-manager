//! Exercises the storage foundation against real SQLite files: migrations,
//! the singleton lock, metadata, the backup/restore procedure, and writer
//! contention. Every test uses its own temporary directory.

use std::path::Path;

use fleet_application::project::ProjectPort as _;
use fleet_storage_sqlite::{StorageError, Store};

fn db_path(dir: &Path) -> std::path::PathBuf {
    dir.join("fleet.db")
}

#[tokio::test]
async fn a_fresh_database_migrates_and_reopens_idempotently() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());

    {
        let store = Store::open(&path).await.expect("fresh database must open");
        assert_eq!(
            store.get_metadata("unset").await.unwrap(),
            None,
            "a fresh database has no metadata"
        );
    }
    {
        // Reopening applies no migrations again and keeps the metadata.
        let store = Store::open(&path).await.expect("reopen must succeed");
        store.set_metadata("probe", "kept").await.unwrap();
    }
    let store = Store::open(&path).await.unwrap();
    assert_eq!(
        store.get_metadata("probe").await.unwrap().as_deref(),
        Some("kept")
    );
}

#[tokio::test]
async fn the_connection_policy_is_wal_with_foreign_keys_on() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db_path(dir.path())).await.unwrap();

    let journal: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(journal.to_ascii_lowercase(), "wal");

    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(foreign_keys, 1);
}

#[tokio::test]
async fn a_second_controller_cannot_open_the_same_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    let _first = Store::open(&path)
        .await
        .expect("the first controller must win");

    let error = Store::open(&path).await.unwrap_err();
    assert!(matches!(error, StorageError::LockHeld { .. }), "{error}");
    assert!(error.to_string().contains("one active controller"));
}

#[tokio::test]
async fn the_lock_releases_when_the_owner_closes_so_restart_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    let first = Store::open(&path).await.unwrap();
    first.close().await;

    let second = Store::open(&path)
        .await
        .expect("a closed owner must release the lock so a restart can proceed");
    let instance: String =
        sqlx::query_scalar("SELECT instance_id FROM controller_lock WHERE id = 1")
            .fetch_one(second.pool())
            .await
            .unwrap();
    assert!(!instance.is_empty());
}

#[tokio::test]
async fn a_database_from_a_newer_build_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    {
        let store = Store::open(&path).await.unwrap();
        // Forge a migration record a future build would have written.
        sqlx::query(
            "INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) \
             VALUES (99999, 'from-the-future', CURRENT_TIMESTAMP, 1, x'00', 0)",
        )
        .execute(store.pool())
        .await
        .unwrap();
    }
    // The forged row means the real schema is behind; pretend the metadata
    // table itself exists so opening is the failing step under test.
    let error = Store::open(&path).await.unwrap_err();
    assert!(
        matches!(error, StorageError::SchemaAhead { found: 99999, .. }),
        "{error}"
    );
    assert!(error.to_string().contains("downgrades are unsupported"));
}

#[tokio::test]
async fn metadata_round_trips_and_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db_path(dir.path())).await.unwrap();
    store.set_metadata("k", "v1").await.unwrap();
    store.set_metadata("k", "v2").await.unwrap();
    assert_eq!(
        store.get_metadata("k").await.unwrap().as_deref(),
        Some("v2")
    );
}

#[tokio::test]
async fn concurrent_writers_serialize_and_preserve_every_write() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db_path(dir.path())).await.unwrap();
    sqlx::query("CREATE TABLE counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL) STRICT")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO counters (name, value) VALUES ('shared', 0)")
        .execute(store.pool())
        .await
        .unwrap();

    let store = std::sync::Arc::new(store);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let store = store.clone();
        tasks.spawn(async move {
            for _ in 0..25 {
                // The write helper takes the write lock up front; a read-then-
                // write transaction under WAL fails immediately with
                // SQLITE_BUSY_SNAPSHOT under this contention.
                let mut tx = store.begin_write().await.unwrap();
                let current: i64 =
                    sqlx::query_scalar("SELECT value FROM counters WHERE name = 'shared'")
                        .fetch_one(&mut *tx)
                        .await
                        .unwrap();
                sqlx::query("UPDATE counters SET value = ?1 WHERE name = 'shared'")
                    .bind(current + 1)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                tx.commit().await.unwrap();
            }
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.expect("a writer task must not panic");
    }

    let total: i64 = sqlx::query_scalar("SELECT value FROM counters WHERE name = 'shared'")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        total, 200,
        "every increment under busy_timeout contention must land"
    );
}

#[tokio::test]
async fn a_backup_restores_into_a_working_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(dir.path());
    let store = Store::open(&path).await.unwrap();
    store.set_metadata("valuable", "fact").await.unwrap();

    let target = dir.path().join("backup.db");
    store.backup_to(&target).await.expect("backup must succeed");

    // A backup over an existing file is refused rather than overwritten.
    let error = store.backup_to(&target).await.unwrap_err();
    assert!(matches!(error, StorageError::Backup { .. }), "{error}");

    // The restore procedure is: stop the controller, put the backup file in
    // place, start again. Simulated here by opening the backup copy directly;
    // it must be a working database with the recorded fact.
    let restored = Store::open(&target)
        .await
        .expect("a backup must open as a database");
    assert_eq!(
        restored.get_metadata("valuable").await.unwrap().as_deref(),
        Some("fact")
    );
}

#[tokio::test]
async fn the_project_repository_round_trips_identity_and_checkouts() {
    use fleet_core::CheckoutFact;

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let projects = fleet_storage_sqlite::ProjectRepository::new(store.pool().clone());

    let created = projects
        .create(&fleet_application::project::NewProject {
            remote: "github.com/Frogbyte-io/fleet-manager".to_owned(),
            name: "fleet-manager".to_owned(),
            description: String::new(),
            idempotency_key: None,
        })
        .await
        .unwrap();
    assert_eq!(created.remote, "github.com/Frogbyte-io/fleet-manager");

    // A conflicting remote is refused by the unique index.
    let conflict = projects
        .create(&fleet_application::project::NewProject {
            remote: "github.com/Frogbyte-io/fleet-manager".to_owned(),
            name: "other".to_owned(),
            description: String::new(),
            idempotency_key: None,
        })
        .await;
    assert!(conflict.is_err(), "the identity conflict is enforced");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects")
        .fetch_one(store.pool())
        .await
        .unwrap();
    eprintln!("DBG projects in db: {count}");
    let machines: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM machines")
        .fetch_one(store.pool())
        .await
        .unwrap();
    eprintln!("DBG machines in db: {machines}");
    // Checkout facts upsert per (project, machine, root). The machine FK
    // requires a real machine row.
    let machine_id = uuid::Uuid::now_v7().to_string();
    sqlx::query("INSERT INTO machines (id, name, description, created_at, updated_at) VALUES (?1, 'machine-a', '', 0, 0)")
        .bind(&machine_id)
        .execute(store.pool())
        .await
        .unwrap_or_else(|error| panic!("the machine row must insert: {error}"));
    let fact = |machine: &str, at: i64| CheckoutFact {
        project_id: created.id.clone(),
        machine_id: machine.to_owned(),
        root: "/home/dev/code/fleet-manager".to_owned(),
        branch: Some("main".to_owned()),
        dirty: Some(false),
        source: "agentless/1".to_owned(),
        observed_at: at,
    };
    projects
        .record_checkout(&fact(&machine_id, 100))
        .await
        .unwrap();
    projects
        .record_checkout(&fact(&machine_id, 200))
        .await
        .unwrap();
    let checkouts = projects.checkouts(&created.id).await.unwrap();
    assert_eq!(checkouts.len(), 1, "the fact upserted, not appended");
    assert_eq!(checkouts[0].observed_at, 200, "the newest observation wins");

    // Delete cascades to the checkouts.
    projects.delete(&created.id).await.unwrap();
    let view = projects.checkouts(&created.id).await.unwrap();
    assert!(view.is_empty(), "the checkout facts cascade");
}

#[tokio::test]
async fn the_project_list_filters_match_literals_and_ignore_stale_observations() {
    use fleet_application::project::{ProjectFilter, ProjectPort as _};
    use fleet_core::CheckoutFact;

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let projects = fleet_storage_sqlite::ProjectRepository::new(store.pool().clone());

    // A remote whose path carries LIKE metacharacters: they must match
    // literally, not as wildcards.
    let created = projects
        .create(&fleet_application::project::NewProject {
            remote: "host/team_a%b/proj_x".to_owned(),
            name: "metachars".to_owned(),
            description: String::new(),
            idempotency_key: None,
        })
        .await
        .unwrap();
    let filter = ProjectFilter {
        remote_prefix: Some("host/team_a".to_owned()),
        name_substring: None,
        after_id: None,
    };
    let listed = projects.list(&filter, 50).await.unwrap();
    assert_eq!(listed.len(), 1, "the literal prefix matches: {listed:?}");

    let wrong = ProjectFilter {
        remote_prefix: Some("host/teamXa".to_owned()),
        name_substring: None,
        after_id: None,
    };
    let listed = projects.list(&wrong, 50).await.unwrap();
    assert!(listed.is_empty(), "the _ wildcard must not match");

    // A stale observation does not replace a newer one. The checkout's
    // machine FK requires a real machine row.
    let machine_id = uuid::Uuid::now_v7().to_string();
    sqlx::query("INSERT INTO machines (id, name, description, created_at, updated_at) VALUES (?1, 'machine-a', '', 0, 0)")
        .bind(&machine_id)
        .execute(store.pool())
        .await
        .unwrap_or_else(|error| panic!("the machine row must insert: {error}"));
    let fact = |machine: &str, at: i64| CheckoutFact {
        project_id: created.id.clone(),
        machine_id: machine.to_owned(),
        root: "/home/dev/code/x".to_owned(),
        branch: Some("main".to_owned()),
        dirty: Some(false),
        source: "agentless/1".to_owned(),
        observed_at: at,
    };
    projects
        .record_checkout(&fact(&machine_id, 200))
        .await
        .unwrap();
    projects
        .record_checkout(&fact(&machine_id, 100))
        .await
        .unwrap();
    let checkouts = projects.checkouts(&created.id).await.unwrap();
    assert_eq!(checkouts[0].observed_at, 200, "the newer fact wins");
}

#[tokio::test]
async fn the_project_checkouts_cascade_when_the_machine_is_deleted() {
    use fleet_application::project::ProjectPort as _;
    use fleet_core::CheckoutFact;

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let projects = fleet_storage_sqlite::ProjectRepository::new(store.pool().clone());
    let created = projects
        .create(&fleet_application::project::NewProject {
            remote: "github.com/Frogbyte-io/fleet-manager".to_owned(),
            name: "fleet-manager".to_owned(),
            description: String::new(),
            idempotency_key: None,
        })
        .await
        .unwrap();
    let machine_id = uuid::Uuid::now_v7().to_string();
    sqlx::query("INSERT INTO machines (id, name, description, created_at, updated_at) VALUES (?1, 'gone', '', 0, 0)")
        .bind(&machine_id)
        .execute(store.pool())
        .await
        .unwrap();
    projects
        .record_checkout(&CheckoutFact {
            project_id: created.id.clone(),
            machine_id: machine_id.clone(),
            root: "/home/dev/code/fleet-manager".to_owned(),
            branch: Some("main".to_owned()),
            dirty: Some(false),
            source: "agentless/1".to_owned(),
            observed_at: 100,
        })
        .await
        .unwrap();
    assert_eq!(projects.checkouts(&created.id).await.unwrap().len(), 1);

    // Deleting the machine cascades: its checkout observations are gone.
    sqlx::query("DELETE FROM machines WHERE id = ?1")
        .bind(&machine_id)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(
        projects.checkouts(&created.id).await.unwrap().is_empty(),
        "a deleted machine has no checkouts to observe"
    );
}
