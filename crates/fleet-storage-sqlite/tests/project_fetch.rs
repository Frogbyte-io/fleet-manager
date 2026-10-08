//! The stored fetch form of a project's remote (#358): the migration backfills
//! existing rows as https, and the repository round-trips the form.

use fleet_application::project::{NewProject, ProjectPort as _};
use fleet_core::{FetchScheme, RemoteFetch};
use fleet_storage_sqlite::{ProjectRepository, Store};

/// The migration file under test, found by name so a renumbering at rebase
/// does not touch this test.
const MIGRATION_SUFFIX: &str = "_project_fetch_form.sql";

#[tokio::test]
async fn the_migration_backfills_existing_projects_as_https() {
    let dir = tempfile::tempdir().unwrap();
    let migrations_dir = dir.path().join("migrations");
    std::fs::create_dir(&migrations_dir).unwrap();
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut held_back = None;
    for entry in std::fs::read_dir(&source).unwrap() {
        let entry = entry.unwrap();
        if entry
            .file_name()
            .to_string_lossy()
            .ends_with(MIGRATION_SUFFIX)
        {
            held_back = Some(entry.file_name());
        } else {
            std::fs::copy(entry.path(), migrations_dir.join(entry.file_name())).unwrap();
        }
    }
    let held_back = held_back.expect("the fetch-form migration exists");
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
    sqlx::query(
        "INSERT INTO projects (id, remote, name, description, created_at, updated_at) \
         VALUES ('old', 'git.example.test/a/b', 'old', '', 1, 1)",
    )
    .execute(&pool)
    .await
    .unwrap();

    std::fs::copy(source.join(&held_back), migrations_dir.join(&held_back)).unwrap();
    sqlx::migrate::Migrator::new(migrations_dir.as_path())
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();

    let project = ProjectRepository::new(pool).get("old").await.unwrap();
    assert_eq!(project.fetch, RemoteFetch::default());
    assert_eq!(project.fetch.scheme, FetchScheme::Https);
    assert_eq!(project.fetch.user, None);
}

#[tokio::test]
async fn the_repository_round_trips_the_fetch_form() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let projects = ProjectRepository::new(store.pool().clone());
    let created = projects
        .create(&NewProject {
            remote: "git.example.test/a/b".to_owned(),
            fetch: RemoteFetch {
                scheme: FetchScheme::Scp,
                user: Some("git".to_owned()),
            },
            name: "scp".to_owned(),
            description: String::new(),
            idempotency_key: None,
        })
        .await
        .unwrap();
    let read = projects.get(&created.id).await.unwrap();
    assert_eq!(read.fetch.scheme, FetchScheme::Scp);
    assert_eq!(read.fetch.user.as_deref(), Some("git"));
}
