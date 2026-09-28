//! The built-in `fleet` skill against a real store: seeding is idempotent,
//! a new release publishes a new version, the API cannot edit or publish
//! the built-in entry, and an operator entry that owns the name is left alone.

use std::sync::Arc;

use fleet_application::authz::ActingPrincipal;
use fleet_application::skill_catalog::{BuiltinSeed, SkillCatalog, SkillCatalogError};
use fleet_controller::builtin_skills::{fleet_skill_content, seed_builtin_skills};
use fleet_storage_sqlite::Store;

const ID: &str = fleet_core::BUILTIN_FLEET_SKILL_CATALOG_ID;

fn catalog(store: &Store) -> SkillCatalog {
    SkillCatalog::new(
        Arc::new(fleet_storage_sqlite::SkillCatalogRepository::new(
            store.pool().clone(),
        )),
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    )
}

fn operator() -> ActingPrincipal {
    ActingPrincipal {
        id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
    }
}

async fn audit_count(store: &Store) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
        .fetch_one(store.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn seeding_is_idempotent_and_audited_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();

    let first = seed_builtin_skills(store.pool(), 1_000).await.unwrap();
    let BuiltinSeed::Published { version_id } = &first else {
        panic!("the first start publishes the built-in skill: {first:?}");
    };
    assert!(version_id.starts_with("builtin-fleet@"));
    let audited = audit_count(&store).await;
    assert!(audited >= 2, "creation and publication are audited");

    let second = seed_builtin_skills(store.pool(), 2_000).await.unwrap();
    assert_eq!(
        second,
        BuiltinSeed::Current {
            version_id: version_id.clone()
        }
    );
    assert_eq!(
        audit_count(&store).await,
        audited,
        "an unchanged restart writes nothing"
    );

    let entry = catalog(&store)
        .get(&fleet_auth::LanAllowAllAuthorizer, &operator(), ID)
        .await
        .unwrap();
    assert_eq!(entry.published_from.as_deref(), Some(version_id.as_str()));
}

#[tokio::test]
async fn a_new_release_publishes_a_new_version() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let catalog = catalog(&store);
    let BuiltinSeed::Published { version_id: old } = catalog
        .seed_builtin(ID, fleet_skill_content().unwrap(), 1)
        .await
        .unwrap()
    else {
        panic!("first seed publishes");
    };

    let mut next = fleet_skill_content().unwrap();
    next.files[0]
        .content
        .push_str("\n## Added in the next release\n");
    let BuiltinSeed::Published { version_id: new } =
        catalog.seed_builtin(ID, next, 2).await.unwrap()
    else {
        panic!("changed content publishes");
    };
    assert_ne!(old, new);

    // Going back to the old release re-points the entry at its version.
    let back = catalog
        .seed_builtin(ID, fleet_skill_content().unwrap(), 3)
        .await
        .unwrap();
    assert_eq!(
        back,
        BuiltinSeed::Updated {
            version_id: old.clone()
        }
    );
    let entry = catalog
        .get(&fleet_auth::LanAllowAllAuthorizer, &operator(), ID)
        .await
        .unwrap();
    assert_eq!(entry.published_from.as_deref(), Some(old.as_str()));
}

#[tokio::test]
async fn the_api_cannot_edit_or_publish_the_builtin_entry() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    seed_builtin_skills(store.pool(), 1).await.unwrap();
    let catalog = catalog(&store);
    let auth = fleet_auth::LanAllowAllAuthorizer;

    let update = catalog
        .update(&auth, &operator(), ID, fleet_skill_content().unwrap(), 2)
        .await;
    assert!(
        matches!(update, Err(SkillCatalogError::Conflict(ref detail)) if detail.contains("built into the controller"))
    );
    let publish = catalog.publish(&auth, &operator(), ID, 2).await;
    assert!(matches!(publish, Err(SkillCatalogError::Conflict(_))));
}

#[tokio::test]
async fn an_operator_entry_that_owns_the_name_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let catalog = catalog(&store);
    let mine = catalog
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            &operator(),
            fleet_skill_content().unwrap(),
            1,
        )
        .await
        .unwrap();

    let seed = seed_builtin_skills(store.pool(), 2).await.unwrap();
    assert!(matches!(seed, BuiltinSeed::NameTaken { .. }));
    let auth = fleet_auth::LanAllowAllAuthorizer;
    let still_mine = catalog.get(&auth, &operator(), &mine.id).await.unwrap();
    assert_eq!(still_mine, mine);
    assert!(matches!(
        catalog.get(&auth, &operator(), ID).await,
        Err(SkillCatalogError::NotFound(_))
    ));
    // Regression: collection-level list/create are authorized against the
    // catalog resource; they used to be refused for want of a resource.
    let entries = catalog.list(&auth, &operator(), None, 50).await.unwrap();
    assert_eq!(
        entries.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
        vec![mine.id.as_str()]
    );
}
