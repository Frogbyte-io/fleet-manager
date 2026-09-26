use fleet_application::skill_catalog::{
    SkillCatalogContent, SkillCatalogFile, SkillCatalogPort, SkillCatalogSource,
    SkillCatalogVersion,
};
use fleet_storage_sqlite::{SkillCatalogRepository, Store};

fn content(markdown: &str) -> SkillCatalogContent {
    SkillCatalogContent {
        name: "hello-world".to_owned(),
        description: "Do useful work".to_owned(),
        files: vec![SkillCatalogFile {
            path: "SKILL.md".to_owned(),
            content: markdown.to_owned(),
        }],
        source: SkillCatalogSource::Authored,
    }
}

#[tokio::test]
async fn drafts_are_mutable_and_published_versions_are_immutable_and_deduplicated() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(&directory.path().join("controller.sqlite"))
        .await
        .unwrap();
    let repository = SkillCatalogRepository::new(store.pool().clone());
    let original = content("---\nname: hello-world\ndescription: Do useful work\n---\n# Hello\n");
    let draft = repository.create(&original, 10).await.unwrap();
    let second_content = SkillCatalogContent {
        name: "second-skill".to_owned(),
        description: "Do other useful work".to_owned(),
        files: vec![SkillCatalogFile {
            path: "SKILL.md".to_owned(),
            content: "---\nname: second-skill\ndescription: Do other useful work\n---\n# Second\n"
                .to_owned(),
        }],
        source: SkillCatalogSource::Authored,
    };
    repository.create(&second_content, 11).await.unwrap();
    let first_page = repository.list(None, 1).await.unwrap();
    assert_eq!(first_page.len(), 2, "one requested row plus one look-ahead");
    let cursor = first_page[0].id.clone();
    assert_eq!(repository.list(Some(&cursor), 1).await.unwrap().len(), 1);
    let digest = original.validate_and_digest().unwrap();
    let version = SkillCatalogVersion {
        id: format!("{}@{digest}", draft.id),
        catalog_id: draft.id.clone(),
        name: original.name.clone(),
        description: original.description.clone(),
        content_digest: digest,
        content: original.clone(),
        published_at: 20,
    };
    let published = repository.publish(&draft.id, &version).await.unwrap();
    let edited = content("---\nname: hello-world\ndescription: Do useful work\n---\n# Updated\n");
    repository.update(&draft.id, &edited, 30).await.unwrap();
    assert_eq!(
        repository.get_version(&published.id).await.unwrap(),
        published
    );
    let same_digest = original.validate_and_digest().unwrap();
    let duplicate = SkillCatalogVersion {
        id: format!("{}@{same_digest}", draft.id),
        published_at: 40,
        ..version
    };
    assert_eq!(
        repository
            .publish(&draft.id, &duplicate)
            .await
            .unwrap()
            .published_at,
        20
    );
    assert_eq!(
        repository
            .list_versions(&draft.id, None, 50)
            .await
            .unwrap()
            .len(),
        1
    );
}
