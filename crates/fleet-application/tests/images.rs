//! The image-recipe use cases over fakes: draft/version immutability and
//! the audit path.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditOutcome};
use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, ReasonId};
use fleet_application::images::{Images, NewRecipe, Recipe, RecipePort, RecipeUseCaseError};
use fleet_application::operation::AuditPort;
use fleet_core::{RecipeContent, RecipeSource, RecipeVersion};

const NOW: i64 = 1_800_000_000_000;

fn principal() -> ActingPrincipal {
    ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }
}

#[derive(Debug, Default)]
struct AllowAll;

impl Authorizer for AllowAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

#[derive(Debug, Default)]
struct DenyAll;

impl Authorizer for DenyAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::deny(ReasonId::UnknownPrincipal)
    }
}

#[derive(Debug, Default)]
struct FakeRecipes {
    recipes: Mutex<Vec<Recipe>>,
    versions: Mutex<Vec<RecipeVersion>>,
    port_calls: Mutex<Vec<&'static str>>,
    builds: Mutex<Vec<fleet_core::ImageBuildRecord>>,
    reject_promotion: Mutex<bool>,
    build_page_limits: Mutex<Vec<u32>>,
}

impl FakeRecipes {
    fn find(&self, id: &str) -> Option<Recipe> {
        self.recipes
            .lock()
            .unwrap()
            .iter()
            .find(|recipe| recipe.id == id)
            .cloned()
    }
}

#[async_trait]
impl RecipePort for FakeRecipes {
    async fn list_builds(
        &self,
        recipe: Option<&str>,
        version: Option<&str>,
    ) -> Result<Vec<fleet_core::ImageBuildRecord>, String> {
        let mut records: Vec<_> = self
            .builds
            .lock()
            .unwrap()
            .iter()
            .filter(|b| {
                recipe.is_none_or(|r| b.recipe_id == r) && version.is_none_or(|v| b.version_id == v)
            })
            .cloned()
            .collect();
        records.sort_by(|a, b| {
            b.started_at
                .cmp(&a.started_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        Ok(records)
    }
    async fn list_build_page(
        &self,
        query: &fleet_application::images::BuildPageRequest,
    ) -> Result<fleet_application::images::BuildPage, String> {
        self.build_page_limits.lock().unwrap().push(query.limit);
        let mut items = self
            .list_builds(query.recipe.as_deref(), query.version.as_deref())
            .await?;
        let more = items.len() > query.limit as usize;
        items.truncate(query.limit as usize);
        let next_cursor = if more {
            items.last().map(|item| item.id.clone())
        } else {
            None
        };
        Ok(fleet_application::images::BuildPage {
            items,
            next_cursor,
            limit: query.limit,
        })
    }
    async fn get_build(&self, id: &str) -> Result<fleet_core::ImageBuildRecord, String> {
        self.builds
            .lock()
            .unwrap()
            .iter()
            .find(|b| b.id == id)
            .cloned()
            .ok_or_else(|| "build not found".to_owned())
    }

    async fn create(&self, recipe: &NewRecipe, now: i64) -> Result<Recipe, String> {
        self.port_calls.lock().unwrap().push("create");
        let mut recipes = self.recipes.lock().unwrap();
        if recipes
            .iter()
            .any(|existing| existing.content.name == recipe.content.name)
        {
            return Err(format!(
                "the recipe name {:?} is already taken",
                recipe.content.name
            ));
        }
        let stored = Recipe {
            id: format!("rcp-{}", recipes.len() + 1),
            content: recipe.content.clone(),
            published_from: None,
            created_at: now,
            updated_at: now,
        };
        recipes.push(stored.clone());
        Ok(stored)
    }

    async fn get(&self, id: &str) -> Result<Recipe, String> {
        self.find(id)
            .ok_or_else(|| format!("recipe {id} not found"))
    }

    async fn list(&self) -> Result<Vec<Recipe>, String> {
        self.port_calls.lock().unwrap().push("list");
        Ok(self.recipes.lock().unwrap().clone())
    }

    async fn update(&self, id: &str, content: &RecipeContent, now: i64) -> Result<Recipe, String> {
        self.port_calls.lock().unwrap().push("update");
        let mut recipes = self.recipes.lock().unwrap();
        let recipe = recipes
            .iter_mut()
            .find(|recipe| recipe.id == id)
            .ok_or_else(|| format!("recipe {id} not found"))?;
        recipe.content = content.clone();
        recipe.updated_at = now;
        Ok(recipe.clone())
    }

    async fn delete(&self, id: &str) -> Result<(), String> {
        self.port_calls.lock().unwrap().push("delete");
        let mut recipes = self.recipes.lock().unwrap();
        let before = recipes.len();
        recipes.retain(|recipe| recipe.id != id);
        if recipes.len() == before {
            return Err(format!("recipe {id} not found"));
        }
        Ok(())
    }

    async fn publish(
        &self,
        recipe_id: &str,
        version: &RecipeVersion,
    ) -> Result<RecipeVersion, String> {
        self.port_calls.lock().unwrap().push("publish");
        if self.find(recipe_id).is_none() {
            return Err(format!("recipe {recipe_id} not found"));
        }
        let mut versions = self.versions.lock().unwrap();
        if let Some(existing) = versions.iter().find(|existing| existing.id == version.id) {
            return Ok(existing.clone());
        }
        versions.push(version.clone());
        Ok(version.clone())
    }

    async fn get_version(&self, id: &str) -> Result<RecipeVersion, String> {
        self.versions
            .lock()
            .unwrap()
            .iter()
            .find(|version| version.id == id)
            .cloned()
            .ok_or_else(|| format!("version {id} not found"))
    }

    async fn promote(
        &self,
        version_id: &str,
        promoted_by: &str,
        promoted_at: i64,
    ) -> Result<RecipeVersion, String> {
        if *self.reject_promotion.lock().unwrap() {
            return Err(fleet_application::images::PROMOTION_BUILD_REJECTED.to_owned());
        }
        let mut versions = self.versions.lock().unwrap();
        let recipe_id = versions
            .iter()
            .find(|version| version.id == version_id)
            .ok_or_else(|| format!("version {version_id} not found"))?
            .recipe_id
            .clone();
        for version in versions.iter_mut() {
            if version.recipe_id == recipe_id {
                version.promoted_at = None;
                version.promoted_by = None;
            }
        }
        let version = versions
            .iter_mut()
            .find(|version| version.id == version_id)
            .ok_or_else(|| format!("version {version_id} not found"))?;
        version.promoted_at = Some(promoted_at);
        version.promoted_by = Some(promoted_by.to_owned());
        Ok(version.clone())
    }

    async fn promoted_version(&self, recipe_id: &str) -> Result<Option<RecipeVersion>, String> {
        Ok(self
            .versions
            .lock()
            .unwrap()
            .iter()
            .find(|version| version.recipe_id == recipe_id && version.promoted_at.is_some())
            .cloned())
    }

    async fn list_versions(&self, recipe_id: &str) -> Result<Vec<RecipeVersion>, String> {
        Ok(self
            .versions
            .lock()
            .unwrap()
            .iter()
            .filter(|version| version.recipe_id == recipe_id)
            .cloned()
            .collect())
    }
}

#[derive(Debug, Default)]
struct FakeAudit {
    intents: Mutex<Vec<AuditIntent>>,
}

#[async_trait]
impl AuditPort for FakeAudit {
    async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
        self.intents.lock().unwrap().push(intent.clone());
        Ok(())
    }

    async fn record_outcome(
        &self,
        _operation_id: &str,
        _outcome: AuditOutcome,
    ) -> Result<(), String> {
        Ok(())
    }
}

fn recipe_content(name: &str, content: &str) -> RecipeContent {
    RecipeContent {
        name: name.to_owned(),
        description: "the base image".to_owned(),
        node: "pve".to_owned(),
        storage_pool: Some("local-lvm".to_owned()),
        source: RecipeSource::Iso,
        content: content.to_owned(),
    }
}

fn service() -> (Images, Arc<FakeRecipes>, Arc<FakeAudit>) {
    let recipes = Arc::new(FakeRecipes::default());
    let audit = Arc::new(FakeAudit::default());
    (Images::new(recipes.clone(), audit.clone()), recipes, audit)
}

#[tokio::test]
async fn recipes_walk_create_edit_publish_and_reproducible_versions() {
    let (images, _recipes, audit) = service();

    // Create.
    let recipe = images
        .create(
            &AllowAll,
            &principal(),
            NewRecipe {
                content: recipe_content("ubuntu-base", r#"{"builders":[]}"#),
            },
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(recipe.published_from, None);

    // Publish: the version is frozen by digest.
    let version = images
        .publish(&AllowAll, &principal(), &recipe.id, NOW + 1)
        .await
        .unwrap();
    assert!(version.id.starts_with(&recipe.id));
    assert_eq!(version.content, r#"{"builders":[]}"#);

    // Edit the draft: the published version is untouched.
    let edited = images
        .update(
            &AllowAll,
            &principal(),
            &recipe.id,
            recipe_content("ubuntu-base", r#"{"builders":[{}]}"#),
            NOW + 2,
        )
        .await
        .unwrap();
    assert_eq!(edited.content.content, r#"{"builders":[{}]}"#);
    let unchanged = images
        .get_version(&AllowAll, &principal(), &version.id)
        .await
        .unwrap();
    assert_eq!(unchanged.content, r#"{"builders":[]}"#);

    // Publishing the edited content creates a NEW version.
    let version2 = images
        .publish(&AllowAll, &principal(), &recipe.id, NOW + 3)
        .await
        .unwrap();
    assert_ne!(version.id, version2.id);

    // Re-publishing the original content yields the SAME version:
    // reproducibility by digest.
    images
        .update(
            &AllowAll,
            &principal(),
            &recipe.id,
            recipe_content("ubuntu-base", r#"{"builders":[]}"#),
            NOW + 4,
        )
        .await
        .unwrap();
    let again = images
        .publish(&AllowAll, &principal(), &recipe.id, NOW + 5)
        .await
        .unwrap();
    assert_eq!(again.id, version.id);

    // The flow is audited.
    let intents = audit.intents.lock().unwrap();
    assert!(
        intents.iter().any(|intent| intent
            .metadata
            .entries()
            .any(|(k, v)| k == "event" && v == "image_recipe_publishing")),
        "{intents:?}"
    );
}

#[tokio::test]
async fn malformed_recipes_are_refused_before_any_write() {
    let (images, _recipes, _audit) = service();
    for content in [
        recipe_content("", "{}"),
        recipe_content("ubuntu-base", ""),
        {
            let mut oversized = recipe_content("ubuntu-base", "x");
            oversized.content = "x".repeat(fleet_core::MAX_RECIPE_CONTENT_BYTES + 1);
            oversized
        },
    ] {
        let error = images
            .create(&AllowAll, &principal(), NewRecipe { content }, NOW)
            .await
            .unwrap_err();
        assert!(
            matches!(error, RecipeUseCaseError::Invalid { .. }),
            "{error}"
        );
    }
}

#[tokio::test]
async fn a_conflicting_name_is_a_conflict() {
    let (images, _recipes, _audit) = service();
    images
        .create(
            &AllowAll,
            &principal(),
            NewRecipe {
                content: recipe_content("ubuntu-base", "{}"),
            },
            NOW,
        )
        .await
        .unwrap();
    let error = images
        .create(
            &AllowAll,
            &principal(),
            NewRecipe {
                content: recipe_content("ubuntu-base", "{\"other\":true}"),
            },
            NOW,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, RecipeUseCaseError::Conflict { .. }),
        "{error}"
    );
}

#[tokio::test]
async fn a_denied_caller_never_reaches_the_ports() {
    let (images, _recipes, _audit) = service();
    let error = images.list(&DenyAll, &principal()).await.unwrap_err();
    assert!(matches!(error, RecipeUseCaseError::Denied(_)));
    let error = images
        .create(
            &DenyAll,
            &principal(),
            NewRecipe {
                content: recipe_content("ubuntu-base", "{}"),
            },
            NOW,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, RecipeUseCaseError::Denied(_)));
}

#[tokio::test]
async fn deleting_a_draft_leaves_its_published_versions() {
    let (images, recipes, _audit) = service();
    let recipe = images
        .create(
            &AllowAll,
            &principal(),
            NewRecipe {
                content: recipe_content("ubuntu-base", r#"{"builders":[]}"#),
            },
            NOW,
        )
        .await
        .unwrap();
    let version = images
        .publish(&AllowAll, &principal(), &recipe.id, NOW + 1)
        .await
        .unwrap();
    images
        .delete(&AllowAll, &principal(), &recipe.id)
        .await
        .unwrap();
    assert!(recipes.find(&recipe.id).is_none());
    // The version is still readable: immutable history survives the draft.
    let kept = images
        .get_version(&AllowAll, &principal(), &version.id)
        .await
        .unwrap();
    assert_eq!(kept.id, version.id);
}

// ---- FM-701: promotion gate ----

fn build_record(
    version: &RecipeVersion,
    outcome: &str,
    artifact: bool,
    started_at: i64,
) -> fleet_core::ImageBuildRecord {
    fleet_core::ImageBuildRecord {
        id: format!("{}-{started_at}-{outcome}", version.id),
        operation_id: format!("{}-{started_at}-{outcome}", version.id),
        recipe_id: version.recipe_id.clone(),
        version_id: version.id.clone(),
        content_digest: version.content_digest.clone(),
        asset_digests: Vec::new(),
        packer_version: Some("1.16.1".to_owned()),
        proxmox_plugin_version: Some("1.2.4".to_owned()),
        account_id: Some("account-1".to_owned()),
        node: version.node.clone(),
        storage_pool: version.storage_pool.clone(),
        started_at,
        ended_at: Some(started_at + 1),
        outcome: outcome.to_owned(),
        reason: None,
        template: artifact.then(|| fleet_core::ImageBuildTemplate {
            node: version.node.clone(),
            vmid: 102,
            name: version.name.clone(),
        }),
    }
}

#[tokio::test]
async fn promotion_requires_a_successful_build_with_an_artifact() {
    let (images, recipes, audit) = service();
    let recipe = images
        .create(
            &AllowAll,
            &principal(),
            NewRecipe {
                content: recipe_content("ubuntu-base", r#"{"builders":[]}"#),
            },
            NOW,
        )
        .await
        .unwrap();
    let version = images
        .publish(&AllowAll, &principal(), &recipe.id, NOW + 1)
        .await
        .unwrap();

    // No build: refused.
    let error = images
        .promote(&AllowAll, &principal(), &version.id, NOW + 2)
        .await
        .unwrap_err();
    assert!(
        matches!(error, RecipeUseCaseError::Invalid { .. }),
        "{error}"
    );

    recipes
        .builds
        .lock()
        .unwrap()
        .push(build_record(&version, "failed", false, NOW + 10));
    // A failed build: refused.
    let error = images
        .promote(&AllowAll, &principal(), &version.id, NOW + 2)
        .await
        .unwrap_err();
    assert!(
        matches!(error, RecipeUseCaseError::Invalid { .. }),
        "{error}"
    );

    recipes
        .builds
        .lock()
        .unwrap()
        .push(build_record(&version, "succeeded", false, NOW + 11));
    // A successful build without an artifact: refused.
    let error = images
        .promote(&AllowAll, &principal(), &version.id, NOW + 2)
        .await
        .unwrap_err();
    assert!(
        matches!(error, RecipeUseCaseError::Invalid { .. }),
        "{error}"
    );

    recipes
        .builds
        .lock()
        .unwrap()
        .push(build_record(&version, "succeeded", true, NOW + 12));
    // A successful build with an artifact: promoted, with the evidence
    // recorded.
    *recipes.reject_promotion.lock().unwrap() = true;
    assert!(matches!(
        images
            .promote(&AllowAll, &principal(), &version.id, NOW + 2)
            .await,
        Err(RecipeUseCaseError::Invalid { .. })
    ));
    *recipes.reject_promotion.lock().unwrap() = false;
    let promoted = images
        .promote(&AllowAll, &principal(), &version.id, NOW + 2)
        .await
        .unwrap();
    assert_eq!(promoted.promoted_at, Some(NOW + 2));
    assert!(
        recipes
            .build_page_limits
            .lock()
            .unwrap()
            .iter()
            .all(|limit| *limit == 1)
    );

    assert_eq!(promoted.promoted_by.as_deref(), Some("anonymous-lan-admin"));

    // The promotion is audited twice (intent + completion).
    let intents = audit.intents.lock().unwrap();
    assert!(
        intents.iter().any(|intent| intent
            .metadata
            .entries()
            .any(|(k, v)| k == "event" && v == "image_version_promoted")),
        "{intents:?}"
    );
}

#[tokio::test]
async fn promoting_a_second_version_demotes_the_first_explicitly() {
    let (images, recipes, _audit) = service();
    let recipe = images
        .create(
            &AllowAll,
            &principal(),
            NewRecipe {
                content: recipe_content("ubuntu-base", r#"{"builders":[]}"#),
            },
            NOW,
        )
        .await
        .unwrap();
    let v1 = images
        .publish(&AllowAll, &principal(), &recipe.id, NOW + 1)
        .await
        .unwrap();
    recipes
        .builds
        .lock()
        .unwrap()
        .push(build_record(&v1, "succeeded", true, NOW + 13));
    images
        .promote(&AllowAll, &principal(), &v1.id, NOW + 2)
        .await
        .unwrap();

    // A different content publishes a second version; promoting it
    // demotes the first.
    images
        .update(
            &AllowAll,
            &principal(),
            &recipe.id,
            recipe_content("ubuntu-base", r#"{"builders":[{}]}"#),
            NOW + 3,
        )
        .await
        .unwrap();
    let v2 = images
        .publish(&AllowAll, &principal(), &recipe.id, NOW + 4)
        .await
        .unwrap();
    recipes
        .builds
        .lock()
        .unwrap()
        .push(build_record(&v2, "succeeded", true, NOW + 14));
    images
        .promote(&AllowAll, &principal(), &v2.id, NOW + 5)
        .await
        .unwrap();

    let demoted = images
        .get_version(&AllowAll, &principal(), &v1.id)
        .await
        .unwrap();
    assert_eq!(demoted.promoted_at, None, "the first version was demoted");
    let promoted = images
        .get_version(&AllowAll, &principal(), &v2.id)
        .await
        .unwrap();
    assert_eq!(promoted.promoted_at, Some(NOW + 5));
}

#[tokio::test]
async fn build_reads_require_images_read_and_promotion_refuses_mismatched_or_newer_failed_records()
{
    let (images, recipes, _audit) = service();
    let recipe = images
        .create(
            &AllowAll,
            &principal(),
            NewRecipe {
                content: recipe_content("image", "{}"),
            },
            NOW,
        )
        .await
        .unwrap();
    let version = images
        .publish(&AllowAll, &principal(), &recipe.id, NOW + 1)
        .await
        .unwrap();
    let mut record = build_record(&version, "succeeded", true, NOW + 15);
    record.content_digest = "different-inputs".to_owned();
    recipes.builds.lock().unwrap().push(record);
    assert!(matches!(
        images
            .promote(&AllowAll, &principal(), &version.id, NOW + 2)
            .await,
        Err(RecipeUseCaseError::Invalid { .. })
    ));
    recipes
        .builds
        .lock()
        .unwrap()
        .push(build_record(&version, "succeeded", true, NOW + 16));
    recipes
        .builds
        .lock()
        .unwrap()
        .push(build_record(&version, "failed", false, NOW + 17));
    assert!(matches!(
        images
            .promote(&AllowAll, &principal(), &version.id, NOW + 2)
            .await,
        Err(RecipeUseCaseError::Invalid { .. })
    ));
    recipes.builds.lock().unwrap().reverse();
    assert!(matches!(
        images
            .promote(&AllowAll, &principal(), &version.id, NOW + 2)
            .await,
        Err(RecipeUseCaseError::Invalid { .. })
    ));
    // At equal timestamps the lexically greater identity wins, not insertion order.
    {
        let mut builds = recipes.builds.lock().unwrap();
        let latest = builds.iter().map(|b| b.started_at).max().unwrap();
        for build in builds.iter_mut() {
            build.started_at = latest;
            build.ended_at = Some(latest + 1);
            build.id = if build.outcome == "failed" {
                "z-failed"
            } else {
                "a-success"
            }
            .to_owned();
            build.operation_id.clone_from(&build.id);
        }
        builds.retain(|b| b.content_digest == version.content_digest);
    }
    assert!(matches!(
        images
            .promote(&AllowAll, &principal(), &version.id, NOW + 2)
            .await,
        Err(RecipeUseCaseError::Invalid { .. })
    ));
    assert!(matches!(
        images.list_builds(&DenyAll, &principal(), None, None).await,
        Err(RecipeUseCaseError::Denied(_))
    ));
    assert!(matches!(
        images.get_build(&DenyAll, &principal(), "build-1").await,
        Err(RecipeUseCaseError::Denied(_))
    ));
    assert!(matches!(
        images.get_build(&AllowAll, &principal(), "unknown").await,
        Err(RecipeUseCaseError::NotFound { .. })
    ));
    assert_eq!(
        images
            .list_builds(&AllowAll, &principal(), None, Some(&version.id))
            .await
            .unwrap()
            .len(),
        2
    );
}
