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
        storage_pool: "local-lvm".to_owned(),
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
