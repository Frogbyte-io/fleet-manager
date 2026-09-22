//! The image-recipe use cases (FM-700): versioned recipes as desired-state
//! resources and the build operation over the pinned Packer CLI.
//!
//! A recipe row is always a **draft**: saving an edit of a published
//! version creates a new draft, and publishing freezes an immutable
//! version identified by its content digest — the same content published
//! twice is the same version. Builds reference an immutable version id,
//! never a mutable draft, so a build of a since-edited recipe is
//! reproducible.
//!
//! The content is stored verbatim and Fleet never re-validates Packer's
//! own fields: `packer validate` is the authority, and unknown fields pass
//! through untouched. Secrets never enter recipes — variables that would
//! carry them ride `-var-file` from secret references at build time.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::operation::AuditPort;
pub use fleet_core::{RecipeContent, RecipeVersion};

/// A stored recipe draft.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipe {
    /// The draft's identity.
    pub id: String,
    /// The recipe content.
    pub content: RecipeContent,
    /// The published version this draft descends from, when any.
    pub published_from: Option<String>,
    /// When the draft was created (epoch millis).
    pub created_at: i64,
    /// When the draft was last edited (epoch millis).
    pub updated_at: i64,
}

/// A creation or edit request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewRecipe {
    /// The recipe content.
    pub content: RecipeContent,
}

/// The recipe storage port.
#[async_trait]
pub trait RecipePort: fmt::Debug + Send + Sync {
    /// Creates a draft, minting its identity.
    ///
    /// # Errors
    ///
    /// Fails when the name is taken or the backend errors.
    async fn create(&self, recipe: &NewRecipe, now: i64) -> Result<Recipe, String>;
    /// Reads one draft.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn get(&self, id: &str) -> Result<Recipe, String>;
    /// Lists drafts, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list(&self) -> Result<Vec<Recipe>, String>;
    /// Replaces a draft's content.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn update(&self, id: &str, content: &RecipeContent, now: i64) -> Result<Recipe, String>;
    /// Removes a draft.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn delete(&self, id: &str) -> Result<(), String>;
    /// Publishes a draft: freezes an immutable version. The same content
    /// published twice yields the same version.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn publish(
        &self,
        recipe_id: &str,
        version: &RecipeVersion,
    ) -> Result<RecipeVersion, String>;
    /// Reads one published version.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn get_version(&self, id: &str) -> Result<RecipeVersion, String>;
    /// Lists a recipe's published versions, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list_versions(&self, recipe_id: &str) -> Result<Vec<RecipeVersion>, String>;
}

/// A use-case rejection, mapped onto public API errors by the adapter.
#[derive(Debug)]
pub enum RecipeUseCaseError {
    /// The caller may not perform the action.
    Denied(Decision),
    /// The request is malformed.
    Invalid {
        /// What is wrong.
        detail: String,
    },
    /// The addressed recipe or version does not exist.
    NotFound {
        /// What was not found.
        what: String,
    },
    /// The recipe name is taken.
    Conflict {
        /// The conflict detail.
        detail: String,
    },
    /// A port failed.
    Backend {
        /// Where.
        context: &'static str,
        /// The failure detail.
        detail: String,
    },
}

impl fmt::Display for RecipeUseCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::Invalid { detail } => write!(f, "invalid request: {detail}"),
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Conflict { detail } => write!(f, "conflict: {detail}"),
            Self::Backend { context, detail } => {
                write!(f, "images {context} failed: {detail}")
            }
        }
    }
}

impl std::error::Error for RecipeUseCaseError {}

/// The image-recipe use cases.
#[derive(Debug)]
pub struct Images {
    recipes: Arc<dyn RecipePort>,
    audit: Arc<dyn AuditPort>,
}

impl Images {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(recipes: Arc<dyn RecipePort>, audit: Arc<dyn AuditPort>) -> Self {
        Self { recipes, audit }
    }

    /// Lists the recipe drafts.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<Vec<Recipe>, RecipeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ImagesRead,
                resource: None,
            },
        )
        .map_err(RecipeUseCaseError::Denied)?;
        self.recipes
            .list()
            .await
            .map_err(|detail| RecipeUseCaseError::Backend {
                context: "recipes",
                detail,
            })
    }

    /// Creates a recipe draft. The audit intent lands before any mutation.
    ///
    /// # Errors
    ///
    /// Fails on denial, a malformed request, a name conflict, or a backend
    /// failure.
    pub async fn create(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        new: NewRecipe,
        now: i64,
    ) -> Result<Recipe, RecipeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ImagesConfig,
                resource: None,
            },
        )
        .map_err(RecipeUseCaseError::Denied)?;
        new.content
            .validate()
            .map_err(|detail| RecipeUseCaseError::Invalid { detail })?;
        self.audit_event(
            principal,
            Permission::ImagesConfig,
            None,
            "image_recipe_creating",
            Some(("name", new.content.name.as_str())),
        )
        .await?;
        self.recipes.create(&new, now).await.map_err(|detail| {
            if detail.contains("taken") || detail.contains("UNIQUE") {
                RecipeUseCaseError::Conflict { detail }
            } else {
                RecipeUseCaseError::Backend {
                    context: "recipes",
                    detail,
                }
            }
        })
    }

    /// Reads one draft.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown recipe, or a backend failure.
    pub async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<Recipe, RecipeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ImagesRead,
                resource: Some(id),
            },
        )
        .map_err(RecipeUseCaseError::Denied)?;
        self.require_recipe(id).await
    }

    /// Replaces a draft's content. The draft stays a draft; publishing is
    /// the explicit act.
    ///
    /// # Errors
    ///
    /// Fails on denial, a malformed request, an unknown recipe, or a
    /// backend failure.
    pub async fn update(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        content: RecipeContent,
        now: i64,
    ) -> Result<Recipe, RecipeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ImagesConfig,
                resource: Some(id),
            },
        )
        .map_err(RecipeUseCaseError::Denied)?;
        content
            .validate()
            .map_err(|detail| RecipeUseCaseError::Invalid { detail })?;
        self.audit_event(
            principal,
            Permission::ImagesConfig,
            Some(id),
            "image_recipe_updating",
            None,
        )
        .await?;
        self.recipes
            .update(id, &content, now)
            .await
            .map_err(|detail| {
                if detail.contains("not found") {
                    RecipeUseCaseError::NotFound {
                        what: format!("recipe {id}"),
                    }
                } else if detail.contains("taken") || detail.contains("UNIQUE") {
                    RecipeUseCaseError::Conflict { detail }
                } else {
                    RecipeUseCaseError::Backend {
                        context: "recipes",
                        detail,
                    }
                }
            })
    }

    /// Removes a draft. Published versions are immutable and stay.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown recipe, or a backend failure.
    pub async fn delete(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<(), RecipeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ImagesConfig,
                resource: Some(id),
            },
        )
        .map_err(RecipeUseCaseError::Denied)?;
        self.audit_event(
            principal,
            Permission::ImagesConfig,
            Some(id),
            "image_recipe_deleting",
            None,
        )
        .await?;
        self.recipes.delete(id).await.map_err(|detail| {
            if detail.contains("not found") {
                RecipeUseCaseError::NotFound {
                    what: format!("recipe {id}"),
                }
            } else {
                RecipeUseCaseError::Backend {
                    context: "recipes",
                    detail,
                }
            }
        })
    }

    /// Publishes a draft: freezes an immutable version identified by its
    /// content digest. The same content published twice yields the same
    /// version, so publishing is idempotent by construction.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown recipe, or a backend failure.
    pub async fn publish(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        recipe_id: &str,
        now: i64,
    ) -> Result<RecipeVersion, RecipeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ImagesConfig,
                resource: Some(recipe_id),
            },
        )
        .map_err(RecipeUseCaseError::Denied)?;
        let recipe = self.require_recipe(recipe_id).await?;
        let digest = recipe
            .content
            .content_digest()
            .map_err(|detail| RecipeUseCaseError::Invalid { detail })?;
        let version = RecipeVersion {
            id: format!("{}@{}", recipe.id, &digest[..16]),
            recipe_id: recipe.id.clone(),
            name: recipe.content.name.clone(),
            description: recipe.content.description.clone(),
            content_digest: digest,
            content: recipe.content.content.clone(),
            source: recipe.content.source,
            node: recipe.content.node.clone(),
            storage_pool: recipe.content.storage_pool.clone(),
            published_at: now,
        };
        self.audit_event(
            principal,
            Permission::ImagesConfig,
            Some(recipe_id),
            "image_recipe_publishing",
            Some(("digest", version.content_digest.as_str())),
        )
        .await?;
        self.recipes
            .publish(recipe_id, &version)
            .await
            .map_err(|detail| RecipeUseCaseError::Backend {
                context: "versions",
                detail,
            })
    }

    /// Reads one published version.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown version, or a backend failure.
    pub async fn get_version(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        version_id: &str,
    ) -> Result<RecipeVersion, RecipeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ImagesRead,
                resource: Some(version_id),
            },
        )
        .map_err(RecipeUseCaseError::Denied)?;
        self.recipes
            .get_version(version_id)
            .await
            .map_err(|detail| {
                if detail.contains("not found") {
                    RecipeUseCaseError::NotFound {
                        what: format!("version {version_id}"),
                    }
                } else {
                    RecipeUseCaseError::Backend {
                        context: "versions",
                        detail,
                    }
                }
            })
    }

    /// Lists a recipe's published versions.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown recipe, or a backend failure.
    pub async fn list_versions(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        recipe_id: &str,
    ) -> Result<Vec<RecipeVersion>, RecipeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ImagesRead,
                resource: Some(recipe_id),
            },
        )
        .map_err(RecipeUseCaseError::Denied)?;
        self.recipes
            .list_versions(recipe_id)
            .await
            .map_err(|detail| RecipeUseCaseError::Backend {
                context: "versions",
                detail,
            })
    }

    async fn require_recipe(&self, id: &str) -> Result<Recipe, RecipeUseCaseError> {
        self.recipes.get(id).await.map_err(|detail| {
            if detail.contains("not found") {
                RecipeUseCaseError::NotFound {
                    what: format!("recipe {id}"),
                }
            } else {
                RecipeUseCaseError::Backend {
                    context: "recipes",
                    detail,
                }
            }
        })
    }

    async fn audit_event(
        &self,
        principal: &ActingPrincipal,
        action: Permission,
        recipe_id: Option<&str>,
        event: &str,
        fact: Option<(&str, &str)>,
    ) -> Result<(), RecipeUseCaseError> {
        let mut metadata = crate::audit::AuditMetadata::default();
        metadata
            .insert("event", event)
            .map_err(|error| RecipeUseCaseError::Backend {
                context: "audit",
                detail: error.to_string(),
            })?;
        if let Some((key, value)) = fact {
            metadata
                .insert(key, value)
                .map_err(|error| RecipeUseCaseError::Backend {
                    context: "audit",
                    detail: error.to_string(),
                })?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: action.id().to_owned(),
                resource: recipe_id.map(str::to_owned),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| RecipeUseCaseError::Backend {
                context: "audit",
                detail,
            })
    }
}
