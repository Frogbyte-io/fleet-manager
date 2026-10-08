//! The image-recipe use cases (FM-700): versioned recipes as desired-state
//! resources and the build operation over the pinned Packer CLI.
//!
//! A recipe row is always a **draft**: saving an edit of a published
//! version creates a new draft, and publishing freezes an immutable
//! version identified by its content digest — the same content published
//! twice with the same options is the same version (the audited
//! insecure-TLS opt-in, #284, is part of the digest). Builds reference an immutable version id,
//! never a mutable draft, so a build of a since-edited recipe is
//! reproducible.
//!
//! The content is stored verbatim and Fleet never re-validates Packer's
//! own syntax: `packer validate` is the authority. Build execution additionally
//! restricts provisioning to supported embedded inputs so local files cannot
//! bypass the immutable snapshot. Secrets never enter recipes — variables that would
//! carry them ride `-var-file` from secret references at build time.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::operation::AuditPort;
pub use fleet_core::{ImageBuildRecord, ImageBuildTemplate, RecipeContent, RecipeVersion};

/// A concurrent build invalidated promotion evidence at the transactional gate.
pub const PROMOTION_BUILD_REJECTED: &str =
    "promotion requires the latest matching successful build record";
/// A build cursor does not belong to the requested history.
pub const BUILD_CURSOR_INVALID: &str = "the cursor names no build in this history";

/// A bounded build-history request.
#[derive(Debug, Default)]
pub struct BuildPageRequest {
    /// Optional recipe filter.
    pub recipe: Option<String>,
    /// Optional immutable version filter.
    pub version: Option<String>,
    /// Last build identity from the preceding page.
    pub cursor: Option<String>,
    /// Requested page size; zero uses the default and values are capped at 200.
    pub limit: u32,
}

/// A page of build records in descending timestamp and identity order.
#[derive(Debug)]
pub struct BuildPage {
    /// Matching records.
    pub items: Vec<ImageBuildRecord>,
    /// Continuation identity when additional records exist.
    pub next_cursor: Option<String>,
    /// Effective page size.
    pub limit: u32,
}

/// Options for [`Images::publish_with`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublishOptions {
    /// Lets the version build with `insecure_skip_tls_verify` (#284): the
    /// token then reaches whatever answers at the recipe's address, so
    /// this is an explicit, audited exception to certificate pinning.
    pub allow_insecure_tls: bool,
}

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

/// The error `RecipePort::build_target_account` returns when several accounts
/// match the recipe's endpoint and none was requested.
pub const TARGET_ACCOUNT_AMBIGUOUS: &str = "target_account_ambiguous";

/// The recipe storage port.
#[async_trait]
pub trait RecipePort: fmt::Debug + Send + Sync {
    /// Resolves a unique target account from an explicit identity or the
    /// frozen recipe endpoint. Missing/ambiguous targets remain unbound.
    ///
    /// # Errors
    /// Fails on a repository error or an unknown explicit identity.
    async fn build_target_account(
        &self,
        _version: &RecipeVersion,
        _requested: Option<&str>,
    ) -> Result<Option<String>, String> {
        Err("build target resolution is not supported".to_owned())
    }

    /// Inserts a running build snapshot before invoking the provider.
    ///
    /// # Errors
    /// Fails on duplicate identity or storage failure.
    async fn start_build(&self, _record: &ImageBuildRecord) -> Result<(), String> {
        Err("build records are not supported by this repository".to_owned())
    }
    /// Completes a running build exactly once, preserving frozen inputs.
    ///
    /// # Errors
    /// Fails when the record is unknown, terminal or storage fails.
    async fn finish_build(&self, _record: &ImageBuildRecord) -> Result<(), String> {
        Err("build records are not supported by this repository".to_owned())
    }
    /// Reads a build by identity.
    ///
    /// # Errors
    /// Fails when unknown or storage fails.
    async fn get_build(&self, _id: &str) -> Result<ImageBuildRecord, String> {
        Err("build record not found".to_owned())
    }
    /// Lists builds newest first, optionally filtered by recipe and version.
    ///
    /// # Errors
    /// Fails on storage failure.
    async fn list_builds(
        &self,
        _recipe: Option<&str>,
        _version: Option<&str>,
    ) -> Result<Vec<ImageBuildRecord>, String> {
        Err("build records are not supported by this repository".to_owned())
    }

    /// Queries at most the requested page plus one continuation record.
    ///
    /// # Errors
    /// Fails on an invalid cursor or storage failure.
    async fn list_build_page(&self, _query: &BuildPageRequest) -> Result<BuildPage, String> {
        Err("build pagination is not supported by this repository".to_owned())
    }

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
    /// Records the promotion, demoting the recipe's other promoted
    /// version explicitly (the demotion is part of the same commit), and
    /// pins `build_id`, the build record that justified it, as the
    /// version's clone source. The backend refuses with
    /// [`PROMOTION_BUILD_REJECTED`] when that build is no longer the
    /// version's latest successful, matching record.
    ///
    /// # Errors
    ///
    /// Fails when the version is unknown, the build is rejected, or the
    /// backend errors.
    async fn promote(
        &self,
        version_id: &str,
        build_id: &str,
        promoted_by: &str,
        promoted_at: i64,
    ) -> Result<RecipeVersion, String>;
    /// The recipe's currently promoted version, when any.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn promoted_version(&self, recipe_id: &str) -> Result<Option<RecipeVersion>, String>;
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
            &[("name", new.content.name.as_str())],
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
            &[],
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
            &[],
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
    /// content digest. The same content published twice with the same
    /// options yields the same version, so publishing is idempotent by
    /// construction. The insecure-TLS opt-in is a build input: with it, the
    /// same content is a different version, whose `content_digest` (the
    /// version digest) covers the opt-in too.
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
        self.publish_with(
            authorizer,
            principal,
            recipe_id,
            now,
            PublishOptions::default(),
        )
        .await
    }

    /// Publishes a draft with explicit publication options. The only one
    /// today is the audited `insecure_skip_tls_verify` opt-in (#284): it is
    /// refused for a recipe that does not skip TLS verification, recorded
    /// on the publication's audit intent, and part of the version digest.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown recipe, a meaningless opt-in, or a
    /// backend failure.
    pub async fn publish_with(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        recipe_id: &str,
        now: i64,
        options: PublishOptions,
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
        if options.allow_insecure_tls && !fleet_core::requests_insecure_tls(&recipe.content.content)
        {
            return Err(RecipeUseCaseError::Invalid {
                detail: "the recipe does not set insecure_skip_tls_verify, so allowInsecureTls \
                         would have no effect; builds already pin the account's certificate"
                    .to_owned(),
            });
        }
        let digest = recipe
            .content
            .version_digest(options.allow_insecure_tls)
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
            storage_pool: recipe.content.storage_pool.clone().unwrap_or_default(),
            published_at: now,
            promoted_at: None,
            promoted_by: None,
            promoted_build_id: None,
            allow_insecure_tls: options.allow_insecure_tls,
        };
        let mut metadata = vec![("digest", version.content_digest.as_str())];
        if version.allow_insecure_tls {
            // The opt-in is the reviewable fact: it lands on the intent,
            // before the version exists.
            metadata.push(("allow_insecure_tls", "true"));
        }
        self.audit_event(
            principal,
            Permission::ImagesConfig,
            Some(recipe_id),
            "image_recipe_publishing",
            &metadata,
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

    /// Promotes a version only when its latest immutable build record has
    /// matching inputs and a successful output template. Evidence is loaded
    /// from the repository; callers cannot supply or forge it.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown version, a gate refusal, or a backend
    /// failure.
    pub async fn promote(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        version_id: &str,
        now: i64,
    ) -> Result<RecipeVersion, RecipeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ImagesConfig,
                resource: Some(version_id),
            },
        )
        .map_err(RecipeUseCaseError::Denied)?;
        let version = self
            .recipes
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
            })?;
        let records = self
            .recipes
            .list_build_page(&BuildPageRequest {
                version: Some(version_id.to_owned()),
                limit: 1,
                ..Default::default()
            })
            .await
            .map_err(|detail| RecipeUseCaseError::Backend {
                context: "builds",
                detail,
            })?;
        let Some(record) = records.items.first() else {
            return Err(RecipeUseCaseError::Invalid {
                detail: "the version has no build record; build it before promoting".to_owned(),
            });
        };
        if record.version_id != version_id
            || record.content_digest != version.content_digest
            || record.outcome != "succeeded"
            || record.ended_at.is_none()
            || record.template.is_none()
        {
            return Err(RecipeUseCaseError::Invalid { detail: "promotion requires the latest build record to have matching inputs and a successful template output".to_owned() });
        }
        self.audit_event(
            principal,
            Permission::ImagesConfig,
            Some(version_id),
            "image_version_promoting",
            &[
                ("digest", version.content_digest.as_str()),
                ("build", record.id.as_str()),
            ],
        )
        .await?;
        let promoted = self
            .recipes
            .promote(version_id, &record.id, &principal.id, now)
            .await
            .map_err(|detail| {
                if detail == PROMOTION_BUILD_REJECTED {
                    RecipeUseCaseError::Invalid { detail }
                } else {
                    RecipeUseCaseError::Backend {
                        context: "versions",
                        detail,
                    }
                }
            })?;
        // The completion audit follows the committed promotion: an audit
        // failure here is surfaced as a backend error naming the committed
        // promotion, never as a rollback that did not happen.
        self.audit_event(
            principal,
            Permission::ImagesConfig,
            Some(version_id),
            "image_version_promoted",
            &[
                ("digest", version.content_digest.as_str()),
                ("build", record.id.as_str()),
            ],
        )
        .await
        .map_err(|error| match error {
            RecipeUseCaseError::Backend { context, detail } => RecipeUseCaseError::Backend {
                context,
                detail: format!("the promotion committed but its audit failed: {detail}"),
            },
            other => other,
        })?;
        Ok(promoted)
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

    /// Reads build history through the centralized images.read permission.
    ///
    /// # Errors
    /// Fails on denial or storage failure.
    pub async fn list_builds(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        recipe: Option<&str>,
        version: Option<&str>,
    ) -> Result<Vec<ImageBuildRecord>, RecipeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ImagesRead,
                resource: version.or(recipe),
            },
        )
        .map_err(RecipeUseCaseError::Denied)?;
        self.recipes
            .list_builds(recipe, version)
            .await
            .map_err(|detail| RecipeUseCaseError::Backend {
                context: "builds",
                detail,
            })
    }

    /// Reads a bounded build page through centralized authorization.
    ///
    /// # Errors
    /// Fails on denial, an invalid cursor or storage failure.
    pub async fn list_build_page(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        mut query: BuildPageRequest,
    ) -> Result<BuildPage, RecipeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ImagesRead,
                resource: query.version.as_deref().or(query.recipe.as_deref()),
            },
        )
        .map_err(RecipeUseCaseError::Denied)?;
        query.limit = if query.limit == 0 {
            50
        } else {
            query.limit.min(200)
        };
        self.recipes
            .list_build_page(&query)
            .await
            .map_err(|detail| {
                if detail == BUILD_CURSOR_INVALID {
                    RecipeUseCaseError::Invalid { detail }
                } else {
                    RecipeUseCaseError::Backend {
                        context: "builds",
                        detail,
                    }
                }
            })
    }

    /// Reads one build through the centralized images.read permission.
    ///
    /// # Errors
    /// Fails on denial, missing record or storage failure.
    pub async fn get_build(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<ImageBuildRecord, RecipeUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ImagesRead,
                resource: Some(id),
            },
        )
        .map_err(RecipeUseCaseError::Denied)?;
        self.recipes.get_build(id).await.map_err(|detail| {
            if detail.contains("not found") {
                RecipeUseCaseError::NotFound {
                    what: format!("build {id}"),
                }
            } else {
                RecipeUseCaseError::Backend {
                    context: "builds",
                    detail,
                }
            }
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
        facts: &[(&str, &str)],
    ) -> Result<(), RecipeUseCaseError> {
        let mut metadata = crate::audit::AuditMetadata::default();
        metadata
            .insert("event", event)
            .map_err(|error| RecipeUseCaseError::Backend {
                context: "audit",
                detail: error.to_string(),
            })?;
        for (key, value) in facts {
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
