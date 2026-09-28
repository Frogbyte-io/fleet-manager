//! Authorized use cases for Fleet's authored and referenced skill catalog.
#![warn(missing_docs)]

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    audit::{AuditIntent, AuditMetadata},
    authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize},
    operation::AuditPort,
};
pub use fleet_core::{SkillCatalogContent, SkillCatalogFile, SkillCatalogSource};

/// The resource that collection-level catalog actions (list, create) are
/// authorized against: `skills.read` and `skills.modify` require a resource,
/// and without one the funnel refuses every such request.
pub const SKILL_CATALOG_RESOURCE: &str = "skill-catalog";

/// Largest catalog page returned by application use cases.
pub const MAX_SKILL_CATALOG_PAGE_SIZE: u32 = 200;

/// Mutable Fleet skill catalog draft.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillCatalogEntry {
    /// Entry identity.
    pub id: String,
    /// Current draft content.
    pub content: SkillCatalogContent,
    /// Most recently published version this draft descends from.
    pub published_from: Option<String>,
    /// Creation time in epoch milliseconds.
    pub created_at: i64,
    /// Last edit time in epoch milliseconds.
    pub updated_at: i64,
}

/// Immutable, content-addressed published skill version.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillCatalogVersion {
    /// Version identity, derived from the catalog entry and content digest.
    pub id: String,
    /// Parent entry identity.
    pub catalog_id: String,
    /// Frozen skill name.
    pub name: String,
    /// Frozen skill description.
    pub description: String,
    /// Content digest.
    pub content_digest: String,
    /// Immutable source and authored files.
    pub content: SkillCatalogContent,
    /// Publication time in epoch milliseconds.
    pub published_at: i64,
}

/// Builds the opaque continuation cursor for a catalog version page.
#[must_use]
pub fn skill_catalog_version_cursor(version: &SkillCatalogVersion) -> String {
    format!("{}|{}", version.published_at, version.id)
}

/// New catalog entry request.
#[derive(Clone, Debug)]
pub struct NewSkillCatalogEntry {
    /// Initial content.
    pub content: SkillCatalogContent,
}

/// Persistence port for drafts and immutable versions.
#[async_trait]
pub trait SkillCatalogPort: fmt::Debug + Send + Sync {
    /// Creates a draft.
    async fn create(
        &self,
        content: &SkillCatalogContent,
        now: i64,
    ) -> Result<SkillCatalogEntry, String>;
    /// Creates a draft under a caller-chosen identity (built-in entries).
    async fn create_with_id(
        &self,
        id: &str,
        content: &SkillCatalogContent,
        now: i64,
    ) -> Result<SkillCatalogEntry, String>;
    /// Reads one draft.
    async fn get(&self, id: &str) -> Result<SkillCatalogEntry, String>;
    /// Lists drafts.
    async fn list(
        &self,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Vec<SkillCatalogEntry>, String>;
    /// Replaces draft content.
    async fn update(
        &self,
        id: &str,
        content: &SkillCatalogContent,
        now: i64,
    ) -> Result<SkillCatalogEntry, String>;
    /// Publishes an immutable version, deduplicating identical content.
    async fn publish(
        &self,
        id: &str,
        version: &SkillCatalogVersion,
    ) -> Result<SkillCatalogVersion, String>;
    /// Reads a published version.
    async fn get_version(&self, id: &str) -> Result<SkillCatalogVersion, String>;
    /// Lists versions for a catalog entry.
    async fn list_versions(
        &self,
        id: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Vec<SkillCatalogVersion>, String>;
}

/// Catalog use-case error.
#[derive(Debug)]
pub enum SkillCatalogError {
    /// Authorization was denied.
    Denied(Decision),
    /// The submitted content was invalid.
    Invalid(String),
    /// Entry or version was absent.
    NotFound(String),
    /// Unique name conflict.
    Conflict(String),
    /// Persistence or audit failure.
    Backend(String),
}

impl fmt::Display for SkillCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(d) => write!(f, "denied: {d}"),
            Self::Invalid(d) => write!(f, "invalid request: {d}"),
            Self::NotFound(d) => write!(f, "not found: {d}"),
            Self::Conflict(d) => write!(f, "conflict: {d}"),
            Self::Backend(d) => write!(f, "skill catalog failed: {d}"),
        }
    }
}
impl std::error::Error for SkillCatalogError {}

/// The audit actor for changes the controller makes on its own behalf,
/// such as seeding built-in catalog entries at startup.
pub const CONTROLLER_ACTOR: &str = "system:fleet-controller";

/// Built-in entries are managed by the controller: the API may read them
/// but never edit or publish them, so a restart cannot overwrite operator
/// work and operator work cannot fork a release's skill.
fn refuse_builtin(id: &str) -> Result<(), SkillCatalogError> {
    if fleet_core::is_builtin_skill_catalog_id(id) {
        return Err(SkillCatalogError::Conflict(format!(
            "catalog entry {id} is built into the controller and changes only with a controller release"
        )));
    }
    Ok(())
}

/// What seeding one built-in entry did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuiltinSeed {
    /// The entry and its published version match this release.
    Current {
        /// The published version this release ships.
        version_id: String,
    },
    /// The entry was created or updated and this release's version published.
    Published {
        /// The newly published version.
        version_id: String,
    },
    /// The draft was brought back to this release's content, whose version
    /// was already published (for example after a controller downgrade).
    Updated {
        /// The already-published version this release ships.
        version_id: String,
    },
    /// An operator-owned entry already uses the built-in skill's name, so
    /// the built-in was not created; the operator's entry is left untouched.
    NameTaken {
        /// The conflict detail.
        detail: String,
    },
}

/// Authorized catalog actions.
#[derive(Debug)]
pub struct SkillCatalog {
    port: Arc<dyn SkillCatalogPort>,
    audit: Arc<dyn AuditPort>,
}

impl SkillCatalog {
    /// Creates the service from its ports.
    #[must_use]
    pub fn new(port: Arc<dyn SkillCatalogPort>, audit: Arc<dyn AuditPort>) -> Self {
        Self { port, audit }
    }

    /// Lists drafts after authorizing catalog read access.
    ///
    /// # Errors
    ///
    /// Returns an error when access is denied or the catalog backend fails.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Vec<SkillCatalogEntry>, SkillCatalogError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::SkillsRead,
                resource: Some(SKILL_CATALOG_RESOURCE),
            },
        )
        .map_err(SkillCatalogError::Denied)?;
        let limit = limit.clamp(1, MAX_SKILL_CATALOG_PAGE_SIZE);
        self.port
            .list(cursor, limit)
            .await
            .map_err(SkillCatalogError::Backend)
    }

    /// Reads a draft and checks entry-scoped access.
    ///
    /// # Errors
    ///
    /// Returns an error when access is denied, the entry is missing, or the backend fails.
    pub async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<SkillCatalogEntry, SkillCatalogError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::SkillsRead,
                resource: Some(id),
            },
        )
        .map_err(SkillCatalogError::Denied)?;
        self.port.get(id).await.map_err(|e| {
            if e.contains("not found") {
                SkillCatalogError::NotFound(format!("catalog entry {id}"))
            } else {
                SkillCatalogError::Backend(e)
            }
        })
    }

    /// Creates a validated catalog draft and audits the mutation first.
    ///
    /// # Errors
    ///
    /// Returns an error when access is denied, validation fails, auditing fails,
    /// the name conflicts, or the catalog backend fails.
    pub async fn create(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        content: SkillCatalogContent,
        now: i64,
    ) -> Result<SkillCatalogEntry, SkillCatalogError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::SkillsModify,
                resource: Some(SKILL_CATALOG_RESOURCE),
            },
        )
        .map_err(SkillCatalogError::Denied)?;
        content
            .validate_and_digest()
            .map_err(SkillCatalogError::Invalid)?;
        self.audit(principal, None, "skill_catalog_created").await?;
        self.port.create(&content, now).await.map_err(|e| {
            if e.contains("taken") || e.contains("UNIQUE") {
                SkillCatalogError::Conflict(e)
            } else {
                SkillCatalogError::Backend(e)
            }
        })
    }

    /// Replaces a validated mutable draft.
    ///
    /// # Errors
    ///
    /// Returns an error when access is denied, validation fails, auditing fails,
    /// the entry is missing, the name conflicts, or the catalog backend fails.
    pub async fn update(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        content: SkillCatalogContent,
        now: i64,
    ) -> Result<SkillCatalogEntry, SkillCatalogError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::SkillsModify,
                resource: Some(id),
            },
        )
        .map_err(SkillCatalogError::Denied)?;
        refuse_builtin(id)?;
        content
            .validate_and_digest()
            .map_err(SkillCatalogError::Invalid)?;
        self.audit(principal, Some(id), "skill_catalog_updated")
            .await?;
        self.port.update(id, &content, now).await.map_err(|e| {
            if e.contains("not found") {
                SkillCatalogError::NotFound(format!("catalog entry {id}"))
            } else if e.contains("taken") || e.contains("UNIQUE") {
                SkillCatalogError::Conflict(e)
            } else {
                SkillCatalogError::Backend(e)
            }
        })
    }

    /// Publishes a validated immutable content version.
    ///
    /// # Errors
    ///
    /// Returns an error when access is denied, the entry is missing, validation
    /// or auditing fails, or the catalog backend fails.
    pub async fn publish(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        now: i64,
    ) -> Result<SkillCatalogVersion, SkillCatalogError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::SkillsModify,
                resource: Some(id),
            },
        )
        .map_err(SkillCatalogError::Denied)?;
        refuse_builtin(id)?;
        let entry = self.port.get(id).await.map_err(|e| {
            if e.contains("not found") {
                SkillCatalogError::NotFound(format!("catalog entry {id}"))
            } else {
                SkillCatalogError::Backend(e)
            }
        })?;
        let digest = entry
            .content
            .validate_and_digest()
            .map_err(SkillCatalogError::Invalid)?;
        self.audit(principal, Some(id), "skill_catalog_published")
            .await?;
        let version = SkillCatalogVersion {
            id: format!("{id}@{digest}"),
            catalog_id: id.to_owned(),
            name: entry.content.name.clone(),
            description: entry.content.description.clone(),
            content_digest: digest,
            content: entry.content,
            published_at: now,
        };
        self.port
            .publish(id, &version)
            .await
            .map_err(SkillCatalogError::Backend)
    }

    /// Reads a pinned version, checking entry access first.
    ///
    /// # Errors
    ///
    /// Returns an error when the version is missing, access is denied, or the
    /// catalog backend fails.
    pub async fn get_version(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<SkillCatalogVersion, SkillCatalogError> {
        let catalog_id = id.split_once('@').map_or(id, |(catalog_id, _)| catalog_id);
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::SkillsRead,
                resource: Some(catalog_id),
            },
        )
        .map_err(SkillCatalogError::Denied)?;
        let version = self.port.get_version(id).await.map_err(|e| {
            if e.contains("not found") {
                SkillCatalogError::NotFound(format!("catalog version {id}"))
            } else {
                SkillCatalogError::Backend(e)
            }
        })?;
        Ok(version)
    }

    /// Lists versions for an entry.
    ///
    /// # Errors
    ///
    /// Returns an error when access is denied or the catalog backend fails.
    pub async fn versions(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Vec<SkillCatalogVersion>, SkillCatalogError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::SkillsRead,
                resource: Some(id),
            },
        )
        .map_err(SkillCatalogError::Denied)?;
        let limit = limit.clamp(1, MAX_SKILL_CATALOG_PAGE_SIZE);
        self.port
            .list_versions(id, cursor, limit)
            .await
            .map_err(SkillCatalogError::Backend)
    }

    /// Makes a built-in entry match the content this controller release
    /// ships: creates it under its reserved identity when missing, replaces
    /// its draft when the content changed, and publishes the release's
    /// immutable version when that version does not exist yet. Idempotent:
    /// a restart with the same release changes nothing and writes no audit
    /// event. This is the controller acting for itself at startup, not a
    /// request, so it is audited under [`CONTROLLER_ACTOR`] rather than
    /// authorized for a principal.
    ///
    /// # Errors
    ///
    /// Returns an error when the shipped content is invalid, auditing
    /// fails, or the catalog backend fails.
    pub async fn seed_builtin(
        &self,
        id: &str,
        content: SkillCatalogContent,
        now: i64,
    ) -> Result<BuiltinSeed, SkillCatalogError> {
        if !fleet_core::is_builtin_skill_catalog_id(id) {
            return Err(SkillCatalogError::Invalid(format!(
                "{id} is not a reserved built-in catalog identity"
            )));
        }
        let digest = content
            .validate_and_digest()
            .map_err(SkillCatalogError::Invalid)?;
        let system = ActingPrincipal {
            id: CONTROLLER_ACTOR.to_owned(),
        };
        let entry = match self.port.get(id).await {
            Ok(entry) => Some(entry),
            Err(e) if e.contains("not found") => None,
            Err(e) => return Err(SkillCatalogError::Backend(e)),
        };
        let mut changed = false;
        match entry {
            None => {
                self.audit(&system, Some(id), "skill_catalog_builtin_created")
                    .await?;
                if let Err(e) = self.port.create_with_id(id, &content, now).await {
                    if e.contains("taken") || e.contains("UNIQUE") {
                        return Ok(BuiltinSeed::NameTaken { detail: e });
                    }
                    return Err(SkillCatalogError::Backend(e));
                }
                changed = true;
            }
            Some(entry) if entry.content != content => {
                self.audit(&system, Some(id), "skill_catalog_builtin_updated")
                    .await?;
                self.port
                    .update(id, &content, now)
                    .await
                    .map_err(SkillCatalogError::Backend)?;
                changed = true;
            }
            Some(_) => {}
        }
        let version_id = format!("{id}@{digest}");
        let published = match self.port.get_version(&version_id).await {
            Ok(_) => false,
            Err(e) if e.contains("not found") => true,
            Err(e) => return Err(SkillCatalogError::Backend(e)),
        };
        // Publishing is idempotent by digest and also records the entry's
        // `publishedFrom`, so a changed draft whose version already exists
        // (a downgrade) is re-pointed at this release's version too.
        if published || changed {
            self.audit(&system, Some(id), "skill_catalog_builtin_published")
                .await?;
            let version = SkillCatalogVersion {
                id: version_id.clone(),
                catalog_id: id.to_owned(),
                name: content.name.clone(),
                description: content.description.clone(),
                content_digest: digest,
                content,
                published_at: now,
            };
            self.port
                .publish(id, &version)
                .await
                .map_err(SkillCatalogError::Backend)?;
        }
        Ok(if published {
            BuiltinSeed::Published { version_id }
        } else if changed {
            BuiltinSeed::Updated { version_id }
        } else {
            BuiltinSeed::Current { version_id }
        })
    }

    async fn audit(
        &self,
        principal: &ActingPrincipal,
        id: Option<&str>,
        event: &str,
    ) -> Result<(), SkillCatalogError> {
        let mut metadata = AuditMetadata::default();
        metadata
            .insert("event", event)
            .map_err(|e| SkillCatalogError::Backend(e.to_string()))?;
        self.audit
            .record_intent(&AuditIntent {
                actor: principal.id.clone(),
                action: Permission::SkillsModify.id().to_owned(),
                resource: id.map(str::to_owned),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(SkillCatalogError::Backend)
    }
}
