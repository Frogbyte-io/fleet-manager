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
    /// Reads one draft.
    async fn get(&self, id: &str) -> Result<SkillCatalogEntry, String>;
    /// Lists drafts.
    async fn list(&self) -> Result<Vec<SkillCatalogEntry>, String>;
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
    async fn list_versions(&self, id: &str) -> Result<Vec<SkillCatalogVersion>, String>;
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
    ) -> Result<Vec<SkillCatalogEntry>, SkillCatalogError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::SkillsRead,
                resource: None,
            },
        )
        .map_err(SkillCatalogError::Denied)?;
        self.port.list().await.map_err(SkillCatalogError::Backend)
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
                resource: None,
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
        let version = self.port.get_version(id).await.map_err(|e| {
            if e.contains("not found") {
                SkillCatalogError::NotFound(format!("catalog version {id}"))
            } else {
                SkillCatalogError::Backend(e)
            }
        })?;
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::SkillsRead,
                resource: Some(&version.catalog_id),
            },
        )
        .map_err(SkillCatalogError::Denied)?;
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
        self.port
            .list_versions(id)
            .await
            .map_err(SkillCatalogError::Backend)
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
