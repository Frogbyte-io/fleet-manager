//! The project use cases: stable identity over mutable facts (FM-300).
//!
//! A project is registered once under its normalized remote and then observed
//! endlessly — checkouts arrive as per-machine facts from the discovery flows
//! (FM-301) and never change the identity. Every mutation funnels through the
//! authorization catalog and appends an audit intent, in that order:
//! authorize first, audit second, mutate last.
//!
//! Identity conflicts are refused, never merged: two remotes that normalize
//! identically are one repository, and the second registration is told so.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use fleet_core::{CheckoutFact, NormalizedRemote, Project, ProjectView};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::operation::PortFailure;

/// The storage contract for projects and their observed checkouts.
#[async_trait]
pub trait ProjectPort: fmt::Debug + Send + Sync {
    /// Registers a project, minting its identity.
    ///
    /// # Errors
    ///
    /// Fails when the remote or name is taken, or the backend errors.
    async fn create(&self, project: &NewProject) -> Result<Project, PortFailure>;
    /// Reads one project.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn get(&self, id: &str) -> Result<Project, PortFailure>;
    /// Lists projects, newest first, narrowed by the filter.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list(&self, filter: &ProjectFilter, limit: u32) -> Result<Vec<Project>, PortFailure>;
    /// Renames or re-describes a project.
    ///
    /// # Errors
    ///
    /// Fails when unknown, the name is taken, or the backend errors.
    async fn update(&self, id: &str, name: &str, description: &str)
    -> Result<Project, PortFailure>;
    /// Removes a project and its observed checkouts.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn delete(&self, id: &str) -> Result<(), PortFailure>;
    /// Upserts one observed checkout fact for a project.
    ///
    /// # Errors
    ///
    /// Fails when the project is unknown or the backend errors.
    async fn record_checkout(&self, fact: &CheckoutFact) -> Result<(), PortFailure>;
    /// The project carrying this caller-scoped idempotency key, when any.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn find_by_idempotency_key(&self, key: &str) -> Result<Option<Project>, PortFailure>;
    /// The project carrying this exact normalized remote, when any.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn find_by_remote(&self, remote: &str) -> Result<Option<Project>, PortFailure>;
    /// The observed checkouts of one project, newest observation first.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn checkouts(&self, project_id: &str) -> Result<Vec<CheckoutFact>, PortFailure>;
}

/// A new project, before identity minting. The remote arrives raw and is
/// normalized here — the normalized form is the stored identity.
#[derive(Clone, Debug)]
pub struct NewProject {
    /// The normalized remote (set by the use case after parsing).
    pub remote: String,
    /// The caller-scoped idempotency key, when one was supplied.
    pub idempotency_key: Option<String>,
    /// The mutable, unique display name.
    pub name: String,
    /// Operator notes.
    pub description: String,
}

/// Filters for the project list; every filter narrows, and absent filters
/// match everything.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectFilter {
    /// Only projects whose normalized remote starts with this prefix.
    pub remote_prefix: Option<String>,
    /// Only projects whose name contains this substring (case-insensitive).
    pub name_substring: Option<String>,
    /// Only projects created after this id (the opaque page cursor), so a
    /// following page really advances.
    pub after_id: Option<String>,
}

/// A use-case rejection, mapped onto public API errors by the adapter.
#[derive(Debug)]
pub enum ProjectUseCaseError {
    /// The caller may not perform the action.
    Denied(Decision),
    /// The project named does not exist.
    NotFound {
        /// What was not found.
        what: String,
    },
    /// The remote or name is taken, or malformed.
    Conflict {
        /// What conflicts.
        detail: String,
    },
    /// The request is malformed.
    Invalid {
        /// What is wrong.
        detail: String,
    },
    /// The port failed.
    Backend {
        /// Where.
        context: &'static str,
        /// The failure detail.
        detail: String,
    },
}

impl fmt::Display for ProjectUseCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Conflict { detail } => write!(f, "conflict: {detail}"),
            Self::Invalid { detail } => write!(f, "invalid request: {detail}"),
            Self::Backend { context, detail } => write!(f, "project {context} failed: {detail}"),
        }
    }
}

impl std::error::Error for ProjectUseCaseError {}

/// The authorized project use cases.
#[derive(Debug)]
pub struct Projects {
    port: Arc<dyn ProjectPort>,
    audit: Arc<dyn crate::operation::AuditPort>,
}

impl Projects {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(port: Arc<dyn ProjectPort>, audit: Arc<dyn crate::operation::AuditPort>) -> Self {
        Self { port, audit }
    }

    /// Registers a project. The remote is normalized here and the normalized
    /// form is the stored identity; a conflicting remote or name is refused.
    ///
    /// # Errors
    ///
    /// Fails on denial, a malformed or conflicting remote/name, or a backend
    /// failure.
    pub async fn register(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        new: NewProject,
        idempotency_key: Option<String>,
    ) -> Result<Project, ProjectUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProjectsCreate,
                resource: None,
            },
        )
        .map_err(ProjectUseCaseError::Denied)?;
        let remote = NormalizedRemote::parse(&new.remote)
            .map_err(|detail| ProjectUseCaseError::Invalid { detail })?;
        validate_name(&new.name)?;
        if new.description.chars().count() > 512 {
            return Err(ProjectUseCaseError::Invalid {
                detail: "the description must be at most 512 characters".to_owned(),
            });
        }

        // Idempotent replay: the same caller key returns the original
        // project instead of a conflict. The key is scoped to the caller.
        let scoped_key = idempotency_key.map(|key| format!("{}:{key}", principal.id));
        if let Some(key) = &scoped_key
            && let Some(existing) = self
                .port
                .find_by_idempotency_key(key)
                .await
                .map_err(|failure| map_port("find_by_idempotency_key", failure))?
        {
            return Ok(existing);
        }

        // The identity conflict is the interesting case: the same repository
        // under a different spelling is refused with the normalized form, so
        // the caller can see what already exists.
        match self.by_remote(&remote).await {
            Ok(Some(existing)) => {
                return Err(ProjectUseCaseError::Conflict {
                    detail: format!(
                        "the remote {raw} is already registered as {existing:?} (normalized: {remote})",
                        raw = new.remote,
                        existing = existing.name,
                    ),
                });
            }
            Ok(None) => {}
            Err(failure) => return Err(map_port("find_by_remote", failure)),
        }

        // The audit intent lands BEFORE the mutation: a failure to audit
        // prevents the mutation, so durable state can never exist without
        // its intent. The minted id is not known yet; the remote carries the
        // correlation.
        self.audit_project(
            principal,
            Permission::ProjectsCreate,
            remote.as_str(),
            Some(("remote", remote.as_str())),
        )
        .await?;
        let stored = NewProject {
            remote: remote.as_str().to_owned(),
            name: new.name.clone(),
            description: new.description.clone(),
            idempotency_key: scoped_key,
        };
        let project = self
            .port
            .create(&stored)
            .await
            .map_err(|failure| map_port("create", failure))?;
        Ok(project)
    }

    /// Reads one project as the read model: the record plus its observed
    /// checkouts.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown project, or a backend failure.
    pub async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<ProjectView, ProjectUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProjectsRead,
                resource: Some(id),
            },
        )
        .map_err(ProjectUseCaseError::Denied)?;
        let project = self
            .port
            .get(id)
            .await
            .map_err(|failure| map_port("get", failure))?;
        let checkouts = self
            .port
            .checkouts(id)
            .await
            .map_err(|failure| map_port("checkouts", failure))?;
        Ok(assemble_view(project, checkouts))
    }

    /// Lists projects, newest first, narrowed by the filter. The read model's
    /// checkouts are not hydrated per project in the list: the detail view
    /// carries them.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        filter: &ProjectFilter,
        limit: u32,
    ) -> Result<Vec<Project>, ProjectUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProjectsRead,
                resource: None,
            },
        )
        .map_err(ProjectUseCaseError::Denied)?;
        let projects = self
            .port
            .list(filter, limit)
            .await
            .map_err(|failure| map_port("list", failure))?;
        Ok(projects)
    }

    /// Renames or re-describes a project.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown project, a taken name, or a backend
    /// failure.
    pub async fn update(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        name: &str,
        description: &str,
    ) -> Result<Project, ProjectUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProjectsUpdate,
                resource: Some(id),
            },
        )
        .map_err(ProjectUseCaseError::Denied)?;
        validate_name(name)?;
        if description.chars().count() > 512 {
            return Err(ProjectUseCaseError::Invalid {
                detail: "the description must be at most 512 characters".to_owned(),
            });
        }
        self.audit_project(principal, Permission::ProjectsUpdate, id, None)
            .await?;
        let project = self
            .port
            .update(id, name, description)
            .await
            .map_err(|failure| map_port("update", failure))?;
        Ok(project)
    }

    /// Removes a project and its observed checkouts. The Git repository
    /// itself, and every checkout on every machine, is untouched: Fleet
    /// forgets a project, it does not delete code.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown project, or a backend failure.
    pub async fn delete(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<(), ProjectUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProjectsDelete,
                resource: Some(id),
            },
        )
        .map_err(ProjectUseCaseError::Denied)?;
        self.audit_project(principal, Permission::ProjectsDelete, id, None)
            .await?;
        self.port
            .delete(id)
            .await
            .map_err(|failure| map_port("delete", failure))?;
        Ok(())
    }

    /// Records one observed checkout fact. Observations are recorded data,
    /// not mutations a caller directs; the authorization is projects-update
    /// because the facts change, but no audit intent is appended — the
    /// observation is the record.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown project, a malformed fact, or a backend
    /// failure.
    pub async fn record_checkout(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        fact: CheckoutFact,
    ) -> Result<(), ProjectUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ProjectsUpdate,
                resource: Some(fact.project_id.as_str()),
            },
        )
        .map_err(ProjectUseCaseError::Denied)?;
        fact.validate()
            .map_err(|detail| ProjectUseCaseError::Invalid { detail })?;
        self.port
            .record_checkout(&fact)
            .await
            .map_err(|failure| map_port("record_checkout", failure))
    }

    async fn by_remote(&self, remote: &NormalizedRemote) -> Result<Option<Project>, PortFailure> {
        // The exact normalized remote, without a prefix-page limit: the
        // identity conflict must be found wherever it sits in the list.
        self.port.find_by_remote(remote.as_str()).await
    }

    async fn audit_project(
        &self,
        principal: &ActingPrincipal,
        action: Permission,
        project_id: &str,
        fact: Option<(&str, &str)>,
    ) -> Result<(), ProjectUseCaseError> {
        let mut metadata = crate::audit::AuditMetadata::default();
        metadata
            .insert("event", "project_mutation")
            .map_err(|error| ProjectUseCaseError::Backend {
                context: "audit",
                detail: error.to_string(),
            })?;
        if let Some((key, value)) = fact {
            metadata
                .insert(key, value)
                .map_err(|error| ProjectUseCaseError::Backend {
                    context: "audit",
                    detail: error.to_string(),
                })?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: action.id().to_owned(),
                resource: Some(project_id.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| ProjectUseCaseError::Backend {
                context: "audit",
                detail,
            })
    }
}

/// Assembles the read model: the record plus its observed checkouts, newest
/// observation first.
#[must_use]
pub fn assemble_view(project: Project, mut checkouts: Vec<CheckoutFact>) -> ProjectView {
    checkouts.sort_by_key(|fact| std::cmp::Reverse(fact.observed_at));
    ProjectView {
        id: project.id,
        remote: project.remote,
        name: project.name,
        description: project.description,
        checkouts,
        created_at: project.created_at,
        updated_at: project.updated_at,
    }
}

fn validate_name(name: &str) -> Result<(), ProjectUseCaseError> {
    if name.is_empty() || name.chars().count() > 128 {
        return Err(ProjectUseCaseError::Invalid {
            detail: "the project name must be 1..=128 characters".to_owned(),
        });
    }
    Ok(())
}

fn map_port(context: &'static str, failure: PortFailure) -> ProjectUseCaseError {
    match failure {
        PortFailure::NotFound { what } => ProjectUseCaseError::NotFound { what },
        PortFailure::Conflict { detail } => ProjectUseCaseError::Conflict { detail },
        PortFailure::Backend { detail } => ProjectUseCaseError::Backend { context, detail },
    }
}
