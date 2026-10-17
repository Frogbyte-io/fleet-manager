//! Coolify read discovery (FM-1030): the Fleet-side types, the source and
//! observation ports, and the discovery use case.
//!
//! Coolify is the primary deploy platform. Discovery lists what its API
//! reports (servers, projects and environments, applications, services,
//! databases, recent deployments) with a read-only token. The provider
//! crate translates Coolify's responses into the types below through an
//! explicit field allow-list, so nothing Coolify may hide behind its
//! `read:sensitive` ability (environment variable values, database
//! passwords, raw Compose files, webhook secrets, deployment logs) can reach
//! Fleet, even when the token holds that ability.
//!
//! # Observations
//!
//! A run stamps every resource class with the time it was attempted. A class
//! that fails keeps the previous run's items and its previous success time
//! and records the failure, so the read view can say "these applications
//! are from yesterday because the last attempt was refused". A class is
//! `stale` when its last attempt failed or its last success is older than
//! [`OBSERVATION_STALE_AFTER_MS`]; the age is computed at read time.
//!
//! # Authorization
//!
//! Running discovery uses the account's credential and writes the cache, so
//! it needs `external_account.config` on the account and is audited before
//! and after. Reading the cached snapshot needs `external_account.read`.
#![warn(missing_docs)]

pub mod lifecycle;
pub mod settings;

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::audit::{AuditIntent, AuditMetadata};
use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::external_accounts::{
    AccountLocks, ExternalAccount, ExternalAccountError, ExternalAccountPort,
    ExternalCredentialStore,
};
use crate::operation::AuditPort;
use fleet_core::{ExternalProviderKind, SensitiveString, SystemClock};

/// How long a successful class observation stays fresh.
pub const OBSERVATION_STALE_AFTER_MS: i64 = 15 * 60 * 1000;
/// The most items kept per resource class; more is reported as partial.
pub const MAX_ITEMS_PER_CLASS: usize = 2000;

/// A Coolify server (a Docker host Coolify manages).
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyServer {
    /// Coolify's identity for the server.
    pub uuid: String,
    /// The server name.
    pub name: String,
    /// The operator's description.
    pub description: String,
    /// The address Coolify connects to.
    pub address: String,
    /// The proxy kind (`TRAEFIK`, `CADDY`, `NONE`), when set.
    pub proxy_type: Option<String>,
    /// Whether Coolify considers the server reachable, when it reports it.
    pub reachable: Option<bool>,
    /// Whether Coolify considers the server usable, when it reports it.
    pub usable: Option<bool>,
}

/// An environment of a project.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyEnvironment {
    /// Coolify's numeric environment id; applications, services, and
    /// databases refer to it.
    pub id: i64,
    /// The environment name.
    pub name: String,
    /// The operator's description.
    pub description: String,
}

/// A Coolify project with its environments.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyProject {
    /// Coolify's identity for the project.
    pub uuid: String,
    /// The project name.
    pub name: String,
    /// The operator's description.
    pub description: String,
    /// The environments. When their fetch failed, the previous run's are
    /// carried forward if known (and `details_stale` is set), else empty.
    pub environments: Vec<CoolifyEnvironment>,
    /// Whether the environments could not be refreshed by the latest run.
    #[serde(default)]
    pub details_stale: bool,
}

/// A deployed application.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyApplication {
    /// Coolify's identity for the application.
    pub uuid: String,
    /// The application name.
    pub name: String,
    /// The operator's description.
    pub description: String,
    /// Coolify's status string, such as `running:healthy`.
    pub status: String,
    /// The public hostnames and URLs, one per entry.
    pub fqdns: Vec<String>,
    /// The numeric environment id.
    pub environment_id: Option<i64>,
    /// The build pack (`nixpacks`, `dockerfile`, `dockercompose`, ...).
    pub build_pack: Option<String>,
    /// The Git repository, with any credentials removed.
    pub git_repository: Option<String>,
    /// The Git branch.
    pub git_branch: Option<String>,
    /// The deployed image reference, `name:tag`, for image applications.
    pub docker_image: Option<String>,
    /// When Coolify created it (as Coolify reports it).
    pub created_at: Option<String>,
    /// When Coolify last changed it.
    pub updated_at: Option<String>,
}

/// A one-click or Compose service.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyService {
    /// Coolify's identity for the service.
    pub uuid: String,
    /// The service name.
    pub name: String,
    /// The operator's description.
    pub description: String,
    /// Coolify's status string, when the list reports one.
    pub status: Option<String>,
    /// The one-click service type, when set.
    pub service_type: Option<String>,
    /// The numeric environment id.
    pub environment_id: Option<i64>,
    /// The public hostnames of the service's applications; carried forward
    /// from the previous run when their fetch failed (`details_stale`).
    pub fqdns: Vec<String>,
    /// Whether the hostnames could not be refreshed by the latest run.
    #[serde(default)]
    pub details_stale: bool,
    /// When Coolify created it.
    pub created_at: Option<String>,
    /// When Coolify last changed it.
    pub updated_at: Option<String>,
}

/// A managed database.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyDatabase {
    /// Coolify's identity for the database.
    pub uuid: String,
    /// The database name.
    pub name: String,
    /// The operator's description.
    pub description: String,
    /// Coolify's status string.
    pub status: String,
    /// The engine, such as `postgresql`, when Coolify or the image says.
    pub engine: Option<String>,
    /// The image reference.
    pub image: Option<String>,
    /// The numeric environment id.
    pub environment_id: Option<i64>,
    /// Whether the database is exposed on a public port.
    pub is_public: Option<bool>,
    /// The public port, when exposed.
    pub public_port: Option<i64>,
}

/// One deployment of an application.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoolifyDeployment {
    /// Coolify's identity for the deployment.
    pub deployment_uuid: String,
    /// The application's name as the deployment records it.
    pub application_name: Option<String>,
    /// The application's identity, when the listing was per application.
    pub application_uuid: Option<String>,
    /// The server's name as the deployment records it.
    pub server_name: Option<String>,
    /// `queued`, `in_progress`, `finished`, `failed`, or `cancelled`.
    pub status: String,
    /// The commit that was deployed.
    pub commit: Option<String>,
    /// The first line of the commit message, bounded and scrubbed.
    pub commit_message: Option<String>,
    /// Whether a webhook started it.
    pub is_webhook: Option<bool>,
    /// Whether the API started it.
    pub is_api: Option<bool>,
    /// The pull request number for preview deployments, `0` otherwise.
    pub pull_request_id: Option<i64>,
    /// When it was queued.
    pub created_at: Option<String>,
    /// When it last changed.
    pub updated_at: Option<String>,
}

/// The resource classes discovery reports on, in run order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceClass {
    /// Servers.
    Servers,
    /// Projects and their environments.
    Projects,
    /// Applications.
    Applications,
    /// Services.
    Services,
    /// Databases.
    Databases,
    /// Recent deployments.
    Deployments,
}

impl ResourceClass {
    /// Every class, in run order.
    pub const ALL: [Self; 6] = [
        Self::Servers,
        Self::Projects,
        Self::Applications,
        Self::Services,
        Self::Databases,
        Self::Deployments,
    ];

    /// The stable wire id.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Servers => "servers",
            Self::Projects => "projects",
            Self::Applications => "applications",
            Self::Services => "services",
            Self::Databases => "databases",
            Self::Deployments => "deployments",
        }
    }
}

/// Why a class could not be fully observed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// The token was refused, or access is disabled or IP-restricted.
    Unauthorized,
    /// The token is valid but lacks the `read` ability.
    InsufficientPermission,
    /// The route does not exist on this Coolify version.
    NotFound,
    /// The instance could not be reached, or redirected.
    Unreachable,
    /// A request or the whole run timed out.
    Timeout,
    /// Coolify answered HTTP 429, or the run's own request budget ran out.
    RateLimited,
    /// The answer was not the documented shape, or an unexpected status.
    InvalidResponse,
}

impl FailureKind {
    /// The stable wire id.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::InsufficientPermission => "insufficient_permission",
            Self::NotFound => "not_found",
            Self::Unreachable => "unreachable",
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

/// A classified, bounded, credential-free failure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassFailure {
    /// The classification.
    pub kind: FailureKind,
    /// A short explanation; never a token, URL, or response body.
    pub detail: String,
}

/// What one class run produced: all of it, some of it (with the reasons),
/// or nothing.
#[derive(Clone, Debug, PartialEq)]
pub enum ClassResult<T> {
    /// The class was listed completely.
    Complete(Vec<T>),
    /// Some items, with the reasons the rest are missing (a failed
    /// environment fetch, a truncated list).
    Partial(Vec<T>, Vec<ClassFailure>),
    /// Nothing was listed.
    Failed(ClassFailure),
}

/// What the provider returns for one run. Items are translated and
/// allow-listed; nothing here carries provider-private fields.
#[derive(Clone, Debug, PartialEq)]
pub struct RawCoolifyDiscovery {
    /// The Coolify version, when `/version` answered.
    pub version: Option<String>,
    /// Servers.
    pub servers: ClassResult<CoolifyServer>,
    /// Projects with their environments.
    pub projects: ClassResult<CoolifyProject>,
    /// Applications.
    pub applications: ClassResult<CoolifyApplication>,
    /// Services.
    pub services: ClassResult<CoolifyService>,
    /// Databases.
    pub databases: ClassResult<CoolifyDatabase>,
    /// Recent deployments.
    pub deployments: ClassResult<CoolifyDeployment>,
    /// Run-level warnings, such as a token that can read sensitive values.
    pub warnings: Vec<String>,
}

/// The discovery port. The provider crate implements it; tests implement it
/// over canned results.
#[async_trait]
pub trait CoolifySource: fmt::Debug + Send + Sync {
    /// Lists the account's resources with a read token. Never mutates,
    /// never requests `read:sensitive` values, and never returns the token.
    async fn discover(&self, base_url: &str, token: &SensitiveString) -> RawCoolifyDiscovery;
}

/// The observation of one resource class.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassObservation<T> {
    /// When the latest attempt ran (epoch millis).
    pub attempted_at: i64,
    /// When the items were last listed successfully, absent when never.
    pub observed_at: Option<i64>,
    /// The failure of the latest attempt, absent when it fully succeeded.
    pub failure: Option<ClassFailure>,
    /// Reasons the latest attempt was partial.
    pub partial: Vec<ClassFailure>,
    /// The items from the last attempt that produced any.
    pub items: Vec<T>,
    /// Whether the stored items were cut to fit the snapshot size bound.
    #[serde(default)]
    pub truncated: bool,
}

impl<T> Default for ClassObservation<T> {
    fn default() -> Self {
        Self {
            attempted_at: 0,
            observed_at: None,
            failure: None,
            partial: Vec::new(),
            items: Vec::new(),
            truncated: false,
        }
    }
}

impl<T: Clone> ClassObservation<T> {
    /// Folds one run into the previous observation: a failure keeps the
    /// previous items and success time.
    fn fold(previous: Option<&Self>, result: ClassResult<T>, now: i64) -> Self {
        match result {
            ClassResult::Complete(mut items) => {
                items.truncate(MAX_ITEMS_PER_CLASS);
                Self {
                    attempted_at: now,
                    observed_at: Some(now),
                    failure: None,
                    partial: Vec::new(),
                    items,
                    truncated: false,
                }
            }
            ClassResult::Partial(mut items, partial) => {
                items.truncate(MAX_ITEMS_PER_CLASS);
                Self {
                    attempted_at: now,
                    observed_at: Some(now),
                    failure: None,
                    partial,
                    items,
                    truncated: false,
                }
            }
            ClassResult::Failed(failure) => Self {
                attempted_at: now,
                observed_at: previous.and_then(|p| p.observed_at),
                failure: Some(failure),
                partial: Vec::new(),
                items: previous.map(|p| p.items.clone()).unwrap_or_default(),
                truncated: previous.is_some_and(|p| p.truncated),
            },
        }
    }
}

impl<T> ClassObservation<T> {
    /// Whether the items are stale at `now`: the latest attempt failed, the
    /// class was never listed, or the last success is too old.
    #[must_use]
    pub fn is_stale(&self, now: i64) -> bool {
        self.failure.is_some()
            || self
                .observed_at
                .is_none_or(|at| now.saturating_sub(at) > OBSERVATION_STALE_AFTER_MS)
    }
}

/// The stored snapshot of one account.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoolifySnapshot {
    /// The Coolify version last seen.
    pub version: Option<String>,
    /// Servers.
    pub servers: ClassObservation<CoolifyServer>,
    /// Projects.
    pub projects: ClassObservation<CoolifyProject>,
    /// Applications.
    pub applications: ClassObservation<CoolifyApplication>,
    /// Services.
    pub services: ClassObservation<CoolifyService>,
    /// Databases.
    pub databases: ClassObservation<CoolifyDatabase>,
    /// Recent deployments.
    pub deployments: ClassObservation<CoolifyDeployment>,
    /// Warnings from the latest run (for example, a token that can read
    /// sensitive values: use a read-only token).
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// The most snapshot JSON bytes kept per account before classes are cut.
pub const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;

impl CoolifySnapshot {
    /// Folds a run into the previous snapshot.
    #[must_use]
    pub fn fold(previous: Option<&Self>, raw: RawCoolifyDiscovery, now: i64) -> Self {
        let mut folded = Self {
            version: raw
                .version
                .or_else(|| previous.and_then(|p| p.version.clone())),
            servers: ClassObservation::fold(previous.map(|p| &p.servers), raw.servers, now),
            projects: ClassObservation::fold(previous.map(|p| &p.projects), raw.projects, now),
            applications: ClassObservation::fold(
                previous.map(|p| &p.applications),
                raw.applications,
                now,
            ),
            services: ClassObservation::fold(previous.map(|p| &p.services), raw.services, now),
            databases: ClassObservation::fold(previous.map(|p| &p.databases), raw.databases, now),
            deployments: ClassObservation::fold(
                previous.map(|p| &p.deployments),
                raw.deployments,
                now,
            ),
            warnings: raw.warnings,
        };
        if let Some(previous) = previous {
            folded.carry_forward_details(previous);
        }
        folded
    }

    /// Items whose follow-up request failed keep the previous run's detail
    /// (environments, hostnames), flagged `details_stale`.
    fn carry_forward_details(&mut self, previous: &Self) {
        for project in &mut self.projects.items {
            if project.details_stale
                && project.environments.is_empty()
                && let Some(old) = previous
                    .projects
                    .items
                    .iter()
                    .find(|p| p.uuid == project.uuid)
            {
                project.environments.clone_from(&old.environments);
            }
        }
        for service in &mut self.services.items {
            if service.details_stale
                && service.fqdns.is_empty()
                && let Some(old) = previous
                    .services
                    .items
                    .iter()
                    .find(|s| s.uuid == service.uuid)
            {
                service.fqdns.clone_from(&old.fqdns);
            }
        }
    }

    /// Cuts the largest classes (halving them) until the serialized
    /// snapshot fits `max_bytes`, flagging each cut class `truncated`,
    /// instead of failing the save.
    pub fn bound(&mut self, max_bytes: usize) {
        loop {
            let size = serde_json::to_vec(self).map_or(0, |bytes| bytes.len());
            if size <= max_bytes {
                return;
            }
            let counts = [
                self.servers.items.len(),
                self.projects.items.len(),
                self.applications.items.len(),
                self.services.items.len(),
                self.databases.items.len(),
                self.deployments.items.len(),
            ];
            let Some((index, count)) = counts.iter().copied().enumerate().max_by_key(|(_, n)| *n)
            else {
                return;
            };
            if count == 0 {
                return;
            }
            let keep = count / 2;
            match index {
                0 => cut(&mut self.servers, keep),
                1 => cut(&mut self.projects, keep),
                2 => cut(&mut self.applications, keep),
                3 => cut(&mut self.services, keep),
                4 => cut(&mut self.databases, keep),
                _ => cut(&mut self.deployments, keep),
            }
        }
    }

    /// The per-class summary: `(class, item count, stale, failure kind)`.
    #[must_use]
    pub fn summary(&self, now: i64) -> Vec<(ResourceClass, usize, bool, Option<FailureKind>)> {
        vec![
            (
                ResourceClass::Servers,
                self.servers.items.len(),
                self.servers.is_stale(now),
                self.servers.failure.as_ref().map(|f| f.kind),
            ),
            (
                ResourceClass::Projects,
                self.projects.items.len(),
                self.projects.is_stale(now),
                self.projects.failure.as_ref().map(|f| f.kind),
            ),
            (
                ResourceClass::Applications,
                self.applications.items.len(),
                self.applications.is_stale(now),
                self.applications.failure.as_ref().map(|f| f.kind),
            ),
            (
                ResourceClass::Services,
                self.services.items.len(),
                self.services.is_stale(now),
                self.services.failure.as_ref().map(|f| f.kind),
            ),
            (
                ResourceClass::Databases,
                self.databases.items.len(),
                self.databases.is_stale(now),
                self.databases.failure.as_ref().map(|f| f.kind),
            ),
            (
                ResourceClass::Deployments,
                self.deployments.items.len(),
                self.deployments.is_stale(now),
                self.deployments.failure.as_ref().map(|f| f.kind),
            ),
        ]
    }
}

fn cut<T>(class: &mut ClassObservation<T>, keep: usize) {
    class.items.truncate(keep);
    class.truncated = true;
}

/// A snapshot with its account and the evaluation time, as the read model
/// returns it.
#[derive(Clone, Debug, PartialEq)]
pub struct CoolifyObservation {
    /// The account the snapshot belongs to.
    pub account_id: String,
    /// The snapshot.
    pub snapshot: CoolifySnapshot,
    /// When the snapshot was last written (epoch millis).
    pub recorded_at: i64,
    /// The time staleness was evaluated against (epoch millis).
    pub evaluated_at: i64,
}

/// The observation store port.
#[async_trait]
pub trait CoolifyObservationPort: fmt::Debug + Send + Sync {
    /// Loads an account's snapshot with the time it was recorded.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn load(&self, account_id: &str) -> Result<Option<(CoolifySnapshot, i64)>, String>;
    /// Stores (replacing) an account's snapshot, only while the account is
    /// still in the state the run started from (`account_updated_at`).
    /// Returns `false`, storing nothing, when the account changed or is
    /// gone.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn save(
        &self,
        account_id: &str,
        snapshot: &CoolifySnapshot,
        recorded_at: i64,
        account_updated_at: i64,
    ) -> Result<bool, String>;
}

/// The Coolify discovery use cases.
#[derive(Debug)]
pub struct CoolifyDiscovery {
    accounts: Arc<dyn ExternalAccountPort>,
    credentials: Arc<dyn ExternalCredentialStore>,
    source: Arc<dyn CoolifySource>,
    observations: Arc<dyn CoolifyObservationPort>,
    audit: Arc<dyn AuditPort>,
}

impl CoolifyDiscovery {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn ExternalAccountPort>,
        credentials: Arc<dyn ExternalCredentialStore>,
        source: Arc<dyn CoolifySource>,
        observations: Arc<dyn CoolifyObservationPort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            accounts,
            credentials,
            source,
            observations,
            audit,
        }
    }

    fn require(
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        action: Permission,
        resource: Option<&str>,
    ) -> Result<(), ExternalAccountError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action,
                resource,
            },
        )
        .map(|_| ())
        .map_err(ExternalAccountError::Denied)
    }

    async fn coolify_account(&self, id: &str) -> Result<ExternalAccount, ExternalAccountError> {
        let account = self.accounts.get(id).await.map_err(|detail| {
            if detail.contains("not found") {
                ExternalAccountError::NotFound {
                    what: format!("account {id}"),
                }
            } else {
                ExternalAccountError::Backend {
                    context: "get",
                    detail,
                }
            }
        })?;
        if account.kind != ExternalProviderKind::Coolify {
            return Err(ExternalAccountError::Invalid {
                detail: format!("account {id} is not a Coolify account"),
            });
        }
        Ok(account)
    }

    /// Reads the endpoint and the token together under the account lock, so
    /// they always belong to the same state of the account.
    async fn resolve(&self, id: &str) -> Result<(ExternalAccount, String), ExternalAccountError> {
        let _account_lock = AccountLocks::global().lock(id).await;
        let account = self.coolify_account(id).await?;
        if account.policy_violation().is_some() {
            return Err(ExternalAccountError::Invalid {
                detail: "a Coolify base URL must use https (a loopback address is allowed); edit the account to use https"
                    .to_owned(),
            });
        }
        let token = self
            .credentials
            .load(id)
            .await
            .map_err(ExternalAccountError::Credentials)?
            .ok_or_else(|| ExternalAccountError::NoSecret {
                account: account.label.clone(),
            })?;
        Ok((account, token))
    }

    /// Runs discovery for one account and records the folded snapshot.
    ///
    /// An unreachable or refusing Coolify is not an error: every class
    /// reports its failure and the previous items stay, marked stale.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown or non-Coolify account, a missing
    /// secret, or a backend failure.
    pub async fn discover(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<CoolifyObservation, ExternalAccountError> {
        Self::require(
            authorizer,
            principal,
            Permission::ExternalAccountConfig,
            Some(id),
        )?;
        let (account, token) = self.resolve(id).await?;
        self.audit(
            principal,
            id,
            "coolify_discovering",
            &[("label", account.label.as_str())],
        )
        .await?;
        let previous = self.load(id).await?;
        let raw = self
            .source
            .discover(&account.base_url, &SensitiveString::new(token))
            .await;
        let now = SystemClock::now_unix_millis();
        let mut snapshot = CoolifySnapshot::fold(previous.as_ref().map(|(s, _)| s), raw, now);
        snapshot.bound(MAX_SNAPSHOT_BYTES);
        let saved = match self
            .observations
            .save(id, &snapshot, now, account.updated_at)
            .await
        {
            Ok(saved) => saved,
            Err(detail) => {
                // Record the failure; the detail stays out of the audit log.
                self.audit(
                    principal,
                    id,
                    "coolify_discovery_failed",
                    &[("label", account.label.as_str()), ("stage", "save")],
                )
                .await?;
                return Err(ExternalAccountError::Backend {
                    context: "coolify observations",
                    detail,
                });
            }
        };
        if !saved {
            self.audit(
                principal,
                id,
                "coolify_discovery_discarded",
                &[
                    ("label", account.label.as_str()),
                    ("reason", "account_changed"),
                ],
            )
            .await?;
            return Err(ExternalAccountError::Conflict {
                detail: "the account changed while discovery ran, so its result was discarded; run discovery again"
                    .to_owned(),
            });
        }
        let counts = snapshot
            .summary(now)
            .into_iter()
            .map(|(class, count, stale, failure)| {
                format!(
                    "{}={count}{}{}",
                    class.id(),
                    if stale { ":stale" } else { "" },
                    failure.map_or(String::new(), |kind| format!(":{}", kind.id()))
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        self.audit(
            principal,
            id,
            "coolify_discovered",
            &[("label", account.label.as_str()), ("classes", &counts)],
        )
        .await?;
        Ok(CoolifyObservation {
            account_id: id.to_owned(),
            snapshot,
            recorded_at: now,
            evaluated_at: now,
        })
    }

    /// Reads the cached snapshot of one account.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown or non-Coolify account, no discovery yet
    /// (`NotFound`), or a backend failure.
    pub async fn observation(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<CoolifyObservation, ExternalAccountError> {
        Self::require(authorizer, principal, Permission::ExternalAccountRead, None)?;
        self.coolify_account(id).await?;
        let (snapshot, recorded_at) =
            self.load(id)
                .await?
                .ok_or_else(|| ExternalAccountError::NotFound {
                    what: format!("a discovery of account {id}; run one first"),
                })?;
        Ok(CoolifyObservation {
            account_id: id.to_owned(),
            snapshot,
            recorded_at,
            evaluated_at: SystemClock::now_unix_millis(),
        })
    }

    async fn load(&self, id: &str) -> Result<Option<(CoolifySnapshot, i64)>, ExternalAccountError> {
        self.observations
            .load(id)
            .await
            .map_err(|detail| ExternalAccountError::Backend {
                context: "coolify observations",
                detail,
            })
    }

    async fn audit(
        &self,
        principal: &ActingPrincipal,
        account_id: &str,
        event: &str,
        facts: &[(&str, &str)],
    ) -> Result<(), ExternalAccountError> {
        let backend = |error: String| ExternalAccountError::Backend {
            context: "audit",
            detail: error,
        };
        let mut metadata = AuditMetadata::default();
        metadata
            .insert("event", event)
            .map_err(|error| backend(error.to_string()))?;
        for (key, value) in facts {
            metadata
                .insert(key, value)
                .map_err(|error| backend(error.to_string()))?;
        }
        self.audit
            .record_intent(&AuditIntent {
                actor: principal.id.clone(),
                action: Permission::ExternalAccountConfig.id().to_owned(),
                resource: Some(account_id.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(kind: FailureKind) -> ClassFailure {
        ClassFailure {
            kind,
            detail: "x".to_owned(),
        }
    }

    #[test]
    fn a_failed_class_keeps_the_previous_items_and_success_time() {
        let first = ClassObservation::fold(
            None,
            ClassResult::Complete(vec![CoolifyServer {
                uuid: "s1".to_owned(),
                ..CoolifyServer::default()
            }]),
            1_000,
        );
        assert!(!first.is_stale(1_000 + OBSERVATION_STALE_AFTER_MS));
        assert!(first.is_stale(1_001 + OBSERVATION_STALE_AFTER_MS));
        let second = ClassObservation::fold(
            Some(&first),
            ClassResult::Failed(failure(FailureKind::Unauthorized)),
            5_000,
        );
        assert_eq!(second.items.len(), 1);
        assert_eq!(second.observed_at, Some(1_000));
        assert_eq!(second.attempted_at, 5_000);
        assert!(second.is_stale(5_000), "a failed attempt is stale at once");
    }

    #[test]
    fn a_never_listed_class_is_stale() {
        let never: ClassObservation<CoolifyServer> = ClassObservation::fold(
            None,
            ClassResult::Failed(failure(FailureKind::Unreachable)),
            10,
        );
        assert!(never.items.is_empty() && never.observed_at.is_none());
        assert!(never.is_stale(10));
    }

    #[test]
    fn a_partial_class_counts_as_observed_and_carries_its_reasons() {
        let partial = ClassObservation::fold(
            None,
            ClassResult::Partial(
                vec![CoolifyProject::default()],
                vec![failure(FailureKind::Timeout)],
            ),
            10,
        );
        assert_eq!(partial.observed_at, Some(10));
        assert_eq!(partial.partial.len(), 1);
        assert!(!partial.is_stale(10));
    }
}
