//! Site templates: deploy a new site on Coolify from a preset (FM-1035,
//! ADR 0016).
//!
//! A template is a thin preset over Coolify's own creation endpoints. Fleet
//! is not a deploy engine: it names the resource, sets its domain, and starts
//! it, and Coolify builds and runs it. Two kinds exist:
//!
//! - a **one-click service** (`POST /services` with a Coolify service
//!   `type`), and
//! - a **public Git application** (`POST /applications/public` with a build
//!   pack, a port, and default environment values).
//!
//! Private repositories (a GitHub App or a deploy key) are not offered: no
//! credential path for them exists in Fleet yet.
//!
//! # Templates are code, not Registry entries
//!
//! The built-in list lives here, versioned and pinned by a SHA-256 digest of
//! each definition, like built-in skills (ADR 0012). A Registry type would be
//! the wrong home: Registry resources are descriptive and never applied
//! (ADR 0016), while a template drives a mutating provider call and must be
//! reviewed and versioned with the controller. The request carries the
//! template's id, version, and digest, so the approver, the executor, and a
//! later revision of the template cannot disagree; a mismatch refuses the
//! request and asks for a new one.
//!
//! # The action
//!
//! One provider action, [`DEPLOY_ACTION`] (`coolify.site.deploy`), risk class
//! `approve`, one operation kind, [`SITE_KIND`]. Filing validates the
//! template, the domain, and the server, project, and environment against the
//! account's latest observation; execution checks them again.
//!
//! Execution runs under the same rules as the other Coolify actions (the
//! per-account lock while the endpoint and token are resolved, a
//! v4.2.0 floor, no token in any value that leaves the module) and these
//! steps, each reported:
//!
//! 1. **find** a resource already created for this request, by a marker in
//!    its description (`fleet-deploy:<request id>`), so a retry never makes a
//!    second one;
//! 2. **create** it, with the domain, without `instant_deploy`;
//! 3. **env**: write the template's default values that are not yet there
//!    (applications; the values are non-secret literals fixed in the
//!    template);
//! 4. **start**: queue the first deployment (an application) or start the
//!    service, unless one is already queued or running;
//! 5. **verify**: follow the deployment or the status for a bounded time.
//!
//! The created uuid is noted in the operation's progress before the next
//! step. A failure after the resource exists completes the operation as
//! `failed` with a structured partial result naming the uuid and what each
//! step did, so a person can finish in Coolify or re-run the request (which
//! reuses the resource).
//!
//! # Secrets
//!
//! A template has no secret values and a deploy request takes none. A
//! template lists the variables a person still has to set (secret keys, by
//! name) in `followUpEnvKeys`; they are set afterwards with `fleetctl
//! services env set`, the held-value path of FM-1034.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use fleet_core::{RiskClass, SensitiveString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Permission, authorize};
use crate::broker::{ActionRequest, Broker, BrokerError, NewActionRequest, ProviderAction};
use crate::coolify::lifecycle::{
    CoolifyLifecycle, CoolifyLifecyclePort, LifecycleError, LifecycleFailure, LifecycleResource,
    LifecycleVerb, Settle, bounded_name, check_version, deployment_terminal, safe_id, scrub_status,
};
use crate::coolify::settings::{CoolifySettingsPort, EnvFlags, EnvWrite, normalize_domain};
use crate::coolify::{CoolifyObservationPort, CoolifySnapshot};
use crate::operation::NewOperation;

/// The operation kind every site deployment runs as.
pub const SITE_KIND: &str = "coolify.site";
/// The action id that deploys a site from a template.
pub const DEPLOY_ACTION: &str = "coolify.site.deploy";
/// The longest resource name.
pub const MAX_SITE_NAME_LEN: usize = 63;
/// The longest repository URL.
pub const MAX_REPOSITORY_LEN: usize = 200;
/// The longest branch name.
pub const MAX_BRANCH_LEN: usize = 100;
/// The prefix of the description marker that ties a created resource to the
/// request that made it.
pub const MARKER_PREFIX: &str = "fleet-deploy:";

// ---------------------------------------------------------------------
// Templates.
// ---------------------------------------------------------------------

/// What a template creates.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum TemplateSource {
    /// A Coolify one-click service.
    Service {
        /// Coolify's service type (`ghost`, `uptime-kuma`, ...).
        service_type: String,
        /// The service's name inside its compose file; the domain attaches
        /// to it.
        domain_service: String,
    },
    /// A public Git repository built by Coolify.
    Git {
        /// Coolify's build pack (`nixpacks`, `static`, ...).
        build_pack: String,
        /// The port the application listens on.
        ports_exposes: u16,
        /// Whether the output is a static site.
        is_static: bool,
    },
}

/// One default environment variable of a Git template: a non-secret literal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateEnv {
    /// The variable's name.
    pub key: String,
    /// The default value (never a secret).
    pub value: String,
}

/// A site template.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteTemplate {
    /// The stable id.
    pub id: String,
    /// The definition's version; bump it with any change.
    pub version: u32,
    /// A short display name.
    pub name: String,
    /// What the template makes.
    pub description: String,
    /// What it creates.
    pub source: TemplateSource,
    /// Default environment values (Git templates).
    pub default_env: Vec<TemplateEnv>,
    /// Variables a person sets after the deploy (by name only).
    pub follow_up_env_keys: Vec<String>,
}

impl SiteTemplate {
    /// The digest that pins this definition: SHA-256 of its canonical JSON.
    #[must_use]
    pub fn digest(&self) -> String {
        let canonical = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(b"fleet-site-template\0");
        hasher.update(canonical.as_bytes());
        hasher
            .finalize()
            .iter()
            .fold(String::with_capacity(64), |mut out, byte| {
                use std::fmt::Write as _;
                let _ = write!(out, "{byte:02x}");
                out
            })
    }

    /// Whether the template deploys a Git repository the caller names.
    #[must_use]
    pub fn needs_repository(&self) -> bool {
        matches!(self.source, TemplateSource::Git { .. })
    }

    /// The resource kind the template creates.
    #[must_use]
    pub fn resource(&self) -> LifecycleResource {
        match self.source {
            TemplateSource::Service { .. } => LifecycleResource::Service,
            TemplateSource::Git { .. } => LifecycleResource::Application,
        }
    }
}

/// The built-in templates.
#[must_use]
pub fn builtin_templates() -> Vec<SiteTemplate> {
    let service = |id: &str, name: &str, description: &str, service_type: &str| SiteTemplate {
        id: id.to_owned(),
        version: 1,
        name: name.to_owned(),
        description: description.to_owned(),
        source: TemplateSource::Service {
            service_type: service_type.to_owned(),
            domain_service: service_type.to_owned(),
        },
        default_env: Vec::new(),
        follow_up_env_keys: Vec::new(),
    };
    vec![
        service(
            "ghost",
            "Ghost",
            "A Ghost publishing site with its database, from Coolify's one-click service.",
            "ghost",
        ),
        service(
            "uptime-kuma",
            "Uptime Kuma",
            "An Uptime Kuma status monitor, from Coolify's one-click service.",
            "uptime-kuma",
        ),
        SiteTemplate {
            id: "static-site".to_owned(),
            version: 1,
            name: "Static site".to_owned(),
            description:
                "A static site served from a public Git repository (Coolify's static build pack)."
                    .to_owned(),
            source: TemplateSource::Git {
                build_pack: "static".to_owned(),
                ports_exposes: 80,
                is_static: true,
            },
            default_env: Vec::new(),
            follow_up_env_keys: Vec::new(),
        },
        SiteTemplate {
            id: "node-app".to_owned(),
            version: 1,
            name: "Node.js app".to_owned(),
            description:
                "A Node.js application from a public Git repository, built by Nixpacks on port 3000."
                    .to_owned(),
            source: TemplateSource::Git {
                build_pack: "nixpacks".to_owned(),
                ports_exposes: 3000,
                is_static: false,
            },
            default_env: vec![
                TemplateEnv {
                    key: "NODE_ENV".to_owned(),
                    value: "production".to_owned(),
                },
                TemplateEnv {
                    key: "PORT".to_owned(),
                    value: "3000".to_owned(),
                },
            ],
            follow_up_env_keys: Vec::new(),
        },
    ]
}

/// A built-in template by id.
#[must_use]
pub fn find_template(id: &str) -> Option<SiteTemplate> {
    builtin_templates()
        .into_iter()
        .find(|template| template.id == id)
}

// ---------------------------------------------------------------------
// The provider port.
// ---------------------------------------------------------------------

/// What a service creation sends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceCreate {
    /// Coolify's service type.
    pub service_type: String,
    /// The service's name.
    pub name: String,
    /// The description, carrying the request marker.
    pub description: String,
    /// The project.
    pub project_uuid: String,
    /// The environment name.
    pub environment_name: String,
    /// The server.
    pub server_uuid: String,
    /// The destination, when the server has several.
    pub destination_uuid: Option<String>,
    /// The sub-application name and its URL.
    pub url: (String, String),
}

/// What an application creation sends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationCreate {
    /// The public repository URL.
    pub git_repository: String,
    /// The branch.
    pub git_branch: String,
    /// The build pack.
    pub build_pack: String,
    /// The exposed port.
    pub ports_exposes: u16,
    /// Whether the output is a static site.
    pub is_static: bool,
    /// The application's name.
    pub name: String,
    /// The description, carrying the request marker.
    pub description: String,
    /// The project.
    pub project_uuid: String,
    /// The environment name.
    pub environment_name: String,
    /// The server.
    pub server_uuid: String,
    /// The destination, when the server has several.
    pub destination_uuid: Option<String>,
    /// The domain URL.
    pub domain: String,
}

/// The Coolify creation client port. The provider crate implements it: a
/// separate mutating surface from read discovery.
#[async_trait]
pub trait CoolifyCreatePort: fmt::Debug + Send + Sync {
    /// The uuid of the resource whose description carries `marker`, if one
    /// exists (`GET` of the list).
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn find_by_marker(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        marker: &str,
    ) -> Result<Option<String>, LifecycleFailure>;

    /// Creates a one-click service (`POST /services`) and returns its uuid.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn create_service(
        &self,
        base_url: &str,
        token: &SensitiveString,
        create: &ServiceCreate,
    ) -> Result<String, LifecycleFailure>;

    /// Creates a public Git application (`POST /applications/public`) and
    /// returns its uuid.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn create_application(
        &self,
        base_url: &str,
        token: &SensitiveString,
        create: &ApplicationCreate,
    ) -> Result<String, LifecycleFailure>;
}

/// Where the executor notes what it created, before it goes on. The
/// controller records it in the operation's progress.
#[async_trait]
pub trait DeployProgress: Send + Sync {
    /// Notes a step; `detail` is safe to print (ids, never a secret).
    async fn note(&self, step: &str, detail: &str);
}

// ---------------------------------------------------------------------
// Parameters.
// ---------------------------------------------------------------------

/// The parameters of a deploy request. Ids and display names only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeployParameters {
    /// The Fleet Coolify account.
    pub account_id: String,
    /// The template.
    pub template_id: String,
    /// The template version the requester saw.
    pub template_version: u32,
    /// The template digest the requester saw.
    pub template_digest: String,
    /// The target server's uuid.
    pub server_uuid: String,
    /// The server's name, for the approver.
    #[serde(default)]
    pub server_name: String,
    /// The target project's uuid.
    pub project_uuid: String,
    /// The project's name, for the approver.
    #[serde(default)]
    pub project_name: String,
    /// The environment name.
    pub environment_name: String,
    /// The destination uuid, when the server has several.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_uuid: Option<String>,
    /// The site's URL (`https://host`).
    pub domain: String,
    /// The resource name.
    pub name: String,
    /// The public repository (Git templates).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// The branch (Git templates).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
}

impl DeployParameters {
    /// The canonical target: the account and the site's host.
    #[must_use]
    pub fn target(&self) -> String {
        format!("site:{}:{}", self.account_id, host_of(&self.domain))
    }
}

fn host_of(domain: &str) -> &str {
    domain
        .split_once("://")
        .map_or(domain, |(_, rest)| rest)
        .trim_end_matches('/')
}

/// The operation payload: the parameters and the request that carries them
/// out (its id makes the created resource findable again).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeployPayload {
    parameters: DeployParameters,
    request_id: String,
}

/// A name Coolify and a person can both read: lowercase letters, digits, and
/// `-`, starting with a letter or digit.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SITE_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// A default resource name for a host (`blog.example.com` becomes
/// `blog-example-com`).
#[must_use]
pub fn name_for_host(host: &str) -> String {
    let mut name: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    name.truncate(MAX_SITE_NAME_LEN);
    name.trim_matches('-').to_owned()
}

fn valid_repository(url: &str) -> Result<(), String> {
    if url.is_empty() || url.len() > MAX_REPOSITORY_LEN {
        return Err(format!(
            "the repository must be 1 to {MAX_REPOSITORY_LEN} bytes"
        ));
    }
    if url
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || "`$;&|<>()\\\"'".contains(c))
    {
        return Err("the repository has a character that is not allowed".to_owned());
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Err("the repository must be a public https:// URL".to_owned());
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') || !rest.contains('/') {
        return Err(
            "the repository must be https://<host>/<path> without credentials (private repositories are not supported)"
                .to_owned(),
        );
    }
    if rest.contains('?') || rest.contains('#') {
        return Err("the repository URL must not carry a query or fragment".to_owned());
    }
    Ok(())
}

fn valid_branch(branch: &str) -> Result<(), String> {
    let ok = !branch.is_empty()
        && branch.len() <= MAX_BRANCH_LEN
        && !branch.starts_with(['-', '/', '.'])
        && !branch.contains("..")
        && !branch.ends_with(['/', '.'])
        && branch
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'));
    if ok {
        Ok(())
    } else {
        Err("the branch is not a valid Git branch name".to_owned())
    }
}

/// Normalizes the site's domain: a bare host or an `http(s)` URL with no
/// path and no port; a bare host becomes `https://host`.
///
/// # Errors
///
/// Returns a caller-safe reason.
pub fn normalize_site_domain(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let url = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let normalized = normalize_domain(&url)?;
    let rest = normalized
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_default();
    if rest.contains('/') || rest.contains(':') || rest.contains('?') || rest.contains('#') {
        return Err("the domain must be a host name (no path or port)".to_owned());
    }
    Ok(normalized)
}

fn validate_parameters(params: &DeployParameters) -> Result<SiteTemplate, String> {
    if !safe_id(&params.account_id) {
        return Err("accountId is not a valid id".to_owned());
    }
    for (what, value) in [
        ("serverUuid", &params.server_uuid),
        ("projectUuid", &params.project_uuid),
    ] {
        if !safe_id(value) {
            return Err(format!("{what} is not a valid Coolify uuid"));
        }
    }
    if let Some(destination) = &params.destination_uuid
        && !safe_id(destination)
    {
        return Err("destinationUuid is not a valid Coolify uuid".to_owned());
    }
    if params.environment_name.is_empty()
        || params.environment_name.len() > 64
        || params.environment_name.chars().any(char::is_control)
    {
        return Err("environmentName is empty, too long, or has control characters".to_owned());
    }
    for display in [&params.server_name, &params.project_name] {
        if display.len() > 128 || display.chars().any(char::is_control) {
            return Err("a display name is too long or has control characters".to_owned());
        }
    }
    if !valid_name(&params.name) {
        return Err(
            "name must be lowercase letters, digits, and '-' (at most 63 characters)".to_owned(),
        );
    }
    if normalize_site_domain(&params.domain).as_deref() != Ok(params.domain.as_str()) {
        return Err("domain must be a normalized https://<host> URL".to_owned());
    }
    let template = find_template(&params.template_id)
        .ok_or_else(|| format!("{} is not a site template", params.template_id))?;
    if template.version != params.template_version || template.digest() != params.template_digest {
        return Err(
            "the template changed since the request was made; nothing was changed, so re-file the request"
                .to_owned(),
        );
    }
    match (&template.source, &params.repository, &params.branch) {
        (TemplateSource::Service { .. }, None, None) => {}
        (TemplateSource::Service { .. }, _, _) => {
            return Err("a one-click service template takes no repository or branch".to_owned());
        }
        (TemplateSource::Git { .. }, Some(repository), Some(branch)) => {
            valid_repository(repository)?;
            valid_branch(branch)?;
        }
        (TemplateSource::Git { .. }, _, _) => {
            return Err("a Git template needs a repository and a branch".to_owned());
        }
    }
    Ok(template)
}

/// The action that deploys a site from a template.
#[derive(Debug, Default)]
pub struct SiteDeployAction;

/// Every site-template action, for the controller's action registry.
#[must_use]
pub fn site_actions() -> Vec<Arc<dyn ProviderAction>> {
    vec![Arc::new(SiteDeployAction)]
}

impl ProviderAction for SiteDeployAction {
    fn id(&self) -> &str {
        DEPLOY_ACTION
    }

    fn operation_kind(&self) -> &str {
        SITE_KIND
    }

    fn risk_class(&self) -> RiskClass {
        // ADR 0016: a new deploy is `approve` by default.
        RiskClass::Approve
    }

    fn validate(&self, target: &str, parameters: &Value) -> Result<(), String> {
        let params: DeployParameters =
            serde_json::from_value(parameters.clone()).map_err(|_| {
                "the parameters are not a site deployment; use POST /site-deployments".to_owned()
            })?;
        validate_parameters(&params)?;
        if params.target() != target {
            return Err("the target must be site:<account>:<host>".to_owned());
        }
        Ok(())
    }

    fn comparable_parameters(&self, parameters: &Value) -> Value {
        // The server and project names are for the approver.
        let mut comparable = parameters.clone();
        if let Some(object) = comparable.as_object_mut() {
            object.remove("serverName");
            object.remove("projectName");
        }
        comparable
    }

    fn operation(&self, request: &ActionRequest) -> Result<NewOperation, String> {
        let parameters: DeployParameters = serde_json::from_value(request.parameters.clone())
            .map_err(|_| "the request parameters are not a site deployment".to_owned())?;
        let payload = serde_json::to_string(&DeployPayload {
            parameters,
            request_id: request.id.clone(),
        })
        .map_err(|_| "the payload could not be built".to_owned())?;
        Ok(NewOperation {
            kind: SITE_KIND.to_owned(),
            idempotency_key: None,
            deadline_at: None,
            correlation_id: None,
            payload_json: Some(payload),
            review_token: None,
        })
    }
}

// ---------------------------------------------------------------------
// Results.
// ---------------------------------------------------------------------

/// What one step of an execution did.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepReport {
    /// `find`, `create`, `env`, `start`, or `verify`.
    pub step: String,
    /// `done`, `reused`, `skipped`, `failed`, or `pending`.
    pub status: String,
    /// A short, safe note.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// How an executed deployment ended. Recorded as the operation result; ids
/// and names only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployOutcome {
    /// The template id.
    pub template: String,
    /// The template version.
    pub template_version: u32,
    /// `deployed` (the deployment was started and followed), or `partial`
    /// (the resource exists but a later step failed; see `steps`).
    pub outcome: String,
    /// `application` or `service`.
    pub resource_kind: String,
    /// The created resource's uuid.
    pub uuid: String,
    /// The running-service id the service list prints.
    pub service_id: String,
    /// The site's URL.
    pub domain: String,
    /// The resource name.
    pub name: String,
    /// Each step.
    pub steps: Vec<StepReport>,
    /// The deployment Coolify queued, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_uuid: Option<String>,
    /// That deployment's last observed status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_status: Option<String>,
    /// The resource's last observed status.
    pub observed_status: String,
    /// Whether the end state was verified.
    pub settled: bool,
    /// Variables to set afterwards (names only).
    pub follow_up_env_keys: Vec<String>,
    /// Why a partial deployment stopped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// An execution that did not finish: the failure text, and what existed by
/// then, so a partial deployment is recorded rather than lost.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeployFailure {
    /// The caller-safe failure text.
    pub message: String,
    /// What was created before the failure, when anything was.
    pub partial: Option<Box<DeployOutcome>>,
}

impl From<String> for DeployFailure {
    fn from(message: String) -> Self {
        Self {
            message,
            partial: None,
        }
    }
}

impl fmt::Display for DeployFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

// ---------------------------------------------------------------------
// The use cases.
// ---------------------------------------------------------------------

/// What a caller asks for.
#[derive(Clone, Debug)]
pub struct DeployRequest {
    /// The Fleet Coolify account id.
    pub account_id: String,
    /// The template id.
    pub template_id: String,
    /// The target server's uuid.
    pub server_uuid: String,
    /// The target project's uuid.
    pub project_uuid: String,
    /// The environment name.
    pub environment_name: String,
    /// The destination uuid, when the server has several.
    pub destination_uuid: Option<String>,
    /// The domain (a host or an `https://` URL).
    pub domain: String,
    /// The resource name; derived from the domain when absent.
    pub name: Option<String>,
    /// The public repository (Git templates).
    pub repository: Option<String>,
    /// The branch (Git templates).
    pub branch: Option<String>,
    /// Why, for the approver.
    pub reason: String,
    /// Where the request came from.
    pub origin: String,
    /// The correlation identity.
    pub correlation_id: Option<String>,
    /// A key making a retry return the request already made.
    pub idempotency_key: Option<String>,
}

/// The site-template use cases.
#[derive(Debug)]
pub struct SiteTemplates {
    lifecycle: Arc<CoolifyLifecycle>,
    lifecycle_port: Arc<dyn CoolifyLifecyclePort>,
    settings_port: Arc<dyn CoolifySettingsPort>,
    create_port: Arc<dyn CoolifyCreatePort>,
    observations: Arc<dyn CoolifyObservationPort>,
    settle: Settle,
}

fn invalid(detail: impl Into<String>) -> LifecycleError {
    LifecycleError::Invalid {
        detail: detail.into(),
    }
}

/// A caller-safe failure for a step that ran into a backend problem.
fn step_error(error: LifecycleError) -> String {
    match error {
        LifecycleError::Backend { context, .. } => format!("{context} failed"),
        other => other.to_string(),
    }
}

impl SiteTemplates {
    /// Composes the use cases from the lifecycle use cases (account and
    /// credential access) and the Coolify ports.
    #[must_use]
    pub fn new(
        lifecycle: Arc<CoolifyLifecycle>,
        lifecycle_port: Arc<dyn CoolifyLifecyclePort>,
        settings_port: Arc<dyn CoolifySettingsPort>,
        create_port: Arc<dyn CoolifyCreatePort>,
        observations: Arc<dyn CoolifyObservationPort>,
    ) -> Self {
        Self {
            lifecycle,
            lifecycle_port,
            settings_port,
            create_port,
            observations,
            settle: Settle::default(),
        }
    }

    /// Replaces the verification timing (tests use no pause).
    #[must_use]
    pub fn with_settle(mut self, settle: Settle) -> Self {
        self.settle = settle;
        self
    }

    /// The built-in templates. Needs `external_account.read`.
    ///
    /// # Errors
    ///
    /// Fails on denial.
    pub fn templates(
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<Vec<SiteTemplate>, LifecycleError> {
        Self::require_read(authorizer, principal)?;
        Ok(builtin_templates())
    }

    fn require_read(
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<(), LifecycleError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ExternalAccountRead,
                resource: None,
            },
        )
        .map(|_| ())
        .map_err(LifecycleError::Denied)
    }

    async fn snapshot(&self, account_id: &str) -> Result<CoolifySnapshot, LifecycleError> {
        let loaded =
            self.observations
                .load(account_id)
                .await
                .map_err(|detail| LifecycleError::Backend {
                    context: "coolify observations",
                    detail,
                })?;
        loaded
            .map(|(snapshot, _)| snapshot)
            .ok_or_else(|| LifecycleError::NotFound {
                what: format!("a discovery of account {account_id}; run one first"),
            })
    }

    /// Files a deploy request: the template, the domain, and the target are
    /// checked against the account's latest observation, then the broker
    /// decides by risk class (`approve`).
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown template or account, a target missing from
    /// the latest observation, a domain already routed to another resource,
    /// a malformed field, an idempotency-key conflict, or a broker refusal.
    #[allow(clippy::too_many_lines)]
    pub async fn request_deploy(
        &self,
        broker: &Broker,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        request: DeployRequest,
        now: i64,
    ) -> Result<ActionRequest, LifecycleError> {
        Self::require_read(authorizer, principal)?;
        let template = find_template(&request.template_id)
            .ok_or_else(|| invalid(format!("{} is not a site template", request.template_id)))?;
        let domain = normalize_site_domain(&request.domain).map_err(invalid)?;
        let name = match request.name.as_deref() {
            Some(name) => name.to_owned(),
            None => name_for_host(host_of(&domain)),
        };
        let account = self.lifecycle.coolify_account(&request.account_id).await?;
        let snapshot = self.snapshot(&account.id).await?;
        // A server or project is named by its uuid or, when that is
        // unambiguous, by its exact name.
        let server = pick(
            &snapshot.servers.items,
            &request.server_uuid,
            |server| (&server.uuid, &server.name),
            "server",
        )?;
        let project = pick(
            &snapshot.projects.items,
            &request.project_uuid,
            |project| (&project.uuid, &project.name),
            "project",
        )?;
        if !project
            .environments
            .iter()
            .any(|environment| environment.name == request.environment_name)
        {
            return Err(LifecycleError::NotFound {
                what: format!(
                    "environment {} in project {}",
                    bounded_name(&request.environment_name),
                    bounded_name(&project.name)
                ),
            });
        }
        if let Some(owner) = route_owner(&snapshot, &domain) {
            return Err(invalid(format!(
                "{domain} is already routed to {owner} in Coolify; pick another domain"
            )));
        }
        let parameters = DeployParameters {
            account_id: account.id.clone(),
            template_id: template.id.clone(),
            template_version: template.version,
            template_digest: template.digest(),
            server_uuid: server.uuid.clone(),
            server_name: bounded_name(&server.name),
            project_uuid: project.uuid.clone(),
            project_name: bounded_name(&project.name),
            environment_name: request.environment_name,
            destination_uuid: request.destination_uuid,
            domain,
            name,
            repository: request.repository,
            branch: request.branch,
        };
        validate_parameters(&parameters).map_err(invalid)?;
        let target = parameters.target();
        let parameters =
            serde_json::to_value(&parameters).map_err(|error| LifecycleError::Backend {
                context: "parameters",
                detail: error.to_string(),
            })?;
        if let Some(key) = request.idempotency_key.as_deref()
            && let Some(existing) = broker
                .existing_for_key(authorizer, &principal.id, key, now)
                .await
                .map_err(LifecycleError::Broker)?
        {
            let same = existing.action_id == DEPLOY_ACTION
                && existing.target == target
                && SiteDeployAction.comparable_parameters(&existing.parameters)
                    == SiteDeployAction.comparable_parameters(&parameters);
            return if same {
                Ok(existing)
            } else {
                Err(LifecycleError::Broker(BrokerError::Conflict {
                    state: existing.state,
                    detail: "the idempotency key was already used for a different request"
                        .to_owned(),
                }))
            };
        }
        broker
            .create(
                authorizer,
                &principal.id,
                NewActionRequest {
                    action_id: DEPLOY_ACTION.to_owned(),
                    target,
                    parameters,
                    reason: request.reason,
                    origin: request.origin,
                    correlation_id: request.correlation_id,
                    idempotency_key: request.idempotency_key,
                },
                now,
            )
            .await
            .map_err(LifecycleError::Broker)
    }

    /// Runs an approved deploy request: the operation executor calls this
    /// with the operation's kind and payload.
    ///
    /// The request may have been filed through the generic `POST /requests`
    /// route, which checks nothing against Coolify, so the template pin and
    /// the target are checked again here against the account's latest
    /// observation.
    ///
    /// # Errors
    ///
    /// Fails with a caller-safe reason. A failure after the resource was
    /// created carries the partial outcome.
    #[allow(clippy::too_many_lines)]
    pub async fn execute(
        &self,
        kind: &str,
        payload: &str,
        progress: &dyn DeployProgress,
    ) -> Result<DeployOutcome, DeployFailure> {
        if kind != SITE_KIND {
            return Err(format!("{kind} is not a site deployment operation").into());
        }
        let DeployPayload {
            parameters: params,
            request_id,
        } = serde_json::from_str(payload)
            .map_err(|_| "the operation payload is not a site deployment".to_owned())?;
        if !safe_id(&request_id) {
            return Err("the operation payload has an invalid request id"
                .to_owned()
                .into());
        }
        let template = validate_parameters(&params)?;
        let snapshot = self
            .snapshot(&params.account_id)
            .await
            .map_err(|error| match error {
                LifecycleError::NotFound { .. } => {
                    "the account has no Coolify observation; run discovery and re-file the request"
                        .to_owned()
                }
                other => step_error(other),
            })?;
        let known = snapshot
            .servers
            .items
            .iter()
            .any(|server| server.uuid == params.server_uuid)
            && snapshot.projects.items.iter().any(|project| {
                project.uuid == params.project_uuid
                    && project
                        .environments
                        .iter()
                        .any(|environment| environment.name == params.environment_name)
            });
        if !known {
            return Err(
                "the server, project, or environment is not in the account's latest Coolify observation; nothing was changed, so run discovery and re-file the request"
                    .to_owned()
                    .into(),
            );
        }
        let (account, token) = self
            .lifecycle
            .resolve(&params.account_id)
            .await
            .map_err(step_error)?;
        let base = account.base_url.as_str();
        let provider = |failure: LifecycleFailure| failure.to_string();
        let version = self
            .lifecycle_port
            .version(base, &token)
            .await
            .map_err(provider)?;
        check_version(&version).map_err(provider)?;

        let resource = template.resource();
        let marker = format!("{MARKER_PREFIX}{request_id}");
        let mut run = Run {
            steps: Vec::new(),
            uuid: String::new(),
            deployment_uuid: None,
            deployment_status: None,
            observed_status: String::new(),
            settled: false,
        };

        // 1. Find a resource an earlier run of this request created.
        let existing = self
            .create_port
            .find_by_marker(base, &token, resource, &marker)
            .await
            .map_err(provider)?;
        // 2. Create it.
        let reused = existing.is_some();
        run.uuid = if let Some(uuid) = existing {
            run.step(
                "find",
                "done",
                Some("found the resource an earlier run created"),
            );
            run.step("create", "reused", None);
            uuid
        } else {
            run.step("find", "done", Some("no resource for this request yet"));
            let created = match &template.source {
                TemplateSource::Service {
                    service_type,
                    domain_service,
                } => {
                    self.create_port
                        .create_service(
                            base,
                            &token,
                            &ServiceCreate {
                                service_type: service_type.clone(),
                                name: params.name.clone(),
                                description: marker.clone(),
                                project_uuid: params.project_uuid.clone(),
                                environment_name: params.environment_name.clone(),
                                server_uuid: params.server_uuid.clone(),
                                destination_uuid: params.destination_uuid.clone(),
                                url: (domain_service.clone(), params.domain.clone()),
                            },
                        )
                        .await
                }
                TemplateSource::Git {
                    build_pack,
                    ports_exposes,
                    is_static,
                } => {
                    self.create_port
                        .create_application(
                            base,
                            &token,
                            &ApplicationCreate {
                                git_repository: params.repository.clone().unwrap_or_default(),
                                git_branch: params.branch.clone().unwrap_or_default(),
                                build_pack: build_pack.clone(),
                                ports_exposes: *ports_exposes,
                                is_static: *is_static,
                                name: params.name.clone(),
                                description: marker.clone(),
                                project_uuid: params.project_uuid.clone(),
                                environment_name: params.environment_name.clone(),
                                server_uuid: params.server_uuid.clone(),
                                destination_uuid: params.destination_uuid.clone(),
                                domain: params.domain.clone(),
                            },
                        )
                        .await
                }
            };
            let uuid = created.map_err(|failure| format!("creating the resource: {failure}"))?;
            if !safe_id(&uuid) {
                return Err(
                    "Coolify created a resource but answered an unusable uuid; find it in Coolify by its description and finish there"
                        .to_owned()
                        .into(),
                );
            }
            run.step("create", "done", None);
            uuid
        };
        // Note the uuid before doing anything else.
        progress
            .note(
                "create",
                &format!(
                    "{} {} {}",
                    resource.id(),
                    if reused { "found" } else { "created" },
                    run.uuid
                ),
            )
            .await;

        // 3. Default environment values (applications).
        if let Err(message) = self
            .apply_env(base, &token, &template, &run.uuid, &mut run.steps)
            .await
        {
            return Err(Self::partial(&template, &params, run, &message));
        }
        // 4. Start.
        if let Err(message) = self.start(base, &token, resource, &mut run).await {
            return Err(Self::partial(&template, &params, run, &message));
        }
        // 5. Verify.
        self.verify(base, &token, resource, &mut run).await;
        progress
            .note("verify", "followed the first deployment")
            .await;
        if matches!(
            run.deployment_status.as_deref(),
            Some("failed" | "cancelled" | "cancelled-by-user")
        ) {
            let message = "the first deployment did not finish; read its log with `fleetctl services logs`, fix the cause, and redeploy";
            return Err(Self::partial(&template, &params, run, message));
        }
        Ok(Self::outcome(&template, &params, run, "deployed", None))
    }

    async fn apply_env(
        &self,
        base: &str,
        token: &SensitiveString,
        template: &SiteTemplate,
        uuid: &str,
        steps: &mut Vec<StepReport>,
    ) -> Result<(), String> {
        if template.default_env.is_empty() {
            steps.push(step(
                "env",
                "skipped",
                Some("the template has no default values"),
            ));
            return Ok(());
        }
        let existing = match self
            .settings_port
            .read_envs(base, token, LifecycleResource::Application, uuid)
            .await
        {
            Ok(existing) => existing,
            Err(failure) => {
                steps.push(step("env", "failed", Some(&failure.to_string())));
                return Err(format!("reading the variables: {failure}"));
            }
        };
        let mut written = 0_usize;
        for default in &template.default_env {
            if existing
                .iter()
                .any(|env| env.key == default.key && !env.is_preview)
            {
                continue;
            }
            let value = SensitiveString::new(default.value.clone());
            let write = EnvWrite {
                key: &default.key,
                value: &value,
                is_preview: false,
                flags: EnvFlags::default(),
            };
            if let Err(failure) = self
                .settings_port
                .create_env(base, token, LifecycleResource::Application, uuid, &write)
                .await
            {
                steps.push(step(
                    "env",
                    "failed",
                    Some(&format!("setting {}: {failure}", default.key)),
                ));
                return Err(format!("setting {}: {failure}", default.key));
            }
            written += 1;
        }
        steps.push(step(
            "env",
            if written == 0 { "skipped" } else { "done" },
            Some(&format!("{written} default value(s) written")),
        ));
        Ok(())
    }

    async fn start(
        &self,
        base: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        run: &mut Run,
    ) -> Result<(), String> {
        let uuid = run.uuid.clone();
        match resource {
            LifecycleResource::Application => {
                let latest = self
                    .lifecycle_port
                    .latest_deployment(base, token, &uuid)
                    .await
                    .map_err(|failure| {
                        run.step("start", "failed", Some(&failure.to_string()));
                        format!("checking for an earlier deployment: {failure}")
                    })?;
                if let Some(deployment) = latest {
                    run.step("start", "skipped", Some("a deployment already exists"));
                    run.deployment_uuid = Some(deployment);
                    return Ok(());
                }
                let ack = self
                    .lifecycle_port
                    .run(base, token, resource, &uuid, LifecycleVerb::Redeploy)
                    .await
                    .map_err(|failure| {
                        run.step("start", "failed", Some(&failure.to_string()));
                        format!("starting the first deployment: {failure}")
                    })?;
                let Some(deployment) = ack.deployment_uuid else {
                    let said = ack
                        .message
                        .map(|m| format!(" (Coolify said: {m})"))
                        .unwrap_or_default();
                    run.step("start", "failed", Some("Coolify queued no deployment"));
                    return Err(format!("Coolify did not queue a deployment{said}"));
                };
                run.step("start", "done", None);
                run.deployment_uuid = Some(deployment);
            }
            LifecycleResource::Service | LifecycleResource::Database => {
                let status = self
                    .lifecycle_port
                    .status(base, token, resource, &uuid)
                    .await
                    .map_err(|failure| {
                        run.step("start", "failed", Some(&failure.to_string()));
                        format!("reading the service: {failure}")
                    })?
                    .status;
                if status.starts_with("running") {
                    run.step("start", "skipped", Some("the service is already running"));
                    run.observed_status = scrub_status(&status);
                    return Ok(());
                }
                self.lifecycle_port
                    .run(base, token, resource, &uuid, LifecycleVerb::Start)
                    .await
                    .map_err(|failure| {
                        run.step("start", "failed", Some(&failure.to_string()));
                        format!("starting the service: {failure}")
                    })?;
                run.step("start", "done", None);
            }
        }
        Ok(())
    }

    /// Follows the deployment or the status for a bounded time. Never fails
    /// the deployment by itself: an unreadable answer is reported as such.
    async fn verify(
        &self,
        base: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        run: &mut Run,
    ) {
        let uuid = run.uuid.clone();
        if let Some(deployment) = run.deployment_uuid.clone() {
            let mut polls = 0;
            let mut status = String::new();
            loop {
                match self
                    .lifecycle_port
                    .deployment(base, token, &deployment)
                    .await
                {
                    Ok(seen) => status = seen.status,
                    Err(_) => break,
                }
                if deployment_terminal(&status) || polls >= self.settle.attempts {
                    break;
                }
                polls += 1;
                if !self.settle.interval.is_zero() {
                    tokio::time::sleep(self.settle.interval).await;
                }
            }
            let status = scrub_status(&status);
            run.settled = status == "finished";
            run.deployment_status = Some(status.clone()).filter(|s| !s.is_empty());
            run.step(
                "verify",
                if run.settled { "done" } else { "pending" },
                Some(&format!(
                    "deployment {}",
                    if status.is_empty() {
                        "unreadable"
                    } else {
                        &status
                    }
                )),
            );
        } else {
            for _ in 0..=self.settle.attempts {
                match self
                    .lifecycle_port
                    .status(base, token, resource, &uuid)
                    .await
                {
                    Ok(state) => {
                        run.settled = state.status.starts_with("running");
                        run.observed_status = scrub_status(&state.status);
                    }
                    Err(failure) => {
                        run.observed_status = format!("unreadable ({})", failure.class.id());
                        break;
                    }
                }
                if run.settled {
                    break;
                }
                if !self.settle.interval.is_zero() {
                    tokio::time::sleep(self.settle.interval).await;
                }
            }
            run.step(
                "verify",
                if run.settled { "done" } else { "pending" },
                Some(&format!("status {}", run.observed_status)),
            );
            return;
        }
        if let Ok(state) = self
            .lifecycle_port
            .status(base, token, resource, &uuid)
            .await
        {
            run.observed_status = scrub_status(&state.status);
        }
    }

    fn outcome(
        template: &SiteTemplate,
        params: &DeployParameters,
        run: Run,
        outcome: &str,
        error: Option<String>,
    ) -> DeployOutcome {
        let resource = template.resource();
        DeployOutcome {
            template: template.id.clone(),
            template_version: template.version,
            outcome: outcome.to_owned(),
            resource_kind: resource.id().to_owned(),
            service_id: crate::coolify::lifecycle::service_id(&params.account_id, &run.uuid),
            uuid: run.uuid,
            domain: params.domain.clone(),
            name: params.name.clone(),
            steps: run.steps,
            deployment_uuid: run.deployment_uuid,
            deployment_status: run.deployment_status,
            observed_status: run.observed_status,
            settled: run.settled,
            follow_up_env_keys: template.follow_up_env_keys.clone(),
            error,
        }
    }

    fn partial(
        template: &SiteTemplate,
        params: &DeployParameters,
        run: Run,
        message: &str,
    ) -> DeployFailure {
        let message = fleet_core::scrub_failure_detail(message);
        let partial = Self::outcome(template, params, run, "partial", Some(message.clone()));
        DeployFailure {
            message: format!(
                "the {} {} was created but the deployment did not complete: {message}",
                partial.resource_kind, partial.uuid
            ),
            partial: Some(Box::new(partial)),
        }
    }
}

/// The mutable state of one execution.
struct Run {
    steps: Vec<StepReport>,
    uuid: String,
    deployment_uuid: Option<String>,
    deployment_status: Option<String>,
    observed_status: String,
    settled: bool,
}

impl Run {
    fn step(&mut self, name: &str, status: &str, detail: Option<&str>) {
        self.steps.push(step(name, status, detail));
    }
}

fn step(name: &str, status: &str, detail: Option<&str>) -> StepReport {
    StepReport {
        step: name.to_owned(),
        status: status.to_owned(),
        detail: detail.map(fleet_core::scrub_failure_detail),
    }
}

/// The one item whose uuid, or else whose exact name, is `wanted`.
fn pick<'a, T>(
    items: &'a [T],
    wanted: &str,
    names: impl Fn(&T) -> (&String, &String),
    what: &str,
) -> Result<&'a T, LifecycleError> {
    if let Some(item) = items.iter().find(|item| names(item).0 == wanted) {
        return Ok(item);
    }
    let mut by_name = items.iter().filter(|item| names(item).1 == wanted);
    match (by_name.next(), by_name.next()) {
        (Some(item), None) => Ok(item),
        (Some(_), Some(_)) => Err(invalid(format!(
            "more than one {what} is named {}; use its uuid",
            bounded_name(wanted)
        ))),
        _ => Err(LifecycleError::NotFound {
            what: format!("that {what} in the latest Coolify observation; run discovery"),
        }),
    }
}

/// The name of the application or service that already routes `domain`, if
/// any (compared case-insensitively, without a trailing slash).
fn route_owner(snapshot: &CoolifySnapshot, domain: &str) -> Option<String> {
    let want = domain.trim_end_matches('/').to_ascii_lowercase();
    let same = |fqdn: &String| fqdn.trim_end_matches('/').to_ascii_lowercase() == want;
    snapshot
        .applications
        .items
        .iter()
        .find(|item| item.fqdns.iter().any(same))
        .map(|item| format!("application {}", bounded_name(&item.name)))
        .or_else(|| {
            snapshot
                .services
                .items
                .iter()
                .find(|item| item.fqdns.iter().any(same))
                .map(|item| format!("service {}", bounded_name(&item.name)))
        })
}

/// The `fleetctl registry` commands that record a deployed site: the domain
/// entry and its `hosted-on` relation. Lines of shell, one command each.
#[must_use]
pub fn registry_patch(outcome: &DeployOutcome) -> Vec<String> {
    let host = host_of(&outcome.domain);
    vec![
        format!("fleetctl registry set domain/{host} --field fqdn={host}"),
        format!(
            "fleetctl registry relate domain/{host} hosted-on coolify:{}",
            outcome.uuid
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(template: &SiteTemplate) -> DeployParameters {
        DeployParameters {
            account_id: "acct1".to_owned(),
            template_id: template.id.clone(),
            template_version: template.version,
            template_digest: template.digest(),
            server_uuid: "srv1".to_owned(),
            server_name: "edge".to_owned(),
            project_uuid: "proj1".to_owned(),
            project_name: "sites".to_owned(),
            environment_name: "production".to_owned(),
            destination_uuid: None,
            domain: "https://blog.example.test".to_owned(),
            name: "blog-example-test".to_owned(),
            repository: template
                .needs_repository()
                .then(|| "https://example.test/o/r".to_owned()),
            branch: template.needs_repository().then(|| "main".to_owned()),
        }
    }

    #[test]
    fn built_in_templates_have_unique_ids_distinct_digests_and_no_secret_defaults() {
        let templates = builtin_templates();
        let mut ids: Vec<&str> = templates.iter().map(|t| t.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), templates.len());
        let mut digests: Vec<String> = templates.iter().map(SiteTemplate::digest).collect();
        digests.sort();
        digests.dedup();
        assert_eq!(digests.len(), templates.len());
        for template in &templates {
            for env in &template.default_env {
                // A default is a literal anyone may read: the redaction
                // helpers must not change it.
                assert_eq!(
                    fleet_core::scrub_failure_detail(&env.value),
                    env.value,
                    "{} default {}",
                    template.id,
                    env.key
                );
            }
        }
    }

    #[test]
    fn the_digest_changes_with_any_field() {
        let mut template = find_template("node-app").unwrap();
        let before = template.digest();
        template.default_env[0].value = "development".to_owned();
        assert_ne!(template.digest(), before);
    }

    #[test]
    fn domains_are_bare_hosts_made_https() {
        assert_eq!(
            normalize_site_domain("Blog.Example.Test").unwrap(),
            "https://blog.example.test"
        );
        assert_eq!(
            normalize_site_domain("http://a.example.test").unwrap(),
            "http://a.example.test"
        );
        for bad in [
            "https://a.example.test/x",
            "a.example.test:8080",
            "user@a.example.test",
            "a b",
            "",
        ] {
            assert!(normalize_site_domain(bad).is_err(), "{bad}");
        }
        assert_eq!(name_for_host("blog.example.test"), "blog-example-test");
    }

    #[test]
    fn parameters_validate_against_the_pinned_template() {
        let ghost = find_template("ghost").unwrap();
        assert!(validate_parameters(&params(&ghost)).is_ok());
        let mut stale = params(&ghost);
        stale.template_digest = "0".repeat(64);
        assert!(
            validate_parameters(&stale)
                .unwrap_err()
                .contains("template changed")
        );
        let mut with_repo = params(&ghost);
        with_repo.repository = Some("https://example.test/o/r".to_owned());
        assert!(validate_parameters(&with_repo).is_err());
        let node = find_template("node-app").unwrap();
        let mut bad = params(&node);
        bad.repository = Some("https://token@example.test/o/r".to_owned());
        assert!(validate_parameters(&bad).is_err());
        let mut bad = params(&node);
        bad.repository = Some("ssh://example.test/o/r".to_owned());
        assert!(validate_parameters(&bad).is_err());
        let mut bad = params(&node);
        bad.branch = Some("--upload-pack=x".to_owned());
        assert!(validate_parameters(&bad).is_err());
        let mut bad = params(&node);
        bad.branch = None;
        assert!(validate_parameters(&bad).is_err());
    }

    #[test]
    fn the_action_is_approve_class_and_checks_its_target() {
        let ghost = find_template("ghost").unwrap();
        let params = params(&ghost);
        let value = serde_json::to_value(&params).unwrap();
        assert_eq!(SiteDeployAction.risk_class(), RiskClass::Approve);
        assert!(SiteDeployAction.validate(&params.target(), &value).is_ok());
        assert!(
            SiteDeployAction
                .validate("site:acct1:other.example.test", &value)
                .is_err()
        );
        let mut renamed = value.clone();
        renamed["serverName"] = serde_json::json!("renamed");
        assert_eq!(
            SiteDeployAction.comparable_parameters(&value),
            SiteDeployAction.comparable_parameters(&renamed)
        );
    }

    #[test]
    fn the_registry_patch_names_the_domain_and_the_resource() {
        let template = find_template("ghost").unwrap();
        let outcome = SiteTemplates::outcome(
            &template,
            &params(&template),
            Run {
                steps: Vec::new(),
                uuid: "svc123".to_owned(),
                deployment_uuid: None,
                deployment_status: None,
                observed_status: "running".to_owned(),
                settled: true,
            },
            "deployed",
            None,
        );
        assert_eq!(
            registry_patch(&outcome),
            [
                "fleetctl registry set domain/blog.example.test --field fqdn=blog.example.test",
                "fleetctl registry relate domain/blog.example.test hosted-on coolify:svc123"
            ]
        );
    }
}
