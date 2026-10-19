//! Coolify lifecycle actions and the deployment log tail (FM-1033).
//!
//! Start, stop, restart, and (for applications) redeploy are provider
//! actions behind the action broker (ADR 0016). This module holds the
//! provider-neutral half:
//!
//! - the [`CoolifyLifecyclePort`] the provider crate implements, with its
//!   own mutating client surface (discovery stays GET-only);
//! - the ten [`ProviderAction`]s (`coolify.<application|service|database>.
//!   <start|stop|restart|redeploy>`), all running as one durable operation
//!   kind, [`LIFECYCLE_KIND`]. Risk classes: `stop` is `approve`, the rest
//!   are `auto`;
//! - [`CoolifyLifecycle`], the use cases: filing a request (the resource must
//!   exist in the account's latest observation), executing an approved
//!   request, and tailing a deployment's log.
//!
//! # Parameters and target
//!
//! A request names a resource by its Coolify uuid, its kind, and the Fleet
//! account that discovered it: ids only, never a token. The target is the
//! running-service id (`coolify:<account>:<uuid>`), so an approver reads the
//! same name the service list prints.
//!
//! # Execution
//!
//! The executor takes the per-account lock while it resolves the endpoint and
//! the token together, checks the probed Coolify version (the lifecycle
//! routes are `POST`; Coolify answers `GET` with 405 since v4.2.0, and older
//! versions are refused rather than guessed at), reads the resource's
//! current status, and then acts:
//!
//! - `stop` of a resource that is already stopped and `start` of one that is
//!   already running succeed as `unchanged` without a call, so a replay after
//!   a crash is harmless;
//! - `restart` and `redeploy` always run;
//! - a resource that vanished fails the operation (`not found`) rather than
//!   being retried into a different one.
//!
//! After the call the resource is read again, a few times at a fixed interval
//! until it shows the expected state, and the last observed status is
//! recorded in the operation result with `settled` saying whether it matched.
//! The stored discovery snapshot is not rewritten: only discovery writes
//! observations, so the status here lives in the operation result and the
//! next discovery run refreshes the read model.
//!
//! # Deployment logs
//!
//! Coolify returns a deployment's `logs` only to a token with the
//! `read:sensitive` ability. The tail works when the token has it and says
//! so plainly when it does not. Entries Coolify marks hidden are dropped, the
//! tail is bounded in lines and bytes, and the text is stripped of terminal
//! escapes and passed through the credential redaction before it is returned.
//! It is never stored. Reading logs sends the account's token, so it needs
//! `external_account.config` on the account and is audited.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fleet_core::{ExternalProviderKind, RiskClass, SensitiveString};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{CoolifyObservationPort, CoolifySnapshot};
use crate::audit::{AuditIntent, AuditMetadata};
use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::broker::{ActionRequest, Broker, BrokerError, NewActionRequest, ProviderAction};
use crate::external_accounts::{
    AccountLocks, ExternalAccount, ExternalAccountPort, ExternalCredentialStore,
};
use crate::operation::{AuditPort, NewOperation};

/// The operation kind every Coolify lifecycle action runs as.
pub const LIFECYCLE_KIND: &str = "coolify.lifecycle";
/// The oldest Coolify whose lifecycle routes this module uses: from v4.2.0
/// the routes are `POST` only (a `GET` answers 405), which this module
/// verified against `routes/api.php` of v4.2.0 through v4.4.6.
pub const MIN_VERSION: (u32, u32, u32) = (4, 2, 0);
/// The default number of log lines returned.
pub const DEFAULT_LOG_LINES: usize = 200;
/// The most log lines a caller may ask for.
pub const MAX_LOG_LINES: usize = 1000;
/// The most log bytes returned, after redaction.
pub const MAX_LOG_BYTES: usize = 64 * 1024;
/// The longest status text kept.
const MAX_STATUS_LEN: usize = 64;
/// The longest resource name kept in parameters.
const MAX_NAME_LEN: usize = 128;

/// What kind of Coolify resource an action acts on.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleResource {
    /// An application.
    Application,
    /// A one-click or Compose service.
    Service,
    /// A managed database.
    Database,
}

impl LifecycleResource {
    /// The stable id, also the Coolify route family.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Service => "service",
            Self::Database => "database",
        }
    }
}

/// A lifecycle verb.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleVerb {
    /// Start (for an application: queue a deployment).
    Start,
    /// Stop.
    Stop,
    /// Restart.
    Restart,
    /// Queue a fresh deployment (applications only).
    Redeploy,
}

impl LifecycleVerb {
    /// The stable id.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Redeploy => "redeploy",
        }
    }

    /// Parses a wire id.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "start" => Some(Self::Start),
            "stop" => Some(Self::Stop),
            "restart" => Some(Self::Restart),
            "redeploy" => Some(Self::Redeploy),
            _ => None,
        }
    }

    /// Whether `resource` offers this verb.
    #[must_use]
    pub const fn allowed_for(self, resource: LifecycleResource) -> bool {
        !matches!(
            (self, resource),
            (
                Self::Redeploy,
                LifecycleResource::Service | LifecycleResource::Database
            )
        )
    }

    /// The default risk class: stopping waits for a person.
    #[must_use]
    pub const fn risk_class(self) -> RiskClass {
        match self {
            Self::Stop => RiskClass::Approve,
            Self::Start | Self::Restart | Self::Redeploy => RiskClass::Auto,
        }
    }
}

/// The action id of one verb on one resource kind.
#[must_use]
pub fn action_id(resource: LifecycleResource, verb: LifecycleVerb) -> String {
    format!("coolify.{}.{}", resource.id(), verb.id())
}

/// What a provider refusal means to Fleet.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleFailureClass {
    /// The token was refused.
    Auth,
    /// The token is valid but lacks the ability (`deploy`, or
    /// `read:sensitive` for logs).
    Permission,
    /// The resource does not exist.
    NotFound,
    /// Coolify's rate limit applies.
    RateLimited,
    /// The Coolify version is not supported.
    Unsupported,
    /// Coolify refused the request.
    Invalid,
    /// Coolify could not be reached or answered something unusable.
    Unavailable,
}

impl LifecycleFailureClass {
    /// The stable name.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Permission => "permission",
            Self::NotFound => "not_found",
            Self::RateLimited => "rate_limited",
            Self::Unsupported => "unsupported",
            Self::Invalid => "invalid",
            Self::Unavailable => "unavailable",
        }
    }
}

/// A classified provider failure. The detail is scrubbed and bounded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleFailure {
    /// What kind of failure.
    pub class: LifecycleFailureClass,
    /// What happened, safe to print.
    pub detail: String,
}

impl LifecycleFailure {
    /// A failure of one class.
    #[must_use]
    pub fn new(class: LifecycleFailureClass, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: fleet_core::scrub_failure_detail(&detail.into()),
        }
    }
}

impl fmt::Display for LifecycleFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.class.id(), self.detail)
    }
}

impl std::error::Error for LifecycleFailure {}

/// What Coolify answered to an accepted lifecycle call.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LifecycleAck {
    /// The deployment uuid, when Coolify queued a deployment.
    pub deployment_uuid: Option<String>,
    /// Coolify's own `message` for the call (scrubbed and bounded), when it
    /// gave one. For an application start or restart that queued nothing it
    /// says why.
    pub message: Option<String>,
}

/// A resource as read back: its status string and numeric id.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResourceState {
    /// Coolify's status string (`running:healthy`, `exited`, ...).
    pub status: String,
    /// Coolify's numeric id, when the answer carried one (deployments refer
    /// to an application by it).
    pub id: Option<i64>,
}

/// One deployment as read for its log.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RawDeployment {
    /// Coolify's deployment status (`queued`, `in_progress`, `finished`,
    /// `failed`, `cancelled`).
    pub status: String,
    /// The raw `logs` value (a JSON-encoded array of entries), present only
    /// when the token may read sensitive values.
    pub logs: Option<String>,
    /// The numeric id of the application the deployment belongs to.
    pub application_id: Option<i64>,
}

/// Whether a deployment status is final.
#[must_use]
pub fn deployment_terminal(status: &str) -> bool {
    matches!(
        status,
        "finished" | "failed" | "cancelled" | "cancelled-by-user"
    )
}

/// The mutating Coolify client port. The provider crate implements it; it
/// is a separate surface from the GET-only discovery source.
#[async_trait]
pub trait CoolifyLifecyclePort: fmt::Debug + Send + Sync {
    /// Reads the instance version (`GET /version`).
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn version(
        &self,
        base_url: &str,
        token: &SensitiveString,
    ) -> Result<String, LifecycleFailure>;

    /// Runs one lifecycle call (`POST`).
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn run(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        uuid: &str,
        verb: LifecycleVerb,
    ) -> Result<LifecycleAck, LifecycleFailure>;

    /// Reads a resource's status string (`GET`).
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure; a missing resource is
    /// `NotFound`.
    async fn status(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        uuid: &str,
    ) -> Result<ResourceState, LifecycleFailure>;

    /// The newest deployment uuid of an application, if it has one.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn latest_deployment(
        &self,
        base_url: &str,
        token: &SensitiveString,
        application_uuid: &str,
    ) -> Result<Option<String>, LifecycleFailure>;

    /// Reads one deployment with its logs, when the token may see them.
    ///
    /// # Errors
    ///
    /// Fails with a classified provider failure.
    async fn deployment(
        &self,
        base_url: &str,
        token: &SensitiveString,
        deployment_uuid: &str,
    ) -> Result<RawDeployment, LifecycleFailure>;
}

/// Parses a Coolify version (`4.4.6`, `v4.4.6`, `4.4.6-rc.1`). The old
/// `4.0.0-beta.N` scheme parses to `4.0.0`, which is below [`MIN_VERSION`].
#[must_use]
pub fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    let text = text.trim().trim_matches('"');
    let text = text.strip_prefix('v').unwrap_or(text);
    let core = text.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    parts.next().is_none().then_some((major, minor, patch))
}

/// Whether `version` supports the lifecycle routes this module sends.
///
/// # Errors
///
/// Returns a caller-safe refusal naming the minimum.
pub fn check_version(version: &str) -> Result<(), LifecycleFailure> {
    let supported = parse_version(version).is_some_and(|parsed| parsed >= MIN_VERSION);
    if supported {
        Ok(())
    } else {
        Err(LifecycleFailure::new(
            LifecycleFailureClass::Unsupported,
            format!(
                "the Coolify version is not supported for lifecycle actions (v{}.{}.{} or newer is needed); update Coolify or use its console",
                MIN_VERSION.0, MIN_VERSION.1, MIN_VERSION.2
            ),
        ))
    }
}

/// The parameters of a lifecycle request, and (with the verb) the payload of
/// its operation. Ids only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleParameters {
    /// The Fleet external account that discovered the resource.
    pub account_id: String,
    /// The resource kind.
    pub resource_kind: LifecycleResource,
    /// The resource's Coolify uuid.
    pub uuid: String,
    /// The resource's name, for the approver.
    pub name: String,
}

impl LifecycleParameters {
    /// The canonical target: the running-service id.
    #[must_use]
    pub fn target(&self) -> String {
        service_id(&self.account_id, &self.uuid)
    }
}

/// The operation payload: the parameters plus the verb.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LifecyclePayload {
    #[serde(flatten)]
    parameters: LifecycleParameters,
    verb: LifecycleVerb,
}

/// The running-service id of a Coolify resource.
#[must_use]
pub fn service_id(account_id: &str, uuid: &str) -> String {
    format!("coolify:{account_id}:{uuid}")
}

/// Splits a running-service id into the account id and the resource uuid.
#[must_use]
pub fn parse_service_id(id: &str) -> Option<(&str, &str)> {
    let rest = id.strip_prefix("coolify:")?;
    let (account, uuid) = rest.rsplit_once(':')?;
    (safe_id(account) && safe_id(uuid)).then_some((account, uuid))
}

pub(crate) fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// One lifecycle provider action.
#[derive(Debug)]
pub struct CoolifyLifecycleAction {
    resource: LifecycleResource,
    verb: LifecycleVerb,
    id: String,
}

impl CoolifyLifecycleAction {
    /// The action of `verb` on `resource`.
    #[must_use]
    pub fn new(resource: LifecycleResource, verb: LifecycleVerb) -> Self {
        Self {
            resource,
            verb,
            id: action_id(resource, verb),
        }
    }
}

/// Every lifecycle action, for the controller's action registry.
#[must_use]
pub fn lifecycle_actions() -> Vec<Arc<dyn ProviderAction>> {
    let mut actions: Vec<Arc<dyn ProviderAction>> = Vec::new();
    for resource in [
        LifecycleResource::Application,
        LifecycleResource::Service,
        LifecycleResource::Database,
    ] {
        for verb in [
            LifecycleVerb::Start,
            LifecycleVerb::Stop,
            LifecycleVerb::Restart,
            LifecycleVerb::Redeploy,
        ] {
            if verb.allowed_for(resource) {
                actions.push(Arc::new(CoolifyLifecycleAction::new(resource, verb)));
            }
        }
    }
    actions
}

impl ProviderAction for CoolifyLifecycleAction {
    fn id(&self) -> &str {
        &self.id
    }

    fn operation_kind(&self) -> &str {
        LIFECYCLE_KIND
    }

    fn risk_class(&self) -> RiskClass {
        self.verb.risk_class()
    }

    fn validate(&self, target: &str, parameters: &Value) -> Result<(), String> {
        let params: LifecycleParameters =
            serde_json::from_value(parameters.clone()).map_err(|_| {
                "the parameters must be accountId, resourceKind, uuid, and name; use POST /services/{id}/actions/{verb}"
                    .to_owned()
            })?;
        validate_parameters(&params)?;
        if params.resource_kind != self.resource {
            return Err("the resourceKind does not match the action".to_owned());
        }
        if params.target() != target {
            return Err("the target must be the service id (coolify:<account>:<uuid>)".to_owned());
        }
        Ok(())
    }

    fn comparable_parameters(&self, parameters: &Value) -> Value {
        // The name is for the approver; a replay is the same request when the
        // account, kind, and uuid agree (the action id carries the verb).
        let mut comparable = parameters.clone();
        if let Some(object) = comparable.as_object_mut() {
            object.remove("name");
        }
        comparable
    }

    fn operation(&self, request: &ActionRequest) -> Result<NewOperation, String> {
        let parameters: LifecycleParameters = serde_json::from_value(request.parameters.clone())
            .map_err(|_| "the request parameters are not a lifecycle request".to_owned())?;
        // Deterministic: the parameters and the verb, nothing else.
        let payload = serde_json::to_string(&LifecyclePayload {
            parameters,
            verb: self.verb,
        })
        .map_err(|_| "the payload could not be built".to_owned())?;
        Ok(NewOperation {
            kind: LIFECYCLE_KIND.to_owned(),
            idempotency_key: None,
            deadline_at: None,
            correlation_id: None,
            payload_json: Some(payload),
            review_token: None,
        })
    }
}

fn validate_parameters(params: &LifecycleParameters) -> Result<(), String> {
    if !safe_id(&params.account_id) {
        return Err("accountId is not a valid id".to_owned());
    }
    if !safe_id(&params.uuid) {
        return Err("uuid is not a valid Coolify uuid".to_owned());
    }
    if params.name.len() > MAX_NAME_LEN || params.name.chars().any(char::is_control) {
        return Err("name is too long or has control characters".to_owned());
    }
    Ok(())
}

/// A lifecycle use-case failure.
#[derive(Debug)]
pub enum LifecycleError {
    /// The caller may not do this.
    Denied(Decision),
    /// The request is malformed or not possible for the resource.
    Invalid {
        /// What is wrong, safe to print.
        detail: String,
    },
    /// The account or resource is not known.
    NotFound {
        /// What was looked up.
        what: String,
    },
    /// The broker refused or failed.
    Broker(BrokerError),
    /// Coolify refused or could not be reached.
    Provider(LifecycleFailure),
    /// A port failed.
    Backend {
        /// Where.
        context: &'static str,
        /// The failure.
        detail: String,
    },
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::Invalid { detail } => write!(f, "invalid request: {detail}"),
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Broker(error) => write!(f, "{error}"),
            Self::Provider(failure) => write!(f, "Coolify: {failure}"),
            Self::Backend { context, .. } => write!(f, "{context} failed"),
        }
    }
}

impl std::error::Error for LifecycleError {}

fn invalid(detail: impl Into<String>) -> LifecycleError {
    LifecycleError::Invalid {
        detail: detail.into(),
    }
}

/// What a caller asks for.
#[derive(Clone, Debug)]
pub struct LifecycleRequest {
    /// The running-service id.
    pub service_id: String,
    /// The verb.
    pub verb: LifecycleVerb,
    /// Why, for the approver.
    pub reason: String,
    /// Where the request came from.
    pub origin: String,
    /// The correlation identity.
    pub correlation_id: Option<String>,
    /// A key making a retry return the request already made.
    pub idempotency_key: Option<String>,
}

/// How an executed action ended. Recorded as the operation result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleOutcome {
    /// `started`, `stopped`, `restarted`, `redeploy_queued`, `start_queued`,
    /// `skipped` (Coolify queued nothing for an application start or
    /// restart; see `message`), or `unchanged`.
    pub outcome: String,
    /// The verb.
    pub verb: String,
    /// The resource kind.
    pub resource_kind: String,
    /// The Coolify uuid.
    pub uuid: String,
    /// The status before the call.
    pub previous_status: String,
    /// The status read after the call.
    pub observed_status: String,
    /// Whether the end state was verified: the deployment finished, or a
    /// stop or a service/database start shows its expected status. A restart
    /// of a service or database cannot be verified and is never settled.
    pub settled: bool,
    /// The deployment Coolify queued, when it did (confirmed by reading it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_uuid: Option<String>,
    /// That deployment's last observed status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_status: Option<String>,
    /// Coolify's own message for the call, scrubbed and bounded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// One deployment's log, bounded and redacted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogTail {
    /// The deployment.
    pub deployment_uuid: String,
    /// Coolify's deployment status.
    pub deployment_status: String,
    /// The redacted log lines, oldest first.
    pub lines: Vec<String>,
    /// Whether earlier lines (or bytes) were cut.
    pub truncated: bool,
    /// Whether redaction changed any line.
    pub redacted: bool,
}

/// How long the post-action re-read waits.
#[derive(Clone, Copy, Debug)]
pub struct Settle {
    /// The most reads after the call.
    pub attempts: u32,
    /// The pause between reads.
    pub interval: Duration,
}

impl Default for Settle {
    fn default() -> Self {
        Self {
            attempts: 4,
            interval: Duration::from_secs(2),
        }
    }
}

/// The Coolify lifecycle use cases.
#[derive(Debug)]
pub struct CoolifyLifecycle {
    accounts: Arc<dyn ExternalAccountPort>,
    credentials: Arc<dyn ExternalCredentialStore>,
    port: Arc<dyn CoolifyLifecyclePort>,
    observations: Arc<dyn CoolifyObservationPort>,
    audit: Arc<dyn AuditPort>,
    settle: Settle,
}

impl CoolifyLifecycle {
    /// Composes the use cases from their ports.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn ExternalAccountPort>,
        credentials: Arc<dyn ExternalCredentialStore>,
        port: Arc<dyn CoolifyLifecyclePort>,
        observations: Arc<dyn CoolifyObservationPort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            accounts,
            credentials,
            port,
            observations,
            audit,
            settle: Settle::default(),
        }
    }

    /// Replaces the post-action re-read timing (tests use no pause).
    #[must_use]
    pub fn with_settle(mut self, settle: Settle) -> Self {
        self.settle = settle;
        self
    }

    fn require(
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        action: Permission,
        resource: Option<&str>,
    ) -> Result<(), LifecycleError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action,
                resource,
            },
        )
        .map(|_| ())
        .map_err(LifecycleError::Denied)
    }

    pub(crate) async fn coolify_account(
        &self,
        id: &str,
    ) -> Result<ExternalAccount, LifecycleError> {
        let account = self.accounts.get(id).await.map_err(|detail| {
            if detail.contains("not found") {
                LifecycleError::NotFound {
                    what: format!("account {id}"),
                }
            } else {
                LifecycleError::Backend {
                    context: "accounts",
                    detail,
                }
            }
        })?;
        if account.kind != ExternalProviderKind::Coolify {
            return Err(invalid(format!("account {id} is not a Coolify account")));
        }
        Ok(account)
    }

    /// The endpoint and the token together, under the account lock.
    pub(crate) async fn resolve(
        &self,
        id: &str,
    ) -> Result<(ExternalAccount, SensitiveString), LifecycleError> {
        let _account_lock = AccountLocks::global().lock(id).await;
        let account = self.coolify_account(id).await?;
        if account.policy_violation().is_some() {
            return Err(invalid(
                "a Coolify base URL must use https (a loopback address is allowed); edit the account to use https",
            ));
        }
        let token = self
            .credentials
            .load(id)
            .await
            .map_err(|error| LifecycleError::Backend {
                context: "credentials",
                detail: error.to_string(),
            })?
            .ok_or_else(|| {
                invalid(format!(
                    "the credential for account {} is not in the secret store; replace it",
                    account.label
                ))
            })?;
        Ok((account, SensitiveString::new(token)))
    }

    /// The kind and name of a resource in the account's latest observation.
    pub(super) async fn observed_resource(
        &self,
        account_id: &str,
        uuid: &str,
    ) -> Result<(LifecycleResource, String), LifecycleError> {
        let loaded =
            self.observations
                .load(account_id)
                .await
                .map_err(|detail| LifecycleError::Backend {
                    context: "coolify observations",
                    detail,
                })?;
        let Some((snapshot, _)) = loaded else {
            return Err(LifecycleError::NotFound {
                what: format!("a discovery of account {account_id}; run one first"),
            });
        };
        find_resource(&snapshot, uuid).ok_or_else(|| LifecycleError::NotFound {
            what: "that resource in the latest Coolify observation; run discovery".to_owned(),
        })
    }

    /// Checks the probed Coolify version against [`MIN_VERSION`]; the
    /// settings routes share the lifecycle routes' floor.
    pub(super) async fn require_supported_version(
        &self,
        base_url: &str,
        token: &SensitiveString,
    ) -> Result<(), LifecycleFailure> {
        let version = self.port.version(base_url, token).await?;
        check_version(&version)
    }

    /// Runs one lifecycle call, for a settings change that asked to be
    /// applied.
    pub(super) async fn run_verb(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        uuid: &str,
        verb: LifecycleVerb,
    ) -> Result<LifecycleAck, LifecycleFailure> {
        self.port.run(base_url, token, resource, uuid, verb).await
    }

    /// Files a lifecycle action request for a running service. The resource
    /// must be in the account's latest observation; the broker decides by
    /// risk class.
    ///
    /// # Errors
    ///
    /// Fails on denial, a malformed id, an unknown resource, a verb the
    /// resource does not offer, or a broker refusal.
    pub async fn request_action(
        &self,
        broker: &Broker,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        request: LifecycleRequest,
        now: i64,
    ) -> Result<ActionRequest, LifecycleError> {
        Self::require(authorizer, principal, Permission::ExternalAccountRead, None)?;
        let (account_id, uuid) = parse_service_id(&request.service_id).ok_or_else(|| {
            invalid("the service id must be a Coolify service (coolify:<account>:<uuid>)")
        })?;
        self.coolify_account(account_id).await?;
        let (resource, name) = self.observed_resource(account_id, uuid).await?;
        if !request.verb.allowed_for(resource) {
            return Err(invalid(format!(
                "a {} cannot be {}ed; use restart",
                resource.id(),
                request.verb.id()
            )));
        }
        let parameters = LifecycleParameters {
            account_id: account_id.to_owned(),
            resource_kind: resource,
            uuid: uuid.to_owned(),
            name: bounded_name(&name),
        };
        let target = parameters.target();
        let parameters =
            serde_json::to_value(&parameters).map_err(|error| LifecycleError::Backend {
                context: "parameters",
                detail: error.to_string(),
            })?;
        broker
            .create(
                authorizer,
                &principal.id,
                NewActionRequest {
                    action_id: action_id(resource, request.verb),
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

    /// Runs an approved request: the operation executor calls this with the
    /// operation's payload.
    ///
    /// The request may have been filed through the generic `POST /requests`
    /// route, which cannot check anything against Coolify, so everything the
    /// approver read is checked again here against the account's latest
    /// observation: the uuid must be known, and its kind and name must still
    /// be the ones in the request. Anything else fails with "re-file".
    ///
    /// # Errors
    ///
    /// Fails with a caller-safe reason: a malformed payload, a request that no
    /// longer matches the observation, a gone account or resource, an
    /// unsupported Coolify version, a provider failure, or a deployment
    /// Coolify did not confirm.
    #[allow(clippy::too_many_lines)]
    pub async fn execute(&self, kind: &str, payload: &str) -> Result<LifecycleOutcome, String> {
        if kind != LIFECYCLE_KIND {
            return Err(format!("{kind} is not a Coolify lifecycle operation"));
        }
        let payload: LifecyclePayload = serde_json::from_str(payload)
            .map_err(|_| "the operation payload is not a Coolify lifecycle request".to_owned())?;
        let LifecyclePayload {
            parameters: params,
            verb,
        } = payload;
        validate_parameters(&params)?;
        if !verb.allowed_for(params.resource_kind) {
            return Err("the verb is not offered for the resource kind".to_owned());
        }
        let resource = params.resource_kind;
        let uuid = params.uuid.as_str();
        // What the approver read must still be true.
        let (observed_kind, observed_name) = self
            .observed_resource(&params.account_id, uuid)
            .await
            .map_err(|error| match error {
                LifecycleError::NotFound { .. } => {
                    "the resource is not in the account's latest Coolify observation; run discovery and re-file the request"
                        .to_owned()
                }
                LifecycleError::Backend { context, .. } => format!("{context} failed"),
                other => other.to_string(),
            })?;
        if observed_kind != resource || bounded_name(&observed_name) != params.name {
            return Err(
                "the request no longer matches the latest Coolify observation (the resource's kind or name differs); nothing was changed, so re-file the request"
                    .to_owned(),
            );
        }
        let (account, token) =
            self.resolve(&params.account_id)
                .await
                .map_err(|error| match error {
                    LifecycleError::Backend { context, .. } => format!("{context} failed"),
                    other => other.to_string(),
                })?;
        let base = account.base_url.as_str();
        let provider = |failure: LifecycleFailure| failure.to_string();
        let version = self.port.version(base, &token).await.map_err(provider)?;
        check_version(&version).map_err(provider)?;

        // The resource must still exist; a gone resource is not retried.
        let previous = self
            .port
            .status(base, &token, resource, uuid)
            .await
            .map_err(|failure| match failure.class {
                LifecycleFailureClass::NotFound => {
                    "the resource no longer exists in Coolify; nothing was changed".to_owned()
                }
                _ => failure.to_string(),
            })?
            .status;
        let previous_state = coarse_state(&previous);
        let unchanged = match verb {
            LifecycleVerb::Stop => previous_state == Coarse::Stopped,
            LifecycleVerb::Start => previous_state == Coarse::Running,
            LifecycleVerb::Restart | LifecycleVerb::Redeploy => false,
        };
        let mut result = LifecycleOutcome {
            outcome: "unchanged".to_owned(),
            verb: verb.id().to_owned(),
            resource_kind: resource.id().to_owned(),
            uuid: uuid.to_owned(),
            previous_status: previous.clone(),
            observed_status: previous,
            settled: true,
            deployment_uuid: None,
            deployment_status: None,
            message: None,
        };
        if unchanged {
            return Ok(result);
        }
        let ack = self
            .port
            .run(base, &token, resource, uuid, verb)
            .await
            .map_err(provider)?;
        result.message = ack.message.clone();
        let says = ack
            .message
            .as_deref()
            .map(|m| format!(" (Coolify said: {m})"))
            .unwrap_or_default();
        // A redeploy that queued nothing is a failure: Coolify answers HTTP
        // 200 with the reason in `message` for an unauthorized resource, a
        // full queue, or a deployment already queued.
        if verb == LifecycleVerb::Redeploy && ack.deployment_uuid.is_none() {
            return Err(format!("Coolify did not queue a deployment{says}"));
        }
        let outcome = match (verb, resource, ack.deployment_uuid.is_some()) {
            (LifecycleVerb::Stop, _, _) => "stopped",
            (LifecycleVerb::Redeploy, _, _) => "redeploy_queued",
            // An application start or restart that queued no deployment was
            // skipped by Coolify (for example one is already queued).
            (
                LifecycleVerb::Start | LifecycleVerb::Restart,
                LifecycleResource::Application,
                false,
            ) => "skipped",
            (LifecycleVerb::Restart, _, _) => "restarted",
            (LifecycleVerb::Start, LifecycleResource::Application, true) => "start_queued",
            (LifecycleVerb::Start, _, _) => "started",
        };
        outcome.clone_into(&mut result.outcome);
        result.settled = false;
        if outcome == "skipped" {
            // Nothing was started by this request; report the status as it is.
            if let Ok(state) = self.port.status(base, &token, resource, uuid).await {
                result.observed_status = state.status;
            }
            return Ok(result);
        }
        if let Some(deployment) = ack.deployment_uuid {
            // Coolify's answer names a deployment: confirm it exists, then
            // follow its status (bounded).
            let mut seen = self
                .port
                .deployment(base, &token, &deployment)
                .await
                .map_err(|failure| {
                    format!(
                        "Coolify named deployment {deployment} but it could not be confirmed ({})",
                        failure.class.id()
                    )
                })?;
            result.deployment_uuid = Some(deployment.clone());
            let mut polls = 0;
            while !deployment_terminal(&seen.status) && polls < self.settle.attempts {
                polls += 1;
                if !self.settle.interval.is_zero() {
                    tokio::time::sleep(self.settle.interval).await;
                }
                match self.port.deployment(base, &token, &deployment).await {
                    Ok(next) => seen = next,
                    Err(_) => break,
                }
            }
            let status = scrub_status(&seen.status);
            result.settled = status == "finished";
            result.deployment_status = Some(status);
            if let Ok(state) = self.port.status(base, &token, resource, uuid).await {
                result.observed_status = state.status;
            }
            return Ok(result);
        }
        // No deployment: read the resource again, a bounded number of times,
        // until it shows the expected state. Only a stop and a service or
        // database start have an end state to verify; a restart's "running"
        // is the same before and after, so it is never reported settled.
        let expected = match verb {
            LifecycleVerb::Stop => Some(Coarse::Stopped),
            LifecycleVerb::Start => Some(Coarse::Running),
            _ => None,
        };
        for _ in 0..self.settle.attempts {
            if !self.settle.interval.is_zero() {
                tokio::time::sleep(self.settle.interval).await;
            }
            match self.port.status(base, &token, resource, uuid).await {
                Ok(state) => {
                    result.settled = expected == Some(coarse_state(&state.status));
                    result.observed_status = state.status;
                    if result.settled {
                        break;
                    }
                }
                Err(failure) => {
                    // The call was accepted; say the verification failed.
                    result.observed_status = format!("unreadable ({})", failure.class.id());
                    break;
                }
            }
        }
        Ok(result)
    }

    /// Tails the log of an application's deployment: the newest one, or the
    /// named one, which must belong to this application. Bounded, redacted,
    /// never stored.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown service, a service that is not an
    /// application, a deployment of another application, a token without
    /// `read:sensitive` (reported plainly), a log in a shape Fleet does not
    /// recognize (nothing is returned), or a provider failure.
    pub async fn logs(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        service_id: &str,
        deployment: Option<&str>,
        lines: Option<usize>,
    ) -> Result<LogTail, LifecycleError> {
        let (account_id, uuid) = parse_service_id(service_id).ok_or_else(|| {
            invalid("the service id must be a Coolify service (coolify:<account>:<uuid>)")
        })?;
        // Reading logs sends the account's token and returns text from the
        // deployment's build: the same privilege as running discovery, so it
        // needs `external_account.config` on the account, consistently.
        Self::require(
            authorizer,
            principal,
            Permission::ExternalAccountConfig,
            Some(account_id),
        )?;
        let wanted = lines.unwrap_or(DEFAULT_LOG_LINES);
        if wanted == 0 || wanted > MAX_LOG_LINES {
            return Err(invalid(format!("lines must be 1 to {MAX_LOG_LINES}")));
        }
        if let Some(deployment) = deployment
            && !safe_id(deployment)
        {
            return Err(invalid("the deployment is not a valid Coolify uuid"));
        }
        self.coolify_account(account_id).await?;
        let (resource, _) = self.observed_resource(account_id, uuid).await?;
        if resource != LifecycleResource::Application {
            return Err(invalid("only an application has deployment logs"));
        }
        let (account, token) = self.resolve(account_id).await?;
        let base = account.base_url.as_str();
        let provider = LifecycleError::Provider;
        let version = self.port.version(base, &token).await.map_err(provider)?;
        check_version(&version).map_err(LifecycleError::Provider)?;
        // The application's own id, to check the deployment against.
        let application_id = self
            .port
            .status(base, &token, LifecycleResource::Application, uuid)
            .await
            .map_err(LifecycleError::Provider)?
            .id
            .ok_or_else(|| {
                invalid("Coolify did not report the application's id, so a deployment cannot be matched to it")
            })?;
        let deployment_uuid = match deployment {
            Some(deployment) => deployment.to_owned(),
            None => self
                .port
                .latest_deployment(base, &token, uuid)
                .await
                .map_err(LifecycleError::Provider)?
                .ok_or_else(|| LifecycleError::NotFound {
                    what: "a deployment of this application".to_owned(),
                })?,
        };
        self.audit(
            principal,
            account_id,
            "coolify_logs_read",
            &[("uuid", uuid), ("deployment", &deployment_uuid)],
        )
        .await?;
        let raw = self
            .port
            .deployment(base, &token, &deployment_uuid)
            .await
            .map_err(LifecycleError::Provider)?;
        // Fail closed: a deployment of another application (or one Coolify
        // does not attribute) is never shown through this service.
        if raw.application_id != Some(application_id) {
            return Err(invalid(
                "that deployment does not belong to this application",
            ));
        }
        let Some(logs) = raw.logs else {
            return Err(LifecycleError::Provider(LifecycleFailure::new(
                LifecycleFailureClass::Permission,
                "Coolify returns deployment logs only to a token with the read:sensitive ability; give the account's token that ability or read the log in Coolify",
            )));
        };
        let mut tail = tail_logs(&logs, wanted, MAX_LOG_BYTES).map_err(|detail| {
            LifecycleError::Provider(LifecycleFailure::new(
                LifecycleFailureClass::Invalid,
                detail,
            ))
        })?;
        tail.deployment_uuid = deployment_uuid;
        tail.deployment_status = scrub_status(&raw.status);
        Ok(tail)
    }

    async fn audit(
        &self,
        principal: &ActingPrincipal,
        account_id: &str,
        event: &str,
        facts: &[(&str, &str)],
    ) -> Result<(), LifecycleError> {
        let backend = |error: String| LifecycleError::Backend {
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

/// The kind and name of the resource with `uuid` in a snapshot.
pub(super) fn find_resource(
    snapshot: &CoolifySnapshot,
    uuid: &str,
) -> Option<(LifecycleResource, String)> {
    if let Some(item) = snapshot.applications.items.iter().find(|i| i.uuid == uuid) {
        return Some((LifecycleResource::Application, item.name.clone()));
    }
    if let Some(item) = snapshot.services.items.iter().find(|i| i.uuid == uuid) {
        return Some((LifecycleResource::Service, item.name.clone()));
    }
    snapshot
        .databases
        .items
        .iter()
        .find(|i| i.uuid == uuid)
        .map(|item| (LifecycleResource::Database, item.name.clone()))
}

pub(crate) fn bounded_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_LEN)
        .collect()
}

/// What a Coolify status says about whether the resource is up.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Coarse {
    Running,
    Stopped,
    Other,
}

/// Coolify statuses read `running:healthy`, `running:unknown`,
/// `exited:unhealthy`, `degraded:unhealthy`, and so on; only the part before
/// the colon says whether it is up.
fn coarse_state(status: &str) -> Coarse {
    let status = status.trim().to_ascii_lowercase();
    match status.split(':').next().unwrap_or_default() {
        "running" => Coarse::Running,
        "exited" | "stopped" | "created" | "dead" => Coarse::Stopped,
        _ => Coarse::Other,
    }
}

/// A status as recorded: a short plain token.
#[must_use]
pub fn scrub_status(status: &str) -> String {
    status
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-' | '(' | ')' | ',' | '.' | ' ')
        })
        .take(MAX_STATUS_LEN)
        .collect()
}

/// Turns Coolify's `logs` value into a bounded, redacted tail.
///
/// The value is a JSON array of entries (`output`, `hidden`, ...), usually
/// carried as a JSON-encoded string. Hidden entries are dropped and entries
/// without text are skipped. Any other shape fails closed: no raw text is
/// returned, because it could not be attributed to entries and so could not
/// be filtered.
///
/// Redaction recognizes credential shapes (Authorization and bearer headers,
/// `key=value` secret pairs, URL credentials, private-key blocks). A secret
/// that a build step prints as ordinary text, such as a build variable echoed
/// by a script, has no shape and is not detectable; that residual risk is why
/// reading logs needs `external_account.config` and is audited.
///
/// # Errors
///
/// Returns a caller-safe reason when the shape is not the documented one.
pub fn tail_logs(raw: &str, max_lines: usize, max_bytes: usize) -> Result<LogTail, String> {
    const UNKNOWN: &str = "the deployment log is not in a shape Fleet recognizes, so nothing is returned; read it in Coolify";
    let parsed: Value = serde_json::from_str(raw).map_err(|_| UNKNOWN.to_owned())?;
    let entries = match parsed {
        Value::String(inner) => {
            serde_json::from_str::<Value>(&inner).map_err(|_| UNKNOWN.to_owned())?
        }
        other => other,
    };
    let Value::Array(entries) = entries else {
        return Err(UNKNOWN.to_owned());
    };
    let mut text = String::new();
    for entry in &entries {
        if !entry.is_object() {
            return Err(UNKNOWN.to_owned());
        }
        if entry.get("hidden").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        if let Some(output) = entry.get("output").and_then(Value::as_str) {
            text.push_str(output);
            text.push('\n');
        }
    }
    // Strip terminal escapes and flatten control characters first so a
    // colour code cannot split a credential from its name, then redact.
    let flattened = fleet_core::flatten_control_characters(&text);
    let mut all: Vec<&str> = flattened.lines().filter(|l| !l.trim().is_empty()).collect();
    let mut truncated = false;
    if all.len() > max_lines {
        all.drain(..all.len() - max_lines);
        truncated = true;
    }
    // Redact the kept window as one text, so a multi-line credential block
    // is recognized, then split again.
    let window = all.join("\n");
    let redacted_text = fleet_core::redact_credentials(&window);
    let redacted = redacted_text != window;
    let mut kept: Vec<String> = redacted_text.lines().map(str::to_owned).collect();
    // Bound the bytes from the front: the tail is the useful part.
    let mut bytes: usize = kept.iter().map(|l| l.len() + 1).sum();
    while bytes > max_bytes && !kept.is_empty() {
        let dropped = kept.remove(0);
        bytes -= dropped.len() + 1;
        truncated = true;
    }
    if let Some(first) = kept.first_mut()
        && first.len() > max_bytes
    {
        let mut cut = first.len() - max_bytes;
        while !first.is_char_boundary(cut) {
            cut += 1;
        }
        *first = first[cut..].to_owned();
        truncated = true;
    }
    Ok(LogTail {
        deployment_uuid: String::new(),
        deployment_status: String::new(),
        lines: kept,
        truncated,
        redacted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn versions_parse_and_gate() {
        assert_eq!(parse_version("4.4.6"), Some((4, 4, 6)));
        assert_eq!(parse_version("v4.2.0"), Some((4, 2, 0)));
        assert_eq!(parse_version("\"4.3.1\"\n"), Some((4, 3, 1)));
        assert_eq!(parse_version("4.0.0-beta.420"), Some((4, 0, 0)));
        assert_eq!(parse_version("latest"), None);
        assert!(check_version("4.4.6").is_ok());
        assert!(check_version("4.2.0").is_ok());
        assert!(check_version("4.1.9").is_err());
        assert!(check_version("4.0.0-beta.420").is_err());
        assert!(check_version("nightly").is_err());
    }

    #[test]
    fn service_ids_round_trip() {
        let id = service_id("acct-1", "appweb0001");
        assert_eq!(parse_service_id(&id), Some(("acct-1", "appweb0001")));
        assert_eq!(parse_service_id("docker:m:c"), None);
        assert_eq!(parse_service_id("coolify:a/b:c"), None);
        assert_eq!(parse_service_id("coolify:only"), None);
    }

    #[test]
    fn risk_classes_and_verbs_per_resource() {
        let actions = lifecycle_actions();
        assert_eq!(actions.len(), 10);
        for action in &actions {
            let stop = action.id().rsplit('.').next() == Some("stop");
            assert_eq!(
                action.risk_class(),
                if stop {
                    RiskClass::Approve
                } else {
                    RiskClass::Auto
                },
                "{}",
                action.id()
            );
            assert_eq!(action.operation_kind(), LIFECYCLE_KIND);
        }
        assert!(
            !actions
                .iter()
                .any(|a| a.id() == "coolify.service.redeploy"
                    || a.id() == "coolify.database.redeploy")
        );
    }

    #[test]
    fn log_tail_drops_hidden_bounds_and_redacts() {
        let entries = json!([
            {"output": "building", "hidden": false, "order": 1},
            {"output": "secret internal step", "hidden": true, "order": 2},
            {"output": "curl -H 'Authorization: Bearer abcdef0123456789abcdef0123456789' x", "hidden": false},
            {"output": "\u{1b}[32mdone\u{1b}[0m", "hidden": false},
        ]);
        // Coolify carries the array as a JSON-encoded string.
        let raw = serde_json::to_string(&entries.to_string()).unwrap();
        let tail = tail_logs(&raw, 10, MAX_LOG_BYTES).unwrap();
        let text = tail.lines.join("\n");
        assert!(!text.contains("secret internal step"));
        assert!(!text.contains("abcdef0123456789abcdef0123456789"), "{text}");
        assert!(text.contains("building") && text.contains("done"));
        assert!(tail.redacted && !tail.truncated);
        let short = tail_logs(&raw, 1, MAX_LOG_BYTES).unwrap();
        assert_eq!(short.lines.len(), 1);
        assert!(short.truncated);
        let tiny = tail_logs(&raw, 10, 12).unwrap();
        // An unknown shape fails closed instead of returning raw text.
        assert!(tail_logs("plain text with token=abc", 10, 100).is_err());
        assert!(tail_logs("{\"logs\": []}", 10, 100).is_err());
        assert!(tail_logs("[\"just a string\"]", 10, 100).is_err());
        assert!(tiny.truncated);
        assert!(tiny.lines.iter().map(|l| l.len() + 1).sum::<usize>() <= 13);
    }
}
