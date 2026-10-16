//! The action broker (FM-1040): agents ask Fleet to run a typed provider
//! action, and policy or a human decides.
//!
//! A request is a durable [`ActionRequest`]. The lifecycle is the pure state
//! machine in `fleet_core` (`pending -> approved | denied | expired`,
//! `approved -> executing`, `executing -> succeeded | failed`). The broker
//! adds three things on top of it:
//!
//! - **Policy.** Every provider action declares a [`RiskClass`]; an operator
//!   override (`FLEET_ACTION_POLICY`) may raise or lower it per action id.
//!   `auto` runs on request, `approve` waits for a human, `deny` is recorded
//!   as denied. Before authenticated identities (M8) this is a guardrail
//!   against agent mistakes, keyed on risk class; it is not a boundary
//!   against a hostile LAN caller (ADR 0016).
//! - **Execution through the normal operation path.** An approved request
//!   asks its action for a [`NewOperation`] and creates it with
//!   [`Operations::create`] under the deciding principal, so authorization,
//!   idempotency, and audit are exactly those of any other operation. The
//!   operation's idempotency key is the request id.
//! - **Exactly-once decisions.** Every transition is a compare-and-set on the
//!   stored state, committed with its audit event. Of any number of
//!   concurrent approvals, exactly one wins and starts the operation.
//!
//! # Expiry is lazy
//!
//! A pending request expires `FLEET_ACTION_REQUEST_TTL_SECONDS` after it was
//! made. Expiry is evaluated when a request is read or decided, not by a
//! background sweeper: it is a pure function of the stored deadline, so a
//! restart or a missed tick cannot leave a request approvable past it. The
//! approve and deny compare-and-set also re-check the deadline in the same
//! statement, so there is no window between the check and the decision. The
//! expiry transition is audited when it is first observed.
//!
//! The same lazy reconciliation moves an `executing` request to `succeeded`
//! or `failed` from its linked operation.
//!
//! # Secrets
//!
//! Parameters are structured and secret-free. They are checked with the
//! `fleet_core` redaction helpers, and a request whose parameters would be
//! changed by them (a credential-like value, or a secret-named key) is
//! refused. Parameters are stored and served, never audited; audit metadata
//! carries only ids, the target, and states.
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use fleet_core::{
    ActionRequestState, IdGenerator as _, RiskClass, action_request_deadline_passed,
    can_transition_action_request,
};

use crate::audit::{AuditIntent, AuditMetadata};
use crate::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId, authorize};
use crate::operation::{
    BROKER_IDEMPOTENCY_PREFIX, NewOperation, OperationUseCaseError, Operations, PortFailure,
};

/// The default time a request may wait for a decision: one day.
pub const DEFAULT_REQUEST_TTL_SECONDS: u64 = 24 * 60 * 60;
/// The shortest configurable request lifetime.
pub const MIN_REQUEST_TTL_SECONDS: u64 = 60;
/// The longest configurable request lifetime: a week.
pub const MAX_REQUEST_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
/// The environment variable holding the request lifetime in seconds.
pub const REQUEST_TTL_VAR: &str = "FLEET_ACTION_REQUEST_TTL_SECONDS";
/// The environment variable holding the per-action risk overrides, as
/// comma-separated `action.id=auto|approve|deny` pairs.
pub const POLICY_VAR: &str = "FLEET_ACTION_POLICY";

/// The largest serialized parameter object.
pub const MAX_PARAMETERS_BYTES: usize = 8 * 1024;
/// The longest target.
pub const MAX_TARGET_LEN: usize = 256;
/// The longest reason or decision note.
pub const MAX_REASON_LEN: usize = 1000;
/// The longest action id.
pub const MAX_ACTION_ID_LEN: usize = 96;
/// The longest idempotency key.
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 128;
/// The longest origin label.
pub const MAX_ORIGIN_LEN: usize = 64;
/// How deep parameters may nest.
const MAX_PARAMETER_DEPTH: usize = 6;
/// The largest page of requests.
pub const MAX_LIST_LIMIT: u32 = 200;
/// How long an `approved` request may wait for its operation to be created
/// before a read calls it failed: the controller stopped in between.
pub const APPROVED_STUCK_GRACE_MILLIS: i64 = 60_000;

/// The actor recorded for transitions no person made: expiry and the sync
/// from an operation's outcome.
pub const SYSTEM_ACTOR: &str = "system:action-broker";
/// The decider recorded when `auto` policy approves a request.
pub const POLICY_AUTO: &str = "policy:auto";
/// The decider recorded when `deny` policy refuses a request.
pub const POLICY_DENY: &str = "policy:deny";

/// One durable action request.
#[derive(Clone, Debug, PartialEq)]
pub struct ActionRequest {
    /// The request's identity.
    pub id: String,
    /// The principal that asked.
    pub requester: String,
    /// Where the request came from (`api`, later `fleetctl` or `mcp`).
    pub origin: String,
    /// The provider action's id, for example `coolify.application.redeploy`.
    pub action_id: String,
    /// What the action acts on, in the provider's terms.
    pub target: String,
    /// The structured, secret-free parameters.
    pub parameters: serde_json::Value,
    /// The effective risk class when the request was made.
    pub risk_class: RiskClass,
    /// Why the requester wants it, for the approver.
    pub reason: String,
    /// Where the request is in its life.
    pub state: ActionRequestState,
    /// Who approved or denied it: a principal, `policy:auto`, or
    /// `policy:deny`.
    pub decided_by: Option<String>,
    /// When it was decided (epoch milliseconds).
    pub decided_at: Option<i64>,
    /// A denier's note, when one was given (scrubbed).
    pub decision_note: Option<String>,
    /// The durable operation that executes it, once created.
    pub operation_id: Option<String>,
    /// Why it failed, when it did (scrubbed and bounded).
    pub failure: Option<String>,
    /// The correlation identity of the request that made it.
    pub correlation_id: Option<String>,
    /// The requester's idempotency key, when one was given. Never served.
    pub idempotency_key: Option<String>,
    /// When it was made (epoch milliseconds).
    pub created_at: i64,
    /// When an undecided request expires (epoch milliseconds).
    pub expires_at: i64,
    /// The last change (epoch milliseconds).
    pub updated_at: i64,
}

/// One compare-and-set transition.
#[derive(Clone, Debug)]
pub struct TransitionUpdate {
    /// The state the request must be in.
    pub from: ActionRequestState,
    /// The state it moves to.
    pub to: ActionRequestState,
    /// Who decided, for `approved` and `denied`.
    pub decided_by: Option<String>,
    /// A denier's note.
    pub decision_note: Option<String>,
    /// The operation, for `executing`.
    pub operation_id: Option<String>,
    /// The failure, for `failed`.
    pub failure: Option<String>,
    /// When (epoch milliseconds).
    pub at: i64,
    /// Also require the request's deadline to be after `at`, in the same
    /// statement. Set for the decisions a human makes.
    pub require_unexpired: bool,
}

/// Storage for action requests. Mechanics only: authorization and the rules
/// belong to [`Broker`].
#[async_trait]
pub trait ActionRequestPort: fmt::Debug + Send + Sync {
    /// Stores a new request and its audit event in one transaction.
    ///
    /// # Errors
    ///
    /// Fails when the store refuses; neither the row nor the event is kept.
    async fn insert(&self, request: &ActionRequest, audit: &AuditIntent) -> Result<(), String>;

    /// Appends an audit event with no state change: a request refused by
    /// policy leaves no row, only this.
    ///
    /// # Errors
    ///
    /// Fails when the store refuses; the event is not kept.
    async fn record_audit(&self, audit: &AuditIntent) -> Result<(), String>;

    /// The requester's request made with this idempotency key, when any.
    ///
    /// # Errors
    ///
    /// Fails when the store errors.
    async fn find_by_idempotency(
        &self,
        requester: &str,
        key: &str,
    ) -> Result<Option<ActionRequest>, String>;

    /// Reads one request.
    ///
    /// # Errors
    ///
    /// Fails when the store errors.
    async fn get(&self, id: &str) -> Result<Option<ActionRequest>, String>;

    /// Lists requests, newest first, optionally of one state.
    ///
    /// # Errors
    ///
    /// Fails when the store errors.
    async fn list(
        &self,
        state: Option<ActionRequestState>,
        limit: u32,
    ) -> Result<Vec<ActionRequest>, String>;

    /// Applies a transition only when the stored state is still
    /// `update.from` (and, when asked, the deadline is still ahead), and
    /// appends its audit event in the same transaction. Answers the updated
    /// request, or `None` when the compare-and-set lost: nothing changed and
    /// nothing was audited.
    ///
    /// # Errors
    ///
    /// Fails when the store errors; nothing is kept.
    async fn transition(
        &self,
        id: &str,
        update: &TransitionUpdate,
        audit: &AuditIntent,
    ) -> Result<Option<ActionRequest>, String>;
}

/// A provider action the broker can run. Providers implement this in their
/// own crate or module and register it in the [`ActionRegistry`]; the broker
/// knows nothing about Coolify or Cloudflare.
pub trait ProviderAction: fmt::Debug + Send + Sync {
    /// The action's stable id (`<provider>.<noun>.<verb>`).
    fn id(&self) -> &str;

    /// The operation kind this action creates. The generic operation surface
    /// refuses it, so the action is the only way to run it.
    fn operation_kind(&self) -> &str;

    /// The default risk class, before any operator override.
    fn risk_class(&self) -> RiskClass;

    /// Validates the target and the (already secret-checked) parameters.
    ///
    /// # Errors
    ///
    /// Returns a caller-safe message when the request is malformed.
    fn validate(&self, target: &str, parameters: &serde_json::Value) -> Result<(), String>;

    /// The durable operation that carries out an approved request. The
    /// broker sets the idempotency key and correlation id.
    ///
    /// The result must be deterministic for the same request: no
    /// timestamps, nonces, or random ids. Recovery of a stuck approved
    /// request builds the operation again and compares its kind and payload
    /// with the operation already holding the idempotency key; a payload that
    /// differs between calls would fail a request whose operation is fine.
    ///
    /// # Errors
    ///
    /// Returns a caller-safe message when the operation cannot be built.
    fn operation(&self, request: &ActionRequest) -> Result<NewOperation, String>;
}

/// The provider actions the controller offers, by id.
#[derive(Debug, Default)]
pub struct ActionRegistry {
    actions: BTreeMap<String, Arc<dyn ProviderAction>>,
}

impl ActionRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an action.
    ///
    /// # Errors
    ///
    /// Fails on a malformed or duplicate id.
    pub fn register(&mut self, action: Arc<dyn ProviderAction>) -> Result<(), String> {
        let id = action.id().to_owned();
        if !valid_action_id(&id) {
            return Err(format!("{id:?} is not a valid action id"));
        }
        if self.actions.contains_key(&id) {
            return Err(format!("action {id} is already registered"));
        }
        self.actions.insert(id, action);
        Ok(())
    }

    /// The action with this id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Arc<dyn ProviderAction>> {
        self.actions.get(id)
    }

    /// The operation kinds the registered actions create, deduplicated.
    #[must_use]
    pub fn operation_kinds(&self) -> std::collections::BTreeSet<String> {
        self.actions
            .values()
            .map(|action| action.operation_kind().to_owned())
            .collect()
    }

    /// The registered ids, in order.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.actions.keys().map(String::as_str)
    }
}

fn valid_action_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ACTION_ID_LEN
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_'))
}

/// The broker's operator settings.
#[derive(Clone, Debug)]
pub struct BrokerSettings {
    request_ttl_millis: i64,
    overrides: BTreeMap<String, RiskClass>,
}

impl Default for BrokerSettings {
    fn default() -> Self {
        Self::new(DEFAULT_REQUEST_TTL_SECONDS, BTreeMap::new())
            .expect("the default lifetime is within its bounds")
    }
}

impl BrokerSettings {
    /// Settings from a lifetime in seconds and per-action overrides.
    ///
    /// # Errors
    ///
    /// Fails when the lifetime is outside
    /// [`MIN_REQUEST_TTL_SECONDS`]`..=`[`MAX_REQUEST_TTL_SECONDS`].
    pub fn new(
        request_ttl_seconds: u64,
        overrides: BTreeMap<String, RiskClass>,
    ) -> Result<Self, String> {
        if !(MIN_REQUEST_TTL_SECONDS..=MAX_REQUEST_TTL_SECONDS).contains(&request_ttl_seconds) {
            return Err(format!(
                "the request lifetime must be {MIN_REQUEST_TTL_SECONDS}..={MAX_REQUEST_TTL_SECONDS} seconds"
            ));
        }
        let millis = i64::try_from(request_ttl_seconds * 1000)
            .map_err(|_| "the request lifetime is out of range".to_owned())?;
        Ok(Self {
            request_ttl_millis: millis,
            overrides,
        })
    }

    /// Parses the two environment values; an unset or empty value is the
    /// default.
    ///
    /// # Errors
    ///
    /// Fails on a malformed value, naming the variable. A typo in policy
    /// must stop startup, not silently fall back to a different class.
    pub fn from_env_values(ttl: Option<&str>, policy: Option<&str>) -> Result<Self, String> {
        let ttl = match ttl.map(str::trim).filter(|value| !value.is_empty()) {
            None => DEFAULT_REQUEST_TTL_SECONDS,
            Some(value) => value
                .parse::<u64>()
                .map_err(|_| format!("{REQUEST_TTL_VAR} must be a number of seconds"))?,
        };
        let mut overrides = BTreeMap::new();
        for pair in policy
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|pair| !pair.is_empty())
        {
            let (action, class) = pair
                .split_once('=')
                .ok_or_else(|| format!("{POLICY_VAR} entry {pair:?} must be action.id=class"))?;
            let action = action.trim();
            if !valid_action_id(action) {
                return Err(format!(
                    "{POLICY_VAR} names an invalid action id {action:?}"
                ));
            }
            let class = RiskClass::from_id(class.trim())
                .map_err(|detail| format!("{POLICY_VAR}: {detail}"))?;
            if overrides.insert(action.to_owned(), class).is_some() {
                return Err(format!("{POLICY_VAR} names {action} twice"));
            }
        }
        Self::new(ttl, overrides).map_err(|detail| format!("{REQUEST_TTL_VAR}: {detail}"))
    }

    /// The class an action runs under: the operator override, else the
    /// action's declared class.
    #[must_use]
    pub fn effective_risk(&self, action: &dyn ProviderAction) -> RiskClass {
        self.overrides
            .get(action.id())
            .copied()
            .unwrap_or_else(|| action.risk_class())
    }

    /// The request lifetime in milliseconds.
    #[must_use]
    pub const fn request_ttl_millis(&self) -> i64 {
        self.request_ttl_millis
    }
}

/// What a caller asks for.
#[derive(Clone, Debug)]
pub struct NewActionRequest {
    /// The provider action's id.
    pub action_id: String,
    /// What it acts on.
    pub target: String,
    /// Structured, secret-free parameters (an object, or null for none).
    pub parameters: serde_json::Value,
    /// Why, for the approver.
    pub reason: String,
    /// Where the request came from.
    pub origin: String,
    /// The correlation identity of the request.
    pub correlation_id: Option<String>,
    /// A key making a retry return the request already made, scoped to the
    /// requester.
    pub idempotency_key: Option<String>,
}

/// A broker use-case failure.
#[derive(Debug)]
pub enum BrokerError {
    /// The caller may not do this.
    Denied(Decision),
    /// The request is malformed: an unknown action, bad parameters, or a
    /// credential-like value.
    Invalid {
        /// What is wrong, safe to print.
        detail: String,
    },
    /// The request does not exist.
    NotFound {
        /// What was looked up.
        what: String,
    },
    /// The request is not in a state that allows this (already decided,
    /// expired, or lost a race to a concurrent decision).
    Conflict {
        /// The state the request is in.
        state: ActionRequestState,
        /// What happened, safe to print.
        detail: String,
    },
    /// Policy denies the action (ADR 0016): at creation nothing is stored and
    /// only an audit event is kept; at approval the request ends `denied`.
    PolicyDenied {
        /// The action.
        action_id: String,
    },
    /// A port failed.
    Backend {
        /// The failing half.
        context: &'static str,
        /// The failure.
        detail: String,
    },
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::Invalid { detail } => write!(f, "invalid: {detail}"),
            Self::NotFound { what } => write!(f, "{what} was not found"),
            Self::Conflict { state, detail } => {
                write!(f, "the request is {}: {detail}", state.id())
            }
            Self::PolicyDenied { action_id } => {
                write!(f, "policy denies the action {action_id}")
            }
            Self::Backend { context, detail } => write!(f, "{context} failed: {detail}"),
        }
    }
}

impl std::error::Error for BrokerError {}

fn backend(context: &'static str) -> impl Fn(String) -> BrokerError {
    move |detail| BrokerError::Backend { context, detail }
}

/// Decorates the request store so each committed change (a new request or a
/// won transition) publishes a payload-free `request.changed` notification.
/// Publishing follows the commit, so a client that refetches sees the change.
#[derive(Debug)]
struct PublishingPort {
    inner: Arc<dyn ActionRequestPort>,
    events: Arc<crate::events::EventHub>,
}

#[async_trait]
impl ActionRequestPort for PublishingPort {
    async fn insert(&self, request: &ActionRequest, audit: &AuditIntent) -> Result<(), String> {
        self.inner.insert(request, audit).await?;
        self.events
            .publish(crate::events::EventKind::RequestChanged);
        Ok(())
    }

    async fn record_audit(&self, audit: &AuditIntent) -> Result<(), String> {
        self.inner.record_audit(audit).await
    }

    async fn find_by_idempotency(
        &self,
        requester: &str,
        key: &str,
    ) -> Result<Option<ActionRequest>, String> {
        self.inner.find_by_idempotency(requester, key).await
    }

    async fn get(&self, id: &str) -> Result<Option<ActionRequest>, String> {
        self.inner.get(id).await
    }

    async fn list(
        &self,
        state: Option<ActionRequestState>,
        limit: u32,
    ) -> Result<Vec<ActionRequest>, String> {
        self.inner.list(state, limit).await
    }

    async fn transition(
        &self,
        id: &str,
        update: &TransitionUpdate,
        audit: &AuditIntent,
    ) -> Result<Option<ActionRequest>, String> {
        let updated = self.inner.transition(id, update, audit).await?;
        if updated.is_some() {
            self.events
                .publish(crate::events::EventKind::RequestChanged);
        }
        Ok(updated)
    }
}

/// The action broker use cases.
#[derive(Debug)]
pub struct Broker {
    requests: Arc<dyn ActionRequestPort>,
    registry: Arc<ActionRegistry>,
    operations: Arc<Operations>,
    settings: BrokerSettings,
}

impl Broker {
    /// Composes the broker.
    #[must_use]
    pub fn new(
        requests: Arc<dyn ActionRequestPort>,
        registry: Arc<ActionRegistry>,
        operations: Arc<Operations>,
        settings: BrokerSettings,
    ) -> Self {
        Self {
            requests,
            registry,
            operations,
            settings,
        }
    }

    /// Publishes `request.changed` (payload-free) after each committed
    /// request change, so the console's inbox updates live.
    #[must_use]
    pub fn with_events(mut self, events: Arc<crate::events::EventHub>) -> Self {
        self.requests = Arc::new(PublishingPort {
            inner: self.requests,
            events,
        });
        self
    }

    /// The registered action ids, for diagnostics.
    pub fn action_ids(&self) -> impl Iterator<Item = &str> {
        self.registry.ids()
    }

    /// Records a request and applies policy: `auto` starts the operation as
    /// the requester, `approve` leaves it pending, and `deny` is refused with
    /// [`BrokerError::PolicyDenied`] and an audit event, storing nothing. The
    /// returned request shows which of the first two happened.
    ///
    /// A request carrying an idempotency key is scoped to its requester: a
    /// retry with the same key and the same content returns the request
    /// already made; the same key with different content conflicts.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown action, invalid or credential-like input,
    /// a policy denial, or a backend failure.
    #[allow(clippy::too_many_lines)]
    pub async fn create(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        new: NewActionRequest,
        now: i64,
    ) -> Result<ActionRequest, BrokerError> {
        // The id is checked before it is used as the authorization resource,
        // and no error echoes caller input.
        if !valid_action_id(&new.action_id) {
            return Err(BrokerError::Invalid {
                detail: "the actionId is not a valid action id".to_owned(),
            });
        }
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::ActionRequest,
                resource: Some(&new.action_id),
            },
        )
        .map_err(BrokerError::Denied)?;
        let action = self
            .registry
            .get(&new.action_id)
            .ok_or_else(|| BrokerError::Invalid {
                detail: "the action is not offered by this controller".to_owned(),
            })?
            .clone();
        validate_text("target", &new.target, MAX_TARGET_LEN, false)?;
        validate_text("reason", &new.reason, MAX_REASON_LEN, true)?;
        validate_text("origin", &new.origin, MAX_ORIGIN_LEN, false)?;
        validate_idempotency_key(new.idempotency_key.as_deref())?;
        let parameters = check_parameters(new.parameters)?;
        action
            .validate(&new.target, &parameters)
            .map_err(|detail| BrokerError::Invalid { detail })?;

        if let Some(key) = new.idempotency_key.as_deref()
            && let Some(existing) = self
                .requests
                .find_by_idempotency(principal_id, key)
                .await
                .map_err(backend("action requests"))?
        {
            return self
                .replay(
                    authorizer,
                    existing,
                    &new.action_id,
                    &new.target,
                    &parameters,
                    now,
                )
                .await;
        }

        let risk_class = self.settings.effective_risk(action.as_ref());
        let (state, decided_by, decided_at) = match risk_class {
            RiskClass::Auto => (
                ActionRequestState::Approved,
                Some(POLICY_AUTO.to_owned()),
                Some(now),
            ),
            RiskClass::Approve => (ActionRequestState::Pending, None, None),
            RiskClass::Deny => (
                ActionRequestState::Denied,
                Some(POLICY_DENY.to_owned()),
                Some(now),
            ),
        };
        let request = ActionRequest {
            id: fleet_core::UuidV7Generator.next_resource_id().to_string(),
            requester: principal_id.to_owned(),
            origin: new.origin,
            action_id: new.action_id,
            target: new.target,
            parameters,
            risk_class,
            reason: new.reason,
            state,
            decided_by,
            decided_at,
            decision_note: None,
            operation_id: None,
            failure: None,
            correlation_id: new.correlation_id,
            idempotency_key: new.idempotency_key,
            created_at: now,
            expires_at: now.saturating_add(self.settings.request_ttl_millis),
            updated_at: now,
        };
        if risk_class == RiskClass::Deny {
            // ADR 0016: a denied action never becomes a record to approve
            // or to read around; the refusal is an audit event only.
            let mut audit = audit_intent(
                principal_id,
                Permission::ActionRequest.id(),
                &request,
                None,
                ActionRequestState::Denied,
                &[],
            )?;
            audit.resource = None;
            audit.decision = Decision::deny(ReasonId::RiskClassDeny);
            self.requests
                .record_audit(&audit)
                .await
                .map_err(backend("action requests"))?;
            return Err(BrokerError::PolicyDenied {
                action_id: request.action_id,
            });
        }
        let audit = audit_intent(
            principal_id,
            Permission::ActionRequest.id(),
            &request,
            None,
            state,
            &[],
        )?;
        if let Err(detail) = self.requests.insert(&request, &audit).await {
            // A concurrent retry with the same key may have won the unique
            // index: that request is the answer.
            if let Some(key) = request.idempotency_key.as_deref()
                && let Ok(Some(existing)) =
                    self.requests.find_by_idempotency(principal_id, key).await
            {
                return self
                    .replay(
                        authorizer,
                        existing,
                        &request.action_id,
                        &request.target,
                        &request.parameters,
                        now,
                    )
                    .await;
            }
            return Err(BrokerError::Backend {
                context: "action requests",
                detail,
            });
        }
        if state == ActionRequestState::Approved {
            return self.start(authorizer, request, now).await;
        }
        Ok(request)
    }

    /// The answer to a retried creation: the request already made, when the
    /// retry asks for the same thing.
    async fn replay(
        &self,
        authorizer: &dyn Authorizer,
        existing: ActionRequest,
        action_id: &str,
        target: &str,
        parameters: &serde_json::Value,
        now: i64,
    ) -> Result<ActionRequest, BrokerError> {
        if existing.action_id != action_id
            || existing.target != target
            || &existing.parameters != parameters
        {
            return Err(BrokerError::Conflict {
                state: existing.state,
                detail: "the idempotency key was already used for a different request".to_owned(),
            });
        }
        self.reconcile(authorizer, existing, now).await
    }

    /// The requester's request already made with this idempotency key, brought
    /// up to date, so a caller that would otherwise do work before creating
    /// the request (a preview that reads a provider) can return it first.
    /// Authorized as a request for the found action.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn existing_for_key(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        key: &str,
        now: i64,
    ) -> Result<Option<ActionRequest>, BrokerError> {
        validate_idempotency_key(Some(key))?;
        let Some(existing) = self
            .requests
            .find_by_idempotency(principal_id, key)
            .await
            .map_err(backend("action requests"))?
        else {
            return Ok(None);
        };
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::ActionRequest,
                resource: Some(&existing.action_id),
            },
        )
        .map_err(BrokerError::Denied)?;
        self.reconcile(authorizer, existing, now).await.map(Some)
    }

    /// Lists requests, newest first, after bringing each up to date (expiry
    /// and operation outcome). A request that cannot be brought up to date
    /// is listed as stored rather than failing the page.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure of the listing itself.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        state: Option<ActionRequestState>,
        limit: u32,
        now: i64,
    ) -> Result<Vec<ActionRequest>, BrokerError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::ActionRead,
                resource: None,
            },
        )
        .map_err(BrokerError::Denied)?;
        let limit = limit.clamp(1, MAX_LIST_LIMIT);
        // Reconciling can move a request out of the filtered state, so the
        // stored page is filtered again after it.
        let stored = self
            .requests
            .list(state, limit)
            .await
            .map_err(backend("action requests"))?;
        let mut out = Vec::with_capacity(stored.len());
        for request in stored {
            let request = match self.reconcile(authorizer, request.clone(), now).await {
                Ok(reconciled) => reconciled,
                Err(_) => request,
            };
            if state.is_none_or(|wanted| wanted == request.state) {
                out.push(request);
            }
        }
        Ok(out)
    }

    /// Reads one request, brought up to date.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown id, or a backend failure.
    pub async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        id: &str,
        now: i64,
    ) -> Result<ActionRequest, BrokerError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::ActionRead,
                resource: None,
            },
        )
        .map_err(BrokerError::Denied)?;
        let request = self.load(id).await?;
        self.reconcile(authorizer, request, now).await
    }

    /// Approves a pending request and starts its operation. The approver
    /// needs `action.approve` for the request's action; the operation is then
    /// created on the brokered route, not the generic one. Of concurrent
    /// approvals exactly one succeeds; the others get
    /// [`BrokerError::Conflict`].
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown id, a request that is not pending (or
    /// expired), an action policy now denies (the request is then denied by
    /// policy), or a backend failure. A request whose operation cannot be
    /// created is returned `failed`, not as an error: the approval happened.
    pub async fn approve(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        id: &str,
        now: i64,
    ) -> Result<ActionRequest, BrokerError> {
        let request = self
            .authorize_decision(authorizer, principal_id, id, Permission::ActionApprove)
            .await?;
        let request = self.reconcile(authorizer, request, now).await?;
        require_pending(&request)?;
        // Policy may have changed since the request was made; a denial now
        // wins over an approval, and the request ends denied by policy.
        let current =
            self.registry
                .get(&request.action_id)
                .ok_or_else(|| BrokerError::Invalid {
                    detail: "the action is no longer offered by this controller".to_owned(),
                })?;
        if self.settings.effective_risk(current.as_ref()) == RiskClass::Deny {
            let update = TransitionUpdate {
                from: ActionRequestState::Pending,
                to: ActionRequestState::Denied,
                decided_by: Some(POLICY_DENY.to_owned()),
                decision_note: Some("policy denies this action".to_owned()),
                operation_id: None,
                failure: None,
                at: now,
                require_unexpired: false,
            };
            let audit = audit_intent(
                SYSTEM_ACTOR,
                "action.policy_deny",
                &request,
                Some(ActionRequestState::Pending),
                ActionRequestState::Denied,
                &[("attemptedBy", principal_id)],
            )?;
            self.requests
                .transition(&request.id, &update, &audit)
                .await
                .map_err(backend("action requests"))?;
            return Err(BrokerError::PolicyDenied {
                action_id: request.action_id,
            });
        }
        let approved = self
            .decide(
                &request,
                principal_id,
                ActionRequestState::Approved,
                None,
                now,
            )
            .await?;
        self.start(authorizer, approved, now).await
    }

    /// Denies a pending request. The optional note is scrubbed.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown id, a request that is not pending (or
    /// expired), an invalid note, or a backend failure.
    pub async fn deny(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        id: &str,
        note: Option<&str>,
        now: i64,
    ) -> Result<ActionRequest, BrokerError> {
        let request = self
            .authorize_decision(authorizer, principal_id, id, Permission::ActionDeny)
            .await?;
        let note = note
            .map(|note| {
                validate_text("note", note, MAX_REASON_LEN, true)?;
                Ok::<_, BrokerError>(note.to_owned())
            })
            .transpose()?;
        let request = self.reconcile(authorizer, request, now).await?;
        require_pending(&request)?;
        self.decide(
            &request,
            principal_id,
            ActionRequestState::Denied,
            note,
            now,
        )
        .await
    }

    /// Loads the request a decision concerns and authorizes the decision
    /// against its action id. A caller refused for an unknown request is
    /// refused the same way as for a known one it may not decide.
    async fn authorize_decision(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        id: &str,
        permission: Permission,
    ) -> Result<ActionRequest, BrokerError> {
        let found = self
            .requests
            .get(id)
            .await
            .map_err(backend("action requests"))?;
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: permission,
                // An unknown request is authorized against the id the caller
                // gave, so it is refused or reported missing like any other.
                resource: Some(
                    found
                        .as_ref()
                        .map_or(id, |request| request.action_id.as_str()),
                ),
            },
        )
        .map_err(BrokerError::Denied)?;
        found.ok_or_else(|| BrokerError::NotFound {
            what: "the action request".to_owned(),
        })
    }

    async fn load(&self, id: &str) -> Result<ActionRequest, BrokerError> {
        self.requests
            .get(id)
            .await
            .map_err(backend("action requests"))?
            .ok_or_else(|| BrokerError::NotFound {
                what: "the action request".to_owned(),
            })
    }

    /// The human decision: `pending -> approved | denied`, one
    /// compare-and-set that also requires the deadline to be ahead.
    async fn decide(
        &self,
        request: &ActionRequest,
        principal_id: &str,
        to: ActionRequestState,
        note: Option<String>,
        now: i64,
    ) -> Result<ActionRequest, BrokerError> {
        let action = if to == ActionRequestState::Approved {
            Permission::ActionApprove
        } else {
            Permission::ActionDeny
        };
        let update = TransitionUpdate {
            from: ActionRequestState::Pending,
            to,
            decided_by: Some(principal_id.to_owned()),
            decision_note: note,
            operation_id: None,
            failure: None,
            at: now,
            require_unexpired: true,
        };
        let audit = audit_intent(
            principal_id,
            action.id(),
            request,
            Some(ActionRequestState::Pending),
            to,
            &[],
        )?;
        if let Some(updated) = self
            .requests
            .transition(&request.id, &update, &audit)
            .await
            .map_err(backend("action requests"))?
        {
            return Ok(updated);
        }
        // The compare-and-set lost: another decision, or the deadline, got
        // there first.
        let current = self.load(&request.id).await?;
        let current = self.latest(current, now).await;
        Err(BrokerError::Conflict {
            state: current.state,
            detail: "another decision was made first".to_owned(),
        })
    }

    /// The principal whose authorization the operation runs under: the
    /// approver, or the requester when policy approved the request.
    fn executing_principal(request: &ActionRequest) -> &str {
        match request.decided_by.as_deref() {
            Some(decider) if !decider.starts_with("policy:") => decider,
            _ => &request.requester,
        }
    }

    /// Creates the operation of an approved request on the brokered route
    /// and links it. A request whose operation cannot be created is failed,
    /// with the reason. The idempotency key is the request id, so running
    /// this again (a slow start racing the stuck-request recovery) returns
    /// the same operation rather than a second one.
    #[allow(clippy::too_many_lines)]
    async fn start(
        &self,
        authorizer: &dyn Authorizer,
        request: ActionRequest,
        now: i64,
    ) -> Result<ActionRequest, BrokerError> {
        let Some(action) = self.registry.get(&request.action_id) else {
            return self
                .fail(&request, "the action is no longer offered", now)
                .await;
        };
        let mut new = match action.operation(&request) {
            Ok(new) => new,
            Err(detail) => {
                return self
                    .fail(
                        &request,
                        &format!("the action could not start: {detail}"),
                        now,
                    )
                    .await;
            }
        };
        if new.kind != action.operation_kind() {
            return self
                .fail(
                    &request,
                    "the action built an operation of a kind it does not declare",
                    now,
                )
                .await;
        }
        // Recovery rebuilds the operation and compares it, so it must be
        // deterministic; check that cheaply in debug builds.
        debug_assert!(
            action
                .operation(&request)
                .is_ok_and(|again| again.payload_json == new.payload_json),
            "ProviderAction::operation must be deterministic for the same request"
        );
        new.idempotency_key = Some(format!("{BROKER_IDEMPOTENCY_PREFIX}{}", request.id));
        new.correlation_id.clone_from(&request.correlation_id);
        let principal = Self::executing_principal(&request).to_owned();
        let operation = match self
            .operations
            .create_brokered(authorizer, &principal, &new)
            .await
        {
            Ok(operation) => operation,
            Err(OperationUseCaseError::Denied(decision)) => {
                return self
                    .fail(
                        &request,
                        &format!("the operation was not permitted: {decision}"),
                        now,
                    )
                    .await;
            }
            Err(OperationUseCaseError::Backend { context, detail }) => {
                return Err(BrokerError::Backend { context, detail });
            }
            Err(other) => {
                return self
                    .fail(
                        &request,
                        &format!("the operation was refused: {other}"),
                        now,
                    )
                    .await;
            }
        };
        // The key is the request's, but an operation that already held it
        // must be the one this request would have made.
        if operation.kind != new.kind || operation.payload_json != new.payload_json {
            return self
                .fail(
                    &request,
                    "the idempotency key already belongs to a different operation",
                    now,
                )
                .await;
        }
        let update = TransitionUpdate {
            from: ActionRequestState::Approved,
            to: ActionRequestState::Executing,
            decided_by: None,
            decision_note: None,
            operation_id: Some(operation.id.clone()),
            failure: None,
            at: now,
            require_unexpired: false,
        };
        let audit = audit_intent(
            SYSTEM_ACTOR,
            "action.execute",
            &request,
            Some(ActionRequestState::Approved),
            ActionRequestState::Executing,
            &[("operationId", &operation.id)],
        )?;
        match self
            .requests
            .transition(&request.id, &update, &audit)
            .await
            .map_err(backend("action requests"))?
        {
            Some(updated) => Ok(updated),
            None => self.load(&request.id).await,
        }
    }

    async fn fail(
        &self,
        request: &ActionRequest,
        failure: &str,
        now: i64,
    ) -> Result<ActionRequest, BrokerError> {
        self.finish(
            request,
            ActionRequestState::Failed,
            Some(failure),
            "action.fail",
            now,
        )
        .await
    }

    /// A system transition (`-> failed`, `-> succeeded`, `-> expired`).
    /// Losing the compare-and-set means someone else made it; the current
    /// request is returned.
    async fn finish(
        &self,
        request: &ActionRequest,
        to: ActionRequestState,
        failure: Option<&str>,
        audit_action: &str,
        now: i64,
    ) -> Result<ActionRequest, BrokerError> {
        let failure = failure.map(fleet_core::scrub_failure_detail);
        let update = TransitionUpdate {
            from: request.state,
            to,
            decided_by: (to == ActionRequestState::Expired).then(|| SYSTEM_ACTOR.to_owned()),
            decision_note: None,
            operation_id: None,
            failure,
            at: now,
            require_unexpired: false,
        };
        let operation_id = request.operation_id.clone().unwrap_or_default();
        let extra: Vec<(&str, &str)> = if operation_id.is_empty() {
            Vec::new()
        } else {
            vec![("operationId", operation_id.as_str())]
        };
        let audit = audit_intent(
            SYSTEM_ACTOR,
            audit_action,
            request,
            Some(request.state),
            to,
            &extra,
        )?;
        match self
            .requests
            .transition(&request.id, &update, &audit)
            .await
            .map_err(backend("action requests"))?
        {
            Some(updated) => Ok(updated),
            None => self.load(&request.id).await,
        }
    }

    /// The request as it stands now, as far as it can be brought up to date
    /// without an authorizer: used after a lost decision, where only the
    /// state is reported.
    async fn latest(&self, request: ActionRequest, now: i64) -> ActionRequest {
        if request.state == ActionRequestState::Pending
            && action_request_deadline_passed(request.expires_at, now)
            && let Ok(expired) = self
                .finish(
                    &request,
                    ActionRequestState::Expired,
                    None,
                    "action.expire",
                    now,
                )
                .await
        {
            return expired;
        }
        request
    }

    /// Brings a request up to date with time and with its operation.
    async fn reconcile(
        &self,
        authorizer: &dyn Authorizer,
        request: ActionRequest,
        now: i64,
    ) -> Result<ActionRequest, BrokerError> {
        match request.state {
            ActionRequestState::Pending
                if action_request_deadline_passed(request.expires_at, now) =>
            {
                self.finish(
                    &request,
                    ActionRequestState::Expired,
                    None,
                    "action.expire",
                    now,
                )
                .await
            }
            ActionRequestState::Approved
                if request.operation_id.is_none()
                    && request
                        .decided_at
                        .is_some_and(|at| now.saturating_sub(at) > APPROVED_STUCK_GRACE_MILLIS) =>
            {
                // The controller may have stopped between the approval and
                // the operation, or the operation may exist but be unlinked.
                // Creating it again with the same idempotency key returns the
                // existing operation or makes it; only a failure to do either
                // fails the request, so a live operation is never orphaned.
                self.start(authorizer, request, now).await
            }
            ActionRequestState::Executing => {
                let Some(operation_id) = request.operation_id.clone() else {
                    return Ok(request);
                };
                let state = match self.operations.get_state(&operation_id).await {
                    Ok(state) => state,
                    Err(PortFailure::NotFound { .. }) => {
                        // An operation that cannot be found will never finish:
                        // give a restart or a slow read its grace, then fail.
                        if now.saturating_sub(request.updated_at) > APPROVED_STUCK_GRACE_MILLIS {
                            return self
                                .fail(&request, "the operation record could not be found", now)
                                .await;
                        }
                        return Ok(request);
                    }
                    // A lookup that fails otherwise leaves the request as it
                    // is: the next read tries again.
                    Err(_) => return Ok(request),
                };
                match state.as_str() {
                    "succeeded" => {
                        self.finish(
                            &request,
                            ActionRequestState::Succeeded,
                            None,
                            "action.succeed",
                            now,
                        )
                        .await
                    }
                    "failed" | "cancelled" | "timed_out" | "blocked_manual_approval" => {
                        let detail = format!("the operation ended {state}");
                        self.fail(&request, &detail, now).await
                    }
                    _ => Ok(request),
                }
            }
            _ => Ok(request),
        }
    }
}

fn require_pending(request: &ActionRequest) -> Result<(), BrokerError> {
    if can_transition_action_request(request.state, ActionRequestState::Approved) {
        Ok(())
    } else {
        Err(BrokerError::Conflict {
            state: request.state,
            detail: "only a pending request can be decided".to_owned(),
        })
    }
}

/// Builds the audit intent of one transition: ids, the target, and states
/// only. Parameters, reasons, and notes are never audited.
fn audit_intent(
    actor: &str,
    action: &str,
    request: &ActionRequest,
    from: Option<ActionRequestState>,
    to: ActionRequestState,
    extra: &[(&str, &str)],
) -> Result<AuditIntent, BrokerError> {
    let mut metadata = AuditMetadata::default();
    let mut put = |key: &str, value: &str| {
        metadata
            .insert(key, value)
            .map_err(|error| BrokerError::Backend {
                context: "audit",
                detail: error.to_string(),
            })
    };
    put("actionId", &request.action_id)?;
    put("target", &request.target)?;
    put("riskClass", request.risk_class.id())?;
    put("requester", &request.requester)?;
    if let Some(from) = from {
        put("from", from.id())?;
    }
    put("to", to.id())?;
    for (key, value) in extra {
        put(key, value)?;
    }
    Ok(AuditIntent {
        actor: actor.to_owned(),
        action: action.to_owned(),
        resource: Some(request.id.clone()),
        decision: Decision::allow(),
        correlation_id: request.correlation_id.clone(),
        operation_id: None,
        metadata,
    })
}

/// A bounded printable-ASCII key; the error never echoes it.
fn validate_idempotency_key(key: Option<&str>) -> Result<(), BrokerError> {
    let Some(key) = key else {
        return Ok(());
    };
    if key.is_empty()
        || key.len() > MAX_IDEMPOTENCY_KEY_LEN
        || !key.chars().all(|c| c.is_ascii_graphic())
    {
        return Err(BrokerError::Invalid {
            detail: format!(
                "the idempotency key must be 1 to {MAX_IDEMPOTENCY_KEY_LEN} printable ASCII characters"
            ),
        });
    }
    Ok(())
}

fn validate_text(
    name: &str,
    value: &str,
    max: usize,
    allow_newline: bool,
) -> Result<(), BrokerError> {
    let invalid = |detail: String| BrokerError::Invalid { detail };
    if value.trim().is_empty() {
        return Err(invalid(format!("the {name} must not be empty")));
    }
    if value.chars().count() > max {
        return Err(invalid(format!(
            "the {name} must be at most {max} characters"
        )));
    }
    if value
        .chars()
        .any(|c| c.is_control() && !(allow_newline && c == '\n'))
    {
        return Err(invalid(format!(
            "the {name} must not contain control characters"
        )));
    }
    if fleet_core::redact_credentials(value) != value {
        return Err(invalid(format!(
            "the {name} looks like it contains a credential; Fleet holds credentials, requests never carry them"
        )));
    }
    Ok(())
}

/// Checks that parameters are a bounded object of secret-free values and
/// answers them (null becomes an empty object).
///
/// A parameter set is refused, not silently redacted, when the shared
/// redaction helpers would change any string in it, or when a key is named
/// like a secret: a request that needed a credential to work would fail at
/// the provider anyway, and storing a masked copy would hide that.
fn check_parameters(parameters: serde_json::Value) -> Result<serde_json::Value, BrokerError> {
    use serde_json::Value;
    let parameters = match parameters {
        Value::Null => Value::Object(serde_json::Map::new()),
        object @ Value::Object(_) => object,
        _ => {
            return Err(BrokerError::Invalid {
                detail: "the parameters must be a JSON object".to_owned(),
            });
        }
    };
    let serialized = parameters.to_string();
    if serialized.len() > MAX_PARAMETERS_BYTES {
        return Err(BrokerError::Invalid {
            detail: format!("the parameters must be at most {MAX_PARAMETERS_BYTES} bytes"),
        });
    }
    if parameter_depth(&parameters) > MAX_PARAMETER_DEPTH {
        return Err(BrokerError::Invalid {
            detail: format!("the parameters must nest at most {MAX_PARAMETER_DEPTH} levels"),
        });
    }
    if credential_like(&parameters) {
        return Err(credential_like_error());
    }
    Ok(parameters)
}

fn credential_like_error() -> BrokerError {
    BrokerError::Invalid {
        detail: "the parameters contain a credential-like value or a secret-named key; Fleet holds provider credentials, requests never carry them".to_owned(),
    }
}

/// Whether the shared credential rules would change or refuse these
/// parameters. A well-formed `mailto:<address>` is not a credential (a DMARC
/// `rua` holds one), so the rules run on a probe copy in which each is
/// replaced by `mailto:x`; the original is what a request stores. Anything
/// else with a credential's shape, including `mailto:user:pw@host`, is still
/// found.
#[must_use]
pub fn credential_like(parameters: &serde_json::Value) -> bool {
    let probe = mailto_probe(parameters);
    // The shared scrubber over every string and key.
    let mut scrubbed = probe.clone();
    fleet_core::redact_json_strings(&mut scrubbed);
    scrubbed != probe || has_secret_shape(&probe)
}

fn mailto_probe(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::String(text) => Value::String(replace_mailto(text)),
        Value::Array(items) => Value::Array(items.iter().map(mailto_probe).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), mailto_probe(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Replaces each well-formed `mailto:<address>` with `mailto:x`. It must
/// start the text or follow whitespace, `=`, `,`, `;`, or `!`; the address
/// ends at whitespace, `,`, `;`, or `!` and has one `@`, no `:`, and plain
/// local and domain characters.
fn replace_mailto(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut previous: Option<char> = None;
    while !rest.is_empty() {
        let at_boundary = previous.is_none_or(|c| c.is_whitespace() || "=,;!".contains(c));
        if at_boundary && let Some(after) = rest.strip_prefix("mailto:") {
            let end = after
                .find(|c: char| c.is_whitespace() || ",;!".contains(c))
                .unwrap_or(after.len());
            if valid_mail_address(&after[..end]) {
                out.push_str("mailto:x");
                previous = Some('x');
                rest = &after[end..];
                continue;
            }
        }
        let c = rest.chars().next().expect("rest is not empty");
        out.push(c);
        previous = Some(c);
        rest = &rest[c.len_utf8()..];
    }
    out
}

fn valid_mail_address(address: &str) -> bool {
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-".contains(c))
}

fn parameter_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => 1 + map.values().map(parameter_depth).max().unwrap_or(0),
        serde_json::Value::Array(items) => 1 + items.iter().map(parameter_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// A key named like a secret, or a `key=value` pair the pair scrubber masks.
fn has_secret_shape(value: &serde_json::Value) -> bool {
    use serde_json::Value;
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            let probe = format!("{key}=fakevalue1234");
            fleet_core::redact_credentials(&probe) != probe
                || match value {
                    Value::String(text) => {
                        let pair = format!("{key}={text}");
                        fleet_core::redact_credentials(&pair) != pair
                    }
                    other => has_secret_shape(other),
                }
        }),
        Value::Array(items) => items.iter().any(has_secret_shape),
        _ => false,
    }
}

/// A trivial provider action for tests of the broker and its adapters. It
/// runs the `noop` operation kind. It exists only in tests (the
/// `test-support` feature, enabled by dev-dependencies) and is never
/// registered by the controller; real actions arrive with their providers.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::{ActionRequest, ProviderAction};
    use crate::operation::NewOperation;
    use fleet_core::RiskClass;

    /// The id of [`NoopAction`].
    pub const NOOP_ACTION_ID: &str = "test.noop.run";

    /// A test-only action with a configurable declared risk class.
    #[derive(Debug)]
    pub struct NoopAction {
        /// The declared class.
        pub risk: RiskClass,
    }

    impl ProviderAction for NoopAction {
        fn id(&self) -> &str {
            NOOP_ACTION_ID
        }

        fn operation_kind(&self) -> &'static str {
            "noop"
        }

        fn risk_class(&self) -> RiskClass {
            self.risk
        }

        fn validate(&self, target: &str, parameters: &serde_json::Value) -> Result<(), String> {
            if target.starts_with("bad-") {
                return Err("the target is not accepted".to_owned());
            }
            if parameters.get("unexpected").is_some() {
                return Err("the parameter unexpected is not accepted".to_owned());
            }
            Ok(())
        }

        fn operation(&self, request: &ActionRequest) -> Result<NewOperation, String> {
            Ok(NewOperation {
                kind: "noop".to_owned(),
                payload_json: Some(serde_json::json!({ "target": request.target }).to_string()),
                ..NewOperation::default()
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_well_formed_mailto_is_not_a_credential_but_credential_shapes_still_are() {
        let params = |text: &str| serde_json::json!({ "content": text });
        for fine in [
            "v=DMARC1; p=none; rua=mailto:a@x.com,mailto:b@y.com!10m",
            "v=DMARC1; p=reject; rua=mailto:d@example.com; ruf=mailto:f@example.com",
            "mailto:d@example.com",
        ] {
            assert!(!credential_like(&params(fine)), "{fine}");
            // The stored copy is the original, not the probe.
            assert!(check_parameters(params(fine)).is_ok_and(|p| p["content"] == fine));
        }
        for refused in [
            "mailto:user:pw@host",
            "x=mailto:a@b,user:pw@host",
            "https://u:p@h",
            "api_key=Zx81QwErTy93LkJhGf62Mn40",
            "v=DMARC1; rua=mailto:a@b@c",
            "see mailto:user:pw@host and mailto:a@b.com",
        ] {
            assert!(credential_like(&params(refused)), "{refused}");
        }
    }

    #[test]
    fn settings_parse_the_environment_values() {
        let settings =
            BrokerSettings::from_env_values(Some("3600"), Some("a.b.c=approve, d.e=deny")).unwrap();
        assert_eq!(settings.request_ttl_millis(), 3_600_000);
        assert_eq!(settings.overrides["a.b.c"], RiskClass::Approve);
        assert_eq!(settings.overrides["d.e"], RiskClass::Deny);
        let defaults = BrokerSettings::from_env_values(None, Some("")).unwrap();
        assert_eq!(
            defaults.request_ttl_millis(),
            i64::try_from(DEFAULT_REQUEST_TTL_SECONDS * 1000).unwrap()
        );
    }

    #[test]
    fn malformed_settings_are_refused_by_name() {
        for (ttl, policy, needle) in [
            (Some("soon"), None, REQUEST_TTL_VAR),
            (Some("5"), None, REQUEST_TTL_VAR),
            (Some("99999999"), None, REQUEST_TTL_VAR),
            (None, Some("a.b"), POLICY_VAR),
            (None, Some("a.b=maybe"), POLICY_VAR),
            (None, Some("A B=auto"), POLICY_VAR),
            (None, Some("a.b=auto,a.b=deny"), POLICY_VAR),
        ] {
            let error = BrokerSettings::from_env_values(ttl, policy).unwrap_err();
            assert!(error.contains(needle), "{error}");
        }
    }

    #[test]
    fn policy_is_the_override_else_the_declared_class() {
        let action = test_support::NoopAction {
            risk: RiskClass::Auto,
        };
        let plain = BrokerSettings::default();
        assert_eq!(plain.effective_risk(&action), RiskClass::Auto);
        let raised = BrokerSettings::from_env_values(
            None,
            Some(&format!("{}=approve", test_support::NOOP_ACTION_ID)),
        )
        .unwrap();
        assert_eq!(raised.effective_risk(&action), RiskClass::Approve);
        let lowered_deny = BrokerSettings::from_env_values(
            None,
            Some(&format!("{}=deny", test_support::NOOP_ACTION_ID)),
        )
        .unwrap();
        let approve_action = test_support::NoopAction {
            risk: RiskClass::Approve,
        };
        assert_eq!(
            lowered_deny.effective_risk(&approve_action),
            RiskClass::Deny
        );
    }

    #[test]
    fn registry_refuses_duplicates_and_bad_ids() {
        let mut registry = ActionRegistry::new();
        let action = || {
            Arc::new(test_support::NoopAction {
                risk: RiskClass::Auto,
            })
        };
        registry.register(action()).unwrap();
        assert!(registry.register(action()).is_err());
        assert!(registry.get(test_support::NOOP_ACTION_ID).is_some());
        assert!(!valid_action_id("Bad Id"));
        assert!(!valid_action_id(""));
        assert!(valid_action_id("coolify.application.redeploy"));
    }

    #[test]
    fn parameters_must_be_a_bounded_object() {
        assert_eq!(
            check_parameters(serde_json::Value::Null).unwrap(),
            serde_json::json!({})
        );
        assert!(check_parameters(serde_json::json!([1])).is_err());
        assert!(check_parameters(serde_json::json!("text")).is_err());
        let big = serde_json::json!({ "x": "a".repeat(MAX_PARAMETERS_BYTES) });
        assert!(check_parameters(big).is_err());
        let deep = serde_json::json!({"a":{"b":{"c":{"d":{"e":{"f":{"g":1}}}}}}});
        assert!(check_parameters(deep).is_err());
        let ok = serde_json::json!({ "service": "web", "force": true, "n": 3, "tags": ["a", "b"] });
        assert_eq!(check_parameters(ok.clone()).unwrap(), ok);
    }

    #[test]
    fn credential_like_parameters_are_refused() {
        for bad in [
            serde_json::json!({ "password": "fakepw1" }),
            serde_json::json!({ "apiToken": "abc" }),
            serde_json::json!({ "nested": { "secret_key": 12345 } }),
            serde_json::json!({ "url": "https://user:fakepw1@example.com/x" }),
            serde_json::json!({ "header": "Authorization: Bearer fakevalue1234" }),
            serde_json::json!({ "list": ["token=fakevalue1234"] }),
            serde_json::json!({ "pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIfake1\n-----END RSA PRIVATE KEY-----" }),
        ] {
            let error = check_parameters(bad.clone()).unwrap_err();
            assert!(
                matches!(&error, BrokerError::Invalid { detail } if detail.contains("credential")),
                "{bad}: {error}"
            );
            // The refusal never echoes the value.
            assert!(!error.to_string().contains("fakepw1"));
        }
    }

    #[test]
    fn text_fields_are_bounded_and_secret_free() {
        assert!(validate_text("target", "app-1", 10, false).is_ok());
        assert!(validate_text("target", " ", 10, false).is_err());
        assert!(validate_text("target", "abcdefghijk", 10, false).is_err());
        assert!(validate_text("target", "a\u{7}b", 10, false).is_err());
        assert!(validate_text("target", "a\nb", 10, false).is_err());
        assert!(validate_text("reason", "a\nb", 10, true).is_ok());
        assert!(validate_text("reason", "use https://u:fakepw1@h/x", 100, true).is_err());
    }
}
