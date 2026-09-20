//! The SSH Add Machine onboarding use cases: a staged, reviewable path from
//! an address to a registered agentless machine (FM-210).
//!
//! Onboarding is deliberately staged — **draft**, **test**, **discover**,
//! **review**, **add** — because the first contact with a host is exactly
//! where an operator must stay in control: the host key is confirmed
//! explicitly, the discovered facts are reviewed before they become machine
//! record, and duplicates are warned about, never silently merged.
//!
//! A **draft** is the staged state: an address, an authentication mode, the
//! proposed machine identity (name, tags, groups), the observed host key, and
//! the facts a probe discovered. Drafts live behind the [`OnboardingPort`]
//! and survive a controller restart, because abandoning a half-reviewed
//! draft on restart would be a small lie about durability.
//!
//! Two invariants shape everything here:
//!
//! 1. **Test has no persistent machine side effect.** Observing a host key
//!    and connecting to it never touches the machines record. Only `add`
//!    mints a machine, and it does so by delegating to the
//!    [`Machines`] use cases — the same authorized, audited funnel as every
//!    other machine mutation.
//! 2. **Drafts hold no secret values.** Authentication is the SSH agent or
//!    an identity-file *path* — the same reference level the `ssh.exec`
//!    payloads already carry; passwords are not supported by the SSH
//!    provider's non-interactive contract. The secret lifecycle is therefore
//!    a lifecycle of *references and trust*: cancelling or completing a draft
//!    deletes its row, and cancelling unpins the host key from the Fleet
//!    known-hosts file unless an existing machine endpoint shares that host.
//!
//! Trust is explicit, not inferred: `test` only observes; `confirm` is a
//! separate authorized act that pins the fingerprint; a later observation
//! that disagrees marks the draft `changed`, and discover/add refuse until
//! the new fingerprint is re-confirmed. The host-key change is the hostile
//! case, and it blocks hard.
//!
//! There is no SSH in this module. Probing, connecting, and probing the
//! inventory belong to the controller's executor over the SSH provider; this
//! module owns what is *true about a draft* and what may happen to it, and
//! reaches the network only through the [`OnboardTrustPort`] (pin/unpin),
//! which the composition root wires to the provider.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::machine::{MachineFilter, MachineStatus, MachineView, Machines, RegisterMachine};
use crate::operation::PortFailure;
use fleet_core::{CapabilityFact, EndpointKind};

/// The stage of a draft's host-key trust, as the review surface displays it.
///
/// This is derived from the recorded state, never stored: `untested` until a
/// test observed a key, `review` while a fingerprint awaits (or lost) its
/// explicit confirmation, and `ready` once the current fingerprint was
/// confirmed. A change re-enters `review` and blocks until re-confirmed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftStage {
    /// No host key observed yet: the first test has not run.
    Untested,
    /// A fingerprint was observed (or changed away from the confirmed one)
    /// and awaits an explicit confirmation.
    Review,
    /// The current fingerprint was explicitly confirmed; discover and add
    /// may proceed.
    Ready,
}

impl DraftStage {
    /// The stable string used in the API and the CLI.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Untested => "untested",
            Self::Review => "review",
            Self::Ready => "ready",
        }
    }
}

/// The recorded host-key trust state of a draft, as stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyStage {
    /// Nothing observed yet.
    Unseen,
    /// A key was observed; the fingerprint awaits explicit confirmation.
    Observed,
    /// The observed fingerprint was explicitly confirmed and pinned.
    Confirmed,
    /// A later observation disagrees with the confirmed fingerprint. The
    /// draft blocks until the new fingerprint is re-confirmed.
    Changed,
}

impl HostKeyStage {
    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Unseen => "unseen",
            Self::Observed => "observed",
            Self::Confirmed => "confirmed",
            Self::Changed => "changed",
        }
    }

    /// Parses the stable string.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "unseen" => Some(Self::Unseen),
            "observed" => Some(Self::Observed),
            "confirmed" => Some(Self::Confirmed),
            "changed" => Some(Self::Changed),
            _ => None,
        }
    }
}

/// The proposed endpoint of a draft, as structured parts. The reference is
/// derived `user@host:port`, the same shape machine SSH endpoints use.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftEndpoint {
    /// The remote login user.
    pub user: String,
    /// The host or address.
    pub host: String,
    /// The TCP port.
    pub port: u16,
}

impl DraftEndpoint {
    /// The SSH endpoint reference, e.g. `deploy@host:22`.
    #[must_use]
    pub fn reference(&self) -> String {
        format!("{}@{}:{}", self.user, self.host, self.port)
    }
}

/// How the controller would authenticate to a draft's endpoint. Mirrors the
/// provider's contract: the agent or an identity file, never a password.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum OnboardAuth {
    /// The controller's running agent (`SSH_AUTH_SOCK`) supplies the key.
    Agent,
    /// A specific identity file, referenced by path. The path is a
    /// reference, not a secret; the provider never reads or stores key
    /// material.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// A host key as observed from the network, staged for review. Host keys are
/// public data; the raw line is exactly what a later pin writes into the
/// Fleet known-hosts file, so what was reviewed is what gets trusted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnboardHostKey {
    /// The key type, e.g. `ED25519`.
    pub key_type: String,
    /// The OpenSSH `SHA256:` fingerprint the reviewer confirms.
    pub fingerprint: String,
    /// The raw `known_hosts` line behind the fingerprint.
    pub raw_line: String,
}

/// The outcome of the connect check a test performed, when it ran. A test
/// that only observed the host key (nothing confirmed yet) attempted no
/// connection: `ssh` would refuse an unpinned host.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestOutcome {
    /// Whether the connect check ran.
    pub connect_attempted: bool,
    /// Whether the connect check succeeded.
    pub connected: bool,
    /// The bounded, already-redacted failure detail, when the check ran and
    /// failed.
    pub detail: Option<String>,
    /// When the test ran (epoch milliseconds).
    pub at: i64,
}

/// A draft: the staged, reviewable state of an Add Machine flow.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnboardingDraft {
    /// The draft's identity.
    pub id: String,
    /// The proposed endpoint.
    pub endpoint: DraftEndpoint,
    /// How the controller would authenticate.
    pub auth: OnboardAuth,
    /// The proposed machine name; `add` registers the machine under it.
    pub name: String,
    /// Operator notes carried onto the machine.
    pub description: String,
    /// Tags carried onto the machine.
    pub tags: Vec<String>,
    /// Groups carried onto the machine.
    pub groups: Vec<String>,
    /// The newest observed host key, when a test ran.
    pub host_key: Option<OnboardHostKey>,
    /// The host-key trust stage.
    pub host_key_stage: HostKeyStage,
    /// The fingerprint the operator confirmed, when any.
    pub confirmed_fingerprint: Option<String>,
    /// The newest test outcome, when a test ran.
    pub last_test: Option<TestOutcome>,
    /// The facts discovery recorded for review; empty until a discover ran.
    pub facts: Vec<CapabilityFact>,
    /// What observed the facts, e.g. `agentless/1`; carried onto the
    /// machine's snapshot at add time.
    pub discovery_source: Option<String>,
    /// The caller's idempotency key, when the draft was created through an
    /// idempotent request; replays return this draft.
    pub idempotency_key: Option<String>,
    /// When discovery completed (epoch milliseconds).
    pub discovered_at: Option<i64>,
    /// Creation time (epoch milliseconds).
    pub created_at: i64,
    /// Last mutation (epoch milliseconds).
    pub updated_at: i64,
}

impl OnboardingDraft {
    /// The derived stage: what the review surface should ask the operator
    /// for next. Facts never gate the stage — unsupported or partial
    /// facts must not block a basic agentless add.
    #[must_use]
    pub fn stage(&self) -> DraftStage {
        match self.host_key_stage {
            HostKeyStage::Unseen => DraftStage::Untested,
            HostKeyStage::Observed | HostKeyStage::Changed => DraftStage::Review,
            HostKeyStage::Confirmed => DraftStage::Ready,
        }
    }

    /// Whether discover and add may proceed: the confirmed fingerprint must
    /// still be the one the host presents.
    #[must_use]
    pub fn trust_ready(&self) -> bool {
        self.host_key_stage == HostKeyStage::Confirmed
    }
}

/// A new draft, before identity minting.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewDraft {
    /// The proposed endpoint.
    pub endpoint: DraftEndpoint,
    /// How the controller would authenticate.
    pub auth: OnboardAuth,
    /// The proposed machine name; `None` derives it from the host.
    pub name: Option<String>,
    /// Operator notes carried onto the machine.
    pub description: String,
    /// Tags carried onto the machine.
    pub tags: Vec<String>,
    /// Groups carried onto the machine.
    pub groups: Vec<String>,
    /// The caller's idempotency key, when one was supplied: replaying a
    /// create with the same key returns the original draft instead of
    /// creating a second one. None for ordinary UI drafts.
    pub idempotency_key: Option<String>,
}

/// The storage contract for onboarding drafts. Drafts are controller-owned
/// review state; nothing here interprets trust or reaches the network.
#[async_trait]
pub trait OnboardingPort: fmt::Debug + Send + Sync {
    /// Creates a draft, minting its identity.
    ///
    /// # Errors
    ///
    /// Fails on a backend error.
    async fn create(&self, draft: &NewDraft) -> Result<OnboardingDraft, PortFailure>;
    /// The draft carrying this idempotency key, when any.
    ///
    /// # Errors
    ///
    /// Fails on a backend error.
    async fn find_by_idempotency_key(
        &self,
        key: &str,
    ) -> Result<Option<OnboardingDraft>, PortFailure>;
    /// Reads one draft.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn get(&self, id: &str) -> Result<OnboardingDraft, PortFailure>;
    /// Lists drafts, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list(&self, limit: u32) -> Result<Vec<OnboardingDraft>, PortFailure>;
    /// Replaces a draft's mutable state wholesale. Drafts are single-writer
    /// review state; the last accepted mutation wins.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn update(&self, draft: &OnboardingDraft) -> Result<OnboardingDraft, PortFailure>;
    /// Deletes a draft and everything staged in it. This *is* the cleanup:
    /// a deleted draft leaves no row, no facts, and no references behind.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn delete(&self, id: &str) -> Result<(), PortFailure>;
}

/// The trust port: pin and unpin a host key in the Fleet known-hosts file.
/// The composition root implements this over the SSH provider's isolated
/// configuration; the application layer never invokes OpenSSH itself.
#[async_trait]
pub trait OnboardTrustPort: fmt::Debug + Send + Sync {
    /// Pins a confirmed observation. Callers must have verified the
    /// fingerprint through the authorized confirm use case first.
    ///
    /// # Errors
    ///
    /// Fails when the trust store cannot be written.
    async fn pin(&self, host: &str, key: &OnboardHostKey) -> Result<(), PortFailure>;
    /// Removes every pin for `host`.
    ///
    /// # Errors
    ///
    /// Fails when the trust store cannot be rewritten.
    async fn unpin(&self, host: &str) -> Result<(), PortFailure>;
}

/// One existing machine whose endpoint matches a draft's host and port.
/// Candidates warn; they never merge or block.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateCandidate {
    /// The existing machine's identity.
    pub machine_id: String,
    /// The existing machine's name.
    pub name: String,
    /// The existing machine's derived connectivity state.
    pub machine_status: MachineStatus,
    /// The matching endpoint reference, as the caller may see it (already
    /// redacted when the caller may not read sensitive endpoint detail).
    pub reference: String,
}

/// The operator-facing draft view: the record with the derived stage, the
/// profile hint, and the duplicate candidates, with credential-bearing
/// endpoint detail redacted when the caller may not see it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftView {
    /// The draft's identity.
    pub id: String,
    /// The proposed endpoint; the user is redacted unless the caller may
    /// read sensitive endpoint detail.
    pub endpoint: DraftEndpoint,
    /// How the controller would authenticate.
    pub auth: OnboardAuth,
    /// The proposed machine name.
    pub name: String,
    /// Operator notes carried onto the machine.
    pub description: String,
    /// Tags carried onto the machine.
    pub tags: Vec<String>,
    /// Groups carried onto the machine.
    pub groups: Vec<String>,
    /// The derived stage: what the flow asks the operator for next.
    pub stage: DraftStage,
    /// The host-key trust stage, as recorded.
    pub host_key_stage: HostKeyStage,
    /// The newest observed host key, when a test ran.
    pub host_key: Option<OnboardHostKey>,
    /// The fingerprint the operator confirmed, when any.
    pub confirmed_fingerprint: Option<String>,
    /// The newest test outcome, when a test ran.
    pub last_test: Option<TestOutcome>,
    /// The facts discovery recorded for review.
    pub facts: Vec<CapabilityFact>,
    /// When discovery completed (epoch milliseconds).
    pub discovered_at: Option<i64>,
    /// The OS/profile hint derived from the facts, when the facts name an
    /// operating system. A display hint only; nothing is applied.
    pub profile_hint: Option<String>,
    /// Existing machines whose endpoints share the draft's host and port.
    /// Empty in list responses; computed for the detail view and for add.
    pub duplicates: Vec<DuplicateCandidate>,
    /// Creation time (epoch milliseconds).
    pub created_at: i64,
    /// Last mutation (epoch milliseconds).
    pub updated_at: i64,
}

/// The outcome of an add: the new machine as the caller may see it, plus the
/// duplicates that were warned about.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddedMachine {
    /// The registered machine's view, redacted per the caller's permissions.
    pub machine: MachineView,
    /// Existing machines that shared the draft's host and port. The add
    /// proceeded anyway: candidates warn, they do not merge.
    pub duplicates: Vec<DuplicateCandidate>,
}

/// A use-case rejection, mapped onto public API errors by the adapter.
#[derive(Debug)]
pub enum OnboardingUseCaseError {
    /// The caller may not perform the action.
    Denied(Decision),
    /// The draft named does not exist.
    NotFound {
        /// What was not found.
        what: String,
    },
    /// The current draft state forbids the action.
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

impl fmt::Display for OnboardingUseCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Conflict { detail } => write!(f, "conflict: {detail}"),
            Self::Invalid { detail } => write!(f, "invalid request: {detail}"),
            Self::Backend { context, detail } => write!(f, "onboarding {context} failed: {detail}"),
        }
    }
}

impl std::error::Error for OnboardingUseCaseError {}

/// The authorized onboarding use cases.
///
/// Every mutation funnels through the authorization catalog and appends an
/// audit intent, in that order. Draft lifecycle actions and add gate on
/// `machine.create` — creating a machine is the outcome of this workflow —
/// and reads gate on `machine.read`.
#[derive(Debug)]
pub struct Onboarding {
    drafts: Arc<dyn OnboardingPort>,
    trust: Arc<dyn OnboardTrustPort>,
    machines: Arc<Machines>,
    audit: Arc<dyn crate::operation::AuditPort>,
}

impl Onboarding {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(
        drafts: Arc<dyn OnboardingPort>,
        trust: Arc<dyn OnboardTrustPort>,
        machines: Arc<Machines>,
        audit: Arc<dyn crate::operation::AuditPort>,
    ) -> Self {
        Self {
            drafts,
            trust,
            machines,
            audit,
        }
    }

    /// Creates a draft. No network contact happens here; the address is
    /// only staged for the first test.
    ///
    /// # Errors
    ///
    /// Fails on denial or a malformed or conflicting draft.
    pub async fn create_draft(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        new: NewDraft,
    ) -> Result<DraftView, OnboardingUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineCreate,
                resource: None,
            },
        )
        .map_err(OnboardingUseCaseError::Denied)?;
        validate_new_draft(&new)?;

        // Idempotent replay: the same key returns the original draft rather
        // than creating a second one.
        if let Some(key) = &new.idempotency_key
            && let Some(existing) = self
                .drafts
                .find_by_idempotency_key(key)
                .await
                .map_err(|failure| map_port("find_by_idempotency_key", failure))?
        {
            let sensitive = self.may_read_sensitive(authorizer, principal, &existing.id);
            return Ok(assemble_view(existing, sensitive, Vec::new()));
        }

        let draft = self
            .drafts
            .create(&new)
            .await
            .map_err(|failure| map_port("create", failure))?;
        self.audit_draft(
            principal,
            &draft.id,
            "onboarding_draft_created",
            Some(("host", &draft.endpoint.host)),
        )
        .await?;
        let sensitive = self.may_read_sensitive(authorizer, principal, &draft.id);
        Ok(assemble_view(draft, sensitive, Vec::new()))
    }

    /// Reads one draft as the operator-facing view, including the derived
    /// stage, the profile hint, and the duplicate candidates.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown draft, or a backend failure.
    pub async fn get_draft(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        now: i64,
    ) -> Result<DraftView, OnboardingUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineRead,
                resource: Some(id),
            },
        )
        .map_err(OnboardingUseCaseError::Denied)?;
        let draft = self
            .drafts
            .get(id)
            .await
            .map_err(|failure| map_port("get", failure))?;
        let sensitive = self.may_read_sensitive(authorizer, principal, id);
        let duplicates = self
            .duplicate_candidates(authorizer, principal, &draft.endpoint, now)
            .await?;
        Ok(assemble_view(draft, sensitive, duplicates))
    }

    /// Lists drafts, newest first, as summary views. Duplicate candidates
    /// are a detail-view concern: computing them per draft per list would
    /// multiply machine scans for facts a summary does not show.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list_drafts(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        limit: u32,
    ) -> Result<Vec<DraftView>, OnboardingUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineRead,
                resource: None,
            },
        )
        .map_err(OnboardingUseCaseError::Denied)?;
        let limit = limit.clamp(1, 200);
        let drafts = self
            .drafts
            .list(limit)
            .await
            .map_err(|failure| map_port("list", failure))?;
        let mut views = Vec::with_capacity(drafts.len());
        for draft in drafts {
            let sensitive = self.may_read_sensitive(authorizer, principal, &draft.id);
            views.push(assemble_view(draft, sensitive, Vec::new()));
        }
        Ok(views)
    }

    /// Confirms the observed fingerprint explicitly. This is the
    /// trust-on-first-use act: the caller states the fingerprint it verified
    /// (out of band, or by reading it in the review surface), and only the
    /// currently observed fingerprint may be confirmed. Confirming over a
    /// change re-pins: the stale pins for the host are removed first.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown draft, a mismatched or malformed
    /// fingerprint, or a backend failure.
    pub async fn confirm_host_key(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        draft_id: &str,
        fingerprint: &str,
    ) -> Result<DraftView, OnboardingUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineCreate,
                resource: None,
            },
        )
        .map_err(OnboardingUseCaseError::Denied)?;
        if !fingerprint.starts_with("SHA256:") || fingerprint.len() > 128 {
            return Err(OnboardingUseCaseError::Invalid {
                detail: "the fingerprint must be an OpenSSH SHA256 fingerprint".to_owned(),
            });
        }
        let mut draft = self
            .drafts
            .get(draft_id)
            .await
            .map_err(|failure| map_port("get", failure))?;
        let host_key = draft
            .host_key
            .clone()
            .ok_or_else(|| OnboardingUseCaseError::Conflict {
                detail: "no host key was observed yet; run a test first".to_owned(),
            })?;
        if host_key.fingerprint != fingerprint {
            return Err(OnboardingUseCaseError::Invalid {
                detail: "the fingerprint does not match the one the host presented".to_owned(),
            });
        }
        if draft.host_key_stage == HostKeyStage::Changed {
            // Re-confirmation over a change: the old pins are stale trust
            // and must go before the new line is appended.
            self.trust
                .unpin(&draft.endpoint.host)
                .await
                .map_err(|failure| map_port("unpin", failure))?;
        }
        self.trust
            .pin(&draft.endpoint.host, &host_key)
            .await
            .map_err(|failure| map_port("pin", failure))?;
        draft.host_key_stage = HostKeyStage::Confirmed;
        draft.confirmed_fingerprint = Some(fingerprint.to_owned());
        draft.updated_at = fleet_core::SystemClock::now_unix_millis();
        let draft = self
            .drafts
            .update(&draft)
            .await
            .map_err(|failure| map_port("update", failure))?;
        self.audit_draft(
            principal,
            draft_id,
            "onboarding_host_key_confirmed",
            Some(("fingerprint", fingerprint)),
        )
        .await?;
        let sensitive = self.may_read_sensitive(authorizer, principal, draft_id);
        Ok(assemble_view(draft, sensitive, Vec::new()))
    }

    /// The draft carrying this caller's idempotency key, as the caller may
    /// see it. Used by import-style flows whose replay must return the
    /// original draft even after the integration changed. The lookup is
    /// keyed to the principal, so a key is never shared across callers.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown key, or a backend failure.
    pub async fn draft_by_key(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        key: &str,
    ) -> Result<Option<DraftView>, OnboardingUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineRead,
                resource: None,
            },
        )
        .map_err(OnboardingUseCaseError::Denied)?;
        let scoped = format!("{}:{key}", principal.id);
        let Some(draft) = self
            .drafts
            .find_by_idempotency_key(&scoped)
            .await
            .map_err(|failure| map_port("find_by_idempotency_key", failure))?
        else {
            return Ok(None);
        };
        let sensitive = self.may_read_sensitive(authorizer, principal, &draft.id);
        Ok(Some(assemble_view(draft, sensitive, Vec::new())))
    }

    /// Abandons a draft: the row is deleted — the defined cleanup — and the
    /// host's pins are removed unless an existing machine endpoint shares
    /// the host, so cancelling one draft never breaks another machine's
    /// trust.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown draft, or a backend failure.
    pub async fn cancel_draft(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        draft_id: &str,
        now: i64,
    ) -> Result<(), OnboardingUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineCreate,
                resource: None,
            },
        )
        .map_err(OnboardingUseCaseError::Denied)?;
        let draft = self
            .drafts
            .get(draft_id)
            .await
            .map_err(|failure| map_port("get", failure))?;
        let shared = self
            .host_is_registered(authorizer, principal, &draft.endpoint, now)
            .await?;
        if !shared {
            self.trust
                .unpin(&draft.endpoint.host)
                .await
                .map_err(|failure| map_port("unpin", failure))?;
        }
        self.drafts
            .delete(draft_id)
            .await
            .map_err(|failure| map_port("delete", failure))?;
        self.audit_draft(principal, draft_id, "onboarding_cancelled", None)
            .await?;
        Ok(())
    }

    /// Completes onboarding: registers the machine under the draft's
    /// identity, confirms the draft's fingerprint on the new endpoint,
    /// ingests the discovered facts and snapshot when any, deletes the
    /// draft, and answers with the new machine plus the duplicates that
    /// were warned about — never merged.
    ///
    /// A draft with partial, unknown, or even zero facts adds fine: the
    /// facts are an observation, not a requirement.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown draft, an unconfirmed or changed host
    /// key, or any machine-mutation failure.
    pub async fn add(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        draft_id: &str,
        now: i64,
    ) -> Result<AddedMachine, OnboardingUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineCreate,
                resource: None,
            },
        )
        .map_err(OnboardingUseCaseError::Denied)?;
        let draft = self
            .drafts
            .get(draft_id)
            .await
            .map_err(|failure| map_port("get", failure))?;
        if !draft.trust_ready() {
            return Err(OnboardingUseCaseError::Conflict {
                detail: "the host key is not confirmed; confirm the fingerprint first".to_owned(),
            });
        }
        let duplicates = self
            .duplicate_candidates(authorizer, principal, &draft.endpoint, now)
            .await?;
        let confirmed_fingerprint = draft.confirmed_fingerprint.clone().ok_or_else(|| {
            OnboardingUseCaseError::Conflict {
                detail: "the draft has no confirmed fingerprint".to_owned(),
            }
        })?;

        let registration = RegisterMachine {
            name: draft.name.clone(),
            description: draft.description.clone(),
            endpoints: vec![crate::machine::NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: draft.endpoint.reference(),
            }],
            tags: draft.tags.clone(),
            groups: draft.groups.clone(),
        };
        let machine = self
            .machines
            .register(authorizer, principal, &registration)
            .await
            .map_err(map_machine_error)?;
        let endpoint_id = machine
            .endpoints
            .iter()
            .find(|endpoint| endpoint.kind == EndpointKind::Ssh)
            .map(|endpoint| endpoint.id.clone())
            .ok_or_else(|| OnboardingUseCaseError::Backend {
                context: "add",
                detail: "the registered machine has no SSH endpoint".to_owned(),
            })?;
        self.machines
            .confirm_host_key(authorizer, principal, &endpoint_id, &confirmed_fingerprint)
            .await
            .map_err(map_machine_error)?;
        if !draft.facts.is_empty() {
            self.machines
                .record_capabilities(authorizer, principal, &machine.id, &draft.facts)
                .await
                .map_err(map_machine_error)?;
            let snapshot = serde_json::to_string(&draft.facts).map_err(|error| {
                OnboardingUseCaseError::Backend {
                    context: "add",
                    detail: format!("the fact set does not serialize: {error}"),
                }
            })?;
            self.machines
                .record_snapshot(
                    authorizer,
                    principal,
                    &machine.id,
                    draft.discovery_source.as_deref().unwrap_or("agentless/1"),
                    &snapshot,
                    draft.discovered_at.unwrap_or(now),
                )
                .await
                .map_err(map_machine_error)?;
        }
        self.drafts
            .delete(draft_id)
            .await
            .map_err(|failure| map_port("delete", failure))?;
        self.audit_draft(principal, &machine.id, "onboarding_completed", None)
            .await?;

        // The response is the fresh read surface — registration, the
        // confirmed fingerprint, and the ingested facts included — not the
        // register call's pre-ingestion record.
        let machine_view = self
            .machines
            .get(authorizer, principal, &machine.id, now)
            .await
            .map_err(map_machine_error)?;
        Ok(AddedMachine {
            machine: machine_view,
            duplicates,
        })
    }

    /// Whether the caller may see sensitive endpoint detail for one draft
    /// or machine. A denial is not an error: it redacts, it does not refuse.
    #[allow(clippy::unused_self)]
    fn may_read_sensitive(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        resource_id: &str,
    ) -> bool {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineReadSensitive,
                resource: Some(resource_id),
            },
        )
        .is_ok()
    }

    /// The existing machines whose SSH endpoints share the draft's host and
    /// port. Names only ever warn.
    async fn duplicate_candidates(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        endpoint: &DraftEndpoint,
        now: i64,
    ) -> Result<Vec<DuplicateCandidate>, OnboardingUseCaseError> {
        let views = self
            .machines
            .list(authorizer, principal, &MachineFilter::default(), 200, now)
            .await
            .map_err(map_machine_error)?;
        Ok(views
            .iter()
            .filter_map(|view| {
                let matching = view.endpoints.iter().find(|candidate| {
                    candidate.kind == EndpointKind::Ssh
                        && endpoint_reference_matches(&candidate.reference, endpoint)
                })?;
                Some(DuplicateCandidate {
                    machine_id: view.id.clone(),
                    name: view.name.clone(),
                    machine_status: view.machine_status,
                    reference: matching.reference.clone(),
                })
            })
            .collect())
    }

    /// Whether any existing machine endpoint references the draft's host.
    /// This is the unpin guard, and it is host-scoped on purpose: removing
    /// pins removes every pin for the host across ports, so a host another
    /// machine already reaches must keep all of them.
    async fn host_is_registered(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        endpoint: &DraftEndpoint,
        now: i64,
    ) -> Result<bool, OnboardingUseCaseError> {
        let views = self
            .machines
            .list(authorizer, principal, &MachineFilter::default(), 200, now)
            .await
            .map_err(map_machine_error)?;
        Ok(views.iter().any(|view| {
            view.endpoints.iter().any(|candidate| {
                candidate.kind == EndpointKind::Ssh
                    && reference_host(&candidate.reference)
                        .is_some_and(|host| host.eq_ignore_ascii_case(&endpoint.host))
            })
        }))
    }

    async fn audit_draft(
        &self,
        principal: &ActingPrincipal,
        resource_id: &str,
        event: &str,
        fact: Option<(&str, &str)>,
    ) -> Result<(), OnboardingUseCaseError> {
        let mut metadata = crate::audit::AuditMetadata::default();
        metadata
            .insert("event", event)
            .map_err(|error| OnboardingUseCaseError::Backend {
                context: "audit",
                detail: error.to_string(),
            })?;
        if let Some((key, value)) = fact {
            metadata
                .insert(key, value)
                .map_err(|error| OnboardingUseCaseError::Backend {
                    context: "audit",
                    detail: error.to_string(),
                })?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: Permission::MachineCreate.id().to_owned(),
                resource: Some(resource_id.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| OnboardingUseCaseError::Backend {
                context: "audit",
                detail,
            })
    }
}

/// Assembles the operator-facing view from a draft. `sensitive` is the
/// authorization answer for the caller's `machine.read.sensitive` request;
/// when it is denied, the endpoint's userinfo is redacted, exactly as the
/// machine read model does.
#[must_use]
pub fn assemble_view(
    draft: OnboardingDraft,
    sensitive: bool,
    duplicates: Vec<DuplicateCandidate>,
) -> DraftView {
    let endpoint = DraftEndpoint {
        user: if sensitive {
            draft.endpoint.user.clone()
        } else {
            "***".to_owned()
        },
        host: draft.endpoint.host.clone(),
        port: draft.endpoint.port,
    };
    let stage = draft.stage();
    let profile_hint = profile_hint(&draft.facts);
    DraftView {
        id: draft.id,
        endpoint,
        auth: draft.auth,
        name: draft.name,
        description: draft.description,
        tags: draft.tags,
        groups: draft.groups,
        stage,
        host_key_stage: draft.host_key_stage,
        host_key: draft.host_key,
        confirmed_fingerprint: draft.confirmed_fingerprint,
        last_test: draft.last_test,
        facts: draft.facts,
        discovered_at: draft.discovered_at,
        profile_hint,
        duplicates,
        created_at: draft.created_at,
        updated_at: draft.updated_at,
    }
}

/// Derives the OS/profile hint from discovered facts: a display string such
/// as `linux/debian/12/x86_64`, built from what the probe actually answered.
/// `None` when no operating-system family was observed. This is a hint for
/// the review step, never an assignment — profiles are applied elsewhere or
/// not at all.
#[must_use]
pub fn profile_hint(facts: &[CapabilityFact]) -> Option<String> {
    let known = |namespace: &str, name: &str| -> Option<String> {
        facts
            .iter()
            .find(|fact| {
                fact.namespace == namespace
                    && fact.name == name
                    && fact.status == fleet_core::CapabilityStatus::Known
            })
            .and_then(|fact| fact.value.clone())
            .filter(|value| !value.is_empty())
    };
    let family = known("os", "family")?;
    let mut parts = vec![family];
    if let Some(distribution) = known("os", "distribution") {
        let versioned = known("os", "distribution_version")
            .map(|version| format!("{distribution}-{version}"))
            .unwrap_or(distribution);
        parts.push(versioned);
    }
    if let Some(architecture) = known("host", "architecture") {
        parts.push(architecture);
    }
    Some(parts.join("/"))
}

/// Whether an endpoint reference (possibly redacted: `***@host:port`)
/// matches a draft's host and port. The userinfo never participates.
#[must_use]
pub fn endpoint_reference_matches(reference: &str, endpoint: &DraftEndpoint) -> bool {
    reference_host(reference).is_some_and(|host| host.eq_ignore_ascii_case(&endpoint.host))
        && reference_port(reference).is_some_and(|port| port == endpoint.port.to_string())
}

/// The host part of an endpoint reference, ignoring userinfo. Bracketed
/// IPv6 literals strip their brackets; the comparison sees the bare
/// address.
#[must_use]
pub(crate) fn reference_host(reference: &str) -> Option<&str> {
    let (_, host_port) = reference.rsplit_once('@')?;
    let host_port = match host_port.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map_or(host_port, |(inner, _)| inner),
        None => host_port,
    };
    let (host, _) = host_port.rsplit_once(':')?;
    Some(host)
}

/// The port part of an endpoint reference, as text.
fn reference_port(reference: &str) -> Option<&str> {
    let (_, host_port) = reference.rsplit_once('@')?;
    let (_, port) = host_port.rsplit_once(':')?;
    Some(port)
}

fn map_port(context: &'static str, failure: PortFailure) -> OnboardingUseCaseError {
    match failure {
        PortFailure::NotFound { what } => OnboardingUseCaseError::NotFound { what },
        PortFailure::Conflict { detail } => OnboardingUseCaseError::Conflict { detail },
        PortFailure::Backend { detail } => OnboardingUseCaseError::Backend { context, detail },
    }
}

fn map_machine_error(error: crate::machine::MachineUseCaseError) -> OnboardingUseCaseError {
    use crate::machine::MachineUseCaseError as E;
    match error {
        E::Denied(decision) => OnboardingUseCaseError::Denied(decision),
        E::NotFound { what } => OnboardingUseCaseError::NotFound { what },
        E::Conflict { detail } => OnboardingUseCaseError::Conflict { detail },
        E::Invalid { detail } => OnboardingUseCaseError::Invalid { detail },
        E::Backend { context, detail } => OnboardingUseCaseError::Backend { context, detail },
    }
}

fn validate_new_draft(new: &NewDraft) -> Result<(), OnboardingUseCaseError> {
    let error = |detail: String| OnboardingUseCaseError::Invalid { detail };
    if new.endpoint.user.is_empty() || new.endpoint.user.len() > 64 {
        return Err(error(
            "the endpoint user must be 1..=64 characters".to_owned(),
        ));
    }
    if new.endpoint.host.is_empty() || new.endpoint.host.len() > 253 {
        return Err(error(
            "the endpoint host must be 1..=253 characters".to_owned(),
        ));
    }
    if new.endpoint.port == 0 {
        return Err(error("the endpoint port must be 1..=65535".to_owned()));
    }
    match &new.auth {
        OnboardAuth::Agent => {}
        OnboardAuth::IdentityFile { path } => {
            if path.is_empty() || path.len() > 512 {
                return Err(error(
                    "the identity-file path must be 1..=512 characters".to_owned(),
                ));
            }
        }
    }
    for tag in &new.tags {
        if tag.is_empty() || tag.len() > 64 {
            return Err(error("tag names must be 1..=64 characters".to_owned()));
        }
    }
    for group in &new.groups {
        if group.is_empty() || group.len() > 64 {
            return Err(error("group names must be 1..=64 characters".to_owned()));
        }
    }
    // The effective name is validated by the machine-name rule, because add
    // registers the machine under it. An absent name derives from the host.
    let name = new
        .name
        .clone()
        .unwrap_or_else(|| new.endpoint.host.clone());
    if name.is_empty() || name.len() > 64 {
        return Err(error(
            "the machine name must be 1..=64 characters; the host is too long to derive one, so name the machine explicitly".to_owned(),
        ));
    }
    if new.description.len() > 512 {
        return Err(error(
            "the description must be at most 512 characters".to_owned(),
        ));
    }
    Ok(())
}
