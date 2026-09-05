//! The onboarding executor and its trust adapter: the controller half of
//! FM-210's Add Machine workflow.
//!
//! [`OnboardingExecutor`] runs the two durable onboarding operation kinds.
//! `machine.onboard.test` probes a draft's host key, decides
//! observed/confirmed/changed against what the draft already trusts, and —
//! only when the fingerprint was confirmed — runs a bounded connection test.
//! It never touches the machines record: a test's side effects live in the
//! draft row, which is the point of the "no persistent machine side effect"
//! rule. `machine.onboard.discover` runs the same agentless probe the
//! machine-level `agentless.inventory` operation uses, but ingests into the
//! draft for review instead of into a machine.
//!
//! [`SshTrustAdapter`] implements the application's [`OnboardTrustPort`] over
//! the SSH provider's isolated configuration directory — the same directory
//! the script executor uses, so there is exactly one Fleet trust store per
//! controller. The provider is synchronous on purpose; every call here rides
//! the blocking pool.
//!
//! Any other kind is delegated to the composed fallback (the SSH executor,
//! itself wrapped by the node executor), so the chain of executors stays one
//! dispatch.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use fleet_application::onboarding::{
    OnboardAuth, OnboardHostKey, OnboardingDraft, OnboardingPort, TestOutcome,
};
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_provider_ssh::{ExecutionLimiter, SshAuth, SshConnectionSpec, SshProvider};

/// How long a host-key probe may take. `ssh-keyscan` bounds itself with the
/// same value; a slower host is an unreachable host.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the connect check may take; the same bound the provider's trust
/// workflow tests use.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The payload of an onboarding operation, as validated JSON.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct OnboardPayload {
    /// The draft the operation works on.
    draft_id: String,
}

/// The kind-dispatching onboarding executor.
#[derive(Debug)]
pub struct OnboardingExecutor {
    drafts: Arc<dyn OnboardingPort>,
    provider: SshProvider,
    limiter: Arc<ExecutionLimiter>,
    fallback: Arc<dyn OperationExecutor>,
}

impl OnboardingExecutor {
    /// Composes the executor from its parts. The provider's isolated
    /// directory must be the controller's SSH work directory, so pins made
    /// here are the pins later SSH operations verify against.
    ///
    /// # Panics
    ///
    /// Panics only if the SSH work directory cannot be prepared, which the
    /// store's own data-directory preparation already ensures.
    #[must_use]
    pub fn new(
        drafts: Arc<dyn OnboardingPort>,
        work_dir: PathBuf,
        limiter: Arc<ExecutionLimiter>,
        fallback: Arc<dyn OperationExecutor>,
    ) -> Self {
        let provider = SshProvider::new(work_dir).expect("the SSH work dir must prepare");
        Self {
            drafts,
            provider,
            limiter,
            fallback,
        }
    }
}

#[async_trait]
impl OperationExecutor for OnboardingExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "machine.onboard.test" => self.execute_test(operations, operation).await,
            "machine.onboard.discover" => self.execute_discover(operations, operation).await,
            _ => self.fallback.execute(operations, operation).await,
        }
    }
}

impl OnboardingExecutor {
    /// The test stage: observe, decide, and — behind a confirmed fingerprint
    /// only — connect. The result is always a truthful observation; a changed
    /// key completes successfully *as an observation*, and the draft's stage
    /// records the block.
    async fn execute_test(
        &self,
        operations: &Operations,
        operation: &Operation,
    ) -> Result<(), String> {
        let payload: OnboardPayload = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a valid onboarding record: {error}"))?;
        let mut draft = self
            .drafts
            .get(&payload.draft_id)
            .await
            .map_err(|failure| failure.to_string())?;
        let spec = connection_spec(&draft)?;

        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!("probing the host key of {}", draft.endpoint.host)),
            )
            .await
            .map_err(|error| error.to_string())?;

        let provider = self.provider.clone();
        let (host, port) = (draft.endpoint.host.clone(), draft.endpoint.port);
        let probed = tokio::task::spawn_blocking(move || {
            provider.probe_host_key(&host, port, PROBE_TIMEOUT)
        })
        .await
        .unwrap_or_else(|join_error| {
            Err(fleet_provider_ssh::SshProviderError::Tool {
                tool: "ssh-keyscan",
                detail: format!("the probe thread failed: {join_error}"),
            })
        });
        let observation = match probed {
            Ok(observation) => observation,
            Err(error) => {
                return fail_operation(
                    operations,
                    &operation.id,
                    "probe_failed",
                    &error.to_string(),
                )
                .await;
            }
        };

        // The decision is against the fingerprint the draft confirmed, if
        // any: nothing confirmed means New, a match means Known, anything
        // else means Changed — and Changed blocks until re-confirmed.
        let decision = self
            .provider
            .decide(draft.confirmed_fingerprint.as_deref(), &observation);
        draft.host_key = Some(OnboardHostKey {
            key_type: observation.key_type.clone(),
            fingerprint: observation.fingerprint.clone(),
            raw_line: observation.raw_line.clone(),
        });
        draft.host_key_stage = match &decision {
            fleet_provider_ssh::TrustDecision::New { .. } => {
                fleet_application::onboarding::HostKeyStage::Observed
            }
            fleet_provider_ssh::TrustDecision::Known { .. } => {
                fleet_application::onboarding::HostKeyStage::Confirmed
            }
            fleet_provider_ssh::TrustDecision::Changed { .. } => {
                fleet_application::onboarding::HostKeyStage::Changed
            }
        };

        let mut outcome = TestOutcome {
            connect_attempted: false,
            connected: false,
            detail: None,
            at: fleet_core::SystemClock::now_unix_millis(),
        };
        if draft.trust_ready() {
            operations
                .record_progress(
                    &operation.id,
                    Some(0),
                    Some(1),
                    Some(&format!(
                        "testing authentication to {}",
                        draft.endpoint.host
                    )),
                )
                .await
                .map_err(|error| error.to_string())?;
            let provider = self.provider.clone();
            let connect =
                tokio::task::spawn_blocking(move || provider.test_connect(&spec, CONNECT_TIMEOUT))
                    .await
                    .unwrap_or_else(|join_error| {
                        Err(fleet_provider_ssh::SshProviderError::Tool {
                            tool: "ssh",
                            detail: format!("the connect thread failed: {join_error}"),
                        })
                    });
            outcome.connect_attempted = true;
            match connect {
                Ok(()) => outcome.connected = true,
                Err(error) => outcome.detail = Some(error.to_string()),
            }
        }
        draft.last_test = Some(outcome.clone());
        draft.updated_at = outcome.at;
        self.drafts
            .update(&draft)
            .await
            .map_err(|failure| failure.to_string())?;

        let result = serde_json::json!({
            "hostKeyStage": draft.host_key_stage.id(),
            "fingerprint": observation.fingerprint,
            "connectAttempted": outcome.connect_attempted,
            "connected": outcome.connected,
        })
        .to_string();
        operations
            .complete(&operation.id, "succeeded", Some(&result), None)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// The discover stage: the agentless probe against a confirmed draft,
    /// ingested into the draft for review. A partial probe is a partial
    /// answer, not a failure; zero facts is still a succeedable discover —
    /// unsupported facts must not block a basic agentless add.
    async fn execute_discover(
        &self,
        operations: &Operations,
        operation: &Operation,
    ) -> Result<(), String> {
        let payload: OnboardPayload = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a valid onboarding record: {error}"))?;
        let mut draft = self
            .drafts
            .get(&payload.draft_id)
            .await
            .map_err(|failure| failure.to_string())?;
        if !draft.trust_ready() {
            let reason = match draft.host_key_stage {
                fleet_application::onboarding::HostKeyStage::Changed => "host_key_changed",
                _ => "host_key_not_confirmed",
            };
            return fail_operation(
                operations,
                &operation.id,
                reason,
                "discover runs only against a draft whose confirmed fingerprint the host still presents",
            )
            .await;
        }
        let spec = connection_spec(&draft)?;

        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!("probing inventory on {}", draft.endpoint.host)),
            )
            .await
            .map_err(|error| error.to_string())?;

        let provider = self.provider.clone();
        let limiter = self.limiter.clone();
        let collected = tokio::task::spawn_blocking(move || {
            fleet_provider_ssh::collect(
                &provider,
                &limiter,
                &spec,
                fleet_provider_ssh::COLLECTION_DEADLINE,
            )
        })
        .await
        .unwrap_or_else(|join_error| {
            Err(fleet_provider_ssh::SshProviderError::Tool {
                tool: "ssh",
                detail: format!("the collection thread failed: {join_error}"),
            })
        });
        let facts = match collected {
            Ok(facts) => facts,
            Err(error) => {
                return fail_operation(
                    operations,
                    &operation.id,
                    "collection_failed",
                    &error.to_string(),
                )
                .await;
            }
        };

        let count = facts.len();
        draft.facts = facts;
        draft.discovery_source = Some(fleet_provider_ssh::PROBE_SOURCE.to_owned());
        draft.discovered_at = Some(fleet_core::SystemClock::now_unix_millis());
        draft.updated_at = fleet_core::SystemClock::now_unix_millis();
        self.drafts
            .update(&draft)
            .await
            .map_err(|failure| failure.to_string())?;

        let result = serde_json::json!({ "facts": count }).to_string();
        operations
            .complete(&operation.id, "succeeded", Some(&result), None)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// Builds the provider's connection spec from a draft. The provider's
/// authentication contract is the agent or an identity file; a draft can
/// carry nothing else.
fn connection_spec(draft: &OnboardingDraft) -> Result<SshConnectionSpec, String> {
    let auth = match &draft.auth {
        OnboardAuth::Agent => SshAuth::Agent,
        OnboardAuth::IdentityFile { path } => SshAuth::IdentityFile { path: path.clone() },
    };
    Ok(SshConnectionSpec {
        host: draft.endpoint.host.clone(),
        port: draft.endpoint.port,
        user: draft.endpoint.user.clone(),
        auth,
    })
}

/// Completes an operation as a failed observation with a bounded, honest
/// reason.
async fn fail_operation(
    operations: &Operations,
    operation_id: &str,
    reason: &str,
    detail: &str,
) -> Result<(), String> {
    let error_json = serde_json::json!({ "reason": reason, "detail": detail }).to_string();
    operations
        .complete(operation_id, "failed", None, Some(&error_json))
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// The SSH trust adapter: pin and unpin over the provider's isolated
/// configuration, on the blocking pool.
#[derive(Debug)]
pub struct SshTrustAdapter {
    provider: SshProvider,
}

impl SshTrustAdapter {
    /// Composes the adapter over the controller's SSH work directory — the
    /// same directory every other SSH surface uses, so one trust store
    /// serves the whole controller.
    ///
    /// # Panics
    ///
    /// Panics only if the SSH work directory cannot be prepared, which the
    /// store's own data-directory preparation already ensures.
    #[must_use]
    pub fn new(work_dir: PathBuf) -> Self {
        let provider = SshProvider::new(work_dir).expect("the SSH work dir must prepare");
        Self { provider }
    }
}

#[async_trait]
impl fleet_application::onboarding::OnboardTrustPort for SshTrustAdapter {
    async fn pin(
        &self,
        _host: &str,
        key: &OnboardHostKey,
    ) -> Result<(), fleet_application::operation::PortFailure> {
        let provider = self.provider.clone();
        let observation = fleet_provider_ssh::HostKeyObservation {
            key_type: key.key_type.clone(),
            fingerprint: key.fingerprint.clone(),
            raw_line: key.raw_line.clone(),
        };
        tokio::task::spawn_blocking(move || provider.pin(&observation))
            .await
            .map_or_else(
                |join_error| {
                    Err(fleet_application::operation::PortFailure::Backend {
                        detail: format!("the trust thread failed: {join_error}"),
                    })
                },
                |outcome| {
                    outcome.map_err(|error| fleet_application::operation::PortFailure::Backend {
                        detail: error.to_string(),
                    })
                },
            )
    }

    async fn unpin(&self, host: &str) -> Result<(), fleet_application::operation::PortFailure> {
        let provider = self.provider.clone();
        let host = host.to_owned();
        tokio::task::spawn_blocking(move || provider.unpin(&host))
            .await
            .map_or_else(
                |join_error| {
                    Err(fleet_application::operation::PortFailure::Backend {
                        detail: format!("the trust thread failed: {join_error}"),
                    })
                },
                |outcome| {
                    outcome.map(|_| ()).map_err(|error| {
                        fleet_application::operation::PortFailure::Backend {
                            detail: error.to_string(),
                        }
                    })
                },
            )
    }
}
