//! The periodic desired-source fetch (FM-1014): an optional controller loop
//! that notices a pushed commit on the configured remote and queues the
//! ordinary `source.fetch` operation for it, so a Registry edit reaches the
//! console without a manual step (a Registry-only revision then activates
//! under the auto-activation policy in `fleet_application::source`).
//!
//! The loop adds no fetch logic of its own. It only resolves the remote's
//! `HEAD` and creates the same durable operation the fetch-now endpoint
//! creates. It never overlaps a fetch: a tick does nothing while any
//! `source.fetch` operation is still pending or running, and an operation
//! it queued that failed is retried on a later tick. It is off unless an
//! interval is configured (`FLEET_DESIRED_FETCH_INTERVAL_SECONDS`).

use std::sync::Arc;
use std::time::Duration;

use fleet_application::operation::{NewOperation, Operations};
use fleet_application::source::{DesiredSource, GitCredentialStore};
use fleet_provider_git::{GitCredential, GitSource};

/// Resolves the head commit of a remote, so tests can stand in for the
/// network.
#[async_trait::async_trait]
pub trait HeadResolver: std::fmt::Debug + Send + Sync {
    /// The full SHA of the remote's default-branch head. The credential
    /// attached is the one configured for that remote, resolved just in
    /// time.
    ///
    /// # Errors
    ///
    /// Fails with a bounded, secret-free detail.
    async fn head(&self, remote: &str, credential_ref: Option<&str>) -> Result<String, String>;
}

/// The resolver over `git ls-remote`.
#[derive(Debug)]
pub struct GitHeadResolver {
    source: GitSource,
    credentials: Option<Arc<dyn GitCredentialStore>>,
}

impl GitHeadResolver {
    /// Composes the resolver over the git work root.
    #[must_use]
    pub fn new(source: GitSource, credentials: Option<Arc<dyn GitCredentialStore>>) -> Self {
        Self {
            source,
            credentials,
        }
    }
}

#[async_trait::async_trait]
impl HeadResolver for GitHeadResolver {
    async fn head(&self, remote: &str, credential_ref: Option<&str>) -> Result<String, String> {
        let credential = match credential_ref {
            None => None,
            Some(reference) => {
                let resolved = match &self.credentials {
                    Some(store) => store.resolve(reference).await,
                    None => Ok(None),
                };
                match resolved {
                    Ok(Some(value)) => Some(GitCredential::from_secret_value(&value)),
                    Ok(None) => return Err(crate::source::CREDENTIAL_UNAVAILABLE.to_owned()),
                    Err(_) => return Err(crate::source::CREDENTIAL_UNREADABLE.to_owned()),
                }
            }
        };
        let source = self.source.clone();
        let remote = remote.to_owned();
        tokio::task::spawn_blocking(move || source.resolve_head(&remote, credential.as_ref()))
            .await
            .map_err(|error| format!("the head lookup thread failed: {error}"))?
    }
}

/// What one tick did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PollOutcome {
    /// No desired-source remote is configured.
    NoRemote,
    /// A `source.fetch` operation is still pending or running.
    Busy,
    /// The head is the commit this loop already fetched successfully.
    Unchanged,
    /// The remote's head could not be resolved.
    ResolveFailed(String),
    /// A `source.fetch` operation was queued for the head.
    Queued {
        /// The queued operation.
        operation_id: String,
        /// The commit it fetches.
        commit_sha: String,
    },
    /// The operation could not be queued.
    QueueFailed(String),
}

/// The last fetch this loop queued.
#[derive(Debug)]
struct Queued {
    operation_id: String,
    commit_sha: String,
}

/// The periodic fetch loop.
#[derive(Debug)]
pub struct SourcePoller {
    desired: Arc<DesiredSource>,
    operations: Arc<Operations>,
    resolver: Arc<dyn HeadResolver>,
    last: tokio::sync::Mutex<Option<Queued>>,
}

impl SourcePoller {
    /// Composes the loop from the use cases and the head resolver.
    #[must_use]
    pub fn new(
        desired: Arc<DesiredSource>,
        operations: Arc<Operations>,
        resolver: Arc<dyn HeadResolver>,
    ) -> Self {
        Self {
            desired,
            operations,
            resolver,
            last: tokio::sync::Mutex::new(None),
        }
    }

    /// Runs one tick. Ticks serialize: a second call waits for the first.
    pub async fn tick(&self) -> PollOutcome {
        let authorizer = fleet_auth::LanAllowAllAuthorizer;
        let principal = fleet_auth::LAN_PRINCIPAL_ID;
        let mut last = self.last.lock().await;
        // Never overlap a fetch, whoever queued it.
        match self.operations.list(&authorizer, principal, 100).await {
            Ok(operations) => {
                if operations.iter().any(|operation| {
                    operation.kind == "source.fetch"
                        && fleet_core::OperationState::from_id(&operation.state)
                            .is_ok_and(|state| !state.is_terminal())
                }) {
                    return PollOutcome::Busy;
                }
            }
            Err(error) => return PollOutcome::QueueFailed(error.to_string()),
        }
        let config = match self.desired.configuration(&authorizer, principal).await {
            Ok(Some(config)) => config,
            Ok(None) => return PollOutcome::NoRemote,
            Err(error) => return PollOutcome::QueueFailed(error.to_string()),
        };
        let head = match self
            .resolver
            .head(&config.remote, config.credential_ref.as_deref())
            .await
        {
            Ok(head) => head,
            Err(detail) => return PollOutcome::ResolveFailed(detail),
        };
        if let Some(queued) = last.as_ref()
            && queued.commit_sha == head
            && self
                .operations
                .get_state(&queued.operation_id)
                .await
                .is_ok_and(|state| state == fleet_core::OperationState::Succeeded.id())
        {
            return PollOutcome::Unchanged;
        }
        // The payload never carries a credential: the executor reads the
        // configured reference itself.
        let payload = serde_json::json!({ "remote": config.remote, "commitSha": head });
        match self
            .operations
            .create(
                &authorizer,
                principal,
                &NewOperation {
                    kind: "source.fetch".to_owned(),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    payload_json: Some(payload.to_string()),
                    review_token: None,
                },
            )
            .await
        {
            Ok(operation) => {
                *last = Some(Queued {
                    operation_id: operation.id.clone(),
                    commit_sha: head.clone(),
                });
                PollOutcome::Queued {
                    operation_id: operation.id,
                    commit_sha: head,
                }
            }
            Err(error) => PollOutcome::QueueFailed(error.to_string()),
        }
    }

    /// Ticks every `interval` until `shutdown` resolves. The first tick
    /// waits one interval, so a restart does not fetch immediately.
    pub async fn run(
        self: Arc<Self>,
        interval: Duration,
        shutdown: impl std::future::Future<Output = ()>,
    ) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                () = tokio::time::sleep(interval) => {}
            }
            let outcome = tokio::select! {
                () = &mut shutdown => break,
                outcome = self.tick() => outcome,
            };
            match outcome {
                PollOutcome::ResolveFailed(detail) | PollOutcome::QueueFailed(detail) => {
                    eprintln!("desired-source poller: {detail}; retrying next interval");
                }
                PollOutcome::NoRemote
                | PollOutcome::Busy
                | PollOutcome::Unchanged
                | PollOutcome::Queued { .. } => {}
            }
        }
    }
}
