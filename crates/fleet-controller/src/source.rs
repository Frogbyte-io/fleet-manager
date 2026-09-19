//! The desired-source executor (FM-403): durable fetch/activate
//! operations over the Git source provider.
//!
//! `source.fetch` clones the pinned commit, validates, and records the
//! outcome through the authorized use case (valid candidates become
//! rollback points; invalid ones are reported and forgotten).
//! `source.activate` activates a fetched candidate through the authorized
//! use case — the activation is serialized and audited there.

use std::sync::Arc;

use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_provider_git::GitSource;

/// The `source.fetch` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FetchPayload {
    /// The desired-state repository's remote.
    remote: String,
    /// The commit SHA to fetch.
    commit_sha: String,
}

/// The `source.activate` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivatePayload {
    /// The commit SHA to activate.
    commit_sha: String,
    /// The content digest the candidate was fetched with.
    content_digest: String,
}

/// The kind-dispatching source executor.
#[derive(Debug)]
pub struct SourceExecutor {
    source: GitSource,
    desired_source: Arc<fleet_application::source::DesiredSource>,
}

impl SourceExecutor {
    /// Composes the executor from its parts.
    ///
    /// # Panics
    ///
    /// Panics only if the git work root cannot be prepared, which the
    /// controller's data-directory preparation already ensures.
    #[must_use]
    pub fn new(
        work_root: std::path::PathBuf,
        desired_source: Arc<fleet_application::source::DesiredSource>,
    ) -> Self {
        Self {
            source: GitSource::new(work_root),
            desired_source,
        }
    }
}

#[async_trait::async_trait]
impl OperationExecutor for SourceExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "source.fetch" => self.fetch(operations, operation).await,
            "source.activate" => self.activate(operations, operation).await,
            _ => Err("not a source kind".to_owned()),
        }
    }
}

impl SourceExecutor {
    async fn fetch(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: FetchPayload = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a valid source record: {error}"))?;
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!("fetching {}", payload.commit_sha)),
            )
            .await
            .map_err(|error| error.to_string())?;
        // The provider runs on the controller's own machine; the
        // validation closure rides the schemas crate's validate_paths.
        let outcome = {
            let source = self.source.clone();
            let remote = payload.remote.clone();
            let commit_sha = payload.commit_sha.clone();
            tokio::task::spawn_blocking(move || {
                source.fetch_candidate(&remote, &commit_sha, |sources| {
                    fleet_schema::validate_paths(sources)
                        .unwrap_or_default()
                        .iter()
                        .map(ToString::to_string)
                        .collect()
                })
            })
            .await
            .map_err(|join_error| format!("the fetch thread failed: {join_error}"))?
        };
        let outcome = match outcome {
            Ok(candidate) => fleet_application::source::FetchOutcome::Candidate {
                digest: candidate.digest,
                diagnostics: candidate.diagnostics,
            },
            Err(detail) => fleet_application::source::FetchOutcome::TransportFailed { detail },
        };
        let handled = self
            .desired_source
            .handle_fetch(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                outcome,
            )
            .await
            .map_err(|error| error.to_string())?;
        let result_json = match handled {
            fleet_application::source::FetchOutcome::Candidate {
                digest,
                diagnostics,
            } => serde_json::json!({
                "commitSha": digest.commit_sha,
                "contentDigest": digest.content_digest,
                "diagnostics": diagnostics,
                "valid": diagnostics.is_empty(),
            })
            .to_string(),
            fleet_application::source::FetchOutcome::TransportFailed { detail } => {
                return complete_failed(operations, &operation.id, &detail).await;
            }
        };
        operations
            .complete(&operation.id, "succeeded", Some(&result_json), None)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn activate(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: ActivatePayload = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a valid source record: {error}"))?;
        // The candidate must have been fetched: the worktree named by the
        // SHA proves it. Validation re-runs against the materialized
        // worktree so the activation gate holds even across restarts.
        let worktree = self
            .source
            .work_root()
            .join(format!("candidate-{}", payload.commit_sha));
        let candidate_known = worktree.exists();
        let diagnostics = if candidate_known {
            let mut sources = Vec::new();
            collect_yaml(&worktree, &worktree, &mut sources);
            fleet_schema::validate_paths(&sources)
                .unwrap_or_default()
                .iter()
                .map(ToString::to_string)
                .collect()
        } else {
            vec!["the candidate was never fetched".to_owned()]
        };
        let revision = self
            .desired_source
            .activate(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &fleet_core::CandidateDigest {
                    commit_sha: payload.commit_sha.clone(),
                    content_digest: payload.content_digest.clone(),
                },
                diagnostics.is_empty(),
                candidate_known,
                Some(&operation.id),
            )
            .await
            .map_err(|error| {
                // A refusal (invalid/unknown candidate) is the operation's
                // public failure, not a backend error.
                error.to_string()
            })?;
        let result_json = serde_json::json!({
            "activated": true,
            "commitSha": revision.commit_sha,
            "contentDigest": revision.content_digest,
        })
        .to_string();
        operations
            .complete(&operation.id, "succeeded", Some(&result_json), None)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// Completes the workflow as a failure with a stable reason.
async fn complete_failed(
    operations: &Operations,
    operation_id: &str,
    detail: &str,
) -> Result<(), String> {
    let error_json = serde_json::json!({ "reason": "fetch_failed", "detail": detail }).to_string();
    operations
        .complete(operation_id, "failed", None, Some(&error_json))
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Collects YAML files under a root, as relative paths.
fn collect_yaml(
    _root: &std::path::Path,
    base: &std::path::Path,
    sources: &mut Vec<std::path::PathBuf>,
) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == ".git") {
                continue;
            }
            collect_yaml(_root, &path, sources);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "yaml")
        {
            sources.push(path);
        }
    }
}

/// The kind-dispatching wrapper the controller composes: the source kinds
/// route to the [`SourceExecutor`], everything else falls through to the
/// rest of the chain unchanged.
#[derive(Debug)]
pub struct SourceDispatch {
    fallback: Arc<dyn OperationExecutor>,
    source: Arc<dyn OperationExecutor>,
}

impl SourceDispatch {
    /// Composes the dispatch from the fallback chain and the source
    /// executor.
    #[must_use]
    pub fn new(fallback: Arc<dyn OperationExecutor>, source: Arc<dyn OperationExecutor>) -> Self {
        Self { fallback, source }
    }
}

#[async_trait::async_trait]
impl OperationExecutor for SourceDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "source.fetch" | "source.activate" => self.source.execute(operations, operation).await,
            _ => self.fallback.execute(operations, operation).await,
        }
    }
}
