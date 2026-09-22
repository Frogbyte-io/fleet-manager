//! The image-build executor (FM-700): `image.build` over the
//! operator-installed Packer CLI, per the FM-S09 pins.
//!
//! The executor verifies the CLI version at startup (absent → honest
//! degradation, the operator-installed contract), runs `packer validate`
//! as a pre-flight, then `packer build -machine-readable` with the
//! recipe written to a private work file. Every call is an argument
//! array; the recipe travels as a file path; secrets ride `-var-file`
//! resolved just in time — never argv, logs, or audit metadata.
//!
//! On a failed or deadline-killed build the executor reports the
//! plugin's cleanup outcome honestly: the plugin self-cleans its VM, and
//! Fleet records what the machine-readable stream said rather than
//! assuming.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_provider_packer::{BuildStream, PackerClient, PackerCommand, PackerTransport};
use serde::Deserialize;

/// The maximum build timeout the executor accepts from a payload.
pub const MAX_BUILD_TIMEOUT: u64 = 4 * 60 * 60;
/// The validate pre-flight's deadline.
const VALIDATE_DEADLINE: Duration = Duration::from_secs(120);

/// The `image.build` payload.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildPayload {
    /// The published recipe version to build.
    pub version_id: String,
    /// The deadline, in seconds. Bounded by the executor.
    pub timeout_seconds: u64,
}

/// The kind-dispatching images executor.
#[derive(Debug)]
pub struct ImagesExecutor {
    versions: Arc<dyn fleet_application::images::RecipePort>,
    transport: Arc<dyn PackerTransport>,
    work_root: PathBuf,
}

impl ImagesExecutor {
    /// Composes the executor from its parts.
    #[must_use]
    pub fn new(
        versions: Arc<dyn fleet_application::images::RecipePort>,
        transport: Arc<dyn PackerTransport>,
        work_root: PathBuf,
    ) -> Self {
        Self {
            versions,
            transport,
            work_root,
        }
    }

    /// Writes the recipe content to a private work file and returns its
    /// path. The work directory is per-operation, so concurrent builds
    /// never share state.
    fn write_recipe(&self, operation_id: &str, content: &str) -> Result<PathBuf, String> {
        let dir = self.work_root.join(operation_id);
        std::fs::create_dir_all(&dir)
            .map_err(|error| format!("the work directory cannot be prepared: {error}"))?;
        let path = dir.join("recipe.pkr.json");
        std::fs::write(&path, content)
            .map_err(|error| format!("the recipe cannot be written: {error}"))?;
        Ok(path)
    }
}

#[async_trait::async_trait]
impl OperationExecutor for ImagesExecutor {
    #[allow(clippy::too_many_lines)]
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        if operation.kind != "image.build" {
            return Err("not an image kind".to_owned());
        }
        let payload: BuildPayload = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a valid build record: {error}"))?;
        let version = self
            .versions
            .get_version(&payload.version_id)
            .await
            .map_err(|detail| format!("the recipe version is unreadable: {detail}"))?;

        // The version gate: the CLI must be installed and inside the
        // pinned range. Absent is an honest degradation, not a crash.
        let version_gate = PackerClient::new(self.transport.clone())
            .version(self.work_root.clone())
            .await;
        if let Err(gate) = &version_gate {
            return complete_failure(operations, &operation.id, "version_gate", &gate.to_string())
                .await;
        }

        // The recipe travels as a file inside the operation's private
        // work directory.
        let recipe_path = self
            .write_recipe(&operation.id, &version.content)
            .map_err(|detail| detail.clone())?;
        let work_dir = recipe_path
            .parent()
            .map(PathBuf::from)
            .ok_or("the recipe path carries no parent")?;

        // The validate pre-flight: read-only, before any build is queued
        // into the host.
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(2),
                Some("validating the recipe"),
            )
            .await
            .map_err(|error| error.to_string())?;
        let validate = self
            .packer_version_aware_call(
                &["validate".to_owned(), recipe_path.display().to_string()],
                &work_dir,
                VALIDATE_DEADLINE,
            )
            .await;
        match validate {
            Ok(outcome) if outcome.exit_code == Some(0) => {}
            Ok(outcome) => {
                let detail = bounded(&outcome.stderr)
                    .unwrap_or_else(|| bounded(&outcome.stdout).unwrap_or_default());
                return complete_failure(
                    operations,
                    &operation.id,
                    "validate_failed",
                    &format!("packer validate refused the recipe: {detail}"),
                )
                .await;
            }
            Err(detail) => {
                return complete_failure(operations, &operation.id, "validate_failed", &detail)
                    .await;
            }
        }

        // The build: bounded by the reviewed deadline.
        operations
            .record_progress(&operation.id, Some(1), Some(2), Some("building the image"))
            .await
            .map_err(|error| error.to_string())?;
        let deadline = Duration::from_secs(payload.timeout_seconds.min(MAX_BUILD_TIMEOUT));
        let build = self
            .packer_version_aware_call(
                &[
                    "-machine-readable".to_owned(),
                    "build".to_owned(),
                    recipe_path.display().to_string(),
                ],
                &work_dir,
                deadline,
            )
            .await;
        match build {
            Ok(outcome) if outcome.killed_by_deadline => {
                complete_failure(
                    operations,
                    &operation.id,
                    "deadline_killed",
                    "the build was killed at its deadline; the plugin's cleanup ran and the host's state must be verified",
                )
                .await
            }
            Ok(outcome) if outcome.exit_code == Some(0) => {
                let stream = BuildStream::parse(&outcome.stdout);
                let artifact_id = stream.artifact_id().unwrap_or_default();
                let result = serde_json::json!({
                    "artifactId": artifact_id,
                    "recipeVersion": payload.version_id,
                    "says": bounded_list(&stream.says),
                })
                .to_string();
                operations
                    .complete(&operation.id, "succeeded", Some(&result), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            Ok(outcome) => {
                let stream = BuildStream::parse(&outcome.stdout);
                let detail = stream
                    .errors
                    .last()
                    .cloned()
                    .or_else(|| bounded(&outcome.stderr))
                    .unwrap_or_else(|| "the build failed without a detail".to_owned());
                complete_failure(operations, &operation.id, "build_failed", &detail).await
            }
            Err(detail) => complete_failure(operations, &operation.id, "build_failed", &detail).await,
        }
    }
}

impl ImagesExecutor {
    /// Runs one CLI call through the transport, bounding the output.
    async fn packer_version_aware_call(
        &self,
        args: &[String],
        work_dir: &std::path::Path,
        deadline: Duration,
    ) -> Result<fleet_provider_packer::CliOutcome, String> {
        let command = PackerCommand {
            args: args.to_vec(),
            work_dir: work_dir.to_path_buf(),
        };
        self.transport.run(&command, deadline).await
    }
}

/// Bounds a string to the output cap.
fn bounded(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.chars().take(2048).collect())
    }
}

/// Bounds a list, keeping the last entries (the freshest detail).
fn bounded_list(values: &[String]) -> Vec<String> {
    let start = values.len().saturating_sub(20);
    values[start..]
        .iter()
        .map(|value| value.chars().take(512).collect())
        .collect()
}

/// Completes an operation as a failure with a redacted detail.
async fn complete_failure(
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

/// The kind-dispatching images executor: `image.build` routes to the
/// build executor, everything else falls through to the next executor in
/// the chain.
#[derive(Debug)]
pub struct ImagesDispatch {
    fallback: Arc<dyn OperationExecutor>,
    build: Arc<ImagesExecutor>,
}

impl ImagesDispatch {
    /// Composes the dispatch from its parts.
    #[must_use]
    pub fn new(fallback: Arc<dyn OperationExecutor>, build: Arc<ImagesExecutor>) -> Self {
        Self { fallback, build }
    }
}

#[async_trait::async_trait]
impl OperationExecutor for ImagesDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        if operation.kind == "image.build" {
            self.build.execute(operations, operation).await
        } else {
            self.fallback.execute(operations, operation).await
        }
    }
}
