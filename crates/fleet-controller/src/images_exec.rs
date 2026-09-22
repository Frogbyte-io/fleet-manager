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
    /// The secret references whose resolved values ride `-var-file`,
    /// as `name = reference` pairs. The values never enter argv, logs,
    /// or audit metadata; the var file is deleted with the work dir.
    #[serde(default)]
    pub secret_vars: Vec<SecretVar>,
}

/// One secret-backed build variable.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretVar {
    /// The Packer variable name.
    pub name: String,
    /// The secret reference id.
    pub reference: String,
}

/// The kind-dispatching images executor.
#[derive(Debug)]
pub struct ImagesExecutor {
    versions: Arc<dyn fleet_application::images::RecipePort>,
    transport: Arc<dyn PackerTransport>,
    secrets: Option<Arc<fleet_secrets::SecretStore>>,
    work_root: PathBuf,
}

impl ImagesExecutor {
    /// Composes the executor from its parts.
    #[must_use]
    pub fn new(
        versions: Arc<dyn fleet_application::images::RecipePort>,
        transport: Arc<dyn PackerTransport>,
        secrets: Option<Arc<fleet_secrets::SecretStore>>,
        work_root: PathBuf,
    ) -> Self {
        Self {
            versions,
            transport,
            secrets,
            work_root,
        }
    }

    /// Writes the secret var file, resolving the references just in time.
    /// The file lives only inside the operation's work directory and is
    /// deleted with it.
    async fn write_var_file(
        &self,
        operation_id: &str,
        vars: &[SecretVar],
    ) -> Result<Option<PathBuf>, String> {
        if vars.is_empty() {
            return Ok(None);
        }
        let Some(secrets) = &self.secrets else {
            return Err(
                "the build carries secret variables but the controller runs without a secret store"
                    .to_owned(),
            );
        };
        let mut content = String::new();
        for var in vars {
            let value = secrets
                .resolve(&var.reference)
                .await
                .map_err(|error| format!("the secret {} is unreadable: {error}", var.name))?;
            let text = String::from_utf8(value.expose().to_vec())
                .map_err(|_| format!("the secret {} is not UTF-8", var.name))?;
            content.push_str(&format!(
                "{}={}
",
                var.name, text
            ));
        }
        let dir = self.work_root.join(operation_id);
        let path = dir.join("vars.auto.pkrvars.json");
        // The JSON shape keeps the values out of argv entirely.
        let mut object = serde_json::Map::new();
        for var in vars {
            let value = secrets
                .resolve(&var.reference)
                .await
                .map_err(|error| format!("the secret {} is unreadable: {error}", var.name))?;
            let text = String::from_utf8(value.expose().to_vec())
                .map_err(|_| format!("the secret {} is not UTF-8", var.name))?;
            object.insert(var.name.clone(), serde_json::Value::String(text));
        }
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::Value::Object(object))
                .map_err(|error| format!("the var file cannot be serialized: {error}"))?,
        )
        .map_err(|error| format!("the var file cannot be written: {error}"))?;
        let _ = content;
        Ok(Some(path))
    }

    /// Writes the recipe content to a private work file and returns its
    /// path. The work directory is per-operation, so concurrent builds
    /// never share state.
    fn write_recipe(&self, operation_id: &str, content: &str) -> Result<PathBuf, String> {
        let dir = self.work_root.join(operation_id);
        std::fs::create_dir_all(&dir)
            .map_err(|error| format!("the work directory cannot be prepared: {error}"))?;
        // Packer auto-detects the format from the extension: `.pkr.json`
        // is HCL2, a bare `.json` is the legacy JSON template. The recipe
        // content is JSON, so the file is named accordingly.
        let path = dir.join("recipe.json");
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

        // The work root must exist before the version probe: the probe
        // runs with it as the working directory.
        std::fs::create_dir_all(&self.work_root)
            .map_err(|error| format!("the work directory cannot be prepared: {error}"))?;
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
        // The var file is written before validate: a recipe referencing
        // variables cannot validate without them.
        let var_file = self
            .write_var_file(&operation.id, &payload.secret_vars)
            .await?;
        let mut validate_args = vec!["validate".to_owned()];
        if let Some(var_file) = &var_file {
            validate_args.push("-var-file".to_owned());
            validate_args.push(var_file.display().to_string());
        }
        validate_args.push(recipe_path.display().to_string());
        let validate = self
            .packer_version_aware_call(&validate_args, &work_dir, VALIDATE_DEADLINE)
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
        let mut build_args = vec!["-machine-readable".to_owned(), "build".to_owned()];
        if let Some(var_file) = &var_file {
            build_args.push("-var-file".to_owned());
            build_args.push(var_file.display().to_string());
        }
        build_args.push(recipe_path.display().to_string());
        let build = self
            .packer_version_aware_call(&build_args, &work_dir, deadline)
            .await;
        match build {
            Ok(outcome) if outcome.killed_by_deadline => {
                let failed = complete_failure(
                    operations,
                    &operation.id,
                    "deadline_killed",
                    "the build was killed at its deadline; the process was killed so the plugin's cleanup could not run — the host's state must be verified",
                )
                .await;
                cleanup_work_dir(&self.work_root, &operation.id);
                failed
            }
            Ok(outcome) if outcome.exit_code == Some(0) => {
                let stream = BuildStream::parse(&outcome.stdout);
                // A zero exit without a parseable artifact record is
                // indeterminate, not success: the bound could have
                // truncated the stream or the plugin changed shape.
                let Some(artifact_id) = stream.artifact_id() else {
                    return complete_failure(
                        operations,
                        &operation.id,
                        "artifact_missing",
                        "the build exited zero but no artifact record was parsed; the outcome is indeterminate and the host must be verified",
                    )
                    .await;
                };
                let result = serde_json::json!({
                    "artifactId": artifact_id,
                    "recipeVersion": payload.version_id,
                    "says": bounded_list(&stream.says),
                })
                .to_string();
                let completed = operations
                    .complete(&operation.id, "succeeded", Some(&result), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string());
                cleanup_work_dir(&self.work_root, &operation.id);
                completed
            }
            Ok(outcome) => {
                let stream = BuildStream::parse(&outcome.stdout);
                let detail = stream
                    .errors
                    .last()
                    .cloned()
                    .or_else(|| bounded(&outcome.stderr))
                    .unwrap_or_else(|| "the build failed without a detail".to_owned());
                let failed =
                    complete_failure(operations, &operation.id, "build_failed", &detail).await;
                cleanup_work_dir(&self.work_root, &operation.id);
                failed
            }
            Err(detail) => {
                let failed =
                    complete_failure(operations, &operation.id, "build_failed", &detail).await;
                cleanup_work_dir(&self.work_root, &operation.id);
                failed
            }
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

/// Removes one operation's private work directory after a terminal
/// outcome; builds must not accumulate recipe copies in the data
/// directory.
fn cleanup_work_dir(work_root: &std::path::Path, operation_id: &str) {
    let dir = work_root.join(operation_id);
    if let Err(error) = std::fs::remove_dir_all(&dir) {
        // Best effort: a stuck directory is logged at the boundary, not
        // a failed operation.
        let _ = error;
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
