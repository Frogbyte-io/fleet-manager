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
//! FM-702 records a safe immutable input snapshot before any CLI call,
//! probes both pinned versions, and completes the build on every terminal
//! executor path. A kill or cancellation cannot prove remote cleanup; its
//! reason code preserves that uncertainty without retaining provider output.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_core::{ImageBuildRecord, ImageBuildTemplate, RecipeVersion};
use fleet_provider_packer::{BuildStream, PackerCommand, PackerTransport, SecretEnv};
use serde::Deserialize;
use sha2::Digest as _;

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
    /// The explicitly selected Fleet target account, when supplied.
    #[serde(default)]
    pub account_id: Option<String>,
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
    accounts: Option<Arc<dyn fleet_application::proxmox::ProxmoxAccountPort>>,
    credentials: Option<Arc<dyn fleet_application::proxmox::ProxmoxCredentialStore>>,
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
            accounts: None,
            credentials: None,
        }
    }

    /// Hands each build its target account's token (#272): resolved just in
    /// time, behind the account's explicit-trust gate, into Packer's child
    /// environment only. Without this the CLI inherits the controller's
    /// environment, as before.
    #[must_use]
    pub fn with_account_credentials(
        mut self,
        accounts: Arc<dyn fleet_application::proxmox::ProxmoxAccountPort>,
        credentials: Arc<dyn fleet_application::proxmox::ProxmoxCredentialStore>,
    ) -> Self {
        self.accounts = Some(accounts);
        self.credentials = Some(credentials);
        self
    }

    /// The Proxmox plugin's credentials for the build's account. A token is
    /// never handed out for an account whose host trust is unconfirmed.
    async fn account_env(&self, account_id: Option<&str>) -> Result<SecretEnv, &'static str> {
        let (Some(accounts), Some(credentials)) = (&self.accounts, &self.credentials) else {
            return Ok(SecretEnv::default());
        };
        let account_id = account_id.ok_or("target_account_missing")?;
        let account = accounts
            .get(account_id)
            .await
            .map_err(|_| "target_account_unreadable")?;
        if account.fingerprint.is_none() {
            return Err("target_account_untrusted");
        }
        let secret = credentials
            .load(account_id)
            .await
            .map_err(|_| "account_credential_unreadable")?
            .ok_or("account_credential_missing")?;
        Ok(SecretEnv::new(vec![
            (
                "PROXMOX_USERNAME".to_owned(),
                fleet_core::SensitiveString::new(account.token_id),
            ),
            (
                "PROXMOX_TOKEN".to_owned(),
                fleet_core::SensitiveString::new(secret),
            ),
        ]))
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

        let target_account = self
            .versions
            .build_target_account(&version, payload.account_id.as_deref())
            .await;
        let target_resolution_failed = target_account.is_err();
        let mut record = ImageBuildRecord {
            id: operation.id.clone(),
            operation_id: operation.id.clone(),
            recipe_id: version.recipe_id.clone(),
            version_id: version.id.clone(),
            content_digest: version.content_digest.clone(),
            asset_digests: provisioning_digests(&version.content),
            packer_version: None,
            proxmox_plugin_version: None,
            account_id: target_account.unwrap_or_default(),
            node: version.node.clone(),
            storage_pool: version.storage_pool.clone(),
            started_at: fleet_core::SystemClock::now_unix_millis(),
            ended_at: None,
            outcome: "running".to_owned(),
            reason: None,
            template: None,
        };
        // No provider invocation is allowed until the immutable input snapshot
        // commits. A duplicate delivery cannot silently overwrite old evidence.
        self.versions.start_build(&record).await?;
        let result = if target_resolution_failed {
            Err("target_account_resolution_failed")
        } else if operations
            .get_state(&operation.id)
            .await
            .is_ok_and(|state| state == "cancelling")
        {
            Err("cancelled")
        } else {
            // A cancel does not drop the build (that SIGKILLs Packer and
            // strands the plugin's VM, #271): it asks the transport to
            // interrupt Packer and waits for its own cleanup to finish.
            let (stop, stop_rx) = tokio::sync::watch::channel(false);
            let work = self.run_build(
                operations,
                operation,
                &payload,
                &version,
                &mut record,
                stop_rx,
            );
            tokio::pin!(work);
            let mut cancel = None;
            let result = loop {
                tokio::select! {
                    result = &mut work => break result,
                    polled = wait_for_cancel(operations, &operation.id), if cancel.is_none() => {
                        let _ = stop.send(true);
                        cancel = Some(if polled.is_ok() { "cancelled" } else { "cancel_poll_failed" });
                    }
                }
            };
            settle_build(cancel, result)
        };
        record.ended_at = Some(fleet_core::SystemClock::now_unix_millis().max(record.started_at));
        match result {
            Ok(template) => {
                record.outcome = "succeeded".to_owned();
                record.template = Some(template);
            }
            Err(reason) => {
                record.outcome = if reason.starts_with("cancelled") {
                    "cancelled"
                } else {
                    "failed"
                }
                .to_owned();
                record.reason = Some(reason.to_owned());
            }
        }
        cleanup_work_dir(&self.work_root, &operation.id);
        // Persist the terminal build before completing the generic operation.
        // No arbitrary provider output enters this record or its audit outcome.
        self.versions.finish_build(&record).await?;
        let result_json = record.template.as_ref().map(|template| {
            serde_json::json!({
                "artifactId": format!("{}:{}", template.node, template.vmid),
                "recipeVersion": record.version_id,
                "buildId": record.id,
            })
            .to_string()
        });
        let error_json = record
            .reason
            .as_ref()
            .map(|reason| serde_json::json!({ "reason": reason }).to_string());
        operations
            .complete(
                &operation.id,
                &record.outcome,
                result_json.as_deref(),
                error_json.as_deref(),
            )
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

impl ImagesExecutor {
    async fn run_build(
        &self,
        operations: &Operations,
        operation: &Operation,
        payload: &BuildPayload,
        version: &RecipeVersion,
        record: &mut ImageBuildRecord,
        stop: tokio::sync::watch::Receiver<bool>,
    ) -> Result<ImageBuildTemplate, &'static str> {
        if record.account_id.as_deref().is_none_or(str::is_empty) {
            return Err("target_account_missing");
        }
        if !version.has_frozen_build_target() {
            return Err("target_snapshot_mismatch");
        }
        // Recipe versions currently store embedded assets only. Refuse
        // mutable external file inputs instead of claiming their path digest
        // proves the bytes Packer would execute.
        if has_external_assets(&version.content) {
            return Err("asset_snapshot_missing");
        }
        std::fs::create_dir_all(&self.work_root).map_err(|_| "work_directory_failed")?;
        let probe = self
            .transport
            .run(
                &PackerCommand {
                    args: vec!["-machine-readable".to_owned(), "version".to_owned()],
                    work_dir: self.work_root.clone(),
                    env: SecretEnv::default(),
                },
                Duration::from_secs(30),
            )
            .await
            .map_err(|_| "version_gate")?;
        record.packer_version = probe.stdout.lines().find_map(|line| {
            let event = fleet_provider_packer::parse_machine_readable_line(line)?;
            (event.event_type == "version" && numeric_version(&event.data).is_some())
                .then_some(event.data)
        });
        let supported = record
            .packer_version
            .as_deref()
            .and_then(numeric_version)
            .is_some_and(|(major, minor, _)| major == 1 && minor >= 15);
        if probe.exit_code != Some(0) || probe.killed_by_deadline || !supported {
            return Err("version_gate");
        }
        let plugins = self
            .transport
            .run(
                &PackerCommand {
                    args: vec!["plugins".to_owned(), "installed".to_owned()],
                    work_dir: self.work_root.clone(),
                    env: SecretEnv::default(),
                },
                Duration::from_secs(30),
            )
            .await
            .map_err(|_| "plugin_version_gate")?;
        // `plugins installed` is the documented discovery surface. Retain
        // only the version from its binary name, never the installation path.
        record.proxmox_plugin_version = plugin_version(&plugins.stdout);
        let supported = record
            .proxmox_plugin_version
            .as_deref()
            .and_then(numeric_version)
            .is_some_and(|(major, minor, patch)| {
                major == 1 && (minor > 2 || (minor == 2 && patch >= 4))
            });
        if plugins.exit_code != Some(0) || plugins.killed_by_deadline || !supported {
            return Err("plugin_version_gate");
        }
        let recipe_path = self
            .write_recipe(&operation.id, &version.content)
            .map_err(|_| "recipe_write_failed")?;
        let work_dir = recipe_path.parent().ok_or("recipe_write_failed")?;
        let var_file = self
            .write_var_file(&operation.id, &payload.secret_vars)
            .await
            .map_err(|_| "secret_resolution_failed")?;
        let env = self.account_env(record.account_id.as_deref()).await?;
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(2),
                Some("validating the recipe"),
            )
            .await
            .map_err(|_| "progress_failed")?;
        let args = |prefix: &[&str]| {
            let mut args: Vec<String> = prefix.iter().map(|s| (*s).to_owned()).collect();
            if let Some(path) = &var_file {
                args.extend(["-var-file".to_owned(), path.display().to_string()]);
            }
            args.push(recipe_path.display().to_string());
            args
        };
        // A cancel that arrived during the probes stops here; one during
        // validate interrupts it, and no build starts afterwards.
        if *stop.borrow() {
            return Err("cancelled");
        }
        let validated = self
            .transport
            .run_stoppable(
                &PackerCommand {
                    args: args(&["validate"]),
                    work_dir: work_dir.to_path_buf(),
                    env: env.clone(),
                },
                VALIDATE_DEADLINE,
                stop.clone(),
            )
            .await
            .map_err(|_| "validate_failed")?
            .outcome;
        if *stop.borrow() {
            return Err("cancelled");
        }
        if validated.killed_by_deadline {
            return Err("deadline_killed");
        }
        if validated.exit_code != Some(0) {
            return Err("validate_failed");
        }
        operations
            .record_progress(&operation.id, Some(1), Some(2), Some("building the image"))
            .await
            .map_err(|_| "progress_failed")?;
        let stoppable = self
            .transport
            .run_stoppable(
                &PackerCommand {
                    args: args(&["-machine-readable", "build"]),
                    work_dir: work_dir.to_path_buf(),
                    env,
                },
                Duration::from_secs(payload.timeout_seconds.min(MAX_BUILD_TIMEOUT)),
                stop,
            )
            .await
            .map_err(|_| "build_failed")?;
        let built = stoppable.outcome;
        // A cancel interrupted the build: only Packer's own clean-cancel
        // report says the plugin removed its VM.
        if !built.killed_by_deadline && stoppable.stopped.is_some() {
            return Err(if stoppable.cleanly_cancelled {
                "cancelled"
            } else {
                "cancelled_unverified"
            });
        }
        if built.killed_by_deadline {
            // Interrupted at the deadline and reported clean by Packer, or
            // only interrupted, or killed after the grace period.
            return Err(if stoppable.cleanly_cancelled {
                "deadline_interrupted"
            } else if stoppable.stopped == Some(fleet_provider_packer::Stopped::Interrupted) {
                "deadline_interrupted_unverified"
            } else {
                "deadline_killed"
            });
        }
        if built.exit_code != Some(0) {
            return Err("build_failed");
        }
        let stream = BuildStream::parse(&built.stdout);
        let id = stream.artifact_id().ok_or("artifact_missing")?;
        output_template(id, version).ok_or("artifact_missing")
    }
}

/// The build's terminal result, given how a cancel (if any) was seen and
/// what the build itself reported.
fn settle_build(
    cancel: Option<&'static str>,
    result: Result<ImageBuildTemplate, &'static str>,
) -> Result<ImageBuildTemplate, &'static str> {
    match (cancel, result) {
        // The build finished before the interrupt took effect: its template
        // exists, so the record says so.
        (_, Ok(template)) => Ok(template),
        // A confirmed cancel: the build's own account of the interrupt is
        // the more precise one (verified or not).
        (Some("cancelled"), Err(reason @ ("cancelled" | "cancelled_unverified"))) => Err(reason),
        // Anything else the cancel side saw, including `cancel_poll_failed`,
        // stays as that: a poll failure is never reported as a cancel.
        (Some(reason), Err(_)) | (None, Err(reason)) => Err(reason),
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

// Only validated numeric version strings may enter public provenance.
fn numeric_version(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.split('.');
    let result = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next().map_or(Some(0), |part| part.parse().ok())?,
    );
    parts.next().is_none().then_some(result)
}

fn plugin_version(output: &str) -> Option<String> {
    let versions: Vec<_> = output
        .lines()
        .filter_map(|line| {
            let name = std::path::Path::new(line.trim()).file_name()?.to_str()?;
            let suffix = name.strip_prefix("packer-plugin-proxmox_v")?;
            let version = suffix.split('_').next()?;
            numeric_version(version)?;
            Some(version.to_owned())
        })
        .collect();
    // Multiple installations make the selected legacy builder ambiguous;
    // refuse instead of claiming a version we cannot prove was executed.
    (versions.len() == 1).then(|| versions[0].clone())
}

fn provisioning_digests(content: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };
    value
        .get("provisioners")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|asset| {
            if let Some(inline) = asset.get("inline").and_then(serde_json::Value::as_array) {
                let lines: Option<Vec<&str>> =
                    inline.iter().map(serde_json::Value::as_str).collect();
                return lines.map(|lines| lines.join("\n"));
            }
            asset
                .get("content")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .map(|bytes| format!("{:x}", sha2::Sha256::digest(bytes.as_bytes())))
        .collect()
}

fn has_external_assets(content: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return true;
    };
    let Some(assets) = value.get("provisioners") else {
        return false;
    };
    let Some(assets) = assets.as_array() else {
        return true;
    };
    // Fail closed: only the documented embedded shell/file forms are supported.
    // Unknown plugins and fields may read host files that cannot be snapshotted.
    assets.iter().any(|asset| {
        let Some(fields) = asset.as_object() else {
            return true;
        };
        let allowed: &[&str] = match asset.get("type").and_then(serde_json::Value::as_str) {
            Some("shell")
                if asset
                    .get("inline")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|lines| lines.iter().all(serde_json::Value::is_string)) =>
            {
                &[
                    "type",
                    "inline",
                    "inline_shebang",
                    "execute_command",
                    "environment_vars",
                    "env",
                    "use_env_var_file",
                    "remote_folder",
                    "remote_file",
                    "remote_path",
                    "start_retry_timeout",
                    "expect_disconnect",
                    "skip_clean",
                    "valid_exit_codes",
                    "pause_before",
                    "pause_after",
                    "timeout",
                    "max_retries",
                    "only",
                    "except",
                ]
            }
            Some("file")
                if asset
                    .get("content")
                    .is_some_and(serde_json::Value::is_string)
                    && asset
                        .get("destination")
                        .is_some_and(serde_json::Value::is_string) =>
            {
                &[
                    "type",
                    "content",
                    "destination",
                    "generated",
                    "pause_before",
                    "pause_after",
                    "timeout",
                    "max_retries",
                    "only",
                    "except",
                ]
            }
            _ => return true,
        };
        fields.keys().any(|key| !allowed.contains(&key.as_str()))
    })
}

fn output_template(artifact: &str, version: &RecipeVersion) -> Option<ImageBuildTemplate> {
    let (node, vmid) = artifact
        .rsplit_once(':')
        .unwrap_or((&version.node, artifact));
    if node != version.node || !vmid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let vmid: u32 = vmid.parse().ok()?;
    if !(100..=999_999_999).contains(&vmid) {
        return None;
    }
    let parsed = fleet_core::StructuredRecipe::from_raw(&version.content)?;
    if parsed.node != node {
        return None;
    }
    let content: serde_json::Value = serde_json::from_str(&version.content).ok()?;
    let builder = content.get("builders")?.as_array()?.iter().find(|b| {
        b.get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|t| t == "proxmox-iso" || t == "proxmox-clone")
    })?;
    let name = builder
        .get("template_name")
        .or_else(|| builder.get("vm_name"))?
        .as_str()?
        .to_owned();
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return None;
    }
    Some(ImageBuildTemplate {
        node: node.to_owned(),
        vmid,
        name,
    })
}

async fn wait_for_cancel(operations: &Operations, id: &str) -> Result<(), String> {
    loop {
        if operations
            .cancel_requested(id)
            .await
            .map_err(|e| e.to_string())?
            && operations.get_state(id).await.map_err(|e| e.to_string())? == "cancelling"
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision};
    use fleet_application::images::{Images, NewRecipe, RecipePort as _};
    use fleet_application::operation::NewOperation;
    use fleet_core::{RecipeContent, RecipeSource};
    use fleet_storage_sqlite::{AuditSink, OperationRepository, RecipeRepository, Store};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct Allow;
    impl Authorizer for Allow {
        fn decide(&self, _: AccessRequest<'_>) -> Decision {
            Decision::allow()
        }
    }

    #[derive(Debug)]
    struct Script {
        repository: Arc<RecipeRepository>,
        operation_id: String,
        replies: Mutex<VecDeque<Result<fleet_provider_packer::CliOutcome, String>>>,
        wait_build: bool,
        building: tokio::sync::Notify,
        saw_var_file: Mutex<Option<String>>,
        interrupted: std::sync::atomic::AtomicBool,
        /// Whether an interrupted build reports Packer's clean cancel.
        clean_cancel: std::sync::atomic::AtomicBool,
        /// Per command: its args joined, and the child's PROXMOX_TOKEN.
        saw_env: Mutex<Vec<(String, Option<String>)>>,
    }
    #[async_trait::async_trait]
    impl PackerTransport for Script {
        async fn run(
            &self,
            command: &PackerCommand,
            _: Duration,
        ) -> Result<fleet_provider_packer::CliOutcome, String> {
            self.saw_env.lock().unwrap().push((
                command.args.join(" "),
                command.env.get("PROXMOX_TOKEN").map(str::to_owned),
            ));
            let record = self.repository.get_build(&self.operation_id).await.unwrap();
            assert_eq!(
                record.outcome, "running",
                "snapshot must exist before every provider invocation"
            );
            assert!(
                command
                    .args
                    .iter()
                    .all(|a| !a.contains("fixture-secret-token"))
            );
            if let Some(index) = command.args.iter().position(|a| a == "-var-file") {
                let path = &command.args[index + 1];
                let contents = std::fs::read_to_string(path).unwrap();
                assert!(contents.contains("fixture-secret-token"));
                *self.saw_var_file.lock().unwrap() = Some(path.clone());
            }
            if self.wait_build && command.args.iter().any(|a| a == "build") {
                self.building.notify_one();
                std::future::pending::<()>().await;
            }
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected Packer command")
        }

        async fn run_stoppable(
            &self,
            command: &PackerCommand,
            deadline: Duration,
            mut stop: tokio::sync::watch::Receiver<bool>,
        ) -> Result<fleet_provider_packer::StoppableOutcome, String> {
            if self.wait_build && command.args.iter().any(|a| a == "build") {
                // A build that runs until it is interrupted, then exits on
                // its own after cleaning up, as Packer does after Ctrl-C.
                self.building.notify_one();
                while !*stop.borrow_and_update() {
                    stop.changed().await.unwrap();
                }
                self.interrupted
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return Ok(fleet_provider_packer::StoppableOutcome {
                    outcome: fleet_provider_packer::CliOutcome {
                        stdout: String::new(),
                        stderr: String::new(),
                        exit_code: Some(1),
                        killed_by_deadline: false,
                    },
                    stopped: Some(fleet_provider_packer::Stopped::Interrupted),
                    cleanly_cancelled: self.clean_cancel.load(std::sync::atomic::Ordering::SeqCst),
                });
            }
            let outcome = self.run(command, deadline).await?;
            // A scripted deadline reply mentioning "interrupted" stands for
            // an interrupt at the deadline; it was clean only when it carries
            // Packer's clean-cancel line.
            let interrupted = outcome.killed_by_deadline && outcome.stdout.contains("interrupted");
            let clean = outcome.killed_by_deadline
                && outcome
                    .stdout
                    .contains(fleet_provider_packer::CLEAN_CANCEL_MESSAGE);
            Ok(fleet_provider_packer::StoppableOutcome {
                stopped: interrupted.then_some(fleet_provider_packer::Stopped::Interrupted),
                cleanly_cancelled: clean,
                outcome,
            })
        }
    }

    fn reply(
        stdout: &str,
        exit_code: Option<i32>,
        killed: bool,
    ) -> Result<fleet_provider_packer::CliOutcome, String> {
        Ok(fleet_provider_packer::CliOutcome {
            stdout: stdout.to_owned(),
            stderr: "fixture-secret-token".to_owned(),
            exit_code,
            killed_by_deadline: killed,
        })
    }

    const CONTENT: &str = r#"{"builders":[{"type":"proxmox-clone","node":"pve","disks":[{"type":"scsi","storage_pool":"local-lvm","disk_size":"8G"}],"vm_name":"ubuntu-base","proxmox_url":"https://pve.example.test:8006/api2/json"}],"provisioners":[{"type":"shell","inline":["echo ready"]}]}"#;

    async fn setup(
        content: &str,
        payload_extra: serde_json::Value,
        replies: Vec<Result<fleet_provider_packer::CliOutcome, String>>,
        wait_build: bool,
    ) -> (
        tempfile::TempDir,
        Store,
        Arc<RecipeRepository>,
        Arc<Operations>,
        Operation,
        Arc<Script>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        sqlx::query("INSERT INTO proxmox_accounts (id, name, host, port, token_id, created_at) VALUES ('account-1', 'fixture', 'pve.example.test', 8006, 'fixture@pve!builder', 1000)")
            .execute(store.pool()).await.unwrap();
        let repository = Arc::new(RecipeRepository::new(store.pool().clone()));
        let audit = Arc::new(AuditSink::new(store.pool().clone()));
        let images = Images::new(repository.clone(), audit.clone());
        let principal = ActingPrincipal {
            id: "anonymous-lan-admin".to_owned(),
        };
        let recipe = images
            .create(
                &Allow,
                &principal,
                NewRecipe {
                    content: RecipeContent {
                        name: "ubuntu-base".to_owned(),
                        description: String::new(),
                        node: "pve".to_owned(),
                        storage_pool: Some("local-lvm".to_owned()),
                        source: RecipeSource::Clone,
                        content: content.to_owned(),
                    },
                },
                1000,
            )
            .await
            .unwrap();
        let version = images
            .publish(&Allow, &principal, &recipe.id, 1001)
            .await
            .unwrap();
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(store.pool().clone())),
            audit,
        ));
        let mut payload = serde_json::json!({"versionId": version.id, "timeoutSeconds": 5, "accountId": "account-1"});
        payload
            .as_object_mut()
            .unwrap()
            .extend(payload_extra.as_object().unwrap().clone());
        let pending = operations
            .create(
                &Allow,
                &principal.id,
                &NewOperation {
                    kind: "image.build".to_owned(),
                    payload_json: Some(payload.to_string()),
                    idempotency_key: None,
                    deadline_at: None,
                    correlation_id: None,
                    review_token: None,
                },
            )
            .await
            .unwrap();
        let mut report = fleet_application::worker::TickReport::default();
        let operation = operations
            .claim_only(
                "images-test",
                fleet_core::SystemClock::now_unix_millis(),
                &mut report,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.id, operation.id);
        let script = Arc::new(Script {
            repository: repository.clone(),
            operation_id: operation.id.clone(),
            replies: Mutex::new(replies.into()),
            wait_build,
            building: tokio::sync::Notify::new(),
            saw_var_file: Mutex::new(None),
            interrupted: std::sync::atomic::AtomicBool::new(false),
            clean_cancel: std::sync::atomic::AtomicBool::new(true),
            saw_env: Mutex::new(Vec::new()),
        });
        (dir, store, repository, operations, operation, script)
    }

    fn probes() -> Vec<Result<fleet_provider_packer::CliOutcome, String>> {
        vec![
            reply("1,,version,1.16.1", Some(0), false),
            reply(
                "/operator/plugins/packer-plugin-proxmox_v1.2.4_x5.0_linux_amd64",
                Some(0),
                false,
            ),
        ]
    }

    /// A credential store holding one token for `account-1`.
    #[derive(Debug)]
    struct OneToken(Option<&'static str>);

    #[async_trait::async_trait]
    impl fleet_application::proxmox::ProxmoxCredentialStore for OneToken {
        async fn load(
            &self,
            _: &str,
        ) -> Result<Option<String>, fleet_application::proxmox::CredentialStoreError> {
            Ok(self.0.map(str::to_owned))
        }
        async fn store(
            &self,
            _: &str,
            _: &str,
        ) -> Result<(), fleet_application::proxmox::CredentialStoreError> {
            Ok(())
        }
        async fn clear(
            &self,
            _: &str,
        ) -> Result<(), fleet_application::proxmox::CredentialStoreError> {
            Ok(())
        }
    }

    /// Runs one build with account credentials wired; answers the record,
    /// what the transport saw, and every stored operation/audit text.
    async fn credential_build(
        trusted: bool,
        token: Option<&'static str>,
    ) -> (
        fleet_core::ImageBuildRecord,
        Vec<(String, Option<String>)>,
        String,
    ) {
        let mut replies = probes();
        replies.extend([
            reply("", Some(0), false),
            reply("1,proxmox-clone,artifact,0,id,pve:120", Some(0), false),
        ]);
        let (dir, store, repository, operations, operation, transport) =
            setup(CONTENT, serde_json::json!({}), replies, false).await;
        if trusted {
            sqlx::query("UPDATE proxmox_accounts SET fingerprint = 'AB' WHERE id = 'account-1'")
                .execute(store.pool())
                .await
                .unwrap();
        }
        let executor = ImagesExecutor::new(
            repository.clone(),
            transport.clone(),
            None,
            dir.path().join("work"),
        )
        .with_account_credentials(
            Arc::new(fleet_storage_sqlite::ProxmoxAccountRepository::new(
                store.pool().clone(),
            )),
            Arc::new(OneToken(token)),
        );
        assert!(
            operations
                .execute_claimed(&executor, operation.clone())
                .await
        );
        let record = repository.get_build(&operation.id).await.unwrap();
        let stored: Vec<String> = sqlx::query_scalar(
            "SELECT COALESCE(payload_json,'') || COALESCE(result_json,'') || COALESCE(error_json,'') FROM operations \
             UNION ALL SELECT metadata_json FROM audit_events",
        )
        .fetch_all(store.pool())
        .await
        .unwrap();
        let seen = transport.saw_env.lock().unwrap().clone();
        (record, seen, stored.join("\n"))
    }

    #[tokio::test]
    async fn a_build_gets_its_trusted_accounts_token_in_the_child_environment_only() {
        let (record, seen, stored) = credential_build(true, Some("fixture-account-token")).await;
        assert_eq!(record.outcome, "succeeded", "{:?}", record.reason);
        // validate and build carry the token; the version probes do not.
        for (args, token) in &seen {
            let wants = args.starts_with("validate") || args.contains(" build ");
            assert_eq!(
                token.as_deref(),
                wants.then_some("fixture-account-token"),
                "{args}"
            );
            assert!(!args.contains("fixture-account-token"));
        }
        assert!(seen.iter().any(|(args, _)| args.contains(" build ")));
        let record_text = serde_json::to_string(&record).unwrap();
        assert!(!record_text.contains("fixture-account-token"));
        assert!(!stored.contains("fixture-account-token"));
    }

    #[tokio::test]
    async fn no_token_leaves_for_an_untrusted_account_or_without_a_stored_token() {
        let (record, seen, _) = credential_build(false, Some("fixture-account-token")).await;
        assert_eq!(record.reason.as_deref(), Some("target_account_untrusted"));
        assert!(
            seen.iter()
                .all(|(args, token)| token.is_none() && !args.starts_with("validate"))
        );

        let (record, seen, _) = credential_build(true, None).await;
        assert_eq!(record.reason.as_deref(), Some("account_credential_missing"));
        assert!(seen.iter().all(|(args, _)| !args.starts_with("validate")));
    }

    #[test]
    fn a_cancel_poll_failure_is_never_reported_as_a_cancel() {
        for reported in ["cancelled", "cancelled_unverified", "build_failed"] {
            assert_eq!(
                super::settle_build(Some("cancel_poll_failed"), Err(reported)).unwrap_err(),
                "cancel_poll_failed",
                "{reported}"
            );
        }
        assert_eq!(
            super::settle_build(Some("cancelled"), Err("cancelled_unverified")).unwrap_err(),
            "cancelled_unverified"
        );
        assert_eq!(
            super::settle_build(Some("cancelled"), Err("build_failed")).unwrap_err(),
            "cancelled"
        );
        assert_eq!(
            super::settle_build(None, Err("validate_failed")).unwrap_err(),
            "validate_failed"
        );
        let template = ImageBuildTemplate {
            node: "pve".to_owned(),
            vmid: 120,
            name: "ubuntu-base".to_owned(),
        };
        assert!(super::settle_build(Some("cancel_poll_failed"), Ok(template)).is_ok());
    }

    #[test]
    fn numeric_versions_accept_the_existing_two_component_contract() {
        assert_eq!(numeric_version("1.15"), Some((1, 15, 0)));
        assert_eq!(numeric_version("1.16.1"), Some((1, 16, 1)));
        for invalid in ["1", "1.15.", "1.15.0.1", "1.15.secret", "1.15-beta"] {
            assert_eq!(numeric_version(invalid), None);
        }
    }

    #[tokio::test]
    async fn two_component_packer_versions_build_and_pve_names_remain_dns_names() {
        let mut replies = probes();
        replies[0] = reply("1,,version,1.15", Some(0), false);
        replies.extend([
            reply("", Some(0), false),
            reply("1,proxmox-clone,artifact,0,id,120", Some(0), false),
        ]);
        let (dir, _store, repository, operations, operation, transport) =
            setup(CONTENT, serde_json::json!({}), replies, false).await;
        let executor =
            ImagesExecutor::new(repository.clone(), transport, None, dir.path().join("work"));
        assert!(
            operations
                .execute_claimed(&executor, operation.clone())
                .await
        );
        let record = repository.get_build(&operation.id).await.unwrap();
        assert_eq!(record.outcome, "succeeded");
        assert_eq!(record.packer_version.as_deref(), Some("1.15"));
        let mut version = repository.get_version(&record.version_id).await.unwrap();
        version.content = CONTENT.replace("ubuntu-base", "ubuntu_base");
        assert!(output_template("120", &version).is_none());
    }

    #[tokio::test]
    async fn build_records_complete_on_every_provider_terminal_path() {
        let mut cases = vec![
            (
                vec![reply("1,,version,0.9.0", Some(0), false)],
                "version_gate",
            ),
            (vec![Err("fixture-secret-token".to_owned())], "version_gate"),
            (
                vec![
                    reply("1,,version,1.16.1", Some(0), false),
                    reply("", Some(0), false),
                ],
                "plugin_version_gate",
            ),
        ];
        for (outcome, reason) in [
            (reply("", Some(1), false), "build_failed"),
            (Err("fixture-secret-token".to_owned()), "build_failed"),
            (reply("", None, true), "deadline_killed"),
            // Interrupted at the deadline and reported clean by Packer.
            (
                reply(
                    "1,,ui,say,Cleanly cancelled builds after being interrupted.",
                    Some(1),
                    true,
                ),
                "deadline_interrupted",
            ),
            // Interrupted at the deadline without Packer's clean report.
            (
                reply("1,,ui,say,build interrupted", Some(1), true),
                "deadline_interrupted_unverified",
            ),
            (reply("", Some(0), false), "artifact_missing"),
            (
                reply("1,proxmox-clone,artifact,0,id,120", Some(0), false),
                "succeeded",
            ),
        ] {
            let mut replies = probes();
            replies.extend([reply("", Some(0), false), outcome]);
            cases.push((replies, reason));
        }
        let mut validate_failed = probes();
        validate_failed.push(reply("", Some(1), false));
        cases.push((validate_failed, "validate_failed"));
        for (outcome, reason) in [
            (Err("fixture-secret-token".to_owned()), "validate_failed"),
            (reply("", None, true), "deadline_killed"),
        ] {
            let mut replies = probes();
            replies.push(outcome);
            cases.push((replies, reason));
        }

        for (replies, reason) in cases {
            let (dir, store, repository, operations, operation, transport) =
                setup(CONTENT, serde_json::json!({}), replies, false).await;
            let executor =
                ImagesExecutor::new(repository.clone(), transport, None, dir.path().join("work"));
            assert!(
                operations
                    .execute_claimed(&executor, operation.clone())
                    .await
            );
            let record = repository.get_build(&operation.id).await.unwrap();
            assert!(record.ended_at.is_some());
            assert_eq!(record.reason.as_deref().unwrap_or(&record.outcome), reason);
            assert_eq!(
                operations.get_state(&operation.id).await.unwrap(),
                record.outcome
            );
            assert_eq!(record.asset_digests.len(), 1);
            assert_eq!(
                record.template.as_ref().map(|t| t.vmid),
                (reason == "succeeded").then_some(120)
            );
            assert!(!dir.path().join("work").join(&operation.id).exists());
            let public =
                serde_json::to_string(&fleet_api::images::ImageBuildDto::from(record)).unwrap();
            assert!(!public.contains("fixture-secret-token"));
            let audit: Vec<String> = sqlx::query_scalar("SELECT metadata_json FROM audit_events")
                .fetch_all(store.pool())
                .await
                .unwrap();
            assert!(
                audit
                    .iter()
                    .all(|row| !row.contains("fixture-secret-token"))
            );
        }
    }

    #[test]
    fn embedded_inputs_fail_closed_for_unknown_provisioners_and_fields() {
        for provisioner in [
            serde_json::json!({"type":"ansible-local", "playbook_paths":["mutable.yml"], "role_paths":["roles"]}),
            serde_json::json!({"type":"salt-masterless", "local_state_tree":"states"}),
            serde_json::json!({"type":"chef-solo", "config_template":"chef.rb"}),
            serde_json::json!({"type":"shell", "inline":["echo ready"], "scripts":["local.sh"]}),
            serde_json::json!({"type":"shell", "inline":["echo ready"], "override":{"builder":{"script":"local.sh"}}}),
            serde_json::json!({"type":"file", "content":"bytes", "destination":"/tmp/file", "source":"mutable"}),
            serde_json::json!({"type":"future-plugin", "inline":["unknown"]}),
        ] {
            assert!(has_external_assets(
                &serde_json::json!({"provisioners":[provisioner]}).to_string()
            ));
        }
        let embedded = serde_json::json!({"provisioners":[
            {"type":"shell", "inline":["echo ready"]},
            {"type":"file", "content":"embedded bytes", "destination":"/tmp/file"}
        ]})
        .to_string();
        assert!(!has_external_assets(&embedded));
        assert_eq!(provisioning_digests(&embedded).len(), 2);
    }

    #[tokio::test]
    async fn refusals_before_provider_execution_still_complete_records() {
        let unbound = CONTENT.replace(
            r#","proxmox_url":"https://pve.example.test:8006/api2/json""#,
            "",
        );
        let external = CONTENT.replace(r#""inline":["echo ready"]"#, r#""script":"external.sh""#);
        let mismatch = CONTENT.replace(r#""node":"pve""#, r#""node":"other""#);
        for (content, payload, replies, reason) in [
            (
                unbound.as_str(),
                serde_json::json!({"accountId": null}),
                Vec::new(),
                "target_account_missing",
            ),
            (
                CONTENT,
                serde_json::json!({"accountId": "unknown"}),
                Vec::new(),
                "target_account_resolution_failed",
            ),
            (
                external.as_str(),
                serde_json::json!({}),
                Vec::new(),
                "asset_snapshot_missing",
            ),
            (
                mismatch.as_str(),
                serde_json::json!({}),
                Vec::new(),
                "target_snapshot_mismatch",
            ),
            (
                CONTENT,
                serde_json::json!({"secretVars": [{"name": "token", "reference": "unavailable"}]}),
                probes(),
                "secret_resolution_failed",
            ),
        ] {
            let (dir, _store, repository, operations, operation, transport) =
                setup(content, payload, replies, false).await;
            let executor =
                ImagesExecutor::new(repository.clone(), transport, None, dir.path().join("work"));
            assert!(
                operations
                    .execute_claimed(&executor, operation.clone())
                    .await
            );
            let record = repository.get_build(&operation.id).await.unwrap();
            assert_eq!(record.outcome, "failed");
            assert_eq!(record.reason.as_deref(), Some(reason));
            assert!(record.ended_at.is_some());
        }
    }

    #[tokio::test]
    async fn cancellation_interrupts_the_build_and_finishes_the_record() {
        let mut replies = probes();
        replies.push(reply("", Some(0), false));
        let (dir, _store, repository, operations, operation, transport) =
            setup(CONTENT, serde_json::json!({}), replies, true).await;
        let executor = ImagesExecutor::new(
            repository.clone(),
            transport.clone(),
            None,
            dir.path().join("work"),
        );
        let running = operations.execute_claimed(&executor, operation.clone());
        let cancel = async {
            transport.building.notified().await;
            operations
                .cancel(&Allow, "anonymous-lan-admin", &operation.id)
                .await
                .unwrap();
        };
        let (completed, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(running, cancel)
        })
        .await
        .unwrap();
        assert!(completed);
        // The build was interrupted gracefully, not dropped (#271).
        assert!(
            transport
                .interrupted
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        let record = repository.get_build(&operation.id).await.unwrap();
        assert_eq!(record.outcome, "cancelled");
        assert_eq!(record.reason.as_deref(), Some("cancelled"));
        assert_eq!(
            operations.get_state(&operation.id).await.unwrap(),
            "cancelled"
        );
        assert!(!dir.path().join("work").join(&operation.id).exists());
    }

    #[tokio::test]
    async fn a_cancel_without_packers_clean_report_is_recorded_as_unverified() {
        let mut replies = probes();
        replies.push(reply("", Some(0), false));
        let (dir, _store, repository, operations, operation, transport) =
            setup(CONTENT, serde_json::json!({}), replies, true).await;
        transport
            .clean_cancel
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let executor = ImagesExecutor::new(
            repository.clone(),
            transport.clone(),
            None,
            dir.path().join("work"),
        );
        let running = operations.execute_claimed(&executor, operation.clone());
        let cancel = async {
            transport.building.notified().await;
            operations
                .cancel(&Allow, "anonymous-lan-admin", &operation.id)
                .await
                .unwrap();
        };
        let (completed, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(running, cancel)
        })
        .await
        .unwrap();
        assert!(completed);
        let record = repository.get_build(&operation.id).await.unwrap();
        assert_eq!(record.outcome, "cancelled");
        assert_eq!(record.reason.as_deref(), Some("cancelled_unverified"));
    }

    #[tokio::test]
    async fn secret_variables_and_var_file_paths_never_enter_build_or_audit_records() {
        let mut replies = probes();
        replies.extend([
            reply("", Some(0), false),
            reply("1,proxmox-clone,artifact,0,id,120", Some(0), false),
        ]);
        let (dir, store, repository, operations, mut operation, transport) =
            setup(CONTENT, serde_json::json!({}), replies, false).await;
        let key = dir.path().join("master.key");
        std::fs::write(
            &key,
            "1 0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let secrets =
            Arc::new(fleet_secrets::SecretStore::open(store.pool().clone(), &key).unwrap());
        let secret = secrets
            .create("build-token", "fixture-secret-token".into())
            .await
            .unwrap();
        let mut payload: serde_json::Value =
            serde_json::from_str(operation.payload_json.as_deref().unwrap()).unwrap();
        payload["secretVars"] = serde_json::json!([{"name": "token", "reference": secret.id}]);
        operation.payload_json = Some(payload.to_string());
        let executor = ImagesExecutor::new(
            repository.clone(),
            transport.clone(),
            Some(secrets),
            dir.path().join("work"),
        );
        assert!(
            operations
                .execute_claimed(&executor, operation.clone())
                .await
        );
        let path = transport
            .saw_var_file
            .lock()
            .unwrap()
            .clone()
            .expect("the secret must be delivered through a var file");
        assert!(!std::path::Path::new(&path).exists());
        let record = repository.get_build(&operation.id).await.unwrap();
        assert_eq!(record.outcome, "succeeded");
        let public =
            serde_json::to_string(&fleet_api::images::ImageBuildDto::from(record)).unwrap();
        let audit: Vec<String> = sqlx::query_scalar("SELECT metadata_json FROM audit_events")
            .fetch_all(store.pool())
            .await
            .unwrap();
        for text in std::iter::once(&public).chain(audit.iter()) {
            assert!(!text.contains("fixture-secret-token"));
            assert!(!text.contains(&path));
            assert!(!text.contains("vars.auto.pkrvars.json"));
        }
    }

    #[test]
    fn plugin_probe_refuses_ambiguous_and_untrusted_version_strings() {
        assert_eq!(
            plugin_version("/private/packer-plugin-proxmox_v1.2.4_x5.0_linux_amd64"),
            Some("1.2.4".to_owned())
        );
        assert_eq!(
            plugin_version("/private/packer-plugin-proxmox_vtoken_x5.0_linux_amd64"),
            None
        );
        assert_eq!(
            plugin_version(
                "packer-plugin-proxmox_v1.2.4_x5.0_linux_amd64\npacker-plugin-proxmox_v1.3.0_x5.0_linux_amd64"
            ),
            None
        );
    }
}
