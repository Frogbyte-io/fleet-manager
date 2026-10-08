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
//!
//! #284 pins the account's confirmed certificate for Packer. The Proxmox
//! plugin verifies TLS against Go's system root pool, which on Linux is
//! exactly `SSL_CERT_FILE` plus the directories in `SSL_CERT_DIR`. Each
//! build captures the host's leaf without credentials, refuses it unless
//! its SHA-256 equals the confirmed pin and it names the account host, and
//! hands the validate/build children that one leaf as their only root (an
//! empty `SSL_CERT_DIR` keeps the system directories out). Go accepts a
//! leaf that is itself in the pool as a chain of one, still checking the
//! host name, validity, and key usage; any other certificate fails the
//! handshake before a request, and so the token, is sent.

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
    certificates: Option<Arc<dyn fleet_provider_proxmox::PveTransport>>,
}

/// The work-directory entries that carry the pinned trust to Packer.
const TLS_DIR: &str = "tls";
/// The pinned leaf, PEM-encoded: `SSL_CERT_FILE`.
const PINNED_CERT_FILE: &str = "pinned.pem";
/// An empty directory: `SSL_CERT_DIR`, so Go loads no system directory.
const EMPTY_CERT_DIR: &str = "roots.d";

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
            certificates: None,
        }
    }

    /// Hands each build its target account's token (#272): resolved just in
    /// time, behind the account's explicit-trust gate, into Packer's child
    /// environment only, together with the account's pinned certificate as
    /// the child's only TLS root (#284). `certificates` captures the host's
    /// leaf without credentials for the pin check. Without this the CLI
    /// inherits the controller's environment, as before.
    #[must_use]
    pub fn with_account_credentials(
        mut self,
        accounts: Arc<dyn fleet_application::proxmox::ProxmoxAccountPort>,
        credentials: Arc<dyn fleet_application::proxmox::ProxmoxCredentialStore>,
        certificates: Arc<dyn fleet_provider_proxmox::PveTransport>,
    ) -> Self {
        self.accounts = Some(accounts);
        self.credentials = Some(credentials);
        self.certificates = Some(certificates);
        self
    }

    /// The version probes' environment: no Proxmox credential at all once
    /// builds get their account's token, rather than the controller's own.
    fn probe_env(&self) -> SecretEnv {
        if self.credentials.is_some() {
            SecretEnv::isolated()
        } else {
            SecretEnv::default()
        }
    }

    /// The Proxmox plugin's environment for the build's account: its
    /// token and, unless the version opted into skipping verification, its
    /// pinned certificate as the only TLS root. A token is never handed out
    /// for an account whose host trust is unconfirmed, or whose host now
    /// presents a certificate other than the confirmed one.
    async fn account_env(
        &self,
        account_id: Option<&str>,
        work_dir: &std::path::Path,
        insecure_tls: bool,
    ) -> Result<SecretEnv, &'static str> {
        let (Some(accounts), Some(credentials), Some(certificates)) =
            (&self.accounts, &self.credentials, &self.certificates)
        else {
            return Ok(SecretEnv::default());
        };
        let account_id = account_id.ok_or("target_account_missing")?;
        let account = accounts
            .get(account_id)
            .await
            .map_err(|_| "target_account_unreadable")?;
        let Some(pinned) = account.fingerprint.as_deref() else {
            return Err("target_account_untrusted");
        };
        // The leaf is captured without credentials and is worth exactly as
        // much as its digest: only the confirmed certificate passes. This
        // runs for opted-in insecure builds too, so even they never hand
        // the token to a host whose certificate changed since confirmation.
        let observed = certificates
            .observe_certificate(&account.host, account.port)
            .await
            .map_err(|_| "target_certificate_unobservable")?;
        let digest: [u8; 32] = sha2::Sha256::digest(&observed.der).into();
        let digest = digest.iter().fold(String::with_capacity(64), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02X}");
            out
        });
        if fleet_provider_proxmox::normalize_fingerprint(pinned) != digest {
            return Err("target_certificate_changed");
        }
        let mut vars = Vec::new();
        if !insecure_tls {
            // Go uses the platform verifier, not `SSL_CERT_FILE`, on these.
            if cfg!(any(target_os = "macos", target_os = "ios", windows)) {
                return Err("certificate_pin_unsupported");
            }
            if !fleet_provider_proxmox::certificate_names_host(&observed.der, &account.host) {
                return Err("target_certificate_name_mismatch");
            }
            let (file, dir) = write_pinned_roots(work_dir, &observed.der)
                .map_err(|_| "certificate_write_failed")?;
            for (name, path) in [("SSL_CERT_FILE", file), ("SSL_CERT_DIR", dir)] {
                vars.push((
                    name.to_owned(),
                    fleet_core::SensitiveString::new(path.display().to_string()),
                ));
            }
        }
        let secret = credentials
            .load(account_id)
            .await
            .map_err(|_| "account_credential_unreadable")?
            .ok_or("account_credential_missing")?;
        vars.extend([
            (
                "PROXMOX_USERNAME".to_owned(),
                fleet_core::SensitiveString::new(account.token_id),
            ),
            (
                "PROXMOX_TOKEN".to_owned(),
                fleet_core::SensitiveString::new(secret),
            ),
        ]);
        Ok(SecretEnv::new(vars))
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
        // Skipping TLS verification sends the token to whatever answers at
        // the recipe's address: only a version published with the audited
        // opt-in may (#284).
        let insecure_tls = fleet_core::requests_insecure_tls(&version.content);
        if insecure_tls && !version.allow_insecure_tls {
            return Err("insecure_tls_not_allowed");
        }
        std::fs::create_dir_all(&self.work_root).map_err(|_| "work_directory_failed")?;
        let probe = self
            .transport
            .run(
                &PackerCommand {
                    args: vec!["-machine-readable".to_owned(), "version".to_owned()],
                    work_dir: self.work_root.clone(),
                    env: self.probe_env(),
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
                    env: self.probe_env(),
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
        let env = self
            .account_env(record.account_id.as_deref(), work_dir, insecure_tls)
            .await?;
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

/// Writes the pinned leaf as the build's only TLS root: a PEM file and an
/// empty directory, both inside the operation's private work directory and
/// removed with it. Answers `(SSL_CERT_FILE, SSL_CERT_DIR)`.
fn write_pinned_roots(
    work_dir: &std::path::Path,
    der: &[u8],
) -> std::io::Result<(PathBuf, PathBuf)> {
    use base64::Engine as _;
    let tls = work_dir.join(TLS_DIR);
    let empty = tls.join(EMPTY_CERT_DIR);
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(&empty)?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).map_err(std::io::Error::other)?);
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    let file = tls.join(PINNED_CERT_FILE);
    std::fs::write(&file, pem)?;
    Ok((file, empty))
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
        /// Per command: its args joined, the child's PROXMOX_TOKEN, and
        /// whether ambient PROXMOX_* are removed.
        saw_env: Mutex<Vec<(String, Option<String>, bool)>>,
        /// Per command: its args joined and the trust it was handed, as
        /// the child would read it at that moment.
        saw_tls: Mutex<Vec<(String, Option<SeenTls>)>>,
    }

    /// The pinned roots one command saw on disk.
    #[derive(Clone, Debug)]
    struct SeenTls {
        file: PathBuf,
        dir: PathBuf,
        pem: String,
        dir_entries: usize,
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
                command.env.is_isolated(),
            ));
            let tls = match (
                command.env.get("SSL_CERT_FILE"),
                command.env.get("SSL_CERT_DIR"),
            ) {
                (None, None) => None,
                (file, dir) => {
                    let file = PathBuf::from(file.expect("SSL_CERT_FILE travels with the dir"));
                    let dir = PathBuf::from(dir.expect("SSL_CERT_DIR travels with the file"));
                    Some(SeenTls {
                        pem: std::fs::read_to_string(&file).unwrap(),
                        dir_entries: std::fs::read_dir(&dir).unwrap().count(),
                        file,
                        dir,
                    })
                }
            };
            self.saw_tls
                .lock()
                .unwrap()
                .push((command.args.join(" "), tls));
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
        setup_with(
            content,
            payload_extra,
            replies,
            wait_build,
            fleet_application::images::PublishOptions::default(),
        )
        .await
    }

    async fn setup_with(
        content: &str,
        payload_extra: serde_json::Value,
        replies: Vec<Result<fleet_provider_packer::CliOutcome, String>>,
        wait_build: bool,
        options: fleet_application::images::PublishOptions,
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
            .publish_with(&Allow, &principal, &recipe.id, 1001, options)
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
            saw_tls: Mutex::new(Vec::new()),
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

    /// A leaf certificate for `names`: what a PVE host would present.
    fn leaf(names: &[&str]) -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        rcgen::CertificateParams::new(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap()
        .self_signed(&key)
        .unwrap()
        .der()
        .to_vec()
    }

    /// The pin Fleet stores for `der`: the confirm step's normalized form.
    fn pin_of(der: &[u8]) -> String {
        let digest: [u8; 32] = sha2::Sha256::digest(der).into();
        digest.iter().map(|byte| format!("{byte:02X}")).collect()
    }

    /// A certificate probe answering one fixed leaf, or no host at all.
    /// It cannot carry a credential: nothing here sees one.
    #[derive(Debug)]
    struct Presents(Option<Vec<u8>>);

    #[async_trait::async_trait]
    impl fleet_provider_proxmox::PveTransport for Presents {
        async fn execute(
            &self,
            _: fleet_provider_proxmox::PveHttpRequest,
        ) -> Result<
            fleet_provider_proxmox::PveHttpResponse,
            fleet_provider_proxmox::PveTransportError,
        > {
            unreachable!("a build never calls the PVE API itself")
        }
        async fn execute_with_body(
            &self,
            _: fleet_provider_proxmox::PveHttpRequest,
            _: Vec<u8>,
        ) -> Result<
            fleet_provider_proxmox::PveHttpResponse,
            fleet_provider_proxmox::PveTransportError,
        > {
            unreachable!("a build never calls the PVE API itself")
        }
        async fn observe_certificate(
            &self,
            host: &str,
            port: u16,
        ) -> Result<
            fleet_provider_proxmox::ObservedCertificate,
            fleet_provider_proxmox::PveTransportError,
        > {
            assert_eq!((host, port), ("pve.example.test", 8006));
            self.0
                .clone()
                .map(|der| fleet_provider_proxmox::ObservedCertificate {
                    fingerprint: pin_of(&der),
                    der,
                })
                .ok_or(fleet_provider_proxmox::PveTransportError::NoCertificate)
        }
    }

    /// One credentialed build's inputs.
    struct Case {
        content: &'static str,
        options: fleet_application::images::PublishOptions,
        /// The certificate whose fingerprint the account pins, if trusted.
        pinned: Option<Vec<u8>>,
        /// The certificate the host presents now, if reachable.
        presented: Option<Vec<u8>>,
        token: Option<&'static str>,
    }

    impl Case {
        fn pinned_and_presented(der: &[u8]) -> Self {
            Self {
                content: CONTENT,
                options: fleet_application::images::PublishOptions::default(),
                pinned: Some(der.to_vec()),
                presented: Some(der.to_vec()),
                token: Some("fixture-account-token"),
            }
        }
    }

    /// What one credentialed build left behind.
    struct Ran {
        record: fleet_core::ImageBuildRecord,
        seen: Vec<(String, Option<String>, bool)>,
        tls: Vec<(String, Option<SeenTls>)>,
        stored: String,
        work: PathBuf,
    }

    /// Runs one build with account credentials wired; answers the record,
    /// what the transport saw, and every stored operation/audit text.
    async fn credential_build(
        trusted: bool,
        token: Option<&'static str>,
    ) -> (
        fleet_core::ImageBuildRecord,
        Vec<(String, Option<String>, bool)>,
        String,
    ) {
        let der = leaf(&["pve.example.test"]);
        let mut case = Case::pinned_and_presented(&der);
        case.token = token;
        if !trusted {
            case.pinned = None;
        }
        let ran = run_case(case).await;
        (ran.record, ran.seen, ran.stored)
    }

    async fn run_case(case: Case) -> Ran {
        let mut replies = probes();
        replies.extend([
            reply("", Some(0), false),
            reply("1,proxmox-clone,artifact,0,id,pve:120", Some(0), false),
        ]);
        let (dir, store, repository, operations, operation, transport) = setup_with(
            case.content,
            serde_json::json!({}),
            replies,
            false,
            case.options,
        )
        .await;
        if let Some(pinned) = &case.pinned {
            sqlx::query("UPDATE proxmox_accounts SET fingerprint = ?1 WHERE id = 'account-1'")
                .bind(pin_of(pinned))
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
            Arc::new(OneToken(case.token)),
            Arc::new(Presents(case.presented.clone())),
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
        let tls = transport.saw_tls.lock().unwrap().clone();
        Ran {
            record,
            seen,
            tls,
            stored: stored.join("\n"),
            work: dir.path().join("work").join(&operation.id),
        }
    }

    #[tokio::test]
    async fn validate_and_build_trust_only_the_pinned_leaf_and_the_files_go_with_the_work_dir() {
        let der = leaf(&["pve.example.test"]);
        let ran = run_case(Case::pinned_and_presented(&der)).await;
        assert_eq!(ran.record.outcome, "succeeded", "{:?}", ran.record.reason);
        let pinned: Vec<_> = ran.tls.iter().filter(|(_, tls)| tls.is_some()).collect();
        // Exactly validate and build get the pin; the version probes do not.
        assert_eq!(pinned.len(), 2, "{:?}", ran.tls);
        for (args, tls) in &ran.tls {
            let wants = args.starts_with("validate") || args.contains(" build ");
            assert_eq!(tls.is_some(), wants, "{args}");
        }
        use base64::Engine as _;
        for (_, tls) in pinned {
            let tls = tls.as_ref().unwrap();
            assert!(tls.file.starts_with(&ran.work), "{}", tls.file.display());
            assert!(tls.dir.starts_with(&ran.work), "{}", tls.dir.display());
            assert_eq!(tls.dir_entries, 0, "the root directory stays empty");
            let body: String = tls
                .pem
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect();
            assert!(tls.pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
            assert!(tls.pem.lines().all(|line| line.len() <= 64));
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .unwrap(),
                der
            );
        }
        // The pin lives only in the children's environment and the work
        // directory, which is gone after the build.
        assert!(
            std::env::var_os("SSL_CERT_FILE")
                .is_none_or(|value| { !std::path::Path::new(&value).starts_with(&ran.work) })
        );
        assert!(!ran.work.exists());
    }

    #[tokio::test]
    async fn a_changed_certificate_fails_the_build_before_packer_or_the_token() {
        let mut case = Case::pinned_and_presented(&leaf(&["pve.example.test"]));
        case.presented = Some(leaf(&["pve.example.test"]));
        let ran = run_case(case).await;
        assert_eq!(
            ran.record.reason.as_deref(),
            Some("target_certificate_changed")
        );
        assert!(ran.seen.iter().all(|(args, token, _)| token.is_none()
            && !args.starts_with("validate")
            && !args.contains(" build ")));
        assert!(!ran.stored.contains("fixture-account-token"));
    }

    #[tokio::test]
    async fn a_leaf_that_does_not_name_the_host_is_refused_not_skipped() {
        let der = leaf(&["pve1.example.test", "192.0.2.10"]);
        let ran = run_case(Case::pinned_and_presented(&der)).await;
        assert_eq!(
            ran.record.reason.as_deref(),
            Some("target_certificate_name_mismatch")
        );
        assert!(ran.seen.iter().all(|(_, token, _)| token.is_none()));
    }

    #[tokio::test]
    async fn an_unreachable_host_hands_out_nothing() {
        let mut case = Case::pinned_and_presented(&leaf(&["pve.example.test"]));
        case.presented = None;
        let ran = run_case(case).await;
        assert_eq!(
            ran.record.reason.as_deref(),
            Some("target_certificate_unobservable")
        );
        assert!(ran.seen.iter().all(|(_, token, _)| token.is_none()));
    }

    const INSECURE: &str = r#"{"builders":[{"type":"proxmox-clone","node":"pve","insecure_skip_tls_verify":true,"disks":[{"type":"scsi","storage_pool":"local-lvm","disk_size":"8G"}],"vm_name":"ubuntu-base","proxmox_url":"https://pve.example.test:8006/api2/json"}]}"#;

    #[tokio::test]
    async fn skipping_verification_needs_the_versions_opt_in() {
        let der = leaf(&["pve.example.test"]);
        let mut case = Case::pinned_and_presented(&der);
        case.content = INSECURE;
        let ran = run_case(case).await;
        assert_eq!(
            ran.record.reason.as_deref(),
            Some("insecure_tls_not_allowed")
        );
        // Refused before any Packer command at all.
        assert!(ran.seen.is_empty(), "{:?}", ran.seen);

        // With the opt-in it builds without a pin, but the token still
        // goes only to the confirmed certificate.
        let mut case = Case::pinned_and_presented(&der);
        case.content = INSECURE;
        case.options.allow_insecure_tls = true;
        let ran = run_case(case).await;
        assert_eq!(ran.record.outcome, "succeeded", "{:?}", ran.record.reason);
        assert!(ran.tls.iter().all(|(_, tls)| tls.is_none()));
        assert!(
            ran.seen
                .iter()
                .any(|(args, token, _)| args.contains(" build ")
                    && token.as_deref() == Some("fixture-account-token"))
        );
        let mut case = Case::pinned_and_presented(&der);
        case.content = INSECURE;
        case.options.allow_insecure_tls = true;
        case.presented = Some(leaf(&["pve.example.test"]));
        let ran = run_case(case).await;
        assert_eq!(
            ran.record.reason.as_deref(),
            Some("target_certificate_changed")
        );
    }

    #[tokio::test]
    async fn a_build_gets_its_trusted_accounts_token_in_the_child_environment_only() {
        let (record, seen, stored) = credential_build(true, Some("fixture-account-token")).await;
        assert_eq!(record.outcome, "succeeded", "{:?}", record.reason);
        // validate and build carry the token; the version probes carry
        // none, not even the controller's own.
        for (args, token, isolated) in &seen {
            assert!(isolated, "{args}");
            let wants = args.starts_with("validate") || args.contains(" build ");
            assert_eq!(
                token.as_deref(),
                wants.then_some("fixture-account-token"),
                "{args}"
            );
            assert!(!args.contains("fixture-account-token"));
        }
        assert!(seen.iter().any(|(args, _, _)| args.contains(" build ")));
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
                .all(|(args, token, _)| token.is_none() && !args.starts_with("validate"))
        );

        let (record, seen, _) = credential_build(true, None).await;
        assert_eq!(record.reason.as_deref(), Some("account_credential_missing"));
        assert!(
            seen.iter()
                .all(|(args, _, _)| !args.starts_with("validate"))
        );
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
