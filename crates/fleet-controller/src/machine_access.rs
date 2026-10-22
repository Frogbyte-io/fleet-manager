//! The controller side of agent SSH access to machines (#493, ADR 0017).
//!
//! - [`SecretBackedMachineKeys`] keeps SSH private keys as encrypted secret
//!   records named `machines/ssh/<uuid>` and resolves them just in time. The
//!   record id is the reference an endpoint's auth holds. Only that
//!   namespace and the existing Git credential namespace (`git/`) resolve,
//!   and only when the value is a usable unencrypted private key, so a
//!   reference can never reach a Proxmox token or another integration's
//!   secret.
//! - [`SshAuthResolver`] turns an [`EndpointAuth`] into the provider's
//!   [`SshAuth`], resolving a stored key at the moment a session starts.
//! - [`MachineAccessDispatch`] wraps the executor chain and runs
//!   `machine.exec` (through the `ssh.exec` executor, so the same bounds,
//!   deadline, cancellation and scrubber apply), `machine.put` (the Lab put
//!   transfer, shared) and `machine.collect` (the Lab fetch, shared).
//!
//! The key text is never logged, returned, or placed in an operation's
//! payload or result; a failure names the problem, not the content.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use fleet_application::lab_artifacts::validate_collect_paths_for;
use fleet_application::machine_access::{EndpointAuth, MachineAccess, MachineKeyPort};
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_provider_ssh::{PrivateKey, SshAuth};
use fleet_secrets::{SecretError, SecretStore, SecretValue};

use crate::lab_artifacts_store::{
    COLLECT_DEADLINE, FsArtifactStore, GuestFiles, GuestPut, fetch_failure, payload_guest_os,
};
use crate::lab_put_store::{FsUploadStore, StagedGuard, parse_payload, put_deadline, put_failure};

/// The secret-record name prefix for keys stored through Fleet.
pub const KEY_PREFIX: &str = "machines/ssh/";
/// The existing Git credential namespace; its SSH keys are usable too.
const GIT_PREFIX: &str = "git/";

/// The key store over the encrypted secret store.
#[derive(Debug)]
pub struct SecretBackedMachineKeys {
    secrets: Arc<SecretStore>,
    protected: Vec<std::path::PathBuf>,
}

impl SecretBackedMachineKeys {
    /// Composes the store over the controller's secret store.
    #[must_use]
    pub fn new(secrets: Arc<SecretStore>) -> Self {
        Self {
            secrets,
            protected: Vec::new(),
        }
    }

    /// Refuses identity files at or under these paths (the SSH work
    /// directory and the master key file). The rest of the data directory,
    /// including the controller user's own `~/.ssh`, stays usable.
    #[must_use]
    pub fn protecting(mut self, paths: Vec<std::path::PathBuf>) -> Self {
        self.protected = paths;
        self
    }

    /// Whether `reference` names a live record inside a namespace usable on
    /// `machine_id`: a `machines/ssh/<machine>/...` record only on its own
    /// machine, an unbound `machines/ssh/...` or `git/...` record anywhere.
    async fn in_namespace(&self, reference: &str, machine_id: &str) -> Result<bool, String> {
        Ok(self
            .secrets
            .list()
            .await
            .map_err(|error| format!("the secret store is unreadable: {error}"))?
            .iter()
            .any(|record| record.id == reference && usable_on(&record.name, machine_id)))
    }

    /// The stored text of a record inside a usable namespace, when it is
    /// live. `None` means missing, revoked, or outside the namespaces.
    async fn text(&self, reference: &str, machine_id: &str) -> Result<Option<String>, String> {
        if !self.in_namespace(reference, machine_id).await? {
            return Ok(None);
        }
        match self.secrets.resolve(reference).await {
            Ok(value) => String::from_utf8(value.expose().to_vec())
                .map(Some)
                .map_err(|_| "the stored credential is not an SSH key".to_owned()),
            // Deleted between the check and the read: revoked.
            Err(SecretError::NotFound { .. }) => Ok(None),
            Err(error) => Err(format!("the stored credential is unreadable: {error}")),
        }
    }
}

#[async_trait]
impl MachineKeyPort for SecretBackedMachineKeys {
    async fn create(&self, private_key: &str, machine_id: Option<&str>) -> Result<String, String> {
        // Refuse anything that is not a usable key before it is stored, so
        // the store never holds a value an endpoint could not use.
        PrivateKey::parse(private_key)?;
        // A key stored for a machine carries the machine in its name, so
        // it resolves for that machine only.
        let name = match machine_id {
            Some(machine) => format!("{KEY_PREFIX}{machine}/{}", uuid::Uuid::now_v7()),
            None => format!("{KEY_PREFIX}{}", uuid::Uuid::now_v7()),
        };
        self.secrets
            .create(
                &name,
                SecretValue::new(private_key.trim().as_bytes().to_vec()),
            )
            .await
            .map(|record| record.id)
            .map_err(|error| format!("the key could not be stored: {error}"))
    }

    fn check_identity_path(&self, path: &str) -> Result<(), String> {
        let given = std::path::Path::new(path);
        // The canonical path when it exists (a symlink cannot hide a
        // protected file); otherwise the path as written.
        let resolved = std::fs::canonicalize(given).unwrap_or_else(|_| given.to_path_buf());
        let protected = self.protected.iter().any(|root| {
            let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.clone());
            resolved.starts_with(&root) || given.starts_with(&root)
        });
        if protected
            || given
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            Err(
                "the identity file is one of the controller's own key files; it is refused"
                    .to_owned(),
            )
        } else {
            Ok(())
        }
    }

    async fn exists(&self, reference: &str, machine_id: &str) -> Result<bool, String> {
        // A live record that is not a usable key (an HTTPS token in the
        // repository-credential namespace) does not count: it could never
        // authenticate a session.
        Ok(self
            .text(reference, machine_id)
            .await?
            .is_some_and(|text| PrivateKey::parse(&text).is_ok()))
    }

    async fn resolve(&self, reference: &str, machine_id: &str) -> Result<Option<String>, String> {
        self.text(reference, machine_id).await
    }
}

/// Resolves an endpoint's auth into the provider's auth, with a stored key
/// resolved just in time.
#[derive(Debug)]
pub struct SshAuthResolver {
    keys: Arc<dyn MachineKeyPort>,
}

impl SshAuthResolver {
    /// Composes the resolver over a key store.
    #[must_use]
    pub fn new(keys: Arc<dyn MachineKeyPort>) -> Self {
        Self { keys }
    }

    /// The provider auth for `auth`.
    ///
    /// # Errors
    ///
    /// Fails, without echoing key text, when a stored key was revoked, is
    /// unreadable, or is not a usable unencrypted private key.
    pub async fn resolve(&self, auth: &EndpointAuth, machine_id: &str) -> Result<SshAuth, String> {
        match auth {
            EndpointAuth::Agent => Ok(SshAuth::Agent),
            EndpointAuth::IdentityFile { path } => {
                self.keys.check_identity_path(path)?;
                Ok(SshAuth::IdentityFile { path: path.clone() })
            }
            EndpointAuth::Secret { credential } => {
                let text = self
                    .keys
                    .resolve(credential, machine_id)
                    .await?
                    .ok_or("the endpoint's stored SSH key no longer exists (revoked)")?;
                let key = PrivateKey::parse(&text)?;
                Ok(SshAuth::StoredKey { key })
            }
        }
    }
}

/// Whether a secret record named `name` may authenticate a session on
/// `machine_id` (see [`SecretBackedMachineKeys`]).
fn usable_on(name: &str, machine_id: &str) -> bool {
    if let Some(rest) = name.strip_prefix(KEY_PREFIX) {
        return match rest.split_once('/') {
            Some((owner, _)) => owner == machine_id,
            None => true,
        };
    }
    name.starts_with(GIT_PREFIX)
}

/// What a machine operation's payload names: where and how to connect.
struct Connection {
    machine_id: String,
    endpoint_id: String,
    auth: EndpointAuth,
}

fn connection(payload: &serde_json::Value) -> Result<Connection, String> {
    let text = |key: &str| {
        payload[key]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("the payload names no {key}"))
    };
    let auth: EndpointAuth = serde_json::from_value(payload["auth"].clone())
        .map_err(|_| "the payload's auth is not valid".to_owned())?;
    auth.validate()?;
    Ok(Connection {
        machine_id: text("machineId")?,
        endpoint_id: text("endpointId")?,
        auth,
    })
}

/// Wraps the executor chain with the machine access kinds (see the module
/// docs).
#[derive(Debug)]
pub struct MachineAccessDispatch {
    inner: Arc<dyn OperationExecutor>,
    access: Arc<MachineAccess>,
    uploads: Option<Arc<FsUploadStore>>,
    store: Option<Arc<FsArtifactStore>>,
    files: Arc<dyn GuestFiles>,
}

impl MachineAccessDispatch {
    /// Composes the wrapper. `uploads` and `store` are present when the
    /// controller has its artifact directory.
    #[must_use]
    pub fn new(
        inner: Arc<dyn OperationExecutor>,
        access: Arc<MachineAccess>,
        uploads: Option<Arc<FsUploadStore>>,
        store: Option<Arc<FsArtifactStore>>,
        files: Arc<dyn GuestFiles>,
    ) -> Self {
        Self {
            inner,
            access,
            uploads,
            store,
            files,
        }
    }

    async fn fail(
        operations: &Operations,
        operation: &Operation,
        reason: &str,
        detail: &str,
        extra: serde_json::Value,
    ) -> Result<(), String> {
        let mut error = serde_json::json!({
            "reason": reason,
            "detail": fleet_core::scrub_failure_detail(detail),
        });
        if let (Some(map), Some(more)) = (error.as_object_mut(), extra.as_object()) {
            map.extend(more.clone());
        }
        operations
            .complete(&operation.id, "failed", None, Some(&error.to_string()))
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// `machine.exec` runs as `ssh.exec`: the payload already has that shape,
    /// so the SSH executor applies its trust gate, bounds, deadline and
    /// scrubber unchanged, and resolves the stored key itself.
    async fn exec(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let mut ssh = operation.clone();
        ssh.kind = "ssh.exec".to_owned();
        self.inner.execute(operations, &ssh).await
    }

    async fn put(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let Some(uploads) = &self.uploads else {
            return Self::fail(
                operations,
                operation,
                "put_unavailable",
                "the controller has no upload staging area",
                serde_json::json!({}),
            )
            .await;
        };
        let value: serde_json::Value = operation
            .payload_json
            .as_deref()
            .and_then(|payload| serde_json::from_str(payload).ok())
            .unwrap_or_default();
        let payload = match parse_payload(operation) {
            Ok(payload) => payload,
            Err(detail) => {
                return Self::fail(
                    operations,
                    operation,
                    "invalid_payload",
                    &detail,
                    serde_json::json!({}),
                )
                .await;
            }
        };
        // The staged file goes whichever way this returns.
        let _staged = StagedGuard {
            store: uploads,
            id: payload.upload_id.clone(),
        };
        let target = connection(&value);
        let extra = serde_json::json!({
            "machineId": value["machineId"],
            "guestPath": payload.guest_path,
        });
        let target = match target {
            Ok(target) => target,
            Err(detail) => {
                return Self::fail(operations, operation, "invalid_payload", &detail, extra).await;
            }
        };
        let source = match uploads.open_staged(&payload.upload_id, payload.size) {
            Ok(file) => file,
            Err(error) => {
                eprintln!(
                    "machine put: machine {}: the staged upload is unusable: {error}",
                    target.machine_id
                );
                return Self::fail(
                    operations,
                    operation,
                    "upload_unavailable",
                    "the staged upload is missing or changed; upload the file again",
                    extra,
                )
                .await;
            }
        };
        if let Err(error) = operations
            .record_progress(&operation.id, Some(0), Some(1), Some("sending the file"))
            .await
        {
            eprintln!(
                "machine put: progress of operation {} not recorded: {error}",
                operation.id
            );
        }
        let outcome = self
            .files
            .put_with_auth(
                &target.machine_id,
                &target.endpoint_id,
                Some(&target.auth),
                GuestPut {
                    guest_os: payload.guest_os,
                    path: payload.guest_path.clone(),
                    size: payload.size,
                    sha256: payload.sha256.clone(),
                    overwrite: payload.overwrite,
                },
                put_deadline(payload.size),
                source,
            )
            .await;
        match put_failure(outcome, &format!("machine {}", target.machine_id)) {
            None => {
                let result = serde_json::json!({
                    "machineId": target.machine_id,
                    "guestPath": payload.guest_path,
                    "sizeBytes": payload.size,
                    "sha256": payload.sha256,
                    "overwrite": payload.overwrite,
                });
                operations
                    .complete(&operation.id, "succeeded", Some(&result.to_string()), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            Some((reason, detail)) => {
                Self::fail(operations, operation, reason, detail, extra).await
            }
        }
    }

    async fn collect(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let Some(store) = &self.store else {
            return Self::fail(
                operations,
                operation,
                "collect_unavailable",
                "the controller has no artifact directory",
                serde_json::json!({}),
            )
            .await;
        };
        let value: serde_json::Value = operation
            .payload_json
            .as_deref()
            .and_then(|payload| serde_json::from_str(payload).ok())
            .unwrap_or_default();
        let paths: Vec<String> = serde_json::from_value(value["paths"].clone()).unwrap_or_default();
        let owner = value["owner"].as_str().unwrap_or("unknown").to_owned();
        let guest_os = match payload_guest_os(operation) {
            Ok(os) => os,
            Err(detail) => {
                return Self::fail(
                    operations,
                    operation,
                    "invalid_payload",
                    &detail,
                    serde_json::json!({}),
                )
                .await;
            }
        };
        let target = match connection(&value) {
            Ok(target) => target,
            Err(detail) => {
                return Self::fail(
                    operations,
                    operation,
                    "invalid_payload",
                    &detail,
                    serde_json::json!({}),
                )
                .await;
            }
        };
        let extra = serde_json::json!({ "machineId": target.machine_id });
        if let Err(detail) = validate_collect_paths_for(guest_os, &paths) {
            return Self::fail(operations, operation, "invalid_paths", &detail, extra).await;
        }
        // Expired files go with each collection: no separate timer owns them.
        if let Err(error) = self
            .access
            .sweep_expired_files(fleet_core::SystemClock::now_unix_millis())
            .await
        {
            eprintln!("machine files: the retention pass failed: {error}");
        }
        let started = std::time::Instant::now();
        let total = i64::try_from(paths.len()).unwrap_or(i64::MAX);
        let mut collected = Vec::new();
        let mut failures: Vec<(String, &'static str)> = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            if let Err(error) = operations
                .record_progress(
                    &operation.id,
                    Some(i64::try_from(index).unwrap_or(i64::MAX)),
                    Some(total),
                    Some(&format!("copying {} of {total}", index + 1)),
                )
                .await
            {
                eprintln!(
                    "machine collect: progress of {} not recorded: {error}",
                    operation.id
                );
            }
            let remaining = COLLECT_DEADLINE.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                failures.push((path.clone(), "deadline_exceeded"));
                continue;
            }
            match self
                .collect_one(
                    store,
                    &target,
                    &owner,
                    &operation.id,
                    guest_os,
                    path,
                    remaining,
                )
                .await
            {
                Ok(file) => collected.push(serde_json::json!({
                    "path": path,
                    "fileId": file.id,
                    "sizeBytes": file.size_bytes,
                    "sha256": file.sha256,
                })),
                Err(reason) => failures.push((path.clone(), reason)),
            }
        }
        if failures.is_empty() {
            let result = serde_json::json!({
                "machineId": target.machine_id,
                "files": collected,
            });
            return operations
                .complete(&operation.id, "succeeded", Some(&result.to_string()), None)
                .await
                .map(|_| ())
                .map_err(|error| error.to_string());
        }
        let detail = format!(
            "{} of {} paths were not collected: {}",
            failures.len(),
            paths.len(),
            failures
                .iter()
                .map(|(path, reason)| format!("{path} ({reason})"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let reason = if collected.is_empty() {
            "collection_failed"
        } else {
            "collection_partial"
        };
        Self::fail(
            operations,
            operation,
            reason,
            &detail,
            serde_json::json!({
                "machineId": target.machine_id,
                "files": collected,
                "failures": failures
                    .iter()
                    .map(|(path, reason)| serde_json::json!({ "path": path, "reason": reason }))
                    .collect::<Vec<_>>(),
            }),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn collect_one(
        &self,
        store: &FsArtifactStore,
        target: &Connection,
        owner: &str,
        operation_id: &str,
        guest_os: fleet_core::GuestOs,
        path: &str,
        remaining: Duration,
    ) -> Result<fleet_application::machine_access::MachineFile, &'static str> {
        let staging = store.stage().map_err(|error| {
            eprintln!("machine collect: cannot stage a collected file: {error}");
            "store_failed"
        })?;
        let (outcome, staging) = self
            .files
            .fetch_with_auth(
                &target.machine_id,
                &target.endpoint_id,
                Some(&target.auth),
                guest_os,
                path,
                store.max_bytes(),
                remaining,
                staging,
            )
            .await;
        if let Some(reason) = fetch_failure(&outcome, &format!("machine {}", target.machine_id)) {
            // Dropping the staging handle removes the partial copy.
            drop(staging);
            return Err(reason);
        }
        let staged = store.finish(staging).map_err(|error| match error {
            fleet_application::lab_artifacts::BlobError::TooLarge { .. } => "too_large",
            _ => "store_failed",
        })?;
        self.access
            .record_file(
                &target.machine_id,
                owner,
                operation_id,
                path,
                &staged,
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await
            .map_err(|error| {
                eprintln!("machine collect: a collected file was not recorded: {error}");
                "store_failed"
            })
    }
}

#[async_trait]
impl OperationExecutor for MachineAccessDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "machine.exec" => self.exec(operations, operation).await,
            "machine.put" => self.put(operations, operation).await,
            "machine.collect" => self.collect(operations, operation).await,
            _ => self.inner.execute(operations, operation).await,
        }
    }
}
