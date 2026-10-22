//! Agent access to Fleet machines over SSH with Fleet-held keys (ADR 0017,
//! issue #493).
//!
//! The controller holds the credential and runs the session: a caller asks
//! for a command, a file put, or a file collect, and never receives the key.
//! This module owns the business rules and nothing that reaches a machine:
//!
//! - [`EndpointAuth`], how an SSH endpoint authenticates, including a
//!   Fleet-held secret reference, and the per-endpoint default
//!   ([`MachineAccess::set_default_auth`], the API #489 calls when it
//!   switches an endpoint to a key it generated).
//! - [`MachineAccess::request_exec`], [`MachineAccess::begin_upload`] /
//!   [`MachineAccess::request_put`] and [`MachineAccess::request_collect`],
//!   which authorize against the machine, validate the request, record an
//!   audit event that carries a command digest and never the command, and
//!   answer the durable operation to queue.
//! - Collected files: [`MachineFile`] records over the shared
//!   content-addressed blob store, listed and downloaded behind
//!   `machines.collect`.
//!
//! Every ports here is an adapter boundary: the controller supplies the
//! secret-backed key store and the SSH executors.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::audit::{AuditIntent, AuditMetadata};
use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::lab::LabUseCaseError;
use crate::lab_artifacts::{
    ArtifactBlobPort, ArtifactPolicy, ArtifactReader, BlobError, StagedBlob, StoredBlob,
    is_sha256_hex, validate_collect_paths_for, validate_guest_path_for,
};
use crate::lab_put::{StagedUpload, UploadStagePort, UploadWriter};
use crate::machine::{Machine, MachinePort};
use crate::operation::{AuditPort, NewOperation, PortFailure};
use fleet_core::{EndpointKind, GuestOs};

/// The most bytes of command a machine exec accepts (script text, or the
/// arguments of an argv command together).
pub const MAX_MACHINE_EXEC_BYTES: usize = crate::lab::MAX_LAB_EXEC_SCRIPT_BYTES;
/// The most arguments of an argv command.
pub const MAX_MACHINE_EXEC_ARGS: usize = 256;
/// The longest a machine exec may run (the SSH exec bound).
pub const MAX_MACHINE_EXEC_TIMEOUT_SECONDS: u64 = crate::lab::MAX_LAB_EXEC_TIMEOUT_SECONDS;
/// The deadline of an exec that names none.
pub const DEFAULT_MACHINE_EXEC_TIMEOUT_SECONDS: u64 = 60;
/// The longest a secret reference or identity-file path may be.
const MAX_REFERENCE_BYTES: usize = 1024;

/// The POSIX script that runs the caller's argv: the arguments reach the
/// script as `$@`, so no caller text is ever parsed by a shell.
pub const POSIX_ARGV_SCRIPT: &str = "exec \"$@\"\n";
/// The PowerShell script that runs the caller's argv from `$args` (ADR
/// 0015's shell layer supplies the arguments), mapping the native exit code
/// the way the layer already does. Windows PowerShell 5.1 builds a native
/// command's line from the argument array itself and does not escape
/// embedded double quotes, so an argument containing `"` may reach the
/// program split or merged differently than given; use `--script` (and the
/// program's own quoting) for such arguments.
pub const POWERSHELL_ARGV_SCRIPT: &str = "$fleetCmd=$args[0];$fleetRest=@();if($args.Count -gt 1){$fleetRest=@($args[1..($args.Count-1)])};& $fleetCmd @fleetRest\n";

/// How an SSH endpoint authenticates. The wire shape is the `auth` object
/// every SSH-driven operation payload already carries.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum EndpointAuth {
    /// The controller's SSH agent and default key files.
    Agent,
    /// A specific identity file on the controller, by path.
    #[serde(rename_all = "camelCase")]
    IdentityFile {
        /// The identity file's path; the path is not secret.
        path: String,
    },
    /// A private key Fleet holds as an encrypted secret, by reference. The
    /// controller resolves it just in time; the key is never returned.
    #[serde(rename_all = "camelCase")]
    Secret {
        /// The secret-record reference (the opaque id a key store returned).
        credential: String,
    },
}

impl EndpointAuth {
    /// The stable kind id: `agent`, `identity-file`, or `secret`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::IdentityFile { .. } => "identity-file",
            Self::Secret { .. } => "secret",
        }
    }

    /// Checks the shape of the reference, not its existence.
    ///
    /// # Errors
    ///
    /// Answers which rule it broke.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Agent => Ok(()),
            Self::IdentityFile { path } => {
                if path.is_empty()
                    || path.len() > MAX_REFERENCE_BYTES
                    || path.chars().any(char::is_control)
                {
                    Err("the identity file path must be 1 to 1024 characters without control characters".to_owned())
                } else {
                    Ok(())
                }
            }
            Self::Secret { credential } => {
                if credential.is_empty()
                    || credential.len() > 128
                    || !credential
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
                {
                    Err("the credential reference must be 1 to 128 characters of letters, digits, `-`, `_`, `.` or `/`".to_owned())
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// Where an endpoint's default authentication is recorded.
#[async_trait]
pub trait EndpointAuthPort: fmt::Debug + Send + Sync {
    /// The endpoint's default auth, when one is recorded.
    ///
    /// # Errors
    ///
    /// Fails with a secret-free detail when the backend errors.
    async fn get(&self, endpoint_id: &str) -> Result<Option<EndpointAuth>, String>;

    /// Records (or, with `None`, clears) the endpoint's default auth.
    ///
    /// # Errors
    ///
    /// Fails with a secret-free detail when the endpoint is unknown or the
    /// backend errors.
    async fn set(&self, endpoint_id: &str, auth: Option<&EndpointAuth>) -> Result<(), String>;
}

/// The controller-held SSH private keys, addressed by opaque reference.
/// Only records created through this port (or the Git credential records it
/// documents) resolve: a reference can never reach another integration's
/// secret.
#[async_trait]
pub trait MachineKeyPort: fmt::Debug + Send + Sync {
    /// Stores a private key and returns its new reference.
    ///
    /// # Errors
    ///
    /// Fails with a secret-free detail when the value is not a usable key or
    /// the store errors.
    async fn create(&self, private_key: &str, machine_id: Option<&str>) -> Result<String, String>;

    /// Whether the reference names a live, usable key.
    ///
    /// # Errors
    ///
    /// Fails with a secret-free detail when the store errors.
    async fn exists(&self, reference: &str, machine_id: &str) -> Result<bool, String>;

    /// Refuses an identity-file path the controller must never offer to
    /// `ssh` (its own key directory and master key). The default accepts.
    ///
    /// # Errors
    ///
    /// Answers why the path is refused.
    fn check_identity_path(&self, _path: &str) -> Result<(), String> {
        Ok(())
    }

    /// Resolves a reference to the key text just in time. `None` means the
    /// reference is missing or revoked.
    ///
    /// # Errors
    ///
    /// Fails with a secret-free detail when the store errors.
    async fn resolve(&self, reference: &str, machine_id: &str) -> Result<Option<String>, String>;
}

/// What to run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecCommand {
    /// A program and its arguments, passed to the guest as data.
    Argv(Vec<String>),
    /// Script text for the guest's shell, sent untouched.
    Script(String),
}

/// The machine an exec, put or collect names, and how to reach it.
#[derive(Clone, Debug, Default)]
pub struct AccessTarget<'a> {
    /// The machine.
    pub machine_id: &'a str,
    /// The SSH endpoint; absent means the machine's only SSH endpoint.
    pub endpoint_id: Option<&'a str>,
    /// An explicit auth, overriding the endpoint's default.
    pub auth: Option<&'a EndpointAuth>,
    /// The guest's OS, which selects the shell and the path rules.
    pub guest_os: GuestOs,
}

/// A machine exec request.
#[derive(Clone, Debug)]
pub struct ExecRequest<'a> {
    /// The target.
    pub target: AccessTarget<'a>,
    /// What to run.
    pub command: ExecCommand,
    /// The deadline in seconds; absent means the default.
    pub timeout_seconds: Option<u64>,
    /// A caller-chosen key making a retry return the queued operation.
    pub idempotency_key: Option<&'a str>,
}

/// Where a put lands.
#[derive(Clone, Debug)]
pub struct PutRequestTarget<'a> {
    /// The machine and endpoint.
    pub target: AccessTarget<'a>,
    /// The absolute guest path of the file to create.
    pub guest_path: &'a str,
    /// Whether an existing regular file may be replaced.
    pub overwrite: bool,
}

/// One collected file's record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineFile {
    /// The record's identity.
    pub id: String,
    /// The machine it came from.
    pub machine_id: String,
    /// The principal that asked for the collection.
    pub owner: String,
    /// The guest path it was collected from.
    pub name: String,
    /// Its size in bytes.
    pub size_bytes: u64,
    /// The lowercase hex SHA-256 of its bytes.
    pub sha256: String,
    /// Where its bytes live, relative to the artifact store's root.
    pub location: String,
    /// The `machine.collect` operation that produced it.
    pub operation_id: Option<String>,
    /// When it was stored (epoch milliseconds).
    pub created_at: i64,
    /// When the retention pass deletes it (epoch milliseconds).
    pub retain_until: i64,
}

/// A file to record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewMachineFile {
    /// The machine it came from.
    pub machine_id: String,
    /// The principal that asked for the collection.
    pub owner: String,
    /// The guest path.
    pub name: String,
    /// Its stored bytes.
    pub blob: StoredBlob,
    /// The operation that produced it.
    pub operation_id: Option<String>,
    /// When it was stored.
    pub created_at: i64,
    /// When the retention pass deletes it.
    pub retain_until: i64,
}

/// Collected-file metadata persistence.
#[async_trait]
pub trait MachineFilePort: fmt::Debug + Send + Sync {
    /// Records a file.
    ///
    /// # Errors
    ///
    /// Fails with a secret-free detail when the backend errors.
    async fn insert(&self, new: &NewMachineFile) -> Result<MachineFile, String>;
    /// Reads one record.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn get(&self, id: &str) -> Result<Option<MachineFile>, String>;
    /// A machine's records, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list(&self, machine_id: &str, limit: u32) -> Result<Vec<MachineFile>, String>;
    /// Records whose retention deadline is at or before `now`.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn expired(&self, now: i64, limit: u32) -> Result<Vec<MachineFile>, String>;
    /// Deletes a record; `false` means it was already gone.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn delete(&self, id: &str) -> Result<bool, String>;
    /// How many records, here or among Lab artifacts, still point at the
    /// blob location. Deduplication means a blob is deleted only at zero.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn location_references(&self, location: &str) -> Result<u64, String>;
}

/// The machine access use cases.
#[derive(Debug)]
pub struct MachineAccess {
    machines: Arc<dyn MachinePort>,
    auths: Arc<dyn EndpointAuthPort>,
    keys: Option<Arc<dyn MachineKeyPort>>,
    audit: Arc<dyn AuditPort>,
    stage: Option<Arc<dyn UploadStagePort>>,
    files: Option<Arc<dyn MachineFilePort>>,
    blobs: Option<Arc<dyn ArtifactBlobPort>>,
    policy: ArtifactPolicy,
    blob_lock: Arc<tokio::sync::Mutex<()>>,
}

impl MachineAccess {
    /// Composes the use cases over the machine records and default-auth
    /// storage. Keys, upload staging and collected files are optional
    /// capabilities of the controller.
    #[must_use]
    pub fn new(
        machines: Arc<dyn MachinePort>,
        auths: Arc<dyn EndpointAuthPort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            machines,
            auths,
            keys: None,
            audit,
            stage: None,
            files: None,
            blobs: None,
            policy: ArtifactPolicy::default(),
            blob_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Serves stored-key authentication from a key store.
    #[must_use]
    pub fn with_keys(mut self, keys: Arc<dyn MachineKeyPort>) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Serves `machines put` from the shared upload staging area.
    #[must_use]
    pub fn with_uploads(mut self, stage: Arc<dyn UploadStagePort>) -> Self {
        self.stage = Some(stage);
        self
    }

    /// Serves `machines collect` and the collected-file reads.
    #[must_use]
    pub fn with_files(
        mut self,
        files: Arc<dyn MachineFilePort>,
        blobs: Arc<dyn ArtifactBlobPort>,
        policy: ArtifactPolicy,
    ) -> Self {
        self.files = Some(files);
        self.blobs = Some(blobs);
        self.policy = policy;
        self
    }

    /// Shares the blob lock with the Lab artifact use cases, so a commit
    /// here and a retention delete there never interleave on the same
    /// content-addressed blob.
    #[must_use]
    pub fn with_blob_lock(mut self, lock: Arc<tokio::sync::Mutex<()>>) -> Self {
        self.blob_lock = lock;
        self
    }

    /// Whether a key store is wired.
    #[must_use]
    pub fn has_keys(&self) -> bool {
        self.keys.is_some()
    }

    /// Whether file puts are wired.
    #[must_use]
    pub fn has_uploads(&self) -> bool {
        self.stage.is_some()
    }

    /// Whether collected files are wired.
    #[must_use]
    pub fn has_files(&self) -> bool {
        self.files.is_some()
    }

    /// The cap on one upload, in bytes, when puts are wired.
    #[must_use]
    pub fn max_upload_bytes(&self) -> Option<u64> {
        self.stage.as_ref().map(|stage| stage.max_bytes())
    }

    /// Stores a private key for stored-key authentication and answers its
    /// reference. The value is never echoed or recorded.
    ///
    /// # Errors
    ///
    /// Fails on denial, a value that is not a usable unencrypted private
    /// key, or when no key store is wired.
    pub async fn store_key(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        private_key: &str,
        machine_id: Option<&str>,
    ) -> Result<String, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::SecretWrite,
                resource: None,
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        if let Some(machine_id) = machine_id {
            // A key bound to a machine is usable only there; the machine
            // must exist and the caller must be allowed to change it.
            authorize(
                authorizer,
                AccessRequest {
                    principal_id: &principal.id,
                    action: Permission::MachineUpdate,
                    resource: Some(machine_id),
                },
            )
            .map_err(LabUseCaseError::Denied)?;
            self.machine(machine_id).await?;
        }
        let keys = self.keys_port()?;
        let reference = keys
            .create(private_key, machine_id)
            .await
            .map_err(|detail| LabUseCaseError::Invalid { detail })?;
        // The event names the new opaque reference, which exists only now.
        self.audit_event(
            principal,
            Permission::SecretWrite,
            machine_id,
            "machine_ssh_key_stored",
            &[("credentialRef", reference.clone())],
        )
        .await?;
        Ok(reference)
    }

    /// An endpoint's recorded default auth.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown machine, or an endpoint that is not one of
    /// the machine's SSH endpoints.
    pub async fn default_auth(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
        endpoint_id: &str,
    ) -> Result<Option<EndpointAuth>, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineRead,
                resource: Some(machine_id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let machine = self.machine(machine_id).await?;
        ssh_endpoint(&machine, endpoint_id)?;
        self.auths.get(endpoint_id).await.map_err(backend)
    }

    /// Records, or with `None` clears, an SSH endpoint's default auth, so
    /// callers need not repeat it. A secret reference must name a key the
    /// store holds. This is the API #489 calls when it switches an endpoint
    /// to the key it generated.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown machine, an endpoint that is not one of
    /// the machine's SSH endpoints, a malformed reference, or a secret that
    /// does not exist.
    pub async fn set_default_auth(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
        endpoint_id: &str,
        auth: Option<&EndpointAuth>,
    ) -> Result<(), LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineUpdate,
                resource: Some(machine_id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let machine = self.machine(machine_id).await?;
        ssh_endpoint(&machine, endpoint_id)?;
        if let Some(auth) = auth {
            auth.validate()
                .map_err(|detail| LabUseCaseError::Invalid { detail })?;
            self.require_key(auth, machine_id).await?;
        }
        // The intent records the kind and the opaque reference, never a key.
        let mut facts = vec![
            ("endpointId", endpoint_id.to_owned()),
            (
                "authKind",
                auth.map_or("none", EndpointAuth::kind).to_owned(),
            ),
        ];
        if let Some(EndpointAuth::Secret { credential }) = auth {
            facts.push(("credentialRef", credential.clone()));
        }
        self.audit_event(
            principal,
            Permission::MachineUpdate,
            Some(machine_id),
            "machine_endpoint_auth_set",
            &facts,
        )
        .await?;
        self.auths.set(endpoint_id, auth).await.map_err(backend)
    }

    /// Validates a machine exec and answers the `machine.exec` operation to
    /// queue. The audit event records the machine, endpoint, auth kind,
    /// timeout, and the SHA-256 of the command, never the command: it may
    /// carry secrets.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown machine or endpoint, an endpoint whose
    /// host key was never confirmed, no usable auth, a missing secret, or an
    /// invalid command or timeout.
    pub async fn request_exec(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        request: &ExecRequest<'_>,
    ) -> Result<NewOperation, LabUseCaseError> {
        let machine_id = request.target.machine_id;
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineExec,
                resource: Some(machine_id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let timeout = request
            .timeout_seconds
            .unwrap_or(DEFAULT_MACHINE_EXEC_TIMEOUT_SECONDS);
        if timeout == 0 || timeout > MAX_MACHINE_EXEC_TIMEOUT_SECONDS {
            return Err(LabUseCaseError::Invalid {
                detail: format!("timeoutSeconds must be 1..={MAX_MACHINE_EXEC_TIMEOUT_SECONDS}"),
            });
        }
        let (script, arguments, digest) =
            prepare_command(&request.command, request.target.guest_os)?;
        let (endpoint_id, auth) = self
            .resolve_target(authorizer, principal, &request.target)
            .await?;
        let facts = [
            ("endpointId", endpoint_id.clone()),
            ("authKind", auth.kind().to_owned()),
            ("commandSha256", digest.clone()),
            ("timeoutSeconds", timeout.to_string()),
            ("guestOs", request.target.guest_os.id().to_owned()),
        ];
        self.audit_event(
            principal,
            Permission::MachineExec,
            Some(machine_id),
            "machine_exec_requested",
            &facts,
        )
        .await?;
        Ok(NewOperation {
            kind: "machine.exec".to_owned(),
            idempotency_key: request.idempotency_key.map(|key| {
                crate::idempotency::scoped_key(
                    "machine-exec",
                    &principal.id,
                    &[machine_id, &digest, key],
                )
            }),
            deadline_at: None,
            correlation_id: None,
            // The payload is the `ssh.exec` shape plus the digest: the
            // executor hands it to the SSH executor unchanged. It carries
            // the secret *reference*, never a key.
            payload_json: Some(
                serde_json::json!({
                    "machineId": machine_id,
                    "endpointId": endpoint_id,
                    "auth": auth,
                    "script": script,
                    "arguments": arguments,
                    "guestOs": request.target.guest_os.id(),
                    "timeoutSeconds": timeout,
                    "commandSha256": digest,
                })
                .to_string(),
            ),
            review_token: None,
        })
    }

    /// Checks the caller, the path and the target, then opens a staging
    /// file. Nothing is accepted from an unauthorized caller or for a
    /// machine that cannot take the file.
    ///
    /// # Errors
    ///
    /// Fails on denial, an invalid path, an unusable target, or a staging
    /// failure.
    pub async fn begin_upload(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        request: &PutRequestTarget<'_>,
    ) -> Result<Box<dyn UploadWriter>, LabUseCaseError> {
        self.check_put(authorizer, principal, request).await?;
        let stage = self.stage_port()?;
        stage.begin().await.map_err(|error| match error {
            BlobError::TooLarge { .. } => LabUseCaseError::Invalid {
                detail: error.to_string(),
            },
            BlobError::Busy { detail } => LabUseCaseError::Busy { detail },
            other => backend(other.to_string()),
        })
    }

    /// Validates a finished upload and answers the `machine.put` operation
    /// to queue, after recording the audit intent. The staged file is
    /// discarded when this refuses.
    ///
    /// # Errors
    ///
    /// Fails on denial, an invalid path or digest, an upload over the cap,
    /// an unusable target, or a backend failure.
    pub async fn request_put(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        request: &PutRequestTarget<'_>,
        staged: &StagedUpload,
    ) -> Result<NewOperation, LabUseCaseError> {
        let queued = self
            .request_put_inner(authorizer, principal, request, staged)
            .await;
        if queued.is_err() {
            self.discard_upload(&staged.id).await;
        }
        queued
    }

    /// Discards a staged upload that will not be queued.
    pub async fn discard_upload(&self, id: &str) {
        if let Some(stage) = &self.stage {
            stage.discard(id).await;
        }
    }

    async fn request_put_inner(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        request: &PutRequestTarget<'_>,
        staged: &StagedUpload,
    ) -> Result<NewOperation, LabUseCaseError> {
        let (endpoint_id, auth) = self.check_put(authorizer, principal, request).await?;
        let stage = self.stage_port()?;
        if !is_sha256_hex(&staged.sha256) {
            return Err(LabUseCaseError::Invalid {
                detail: "the upload's SHA-256 is not a lowercase hex digest".to_owned(),
            });
        }
        if staged.size_bytes > stage.max_bytes() {
            return Err(LabUseCaseError::Invalid {
                detail: BlobError::TooLarge {
                    max_bytes: stage.max_bytes(),
                }
                .to_string(),
            });
        }
        let machine_id = request.target.machine_id;
        self.audit_event(
            principal,
            Permission::MachinePut,
            Some(machine_id),
            "machine_put_requested",
            &[
                ("endpointId", endpoint_id.clone()),
                ("authKind", auth.kind().to_owned()),
                ("guestPath", request.guest_path.to_owned()),
                ("sizeBytes", staged.size_bytes.to_string()),
                ("sha256", staged.sha256.clone()),
                ("overwrite", request.overwrite.to_string()),
            ],
        )
        .await?;
        Ok(NewOperation {
            kind: "machine.put".to_owned(),
            idempotency_key: None,
            deadline_at: None,
            correlation_id: None,
            payload_json: Some(
                serde_json::json!({
                    "machineId": machine_id,
                    "endpointId": endpoint_id,
                    "auth": auth,
                    "guestPath": request.guest_path,
                    "uploadId": staged.id,
                    "sizeBytes": staged.size_bytes,
                    "sha256": staged.sha256,
                    "overwrite": request.overwrite,
                    "guestOs": request.target.guest_os.id(),
                })
                .to_string(),
            ),
            review_token: None,
        })
    }

    async fn check_put(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        request: &PutRequestTarget<'_>,
    ) -> Result<(String, EndpointAuth), LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachinePut,
                resource: Some(request.target.machine_id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        self.stage_port()?;
        validate_guest_path_for(request.target.guest_os, request.guest_path).map_err(|detail| {
            LabUseCaseError::Invalid {
                detail: format!("guest path: {detail}"),
            }
        })?;
        self.resolve_target(authorizer, principal, &request.target)
            .await
    }

    /// Validates a collection of guest paths and answers the
    /// `machine.collect` operation to queue.
    ///
    /// # Errors
    ///
    /// Fails on denial, invalid paths, an unusable target, or when collected
    /// files are not wired.
    pub async fn request_collect(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        target: &AccessTarget<'_>,
        paths: &[String],
    ) -> Result<NewOperation, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineCollect,
                resource: Some(target.machine_id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        self.files_port()?;
        validate_collect_paths_for(target.guest_os, paths)
            .map_err(|detail| LabUseCaseError::Invalid { detail })?;
        let (endpoint_id, auth) = self.resolve_target(authorizer, principal, target).await?;
        self.audit_event(
            principal,
            Permission::MachineCollect,
            Some(target.machine_id),
            "machine_collect_requested",
            &[
                ("endpointId", endpoint_id.clone()),
                ("authKind", auth.kind().to_owned()),
                ("paths", paths.len().to_string()),
            ],
        )
        .await?;
        Ok(NewOperation {
            kind: "machine.collect".to_owned(),
            idempotency_key: None,
            deadline_at: None,
            correlation_id: None,
            payload_json: Some(
                serde_json::json!({
                    "machineId": target.machine_id,
                    "endpointId": endpoint_id,
                    "auth": auth,
                    "paths": paths,
                    "guestOs": target.guest_os.id(),
                    "owner": principal.id,
                })
                .to_string(),
            ),
            review_token: None,
        })
    }

    /// Lists the files collected from a machine, newest first.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list_files(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
        limit: u32,
    ) -> Result<Vec<MachineFile>, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineCollect,
                resource: Some(machine_id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        self.files_port()?
            .list(machine_id, limit.clamp(1, 500))
            .await
            .map_err(backend)
    }

    /// Reads one collected file's metadata.
    ///
    /// # Errors
    ///
    /// Fails on denial or an unknown file.
    pub async fn get_file(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<MachineFile, LabUseCaseError> {
        let file = self
            .files_port()?
            .get(id)
            .await
            .map_err(backend)?
            .ok_or_else(|| LabUseCaseError::NotFound {
                what: format!("collected file {id}"),
            })?;
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineCollect,
                resource: Some(&file.machine_id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        Ok(file)
    }

    /// Opens a collected file's bytes for download, after the store verified
    /// them against the recorded size and SHA-256. Needs `machines.collect`
    /// on the file's machine and records an audit event: a collected file
    /// can be sensitive.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown file, or bytes that are missing or no
    /// longer match their digest (a conflict, never served).
    pub async fn open_file(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<(MachineFile, ArtifactReader), LabUseCaseError> {
        let files = self.files_port()?;
        let file =
            files
                .get(id)
                .await
                .map_err(backend)?
                .ok_or_else(|| LabUseCaseError::NotFound {
                    what: format!("collected file {id}"),
                })?;
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineCollect,
                resource: Some(&file.machine_id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        self.audit_event(
            principal,
            Permission::MachineCollect,
            Some(&file.machine_id),
            "machine_file_downloaded",
            &[("fileId", file.id.clone()), ("sha256", file.sha256.clone())],
        )
        .await?;
        let blobs = self.blobs.as_ref().ok_or_else(unwired_files)?;
        let reader = blobs
            .open(&file.location, &file.sha256, file.size_bytes)
            .await
            .map_err(|error| match error {
                BlobError::Corrupt { .. } | BlobError::Missing | BlobError::InvalidLocation => {
                    LabUseCaseError::Conflict {
                        detail: format!("collected file {id}: {error}"),
                    }
                }
                other => backend(other.to_string()),
            })?;
        Ok((file, reader))
    }

    /// Commits one collected file's staged bytes and records it. Called by
    /// the collect executor, which is a system actor, so no authorization
    /// applies here; the request that queued it was authorized. The staged
    /// bytes are discarded on any failure.
    ///
    /// The blob store is content-addressed and shared with Lab artifacts, so
    /// a blob a Lab sweep removes between this commit and the insert would
    /// leave a record whose download reports a missing blob (a conflict,
    /// never wrong bytes).
    ///
    /// # Errors
    ///
    /// Fails when the file is over the size cap or cannot be stored.
    pub async fn record_file(
        &self,
        machine_id: &str,
        owner: &str,
        operation_id: &str,
        path: &str,
        staged: &StagedBlob,
        now: i64,
    ) -> Result<MachineFile, LabUseCaseError> {
        let recorded = async {
            let files = self.files_port()?;
            let blobs = self.blobs.as_ref().ok_or_else(unwired_files)?;
            if staged.size_bytes > self.policy.max_bytes {
                return Err(LabUseCaseError::Invalid {
                    detail: BlobError::TooLarge {
                        max_bytes: self.policy.max_bytes,
                    }
                    .to_string(),
                });
            }
            let _guard = self.blob_lock.lock().await;
            let blob = blobs.commit(staged).await.map_err(|error| match error {
                BlobError::TooLarge { .. } => LabUseCaseError::Invalid {
                    detail: error.to_string(),
                },
                other => backend(other.to_string()),
            })?;
            files
                .insert(&NewMachineFile {
                    machine_id: machine_id.to_owned(),
                    owner: owner.to_owned(),
                    name: path.to_owned(),
                    blob,
                    operation_id: Some(operation_id.to_owned()),
                    created_at: now,
                    retain_until: self.policy.retain_until(now),
                })
                .await
                .map_err(backend)
        }
        .await;
        if recorded.is_err()
            && let Some(blobs) = &self.blobs
        {
            blobs.discard(staged).await;
        }
        recorded
    }

    /// Deletes collected files past their retention and their bytes once no
    /// record (here or among Lab artifacts) points at them. Returns how many
    /// records were deleted.
    ///
    /// # Errors
    ///
    /// Fails when the expired set cannot be read.
    pub async fn sweep_expired_files(&self, now: i64) -> Result<usize, LabUseCaseError> {
        let files = self.files_port()?;
        let blobs = self.blobs.as_ref().ok_or_else(unwired_files)?;
        let mut deleted = 0;
        for file in files.expired(now, 100).await.map_err(backend)? {
            let _guard = self.blob_lock.lock().await;
            if !files.delete(&file.id).await.map_err(backend)? {
                continue;
            }
            deleted += 1;
            let remaining = files
                .location_references(&file.location)
                .await
                .map_err(backend)?;
            if remaining == 0
                && let Err(error) = blobs.remove(&file.location).await
            {
                eprintln!("machine files: cannot remove an expired blob: {error}");
            }
        }
        Ok(deleted)
    }

    /// The retention policy of collected files.
    #[must_use]
    pub fn policy(&self) -> ArtifactPolicy {
        self.policy
    }

    /// Picks the SSH endpoint and the auth to use: the endpoint the caller
    /// named (or the machine's only SSH endpoint), whose host key must be
    /// confirmed, and the caller's explicit auth or else the endpoint's
    /// recorded default. With neither there is no auth: the controller's own
    /// agent keys are not the machine's credential, so there is no implicit
    /// fall back.
    async fn resolve_target(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        target: &AccessTarget<'_>,
    ) -> Result<(String, EndpointAuth), LabUseCaseError> {
        // The endpoint's default is the credential an operator granted to
        // everyone who may run commands there. Naming another one (a stored
        // key, an identity file on the controller, the controller's agent)
        // chooses which credential the controller uses, so it needs the
        // right to change the machine.
        if target.auth.is_some() {
            authorize(
                authorizer,
                AccessRequest {
                    principal_id: &principal.id,
                    action: Permission::MachineUpdate,
                    resource: Some(target.machine_id),
                },
            )
            .map_err(LabUseCaseError::Denied)?;
        }
        let machine = self.machine(target.machine_id).await?;
        let endpoint_id = if let Some(id) = target.endpoint_id {
            ssh_endpoint(&machine, id)?.id.clone()
        } else {
            let mut ssh = machine
                .endpoints
                .iter()
                .filter(|endpoint| endpoint.kind == EndpointKind::Ssh);
            match (ssh.next(), ssh.next()) {
                (Some(only), None) => only.id.clone(),
                (None, _) => {
                    return Err(LabUseCaseError::Invalid {
                        detail: "the machine has no SSH endpoint".to_owned(),
                    });
                }
                (Some(_), Some(_)) => {
                    return Err(LabUseCaseError::Invalid {
                        detail: "the machine has several SSH endpoints; name one with endpointId"
                            .to_owned(),
                    });
                }
            }
        };
        let verified = self
            .machines
            .verified_fingerprint(&endpoint_id)
            .await
            .map_err(|failure| backend(failure.to_string()))?;
        if verified.is_none() {
            return Err(LabUseCaseError::Invalid {
                detail: "the endpoint's host key was never confirmed; run the trust workflow first"
                    .to_owned(),
            });
        }
        let auth = match target.auth {
            Some(auth) => auth.clone(),
            None => self
                .auths
                .get(&endpoint_id)
                .await
                .map_err(backend)?
                .ok_or_else(|| LabUseCaseError::Invalid {
                    detail: "the endpoint has no default auth; pass an explicit auth or record one (machines endpoint-auth set)".to_owned(),
                })?,
        };
        auth.validate()
            .map_err(|detail| LabUseCaseError::Invalid { detail })?;
        self.require_key(&auth, target.machine_id).await?;
        Ok((endpoint_id, auth))
    }

    /// A secret reference must resolve to a live key; other auth kinds have
    /// nothing to check here.
    async fn require_key(
        &self,
        auth: &EndpointAuth,
        machine_id: &str,
    ) -> Result<(), LabUseCaseError> {
        if let (EndpointAuth::IdentityFile { path }, Some(keys)) = (auth, &self.keys) {
            keys.check_identity_path(path)
                .map_err(|detail| LabUseCaseError::Invalid { detail })?;
        }
        let EndpointAuth::Secret { credential } = auth else {
            return Ok(());
        };
        let keys = self.keys_port()?;
        if keys.exists(credential, machine_id).await.map_err(backend)? {
            Ok(())
        } else {
            Err(LabUseCaseError::Invalid {
                detail:
                    "the credential reference does not name a stored SSH key usable on this machine"
                        .to_owned(),
            })
        }
    }

    async fn machine(&self, id: &str) -> Result<Machine, LabUseCaseError> {
        self.machines
            .get(id)
            .await
            .map_err(|failure| match failure {
                PortFailure::NotFound { what } => LabUseCaseError::NotFound { what },
                other => backend(other.to_string()),
            })
    }

    fn keys_port(&self) -> Result<&Arc<dyn MachineKeyPort>, LabUseCaseError> {
        self.keys.as_ref().ok_or_else(|| LabUseCaseError::Invalid {
            detail: "no SSH key store is available on this controller".to_owned(),
        })
    }

    fn stage_port(&self) -> Result<&Arc<dyn UploadStagePort>, LabUseCaseError> {
        self.stage.as_ref().ok_or_else(|| LabUseCaseError::Busy {
            detail: "file puts are not wired; the controller needs its artifact directory"
                .to_owned(),
        })
    }

    fn files_port(&self) -> Result<&Arc<dyn MachineFilePort>, LabUseCaseError> {
        self.files.as_ref().ok_or_else(unwired_files)
    }

    async fn audit_event(
        &self,
        principal: &ActingPrincipal,
        action: Permission,
        resource: Option<&str>,
        event: &str,
        facts: &[(&str, String)],
    ) -> Result<(), LabUseCaseError> {
        let audit_error = |error: crate::audit::MetadataError| LabUseCaseError::Backend {
            context: "audit",
            detail: error.to_string(),
        };
        let mut metadata = AuditMetadata::default();
        metadata.insert("event", event).map_err(audit_error)?;
        for (key, value) in facts {
            metadata.insert(key, value).map_err(audit_error)?;
        }
        self.audit
            .record_intent(&AuditIntent {
                actor: principal.id.clone(),
                action: action.id().to_owned(),
                resource: resource.map(str::to_owned),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "audit",
                detail,
            })
    }
}

/// The SSH endpoint `endpoint_id` of `machine`, or why it is not usable.
fn ssh_endpoint<'a>(
    machine: &'a Machine,
    endpoint_id: &str,
) -> Result<&'a crate::machine::Endpoint, LabUseCaseError> {
    let endpoint = machine
        .endpoints
        .iter()
        .find(|endpoint| endpoint.id == endpoint_id)
        .ok_or_else(|| LabUseCaseError::NotFound {
            what: format!("endpoint {endpoint_id} on machine {}", machine.id),
        })?;
    if endpoint.kind == EndpointKind::Ssh {
        Ok(endpoint)
    } else {
        Err(LabUseCaseError::Invalid {
            detail: format!(
                "the endpoint is {:?}, not an SSH endpoint",
                endpoint.kind.id()
            ),
        })
    }
}

/// Turns the command into the script and arguments the SSH executor runs,
/// and the SHA-256 recorded in the audit event.
fn prepare_command(
    command: &ExecCommand,
    guest_os: GuestOs,
) -> Result<(String, Vec<String>, String), LabUseCaseError> {
    let invalid = |detail: String| LabUseCaseError::Invalid { detail };
    match command {
        ExecCommand::Script(script) => {
            if script.trim().is_empty() || script.len() > MAX_MACHINE_EXEC_BYTES {
                return Err(invalid(format!(
                    "the command must be non-empty and at most {MAX_MACHINE_EXEC_BYTES} bytes"
                )));
            }
            if script.contains('\0') {
                return Err(invalid("the command contains a NUL byte".to_owned()));
            }
            Ok((script.clone(), Vec::new(), digest(&[script.as_bytes()])))
        }
        ExecCommand::Argv(argv) => {
            if argv.is_empty() || argv.len() > MAX_MACHINE_EXEC_ARGS {
                return Err(invalid(format!(
                    "a command has 1 to {MAX_MACHINE_EXEC_ARGS} arguments"
                )));
            }
            // An empty argument cannot ride the shell-inert metadata framing
            // (the guest side drops it), so it is refused instead of silently
            // changing the command.
            if argv.iter().any(String::is_empty) {
                return Err(invalid(
                    "an empty argument cannot be passed; use --script for it".to_owned(),
                ));
            }
            if argv.iter().any(|arg| arg.contains('\0')) {
                return Err(invalid("an argument contains a NUL byte".to_owned()));
            }
            if argv.iter().map(String::len).sum::<usize>() > MAX_MACHINE_EXEC_BYTES {
                return Err(invalid(format!(
                    "the arguments are longer than {MAX_MACHINE_EXEC_BYTES} bytes together"
                )));
            }
            let script = match guest_os {
                GuestOs::Linux => POSIX_ARGV_SCRIPT,
                GuestOs::Windows => POWERSHELL_ARGV_SCRIPT,
            };
            let mut parts: Vec<&[u8]> = Vec::new();
            for arg in argv {
                parts.push(arg.as_bytes());
            }
            Ok((script.to_owned(), argv.clone(), digest(&parts)))
        }
    }
}

/// SHA-256 over NUL-separated parts.
fn digest(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
        hasher.update([0_u8]);
    }
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        })
}

fn backend(detail: String) -> LabUseCaseError {
    LabUseCaseError::Backend {
        context: "machine access",
        detail,
    }
}

fn unwired_files() -> LabUseCaseError {
    LabUseCaseError::Busy {
        detail: "collected files are not wired; the controller needs its artifact directory"
            .to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_auth_has_the_payload_wire_shape() {
        assert_eq!(
            serde_json::to_value(EndpointAuth::Agent).unwrap(),
            serde_json::json!({ "type": "agent" })
        );
        assert_eq!(
            serde_json::to_value(EndpointAuth::IdentityFile {
                path: "/k".to_owned()
            })
            .unwrap(),
            serde_json::json!({ "type": "identityFile", "path": "/k" })
        );
        assert_eq!(
            serde_json::to_value(EndpointAuth::Secret {
                credential: "abc-1".to_owned()
            })
            .unwrap(),
            serde_json::json!({ "type": "secret", "credential": "abc-1" })
        );
        let parsed: EndpointAuth =
            serde_json::from_str(r#"{"type":"secret","credential":"abc-1"}"#).unwrap();
        assert_eq!(parsed.kind(), "secret");
        assert!(serde_json::from_str::<EndpointAuth>(r#"{"type":"password"}"#).is_err());
    }

    #[test]
    fn endpoint_auth_validation_refuses_malformed_references() {
        assert!(EndpointAuth::Agent.validate().is_ok());
        for bad in ["", "has space", "semi;colon", "new\nline", &"a".repeat(129)] {
            assert!(
                EndpointAuth::Secret {
                    credential: bad.to_owned()
                }
                .validate()
                .is_err(),
                "{bad:?}"
            );
        }
        assert!(
            EndpointAuth::Secret {
                credential: "01890f3e-9b4a-7cc2-98c3-d24e8f58f2a1".to_owned()
            }
            .validate()
            .is_ok()
        );
        assert!(
            EndpointAuth::IdentityFile {
                path: String::new()
            }
            .validate()
            .is_err()
        );
        assert!(
            EndpointAuth::IdentityFile {
                path: "/a\u{0}b".to_owned()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn an_argv_command_rides_as_arguments_and_is_digested() {
        let argv = ExecCommand::Argv(vec!["printf".to_owned(), "a b".to_owned()]);
        let (script, arguments, digest) = prepare_command(&argv, GuestOs::Linux).unwrap();
        assert_eq!(script, POSIX_ARGV_SCRIPT);
        assert_eq!(arguments, ["printf", "a b"]);
        assert_eq!(digest.len(), 64);
        let (windows, _, same) = prepare_command(&argv, GuestOs::Windows).unwrap();
        assert_eq!(windows, POWERSHELL_ARGV_SCRIPT);
        assert_eq!(same, digest, "the digest names the command, not the shell");
        // The NUL framing keeps ["ab", "c"] and ["a", "bc"] apart.
        let other = ExecCommand::Argv(vec!["a".to_owned(), "bc".to_owned()]);
        let split = ExecCommand::Argv(vec!["ab".to_owned(), "c".to_owned()]);
        assert_ne!(
            prepare_command(&other, GuestOs::Linux).unwrap().2,
            prepare_command(&split, GuestOs::Linux).unwrap().2
        );
    }

    #[test]
    fn the_windows_argv_script_is_fixed_text_and_carries_no_caller_data() {
        let hostile = ExecCommand::Argv(vec!["cmd.exe".to_owned(), "\"; calc \"$(x)".to_owned()]);
        let (script, arguments, _) = prepare_command(&hostile, GuestOs::Windows).unwrap();
        assert_eq!(script, POWERSHELL_ARGV_SCRIPT);
        assert!(!script.contains("calc"));
        assert_eq!(arguments[1], "\"; calc \"$(x)");
        // The script is one line of the safe alphabet the shell layer checks
        // its own text against: no quotes that could end a string early.
        assert!(!script.contains('"'));
    }

    #[test]
    fn commands_are_bounded_and_refuse_what_the_framing_cannot_carry() {
        let script =
            |text: &str| prepare_command(&ExecCommand::Script(text.to_owned()), GuestOs::Linux);
        assert!(script("echo ok").is_ok());
        assert!(script("   ").is_err());
        assert!(script("a\u{0}b").is_err());
        assert!(script(&"x".repeat(MAX_MACHINE_EXEC_BYTES + 1)).is_err());
        let argv = |words: Vec<&str>| {
            prepare_command(
                &ExecCommand::Argv(words.into_iter().map(str::to_owned).collect()),
                GuestOs::Linux,
            )
        };
        assert!(argv(vec![]).is_err());
        // An empty argument would be dropped by the guest-side framing.
        assert!(argv(vec!["ls", ""]).is_err());
        assert!(argv(vec!["ls", "a\u{0}b"]).is_err());
        assert!(
            prepare_command(
                &ExecCommand::Argv(vec!["x".to_owned(); MAX_MACHINE_EXEC_ARGS + 1]),
                GuestOs::Linux
            )
            .is_err()
        );
    }
}
