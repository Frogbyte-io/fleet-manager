//! Agent SSH access to Fleet machines (#493, ADR 0017): stored SSH keys, the
//! per-endpoint default auth, `exec`, `put` and `collect`, and the collected
//! files.
//!
//! The controller holds the key and runs the session. Nothing here returns
//! a private key: the key store answers a reference, an endpoint's auth is a
//! kind and a reference, and a command's output is scrubbed by the executor.
//! Every route is a thin adapter over [`MachineAccess`]; authorization,
//! validation and the audit event live in the use case.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{
    Extension, Json,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use fleet_application::lab::LabUseCaseError;
use fleet_application::lab_artifacts::is_sha256_hex;
use fleet_application::lab_put::StagedUpload;
use fleet_application::machine_access::{
    AccessTarget, EndpointAuth, ExecCommand, ExecRequest, MachineAccess, MachineFile,
    PutRequestTarget,
};
use fleet_core::{CorrelationId, ErrorCode, GuestOs, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};
use crate::lab::map_lab_error;
use crate::lab_put::{CONTENT_SHA256_HEADER, stream_upload, too_large};

/// How an SSH endpoint authenticates. A stored key is named by reference and
/// is never returned.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum EndpointAuthDto {
    /// The controller's SSH agent and default key files.
    Agent,
    /// An identity file on the controller, by path.
    #[serde(rename_all = "camelCase")]
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
    /// A private key Fleet holds as an encrypted secret, by reference.
    #[serde(rename_all = "camelCase")]
    Secret {
        /// The reference returned when the key was stored.
        credential: String,
    },
}

impl From<EndpointAuth> for EndpointAuthDto {
    fn from(auth: EndpointAuth) -> Self {
        match auth {
            EndpointAuth::Agent => Self::Agent,
            EndpointAuth::IdentityFile { path } => Self::IdentityFile { path },
            EndpointAuth::Secret { credential } => Self::Secret { credential },
        }
    }
}

impl From<EndpointAuthDto> for EndpointAuth {
    fn from(auth: EndpointAuthDto) -> Self {
        match auth {
            EndpointAuthDto::Agent => Self::Agent,
            EndpointAuthDto::IdentityFile { path } => Self::IdentityFile { path },
            EndpointAuthDto::Secret { credential } => Self::Secret { credential },
        }
    }
}

fn access_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<MachineAccess>, ApiErrorResponse> {
    state
        .lab
        .as_ref()
        .and_then(|lab| lab.machine_access().cloned())
        .ok_or_else(|| {
            let public = PublicError::new(
                ErrorCode::from_str("machine_unavailable")
                    .expect("the literal is valid error code syntax"),
                "machine access is not wired; the controller needs its database",
                RetryClass::Backoff,
            );
            ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
        })
}

fn parse_guest_os(
    text: Option<&str>,
    correlation_id: CorrelationId,
) -> Result<GuestOs, ApiErrorResponse> {
    match text {
        None => Ok(GuestOs::Linux),
        Some(id) => GuestOs::from_id(id).map_err(|_| {
            crate::machines::invalid_request("guestOs must be `linux` or `windows`", correlation_id)
        }),
    }
}

/// The body of `POST /machine-ssh-keys`.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoreSshKeyRequest {
    /// An unencrypted PEM or OpenSSH private key. It is stored in the
    /// encrypted secret store and never returned or recorded.
    pub private_key: String,
    /// Binds the key to one machine: it then resolves for that machine only.
    /// Absent, the key is unbound and usable on any machine by a caller who
    /// may change that machine's credentials.
    pub machine_id: Option<String>,
}

/// The reference of a stored SSH key.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoredSshKeyDto {
    /// The reference to use as `credential` in a `secret` endpoint auth.
    pub credential_ref: String,
}

/// Stores an SSH private key for stored-key authentication and returns its
/// reference. The key is never returned, logged, or recorded in an audit
/// event.
///
/// # Errors
///
/// Returns the public error envelope on refusal, a value that is not a
/// usable unencrypted private key, or when no secret store is configured.
#[utoipa::path(
    post,
    path = "/machine-ssh-keys",
    tag = "machines",
    operation_id = "storeMachineSshKey",
    request_body = StoreSshKeyRequest,
    responses(
        (status = 201, description = "The key is stored; the reference is the only thing returned.", body = Resource<StoredSshKeyDto>),
        (status = 400, description = "The value is not a usable unencrypted private key, or no secret store is configured.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not write secrets.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Machine access is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn store_machine_ssh_key(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    request: Result<Json<StoreSshKeyRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<StoredSshKeyDto>>), ApiErrorResponse> {
    let access = access_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        crate::machines::invalid_request(
            "the request body must be valid JSON with a privateKey",
            correlation_id,
        )
    })?;
    let credential_ref = access
        .store_key(
            state.authorizer.as_ref(),
            &principal,
            &request.private_key,
            request.machine_id.as_deref(),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok((
        StatusCode::CREATED,
        Json(Resource::new(StoredSshKeyDto { credential_ref })),
    ))
}

/// An endpoint's recorded default auth.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EndpointAuthStateDto {
    /// The default auth, or `null` when none is recorded.
    pub auth: Option<EndpointAuthDto>,
}

/// Reads an SSH endpoint's default auth.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown machine, or an
/// endpoint that is not one of the machine's SSH endpoints.
#[utoipa::path(
    get,
    path = "/machines/{machineId}/endpoints/{endpointId}/auth",
    tag = "machines",
    operation_id = "getMachineEndpointAuth",
    params(
        ("machineId" = String, Path, description = "The machine's identity."),
        ("endpointId" = String, Path, description = "The SSH endpoint's identity."),
    ),
    responses(
        (status = 200, description = "The endpoint's default auth.", body = Resource<EndpointAuthStateDto>),
        (status = 400, description = "The endpoint is not an SSH endpoint.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not read machines.", body = crate::error::ApiError),
        (status = 404, description = "The machine or endpoint does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Machine access is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn get_machine_endpoint_auth(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path((machine_id, endpoint_id)): Path<(String, String)>,
) -> Result<Json<Resource<EndpointAuthStateDto>>, ApiErrorResponse> {
    let access = access_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let auth = access
        .default_auth(
            state.authorizer.as_ref(),
            &principal,
            &machine_id,
            &endpoint_id,
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(Json(Resource::new(EndpointAuthStateDto {
        auth: auth.map(Into::into),
    })))
}

/// The body of `PUT /machines/{machineId}/endpoints/{endpointId}/auth`.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SetEndpointAuthRequest {
    /// The default auth to record.
    pub auth: EndpointAuthDto,
}

/// Records an SSH endpoint's default auth, so callers need not repeat it. A
/// `secret` reference must name a stored SSH key.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown machine or
/// endpoint, a malformed reference, or a secret that does not exist.
#[utoipa::path(
    put,
    path = "/machines/{machineId}/endpoints/{endpointId}/auth",
    tag = "machines",
    operation_id = "setMachineEndpointAuth",
    params(
        ("machineId" = String, Path, description = "The machine's identity."),
        ("endpointId" = String, Path, description = "The SSH endpoint's identity."),
    ),
    request_body = SetEndpointAuthRequest,
    responses(
        (status = 200, description = "The recorded default auth.", body = Resource<EndpointAuthStateDto>),
        (status = 400, description = "The endpoint is not an SSH endpoint, the reference is malformed, or the secret does not name a stored SSH key.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not update machines.", body = crate::error::ApiError),
        (status = 404, description = "The machine or endpoint does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Machine access is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn set_machine_endpoint_auth(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path((machine_id, endpoint_id)): Path<(String, String)>,
    request: Result<Json<SetEndpointAuthRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Resource<EndpointAuthStateDto>>, ApiErrorResponse> {
    let access = access_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        crate::machines::invalid_request(
            "the request body must be valid JSON with an auth object",
            correlation_id,
        )
    })?;
    let auth: EndpointAuth = request.auth.into();
    access
        .set_default_auth(
            state.authorizer.as_ref(),
            &principal,
            &machine_id,
            &endpoint_id,
            Some(&auth),
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(Json(Resource::new(EndpointAuthStateDto {
        auth: Some(auth.into()),
    })))
}

/// Clears an SSH endpoint's default auth.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown machine or
/// endpoint.
#[utoipa::path(
    delete,
    path = "/machines/{machineId}/endpoints/{endpointId}/auth",
    tag = "machines",
    operation_id = "clearMachineEndpointAuth",
    params(
        ("machineId" = String, Path, description = "The machine's identity."),
        ("endpointId" = String, Path, description = "The SSH endpoint's identity."),
    ),
    responses(
        (status = 200, description = "The endpoint now has no default auth.", body = Resource<EndpointAuthStateDto>),
        (status = 400, description = "The endpoint is not an SSH endpoint.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not update machines.", body = crate::error::ApiError),
        (status = 404, description = "The machine or endpoint does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Machine access is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn clear_machine_endpoint_auth(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path((machine_id, endpoint_id)): Path<(String, String)>,
) -> Result<Json<Resource<EndpointAuthStateDto>>, ApiErrorResponse> {
    let access = access_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    access
        .set_default_auth(
            state.authorizer.as_ref(),
            &principal,
            &machine_id,
            &endpoint_id,
            None,
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(Json(Resource::new(EndpointAuthStateDto { auth: None })))
}

/// The body of `POST /machines/{machineId}/exec`.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineExecRequest {
    /// The SSH endpoint; absent means the machine's only SSH endpoint.
    pub endpoint_id: Option<String>,
    /// An explicit auth, overriding the endpoint's default.
    pub auth: Option<EndpointAuthDto>,
    /// A program and its arguments, passed to the guest as data (no shell
    /// parses them). Exactly one of `command` and `script` is required.
    pub command: Option<Vec<String>>,
    /// Script text for the guest's shell (bash, or PowerShell on Windows),
    /// sent untouched.
    pub script: Option<String>,
    /// The deadline in seconds (1-900; default 60).
    pub timeout_seconds: Option<u64>,
    /// The guest's OS, `linux` (default) or `windows`.
    pub guest_os: Option<String>,
}

/// Runs a bounded command on a machine over its SSH endpoint, with the
/// endpoint's stored credential, as a `machine.exec` operation. The result
/// carries the exit code, scrubbed and bounded stdout and stderr, and
/// truncation flags. The audit event records the command's SHA-256, never
/// the command.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown machine or
/// endpoint, an endpoint whose host key was never confirmed, no usable auth,
/// or an invalid command.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/exec",
    tag = "machines",
    operation_id = "execMachine",
    params(
        ("machineId" = String, Path, description = "The machine's identity."),
        ("Idempotency-Key" = Option<String>, Header, description = "A caller-chosen key: a retry with the same key and command returns the operation already queued."),
    ),
    request_body = MachineExecRequest,
    responses(
        (status = 202, description = "The command is queued as a `machine.exec` operation; its result records the exit code and output.", body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The command, timeout or target is invalid, the host key was never confirmed, or the endpoint has no auth.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not run commands on this machine.", body = crate::error::ApiError),
        (status = 404, description = "The machine or endpoint does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Machine access is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn exec_machine(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: HeaderMap,
    Path(machine_id): Path<String>,
    request: Result<Json<MachineExecRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let access = access_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        crate::machines::invalid_request(
            "the request body must be valid JSON with a command or a script",
            correlation_id,
        )
    })?;
    let command = match (request.command, request.script) {
        (Some(argv), None) => ExecCommand::Argv(argv),
        (None, Some(script)) => ExecCommand::Script(script),
        _ => {
            return Err(crate::machines::invalid_request(
                "exactly one of command and script is required",
                correlation_id,
            ));
        }
    };
    let auth: Option<EndpointAuth> = request.auth.map(Into::into);
    let guest_os = parse_guest_os(request.guest_os.as_deref(), correlation_id)?;
    let idempotency_key = headers
        .get(crate::IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok());
    let mut new = access
        .request_exec(
            state.authorizer.as_ref(),
            &principal,
            &ExecRequest {
                target: AccessTarget {
                    machine_id: &machine_id,
                    endpoint_id: request.endpoint_id.as_deref(),
                    auth: auth.as_ref(),
                    guest_os,
                },
                command,
                timeout_seconds: request.timeout_seconds,
                idempotency_key,
            },
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    new.correlation_id = Some(correlation_id.to_string());
    let operation = state
        .operations
        .create_machine_access(state.authorizer.as_ref(), &principal.id, &machine_id, &new)
        .await
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
    Ok((StatusCode::ACCEPTED, Json(Resource::new(operation.into()))))
}

/// The body of `POST /machines/{machineId}/collect`.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineCollectRequest {
    /// The SSH endpoint; absent means the machine's only SSH endpoint.
    pub endpoint_id: Option<String>,
    /// An explicit auth, overriding the endpoint's default.
    pub auth: Option<EndpointAuthDto>,
    /// 1 to 16 distinct absolute guest paths of regular files, each at most
    /// 1024 bytes, without `.`, `..` or empty components or control
    /// characters (a Windows guest takes drive-absolute paths). Each file
    /// must fit the controller's artifact size cap.
    pub paths: Vec<String>,
    /// The guest's OS, `linux` (default) or `windows`.
    pub guest_os: Option<String>,
}

/// Copies declared files off a machine into the controller's artifact store
/// as a `machine.collect` operation. A path that cannot be copied fails the
/// operation (the files that were copied stay stored); the result lists the
/// stored files.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown machine or
/// endpoint, no usable auth, or invalid paths.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/collect",
    tag = "machines",
    operation_id = "collectMachineFiles",
    params(
        ("machineId" = String, Path, description = "The machine's identity."),
        ("Idempotency-Key" = Option<String>, Header, description = "A caller-chosen key: a retry with the same key returns the operation already queued."),
    ),
    request_body = MachineCollectRequest,
    responses(
        (status = 202, description = "The copy is queued as a `machine.collect` operation; its result lists the stored files.", body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The paths or target are invalid, the host key was never confirmed, or the endpoint has no auth.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not collect files from this machine.", body = crate::error::ApiError),
        (status = 404, description = "The machine or endpoint does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Machine access is not wired, or the controller has no artifact store.", body = crate::error::ApiError),
    )
)]
pub async fn collect_machine_files(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: HeaderMap,
    Path(machine_id): Path<String>,
    request: Result<Json<MachineCollectRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let access = access_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        crate::machines::invalid_request(
            "the request body must be valid JSON with a paths array",
            correlation_id,
        )
    })?;
    let auth: Option<EndpointAuth> = request.auth.map(Into::into);
    let guest_os = parse_guest_os(request.guest_os.as_deref(), correlation_id)?;
    let mut new = access
        .request_collect(
            state.authorizer.as_ref(),
            &principal,
            &AccessTarget {
                machine_id: &machine_id,
                endpoint_id: request.endpoint_id.as_deref(),
                auth: auth.as_ref(),
                guest_os,
            },
            &request.paths,
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    new.correlation_id = Some(correlation_id.to_string());
    new.idempotency_key = headers
        .get(crate::IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|key| {
            fleet_application::idempotency::scoped_key(
                "machine-collect",
                &principal.id,
                &[&machine_id, key],
            )
        });
    let operation = state
        .operations
        .create_machine_access(state.authorizer.as_ref(), &principal.id, &machine_id, &new)
        .await
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
    Ok((StatusCode::ACCEPTED, Json(Resource::new(operation.into()))))
}

/// Where on the machine to put the uploaded file, and how to reach it.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PutMachineFileParams {
    /// The absolute guest path of the file to create. Its directory must
    /// already exist.
    pub path: String,
    /// Replace an existing regular file at the path (default false).
    #[serde(default)]
    pub overwrite: bool,
    /// The SSH endpoint; absent means the machine's only SSH endpoint.
    pub endpoint_id: Option<String>,
    /// The guest's OS, `linux` (default) or `windows`.
    pub guest_os: Option<String>,
    /// An explicit auth kind (`agent`, `identityFile` or `secret`),
    /// overriding the endpoint's default.
    pub auth_type: Option<String>,
    /// The secret reference, for `authType=secret`.
    pub credential: Option<String>,
    /// The identity file path, for `authType=identityFile`.
    pub identity_path: Option<String>,
}

fn explicit_auth(
    params: &PutMachineFileParams,
    correlation_id: CorrelationId,
) -> Result<Option<EndpointAuth>, ApiErrorResponse> {
    let bad = |message: &str| crate::machines::invalid_request(message, correlation_id);
    match params.auth_type.as_deref() {
        None => Ok(None),
        Some("agent") => Ok(Some(EndpointAuth::Agent)),
        Some("identityFile") => params
            .identity_path
            .clone()
            .map(|path| Some(EndpointAuth::IdentityFile { path }))
            .ok_or_else(|| bad("authType=identityFile needs identityPath")),
        Some("secret") => params
            .credential
            .clone()
            .map(|credential| Some(EndpointAuth::Secret { credential }))
            .ok_or_else(|| bad("authType=secret needs credential")),
        Some(_) => Err(bad("authType must be agent, identityFile or secret")),
    }
}

/// Copies one file onto a machine as a `machine.put` operation. The body is
/// the raw file. It is streamed into controller staging (the cap is enforced
/// while streaming) and sent over the endpoint's stored credential; the
/// controller verifies the SHA-256 inside the guest and moves the file into
/// place only after it matches, so a failed put leaves nothing at the path.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown machine or
/// endpoint, no usable auth, an invalid path, or an upload over the cap.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/files",
    tag = "machines",
    operation_id = "putMachineFile",
    params(
        ("machineId" = String, Path, description = "The machine's identity."),
        ("path" = String, Query, description = "The absolute guest path of the file to create."),
        ("overwrite" = Option<bool>, Query, description = "Replace an existing regular file at the path (default false)."),
        ("endpointId" = Option<String>, Query, description = "The SSH endpoint; absent means the machine's only SSH endpoint."),
        ("guestOs" = Option<String>, Query, description = "`linux` (default) or `windows`."),
        ("authType" = Option<String>, Query, description = "An explicit auth kind: `agent`, `identityFile` or `secret`."),
        ("credential" = Option<String>, Query, description = "The secret reference, for `authType=secret`."),
        ("identityPath" = Option<String>, Query, description = "The identity file path, for `authType=identityFile`."),
        ("X-Content-SHA256" = Option<String>, Header, description = "The file's lowercase hex SHA-256; the upload is refused when what arrives hashes differently."),
        ("Idempotency-Key" = Option<String>, Header, description = "A caller-chosen key bound to the target and the file's digest."),
    ),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The file's raw bytes."),
    responses(
        (status = 202, description = "The copy is queued as a `machine.put` operation; its result records the guest path, size and SHA-256.", body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The path or target is invalid, the host key was never confirmed, the endpoint has no auth, or the declared SHA-256 does not match the body.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not put files onto this machine.", body = crate::error::ApiError),
        (status = 404, description = "The machine or endpoint does not exist.", body = crate::error::ApiError),
        (status = 408, description = "The upload body stalled for a minute.", body = crate::error::ApiError),
        (status = 413, description = "The file exceeds the controller's upload cap.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "The controller has no upload staging area, or too many uploads are in flight (code `busy`).", body = crate::error::ApiError),
    )
)]
pub async fn put_machine_file(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: HeaderMap,
    Path(machine_id): Path<String>,
    Query(params): Query<PutMachineFileParams>,
    body: Body,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let access = access_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let declared = match headers.get(CONTENT_SHA256_HEADER) {
        None => None,
        Some(value) => Some(
            value
                .to_str()
                .ok()
                .filter(|value| is_sha256_hex(value))
                .ok_or_else(|| {
                    crate::machines::invalid_request(
                        "X-Content-SHA256 must be a lowercase hex SHA-256",
                        correlation_id,
                    )
                })?
                .to_owned(),
        ),
    };
    let auth = explicit_auth(&params, correlation_id)?;
    let guest_os = parse_guest_os(params.guest_os.as_deref(), correlation_id)?;
    let target = PutRequestTarget {
        target: AccessTarget {
            machine_id: &machine_id,
            endpoint_id: params.endpoint_id.as_deref(),
            auth: auth.as_ref(),
            guest_os,
        },
        guest_path: &params.path,
        overwrite: params.overwrite,
    };
    // Authorization, the path and the target are checked before any byte is
    // read.
    let writer = access
        .begin_upload(state.authorizer.as_ref(), &principal, &target)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    let max_bytes = access.max_upload_bytes().unwrap_or(0);
    let announced = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if announced.is_some_and(|length| length > max_bytes) {
        return Err(too_large(max_bytes, correlation_id));
    }
    let staged = stream_upload(writer, body, correlation_id).await?;
    // From here the staging file is owned by a detached task, so a client
    // that disconnects cannot cancel the hand-off halfway and orphan it.
    let idempotency_key = headers
        .get(crate::IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let staged_id = staged.id.clone();
    let queued = tokio::spawn(queue_put(
        state,
        access.clone(),
        principal,
        QueuedPut {
            machine_id,
            endpoint_id: params.endpoint_id,
            auth,
            guest_os,
            guest_path: params.path,
            overwrite: params.overwrite,
            declared,
            idempotency_key,
            staged,
        },
        correlation_id,
    ))
    .await;
    let Ok(result) = queued else {
        access.discard_upload(&staged_id).await;
        return Err(map_lab_error(
            &LabUseCaseError::Backend {
                context: "uploads",
                detail: "the queueing task failed".to_owned(),
            },
            correlation_id,
        ));
    };
    let operation = result?;
    Ok((StatusCode::ACCEPTED, Json(Resource::new(operation.into()))))
}

/// What the hand-off needs once the body is staged.
struct QueuedPut {
    machine_id: String,
    endpoint_id: Option<String>,
    auth: Option<EndpointAuth>,
    guest_os: GuestOs,
    guest_path: String,
    overwrite: bool,
    declared: Option<String>,
    idempotency_key: Option<String>,
    staged: StagedUpload,
}

/// Checks the declared digest, validates and audits the request, and queues
/// the `machine.put` operation. The staged file is discarded on every
/// refusal.
async fn queue_put(
    state: Arc<crate::operations::ApiState>,
    access: Arc<MachineAccess>,
    principal: crate::ActingPrincipal,
    put: QueuedPut,
    correlation_id: CorrelationId,
) -> Result<fleet_application::operation::Operation, ApiErrorResponse> {
    let QueuedPut {
        machine_id,
        endpoint_id,
        auth,
        guest_os,
        guest_path,
        overwrite,
        declared,
        idempotency_key,
        staged,
    } = put;
    if declared.as_deref().is_some_and(|sha| sha != staged.sha256) {
        access.discard_upload(&staged.id).await;
        return Err(crate::machines::invalid_request(
            "the SHA-256 of the received file does not match X-Content-SHA256",
            correlation_id,
        ));
    }
    let target = PutRequestTarget {
        target: AccessTarget {
            machine_id: &machine_id,
            endpoint_id: endpoint_id.as_deref(),
            auth: auth.as_ref(),
            guest_os,
        },
        guest_path: &guest_path,
        overwrite,
    };
    let mut new = access
        .request_put(state.authorizer.as_ref(), &principal, &target, &staged)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    new.correlation_id = Some(correlation_id.to_string());
    // The key is bound to the target and the file's digest, so reusing it
    // for a different file queues a different operation.
    new.idempotency_key = idempotency_key.map(|key| {
        let binding = crate::lab_put::sha256_hex(
            format!("{guest_path}\0{overwrite}\0{}", staged.sha256).as_bytes(),
        );
        fleet_application::idempotency::scoped_key(
            "machine-put",
            &principal.id,
            &[&machine_id, &binding, &key],
        )
    });
    let operation = match state
        .operations
        .create_machine_access(state.authorizer.as_ref(), &principal.id, &machine_id, &new)
        .await
    {
        Ok(operation) => operation,
        Err(error) => {
            access.discard_upload(&staged.id).await;
            return Err(crate::operations::map_use_case_error(
                &error,
                correlation_id,
            ));
        }
    };
    // A replayed key returns the earlier operation, which owns its own
    // staging file; this upload's copy is redundant.
    let owns_upload = operation
        .payload_json
        .as_deref()
        .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
        .is_some_and(|payload| payload["uploadId"].as_str() == Some(staged.id.as_str()));
    if !owns_upload {
        access.discard_upload(&staged.id).await;
    }
    Ok(operation)
}

/// One file collected from a machine.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineFileDto {
    /// The file record's identity.
    pub id: String,
    /// The machine it came from.
    pub machine_id: String,
    /// The principal that asked for the collection.
    pub owner: String,
    /// The guest path it was collected from.
    pub path: String,
    /// The size in bytes.
    pub size_bytes: u64,
    /// The lowercase hex sha256 of the bytes.
    pub sha256: String,
    /// The `machine.collect` operation that produced it.
    pub operation_id: Option<String>,
    /// When it was stored (epoch milliseconds).
    pub created_at: i64,
    /// When the retention pass deletes it (epoch milliseconds).
    pub retain_until: i64,
}

impl From<MachineFile> for MachineFileDto {
    fn from(file: MachineFile) -> Self {
        Self {
            id: file.id,
            machine_id: file.machine_id,
            owner: file.owner,
            path: file.name,
            size_bytes: file.size_bytes,
            sha256: file.sha256,
            operation_id: file.operation_id,
            created_at: file.created_at,
            retain_until: file.retain_until,
        }
    }
}

/// The list-files query parameters.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListMachineFilesParams {
    /// The page size (1-200; default 50).
    pub limit: Option<u32>,
}

/// Lists the files collected from a machine, newest first.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/machines/{machineId}/files",
    tag = "machines",
    operation_id = "listMachineFiles",
    params(
        ("machineId" = String, Path, description = "The machine's identity."),
        ("limit" = Option<u32>, Query, description = "The page size (1-200; default 50)."),
    ),
    responses(
        (status = 200, description = "The collected files, newest first.", body = Page<MachineFileDto>),
        (status = 400, description = "The query parameters are malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not collect files from this machine.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Machine access is not wired, or the controller has no artifact store.", body = crate::error::ApiError),
    )
)]
pub async fn list_machine_files(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(machine_id): Path<String>,
    params: Result<Query<ListMachineFilesParams>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Page<MachineFileDto>>, ApiErrorResponse> {
    let params = params.map_err(|rejection| {
        crate::machines::invalid_request(
            &format!("the files list query is malformed: {rejection}"),
            correlation_id,
        )
    })?;
    let access = access_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let limit = params
        .limit
        .unwrap_or(crate::envelope::DEFAULT_PAGE_LIMIT)
        .clamp(1, crate::envelope::MAX_PAGE_LIMIT);
    let files = access
        .list_files(state.authorizer.as_ref(), &principal, &machine_id, limit)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(Json(Page {
        items: files.into_iter().map(Into::into).collect(),
        page: PageInfo {
            next_cursor: None,
            limit,
        },
    }))
}

/// Reads one collected file's metadata.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown file.
#[utoipa::path(
    get,
    path = "/machine-files/{fileId}",
    tag = "machines",
    operation_id = "getMachineFile",
    params(("fileId" = String, Path, description = "The collected file's identity.")),
    responses(
        (status = 200, description = "The file's metadata.", body = Resource<MachineFileDto>),
        (status = 403, description = "The caller may not collect files from this machine.", body = crate::error::ApiError),
        (status = 404, description = "The file does not exist.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Machine access is not wired, or the controller has no artifact store.", body = crate::error::ApiError),
    )
)]
pub async fn get_machine_file(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(file_id): Path<String>,
) -> Result<Json<Resource<MachineFileDto>>, ApiErrorResponse> {
    let access = access_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let file = access
        .get_file(state.authorizer.as_ref(), &principal, &file_id)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(Json(Resource::new(file.into())))
}

/// Streams one collected file's bytes. The controller re-hashes them first
/// and refuses (409) bytes that no longer match the recorded size and
/// sha256; the response carries the digest as `Repr-Digest` and `ETag`.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown file, or bytes
/// that are missing or corrupt.
#[utoipa::path(
    get,
    path = "/machine-files/{fileId}/content",
    tag = "machines",
    operation_id = "downloadMachineFile",
    params(("fileId" = String, Path, description = "The collected file's identity.")),
    responses(
        (status = 200, description = "The file's verified bytes.", body = crate::lab_artifacts::ArtifactBytes, content_type = "application/octet-stream",
            headers(
                ("Repr-Digest" = String, description = "The bytes' sha256, as `sha-256=:<base64>:` (RFC 9530)."),
                ("ETag" = String, description = "The bytes' sha256, as `\"sha256:<hex>\"`."),
            )
        ),
        (status = 403, description = "The caller may not collect files from this machine.", body = crate::error::ApiError),
        (status = 404, description = "The file does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The stored bytes are missing or no longer match their digest.", body = crate::error::ApiError),
        (status = 500, description = "A backend port failed.", body = crate::error::ApiError),
        (status = 503, description = "Machine access is not wired, or the controller has no artifact store.", body = crate::error::ApiError),
    )
)]
pub async fn download_machine_file(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(file_id): Path<String>,
) -> Result<Response, ApiErrorResponse> {
    let access = access_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let (file, reader) = access
        .open_file(state.authorizer.as_ref(), &principal, &file_id)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(crate::lab_artifacts::artifact_response(
        reader,
        file.size_bytes,
        &file.sha256,
        &file.name,
    ))
}
