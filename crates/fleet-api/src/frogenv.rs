//! The Frogenv surface (FM-303): durable, audited operations through the
//! documented CLI contract. This adapter decides nothing; it translates
//! HTTP into operation creation and authorization calls.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use fleet_core::CorrelationId;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::ApiErrorResponse;

/// How a Frogenv operation's endpoint authenticates.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum FrogenvAuthDto {
    /// The controller's agent supplies the key.
    Agent,
    /// A specific identity file.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// The body of the start-frogenv-operation request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartFrogenvOperationRequest {
    /// The machine to act on (must match the path's machine).
    pub machine_id: String,
    /// The SSH endpoint id to act through.
    pub endpoint_id: String,
    /// How the endpoint authenticates.
    pub auth: FrogenvAuthDto,
    /// The action to run: `status`, `setup`, `login`, `request`, `sync`,
    /// or `envRun` (a command executed under a checkout's environment). A
    /// closed enum: anything else is malformed.
    pub action: FrogenvActionDto,
    /// The checkout root whose environment binds an `env run` command.
    pub root: Option<String>,
    /// The command to run under `env run`, as an argument array. Never a
    /// shell string.
    #[serde(default)]
    pub command: Vec<String>,
    /// The deadline, in seconds. Bounded by the executor.
    pub timeout_seconds: u64,
}

/// The Frogenv action a request names.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum FrogenvActionDto {
    /// Read the machine's Frogenv status.
    Status,
    /// Run the setup ceremony.
    Setup,
    /// Run the login ceremony.
    Login,
    /// Request this machine's registration.
    Request,
    /// Sync the environment files.
    Sync,
    /// Run an environment-bound command through `frogenv env run`.
    EnvRun,
}

impl FrogenvActionDto {
    /// The operation kind the action maps to.
    #[must_use]
    pub fn kind(self) -> &'static str {
        match self {
            Self::Status => "frogenv.status",
            Self::Setup => "frogenv.setup",
            Self::Login => "frogenv.login",
            Self::Request => "frogenv.request",
            Self::Sync => "frogenv.sync",
            Self::EnvRun => "frogenv.env-run",
        }
    }

    /// The permission the action requires.
    #[must_use]
    pub fn permission(self) -> fleet_application::authz::Permission {
        match self {
            Self::Status => fleet_application::authz::Permission::FrogenvRead,
            _ => fleet_application::authz::Permission::FrogenvOperate,
        }
    }
}

/// Starts a Frogenv operation.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/frogenv/operations",
    tag = "machines",
    operation_id = "startFrogenvOperation",
    request_body = StartFrogenvOperationRequest,
    params(
        ("machineId" = String, Path, description = "The machine to act on.")
    ),
    responses(
        (
            status = 202,
            description = "The Frogenv operation was accepted. Requires machine.read for the machine in addition to the action's frogenv permission.",
            body = Resource<crate::operations::OperationDto>
        ),
        (
            status = 400,
            description = "The request is malformed.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not perform the Frogenv action.",
            body = crate::error::ApiError
        ),
        (
            status = 404,
            description = "The machine does not exist.",
            body = crate::error::ApiError
        ),
    )
)]
#[allow(clippy::too_many_lines)]
pub async fn start_frogenv_operation(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: axum::http::HeaderMap,
    Path(machine_id): Path<String>,
    Json(request): Json<StartFrogenvOperationRequest>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let machines = crate::machines::machines_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    // The body's machine must agree with the path's: two names for one
    // machine is a malformed request, not a fallback.
    if request.machine_id != machine_id {
        return Err(crate::machines::invalid_request(
            "the body's machineId does not match the path's machine",
            correlation_id,
        ));
    }
    // The machine must exist before the authorization names it. The
    // machine-read check is part of the contract: a caller who cannot see
    // machines cannot discover which ids exist to act on. The Frogenv
    // permission is required in addition, not instead.
    let _machine = machines
        .get(
            state.authorizer.as_ref(),
            &principal,
            &machine_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| crate::machines::map_machine_error(&error, correlation_id))?;
    if let Err(decision) = fleet_application::authz::authorize(
        state.authorizer.as_ref(),
        fleet_application::authz::AccessRequest {
            principal_id: &principal.id,
            action: request.action.permission(),
            resource: Some(&machine_id),
        },
    ) {
        return Err(crate::machines::denied_error(decision, correlation_id));
    }
    // An env run carries its checkout root and command; the other actions
    // carry neither.
    let mut payload = serde_json::json!({
        "machineId": machine_id,
        "endpointId": request.endpoint_id,
        "auth": serde_json::to_value(&request.auth)
            .map_err(|error| crate::machines::invalid_request(&error.to_string(), correlation_id))?,
        "timeoutSeconds": request.timeout_seconds,
    });
    if request.action == FrogenvActionDto::EnvRun {
        let Some(root) = &request.root else {
            return Err(crate::machines::invalid_request(
                "an env run requires the checkout root",
                correlation_id,
            ));
        };
        if request.command.is_empty() {
            return Err(crate::machines::invalid_request(
                "an env run requires a command",
                correlation_id,
            ));
        }
        // The executor's constraints are checked here too, so a malformed
        // root or argument is a 400, never a queued operation.
        if !root.starts_with('/') || root.len() > 400 {
            return Err(crate::machines::invalid_request(
                "the checkout root must be an absolute path of at most 400 characters",
                correlation_id,
            ));
        }
        if root.split('/').any(|segment| segment == "..") {
            return Err(crate::machines::invalid_request(
                "the checkout root must not contain a `..` segment",
                correlation_id,
            ));
        }
        if root.chars().any(char::is_control) {
            return Err(crate::machines::invalid_request(
                "the checkout root must not contain control characters",
                correlation_id,
            ));
        }
        for argument in &request.command {
            if argument.is_empty() || argument.len() > 1024 {
                return Err(crate::machines::invalid_request(
                    "every command argument must be 1..=1024 characters",
                    correlation_id,
                ));
            }
            if argument.chars().any(char::is_control) {
                return Err(crate::machines::invalid_request(
                    "command arguments must not contain control characters",
                    correlation_id,
                ));
            }
        }
        payload["root"] = serde_json::json!(root);
        payload["command"] = serde_json::json!(request.command);
    }
    // A caller-scoped idempotency key makes a retried POST return the
    // original operation instead of a second one.
    let idempotency_key = headers
        .get(crate::IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|key| format!("{}:{key}", principal.id));
    let operation = state
        .operations
        .create(
            state.authorizer.as_ref(),
            &principal.id,
            &fleet_application::operation::NewOperation {
                kind: request.action.kind().to_owned(),
                idempotency_key,
                deadline_at: None,
                correlation_id: Some(correlation_id.to_string()),
                payload_json: Some(payload.to_string()),
            },
        )
        .await
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(Resource::new(crate::operations::OperationDto::from(
            operation,
        ))),
    ))
}
