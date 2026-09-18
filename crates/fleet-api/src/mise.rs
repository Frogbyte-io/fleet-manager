//! The mise surface (FM-304): durable, audited operations through the
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

/// How a mise operation's endpoint authenticates.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum MiseAuthDto {
    /// The controller's agent supplies the key.
    Agent,
    /// A specific identity file.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// The mise action a request names.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum MiseActionDto {
    /// Read the tool/coding-agent inventory.
    Inventory,
    /// Read mise's own tool inventory.
    Status,
    /// Install a pinned tool version (idempotent).
    Install,
    /// Run a project command through `mise exec` inside a checkout.
    Exec,
}

impl MiseActionDto {
    /// The operation kind the action maps to.
    #[must_use]
    pub fn kind(self) -> &'static str {
        match self {
            Self::Inventory => "tools.inventory",
            Self::Status => "mise.status",
            Self::Install => "mise.install",
            Self::Exec => "mise.exec",
        }
    }

    /// The permission the action requires.
    #[must_use]
    pub fn permission(self) -> fleet_application::authz::Permission {
        match self {
            Self::Inventory | Self::Status => fleet_application::authz::Permission::ToolsRead,
            Self::Install | Self::Exec => fleet_application::authz::Permission::MiseOperate,
        }
    }
}

/// The body of the start-mise-operation request.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartMiseOperationRequest {
    /// The machine to act on (must match the path's machine).
    pub machine_id: String,
    /// The SSH endpoint id to act through.
    pub endpoint_id: String,
    /// How the endpoint authenticates.
    pub auth: MiseAuthDto,
    /// The action to run. A closed enum: anything else is malformed.
    pub action: MiseActionDto,
    /// The tool to install, for the install action.
    pub tool: Option<String>,
    /// The pinned version to install, for the install action.
    pub version: Option<String>,
    /// The checkout root whose mise configuration binds an exec command.
    pub root: Option<String>,
    /// The command to run, as an argument array. Never a shell string.
    #[serde(default)]
    pub command: Vec<String>,
    /// The deadline, in seconds. Bounded by the executor.
    pub timeout_seconds: u64,
}

/// Starts a mise operation.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    post,
    path = "/machines/{machineId}/mise/operations",
    tag = "machines",
    operation_id = "startMiseOperation",
    request_body = StartMiseOperationRequest,
    params(
        ("machineId" = String, Path, description = "The machine to act on.")
    ),
    responses(
        (
            status = 202,
            description = "The mise operation was accepted. Requires machine.read for the machine in addition to the action's permission.",
            body = Resource<crate::operations::OperationDto>
        ),
        (
            status = 400,
            description = "The request is malformed.",
            body = crate::error::ApiError
        ),
        (
            status = 403,
            description = "The caller may not perform the mise action.",
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
pub async fn start_mise_operation(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: axum::http::HeaderMap,
    Path(machine_id): Path<String>,
    Json(request): Json<StartMiseOperationRequest>,
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
    // machines cannot discover which ids exist to act on.
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
    let mut payload = serde_json::json!({
        "machineId": machine_id,
        "endpointId": request.endpoint_id,
        "auth": serde_json::to_value(&request.auth)
            .map_err(|error| crate::machines::invalid_request(&error.to_string(), correlation_id))?,
        "timeoutSeconds": request.timeout_seconds,
    });
    match request.action {
        MiseActionDto::Install => {
            let Some(tool) = &request.tool else {
                return Err(crate::machines::invalid_request(
                    "an install requires the tool name",
                    correlation_id,
                ));
            };
            let Some(version) = &request.version else {
                return Err(crate::machines::invalid_request(
                    "an install requires the pinned version",
                    correlation_id,
                ));
            };
            if tool.is_empty() || tool.starts_with('-') || tool.chars().any(char::is_control) {
                return Err(crate::machines::invalid_request(
                    "the tool name must carry no leading dash or control characters",
                    correlation_id,
                ));
            }
            if version.is_empty()
                || version.starts_with('-')
                || version.chars().any(char::is_control)
            {
                return Err(crate::machines::invalid_request(
                    "the version must carry no leading dash or control characters",
                    correlation_id,
                ));
            }
            payload["tool"] = serde_json::json!(tool);
            payload["version"] = serde_json::json!(version);
        }
        MiseActionDto::Exec => {
            let Some(root) = &request.root else {
                return Err(crate::machines::invalid_request(
                    "an exec requires the checkout root",
                    correlation_id,
                ));
            };
            if request.command.is_empty() {
                return Err(crate::machines::invalid_request(
                    "an exec requires a command",
                    correlation_id,
                ));
            }
            if !root.starts_with('/') || root.chars().count() > 400 {
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
        MiseActionDto::Inventory | MiseActionDto::Status => {
            if request.root.is_some() || !request.command.is_empty() {
                return Err(crate::machines::invalid_request(
                    "--root and a command apply to exec only",
                    correlation_id,
                ));
            }
        }
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
