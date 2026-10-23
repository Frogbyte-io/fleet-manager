//! Permanent, Fleet-managed VMs (#489): the reviewed `machine.create` and
//! the product-key store.
//!
//! The routes are thin adapters over [`PersistentMachines`]. The review call
//! renders exactly what will run and answers the token that binds the create
//! call to it; the create call recomputes the same payload from the same spec
//! and queues the operation, whose creation re-checks the token. Nothing here
//! carries a secret value except the product key a caller stores, which is
//! never returned.

use std::str::FromStr as _;
use std::sync::Arc;

use axum::{Extension, Json, extract::State, http::StatusCode};
use fleet_application::persistent::{CreateMachineSpec, PersistentMachines};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::Resource;
use crate::error::{ApiError, ApiErrorResponse};
use crate::lab::map_lab_error;

fn persistent_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<PersistentMachines>, ApiErrorResponse> {
    state
        .lab
        .as_ref()
        .and_then(|lab| lab.machine_access())
        .and_then(|access| access.persistent().cloned())
        .ok_or_else(|| {
            let public = PublicError::new(
                ErrorCode::from_str("machine_unavailable")
                    .expect("the literal is valid error code syntax"),
                "persistent machine creation is not wired; the controller needs its database and secret store",
                RetryClass::Backoff,
            );
            ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
        })
}

fn read_spec(
    spec: serde_json::Value,
    correlation_id: CorrelationId,
) -> Result<CreateMachineSpec, ApiErrorResponse> {
    serde_json::from_value(spec).map_err(|error| {
        crate::machines::invalid_request(
            &format!("the machine spec is not valid: {error}"),
            correlation_id,
        )
    })
}

/// The body of `POST /machines/create/review`.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReviewMachineCreateRequest {
    /// The machine to create: account, promoted image version, name, optional
    /// placement and hardware, tags, description, `onboot`, `protection`
    /// (default on), the guest OS, the bootstrap login, the host-key trust,
    /// the SSH credential choice (`generate`, `reference` or `publicKey`),
    /// an optional login user, the Windows options (administrator password
    /// policy and activation) and the deadline. It holds references and
    /// public keys only, never a secret value.
    #[schema(value_type = Object)]
    pub spec: serde_json::Value,
}

/// What a reviewed create will run, and the token that binds it.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineCreateReviewDto {
    /// The token the create call must present.
    pub review_token: String,
    /// The spec as it will run, with every default filled in.
    #[schema(value_type = Object)]
    pub spec: serde_json::Value,
}

/// Reviews a persistent machine creation: validates the spec, checks that
/// the image version is promoted and that the credential references exist,
/// and returns the spec as it will run with the review token. Nothing is
/// created.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an invalid spec.
#[utoipa::path(
    post,
    path = "/machines/create/review",
    tag = "machines",
    operation_id = "reviewMachineCreate",
    request_body = ReviewMachineCreateRequest,
    responses(
        (status = 200, description = "The review record; present its token to the create call.", body = Resource<MachineCreateReviewDto>),
        (status = 400, description = "The spec is invalid, the image version is not promoted, or a reference names nothing.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not provision machines.", body = crate::error::ApiError),
        (status = 503, description = "Persistent machine creation is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn review_machine_create(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    request: Result<Json<ReviewMachineCreateRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Resource<MachineCreateReviewDto>>, ApiErrorResponse> {
    let persistent = persistent_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        crate::machines::invalid_request(
            "the request body must be valid JSON with a spec",
            correlation_id,
        )
    })?;
    let spec = read_spec(request.spec, correlation_id)?;
    let prepared = persistent
        .prepare(state.authorizer.as_ref(), &principal, &spec)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(Json(Resource::new(MachineCreateReviewDto {
        review_token: prepared.review_token,
        spec: serde_json::to_value(&spec).unwrap_or_default(),
    })))
}

/// The body of `POST /machines/create`.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineCreateRequest {
    /// The spec, identical to the reviewed one.
    #[schema(value_type = Object)]
    pub spec: serde_json::Value,
    /// The token from the review call.
    pub review_token: String,
}

/// Creates a permanent VM as a durable `machine.create` operation. The
/// operation clones the promoted image, applies the reviewed settings,
/// starts the guest, waits for its address and SSH host key, registers and
/// links the machine, installs the chosen SSH key and removes the image's
/// shared key, and optionally finishes the Windows setup. Its result names
/// the machine and endpoint, never a key.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an invalid spec, or a
/// review token that does not match the spec.
#[utoipa::path(
    post,
    path = "/machines/create",
    tag = "machines",
    operation_id = "createMachine",
    params(
        ("Idempotency-Key" = Option<String>, Header, description = "A caller-chosen key: a retry with the same key returns the operation already queued."),
    ),
    request_body = MachineCreateRequest,
    responses(
        (status = 202, description = "The creation is queued as a `machine.create` operation.", body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The spec is invalid or the review token does not match it.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not provision machines.", body = crate::error::ApiError),
        (status = 503, description = "Persistent machine creation is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn create_machine(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: axum::http::HeaderMap,
    request: Result<Json<MachineCreateRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let persistent = persistent_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        crate::machines::invalid_request(
            "the request body must be valid JSON with a spec and a reviewToken",
            correlation_id,
        )
    })?;
    let spec = read_spec(request.spec, correlation_id)?;
    let prepared = persistent
        .prepare(state.authorizer.as_ref(), &principal, &spec)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    let idempotency_key = headers
        .get(crate::IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|key| {
            fleet_application::idempotency::scoped_key(
                fleet_application::idempotency::CALLER_KEY,
                &principal.id,
                &[key],
            )
        });
    let operation = state
        .operations
        .create_machine_create(
            state.authorizer.as_ref(),
            &principal.id,
            &fleet_application::operation::NewOperation {
                kind: "machine.create".to_owned(),
                idempotency_key,
                deadline_at: None,
                correlation_id: Some(correlation_id.to_string()),
                payload_json: Some(prepared.payload_json),
                review_token: Some(request.review_token),
            },
        )
        .await
        .map_err(|error| crate::operations::map_use_case_error(&error, correlation_id))?;
    persistent
        .record_requested(&principal, &operation.id, &spec)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(Resource::new(crate::operations::OperationDto::from(
            operation,
        ))),
    ))
}

/// The body of `POST /machine-product-keys`.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoreProductKeyRequest {
    /// The Windows product key (five groups of five letters and digits).
    pub product_key: String,
}

impl std::fmt::Debug for StoreProductKeyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreProductKeyRequest")
            .field("product_key", &"[redacted]")
            .finish()
    }
}

/// The reference of a stored product key.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoredProductKeyDto {
    /// The reference to use as `secret` in a product-key activation.
    pub secret_ref: String,
}

/// Stores a Windows product key as an encrypted secret and returns its
/// reference. The key is readable only by the create executor and is never
/// returned, logged, or recorded in an audit event.
///
/// # Errors
///
/// Returns the public error envelope on refusal, a value that is not a
/// product key, or when no secret store is configured.
#[utoipa::path(
    post,
    path = "/machine-product-keys",
    tag = "machines",
    operation_id = "storeMachineProductKey",
    request_body = StoreProductKeyRequest,
    responses(
        (status = 201, description = "The key is stored; the reference is the only thing returned.", body = Resource<StoredProductKeyDto>),
        (status = 400, description = "The value is not a product key.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not write secrets.", body = crate::error::ApiError),
        (status = 503, description = "Persistent machine creation is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn store_machine_product_key(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    request: Result<Json<StoreProductKeyRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Resource<StoredProductKeyDto>>), ApiErrorResponse> {
    let persistent = persistent_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        crate::machines::invalid_request(
            "the request body must be valid JSON with a productKey",
            correlation_id,
        )
    })?;
    let secret_ref = persistent
        .store_product_key(state.authorizer.as_ref(), &principal, &request.product_key)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok((
        StatusCode::CREATED,
        Json(Resource::new(StoredProductKeyDto { secret_ref })),
    ))
}

/// What abandoning a marker will do, and the token that binds it.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AbandonReviewDto {
    /// The token the abandon call must present.
    pub review_token: String,
    /// The Proxmox account.
    pub account_id: String,
    /// The VMID whose marker will be removed.
    pub vmid: u32,
    /// The machine name the marker records.
    pub name: String,
}

/// Reviews abandoning a persistent marker whose creation never completed
/// (a failed clone, or a guest removed by hand). A marker of a created
/// machine is refused: destroy that machine instead.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown marker, or a
/// marker of a created machine.
#[utoipa::path(
    post,
    path = "/machines/persistent/{accountId}/{vmid}/abandon/review",
    tag = "machines",
    operation_id = "reviewAbandonPersistentMarker",
    params(
        ("accountId" = String, Path, description = "The Proxmox account."),
        ("vmid" = u32, Path, description = "The guest's VMID.")
    ),
    responses(
        (status = 200, description = "The review record; present its token to the abandon call.", body = Resource<AbandonReviewDto>),
        (status = 403, description = "The caller may not provision machines.", body = crate::error::ApiError),
        (status = 404, description = "The marker does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The marker belongs to a created machine.", body = crate::error::ApiError),
        (status = 503, description = "Persistent machine creation is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn review_abandon_marker(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    axum::extract::Path((account_id, vmid)): axum::extract::Path<(String, u32)>,
) -> Result<Json<Resource<AbandonReviewDto>>, ApiErrorResponse> {
    let persistent = persistent_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    fleet_application::authz::authorize(
        state.authorizer.as_ref(),
        fleet_application::authz::AccessRequest {
            principal_id: &principal.id,
            action: fleet_application::authz::Permission::MachineProvision,
            resource: None,
        },
    )
    .map_err(|decision| crate::machines::denied_error(decision, correlation_id))?;
    let marker = persistent
        .marker(&account_id, vmid)
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?
        .ok_or_else(|| {
            map_lab_error(
                &fleet_application::lab::LabUseCaseError::NotFound {
                    what: format!("a persistent marker for {account_id}/{vmid}"),
                },
                correlation_id,
            )
        })?;
    if marker.cloned || marker.state == fleet_application::persistent::PersistentState::Ready {
        return Err(map_lab_error(
            &fleet_application::lab::LabUseCaseError::Conflict {
                detail: format!(
                    "{} is a created machine, not an abandoned creation; destroy it with the reviewed destroy",
                    marker.name
                ),
            },
            correlation_id,
        ));
    }
    let (_, token) = PersistentMachines::abandon_payload(&account_id, vmid);
    Ok(Json(Resource::new(AbandonReviewDto {
        review_token: token,
        account_id,
        vmid,
        name: marker.name,
    })))
}

/// The body of the abandon call.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AbandonMarkerRequest {
    /// The token from the review call.
    pub review_token: String,
}

/// Abandons a reviewed marker: it is removed, with an audit event, and its
/// VMID and name are free again.
///
/// # Errors
///
/// Returns the public error envelope on refusal, a review token that does
/// not match, or an unknown marker.
#[utoipa::path(
    post,
    path = "/machines/persistent/{accountId}/{vmid}/abandon",
    tag = "machines",
    operation_id = "abandonPersistentMarker",
    params(
        ("accountId" = String, Path, description = "The Proxmox account."),
        ("vmid" = u32, Path, description = "The guest's VMID.")
    ),
    request_body = AbandonMarkerRequest,
    responses(
        (status = 204, description = "The marker was removed."),
        (status = 400, description = "The review token does not match.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not provision machines.", body = crate::error::ApiError),
        (status = 404, description = "The marker does not exist.", body = crate::error::ApiError),
        (status = 409, description = "The marker belongs to a created machine.", body = crate::error::ApiError),
        (status = 503, description = "Persistent machine creation is not wired.", body = crate::error::ApiError),
    )
)]
pub async fn abandon_marker(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    axum::extract::Path((account_id, vmid)): axum::extract::Path<(String, u32)>,
    request: Result<Json<AbandonMarkerRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<StatusCode, ApiErrorResponse> {
    let persistent = persistent_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let Json(request) = request.map_err(|_| {
        crate::machines::invalid_request(
            "the request body must be valid JSON with a reviewToken",
            correlation_id,
        )
    })?;
    persistent
        .abandon(
            state.authorizer.as_ref(),
            &principal,
            &account_id,
            vmid,
            &request.review_token,
        )
        .await
        .map_err(|error| map_lab_error(&error, correlation_id))?;
    Ok(StatusCode::NO_CONTENT)
}
