//! The image-recipe surface: drafts, immutable versions, and the build
//! operation (FM-700).
//!
//! This adapter decides nothing about recipes; it translates HTTP into
//! the application's use cases and their outcomes into the public
//! envelopes. The recipe content passes through verbatim — Fleet never
//! re-validates Packer's own fields.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use fleet_application::images::{NewRecipe, Recipe, RecipeUseCaseError, RecipeVersion};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RecipeContent, RecipeSource, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Page, PageInfo, Resource};
use crate::error::{ApiError, ApiErrorResponse};

/// Extracts the image use cases from the API state, or answers with the
/// standard envelope when the controller was composed without one.
fn images_or_error(
    state: &crate::operations::ApiState,
    correlation_id: CorrelationId,
) -> Result<Arc<fleet_application::images::Images>, ApiErrorResponse> {
    state.images.clone().ok_or_else(|| {
        let public = PublicError::new(
            ErrorCode::from_str("machine_unavailable")
                .expect("the literal is valid error code syntax"),
            "the image surface is not wired; the controller needs its database",
            RetryClass::Backoff,
        );
        ApiError::new(&public, correlation_id).with_status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

/// Maps an image use-case outcome onto the public error envelope, once.
fn map_images_error(error: &RecipeUseCaseError, correlation_id: CorrelationId) -> ApiErrorResponse {
    let (status, code, retry): (StatusCode, &str, RetryClass) = match error {
        RecipeUseCaseError::Denied(_) => (StatusCode::FORBIDDEN, "denied", RetryClass::Never),
        RecipeUseCaseError::NotFound { .. } => {
            (StatusCode::NOT_FOUND, "not_found", RetryClass::Never)
        }
        RecipeUseCaseError::Conflict { .. } => {
            (StatusCode::CONFLICT, "conflict", RetryClass::Never)
        }
        RecipeUseCaseError::Invalid { .. } => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            RetryClass::Never,
        ),
        RecipeUseCaseError::Backend { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            RetryClass::Backoff,
        ),
    };
    let message = match error {
        RecipeUseCaseError::Backend { .. } => {
            "the request could not be completed; the detail is in the controller log".to_owned()
        }
        other => other.to_string(),
    };
    let public = PublicError::new(
        ErrorCode::from_str(code).expect("the literal is valid error code syntax"),
        message,
        retry,
    );
    ApiError::new(&public, correlation_id).with_status(status)
}

/// One recipe draft.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecipeDto {
    /// The draft's identity.
    pub id: String,
    /// The recipe name.
    pub name: String,
    /// The recipe description.
    pub description: String,
    /// The PVE node the recipe builds on.
    pub node: String,
    /// The PVE storage pool the build writes to.
    pub storage_pool: String,
    /// What the recipe builds from: `iso` or `clone`.
    pub source: String,
    /// The raw Packer template content, verbatim.
    pub content: String,
    /// The published version this draft descends from, when any.
    pub published_from: Option<String>,
    /// When the draft was created.
    pub created_at: i64,
    /// When the draft was last edited.
    pub updated_at: i64,
}

impl From<Recipe> for RecipeDto {
    fn from(recipe: Recipe) -> Self {
        Self {
            id: recipe.id,
            name: recipe.content.name,
            description: recipe.content.description,
            node: recipe.content.node,
            storage_pool: recipe.content.storage_pool.unwrap_or_default(),
            source: recipe.content.source.id().to_owned(),
            content: recipe.content.content,
            published_from: recipe.published_from,
            created_at: recipe.created_at,
            updated_at: recipe.updated_at,
        }
    }
}

/// One published recipe version.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecipeVersionDto {
    /// The version's identity.
    pub id: String,
    /// The recipe the version came from.
    pub recipe_id: String,
    /// The recipe name at publication time.
    pub name: String,
    /// The frozen description.
    pub description: String,
    /// The frozen content digest.
    pub content_digest: String,
    /// The frozen content.
    pub content: String,
    /// What the version builds from.
    pub source: String,
    /// The node at publication time.
    pub node: String,
    /// The storage pool at publication time.
    pub storage_pool: String,
    /// When the version was published.
    pub published_at: i64,
    /// When the version was promoted, when any.
    pub promoted_at: Option<i64>,
    /// Who promoted the version, when any.
    pub promoted_by: Option<String>,
    /// The structured view of the version's content, when it carries a
    /// Proxmox builder block. `None` for non-JSON templates or builders
    /// outside the Proxmox family.
    pub structured: Option<StructuredRecipeDto>,
}

/// The structured view: exactly the supported Proxmox field subset.
///
/// The `firstDisk*`, `networkBridge`, and `bootIso*` fields follow the
/// Packer Proxmox plugin's schema (#278). The older fields keep their
/// published `/api/v1` meaning: they read top-level builder keys, most of
/// which the plugin does not accept, and are deprecated in favour of the
/// new ones (the compatibility policy in this crate's README).
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StructuredRecipeDto {
    /// The PVE node the recipe builds on.
    pub node: String,
    /// Deprecated: the builder's top-level `vm_storage_pool`/`storage_pool`,
    /// which the plugin refuses. Use `firstDiskStoragePool`.
    #[schema(deprecated)]
    pub storage_pool: String,
    /// What the recipe builds from: `iso` or `clone`.
    pub source: String,
    /// Deprecated: the top-level `iso_file`. Use `bootIsoFile`.
    #[schema(deprecated)]
    pub iso_file: Option<String>,
    /// Deprecated: the top-level `iso_storage_pool`. Use `bootIsoStoragePool`.
    #[schema(deprecated)]
    pub iso_storage_pool: Option<String>,
    /// The guest to clone, for the clone source.
    pub clone_vm: Option<String>,
    /// The vCPU count.
    pub cores: Option<u32>,
    /// The memory in MiB.
    pub memory: Option<u32>,
    /// Deprecated: the top-level `disk_size`, which the plugin refuses. Use
    /// `firstDiskSize`.
    #[schema(deprecated)]
    pub disk_size: Option<String>,
    /// Deprecated: the top-level `bridge`, which the plugin refuses. Use
    /// `networkBridge`.
    #[schema(deprecated)]
    pub bridge: Option<String>,
    /// Deprecated: the top-level `ciuser`; the plugin has no such key.
    #[schema(deprecated)]
    pub cloud_init_user: Option<String>,
    /// Deprecated: the top-level `sshkeys`; the plugin has no such key.
    #[schema(deprecated)]
    pub ssh_keys: Option<String>,
    /// The first disk's storage pool (`disks[0].storage_pool`). Absent when
    /// the builder declares no disk: a clone then keeps its source's storage.
    pub first_disk_storage_pool: Option<String>,
    /// The first disk's size (`disks[0].disk_size`).
    pub first_disk_size: Option<String>,
    /// The first network adapter's bridge (`network_adapters[0].bridge`).
    pub network_bridge: Option<String>,
    /// The boot ISO (`boot_iso.iso_file`, or the deprecated top-level key).
    pub boot_iso_file: Option<String>,
    /// The boot ISO's storage pool (`boot_iso.iso_storage_pool`, or the
    /// deprecated top-level key).
    pub boot_iso_storage_pool: Option<String>,
}

impl StructuredRecipeDto {
    /// The view of `content`, when it has one: the plugin-schema fields from
    /// fleet-core, and the deprecated fields read as `/api/v1` published them.
    fn of(content: &str) -> Option<Self> {
        let structured = fleet_core::StructuredRecipe::from_raw(content)?;
        // The same builder fleet-core chose: the first proxmox-iso/clone.
        let document: serde_json::Value = serde_json::from_str(content).ok()?;
        let builder = document
            .get("builders")
            .and_then(serde_json::Value::as_array)?
            .iter()
            .find(|builder| {
                matches!(
                    builder.get("type").and_then(serde_json::Value::as_str),
                    Some("proxmox-iso" | "proxmox-clone")
                )
            })?
            .clone();
        let legacy = |key: &str| {
            builder
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        Some(Self {
            node: structured.node,
            storage_pool: legacy("vm_storage_pool")
                .or_else(|| legacy("storage_pool"))
                .unwrap_or_default(),
            source: structured.source.id().to_owned(),
            iso_file: legacy("iso_file"),
            iso_storage_pool: legacy("iso_storage_pool"),
            clone_vm: structured.clone_vm,
            cores: structured.cores,
            memory: structured.memory,
            disk_size: legacy("disk_size"),
            bridge: legacy("bridge"),
            cloud_init_user: legacy("ciuser"),
            ssh_keys: legacy("sshkeys"),
            first_disk_storage_pool: structured.storage_pool,
            first_disk_size: structured.disk_size,
            network_bridge: structured.bridge,
            boot_iso_file: structured.iso_file,
            boot_iso_storage_pool: structured.iso_storage_pool,
        })
    }
}

impl From<RecipeVersion> for RecipeVersionDto {
    fn from(version: RecipeVersion) -> Self {
        let structured = StructuredRecipeDto::of(&version.content);
        Self {
            id: version.id,
            recipe_id: version.recipe_id,
            name: version.name,
            description: version.description,
            content_digest: version.content_digest,
            content: version.content,
            source: version.source.id().to_owned(),
            node: version.node,
            storage_pool: version.storage_pool,
            published_at: version.published_at,
            promoted_at: version.promoted_at,
            promoted_by: version.promoted_by,
            structured,
        }
    }
}

/// The create/update request. The content passes through verbatim.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SaveRecipeRequest {
    /// The recipe name.
    pub name: String,
    /// The recipe description.
    pub description: String,
    /// The PVE node the recipe builds on.
    pub node: String,
    /// The PVE storage pool the build writes to.
    pub storage_pool: String,
    /// What the recipe builds from: `iso` or `clone`.
    pub source: String,
    /// The raw Packer template content, verbatim.
    pub content: String,
}

impl SaveRecipeRequest {
    fn into_content(self) -> Result<RecipeContent, ApiErrorResponse> {
        let source = RecipeSource::from_id(&self.source).map_err(|detail| {
            let public = PublicError::new(
                ErrorCode::from_str("invalid_request")
                    .expect("the literal is valid error code syntax"),
                detail,
                RetryClass::Never,
            );
            ApiError::new(
                &public,
                CorrelationId::from_str("00000000-0000-0000-0000-000000000000")
                    .expect("the literal is valid"),
            )
            .with_status(StatusCode::BAD_REQUEST)
        })?;
        Ok(RecipeContent {
            name: self.name,
            description: self.description,
            node: self.node,
            storage_pool: Some(self.storage_pool),
            source,
            content: self.content,
        })
    }
}

use std::str::FromStr as _;

/// The list-recipes query parameters.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListRecipesParams {
    /// The maximum number of recipes to return.
    pub limit: Option<u32>,
    /// The opaque cursor: the last recipe id of the previous page.
    pub cursor: Option<String>,
}

/// Lists the recipe drafts.
///
/// # Errors
///
/// Returns the public error envelope on refusal or backend failure.
#[utoipa::path(
    get,
    path = "/images/recipes",
    tag = "images",
    operation_id = "listImageRecipes",
    params(
        ("limit" = Option<u32>, Query, description = "The maximum number of recipes to return."),
        ("cursor" = Option<String>, Query, description = "The opaque cursor: the last recipe id of the previous page.")
    ),
    responses(
        (status = 200, description = "The recipe drafts, newest first.", body = Page<RecipeDto>),
        (status = 403, description = "The caller may not read the image surface.", body = crate::error::ApiError),
    )
)]

pub async fn list_image_recipes(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(params): Query<ListRecipesParams>,
) -> Result<Json<Page<RecipeDto>>, ApiErrorResponse> {
    let images = images_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let limit = params
        .limit
        .filter(|limit| *limit > 0)
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .min(MAX_PAGE_LIMIT);
    let mut recipes = images
        .list(state.authorizer.as_ref(), &principal)
        .await
        .map_err(|error| map_images_error(&error, correlation_id))?;
    if let Some(cursor) = &params.cursor {
        let Some(position) = recipes.iter().position(|recipe| recipe.id == *cursor) else {
            return Err(crate::machines::invalid_request(
                "the cursor names no recipe in the list",
                correlation_id,
            ));
        };
        recipes.drain(..=position);
    }
    recipes.truncate(usize::try_from(limit).unwrap_or(recipes.len()));
    let next_cursor = (recipes.len() == usize::try_from(limit).unwrap_or(0))
        .then(|| recipes.last().map(|recipe| recipe.id.clone()))
        .flatten();
    let items: Vec<RecipeDto> = recipes.into_iter().map(Into::into).collect();
    Ok(Json(Page {
        page: PageInfo { next_cursor, limit },
        items,
    }))
}

/// Creates a recipe draft.
///
/// # Errors
///
/// Returns the public error envelope on refusal, conflict, or malformed
/// request.
#[utoipa::path(
    post,
    path = "/images/recipes",
    tag = "images",
    operation_id = "createImageRecipe",
    request_body = SaveRecipeRequest,
    responses(
        (status = 201, description = "The draft was created.", body = Resource<RecipeDto>),
        (status = 400, description = "The request is malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not configure the image surface.", body = crate::error::ApiError),
        (status = 409, description = "The recipe name is taken.", body = crate::error::ApiError),
    )
)]
pub async fn create_image_recipe(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Json(request): Json<SaveRecipeRequest>,
) -> Result<(StatusCode, Json<Resource<RecipeDto>>), ApiErrorResponse> {
    let images = images_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let content = request.into_content()?;
    let recipe = images
        .create(
            state.authorizer.as_ref(),
            &principal,
            NewRecipe { content },
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_images_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(recipe.into()))))
}

/// Reads one draft.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown recipe.
#[utoipa::path(
    get,
    path = "/images/recipes/{recipeId}",
    tag = "images",
    operation_id = "getImageRecipe",
    params(("recipeId" = String, Path, description = "The recipe's identity.")),
    responses(
        (status = 200, description = "The draft.", body = Resource<RecipeDto>),
        (status = 403, description = "The caller may not read the image surface.", body = crate::error::ApiError),
        (status = 404, description = "The recipe does not exist.", body = crate::error::ApiError),
    )
)]
pub async fn get_image_recipe(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(recipe_id): Path<String>,
) -> Result<Json<Resource<RecipeDto>>, ApiErrorResponse> {
    let images = images_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let recipe = images
        .get(state.authorizer.as_ref(), &principal, &recipe_id)
        .await
        .map_err(|error| map_images_error(&error, correlation_id))?;
    Ok(Json(Resource::new(recipe.into())))
}

/// Replaces a draft's content.
///
/// # Errors
///
/// Returns the public error envelope on refusal, malformed request, or
/// unknown recipe.
#[utoipa::path(
    put,
    path = "/images/recipes/{recipeId}",
    tag = "images",
    operation_id = "updateImageRecipe",
    params(("recipeId" = String, Path, description = "The recipe's identity.")),
    request_body = SaveRecipeRequest,
    responses(
        (status = 200, description = "The draft was updated.", body = Resource<RecipeDto>),
        (status = 400, description = "The request is malformed.", body = crate::error::ApiError),
        (status = 404, description = "The recipe does not exist.", body = crate::error::ApiError),
    )
)]
pub async fn update_image_recipe(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(recipe_id): Path<String>,
    Json(request): Json<SaveRecipeRequest>,
) -> Result<Json<Resource<RecipeDto>>, ApiErrorResponse> {
    let images = images_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let content = request.into_content()?;
    let recipe = images
        .update(
            state.authorizer.as_ref(),
            &principal,
            &recipe_id,
            content,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_images_error(&error, correlation_id))?;
    Ok(Json(Resource::new(recipe.into())))
}

/// Removes a draft. Published versions are immutable and stay.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown recipe.
#[utoipa::path(
    delete,
    path = "/images/recipes/{recipeId}",
    tag = "images",
    operation_id = "deleteImageRecipe",
    params(("recipeId" = String, Path, description = "The recipe's identity.")),
    responses(
        (status = 204, description = "The draft was removed."),
        (status = 404, description = "The recipe does not exist.", body = crate::error::ApiError),
    )
)]
pub async fn delete_image_recipe(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(recipe_id): Path<String>,
) -> Result<StatusCode, ApiErrorResponse> {
    let images = images_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    images
        .delete(state.authorizer.as_ref(), &principal, &recipe_id)
        .await
        .map_err(|error| map_images_error(&error, correlation_id))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Publishes a draft: freezes an immutable version identified by its
/// content digest. Idempotent by construction.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown recipe.
#[utoipa::path(
    post,
    path = "/images/recipes/{recipeId}/publish",
    tag = "images",
    operation_id = "publishImageRecipe",
    params(("recipeId" = String, Path, description = "The recipe's identity.")),
    responses(
        (status = 201, description = "The version was published.", body = Resource<RecipeVersionDto>),
        (status = 404, description = "The recipe does not exist.", body = crate::error::ApiError),
    )
)]
pub async fn publish_image_recipe(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(recipe_id): Path<String>,
) -> Result<(StatusCode, Json<Resource<RecipeVersionDto>>), ApiErrorResponse> {
    let images = images_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let version = images
        .publish(
            state.authorizer.as_ref(),
            &principal,
            &recipe_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_images_error(&error, correlation_id))?;
    Ok((StatusCode::CREATED, Json(Resource::new(version.into()))))
}

/// Lists a recipe's published versions.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown recipe.
#[utoipa::path(
    get,
    path = "/images/recipes/{recipeId}/versions",
    tag = "images",
    operation_id = "listImageRecipeVersions",
    params(("recipeId" = String, Path, description = "The recipe's identity.")),
    responses(
        (status = 200, description = "The published versions, newest first.", body = Page<RecipeVersionDto>),
        (status = 403, description = "The caller may not read the image surface.", body = crate::error::ApiError),
    )
)]
pub async fn list_image_recipe_versions(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(recipe_id): Path<String>,
) -> Result<Json<Page<RecipeVersionDto>>, ApiErrorResponse> {
    let images = images_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let versions = images
        .list_versions(state.authorizer.as_ref(), &principal, &recipe_id)
        .await
        .map_err(|error| map_images_error(&error, correlation_id))?;
    let items: Vec<RecipeVersionDto> = versions.into_iter().map(Into::into).collect();
    Ok(Json(Page {
        page: PageInfo {
            next_cursor: None,
            limit: items.len().try_into().unwrap_or(u32::MAX),
        },
        items,
    }))
}

/// The build request: which version to build and the deadline.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BuildImageRequest {
    /// The published recipe version to build.
    pub version_id: String,
    /// The deadline, in seconds. Bounded by the executor.
    pub timeout_seconds: u64,
    /// Target account override; otherwise resolved from the recipe endpoint.
    pub account_id: Option<String>,
    /// The secret-backed build variables, as name/reference pairs. The
    /// values never enter argv, logs, or audit metadata.
    #[serde(default)]
    pub secret_vars: Vec<SecretVarDto>,
}

/// One secret-backed build variable.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretVarDto {
    /// The Packer variable name.
    pub name: String,
    /// The secret reference id.
    pub reference: String,
}

/// Starts a build of one published version as a durable operation. The
/// executor verifies the CLI version, validates the recipe, and runs the
/// build over the operator-installed Packer CLI.
///
/// # Errors
///
/// Returns the public error envelope on refusal or a malformed request.
#[utoipa::path(
    post,
    path = "/images/builds",
    tag = "images",
    operation_id = "startImageBuild",
    request_body = BuildImageRequest,
    responses(
        (status = 202, description = "The build operation was accepted and is durable.", body = Resource<crate::operations::OperationDto>),
        (status = 400, description = "The request is malformed.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not configure the image surface.", body = crate::error::ApiError),
        (status = 404, description = "The version does not exist.", body = crate::error::ApiError),
    )
)]
pub async fn start_image_build(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    headers: axum::http::HeaderMap,
    Json(request): Json<BuildImageRequest>,
) -> Result<(StatusCode, Json<Resource<crate::operations::OperationDto>>), ApiErrorResponse> {
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    if let Err(decision) = fleet_application::authz::authorize(
        state.authorizer.as_ref(),
        fleet_application::authz::AccessRequest {
            principal_id: &principal.id,
            action: fleet_application::authz::Permission::ImagesConfig,
            resource: None,
        },
    ) {
        return Err(crate::machines::denied_error(decision, correlation_id));
    }
    if request.timeout_seconds == 0 || request.timeout_seconds > 4 * 60 * 60 {
        return Err(crate::machines::invalid_request(
            "the timeout must be 1..=14400 seconds",
            correlation_id,
        ));
    }
    // The version must exist before the operation is queued: an invalid
    // build is a 404 here, not a worker failure later.
    if let Some(images) = &state.images {
        images
            .get_version(state.authorizer.as_ref(), &principal, &request.version_id)
            .await
            .map_err(|error| map_images_error(&error, correlation_id))?;
    }
    let payload = serde_json::json!({
        "versionId": request.version_id,
        "timeoutSeconds": request.timeout_seconds,
        "accountId": request.account_id,
        "secretVars": request.secret_vars,
    });
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
                kind: "image.build".to_owned(),
                idempotency_key,
                deadline_at: None,
                correlation_id: Some(correlation_id.to_string()),
                payload_json: Some(payload.to_string()),
                review_token: None,
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

/// Promotes one version as the recipe's built image. The gate verifies
/// the latest immutable build record has matching inputs and a successful
/// output template.
///
/// # Errors
///
/// Returns the public error envelope on refusal, an unknown version, or a
/// gate refusal.
#[utoipa::path(
    post,
    path = "/images/versions/{versionId}/promote",
    tag = "images",
    operation_id = "promoteImageVersion",
    params(("versionId" = String, Path, description = "The version's identity.")),
    responses(
        (status = 200, description = "The version was promoted; the recipe's previous promotion was demoted explicitly.", body = Resource<RecipeVersionDto>),
        (status = 400, description = "The promotion gate refused: no successful build or no artifact.", body = crate::error::ApiError),
        (status = 403, description = "The caller may not configure the image surface.", body = crate::error::ApiError),
        (status = 404, description = "The version does not exist.", body = crate::error::ApiError),
    )
)]
pub async fn promote_image_version(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(version_id): Path<String>,
) -> Result<Json<Resource<RecipeVersionDto>>, ApiErrorResponse> {
    let images = images_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let version = images
        .promote(
            state.authorizer.as_ref(),
            &principal,
            &version_id,
            fleet_core::SystemClock::now_unix_millis(),
        )
        .await
        .map_err(|error| map_images_error(&error, correlation_id))?;
    Ok(Json(Resource::new(version.into())))
}

/// Reads one published version with its structured view.
///
/// # Errors
///
/// Returns the public error envelope on refusal or an unknown version.
#[utoipa::path(
    get,
    path = "/images/versions/{versionId}",
    tag = "images",
    operation_id = "getImageVersion",
    params(("versionId" = String, Path, description = "The version's identity.")),
    responses(
        (status = 200, description = "The version with its structured view.", body = Resource<RecipeVersionDto>),
        (status = 403, description = "The caller may not read the image surface.", body = crate::error::ApiError),
        (status = 404, description = "The version does not exist.", body = crate::error::ApiError),
    )
)]
pub async fn get_image_version(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(version_id): Path<String>,
) -> Result<Json<Resource<RecipeVersionDto>>, ApiErrorResponse> {
    let images = images_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let version = images
        .get_version(state.authorizer.as_ref(), &principal, &version_id)
        .await
        .map_err(|error| map_images_error(&error, correlation_id))?;
    Ok(Json(Resource::new(version.into())))
}

/// Safe build provenance and outcome; credentials and work paths are excluded.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageBuildDto {
    /// Build identity.
    pub id: String,
    /// Durable operation identity.
    pub operation_id: String,
    /// Recipe identity.
    pub recipe_id: String,
    /// Immutable version identity.
    pub version_id: String,
    /// Frozen recipe digest.
    pub content_digest: String,
    /// Frozen provisioning asset digests.
    pub asset_digests: Vec<String>,
    /// Probed Packer version, when available.
    pub packer_version: Option<String>,
    /// Probed Proxmox plugin version, when available.
    pub proxmox_plugin_version: Option<String>,
    /// Resolved target account; absent when target binding failed.
    pub account_id: Option<String>,
    /// Frozen target node.
    pub node: String,
    /// Frozen target storage.
    pub storage_pool: String,
    /// Start time in epoch milliseconds.
    pub started_at: i64,
    /// End time in epoch milliseconds.
    pub ended_at: Option<i64>,
    /// Running, succeeded, failed or cancelled.
    pub outcome: String,
    /// Safe terminal reason code.
    pub reason: Option<String>,
    /// Output template identity.
    pub template: Option<ImageBuildTemplateDto>,
}

/// A concrete output template identity.
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageBuildTemplateDto {
    /// Template node.
    pub node: String,
    /// Template VMID.
    pub vmid: u32,
    /// Template name.
    pub name: String,
}

impl From<fleet_core::ImageBuildRecord> for ImageBuildDto {
    fn from(record: fleet_core::ImageBuildRecord) -> Self {
        Self {
            id: record.id,
            operation_id: record.operation_id,
            recipe_id: record.recipe_id,
            version_id: record.version_id,
            content_digest: record.content_digest,
            asset_digests: record.asset_digests,
            packer_version: record.packer_version,
            proxmox_plugin_version: record.proxmox_plugin_version,
            account_id: record.account_id,
            node: record.node,
            storage_pool: record.storage_pool,
            started_at: record.started_at,
            ended_at: record.ended_at,
            outcome: record.outcome,
            reason: record.reason,
            template: record.template.map(|template| ImageBuildTemplateDto {
                node: template.node,
                vmid: template.vmid,
                name: template.name,
            }),
        }
    }
}

/// Build history filters.
#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct BuildQuery {
    /// Maximum records per page (default 50, maximum 200).
    pub limit: Option<u32>,
    /// Last build identity returned by the preceding page.
    pub cursor: Option<String>,
    /// Filter by recipe identity.
    pub recipe_id: Option<String>,
    /// Filter by immutable version identity.
    pub version_id: Option<String>,
}

/// Lists recorded image builds under images.read.
///
/// # Errors
/// Returns the standard error envelope on denial or backend failure.
#[utoipa::path(get, path = "/images/builds", tag = "images", operation_id = "listImageBuilds",
    params(BuildQuery), responses(
        (status = 400, description = "Invalid build cursor.", body = crate::error::ApiError),
        (status = 200, description = "Build records, newest first.", body = Page<ImageBuildDto>),
        (status = 403, description = "Images read permission is required.", body = crate::error::ApiError)
    ))]
pub async fn list_image_builds(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Query(query): Query<BuildQuery>,
) -> Result<Json<Page<ImageBuildDto>>, ApiErrorResponse> {
    let images = images_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let records = images
        .list_build_page(
            state.authorizer.as_ref(),
            &principal,
            fleet_application::images::BuildPageRequest {
                recipe: query.recipe_id,
                version: query.version_id,
                cursor: query.cursor,
                limit: query.limit.unwrap_or_default(),
            },
        )
        .await
        .map_err(|error| map_images_error(&error, correlation_id))?;
    let items: Vec<ImageBuildDto> = records.items.into_iter().map(Into::into).collect();
    Ok(Json(Page {
        page: PageInfo {
            next_cursor: records.next_cursor,
            limit: records.limit,
        },
        items,
    }))
}

/// Reads one recorded image build under images.read.
///
/// # Errors
/// Returns the standard error envelope on denial, missing record or backend failure.
#[utoipa::path(get, path = "/images/builds/{buildId}", tag = "images", operation_id = "getImageBuild",
    params(("buildId" = String, Path, description = "Build identity.")), responses(
        (status = 200, description = "Safe build provenance and outcome.", body = Resource<ImageBuildDto>),
        (status = 403, description = "Images read permission is required.", body = crate::error::ApiError),
        (status = 404, description = "Build record not found.", body = crate::error::ApiError)
    ))]
pub async fn get_image_build(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
    Path(id): Path<String>,
) -> Result<Json<Resource<ImageBuildDto>>, ApiErrorResponse> {
    let images = images_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let record = images
        .get_build(state.authorizer.as_ref(), &principal, &id)
        .await
        .map_err(|error| map_images_error(&error, correlation_id))?;
    Ok(Json(Resource::new(record.into())))
}

#[cfg(test)]
mod structured_dto_tests {
    use super::StructuredRecipeDto;

    #[test]
    fn the_v1_fields_keep_their_published_meaning_beside_the_plugin_fields() {
        let content = r#"{"builders": [{
            "type": "proxmox-iso", "node": "pve",
            "vm_storage_pool": "legacy-pool", "disk_size": "9G", "bridge": "vmbr9",
            "ciuser": "dev", "sshkeys": "ssh-ed25519%20AAA", "iso_file": "local:iso/old.iso",
            "boot_iso": {"iso_file": "local:iso/new.iso", "iso_storage_pool": "local"},
            "disks": [{"type": "scsi", "storage_pool": "local-lvm", "disk_size": "20G"}],
            "network_adapters": [{"model": "virtio", "bridge": "vmbr0"}]
        }]}"#;
        let dto = StructuredRecipeDto::of(content).expect("a structured view");
        // /api/v1 (deprecated): top-level keys, as published.
        assert_eq!(dto.storage_pool, "legacy-pool");
        assert_eq!(dto.disk_size.as_deref(), Some("9G"));
        assert_eq!(dto.bridge.as_deref(), Some("vmbr9"));
        assert_eq!(dto.cloud_init_user.as_deref(), Some("dev"));
        assert_eq!(dto.ssh_keys.as_deref(), Some("ssh-ed25519%20AAA"));
        assert_eq!(dto.iso_file.as_deref(), Some("local:iso/old.iso"));
        // The plugin schema (#278).
        assert_eq!(dto.first_disk_storage_pool.as_deref(), Some("local-lvm"));
        assert_eq!(dto.first_disk_size.as_deref(), Some("20G"));
        assert_eq!(dto.network_bridge.as_deref(), Some("vmbr0"));
        assert_eq!(dto.boot_iso_file.as_deref(), Some("local:iso/new.iso"));
        assert_eq!(dto.boot_iso_storage_pool.as_deref(), Some("local"));
        assert!(StructuredRecipeDto::of("source \"proxmox-iso\" \"x\" {}").is_none());
    }
}
