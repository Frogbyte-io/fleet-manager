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
    extract::{Path, State},
    http::StatusCode,
};
use fleet_application::images::{NewRecipe, Recipe, RecipeUseCaseError, RecipeVersion};
use fleet_core::{CorrelationId, ErrorCode, PublicError, RecipeContent, RecipeSource, RetryClass};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{Page, PageInfo, Resource};
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
            storage_pool: recipe.content.storage_pool,
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
}

impl From<RecipeVersion> for RecipeVersionDto {
    fn from(version: RecipeVersion) -> Self {
        Self {
            id: version.id,
            recipe_id: version.recipe_id,
            name: version.name,
            content_digest: version.content_digest,
            content: version.content,
            source: version.source.id().to_owned(),
            node: version.node,
            storage_pool: version.storage_pool,
            published_at: version.published_at,
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
            storage_pool: self.storage_pool,
            source,
            content: self.content,
        })
    }
}

use std::str::FromStr as _;

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
    responses(
        (status = 200, description = "The recipe drafts, newest first.", body = Page<RecipeDto>),
        (status = 403, description = "The caller may not read the image surface.", body = crate::error::ApiError),
    )
)]
pub async fn list_image_recipes(
    State(state): State<Arc<crate::operations::ApiState>>,
    principal: Option<Extension<crate::ActingPrincipal>>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<Page<RecipeDto>>, ApiErrorResponse> {
    let images = images_or_error(&state, correlation_id)?;
    let principal = crate::operations::principal_or_error(principal, correlation_id)?;
    let recipes = images
        .list(state.authorizer.as_ref(), &principal)
        .await
        .map_err(|error| map_images_error(&error, correlation_id))?;
    let items: Vec<RecipeDto> = recipes.into_iter().map(Into::into).collect();
    Ok(Json(Page {
        page: PageInfo {
            next_cursor: None,
            limit: items.len().try_into().unwrap_or(u32::MAX),
        },
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
    let payload = serde_json::json!({
        "versionId": request.version_id,
        "timeoutSeconds": request.timeout_seconds,
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
