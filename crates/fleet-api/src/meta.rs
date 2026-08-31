use axum::{Extension, Json};
use fleet_core::CorrelationId;
use serde::Serialize;
use utoipa::ToSchema;

use crate::{API_VERSION, envelope::Resource};

/// Non-authoritative description of the API this controller serves.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    /// The version segment of the served API path.
    #[schema(example = "v1")]
    pub api_version: String,
    /// The service that answered, for operators reading a proxied response.
    #[schema(example = "fleet-controller")]
    pub service: String,
}

/// Returns the served API version.
///
/// This endpoint reads no state, requires no authorization, and creates no
/// operation. It exists so the conventions in this crate are exercised end to
/// end before any resource endpoint exists.
#[utoipa::path(
    get,
    path = "/meta",
    tag = "meta",
    operation_id = "getMeta",
    responses(
        (
            status = 200,
            description = "The API version this controller serves.",
            body = Resource<Meta>,
            headers(("x-correlation-id" = String, description = "Correlation identity of this request."))
        ),
        (
            status = 400,
            description = "The supplied x-correlation-id header was not a canonical opaque Fleet identity.",
            body = crate::error::ApiError
        ),
    )
)]
pub async fn get_meta(
    Extension(_correlation_id): Extension<CorrelationId>,
) -> Json<Resource<Meta>> {
    Json(Resource::new(Meta {
        api_version: API_VERSION.to_owned(),
        service: "fleet-controller".to_owned(),
    }))
}
