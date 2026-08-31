use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use fleet_core::{CorrelationId, PublicError, RetryClass};
use serde::Serialize;
use utoipa::ToSchema;

/// Whether and how a caller may retry a failed request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum Retry {
    /// Retrying the same request is not expected to succeed.
    Never,
    /// The request may be retried immediately.
    Immediate,
    /// The request may be retried after exponential backoff.
    Backoff,
}

impl From<RetryClass> for Retry {
    fn from(class: RetryClass) -> Self {
        match class {
            RetryClass::Never => Self::Never,
            RetryClass::Immediate => Self::Immediate,
            RetryClass::Backoff => Self::Backoff,
        }
    }
}

/// One rejected input, identified by its location in the request body or query.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FieldViolation {
    /// JSON pointer into the request body, or a query parameter name.
    #[schema(example = "/spec/name")]
    pub field: String,
    /// Stable machine-readable reason this field was rejected.
    #[schema(example = "invalid_slug")]
    pub code: String,
    /// Caller-safe explanation.
    pub message: String,
}

/// The body of every unsuccessful response.
///
/// It is built from [`PublicError`], which is the type that decides what is
/// safe to disclose. Internal causes, provider output, and secret values are
/// excluded there rather than filtered here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    /// Stable machine-readable code. Clients branch on this, not on `message`.
    #[schema(example = "malformed_correlation_id")]
    pub code: String,
    /// Caller-safe human-readable summary.
    pub message: String,
    /// Retry guidance for this specific failure.
    pub retry: Retry,
    /// The correlation identity of the request that failed. It is also returned
    /// in the `x-correlation-id` response header, and is what an operator needs
    /// to find the request in the audit trail.
    #[schema(example = "01900a3c-b576-7287-a004-61d5b384a076")]
    pub correlation_id: String,
    /// Per-field rejections, when the failure is a validation failure.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub field_violations: Vec<FieldViolation>,
}

impl ApiError {
    /// Builds the error body from a domain failure and the failing request's
    /// correlation identity.
    #[must_use]
    pub fn new(error: &PublicError, correlation_id: CorrelationId) -> Self {
        Self {
            code: error.code().to_string(),
            message: error.message().to_owned(),
            retry: error.retry().into(),
            correlation_id: correlation_id.to_string(),
            field_violations: Vec::new(),
        }
    }

    /// Attaches per-field rejections.
    #[must_use]
    pub fn with_field_violations(mut self, violations: Vec<FieldViolation>) -> Self {
        self.field_violations = violations;
        self
    }

    /// Pairs this body with the status code the response carries.
    #[must_use]
    pub const fn with_status(self, status: StatusCode) -> ApiErrorResponse {
        ApiErrorResponse { status, body: self }
    }
}

/// An [`ApiError`] and the status code it is returned with.
///
/// The status is deliberately not part of the serialized body: it is already on
/// the response, and duplicating it invites the two to disagree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiErrorResponse {
    status: StatusCode,
    body: ApiError,
}

impl ApiErrorResponse {
    /// Returns the status code this failure is returned with.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the serialized failure body.
    #[must_use]
    pub const fn body(&self) -> &ApiError {
        &self.body
    }
}

impl IntoResponse for ApiErrorResponse {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}
