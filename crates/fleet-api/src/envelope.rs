use serde::Serialize;
use utoipa::ToSchema;

/// The default number of items a list endpoint returns.
pub const DEFAULT_PAGE_LIMIT: u32 = 50;

/// The largest page a caller may request.
pub const MAX_PAGE_LIMIT: u32 = 200;

/// A single resource.
///
/// The payload is nested under `data` so that later top-level fields are an
/// additive change rather than a breaking one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct Resource<T> {
    /// The resource representation.
    pub data: T,
}

impl<T> Resource<T> {
    /// Wraps a resource representation.
    pub const fn new(data: T) -> Self {
        Self { data }
    }
}

/// Where a list response sits in its result set.
///
/// Pagination is cursor-based, never offset-based: an offset silently skips or
/// repeats rows when the underlying set changes between requests. The cursor is
/// opaque, and a client that parses one is relying on an implementation detail
/// that is free to change.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PageInfo {
    /// Cursor for the next page, or `null` on the last page.
    pub next_cursor: Option<String>,
    /// The number of items this page was limited to.
    #[schema(example = 50)]
    pub limit: u32,
}

/// A page of resources.
///
/// The concrete schema for a list endpoint appears when that endpoint does;
/// [`PageInfo`] is the part of the shape that is fixed for every one of them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct Page<T> {
    /// The items on this page, in the endpoint's documented order.
    pub items: Vec<T>,
    /// Where this page sits in the result set.
    pub page: PageInfo,
}

/// The lifecycle state of a durable operation.
///
/// FM-108 owns the operation model itself. This enum exists so the accepted
/// envelope has a typed status from the start.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum OperationStatus {
    /// Accepted and durable, not yet started.
    Pending,
    /// Started and not yet terminal.
    Running,
    /// Finished successfully.
    Succeeded,
    /// Finished unsuccessfully.
    Failed,
    /// Stopped before completion.
    Cancelled,
}

/// What a mutation returns instead of holding the request open.
///
/// Per ADR-0002, a long infrastructure workflow is a durable operation the
/// caller polls or subscribes to, not an HTTP request kept alive for minutes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperationAccepted {
    /// Opaque identity of the durable operation.
    #[schema(example = "01900a3c-e8a9-75ba-9337-94a8e6b7d3a9")]
    pub operation_id: String,
    /// The operation's state at the time the response was written.
    pub status: OperationStatus,
    /// Correlation identity shared by the request, the operation, and its audit
    /// events.
    #[schema(example = "01900a3c-b576-7287-a004-61d5b384a076")]
    pub correlation_id: String,
}
