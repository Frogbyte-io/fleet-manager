//! Guards on the generated `OpenAPI` document.
//!
//! The document is a published contract consumed by a generated client, so the
//! failure mode that matters is drift: code changes, document does not, and the
//! client silently describes an API that no longer exists.

use std::{fs, path::PathBuf};

use fleet_api::openapi_json;
use serde_json::Value;

fn checked_in_document() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the api crate lives two directories below the repository root")
        .join("packages/api-client/openapi.json");
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "the generated document must be committed at {}: {error}",
            path.display()
        )
    })
}

#[test]
fn generation_is_reproducible() {
    assert_eq!(openapi_json(), openapi_json());
}

#[test]
fn the_checked_in_document_matches_the_code() {
    assert_eq!(
        checked_in_document(),
        openapi_json(),
        "run `cargo run -p fleet-api --bin fleet-openapi -- generate`"
    );
}

#[test]
fn the_document_publishes_the_conventions_no_endpoint_uses_yet() {
    let document: Value =
        serde_json::from_str(&openapi_json()).expect("the document is valid JSON");
    let schemas = &document["components"]["schemas"];

    for schema in [
        "ApiError",
        "FieldViolation",
        "Retry",
        "PageInfo",
        "OperationAccepted",
        "OperationStatus",
    ] {
        assert!(
            !schemas[schema].is_null(),
            "{schema} must stay in the published contract even before an endpoint returns it"
        );
    }
}

#[test]
fn the_document_serves_every_path_under_the_versioned_prefix() {
    let document: Value =
        serde_json::from_str(&openapi_json()).expect("the document is valid JSON");
    let paths = document["paths"]
        .as_object()
        .expect("the document declares paths");

    assert!(paths.contains_key("/api/v1/meta"));
    for path in paths.keys() {
        assert!(
            path.starts_with("/api/v1/"),
            "{path} is published outside the versioned prefix"
        );
    }
}
