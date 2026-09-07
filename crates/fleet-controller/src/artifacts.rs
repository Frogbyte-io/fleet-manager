//! The download surface: node artifacts the controller itself distributes.
//!
//! The service package lives in one directory on the controller host
//! (`Settings::artifacts_dir`, `<dir>/fleetd/`); `GET /downloads/fleetd/<file>`
//! serves it as an opaque octet stream. The node — or any operator script —
//! downloads it over the LAN and verifies the archive's sha256 before
//! installing; serving is dumb on purpose: no listing, no generation, no
//! auth surface beyond the trusted-LAN wrapper this controller already
//! runs behind.
//!
//! Path containment is structural: the request path is canonicalized and
//! must stay inside the artifact directory; traversal attempts answer 404,
//! never an error message about the filesystem.

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;

/// Builds the router serving `<artifacts_dir>/fleetd/<file>` under
/// `/downloads`.
pub fn artifacts_router(artifacts_dir: PathBuf) -> Router {
    Router::new().route(
        "/fleetd/{*file}",
        get(serve_artifact).with_state(Arc::new(artifacts_dir)),
    )
}

async fn serve_artifact(
    State(root): State<Arc<PathBuf>>,
    AxumPath(file): AxumPath<String>,
) -> Response {
    let requested = PathBuf::from(&file);
    if requested.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    }) {
        return not_found();
    }
    let base = root.join("fleetd");
    let resolved = base.join(&requested);
    let Ok(canonical) = resolved.canonicalize() else {
        return not_found();
    };
    let Ok(base_canonical) = base.canonicalize() else {
        return not_found();
    };
    if !canonical.starts_with(&base_canonical) || !canonical.is_file() {
        return not_found();
    }
    match tokio::fs::read(&canonical).await {
        Ok(bytes) => (
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(_) => not_found(),
    }
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}
