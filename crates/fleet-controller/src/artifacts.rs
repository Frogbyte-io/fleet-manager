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
//!
//! The same directory carries the `fleetctl` binaries built with this
//! controller (`<dir>/fleetctl/fleetctl-<platform>[.exe]`, the names the
//! GitHub release assets use). `GET /downloads/fleetctl/<platform>` serves
//! one, with its sha256 in the `x-checksum-sha256` header, and
//! `GET /downloads/fleetctl/<platform>.sha256` serves the digest as a
//! `sha256sum`-format line. The platform comes from a fixed list, so no
//! request path reaches the filesystem; a platform the controller does not
//! carry answers 404. Both routes sit behind the listener's caller
//! resolution, like the `fleetd` package.

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderName, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

/// The response header carrying a served binary's sha256, lowercase hex.
pub const CHECKSUM_HEADER: HeaderName = HeaderName::from_static("x-checksum-sha256");

/// The `fleetctl` platforms the download route knows, with the file each
/// one is stored as under `<artifacts_dir>/fleetctl/` and the name it is
/// saved as. A platform here that the directory lacks answers 404.
const FLEETCTL_PLATFORMS: &[(&str, &str, &str)] = &[
    ("linux-x86_64", "fleetctl-linux-x86_64", "fleetctl"),
    ("linux-aarch64", "fleetctl-linux-aarch64", "fleetctl"),
    (
        "windows-x86_64",
        "fleetctl-windows-x86_64.exe",
        "fleetctl.exe",
    ),
];

/// Builds the router serving `<artifacts_dir>/fleetd/<file>` and the
/// `fleetctl` binaries under `/downloads`.
pub fn artifacts_router(artifacts_dir: PathBuf) -> Router {
    let root = Arc::new(artifacts_dir);
    Router::new()
        .route(
            "/fleetd/{*file}",
            get(serve_artifact).with_state(Arc::clone(&root)),
        )
        .route("/fleetctl/{file}", get(serve_fleetctl).with_state(root))
}

/// Serves `fleetctl` for one platform, or its digest for `<platform>.sha256`.
async fn serve_fleetctl(
    State(root): State<Arc<PathBuf>>,
    AxumPath(file): AxumPath<String>,
) -> Response {
    let (platform, digest_only) = match file.strip_suffix(".sha256") {
        Some(platform) => (platform, true),
        None => (file.as_str(), false),
    };
    let Some(&(_, stored, saved_as)) = FLEETCTL_PLATFORMS
        .iter()
        .find(|(known, _, _)| *known == platform)
    else {
        return not_found();
    };
    let path = root.join("fleetctl").join(stored);
    // The binary is tens of megabytes; read and hash it off the runtime.
    let loaded = tokio::task::spawn_blocking(move || {
        if !path.is_file() {
            return None;
        }
        let bytes = std::fs::read(&path).ok()?;
        let digest = sha256_hex(&bytes);
        Some((bytes, digest))
    })
    .await
    .ok()
    .flatten();
    let Some((bytes, digest)) = loaded else {
        return not_found();
    };
    if digest_only {
        return (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("{digest}  {saved_as}\n"),
        )
            .into_response();
    }
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{saved_as}\""),
            ),
            (CHECKSUM_HEADER, digest),
        ],
        bytes,
    )
        .into_response()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        })
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
        Ok(bytes) => ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response(),
        Err(_) => not_found(),
    }
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt as _;

    const LINUX_BINARY: &[u8] = b"\x7fELF pretend fleetctl";
    // sha256 of LINUX_BINARY, computed independently with `sha256sum`.
    const LINUX_DIGEST: &str = "5b6b64736fef6e45fe99dbc623b041a35ce07b47b10e4bf79da8a2fe8703c7d1";

    fn artifacts() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("fleetctl")).unwrap();
        std::fs::write(
            dir.path().join("fleetctl/fleetctl-linux-x86_64"),
            LINUX_BINARY,
        )
        .unwrap();
        dir
    }

    async fn get(dir: &std::path::Path, uri: &str) -> Response {
        artifacts_router(dir.to_path_buf())
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn body(response: Response) -> Vec<u8> {
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn serves_the_binary_for_a_carried_platform_with_its_digest() {
        let dir = artifacts();
        let response = get(dir.path(), "/fleetctl/linux-x86_64").await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers().clone();
        assert_eq!(headers[header::CONTENT_TYPE], "application/octet-stream");
        assert_eq!(
            headers[header::CONTENT_DISPOSITION],
            "attachment; filename=\"fleetctl\""
        );
        assert_eq!(headers[CHECKSUM_HEADER], LINUX_DIGEST);
        assert_eq!(body(response).await, LINUX_BINARY);
    }

    #[tokio::test]
    async fn serves_a_sha256sum_line_beside_the_binary() {
        let dir = artifacts();
        let response = get(dir.path(), "/fleetctl/linux-x86_64.sha256").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            String::from_utf8(body(response).await).unwrap(),
            format!("{LINUX_DIGEST}  fleetctl\n")
        );
    }

    #[tokio::test]
    async fn windows_saves_as_an_exe() {
        let dir = artifacts();
        std::fs::write(
            dir.path().join("fleetctl/fleetctl-windows-x86_64.exe"),
            b"MZ",
        )
        .unwrap();
        let response = get(dir.path(), "/fleetctl/windows-x86_64").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=\"fleetctl.exe\""
        );
        let digest = get(dir.path(), "/fleetctl/windows-x86_64.sha256").await;
        assert!(
            String::from_utf8(body(digest).await)
                .unwrap()
                .ends_with("  fleetctl.exe\n")
        );
    }

    #[tokio::test]
    async fn a_platform_the_controller_does_not_carry_is_not_found() {
        let dir = artifacts();
        for uri in [
            "/fleetctl/linux-aarch64",
            "/fleetctl/linux-aarch64.sha256",
            "/fleetctl/windows-x86_64",
        ] {
            let response = get(dir.path(), uri).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
            assert_eq!(body(response).await, b"not found", "{uri}");
        }
    }

    #[tokio::test]
    async fn unknown_platforms_and_stored_names_are_not_found() {
        let dir = artifacts();
        // The stored file name is not itself a platform, and nothing outside
        // the fixed list reaches the filesystem.
        for uri in [
            "/fleetctl/fleetctl-linux-x86_64",
            "/fleetctl/darwin-aarch64",
            "/fleetctl/..%2Ffleetctl%2Ffleetctl-linux-x86_64",
            "/fleetctl/.sha256",
            "/fleetctl/linux-x86_64/extra",
        ] {
            let response = get(dir.path(), uri).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        }
    }

    #[tokio::test]
    async fn a_controller_without_a_fleetctl_directory_answers_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let response = get(dir.path(), "/fleetctl/linux-x86_64").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
