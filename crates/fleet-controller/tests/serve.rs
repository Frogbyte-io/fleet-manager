//! Exercises the composed controller over real HTTP: health probes, the
//! static web shell, and the public API behind one listener. The transport is
//! a raw HTTP/1.0 request so the test holds no HTTP client dependency.

use std::path::Path;
use std::time::Duration;

use fleet_controller::{Settings, serve_on};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Writes a minimal web shell distribution: an entry point and an asset.
fn shell_dist() -> tempfile::TempDir {
    let dist = tempfile::tempdir().expect("temporary web dist must create");
    std::fs::write(dist.path().join("index.html"), "<html>fleet shell</html>\n")
        .expect("index.html must write");
    std::fs::create_dir(dist.path().join("assets")).expect("assets dir must create");
    std::fs::write(
        dist.path().join("assets").join("app.js"),
        "console.log('fleet');\n",
    )
    .expect("app.js must write");
    dist
}

fn settings(web_dist: &Path) -> Settings {
    Settings {
        listen: "127.0.0.1:0"
            .parse()
            .expect("the test listen address must parse"),
        web_dist: web_dist.to_path_buf(),
    }
}

/// Binds an ephemeral listener, starts the server with a manual shutdown
/// trigger, and returns the bound address plus the trigger's sender.
async fn spawn(settings: Settings) -> (std::net::SocketAddr, oneshot::Sender<()>) {
    let listener = TcpListener::bind(settings.listen)
        .await
        .expect("listener must bind");
    let address = listener
        .local_addr()
        .expect("bound listener must report its address");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        serve_on(listener, settings, async {
            let _ = shutdown_rx.await;
        })
        .await
        .expect("the server must serve without I/O errors");
    });
    (address, shutdown_tx)
}

/// Performs one HTTP/1.0 GET and returns the status code and full body.
async fn get(address: std::net::SocketAddr, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("the server must accept");
    let request = format!("GET {path} HTTP/1.0\r\nHost: {address}\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("request must write");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("connection must close after an HTTP/1.0 response");
    let text = String::from_utf8_lossy(&response).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    (status, body.to_owned())
}

#[tokio::test]
async fn health_probes_answer_ok() {
    let dist = shell_dist();
    let (address, _shutdown) = spawn(settings(dist.path())).await;
    let (status, body) = get(address, "/healthz").await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok\n");
    let (status, body) = get(address, "/readyz").await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok\n");
}

#[tokio::test]
async fn the_web_shell_is_served_with_its_assets() {
    let dist = shell_dist();
    let (address, _shutdown) = spawn(settings(dist.path())).await;
    let (status, body) = get(address, "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "<html>fleet shell</html>\n");
    let (status, body) = get(address, "/assets/app.js").await;
    assert_eq!(status, 200);
    assert_eq!(body, "console.log('fleet');\n");
}

#[tokio::test]
async fn the_public_api_answers_behind_the_same_listener() {
    let dist = shell_dist();
    let (address, _shutdown) = spawn(settings(dist.path())).await;
    let (status, body) = get(address, "/api/v1/meta").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"service\":\"fleet-controller\""), "{body}");
}

#[tokio::test]
async fn unknown_api_paths_keep_the_json_error_envelope() {
    let dist = shell_dist();
    let (address, _shutdown) = spawn(settings(dist.path())).await;
    let (status, body) = get(address, "/api/v1/no-such-endpoint").await;
    assert_eq!(status, 404);
    assert!(body.contains("\"code\":\"not_found\""), "{body}");
}

#[tokio::test]
async fn a_missing_web_shell_is_reported_by_readiness_without_stopping_the_api() {
    let empty = tempfile::tempdir().expect("empty dist must create");
    let (address, _shutdown) = spawn(settings(empty.path())).await;
    let (status, _) = get(address, "/readyz").await;
    assert_eq!(status, 503);
    let (status, _) = get(address, "/api/v1/meta").await;
    assert_eq!(status, 200);
    let (status, _) = get(address, "/healthz").await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn graceful_shutdown_stops_the_server_and_releases_the_listener() {
    let dist = shell_dist();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener must bind");
    let address = listener
        .local_addr()
        .expect("bound listener must report its address");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        serve_on(listener, settings(dist.path()), async {
            let _ = shutdown_rx.await;
        })
        .await
    });

    let (status, _) = get(address, "/healthz").await;
    assert_eq!(status, 200);

    shutdown_tx
        .send(())
        .expect("the server must still be running");
    let result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("graceful shutdown must complete")
        .expect("the server task must not panic");
    assert!(result.is_ok(), "the server must stop without an I/O error");

    // The listener is released, so a new bind on the same port succeeds.
    TcpListener::bind(address)
        .await
        .expect("the listener must be released after shutdown");
}
