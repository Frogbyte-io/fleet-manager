//! A real controller for one scenario: the `fleet-controller` binary (the
//! production composition of API, worker, and the pinned PVE transport)
//! over a throwaway data directory and master key, driven by the real
//! `fleetctl` binary for the operator's steps.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;

use super::config::FLEETCTL_VAR;
use super::redact::Redactor;

/// One running controller.
#[derive(Debug)]
pub struct Controller {
    /// The running process and the address it listens on; both change when
    /// [`Controller::with_store`] restarts it (the address only if the port
    /// could not be reused).
    process: Mutex<(Child, std::net::SocketAddr)>,
    dir: tempfile::TempDir,
    fleetctl: PathBuf,
    redactor: Redactor,
}

impl Drop for Controller {
    fn drop(&mut self) {
        let process = self
            .process
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = process.0.kill();
        let _ = process.0.wait();
    }
}

/// What one `fleetctl` invocation answered.
#[derive(Debug)]
pub struct CliAnswer {
    /// Whether it exited zero.
    pub success: bool,
    /// The decoded payload on stdout: fleetctl prints a resource's `data`
    /// (a page keeps its `items`); `Null` when it printed no JSON.
    pub json: Value,
    /// stderr, redacted.
    pub stderr: String,
}

/// Locates the `fleetctl` binary: the runner's explicit path, or the one
/// built beside this test binary (`target/<profile>/fleetctl`).
///
/// # Errors
///
/// When neither exists.
pub fn locate_fleetctl() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os(FLEETCTL_VAR) {
        let path = PathBuf::from(path);
        return if path.is_file() {
            Ok(path)
        } else {
            Err(format!("{FLEETCTL_VAR}={} is not a file", path.display()))
        };
    }
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    // target/<profile>/deps/proxmox_live-<hash> → target/<profile>/fleetctl
    let candidate = exe
        .parent()
        .and_then(Path::parent)
        .map(|profile| profile.join(format!("fleetctl{}", std::env::consts::EXE_SUFFIX)));
    match candidate {
        Some(path) if path.is_file() => Ok(path),
        _ => Err(format!(
            "the live suite drives the real fleetctl binary: run `cargo build -p fleetctl` first \
             (cargo xtask pve-acceptance does), or set {FLEETCTL_VAR}"
        )),
    }
}

fn free_port() -> Result<u16, String> {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .map_err(|error| format!("cannot reserve a loopback port: {error}"))
}

impl Controller {
    /// Starts the controller and waits until its Proxmox surface answers.
    ///
    /// # Errors
    ///
    /// When the binary cannot start or never becomes ready.
    pub async fn start(redactor: Redactor) -> Result<Self, String> {
        let fleetctl = locate_fleetctl()?;
        let mut last = String::new();
        // The free-port window is racy; a lost race shows as an early exit.
        for _ in 0..3 {
            match Self::try_start(&fleetctl, redactor.clone()).await {
                Ok(controller) => return Ok(controller),
                Err(detail) => last = detail,
            }
        }
        Err(last)
    }

    async fn try_start(fleetctl: &Path, redactor: Redactor) -> Result<Self, String> {
        let dir = tempfile::tempdir().map_err(|error| error.to_string())?;
        let web = dir.path().join("web");
        let data = dir.path().join("data");
        std::fs::create_dir_all(&web).map_err(|error| error.to_string())?;
        std::fs::create_dir_all(&data).map_err(|error| error.to_string())?;
        std::fs::write(web.join("index.html"), "<html>fleet</html>")
            .map_err(|error| error.to_string())?;
        let key_path = dir.path().join("master.key");
        let mut key = [0_u8; 32];
        getrandom::getrandom(&mut key).map_err(|error| error.to_string())?;
        let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        write_private(&key_path, &format!("1 {hex}\n"))?;
        let port = free_port()?;
        let address: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
        let child = spawn_child(dir.path(), address)?;
        // Owned by the controller from here on, so Drop kills it on every
        // path, including a failed readiness wait.
        let controller = Self {
            process: Mutex::new((child, address)),
            dir,
            fleetctl: fleetctl.to_path_buf(),
            redactor,
        };
        controller.wait_ready().await?;
        Ok(controller)
    }

    fn address(&self) -> std::net::SocketAddr {
        self.process
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .1
    }

    /// The exit status when the controller process has already exited.
    fn exited(&self) -> Option<std::process::ExitStatus> {
        let mut process = self
            .process
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        process.0.try_wait().ok().flatten()
    }

    /// Waits until the Proxmox surface answers, or the process exits.
    async fn wait_ready(&self) -> Result<(), String> {
        for _ in 0..150 {
            if let Some(status) = self.exited() {
                return Err(format!(
                    "the controller exited during startup ({status}): {}",
                    self.log_tail()
                ));
            }
            if let Ok((200, _)) = self.try_get("/api/v1/proxmox/accounts").await {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(format!(
            "the controller never became ready: {}",
            self.log_tail()
        ))
    }

    /// Stops the controller, runs `work` against its store, then restarts
    /// the controller on the same data directory and master key.
    ///
    /// The store admits one active controller (an OS lock on `fleet.lock`),
    /// so fixture writes cannot happen while the controller runs. The
    /// controller is asked to stop (SIGTERM, then a kill after a grace
    /// period), the store is opened, `work` runs, and the store is closed
    /// before the restart so the lock is free again. The restart reuses the
    /// listen address, so URLs held by the caller stay valid; only if the
    /// port cannot be rebound does the controller move to a new one, which
    /// [`Controller::url`] and every request method then follow.
    ///
    /// # Errors
    ///
    /// When the store cannot be opened, `work` fails, or the controller does
    /// not come back. The controller is restarted even if `work` fails.
    pub async fn with_store<T>(
        &self,
        work: impl AsyncFnOnce(&fleet_storage_sqlite::Store) -> Result<T, String>,
    ) -> Result<T, String> {
        self.stop().await?;
        let outcome = async {
            let store = fleet_storage_sqlite::Store::open(&self.database())
                .await
                .map_err(|error| format!("cannot open the controller's store: {error}"))?;
            let result = work(&store).await;
            store.close().await;
            result
        }
        .await;
        let restarted = self.restart().await;
        match (outcome, restarted) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(detail), _) | (Ok(_), Err(detail)) => Err(detail),
        }
    }

    /// SIGTERM, wait up to 10 s for a clean exit, then kill.
    async fn stop(&self) -> Result<(), String> {
        {
            let process = self
                .process
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            #[cfg(unix)]
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(process.0.id().to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            #[cfg(not(unix))]
            drop(process);
        }
        for _ in 0..100 {
            if self.exited().is_some() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let mut process = self
            .process
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        process
            .0
            .kill()
            .map_err(|error| format!("cannot stop the controller: {error}"))?;
        process
            .0
            .wait()
            .map_err(|error| format!("cannot reap the controller: {error}"))?;
        Ok(())
    }

    /// Starts a new process on the same directory, preferring the old port.
    async fn restart(&self) -> Result<(), String> {
        let old = self.address();
        let mut last = String::new();
        // Rebinding the same port can race the kernel releasing it; retry
        // briefly, then fall back to a fresh port.
        for attempt in 0..8 {
            let address = if attempt < 5 {
                old
            } else {
                ([127, 0, 0, 1], free_port()?).into()
            };
            let child = spawn_child(self.dir.path(), address)?;
            {
                let mut process = self
                    .process
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *process = (child, address);
            }
            match self.wait_ready().await {
                Ok(()) => return Ok(()),
                Err(detail) => {
                    last = detail;
                    // A still-running but unready process must not linger.
                    {
                        let mut process = self
                            .process
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let _ = process.0.kill();
                        let _ = process.0.wait();
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        Err(format!("the controller did not restart: {last}"))
    }

    /// The controller's base URL (it follows a restart onto a new port).
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.address())
    }

    /// The controller's SQLite database (for fixture seeding only).
    #[must_use]
    pub fn database(&self) -> PathBuf {
        self.dir.path().join("data").join("fleet.db")
    }

    /// The last lines of the controller's log, redacted.
    #[must_use]
    pub fn log_tail(&self) -> String {
        let text =
            std::fs::read_to_string(self.dir.path().join("controller.log")).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let tail = lines[lines.len().saturating_sub(15)..].join(" | ");
        self.redactor.line(&tail)
    }

    async fn try_get(&self, path: &str) -> Result<(u16, Value), String> {
        raw(self.address(), "GET", path, None).await
    }

    /// GET; transport failures become an error.
    ///
    /// # Errors
    ///
    /// When the controller is unreachable.
    pub async fn get(&self, path: &str) -> Result<(u16, Value), String> {
        raw(self.address(), "GET", path, None).await
    }

    /// POST with a JSON body.
    ///
    /// # Errors
    ///
    /// When the controller is unreachable.
    pub async fn post(&self, path: &str, body: &Value) -> Result<(u16, Value), String> {
        raw(self.address(), "POST", path, Some(body)).await
    }

    /// Runs `fleetctl --url <controller> --output json <args>` with optional
    /// stdin. Secrets only ever travel on stdin, never in arguments.
    ///
    /// # Errors
    ///
    /// When the binary cannot run.
    pub async fn fleetctl(
        &self,
        args: &[String],
        stdin: Option<String>,
    ) -> Result<CliAnswer, String> {
        let program = self.fleetctl.clone();
        let mut full = vec![
            "--url".to_owned(),
            self.url(),
            "--output".to_owned(),
            "json".to_owned(),
        ];
        full.extend(args.iter().cloned());
        let redactor = self.redactor.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::Write as _;
            let mut child = Command::new(program)
                .args(&full)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|error| format!("fleetctl must start: {error}"))?;
            // Dropping the pipe closes fleetctl's stdin after the input.
            if let Some(mut pipe) = child.stdin.take()
                && let Some(input) = stdin
            {
                pipe.write_all(input.as_bytes())
                    .map_err(|error| format!("fleetctl stdin: {error}"))?;
            }
            let output = child
                .wait_with_output()
                .map_err(|error| format!("fleetctl did not finish: {error}"))?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(CliAnswer {
                success: output.status.success(),
                json: {
                    let parsed: Value = serde_json::from_str(stdout.trim()).unwrap_or(Value::Null);
                    // Tolerate an envelope too, should fleetctl ever print one.
                    match parsed.get("data") {
                        Some(data) if parsed.get("items").is_none() => data.clone(),
                        _ => parsed,
                    }
                },
                stderr: redactor.line(&String::from_utf8_lossy(&output.stderr)),
            })
        })
        .await
        .map_err(|error| format!("fleetctl task: {error}"))?
    }
}

/// Spawns `fleet-controller serve` over `dir`'s `web`, `data`, and
/// `master.key`, logging (appending) to `dir/controller.log`.
fn spawn_child(dir: &Path, address: std::net::SocketAddr) -> Result<Child, String> {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("controller.log"))
        .map_err(|error| error.to_string())?;
    let log_err = log.try_clone().map_err(|error| error.to_string())?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_fleet-controller"));
    // The child sees none of the suite's own FLEET_* variables.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("FLEET_") {
            command.env_remove(key);
        }
    }
    command
        .arg("serve")
        .env("FLEET_LISTEN", address.to_string())
        .env("FLEET_WEB_DIST", dir.join("web"))
        .env("FLEET_DATA_DIR", dir.join("data"))
        .env("FLEET_MASTER_KEY_FILE", dir.join("master.key"))
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .map_err(|error| format!("the controller binary must start: {error}"))
}

/// Writes a file created 0600.
fn write_private(path: &Path, contents: &str) -> Result<(), String> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// One raw HTTP/1.1 request; the suite asserts on bodies, not clients.
async fn raw(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<(u16, Value), String> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .map_err(|error| format!("the controller is unreachable: {error}"))?;
    let payload = body.map(Value::to_string);
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: fleet-acceptance\r\n");
    if let Some(payload) = &payload {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            payload.len()
        ));
    }
    head.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    if let Some(payload) = &payload {
        stream
            .write_all(payload.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
    }
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(120), stream.read_to_end(&mut response))
        .await
        .map_err(|_| format!("{method} {path}: no answer within 120s"))?
        .map_err(|error| error.to_string())?;
    let text = String::from_utf8_lossy(&response);
    let (head, rest) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "not an HTTP response".to_owned())?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "no HTTP status".to_owned())?;
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(rest)
    } else {
        rest.to_owned()
    };
    Ok((
        status,
        serde_json::from_str(body.trim()).unwrap_or(Value::Null),
    ))
}

/// Decodes a chunked body.
fn dechunk(mut rest: &str) -> String {
    let mut out = String::new();
    while let Some((size, after)) = rest.split_once("\r\n") {
        let Ok(size) = usize::from_str_radix(size.trim(), 16) else {
            break;
        };
        if size == 0 || after.len() < size {
            break;
        }
        out.push_str(&after[..size]);
        rest = after[size..].trim_start_matches("\r\n");
    }
    out
}
