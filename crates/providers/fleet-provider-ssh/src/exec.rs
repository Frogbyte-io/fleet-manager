//! Bounded SSH command execution over the verified endpoint.
//!
//! The transport rule that makes this safe is structural: **the caller's data
//! never passes through a remote shell.** OpenSSH hands the remote login
//! shell one command *string*, so any caller text on that string is subject
//! to remote-shell parsing. This executor therefore transports everything the
//! caller controls — working directory, environment, arguments — inside one
//! base64 metadata blob (only `[A-Za-z0-9+/=]`, shell-inert), and the script
//! itself rides on the remote shell's stdin. What the remote shell parses is
//! exactly two things, both fixed: `bash -s --` and the inert blob.
//!
//! Bounds: output is capped per stream with a truncation flag; the deadline
//! kills the local `ssh` process and reports remote uncertainty honestly (the
//! remote command may have run); concurrency is limited by a permit guard
//! because every concurrent session costs a file descriptor and a slot on
//! the remote host.

use std::io::{Read, Write as _};
use std::process::Child;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;

use crate::{SshConnectionSpec, SshProvider, SshProviderError};

/// The per-stream output cap. Provider output is evidence, not a payload;
/// anything larger belongs in an artifact store.
pub const MAX_STREAM_BYTES: usize = 64 * 1024;

/// The metadata the remote prologue decodes before running the script.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScriptMetadata {
    /// Working directory; empty means the remote login's default.
    pub working_directory: String,
    /// Environment variables to export, in order.
    pub environment: Vec<(String, String)>,
    /// Positional arguments for the script (`$1` onwards).
    pub arguments: Vec<String>,
}

/// A serialized metadata blob; shell-inert by construction. Fields are
/// NUL-framed and base64-encoded, so nothing in the caller's data can break
/// out of one argv item.
#[must_use]
pub fn encode_metadata(metadata: &ScriptMetadata) -> String {
    let mut raw = Vec::new();
    raw.extend_from_slice(metadata.working_directory.as_bytes());
    raw.push(0);
    for (key, value) in &metadata.environment {
        // One field "KEY=VALUE": the value may contain '=' freely, and the
        // remote side exports the field without re-parsing it.
        raw.extend_from_slice(key.as_bytes());
        raw.push(b'=');
        raw.extend_from_slice(value.as_bytes());
        raw.push(0);
    }
    raw.push(0);
    for argument in &metadata.arguments {
        raw.extend_from_slice(argument.as_bytes());
        raw.push(0);
    }
    raw.push(0);
    base64::engine::general_purpose::STANDARD.encode(&raw)
}

/// Decodes a metadata blob; malformed blobs are a caller error, never a
/// remote execution error.
///
/// # Errors
///
/// Fails on a blob that is not base64 or not the expected framing.
pub fn decode_metadata(blob: &str) -> Result<ScriptMetadata, SshProviderError> {
    use base64::engine::general_purpose::STANDARD;
    let raw = STANDARD
        .decode(blob.as_bytes())
        .map_err(|error| SshProviderError::Setup {
            detail: format!("the metadata blob is not base64: {error}"),
        })?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let mut fields = text.split('\u{0}');
    let working_directory = fields.next().unwrap_or_default().to_owned();
    let mut environment = Vec::new();
    for field in fields.by_ref() {
        if field.is_empty() {
            // The framing's empty field terminates the environment list.
            break;
        }
        // One field "KEY=VALUE"; the value may contain '=' freely.
        let (key, value) = field
            .split_once('=')
            .ok_or_else(|| SshProviderError::Setup {
                detail: format!("the environment field {field:?} is not KEY=VALUE"),
            })?;
        environment.push((key.to_owned(), value.to_owned()));
    }
    let arguments = fields
        .filter(|field| !field.is_empty())
        .map(str::to_owned)
        .collect();
    Ok(ScriptMetadata {
        working_directory,
        environment,
        arguments,
    })
}

/// The prologue the remote `bash -s -- <blob>` runs before the script. Fixed
/// text, owned by this crate: it decodes the blob, enters the working
/// directory, exports the environment, and sets the caller's arguments as
/// `$@` before the script text that follows on the same stdin. The framing's
/// trailing empty field is not a caller argument; genuinely empty caller
/// arguments are dropped by the same filter. Bash is named
/// explicitly because the supported Linux baseline (Debian/Ubuntu) guarantees
/// it and the login shell is not assumed to be anything in particular.
/// The delimiter for `read -d` is a NUL byte; it is written literally in the
/// source and shows here as a control character.
#[must_use]
pub fn remote_prologue() -> &'static str {
    "fleet_meta=$1; shift\n\
     fleet_have_dir=''\n\
     fleet_env_done=''\n\
     while IFS= read -r -d $'\\0' fleet_field; do\n\
       if [ -z \"$fleet_env_done\" ]; then\n\
         if [ -z \"$fleet_have_dir\" ]; then\n\
           fleet_have_dir=1\n\
           fleet_dir=$fleet_field\n\
         elif [ -z \"$fleet_field\" ]; then\n\
           fleet_env_done=1\n\
         else\n\
           export \"$fleet_field\"\n\
         fi\n\
       elif [ -n \"$fleet_field\" ]; then\n\
         set -- \"$@\" \"$fleet_field\"\n\
       fi\n\
     done < <(printf '%s' \"$fleet_meta\" | base64 -d) || exit 90\n\
     [ -z \"$fleet_dir\" ] || cd \"$fleet_dir\" || exit 90\n"
}

/// The result of one execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionResult {
    /// The remote exit code, when the process survived the deadline.
    pub exit_code: Option<i32>,
    /// Capped stdout.
    pub stdout: String,
    /// Capped stderr.
    pub stderr: String,
    /// Whether the stdout cap bit.
    pub truncated_stdout: bool,
    /// Whether the stderr cap bit.
    pub truncated_stderr: bool,
    /// True when the local `ssh` process was killed at the deadline. The
    /// remote command's fate is unknown; callers must not claim success.
    pub killed_by_deadline: bool,
}

/// A concurrency permit pool: at most `max` remote sessions at once.
#[derive(Debug)]
pub struct ExecutionLimiter {
    max: usize,
    held: Mutex<usize>,
    released: Condvar,
}

impl ExecutionLimiter {
    /// A pool of `max` permits.
    #[must_use]
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max,
            held: Mutex::new(0),
            released: Condvar::new(),
        })
    }

    fn acquire(&self) -> bool {
        let mut held = self.held.lock().unwrap();
        if *held >= self.max {
            return false;
        }
        *held += 1;
        true
    }

    fn release(&self) {
        let mut held = self.held.lock().unwrap();
        *held -= 1;
        self.released.notify_one();
    }

    /// How many permits are currently held, for backpressure visibility.
    ///
    /// # Panics
    ///
    /// Panics only if the pool's mutex is poisoned by a panicked holder,
    /// which the executor never does.
    #[must_use]
    pub fn held(&self) -> usize {
        *self.held.lock().unwrap()
    }

    /// The pool's capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.max
    }
}

/// How much of a stream to read at once.
const READ_CHUNK: usize = 8 * 1024;

/// How often the deadline is polled while the remote session runs.
const POLL: Duration = Duration::from_millis(50);

/// Bounded, deadline-killed remote execution.
///
/// # Errors
///
/// Fails on setup/tool errors and connection failures; a deadline kill is a
/// *result*, not an error, and is reported in [`ExecutionResult`].
pub fn execute_script(
    provider: &SshProvider,
    limiter: &ExecutionLimiter,
    endpoint: &SshConnectionSpec,
    script: &str,
    metadata: &ScriptMetadata,
    deadline: Duration,
) -> Result<ExecutionResult, SshProviderError> {
    if !limiter.acquire() {
        return Err(SshProviderError::Tool {
            tool: "ssh",
            detail: format!(
                "the concurrency limit ({}) is saturated; no session slot is free",
                limiter.capacity()
            ),
        });
        // The permit is deliberately not held: no process was started.
    }
    let result = execute_script_inner(provider, endpoint, script, metadata, deadline);
    limiter.release();
    result
}

fn execute_script_inner(
    provider: &SshProvider,
    endpoint: &SshConnectionSpec,
    script: &str,
    metadata: &ScriptMetadata,
    deadline: Duration,
) -> Result<ExecutionResult, SshProviderError> {
    let started = Instant::now();
    let config_path = provider.write_config()?;
    let blob = encode_metadata(metadata);

    let mut command = std::process::Command::new("ssh");
    command
        .arg("-F")
        .arg(&config_path)
        .arg("-o")
        .arg(format!("ConnectTimeout={}", deadline.as_secs().max(1)))
        .arg("-T")
        .arg("-p")
        .arg(endpoint.port.to_string());
    match &endpoint.auth {
        crate::SshAuth::Agent => {}
        crate::SshAuth::IdentityFile { path } => {
            command.arg("-i").arg(path);
        }
    }
    crate::add_ssh_destination(&mut command, endpoint);
    command
        // The remote shell parses exactly this: `bash -s --` and the inert
        // blob.
        .arg(format!("bash -s -- {blob}"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child: Child = command.spawn().map_err(|error| SshProviderError::Tool {
        tool: "ssh",
        detail: format!("cannot start: {error}"),
    })?;
    // The script rides stdin; the prologue decodes the blob from `$1`.
    child
        .stdin
        .take()
        .ok_or_else(|| SshProviderError::Tool {
            tool: "ssh",
            detail: "the ssh process has no stdin".to_owned(),
        })?
        .write_all(format!("{}{script}", remote_prologue()).as_bytes())
        .map_err(|error| SshProviderError::Tool {
            tool: "ssh",
            detail: format!("cannot send the script: {error}"),
        })?;

    // Reader threads drain the pipes so a silent remote session cannot wedge
    // the deadline poll; killing the child closes the pipes and ends them.
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let stdout_reader = std::thread::spawn(move || bounded_read(stdout_pipe));
    let stderr_reader = std::thread::spawn(move || bounded_read(stderr_pipe));

    loop {
        if started.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            // The pipes close with the process; join the readers.
            let (stdout, truncated_stdout) = stdout_reader.join().unwrap_or_default();
            let (stderr, truncated_stderr) = stderr_reader.join().unwrap_or_default();
            return Ok(ExecutionResult {
                exit_code: None,
                stdout,
                stderr,
                truncated_stdout,
                truncated_stderr,
                killed_by_deadline: true,
            });
        }
        if let Some(status) = child.try_wait().unwrap_or(None) {
            let (stdout, truncated_stdout) = stdout_reader.join().unwrap_or_default();
            let (stderr, truncated_stderr) = stderr_reader.join().unwrap_or_default();
            return Ok(ExecutionResult {
                exit_code: status.code(),
                stdout,
                stderr,
                truncated_stdout,
                truncated_stderr,
                killed_by_deadline: false,
            });
        }
        std::thread::sleep(POLL);
    }
}

/// Drains a pipe to its cap; returns the capped text and whether the cap bit.
fn bounded_read<R: Read>(mut pipe: Option<R>) -> (String, bool) {
    let Some(pipe) = pipe.as_mut() else {
        return (String::new(), false);
    };
    let mut sink = Vec::new();
    let mut truncated = false;
    let mut chunk = [0_u8; READ_CHUNK];
    loop {
        // A closed pipe and an error both end the reader; the child is killed
        // by the deadline path, which closes the pipes with the process.
        match pipe.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                let room = MAX_STREAM_BYTES.saturating_sub(sink.len());
                let keep = room.min(read);
                sink.extend_from_slice(&chunk[..keep]);
                // Keep draining past the cap to close the pipe cleanly,
                // discarding the excess.
                truncated = truncated || keep < read;
            }
        }
    }
    (String::from_utf8_lossy(&sink).into_owned(), truncated)
}
