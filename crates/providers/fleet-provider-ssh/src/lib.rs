//! The SSH provider: agentless access through the system OpenSSH client.
//!
//! Fleet never implements SSH. It invokes the system `ssh`, `ssh-keyscan`,
//! and `ssh-keygen` binaries — the tools operators already trust — against
//! an **isolated** Fleet-owned configuration directory, so Fleet's trust
//! decisions never read or write the user's `~/.ssh/config`, and the user's
//! `known_hosts` never silently answers for Fleet.
//!
//! The trust workflow is the point of this crate:
//!
//! - **Probe** fetches a host's key with `ssh-keyscan` and derives its
//!   fingerprint with `ssh-keygen`, bounded by timeouts.
//! - **Decide** compares the fingerprint against the endpoint's verified
//!   fingerprint: absent means `New` (trust-on-first-use requires an
//!   authorized confirmation), equal means `Known`, different means
//!   `Changed` — and a changed key blocks the connection, hard.
//! - **Pin** records the confirmed fingerprint on the endpoint.
//! - **Connect** runs a bounded `ssh` probe with `StrictHostKeyChecking yes`
//!   against the Fleet known-hosts file, so a key swap at connection time
//!   still fails closed.
//!
//! Authentication supports the agent and identity files only. Password
//! authentication is deliberately unsupported: it needs interactive prompts
//! or helper binaries, and Fleet's remote execution must run unattended and
//! non-interactive (see FM-202). This crate never prints or stores key
//! material; diagnostics name endpoints, not secrets.
//!
//! This crate is synchronous on purpose: callers that need async wrap it in
//! `spawn_blocking` (FM-202 owns that integration).
#![warn(missing_docs)]

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

pub mod discovery;
pub mod exec;
pub mod fetch;
pub mod inventory;

pub use discovery::{
    DISCOVERY_DEADLINE, DISCOVERY_SOURCE, DiscoveredCheckout, MAX_CHECKOUTS, discover,
    discovery_script, parse_discovery_output,
};
pub use exec::{
    ExecutionLimiter, ExecutionResult, MAX_STREAM_BYTES, ScriptMetadata, decode_metadata,
    encode_metadata, execute_script, remote_prologue,
};
pub use fetch::{FetchOutcome, fetch_file};
pub use inventory::{COLLECTION_DEADLINE, PROBE_SOURCE, collect, parse_probe_output, probe_script};

/// One host's key, as observed from the network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostKeyObservation {
    /// The key type, e.g. `ED25519`.
    pub key_type: String,
    /// The colon-separated OpenSSH fingerprint, e.g. `SHA256:...`.
    pub fingerprint: String,
    /// The raw `known_hosts` line `ssh-keyscan` produced; this is exactly what
    /// gets pinned into the Fleet `known_hosts` file, so what the operator
    /// confirms is what gets stored.
    pub raw_line: String,
}

/// The comparison between an observed key and what the endpoint already
/// trusts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustDecision {
    /// No verified fingerprint exists yet: trust-on-first-use needs an
    /// authorized confirmation of the fingerprint before anything proceeds.
    New {
        /// What the network presented.
        observation: HostKeyObservation,
    },
    /// The observed key matches the verified fingerprint.
    Known {
        /// What the network presented.
        observation: HostKeyObservation,
    },
    /// The observed key differs from the verified one. The endpoint must not
    /// be used until a human re-confirms; this is the hostile case.
    Changed {
        /// The fingerprint the endpoint had verified before.
        expected: String,
        /// What the network presented instead.
        observation: HostKeyObservation,
    },
}

/// A provider failure that is safe to print: endpoint names and fingerprints,
/// never key material or command output beyond one bounded line.
#[derive(Debug)]
pub enum SshProviderError {
    /// The isolated configuration directory could not be prepared.
    Setup {
        /// What went wrong.
        detail: String,
    },
    /// An OpenSSH tool could not be started or timed out.
    Tool {
        /// Which tool failed.
        tool: &'static str,
        /// What went wrong.
        detail: String,
    },
    /// The host did not present a key we could fingerprint.
    NoHostKey {
        /// What went wrong.
        detail: String,
    },
    /// The connection attempt failed; the detail is redacted output.
    Connect {
        /// What went wrong.
        detail: String,
    },
}

impl std::fmt::Display for SshProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setup { detail } => write!(f, "SSH setup failed: {detail}"),
            Self::Tool { tool, detail } => write!(f, "OpenSSH {tool} failed: {detail}"),
            Self::NoHostKey { detail } => write!(f, "the host presented no usable key: {detail}"),
            Self::Connect { detail } => write!(f, "the connection failed: {detail}"),
        }
    }
}

impl std::error::Error for SshProviderError {}

/// The provider: one isolated configuration directory per store. Cloning
/// shares the same directory on purpose: one trust store per controller.
#[derive(Clone, Debug)]
pub struct SshProvider {
    work_dir: PathBuf,
}

impl SshProvider {
    /// Creates a provider whose isolated configuration lives under `work_dir`
    /// (typically `<data dir>/ssh`).
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be created or written.
    pub fn new(work_dir: PathBuf) -> Result<Self, SshProviderError> {
        std::fs::create_dir_all(&work_dir).map_err(|error| SshProviderError::Setup {
            detail: format!("cannot create {}: {error}", work_dir.display()),
        })?;
        // The isolated directory is owner-only: known_hosts and the config
        // live here.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&work_dir, std::fs::Permissions::from_mode(0o700)).map_err(
                |error| SshProviderError::Setup {
                    detail: format!("cannot secure {}: {error}", work_dir.display()),
                },
            )?;
        }
        #[cfg(not(unix))]
        let _ = &work_dir;
        Ok(Self { work_dir })
    }

    /// The Fleet-owned `known_hosts` file.
    #[must_use]
    pub fn known_hosts_path(&self) -> PathBuf {
        self.work_dir.join("known_hosts")
    }

    /// Probes a host's key: `ssh-keyscan` fetches, `ssh-keygen` fingerprints.
    ///
    /// # Errors
    ///
    /// Fails when the tools fail, time out, or the host presents nothing.
    pub fn probe_host_key(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<HostKeyObservation, SshProviderError> {
        let mut command = Command::new("ssh-keyscan");
        command
            .arg("-t")
            .arg("ed25519,rsa")
            .arg("-p")
            .arg(port.to_string())
            .arg("-T")
            .arg(timeout.as_secs().to_string());
        add_ssh_keyscan_host(&mut command, host);
        let raw = command.output().map_err(|error| SshProviderError::Tool {
            tool: "ssh-keyscan",
            detail: format!("cannot start: {error}"),
        })?;
        let stdout = String::from_utf8_lossy(&raw.stdout);
        let line = stdout
            .lines()
            .find(|line| !line.starts_with('#') && !line.trim().is_empty())
            .ok_or_else(|| SshProviderError::NoHostKey {
                detail: "ssh-keyscan returned no key within the timeout".to_owned(),
            })?
            .to_owned();

        // Fingerprint the key through ssh-keygen so the fingerprint format is
        // the one operators see everywhere else.
        let key_file = self.work_dir.join("probe.tmp");
        std::fs::write(&key_file, &line).map_err(|error| SshProviderError::Setup {
            detail: format!("cannot stage the probe: {error}"),
        })?;
        let fingerprinted = Command::new("ssh-keygen")
            .arg("-lf")
            .arg(&key_file)
            .output()
            .map_err(|error| SshProviderError::Tool {
                tool: "ssh-keygen",
                detail: format!("cannot start: {error}"),
            });
        let _ = std::fs::remove_file(&key_file);
        let fingerprinted = fingerprinted?;
        if !fingerprinted.status.success() {
            return Err(SshProviderError::NoHostKey {
                detail: redact_failure(&String::from_utf8_lossy(&fingerprinted.stderr)),
            });
        }
        let summary = String::from_utf8_lossy(&fingerprinted.stdout);
        let parsed = parse_keygen_summary(&summary).ok_or_else(|| SshProviderError::NoHostKey {
            detail: "ssh-keygen produced an unreadable summary".to_owned(),
        })?;
        Ok(HostKeyObservation {
            key_type: parsed.0,
            fingerprint: parsed.1,
            raw_line: line,
        })
    }

    /// Decides what an observed key means for an endpoint with the given
    /// verified fingerprint (`None` when the endpoint was never confirmed).
    #[must_use]
    pub fn decide(
        &self,
        expected: Option<&str>,
        observation: &HostKeyObservation,
    ) -> TrustDecision {
        match expected {
            None => TrustDecision::New {
                observation: observation.clone(),
            },
            Some(expected) if expected == observation.fingerprint => TrustDecision::Known {
                observation: observation.clone(),
            },
            Some(expected) => TrustDecision::Changed {
                expected: expected.to_owned(),
                observation: observation.clone(),
            },
        }
    }

    /// Pins a confirmed observation into the Fleet known-hosts file. Only
    /// call this after an authorized confirmation of the fingerprint; the
    /// caller decides what "authorized" means (FM-210 wires it to a review
    /// step).
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be written.
    pub fn pin(&self, observation: &HostKeyObservation) -> Result<(), SshProviderError> {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.known_hosts_path())
            .map_err(|error| SshProviderError::Setup {
                detail: format!("cannot open known_hosts: {error}"),
            })?;
        writeln!(file, "{}", observation.raw_line).map_err(|error| SshProviderError::Setup {
            detail: format!("cannot write known_hosts: {error}"),
        })
    }

    /// Removes every pin for `host` (used when a machine is deleted, or when
    /// an operator deliberately re-confirms a changed key).
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be rewritten.
    pub fn unpin(&self, host: &str) -> Result<usize, SshProviderError> {
        let path = self.known_hosts_path();
        let Ok(content) = std::fs::read_to_string(&path) else {
            return Ok(0);
        };
        let kept: Vec<&str> = content
            .lines()
            .filter(|line| !host_matches_line(line, host))
            .collect();
        let removed = content.lines().count() - kept.len();
        if removed > 0 {
            std::fs::write(&path, format!("{}\n", kept.join("\n"))).map_err(|error| {
                SshProviderError::Setup {
                    detail: format!("cannot rewrite known_hosts: {error}"),
                }
            })?;
        }
        Ok(removed)
    }

    /// Runs a bounded, non-interactive connection test against the endpoint.
    /// The remote command is `true`: nothing is executed beyond OpenSSH's own
    /// session setup.
    ///
    /// # Errors
    ///
    /// Fails when authentication, the network, or the host key check fails.
    pub fn test_connect(
        &self,
        endpoint: &SshConnectionSpec,
        timeout: Duration,
    ) -> Result<(), SshProviderError> {
        let config_path = self.write_config(&endpoint.auth)?;
        let mut command = Command::new("ssh");
        command
            .arg("-F")
            .arg(&config_path)
            .arg("-o")
            .arg(format!("ConnectTimeout={}", timeout.as_secs()))
            .arg("-p")
            .arg(endpoint.port.to_string());
        match &endpoint.auth {
            SshAuth::Agent => {}
            SshAuth::IdentityFile { path } => {
                command.arg("-i").arg(path);
            }
        }
        add_ssh_destination(&mut command, endpoint);
        command.arg("true");

        let output = command.output().map_err(|error| SshProviderError::Tool {
            tool: "ssh",
            detail: format!("cannot start: {error}"),
        })?;
        if output.status.success() {
            return Ok(());
        }
        Err(SshProviderError::Connect {
            detail: redact_failure(&String::from_utf8_lossy(&output.stderr)),
        })
    }

    /// Writes the isolated config for one authentication method. Each method
    /// has its own file, and each write is an atomic rename, so concurrent
    /// operations never read a partial config.
    ///
    /// The identity policy is explicit:
    ///
    /// - [`SshAuth::IdentityFile`]: `IdentitiesOnly yes` (with `-i` on the
    ///   command line), so the configured file is the only identity offered.
    /// - [`SshAuth::Agent`]: `IdentitiesOnly no` is OpenSSH's own default: it
    ///   offers every key the agent holds, then the controller user's default
    ///   identity files (`~/.ssh/id_*`). A controller with no agent therefore
    ///   still authenticates with its default key. Offering a key reveals only
    ///   its public half; `MaxAuthTries` on the target bounds the attempts.
    fn write_config(&self, auth: &SshAuth) -> Result<PathBuf, SshProviderError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let (name, identity) = match auth {
            SshAuth::Agent => ("config-agent", AGENT_IDENTITY_POLICY),
            SshAuth::IdentityFile { .. } => ("config-identity-file", IDENTITY_FILE_POLICY),
        };
        let path = self.work_dir.join(name);
        // The known-hosts path must be absolute: the ssh process runs with
        // the controller's working directory, not this crate's directory.
        let known_hosts = self.known_hosts_path().display().to_string();
        let contents = format!(
            "StrictHostKeyChecking yes\n\
             UserKnownHostsFile {known_hosts}\n\
             HashKnownHosts yes\n\
             BatchMode yes\n\
             LogLevel ERROR\n\
             PreferredAuthentications publickey\n\
             {identity}"
        );
        // Write a private temporary file and rename it into place: a
        // concurrent `ssh -F` sees the old or the new complete file, never
        // an empty or truncated one (which would silently drop the host-key
        // pinning and the identity policy).
        let temporary = self.work_dir.join(format!(
            "{name}.{}.{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::write(&temporary, contents)
            .and_then(|()| std::fs::rename(&temporary, &path))
            .map_err(|error| {
                let _ = std::fs::remove_file(&temporary);
                SshProviderError::Setup {
                    detail: format!("cannot write the isolated config: {error}"),
                }
            })?;
        Ok(path)
    }
}

/// OpenSSH's default: agent keys first, then the default identity files.
const AGENT_IDENTITY_POLICY: &str = "IdentitiesOnly no\n";
/// Offers only the identity file passed with `-i`.
const IDENTITY_FILE_POLICY: &str = "IdentitiesOnly yes\n";

pub(crate) fn add_ssh_destination(command: &mut Command, endpoint: &SshConnectionSpec) {
    command
        .arg("--")
        .arg(format!("{}@{}", endpoint.user, endpoint.host));
}

pub(crate) fn add_ssh_keyscan_host(command: &mut Command, host: &str) {
    command.arg("--").arg(host);
}

/// How Fleet authenticates to an SSH endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SshAuth {
    /// The caller's agent (`SSH_AUTH_SOCK`) supplies keys, then the user's
    /// default `~/.ssh/id_*` files (OpenSSH's default).
    Agent,
    /// A specific identity file, referenced by path. The path is not secret;
    /// a passphrase would be, and Fleet does not do passphrase prompts.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// The connection spec for a test: everything `ssh` needs, nothing secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshConnectionSpec {
    /// The host.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The remote user.
    pub user: String,
    /// The authentication method.
    pub auth: SshAuth,
}

/// Extracts `(key type, fingerprint)` from an `ssh-keygen -lf` summary line:
/// `256 SHA256:xxxx comment (ED25519)`.
fn parse_keygen_summary(summary: &str) -> Option<(String, String)> {
    let line = summary.lines().next()?;
    let mut parts = line.split_whitespace();
    let _bits = parts.next()?;
    let fingerprint = parts.next()?;
    // The trailing parenthesized type is the last token.
    let key_type = parts
        .next_back()?
        .trim_matches(|c| c == '(' || c == ')')
        .to_owned();
    Some((key_type, fingerprint.to_owned()))
}

/// Whether a `known_hosts` line concerns `host`. Hashed entries (`HashKnownHosts`
/// `yes`) start with `|1|` and cannot be matched textually; Fleet pins raw
/// lines itself, and hashed pins are left to OpenSSH's own verification.
fn host_matches_line(line: &str, host: &str) -> bool {
    if line.starts_with('|') {
        return false;
    }
    let first_field = line.split_whitespace().next().unwrap_or("");
    first_field.split(',').any(|pattern| {
        pattern == host
            || (pattern.starts_with('[')
                && pattern
                    .trim_start_matches('[')
                    .split(']')
                    .next()
                    .is_some_and(|entry_host| entry_host == host))
    })
}

/// Picks the most informative bounded line from a tool's stderr. OpenSSH
/// puts banner noise (the `@@@@` warning block) before the actual reason, so
/// a recognized failure reason wins; otherwise the last line does.
pub(crate) fn redact_failure(text: &str) -> String {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let reason = lines
        .iter()
        .find(|line| {
            line.contains("Host key verification failed")
                || line.contains("Permission denied")
                || line.contains("Connection refused")
                || line.contains("Connection timed out")
        })
        .or_else(|| lines.last());
    let line = reason.copied().unwrap_or("no detail");
    // Bound the scanned input first (on a char boundary) so the scrub stays
    // cheap, scrub credentials and control characters, then cut the result:
    // cutting first could split a credential and keep half of it.
    let scrubbed = fleet_core::flatten_control_characters(&fleet_core::redact_credentials(
        truncate_on_boundary(line, SCRUB_WINDOW),
    ));
    let limit = scrubbed
        .char_indices()
        .nth(MAX_DETAIL_CHARS)
        .map(|(index, _)| index);
    match limit {
        Some(index) => format!("{}…", &scrubbed[..index]),
        None => scrubbed,
    }
}

/// Characters of a failure line kept in `connection_failed` details.
const MAX_DETAIL_CHARS: usize = 200;
/// Bytes of a failure line scanned for credentials.
const SCRUB_WINDOW: usize = 4096;

/// The longest prefix of `text` of at most `max` bytes that ends on a char
/// boundary.
fn truncate_on_boundary(text: &str, max: usize) -> &str {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::{
        SshAuth, SshConnectionSpec, SshProvider, add_ssh_destination, add_ssh_keyscan_host,
        redact_failure,
    };
    use std::process::Command;

    #[test]
    fn failure_detail_redacts_credentials() {
        let detail = redact_failure("fatal: cannot reach https://user:hunter2@host.invalid/x.git");
        assert!(!detail.contains("hunter2"), "{detail}");
        let scp = redact_failure("ssh: deploy:hunter2@host.invalid: Permission denied");
        assert!(!scp.contains("hunter2"), "{scp}");
    }

    #[test]
    fn failure_detail_cuts_on_a_char_boundary() {
        // 3-byte characters: byte 200 falls inside one.
        let detail = redact_failure(&"€".repeat(500));
        assert_eq!(detail.chars().count(), 201, "{detail}");
        assert!(detail.ends_with('…'));
        // A multibyte cut inside the scan window must not panic either.
        let long = format!("Permission denied {}", "é".repeat(10_000));
        assert!(redact_failure(&long).ends_with('…'));
    }

    #[test]
    fn failure_detail_flattens_control_characters() {
        let detail = redact_failure("Permission denied\u{1b}[31m\u{7}");
        assert!(!detail.chars().any(char::is_control), "{detail:?}");
    }

    fn effective_options(config: &std::path::Path, extra: &[&str]) -> Vec<String> {
        let output = Command::new("ssh")
            .arg("-G")
            .arg("-F")
            .arg(config)
            .args(extra)
            .args(["--", "user@host.invalid"])
            .output()
            .expect("ssh -G runs");
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn agent_auth_offers_agent_keys_and_default_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let provider = SshProvider::new(dir.path().to_path_buf()).expect("provider");
        let config = provider.write_config(&SshAuth::Agent).expect("config");
        let text = std::fs::read_to_string(&config).expect("config text");
        assert!(text.contains("IdentitiesOnly no\n"), "{text}");
        assert!(!text.contains("IdentitiesOnly yes"), "{text}");
        let options = effective_options(&config, &[]);
        assert!(
            options.contains(&"identitiesonly no".to_owned()),
            "{options:?}"
        );
        let identities: Vec<_> = options
            .iter()
            .filter(|line| line.starts_with("identityfile "))
            .collect();
        assert!(
            identities.contains(&&"identityfile ~/.ssh/id_ed25519".to_owned()),
            "the default identity files stay in the offer: {identities:?}"
        );
        assert!(
            !identities.contains(&&"identityfile none".to_owned()),
            "{identities:?}"
        );
    }

    #[test]
    fn identity_file_auth_pins_its_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("key");
        std::fs::write(&key, "not a real key").expect("write key");
        let provider = SshProvider::new(dir.path().to_path_buf()).expect("provider");
        let auth = SshAuth::IdentityFile {
            path: key.display().to_string(),
        };
        let config = provider.write_config(&auth).expect("config");
        let options = effective_options(&config, &["-i", &key.display().to_string()]);
        assert!(
            options.contains(&"identitiesonly yes".to_owned()),
            "{options:?}"
        );
        assert!(
            options.contains(&format!("identityfile {}", key.display())),
            "{options:?}"
        );
    }

    #[test]
    fn auth_methods_use_separate_config_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let provider = SshProvider::new(dir.path().to_path_buf()).expect("provider");
        let agent = provider.write_config(&SshAuth::Agent).expect("agent");
        let file = provider
            .write_config(&SshAuth::IdentityFile {
                path: "k".to_owned(),
            })
            .expect("file");
        assert_ne!(agent, file);
    }

    #[test]
    fn ssh_destination_is_after_the_option_terminator() {
        let endpoint = SshConnectionSpec {
            host: "-Fmalicious".to_owned(),
            port: 22,
            user: "-oProxyCommand=malicious".to_owned(),
            auth: SshAuth::Agent,
        };
        let mut command = Command::new("ssh");
        add_ssh_destination(&mut command, &endpoint);
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args, ["--", "-oProxyCommand=malicious@-Fmalicious"]);
    }

    #[test]
    fn ssh_keyscan_host_is_after_the_option_terminator() {
        let mut command = Command::new("ssh-keyscan");
        add_ssh_keyscan_host(&mut command, "-Fmalicious");
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args, ["--", "-Fmalicious"]);
    }
}
