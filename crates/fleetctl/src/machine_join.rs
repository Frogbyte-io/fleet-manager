//! `fleetctl machines join` and `fleetctl system ssh-public-key`.
//!
//! `machines join` runs **on the machine being added**, as the account the
//! coding agents use, and does what `docs/operations/add-a-machine.md` used
//! to do by hand:
//!
//! 1. fetches the controller's SSH public key (`GET /system/ssh-public-key`)
//!    and refuses when the controller has none;
//! 2. checks, without changing anything, that this machine's SSH server
//!    answers, and on Windows that `DefaultShell` is Windows PowerShell 5.1
//!    and password login is off (elevated fixes are printed, never run); on
//!    Linux, that no stand-in `skills-manager-cli` would shadow the real one;
//! 3. adds the key to this account's `authorized_keys` once, with the
//!    permissions sshd requires (a Windows administrator is refused with the
//!    elevated `administrators_authorized_keys` commands instead, ADR 0021);
//! 4. onboards the machine through the public API: draft, test, a host key
//!    fingerprint compared against this machine's own key file and confirmed
//!    only when identical, test, discover, add;
//! 5. follows the queued Skills Manager install and rolls out the newest
//!    built-in `fleet` skill to the agents Skills Manager found installed.
//!
//! Every controller call is an ordinary public API request with its usual
//! authorization and audit. Local probes go through [`JoinHost`], so each
//! step is tested with a fake machine.

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, TcpStream, ToSocketAddrs as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use crate::{CliError, Command, Invocation, Output, usage};

/// The controller read endpoint of the controller's SSH public key.
pub const SSH_PUBLIC_KEY_PATH: &str = "/api/v1/system/ssh-public-key";

/// The built-in Fleet skill's catalog entry.
pub const BUILTIN_FLEET_CATALOG_ID: &str = "builtin-fleet";

/// How long one rollout may run on the machine.
const ROLLOUT_TIMEOUT_SECONDS: u64 = 300;

/// The default bound on each operation the join waits for.
pub const DEFAULT_WAIT_SECONDS: u64 = 600;

/// The PowerShell 5.1 path `DefaultShell` must name, under `%SystemRoot%`.
const WINDOWS_POWERSHELL_51: &str = r"System32\WindowsPowerShell\v1.0\powershell.exe";

/// The Administrators group SID. Grants use SIDs, not names: account names
/// are localized, so `SYSTEM` or `Administrators` fail on some Windows.
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
/// The `LocalSystem` account SID.
const SYSTEM_SID: &str = "S-1-5-18";

/// The arguments of `machines join`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinArgs {
    /// The address the controller connects to; `tailscale ip -4` when unset.
    pub host: Option<String>,
    /// The SSH port.
    pub port: u16,
    /// The SSH login; the current account when unset.
    pub user: Option<String>,
    /// The machine name; the hostname when unset.
    pub name: Option<String>,
    /// This machine's host public key file, when sshd uses a non-default one.
    pub host_key_file: Option<String>,
    /// The agents to deploy the `fleet` skill to; the installed ones when empty.
    pub agents: Vec<String>,
    /// Skip the Skills Manager and `fleet` skill steps.
    pub no_skills: bool,
    /// Continue with an already enrolled machine instead of stopping.
    pub resume: bool,
    /// A Windows administrator confirms the key is in
    /// `administrators_authorized_keys` (installed elevated by the operator).
    pub admin_key_installed: bool,
    /// The bound on each operation the join waits for, in seconds.
    pub timeout: u64,
}

impl Default for JoinArgs {
    fn default() -> Self {
        Self {
            host: None,
            port: 22,
            user: None,
            name: None,
            host_key_file: None,
            agents: Vec::new(),
            no_skills: false,
            resume: false,
            admin_key_installed: false,
            timeout: DEFAULT_WAIT_SECONDS,
        }
    }
}

fn value<'a>(flags: &mut impl Iterator<Item = &'a str>, name: &str) -> Result<String, CliError> {
    flags
        .next()
        .filter(|candidate| !candidate.starts_with("--"))
        .map(str::to_owned)
        .ok_or_else(|| CliError {
            message: format!("{name} requires a value"),
        })
}

fn output_flag<'a>(
    flags: &mut impl Iterator<Item = &'a str>,
    output: &mut Output,
) -> Result<(), CliError> {
    *output = match value(flags, "--output")?.as_str() {
        "json" => Output::Json,
        "text" => Output::Text,
        other => {
            return Err(CliError {
                message: format!("--output must be json or text, not {other:?}"),
            });
        }
    };
    Ok(())
}

/// Parses `machines join ...` (the words after `machines join`).
pub(crate) fn parse_join(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let mut args = JoinArgs::default();
    let mut flags = rest.iter().copied();
    while let Some(flag) = flags.next() {
        match flag {
            "--host" => args.host = Some(value(&mut flags, "--host")?),
            "--port" => {
                args.port = value(&mut flags, "--port")?
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port > 0)
                    .ok_or_else(|| CliError {
                        message: "--port must be a number from 1 to 65535".to_owned(),
                    })?;
            }
            "--user" => args.user = Some(value(&mut flags, "--user")?),
            "--name" => args.name = Some(value(&mut flags, "--name")?),
            "--host-key-file" => args.host_key_file = Some(value(&mut flags, "--host-key-file")?),
            "--agents" | "--agent" => {
                for agent in value(&mut flags, flag)?.split(',') {
                    let agent = agent.trim();
                    if !agent.is_empty() && !args.agents.iter().any(|known| known == agent) {
                        args.agents.push(agent.to_owned());
                    }
                }
            }
            "--no-skills" => args.no_skills = true,
            "--resume" => args.resume = true,
            "--admin-key-installed" => args.admin_key_installed = true,
            "--timeout" => {
                args.timeout = value(&mut flags, "--timeout")?
                    .parse::<u64>()
                    .ok()
                    .filter(|seconds| (1..=7200).contains(seconds))
                    .ok_or_else(|| CliError {
                        message: "--timeout must be a number of seconds from 1 to 7200".to_owned(),
                    })?;
            }
            "--output" => output_flag(&mut flags, output)?,
            other => {
                return Err(CliError {
                    message: format!(
                        "unknown argument {other:?} for machines join; see the usage below\n\n{}",
                        usage()
                    ),
                });
            }
        }
    }
    if args.no_skills && !args.agents.is_empty() {
        return Err(CliError {
            message: "--agents chooses where the fleet skill goes; it cannot be combined with --no-skills".to_owned(),
        });
    }
    for (flag, given) in [
        ("--host", &args.host),
        ("--user", &args.user),
        ("--name", &args.name),
    ] {
        if given.as_deref().is_some_and(|text| text.trim().is_empty()) {
            return Err(CliError {
                message: format!("{flag} must not be empty"),
            });
        }
    }
    Ok(Command::MachinesJoin(args))
}

/// Parses `system ssh-public-key [--output json|text]`.
pub(crate) fn parse_public_key(rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let mut flags = rest.iter().copied();
    while let Some(flag) = flags.next() {
        match flag {
            "--output" => output_flag(&mut flags, output)?,
            other => {
                return Err(CliError {
                    message: format!("unknown argument {other:?} for system ssh-public-key"),
                });
            }
        }
    }
    Ok(Command::SystemSshPublicKey)
}

// ---------------------------------------------------------------------------
// The local machine.
// ---------------------------------------------------------------------------

/// The operating system family of this machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Platform {
    /// Linux (and other Unix): OpenSSH reads `~/.ssh/authorized_keys`.
    Unix,
    /// Windows with the in-box OpenSSH Server.
    Windows,
}

/// What one local program printed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProgramOutput {
    /// Whether it exited 0.
    pub success: bool,
    /// Its standard output.
    pub stdout: String,
    /// Its standard error.
    pub stderr: String,
}

/// The local machine as the join sees it. [`SystemHost`] is the real one.
pub trait JoinHost {
    /// This machine's platform.
    fn platform(&self) -> Platform;
    /// One environment variable.
    fn env(&self, name: &str) -> Option<String>;
    /// Runs a program with arguments (no shell), bounded in time.
    ///
    /// # Errors
    ///
    /// Fails when it cannot start or does not finish in time.
    fn run(&self, program: &Path, args: &[&str]) -> Result<ProgramOutput, String>;
    /// The first `name` on `PATH` (with Windows' executable extensions).
    fn find_on_path(&self, name: &str) -> Option<PathBuf>;
    /// Connects to `host:port` and answers the server's first line.
    ///
    /// # Errors
    ///
    /// Fails when nothing answers in time.
    fn ssh_banner(&self, host: &str, port: u16) -> Result<String, String>;
    /// This machine's name.
    fn hostname(&self) -> Option<String>;
}

/// The real machine.
#[derive(Debug, Default)]
pub struct SystemHost;

/// How long a local probe program may run.
const PROGRAM_DEADLINE: Duration = Duration::from_secs(15);

impl JoinHost for SystemHost {
    fn platform(&self) -> Platform {
        if cfg!(windows) {
            Platform::Windows
        } else {
            Platform::Unix
        }
    }

    fn env(&self, name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|value| !value.is_empty())
    }

    fn run(&self, program: &Path, args: &[&str]) -> Result<ProgramOutput, String> {
        let mut child = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|error| format!("cannot run {}: {error}", program.display()))?;
        let deadline = std::time::Instant::now() + PROGRAM_DEADLINE;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{} did not finish within {}s",
                        program.display(),
                        PROGRAM_DEADLINE.as_secs()
                    ));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(error) => {
                    return Err(format!("cannot wait for {}: {error}", program.display()));
                }
            }
        }
        let output = child
            .wait_with_output()
            .map_err(|error| format!("cannot read {}: {error}", program.display()))?;
        Ok(ProgramOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn find_on_path(&self, name: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        let extensions: Vec<String> = if cfg!(windows) {
            std::env::var("PATHEXT")
                .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".to_owned())
                .split(';')
                .map(str::to_owned)
                .chain(std::iter::once(String::new()))
                .collect()
        } else {
            vec![String::new()]
        };
        std::env::split_paths(&path).find_map(|dir| {
            extensions.iter().find_map(|extension| {
                let candidate = dir.join(format!("{name}{extension}"));
                candidate.is_file().then_some(candidate)
            })
        })
    }

    fn ssh_banner(&self, host: &str, port: u16) -> Result<String, String> {
        let address = (host, port)
            .to_socket_addrs()
            .map_err(|error| format!("cannot resolve {host}: {error}"))?
            .next()
            .ok_or_else(|| format!("{host} has no address"))?;
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3))
            .map_err(|error| format!("nothing answers on {host}:{port} ({error})"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|error| error.to_string())?;
        let mut buffer = [0_u8; 256];
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("{host}:{port} sent nothing ({error})"))?;
        // Polite close: the server logs a pre-auth disconnect either way.
        let _ = stream.write_all(b"SSH-2.0-fleetctl-preflight\r\n");
        Ok(String::from_utf8_lossy(&buffer[..read])
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned())
    }

    fn hostname(&self) -> Option<String> {
        if cfg!(windows) {
            return self.env("COMPUTERNAME");
        }
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .or_else(|_| std::fs::read_to_string("/etc/hostname"))
            .ok()
            .or_else(|| {
                self.run(Path::new("hostname"), &[])
                    .ok()
                    .filter(|output| output.success)
                    .map(|output| output.stdout)
            })
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty())
    }
}

/// This account's home directory.
fn home_dir(host: &dyn JoinHost) -> Result<PathBuf, CliError> {
    let variable = match host.platform() {
        Platform::Unix => "HOME",
        Platform::Windows => "USERPROFILE",
    };
    host.env(variable)
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .ok_or_else(|| CliError {
            message: format!(
                "{variable} is not set to an absolute path; cannot find this account's home"
            ),
        })
}

/// This account's login name.
fn current_user(host: &dyn JoinHost) -> Result<String, CliError> {
    let found = match host.platform() {
        Platform::Unix => host
            .env("USER")
            .or_else(|| host.env("LOGNAME"))
            .or_else(|| {
                host.run(Path::new("id"), &["-un"])
                    .ok()
                    .filter(|output| output.success)
                    .map(|output| output.stdout.trim().to_owned())
                    .filter(|name| !name.is_empty())
            }),
        Platform::Windows => host.env("USERNAME"),
    };
    found.ok_or_else(|| CliError {
        message: "cannot tell which account this is; pass --user <login>".to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Pure steps.
// ---------------------------------------------------------------------------

/// Whether `authorized_keys` content already authorizes `key` (same type and
/// blob, with or without options or a different comment).
#[must_use]
pub fn authorizes(content: &str, key: &fleet_core::SshPublicKey) -> bool {
    content
        .lines()
        .filter_map(authorized_key_fields)
        .any(|(kind, blob)| kind == key.key_type && blob == key.blob)
}

/// The key type and blob of one `authorized_keys` line, as sshd reads it
/// (`sshd(8)`, section "authorized keys file format"): an optional options field
/// (comma-separated, double quotes may hold spaces), then the key type, the
/// base64 key and an ignored comment. `None` for blank and comment lines.
#[must_use]
pub fn authorized_key_fields(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let looks_like_type = |word: &str| {
        word.starts_with("ssh-") || word.starts_with("ecdsa-") || word.starts_with("sk-")
    };
    let first = line.split_whitespace().next()?;
    let key_part = if looks_like_type(first) {
        line
    } else {
        // Skip the options field: it ends at the first whitespace outside
        // double quotes, where `\"` is an escaped quote.
        let mut quoted = false;
        let mut escaped = false;
        let mut end = None;
        for (index, character) in line.char_indices() {
            match character {
                _ if escaped => escaped = false,
                '\\' if quoted => escaped = true,
                '"' => quoted = !quoted,
                c if c.is_whitespace() && !quoted => {
                    end = Some(index);
                    break;
                }
                _ => {}
            }
        }
        line[end?..].trim_start()
    };
    let mut words = key_part.split_whitespace();
    let kind = words.next().filter(|word| looks_like_type(word))?;
    let blob = words.next()?;
    Some((kind, blob))
}

/// The bytes to append to `authorized_keys` content so it authorizes `key`,
/// or `None` when it already does.
#[must_use]
pub fn authorized_keys_addition(content: &str, key: &fleet_core::SshPublicKey) -> Option<String> {
    if authorizes(content, key) {
        return None;
    }
    let separator = if content.is_empty() || content.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    Some(format!("{separator}{}\n", key.line()))
}

/// What the key step did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyInstall {
    /// The key was appended.
    Added,
    /// The key was already there.
    Present,
    /// A Windows administrator said the operator installed it elevated.
    AdministratorsFile,
}

impl KeyInstall {
    fn id(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Present => "present",
            Self::AdministratorsFile => "administrators_authorized_keys",
        }
    }
}

/// Adds `key` to `<home>/.ssh/authorized_keys` once, with the permissions
/// sshd requires: on Unix `~/.ssh` 0700 and the file 0600; on Windows the
/// protected ACL from the workstation runbook (the user, SYSTEM and
/// Administrators), applied with `icacls`.
///
/// # Errors
///
/// Fails when the file cannot be read, written or secured.
pub fn install_authorized_key(
    host: &dyn JoinHost,
    home: &Path,
    key: &fleet_core::SshPublicKey,
) -> Result<(KeyInstall, PathBuf), CliError> {
    let dir = home.join(".ssh");
    let path = dir.join("authorized_keys");
    let fail = |what: &str, error: &dyn std::fmt::Display| CliError {
        message: format!("cannot {what}: {error}"),
    };
    std::fs::create_dir_all(&dir)
        .map_err(|error| fail(&format!("create {}", dir.display()), &error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| fail(&format!("restrict {}", dir.display()), &error))?;
    }
    let existing = match std::fs::read(&path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(fail(&format!("read {}", path.display()), &error)),
    };
    let outcome = match authorized_keys_addition(&existing, key) {
        None => KeyInstall::Present,
        Some(addition) => {
            let mut options = std::fs::OpenOptions::new();
            options.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options
                .open(&path)
                .map_err(|error| fail(&format!("open {}", path.display()), &error))?;
            file.write_all(addition.as_bytes())
                .and_then(|()| file.flush())
                .map_err(|error| fail(&format!("write {}", path.display()), &error))?;
            KeyInstall::Added
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| fail(&format!("restrict {}", path.display()), &error))?;
    }
    if host.platform() == Platform::Windows {
        let user = current_user(host)?;
        let args = windows_acl_args(&path, &user);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = host
            .run(Path::new("icacls"), &args)
            .map_err(|error| fail("secure authorized_keys", &error))?;
        if !output.success {
            return Err(CliError {
                message: format!(
                    "icacls could not secure {}: {}",
                    path.display(),
                    first_line(&output.stdout, &output.stderr)
                ),
            });
        }
    }
    Ok((outcome, path))
}

/// The `icacls` arguments that give `authorized_keys` the protected ACL
/// sshd accepts: no inherited entries, full control for the user, SYSTEM
/// and Administrators only.
#[must_use]
pub fn windows_acl_args(path: &Path, user: &str) -> Vec<String> {
    vec![
        path.display().to_string(),
        "/inheritance:r".to_owned(),
        "/grant".to_owned(),
        format!("{user}:F"),
        "/grant".to_owned(),
        format!("*{SYSTEM_SID}:F"),
        "/grant".to_owned(),
        format!("*{ADMINISTRATORS_SID}:F"),
    ]
}

/// The first non-empty line of two outputs, for an error message.
fn first_line(stdout: &str, stderr: &str) -> String {
    stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no detail")
        .to_owned()
}

/// Whether `--user` names the account the join runs as. Windows account
/// names are case-insensitive; Unix ones are not.
#[must_use]
pub fn same_account(platform: Platform, given: &str, account: &str) -> bool {
    match platform {
        Platform::Unix => given == account,
        Platform::Windows => given.eq_ignore_ascii_case(account),
    }
}

/// The first IPv4 address `tailscale ip -4` printed.
#[must_use]
pub fn parse_tailscale_ipv4(stdout: &str) -> Option<Ipv4Addr> {
    stdout
        .lines()
        .find_map(|line| line.trim().parse::<Ipv4Addr>().ok())
}

/// Whether `whoami /groups` lists the Administrators group. An account in
/// it is matched by the default `sshd_config`'s `Match Group
/// administrators` even from a non-elevated session (the group shows as
/// "deny only" there), so sshd reads `administrators_authorized_keys`.
#[must_use]
pub fn is_administrator(whoami_groups: &str) -> bool {
    whoami_groups
        .lines()
        .any(|line| line.contains(ADMINISTRATORS_SID))
}

/// The `DefaultShell` value in `reg query HKLM\SOFTWARE\OpenSSH /v
/// DefaultShell` output, when set.
#[must_use]
pub fn parse_default_shell(reg_output: &str) -> Option<String> {
    reg_output.lines().find_map(|line| {
        // `DefaultShell    REG_SZ    C:\...`: the name, the type, then the
        // value, which may itself contain spaces.
        let (name, rest) = line.trim().split_once(char::is_whitespace)?;
        if !name.eq_ignore_ascii_case("DefaultShell") {
            return None;
        }
        let (kind, value) = rest.trim_start().split_once(char::is_whitespace)?;
        kind.starts_with("REG_")
            .then(|| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    })
}

/// Whether a `DefaultShell` value names Windows PowerShell 5.1 under this
/// machine's `%SystemRoot%`.
#[must_use]
pub fn is_windows_powershell_51(value: &str, system_root: &str) -> bool {
    let expanded = {
        let lower = value.to_ascii_lowercase();
        match lower.find("%systemroot%") {
            Some(start) => format!(
                "{}{system_root}{}",
                &value[..start],
                &value[start + "%systemroot%".len()..]
            ),
            None => value.to_owned(),
        }
    };
    let want = format!(
        "{}\\{WINDOWS_POWERSHELL_51}",
        system_root.trim_end_matches('\\')
    );
    expanded
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .eq_ignore_ascii_case(&want)
}

/// Whether an `sshd_config` turns password login off. OpenSSH uses the
/// first value of a keyword, and a `Match` block can only narrow it; the
/// default is `yes`.
#[must_use]
pub fn password_auth_disabled(sshd_config: &str) -> bool {
    for line in sshd_config.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line
            .split(|c: char| c.is_whitespace() || c == '=')
            .filter(|w| !w.is_empty());
        let keyword = words.next().unwrap_or_default();
        if keyword.eq_ignore_ascii_case("Match") {
            // A Match block may turn it back on for some users: only the
            // global value counts, and it comes first.
            break;
        }
        if keyword.eq_ignore_ascii_case("PasswordAuthentication") {
            return words
                .next()
                .is_some_and(|value| value.eq_ignore_ascii_case("no"));
        }
    }
    false
}

/// Why a `skills-manager-cli` found on this machine is not the real one.
#[must_use]
pub fn stand_in_reason(head: &[u8], version: Result<&ProgramOutput, &str>) -> Option<String> {
    if head.starts_with(b"#!") {
        return Some("it is a script, not the Skills Manager binary".to_owned());
    }
    match version {
        Err(error) => Some(format!("it does not run: {error}")),
        Ok(output) if !output.success => Some("`skills-manager-cli --version` failed".to_owned()),
        Ok(output) => {
            let first = output.stdout.lines().next().unwrap_or_default().trim();
            let real = first
                .strip_prefix("skills-manager-cli ")
                .is_some_and(|version| {
                    !version.is_empty()
                        && version
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
                });
            (!real).then(|| {
                format!(
                    "`skills-manager-cli --version` printed {:?} instead of `skills-manager-cli <version>`",
                    first.chars().take(80).collect::<String>()
                )
            })
        }
    }
}

/// The elevated one-time Windows setup (from the workstation runbook).
pub const WINDOWS_ELEVATED_SETUP: &str = r#"Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
# Accept SSH only on the tailnet.
Set-NetFirewallRule -Name OpenSSH-Server-In-TCP -InterfaceAlias Tailscale
# Fleet's scripts need Windows PowerShell 5.1 as the SSH login shell.
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
  -Value "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -PropertyType String -Force
# Key login only.
# OpenSSH uses the first value it reads, so line 1 decides for every user.
$c = "$env:ProgramData\ssh\sshd_config"
$t = @(Get-Content $c)
if ($t[0] -ne 'PasswordAuthentication no') { Set-Content $c (@('PasswordAuthentication no') + $t) }
Restart-Service sshd"#;

/// A PowerShell single-quoted string literal.
fn powershell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// The elevated commands that authorize `key_line` for an administrator.
#[must_use]
pub fn administrators_key_block(key_line: &str) -> String {
    let key = powershell_quote(key_line);
    format!(
        "$k = \"$env:ProgramData\\ssh\\administrators_authorized_keys\"\n\
         if (-not ((Test-Path $k) -and (Select-String -Path $k -SimpleMatch {key} -Quiet))) {{\n  \
         Add-Content -Path $k -Value {key} -Encoding ascii\n}}\n\
         icacls $k /inheritance:r /grant \"*{ADMINISTRATORS_SID}:F\" /grant \"*{SYSTEM_SID}:F\""
    )
}

/// The refusal for a Windows administrator account (ADR 0021 decision 7).
#[must_use]
pub fn administrator_refusal(key_line: &str) -> String {
    format!(
        "this account is a member of Administrators, so sshd ignores its own authorized_keys and reads \
         %ProgramData%\\ssh\\administrators_authorized_keys, which only an elevated session can change.\n\n\
         Warning: a key in that file logs in as ANY administrator on this machine, with the full elevated \
         token and no UAC prompt; anyone who may run commands on this machine through Fleet then has full \
         control of it. Prefer joining from a standard (non-administrator) account.\n\n\
         To continue as this administrator anyway, run in Windows PowerShell as Administrator:\n\n{}\n\n\
         then run `fleetctl machines join --admin-key-installed` again (with the same other options).",
        administrators_key_block(key_line)
    )
}

/// The newest version id on the first page of a catalog versions listing
/// (the controller orders it newest first).
#[must_use]
pub fn newest_version(page: &Value) -> Option<String> {
    page["items"]
        .as_array()?
        .iter()
        .max_by_key(|version| version["publishedAt"].as_i64().unwrap_or(i64::MIN))
        .and_then(|version| version["id"].as_str())
        .map(str::to_owned)
}

/// The agents a Skills Manager snapshot reports installed and enabled.
#[must_use]
pub fn installed_agents(snapshot: &Value) -> Vec<String> {
    snapshot["data"]["agents"]
        .as_array()
        .map(|agents| {
            agents
                .iter()
                .filter(|agent| agent["installed"] == true && agent["enabled"] != false)
                .filter_map(|agent| agent["key"].as_str())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The onboarding draft request.
#[must_use]
pub fn draft_body(user: &str, host: &str, port: u16, name: &str) -> Value {
    json!({
        "user": user,
        "host": host,
        "port": port,
        "name": name,
        "auth": {"type": "agent"},
    })
}

/// The `fleet` skill rollout request.
#[must_use]
pub fn rollout_body(
    version_id: &str,
    machine_id: &str,
    endpoint_id: &str,
    agents: &[String],
) -> Value {
    json!({
        "versionId": version_id,
        "machineId": machine_id,
        "endpointId": endpoint_id,
        "auth": {"type": "agent"},
        "agents": agents,
        "timeoutSeconds": ROLLOUT_TIMEOUT_SECONDS,
    })
}

/// The plain Skills Manager probe request (no install pin).
#[must_use]
pub fn probe_body(machine_id: &str, endpoint_id: &str) -> Value {
    json!({
        "machineId": machine_id,
        "endpointId": endpoint_id,
        "auth": {"type": "agent"},
        "agents": [],
        "dryRun": false,
        "timeoutSeconds": ROLLOUT_TIMEOUT_SECONDS,
    })
}

/// The refusal for an observed host key that is not this machine's own.
#[must_use]
pub fn fingerprint_mismatch(local: &str, observed: &str, host: &str, port: u16) -> String {
    format!(
        "REFUSED: the host key the controller saw at {host}:{port} ({observed}) is not this machine's own \
         key ({local}). The controller is not talking to this machine: the address may belong to another \
         machine, or something is intercepting the connection. Nothing was confirmed and the draft was \
         cancelled. Check --host (it must be this machine's tailnet address) before trying again."
    )
}

/// The SSH endpoint of a machine view: the one at `host:port` when several.
#[must_use]
pub fn ssh_endpoint_id(machine: &Value, host: &str, port: u16) -> Option<String> {
    let endpoints: Vec<&Value> = machine["endpoints"]
        .as_array()?
        .iter()
        .filter(|endpoint| endpoint["kind"] == "ssh")
        .collect();
    let suffix = format!("@{host}:{port}");
    endpoints
        .iter()
        .find(|endpoint| {
            endpoint["reference"]
                .as_str()
                .is_some_and(|reference| reference.ends_with(&suffix))
        })
        .or_else(|| endpoints.first())
        .and_then(|endpoint| endpoint["id"].as_str())
        .map(str::to_owned)
}

// ---------------------------------------------------------------------------
// Preflight.
// ---------------------------------------------------------------------------

/// Local findings that stop the join before anything changes.
#[derive(Debug, Default)]
pub struct Preflight {
    /// What is wrong, one line each.
    pub problems: Vec<String>,
    /// Whether the elevated Windows setup block fixes them.
    pub needs_elevated_setup: bool,
    /// Non-blocking notes.
    pub warnings: Vec<String>,
}

/// Checks this machine before anything changes. Read-only.
#[must_use]
pub fn preflight(host: &dyn JoinHost, home: &Path, address: &str, port: u16) -> Preflight {
    let mut found = Preflight::default();
    let banner = host
        .ssh_banner("127.0.0.1", port)
        .or_else(|first| host.ssh_banner(address, port).map_err(|_| first));
    match banner {
        Ok(line) if line.starts_with("SSH-") => {}
        Ok(line) => found.problems.push(format!(
            "port {port} on this machine answers, but not as an SSH server ({:?})",
            line.chars().take(60).collect::<String>()
        )),
        Err(error) => {
            found.problems.push(format!(
                "no SSH server answers on port {port} of this machine: {error}"
            ));
            if host.platform() == Platform::Unix {
                found.problems.push(
                    "start it: `sudo systemctl enable --now ssh` (Debian/Ubuntu; install `openssh-server` first if it is missing)"
                        .to_owned(),
                );
            } else {
                found.needs_elevated_setup = true;
            }
        }
    }
    match host.platform() {
        Platform::Windows => windows_preflight(host, &mut found),
        Platform::Unix => skills_manager_preflight(host, home, &mut found),
    }
    found
}

fn windows_preflight(host: &dyn JoinHost, found: &mut Preflight) {
    let system_root = host
        .env("SystemRoot")
        .unwrap_or_else(|| r"C:\Windows".to_owned());
    let shell = host
        .run(
            Path::new("reg"),
            &["query", r"HKLM\SOFTWARE\OpenSSH", "/v", "DefaultShell"],
        )
        .ok()
        .filter(|output| output.success)
        .and_then(|output| parse_default_shell(&output.stdout));
    match shell {
        Some(value) if is_windows_powershell_51(&value, &system_root) => {}
        Some(value) => {
            found.problems.push(format!(
                "OpenSSH DefaultShell is {value:?}; Fleet needs Windows PowerShell 5.1 ({system_root}\\{WINDOWS_POWERSHELL_51})"
            ));
            found.needs_elevated_setup = true;
        }
        None => {
            found.problems.push(
                "OpenSSH DefaultShell is not set, so SSH logins get cmd.exe; Fleet needs Windows PowerShell 5.1".to_owned(),
            );
            found.needs_elevated_setup = true;
        }
    }
    let config = host
        .env("ProgramData")
        .map(|data| PathBuf::from(data).join("ssh").join("sshd_config"));
    match config.as_deref().map(std::fs::read_to_string) {
        Some(Ok(text)) if password_auth_disabled(&text) => {}
        Some(Ok(_)) => {
            found
                .problems
                .push("sshd accepts password logins; Fleet requires key login only (PasswordAuthentication no)".to_owned());
            found.needs_elevated_setup = true;
        }
        Some(Err(error)) => found.warnings.push(format!(
            "could not read sshd_config to check that password login is off ({error}); make sure it says `PasswordAuthentication no`"
        )),
        None => found
            .warnings
            .push("ProgramData is not set; could not check that password login is off".to_owned()),
    }
}

fn skills_manager_preflight(host: &dyn JoinHost, home: &Path, found: &mut Preflight) {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(on_path) = host.find_on_path("skills-manager-cli") {
        candidates.push(on_path);
    }
    let managed = home.join(".local/bin/skills-manager-cli");
    if managed.is_file() && !candidates.contains(&managed) {
        candidates.push(managed);
    }
    for candidate in candidates {
        let mut head = [0_u8; 2];
        let read = std::fs::File::open(&candidate)
            .and_then(|mut file| file.read(&mut head))
            .unwrap_or(0);
        let version = host.run(&candidate, &["--version"]);
        let reason = stand_in_reason(&head[..read], version.as_ref().map_err(String::as_str));
        if let Some(reason) = reason {
            found.problems.push(format!(
                "{} is not the real Skills Manager CLI: {reason}. Fleet would read fake skills from it and \
                 never install the real one. Remove or rename it yourself (Fleet installs the pinned binary), \
                 then run the join again.",
                candidate.display()
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Running against the controller.
// ---------------------------------------------------------------------------

fn get(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    path: &str,
    query: &[(&'static str, String)],
) -> Result<Value, CliError> {
    crate::send(
        client,
        invocation,
        reqwest::Method::GET,
        path,
        query,
        None,
        uuid::Uuid::now_v7().to_string(),
    )
}

fn post(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    path: &str,
    body: Option<&Value>,
) -> Result<Value, CliError> {
    crate::send(
        client,
        invocation,
        reqwest::Method::POST,
        path,
        &[],
        body,
        uuid::Uuid::now_v7().to_string(),
    )
}

/// Fetches and parses the controller's SSH public key, refusing anything
/// but a usable one.
fn controller_key(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
) -> Result<(Value, fleet_core::SshPublicKey), CliError> {
    let answer = get(client, invocation, SSH_PUBLIC_KEY_PATH, &[])?;
    if answer["state"] != "present" {
        return Err(CliError {
            message: format!(
                "the controller has no usable SSH key ({}): {}",
                answer["state"].as_str().unwrap_or("unknown"),
                answer["detail"].as_str().unwrap_or("no detail")
            ),
        });
    }
    let line = answer["publicKey"].as_str().unwrap_or_default();
    let key = fleet_core::parse_public_key(line).map_err(|error| CliError {
        message: format!("the controller published a malformed SSH key: {error}"),
    })?;
    if answer["fingerprint"].as_str() != Some(key.fingerprint.as_str()) {
        return Err(CliError {
            message: "the controller's published fingerprint does not match its public key"
                .to_owned(),
        });
    }
    Ok((answer, key))
}

/// Runs `system ssh-public-key`.
pub(crate) fn run_public_key(invocation: &Invocation) -> Result<(String, u8), CliError> {
    let client = crate::http_client()?;
    let answer = get(&client, invocation, SSH_PUBLIC_KEY_PATH, &[])?;
    let present = answer["state"] == "present";
    let text = match invocation.output {
        Output::Json => serde_json::to_string_pretty(&answer).unwrap_or_default(),
        Output::Text if present => answer["publicKey"].as_str().unwrap_or_default().to_owned(),
        Output::Text => {
            return Err(CliError {
                message: format!(
                    "the controller has no usable SSH key ({}): {}",
                    answer["state"].as_str().unwrap_or("unknown"),
                    answer["detail"].as_str().unwrap_or("no detail")
                ),
            });
        }
    };
    Ok((text, u8::from(!present)))
}

/// Reports one step on stderr, so stdout stays the result.
fn step(text: &str) {
    eprintln!("fleetctl: {text}");
}

/// The address, account and name the controller will use.
#[derive(Clone, Debug)]
struct Target {
    user: String,
    host: String,
    port: u16,
    name: String,
}

fn resolve_target(host: &dyn JoinHost, args: &JoinArgs) -> Result<Target, CliError> {
    let address = if let Some(address) = &args.host {
        address.trim().to_owned()
    } else {
        {
            let tailscale = host
                .find_on_path("tailscale")
                .unwrap_or_else(|| PathBuf::from("tailscale"));
            let output = host.run(&tailscale, &["ip", "-4"]).map_err(|error| CliError {
                message: format!(
                    "cannot find this machine's tailnet address ({error}); pass --host <address the controller can reach>"
                ),
            })?;
            parse_tailscale_ipv4(&output.stdout)
                .filter(|_| output.success)
                .ok_or_else(|| CliError {
                    message: format!(
                        "`tailscale ip -4` gave no IPv4 address ({}); pass --host <address the controller can reach>",
                        first_line(&output.stdout, &output.stderr)
                    ),
                })?
                .to_string()
        }
    };
    // The key goes into this account's authorized_keys, so the controller
    // must log in as this account: another --user would get a draft whose
    // login was never given the key.
    let account = current_user(host)?;
    let user = match &args.user {
        Some(user) if !same_account(host.platform(), user.trim(), &account) => {
            return Err(CliError {
                message: format!(
                    "--user {} is not this account ({account}): the join installs the controller's key for the \
                     account it runs as, so run it as {} instead (or leave --user out)",
                    user.trim(),
                    user.trim()
                ),
            });
        }
        _ => account,
    };
    let name = match &args.name {
        Some(name) => name.trim().to_owned(),
        None => host.hostname().ok_or_else(|| CliError {
            message: "cannot read this machine's hostname; pass --name <machine name>".to_owned(),
        })?,
    };
    Ok(Target {
        user,
        host: address,
        port: args.port,
        name,
    })
}

/// This machine's own host key, read from its file.
fn local_host_key(
    host: &dyn JoinHost,
    args: &JoinArgs,
) -> Result<(PathBuf, fleet_core::SshPublicKey), CliError> {
    let path = match &args.host_key_file {
        Some(path) => PathBuf::from(path),
        None => match host.platform() {
            Platform::Unix => PathBuf::from("/etc/ssh/ssh_host_ed25519_key.pub"),
            Platform::Windows => PathBuf::from(
                host.env("ProgramData")
                    .unwrap_or_else(|| r"C:\ProgramData".to_owned()),
            )
            .join("ssh")
            .join("ssh_host_ed25519_key.pub"),
        },
    };
    let text = std::fs::read_to_string(&path).map_err(|error| CliError {
        message: format!(
            "cannot read this machine's SSH host key {} ({error}); is the OpenSSH server installed? \
             Pass --host-key-file when sshd uses another HostKey",
            path.display()
        ),
    })?;
    let key = fleet_core::parse_public_key(&text).map_err(|error| CliError {
        message: format!("{} is not an SSH public key: {error}", path.display()),
    })?;
    Ok((path, key))
}

/// The draft id, while it exists, so a failure can cancel it.
struct DraftGuard<'a> {
    client: &'a reqwest::blocking::Client,
    invocation: &'a Invocation,
    id: Option<String>,
}

impl DraftGuard<'_> {
    fn cancel(&mut self) {
        if let Some(id) = self.id.take() {
            let path = format!("/api/v1/machines/onboarding/drafts/{id}/cancel");
            match post(self.client, self.invocation, &path, None) {
                Ok(_) => step(&format!("cancelled onboarding draft {id}")),
                Err(error) => step(&format!(
                    "could not cancel onboarding draft {id} ({error}); cancel it with `fleetctl machines onboard cancel {id}`"
                )),
            }
        }
    }

    fn keep(&mut self) {
        self.id = None;
    }
}

impl Drop for DraftGuard<'_> {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Starts a draft stage operation, waits for it and answers the draft.
fn run_stage(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    draft_id: &str,
    stage: &str,
    timeout: u64,
) -> Result<(Value, Value), CliError> {
    let started = post(
        client,
        invocation,
        &format!("/api/v1/machines/onboarding/drafts/{draft_id}/{stage}"),
        None,
    )?;
    let operation_id = started["data"]["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let finished = crate::wait_for_operation(client, invocation, &operation_id, timeout)?;
    let draft = get(
        client,
        invocation,
        &format!("/api/v1/machines/onboarding/drafts/{draft_id}"),
        &[],
    )?;
    Ok((finished["data"].clone(), draft["data"].clone()))
}

/// The failure detail of a finished operation.
fn operation_failure(operation: &Value) -> String {
    let error = operation["errorJson"]
        .as_str()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .unwrap_or(Value::Null);
    let code = error["code"].as_str().unwrap_or("unknown");
    let message = error["message"]
        .as_str()
        .or_else(|| error["detail"].as_str())
        .unwrap_or("no detail");
    format!(
        "{} ({code}): {message}",
        operation["state"].as_str().unwrap_or("unknown")
    )
}

/// What the enrollment part produced.
struct Enrolled {
    machine_id: String,
    name: String,
    endpoint_id: String,
    resumed: bool,
    skills_manager: Value,
}

/// Draft → test → compare and confirm → test → discover → add.
#[allow(clippy::too_many_lines)]
fn enroll(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    args: &JoinArgs,
    target: &Target,
    local_fingerprint: &str,
) -> Result<Enrolled, CliError> {
    let created = post(
        client,
        invocation,
        "/api/v1/machines/onboarding/drafts",
        Some(&draft_body(
            &target.user,
            &target.host,
            target.port,
            &target.name,
        )),
    )?;
    let draft = &created["data"];
    let mut guard = DraftGuard {
        client,
        invocation,
        id: draft["id"].as_str().map(str::to_owned),
    };
    let draft_id = guard.id.clone().ok_or_else(|| CliError {
        message: "the controller created a draft without an id".to_owned(),
    })?;
    step(&format!(
        "onboarding draft {draft_id} for {}@{}:{}",
        target.user, target.host, target.port
    ));
    // The duplicate candidates are computed on read, not on create.
    let read = get(
        client,
        invocation,
        &format!("/api/v1/machines/onboarding/drafts/{draft_id}"),
        &[],
    )?;
    let duplicates: Vec<Value> = read["data"]["duplicates"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !duplicates.is_empty() {
        guard.cancel();
        let names: Vec<String> = duplicates
            .iter()
            .map(|duplicate| {
                format!(
                    "{} ({})",
                    duplicate["name"].as_str().unwrap_or("-"),
                    duplicate["machineId"].as_str().unwrap_or("-")
                )
            })
            .collect();
        if !args.resume {
            return Err(CliError {
                message: format!(
                    "{}:{} is already enrolled as {}. Run the join again with --resume to deploy the fleet \
                     skill to it, or remove it first (`fleetctl machines remove <machine-id>`)",
                    target.host,
                    target.port,
                    names.join(", ")
                ),
            });
        }
        let [duplicate] = duplicates.as_slice() else {
            return Err(CliError {
                message: format!(
                    "--resume needs exactly one machine at {}:{}, but these share it: {}",
                    target.host,
                    target.port,
                    names.join(", ")
                ),
            });
        };
        let machine_id = duplicate["machineId"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let machine = get(
            client,
            invocation,
            &format!("/api/v1/machines/{machine_id}"),
            &[],
        )?;
        let endpoint_id =
            ssh_endpoint_id(&machine["data"], &target.host, target.port).ok_or_else(|| {
                CliError {
                    message: format!("machine {machine_id} has no SSH endpoint to resume with"),
                }
            })?;
        step(&format!(
            "resuming with machine {} ({machine_id}), already enrolled",
            names[0]
        ));
        return Ok(Enrolled {
            machine_id,
            name: machine["data"]["name"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            endpoint_id,
            resumed: true,
            skills_manager: Value::Null,
        });
    }

    let (_, observed) = run_stage(client, invocation, &draft_id, "test", args.timeout)?;
    let Some(fingerprint) = observed["hostKey"]["fingerprint"].as_str() else {
        return Err(CliError {
            message: format!(
                "the controller could not reach {}:{} to read its host key: {}. Check that --host is this \
                 machine's tailnet address and that the tailnet lets the controller reach port {}",
                target.host,
                target.port,
                observed["lastTest"]["detail"]
                    .as_str()
                    .unwrap_or("no detail"),
                target.port
            ),
        });
    };
    if !fleet_core::fingerprints_match(fingerprint, local_fingerprint) {
        guard.cancel();
        return Err(CliError {
            message: fingerprint_mismatch(
                local_fingerprint,
                fingerprint,
                &target.host,
                target.port,
            ),
        });
    }
    step(&format!(
        "host key {fingerprint} matches this machine's own key; confirming"
    ));
    post(
        client,
        invocation,
        &format!("/api/v1/machines/onboarding/drafts/{draft_id}/confirm-host-key"),
        Some(&json!({ "fingerprint": local_fingerprint })),
    )?;

    let (_, tested) = run_stage(client, invocation, &draft_id, "test", args.timeout)?;
    if tested["lastTest"]["connected"] != true {
        let detail = tested["lastTest"]["detail"].as_str().unwrap_or("no detail");
        let hint = if detail.contains("Permission denied") {
            " The controller's key was refused: on Windows an administrator's key must be in \
             administrators_authorized_keys; on Linux check that sshd reads ~/.ssh/authorized_keys."
        } else if detail.contains("Load key") {
            " The controller cannot read its own key file; see the controller log at startup."
        } else {
            ""
        };
        return Err(CliError {
            message: format!(
                "the controller could not log in as {}: {detail}.{hint}",
                target.user
            ),
        });
    }
    if let Some(reason) = tested["shellCheck"]["refusalReason"].as_str() {
        return Err(CliError {
            message: format!(
                "the login shell is refused ({reason}): {}",
                tested["shellCheck"]["refusalDetail"]
                    .as_str()
                    .unwrap_or("no detail")
            ),
        });
    }
    step("the controller logged in; discovering this machine");

    let (discover, _) = run_stage(client, invocation, &draft_id, "discover", args.timeout)?;
    if discover["state"] != "succeeded" {
        return Err(CliError {
            message: format!(
                "discovery did not succeed: {}",
                operation_failure(&discover)
            ),
        });
    }

    let added = post(
        client,
        invocation,
        &format!("/api/v1/machines/onboarding/drafts/{draft_id}/add"),
        None,
    )?;
    guard.keep();
    let machine = &added["data"]["machine"];
    let machine_id = machine["id"].as_str().unwrap_or_default().to_owned();
    let endpoint_id = ssh_endpoint_id(machine, &target.host, target.port).unwrap_or_default();
    step(&format!("added machine {} ({machine_id})", target.name));
    Ok(Enrolled {
        machine_id,
        name: machine["name"].as_str().unwrap_or(&target.name).to_owned(),
        endpoint_id,
        resumed: false,
        skills_manager: added["data"]["skillsManager"].clone(),
    })
}

/// Follows Skills Manager to a fresh snapshot and rolls out the `fleet`
/// skill. Answers the `skills` part of the summary and whether it failed.
#[allow(clippy::too_many_lines)]
fn deploy_skills(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    args: &JoinArgs,
    enrolled: &Enrolled,
) -> (Value, Value, bool) {
    let mut manager = json!({ "followUp": enrolled.skills_manager.clone() });
    let failed = |manager: Value, reason: String| {
        (
            manager,
            json!({ "status": "failed", "reason": reason }),
            true,
        )
    };
    // The install the add queued, or a plain probe of what is installed.
    let probe_id = if enrolled.skills_manager["status"] == "queued" {
        enrolled.skills_manager["operationId"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    } else {
        {
            if let Some(reason) = enrolled.skills_manager["reason"].as_str() {
                step(&format!("Skills Manager install not queued: {reason}"));
            }
            match post(
                client,
                invocation,
                &format!("/api/v1/machines/{}/skills/operations", enrolled.machine_id),
                Some(&probe_body(&enrolled.machine_id, &enrolled.endpoint_id)),
            ) {
                Ok(started) => started["data"]["id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                Err(error) => {
                    return failed(manager, format!("could not probe Skills Manager: {error}"));
                }
            }
        }
    };
    step(&format!("waiting for skills.probe {probe_id}"));
    manager["operationId"] = json!(probe_id);
    let probe = match crate::wait_for_operation(client, invocation, &probe_id, args.timeout) {
        Ok(body) => body["data"].clone(),
        Err(error) => return failed(manager, error.message),
    };
    manager["state"] = probe["state"].clone();
    if probe["state"] != "succeeded" {
        return failed(
            manager,
            format!(
                "the Skills Manager probe did not succeed: {}",
                operation_failure(&probe)
            ),
        );
    }
    let agents = if args.agents.is_empty() {
        match get(
            client,
            invocation,
            &format!("/api/v1/machines/{}/skills", enrolled.machine_id),
            &[],
        ) {
            Ok(snapshot) if snapshot["data"]["availability"] != "available" => {
                return failed(
                    manager,
                    format!(
                        "Skills Manager is {} on the machine (the controller installs it after an add when \
                         FLEET_SKILLS_MANAGER_AUTO_INSTALL is on; install skills-manager-cli by hand otherwise)",
                        snapshot["data"]["availability"]
                            .as_str()
                            .unwrap_or("unknown")
                    ),
                );
            }
            Ok(snapshot) => installed_agents(&snapshot["data"]),
            Err(error) => {
                return failed(
                    manager,
                    format!("could not read the Skills Manager snapshot: {error}"),
                );
            }
        }
    } else {
        args.agents.clone()
    };
    if agents.is_empty() {
        return (
            manager,
            json!({
                "status": "skipped",
                "agents": [],
                "reason": "Skills Manager reports no coding agent installed; install one, then run the join again with --resume",
            }),
            false,
        );
    }
    let versions = match get(
        client,
        invocation,
        &format!("/api/v1/skills/catalog/{BUILTIN_FLEET_CATALOG_ID}/versions"),
        &[("limit", "1".to_owned())],
    ) {
        Ok(page) => page,
        Err(error) => {
            return failed(
                manager,
                format!("could not list the fleet skill's versions: {error}"),
            );
        }
    };
    let Some(version_id) = newest_version(&versions) else {
        return failed(
            manager,
            "the controller has no published fleet skill version".to_owned(),
        );
    };
    step(&format!(
        "rolling out the fleet skill ({version_id}) to {}",
        agents.join(", ")
    ));
    // A fresh key per attempt: an identical earlier request that failed
    // would otherwise answer with that failed operation (#644).
    let started = crate::send_with_key(
        client,
        invocation,
        reqwest::Method::POST,
        "/api/v1/skills/catalog/rollouts",
        &[],
        Some(&rollout_body(
            &version_id,
            &enrolled.machine_id,
            &enrolled.endpoint_id,
            &agents,
        )),
        uuid::Uuid::now_v7().to_string(),
        Some(&format!("machines-join-{}", uuid::Uuid::now_v7())),
    );
    let operation_id = match started {
        Ok(body) => body["data"]["id"].as_str().unwrap_or_default().to_owned(),
        Err(error) => return failed(manager, format!("the rollout was refused: {error}")),
    };
    let rollout = match crate::wait_for_operation(client, invocation, &operation_id, args.timeout) {
        Ok(body) => body["data"].clone(),
        Err(error) => return failed(manager, error.message),
    };
    let ok = rollout["state"] == "succeeded";
    (
        manager,
        json!({
            "status": if ok { "deployed" } else { "failed" },
            "versionId": version_id,
            "agents": agents,
            "operationId": operation_id,
            "reason": if ok { Value::Null } else { json!(operation_failure(&rollout)) },
        }),
        !ok,
    )
}

/// Runs `machines join` on the real machine.
pub(crate) fn run(invocation: &Invocation, args: &JoinArgs) -> Result<(String, u8), CliError> {
    run_on(invocation, args, &SystemHost)
}

/// Runs `machines join` with `host` as the local machine.
///
/// # Errors
///
/// Fails, before the machine is added, on any refusal; the draft the join
/// created is cancelled. After the add, a skills failure is reported in the
/// summary with exit code 1 instead.
pub fn run_on(
    invocation: &Invocation,
    args: &JoinArgs,
    host: &dyn JoinHost,
) -> Result<(String, u8), CliError> {
    let client = crate::http_client()?;
    let (published, key) = controller_key(&client, invocation)?;
    step(&format!("controller SSH key {}", key.fingerprint));

    let home = home_dir(host)?;
    let target = resolve_target(host, args)?;
    let (host_key_path, local_key) = local_host_key(host, args)?;

    let checks = preflight(host, &home, &target.host, target.port);
    for warning in &checks.warnings {
        step(&format!("warning: {warning}"));
    }
    let administrator = host.platform() == Platform::Windows
        && host
            .run(Path::new("whoami"), &["/groups", "/fo", "csv", "/nh"])
            .is_ok_and(|output| is_administrator(&output.stdout));
    if !checks.problems.is_empty() {
        let mut message = format!(
            "this machine is not ready; nothing was changed:\n  - {}",
            checks.problems.join("\n  - ")
        );
        if checks.needs_elevated_setup {
            message.push_str(
                "\n\nRun once in Windows PowerShell as Administrator, then run the join again:\n\n",
            );
            message.push_str(WINDOWS_ELEVATED_SETUP);
        }
        return Err(CliError { message });
    }

    let (key_install, key_path) = if administrator {
        if !args.admin_key_installed {
            return Err(CliError {
                message: administrator_refusal(&key.line()),
            });
        }
        step(
            "administrator account: using the key the operator installed in administrators_authorized_keys",
        );
        (
            KeyInstall::AdministratorsFile,
            PathBuf::from(
                host.env("ProgramData")
                    .unwrap_or_else(|| r"C:\ProgramData".to_owned()),
            )
            .join("ssh")
            .join("administrators_authorized_keys"),
        )
    } else {
        install_authorized_key(host, &home, &key)?
    };
    step(&format!(
        "controller key {} in {}",
        key_install.id(),
        key_path.display()
    ));

    let enrolled = enroll(&client, invocation, args, &target, &local_key.fingerprint)?;
    let (manager, skills, skills_failed) = if args.no_skills {
        (
            json!({ "followUp": enrolled.skills_manager.clone() }),
            json!({ "status": "skipped", "reason": "--no-skills" }),
            false,
        )
    } else {
        deploy_skills(&client, invocation, args, &enrolled)
    };
    let summary = json!({
        "machineId": enrolled.machine_id,
        "name": enrolled.name,
        "endpointId": enrolled.endpoint_id,
        "endpoint": {"user": target.user, "host": target.host, "port": target.port},
        "resumed": enrolled.resumed,
        "hostKey": {
            "fingerprint": local_key.fingerprint,
            "file": host_key_path.display().to_string(),
        },
        "controllerKey": {
            "fingerprint": published["fingerprint"],
            "authorizedKeys": key_install.id(),
            "file": key_path.display().to_string(),
        },
        "skillsManager": manager,
        "skills": skills,
        "warnings": checks.warnings,
    });
    let text = match invocation.output {
        Output::Json => serde_json::to_string_pretty(&summary).unwrap_or_default(),
        Output::Text => render(&summary),
    };
    Ok((text, u8::from(skills_failed)))
}

/// The human summary of a join.
#[must_use]
pub fn render(summary: &Value) -> String {
    let text = |value: &Value| value.as_str().unwrap_or("-").to_owned();
    let mut lines = vec![
        format!(
            "{} machine {} ({})",
            if summary["resumed"] == true {
                "resumed"
            } else {
                "joined"
            },
            text(&summary["name"]),
            text(&summary["machineId"])
        ),
        format!(
            "  endpoint {}  {}@{}:{}",
            text(&summary["endpointId"]),
            text(&summary["endpoint"]["user"]),
            text(&summary["endpoint"]["host"]),
            summary["endpoint"]["port"]
        ),
        format!("  host key {}", text(&summary["hostKey"]["fingerprint"])),
        format!(
            "  controller key {} ({})",
            text(&summary["controllerKey"]["fingerprint"]),
            text(&summary["controllerKey"]["authorizedKeys"])
        ),
    ];
    let skills = &summary["skills"];
    match skills["status"].as_str() {
        Some("deployed") => {
            let agents: Vec<&str> = skills["agents"]
                .as_array()
                .map(|agents| agents.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            lines.push(format!("  fleet skill deployed to {}", agents.join(", ")));
        }
        Some(status) => lines.push(format!(
            "  fleet skill {status}: {}",
            text(&skills["reason"])
        )),
        None => {}
    }
    if skills["status"] == "failed" {
        lines.push(
            "  the machine is enrolled; fix the cause and run `fleetctl machines join --resume`"
                .to_owned(),
        );
    }
    for warning in summary["warnings"].as_array().into_iter().flatten() {
        lines.push(format!("  warning: {}", text(warning)));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests;
