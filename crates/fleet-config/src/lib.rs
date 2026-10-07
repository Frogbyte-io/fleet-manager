//! Typed controller configuration and startup validation.
//!
//! The controller must not start on a setting it does not understand, and it
//! must never render secret values. This crate owns both properties: it loads
//! configuration from layered sources, validates every unsafe setting before
//! readiness, and can print an effective-config summary that structurally
//! cannot contain secret material, because the configuration holds only
//! references (paths), never the secret values themselves.
//!
//! Documented precedence, from weakest to strongest:
//!
//! 1. Built-in defaults — deliberately the safe ones: loopback listener.
//! 2. The configuration file, selected with `--config <path>` (TOML).
//! 3. Environment variables (`FLEET_LISTEN`, `FLEET_TAILSCALE_SERVE_LISTEN`,
//!    `FLEET_WEB_DIST`, `FLEET_DATA_DIR`, `FLEET_MASTER_KEY_FILE`,
//!    `FLEET_LAB_SWEEP_INTERVAL_SECONDS`, `FLEET_LAB_MEMORY_OVERCOMMIT`,
//!    `FLEET_LAB_CPU_OVERCOMMIT`, `FLEET_LAB_CAPACITY_MAX_AGE_SECONDS`).
//!
//! `FLEET_LAB_SWEEP_INTERVAL_SECONDS` (TOML `lab_sweep_interval_seconds`,
//! default 60) is the Lab sweeper's interval; `0` disables the background
//! sweeper and leaves the manual sweep. A value that is not a whole number
//! of seconds fails configuration loading.
//!
//! `FLEET_TAILSCALE_SERVE_LISTEN` is optional. When set, it must be a valid,
//! nonzero loopback socket address distinct from `FLEET_LISTEN`; invalid
//! addresses fail configuration loading with [`ConfigError::TailscaleServeListenInvalid`].
//!
//! There is no default master-key path: an unset key source is a valid
//! pre-secrets state that must degrade loudly rather than point at a file
//! that does not exist.
#![warn(missing_docs)]

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The configuration file format version this crate reads. A file that does
/// not declare exactly this version is rejected rather than guessed at.
pub const CONFIG_VERSION: u32 = 1;

/// Environment variable holding the HTTP listen address.
pub const LISTEN_VAR: &str = "FLEET_LISTEN";
/// Environment variable holding the built web shell's directory.
pub const WEB_DIST_VAR: &str = "FLEET_WEB_DIST";
/// Environment variable holding the controller's runtime state directory.
pub const DATA_DIR_VAR: &str = "FLEET_DATA_DIR";
/// Environment variable holding the master key file path.
pub const MASTER_KEY_FILE_VAR: &str = "FLEET_MASTER_KEY_FILE";
/// Environment variable enabling a dedicated Tailscale Serve identity listener.
pub const TAILSCALE_SERVE_LISTEN_VAR: &str = "FLEET_TAILSCALE_SERVE_LISTEN";
/// Environment variable holding the Lab sweeper's interval in seconds
/// (`0` disables the background sweeper; the manual sweep stays).
pub const LAB_SWEEP_INTERVAL_VAR: &str = "FLEET_LAB_SWEEP_INTERVAL_SECONDS";
/// The default Lab sweeper interval (FM-716).
pub const DEFAULT_LAB_SWEEP_INTERVAL_SECONDS: u64 = 60;
/// Environment variable holding the Lab placement memory overcommit ratio.
pub const LAB_MEMORY_OVERCOMMIT_VAR: &str = "FLEET_LAB_MEMORY_OVERCOMMIT";
/// Environment variable holding the Lab placement CPU overcommit ratio.
pub const LAB_CPU_OVERCOMMIT_VAR: &str = "FLEET_LAB_CPU_OVERCOMMIT";
/// Environment variable holding the maximum age of a node capacity
/// observation Lab placement accepts, in seconds.
pub const LAB_CAPACITY_MAX_AGE_VAR: &str = "FLEET_LAB_CAPACITY_MAX_AGE_SECONDS";
/// The largest Lab overcommit ratio accepted.
pub const MAX_LAB_OVERCOMMIT: f64 = 16.0;
/// The largest Lab capacity observation age accepted: one day.
pub const MAX_LAB_CAPACITY_AGE_SECONDS: u64 = 86_400;

/// The default listen address: loopback only, because the controller is a
/// trusted-LAN service and must not face an untrusted network by accident.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
/// The default web shell directory for development runs beside the workspace.
pub const DEFAULT_WEB_DIST: &str = "./web";
/// The default runtime state directory.
pub const DEFAULT_DATA_DIR: &str = "./data";

/// The effective controller configuration after layering and validation.
#[derive(Clone, Debug)]
pub struct ControllerConfig {
    /// The address the HTTP listener binds.
    pub listen: SocketAddr,
    /// Optional loopback listener dedicated to requests proxied by Tailscale Serve.
    pub tailscale_serve_listen: Option<SocketAddr>,
    /// The directory holding the built web shell; served at `/`.
    pub web_dist: PathBuf,
    /// The directory holding runtime state (database, backups, operations).
    /// Created during validation if missing.
    pub data_dir: PathBuf,
    /// The master key file for the secret store, when configured. The path is
    /// a reference; the key material is read by the secret store, never here.
    pub master_key_file: Option<PathBuf>,
    /// How often the Lab sweeper expires leases, queues due cleanups, and
    /// reconciles Lab guests, in seconds; `0` disables it.
    pub lab_sweep_interval_seconds: u64,
    /// The Lab placement policy (FM-715).
    pub lab_placement: LabPlacementConfig,
}

/// The Lab placement policy settings (FM-715).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LabPlacementConfig {
    /// The ratio applied to a node's total memory; `1.0` is no overcommit.
    pub memory_overcommit: f64,
    /// The ratio applied to a node's logical CPU count; `1.0` is no
    /// overcommit.
    pub cpu_overcommit: f64,
    /// How old a node capacity observation may be before placement refuses
    /// it, in seconds.
    pub capacity_max_age_seconds: u64,
}

impl Default for LabPlacementConfig {
    fn default() -> Self {
        Self {
            memory_overcommit: 1.0,
            cpu_overcommit: 1.0,
            capacity_max_age_seconds: 300,
        }
    }
}

/// The TOML configuration file's on-disk shape.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    /// Absent versions are reported as a version problem, not a parse one.
    version: Option<u32>,
    listen: Option<String>,
    tailscale_serve_listen: Option<String>,
    web_dist: Option<String>,
    data_dir: Option<String>,
    master_key_file: Option<String>,
    lab_sweep_interval_seconds: Option<u64>,
    lab_memory_overcommit: Option<f64>,
    lab_cpu_overcommit: Option<f64>,
    lab_capacity_max_age_seconds: Option<u64>,
}

/// A configuration problem that is safe to print: paths and expected facts,
/// never secret material (this crate never reads file contents).
#[derive(Debug)]
pub enum ConfigError {
    /// The configuration file could not be read from disk.
    FileRead {
        /// The file path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        error: std::io::Error,
    },
    /// The configuration file is not the expected TOML shape.
    Parse {
        /// The parser's complaint, verbatim.
        detail: String,
    },
    /// The file declares a different format version than this crate reads.
    Version {
        /// The version the file declared, when any.
        found: Option<u32>,
        /// The version this build reads.
        expected: u32,
    },
    /// The listen setting is not a valid socket address.
    ListenInvalid {
        /// The value that failed to parse.
        value: String,
    },
    /// The configured Tailscale Serve listener is not a socket address.
    TailscaleServeListenInvalid {
        /// The value that failed to parse.
        value: String,
    },
    /// The Lab sweeper interval is not a whole number of seconds.
    LabSweepIntervalInvalid {
        /// The value that failed to parse.
        value: String,
    },
    /// The Tailscale Serve listener is not the documented IPv4 loopback target.
    TailscaleServeListenerNotLoopback {
        /// The configured address.
        value: SocketAddr,
    },
    /// Port zero cannot be used because Tailscale Serve needs a stable target.
    TailscaleServeListenerPortZero,
    /// Identity mode requires the regular controller listener to remain local.
    IdentityModeRequiresLoopbackListener {
        /// The configured address.
        value: SocketAddr,
    },
    /// The direct and Tailscale Serve listeners cannot bind the same address.
    ControllerListenersConflict {
        /// The conflicting address.
        value: SocketAddr,
    },
    /// The runtime state directory could not be created or is not one.
    DataDirUnavailable {
        /// The directory path that is unusable.
        path: PathBuf,
        /// Why it is unusable.
        error: std::io::Error,
    },
    /// The configured master key file does not exist.
    MasterKeyMissing {
        /// The configured path.
        path: PathBuf,
    },
    /// The configured master key path is not a regular file.
    MasterKeyNotAFile {
        /// The configured path.
        path: PathBuf,
    },
    /// The master key file's permissions would expose it beyond its owner.
    MasterKeyPermissions {
        /// The configured path.
        path: PathBuf,
        /// The observed permission bits.
        mode: u32,
    },
    /// A Lab placement setting is not a number in its accepted range.
    LabPlacementInvalid {
        /// The setting's name.
        setting: &'static str,
        /// The value that was refused.
        value: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LabPlacementInvalid { setting, value } => write!(
                f,
                "{setting} must be an overcommit ratio greater than 0 and at most {MAX_LAB_OVERCOMMIT}, or an age of 1..={MAX_LAB_CAPACITY_AGE_SECONDS} seconds; got {value:?}"
            ),
            Self::FileRead { path, error } => {
                write!(f, "cannot read config file {}: {error}", path.display())
            }
            Self::Parse { detail } => write!(f, "invalid config file: {detail}"),
            Self::Version { found, expected } => match found {
                Some(found) => write!(
                    f,
                    "config file declares version {found}, but this build reads version {expected}"
                ),
                None => write!(
                    f,
                    "config file does not declare a version; this build reads version {expected}"
                ),
            },
            Self::ListenInvalid { value } => {
                write!(f, "{LISTEN_VAR} is not a socket address: {value:?}")
            }
            Self::LabSweepIntervalInvalid { value } => write!(
                f,
                "{LAB_SWEEP_INTERVAL_VAR} must be a whole number of seconds (0 disables the sweeper), not {value:?}"
            ),
            Self::TailscaleServeListenInvalid { value } => write!(
                f,
                "{TAILSCALE_SERVE_LISTEN_VAR} is not a socket address: {value:?}"
            ),
            Self::TailscaleServeListenerNotLoopback { value } => write!(
                f,
                "{TAILSCALE_SERVE_LISTEN_VAR} must use 127.0.0.1 for Tailscale Serve, got {value}"
            ),
            Self::TailscaleServeListenerPortZero => write!(
                f,
                "{TAILSCALE_SERVE_LISTEN_VAR} must use a fixed nonzero port for Tailscale Serve"
            ),
            Self::IdentityModeRequiresLoopbackListener { value } => write!(
                f,
                "{TAILSCALE_SERVE_LISTEN_VAR} is enabled, so {LISTEN_VAR} must also use a loopback address, got {value}"
            ),
            Self::ControllerListenersConflict { value } => write!(
                f,
                "{TAILSCALE_SERVE_LISTEN_VAR} must differ from {LISTEN_VAR}, both are {value}"
            ),
            Self::DataDirUnavailable { path, error } => {
                write!(
                    f,
                    "runtime state directory {} is unavailable: {error}",
                    path.display()
                )
            }
            Self::MasterKeyMissing { path } => {
                write!(f, "master key file {} does not exist", path.display())
            }
            Self::MasterKeyNotAFile { path } => {
                write!(
                    f,
                    "master key path {} is not a regular file",
                    path.display()
                )
            }
            Self::MasterKeyPermissions { path, mode } => write!(
                f,
                "master key file {} is too exposed: mode {mode:04o}, expected owner-only (0600)",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Resolves one environment lookup; production reads the process environment.
pub type EnvLookup<'a> = &'a dyn Fn(&str) -> Option<String>;

/// Reads the process environment.
pub fn process_env() -> EnvLookup<'static> {
    &|key| std::env::var(key).ok()
}

/// Layered load: built-in defaults, then the TOML file (when a path is given),
/// then the environment lookup. Validation runs afterwards in [`ControllerConfig::validate`].
///
/// # Errors
///
/// Fails when the file cannot be read or parsed, declares a foreign version,
/// or the listen setting is not a socket address.
pub fn load(
    config_file: Option<&Path>,
    env: EnvLookup<'_>,
) -> Result<ControllerConfig, ConfigError> {
    let mut listen: Option<String> = None;
    let mut tailscale_serve_listen: Option<String> = None;
    let mut web_dist: Option<String> = None;
    let mut data_dir: Option<String> = None;
    let mut master_key_file: Option<String> = None;
    let mut lab_sweep_interval_seconds: Option<u64> = None;
    let mut lab_placement = LabPlacementConfig::default();

    if let Some(path) = config_file {
        let raw = std::fs::read_to_string(path).map_err(|error| ConfigError::FileRead {
            path: path.to_path_buf(),
            error,
        })?;
        let file: ConfigFile = toml::from_str(&raw).map_err(|error| ConfigError::Parse {
            detail: error.to_string(),
        })?;
        if file.version != Some(CONFIG_VERSION) {
            return Err(ConfigError::Version {
                found: file.version,
                expected: CONFIG_VERSION,
            });
        }
        listen = file.listen;
        tailscale_serve_listen = file.tailscale_serve_listen;
        web_dist = file.web_dist;
        data_dir = file.data_dir;
        master_key_file = file.master_key_file;
        lab_sweep_interval_seconds = file.lab_sweep_interval_seconds;
        if let Some(ratio) = file.lab_memory_overcommit {
            lab_placement.memory_overcommit = ratio;
        }
        if let Some(ratio) = file.lab_cpu_overcommit {
            lab_placement.cpu_overcommit = ratio;
        }
        if let Some(age) = file.lab_capacity_max_age_seconds {
            lab_placement.capacity_max_age_seconds = age;
        }
    }

    listen = env(LISTEN_VAR).or(listen);
    tailscale_serve_listen = env(TAILSCALE_SERVE_LISTEN_VAR).or(tailscale_serve_listen);
    web_dist = env(WEB_DIST_VAR).or(web_dist);
    data_dir = env(DATA_DIR_VAR).or(data_dir);
    master_key_file = env(MASTER_KEY_FILE_VAR).or(master_key_file);
    if let Some(raw) = env(LAB_SWEEP_INTERVAL_VAR) {
        lab_sweep_interval_seconds = Some(
            raw.trim()
                .parse()
                .map_err(|_| ConfigError::LabSweepIntervalInvalid { value: raw })?,
        );
    }
    let invalid =
        |setting: &'static str, value: String| ConfigError::LabPlacementInvalid { setting, value };
    if let Some(raw) = env(LAB_MEMORY_OVERCOMMIT_VAR) {
        lab_placement.memory_overcommit = raw
            .trim()
            .parse()
            .map_err(|_| invalid("lab_memory_overcommit", raw))?;
    }
    if let Some(raw) = env(LAB_CPU_OVERCOMMIT_VAR) {
        lab_placement.cpu_overcommit = raw
            .trim()
            .parse()
            .map_err(|_| invalid("lab_cpu_overcommit", raw))?;
    }
    if let Some(raw) = env(LAB_CAPACITY_MAX_AGE_VAR) {
        lab_placement.capacity_max_age_seconds = raw
            .trim()
            .parse()
            .map_err(|_| invalid("lab_capacity_max_age_seconds", raw))?;
    }
    for (setting, ratio) in [
        ("lab_memory_overcommit", lab_placement.memory_overcommit),
        ("lab_cpu_overcommit", lab_placement.cpu_overcommit),
    ] {
        if !ratio.is_finite() || ratio <= 0.0 || ratio > MAX_LAB_OVERCOMMIT {
            return Err(invalid(setting, ratio.to_string()));
        }
    }
    if lab_placement.capacity_max_age_seconds == 0
        || lab_placement.capacity_max_age_seconds > MAX_LAB_CAPACITY_AGE_SECONDS
    {
        return Err(invalid(
            "lab_capacity_max_age_seconds",
            lab_placement.capacity_max_age_seconds.to_string(),
        ));
    }

    let listen_raw = listen.unwrap_or_else(|| DEFAULT_LISTEN.to_owned());
    let listen: SocketAddr = listen_raw
        .parse()
        .map_err(|_| ConfigError::ListenInvalid { value: listen_raw })?;
    let tailscale_serve_listen = match tailscale_serve_listen {
        Some(raw) => Some(
            raw.parse()
                .map_err(|_| ConfigError::TailscaleServeListenInvalid { value: raw })?,
        ),
        None => None,
    };

    Ok(ControllerConfig {
        listen,
        tailscale_serve_listen,
        web_dist: web_dist.map_or_else(|| PathBuf::from(DEFAULT_WEB_DIST), PathBuf::from),
        data_dir: data_dir.map_or_else(|| PathBuf::from(DEFAULT_DATA_DIR), PathBuf::from),
        master_key_file: master_key_file.map(PathBuf::from),
        lab_sweep_interval_seconds: lab_sweep_interval_seconds
            .unwrap_or(DEFAULT_LAB_SWEEP_INTERVAL_SECONDS),
        lab_placement,
    })
}

impl ControllerConfig {
    /// Validates every setting whose failure must happen before readiness:
    /// the state directory is usable, and a configured master key file exists,
    /// is regular, and is not readable beyond its owner (Unix).
    ///
    /// # Errors
    ///
    /// Fails closed on the first unsafe setting, with a diagnostic naming the
    /// setting and never any secret value.
    pub fn validate(&self) -> Result<(), ConfigError> {
        std::fs::create_dir_all(&self.data_dir).map_err(|error| {
            ConfigError::DataDirUnavailable {
                path: self.data_dir.clone(),
                error,
            }
        })?;
        if !self.data_dir.is_dir() {
            return Err(ConfigError::DataDirUnavailable {
                path: self.data_dir.clone(),
                error: std::io::Error::other("not a directory"),
            });
        }

        if let Some(serve_listen) = self.tailscale_serve_listen {
            if serve_listen.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) {
                return Err(ConfigError::TailscaleServeListenerNotLoopback {
                    value: serve_listen,
                });
            }
            if serve_listen.port() == 0 {
                return Err(ConfigError::TailscaleServeListenerPortZero);
            }
            if !self.listen.ip().is_loopback() {
                return Err(ConfigError::IdentityModeRequiresLoopbackListener {
                    value: self.listen,
                });
            }
            if self.listen == serve_listen {
                return Err(ConfigError::ControllerListenersConflict {
                    value: serve_listen,
                });
            }
        }

        if let Some(key_file) = &self.master_key_file {
            validate_master_key_file(key_file)?;
        }
        Ok(())
    }

    /// The effective configuration as safe-to-print text: every reference is
    /// shown, and no secret value can appear because this crate never reads
    /// file contents.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut lines = vec![
            format!("listen = {}", self.listen),
            format!("web_dist = {}", self.web_dist.display()),
            format!("data_dir = {}", self.data_dir.display()),
            format!("config_version = {CONFIG_VERSION}"),
            format!(
                "lab_sweep_interval_seconds = {}{}",
                self.lab_sweep_interval_seconds,
                if self.lab_sweep_interval_seconds == 0 {
                    " (disabled)"
                } else {
                    ""
                }
            ),
        ];
        if let Some(address) = self.tailscale_serve_listen {
            lines.push(format!("tailscale_serve_listen = {address}"));
        }
        match &self.master_key_file {
            Some(path) => lines.push(format!(
                "master_key_file = {} (mode 0600 required)",
                path.display()
            )),
            None => lines.push("master_key_file = <unset; secret store unavailable>".to_owned()),
        }
        lines.push(format!(
            "lab_memory_overcommit = {}",
            self.lab_placement.memory_overcommit
        ));
        lines.push(format!(
            "lab_cpu_overcommit = {}",
            self.lab_placement.cpu_overcommit
        ));
        lines.push(format!(
            "lab_capacity_max_age_seconds = {}",
            self.lab_placement.capacity_max_age_seconds
        ));
        lines.join("\n")
    }
}

fn validate_master_key_file(path: &Path) -> Result<(), ConfigError> {
    let metadata = std::fs::metadata(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => ConfigError::MasterKeyMissing {
            path: path.to_path_buf(),
        },
        _ => ConfigError::MasterKeyNotAFile {
            path: path.to_path_buf(),
        },
    })?;
    if !metadata.is_file() {
        return Err(ConfigError::MasterKeyNotAFile {
            path: path.to_path_buf(),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(ConfigError::MasterKeyPermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
