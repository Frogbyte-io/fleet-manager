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
//! 3. Environment variables (`FLEET_LISTEN`, `FLEET_WEB_DIST`,
//!    `FLEET_DATA_DIR`, `FLEET_MASTER_KEY_FILE`).
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
    /// The directory holding the built web shell; served at `/`.
    pub web_dist: PathBuf,
    /// The directory holding runtime state (database, backups, operations).
    /// Created during validation if missing.
    pub data_dir: PathBuf,
    /// The master key file for the secret store, when configured. The path is
    /// a reference; the key material is read by the secret store, never here.
    pub master_key_file: Option<PathBuf>,
}

/// The TOML configuration file's on-disk shape.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    /// Absent versions are reported as a version problem, not a parse one.
    version: Option<u32>,
    listen: Option<String>,
    web_dist: Option<String>,
    data_dir: Option<String>,
    master_key_file: Option<String>,
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
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
    let mut web_dist: Option<String> = None;
    let mut data_dir: Option<String> = None;
    let mut master_key_file: Option<String> = None;

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
        web_dist = file.web_dist;
        data_dir = file.data_dir;
        master_key_file = file.master_key_file;
    }

    listen = env(LISTEN_VAR).or(listen);
    web_dist = env(WEB_DIST_VAR).or(web_dist);
    data_dir = env(DATA_DIR_VAR).or(data_dir);
    master_key_file = env(MASTER_KEY_FILE_VAR).or(master_key_file);

    let listen_raw = listen.unwrap_or_else(|| DEFAULT_LISTEN.to_owned());
    let listen: SocketAddr = listen_raw
        .parse()
        .map_err(|_| ConfigError::ListenInvalid { value: listen_raw })?;

    Ok(ControllerConfig {
        listen,
        web_dist: web_dist.map_or_else(|| PathBuf::from(DEFAULT_WEB_DIST), PathBuf::from),
        data_dir: data_dir.map_or_else(|| PathBuf::from(DEFAULT_DATA_DIR), PathBuf::from),
        master_key_file: master_key_file.map(PathBuf::from),
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
        ];
        match &self.master_key_file {
            Some(path) => lines.push(format!(
                "master_key_file = {} (mode 0600 required)",
                path.display()
            )),
            None => lines.push("master_key_file = <unset; secret store unavailable>".to_owned()),
        }
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
