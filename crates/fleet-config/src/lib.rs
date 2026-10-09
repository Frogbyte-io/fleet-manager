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
//!    `FLEET_LAB_CPU_OVERCOMMIT`, `FLEET_LAB_CAPACITY_MAX_AGE_SECONDS`,
//!    `FLEET_LAB_ARTIFACTS_DIR`, `FLEET_LAB_ARTIFACT_RETENTION_SECONDS`,
//!    `FLEET_LAB_ARTIFACT_MAX_BYTES`, `FLEET_LAB_PUT_MAX_BYTES`, `FLEET_IMAGE_BUILD_PROXY`,
//!    `FLEET_IMAGE_BUILD_NO_PROXY`, `FLEET_IMAGE_BUILD_ADDRESS_POOL`,
//!    `FLEET_IMAGE_BUILD_ADDRESS_POOL_RANGE`,
//!    `FLEET_IMAGE_BUILD_ADDRESS_POOL_GATEWAY`,
//!    `FLEET_IMAGE_BUILD_ADDRESS_POOL_DNS`,
//!    `FLEET_IMAGE_BUILD_ADDRESS_POOL_REFUSE_ISO`).
//!
//! `FLEET_IMAGE_BUILD_ADDRESS_POOL` (TOML `image_build_address_pool`, off by
//! default) is the opt-in build address pool (#337): an IPv4 CIDR, with
//! `..._RANGE` (`first-last`), `..._GATEWAY`, and optionally `..._DNS`. With
//! it, each `proxmox-clone` image build gets a Fleet-assigned static address
//! and Fleet, not the build guest, chooses where the communicator connects.
//! The range, gateway, DNS, and refuse-ISO settings without the CIDR fail
//! loading, so a typo cannot silently leave the pool off.
//!
//! `FLEET_IMAGE_BUILD_PROXY` (TOML `image_build_proxy`, off by default) is
//! the explicit proxy Packer image builds may use (#339). It must be a bare
//! `http://host[:port]`: a value with credentials, a path, a query, or a
//! fragment fails loading, and the error never repeats the value.
//!
//! `FLEET_LAB_SWEEP_INTERVAL_SECONDS` (TOML `lab_sweep_interval_seconds`,
//! default 60) is the Lab sweeper's interval; `0` disables the background
//! sweeper and leaves the manual sweep. A value that is not a whole number
//! of seconds fails configuration loading.
//!
//! Lab artifacts (FM-721) keep their bytes under `FLEET_LAB_ARTIFACTS_DIR`
//! (TOML `lab_artifacts_dir`, default `<data_dir>/lab-artifacts`), for
//! `FLEET_LAB_ARTIFACT_RETENTION_SECONDS` (TOML
//! `lab_artifact_retention_seconds`, default 7 days), and refuse any one
//! artifact above `FLEET_LAB_ARTIFACT_MAX_BYTES` (TOML
//! `lab_artifact_max_bytes`, default 64 MiB). Both numbers must be whole and
//! positive. `lab put` uploads are capped by `FLEET_LAB_PUT_MAX_BYTES` (TOML
//! `lab_put_max_bytes`, default 2 GiB).
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
/// Environment variable holding the Lab artifact directory (FM-721).
pub const LAB_ARTIFACTS_DIR_VAR: &str = "FLEET_LAB_ARTIFACTS_DIR";
/// Environment variable holding how long Lab artifacts are kept, in seconds.
pub const LAB_ARTIFACT_RETENTION_VAR: &str = "FLEET_LAB_ARTIFACT_RETENTION_SECONDS";
/// Environment variable holding the largest Lab artifact, in bytes.
pub const LAB_ARTIFACT_MAX_BYTES_VAR: &str = "FLEET_LAB_ARTIFACT_MAX_BYTES";
/// The default Lab artifact retention: seven days.
pub const DEFAULT_LAB_ARTIFACT_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;
/// The default Lab artifact size cap: 64 MiB.
pub const DEFAULT_LAB_ARTIFACT_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// The environment variable that caps one file `lab put` uploads (#393).
pub const LAB_PUT_MAX_BYTES_VAR: &str = "FLEET_LAB_PUT_MAX_BYTES";
/// The default cap on one `lab put` upload: 2 GiB, enough for packaged
/// desktop installers.
pub const DEFAULT_LAB_PUT_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// The Lab artifact directory's name under the data directory by default.
pub const DEFAULT_LAB_ARTIFACTS_SUBDIR: &str = "lab-artifacts";

/// Environment variable holding the proxy image builds may use (#339). Off
/// when unset or empty.
pub const IMAGE_BUILD_PROXY_VAR: &str = "FLEET_IMAGE_BUILD_PROXY";
/// Environment variable holding the hosts an image build reaches directly
/// even with a proxy configured (`NO_PROXY` syntax).
pub const IMAGE_BUILD_NO_PROXY_VAR: &str = "FLEET_IMAGE_BUILD_NO_PROXY";
/// Environment variable holding the build address pool's CIDR (#337). Off
/// when unset or empty.
pub const IMAGE_BUILD_ADDRESS_POOL_VAR: &str = "FLEET_IMAGE_BUILD_ADDRESS_POOL";
/// The inclusive `first-last` range Fleet hands out from the pool.
pub const IMAGE_BUILD_ADDRESS_POOL_RANGE_VAR: &str = "FLEET_IMAGE_BUILD_ADDRESS_POOL_RANGE";
/// The gateway handed to build guests.
pub const IMAGE_BUILD_ADDRESS_POOL_GATEWAY_VAR: &str = "FLEET_IMAGE_BUILD_ADDRESS_POOL_GATEWAY";
/// Optional DNS servers handed to build guests.
pub const IMAGE_BUILD_ADDRESS_POOL_DNS_VAR: &str = "FLEET_IMAGE_BUILD_ADDRESS_POOL_DNS";
/// Whether `proxmox-iso` builds are refused while the pool is set.
pub const IMAGE_BUILD_ADDRESS_POOL_REFUSE_ISO_VAR: &str =
    "FLEET_IMAGE_BUILD_ADDRESS_POOL_REFUSE_ISO";
/// The longest `NO_PROXY` list accepted.
pub const MAX_IMAGE_BUILD_NO_PROXY_BYTES: usize = 1024;

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
    /// Where Lab artifact bytes live (FM-721). The controller prepares it at
    /// startup and serves without Lab artifacts when it cannot.
    pub lab_artifacts_dir: PathBuf,
    /// How long a Lab artifact is kept, in seconds; the Lab sweeper deletes
    /// it afterwards.
    pub lab_artifact_retention_seconds: u64,
    /// The largest Lab artifact the store accepts, in bytes.
    pub lab_artifact_max_bytes: u64,
    /// The largest file one `lab put` uploads, in bytes (#393).
    pub lab_put_max_bytes: u64,
    /// The Lab placement policy (FM-715).
    pub lab_placement: LabPlacementConfig,
    /// The proxy image builds may use, when the operator opted in (#339).
    pub image_build_proxy: Option<ImageBuildProxy>,
    /// The build address pool, when the operator opted in (#337).
    pub image_build_address_pool: Option<fleet_core::BuildAddressPool>,
}

/// The proxy Packer image builds may use (#339). Credential-free by
/// construction: a URL with userinfo is refused when the setting is read,
/// so everything here may appear in logs, audit metadata, and summaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageBuildProxy {
    /// `http://host[:port]`, normalized.
    url: String,
    /// The `NO_PROXY` list, when one was configured.
    no_proxy: Option<String>,
}

impl ImageBuildProxy {
    /// Parses and validates the two settings.
    ///
    /// # Errors
    ///
    /// Fails when the URL is not a bare `http://host[:port]` (userinfo,
    /// a path, a query, or a fragment are refused) or the list holds
    /// anything but host-list characters. The error names the setting and
    /// the rule, never the value.
    pub fn parse(url: &str, no_proxy: Option<&str>) -> Result<Self, ConfigError> {
        let invalid = |setting: &'static str, rule: &'static str| {
            ConfigError::ImageBuildProxyInvalid { setting, rule }
        };
        let url = url.trim();
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| invalid(IMAGE_BUILD_PROXY_VAR, "must start with http://"))?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme == "https" {
            // Under the certificate pin, `SSL_CERT_FILE` makes the PVE leaf
            // the only trusted root, so the handshake with an HTTPS proxy
            // (a different certificate) could never verify.
            return Err(invalid(
                IMAGE_BUILD_PROXY_VAR,
                "must use http://: an https:// proxy cannot work, because the build trusts only the PVE certificate",
            ));
        }
        if scheme != "http" {
            return Err(invalid(IMAGE_BUILD_PROXY_VAR, "must start with http://"));
        }
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.contains('@') {
            return Err(invalid(
                IMAGE_BUILD_PROXY_VAR,
                "must not carry credentials (user:password@); a proxy that needs them is not supported",
            ));
        }
        if !authority.is_ascii()
            || authority.contains(['/', '?', '#', '\\', '%'])
            || authority
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(invalid(
                IMAGE_BUILD_PROXY_VAR,
                "must be a bare scheme://host[:port] of ASCII, with no path, query, fragment, or percent-encoding",
            ));
        }
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, tail) = bracketed
                .split_once(']')
                .ok_or_else(|| invalid(IMAGE_BUILD_PROXY_VAR, "has an unclosed IPv6 bracket"))?;
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(invalid(
                    IMAGE_BUILD_PROXY_VAR,
                    "has an invalid IPv6 address",
                ));
            }
            let port = match tail {
                "" => None,
                tail => Some(tail.strip_prefix(':').ok_or_else(|| {
                    invalid(IMAGE_BUILD_PROXY_VAR, "has text after the IPv6 address")
                })?),
            };
            (format!("[{host}]"), port)
        } else {
            let (host, port) = match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            };
            let host_ok = !host.is_empty()
                && host.starts_with(|c: char| c.is_ascii_alphanumeric())
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
            if !host_ok {
                return Err(invalid(IMAGE_BUILD_PROXY_VAR, "has an invalid host"));
            }
            (host.to_owned(), port)
        };
        let port = match port {
            Some(port) => Some(
                Some(port)
                    .filter(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|port| port.parse::<u16>().ok())
                    .filter(|port| *port != 0)
                    .ok_or_else(|| invalid(IMAGE_BUILD_PROXY_VAR, "has an invalid port"))?,
            ),
            None => None,
        };
        let url = match port {
            Some(port) => format!("{scheme}://{host}:{port}"),
            None => format!("{scheme}://{host}"),
        };
        let no_proxy = parse_no_proxy(no_proxy)?;
        Ok(Self { url, no_proxy })
    }

    /// The proxy URL, without credentials.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The `NO_PROXY` list, when one is set.
    #[must_use]
    pub fn no_proxy(&self) -> Option<&str> {
        self.no_proxy.as_deref()
    }
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
    lab_artifacts_dir: Option<String>,
    lab_artifact_retention_seconds: Option<u64>,
    lab_artifact_max_bytes: Option<u64>,
    lab_put_max_bytes: Option<u64>,
    image_build_proxy: Option<String>,
    image_build_no_proxy: Option<String>,
    image_build_address_pool: Option<String>,
    image_build_address_pool_range: Option<String>,
    image_build_address_pool_gateway: Option<String>,
    image_build_address_pool_dns: Option<String>,
    image_build_address_pool_refuse_iso: Option<bool>,
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
    /// A Lab artifact bound is not a whole, positive number.
    LabArtifactSettingInvalid {
        /// The setting's environment variable.
        setting: &'static str,
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
    /// An image-build proxy setting breaks a rule. Never carries the
    /// value: a proxy URL can hold credentials.
    ImageBuildProxyInvalid {
        /// The setting's environment variable.
        setting: &'static str,
        /// The rule it breaks.
        rule: &'static str,
    },
    /// A build address pool setting breaks a rule (#337). Names the rule,
    /// never the value.
    ImageBuildAddressPoolInvalid {
        /// The setting's environment variable.
        setting: &'static str,
        /// The rule it breaks.
        rule: &'static str,
    },
    /// A Lab placement setting is not a number in its accepted range.
    LabPlacementInvalid {
        /// The setting as its source names it: the environment variable, or
        /// the file key.
        setting: &'static str,
        /// The value that was refused.
        value: String,
        /// What the setting accepts.
        expected: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImageBuildProxyInvalid { setting, rule } => write!(
                f,
                "{setting} (or its config-file key) {rule}; the value is not shown"
            ),
            Self::ImageBuildAddressPoolInvalid { setting, rule } => write!(
                f,
                "{setting} (or its config-file key): {rule}; the value is not shown"
            ),
            Self::LabPlacementInvalid {
                setting,
                value,
                expected,
            } => write!(f, "{setting} must be {expected}; got {value:?}"),
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
            Self::LabArtifactSettingInvalid { setting, value } => write!(
                f,
                "{setting} (or its config-file key) must be a whole, positive number, not {value:?}"
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
#[allow(clippy::too_many_lines)]
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
    let mut lab_artifacts_dir: Option<String> = None;
    let mut lab_artifact_retention_seconds: Option<u64> = None;
    let mut lab_artifact_max_bytes: Option<u64> = None;
    let mut lab_put_max_bytes: Option<u64> = None;
    let mut image_build_proxy: Option<String> = None;
    let mut image_build_no_proxy: Option<String> = None;
    let mut address_pool = AddressPoolSettings::default();

    if let Some(path) = config_file {
        let raw = std::fs::read_to_string(path).map_err(|error| ConfigError::FileRead {
            path: path.to_path_buf(),
            error,
        })?;
        let file: ConfigFile = toml::from_str(&raw).map_err(|error| ConfigError::Parse {
            detail: parse_detail(&raw, &error),
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
        lab_artifacts_dir = file.lab_artifacts_dir;
        lab_artifact_retention_seconds = file.lab_artifact_retention_seconds;
        lab_artifact_max_bytes = file.lab_artifact_max_bytes;
        lab_put_max_bytes = file.lab_put_max_bytes;
        image_build_proxy = file.image_build_proxy;
        image_build_no_proxy = file.image_build_no_proxy;
        address_pool = AddressPoolSettings {
            cidr: file.image_build_address_pool,
            range: file.image_build_address_pool_range,
            gateway: file.image_build_address_pool_gateway,
            dns: file.image_build_address_pool_dns,
            refuse_iso: file.image_build_address_pool_refuse_iso,
        };
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
    let lab_placement = layer_lab_placement(lab_placement, env)?;

    lab_artifacts_dir = env(LAB_ARTIFACTS_DIR_VAR).or(lab_artifacts_dir);
    let lab_artifact_retention_seconds = positive_setting(
        LAB_ARTIFACT_RETENTION_VAR,
        lab_artifact_retention_seconds,
        env(LAB_ARTIFACT_RETENTION_VAR),
        DEFAULT_LAB_ARTIFACT_RETENTION_SECONDS,
    )?;
    let lab_artifact_max_bytes = positive_setting(
        LAB_ARTIFACT_MAX_BYTES_VAR,
        lab_artifact_max_bytes,
        env(LAB_ARTIFACT_MAX_BYTES_VAR),
        DEFAULT_LAB_ARTIFACT_MAX_BYTES,
    )?;
    let lab_put_max_bytes = positive_setting(
        LAB_PUT_MAX_BYTES_VAR,
        lab_put_max_bytes,
        env(LAB_PUT_MAX_BYTES_VAR),
        DEFAULT_LAB_PUT_MAX_BYTES,
    )?;

    let image_build_proxy = layer_image_build_proxy(image_build_proxy, image_build_no_proxy, env)?;
    let image_build_address_pool = layer_address_pool(address_pool, env)?;

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

    let data_dir = data_dir.map_or_else(|| PathBuf::from(DEFAULT_DATA_DIR), PathBuf::from);
    Ok(ControllerConfig {
        listen,
        tailscale_serve_listen,
        web_dist: web_dist.map_or_else(|| PathBuf::from(DEFAULT_WEB_DIST), PathBuf::from),
        lab_artifacts_dir: lab_artifacts_dir.map_or_else(
            || data_dir.join(DEFAULT_LAB_ARTIFACTS_SUBDIR),
            PathBuf::from,
        ),
        lab_artifact_retention_seconds,
        lab_artifact_max_bytes,
        lab_put_max_bytes,
        data_dir,
        master_key_file: master_key_file.map(PathBuf::from),
        lab_sweep_interval_seconds: lab_sweep_interval_seconds
            .unwrap_or(DEFAULT_LAB_SWEEP_INTERVAL_SECONDS),
        lab_placement,
        image_build_proxy,
        image_build_address_pool,
    })
}

/// The build address pool settings before layering.
#[derive(Default)]
struct AddressPoolSettings {
    cidr: Option<String>,
    range: Option<String>,
    gateway: Option<String>,
    dns: Option<String>,
    refuse_iso: Option<bool>,
}

/// Layers the build address pool environment over the file's keys (#337).
/// An empty environment value (a Compose `${VAR:-}` default) means unset and
/// does not override the file. The companion settings without the CIDR are
/// refused, so a typo cannot leave the pool silently off.
fn layer_address_pool(
    file: AddressPoolSettings,
    env: EnvLookup<'_>,
) -> Result<Option<fleet_core::BuildAddressPool>, ConfigError> {
    let set = |value: Option<String>| value.filter(|value| !value.trim().is_empty());
    let cidr = set(env(IMAGE_BUILD_ADDRESS_POOL_VAR)).or_else(|| set(file.cidr));
    let range = set(env(IMAGE_BUILD_ADDRESS_POOL_RANGE_VAR)).or_else(|| set(file.range));
    let gateway = set(env(IMAGE_BUILD_ADDRESS_POOL_GATEWAY_VAR)).or_else(|| set(file.gateway));
    let dns = set(env(IMAGE_BUILD_ADDRESS_POOL_DNS_VAR)).or_else(|| set(file.dns));
    let refuse_iso = match set(env(IMAGE_BUILD_ADDRESS_POOL_REFUSE_ISO_VAR)) {
        Some(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => {
                return Err(ConfigError::ImageBuildAddressPoolInvalid {
                    setting: IMAGE_BUILD_ADDRESS_POOL_REFUSE_ISO_VAR,
                    rule: "must be true or false",
                });
            }
        },
        None => file.refuse_iso,
    };
    let Some(cidr) = cidr else {
        let orphan = [
            (IMAGE_BUILD_ADDRESS_POOL_RANGE_VAR, range.is_some()),
            (IMAGE_BUILD_ADDRESS_POOL_GATEWAY_VAR, gateway.is_some()),
            (IMAGE_BUILD_ADDRESS_POOL_DNS_VAR, dns.is_some()),
            (
                IMAGE_BUILD_ADDRESS_POOL_REFUSE_ISO_VAR,
                refuse_iso == Some(true),
            ),
        ]
        .into_iter()
        .find_map(|(setting, present)| present.then_some(setting));
        return match orphan {
            Some(setting) => Err(ConfigError::ImageBuildAddressPoolInvalid {
                setting,
                rule: "is set but FLEET_IMAGE_BUILD_ADDRESS_POOL (the CIDR) is not",
            }),
            None => Ok(None),
        };
    };
    let range = range.ok_or(ConfigError::ImageBuildAddressPoolInvalid {
        setting: IMAGE_BUILD_ADDRESS_POOL_RANGE_VAR,
        rule: "is required with FLEET_IMAGE_BUILD_ADDRESS_POOL",
    })?;
    let gateway = gateway.ok_or(ConfigError::ImageBuildAddressPoolInvalid {
        setting: IMAGE_BUILD_ADDRESS_POOL_GATEWAY_VAR,
        rule: "is required with FLEET_IMAGE_BUILD_ADDRESS_POOL",
    })?;
    fleet_core::BuildAddressPool::parse(
        &cidr,
        &range,
        &gateway,
        dns.as_deref(),
        refuse_iso.unwrap_or(false),
    )
    .map(Some)
    .map_err(|error| ConfigError::ImageBuildAddressPoolInvalid {
        setting: match error.field {
            "range" => IMAGE_BUILD_ADDRESS_POOL_RANGE_VAR,
            "gateway" => IMAGE_BUILD_ADDRESS_POOL_GATEWAY_VAR,
            "dns" => IMAGE_BUILD_ADDRESS_POOL_DNS_VAR,
            _ => IMAGE_BUILD_ADDRESS_POOL_VAR,
        },
        rule: error.rule,
    })
}

/// Validates the direct-connection list; empty means none.
fn parse_no_proxy(list: Option<&str>) -> Result<Option<String>, ConfigError> {
    let Some(list) = list.map(str::trim).filter(|list| !list.is_empty()) else {
        return Ok(None);
    };
    let ok = list.len() <= MAX_IMAGE_BUILD_NO_PROXY_BYTES
        && list.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '-' | '_' | ',' | ':' | '*' | '/' | '[' | ']')
        });
    if ok {
        Ok(Some(list.to_owned()))
    } else {
        Err(ConfigError::ImageBuildProxyInvalid {
            setting: IMAGE_BUILD_NO_PROXY_VAR,
            rule: "must be a comma-separated host list of ASCII letters, digits, and . - _ : * / [ ] (at most 1024 bytes)",
        })
    }
}

/// The parser's complaint, unless the file holds an image-build proxy
/// setting: the parser quotes the offending line, and a proxy URL there
/// could carry credentials (an unquoted value, a misspelled key, and a
/// wrong type all quote it). Then only the line is named.
fn parse_detail(raw: &str, error: &toml::de::Error) -> String {
    if !raw.contains("image_build") {
        return error.to_string();
    }
    let line = error.span().map_or(0, |span| {
        raw[..span.start.min(raw.len())].matches('\n').count() + 1
    });
    format!(
        "TOML syntax or shape error at line {line} (details withheld: the file sets image_build_* settings, which may hold a proxy URL)"
    )
}

/// Layers the image-build proxy environment over the file's keys. An empty
/// value (a Compose `${VAR:-}` default) means off.
fn layer_image_build_proxy(
    file_proxy: Option<String>,
    file_no_proxy: Option<String>,
    env: EnvLookup<'_>,
) -> Result<Option<ImageBuildProxy>, ConfigError> {
    // An empty environment value is unset: it must not override the file.
    let set = |value: Option<String>| value.filter(|value| !value.trim().is_empty());
    let proxy = set(env(IMAGE_BUILD_PROXY_VAR)).or_else(|| set(file_proxy));
    let no_proxy = set(env(IMAGE_BUILD_NO_PROXY_VAR)).or_else(|| set(file_no_proxy));
    // Checked even when no proxy is set, so a typo fails at startup.
    parse_no_proxy(no_proxy.as_deref())?;
    match proxy {
        Some(url) => Ok(Some(ImageBuildProxy::parse(&url, no_proxy.as_deref())?)),
        None => Ok(None),
    }
}

/// Layers the `FLEET_LAB_*` environment over the file's Lab placement
/// settings and range-checks the result. Each failure names the setting as
/// its winning source spells it.
fn layer_lab_placement(
    mut lab_placement: LabPlacementConfig,
    env: EnvLookup<'_>,
) -> Result<LabPlacementConfig, ConfigError> {
    let ratio_expected =
        || format!("an overcommit ratio greater than 0 and at most {MAX_LAB_OVERCOMMIT}");
    let age_expected =
        || format!("a whole number of seconds in 1..={MAX_LAB_CAPACITY_AGE_SECONDS}");
    let invalid =
        |setting: &'static str, value: String, expected: String| ConfigError::LabPlacementInvalid {
            setting,
            value,
            expected,
        };
    let mut sources = [
        "lab_memory_overcommit",
        "lab_cpu_overcommit",
        "lab_capacity_max_age_seconds",
    ];
    for (index, var, is_ratio) in [
        (0, LAB_MEMORY_OVERCOMMIT_VAR, true),
        (1, LAB_CPU_OVERCOMMIT_VAR, true),
        (2, LAB_CAPACITY_MAX_AGE_VAR, false),
    ] {
        let Some(raw) = env(var) else { continue };
        sources[index] = var;
        if is_ratio {
            let ratio: f64 = raw
                .trim()
                .parse()
                .map_err(|_| invalid(var, raw.clone(), ratio_expected()))?;
            if index == 0 {
                lab_placement.memory_overcommit = ratio;
            } else {
                lab_placement.cpu_overcommit = ratio;
            }
        } else {
            lab_placement.capacity_max_age_seconds = raw
                .trim()
                .parse()
                .map_err(|_| invalid(var, raw.clone(), age_expected()))?;
        }
    }
    lab_placement.check(sources)?;
    Ok(lab_placement)
}

impl LabPlacementConfig {
    /// Range-checks the policy, naming each setting as `sources` spells it
    /// (memory ratio, CPU ratio, capacity age).
    fn check(&self, sources: [&'static str; 3]) -> Result<(), ConfigError> {
        let ratio_ok = |ratio: f64| ratio.is_finite() && ratio > 0.0 && ratio <= MAX_LAB_OVERCOMMIT;
        for (setting, ratio) in [
            (sources[0], self.memory_overcommit),
            (sources[1], self.cpu_overcommit),
        ] {
            if !ratio_ok(ratio) {
                return Err(ConfigError::LabPlacementInvalid {
                    setting,
                    value: ratio.to_string(),
                    expected: format!(
                        "an overcommit ratio greater than 0 and at most {MAX_LAB_OVERCOMMIT}"
                    ),
                });
            }
        }
        if !(1..=MAX_LAB_CAPACITY_AGE_SECONDS).contains(&self.capacity_max_age_seconds) {
            return Err(ConfigError::LabPlacementInvalid {
                setting: sources[2],
                value: self.capacity_max_age_seconds.to_string(),
                expected: format!(
                    "a whole number of seconds in 1..={MAX_LAB_CAPACITY_AGE_SECONDS}"
                ),
            });
        }
        Ok(())
    }
}

/// A whole, positive Lab artifact bound: the environment's raw value wins
/// over the file's, the default fills in, and zero is refused.
fn positive_setting(
    setting: &'static str,
    value: Option<u64>,
    raw: Option<String>,
    default: u64,
) -> Result<u64, ConfigError> {
    let value =
        match raw {
            Some(raw) => Some(raw.trim().parse::<u64>().map_err(|_| {
                ConfigError::LabArtifactSettingInvalid {
                    setting,
                    value: raw.clone(),
                }
            })?),
            None => value,
        };
    match value {
        Some(0) => Err(ConfigError::LabArtifactSettingInvalid {
            setting,
            value: "0".to_owned(),
        }),
        Some(value) => Ok(value),
        None => Ok(default),
    }
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

        for (setting, value) in [
            (
                LAB_ARTIFACT_RETENTION_VAR,
                self.lab_artifact_retention_seconds,
            ),
            (LAB_ARTIFACT_MAX_BYTES_VAR, self.lab_artifact_max_bytes),
            (LAB_PUT_MAX_BYTES_VAR, self.lab_put_max_bytes),
        ] {
            if value == 0 {
                return Err(ConfigError::LabArtifactSettingInvalid {
                    setting,
                    value: "0".to_owned(),
                });
            }
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
        // Layering already range-checks the policy; a config built or
        // changed in code is checked again before startup uses it.
        self.lab_placement.check([
            "lab_memory_overcommit",
            "lab_cpu_overcommit",
            "lab_capacity_max_age_seconds",
        ])?;
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
            format!("lab_artifacts_dir = {}", self.lab_artifacts_dir.display()),
            format!(
                "lab_artifact_retention_seconds = {}",
                self.lab_artifact_retention_seconds
            ),
            format!("lab_artifact_max_bytes = {}", self.lab_artifact_max_bytes),
            format!("lab_put_max_bytes = {}", self.lab_put_max_bytes),
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
        match &self.image_build_proxy {
            Some(proxy) => {
                lines.push(format!("image_build_proxy = {}", proxy.url()));
                if let Some(no_proxy) = proxy.no_proxy() {
                    lines.push(format!("image_build_no_proxy = {no_proxy}"));
                }
            }
            None => lines.push("image_build_proxy = <unset; builds connect directly>".to_owned()),
        }
        match &self.image_build_address_pool {
            Some(pool) => lines.push(format!(
                "image_build_address_pool = {} range {} gateway {}{}{}",
                pool.cidr(),
                pool.range(),
                pool.gateway(),
                if pool.dns().is_empty() {
                    String::new()
                } else {
                    format!(
                        " dns {}",
                        pool.dns()
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(" ")
                    )
                },
                if pool.refuses_iso() {
                    " (proxmox-iso builds refused)"
                } else {
                    ""
                },
            )),
            None => lines.push(
                "image_build_address_pool = <unset; build guests choose their own address>"
                    .to_owned(),
            ),
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
