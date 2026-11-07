//! Where `fleetctl` finds its controller (#614).
//!
//! The controller URL comes from the first of these that is set:
//!
//! 1. `--url <controller>` on the command line;
//! 2. the `FLEET_URL` environment variable;
//! 3. `url` in the user config file, `$XDG_CONFIG_HOME/fleet/config.toml`
//!    (falling back to `~/.config/fleet/config.toml`) on Unix and
//!    `%APPDATA%\fleet\config.toml` on Windows;
//! 4. [`DEFAULT_URL`](crate::DEFAULT_URL), the controller's loopback listener.
//!
//! Only the `url` key of the config file is read; other keys are ignored so
//! the file (and the `credentials.toml` planned beside it) can grow. Every
//! source is validated the same way: `http` or `https`, a host, no user
//! name or password, no query or fragment. An error names the source and
//! never echoes the value, which could carry a credential.
//!
//! Only `--url` is the explicit direct-controller override for `status`:
//! `FLEET_URL` and the config file are ambient per-login settings, so on a
//! node they would otherwise silently reroute `status` away from the local
//! fleetd socket.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::CliError;

/// The environment variable that names the controller.
pub const URL_ENV: &str = "FLEET_URL";

/// The config file's name inside the Fleet config directory.
pub const CONFIG_FILE: &str = "config.toml";

/// Which source supplied the controller URL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UrlSource {
    /// `--url` on the command line.
    Flag,
    /// The `FLEET_URL` environment variable.
    Env,
    /// `url` in the user config file at this path.
    Config(PathBuf),
    /// Nothing was set: [`DEFAULT_URL`](crate::DEFAULT_URL).
    Default,
}

impl UrlSource {
    /// The stable id reported in `system`'s `client.urlSource`.
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::Env => "env",
            Self::Config(_) => "config",
            Self::Default => "default",
        }
    }

    /// How an error message names the source.
    fn describe(&self) -> String {
        match self {
            Self::Flag => "--url".to_owned(),
            Self::Env => URL_ENV.to_owned(),
            Self::Config(path) => format!("`url` in {}", path.display()),
            Self::Default => "the default controller URL".to_owned(),
        }
    }
}

/// The ambient settings `fleetctl` reads when `--url` is absent, captured
/// once so tests can inject them instead of touching the process.
#[derive(Clone, Debug, Default)]
pub struct ClientEnvironment {
    /// `FLEET_URL`, when set.
    pub fleet_url: Option<String>,
    /// The config file to read, when a config directory could be resolved.
    pub config_file: Option<PathBuf>,
}

impl ClientEnvironment {
    /// No `FLEET_URL` and no config file: only `--url` or the default.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Reads `FLEET_URL` and resolves the config file from this process.
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            fleet_url: std::env::var(URL_ENV).ok(),
            config_file: config_file(|name| std::env::var_os(name), cfg!(windows)),
        }
    }
}

/// The config file path for a platform, from the given environment lookup.
///
/// Windows uses `%APPDATA%\fleet\config.toml`. Elsewhere,
/// `$XDG_CONFIG_HOME/fleet/config.toml` when that is an absolute path (the
/// XDG Base Directory specification ignores a relative one), otherwise
/// `$HOME/.config/fleet/config.toml`. `None` when no base is set.
#[must_use]
pub fn config_file(env: impl Fn(&str) -> Option<OsString>, windows: bool) -> Option<PathBuf> {
    let non_empty = |name: &str| env(name).filter(|value| !value.is_empty());
    let base = if windows {
        PathBuf::from(non_empty("APPDATA")?)
    } else if let Some(xdg) = non_empty("XDG_CONFIG_HOME").map(PathBuf::from)
        && xdg.is_absolute()
    {
        xdg
    } else {
        PathBuf::from(non_empty("HOME")?).join(".config")
    };
    Some(base.join("fleet").join(CONFIG_FILE))
}

/// Resolves the controller URL: `--url`, then `FLEET_URL`, then the config
/// file, then the default. A later source is not consulted once an earlier
/// one is set, so a broken config file does not affect `--url`.
///
/// # Errors
///
/// Fails when the chosen value is not a valid controller URL, or the config
/// file exists but cannot be read or parsed.
pub fn resolve(
    flag: Option<&str>,
    environment: &ClientEnvironment,
) -> Result<(String, UrlSource), CliError> {
    if let Some(value) = flag {
        return validated(value, UrlSource::Flag);
    }
    if let Some(value) = environment
        .fleet_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return validated(value, UrlSource::Env);
    }
    if let Some(path) = &environment.config_file
        && let Some(value) = read_config_url(path)?
    {
        return validated(&value, UrlSource::Config(path.clone()));
    }
    Ok((crate::DEFAULT_URL.to_owned(), UrlSource::Default))
}

/// The config file's `url`, or `None` when the file or the key is absent.
fn read_config_url(path: &Path) -> Result<Option<String>, CliError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CliError {
                message: format!("cannot read the config file {}: {error}", path.display()),
            });
        }
    };
    // The parse error's own text quotes the offending line, which could hold
    // a credential in a future key, so only its position is reported.
    let table: toml::Table = text.parse().map_err(|error: toml::de::Error| CliError {
        message: format!(
            "the config file {} is not valid TOML{}",
            path.display(),
            error
                .span()
                .map(|span| format!(" (at byte {})", span.start))
                .unwrap_or_default()
        ),
    })?;
    match table.get("url") {
        None => Ok(None),
        Some(toml::Value::String(url)) => Ok(Some(url.clone())),
        Some(_) => Err(CliError {
            message: format!(
                "`url` in the config file {} must be a string",
                path.display()
            ),
        }),
    }
}

/// Checks one value and returns it without a trailing `/`.
fn validated(value: &str, source: UrlSource) -> Result<(String, UrlSource), CliError> {
    let fail = |reason: &str| CliError {
        message: format!(
            "{} is not a valid controller URL: {reason}",
            source.describe()
        ),
    };
    let trimmed = value.trim().trim_end_matches('/');
    let parsed = reqwest::Url::parse(trimmed).map_err(|error| fail(&error.to_string()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(fail("the scheme must be http or https"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(fail(
            "it must not carry a user name or password; set FLEET_TOKEN for a credential",
        ));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(fail("it has no host"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(fail("it must not have a query or fragment"));
    }
    Ok((trimmed.to_owned(), source))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(fleet_url: Option<&str>, config_file: Option<PathBuf>) -> ClientEnvironment {
        ClientEnvironment {
            fleet_url: fleet_url.map(str::to_owned),
            config_file,
        }
    }

    fn write_config(dir: &Path, text: &str) -> PathBuf {
        let path = dir.join("fleet").join(CONFIG_FILE);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn precedence_is_flag_then_env_then_config_then_default() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_config(dir.path(), "url = \"https://config.example:8443/\"\n");

        let all = env(Some("http://env.example:8080"), Some(config.clone()));
        assert_eq!(
            resolve(Some("http://flag.example:1/"), &all).unwrap(),
            ("http://flag.example:1".to_owned(), UrlSource::Flag)
        );
        assert_eq!(
            resolve(None, &all).unwrap(),
            ("http://env.example:8080".to_owned(), UrlSource::Env)
        );
        let config_only = env(None, Some(config.clone()));
        assert_eq!(
            resolve(None, &config_only).unwrap(),
            (
                "https://config.example:8443".to_owned(),
                UrlSource::Config(config)
            )
        );
        assert_eq!(
            resolve(None, &ClientEnvironment::none()).unwrap(),
            (crate::DEFAULT_URL.to_owned(), UrlSource::Default)
        );
        // An empty FLEET_URL counts as unset.
        let empty = env(Some("  "), None);
        assert_eq!(resolve(None, &empty).unwrap().1, UrlSource::Default);
    }

    #[test]
    fn a_missing_config_file_or_key_falls_back_to_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let missing = env(None, Some(dir.path().join("fleet").join(CONFIG_FILE)));
        assert_eq!(resolve(None, &missing).unwrap().1, UrlSource::Default);

        let other_keys = write_config(dir.path(), "[future]\ntoken_ref = \"x\"\nother = 1\n");
        assert_eq!(
            resolve(None, &env(None, Some(other_keys))).unwrap().1,
            UrlSource::Default
        );
    }

    #[test]
    fn a_malformed_config_file_fails_naming_the_file_without_its_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "url = \"http://a:1\"\nsecret = hunter2 nope\n");
        let error = resolve(None, &env(None, Some(path.clone()))).unwrap_err();
        assert!(
            error.message.contains(&path.display().to_string()),
            "{error}"
        );
        assert!(error.message.contains("not valid TOML"), "{error}");
        assert!(!error.message.contains("hunter2"), "{error}");

        let path = write_config(dir.path(), "url = 8080\n");
        let error = resolve(None, &env(None, Some(path))).unwrap_err();
        assert!(error.message.contains("must be a string"), "{error}");

        // --url and FLEET_URL never read the file, so a broken one is moot.
        let path = write_config(dir.path(), "not toml at all [");
        let broken = env(None, Some(path.clone()));
        assert!(resolve(Some("http://flag:1"), &broken).is_ok());
        assert!(resolve(None, &env(Some("http://env:1"), Some(path))).is_ok());
    }

    #[test]
    fn a_bad_url_names_its_source_and_never_echoes_a_credential() {
        let dir = tempfile::tempdir().unwrap();
        let bad = [
            ("ftp://host:21", "http or https"),
            ("http://user:s3cret@host:8080", "user name or password"),
            ("https://token@host", "user name or password"),
            ("http://host:8080/?x=1", "query or fragment"),
            ("http://host:8080/#frag", "query or fragment"),
            ("not a url", "not a valid controller URL"),
        ];
        for (value, reason) in bad {
            let error = resolve(Some(value), &ClientEnvironment::none()).unwrap_err();
            assert!(error.message.starts_with("--url "), "{error}");
            assert!(error.message.contains(reason), "{value}: {error}");
            assert!(!error.message.contains("s3cret"), "{error}");

            let error = resolve(None, &env(Some(value), None)).unwrap_err();
            assert!(error.message.starts_with("FLEET_URL "), "{error}");
            assert!(error.message.contains(reason), "{value}: {error}");
            assert!(!error.message.contains("s3cret"), "{error}");

            let path = write_config(dir.path(), &format!("url = {value:?}\n"));
            let error = resolve(None, &env(None, Some(path.clone()))).unwrap_err();
            assert!(
                error
                    .message
                    .starts_with(&format!("`url` in {}", path.display())),
                "{error}"
            );
            assert!(error.message.contains(reason), "{value}: {error}");
            assert!(!error.message.contains("s3cret"), "{error}");
        }
    }

    #[test]
    fn the_config_path_follows_each_platform_convention() {
        let lookup = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| OsString::from(value))
            }
        };
        let appdata = r"C:\Users\dev\AppData\Roaming";
        assert_eq!(
            config_file(
                lookup(&[
                    ("APPDATA", r"C:\Users\dev\AppData\Roaming"),
                    ("XDG_CONFIG_HOME", "/ignored"),
                    ("HOME", "/ignored"),
                ]),
                true
            ),
            Some(PathBuf::from(appdata).join("fleet").join("config.toml"))
        );
        assert_eq!(config_file(lookup(&[("HOME", "/home/dev")]), true), None);
        assert_eq!(
            config_file(
                lookup(&[("XDG_CONFIG_HOME", "/xdg"), ("HOME", "/home/dev")]),
                false
            ),
            Some(PathBuf::from("/xdg/fleet/config.toml"))
        );
        // A relative or empty XDG_CONFIG_HOME is ignored, as the spec says.
        for xdg in ["relative/dir", ""] {
            let pairs: &'static [(&'static str, &'static str)] = if xdg.is_empty() {
                &[("XDG_CONFIG_HOME", ""), ("HOME", "/home/dev")]
            } else {
                &[("XDG_CONFIG_HOME", "relative/dir"), ("HOME", "/home/dev")]
            };
            assert_eq!(
                config_file(lookup(pairs), false),
                Some(PathBuf::from("/home/dev/.config/fleet/config.toml"))
            );
        }
        assert_eq!(config_file(lookup(&[]), false), None);
    }
}
