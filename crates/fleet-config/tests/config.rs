//! Exercises the configuration contract: layering precedence, fail-closed
//! validation, and the redaction property of every diagnostic surface. All
//! environment lookups are injected, so the tests never touch the process
//! environment of the runner.

use std::collections::HashMap;
use std::path::Path;

use fleet_config::{CONFIG_VERSION, ConfigError, ControllerConfig};

type Env = HashMap<String, String>;

fn env_of(entries: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: Env = entries
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |key| map.get(key).cloned()
}

fn none_env(_key: &str) -> Option<String> {
    None
}

fn write_config(dir: &Path, text: &str) -> std::path::PathBuf {
    let path = dir.join("fleet.toml");
    std::fs::write(&path, text).expect("config fixture must write");
    path
}

const VALID_FILE: &str = "\
version = 1
listen = \"127.0.0.1:9090\"
web_dist = \"./dist\"
data_dir = \"./state\"
";

// Precedence -----------------------------------------------------------------

#[test]
fn defaults_are_safe_without_any_source() {
    let config = fleet_config::load(None, &none_env).expect("defaults must load");
    assert_eq!(config.listen, "127.0.0.1:8080".parse().unwrap());
    assert!(config.master_key_file.is_none());
    assert_eq!(config.web_dist, Path::new("./web"));
    assert_eq!(config.data_dir, Path::new("./data"));
}

#[test]
fn the_config_file_overrides_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let file = write_config(dir.path(), VALID_FILE);
    let config = fleet_config::load(Some(&file), &none_env).expect("valid file must load");
    assert_eq!(config.listen, "127.0.0.1:9090".parse().unwrap());
    assert_eq!(config.web_dist, Path::new("./dist"));
    assert_eq!(config.data_dir, Path::new("./state"));
}

#[test]
fn the_environment_overrides_the_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = write_config(dir.path(), VALID_FILE);
    let config = fleet_config::load(
        Some(&file),
        &env_of(&[(fleet_config::LISTEN_VAR, "127.0.0.1:7070")]),
    )
    .expect("layered load must succeed");
    assert_eq!(config.listen, "127.0.0.1:7070".parse().unwrap());
    // Un-overridden file values survive.
    assert_eq!(config.web_dist, Path::new("./dist"));
}

#[test]
fn every_setting_can_be_overridden_from_the_environment() {
    let env = env_of(&[
        (fleet_config::LISTEN_VAR, "127.0.0.1:6060"),
        (fleet_config::WEB_DIST_VAR, "/opt/web"),
        (fleet_config::DATA_DIR_VAR, "/var/lib/fleet"),
        (fleet_config::MASTER_KEY_FILE_VAR, "/run/secrets/master_key"),
    ]);
    let config = fleet_config::load(None, &env).expect("layered load must succeed");
    assert_eq!(config.listen, "127.0.0.1:6060".parse().unwrap());
    assert_eq!(config.web_dist, Path::new("/opt/web"));
    assert_eq!(config.data_dir, Path::new("/var/lib/fleet"));
    assert_eq!(
        config.master_key_file.as_deref(),
        Some(Path::new("/run/secrets/master_key"))
    );
}

// File format ----------------------------------------------------------------

#[test]
fn a_foreign_version_is_rejected_not_guessed_at() {
    let dir = tempfile::tempdir().unwrap();
    let file = write_config(
        dir.path(),
        &VALID_FILE.replace("version = 1", "version = 2"),
    );
    let error = fleet_config::load(Some(&file), &none_env).unwrap_err();
    assert!(matches!(
        error,
        ConfigError::Version {
            found: Some(2),
            expected: CONFIG_VERSION
        }
    ));
    assert!(error.to_string().contains("version 2"));
}

#[test]
fn a_missing_version_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let file = write_config(dir.path(), "listen = \"127.0.0.1:9090\"\n");
    let error = fleet_config::load(Some(&file), &none_env).unwrap_err();
    assert!(matches!(
        error,
        ConfigError::Version {
            found: None,
            expected: 1
        }
    ));
}

#[test]
fn unknown_file_fields_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let file = write_config(dir.path(), &format!("{VALID_FILE}surprise = true\n"));
    let error = fleet_config::load(Some(&file), &none_env).unwrap_err();
    assert!(matches!(error, ConfigError::Parse { .. }));
}

#[test]
fn an_unreadable_file_is_a_config_error() {
    let error =
        fleet_config::load(Some(Path::new("/nonexistent/fleet.toml")), &none_env).unwrap_err();
    assert!(matches!(error, ConfigError::FileRead { .. }));
}

// Fail-closed validation -----------------------------------------------------

#[test]
fn an_invalid_listen_value_fails() {
    let error = fleet_config::load(
        None,
        &env_of(&[(fleet_config::LISTEN_VAR, "not-an-address")]),
    )
    .unwrap_err();
    assert!(matches!(error, ConfigError::ListenInvalid { .. }));
    assert!(error.to_string().contains("not-an-address"));
}

#[test]
fn tailscale_listener_requires_both_loopback_and_distinct_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let config = fleet_config::load(
        None,
        &env_of(&[
            (fleet_config::LISTEN_VAR, "0.0.0.0:8080"),
            (fleet_config::TAILSCALE_SERVE_LISTEN_VAR, "127.0.0.1:8081"),
            (fleet_config::DATA_DIR_VAR, dir.path().to_str().unwrap()),
        ]),
    )
    .unwrap();
    let error = config.validate().unwrap_err();
    assert!(matches!(
        error,
        ConfigError::IdentityModeRequiresLoopbackListener { .. }
    ));

    let config = fleet_config::load(
        None,
        &env_of(&[
            (fleet_config::LISTEN_VAR, "127.0.0.1:8080"),
            (fleet_config::TAILSCALE_SERVE_LISTEN_VAR, "127.0.0.1:8080"),
            (fleet_config::DATA_DIR_VAR, dir.path().to_str().unwrap()),
        ]),
    )
    .unwrap();
    let error = config.validate().unwrap_err();
    assert!(matches!(
        error,
        ConfigError::ControllerListenersConflict { .. }
    ));
}

#[test]
fn validation_creates_the_state_directory() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("nested").join("state");
    let config = ControllerConfig {
        listen: "127.0.0.1:8080".parse().unwrap(),
        web_dist: dir.path().to_path_buf(),
        data_dir: state.clone(),
        master_key_file: None,
        tailscale_serve_listen: None,
    };
    config
        .validate()
        .expect("creating a nested state directory must succeed");
    assert!(state.is_dir());
}

#[test]
fn an_uncreatable_state_directory_fails_validation() {
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"x").unwrap();
    let config = ControllerConfig {
        listen: "127.0.0.1:8080".parse().unwrap(),
        web_dist: dir.path().to_path_buf(),
        data_dir: blocker.join("state"),
        master_key_file: None,
        tailscale_serve_listen: None,
    };
    let error = config.validate().unwrap_err();
    assert!(matches!(error, ConfigError::DataDirUnavailable { .. }));
}

#[test]
fn a_missing_master_key_file_fails_validation() {
    let dir = tempfile::tempdir().unwrap();
    let config = ControllerConfig {
        listen: "127.0.0.1:8080".parse().unwrap(),
        web_dist: dir.path().to_path_buf(),
        data_dir: dir.path().join("state"),
        master_key_file: Some(dir.path().join("absent_key")),
        tailscale_serve_listen: None,
    };
    let error = config.validate().unwrap_err();
    assert!(matches!(error, ConfigError::MasterKeyMissing { .. }));
}

#[test]
fn a_directory_as_master_key_path_is_not_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let config = ControllerConfig {
        listen: "127.0.0.1:8080".parse().unwrap(),
        web_dist: dir.path().to_path_buf(),
        data_dir: dir.path().join("state"),
        master_key_file: Some(dir.path().to_path_buf()),
        tailscale_serve_listen: None,
    };
    let error = config.validate().unwrap_err();
    assert!(matches!(error, ConfigError::MasterKeyNotAFile { .. }));
}

#[cfg(unix)]
#[test]
fn a_group_or_world_readable_master_key_file_is_unsafe() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("master_key");
    std::fs::write(&key, b"not-a-real-key").unwrap();
    for mode in [0o644, 0o640, 0o666] {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        let config = ControllerConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            web_dist: dir.path().to_path_buf(),
            data_dir: dir.path().join("state"),
            master_key_file: Some(key.clone()),
            tailscale_serve_listen: None,
        };
        let error = config.validate().unwrap_err();
        match error {
            ConfigError::MasterKeyPermissions { mode: found, .. } => {
                assert_eq!(found, mode);
            }
            other => panic!("expected MasterKeyPermissions for mode {mode:04o}, got {other:?}"),
        }
        assert!(error.to_string().contains("0600"));
    }

    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = ControllerConfig {
        listen: "127.0.0.1:8080".parse().unwrap(),
        web_dist: dir.path().to_path_buf(),
        data_dir: dir.path().join("state"),
        master_key_file: Some(key),
        tailscale_serve_listen: None,
    };
    config
        .validate()
        .expect("an owner-only key file must validate");
}

// Redaction ------------------------------------------------------------------

#[test]
fn no_diagnostic_surface_contains_secret_material() {
    // The content must never appear in any rendering of the configuration.
    const SECRET_MATERIAL: &str = "top-secret-master-key-bytes-0123456789";
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("master_key");
    std::fs::write(&key, SECRET_MATERIAL).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let config = ControllerConfig {
        listen: "127.0.0.1:8080".parse().unwrap(),
        web_dist: dir.path().to_path_buf(),
        data_dir: dir.path().join("state"),
        master_key_file: Some(key.clone()),
        tailscale_serve_listen: None,
    };
    config
        .validate()
        .expect("the fixture key file must validate");

    let renderings = [
        format!("{config:?}"),
        config.summary(),
        match config.validate() {
            Ok(()) => String::new(),
            Err(error) => error.to_string(),
        },
    ];
    for rendering in renderings {
        assert!(
            !rendering.contains(SECRET_MATERIAL),
            "secret material leaked into a diagnostic: {rendering}"
        );
    }
    let summary = config.summary();
    assert!(
        summary.contains(key.to_str().unwrap()),
        "the summary shows the reference"
    );
}
