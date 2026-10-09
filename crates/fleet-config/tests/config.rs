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

#[test]
fn lab_placement_defaults_layer_from_file_then_environment() {
    let defaults = fleet_config::load(None, &none_env).unwrap();
    assert_eq!(
        defaults.lab_placement,
        fleet_config::LabPlacementConfig {
            memory_overcommit: 1.0,
            cpu_overcommit: 1.0,
            capacity_max_age_seconds: 300,
        }
    );
    let dir = tempfile::tempdir().unwrap();
    let file = write_config(
        dir.path(),
        &format!(
            "{VALID_FILE}lab_memory_overcommit = 1.25\nlab_cpu_overcommit = 4.0\nlab_capacity_max_age_seconds = 60\n"
        ),
    );
    let config = fleet_config::load(
        Some(&file),
        &env_of(&[(fleet_config::LAB_CPU_OVERCOMMIT_VAR, "2")]),
    )
    .unwrap();
    assert!((config.lab_placement.memory_overcommit - 1.25).abs() < f64::EPSILON);
    assert!((config.lab_placement.cpu_overcommit - 2.0).abs() < f64::EPSILON);
    assert_eq!(config.lab_placement.capacity_max_age_seconds, 60);
    assert!(config.summary().contains("lab_cpu_overcommit = 2"));
}

#[test]
fn out_of_range_lab_placement_settings_are_refused() {
    for (var, value) in [
        (fleet_config::LAB_MEMORY_OVERCOMMIT_VAR, "0"),
        (fleet_config::LAB_MEMORY_OVERCOMMIT_VAR, "NaN"),
        (fleet_config::LAB_CPU_OVERCOMMIT_VAR, "17"),
        (fleet_config::LAB_CPU_OVERCOMMIT_VAR, "lots"),
        (fleet_config::LAB_CAPACITY_MAX_AGE_VAR, "0"),
        (fleet_config::LAB_CAPACITY_MAX_AGE_VAR, "-5"),
    ] {
        let error = fleet_config::load(None, &env_of(&[(var, value)])).unwrap_err();
        assert!(
            matches!(error, ConfigError::LabPlacementInvalid { setting, .. } if setting == var),
            "{var}={value}: {error:?}"
        );
        // The guidance is the setting's own constraint, never the other's.
        let message = error.to_string();
        if var == fleet_config::LAB_CAPACITY_MAX_AGE_VAR {
            assert!(
                message.contains("seconds") && !message.contains("ratio"),
                "{message}"
            );
        } else {
            assert!(
                message.contains("ratio") && !message.contains("seconds"),
                "{message}"
            );
        }
    }
}

#[test]
fn validate_refuses_an_out_of_range_placement_policy_set_in_code() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = fleet_config::load(None, &none_env).expect("defaults must load");
    config.data_dir = dir.path().to_path_buf();
    config.validate().expect("the default policy must validate");
    config.lab_placement.memory_overcommit = 32.0;
    assert!(matches!(
        config.validate().unwrap_err(),
        ConfigError::LabPlacementInvalid {
            setting: "lab_memory_overcommit",
            ..
        }
    ));
    config.lab_placement.memory_overcommit = 1.0;
    config.lab_placement.capacity_max_age_seconds = 0;
    assert!(matches!(
        config.validate().unwrap_err(),
        ConfigError::LabPlacementInvalid {
            setting: "lab_capacity_max_age_seconds",
            ..
        }
    ));
}

#[test]
fn a_file_sourced_lab_setting_is_named_by_its_file_key() {
    let dir = tempfile::tempdir().unwrap();
    let file = write_config(
        dir.path(),
        &format!("{VALID_FILE}lab_cpu_overcommit = 20.0\n"),
    );
    let error = fleet_config::load(Some(&file), &none_env).unwrap_err();
    assert!(
        matches!(
            error,
            ConfigError::LabPlacementInvalid {
                setting: "lab_cpu_overcommit",
                ..
            }
        ),
        "{error:?}"
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
fn tailscale_listener_requires_a_fixed_ipv4_loopback_port() {
    let dir = tempfile::tempdir().unwrap();
    let config = fleet_config::load(
        None,
        &env_of(&[
            (fleet_config::LISTEN_VAR, "127.0.0.1:8080"),
            (fleet_config::TAILSCALE_SERVE_LISTEN_VAR, "0.0.0.0:8081"),
            (fleet_config::DATA_DIR_VAR, dir.path().to_str().unwrap()),
        ]),
    )
    .unwrap();
    assert!(matches!(
        config.validate(),
        Err(ConfigError::TailscaleServeListenerNotLoopback { .. })
    ));

    let config = fleet_config::load(
        None,
        &env_of(&[
            (fleet_config::LISTEN_VAR, "127.0.0.1:8080"),
            (fleet_config::TAILSCALE_SERVE_LISTEN_VAR, "127.0.0.1:0"),
            (fleet_config::DATA_DIR_VAR, dir.path().to_str().unwrap()),
        ]),
    )
    .unwrap();
    assert!(matches!(
        config.validate(),
        Err(ConfigError::TailscaleServeListenerPortZero)
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
        lab_sweep_interval_seconds: 60,
        lab_artifacts_dir: dir.path().join("lab-artifacts"),
        lab_artifact_retention_seconds: fleet_config::DEFAULT_LAB_ARTIFACT_RETENTION_SECONDS,
        lab_artifact_max_bytes: fleet_config::DEFAULT_LAB_ARTIFACT_MAX_BYTES,
        lab_put_max_bytes: fleet_config::DEFAULT_LAB_PUT_MAX_BYTES,
        tailscale_serve_listen: None,
        lab_placement: fleet_config::LabPlacementConfig::default(),
        image_build_proxy: None,
        image_build_address_pool: None,
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
        lab_sweep_interval_seconds: 60,
        lab_artifacts_dir: dir.path().join("lab-artifacts"),
        lab_artifact_retention_seconds: fleet_config::DEFAULT_LAB_ARTIFACT_RETENTION_SECONDS,
        lab_artifact_max_bytes: fleet_config::DEFAULT_LAB_ARTIFACT_MAX_BYTES,
        lab_put_max_bytes: fleet_config::DEFAULT_LAB_PUT_MAX_BYTES,
        tailscale_serve_listen: None,
        lab_placement: fleet_config::LabPlacementConfig::default(),
        image_build_proxy: None,
        image_build_address_pool: None,
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
        lab_sweep_interval_seconds: 60,
        lab_artifacts_dir: dir.path().join("lab-artifacts"),
        lab_artifact_retention_seconds: fleet_config::DEFAULT_LAB_ARTIFACT_RETENTION_SECONDS,
        lab_artifact_max_bytes: fleet_config::DEFAULT_LAB_ARTIFACT_MAX_BYTES,
        lab_put_max_bytes: fleet_config::DEFAULT_LAB_PUT_MAX_BYTES,
        tailscale_serve_listen: None,
        lab_placement: fleet_config::LabPlacementConfig::default(),
        image_build_proxy: None,
        image_build_address_pool: None,
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
        lab_sweep_interval_seconds: 60,
        lab_artifacts_dir: dir.path().join("lab-artifacts"),
        lab_artifact_retention_seconds: fleet_config::DEFAULT_LAB_ARTIFACT_RETENTION_SECONDS,
        lab_artifact_max_bytes: fleet_config::DEFAULT_LAB_ARTIFACT_MAX_BYTES,
        lab_put_max_bytes: fleet_config::DEFAULT_LAB_PUT_MAX_BYTES,
        tailscale_serve_listen: None,
        lab_placement: fleet_config::LabPlacementConfig::default(),
        image_build_proxy: None,
        image_build_address_pool: None,
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
            lab_sweep_interval_seconds: 60,
            lab_artifacts_dir: dir.path().join("lab-artifacts"),
            lab_artifact_retention_seconds: fleet_config::DEFAULT_LAB_ARTIFACT_RETENTION_SECONDS,
            lab_artifact_max_bytes: fleet_config::DEFAULT_LAB_ARTIFACT_MAX_BYTES,
            lab_put_max_bytes: fleet_config::DEFAULT_LAB_PUT_MAX_BYTES,
            tailscale_serve_listen: None,
            lab_placement: fleet_config::LabPlacementConfig::default(),
            image_build_proxy: None,
            image_build_address_pool: None,
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
        lab_sweep_interval_seconds: 60,
        lab_artifacts_dir: dir.path().join("lab-artifacts"),
        lab_artifact_retention_seconds: fleet_config::DEFAULT_LAB_ARTIFACT_RETENTION_SECONDS,
        lab_artifact_max_bytes: fleet_config::DEFAULT_LAB_ARTIFACT_MAX_BYTES,
        lab_put_max_bytes: fleet_config::DEFAULT_LAB_PUT_MAX_BYTES,
        tailscale_serve_listen: None,
        lab_placement: fleet_config::LabPlacementConfig::default(),
        image_build_proxy: None,
        image_build_address_pool: None,
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
        lab_sweep_interval_seconds: 60,
        lab_artifacts_dir: dir.path().join("lab-artifacts"),
        lab_artifact_retention_seconds: fleet_config::DEFAULT_LAB_ARTIFACT_RETENTION_SECONDS,
        lab_artifact_max_bytes: fleet_config::DEFAULT_LAB_ARTIFACT_MAX_BYTES,
        lab_put_max_bytes: fleet_config::DEFAULT_LAB_PUT_MAX_BYTES,
        tailscale_serve_listen: None,
        lab_placement: fleet_config::LabPlacementConfig::default(),
        image_build_proxy: None,
        image_build_address_pool: None,
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

#[test]
fn the_lab_sweep_interval_defaults_and_layers() {
    let config = fleet_config::load(None, &|_| None).unwrap();
    assert_eq!(
        config.lab_sweep_interval_seconds,
        fleet_config::DEFAULT_LAB_SWEEP_INTERVAL_SECONDS
    );
    let disabled = fleet_config::load(None, &|key| {
        (key == fleet_config::LAB_SWEEP_INTERVAL_VAR).then(|| "0".to_owned())
    })
    .unwrap();
    assert_eq!(disabled.lab_sweep_interval_seconds, 0);
    assert!(
        disabled
            .summary()
            .contains("lab_sweep_interval_seconds = 0 (disabled)")
    );
    let invalid = fleet_config::load(None, &|key| {
        (key == fleet_config::LAB_SWEEP_INTERVAL_VAR).then(|| "soon".to_owned())
    });
    assert!(matches!(
        invalid,
        Err(fleet_config::ConfigError::LabSweepIntervalInvalid { .. })
    ));

    // The file layer applies, and the environment overrides it.
    let dir = tempfile::tempdir().unwrap();
    let file = write_config(
        dir.path(),
        &format!("{VALID_FILE}lab_sweep_interval_seconds = 300\n"),
    );
    let from_file = fleet_config::load(Some(&file), &none_env).unwrap();
    assert_eq!(from_file.lab_sweep_interval_seconds, 300);
    let overridden = fleet_config::load(
        Some(&file),
        &env_of(&[(fleet_config::LAB_SWEEP_INTERVAL_VAR, "15")]),
    )
    .unwrap();
    assert_eq!(overridden.lab_sweep_interval_seconds, 15);
}

#[test]
fn the_lab_artifact_settings_default_layer_and_refuse_zero() {
    let config = fleet_config::load(None, &|_| None).unwrap();
    assert_eq!(
        config.lab_artifacts_dir,
        config
            .data_dir
            .join(fleet_config::DEFAULT_LAB_ARTIFACTS_SUBDIR)
    );
    assert_eq!(
        config.lab_artifact_retention_seconds,
        fleet_config::DEFAULT_LAB_ARTIFACT_RETENTION_SECONDS
    );
    assert_eq!(
        config.lab_artifact_max_bytes,
        fleet_config::DEFAULT_LAB_ARTIFACT_MAX_BYTES
    );
    assert!(config.summary().contains(&format!(
        "lab_artifact_max_bytes = {}",
        fleet_config::DEFAULT_LAB_ARTIFACT_MAX_BYTES
    )));

    let dir = tempfile::tempdir().unwrap();
    let file = write_config(
        dir.path(),
        &format!(
            "{VALID_FILE}lab_artifacts_dir = \"/srv/fleet-artifacts\"\nlab_artifact_retention_seconds = 3600\nlab_artifact_max_bytes = 1024\n"
        ),
    );
    let from_file = fleet_config::load(Some(&file), &none_env).unwrap();
    assert_eq!(
        from_file.lab_artifacts_dir,
        std::path::PathBuf::from("/srv/fleet-artifacts")
    );
    assert_eq!(from_file.lab_artifact_retention_seconds, 3600);
    assert_eq!(from_file.lab_artifact_max_bytes, 1024);
    let overridden = fleet_config::load(
        Some(&file),
        &env_of(&[
            (
                fleet_config::LAB_ARTIFACTS_DIR_VAR,
                "/var/lib/fleet/artifacts",
            ),
            (fleet_config::LAB_ARTIFACT_RETENTION_VAR, "60"),
            (fleet_config::LAB_ARTIFACT_MAX_BYTES_VAR, "2048"),
        ]),
    )
    .unwrap();
    assert_eq!(
        overridden.lab_artifacts_dir,
        std::path::PathBuf::from("/var/lib/fleet/artifacts")
    );
    assert_eq!(overridden.lab_artifact_retention_seconds, 60);
    assert_eq!(overridden.lab_artifact_max_bytes, 2048);

    // The `lab put` cap defaults to 2 GiB and layers like the others.
    assert_eq!(config.lab_put_max_bytes, 2 * 1024 * 1024 * 1024);
    let put_file = write_config(
        dir.path(),
        &format!("{VALID_FILE}lab_put_max_bytes = 4096\n"),
    );
    assert_eq!(
        fleet_config::load(Some(&put_file), &none_env)
            .unwrap()
            .lab_put_max_bytes,
        4096
    );
    let put_env = fleet_config::load(
        Some(&put_file),
        &env_of(&[(fleet_config::LAB_PUT_MAX_BYTES_VAR, "8192")]),
    )
    .unwrap();
    assert_eq!(put_env.lab_put_max_bytes, 8192);

    // The file layer refuses zero too.
    for key in [
        "lab_artifact_retention_seconds",
        "lab_artifact_max_bytes",
        "lab_put_max_bytes",
    ] {
        let zero = write_config(dir.path(), &format!("{VALID_FILE}{key} = 0\n"));
        assert!(
            matches!(
                fleet_config::load(Some(&zero), &none_env),
                Err(fleet_config::ConfigError::LabArtifactSettingInvalid { .. })
            ),
            "{key} = 0 was accepted"
        );
    }

    for (var, value) in [
        (fleet_config::LAB_ARTIFACT_RETENTION_VAR, "0"),
        (fleet_config::LAB_ARTIFACT_MAX_BYTES_VAR, "0"),
        (fleet_config::LAB_ARTIFACT_MAX_BYTES_VAR, "lots"),
    ] {
        assert!(
            matches!(
                fleet_config::load(None, &env_of(&[(var, value)])),
                Err(fleet_config::ConfigError::LabArtifactSettingInvalid { .. })
            ),
            "{var}={value} was accepted"
        );
    }
}

#[test]
fn validation_refuses_zero_lab_artifact_bounds() {
    let dir = tempfile::tempdir().unwrap();
    for (retention, max_bytes) in [(0, 1), (1, 0)] {
        let config = ControllerConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            web_dist: dir.path().to_path_buf(),
            data_dir: dir.path().join("state"),
            master_key_file: None,
            lab_sweep_interval_seconds: 60,
            lab_artifacts_dir: dir.path().join("lab-artifacts"),
            lab_artifact_retention_seconds: retention,
            lab_artifact_max_bytes: max_bytes,
            lab_put_max_bytes: fleet_config::DEFAULT_LAB_PUT_MAX_BYTES,
            tailscale_serve_listen: None,
            lab_placement: fleet_config::LabPlacementConfig::default(),
            image_build_proxy: None,
            image_build_address_pool: None,
        };
        assert!(matches!(
            config.validate(),
            Err(fleet_config::ConfigError::LabArtifactSettingInvalid { .. })
        ));
    }
}

// Image-build proxy (#339) ---------------------------------------------------

#[test]
fn the_image_build_proxy_is_off_by_default_and_for_an_empty_value() {
    assert_eq!(
        fleet_config::load(None, &none_env)
            .unwrap()
            .image_build_proxy,
        None
    );
    // A Compose `${VAR:-}` default hands the controller an empty string.
    let env = env_of(&[
        ("FLEET_IMAGE_BUILD_PROXY", ""),
        ("FLEET_IMAGE_BUILD_NO_PROXY", "pve.example.test"),
    ]);
    let config = fleet_config::load(None, &env).unwrap();
    assert_eq!(config.image_build_proxy, None);
    assert!(
        config
            .summary()
            .contains("image_build_proxy = <unset; builds connect directly>")
    );
}

#[test]
fn the_image_build_proxy_layers_from_file_then_environment() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        "version = 1\nimage_build_proxy = \"http://file-proxy.example.test:3128\"\nimage_build_no_proxy = \"localhost\"\n",
    );
    let config = fleet_config::load(Some(&path), &none_env).unwrap();
    let proxy = config.image_build_proxy.unwrap();
    assert_eq!(proxy.url(), "http://file-proxy.example.test:3128");
    assert_eq!(proxy.no_proxy(), Some("localhost"));

    let env = env_of(&[
        (
            "FLEET_IMAGE_BUILD_PROXY",
            " HTTP://Env-Proxy.example.test:8443/ ",
        ),
        ("FLEET_IMAGE_BUILD_NO_PROXY", ".lan,10.0.0.0/8"),
    ]);
    let config = fleet_config::load(Some(&path), &env).unwrap();
    let proxy = config.image_build_proxy.clone().unwrap();
    assert_eq!(proxy.url(), "http://Env-Proxy.example.test:8443");
    assert_eq!(proxy.no_proxy(), Some(".lan,10.0.0.0/8"));
    let summary = config.summary();
    assert!(summary.contains("image_build_proxy = http://Env-Proxy.example.test:8443"));
    assert!(summary.contains("image_build_no_proxy = .lan,10.0.0.0/8"));
}

#[test]
fn a_bad_image_build_proxy_is_refused_without_echoing_the_value() {
    for bad in [
        "http://user:hunter2@proxy.example.test:3128",
        "http://:hunter2@proxy.example.test:3128",
        "http://proxy.example.test:3128/path?token=hunter2",
        "http://proxy.example.test:3128#hunter2",
        "https://proxy.example.test:3128",
        "socks5://proxy.example.test:1080",
        "http://[::1]x:3128",
        "http://[::1]:",
        "http://[::1]:99999",
        "http://[::1]3128",
        "http://[::1]/hunter2",
        "http://[::1]:3128hunter2",
        "http://pro[xy.example.test",
        "http://proxy].example.test",
        "http://proxy.example.test%2Ehunter2",
        "http://pr%6Fxy.example.test",
        "http://prøxy.example.test",
        "http://proxy.example.test:31\u{0663}",
        "http://proxy.example.test\thunter2",
        "proxy.example.test:3128",
        "http://",
        "http://proxy.example.test:0",
        "http://proxy.example.test:99999",
        "http://proxy.example.test:",
        "http://pro xy.example.test",
        "http://[::1",
        "http://a:b:c",
    ] {
        let entries = [("FLEET_IMAGE_BUILD_PROXY", bad)];
        let env = env_of(&entries);
        let error = fleet_config::load(None, &env).unwrap_err();
        assert!(matches!(error, ConfigError::ImageBuildProxyInvalid { .. }));
        let text = error.to_string();
        assert!(text.contains("FLEET_IMAGE_BUILD_PROXY"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("proxy.example"), "{text}");
        assert!(!format!("{error:?}").contains("hunter2"));
    }
    let env = env_of(&[
        ("FLEET_IMAGE_BUILD_PROXY", "http://proxy.example.test:3128"),
        ("FLEET_IMAGE_BUILD_NO_PROXY", "a@b"),
    ]);
    let error = fleet_config::load(None, &env).expect_err("no_proxy");
    assert!(error.to_string().contains("FLEET_IMAGE_BUILD_NO_PROXY"));
}

#[test]
fn well_formed_image_build_proxies_are_accepted() {
    for (raw, expected) in [
        ("http://proxy.example.test", "http://proxy.example.test"),
        ("http://127.0.0.1:3128/", "http://127.0.0.1:3128"),
        ("http://[2001:db8::1]:8443", "http://[2001:db8::1]:8443"),
        ("http://[::1]", "http://[::1]"),
    ] {
        let entries = [("FLEET_IMAGE_BUILD_PROXY", raw)];
        let env = env_of(&entries);
        let config = fleet_config::load(None, &env).unwrap();
        assert_eq!(config.image_build_proxy.unwrap().url(), expected);
    }
}

#[test]
fn a_bad_no_proxy_list_is_refused_with_or_without_a_proxy() {
    let long = "a".repeat(1025);
    let exact = "a".repeat(1024);
    for bad in ["a b", "a@b", "h=1", "høst", long.as_str()] {
        let entries = [("FLEET_IMAGE_BUILD_NO_PROXY", bad)];
        let env = env_of(&entries);
        let error = fleet_config::load(None, &env).unwrap_err();
        assert!(error.to_string().contains("FLEET_IMAGE_BUILD_NO_PROXY"));
    }
    let entries = [("FLEET_IMAGE_BUILD_NO_PROXY", exact.as_str())];
    assert!(fleet_config::load(None, &env_of(&entries)).is_ok());
}

#[test]
fn an_empty_environment_value_does_not_override_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        "version = 1\nimage_build_proxy = \"http://file-proxy.example.test:3128\"\nimage_build_no_proxy = \"localhost\"\n",
    );
    let env = env_of(&[
        ("FLEET_IMAGE_BUILD_PROXY", ""),
        ("FLEET_IMAGE_BUILD_NO_PROXY", "  "),
    ]);
    let proxy = fleet_config::load(Some(&path), &env)
        .unwrap()
        .image_build_proxy
        .unwrap();
    assert_eq!(proxy.url(), "http://file-proxy.example.test:3128");
    assert_eq!(proxy.no_proxy(), Some("localhost"));
}

#[test]
fn toml_errors_never_quote_a_proxy_setting() {
    let dir = tempfile::tempdir().unwrap();
    for text in [
        // Unquoted value.
        "version = 1\nimage_build_proxy = http://user:hunter2@proxy.example.test:3128\n",
        // Misspelled key.
        "version = 1\nimage_build_proxi = \"http://user:hunter2@proxy.example.test:3128\"\n",
        // Wrong type.
        "version = 1\nimage_build_proxy = [\"http://user:hunter2@proxy.example.test\"]\n",
        "version = 1\nimage_build_no_proxy = 7\nimage_build_proxy = \"http://user:hunter2@p\" junk\n",
    ] {
        let path = write_config(dir.path(), text);
        let error = fleet_config::load(Some(&path), &none_env).unwrap_err();
        assert!(matches!(error, ConfigError::Parse { .. }), "{text}");
        let shown = format!("{error} {error:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(!shown.contains("proxy.example"), "{shown}");
    }
    // Other files keep the parser's full message.
    let path = write_config(dir.path(), "version = 1\nlisten = 5\n");
    let shown = fleet_config::load(Some(&path), &none_env)
        .unwrap_err()
        .to_string();
    assert!(shown.contains("listen"), "{shown}");
}

// Build address pool (#337) --------------------------------------------------

const POOL_ENV: [(&str, &str); 4] = [
    ("FLEET_IMAGE_BUILD_ADDRESS_POOL", "192.0.2.0/24"),
    (
        "FLEET_IMAGE_BUILD_ADDRESS_POOL_RANGE",
        "192.0.2.100-192.0.2.150",
    ),
    ("FLEET_IMAGE_BUILD_ADDRESS_POOL_GATEWAY", "192.0.2.1"),
    ("FLEET_IMAGE_BUILD_ADDRESS_POOL_DNS", "192.0.2.2"),
];

#[test]
fn the_build_address_pool_is_off_by_default_and_for_empty_values() {
    let config = fleet_config::load(None, &none_env).unwrap();
    assert!(config.image_build_address_pool.is_none());
    assert!(
        config
            .summary()
            .contains("image_build_address_pool = <unset; build guests choose their own address>")
    );
    // A Compose `${VAR:-}` default hands the controller empty strings.
    let env = env_of(&[
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL", ""),
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL_RANGE", ""),
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL_GATEWAY", ""),
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL_DNS", ""),
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL_REFUSE_ISO", ""),
    ]);
    assert!(
        fleet_config::load(None, &env)
            .unwrap()
            .image_build_address_pool
            .is_none()
    );
}

#[test]
fn the_build_address_pool_loads_from_the_environment_and_shows_in_the_summary() {
    let mut entries = POOL_ENV.to_vec();
    entries.push(("FLEET_IMAGE_BUILD_ADDRESS_POOL_REFUSE_ISO", "true"));
    let config = fleet_config::load(None, &env_of(&entries)).unwrap();
    let pool = config.image_build_address_pool.clone().unwrap();
    assert_eq!(pool.size(), 51);
    assert!(pool.refuses_iso());
    let summary = config.summary();
    assert!(
        summary.contains(
            "image_build_address_pool = 192.0.2.0/24 range 192.0.2.100-192.0.2.150 gateway 192.0.2.1 dns 192.0.2.2 (proxmox-iso builds refused)"
        ),
        "{summary}"
    );
}

#[test]
fn the_build_address_pool_layers_from_file_then_environment() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        "version = 1\n\
         image_build_address_pool = \"198.51.100.0/24\"\n\
         image_build_address_pool_range = \"198.51.100.20-198.51.100.30\"\n\
         image_build_address_pool_gateway = \"198.51.100.1\"\n\
         image_build_address_pool_refuse_iso = true\n",
    );
    let config = fleet_config::load(Some(&path), &none_env).unwrap();
    let pool = config.image_build_address_pool.unwrap();
    assert_eq!(pool.cidr(), "198.51.100.0/24");
    assert!(pool.refuses_iso());
    // The environment wins, key by key; an empty value does not override.
    let env = env_of(&[
        (
            "FLEET_IMAGE_BUILD_ADDRESS_POOL_RANGE",
            "198.51.100.40-198.51.100.50",
        ),
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL_GATEWAY", ""),
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL_REFUSE_ISO", "false"),
    ]);
    let pool = fleet_config::load(Some(&path), &env)
        .unwrap()
        .image_build_address_pool
        .unwrap();
    assert_eq!(pool.range(), "198.51.100.40-198.51.100.50");
    assert_eq!(pool.gateway().to_string(), "198.51.100.1");
    assert!(!pool.refuses_iso());
}

#[test]
fn a_bad_or_partial_build_address_pool_fails_loading_without_echoing_values() {
    let bad: [(&str, &str); 6] = [
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL", "192.0.2.77/24"),
        (
            "FLEET_IMAGE_BUILD_ADDRESS_POOL_RANGE",
            "192.0.2.150-192.0.2.100",
        ),
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL_GATEWAY", "192.0.2.120"),
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL_DNS", "127.0.0.1"),
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL_REFUSE_ISO", "maybe"),
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL", "169.254.0.0/16"),
    ];
    for (key, value) in bad {
        let mut entries: Vec<(&str, &str)> = POOL_ENV.to_vec();
        entries.retain(|(k, _)| *k != key);
        entries.push((key, value));
        let error = fleet_config::load(None, &env_of(&entries))
            .expect_err(&format!("{key}={value} must be refused"))
            .to_string();
        assert!(error.contains("FLEET_IMAGE_BUILD_ADDRESS_POOL"), "{error}");
        assert!(
            !error.contains(value) && !error.contains("192.0.2."),
            "{error}"
        );
    }
    // A companion setting needs the CIDR; the CIDR needs range and gateway.
    for (key, value) in [
        (
            "FLEET_IMAGE_BUILD_ADDRESS_POOL_RANGE",
            "192.0.2.10-192.0.2.20",
        ),
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL_GATEWAY", "192.0.2.1"),
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL_DNS", "192.0.2.2"),
        ("FLEET_IMAGE_BUILD_ADDRESS_POOL_REFUSE_ISO", "true"),
    ] {
        assert!(
            fleet_config::load(None, &env_of(&[(key, value)])).is_err(),
            "{key}"
        );
    }
    for missing in [
        "FLEET_IMAGE_BUILD_ADDRESS_POOL_RANGE",
        "FLEET_IMAGE_BUILD_ADDRESS_POOL_GATEWAY",
    ] {
        let mut entries: Vec<(&str, &str)> = POOL_ENV.to_vec();
        entries.retain(|(k, _)| *k != missing);
        assert!(
            fleet_config::load(None, &env_of(&entries)).is_err(),
            "{missing}"
        );
    }
}
