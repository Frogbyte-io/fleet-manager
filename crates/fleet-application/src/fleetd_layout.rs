//! The fleetd installer's environment (#616): which variables a
//! `machine.install-fleetd` may pass to `deploy/fleetd/install.sh`, and what
//! values they may take. The same rules apply when the install is accepted,
//! when it runs, and when a machine removal reuses the recorded layout for
//! `deploy/fleetd/uninstall.sh`, which runs with root privileges and deletes
//! `FLEETD_STATE_DIR` recursively with `--purge`.
//!
//! - Only the documented installer variables are accepted
//!   ([`INSTALLER_VARIABLES`]), so nothing like `BASH_ENV` or `LD_PRELOAD`
//!   reaches a privileged script.
//! - No name or value contains NUL or another control character: the SSH
//!   provider frames its metadata with NUL, and a newline has no place in a
//!   path.
//! - Directory and file variables are absolute paths without `..`.
//! - `FLEETD_STATE_DIR` is never a system root or a top-level directory.
//! - `FLEETD_SERVICE` is a plain unit name.
//! - The tool overrides (`FLEETD_SYSTEMCTL`, `FLEETD_USER_ADD`,
//!   `FLEETD_RUNUSER`) run as root, so a production controller accepts them
//!   only from `/bin`, `/usr/bin`, `/sbin` or `/usr/sbin`, and refuses the
//!   test harness's `FLEETD_STUB_LOG`. A controller composed in installer test
//!   mode ([`InstallerTools::Any`], never set by the controller binary)
//!   accepts any absolute tool path and the stub log, which the hermetic
//!   install tests need for their stubs.
#![warn(missing_docs)]

/// The installer variables `machine.install-fleetd` accepts: the layout
/// overrides `install.sh` and `uninstall.sh` read, the tool overrides the
/// containers and tests use, and the test harness's stub log.
pub const INSTALLER_VARIABLES: [&str; 10] = [
    "FLEETD_ARCHIVE_DIR",
    "FLEETD_BIN_DIR",
    "FLEETD_UNIT_DIR",
    "FLEETD_ENV_FILE",
    "FLEETD_STATE_DIR",
    "FLEETD_SERVICE",
    "FLEETD_SYSTEMCTL",
    "FLEETD_USER_ADD",
    "FLEETD_RUNUSER",
    "FLEETD_STUB_LOG",
];

/// Which tool overrides the installer environment accepts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum InstallerTools {
    /// Production: tools only from the system binary directories, no stub
    /// log.
    #[default]
    System,
    /// Installer test mode: any absolute tool path and the stub log.
    Any,
}

/// The directories a production tool override may name a tool in.
const SYSTEM_TOOL_DIRECTORIES: [&str; 4] = ["/bin", "/usr/bin", "/sbin", "/usr/sbin"];

/// The tool overrides, which the installer runs as root, and the only file
/// name each may name in production.
const TOOL_VARIABLES: [(&str, &str); 3] = [
    ("FLEETD_SYSTEMCTL", "systemctl"),
    ("FLEETD_USER_ADD", "useradd"),
    ("FLEETD_RUNUSER", "runuser"),
];

/// The installer layout overrides an uninstall honours (`uninstall.sh` reads
/// the same names).
pub const LAYOUT_VARIABLES: [&str; 6] = [
    "FLEETD_BIN_DIR",
    "FLEETD_UNIT_DIR",
    "FLEETD_ENV_FILE",
    "FLEETD_STATE_DIR",
    "FLEETD_SERVICE",
    "FLEETD_SYSTEMCTL",
];

/// Directories `FLEETD_STATE_DIR` may never be: purging it deletes it.
const PROTECTED_DIRECTORIES: [&str; 37] = [
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/media",
    "/mnt",
    "/opt",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/snap",
    "/srv",
    "/sys",
    "/tmp",
    "/usr",
    "/var",
    "/etc/systemd",
    "/run/user",
    "/usr/bin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/libexec",
    "/usr/local",
    "/usr/sbin",
    "/usr/share",
    "/var/cache",
    "/var/lib",
    "/var/log",
    "/var/spool",
    "/var/tmp",
];

/// World-writable system directories a production state directory may not
/// live under.
const WORLD_WRITABLE_DIRECTORIES: [&str; 3] = ["/tmp", "/var/tmp", "/dev/shm"];

/// The longest value accepted.
const MAX_VALUE_BYTES: usize = 1024;

/// Checks one installer variable.
///
/// # Errors
///
/// Names the variable and the rule it broke.
pub fn validate_installer_variable(
    name: &str,
    value: &str,
    tools: InstallerTools,
) -> Result<(), String> {
    if name.chars().any(char::is_control) || value.chars().any(char::is_control) {
        return Err(format!(
            "installer variable {:?} contains a control character",
            name.escape_debug().to_string()
        ));
    }
    if !INSTALLER_VARIABLES.contains(&name) {
        return Err(format!(
            "installer variable {name:?} is not accepted; the accepted names are {}",
            INSTALLER_VARIABLES.join(", ")
        ));
    }
    if value.is_empty() || value.len() > MAX_VALUE_BYTES {
        return Err(format!(
            "installer variable {name} must be 1 to {MAX_VALUE_BYTES} bytes"
        ));
    }
    if name == "FLEETD_SERVICE" {
        return if value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '-'))
            && !matches!(value, "." | "..")
        {
            Ok(())
        } else {
            Err(format!(
                "installer variable FLEETD_SERVICE must be a unit name of letters, digits, `@`, `.`, `_` or `-`, not {value:?}"
            ))
        };
    }
    if name == "FLEETD_STUB_LOG" && tools == InstallerTools::System {
        return Err(
            "installer variable FLEETD_STUB_LOG is only accepted by a controller in installer test mode"
                .to_owned(),
        );
    }
    // Every other variable is a directory, a file or a tool: an absolute path.
    let components = absolute_components(name, value)?;
    if let Some((_, tool)) = TOOL_VARIABLES
        .iter()
        .find(|(variable, _)| *variable == name)
        && tools == InstallerTools::System
    {
        let (file, directory) = components
            .split_last()
            .map_or(("", "/".to_owned()), |(file, directory)| {
                (*file, format!("/{}", directory.join("/")))
            });
        if file != *tool || !SYSTEM_TOOL_DIRECTORIES.contains(&directory.as_str()) {
            return Err(format!(
                "installer variable {name} runs as root, so it must be {tool} in {}, not {value:?}",
                SYSTEM_TOOL_DIRECTORIES.join(", ")
            ));
        }
    }
    if name == "FLEETD_STATE_DIR" {
        let normalized = format!("/{}", components.join("/"));
        if components.len() < 2 || PROTECTED_DIRECTORIES.contains(&normalized.as_str()) {
            return Err(format!(
                "installer variable FLEETD_STATE_DIR must be fleetd's own directory, not the system directory {normalized:?} (uninstalling with --purge deletes it)"
            ));
        }
        // install.sh and the purge both refuse a state directory under a
        // group- or world-writable ancestor, in every mode (the scripts have
        // no test mode), so no install may put it there: an accepted layout
        // stays installable and removable. The hermetic install tests keep
        // theirs under $HOME.
        if let Some(shared) = WORLD_WRITABLE_DIRECTORIES
            .iter()
            .find(|shared| normalized.starts_with(&format!("{shared}/")))
        {
            return Err(format!(
                "installer variable FLEETD_STATE_DIR must not be under the world-writable {shared} (uninstalling with --purge refuses such a directory), not {normalized:?}"
            ));
        }
    }
    Ok(())
}

/// Checks a whole installer environment.
///
/// # Errors
///
/// As [`validate_installer_variable`], for the first variable that breaks a
/// rule.
pub fn validate_installer_env(
    entries: &[(String, String)],
    tools: InstallerTools,
) -> Result<(), String> {
    entries
        .iter()
        .try_for_each(|(name, value)| validate_installer_variable(name, value, tools))
}

/// The components of an absolute, normalized path: no `..`, no `.`, no
/// `//` and no trailing `/`, so the scripts never test one path and act on
/// another (`link/` is the link's target to `rm`, but not to `[ -L ]`).
fn absolute_components<'a>(name: &str, value: &'a str) -> Result<Vec<&'a str>, String> {
    if !value.starts_with('/') {
        return Err(format!(
            "installer variable {name} must be an absolute path, not {value:?}"
        ));
    }
    if value != "/"
        && (value.ends_with('/')
            || value.contains("//")
            || value.split('/').any(|part| part == "."))
    {
        return Err(format!(
            "installer variable {name} must be a normalized path (no trailing `/`, `//` or `.`), not {value:?}"
        ));
    }
    let components: Vec<&str> = value
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    if components.contains(&"..") {
        return Err(format!(
            "installer variable {name} must not contain `..`, not {value:?}"
        ));
    }
    Ok(components)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(name: &str, value: &str) {
        validate_installer_variable(name, value, InstallerTools::System)
            .unwrap_or_else(|error| panic!("{name}={value}: {error}"));
    }

    fn refused(name: &str, value: &str) -> String {
        validate_installer_variable(name, value, InstallerTools::System)
            .expect_err(&format!("{name}={value} must be refused"))
    }

    #[test]
    fn production_tools_come_from_the_system_directories_and_tests_may_use_stubs() {
        ok("FLEETD_SYSTEMCTL", "/usr/bin/systemctl");
        ok("FLEETD_USER_ADD", "/sbin/useradd");
        ok("FLEETD_RUNUSER", "/usr/sbin/runuser");
        // Only the tool's own name, in production.
        refused("FLEETD_SYSTEMCTL", "/bin/true");
        refused("FLEETD_USER_ADD", "/usr/bin/bash");
        refused("FLEETD_RUNUSER", "/usr/bin/sudo");
        refused("FLEETD_SYSTEMCTL", "/usr/bin/systemctl/");
        refused("FLEETD_USER_ADD", "/usr/sbin//useradd");
        for (name, value) in [
            ("FLEETD_SYSTEMCTL", "/tmp/stubs/systemctl"),
            ("FLEETD_SYSTEMCTL", "/usr/local/bin/systemctl"),
            ("FLEETD_SYSTEMCTL", "/usr/bin"),
            ("FLEETD_SYSTEMCTL", "/usr/bin/x/../../tmp/evil"),
            ("FLEETD_USER_ADD", "/home/alice/useradd"),
            ("FLEETD_RUNUSER", "/usr/bin/sub/runuser"),
            ("FLEETD_STUB_LOG", "/tmp/stubs.log"),
        ] {
            refused(name, value);
            // Test mode still refuses `..` and a bare directory as a tool is
            // still a path; everything else here is a stub test mode accepts.
            if !value.contains("..") && value != "/usr/bin" {
                validate_installer_variable(name, value, InstallerTools::Any)
                    .unwrap_or_else(|error| panic!("test mode {name}={value}: {error}"));
            }
        }
        // Test mode relaxes only the tool and stub-log rules.
        assert!(
            validate_installer_variable("FLEETD_STATE_DIR", "/etc", InstallerTools::Any).is_err()
        );
        assert!(validate_installer_variable("BASH_ENV", "/tmp/x", InstallerTools::Any).is_err());
    }

    #[test]
    fn the_layouts_the_tests_and_defaults_use_are_accepted() {
        ok("FLEETD_STATE_DIR", "/var/lib/fleetd");
        ok("FLEETD_STATE_DIR", "/srv/fleet/state");
        ok("FLEETD_BIN_DIR", "/usr/local/bin");
        ok("FLEETD_UNIT_DIR", "/etc/systemd/system");
        ok("FLEETD_ENV_FILE", "/etc/default/fleetd");
        ok("FLEETD_SERVICE", "fleetd@test.service-1_a");
        ok("FLEETD_SYSTEMCTL", "/bin/systemctl");
        ok("FLEETD_USER_ADD", "/usr/sbin/useradd");
        ok("FLEETD_RUNUSER", "/usr/sbin/runuser");
        ok("FLEETD_ARCHIVE_DIR", "/tmp/fleetd-install.x");
    }

    #[test]
    fn a_state_dir_under_a_world_writable_directory_is_refused_in_every_mode() {
        for dir in [
            "/tmp/fleetd",
            "/tmp/.tmpAbC/state",
            "/var/tmp/fleetd",
            "/dev/shm/fleetd",
        ] {
            let error = refused("FLEETD_STATE_DIR", dir);
            assert!(error.contains("world-writable"), "{dir}: {error}");
            // In test mode too: install.sh refuses such an ancestor itself.
            let error = validate_installer_variable("FLEETD_STATE_DIR", dir, InstallerTools::Any)
                .unwrap_err();
            assert!(error.contains("world-writable"), "test mode {dir}: {error}");
        }
        ok("FLEETD_STATE_DIR", "/var/lib/fleetd");
        ok("FLEETD_STATE_DIR", "/tmpfleet/state");
    }

    #[test]
    fn a_state_dir_that_is_a_system_directory_is_refused() {
        for dir in [
            "/",
            "/etc",
            "/etc/",
            "//etc",
            "/usr",
            "/var",
            "/home",
            "/root",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/boot",
            "/opt",
            "/srv",
            "/tmp",
            "/var/lib",
            "/usr/local",
            "/./etc",
            "/var/lib/",
        ] {
            let error = refused("FLEETD_STATE_DIR", dir);
            assert!(error.contains("FLEETD_STATE_DIR"), "{dir}: {error}");
        }
    }

    #[test]
    fn non_normalized_paths_are_refused() {
        for value in [
            "/var/lib/fleetd/",
            "/var/lib//fleetd",
            "/var/lib/./fleetd",
            "/var/lib/fleetd/.",
        ] {
            let error = refused("FLEETD_STATE_DIR", value);
            assert!(error.contains("normalized"), "{value}: {error}");
            refused("FLEETD_BIN_DIR", value);
        }
        ok("FLEETD_BIN_DIR", "/");
    }

    #[test]
    fn relative_paths_and_dotdot_are_refused() {
        refused("FLEETD_BIN_DIR", "usr/local/bin");
        refused("FLEETD_UNIT_DIR", "/etc/systemd/../../");
        refused("FLEETD_STATE_DIR", "/var/lib/fleetd/../../..");
        refused("FLEETD_SYSTEMCTL", "systemctl");
        refused("FLEETD_USER_ADD", "./useradd");
        refused("FLEETD_RUNUSER", "");
    }

    #[test]
    fn control_characters_unknown_names_and_odd_services_are_refused() {
        refused("FLEETD_STATE_DIR", "/var/lib/fleetd\0BASH_ENV=/tmp/x");
        refused("FLEETD_BIN_DIR", "/usr/local/bin\n/etc");
        refused("FLEETD_STATE\0DIR", "/var/lib/fleetd");
        assert!(refused("BASH_ENV", "/tmp/x").contains("not accepted"));
        refused("LD_PRELOAD", "/tmp/x.so");
        refused("FLEETD_SERVICE", "fleetd; rm -rf /");
        refused("FLEETD_SERVICE", "../fleetd");
        refused("FLEETD_SERVICE", "..");
        assert!(
            validate_installer_env(
                &[
                    ("FLEETD_BIN_DIR".to_owned(), "/opt/fleet/bin".to_owned()),
                    ("FLEETD_STATE_DIR".to_owned(), "/etc".to_owned()),
                ],
                InstallerTools::System
            )
            .is_err()
        );
    }
}
