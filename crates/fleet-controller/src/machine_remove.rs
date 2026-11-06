//! The controller side of removing a machine (#616): the fleetd uninstall
//! over SSH, and the composition of the removal use case.
//!
//! The uninstall is the shipped `deploy/fleetd/uninstall.sh`, run with
//! `--purge` (the machine's node identity is deleted with it, so the state
//! the script would keep could never be used again). It rides SSH stdin like
//! the install script, over the endpoint's confirmed host key and the
//! authentication the review bound; it touches nothing else on the machine.
//! Its output is scrubbed and cut to one line before anything records it.
//!
//! The uninstall honours the layout the machine's fleetd was installed with:
//! the review reads the installer layout overrides (`FLEETD_BIN_DIR`,
//! `FLEETD_UNIT_DIR`, ...) of the machine's last successful
//! `machine.install-fleetd` and the script runs with them. A preflight runs
//! before the script and fails the uninstall when neither the unit nor the
//! binary is where that layout says, so a fleetd installed some other way is
//! reported as not found instead of "removed".

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fleet_application::machine::MachinePort;
use fleet_application::machine_access::EndpointAuth;
use fleet_application::machine_remove::{
    FleetdUninstall, FleetdUninstallPort, MachineRemoval, NodeSessionPort,
};
use fleet_provider_ssh::{ExecutionLimiter, SshAuth, SshProvider};

use crate::exec::resolve_ssh_endpoint;
use crate::machine_access::SshAuthResolver;

/// The shipped uninstall script, delivered over SSH stdin.
pub const UNINSTALL_SCRIPT: &str = include_str!("../../../deploy/fleetd/uninstall.sh");

/// Runs before the uninstall: with the same defaults and overrides the
/// script reads, it refuses when there is no fleetd unit and no fleetd binary
/// to remove (exit 3), instead of letting the script report success.
pub const UNINSTALL_PREFLIGHT: &str = r#"UNIT_DIR="${FLEETD_UNIT_DIR:-/etc/systemd/system}"
BIN_DIR="${FLEETD_BIN_DIR:-/usr/local/bin}"
SERVICE="${FLEETD_SERVICE:-fleetd}"
if [ ! -e "$UNIT_DIR/$SERVICE.service" ] && [ ! -e "$BIN_DIR/fleetd" ]; then
    printf 'uninstall: no fleetd found: neither %s nor %s exists, so nothing was removed (fleetd may have been installed with another layout, or already removed; remove the machine without --uninstall)\n' "$UNIT_DIR/$SERVICE.service" "$BIN_DIR/fleetd" >&2
    exit 3
fi
"#;

/// The script the uninstall runs: the preflight, then the shipped script.
#[must_use]
pub fn uninstall_script() -> String {
    format!("{UNINSTALL_PREFLIGHT}{UNINSTALL_SCRIPT}")
}

/// The argument the uninstall runs with.
pub const UNINSTALL_ARGUMENTS: [&str; 1] = ["--purge"];

/// The bound on the uninstall: it stops a service and removes four files.
pub const UNINSTALL_TIMEOUT: Duration = Duration::from_secs(120);

/// The longest line of remote output kept in a result or a failure.
const LINE_LIMIT: usize = 300;

/// [`FleetdUninstallPort`] over the SSH provider.
#[derive(Debug)]
pub struct SshFleetdUninstaller {
    machines: Arc<dyn MachinePort>,
    provider: SshProvider,
    limiter: Arc<ExecutionLimiter>,
    resolver: Option<Arc<SshAuthResolver>>,
}

impl SshFleetdUninstaller {
    /// Over the controller's SSH work directory, so the trust workflow's pins
    /// serve the uninstall like any other SSH work. Without a resolver (no
    /// secret store) a stored-key authentication is refused.
    ///
    /// # Errors
    ///
    /// Fails when the SSH work directory cannot be prepared.
    pub fn new(
        machines: Arc<dyn MachinePort>,
        work_dir: std::path::PathBuf,
        limiter: Arc<ExecutionLimiter>,
        resolver: Option<Arc<SshAuthResolver>>,
    ) -> Result<Self, String> {
        let provider = SshProvider::new(work_dir).map_err(|error| error.to_string())?;
        Ok(Self {
            machines,
            provider,
            limiter,
            resolver,
        })
    }

    async fn ssh_auth(&self, auth: &EndpointAuth, machine_id: &str) -> Result<SshAuth, String> {
        match (&self.resolver, auth) {
            (Some(resolver), auth) => resolver.resolve(auth, machine_id).await,
            (None, EndpointAuth::Agent) => Ok(SshAuth::Agent),
            (None, EndpointAuth::IdentityFile { path }) => {
                Ok(SshAuth::IdentityFile { path: path.clone() })
            }
            (None, EndpointAuth::Secret { .. }) => Err(
                "the controller has no secret store, so it cannot use a stored SSH key".to_owned(),
            ),
        }
    }
}

#[async_trait]
impl FleetdUninstallPort for SshFleetdUninstaller {
    async fn uninstall(&self, request: &FleetdUninstall) -> Result<String, String> {
        // The review validated the layout; it is checked again here because
        // it reaches a root script that deletes FLEETD_STATE_DIR.
        for (name, value) in &request.plan.layout {
            if !fleet_application::machine_remove::LAYOUT_VARIABLES.contains(&name.as_str()) {
                return Err(format!("{name} is not an uninstall layout variable"));
            }
            fleet_application::fleetd_layout::validate_installer_variable(
                name,
                value,
                fleet_application::fleetd_layout::InstallerTools::System,
            )?;
        }
        let auth = self
            .ssh_auth(&request.plan.auth, &request.machine_id)
            .await?;
        let (spec, _verified, _host) = resolve_ssh_endpoint(
            self.machines.as_ref(),
            &request.machine_id,
            &request.plan.endpoint_id,
            auth,
        )
        .await?;
        let metadata = fleet_provider_ssh::ScriptMetadata {
            working_directory: String::new(),
            // Only the layout names reach the machine; the review bound them.
            environment: request
                .plan
                .layout
                .iter()
                .filter(|(name, _)| {
                    fleet_application::machine_remove::LAYOUT_VARIABLES.contains(&name.as_str())
                })
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            arguments: UNINSTALL_ARGUMENTS
                .iter()
                .map(|arg| (*arg).to_owned())
                .collect(),
        };
        let provider = self.provider.clone();
        let limiter = self.limiter.clone();
        let script = uninstall_script();
        let outcome = tokio::task::spawn_blocking(move || {
            fleet_provider_ssh::execute_script(
                &provider,
                &limiter,
                &spec,
                &script,
                &metadata,
                UNINSTALL_TIMEOUT,
            )
        })
        .await
        .map_err(|error| format!("the uninstall thread failed: {error}"))?
        .map_err(|error| one_line(&error.to_string()))?;
        interpret(&outcome)
    }
}

/// What an uninstall run came to: its last line on success, a failure with
/// the first informative line otherwise. The remote fate of a run the
/// deadline killed is unknown, so it is a failure.
fn interpret(outcome: &fleet_provider_ssh::ExecutionResult) -> Result<String, String> {
    if outcome.killed_by_deadline {
        return Err(format!(
            "the uninstall did not finish within {}s; its result on the machine is unknown",
            UNINSTALL_TIMEOUT.as_secs()
        ));
    }
    if outcome.exit_code != Some(0) {
        let detail = [outcome.stderr.as_str(), outcome.stdout.as_str()]
            .into_iter()
            .map(one_line)
            .find(|line| !line.is_empty())
            .unwrap_or_else(|| "no remote output".to_owned());
        return Err(format!(
            "the uninstall script exited {}: {detail}",
            outcome
                .exit_code
                .map_or_else(|| "with no exit code".to_owned(), |code| code.to_string())
        ));
    }
    Ok(last_line(&outcome.stdout))
}

/// The first non-empty line of scrubbed remote text, bounded.
fn one_line(text: &str) -> String {
    let (scrubbed, _) = fleet_core::scrub_and_bound_with(text, false, str::to_owned);
    scrubbed
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(bound)
        .unwrap_or_default()
}

/// The last non-empty line of scrubbed remote text, bounded.
fn last_line(text: &str) -> String {
    let (scrubbed, _) = fleet_core::scrub_and_bound_with(text, false, str::to_owned);
    scrubbed
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .map_or_else(|| "uninstalled".to_owned(), bound)
}

fn bound(line: &str) -> String {
    if line.len() <= LINE_LIMIT {
        return line.to_owned();
    }
    let mut end = LINE_LIMIT;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &line[..end])
}

/// [`NodeSessionPort`] over the node gateway's session registry.
#[derive(Debug)]
pub struct GatewaySessions(pub Arc<crate::gateway::GatewayService>);

#[async_trait]
impl NodeSessionPort for GatewaySessions {
    async fn close(&self, machine_id: &str) -> bool {
        self.0.close_session(machine_id)
    }
}

/// Composes the removal use case over the store: the holds and the guarded
/// delete, the USB gate, the SSH trust store in the controller's SSH work
/// directory, the endpoints' stored authentication, and the uninstall. The
/// key store (`keys`, with the secret store) revokes the machine's stored
/// secrets; without it a machine with stored secrets is refused. The gateway
/// closes a removed machine's live session when the node services run.
///
/// # Errors
///
/// Fails when the SSH work directory cannot be prepared.
pub fn compose(
    pool: &sqlx::SqlitePool,
    ssh_work_dir: std::path::PathBuf,
    keys: Option<Arc<dyn fleet_application::machine_access::MachineKeyPort>>,
    resolver: Option<Arc<SshAuthResolver>>,
    gateway: Option<Arc<crate::gateway::GatewayService>>,
) -> Result<MachineRemoval, String> {
    let records: Arc<dyn MachinePort> =
        Arc::new(fleet_storage_sqlite::MachineRepository::new(pool.clone()));
    let uninstaller = SshFleetdUninstaller::new(
        records.clone(),
        ssh_work_dir.clone(),
        ExecutionLimiter::new(2),
        resolver,
    )?;
    let removal = MachineRemoval::new(
        records,
        Arc::new(fleet_storage_sqlite::MachineRemovalRepository::new(
            pool.clone(),
        )),
        Arc::new(
            fleet_application::machine_usb::StoreMachineHardwareGate::new(Arc::new(
                fleet_storage_sqlite::HardwareRepository::new(pool.clone()),
            )),
        ),
        Arc::new(crate::onboard::SshTrustAdapter::new(ssh_work_dir)),
        Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone())),
    )
    .with_endpoint_auth(Arc::new(fleet_storage_sqlite::EndpointAuthRepository::new(
        pool.clone(),
    )))
    .with_uninstaller(Arc::new(uninstaller));
    let removal = match keys {
        Some(keys) => removal.with_key_revocation(keys),
        None => removal,
    };
    Ok(match gateway {
        Some(gateway) => removal.with_sessions(Arc::new(GatewaySessions(gateway))),
        None => removal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(
        exit: Option<i32>,
        stdout: &str,
        stderr: &str,
        killed: bool,
    ) -> fleet_provider_ssh::ExecutionResult {
        fleet_provider_ssh::ExecutionResult {
            exit_code: exit,
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            truncated_stdout: false,
            truncated_stderr: false,
            killed_by_deadline: killed,
        }
    }

    #[test]
    fn the_preflight_refuses_when_no_fleetd_is_in_the_layout() {
        let dir = tempfile::tempdir().unwrap();
        let run = |unit_dir: &std::path::Path| {
            std::process::Command::new("bash")
                .arg("-c")
                .arg(format!("{UNINSTALL_PREFLIGHT}echo reached"))
                .env("FLEETD_UNIT_DIR", unit_dir)
                .env("FLEETD_BIN_DIR", unit_dir)
                .output()
                .unwrap()
        };
        let missing = run(dir.path());
        assert_eq!(missing.status.code(), Some(3));
        let stderr = String::from_utf8_lossy(&missing.stderr);
        assert!(stderr.contains("no fleetd found"), "{stderr}");
        assert!(!String::from_utf8_lossy(&missing.stdout).contains("reached"));
        std::fs::write(dir.path().join("fleetd.service"), "").unwrap();
        let present = run(dir.path());
        assert_eq!(present.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&present.stdout).contains("reached"));
        assert!(uninstall_script().starts_with(UNINSTALL_PREFLIGHT));
        assert!(uninstall_script().ends_with(UNINSTALL_SCRIPT));
    }

    /// Runs the shipped uninstall in a scratch layout with a `systemctl`
    /// stub that logs its arguments and exits `systemctl_exit`.
    fn run_uninstall(unit_present: bool, systemctl_exit: i32) -> (Option<i32>, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let log = root.join("systemctl.log");
        let stub = root.join("systemctl");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\necho \"$*\" >> {}\nexit {systemctl_exit}\n",
                log.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let unit = root.join("fleetd.service");
        if unit_present {
            std::fs::write(&unit, "").unwrap();
        }
        std::fs::write(root.join("fleetd"), "").unwrap();
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(UNINSTALL_SCRIPT)
            .env("FLEETD_UNIT_DIR", root)
            .env("FLEETD_BIN_DIR", root)
            .env("FLEETD_ENV_FILE", root.join("fleetd.env"))
            .env("FLEETD_STATE_DIR", root.join("state"))
            .env("FLEETD_SYSTEMCTL", &stub)
            .output()
            .unwrap();
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        let still_there = if unit.exists() {
            "unit kept"
        } else {
            "unit removed"
        };
        (
            output.status.code(),
            format!("{}{}", String::from_utf8_lossy(&output.stderr), still_there),
            calls,
        )
    }

    /// Runs `uninstall.sh --purge` with the unit present and a `systemctl`
    /// that succeeds, against the state directory `state`, which the
    /// closure prepares. Answers the exit code, stderr, and whether the unit
    /// file is still there.
    fn run_purge(
        state: impl FnOnce(&std::path::Path) -> std::path::PathBuf,
    ) -> (Option<i32>, String, bool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let stub = root.join("systemctl");
        std::fs::write(&stub, "#!/bin/sh\nexit 0\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let unit = root.join("fleetd.service");
        std::fs::write(&unit, "").unwrap();
        let state_dir = state(root);
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(UNINSTALL_SCRIPT)
            .arg("uninstall.sh")
            .arg("--purge")
            .env("FLEETD_UNIT_DIR", root)
            .env("FLEETD_BIN_DIR", root)
            .env("FLEETD_ENV_FILE", root.join("fleetd.env"))
            .env("FLEETD_STATE_DIR", &state_dir)
            .env("FLEETD_SYSTEMCTL", &stub)
            .output()
            .unwrap();
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
            unit.exists(),
            dir,
        )
    }

    #[test]
    fn a_purge_refuses_a_directory_that_is_not_fleetds_and_removes_nothing() {
        // A populated directory fleetd never wrote (no node.key).
        let (code, stderr, unit_kept, dir) = run_purge(|root| {
            let foreign = root.join("home-alice");
            std::fs::create_dir(&foreign).unwrap();
            std::fs::write(foreign.join("thesis.tex"), "years of work").unwrap();
            foreign
        });
        assert_ne!(code, Some(0), "{stderr}");
        assert!(stderr.contains("node.key"), "{stderr}");
        assert!(stderr.contains("nothing was removed"), "{stderr}");
        assert!(unit_kept, "the refusal comes before anything is removed");
        assert!(dir.path().join("home-alice/thesis.tex").exists());

        // A symbolic link, even to a real fleetd state directory.
        let (code, stderr, unit_kept, dir) = run_purge(|root| {
            let real = root.join("real-state");
            std::fs::create_dir(&real).unwrap();
            std::fs::write(real.join("node.key"), "key").unwrap();
            let link = root.join("state-link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            link
        });
        assert_ne!(code, Some(0), "{stderr}");
        assert!(stderr.contains("symbolic link"), "{stderr}");
        assert!(unit_kept);
        assert!(dir.path().join("real-state/node.key").exists());

        // A system directory (owned by root, and on the denylist).
        let (code, stderr, unit_kept, _dir) = run_purge(|_| "/var/lib".into());
        assert_ne!(code, Some(0), "{stderr}");
        assert!(stderr.contains("refusing to purge"), "{stderr}");
        assert!(unit_kept);
        assert!(std::path::Path::new("/var/lib").is_dir());
    }

    #[test]
    fn a_purge_removes_fleetds_own_state_and_an_empty_directory() {
        let (code, stderr, unit_kept, dir) = run_purge(|root| {
            let state = root.join("state");
            std::fs::create_dir(&state).unwrap();
            for name in ["node.key", "credential", "machine-id", "journal.ndjson"] {
                std::fs::write(state.join(name), "x").unwrap();
            }
            state
        });
        assert_eq!(code, Some(0), "{stderr}");
        assert!(!unit_kept);
        assert!(!dir.path().join("state").exists());

        let (code, stderr, _, dir) = run_purge(|root| {
            let state = root.join("state");
            std::fs::create_dir(&state).unwrap();
            state
        });
        assert_eq!(code, Some(0), "{stderr}");
        assert!(!dir.path().join("state").exists());
    }

    #[test]
    fn the_install_refuses_to_adopt_a_foreign_or_linked_state_directory() {
        const INSTALL_SCRIPT: &str = include_str!("../../../deploy/fleetd/install.sh");
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir(root.join("archive")).unwrap();
        std::fs::write(root.join("archive/fleetd.service"), "").unwrap();
        std::fs::write(root.join("archive/fleetd"), "#!/bin/sh\nexit 0\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                root.join("archive/fleetd"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let foreign = root.join("foreign");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::write(foreign.join("data"), "not fleetd's").unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&foreign, &link).unwrap();
        for (state, why) in [(&foreign, "not fleetd's"), (&link, "symbolic link")] {
            let output = std::process::Command::new("bash")
                .arg("-c")
                .arg(INSTALL_SCRIPT)
                .arg(root.join("archive/install.sh"))
                .env("FLEETD_ARCHIVE_DIR", root.join("archive"))
                .env("FLEETD_STATE_DIR", state)
                .env("FLEETD_BIN_DIR", root.join("bin"))
                .env("FLEETD_UNIT_DIR", root.join("unit"))
                .env("FLEETD_ENV_FILE", root.join("env"))
                .env("FLEETD_SYSTEMCTL", "/bin/true")
                .env("FLEETD_USER_ADD", "/bin/true")
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_ne!(output.status.code(), Some(0), "{stderr}");
            assert!(stderr.contains(why), "{stderr}");
            assert!(
                !root.join("bin").exists(),
                "nothing was installed: {stderr}"
            );
        }
        assert!(foreign.join("data").exists());
    }

    #[test]
    fn an_active_service_without_its_unit_is_not_removed() {
        // systemctl answers 0 to everything, so `is-active` says active.
        let (code, stderr, calls) = run_uninstall(false, 0);
        assert_ne!(code, Some(0), "{stderr}");
        assert!(stderr.contains("still active"), "{stderr}");
        assert!(calls.contains("is-active"), "{calls}");
    }

    #[test]
    fn a_service_that_cannot_be_stopped_is_not_removed() {
        let (code, stderr, calls) = run_uninstall(true, 1);
        assert_ne!(code, Some(0), "{stderr}");
        assert!(stderr.contains("cannot stop and disable"), "{stderr}");
        assert!(stderr.ends_with("unit kept"), "{stderr}");
        assert!(calls.contains("disable --now fleetd"), "{calls}");
    }

    #[test]
    fn an_absent_unit_is_not_stopped_and_a_present_one_is() {
        let (code, stderr, calls) = run_uninstall(false, 1);
        assert_eq!(code, Some(0), "{stderr}");
        assert!(!calls.contains("disable"), "{calls}");
        let (code, stderr, calls) = run_uninstall(true, 0);
        assert_eq!(code, Some(0), "{stderr}");
        assert!(calls.contains("disable --now fleetd"), "{calls}");
        assert!(stderr.ends_with("unit removed"), "{stderr}");
    }

    #[test]
    fn the_shipped_script_runs_with_purge() {
        assert!(UNINSTALL_SCRIPT.contains("systemctl"));
        assert!(UNINSTALL_SCRIPT.contains("--purge"));
        assert_eq!(UNINSTALL_ARGUMENTS, ["--purge"]);
    }

    #[test]
    fn a_clean_exit_answers_the_last_line() {
        let outcome = result(
            Some(0),
            "uninstall: something\nuninstall: service removed and state purged; the next install enrolls fresh\n",
            "",
            false,
        );
        assert_eq!(
            interpret(&outcome).unwrap(),
            "uninstall: service removed and state purged; the next install enrolls fresh"
        );
    }

    #[test]
    fn a_failed_exit_is_a_failure_with_the_first_line() {
        let outcome = result(
            Some(1),
            "",
            "uninstall: cannot remove /etc/systemd/system/fleetd.service\nmore\n",
            false,
        );
        let error = interpret(&outcome).unwrap_err();
        assert!(error.contains("exited 1"), "{error}");
        assert!(error.contains("cannot remove"), "{error}");
        assert!(!error.contains("more"), "{error}");
    }

    #[test]
    fn a_killed_run_is_a_failure() {
        let outcome = result(None, "", "", true);
        assert!(interpret(&outcome).unwrap_err().contains("unknown"));
    }

    #[test]
    fn output_is_scrubbed_and_bounded() {
        let long = "x".repeat(1000);
        let outcome = result(
            Some(2),
            "",
            &format!("https://user:hunter2hunter2@example.invalid/ {long}"),
            false,
        );
        let error = interpret(&outcome).unwrap_err();
        assert!(!error.contains("hunter2hunter2"), "{error}");
        assert!(error.len() < 400, "{}", error.len());
    }
}
