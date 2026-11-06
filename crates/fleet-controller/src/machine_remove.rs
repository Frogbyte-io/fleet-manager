//! The controller side of removing a machine (#616): the fleetd uninstall
//! over SSH, and the composition of the removal use case.
//!
//! The uninstall is the shipped `deploy/fleetd/uninstall.sh`, run with
//! `--purge` (the machine's node identity is deleted with it, so the state
//! the script would keep could never be used again). It rides SSH stdin like
//! the install script, over the endpoint's confirmed host key and the
//! authentication the review bound; it touches nothing else on the machine.
//! Its output is scrubbed and cut to one line before anything records it.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fleet_application::machine::MachinePort;
use fleet_application::machine_access::EndpointAuth;
use fleet_application::machine_remove::{FleetdUninstall, FleetdUninstallPort};
use fleet_provider_ssh::{ExecutionLimiter, SshAuth, SshProvider};

use crate::exec::resolve_ssh_endpoint;
use crate::machine_access::SshAuthResolver;

/// The shipped uninstall script, delivered over SSH stdin.
pub const UNINSTALL_SCRIPT: &str = include_str!("../../../deploy/fleetd/uninstall.sh");

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
            environment: Vec::new(),
            arguments: UNINSTALL_ARGUMENTS
                .iter()
                .map(|arg| (*arg).to_owned())
                .collect(),
        };
        let provider = self.provider.clone();
        let limiter = self.limiter.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            fleet_provider_ssh::execute_script(
                &provider,
                &limiter,
                &spec,
                UNINSTALL_SCRIPT,
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

/// Composes the removal use case over the store: the delete through the
/// machine use cases (which revoke the machine's bound keys when `keys` is
/// given), the hold checks, the USB gate, the SSH trust store in the
/// controller's SSH work directory, the endpoints' stored authentication, and
/// the uninstall.
///
/// # Errors
///
/// Fails when the SSH work directory cannot be prepared.
pub fn compose(
    pool: &sqlx::SqlitePool,
    ssh_work_dir: std::path::PathBuf,
    keys: Option<Arc<dyn fleet_application::machine_access::MachineKeyPort>>,
    resolver: Option<Arc<SshAuthResolver>>,
) -> Result<fleet_application::machine_remove::MachineRemoval, String> {
    let records: Arc<dyn MachinePort> =
        Arc::new(fleet_storage_sqlite::MachineRepository::new(pool.clone()));
    let audit = Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone()));
    let machines = fleet_application::machine::Machines::new(records.clone(), audit.clone());
    let machines = match keys {
        Some(keys) => machines.with_key_revocation(keys),
        None => machines,
    };
    let uninstaller = SshFleetdUninstaller::new(
        records.clone(),
        ssh_work_dir.clone(),
        ExecutionLimiter::new(2),
        resolver,
    )?;
    Ok(fleet_application::machine_remove::MachineRemoval::new(
        Arc::new(machines),
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
        audit,
    )
    .with_endpoint_auth(Arc::new(fleet_storage_sqlite::EndpointAuthRepository::new(
        pool.clone(),
    )))
    .with_uninstaller(Arc::new(uninstaller)))
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
