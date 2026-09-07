//! The node-install executor: the audited SSH bootstrap operation that turns
//! an agentless machine into a managed one (FM-211).
//!
//! `machine.install-fleetd` is the whole "Install Fleet Node" bootstrap in
//! one durable operation: verify the endpoint's trust, mint a single-use
//! enrollment token, download and checksum-verify the service package on the
//! node, install the hardened systemd service, enroll the node, start the
//! service, and wait — bounded — for the gateway session to reach
//! `connected` before the operation succeeds.
//!
//! Two properties carry the security weight of this issue:
//!
//! 1. **The enrollment token leaves no reusable trace.** The executor mints
//!    the token in memory and embeds it *in the script text*, which rides
//!    ssh stdin and is invisible to the remote process list (the metadata
//!    blob that is in argv carries no token). The script pipes it to
//!    `fleetd enroll --token-stdin`; nothing writes it to remote disk, and
//!    the token is consumed server-side at enroll. The operation's payload,
//!    result, and error JSON never contain it.
//! 2. **Failed installs leave the agentless endpoint usable.** The install
//!    script cleans up its own partial work, and this executor only ever
//!    adds the node surface — the machine's SSH endpoints, facts, and
//!    trust state are untouched, so an inventory probe still works after a
//!    failed install (tested).
//!
//! The token is minted through the authorized `Nodes::create_token` use case
//! acting as the trusted-LAN principal: the worker is trusted infrastructure
//! acting on operations callers already created, and minting is part of that
//! work — the use case's own authorization funnel and audit event record it.
//! There is deliberately no path that skips the funnel.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use fleet_application::authz::{ActingPrincipal, Permission};
use fleet_application::machine::MachinePort;
use fleet_application::node::{GatewayState, Nodes};
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_provider_ssh::{ExecutionLimiter, SshAuth, SshProvider};

use crate::exec::resolve_ssh_endpoint;

/// The lifetime of the minted enrollment token: long enough to survive a
/// queue behind other SSH work, short enough that a leaked copy dies on its
/// own.
pub const INSTALL_TOKEN_TTL_MILLIS: i64 = 10 * 60 * 1000;

/// The default bound on waiting for the node's gateway session after the
/// service starts.
pub const DEFAULT_CONNECT_WAIT_SECONDS: u64 = 60;

/// The hard bound on the connect wait.
pub const MAX_CONNECT_WAIT_SECONDS: u64 = 300;

/// The hard bound on the whole install script.
pub const MAX_INSTALL_TIMEOUT: u64 = 900;

/// The payload of a `machine.install-fleetd` operation, as validated JSON.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallPayload {
    /// The machine gaining the node.
    pub machine_id: String,
    /// The SSH endpoint the bootstrap runs over.
    pub endpoint_id: String,
    /// How the controller authenticates to the endpoint.
    pub auth: InstallAuth,
    /// The whole-install deadline, in seconds. Bounded hard.
    pub timeout_seconds: u64,
    /// Where the service archive downloads from, e.g. the controller's own
    /// `/downloads/fleetd/...`.
    pub artifact_url: String,
    /// The archive's expected sha256. Mandatory: an unverified package
    /// never installs.
    pub artifact_sha256: String,
    /// The controller base URL the daemon connects to. Derived from the
    /// artifact URL's origin when absent.
    pub controller_url: Option<String>,
    /// How long to wait for the gateway session, in seconds.
    pub connect_wait_seconds: Option<u64>,
    /// Extra environment for the installer, e.g. the layout overrides
    /// (`FLEETD_STATE_DIR`, `FLEETD_SYSTEMCTL`, …) containers and tests use.
    /// Never carries secrets: this rides the argv-visible metadata blob.
    #[serde(default)]
    pub installer_env: Vec<(String, String)>,
}

/// How the endpoint authenticates; mirrors the ssh.exec payload's shape so
/// callers treat every SSH surface the same way.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum InstallAuth {
    /// The controller's agent supplies the key.
    Agent,
    /// A specific identity file.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// The kind-dispatching install executor.
#[derive(Debug)]
pub struct InstallExecutor {
    machines: Arc<dyn MachinePort>,
    nodes: Arc<Nodes>,
    provider: SshProvider,
    limiter: Arc<ExecutionLimiter>,
    fallback: Arc<dyn OperationExecutor>,
}

impl InstallExecutor {
    /// Composes the executor from its parts. The provider's isolated
    /// directory must be the controller's SSH work directory, so the trust
    /// workflow's pins serve the install exactly like any other SSH work.
    ///
    /// # Panics
    ///
    /// Panics only if the SSH work directory cannot be prepared, which the
    /// store's own data-directory preparation already ensures.
    #[must_use]
    pub fn new(
        machines: Arc<dyn MachinePort>,
        nodes: Arc<Nodes>,
        work_dir: std::path::PathBuf,
        limiter: Arc<ExecutionLimiter>,
        fallback: Arc<dyn OperationExecutor>,
    ) -> Self {
        let provider = SshProvider::new(work_dir).expect("the SSH work dir must prepare");
        Self {
            machines,
            nodes,
            provider,
            limiter,
            fallback,
        }
    }
}

#[async_trait]
impl OperationExecutor for InstallExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "machine.install-fleetd" => self.execute_install(operations, operation).await,
            _ => self.fallback.execute(operations, operation).await,
        }
    }
}

impl InstallExecutor {
    async fn execute_install(
        &self,
        operations: &Operations,
        operation: &Operation,
    ) -> Result<(), String> {
        let payload: InstallPayload = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a valid install record: {error}"))?;
        let auth = match &payload.auth {
            InstallAuth::Agent => SshAuth::Agent,
            InstallAuth::IdentityFile { path } => SshAuth::IdentityFile { path: path.clone() },
        };
        let (spec, _verified, host) = resolve_ssh_endpoint(
            self.machines.as_ref(),
            &payload.machine_id,
            &payload.endpoint_id,
            auth,
        )
        .await?;
        let controller_url = payload
            .controller_url
            .clone()
            .unwrap_or_else(|| origin_of(&payload.artifact_url));

        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(2),
                Some(&format!("checking node trust for {host}")),
            )
            .await
            .map_err(|error| error.to_string())?;

        // The node's existing identity decides the enrollment mode: none
        // means first enrollment, a revoked identity means a forced
        // re-enrollment (the installer wipes the stale node state first),
        // and a live identity means a plain upgrade — no token is minted
        // and none is needed, because the installer re-proves the same key.
        let principal = ActingPrincipal {
            id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        };
        let view = self
            .nodes
            .node_view(
                &fleet_auth::LanAllowAllAuthorizer,
                &principal,
                &payload.machine_id,
            )
            .await
            .map_err(|error| format!("the node view is unavailable: {error}"))?;
        let enrollment = match view.identity.as_ref() {
            None => Enrollment::First,
            Some(identity) => match identity.status {
                fleet_application::node::NodeStatus::Revoked => Enrollment::Forced,
                fleet_application::node::NodeStatus::Active => Enrollment::Upgrade,
            },
        };

        let token = match enrollment {
            Enrollment::Upgrade => None,
            Enrollment::First | Enrollment::Forced => {
                operations
                    .record_progress(
                        &operation.id,
                        Some(0),
                        Some(2),
                        Some(&format!("minting an enrollment token for {host}")),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                // The token is minted through the authorized use case and
                // lives only in this step's memory: it goes into the script
                // text (ssh stdin), never into argv, the payload, or any
                // file.
                let minted = self
                    .nodes
                    .create_token(
                        &fleet_auth::LanAllowAllAuthorizer,
                        &principal,
                        &payload.machine_id,
                        Some(INSTALL_TOKEN_TTL_MILLIS),
                    )
                    .await
                    .map_err(|error| {
                        format!("the enrollment token could not be minted: {error}")
                    })?;
                Some(minted.token)
            }
        };

        let script = install_script(token.as_deref(), enrollment == Enrollment::Forced);
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(2),
                Some(&format!("installing on {host}")),
            )
            .await
            .map_err(|error| error.to_string())?;

        let deadline = Duration::from_secs(payload.timeout_seconds.min(MAX_INSTALL_TIMEOUT));
        if let Err(detail) = self
            .run_install_script(&spec, &script, &payload, deadline)
            .await
        {
            return fail_operation(operations, &operation.id, "install_failed", &detail).await;
        }

        let wait_seconds = payload
            .connect_wait_seconds
            .unwrap_or(DEFAULT_CONNECT_WAIT_SECONDS)
            .min(MAX_CONNECT_WAIT_SECONDS);
        operations
            .record_progress(
                &operation.id,
                Some(1),
                Some(2),
                Some(&format!(
                    "installed; waiting for the node's gateway session (≤{wait_seconds}s)"
                )),
            )
            .await
            .map_err(|error| error.to_string())?;
        match self
            .wait_until_connected(&payload.machine_id, wait_seconds)
            .await
        {
            Ok(()) => {
                let result_json = serde_json::json!({
                    "connected": true,
                    "machineId": payload.machine_id,
                    "controllerUrl": controller_url,
                })
                .to_string();
                operations
                    .complete(&operation.id, "succeeded", Some(&result_json), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            Err(detail) => {
                fail_operation(operations, &operation.id, "node_did_not_connect", &detail).await
            }
        }
    }

    /// Runs the generated install script over the provider's transport. The
    /// working directory is a fresh temp dir; the script cleans up after
    /// itself.
    async fn run_install_script(
        &self,
        spec: &fleet_provider_ssh::SshConnectionSpec,
        script: &str,
        payload: &InstallPayload,
        deadline: Duration,
    ) -> Result<(), String> {
        let metadata = fleet_provider_ssh::ScriptMetadata {
            working_directory: String::new(),
            environment: vec![
                (
                    "FLEET_ARTIFACT_URL".to_owned(),
                    payload.artifact_url.clone(),
                ),
                (
                    "FLEET_ARTIFACT_SHA256".to_owned(),
                    payload.artifact_sha256.clone(),
                ),
                (
                    "FLEET_CONTROLLER_URL".to_owned(),
                    payload
                        .controller_url
                        .clone()
                        .unwrap_or_else(|| origin_of(&payload.artifact_url)),
                ),
            ]
            .into_iter()
            .chain(payload.installer_env.clone())
            .collect(),
            arguments: Vec::new(),
        };
        let provider = self.provider.clone();
        let limiter = self.limiter.clone();
        let spec = spec.clone();
        let script = script.to_owned();
        let outcome = tokio::task::spawn_blocking(move || {
            fleet_provider_ssh::execute_script(
                &provider, &limiter, &spec, &script, &metadata, deadline,
            )
        })
        .await
        .unwrap_or_else(|join_error| {
            Err(fleet_provider_ssh::SshProviderError::Tool {
                tool: "ssh",
                detail: format!("the install thread failed: {join_error}"),
            })
        });
        let result = outcome.map_err(|error| error.to_string())?;
        if result.killed_by_deadline {
            return Err(
                "the local ssh process was killed at the deadline; the remote install's fate is unknown"
                    .to_owned(),
            );
        }
        if result.exit_code != Some(0) {
            return Err(format!(
                "the install script exited {}: {}",
                result
                    .exit_code
                    .map_or_else(|| "with no exit code".to_owned(), |code| code.to_string()),
                first_lines(&result.stderr, &result.stdout),
            ));
        }
        Ok(())
    }

    /// Polls the node view until the machine's gateway session reports
    /// connected, bounded by the wait.
    async fn wait_until_connected(
        &self,
        machine_id: &str,
        wait_seconds: u64,
    ) -> Result<(), String> {
        let deadline = std::time::Instant::now() + Duration::from_secs(wait_seconds);
        let principal = ActingPrincipal {
            id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        };
        loop {
            let view = self
                .nodes
                .node_view(&fleet_auth::LanAllowAllAuthorizer, &principal, machine_id)
                .await
                .map_err(|error| format!("the node view is unavailable: {error}"))?;
            let connected = view
                .identity
                .as_ref()
                .is_some_and(|identity| identity.gateway_state == GatewayState::Connected);
            if connected {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "the service did not reach a connected gateway session within {wait_seconds}s; \
                     the install itself may have succeeded — inspect the machine's node surface"
                ));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

/// The enrollment mode the existing node identity implies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Enrollment {
    /// No identity yet: mint a token and enroll.
    First,
    /// The identity was revoked: mint a token and force a re-enrollment over
    /// the stale local state.
    Forced,
    /// A live identity exists: upgrade only, no token, no enrollment.
    Upgrade,
}

/// The install script. The enrollment token, when there is one, is
/// interpolated into the script text — stdin-delivered, never argv — and
/// piped straight into `fleetd enroll --token-stdin` by install.sh. The
/// download and its digest are verified before anything executes.
fn install_script(token: Option<&str>, force_enroll: bool) -> String {
    let token_line = token
        .map(|token| format!("export FLEET_ENROLL_TOKEN={token}\n"))
        .unwrap_or_default();
    let force_line = if force_enroll {
        "export FLEET_FORCE_ENROLL=1\n"
    } else {
        ""
    };
    format!(
        r#"set -eu
STAMP="$(mktemp -d /tmp/fleetd-install.XXXXXX)"
trap 'rm -rf "$STAMP"' EXIT
curl -fsSL --max-time 120 -o "$STAMP/fleetd-pkg.tar.gz" "$FLEET_ARTIFACT_URL"
echo "$FLEET_ARTIFACT_SHA256  $STAMP/fleetd-pkg.tar.gz" | sha256sum -c - >/dev/null 2>&1 \
  || {{ echo "the downloaded package does not match its digest; refusing to install"; exit 40; }}
tar -xzf "$STAMP/fleetd-pkg.tar.gz" -C "$STAMP"
{force_line}{token_line}bash "$STAMP/install.sh"
unset FLEET_ENROLL_TOKEN FLEET_FORCE_ENROLL
"#
    )
}

/// The controller base URL of an artifact URL: scheme plus authority.
fn origin_of(artifact_url: &str) -> String {
    let (scheme, rest) = artifact_url
        .split_once("://")
        .unwrap_or(("http", artifact_url));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    format!("{scheme}://{authority}")
}

/// The first informative line of remote output for a failure detail.
fn first_lines(stderr: &str, stdout: &str) -> String {
    let pick = |text: &str| -> Option<String> {
        text.lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(|line| {
                if line.len() > 300 {
                    format!("{}…", &line[..300])
                } else {
                    line.to_owned()
                }
            })
    };
    pick(stderr)
        .or_else(|| pick(stdout))
        .unwrap_or_else(|| "no remote output".to_owned())
}

/// Completes an operation as a failed step with a bounded, honest reason.
async fn fail_operation(
    operations: &Operations,
    operation_id: &str,
    reason: &str,
    detail: &str,
) -> Result<(), String> {
    let error_json = serde_json::json!({ "reason": reason, "detail": detail }).to_string();
    operations
        .complete(operation_id, "failed", None, Some(&error_json))
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// The permission this operation's *creation* implies; minting runs through
/// the authorized use case. Kept here as the executor's own documentation of
/// the gate it relies on.
#[allow(dead_code)]
const IMPLIED_PERMISSION: Permission = Permission::NodeEnroll;
