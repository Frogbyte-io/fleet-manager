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

use fleet_application::authz::ActingPrincipal;
use fleet_application::machine::MachinePort;
use fleet_application::node::Nodes;
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

/// How long the post-connect inventory verification waits for the node's
/// facts.
pub const INVENTORY_VERIFY_MILLIS: i64 = 120_000;

/// The bounded payload for the inventory command's result.
pub const INVENTORY_RESULT_BYTES: u32 = 64 * 1024;

/// The payload of a `machine.install-fleetd` operation, as validated JSON.
///
/// Two modes share this shape. **Explicit** (FM-211): the caller supplies
/// `artifactUrl` and `artifactSha256`. **Auto** (FM-212's orchestrated
/// upgrade): both are omitted and the executor selects the artifact from the
/// controller's store against the machine's own facts, requires
/// `controllerUrl`, and — once the session connects — verifies the node's
/// inventory before completing.
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
    /// Where the service archive downloads from. Explicit mode; absent in
    /// auto mode, where the executor builds it from `controllerUrl`.
    pub artifact_url: Option<String>,
    /// The archive's expected sha256. Explicit mode; the executor computes
    /// it from the store in auto mode. An unverified package never installs.
    pub artifact_sha256: Option<String>,
    /// The controller base URL the daemon connects to. Derived from the
    /// artifact URL's origin when absent; required in auto mode.
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
    gateway: Arc<crate::gateway::GatewayService>,
    provider: SshProvider,
    limiter: Arc<ExecutionLimiter>,
    /// The controller's artifact store; auto mode reads the service package
    /// from here. Absent in most tests, which supply explicit artifacts.
    artifacts_dir: Option<std::path::PathBuf>,
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
        gateway: Arc<crate::gateway::GatewayService>,
        work_dir: std::path::PathBuf,
        limiter: Arc<ExecutionLimiter>,
        artifacts_dir: Option<std::path::PathBuf>,
        fallback: Arc<dyn OperationExecutor>,
    ) -> Self {
        let provider = SshProvider::new(work_dir).expect("the SSH work dir must prepare");
        Self {
            machines,
            nodes,
            gateway,
            provider,
            limiter,
            artifacts_dir,
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

        // Artifact resolution: explicit mode carries url + digest; auto mode
        // selects both from the controller's store against the machine's
        // own facts. Anything in between is a malformed request.
        let (artifact_url, artifact_sha256, artifact_name) = match (
            &payload.artifact_url,
            &payload.artifact_sha256,
        ) {
            (Some(url), Some(digest)) => (url.clone(), digest.clone(), None),
            (None, None) => {
                let controller_url = payload.controller_url.clone().ok_or_else(|| {
                    "controllerUrl is required for the orchestrated install".to_owned()
                })?;
                operations
                    .record_progress(
                        &operation.id,
                        Some(0),
                        Some(3),
                        Some("selecting the service package"),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let (name, digest) = self.select_artifact(&payload.machine_id).await?;
                (
                    format!("{controller_url}/downloads/fleetd/{name}"),
                    digest,
                    Some(name),
                )
            }
            _ => {
                return fail_operation(
                        operations,
                        &operation.id,
                        "invalid_request",
                        "supply artifactUrl and artifactSha256 together, or neither for the orchestrated install",
                    )
                    .await;
            }
        };
        let controller_url = payload
            .controller_url
            .clone()
            .unwrap_or_else(|| origin_of(&artifact_url));

        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(3),
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
                        Some(3),
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
                Some(3),
                Some(&format!("installing on {host}")),
            )
            .await
            .map_err(|error| error.to_string())?;

        let deadline = Duration::from_secs(payload.timeout_seconds.min(MAX_INSTALL_TIMEOUT));
        if let Err(detail) = self
            .run_install_script(
                &spec,
                &script,
                &artifact_url,
                &artifact_sha256,
                &payload,
                deadline,
            )
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
        if let Err(detail) = self
            .wait_until_connected(&payload.machine_id, wait_seconds)
            .await
        {
            return fail_operation(operations, &operation.id, "node_did_not_connect", &detail)
                .await;
        }

        // FM-212's verification: a connected node must also report facts.
        operations
            .record_progress(
                &operation.id,
                Some(2),
                Some(3),
                Some("verifying the node's inventory"),
            )
            .await
            .map_err(|error| error.to_string())?;
        match self
            .verify_inventory(operations, &operation.id, &payload.machine_id)
            .await
        {
            Ok(facts) => {
                let result_json = serde_json::json!({
                    "connected": true,
                    "machineId": payload.machine_id,
                    "controllerUrl": controller_url,
                    "artifact": artifact_name,
                    "inventoryFacts": facts,
                })
                .to_string();
                operations
                    .complete(&operation.id, "succeeded", Some(&result_json), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            Err(detail) => {
                fail_operation(operations, &operation.id, "inventory_unverified", &detail).await
            }
        }
    }

    /// Selects the service package for one machine from the controller's
    /// artifact store: the machine's own facts name the platform, and the
    /// store must hold an archive for it. The digest comes from the archive
    /// bytes themselves; the node re-verifies after download.
    async fn select_artifact(&self, machine_id: &str) -> Result<(String, String), String> {
        let dir = self.artifacts_dir.as_ref().ok_or_else(|| {
            "the controller has no artifact store configured; supply artifactUrl and artifactSha256 explicitly".to_owned()
        })?;
        let machine = self
            .machines
            .get(machine_id)
            .await
            .map_err(|failure| format!("the machine is unreadable: {failure}"))?;
        let fact = |namespace: &str, name: &str| -> Option<String> {
            machine
                .capabilities
                .iter()
                .find(|candidate| {
                    candidate.namespace == namespace
                        && candidate.name == name
                        && candidate.value.is_some()
                        && matches!(
                            candidate.status,
                            fleet_core::CapabilityStatus::Known
                                | fleet_core::CapabilityStatus::Stale
                        )
                })
                .and_then(|candidate| candidate.value.clone())
        };
        let family = fact("os", "family");
        if !family
            .as_deref()
            .is_some_and(|family| family.eq_ignore_ascii_case("linux"))
        {
            return Err(format!(
                "the automated install supports linux; this machine reports os.family = {family:?}. \
                 Discover the machine again, or supply artifactUrl and artifactSha256 explicitly"
            ));
        }
        let Some(architecture) = fact("host", "architecture") else {
            return Err(
                "the machine's architecture is unknown; discover the machine first, or supply artifactUrl and artifactSha256 explicitly".to_owned(),
            );
        };
        let platform = match architecture.as_str() {
            "x86_64" | "amd64" => "linux-x86_64",
            "aarch64" | "arm64" => "linux-aarch64",
            other => {
                return Err(format!(
                    "the automated install supports x86_64 and aarch64; this machine reports {other:?}.                      Supply artifactUrl and artifactSha256 explicitly"
                ));
            }
        };
        // The store may accumulate several versions; the highest version
        // string wins. Names are `fleetd-<version>-<platform>.tar.gz`.
        let suffix = format!("-{platform}.tar.gz");
        let mut candidates: Vec<String> = match std::fs::read_dir(dir.join("fleetd")) {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().to_string())
                .filter(|name| name.starts_with("fleetd-") && name.ends_with(&suffix))
                .collect(),
            Err(error) => {
                return Err(format!("the artifact store is unreadable: {error}"));
            }
        };
        candidates.sort();
        let Some(archive) = candidates.pop() else {
            return Err(format!(
                "no fleetd package for {platform} in the controller's artifact store;                  the supported platforms are x86_64 and aarch64 on linux"
            ));
        };
        let path = dir.join("fleetd").join(&archive);
        let digest = file_sha256(&path)
            .map_err(|error| format!("the artifact {archive} is unreadable: {error}"))?;
        Ok((archive, digest))
    }

    /// Dispatches one `node.inventory` command through the live session and
    /// requires facts with fleetd provenance on the machine afterwards.
    async fn verify_inventory(
        &self,
        operations: &Operations,
        operation_id: &str,
        machine_id: &str,
    ) -> Result<usize, String> {
        let deadline = fleet_core::SystemClock::now_unix_millis() + INVENTORY_VERIFY_MILLIS;
        let command = fleet_protocol::wire::Command {
            operation_id: operation_id.to_owned(),
            kind: "node.inventory".to_owned(),
            kind_schema_version: 1,
            deadline_unix_millis: deadline,
            idempotency_key: format!("{operation_id}-inventory"),
            authorization_digest: String::new(),
            max_output_bytes: INVENTORY_RESULT_BYTES,
            cancellation: fleet_protocol::wire::CancellationPolicy::BestEffort as i32,
            payload: serde_json::to_vec(&serde_json::json!({ "expectedRevision": null }))
                .unwrap_or_default(),
        };
        let dispatch = self.gateway.dispatch(machine_id, command);
        let outcome = tokio::time::timeout(
            Duration::from_millis(u64::try_from(INVENTORY_VERIFY_MILLIS).unwrap_or(u64::MAX)),
            dispatch,
        )
        .await;
        self.gateway.release(machine_id);
        let result = match outcome {
            Ok(outcome) => {
                outcome.map_err(|error| format!("the inventory command failed: {error}"))?
            }
            Err(_) => {
                return Err(
                    "the node did not answer the inventory request within the bound; \
                     the install itself succeeded — retry inventory later"
                        .to_owned(),
                );
            }
        };
        let succeeded = fleet_protocol::wire::ResultStatus::try_from(result.status)
            .map(|status| status == fleet_protocol::wire::ResultStatus::Succeeded)
            .unwrap_or(false);
        if !succeeded {
            return Err(format!(
                "the node refused the inventory request: {}",
                String::from_utf8_lossy(&result.payload)
            ));
        }
        let facts = crate::gateway::ingest_inventory_report(
            self.machines.as_ref(),
            machine_id,
            &result.payload,
        )
        .await?;
        if facts == 0 {
            return Err(
                "the node reported an empty inventory; check the service's journal".to_owned(),
            );
        }
        operations
            .record_progress(
                operation_id,
                Some(3),
                Some(3),
                Some(&format!("verified: the node reported {facts} facts")),
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(facts)
    }

    /// Runs the generated install script over the provider's transport. The
    /// working directory is a fresh temp dir; the script cleans up after
    /// itself.
    async fn run_install_script(
        &self,
        spec: &fleet_provider_ssh::SshConnectionSpec,
        script: &str,
        artifact_url: &str,
        artifact_sha256: &str,
        payload: &InstallPayload,
        deadline: Duration,
    ) -> Result<(), String> {
        let metadata = fleet_provider_ssh::ScriptMetadata {
            working_directory: String::new(),
            environment: vec![
                ("FLEET_ARTIFACT_URL".to_owned(), artifact_url.to_owned()),
                (
                    "FLEET_ARTIFACT_SHA256".to_owned(),
                    artifact_sha256.to_owned(),
                ),
                (
                    "FLEET_CONTROLLER_URL".to_owned(),
                    payload
                        .controller_url
                        .clone()
                        .unwrap_or_else(|| origin_of(artifact_url)),
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

    /// Polls the LIVE session registry until the machine has an open
    /// gateway session, bounded by the wait. The persisted `gateway_state`
    /// is a cache that survives controller restarts; only the registry
    /// answers "is this session open right now", which is what the
    /// inventory dispatch will rely on.
    async fn wait_until_connected(
        &self,
        machine_id: &str,
        wait_seconds: u64,
    ) -> Result<(), String> {
        let deadline = std::time::Instant::now() + Duration::from_secs(wait_seconds);
        loop {
            if self.gateway.session_of(machine_id).await.is_some() {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "the service did not reach a connected gateway session within {wait_seconds}s; \
                     the install itself may have succeeded — check 'systemctl status fleetd' on the \
                     node, then retry this install (it is idempotent), or revoke and reinstall"
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

/// The archive's sha256, computed on the controller so auto mode can hand
/// the node an authoritative digest. The node re-verifies after download.
fn file_sha256(path: &std::path::Path) -> Result<String, String> {
    use sha2::{Digest as _, Sha256};
    let bytes =
        std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        }))
}
