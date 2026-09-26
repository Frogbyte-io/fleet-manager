//! The Skills Manager executor (FM-302): probe, deploy, and undeploy
//! through the documented `skills-manager-cli --json` contract, over the
//! bounded SSH transport.
//!
//! The transport rule from the provider holds in full: the CLI's name is
//! fixed, and every caller-controlled value — skill ids, agent ids, an
//! external skills root — rides the base64 metadata blob as positional
//! arguments, never through a remote shell. A version probe runs first on
//! every kind: a CLI outside the tested range, or one that answers in an
//! undocumented shape, degrades explicitly to `unsupported_version`
//! instead of guessing.
//!
//! Deploy and undeploy are audited durable operations with bounded
//! output; `--dry-run` is preserved when the caller supplied it, never
//! silently upgraded to a real mutation. Secrets never ride arguments,
//! output, or audit: the result path redacts before anything becomes
//! public.
//!
//! Install with checksum verification: the probe payload may pin a
//! release (URL, sha256, version range); the fixed script verifies the
//! digest before placing the binary and refuses a mismatch loudly.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use fleet_application::machine::MachinePort;
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_provider_ssh::{ExecutionLimiter, ScriptMetadata, SshConnectionSpec};

use crate::exec::{MAX_SCRIPT_TIMEOUT, resolve_ssh_endpoint};

/// The version gate's outcome, typed so each failure keeps its own public
/// reason.
#[derive(Debug)]
enum GateOutcome {
    /// The CLI is present, identified, and within the tested range.
    Pass,
    /// The CLI is absent: the machine answered, the tool is not there.
    Absent,
    /// The CLI answered but not in the documented shape, or its version
    /// is outside the tested range.
    Unsupported {
        /// The caller-safe detail.
        detail: String,
    },
    /// The transport failed before the CLI could answer.
    Connection {
        /// The redacted detail.
        detail: String,
    },
    /// The deadline killed the gate.
    Deadline,
}

/// The exact CLI version the read contract fixtures were recorded against.
/// Other versions degrade explicitly until fixtures are refreshed.
pub const TESTED_CLI_VERSION: &str = "1.40.0";

/// The deadline bound for one skills operation.
pub const MAX_SKILLS_TIMEOUT: u64 = MAX_SCRIPT_TIMEOUT;

/// How the endpoint authenticates.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
enum Auth {
    /// The controller's agent supplies the key.
    Agent,
    /// A specific identity file.
    IdentityFile {
        /// The identity file's path.
        path: String,
    },
}

/// The `skills.probe` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProbePayload {
    machine_id: String,
    endpoint_id: String,
    auth: Auth,
    /// An external skills root to probe against, when one is named.
    #[serde(default)]
    skills_root: Option<String>,
    /// An optional pinned release to install when the CLI is absent:
    /// the download URL.
    #[serde(default)]
    artifact_url: Option<String>,
    /// The pinned release's expected sha256.
    #[serde(default)]
    artifact_sha256: Option<String>,
    timeout_seconds: u64,
}

/// The `skills.deploy` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeployPayload {
    machine_id: String,
    endpoint_id: String,
    auth: Auth,
    /// The skill to deploy.
    skill_id: String,
    /// The agents to deploy to, as documented ids.
    agents: Vec<String>,
    /// An external skills root, when the deployment targets one.
    #[serde(default)]
    skills_root: Option<String>,
    /// Preserve a caller's dry run: never upgraded to a real mutation.
    #[serde(default)]
    dry_run: bool,
    timeout_seconds: u64,
}

/// The `skills.undeploy` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct UndeployPayload {
    machine_id: String,
    endpoint_id: String,
    auth: Auth,
    skill_id: String,
    agents: Vec<String>,
    #[serde(default)]
    skills_root: Option<String>,
    #[serde(default)]
    dry_run: bool,
    timeout_seconds: u64,
}

/// Payload for versioned Skills Manager library and preset mutations.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
struct LibraryPayload {
    machine_id: String,
    endpoint_id: String,
    auth: Auth,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    source_url: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    git_subpath: Option<String>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    local: bool,
    #[serde(default)]
    git: bool,
    #[serde(default)]
    sync: bool,
    #[serde(default)]
    sync_preset: Option<String>,
    #[serde(default)]
    force: bool,
    #[serde(default)]
    agents: Vec<String>,
    #[serde(default)]
    skills_root: Option<String>,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    confirm: bool,
    timeout_seconds: u64,
}

/// Payload for one immutable catalog version rollout.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CatalogRolloutPayload {
    machine_id: String,
    endpoint_id: String,
    auth: Auth,
    catalog_id: String,
    version_id: String,
    agents: Vec<String>,
    timeout_seconds: u64,
}

/// The kind-dispatching skills executor.
pub struct SkillsExecutor {
    machines: Arc<dyn MachinePort>,
    provider: fleet_provider_ssh::SshProvider,
    limiter: Arc<ExecutionLimiter>,
    snapshots: Option<Arc<dyn fleet_application::skills::SkillsPort>>,
    catalog: Option<Arc<dyn fleet_application::skill_catalog::SkillCatalogPort>>,
    /// Retained for the provider's isolated directory lifetime.
    #[allow(dead_code)]
    work_dir: std::path::PathBuf,
}

impl std::fmt::Debug for SkillsExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkillsExecutor").finish_non_exhaustive()
    }
}

impl SkillsExecutor {
    async fn catalog_target(
        &self,
        payload: &CatalogRolloutPayload,
    ) -> Result<(SshConnectionSpec, Duration), (&'static str, String)> {
        let budget = deadline(payload.timeout_seconds);
        let started = Instant::now();
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await
            .map_err(|detail| ("connection_failed", detail))?;
        let gate_budget = budget.saturating_sub(started.elapsed());
        if gate_budget.is_zero() {
            return Err((
                "deadline_killed",
                "the catalog rollout reached its deadline while resolving the machine".to_owned(),
            ));
        }
        match self.version_gate(&spec, gate_budget).await {
            GateOutcome::Pass => {}
            GateOutcome::Absent => {
                return Err((
                    "cli_absent",
                    "skills-manager-cli is not installed".to_owned(),
                ));
            }
            GateOutcome::Unsupported { detail } => return Err(("unsupported_version", detail)),
            GateOutcome::Connection { detail } => return Err(("connection_failed", detail)),
            GateOutcome::Deadline => {
                return Err((
                    "deadline_killed",
                    "the Skills Manager version gate exceeded its deadline".to_owned(),
                ));
            }
        }
        let remaining = budget.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err((
                "deadline_killed",
                "the catalog rollout reached its deadline during the version gate".to_owned(),
            ));
        }
        Ok((spec, remaining))
    }

    async fn catalog_rollout(
        &self,
        operations: &Operations,
        operation: &Operation,
    ) -> Result<(), String> {
        let payload: CatalogRolloutPayload = payload(operation)?;
        if payload.agents.is_empty() || payload.agents.len() > 32 {
            return complete_failure(
                operations,
                &operation.id,
                "invalid_request",
                "a catalog rollout requires 1..=32 explicit agents",
            )
            .await;
        }
        for agent in &payload.agents {
            validate_id(agent, "an agent id")?;
        }
        let Some(catalog) = &self.catalog else {
            return complete_failure(
                operations,
                &operation.id,
                "catalog_unavailable",
                "the Fleet skill catalog storage is not wired",
            )
            .await;
        };
        let version = match catalog.get_version(&payload.version_id).await {
            Ok(version) => version,
            Err(_) => {
                return complete_failure(
                    operations,
                    &operation.id,
                    "catalog_version_missing",
                    "the pinned catalog version is unavailable",
                )
                .await;
            }
        };
        let digest = version.content.validate_and_digest()?;
        if digest != version.content_digest
            || version.content.name != version.name
            || version.catalog_id != payload.catalog_id
        {
            return complete_failure(
                operations,
                &operation.id,
                "catalog_digest_mismatch",
                "the pinned catalog version failed its content integrity check",
            )
            .await;
        }
        if let fleet_core::SkillCatalogSource::Referenced {
            reference,
            subpath,
            revision,
        } = &version.content.source
        {
            let install_reference =
                match catalog_install_reference(reference, subpath.as_deref(), revision.as_deref())
                {
                    Ok(reference) => reference,
                    Err(detail) => {
                        return complete_failure(
                            operations,
                            &operation.id,
                            "unsupported_source_pin",
                            &detail,
                        )
                        .await;
                    }
                };
            let (spec, remaining) = match self.catalog_target(&payload).await {
                Ok(target) => target,
                Err((code, detail)) => {
                    return complete_failure(operations, &operation.id, code, &detail).await;
                }
            };
            let is_git = reference.starts_with("https://")
                || reference.starts_with("ssh://")
                || reference.ends_with(".git");
            let mut args = vec![
                version.name.clone(),
                install_reference,
                if is_git {
                    "true".to_owned()
                } else {
                    "false".to_owned()
                },
                payload.agents.len().to_string(),
            ];
            args.extend(payload.agents.iter().cloned());
            let metadata = ScriptMetadata {
                working_directory: String::new(),
                environment: Vec::new(),
                arguments: args,
            };
            let (result, detail) = self
                .run(&spec, &referenced_rollout_script(), &metadata, remaining)
                .await;
            return finish_cli(
                operations,
                &operation.id,
                result,
                detail,
                "referenced catalog rollout",
            )
            .await;
        }
        let (spec, remaining) = match self.catalog_target(&payload).await {
            Ok(target) => target,
            Err((code, detail)) => {
                return complete_failure(operations, &operation.id, code, &detail).await;
            }
        };
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(3),
                Some("staging the pinned Fleet skill version"),
            )
            .await
            .map_err(|e| e.to_string())?;
        let mut arguments = vec![
            version.name.clone(),
            version.content_digest.clone(),
            version.content.files.len().to_string(),
        ];
        for file in &version.content.files {
            let digest = sha256_hex(file.content.as_bytes());
            arguments.push(file.path.clone());
            arguments
                .push(base64::engine::general_purpose::STANDARD.encode(file.content.as_bytes()));
            arguments.push(digest);
        }
        arguments.push(payload.agents.len().to_string());
        arguments.extend(payload.agents.iter().cloned());
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment: Vec::new(),
            arguments,
        };
        let (result, detail) = self
            .run(&spec, &catalog_rollout_script(), &metadata, remaining)
            .await;
        finish_cli(operations, &operation.id, result, detail, "catalog rollout").await
    }

    /// Composes the executor from its parts.
    ///
    /// # Panics
    ///
    /// Panics only if the SSH work directory cannot be prepared, which the
    /// store's own data-directory preparation already ensures.
    #[must_use]
    pub fn new(
        machines: Arc<dyn MachinePort>,
        work_dir: std::path::PathBuf,
        limiter: Arc<ExecutionLimiter>,
    ) -> Self {
        let provider = fleet_provider_ssh::SshProvider::new(work_dir.clone())
            .expect("the SSH work dir must prepare");
        Self {
            machines,
            provider,
            limiter,
            snapshots: None,
            catalog: None,
            work_dir,
        }
    }

    /// Attach durable storage for normalized skill observations.
    #[must_use]
    pub fn with_snapshot_port(
        mut self,
        snapshots: Arc<dyn fleet_application::skills::SkillsPort>,
    ) -> Self {
        self.snapshots = Some(snapshots);
        self
    }

    /// Attach immutable catalog storage for authored skill rollouts.
    #[must_use]
    pub fn with_catalog_port(
        mut self,
        catalog: Arc<dyn fleet_application::skill_catalog::SkillCatalogPort>,
    ) -> Self {
        self.catalog = Some(catalog);
        self
    }

    async fn resolve(
        &self,
        machine_id: &str,
        endpoint_id: &str,
        auth: &Auth,
    ) -> Result<SshConnectionSpec, String> {
        let ssh_auth = match auth {
            Auth::Agent => fleet_provider_ssh::SshAuth::Agent,
            Auth::IdentityFile { path } => {
                fleet_provider_ssh::SshAuth::IdentityFile { path: path.clone() }
            }
        };
        let (spec, _verified, _host) =
            resolve_ssh_endpoint(self.machines.as_ref(), machine_id, endpoint_id, ssh_auth).await?;
        Ok(spec)
    }

    async fn run(
        &self,
        spec: &SshConnectionSpec,
        script: &str,
        metadata: &ScriptMetadata,
        deadline: Duration,
    ) -> (Option<fleet_provider_ssh::ExecutionResult>, Option<String>) {
        let provider = self.provider.clone();
        let limiter = self.limiter.clone();
        let spec = spec.clone();
        let script = script.to_owned();
        let metadata = metadata.clone();
        tokio::task::spawn_blocking(move || {
            fleet_provider_ssh::execute_script(
                &provider, &limiter, &spec, &script, &metadata, deadline,
            )
        })
        .await
        .map_or_else(
            |join_error| {
                (
                    None,
                    Some(format!("the execution thread failed: {join_error}")),
                )
            },
            |outcome| match outcome {
                Ok(result) => (Some(result), None),
                Err(error) => (None, Some(error.to_string())),
            },
        )
    }
}

#[async_trait::async_trait]
impl OperationExecutor for SkillsExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "skills.probe" => self.probe(operations, operation).await,
            "skills.deploy" => self.deploy(operations, operation).await,
            "skills.undeploy" => self.undeploy(operations, operation).await,
            "skills.catalog-rollout" => self.catalog_rollout(operations, operation).await,
            "skills.install"
            | "skills.update"
            | "skills.check"
            | "skills.remove"
            | "skills.adopt"
            | "skills.set-source"
            | "presets.create"
            | "presets.update"
            | "presets.delete"
            | "presets.add-skill"
            | "presets.remove-skill"
            | "presets.deploy"
            | "presets.undeploy" => self.library_operation(operations, operation).await,
            _ => Err("not a skills kind".to_owned()),
        }
    }
}

impl SkillsExecutor {
    async fn library_operation(
        &self,
        operations: &Operations,
        operation: &Operation,
    ) -> Result<(), String> {
        let payload: LibraryPayload = payload(operation)?;
        let action = operation.kind.as_str();
        let missing_required = match action {
            "skills.install" => payload.reference.is_none(),
            "skills.remove" => payload.reference.is_none() && payload.references.is_empty(),
            "skills.adopt" => payload.path.is_none() && payload.paths.is_empty(),
            "skills.set-source" => payload.reference.is_none() || payload.source_url.is_none(),
            "presets.create" | "presets.update" | "presets.delete" | "presets.deploy"
            | "presets.undeploy" => payload.reference.is_none(),
            "presets.add-skill" | "presets.remove-skill" => {
                payload.reference.is_none() || payload.path.is_none()
            }
            _ => false,
        };
        if missing_required {
            return complete_failure(
                operations,
                &operation.id,
                "invalid_request",
                "the selected operation is missing a required reference or path",
            )
            .await;
        }
        if payload.force && action != "skills.set-source" {
            return complete_failure(
                operations,
                &operation.id,
                "invalid_request",
                "force is supported only for skills.set-source",
            )
            .await;
        }
        if action == "presets.create" && payload.name.is_some() {
            return complete_failure(
                operations,
                &operation.id,
                "invalid_request",
                "presets.create uses reference as its name; name is only valid for update",
            )
            .await;
        }
        if matches!(action, "skills.remove" | "presets.delete") && !payload.confirm {
            return complete_failure(
                operations,
                &operation.id,
                "confirmation_required",
                "explicit confirmation is required for removal",
            )
            .await;
        }
        if payload.dry_run
            && !matches!(
                action,
                "skills.remove"
                    | "skills.adopt"
                    | "skills.set-source"
                    | "presets.deploy"
                    | "presets.undeploy"
                    | "presets.delete"
            )
        {
            return complete_failure(
                operations,
                &operation.id,
                "unsupported_dry_run",
                "the pinned CLI does not support dry-run for this operation",
            )
            .await;
        }
        if let Some(url) = payload.source_url.as_deref()
            && url_has_userinfo(url)
        {
            return complete_failure(
                operations,
                &operation.id,
                "invalid_source",
                "credential-bearing or malformed source URLs are not accepted",
            )
            .await;
        }
        if let Some(reference) = payload.reference.as_deref() {
            if url_has_userinfo(reference) {
                return complete_failure(
                    operations,
                    &operation.id,
                    "invalid_source",
                    "credential-bearing source URLs are not accepted",
                )
                .await;
            }
            validate_id(reference, "the skill or preset reference")?;
        }
        if payload.local && payload.git {
            return complete_failure(
                operations,
                &operation.id,
                "invalid_request",
                "install source flags --local and --git are mutually exclusive",
            )
            .await;
        }
        if payload.sync && payload.sync_preset.is_some() {
            return complete_failure(
                operations,
                &operation.id,
                "invalid_request",
                "install sync options are mutually exclusive",
            )
            .await;
        }
        for (label, value) in [
            ("name", payload.name.as_deref()),
            ("description", payload.description.as_deref()),
            ("icon", payload.icon.as_deref()),
            ("sync preset", payload.sync_preset.as_deref()),
            ("Git subpath", payload.git_subpath.as_deref()),
            ("branch", payload.branch.as_deref()),
        ] {
            if value.is_some_and(|value| value.chars().any(char::is_control)) {
                return complete_failure(
                    operations,
                    &operation.id,
                    "invalid_request",
                    &format!("{label} must not contain control characters"),
                )
                .await;
            }
        }
        if let Some(path) = payload.path.as_deref()
            && (path.is_empty() || path.starts_with('-') || path.chars().any(char::is_control))
        {
            return complete_failure(operations, &operation.id, "invalid_request", "paths must be non-empty, must not start with a dash, and must not contain control characters").await;
        }
        if action == "presets.update"
            && payload.name.is_none()
            && payload.description.is_none()
            && payload.icon.is_none()
        {
            return complete_failure(
                operations,
                &operation.id,
                "invalid_request",
                "preset update needs at least one changed field",
            )
            .await;
        }
        for reference in &payload.references {
            if url_has_userinfo(reference) {
                return complete_failure(
                    operations,
                    &operation.id,
                    "invalid_source",
                    "credential-bearing source URLs are not accepted",
                )
                .await;
            }
            validate_id(reference, "a skill reference")?;
        }
        if payload.paths.iter().any(|path| {
            path.is_empty() || path.starts_with('-') || path.chars().any(char::is_control)
        }) {
            return complete_failure(
                operations,
                &operation.id,
                "invalid_request",
                "adoption paths must be non-empty and contain no control characters",
            )
            .await;
        }
        for agent in &payload.agents {
            validate_id(agent, "an agent id")?;
        }
        if let Some(root) = payload.skills_root.as_deref() {
            validate_root(root)?;
        }
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        let operation_deadline = deadline(payload.timeout_seconds);
        match self.version_gate(&spec, operation_deadline).await {
            GateOutcome::Pass => {}
            GateOutcome::Absent => {
                return complete_failure(
                    operations,
                    &operation.id,
                    "cli_absent",
                    "skills-manager-cli is not installed",
                )
                .await;
            }
            GateOutcome::Unsupported { detail } => {
                return complete_failure(operations, &operation.id, "unsupported_version", &detail)
                    .await;
            }
            GateOutcome::Connection { detail } => {
                return complete_failure(operations, &operation.id, "connection_failed", &detail)
                    .await;
            }
            GateOutcome::Deadline => return complete_failure(
                operations,
                &operation.id,
                "deadline_killed",
                "the version gate was killed at its deadline; the machine's skill state is unknown",
            )
            .await,
        }
        let mut arguments = Vec::new();
        match action {
            "skills.adopt" => {
                if let Some(path) = payload.path {
                    arguments.push(path);
                }
                arguments.extend(payload.paths);
            }
            "skills.set-source" => {
                if let Some(reference) = payload.reference {
                    arguments.push(reference);
                }
                if let Some(url) = payload.source_url.as_ref() {
                    arguments.push(url.clone());
                }
                if let Some(path) = payload.path {
                    arguments.push(path);
                }
                if let Some(branch) = payload.branch {
                    arguments.push(branch);
                }
            }
            "presets.add-skill" | "presets.remove-skill" => {
                if let Some(reference) = payload.reference {
                    arguments.push(reference);
                }
                if let Some(path) = payload.path {
                    arguments.push(path);
                }
            }
            "presets.deploy" | "presets.undeploy" => {
                if let Some(reference) = payload.reference {
                    arguments.push(reference);
                }
                arguments.extend(payload.agents);
            }
            "skills.remove" => {
                if let Some(reference) = payload.reference {
                    arguments.push(reference);
                }
                arguments.extend(payload.references);
            }
            _ => {
                if let Some(reference) = payload.reference {
                    arguments.push(reference);
                }
            }
        }
        let script = library_script(action, payload.dry_run, payload.confirm, payload.force);
        let mut environment = root_environment(payload.skills_root.as_deref());
        for (key, value) in [
            ("FLEET_INSTALL_LOCAL", payload.local.then(|| "1".to_owned())),
            ("FLEET_INSTALL_GIT", payload.git.then(|| "1".to_owned())),
            ("FLEET_INSTALL_SYNC", payload.sync.then(|| "1".to_owned())),
            ("FLEET_INSTALL_NAME", payload.name.clone()),
            ("FLEET_INSTALL_SYNC_PRESET", payload.sync_preset.clone()),
            ("FLEET_PRESET_NAME", payload.name),
            ("FLEET_PRESET_DESCRIPTION", payload.description),
            ("FLEET_PRESET_ICON", payload.icon),
            ("FLEET_ADOPT_GIT_URL", payload.source_url.clone()),
            ("FLEET_ADOPT_GIT_SUBPATH", payload.git_subpath),
        ] {
            if let Some(value) = value {
                environment.push((key.to_owned(), value));
            }
        }
        if payload.force {
            environment.push(("FLEET_SOURCE_FORCE".to_owned(), "1".to_owned()));
        }
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment,
            arguments,
        };
        let (result, detail) = self
            .run(&spec, &script, &metadata, operation_deadline)
            .await;
        finish_cli(operations, &operation.id, result, detail, action).await
    }

    async fn probe(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: ProbePayload = payload(operation)?;
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        operations
            .record_progress(&operation.id, Some(0), Some(1), Some("probing the CLI"))
            .await
            .map_err(|error| error.to_string())?;
        let deadline = deadline(payload.timeout_seconds);
        // A pinned release installs when the CLI is absent; the fixed
        // script verifies the digest before placing the binary.
        // A partial pin is refused before anything runs: a silent unpinned
        // probe would pretend the caller's intent was honored.
        if payload.artifact_url.is_some() != payload.artifact_sha256.is_some() {
            return Err("the pinned release requires both an artifact URL and a sha256".to_owned());
        }
        let pinned = payload
            .artifact_url
            .as_deref()
            .zip(payload.artifact_sha256.as_deref());
        if let Some((url, sha256)) = &pinned {
            if url.is_empty() || sha256.is_empty() {
                return Err(
                    "the pinned release requires both an artifact URL and a sha256".to_owned(),
                );
            }
            // The URL rides the metadata's NUL-framed environment; control
            // characters cannot break the framing but would smuggle fields.
            if url_has_userinfo(url) {
                return Err(
                    "credential-bearing or malformed artifact URLs are not accepted".to_owned(),
                );
            }
            if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("the artifact sha256 must be 64 hex characters".to_owned());
            }
        }
        // The pin rides the environment (absent means no pin) because the
        // prologue drops empty positional arguments; the root rides $1.
        let mut environment = Vec::new();
        if let Some((url, sha256)) = &pinned {
            environment.push(("FLEET_PIN_URL".to_owned(), (*url).to_owned()));
            environment.push(("FLEET_PIN_SHA256".to_owned(), (*sha256).to_owned()));
        }
        let arguments: Vec<String> = match &payload.skills_root {
            Some(root) => {
                validate_root(root)?;
                vec![root.clone()]
            }
            None => Vec::new(),
        };
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment,
            arguments,
        };
        let (result, detail) = self.run(&spec, &probe_script(), &metadata, deadline).await;
        match (result, detail) {
            (Some(result), _) if result.killed_by_deadline => {
                complete_failure(
                    operations,
                    &operation.id,
                    "deadline_killed",
                    "the probe was killed at its deadline; the CLI's state is unknown",
                )
                .await
            }
            (Some(result), _) if result.exit_code == Some(0) => {
                if result.truncated_stdout {
                    return complete_failure(
                        operations,
                        &operation.id,
                        "inventory_too_large",
                        "the bounded skills inventory response was truncated; the previous observation was retained",
                    )
                    .await;
                }
                let parsed: Option<serde_json::Value> = result
                    .stdout
                    .lines()
                    .find_map(|line| serde_json::from_str(line).ok());
                // An empty or non-conforming answer is an unsupported CLI,
                // not a success with a null probe.
                let Some(parsed) = parsed else {
                    return complete_failure(
                        operations,
                        &operation.id,
                        "unsupported_version",
                        "the CLI's probe did not answer in the documented shape",
                    )
                    .await;
                };
                if let Some(reason) = parsed["installFailed"].as_str() {
                    let (code, detail) = match reason {
                        "checksum_mismatch" => (
                            "checksum_mismatch",
                            "the pinned Skills Manager checksum did not match",
                        ),
                        "download_failed" => (
                            "install_failed",
                            "the pinned Skills Manager artifact could not be downloaded",
                        ),
                        _ => (
                            "install_failed",
                            "the pinned Skills Manager binary could not be installed",
                        ),
                    };
                    return complete_failure(operations, &operation.id, code, detail).await;
                }
                if parsed["inventoryTooLarge"].as_bool() == Some(true) {
                    return complete_failure(operations, &operation.id, "inventory_too_large", "the Skills Manager inventory exceeds the bounded probe response; the previous observation was retained").await;
                }
                let Some(snapshot) = normalize_probe(&payload.machine_id, &parsed) else {
                    return complete_failure(
                        operations,
                        &operation.id,
                        "unsupported_version",
                        "the CLI's skills contract did not answer in the documented shape",
                    )
                    .await;
                };
                if let Some(port) = &self.snapshots {
                    port.record(&snapshot)
                        .await
                        .map_err(|_| "skills snapshot persistence failed".to_owned())?;
                }
                // Operation results are readable with operations.read. Keep
                // the sensitive inventory behind the skills.read endpoints.
                let result_json = serde_json::json!({
                    "snapshotRecorded": self.snapshots.is_some(),
                    "availability": match snapshot.availability {
                        fleet_application::skills::SkillsAvailability::Available => "available",
                        fleet_application::skills::SkillsAvailability::Absent => "absent",
                        fleet_application::skills::SkillsAvailability::Unsupported => "unsupported",
                    },
                    "observedAt": snapshot.observed_at,
                })
                .to_string();
                operations
                    .complete(&operation.id, "succeeded", Some(&result_json), None)
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
            (Some(result), _) => {
                complete_failure(
                    operations,
                    &operation.id,
                    "probe_failed",
                    &redact_output(&result.stderr),
                )
                .await
            }
            (None, Some(detail)) => {
                complete_failure(operations, &operation.id, "connection_failed", &detail).await
            }
            (None, None) => Err("the probe produced neither a result nor a detail".to_owned()),
        }
    }

    async fn deploy(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: DeployPayload = payload(operation)?;
        validate_id(&payload.skill_id, "the skill id")?;
        for agent in &payload.agents {
            validate_id(agent, "an agent id")?;
        }
        if let Some(root) = &payload.skills_root {
            validate_root(root)?;
        }
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        // The version gate runs before every mutation: an untested CLI
        // degrades explicitly instead of guessing. One deadline covers
        // the gate and the mutation together.
        let operation_deadline = deadline(payload.timeout_seconds);
        match self.version_gate(&spec, operation_deadline).await {
            GateOutcome::Pass => {}
            GateOutcome::Absent => {
                return complete_failure(
                    operations,
                    &operation.id,
                    "cli_absent",
                    "skills-manager-cli is not installed",
                )
                .await;
            }
            GateOutcome::Unsupported { detail } => {
                return complete_failure(operations, &operation.id, "unsupported_version", &detail)
                    .await;
            }
            GateOutcome::Connection { detail } => {
                return complete_failure(operations, &operation.id, "connection_failed", &detail)
                    .await;
            }
            GateOutcome::Deadline => {
                return complete_failure(
                    operations,
                    &operation.id,
                    "deadline_killed",
                    "the version gate was killed at its deadline; the machine's skill state is unknown",
                )
                .await;
            }
        }
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!(
                    "deploying {} to {} agent(s){}",
                    payload.skill_id,
                    payload.agents.len(),
                    if payload.dry_run { " (dry run)" } else { "" },
                )),
            )
            .await
            .map_err(|error| error.to_string())?;
        // The CLI is resolved off-PATH by the fixed script; the skill id
        // and every agent id stay separate positional parameters, and the
        // skills root rides the environment.
        let mut arguments = vec![payload.skill_id.clone()];
        arguments.extend(payload.agents.iter().cloned());
        let script = if payload.dry_run {
            mutation_script("deploy", true)
        } else {
            mutation_script("deploy", false)
        };
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment: root_environment(payload.skills_root.as_deref()),
            arguments,
        };
        let (result, detail) = self
            .run(&spec, &script, &metadata, operation_deadline)
            .await;
        finish_cli(operations, &operation.id, result, detail, "deploy").await
    }

    async fn undeploy(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: UndeployPayload = payload(operation)?;
        validate_id(&payload.skill_id, "the skill id")?;
        for agent in &payload.agents {
            validate_id(agent, "an agent id")?;
        }
        if let Some(root) = &payload.skills_root {
            validate_root(root)?;
        }
        let spec = self
            .resolve(&payload.machine_id, &payload.endpoint_id, &payload.auth)
            .await?;
        // The version gate runs before every mutation.
        let operation_deadline = deadline(payload.timeout_seconds);
        match self.version_gate(&spec, operation_deadline).await {
            GateOutcome::Pass => {}
            GateOutcome::Absent => {
                return complete_failure(
                    operations,
                    &operation.id,
                    "cli_absent",
                    "skills-manager-cli is not installed",
                )
                .await;
            }
            GateOutcome::Unsupported { detail } => {
                return complete_failure(operations, &operation.id, "unsupported_version", &detail)
                    .await;
            }
            GateOutcome::Connection { detail } => {
                return complete_failure(operations, &operation.id, "connection_failed", &detail)
                    .await;
            }
            GateOutcome::Deadline => {
                return complete_failure(
                    operations,
                    &operation.id,
                    "deadline_killed",
                    "the version gate was killed at its deadline; the machine's skill state is unknown",
                )
                .await;
            }
        }
        operations
            .record_progress(
                &operation.id,
                Some(0),
                Some(1),
                Some(&format!(
                    "undeploying {} from {} agent(s){}",
                    payload.skill_id,
                    payload.agents.len(),
                    if payload.dry_run { " (dry run)" } else { "" },
                )),
            )
            .await
            .map_err(|error| error.to_string())?;
        let mut arguments = vec![payload.skill_id.clone()];
        arguments.extend(payload.agents.iter().cloned());
        let script = mutation_script("undeploy", payload.dry_run);
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment: root_environment(payload.skills_root.as_deref()),
            arguments,
        };
        let (result, detail) = self
            .run(&spec, &script, &metadata, operation_deadline)
            .await;
        finish_cli(operations, &operation.id, result, detail, "undeploy").await
    }

    /// The version gate shared by every kind: the CLI must identify
    /// itself in a documented shape with a version at or below the tested
    /// one. A failure names the reason; `None` means the gate passed.
    async fn version_gate(&self, spec: &SshConnectionSpec, deadline: Duration) -> GateOutcome {
        let metadata = ScriptMetadata {
            working_directory: String::new(),
            environment: Vec::new(),
            arguments: Vec::new(),
        };
        let script = r#"for fleet_candidate in "$HOME/.local/bin/skills-manager-cli" "$(command -v skills-manager-cli 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
if [ -z "${fleet_cli:-}" ]; then
  echo '{"present":false,"reason64":"'$(printf '%s' "skills-manager-cli is not installed" | base64 -w0)'"}'
  exit 0
fi
fleet_version=$("$fleet_cli" --version 2>/dev/null | head -n 1)
printf '{"version64":"%s"}\n' "$(printf '%s' "$fleet_version" | base64 -w0)"
"#
        .to_owned();
        let (result, detail) = self.run(spec, &script, &metadata, deadline).await;
        let Some(result) = result else {
            return GateOutcome::Connection {
                detail: detail.unwrap_or_else(|| "the gate produced no result".to_owned()),
            };
        };
        if result.killed_by_deadline {
            return GateOutcome::Deadline;
        }
        if result.exit_code != Some(0) {
            return GateOutcome::Connection {
                detail: redact_output(&result.stderr),
            };
        }
        // Parse the gate's answer; a malformed answer is an unsupported
        // CLI, not a pass.
        let parsed: Option<serde_json::Value> = result
            .stdout
            .lines()
            .find_map(|line| serde_json::from_str(line).ok());
        let Some(parsed) = parsed else {
            return GateOutcome::Unsupported {
                detail: "the CLI's version gate did not answer in the documented shape".to_owned(),
            };
        };
        if parsed["present"].as_bool() == Some(false) {
            return GateOutcome::Absent;
        }
        // The documented version shapes: the provider's JSON document or
        // the bare `skills-manager-cli <version>` line, both base64'd by
        // the gate script.
        let version = decoded_field(&parsed, "version64");
        let Some(version) = version else {
            return GateOutcome::Unsupported {
                detail: "the CLI did not report a version in the documented shape".to_owned(),
            };
        };
        let Some(version) = parse_version_text(&version) else {
            return GateOutcome::Unsupported {
                detail: "the CLI did not report a version in the documented shape".to_owned(),
            };
        };
        if !version_acceptable(&version) {
            return GateOutcome::Unsupported {
                detail: format!(
                    "the CLI reports {version}, but the tested contract version is exactly {TESTED_CLI_VERSION}"
                ),
            };
        }
        GateOutcome::Pass
    }
}

/// The fixed probe script: presence, version, and the agent listing, as
/// one JSON line with base64 values. An absent CLI reports honestly.
fn probe_script() -> String {
    r#"fleet_b64() { printf '%s' "$1" | base64 -w0; }
fleet_emit_absent() {
  printf '{"present":false}\n'
}
fleet_emit_failure() {
  printf '{"installFailed":"%s"}\n' "$1"
}
# Resolve the managed copy or a service-account PATH copy.
for fleet_candidate in "$HOME/.local/bin/skills-manager-cli" "$(command -v skills-manager-cli 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
fleet_root=$1
if [ -z "${fleet_cli:-}" ] && [ -n "${FLEET_PIN_URL:-}" ] && [ -n "${FLEET_PIN_SHA256:-}" ]; then
  fleet_tmp=$(mktemp) || { fleet_emit_failure download_failed; exit 0; }
  trap 'rm -f "$fleet_tmp"' EXIT
  curl -fsSL --max-time 120 -o "$fleet_tmp" "$FLEET_PIN_URL" || { fleet_emit_failure download_failed; exit 0; }
  fleet_digest=$(sha256sum "$fleet_tmp" | awk '{print $1}')
  if [ "$fleet_digest" != "$FLEET_PIN_SHA256" ]; then fleet_emit_failure checksum_mismatch; exit 0; fi
  chmod +x "$fleet_tmp"
  mkdir -p "$HOME/.local/bin" || { fleet_emit_failure install_failed; exit 0; }
  mv "$fleet_tmp" "$HOME/.local/bin/skills-manager-cli" || { fleet_emit_failure install_failed; exit 0; }
  fleet_cli="$HOME/.local/bin/skills-manager-cli"
fi
if [ -z "${fleet_cli:-}" ]; then fleet_emit_absent; exit 0; fi
fleet_version_output=$("$fleet_cli" --version 2>/dev/null | head -n 1)
if [ -z "$fleet_version_output" ]; then printf '{"present":true,"unidentified":true}\n'; exit 0; fi
case "$fleet_version_output" in
  '{'*) fleet_version=$(printf '%s' "$fleet_version_output" | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p') ;;
  *) fleet_version=$fleet_version_output ;;
esac
if [ -z "$fleet_version" ]; then printf '{"present":true,"unidentified":true}\n'; exit 0; fi
fleet_version64=$(fleet_b64 "$fleet_version")
case "$fleet_version" in
  'skills-manager-cli 1.40.0'|'1.40.0') fleet_version='1.40.0'; fleet_version64=$(fleet_b64 "$fleet_version") ;;
  *) printf '{"present":true,"version64":"%s","unsupportedVersion":true}\n' "$fleet_version64"; exit 0 ;;
esac
fleet_json() {
  if [ -n "$fleet_root" ]; then "$fleet_cli" --skills-root "$fleet_root" --json "$@"; else "$fleet_cli" --json "$@"; fi
}
# Keep temporary upstream documents private and bounded. The EXIT trap
# removes them on normal remote exit; a local SSH deadline cannot guarantee
# that the remote process exits, so an interrupted command can leave a file.
fleet_tmp=$(mktemp) || { printf '{"present":true,"version64":"%s","inventoryFailed":true}\n' "$fleet_version64"; exit 0; }
trap 'rm -f "$fleet_tmp"' EXIT
fleet_collect() {
  fleet_max=$1; shift
  : > "$fleet_tmp" || return 1
  fleet_json "$@" > "$fleet_tmp" 2>/dev/null || return 1
  fleet_bytes=$(wc -c < "$fleet_tmp")
  [ "$fleet_bytes" -le "$fleet_max" ] || return 2
  cat "$fleet_tmp"
}
fleet_agents_status=0; fleet_agents=$(fleet_collect 65536 agents list) || fleet_agents_status=$?
fleet_skills_status=0; fleet_skills=$(fleet_collect 393216 skills list) || fleet_skills_status=$?
fleet_presets_status=0; fleet_presets=$(fleet_collect 65536 presets list) || fleet_presets_status=$?
fleet_checks_status=0; fleet_checks=$(fleet_collect 196608 skills check --all) || fleet_checks_status=$?
if [ "$fleet_agents_status" = 2 ] || [ "$fleet_skills_status" = 2 ] || [ "$fleet_presets_status" = 2 ] || [ "$fleet_checks_status" = 2 ]; then
  printf '{"present":true,"version64":"%s","inventoryTooLarge":true}\n' "$fleet_version64"
  exit 0
fi
printf '{"present":true,"version64":"%s","agents64":"%s","skills64":"%s","presets64":"%s","checks64":"%s","agentsFailed":%s,"skillsFailed":%s,"presetsFailed":%s,"updateCheckFailed":%s}\n' \
  "$fleet_version64" "$(fleet_b64 "${fleet_agents:-[]}")" "$(fleet_b64 "${fleet_skills:-[]}")" "$(fleet_b64 "${fleet_presets:-[]}")" "$(fleet_b64 "${fleet_checks:-[]}")" \
  "$( [ "$fleet_agents_status" = 0 ] && echo false || echo true )" "$( [ "$fleet_skills_status" = 0 ] && echo false || echo true )" "$( [ "$fleet_presets_status" = 0 ] && echo false || echo true )" "$( [ "$fleet_checks_status" = 0 ] && echo false || echo true )"
"#
    .to_owned()
}

fn normalize_probe(
    machine_id: &str,
    raw: &serde_json::Value,
) -> Option<fleet_application::skills::SkillsSnapshot> {
    use fleet_application::skills::{SkillsAvailability, SkillsSnapshot};
    let now = fleet_core::SystemClock::now_unix_millis();
    if raw["present"].as_bool() == Some(false) {
        return Some(SkillsSnapshot {
            machine_id: machine_id.to_owned(),
            availability: SkillsAvailability::Absent,
            cli_version: None,
            data: serde_json::json!({"skills": [], "presets": [], "agents": []}),
            update_check: "unavailable".into(),
            observed_at: now,
        });
    }
    if raw["unidentified"].as_bool() == Some(true) {
        return Some(SkillsSnapshot {
            machine_id: machine_id.to_owned(),
            availability: SkillsAvailability::Unsupported,
            cli_version: None,
            data: serde_json::json!({"skills": [], "presets": [], "agents": []}),
            update_check: "unsupported".into(),
            observed_at: now,
        });
    }
    let version = decoded_field(raw, "version64")?;
    let version = parse_version_text(&version)?;
    if !version_acceptable(&version) {
        return Some(SkillsSnapshot {
            machine_id: machine_id.to_owned(),
            availability: SkillsAvailability::Unsupported,
            cli_version: Some(version),
            data: serde_json::json!({"skills": [], "presets": [], "agents": []}),
            update_check: "unsupported".into(),
            observed_at: now,
        });
    }
    if raw["agentsFailed"].as_bool() == Some(true)
        || raw["skillsFailed"].as_bool() == Some(true)
        || raw["presetsFailed"].as_bool() == Some(true)
    {
        return None;
    }
    let agents: serde_json::Value = serde_json::from_slice(&decode_field(raw, "agents64")?).ok()?;
    let skills: serde_json::Value = serde_json::from_slice(&decode_field(raw, "skills64")?).ok()?;
    let presets: serde_json::Value =
        serde_json::from_slice(&decode_field(raw, "presets64")?).ok()?;
    let checks: serde_json::Value = serde_json::from_slice(&decode_field(raw, "checks64")?).ok()?;
    let agents = agents.as_array()?;
    let skills = skills.as_array()?;
    let presets = presets.as_array()?;
    let checks = if raw["updateCheckFailed"].as_bool() == Some(true) {
        &[][..]
    } else {
        checks.as_array()?.as_slice()
    };
    let mut check_status = std::collections::HashMap::new();
    for check in checks {
        let id = safe_json_text(check.get("skill_id")?, 255)?;
        let status = safe_json_text(check.get("update_status")?, 64)?;
        check_status.insert(id.to_owned(), status.to_owned());
    }
    let normalized_agents = agents
        .iter()
        .map(|agent| {
            let id = safe_json_text(agent.get("id")?, 255)?;
            let name = match agent.get("name") {
                Some(value) => safe_json_text(value, 512)?,
                None => id,
            };
            let installed = optional_bool(agent, "installed", false)?;
            let enabled = optional_bool(agent, "enabled", false)?;
            Some(serde_json::json!({"id": id, "name": name, "installed": installed, "enabled": enabled}))
        })
        .collect::<Option<Vec<_>>>()?;
    let normalized_skills = skills
        .iter()
        .map(|skill| {
            let id = safe_json_text(skill.get("id")?, 255)?;
            let name = safe_json_text(skill.get("name")?, 512)?;
            let enabled = skill.get("enabled")?.as_bool()?;
            let preset_ids = safe_string_array(skill.get("preset_ids")?, 255)?;
            let deployed_to = safe_string_array(skill.get("deployed_to")?, 255)?;
            let update_status = match check_status.get(id).map(String::as_str) {
                Some("update_available") => "update_available",
                Some("up_to_date") => "up_to_date",
                Some("local_only") => "local_only",
                _ => "unknown",
            };
            Some(serde_json::json!({"id": id, "name": name, "enabled": enabled, "presetIds": preset_ids, "deployedTo": deployed_to, "updateStatus": update_status}))
        })
        .collect::<Option<Vec<_>>>()?;
    let normalized_presets = presets
        .iter()
        .map(|preset| {
            let id = safe_json_text(preset.get("id")?, 255)?;
            let name = safe_json_text(preset.get("name")?, 512)?;
            let skill_count = preset.get("skill_count")?.as_u64()?;
            let active = preset.get("active")?.as_bool()?;
            Some(serde_json::json!({"id": id, "name": name, "skillCount": skill_count, "active": active}))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(SkillsSnapshot {
        machine_id: machine_id.to_owned(),
        availability: SkillsAvailability::Available,
        cli_version: Some(version),
        data: serde_json::json!({"skills": normalized_skills, "presets": normalized_presets, "agents": normalized_agents}),
        update_check: if raw["updateCheckFailed"].as_bool() == Some(true) {
            "failed"
        } else {
            "complete"
        }
        .into(),
        observed_at: now,
    })
}

fn safe_json_text(value: &serde_json::Value, max_bytes: usize) -> Option<&str> {
    let text = value.as_str()?;
    (!text.is_empty() && text.len() <= max_bytes && !text.chars().any(char::is_control))
        .then_some(text)
}

fn optional_bool(object: &serde_json::Value, key: &str, default: bool) -> Option<bool> {
    match object.get(key) {
        None => Some(default),
        Some(value) => value.as_bool(),
    }
}

fn safe_string_array(value: &serde_json::Value, max_bytes: usize) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| safe_json_text(item, max_bytes).map(str::to_owned))
        .collect()
}

fn decode_field(value: &serde_json::Value, field: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value.get(field)?.as_str()?)
        .ok()
}

/// The fixed mutation script: `$1` is the skill id, `$2` onwards the
/// agent ids, each kept as a separate positional parameter so an id with
/// spaces or glob characters stays one argument. `FLEET_SKILLS_ROOT`
/// carries an external root when one is named. `--json` is always passed:
/// the completion path parses the CLI's own contract.
#[must_use]
pub fn mutation_script_for_test(verb: &str, dry_run: bool) -> String {
    mutation_script(verb, dry_run)
}

fn mutation_script(verb: &str, dry_run: bool) -> String {
    let dry_run_line: &str = if dry_run { "fleet_dry=--dry-run\n" } else { "" };
    format!(
        r#"for fleet_candidate in "$HOME/.local/bin/skills-manager-cli" "$(command -v skills-manager-cli 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
[ -n "${{fleet_cli:-}}" ] || {{ echo "skills-manager-cli is not installed" >&2; exit 3; }}
{dry_run_line}fleet_root_arg=""
if [ -n "${{FLEET_SKILLS_ROOT:-}}" ]; then
  fleet_root_arg="--skills-root"
fi
# Each agent becomes its own `--agent <id>` pair. The positional
# parameters are rebuilt in place: $1 (the skill id) is saved, then every
# agent is re-set as `--agent <id>` pairs, so each id stays a single
# argument and nothing expands unquoted.
fleet_skill=$1
shift
fleet_agent_args=()
for fleet_agent in "$@"; do
  fleet_agent_args+=("--agent" "$fleet_agent")
done
fleet_dry_args=()
[ -n "${{fleet_dry:-}}" ] && fleet_dry_args+=(--dry-run)
fleet_verb={verb:?}
case "$fleet_verb" in
  deploy)
    if [ -n "$fleet_root_arg" ]; then
      "$fleet_cli" --skills-root "$FLEET_SKILLS_ROOT" --json skills deploy "$fleet_skill" "${{fleet_agent_args[@]}}" "${{fleet_dry_args[@]}}"
    else
      "$fleet_cli" --json skills deploy "$fleet_skill" "${{fleet_agent_args[@]}}" "${{fleet_dry_args[@]}}"
    fi
    ;;
  undeploy)
    if [ -n "$fleet_root_arg" ]; then
      "$fleet_cli" --skills-root "$FLEET_SKILLS_ROOT" --json skills undeploy "$fleet_skill" "${{fleet_agent_args[@]}}" --yes "${{fleet_dry_args[@]}}"
    else
      "$fleet_cli" --json skills undeploy "$fleet_skill" "${{fleet_agent_args[@]}}" --yes "${{fleet_dry_args[@]}}"
    fi
    ;;
esac
"#
    )
}

fn library_script(kind: &str, dry_run: bool, confirm: bool, force: bool) -> String {
    let is_preset = kind.starts_with("presets.");
    let verb = kind.split_once('.').map_or("", |(_, verb)| verb);
    let dry = if dry_run { "--dry-run" } else { "" };
    let yes = if confirm { "--yes" } else { "" };
    let force = if force { "--force" } else { "" };
    let script = r#"for fleet_candidate in "$HOME/.local/bin/skills-manager-cli" "$(command -v skills-manager-cli 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
[ -n "${FLEET_CLI:-}" ] || FLEET_CLI="$fleet_cli"
[ -n "${FLEET_CLI:-}" ] || { echo "skills-manager-cli is not installed" >&2; exit 3; }
fleet_ref=${1:-}; [ "$#" -eq 0 ] || shift
fleet_global=(--json)
if [ -n "${FLEET_SKILLS_ROOT:-}" ]; then fleet_global+=(--skills-root "$FLEET_SKILLS_ROOT"); fi
fleet_dry=(__DRY__)
fleet_yes=(__YES__)
fleet_force=(__FORCE__)
__BODY__
"#;
    let body = match (is_preset, verb) {
        (false, "install") => {
            r#"fleet_install_args=(); [ -z "${FLEET_INSTALL_LOCAL:-}" ] || fleet_install_args+=(--local); [ -z "${FLEET_INSTALL_GIT:-}" ] || fleet_install_args+=(--git); [ -z "${FLEET_INSTALL_NAME:-}" ] || fleet_install_args+=(--name "$FLEET_INSTALL_NAME"); [ -z "${FLEET_INSTALL_SYNC:-}" ] || fleet_install_args+=(--sync); [ -z "${FLEET_INSTALL_SYNC_PRESET:-}" ] || fleet_install_args+=(--sync-preset "$FLEET_INSTALL_SYNC_PRESET"); "$FLEET_CLI" "${fleet_global[@]}" skills install "$fleet_ref" "${fleet_install_args[@]}""#
        }
        (false, "update") => {
            r#"if [ -n "$fleet_ref" ]; then "$FLEET_CLI" "${fleet_global[@]}" skills update "$fleet_ref" "${fleet_dry[@]}"; else "$FLEET_CLI" "${fleet_global[@]}" skills update --all "${fleet_dry[@]}"; fi"#
        }
        (false, "check") => {
            r#"if [ -n "$fleet_ref" ]; then "$FLEET_CLI" "${fleet_global[@]}" skills check "$fleet_ref"; else "$FLEET_CLI" "${fleet_global[@]}" skills check --all; fi"#
        }
        (false, "remove") => {
            r#""$FLEET_CLI" "${fleet_global[@]}" skills remove "$fleet_ref" "$@" "${fleet_yes[@]}" "${fleet_dry[@]}""#
        }
        (false, "adopt") => {
            r#"fleet_adopt_args=("$fleet_ref" "$@"); [ -z "${FLEET_ADOPT_GIT_URL:-}" ] || fleet_adopt_args+=(--git-url "$FLEET_ADOPT_GIT_URL"); [ -z "${FLEET_ADOPT_GIT_SUBPATH:-}" ] || fleet_adopt_args+=(--git-subpath "$FLEET_ADOPT_GIT_SUBPATH"); "$FLEET_CLI" "${fleet_global[@]}" skills adopt "${fleet_adopt_args[@]}" "${fleet_dry[@]}""#
        }
        (false, "set-source") => {
            r#"fleet_url=$1; shift; fleet_subpath=${1:-}; [ "$#" -eq 0 ] || shift; fleet_branch=${1:-}; fleet_source_args=(--git-url "$fleet_url"); [ -z "$fleet_subpath" ] || fleet_source_args+=(--subpath "$fleet_subpath"); [ -z "$fleet_branch" ] || fleet_source_args+=(--branch "$fleet_branch"); "$FLEET_CLI" "${fleet_global[@]}" skills set-source "$fleet_ref" "${fleet_source_args[@]}" "${fleet_force[@]}" "${fleet_dry[@]}""#
        }
        (true, "create") => {
            r#"fleet_preset_args=(); [ -z "${FLEET_PRESET_DESCRIPTION:-}" ] || fleet_preset_args+=(--description "$FLEET_PRESET_DESCRIPTION"); [ -z "${FLEET_PRESET_ICON:-}" ] || fleet_preset_args+=(--icon "$FLEET_PRESET_ICON"); "$FLEET_CLI" "${fleet_global[@]}" presets create "$fleet_ref" "${fleet_preset_args[@]}""#
        }
        (true, "update") => {
            r#"fleet_preset_args=(); [ -z "${FLEET_PRESET_NAME:-}" ] || fleet_preset_args+=(--name "$FLEET_PRESET_NAME"); [ -z "${FLEET_PRESET_DESCRIPTION:-}" ] || fleet_preset_args+=(--description "$FLEET_PRESET_DESCRIPTION"); [ -z "${FLEET_PRESET_ICON:-}" ] || fleet_preset_args+=(--icon "$FLEET_PRESET_ICON"); "$FLEET_CLI" "${fleet_global[@]}" presets update "$fleet_ref" "${fleet_preset_args[@]}""#
        }
        (true, "delete") => {
            r#""$FLEET_CLI" "${fleet_global[@]}" presets delete "$fleet_ref" "${fleet_yes[@]}" "${fleet_dry[@]}""#
        }
        (true, "add-skill") => {
            r#"fleet_skill=$1; "$FLEET_CLI" "${fleet_global[@]}" presets add-skill "$fleet_ref" "$fleet_skill""#
        }
        (true, "remove-skill") => {
            r#"fleet_skill=$1; "$FLEET_CLI" "${fleet_global[@]}" presets remove-skill "$fleet_ref" "$fleet_skill""#
        }
        (true, "deploy" | "undeploy") => {
            r#"fleet_agents=(); for fleet_agent in "$@"; do fleet_agents+=(--agent "$fleet_agent"); done; "$FLEET_CLI" "${fleet_global[@]}" presets __VERB__ "$fleet_ref" "${fleet_agents[@]}" "${fleet_dry[@]}""#
        }
        _ => r#"echo "unsupported skills operation" >&2; exit 2"#,
    };
    script
        .replace("__DRY__", dry)
        .replace("__YES__", yes)
        .replace("__FORCE__", force)
        .replace("__VERB__", verb)
        .replace("__BODY__", body)
}

/// The skills-root environment: empty means the default library.
fn root_environment(root: Option<&str>) -> Vec<(String, String)> {
    match root {
        Some(root) => vec![("FLEET_SKILLS_ROOT".to_owned(), root.to_owned())],
        None => Vec::new(),
    }
}

/// Parses the documented `--version` shapes: the provider's JSON
/// document, the `skills-manager-cli <version>` line, or a bare semver.
fn parse_version_text(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed)
        && let Some(version) = value["version"].as_str()
        && !version.is_empty()
    {
        return Some(version.to_owned());
    }
    let first = trimmed.lines().next().unwrap_or_default().trim();
    let bare = first.strip_prefix("skills-manager-cli ").unwrap_or(first);
    // Both documented forms normalize through the same semver check, so a
    // prefixed line cannot carry trailing garbage a bare line could not.
    let parts: Vec<&str> = bare.split('.').collect();
    if (2..=3).contains(&parts.len())
        && parts.iter().all(|part| {
            let numeric = part.split(['-', '+']).next().unwrap_or(part);
            !numeric.is_empty() && numeric.chars().all(|c| c.is_ascii_digit())
        })
    {
        return Some(bare.to_owned());
    }
    None
}

/// Only the exact fixture version is accepted until fixtures are refreshed.
fn version_acceptable(version: &str) -> bool {
    version == TESTED_CLI_VERSION
}

/// Decodes one base64 field from a probe JSON line.
fn decoded_field(line: &serde_json::Value, key: &str) -> Option<String> {
    use base64::Engine as _;
    let raw = line[key].as_str()?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())?;
    Some(decoded).filter(|decoded| !decoded.is_empty())
}

/// Validates an identifier: bounded, no control characters, no leading
/// dash (so it can never be mistaken for an option).
fn validate_id(id: &str, what: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 255 {
        return Err(format!("{what} must be 1..=255 characters"));
    }
    if id.starts_with('-') {
        return Err(format!("{what} must not start with a dash"));
    }
    if id.chars().any(char::is_control) {
        return Err(format!("{what} must not contain control characters"));
    }
    Ok(())
}

/// Validates an absolute skills root: absolute-shaped, bounded, no `..`
/// segment, no control characters.
fn validate_root(root: &str) -> Result<(), String> {
    if !root.starts_with('/') || root.len() > 400 {
        return Err(
            "the skills root must be an absolute path of at most 400 characters".to_owned(),
        );
    }
    if root.split('/').any(|segment| segment == "..") {
        return Err("the skills root must not contain a `..` segment".to_owned());
    }
    if root.chars().any(char::is_control) {
        return Err("the skills root must not contain control characters".to_owned());
    }
    Ok(())
}

/// The deadline clamp shared by every skills kind.
fn deadline(seconds: u64) -> Duration {
    Duration::from_secs(seconds.min(MAX_SKILLS_TIMEOUT))
}

fn url_has_userinfo(value: &str) -> bool {
    let has_credential_parameter = |query: &str| {
        query.split('&').any(|pair| {
            let key = pair
                .split('=')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            [
                "token",
                "access_token",
                "refresh_token",
                "password",
                "passwd",
                "secret",
                "client_secret",
                "api_key",
                "apikey",
                "auth",
                "signature",
                "sig",
                "credential",
            ]
            .contains(&key.as_str())
        })
    };
    let credential_query = value
        .split(['?', '#'])
        .skip(1)
        .any(has_credential_parameter);
    let credential_userinfo = value.split_once("://").is_some_and(|(scheme, rest)| {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        authority.split_once('@').is_some_and(|(userinfo, _)| {
            !(scheme.eq_ignore_ascii_case("ssh")
                && userinfo == "git"
                && authority.matches('@').count() == 1)
        })
    });
    credential_query || value.chars().any(char::is_control) || credential_userinfo
}

/// Decodes and validates an operation's payload.
fn payload<T: serde::de::DeserializeOwned>(operation: &Operation) -> Result<T, String> {
    serde_json::from_str(
        operation
            .payload_json
            .as_deref()
            .ok_or("the operation carries no payload")?,
    )
    .map_err(|error| format!("the payload is not a valid skills record: {error}"))
}

/// Completes an operation as a failure with a redacted detail.
async fn complete_failure(
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

/// Finishes a deploy or undeploy from the execution outcome.
async fn finish_cli(
    operations: &Operations,
    operation_id: &str,
    result: Option<fleet_provider_ssh::ExecutionResult>,
    detail: Option<String>,
    what: &str,
) -> Result<(), String> {
    match (result, detail) {
        (Some(result), _) if result.killed_by_deadline => {
            complete_failure(
                operations,
                operation_id,
                "deadline_killed",
                &format!(
                    "the {what} was killed at its deadline; the machine's skill state is unknown"
                ),
            )
            .await
        }
        (Some(result), _) if result.exit_code == Some(0) => {
            let parsed: Option<serde_json::Value> = result
                .stdout
                .lines()
                .find_map(|line| serde_json::from_str(line).ok());
            let result_json =
                serde_json::json!({ "outcome": parsed.as_ref().map(safe_cli_outcome) }).to_string();
            operations
                .complete(operation_id, "succeeded", Some(&result_json), None)
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
        (Some(result), _) => {
            if let Some(parsed) = result
                .stdout
                .lines()
                .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            {
                let data = safe_cli_outcome(&parsed);
                if data.get("code").is_some()
                    || data.get("targetConflict").is_some()
                    || data.get("target_conflict").is_some()
                    || data.get("heldBackRemovals").is_some()
                    || data.get("held_back_removals").is_some()
                {
                    let error_json = serde_json::json!({
                        "reason": data.get("code").cloned().unwrap_or_else(|| serde_json::json!("cli_failed")),
                        "detail": redact_output(parsed.get("message").and_then(serde_json::Value::as_str).unwrap_or("the CLI rejected the operation")),
                        "data": data,
                    }).to_string();
                    operations
                        .complete(operation_id, "failed", None, Some(&error_json))
                        .await
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                } else {
                    complete_failure(
                        operations,
                        operation_id,
                        "cli_failed",
                        &redact_output(&result.stderr),
                    )
                    .await
                }
            } else {
                complete_failure(
                    operations,
                    operation_id,
                    "cli_failed",
                    &redact_output(&result.stderr),
                )
                .await
            }
        }
        (None, Some(detail)) => {
            complete_failure(operations, operation_id, "connection_failed", &detail).await
        }
        (None, None) => Err(format!("the {what} produced neither a result nor a detail")),
    }
}

/// Retain only the documented conflict/report fields needed by callers.
/// The recursive redactor also prevents credential-shaped URLs returned by
/// a CLI error from entering durable operation output.
fn safe_cli_outcome(value: &serde_json::Value) -> serde_json::Value {
    fn redact(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::String(text) => serde_json::Value::String(redact_output(text)),
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.iter().map(redact).collect())
            }
            serde_json::Value::Object(map) => serde_json::Value::Object(
                map.iter()
                    .map(|(key, value)| (key.clone(), redact(value)))
                    .collect(),
            ),
            _ => value.clone(),
        }
    }
    let mut safe = serde_json::Map::new();
    for key in [
        "code",
        "message",
        "skillId",
        "deployedTo",
        "skills",
        "updated",
        "checked",
        "status",
        "target_conflict",
        "targetConflict",
        "paths",
        "held_back_removals",
        "heldBackRemovals",
        "versionDigest",
        "verified",
    ] {
        if let Some(value) = value.get(key) {
            safe.insert(key.to_owned(), redact(value));
        }
    }
    if let Some(error) = value.get("error").and_then(serde_json::Value::as_object) {
        for key in [
            "code",
            "target_conflict",
            "targetConflict",
            "paths",
            "held_back_removals",
            "heldBackRemovals",
        ] {
            if let Some(value) = error.get(key) {
                safe.insert(key.to_owned(), redact(value));
            }
        }
    }
    serde_json::Value::Object(safe)
}

/// Redacts credential-shaped userinfo and control noise from CLI output
/// before it becomes a public result.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(bytes);
    digest
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn catalog_rollout_script() -> String {
    r#"set -euo pipefail
fleet_name=$1; fleet_digest=$2; fleet_count=$3; shift 3
case "$fleet_name" in (*[!a-z0-9-]*|''|-*|*-) echo "invalid skill name" >&2; exit 2;; esac
fleet_parent="$HOME/.local/share/fleet/skills"
for fleet_dir in "$HOME/.local" "$HOME/.local/share" "$HOME/.local/share/fleet" "$fleet_parent"; do
  [ ! -L "$fleet_dir" ] || { echo "Fleet staging path must not be a symlink" >&2; exit 2; }
done
install -d -m 700 "$HOME/.local/share/fleet" "$fleet_parent"
for fleet_dir in "$HOME/.local" "$HOME/.local/share" "$HOME/.local/share/fleet" "$fleet_parent"; do
  [ ! -L "$fleet_dir" ] && [ -O "$fleet_dir" ] || { echo "Fleet staging path must be a user-owned directory and must not be a symlink" >&2; exit 2; }
done
fleet_target="$fleet_parent/$fleet_name"
[ ! -L "$fleet_target" ] && { [ ! -e "$fleet_target" ] || [ -O "$fleet_target" ]; } || { echo "Fleet staging target must be user-owned and must not be a symlink" >&2; exit 2; }
fleet_tmp="$fleet_parent/.${fleet_name}.staging.$$"
fleet_backup="$fleet_parent/.${fleet_name}.backup.$$"
[ ! -e "$fleet_tmp" ] && [ ! -L "$fleet_tmp" ] && [ ! -e "$fleet_backup" ] && [ ! -L "$fleet_backup" ] || { echo "Fleet staging temporary path already exists" >&2; exit 2; }
mkdir -m 700 "$fleet_tmp"
fleet_committed=0
fleet_restore() { if [ "$fleet_committed" -eq 0 ] && [ -d "$fleet_backup" ]; then rm -rf "$fleet_target"; mv "$fleet_backup" "$fleet_target"; fi; rm -rf "$fleet_tmp"; }
trap fleet_restore EXIT HUP INT TERM
i=0
while [ "$i" -lt "$fleet_count" ]; do
  fleet_rel=$1; fleet_b64=$2; fleet_expected=$3; shift 3
  case "$fleet_rel" in (''|/*|../*|*/../*|*/..|*\\*) echo "invalid staged path" >&2; exit 2;; esac
  fleet_file="$fleet_tmp/$fleet_rel"
  install -d -m 700 "$(dirname "$fleet_file")"
  printf '%s' "$fleet_b64" | base64 -d > "$fleet_file"
  chmod 600 "$fleet_file"
  fleet_actual=$(sha256sum "$fleet_file" | cut -d ' ' -f 1)
  [ "$fleet_actual" = "$fleet_expected" ] || { echo "staged file digest mismatch" >&2; exit 2; }
  i=$((i + 1))
done
fleet_agents=$1; shift
[ "$#" -eq "$fleet_agents" ] || { echo "invalid explicit agent list" >&2; exit 2; }
fleet_cli=""
for fleet_candidate in "$HOME/.local/bin/skills-manager-cli" "$(command -v skills-manager-cli 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
[ -n "$fleet_cli" ] || { echo "skills-manager-cli is not installed" >&2; exit 3; }
if [ -e "$fleet_target" ]; then mv "$fleet_target" "$fleet_backup"; fi
mv "$fleet_tmp" "$fleet_target"
if "$fleet_cli" --json skills show "$fleet_name" >/dev/null 2>&1; then
  fleet_update_output=$("$fleet_cli" --json skills update "$fleet_name")
  case "$fleet_update_output" in (*held_back_removals*) echo "$fleet_update_output"; echo "update held back removals; inspect the Skills Manager result" >&2; exit 4;; esac
else
  "$fleet_cli" --json skills install "$fleet_target" --local
fi
fleet_agent_args=()
while [ "$#" -gt 0 ]; do fleet_agent_args+=("$1"); shift; done
"$fleet_cli" --json skills deploy "$fleet_name" "${fleet_agent_args[@]}"
"$fleet_cli" --json skills show "$fleet_name" >/dev/null
"$fleet_cli" --json skills status >/dev/null
fleet_committed=1
rm -rf "$fleet_backup"
trap - EXIT HUP INT TERM
printf '{\"versionDigest\":\"%s\",\"verified\":true}\\n' "$fleet_digest"
"#.to_owned()
}

/// Converts catalog GitHub source pins to the install URL form documented by
/// Skills Manager. Other providers need their URL layout to be explicit.
fn catalog_install_reference(
    reference: &str,
    subpath: Option<&str>,
    revision: Option<&str>,
) -> Result<String, String> {
    if subpath.is_none() && revision.is_none() {
        return Ok(reference.to_owned());
    }
    let Some(base) = reference.strip_prefix("https://github.com/") else {
        return Err(
            "Skills Manager v1.40 supports pinned subpaths through GitHub /tree/<revision>/<subpath> URLs"
                .to_owned(),
        );
    };
    if subpath.is_some() && revision.is_none() {
        return Err("a Git subpath requires an explicit revision; the Skills Manager URL contract cannot resolve the repository default branch".to_owned());
    }
    if revision.is_some() && subpath.is_none() {
        return Err("a Git revision pin requires a subpath for the documented Skills Manager install URL form".to_owned());
    }
    let repository = base
        .strip_suffix(".git")
        .unwrap_or(base)
        .trim_end_matches('/');
    if repository.split('/').count() != 2
        || repository
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("pinned Git references must use a GitHub repository root URL".to_owned());
    }
    let revision = revision.expect("a Git subpath or revision requires an explicit revision");
    if !revision
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(
            "Git revision contains characters unsupported by the Skills Manager URL contract"
                .to_owned(),
        );
    }
    let mut install_reference = format!("https://github.com/{repository}/tree/{revision}");
    if let Some(subpath) = subpath {
        if !subpath.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        }) {
            return Err(
                "Git subpath contains characters unsupported by the Skills Manager URL contract"
                    .to_owned(),
            );
        }
        install_reference.push('/');
        install_reference.push_str(subpath);
    }
    Ok(install_reference)
}

fn referenced_rollout_script() -> String {
    r#"set -euo pipefail
fleet_name=$1; fleet_reference=$2; fleet_git=$3; fleet_agents=$4; shift 4
fleet_cli=""
for fleet_candidate in "$HOME/.local/bin/skills-manager-cli" "$(command -v skills-manager-cli 2>/dev/null)"; do
  [ -n "$fleet_candidate" ] && [ -x "$fleet_candidate" ] && fleet_cli="$fleet_candidate" && break
done
[ -n "$fleet_cli" ] || { echo "skills-manager-cli is not installed" >&2; exit 3; }
if ! "$fleet_cli" --json skills show "$fleet_name" >/dev/null 2>&1; then
  fleet_install_args=(--name "$fleet_name")
  [ "$fleet_git" = "true" ] && fleet_install_args+=(--git)
  "$fleet_cli" --json skills install "$fleet_reference" "${fleet_install_args[@]}"
else
  if [ "$fleet_git" = "true" ]; then
    "$fleet_cli" --json skills set-source "$fleet_name" --git-url "$fleet_reference" --force
  else
    command -v jq >/dev/null 2>&1 || { echo "jq is required to validate an existing non-Git skill source" >&2; exit 3; }
    fleet_existing=$("$fleet_cli" --json skills show "$fleet_name")
    if printf '%s' "$fleet_existing" | jq -e --arg reference "$fleet_reference" '.source_ref == $reference' >/dev/null 2>&1; then
      "$fleet_cli" --json skills update "$fleet_name"
    else
      echo "the existing skill uses a different non-Git source; refusing to remove and reinstall it" >&2
      exit 4
    fi
  fi
fi
[ "$#" -eq "$fleet_agents" ] || { echo "invalid explicit agent list" >&2; exit 2; }
fleet_agent_args=("$@")
"$fleet_cli" --json skills deploy "$fleet_name" "${fleet_agent_args[@]}"
"$fleet_cli" --json skills show "$fleet_name" >/dev/null
"$fleet_cli" --json skills status >/dev/null
printf '{\"source\":\"referenced\",\"verified\":true}\\n'
"#.to_owned()
}

fn redact_output(text: &str) -> String {
    let trimmed = text.trim();
    let bounded = if trimmed.len() > 3_000 {
        let mut end = 3_000;
        while !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        &trimmed[..end]
    } else {
        trimmed
    };
    fleet_provider_skills_manager::redact(bounded)
}

/// The kind-dispatching wrapper the controller composes: the skills kinds
/// route to the [`SkillsExecutor`], everything else falls through to the
/// rest of the chain unchanged.
#[derive(Debug)]
pub struct SkillsDispatch {
    fallback: Arc<dyn OperationExecutor>,
    skills: Arc<dyn OperationExecutor>,
}

impl SkillsDispatch {
    /// Composes the dispatch from the fallback chain and the skills
    /// executor.
    #[must_use]
    pub fn new(fallback: Arc<dyn OperationExecutor>, skills: Arc<dyn OperationExecutor>) -> Self {
        Self { fallback, skills }
    }
}

#[async_trait::async_trait]
impl OperationExecutor for SkillsDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            "skills.probe"
            | "skills.deploy"
            | "skills.undeploy"
            | "skills.install"
            | "skills.catalog-rollout"
            | "skills.update"
            | "skills.check"
            | "skills.remove"
            | "skills.adopt"
            | "skills.set-source"
            | "presets.create"
            | "presets.update"
            | "presets.delete"
            | "presets.add-skill"
            | "presets.remove-skill"
            | "presets.deploy"
            | "presets.undeploy" => self.skills.execute(operations, operation).await,
            _ => self.fallback.execute(operations, operation).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        catalog_install_reference, catalog_rollout_script, library_script, normalize_probe,
        parse_version_text, referenced_rollout_script, sha256_hex, url_has_userinfo,
    };

    fn b64(value: &str) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(value)
    }

    #[test]
    fn catalog_rollout_stages_verified_files_and_reruns_as_update() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path();
        let bin = home.join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let log = home.join("calls.log");
        let cli = bin.join("skills-manager-cli");
        std::fs::write(&cli, format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$2 $3\" in\n  'skills show') test -f \"$HOME/installed\" ;;\n  'skills install') touch \"$HOME/installed\" ;;\n  'skills update'|'skills deploy'|'skills status') printf '{{}}\\n' ;;\n  *) exit 8 ;;\nesac\n", log.display())).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o700)).unwrap();
        let contents = "---\nname: hello-world\ndescription: Do useful work\n---\n# Hello\n";
        let args = [
            "hello-world".to_owned(),
            "abc123".to_owned(),
            "1".to_owned(),
            "SKILL.md".to_owned(),
            b64(contents),
            sha256_hex(contents.as_bytes()),
            "1".to_owned(),
            "claude_code".to_owned(),
        ];
        for _ in 0..2 {
            let output = std::process::Command::new("bash")
                .arg("-c")
                .arg(catalog_rollout_script())
                .arg("fleet-rollout")
                .args(&args)
                .env("HOME", home)
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert_eq!(
            std::fs::read_to_string(home.join(".local/share/fleet/skills/hello-world/SKILL.md"))
                .unwrap(),
            contents
        );
        let calls = std::fs::read_to_string(log).unwrap();
        assert!(calls.contains("skills install"));
        assert!(calls.contains("skills update hello-world"));
        assert_eq!(
            calls
                .matches("skills deploy hello-world claude_code")
                .count(),
            2
        );
    }

    #[test]
    fn catalog_git_references_use_the_documented_subpath_url_form() {
        assert_eq!(
            catalog_install_reference(
                "https://github.com/example/skills.git",
                Some("skills/reviewer"),
                Some("v2.1.0"),
            )
            .unwrap(),
            "https://github.com/example/skills/tree/v2.1.0/skills/reviewer"
        );
        assert!(
            catalog_install_reference(
                "https://github.com/example/skills",
                Some("skills/reviewer"),
                None,
            )
            .is_err()
        );
        assert!(
            catalog_install_reference(
                "https://gitlab.com/example/skills",
                Some("skills/reviewer"),
                Some("v2.1.0"),
            )
            .is_err()
        );
        assert!(
            catalog_install_reference(
                "https://github.com/example/skills",
                Some("../outside"),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn referenced_rollout_rebinds_an_existing_git_skill_to_the_pinned_version() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path();
        let bin = home.join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(home.join("installed"), "old source").unwrap();
        let log = home.join("calls.log");
        let cli = bin.join("skills-manager-cli");
        std::fs::write(
            &cli,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$2 $3\" in\n  'skills show') test -f \"$HOME/installed\" ;;\n  'skills set-source') touch \"$HOME/rebound\" ;;\n  'skills deploy'|'skills status') printf '{{}}\\n' ;;\n  *) exit 8 ;;\nesac\n",
                log.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o700)).unwrap();
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(referenced_rollout_script())
            .arg("fleet-rollout")
            .args([
                "release-notes",
                "https://github.com/example/skills/tree/v2.1.0/release-notes",
                "true",
                "1",
                "codex",
            ])
            .env("HOME", home)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(home.join("rebound").exists());
        let calls = std::fs::read_to_string(log).unwrap();
        assert!(calls.contains("skills set-source release-notes --git-url https://github.com/example/skills/tree/v2.1.0/release-notes --force"));
        assert!(calls.contains("skills deploy release-notes codex"));
        assert!(!calls.contains("skills update release-notes"));
    }

    #[test]
    fn referenced_non_git_rollout_updates_only_when_json_source_ref_matches() {
        let root = tempfile::tempdir().unwrap();
        let reference = "file:///srv/fleet/catalog/hello-world";
        for (name, show_json, succeeds) in [
            (
                "matching",
                r#"{ "name": "hello-world", "source_ref": "file:///srv/fleet/catalog/hello-world" }"#,
                true,
            ),
            (
                "mismatched",
                r#"{ "name": "hello-world", "source_ref": "file:///srv/other/hello-world" }"#,
                false,
            ),
            ("malformed", "not json", false),
        ] {
            let home = root.path().join(name);
            let bin = home.join(".local/bin");
            std::fs::create_dir_all(&bin).unwrap();
            let log = home.join("calls.log");
            let cli = bin.join("skills-manager-cli");
            let jq = bin.join("jq");
            std::fs::write(
                &jq,
                "#!/bin/sh\n[ \"$1\" = '-e' ] && [ \"$2\" = '--arg' ] && [ \"$3\" = 'reference' ] && [ \"$4\" = \"$EXPECTED_REFERENCE\" ] && [ \"$5\" = '.source_ref == $reference' ] || exit 42\ncat >/dev/null\n[ \"$JQ_MATCH\" = true ]\n",
            )
            .unwrap();
            std::fs::write(
                &cli,
                format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$2 $3\" in\n  'skills show') printf '%s\\n' \"$SHOW_JSON\" ;;\n  'skills update'|'skills deploy'|'skills status') printf '{{}}\\n' ;;\n  *) exit 8 ;;\nesac\n",
                    log.display()
                ),
            )
            .unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&jq, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o700)).unwrap();
            let output = std::process::Command::new("bash")
                .arg("-c")
                .arg(referenced_rollout_script())
                .arg("fleet-rollout")
                .args(["hello-world", reference, "false", "1", "codex"])
                .env("HOME", &home)
                .env("SHOW_JSON", show_json)
                .env("JQ_MATCH", succeeds.to_string())
                .env("EXPECTED_REFERENCE", reference)
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .output()
                .unwrap();
            assert_eq!(output.status.success(), succeeds, "case: {name}");
            let calls = std::fs::read_to_string(log).unwrap();
            assert_eq!(calls.contains("skills update hello-world"), succeeds);
            assert_eq!(calls.contains("skills deploy hello-world codex"), succeeds);
        }
    }

    #[test]
    fn ssh_git_url_exception_rejects_additional_userinfo() {
        assert!(!url_has_userinfo("ssh://git@github.com/org/repo.git"));
        assert!(url_has_userinfo(
            "ssh://git@user:secret@github.com/org/repo.git"
        ));
    }

    #[test]
    fn both_documented_version_shapes_normalize_identically() {
        assert_eq!(
            parse_version_text("skills-manager-cli 1.34.2"),
            parse_version_text("1.34.2")
        );
        assert_eq!(
            parse_version_text("skills-manager-cli 1.2.3-beta"),
            parse_version_text("1.2.3-beta")
        );
        assert_eq!(parse_version_text("skills-manager-cli 1.34.2 junk"), None);
        assert_eq!(parse_version_text(""), None);
        // The provider's JSON document shape is the third documented form.
        assert_eq!(
            parse_version_text(r#"{"version":"1.34.2"}"#),
            Some("1.34.2".to_owned())
        );
        assert_eq!(parse_version_text(r#"{"foo":"bar"}"#), None);
    }

    #[test]
    fn library_scripts_keep_confirmation_explicit_and_quote_positional_values() {
        let unconfirmed = library_script("skills.remove", false, false, false);
        let confirmed = library_script("skills.remove", true, true, false);
        assert!(unconfirmed.contains("fleet_yes=()"));
        assert!(!unconfirmed.contains("--yes"));
        assert!(confirmed.contains("fleet_yes=(--yes)"));
        assert!(confirmed.contains("fleet_dry=(--dry-run)"));
        assert!(confirmed.contains("skills remove \"$fleet_ref\""));
        let add_skill = library_script("presets.add-skill", false, false, false);
        assert!(add_skill.contains("presets add-skill \"$fleet_ref\" \"$fleet_skill\""));
        let install = library_script("skills.install", false, false, false);
        assert!(install.contains("skills install \"$fleet_ref\" \"${fleet_install_args[@]}\""));
        let set_source = library_script("skills.set-source", true, false, true);
        assert!(set_source.contains("\"${fleet_force[@]}\" \"${fleet_dry[@]}\""));
    }

    #[test]
    fn unsupported_cli_versions_are_recorded_without_guessing_at_the_contract() {
        let raw =
            serde_json::json!({ "present": true, "version64": b64("skills-manager-cli 2.0.0") });
        let snapshot = normalize_probe("m-1", &raw).unwrap();
        assert!(matches!(
            snapshot.availability,
            fleet_application::skills::SkillsAvailability::Unsupported
        ));
        assert_eq!(snapshot.cli_version.as_deref(), Some("2.0.0"));
        assert_eq!(snapshot.data["skills"], serde_json::json!([]));
    }

    #[test]
    fn malformed_entries_reject_the_whole_inventory() {
        let raw = serde_json::json!({
            "present": true,
            "version64": b64("skills-manager-cli 1.40.0"),
            "agents64": b64("[]"),
            "skills64": b64(r#"[{"id":"s","name":"Skill","enabled":true,"preset_ids":[],"deployed_to":"malformed"}]"#),
            "presets64": b64("[]"),
            "checks64": b64("[]"),
        });
        assert!(normalize_probe("m-1", &raw).is_none());
    }

    #[test]
    fn unidentified_binaries_are_not_reported_as_absent() {
        let snapshot = normalize_probe(
            "m-1",
            &serde_json::json!({"present": true, "unidentified": true}),
        )
        .unwrap();
        assert!(matches!(
            snapshot.availability,
            fleet_application::skills::SkillsAvailability::Unsupported
        ));
        assert_eq!(snapshot.cli_version, None);
    }
}
