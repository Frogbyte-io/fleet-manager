//! The `fleetctl` command line: the human and agent surface over the same
//! public API the web app uses.
//!
//! There is no second authority here and no private transport: every command
//! is one HTTP call to the controller's `/api/v1`, so the CLI sees exactly
//! what the web sees — the same envelopes, the same error codes, the same
//! correlation identity. Output is either aligned human text or stable JSON
//! (`--output json`), which is the mode Fleet skills consume.
//!
//! The implementation is a library plus a thin binary so the contract can be
//! exercised in tests against a real controller.

use std::fmt;

/// One controller request in transport-neutral form: method, path, query,
/// and body.
type RequestShape = (
    reqwest::Method,
    String,
    Vec<(&'static str, String)>,
    Option<Value>,
);

use serde_json::Value;

/// The controller address used when `--url` is absent: the safe default, the
/// controller's own documented loopback listener.
pub const DEFAULT_URL: &str = "http://127.0.0.1:8080";

/// The state directory `fleetctl status` consults when `--socket` is absent,
/// the same default `fleetd` uses.
pub const DEFAULT_SOCKET: &str = "fleetd-state/local.sock";

/// A CLI failure: what went wrong and where the message belongs.
#[derive(Debug)]
pub struct CliError {
    /// Caller-safe message, printed to stderr.
    pub message: String,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// The parsed command line.
#[derive(Clone, Debug, PartialEq)]
pub struct Invocation {
    /// The controller base URL.
    pub url: String,
    /// Whether `--url` was given: the explicit direct-controller override
    /// for the `status` command's route selection.
    pub url_explicit: bool,
    /// The local socket path for the `status` command.
    pub socket: String,
    /// The output mode.
    pub output: Output,
    /// The command and its arguments.
    pub command: Command,
}

/// The output mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Output {
    /// Aligned human-readable text (the default).
    Text,
    /// Stable JSON for scripts and Fleet skills.
    Json,
}

/// The commands `fleetctl` knows.
#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    /// The node and Fleet read status. Prefers the node's local socket
    /// unless `--url` names the controller explicitly.
    Status,
    /// The system view.
    System,
    /// List operations.
    OperationsList {
        /// Maximum entries to request.
        limit: Option<u32>,
    },
    /// Read one operation.
    OperationsGet {
        /// The operation id.
        id: String,
    },
    /// Request cancellation of an operation.
    OperationsCancel {
        /// The operation id.
        id: String,
    },
    /// List machines with optional filters.
    MachinesList {
        /// Only machines carrying this tag.
        tag: Option<String>,
        /// Only machines in this group.
        group: Option<String>,
        /// Only machines carrying this capability, as `namespace:name`.
        capability: Option<String>,
        /// Only machines in this state.
        status: Option<String>,
        /// Maximum entries to request.
        limit: Option<u32>,
    },
    /// Read one machine.
    MachinesGet {
        /// The machine id.
        id: String,
    },
    /// Create an Add Machine onboarding draft from address and auth mode.
    MachinesOnboardCreate {
        /// The remote login user.
        user: String,
        /// The host or address.
        host: String,
        /// The TCP port; 22 when omitted.
        port: Option<u16>,
        /// The proposed machine name; derived from the host when omitted.
        name: Option<String>,
        /// Operator notes carried onto the machine.
        description: Option<String>,
        /// Tags carried onto the machine.
        tags: Vec<String>,
        /// Groups carried onto the machine.
        groups: Vec<String>,
        /// How the controller would authenticate.
        auth: OnboardAuthArg,
    },
    /// List onboarding drafts.
    MachinesOnboardList {
        /// Maximum entries to request.
        limit: Option<u32>,
    },
    /// Read one draft in full: the review surface.
    MachinesOnboardGet {
        /// The draft id.
        id: String,
    },
    /// Run the test stage: probe the host key, and once confirmed, test
    /// authentication. With `--wait`, poll the operation and print the
    /// refreshed draft.
    MachinesOnboardTest {
        /// The draft id.
        id: String,
        /// Poll the operation to a terminal state, then print the draft.
        wait: bool,
        /// The poll bound, in seconds (with `--wait`).
        timeout: u64,
    },
    /// Run the discover stage: the agentless inventory probe into the
    /// draft, only against a confirmed fingerprint.
    MachinesOnboardDiscover {
        /// The draft id.
        id: String,
        /// Poll the operation to a terminal state, then print the draft.
        wait: bool,
        /// The poll bound, in seconds (with `--wait`).
        timeout: u64,
    },
    /// Confirm the observed fingerprint explicitly (trust-on-first-use).
    MachinesOnboardConfirm {
        /// The draft id.
        id: String,
        /// The OpenSSH `SHA256:` fingerprint to confirm.
        fingerprint: String,
    },
    /// Complete onboarding: register the machine from the draft.
    MachinesOnboardAdd {
        /// The draft id.
        id: String,
    },
    /// Cancel a draft: the row is deleted and an unregistered host's pins
    /// are removed.
    MachinesOnboardCancel {
        /// The draft id.
        id: String,
    },
    /// List projects, newest first.
    ProjectsList {
        /// Only projects whose normalized remote starts with this prefix.
        remote_prefix: Option<String>,
        /// Only projects whose name contains this substring.
        name_substring: Option<String>,
        /// Maximum entries to request.
        limit: Option<u32>,
    },
    /// Read one project with its observed checkouts.
    ProjectsGet {
        /// The project id.
        id: String,
    },
    /// Register a project from its Git remote (any common spelling).
    ProjectsCreate {
        /// The Git remote.
        remote: String,
        /// The display name.
        name: String,
        /// Operator notes.
        description: Option<String>,
    },
    /// Rename or re-describe a project. An absent description preserves the
    /// current one.
    ProjectsUpdate {
        /// The project id.
        id: String,
        /// The display name.
        name: String,
        /// Operator notes; None preserves the current description.
        description: Option<String>,
    },
    /// Remove a project and its observed checkouts (repositories untouched).
    ProjectsDelete {
        /// The project id.
        id: String,
    },
    /// Start a checkout discovery for a project on a machine.
    ProjectsDiscover {
        /// The project id.
        id: String,
        /// The machine whose standard roots to scan.
        machine: String,
        /// The SSH endpoint id to probe through.
        endpoint: String,
        /// How the endpoint authenticates.
        auth: OnboardAuthArg,
        /// The identity file's path, for identity-file auth.
        identity: Option<String>,
        /// Wait for the operation to finish.
        wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// Make a project ready on a machine: plan, execute, and verify.
    /// The plan is inspectable with --dry-run.
    ProjectsReady {
        /// The project id.
        id: String,
        /// The machine to make ready on.
        machine: String,
        /// The SSH endpoint id to act through.
        endpoint: String,
        /// The checkout root the workflow targets.
        root: String,
        /// Compute and show the plan without executing it.
        dry_run: bool,
        /// How the endpoint authenticates.
        auth: OnboardAuthArg,
        /// Wait for the workflow to finish.
        wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// Record a discovery result as the project's observed checkouts. The
    /// discovery result JSON is read from standard input.
    ProjectsRecord {
        /// The project id.
        id: String,
        /// The machine the checkouts were observed on.
        machine: String,
    },
    /// Clone a project's remote into a checkout root on a machine.
    ProjectsClone {
        /// The project id.
        id: String,
        /// The machine to clone on.
        machine: String,
        /// The SSH endpoint id to act through.
        endpoint: String,
        /// Where the clone lands, absolute.
        root: String,
        /// The branch to check out, when one is named.
        branch: Option<String>,
        /// How the endpoint authenticates.
        auth: OnboardAuthArg,
        /// The identity file's path, for identity-file auth.
        identity: Option<String>,
        /// Wait for the operation to finish.
        wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// Pull a project's checkout on a machine, fast-forward only.
    ProjectsPull {
        /// The project id.
        id: String,
        /// The machine to pull on.
        machine: String,
        /// The SSH endpoint id to act through.
        endpoint: String,
        /// The checkout root, absolute.
        root: String,
        /// How the endpoint authenticates.
        auth: OnboardAuthArg,
        /// The identity file's path, for identity-file auth.
        identity: Option<String>,
        /// Wait for the operation to finish.
        wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// Read a checkout's status on a machine.
    ProjectsStatus {
        /// The project id.
        id: String,
        /// The machine to probe.
        machine: String,
        /// The SSH endpoint id to act through.
        endpoint: String,
        /// The checkout root, absolute.
        root: String,
        /// How the endpoint authenticates.
        auth: OnboardAuthArg,
        /// The identity file's path, for identity-file auth.
        identity: Option<String>,
        /// Wait for the operation to finish.
        wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// Write a guarded agent config file under a checkout root. The
    /// contents are read from standard input.
    ProjectsWriteConfig {
        /// The project id.
        id: String,
        /// The machine to write on.
        machine: String,
        /// The SSH endpoint id to act through.
        endpoint: String,
        /// The checkout root, absolute.
        root: String,
        /// Which agent config file to write.
        file_name: String,
        /// How the endpoint authenticates.
        auth: OnboardAuthArg,
        /// The identity file's path, for identity-file auth.
        identity: Option<String>,
        /// Wait for the operation to finish.
        wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// Probe the Skills Manager CLI on a machine (and optionally install a
    /// pinned release).
    SkillsProbe {
        /// The machine to probe.
        machine: String,
        /// The SSH endpoint id to act through.
        endpoint: String,
        /// How the endpoint authenticates.
        auth: OnboardAuthArg,
        /// An external skills root, when one is named.
        skills_root: Option<String>,
        /// The pinned release's URL, when installing.
        artifact_url: Option<String>,
        /// The pinned release's expected sha256.
        artifact_sha256: Option<String>,
        /// Wait for the operation to finish.
        wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// Deploy a skill to agents through the Skills Manager CLI.
    SkillsDeploy {
        /// The machine to act on.
        machine: String,
        /// The SSH endpoint id to act through.
        endpoint: String,
        /// How the endpoint authenticates.
        auth: OnboardAuthArg,
        /// The skill to deploy.
        skill: String,
        /// The agents to deploy to.
        agents: Vec<String>,
        /// An external skills root, when one is named.
        skills_root: Option<String>,
        /// Keep the operation a dry run.
        dry_run: bool,
        /// Wait for the operation to finish.
        wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// Undeploy a skill from agents through the Skills Manager CLI.
    SkillsUndeploy {
        /// The machine to act on.
        machine: String,
        /// The SSH endpoint id to act through.
        endpoint: String,
        /// How the endpoint authenticates.
        auth: OnboardAuthArg,
        /// The skill to undeploy.
        skill: String,
        /// The agents to undeploy from.
        agents: Vec<String>,
        /// An external skills root, when one is named.
        skills_root: Option<String>,
        /// Keep the operation a dry run.
        dry_run: bool,
        /// Wait for the operation to finish.
        wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// Run a Frogenv action on a machine: status, a ceremony, sync, or
    /// an environment-bound command.
    FrogenvOperation {
        /// The machine to act on.
        machine: String,
        /// The SSH endpoint id to act through.
        endpoint: String,
        /// How the endpoint authenticates.
        auth: OnboardAuthArg,
        /// The action to run.
        action: String,
        /// The checkout root, for env run.
        root: Option<String>,
        /// The command arguments, for env run.
        command: Vec<String>,
        /// Wait for the operation to finish.
        wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// Run a mise action on a machine: inventory, status, install, or a
    /// project command through `mise exec`.
    MiseOperation {
        /// The machine to act on.
        machine: String,
        /// The SSH endpoint id to act through.
        endpoint: String,
        /// How the endpoint authenticates.
        auth: OnboardAuthArg,
        /// The action to run.
        action: String,
        /// The tool to install, for install.
        tool: Option<String>,
        /// The pinned version, for install.
        version: Option<String>,
        /// The checkout root, for exec.
        root: Option<String>,
        /// The command arguments, for exec.
        command: Vec<String>,
        /// Wait for the operation to finish.
        wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// Execute an apply plan on a machine. The plan JSON is read from
    /// standard input.
    ApplyWorkflow {
        /// The machine to apply on.
        machine: String,
        /// The SSH endpoint id to act through.
        endpoint: String,
        /// How the endpoint authenticates.
        auth: OnboardAuthArg,
        /// The plan's identity.
        plan_id: String,
        /// Wait for the workflow to finish.
        wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// Show the Tailscale integration's status (configured or not).
    TailnetStatus,
    /// Configure the Tailscale OAuth client. The secret is read from
    /// standard input and never placed in a process argument.
    TailnetConfigure {
        /// The OAuth client identifier.
        client_id: String,
    },
    /// Remove the stored Tailscale OAuth client.
    TailnetClear,
    /// List tailnet devices, correlated with Fleet machines by evidence
    /// only.
    TailnetDevices {
        /// Maximum entries to request.
        limit: Option<u32>,
    },
    /// Import a tailnet device as an SSH onboarding draft; the standard
    /// onboarding flow (test, confirm, add) takes it from there.
    TailnetImport {
        /// The device's node id.
        node_id: String,
        /// The SSH login user on the target machine.
        user: String,
        /// The SSH port; 22 when omitted.
        port: Option<u16>,
    },
    /// List the configured Proxmox accounts.
    ProxmoxAccounts,
    /// Create a Proxmox account. The token secret is read from standard
    /// input and never placed in a process argument.
    ProxmoxCreate {
        /// The operator-facing account name.
        name: String,
        /// The PVE host (IP or DNS name).
        host: String,
        /// The API port; 8006 when omitted.
        port: Option<u16>,
        /// The API token id (`user@realm!tokenname`).
        token_id: String,
    },
    /// Remove a Proxmox account and its secret.
    ProxmoxDelete {
        /// The account's identity.
        account_id: String,
    },
    /// Observe a host's certificate fingerprint without sending any
    /// credential.
    ProxmoxObserve {
        /// The account's identity.
        account_id: String,
    },
    /// Confirm the observed fingerprint as the account's trust anchor.
    ProxmoxConfirm {
        /// The account's identity.
        account_id: String,
        /// The fingerprint as observed (colons optional).
        fingerprint: String,
    },
    /// Discover the cluster through one trusted account.
    ProxmoxDiscover {
        /// The account's identity.
        account_id: String,
    },
    /// List the account's guests with their Fleet-machine association
    /// candidates (evidence only).
    ProxmoxGuests {
        /// The account's identity.
        account_id: String,
    },
    /// Record one guest's facts onto a confirmed Fleet machine.
    ProxmoxObserveGuest {
        /// The account's identity.
        account_id: String,
        /// The guest's VMID.
        vmid: u32,
        /// The machine the guest is confirmed to be.
        machine_id: String,
    },
    /// Review then run a destructive-adjacent operation on a guest.
    ProxmoxDestructive {
        /// The action: snapshot, snapshot-revert, snapshot-delete, clone,
        /// template, or task-cancel.
        action: String,
        /// The account's identity.
        account_id: String,
        /// The guest's hosting node.
        node: String,
        /// The guest's VMID.
        vmid: u32,
        /// The action-specific parameters, as JSON on standard input.
        params: Option<String>,
        /// Wait for the operation to finish.
        wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// Run a lifecycle action on a guest as a durable operation.
    ProxmoxLifecycle {
        /// The action: start, stop, shutdown, or reboot.
        action: String,
        /// The account's identity.
        account_id: String,
        /// The guest's hosting node.
        node: String,
        /// The guest's VMID.
        vmid: u32,
        /// Wait for the operation to finish.
        wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// Start the audited "Install Fleet Node" bootstrap on an agentless
    /// machine: download the checksummed service package on the node,
    /// install the systemd service, enroll, and wait for the gateway
    /// session.
    MachinesInstallNode {
        /// The machine gaining the node.
        machine_id: String,
        /// The SSH endpoint id to bootstrap over.
        endpoint: String,
        /// How the controller authenticates to the endpoint.
        auth: OnboardAuthArg,
        /// Where the service archive downloads from. Absent together with
        /// the digest in the orchestrated install: the controller selects
        /// the package for the machine's own platform.
        artifact_url: Option<String>,
        /// The archive's expected sha256 (mandatory in explicit mode).
        artifact_sha256: Option<String>,
        /// The controller URL the daemon connects to; the CLI defaults it
        /// to its own `--url` (the node must reach the same controller).
        controller_url: Option<String>,
        /// The whole-install deadline, in seconds.
        install_timeout: u64,
        /// How long to wait for the gateway session, in seconds.
        connect_wait: Option<u64>,
        /// Poll the operation to a terminal state.
        wait: bool,
        /// The poll bound, in seconds (with `--wait`).
        poll_timeout: u64,
    },
}

/// How the CLI spells the draft's authentication mode.
#[derive(Clone, Debug, PartialEq)]
pub enum OnboardAuthArg {
    /// The controller's running agent supplies the key.
    Agent,
    /// An identity file, by path.
    IdentityFile(String),
}

/// Parses the command line.
///
/// # Errors
///
/// Fails with a caller-safe usage message on anything unexpected.
pub fn parse(args: &[String]) -> Result<Invocation, CliError> {
    let mut url = DEFAULT_URL.to_owned();
    let mut url_explicit = false;
    let mut socket = DEFAULT_SOCKET.to_owned();
    let mut output = Output::Text;
    let mut rest = Vec::new();
    let mut index = 0;
    // `--version`/`--help` are parsed only before the command word: after
    // the first positional, everything belongs to the subcommand, so a
    // subcommand's own `--version` (mise install) is never mistaken for
    // the CLI's own. The connection/output globals must precede the
    // command word, matching the documented grammar.
    let mut command_started = false;
    while index < args.len() {
        if command_started {
            rest.push(args[index].clone());
            index += 1;
            continue;
        }
        match args[index].as_str() {
            "--help" | "-h" | "--version" | "-V" => {
                // Handled by the binary before parsing; treat as usage here.
                return Err(CliError { message: usage() });
            }
            "--url" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| CliError {
                    message: "--url requires a value".to_owned(),
                })?;
                value.trim_end_matches('/').clone_into(&mut url);
                url_explicit = true;
            }
            "--socket" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| CliError {
                    message: "--socket requires a path".to_owned(),
                })?;
                value.clone_into(&mut socket);
            }
            "--output" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| CliError {
                    message: "--output requires json or text".to_owned(),
                })?;
                output = match value.as_str() {
                    "json" => Output::Json,
                    "text" => Output::Text,
                    other => {
                        return Err(CliError {
                            message: format!("--output must be json or text, not {other:?}"),
                        });
                    }
                };
            }
            _ => {
                command_started = true;
                rest.push(args[index].clone());
            }
        }
        index += 1;
    }

    let words: Vec<&str> = rest.iter().map(String::as_str).collect();
    let command = match words.as_slice() {
        ["status"] => Command::Status,
        ["system"] => Command::System,
        ["operations", "list"] => Command::OperationsList { limit: None },
        ["operations", "list", "--limit", value] => Command::OperationsList {
            limit: Some(value.parse().map_err(|_| CliError {
                message: format!("--limit must be a number, not {value:?}"),
            })?),
        },
        ["operations", "get", id] => Command::OperationsGet {
            id: (*id).to_owned(),
        },
        ["operations", "cancel", id] => Command::OperationsCancel {
            id: (*id).to_owned(),
        },
        ["machines", "list", rest @ ..] => parse_machines_list(rest)?,
        ["machines", "get", id] => Command::MachinesGet {
            id: (*id).to_owned(),
        },
        ["machines", "onboard", verb, rest @ ..] => parse_onboard_command(verb, rest)?,
        ["skills", verb, machine_id, rest @ ..] => parse_skills_command(verb, machine_id, rest)?,
        ["frogenv", action, machine_id, rest @ ..] => {
            parse_frogenv_command(action, machine_id, rest)?
        }
        ["mise", action, machine_id, rest @ ..] => parse_mise_command(action, machine_id, rest)?,
        ["apply", machine_id, rest @ ..] => parse_apply_command(machine_id, rest)?,
        ["machines", "install-node", machine_id, rest @ ..] => {
            parse_install_node(machine_id, rest, &url)?
        }
        ["tailnet", verb, rest @ ..] => parse_tailnet_command(verb, rest)?,
        ["proxmox", verb, rest @ ..] => parse_proxmox_command(verb, rest)?,
        ["projects", verb, rest @ ..] => parse_projects_command(verb, rest)?,
        _ => return Err(CliError { message: usage() }),
    };
    Ok(Invocation {
        url,
        url_explicit,
        socket,
        output,
        command,
    })
}

/// Parses the flags of `machines list`; each takes one value.
fn parse_machines_list(rest: &[&str]) -> Result<Command, CliError> {
    let mut tag: Option<String> = None;
    let mut group: Option<String> = None;
    let mut capability: Option<String> = None;
    let mut status: Option<String> = None;
    let mut limit = None;
    let mut flags = rest.iter().copied();
    while let Some(flag) = flags.next() {
        let mut value = |name: &str| {
            flags.next().ok_or_else(|| CliError {
                message: format!("--{name} requires a value"),
            })
        };
        match flag {
            "--tag" => tag = Some(value("tag")?.to_owned()),
            "--group" => group = Some(value("group")?.to_owned()),
            "--capability" => capability = Some(value("capability")?.to_owned()),
            "--status" => status = Some(value("status")?.to_owned()),
            "--limit" => {
                let parsed = value("limit")?;
                limit = Some(parsed.parse().map_err(|_| CliError {
                    message: format!("--limit must be a number, not {parsed:?}"),
                })?);
            }
            other => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    Ok(Command::MachinesList {
        tag,
        group,
        capability,
        status,
        limit,
    })
}

/// Parses one `fleetctl projects` subcommand.
#[allow(clippy::too_many_lines)]
fn parse_projects_command(verb: &str, rest: &[&str]) -> Result<Command, CliError> {
    match verb {
        "list" => {
            let mut remote_prefix = None;
            let mut name_substring = None;
            let mut limit = None;
            let mut flags = rest.iter().copied();
            while let Some(flag) = flags.next() {
                match flag {
                    "--remote-prefix" => {
                        remote_prefix = Some(
                            flags
                                .next()
                                .ok_or_else(|| CliError {
                                    message: "--remote-prefix requires a value".to_owned(),
                                })?
                                .to_owned(),
                        );
                    }
                    "--name-substring" => {
                        name_substring = Some(
                            flags
                                .next()
                                .ok_or_else(|| CliError {
                                    message: "--name-substring requires a value".to_owned(),
                                })?
                                .to_owned(),
                        );
                    }
                    "--limit" => {
                        let value = flags.next().ok_or_else(|| CliError {
                            message: "--limit requires a value".to_owned(),
                        })?;
                        limit = Some(value.parse().map_err(|_| CliError {
                            message: format!("--limit must be a number, not {value:?}"),
                        })?);
                    }
                    other => {
                        return Err(CliError {
                            message: format!(
                                "unknown flag {other:?}; see the usage below\n\n{}",
                                usage()
                            ),
                        });
                    }
                }
            }
            Ok(Command::ProjectsList {
                remote_prefix,
                name_substring,
                limit,
            })
        }
        "get" => match rest {
            [id] => Ok(Command::ProjectsGet {
                id: (*id).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "create" => match rest {
            ["--remote", remote, "--name", name] => Ok(Command::ProjectsCreate {
                remote: (*remote).to_owned(),
                name: (*name).to_owned(),
                description: None,
            }),
            [
                "--remote",
                remote,
                "--name",
                name,
                "--description",
                description,
            ] => Ok(Command::ProjectsCreate {
                remote: (*remote).to_owned(),
                name: (*name).to_owned(),
                description: Some((*description).to_owned()),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "update" => match rest {
            // A rename without --description preserves the current
            // description: the CLI cannot know it, so it must not clear it.
            [id, "--name", name] => Ok(Command::ProjectsUpdate {
                id: (*id).to_owned(),
                name: (*name).to_owned(),
                description: None,
            }),
            [id, "--name", name, "--description", description] => Ok(Command::ProjectsUpdate {
                id: (*id).to_owned(),
                name: (*name).to_owned(),
                description: Some((*description).to_owned()),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "delete" => match rest {
            [id] => Ok(Command::ProjectsDelete {
                id: (*id).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "discover" => match rest {
            [id, machine_id, rest @ ..] => {
                let (flags, wait, timeout) = parse_checkout_flags(rest)?;
                Ok(Command::ProjectsDiscover {
                    id: (*id).to_owned(),
                    machine: (*machine_id).to_owned(),
                    endpoint: flags.endpoint,
                    auth: flags.auth,
                    identity: flags.identity,
                    wait,
                    timeout,
                })
            }
            _ => Err(CliError { message: usage() }),
        },
        "record" => match rest {
            [id, machine_id] => Ok(Command::ProjectsRecord {
                id: (*id).to_owned(),
                machine: (*machine_id).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "ready" => match rest {
            [id, machine_id, "--root", root, rest @ ..] => {
                // --dry-run is a ready-only flag and is consumed before
                // the shared parser sees the rest, so a documented
                // invocation is never refused as an unknown flag.
                let dry_run = rest.contains(&"--dry-run");
                let remaining: Vec<&str> = rest
                    .iter()
                    .copied()
                    .filter(|flag| *flag != "--dry-run")
                    .collect();
                let (flags, wait, timeout) = parse_checkout_flags(&remaining)?;
                Ok(Command::ProjectsReady {
                    id: (*id).to_owned(),
                    machine: (*machine_id).to_owned(),
                    endpoint: flags.endpoint,
                    root: (*root).to_owned(),
                    dry_run,
                    auth: flags.auth,
                    wait,
                    timeout,
                })
            }
            _ => Err(CliError { message: usage() }),
        },
        "clone" => match rest {
            [id, machine_id, "--root", root, rest @ ..] => {
                let (flags, wait, timeout) = parse_checkout_flags(rest)?;
                let branch = flags.branch;
                Ok(Command::ProjectsClone {
                    id: (*id).to_owned(),
                    machine: (*machine_id).to_owned(),
                    endpoint: flags.endpoint,
                    root: (*root).to_owned(),
                    branch,
                    auth: flags.auth,
                    identity: flags.identity,
                    wait,
                    timeout,
                })
            }
            _ => Err(CliError { message: usage() }),
        },
        "pull" => match rest {
            [id, machine_id, "--root", root, rest @ ..] => {
                let (flags, wait, timeout) = parse_checkout_flags(rest)?;
                Ok(Command::ProjectsPull {
                    id: (*id).to_owned(),
                    machine: (*machine_id).to_owned(),
                    endpoint: flags.endpoint,
                    root: (*root).to_owned(),
                    auth: flags.auth,
                    identity: flags.identity,
                    wait,
                    timeout,
                })
            }
            _ => Err(CliError { message: usage() }),
        },
        "status" => match rest {
            [id, machine_id, "--root", root, rest @ ..] => {
                let (flags, wait, timeout) = parse_checkout_flags(rest)?;
                Ok(Command::ProjectsStatus {
                    id: (*id).to_owned(),
                    machine: (*machine_id).to_owned(),
                    endpoint: flags.endpoint,
                    root: (*root).to_owned(),
                    auth: flags.auth,
                    identity: flags.identity,
                    wait,
                    timeout,
                })
            }
            _ => Err(CliError { message: usage() }),
        },
        "write-config" => match rest {
            [
                id,
                machine_id,
                "--root",
                root,
                "--file",
                file_name,
                rest @ ..,
            ] => {
                let (flags, wait, timeout) = parse_checkout_flags(rest)?;
                Ok(Command::ProjectsWriteConfig {
                    id: (*id).to_owned(),
                    machine: (*machine_id).to_owned(),
                    endpoint: flags.endpoint,
                    root: (*root).to_owned(),
                    file_name: (*file_name).to_owned(),
                    auth: flags.auth,
                    identity: flags.identity,
                    wait,
                    timeout,
                })
            }
            _ => Err(CliError { message: usage() }),
        },
        _ => Err(CliError { message: usage() }),
    }
}

/// The endpoint/auth flags the checkout commands share.
struct CheckoutEndpointFlags {
    endpoint: String,
    auth: OnboardAuthArg,
    identity: Option<String>,
    branch: Option<String>,
}

/// Parses the flags shared by the checkout commands: `--endpoint`,
/// `--auth`, `--identity`, and (clone only) `--branch`. Returns the flags
/// plus the wait/timeout pair.
fn parse_checkout_flags(
    rest: &[&str],
) -> Result<(CheckoutEndpointFlags, bool, Option<u64>), CliError> {
    let mut endpoint: Option<String> = None;
    let mut auth: Option<String> = None;
    let mut identity: Option<String> = None;
    let mut branch: Option<String> = None;
    let mut wait = false;
    let mut timeout: Option<u64> = None;
    let mut flags = rest.iter().copied();
    while let Some(flag) = flags.next() {
        let mut value = |name: &str| {
            flags.next().ok_or_else(|| CliError {
                message: format!("--{name} requires a value"),
            })
        };
        match flag {
            "--endpoint" => endpoint = Some(value("endpoint")?.to_owned()),
            "--auth" => auth = Some(value("auth")?.to_owned()),
            "--identity" => identity = Some(value("identity")?.to_owned()),
            "--branch" => branch = Some(value("branch")?.to_owned()),
            "--wait" => wait = true,
            "--timeout" => {
                let parsed = value("timeout")?;
                timeout = Some(parsed.parse().map_err(|_| CliError {
                    message: format!("--timeout must be a number, not {parsed:?}"),
                })?);
            }
            other => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let auth_arg = resolve_auth_argument(auth.as_deref(), identity.clone())?;
    Ok((
        CheckoutEndpointFlags {
            endpoint: endpoint.ok_or_else(|| CliError {
                message: "--endpoint <endpoint-id> is required".to_owned(),
            })?,
            auth: auth_arg,
            identity,
            branch,
        },
        wait,
        timeout,
    ))
}

/// Parses one `fleetctl tailnet` subcommand.
fn parse_tailnet_command(verb: &str, rest: &[&str]) -> Result<Command, CliError> {
    match verb {
        "status" => match rest {
            [] => Ok(Command::TailnetStatus),
            _ => Err(CliError { message: usage() }),
        },
        "configure" => match rest {
            ["--client-id", client_id] => Ok(Command::TailnetConfigure {
                client_id: (*client_id).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "clear" => match rest {
            [] => Ok(Command::TailnetClear),
            _ => Err(CliError { message: usage() }),
        },
        "devices" => {
            let mut limit = None;
            let mut flags = rest.iter().copied();
            while let Some(flag) = flags.next() {
                match flag {
                    "--limit" => {
                        let value = flags.next().ok_or_else(|| CliError {
                            message: "--limit requires a value".to_owned(),
                        })?;
                        limit = Some(value.parse().map_err(|_| CliError {
                            message: format!("--limit must be a number, not {value:?}"),
                        })?);
                    }
                    other => {
                        return Err(CliError {
                            message: format!(
                                "unknown flag {other:?}; see the usage below\n\n{}",
                                usage()
                            ),
                        });
                    }
                }
            }
            Ok(Command::TailnetDevices { limit })
        }
        "import" => match rest {
            [node_id, "--user", user] => Ok(Command::TailnetImport {
                node_id: (*node_id).to_owned(),
                user: (*user).to_owned(),
                port: None,
            }),
            [node_id, "--user", user, "--port", port] => {
                let parsed = port.parse::<u16>().map_err(|_| CliError {
                    message: format!("--port must be a number, not {port:?}"),
                })?;
                Ok(Command::TailnetImport {
                    node_id: (*node_id).to_owned(),
                    user: (*user).to_owned(),
                    port: Some(parsed),
                })
            }
            _ => Err(CliError { message: usage() }),
        },
        _ => Err(CliError { message: usage() }),
    }
}

/// Parses one `fleetctl proxmox` subcommand.
#[allow(clippy::too_many_lines)]
fn parse_proxmox_command(verb: &str, rest: &[&str]) -> Result<Command, CliError> {
    match verb {
        "accounts" => match rest {
            [] => Ok(Command::ProxmoxAccounts),
            _ => Err(CliError { message: usage() }),
        },
        "create" => {
            let mut name = None;
            let mut host = None;
            let mut port = None;
            let mut token_id = None;
            let mut flags = rest.iter().copied();
            while let Some(flag) = flags.next() {
                match flag {
                    "--name" => {
                        name = Some(
                            flags
                                .next()
                                .ok_or_else(|| CliError {
                                    message: "--name requires a value".to_owned(),
                                })?
                                .to_owned(),
                        );
                    }
                    "--host" => {
                        host = Some(
                            flags
                                .next()
                                .ok_or_else(|| CliError {
                                    message: "--host requires a value".to_owned(),
                                })?
                                .to_owned(),
                        );
                    }
                    "--port" => {
                        let value = flags.next().ok_or_else(|| CliError {
                            message: "--port requires a value".to_owned(),
                        })?;
                        port = Some(value.parse().map_err(|_| CliError {
                            message: format!("--port must be a number, not {value:?}"),
                        })?);
                    }
                    "--token-id" => {
                        token_id = Some(
                            flags
                                .next()
                                .ok_or_else(|| CliError {
                                    message: "--token-id requires a value".to_owned(),
                                })?
                                .to_owned(),
                        );
                    }
                    other => {
                        return Err(CliError {
                            message: format!(
                                "unknown flag {other:?}; see the usage below\n\n{}",
                                usage()
                            ),
                        });
                    }
                }
            }
            Ok(Command::ProxmoxCreate {
                name: name.ok_or_else(|| CliError {
                    message: "--name is required".to_owned(),
                })?,
                host: host.ok_or_else(|| CliError {
                    message: "--host is required".to_owned(),
                })?,
                port,
                token_id: token_id.ok_or_else(|| CliError {
                    message: "--token-id is required".to_owned(),
                })?,
            })
        }
        "delete" => match rest {
            [account_id] => Ok(Command::ProxmoxDelete {
                account_id: (*account_id).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "observe" => match rest {
            [account_id] => Ok(Command::ProxmoxObserve {
                account_id: (*account_id).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "confirm" => match rest {
            [account_id, "--fingerprint", fingerprint] => Ok(Command::ProxmoxConfirm {
                account_id: (*account_id).to_owned(),
                fingerprint: (*fingerprint).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "discover" => match rest {
            [account_id] => Ok(Command::ProxmoxDiscover {
                account_id: (*account_id).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "guests" => match rest {
            [account_id] => Ok(Command::ProxmoxGuests {
                account_id: (*account_id).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "observe-guest" => match rest {
            [account_id, vmid, "--machine", machine_id] => {
                let parsed = vmid.parse::<u32>().map_err(|_| CliError {
                    message: format!("the VMID must be a number, not {vmid:?}"),
                })?;
                Ok(Command::ProxmoxObserveGuest {
                    account_id: (*account_id).to_owned(),
                    vmid: parsed,
                    machine_id: (*machine_id).to_owned(),
                })
            }
            _ => Err(CliError { message: usage() }),
        },
        "snapshot" | "snapshot-revert" | "snapshot-delete" | "clone" | "template"
        | "task-cancel" => {
            let mut account_id = None;
            let mut node = None;
            let mut vmid = None;
            let mut wait = false;
            let mut timeout = None;
            let mut flags = rest.iter().copied();
            while let Some(flag) = flags.next() {
                match flag {
                    "--account" => {
                        account_id = Some(
                            flags
                                .next()
                                .ok_or_else(|| CliError {
                                    message: "--account requires a value".to_owned(),
                                })?
                                .to_owned(),
                        );
                    }
                    "--node" => {
                        node = Some(
                            flags
                                .next()
                                .ok_or_else(|| CliError {
                                    message: "--node requires a value".to_owned(),
                                })?
                                .to_owned(),
                        );
                    }
                    "--vmid" => {
                        let value = flags.next().ok_or_else(|| CliError {
                            message: "--vmid requires a value".to_owned(),
                        })?;
                        vmid = Some(value.parse().map_err(|_| CliError {
                            message: format!("--vmid must be a number, not {value:?}"),
                        })?);
                    }
                    "--wait" => wait = true,
                    "--timeout" => {
                        let value = flags.next().ok_or_else(|| CliError {
                            message: "--timeout requires a value".to_owned(),
                        })?;
                        timeout = Some(value.parse().map_err(|_| CliError {
                            message: format!("--timeout must be a number, not {value:?}"),
                        })?);
                    }
                    other => {
                        return Err(CliError {
                            message: format!(
                                "unknown flag {other:?}; see the usage below\n\n{}",
                                usage()
                            ),
                        });
                    }
                }
            }
            // The action's parameters arrive as JSON on standard input at
            // request time; the CLI never puts them in argv.
            Ok(Command::ProxmoxDestructive {
                action: verb.to_owned(),
                account_id: account_id.ok_or_else(|| CliError {
                    message: "--account is required".to_owned(),
                })?,
                node: node.ok_or_else(|| CliError {
                    message: "--node is required".to_owned(),
                })?,
                vmid: vmid.ok_or_else(|| CliError {
                    message: "--vmid is required".to_owned(),
                })?,
                params: None,
                wait,
                timeout,
            })
        }
        "start" | "stop" | "shutdown" | "reboot" => {
            let mut account_id = None;
            let mut node = None;
            let mut vmid = None;
            let mut wait = false;
            let mut timeout = None;
            let mut flags = rest.iter().copied();
            while let Some(flag) = flags.next() {
                match flag {
                    "--account" => {
                        account_id = Some(
                            flags
                                .next()
                                .ok_or_else(|| CliError {
                                    message: "--account requires a value".to_owned(),
                                })?
                                .to_owned(),
                        );
                    }
                    "--node" => {
                        node = Some(
                            flags
                                .next()
                                .ok_or_else(|| CliError {
                                    message: "--node requires a value".to_owned(),
                                })?
                                .to_owned(),
                        );
                    }
                    "--vmid" => {
                        let value = flags.next().ok_or_else(|| CliError {
                            message: "--vmid requires a value".to_owned(),
                        })?;
                        vmid = Some(value.parse().map_err(|_| CliError {
                            message: format!("--vmid must be a number, not {value:?}"),
                        })?);
                    }
                    "--wait" => wait = true,
                    "--timeout" => {
                        let value = flags.next().ok_or_else(|| CliError {
                            message: "--timeout requires a value".to_owned(),
                        })?;
                        timeout = Some(value.parse().map_err(|_| CliError {
                            message: format!("--timeout must be a number, not {value:?}"),
                        })?);
                    }
                    other => {
                        return Err(CliError {
                            message: format!(
                                "unknown flag {other:?}; see the usage below\n\n{}",
                                usage()
                            ),
                        });
                    }
                }
            }
            Ok(Command::ProxmoxLifecycle {
                action: verb.to_owned(),
                account_id: account_id.ok_or_else(|| CliError {
                    message: "--account is required".to_owned(),
                })?,
                node: node.ok_or_else(|| CliError {
                    message: "--node is required".to_owned(),
                })?,
                vmid: vmid.ok_or_else(|| CliError {
                    message: "--vmid is required".to_owned(),
                })?,
                wait,
                timeout,
            })
        }
        _ => Err(CliError { message: usage() }),
    }
}

fn usage() -> String {
    format!(
        "Usage: fleetctl [--url <controller>] [--socket <path>] [--output json|text] <command>\n\nCommands:\n  status\n  system\n  operations list [--limit <n>]\n  operations get <id>\n  operations cancel <id>\n  machines list [--tag <tag>] [--group <group>] [--capability <ns:name>] [--status <state>] [--limit <n>]\n  machines get <id>\n  machines onboard create --user <user> --host <host> [--port <n>] [--name <name>] [--description <text>] [--tag <tag>]... [--group <group>]... --auth agent|identity-file [--identity <path>]\n  machines onboard list [--limit <n>]\n  machines onboard get <draft-id>\n  machines onboard test <draft-id> [--wait] [--timeout <seconds>]\n  machines onboard discover <draft-id> [--wait] [--timeout <seconds>]\n  machines onboard confirm <draft-id> --fingerprint <SHA256:...>\n  machines onboard add <draft-id>\n  machines onboard cancel <draft-id>\n  projects list [--remote-prefix <p>] [--name-substring <s>] [--limit <n>]\n  projects get <id>\n  projects create --remote <url> --name <name> [--description <text>]\n  projects update <id> --name <name> [--description <text>]\n  projects delete <id>\n  projects discover <id> <machine-id> --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--wait] [--timeout <s>]\n  projects record <id> <machine-id> (the discovery result is read from stdin)\n  projects ready <id> <machine-id> --root <path> [--dry-run] --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--wait] [--timeout <s>]\n  projects clone <id> <machine-id> --root <path> [--branch <name>] --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--wait] [--timeout <s>]\n  projects pull <id> <machine-id> --root <path> --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--wait] [--timeout <s>]\n  projects status <id> <machine-id> --root <path> --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--wait] [--timeout <s>]\n  projects write-config <id> <machine-id> --root <path> --file <name> --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--wait] [--timeout <s>] (contents from stdin)\n  skills probe <machine-id> --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--skills-root <path>] [--artifact-url <url> --artifact-sha256 <digest>] [--wait] [--timeout <s>]\n  skills deploy <machine-id> --skill <id> --agent <id>... --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--skills-root <path>] [--dry-run] [--wait] [--timeout <s>]\n  skills undeploy <machine-id> --skill <id> --agent <id>... --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--skills-root <path>] [--dry-run] [--wait] [--timeout <s>]\n  frogenv status|setup|login|request|sync <machine-id> --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--wait] [--timeout <s>]\n  frogenv run <machine-id> --root <path> --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--wait] [--timeout <s>] -- <command> [args...]\n  mise inventory|status <machine-id> --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--wait] [--timeout <s>]\n  mise install <machine-id> --tool <name> --version <pin> --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--wait] [--timeout <s>]\n  mise exec <machine-id> --root <path> --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--wait] [--timeout <s>] -- <command> [args...]\n  apply <machine-id> --plan-id <id> --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--wait] [--timeout <s>] (the plan JSON is read from stdin)\n  tailnet status\n  tailnet configure --client-id <id> (the client secret is read from stdin)\n  tailnet clear\n  tailnet devices [--limit <n>]\n  tailnet import <node-id> --user <user> [--port <n>]\n  proxmox accounts\n  proxmox create --name <name> --host <host> [--port <n>] --token-id <id> (the token secret is read from stdin)\n  proxmox delete <account-id>\n  proxmox observe <account-id>\n  proxmox confirm <account-id> --fingerprint <SHA256>\n  proxmox discover <account-id>\n  proxmox guests <account-id>\n  proxmox observe-guest <account-id> <vmid> --machine <machine-id>\n  machines install-node <machine-id> --endpoint <endpoint-id> --auth agent|identity-file [--identity <path>] [--artifact-url <url> --artifact-sha256 <digest>] [--controller-url <url>] [--install-timeout <s>] [--connect-timeout <s>] [--wait] [--timeout <s>]\n\n`status` prefers the node's local socket (default {DEFAULT_SOCKET}); `--url` is the explicit direct-controller override. Other commands talk to the controller, which defaults to {DEFAULT_URL}."
    )
}

/// Parses one `machines onboard` subcommand.
fn parse_onboard_command(verb: &str, rest: &[&str]) -> Result<Command, CliError> {
    match verb {
        "create" => parse_onboard_create(rest),
        "list" => {
            let mut limit = None;
            let mut flags = rest.iter().copied();
            while let Some(flag) = flags.next() {
                match flag {
                    "--limit" => {
                        let value = flags.next().ok_or_else(|| CliError {
                            message: "--limit requires a value".to_owned(),
                        })?;
                        limit = Some(value.parse().map_err(|_| CliError {
                            message: format!("--limit must be a number, not {value:?}"),
                        })?);
                    }
                    other => {
                        return Err(CliError {
                            message: format!(
                                "unknown flag {other:?}; see the usage below\n\n{}",
                                usage()
                            ),
                        });
                    }
                }
            }
            Ok(Command::MachinesOnboardList { limit })
        }
        "get" => match rest {
            [id] => Ok(Command::MachinesOnboardGet {
                id: (*id).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "test" => match rest {
            [id, flags @ ..] => parse_onboard_stage(id, flags, false),
            _ => Err(CliError { message: usage() }),
        },
        "discover" => match rest {
            [id, flags @ ..] => parse_onboard_stage(id, flags, true),
            _ => Err(CliError { message: usage() }),
        },
        "confirm" => match rest {
            [id, "--fingerprint", fingerprint] => Ok(Command::MachinesOnboardConfirm {
                id: (*id).to_owned(),
                fingerprint: (*fingerprint).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "add" => match rest {
            [id] => Ok(Command::MachinesOnboardAdd {
                id: (*id).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        "cancel" => match rest {
            [id] => Ok(Command::MachinesOnboardCancel {
                id: (*id).to_owned(),
            }),
            _ => Err(CliError { message: usage() }),
        },
        _ => Err(CliError { message: usage() }),
    }
}

/// Parses `machines install-node <machineId>` and its flags. The artifact
/// flags are optional: omitted together, the controller selects the package
/// for the machine's own platform (the orchestrated install). The
/// controller URL defaults to the CLI's own `--url`, because the node must
/// reach the same controller this command talks to.
fn parse_install_node(machine_id: &str, rest: &[&str], url: &str) -> Result<Command, CliError> {
    let mut endpoint: Option<String> = None;
    let mut auth: Option<String> = None;
    let mut identity: Option<String> = None;
    let mut artifact_url: Option<String> = None;
    let mut artifact_sha256: Option<String> = None;
    let mut controller_url: Option<String> = None;
    let mut install_timeout: u64 = 300;
    let mut connect_wait: Option<u64> = None;
    let mut wait = false;
    let mut poll_timeout: u64 = 300;
    let mut flags = rest.iter().copied();
    while let Some(flag) = flags.next() {
        let mut value = |name: &str| {
            flags.next().ok_or_else(|| CliError {
                message: format!("--{name} requires a value"),
            })
        };
        match flag {
            "--endpoint" => endpoint = Some(value("endpoint")?.to_owned()),
            "--auth" => auth = Some(value("auth")?.to_owned()),
            "--identity" => identity = Some(value("identity")?.to_owned()),
            "--artifact-url" => artifact_url = Some(value("artifact-url")?.to_owned()),
            "--artifact-sha256" => artifact_sha256 = Some(value("artifact-sha256")?.to_owned()),
            "--controller-url" => controller_url = Some(value("controller-url")?.to_owned()),
            "--install-timeout" => {
                let parsed = value("install-timeout")?;
                install_timeout = parsed.parse().map_err(|_| CliError {
                    message: format!("--install-timeout must be a number, not {parsed:?}"),
                })?;
            }
            "--connect-timeout" => {
                let parsed = value("connect-timeout")?;
                connect_wait = Some(parsed.parse().map_err(|_| CliError {
                    message: format!("--connect-timeout must be a number, not {parsed:?}"),
                })?);
            }
            "--wait" => wait = true,
            "--timeout" => {
                let parsed = value("timeout")?;
                poll_timeout = parsed.parse().map_err(|_| CliError {
                    message: format!("--timeout must be a number, not {parsed:?}"),
                })?;
            }
            other => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let auth = match (auth.as_deref(), identity) {
        (Some("agent"), None) => OnboardAuthArg::Agent,
        (Some("identity-file"), Some(path)) => OnboardAuthArg::IdentityFile(path),
        (Some("identity-file"), None) => {
            return Err(CliError {
                message: "--auth identity-file requires --identity <path>".to_owned(),
            });
        }
        (Some(other), _) => {
            return Err(CliError {
                message: format!("--auth must be agent or identity-file, not {other:?}"),
            });
        }
        (None, _) => {
            return Err(CliError {
                message: "--auth is required: agent or identity-file".to_owned(),
            });
        }
    };
    if artifact_url.is_some() != artifact_sha256.is_some() {
        return Err(CliError {
            message: "--artifact-url and --artifact-sha256 must be supplied together                      (or both omitted for the orchestrated install)"
                .to_owned(),
        });
    }
    Ok(Command::MachinesInstallNode {
        machine_id: machine_id.to_owned(),
        endpoint: endpoint.ok_or_else(|| CliError {
            message: "--endpoint <endpoint-id> is required".to_owned(),
        })?,
        auth,
        artifact_url,
        artifact_sha256,
        controller_url: controller_url.or_else(|| Some(url.to_owned())),
        install_timeout,
        connect_wait,
        wait,
        poll_timeout,
    })
}

/// Parses the flags of `machines onboard create`; tags and groups repeat.
fn parse_onboard_create(rest: &[&str]) -> Result<Command, CliError> {
    let mut user: Option<String> = None;
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut name: Option<String> = None;
    let mut description: Option<String> = None;
    let mut tags = Vec::new();
    let mut groups = Vec::new();
    let mut auth: Option<String> = None;
    let mut identity: Option<String> = None;
    let mut flags = rest.iter().copied();
    while let Some(flag) = flags.next() {
        let mut value = |name: &str| {
            flags.next().ok_or_else(|| CliError {
                message: format!("--{name} requires a value"),
            })
        };
        match flag {
            "--user" => user = Some(value("user")?.to_owned()),
            "--host" => host = Some(value("host")?.to_owned()),
            "--port" => {
                let parsed = value("port")?;
                port = Some(parsed.parse().map_err(|_| CliError {
                    message: format!("--port must be a number, not {parsed:?}"),
                })?);
            }
            "--name" => name = Some(value("name")?.to_owned()),
            "--description" => description = Some(value("description")?.to_owned()),
            "--tag" => tags.push(value("tag")?.to_owned()),
            "--group" => groups.push(value("group")?.to_owned()),
            "--auth" => auth = Some(value("auth")?.to_owned()),
            "--identity" => identity = Some(value("identity")?.to_owned()),
            other => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let auth = match (auth.as_deref(), identity) {
        (Some("agent"), None) => OnboardAuthArg::Agent,
        (Some("identity-file"), Some(path)) => OnboardAuthArg::IdentityFile(path),
        (Some("identity-file"), None) => {
            return Err(CliError {
                message: "--auth identity-file requires --identity <path>".to_owned(),
            });
        }
        (Some(other), _) => {
            return Err(CliError {
                message: format!("--auth must be agent or identity-file, not {other:?}"),
            });
        }
        (None, _) => {
            return Err(CliError {
                message: "--auth is required: agent or identity-file".to_owned(),
            });
        }
    };
    let user = user.ok_or_else(|| CliError {
        message: "--user is required".to_owned(),
    })?;
    let host = host.ok_or_else(|| CliError {
        message: "--host is required".to_owned(),
    })?;
    Ok(Command::MachinesOnboardCreate {
        user,
        host,
        port,
        name,
        description,
        tags,
        groups,
        auth,
    })
}

/// Parses the flags of the `test` and `discover` stages.
fn parse_onboard_stage(id: &str, rest: &[&str], discover: bool) -> Result<Command, CliError> {
    let mut wait = false;
    let mut timeout: u64 = if discover { 300 } else { 60 };
    let mut flags = rest.iter().copied();
    while let Some(flag) = flags.next() {
        match flag {
            "--wait" => wait = true,
            "--timeout" => {
                let value = flags.next().ok_or_else(|| CliError {
                    message: "--timeout requires a value".to_owned(),
                })?;
                timeout = value.parse().map_err(|_| CliError {
                    message: format!("--timeout must be a number, not {value:?}"),
                })?;
            }
            other => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let id = id.to_owned();
    if discover {
        Ok(Command::MachinesOnboardDiscover { id, wait, timeout })
    } else {
        Ok(Command::MachinesOnboardTest { id, wait, timeout })
    }
}

/// Runs one invocation, returning the text for stdout.
///
/// # Errors
///
/// Fails with a message for stderr on any refused or failed request; the
/// error's envelope code, when the controller produced one, is included so
/// scripts can branch on it.
pub fn run(invocation: &Invocation) -> Result<String, CliError> {
    if invocation.command == Command::Status && !invocation.url_explicit {
        // The local route: the daemon's constrained status surface, reached
        // without controller credentials. The override is explicit --url.
        #[cfg(unix)]
        let body = local_status(&invocation.socket)?;
        #[cfg(not(unix))]
        let body: Value = {
            let _ = &invocation.socket;
            return Err(CliError {
                message: "the node's local surface is only available on Unix platforms".to_owned(),
            });
        };
        return render_routed(invocation, &body, "local");
    }
    if invocation.command == Command::Status {
        // The explicit direct-controller override.
        let client = http_client()?;
        let response = client
            .get(format!("{}/api/v1/system", invocation.url))
            .header("x-correlation-id", uuid::Uuid::now_v7().to_string())
            .send()
            .map_err(|error| CliError {
                message: format!("the controller did not answer: {error}"),
            })?;
        let status = reqwest::StatusCode::as_u16(&response.status());
        let body: Value = response.json().map_err(|error| CliError {
            message: format!("the controller's answer was not JSON: {error}"),
        })?;
        if !(200..300).contains(&status) {
            let code = body["code"].as_str().unwrap_or("unknown");
            let message = body["message"].as_str().unwrap_or("no detail");
            return Err(CliError {
                message: format!("the controller refused ({status}, {code}): {message}"),
            });
        }
        return render_routed(invocation, &body, "controller");
    }

    let correlation_id = uuid::Uuid::now_v7().to_string();
    let client = http_client()?;

    let (method, path, query, request_body) = request_for(&invocation.command)?;

    let body = send(
        &client,
        invocation,
        method,
        &path,
        &query,
        request_body.as_ref(),
        correlation_id,
    )?;
    let body = follow_wait_stage(&client, invocation, body)?;
    let body = follow_review(&client, invocation, body)?;
    let body = follow_install_wait(&client, invocation, body)?;
    let body = follow_checkout_wait(&client, invocation, body)?;
    let payload = if body.get("items").is_some() {
        body
    } else {
        body.get("data").cloned().unwrap_or(body)
    };
    Ok(render(invocation, &payload))
}

/// The install command's `--wait`: chase the install operation to a terminal
/// state and answer with its outcome — connected, or the bounded failure
/// reason.
fn follow_install_wait(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    body: Value,
) -> Result<Value, CliError> {
    let Command::MachinesInstallNode {
        wait: true,
        poll_timeout,
        ..
    } = &invocation.command
    else {
        return Ok(body);
    };
    let operation_id = body["data"]["id"].as_str().unwrap_or_default().to_owned();
    if operation_id.is_empty() {
        return Err(CliError {
            message: "the controller did not answer with an operation id".to_owned(),
        });
    }
    wait_for_operation(client, invocation, &operation_id, *poll_timeout)
}

/// The destructive command's two-step flow: the review's answer carries
/// the token; the run request presents it with the identical payload, so
/// what runs is what was reviewed.
fn follow_review(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    body: Value,
) -> Result<Value, CliError> {
    let Command::ProxmoxDestructive {
        action,
        account_id,
        node,
        vmid,
        ..
    } = &invocation.command
    else {
        return Ok(body);
    };
    let Some(token) = body["data"]["reviewToken"].as_str() else {
        return Err(CliError {
            message: "the review did not answer with a token".to_owned(),
        });
    };
    // The reviewed params are the ones the controller echoed back: reusing
    // them guarantees the run's bytes match the reviewed bytes.
    let params_value = body["data"]["params"].clone();
    let run_body = serde_json::json!({
        "node": node,
        "reviewToken": token,
        "params": params_value,
        "timeoutSeconds": 300,
    });
    let correlation_id = uuid::Uuid::now_v7().to_string();
    send(
        client,
        invocation,
        reqwest::Method::POST,
        &format!("/api/v1/proxmox/accounts/{account_id}/guests/{vmid}/{action}/run"),
        &[],
        Some(&run_body),
        correlation_id,
    )
}

/// The `--wait` stages chase their own operation to a terminal state and
/// then answer with the refreshed draft: the review surface, not the
/// operation.
fn follow_wait_stage(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    body: Value,
) -> Result<Value, CliError> {
    let (Command::MachinesOnboardTest {
        id,
        wait: true,
        timeout,
    }
    | Command::MachinesOnboardDiscover {
        id,
        wait: true,
        timeout,
    }) = &invocation.command
    else {
        return Ok(body);
    };
    let operation_id = body["data"]["id"].as_str().unwrap_or_default().to_owned();
    wait_for_operation(client, invocation, &operation_id, *timeout)?;
    send(
        client,
        invocation,
        reqwest::Method::GET,
        &format!("/api/v1/machines/onboarding/drafts/{id}"),
        &[],
        None,
        uuid::Uuid::now_v7().to_string(),
    )
}

/// Polls a checkout operation to a terminal state when `--wait` was
/// supplied, then answers the operation's own body.
fn follow_checkout_wait(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    body: Value,
) -> Result<Value, CliError> {
    let wait = match &invocation.command {
        Command::ProjectsDiscover { wait, timeout, .. }
        | Command::ProjectsClone { wait, timeout, .. }
        | Command::ProjectsPull { wait, timeout, .. }
        | Command::ProjectsStatus { wait, timeout, .. }
        | Command::ProjectsWriteConfig { wait, timeout, .. }
        | Command::SkillsProbe { wait, timeout, .. }
        | Command::SkillsDeploy { wait, timeout, .. }
        | Command::SkillsUndeploy { wait, timeout, .. }
        | Command::FrogenvOperation { wait, timeout, .. }
        | Command::MiseOperation { wait, timeout, .. }
        | Command::ProjectsReady { wait, timeout, .. }
        | Command::ApplyWorkflow { wait, timeout, .. }
        | Command::ProxmoxLifecycle { wait, timeout, .. }
        | Command::ProxmoxDestructive { wait, timeout, .. } => (*wait, *timeout),
        _ => return Ok(body),
    };
    if !wait.0 {
        return Ok(body);
    }
    let operation_id = body["data"]["id"].as_str().unwrap_or_default().to_owned();
    if operation_id.is_empty() {
        return Ok(body);
    }
    wait_for_operation(client, invocation, &operation_id, wait.1.unwrap_or(300))
}

/// Renders one decoded payload for the invocation's output mode.
fn render(invocation: &Invocation, payload: &Value) -> String {
    match invocation.output {
        Output::Json => serde_json::to_string_pretty(payload)
            .unwrap_or_else(|error| format!("{{\"code\":\"internal\",\"message\":\"{error}\"}}")),
        Output::Text => match invocation.command {
            // The machine surface has its own renderer: an empty page must
            // say "no machines", not borrow the operations table.
            Command::MachinesList { .. } | Command::MachinesGet { .. } => {
                render_machines(Some(payload))
            }
            Command::MachinesOnboardList { .. }
            | Command::MachinesOnboardGet { .. }
            | Command::MachinesOnboardCreate { .. }
            | Command::MachinesOnboardConfirm { .. }
            | Command::MachinesOnboardTest { .. }
            | Command::MachinesOnboardDiscover { .. }
            | Command::MachinesOnboardAdd { .. }
            | Command::MachinesOnboardCancel { .. }
            | Command::TailnetImport { .. } => render_onboarding(Some(payload)),
            Command::ProjectsCreate { .. } | Command::ProjectsUpdate { .. } => {
                render_project_mutation(payload)
            }
            Command::ProjectsDelete { .. } => render_project_deleted(),
            Command::ProjectsList { .. }
            | Command::ProjectsGet { .. }
            | Command::ProjectsDiscover { .. }
            | Command::ProjectsRecord { .. } => render_projects(Some(payload)),
            Command::TailnetStatus
            | Command::TailnetConfigure { .. }
            | Command::TailnetClear
            | Command::TailnetDevices { .. } => render_tailnet(Some(payload)),
            Command::ProxmoxAccounts
            | Command::ProxmoxCreate { .. }
            | Command::ProxmoxDelete { .. }
            | Command::ProxmoxObserve { .. }
            | Command::ProxmoxConfirm { .. }
            | Command::ProxmoxDiscover { .. }
            | Command::ProxmoxGuests { .. }
            | Command::ProxmoxObserveGuest { .. } => render_proxmox(Some(payload)),
            _ => render_text(Some(payload)),
        },
    }
}

/// The controller request for one command: method, path, query, and body,
/// in API order.
#[allow(clippy::too_many_lines)]
fn request_for(command: &Command) -> Result<RequestShape, CliError> {
    Ok(match command {
        // `status` took one of the two routes above.
        Command::Status => unreachable!("the status command returned before dispatch"),
        Command::System => (
            reqwest::Method::GET,
            "/api/v1/system".to_owned(),
            Vec::new(),
            None,
        ),
        Command::OperationsList { .. } => {
            let limit = match command {
                Command::OperationsList { limit: Some(limit) } => format!("?limit={limit}"),
                _ => String::new(),
            };
            (
                reqwest::Method::GET,
                format!("/api/v1/operations{limit}"),
                Vec::new(),
                None,
            )
        }
        Command::OperationsGet { id } => (
            reqwest::Method::GET,
            format!("/api/v1/operations/{id}"),
            Vec::new(),
            None,
        ),
        Command::OperationsCancel { id } => (
            reqwest::Method::POST,
            format!("/api/v1/operations/{id}/cancel"),
            Vec::new(),
            None,
        ),
        Command::MachinesList {
            tag,
            group,
            capability,
            status,
            limit,
        } => (
            reqwest::Method::GET,
            "/api/v1/machines".to_owned(),
            machines_list_query(
                tag.as_ref(),
                group.as_ref(),
                capability.as_ref(),
                status.as_ref(),
                *limit,
            ),
            None,
        ),
        Command::MachinesGet { id } => (
            reqwest::Method::GET,
            format!("/api/v1/machines/{id}"),
            Vec::new(),
            None,
        ),
        command @ (Command::MachinesOnboardCreate { .. }
        | Command::MachinesOnboardList { .. }
        | Command::MachinesOnboardGet { .. }
        | Command::MachinesOnboardTest { .. }
        | Command::MachinesOnboardDiscover { .. }
        | Command::MachinesOnboardConfirm { .. }
        | Command::MachinesOnboardAdd { .. }
        | Command::MachinesOnboardCancel { .. }) => onboard_request(command),
        Command::MachinesInstallNode { .. } => install_node_request(command),
        Command::ProjectsList {
            remote_prefix,
            name_substring,
            limit,
        } => (
            reqwest::Method::GET,
            "/api/v1/projects".to_owned(),
            {
                let mut query = Vec::new();
                if let Some(prefix) = remote_prefix {
                    query.push(("remotePrefix", prefix.clone()));
                }
                if let Some(substring) = name_substring {
                    query.push(("nameSubstring", substring.clone()));
                }
                if let Some(limit) = limit {
                    query.push(("limit", limit.to_string()));
                }
                query
            },
            None,
        ),
        Command::ProjectsGet { id } => (
            reqwest::Method::GET,
            format!("/api/v1/projects/{id}"),
            Vec::new(),
            None,
        ),
        Command::ProjectsCreate {
            remote,
            name,
            description,
        } => {
            let mut body = serde_json::json!({ "remote": remote, "name": name });
            if let Some(description) = description {
                body["description"] = serde_json::json!(description);
            }
            (
                reqwest::Method::POST,
                "/api/v1/projects".to_owned(),
                Vec::new(),
                Some(body),
            )
        }
        Command::ProjectsUpdate {
            id,
            name,
            description,
        } => {
            // An absent description means "keep the current one": the API
            // treats a missing field as no change.
            let body = match description {
                Some(description) => {
                    serde_json::json!({ "name": name, "description": description })
                }
                None => serde_json::json!({ "name": name }),
            };
            (
                reqwest::Method::PATCH,
                format!("/api/v1/projects/{id}"),
                Vec::new(),
                Some(body),
            )
        }
        Command::ProjectsDelete { id } => (
            reqwest::Method::DELETE,
            format!("/api/v1/projects/{id}"),
            Vec::new(),
            None,
        ),
        Command::ProjectsReady {
            id,
            machine,
            endpoint,
            root,
            dry_run,
            auth,
            ..
        } => (
            reqwest::Method::POST,
            format!("/api/v1/projects/{id}/ready"),
            Vec::new(),
            Some(serde_json::json!({
                "machineId": machine,
                "endpointId": endpoint,
                "auth": checkout_auth_value(auth),
                "root": root,
                "dryRun": dry_run,
                "timeoutSeconds": 1800,
            })),
        ),
        Command::ProjectsDiscover {
            id,
            machine,
            endpoint,
            auth,
            ..
        } => (
            reqwest::Method::POST,
            format!("/api/v1/projects/{id}/discoveries"),
            Vec::new(),
            Some(checkout_request_body(machine, endpoint, auth)),
        ),
        Command::ProjectsRecord { id, machine } => (
            reqwest::Method::POST,
            format!("/api/v1/projects/{id}/checkouts"),
            Vec::new(),
            Some(record_checkouts_body(machine)?),
        ),
        Command::ProjectsClone {
            id: _,
            machine,
            endpoint,
            root,
            branch,
            auth,
            ..
        } => (
            reqwest::Method::POST,
            "/api/v1/operations".to_owned(),
            Vec::new(),
            Some(checkout_operation_body(
                "projects.clone",
                machine,
                endpoint,
                auth,
                Some(root.clone()),
                branch.clone(),
            )),
        ),
        Command::ProjectsPull {
            id: _,
            machine,
            endpoint,
            root,
            auth,
            ..
        } => (
            reqwest::Method::POST,
            "/api/v1/operations".to_owned(),
            Vec::new(),
            Some(checkout_operation_body(
                "projects.pull",
                machine,
                endpoint,
                auth,
                Some(root.clone()),
                None,
            )),
        ),
        Command::ProjectsStatus {
            id: _,
            machine,
            endpoint,
            root,
            auth,
            ..
        } => (
            reqwest::Method::POST,
            "/api/v1/operations".to_owned(),
            Vec::new(),
            Some(checkout_operation_body(
                "projects.status",
                machine,
                endpoint,
                auth,
                Some(root.clone()),
                None,
            )),
        ),
        Command::ProjectsWriteConfig {
            id: _,
            machine,
            endpoint,
            root,
            file_name,
            auth,
            ..
        } => (
            reqwest::Method::POST,
            "/api/v1/operations".to_owned(),
            Vec::new(),
            Some(checkout_write_config_body(
                machine, endpoint, auth, root, file_name,
            )?),
        ),
        Command::SkillsProbe {
            machine,
            endpoint,
            auth,
            skills_root,
            artifact_url,
            artifact_sha256,
            ..
        } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/{machine}/skills/operations"),
            Vec::new(),
            Some(skills_request_body(
                machine,
                endpoint,
                auth,
                None,
                &[],
                skills_root.as_ref(),
                false,
                None,
                artifact_url.as_ref(),
                artifact_sha256.as_ref(),
            )),
        ),
        Command::SkillsDeploy {
            machine,
            endpoint,
            auth,
            skill,
            agents,
            skills_root,
            dry_run,
            ..
        } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/{machine}/skills/operations"),
            Vec::new(),
            Some(skills_request_body(
                machine,
                endpoint,
                auth,
                Some(skill.as_str()),
                agents,
                skills_root.as_ref(),
                *dry_run,
                Some("deploy"),
                None,
                None,
            )),
        ),
        Command::SkillsUndeploy {
            machine,
            endpoint,
            auth,
            skill,
            agents,
            skills_root,
            dry_run,
            ..
        } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/{machine}/skills/operations"),
            Vec::new(),
            Some(skills_request_body(
                machine,
                endpoint,
                auth,
                Some(skill.as_str()),
                agents,
                skills_root.as_ref(),
                *dry_run,
                Some("undeploy"),
                None,
                None,
            )),
        ),
        Command::FrogenvOperation {
            machine,
            endpoint,
            auth,
            action,
            root,
            command,
            ..
        } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/{machine}/frogenv/operations"),
            Vec::new(),
            Some(frogenv_request_body(
                machine,
                endpoint,
                auth,
                action,
                root.as_ref(),
                command,
            )),
        ),
        Command::MiseOperation {
            machine,
            endpoint,
            auth,
            action,
            tool,
            version,
            root,
            command,
            ..
        } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/{machine}/mise/operations"),
            Vec::new(),
            Some(mise_request_body(
                machine,
                endpoint,
                auth,
                action,
                tool.as_ref(),
                version.as_ref(),
                root.as_ref(),
                command,
            )),
        ),
        Command::ApplyWorkflow {
            machine,
            endpoint,
            auth,
            plan_id,
            ..
        } => {
            // The plan document may span multiple lines: read stdin to
            // EOF, then split it into its actions and approvals so both
            // request fields are populated.
            let document: serde_json::Value =
                serde_json::from_str(&read_stdin_to_end("the plan JSON")?).map_err(|error| {
                    CliError {
                        message: format!("the plan JSON is not valid: {error}"),
                    }
                })?;
            let actions = document.get("actions").cloned().ok_or_else(|| CliError {
                message: "the plan document must carry an actions array".to_owned(),
            })?;
            let approvals = document.get("approvals").cloned().unwrap_or_default();
            (
                reqwest::Method::POST,
                format!("/api/v1/machines/{machine}/apply"),
                Vec::new(),
                Some(serde_json::json!({
                    "machineId": machine,
                    "endpointId": endpoint,
                    "auth": checkout_auth_value(auth),
                    "planId": plan_id,
                    "actions": actions,
                    "approvals": approvals,
                    "timeoutSeconds": 1800,
                })),
            )
        }
        Command::TailnetStatus => (
            reqwest::Method::GET,
            "/api/v1/tailnet/status".to_owned(),
            Vec::new(),
            None,
        ),
        Command::TailnetConfigure { client_id } => (
            reqwest::Method::PUT,
            "/api/v1/tailnet/config".to_owned(),
            Vec::new(),
            Some(serde_json::json!({
                "clientId": client_id,
                "clientSecret": read_stdin_line("the OAuth client secret")?,
            })),
        ),
        Command::TailnetClear => (
            reqwest::Method::DELETE,
            "/api/v1/tailnet/config".to_owned(),
            Vec::new(),
            None,
        ),
        Command::TailnetDevices { limit } => (
            reqwest::Method::GET,
            "/api/v1/tailnet/devices".to_owned(),
            limit
                .map(|limit| vec![("limit", limit.to_string())])
                .unwrap_or_default(),
            None,
        ),
        Command::ProxmoxAccounts => (
            reqwest::Method::GET,
            "/api/v1/proxmox/accounts".to_owned(),
            Vec::new(),
            None,
        ),
        Command::ProxmoxCreate {
            name,
            host,
            port,
            token_id,
        } => {
            let mut body = serde_json::json!({
                "name": name,
                "host": host,
                "tokenId": token_id,
                "tokenSecret": read_stdin_line("the API token secret")?,
            });
            if let Some(port) = port {
                body["port"] = serde_json::json!(port);
            }
            (
                reqwest::Method::POST,
                "/api/v1/proxmox/accounts".to_owned(),
                Vec::new(),
                Some(body),
            )
        }
        Command::ProxmoxDelete { account_id } => (
            reqwest::Method::DELETE,
            format!("/api/v1/proxmox/accounts/{account_id}"),
            Vec::new(),
            None,
        ),
        Command::ProxmoxObserve { account_id } => (
            reqwest::Method::POST,
            format!("/api/v1/proxmox/accounts/{account_id}/observe"),
            Vec::new(),
            None,
        ),
        Command::ProxmoxConfirm {
            account_id,
            fingerprint,
        } => (
            reqwest::Method::POST,
            format!("/api/v1/proxmox/accounts/{account_id}/confirm"),
            Vec::new(),
            Some(serde_json::json!({ "fingerprint": fingerprint })),
        ),
        Command::ProxmoxDiscover { account_id } => (
            reqwest::Method::GET,
            format!("/api/v1/proxmox/accounts/{account_id}/discovery"),
            Vec::new(),
            None,
        ),
        Command::ProxmoxGuests { account_id } => (
            reqwest::Method::GET,
            format!("/api/v1/proxmox/accounts/{account_id}/guests"),
            Vec::new(),
            None,
        ),
        Command::ProxmoxObserveGuest {
            account_id,
            vmid,
            machine_id,
        } => (
            reqwest::Method::POST,
            format!("/api/v1/proxmox/accounts/{account_id}/guests/{vmid}/observe"),
            Vec::new(),
            Some(serde_json::json!({ "machineId": machine_id })),
        ),
        Command::ProxmoxDestructive {
            action,
            account_id,
            node,
            vmid,
            params,
            ..
        } => {
            // Step one: the review. The run request is composed after the
            // review's token arrives (see follow_review). The parameters
            // arrive as JSON on standard input; the CLI never puts them
            // in argv.
            let text = match params.as_deref() {
                Some(text) => text.to_owned(),
                None => read_stdin_line("the action parameters as JSON")?,
            };
            let params_value: serde_json::Value =
                serde_json::from_str(&text).map_err(|error| CliError {
                    message: format!("the action parameters are not valid JSON: {error}"),
                })?;
            (
                reqwest::Method::POST,
                format!("/api/v1/proxmox/accounts/{account_id}/guests/{vmid}/{action}/review"),
                Vec::new(),
                Some(serde_json::json!({
                    "node": node,
                    "params": params_value,
                })),
            )
        }
        Command::ProxmoxLifecycle {
            action,
            account_id,
            node,
            vmid,
            timeout,
            ..
        } => (
            reqwest::Method::POST,
            format!("/api/v1/proxmox/accounts/{account_id}/guests/{vmid}/{action}"),
            Vec::new(),
            Some(serde_json::json!({
                "node": node,
                "vmid": vmid,
                "timeoutSeconds": timeout.unwrap_or(300),
            })),
        ),
        Command::TailnetImport {
            node_id,
            user,
            port,
        } => {
            let mut body = serde_json::json!({ "user": user });
            if let Some(port) = port {
                body["port"] = serde_json::json!(port);
            }
            (
                reqwest::Method::POST,
                format!("/api/v1/tailnet/devices/{node_id}/import"),
                Vec::new(),
                Some(body),
            )
        }
    })
}

/// The install-node request: a durable `machine.install-fleetd` operation
/// whose payload carries no secret — the enrollment token is minted inside
/// the executor at install time.
fn install_node_request(command: &Command) -> RequestShape {
    let Command::MachinesInstallNode {
        machine_id,
        endpoint,
        auth,
        artifact_url,
        artifact_sha256,
        controller_url,
        install_timeout,
        connect_wait,
        ..
    } = command
    else {
        unreachable!("install_node_request serves install commands only");
    };
    let auth_value = match auth {
        OnboardAuthArg::Agent => serde_json::json!({ "type": "agent" }),
        OnboardAuthArg::IdentityFile(path) => {
            serde_json::json!({ "type": "identityFile", "path": path })
        }
    };
    let mut payload = serde_json::json!({
        "machineId": machine_id,
        "endpointId": endpoint,
        "auth": auth_value,
        "timeoutSeconds": install_timeout,
    });
    if let (Some(artifact_url), Some(artifact_sha256)) = (artifact_url, artifact_sha256) {
        payload["artifactUrl"] = serde_json::json!(artifact_url);
        payload["artifactSha256"] = serde_json::json!(artifact_sha256);
    }
    if let Some(controller_url) = controller_url {
        payload["controllerUrl"] = serde_json::json!(controller_url);
    }
    if let Some(connect_wait) = connect_wait {
        payload["connectWaitSeconds"] = serde_json::json!(connect_wait);
    }
    let slack = connect_wait.unwrap_or(60) + 120;
    (
        reqwest::Method::POST,
        "/api/v1/operations".to_owned(),
        Vec::new(),
        Some(serde_json::json!({
            "kind": "machine.install-fleetd",
            "payloadJson": payload.to_string(),
            "deadlineAt": fleet_now_millis() + (install_timeout + slack) * 1000,
        })),
    )
}

/// Reads one line from standard input, for write-only secrets.
/// Reads standard input to EOF: multi-line documents (an apply plan)
/// arrive whole.
fn read_stdin_to_end(what: &str) -> Result<String, CliError> {
    use std::io::Read as _;
    let mut document = String::new();
    std::io::stdin()
        .read_to_string(&mut document)
        .map_err(|error| CliError {
            message: format!("cannot read {what} from stdin: {error}"),
        })?;
    let document = document.trim().to_owned();
    if document.is_empty() {
        return Err(CliError {
            message: format!("{what} must not be empty"),
        });
    }
    Ok(document)
}

fn read_stdin_line(what: &str) -> Result<String, CliError> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|error| CliError {
            message: format!("cannot read {what} from stdin: {error}"),
        })?;
    let line = line.trim().to_owned();
    if line.is_empty() {
        return Err(CliError {
            message: format!("{what} must not be empty"),
        });
    }
    Ok(line)
}

/// Reads standard input to EOF: JSON documents are multi-line. Only the
/// document inputs use this; single-line secrets keep the newline-
/// terminating reader.
fn read_stdin_to_eof(what: &str) -> Result<String, CliError> {
    use std::io::Read as _;
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .map_err(|error| CliError {
            message: format!("cannot read {what} from stdin: {error}"),
        })?;
    let text = text.trim().to_owned();
    if text.is_empty() {
        return Err(CliError {
            message: format!("{what} must not be empty"),
        });
    }
    Ok(text)
}

/// Wall-clock now, in epoch milliseconds.
fn fleet_now_millis() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}
/// The onboarding requests: one dispatch, in API order. The create body
/// carries only what was supplied, so the controller's defaults apply.
fn onboard_request(command: &Command) -> RequestShape {
    match command {
        Command::MachinesOnboardCreate {
            user,
            host,
            port,
            name,
            description,
            tags,
            groups,
            auth,
        } => {
            let auth_value = match auth {
                OnboardAuthArg::Agent => serde_json::json!({ "type": "agent" }),
                OnboardAuthArg::IdentityFile(path) => {
                    serde_json::json!({ "type": "identityFile", "path": path })
                }
            };
            let mut body = serde_json::json!({
                "user": user,
                "host": host,
                "auth": auth_value,
            });
            if let Some(port) = port {
                body["port"] = serde_json::json!(port);
            }
            if let Some(name) = name {
                body["name"] = serde_json::json!(name);
            }
            if let Some(description) = description {
                body["description"] = serde_json::json!(description);
            }
            if !tags.is_empty() {
                body["tags"] = serde_json::json!(tags);
            }
            if !groups.is_empty() {
                body["groups"] = serde_json::json!(groups);
            }
            (
                reqwest::Method::POST,
                "/api/v1/machines/onboarding/drafts".to_owned(),
                Vec::new(),
                Some(body),
            )
        }
        Command::MachinesOnboardList { limit } => (
            reqwest::Method::GET,
            "/api/v1/machines/onboarding/drafts".to_owned(),
            limit
                .map(|limit| vec![("limit", limit.to_string())])
                .unwrap_or_default(),
            None,
        ),
        Command::MachinesOnboardGet { id } => (
            reqwest::Method::GET,
            format!("/api/v1/machines/onboarding/drafts/{id}"),
            Vec::new(),
            None,
        ),
        Command::MachinesOnboardTest { id, .. } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/onboarding/drafts/{id}/test"),
            Vec::new(),
            None,
        ),
        Command::MachinesOnboardDiscover { id, .. } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/onboarding/drafts/{id}/discover"),
            Vec::new(),
            None,
        ),
        Command::MachinesOnboardConfirm { id, fingerprint } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/onboarding/drafts/{id}/confirm-host-key"),
            Vec::new(),
            Some(serde_json::json!({ "fingerprint": fingerprint })),
        ),
        Command::MachinesOnboardAdd { id } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/onboarding/drafts/{id}/add"),
            Vec::new(),
            None,
        ),
        Command::MachinesOnboardCancel { id } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/onboarding/drafts/{id}/cancel"),
            Vec::new(),
            None,
        ),
        _ => unreachable!("onboard_request serves onboarding commands only"),
    }
}

/// The machines-list query parameters, in API order.
fn machines_list_query(
    tag: Option<&String>,
    group: Option<&String>,
    capability: Option<&String>,
    status: Option<&String>,
    limit: Option<u32>,
) -> Vec<(&'static str, String)> {
    let mut query: Vec<(&'static str, String)> = Vec::new();
    for (name, value) in [
        ("tag", tag),
        ("group", group),
        ("capability", capability),
        ("status", status),
    ] {
        if let Some(value) = value {
            query.push((name, value.clone()));
        }
    }
    if let Some(limit) = limit {
        query.push(("limit", limit.to_string()));
    }
    query
}

/// Sends one controller request and answers the decoded body, refusing
/// non-2xx answers with the envelope's code and message. An empty 204 body
/// decodes as `null`.
fn send(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    method: reqwest::Method,
    path: &str,
    query: &[(&'static str, String)],
    body: Option<&Value>,
    correlation_id: String,
) -> Result<Value, CliError> {
    let mut request = client
        .request(method, format!("{}{}", invocation.url, path))
        .header("x-correlation-id", correlation_id);
    if !query.is_empty() {
        request = request.query(query);
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request.send().map_err(|error| CliError {
        message: format!("the controller did not answer: {error}"),
    })?;
    let status = reqwest::StatusCode::as_u16(&response.status());
    if status == 204 {
        return Ok(Value::Null);
    }
    let body: Value = response.json().map_err(|error| CliError {
        message: format!("the controller's answer was not JSON: {error}"),
    })?;
    if !(200..300).contains(&status) {
        let code = body["code"].as_str().unwrap_or("unknown");
        let message = body["message"].as_str().unwrap_or("no detail");
        return Err(CliError {
            message: format!("the controller refused ({status}, {code}): {message}"),
        });
    }
    Ok(body)
}

/// Polls one operation to a terminal state, answering its body. Polling
/// ends at the caller's bound; a still-running operation is an error, not a
/// hang.
fn wait_for_operation(
    client: &reqwest::blocking::Client,
    invocation: &Invocation,
    operation_id: &str,
    timeout_secs: u64,
) -> Result<Value, CliError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        let body = send(
            client,
            invocation,
            reqwest::Method::GET,
            &format!("/api/v1/operations/{operation_id}"),
            &[],
            None,
            uuid::Uuid::now_v7().to_string(),
        )?;
        let state = body["data"]["state"].as_str().unwrap_or("");
        if !["pending", "running", "cancelling"].contains(&state) {
            return Ok(body);
        }
        if std::time::Instant::now() >= deadline {
            return Err(CliError {
                message: format!(
                    "the operation {operation_id} did not reach a terminal state within {timeout_secs}s; it is still durable — check `fleetctl operations get {operation_id}`"
                ),
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

fn http_client() -> Result<reqwest::blocking::Client, CliError> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|error| CliError {
            message: format!("cannot build an HTTP client: {error}"),
        })
}

/// Reads the node's local status surface over the Unix socket, without any
/// controller credential.
#[cfg(unix)]
fn local_status(socket: &str) -> Result<Value, CliError> {
    use std::io::{Read as _, Write as _};
    let mut stream = std::os::unix::net::UnixStream::connect(socket).map_err(|error| CliError {
        message: format!(
            "the node's local surface at {socket} is unreachable: {error}; \
                 is `fleetd run` active, or pass --url to talk to the controller directly?"
        ),
    })?;
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
    stream
        .write_all(b"GET /local/status HTTP/1.1\r\nHost: fleetd-local\r\nConnection: close\r\n\r\n")
        .map_err(|error| CliError {
            message: format!("the local request failed: {error}"),
        })?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| CliError {
            message: format!("the local response failed: {error}"),
        })?;
    let text = String::from_utf8_lossy(&response);
    let (_head, body) = text.split_once("\r\n\r\n").ok_or_else(|| CliError {
        message: "the local answer has no body separator".to_owned(),
    })?;
    serde_json::from_str(body.trim()).map_err(|error| CliError {
        message: format!("the local answer is not JSON: {error}"),
    })
}

/// Wraps a status body with its route and renders it.
fn render_routed(
    invocation: &Invocation,
    body: &Value,
    route: &'static str,
) -> Result<String, CliError> {
    let payload = serde_json::json!({ "route": route, "status": body });
    Ok(match invocation.output {
        Output::Json => serde_json::to_string_pretty(&payload).map_err(|error| CliError {
            message: format!("cannot render the answer: {error}"),
        })?,
        Output::Text => render_for_test(&payload),
    })
}

/// Renders one JSON value (or a page) as aligned human text.
/// Renders a JSON payload as human text; exposed for contract tests.
#[doc(hidden)]
#[must_use]
pub fn render_for_test(value: &Value) -> String {
    render_text(Some(value))
}

/// Renders the machine surface as human text; exposed for contract tests.
#[doc(hidden)]
#[must_use]
pub fn render_machines_for_test(value: &Value) -> String {
    render_machines(Some(value))
}

fn render_machines(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        let mut lines = vec![format!(
            "{:<24} {:<10} {:<32} {}",
            "NAME", "STATUS", "ENDPOINT", "TAGS"
        )];
        for item in items {
            lines.push(machine_line(item));
        }
        if items.is_empty() {
            lines.push("(no machines)".to_owned());
        }
        lines.join("\n")
    } else {
        machine_detail(value)
    }
}

fn render_text(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        let mut lines = vec![format!("{:<38} {:<10} {:<12}", "ID", "KIND", "STATE")];
        for item in items {
            lines.push(operation_line(item));
        }
        if items.is_empty() {
            lines.push("(no operations)".to_owned());
        }
        lines.join("\n")
    } else if value.get("kind").is_some() && value.get("state").is_some() {
        operation_detail(value)
    } else {
        // System view.
        let mut lines = Vec::new();
        for (key, val) in value.as_object().into_iter().flatten() {
            let rendered = match val {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            lines.push(format!("{key}: {rendered}"));
        }
        lines.join("\n")
    }
}

fn operation_line(operation: &Value) -> String {
    format!(
        "{:<38} {:<10} {:<12}",
        operation["id"].as_str().unwrap_or("-"),
        operation["kind"].as_str().unwrap_or("-"),
        operation["state"].as_str().unwrap_or("-")
    )
}

/// Renders the onboarding surface as human text; exposed for contract tests.
#[doc(hidden)]
#[must_use]
pub fn render_onboarding_for_test(value: &Value) -> String {
    render_onboarding(Some(value))
}

fn render_onboarding(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        let mut lines = vec![format!(
            "{:<38} {:<10} {:<28} {}",
            "ID", "STAGE", "ENDPOINT", "NAME"
        )];
        for item in items {
            let endpoint = format!(
                "***@{}:{}",
                item["endpoint"]["host"].as_str().unwrap_or("-"),
                item["endpoint"]["port"]
            );
            lines.push(format!(
                "{:<38} {:<10} {:<28} {}",
                item["id"].as_str().unwrap_or("-"),
                item["stage"].as_str().unwrap_or("-"),
                endpoint,
                item["name"].as_str().unwrap_or("-"),
            ));
        }
        if items.is_empty() {
            lines.push("(no onboarding drafts)".to_owned());
        }
        return lines.join("\n");
    }
    if value.get("machine").is_some() {
        // The add answer: the new machine plus the duplicates that were
        // warned about, never merged.
        let machine = &value["machine"];
        let mut lines = vec![format!(
            "machine registered: {} ({})",
            machine["id"].as_str().unwrap_or("-"),
            machine["name"].as_str().unwrap_or("-")
        )];
        for endpoint in machine["endpoints"].as_array().into_iter().flatten() {
            lines.push(format!(
                "  endpoint: {} {}",
                endpoint["kind"].as_str().unwrap_or("-"),
                endpoint["reference"].as_str().unwrap_or("-")
            ));
        }
        match value["duplicates"].as_array() {
            Some(candidates) if !candidates.is_empty() => {
                lines.push("duplicates (warned, not merged):".to_owned());
                for candidate in candidates {
                    lines.push(format!(
                        "  {} {} ({})",
                        candidate["machineId"].as_str().unwrap_or("-"),
                        candidate["reference"].as_str().unwrap_or("-"),
                        candidate["machineStatus"].as_str().unwrap_or("-"),
                    ));
                }
            }
            _ => lines.push("duplicates: (none)".to_owned()),
        }
        return lines.join("\n");
    }
    draft_detail(value)
}

/// Renders the project surface as human text; exposed for contract tests.
#[doc(hidden)]
#[must_use]
pub fn render_projects_for_test(value: &Value) -> String {
    render_projects(Some(value))
}

fn render_projects(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        let mut lines = vec![format!("{:<38} {:<28} {}", "ID", "REMOTE", "NAME")];
        for item in items {
            lines.push(format!(
                "{:<38} {:<28} {}",
                item["id"].as_str().unwrap_or("-"),
                item["remote"].as_str().unwrap_or("-"),
                item["name"].as_str().unwrap_or("-"),
            ));
        }
        if items.is_empty() {
            lines.push("(no projects)".to_owned());
        }
        return lines.join("\n");
    }
    // Detail or mutation answer.
    let mut lines = Vec::new();
    for key in ["id", "remote", "name", "description"] {
        if let Some(rendered) = value.get(key).and_then(Value::as_str) {
            lines.push(format!("{key}: {rendered}"));
        }
    }
    match value["checkouts"].as_array() {
        Some(checkouts) if !checkouts.is_empty() => {
            lines.push("checkouts:".to_owned());
            for checkout in checkouts {
                lines.push(format!(
                    "  {} @ {} ({}{}) at {}",
                    checkout["machineId"].as_str().unwrap_or("-"),
                    checkout["root"].as_str().unwrap_or("-"),
                    checkout["branch"].as_str().unwrap_or("-"),
                    if checkout["dirty"] == true {
                        ", dirty"
                    } else {
                        ""
                    },
                    checkout["observedAt"]
                ));
            }
        }
        _ => lines.push("checkouts: (none observed)".to_owned()),
    }
    lines.join("\n")
}

/// Renders a project mutation answer (create/update), which the API returns
/// without hydrated checkouts.
fn render_project_mutation(payload: &Value) -> String {
    render_projects(Some(payload))
}

/// Renders a project deletion answer.
fn render_project_deleted() -> String {
    "project removed".to_owned()
}

/// Renders the Proxmox surface as human text; exposed for contract tests.
#[doc(hidden)]
#[must_use]
pub fn render_proxmox_for_test(value: &Value) -> String {
    render_proxmox(Some(value))
}

/// Renders the Proxmox guests surface; exposed for contract tests. The
/// guests and accounts endpoints share the page envelope, so the renderer
/// is command-scoped rather than guessing from the payload.
#[doc(hidden)]
#[must_use]
pub fn render_proxmox_guests_for_test(value: &Value) -> String {
    render_proxmox_guests(Some(value))
}

#[allow(clippy::too_many_lines)]
fn render_proxmox_guests(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    // Guests list: one row per guest with its agent state and candidates.
    let Some(items) = value.get("items").and_then(Value::as_array) else {
        return String::new();
    };
    let mut lines = vec![format!(
        "{:<10} {:<10} {:<24} {:<12} {}",
        "VMID", "KIND", "NAME", "AGENT", "FLEET CANDIDATES"
    )];
    for guest in items {
        let agent = match &guest["agent"] {
            Value::Null => "-".to_owned(),
            agent => {
                if agent["online"] == true {
                    "online".to_owned()
                } else {
                    "unreachable".to_owned()
                }
            }
        };
        let candidates = guest["candidates"]
            .as_array()
            .map(|candidates| {
                candidates
                    .iter()
                    .filter_map(|candidate| {
                        Some(format!(
                            "{} ({})",
                            candidate["machineName"].as_str()?,
                            candidate["kind"].as_str()?
                        ))
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        lines.push(format!(
            "{:<10} {:<10} {:<24} {:<12} {}",
            guest["vmid"]
                .as_u64()
                .map_or_else(|| "-".to_owned(), |v| v.to_string()),
            guest["kind"].as_str().unwrap_or("-"),
            guest["name"].as_str().unwrap_or("-"),
            agent,
            if candidates.is_empty() {
                "-"
            } else {
                &candidates
            }
        ));
    }
    if items.is_empty() {
        lines.push("(no guests reported)".to_owned());
    }
    lines.join("\n")
}

#[allow(clippy::too_many_lines)]
fn render_proxmox(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    // Discovery: a snapshot with resources and honest warnings.
    if let Some(resources) = value.get("resources").and_then(Value::as_array) {
        let mut lines = vec![format!(
            "{:<18} {:<10} {:<28} {:<20} {}",
            "KIND", "VMID", "ID", "NAME", "STATUS"
        )];
        for resource in resources {
            lines.push(format!(
                "{:<18} {:<10} {:<28} {:<20} {}",
                resource["kind"].as_str().unwrap_or("-"),
                resource["vmid"]
                    .as_u64()
                    .map_or_else(|| "-".to_owned(), |v| v.to_string()),
                resource["id"].as_str().unwrap_or("-"),
                resource["name"].as_str().unwrap_or("-"),
                resource["status"].as_str().unwrap_or("-"),
            ));
        }
        if resources.is_empty() {
            lines.push("(no resources reported)".to_owned());
        }
        if let Some(warnings) = value.get("warnings").and_then(Value::as_array)
            && !warnings.is_empty()
        {
            lines.push(String::new());
            lines.push("warnings:".to_owned());
            for warning in warnings {
                if let Some(text) = warning.as_str() {
                    lines.push(format!("  {text}"));
                }
            }
        }
        if let Some(version) = value.get("pveVersion").and_then(Value::as_str) {
            lines.insert(0, format!("PVE {version}"));
        }
        return lines.join("\n");
    }
    // Guests list: one row per guest with its agent state and candidates.
    if let Some(items) = value.get("items").and_then(Value::as_array)
        && items.first().is_some_and(|item| item.get("vmid").is_some())
    {
        let mut lines = vec![format!(
            "{:<10} {:<10} {:<24} {:<12} {}",
            "VMID", "KIND", "NAME", "AGENT", "FLEET CANDIDATES"
        )];
        for guest in items {
            let agent = match &guest["agent"] {
                Value::Null => "-".to_owned(),
                agent => {
                    if agent["online"] == true {
                        "online".to_owned()
                    } else {
                        "unreachable".to_owned()
                    }
                }
            };
            let candidates = guest["candidates"]
                .as_array()
                .map(|candidates| {
                    candidates
                        .iter()
                        .filter_map(|candidate| {
                            Some(format!(
                                "{} ({})",
                                candidate["machineName"].as_str()?,
                                candidate["kind"].as_str()?
                            ))
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            lines.push(format!(
                "{:<10} {:<10} {:<24} {:<12} {}",
                guest["vmid"]
                    .as_u64()
                    .map_or_else(|| "-".to_owned(), |v| v.to_string()),
                guest["kind"].as_str().unwrap_or("-"),
                guest["name"].as_str().unwrap_or("-"),
                agent,
                if candidates.is_empty() {
                    "-"
                } else {
                    &candidates
                }
            ));
        }
        if items.is_empty() {
            lines.push("(no guests reported)".to_owned());
        }
        return lines.join("\n");
    }
    // Accounts list: one row per account with its trust state.
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        let mut lines = vec![format!(
            "{:<38} {:<24} {:<32} {}",
            "ID", "NAME", "TOKEN ID", "TRUST"
        )];
        for account in items {
            lines.push(format!(
                "{:<38} {:<24} {:<32} {}",
                account["id"].as_str().unwrap_or("-"),
                account["name"].as_str().unwrap_or("-"),
                account["tokenId"].as_str().unwrap_or("-"),
                account["fingerprintState"].as_str().unwrap_or("-"),
            ));
        }
        if items.is_empty() {
            lines.push("(no Proxmox accounts)".to_owned());
        }
        return lines.join("\n");
    }
    // Single account / fingerprint / deletion answers: key facts only.
    let mut lines = Vec::new();
    for (key, val) in value.as_object().into_iter().flatten() {
        let rendered = match val {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        lines.push(format!("{key}: {rendered}"));
    }
    if lines.is_empty() {
        lines.push("account removed".to_owned());
    }
    lines.join("\n")
}

/// Renders the tailnet surface as human text; exposed for contract tests.
#[doc(hidden)]
#[must_use]
pub fn render_tailnet_for_test(value: &Value) -> String {
    render_tailnet(Some(value))
}

fn render_tailnet(value: Option<&Value>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        let mut lines = vec![format!(
            "{:<22} {:<12} {:<30} {}",
            "NODE ID", "STATE", "DEVICE", "FLEET CANDIDATES"
        )];
        for item in items {
            let state = if item["connectedToControl"] == true {
                "connected"
            } else if item["online"] == true {
                "online"
            } else {
                "offline"
            };
            let candidates = item["candidates"]
                .as_array()
                .map(|candidates| {
                    candidates
                        .iter()
                        .filter_map(|candidate| {
                            Some(format!(
                                "{} ({})",
                                candidate["machineName"].as_str()?,
                                candidate["kind"].as_str()?
                            ))
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let device = format!(
                "{} {}",
                item["hostname"].as_str().unwrap_or("-"),
                item["addresses"]
                    .as_array()
                    .and_then(|addresses| addresses.first())
                    .and_then(Value::as_str)
                    .unwrap_or("-")
            );
            lines.push(format!(
                "{:<22} {:<12} {:<30} {}",
                item["nodeId"].as_str().unwrap_or("-"),
                state,
                device,
                if candidates.is_empty() {
                    "-"
                } else {
                    &candidates
                }
            ));
        }
        if items.is_empty() {
            lines.push("(no tailnet devices)".to_owned());
        }
        return lines.join("\n");
    }
    // Status/configure/clear answer: key facts only.
    let mut lines = Vec::new();
    for (key, val) in value.as_object().into_iter().flatten() {
        let rendered = match val {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        lines.push(format!("{key}: {rendered}"));
    }
    lines.join("\n")
}

fn draft_detail(draft: &Value) -> String {
    let mut lines = Vec::new();
    for key in ["id", "name", "description", "stage", "hostKeyStage"] {
        if let Some(value) = draft.get(key) {
            let rendered = match value {
                Value::String(text) => text.clone(),
                Value::Null => continue,
                other => other.to_string(),
            };
            lines.push(format!("{key}: {rendered}"));
        }
    }
    lines.push(format!(
        "endpoint: {}@{}:{}",
        draft["endpoint"]["user"].as_str().unwrap_or("-"),
        draft["endpoint"]["host"].as_str().unwrap_or("-"),
        draft["endpoint"]["port"]
    ));
    match &draft["auth"] {
        auth if auth["type"] == "identityFile" => lines.push(format!(
            "auth: identity file {}",
            auth["path"].as_str().unwrap_or("-")
        )),
        auth if auth["type"] == "agent" => lines.push("auth: ssh agent".to_owned()),
        _ => {}
    }
    if let Some(key) = draft.get("hostKey")
        && !key.is_null()
    {
        lines.push(format!(
            "hostKey: {} {}",
            key["keyType"].as_str().unwrap_or("-"),
            key["fingerprint"].as_str().unwrap_or("-")
        ));
    }
    if let Some(fingerprint) = draft.get("confirmedFingerprint")
        && !fingerprint.is_null()
    {
        lines.push(format!("confirmedFingerprint: {fingerprint}"));
    }
    if let Some(test) = draft.get("lastTest")
        && !test.is_null()
    {
        let outcome = if test["connectAttempted"] == true && test["connected"] == true {
            "connected"
        } else if test["connectAttempted"] == true {
            "failed"
        } else {
            "not attempted (fingerprint unconfirmed)"
        };
        lines.push(format!(
            "lastTest: {outcome}{}",
            test["detail"]
                .as_str()
                .map(|detail| format!(" ({detail})"))
                .unwrap_or_default()
        ));
    }
    if let Some(hint) = draft.get("profileHint")
        && !hint.is_null()
    {
        lines.push(format!("profileHint: {hint}"));
    }
    match draft["facts"].as_array() {
        Some(facts) if !facts.is_empty() => {
            lines.push(format!("facts: {}", facts.len()));
            for fact in facts {
                lines.push(format!(
                    "  {}.{} = {} ({})",
                    fact["namespace"].as_str().unwrap_or("-"),
                    fact["name"].as_str().unwrap_or("-"),
                    fact["value"].as_str().unwrap_or("–"),
                    fact["status"].as_str().unwrap_or("-"),
                ));
            }
        }
        _ => lines.push("facts: (none discovered)".to_owned()),
    }
    match draft["duplicates"].as_array() {
        Some(candidates) if !candidates.is_empty() => {
            lines.push("duplicates (warned, not merged):".to_owned());
            for candidate in candidates {
                lines.push(format!(
                    "  {} {} ({})",
                    candidate["machineId"].as_str().unwrap_or("-"),
                    candidate["reference"].as_str().unwrap_or("-"),
                    candidate["machineStatus"].as_str().unwrap_or("-"),
                ));
            }
        }
        _ => {}
    }
    lines.join("\n")
}

fn machine_line(machine: &Value) -> String {
    let endpoint = machine["endpoints"]
        .as_array()
        .and_then(|endpoints| endpoints.first())
        .and_then(|endpoint| endpoint["reference"].as_str())
        .unwrap_or("-");
    let tags = machine["tags"]
        .as_array()
        .map(|tags| {
            tags.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    format!(
        "{:<24} {:<10} {:<32} {}",
        machine["name"].as_str().unwrap_or("-"),
        machine["machineStatus"].as_str().unwrap_or("-"),
        endpoint,
        tags
    )
}

fn machine_detail(machine: &Value) -> String {
    let mut lines = Vec::new();
    for key in [
        "id",
        "name",
        "description",
        "machineStatus",
        "lastSeenAt",
        "createdAt",
        "updatedAt",
    ] {
        if let Some(value) = machine.get(key) {
            let rendered = match value {
                Value::String(text) => text.clone(),
                Value::Null => continue,
                other => other.to_string(),
            };
            lines.push(format!("{key}: {rendered}"));
        }
    }
    for (label, key) in [
        ("endpoints", "endpoints"),
        ("tags", "tags"),
        ("groups", "groups"),
    ] {
        if let Some(items) = machine.get(key).and_then(Value::as_array) {
            let rendered = items
                .iter()
                .map(|item| match (key, item) {
                    ("endpoints", endpoint) => format!(
                        "  {} {}",
                        endpoint["kind"].as_str().unwrap_or("-"),
                        endpoint["reference"].as_str().unwrap_or("-")
                    ),
                    (_, tag) => format!("  {}", tag.as_str().unwrap_or("-")),
                })
                .collect::<Vec<_>>()
                .join("\n");
            lines.push(format!(
                "{label}:{}{}",
                if rendered.is_empty() { " (none)" } else { "" },
                if rendered.is_empty() {
                    String::new()
                } else {
                    format!("\n{rendered}")
                }
            ));
        }
    }
    if let Some(observation) = machine.get("lastObservation")
        && !observation.is_null()
    {
        lines.push(format!(
            "lastObservation: {} at {}",
            observation["source"].as_str().unwrap_or("-"),
            observation["collectedAt"]
        ));
    }
    if let Some(capabilities) = machine.get("capabilities").and_then(Value::as_array) {
        if capabilities.is_empty() {
            lines.push("capabilities: (none observed)".to_owned());
        } else {
            lines.push("capabilities:".to_owned());
            for fact in capabilities {
                lines.push(format!(
                    "  {}.{} = {} ({}, {}) at {}",
                    fact["namespace"].as_str().unwrap_or("-"),
                    fact["name"].as_str().unwrap_or("-"),
                    fact["value"].as_str().unwrap_or("–"),
                    fact["status"].as_str().unwrap_or("-"),
                    fact["source"].as_str().unwrap_or("-"),
                    fact["observedAt"]
                ));
            }
        }
    }
    lines.join("\n")
}

fn operation_detail(operation: &Value) -> String {
    let mut lines = Vec::new();
    for (key, val) in operation.as_object().into_iter().flatten() {
        let rendered = match val {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        lines.push(format!("{key}: {rendered}"));
    }
    lines.join("\n")
}

/// The auth value the checkout commands share.
fn checkout_auth_value(auth: &OnboardAuthArg) -> serde_json::Value {
    match auth {
        OnboardAuthArg::Agent => serde_json::json!({ "type": "agent" }),
        OnboardAuthArg::IdentityFile(path) => {
            serde_json::json!({ "type": "identityFile", "path": path })
        }
    }
}

/// The start-discovery request body.
fn checkout_request_body(
    machine: &str,
    endpoint: &str,
    auth: &OnboardAuthArg,
) -> serde_json::Value {
    serde_json::json!({
        "machineId": machine,
        "endpointId": endpoint,
        "auth": checkout_auth_value(auth),
        "timeoutSeconds": 120,
    })
}

/// The record-checkouts request body: the discovery result read from
/// standard input supplies the checkouts.
fn record_checkouts_body(machine: &str) -> Result<serde_json::Value, CliError> {
    let stdin = read_stdin_line("the discovery result")?;
    let parsed: serde_json::Value =
        serde_json::from_str(stdin.trim()).map_err(|error| CliError {
            message: format!("the discovery result is not JSON: {error}"),
        })?;
    Ok(serde_json::json!({
        "machineId": machine,
        "checkouts": parsed["data"]["result"]["checkouts"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| parsed["checkouts"].as_array().cloned().unwrap_or_default()),
    }))
}

/// The create-operation body for one checkout action.
fn checkout_operation_body(
    kind: &str,
    machine: &str,
    endpoint: &str,
    auth: &OnboardAuthArg,
    root: Option<String>,
    branch: Option<String>,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "machineId": machine,
        "endpointId": endpoint,
        "auth": checkout_auth_value(auth),
        "timeoutSeconds": 300,
    });
    if let Some(root) = root {
        payload["root"] = serde_json::json!(root);
    }
    if let Some(branch) = branch {
        payload["branch"] = serde_json::json!(branch);
    }
    serde_json::json!({
        "kind": kind,
        "payload": payload,
    })
}

/// The create-operation body for a guarded agent config write; the
/// contents arrive on standard input.
fn checkout_write_config_body(
    machine: &str,
    endpoint: &str,
    auth: &OnboardAuthArg,
    root: &str,
    file_name: &str,
) -> Result<serde_json::Value, CliError> {
    let contents = read_stdin_line("the file contents")?;
    Ok(serde_json::json!({
        "kind": "projects.write-config",
        "payload": {
            "machineId": machine,
            "endpointId": endpoint,
            "auth": checkout_auth_value(auth),
            "root": root,
            "fileName": file_name,
            "contents": contents,
            "timeoutSeconds": 120,
        },
    }))
}

/// Parses one `fleetctl skills` subcommand.
#[allow(clippy::too_many_lines)]
fn parse_skills_command(verb: &str, machine_id: &str, rest: &[&str]) -> Result<Command, CliError> {
    let mut endpoint: Option<String> = None;
    let mut auth: Option<String> = None;
    let mut identity: Option<String> = None;
    let mut skills_root: Option<String> = None;
    let mut artifact_url: Option<String> = None;
    let mut artifact_sha256: Option<String> = None;
    let mut skill: Option<String> = None;
    let mut agents: Vec<String> = Vec::new();
    let mut dry_run = false;
    let mut wait = false;
    let mut timeout: Option<u64> = None;
    let mut flags = rest.iter().copied();
    while let Some(flag) = flags.next() {
        let mut value = |name: &str| {
            flags.next().ok_or_else(|| CliError {
                message: format!("--{name} requires a value"),
            })
        };
        match flag {
            "--endpoint" => endpoint = Some(value("endpoint")?.to_owned()),
            "--auth" => auth = Some(value("auth")?.to_owned()),
            "--identity" => identity = Some(value("identity")?.to_owned()),
            "--skills-root" => skills_root = Some(value("skills-root")?.to_owned()),
            "--artifact-url" => artifact_url = Some(value("artifact-url")?.to_owned()),
            "--artifact-sha256" => artifact_sha256 = Some(value("artifact-sha256")?.to_owned()),
            "--skill" => skill = Some(value("skill")?.to_owned()),
            "--agent" => agents.push(value("agent")?.to_owned()),
            "--dry-run" => dry_run = true,
            "--wait" => wait = true,
            "--timeout" => {
                let parsed = value("timeout")?;
                timeout = Some(parsed.parse().map_err(|_| CliError {
                    message: format!("--timeout must be a number, not {parsed:?}"),
                })?);
            }
            other => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let auth_arg = match (auth.as_deref(), identity) {
        (Some("agent"), _) => OnboardAuthArg::Agent,
        (Some("identity-file"), Some(path)) => OnboardAuthArg::IdentityFile(path),
        (Some("identity-file"), None) => {
            return Err(CliError {
                message: "--auth identity-file requires --identity <path>".to_owned(),
            });
        }
        (Some(other), _) => {
            return Err(CliError {
                message: format!("--auth must be agent or identity-file, not {other:?}"),
            });
        }
        (None, _) => {
            return Err(CliError {
                message: "--auth is required: agent or identity-file".to_owned(),
            });
        }
    };
    let endpoint = endpoint.ok_or_else(|| CliError {
        message: "--endpoint <endpoint-id> is required".to_owned(),
    })?;
    if verb == "probe" {
        // Probe-only flags on a mutation, or mutation-only flags on a
        // probe, are typos the caller must see, not silently dropped.
        if !agents.is_empty() || skill.is_some() || dry_run {
            return Err(CliError {
                message: "--skill/--agent/--dry-run apply to deploy and undeploy only".to_owned(),
            });
        }
        if artifact_url.is_some() != artifact_sha256.is_some() {
            return Err(CliError {
                message: "--artifact-url and --artifact-sha256 must be supplied together"
                    .to_owned(),
            });
        }
        return Ok(Command::SkillsProbe {
            machine: machine_id.to_owned(),
            endpoint,
            auth: auth_arg,
            skills_root,
            artifact_url,
            artifact_sha256,
            wait,
            timeout,
        });
    }
    match verb {
        "deploy" | "undeploy" => {
            let skill = skill.ok_or_else(|| CliError {
                message: "--skill <id> is required".to_owned(),
            })?;
            if agents.is_empty() {
                return Err(CliError {
                    message: "--agent <id> is required at least once".to_owned(),
                });
            }
            if artifact_url.is_some() || artifact_sha256.is_some() {
                return Err(CliError {
                    message: "--artifact-url/--artifact-sha256 apply to probe only".to_owned(),
                });
            }
            if verb == "deploy" {
                Ok(Command::SkillsDeploy {
                    machine: machine_id.to_owned(),
                    endpoint,
                    auth: auth_arg,
                    skill,
                    agents,
                    skills_root,
                    dry_run,
                    wait,
                    timeout,
                })
            } else {
                Ok(Command::SkillsUndeploy {
                    machine: machine_id.to_owned(),
                    endpoint,
                    auth: auth_arg,
                    skill,
                    agents,
                    skills_root,
                    dry_run,
                    wait,
                    timeout,
                })
            }
        }
        _ => Err(CliError { message: usage() }),
    }
}

/// The start-skills-operation request body.
#[allow(clippy::too_many_arguments)]
fn skills_request_body(
    machine: &str,
    endpoint: &str,
    auth: &OnboardAuthArg,
    skill: Option<&str>,
    agents: &[String],
    skills_root: Option<&String>,
    dry_run: bool,
    direction: Option<&str>,
    artifact_url: Option<&String>,
    artifact_sha256: Option<&String>,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "machineId": machine,
        "endpointId": endpoint,
        "auth": checkout_auth_value(auth),
        "agents": agents,
        "dryRun": dry_run,
        "timeoutSeconds": 300,
    });
    if let Some(skill) = skill {
        body["skillId"] = serde_json::json!(skill);
    }
    if let Some(root) = skills_root {
        body["skillsRoot"] = serde_json::json!(root);
    }
    if let Some(direction) = direction {
        body["direction"] = serde_json::json!(direction);
    }
    if let Some(url) = artifact_url {
        body["artifactUrl"] = serde_json::json!(url);
    }
    if let Some(sha256) = artifact_sha256 {
        body["artifactSha256"] = serde_json::json!(sha256);
    }
    body
}

/// Resolves the `--auth`/`--identity` pair into the shared auth argument.
/// The same input errors the same way in every command family: a silent
/// discard would make a caller believe an identity file was honored.
fn resolve_auth_argument(
    auth: Option<&str>,
    identity: Option<String>,
) -> Result<OnboardAuthArg, CliError> {
    match (auth, identity) {
        (Some("agent"), None) => Ok(OnboardAuthArg::Agent),
        (Some("agent"), Some(_)) => Err(CliError {
            message: "--identity applies to --auth identity-file only".to_owned(),
        }),
        (Some("identity-file"), Some(path)) => Ok(OnboardAuthArg::IdentityFile(path)),
        (Some("identity-file"), None) => Err(CliError {
            message: "--auth identity-file requires --identity <path>".to_owned(),
        }),
        (Some(other), _) => Err(CliError {
            message: format!("--auth must be agent or identity-file, not {other:?}"),
        }),
        (None, _) => Err(CliError {
            message: "--auth is required: agent or identity-file".to_owned(),
        }),
    }
}

/// Parses one `fleetctl frogenv` subcommand.
fn parse_frogenv_command(
    action: &str,
    machine_id: &str,
    rest: &[&str],
) -> Result<Command, CliError> {
    let valid_action = matches!(
        action,
        "status" | "setup" | "login" | "request" | "sync" | "run"
    );
    if !valid_action {
        return Err(CliError { message: usage() });
    }
    let mut endpoint: Option<String> = None;
    let mut auth: Option<String> = None;
    let mut identity: Option<String> = None;
    let mut root: Option<String> = None;
    let mut command: Vec<String> = Vec::new();
    let mut wait = false;
    let mut timeout: Option<u64> = None;
    let mut flags = rest.iter().copied();
    while let Some(flag) = flags.next() {
        let mut value = |name: &str| {
            flags.next().ok_or_else(|| CliError {
                message: format!("--{name} requires a value"),
            })
        };
        match flag {
            "--endpoint" => endpoint = Some(value("endpoint")?.to_owned()),
            "--auth" => auth = Some(value("auth")?.to_owned()),
            "--identity" => identity = Some(value("identity")?.to_owned()),
            "--root" => root = Some(value("root")?.to_owned()),
            "--" => {
                // Everything after `--` is the env run command array.
                command = flags.by_ref().map(std::borrow::ToOwned::to_owned).collect();
                break;
            }
            "--wait" => wait = true,
            "--timeout" => {
                let parsed = value("timeout")?;
                timeout = Some(parsed.parse().map_err(|_| CliError {
                    message: format!("--timeout must be a number, not {parsed:?}"),
                })?);
            }
            other => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let auth_arg = resolve_auth_argument(auth.as_deref(), identity)?;
    let endpoint = endpoint.ok_or_else(|| CliError {
        message: "--endpoint <endpoint-id> is required".to_owned(),
    })?;
    // `run` requires a root and a command; the other actions take
    // neither, and the separator itself is run-only: a bare `--` on a
    // non-run action is a malformed form, not an empty command.
    if action == "run" {
        if root.is_none() {
            return Err(CliError {
                message: "--root <path> is required for env run".to_owned(),
            });
        }
        if command.is_empty() {
            return Err(CliError {
                message: "a command must follow `--` for env run".to_owned(),
            });
        }
    } else if root.is_some() || !command.is_empty() {
        return Err(CliError {
            message: "--root and a command apply to env run only".to_owned(),
        });
    }
    Ok(Command::FrogenvOperation {
        machine: machine_id.to_owned(),
        endpoint,
        auth: auth_arg,
        action: action.to_owned(),
        root,
        command,
        wait,
        timeout,
    })
}

/// The start-frogenv-operation request body.
fn frogenv_request_body(
    machine: &str,
    endpoint: &str,
    auth: &OnboardAuthArg,
    action: &str,
    root: Option<&String>,
    command: &[String],
) -> serde_json::Value {
    let action = match action {
        "status" => "status",
        "setup" => "setup",
        "login" => "login",
        "request" => "request",
        "sync" => "sync",
        _ => "envRun",
    };
    let mut body = serde_json::json!({
        "machineId": machine,
        "endpointId": endpoint,
        "auth": checkout_auth_value(auth),
        "action": action,
        "timeoutSeconds": 300,
    });
    if let Some(root) = root {
        body["root"] = serde_json::json!(root);
    }
    if !command.is_empty() {
        body["command"] = serde_json::json!(command);
    }
    body
}

/// Parses one `fleetctl mise` subcommand.
fn parse_mise_command(action: &str, machine_id: &str, rest: &[&str]) -> Result<Command, CliError> {
    let valid_action = matches!(action, "inventory" | "status" | "install" | "exec");
    if !valid_action {
        return Err(CliError { message: usage() });
    }
    let mut endpoint: Option<String> = None;
    let mut auth: Option<String> = None;
    let mut identity: Option<String> = None;
    let mut tool: Option<String> = None;
    let mut version: Option<String> = None;
    let mut root: Option<String> = None;
    let mut command: Vec<String> = Vec::new();
    let mut wait = false;
    let mut timeout: Option<u64> = None;
    let mut flags = rest.iter().copied();
    while let Some(flag) = flags.next() {
        let mut value = |name: &str| {
            flags.next().ok_or_else(|| CliError {
                message: format!("--{name} requires a value"),
            })
        };
        match flag {
            "--endpoint" => endpoint = Some(value("endpoint")?.to_owned()),
            "--auth" => auth = Some(value("auth")?.to_owned()),
            "--identity" => identity = Some(value("identity")?.to_owned()),
            "--tool" => tool = Some(value("tool")?.to_owned()),
            "--version" => version = Some(value("version")?.to_owned()),
            "--root" => root = Some(value("root")?.to_owned()),
            "--" => {
                // Everything after `--` is the exec command array.
                command = flags.by_ref().map(std::borrow::ToOwned::to_owned).collect();
                break;
            }
            "--wait" => wait = true,
            "--timeout" => {
                let parsed = value("timeout")?;
                timeout = Some(parsed.parse().map_err(|_| CliError {
                    message: format!("--timeout must be a number, not {parsed:?}"),
                })?);
            }
            other => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let auth_arg = resolve_auth_argument(auth.as_deref(), identity)?;
    let endpoint = endpoint.ok_or_else(|| CliError {
        message: "--endpoint <endpoint-id> is required".to_owned(),
    })?;
    // Action-specific requirements: install needs tool+version, exec
    // needs root+command, and the read-only actions take neither.
    if action == "install" {
        if tool.is_none() || version.is_none() {
            return Err(CliError {
                message: "--tool <name> and --version <pin> are required for install".to_owned(),
            });
        }
    } else if action == "exec" {
        if root.is_none() {
            return Err(CliError {
                message: "--root <path> is required for exec".to_owned(),
            });
        }
        if command.is_empty() {
            return Err(CliError {
                message: "a command must follow `--` for exec".to_owned(),
            });
        }
    } else if tool.is_some() || version.is_some() || root.is_some() || !command.is_empty() {
        return Err(CliError {
            message: "--tool/--version apply to install and --root/-- apply to exec only"
                .to_owned(),
        });
    }
    Ok(Command::MiseOperation {
        machine: machine_id.to_owned(),
        endpoint,
        auth: auth_arg,
        action: action.to_owned(),
        tool,
        version,
        root,
        command,
        wait,
        timeout,
    })
}

/// The start-mise-operation request body.
#[allow(clippy::too_many_arguments)]
fn mise_request_body(
    machine: &str,
    endpoint: &str,
    auth: &OnboardAuthArg,
    action: &str,
    tool: Option<&String>,
    version: Option<&String>,
    root: Option<&String>,
    command: &[String],
) -> serde_json::Value {
    let action = match action {
        "inventory" => "inventory",
        "status" => "status",
        "install" => "install",
        _ => "exec",
    };
    let mut body = serde_json::json!({
        "machineId": machine,
        "endpointId": endpoint,
        "auth": checkout_auth_value(auth),
        "action": action,
        "timeoutSeconds": 300,
    });
    if let Some(tool) = tool {
        body["tool"] = serde_json::json!(tool);
    }
    if let Some(version) = version {
        body["version"] = serde_json::json!(version);
    }
    if let Some(root) = root {
        body["root"] = serde_json::json!(root);
    }
    if !command.is_empty() {
        body["command"] = serde_json::json!(command);
    }
    body
}

/// Parses one `fleetctl apply` subcommand: the plan identity and its
/// flags; the plan JSON itself is read from standard input at request
/// time.
fn parse_apply_command(machine_id: &str, rest: &[&str]) -> Result<Command, CliError> {
    let mut endpoint: Option<String> = None;
    let mut auth: Option<String> = None;
    let mut identity: Option<String> = None;
    let mut plan_id: Option<String> = None;
    let mut wait = false;
    let mut timeout: Option<u64> = None;
    let mut flags = rest.iter().copied();
    while let Some(flag) = flags.next() {
        let mut value = |name: &str| {
            flags.next().ok_or_else(|| CliError {
                message: format!("--{name} requires a value"),
            })
        };
        match flag {
            "--endpoint" => endpoint = Some(value("endpoint")?.to_owned()),
            "--auth" => auth = Some(value("auth")?.to_owned()),
            "--identity" => identity = Some(value("identity")?.to_owned()),
            "--plan-id" => plan_id = Some(value("plan-id")?.to_owned()),
            "--wait" => wait = true,
            "--timeout" => {
                let parsed = value("timeout")?;
                timeout = Some(parsed.parse().map_err(|_| CliError {
                    message: format!("--timeout must be a number, not {parsed:?}"),
                })?);
            }
            other => {
                return Err(CliError {
                    message: format!("unknown flag {other:?}; see the usage below\n\n{}", usage()),
                });
            }
        }
    }
    let auth_arg = resolve_auth_argument(auth.as_deref(), identity)?;
    Ok(Command::ApplyWorkflow {
        machine: machine_id.to_owned(),
        endpoint: endpoint.ok_or_else(|| CliError {
            message: "--endpoint <endpoint-id> is required".to_owned(),
        })?,
        auth: auth_arg,
        plan_id: plan_id.ok_or_else(|| CliError {
            message: "--plan-id <id> is required".to_owned(),
        })?,
        wait,
        timeout,
    })
}
