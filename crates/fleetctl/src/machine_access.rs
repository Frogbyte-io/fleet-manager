//! `fleetctl machines exec|put|collect|files|file-get|endpoint-auth|ssh-key`
//! (#493, ADR 0017): agent access to Fleet machines over SSH with a key the
//! controller holds.
//!
//! The commands are adapters over `/api/v1/machines/*`. The controller holds
//! the key and runs the session; nothing here ever receives it. `ssh-key
//! store` reads a private key from stdin, once, to hand it to the controller,
//! and prints only the reference it gets back. Authorization and the audit
//! event (with the command's digest, never the command) are the
//! controller's.
//!
//! `exec`, `put` and `collect` wait for the operation by default and answer
//! the outcome as JSON; `--no-wait` answers the queued operation instead.
//! `exec` exits with the command's exit code (1 when it did not run to an
//! exit code), so a script can branch on it.

use std::fmt::Write as _;

use serde_json::{Value, json};

use crate::{CliError, Command, Invocation, Output, RequestShape, usage};

/// The deadline of an exec that names none, matching the controller.
const DEFAULT_EXEC_TIMEOUT: u64 = 60;
/// Extra seconds the CLI waits beyond the command's own bound: queueing, the
/// session start and the copy of the output.
const WAIT_MARGIN: u64 = 60;

/// How the caller asks for authentication, overriding the endpoint's default.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthArgs {
    /// `agent`, `identity-file` or `secret`.
    pub kind: Option<String>,
    /// The identity file path, for `identity-file`.
    pub identity: Option<String>,
    /// The secret reference, for `secret`.
    pub credential: Option<String>,
}

impl AuthArgs {
    /// The wire object of the controller's `EndpointAuth`, when one was given.
    fn to_json(&self) -> Result<Option<Value>, CliError> {
        let missing = |flag: &str, kind: &str| CliError {
            message: format!("--auth {kind} needs {flag}"),
        };
        match self.kind.as_deref() {
            None => {
                if self.identity.is_some() || self.credential.is_some() {
                    return Err(CliError {
                        message: "--identity and --credential need --auth".to_owned(),
                    });
                }
                Ok(None)
            }
            Some("agent") => Ok(Some(json!({ "type": "agent" }))),
            Some("identity-file") => Ok(Some(json!({
                "type": "identityFile",
                "path": self.identity.as_ref().ok_or_else(|| missing("--identity <path>", "identity-file"))?,
            }))),
            Some("secret") => Ok(Some(json!({
                "type": "secret",
                "credential": self.credential.as_ref().ok_or_else(|| missing("--credential <ref>", "secret"))?,
            }))),
            Some(other) => Err(CliError {
                message: format!("--auth must be agent, identity-file or secret, not {other:?}"),
            }),
        }
    }
}

/// The target of a machine command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Target {
    /// The machine.
    pub machine: String,
    /// The SSH endpoint; the machine's only SSH endpoint when absent.
    pub endpoint: Option<String>,
    /// An explicit auth, overriding the endpoint's default.
    pub auth: AuthArgs,
    /// `linux` (default) or `windows`.
    pub os: Option<String>,
}

/// One `machines` access subcommand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MachineAccessAction {
    /// `machines ssh-key store [--machine <id>]`: the private key is read
    /// from stdin; with a machine it is usable on that machine only.
    SshKeyStore {
        /// The machine the key is bound to.
        machine: Option<String>,
    },
    /// `machines product-key store`: the Windows product key is read from
    /// stdin (#489).
    ProductKeyStore,
    /// `machines create ...`: a permanent, Fleet-managed VM (#489).
    Create(Box<crate::persistent::CreateArgs>),
    /// `machines abandon --account <id> --vmid <n>`: drop the marker of a
    /// creation that never completed (#489).
    Abandon {
        /// The Proxmox account.
        account: String,
        /// The VMID.
        vmid: u32,
    },
    /// `machines endpoint-auth get <machine> <endpoint>`.
    EndpointAuthGet {
        /// The machine.
        machine: String,
        /// The SSH endpoint.
        endpoint: String,
    },
    /// `machines endpoint-auth set <machine> <endpoint> --auth ...`.
    EndpointAuthSet {
        /// The machine.
        machine: String,
        /// The SSH endpoint.
        endpoint: String,
        /// The default auth to record.
        auth: AuthArgs,
    },
    /// `machines endpoint-auth clear <machine> <endpoint>`.
    EndpointAuthClear {
        /// The machine.
        machine: String,
        /// The SSH endpoint.
        endpoint: String,
    },
    /// `machines exec <machine> -- <command> [args...]`.
    Exec {
        /// The machine and how to reach it.
        target: Target,
        /// The program and its arguments, or one script word with `script`.
        words: Vec<String>,
        /// The one word is script text for the guest's shell, sent untouched.
        script: bool,
        /// The deadline in seconds.
        timeout: Option<u64>,
        /// A key making a retry return the operation already queued.
        idempotency_key: Option<String>,
        /// Queue only; answer the operation instead of its outcome.
        no_wait: bool,
    },
    /// `machines put <machine> <local-path> <guest-path>`.
    Put {
        /// The machine and how to reach it.
        target: Target,
        /// The local file to send.
        local_path: String,
        /// The absolute guest path to create.
        guest_path: String,
        /// Replace an existing regular file at the guest path.
        overwrite: bool,
        /// Queue only.
        no_wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// `machines collect <machine> <guest-path>...`.
    Collect {
        /// The machine and how to reach it.
        target: Target,
        /// The absolute guest paths to copy.
        paths: Vec<String>,
        /// Queue only.
        no_wait: bool,
        /// How long to wait, in seconds.
        timeout: Option<u64>,
    },
    /// `machines files <machine>`: the files collected from a machine.
    Files {
        /// The machine.
        machine: String,
        /// The page size.
        limit: Option<u32>,
    },
    /// `machines file-get <file-id> --out <file>`.
    FileGet {
        /// The collected file's identity.
        file_id: String,
        /// Where to write it.
        out: String,
    },
}

/// Parses `machines <verb> ...` for the access verbs.
pub(crate) fn parse(verb: &str, rest: &[&str], output: &mut Output) -> Result<Command, CliError> {
    let action = match verb {
        "ssh-key" => match rest {
            ["store", flags @ ..] => {
                let mut machine = None;
                parse_flags(flags, output, |flag, value| match flag {
                    "--machine" => {
                        machine = Some(value()?);
                        Ok(())
                    }
                    other => Err(unknown(other)),
                })?;
                MachineAccessAction::SshKeyStore { machine }
            }
            _ => return Err(CliError { message: usage() }),
        },
        "product-key" => match rest {
            ["store", flags @ ..] => {
                parse_flags(flags, output, |flag, _| Err(unknown(flag)))?;
                MachineAccessAction::ProductKeyStore
            }
            _ => return Err(CliError { message: usage() }),
        },
        "abandon" => crate::persistent::parse_abandon(rest, output)?,
        "create" => {
            MachineAccessAction::Create(Box::new(crate::persistent::parse_create(rest, output)?))
        }
        "endpoint-auth" => parse_endpoint_auth(rest, output)?,
        "exec" => parse_exec(rest, output)?,
        "put" => parse_put(rest, output)?,
        "collect" => parse_collect(rest, output)?,
        "files" => {
            let Some((machine, flags)) = rest.split_first() else {
                return Err(CliError { message: usage() });
            };
            let mut limit = None;
            parse_flags(flags, output, |flag, value| match flag {
                "--limit" => {
                    limit = Some(number("limit", &value()?)?);
                    Ok(())
                }
                other => Err(unknown(other)),
            })?;
            MachineAccessAction::Files {
                machine: (*machine).to_owned(),
                limit: limit.map(|n| u32::try_from(n).unwrap_or(u32::MAX)),
            }
        }
        "file-get" => {
            let Some((file_id, flags)) = rest.split_first() else {
                return Err(CliError { message: usage() });
            };
            let mut out = None;
            parse_flags(flags, output, |flag, value| match flag {
                "--out" => {
                    out = Some(value()?);
                    Ok(())
                }
                other => Err(unknown(other)),
            })?;
            MachineAccessAction::FileGet {
                file_id: (*file_id).to_owned(),
                out: out.ok_or_else(|| CliError {
                    message: "machines file-get needs --out <file>".to_owned(),
                })?,
            }
        }
        _ => return Err(CliError { message: usage() }),
    };
    Ok(Command::MachineAccess(action))
}

fn unknown(flag: &str) -> CliError {
    CliError {
        message: format!("unknown flag {flag:?}; see the usage below\n\n{}", usage()),
    }
}

fn number(name: &str, raw: &str) -> Result<u64, CliError> {
    raw.parse().map_err(|_| CliError {
        message: format!("--{name} must be a number, not {raw:?}"),
    })
}

/// Walks flags (stopping before a `--`), handing each to `handle` with a
/// reader for its value; `--output` is taken here. Answers the words left
/// after a `--` separator, when there is one.
fn parse_flags<'a>(
    flags: &[&'a str],
    output: &mut Output,
    mut handle: impl FnMut(&str, &mut dyn FnMut() -> Result<String, CliError>) -> Result<(), CliError>,
) -> Result<Vec<&'a str>, CliError> {
    let mut iter = flags.iter().copied();
    while let Some(flag) = iter.next() {
        if flag == "--" {
            return Ok(iter.collect());
        }
        if flag == "--output" {
            *output = match iter.next() {
                Some("json") => Output::Json,
                Some("text") => Output::Text,
                other => {
                    return Err(CliError {
                        message: format!("--output must be json or text, not {other:?}"),
                    });
                }
            };
            continue;
        }
        let name = flag.trim_start_matches('-').to_owned();
        let mut value = || {
            iter.next()
                .filter(|candidate| !candidate.starts_with("--"))
                .map(str::to_owned)
                .ok_or_else(|| CliError {
                    message: format!("--{name} requires a value"),
                })
        };
        handle(flag, &mut value)?;
    }
    Ok(Vec::new())
}

/// The target flags shared by exec, put and collect. Returns whether the
/// flag was one of them.
fn target_flag(
    target: &mut Target,
    flag: &str,
    value: &mut dyn FnMut() -> Result<String, CliError>,
) -> Result<bool, CliError> {
    match flag {
        "--endpoint" => target.endpoint = Some(value()?),
        "--auth" => target.auth.kind = Some(value()?),
        "--identity" => target.auth.identity = Some(value()?),
        "--credential" => target.auth.credential = Some(value()?),
        "--os" => {
            let os = value()?;
            if !matches!(os.as_str(), "linux" | "windows") {
                return Err(CliError {
                    message: "--os must be linux or windows".to_owned(),
                });
            }
            target.os = Some(os);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn parse_endpoint_auth(
    rest: &[&str],
    output: &mut Output,
) -> Result<MachineAccessAction, CliError> {
    let [verb, machine, endpoint, flags @ ..] = rest else {
        return Err(CliError { message: usage() });
    };
    let mut target = Target::default();
    parse_flags(flags, output, |flag, value| {
        if *verb == "set"
            && target_flag(&mut target, flag, value)?
            && flag != "--endpoint"
            && flag != "--os"
        {
            return Ok(());
        }
        Err(unknown(flag))
    })?;
    let (machine, endpoint) = ((*machine).to_owned(), (*endpoint).to_owned());
    match *verb {
        "get" => Ok(MachineAccessAction::EndpointAuthGet { machine, endpoint }),
        "clear" => Ok(MachineAccessAction::EndpointAuthClear { machine, endpoint }),
        "set" => {
            if target.auth.kind.is_none() {
                return Err(CliError {
                    message: "machines endpoint-auth set needs --auth agent|identity-file|secret"
                        .to_owned(),
                });
            }
            // Validate now so a malformed request never leaves the process.
            target.auth.to_json()?;
            Ok(MachineAccessAction::EndpointAuthSet {
                machine,
                endpoint,
                auth: target.auth,
            })
        }
        _ => Err(CliError { message: usage() }),
    }
}

fn parse_exec(rest: &[&str], output: &mut Output) -> Result<MachineAccessAction, CliError> {
    let Some((machine, flags)) = rest.split_first() else {
        return Err(CliError { message: usage() });
    };
    if machine.starts_with("--") {
        return Err(CliError { message: usage() });
    }
    let mut target = Target {
        machine: (*machine).to_owned(),
        ..Target::default()
    };
    let (mut timeout, mut script, mut idempotency_key, mut no_wait) = (None, false, None, false);
    let words = parse_flags(flags, output, |flag, value| {
        if target_flag(&mut target, flag, value)? {
            return Ok(());
        }
        match flag {
            "--timeout" => timeout = Some(number("timeout", &value()?)?),
            "--idempotency-key" => idempotency_key = Some(value()?),
            "--script" => script = true,
            "--no-wait" => no_wait = true,
            other => return Err(unknown(other)),
        }
        Ok(())
    })?;
    if words.is_empty() {
        return Err(CliError {
            message: "a command must follow `--`".to_owned(),
        });
    }
    if script && words.len() != 1 {
        return Err(CliError {
            message: "--script takes exactly one word after `--`: the script text".to_owned(),
        });
    }
    target.auth.to_json()?;
    Ok(MachineAccessAction::Exec {
        target,
        words: words.into_iter().map(str::to_owned).collect(),
        script,
        timeout,
        idempotency_key,
        no_wait,
    })
}

fn parse_put(rest: &[&str], output: &mut Output) -> Result<MachineAccessAction, CliError> {
    let mut target = Target::default();
    let (mut overwrite, mut no_wait, mut timeout) = (false, false, None);
    let mut positionals: Vec<String> = Vec::new();
    // Positionals and flags interleave, so walk the words once and let the
    // flag reader consume values itself.
    let mut iter = rest.iter().copied().peekable();
    while let Some(word) = iter.next() {
        if word.starts_with("--") {
            let mut one = vec![word];
            if !matches!(word, "--overwrite" | "--no-wait")
                && let Some(next) = iter.next()
            {
                one.push(next);
            }
            parse_flags(&one, output, |flag, value| {
                if target_flag(&mut target, flag, value)? {
                    return Ok(());
                }
                match flag {
                    "--overwrite" => overwrite = true,
                    "--no-wait" => no_wait = true,
                    "--timeout" => timeout = Some(number("timeout", &value()?)?),
                    other => return Err(unknown(other)),
                }
                Ok(())
            })?;
        } else {
            positionals.push(word.to_owned());
        }
    }
    let [machine, local_path, guest_path] = positionals.as_slice() else {
        return Err(CliError { message: usage() });
    };
    target.machine.clone_from(machine);
    target.auth.to_json()?;
    Ok(MachineAccessAction::Put {
        target,
        local_path: local_path.clone(),
        guest_path: guest_path.clone(),
        overwrite,
        no_wait,
        timeout,
    })
}

fn parse_collect(rest: &[&str], output: &mut Output) -> Result<MachineAccessAction, CliError> {
    let mut target = Target::default();
    let (mut no_wait, mut timeout) = (false, None);
    let mut positionals: Vec<String> = Vec::new();
    let mut iter = rest.iter().copied();
    while let Some(word) = iter.next() {
        if word.starts_with("--") {
            let mut one = vec![word];
            if word != "--no-wait"
                && let Some(next) = iter.next()
            {
                one.push(next);
            }
            parse_flags(&one, output, |flag, value| {
                if target_flag(&mut target, flag, value)? {
                    return Ok(());
                }
                match flag {
                    "--no-wait" => no_wait = true,
                    "--timeout" => timeout = Some(number("timeout", &value()?)?),
                    other => return Err(unknown(other)),
                }
                Ok(())
            })?;
        } else {
            positionals.push(word.to_owned());
        }
    }
    let Some((machine, paths)) = positionals.split_first() else {
        return Err(CliError { message: usage() });
    };
    if paths.is_empty() {
        return Err(CliError {
            message: "name at least one absolute guest path to collect".to_owned(),
        });
    }
    target.machine.clone_from(machine);
    target.auth.to_json()?;
    Ok(MachineAccessAction::Collect {
        target,
        paths: paths.to_vec(),
        no_wait,
        timeout,
    })
}

/// The JSON fields every machine request body shares.
fn target_body(target: &Target) -> Result<serde_json::Map<String, Value>, CliError> {
    let mut body = serde_json::Map::new();
    if let Some(endpoint) = &target.endpoint {
        body.insert("endpointId".to_owned(), json!(endpoint));
    }
    if let Some(auth) = target.auth.to_json()? {
        body.insert("auth".to_owned(), auth);
    }
    if let Some(os) = &target.os {
        body.insert("guestOs".to_owned(), json!(os));
    }
    Ok(body)
}

/// The controller request of one subcommand: the primary request, for the
/// commands that stream (`put`, `file-get`) the one that starts them.
#[allow(clippy::too_many_lines)]
pub(crate) fn request(action: &MachineAccessAction) -> Result<RequestShape, CliError> {
    Ok(match action {
        MachineAccessAction::SshKeyStore { .. } => (
            reqwest::Method::POST,
            "/api/v1/machine-ssh-keys".to_owned(),
            Vec::new(),
            // The key is read from stdin when the command runs, never here.
            None,
        ),
        MachineAccessAction::ProductKeyStore => (
            reqwest::Method::POST,
            "/api/v1/machine-product-keys".to_owned(),
            Vec::new(),
            // The key is read from stdin when the command runs, never here.
            None,
        ),
        MachineAccessAction::Abandon { account, vmid } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/persistent/{account}/{vmid}/abandon/review"),
            Vec::new(),
            None,
        ),
        MachineAccessAction::Create(args) => (
            reqwest::Method::POST,
            "/api/v1/machines/create/review".to_owned(),
            Vec::new(),
            Some(json!({ "spec": args.spec() })),
        ),
        MachineAccessAction::EndpointAuthGet { machine, endpoint } => (
            reqwest::Method::GET,
            format!("/api/v1/machines/{machine}/endpoints/{endpoint}/auth"),
            Vec::new(),
            None,
        ),
        MachineAccessAction::EndpointAuthSet {
            machine,
            endpoint,
            auth,
        } => (
            reqwest::Method::PUT,
            format!("/api/v1/machines/{machine}/endpoints/{endpoint}/auth"),
            Vec::new(),
            Some(json!({ "auth": auth.to_json()?.unwrap_or(Value::Null) })),
        ),
        MachineAccessAction::EndpointAuthClear { machine, endpoint } => (
            reqwest::Method::DELETE,
            format!("/api/v1/machines/{machine}/endpoints/{endpoint}/auth"),
            Vec::new(),
            None,
        ),
        MachineAccessAction::Exec {
            target,
            words,
            script,
            timeout,
            ..
        } => {
            let mut body = target_body(target)?;
            if *script {
                body.insert("script".to_owned(), json!(words[0]));
            } else {
                body.insert("command".to_owned(), json!(words));
            }
            if let Some(timeout) = timeout {
                body.insert("timeoutSeconds".to_owned(), json!(timeout));
            }
            (
                reqwest::Method::POST,
                format!("/api/v1/machines/{}/exec", target.machine),
                Vec::new(),
                Some(Value::Object(body)),
            )
        }
        MachineAccessAction::Put {
            target,
            guest_path,
            overwrite,
            ..
        } => (
            reqwest::Method::POST,
            format!("/api/v1/machines/{}/files", target.machine),
            put_query(target, guest_path, *overwrite),
            // The file's bytes are the body, streamed when the command runs.
            None,
        ),
        MachineAccessAction::Collect { target, paths, .. } => {
            let mut body = target_body(target)?;
            body.insert("paths".to_owned(), json!(paths));
            (
                reqwest::Method::POST,
                format!("/api/v1/machines/{}/collect", target.machine),
                Vec::new(),
                Some(Value::Object(body)),
            )
        }
        MachineAccessAction::Files { machine, limit } => (
            reqwest::Method::GET,
            format!("/api/v1/machines/{machine}/files"),
            limit
                .map(|limit| vec![("limit", limit.to_string())])
                .unwrap_or_default(),
            None,
        ),
        MachineAccessAction::FileGet { file_id, .. } => (
            reqwest::Method::GET,
            format!("/api/v1/machine-files/{file_id}"),
            Vec::new(),
            None,
        ),
    })
}

/// The query of a put: the path and the target. An explicit auth travels as
/// `authType` and its reference, never a key.
fn put_query(target: &Target, guest_path: &str, overwrite: bool) -> Vec<(&'static str, String)> {
    let mut query = vec![("path", guest_path.to_owned())];
    if overwrite {
        query.push(("overwrite", "true".to_owned()));
    }
    if let Some(endpoint) = &target.endpoint {
        query.push(("endpointId", endpoint.clone()));
    }
    if let Some(os) = &target.os {
        query.push(("guestOs", os.clone()));
    }
    match target.auth.kind.as_deref() {
        Some("agent") => query.push(("authType", "agent".to_owned())),
        Some("identity-file") => {
            query.push(("authType", "identityFile".to_owned()));
            if let Some(identity) = &target.auth.identity {
                query.push(("identityPath", identity.clone()));
            }
        }
        Some("secret") => {
            query.push(("authType", "secret".to_owned()));
            if let Some(credential) = &target.auth.credential {
                query.push(("credential", credential.clone()));
            }
        }
        _ => {}
    }
    query
}

fn clamp_exit(code: Option<i64>) -> u8 {
    code.map_or(1, |code| u8::try_from(code.clamp(0, 255)).unwrap_or(1))
}

/// Runs one subcommand: sends the request, follows the operation unless
/// `--no-wait`, and answers the rendered payload with the exit code.
#[allow(clippy::too_many_lines)]
pub(crate) fn run(
    invocation: &Invocation,
    action: &MachineAccessAction,
) -> Result<(String, u8), CliError> {
    let client = crate::http_client()?;
    let correlation_id = uuid::Uuid::now_v7().to_string();
    let rendered = |payload: &Value| crate::render(invocation, payload);
    match action {
        MachineAccessAction::FileGet { file_id, out } => {
            let body = crate::download_from(
                invocation,
                &format!("/api/v1/machine-files/{file_id}"),
                &format!("/api/v1/machine-files/{file_id}/content"),
                file_id,
                out,
            )?;
            Ok((rendered(&body), 0))
        }
        MachineAccessAction::SshKeyStore { machine } => {
            let key = crate::read_stdin_to_eof("the SSH private key")?;
            let body = crate::send(
                &client,
                invocation,
                reqwest::Method::POST,
                "/api/v1/machine-ssh-keys",
                &[],
                Some(&json!({ "privateKey": key, "machineId": machine })),
                correlation_id,
            )?;
            Ok((rendered(&body["data"]), 0))
        }
        MachineAccessAction::ProductKeyStore => {
            let key = crate::read_stdin_to_eof("the Windows product key")?;
            let body = crate::send(
                &client,
                invocation,
                reqwest::Method::POST,
                "/api/v1/machine-product-keys",
                &[],
                Some(&json!({ "productKey": key.trim() })),
                correlation_id,
            )?;
            Ok((rendered(&body["data"]), 0))
        }
        MachineAccessAction::Abandon { account, vmid } => {
            let payload = crate::persistent::run_abandon(invocation, account, *vmid)?;
            Ok((rendered(&payload), 0))
        }
        MachineAccessAction::Create(args) => {
            let (payload, exit) = crate::persistent::run_create(invocation, args)?;
            Ok((rendered(&payload), exit))
        }
        MachineAccessAction::Put {
            target,
            local_path,
            guest_path,
            overwrite,
            no_wait,
            timeout,
        } => {
            let body = crate::upload_file(
                invocation,
                &format!("/api/v1/machines/{}/files", target.machine),
                &put_query(target, guest_path, *overwrite),
                local_path,
                correlation_id,
            )?;
            if *no_wait {
                return Ok((rendered(&body["data"]), 0));
            }
            let operation_id = operation_id(&body);
            let (data, output) = crate::wait_for_operation_output(
                &client,
                invocation,
                &operation_id,
                timeout.unwrap_or(900),
            )?;
            let payload = json!({
                "operationId": operation_id,
                "state": data["state"],
                "machineId": output["machineId"],
                "guestPath": output["guestPath"],
                "sizeBytes": output["sizeBytes"],
                "sha256": output["sha256"],
                "reason": output["reason"],
                "detail": output["detail"],
            });
            let exit = u8::from(payload["state"] != "succeeded");
            Ok((rendered(&payload), exit))
        }
        MachineAccessAction::Exec {
            target,
            idempotency_key,
            no_wait,
            timeout,
            ..
        } => {
            let (method, path, query, body) = request(action)?;
            let queued = crate::send_with_key(
                &client,
                invocation,
                method,
                &path,
                &query,
                body.as_ref(),
                correlation_id,
                idempotency_key.as_deref(),
            )?;
            let _ = target;
            if *no_wait {
                return Ok((rendered(&queued["data"]), 0));
            }
            let operation_id = operation_id(&queued);
            let bound = timeout.unwrap_or(DEFAULT_EXEC_TIMEOUT);
            let (data, output) = crate::wait_for_operation_output(
                &client,
                invocation,
                &operation_id,
                bound.saturating_add(WAIT_MARGIN),
            )?;
            let payload = json!({
                "operationId": operation_id,
                "state": data["state"],
                "exitCode": output["exitCode"],
                "stdout": output["stdout"],
                "stderr": output["stderr"],
                "truncatedStdout": output["truncatedStdout"],
                "truncatedStderr": output["truncatedStderr"],
                "reason": output["reason"],
                "detail": output["detail"],
            });
            let exit = if data["state"] == "succeeded" {
                clamp_exit(output["exitCode"].as_i64())
            } else {
                // A command that exited nonzero reports its own code; one
                // that never ran to an exit code (a refused session, a
                // deadline kill) is a plain failure.
                let code = output["exitCode"].as_i64().filter(|code| *code > 0);
                clamp_exit(code)
            };
            Ok((rendered(&payload), exit))
        }
        MachineAccessAction::Collect {
            no_wait, timeout, ..
        } => {
            let (method, path, query, body) = request(action)?;
            let queued = crate::send(
                &client,
                invocation,
                method,
                &path,
                &query,
                body.as_ref(),
                correlation_id,
            )?;
            if *no_wait {
                return Ok((rendered(&queued["data"]), 0));
            }
            let operation_id = operation_id(&queued);
            let (data, output) = crate::wait_for_operation_output(
                &client,
                invocation,
                &operation_id,
                timeout.unwrap_or(660),
            )?;
            let payload = json!({
                "operationId": operation_id,
                "state": data["state"],
                "machineId": output["machineId"],
                "files": output["files"],
                "failures": output["failures"],
                "reason": output["reason"],
                "detail": output["detail"],
            });
            let exit = u8::from(payload["state"] != "succeeded");
            Ok((rendered(&payload), exit))
        }
        _ => {
            let (method, path, query, body) = request(action)?;
            let answer = crate::send(
                &client,
                invocation,
                method,
                &path,
                &query,
                body.as_ref(),
                correlation_id,
            )?;
            let payload = if answer.get("items").is_some() {
                answer
            } else {
                answer.get("data").cloned().unwrap_or(answer)
            };
            Ok((rendered(&payload), 0))
        }
    }
}

fn operation_id(body: &Value) -> String {
    body["data"]["id"].as_str().unwrap_or_default().to_owned()
}

/// Server-supplied text for a terminal: control characters other than
/// newline and tab become spaces.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// The text rendering of a payload; `--output json` is the contract.
pub(crate) fn render(payload: &Value) -> String {
    let text = |value: &Value| match value {
        Value::String(text) => clean(text),
        Value::Null => "-".to_owned(),
        other => clean(&other.to_string()),
    };
    if payload.get("items").is_some() {
        let items = payload["items"].as_array().cloned().unwrap_or_default();
        if items.is_empty() {
            return "no collected files".to_owned();
        }
        return items
            .iter()
            .map(|file| {
                format!(
                    "{}  {:>10} bytes  {}  {}",
                    text(&file["id"]),
                    text(&file["sizeBytes"]),
                    text(&file["sha256"]),
                    text(&file["path"])
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    if payload.get("stdout").is_some() {
        let mut out = String::new();
        if let Some(stdout) = payload["stdout"].as_str() {
            out.push_str(&clean(stdout));
        }
        if let Some(stderr) = payload["stderr"].as_str().filter(|s| !s.is_empty()) {
            out.push_str("\n--- stderr ---\n");
            out.push_str(&clean(stderr));
        }
        if payload["truncatedStdout"] == true || payload["truncatedStderr"] == true {
            out.push_str("\n[output truncated]");
        }
        if payload["state"] != "succeeded" {
            let _ = write!(
                out,
                "\n[{}: exit {}{}]",
                text(&payload["state"]),
                text(&payload["exitCode"]),
                payload["reason"]
                    .as_str()
                    .map(|reason| format!(", {}", clean(reason)))
                    .unwrap_or_default()
            );
        }
        return out;
    }
    // The persistent VM results (#489) are structured: show them whole.
    if ["vmid", "secretRef", "reviewToken", "step"]
        .iter()
        .any(|key| payload.get(*key).is_some())
    {
        return serde_json::to_string_pretty(payload).unwrap_or_default();
    }
    if let Some(credential) = payload["credentialRef"].as_str() {
        return format!("credential {}", clean(credential));
    }
    if payload.get("auth").is_some() {
        return match &payload["auth"] {
            Value::Null => "no default auth".to_owned(),
            auth => format!("default auth {}", clean(&auth.to_string())),
        };
    }
    if let Some(files) = payload["files"].as_array() {
        let mut lines: Vec<String> = files
            .iter()
            .map(|file| {
                format!(
                    "{}  {} bytes  {}",
                    text(&file["fileId"]),
                    text(&file["sizeBytes"]),
                    text(&file["path"])
                )
            })
            .collect();
        if let Some(detail) = payload["detail"].as_str() {
            lines.push(clean(detail));
        }
        return lines.join("\n");
    }
    serde_json::to_string_pretty(payload).unwrap_or_default()
}
