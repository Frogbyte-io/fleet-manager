//! The live-target contract: every target is described by environment
//! variables, and every secret is read from a file. The names follow the
//! FM-612 runbook (`docs/operations/proxmox-test-cluster.md`, step 7) and
//! `deploy/pve-test/pve-test env`, so a block printed there pastes straight
//! into the env file this suite reads.
//!
//! The gate mirrors `pin_live.rs`: without `FLEET_PVE_LIVE=1` the suite
//! skips; with the gate on, a missing or malformed variable is a loud
//! failure, never a silent pass.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use fleet_core::SensitiveString;

/// The live gate.
pub const LIVE_GATE: &str = "FLEET_PVE_LIVE";
/// The prefix of every per-target variable.
pub const TARGET_PREFIX: &str = "FLEET_PVE_TARGET_";
/// Restricts a run to one target (set by `cargo xtask pve-acceptance --target`).
pub const TARGET_FILTER: &str = "FLEET_PVE_ACCEPTANCE_TARGET";
/// The `fleetctl` binary the suite drives (set by the xtask runner).
pub const FLEETCTL_VAR: &str = "FLEET_PVE_ACCEPTANCE_FLEETCTL";
/// The FM-612 env file, passed through to `deploy/pve-test/pve-test`.
pub const PVE_TEST_ENV_FILE: &str = "FLEET_PVE_TEST_ENV_FILE";

/// The fewest VMIDs a range must hold: four scratch guests (task polling
/// twice, destructive gate, association) plus two never-created targets
/// (privilege failure, partial-node failure).
pub const MIN_RANGE_SLOTS: u32 = 6;

/// PVE's smallest and largest guest identifiers.
const PVE_MIN_VMID: u32 = 100;
const PVE_MAX_VMID: u32 = 999_999_999;

/// The gate's verdict.
#[derive(Debug)]
pub enum Gate {
    /// `FLEET_PVE_LIVE` is not `1`: the suite skips with this reason.
    Off(String),
    /// The gate is on and every selected target parsed.
    On(Vec<Target>),
}

/// One API token: the identifier and the secret read from its file.
pub struct Token {
    /// `user@realm!name`.
    pub id: String,
    /// The secret, never printed.
    pub secret: SensitiveString,
    /// Where it came from, for messages.
    pub file: PathBuf,
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("id", &"<redacted>")
            .field("secret", &self.secret)
            .field("file", &self.file)
            .finish()
    }
}

/// The node `deploy/pve-test/pve-test node-down` takes offline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownNode {
    /// The PVE node name, as discovery reports it.
    pub node: String,
    /// The `pve-test` role (`node-a` or `node-b`).
    pub role: String,
}

/// The inclusive VMID range the suite may create and destroy guests in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmidRange {
    /// The first VMID.
    pub first: u32,
    /// The last VMID, inclusive.
    pub last: u32,
}

impl VmidRange {
    /// Parses `<first>-<last>`.
    ///
    /// # Errors
    ///
    /// Refuses a malformed, inverted, out-of-PVE-bounds, or too-small range.
    pub fn parse(value: &str) -> Result<Self, String> {
        let (first, last) = value
            .trim()
            .split_once('-')
            .ok_or_else(|| format!("expected <first>-<last>, not {value:?}"))?;
        let parse = |part: &str| {
            part.trim()
                .parse::<u32>()
                .map_err(|_| format!("{part:?} is not a VMID"))
        };
        let (first, last) = (parse(first)?, parse(last)?);
        if first < PVE_MIN_VMID || last > PVE_MAX_VMID {
            return Err(format!(
                "the range must lie within PVE's VMIDs {PVE_MIN_VMID}-{PVE_MAX_VMID}"
            ));
        }
        if first > last {
            return Err(format!("the range {first}-{last} is inverted"));
        }
        if last - first + 1 < MIN_RANGE_SLOTS {
            return Err(format!(
                "the range {first}-{last} holds fewer than {MIN_RANGE_SLOTS} VMIDs"
            ));
        }
        Ok(Self { first, last })
    }

    /// Whether the VMID lies inside the range.
    #[must_use]
    pub fn contains(self, vmid: u32) -> bool {
        (self.first..=self.last).contains(&vmid)
    }

    /// The guard every mutation helper calls first: a VMID outside the
    /// range is refused before any request is built.
    ///
    /// # Errors
    ///
    /// Returns the refusal when the VMID lies outside the range.
    pub fn check(self, vmid: u32) -> Result<u32, String> {
        if self.contains(vmid) {
            Ok(vmid)
        } else {
            Err(format!(
                "refusing VMID {vmid}: it lies outside the suite's VMID_RANGE {}-{}",
                self.first, self.last
            ))
        }
    }
}

impl fmt::Display for VmidRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.first, self.last)
    }
}

/// One live PVE target.
#[derive(Debug)]
pub struct Target {
    /// `<NAME>` in `FLEET_PVE_TARGET_<NAME>_*`.
    pub name: String,
    /// The API host (bare host or IP).
    pub host: String,
    /// The API port.
    pub port: u16,
    /// The admin-scoped token.
    pub token: Token,
    /// The API certificate's SHA-256, normalized (no colons, upper case).
    pub fingerprint: String,
    /// The node Fleet talks to and the template lives on.
    pub node: String,
    /// The guest storage discovery must report on that node.
    pub storage: String,
    /// The guest-agent test template, outside the range.
    pub template_vmid: u32,
    /// The scratch range.
    pub range: VmidRange,
    /// The read-only (`PVEAuditor`) token, when configured.
    pub ro_token: Option<Token>,
    /// The node to take down, on a cluster target.
    pub down: Option<DownNode>,
}

impl Target {
    /// The variable name for one of this target's fields.
    #[must_use]
    pub fn var(&self, field: &str) -> String {
        format!("{TARGET_PREFIX}{}_{field}", self.name)
    }
}

/// Reads one secret file. The file must not be readable by group or others
/// (as `ssh` refuses a loose key), and an empty file is refused. Errors
/// never carry the file's content.
///
/// # Errors
///
/// Returns why the file was refused.
pub fn read_secret_file(path: &Path) -> Result<SensitiveString, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} is readable by group or others (mode {mode:o}); chmod 600 it",
                path.display()
            ));
        }
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let secret = raw.trim();
    if secret.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(SensitiveString::new(secret.to_owned()))
}

/// Loads the gate from the process environment.
///
/// # Errors
///
/// Returns every problem found when the gate is on.
pub fn load_process() -> Result<Gate, String> {
    let env: BTreeMap<String, String> = std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect();
    load(&env, read_secret_file)
}

/// Loads the gate from an environment map, reading secrets through
/// `read_secret`. Every problem is collected so one run reports them all.
///
/// # Errors
///
/// Returns every problem found when the gate is on.
pub fn load(
    env: &BTreeMap<String, String>,
    read_secret: impl Fn(&Path) -> Result<SensitiveString, String>,
) -> Result<Gate, String> {
    if env.get(LIVE_GATE).map(|value| value.trim()) != Some("1") {
        return Ok(Gate::Off(format!("{LIVE_GATE} is not 1")));
    }
    let mut names: Vec<String> = env
        .keys()
        .filter_map(|key| key.strip_prefix(TARGET_PREFIX)?.strip_suffix("_HOST"))
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect();
    names.sort();
    names.dedup();
    if names.is_empty() {
        return Err(format!(
            "{LIVE_GATE}=1 requires at least one target: set {TARGET_PREFIX}<NAME>_HOST and its \
             siblings (see docs/operations/proxmox-test-cluster.md, step 7)"
        ));
    }
    if let Some(filter) = env.get(TARGET_FILTER).map(|value| value.trim())
        && !filter.is_empty()
    {
        if !names.iter().any(|name| name == filter) {
            return Err(format!(
                "{TARGET_FILTER}={filter} names no configured target (configured: {})",
                names.join(", ")
            ));
        }
        names.retain(|name| name == filter);
    }
    let mut problems: Vec<String> = names
        .iter()
        .filter(|name| !valid_target_name(name))
        .map(|name| {
            format!("{TARGET_PREFIX}{name:?}_HOST: a target name may hold only A-Z, a-z, 0-9 and _")
        })
        .collect();
    if !problems.is_empty() {
        return Err(format!(
            "{LIVE_GATE}=1 but the target configuration is incomplete:\n  - {}",
            problems.join("\n  - ")
        ));
    }
    let mut targets = Vec::new();
    for name in names {
        match target(env, &name, &read_secret) {
            Ok(target) => targets.push(target),
            Err(mut found) => problems.append(&mut found),
        }
    }
    if problems.is_empty() {
        Ok(Gate::On(targets))
    } else {
        Err(format!(
            "{LIVE_GATE}=1 but the target configuration is incomplete:\n  - {}",
            problems.join("\n  - ")
        ))
    }
}

/// Whether `name` is a usable `<NAME>`: `[A-Za-z0-9_]+`. The name is
/// emitted as one space-separated field of every result line, so anything
/// else (whitespace above all) would split it.
#[must_use]
pub fn valid_target_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether `host` is a bare host or IP: no scheme, path, whitespace, or
/// port. A colon is allowed only in an IPv6 address (bracketed or not).
fn bare_host(host: &str) -> bool {
    if host.contains("://") || host.contains('/') || host.contains(char::is_whitespace) {
        return false;
    }
    if !host.contains(':') {
        return true;
    }
    let inner = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    inner.parse::<std::net::Ipv6Addr>().is_ok()
}

/// Parses one target, collecting every problem.
fn target(
    env: &BTreeMap<String, String>,
    name: &str,
    read_secret: &impl Fn(&Path) -> Result<SensitiveString, String>,
) -> Result<Target, Vec<String>> {
    let mut problems = Vec::new();
    let var = |field: &str| format!("{TARGET_PREFIX}{name}_{field}");
    let optional = |field: &str| {
        env.get(&var(field))
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    };
    let mut required = |field: &str| {
        let value = optional(field);
        if value.is_none() {
            problems.push(format!("{LIVE_GATE}=1 requires {}", var(field)));
        }
        value
    };
    let host = required("HOST");
    let token_id = required("TOKEN_ID");
    let token_file = required("TOKEN_SECRET_FILE");
    let fingerprint = required("FINGERPRINT");
    let node = required("NODE");
    let storage = required("STORAGE");
    let template = required("TEMPLATE_VMID");
    let range = required("VMID_RANGE");

    if let Some(host) = &host
        && !bare_host(host)
    {
        problems.push(format!(
            "{} must be a bare host or IP, not a URL or host:port (set {} for the port)",
            var("HOST"),
            var("PORT")
        ));
    }
    let port = match optional("PORT") {
        None => 8006,
        Some(value) => match value.parse::<u16>() {
            Ok(port) if port > 0 => port,
            _ => {
                problems.push(format!("{} is not a TCP port", var("PORT")));
                0
            }
        },
    };
    let fingerprint = fingerprint.and_then(|value| {
        let normalized = fleet_provider_proxmox::normalize_fingerprint(&value);
        if normalized.len() == 64 && normalized.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(normalized)
        } else {
            problems.push(format!(
                "{} must be a SHA-256 fingerprint (64 hex digits, colons optional)",
                var("FINGERPRINT")
            ));
            None
        }
    });
    let range = range.and_then(|value| match VmidRange::parse(&value) {
        Ok(range) => Some(range),
        Err(detail) => {
            problems.push(format!("{}: {detail}", var("VMID_RANGE")));
            None
        }
    });
    let template = template.and_then(|value| match value.parse::<u32>() {
        Ok(vmid) if (PVE_MIN_VMID..=PVE_MAX_VMID).contains(&vmid) => Some(vmid),
        Ok(_) => {
            problems.push(format!(
                "{} must lie within PVE's VMIDs {PVE_MIN_VMID}-{PVE_MAX_VMID}",
                var("TEMPLATE_VMID")
            ));
            None
        }
        Err(_) => {
            problems.push(format!("{} is not a VMID", var("TEMPLATE_VMID")));
            None
        }
    });
    if let (Some(range), Some(template)) = (range, template)
        && range.contains(template)
    {
        problems.push(format!(
            "{} ({template}) lies inside {} ({range}); the template must stay outside the \
             range the suite destroys guests in",
            var("TEMPLATE_VMID"),
            var("VMID_RANGE")
        ));
    }
    let mut token = |id: Option<String>, file: Option<String>, label: &str| {
        let (id, file) = (id?, PathBuf::from(file?));
        if !id.contains('!') || !id.contains('@') {
            problems.push(format!("{label} must be an API token id (user@realm!name)"));
            return None;
        }
        match read_secret(&file) {
            Ok(secret) => Some(Token { id, secret, file }),
            Err(detail) => {
                problems.push(format!("{label}: {detail}"));
                None
            }
        }
    };
    let admin = token(token_id, token_file, &var("TOKEN_ID"));
    let ro = match (optional("RO_TOKEN_ID"), optional("RO_TOKEN_SECRET_FILE")) {
        (None, None) => None,
        (Some(id), Some(file)) => token(Some(id), Some(file), &var("RO_TOKEN_ID")),
        _ => {
            problems.push(format!(
                "{} and {} are set together or not at all",
                var("RO_TOKEN_ID"),
                var("RO_TOKEN_SECRET_FILE")
            ));
            None
        }
    };
    let down = match (optional("DOWN_NODE"), optional("DOWN_ROLE")) {
        (None, None) => None,
        (Some(node), Some(role)) => {
            if matches!(role.as_str(), "node-a" | "node-b") {
                Some(DownNode { node, role })
            } else {
                problems.push(format!(
                    "{} must be a pve-test cluster role (node-a or node-b)",
                    var("DOWN_ROLE")
                ));
                None
            }
        }
        _ => {
            problems.push(format!(
                "{} and {} are set together or not at all",
                var("DOWN_NODE"),
                var("DOWN_ROLE")
            ));
            None
        }
    };
    if let (Some(down), Some(node)) = (&down, &node)
        && &down.node == node
    {
        problems.push(format!(
            "{} must name the peer node, not {} itself",
            var("DOWN_NODE"),
            var("NODE")
        ));
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    // Every field is present: the problems list would be non-empty otherwise.
    match (host, admin, fingerprint, node, storage, template, range) {
        (
            Some(host),
            Some(token),
            Some(fingerprint),
            Some(node),
            Some(storage),
            Some(template_vmid),
            Some(range),
        ) => Ok(Target {
            name: name.to_owned(),
            host,
            port,
            token,
            fingerprint,
            node,
            storage,
            template_vmid,
            range,
            ro_token: ro,
            down,
        }),
        _ => Err(vec![format!("target {name} is incomplete")]),
    }
}
