//! The running-service read model (FM-1031): what is running, where, and
//! whether it is healthy, joined from Coolify discovery observations
//! (FM-1030), Docker containers on Fleet machines, and the Registry
//! (FM-1012).
//!
//! Nothing here is stored: a read gathers the inputs the caller may read,
//! hands them to the pure [`join`], and returns the result with a
//! [`Coverage`] report that says which inputs were missing, denied, or
//! stale. The adapters (API, `fleetctl`) add nothing to it.
//!
//! # Joins
//!
//! * **Coolify server to Fleet machine.** First an explicit link: a machine
//!   tag `coolify-server:<server-uuid>`. Then the server's address against
//!   the machine's addresses (its SSH endpoint hosts and its `network/ipv*`
//!   capability facts; a tailnet-onboarded machine's endpoint host is its
//!   tailnet address). More than one candidate is reported as `ambiguous`
//!   with the candidates, never guessed.
//! * **Docker container to Coolify resource.** Coolify labels the
//!   containers it manages with `coolify.applicationUuid`,
//!   `coolify.serviceUuid`, or `coolify.databaseUuid` (Coolify's
//!   `bootstrap/helpers/docker.php`, `defaultLabels` and
//!   `defaultDatabaseLabels`). A container carrying a known resource uuid
//!   is folded into that resource, so a workload is listed once; every
//!   other container is its own `docker` service. A container is also
//!   evidence of the machine a resource runs on.
//! * **Resource to server.** Coolify's list endpoints do not name a
//!   resource's server, so it is derived: container evidence, then the
//!   server named by the resource's latest deployment, then the only
//!   server of the account.
//! * **Registry.** An explicit `hosted-on` relation to `coolify:<uuid>`,
//!   and any `domain` entry whose fqdn equals a Coolify FQDN host or is a
//!   parent domain of it (`example.com` matches `www.example.com`).
//!
//! # Authorization
//!
//! There is no `services.read` permission: the model is a view over inputs
//! that each have their own, and a second permission would let a caller see
//! through a denial. The caller's view is the union of what each input
//! allows (`external_account.read` for Coolify, `machine.read` per machine
//! for machines and their containers, `registry.read` for Registry links);
//! an input the caller may not read is left out and reported in the
//! coverage rather than failing the read. A caller who may read none of
//! them is denied. Container observations do not exist yet (M5), so they
//! are authorized as `machine.read` until `containers.read` exists.
#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use fleet_core::{EndpointKind, ExternalProviderKind, SystemClock};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::coolify::{
    CoolifyApplication, CoolifyDatabase, CoolifyObservationPort, CoolifyServer, CoolifyService,
    CoolifySnapshot,
};
use crate::external_accounts::{ExternalAccount, ExternalAccountPort};
use crate::machine::{MachineFilter, MachineStatus, Machines};
use crate::registry::{EntryCursor, RegistryEntryFilter, RegistryEntryRecord, RegistryReadModel};

/// How long a container observation stays fresh.
pub const CONTAINER_STALE_AFTER_MS: i64 = 15 * 60 * 1000;
/// The tag prefix that links a machine to a Coolify server explicitly.
pub const SERVER_LINK_TAG_PREFIX: &str = "coolify-server:";
const MACHINE_PAGE: u32 = 200;
const MAX_MACHINES: usize = 5000;
const REGISTRY_PAGE: i64 = 500;
const MAX_REGISTRY_ENTRIES: usize = 20_000;

/// Where a service was observed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ServiceSource {
    /// A Coolify discovery observation.
    Coolify,
    /// A Docker container observation on a Fleet machine.
    Docker,
}

impl ServiceSource {
    /// The stable wire id.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Coolify => "coolify",
            Self::Docker => "docker",
        }
    }

    /// Parses a wire id.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "coolify" => Some(Self::Coolify),
            "docker" => Some(Self::Docker),
            _ => None,
        }
    }
}

/// What kind of workload a service is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceKind {
    /// A Coolify application.
    Application,
    /// A Coolify one-click or Compose service.
    Service,
    /// A Coolify managed database.
    Database,
    /// A Docker container Coolify does not manage.
    Container,
}

impl ServiceKind {
    /// The stable wire id.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Service => "service",
            Self::Database => "database",
            Self::Container => "container",
        }
    }
}

/// The normalized run state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceState {
    /// Running and, when it reports health, healthy.
    Running,
    /// Running but unhealthy, or restarting.
    Degraded,
    /// Not running.
    Stopped,
    /// The source reported nothing usable.
    Unknown,
}

impl ServiceState {
    /// The stable wire id.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Degraded => "degraded",
            Self::Stopped => "stopped",
            Self::Unknown => "unknown",
        }
    }

    /// Normalizes a Coolify status such as `running:healthy`.
    #[must_use]
    pub fn from_coolify(status: &str) -> Self {
        let status = status.trim().to_ascii_lowercase();
        let head = status.split(':').next().unwrap_or_default();
        match head {
            "running" if status.contains("unhealthy") => Self::Degraded,
            "running" => Self::Running,
            "degraded" | "restarting" => Self::Degraded,
            "exited" | "stopped" | "created" | "paused" | "dead" => Self::Stopped,
            _ => Self::Unknown,
        }
    }

    /// Normalizes a Docker state and status text.
    #[must_use]
    pub fn from_docker(state: &str, status: &str) -> Self {
        let state = state.trim().to_ascii_lowercase();
        match state.as_str() {
            "running" if status.to_ascii_lowercase().contains("unhealthy") => Self::Degraded,
            "running" => Self::Running,
            "restarting" => Self::Degraded,
            "exited" | "dead" | "created" | "paused" | "removing" => Self::Stopped,
            _ => Self::Unknown,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Running => 0,
            Self::Unknown => 1,
            Self::Stopped => 2,
            Self::Degraded => 3,
        }
    }
}

/// One Docker container observed on a Fleet machine, reduced to what the
/// join needs. The port implementation allow-lists labels into
/// [`CoolifyLabels`]; arbitrary labels never reach the application.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObservedContainer {
    /// The container id.
    pub id: String,
    /// The container name, without the leading slash.
    pub name: String,
    /// The image reference.
    pub image: String,
    /// The Docker state (`running`, `exited`, ...).
    pub state: String,
    /// The human status (`Up 3 hours (healthy)`).
    pub status: String,
    /// Coolify's labels, when the container carries any.
    pub coolify: Option<CoolifyLabels>,
}

/// The allow-listed Coolify labels of a container.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoolifyLabels {
    /// `coolify.managed` is `true`.
    pub managed: bool,
    /// The resource kind the uuid label named: `application`, `service`,
    /// or `database`.
    pub kind: Option<ServiceKind>,
    /// The resource uuid from `coolify.{kind}Uuid`.
    pub uuid: Option<String>,
}

impl CoolifyLabels {
    /// Reads the allow-listed keys out of a container's labels; `None` when
    /// the container carries no Coolify label at all. Other labels are
    /// never looked at.
    pub fn from_labels<'a>(labels: impl IntoIterator<Item = (&'a str, &'a str)>) -> Option<Self> {
        let mut found = Self::default();
        let mut any = false;
        for (key, value) in labels {
            let kind = match key {
                "coolify.managed" => {
                    found.managed = value.eq_ignore_ascii_case("true");
                    any = true;
                    continue;
                }
                "coolify.applicationUuid" => ServiceKind::Application,
                "coolify.serviceUuid" => ServiceKind::Service,
                "coolify.databaseUuid" => ServiceKind::Database,
                _ => continue,
            };
            any = true;
            if !value.is_empty() {
                found.kind = Some(kind);
                found.uuid = Some(value.to_owned());
            }
        }
        any.then_some(found)
    }
}

/// The containers observed on one machine.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MachineContainers {
    /// The machine.
    pub machine_id: String,
    /// When the containers were observed (epoch millis); absent when never.
    pub observed_at: Option<i64>,
    /// The containers.
    pub containers: Vec<ObservedContainer>,
}

/// The Docker observation port. M5 (Docker visibility) supplies the real
/// implementation; until then the controller composes
/// [`NoContainerObservations`].
#[async_trait]
pub trait ContainerObservationPort: fmt::Debug + Send + Sync {
    /// Whether container observations exist at all.
    fn available(&self) -> bool {
        true
    }
    /// The stored container observations of the given machines. Machines
    /// never observed may be absent.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn observed(&self, machine_ids: &[String]) -> Result<Vec<MachineContainers>, String>;
}

/// The placeholder port: no Docker observations are stored yet.
#[derive(Debug, Default)]
pub struct NoContainerObservations;

#[async_trait]
impl ContainerObservationPort for NoContainerObservations {
    fn available(&self) -> bool {
        false
    }
    async fn observed(&self, _: &[String]) -> Result<Vec<MachineContainers>, String> {
        Ok(Vec::new())
    }
}

/// One machine, reduced to what the join needs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceMachine {
    /// The machine's identity.
    pub id: String,
    /// The machine's name.
    pub name: String,
    /// The derived connectivity state.
    pub status: MachineStatus,
    /// The machine's known addresses, lowercase.
    pub addresses: Vec<String>,
    /// The machine's tags.
    pub tags: Vec<String>,
}

/// A reference to a machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineRef {
    /// The machine's identity.
    pub id: String,
    /// The machine's name.
    pub name: String,
}

/// How a Coolify server or resource was placed on a Fleet machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchState {
    /// Exactly one machine.
    Matched,
    /// More than one machine fits; none is chosen.
    Ambiguous,
    /// No machine fits.
    Unmatched,
    /// The resource's server could not be determined.
    Unknown,
}

impl MatchState {
    /// The stable wire id.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Ambiguous => "ambiguous",
            Self::Unmatched => "unmatched",
            Self::Unknown => "unknown",
        }
    }
}

/// The evidence behind a placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchBasis {
    /// A `coolify-server:<uuid>` machine tag.
    ExplicitTag,
    /// The server address equals a machine address.
    Address,
    /// A container of the resource was observed on the machine.
    Container,
}

impl MatchBasis {
    /// The stable wire id.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::ExplicitTag => "explicit_tag",
            Self::Address => "address",
            Self::Container => "container",
        }
    }
}

/// The machine placement of a service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Placement {
    /// The outcome.
    pub state: MatchState,
    /// What the outcome rests on, when there is evidence.
    pub basis: Option<MatchBasis>,
    /// The machine, when matched.
    pub machine: Option<MachineRef>,
    /// The candidates, when ambiguous.
    pub candidates: Vec<MachineRef>,
}

impl Placement {
    fn unknown() -> Self {
        Self {
            state: MatchState::Unknown,
            basis: None,
            machine: None,
            candidates: Vec::new(),
        }
    }
}

/// A Coolify server as a service refers to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerRef {
    /// The server's uuid.
    pub uuid: String,
    /// The server's name.
    pub name: String,
    /// The address Coolify connects to.
    pub address: String,
}

/// A container of a service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerRef {
    /// The machine it runs on.
    pub machine_id: String,
    /// The container id.
    pub id: String,
    /// The container name.
    pub name: String,
    /// The image.
    pub image: String,
    /// The normalized state.
    pub state: ServiceState,
    /// The human status text.
    pub status: String,
}

/// The newest known deployment of a Coolify application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LastDeploy {
    /// The deployment uuid.
    pub deployment_uuid: String,
    /// Coolify's deployment status.
    pub status: String,
    /// The commit, when recorded.
    pub commit: Option<String>,
    /// When the deployment last changed, as Coolify reports it.
    pub at: Option<String>,
    /// Whether the deployments class is stale.
    pub stale: bool,
}

/// How a Registry entry relates to a service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryLinkKind {
    /// The entry has a `hosted-on` relation to the Coolify resource.
    HostedOn,
    /// A `domain` entry's fqdn matches a service hostname.
    DomainMatch,
}

impl RegistryLinkKind {
    /// The stable wire id.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::HostedOn => "hosted_on",
            Self::DomainMatch => "domain_match",
        }
    }
}

/// A Registry entry related to a service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryLink {
    /// The entry's type.
    pub entry_type: String,
    /// The entry's key.
    pub key: String,
    /// How it relates.
    pub link: RegistryLinkKind,
    /// The service hostname a domain match went through.
    pub host: Option<String>,
}

/// The Coolify identity of a service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoolifyRef {
    /// The Coolify account the resource was discovered through.
    pub account_id: String,
    /// The account's label.
    pub account_label: String,
    /// The resource uuid.
    pub uuid: String,
    /// Coolify's raw status string, when it reported one.
    pub status: Option<String>,
    /// The project uuid, when the environment could be resolved.
    pub project_uuid: Option<String>,
    /// The project name.
    pub project_name: Option<String>,
    /// The environment name.
    pub environment_name: Option<String>,
    /// The build pack, image, or engine summarizing what it is.
    pub detail: Option<String>,
}

/// One running service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningService {
    /// The stable id: `coolify:<account>:<uuid>` or `docker:<machine>:<name>`.
    pub id: String,
    /// The display name.
    pub name: String,
    /// What kind of workload it is.
    pub kind: ServiceKind,
    /// Where it was observed; both for a Coolify resource whose containers
    /// were seen.
    pub sources: Vec<ServiceSource>,
    /// The normalized state.
    pub state: ServiceState,
    /// The Coolify identity, for Coolify resources.
    pub coolify: Option<CoolifyRef>,
    /// The Coolify server, when known.
    pub server: Option<ServerRef>,
    /// The Fleet machine placement.
    pub placement: Placement,
    /// The containers observed for it.
    pub containers: Vec<ContainerRef>,
    /// The public hostnames, as Coolify reports them.
    pub fqdns: Vec<String>,
    /// The latest known deployment, for applications.
    pub last_deploy: Option<LastDeploy>,
    /// The related Registry entries.
    pub registry: Vec<RegistryLink>,
    /// A link into the Coolify UI (the project page: Coolify's API does
    /// not return the environment uuid its resource pages need).
    pub deep_link: Option<String>,
    /// Whether any input behind this service is stale.
    pub stale: bool,
    /// Why it is stale: `coolify_<class>_stale`, `fqdns_stale`,
    /// `machine_offline`, `machine_stale`, `containers_stale`.
    pub stale_reasons: Vec<String>,
}

/// A Coolify server that matched more than one machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmbiguousServer {
    /// The account.
    pub account_id: String,
    /// The server.
    pub server: ServerRef,
    /// What the match rested on.
    pub basis: MatchBasis,
    /// The machines that fit.
    pub candidates: Vec<MachineRef>,
}

/// The state of one input of the read model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputState {
    /// The input was read.
    Available,
    /// Nothing is configured for it (no Coolify account, no Docker
    /// observation store, no active Registry revision).
    NotConfigured,
    /// The caller may not read it; it is left out.
    Denied,
    /// Reading it failed; it is left out.
    Unavailable(String),
}

impl InputState {
    /// The stable wire id.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::NotConfigured => "not_configured",
            Self::Denied => "denied",
            Self::Unavailable(_) => "unavailable",
        }
    }
}

/// One Coolify account's observation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountCoverage {
    /// The account.
    pub account_id: String,
    /// Its label.
    pub label: String,
    /// Whether a discovery was ever recorded.
    pub observed: bool,
    /// When the snapshot was recorded.
    pub recorded_at: Option<i64>,
    /// The resource classes that are stale.
    pub stale_classes: Vec<String>,
    /// The resource classes cut to fit the snapshot bound; services of
    /// these classes may be missing.
    pub truncated_classes: Vec<String>,
}

/// What the answer was built from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Coverage {
    /// Coolify observations.
    pub coolify: InputState,
    /// Per-account detail.
    pub accounts: Vec<AccountCoverage>,
    /// Fleet machines.
    pub machines: InputState,
    /// Docker container observations.
    pub containers: InputState,
    /// The Registry.
    pub registry: InputState,
}

/// The services list answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServicesView {
    /// The services, ordered by id.
    pub services: Vec<RunningService>,
    /// Coolify servers that matched more than one machine.
    pub ambiguous_servers: Vec<AmbiguousServer>,
    /// What the answer was built from.
    pub coverage: Coverage,
    /// The read time (epoch millis).
    pub evaluated_at: i64,
}

/// A list filter; all set filters must match.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceFilter {
    /// Only services observed by this source.
    pub source: Option<ServiceSource>,
    /// Only services placed on this machine.
    pub machine_id: Option<String>,
    /// Only services whose name or hostname contains this text.
    pub query: Option<String>,
}

// ---------------------------------------------------------------------
// The pure join
// ---------------------------------------------------------------------

/// One Coolify account's inputs.
#[derive(Clone, Debug)]
pub struct AccountInput {
    /// The account.
    pub account: ExternalAccount,
    /// The snapshot and when it was recorded, when discovery ran.
    pub snapshot: Option<(CoolifySnapshot, i64)>,
}

/// Everything the join reads.
#[derive(Clone, Debug, Default)]
pub struct JoinInput {
    /// The read time (epoch millis).
    pub now: i64,
    /// The Coolify accounts the caller may read.
    pub accounts: Vec<AccountInput>,
    /// The machines the caller may read.
    pub machines: Vec<ServiceMachine>,
    /// The container observations of those machines.
    pub containers: Vec<MachineContainers>,
    /// The Registry entries, when the caller may read them.
    pub registry: Vec<RegistryEntryRecord>,
}

/// What the join produced.
#[derive(Clone, Debug, Default)]
pub struct JoinOutput {
    /// The services, ordered by id.
    pub services: Vec<RunningService>,
    /// Servers that matched several machines.
    pub ambiguous_servers: Vec<AmbiguousServer>,
}

struct ServerMatch {
    state: MatchState,
    basis: Option<MatchBasis>,
    candidates: Vec<MachineRef>,
}

fn machine_ref(machine: &ServiceMachine) -> MachineRef {
    MachineRef {
        id: machine.id.clone(),
        name: machine.name.clone(),
    }
}

fn match_server(server: &CoolifyServer, machines: &[ServiceMachine]) -> ServerMatch {
    let tag = format!(
        "{SERVER_LINK_TAG_PREFIX}{}",
        server.uuid.to_ascii_lowercase()
    );
    let tagged: Vec<MachineRef> = machines
        .iter()
        .filter(|machine| machine.tags.iter().any(|t| t.to_ascii_lowercase() == tag))
        .map(machine_ref)
        .collect();
    let (candidates, basis) = if tagged.is_empty() {
        let address = normalize_host(&server.address);
        let by_address: Vec<MachineRef> = if address.is_empty() {
            Vec::new()
        } else {
            machines
                .iter()
                .filter(|machine| machine.addresses.contains(&address))
                .map(machine_ref)
                .collect()
        };
        (by_address, MatchBasis::Address)
    } else {
        (tagged, MatchBasis::ExplicitTag)
    };
    match candidates.len() {
        0 => ServerMatch {
            state: MatchState::Unmatched,
            basis: None,
            candidates,
        },
        1 => ServerMatch {
            state: MatchState::Matched,
            basis: Some(basis),
            candidates,
        },
        _ => ServerMatch {
            state: MatchState::Ambiguous,
            basis: Some(basis),
            candidates,
        },
    }
}

/// Lowercases a host or address and strips brackets, a port, a scheme, and
/// a trailing dot.
#[must_use]
pub fn normalize_host(text: &str) -> String {
    let mut host = text.trim();
    if let Some((_, rest)) = host.split_once("://") {
        host = rest;
    }
    host = host.split(['/', '?', '#']).next().unwrap_or_default();
    if let Some((_, rest)) = host.rsplit_once('@') {
        host = rest;
    }
    if let Some(rest) = host.strip_prefix('[') {
        host = rest.split(']').next().unwrap_or_default();
    } else if host.matches(':').count() == 1 {
        host = host.split(':').next().unwrap_or_default();
    }
    host.trim_end_matches('.').to_ascii_lowercase()
}

struct Resource<'a> {
    kind: ServiceKind,
    uuid: &'a str,
    name: &'a str,
    status: Option<&'a str>,
    environment_id: Option<i64>,
    fqdns: &'a [String],
    details_stale: bool,
    detail: Option<String>,
}

fn resources(snapshot: &CoolifySnapshot) -> Vec<Resource<'_>> {
    let mut out = Vec::new();
    for app in &snapshot.applications.items {
        out.push(app_resource(app));
    }
    for service in &snapshot.services.items {
        out.push(service_resource(service));
    }
    for database in &snapshot.databases.items {
        out.push(database_resource(database));
    }
    out
}

fn app_resource(app: &CoolifyApplication) -> Resource<'_> {
    Resource {
        kind: ServiceKind::Application,
        uuid: &app.uuid,
        name: &app.name,
        status: Some(app.status.as_str()).filter(|s| !s.is_empty()),
        environment_id: app.environment_id,
        fqdns: &app.fqdns,
        details_stale: false,
        detail: app.docker_image.clone().or_else(|| app.build_pack.clone()),
    }
}

fn service_resource(service: &CoolifyService) -> Resource<'_> {
    Resource {
        kind: ServiceKind::Service,
        uuid: &service.uuid,
        name: &service.name,
        status: service.status.as_deref().filter(|s| !s.is_empty()),
        environment_id: service.environment_id,
        fqdns: &service.fqdns,
        details_stale: service.details_stale,
        detail: service.service_type.clone(),
    }
}

fn database_resource(database: &CoolifyDatabase) -> Resource<'_> {
    Resource {
        kind: ServiceKind::Database,
        uuid: &database.uuid,
        name: &database.name,
        status: Some(database.status.as_str()).filter(|s| !s.is_empty()),
        environment_id: database.environment_id,
        fqdns: &[],
        details_stale: false,
        detail: database.engine.clone().or_else(|| database.image.clone()),
    }
}

fn class_name(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::Application => "applications",
        ServiceKind::Service => "services",
        ServiceKind::Database | ServiceKind::Container => "databases",
    }
}

/// The hostname of an FQDN entry (which may be a URL), lowercased.
fn fqdn_host(entry: &str) -> String {
    normalize_host(entry)
}

fn domain_matches(domain: &str, host: &str) -> bool {
    !domain.is_empty()
        && (host == domain
            || host
                .strip_suffix(domain)
                .is_some_and(|prefix| prefix.ends_with('.')))
}

fn registry_links(
    entries: &[RegistryEntryRecord],
    uuid: Option<&str>,
    fqdns: &[String],
) -> Vec<RegistryLink> {
    let hosts: Vec<String> = fqdns.iter().map(|f| fqdn_host(f)).collect();
    let mut links: BTreeMap<(String, String), RegistryLink> = BTreeMap::new();
    for entry in entries {
        let identity = (entry.entry_type.clone(), entry.key.to_lowercase());
        let hosted = uuid.is_some_and(|uuid| {
            entry.relations.iter().any(|relation| {
                relation.relation_type == "hosted-on"
                    && relation.target.class == "coolify"
                    && relation.target.reference.eq_ignore_ascii_case(uuid)
            })
        });
        if hosted {
            links.insert(
                identity,
                RegistryLink {
                    entry_type: entry.entry_type.clone(),
                    key: entry.key.clone(),
                    link: RegistryLinkKind::HostedOn,
                    host: None,
                },
            );
            continue;
        }
        if entry.entry_type == "domain" && !links.contains_key(&identity) {
            let domain = normalize_host(&entry.key);
            if let Some(host) = hosts.iter().find(|host| domain_matches(&domain, host)) {
                links.insert(
                    identity,
                    RegistryLink {
                        entry_type: entry.entry_type.clone(),
                        key: entry.key.clone(),
                        link: RegistryLinkKind::DomainMatch,
                        host: Some(host.clone()),
                    },
                );
            }
        }
    }
    links.into_values().collect()
}

fn container_ref(machine_id: &str, container: &ObservedContainer) -> ContainerRef {
    ContainerRef {
        machine_id: machine_id.to_owned(),
        id: container.id.clone(),
        name: container.name.clone(),
        image: container.image.clone(),
        state: ServiceState::from_docker(&container.state, &container.status),
        status: container.status.clone(),
    }
}

fn worst(containers: &[ContainerRef]) -> ServiceState {
    containers
        .iter()
        .map(|c| c.state)
        .max_by_key(|s| s.rank())
        .unwrap_or(ServiceState::Unknown)
}

fn machine_staleness(status: MachineStatus) -> Option<&'static str> {
    match status {
        MachineStatus::Offline => Some("machine_offline"),
        MachineStatus::Stale => Some("machine_stale"),
        MachineStatus::Connected | MachineStatus::Agentless => None,
    }
}

/// Joins the inputs into running services. Pure and deterministic.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn join(input: &JoinInput) -> JoinOutput {
    let machines_by_id: BTreeMap<&str, &ServiceMachine> =
        input.machines.iter().map(|m| (m.id.as_str(), m)).collect();
    let observed_at: BTreeMap<&str, Option<i64>> = input
        .containers
        .iter()
        .map(|c| (c.machine_id.as_str(), c.observed_at))
        .collect();

    // Container evidence: resource uuid -> (machine id, container).
    let mut by_uuid: BTreeMap<String, Vec<(&str, &ObservedContainer)>> = BTreeMap::new();
    for machine in &input.containers {
        for container in &machine.containers {
            if let Some(uuid) = container.coolify.as_ref().and_then(|c| c.uuid.as_ref()) {
                by_uuid
                    .entry(uuid.to_ascii_lowercase())
                    .or_default()
                    .push((machine.machine_id.as_str(), container));
            }
        }
    }
    let mut claimed: BTreeSet<(String, String)> = BTreeSet::new();
    let mut out = JoinOutput::default();

    for AccountInput { account, snapshot } in &input.accounts {
        let Some((snapshot, _)) = snapshot else {
            continue;
        };
        let server_matches: Vec<(&CoolifyServer, ServerMatch)> = snapshot
            .servers
            .items
            .iter()
            .map(|server| (server, match_server(server, &input.machines)))
            .collect();
        for (server, matched) in &server_matches {
            if matched.state == MatchState::Ambiguous
                && let Some(basis) = matched.basis
            {
                out.ambiguous_servers.push(AmbiguousServer {
                    account_id: account.id.clone(),
                    server: server_ref(server),
                    basis,
                    candidates: matched.candidates.clone(),
                });
            }
        }
        let sole_server = (snapshot.servers.items.len() == 1
            && !snapshot.servers.truncated
            && !snapshot.servers.is_stale(input.now))
        .then(|| &snapshot.servers.items[0]);
        let stale_class = |kind: ServiceKind| match kind {
            ServiceKind::Application => snapshot.applications.is_stale(input.now),
            ServiceKind::Service => snapshot.services.is_stale(input.now),
            _ => snapshot.databases.is_stale(input.now),
        };

        for resource in resources(snapshot) {
            let evidence = by_uuid
                .get(&resource.uuid.to_ascii_lowercase())
                .cloned()
                .unwrap_or_default();
            let mut containers: Vec<ContainerRef> = evidence
                .iter()
                .map(|(machine_id, container)| container_ref(machine_id, container))
                .collect();
            containers.sort_by(|a, b| (&a.machine_id, &a.name).cmp(&(&b.machine_id, &b.name)));
            for (machine_id, container) in &evidence {
                claimed.insert(((*machine_id).to_owned(), container.id.clone()));
            }
            let evidence_machines: BTreeSet<&str> = evidence.iter().map(|(m, _)| *m).collect();

            // The server: a resource's own server is not in Coolify's list
            // answers, so derive it.
            let mut server: Option<&(&CoolifyServer, ServerMatch)> = None;
            if resource.kind == ServiceKind::Application {
                let deployed_on = snapshot
                    .deployments
                    .items
                    .iter()
                    .filter(|d| d.application_uuid.as_deref() == Some(resource.uuid))
                    .find_map(|d| d.server_name.as_deref());
                if let Some(name) = deployed_on {
                    let named: Vec<_> = server_matches
                        .iter()
                        .filter(|(s, _)| s.name == name)
                        .collect();
                    if named.len() == 1 {
                        server = Some(named[0]);
                    }
                }
            }
            if server.is_none() && evidence_machines.len() == 1 {
                let machine_id = evidence_machines.iter().next().copied().unwrap_or_default();
                let on_machine: Vec<_> = server_matches
                    .iter()
                    .filter(|(_, m)| {
                        m.state == MatchState::Matched
                            && m.candidates.first().is_some_and(|c| c.id == machine_id)
                    })
                    .collect();
                if on_machine.len() == 1 {
                    server = Some(on_machine[0]);
                }
            }
            if server.is_none()
                && let Some(sole) = sole_server
            {
                server = server_matches.iter().find(|(s, _)| s.uuid == sole.uuid);
            }

            let placement = if evidence_machines.len() == 1 {
                let id = evidence_machines.iter().next().copied().unwrap_or_default();
                let machine = machines_by_id.get(id).map(|m| machine_ref(m));
                Placement {
                    state: MatchState::Matched,
                    basis: Some(MatchBasis::Container),
                    machine,
                    candidates: Vec::new(),
                }
            } else if evidence_machines.len() > 1 {
                Placement {
                    state: MatchState::Ambiguous,
                    basis: Some(MatchBasis::Container),
                    machine: None,
                    candidates: evidence_machines
                        .iter()
                        .filter_map(|id| machines_by_id.get(id).map(|m| machine_ref(m)))
                        .collect(),
                }
            } else if let Some((_, matched)) = server {
                Placement {
                    state: matched.state,
                    basis: matched.basis,
                    machine: (matched.state == MatchState::Matched)
                        .then(|| matched.candidates[0].clone()),
                    candidates: if matched.state == MatchState::Ambiguous {
                        matched.candidates.clone()
                    } else {
                        Vec::new()
                    },
                }
            } else {
                Placement::unknown()
            };

            let state = match resource.status {
                Some(status) => ServiceState::from_coolify(status),
                None if !containers.is_empty() => worst(&containers),
                None => ServiceState::Unknown,
            };

            let mut reasons = Vec::new();
            if stale_class(resource.kind) {
                reasons.push(format!("coolify_{}_stale", class_name(resource.kind)));
            }
            if resource.details_stale {
                reasons.push("fqdns_stale".to_owned());
            }
            if let Some(machine) = &placement.machine
                && let Some(known) = machines_by_id.get(machine.id.as_str())
                && let Some(reason) = machine_staleness(known.status)
            {
                reasons.push(reason.to_owned());
            }
            if evidence_machines.iter().any(|id| {
                observed_at
                    .get(id)
                    .copied()
                    .flatten()
                    .is_none_or(|at| input.now.saturating_sub(at) > CONTAINER_STALE_AFTER_MS)
            }) {
                reasons.push("containers_stale".to_owned());
            }

            let project = resource.environment_id.and_then(|id| {
                snapshot
                    .projects
                    .items
                    .iter()
                    .find_map(|p| p.environments.iter().find(|e| e.id == id).map(|e| (p, e)))
            });
            let mut sources = vec![ServiceSource::Coolify];
            if !containers.is_empty() {
                sources.push(ServiceSource::Docker);
            }
            let last_deploy = (resource.kind == ServiceKind::Application)
                .then(|| {
                    snapshot
                        .deployments
                        .items
                        .iter()
                        .filter(|d| d.application_uuid.as_deref() == Some(resource.uuid))
                        .max_by(|a, b| {
                            (&a.created_at, &a.updated_at).cmp(&(&b.created_at, &b.updated_at))
                        })
                        .map(|d| LastDeploy {
                            deployment_uuid: d.deployment_uuid.clone(),
                            status: d.status.clone(),
                            commit: d.commit.clone(),
                            at: d.updated_at.clone().or_else(|| d.created_at.clone()),
                            stale: snapshot.deployments.is_stale(input.now),
                        })
                })
                .flatten();
            let base = account.base_url.trim_end_matches('/');
            out.services.push(RunningService {
                id: format!("coolify:{}:{}", account.id, resource.uuid),
                name: resource.name.to_owned(),
                kind: resource.kind,
                sources,
                state,
                coolify: Some(CoolifyRef {
                    account_id: account.id.clone(),
                    account_label: account.label.clone(),
                    uuid: resource.uuid.to_owned(),
                    status: resource.status.map(str::to_owned),
                    project_uuid: project.map(|(p, _)| p.uuid.clone()),
                    project_name: project.map(|(p, _)| p.name.clone()),
                    environment_name: project.map(|(_, e)| e.name.clone()),
                    detail: resource.detail.clone(),
                }),
                server: server.map(|(s, _)| server_ref(s)),
                placement,
                containers,
                fqdns: resource.fqdns.to_vec(),
                last_deploy,
                registry: registry_links(&input.registry, Some(resource.uuid), resource.fqdns),
                deep_link: project.map(|(p, _)| format!("{base}/project/{}", p.uuid)),
                stale: !reasons.is_empty(),
                stale_reasons: reasons,
            });
        }
    }

    // Containers no Coolify resource claimed are services of their own.
    for machine in &input.containers {
        let Some(known) = machines_by_id.get(machine.machine_id.as_str()) else {
            continue;
        };
        for container in &machine.containers {
            if claimed.contains(&(machine.machine_id.clone(), container.id.clone())) {
                continue;
            }
            let reference = container_ref(&machine.machine_id, container);
            let mut reasons = Vec::new();
            if let Some(reason) = machine_staleness(known.status) {
                reasons.push(reason.to_owned());
            }
            if machine
                .observed_at
                .is_none_or(|at| input.now.saturating_sub(at) > CONTAINER_STALE_AFTER_MS)
            {
                reasons.push("containers_stale".to_owned());
            }
            out.services.push(RunningService {
                id: format!("docker:{}:{}", machine.machine_id, container.name),
                name: container.name.clone(),
                kind: ServiceKind::Container,
                sources: vec![ServiceSource::Docker],
                state: reference.state,
                coolify: None,
                server: None,
                placement: Placement {
                    state: MatchState::Matched,
                    basis: None,
                    machine: Some(machine_ref(known)),
                    candidates: Vec::new(),
                },
                containers: vec![reference],
                fqdns: Vec::new(),
                last_deploy: None,
                registry: Vec::new(),
                deep_link: None,
                stale: !reasons.is_empty(),
                stale_reasons: reasons,
            });
        }
    }
    out.services.sort_by(|a, b| a.id.cmp(&b.id));
    out.ambiguous_servers
        .sort_by(|a, b| (&a.account_id, &a.server.uuid).cmp(&(&b.account_id, &b.server.uuid)));
    out
}

fn server_ref(server: &CoolifyServer) -> ServerRef {
    ServerRef {
        uuid: server.uuid.clone(),
        name: server.name.clone(),
        address: server.address.clone(),
    }
}

impl ServiceFilter {
    fn keeps(&self, service: &RunningService) -> bool {
        if let Some(source) = self.source
            && !service.sources.contains(&source)
        {
            return false;
        }
        if let Some(machine) = &self.machine_id
            && service.placement.machine.as_ref().map(|m| &m.id) != Some(machine)
        {
            return false;
        }
        if let Some(query) = &self.query {
            let query = query.to_lowercase();
            if !service.name.to_lowercase().contains(&query)
                && !service
                    .fqdns
                    .iter()
                    .any(|f| f.to_lowercase().contains(&query))
            {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------
// Input ports and the use case
// ---------------------------------------------------------------------

/// Why an input could not be read.
#[derive(Debug)]
pub enum InputError {
    /// The caller may not read it.
    Denied(Decision),
    /// Reading failed.
    Unavailable(String),
}

/// The machine input of the read model.
#[async_trait]
pub trait ServiceMachines: fmt::Debug + Send + Sync {
    /// The machines the caller may read.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    async fn machines(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        now: i64,
    ) -> Result<Vec<ServiceMachine>, InputError>;
}

/// The Registry input of the read model.
#[async_trait]
pub trait ServiceRegistry: fmt::Debug + Send + Sync {
    /// All entries of the active revision, or none when there is none.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    async fn entries(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<Vec<RegistryEntryRecord>, InputError>;
}

/// The addresses a machine is known by: its SSH endpoint hosts and its
/// recorded `network/ipv*` facts.
#[must_use]
pub fn machine_addresses(view: &crate::machine::MachineView) -> Vec<String> {
    let mut addresses = BTreeSet::new();
    for endpoint in &view.endpoints {
        if endpoint.kind == EndpointKind::Ssh {
            let host = normalize_host(&endpoint.reference);
            if !host.is_empty() {
                addresses.insert(host);
            }
        }
    }
    for fact in &view.capabilities {
        if fact.namespace == "network"
            && fact.name.starts_with("ipv")
            && let Some(value) = &fact.value
        {
            let host = normalize_host(value);
            if !host.is_empty() {
                addresses.insert(host);
            }
        }
    }
    addresses.into_iter().collect()
}

#[async_trait]
impl ServiceMachines for Machines {
    async fn machines(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        now: i64,
    ) -> Result<Vec<ServiceMachine>, InputError> {
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let filter = MachineFilter {
                cursor: cursor.clone(),
                ..MachineFilter::default()
            };
            let page = self
                .list(authorizer, principal, &filter, MACHINE_PAGE, now)
                .await
                .map_err(|error| match error {
                    crate::machine::MachineUseCaseError::Denied(decision) => {
                        InputError::Denied(decision)
                    }
                    other => InputError::Unavailable(other.to_string()),
                })?;
            let full = page.len() >= MACHINE_PAGE as usize;
            cursor = page.last().map(|view| view.id.clone());
            for view in page {
                // Per-machine decision: a machine the caller may not read
                // is not part of their view.
                let allowed = authorize(
                    authorizer,
                    AccessRequest {
                        principal_id: &principal.id,
                        action: Permission::MachineRead,
                        resource: Some(&view.id),
                    },
                )
                .is_ok();
                if allowed {
                    out.push(ServiceMachine {
                        addresses: machine_addresses(&view),
                        id: view.id,
                        name: view.name,
                        status: view.machine_status,
                        tags: view.tags,
                    });
                }
            }
            if !full || out.len() >= MAX_MACHINES {
                break;
            }
        }
        Ok(out)
    }
}

#[async_trait]
impl ServiceRegistry for RegistryReadModel {
    async fn entries(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<Vec<RegistryEntryRecord>, InputError> {
        let mut out: Vec<RegistryEntryRecord> = Vec::new();
        let mut after: Option<EntryCursor> = None;
        loop {
            let answered = self
                .list_entries(
                    authorizer,
                    &principal.id,
                    &RegistryEntryFilter::default(),
                    after.as_ref(),
                    REGISTRY_PAGE,
                )
                .await
                .map_err(|error| match error {
                    crate::project::ProjectUseCaseError::Denied(decision) => {
                        InputError::Denied(decision)
                    }
                    other => InputError::Unavailable(other.to_string()),
                })?;
            let mut page = answered.value;
            let more = i64::try_from(page.len()).unwrap_or(i64::MAX) > REGISTRY_PAGE;
            page.truncate(usize::try_from(REGISTRY_PAGE).unwrap_or(usize::MAX));
            after = page.last().map(|entry| EntryCursor {
                entry_type: entry.entry_type.clone(),
                key: entry.key.clone(),
            });
            out.extend(page);
            if !more || out.len() >= MAX_REGISTRY_ENTRIES {
                break;
            }
        }
        Ok(out)
    }
}

/// A rejection of the services read.
#[derive(Debug)]
pub enum ServicesError {
    /// The caller may read none of the inputs.
    Denied(Decision),
    /// The service does not exist in the caller's view.
    NotFound,
}

impl fmt::Display for ServicesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::NotFound => write!(f, "not found: running service"),
        }
    }
}

impl std::error::Error for ServicesError {}

/// The running-service read use cases.
#[derive(Debug)]
pub struct RunningServices {
    accounts: Arc<dyn ExternalAccountPort>,
    observations: Arc<dyn CoolifyObservationPort>,
    machines: Arc<dyn ServiceMachines>,
    containers: Arc<dyn ContainerObservationPort>,
    registry: Option<Arc<dyn ServiceRegistry>>,
}

impl RunningServices {
    /// Composes the read model from its input ports.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn ExternalAccountPort>,
        observations: Arc<dyn CoolifyObservationPort>,
        machines: Arc<dyn ServiceMachines>,
        containers: Arc<dyn ContainerObservationPort>,
        registry: Option<Arc<dyn ServiceRegistry>>,
    ) -> Self {
        Self {
            accounts,
            observations,
            machines,
            containers,
            registry,
        }
    }

    /// Lists running services, filtered, with the coverage report.
    ///
    /// # Errors
    ///
    /// Fails with a denial only when the caller may read none of the
    /// inputs; any other input failure is reported in the coverage.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        filter: &ServiceFilter,
    ) -> Result<ServicesView, ServicesError> {
        let now = SystemClock::now_unix_millis();
        let mut view = self.gather(authorizer, principal, now).await?;
        view.services.retain(|service| filter.keeps(service));
        Ok(view)
    }

    /// Reads one service by id.
    ///
    /// # Errors
    ///
    /// Fails on denial, or when no such service is in the caller's view.
    pub async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<(RunningService, Coverage), ServicesError> {
        let now = SystemClock::now_unix_millis();
        let view = self.gather(authorizer, principal, now).await?;
        let service = view
            .services
            .into_iter()
            .find(|service| service.id == id)
            .ok_or(ServicesError::NotFound)?;
        Ok((service, view.coverage))
    }

    #[allow(clippy::too_many_lines)]
    async fn gather(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        now: i64,
    ) -> Result<ServicesView, ServicesError> {
        let mut denial: Option<Decision> = None;
        let mut input = JoinInput {
            now,
            ..JoinInput::default()
        };

        // Coolify: external_account.read.
        let mut account_coverage = Vec::new();
        let coolify = match authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::ExternalAccountRead,
                resource: None,
            },
        ) {
            Err(decision) => {
                denial.get_or_insert(decision);
                InputState::Denied
            }
            Ok(_) => match self.accounts.list().await {
                Err(detail) => InputState::Unavailable(detail),
                Ok(accounts) => {
                    let accounts: Vec<_> = accounts
                        .into_iter()
                        .filter(|a| a.kind == ExternalProviderKind::Coolify)
                        .collect();
                    if accounts.is_empty() {
                        InputState::NotConfigured
                    } else {
                        let mut failure = None;
                        for account in accounts {
                            match self.observations.load(&account.id).await {
                                Ok(snapshot) => {
                                    account_coverage.push(account_coverage_of(
                                        &account,
                                        snapshot.as_ref(),
                                        now,
                                    ));
                                    input.accounts.push(AccountInput { account, snapshot });
                                }
                                Err(detail) => failure = Some(detail),
                            }
                        }
                        failure.map_or(InputState::Available, InputState::Unavailable)
                    }
                }
            },
        };

        // Machines: machine.read per machine.
        let machines = match self.machines.machines(authorizer, principal, now).await {
            Ok(machines) => {
                input.machines = machines;
                InputState::Available
            }
            Err(InputError::Denied(decision)) => {
                denial.get_or_insert(decision);
                InputState::Denied
            }
            Err(InputError::Unavailable(detail)) => InputState::Unavailable(detail),
        };

        // Containers of the machines the caller may read.
        let containers = if !self.containers.available() {
            InputState::NotConfigured
        } else if machines != InputState::Available {
            machines.clone()
        } else {
            let ids: Vec<String> = input.machines.iter().map(|m| m.id.clone()).collect();
            match self.containers.observed(&ids).await {
                Ok(found) => {
                    input.containers = found
                        .into_iter()
                        .filter(|c| ids.contains(&c.machine_id))
                        .collect();
                    InputState::Available
                }
                Err(detail) => InputState::Unavailable(detail),
            }
        };

        // Registry: registry.read.
        let registry = match &self.registry {
            None => InputState::NotConfigured,
            Some(registry) => match registry.entries(authorizer, principal).await {
                Ok(entries) => {
                    input.registry = entries;
                    InputState::Available
                }
                Err(InputError::Denied(decision)) => {
                    denial.get_or_insert(decision);
                    InputState::Denied
                }
                Err(InputError::Unavailable(detail)) => InputState::Unavailable(detail),
            },
        };

        let unreadable =
            |state: &InputState| matches!(state, InputState::Denied | InputState::NotConfigured);
        if denial.is_some()
            && unreadable(&coolify)
            && unreadable(&machines)
            && unreadable(&registry)
            && let Some(decision) = denial
        {
            return Err(ServicesError::Denied(decision));
        }
        let joined = join(&input);
        Ok(ServicesView {
            services: joined.services,
            ambiguous_servers: joined.ambiguous_servers,
            coverage: Coverage {
                coolify,
                accounts: account_coverage,
                machines,
                containers,
                registry,
            },
            evaluated_at: now,
        })
    }
}

fn account_coverage_of(
    account: &ExternalAccount,
    snapshot: Option<&(CoolifySnapshot, i64)>,
    now: i64,
) -> AccountCoverage {
    let mut coverage = AccountCoverage {
        account_id: account.id.clone(),
        label: account.label.clone(),
        observed: snapshot.is_some(),
        recorded_at: snapshot.map(|(_, at)| *at),
        stale_classes: Vec::new(),
        truncated_classes: Vec::new(),
    };
    if let Some((snapshot, _)) = snapshot {
        let truncated = [
            ("servers", snapshot.servers.truncated),
            ("projects", snapshot.projects.truncated),
            ("applications", snapshot.applications.truncated),
            ("services", snapshot.services.truncated),
            ("databases", snapshot.databases.truncated),
            ("deployments", snapshot.deployments.truncated),
        ];
        for (class, _, stale, _) in snapshot.summary(now) {
            if stale {
                coverage.stale_classes.push(class.id().to_owned());
            }
        }
        for (class, cut) in truncated {
            if cut {
                coverage.truncated_classes.push(class.to_owned());
            }
        }
    }
    coverage
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coolify::{
        ClassFailure, CoolifyDeployment, CoolifyEnvironment, CoolifyProject, FailureKind,
    };
    use crate::registry::{RegistryRelationRecord, RegistryTarget};

    const NOW: i64 = 10_000_000;

    fn account() -> ExternalAccount {
        ExternalAccount {
            id: "acc1".to_owned(),
            kind: ExternalProviderKind::Coolify,
            label: "prod".to_owned(),
            base_url: "https://coolify.example.test/".to_owned(),
            scope_id: None,
            notes: String::new(),
            last_probe: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn server(uuid: &str, name: &str, address: &str) -> CoolifyServer {
        CoolifyServer {
            uuid: uuid.to_owned(),
            name: name.to_owned(),
            address: address.to_owned(),
            ..CoolifyServer::default()
        }
    }

    fn app(uuid: &str, name: &str, fqdns: &[&str]) -> CoolifyApplication {
        CoolifyApplication {
            uuid: uuid.to_owned(),
            name: name.to_owned(),
            status: "running:healthy".to_owned(),
            fqdns: fqdns.iter().map(|f| (*f).to_owned()).collect(),
            environment_id: Some(1),
            ..CoolifyApplication::default()
        }
    }

    fn fresh<T>(items: Vec<T>) -> crate::coolify::ClassObservation<T> {
        crate::coolify::ClassObservation {
            attempted_at: NOW,
            observed_at: Some(NOW),
            items,
            ..crate::coolify::ClassObservation::default()
        }
    }

    fn snapshot(servers: Vec<CoolifyServer>, apps: Vec<CoolifyApplication>) -> CoolifySnapshot {
        CoolifySnapshot {
            servers: fresh(servers),
            projects: fresh(vec![CoolifyProject {
                uuid: "prj1".to_owned(),
                name: "shop".to_owned(),
                environments: vec![CoolifyEnvironment {
                    id: 1,
                    name: "production".to_owned(),
                    description: String::new(),
                }],
                ..CoolifyProject::default()
            }]),
            applications: fresh(apps),
            services: fresh(Vec::new()),
            databases: fresh(Vec::new()),
            deployments: fresh(Vec::new()),
            ..CoolifySnapshot::default()
        }
    }

    fn machine(id: &str, address: &str, tags: &[&str]) -> ServiceMachine {
        ServiceMachine {
            id: id.to_owned(),
            name: format!("name-{id}"),
            status: MachineStatus::Connected,
            addresses: vec![address.to_owned()],
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
        }
    }

    fn container(id: &str, name: &str, labels: Option<CoolifyLabels>) -> ObservedContainer {
        ObservedContainer {
            id: id.to_owned(),
            name: name.to_owned(),
            image: "img:1".to_owned(),
            state: "running".to_owned(),
            status: "Up 1 hour".to_owned(),
            coolify: labels,
        }
    }

    fn on(machine_id: &str, containers: Vec<ObservedContainer>) -> MachineContainers {
        MachineContainers {
            machine_id: machine_id.to_owned(),
            observed_at: Some(NOW),
            containers,
        }
    }

    fn input(snapshot: Option<CoolifySnapshot>) -> JoinInput {
        JoinInput {
            now: NOW,
            accounts: vec![AccountInput {
                account: account(),
                snapshot: snapshot.map(|s| (s, NOW)),
            }],
            ..JoinInput::default()
        }
    }

    fn entry(
        entry_type: &str,
        key: &str,
        relations: Vec<(&str, &str, &str)>,
    ) -> RegistryEntryRecord {
        RegistryEntryRecord {
            entry_type: entry_type.to_owned(),
            key: key.to_owned(),
            resource_id: "r".to_owned(),
            name: key.to_owned(),
            fields: serde_json::json!({}),
            tags: Vec::new(),
            links: serde_json::json!([]),
            notes: None,
            relations: relations
                .into_iter()
                .map(|(kind, class, reference)| RegistryRelationRecord {
                    relation_type: kind.to_owned(),
                    target: RegistryTarget {
                        class: class.to_owned(),
                        reference: reference.to_owned(),
                    },
                })
                .collect(),
            source_path: None,
        }
    }

    #[test]
    fn coolify_only_resource_with_sole_server_and_deep_link() {
        let mut snap = snapshot(
            vec![server("s1", "local", "10.0.0.9")],
            vec![app("a1", "web", &["https://shop.example.test"])],
        );
        snap.deployments = fresh(vec![CoolifyDeployment {
            deployment_uuid: "d1".to_owned(),
            application_uuid: Some("a1".to_owned()),
            status: "finished".to_owned(),
            created_at: Some("2026-01-01T00:00:00Z".to_owned()),
            ..CoolifyDeployment::default()
        }]);
        let out = join(&input(Some(snap)));
        assert_eq!(out.services.len(), 1);
        let service = &out.services[0];
        assert_eq!(service.id, "coolify:acc1:a1");
        assert_eq!(service.sources, vec![ServiceSource::Coolify]);
        assert_eq!(service.state, ServiceState::Running);
        assert_eq!(service.server.as_ref().unwrap().uuid, "s1");
        assert_eq!(service.placement.state, MatchState::Unmatched);
        assert_eq!(
            service.deep_link.as_deref(),
            Some("https://coolify.example.test/project/prj1")
        );
        assert_eq!(service.last_deploy.as_ref().unwrap().status, "finished");
        assert!(!service.stale);
    }

    #[test]
    fn docker_only_containers_are_their_own_services() {
        let mut join_input = JoinInput {
            now: NOW,
            machines: vec![machine("m1", "10.0.0.9", &[])],
            containers: vec![on("m1", vec![container("c1", "redis", None)])],
            ..JoinInput::default()
        };
        let out = join(&join_input);
        assert_eq!(out.services.len(), 1);
        assert_eq!(out.services[0].id, "docker:m1:redis");
        assert_eq!(out.services[0].sources, vec![ServiceSource::Docker]);
        assert_eq!(out.services[0].placement.machine.as_ref().unwrap().id, "m1");
        // A machine the caller cannot read contributes nothing.
        join_input.machines.clear();
        assert!(join(&join_input).services.is_empty());
    }

    #[test]
    fn a_coolify_resource_and_its_container_are_listed_once() {
        let mut join_input = input(Some(snapshot(
            vec![
                server("s1", "local", "10.0.0.9"),
                server("s2", "edge", "10.0.0.8"),
            ],
            vec![app("a1", "web", &[])],
        )));
        join_input.machines = vec![
            machine("m1", "10.0.0.9", &[]),
            machine("m2", "10.0.0.8", &[]),
        ];
        join_input.containers = vec![on(
            "m2",
            vec![
                container(
                    "c1",
                    "a1-123",
                    CoolifyLabels::from_labels([
                        ("coolify.managed", "true"),
                        ("coolify.applicationUuid", "A1"),
                        ("com.example.secret", "hunter2"),
                    ]),
                ),
                container("c2", "plain", None),
            ],
        )];
        let out = join(&join_input);
        let ids: Vec<_> = out.services.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["coolify:acc1:a1", "docker:m2:plain"]);
        let web = &out.services[0];
        assert_eq!(
            web.sources,
            vec![ServiceSource::Coolify, ServiceSource::Docker]
        );
        assert_eq!(web.containers.len(), 1);
        assert_eq!(web.placement.basis, Some(MatchBasis::Container));
        assert_eq!(web.placement.machine.as_ref().unwrap().id, "m2");
        // The container evidence also resolves the server.
        assert_eq!(web.server.as_ref().unwrap().uuid, "s2");
    }

    #[test]
    fn an_ambiguous_server_is_reported_and_never_guessed() {
        let mut join_input = input(Some(snapshot(
            vec![server("s1", "local", "10.0.0.9")],
            vec![app("a1", "web", &[])],
        )));
        join_input.machines = vec![
            machine("m1", "10.0.0.9", &[]),
            machine("m2", "10.0.0.9", &[]),
        ];
        let out = join(&join_input);
        assert_eq!(out.ambiguous_servers.len(), 1);
        assert_eq!(out.ambiguous_servers[0].candidates.len(), 2);
        assert_eq!(out.ambiguous_servers[0].basis, MatchBasis::Address);
        let web = &out.services[0];
        assert_eq!(web.placement.state, MatchState::Ambiguous);
        assert!(web.placement.machine.is_none());
        assert_eq!(web.placement.candidates.len(), 2);
    }

    #[test]
    fn an_explicit_tag_wins_over_an_address_match() {
        let mut join_input = input(Some(snapshot(
            vec![server("S1", "local", "10.0.0.9")],
            vec![app("a1", "web", &[])],
        )));
        join_input.machines = vec![
            machine("m1", "10.0.0.9", &[]),
            machine("m2", "10.9.9.9", &["coolify-server:s1"]),
        ];
        let out = join(&join_input);
        assert!(out.ambiguous_servers.is_empty());
        let web = &out.services[0];
        assert_eq!(web.placement.machine.as_ref().unwrap().id, "m2");
        assert_eq!(web.placement.basis, Some(MatchBasis::ExplicitTag));
    }

    #[test]
    fn fqdns_link_domain_entries_and_hosted_on_relations() {
        let mut join_input = input(Some(snapshot(
            vec![server("s1", "local", "10.0.0.9")],
            vec![app("a1", "web", &["https://WWW.Shop.example.test/"])],
        )));
        join_input.registry = vec![
            entry("domain", "Shop.example.test", vec![]),
            entry("domain", "other.example.test", vec![]),
            entry("domain", "hop.example.test", vec![]),
            entry("service", "hosting", vec![("hosted-on", "coolify", "A1")]),
            entry(
                "service",
                "unrelated",
                vec![("hosted-on", "coolify", "zzz")],
            ),
        ];
        let out = join(&join_input);
        let links = &out.services[0].registry;
        let summary: Vec<_> = links
            .iter()
            .map(|l| (l.entry_type.as_str(), l.key.as_str(), l.link))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("domain", "Shop.example.test", RegistryLinkKind::DomainMatch),
                ("service", "hosting", RegistryLinkKind::HostedOn),
            ]
        );
        assert_eq!(links[0].host.as_deref(), Some("www.shop.example.test"));
    }

    #[test]
    fn staleness_propagates_from_every_input() {
        let mut snap = snapshot(
            vec![server("s1", "local", "10.0.0.9")],
            vec![app("a1", "web", &[])],
        );
        snap.applications.failure = Some(ClassFailure {
            kind: FailureKind::Unreachable,
            detail: "x".to_owned(),
        });
        let mut join_input = input(Some(snap));
        let mut offline = machine("m1", "10.0.0.9", &[]);
        offline.status = MachineStatus::Offline;
        join_input.machines = vec![offline];
        join_input.containers = vec![MachineContainers {
            machine_id: "m1".to_owned(),
            observed_at: Some(NOW - CONTAINER_STALE_AFTER_MS - 1),
            containers: vec![
                container(
                    "c1",
                    "a1-1",
                    CoolifyLabels::from_labels([("coolify.applicationUuid", "a1")]),
                ),
                container("c2", "plain", None),
            ],
        }];
        let out = join(&join_input);
        let web = out
            .services
            .iter()
            .find(|s| s.id == "coolify:acc1:a1")
            .unwrap();
        assert!(web.stale);
        assert_eq!(
            web.stale_reasons,
            vec![
                "coolify_applications_stale",
                "machine_offline",
                "containers_stale"
            ]
        );
        let plain = out
            .services
            .iter()
            .find(|s| s.id == "docker:m1:plain")
            .unwrap();
        assert_eq!(
            plain.stale_reasons,
            vec!["machine_offline", "containers_stale"]
        );
    }

    #[test]
    fn host_normalization_handles_urls_ports_and_brackets() {
        assert_eq!(normalize_host("root@Host.Example:2222"), "host.example");
        assert_eq!(normalize_host("https://a.b/c?d"), "a.b");
        assert_eq!(normalize_host("[fd7a::1]:22"), "fd7a::1");
        assert_eq!(normalize_host("10.0.0.1."), "10.0.0.1");
        assert!(domain_matches("example.com", "www.example.com"));
        assert!(!domain_matches("example.com", "badexample.com"));
    }

    #[test]
    fn states_normalize() {
        assert_eq!(
            ServiceState::from_coolify("running:healthy"),
            ServiceState::Running
        );
        assert_eq!(
            ServiceState::from_coolify("running:unhealthy"),
            ServiceState::Degraded
        );
        assert_eq!(
            ServiceState::from_coolify("exited:unhealthy"),
            ServiceState::Stopped
        );
        assert_eq!(ServiceState::from_coolify(""), ServiceState::Unknown);
        assert_eq!(
            ServiceState::from_docker("running", "Up (unhealthy)"),
            ServiceState::Degraded
        );
    }
}
