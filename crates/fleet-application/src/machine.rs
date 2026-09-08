//! The machine use cases: stable identity over mutable facts.
//!
//! A machine is registered once and then observed endlessly. Registration
//! mints the identity; everything else — names, endpoints, tags, groups,
//! capability facts, inventory snapshots — changes through the use cases
//! here, each behind the authorization funnel and each mutation audited.
//!
//! The port below is the storage contract; the SQLite adapter implements it.
//! Deliberately absent: anything that *reaches* a machine. SSH execution,
//! node protocol, and probes belong to their own providers and services;
//! this module only owns what is true about a machine as a matter of record.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::node::{GatewayState, NodeStatus};
use crate::operation::PortFailure;
use fleet_core::{CapabilityFact, CapabilityStatus, EndpointKind, Timestamp};

/// How long a recorded `known` capability fact stays fresh in the read
/// model before it displays as `stale`. Probes run on demand — an
/// `agentless.inventory` operation or a `node.inventory` command — not on a
/// timer, so this threshold is deliberately generous: it says "nothing has
/// re-observed this fact for a day", not "the fact is wrong". The exact
/// observation time always travels with the fact.
pub const CAPABILITY_FRESHNESS_MS: i64 = 24 * 60 * 60 * 1000;

/// One registered machine, as read back by queries.
///
/// This is the *record*: what was observed, as it was observed. The
/// operator-facing read model is [`MachineView`], which derives machine
/// status and effective fact statuses at a read time.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Machine {
    /// The stable identity.
    pub id: String,
    /// The mutable, unique label.
    pub name: String,
    /// Operator notes.
    pub description: String,
    /// How the machine is reached today; endpoints coexist.
    pub endpoints: Vec<Endpoint>,
    /// Tags, filterable.
    pub tags: Vec<String>,
    /// Groups, filterable.
    pub groups: Vec<String>,
    /// The recorded capability facts, upserted per `(namespace, name)`.
    pub capabilities: Vec<CapabilityFact>,
    /// The newest inventory observation, when the machine was ever probed.
    pub last_observation: Option<InventoryObservation>,
    /// The node trust link, when the machine has an enrolled node.
    pub node: Option<NodeLink>,
    /// Registration time (epoch milliseconds).
    pub created_at: i64,
    /// Last mutation (epoch milliseconds).
    pub updated_at: i64,
}

/// One connection endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    /// The endpoint's identity.
    pub id: String,
    /// How this endpoint reaches the machine.
    pub kind: EndpointKind,
    /// The reference, e.g. `user@host:port` for SSH or the node id for
    /// fleetd. Never carries a secret.
    pub reference: String,
}

/// The newest inventory observation of a machine: what probed it and when.
/// The payload itself stays in the snapshot record; the read model surfaces
/// only the provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryObservation {
    /// What observed it, e.g. `agentless/1` or `fleetd/1.2.3`.
    pub source: String,
    /// When the observation was collected (epoch milliseconds).
    pub collected_at: i64,
}

/// The node trust link recorded for a machine, when one is enrolled. This
/// is the connectivity half of the node relationship; keys, credentials,
/// and tokens stay behind `node.read` on the node surface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeLink {
    /// The durable gateway state the session registry last persisted.
    pub gateway_state: GatewayState,
    /// The identity's status; a revoked identity can never reconnect.
    pub identity_status: NodeStatus,
    /// The last gateway observation time, when the node ever connected
    /// (epoch milliseconds).
    pub last_seen_at: Option<i64>,
}

/// The derived connectivity state of a machine, as the list and detail
/// views display it. `agentless` means reached over SSH with no enrolled
/// node; `connected`, `stale`, and `offline` are the node gateway's own
/// vocabulary. A machine whose node identity was revoked is `offline`: the
/// honest state of something that cannot reconnect until re-enrolled.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineStatus {
    /// The node gateway session is open and heartbeats are fresh.
    Connected,
    /// The node gateway session is open but heartbeats aged past the
    /// threshold.
    Stale,
    /// No live node session: absent, or enrolled but never connected, or
    /// revoked.
    Offline,
    /// No node identity: reached over SSH only.
    Agentless,
}

impl MachineStatus {
    /// The stable string used in the API and the CLI.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Stale => "stale",
            Self::Offline => "offline",
            Self::Agentless => "agentless",
        }
    }

    /// Parses the stable string.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "connected" => Some(Self::Connected),
            "stale" => Some(Self::Stale),
            "offline" => Some(Self::Offline),
            "agentless" => Some(Self::Agentless),
            _ => None,
        }
    }

    /// Derives the machine status from the recorded node link, when any.
    #[must_use]
    pub fn derive(node: Option<&NodeLink>) -> Self {
        match node {
            None => Self::Agentless,
            Some(link) => match link.identity_status {
                NodeStatus::Revoked => Self::Offline,
                NodeStatus::Active => match link.gateway_state {
                    GatewayState::Connected => Self::Connected,
                    GatewayState::Stale => Self::Stale,
                    GatewayState::Offline => Self::Offline,
                },
            },
        }
    }
}

/// One capability fact as the read model displays it: the recorded status
/// with the staleness rule applied at the read time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityFactView {
    /// The namespace, e.g. `os`, `tool`, `agent`.
    pub namespace: String,
    /// The capability name within the namespace, e.g. `git`, `family`.
    pub name: String,
    /// The observed value, when the capability has one.
    pub value: Option<String>,
    /// The effective status at the read time: recorded `known` ages into
    /// `stale`; `unknown` and `unavailable` are what the machine reported.
    pub status: CapabilityStatus,
    /// When the fact was observed (epoch milliseconds).
    pub observed_at: i64,
    /// What observed it: a probe name and version, e.g. `agentless/1`.
    pub source: String,
}

/// The operator-facing machine read model: the record with the derived
/// machine status, the effective capability statuses, and credential-bearing
/// endpoint detail redacted when the caller may not see it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineView {
    /// The stable identity.
    pub id: String,
    /// The mutable, unique label.
    pub name: String,
    /// Operator notes.
    pub description: String,
    /// How the machine is reached today; endpoint references are redacted
    /// unless the caller may read sensitive endpoint detail.
    pub endpoints: Vec<Endpoint>,
    /// Tags, filterable.
    pub tags: Vec<String>,
    /// Groups, filterable.
    pub groups: Vec<String>,
    /// The derived connectivity state at the read time.
    pub machine_status: MachineStatus,
    /// The last gateway observation time, when the node ever connected
    /// (epoch milliseconds).
    pub last_seen_at: Option<i64>,
    /// The newest inventory observation, when the machine was ever probed.
    pub last_observation: Option<InventoryObservation>,
    /// The capability facts with effective statuses at the read time.
    pub capabilities: Vec<CapabilityFactView>,
    /// Registration time (epoch milliseconds).
    pub created_at: i64,
    /// Last mutation (epoch milliseconds).
    pub updated_at: i64,
}

impl MachineView {
    /// Assembles the view from the record at the given read time.
    ///
    /// `sensitive` is the authorization answer for the caller's
    /// `machine.read.sensitive` request; when it is denied, the userinfo of
    /// ssh endpoint references is redacted. The decision belongs to the use
    /// case because it shapes what a caller may see, and the authorization
    /// funnel is the only place that decides.
    #[must_use]
    pub fn assemble(machine: Machine, now: i64, sensitive: bool) -> Self {
        let machine_status = MachineStatus::derive(machine.node.as_ref());
        let capabilities = machine
            .capabilities
            .iter()
            .map(|fact| CapabilityFactView {
                namespace: fact.namespace.clone(),
                name: fact.name.clone(),
                value: fact.value.clone(),
                status: fact
                    .effective_status(Timestamp::from_unix_millis(now), CAPABILITY_FRESHNESS_MS),
                observed_at: fact.observed_at.unix_millis(),
                source: fact.source.clone(),
            })
            .collect();
        MachineView {
            id: machine.id,
            name: machine.name,
            description: machine.description,
            endpoints: machine
                .endpoints
                .iter()
                .map(|endpoint| Endpoint {
                    id: endpoint.id.clone(),
                    kind: endpoint.kind,
                    reference: if sensitive {
                        endpoint.reference.clone()
                    } else {
                        redact_userinfo(&endpoint.reference)
                    },
                })
                .collect(),
            tags: machine.tags,
            groups: machine.groups,
            machine_status,
            last_seen_at: machine.node.and_then(|node| node.last_seen_at),
            last_observation: machine.last_observation,
            capabilities,
            created_at: machine.created_at,
            updated_at: machine.updated_at,
        }
    }
}

/// Replaces the userinfo of a `user@host` reference with a marker. A
/// reference without userinfo is unchanged; the host is not sensitive
/// (the machine's endpoints are already the point of the surface).
fn redact_userinfo(reference: &str) -> String {
    match reference.split_once('@') {
        Some((_, host)) => format!("***@{host}"),
        None => reference.to_owned(),
    }
}

/// A registration request: identity is minted here, not supplied.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterMachine {
    /// The machine's unique name.
    pub name: String,
    /// Operator notes.
    pub description: String,
    /// Initial endpoints; at least one is required so a machine is never
    /// registered unreachable.
    pub endpoints: Vec<NewEndpoint>,
    /// Initial tags.
    pub tags: Vec<String>,
    /// Initial groups.
    pub groups: Vec<String>,
}

/// A new endpoint, before identity minting.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewEndpoint {
    /// How this endpoint reaches the machine.
    pub kind: EndpointKind,
    /// The reference.
    pub reference: String,
}

/// Filters for the machine list; every filter narrows, and absent filters
/// match everything.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MachineFilter {
    /// Only machines carrying this tag.
    pub tag: Option<String>,
    /// Only machines in this group.
    pub group: Option<String>,
    /// Only machines whose capability `(namespace, name)` exists.
    pub capability: Option<(String, String)>,
    /// Only machines in this derived connectivity state. `agentless` means
    /// "no node identity", so it cannot be combined with the other values.
    pub status: Option<MachineStatus>,
}

/// A use-case rejection, mapped onto public API errors by the adapter.
#[derive(Debug)]
pub enum MachineUseCaseError {
    /// The caller may not perform the action.
    Denied(Decision),
    /// The machine, tag, or endpoint named does not exist.
    NotFound {
        /// What was not found.
        what: String,
    },
    /// The name or reference is taken, or malformed.
    Conflict {
        /// What conflicts.
        detail: String,
    },
    /// The request is malformed.
    Invalid {
        /// What is wrong.
        detail: String,
    },
    /// The port failed.
    Backend {
        /// Where.
        context: &'static str,
        /// The failure detail.
        detail: String,
    },
}

impl fmt::Display for MachineUseCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Conflict { detail } => write!(f, "conflict: {detail}"),
            Self::Invalid { detail } => write!(f, "invalid request: {detail}"),
            Self::Backend { context, detail } => write!(f, "machine {context} failed: {detail}"),
        }
    }
}

impl std::error::Error for MachineUseCaseError {}

/// The storage contract for machines.
#[async_trait]
pub trait MachinePort: fmt::Debug + Send + Sync {
    /// Registers a machine with its initial facts.
    ///
    /// # Errors
    ///
    /// Fails on a taken name, an unknown tag, or a backend error.
    async fn register(&self, registration: &RegisterMachine) -> Result<Machine, PortFailure>;
    /// Reads one machine.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn get(&self, id: &str) -> Result<Machine, PortFailure>;
    /// Lists machines, newest first, narrowed by the filter.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list(&self, filter: &MachineFilter, limit: u32) -> Result<Vec<Machine>, PortFailure>;
    /// Renames or re-describes a machine.
    ///
    /// # Errors
    ///
    /// Fails when unknown, the name is taken, or the backend errors.
    async fn update(&self, id: &str, name: &str, description: &str)
    -> Result<Machine, PortFailure>;
    /// Replaces the machine's endpoint set.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn set_endpoints(
        &self,
        id: &str,
        endpoints: &[NewEndpoint],
    ) -> Result<Machine, PortFailure>;
    /// Adds one tag to a machine, creating the tag if needed.
    ///
    /// # Errors
    ///
    /// Fails when the machine is unknown or the backend errors.
    async fn add_tag(&self, id: &str, tag: &str) -> Result<Machine, PortFailure>;
    /// Removes one tag from a machine.
    ///
    /// # Errors
    ///
    /// Fails when the machine is unknown or the backend errors.
    async fn remove_tag(&self, id: &str, tag: &str) -> Result<Machine, PortFailure>;
    /// Adds the machine to one group, creating the group if needed.
    ///
    /// # Errors
    ///
    /// Fails when the machine is unknown or the backend errors.
    async fn add_group(&self, id: &str, group: &str) -> Result<Machine, PortFailure>;
    /// Removes the machine from one group.
    ///
    /// # Errors
    ///
    /// Fails when the machine is unknown or the backend errors.
    async fn remove_group(&self, id: &str, group: &str) -> Result<Machine, PortFailure>;
    /// Records one inventory snapshot.
    ///
    /// # Errors
    ///
    /// Fails when the machine is unknown or the backend errors.
    async fn record_snapshot(
        &self,
        id: &str,
        source: &str,
        payload_json: &str,
        collected_at: i64,
    ) -> Result<(), PortFailure>;
    /// Upserts capability facts for a machine.
    ///
    /// # Errors
    ///
    /// Fails when the machine is unknown, a fact is malformed, or the
    /// backend errors.
    async fn record_capabilities(
        &self,
        id: &str,
        facts: &[CapabilityFact],
    ) -> Result<(), PortFailure>;
    /// Removes a machine and all its facts.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn delete(&self, id: &str) -> Result<(), PortFailure>;
    /// Records an operator-confirmed host-key fingerprint on one endpoint.
    ///
    /// # Errors
    ///
    /// Fails when the endpoint is unknown or the backend errors.
    async fn confirm_fingerprint(
        &self,
        endpoint_id: &str,
        fingerprint: &str,
        confirmed_at: i64,
    ) -> Result<(), PortFailure>;
    /// The fingerprint previously confirmed for one endpoint, when any.
    ///
    /// # Errors
    ///
    /// Fails when the endpoint is unknown or the backend errors.
    async fn verified_fingerprint(&self, endpoint_id: &str) -> Result<Option<String>, PortFailure>;
    /// The revision of the newest inventory snapshot recorded for a
    /// machine, when any. This is what the controller sends back as
    /// `expectedRevision`, so the node answers with a delta when the two
    /// agree and a full snapshot when they have drifted apart.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn latest_inventory_revision(&self, machine_id: &str)
    -> Result<Option<u64>, PortFailure>;
}

/// The authorized machine use cases.
#[derive(Debug)]
pub struct Machines {
    port: Arc<dyn MachinePort>,
    audit: Arc<dyn crate::operation::AuditPort>,
}

impl Machines {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(port: Arc<dyn MachinePort>, audit: Arc<dyn crate::operation::AuditPort>) -> Self {
        Self { port, audit }
    }

    /// Registers a machine.
    ///
    /// # Errors
    ///
    /// Fails on denial or a malformed or conflicting registration.
    pub async fn register(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        registration: &RegisterMachine,
    ) -> Result<Machine, MachineUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineCreate,
                resource: None,
            },
        )
        .map_err(MachineUseCaseError::Denied)?;
        validate_registration(registration)?;

        let machine = self
            .port
            .register(registration)
            .await
            .map_err(|failure| map_port("register", failure))?;
        self.audit_machine(
            principal,
            Permission::MachineCreate,
            &machine.id,
            Some(machine.correlation_note()),
        )
        .await?;
        Ok(machine)
    }

    /// Reads one machine as the operator-facing view.
    ///
    /// The staleness rule is applied at `now`, so callers — and tests —
    /// decide the read time. Endpoint references carry their
    /// credential-bearing detail only when the caller is authorized for
    /// `machine.read.sensitive`; otherwise the userinfo is redacted.
    ///
    /// # Errors
    ///
    /// Fails on denial or an unknown machine.
    pub async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        now: i64,
    ) -> Result<MachineView, MachineUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineRead,
                resource: Some(id),
            },
        )
        .map_err(MachineUseCaseError::Denied)?;
        let sensitive = self.may_read_sensitive(authorizer, principal, id);
        let machine = self
            .port
            .get(id)
            .await
            .map_err(|failure| map_port("get", failure))?;
        Ok(MachineView::assemble(machine, now, sensitive))
    }

    /// Lists machines, newest first, as the operator-facing view.
    ///
    /// The staleness rule is applied at `now`, and the sensitive-endpoint
    /// question is asked per machine, so a future policy can grant
    /// unredacted detail for some machines and not others.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        filter: &MachineFilter,
        limit: u32,
        now: i64,
    ) -> Result<Vec<MachineView>, MachineUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineRead,
                resource: None,
            },
        )
        .map_err(MachineUseCaseError::Denied)?;
        let machines = self
            .port
            .list(filter, limit)
            .await
            .map_err(|failure| map_port("list", failure))?;
        Ok(machines
            .into_iter()
            .map(|machine| {
                let sensitive = self.may_read_sensitive(authorizer, principal, &machine.id);
                MachineView::assemble(machine, now, sensitive)
            })
            .collect())
    }

    /// Asks the authorizer once for the sensitive endpoint detail of one
    /// machine. A denial is not an error: it redacts, it does not refuse.
    #[allow(clippy::unused_self)]
    fn may_read_sensitive(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
    ) -> bool {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineReadSensitive,
                resource: Some(machine_id),
            },
        )
        .is_ok()
    }

    /// Renames or re-describes a machine.
    ///
    /// # Errors
    ///
    /// Fails on denial, unknown machine, or a taken name.
    pub async fn update(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        name: &str,
        description: &str,
    ) -> Result<Machine, MachineUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineUpdate,
                resource: Some(id),
            },
        )
        .map_err(MachineUseCaseError::Denied)?;
        validate_name(name).map_err(|detail| MachineUseCaseError::Invalid { detail })?;

        let machine = self
            .port
            .update(id, name, description)
            .await
            .map_err(|failure| map_port("update", failure))?;
        self.audit_machine(
            principal,
            Permission::MachineUpdate,
            id,
            Some(machine.correlation_note()),
        )
        .await?;
        Ok(machine)
    }

    /// Replaces the machine's endpoints.
    ///
    /// # Errors
    ///
    /// Fails on denial, unknown machine, or malformed endpoints.
    pub async fn set_endpoints(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        endpoints: &[NewEndpoint],
    ) -> Result<Machine, MachineUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineUpdate,
                resource: Some(id),
            },
        )
        .map_err(MachineUseCaseError::Denied)?;
        validate_endpoints(endpoints)?;

        let machine = self
            .port
            .set_endpoints(id, endpoints)
            .await
            .map_err(|failure| map_port("set_endpoints", failure))?;
        self.audit_machine(
            principal,
            Permission::MachineUpdate,
            id,
            Some(machine.correlation_note()),
        )
        .await?;
        Ok(machine)
    }

    /// Adds a tag.
    ///
    /// # Errors
    ///
    /// Fails on denial or an unknown machine.
    pub async fn add_tag(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        tag: &str,
    ) -> Result<Machine, MachineUseCaseError> {
        self.authorized_tag_group_change(authorizer, principal, id, "tag", tag)?;
        let machine = self
            .port
            .add_tag(id, tag)
            .await
            .map_err(|failure| map_port("add_tag", failure))?;
        self.audit_machine(
            principal,
            Permission::MachineUpdate,
            id,
            Some(machine.correlation_note()),
        )
        .await?;
        Ok(machine)
    }

    /// Removes a tag.
    ///
    /// # Errors
    ///
    /// Fails on denial or an unknown machine.
    pub async fn remove_tag(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        tag: &str,
    ) -> Result<Machine, MachineUseCaseError> {
        self.authorized_tag_group_change(authorizer, principal, id, "tag", tag)?;
        let machine = self
            .port
            .remove_tag(id, tag)
            .await
            .map_err(|failure| map_port("remove_tag", failure))?;
        self.audit_machine(
            principal,
            Permission::MachineUpdate,
            id,
            Some(machine.correlation_note()),
        )
        .await?;
        Ok(machine)
    }

    /// Adds a group.
    ///
    /// # Errors
    ///
    /// Fails on denial or an unknown machine.
    pub async fn add_group(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        group: &str,
    ) -> Result<Machine, MachineUseCaseError> {
        self.authorized_tag_group_change(authorizer, principal, id, "group", group)?;
        let machine = self
            .port
            .add_group(id, group)
            .await
            .map_err(|failure| map_port("add_group", failure))?;
        self.audit_machine(
            principal,
            Permission::MachineUpdate,
            id,
            Some(machine.correlation_note()),
        )
        .await?;
        Ok(machine)
    }

    /// Removes a group.
    ///
    /// # Errors
    ///
    /// Fails on denial or an unknown machine.
    pub async fn remove_group(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        group: &str,
    ) -> Result<Machine, MachineUseCaseError> {
        self.authorized_tag_group_change(authorizer, principal, id, "group", group)?;
        let machine = self
            .port
            .remove_group(id, group)
            .await
            .map_err(|failure| map_port("remove_group", failure))?;
        self.audit_machine(
            principal,
            Permission::MachineUpdate,
            id,
            Some(machine.correlation_note()),
        )
        .await?;
        Ok(machine)
    }

    /// Records an inventory snapshot. Observations are recorded data, not
    /// mutations a caller directs; the authorization is machine-update
    /// because the facts change, but no audit intent is appended — snapshots
    /// can arrive every minute and would drown the ledger. The snapshot
    /// itself is the record.
    ///
    /// # Errors
    ///
    /// Fails on denial, unknown machine, or a backend failure.
    pub async fn record_snapshot(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        source: &str,
        payload_json: &str,
        collected_at: i64,
    ) -> Result<(), MachineUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineUpdate,
                resource: Some(id),
            },
        )
        .map_err(MachineUseCaseError::Denied)?;
        if payload_json.len() > 64 * 1024 {
            return Err(MachineUseCaseError::Invalid {
                detail: "the snapshot payload exceeds 64 KiB".to_owned(),
            });
        }
        self.port
            .record_snapshot(id, source, payload_json, collected_at)
            .await
            .map_err(|failure| map_port("record_snapshot", failure))
    }

    /// Upserts capability facts.
    ///
    /// # Errors
    ///
    /// Fails on denial, unknown machine, malformed facts, or a backend
    /// failure.
    pub async fn record_capabilities(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        facts: &[CapabilityFact],
    ) -> Result<(), MachineUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineUpdate,
                resource: Some(id),
            },
        )
        .map_err(MachineUseCaseError::Denied)?;
        for fact in facts {
            fact.validate()
                .map_err(|detail| MachineUseCaseError::Invalid { detail })?;
        }
        self.port
            .record_capabilities(id, facts)
            .await
            .map_err(|failure| map_port("record_capabilities", failure))
    }

    /// Records an operator-confirmed host-key fingerprint for an endpoint.
    /// This is the trust-on-first-use confirmation: the caller supplies the
    /// fingerprint it verified out of band, and the confirmation is audited.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown endpoint, or a backend failure.
    pub async fn confirm_host_key(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        endpoint_id: &str,
        fingerprint: &str,
    ) -> Result<(), MachineUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineUpdate,
                resource: Some(endpoint_id),
            },
        )
        .map_err(MachineUseCaseError::Denied)?;
        if !fingerprint.starts_with("SHA256:") || fingerprint.len() > 128 {
            return Err(MachineUseCaseError::Invalid {
                detail: "the fingerprint must be an OpenSSH SHA256 fingerprint".to_owned(),
            });
        }
        self.port
            .confirm_fingerprint(
                endpoint_id,
                fingerprint,
                fleet_core::SystemClock::now_unix_millis(),
            )
            .await
            .map_err(|failure| map_port("confirm_fingerprint", failure))?;
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: Permission::MachineUpdate.id().to_owned(),
                resource: Some(endpoint_id.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata: {
                    let mut metadata = crate::audit::AuditMetadata::default();
                    metadata
                        .insert("event", "host_key_confirmed")
                        .map_err(|error| MachineUseCaseError::Backend {
                            context: "audit",
                            detail: error.to_string(),
                        })?;
                    metadata
                },
            })
            .await
            .map_err(|detail| MachineUseCaseError::Backend {
                context: "audit",
                detail,
            })?;
        Ok(())
    }

    /// The fingerprint previously confirmed for an endpoint.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn verified_host_key(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        endpoint_id: &str,
    ) -> Result<Option<String>, MachineUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineRead,
                resource: Some(endpoint_id),
            },
        )
        .map_err(MachineUseCaseError::Denied)?;
        self.port
            .verified_fingerprint(endpoint_id)
            .await
            .map_err(|failure| map_port("verified_fingerprint", failure))
    }

    /// Removes a machine and all its facts.
    ///
    /// # Errors
    ///
    /// Fails on denial or an unknown machine.
    pub async fn delete(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<(), MachineUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineDelete,
                resource: Some(id),
            },
        )
        .map_err(MachineUseCaseError::Denied)?;
        self.port
            .delete(id)
            .await
            .map_err(|failure| map_port("delete", failure))?;
        self.audit_machine(principal, Permission::MachineDelete, id, None)
            .await?;
        Ok(())
    }

    #[allow(clippy::unused_self)]
    fn authorized_tag_group_change(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        kind: &str,
        name: &str,
    ) -> Result<(), MachineUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineUpdate,
                resource: Some(id),
            },
        )
        .map_err(MachineUseCaseError::Denied)?;
        if name.is_empty() || name.len() > 64 {
            return Err(MachineUseCaseError::Invalid {
                detail: format!("{kind} names must be 1..=64 characters"),
            });
        }
        Ok(())
    }

    async fn audit_machine(
        &self,
        principal: &ActingPrincipal,
        action: Permission,
        machine_id: &str,
        note: Option<String>,
    ) -> Result<(), MachineUseCaseError> {
        let mut metadata = crate::audit::AuditMetadata::default();
        if let Some(note) = note {
            metadata
                .insert("note", &note)
                .map_err(|error| MachineUseCaseError::Backend {
                    context: "audit",
                    detail: error.to_string(),
                })?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: action.id().to_owned(),
                resource: Some(machine_id.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| MachineUseCaseError::Backend {
                context: "audit",
                detail,
            })
    }
}

fn map_port(context: &'static str, failure: PortFailure) -> MachineUseCaseError {
    match failure {
        PortFailure::NotFound { what } => MachineUseCaseError::NotFound { what },
        PortFailure::Backend { detail } => MachineUseCaseError::Backend { context, detail },
    }
}

fn validate_registration(registration: &RegisterMachine) -> Result<(), MachineUseCaseError> {
    validate_name(&registration.name).map_err(|detail| MachineUseCaseError::Invalid { detail })?;
    validate_endpoints(&registration.endpoints)?;
    for tag in &registration.tags {
        if tag.is_empty() || tag.len() > 64 {
            return Err(MachineUseCaseError::Invalid {
                detail: "tag names must be 1..=64 characters".to_owned(),
            });
        }
    }
    for group in &registration.groups {
        if group.is_empty() || group.len() > 64 {
            return Err(MachineUseCaseError::Invalid {
                detail: "group names must be 1..=64 characters".to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err("machine names must be 1..=64 characters".to_owned());
    }
    Ok(())
}

fn validate_endpoints(endpoints: &[NewEndpoint]) -> Result<(), MachineUseCaseError> {
    if endpoints.is_empty() {
        return Err(MachineUseCaseError::Invalid {
            detail: "a machine needs at least one endpoint".to_owned(),
        });
    }
    for endpoint in endpoints {
        if endpoint.reference.is_empty() || endpoint.reference.len() > 255 {
            return Err(MachineUseCaseError::Invalid {
                detail: "endpoint references must be 1..=255 characters".to_owned(),
            });
        }
    }
    Ok(())
}

impl Machine {
    fn correlation_note(&self) -> String {
        format!("{} endpoint(s)", self.endpoints.len())
    }
}
