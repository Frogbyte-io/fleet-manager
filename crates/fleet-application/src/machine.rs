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

use crate::audit::AuditOutcome;
use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::operation::PortFailure;
use fleet_core::{CapabilityFact, EndpointKind};

/// One registered machine, as read back by queries.
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

    /// Reads one machine.
    ///
    /// # Errors
    ///
    /// Fails on denial or an unknown machine.
    pub async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<Machine, MachineUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineRead,
                resource: Some(id),
            },
        )
        .map_err(MachineUseCaseError::Denied)?;
        self.port
            .get(id)
            .await
            .map_err(|failure| map_port("get", failure))
    }

    /// Lists machines, newest first.
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
    ) -> Result<Vec<Machine>, MachineUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::MachineRead,
                resource: None,
            },
        )
        .map_err(MachineUseCaseError::Denied)?;
        self.port
            .list(filter, limit)
            .await
            .map_err(|failure| map_port("list", failure))
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

/// The outcome of a machine mutation for the audit ledger; mutations of
/// machines succeed or fail as a whole, so outcomes are recorded directly.
impl Machines {
    /// Records the terminal outcome for a machine mutation whose intent was
    /// already appended. Machinery for FM-209's API surface; unused until
    /// then.
    #[allow(dead_code)]
    async fn audit_outcome(&self, machine_id: &str, outcome: AuditOutcome) -> Result<(), String> {
        self.audit.record_outcome(machine_id, outcome).await
    }
}
