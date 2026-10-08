//! The Lab use cases (FM-710): versioned templates and the provisioning
//! saga's first half — template management, provisioning, and readiness.
//!
//! A template pins a **promoted** image version: the pin is validated
//! against the image use cases at creation/publish time, so a template
//! cannot pin an unpromoted or nonexistent version. Guest states are
//! explicit — `provisioned` (cloned + booted) is distinct from `ready`
//! (the probe passed), and `never_ready` is the recorded failure when the
//! readiness deadline expires. TTL begins only at ready.
//!
//! The saga records external IDs before continuing: the provisioned
//! guest's VMID/node live in the provisioning record, so a re-run
//! discovers existing state and resumes instead of creating a second VM.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::operation::{AuditPort, PortFailure};
use crate::project::ProjectPort;
pub use fleet_core::{
    CleanupStrategy, GuestState, LabTemplateContent, ReadinessProbe, RecipeVersion,
};
pub use fleet_core::{Lease, LeaseState};

/// A stored template draft.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabTemplate {
    /// The draft's identity.
    pub id: String,
    /// The template content.
    pub content: LabTemplateContent,
    /// The published version this draft descends from, when any.
    pub published_from: Option<String>,
    /// When the draft was created (epoch millis).
    pub created_at: i64,
    /// When the draft was last edited (epoch millis).
    pub updated_at: i64,
}

/// A published template version: immutable, with provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabTemplateVersion {
    /// The version's identity.
    pub id: String,
    /// The template the version came from.
    pub template_id: String,
    /// The template name at publication time.
    pub name: String,
    /// The frozen content.
    pub content: LabTemplateContent,
    /// The pinned image version's digest at publication time: the
    /// provenance that makes an active lease reproducible.
    pub image_digest: String,
    /// Who published the version.
    pub published_by: String,
    /// When the version was published (epoch millis).
    pub published_at: i64,
}

/// A creation or edit request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewLabTemplate {
    /// The template content.
    pub content: LabTemplateContent,
}

/// The image-version pin validator: the application boundary where the
/// image use cases live. The lab use cases call it before accepting a
/// pin; a template cannot reference an unpromoted or nonexistent version.
#[async_trait]
pub trait ImagePinValidator: fmt::Debug + Send + Sync {
    /// The pinned version, when it exists **and is promoted**.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read.
    async fn promoted_version(&self, version_id: &str) -> Result<Option<RecipeVersion>, String>;
}

/// The template storage port.
#[async_trait]
pub trait LabTemplatePort: fmt::Debug + Send + Sync {
    /// Creates a draft, minting its identity.
    ///
    /// # Errors
    ///
    /// Fails when the name is taken or the backend errors.
    async fn create(&self, template: &NewLabTemplate, now: i64) -> Result<LabTemplate, String>;
    /// Reads one draft.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn get(&self, id: &str) -> Result<LabTemplate, String>;
    /// Lists drafts, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list(&self) -> Result<Vec<LabTemplate>, String>;
    /// Replaces a draft's content.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn update(
        &self,
        id: &str,
        content: &LabTemplateContent,
        now: i64,
    ) -> Result<LabTemplate, String>;
    /// Removes a draft. Published versions stay.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn delete(&self, id: &str) -> Result<(), String>;
    /// Publishes a draft: freezes an immutable version with provenance.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn publish(
        &self,
        template_id: &str,
        version: &LabTemplateVersion,
    ) -> Result<LabTemplateVersion, String>;
    /// Reads one published version.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn get_version(&self, id: &str) -> Result<LabTemplateVersion, String>;
}

/// A provisioning record: the saga's durable state for one provisioned
/// guest, carrying the external IDs each step recorded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionRecord {
    /// The record's identity.
    pub id: String,
    /// The template version the guest was provisioned from.
    pub template_version_id: String,
    /// The lease this saga provisions, when started from a lease.
    pub lease_id: Option<String>,
    /// The guest's current state.
    pub state: GuestState,
    /// The PVE node the guest landed on, once cloned.
    pub node: Option<String>,
    /// The guest's VMID, once cloned.
    pub vmid: Option<u32>,
    /// The clone task's UPID, while running.
    pub clone_upid: Option<String>,
    /// The guest's IPv4 address, once the agent reported one.
    pub guest_ipv4: Option<String>,
    /// The temporary Fleet machine, retained for cleanup.
    pub machine_id: Option<String>,
    /// The SSH endpoint belonging to that machine.
    pub endpoint_id: Option<String>,
    /// The durable M3 child operation, recorded before execution.
    pub ready_project_operation_id: Option<String>,
    /// Absolute readiness deadline, unchanged by a resumed execution.
    pub readiness_deadline_at: Option<i64>,
    /// The named saga step that failed, without provider output or secrets.
    pub failed_step: Option<String>,
    /// The Proxmox account the guest was cloned through, recorded before
    /// the clone so cleanup destroys it through the same account.
    pub account_id: Option<String>,
    /// The caller-scoped idempotency key, when one was supplied.
    pub idempotency_key: Option<String>,
    /// When the guest reached ready (epoch millis), when it did — the TTL
    /// clock's start.
    pub ready_at: Option<i64>,
    /// When the record was created (epoch millis).
    pub created_at: i64,
    /// When the record was last updated (epoch millis).
    pub updated_at: i64,
}

/// A new provisioning record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewProvision {
    /// The template version being provisioned.
    pub template_version_id: String,
    /// The lease this saga provisions, when linked.
    pub lease_id: Option<String>,
    /// The caller-scoped idempotency key, when one was supplied.
    pub idempotency_key: Option<String>,
}

/// The provisioning storage port.
#[async_trait]
pub trait ProvisionPort: fmt::Debug + Send + Sync {
    /// Creates a record, minting its identity.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn create(&self, new: &NewProvision, now: i64) -> Result<ProvisionRecord, String>;
    /// The record carrying this caller-scoped idempotency key, when any.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn find_by_idempotency_key(&self, key: &str) -> Result<Option<ProvisionRecord>, String>;
    /// Reads one record.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn get(&self, id: &str) -> Result<ProvisionRecord, String>;
    /// Updates the record's saga state (external IDs, guest state).
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn update(&self, record: &ProvisionRecord) -> Result<(), String>;
    /// Atomically records provision readiness and, when linked, the lease's
    /// ready state and expiry. This prevents either row from becoming the
    /// sole source of truth after a partial write.
    ///
    /// # Errors
    ///
    /// Fails when the record/lease link changed or the backend errors.
    async fn complete_ready(
        &self,
        record: &ProvisionRecord,
        lease_expires_at: Option<i64>,
    ) -> Result<(), String>;
    /// Registers and associates one Lab-owned machine atomically, or returns
    /// the existing association. The application authorizes and audits intent
    /// before invoking this mutation.
    async fn ensure_guest_machine(
        &self,
        _record_id: &str,
        _reference: &str,
    ) -> Result<ProvisionRecord, String> {
        Err("Lab machine registration is unavailable".to_owned())
    }

    /// Reads the unique durable Lab association for a machine, including
    /// terminal records whose queued children still need cancellation checks.
    async fn find_by_machine_id(
        &self,
        machine_id: &str,
    ) -> Result<Option<ProvisionRecord>, String> {
        Ok(self
            .list()
            .await?
            .into_iter()
            .find(|record| record.machine_id.as_deref() == Some(machine_id)))
    }

    /// Lists records, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list(&self) -> Result<Vec<ProvisionRecord>, String>;
    /// Reserves the clone target (node and VMID) on a `provisioning` record
    /// that has not started its clone yet, in one transaction, before the
    /// clone is requested (the saga rule, issue #220). The reservation is
    /// refused when another `provisioning` record already holds the VMID.
    /// A record that already holds a reservation keeps it: the returned
    /// record carries whatever target is stored.
    ///
    /// # Errors
    ///
    /// Fails when the record is unknown, is not `provisioning`, already
    /// started its clone, or the backend errors.
    async fn reserve_clone_target(
        &self,
        record_id: &str,
        node: &str,
        vmid: u32,
    ) -> Result<CloneTargetReservation, String>;
}

/// Adapter contract for the existing SSH trust/exec and M3 operation paths.
/// `false` means retryable unavailability; an error is terminal. Provider
/// output must not be returned as an error because it may contain secrets.
#[async_trait]
pub trait LabReadinessPort: fmt::Debug + Send + Sync {
    /// Observes and pins/compares the host key through FM-201.
    async fn trust(
        &self,
        record: &ProvisionRecord,
        content: &LabTemplateContent,
        remaining: std::time::Duration,
    ) -> Result<bool, String>;
    /// Runs the template command through FM-202, succeeding only on exit 0.
    async fn ssh_probe(
        &self,
        operations: &crate::operation::Operations,
        _parent_id: &str,
        record: &ProvisionRecord,
        command: &str,
        remaining: std::time::Duration,
    ) -> Result<bool, String>;
    /// Creates or re-finds a durable M3 child with a provision-scoped key.
    async fn create_project(
        &self,
        operations: &crate::operation::Operations,
        _parent_id: &str,
        record: &ProvisionRecord,
        project_id: &str,
        remaining: std::time::Duration,
    ) -> Result<String, String>;
    /// Executes/polls that child and accepts only a successful verify step.
    async fn project_verified(
        &self,
        operations: &crate::operation::Operations,
        child_id: &str,
        remaining: std::time::Duration,
    ) -> Result<bool, String>;
}

/// A safe named readiness failure. External output is excluded.
#[derive(Debug)]
pub struct LabReadinessFailure {
    /// The saga step that did not complete.
    pub step: &'static str,
}

/// Executes Lab readiness policy using the existing adapter contracts.
/// The absolute deadline and child identity are durable before remote work.
pub struct LabBootstrap<'a> {
    /// Provision persistence.
    pub provisions: &'a dyn ProvisionPort,
    /// SSH and ready-project adapters.
    pub readiness: &'a dyn LabReadinessPort,
    /// Mutation audit sink.
    pub audit: &'a dyn AuditPort,
    /// Active centralized authorization policy.
    pub authorizer: &'a dyn Authorizer,
    /// The controller's acting identity.
    pub principal: &'a ActingPrincipal,
}

impl LabBootstrap<'_> {
    /// Associates the guest, trusts SSH, runs the configured probe and applies
    /// the bootstrap project. Returns the latest record; the caller commits
    /// readiness and its TTL atomically only after this succeeds.
    ///
    /// # Errors
    /// Returns the safe named step on denial, deadline, cancellation or failure.
    pub async fn run(
        &self,
        operations: &crate::operation::Operations,
        operation_id: &str,
        record: ProvisionRecord,
        content: &LabTemplateContent,
    ) -> Result<ProvisionRecord, LabReadinessFailure> {
        let record_id = record.id.clone();
        let outcome = self
            .run_inner(operations, operation_id, record, content)
            .await;
        if outcome.is_err()
            && let Ok(record) = self.provisions.get(&record_id).await
            && let Some(child) = record.ready_project_operation_id.as_deref()
        {
            let _ = operations
                .cancel(self.authorizer, &self.principal.id, child)
                .await;
        }
        outcome
    }

    // Keep the ordered saga transitions together for review.
    #[allow(clippy::too_many_lines)]
    async fn run_inner(
        &self,
        operations: &crate::operation::Operations,
        operation_id: &str,
        mut record: ProvisionRecord,
        content: &LabTemplateContent,
    ) -> Result<ProvisionRecord, LabReadinessFailure> {
        let failure = |step| LabReadinessFailure { step };
        self.remaining(operations, operation_id, &record, "machine_registration")
            .await?;
        content
            .validate_ssh()
            .map_err(|_| failure("ssh_configuration"))?;
        let host = record
            .guest_ipv4
            .as_deref()
            .ok_or_else(|| failure("guest_ip"))?;
        host.parse::<std::net::Ipv4Addr>()
            .map_err(|_| failure("guest_ip"))?;
        for action in [Permission::LabProvision, Permission::MachineCreate] {
            authorize(
                self.authorizer,
                AccessRequest {
                    principal_id: &self.principal.id,
                    action,
                    resource: if action == Permission::LabProvision {
                        Some(record.lease_id.as_deref().unwrap_or(&record.id))
                    } else {
                        None
                    },
                },
            )
            .map_err(|_| failure("machine_registration"))?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: self.principal.id.clone(),
                action: Permission::MachineCreate.id().to_owned(),
                resource: Some(record.id.clone()),
                decision: Decision::allow(),
                correlation_id: Some(operation_id.to_owned()),
                operation_id: Some(operation_id.to_owned()),
                metadata: crate::audit::AuditMetadata::default(),
            })
            .await
            .map_err(|_| failure("machine_registration"))?;
        let reference = format!("{}@{host}:{}", content.ssh_user, content.ssh_port);
        record = self
            .provisions
            .ensure_guest_machine(&record.id, &reference)
            .await
            .map_err(|_| failure("machine_registration"))?;
        record.state = GuestState::Bootstrapping;
        self.provisions
            .update(&record)
            .await
            .map_err(|_| failure("bootstrapping"))?;
        self.poll(
            operations,
            operation_id,
            &record,
            "ssh_trust",
            |remaining| self.readiness.trust(&record, content, remaining),
        )
        .await?;
        if content.readiness_probe == ReadinessProbe::SshExec {
            let command = content
                .readiness_command
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| failure("ssh_exec"))?;
            self.poll(operations, operation_id, &record, "ssh_exec", |remaining| {
                self.readiness
                    .ssh_probe(operations, operation_id, &record, command, remaining)
            })
            .await?;
        }
        if content.readiness_probe == ReadinessProbe::ProjectReady
            && content.bootstrap_project_id.is_none()
        {
            return Err(failure("project_ready"));
        }
        if let Some(project_id) = content.bootstrap_project_id.as_deref() {
            if record.ready_project_operation_id.is_none() {
                let remaining = self
                    .remaining(operations, operation_id, &record, "project_setup")
                    .await?;
                let child = tokio::time::timeout(
                    remaining,
                    self.readiness.create_project(
                        operations,
                        operation_id,
                        &record,
                        project_id,
                        remaining,
                    ),
                )
                .await
                .map_err(|_| failure("project_setup"))?
                .map_err(|_| failure("project_setup"))?;
                record.ready_project_operation_id = Some(child.clone());
                if self.provisions.update(&record).await.is_err() {
                    // Cancellation must not depend on the association write
                    // having succeeded: this child is already durable.
                    let _ = operations
                        .cancel(self.authorizer, &self.principal.id, &child)
                        .await;
                    return Err(failure("project_setup"));
                }
            }
            let child = record
                .ready_project_operation_id
                .as_deref()
                .expect("recorded above");
            self.poll(
                operations,
                operation_id,
                &record,
                "project_ready",
                |remaining| {
                    self.readiness
                        .project_verified(operations, child, remaining)
                },
            )
            .await?;
        }
        self.remaining(operations, operation_id, &record, "ready")
            .await?;
        Ok(record)
    }

    async fn poll<F, Fut>(
        &self,
        operations: &crate::operation::Operations,
        operation_id: &str,
        record: &ProvisionRecord,
        step: &'static str,
        mut attempt: F,
    ) -> Result<(), LabReadinessFailure>
    where
        F: FnMut(std::time::Duration) -> Fut,
        Fut: std::future::Future<Output = Result<bool, String>>,
    {
        loop {
            let remaining = self
                .remaining(operations, operation_id, record, step)
                .await?;
            match tokio::time::timeout(remaining, attempt(remaining)).await {
                Ok(Ok(true)) => return Ok(()),
                Ok(Ok(false)) => {
                    tokio::time::sleep(remaining.min(std::time::Duration::from_secs(2))).await;
                }
                _ => return Err(LabReadinessFailure { step }),
            }
        }
    }

    async fn remaining(
        &self,
        operations: &crate::operation::Operations,
        operation_id: &str,
        record: &ProvisionRecord,
        step: &'static str,
    ) -> Result<std::time::Duration, LabReadinessFailure> {
        if operations
            .cancel_requested(operation_id)
            .await
            .map_err(|_| LabReadinessFailure { step })?
        {
            return Err(LabReadinessFailure { step: "cancelled" });
        }
        let millis = record
            .readiness_deadline_at
            .unwrap_or(0)
            .saturating_sub(fleet_core::SystemClock::now_unix_millis());
        if millis <= 0 {
            return Err(LabReadinessFailure { step });
        }
        Ok(std::time::Duration::from_millis(
            u64::try_from(millis).unwrap_or(0),
        ))
    }
}

/// The outcome of [`ProvisionPort::reserve_clone_target`].
#[derive(Clone, Debug, Eq, PartialEq)]
// Retain the existing port contract as the readiness record gains durable IDs.
#[allow(clippy::large_enum_variant)]
pub enum CloneTargetReservation {
    /// The record holds a reservation; it carries the stored node and VMID.
    Reserved(ProvisionRecord),
    /// Another in-flight record already holds the VMID.
    HeldBy {
        /// The record that holds the VMID.
        record_id: String,
    },
}

/// The recorded image build artifacts: the Proxmox template VMIDs that
/// `image.build` operations produced. The executor clones from these and
/// the cleanup guard refuses to destroy the promoted ones.
///
/// A build is not tied to a Fleet Proxmox account (Packer uses its own
/// credentials), so artifacts are keyed by image version only. The
/// executor therefore requires the artifact VMID to be a live template in
/// the cluster it clones in.
#[async_trait]
pub trait ImageArtifactPort: fmt::Debug + Send + Sync {
    /// The template VMID of the build the image version's promotion pinned
    /// (issue #281): a later rebuild never moves it. A version without a
    /// pin (promoted before pins were recorded) falls back to its latest
    /// successful build. `None` when there is no such build, or when that
    /// latest build recorded no artifact: an older build is never a
    /// fallback.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read or the recorded artifact is not
    /// a VMID.
    async fn template_vmid(&self, image_version_id: &str) -> Result<Option<u32>, String>;
    /// The template VMIDs recorded by the successful builds of every
    /// currently promoted image version, plus every build a promotion
    /// pinned, including a demoted version's (the pin outlives demotion).
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read.
    async fn promoted_template_vmids(&self) -> Result<Vec<u32>, String>;
}

/// The Lab cleanup guard (issue #220): a VMID that is a template, or that
/// matches a protected image build artifact, is never destroyed by Lab
/// cleanup, whatever a provision record claims. The protected artifacts are
/// [`ImageArtifactPort::promoted_template_vmids`]: every successful build of
/// a promoted image version, plus every build a promotion pinned, including
/// a demoted version's (issue #281). Fleet has
/// no Lab destroy path yet; the cleanup that FM-711 adds must call this
/// with the cluster's live truth before it deletes anything. The
/// provision executor already applies it before it resumes a record.
///
/// # Errors
///
/// Returns the refusal reason.
pub fn guard_destroy_target(
    vmid: u32,
    is_template: bool,
    promoted_template_vmids: &[u32],
) -> Result<(), String> {
    if is_template {
        return Err(format!(
            "VMID {vmid} is a template; Lab cleanup never destroys a template"
        ));
    }
    if promoted_template_vmids.contains(&vmid) {
        return Err(format!(
            "VMID {vmid} is a protected image build artifact (a promoted version's build or a promotion's pinned build); Lab cleanup never destroys an image template"
        ));
    }
    Ok(())
}

/// A lease creation request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewLease {
    /// The template version to lease from.
    pub template_version_id: String,
    /// The purpose the lease records.
    pub purpose: String,
    /// The project the lease is scoped to, when any.
    pub project_id: Option<String>,
    /// The cleanup strategy inherited from the template.
    pub cleanup: CleanupStrategy,
    /// The TTL seconds inherited from the template.
    pub ttl_seconds: u32,
}

/// The lease storage port.
#[async_trait]
pub trait LeasePort: fmt::Debug + Send + Sync {
    /// Creates a lease, minting its identity.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn create(&self, lease: &NewLease, owner: &str, now: i64) -> Result<Lease, String>;
    /// Reads one lease.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn get(&self, id: &str) -> Result<Lease, String>;
    /// Updates the lease's mutable state.
    ///
    /// # Errors
    ///
    /// Fails when unknown or the backend errors.
    async fn update(&self, lease: &Lease) -> Result<(), String>;
    /// Lists leases, newest first, narrowed by the project when given.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list(&self, project_id: Option<&str>) -> Result<Vec<Lease>, String>;
    /// Lists the leases whose TTL has expired at `now`.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn expired(&self, now: i64) -> Result<Vec<Lease>, String>;
    /// Extends a ready lease's expiry if the observed deadline is still
    /// current and unexpired. Returns false when the sweeper or another
    /// extension changed the lease first.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn extend_ready(
        &self,
        id: &str,
        observed_expires_at: i64,
        now: i64,
        new_expires_at: i64,
    ) -> Result<bool, String>;
    /// Attaches a provision record to a requested lease, moving it into
    /// provisioning. Returns whether this call made the transition, accepts
    /// an already attached matching link, or rejects a conflict.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn attach_provision(
        &self,
        id: &str,
        provision_id: &str,
    ) -> Result<AttachProvisionOutcome, String>;
    /// Claims one lease for release, conditional on its observed state:
    /// the compare-and-set that keeps concurrent sweeps from
    /// double-claiming or winning over an extension after an expiry scan.
    /// Returns whether this caller won the claim.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn claim_for_release(
        &self,
        id: &str,
        observed: LeaseState,
        observed_expires_at: i64,
        now: i64,
    ) -> Result<bool, String>;
    /// Moves a lease to `to` only while it is still in `observed` with the
    /// same provision link: the compare-and-set that keeps the sweeper's
    /// compensation from overwriting a concurrent `complete_ready`, release,
    /// or executor compensation. Returns whether this caller made the
    /// transition.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn transition(
        &self,
        id: &str,
        observed: LeaseState,
        provision_id: Option<&str>,
        to: LeaseState,
    ) -> Result<bool, String>;
    /// Re-arms the cleanup of a `cleanup_failed` lease: moves it back to
    /// `releasing` with `attempts` recorded and nothing scheduled,
    /// conditional on the lease still being `cleanup_failed` with
    /// `observed_attempts`, so two concurrent re-arms (or a re-arm racing
    /// the attempt it queued) cannot overwrite each other. Returns whether
    /// this caller made the transition.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn rearm_cleanup(
        &self,
        id: &str,
        observed_attempts: u32,
        attempts: u32,
    ) -> Result<bool, String>;
}

/// Result of linking a provision record to a lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachProvisionOutcome {
    /// The lease transitioned from requested to provisioning.
    Attached,
    /// The same provision was already attached.
    AlreadyAttached,
    /// The lease changed to an incompatible state or link.
    Conflict,
}

/// A use-case rejection, mapped onto public API errors by the adapter.
#[derive(Debug)]
pub enum LabUseCaseError {
    /// The caller may not perform the action.
    Denied(Decision),
    /// The request is malformed.
    Invalid {
        /// What is wrong.
        detail: String,
    },
    /// The addressed template, version, or record does not exist.
    NotFound {
        /// What was not found.
        what: String,
    },
    /// The template name is taken.
    Conflict {
        /// The conflict detail.
        detail: String,
    },
    /// The image pin was refused: the version is unknown or unpromoted.
    PinRefused {
        /// The refusal detail.
        detail: String,
    },
    /// A port failed.
    Backend {
        /// Where.
        context: &'static str,
        /// The failure detail.
        detail: String,
    },
}

impl fmt::Display for LabUseCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::Invalid { detail } => write!(f, "invalid request: {detail}"),
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::Conflict { detail } => write!(f, "conflict: {detail}"),
            Self::PinRefused { detail } => write!(f, "the image pin was refused: {detail}"),
            Self::Backend { context, detail } => write!(f, "lab {context} failed: {detail}"),
        }
    }
}

impl std::error::Error for LabUseCaseError {}

/// The Lab use cases.
#[derive(Debug)]
pub struct Lab {
    templates: Arc<dyn LabTemplatePort>,
    provisions: Arc<dyn ProvisionPort>,
    leases: Arc<dyn LeasePort>,
    image_pins: Arc<dyn ImagePinValidator>,
    projects: Arc<dyn ProjectPort>,
    audit: Arc<dyn AuditPort>,
    artifacts: Option<Arc<crate::lab_artifacts::LabArtifacts>>,
    pools: Option<Arc<crate::lab_pool::LabPools>>,
}

impl Lab {
    /// Composes the service from its ports.
    #[must_use]
    pub fn new(
        templates: Arc<dyn LabTemplatePort>,
        provisions: Arc<dyn ProvisionPort>,
        leases: Arc<dyn LeasePort>,
        image_pins: Arc<dyn ImagePinValidator>,
        projects: Arc<dyn ProjectPort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            templates,
            provisions,
            leases,
            image_pins,
            projects,
            audit,
            artifacts: None,
            pools: None,
        }
    }

    /// Serves the Lab pool use cases (FM-717) beside the Lab surface.
    #[must_use]
    pub fn with_pools(mut self, pools: Arc<crate::lab_pool::LabPools>) -> Self {
        self.pools = Some(pools);
        self
    }

    /// The Lab pool use cases, when the controller composed them.
    #[must_use]
    pub fn pools(&self) -> Option<&Arc<crate::lab_pool::LabPools>> {
        self.pools.as_ref()
    }

    /// Serves the Lab artifact use cases (FM-721) beside the Lab surface.
    #[must_use]
    pub fn with_artifacts(mut self, artifacts: Arc<crate::lab_artifacts::LabArtifacts>) -> Self {
        self.artifacts = Some(artifacts);
        self
    }

    /// The Lab artifact use cases, when the controller composed them.
    #[must_use]
    pub fn artifacts(&self) -> Option<&Arc<crate::lab_artifacts::LabArtifacts>> {
        self.artifacts.as_ref()
    }

    /// Creates a lease from a published template version: the lease
    /// inherits the template's cleanup strategy, TTL, and bootstrap
    /// project, starts in `requested`, and is audited. An explicit project
    /// id that names an existing project overrides the inheritance; an
    /// inherited bootstrap project that no longer exists fails the
    /// creation so the caller can supply a replacement. The provisioning
    /// saga is started by the caller (the executor composes them).
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown version/project/lease, a stale template
    /// bootstrap project, a lifecycle conflict, or a backend failure.
    pub async fn create_lease(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        new: NewLease,
        now: i64,
    ) -> Result<Lease, LabUseCaseError> {
        // The authorization precedes the read: a denied caller cannot
        // probe lease existence through NotFound versus Denied.
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabLease,
                resource: Some(&new.template_version_id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let version = self
            .templates
            .get_version(&new.template_version_id)
            .await
            .map_err(|detail| {
                if detail.contains("not found") {
                    LabUseCaseError::NotFound {
                        what: format!("version {}", new.template_version_id),
                    }
                } else {
                    LabUseCaseError::Backend {
                        context: "versions",
                        detail,
                    }
                }
            })?;
        if new.purpose.is_empty() || new.purpose.chars().count() > 512 {
            return Err(LabUseCaseError::Invalid {
                detail: "the purpose must be 1..=512 characters".to_owned(),
            });
        }
        // An explicit project must exist. Without one, the lease inherits
        // the template version's bootstrap project — which must also still
        // exist: deleting a project leaves the frozen template versions
        // pointing at it, and the lease's FK would otherwise reject the
        // inherited id as an opaque backend failure.
        let inherited = {
            let project_id = self
                .resolve_lease_project(
                    new.project_id.as_deref(),
                    version.content.bootstrap_project_id.as_deref(),
                )
                .await?;
            NewLease {
                project_id,
                cleanup: version.content.cleanup,
                ttl_seconds: version.content.ttl_seconds,
                ..new
            }
        };
        let audit_fact = inherited.project_id.as_deref().map(|id| ("projectId", id));
        self.audit_event(
            principal,
            Permission::LabLease,
            Some(&version.id),
            "lab_lease_creating",
            audit_fact,
        )
        .await?;
        self.leases
            .create(&inherited, &principal.id, now)
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "leases",
                detail,
            })
    }

    /// Resolves the lease's project linkage: an explicit id must exist,
    /// and with none given the template version's bootstrap project must
    /// also still exist — deleting a project leaves the frozen template
    /// versions pointing at it, and the lease's FK would otherwise reject
    /// the inherited id as an opaque backend failure.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` when a referenced project is missing so the API
    /// maps it to a 400, and `Backend` on a port failure.
    async fn resolve_lease_project(
        &self,
        explicit: Option<&str>,
        bootstrap: Option<&str>,
    ) -> Result<Option<String>, LabUseCaseError> {
        let (id, what) = match (explicit, bootstrap) {
            (Some(id), _) => (id, format!("project {id} does not exist")),
            (None, Some(id)) => (
                id,
                format!(
                    "the template version's bootstrap project {id} no longer \
                     exists; supply an explicit project id for the lease"
                ),
            ),
            (None, None) => return Ok(None),
        };
        match self.projects.get(id).await {
            Ok(_) => Ok(Some(id.to_owned())),
            Err(PortFailure::NotFound { .. }) => Err(LabUseCaseError::Invalid { detail: what }),
            Err(failure) => Err(LabUseCaseError::Backend {
                context: "projects",
                detail: failure.to_string(),
            }),
        }
    }

    /// Lists the leases, narrowed by the project when given.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list_leases(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        project_id: Option<&str>,
    ) -> Result<Vec<Lease>, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabRead,
                resource: None,
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        self.leases
            .list(project_id)
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "leases",
                detail,
            })
    }

    /// Reads one lease.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown lease, or a backend failure.
    pub async fn get_lease(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<Lease, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabRead,
                resource: Some(id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        self.leases.get(id).await.map_err(|detail| {
            if detail.contains("not found") {
                LabUseCaseError::NotFound {
                    what: format!("lease {id}"),
                }
            } else {
                LabUseCaseError::Backend {
                    context: "leases",
                    detail,
                }
            }
        })
    }

    /// Validates a command for a ready lease's guest and answers the
    /// `lab.exec` operation to queue (FM-720). The lease must be `ready`
    /// and unexpired, and its guest must be a registered Lab machine. The
    /// command itself is never audited: it may carry secrets.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown lease, a lease that is not ready or has
    /// expired, a guest without a Lab machine, or an invalid command.
    #[allow(clippy::too_many_arguments)]
    pub async fn exec_lease(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        script: &str,
        timeout_seconds: u64,
        idempotency_key: Option<&str>,
        now: i64,
    ) -> Result<crate::operation::NewOperation, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabExec,
                resource: Some(id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        if script.trim().is_empty() || script.len() > MAX_LAB_EXEC_SCRIPT_BYTES {
            return Err(LabUseCaseError::Invalid {
                detail: format!(
                    "the command must be non-empty and at most {MAX_LAB_EXEC_SCRIPT_BYTES} bytes"
                ),
            });
        }
        if timeout_seconds == 0 || timeout_seconds > MAX_LAB_EXEC_TIMEOUT_SECONDS {
            return Err(LabUseCaseError::Invalid {
                detail: format!("timeoutSeconds must be 1..={MAX_LAB_EXEC_TIMEOUT_SECONDS}"),
            });
        }
        let lease = self.leases.get(id).await.map_err(|detail| {
            if detail.contains("not found") {
                LabUseCaseError::NotFound {
                    what: format!("lease {id}"),
                }
            } else {
                LabUseCaseError::Backend {
                    context: "leases",
                    detail,
                }
            }
        })?;
        lease_exec_ready(&lease, now).map_err(|detail| LabUseCaseError::Invalid { detail })?;
        let record = match &lease.provision_id {
            Some(provision) => Some(self.provisions.get(provision).await.map_err(|detail| {
                LabUseCaseError::Backend {
                    context: "provisions",
                    detail,
                }
            })?),
            None => None,
        };
        if record
            .as_ref()
            .is_none_or(|record| record.machine_id.is_none() || record.endpoint_id.is_none())
        {
            return Err(LabUseCaseError::Invalid {
                detail: "the lease's guest has no registered Lab machine to run on".to_owned(),
            });
        }
        self.audit_event(
            principal,
            Permission::LabExec,
            Some(id),
            "lab_exec_requested",
            None,
        )
        .await?;
        Ok(crate::operation::NewOperation {
            kind: "lab.exec".to_owned(),
            idempotency_key: idempotency_key
                .map(|key| format!("{}:lab-exec:{id}:{key}", principal.id)),
            deadline_at: None,
            correlation_id: None,
            payload_json: Some(
                serde_json::json!({
                    "leaseId": id,
                    "script": script,
                    "timeoutSeconds": timeout_seconds,
                })
                .to_string(),
            ),
            review_token: None,
        })
    }

    /// Releases a lease: transitions it into `releasing` and records the
    /// intent. The executor performs the cleanup (destroy/revert through
    /// the destructive gate) and completes the release. A `keep` request
    /// requires the elevated `lab.keep` permission and transfers the VM
    /// out of automatic cleanup instead.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown lease, or a backend failure.
    pub async fn release_lease(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        keep: bool,
        _now: i64,
    ) -> Result<Lease, LabUseCaseError> {
        // `keep` is the elevated path: a different catalog entry governs
        // it, so a caller allowed to lease is not automatically allowed
        // to keep. The authorization precedes the read.
        let action = if keep {
            Permission::LabKeep
        } else {
            Permission::LabLease
        };
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action,
                resource: Some(id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let lease = self.leases.get(id).await.map_err(|detail| {
            if detail.contains("not found") {
                LabUseCaseError::NotFound {
                    what: format!("lease {id}"),
                }
            } else {
                LabUseCaseError::Backend {
                    context: "leases",
                    detail,
                }
            }
        })?;
        if lease.state.is_terminal() {
            return Err(LabUseCaseError::Invalid {
                detail: format!("the lease {id} is already {}", lease.state.id()),
            });
        }
        self.audit_event(
            principal,
            action,
            Some(id),
            if keep {
                "lab_lease_keeping"
            } else {
                "lab_lease_releasing"
            },
            None,
        )
        .await?;
        let mut updated = lease.clone();
        updated.state = LeaseState::Releasing;
        if keep {
            // The keep decision is persisted: the cleanup executor sees
            // Keep and detaches the VM from automatic cleanup instead of
            // destroying it.
            updated.cleanup = CleanupStrategy::Keep;
        }
        self.leases
            .update(&updated)
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "leases",
                detail,
            })?;
        Ok(updated)
    }

    /// Re-arms the cleanup of a `cleanup_failed` lease once an operator has
    /// fixed the cause (#292): the lease goes back to `releasing` with a
    /// fresh round of [`MAX_CLEANUP_ATTEMPTS`] attempts and nothing
    /// scheduled, so its next `lab.cleanup` is due at once. The caller
    /// queues that operation. Re-arming needs `lab.lease`, the permission
    /// that already queues the same cleanup through a release: it resumes
    /// the release the lease recorded, with the same strategy and the same
    /// destroy guards, and grants nothing a release does not.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown lease, a lease that is not
    /// `cleanup_failed` (invalid), a concurrent re-arm (conflict), or a
    /// backend failure.
    pub async fn retry_cleanup(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<Lease, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabLease,
                resource: Some(id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let lease = self.leases.get(id).await.map_err(|detail| {
            if detail.contains("not found") {
                LabUseCaseError::NotFound {
                    what: format!("lease {id}"),
                }
            } else {
                LabUseCaseError::Backend {
                    context: "leases",
                    detail,
                }
            }
        })?;
        if lease.state != LeaseState::CleanupFailed {
            return Err(LabUseCaseError::Invalid {
                detail: format!(
                    "the lease {id} is {}; only a cleanup_failed lease can retry its cleanup",
                    lease.state.id()
                ),
            });
        }
        let mut rearmed = lease.clone();
        rearm_cleanup(&mut rearmed);
        let failed_attempts = lease.cleanup_attempts.to_string();
        // The intent precedes the mutation; the completion is recorded only
        // once this caller's compare-and-set won, so a concurrent loser
        // leaves a request, never a re-arm that did not happen.
        self.audit_event(
            principal,
            Permission::LabLease,
            Some(id),
            "lab_lease_cleanup_rearm_requested",
            Some(("failedAttempts", &failed_attempts)),
        )
        .await?;
        let won = self
            .leases
            .rearm_cleanup(id, lease.cleanup_attempts, rearmed.cleanup_attempts)
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "leases",
                detail,
            })?;
        if !won {
            return Err(LabUseCaseError::Conflict {
                detail: "the lease changed before its cleanup could be re-armed".to_owned(),
            });
        }
        // The required audit is the intent above, recorded before the
        // change. The completion record is best effort: the re-arm is
        // committed, and failing here would return before the caller
        // queues the cleanup the lease now owes.
        let _ = self
            .audit_event(
                principal,
                Permission::LabLease,
                Some(id),
                "lab_lease_cleanup_rearmed",
                Some(("failedAttempts", &failed_attempts)),
            )
            .await;
        Ok(rearmed)
    }

    /// Extends a ready lease by adding seconds to its existing expiry. The
    /// absolute maximum lifetime is measured from creation and cannot be
    /// extended.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown or non-ready lease, an expired lease, an
    /// extension beyond the absolute limit, or a concurrent state change.
    pub async fn extend_lease(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        by_seconds: u32,
        now: i64,
    ) -> Result<Lease, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabExtend,
                resource: Some(id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let lease = self.leases.get(id).await.map_err(|detail| {
            if detail.contains("not found") {
                LabUseCaseError::NotFound {
                    what: format!("lease {id}"),
                }
            } else {
                LabUseCaseError::Backend {
                    context: "leases",
                    detail,
                }
            }
        })?;
        let observed_expires_at = lease.expires_at.ok_or_else(|| LabUseCaseError::Invalid {
            detail: "only ready leases with a TTL deadline can be extended".to_owned(),
        })?;
        let new_expires_at = lease
            .extend_expiry(now, by_seconds)
            .map_err(|detail| LabUseCaseError::Invalid { detail })?;
        self.audit_event(
            principal,
            Permission::LabExtend,
            Some(id),
            "lab_lease_extension_requested",
            None,
        )
        .await?;
        let extended = self
            .leases
            .extend_ready(id, observed_expires_at, now, new_expires_at)
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "leases",
                detail,
            })?;
        if !extended {
            return Err(LabUseCaseError::Conflict {
                detail: "the lease changed state or expiry before it could be extended".to_owned(),
            });
        }
        let mut updated = lease;
        updated.expires_at = Some(new_expires_at);
        Ok(updated)
    }

    /// The expiry sweeper's transition: every lease whose TTL has expired
    /// at `now` moves into `releasing` with the release intent recorded.
    /// The sweeper survives restart because the deadlines live in the
    /// rows; the caller recomputes on startup.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn sweep_expired(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        now: i64,
    ) -> Result<Vec<Lease>, LabUseCaseError> {
        self.sweep_expired_with_progress(authorizer, principal, now, || {})
            .await
    }

    /// Sweeps expired leases and calls `on_claim` immediately after each
    /// durable transition. The callback lets adapters publish invalidations
    /// even if a later lease in the same sweep fails.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure; prior successful claims remain
    /// reported through `on_claim`.
    pub async fn sweep_expired_with_progress(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        now: i64,
        mut on_claim: impl FnMut(),
    ) -> Result<Vec<Lease>, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabLease,
                resource: None,
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let expired =
            self.leases
                .expired(now)
                .await
                .map_err(|detail| LabUseCaseError::Backend {
                    context: "leases",
                    detail,
                })?;
        let mut released = Vec::new();
        for lease in expired {
            let Some(observed_expires_at) = lease.expires_at else {
                continue;
            };
            self.audit_event(
                principal,
                Permission::LabLease,
                Some(&lease.id),
                "lab_lease_expiring",
                None,
            )
            .await?;
            // The claim is conditional on the observed ready state: a
            // concurrent sweep or cleanup completion cannot double-claim
            // or regress the state.
            let mut claimed = lease.clone();
            claimed.state = LeaseState::Releasing;
            let claimed_ok = self
                .leases
                .claim_for_release(&lease.id, LeaseState::Ready, observed_expires_at, now)
                .await
                .map_err(|detail| LabUseCaseError::Backend {
                    context: "leases",
                    detail,
                })?;
            if claimed_ok {
                released.push(claimed);
                on_claim();
            }
        }
        Ok(released)
    }

    /// Lists the template drafts.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list_templates(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<Vec<LabTemplate>, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabRead,
                resource: None,
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        self.templates
            .list()
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "templates",
                detail,
            })
    }

    /// Creates a template draft after validating the image pin. The audit
    /// intent lands before any mutation.
    ///
    /// # Errors
    ///
    /// Fails on denial, a malformed request, a refused pin, a name
    /// conflict, or a backend failure.
    pub async fn create_template(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        new: NewLabTemplate,
        now: i64,
    ) -> Result<LabTemplate, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabConfig,
                resource: None,
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        new.content
            .validate()
            .map_err(|detail| LabUseCaseError::Invalid { detail })?;
        self.validate_pin(&new.content.image_version_id).await?;
        self.audit_event(
            principal,
            Permission::LabConfig,
            None,
            "lab_template_creating",
            Some(("name", new.content.name.as_str())),
        )
        .await?;
        self.templates.create(&new, now).await.map_err(|detail| {
            if detail.contains("taken") || detail.contains("UNIQUE") {
                LabUseCaseError::Conflict { detail }
            } else {
                LabUseCaseError::Backend {
                    context: "templates",
                    detail,
                }
            }
        })
    }

    /// Reads one draft.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown template, or a backend failure.
    pub async fn get_template(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<LabTemplate, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabRead,
                resource: Some(id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        self.require_template(id).await
    }

    /// Replaces a draft's content after validating the image pin.
    ///
    /// # Errors
    ///
    /// Fails on denial, a malformed request, a refused pin, an unknown
    /// template, or a backend failure.
    pub async fn update_template(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
        content: LabTemplateContent,
        now: i64,
    ) -> Result<LabTemplate, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabConfig,
                resource: Some(id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        content
            .validate()
            .map_err(|detail| LabUseCaseError::Invalid { detail })?;
        self.validate_pin(&content.image_version_id).await?;
        self.audit_event(
            principal,
            Permission::LabConfig,
            Some(id),
            "lab_template_updating",
            None,
        )
        .await?;
        self.templates
            .update(id, &content, now)
            .await
            .map_err(|detail| {
                if detail.contains("not found") {
                    LabUseCaseError::NotFound {
                        what: format!("template {id}"),
                    }
                } else if detail.contains("taken") || detail.contains("UNIQUE") {
                    LabUseCaseError::Conflict { detail }
                } else {
                    LabUseCaseError::Backend {
                        context: "templates",
                        detail,
                    }
                }
            })
    }

    /// Removes a draft. Published versions stay.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown template, or a backend failure.
    pub async fn delete_template(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<(), LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabConfig,
                resource: Some(id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        self.audit_event(
            principal,
            Permission::LabConfig,
            Some(id),
            "lab_template_deleting",
            None,
        )
        .await?;
        self.templates.delete(id).await.map_err(|detail| {
            if detail.contains("not found") {
                LabUseCaseError::NotFound {
                    what: format!("template {id}"),
                }
            } else {
                LabUseCaseError::Backend {
                    context: "templates",
                    detail,
                }
            }
        })
    }

    /// Publishes a draft: freezes an immutable version with provenance
    /// (the publisher and the pinned image's digest). The pin is
    /// re-validated at publish time — an image demoted between edit and
    /// publish refuses here.
    ///
    /// # Errors
    ///
    /// Fails on denial, a refused pin, an unknown template, or a backend
    /// failure.
    pub async fn publish_template(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        template_id: &str,
        now: i64,
    ) -> Result<LabTemplateVersion, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabConfig,
                resource: Some(template_id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let template = self.require_template(template_id).await?;
        let pin = self
            .validate_pin(&template.content.image_version_id)
            .await?;
        let version = LabTemplateVersion {
            id: format!("{}@{}", template.id, &pin.content_digest[..16]),
            template_id: template.id.clone(),
            name: template.content.name.clone(),
            content: template.content.clone(),
            image_digest: pin.content_digest.clone(),
            published_by: principal.id.clone(),
            published_at: now,
        };
        self.audit_event(
            principal,
            Permission::LabConfig,
            Some(template_id),
            "lab_template_publishing",
            Some(("digest", pin.content_digest.as_str())),
        )
        .await?;
        self.templates
            .publish(template_id, &version)
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "versions",
                detail,
            })
    }

    /// Reads one published version.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown version, or a backend failure.
    pub async fn get_template_version(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        version_id: &str,
    ) -> Result<LabTemplateVersion, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabRead,
                resource: Some(version_id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        self.templates
            .get_version(version_id)
            .await
            .map_err(|detail| {
                if detail.contains("not found") {
                    LabUseCaseError::NotFound {
                        what: format!("version {version_id}"),
                    }
                } else {
                    LabUseCaseError::Backend {
                        context: "versions",
                        detail,
                    }
                }
            })
    }

    /// Starts provisioning a published template version: creates the
    /// record and returns it in `provisioning`. An idempotency key scoped
    /// to the caller makes a retry return the in-flight record instead of
    /// creating a second guest saga. The saga's external-ID steps are
    /// driven by the executor; this use case is the durable entry point.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown version, or a backend failure.
    #[allow(clippy::too_many_lines)]
    pub async fn start_provision(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        version_id: &str,
        lease_id: Option<&str>,
        idempotency_key: Option<&str>,
        now: i64,
    ) -> Result<ProvisionRecord, LabUseCaseError> {
        self.start_provision_with_outcome(
            authorizer,
            principal,
            version_id,
            lease_id,
            idempotency_key,
            now,
        )
        .await
        .map(|(record, _)| record)
    }

    #[allow(clippy::too_many_lines)]
    async fn start_provision_with_outcome(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        version_id: &str,
        lease_id: Option<&str>,
        idempotency_key: Option<&str>,
        now: i64,
    ) -> Result<(ProvisionRecord, bool), LabUseCaseError> {
        let authorization_resource = lease_id.unwrap_or(version_id);
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabProvision,
                resource: Some(authorization_resource),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let lease = if let Some(lease_id) = lease_id {
            let lease = self.leases.get(lease_id).await.map_err(|detail| {
                if detail.contains("not found") {
                    LabUseCaseError::NotFound {
                        what: format!("lease {lease_id}"),
                    }
                } else {
                    LabUseCaseError::Backend {
                        context: "leases",
                        detail,
                    }
                }
            })?;
            if lease.template_version_id != version_id {
                return Err(LabUseCaseError::Invalid {
                    detail: "the lease uses a different template version".to_owned(),
                });
            }
            if lease.state != LeaseState::Requested
                && !(matches!(
                    lease.state,
                    LeaseState::Provisioning | LeaseState::Booting | LeaseState::Bootstrapping
                ) && lease.provision_id.is_some())
            {
                return Err(LabUseCaseError::Conflict {
                    detail: format!("lease {lease_id} is not awaiting provisioning"),
                });
            }
            Some(lease)
        } else {
            None
        };
        // The version must exist and its image pin must still be
        // promoted: a demotion between publish and provision refuses.
        let version = self
            .templates
            .get_version(version_id)
            .await
            .map_err(|detail| {
                if detail.contains("not found") {
                    LabUseCaseError::NotFound {
                        what: format!("version {version_id}"),
                    }
                } else {
                    LabUseCaseError::Backend {
                        context: "versions",
                        detail,
                    }
                }
            })?;
        self.validate_pin(&version.content.image_version_id).await?;
        self.audit_event(
            principal,
            Permission::LabProvision,
            Some(lease_id.unwrap_or(version_id)),
            "lab_provision_starting",
            Some(("digest", version.image_digest.as_str())),
        )
        .await?;
        // Idempotent replay: the caller-scoped key returns the in-flight
        // record instead of creating a second guest saga.
        let scoped_key = lease_id
            .map(|id| format!("{}:lab-lease:{id}", principal.id))
            .or_else(|| idempotency_key.map(|key| format!("{}:{key}", principal.id)));
        if let Some(key) = &scoped_key
            && let Some(existing) =
                self.provisions
                    .find_by_idempotency_key(key)
                    .await
                    .map_err(|detail| LabUseCaseError::Backend {
                        context: "provisions",
                        detail,
                    })?
        {
            if existing.lease_id.as_deref() != lease_id {
                return Err(LabUseCaseError::Conflict {
                    detail: "the idempotency key is already attached to another lease".to_owned(),
                });
            }
            if existing.state == GuestState::NeverReady {
                return Err(LabUseCaseError::Conflict {
                    detail: "this lease's provision attempt is terminal; release it and request a replacement lease".to_owned(),
                });
            }
            let changed = self
                .attach_lease_provision(lease.as_ref(), &existing)
                .await?;
            return Ok((existing, changed));
        }
        let mut provision = self
            .provisions
            .create(
                &NewProvision {
                    template_version_id: version_id.to_owned(),
                    lease_id: lease_id.map(str::to_owned),
                    idempotency_key: scoped_key,
                },
                now,
            )
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "provisions",
                detail,
            })?;
        // The readiness deadline runs from the request (lab.md): recorded
        // before any step, so the sweeper can compensate a saga the
        // controller died in before it booted a guest (#302).
        if provision.readiness_deadline_at.is_none() {
            provision.readiness_deadline_at = Some(now.saturating_add(
                i64::from(version.content.readiness_deadline_seconds).saturating_mul(1_000),
            ));
            self.provisions.update(&provision).await.map_err(|detail| {
                LabUseCaseError::Backend {
                    context: "provisions",
                    detail,
                }
            })?;
        }
        let changed = self
            .attach_lease_provision(lease.as_ref(), &provision)
            .await?;
        Ok((provision, changed))
    }

    /// Starts the provision saga attached to an existing lease.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown lease, a mismatched/non-requested lease,
    /// an unpromoted image pin, or a backend failure.
    pub async fn start_lease_provision(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        lease_id: &str,
        idempotency_key: Option<&str>,
        now: i64,
    ) -> Result<(ProvisionRecord, bool), LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabProvision,
                resource: Some(lease_id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        let lease = self.leases.get(lease_id).await.map_err(|detail| {
            if detail.contains("not found") {
                LabUseCaseError::NotFound {
                    what: format!("lease {lease_id}"),
                }
            } else {
                LabUseCaseError::Backend {
                    context: "leases",
                    detail,
                }
            }
        })?;
        self.start_provision_with_outcome(
            authorizer,
            principal,
            &lease.template_version_id,
            Some(lease_id),
            idempotency_key,
            now,
        )
        .await
    }

    async fn attach_lease_provision(
        &self,
        lease: Option<&Lease>,
        provision: &ProvisionRecord,
    ) -> Result<bool, LabUseCaseError> {
        let Some(lease) = lease else {
            return Ok(false);
        };
        if provision.lease_id.as_deref() != Some(lease.id.as_str()) {
            return Err(LabUseCaseError::Conflict {
                detail: "the provision record is not linked to this lease".to_owned(),
            });
        }
        let attached = self
            .leases
            .attach_provision(&lease.id, &provision.id)
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "leases",
                detail,
            })?;
        match attached {
            AttachProvisionOutcome::Attached => Ok(true),
            AttachProvisionOutcome::AlreadyAttached => Ok(false),
            AttachProvisionOutcome::Conflict => Err(LabUseCaseError::Conflict {
                detail: format!("lease {} changed before provisioning started", lease.id),
            }),
        }
    }

    /// Lists the provisioning records.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list_provisions(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
    ) -> Result<Vec<ProvisionRecord>, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabRead,
                resource: None,
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        self.provisions
            .list()
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "provisions",
                detail,
            })
    }

    /// Reads one provisioning record.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown record, or a backend failure.
    pub async fn get_provision(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        id: &str,
    ) -> Result<ProvisionRecord, LabUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::LabRead,
                resource: Some(id),
            },
        )
        .map_err(LabUseCaseError::Denied)?;
        self.provisions.get(id).await.map_err(|detail| {
            if detail.contains("not found") {
                LabUseCaseError::NotFound {
                    what: format!("provision {id}"),
                }
            } else {
                LabUseCaseError::Backend {
                    context: "provisions",
                    detail,
                }
            }
        })
    }

    async fn validate_pin(&self, version_id: &str) -> Result<RecipeVersion, LabUseCaseError> {
        let promoted = self
            .image_pins
            .promoted_version(version_id)
            .await
            .map_err(|detail| {
                // An unknown version is a pin refusal, not a backend
                // failure: the caller named an image that does not exist.
                if detail.contains("not found") {
                    LabUseCaseError::PinRefused {
                        detail: format!(
                            "the image version {version_id} does not exist; only promoted versions can be pinned"
                        ),
                    }
                } else {
                    LabUseCaseError::Backend {
                        context: "image_pins",
                        detail,
                    }
                }
            })?;
        promoted.ok_or_else(|| LabUseCaseError::PinRefused {
            detail: format!(
                "the image version {version_id} is not promoted; only promoted versions can be pinned"
            ),
        })
    }

    async fn require_template(&self, id: &str) -> Result<LabTemplate, LabUseCaseError> {
        self.templates.get(id).await.map_err(|detail| {
            if detail.contains("not found") {
                LabUseCaseError::NotFound {
                    what: format!("template {id}"),
                }
            } else {
                LabUseCaseError::Backend {
                    context: "templates",
                    detail,
                }
            }
        })
    }

    async fn audit_event(
        &self,
        principal: &ActingPrincipal,
        action: Permission,
        template_id: Option<&str>,
        event: &str,
        fact: Option<(&str, &str)>,
    ) -> Result<(), LabUseCaseError> {
        let mut metadata = crate::audit::AuditMetadata::default();
        metadata
            .insert("event", event)
            .map_err(|error| LabUseCaseError::Backend {
                context: "audit",
                detail: error.to_string(),
            })?;
        if let Some((key, value)) = fact {
            metadata
                .insert(key, value)
                .map_err(|error| LabUseCaseError::Backend {
                    context: "audit",
                    detail: error.to_string(),
                })?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal.id.clone(),
                action: action.id().to_owned(),
                resource: template_id.map(str::to_owned),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| LabUseCaseError::Backend {
                context: "audit",
                detail,
            })
    }
}

/// The failed cleanup attempts after which a releasing lease stops
/// retrying and becomes `cleanup_failed`: it then visibly owns whatever is
/// left on the host until an operator resolves it. An operator re-arm
/// ([`rearm_cleanup`]) grants another round of this many attempts.
pub const MAX_CLEANUP_ATTEMPTS: u32 = 5;

/// The delay before the next cleanup attempt after `attempts` failed ones:
/// one minute, doubling, capped at an hour.
#[must_use]
pub fn cleanup_backoff_millis(attempts: u32) -> i64 {
    const MINUTE: i64 = 60_000;
    let factor = 1_i64 << attempts.saturating_sub(1).min(6);
    (MINUTE * factor).min(60 * MINUTE)
}

/// What one failed cleanup attempt does to its lease: it stays `releasing`
/// with the next attempt scheduled, or, once the round's attempts are
/// exhausted, becomes `cleanup_failed` with nothing scheduled.
///
/// `cleanup_attempts` counts every failed attempt over the lease's life and
/// never goes back: each attempt's idempotency key names that count
/// ([`cleanup_operation`]), so a count that went back would name an old
/// attempt's operation instead of queuing a new one. Attempts therefore
/// run in rounds of [`MAX_CLEANUP_ATTEMPTS`]: a round ends at the next
/// multiple, and the backoff restarts with each round.
pub fn record_cleanup_failure(lease: &mut Lease, now: i64) {
    lease.cleanup_attempts = lease.cleanup_attempts.saturating_add(1);
    let in_round = lease.cleanup_attempts % MAX_CLEANUP_ATTEMPTS;
    if in_round == 0 {
        lease.state = LeaseState::CleanupFailed;
        lease.cleanup_next_at = None;
    } else {
        lease.state = LeaseState::Releasing;
        lease.cleanup_next_at = Some(now.saturating_add(cleanup_backoff_millis(in_round)));
    }
}

/// What an operator re-arm does to a `cleanup_failed` lease (#292): it is
/// `releasing` again with a fresh round of [`MAX_CLEANUP_ATTEMPTS`]
/// attempts and its next attempt due at once. The failed-attempt count is
/// kept, so the next attempt's idempotency key is one no earlier attempt
/// used. Fleet only ever raises the count, and a `cleanup_failed` lease
/// ends on a round boundary; a count off it (after a change of the limit)
/// is rounded up, never down onto an earlier key. A count lowered by
/// editing the database by hand is outside that guarantee.
pub fn rearm_cleanup(lease: &mut Lease) {
    lease.state = LeaseState::Releasing;
    lease.cleanup_attempts = lease
        .cleanup_attempts
        .max(1)
        .next_multiple_of(MAX_CLEANUP_ATTEMPTS);
    lease.cleanup_next_at = None;
}

/// Where a lease goes after its provision failed or was cancelled: to
/// `releasing` (cleanup owed) when the record allocated a guest, including
/// from `failed`, whose terminal state would otherwise strand the guest; to
/// `failed` when an in-flight lease never allocated one; otherwise nowhere.
#[must_use]
pub fn provision_compensation(state: LeaseState, allocated: bool) -> Option<LeaseState> {
    let in_flight = matches!(
        state,
        LeaseState::Provisioning | LeaseState::Booting | LeaseState::Bootstrapping
    );
    match (in_flight || state == LeaseState::Failed, allocated) {
        (true, true) => Some(LeaseState::Releasing),
        (true, false) if in_flight => Some(LeaseState::Failed),
        _ => None,
    }
}

/// The largest command a Lab exec accepts.
pub const MAX_LAB_EXEC_SCRIPT_BYTES: usize = 64 * 1024;
/// The longest a Lab exec may run (the SSH exec bound).
pub const MAX_LAB_EXEC_TIMEOUT_SECONDS: u64 = 900;

/// Whether a lease may run a command at `now`: it is `ready` and its TTL
/// has not expired. Checked when the exec is requested and again when it
/// runs.
///
/// # Errors
///
/// Answers why it may not.
pub fn lease_exec_ready(lease: &Lease, now: i64) -> Result<(), String> {
    if lease.state != LeaseState::Ready {
        return Err(format!(
            "the lease is {}; commands run only on a ready lease",
            lease.state.id()
        ));
    }
    // A ready lease always has a TTL deadline; one without is not trusted
    // to run commands indefinitely.
    match lease.expires_at {
        Some(expires) if expires > now => {}
        Some(_) => return Err("the lease has expired".to_owned()),
        None => return Err("the lease has no expiry deadline".to_owned()),
    }
    Ok(())
}

/// How long past its readiness deadline an in-flight lease may stay before
/// the sweeper compensates it: the provision executor enforces the deadline
/// itself, so this only catches a provision that stopped running.
pub const STUCK_GRACE_MILLIS: i64 = 10 * 60 * 1000;

/// Whether `record`, the record named by `lease.provision_id`, holds a guest
/// that belongs to `lease`: it links back to the lease and allocated a VMID.
/// Only then may compensation queue a cleanup for it; an inconsistent link
/// must never move this lease to a cleanup that would destroy another
/// lease's VM.
#[must_use]
pub fn lease_allocated(lease: &Lease, record: Option<&ProvisionRecord>) -> bool {
    record.is_some_and(|record| {
        record.lease_id.as_deref() == Some(lease.id.as_str()) && record.vmid.is_some()
    })
}

/// Where the sweeper moves a lease whose provision stopped converging, if
/// anywhere (FM-716). An in-flight lease is compensated once it is past its
/// readiness deadline plus [`STUCK_GRACE_MILLIS`], or past its maximum
/// lifetime (both inclusive, like the TTL and cleanup deadlines). A record
/// counts as the lease's guest only when it links back to the lease
/// ([`lease_allocated`]). A `failed` lease whose record still holds a guest
/// is moved to cleanup at once: `failed` is terminal, so a crash between the failure and
/// its compensation would otherwise strand the guest.
#[must_use]
pub fn stuck_compensation(
    lease: &Lease,
    record: Option<&ProvisionRecord>,
    now: i64,
) -> Option<LeaseState> {
    let allocated = lease_allocated(lease, record);
    let due = match lease.state {
        LeaseState::Failed => true,
        LeaseState::Provisioning | LeaseState::Booting | LeaseState::Bootstrapping => {
            record
                .and_then(|record| record.readiness_deadline_at)
                .is_some_and(|deadline| deadline.saturating_add(STUCK_GRACE_MILLIS) <= now)
                || lease.max_lifetime_at <= now
        }
        _ => false,
    };
    if due {
        provision_compensation(lease.state, allocated)
    } else {
        None
    }
}

/// Whether a Fleet-named Lab guest (`fm-lab-<record>`), listed through
/// `account_id` with `vmid`, is accounted for by Lab state (FM-716): its
/// record exists and names that account and VMID (the ones cleanup would
/// destroy through), and the record is standalone, or its lease links back
/// to it (`provision_id`) and still owns the
/// guest (any state but `released` or `failed`), or the lease was released
/// with `keep`. A record whose lease no longer exists owns nothing.
#[must_use]
pub fn guest_owned(
    record: Option<&ProvisionRecord>,
    lease: Option<&Lease>,
    account_id: &str,
    vmid: u32,
) -> bool {
    let Some(record) = record else {
        return false;
    };
    if record.vmid != Some(vmid) || record.account_id.as_deref() != Some(account_id) {
        return false;
    }
    if record.lease_id.is_none() {
        return true;
    }
    // The lease must link back to this record: its cleanup destroys only the
    // guest its own `provision_id` names.
    lease
        .filter(|lease| lease.provision_id.as_deref() == Some(record.id.as_str()))
        .is_some_and(|lease| match lease.state {
            LeaseState::Released => lease.cleanup == CleanupStrategy::Keep,
            LeaseState::Failed => false,
            _ => true,
        })
}

/// Whether a releasing lease's next cleanup attempt may be queued at `now`:
/// not before the backoff after a failed attempt has passed.
#[must_use]
pub fn cleanup_due(lease: &Lease, now: i64) -> bool {
    lease.state == LeaseState::Releasing && lease.cleanup_next_at.is_none_or(|due| due <= now)
}

/// The `lab.cleanup` operation for a releasing lease's next attempt. The
/// idempotency key names the attempt, so a repeated release or sweep never
/// queues a second cleanup for the same attempt, while a retry after a
/// failed attempt, or after an operator re-arm, queues a new one.
#[must_use]
pub fn cleanup_operation(
    lease: &Lease,
    correlation_id: Option<String>,
) -> crate::operation::NewOperation {
    crate::operation::NewOperation {
        kind: "lab.cleanup".to_owned(),
        idempotency_key: Some(format!(
            "lab-cleanup:{}:{}",
            lease.id, lease.cleanup_attempts
        )),
        deadline_at: None,
        correlation_id,
        payload_json: Some(serde_json::json!({ "leaseId": lease.id }).to_string()),
        review_token: None,
    }
}

#[cfg(test)]
mod tests {
    use super::guard_destroy_target;

    #[test]
    fn a_failed_provision_owes_cleanup_only_for_an_allocated_guest() {
        use fleet_core::LeaseState::{
            Booting, Failed, Provisioning, Ready, Released, Releasing, Requested,
        };
        assert_eq!(
            super::provision_compensation(Provisioning, true),
            Some(Releasing)
        );
        assert_eq!(
            super::provision_compensation(Booting, true),
            Some(Releasing)
        );
        // FM-714 marks a readiness failure `failed`; its guest still needs cleanup.
        assert_eq!(super::provision_compensation(Failed, true), Some(Releasing));
        assert_eq!(
            super::provision_compensation(Provisioning, false),
            Some(Failed)
        );
        assert_eq!(super::provision_compensation(Failed, false), None);
        for state in [Requested, Ready, Releasing, Released] {
            assert_eq!(
                super::provision_compensation(state, true),
                None,
                "{state:?}"
            );
        }
    }

    #[test]
    fn cleanup_backs_off_then_gives_up_visibly() {
        assert_eq!(super::cleanup_backoff_millis(1), 60_000);
        assert_eq!(super::cleanup_backoff_millis(2), 120_000);
        assert_eq!(super::cleanup_backoff_millis(40), 3_600_000);
        let mut lease = fleet_core::Lease {
            id: "l1".to_owned(),
            state: fleet_core::LeaseState::Releasing,
            ..fleet_core::Lease::default()
        };
        for attempt in 1..super::MAX_CLEANUP_ATTEMPTS {
            super::record_cleanup_failure(&mut lease, 1_000);
            assert_eq!(
                lease.state,
                fleet_core::LeaseState::Releasing,
                "attempt {attempt}"
            );
            assert_eq!(
                lease.cleanup_next_at,
                Some(1_000 + super::cleanup_backoff_millis(attempt))
            );
        }
        super::record_cleanup_failure(&mut lease, 2_000);
        assert_eq!(lease.state, fleet_core::LeaseState::CleanupFailed);
        assert_eq!(lease.cleanup_next_at, None);
        // Not due again until the backoff passes.
        lease.state = fleet_core::LeaseState::Releasing;
        lease.cleanup_next_at = Some(5_000);
        assert!(!super::cleanup_due(&lease, 4_999));
        assert!(super::cleanup_due(&lease, 5_000));
        lease.state = fleet_core::LeaseState::CleanupFailed;
        // Each attempt gets its own idempotency key.
        let key = super::cleanup_operation(&lease, None).idempotency_key;
        assert_eq!(key.as_deref(), Some("lab-cleanup:l1:5"));
    }

    fn record(vmid: Option<u32>, lease_id: Option<&str>) -> super::ProvisionRecord {
        super::ProvisionRecord {
            id: "r1".to_owned(),
            template_version_id: "tv1".to_owned(),
            lease_id: lease_id.map(str::to_owned),
            state: fleet_core::GuestState::default(),
            node: vmid.map(|_| "pve".to_owned()),
            vmid,
            clone_upid: None,
            guest_ipv4: None,
            machine_id: None,
            endpoint_id: None,
            ready_project_operation_id: None,
            readiness_deadline_at: Some(10_000),
            failed_step: None,
            account_id: Some("a1".to_owned()),
            idempotency_key: None,
            ready_at: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn the_sweeper_compensates_stuck_and_failed_leases_by_what_they_allocated() {
        use super::{STUCK_GRACE_MILLIS, stuck_compensation};
        use fleet_core::LeaseState::{Booting, Failed, Provisioning, Ready, Releasing};
        let lease = |state| fleet_core::Lease {
            id: "l1".to_owned(),
            state,
            max_lifetime_at: i64::MAX,
            ..fleet_core::Lease::default()
        };
        let past = 10_000 + STUCK_GRACE_MILLIS + 1;
        let guest = record(Some(9000), Some("l1"));
        let none = record(None, Some("l1"));
        // Inside the grace the provision may still be running.
        assert_eq!(
            stuck_compensation(&lease(Provisioning), Some(&guest), 10_001),
            None
        );
        assert_eq!(
            stuck_compensation(&lease(Provisioning), Some(&guest), past),
            Some(Releasing)
        );
        assert_eq!(
            stuck_compensation(&lease(Booting), Some(&none), past),
            Some(Failed)
        );
        // Both deadlines are inclusive: due the moment they are reached.
        assert_eq!(
            stuck_compensation(&lease(Provisioning), Some(&guest), past - 1),
            Some(Releasing)
        );
        assert_eq!(
            stuck_compensation(&lease(Provisioning), Some(&guest), past - 2),
            None
        );
        // Past the maximum lifetime, whatever the deadline.
        let mut old = lease(Booting);
        old.max_lifetime_at = 5;
        assert_eq!(stuck_compensation(&old, None, 5), Some(Failed));
        assert_eq!(stuck_compensation(&old, None, 4), None);
        // A failed lease still holding a guest is repaired at once; one
        // that never allocated stays failed.
        assert_eq!(
            stuck_compensation(&lease(Failed), Some(&guest), 0),
            Some(Releasing)
        );
        assert_eq!(stuck_compensation(&lease(Failed), Some(&none), past), None);
        assert_eq!(stuck_compensation(&lease(Ready), Some(&guest), past), None);
        // A record linked to another lease is not this lease's guest: no
        // cleanup through this lease, only the unallocated outcome.
        let foreign = record(Some(9000), Some("l2"));
        assert_eq!(
            stuck_compensation(&lease(Provisioning), Some(&foreign), past),
            Some(Failed)
        );
        assert_eq!(stuck_compensation(&lease(Failed), Some(&foreign), 0), None);
        // The executor's failure-path compensation shares the predicate.
        assert!(super::lease_allocated(&lease(Failed), Some(&guest)));
        assert!(!super::lease_allocated(&lease(Failed), Some(&foreign)));
        assert!(!super::lease_allocated(&lease(Failed), Some(&none)));
        assert!(!super::lease_allocated(&lease(Failed), None));
    }

    #[test]
    fn a_guest_is_owned_only_through_its_records_account_and_vmid() {
        use super::guest_owned;
        use fleet_core::{CleanupStrategy, LeaseState};
        let lease = |state, cleanup| fleet_core::Lease {
            id: "l1".to_owned(),
            state,
            cleanup,
            provision_id: Some("r1".to_owned()),
            ..fleet_core::Lease::default()
        };
        let linked = record(Some(9000), Some("l1"));
        let ready = lease(LeaseState::Ready, CleanupStrategy::Destroy);
        assert!(guest_owned(Some(&linked), Some(&ready), "a1", 9000));
        // The same VMID on another account is not this record's guest.
        assert!(!guest_owned(Some(&linked), Some(&ready), "a2", 9000));
        assert!(!guest_owned(Some(&linked), Some(&ready), "a1", 9001));
        let mut unbound = linked.clone();
        unbound.account_id = None;
        assert!(!guest_owned(Some(&unbound), Some(&ready), "a1", 9000));
        assert!(!guest_owned(None, None, "a1", 9000));
        // Standalone records own their guest; a vanished lease owns nothing.
        assert!(guest_owned(
            Some(&record(Some(9000), None)),
            None,
            "a1",
            9000
        ));
        assert!(!guest_owned(Some(&linked), None, "a1", 9000));
        let kept = lease(LeaseState::Released, CleanupStrategy::Keep);
        let destroyed = lease(LeaseState::Released, CleanupStrategy::Destroy);
        let failed = lease(LeaseState::Failed, CleanupStrategy::Destroy);
        assert!(guest_owned(Some(&linked), Some(&kept), "a1", 9000));
        assert!(!guest_owned(Some(&linked), Some(&destroyed), "a1", 9000));
        assert!(!guest_owned(Some(&linked), Some(&failed), "a1", 9000));
        // A lease that points at another record does not own this guest.
        let mut elsewhere = ready.clone();
        elsewhere.provision_id = Some("r2".to_owned());
        assert!(!guest_owned(Some(&linked), Some(&elsewhere), "a1", 9000));
        elsewhere.provision_id = None;
        assert!(!guest_owned(Some(&linked), Some(&elsewhere), "a1", 9000));
    }

    #[test]
    fn a_rearm_grants_a_fresh_round_under_new_idempotency_keys() {
        use fleet_core::LeaseState::{CleanupFailed, Releasing};
        let max = super::MAX_CLEANUP_ATTEMPTS;
        let mut lease = fleet_core::Lease {
            id: "l1".to_owned(),
            state: Releasing,
            ..fleet_core::Lease::default()
        };
        let mut keys = std::collections::HashSet::new();
        let mut attempt = |lease: &mut fleet_core::Lease| {
            let key = super::cleanup_operation(lease, None)
                .idempotency_key
                .unwrap();
            assert!(keys.insert(key.clone()), "{key} was already used");
            super::record_cleanup_failure(lease, 1_000);
        };
        for _ in 0..max {
            attempt(&mut lease);
        }
        assert_eq!(lease.state, CleanupFailed);
        assert_eq!(lease.cleanup_attempts, max);

        super::rearm_cleanup(&mut lease);
        assert_eq!(lease.state, Releasing);
        assert_eq!(lease.cleanup_next_at, None);
        assert!(super::cleanup_due(&lease, 0));
        // The round restarts the backoff and runs the full budget again,
        // each attempt under a key no earlier attempt used.
        attempt(&mut lease);
        assert_eq!(lease.state, Releasing);
        assert_eq!(
            lease.cleanup_next_at,
            Some(1_000 + super::cleanup_backoff_millis(1))
        );
        for _ in 1..max {
            attempt(&mut lease);
        }
        assert_eq!(lease.state, CleanupFailed);
        assert_eq!(lease.cleanup_attempts, 2 * max);

        // A count off the round boundary (after a change of the limit) is
        // rounded up, never back onto a used key.
        lease.cleanup_attempts = 0;
        super::rearm_cleanup(&mut lease);
        assert_eq!(lease.cleanup_attempts, max);
        lease.cleanup_attempts = max + 2;
        super::rearm_cleanup(&mut lease);
        assert_eq!(lease.cleanup_attempts, 2 * max);
    }

    #[test]
    fn the_cleanup_guard_refuses_templates_and_image_artifacts() {
        assert!(
            guard_destroy_target(9000, true, &[])
                .unwrap_err()
                .contains("is a template")
        );
        assert!(
            guard_destroy_target(9000, false, &[120, 9000])
                .unwrap_err()
                .contains("build artifact")
        );
        assert!(guard_destroy_target(9001, false, &[120, 9000]).is_ok());
    }
}
