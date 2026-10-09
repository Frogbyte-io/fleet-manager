//! Pooled Lab guests in the controller (FM-717): the Proxmox reads behind
//! [`PoolGuestPort`], the reviewed revert that fill and cleanup share, and
//! the `lab.pool.fill` executor. The rules are
//! [`fleet_application::lab_pool`]'s; this module is the adapter.
//!
//! A revert always runs as FM-603's reviewed `proxmox.guest.snapshot-revert`
//! child operation, whose review token the controller computes over the
//! exact payload (it never comes from a caller), after the guest passed
//! [`member_identity`]. It is verified by reading the guest's config back
//! ([`verify_reverted`]): PVE's rollback sets the config's `parent` to the
//! restored snapshot and removes its `rollback` lock when it finishes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_application::lab::{ImageArtifactPort, LabTemplatePort};
use fleet_application::lab_pool::{
    FILL_KIND, FillResult, GuestObservation, LabPoolPort, MemberState, PoolGuestPort,
    RevertedConfig, member_audit, member_identity, verify_audio, verify_reverted,
};
use fleet_application::operation::{AuditPort, NewOperation, Operation, Operations};
use fleet_application::proxmox::{ProxmoxAccountPort, ProxmoxCredentialStore};
use fleet_application::worker::OperationExecutor;
use fleet_provider_proxmox::ProxmoxSource as _;

/// How long one revert child may take, including PVE's stop of a running
/// guest.
pub const REVERT_TIMEOUT_SECONDS: u64 = 600;
/// How long a caller waits for a reviewed child the worker claimed first.
const CHILD_WAIT: Duration = Duration::from_secs(REVERT_TIMEOUT_SECONDS + 60);

/// [`PoolGuestPort`] over the Proxmox provider, through the pool's account
/// with its confirmed fingerprint.
#[derive(Debug)]
pub struct ProxmoxPoolGuests {
    accounts: Arc<dyn ProxmoxAccountPort>,
    credentials: Arc<dyn ProxmoxCredentialStore>,
    client: fleet_provider_proxmox::ProxmoxClient,
    artifacts: Arc<dyn ImageArtifactPort>,
}

impl ProxmoxPoolGuests {
    /// Composes the port from its parts.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn ProxmoxAccountPort>,
        credentials: Arc<dyn ProxmoxCredentialStore>,
        client: fleet_provider_proxmox::ProxmoxClient,
        artifacts: Arc<dyn ImageArtifactPort>,
    ) -> Self {
        Self {
            accounts,
            credentials,
            client,
            artifacts,
        }
    }

    async fn request(
        &self,
        account_id: &str,
    ) -> Result<fleet_provider_proxmox::PveHttpRequest, String> {
        let account = self
            .accounts
            .get(account_id)
            .await
            .map_err(|detail| format!("the account is unreadable: {detail}"))?;
        if account.fingerprint.is_none() {
            return Err(format!(
                "the account {} has no confirmed fingerprint; confirm the host's trust first",
                account.name
            ));
        }
        let secret = self
            .credentials
            .load(account_id)
            .await
            .map_err(|error| format!("the credential store failed: {error}"))?
            .ok_or_else(|| {
                format!(
                    "the API token for account {} is not in the secret store",
                    account.name
                )
            })?;
        Ok(crate::proxmox_exec::pve_request(&account, secret))
    }
}

#[async_trait::async_trait]
impl PoolGuestPort for ProxmoxPoolGuests {
    async fn observe(
        &self,
        account_id: &str,
        vmid: u32,
        baseline: &str,
    ) -> Result<GuestObservation, String> {
        let request = self.request(account_id).await?;
        let protected = self
            .artifacts
            .promoted_template_vmids()
            .await
            .map_err(|detail| format!("the image artifacts are unreadable: {detail}"))?;
        let resources = self
            .client
            .list_guest_resources(request.clone())
            .await
            .map_err(|error| format!("the resource listing failed: {error}"))?;
        let Some(guest) = resources
            .into_iter()
            .find(|resource| resource.vmid == Some(vmid))
        else {
            return Ok(GuestObservation {
                protected_artifact: protected.contains(&vmid),
                ..GuestObservation::default()
            });
        };
        // Only a QEMU guest's snapshots are read: anything else is refused
        // by its kind.
        let baseline_present = match (guest.kind.as_str(), guest.node.as_deref()) {
            ("qemu", Some(node)) => self
                .client
                .guest_snapshots(request, node, vmid)
                .await
                .map_err(|error| format!("the snapshot listing failed: {error}"))?
                .iter()
                .any(|snapshot| snapshot.name == baseline),
            _ => false,
        };
        Ok(GuestObservation {
            kind: Some(guest.kind),
            node: guest.node,
            name: guest.name,
            baseline_present,
            protected_artifact: protected.contains(&vmid),
        })
    }

    async fn reverted_config(
        &self,
        account_id: &str,
        node: &str,
        vmid: u32,
    ) -> Result<RevertedConfig, String> {
        let request = self.request(account_id).await?;
        let flags = self
            .client
            .qemu_config_flags(request, node, vmid)
            .await
            .map_err(|error| format!("the guest config is unreadable: {error}"))?;
        Ok(RevertedConfig {
            template: flags.template,
            lock: flags.lock,
            parent: flags.parent,
            audio_unreadable: flags.audio_unreadable,
            audio: flags.audio.map(|audio| fleet_core::LabAudio {
                device: audio.device,
                driver: audio.driver,
            }),
        })
    }
}

/// Creates (or re-finds, by `idempotency_key`) one reviewed destructive
/// child operation, runs it through `executor` (or waits for the worker
/// that claimed it first), and answers its final record. The review token
/// is computed here over the exact payload bytes, as the reviewed endpoint
/// does: the controller reviews its own Lab work.
///
/// # Errors
///
/// Fails when the child cannot be created or read, or does not finish in
/// time.
pub async fn run_reviewed_child(
    operations: &Operations,
    executor: &dyn OperationExecutor,
    kind: &str,
    payload: String,
    idempotency_key: String,
    correlation_id: &str,
    wait: Duration,
) -> Result<Operation, String> {
    let review_token = fleet_application::operation::review_token_for(kind, &payload);
    let child = operations
        .create(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &NewOperation {
                kind: kind.to_owned(),
                idempotency_key: Some(idempotency_key),
                deadline_at: None,
                correlation_id: Some(correlation_id.to_owned()),
                payload_json: Some(payload),
                review_token: Some(review_token),
            },
        )
        .await
        .map_err(|_| format!("the {kind} child could not be created"))?;
    let _ = operations
        .claim_only_execute(executor, &child.id, fleet_auth::LAN_PRINCIPAL_ID)
        .await;
    let started = Instant::now();
    loop {
        let current = operations
            .get(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &child.id,
            )
            .await
            .map_err(|_| format!("the {kind} child is unreadable"))?;
        if !matches!(current.state.as_str(), "pending" | "running" | "cancelling") {
            return Ok(current);
        }
        if started.elapsed() > wait {
            return Err(format!("the {kind} child did not finish in time"));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// The `reason` a failed child recorded, or its state.
#[must_use]
pub fn child_reason(child: &Operation) -> String {
    child
        .error_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .and_then(|error| error["reason"].as_str().map(str::to_owned))
        .unwrap_or_else(|| child.state.clone())
}

/// One revert of a pool member: which guest, to what, under which key.
#[derive(Debug)]
pub struct Revert<'a> {
    /// The account the guest is reached through.
    pub account_id: &'a str,
    /// The guest's VMID.
    pub vmid: u32,
    /// The name a fill recorded, when one did.
    pub recorded_name: Option<&'a str>,
    /// The baseline snapshot.
    pub baseline: &'a str,
    /// The child's idempotency key: one per attempt.
    pub idempotency_key: String,
    /// The correlation the child carries (the lease or the pool).
    pub correlation_id: &'a str,
}

/// Why a member was not (verifiably) reverted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevertFailure {
    /// Fleet could not decide: an account, the cluster, the store, or the
    /// child could not be read in time. Nothing says the guest is wrong, so
    /// the member is not quarantined for it; the revert is retried.
    Unavailable(String),
    /// The guest must not be reverted, the rollback failed, or its result
    /// is not the baseline: the member is quarantined.
    Refused(String),
}

impl RevertFailure {
    /// The failure's detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::Unavailable(detail) | Self::Refused(detail) => detail,
        }
    }
}

/// A verified revert: where the guest is, its name, and the config the
/// verification read.
#[derive(Debug)]
pub struct Reverted {
    /// The node the guest is on.
    pub node: String,
    /// The guest's name.
    pub name: String,
    /// The config read after the rollback.
    pub config: RevertedConfig,
}

/// Checks the guest's identity, reverts it to its baseline through the
/// reviewed revert, and verifies the result. Answers the guest's node and
/// name.
///
/// # Errors
///
/// Answers why the guest was not (verifiably) reverted, and whether that
/// condemns the member ([`RevertFailure::Refused`]) or only the attempt.
pub async fn revert_member(
    operations: &Operations,
    reverter: &dyn OperationExecutor,
    guests: &dyn PoolGuestPort,
    revert: Revert<'_>,
) -> Result<Reverted, RevertFailure> {
    let observed = guests
        .observe(revert.account_id, revert.vmid, revert.baseline)
        .await
        .map_err(RevertFailure::Unavailable)?;
    let (node, name) = member_identity(
        &observed,
        revert.vmid,
        revert.recorded_name,
        revert.baseline,
    )
    .map_err(RevertFailure::Refused)?;
    let payload = serde_json::json!({
        "accountId": revert.account_id,
        "node": node,
        "vmid": revert.vmid,
        "timeoutSeconds": REVERT_TIMEOUT_SECONDS,
        "params": { "snapshot": revert.baseline },
    })
    .to_string();
    let child = run_reviewed_child(
        operations,
        reverter,
        "proxmox.guest.snapshot-revert",
        payload,
        revert.idempotency_key,
        revert.correlation_id,
        CHILD_WAIT,
    )
    .await
    .map_err(RevertFailure::Unavailable)?;
    if child.state != "succeeded" {
        return Err(RevertFailure::Refused(format!(
            "the revert to {} ended {}: {}",
            revert.baseline,
            child.state,
            child_reason(&child)
        )));
    }
    // An unreadable config after the rollback is an undecided revert: a
    // re-run re-finds the same child by its key and reads again.
    let config = guests
        .reverted_config(revert.account_id, &node, revert.vmid)
        .await
        .map_err(RevertFailure::Unavailable)?;
    verify_reverted(&config, revert.baseline).map_err(|detail| {
        RevertFailure::Refused(format!("the revert is not verified: {detail}"))
    })?;
    Ok(Reverted { node, name, config })
}

/// The `lab.pool.fill` payload.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FillPayload {
    pool_id: String,
}

/// The `lab.pool.fill` executor: every `filling` member of the pool is
/// checked, reverted to the baseline, verified, and made `available`, or
/// quarantined with the reason. Each step is idempotent, so a re-run after
/// a crash resumes with the members still `filling`.
#[derive(Debug)]
pub struct LabPoolFillExecutor {
    pools: Arc<dyn LabPoolPort>,
    /// Reads the template version whose audio declaration members must meet.
    templates: Arc<dyn LabTemplatePort>,
    guests: Arc<dyn PoolGuestPort>,
    /// Executes the reviewed revert child (the destructive executor).
    reverter: Arc<dyn OperationExecutor>,
    audit: Arc<dyn AuditPort>,
}

impl LabPoolFillExecutor {
    /// Composes the executor from its parts.
    #[must_use]
    pub fn new(
        pools: Arc<dyn LabPoolPort>,
        templates: Arc<dyn LabTemplatePort>,
        guests: Arc<dyn PoolGuestPort>,
        reverter: Arc<dyn OperationExecutor>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            pools,
            templates,
            guests,
            reverter,
            audit,
        }
    }
}

#[async_trait::async_trait]
impl OperationExecutor for LabPoolFillExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload: FillPayload = serde_json::from_str(
            operation
                .payload_json
                .as_deref()
                .ok_or("the operation carries no payload")?,
        )
        .map_err(|error| format!("the payload is not a pool fill: {error}"))?;
        let pool = self.pools.get(&payload.pool_id).await?;
        // A member must carry the audio device the template version
        // declares (issue #398); a version without one asks nothing.
        let wanted_audio = self
            .templates
            .get_version(&pool.template_version_id)
            .await?
            .content
            .audio;
        let filling: Vec<_> = self
            .pools
            .members(&pool.id)
            .await?
            .into_iter()
            .filter(|member| member.state == MemberState::Filling)
            .collect();
        let total = i64::try_from(filling.len()).unwrap_or(i64::MAX);
        let mut available = Vec::new();
        let mut quarantined = Vec::new();
        let mut pending = Vec::new();
        for (done, member) in filling.into_iter().enumerate() {
            if member.draining {
                // Drained while filling: it leaves without a revert.
                let now = fleet_core::SystemClock::now_unix_millis();
                self.pools
                    .finish_fill(
                        &member.id,
                        &FillResult::Quarantined {
                            detail: "drained before its fill".to_owned(),
                        },
                        now,
                    )
                    .await?;
                let _ = self
                    .audit
                    .record_intent(&member_audit(
                        fleet_auth::LAN_PRINCIPAL_ID,
                        &pool.id,
                        Some(&operation.id),
                        "lab_pool_member_removed",
                        &[("vmid", member.vmid.to_string())],
                    ))
                    .await;
                continue;
            }
            let _ = operations
                .record_progress(
                    &operation.id,
                    Some(i64::try_from(done).unwrap_or(i64::MAX)),
                    Some(total),
                    Some(&format!("verifying and reverting VMID {}", member.vmid)),
                )
                .await;
            let outcome = revert_member(
                operations,
                self.reverter.as_ref(),
                self.guests.as_ref(),
                Revert {
                    account_id: &member.account_id,
                    vmid: member.vmid,
                    recorded_name: None,
                    baseline: &pool.baseline_snapshot,
                    idempotency_key: format!("lab-pool-fill:{}", member.id),
                    correlation_id: &pool.id,
                },
            )
            .await;
            // The member's config after the revert is what a lease gets.
            let outcome = outcome.and_then(|reverted| {
                verify_audio(&reverted.config, wanted_audio.as_ref())
                    .map(|()| (reverted.node.clone(), reverted.name.clone()))
                    .map_err(|detail| {
                        RevertFailure::Refused(format!(
                            "the member does not match the template's audio device: {detail}"
                        ))
                    })
            });
            let now = fleet_core::SystemClock::now_unix_millis();
            let (result, event, facts) = match outcome {
                Err(RevertFailure::Unavailable(detail)) => {
                    // Undecided: the member stays filling for a re-fill.
                    let detail = fleet_core::scrub_failure_detail(&detail);
                    pending.push(serde_json::json!({ "vmid": member.vmid, "detail": detail }));
                    continue;
                }
                Ok((node, name)) => {
                    available.push(member.vmid);
                    (
                        FillResult::Available {
                            node: node.clone(),
                            name,
                        },
                        "lab_pool_member_available",
                        vec![("vmid", member.vmid.to_string()), ("node", node)],
                    )
                }
                Err(RevertFailure::Refused(detail)) => {
                    let detail = fleet_core::scrub_failure_detail(&detail);
                    quarantined.push(member.vmid);
                    (
                        FillResult::Quarantined {
                            detail: detail.clone(),
                        },
                        "lab_pool_member_quarantined",
                        vec![("vmid", member.vmid.to_string()), ("reason", detail)],
                    )
                }
            };
            self.pools.finish_fill(&member.id, &result, now).await?;
            // Best effort, like cleanup: the member row is the truth.
            let _ = self
                .audit
                .record_intent(&member_audit(
                    fleet_auth::LAN_PRINCIPAL_ID,
                    &pool.id,
                    Some(&operation.id),
                    event,
                    &facts,
                ))
                .await;
        }
        let result = serde_json::json!({
            "poolId": pool.id,
            "available": available,
            "quarantined": quarantined,
            "pending": pending,
        })
        .to_string();
        // A quarantined member is a recorded outcome, not a failed fill; a
        // member left filling is: the fill must be queued again.
        if pending.is_empty() {
            operations
                .complete(&operation.id, "succeeded", Some(&result), None)
                .await
        } else {
            let error = serde_json::json!({
                "reason": "fill_incomplete",
                "detail": "some members could not be verified and are still filling; fill the pool again once the cause is fixed",
                "available": available,
                "quarantined": quarantined,
                "pending": pending,
            })
            .to_string();
            operations
                .complete(&operation.id, "failed", Some(&result), Some(&error))
                .await
        }
        .map(|_| ())
        .map_err(|error| error.to_string())
    }
}

/// Routes `lab.pool.fill` to the fill executor; everything else falls
/// through.
#[derive(Debug)]
pub struct LabPoolDispatch {
    fallback: Arc<dyn OperationExecutor>,
    fill: Arc<LabPoolFillExecutor>,
}

impl LabPoolDispatch {
    /// Composes the dispatch from its parts.
    #[must_use]
    pub fn new(fallback: Arc<dyn OperationExecutor>, fill: Arc<LabPoolFillExecutor>) -> Self {
        Self { fallback, fill }
    }
}

#[async_trait::async_trait]
impl OperationExecutor for LabPoolDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        if operation.kind == FILL_KIND {
            self.fill.execute(operations, operation).await
        } else {
            self.fallback.execute(operations, operation).await
        }
    }
}
