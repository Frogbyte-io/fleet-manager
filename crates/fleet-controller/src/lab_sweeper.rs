//! The Lab sweeper (FM-716): the controller's background loop that keeps
//! Lab leases converging without an operator, across restarts. Every tick:
//!
//! 1. expires `ready` leases past their TTL into `releasing` (FM-711's
//!    compare-and-set claim);
//! 2. compensates leases stuck in provisioning past their readiness
//!    deadline (or their maximum lifetime), and `failed` leases still
//!    holding a guest: a lease owning a guest is moved to cleanup, one that
//!    never allocated a guest is failed (a compare-and-set, so a provision
//!    completing concurrently wins);
//! 3. queues the `lab.cleanup` of every `releasing` lease whose next attempt
//!    is due (FM-713). That covers backoff retries, and a release or
//!    compensation whose enqueue was lost after the lease committed. It runs
//!    after step 2 so a compensated lease is queued in the same tick;
//! 4. reconciles the Fleet-named Lab guests (`fm-lab-<record>`) on every
//!    trusted Proxmox account against the Lab records, and reports, once
//!    per guest, any that no live lease or provision owns. It never deletes
//!    a guest it cannot attribute.
//! 5. deletes Lab artifacts past their retention deadline (FM-721), when
//!    the artifact store is composed.
//!
//! The rules (what is stuck, what is owned, what is due) live in
//! `fleet_application::lab`; this module only reads rows, applies them, and
//! queues operations. Every deadline and attempt lives in the rows, so a
//! restarted controller picks up exactly where the last one stopped.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleet_application::audit::{AuditIntent, AuditMetadata};
use fleet_application::authz::{Decision, Permission};
use fleet_application::lab::{
    Lab, LeasePort, ProvisionPort, cleanup_due, cleanup_operation, guest_owned,
    record_cleanup_failure, stuck_compensation,
};
use fleet_application::operation::{AuditPort, Operations};

/// Re-exported for callers that reason about the sweeper's grace.
pub use fleet_application::lab::STUCK_GRACE_MILLIS;

/// The Fleet name prefix of every Lab guest; the rest is the provision
/// record's identity.
pub const LAB_GUEST_PREFIX: &str = "fm-lab-";

/// One Fleet-named Lab guest on a Proxmox account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabGuest {
    /// The account it was listed through.
    pub account_id: String,
    /// The node it lives on.
    pub node: String,
    /// Its VMID.
    pub vmid: u32,
    /// Its name (`fm-lab-<record>`).
    pub name: String,
}

/// The Lab guests that exist on the Proxmox side.
#[async_trait::async_trait]
pub trait LabGuestInventory: std::fmt::Debug + Send + Sync {
    /// Every `fm-lab-*` QEMU guest on every trusted account. An account
    /// that cannot be read is skipped, not fatal.
    async fn lab_guests(&self) -> Vec<LabGuest>;
}

/// The inventory over the trusted Proxmox accounts.
#[derive(Debug)]
pub struct ProxmoxLabGuests {
    accounts: Arc<dyn fleet_application::proxmox::ProxmoxAccountPort>,
    credentials: Arc<dyn fleet_application::proxmox::ProxmoxCredentialStore>,
    client: fleet_provider_proxmox::ProxmoxClient,
}

impl ProxmoxLabGuests {
    /// Composes the inventory.
    #[must_use]
    pub fn new(
        accounts: Arc<dyn fleet_application::proxmox::ProxmoxAccountPort>,
        credentials: Arc<dyn fleet_application::proxmox::ProxmoxCredentialStore>,
        client: fleet_provider_proxmox::ProxmoxClient,
    ) -> Self {
        Self {
            accounts,
            credentials,
            client,
        }
    }
}

#[async_trait::async_trait]
impl LabGuestInventory for ProxmoxLabGuests {
    async fn lab_guests(&self) -> Vec<LabGuest> {
        let Ok(accounts) = self.accounts.list().await else {
            return Vec::new();
        };
        let mut guests = Vec::new();
        for account in accounts {
            // The explicit-trust gate: an unconfirmed host is never sent
            // the token.
            if account.fingerprint.is_none() {
                continue;
            }
            let Ok(Some(secret)) = self.credentials.load(&account.id).await else {
                continue;
            };
            let request = crate::proxmox_exec::pve_request(&account, secret);
            let Ok(resources) = self.client.list_guest_resources(request).await else {
                continue;
            };
            for guest in resources {
                let (Some(vmid), Some(name), Some(node)) = (guest.vmid, guest.name, guest.node)
                else {
                    continue;
                };
                if guest.kind == "qemu" && name.starts_with(LAB_GUEST_PREFIX) {
                    guests.push(LabGuest {
                        account_id: account.id.clone(),
                        node,
                        vmid,
                        name,
                    });
                }
            }
        }
        guests
    }
}

/// What one tick did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TickReport {
    /// Ready leases expired into releasing.
    pub expired: usize,
    /// Cleanup attempts queued (new pending operations).
    pub cleanups_queued: usize,
    /// Cleanup attempts interrupted by a crash, counted as failed (#301).
    pub cleanups_abandoned: usize,
    /// Stuck leases compensated.
    pub compensated: usize,
    /// Guests newly reported as unowned this tick.
    pub orphans: Vec<LabGuest>,
    /// Lab artifacts deleted past their retention deadline.
    pub artifacts_expired: usize,
    /// Per-lease steps and per-artifact retention deletions that failed
    /// this tick (logged by the loop and retried on the next tick); the rest
    /// of the tick still ran.
    pub failures: Vec<String>,
}

/// The Lab sweeper.
#[derive(Debug)]
pub struct LabSweeper {
    lab: Arc<Lab>,
    leases: Arc<dyn LeasePort>,
    provisions: Arc<dyn ProvisionPort>,
    operations: Arc<Operations>,
    audit: Arc<dyn AuditPort>,
    events: Option<Arc<fleet_application::events::EventHub>>,
    inventory: Option<Arc<dyn LabGuestInventory>>,
    artifacts: Option<Arc<fleet_application::lab_artifacts::LabArtifacts>>,
    /// Orphans already reported by this process, so each is audited once.
    reported: Mutex<HashSet<(String, u32)>>,
}

impl LabSweeper {
    /// Composes the sweeper.
    #[must_use]
    pub fn new(
        lab: Arc<Lab>,
        leases: Arc<dyn LeasePort>,
        provisions: Arc<dyn ProvisionPort>,
        operations: Arc<Operations>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            lab,
            leases,
            provisions,
            operations,
            audit,
            events: None,
            inventory: None,
            artifacts: None,
            reported: Mutex::new(HashSet::new()),
        }
    }

    /// Publishes `lease.changed` when a tick changes a lease.
    #[must_use]
    pub fn with_events(mut self, events: Arc<fleet_application::events::EventHub>) -> Self {
        self.events = Some(events);
        self
    }

    /// Reconciles against the Proxmox side's Lab guests.
    #[must_use]
    pub fn with_inventory(mut self, inventory: Arc<dyn LabGuestInventory>) -> Self {
        self.inventory = Some(inventory);
        self
    }

    /// Deletes Lab artifacts past their retention deadline (FM-721).
    #[must_use]
    pub fn with_artifacts(
        mut self,
        artifacts: Arc<fleet_application::lab_artifacts::LabArtifacts>,
    ) -> Self {
        self.artifacts = Some(artifacts);
        self
    }

    /// Runs one tick at `now`.
    ///
    /// # Errors
    ///
    /// Fails when the lease or provision store cannot be listed; a tick
    /// that fails part-way leaves every change it made committed (and
    /// announced). A failure confined to one lease is reported in
    /// [`TickReport::failures`] instead, so it cannot stall the others.
    pub async fn tick(&self, now: i64) -> Result<TickReport, String> {
        let principal = fleet_application::authz::ActingPrincipal {
            id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        };
        // 1. Expiry. Each committed claim is announced at once, so a later
        // failure in this tick cannot leave clients unaware of it.
        let expired = self
            .lab
            .sweep_expired_with_progress(
                &fleet_auth::LanAllowAllAuthorizer,
                &principal,
                now,
                || {
                    self.changed();
                },
            )
            .await
            .map_err(|error| error.to_string())?
            .len();
        let mut report = TickReport {
            expired,
            ..TickReport::default()
        };

        // 2. Stuck and failed provisions.
        let records: HashMap<String, _> = self
            .provisions
            .list()
            .await?
            .into_iter()
            .map(|record| (record.id.clone(), record))
            .collect();
        for lease in self.leases.list(None).await? {
            let record = lease.provision_id.as_deref().and_then(|id| records.get(id));
            let Some(state) = stuck_compensation(&lease, record, now) else {
                continue;
            };
            match self
                .leases
                .transition(&lease.id, lease.state, lease.provision_id.as_deref(), state)
                .await
            {
                // The lease moved on (it became ready, was released, or the
                // executor compensated it) since it was listed.
                Ok(false) => {}
                Ok(true) => {
                    self.changed();
                    report.compensated += 1;
                    // The transition is committed; a refused audit is
                    // reported rather than hidden.
                    if let Err(error) = self
                        .audit(
                            &lease.id,
                            "lab_lease_stuck_compensated",
                            &[
                                ("from", lease.state.id().to_owned()),
                                ("to", state.id().to_owned()),
                            ],
                        )
                        .await
                    {
                        report.failures.push(format!(
                            "auditing the compensation of lease {}: {error}",
                            lease.id
                        ));
                    }
                }
                Err(error) => report
                    .failures
                    .push(format!("compensating lease {}: {error}", lease.id)),
            }
        }

        // 3. Due cleanups (re-read: steps 1 and 2 changed states). The
        // create is idempotent per attempt, so only an operation created
        // during this tick counts as newly queued.
        let tick_started = fleet_core::SystemClock::now_unix_millis();
        for lease in &self.leases.list(None).await? {
            if !cleanup_due(lease, now) {
                continue;
            }
            match self
                .operations
                .create_lab_cleanup(
                    &fleet_auth::LanAllowAllAuthorizer,
                    fleet_auth::LAN_PRINCIPAL_ID,
                    &lease.id,
                    &cleanup_operation(lease, None),
                )
                .await
            {
                Ok(operation) if operation.created_at >= tick_started => {
                    self.changed();
                    report.cleanups_queued += 1;
                }
                // The attempt's operation already ended without releasing
                // the lease: the controller died mid-cleanup and worker
                // maintenance failed it, which records nothing on the lease.
                // Count it as a failed attempt so the next one gets a fresh
                // key, with backoff (#301).
                Ok(operation) if abandoned_attempt(&operation) => {
                    match self.leases.get(&lease.id).await {
                        Ok(mut current)
                            if current.state == fleet_core::LeaseState::Releasing
                                && current.cleanup_attempts == lease.cleanup_attempts =>
                        {
                            record_cleanup_failure(
                                &mut current,
                                fleet_core::SystemClock::now_unix_millis(),
                            );
                            match self.leases.update(&current).await {
                                Ok(()) => {
                                    self.changed();
                                    report.cleanups_abandoned += 1;
                                }
                                Err(error) => report.failures.push(format!(
                                    "recording the abandoned cleanup of lease {}: {error}",
                                    lease.id
                                )),
                            }
                        }
                        Ok(_) => {}
                        Err(error) => report.failures.push(format!(
                            "re-reading lease {} after an abandoned cleanup: {error}",
                            lease.id
                        )),
                    }
                }
                Ok(_) => {}
                Err(error) => report.failures.push(format!(
                    "queueing the cleanup of lease {}: {error}",
                    lease.id
                )),
            }
        }

        // 4. Orphans. Ownership is judged against rows listed after the
        // guests (so a provision racing the listing is seen), and a store
        // failure fails the tick instead of reading as "no record".
        if let Some(inventory) = &self.inventory {
            let guests = inventory.lab_guests().await;
            if !guests.is_empty() {
                let records: HashMap<String, _> = self
                    .provisions
                    .list()
                    .await?
                    .into_iter()
                    .map(|record| (record.id.clone(), record))
                    .collect();
                let leases = self.leases.list(None).await?;
                let leases: HashMap<&str, _> = leases
                    .iter()
                    .map(|lease| (lease.id.as_str(), lease))
                    .collect();
                for guest in guests {
                    if self.owned(&guest, &records, &leases) {
                        continue;
                    }
                    let key = (guest.account_id.clone(), guest.vmid);
                    if self.reported()?.contains(&key) {
                        continue;
                    }
                    // Marked reported only once its audit is recorded, so a
                    // refused audit is retried on the next tick.
                    match self
                        .audit(
                            &guest.name,
                            "lab_orphan_guest",
                            &[
                                ("accountId", guest.account_id.clone()),
                                ("node", guest.node.clone()),
                                ("vmid", guest.vmid.to_string()),
                            ],
                        )
                        .await
                    {
                        Ok(()) => {
                            self.reported()?.insert(key);
                            report.orphans.push(guest);
                        }
                        Err(error) => report.failures.push(format!(
                            "auditing unowned guest {} (VMID {}): {error}",
                            guest.name, guest.vmid
                        )),
                    }
                }
            }
        }

        // 5. Artifact retention. Its own failures never stall the lease
        // steps above; they are reported and retried next tick.
        if let Some(artifacts) = &self.artifacts {
            match artifacts
                .sweep_retention(&fleet_auth::LanAllowAllAuthorizer, &principal, now)
                .await
            {
                Ok(retention) => {
                    report.artifacts_expired = retention.deleted;
                    report.failures.extend(retention.failures);
                }
                Err(error) => report
                    .failures
                    .push(format!("sweeping expired artifacts: {error}")),
            }
        }
        Ok(report)
    }

    /// Announces a committed lease change.
    fn changed(&self) {
        if let Some(events) = &self.events {
            events.publish(fleet_application::events::EventKind::LeaseChanged);
        }
    }

    /// Whether a listed Lab guest is accounted for by Lab state
    /// ([`guest_owned`]). A name that is not a Lab name is not ours to judge.
    fn owned(
        &self,
        guest: &LabGuest,
        records: &HashMap<String, fleet_application::lab::ProvisionRecord>,
        leases: &HashMap<&str, &fleet_core::Lease>,
    ) -> bool {
        let Some(record_id) = guest.name.strip_prefix(LAB_GUEST_PREFIX) else {
            return true;
        };
        let record = records.get(record_id);
        let lease = record
            .and_then(|record| record.lease_id.as_deref())
            .and_then(|id| leases.get(id).copied());
        guest_owned(record, lease, &guest.account_id, guest.vmid)
    }

    /// The orphans already reported by this process.
    fn reported(&self) -> Result<std::sync::MutexGuard<'_, HashSet<(String, u32)>>, String> {
        self.reported
            .lock()
            .map_err(|_| "the orphan set is poisoned".to_owned())
    }

    async fn audit(
        &self,
        resource: &str,
        event: &str,
        facts: &[(&str, String)],
    ) -> Result<(), String> {
        let mut metadata = AuditMetadata::default();
        metadata
            .insert("event", event)
            .map_err(|error| error.to_string())?;
        for (key, value) in facts {
            metadata
                .insert(key, value)
                .map_err(|error| error.to_string())?;
        }
        self.audit
            .record_intent(&AuditIntent {
                actor: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
                action: Permission::LabLease.id().to_owned(),
                resource: Some(resource.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
    }

    /// Ticks every `interval` until `shutdown` resolves. Shutdown also
    /// cancels an in-flight tick (for example one waiting on an unreachable
    /// Proxmox host): every step commits on its own, so a cancelled tick
    /// leaves only committed changes, and the next run resumes from the
    /// rows. A failed tick is logged and retried on the next one. Each tick
    /// transitions lease rows (expiry and compensation), records audit
    /// intents, publishes `lease.changed`, and queues cleanup operations; it
    /// never runs Proxmox work itself, so it never blocks the worker.
    pub async fn run(
        self: Arc<Self>,
        interval: Duration,
        shutdown: impl std::future::Future<Output = ()>,
    ) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                () = tokio::time::sleep(interval) => {}
            }
            let now = fleet_core::SystemClock::now_unix_millis();
            let result = tokio::select! {
                () = &mut shutdown => break,
                result = self.tick(now) => result,
            };
            match result {
                Ok(report) => {
                    for guest in &report.orphans {
                        eprintln!(
                            "lab sweeper: guest {} (VMID {} on {}) has no live Lab owner; it was reported, not deleted",
                            guest.name, guest.vmid, guest.node
                        );
                    }
                    for failure in &report.failures {
                        eprintln!("lab sweeper: {failure}; retrying next tick");
                    }
                }
                Err(error) => eprintln!("lab sweeper: tick failed: {error}"),
            }
        }
    }
}

/// Whether a cleanup operation ended without succeeding while its lease is
/// still `releasing` at the same attempt count. The executor records its
/// own failures on the lease before it completes the operation, so this
/// only holds for an attempt interrupted by a crash.
fn abandoned_attempt(operation: &fleet_application::operation::Operation) -> bool {
    fleet_core::OperationState::from_id(&operation.state)
        .is_ok_and(|state| state.is_terminal() && state != fleet_core::OperationState::Succeeded)
}
