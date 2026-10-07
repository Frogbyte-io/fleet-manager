//! The Lab sweeper (FM-716): the controller's background loop that keeps
//! Lab leases converging without an operator, across restarts. Every tick:
//!
//! 1. expires `ready` leases past their TTL into `releasing` (FM-711's
//!    compare-and-set claim);
//! 2. queues the `lab.cleanup` of every `releasing` lease whose next attempt
//!    is due (FM-713). That covers backoff retries, and a release or
//!    compensation whose enqueue was lost after the lease committed;
//! 3. compensates leases stuck in provisioning past their readiness deadline
//!    (or their maximum lifetime): a lease owning a guest is moved to
//!    cleanup, one that never allocated a guest is failed;
//! 4. reconciles the Fleet-named Lab guests (`fm-lab-<record>`) on every
//!    trusted Proxmox account against the Lab records, and reports, once
//!    per guest, any that no live lease or provision owns. It never deletes
//!    a guest it cannot attribute.
//!
//! Every deadline and attempt lives in the rows, so a restarted controller
//! picks up exactly where the last one stopped.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleet_application::audit::{AuditIntent, AuditMetadata};
use fleet_application::authz::{Decision, Permission};
use fleet_application::lab::{
    Lab, LeasePort, ProvisionPort, cleanup_due, cleanup_operation, provision_compensation,
};
use fleet_application::operation::{AuditPort, Operations};
use fleet_core::LeaseState;

/// How long past its readiness deadline an in-flight lease may stay before
/// the sweeper compensates it: the provision executor enforces the deadline
/// itself, so this only catches a provision that stopped running.
pub const STUCK_GRACE_MILLIS: i64 = 10 * 60 * 1000;

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
    /// Stuck leases compensated.
    pub compensated: usize,
    /// Guests newly reported as unowned this tick.
    pub orphans: Vec<LabGuest>,
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

    /// Runs one tick at `now`.
    ///
    /// # Errors
    ///
    /// Fails when the lease or provision store cannot be read; a tick that
    /// fails part-way leaves every change it made committed.
    pub async fn tick(&self, now: i64) -> Result<TickReport, String> {
        let principal = fleet_application::authz::ActingPrincipal {
            id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        };
        // 1. Expiry.
        let expired = self
            .lab
            .sweep_expired(&fleet_auth::LanAllowAllAuthorizer, &principal, now)
            .await
            .map_err(|error| error.to_string())?
            .len();
        let mut report = TickReport {
            expired,
            ..TickReport::default()
        };

        // 3 before 2, so a compensated lease is queued in the same tick.
        let leases = self.leases.list(None).await?;
        for mut lease in leases.clone() {
            if !matches!(
                lease.state,
                LeaseState::Provisioning | LeaseState::Booting | LeaseState::Bootstrapping
            ) {
                continue;
            }
            let record = match &lease.provision_id {
                Some(id) => Some(self.provisions.get(id).await?),
                None => None,
            };
            let deadline = record
                .as_ref()
                .and_then(|record| record.readiness_deadline_at)
                .map(|deadline| deadline.saturating_add(STUCK_GRACE_MILLIS));
            let stuck =
                deadline.is_some_and(|deadline| deadline < now) || lease.max_lifetime_at < now;
            if !stuck {
                continue;
            }
            let allocated = record.as_ref().is_some_and(|record| record.vmid.is_some());
            if let Some(state) = provision_compensation(lease.state, allocated) {
                lease.state = state;
                self.leases.update(&lease).await?;
                self.audit(
                    &lease.id,
                    "lab_lease_stuck_compensated",
                    &[("to", state.id().to_owned())],
                )
                .await;
                report.compensated += 1;
            }
        }

        // 2. Due cleanups (re-read: steps 1 and 3 changed states). The
        // create is idempotent per attempt, so only an operation created
        // during this tick counts as newly queued.
        let tick_started = fleet_core::SystemClock::now_unix_millis();
        for lease in self.leases.list(None).await? {
            if !cleanup_due(&lease, now) {
                continue;
            }
            if let Ok(operation) = self
                .operations
                .create_lab_cleanup(
                    &fleet_auth::LanAllowAllAuthorizer,
                    fleet_auth::LAN_PRINCIPAL_ID,
                    &lease.id,
                    &cleanup_operation(&lease, None),
                )
                .await
                && operation.created_at >= tick_started
            {
                report.cleanups_queued += 1;
            }
        }

        // 4. Orphans.
        if let Some(inventory) = &self.inventory {
            for guest in inventory.lab_guests().await {
                if !self.owned(&guest).await? {
                    let fresh = self
                        .reported
                        .lock()
                        .map_err(|_| "the orphan set is poisoned".to_owned())?
                        .insert((guest.account_id.clone(), guest.vmid));
                    if fresh {
                        self.audit(
                            &guest.name,
                            "lab_orphan_guest",
                            &[
                                ("accountId", guest.account_id.clone()),
                                ("node", guest.node.clone()),
                                ("vmid", guest.vmid.to_string()),
                            ],
                        )
                        .await;
                        report.orphans.push(guest);
                    }
                }
            }
        }

        if report.expired + report.compensated + report.cleanups_queued > 0
            && let Some(events) = &self.events
        {
            events.publish(fleet_application::events::EventKind::LeaseChanged);
        }
        Ok(report)
    }

    /// Whether a Lab guest is accounted for: its provision record exists,
    /// and either it is a standalone provision, its lease still owns it
    /// (any state but released or failed), or the lease was released with
    /// `keep`.
    async fn owned(&self, guest: &LabGuest) -> Result<bool, String> {
        let Some(record_id) = guest.name.strip_prefix(LAB_GUEST_PREFIX) else {
            return Ok(true);
        };
        let Ok(record) = self.provisions.get(record_id).await else {
            return Ok(false);
        };
        if record.vmid != Some(guest.vmid) {
            return Ok(false);
        }
        let Some(lease_id) = record.lease_id else {
            return Ok(true);
        };
        let lease = self.leases.get(&lease_id).await?;
        Ok(match lease.state {
            LeaseState::Released => lease.cleanup == fleet_core::CleanupStrategy::Keep,
            LeaseState::Failed => false,
            _ => true,
        })
    }

    async fn audit(&self, resource: &str, event: &str, facts: &[(&str, String)]) {
        let mut metadata = AuditMetadata::default();
        let _ = metadata.insert("event", event);
        for (key, value) in facts {
            let _ = metadata.insert(key, value);
        }
        let _ = self
            .audit
            .record_intent(&AuditIntent {
                actor: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
                action: Permission::LabLease.id().to_owned(),
                resource: Some(resource.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await;
    }

    /// Ticks every `interval` until `shutdown` resolves. A failed tick is
    /// logged and retried on the next one; the loop never blocks the worker
    /// (it only reads rows and queues operations).
    pub async fn run(
        self: Arc<Self>,
        interval: Duration,
        shutdown: impl std::future::Future<Output = ()>,
    ) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                () = tokio::time::sleep(interval) => {
                    let now = fleet_core::SystemClock::now_unix_millis();
                    match self.tick(now).await {
                        Ok(report) if !report.orphans.is_empty() => {
                            for guest in &report.orphans {
                                eprintln!(
                                    "lab sweeper: guest {} (VMID {} on {}) has no live Lab owner; it was reported, not deleted",
                                    guest.name, guest.vmid, guest.node
                                );
                            }
                        }
                        Ok(_) => {}
                        Err(error) => eprintln!("lab sweeper: tick failed: {error}"),
                    }
                }
            }
        }
    }
}
