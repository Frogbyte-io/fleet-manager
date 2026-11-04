//! The hardware reconciler (FM-1124, ADR 0019 decision 8, M11): converges
//! the database and Proxmox after crashes and manual changes. It runs once
//! at startup and then periodically from the Lab sweeper.
//!
//! The reconciler **reports** what it does not own and **repairs** only what
//! Fleet itself attached. The rules, in the order they bind:
//!
//! - **Only Fleet's own entry is ever deleted**: the exact `mapping=<id>`
//!   value (the provider deletes only that, and refuses anything else with
//!   `ForeignSlot`) in the slot a reservation recorded, for a row whose
//!   attach Fleet wrote or attempted (`attached`, `detaching`,
//!   `detach_failed`, and `attach_unknown` *with* a slot). An entry on any
//!   other guest, in any other slot, or on a row that only recorded its
//!   attach (`attaching`, or `attach_unknown` with no slot) is never deleted,
//!   never adopted and never claimed: it reaches the inventory (the refresh
//!   marks a device `externally_attached`; an unproven row is
//!   `attach_unknown`, which reads `quarantined`) and an audit finding, and
//!   waits for an operator (`hardware.override-release`).
//! - **A guest that is absent is not proof of detach.** The cluster listing
//!   omits guests the token cannot audit, so a recorded guest the listing
//!   does not show is a finding, never a release. An unreadable guest, a
//!   template, and a pending detach (PVE keeps the device until the guest
//!   restarts) are findings too.
//! - **Never release on a guess, never after an uncertain detach.** A live
//!   row is released only after a read of every `usbN` entry of the guest in
//!   both views shows no reference to the mapping (the row goes through
//!   `detaching` with its slot cleared first, so a crash between the two
//!   steps cannot later make the reconciler delete an entry it cannot show
//!   was Fleet's), or after Fleet deleted its own entry and the read-back
//!   showed none. A failed, refused or pending detach keeps the row.
//! - **A live owner is left alone.** Only rows whose owner is over are
//!   acted on: a lease that is `released`, `cleanup_failed` or `failed`
//!   without a guest, a missing lease, a missing machine. A provision in
//!   flight owns its rows' steps; a releasing lease (or a failed one that
//!   owns a guest) is the lease cleanup's, which retries with backoff and
//!   ends `cleanup_failed`; a ready lease or an existing machine holds its
//!   device. A row touched in the last few minutes is skipped by the
//!   periodic pass (a step may be in flight), not by the startup pass (no
//!   step of this process can be).
//! - **An entry Fleet recorded for a released reservation** (a write that
//!   landed after its row was released and that the saga could not remove)
//!   is removed under the same exact-value rule, when the device has no live
//!   reservation, the guest is listed, and the release is recent. A row
//!   released by an override has its slot cleared and is never examined.
//!
//! Bounded and idempotent: a pass inspects at most [`MAX_ROWS_PER_PASS`]
//! live rows and makes at most [`MAX_GUEST_READS_PER_PASS`] guest reads (a
//! guest read is two config reads), one resource listing per account. A row
//! whose pass changed nothing is not examined again before a doubling
//! backoff (a pass interval up to an hour); a pass that cannot read the
//! store or an account backs the whole pass off the same way. Rows beyond
//! the budget wait for a later pass; nothing loops.
//!
//! Audit events (ids, nodes, VMIDs and slots only; provider detail is
//! scrubbed and bounded; never a secret or a serial), filed under
//! `hardware.refresh` by the controller's principal: `hardware_reconciled`
//! (a row or entry was changed, with the `outcome`),
//! `hardware_reconcile_finding` (something it will not change, once per
//! process per row and finding), `hardware_externally_attached` (a guest
//! Fleet did not attach references a device, once per process per entry),
//! the required `hardware_detach_requested` intent before every delete (a
//! refused sink means no delete), and the store's own `hardware_released`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditMetadata};
use fleet_application::authz::{ActingPrincipal, Decision, Permission};
use fleet_application::hardware::{HardwareStore, HardwareStoreError};
use fleet_application::hardware_inventory::HardwareInventory;
use fleet_application::hardware_reservation::{AuditContext, HardwareReservations};
use fleet_application::operation::AuditPort;
use fleet_application::proxmox::{ProxmoxAccountPort, ProxmoxCredentialStore};
use fleet_core::{
    DeviceStatus, GuestTarget, HardwareDevice, HardwareReservation, HardwareReservationState,
    LeaseState, ReservationOwnerKind,
};
use fleet_provider_proxmox::usb_attach::{PveUsbError, PveUsbState};
use fleet_provider_proxmox::{ProxmoxClient, PveHttpRequest};
use sqlx::Row as _;

use HardwareReservationState as State;

/// The gap between periodic passes, in milliseconds.
pub const PASS_INTERVAL_MS: i64 = 300_000;

/// The longest backoff for a pass or a row, in milliseconds.
pub const MAX_BACKOFF_MS: i64 = 3_600_000;

/// How recently a row must have changed for the periodic pass to skip it (a
/// saga step may be running), in milliseconds.
pub const FRESH_ROW_MS: i64 = 300_000;

/// How often an account with devices is refreshed, in milliseconds. It stays
/// under the inventory's observation bound (15 minutes), so devices do not
/// read as stale between two refreshes.
pub const REFRESH_INTERVAL_MS: i64 = 600_000;

/// The most live rows one pass inspects.
pub const MAX_ROWS_PER_PASS: usize = 256;

/// The most guests one pass reads (each is two config reads).
pub const MAX_GUEST_READS_PER_PASS: usize = 32;

/// How long after its release a row that recorded a slot is still examined
/// for a leftover entry, in milliseconds.
pub const RELEASED_LOOKBACK_MS: i64 = 86_400_000;

/// The most recently released rows one pass considers.
pub const MAX_RELEASED_PER_PASS: usize = 64;

/// The longest provider detail kept in an audit fact.
const MAX_DETAIL_CHARS: usize = 240;

// ── the pure rules ──────────────────────────────────────────────────────

/// Who owns a reservation's next move.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerStanding {
    /// A provision is in flight: a saga step may be running.
    Provisioning,
    /// The owner is live and holds the device (a ready lease, a machine).
    Live,
    /// A lease cleanup owns it (releasing, or failed with a guest): it
    /// retries with backoff and ends `cleanup_failed`.
    CleanupOwns,
    /// The owner is over: nothing else will detach or release the row.
    Ended,
}

impl OwnerStanding {
    /// The standing of a lease in `state`; `has_guest` is whether its
    /// provision allocated a guest.
    #[must_use]
    pub const fn of_lease(state: LeaseState, has_guest: bool) -> Self {
        match state {
            LeaseState::Requested
            | LeaseState::Queued
            | LeaseState::Reserving
            | LeaseState::Provisioning
            | LeaseState::Booting
            | LeaseState::Bootstrapping => Self::Provisioning,
            LeaseState::Ready => Self::Live,
            LeaseState::Releasing => Self::CleanupOwns,
            LeaseState::Failed if has_guest => Self::CleanupOwns,
            LeaseState::Failed | LeaseState::Released | LeaseState::CleanupFailed => Self::Ended,
        }
    }
}

/// What a read of the recorded guest showed about the device's mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestView {
    /// No read was needed or made.
    NotRead,
    /// The pass's read budget was spent; the row waits for a later pass.
    Deferred,
    /// The cluster listing does not show the guest.
    Absent,
    /// The guest, or one of its two config views, could not be read.
    Unreadable(String),
    /// The VMID is a template now.
    Template,
    /// Every `usbN` slot that references the mapping, in either view.
    Refs(Vec<String>),
}

/// Something the reconciler sees and will not change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Finding {
    /// The recorded guest is not in the cluster listing.
    GuestAbsent,
    /// The guest could not be read in full.
    GuestUnreadable,
    /// The VMID is a template.
    TemplateGuest,
    /// The guest references the mapping and nothing shows Fleet wrote it.
    UnprovenEntry,
    /// The guest references the mapping somewhere other than the recorded
    /// slot, or in more than one slot.
    AmbiguousEntry,
    /// PVE keeps the device until the guest restarts.
    DetachPending,
    /// The delete was refused, failed, or could not be confirmed.
    DetachFailed,
    /// The row's own record contradicts itself (no guest to read).
    InconsistentRow,
    /// The row's device is not in the inventory.
    DeviceUnknown,
}

impl Finding {
    /// The stable id recorded in the audit event.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::GuestAbsent => "guest_absent",
            Self::GuestUnreadable => "guest_unreadable",
            Self::TemplateGuest => "template_guest",
            Self::UnprovenEntry => "unproven_entry",
            Self::AmbiguousEntry => "ambiguous_entry",
            Self::DetachPending => "detach_pending",
            Self::DetachFailed => "detach_failed",
            Self::InconsistentRow => "inconsistent_row",
            Self::DeviceUnknown => "device_unknown",
        }
    }
}

/// What to do with one live row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Plan {
    /// Not the reconciler's: a step, a cleanup or a live owner has it.
    NotMine,
    /// Release a hold that never attached.
    ReleaseHeld,
    /// The guest shows no reference: release through `detaching`.
    ReleaseAbsent,
    /// An attach that only recorded itself meets an entry nothing proves
    /// Fleet wrote: `attach_unknown`, no slot.
    MarkUnproven,
    /// Delete Fleet's own entry in the recorded slot, confirm, release.
    RemoveEntry {
        /// The recorded slot.
        slot: u8,
    },
    /// Report and leave.
    Report(Finding),
}

/// The slot name for an index.
fn slot_name(index: u8) -> String {
    format!("usb{index}")
}

/// Whether deciding the row needs a read of the recorded guest.
#[must_use]
pub const fn needs_guest(state: State, standing: OwnerStanding) -> bool {
    matches!(standing, OwnerStanding::Ended) && !matches!(state, State::Held | State::Released)
}

/// The decision table: what to do with a live row given its owner and what
/// a read of its recorded guest showed. Pure, so it is tested as a table.
#[must_use]
pub fn plan(
    state: State,
    recorded_slot: Option<u8>,
    has_guest: bool,
    standing: OwnerStanding,
    guest: &GuestView,
) -> Plan {
    if standing != OwnerStanding::Ended || state == State::Released {
        return Plan::NotMine;
    }
    if state == State::Held {
        // A hold that recorded a slot is not a hold that never attached.
        return if recorded_slot.is_some() {
            Plan::Report(Finding::InconsistentRow)
        } else {
            Plan::ReleaseHeld
        };
    }
    if !has_guest {
        return Plan::Report(Finding::InconsistentRow);
    }
    match guest {
        GuestView::NotRead | GuestView::Deferred => Plan::Report(Finding::InconsistentRow),
        GuestView::Absent => Plan::Report(Finding::GuestAbsent),
        GuestView::Unreadable(_) => Plan::Report(Finding::GuestUnreadable),
        GuestView::Template => Plan::Report(Finding::TemplateGuest),
        GuestView::Refs(slots) if slots.is_empty() => Plan::ReleaseAbsent,
        GuestView::Refs(slots) => match state {
            State::Attaching => Plan::MarkUnproven,
            State::AttachUnknown | State::Attached | State::Detaching | State::DetachFailed => {
                match recorded_slot {
                    Some(slot) if slots.len() == 1 && slots[0] == slot_name(slot) => {
                        Plan::RemoveEntry { slot }
                    }
                    Some(_) => Plan::Report(Finding::AmbiguousEntry),
                    None => Plan::Report(Finding::UnprovenEntry),
                }
            }
            State::Held | State::Released => Plan::NotMine,
        },
    }
}

/// The next backoff after `attempts` unchanged looks, in milliseconds.
#[must_use]
pub fn backoff_ms(attempts: u32) -> i64 {
    let shift = attempts.min(16);
    PASS_INTERVAL_MS
        .saturating_mul(1_i64 << shift)
        .min(MAX_BACKOFF_MS)
}

// ── the records the reconciler reads ────────────────────────────────────

/// A released reservation that recorded a guest and slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasedSlot {
    /// The reservation.
    pub reservation: HardwareReservation,
}

/// What the reconciler reads beyond the hardware store port: whether an
/// owner still counts, and the recently released rows.
#[async_trait]
pub trait ReconcilerRecords: std::fmt::Debug + Send + Sync {
    /// The standing of an owner. An unknown lease or machine is `Ended`.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn standing(
        &self,
        kind: ReservationOwnerKind,
        owner_id: &str,
    ) -> Result<OwnerStanding, String>;

    /// Rows released at or after `since` that recorded a guest and slot,
    /// newest first, at most `limit`.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn released_with_slot(
        &self,
        since: i64,
        limit: usize,
    ) -> Result<Vec<ReleasedSlot>, String>;
}

/// [`ReconcilerRecords`] over the controller's SQLite pool.
#[derive(Clone, Debug)]
pub struct SqliteReconcilerRecords {
    pool: sqlx::SqlitePool,
}

impl SqliteReconcilerRecords {
    /// Over the controller's pool.
    #[must_use]
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ReconcilerRecords for SqliteReconcilerRecords {
    async fn standing(
        &self,
        kind: ReservationOwnerKind,
        owner_id: &str,
    ) -> Result<OwnerStanding, String> {
        match kind {
            ReservationOwnerKind::Lease => {
                let row = sqlx::query(
                    "SELECT l.state AS state, p.vmid IS NOT NULL AS has_guest \
                     FROM lab_leases l LEFT JOIN lab_provisions p ON p.id = l.provision_id \
                     WHERE l.id = ?1",
                )
                .bind(owner_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| format!("the lease could not be read: {error}"))?;
                let Some(row) = row else {
                    return Ok(OwnerStanding::Ended);
                };
                let state: String = row.get("state");
                let state = LeaseState::from_id(&state)?;
                Ok(OwnerStanding::of_lease(state, row.get("has_guest")))
            }
            ReservationOwnerKind::Machine => {
                let exists = sqlx::query_scalar::<_, i64>("SELECT 1 FROM machines WHERE id = ?1")
                    .bind(owner_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|error| format!("the machine could not be read: {error}"))?
                    .is_some();
                Ok(if exists {
                    OwnerStanding::Live
                } else {
                    OwnerStanding::Ended
                })
            }
        }
    }

    async fn released_with_slot(
        &self,
        since: i64,
        limit: usize,
    ) -> Result<Vec<ReleasedSlot>, String> {
        let rows = sqlx::query(
            "SELECT id, device_id, owner_kind, owner_id, guest_account, guest_node, guest_vmid, \
             usb_slot, created_at, updated_at, released_at \
             FROM hardware_reservations \
             WHERE state = 'released' AND usb_slot IS NOT NULL AND guest_vmid IS NOT NULL \
             AND released_at >= ?1 ORDER BY released_at DESC LIMIT ?2",
        )
        .bind(since)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("the released reservations could not be read: {error}"))?;
        rows.iter()
            .map(|row| {
                let owner_kind: String = row.get("owner_kind");
                let vmid: i64 = row.get("guest_vmid");
                let slot: i64 = row.get("usb_slot");
                Ok(ReleasedSlot {
                    reservation: HardwareReservation {
                        id: row.get("id"),
                        device_id: row.get("device_id"),
                        owner_kind: ReservationOwnerKind::from_id(&owner_kind)?,
                        owner_id: row.get("owner_id"),
                        state: State::Released,
                        guest: Some(GuestTarget {
                            account_id: row.get("guest_account"),
                            node: row.get("guest_node"),
                            vmid: u32::try_from(vmid)
                                .map_err(|_| "a stored VMID is out of range".to_owned())?,
                            usb_slot: Some(
                                u8::try_from(slot)
                                    .map_err(|_| "a stored slot is out of range".to_owned())?,
                            ),
                        }),
                        created_at: row.get("created_at"),
                        updated_at: row.get("updated_at"),
                        released_at: row.get("released_at"),
                    },
                })
            })
            .collect()
    }
}

// ── the reconciler ──────────────────────────────────────────────────────

/// What one pass did.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReconcileReport {
    /// Whether this was the startup pass.
    pub startup: bool,
    /// Live rows inspected.
    pub rows_seen: usize,
    /// Rows not examined: not the reconciler's, fresh, or backing off.
    pub skipped: usize,
    /// Rows left for a later pass because the read budget was spent.
    pub deferred: usize,
    /// Guests read.
    pub guest_reads: usize,
    /// Reservations released.
    pub released: usize,
    /// `usbN` entries Fleet deleted (its own, from live rows and leftovers).
    pub entries_removed: usize,
    /// Rows moved to `attach_unknown` because an entry could not be proven.
    pub marked_unproven: usize,
    /// Findings newly reported this pass.
    pub findings: usize,
    /// Accounts whose inventory was refreshed.
    pub accounts_refreshed: usize,
    /// Failures that were retried later (the rest of the pass still ran).
    pub failures: Vec<String>,
    /// Whether the pass could not do its work at all (a store or account
    /// list that cannot be read): the next pass backs off.
    pub pass_failed: bool,
}

/// What looking at a row came to, for its backoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    /// The row changed or was finished: look again at the next pass.
    Progress,
    /// Nothing changed: back off.
    Unchanged,
}

#[derive(Debug, Default)]
struct RowMemory {
    attempts: u32,
    next_try_at: i64,
    last_examined: i64,
}

#[derive(Debug, Default)]
struct RefreshMemory {
    last_ok: i64,
    failures: u32,
    next_try_at: i64,
}

#[derive(Debug, Default)]
struct Inner {
    next_pass_at: i64,
    pass_failures: u32,
    rows: HashMap<String, RowMemory>,
    refreshes: HashMap<String, RefreshMemory>,
    reported: HashSet<(String, &'static str)>,
    external: HashMap<String, HashSet<String>>,
    released_checked: HashSet<String>,
}

/// What one pass may still read.
struct Budget {
    left: usize,
    reads: usize,
}

/// A live row with its device.
struct Row {
    reservation: HardwareReservation,
    device: HardwareDevice,
}

/// The per-account reads one pass shares.
struct AccountRun {
    request: Result<PveHttpRequest, String>,
    resources: Option<Result<HashMap<u32, String>, String>>,
}

/// The hardware reconciler.
#[derive(Debug)]
pub struct HardwareReconciler {
    accounts: Arc<dyn ProxmoxAccountPort>,
    credentials: Arc<dyn ProxmoxCredentialStore>,
    client: ProxmoxClient,
    store: Arc<dyn HardwareStore>,
    reservations: Arc<HardwareReservations>,
    inventory: Arc<HardwareInventory>,
    audit: Arc<dyn AuditPort>,
    records: Arc<dyn ReconcilerRecords>,
    inner: Mutex<Inner>,
    running: tokio::sync::Mutex<()>,
}

fn bounded(text: &str) -> String {
    let scrubbed = fleet_core::scrub_failure_detail(text);
    if scrubbed.chars().count() <= MAX_DETAIL_CHARS {
        scrubbed
    } else {
        let mut cut: String = scrubbed.chars().take(MAX_DETAIL_CHARS).collect();
        cut.push('…');
        cut
    }
}

impl HardwareReconciler {
    /// Composes the reconciler over the Proxmox account, the hardware store,
    /// the reservation use cases and the inventory it refreshes.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        accounts: Arc<dyn ProxmoxAccountPort>,
        credentials: Arc<dyn ProxmoxCredentialStore>,
        client: ProxmoxClient,
        store: Arc<dyn HardwareStore>,
        reservations: Arc<HardwareReservations>,
        inventory: Arc<HardwareInventory>,
        audit: Arc<dyn AuditPort>,
        records: Arc<dyn ReconcilerRecords>,
    ) -> Self {
        Self {
            accounts,
            credentials,
            client,
            store,
            reservations,
            inventory,
            audit,
            records,
            inner: Mutex::new(Inner::default()),
            running: tokio::sync::Mutex::new(()),
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock only ever holds memory of what was looked at; the
        // rows themselves are the truth.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The startup pass: runs at once, whatever the schedule, and does not
    /// skip recently changed rows (no step of this process can be running).
    pub async fn startup(&self, now: i64) -> ReconcileReport {
        let _guard = self.running.lock().await;
        self.run(now, true).await
    }

    /// The periodic pass: runs when one is due (the interval, or the
    /// backoff after a failed pass) and answers `None` when it is not or
    /// when another pass is running.
    pub async fn tick(&self, now: i64) -> Option<ReconcileReport> {
        if now < self.inner().next_pass_at {
            return None;
        }
        let _guard = self.running.try_lock().ok()?;
        Some(self.run(now, false).await)
    }

    async fn run(&self, now: i64, startup: bool) -> ReconcileReport {
        let report = self.pass(now, startup).await;
        let mut inner = self.inner();
        if report.pass_failed {
            inner.pass_failures = inner.pass_failures.saturating_add(1);
            inner.next_pass_at = now.saturating_add(backoff_ms(inner.pass_failures));
        } else {
            inner.pass_failures = 0;
            inner.next_pass_at = now.saturating_add(PASS_INTERVAL_MS);
        }
        report
    }

    // ── one pass ─────────────────────────────────────────────────────────

    #[allow(clippy::too_many_lines)]
    async fn pass(&self, now: i64, startup: bool) -> ReconcileReport {
        let mut report = ReconcileReport {
            startup,
            ..ReconcileReport::default()
        };
        let live = match self.store.list_live_reservations().await {
            Ok(live) => live,
            Err(error) => {
                report.pass_failed = true;
                report
                    .failures
                    .push(format!("the live reservations are unreadable: {error}"));
                return report;
            }
        };
        let accounts = match self.accounts.list().await {
            Ok(accounts) => accounts,
            Err(detail) => {
                report.pass_failed = true;
                report
                    .failures
                    .push(format!("the accounts are unreadable: {detail}"));
                return report;
            }
        };
        {
            // Memory of rows that are no longer live is dropped, so it stays
            // bounded by what exists.
            let ids: HashSet<&str> = live.iter().map(|row| row.id.as_str()).collect();
            let mut inner = self.inner();
            inner.rows.retain(|id, _| ids.contains(id.as_str()));
            inner.reported.retain(|(id, _)| ids.contains(id.as_str()));
            if inner.released_checked.len() > 4 * MAX_RELEASED_PER_PASS {
                inner.released_checked.clear();
            }
        }
        let released = match self
            .records
            .released_with_slot(
                now.saturating_sub(RELEASED_LOOKBACK_MS),
                MAX_RELEASED_PER_PASS,
            )
            .await
        {
            Ok(released) => released,
            Err(detail) => {
                report.failures.push(detail);
                Vec::new()
            }
        };
        let fresh_ms = if startup { 0 } else { FRESH_ROW_MS };
        let mut budget = Budget {
            left: MAX_GUEST_READS_PER_PASS,
            reads: 0,
        };
        let mut unplaced: Vec<&HardwareReservation> = live.iter().collect();
        unplaced.truncate(MAX_ROWS_PER_PASS);
        for account in accounts {
            // The explicit-trust gate: an unconfirmed host is never sent the
            // token.
            if account.fingerprint.is_none() {
                continue;
            }
            let devices = match self.store.list_devices(&account.id).await {
                Ok(devices) => devices,
                Err(error) => {
                    report.pass_failed = true;
                    report.failures.push(format!(
                        "the devices of account {} are unreadable: {error}",
                        account.id
                    ));
                    continue;
                }
            };
            if devices.is_empty() {
                continue;
            }
            let by_device: HashMap<&str, &HardwareDevice> = devices
                .iter()
                .map(|device| (device.id.as_str(), device))
                .collect();
            let mut rows = Vec::new();
            unplaced.retain(
                |reservation| match by_device.get(reservation.device_id.as_str()) {
                    Some(device) => {
                        rows.push(Row {
                            reservation: (*reservation).clone(),
                            device: (*device).clone(),
                        });
                        false
                    }
                    None => true,
                },
            );
            let mut leftovers = Vec::new();
            for row in &released {
                if let Some(device) = by_device.get(row.reservation.device_id.as_str()) {
                    leftovers.push(Row {
                        reservation: row.reservation.clone(),
                        device: (*device).clone(),
                    });
                }
            }
            let mut run = AccountRun {
                request: self.request(&account.id).await,
                resources: None,
            };
            let mut changed = false;
            self.reconcile_rows(
                &mut run,
                rows,
                now,
                fresh_ms,
                startup,
                &mut budget,
                &mut report,
                &mut changed,
            )
            .await;
            self.reconcile_leftovers(
                &mut run,
                leftovers,
                now,
                fresh_ms,
                startup,
                &mut budget,
                &mut report,
                &mut changed,
            )
            .await;
            self.refresh_account(&account.id, now, startup, changed, &mut report)
                .await;
        }
        report.guest_reads = budget.reads;
        // Rows whose device no account lists (the account was deleted).
        for reservation in unplaced {
            if self
                .note_finding(&reservation.id, Finding::DeviceUnknown)
                .is_some()
            {
                report.findings += 1;
                let mut metadata = Self::metadata("hardware_reconcile_finding", startup);
                let _ = metadata.insert("reservation_id", &reservation.id);
                let _ = metadata.insert("finding", Finding::DeviceUnknown.id());
                let _ = metadata.insert("device_id", &reservation.device_id);
                let _ = self.record(&reservation.device_id, metadata).await;
            }
        }
        report
    }

    #[allow(clippy::too_many_arguments)]
    async fn reconcile_rows(
        &self,
        run: &mut AccountRun,
        mut rows: Vec<Row>,
        now: i64,
        fresh_ms: i64,
        startup: bool,
        budget: &mut Budget,
        report: &mut ReconcileReport,
        changed: &mut bool,
    ) {
        // Rows never looked at first, then the least recently looked at.
        {
            let inner = self.inner();
            rows.sort_by_key(|row| {
                (
                    inner
                        .rows
                        .get(&row.reservation.id)
                        .map_or(i64::MIN, |memory| memory.last_examined),
                    row.reservation.created_at,
                )
            });
        }
        for row in rows {
            report.rows_seen += 1;
            let id = row.reservation.id.clone();
            let backing_off = self
                .inner()
                .rows
                .get(&id)
                .is_some_and(|memory| memory.next_try_at > now);
            if backing_off || now.saturating_sub(row.reservation.updated_at) < fresh_ms {
                report.skipped += 1;
                continue;
            }
            let standing = match self
                .records
                .standing(row.reservation.owner_kind, &row.reservation.owner_id)
                .await
            {
                Ok(standing) => standing,
                Err(detail) => {
                    report.failures.push(format!("reservation {id}: {detail}"));
                    continue;
                }
            };
            let state = row.reservation.state;
            let slot = row
                .reservation
                .guest
                .as_ref()
                .and_then(|guest| guest.usb_slot);
            let has_guest = row.reservation.guest.is_some();
            let view = if needs_guest(state, standing) && has_guest {
                self.view_of(run, &row, budget).await
            } else {
                GuestView::NotRead
            };
            if view == GuestView::Deferred {
                report.deferred += 1;
                continue;
            }
            let decision = plan(state, slot, has_guest, standing, &view);
            if decision == Plan::NotMine {
                report.skipped += 1;
                continue;
            }
            let outcome = self
                .execute(run, &row, decision, &view, now, startup, report, changed)
                .await;
            let mut inner = self.inner();
            let memory = inner.rows.entry(id).or_default();
            memory.last_examined = now;
            match outcome {
                Outcome::Progress => {
                    memory.attempts = 0;
                    memory.next_try_at = 0;
                }
                Outcome::Unchanged => {
                    memory.attempts = memory.attempts.saturating_add(1);
                    memory.next_try_at = now.saturating_add(backoff_ms(memory.attempts));
                }
            }
        }
    }

    // ── reads ────────────────────────────────────────────────────────────

    async fn request(&self, account_id: &str) -> Result<PveHttpRequest, String> {
        let account = self
            .accounts
            .get(account_id)
            .await
            .map_err(|detail| format!("the account is unreadable: {detail}"))?;
        if account.fingerprint.is_none() {
            return Err(format!(
                "the account {} has no confirmed fingerprint",
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

    /// The node the cluster lists the guest on, once per account and pass.
    async fn node_of(&self, run: &mut AccountRun, vmid: u32) -> Result<Option<String>, String> {
        let request = run.request.clone()?;
        if run.resources.is_none() {
            let listed = self
                .client
                .list_guest_resources(PveHttpRequest {
                    path: "/api2/json/cluster/resources".to_owned(),
                    ..request
                })
                .await
                .map(|resources| {
                    resources
                        .into_iter()
                        .filter(|resource| resource.kind == "qemu")
                        .filter_map(|resource| Some((resource.vmid?, resource.node?)))
                        .collect::<HashMap<u32, String>>()
                })
                .map_err(|error| {
                    bounded(&format!("the cluster's guest list is unreadable: {error}"))
                });
            run.resources = Some(listed);
        }
        match run.resources.as_ref() {
            Some(Ok(nodes)) => Ok(nodes.get(&vmid).cloned()),
            Some(Err(detail)) => Err(detail.clone()),
            None => Err("the guest list was not read".to_owned()),
        }
    }

    /// Reads the row's recorded guest: every `usbN` entry in both views that
    /// references the device's mapping.
    async fn view_of(&self, run: &mut AccountRun, row: &Row, budget: &mut Budget) -> GuestView {
        let Some(target) = &row.reservation.guest else {
            return GuestView::NotRead;
        };
        self.view_at(run, target.vmid, &row.device.mapping_id, Some(budget))
            .await
    }

    /// Reads one guest. With a budget the read is metered (a guest the
    /// cluster does not list costs nothing: no config is read for it);
    /// without one it is the confirmation read of a delete just made.
    async fn view_at(
        &self,
        run: &mut AccountRun,
        vmid: u32,
        mapping: &str,
        budget: Option<&mut Budget>,
    ) -> GuestView {
        let node = match self.node_of(run, vmid).await {
            Ok(Some(node)) => node,
            Ok(None) => return GuestView::Absent,
            Err(detail) => return GuestView::Unreadable(detail),
        };
        if let Some(budget) = budget {
            if budget.left == 0 {
                return GuestView::Deferred;
            }
            budget.left -= 1;
            budget.reads += 1;
        }
        let Ok(request) = run.request.clone() else {
            return GuestView::Unreadable("the account's token is unavailable".to_owned());
        };
        match self
            .client
            .qemu_usb_references(request, &node, vmid, true)
            .await
        {
            Err(error) => GuestView::Unreadable(bounded(&error.to_string())),
            Ok(read) => {
                if let Some(detail) = read.applied_unread {
                    return GuestView::Unreadable(bounded(&format!(
                        "the running configuration is unreadable: {detail}"
                    )));
                }
                if read.template {
                    return GuestView::Template;
                }
                let slots: BTreeSet<String> = read
                    .references
                    .into_iter()
                    .filter(|reference| reference.mapping_id == mapping)
                    .map(|reference| reference.slot)
                    .collect();
                GuestView::Refs(slots.into_iter().collect())
            }
        }
    }

    // ── audit ────────────────────────────────────────────────────────────

    fn metadata(event: &str, startup: bool) -> AuditMetadata {
        let mut metadata = AuditMetadata::default();
        let _ = metadata.insert("event", event);
        let _ = metadata.insert("pass", if startup { "startup" } else { "periodic" });
        metadata
    }

    async fn record(&self, device_id: &str, metadata: AuditMetadata) -> Result<(), String> {
        self.audit
            .record_intent(&AuditIntent {
                actor: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
                action: Permission::HardwareRefresh.id().to_owned(),
                resource: Some(device_id.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
    }

    /// An event about one row: ids, states, nodes and slots only.
    async fn event(
        &self,
        name: &str,
        startup: bool,
        row: &Row,
        facts: &[(&str, String)],
    ) -> Result<(), String> {
        let reservation = &row.reservation;
        let mut metadata = Self::metadata(name, startup);
        let _ = metadata.insert("reservation_id", &reservation.id);
        let _ = metadata.insert("owner_kind", reservation.owner_kind.id());
        let _ = metadata.insert("owner_id", &reservation.owner_id);
        let _ = metadata.insert("mapping", &row.device.mapping_id);
        let _ = metadata.insert("from_state", reservation.state.id());
        if let Some(guest) = &reservation.guest {
            let _ = metadata.insert("node", &guest.node);
            let _ = metadata.insert("guest_vmid", &guest.vmid.to_string());
            if let Some(slot) = guest.usb_slot {
                let _ = metadata.insert("usb_slot", &slot_name(slot));
            }
        }
        for (key, value) in facts {
            let _ = metadata.insert(key, value);
        }
        self.record(&row.device.id, metadata).await
    }

    /// Whether a finding is new to this process (and so reported).
    fn note_finding(&self, reservation_id: &str, finding: Finding) -> Option<()> {
        self.inner()
            .reported
            .insert((reservation_id.to_owned(), finding.id()))
            .then_some(())
    }

    async fn finding(
        &self,
        startup: bool,
        row: &Row,
        finding: Finding,
        detail: Option<&str>,
        report: &mut ReconcileReport,
    ) {
        if self.note_finding(&row.reservation.id, finding).is_none() {
            return;
        }
        report.findings += 1;
        let mut facts = vec![("finding", finding.id().to_owned())];
        if let Some(detail) = detail {
            facts.push(("detail", bounded(detail)));
        }
        if self
            .event("hardware_reconcile_finding", startup, row, &facts)
            .await
            .is_err()
        {
            // Reported again at the next look instead of being lost.
            self.inner()
                .reported
                .remove(&(row.reservation.id.clone(), finding.id()));
        }
    }

    async fn reconciled(&self, startup: bool, row: &Row, outcome: &str, facts: &[(&str, String)]) {
        let mut all = vec![("outcome", outcome.to_owned())];
        all.extend(facts.iter().cloned());
        // Best effort: the row is the truth and the repair is done.
        let _ = self.event("hardware_reconciled", startup, row, &all).await;
    }

    fn context() -> AuditContext {
        AuditContext {
            actor: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
            operation_id: None,
        }
    }

    // ── repairs ──────────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    async fn execute(
        &self,
        run: &mut AccountRun,
        row: &Row,
        decision: Plan,
        view: &GuestView,
        now: i64,
        startup: bool,
        report: &mut ReconcileReport,
        changed: &mut bool,
    ) -> Outcome {
        let id = row.reservation.id.clone();
        let result = match decision {
            Plan::NotMine => return Outcome::Unchanged,
            Plan::Report(finding) => {
                let detail = match view {
                    GuestView::Unreadable(detail) => Some(detail.as_str()),
                    _ => None,
                };
                self.finding(startup, row, finding, detail, report).await;
                return Outcome::Unchanged;
            }
            Plan::ReleaseHeld => self
                .release(row, now)
                .await
                .map(|()| ("released_owner_finished", Vec::new())),
            Plan::ReleaseAbsent => self.release_absent(row, now).await,
            Plan::MarkUnproven => self.mark_unproven(row, now).await,
            Plan::RemoveEntry { slot } => {
                return self
                    .remove_entry(run, row, slot, now, startup, report, changed)
                    .await;
            }
        };
        match result {
            Ok((outcome, facts)) => {
                *changed = true;
                match outcome {
                    "marked_attach_unknown" => {
                        report.marked_unproven += 1;
                        self.finding(startup, row, Finding::UnprovenEntry, None, report)
                            .await;
                    }
                    _ => report.released += 1,
                }
                self.reconciled(startup, row, outcome, &facts).await;
                Outcome::Progress
            }
            Err(error) => self.moved_or_failed(&id, &error, report),
        }
    }

    /// A refused move means another writer moved the row first (the lease's
    /// own cleanup, a saga step): not a failure, looked at again later.
    fn moved_or_failed(
        &self,
        id: &str,
        error: &HardwareStoreError,
        report: &mut ReconcileReport,
    ) -> Outcome {
        if !matches!(error, HardwareStoreError::IllegalTransition { .. }) {
            report.failures.push(format!("reservation {id}: {error}"));
        }
        Outcome::Unchanged
    }

    async fn release(&self, row: &Row, now: i64) -> Result<(), HardwareStoreError> {
        self.reservations
            .release(&Self::context(), &row.reservation.id, now)
            .await
            .map(|_| ())
    }

    /// The target the row records, with its slot cleared and the node the
    /// cluster lists now.
    fn target_without_slot(row: &Row) -> Option<GuestTarget> {
        row.reservation.guest.as_ref().map(|guest| GuestTarget {
            account_id: guest.account_id.clone(),
            node: guest.node.clone(),
            vmid: guest.vmid,
            usb_slot: None,
        })
    }

    /// The guest shows no reference to the mapping in either view: release
    /// through `detaching` with the slot cleared first.
    async fn release_absent(
        &self,
        row: &Row,
        now: i64,
    ) -> Result<(&'static str, Vec<(&'static str, String)>), HardwareStoreError> {
        if row.reservation.state != State::Detaching {
            self.store
                .transition_reservation(
                    &row.reservation.id,
                    row.reservation.state,
                    State::Detaching,
                    Self::target_without_slot(row).as_ref(),
                    now,
                )
                .await?;
        }
        self.release(row, now).await?;
        Ok((
            "released_confirmed_absent",
            vec![("confirmed_absent", "true".to_owned())],
        ))
    }

    /// An attach that only recorded itself meets an entry nothing proves
    /// Fleet wrote: `attach_unknown` with no slot, which cleanup and the
    /// reconciler never delete for.
    async fn mark_unproven(
        &self,
        row: &Row,
        now: i64,
    ) -> Result<(&'static str, Vec<(&'static str, String)>), HardwareStoreError> {
        self.store
            .transition_reservation(
                &row.reservation.id,
                State::Attaching,
                State::AttachUnknown,
                Self::target_without_slot(row).as_ref(),
                now,
            )
            .await?;
        Ok(("marked_attach_unknown", Vec::new()))
    }

    /// Deletes Fleet's own entry in the recorded slot of a live row, behind
    /// the required audit intent, confirms by a full read, and releases.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn remove_entry(
        &self,
        run: &mut AccountRun,
        row: &Row,
        slot: u8,
        now: i64,
        startup: bool,
        report: &mut ReconcileReport,
        changed: &mut bool,
    ) -> Outcome {
        let id = row.reservation.id.clone();
        let Some(recorded) = row.reservation.guest.clone() else {
            return Outcome::Unchanged;
        };
        let node = match self.node_of(run, recorded.vmid).await {
            Ok(Some(node)) => node,
            _ => return Outcome::Unchanged,
        };
        let Ok(request) = run.request.clone() else {
            return Outcome::Unchanged;
        };
        let slot_text = slot_name(slot);
        let mapping = row.device.mapping_id.as_str();
        let target = GuestTarget {
            account_id: recorded.account_id.clone(),
            node: node.clone(),
            vmid: recorded.vmid,
            usb_slot: Some(slot),
        };
        let detaching = if row.reservation.state == State::Detaching {
            row.reservation.clone()
        } else {
            match self
                .store
                .transition_reservation(
                    &id,
                    row.reservation.state,
                    State::Detaching,
                    Some(&target),
                    now,
                )
                .await
            {
                Ok(moved) => moved,
                Err(error) => return self.moved_or_failed(&id, &error, report),
            }
        };
        *changed = true;
        let row = Row {
            reservation: detaching,
            device: row.device.clone(),
        };
        // The intent is required: a delete the audit sink refused is not
        // made, and the row says the detach did not happen.
        let intent = [
            ("node", node.clone()),
            ("guest_vmid", recorded.vmid.to_string()),
            ("usb_slot", slot_text.clone()),
        ];
        if let Err(detail) = self
            .event("hardware_detach_requested", startup, &row, &intent)
            .await
        {
            report.failures.push(format!(
                "reservation {id}: the detach audit failed, so nothing was deleted: {}",
                bounded(&detail)
            ));
            self.detach_failed(
                &row,
                now,
                startup,
                report,
                "the audit sink refused the intent",
            )
            .await;
            return Outcome::Unchanged;
        }
        let detach = self
            .client
            .qemu_usb_detach(request, &node, recorded.vmid, &slot_text, mapping)
            .await;
        match detach {
            Ok(done) if done.state == PveUsbState::Applied => {
                match self.view_at(run, recorded.vmid, mapping, None).await {
                    GuestView::Refs(slots) if slots.is_empty() => {
                        report.entries_removed += 1;
                        match self.release(&row, now).await {
                            Ok(()) => {
                                // Released after a delete and a confirming
                                // read: nothing is left to look for.
                                self.inner().released_checked.insert(id.clone());
                                report.released += 1;
                                self.reconciled(
                                    startup,
                                    &row,
                                    "entry_removed_and_released",
                                    &[("usb_slot", slot_text)],
                                )
                                .await;
                                Outcome::Progress
                            }
                            Err(error) => self.moved_or_failed(&id, &error, report),
                        }
                    }
                    GuestView::Refs(slots) => {
                        let detail = format!(
                            "the guest still references the mapping in {}",
                            slots.join(", ")
                        );
                        self.detach_failed(&row, now, startup, report, &detail)
                            .await;
                        Outcome::Unchanged
                    }
                    other => {
                        let detail = format!("the detach could not be confirmed ({other:?})");
                        self.detach_failed(&row, now, startup, report, &detail)
                            .await;
                        Outcome::Unchanged
                    }
                }
            }
            Ok(_) => {
                // PVE keeps the device until the guest restarts: the row
                // stays `detaching`, never released.
                self.finding(startup, &row, Finding::DetachPending, None, report)
                    .await;
                Outcome::Unchanged
            }
            Err(error) => {
                let detail = match &error {
                    PveUsbError::ForeignSlot { .. } => {
                        "the slot holds something other than the exact entry Fleet writes; it was left untouched".to_owned()
                    }
                    other => other.to_string(),
                };
                self.detach_failed(&row, now, startup, report, &detail)
                    .await;
                Outcome::Unchanged
            }
        }
    }

    /// The delete failed or could not be confirmed: `detach_failed`, which
    /// reads `quarantined`, and a finding.
    async fn detach_failed(
        &self,
        row: &Row,
        now: i64,
        startup: bool,
        report: &mut ReconcileReport,
        detail: &str,
    ) {
        let failed = match self
            .store
            .transition_reservation(
                &row.reservation.id,
                State::Detaching,
                State::DetachFailed,
                None,
                now,
            )
            .await
        {
            Ok(failed) => failed,
            Err(_) => row.reservation.clone(),
        };
        let row = Row {
            reservation: failed,
            device: row.device.clone(),
        };
        self.finding(startup, &row, Finding::DetachFailed, Some(detail), report)
            .await;
    }

    // ── entries recorded for a released reservation ──────────────────────

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn reconcile_leftovers(
        &self,
        run: &mut AccountRun,
        rows: Vec<Row>,
        now: i64,
        fresh_ms: i64,
        startup: bool,
        budget: &mut Budget,
        report: &mut ReconcileReport,
        changed: &mut bool,
    ) {
        for row in rows {
            let id = row.reservation.id.clone();
            let Some(recorded) = row.reservation.guest.clone() else {
                continue;
            };
            let Some(slot) = recorded.usb_slot else {
                continue;
            };
            let released_at = row.reservation.released_at.unwrap_or(now);
            let (checked, backing_off) = {
                let inner = self.inner();
                (
                    inner.released_checked.contains(&id),
                    inner
                        .rows
                        .get(&id)
                        .is_some_and(|memory| memory.next_try_at > now),
                )
            };
            if checked || backing_off || now.saturating_sub(released_at) < fresh_ms {
                continue;
            }
            // A device someone holds now is that holder's to account for.
            match self.store.live_reservation_for_device(&row.device.id).await {
                Ok(None) => {}
                Ok(Some(_)) => {
                    self.inner().released_checked.insert(id);
                    continue;
                }
                Err(error) => {
                    report.failures.push(format!("reservation {id}: {error}"));
                    continue;
                }
            }
            let view = self
                .view_at(
                    run,
                    recorded.vmid,
                    &row.device.mapping_id,
                    Some(&mut *budget),
                )
                .await;
            let slot_text = slot_name(slot);
            match view {
                GuestView::Deferred => report.deferred += 1,
                GuestView::Refs(slots) if slots.len() == 1 && slots[0] == slot_text => {
                    self.remove_leftover(run, &row, slot, now, startup, report, changed)
                        .await;
                }
                GuestView::Unreadable(_) => {
                    let mut inner = self.inner();
                    let memory = inner.rows.entry(id).or_default();
                    memory.attempts = memory.attempts.saturating_add(1);
                    memory.next_try_at = now.saturating_add(backoff_ms(memory.attempts));
                }
                // No entry, an entry elsewhere (not what the row recorded),
                // a template, or a guest the cluster does not list: nothing
                // this row can claim. Not looked at again by this process.
                _ => {
                    self.inner().released_checked.insert(id);
                }
            }
        }
    }

    /// Deletes the exact entry a released row recorded, which nothing holds.
    #[allow(clippy::too_many_arguments)]
    async fn remove_leftover(
        &self,
        run: &mut AccountRun,
        row: &Row,
        slot: u8,
        now: i64,
        startup: bool,
        report: &mut ReconcileReport,
        changed: &mut bool,
    ) {
        let id = row.reservation.id.clone();
        let Some(recorded) = row.reservation.guest.clone() else {
            return;
        };
        let Ok(Some(node)) = self.node_of(run, recorded.vmid).await else {
            return;
        };
        let Ok(request) = run.request.clone() else {
            return;
        };
        let slot_text = slot_name(slot);
        let mapping = row.device.mapping_id.as_str();
        let intent = [
            ("node", node.clone()),
            ("guest_vmid", recorded.vmid.to_string()),
            ("usb_slot", slot_text.clone()),
            ("leftover", "true".to_owned()),
        ];
        if let Err(detail) = self
            .event("hardware_detach_requested", startup, row, &intent)
            .await
        {
            report.failures.push(format!(
                "released reservation {id}: the detach audit failed, so nothing was deleted: {}",
                bounded(&detail)
            ));
            self.back_off(&id, now);
            return;
        }
        let outcome = match self
            .client
            .qemu_usb_detach(request, &node, recorded.vmid, &slot_text, mapping)
            .await
        {
            Ok(done) if done.state == PveUsbState::Applied => {
                *changed = true;
                report.entries_removed += 1;
                self.inner().released_checked.insert(id);
                "leftover_removed"
            }
            Ok(_) => {
                self.back_off(&id, now);
                "leftover_pending"
            }
            Err(_) => {
                self.back_off(&id, now);
                "leftover_unremoved"
            }
        };
        self.reconciled(startup, row, outcome, &[("leftover", "true".to_owned())])
            .await;
    }

    fn back_off(&self, id: &str, now: i64) {
        let mut inner = self.inner();
        let memory = inner.rows.entry(id.to_owned()).or_default();
        memory.attempts = memory.attempts.saturating_add(1);
        memory.next_try_at = now.saturating_add(backoff_ms(memory.attempts));
    }

    // ── the inventory ────────────────────────────────────────────────────

    /// Refreshes the account's inventory so the findings reach the device
    /// status: an unreferenced device is `available`, a device a guest Fleet
    /// did not attach it to is `externally_attached`, an unknown or failed
    /// row reads `quarantined`. Done the first time this process sees the
    /// account (so after a restart), when the pass changed something, and
    /// when the last refresh is older than [`REFRESH_INTERVAL_MS`].
    async fn refresh_account(
        &self,
        account_id: &str,
        now: i64,
        startup: bool,
        changed: bool,
        report: &mut ReconcileReport,
    ) {
        let due = {
            let inner = self.inner();
            match inner.refreshes.get(account_id) {
                None => true,
                Some(memory) => {
                    memory.next_try_at <= now
                        && (changed || now.saturating_sub(memory.last_ok) >= REFRESH_INTERVAL_MS)
                }
            }
        };
        if !due {
            return;
        }
        let refreshed = self
            .inventory
            .refresh(
                &fleet_auth::LanAllowAllAuthorizer,
                &ActingPrincipal {
                    id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
                },
                None,
                account_id,
            )
            .await;
        match refreshed {
            Ok(refreshed) => {
                {
                    let mut inner = self.inner();
                    let memory = inner.refreshes.entry(account_id.to_owned()).or_default();
                    memory.last_ok = now;
                    memory.failures = 0;
                    memory.next_try_at = 0;
                }
                report.accounts_refreshed += 1;
                self.report_external(account_id, startup, &refreshed, report)
                    .await;
            }
            Err(error) => {
                let mut inner = self.inner();
                let memory = inner.refreshes.entry(account_id.to_owned()).or_default();
                memory.failures = memory.failures.saturating_add(1);
                memory.next_try_at = now.saturating_add(backoff_ms(memory.failures));
                report.failures.push(format!(
                    "the inventory of account {account_id} could not be refreshed: {}",
                    bounded(&error.to_string())
                ));
            }
        }
    }

    /// Reports each guest entry for a device Fleet did not attach it to,
    /// once per process: a device nobody holds is `externally_attached`; a
    /// device Fleet holds that another guest also references is a conflict.
    async fn report_external(
        &self,
        account_id: &str,
        startup: bool,
        refreshed: &fleet_application::hardware_inventory::RefreshReport,
        report: &mut ReconcileReport,
    ) {
        let mut current: HashSet<String> = HashSet::new();
        let mut fresh: Vec<(String, BTreeMap<&'static str, String>)> = Vec::new();
        for device in &refreshed.devices {
            let held = device.view.holder.is_some();
            for reference in device
                .external_references
                .iter()
                .filter(|reference| !reference.template)
            {
                let key = format!(
                    "{}/{}/{}/{}",
                    device.view.device.id, reference.node, reference.vmid, reference.slot
                );
                current.insert(key.clone());
                let kind = if held {
                    "hardware_reconcile_finding"
                } else if device.view.status == DeviceStatus::ExternallyAttached {
                    "hardware_externally_attached"
                } else {
                    continue;
                };
                let mut facts = BTreeMap::new();
                facts.insert("event", kind.to_owned());
                facts.insert("device_id", device.view.device.id.clone());
                facts.insert("mapping", device.view.device.mapping_id.clone());
                facts.insert("node", reference.node.clone());
                facts.insert("guest_vmid", reference.vmid.to_string());
                facts.insert("usb_slot", reference.slot.clone());
                if let Some(pending) = reference.pending {
                    facts.insert("pending", pending.id().to_owned());
                }
                if let Some(holder) = &device.view.holder {
                    facts.insert("finding", "foreign_reference_to_held_device".to_owned());
                    facts.insert("reservation_id", holder.id.clone());
                }
                fresh.push((key, facts));
            }
        }
        let new: Vec<(String, BTreeMap<&'static str, String>)> = {
            let mut inner = self.inner();
            let seen = inner.external.entry(account_id.to_owned()).or_default();
            seen.retain(|key| current.contains(key));
            fresh
                .into_iter()
                .filter(|(key, _)| seen.insert(key.clone()))
                .collect()
        };
        for (key, facts) in new {
            let mut metadata = Self::metadata(
                facts
                    .get("event")
                    .map_or("hardware_externally_attached", String::as_str),
                startup,
            );
            let device_id = facts.get("device_id").cloned().unwrap_or_default();
            for (name, value) in &facts {
                if *name != "event" {
                    let _ = metadata.insert(name, value);
                }
            }
            if self.record(&device_id, metadata).await.is_ok() {
                report.findings += 1;
            } else if let Some(seen) = self.inner().external.get_mut(account_id) {
                // Reported again at the next refresh instead of being lost.
                seen.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use GuestView::{Absent, NotRead, Refs, Template, Unreadable};
    use OwnerStanding::{CleanupOwns, Ended, Live, Provisioning};

    fn refs(slots: &[&str]) -> GuestView {
        Refs(slots.iter().map(|slot| (*slot).to_owned()).collect())
    }

    /// (state, recorded slot, owner, what the guest showed, the plan).
    #[allow(clippy::type_complexity)]
    fn table() -> Vec<(State, Option<u8>, OwnerStanding, GuestView, Plan)> {
        use Finding as F;
        use Plan as P;
        use State::{AttachUnknown, Attached, Attaching, DetachFailed, Detaching, Held};
        let mut rows = Vec::new();
        // A live or in-flight owner is never the reconciler's, whatever the
        // guest shows.
        for state in [
            Held,
            Attaching,
            Attached,
            Detaching,
            AttachUnknown,
            DetachFailed,
        ] {
            for standing in [Provisioning, Live, CleanupOwns] {
                for guest in [NotRead, Absent, refs(&[]), refs(&["usb0"])] {
                    rows.push((state, Some(0), standing, guest, P::NotMine));
                }
            }
        }
        // A hold that never attached, its owner over: released on the
        // owner's word, with no guest read.
        rows.push((Held, None, Ended, NotRead, P::ReleaseHeld));
        rows.push((Held, Some(1), Ended, NotRead, P::Report(F::InconsistentRow)));
        // The guest shows nothing in either view: released, whatever state
        // the attach or detach was left in.
        for state in [Attaching, Attached, Detaching, AttachUnknown, DetachFailed] {
            for slot in [None, Some(2)] {
                rows.push((state, slot, Ended, refs(&[]), P::ReleaseAbsent));
            }
        }
        // An entry in exactly the recorded slot, for a row whose attach
        // Fleet wrote or attempted: Fleet's own, removed.
        for state in [Attached, Detaching, DetachFailed, AttachUnknown] {
            rows.push((
                state,
                Some(2),
                Ended,
                refs(&["usb2"]),
                P::RemoveEntry { slot: 2 },
            ));
            // Anywhere else, or in more than one slot: not provably the one
            // Fleet wrote.
            rows.push((
                state,
                Some(2),
                Ended,
                refs(&["usb3"]),
                P::Report(F::AmbiguousEntry),
            ));
            rows.push((
                state,
                Some(2),
                Ended,
                refs(&["usb2", "usb3"]),
                P::Report(F::AmbiguousEntry),
            ));
            // No slot recorded: nothing shows the entry is Fleet's.
            rows.push((
                state,
                None,
                Ended,
                refs(&["usb2"]),
                P::Report(F::UnprovenEntry),
            ));
        }
        // An attach that only recorded itself proves nothing about an entry.
        rows.push((Attaching, Some(0), Ended, refs(&["usb0"]), P::MarkUnproven));
        rows.push((Attaching, None, Ended, refs(&["usb4"]), P::MarkUnproven));
        // A guest that cannot be judged is never released.
        for state in [Attaching, Attached, Detaching, AttachUnknown, DetachFailed] {
            rows.push((state, Some(1), Ended, Absent, P::Report(F::GuestAbsent)));
            rows.push((
                state,
                Some(1),
                Ended,
                Unreadable("500".to_owned()),
                P::Report(F::GuestUnreadable),
            ));
            rows.push((state, Some(1), Ended, Template, P::Report(F::TemplateGuest)));
            rows.push((
                state,
                Some(1),
                Ended,
                NotRead,
                P::Report(F::InconsistentRow),
            ));
        }
        rows
    }

    #[test]
    fn the_decision_table_holds() {
        for (state, slot, standing, guest, expected) in table() {
            assert_eq!(
                plan(state, slot, true, standing, &guest),
                expected,
                "{} slot {slot:?} {standing:?} {guest:?}",
                state.id()
            );
        }
    }

    #[test]
    fn a_row_with_no_recorded_guest_is_a_finding_not_a_guess() {
        for state in [
            State::Attaching,
            State::Attached,
            State::Detaching,
            State::AttachUnknown,
            State::DetachFailed,
        ] {
            assert_eq!(
                plan(state, None, false, Ended, &NotRead),
                Plan::Report(Finding::InconsistentRow),
                "{}",
                state.id()
            );
        }
    }

    #[test]
    fn nothing_is_released_unless_the_guest_showed_no_reference() {
        // The invariant behind the table: a plan that releases or deletes
        // exists only for a held row or a full read that supports it.
        for state in State::ALL {
            for guest in [
                NotRead,
                Absent,
                Unreadable("x".to_owned()),
                Template,
                refs(&["usb0"]),
                refs(&["usb0", "usb1"]),
            ] {
                let decided = plan(state, Some(0), true, Ended, &guest);
                assert!(
                    !matches!(decided, Plan::ReleaseAbsent),
                    "{} {guest:?}: released on a guess",
                    state.id()
                );
                if state != State::Held && !matches!(guest, GuestView::Refs(_)) {
                    assert!(
                        matches!(decided, Plan::Report(_) | Plan::NotMine),
                        "{} {guest:?}: {decided:?}",
                        state.id()
                    );
                }
            }
        }
    }

    #[test]
    fn only_an_ended_owner_with_an_attempted_attach_needs_a_guest_read() {
        for state in State::ALL {
            for standing in [Provisioning, Live, CleanupOwns, Ended] {
                assert_eq!(
                    needs_guest(state, standing),
                    standing == Ended && !matches!(state, State::Held | State::Released),
                    "{} {standing:?}",
                    state.id()
                );
            }
        }
    }

    #[test]
    fn lease_states_map_to_who_owns_the_next_move() {
        for (state, has_guest, expected) in [
            (LeaseState::Requested, false, Provisioning),
            (LeaseState::Queued, false, Provisioning),
            (LeaseState::Reserving, false, Provisioning),
            (LeaseState::Provisioning, true, Provisioning),
            (LeaseState::Booting, true, Provisioning),
            (LeaseState::Bootstrapping, true, Provisioning),
            (LeaseState::Ready, true, Live),
            (LeaseState::Releasing, true, CleanupOwns),
            (LeaseState::Failed, true, CleanupOwns),
            (LeaseState::Failed, false, Ended),
            (LeaseState::Released, true, Ended),
            (LeaseState::Released, false, Ended),
            (LeaseState::CleanupFailed, true, Ended),
        ] {
            assert_eq!(
                OwnerStanding::of_lease(state, has_guest),
                expected,
                "{} guest={has_guest}",
                state.id()
            );
        }
    }

    #[test]
    fn backoff_doubles_and_is_bounded() {
        assert_eq!(backoff_ms(0), PASS_INTERVAL_MS);
        assert_eq!(backoff_ms(1), 2 * PASS_INTERVAL_MS);
        assert_eq!(backoff_ms(2), 4 * PASS_INTERVAL_MS);
        assert_eq!(backoff_ms(40), MAX_BACKOFF_MS);
        assert_eq!(backoff_ms(u32::MAX), MAX_BACKOFF_MS);
    }
}
