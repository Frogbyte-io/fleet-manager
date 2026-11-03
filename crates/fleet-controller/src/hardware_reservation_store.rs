//! The transactional hardware reservation store (FM-1120, ADR 0019
//! decision 2).
//!
//! Every operation is one `BEGIN IMMEDIATE` transaction, so the read of the
//! device and its live holder and the insert cannot interleave with another
//! reservation; the partial unique index over live reservations stays the
//! last line of defence, not the first. The store never calls Proxmox.
//!
//! The rules (what refuses, what may be released) live in
//! `fleet_application::hardware_reservation`; this adapter runs them against
//! the `hardware_*` tables and, for a lease owner, the lease's own state,
//! which is authoritative exactly as for capacity reservations (FM-715,
//! `lab_placement`): a row whose lease is released, or failed without an
//! allocated guest, no longer counts. Only a hold that never started an
//! attach is released on that authority. A row that attached, or whose
//! attach or detach outcome is unknown, is never released on the owner's
//! word (ADR 0019 forbids releasing after a failed or uncertain detach).

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteRow;
use uuid::Uuid;

use fleet_application::hardware::HardwareStoreError;
use fleet_application::hardware_reservation::{
    HardwareReservationPort, ReleaseCause, ReleaseOutcome, ReleasedReservation, ReserveDecision,
    ReserveOutcome, ReserveRefusal, ReserveRequest, device_allocatable, releasable_by_flow,
    releasable_when_owner_finished,
};
use fleet_core::{
    DeviceStatus, GuestTarget, HardwareReservation, HardwareReservationState, ReservationOwnerKind,
};

type Tx<'a> = sqlx::Transaction<'a, sqlx::Sqlite>;

macro_rules! select_reservation {
    ($tail:literal) => {
        concat!(
            "SELECT id, device_id, owner_kind, owner_id, state, guest_account, guest_node, \
             guest_vmid, usb_slot, created_at, updated_at, released_at \
             FROM hardware_reservations ",
            $tail
        )
    };
}

/// The reservation store over the controller's SQLite pool.
#[derive(Debug)]
pub struct SqliteHardwareReservations {
    pool: SqlitePool,
}

impl SqliteHardwareReservations {
    /// Creates the store over the controller's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    async fn begin(&self, context: &str) -> Result<Tx<'static>, HardwareStoreError> {
        self.pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| backend(context, &error))
    }
}

fn backend(context: &str, error: &impl std::fmt::Display) -> HardwareStoreError {
    HardwareStoreError::Backend(format!("{context} failed: {error}"))
}

#[allow(clippy::needless_pass_by_value)] // used directly as a `map_err` function
fn corrupt(message: String) -> HardwareStoreError {
    HardwareStoreError::Backend(format!("stored hardware record is invalid: {message}"))
}

fn row_to_reservation(row: &SqliteRow) -> Result<HardwareReservation, HardwareStoreError> {
    let owner_kind: String = row.get("owner_kind");
    let state: String = row.get("state");
    let guest = match row.get::<Option<i64>, _>("guest_vmid") {
        None => None,
        Some(vmid) => Some(GuestTarget {
            account_id: row
                .get::<Option<String>, _>("guest_account")
                .ok_or_else(|| corrupt("a guest without an account".to_owned()))?,
            node: row
                .get::<Option<String>, _>("guest_node")
                .ok_or_else(|| corrupt("a guest without a node".to_owned()))?,
            vmid: u32::try_from(vmid).map_err(|_| corrupt("vmid out of range".to_owned()))?,
            usb_slot: row
                .get::<Option<i64>, _>("usb_slot")
                .map(|slot| u8::try_from(slot).map_err(|_| corrupt("slot out of range".into())))
                .transpose()?,
        }),
    };
    Ok(HardwareReservation {
        id: row.get("id"),
        device_id: row.get("device_id"),
        owner_kind: ReservationOwnerKind::from_id(&owner_kind).map_err(corrupt)?,
        owner_id: row.get("owner_id"),
        state: HardwareReservationState::from_id(&state).map_err(corrupt)?,
        guest,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        released_at: row.get("released_at"),
    })
}

fn slot_recorded(reservation: &HardwareReservation) -> bool {
    reservation
        .guest
        .as_ref()
        .is_some_and(|guest| guest.usb_slot.is_some())
}

async fn load_reservation(
    tx: &mut Tx<'_>,
    id: &str,
) -> Result<Option<HardwareReservation>, HardwareStoreError> {
    sqlx::query(select_reservation!("WHERE id = ?1"))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| backend("read hardware reservation", &error))?
        .as_ref()
        .map(row_to_reservation)
        .transpose()
}

async fn live_for_device(
    tx: &mut Tx<'_>,
    device_id: &str,
) -> Result<Option<HardwareReservation>, HardwareStoreError> {
    sqlx::query(select_reservation!(
        "WHERE device_id = ?1 AND state <> 'released'"
    ))
    .bind(device_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| backend("read the device's live reservation", &error))?
    .as_ref()
    .map(row_to_reservation)
    .transpose()
}

async fn device_status(
    tx: &mut Tx<'_>,
    device_id: &str,
) -> Result<Option<DeviceStatus>, HardwareStoreError> {
    sqlx::query("SELECT status, unsupported_reason FROM hardware_devices WHERE id = ?1")
        .bind(device_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| backend("read hardware device", &error))?
        .map(|row| {
            let status: String = row.get("status");
            let reason: Option<String> = row.get("unsupported_reason");
            DeviceStatus::from_parts(&status, reason.as_deref()).map_err(corrupt)
        })
        .transpose()
}

/// Whether the owner still counts. For a lease this is the FM-715 rule
/// (`lab_placement`): the lease exists, is not `released`, and has not
/// `failed` without an allocated VMID. A machine counts while it exists
/// (a machine's reservation is released by an explicit detach, and the
/// machine cannot be removed while one is held).
async fn owner_counts(
    tx: &mut Tx<'_>,
    kind: ReservationOwnerKind,
    owner_id: &str,
) -> Result<bool, HardwareStoreError> {
    let counts = match kind {
        ReservationOwnerKind::Lease => sqlx::query_scalar::<_, bool>(
            "SELECT l.state != 'released' AND NOT (l.state = 'failed' AND p.vmid IS NULL) \
             FROM lab_leases l LEFT JOIN lab_provisions p ON p.id = l.provision_id \
             WHERE l.id = ?1",
        )
        .bind(owner_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| backend("read the reservation's lease", &error))?
        .unwrap_or(false),
        ReservationOwnerKind::Machine => {
            sqlx::query_scalar::<_, i64>("SELECT 1 FROM machines WHERE id = ?1")
                .bind(owner_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|error| backend("read the reservation's machine", &error))?
                .is_some()
        }
    };
    Ok(counts)
}

/// Marks a live row released and returns it with the row as it was. The
/// device's derived `reserved` status goes back to `available`; any other
/// status (a quarantine, say) is left for the refresh or reconciler that
/// owns it.
async fn release_row(
    tx: &mut Tx<'_>,
    previous: HardwareReservation,
    cause: ReleaseCause,
    now: i64,
) -> Result<ReleasedReservation, HardwareStoreError> {
    // The override discards the slot because it never confirmed the
    // detach; a flow release keeps the guest and slot as history.
    let clear_slot = cause == ReleaseCause::Override;
    let done = sqlx::query(
        "UPDATE hardware_reservations SET state = 'released', updated_at = ?3, released_at = ?3, \
         usb_slot = CASE WHEN ?4 THEN NULL ELSE usb_slot END \
         WHERE id = ?1 AND state = ?2",
    )
    .bind(&previous.id)
    .bind(previous.state.id())
    .bind(now)
    .bind(clear_slot)
    .execute(&mut **tx)
    .await
    .map_err(|error| backend("release hardware reservation", &error))?;
    if done.rows_affected() == 0 {
        return Err(HardwareStoreError::Backend(
            "the reservation changed while it was released".to_owned(),
        ));
    }
    sqlx::query(
        "UPDATE hardware_devices SET status = 'available', updated_at = ?2 \
         WHERE id = ?1 AND status = 'reserved'",
    )
    .bind(&previous.device_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|error| backend("free the released device", &error))?;
    let current = load_reservation(tx, &previous.id)
        .await?
        .ok_or(HardwareStoreError::NotFound)?;
    Ok(ReleasedReservation {
        previous,
        current,
        cause,
    })
}

/// The reserve rules, inside the caller's transaction. Rows released on the
/// way are pushed to `released` even when the decision is a refusal: the
/// correction is committed regardless.
async fn reserve_in(
    tx: &mut Tx<'_>,
    request: &ReserveRequest,
    now: i64,
    released: &mut Vec<ReleasedReservation>,
) -> Result<ReserveDecision, HardwareStoreError> {
    if device_status(tx, &request.device_id).await?.is_none() {
        return Ok(ReserveDecision::Refused(ReserveRefusal::DeviceUnknown));
    }
    let requester_counts = owner_counts(tx, request.owner_kind, &request.owner_id).await?;
    if let Some(live) = live_for_device(tx, &request.device_id).await? {
        let same_owner = live.owner_kind == request.owner_kind && live.owner_id == request.owner_id;
        if same_owner && requester_counts {
            // A repeat (a retried step, a restart): the existing row,
            // whatever state the saga has taken it to.
            return Ok(ReserveDecision::Reserved {
                reservation: live,
                created: false,
            });
        }
        let holder_counts = if same_owner {
            requester_counts
        } else {
            owner_counts(tx, live.owner_kind, &live.owner_id).await?
        };
        if !holder_counts && releasable_when_owner_finished(live.state, slot_recorded(&live)) {
            released.push(release_row(tx, live, ReleaseCause::OwnerFinished, now).await?);
        } else if same_owner {
            // The requester's own row, which no longer counts, is past
            // releasing on its word; it is not a new grant either.
            return Ok(ReserveDecision::Refused(ReserveRefusal::OwnerFinished {
                owner_kind: request.owner_kind,
                owner_id: request.owner_id.clone(),
            }));
        } else {
            return Ok(ReserveDecision::Refused(ReserveRefusal::Busy {
                holder: Box::new(live),
            }));
        }
    }
    // The device is free of live holders. A finished owner reserves nothing.
    if !requester_counts {
        return Ok(ReserveDecision::Refused(ReserveRefusal::OwnerFinished {
            owner_kind: request.owner_kind,
            owner_id: request.owner_id.clone(),
        }));
    }
    let status = device_status(tx, &request.device_id)
        .await?
        .ok_or(HardwareStoreError::NotFound)?;
    if !device_allocatable(status) {
        return Ok(ReserveDecision::Refused(ReserveRefusal::NotAllocatable {
            status,
        }));
    }
    let id = Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO hardware_reservations \
         (id, device_id, owner_kind, owner_id, state, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, 'held', ?5, ?5)",
    )
    .bind(&id)
    .bind(&request.device_id)
    .bind(request.owner_kind.id())
    .bind(&request.owner_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|error| backend("insert hardware reservation", &error))?;
    sqlx::query("UPDATE hardware_devices SET status = 'reserved', updated_at = ?2 WHERE id = ?1")
        .bind(&request.device_id)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|error| backend("mark the device reserved", &error))?;
    let reservation = load_reservation(tx, &id)
        .await?
        .ok_or(HardwareStoreError::NotFound)?;
    Ok(ReserveDecision::Reserved {
        reservation,
        created: true,
    })
}

#[async_trait]
impl HardwareReservationPort for SqliteHardwareReservations {
    async fn reserve(
        &self,
        request: &ReserveRequest,
        now: i64,
    ) -> Result<ReserveOutcome, HardwareStoreError> {
        let mut tx = self.begin("begin hardware reservation").await?;
        let mut released = Vec::new();
        let decision = reserve_in(&mut tx, request, now, &mut released).await?;
        // Commit refusals too: a stale row released on the way stays
        // released, and nothing else was written.
        tx.commit()
            .await
            .map_err(|error| backend("commit hardware reservation", &error))?;
        Ok(ReserveOutcome { decision, released })
    }

    async fn release(&self, id: &str, now: i64) -> Result<ReleaseOutcome, HardwareStoreError> {
        let mut tx = self.begin("begin hardware release").await?;
        let current = load_reservation(&mut tx, id)
            .await?
            .ok_or(HardwareStoreError::NotFound)?;
        if current.state == HardwareReservationState::Released {
            return Ok(ReleaseOutcome::AlreadyReleased(current));
        }
        if !releasable_by_flow(current.state, slot_recorded(&current)) {
            return Err(HardwareStoreError::IllegalTransition {
                from: current.state,
                to: HardwareReservationState::Released,
                actual: current.state,
            });
        }
        let released = release_row(&mut tx, current, ReleaseCause::Completed, now).await?;
        tx.commit()
            .await
            .map_err(|error| backend("commit hardware release", &error))?;
        Ok(ReleaseOutcome::Released(released))
    }

    async fn override_release(
        &self,
        id: &str,
        now: i64,
    ) -> Result<ReleasedReservation, HardwareStoreError> {
        let mut tx = self.begin("begin hardware override release").await?;
        let current = load_reservation(&mut tx, id)
            .await?
            .ok_or(HardwareStoreError::NotFound)?;
        if !current.state.is_live() {
            return Err(HardwareStoreError::IllegalTransition {
                from: current.state,
                to: HardwareReservationState::Released,
                actual: current.state,
            });
        }
        let released = release_row(&mut tx, current, ReleaseCause::Override, now).await?;
        tx.commit()
            .await
            .map_err(|error| backend("commit hardware override release", &error))?;
        Ok(released)
    }
}
