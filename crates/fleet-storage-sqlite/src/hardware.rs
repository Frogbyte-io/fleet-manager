//! The hardware repository (FM-1101, ADR 0019): device inventory and
//! exclusive reservations. The partial unique index on live reservations
//! is the arbiter of a double hold; the state machine lives in
//! `fleet-core` and every transition is a compare-and-set on the stored
//! state.

use async_trait::async_trait;
use sqlx::Row as _;
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteRow;

use fleet_application::hardware::{
    DeviceObservation, HardwareStore, HardwareStoreError, NewHardwareReservation,
};
use fleet_core::{
    DeviceNodeEntry, DeviceStatus, GuestTarget, HardwareDevice, HardwareKind, HardwareReservation,
    HardwareReservationState, ReservationOwnerKind,
};

/// The hardware repository over a pool.
#[derive(Debug)]
pub struct HardwareRepository {
    pool: SqlitePool,
}

macro_rules! select_reservations {
    ($($tail:literal),*) => {
        concat!(
            "SELECT id, device_id, owner_kind, owner_id, state, guest_account, guest_node, \
             guest_vmid, usb_slot, created_at, updated_at, released_at \
             FROM hardware_reservations ",
            $($tail),*
        )
    };
}

fn backend(context: &str, error: &impl std::fmt::Display) -> HardwareStoreError {
    HardwareStoreError::Backend(format!("{context} failed: {error}"))
}

#[allow(clippy::needless_pass_by_value)] // used directly as a `map_err` function
fn corrupt(message: String) -> HardwareStoreError {
    HardwareStoreError::Backend(format!("stored hardware record is invalid: {message}"))
}

#[allow(clippy::needless_pass_by_value)]
fn is_violation(error: &sqlx::Error, wanted: sqlx::error::ErrorKind) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.kind() == wanted)
}

impl HardwareRepository {
    /// Creates a repository over the store's pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    async fn conn(&self) -> Result<sqlx::pool::PoolConnection<sqlx::Sqlite>, HardwareStoreError> {
        self.pool
            .acquire()
            .await
            .map_err(|error| backend("acquire a connection", &error))
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

    async fn load_device(
        conn: &mut sqlx::SqliteConnection,
        key: DeviceKey<'_>,
    ) -> Result<Option<HardwareDevice>, HardwareStoreError> {
        let (sql, first, second) = match key {
            DeviceKey::Id(id) => (
                "SELECT id, account_id, mapping_id, kind, status, unsupported_reason, note, \
                 created_at, updated_at FROM hardware_devices WHERE id = ?1",
                id,
                None,
            ),
            DeviceKey::Mapping(account, mapping) => (
                "SELECT id, account_id, mapping_id, kind, status, unsupported_reason, note, \
                 created_at, updated_at FROM hardware_devices \
                 WHERE account_id = ?1 AND mapping_id = ?2",
                account,
                Some(mapping),
            ),
        };
        let mut query = sqlx::query(sql).bind(first);
        if let Some(second) = second {
            query = query.bind(second);
        }
        let Some(row) = query
            .fetch_optional(&mut *conn)
            .await
            .map_err(|error| backend("read hardware device", &error))?
        else {
            return Ok(None);
        };
        let id: String = row.get("id");
        let entries = sqlx::query(
            "SELECT node, vendor_id, product_id, usbpath, manufacturer, product, last_seen_at \
             FROM hardware_device_entries WHERE device_id = ?1 ORDER BY node",
        )
        .bind(&id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|error| backend("read hardware device entries", &error))?
        .iter()
        .map(|entry| DeviceNodeEntry {
            node: entry.get("node"),
            vendor_id: entry.get("vendor_id"),
            product_id: entry.get("product_id"),
            usbpath: entry.get("usbpath"),
            manufacturer: entry.get("manufacturer"),
            product: entry.get("product"),
            last_seen_at: entry.get("last_seen_at"),
        })
        .collect();
        let kind: String = row.get("kind");
        let status: String = row.get("status");
        let reason: Option<String> = row.get("unsupported_reason");
        Ok(Some(HardwareDevice {
            id,
            account_id: row.get("account_id"),
            mapping_id: row.get("mapping_id"),
            kind: HardwareKind::from_id(&kind).map_err(corrupt)?,
            entries,
            status: DeviceStatus::from_parts(&status, reason.as_deref()).map_err(corrupt)?,
            note: row.get("note"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }))
    }

    async fn load_reservation(
        &self,
        id: &str,
    ) -> Result<Option<HardwareReservation>, HardwareStoreError> {
        sqlx::query(select_reservations!("WHERE id = ?1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| backend("read hardware reservation", &error))?
            .as_ref()
            .map(Self::row_to_reservation)
            .transpose()
    }

    async fn live(
        &self,
        scope: LiveScope<'_>,
    ) -> Result<Vec<HardwareReservation>, HardwareStoreError> {
        let rows = match scope {
            LiveScope::All => {
                sqlx::query(select_reservations!(
                    "WHERE state <> 'released' ORDER BY created_at, id"
                ))
                .fetch_all(&self.pool)
                .await
            }
            LiveScope::Device(device_id) => {
                sqlx::query(select_reservations!(
                    "WHERE state <> 'released' AND device_id = ?1 ORDER BY created_at, id"
                ))
                .bind(device_id)
                .fetch_all(&self.pool)
                .await
            }
            LiveScope::Owner(kind, owner_id) => {
                sqlx::query(select_reservations!(
                    "WHERE state <> 'released' AND owner_kind = ?1 AND owner_id = ?2 \
                     ORDER BY created_at, id"
                ))
                .bind(kind.id())
                .bind(owner_id)
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(|error| backend("list hardware reservations", &error))?;
        rows.iter().map(Self::row_to_reservation).collect()
    }
}

#[derive(Clone, Copy)]
enum LiveScope<'a> {
    All,
    Device(&'a str),
    Owner(ReservationOwnerKind, &'a str),
}

#[derive(Clone, Copy)]
enum DeviceKey<'a> {
    Id(&'a str),
    Mapping(&'a str, &'a str),
}

#[async_trait]
impl HardwareStore for HardwareRepository {
    async fn upsert_device(
        &self,
        observation: &DeviceObservation,
        now: i64,
    ) -> Result<HardwareDevice, HardwareStoreError> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|error| backend("begin hardware upsert", &error))?;
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT id FROM hardware_devices WHERE account_id = ?1 AND mapping_id = ?2",
        )
        .bind(&observation.account_id)
        .bind(&observation.mapping_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| backend("look up hardware device", &error))?;
        let id = if let Some(id) = existing {
            sqlx::query(
                "UPDATE hardware_devices SET kind = ?2, status = ?3, unsupported_reason = ?4, \
                 updated_at = ?5 WHERE id = ?1",
            )
            .bind(&id)
            .bind(observation.kind.id())
            .bind(observation.status.id())
            .bind(
                observation
                    .status
                    .reason()
                    .map(fleet_core::UnsupportedReason::id),
            )
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|error| backend("update hardware device", &error))?;
            id
        } else {
            sqlx::query(
                "INSERT INTO hardware_devices \
                 (id, account_id, mapping_id, kind, status, unsupported_reason, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            )
            .bind(&observation.id)
            .bind(&observation.account_id)
            .bind(&observation.mapping_id)
            .bind(observation.kind.id())
            .bind(observation.status.id())
            .bind(observation.status.reason().map(fleet_core::UnsupportedReason::id))
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                if is_violation(&error, sqlx::error::ErrorKind::CheckViolation) {
                    HardwareStoreError::Invalid(format!("invalid device: {error}"))
                } else {
                    backend("insert hardware device", &error)
                }
            })?;
            observation.id.clone()
        };
        sqlx::query("DELETE FROM hardware_device_entries WHERE device_id = ?1")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(|error| backend("clear hardware device entries", &error))?;
        for entry in &observation.entries {
            sqlx::query(
                "INSERT INTO hardware_device_entries \
                 (device_id, node, vendor_id, product_id, usbpath, manufacturer, product, last_seen_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .bind(&id)
            .bind(&entry.node)
            .bind(&entry.vendor_id)
            .bind(&entry.product_id)
            .bind(&entry.usbpath)
            .bind(&entry.manufacturer)
            .bind(&entry.product)
            .bind(entry.last_seen_at)
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                if is_violation(&error, sqlx::error::ErrorKind::UniqueViolation) {
                    HardwareStoreError::Invalid(format!("two entries for node {:?}", entry.node))
                } else if is_violation(&error, sqlx::error::ErrorKind::CheckViolation) {
                    HardwareStoreError::Invalid(format!("invalid entry: {error}"))
                } else {
                    backend("insert hardware device entry", &error)
                }
            })?;
        }
        let device = Self::load_device(&mut tx, DeviceKey::Id(&id)).await?;
        tx.commit()
            .await
            .map_err(|error| backend("commit hardware upsert", &error))?;
        device.ok_or(HardwareStoreError::NotFound)
    }

    async fn device(&self, id: &str) -> Result<Option<HardwareDevice>, HardwareStoreError> {
        let mut conn = self.conn().await?;
        Self::load_device(&mut conn, DeviceKey::Id(id)).await
    }

    async fn device_by_mapping(
        &self,
        account_id: &str,
        mapping_id: &str,
    ) -> Result<Option<HardwareDevice>, HardwareStoreError> {
        let mut conn = self.conn().await?;
        Self::load_device(&mut conn, DeviceKey::Mapping(account_id, mapping_id)).await
    }

    async fn list_devices(
        &self,
        account_id: &str,
    ) -> Result<Vec<HardwareDevice>, HardwareStoreError> {
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM hardware_devices WHERE account_id = ?1 ORDER BY mapping_id",
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| backend("list hardware devices", &error))?;
        let mut devices = Vec::with_capacity(ids.len());
        let mut conn = self.conn().await?;
        for id in ids {
            if let Some(device) = Self::load_device(&mut conn, DeviceKey::Id(&id)).await? {
                devices.push(device);
            }
        }
        Ok(devices)
    }

    async fn set_device_status(
        &self,
        id: &str,
        status: DeviceStatus,
        now: i64,
    ) -> Result<(), HardwareStoreError> {
        let done = sqlx::query(
            "UPDATE hardware_devices SET status = ?2, unsupported_reason = ?3, updated_at = ?4 \
             WHERE id = ?1",
        )
        .bind(id)
        .bind(status.id())
        .bind(status.reason().map(fleet_core::UnsupportedReason::id))
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|error| backend("set hardware device status", &error))?;
        if done.rows_affected() == 0 {
            return Err(HardwareStoreError::NotFound);
        }
        Ok(())
    }

    async fn set_device_note(
        &self,
        id: &str,
        note: Option<&str>,
        now: i64,
    ) -> Result<(), HardwareStoreError> {
        let done =
            sqlx::query("UPDATE hardware_devices SET note = ?2, updated_at = ?3 WHERE id = ?1")
                .bind(id)
                .bind(note)
                .bind(now)
                .execute(&self.pool)
                .await
                .map_err(|error| {
                    if is_violation(&error, sqlx::error::ErrorKind::CheckViolation) {
                        HardwareStoreError::Invalid("the note is too long".to_owned())
                    } else {
                        backend("set hardware device note", &error)
                    }
                })?;
        if done.rows_affected() == 0 {
            return Err(HardwareStoreError::NotFound);
        }
        Ok(())
    }

    async fn insert_reservation(
        &self,
        reservation: &NewHardwareReservation,
        now: i64,
    ) -> Result<HardwareReservation, HardwareStoreError> {
        if let Some(guest) = &reservation.guest {
            guest.validate().map_err(HardwareStoreError::Invalid)?;
        }
        let guest = reservation.guest.as_ref();
        let inserted = sqlx::query(
            "INSERT INTO hardware_reservations \
             (id, device_id, owner_kind, owner_id, state, guest_account, guest_node, guest_vmid, \
              usb_slot, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, 'held', ?5, ?6, ?7, ?8, ?9, ?9)",
        )
        .bind(&reservation.id)
        .bind(&reservation.device_id)
        .bind(reservation.owner_kind.id())
        .bind(&reservation.owner_id)
        .bind(guest.map(|guest| guest.account_id.as_str()))
        .bind(guest.map(|guest| guest.node.as_str()))
        .bind(guest.map(|guest| i64::from(guest.vmid)))
        .bind(guest.and_then(|guest| guest.usb_slot).map(i64::from))
        .bind(now)
        .execute(&self.pool)
        .await;
        match inserted {
            Ok(_) => {}
            Err(error) if is_violation(&error, sqlx::error::ErrorKind::UniqueViolation) => {
                // The unique index fired: either the live-per-device index or
                // a repeated reservation id.
                return match self
                    .live_reservation_for_device(&reservation.device_id)
                    .await?
                {
                    Some(holder) => Err(HardwareStoreError::Held {
                        holder: Box::new(holder),
                    }),
                    None => Err(HardwareStoreError::Invalid(
                        "the reservation id is already used".to_owned(),
                    )),
                };
            }
            Err(error) if is_violation(&error, sqlx::error::ErrorKind::ForeignKeyViolation) => {
                return Err(HardwareStoreError::NotFound);
            }
            Err(error) if is_violation(&error, sqlx::error::ErrorKind::CheckViolation) => {
                return Err(HardwareStoreError::Invalid(format!(
                    "invalid reservation: {error}"
                )));
            }
            Err(error) => return Err(backend("insert hardware reservation", &error)),
        }
        self.load_reservation(&reservation.id)
            .await?
            .ok_or(HardwareStoreError::NotFound)
    }

    async fn reservation(
        &self,
        id: &str,
    ) -> Result<Option<HardwareReservation>, HardwareStoreError> {
        self.load_reservation(id).await
    }

    async fn live_reservation_for_device(
        &self,
        device_id: &str,
    ) -> Result<Option<HardwareReservation>, HardwareStoreError> {
        Ok(self
            .live(LiveScope::Device(device_id))
            .await?
            .into_iter()
            .next())
    }

    async fn live_reservations_for_owner(
        &self,
        owner_kind: ReservationOwnerKind,
        owner_id: &str,
    ) -> Result<Vec<HardwareReservation>, HardwareStoreError> {
        self.live(LiveScope::Owner(owner_kind, owner_id)).await
    }

    async fn list_live_reservations(&self) -> Result<Vec<HardwareReservation>, HardwareStoreError> {
        self.live(LiveScope::All).await
    }

    async fn transition_reservation(
        &self,
        id: &str,
        from: HardwareReservationState,
        to: HardwareReservationState,
        guest: Option<&GuestTarget>,
        now: i64,
    ) -> Result<HardwareReservation, HardwareStoreError> {
        if let Some(guest) = guest {
            guest.validate().map_err(HardwareStoreError::Invalid)?;
        }
        let current = self
            .load_reservation(id)
            .await?
            .ok_or(HardwareStoreError::NotFound)?;
        if !from.can_transition_to(to) || current.state != from {
            return Err(HardwareStoreError::IllegalTransition {
                from,
                to,
                actual: current.state,
            });
        }
        // Compare-and-set on the state: a concurrent writer that moved the
        // reservation first makes this update match no row.
        let released_at = (to == HardwareReservationState::Released).then_some(now);
        let done = sqlx::query(
            "UPDATE hardware_reservations SET state = ?3, updated_at = ?4, released_at = ?5, \
             guest_account = CASE WHEN ?6 THEN ?7 ELSE guest_account END, \
             guest_node = CASE WHEN ?6 THEN ?8 ELSE guest_node END, \
             guest_vmid = CASE WHEN ?6 THEN ?9 ELSE guest_vmid END, \
             usb_slot = CASE WHEN ?6 THEN ?10 ELSE usb_slot END \
             WHERE id = ?1 AND state = ?2",
        )
        .bind(id)
        .bind(from.id())
        .bind(to.id())
        .bind(now)
        .bind(released_at)
        .bind(guest.is_some())
        .bind(guest.map(|guest| guest.account_id.as_str()))
        .bind(guest.map(|guest| guest.node.as_str()))
        .bind(guest.map(|guest| i64::from(guest.vmid)))
        .bind(guest.and_then(|guest| guest.usb_slot).map(i64::from))
        .execute(&self.pool)
        .await
        .map_err(|error| {
            if is_violation(&error, sqlx::error::ErrorKind::CheckViolation) {
                HardwareStoreError::Invalid(format!("invalid guest target: {error}"))
            } else {
                backend("move hardware reservation", &error)
            }
        })?;
        let updated = self
            .load_reservation(id)
            .await?
            .ok_or(HardwareStoreError::NotFound)?;
        if done.rows_affected() == 0 {
            return Err(HardwareStoreError::IllegalTransition {
                from,
                to,
                actual: updated.state,
            });
        }
        Ok(updated)
    }
}
