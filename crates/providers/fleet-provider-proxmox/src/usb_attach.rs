//! Attach and detach one USB resource mapping on a QEMU guest (FM-1122).
//!
//! Fleet writes `usbN=mapping=<id>` and nothing else: a raw `host=` entry is
//! root-only in PVE (`only root can set 'usbN' config for real devices`), so
//! a resource mapping is the only path a token has, and the only one this
//! module can express. Behaviour follows the FM-S11 spike
//! (`docs/research/proxmox-usb.md`, measured on PVE 8.4.0 and 9.2.2) and
//! ADR 0019.
//!
//! The write path has the safety of the rest of the guest config path:
//!
//! 1. Read the config (`GET …/config`) and its pending changes
//!    (`GET …/pending`). Refuse a template and a locked guest. The two reads
//!    must agree on the digest, or they straddled a change and are read again.
//! 2. Attach picks the lowest `usbN` slot that is free in **both** views of
//!    the guest (the applied one and the pending one), so a slot whose
//!    removal is only pending is not reused. Detach acts only on the slot the
//!    caller names.
//! 3. Write conditional on the digest read in step 1. PVE refuses a stale
//!    digest with `checksum mismatch`, and nothing is written.
//! 4. Read back through `pending` and report what was seen. A plain value
//!    with no `pending` or `delete` member is applied. Anything else is
//!    reported as [`PveUsbState::Pending`] (a running guest whose `hotplug`
//!    option lacks `usb` keeps the old device set until it restarts) and a
//!    read-back that disagrees with the write is an error, never a success.
//!
//! Both calls are idempotent. They return [`PveUsbChange::Unchanged`]
//! without a write when the guest is already in the requested state, so a
//! retry after a lost answer is safe.
//!
//! **A slot Fleet did not write is never deleted.** Fleet writes exactly
//! `mapping=<id>`. A detach names the slot *and* the mapping the caller
//! recorded for it, and deletes only when the slot holds exactly that value.
//! A slot with another mapping, a `host=` device, or the same mapping with
//! extra options (`mapping=<id>,usb3=1`, as an operator writes it) is
//! refused with [`PveUsbError::ForeignSlot`] and left untouched. Whether the
//! caller wrote the slot is the caller's reservation record; this module
//! cannot see it, so the caller must pass only a slot it recorded.
//!
//! **A failed hotplug leaves state behind.** PVE answers `400 hotplug
//! problem` for an absent device or an unusable mapping, yet keeps the entry
//! as a pending value, and the next start would fail. When the write fails
//! after PVE has accepted its digest and permissions, attach reads the guest
//! again and removes the entry it just wrote, conditional on the new digest,
//! then reports what became of it in [`PveUsbCleanup`]. It never removes a
//! slot that holds anything other than the value it wrote.
//!
//! Needed privileges are declared in [`USB_ATTACH_PRIVILEGES`]:
//! `VM.Audit` to read, and `VM.Config.HWType` on the guest plus `Mapping.Use`
//! on the mapping to attach **and** to detach. This module does not authorize
//! or audit: the caller does both before it calls.

use std::collections::BTreeMap;
use std::fmt;

// The privilege rows and the refusal parser live in `permissions.rs` (the
// crate root exports no new names); they are public through this module.
pub use crate::permissions::{
    PveRefusedPrivilege, PveUsbPrivilegeRow, USB_ATTACH_PRIVILEGES, parse_refused_privilege,
};
use crate::{
    ProxmoxClient, PveApiError, PveHttpMethod, PveHttpRequest, loose_number, type_name_of,
    urlencode,
};

/// How many `usbN` slots a guest has (`usb0` to `usb13`), the
/// `$MAX_USB_DEVICES` of `qemu-server`'s `PVE::QemuServer::USB`. The spike
/// used four slots and did not measure the limit; attach takes the lowest
/// free slot, so a guest reaches the higher ones only when the lower ones are
/// taken, and PVE refuses a slot beyond its own limit.
pub const MAX_USB_SLOTS: u8 = 14;

/// The longest mapping id accepted, in characters.
pub const MAX_MAPPING_ID_CHARS: usize = 64;

/// The longest `usbN` value read from a config, in characters. A longer one
/// is a payload error, never truncated.
const MAX_VALUE_CHARS: usize = 256;

/// The most entries read from one `pending` answer.
const MAX_PENDING_ENTRIES: usize = 2048;

/// Whether a call wrote to the guest or found it already in the state asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PveUsbChange {
    /// The call wrote the change and read it back.
    Written,
    /// The guest was already in the requested state; nothing was written.
    Unchanged,
}

/// Whether the guest's running configuration agrees with the stored one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PveUsbState {
    /// PVE applied the change: for an attach the device is configured (and
    /// hotplugged when the guest runs), for a detach it is gone.
    Applied,
    /// PVE stored the change but a restart applies it. For an attach the
    /// device is not on the guest yet; for a detach it is still there. A
    /// caller must report `attach_pending` or `detach_pending`, never
    /// attached or released.
    Pending,
}

/// What a call saw when it read the guest back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PveUsbOutcome {
    /// The slot, such as `usb2`.
    pub slot: String,
    /// The mapping id the call was about.
    pub mapping_id: String,
    /// Whether the call wrote.
    pub change: PveUsbChange,
    /// Applied or pending.
    pub state: PveUsbState,
    /// The slot's value in the guest's stored configuration as read back:
    /// `mapping=<id>` while the entry exists, `None` once a detach is
    /// applied. After a pending detach it is the value that will go.
    pub observed: Option<String>,
    /// The config digest read back, to chain a further conditional write.
    pub digest: String,
}

/// What became of the entry a failed attach may have left behind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PveUsbCleanup {
    /// The slot is empty again; PVE kept nothing, or Fleet removed it.
    Removed,
    /// The slot was already empty when the guest was read back.
    NothingToRemove,
    /// The entry may still be there. The caller keeps its reservation and
    /// resolves it, as ADR 0019 decision 3 says.
    Failed {
        /// Why, bounded.
        detail: String,
    },
}

/// A refused or failed attach or detach.
#[derive(Debug)]
pub enum PveUsbError {
    /// The mapping id, the slot or another input is not acceptable. Nothing
    /// was sent.
    InvalidInput {
        /// What is wrong.
        detail: String,
    },
    /// The guest is a template. Fleet never changes a template: a clone
    /// would inherit the device entry.
    Template,
    /// The guest's config is locked (`clone`, `backup`, …). Nothing was
    /// written.
    Locked {
        /// The lock name.
        lock: String,
    },
    /// The config digest no longer matches: someone changed the guest
    /// between the read and the write. Nothing was written; read again.
    DigestConflict,
    /// PVE refused the token (403). Nothing was written.
    Refused {
        /// The privilege and ACL path PVE named, when its answer says.
        privilege: Option<PveRefusedPrivilege>,
        /// The bounded PVE detail.
        detail: String,
    },
    /// Every slot is taken. Nothing was written.
    SlotsFull {
        /// How many slots the guest has.
        slots: u8,
    },
    /// The slot holds something Fleet did not write (or the guest already
    /// references this mapping in a form Fleet does not write). Nothing was
    /// written or deleted.
    ForeignSlot {
        /// The slot.
        slot: String,
        /// Its value, bounded.
        observed: String,
    },
    /// More than one slot holds the mapping. Fleet does not guess which one
    /// it wrote; nothing was changed.
    Ambiguous {
        /// The slots that reference the mapping.
        slots: Vec<String>,
    },
    /// The slot has an unapplied change that this call cannot be idempotent
    /// over (for example a pending removal of the mapping being attached).
    /// It is applied by the guest's next restart; nothing was written.
    PendingConflict {
        /// The slot.
        slot: String,
    },
    /// The write failed after PVE accepted the digest and permissions, so it
    /// may have left an entry behind. Attach has already tried to remove it.
    WriteFailed {
        /// The slot written.
        slot: String,
        /// The HTTP status.
        status: u16,
        /// The bounded PVE detail.
        detail: String,
        /// What became of the entry.
        cleanup: PveUsbCleanup,
    },
    /// The write was accepted but the read-back disagrees with it. The
    /// caller must not treat the call as done.
    ReadBackMismatch {
        /// The slot.
        slot: String,
        /// The slot's stored value as read back.
        observed: Option<String>,
    },
    /// The outcome cannot be determined: the answer to the write was lost, or
    /// the write was accepted and the read-back failed. The device may or may
    /// not be configured. Keep the reservation held and retry (both calls are
    /// idempotent) or let the reconciler read the guest.
    Indeterminate {
        /// The slot, when one was chosen.
        slot: Option<String>,
        /// What happened, bounded.
        detail: String,
    },
    /// Any other API failure before a write (reads, authentication,
    /// payloads).
    Api(PveApiError),
}

impl fmt::Display for PveUsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { detail } => write!(f, "invalid USB request: {detail}"),
            Self::Template => write!(f, "the guest is a template; Fleet does not change it"),
            Self::Locked { lock } => write!(f, "the guest's config is locked ({lock})"),
            Self::DigestConflict => write!(
                f,
                "the guest's config changed since it was read (digest conflict); nothing was written"
            ),
            Self::Refused { privilege, detail } => match privilege {
                Some(privilege) => write!(
                    f,
                    "the token lacks {} on {}",
                    privilege.privilege, privilege.path
                ),
                None => write!(f, "the token lacks a privilege (403): {detail}"),
            },
            Self::SlotsFull { slots } => write!(f, "all {slots} USB slots of the guest are taken"),
            Self::ForeignSlot { slot, observed } => write!(
                f,
                "{slot} holds {observed:?}, which Fleet did not write; it was left untouched"
            ),
            Self::Ambiguous { slots } => write!(
                f,
                "the mapping is referenced by more than one slot ({}); nothing was changed",
                slots.join(", ")
            ),
            Self::PendingConflict { slot } => write!(
                f,
                "{slot} has an unapplied change that the guest's next restart applies"
            ),
            Self::WriteFailed {
                slot,
                status,
                detail,
                cleanup,
            } => {
                write!(f, "writing {slot} failed ({status}): {detail}; ")?;
                match cleanup {
                    PveUsbCleanup::Removed => write!(f, "no entry remains"),
                    PveUsbCleanup::NothingToRemove => write!(f, "PVE kept no entry"),
                    PveUsbCleanup::Failed { detail } => {
                        write!(f, "the entry may remain: {detail}")
                    }
                }
            }
            Self::ReadBackMismatch { slot, observed } => write!(
                f,
                "the read-back of {slot} ({observed:?}) disagrees with the write"
            ),
            Self::Indeterminate { slot, detail } => match slot {
                Some(slot) => write!(f, "the outcome for {slot} is not known: {detail}"),
                None => write!(f, "the outcome is not known: {detail}"),
            },
            Self::Api(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PveUsbError {}

impl From<PveApiError> for PveUsbError {
    fn from(error: PveApiError) -> Self {
        match error {
            PveApiError::Forbidden { detail } => Self::Refused {
                privilege: parse_refused_privilege(&detail),
                detail,
            },
            other => Self::Api(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// A PVE mapping id as Fleet will write it into a property string. The check
/// is stricter than PVE's `pve-configid`: letters, digits, `-`, `_` and `.`,
/// starting with a letter. It exists so that no id can add a property
/// (`x,host=1-7`) to the value Fleet writes.
fn valid_mapping_id(id: &str) -> bool {
    id.len() <= MAX_MAPPING_ID_CHARS
        && id.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// The index of a `usbN` key: `usb0` to `usb13`, no sign, no leading zero.
fn slot_index(key: &str) -> Option<u8> {
    let digits = key.strip_prefix("usb")?;
    if digits.is_empty()
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return None;
    }
    digits.parse().ok().filter(|index| *index < MAX_USB_SLOTS)
}

fn slot_key(index: u8) -> String {
    format!("usb{index}")
}

/// The one value Fleet writes for a mapping.
fn canonical_value(mapping_id: &str) -> String {
    format!("mapping={mapping_id}")
}

/// The mapping id a `usbN` value names, when it has a `mapping=` property.
fn mapping_of(value: &str) -> Option<&str> {
    value
        .split(',')
        .find_map(|part| part.strip_prefix("mapping="))
}

fn invalid(detail: impl Into<String>) -> PveUsbError {
    PveUsbError::InvalidInput {
        detail: detail.into(),
    }
}

fn validated(mapping_id: &str) -> Result<(), PveUsbError> {
    if valid_mapping_id(mapping_id) {
        Ok(())
    } else {
        Err(invalid(format!(
            "the mapping id must start with a letter and use only letters, digits, '-', '_' and '.' (at most {MAX_MAPPING_ID_CHARS} characters)"
        )))
    }
}

// ---------------------------------------------------------------------------
// Reading the guest
// ---------------------------------------------------------------------------

/// One slot as the guest's two views show it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SlotView {
    /// The value the running guest has (the `value` member of a `pending`
    /// entry).
    applied: Option<String>,
    /// A value a restart will apply (the `pending` member).
    pending: Option<String>,
    /// A restart will remove the entry (the `delete` member).
    delete: bool,
}

impl SlotView {
    /// The value the stored config holds for the slot, which is what a plain
    /// `GET …/config` shows: the pending value when there is one, nothing
    /// when removal is pending, else the applied value.
    fn stored(&self) -> Option<&str> {
        if let Some(pending) = &self.pending {
            Some(pending)
        } else if self.delete {
            None
        } else {
            self.applied.as_deref()
        }
    }

    /// Any value this slot holds in either view, for reporting.
    fn any(&self) -> &str {
        self.pending
            .as_deref()
            .or(self.applied.as_deref())
            .unwrap_or_default()
    }

    /// Whether either view references `mapping_id`.
    fn references(&self, mapping_id: &str) -> bool {
        [&self.applied, &self.pending]
            .into_iter()
            .flatten()
            .any(|value| mapping_of(value) == Some(mapping_id))
    }

    /// Applied and nothing pending: exactly `value`.
    fn is_applied(&self, value: &str) -> bool {
        self.applied.as_deref() == Some(value) && self.pending.is_none() && !self.delete
    }

    /// An add that a restart applies: exactly `value`, not running yet.
    fn is_pending_add(&self, value: &str) -> bool {
        self.applied.is_none() && self.pending.as_deref() == Some(value) && !self.delete
    }

    /// A removal that a restart applies, of exactly `value`.
    fn is_pending_delete(&self, value: &str) -> bool {
        self.applied.as_deref() == Some(value) && self.pending.is_none() && self.delete
    }
}

/// The facts one write needs, read from `config` and `pending`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    template: bool,
    lock: Option<String>,
    digest: String,
    slots: BTreeMap<u8, SlotView>,
}

fn payload(detail: impl Into<String>) -> PveApiError {
    PveApiError::InvalidPayload {
        detail: detail.into(),
    }
}

fn usb_text(key: &str, value: &serde_json::Value) -> Result<String, PveApiError> {
    match value.as_str() {
        Some(text) if text.chars().count() <= MAX_VALUE_CHARS => Ok(text.to_owned()),
        Some(_) => Err(payload(format!(
            "the {key} entry is over the {MAX_VALUE_CHARS}-character bound"
        ))),
        None => Err(payload(format!(
            "the {key} entry is not a string (it is a {})",
            type_name_of(value)
        ))),
    }
}

/// Whether a PVE flag member is set; PVE answers `1`, `true` or `"1"`.
fn flag_set(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Bool(flag) => *flag,
        serde_json::Value::Number(number) => number.as_u64().is_some_and(|n| n != 0),
        serde_json::Value::String(text) => text == "1" || text == "true",
        _ => false,
    }
}

/// Builds a [`Snapshot`] from the two answers. The `pending` list is the
/// authority for both views; the stored config only fills a `usbN` the list
/// lacks, so the slot counts as taken (a free slot is never guessed).
///
/// `Ok(None)` means the two answers carry different digests: they straddle a
/// change by another writer and must be read again.
fn parse_snapshot(
    config_value: &serde_json::Value,
    pending: &serde_json::Value,
) -> Result<Option<Snapshot>, PveApiError> {
    let Some(config) = config_value.as_object() else {
        return Err(payload(format!(
            "the guest config is not an object (it is a {})",
            type_name_of(config_value)
        )));
    };
    let template = match config.get("template") {
        None | Some(serde_json::Value::Null) => false,
        Some(_) => match loose_number(config_value, "template") {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(payload("the guest config's template flag is unreadable")),
        },
    };
    let lock = match config.get("lock") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(lock)) if lock.chars().count() <= 32 => Some(lock.clone()),
        Some(_) => return Err(payload("the guest config's lock field is unreadable")),
    };
    // A conditional write needs the digest; without one there is nothing to
    // be conditional on.
    let digest = match config.get("digest").and_then(serde_json::Value::as_str) {
        Some(digest) if !digest.is_empty() && digest.chars().count() <= 64 => digest.to_owned(),
        _ => return Err(payload("the guest config carries no usable digest")),
    };

    let entries = match pending {
        serde_json::Value::Array(entries) if entries.len() <= MAX_PENDING_ENTRIES => entries,
        serde_json::Value::Array(_) => {
            return Err(payload(format!(
                "the pending list has more than {MAX_PENDING_ENTRIES} entries"
            )));
        }
        other => {
            return Err(payload(format!(
                "the pending payload is not a list (it is a {})",
                type_name_of(other)
            )));
        }
    };
    let mut pending_digest = None;
    let mut slots: BTreeMap<u8, SlotView> = BTreeMap::new();
    for entry in entries {
        let Some(key) = entry.get("key").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if key == "digest" {
            pending_digest = entry
                .get("value")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            continue;
        }
        let Some(index) = slot_index(key) else {
            continue;
        };
        let view = slots.entry(index).or_default();
        if let Some(value) = entry.get("value") {
            view.applied = Some(usb_text(key, value)?);
        }
        if let Some(value) = entry.get("pending") {
            view.pending = Some(usb_text(key, value)?);
        }
        view.delete = entry.get("delete").is_some_and(flag_set);
    }
    if pending_digest.is_some_and(|seen| seen != digest) {
        return Ok(None);
    }
    for (key, value) in config {
        if let Some(index) = slot_index(key) {
            // In the stored config but not in the pending list: applied, as
            // far as anything can tell.
            slots.entry(index).or_insert_with(|| SlotView {
                applied: usb_text(key, value).ok(),
                ..SlotView::default()
            });
        }
    }
    Ok(Some(Snapshot {
        template,
        lock,
        digest,
        slots,
    }))
}

fn config_path(node: &str, vmid: u32) -> String {
    format!("/api2/json/nodes/{}/qemu/{vmid}/config", urlencode(node))
}

fn pending_path(node: &str, vmid: u32) -> String {
    format!("/api2/json/nodes/{}/qemu/{vmid}/pending", urlencode(node))
}

/// How a failed write is treated.
enum WriteVerdict {
    /// PVE refused before it changed anything.
    Refused(PveUsbError),
    /// The answer is lost or unreadable; the write may have landed.
    Lost(String),
    /// PVE failed after taking the digest and permissions; it may have left
    /// an entry behind.
    Failed { status: u16, detail: String },
}

fn classify_write_error(error: PveApiError) -> WriteVerdict {
    match error {
        PveApiError::Forbidden { .. } | PveApiError::Auth => {
            WriteVerdict::Refused(PveUsbError::from(error))
        }
        PveApiError::Transport(error) => WriteVerdict::Lost(error.to_string()),
        PveApiError::InvalidPayload { detail } => WriteVerdict::Lost(detail),
        PveApiError::Http { status, detail } => {
            if detail.contains("checksum mismatch") {
                WriteVerdict::Refused(PveUsbError::DigestConflict)
            } else if let Some(lock) = locked_by(&detail) {
                WriteVerdict::Refused(PveUsbError::Locked { lock })
            } else {
                WriteVerdict::Failed { status, detail }
            }
        }
    }
}

/// The lock named by PVE's `VM is locked (<lock>)`.
fn locked_by(detail: &str) -> Option<String> {
    let rest = &detail[detail.find("is locked (")? + "is locked (".len()..];
    let lock = &rest[..rest.find(')')?];
    (!lock.is_empty() && lock.len() <= 32).then(|| lock.to_owned())
}

// ---------------------------------------------------------------------------
// The calls
// ---------------------------------------------------------------------------

impl ProxmoxClient {
    /// Reads the guest's config and pending list into one [`Snapshot`],
    /// reading again once when they straddle a change.
    async fn usb_snapshot(
        &self,
        request: &PveHttpRequest,
        node: &str,
        vmid: u32,
    ) -> Result<Snapshot, PveUsbError> {
        for _ in 0..2 {
            let config = self
                .call(PveHttpRequest {
                    path: config_path(node, vmid),
                    method: PveHttpMethod::Get,
                    ..request.clone()
                })
                .await?;
            let pending = self
                .call(PveHttpRequest {
                    path: pending_path(node, vmid),
                    method: PveHttpMethod::Get,
                    ..request.clone()
                })
                .await?;
            if let Some(snapshot) = parse_snapshot(&config, &pending)? {
                return Ok(snapshot);
            }
        }
        Err(PveUsbError::DigestConflict)
    }

    /// One digest-conditional config write.
    async fn usb_write(
        &self,
        request: &PveHttpRequest,
        node: &str,
        vmid: u32,
        body: &serde_json::Value,
    ) -> Result<(), PveApiError> {
        self.call_method_with_body(
            request.clone(),
            PveHttpMethod::Put,
            &config_path(node, vmid),
            body,
        )
        .await
        .map(|_| ())
    }

    /// Reads the guest and refuses a template or a locked guest.
    async fn usb_checked_snapshot(
        &self,
        request: &PveHttpRequest,
        node: &str,
        vmid: u32,
    ) -> Result<Snapshot, PveUsbError> {
        let snapshot = self.usb_snapshot(request, node, vmid).await?;
        if snapshot.template {
            return Err(PveUsbError::Template);
        }
        if let Some(lock) = snapshot.lock {
            return Err(PveUsbError::Locked { lock });
        }
        Ok(snapshot)
    }

    /// Attaches the USB mapping `mapping_id` to a QEMU guest as the lowest
    /// free `usbN` slot, writing `usbN=mapping=<id>` conditional on the
    /// config digest and reading it back (`PUT` and `GET …/config`,
    /// `GET …/pending`; needs `VM.Audit` and `VM.Config.HWType` on
    /// `/vms/{vmid}` and `Mapping.Use` on `/mapping/usb/{mapping_id}`).
    ///
    /// Idempotent: a guest that already holds exactly `mapping=<mapping_id>`
    /// in one slot returns [`PveUsbChange::Unchanged`] without a write, in the
    /// state it is in (applied, or pending until the guest restarts). The
    /// caller decides whether it wrote that slot.
    ///
    /// A running guest whose `hotplug` option lacks `usb` stores the entry as
    /// pending: the outcome says [`PveUsbState::Pending`], and the device is
    /// not on the guest until it restarts. The caller verifies the device is
    /// present and unreserved before calling; this call does not.
    ///
    /// # Errors
    ///
    /// [`PveUsbError`]: a template or locked guest, a stale digest, a refused
    /// privilege, full slots, a slot or reference Fleet did not write, a
    /// failed write (after which the entry was removed or reported), a
    /// read-back that disagrees, and an outcome that cannot be known.
    pub async fn qemu_usb_attach(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        mapping_id: &str,
    ) -> Result<PveUsbOutcome, PveUsbError> {
        validated(mapping_id)?;
        let value = canonical_value(mapping_id);
        let snapshot = self.usb_checked_snapshot(&request, node, vmid).await?;

        let references: Vec<(u8, &SlotView)> = snapshot
            .slots
            .iter()
            .filter(|(_, view)| view.references(mapping_id))
            .map(|(index, view)| (*index, view))
            .collect();
        match references.as_slice() {
            [] => {}
            [(index, view)] => {
                let slot = slot_key(*index);
                let state = if view.is_applied(&value) {
                    PveUsbState::Applied
                } else if view.is_pending_add(&value) {
                    PveUsbState::Pending
                } else if [&view.applied, &view.pending]
                    .into_iter()
                    .flatten()
                    .all(|seen| *seen == value)
                {
                    // Exactly our value, with a removal or a change queued.
                    return Err(PveUsbError::PendingConflict { slot });
                } else {
                    return Err(PveUsbError::ForeignSlot {
                        slot,
                        observed: view.any().to_owned(),
                    });
                };
                return Ok(PveUsbOutcome {
                    slot,
                    mapping_id: mapping_id.to_owned(),
                    change: PveUsbChange::Unchanged,
                    state,
                    observed: Some(value),
                    digest: snapshot.digest,
                });
            }
            many => {
                return Err(PveUsbError::Ambiguous {
                    slots: many.iter().map(|(index, _)| slot_key(*index)).collect(),
                });
            }
        }

        let Some(index) = (0..MAX_USB_SLOTS).find(|index| !snapshot.slots.contains_key(index))
        else {
            return Err(PveUsbError::SlotsFull {
                slots: MAX_USB_SLOTS,
            });
        };
        let slot = slot_key(index);
        let body = serde_json::json!({ slot.as_str(): value, "digest": snapshot.digest });
        if let Err(error) = self.usb_write(&request, node, vmid, &body).await {
            return Err(match classify_write_error(error) {
                WriteVerdict::Refused(error) => error,
                WriteVerdict::Lost(detail) => PveUsbError::Indeterminate {
                    slot: Some(slot),
                    detail,
                },
                WriteVerdict::Failed { status, detail } => {
                    let cleanup = self
                        .usb_remove_leftover(&request, node, vmid, index, &value)
                        .await;
                    PveUsbError::WriteFailed {
                        slot,
                        status,
                        detail,
                        cleanup,
                    }
                }
            });
        }

        let after = self
            .usb_snapshot(&request, node, vmid)
            .await
            .map_err(|error| PveUsbError::Indeterminate {
                slot: Some(slot.clone()),
                detail: format!("the write was accepted but the read-back failed: {error}"),
            })?;
        let view = after.slots.get(&index);
        let state = match view {
            Some(view) if view.is_applied(&value) => PveUsbState::Applied,
            Some(view) if view.is_pending_add(&value) => PveUsbState::Pending,
            other => {
                return Err(PveUsbError::ReadBackMismatch {
                    slot,
                    observed: other.and_then(SlotView::stored).map(str::to_owned),
                });
            }
        };
        Ok(PveUsbOutcome {
            slot,
            mapping_id: mapping_id.to_owned(),
            change: PveUsbChange::Written,
            state,
            observed: Some(value),
            digest: after.digest,
        })
    }

    /// Removes the entry a failed attach may have left in `index`, but only
    /// if it holds exactly `value`, conditional on a fresh digest.
    async fn usb_remove_leftover(
        &self,
        request: &PveHttpRequest,
        node: &str,
        vmid: u32,
        index: u8,
        value: &str,
    ) -> PveUsbCleanup {
        let failed = |detail: String| PveUsbCleanup::Failed { detail };
        let snapshot = match self.usb_snapshot(request, node, vmid).await {
            Ok(snapshot) => snapshot,
            Err(error) => return failed(format!("the guest could not be read back: {error}")),
        };
        let slot = slot_key(index);
        match snapshot.slots.get(&index) {
            None => return PveUsbCleanup::NothingToRemove,
            Some(view) if view.is_pending_add(value) || view.is_applied(value) => {}
            Some(_) => {
                return failed(format!(
                    "{slot} holds a value Fleet did not write; it was left untouched"
                ));
            }
        }
        let body = serde_json::json!({ "delete": slot, "digest": snapshot.digest });
        if let Err(error) = self.usb_write(request, node, vmid, &body).await {
            return failed(format!("removing {slot} failed: {error}"));
        }
        match self.usb_snapshot(request, node, vmid).await {
            Ok(after) => match after.slots.get(&index) {
                None => PveUsbCleanup::Removed,
                Some(_) => failed(format!("{slot} is still configured after its removal")),
            },
            Err(error) => failed(format!("the removal could not be read back: {error}")),
        }
    }

    /// Detaches `mapping_id` from `slot` of a QEMU guest: writes
    /// `delete=<slot>` conditional on the config digest and reads it back
    /// (needs `VM.Audit`, `VM.Config.HWType` on `/vms/{vmid}` and
    /// `Mapping.Use` on the mapping the slot currently names).
    ///
    /// The caller passes the slot **and** the mapping it recorded when it
    /// attached. The slot is deleted only when it holds exactly
    /// `mapping=<mapping_id>`; anything else is
    /// [`PveUsbError::ForeignSlot`] and nothing is deleted.
    ///
    /// Idempotent: an empty slot returns [`PveUsbChange::Unchanged`] with
    /// [`PveUsbState::Applied`] and no write; a removal already pending
    /// returns `Unchanged` with [`PveUsbState::Pending`]. A running guest
    /// whose `hotplug` option lacks `usb` keeps the device until it restarts,
    /// and the outcome says [`PveUsbState::Pending`]: the caller must not
    /// release the device yet.
    ///
    /// # Errors
    ///
    /// [`PveUsbError`], as for [`Self::qemu_usb_attach`]. A token that lost
    /// `Mapping.Use` can detach nothing and gets
    /// [`PveUsbError::Refused`], which the caller reports to an operator.
    pub async fn qemu_usb_detach(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        slot: &str,
        mapping_id: &str,
    ) -> Result<PveUsbOutcome, PveUsbError> {
        validated(mapping_id)?;
        let Some(index) = slot_index(slot) else {
            return Err(invalid(format!(
                "{slot:?} is not a USB slot (usb0 to usb{})",
                MAX_USB_SLOTS - 1
            )));
        };
        let value = canonical_value(mapping_id);
        let snapshot = self.usb_checked_snapshot(&request, node, vmid).await?;
        let outcome = |change, state, observed: Option<String>, digest: String| PveUsbOutcome {
            slot: slot.to_owned(),
            mapping_id: mapping_id.to_owned(),
            change,
            state,
            observed,
            digest,
        };

        match snapshot.slots.get(&index) {
            None => {
                return Ok(outcome(
                    PveUsbChange::Unchanged,
                    PveUsbState::Applied,
                    None,
                    snapshot.digest,
                ));
            }
            Some(view) => {
                let ours = [&view.applied, &view.pending]
                    .into_iter()
                    .flatten()
                    .all(|seen| *seen == value);
                if !ours {
                    return Err(PveUsbError::ForeignSlot {
                        slot: slot.to_owned(),
                        observed: view.any().to_owned(),
                    });
                }
                if view.is_pending_delete(&value) {
                    return Ok(outcome(
                        PveUsbChange::Unchanged,
                        PveUsbState::Pending,
                        Some(value),
                        snapshot.digest,
                    ));
                }
                if !(view.is_applied(&value) || view.is_pending_add(&value)) {
                    return Err(PveUsbError::PendingConflict {
                        slot: slot.to_owned(),
                    });
                }
            }
        }

        let body = serde_json::json!({ "delete": slot, "digest": snapshot.digest });
        if let Err(error) = self.usb_write(&request, node, vmid, &body).await {
            return Err(match classify_write_error(error) {
                WriteVerdict::Refused(error) => error,
                WriteVerdict::Lost(detail) => PveUsbError::Indeterminate {
                    slot: Some(slot.to_owned()),
                    detail,
                },
                WriteVerdict::Failed { status, detail } => {
                    PveUsbError::Api(PveApiError::Http { status, detail })
                }
            });
        }

        let after = self
            .usb_snapshot(&request, node, vmid)
            .await
            .map_err(|error| PveUsbError::Indeterminate {
                slot: Some(slot.to_owned()),
                detail: format!("the write was accepted but the read-back failed: {error}"),
            })?;
        match after.slots.get(&index) {
            None => Ok(outcome(
                PveUsbChange::Written,
                PveUsbState::Applied,
                None,
                after.digest,
            )),
            Some(view) if view.is_pending_delete(&value) => Ok(outcome(
                PveUsbChange::Written,
                PveUsbState::Pending,
                Some(value),
                after.digest,
            )),
            other => Err(PveUsbError::ReadBackMismatch {
                slot: slot.to_owned(),
                observed: other.and_then(SlotView::stored).map(str::to_owned),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use fleet_core::SensitiveString;
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    use crate::{PveCredentials, PveHttpResponse, PveTransport, PveTransportError};

    const NODE: &str = "pve9-n1";
    const VMID: u32 = 9100;
    const MAPPING: &str = "fm-test-reader";
    const OTHER: &str = "fm-test-stick";
    const SECRET: &str = "fixture-secret";

    fn request() -> PveHttpRequest {
        PveHttpRequest {
            host: "pve.test".into(),
            port: 8006,
            path: "/".into(),
            pinned_fingerprint: Some("fixture-pin".into()),
            credentials: Arc::new(PveCredentials {
                token_id: "fleet@pve!test".into(),
                token: SensitiveString::new(SECRET),
            }),
            method: PveHttpMethod::Post,
        }
    }

    // -- A fake PVE: one guest whose config behaves like the spike's --------

    #[derive(Debug)]
    #[allow(clippy::struct_excessive_bools)] // independent fault switches
    struct State {
        running: bool,
        hotplug_usb: bool,
        template: bool,
        lock: Option<String>,
        applied: BTreeMap<String, String>,
        pending_add: BTreeMap<String, String>,
        pending_delete: BTreeSet<String>,
        digest: u32,
        has_audit: bool,
        has_hwtype: bool,
        has_mapping_use: bool,
        /// The next write fails after PVE took the digest and permissions.
        fail_next_put: Option<(u16, Value)>,
        /// ... and leaves its entry behind as a pending value.
        leave_leftover: bool,
        /// ... holding this value instead of the one written (another
        /// writer got there first).
        leftover_value: Option<String>,
        /// Deleting a usb entry is refused (403, Mapping.Use).
        deny_delete: bool,
        /// A concurrent writer changes the config just before our write.
        bump_before_put: bool,
        /// The config answer carries a digest the pending answer then
        /// outdates, once.
        straddle_once: bool,
        /// The transport loses the answer to a write.
        lose_put_answer: bool,
        /// PVE answers 200 but ignores the write.
        drop_writes: bool,
        gets: usize,
        puts: Vec<Value>,
    }

    #[derive(Debug)]
    struct Fake {
        state: Mutex<State>,
    }

    impl Fake {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(State {
                    running: false,
                    hotplug_usb: true,
                    template: false,
                    lock: None,
                    applied: BTreeMap::new(),
                    pending_add: BTreeMap::new(),
                    pending_delete: BTreeSet::new(),
                    digest: 1,
                    has_audit: true,
                    has_hwtype: true,
                    has_mapping_use: true,
                    fail_next_put: None,
                    leave_leftover: false,
                    leftover_value: None,
                    deny_delete: false,
                    bump_before_put: false,
                    straddle_once: false,
                    lose_put_answer: false,
                    drop_writes: false,
                    gets: 0,
                    puts: Vec::new(),
                }),
            })
        }

        fn with(self: &Arc<Self>, change: impl FnOnce(&mut State)) -> Arc<Self> {
            change(&mut self.state.lock().unwrap());
            Arc::clone(self)
        }

        fn client(self: &Arc<Self>) -> ProxmoxClient {
            ProxmoxClient::new(self.clone())
        }

        /// The usb keys of the stored config (what `GET …/config` shows).
        fn stored(&self) -> BTreeMap<String, String> {
            let state = self.state.lock().unwrap();
            merged(&state)
        }

        fn applied(&self) -> BTreeMap<String, String> {
            self.state.lock().unwrap().applied.clone()
        }

        fn puts(&self) -> Vec<Value> {
            self.state.lock().unwrap().puts.clone()
        }
    }

    fn merged(state: &State) -> BTreeMap<String, String> {
        let mut stored: BTreeMap<String, String> = state
            .applied
            .iter()
            .filter(|(key, _)| !state.pending_delete.contains(*key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        stored.extend(state.pending_add.clone());
        stored
    }

    fn digest_of(state: &State) -> String {
        format!("{:040x}", state.digest)
    }

    fn ok(data: &Value) -> (u16, Value) {
        (200, json!({ "data": data }))
    }

    fn denied(path: &str, privilege: &str) -> (u16, Value) {
        (
            403,
            json!({"errors": null, "message": format!("Permission check failed ({path}, {privilege})\n")}),
        )
    }

    const HW_GATE: &str = "VM.Config.Disk|VM.Config.CDROM|VM.Config.CPU|VM.Config.Memory|VM.Config.Network|VM.Config.HWType|VM.Config.Options|VM.Config.Cloudinit";

    impl Fake {
        #[allow(clippy::too_many_lines)] // one flat table of PVE's behaviours
        fn answer(&self, method: PveHttpMethod, path: &str, body: Option<Value>) -> (u16, Value) {
            let mut state = self.state.lock().unwrap();
            let route = path
                .strip_prefix("/api2/json/nodes/")
                .and_then(|rest| rest.split_once('/'))
                .and_then(|(node, rest)| rest.strip_prefix("qemu/").map(|rest| (node, rest)))
                .and_then(|(node, rest)| {
                    rest.split_once('/').map(|(vmid, tail)| (node, vmid, tail))
                });
            let Some((node, vmid, tail)) = route else {
                return (404, json!({"message": "no such path"}));
            };
            assert_eq!((node, vmid), (NODE, "9100"), "the fake serves one guest");
            match (method, tail) {
                (PveHttpMethod::Get, "config") => {
                    state.gets += 1;
                    if !state.has_audit {
                        return denied("/vms/9100", "VM.Audit");
                    }
                    let mut config = json!({
                        "name": "fm-fake-guest", "memory": "1024", "cores": 1,
                        "digest": digest_of(&state),
                        "hotplug": if state.hotplug_usb { "network,disk,usb" } else { "network,disk" },
                    });
                    if state.template {
                        config["template"] = json!(1);
                    }
                    if let Some(lock) = &state.lock {
                        config["lock"] = json!(lock);
                    }
                    for (key, value) in merged(&state) {
                        config[key] = json!(value);
                    }
                    if state.straddle_once {
                        state.straddle_once = false;
                        state.digest += 1;
                    }
                    ok(&config)
                }
                (PveHttpMethod::Get, "pending") => {
                    state.gets += 1;
                    let mut list = vec![
                        json!({"key": "name", "value": "fm-fake-guest"}),
                        json!({"key": "digest", "value": digest_of(&state)}),
                    ];
                    for (key, value) in &state.applied {
                        let mut item = json!({"key": key, "value": value});
                        if state.pending_delete.contains(key) {
                            item["delete"] = json!(1);
                        } else if let Some(next) = state.pending_add.get(key) {
                            item["pending"] = json!(next);
                        }
                        list.push(item);
                    }
                    for (key, value) in &state.pending_add {
                        if !state.applied.contains_key(key) {
                            list.push(json!({"key": key, "pending": value}));
                        }
                    }
                    ok(&Value::Array(list))
                }
                (PveHttpMethod::Put, "config") => {
                    let body = body.expect("a PUT has a body");
                    state.puts.push(body.clone());
                    if state.bump_before_put {
                        state.bump_before_put = false;
                        state.digest += 1;
                    }
                    let object = body.as_object().expect("an object body");
                    let delete = object.get("delete").and_then(Value::as_str);
                    let add = object.iter().find(|(key, _)| key.starts_with("usb"));
                    // Permissions first, as qemu-server's check does.
                    if !state.has_hwtype {
                        return denied("/vms/9100", HW_GATE);
                    }
                    if let Some((_, value)) = add {
                        let mapping = mapping_of(value.as_str().unwrap()).unwrap().to_owned();
                        if !state.has_mapping_use {
                            return denied(&format!("/mapping/usb/{mapping}"), "Mapping.Use");
                        }
                    }
                    if let Some(key) = delete {
                        let held = merged(&state)
                            .get(key)
                            .cloned()
                            .or_else(|| state.applied.get(key).cloned());
                        if let Some(mapping) = held.as_deref().and_then(mapping_of)
                            && (!state.has_mapping_use || state.deny_delete)
                        {
                            return denied(&format!("/mapping/usb/{mapping}"), "Mapping.Use");
                        }
                    }
                    if let Some(lock) = &state.lock {
                        return (500, json!({"message": format!("VM is locked ({lock})")}));
                    }
                    if object.get("digest").and_then(Value::as_str) != Some(&digest_of(&state)) {
                        return (
                            500,
                            json!({"message": "checksum mismatch (file change by other user?)"}),
                        );
                    }
                    if state.lose_put_answer {
                        // The change lands; the answer does not.
                        state.lose_put_answer = false;
                        apply(&mut state, object);
                        return (0, Value::Null);
                    }
                    if let Some((status, answer)) = state.fail_next_put.take() {
                        if state.leave_leftover
                            && let Some((key, value)) = add
                        {
                            let left = state
                                .leftover_value
                                .clone()
                                .unwrap_or_else(|| value.as_str().unwrap().to_owned());
                            state.pending_add.insert(key.clone(), left);
                            state.digest += 1;
                        }
                        return (status, answer);
                    }
                    if !state.drop_writes {
                        apply(&mut state, object);
                    }
                    ok(&Value::Null)
                }
                other => panic!("unexpected call {other:?}"),
            }
        }
    }

    fn apply(state: &mut State, object: &serde_json::Map<String, Value>) {
        let hold_back = state.running && !state.hotplug_usb;
        for (key, value) in object {
            if let (true, Some(value)) = (key.starts_with("usb"), value.as_str()) {
                if hold_back {
                    state.pending_add.insert(key.clone(), value.to_owned());
                } else {
                    state.applied.insert(key.clone(), value.to_owned());
                }
            } else if key == "delete" {
                let key = value.as_str().unwrap().to_owned();
                if state.pending_add.remove(&key).is_some() {
                    // A queued add is simply cancelled.
                } else if hold_back {
                    state.pending_delete.insert(key);
                } else {
                    state.applied.remove(&key);
                }
            }
        }
        state.digest += 1;
    }

    #[async_trait]
    impl PveTransport for Fake {
        async fn execute(
            &self,
            request: PveHttpRequest,
        ) -> Result<PveHttpResponse, PveTransportError> {
            let (status, body) = self.answer(request.method, &request.path, None);
            Ok(PveHttpResponse {
                status,
                body: body.to_string().into_bytes(),
            })
        }

        async fn execute_with_body(
            &self,
            request: PveHttpRequest,
            body: Vec<u8>,
        ) -> Result<PveHttpResponse, PveTransportError> {
            let (status, answer) = self.answer(
                request.method,
                &request.path,
                Some(serde_json::from_slice(&body).unwrap()),
            );
            if status == 0 {
                return Err(PveTransportError::Connect {
                    detail: "connection reset".to_owned(),
                });
            }
            Ok(PveHttpResponse {
                status,
                body: answer.to_string().into_bytes(),
            })
        }
    }

    async fn attach(fake: &Arc<Fake>, mapping: &str) -> Result<PveUsbOutcome, PveUsbError> {
        fake.client()
            .qemu_usb_attach(request(), NODE, VMID, mapping)
            .await
    }

    async fn detach(
        fake: &Arc<Fake>,
        slot: &str,
        mapping: &str,
    ) -> Result<PveUsbOutcome, PveUsbError> {
        fake.client()
            .qemu_usb_detach(request(), NODE, VMID, slot, mapping)
            .await
    }

    fn value(mapping: &str) -> String {
        format!("mapping={mapping}")
    }

    fn running_hotplug_off(state: &mut State) {
        state.running = true;
        state.hotplug_usb = false;
    }

    // -- Attach ---------------------------------------------------------------

    #[tokio::test]
    async fn attach_writes_the_lowest_free_slot_under_the_digest_and_reads_it_back() {
        let fake = Fake::new().with(|state| {
            state.applied.insert("usb0".into(), value(OTHER));
            state.applied.insert("usb2".into(), value("fm-other"));
        });
        let before = fake.state.lock().unwrap().digest;
        let outcome = attach(&fake, MAPPING).await.unwrap();
        assert_eq!(outcome.slot, "usb1");
        assert_eq!(outcome.change, PveUsbChange::Written);
        assert_eq!(outcome.state, PveUsbState::Applied);
        assert_eq!(outcome.observed.as_deref(), Some("mapping=fm-test-reader"));
        assert_eq!(fake.stored()["usb1"], "mapping=fm-test-reader");
        // The two foreign slots were not touched.
        assert_eq!(fake.stored()["usb0"], value(OTHER));
        assert_eq!(fake.stored()["usb2"], "mapping=fm-other");
        // The write named the digest that was read, and only that slot.
        let puts = fake.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(
            puts[0],
            json!({"usb1": "mapping=fm-test-reader", "digest": format!("{before:040x}")})
        );
        // The digest returned is the one read back, after the write.
        assert_eq!(outcome.digest, digest_of(&fake.state.lock().unwrap()));
        assert_ne!(outcome.digest, format!("{before:040x}"));
    }

    #[tokio::test]
    async fn attach_to_a_running_guest_with_usb_hotplug_is_applied_at_once() {
        let fake = Fake::new().with(|state| state.running = true);
        let outcome = attach(&fake, MAPPING).await.unwrap();
        assert_eq!(outcome.state, PveUsbState::Applied);
        assert_eq!(fake.applied()["usb0"], "mapping=fm-test-reader");
    }

    #[tokio::test]
    async fn attach_to_a_running_guest_without_usb_hotplug_is_reported_pending() {
        let fake = Fake::new().with(running_hotplug_off);
        let outcome = attach(&fake, MAPPING).await.unwrap();
        assert_eq!(outcome.change, PveUsbChange::Written);
        assert_eq!(outcome.state, PveUsbState::Pending);
        // The stored config has it; the running guest does not.
        assert_eq!(fake.stored()["usb0"], "mapping=fm-test-reader");
        assert!(fake.applied().is_empty());
    }

    #[tokio::test]
    async fn attach_is_idempotent_and_does_not_write_twice() {
        let fake = Fake::new();
        let first = attach(&fake, MAPPING).await.unwrap();
        let again = attach(&fake, MAPPING).await.unwrap();
        assert_eq!(again.slot, first.slot);
        assert_eq!(again.change, PveUsbChange::Unchanged);
        assert_eq!(again.state, PveUsbState::Applied);
        assert_eq!(fake.puts().len(), 1);
    }

    #[tokio::test]
    async fn attach_retried_on_a_pending_entry_stays_pending_without_a_write() {
        let fake = Fake::new().with(running_hotplug_off);
        attach(&fake, MAPPING).await.unwrap();
        let again = attach(&fake, MAPPING).await.unwrap();
        assert_eq!(again.change, PveUsbChange::Unchanged);
        assert_eq!(again.state, PveUsbState::Pending);
        assert_eq!(fake.puts().len(), 1);
    }

    #[tokio::test]
    async fn attach_does_not_reuse_a_slot_whose_removal_is_only_pending() {
        // usb0 still holds a device on the running guest; its removal waits
        // for a restart, so the stored config shows the slot empty.
        let fake = Fake::new().with(|state| {
            running_hotplug_off(state);
            state.applied.insert("usb0".into(), value(OTHER));
            state.pending_delete.insert("usb0".into());
        });
        assert!(!fake.stored().contains_key("usb0"));
        let outcome = attach(&fake, MAPPING).await.unwrap();
        assert_eq!(outcome.slot, "usb1");
    }

    #[tokio::test]
    async fn attach_refuses_a_template_and_writes_nothing() {
        let fake = Fake::new().with(|state| state.template = true);
        assert!(matches!(
            attach(&fake, MAPPING).await,
            Err(PveUsbError::Template)
        ));
        assert!(fake.puts().is_empty());
    }

    #[tokio::test]
    async fn attach_refuses_a_locked_guest_and_writes_nothing() {
        let fake = Fake::new().with(|state| state.lock = Some("clone".into()));
        match attach(&fake, MAPPING).await {
            Err(PveUsbError::Locked { lock }) => assert_eq!(lock, "clone"),
            other => panic!("{other:?}"),
        }
        assert!(fake.puts().is_empty());
    }

    #[test]
    fn write_failures_are_classified_by_what_pve_did_before_failing() {
        let http = |status, detail: &str| PveApiError::Http {
            status,
            detail: detail.to_owned(),
        };
        // A lock taken between the read and the write, and a stale digest,
        // are refusals: PVE changed nothing.
        assert!(matches!(
            classify_write_error(http(500, r#"{"message":"VM is locked (backup)"}"#)),
            WriteVerdict::Refused(PveUsbError::Locked { ref lock }) if lock == "backup"
        ));
        assert!(matches!(
            classify_write_error(http(500, "checksum mismatch (file change by other user?)")),
            WriteVerdict::Refused(PveUsbError::DigestConflict)
        ));
        assert!(matches!(
            classify_write_error(PveApiError::Forbidden {
                detail: "Permission check failed (/vms/1, VM.Audit)".to_owned()
            }),
            WriteVerdict::Refused(PveUsbError::Refused { .. })
        ));
        // A lost answer or an unreadable one may hide a write that landed.
        assert!(matches!(
            classify_write_error(PveApiError::InvalidPayload {
                detail: "x".to_owned()
            }),
            WriteVerdict::Lost(_)
        ));
        // Anything else after the checks may have left an entry.
        assert!(matches!(
            classify_write_error(http(400, "hotplug problem")),
            WriteVerdict::Failed { status: 400, .. }
        ));
        assert!(matches!(
            classify_write_error(http(500, "internal error")),
            WriteVerdict::Failed { status: 500, .. }
        ));
    }

    #[tokio::test]
    async fn attach_with_every_slot_taken_is_refused_and_writes_nothing() {
        let fake = Fake::new().with(|state| {
            for index in 0..MAX_USB_SLOTS {
                state
                    .applied
                    .insert(format!("usb{index}"), value(&format!("fm-held-{index}")));
            }
        });
        match attach(&fake, MAPPING).await {
            Err(PveUsbError::SlotsFull { slots }) => assert_eq!(slots, MAX_USB_SLOTS),
            other => panic!("{other:?}"),
        }
        assert!(fake.puts().is_empty());
    }

    #[tokio::test]
    async fn a_digest_conflict_writes_nothing() {
        let fake = Fake::new().with(|state| {
            state.bump_before_put = true;
            state.applied.insert("usb0".into(), value(OTHER));
        });
        let before = fake.stored();
        assert!(matches!(
            attach(&fake, MAPPING).await,
            Err(PveUsbError::DigestConflict)
        ));
        assert_eq!(fake.stored(), before);
        assert_eq!(fake.puts().len(), 1, "no cleanup write follows a conflict");
    }

    #[tokio::test]
    async fn a_missing_mapping_use_is_a_named_refusal_and_writes_nothing() {
        let fake = Fake::new().with(|state| state.has_mapping_use = false);
        match attach(&fake, MAPPING).await {
            Err(PveUsbError::Refused { privilege, .. }) => {
                let privilege = privilege.expect("PVE names the privilege");
                assert_eq!(privilege.path, "/mapping/usb/fm-test-reader");
                assert_eq!(privilege.privilege, "Mapping.Use");
            }
            other => panic!("{other:?}"),
        }
        assert!(fake.stored().is_empty());
        assert_eq!(fake.puts().len(), 1, "no cleanup write follows a refusal");
    }

    #[tokio::test]
    async fn a_missing_vm_config_privilege_is_a_refusal() {
        let fake = Fake::new().with(|state| state.has_hwtype = false);
        match attach(&fake, MAPPING).await {
            Err(PveUsbError::Refused { privilege, .. }) => {
                let privilege = privilege.unwrap();
                assert_eq!(privilege.path, "/vms/9100");
                assert!(privilege.privilege.contains("VM.Config.HWType"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_token_that_cannot_read_the_guest_is_refused_before_any_write() {
        let fake = Fake::new().with(|state| state.has_audit = false);
        assert!(matches!(
            attach(&fake, MAPPING).await,
            Err(PveUsbError::Refused { .. })
        ));
        assert!(fake.puts().is_empty());
    }

    #[tokio::test]
    async fn a_failed_hotplug_removes_the_entry_it_left_behind() {
        let fake = Fake::new().with(|state| {
            state.running = true;
            state.leave_leftover = true;
            state.fail_next_put = Some((
                400,
                json!({"message": "Parameter verification failed.",
                       "errors": {"usb0": "hotplug problem - USB Mapping invalid (hardware probably changed): usb device '1-55' not found"}}),
            ));
        });
        match attach(&fake, MAPPING).await {
            Err(PveUsbError::WriteFailed {
                slot,
                status,
                detail,
                cleanup,
            }) => {
                assert_eq!((slot.as_str(), status), ("usb0", 400));
                assert!(detail.contains("hotplug problem"), "{detail}");
                assert_eq!(cleanup, PveUsbCleanup::Removed);
            }
            other => panic!("{other:?}"),
        }
        assert!(fake.stored().is_empty(), "the leftover entry is gone");
        // The cleanup delete was itself conditional on a fresh digest.
        let puts = fake.puts();
        assert_eq!(puts.len(), 2);
        assert_eq!(puts[1]["delete"], "usb0");
        assert_ne!(puts[1]["digest"], puts[0]["digest"]);
    }

    #[tokio::test]
    async fn a_failed_write_that_left_nothing_reports_nothing_to_remove() {
        let fake = Fake::new().with(|state| {
            state.fail_next_put = Some((400, json!({"message": "Parameter verification failed."})));
        });
        match attach(&fake, MAPPING).await {
            Err(PveUsbError::WriteFailed { cleanup, .. }) => {
                assert_eq!(cleanup, PveUsbCleanup::NothingToRemove);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(fake.puts().len(), 1);
    }

    #[tokio::test]
    async fn a_cleanup_that_cannot_run_is_reported_so_the_caller_keeps_its_reservation() {
        let fake = Fake::new().with(|state| {
            state.leave_leftover = true;
            state.deny_delete = true;
            state.fail_next_put = Some((400, json!({"message": "hotplug problem"})));
        });
        match attach(&fake, MAPPING).await {
            Err(PveUsbError::WriteFailed { cleanup, .. }) => match cleanup {
                PveUsbCleanup::Failed { detail } => {
                    assert!(detail.contains("Mapping.Use"), "{detail}");
                }
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        }
        assert_eq!(fake.stored()["usb0"], "mapping=fm-test-reader");
    }

    #[tokio::test]
    async fn cleanup_never_removes_a_slot_holding_another_value() {
        // PVE failed, and by the time the guest is read again the slot holds
        // an operator's own entry, not the one Fleet wrote.
        let fake = Fake::new().with(|state| {
            state.leave_leftover = true;
            state.leftover_value = Some("mapping=operator-device,usb3=1".into());
            state.fail_next_put = Some((400, json!({"message": "hotplug problem"})));
        });
        match attach(&fake, MAPPING).await {
            Err(PveUsbError::WriteFailed { cleanup, .. }) => match cleanup {
                PveUsbCleanup::Failed { detail } => {
                    assert!(detail.contains("did not write"), "{detail}");
                }
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        }
        assert_eq!(fake.stored()["usb0"], "mapping=operator-device,usb3=1");
        assert_eq!(fake.puts().len(), 1, "no delete was sent");
    }

    #[tokio::test]
    async fn a_lost_answer_is_indeterminate_and_a_retry_finds_the_entry() {
        let fake = Fake::new().with(|state| state.lose_put_answer = true);
        match attach(&fake, MAPPING).await {
            Err(PveUsbError::Indeterminate { slot, .. }) => {
                assert_eq!(slot.as_deref(), Some("usb0"));
            }
            other => panic!("{other:?}"),
        }
        // The write landed although the answer did not.
        let retry = attach(&fake, MAPPING).await.unwrap();
        assert_eq!(retry.change, PveUsbChange::Unchanged);
        assert_eq!(retry.slot, "usb0");
        assert_eq!(fake.puts().len(), 1);
    }

    #[tokio::test]
    async fn a_read_back_that_disagrees_is_an_error_not_a_success() {
        let fake = Fake::new().with(|state| state.drop_writes = true);
        match attach(&fake, MAPPING).await {
            Err(PveUsbError::ReadBackMismatch { slot, observed }) => {
                assert_eq!(slot, "usb0");
                assert_eq!(observed, None);
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn the_guest_already_referencing_the_mapping_in_a_form_fleet_does_not_write_is_left_alone()
     {
        let fake = Fake::new().with(|state| {
            state
                .applied
                .insert("usb0".into(), "mapping=fm-test-reader,usb3=1".into());
        });
        match attach(&fake, MAPPING).await {
            Err(PveUsbError::ForeignSlot { slot, observed }) => {
                assert_eq!(slot, "usb0");
                assert_eq!(observed, "mapping=fm-test-reader,usb3=1");
            }
            other => panic!("{other:?}"),
        }
        assert!(fake.puts().is_empty());
    }

    #[tokio::test]
    async fn two_slots_holding_the_mapping_are_ambiguous() {
        let fake = Fake::new().with(|state| {
            state.applied.insert("usb0".into(), value(MAPPING));
            state.applied.insert("usb3".into(), value(MAPPING));
        });
        match attach(&fake, MAPPING).await {
            Err(PveUsbError::Ambiguous { slots }) => assert_eq!(slots, ["usb0", "usb3"]),
            other => panic!("{other:?}"),
        }
        assert!(fake.puts().is_empty());
    }

    #[tokio::test]
    async fn a_pending_removal_of_the_same_mapping_is_a_conflict_not_an_attach() {
        let fake = Fake::new().with(|state| {
            running_hotplug_off(state);
            state.applied.insert("usb0".into(), value(MAPPING));
            state.pending_delete.insert("usb0".into());
        });
        match attach(&fake, MAPPING).await {
            Err(PveUsbError::PendingConflict { slot }) => assert_eq!(slot, "usb0"),
            other => panic!("{other:?}"),
        }
        assert!(fake.puts().is_empty());
    }

    #[tokio::test]
    async fn a_mapping_id_cannot_smuggle_a_property_into_the_value() {
        let fake = Fake::new();
        for id in [
            "",
            "x,host=1-7",
            "x,usb3=1",
            "x=y",
            "with space",
            "1leading-digit",
            "-dash",
            "new\nline",
            &"a".repeat(MAX_MAPPING_ID_CHARS + 1),
        ] {
            assert!(
                matches!(
                    attach(&fake, id).await,
                    Err(PveUsbError::InvalidInput { .. })
                ),
                "{id:?}"
            );
        }
        assert_eq!(fake.state.lock().unwrap().gets, 0, "nothing was even read");
        assert!(fake.puts().is_empty());
    }

    #[tokio::test]
    async fn reads_that_straddle_a_change_are_read_again() {
        let fake = Fake::new().with(|state| state.straddle_once = true);
        let outcome = attach(&fake, MAPPING).await.unwrap();
        assert_eq!(outcome.change, PveUsbChange::Written);
    }

    #[tokio::test]
    async fn a_config_without_a_digest_cannot_be_written_conditionally() {
        let snapshot = parse_snapshot(&json!({"name": "x"}), &json!([]));
        assert!(matches!(snapshot, Err(PveApiError::InvalidPayload { .. })));
    }

    #[tokio::test]
    async fn errors_never_carry_the_token_secret() {
        let fake = Fake::new().with(|state| state.has_mapping_use = false);
        let error = attach(&fake, MAPPING).await.unwrap_err();
        assert!(!format!("{error} {error:?}").contains(SECRET));
    }

    // -- Detach ---------------------------------------------------------------

    #[tokio::test]
    async fn detach_removes_the_slot_under_the_digest_and_reads_it_back() {
        let fake = Fake::new().with(|state| {
            state.applied.insert("usb0".into(), value(OTHER));
            state.applied.insert("usb1".into(), value(MAPPING));
        });
        let outcome = detach(&fake, "usb1", MAPPING).await.unwrap();
        assert_eq!(outcome.change, PveUsbChange::Written);
        assert_eq!(outcome.state, PveUsbState::Applied);
        assert_eq!(outcome.observed, None);
        assert_eq!(fake.stored().len(), 1);
        assert_eq!(fake.stored()["usb0"], value(OTHER));
        let puts = fake.puts();
        assert_eq!(puts[0]["delete"], "usb1");
        assert!(puts[0]["digest"].is_string());
    }

    #[tokio::test]
    async fn detach_is_idempotent_on_an_empty_slot() {
        let fake = Fake::new();
        let outcome = detach(&fake, "usb3", MAPPING).await.unwrap();
        assert_eq!(outcome.change, PveUsbChange::Unchanged);
        assert_eq!(outcome.state, PveUsbState::Applied);
        assert_eq!(outcome.observed, None);
        assert!(fake.puts().is_empty());
    }

    #[tokio::test]
    async fn attach_then_detach_twice_ends_empty_with_one_write_each() {
        let fake = Fake::new().with(|state| state.running = true);
        let attached = attach(&fake, MAPPING).await.unwrap();
        detach(&fake, &attached.slot, MAPPING).await.unwrap();
        let again = detach(&fake, &attached.slot, MAPPING).await.unwrap();
        assert_eq!(again.change, PveUsbChange::Unchanged);
        assert!(fake.stored().is_empty());
        assert_eq!(fake.puts().len(), 2);
    }

    #[tokio::test]
    async fn detach_from_a_running_guest_without_usb_hotplug_is_pending_until_restart() {
        let fake = Fake::new().with(|state| {
            running_hotplug_off(state);
            state.applied.insert("usb0".into(), value(MAPPING));
        });
        let outcome = detach(&fake, "usb0", MAPPING).await.unwrap();
        assert_eq!(outcome.change, PveUsbChange::Written);
        assert_eq!(outcome.state, PveUsbState::Pending);
        // The device is still on the running guest.
        assert_eq!(fake.applied()["usb0"], value(MAPPING));
        assert!(fake.stored().is_empty());
        // A retry reports the same pending state without writing again.
        let again = detach(&fake, "usb0", MAPPING).await.unwrap();
        assert_eq!(again.change, PveUsbChange::Unchanged);
        assert_eq!(again.state, PveUsbState::Pending);
        assert_eq!(again.observed.as_deref(), Some("mapping=fm-test-reader"));
        assert_eq!(fake.puts().len(), 1);
    }

    #[tokio::test]
    async fn detach_cancels_an_attach_that_is_still_pending() {
        let fake = Fake::new().with(running_hotplug_off);
        let attached = attach(&fake, MAPPING).await.unwrap();
        assert_eq!(attached.state, PveUsbState::Pending);
        let outcome = detach(&fake, &attached.slot, MAPPING).await.unwrap();
        assert_eq!(outcome.state, PveUsbState::Applied);
        assert!(fake.stored().is_empty());
    }

    #[tokio::test]
    async fn detach_never_deletes_a_slot_fleet_did_not_write() {
        let foreign = [
            // Another mapping.
            ("usb0", value(OTHER)),
            // The same mapping as an operator writes it, with options.
            ("usb1", "mapping=fm-test-reader,usb3=1".to_owned()),
            // A raw device.
            ("usb2", "host=1-7".to_owned()),
            ("usb3", "host=05ac:1500".to_owned()),
        ];
        for (slot, held) in foreign {
            let fake = Fake::new().with(|state| {
                state.running = true;
                state.applied.insert(slot.to_owned(), held.clone());
            });
            let before = fake.stored();
            match detach(&fake, slot, MAPPING).await {
                Err(PveUsbError::ForeignSlot {
                    slot: named,
                    observed,
                }) => {
                    assert_eq!(named, slot);
                    assert_eq!(observed, held);
                }
                other => panic!("{slot}: {other:?}"),
            }
            assert_eq!(fake.stored(), before, "{slot} is untouched");
            assert!(fake.puts().is_empty(), "{slot}: no write was sent");
        }
    }

    #[tokio::test]
    async fn detach_names_the_slot_it_deletes_and_no_other() {
        let fake = Fake::new().with(|state| {
            state.applied.insert("usb0".into(), value(MAPPING));
            state.applied.insert("usb1".into(), value(MAPPING));
        });
        detach(&fake, "usb1", MAPPING).await.unwrap();
        assert_eq!(fake.stored().keys().collect::<Vec<_>>(), ["usb0"]);
    }

    #[tokio::test]
    async fn detach_refuses_a_template_and_a_locked_guest() {
        let template = Fake::new().with(|state| {
            state.template = true;
            state.applied.insert("usb0".into(), value(MAPPING));
        });
        assert!(matches!(
            detach(&template, "usb0", MAPPING).await,
            Err(PveUsbError::Template)
        ));
        assert!(template.puts().is_empty());

        let locked = Fake::new().with(|state| {
            state.lock = Some("snapshot".into());
            state.applied.insert("usb0".into(), value(MAPPING));
        });
        assert!(matches!(
            detach(&locked, "usb0", MAPPING).await,
            Err(PveUsbError::Locked { .. })
        ));
        assert!(locked.puts().is_empty());
    }

    #[tokio::test]
    async fn a_detach_needs_mapping_use_and_says_so() {
        let fake = Fake::new().with(|state| {
            state.applied.insert("usb0".into(), value(MAPPING));
            state.has_mapping_use = false;
        });
        match detach(&fake, "usb0", MAPPING).await {
            Err(PveUsbError::Refused { privilege, .. }) => {
                assert_eq!(privilege.unwrap().privilege, "Mapping.Use");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(fake.stored()["usb0"], value(MAPPING));
    }

    #[tokio::test]
    async fn a_detach_digest_conflict_deletes_nothing() {
        let fake = Fake::new().with(|state| {
            state.bump_before_put = true;
            state.applied.insert("usb0".into(), value(MAPPING));
        });
        assert!(matches!(
            detach(&fake, "usb0", MAPPING).await,
            Err(PveUsbError::DigestConflict)
        ));
        assert_eq!(fake.stored()["usb0"], value(MAPPING));
    }

    #[tokio::test]
    async fn a_detach_whose_read_back_still_shows_the_entry_is_not_a_success() {
        let fake = Fake::new().with(|state| {
            state.drop_writes = true;
            state.applied.insert("usb0".into(), value(MAPPING));
        });
        match detach(&fake, "usb0", MAPPING).await {
            Err(PveUsbError::ReadBackMismatch { observed, .. }) => {
                assert_eq!(observed.as_deref(), Some("mapping=fm-test-reader"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_lost_detach_answer_is_indeterminate_and_a_retry_confirms_it() {
        let fake = Fake::new().with(|state| {
            state.lose_put_answer = true;
            state.applied.insert("usb0".into(), value(MAPPING));
        });
        assert!(matches!(
            detach(&fake, "usb0", MAPPING).await,
            Err(PveUsbError::Indeterminate { .. })
        ));
        let retry = detach(&fake, "usb0", MAPPING).await.unwrap();
        assert_eq!(retry.change, PveUsbChange::Unchanged);
        assert_eq!(retry.state, PveUsbState::Applied);
    }

    #[tokio::test]
    async fn a_detach_rejects_slots_that_are_not_usb_slots() {
        let fake = Fake::new();
        for slot in [
            "", "usb", "usb14", "usb01", "usb-1", "usb+1", "host", "scsi0", "usb0 ",
        ] {
            assert!(
                matches!(
                    detach(&fake, slot, MAPPING).await,
                    Err(PveUsbError::InvalidInput { .. })
                ),
                "{slot:?}"
            );
        }
        assert!(matches!(
            detach(&fake, "usb0", "bad,id").await,
            Err(PveUsbError::InvalidInput { .. })
        ));
        assert_eq!(fake.state.lock().unwrap().gets, 0);
    }

    #[test]
    fn slot_indexes_and_values_parse_strictly() {
        assert_eq!(slot_index("usb0"), Some(0));
        assert_eq!(slot_index("usb13"), Some(13));
        assert_eq!(slot_index("usb14"), None);
        assert_eq!(slot_index("usb00"), None);
        assert_eq!(mapping_of("mapping=a,usb3=1"), Some("a"));
        assert_eq!(mapping_of("usb3=1,mapping=a"), Some("a"));
        assert_eq!(mapping_of("host=1-7"), None);
    }

    // -- Fixture contract tests ------------------------------------------------
    //
    // Replays of the FM-S11 recordings (`docs/research/fixtures/proxmox-usb`),
    // which are real responses of PVE 9.2.2 and 8.4.0, sanitized. The
    // recordings are read in place so there is one copy of them.

    macro_rules! recording {
        ($major:literal, $name:literal) => {
            serde_json::from_str::<Value>(include_str!(concat!(
                "../../../../docs/research/fixtures/proxmox-usb/pve-",
                $major,
                "/",
                $name,
                ".json"
            )))
            .expect("a recording is JSON")
        };
    }

    /// One step of a replay: the request the provider must make and the
    /// recorded answer.
    struct Step {
        method: PveHttpMethod,
        path: String,
        /// The PUT body without its digest, when the step is a write.
        params: Option<Value>,
        digest: Option<String>,
        status: u16,
        body: Value,
    }

    /// A recorded exchange as a replay step. A 2xx answer is the recording's
    /// `response` under PVE's `data` envelope; an error answer is the
    /// recorded body as is.
    fn step(recording: &Value, digest: Option<&str>) -> Step {
        let request = &recording["request"];
        let method = match request["method"].as_str().unwrap() {
            "GET" => PveHttpMethod::Get,
            "PUT" => PveHttpMethod::Put,
            other => panic!("unexpected recorded method {other}"),
        };
        let status = u16::try_from(recording["http_status"].as_u64().unwrap()).unwrap();
        let body = if (200..300).contains(&status) {
            json!({ "data": recording["response"] })
        } else {
            recording["response"].clone()
        };
        Step {
            method,
            path: format!(
                "/api2/json{}",
                request["path"]
                    .as_str()
                    .unwrap()
                    .replace("/nodes/pve8/", "/nodes/pve9-n1/")
                    .replace("/nodes/pve/", "/nodes/pve9-n1/")
            ),
            params: (method == PveHttpMethod::Put).then(|| request["params"].clone()),
            digest: digest.map(str::to_owned),
            status,
            body,
        }
    }

    /// Serves the recorded steps in order and fails on any other request.
    #[derive(Debug)]
    struct Replay {
        steps: Mutex<std::collections::VecDeque<Step>>,
    }

    impl std::fmt::Debug for Step {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{:?} {}", self.method, self.path)
        }
    }

    impl Replay {
        fn new(steps: Vec<Step>) -> Arc<Self> {
            Arc::new(Self {
                steps: Mutex::new(steps.into()),
            })
        }

        fn next(&self, request: &PveHttpRequest, body: Option<Value>) -> PveHttpResponse {
            let step = self.steps.lock().unwrap().pop_front().unwrap_or_else(|| {
                panic!(
                    "unexpected request {} {}",
                    request.method as u8, request.path
                )
            });
            assert_eq!(
                (request.method, request.path.as_str()),
                (step.method, step.path.as_str())
            );
            if let Some(expected) = &step.params {
                let mut sent = body.expect("a write has a body");
                let digest = sent.as_object_mut().unwrap().remove("digest");
                assert_eq!(&sent, expected, "the write matches the recording");
                if let Some(want) = &step.digest {
                    assert_eq!(
                        digest,
                        Some(json!(want)),
                        "the write is conditional on the digest read"
                    );
                }
            }
            PveHttpResponse {
                status: step.status,
                body: step.body.to_string().into_bytes(),
            }
        }

        fn done(&self) {
            assert!(self.steps.lock().unwrap().is_empty(), "every step was used");
        }
    }

    #[async_trait]
    impl PveTransport for Replay {
        async fn execute(
            &self,
            request: PveHttpRequest,
        ) -> Result<PveHttpResponse, PveTransportError> {
            Ok(self.next(&request, None))
        }

        async fn execute_with_body(
            &self,
            request: PveHttpRequest,
            body: Vec<u8>,
        ) -> Result<PveHttpResponse, PveTransportError> {
            Ok(self.next(&request, Some(serde_json::from_slice(&body).unwrap())))
        }
    }

    async fn replay_attach(
        steps: Vec<Step>,
        vmid: u32,
        mapping: &str,
    ) -> (Result<PveUsbOutcome, PveUsbError>, Arc<Replay>) {
        let replay = Replay::new(steps);
        let result = ProxmoxClient::new(replay.clone())
            .qemu_usb_attach(request(), NODE, vmid, mapping)
            .await;
        (result, replay)
    }

    async fn replay_detach(
        steps: Vec<Step>,
        vmid: u32,
        slot: &str,
        mapping: &str,
    ) -> (Result<PveUsbOutcome, PveUsbError>, Arc<Replay>) {
        let replay = Replay::new(steps);
        let result = ProxmoxClient::new(replay.clone())
            .qemu_usb_detach(request(), NODE, vmid, slot, mapping)
            .await;
        (result, replay)
    }

    fn without_usb0(recording: &Value, digest: &str) -> Value {
        let mut recording = recording.clone();
        match &mut recording["response"] {
            Value::Object(config) => {
                config.remove("usb0");
                config.insert("digest".into(), json!(digest));
            }
            Value::Array(list) => {
                list.retain(|item| item["key"] != "usb0");
                for item in list.iter_mut().filter(|item| item["key"] == "digest") {
                    item["value"] = json!(digest);
                }
            }
            other => panic!("unexpected recording shape {other:?}"),
        }
        recording
    }

    const A: &str = "fm-test-superdrive-a";

    #[tokio::test]
    async fn recorded_hotplug_attach_on_pve_9_is_written_then_read_back_applied() {
        // Pre-state: the recorded post-state without usb0 (derived).
        let pre = "00000000000000000000000000000000000000aa";
        let steps = vec![
            step(
                &without_usb0(&recording!("9.2.2", "h2-config-after-attach"), pre),
                None,
            ),
            step(
                &without_usb0(&recording!("9.2.2", "h2-pending-after-attach"), pre),
                None,
            ),
            step(
                &recording!("9.2.2", "h2-put-usb0-mapping-running"),
                Some(pre),
            ),
            step(&recording!("9.2.2", "h2-config-after-attach"), None),
            step(&recording!("9.2.2", "h2-pending-after-attach"), None),
        ];
        let (result, replay) = replay_attach(steps, 9563, A).await;
        let outcome = result.unwrap();
        assert_eq!(
            (outcome.slot.as_str(), outcome.change, outcome.state),
            ("usb0", PveUsbChange::Written, PveUsbState::Applied)
        );
        assert_eq!(outcome.digest, "576cb8843c272804a9ea5f2a93342df47352528e");
        replay.done();
    }

    #[tokio::test]
    async fn recorded_hotplug_detach_on_pve_9_is_pending_until_restart() {
        // Guest 9563 with hotplug=network,disk: usb0 applied, usb1 a queued add.
        let steps = vec![
            step(&recording!("9.2.2", "p1-config"), None),
            step(&recording!("9.2.2", "p1-pending"), None),
            step(
                &recording!("9.2.2", "p2-delete-usb0-running-hotplug-off"),
                Some("40fb8a8c07acc2dde13184e9f3821894142479b5"),
            ),
            step(&recording!("9.2.2", "p2-config"), None),
            step(&recording!("9.2.2", "p2-pending"), None),
        ];
        let (result, replay) = replay_detach(steps, 9563, "usb0", A).await;
        let outcome = result.unwrap();
        assert_eq!(
            (outcome.change, outcome.state),
            (PveUsbChange::Written, PveUsbState::Pending)
        );
        assert_eq!(
            outcome.observed.as_deref(),
            Some("mapping=fm-test-superdrive-a")
        );
        assert_eq!(outcome.digest, "97e6c8a1325c19303d32b1834a0cb1518e178f23");
        replay.done();
    }

    #[tokio::test]
    async fn a_recorded_pending_attach_is_found_again_without_a_write() {
        let steps = vec![
            step(&recording!("9.2.2", "p5-config-default"), None),
            step(&recording!("9.2.2", "p5-pending"), None),
        ];
        let (result, replay) = replay_attach(steps, 9563, A).await;
        let outcome = result.unwrap();
        assert_eq!(
            (outcome.slot.as_str(), outcome.change, outcome.state),
            ("usb0", PveUsbChange::Unchanged, PveUsbState::Pending)
        );
        replay.done();
    }

    #[tokio::test]
    async fn a_recorded_pending_delete_is_found_again_without_a_write() {
        let steps = vec![
            step(&recording!("9.2.2", "p2-config"), None),
            step(&recording!("9.2.2", "p2-pending"), None),
        ];
        let (result, replay) = replay_detach(steps, 9563, "usb0", A).await;
        let outcome = result.unwrap();
        assert_eq!(
            (outcome.change, outcome.state),
            (PveUsbChange::Unchanged, PveUsbState::Pending)
        );
        replay.done();
    }

    #[tokio::test]
    async fn a_recorded_template_is_refused() {
        // The recorded config of a converted template (t9); its pending list
        // is the recorded shape with that config's digest.
        let config = recording!("9.2.2", "t9-template-config");
        let mut pending = recording!("9.2.2", "h2-pending-after-attach");
        pending["request"]["path"] = json!("/nodes/pve/qemu/9564/pending");
        for item in pending["response"].as_array_mut().unwrap() {
            if item["key"] == "digest" {
                item["value"] = config["response"]["digest"].clone();
            }
        }
        let (result, replay) = replay_attach(
            vec![step(&config, None), step(&pending, None)],
            9564,
            "fm-test-verbatim",
        )
        .await;
        assert!(matches!(result, Err(PveUsbError::Template)), "{result:?}");
        replay.done();
    }

    #[tokio::test]
    async fn a_recorded_failed_hotplug_leaves_an_entry_that_is_removed() {
        // 9564: the recorded attach of a mapping whose port is empty answered
        // 400 and left usb0 queued (a3-config, a3-pending).
        let pre = "00000000000000000000000000000000000000bb";
        let after = "00000000000000000000000000000000000000cc";
        let steps = vec![
            step(&without_usb0(&recording!("9.2.2", "a3-config"), pre), None),
            step(&without_usb0(&recording!("9.2.2", "a3-pending"), pre), None),
            step(&recording!("9.2.2", "a3-set-absentpath-running"), Some(pre)),
            // The cleanup reads the guest, sees the leftover, deletes it
            // under the digest it just read, and reads back.
            step(&recording!("9.2.2", "a3-config"), None),
            step(&recording!("9.2.2", "a3-pending"), None),
            Step {
                method: PveHttpMethod::Put,
                path: "/api2/json/nodes/pve9-n1/qemu/9564/config".to_owned(),
                params: Some(json!({"delete": "usb0"})),
                digest: Some("8d14d706f6117d7b10836a3dd896907c2f462864".to_owned()),
                status: 200,
                body: json!({"data": null}),
            },
            step(
                &without_usb0(&recording!("9.2.2", "a3-config"), after),
                None,
            ),
            step(
                &without_usb0(&recording!("9.2.2", "a3-pending"), after),
                None,
            ),
        ];
        let (result, replay) = replay_attach(steps, 9564, "fm-test-tmp-absentpath").await;
        match result {
            Err(PveUsbError::WriteFailed {
                slot,
                status,
                detail,
                cleanup,
            }) => {
                assert_eq!((slot.as_str(), status), ("usb0", 400));
                assert!(detail.contains("hotplug problem"), "{detail}");
                assert_eq!(cleanup, PveUsbCleanup::Removed);
            }
            other => panic!("{other:?}"),
        }
        replay.done();
    }

    #[tokio::test]
    async fn a_recorded_stale_digest_is_a_conflict_for_attach_and_detach() {
        // The recorded refusals (k3, k4): 500 "checksum mismatch".
        let pre = "00000000000000000000000000000000000000dd";
        let steps = vec![
            step(
                &without_usb0(&recording!("9.2.2", "h2-config-after-attach"), pre),
                None,
            ),
            step(
                &without_usb0(&recording!("9.2.2", "h2-pending-after-attach"), pre),
                None,
            ),
            step(&recording!("9.2.2", "k3-attach-stale-digest"), None),
        ];
        // The recorded write named usb1; ours names usb0, so compare loosely
        // by replaying only the recorded answer.
        let mut steps = steps;
        steps[2].params = None;
        let (result, replay) = replay_attach(steps, 9563, "fm-test-superdrive-b").await;
        assert!(
            matches!(result, Err(PveUsbError::DigestConflict)),
            "{result:?}"
        );
        replay.done();

        let steps = vec![
            step(&recording!("9.2.2", "h2-config-after-attach"), None),
            step(&recording!("9.2.2", "h2-pending-after-attach"), None),
            {
                let mut write = step(&recording!("9.2.2", "k4-delete-stale-digest"), None);
                write.params = Some(json!({"delete": "usb0"}));
                write
            },
        ];
        let (result, replay) = replay_detach(steps, 9563, "usb0", A).await;
        assert!(
            matches!(result, Err(PveUsbError::DigestConflict)),
            "{result:?}"
        );
        replay.done();
    }

    #[tokio::test]
    async fn recorded_refusals_name_the_privilege_for_attach_and_detach() {
        // pr6: a token with no VM.Config.* privilege at all is stopped by
        // PVE's generic gate, which names every alternative.
        let pre = "00000000000000000000000000000000000000ee";
        let steps = vec![
            step(
                &without_usb0(&recording!("9.2.2", "h2-config-after-attach"), pre),
                None,
            ),
            step(
                &without_usb0(&recording!("9.2.2", "h2-pending-after-attach"), pre),
                None,
            ),
            step(&recording!("9.2.2", "pr6-privsep-token-no-acl"), Some(pre)),
        ];
        let (result, replay) = replay_attach(steps, 9563, A).await;
        match result {
            Err(PveUsbError::Refused { privilege, .. }) => {
                let privilege = privilege.unwrap();
                assert_eq!(privilege.path, "/vms/9563");
                assert!(privilege.privilege.contains("VM.Config.HWType"));
            }
            other => panic!("{other:?}"),
        }
        replay.done();

        // pr5: VM.Config.HWType but no Mapping.Use on the mapping.
        let steps = vec![
            step(
                &without_usb0(&recording!("9.2.2", "h2-config-after-attach"), pre),
                None,
            ),
            step(
                &without_usb0(&recording!("9.2.2", "h2-pending-after-attach"), pre),
                None,
            ),
            step(&recording!("9.2.2", "pr5-hotplug-no-use"), Some(pre)),
        ];
        let (result, replay) = replay_attach(steps, 9563, A).await;
        match result {
            Err(PveUsbError::Refused { privilege, .. }) => {
                let privilege = privilege.unwrap();
                assert_eq!(privilege.path, "/mapping/usb/fm-test-superdrive-a");
                assert_eq!(privilege.privilege, "Mapping.Use");
            }
            other => panic!("{other:?}"),
        }
        replay.done();

        // pw5: a detach with VM.Config.HWType only is refused for Mapping.Use.
        let steps = vec![
            step(&recording!("9.2.2", "h2-config-after-attach"), None),
            step(&recording!("9.2.2", "h2-pending-after-attach"), None),
            step(&recording!("9.2.2", "pw5-delete-usb-hwtype-only"), None),
        ];
        let (result, replay) = replay_detach(steps, 9563, "usb0", A).await;
        match result {
            Err(PveUsbError::Refused { privilege, .. }) => {
                let privilege = privilege.unwrap();
                assert_eq!(privilege.path, "/mapping/usb/fm-test-superdrive-b");
                assert_eq!(privilege.privilege, "Mapping.Use");
            }
            other => panic!("{other:?}"),
        }
        replay.done();
    }

    #[tokio::test]
    async fn pve_8_4_recordings_behave_like_9_2_2() {
        const TABLET: &str = "fm-test-tablet-path";
        // Applied attach found again: no write.
        let steps = vec![
            step(&recording!("8.4.0", "h8-config"), None),
            step(&recording!("8.4.0", "h8-pending"), None),
        ];
        let (result, replay) = replay_attach(steps, 9563, TABLET).await;
        let outcome = result.unwrap();
        assert_eq!(
            (outcome.slot.as_str(), outcome.change, outcome.state),
            ("usb0", PveUsbChange::Unchanged, PveUsbState::Applied)
        );
        replay.done();

        // hotplug without usb: the recorded pending list is the authority
        // even though the config's current view has no usb0.
        let steps = vec![
            step(&recording!("8.4.0", "p8-config-current1"), None),
            step(&recording!("8.4.0", "p8-pending"), None),
        ];
        let (result, replay) = replay_attach(steps, 9563, TABLET).await;
        let outcome = result.unwrap();
        assert_eq!(
            (outcome.change, outcome.state),
            (PveUsbChange::Unchanged, PveUsbState::Pending)
        );
        replay.done();

        // An entry an operator wrote with options is not Fleet's to delete.
        let steps = vec![
            step(&recording!("8.4.0", "h8-config-after-detach"), None),
            step(&recording!("8.4.0", "h8-pending-after-detach"), None),
        ];
        let (result, replay) = replay_detach(steps, 9563, "usb1", "fm-test-tablet-id").await;
        match result {
            Err(PveUsbError::ForeignSlot { slot, observed }) => {
                assert_eq!(slot, "usb1");
                assert_eq!(observed, "mapping=fm-test-tablet-id,usb3=1");
            }
            other => panic!("{other:?}"),
        }
        replay.done();
    }
}
