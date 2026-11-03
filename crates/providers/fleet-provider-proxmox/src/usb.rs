//! Read-only USB reads: the cluster resource mappings and the node USB
//! inventory (FM-1110, M11).
//!
//! The shapes, privileges and failure modes below were measured by the
//! FM-S11 spike (`docs/research/proxmox-usb.md`) on PVE 8.4.0 and 9.2.2; the
//! shapes are identical on both, so there is one normalizer, not one per
//! major. What the spike established, and what this module does with it:
//!
//! - `GET /cluster/mapping/usb` (optionally `?check-node=<node>`) lists the
//!   mappings. Each `map` entry is a property string
//!   `node=<node>,id=<vendor:product>[,path=<bus>-<usbpath>]`; `id` is
//!   mandatory. With `check-node`, every item also carries `errors[]` of
//!   `{message, severity}`, which is how the presence and the fingerprint of
//!   a device are known without the node inventory. The listing needs
//!   `Mapping.Audit`; **without it PVE answers an empty `200`, not an
//!   error**, so an empty list proves nothing about privileges. The
//!   distinguishing probe is a per-mapping read ([`ProxmoxClient::usb_mapping`]),
//!   which answers 403 without the privilege.
//! - `GET /nodes/{node}/hardware/usb` needs `Sys.Modify` on `/`, which no
//!   read-only role holds, so a 403 here is the normal case for the base
//!   Fleet token and not a fault. Its items carry no serial, and `usbpath`
//!   only on devices that are not root hubs.
//! - The endpoints are absent on a PVE that predates resource mappings;
//!   PVE answers 501 `Method '…' not implemented` (404 is treated the same
//!   way). No old-PVE answer was recorded by the spike, so that case is
//!   covered by a synthetic test.
//! - `check-node` messages are decorated (the recordings carry an
//!   `Invalid configuration: ` prefix and a trailing newline on device
//!   errors, none on the node warning); they are normalized and classified
//!   into [`PveUsbCheckKind`], with the text kept.
//!
//! Decoding is tolerant and bounded, like the rest of the provider: a
//! malformed entry becomes a bounded warning and never fails the list; every
//! list is capped, and a capped list says so (`truncated`) instead of passing
//! as complete. A mapping some of whose `map` entries could not be read
//! carries a non-zero `unreadable_entries`, so a consumer never mistakes a
//! partly read mapping for a clean one. Identity fields (ids, node names,
//! ports) that are malformed or over-long are refused, never repaired;
//! display strings are flattened, redacted and truncated.
//!
//! Nothing here writes. Errors never carry the token: the detail is the
//! bounded, redacted API body the other reads already use.

use std::collections::BTreeSet;
use std::fmt;

use super::{
    ProxmoxClient, PveApiError, PveHttpMethod, PveHttpRequest, bounded_str, loose_number,
    safe_node_path_segment, type_name_of, urlencode,
};

/// The most mappings kept from one listing; the rest is reported as
/// truncated. Mappings are operator-made, so a cluster has a handful.
pub const MAX_USB_MAPPINGS: usize = 256;

/// The most `map` entries kept per mapping (one per node at most).
pub const MAX_USB_MAP_ENTRIES: usize = 64;

/// The most check issues kept per mapping.
pub const MAX_USB_CHECK_ISSUES: usize = 16;

/// The most devices kept from one node's inventory.
pub const MAX_USB_DEVICES: usize = 1024;

/// The most rows examined in one answer, whatever they contain. Rows past
/// this are counted and never parsed, so a hostile answer costs a bounded
/// amount of work.
const MAX_ROWS_EXAMINED: usize = 4096;

/// The most warnings kept; one summarizing warning follows when exceeded.
const MAX_WARNINGS: usize = 32;

/// The longest display string kept (description, manufacturer, product,
/// check message).
const MAX_TEXT_CHARS: usize = 256;

/// The longest `map` entry or other identity string examined.
const MAX_ENTRY_CHARS: usize = 256;

/// The longest excerpt of foreign text quoted in a warning.
const MAX_EXCERPT_CHARS: usize = 64;

/// The longest privilege path or name quoted from a 403.
const MAX_PRIVILEGE_CHARS: usize = 128;

/// A read failure, classified for the caller. The base Fleet token routinely
/// causes [`Self::PermissionDenied`] on the node inventory, which is an
/// expected, explained state rather than a fault.
#[derive(Debug)]
pub enum PveUsbError {
    /// The request was refused before it was sent (a node or mapping id that
    /// is not a safe path segment).
    InvalidRequest {
        /// What was wrong, bounded.
        detail: String,
    },
    /// The credentials were refused (401).
    Unauthenticated,
    /// The token lacks a privilege (403). The node inventory needs
    /// `Sys.Modify` on `/`; a per-mapping read needs `Mapping.Audit`.
    PermissionDenied {
        /// The bounded, redacted API detail.
        detail: String,
        /// The privilege PVE named, when its message could be read.
        required: Option<PveUsbRequiredPrivilege>,
    },
    /// The endpoint does not exist: a PVE that predates USB resource
    /// mappings (or the node inventory) answers 501 or 404.
    EndpointAbsent {
        /// The PVE version, when it could be read.
        version: Option<String>,
        /// The bounded API detail.
        detail: String,
    },
    /// Anything else: a transport failure, a 5xx, an answer that is not
    /// JSON or not the expected shape. The cause keeps its own class (a
    /// certificate-pin failure stays distinguishable).
    Unreadable {
        /// The underlying failure.
        cause: PveApiError,
    },
}

/// The privilege a 403 named: `Permission check failed (<path>, <privilege>)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PveUsbRequiredPrivilege {
    /// The ACL path, e.g. `/`.
    pub path: String,
    /// The privilege (or `a|b` alternatives), e.g. `Sys.Modify`.
    pub privilege: String,
}

impl fmt::Display for PveUsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest { detail } => write!(f, "invalid USB read request: {detail}"),
            Self::Unauthenticated => write!(f, "the API token was refused (401)"),
            Self::PermissionDenied { detail, required } => match required {
                Some(required) => write!(
                    f,
                    "the token lacks {} on {}: {detail}",
                    required.privilege, required.path
                ),
                None => write!(f, "the token lacks the privilege (403): {detail}"),
            },
            Self::EndpointAbsent { version, detail } => write!(
                f,
                "this Proxmox VE ({}) has no such USB endpoint: {detail}",
                version.as_deref().unwrap_or("version unknown")
            ),
            Self::Unreadable { cause } => write!(f, "the USB answer is unreadable: {cause}"),
        }
    }
}

impl std::error::Error for PveUsbError {}

/// How serious a `check-node` finding is, as PVE states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PveUsbSeverity {
    /// `error`: the mapping would fail an attach or a start.
    Error,
    /// `warning`: for example no entry for the node.
    Warning,
    /// A severity this module does not know. Treated as not clean.
    Unknown,
}

/// What a `check-node` finding says, derived from PVE's message text. The
/// text is always kept; `Other` is the honest fallback for a message this
/// module does not recognize.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PveUsbCheckKind {
    /// `usb device '<path>' not found`: nothing is at the mapped port (or
    /// no device matches the id), i.e. the device is absent.
    DeviceNotFound,
    /// `'id' does not match for '<name>' (a != b)`: another device sits at
    /// the mapped port.
    IdMismatch,
    /// `No mapping for node <node>.`: the mapping has no entry for the node.
    NoMappingForNode,
    /// Any other message.
    Other,
}

/// One `check-node` finding for a mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PveUsbCheckIssue {
    /// PVE's severity.
    pub severity: PveUsbSeverity,
    /// The derived class.
    pub kind: PveUsbCheckKind,
    /// PVE's message, trimmed, without the `Invalid configuration: `
    /// decoration, flattened, redacted and bounded.
    pub message: String,
}

/// One `map` entry: `node=<node>,id=<vendor:product>[,path=<bus>-<usbpath>]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PveUsbMapEntry {
    /// The node the entry is for.
    pub node: String,
    /// The vendor id, four lowercase hex digits.
    pub vendor_id: String,
    /// The product id, four lowercase hex digits.
    pub product_id: String,
    /// The port, `<busnum>-<usbpath>` (e.g. `1-10`), when the entry is
    /// path-based. `None` is an id-only entry, which PVE resolves to the
    /// first matching device and does not flag as ambiguous.
    pub path: Option<String>,
}

impl PveUsbMapEntry {
    /// The `vendor:product` id as PVE writes it.
    #[must_use]
    pub fn hardware_id(&self) -> String {
        format!("{}:{}", self.vendor_id, self.product_id)
    }
}

/// One USB resource mapping, in the provider's own shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PveUsbMapping {
    /// The mapping id (the name guests reference as `mapping=<id>`).
    pub id: String,
    /// The operator's description, when set.
    pub description: Option<String>,
    /// PVE's config digest of the mapping file, when carried.
    pub digest: Option<String>,
    /// The readable `map` entries.
    pub entries: Vec<PveUsbMapEntry>,
    /// How many `map` entries were malformed or beyond the bound. Non-zero
    /// means this mapping is only partly known and must not be treated as
    /// complete.
    pub unreadable_entries: usize,
    /// The `check-node` findings, when the list was read with `check-node`.
    /// `None` means not checked (so presence is unknown); an empty list
    /// means PVE found nothing wrong.
    pub issues: Option<Vec<PveUsbCheckIssue>>,
}

impl PveUsbMapping {
    /// The entries for one node. More than one is a mapping PVE accepts at
    /// creation and refuses at attach (`More than one USB mapping per host
    /// not supported`).
    pub fn entries_for_node<'a>(
        &'a self,
        node: &'a str,
    ) -> impl Iterator<Item = &'a PveUsbMapEntry> + 'a {
        self.entries.iter().filter(move |entry| entry.node == node)
    }

    /// Whether the node check ran and PVE reported nothing at all: `Some(true)`
    /// is a pass, `Some(false)` means at least one finding (a warning such as
    /// no entry for the node is not a pass), `None` means it was not checked.
    #[must_use]
    pub fn check_passed(&self) -> Option<bool> {
        self.issues.as_ref().map(Vec::is_empty)
    }
}

/// The mapping list with the PVE version it was read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PveUsbMappings {
    /// The PVE version string, e.g. `9.2.2`.
    pub version: String,
    /// The node the list was checked against (`check-node`), when it was.
    pub checked_node: Option<String>,
    /// The mappings, sorted by id.
    pub mappings: Vec<PveUsbMapping>,
    /// Entries isolated as malformed, bounded.
    pub warnings: Vec<String>,
    /// Whether rows were dropped by the bounds; the list is then incomplete.
    pub truncated: bool,
}

impl PveUsbMappings {
    /// Whether an empty list could mean the token lacks `Mapping.Audit`.
    /// PVE answers an unprivileged listing with an empty `200`, so an empty
    /// list is "no visible mappings", not "no mappings". Settle it with a
    /// per-mapping read of an id the caller already knows
    /// ([`ProxmoxClient::usb_mapping`]). A non-empty list proves the
    /// privilege, though not that every mapping is visible: with
    /// `Mapping.Audit` on one mapping only, only that one is listed.
    #[must_use]
    pub fn could_be_unprivileged(&self) -> bool {
        self.mappings.is_empty() && !self.truncated
    }
}

/// One mapping read directly, the probe that tells a missing
/// `Mapping.Audit` (403) from an empty cluster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PveUsbMappingRead {
    /// The PVE version string.
    pub version: String,
    /// The mapping. Its `issues` are `None`: the per-mapping read has no
    /// `check-node`.
    pub mapping: PveUsbMapping,
    /// Malformed entries, bounded.
    pub warnings: Vec<String>,
}

/// One USB device from the node inventory. There is no serial: PVE does not
/// return one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PveUsbDevice {
    /// The USB bus number.
    pub busnum: u32,
    /// The device number on the bus. It changes on every enumeration and
    /// must never identify a device.
    pub devnum: u32,
    /// The vendor id, four lowercase hex digits.
    pub vendor_id: String,
    /// The product id, four lowercase hex digits.
    pub product_id: String,
    /// The port path within the bus (`usbpath`, e.g. `10` or `2.4`). Stable
    /// across re-enumeration.
    pub usbpath: String,
    /// `<busnum>-<usbpath>`, the form a mapping's `path=` uses (`1-10`).
    pub path: String,
    /// The hub tier, when carried.
    pub level: Option<u32>,
    /// The hub port, when carried.
    pub port: Option<u32>,
    /// The USB class code, when carried.
    pub class: Option<u32>,
    /// The negotiated speed in Mbit/s as PVE states it (a string such as
    /// `480`; low speed is `1.5`), when carried.
    pub speed: Option<String>,
    /// The manufacturer string, when carried, bounded.
    pub manufacturer: Option<String>,
    /// The product string, when carried, bounded.
    pub product: Option<String>,
}

impl PveUsbDevice {
    /// The `vendor:product` id as PVE writes it.
    #[must_use]
    pub fn hardware_id(&self) -> String {
        format!("{}:{}", self.vendor_id, self.product_id)
    }
}

/// A node's USB inventory with the PVE version it was read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PveUsbInventory {
    /// The PVE version string.
    pub version: String,
    /// The node read.
    pub node: String,
    /// The attachable devices (root hubs excluded), sorted by bus and
    /// device number.
    pub devices: Vec<PveUsbDevice>,
    /// How many root hubs were skipped. They cannot be attached and carry no
    /// `usbpath`.
    pub root_hubs: usize,
    /// Rows isolated as malformed, bounded.
    pub warnings: Vec<String>,
    /// Whether rows were dropped by the bounds; the inventory is then
    /// incomplete.
    pub truncated: bool,
}

impl ProxmoxClient {
    /// Reads the cluster's USB resource mappings
    /// (`GET /cluster/mapping/usb`). With `check_node`, PVE also validates
    /// every mapping against that node (`?check-node=`), which fills
    /// [`PveUsbMapping::issues`]. Read-only and bounded.
    ///
    /// # Errors
    ///
    /// [`PveUsbError`], classified. Note that a token without
    /// `Mapping.Audit` does **not** fail: it receives an empty list (see
    /// [`PveUsbMappings::could_be_unprivileged`]).
    pub async fn usb_mappings(
        &self,
        request: PveHttpRequest,
        check_node: Option<&str>,
    ) -> Result<PveUsbMappings, PveUsbError> {
        let mut path = "/api2/json/cluster/mapping/usb".to_owned();
        if let Some(node) = check_node {
            if !safe_node_path_segment(node) {
                return Err(PveUsbError::InvalidRequest {
                    detail: format!("{} is not a safe node name", excerpt(node)),
                });
            }
            path.push_str("?check-node=");
            path.push_str(&urlencode(node));
        }
        let (version, data) = self.usb_get(&request, path).await?;
        normalize_mappings(version, check_node, &data)
    }

    /// Reads one USB resource mapping (`GET /cluster/mapping/usb/{id}`).
    /// This is the probe that tells a missing `Mapping.Audit` (403,
    /// [`PveUsbError::PermissionDenied`]) from a cluster that has no
    /// mappings, which the list cannot.
    ///
    /// # Errors
    ///
    /// [`PveUsbError`], classified.
    pub async fn usb_mapping(
        &self,
        request: PveHttpRequest,
        mapping_id: &str,
    ) -> Result<PveUsbMappingRead, PveUsbError> {
        if !is_safe_mapping_id(mapping_id) {
            return Err(PveUsbError::InvalidRequest {
                detail: format!("{} is not a safe mapping id", excerpt(mapping_id)),
            });
        }
        let path = format!("/api2/json/cluster/mapping/usb/{}", urlencode(mapping_id));
        let (version, data) = self.usb_get(&request, path).await?;
        let mut warnings = Warnings::default();
        let Some(object) = data.as_object() else {
            return Err(PveUsbError::Unreadable {
                cause: PveApiError::InvalidPayload {
                    detail: format!(
                        "the mapping payload is not an object (it is a {})",
                        type_name_of(&data)
                    ),
                },
            });
        };
        // The per-mapping answer carries no `id`: the caller's id is the
        // name. A body that does carry a different one is not trusted.
        if let Some(reported) = object.get("id").and_then(serde_json::Value::as_str)
            && reported != mapping_id
        {
            return Err(PveUsbError::Unreadable {
                cause: PveApiError::InvalidPayload {
                    detail: format!(
                        "asked for mapping {} but the answer names {}",
                        excerpt(mapping_id),
                        excerpt(reported)
                    ),
                },
            });
        }
        let mapping = normalize_mapping_fields(mapping_id, &data, false, &mut warnings);
        Ok(PveUsbMappingRead {
            version,
            mapping,
            warnings: warnings.finish(),
        })
    }

    /// Reads one node's USB inventory (`GET /nodes/{node}/hardware/usb`).
    /// PVE requires `Sys.Modify` on `/` for it, which the base Fleet token
    /// does not hold: expect [`PveUsbError::PermissionDenied`], and treat the
    /// inventory as optional enrichment of what the mapping list says.
    ///
    /// # Errors
    ///
    /// [`PveUsbError`], classified.
    pub async fn usb_inventory(
        &self,
        request: PveHttpRequest,
        node: &str,
    ) -> Result<PveUsbInventory, PveUsbError> {
        if !safe_node_path_segment(node) {
            return Err(PveUsbError::InvalidRequest {
                detail: format!("{} is not a safe node name", excerpt(node)),
            });
        }
        let path = format!("/api2/json/nodes/{}/hardware/usb", urlencode(node));
        let (version, data) = self.usb_get(&request, path).await?;
        normalize_inventory(version, node, &data)
    }

    /// The version, then one GET, both classified. The version comes first:
    /// every authenticated principal may read it, it anchors provenance, and
    /// it names the PVE in an absent-endpoint error.
    async fn usb_get(
        &self,
        request: &PveHttpRequest,
        path: String,
    ) -> Result<(String, serde_json::Value), PveUsbError> {
        let version = self
            .read_version(request)
            .await
            .map_err(|error| classify(error, None))?;
        let read = PveHttpRequest {
            path,
            method: PveHttpMethod::Get,
            ..request.clone()
        };
        let data = self
            .call(read)
            .await
            .map_err(|error| classify(error, Some(&version)))?;
        Ok((version, data))
    }
}

/// Classifies a transport-level failure for the USB reads.
fn classify(error: PveApiError, version: Option<&str>) -> PveUsbError {
    match error {
        PveApiError::Auth => PveUsbError::Unauthenticated,
        PveApiError::Forbidden { detail } => PveUsbError::PermissionDenied {
            required: required_privilege(&detail),
            detail,
        },
        // PVE answers an unknown path 501 `Method '…' not implemented`.
        PveApiError::Http {
            status: 404 | 501,
            detail,
        } => PveUsbError::EndpointAbsent {
            version: version.map(str::to_owned),
            detail,
        },
        other => PveUsbError::Unreadable { cause: other },
    }
}

/// The privilege a 403 body names, from `Permission check failed (/, Sys.Modify)`.
/// `None` when the message names none (`Permission check failed`).
fn required_privilege(detail: &str) -> Option<PveUsbRequiredPrivilege> {
    const MARKER: &str = "Permission check failed (";
    let rest = &detail[detail.find(MARKER)? + MARKER.len()..];
    let (path, privilege) = rest[..rest.find(')')?].split_once(", ")?;
    if path.is_empty()
        || privilege.is_empty()
        || path.chars().count() > MAX_PRIVILEGE_CHARS
        || privilege.chars().count() > MAX_PRIVILEGE_CHARS
    {
        return None;
    }
    Some(PveUsbRequiredPrivilege {
        path: path.to_owned(),
        privilege: privilege.to_owned(),
    })
}

/// Collects warnings under [`MAX_WARNINGS`], then counts the rest.
#[derive(Default)]
struct Warnings {
    items: Vec<String>,
    dropped: usize,
}

impl Warnings {
    fn push(&mut self, warning: String) {
        if self.items.len() < MAX_WARNINGS {
            self.items.push(warning);
        } else {
            self.dropped += 1;
        }
    }

    fn finish(mut self) -> Vec<String> {
        if self.dropped > 0 {
            self.items
                .push(format!("{} more warnings were not kept", self.dropped));
        }
        self.items
    }
}

/// Foreign text made safe to show: control characters flattened, line breaks
/// and runs of whitespace collapsed to one space, URL credentials redacted,
/// cut to `max` characters (`…` marks a cut). The input is cut first so a
/// hostile string costs a bounded amount of work.
fn clean_text(value: &str, max: usize) -> String {
    let head: String = value.chars().take(max.saturating_mul(4)).collect();
    let flattened =
        fleet_core::redact_url_credentials(&fleet_core::flatten_control_characters(&head));
    let single_line = flattened.split_whitespace().collect::<Vec<_>>().join(" ");
    if single_line.chars().count() > max {
        let mut cut: String = single_line.chars().take(max).collect();
        cut.push('…');
        cut
    } else {
        single_line
    }
}

/// A bounded, single-line quote of foreign text for a warning.
fn excerpt(text: &str) -> String {
    format!("{:?}", clean_text(text, MAX_EXCERPT_CHARS))
}

/// A display string: cleaned and bounded. Display text never identifies
/// anything, so truncating it is harmless; an empty result is `None`.
fn display_text(value: &str) -> Option<String> {
    let cleaned = clean_text(value, MAX_TEXT_CHARS);
    (!cleaned.is_empty()).then_some(cleaned)
}

/// A mapping id is used as a path segment and inside `mapping=<id>`, so it
/// is held to the same safe alphabet as a node name, and bounded.
fn is_safe_mapping_id(id: &str) -> bool {
    id.chars().count() <= 64 && safe_node_path_segment(id)
}

/// `vvvv` as four lowercase hex digits.
fn hex4(value: &str) -> Option<String> {
    (value.len() == 4 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

/// `<busnum>-<usbpath>`: digits, a dash, then dot-separated digit groups
/// (PVE's `^\d+-\d+(\.\d+)*$`).
fn valid_port_path(path: &str) -> bool {
    let Some((bus, ports)) = path.split_once('-') else {
        return false;
    };
    !bus.is_empty() && bus.bytes().all(|byte| byte.is_ascii_digit()) && valid_usbpath(ports)
}

/// `10` or `2.4`: dot-separated digit groups.
fn valid_usbpath(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 32
        && path
            .split('.')
            .all(|group| !group.is_empty() && group.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Parses one `map` entry string. Unknown keys are ignored (PVE may add
/// some); the three known ones are validated strictly.
fn parse_map_entry(raw: &str) -> Result<PveUsbMapEntry, String> {
    if raw.chars().count() > MAX_ENTRY_CHARS {
        return Err(format!(
            "the entry is over the {MAX_ENTRY_CHARS}-character bound"
        ));
    }
    let (mut node, mut id, mut path) = (None, None, None);
    for property in raw
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let Some((key, value)) = property.split_once('=') else {
            return Err(format!("the property {} has no value", excerpt(property)));
        };
        let slot = match key {
            "node" => &mut node,
            "id" => &mut id,
            "path" => &mut path,
            _ => continue,
        };
        if slot.replace(value).is_some() {
            return Err(format!("the {key} property appears twice"));
        }
    }
    let node = node.ok_or_else(|| "the entry names no node".to_owned())?;
    if !safe_node_path_segment(node) {
        return Err(format!("{} is not a safe node name", excerpt(node)));
    }
    let id = id.ok_or_else(|| "the entry carries no id (PVE requires one)".to_owned())?;
    let (vendor, product) = id
        .split_once(':')
        .and_then(|(vendor, product)| Some((hex4(vendor)?, hex4(product)?)))
        .ok_or_else(|| format!("the id {} is not vendor:product hex", excerpt(id)))?;
    let path = match path {
        Some(path) if valid_port_path(path) => Some(path.to_owned()),
        Some(path) => return Err(format!("the path {} is not <bus>-<port>", excerpt(path))),
        None => None,
    };
    Ok(PveUsbMapEntry {
        node: node.to_owned(),
        vendor_id: vendor,
        product_id: product,
        path,
    })
}

/// Derives the class of a `check-node` message.
fn check_kind(message: &str) -> PveUsbCheckKind {
    let lowered = message.to_ascii_lowercase();
    if lowered.starts_with("no mapping for node") {
        PveUsbCheckKind::NoMappingForNode
    } else if lowered.contains("'id' does not match") {
        PveUsbCheckKind::IdMismatch
    } else if lowered.contains("usb device") && lowered.contains("not found") {
        PveUsbCheckKind::DeviceNotFound
    } else {
        PveUsbCheckKind::Other
    }
}

/// Reads one `errors[]` item. A malformed item is a warning and is kept as
/// an unclassified error so it can never read as a clean check.
fn normalize_issue(item: &serde_json::Value) -> Result<PveUsbCheckIssue, String> {
    let message = item
        .get("message")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "the issue carries no message".to_owned())?;
    let message = message.trim();
    let message = message
        .strip_prefix("Invalid configuration:")
        .map_or(message, str::trim_start);
    let severity = match item.get("severity").and_then(serde_json::Value::as_str) {
        Some("error") => PveUsbSeverity::Error,
        Some("warning") => PveUsbSeverity::Warning,
        _ => PveUsbSeverity::Unknown,
    };
    Ok(PveUsbCheckIssue {
        severity,
        kind: check_kind(message),
        message: display_text(message).unwrap_or_default(),
    })
}

/// Reads a mapping's `errors[]`, bounded. An unreadable finding is kept as
/// an unclassified error so it can never read as a clean check.
fn normalize_issues(
    id: &str,
    rows: &[serde_json::Value],
    warnings: &mut Warnings,
) -> Vec<PveUsbCheckIssue> {
    let mut issues = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if index >= MAX_USB_CHECK_ISSUES {
            warnings.push(format!(
                "mapping {}: {} check findings beyond the {MAX_USB_CHECK_ISSUES}-finding bound were not kept",
                excerpt(id),
                rows.len() - MAX_USB_CHECK_ISSUES
            ));
            break;
        }
        match normalize_issue(row) {
            Ok(issue) => issues.push(issue),
            Err(detail) => {
                warnings.push(format!(
                    "mapping {} finding #{index}: {detail}",
                    excerpt(id)
                ));
                issues.push(PveUsbCheckIssue {
                    severity: PveUsbSeverity::Unknown,
                    kind: PveUsbCheckKind::Other,
                    message: "an unreadable check finding".to_owned(),
                });
            }
        }
    }
    issues
}

/// The fields every mapping shape shares (`description`, `digest`, `map`,
/// and `errors` when `checked`). The id is the caller's.
fn normalize_mapping_fields(
    id: &str,
    entry: &serde_json::Value,
    checked: bool,
    warnings: &mut Warnings,
) -> PveUsbMapping {
    let description = entry
        .get("description")
        .and_then(serde_json::Value::as_str)
        .and_then(display_text);
    let digest = entry
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .filter(|digest| digest.len() <= 128 && digest.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(str::to_owned);

    let mut entries = Vec::new();
    let mut unreadable_entries = 0_usize;
    match entry.get("map") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Array(rows)) => {
            for (index, row) in rows.iter().enumerate() {
                if index >= MAX_USB_MAP_ENTRIES {
                    unreadable_entries += rows.len() - MAX_USB_MAP_ENTRIES;
                    warnings.push(format!(
                        "mapping {}: {} map entries beyond the {MAX_USB_MAP_ENTRIES}-entry bound were not read",
                        excerpt(id),
                        rows.len() - MAX_USB_MAP_ENTRIES
                    ));
                    break;
                }
                let parsed = row
                    .as_str()
                    .ok_or_else(|| format!("the entry is a {}, not a string", type_name_of(row)))
                    .and_then(parse_map_entry);
                match parsed {
                    Ok(parsed) => entries.push(parsed),
                    Err(detail) => {
                        unreadable_entries += 1;
                        warnings.push(format!("mapping {} entry #{index}: {detail}", excerpt(id)));
                    }
                }
            }
        }
        Some(other) => {
            unreadable_entries += 1;
            warnings.push(format!(
                "mapping {}: the map is not a list (it is a {})",
                excerpt(id),
                type_name_of(other)
            ));
        }
    }

    let issues = if !checked {
        None
    } else if let Some(serde_json::Value::Array(rows)) = entry.get("errors") {
        Some(normalize_issues(id, rows, warnings))
    } else {
        warnings.push(format!(
            "mapping {}: the node check answered no findings list; presence is unknown",
            excerpt(id)
        ));
        None
    };

    PveUsbMapping {
        id: id.to_owned(),
        description,
        digest,
        entries,
        unreadable_entries,
        issues,
    }
}

/// Normalizes a `/cluster/mapping/usb` payload.
fn normalize_mappings(
    version: String,
    checked_node: Option<&str>,
    data: &serde_json::Value,
) -> Result<PveUsbMappings, PveUsbError> {
    let rows: &[serde_json::Value] = match data {
        serde_json::Value::Array(rows) => rows,
        // `data: null` is an empty list: honest, not an error.
        serde_json::Value::Null => &[],
        other => {
            return Err(PveUsbError::Unreadable {
                cause: PveApiError::InvalidPayload {
                    detail: format!(
                        "the mapping list is not a list (it is a {})",
                        type_name_of(other)
                    ),
                },
            });
        }
    };
    let mut warnings = Warnings::default();
    let mut truncated = rows.len() > MAX_ROWS_EXAMINED;
    let mut mappings = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, row) in rows.iter().take(MAX_ROWS_EXAMINED).enumerate() {
        if mappings.len() >= MAX_USB_MAPPINGS {
            truncated = true;
            break;
        }
        let id = match bounded_str(row, "id", 64) {
            Ok(Some(id)) if is_safe_mapping_id(&id) => id,
            Ok(Some(id)) => {
                warnings.push(format!(
                    "mapping #{index}: the id {} is not a safe mapping id",
                    excerpt(&id)
                ));
                continue;
            }
            Ok(None) => {
                warnings.push(format!("mapping #{index}: the entry carries no id"));
                continue;
            }
            Err(detail) => {
                warnings.push(format!("mapping #{index}: {detail}"));
                continue;
            }
        };
        if let Some(kind) = row.get("type").and_then(serde_json::Value::as_str)
            && kind != "usb"
        {
            warnings.push(format!(
                "mapping {}: the type is {}, not usb",
                excerpt(&id),
                excerpt(kind)
            ));
            continue;
        }
        if !seen.insert(id.clone()) {
            warnings.push(format!(
                "mapping {} is listed twice; the first is kept",
                excerpt(&id)
            ));
            continue;
        }
        mappings.push(normalize_mapping_fields(
            &id,
            row,
            checked_node.is_some(),
            &mut warnings,
        ));
    }
    if truncated {
        warnings.push(format!(
            "the answer lists {} mappings; only the first {MAX_USB_MAPPINGS} were read and the list is incomplete",
            rows.len()
        ));
    }
    mappings.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(PveUsbMappings {
        version,
        checked_node: checked_node.map(str::to_owned),
        mappings,
        warnings: warnings.finish(),
        truncated,
    })
}

/// One inventory row: an attachable device, or a root hub to skip.
enum Row {
    Device(Box<PveUsbDevice>),
    RootHub,
}

/// Normalizes one inventory row. A root hub is `level` 0 with no `usbpath`;
/// a row with no `usbpath` that is not plainly a root hub cannot be
/// addressed and is malformed.
fn normalize_device(row: &serde_json::Value) -> Result<Row, String> {
    if !row.is_object() {
        return Err(format!("the row is a {}, not an object", type_name_of(row)));
    }
    let number = |key: &str| -> Result<Option<u32>, String> {
        match row.get(key) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(_) => loose_number(row, key)
                .and_then(|value| u32::try_from(value).ok())
                .map(Some)
                .ok_or_else(|| format!("the {key} field is not a number")),
        }
    };
    let busnum = number("busnum")?.ok_or_else(|| "the row carries no busnum".to_owned())?;
    let devnum = number("devnum")?.ok_or_else(|| "the row carries no devnum".to_owned())?;
    let level = number("level")?;
    let usbpath = match row.get("usbpath") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(path)) if valid_usbpath(path) => Some(path.clone()),
        Some(serde_json::Value::String(path)) => {
            return Err(format!("the usbpath {} is not a port path", excerpt(path)));
        }
        // PVE writes `usbpath` as a string; a bare number is tolerated.
        Some(serde_json::Value::Number(number)) => {
            Some(number.to_string()).filter(|path| valid_usbpath(path))
        }
        Some(other) => {
            return Err(format!(
                "the usbpath is a {}, not a string",
                type_name_of(other)
            ));
        }
    };
    let Some(usbpath) = usbpath else {
        return if level == Some(0) {
            Ok(Row::RootHub)
        } else {
            Err("the row carries no usbpath and is not a root hub".to_owned())
        };
    };
    let id_field = |key: &str| -> Result<String, String> {
        row.get(key)
            .and_then(serde_json::Value::as_str)
            .and_then(hex4)
            .ok_or_else(|| format!("the {key} field is not four hex digits"))
    };
    let vendor_id = id_field("vendid")?;
    let product_id = id_field("prodid")?;
    let speed = match row.get("speed") {
        Some(serde_json::Value::String(speed)) => Some(speed.trim().to_owned()),
        Some(serde_json::Value::Number(speed)) => Some(speed.to_string()),
        _ => None,
    }
    .filter(|speed| {
        !speed.is_empty()
            && speed.len() <= 16
            && speed
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
    });
    let text = |key: &str| {
        row.get(key)
            .and_then(serde_json::Value::as_str)
            .and_then(display_text)
    };
    Ok(Row::Device(Box::new(PveUsbDevice {
        busnum,
        devnum,
        vendor_id,
        product_id,
        path: format!("{busnum}-{usbpath}"),
        usbpath,
        level,
        port: number("port")?,
        class: number("class")?,
        speed,
        manufacturer: text("manufacturer"),
        product: text("product"),
    })))
}

/// Normalizes a `/nodes/{node}/hardware/usb` payload.
fn normalize_inventory(
    version: String,
    node: &str,
    data: &serde_json::Value,
) -> Result<PveUsbInventory, PveUsbError> {
    let rows: &[serde_json::Value] = match data {
        serde_json::Value::Array(rows) => rows,
        serde_json::Value::Null => &[],
        other => {
            return Err(PveUsbError::Unreadable {
                cause: PveApiError::InvalidPayload {
                    detail: format!(
                        "the USB inventory is not a list (it is a {})",
                        type_name_of(other)
                    ),
                },
            });
        }
    };
    let mut warnings = Warnings::default();
    let mut truncated = rows.len() > MAX_ROWS_EXAMINED;
    let mut devices: Vec<PveUsbDevice> = Vec::new();
    let mut root_hubs = 0_usize;
    for (index, row) in rows.iter().take(MAX_ROWS_EXAMINED).enumerate() {
        match normalize_device(row) {
            Ok(Row::RootHub) => root_hubs += 1,
            Ok(Row::Device(device)) => {
                if devices
                    .iter()
                    .any(|seen| (seen.busnum, seen.devnum) == (device.busnum, device.devnum))
                {
                    warnings.push(format!(
                        "device #{index}: bus {} device {} is listed twice; the first is kept",
                        device.busnum, device.devnum
                    ));
                } else if devices.len() >= MAX_USB_DEVICES {
                    truncated = true;
                } else {
                    devices.push(*device);
                }
            }
            Err(detail) => warnings.push(format!("device #{index}: {detail}")),
        }
    }
    if truncated {
        warnings.push(format!(
            "the answer lists {} rows; only the first {MAX_USB_DEVICES} devices were kept and the inventory is incomplete",
            rows.len()
        ));
    }
    devices.sort_by_key(|device| (device.busnum, device.devnum));
    Ok(PveUsbInventory {
        version,
        node: node.to_owned(),
        devices,
        root_hubs,
        warnings: warnings.finish(),
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn mappings(data: &serde_json::Value) -> PveUsbMappings {
        normalize_mappings("9.2.2".to_owned(), None, data).expect("a list normalizes")
    }

    fn inventory(data: &serde_json::Value) -> PveUsbInventory {
        normalize_inventory("9.2.2".to_owned(), "pve", data).expect("a list normalizes")
    }

    #[test]
    fn map_entries_parse_strictly_and_ignore_unknown_keys() {
        let entry = parse_map_entry("node=pve,id=05AC:1500,path=1-10").unwrap();
        assert_eq!(entry.node, "pve");
        assert_eq!(entry.hardware_id(), "05ac:1500", "ids are lowercased");
        assert_eq!(entry.path.as_deref(), Some("1-10"));

        let id_only = parse_map_entry("node=pve,id=18a5:0428").unwrap();
        assert_eq!(id_only.path, None);

        let future = parse_map_entry("node=pve,id=18a5:0428,hardware-id=whatever").unwrap();
        assert_eq!(future.hardware_id(), "18a5:0428");

        assert_eq!(
            parse_map_entry("node=pve,id=05ac:1500,path=2-4.1.3")
                .unwrap()
                .path
                .as_deref(),
            Some("2-4.1.3")
        );
    }

    #[test]
    fn malformed_map_entries_are_refused_never_repaired() {
        for (raw, why) in [
            ("node=pve,path=1-10", "id is mandatory"),
            ("id=05ac:1500", "node is mandatory"),
            ("node=pve,id=05ac", "id is not vendor:product"),
            ("node=pve,id=05ac:15zz", "non-hex id"),
            ("node=pve,id=05ac:15000", "long id"),
            ("node=pve,id=05ac:1500,path=1", "path has no port"),
            ("node=pve,id=05ac:1500,path=1-", "empty port"),
            ("node=pve,id=05ac:1500,path=x-1", "non-numeric bus"),
            ("node=pve,id=05ac:1500,path=1-2..3", "empty port group"),
            ("node=pve,node=other,id=05ac:1500", "duplicate key"),
            ("node=pve,id", "property without value"),
            ("node=../etc,id=05ac:1500", "unsafe node name"),
            ("node=a/b,id=05ac:1500", "unsafe node name"),
            ("", "empty"),
        ] {
            assert!(parse_map_entry(raw).is_err(), "{why}: {raw:?}");
        }
        let over = format!("node=pve,id=05ac:1500,{}=x", "k".repeat(300));
        assert!(parse_map_entry(&over).is_err());
    }

    #[test]
    fn one_malformed_mapping_never_hides_the_rest() {
        let data = json!([
            {"id": "good", "type": "usb", "map": ["node=pve,id=05ac:1500,path=1-10"]},
            {"type": "usb", "map": ["node=pve,id=05ac:1500"]},
            "not an object",
            42,
            null,
            {"id": "has space", "map": []},
            {"id": "pci-thing", "type": "pci", "map": []},
            {"id": "bad-map", "map": "node=pve,id=05ac:1500"},
            {"id": "half", "map": ["node=pve,id=05ac:1500", "node=pve", 7]},
            {"id": "good", "map": ["node=other,id=1111:2222"]},
        ]);
        let list = mappings(&data);
        let ids: Vec<&str> = list.mappings.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, ["bad-map", "good", "half"]);
        assert!(!list.truncated);

        let half = list.mappings.iter().find(|m| m.id == "half").unwrap();
        assert_eq!(half.entries.len(), 1);
        assert_eq!(
            half.unreadable_entries, 2,
            "a partly read mapping says so, it never reads as clean"
        );
        let bad_map = list.mappings.iter().find(|m| m.id == "bad-map").unwrap();
        assert!(bad_map.entries.is_empty());
        assert_eq!(bad_map.unreadable_entries, 1);
        let good = list.mappings.iter().find(|m| m.id == "good").unwrap();
        assert_eq!(good.entries[0].node, "pve", "the first duplicate is kept");

        let all = list.warnings.join("\n");
        for needle in [
            "mapping #1: the entry carries no id",
            "mapping #2",
            "mapping #3",
            "mapping #4",
            "not a safe mapping id",
            "not usb",
            "listed twice",
            "not a list",
        ] {
            assert!(all.contains(needle), "missing {needle:?} in:\n{all}");
        }
    }

    #[test]
    fn oversized_lists_are_bounded_and_say_so() {
        let rows: Vec<_> = (0..MAX_USB_MAPPINGS + 10)
            .map(|index| json!({"id": format!("m{index:04}"), "map": []}))
            .collect();
        let list = mappings(&serde_json::Value::Array(rows));
        assert_eq!(list.mappings.len(), MAX_USB_MAPPINGS);
        assert!(list.truncated, "an incomplete list must not pass as whole");
        assert!(list.warnings.iter().any(|w| w.contains("incomplete")));

        let entries: Vec<_> = (0..MAX_USB_MAP_ENTRIES + 5)
            .map(|index| format!("node=n{index},id=05ac:1500"))
            .collect();
        let list = mappings(&json!([{"id": "wide", "map": entries}]));
        let wide = &list.mappings[0];
        assert_eq!(wide.entries.len(), MAX_USB_MAP_ENTRIES);
        assert_eq!(wide.unreadable_entries, 5);

        let findings: Vec<_> = (0..MAX_USB_CHECK_ISSUES + 3)
            .map(|_| json!({"message": "x", "severity": "warning"}))
            .collect();
        let checked = normalize_mappings(
            "9.2.2".to_owned(),
            Some("pve"),
            &json!([{"id": "noisy", "map": [], "errors": findings}]),
        )
        .unwrap();
        assert_eq!(
            checked.mappings[0].issues.as_ref().unwrap().len(),
            MAX_USB_CHECK_ISSUES
        );
        assert!(checked.warnings.iter().any(|w| w.contains("finding bound")));
    }

    #[test]
    fn warnings_are_bounded_and_quote_foreign_text_briefly() {
        let rows: Vec<_> = (0..200)
            .map(|index| json!({"id": format!("bad id {index}\n{}", "x".repeat(500))}))
            .collect();
        let list = mappings(&serde_json::Value::Array(rows));
        assert!(list.mappings.is_empty());
        assert!(list.warnings.len() <= MAX_WARNINGS + 1);
        assert!(list.warnings.last().unwrap().contains("more warnings"));
        for warning in &list.warnings {
            assert!(warning.chars().count() < 300, "{warning}");
            assert!(!warning.contains('\n'));
        }
    }

    #[test]
    fn rows_past_the_examination_bound_are_counted_not_parsed() {
        let rows = vec![json!(null); MAX_ROWS_EXAMINED + 1];
        let list = mappings(&serde_json::Value::Array(rows.clone()));
        assert!(list.truncated);
        let inv = inventory(&serde_json::Value::Array(rows));
        assert!(inv.truncated);
    }

    #[test]
    fn non_lists_are_payload_errors_and_null_is_empty() {
        for data in [json!({"a": 1}), json!("x"), json!(3), json!(true)] {
            assert!(matches!(
                normalize_mappings("9.2.2".to_owned(), None, &data),
                Err(PveUsbError::Unreadable {
                    cause: PveApiError::InvalidPayload { .. }
                })
            ));
            assert!(matches!(
                normalize_inventory("9.2.2".to_owned(), "pve", &data),
                Err(PveUsbError::Unreadable {
                    cause: PveApiError::InvalidPayload { .. }
                })
            ));
        }
        assert!(mappings(&json!(null)).could_be_unprivileged());
        assert!(inventory(&json!(null)).devices.is_empty());
    }

    #[test]
    fn display_text_is_flattened_redacted_and_truncated() {
        let list = mappings(&json!([{
            "id": "m",
            "description": format!("line one\nline two https://user:hunter2@example.invalid/x {}", "y".repeat(400)),
            "map": []
        }]));
        let description = list.mappings[0].description.as_deref().unwrap();
        assert!(!description.contains('\n'));
        assert!(!description.contains("hunter2"), "{description}");
        assert!(description.chars().count() <= MAX_TEXT_CHARS + 1);
    }

    #[test]
    fn check_findings_are_classified_and_never_read_as_clean_when_unreadable() {
        let data = json!([{
            "id": "m",
            "map": ["node=pve,id=05ac:1500,path=1-10"],
            "errors": [
                {"message": "Invalid configuration: usb device '1-10' not found\n", "severity": "error"},
                {"message": "'id' does not match for 'x' (05ac:1500 != 05ac:1501)", "severity": "error"},
                {"message": "No mapping for node pve.", "severity": "warning"},
                {"message": "something new", "severity": "info"},
                {"severity": "error"},
                "nope"
            ]
        }]);
        let list = normalize_mappings("9.2.2".to_owned(), Some("pve"), &data).unwrap();
        let issues = list.mappings[0].issues.as_ref().unwrap();
        let kinds: Vec<_> = issues.iter().map(|i| i.kind).collect();
        assert_eq!(
            kinds,
            [
                PveUsbCheckKind::DeviceNotFound,
                PveUsbCheckKind::IdMismatch,
                PveUsbCheckKind::NoMappingForNode,
                PveUsbCheckKind::Other,
                PveUsbCheckKind::Other,
                PveUsbCheckKind::Other,
            ]
        );
        assert_eq!(
            issues[0].message, "usb device '1-10' not found",
            "decoration is stripped"
        );
        assert_eq!(issues[3].severity, PveUsbSeverity::Unknown);
        assert_eq!(list.mappings[0].check_passed(), Some(false));
        assert_eq!(list.warnings.len(), 2, "two unreadable findings");

        let missing_errors = normalize_mappings(
            "9.2.2".to_owned(),
            Some("pve"),
            &json!([{"id": "m", "map": []}]),
        )
        .unwrap();
        assert_eq!(missing_errors.mappings[0].issues, None);
        assert_eq!(missing_errors.mappings[0].check_passed(), None);
        assert!(!missing_errors.warnings.is_empty());

        let clean = normalize_mappings(
            "9.2.2".to_owned(),
            Some("pve"),
            &json!([{"id": "m", "map": [], "errors": []}]),
        )
        .unwrap();
        assert_eq!(clean.mappings[0].check_passed(), Some(true));
    }

    #[test]
    fn inventory_skips_root_hubs_and_isolates_bad_rows() {
        let data = json!([
            {"busnum": 1, "devnum": 1, "level": 0, "vendid": "1d6b", "prodid": "0002"},
            {"busnum": 1, "devnum": 3, "level": 1, "port": 6, "class": 0, "speed": "480",
             "usbpath": "7", "vendid": "05AC", "prodid": "1500",
             "manufacturer": "Apple Inc.", "product": "MacBook Air SuperDrive"},
            {"busnum": "2", "devnum": "5", "usbpath": "4.1", "vendid": "18a5", "prodid": "0428"},
            {"busnum": 1, "devnum": 9, "level": 1, "vendid": "05ac", "prodid": "1500"},
            {"busnum": 1, "devnum": 10, "usbpath": "../1", "vendid": "05ac", "prodid": "1500"},
            {"busnum": 1, "devnum": 11, "usbpath": "3", "vendid": "zzzz", "prodid": "1500"},
            {"devnum": 12, "usbpath": "3", "vendid": "05ac", "prodid": "1500"},
            {"busnum": 1, "devnum": 3, "usbpath": "7", "vendid": "05ac", "prodid": "1500"},
            "junk",
            null
        ]);
        let inv = inventory(&data);
        assert_eq!(inv.root_hubs, 1);
        let paths: Vec<_> = inv.devices.iter().map(|d| d.path.as_str()).collect();
        assert_eq!(paths, ["1-7", "2-4.1"], "sorted by bus then devnum");
        let drive = &inv.devices[0];
        assert_eq!(drive.hardware_id(), "05ac:1500");
        assert_eq!(drive.usbpath, "7");
        assert_eq!(drive.speed.as_deref(), Some("480"));
        assert_eq!(drive.product.as_deref(), Some("MacBook Air SuperDrive"));
        assert_eq!(inv.devices[1].devnum, 5, "stringly numbers are accepted");
        assert_eq!(inv.warnings.len(), 7, "{:#?}", inv.warnings);
    }

    #[test]
    fn oversized_inventory_is_bounded_and_says_so() {
        let rows: Vec<_> = (0..MAX_USB_DEVICES + 20)
            .map(|index| {
                json!({"busnum": 1, "devnum": index + 2, "level": 1, "usbpath": "1",
                       "vendid": "05ac", "prodid": "1500"})
            })
            .collect();
        let inv = inventory(&serde_json::Value::Array(rows));
        assert_eq!(inv.devices.len(), MAX_USB_DEVICES);
        assert!(inv.truncated);
    }

    #[test]
    fn privilege_is_read_from_the_403_message() {
        let detail = r#"{"errors":null,"message":"Permission check failed (/, Sys.Modify)\n"}"#;
        assert_eq!(
            required_privilege(detail),
            Some(PveUsbRequiredPrivilege {
                path: "/".to_owned(),
                privilege: "Sys.Modify".to_owned()
            })
        );
        assert_eq!(required_privilege("Permission check failed"), None);
        assert_eq!(required_privilege("Permission check failed (/, "), None);
        assert_eq!(required_privilege("Permission check failed ()"), None);
        assert_eq!(required_privilege(""), None);
    }

    #[test]
    fn classification_covers_every_api_failure() {
        assert!(matches!(
            classify(PveApiError::Auth, None),
            PveUsbError::Unauthenticated
        ));
        assert!(matches!(
            classify(
                PveApiError::Forbidden {
                    detail: "x".to_owned()
                },
                None
            ),
            PveUsbError::PermissionDenied { required: None, .. }
        ));
        for status in [404, 501] {
            assert!(matches!(
                classify(
                    PveApiError::Http {
                        status,
                        detail: "x".to_owned()
                    },
                    Some("7.4-1")
                ),
                PveUsbError::EndpointAbsent {
                    version: Some(_),
                    ..
                }
            ));
        }
        for status in [400, 500, 595] {
            assert!(matches!(
                classify(
                    PveApiError::Http {
                        status,
                        detail: "x".to_owned()
                    },
                    None
                ),
                PveUsbError::Unreadable { .. }
            ));
        }
    }
}
