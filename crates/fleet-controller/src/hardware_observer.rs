//! The hardware inventory's Proxmox read port over the provider (FM-1111,
//! ADR 0019).
//!
//! One refresh makes these reads through the account's token, all `GET`s and
//! none of them privileged beyond what the opt-in `FleetUsb` role and the
//! discover tier grant:
//!
//! 1. `GET /cluster/mapping/usb` (`Mapping.Audit`). An empty `200` is
//!    reported as it is; the application settles it with the permissions.
//! 2. `GET /access/permissions`, the token's own privileges.
//! 3. Per node a mapping names: `GET /cluster/mapping/usb?check-node=<node>`
//!    (presence and the fingerprint) and `GET /nodes/{node}/hardware/usb`
//!    (`Sys.Modify` on `/`, so a refusal is the normal case and the inventory
//!    is optional enrichment).
//! 4. Every QEMU guest's `usbN` entries: `GET /cluster/resources` then one
//!    `GET …/config` per guest, plus `?current=1` for a running guest, whose
//!    applied view can differ from the stored one. Bounded
//!    ([`MAX_SCANNED_GUESTS`]), concurrent, and tolerant: a guest that cannot
//!    be read is counted, never fatal.
//!
//!    The listing omits every guest the token cannot audit, so a clean scan
//!    proves nothing about those. One cross-check exists (#596):
//!    `GET /cluster/nextid` and `GET /cluster/nextid?vmid=<id>` answer for any
//!    caller, whatever its `VM.Audit`. Walking down from the cluster's next
//!    free VMID, every VMID the listing did not name and PVE says is in use
//!    is a guest the token cannot see ([`find_hidden_guests`]). It can only
//!    find guests, never rule them out, and does not look above the next
//!    free VMID.
//!
//! Provider shapes are translated here into the application's own
//! (`fleet_application::hardware_inventory`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use fleet_application::hardware_inventory::{
    HardwareObservePort, RawGuestReference, RawGuestScan, RawHardwareObservation, RawMapEntry,
    RawMapping, RawMappingsRead, RawNode, RawNodeCheck, RawPermissionsRead, RawUsbDevice,
    ReferencePending,
};
use fleet_application::proxmox::privileges::RawTokenPermissions;
use fleet_application::proxmox::{ProxmoxAccount, ProxmoxSourceError};
use fleet_core::SensitiveString;
use fleet_provider_proxmox::usb::{PveUsbCheckKind, PveUsbError, PveUsbSeverity};
use fleet_provider_proxmox::{ProxmoxClient, PveApiError};
use futures_util::StreamExt as _;

use crate::proxmox_store::{map_api_error, pinned_request};

/// The most guests whose config one refresh reads. A bigger cluster is
/// reported as truncated rather than read without bound.
pub const MAX_SCANNED_GUESTS: usize = 512;

/// The most VMIDs probed for a hidden guest in one refresh (`nextid?vmid=`
/// requests, one after the other).
const MAX_HIDDEN_PROBES: usize = 16;

/// The most VMIDs one refresh walks over while looking for a hidden guest.
const MAX_HIDDEN_STEPS: usize = 256;

/// The most hidden VMIDs one refresh reports.
const MAX_HIDDEN_REPORTED: usize = 8;

/// The lowest VMID PVE hands out.
const FIRST_VMID: u32 = 100;

/// The most nodes one refresh checks.
pub const MAX_CHECKED_NODES: usize = 16;

/// How many guest configs are read at once.
const GUEST_CONCURRENCY: usize = 8;

/// How many nodes are checked at once.
const NODE_CONCURRENCY: usize = 4;

/// The most per-guest read failures quoted as warnings.
const MAX_GUEST_WARNINGS: usize = 8;

/// The longest provider detail quoted in a note or warning.
const MAX_DETAIL_CHARS: usize = 160;

fn bounded(text: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let flat = flat.trim();
    if flat.chars().count() <= MAX_DETAIL_CHARS {
        flat.to_owned()
    } else {
        let mut cut: String = flat.chars().take(MAX_DETAIL_CHARS).collect();
        cut.push('…');
        cut
    }
}

/// The inventory's Proxmox read port over the provider client.
#[derive(Clone, Debug)]
pub struct ProviderHardwareObserver {
    client: ProxmoxClient,
}

impl ProviderHardwareObserver {
    /// Composes the port over the provider client.
    #[must_use]
    pub fn new(client: ProxmoxClient) -> Self {
        Self { client }
    }
}

/// Maps a USB read failure that makes the observation meaningless.
fn fatal(error: PveUsbError) -> ProxmoxSourceError {
    match error {
        PveUsbError::Unauthenticated => ProxmoxSourceError::Auth,
        PveUsbError::Unreadable { cause } => map_api_error(cause),
        other => ProxmoxSourceError::InvalidPayload {
            detail: bounded(&other.to_string()),
        },
    }
}

fn convert_mapping(mapping: &fleet_provider_proxmox::usb::PveUsbMapping) -> RawMapping {
    RawMapping {
        id: mapping.id.clone(),
        entries: mapping
            .entries
            .iter()
            .map(|entry| RawMapEntry {
                node: entry.node.clone(),
                vendor_id: entry.vendor_id.clone(),
                product_id: entry.product_id.clone(),
                path: entry.path.clone(),
            })
            .collect(),
        unreadable_entries: mapping.unreadable_entries,
    }
}

/// What `check-node` said about a mapping that has an entry for the node.
fn check_of(mapping: &fleet_provider_proxmox::usb::PveUsbMapping) -> RawNodeCheck {
    let Some(issues) = &mapping.issues else {
        return RawNodeCheck::Unchecked {
            detail: "the answer carried no check".to_owned(),
        };
    };
    // A device error (absent, another device at the port, anything PVE calls
    // an error or a severity this code does not know) means an attach would
    // fail: not present. A bare warning does not.
    if let Some(issue) = issues.iter().find(|issue| {
        matches!(
            issue.severity,
            PveUsbSeverity::Error | PveUsbSeverity::Unknown
        ) || matches!(
            issue.kind,
            PveUsbCheckKind::DeviceNotFound | PveUsbCheckKind::IdMismatch
        )
    }) {
        return RawNodeCheck::NotPresent {
            detail: bounded(&issue.message),
        };
    }
    RawNodeCheck::Present
}

async fn observe_node(
    client: &ProxmoxClient,
    account: &ProxmoxAccount,
    secret: &SensitiveString,
    node: String,
    mapping_ids: Vec<String>,
) -> (RawNode, Vec<String>) {
    let mut warnings = Vec::new();
    let mut checks = BTreeMap::new();
    let unchecked = |detail: String| RawNodeCheck::Unchecked { detail };
    match pinned_request(account, secret, "/api2/json/cluster/mapping/usb") {
        Err(error) => {
            for id in &mapping_ids {
                checks.insert(id.clone(), unchecked(bounded(&error.to_string())));
            }
        }
        Ok(request) => match client.usb_mappings(request, Some(&node)).await {
            Ok(list) => {
                for id in &mapping_ids {
                    let check = list
                        .mappings
                        .iter()
                        .find(|mapping| &mapping.id == id)
                        .map_or_else(
                            || unchecked("the checked list does not carry the mapping".to_owned()),
                            check_of,
                        );
                    checks.insert(id.clone(), check);
                }
            }
            Err(error) => {
                let detail = bounded(&error.to_string());
                for id in &mapping_ids {
                    checks.insert(id.clone(), unchecked(detail.clone()));
                }
            }
        },
    }
    // The inventory is optional enrichment: the base token lacks
    // `Sys.Modify`, so a refusal (or an absent endpoint) is silent.
    let inventory = match pinned_request(account, secret, "/api2/json/version") {
        Err(_) => None,
        Ok(request) => match client.usb_inventory(request, &node).await {
            Ok(inventory) => Some(
                inventory
                    .devices
                    .into_iter()
                    .map(|device| RawUsbDevice {
                        path: device.path,
                        vendor_id: device.vendor_id,
                        product_id: device.product_id,
                        manufacturer: device.manufacturer,
                        product: device.product,
                    })
                    .collect(),
            ),
            Err(PveUsbError::PermissionDenied { .. } | PveUsbError::EndpointAbsent { .. }) => None,
            Err(error) => {
                warnings.push(format!(
                    "node {node}: the USB inventory is unreadable: {}",
                    bounded(&error.to_string())
                ));
                None
            }
        },
    };
    (
        RawNode {
            node,
            checks,
            inventory,
        },
        warnings,
    )
}

/// What the VMID cross-check found.
#[derive(Debug, Default)]
struct HiddenGuests {
    /// VMIDs PVE says exist although the listing did not name them,
    /// ascending.
    vmids: Vec<u32>,
    /// Whether a transient failure stopped the check from running.
    failed: bool,
}

/// Whether a failed read is the kind that clears by itself (a server error
/// or a transport failure), as against a refusal or an absent endpoint,
/// which say nothing either way.
fn is_transient(error: &PveApiError) -> bool {
    matches!(error, PveApiError::Transport(_))
        || matches!(error, PveApiError::Http { status, .. } if *status >= 500)
}

/// Finds guests that exist although the listing did not name them.
///
/// `first_free` is `GET /cluster/nextid` read *before* the listing, so a
/// guest created in between can only add to the listing, never to the
/// suspects. PVE hands out the lowest free VMID at or above the cluster's
/// `next-id` lower bound (default 100, not readable without `Sys.Audit` on
/// `/`), so every VMID from that bound up to `first_free` is in use. The
/// search walks down from `first_free - 1` over that run: a VMID the listing
/// named is a visible guest and costs nothing; an unnamed one is settled with
/// `nextid?vmid=` (`400` means it exists, hidden from the token). The first
/// *free* VMID means the walk has left the run (below a raised lower bound)
/// and ends it. Bounded in probes and steps. Positive evidence only: no
/// finding never means "none", and a guest above `first_free` or beyond the
/// bounds is not looked for.
async fn find_hidden_guests(
    client: &ProxmoxClient,
    account: &ProxmoxAccount,
    secret: &SensitiveString,
    first_free: Option<u32>,
    listed: &BTreeSet<u32>,
) -> HiddenGuests {
    let mut found = HiddenGuests::default();
    let Some(first_free) = first_free else {
        return found;
    };
    let mut probes = 0;
    let mut steps = 0;
    let mut vmid = first_free;
    while vmid > FIRST_VMID && steps < MAX_HIDDEN_STEPS && probes < MAX_HIDDEN_PROBES {
        vmid -= 1;
        steps += 1;
        if listed.contains(&vmid) {
            continue;
        }
        let Ok(request) = pinned_request(account, secret, "/api2/json/version") else {
            break;
        };
        probes += 1;
        match client.vmid_in_use(request, vmid).await {
            Ok(true) => {
                found.vmids.push(vmid);
                if found.vmids.len() >= MAX_HIDDEN_REPORTED {
                    break;
                }
            }
            Ok(false) => break,
            Err(error) => {
                found.failed = is_transient(&error);
                break;
            }
        }
    }
    found.vmids.sort_unstable();
    found
}

async fn scan_guests(
    client: &ProxmoxClient,
    account: &ProxmoxAccount,
    secret: &SensitiveString,
    warnings: &mut Vec<String>,
) -> RawGuestScan {
    let mut scan = RawGuestScan::default();
    // Before the listing, see `find_hidden_guests`.
    let mut cross_check_failed = false;
    let first_free = match pinned_request(account, secret, "/api2/json/version") {
        Ok(request) => match client.next_vmid(request).await {
            Ok(vmid) => Some(vmid),
            Err(error) => {
                cross_check_failed = is_transient(&error);
                None
            }
        },
        Err(_) => None,
    };
    let listed = match pinned_request(account, secret, "/api2/json/cluster/resources") {
        Ok(request) => client.list_guest_resources(request).await,
        Err(error) => Err(PveApiError::InvalidPayload {
            detail: error.to_string(),
        }),
    };
    let mut named: BTreeSet<u32> = BTreeSet::new();
    let guests = match listed {
        Ok(resources) => resources
            .into_iter()
            .inspect(|resource| {
                named.extend(resource.vmid);
            })
            .filter(|resource| matches!(resource.kind.as_str(), "qemu" | "qemu-template"))
            .filter_map(|resource| {
                Some((
                    resource.node?,
                    resource.vmid?,
                    resource.name,
                    resource.kind == "qemu-template",
                    resource.status.as_deref() == Some("running"),
                ))
            })
            .collect::<Vec<_>>(),
        Err(error) => {
            warnings.push(format!(
                "the guest list is unreadable ({}); no guest config was checked",
                bounded(&error.to_string())
            ));
            // Nothing was scanned: that is an incomplete scan, not an empty one.
            scan.truncated = true;
            return scan;
        }
    };
    scan.guests_listed = guests.len();
    if guests.len() > MAX_SCANNED_GUESTS {
        scan.truncated = true;
    }
    let reads = futures_util::stream::iter(guests.into_iter().take(MAX_SCANNED_GUESTS).map(
        |(node, vmid, name, template, running)| async move {
            let result = match pinned_request(account, secret, "/api2/json/version") {
                Ok(request) => client
                    .qemu_usb_references(request, &node, vmid, running)
                    .await
                    .map_err(|error| bounded(&error.to_string())),
                Err(error) => Err(bounded(&error.to_string())),
            };
            (node, vmid, name, template, running, result)
        },
    ))
    .buffer_unordered(GUEST_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;
    let mut failures = 0_usize;
    for (node, vmid, name, template, running, result) in reads {
        match result {
            Ok(references) => {
                // A guest whose applied view could not be read keeps the
                // references its stored view showed, but it is not fully
                // read: a reference only the running guest holds may be
                // missing, so it counts with the unreadable ones.
                let partial = references.applied_unread.clone();
                if let Some(detail) = &partial {
                    scan.guests_unreadable += 1;
                    failures += 1;
                    if failures <= MAX_GUEST_WARNINGS {
                        warnings.push(format!(
                            "guest qemu/{vmid} on {node}: the applied config could not be read: {}",
                            bounded(detail)
                        ));
                    }
                } else {
                    scan.guests_read += 1;
                }
                for reference in references.references {
                    let pending = match (
                        partial.is_none() && running,
                        reference.stored,
                        reference.applied,
                    ) {
                        (true, true, false) => Some(ReferencePending::Add),
                        (true, false, true) => Some(ReferencePending::Remove),
                        _ => None,
                    };
                    scan.references.push(RawGuestReference {
                        node: node.clone(),
                        vmid,
                        guest_name: name.clone(),
                        template: template || references.template,
                        slot: reference.slot,
                        mapping_id: reference.mapping_id,
                        pending,
                    });
                }
            }
            Err(detail) => {
                scan.guests_unreadable += 1;
                failures += 1;
                if failures <= MAX_GUEST_WARNINGS {
                    warnings.push(format!("guest qemu/{vmid} on {node}: {detail}"));
                }
            }
        }
    }
    if failures > MAX_GUEST_WARNINGS {
        warnings.push(format!(
            "{} more guest configs could not be read",
            failures - MAX_GUEST_WARNINGS
        ));
    }
    let hidden = find_hidden_guests(client, account, secret, first_free, &named).await;
    scan.hidden_vmids = hidden.vmids;
    scan.cross_check_failed = cross_check_failed || hidden.failed;
    scan.references.sort_by(|left, right| {
        (&left.node, left.vmid, &left.slot).cmp(&(&right.node, right.vmid, &right.slot))
    });
    scan
}

#[async_trait]
impl HardwareObservePort for ProviderHardwareObserver {
    async fn observe(
        &self,
        account: &ProxmoxAccount,
        secret: &SensitiveString,
    ) -> Result<RawHardwareObservation, ProxmoxSourceError> {
        let mut warnings = Vec::new();
        let request = pinned_request(account, secret, "/api2/json/cluster/mapping/usb")?;
        let listing = match self.client.usb_mappings(request, None).await {
            Ok(listing) => listing,
            Err(PveUsbError::EndpointAbsent { version, .. }) => {
                return Ok(RawHardwareObservation {
                    mappings: RawMappingsRead::EndpointAbsent { version },
                    nodes: Vec::new(),
                    guests: RawGuestScan::default(),
                    permissions: RawPermissionsRead::Unreadable {
                        detail: "not read".to_owned(),
                    },
                    warnings,
                });
            }
            Err(PveUsbError::PermissionDenied { detail, .. }) => {
                return Ok(RawHardwareObservation {
                    mappings: RawMappingsRead::Denied {
                        version: None,
                        detail: bounded(&detail),
                    },
                    nodes: Vec::new(),
                    guests: RawGuestScan::default(),
                    permissions: RawPermissionsRead::Unreadable {
                        detail: "not read".to_owned(),
                    },
                    warnings,
                });
            }
            Err(error) => return Err(fatal(error)),
        };
        warnings.extend(listing.warnings.iter().map(|warning| bounded(warning)));
        let mappings: Vec<RawMapping> = listing.mappings.iter().map(convert_mapping).collect();

        let permissions = match self
            .client
            .token_permissions_map(pinned_request(
                account,
                secret,
                "/api2/json/access/permissions",
            )?)
            .await
        {
            Ok(read) => RawPermissionsRead::Read(RawTokenPermissions {
                version: read.version,
                paths: read.paths,
                warnings: read.warnings,
                truncated: read.truncated,
                vmids_in_use: read.vmids_in_use,
            }),
            Err(error) => RawPermissionsRead::Unreadable {
                detail: bounded(&error.to_string()),
            },
        };

        // Every node a mapping names, with the mappings that have an entry
        // there.
        let mut by_node: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for mapping in &mappings {
            for entry in &mapping.entries {
                by_node
                    .entry(entry.node.clone())
                    .or_default()
                    .insert(mapping.id.clone());
            }
        }
        if by_node.len() > MAX_CHECKED_NODES {
            warnings.push(format!(
                "mappings name {} nodes; only the first {MAX_CHECKED_NODES} were checked",
                by_node.len()
            ));
        }
        let observed = futures_util::stream::iter(by_node.into_iter().take(MAX_CHECKED_NODES).map(
            |(node, ids)| {
                observe_node(
                    &self.client,
                    account,
                    secret,
                    node,
                    ids.into_iter().collect(),
                )
            },
        ))
        .buffer_unordered(NODE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
        let mut nodes = Vec::with_capacity(observed.len());
        for (node, node_warnings) in observed {
            nodes.push(node);
            warnings.extend(node_warnings);
        }
        nodes.sort_by(|left, right| left.node.cmp(&right.node));

        // A refresh with no mapping has no guest to look for.
        let guests = if mappings.is_empty() {
            RawGuestScan::default()
        } else {
            scan_guests(&self.client, account, secret, &mut warnings).await
        };
        warnings.truncate(64);
        Ok(RawHardwareObservation {
            mappings: RawMappingsRead::Read {
                version: listing.version,
                mappings,
                rows_returned: listing.rows_returned,
                truncated: listing.truncated,
            },
            nodes,
            guests,
            permissions,
            warnings,
        })
    }
}

/// Shares one observer between the use case and anything else that needs it.
#[must_use]
pub fn shared(client: ProxmoxClient) -> Arc<ProviderHardwareObserver> {
    Arc::new(ProviderHardwareObserver::new(client))
}
