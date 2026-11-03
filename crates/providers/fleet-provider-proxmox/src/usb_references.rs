//! Which USB resource mappings a QEMU guest's config references (FM-1111).
//!
//! The hardware inventory marks a device `externally_attached` when a guest
//! Fleet did not attach it to references its mapping, so it needs one bounded,
//! tolerant read of a guest's `usbN` entries. PVE gives no exclusivity (FM-S11
//! measured a second guest starting with a mapping another running guest
//! held), so the only way to know is to read the configs.
//!
//! Two views of one guest matter. `GET …/config` answers the stored
//! configuration, which already folds in pending changes; `?current=1`
//! answers what the running guest actually holds. A guest whose `hotplug`
//! option lacks `usb` and whose entry was removed keeps the device until it
//! restarts, and then only the applied view shows the reference. The caller
//! asks for the applied view only for guests where it can differ (a running
//! guest), and a reference seen in either view counts.
//!
//! Only the `mapping=` property is read. A `host=` entry (root-only in PVE)
//! names no mapping and is not a reference to one. Values are bounded, a
//! malformed `usbN` is skipped, and nothing here writes.

use super::{
    ProxmoxClient, PveApiError, PveHttpMethod, PveHttpRequest, loose_number,
    safe_node_path_segment, type_name_of, urlencode,
};

/// The highest `usbN` index PVE has (`usb0` to `usb13`).
const MAX_USB_SLOTS: u8 = 14;

/// The longest `usbN` value examined; a longer one is skipped, not truncated.
const MAX_VALUE_CHARS: usize = 256;

/// The longest mapping id kept from a `mapping=` property.
const MAX_MAPPING_CHARS: usize = 64;

/// One `usbN` entry that names a mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PveUsbReference {
    /// The slot, such as `usb0`.
    pub slot: String,
    /// The mapping id the entry names.
    pub mapping_id: String,
    /// Whether the stored configuration (pending changes folded in) holds it.
    pub stored: bool,
    /// Whether the running guest's applied configuration holds it. `false`
    /// also covers a view that was not read.
    pub applied: bool,
}

/// A guest's mapping references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PveUsbGuestReferences {
    /// Whether the guest is a template. A template holds no device, but its
    /// clones inherit the entry.
    pub template: bool,
    /// The references, ordered by slot index.
    pub references: Vec<PveUsbReference>,
}

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

/// The mapping a `usbN` value names, when it has a plausible `mapping=`.
fn mapping_of(value: &str) -> Option<&str> {
    let id = value
        .split(',')
        .find_map(|part| part.strip_prefix("mapping="))?;
    (!id.is_empty()
        && id.chars().count() <= MAX_MAPPING_CHARS
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
    .then_some(id)
}

/// The `(index, slot, mapping)` entries of one config answer, skipping
/// anything that is not a plausible `usbN: …mapping=<id>…` string.
fn entries(config: &serde_json::Map<String, serde_json::Value>) -> Vec<(u8, String, String)> {
    config
        .iter()
        .filter_map(|(key, value)| {
            let index = slot_index(key)?;
            let text = value
                .as_str()
                .filter(|t| t.chars().count() <= MAX_VALUE_CHARS)?;
            Some((index, key.clone(), mapping_of(text)?.to_owned()))
        })
        .collect()
}

fn scrub(error: PveApiError, request: &PveHttpRequest) -> PveApiError {
    let secret = request.credentials.token.expose();
    if secret.is_empty() {
        return error;
    }
    let clean = |detail: String| detail.replace(secret, "[redacted]");
    match error {
        PveApiError::Forbidden { detail } => PveApiError::Forbidden {
            detail: clean(detail),
        },
        PveApiError::Http { status, detail } => PveApiError::Http {
            status,
            detail: clean(detail),
        },
        PveApiError::InvalidPayload { detail } => PveApiError::InvalidPayload {
            detail: clean(detail),
        },
        other => other,
    }
}

impl ProxmoxClient {
    /// Reads which USB resource mappings one QEMU guest's config references
    /// (`GET /nodes/{node}/qemu/{vmid}/config`, and with `include_applied`
    /// also `?current=1`). Needs `VM.Audit` on the guest. Read-only.
    ///
    /// # Errors
    ///
    /// [`PveApiError`]: a refused node name or VMID is `InvalidPayload`
    /// (nothing is sent), a 403 is `Forbidden`, and an answer that is not a
    /// config object is `InvalidPayload`. The detail never carries the
    /// token.
    pub async fn qemu_usb_references(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        include_applied: bool,
    ) -> Result<PveUsbGuestReferences, PveApiError> {
        if !safe_node_path_segment(node) || vmid == 0 {
            return Err(PveApiError::InvalidPayload {
                detail: "the guest address is not a safe API path".to_owned(),
            });
        }
        let base = format!("/api2/json/nodes/{}/qemu/{vmid}/config", urlencode(node));
        let stored = self.usb_config_read(&request, base.clone()).await?;
        let applied = if include_applied {
            Some(
                self.usb_config_read(&request, format!("{base}?current=1"))
                    .await?,
            )
        } else {
            None
        };
        let stored_config = stored.as_object().ok_or_else(|| not_a_config(&stored))?;
        let template = match stored_config.get("template") {
            None | Some(serde_json::Value::Null) => false,
            Some(_) => loose_number(&stored, "template") == Some(1),
        };
        let mut merged: std::collections::BTreeMap<(u8, String), PveUsbReference> =
            std::collections::BTreeMap::new();
        for (index, slot, mapping_id) in entries(stored_config) {
            merged.insert(
                (index, mapping_id.clone()),
                PveUsbReference {
                    slot,
                    mapping_id,
                    stored: true,
                    applied: false,
                },
            );
        }
        if let Some(applied) = &applied {
            let applied_config = applied.as_object().ok_or_else(|| not_a_config(applied))?;
            for (index, slot, mapping_id) in entries(applied_config) {
                merged
                    .entry((index, mapping_id.clone()))
                    .and_modify(|reference| reference.applied = true)
                    .or_insert(PveUsbReference {
                        slot,
                        mapping_id,
                        stored: false,
                        applied: true,
                    });
            }
        }
        Ok(PveUsbGuestReferences {
            template,
            references: merged.into_values().collect(),
        })
    }

    async fn usb_config_read(
        &self,
        request: &PveHttpRequest,
        path: String,
    ) -> Result<serde_json::Value, PveApiError> {
        self.call(PveHttpRequest {
            path,
            method: PveHttpMethod::Get,
            ..request.clone()
        })
        .await
        .map_err(|error| scrub(error, request))
    }
}

fn not_a_config(value: &serde_json::Value) -> PveApiError {
    PveApiError::InvalidPayload {
        detail: format!(
            "the guest config is not an object (it is a {})",
            type_name_of(value)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PveCredentials, PveHttpResponse, PveTransport, PveTransportError};
    use async_trait::async_trait;
    use fleet_core::SensitiveString;
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct Script {
        routes: Vec<(&'static str, u16, serde_json::Value)>,
        seen: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl PveTransport for Script {
        async fn execute(
            &self,
            request: PveHttpRequest,
        ) -> Result<PveHttpResponse, PveTransportError> {
            assert_eq!(request.method, PveHttpMethod::Get);
            self.seen.lock().unwrap().push(request.path.clone());
            let (_, status, body) = self
                .routes
                .iter()
                .find(|(path, _, _)| request.path.ends_with(path))
                .unwrap_or_else(|| panic!("unscripted {}", request.path));
            Ok(PveHttpResponse {
                status: *status,
                body: body.to_string().into_bytes(),
            })
        }

        async fn execute_with_body(
            &self,
            _request: PveHttpRequest,
            _body: Vec<u8>,
        ) -> Result<PveHttpResponse, PveTransportError> {
            panic!("the reference read never sends a body");
        }
    }

    fn request() -> PveHttpRequest {
        PveHttpRequest {
            host: "pve.example".to_owned(),
            port: 8006,
            path: String::new(),
            pinned_fingerprint: Some("AA".to_owned()),
            credentials: Arc::new(PveCredentials {
                token_id: "fleet@pve!fleet".to_owned(),
                token: SensitiveString::new("top-secret-value".to_owned()),
            }),
            method: PveHttpMethod::Get,
        }
    }

    fn client(routes: Vec<(&'static str, u16, serde_json::Value)>) -> (ProxmoxClient, Arc<Script>) {
        let script = Arc::new(Script {
            routes,
            seen: Mutex::new(Vec::new()),
        });
        (ProxmoxClient::new(script.clone()), script)
    }

    #[tokio::test]
    async fn reads_mapping_references_and_ignores_everything_else() {
        let (client, script) = client(vec![(
            "/qemu/101/config",
            200,
            serde_json::json!({"data": {
                "name": "vm", "usb0": "mapping=dev-a,usb3=1", "usb1": "host=1-2",
                "usb2": "spice", "usb3": "mapping=bad id", "usb07": "mapping=x",
                "usb99": "mapping=y", "memory": 512
            }}),
        )]);
        let refs = client
            .qemu_usb_references(request(), "pve", 101, false)
            .await
            .unwrap();
        assert!(!refs.template);
        assert_eq!(
            refs.references,
            vec![PveUsbReference {
                slot: "usb0".to_owned(),
                mapping_id: "dev-a".to_owned(),
                stored: true,
                applied: false
            }]
        );
        assert_eq!(script.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_applied_view_adds_a_reference_a_pending_removal_hides() {
        let (client, _) = client(vec![
            (
                "/qemu/7/config?current=1",
                200,
                serde_json::json!({"data": {"usb0": "mapping=dev-a", "usb1": "mapping=dev-b"}}),
            ),
            (
                "/qemu/7/config",
                200,
                serde_json::json!({"data": {"template": 1, "usb1": "mapping=dev-b"}}),
            ),
        ]);
        let refs = client
            .qemu_usb_references(request(), "pve", 7, true)
            .await
            .unwrap();
        assert!(refs.template);
        let summary: Vec<_> = refs
            .references
            .iter()
            .map(|r| (r.slot.as_str(), r.stored, r.applied))
            .collect();
        assert_eq!(summary, [("usb0", false, true), ("usb1", true, true)]);
    }

    #[tokio::test]
    async fn a_refusal_and_a_bad_address_are_errors_without_the_secret() {
        let (client, script) = client(vec![(
            "/qemu/9/config",
            403,
            serde_json::json!({"message": "Permission check failed top-secret-value"}),
        )]);
        let error = client
            .qemu_usb_references(request(), "pve", 9, false)
            .await
            .unwrap_err();
        assert!(matches!(error, PveApiError::Forbidden { .. }));
        assert!(!error.to_string().contains("top-secret-value"), "{error}");
        let error = client
            .qemu_usb_references(request(), "../etc", 9, false)
            .await
            .unwrap_err();
        assert!(matches!(error, PveApiError::InvalidPayload { .. }));
        assert_eq!(script.seen.lock().unwrap().len(), 1, "nothing was sent");
    }
}
