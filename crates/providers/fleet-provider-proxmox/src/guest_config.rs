//! Guest settings and targeted clones for persistent VMs (#489): reading
//! the few config keys Fleet manages, writing an allow-listed subset of
//! them conditionally on the config digest, and cloning onto a chosen
//! storage or node. Inherent methods, so the [`crate::ProxmoxSource`] port
//! and its fakes are untouched.

use super::{
    ProxmoxClient, PveApiError, PveAudio, PveHttpMethod, PveHttpRequest, Upid, bounded_str,
    loose_number, read_audio, type_name_of, urlencode,
};

/// The settings of a QEMU guest that Fleet manages on persistent VMs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PveQemuSettings {
    /// The guest's name.
    pub name: Option<String>,
    /// Whether the guest is a template.
    pub template: bool,
    /// Whether PVE refuses to remove the guest.
    pub protection: bool,
    /// Whether the guest starts when the node boots.
    pub onboot: bool,
    /// The guest's tags.
    pub tags: Vec<String>,
    /// The description.
    pub description: Option<String>,
    /// The config lock (`clone` while a clone runs).
    pub lock: Option<String>,
    /// The config digest, for conditional writes.
    pub digest: Option<String>,
    /// vCPU cores per socket.
    pub cores: Option<u32>,
    /// Memory in MiB.
    pub memory_mib: Option<u32>,
    /// Whether `memory` is a property string with more than the size.
    pub memory_has_options: bool,
    /// The `net0` property string.
    pub net0: Option<String>,
    /// The virtual audio device.
    pub audio: Option<PveAudio>,
}

/// An allow-listed settings write. Only these keys can be written, so a
/// caller cannot reach hook scripts, passthrough or anything else.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PveQemuWrite {
    /// Replace the tags; an empty list removes them.
    pub tags: Option<Vec<String>>,
    /// Replace the description; empty removes it.
    pub description: Option<String>,
    /// Start on node boot.
    pub onboot: Option<bool>,
    /// Refuse (or allow) deletion.
    pub protection: Option<bool>,
    /// vCPU cores.
    pub cores: Option<u32>,
    /// Memory in MiB.
    pub memory_mib: Option<u32>,
    /// The whole `net0` value, already rewritten by [`with_bridge`].
    pub net0: Option<String>,
    /// The audio device.
    pub audio: Option<PveAudio>,
}

impl PveQemuWrite {
    /// Whether the write changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The request body: values to set, and the keys to delete (an empty
    /// tag list or description is a delete, which PVE accepts everywhere).
    #[must_use]
    pub fn body(&self, digest: &str) -> serde_json::Value {
        let mut body = serde_json::json!({ "digest": digest });
        let mut delete: Vec<&str> = Vec::new();
        match &self.tags {
            Some(tags) if tags.is_empty() => delete.push("tags"),
            Some(tags) => body["tags"] = serde_json::json!(tags.join(";")),
            None => {}
        }
        match &self.description {
            Some(text) if text.is_empty() => delete.push("description"),
            Some(text) => body["description"] = serde_json::json!(text),
            None => {}
        }
        if let Some(onboot) = self.onboot {
            body["onboot"] = serde_json::json!(u8::from(onboot));
        }
        if let Some(protection) = self.protection {
            body["protection"] = serde_json::json!(u8::from(protection));
        }
        if let Some(cores) = self.cores {
            body["cores"] = serde_json::json!(cores);
        }
        if let Some(memory) = self.memory_mib {
            body["memory"] = serde_json::json!(memory);
        }
        if let Some(net0) = &self.net0 {
            body["net0"] = serde_json::json!(net0);
        }
        if let Some(audio) = &self.audio {
            body["audio0"] = serde_json::json!(audio.to_property());
        }
        if !delete.is_empty() {
            body["delete"] = serde_json::json!(delete.join(","));
        }
        body
    }
}

/// Rewrites the bridge of a `net0` property string, keeping the model, MAC
/// and every other property.
///
/// # Errors
///
/// Fails when the string has no `bridge=` property to rewrite.
pub fn with_bridge(net0: &str, bridge: &str) -> Result<String, String> {
    let mut found = false;
    let parts: Vec<String> = net0
        .split(',')
        .map(|part| {
            if part.starts_with("bridge=") {
                found = true;
                format!("bridge={bridge}")
            } else {
                part.to_owned()
            }
        })
        .collect();
    if found {
        Ok(parts.join(","))
    } else {
        Err("net0 has no bridge to change".to_owned())
    }
}

fn flag(config: &serde_json::Value, key: &str) -> Result<bool, PveApiError> {
    match config.get(key) {
        None | Some(serde_json::Value::Null) => Ok(false),
        Some(_) => match loose_number(config, key) {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err(PveApiError::InvalidPayload {
                detail: format!("the guest config's {key} flag is unreadable"),
            }),
        },
    }
}

/// Reads the managed settings out of one config object.
fn parse_settings(config: &serde_json::Value) -> Result<PveQemuSettings, PveApiError> {
    if !config.is_object() {
        return Err(PveApiError::InvalidPayload {
            detail: format!(
                "the guest config is not an object (it is a {})",
                type_name_of(config)
            ),
        });
    }
    let text = |key: &str, limit: usize| {
        bounded_str(config, key, limit).map_err(|detail| PveApiError::InvalidPayload { detail })
    };
    let (audio, _) = read_audio(config);
    let memory = config.get("memory");
    let memory_has_options = memory
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.contains(','));
    let memory_mib = match memory {
        Some(serde_json::Value::String(value)) if memory_has_options => value
            .split(',')
            .find_map(|part| part.strip_prefix("current=").or(Some(part)))
            .and_then(|value| value.trim().parse().ok()),
        _ => loose_number(config, "memory").and_then(|value| u32::try_from(value).ok()),
    };
    Ok(PveQemuSettings {
        name: text("name", 128)?,
        template: flag(config, "template")?,
        protection: flag(config, "protection")?,
        onboot: flag(config, "onboot")?,
        tags: text("tags", 512)?
            .map(|tags| {
                tags.split([';', ',', ' '])
                    .filter(|tag| !tag.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        description: text("description", 8_192)?,
        lock: text("lock", 32)?,
        digest: text("digest", 64)?,
        cores: loose_number(config, "cores").and_then(|value| u32::try_from(value).ok()),
        memory_mib,
        memory_has_options,
        net0: text("net0", 512)?,
        audio,
    })
}

impl ProxmoxClient {
    /// Reads the settings Fleet manages on a persistent guest
    /// (`GET /nodes/{node}/qemu/{vmid}/config`; needs `VM.Audit`).
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`], including a config that is unreadable.
    pub async fn qemu_settings(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
    ) -> Result<PveQemuSettings, PveApiError> {
        let config = self
            .call(PveHttpRequest {
                path: format!("/api2/json/nodes/{}/qemu/{vmid}/config", urlencode(node)),
                method: PveHttpMethod::Get,
                ..request
            })
            .await?;
        parse_settings(&config)
    }

    /// Writes an allow-listed subset of a guest's settings
    /// (`PUT /nodes/{node}/qemu/{vmid}/config`, synchronous), conditional on
    /// `digest`. Needs `VM.Config.Options` (and `.CPU`, `.Memory`,
    /// `.Network`, `.HWType` for those keys). The caller decides which
    /// guest may be changed.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`], including PVE's refusal of a locked
    /// guest or a stale digest, and `InvalidPayload` for an empty write.
    pub async fn qemu_write_settings(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        write: &PveQemuWrite,
        digest: &str,
    ) -> Result<(), PveApiError> {
        if write.is_empty() {
            return Err(PveApiError::InvalidPayload {
                detail: "there is no setting to write".to_owned(),
            });
        }
        self.call_method_with_body(
            request,
            PveHttpMethod::Put,
            &format!("/api2/json/nodes/{}/qemu/{vmid}/config", urlencode(node)),
            &write.body(digest),
        )
        .await
        .map(|_| ())
    }

    /// Clones a guest, optionally onto another node and storage
    /// (`POST /nodes/{node}/qemu/{vmid}/clone` with `target` and
    /// `storage`; a storage needs a full clone). Answers the task.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`].
    #[allow(clippy::too_many_arguments)]
    pub async fn guest_clone_placed(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        new_id: u32,
        name: &str,
        target_node: Option<&str>,
        storage: Option<&str>,
    ) -> Result<Upid, PveApiError> {
        let mut body = serde_json::json!({ "newid": new_id, "name": name, "full": true });
        if let Some(target) = target_node {
            body["target"] = serde_json::json!(target);
        }
        if let Some(storage) = storage {
            body["storage"] = serde_json::json!(storage);
        }
        let data = self
            .call_with_body(
                request,
                &format!("/api2/json/nodes/{}/qemu/{vmid}/clone", urlencode(node)),
                &body,
            )
            .await?;
        let Some(raw) = data.as_str() else {
            return Err(PveApiError::InvalidPayload {
                detail: "the clone answer carries no UPID string".to_owned(),
            });
        };
        Upid::parse(raw).map_err(|detail| PveApiError::InvalidPayload { detail })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bridge_is_rewritten_and_everything_else_kept() {
        assert_eq!(
            with_bridge("virtio=DE:AD:BE:EF:00:01,bridge=vmbr0,firewall=1", "vmbr7").unwrap(),
            "virtio=DE:AD:BE:EF:00:01,bridge=vmbr7,firewall=1"
        );
        assert!(with_bridge("virtio=DE:AD:BE:EF:00:01", "vmbr7").is_err());
    }

    #[test]
    fn a_write_sets_values_and_deletes_empty_lists() {
        let body = PveQemuWrite {
            tags: Some(Vec::new()),
            description: Some(String::new()),
            onboot: Some(true),
            protection: Some(false),
            cores: Some(4),
            ..PveQemuWrite::default()
        }
        .body("abc");
        assert_eq!(body["digest"], "abc");
        assert_eq!(body["delete"], "tags,description");
        assert_eq!(body["onboot"], 1);
        assert_eq!(body["protection"], 0);
        assert_eq!(body["cores"], 4);
        assert!(body.get("tags").is_none());
        let body = PveQemuWrite {
            tags: Some(vec!["a".to_owned(), "b".to_owned()]),
            ..PveQemuWrite::default()
        }
        .body("d");
        assert_eq!(body["tags"], "a;b");
        assert!(body.get("delete").is_none());
    }

    #[test]
    fn settings_parse_the_keys_fleet_manages() {
        let settings = parse_settings(&serde_json::json!({
            "name": "vm", "protection": 1, "onboot": "0", "tags": "fleet-pve-test;x",
            "description": "d", "cores": 2, "memory": "4096", "digest": "abc",
            "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0", "lock": "clone"
        }))
        .unwrap();
        assert!(settings.protection && !settings.onboot && !settings.template);
        assert_eq!(settings.tags, vec!["fleet-pve-test", "x"]);
        assert_eq!(settings.memory_mib, Some(4096));
        assert_eq!(settings.lock.as_deref(), Some("clone"));
        assert!(parse_settings(&serde_json::json!([])).is_err());
    }
}
