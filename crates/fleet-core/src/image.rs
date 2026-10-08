//! The image-recipe primitives (FM-700): the recipe content model, its
//! draft/version lifecycle, and the digest binding a build to the exact
//! bytes it was defined by.

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

/// The maximum recipe content Fleet accepts. A Packer template is bounded
/// configuration; anything larger is refused rather than materialized.
pub const MAX_RECIPE_CONTENT_BYTES: usize = 256 * 1024;

/// The source a recipe builds from.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeSource {
    /// Build from an ISO (the classic install flow).
    #[default]
    Iso,
    /// Build by cloning an existing guest.
    Clone,
}

impl RecipeSource {
    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Iso => "iso",
            Self::Clone => "clone",
        }
    }

    /// Parses the stable string.
    ///
    /// # Errors
    ///
    /// Fails on an unrecognized source id.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "iso" => Ok(Self::Iso),
            "clone" => Ok(Self::Clone),
            other => Err(format!("unrecognized recipe source {other:?}")),
        }
    }
}

/// One image recipe: the Fleet metadata plus the raw `.pkr.json` content
/// stored verbatim. Packer's own fields are not re-validated by Fleet —
/// `packer validate` is the authority, and unknown fields pass through
/// untouched.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipeContent {
    /// The operator-facing recipe name.
    pub name: String,
    /// The operator-facing description.
    pub description: String,
    /// The PVE node the recipe builds on.
    pub node: String,
    /// The PVE storage pool the build writes to. `None` when the builder
    /// block omits it (consistent with `node`'s absence rule).
    pub storage_pool: Option<String>,
    /// What the recipe builds from.
    pub source: RecipeSource,
    /// The raw Packer template content (`.pkr.json`/`.pkr.hcl`), stored
    /// verbatim. Unknown fields are Fleet's problem never to touch.
    pub content: String,
}

impl RecipeContent {
    /// The SHA-256 digest of the recipe's bytes: the identity a build
    /// references, so a build of a since-edited recipe is reproducible.
    ///
    /// # Errors
    ///
    /// Fails when the content exceeds the bound.
    pub fn content_digest(&self) -> Result<String, String> {
        self.digest(false)
    }

    /// The digest of a version published from this content. A version that
    /// opts into `insecure_skip_tls_verify` (#284) is a different build
    /// input, so the opt-in joins the digest; without it the digest is
    /// exactly [`Self::content_digest`], so every version published before
    /// the opt-in existed keeps its identity.
    ///
    /// # Errors
    ///
    /// Fails when the content exceeds the bound.
    pub fn version_digest(&self, allow_insecure_tls: bool) -> Result<String, String> {
        self.digest(allow_insecure_tls)
    }

    fn digest(&self, allow_insecure_tls: bool) -> Result<String, String> {
        if self.content.len() > MAX_RECIPE_CONTENT_BYTES {
            return Err(format!(
                "the recipe content is {} bytes, over the {MAX_RECIPE_CONTENT_BYTES}-byte bound",
                self.content.len()
            ));
        }
        // The digest covers every build-affecting field: the Packer bytes
        // AND the Fleet metadata (node, pool, source), so a metadata-only
        // edit produces a new version instead of silently reusing one.
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.content.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.node.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.storage_pool.as_deref().unwrap_or_default().as_bytes());
        hasher.update(b"\n");
        hasher.update(self.source.id().as_bytes());
        if allow_insecure_tls {
            hasher.update(b"\nallow-insecure-tls");
        }
        let digest: [u8; 32] = hasher.finalize().into();
        Ok(digest.iter().fold(String::with_capacity(64), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        }))
    }

    /// Validates the Fleet-owned metadata. Packer's own fields are the
    /// CLI's authority, not Fleet's.
    ///
    /// # Errors
    ///
    /// Fails on a malformed field.
    pub fn validate(&self) -> Result<(), String> {
        let count = self.name.chars().count();
        if count == 0 || count > 128 {
            return Err("the name must be 1..=128 characters".to_owned());
        }
        if self.description.chars().count() > 512 {
            return Err("the description must be at most 512 characters".to_owned());
        }
        for (label, value) in [
            ("node", &self.node),
            (
                "storage_pool",
                &self.storage_pool.clone().unwrap_or_default(),
            ),
        ] {
            let len = value.chars().count();
            if len == 0 || len > 128 {
                return Err(format!("the {label} must be 1..=128 characters"));
            }
        }
        if self.content.is_empty() {
            return Err("the recipe content must not be empty".to_owned());
        }
        self.content_digest()?;
        Ok(())
    }
}

/// Whether a recipe's builders ask Packer's Proxmox plugin to skip TLS
/// verification (#284). Any `insecure_skip_tls_verify` value other than a
/// literal `false` counts, including a template variable: Fleet cannot know
/// what it resolves to. Keys match case-insensitively, as Packer's
/// `mapstructure` decoding does. Content that is not a JSON template is
/// judged by whether the key appears in it at all.
#[must_use]
pub fn requests_insecure_tls(content: &str) -> bool {
    const KEY: &str = "insecure_skip_tls_verify";
    let Ok(template) = serde_json::from_str::<serde_json::Value>(content) else {
        return content.to_ascii_lowercase().contains(KEY);
    };
    // Every case-insensitive `builders` key counts: which one a decoder
    // keeps is not Fleet's to guess.
    template.as_object().is_some_and(|object| {
        object
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("builders"))
            .filter_map(|(_, builders)| builders.as_array())
            .flatten()
            .filter_map(serde_json::Value::as_object)
            .any(|builder| {
                builder.iter().any(|(key, value)| {
                    key.eq_ignore_ascii_case(KEY) && *value != serde_json::Value::Bool(false)
                })
            })
    })
}

/// A published recipe version: immutable, identified by its digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipeVersion {
    /// The version's identity: the recipe it came from plus the content
    /// digest, so the same content published twice is the same version.
    pub id: String,
    /// The recipe the version came from.
    pub recipe_id: String,
    /// The recipe name at publication time.
    pub name: String,
    /// The frozen content digest.
    pub content_digest: String,
    /// The frozen description.
    pub description: String,
    /// The frozen content.
    pub content: String,
    /// The source at publication time.
    pub source: RecipeSource,
    /// The node at publication time.
    pub node: String,
    /// The storage pool at publication time.
    pub storage_pool: String,
    /// When the version was published (epoch millis).
    pub published_at: i64,
    /// When the version was promoted (epoch millis), when any. At most
    /// one version per recipe is promoted; the latest promotion demotes
    /// the previous one explicitly.
    pub promoted_at: Option<i64>,
    /// Who promoted the version.
    pub promoted_by: Option<String>,
    /// The build record the version's latest promotion pinned: Lab clones
    /// this build's template, and a later rebuild never changes it (issue
    /// #281). Kept after a demotion so earlier leases keep their source.
    /// `None` when the version was never promoted, or was promoted before
    /// the pin existed and not since.
    pub promoted_build_id: Option<String>,
    /// Whether the version may build with `insecure_skip_tls_verify` (#284).
    /// Set only by an explicit, audited opt-in at publication and part of
    /// the version digest. Without it, a build of a recipe that skips TLS
    /// verification is refused (`insecure_tls_not_allowed`); every other
    /// build pins the account's confirmed certificate for Packer.
    #[serde(default)]
    pub allow_insecure_tls: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipe(content: &str) -> RecipeContent {
        RecipeContent {
            name: "ubuntu-base".to_owned(),
            description: "the base image".to_owned(),
            node: "pve".to_owned(),
            storage_pool: Some("local-lvm".to_owned()),
            source: RecipeSource::Iso,
            content: content.to_owned(),
        }
    }

    #[test]
    fn digests_are_stable_and_content_sensitive() {
        let a = recipe("{\"builders\":[]}");
        let b = recipe("{\"builders\":[]}");
        let c = recipe("{\"builders\":[{}]}");
        assert_eq!(a.content_digest().unwrap(), b.content_digest().unwrap());
        assert_ne!(a.content_digest().unwrap(), c.content_digest().unwrap());
    }

    #[test]
    fn the_insecure_tls_opt_in_is_part_of_the_version_digest_only_when_set() {
        let a = recipe("{\"builders\":[]}");
        assert_eq!(
            a.version_digest(false).unwrap(),
            a.content_digest().unwrap()
        );
        assert_ne!(a.version_digest(true).unwrap(), a.content_digest().unwrap());
    }

    #[test]
    fn insecure_tls_requests_are_recognized_in_every_spelling() {
        for content in [
            r#"{"builders":[{"type":"proxmox-clone","insecure_skip_tls_verify":true}]}"#,
            r#"{"builders":[{"type":"proxmox-clone","insecure_skip_tls_verify":"true"}]}"#,
            r#"{"builders":[{"type":"proxmox-clone","insecure_skip_tls_verify":"{{user `skip`}}"}]}"#,
            r#"{"builders":[{"type":"proxmox-clone"},{"INSECURE_SKIP_TLS_VERIFY":1}]}"#,
            r#"{"Builders":[{"Insecure_Skip_Tls_Verify":true}]}"#,
            r#"{"Builders":[{"type":"proxmox-clone"}],"builders":[{"insecure_skip_tls_verify":true}]}"#,
            r#"{"builders":[{"type":"proxmox-clone"}],"BUILDERS":[{"insecure_skip_tls_verify":true}]}"#,
            "source \"proxmox-clone\" \"x\" { insecure_skip_tls_verify = true }",
        ] {
            assert!(requests_insecure_tls(content), "{content}");
        }
        for content in [
            r#"{"builders":[{"type":"proxmox-clone"}]}"#,
            r#"{"builders":[{"type":"proxmox-clone","insecure_skip_tls_verify":false}]}"#,
            r#"{"variables":{"insecure_skip_tls_verify":"true"},"builders":[{}]}"#,
            "not json",
        ] {
            assert!(!requests_insecure_tls(content), "{content}");
        }
    }

    #[test]
    fn validation_refuses_malformed_metadata_and_oversized_content() {
        let mut bad = recipe("{}");
        bad.name = String::new();
        assert!(bad.validate().is_err());
        bad.name = "ok".to_owned();
        bad.node = String::new();
        assert!(bad.validate().is_err());
        bad.node = "pve".to_owned();
        bad.content = "x".repeat(MAX_RECIPE_CONTENT_BYTES + 1);
        assert!(bad.validate().is_err());
        assert!(recipe("{}").validate().is_ok());
    }

    #[test]
    fn sources_round_trip_their_ids() {
        for id in ["iso", "clone"] {
            let source = RecipeSource::from_id(id).unwrap();
            assert_eq!(source.id(), id);
        }
        assert!(RecipeSource::from_id("mystery").is_err());
    }
}

/// The structured recipe: exactly the supported Proxmox field subset,
/// mapped onto a canonical `.pkr.json` skeleton. Fields outside the
/// subset live only in the raw content and survive every round-trip.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuredRecipe {
    /// The PVE node the recipe builds on.
    pub node: String,
    /// The PVE storage pool of the builder's first declared disk
    /// (`disks[0].storage_pool`). `None` when the builder declares no disk:
    /// a `proxmox-clone` without `disks` keeps the source template's
    /// storage, which the plugin offers no key for.
    pub storage_pool: Option<String>,
    /// What the recipe builds from.
    pub source: RecipeSource,
    /// The ISO file path, for the iso source: `boot_iso.iso_file`, or the
    /// plugin's deprecated top-level `iso_file`.
    pub iso_file: Option<String>,
    /// The ISO's storage pool, for the iso source: `boot_iso.iso_storage_pool`,
    /// or the deprecated top-level `iso_storage_pool`.
    pub iso_storage_pool: Option<String>,
    /// The guest to clone, for the clone source.
    pub clone_vm: Option<String>,
    /// The vCPU count.
    pub cores: Option<u32>,
    /// The memory in MiB.
    pub memory: Option<u32>,
    /// The first disk's size (`disks[0].disk_size`), as Packer's
    /// `G`-suffixed string.
    pub disk_size: Option<String>,
    /// The first network adapter's bridge (`network_adapters[0].bridge`).
    pub bridge: Option<String>,
}

/// A parsed `.pkr.json`'s shape, as the structured view needs: the
/// builders' `proxmox-*` block and whether the content parsed as JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedTemplate {
    /// Whether the content parsed as JSON at all.
    pub is_json: bool,
    /// The first `proxmox-*` builder block, when the content carries one.
    pub builder: Option<BuilderBlock>,
}

/// One builder block's fields, as the structured view reads them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuilderBlock {
    /// The builder's `type`, e.g. `proxmox-clone`.
    pub ptype: String,
    /// The block's fields, as raw JSON.
    pub fields: serde_json::Value,
}

/// Extracts the parsed template shape from raw content. Tolerant: a
/// non-JSON template (`.pkr.hcl`) reports `is_json: false` and no
/// structured view is offered.
#[must_use]
pub fn parse_template(content: &str) -> ParsedTemplate {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return ParsedTemplate::default();
    };
    let builder = value
        .get("builders")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .find_map(|builder| {
            // Only the two supported builders receive a structured view:
            // arbitrary `proxmox*` types would get a misleading one.
            let ptype = builder
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            (ptype == "proxmox-iso" || ptype == "proxmox-clone").then(|| BuilderBlock {
                ptype: ptype.to_owned(),
                fields: builder.clone(),
            })
        });
    ParsedTemplate {
        is_json: true,
        builder,
    }
}

fn field_str<'a>(builder: &'a BuilderBlock, key: &str) -> Option<&'a str> {
    builder.fields.get(key).and_then(serde_json::Value::as_str)
}

/// One string field of the first entry of a builder's list field, e.g.
/// `disks[0].storage_pool`: the plugin's block shape (packer-plugin-proxmox
/// 1.2.x, `builder/proxmox/common/config.go`).
fn first_entry_str<'a>(builder: &'a BuilderBlock, list: &str, key: &str) -> Option<&'a str> {
    builder
        .fields
        .get(list)
        .and_then(serde_json::Value::as_array)
        .and_then(|entries| entries.first())
        .and_then(|entry| entry.get(key))
        .and_then(serde_json::Value::as_str)
}

/// A `boot_iso` field, falling back to the deprecated top-level key.
fn boot_iso_str<'a>(builder: &'a BuilderBlock, key: &str) -> Option<&'a str> {
    builder
        .fields
        .get("boot_iso")
        .and_then(|iso| iso.get(key))
        .and_then(serde_json::Value::as_str)
        .or_else(|| field_str(builder, key))
}

impl StructuredRecipe {
    /// The structured view of raw content, when it carries a Proxmox
    /// builder block. `None` means the content has no structured view (a
    /// non-JSON template or no Proxmox builder).
    #[must_use]
    pub fn from_raw(content: &str) -> Option<Self> {
        let parsed = parse_template(content);
        let builder = parsed.builder?;
        Some(Self {
            node: field_str(&builder, "node")?.to_owned(),
            storage_pool: first_entry_str(&builder, "disks", "storage_pool").map(str::to_owned),

            // The builder type is the source of truth, not the presence
            // of a clone field.
            source: match builder.ptype.as_str() {
                "proxmox-clone" => RecipeSource::Clone,
                _ => RecipeSource::Iso,
            },
            iso_file: boot_iso_str(&builder, "iso_file").map(str::to_owned),
            iso_storage_pool: boot_iso_str(&builder, "iso_storage_pool").map(str::to_owned),
            // Packer's `clone_vm` is the VM **name** (a string); the
            // numeric VMID is the separate `clone_vm_id` field. Both are
            // accepted; the name form is the documented one.
            clone_vm: builder
                .fields
                .get("clone_vm")
                .map(|value| match value {
                    serde_json::Value::String(text) => text.clone(),
                    serde_json::Value::Number(number) => number.to_string(),
                    other => other.to_string(),
                })
                .or_else(|| {
                    builder
                        .fields
                        .get("clone_vm_id")
                        .and_then(serde_json::Value::as_u64)
                        .map(|value| value.to_string())
                }),
            cores: builder
                .fields
                .get("cores")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u32::try_from(value).ok()),
            memory: builder
                .fields
                .get("memory")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u32::try_from(value).ok()),
            disk_size: first_entry_str(&builder, "disks", "disk_size").map(str::to_owned),
            bridge: first_entry_str(&builder, "network_adapters", "bridge").map(str::to_owned),
        })
    }
}

#[cfg(test)]
mod structured_tests {
    use super::*;

    #[test]
    fn the_structured_view_parses_a_proxmox_builder() {
        let content = r#"{
            "builders": [{
                "type": "proxmox-clone",
                "node": "pve",
                "clone_vm": 101,
                "cores": 2,
                "memory": 2048,
                "disks": [{"type": "scsi", "storage_pool": "local-lvm", "disk_size": "10G"}],
                "network_adapters": [{"model": "virtio", "bridge": "vmbr0"}],
                "unknown_field": {"nested": true}
            }],
            "variables": {"x": 1}
        }"#;
        let structured = StructuredRecipe::from_raw(content).expect("a structured view");
        assert_eq!(structured.node, "pve");
        assert_eq!(structured.source, RecipeSource::Clone);
        assert_eq!(structured.clone_vm.as_deref(), Some("101"));
        assert_eq!(structured.storage_pool.as_deref(), Some("local-lvm"));
        assert_eq!(structured.cores, Some(2));
        assert_eq!(structured.memory, Some(2048));
        assert_eq!(structured.disk_size.as_deref(), Some("10G"));
        assert_eq!(structured.bridge.as_deref(), Some("vmbr0"));
    }

    #[test]
    fn the_structured_view_reads_only_keys_the_plugin_has() {
        // The plugin has no top-level storage, disk size, or bridge key
        // (`packer validate` refuses them), so the view ignores them rather
        // than presenting a value Packer would never apply.
        let invalid = r#"{"builders": [{
            "type": "proxmox-iso", "node": "pve",
            "vm_storage_pool": "local-lvm", "storage_pool": "local-lvm",
            "disk_size": "10G", "bridge": "vmbr0"
        }]}"#;
        let structured = StructuredRecipe::from_raw(invalid).expect("a structured view");
        assert_eq!(structured.storage_pool, None);
        assert_eq!(structured.disk_size, None);
        assert_eq!(structured.bridge, None);
        // boot_iso wins over the deprecated top-level ISO keys.
        let iso = r#"{"builders": [{
            "type": "proxmox-iso", "node": "pve",
            "boot_iso": {"iso_file": "local:iso/new.iso", "iso_storage_pool": "local"},
            "iso_file": "local:iso/old.iso"
        }]}"#;
        let structured = StructuredRecipe::from_raw(iso).expect("a structured view");
        assert_eq!(structured.iso_file.as_deref(), Some("local:iso/new.iso"));
        assert_eq!(structured.iso_storage_pool.as_deref(), Some("local"));
        let deprecated = r#"{"builders": [{"type": "proxmox-iso", "node": "pve", "iso_file": "local:iso/old.iso"}]}"#;
        assert_eq!(
            StructuredRecipe::from_raw(deprecated)
                .and_then(|s| s.iso_file)
                .as_deref(),
            Some("local:iso/old.iso")
        );
    }

    #[test]
    fn non_json_templates_have_no_structured_view() {
        // HCL2 content: honest absence, not a guess.
        assert!(StructuredRecipe::from_raw("source \"proxmox-clone\" {} {}").is_none());
        // JSON without a Proxmox builder: no structured view.
        assert!(StructuredRecipe::from_raw(r#"{"builders":[{"type":"docker"}]}"#).is_none());
    }
}

/// A safe, immutable snapshot of an image build. Raw variables, credentials,
/// filesystem paths and Packer output are deliberately excluded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageBuildRecord {
    /// Stable build identity (the durable operation id).
    pub id: String,
    /// The durable operation executing this build.
    pub operation_id: String,
    /// The recipe this build belongs to.
    pub recipe_id: String,
    /// The immutable recipe version.
    pub version_id: String,
    /// Digest binding the build to all recipe inputs.
    pub content_digest: String,
    /// Digests of provisioning assets; never their paths or contents.
    pub asset_digests: Vec<String>,
    /// Probed Packer version; absent when the probe failed.
    pub packer_version: Option<String>,
    /// Probed Proxmox plugin version; absent when the probe failed.
    pub proxmox_plugin_version: Option<String>,
    /// Resolved target Fleet account; absent only when target binding failed.
    pub account_id: Option<String>,
    /// Frozen target node.
    pub node: String,
    /// Frozen target storage pool.
    pub storage_pool: String,
    /// Start time in epoch milliseconds.
    pub started_at: i64,
    /// Completion time in epoch milliseconds.
    pub ended_at: Option<i64>,
    /// Running, succeeded, failed, or cancelled.
    pub outcome: String,
    /// Safe terminal reason code; never provider output.
    pub reason: Option<String>,
    /// Concrete output template identity, present only on success.
    pub template: Option<ImageBuildTemplate>,
}

/// The concrete template produced by an image build.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageBuildTemplate {
    /// Target node reported by the artifact or frozen recipe.
    pub node: String,
    /// Proxmox VMID.
    pub vmid: u32,
    /// Template name from the frozen recipe builder.
    pub name: String,
}

impl RecipeVersion {
    /// Whether a single builder's declared target matches this version's
    /// immutable Fleet metadata. Dynamic or ambiguous targets cannot be
    /// represented by one reproducible build record.
    #[must_use]
    pub fn has_frozen_build_target(&self) -> bool {
        let Some(structured) = StructuredRecipe::from_raw(&self.content) else {
            return false;
        };
        let Ok(content) = serde_json::from_str::<serde_json::Value>(&self.content) else {
            return false;
        };
        content
            .get("builders")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|builders| builders.len() == 1)
            && [self.node.as_str(), self.storage_pool.as_str()]
                .iter()
                .all(|target| {
                    !target.is_empty()
                        && target.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                        })
                })
            && structured.node == self.node
            && self.frozen_storage(&content)
            && structured.source == self.source
    }

    /// Whether the builder's storage matches the version's. Every declared
    /// disk must name the version's pool literally. A `proxmox-clone` with
    /// no `disks` keeps the source template's storage, for which the plugin
    /// has no key: the version's pool is then the operator's declaration,
    /// not something the recipe can prove. An ISO build always needs a disk.
    fn frozen_storage(&self, content: &serde_json::Value) -> bool {
        let disks = content
            .get("builders")
            .and_then(|builders| builders.get(0))
            .and_then(|builder| builder.get("disks"));
        match disks {
            None => self.source == RecipeSource::Clone,
            Some(serde_json::Value::Array(disks)) if !disks.is_empty() => {
                disks.iter().all(|disk| {
                    disk.get("storage_pool").and_then(serde_json::Value::as_str)
                        == Some(self.storage_pool.as_str())
                })
            }
            Some(_) => false,
        }
    }
}

#[cfg(test)]
mod frozen_target_tests {
    use super::*;

    #[test]
    fn matching_metadata_cannot_freeze_interpolated_targets() {
        for (node, storage_pool, expected) in [
            ("pve-1", "local-lvm", true),
            ("{{user `node`}}", "local-lvm", false),
            ("pve", "{{user `storage`}}", false),
            ("${var.node}", "local-lvm", false),
            ("pve", "${var.storage}", false),
        ] {
            let version = RecipeVersion {
                id: "v".to_owned(), recipe_id: "r".to_owned(), name: "image".to_owned(),
                description: String::new(), content_digest: "digest".to_owned(),
                content: serde_json::json!({"builders":[{"type":"proxmox-clone", "node":node, "disks":[{"type":"scsi", "storage_pool":storage_pool, "disk_size":"8G"}]}]}).to_string(),
                source: RecipeSource::Clone, node: node.to_owned(), storage_pool: storage_pool.to_owned(),
                published_at: 1, promoted_at: None, promoted_by: None, promoted_build_id: None, allow_insecure_tls: false,
            };
            assert_eq!(version.has_frozen_build_target(), expected);
        }
    }

    fn version(source: RecipeSource, builder: &serde_json::Value) -> RecipeVersion {
        RecipeVersion {
            id: "v".to_owned(),
            recipe_id: "r".to_owned(),
            name: "image".to_owned(),
            description: String::new(),
            content_digest: "digest".to_owned(),
            content: serde_json::json!({ "builders": [builder] }).to_string(),
            source,
            node: "pve".to_owned(),
            storage_pool: "local-lvm".to_owned(),
            published_at: 1,
            promoted_at: None,
            promoted_by: None,
            promoted_build_id: None,
            allow_insecure_tls: false,
        }
    }

    #[test]
    fn the_storage_target_follows_the_plugin_schema() {
        let clone =
            serde_json::json!({"type": "proxmox-clone", "node": "pve", "clone_vm_id": 7000});
        // A disk-less clone inherits the source's storage.
        assert!(version(RecipeSource::Clone, &clone).has_frozen_build_target());
        // Declared disks must all name the version's pool.
        let mut with_disks = clone.clone();
        with_disks["disks"] = serde_json::json!([
            {"type": "scsi", "storage_pool": "local-lvm", "disk_size": "8G"},
            {"type": "scsi", "storage_pool": "other", "disk_size": "8G"}
        ]);
        assert!(!version(RecipeSource::Clone, &with_disks).has_frozen_build_target());
        // An ISO build without a disk has no storage target at all.
        let iso = serde_json::json!({"type": "proxmox-iso", "node": "pve"});
        assert!(!version(RecipeSource::Iso, &iso).has_frozen_build_target());
        let mut iso_disk = iso;
        iso_disk["disks"] =
            serde_json::json!([{"type": "scsi", "storage_pool": "local-lvm", "disk_size": "8G"}]);
        assert!(version(RecipeSource::Iso, &iso_disk).has_frozen_build_target());
        // The plugin-invalid top-level key no longer freezes anything.
        let legacy = serde_json::json!({"type": "proxmox-iso", "node": "pve", "vm_storage_pool": "local-lvm"});
        assert!(!version(RecipeSource::Iso, &legacy).has_frozen_build_target());
    }
}
