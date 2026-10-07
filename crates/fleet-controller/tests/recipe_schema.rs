//! Contract test (#278): every key Fleet's structured recipe view reads is a
//! key the Packer Proxmox plugin accepts, and a recipe Fleet can freeze as a
//! build target also passes `packer validate`.
//!
//! The structured-view half always runs. The `packer validate` half runs
//! when an operator-installed `packer` with the Proxmox plugin is on `PATH`
//! (FM-S09: never bundled) and otherwise says so on stderr and passes:
//! `cargo xtask image-acceptance` is the gate that requires Packer.

use std::process::Command;

use fleet_core::{RecipeSource, RecipeVersion, StructuredRecipe};
use serde_json::{Value, json};

/// Builder fields every recipe here shares. The credential values are
/// placeholders: `packer validate` never contacts the host.
fn base(kind: &str) -> Value {
    json!({
        "type": kind,
        "proxmox_url": "https://pve.example.test:8006/api2/json",
        "username": "fleet@pve!fixture",
        "token": "placeholder",
        "node": "pve1",
        "vm_id": 901,
        "template_name": "fleet-image",
        "cores": 2,
        "memory": 2048,
        "communicator": "none"
    })
}

fn with(mut builder: Value, extra: Value) -> String {
    for (key, value) in extra.as_object().expect("an object").clone() {
        builder[key] = value;
    }
    json!({ "builders": [builder] }).to_string()
}

fn disk() -> Value {
    json!([{ "type": "scsi", "storage_pool": "local-lvm", "disk_size": "8G" }])
}

fn nic() -> Value {
    json!([{ "model": "virtio", "bridge": "vmbr0" }])
}

/// The recipes the structured view and the editor produce, by builder.
fn valid_recipes() -> Vec<(&'static str, RecipeSource, String)> {
    vec![
        (
            "a disk-less linked clone",
            RecipeSource::Clone,
            with(
                base("proxmox-clone"),
                json!({ "clone_vm_id": 7000, "full_clone": false, "network_adapters": nic() }),
            ),
        ),
        (
            "a clone with an added disk",
            RecipeSource::Clone,
            with(
                base("proxmox-clone"),
                json!({ "clone_vm": "golden", "disks": disk(), "network_adapters": nic() }),
            ),
        ),
        (
            "an ISO build through boot_iso",
            RecipeSource::Iso,
            with(
                base("proxmox-iso"),
                json!({
                    "boot_iso": { "type": "scsi", "iso_file": "local:iso/debian.iso", "iso_storage_pool": "local", "unmount": true },
                    "disks": disk(),
                    "network_adapters": nic()
                }),
            ),
        ),
    ]
}

fn version(source: RecipeSource, content: String) -> RecipeVersion {
    RecipeVersion {
        id: "v".to_owned(),
        recipe_id: "r".to_owned(),
        name: "image".to_owned(),
        description: String::new(),
        content_digest: "digest".to_owned(),
        content,
        source,
        node: "pve1".to_owned(),
        storage_pool: "local-lvm".to_owned(),
        published_at: 1,
        promoted_at: None,
        promoted_by: None,
        promoted_build_id: None,
    }
}

#[test]
fn the_structured_view_reads_the_plugin_keys_and_freezes_the_target() {
    for (label, source, content) in valid_recipes() {
        let structured = StructuredRecipe::from_raw(&content).expect(label);
        assert_eq!(structured.node, "pve1", "{label}");
        assert_eq!(structured.bridge.as_deref(), Some("vmbr0"), "{label}");
        if content.contains("\"disks\"") {
            assert_eq!(
                structured.storage_pool.as_deref(),
                Some("local-lvm"),
                "{label}"
            );
            assert_eq!(structured.disk_size.as_deref(), Some("8G"), "{label}");
        } else {
            assert_eq!(structured.storage_pool, None, "{label}");
        }
        assert!(
            version(source, content).has_frozen_build_target(),
            "{label} must freeze as a build target"
        );
    }
}

/// Runs `packer validate` on `content`; `None` when no usable Packer is
/// installed.
fn packer_validate(content: &str) -> Option<(bool, String)> {
    let installed = Command::new("packer")
        .args(["plugins", "installed"])
        .output()
        .ok()?;
    let plugins = String::from_utf8_lossy(&installed.stdout);
    if !installed.status.success() || !plugins.contains("packer-plugin-proxmox") {
        return None;
    }
    let dir = tempfile::tempdir().expect("a temporary directory");
    // A bare `.json` is Packer's legacy JSON template, as the executor
    // writes it.
    let path = dir.path().join("recipe.json");
    std::fs::write(&path, content).expect("the recipe is written");
    let output = Command::new("packer")
        .arg("validate")
        .arg(&path)
        .current_dir(dir.path())
        .output()
        .expect("packer runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Some((output.status.success(), text))
}

#[test]
fn packer_validate_accepts_every_structured_shape_and_refuses_the_old_keys() {
    if packer_validate("{}").is_none() {
        eprintln!(
            "skipped: no packer with the Proxmox plugin on PATH (FM-S09: operator-installed)"
        );
        return;
    }
    for (label, _, content) in valid_recipes() {
        let (ok, text) = packer_validate(&content).expect("packer is installed");
        assert!(ok, "packer validate refused {label}: {text}");
    }
    // The keys the structured view used to read (and the editor wrote) are
    // not plugin keys; this is the regression #278 fixed.
    for key in [
        "vm_storage_pool",
        "storage_pool",
        "disk_size",
        "bridge",
        "ciuser",
        "sshkeys",
    ] {
        let content = with(
            base("proxmox-clone"),
            json!({ "clone_vm_id": 7000, key: "x" }),
        );
        let (ok, text) = packer_validate(&content).expect("packer is installed");
        assert!(
            !ok && text.contains("unknown configuration key"),
            "packer accepted top-level {key}: {text}"
        );
    }
}
