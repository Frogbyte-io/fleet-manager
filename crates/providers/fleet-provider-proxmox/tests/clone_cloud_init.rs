//! Issue #561: Lab writes the controller's SSH public key to a Windows
//! clone's cloud-init drive (`PUT /nodes/{node}/qemu/{vmid}/config` with
//! `ciuser` and `sshkeys`) and reads it back. Synthetic responses.
use async_trait::async_trait;
use fleet_core::SensitiveString;
use fleet_provider_proxmox::*;
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct Transport {
    answer: serde_json::Value,
    seen: Mutex<Vec<(PveHttpRequest, Option<serde_json::Value>)>>,
}

impl Transport {
    fn new(answer: serde_json::Value) -> Arc<Self> {
        Arc::new(Self {
            answer,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn respond(&self, request: PveHttpRequest, body: Option<serde_json::Value>) -> PveHttpResponse {
        self.seen.lock().unwrap().push((request, body));
        PveHttpResponse {
            status: 200,
            body: self.answer.to_string().into_bytes(),
        }
    }
}

#[async_trait]
impl PveTransport for Transport {
    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        Ok(self.respond(request, Some(serde_json::from_slice(&body).unwrap())))
    }

    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        Ok(self.respond(request, None))
    }
}

fn request() -> PveHttpRequest {
    PveHttpRequest {
        host: "pve.test".into(),
        port: 8006,
        path: "/".into(),
        pinned_fingerprint: Some("fixture-pin".into()),
        credentials: Arc::new(PveCredentials {
            token_id: "fleet@pve!test".into(),
            token: SensitiveString::new("fixture-secret"),
        }),
        method: PveHttpMethod::Post,
    }
}

const CONFIG_PATH: &str = "/api2/json/nodes/pve9-n1/qemu/9000/config";
const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureFixtureFixtureFixtureFixture00";

#[tokio::test]
async fn the_cloud_init_login_is_a_conditional_put_with_percent_encoded_public_keys() {
    let transport = Transport::new(json!({"data": null}));
    ProxmoxClient::new(transport.clone())
        .qemu_set_cloud_init_login(
            request(),
            "pve9-n1",
            9000,
            "fleetadmin",
            &[KEY.to_owned()],
            "3c1f0a5d",
        )
        .await
        .unwrap();
    let seen = transport.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0.path, CONFIG_PATH);
    assert_eq!(seen[0].0.method, PveHttpMethod::Put);
    let body = seen[0].1.clone().unwrap();
    assert_eq!(body["ciuser"], "fleetadmin");
    assert_eq!(body["digest"], "3c1f0a5d");
    let sent = body["sshkeys"].as_str().unwrap();
    assert!(sent.starts_with("ssh-ed25519%20AAAA"), "{sent}");
    assert!(!sent.contains(' ') && !sent.contains('+'));
}

#[tokio::test]
async fn the_cloud_init_login_refuses_anything_but_public_key_lines() {
    let transport = Transport::new(json!({"data": null}));
    let client = ProxmoxClient::new(transport.clone());
    for keys in [
        vec![],
        vec!["-----BEGIN OPENSSH PRIVATE KEY-----".to_owned()],
        vec![format!("{KEY} comment")],
        vec![format!("{KEY}\nssh-rsa AAAA")],
        vec!["ssh-dss AAAA".to_owned()],
    ] {
        let result = client
            .qemu_set_cloud_init_login(request(), "n", 9000, "fleetadmin", &keys, "d")
            .await;
        assert!(
            matches!(result, Err(PveApiError::InvalidPayload { .. })),
            "{keys:?}"
        );
    }
    let bad_user = client
        .qemu_set_cloud_init_login(request(), "n", 9000, "a b", &[KEY.to_owned()], "d")
        .await;
    assert!(matches!(bad_user, Err(PveApiError::InvalidPayload { .. })));
    assert!(transport.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_config_read_decodes_the_cloud_init_login() {
    let transport = Transport::new(json!({"data": {
        "scsi0": "local-lvm:vm-9000-disk-0,size=8G",
        "ciuser": "fleetadmin",
        "sshkeys": "ssh-ed25519%20AAAAkey1%0Assh-rsa%20AAAAkey2%0A",
    }}));
    let read = ProxmoxClient::new(transport)
        .qemu_hardware(request(), "pve9-n1", 9000)
        .await
        .unwrap();
    assert_eq!(read.cloud_init_user.as_deref(), Some("fleetadmin"));
    assert_eq!(
        read.cloud_init_ssh_keys,
        ["ssh-ed25519 AAAAkey1", "ssh-rsa AAAAkey2"]
    );
}

async fn read(config: serde_json::Value) -> PveQemuHardware {
    ProxmoxClient::new(Transport::new(json!({ "data": config })))
        .qemu_hardware(request(), "pve9-n1", 9000)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_cloud_init_drive_is_detected_on_ide_sata_or_scsi_slots() {
    assert!(
        read(json!({"ide2": "local-lvm:vm-9000-cloudinit,media=cdrom,size=4M"}))
            .await
            .has_cloud_init_drive
    );
    for volume in [
        "local:9000/vm-9000-cloudinit.qcow2,media=cdrom",
        "nfs-store:9000/vm-9000-cloudinit.raw,media=cdrom",
        "dir:9000/vm-9000-cloudinit.vmdk",
    ] {
        assert!(
            read(json!({ "ide0": volume })).await.has_cloud_init_drive,
            "{volume}"
        );
    }
    for volume in [
        "local:9000/vm-9000-disk-0.qcow2",
        "local:9000/vm-9000-cloudinit.iso",
        "local:iso/cloudinit",
        "local:9000/vm--cloudinit.qcow2",
    ] {
        assert!(
            !read(json!({ "ide0": volume })).await.has_cloud_init_drive,
            "{volume}"
        );
    }
    assert!(
        read(json!({"scsi1": "local-lvm:vm-9000-cloudinit,size=4M"}))
            .await
            .has_cloud_init_drive
    );
    assert!(
        !read(json!({"ide2": "local:iso/seed.iso,media=cdrom", "scsi0": "local-lvm:vm-9000-disk-0,size=8G"}))
            .await
            .has_cloud_init_drive
    );
    // A description that mentions it is not a drive.
    assert!(
        !read(json!({"description": "x:cloudinit", "scsi0": "local-lvm:vm-9000-disk-0"}))
            .await
            .has_cloud_init_drive
    );
}

#[tokio::test]
async fn an_overlong_ciuser_or_oversized_sshkeys_do_not_fail_the_read() {
    let read = read(json!({
        "ciuser": "u".repeat(500),
        "sshkeys": "a".repeat(40_000),
    }))
    .await;
    assert_eq!(read.cloud_init_user, None);
    assert!(read.cloud_init_ssh_keys.is_empty());
    assert!(read.cloud_init_ssh_keys_oversized);
}

#[test]
fn only_the_listed_key_types_with_a_clean_blob_are_public_key_lines() {
    for kind in [
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    ] {
        assert!(is_public_key_line(&format!("{kind} AAAAB3+/=")), "{kind}");
    }
    for line in [
        "ecdsa-sha2-nistp999 AAAA",
        "sk-ssh-ed25519@evil AAAA",
        "ssh-ed25519 AAAA\tB",
        "ssh-ed25519 AA\u{7}AA",
        "ssh-ed25519 AAA!",
        "ssh-ed25519 ",
    ] {
        assert!(!is_public_key_line(line), "{line:?}");
    }
}
