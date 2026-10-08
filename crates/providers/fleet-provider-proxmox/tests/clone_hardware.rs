//! Issue #372: Lab applies a template's cores, memory, and disk to its
//! clone. Contract for reading the hardware out of the QEMU config
//! (`GET /nodes/{node}/qemu/{vmid}/config`), the synchronous config update
//! (`PUT …/config` with `cores`/`memory`), and the disk resize
//! (`PUT …/resize`), the same on PVE 8.x and 9.x. Synthetic, sanitized
//! responses; see `fixtures/README.md`.
use async_trait::async_trait;
use fleet_core::SensitiveString;
use fleet_provider_proxmox::*;
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct Transport {
    answer: (u16, serde_json::Value),
    seen: Mutex<Vec<(PveHttpRequest, Option<serde_json::Value>)>>,
}

impl Transport {
    fn new(status: u16, body: serde_json::Value) -> Arc<Self> {
        Arc::new(Self {
            answer: (status, body),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn respond(&self, request: PveHttpRequest, body: Option<serde_json::Value>) -> PveHttpResponse {
        self.seen.lock().unwrap().push((request, body));
        PveHttpResponse {
            status: self.answer.0,
            body: self.answer.1.to_string().into_bytes(),
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
const RESIZE_PATH: &str = "/api2/json/nodes/pve9-n1/qemu/9000/resize";

async fn hardware(
    body: serde_json::Value,
) -> (Result<PveQemuHardware, PveApiError>, Arc<Transport>) {
    let transport = Transport::new(200, body);
    let hardware = ProxmoxClient::new(transport.clone())
        .qemu_hardware(request(), "pve9-n1", 9000)
        .await;
    (hardware, transport)
}

fn boot_disk(key: &str, size_mib: Option<u64>) -> PveBootDisk {
    PveBootDisk {
        key: key.to_owned(),
        size_mib,
    }
}

#[tokio::test]
async fn a_clone_config_reads_as_its_cores_memory_and_boot_disk() {
    let (read, transport) = hardware(json!({"data": {
        "name": "fm-lab-record-1",
        "cores": 2,
        "memory": "2048",
        "boot": "order=scsi0;ide2;net0",
        "scsi0": "local-lvm:vm-9000-disk-0,discard=on,size=20G",
        "ide2": "local:iso/seed.iso,media=cdrom,size=366K",
        "digest": "3c1f0a5d9e7b2c4a6f8e0d1c3b5a79e8f6d4c2b0",
    }}))
    .await;
    assert_eq!(
        read.unwrap(),
        PveQemuHardware {
            cores: 2,
            memory_mib: 2048,
            memory_has_options: false,
            boot_disk: Some(boot_disk("scsi0", Some(20 * 1024))),
            digest: Some("3c1f0a5d9e7b2c4a6f8e0d1c3b5a79e8f6d4c2b0".to_owned()),
        }
    );
    let seen = transport.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0.path, CONFIG_PATH);
    assert_eq!(seen[0].0.method, PveHttpMethod::Get);
}

#[tokio::test]
async fn pve_defaults_apply_when_the_config_names_no_cores_or_memory() {
    let (read, _) = hardware(json!({"data": {"scsi0": "local-lvm:vm-9000-disk-0,size=8G"}})).await;
    let read = read.unwrap();
    assert_eq!((read.cores, read.memory_mib), (1, 512));
    assert_eq!(read.boot_disk, Some(boot_disk("scsi0", Some(8 * 1024))));
}

#[tokio::test]
async fn a_memory_property_string_is_read_and_flagged() {
    let (read, _) = hardware(json!({"data": {"memory": "current=4096,max=65536"}})).await;
    let read = read.unwrap();
    assert_eq!(read.memory_mib, 4096);
    assert!(read.memory_has_options);
    let (plain, _) = hardware(json!({"data": {"memory": 4096}})).await;
    let plain = plain.unwrap();
    assert_eq!(plain.memory_mib, 4096);
    assert!(!plain.memory_has_options);
}

#[tokio::test]
async fn the_boot_disk_follows_the_boot_order_then_bootdisk_then_the_only_disk() {
    // The order wins, and a CD-ROM never counts.
    let (read, _) = hardware(json!({"data": {
        "boot": "order=ide2;virtio1;scsi0",
        "ide2": "local:iso/x.iso,media=cdrom",
        "scsi0": "local-lvm:vm-9000-disk-0,size=10G",
        "virtio1": "local-lvm:vm-9000-disk-1,size=30720M",
    }}))
    .await;
    assert_eq!(
        read.unwrap().boot_disk,
        Some(boot_disk("virtio1", Some(30 * 1024)))
    );

    // No order: the legacy bootdisk key.
    let (read, _) = hardware(json!({"data": {
        "bootdisk": "scsi1",
        "scsi0": "local-lvm:vm-9000-disk-0,size=10G",
        "scsi1": "local-lvm:vm-9000-disk-1,size=1T",
    }}))
    .await;
    assert_eq!(
        read.unwrap().boot_disk,
        Some(boot_disk("scsi1", Some(1024 * 1024)))
    );

    // Several disks and nothing says which boots: none is picked.
    let (read, _) = hardware(json!({"data": {
        "scsi0": "local-lvm:vm-9000-disk-0,size=10G",
        "scsi1": "local-lvm:vm-9000-disk-1,size=10G",
    }}))
    .await;
    assert_eq!(read.unwrap().boot_disk, None);

    // No disk at all, and a disk whose size the config does not state.
    let (read, _) = hardware(json!({"data": {"cores": 1}})).await;
    assert_eq!(read.unwrap().boot_disk, None);
    let (read, _) = hardware(json!({"data": {"scsi0": "local-lvm:vm-9000-disk-0"}})).await;
    assert_eq!(read.unwrap().boot_disk, Some(boot_disk("scsi0", None)));
    // Sizes round up to whole MiB.
    let (read, _) = hardware(json!({"data": {"scsi0": "x:y,size=1500K"}})).await;
    assert_eq!(read.unwrap().boot_disk, Some(boot_disk("scsi0", Some(2))));
}

#[tokio::test]
async fn an_unreadable_hardware_config_is_refused() {
    for body in [
        json!({"data": null}),
        json!({"data": {"cores": "many"}}),
        json!({"data": {"cores": 0}}),
        json!({"data": {"memory": "lots"}}),
        json!({"data": {"memory": ["2048"]}}),
        json!({"data": {"digest": "0".repeat(65)}}),
    ] {
        let (read, _) = hardware(body.clone()).await;
        assert!(
            matches!(read, Err(PveApiError::InvalidPayload { .. })),
            "{body}: {read:?}"
        );
    }
}

#[tokio::test]
async fn setting_hardware_is_a_conditional_put_of_only_the_given_values() {
    let transport = Transport::new(200, json!({"data": null}));
    let client = ProxmoxClient::new(transport.clone());
    client
        .qemu_set_hardware(request(), "pve9-n1", 9000, Some(4), Some(8192), "3c1f0a5d")
        .await
        .unwrap();
    client
        .qemu_set_hardware(request(), "pve9-n1", 9000, Some(4), None, "3c1f0a5d")
        .await
        .unwrap();
    {
        let seen = transport.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        for (request, _) in seen.iter() {
            assert_eq!(request.path, CONFIG_PATH);
            assert_eq!(request.method, PveHttpMethod::Put);
            assert_eq!(request.pinned_fingerprint.as_deref(), Some("fixture-pin"));
        }
        assert_eq!(
            seen[0].1,
            Some(json!({"cores": 4, "memory": 8192, "digest": "3c1f0a5d"}))
        );
        assert_eq!(seen[1].1, Some(json!({"cores": 4, "digest": "3c1f0a5d"})));
    }
    // Nothing to set is refused before any request.
    let error = client
        .qemu_set_hardware(request(), "pve9-n1", 9000, None, None, "3c1f0a5d")
        .await
        .unwrap_err();
    assert!(matches!(error, PveApiError::InvalidPayload { .. }));
    assert_eq!(transport.seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn resizing_is_a_conditional_put_to_an_absolute_size() {
    let transport = Transport::new(200, json!({"data": null}));
    let client = ProxmoxClient::new(transport.clone());
    client
        .qemu_resize_disk(request(), "pve9-n1", 9000, "scsi0", 40, "3c1f0a5d")
        .await
        .unwrap();
    {
        let seen = transport.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let (request, body) = &seen[0];
        assert_eq!(request.path, RESIZE_PATH);
        assert_eq!(request.method, PveHttpMethod::Put);
        assert_eq!(
            body,
            &Some(json!({"disk": "scsi0", "size": "40G", "digest": "3c1f0a5d"}))
        );
    }
    // Only a QEMU disk key goes into the request.
    for disk in [
        "", "net0", "scsi", "scsi100", "scsi0;rm", "../scsi0", "SCSI0",
    ] {
        let error = client
            .qemu_resize_disk(request(), "pve9-n1", 9000, disk, 40, "3c1f0a5d")
            .await
            .unwrap_err();
        assert!(
            matches!(error, PveApiError::InvalidPayload { .. }),
            "{disk:?}: {error:?}"
        );
    }
    assert_eq!(transport.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn pve_refusals_of_the_hardware_writes_surface_as_errors() {
    // `check_vm_modify_config_perm`: cores need VM.Config.CPU, memory
    // VM.Config.Memory; resize needs VM.Config.Disk, all on /vms/{vmid}.
    for (privilege, call) in [
        ("VM.Config.CPU", "cores"),
        ("VM.Config.Memory", "memory"),
        ("VM.Config.Disk", "resize"),
    ] {
        let forbidden = Transport::new(
            403,
            json!({"data": null, "message": format!("Permission check failed (/vms/9000, {privilege})\n")}),
        );
        let client = ProxmoxClient::new(forbidden);
        let error = match call {
            "cores" => client
                .qemu_set_hardware(request(), "pve9-n1", 9000, Some(2), None, "d")
                .await
                .unwrap_err(),
            "memory" => client
                .qemu_set_hardware(request(), "pve9-n1", 9000, None, Some(2048), "d")
                .await
                .unwrap_err(),
            _ => client
                .qemu_resize_disk(request(), "pve9-n1", 9000, "scsi0", 20, "d")
                .await
                .unwrap_err(),
        };
        assert!(
            matches!(&error, PveApiError::Forbidden { detail } if detail.contains(privilege)),
            "{error:?}"
        );
    }
    // A stale digest and a shrink are server refusals, never writes.
    for message in [
        "checksum mismatch (file change by other user?)\n",
        "shrinking disks is not supported\n",
    ] {
        let refused = Transport::new(500, json!({"data": null, "message": message}));
        let error = ProxmoxClient::new(refused)
            .qemu_resize_disk(request(), "pve9-n1", 9000, "scsi0", 10, "stale")
            .await
            .unwrap_err();
        assert!(
            matches!(error, PveApiError::Http { status: 500, .. }),
            "{error:?}"
        );
    }
}
