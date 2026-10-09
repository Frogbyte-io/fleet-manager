//! Issue #290: Lab clears the `protection` flag a clone copies from its
//! template. Contract for the QEMU config read
//! (`GET /nodes/{node}/qemu/{vmid}/config`) and the synchronous config
//! update (`PUT …/config` with `protection=0`), the same on PVE 8.x and
//! 9.x. Synthetic, sanitized responses; see `fixtures/README.md`.
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

async fn flags(
    body: serde_json::Value,
) -> (Result<PveQemuConfigFlags, PveApiError>, Arc<Transport>) {
    let transport = Transport::new(200, body);
    let flags = ProxmoxClient::new(transport.clone())
        .qemu_config_flags(request(), "pve9-n1", 9000)
        .await;
    (flags, transport)
}

#[tokio::test]
async fn a_fresh_clone_of_a_protected_template_reads_as_protected() {
    // `clone_vm` copies every option but snapshot state, unused disks, and
    // MACs, so `protection: 1` lands on the clone.
    let (flags, transport) = flags(json!({"data": {
        "name": "fm-lab-record-1",
        "protection": 1,
        "cores": 2,
        "memory": "2048",
        "scsi0": "local-lvm:vm-9000-disk-0,size=20G",
        "digest": "3c1f0a5d9e7b2c4a6f8e0d1c3b5a79e8f6d4c2b0",
    }}))
    .await;
    assert_eq!(
        flags.unwrap(),
        PveQemuConfigFlags {
            name: Some("fm-lab-record-1".to_owned()),
            template: false,
            protection: true,
            lock: None,
            digest: Some("3c1f0a5d9e7b2c4a6f8e0d1c3b5a79e8f6d4c2b0".to_owned()),
            parent: None,
            audio: None,
        }
    );
    let seen = transport.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0.path, CONFIG_PATH);
    assert_eq!(seen[0].0.method, PveHttpMethod::Get);
    assert_eq!(seen[0].0.pinned_fingerprint.as_deref(), Some("fixture-pin"));
}

#[tokio::test]
async fn a_running_clone_reports_its_lock_and_an_unprotected_one_no_flag() {
    // While `clone_vm` copies disks, the target config holds `lock: clone`.
    let (running, _) = flags(json!({"data": {"lock": "clone", "digest": "00"}})).await;
    let running = running.unwrap();
    assert_eq!(running.lock.as_deref(), Some("clone"));
    assert_eq!(running.name, None);

    let (plain, _) = flags(json!({"data": {"name": "fm-lab-record-1", "protection": 0}})).await;
    let plain = plain.unwrap();
    assert!(!plain.protection && !plain.template && plain.lock.is_none());

    // The JSON formatter may answer flags as strings.
    let (loose, _) = flags(json!({"data": {"template": "1", "protection": "1"}})).await;
    let loose = loose.unwrap();
    assert!(loose.template && loose.protection);
}

#[tokio::test]
async fn an_unreadable_config_is_refused() {
    for body in [
        json!({"data": null}),
        json!({"data": ["protection", 1]}),
        json!({"data": {"protection": "yes"}}),
        json!({"data": {"template": 2}}),
        // Over-long values are refused, never truncated.
        json!({"data": {"name": "x".repeat(129)}}),
        json!({"data": {"digest": "0".repeat(65)}}),
        json!({"data": {"lock": "l".repeat(33)}}),
        json!({"data": {"lock": 1}}),
        json!({"data": {"lock": {"kind": "clone"}}}),
    ] {
        let (flags, _) = flags(body.clone()).await;
        assert!(
            matches!(flags, Err(PveApiError::InvalidPayload { .. })),
            "{body}: {flags:?}"
        );
    }
}

#[tokio::test]
async fn clearing_protection_is_a_put_of_protection_zero_with_the_digest() {
    // `update_vm` is synchronous: `{"data": null}`.
    let transport = Transport::new(200, json!({"data": null}));
    let client = ProxmoxClient::new(transport.clone());
    client
        .qemu_clear_protection(request(), "pve9-n1", 9000, "3c1f0a5d")
        .await
        .unwrap();
    let seen = transport.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let (request, body) = &seen[0];
    assert_eq!(request.path, CONFIG_PATH);
    assert_eq!(request.method, PveHttpMethod::Put);
    assert_eq!(request.pinned_fingerprint.as_deref(), Some("fixture-pin"));
    // Always conditional on the digest of the checked config.
    assert_eq!(body, &Some(json!({"protection": 0, "digest": "3c1f0a5d"})));
}

#[tokio::test]
async fn pve_refusals_of_the_update_surface_as_errors() {
    // `check_vm_modify_config_perm`: `protection` is a general option,
    // checked as VM.Config.Options on /vms/{vmid}.
    let forbidden = Transport::new(
        403,
        json!({"data": null, "message": "Permission check failed (/vms/9000, VM.Config.Options)\n"}),
    );
    let error = ProxmoxClient::new(forbidden)
        .qemu_clear_protection(request(), "pve9-n1", 9000, "3c1f0a5d")
        .await
        .unwrap_err();
    assert!(
        matches!(&error, PveApiError::Forbidden { detail } if detail.contains("VM.Config.Options")),
        "{error:?}"
    );

    // `update_vm_api` refuses a stale digest, then a locked guest
    // (`check_lock`), before it writes.
    for message in [
        "checksum mismatch (file change by other user?)\n",
        "VM is locked (clone)\n",
    ] {
        let refused = Transport::new(500, json!({"data": null, "message": message}));
        let error = ProxmoxClient::new(refused)
            .qemu_clear_protection(request(), "pve9-n1", 9000, "stale")
            .await
            .unwrap_err();
        assert!(
            matches!(error, PveApiError::Http { status: 500, .. }),
            "{error:?}"
        );
    }
}

#[tokio::test]
async fn the_config_parent_names_the_snapshot_a_rollback_restored() {
    // PVE's rollback sets `parent` to the restored snapshot (FM-717).
    let (reverted, _) = flags(json!({"data": {
        "name": "pool-member",
        "parent": "baseline",
        "digest": "3c1f0a5d9e7b2c4a6f8e0d1c3b5a79e8f6d4c2b0",
    }}))
    .await;
    assert_eq!(reverted.unwrap().parent.as_deref(), Some("baseline"));
    // An over-long parent is a payload error, never truncated into a match.
    let (long, _) = flags(json!({"data": {"parent": "b".repeat(41)}})).await;
    assert!(long.is_err());
}
