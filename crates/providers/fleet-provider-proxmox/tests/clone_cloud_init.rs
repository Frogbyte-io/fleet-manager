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
