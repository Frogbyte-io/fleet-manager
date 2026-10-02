//! Contract tests for the `/cluster/nextid` read the Lab executor reserves
//! clone targets from (issue #220). PVE declares the answer an integer;
//! both the number and the string encoding are accepted, and nothing that
//! is not a valid VMID is.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_core::SensitiveString;
use fleet_provider_proxmox::{
    ProxmoxClient, PveApiError, PveCredentials, PveHttpMethod, PveHttpRequest, PveHttpResponse,
    PveTransport, PveTransportError,
};

const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";

#[derive(Debug)]
struct OneAnswer {
    status: u16,
    body: &'static str,
    seen: Mutex<Vec<(String, PveHttpMethod)>>,
}

#[async_trait]
impl PveTransport for OneAnswer {
    async fn execute_with_body(
        &self,
        _request: PveHttpRequest,
        _body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        panic!("nextid is a GET without a body")
    }

    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        self.seen
            .lock()
            .unwrap()
            .push((request.path.clone(), request.method));
        Ok(PveHttpResponse {
            status: self.status,
            body: self.body.as_bytes().to_vec(),
        })
    }
}

fn request() -> PveHttpRequest {
    PveHttpRequest {
        host: "pve-api.example.test".to_owned(),
        port: 8006,
        path: String::new(),
        pinned_fingerprint: Some(FP.to_owned()),
        credentials: Arc::new(PveCredentials {
            token_id: "fleet@pve!lab".to_owned(),
            token: SensitiveString::new("the-token-secret-material".to_owned()),
        }),
        method: PveHttpMethod::Post,
    }
}

async fn next_vmid(status: u16, body: &'static str) -> (Result<u32, PveApiError>, Arc<OneAnswer>) {
    let transport = Arc::new(OneAnswer {
        status,
        body,
        seen: Mutex::new(Vec::new()),
    });
    let client = ProxmoxClient::new(transport.clone());
    (client.next_vmid(request()).await, transport)
}

#[tokio::test]
async fn the_next_vmid_is_read_as_a_get_in_either_encoding() {
    let (vmid, transport) = next_vmid(200, r#"{"data":"9000"}"#).await;
    assert_eq!(vmid.unwrap(), 9000);
    assert_eq!(
        transport.seen.lock().unwrap().as_slice(),
        &[("/api2/json/cluster/nextid".to_owned(), PveHttpMethod::Get)]
    );
    let (vmid, _) = next_vmid(200, r#"{"data":9001}"#).await;
    assert_eq!(vmid.unwrap(), 9001);
}

#[tokio::test]
async fn an_answer_that_is_not_a_vmid_is_refused() {
    for body in [
        r#"{"data":null}"#,
        r#"{"data":"ninety"}"#,
        r#"{"data":99}"#,
        r#"{"data":-1}"#,
        r#"{"data":4294967296}"#,
        r#"{"data":{"vmid":9000}}"#,
    ] {
        let (vmid, _) = next_vmid(200, body).await;
        assert!(
            matches!(vmid, Err(PveApiError::InvalidPayload { .. })),
            "{body}: {vmid:?}"
        );
    }
    // An exhausted `next-id` range is PVE's 500, surfaced as-is.
    let (vmid, _) = next_vmid(
        500,
        r#"{"data":null,"message":"unable to get any free VMID in range [9000, 9010]\n"}"#,
    )
    .await;
    assert!(
        matches!(vmid, Err(PveApiError::Http { status: 500, .. })),
        "{vmid:?}"
    );
}
