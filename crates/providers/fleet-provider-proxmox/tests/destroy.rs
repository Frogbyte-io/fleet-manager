//! QEMU destroy contract: the 8.x/9.x DELETE returns a qmdestroy UPID.
use async_trait::async_trait;
use fleet_core::SensitiveString;
use fleet_provider_proxmox::*;
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct Transport {
    config: (u16, serde_json::Value),
    deletion: (u16, serde_json::Value),
    seen: Mutex<Vec<PveHttpRequest>>,
}
#[async_trait]
impl PveTransport for Transport {
    async fn execute_with_body(
        &self,
        _: PveHttpRequest,
        _: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        panic!("destroy sends no body")
    }

    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        let answer = if request.path.contains("/tasks/") {
            assert_eq!(request.method, PveHttpMethod::Get);
            &self.deletion
        } else if request.path.ends_with("/config") {
            assert_eq!(request.method, PveHttpMethod::Get);
            &self.config
        } else {
            assert_eq!(request.method, PveHttpMethod::Delete);
            assert_eq!(request.path, "/api2/json/nodes/pve/qemu/101?purge=1");
            &self.deletion
        };
        self.seen.lock().unwrap().push(request);
        Ok(PveHttpResponse {
            status: answer.0,
            body: answer.1.to_string().into_bytes(),
        })
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
        method: PveHttpMethod::Get,
    }
}
const UPID: &str = "UPID:pve:0015523F:0C6DF532:6AAFE1EC:qmdestroy:101:fleet@pve!test:";
fn transport(
    config: (u16, serde_json::Value),
    deletion: (u16, serde_json::Value),
) -> Arc<Transport> {
    Arc::new(Transport {
        config,
        deletion,
        seen: Mutex::new(vec![]),
    })
}
#[tokio::test]
async fn destroy_returns_target_task_and_preserves_tls_pin() {
    let transport = transport(
        (200, json!({"data":{"template":0}})),
        (200, json!({"data":UPID})),
    );
    let task = ProxmoxClient::new(transport.clone())
        .guest_destroy(request(), "pve", 101, true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(task.task_type, "qmdestroy");
    assert_eq!(transport.seen.lock().unwrap().len(), 2);
    assert!(
        transport
            .seen
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.pinned_fingerprint.as_deref() == Some("fixture-pin"))
    );
}
#[tokio::test]
async fn missing_config_and_delete_race_are_idempotent() {
    let missing = json!({"data":null,"message":"Configuration file 'nodes/pve/qemu-server/101.conf' does not exist\n"});
    for at_delete in [false, true] {
        let config = if at_delete {
            (200, json!({"data":{}}))
        } else {
            (500, missing.clone())
        };
        let transport = transport(config, (500, missing.clone()));
        assert!(
            ProxmoxClient::new(transport.clone())
                .guest_destroy(request(), "pve", 101, true)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            transport.seen.lock().unwrap().len(),
            if at_delete { 2 } else { 1 }
        );
    }
}
#[tokio::test]
async fn templates_are_refused_without_a_delete() {
    for flag in [json!(1), json!("1")] {
        let transport = transport(
            (200, json!({"data":{"template":flag}})),
            (200, json!({"data":UPID})),
        );
        assert!(
            ProxmoxClient::new(transport.clone())
                .guest_destroy(request(), "pve", 101, true)
                .await
                .is_err()
        );
        assert_eq!(transport.seen.lock().unwrap().len(), 1);
    }
}
#[tokio::test]
async fn forbidden_other_missing_paths_and_invalid_tasks_remain_errors() {
    for deletion in [
        (
            403,
            json!({"message":"Permission check failed (/vms/101, VM.Allocate)"}),
        ),
        (404, json!({"message":"no such endpoint"})),
        (
            500,
            json!({"message":"Configuration file 'nodes/pve/qemu-server/999.conf' does not exist"}),
        ),
        (200, json!({"data":null})),
        (200, json!({"data":UPID.replace("qmdestroy", "qmstop")})),
    ] {
        let transport = transport((200, json!({"data":{}})), deletion);
        assert!(
            ProxmoxClient::new(transport)
                .guest_destroy(request(), "pve", 101, true)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn unreadable_config_is_never_absence_or_permission_to_delete() {
    for config in [
        (
            403,
            json!({"message":"Permission check failed (/vms/101, VM.Audit)"}),
        ),
        (200, json!({"data":null})),
        (200, json!({"data":{"template":"invalid"}})),
    ] {
        let transport = transport(config, (200, json!({"data":UPID})));
        assert!(
            ProxmoxClient::new(transport.clone())
                .guest_destroy(request(), "pve", 101, true)
                .await
                .is_err()
        );
        assert_eq!(transport.seen.lock().unwrap().len(), 1);
    }
}
#[tokio::test]
async fn destroy_task_error_is_not_success() {
    let transport = transport(
        (200, json!({"data":{}})),
        (
            200,
            json!({"data":{"status":"stopped","exitstatus":"ERROR: disk locked"}}),
        ),
    );
    let status = ProxmoxClient::new(transport)
        .task_status(request(), &Upid::parse(UPID).unwrap())
        .await
        .unwrap();
    assert!(matches!(status, TaskStatus::Error { .. }));
}
