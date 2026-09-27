use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_core::SensitiveString;
use fleet_provider_proxmox::{
    ProxmoxClient, ProxmoxSource, PveCredentials, PveHttpMethod, PveHttpRequest, PveHttpResponse,
    PveTransport, PveTransportError,
};

const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";

#[derive(Debug)]
struct FixtureTransport {
    family: &'static str,
    requests: Mutex<Vec<String>>,
}

impl FixtureTransport {
    fn new(family: &'static str) -> Self {
        Self {
            family,
            requests: Mutex::new(Vec::new()),
        }
    }

    fn response(&self, path: &str) -> (u16, &'static str) {
        match (self.family, path) {
            ("pve8", "/api2/json/version") => (200, include_str!("fixtures/pve8/version.json")),
            ("pve8", "/api2/json/cluster/resources") => {
                (200, include_str!("fixtures/pve8/cluster-resources.json"))
            }
            ("pve8", "/api2/json/nodes/pve8/status") => {
                (200, include_str!("fixtures/pve8/node-status.json"))
            }
            ("pve8", "/api2/json/nodes/pve8/storage") => {
                (200, include_str!("fixtures/pve8/node-storage.json"))
            }
            ("pve9", "/api2/json/version") => (200, include_str!("fixtures/pve9/version.json")),
            ("pve9", "/api2/json/cluster/resources") => {
                (200, include_str!("fixtures/pve9/cluster-resources.json"))
            }
            ("pve9", "/api2/json/nodes/pve9/status") => {
                (200, include_str!("fixtures/pve9/node-status.json"))
            }
            ("pve9", "/api2/json/nodes/pve9/storage") => {
                (200, include_str!("fixtures/pve9/node-storage.json"))
            }
            ("pve9", "/api2/json/nodes/pve9b/status") => {
                (503, r#"{"message":"node status unavailable"}"#)
            }
            ("pve9", "/api2/json/nodes/pve9b/storage") => (
                200,
                r#"{"data":[{"storage":"shared-pool","used":30,"total":100,"avail":70}]}"#,
            ),
            _ => panic!("unexpected PVE request path: {path}"),
        }
    }
}

#[async_trait]
impl PveTransport for FixtureTransport {
    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        assert_eq!(request.method, PveHttpMethod::Get);
        assert_eq!(request.pinned_fingerprint.as_deref(), Some(FP));
        self.requests.lock().unwrap().push(request.path.clone());
        let (status, body) = self.response(&request.path);
        Ok(PveHttpResponse {
            status,
            body: body.as_bytes().to_vec(),
        })
    }

    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        _body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        self.execute(request).await
    }
}

fn request() -> PveHttpRequest {
    PveHttpRequest {
        host: "pve.test".to_owned(),
        port: 8006,
        path: "/api2/json/cluster/resources".to_owned(),
        pinned_fingerprint: Some(FP.to_owned()),
        credentials: Arc::new(PveCredentials {
            token_id: "fleet@pve!readonly".to_owned(),
            token: SensitiveString::new("fixture-secret"),
        }),
        method: PveHttpMethod::Get,
    }
}

#[tokio::test]
async fn pve8_node_and_storage_capacity_are_normalized_in_bytes() {
    let transport = Arc::new(FixtureTransport::new("pve8"));
    let client = ProxmoxClient::new(transport.clone());

    let discovery = client.discover(request()).await.unwrap();

    assert_eq!(discovery.version, "8.4.1");
    assert!(discovery.warnings.is_empty(), "{:?}", discovery.warnings);
    assert_eq!(discovery.node_capacities.len(), 1);
    let node = &discovery.node_capacities[0];
    assert_eq!(node.node, "pve8");
    assert_eq!(node.cpu_usage_ratio, Some(0.375));
    assert_eq!(node.cpu_count, Some(12));
    assert_eq!(node.memory_used_bytes, Some(17_179_869_184));
    assert_eq!(node.memory_total_bytes, Some(34_359_738_368));
    assert_eq!(node.storages.len(), 2);
    assert_eq!(node.storages[0].storage, "local");
    assert_eq!(node.storages[0].used_bytes, 21_474_836_480);
    assert_eq!(node.storages[0].total_bytes, 107_374_182_400);
    let mut requests = transport.requests.lock().unwrap().clone();
    requests.sort_unstable();
    let mut expected = vec![
        "/api2/json/version",
        "/api2/json/cluster/resources",
        "/api2/json/nodes/pve8/status",
        "/api2/json/nodes/pve8/storage",
    ];
    expected.sort_unstable();
    assert_eq!(requests, expected);
}

#[tokio::test]
async fn pve9_capacity_isolated_to_nodes_and_storage_survives_status_failure() {
    let transport = Arc::new(FixtureTransport::new("pve9"));
    let client = ProxmoxClient::new(transport);

    let discovery = client.discover(request()).await.unwrap();

    assert_eq!(discovery.version, "9.2.2");
    assert_eq!(discovery.node_capacities.len(), 2);
    let pve9 = discovery
        .node_capacities
        .iter()
        .find(|node| node.node == "pve9")
        .unwrap();
    assert_eq!(pve9.cpu_usage_ratio, Some(0.125));
    assert_eq!(pve9.cpu_count, Some(16));
    assert_eq!(pve9.memory_used_bytes, Some(16_835_707_904));
    assert_eq!(pve9.memory_total_bytes, Some(67_342_831_616));
    assert_eq!(pve9.storages.len(), 2);

    let pve9b = discovery
        .node_capacities
        .iter()
        .find(|node| node.node == "pve9b")
        .unwrap();
    assert_eq!(pve9b.cpu_usage_ratio, None);
    assert_eq!(pve9b.memory_used_bytes, None);
    assert_eq!(pve9b.storages.len(), 1);
    assert!(
        discovery
            .warnings
            .iter()
            .any(|warning| { warning.contains("pve9b") && warning.contains("status") })
    );
}
