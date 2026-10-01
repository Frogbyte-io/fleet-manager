//! Contract tests for the bounded task-history read (FM-609) over PVE 8.x
//! and 9.x task-list shapes. One node is unreachable and one is offline;
//! both must become per-node warnings, never a failed read.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_core::SensitiveString;
use fleet_provider_proxmox::{
    MAX_TASKS_PER_NODE, ProxmoxClient, PveCredentials, PveHttpMethod, PveHttpRequest,
    PveHttpResponse, PveTaskOutcome, PveTaskQuery, PveTaskSource, PveTransport, PveTransportError,
    TaskStatus,
};

const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";

#[derive(Debug)]
struct FixtureTransport {
    family: &'static str,
    resources: Option<&'static str>,
    requests: Mutex<Vec<String>>,
}

impl FixtureTransport {
    fn new(family: &'static str) -> Arc<Self> {
        Arc::new(Self {
            family,
            resources: None,
            requests: Mutex::new(Vec::new()),
        })
    }

    fn with_resources(family: &'static str, resources: &'static str) -> Arc<Self> {
        Arc::new(Self {
            family,
            resources: Some(resources),
            requests: Mutex::new(Vec::new()),
        })
    }

    fn requests(&self) -> Vec<String> {
        let mut requests = self.requests.lock().unwrap().clone();
        requests.sort_unstable();
        requests
    }

    fn response(&self, path: &str) -> (u16, &'static str) {
        let (route, _query) = path.split_once('?').unwrap_or((path, ""));
        let healthy = self.family;
        let down = format!("{healthy}b");
        match route {
            "/api2/json/version" => match self.family {
                "pve8" => (200, include_str!("fixtures/pve8/version.json")),
                _ => (200, include_str!("fixtures/pve9/version.json")),
            },
            "/api2/json/cluster/resources" if self.resources.is_some() => {
                (200, self.resources.unwrap())
            }
            "/api2/json/cluster/resources" => match self.family {
                "pve8" => (
                    200,
                    include_str!("fixtures/pve8/tasks-cluster-resources.json"),
                ),
                _ => (
                    200,
                    include_str!("fixtures/pve9/tasks-cluster-resources.json"),
                ),
            },
            route if route == format!("/api2/json/nodes/{healthy}/tasks") => match self.family {
                "pve8" => (200, include_str!("fixtures/pve8/node-tasks.json")),
                _ => (200, include_str!("fixtures/pve9/node-tasks.json")),
            },
            // PVE proxies the node call; an unreachable node answers 595
            // from the proxying node.
            route if route == format!("/api2/json/nodes/{down}/tasks") => {
                (595, r#"{"data":null,"message":"No route to host"}"#)
            }
            other => panic!("unexpected PVE request path: {other}"),
        }
    }
}

#[async_trait]
impl PveTransport for FixtureTransport {
    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        assert_eq!(request.method, PveHttpMethod::Get, "the read never mutates");
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
        _request: PveHttpRequest,
        _body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        panic!("the task read never sends a body");
    }
}

fn request() -> PveHttpRequest {
    PveHttpRequest {
        host: "pve.test".to_owned(),
        port: 8006,
        path: "/api2/json/version".to_owned(),
        pinned_fingerprint: Some(FP.to_owned()),
        credentials: Arc::new(PveCredentials {
            token_id: "fleet@pve!fleet-ops".to_owned(),
            token: SensitiveString::new("fixture-secret"),
        }),
        method: PveHttpMethod::Get,
    }
}

fn query() -> PveTaskQuery {
    PveTaskQuery {
        limit_per_node: 50,
        ..PveTaskQuery::default()
    }
}

async fn assert_family(family: &'static str, version: &str, base: i64) {
    let transport = FixtureTransport::new(family);
    let client = ProxmoxClient::new(transport.clone());

    let history = client.task_history(request(), &query()).await.unwrap();

    assert_eq!(history.version, version);
    // The healthy node's five tasks land newest first.
    assert_eq!(history.tasks.len(), 5, "{:?}", history.tasks);
    let starts: Vec<i64> = history.tasks.iter().map(|task| task.started_at).collect();
    assert_eq!(
        starts,
        vec![base + 600, base + 300, base + 200, base + 100, base]
    );

    let running = &history.tasks[0];
    assert_eq!(running.upid.node, family);
    assert_eq!(running.upid.task_type, "qmstart");
    assert_eq!(running.upid.target, "101");
    // The user exactly as PVE reports it: split into user and token name.
    assert_eq!(running.user, "fleet@pve");
    assert_eq!(running.token_id.as_deref(), Some("fleet-ops"));
    assert_eq!(running.ended_at, None);
    assert_eq!(running.status, TaskStatus::Running);

    let shutdown = &history.tasks[1];
    assert_eq!(shutdown.status, TaskStatus::Ok);
    assert_eq!(shutdown.ended_at, Some(base + 342));

    // WARNINGS keeps its detail in the existing taxonomy's error variant.
    let backup = &history.tasks[2];
    assert_eq!(backup.upid.task_type, "vzdump");
    assert_eq!(backup.upid.target, "", "a node-level task carries no id");
    assert_eq!(
        backup.status,
        TaskStatus::Error {
            detail: "WARNINGS: 2".to_owned()
        }
    );
    assert_eq!(backup.user, "root@pam");
    assert_eq!(backup.token_id, None);

    let failed = &history.tasks[3];
    assert!(
        matches!(&failed.status, TaskStatus::Error { detail } if detail.contains("clone failed")),
        "{:?}",
        failed.status
    );

    // The unreachable node and the offline node are per-node warnings.
    assert_eq!(history.warnings.len(), 2, "{:?}", history.warnings);
    assert!(
        history
            .warnings
            .iter()
            .any(|warning| warning.starts_with(&format!("node {family}b tasks are unavailable"))),
        "{:?}",
        history.warnings
    );
    assert!(
        history
            .warnings
            .iter()
            .any(|warning| warning.starts_with(&format!("node {family}c is offline"))),
        "{:?}",
        history.warnings
    );
    for warning in &history.warnings {
        assert!(!warning.contains("fixture-secret"), "{warning}");
    }

    // The offline node is never called; both online nodes are, bounded.
    assert_eq!(
        transport.requests(),
        vec![
            "/api2/json/cluster/resources".to_owned(),
            format!("/api2/json/nodes/{family}/tasks?source=all&limit=50"),
            format!("/api2/json/nodes/{family}b/tasks?source=all&limit=50"),
            "/api2/json/version".to_owned(),
        ]
    );
}

#[tokio::test]
async fn pve8_task_history_reads_per_node_and_isolates_a_down_node() {
    assert_family("pve8", "8.4.1", 1_754_000_000).await;
}

#[tokio::test]
async fn pve9_task_history_reads_per_node_and_isolates_a_down_node() {
    assert_family("pve9", "9.2.2", 1_759_000_000).await;
}

#[tokio::test]
async fn node_vmid_and_source_filters_reach_the_node_request() {
    let transport = FixtureTransport::new("pve9");
    let client = ProxmoxClient::new(transport.clone());

    let history = client
        .task_history(
            request(),
            &PveTaskQuery {
                node: Some("pve9".to_owned()),
                vmid: Some(101),
                source: PveTaskSource::Active,
                outcome: None,
                limit_per_node: 10_000,
            },
        )
        .await
        .unwrap();

    // Only the named node is read, with the vmid filter pushed to PVE and
    // the limit clamped to the bound.
    assert!(history.warnings.is_empty(), "{:?}", history.warnings);
    assert_eq!(
        transport.requests(),
        vec![
            "/api2/json/cluster/resources".to_owned(),
            format!(
                "/api2/json/nodes/pve9/tasks?source=active&limit={MAX_TASKS_PER_NODE}&vmid=101"
            ),
            "/api2/json/version".to_owned(),
        ]
    );
}

#[tokio::test]
async fn an_unknown_node_filter_warns_instead_of_reading() {
    let transport = FixtureTransport::new("pve8");
    let client = ProxmoxClient::new(transport.clone());

    let history = client
        .task_history(
            request(),
            &PveTaskQuery {
                node: Some("elsewhere".to_owned()),
                ..query()
            },
        )
        .await
        .unwrap();

    assert!(history.tasks.is_empty());
    assert_eq!(history.warnings.len(), 1);
    assert!(history.warnings[0].contains("not a member of the cluster"));
}

#[tokio::test]
async fn a_full_node_page_warns_that_older_tasks_are_not_listed() {
    let transport = FixtureTransport::new("pve9");
    let client = ProxmoxClient::new(transport);

    let history = client
        .task_history(
            request(),
            &PveTaskQuery {
                node: Some("pve9".to_owned()),
                limit_per_node: 5,
                ..PveTaskQuery::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(history.tasks.len(), 5);
    assert_eq!(history.warnings.len(), 1, "{:?}", history.warnings);
    assert!(history.warnings[0].contains("the per-node bound"));
}

#[tokio::test]
async fn the_outcome_filter_reaches_the_node_request_as_statusfilter() {
    for (outcome, wire) in [
        (PveTaskOutcome::Ok, "ok"),
        (PveTaskOutcome::Error, "warning,error"),
        (PveTaskOutcome::Unknown, "unknown"),
    ] {
        let transport = FixtureTransport::new("pve9");
        let client = ProxmoxClient::new(transport.clone());
        client
            .task_history(
                request(),
                &PveTaskQuery {
                    node: Some("pve9".to_owned()),
                    outcome: Some(outcome),
                    limit_per_node: 50,
                    ..PveTaskQuery::default()
                },
            )
            .await
            .unwrap();
        assert!(
            transport.requests().contains(&format!(
                "/api2/json/nodes/pve9/tasks?source=all&limit=50&statusfilter={wire}"
            )),
            "{:?}",
            transport.requests()
        );
    }
}

#[tokio::test]
async fn a_malformed_cluster_resource_row_warns_instead_of_vanishing() {
    // The first row is a node that lost its type; the second is a node
    // with an over-long name; the third is an unknown type that is not a
    // node and stays silent.
    let long = "n".repeat(300);
    let resources: &'static str = Box::leak(
        format!(
            r#"{{"data": [{{"id": "node/pve9"}}, {{"id": "node/pve9x", "type": "node", "node": "{long}"}}, {{"id": "future/1", "type": "future-kind"}}, {{"id": "node/pve9", "type": "node", "node": "pve9", "status": "online"}}]}}"#
        )
        .into_boxed_str(),
    );
    let transport = FixtureTransport::with_resources("pve9", resources);
    let client = ProxmoxClient::new(transport);

    let history = client.task_history(request(), &query()).await.unwrap();

    assert_eq!(history.tasks.len(), 5, "the readable node is still read");
    let rows: Vec<&String> = history
        .warnings
        .iter()
        .filter(|warning| warning.starts_with("cluster resource"))
        .collect();
    assert_eq!(rows.len(), 2, "{:?}", history.warnings);
    assert!(rows[0].contains("node/pve9"), "{rows:?}");
    assert!(rows[1].contains("node/pve9x"), "{rows:?}");
    assert!(
        rows.iter().all(|warning| warning.len() < 400),
        "the warning is bounded: {rows:?}"
    );
    assert!(
        !history.warnings.iter().any(|w| w.contains("future")),
        "{:?}",
        history.warnings
    );
}
