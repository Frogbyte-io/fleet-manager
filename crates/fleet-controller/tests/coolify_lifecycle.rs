//! FM-1033: Coolify lifecycle actions and the deployment log tail end to end
//! over a real controller router, a real secret store and SQLite, the action
//! broker, the lifecycle executor, and a stateful local stub that speaks the
//! routes of Coolify v4.4.6 (`routes/api.php`: the lifecycle routes are
//! `POST`, a `GET` answers 405). The bodies are synthetic, written from the
//! controllers' documented response shapes; no live token was used.
//!
//! The token must never appear in an API answer, the audit ledger, or an
//! operation's payload or result.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use fleet_application::coolify::lifecycle::{CoolifyLifecycle, Settle};
use fleet_application::operation::Operations;
use fleet_controller::coolify_exec::CoolifyLifecycleExecutor;
use fleet_controller::{Settings, build_router, compose_node_services};
use fleet_secrets::SecretStore;
use fleet_storage_sqlite::{OperationRepository, Store};
use serde_json::{Value, json};
use sqlx::Row as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const TOKEN: &str = "coolify-lifecycle-deploy-token-0001";
const APP: &str = "appweb000000000001";
const SVC: &str = "svcplausible000000001";
const DB: &str = "dbpostgres00000000001";
const DEPLOYMENT: &str = "dep0000000000000001";

#[derive(Default)]
struct Coolify {
    version: String,
    statuses: HashMap<String, String>,
    /// Whether the token may read sensitive values (deployment logs).
    sensitive: bool,
    /// Every request as `METHOD target`.
    log: Vec<String>,
}

type Shared = Arc<Mutex<Coolify>>;

fn logs_value() -> String {
    // Coolify carries the entries as a JSON-encoded string.
    let entries = json!([
        {"command": null, "output": "Starting deployment of web", "type": "stdout", "hidden": false, "order": 1},
        {"command": null, "output": "internal bookkeeping", "type": "stdout", "hidden": true, "order": 2},
        {"command": null, "output": "curl -H 'Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789' https://api.example.test", "type": "stdout", "hidden": false, "order": 3},
        {"command": null, "output": "\u{1b}[32mDeployment finished\u{1b}[0m", "type": "stdout", "hidden": false, "order": 4},
    ]);
    entries.to_string()
}

fn respond(state: &mut Coolify, method: &str, target: &str) -> (u16, String) {
    state.log.push(format!("{method} {target}"));
    let path = target.split('?').next().unwrap_or_default();
    let path = path.strip_prefix("/api/v1").unwrap_or(path);
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    let status_of = |state: &Coolify, uuid: &str| state.statuses.get(uuid).cloned();
    match (method, segments.as_slice()) {
        ("GET", ["version"]) => (200, state.version.clone()),
        ("GET", ["servers" | "projects" | "deployments"]) => (200, "[]".to_owned()),
        ("GET", ["applications"]) => (
            200,
            json!([{"uuid": APP, "name": "web", "status": state.statuses[APP], "environment_id": 1,
                    "fqdn": "https://shop.example.test", "build_pack": "nixpacks"}])
            .to_string(),
        ),
        ("GET", ["services"]) => (
            200,
            json!([{"uuid": SVC, "name": "plausible", "status": state.statuses[SVC], "environment_id": 1}])
                .to_string(),
        ),
        ("GET", ["services", _, "applications"]) => (200, "[]".to_owned()),
        ("GET", ["databases"]) => (
            200,
            json!([{"uuid": DB, "name": "shop-db", "status": state.statuses[DB], "environment_id": 1,
                    "image": "postgres:16-alpine"}])
            .to_string(),
        ),
        ("GET", ["applications" | "services" | "databases", uuid]) => {
            match status_of(state, uuid) {
                Some(status) => (200, json!({"uuid": uuid, "status": status}).to_string()),
                None => (404, json!({"message": "Resource not found."}).to_string()),
            }
        }
        ("GET", ["applications" | "services" | "databases", _, "start" | "stop" | "restart"])
        | ("GET", ["deploy"]) => (
            405,
            json!({"message": "This endpoint has changed to a POST request."}).to_string(),
        ),
        ("POST", [family @ ("applications" | "services" | "databases"), uuid, verb]) => {
            let _ = family;
            if !state.statuses.contains_key(*uuid) {
                return (404, json!({"message": "Resource not found."}).to_string());
            }
            let next = match *verb {
                "stop" => "exited",
                "start" | "restart" => "running:healthy",
                _ => return (404, json!({"message": "Not found."}).to_string()),
            };
            state.statuses.insert((*uuid).to_owned(), next.to_owned());
            (
                200,
                json!({"message": "Request queued.", "deployment_uuid": DEPLOYMENT}).to_string(),
            )
        }
        ("POST", ["deploy"]) => {
            let uuid = target
                .split("uuid=")
                .nth(1)
                .and_then(|rest| rest.split('&').next())
                .unwrap_or_default();
            if !state.statuses.contains_key(uuid) {
                return (404, json!({"message": "No resources found."}).to_string());
            }
            (
                200,
                json!({"deployments": [{"message": "Application web deployment queued.",
                    "resource_uuid": uuid, "deployment_uuid": DEPLOYMENT}]})
                .to_string(),
            )
        }
        ("GET", ["deployments", "applications", _]) => (
            200,
            json!({"count": 1, "deployments": [{"deployment_uuid": DEPLOYMENT, "status": "finished"}]})
                .to_string(),
        ),
        ("GET", ["deployments", uuid]) if *uuid == DEPLOYMENT => {
            let mut body = json!({"deployment_uuid": DEPLOYMENT, "status": "finished"});
            if state.sensitive {
                body["logs"] = json!(logs_value());
            }
            (200, body.to_string())
        }
        _ => (404, json!({"message": "Not found."}).to_string()),
    }
}

async fn stub_coolify(state: Shared) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let state = state.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0_u8; 8192];
                let read = socket.read(&mut buffer).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buffer[..read]).to_string();
                let mut words = head.split_whitespace();
                let method = words.next().unwrap_or_default().to_owned();
                let target = words.next().unwrap_or_default().to_owned();
                let (status, body) = if head.contains(&format!("Bearer {TOKEN}")) {
                    respond(&mut state.lock().unwrap(), &method, &target)
                } else {
                    (401, json!({"message": "Unauthenticated."}).to_string())
                };
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    base
}

async fn raw(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: test\r\n");
    if let Some(body) = &body {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.to_string().len()
        ));
    }
    head.push_str("Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    if let Some(body) = &body {
        stream.write_all(body.to_string().as_bytes()).await.unwrap();
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    let (head, rest) = text.split_once("\r\n\r\n").expect("an HTTP response");
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap();
    assert!(!text.contains(TOKEN), "the token reached an answer");
    (status, serde_json::from_str(rest).unwrap_or(Value::Null))
}

struct Rig {
    address: std::net::SocketAddr,
    store: Store,
    operations: Arc<Operations>,
    executor: CoolifyLifecycleExecutor,
    coolify: Shared,
    account: String,
    _dirs: Vec<tempfile::TempDir>,
}

impl Rig {
    async fn new() -> Self {
        let coolify: Shared = Arc::new(Mutex::new(Coolify {
            version: "4.4.6".to_owned(),
            statuses: HashMap::from([
                (APP.to_owned(), "running:healthy".to_owned()),
                (SVC.to_owned(), "running:healthy".to_owned()),
                (DB.to_owned(), "running:healthy".to_owned()),
            ]),
            sensitive: true,
            log: Vec::new(),
        }));
        let base = stub_coolify(coolify.clone()).await;
        let dist = tempfile::tempdir().unwrap();
        std::fs::write(dist.path().join("index.html"), "<html>fleet</html>").unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(&store_dir.path().join("fleet.db"))
            .await
            .unwrap();
        let key_dir = tempfile::tempdir().unwrap();
        let key_path = key_dir.path().join("master.key");
        std::fs::write(
            &key_path,
            "1 0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let secrets = Arc::new(SecretStore::open(store.pool().clone(), &key_path).unwrap());
        let crypto = fleet_controller::node_crypto::NodeCryptoService::open(&secrets)
            .await
            .unwrap();
        let mut services = compose_node_services(store.pool(), Arc::new(crypto));
        services.external_accounts = Some(
            fleet_controller::external_accounts_store::compose_external_accounts(
                store.pool(),
                secrets.clone(),
            ),
        );
        services.coolify_discovery = Some(
            fleet_controller::external_accounts_store::compose_coolify_discovery(
                store.pool(),
                secrets.clone(),
            ),
        );
        services.coolify_lifecycle =
            Some(fleet_controller::coolify_exec::compose_coolify_lifecycle(
                store.pool(),
                secrets.clone(),
            ));
        // The executor under test waits no time between the re-reads.
        let lifecycle = Arc::new(
            CoolifyLifecycle::new(
                Arc::new(fleet_storage_sqlite::ExternalAccountRepository::new(
                    store.pool().clone(),
                )),
                Arc::new(
                    fleet_controller::external_accounts_store::SecretBackedExternalCredentials::new(
                        secrets.clone(),
                    ),
                ),
                Arc::new(fleet_provider_coolify::CoolifyHttpLifecycle),
                Arc::new(fleet_storage_sqlite::CoolifyObservationRepository::new(
                    store.pool().clone(),
                )),
                Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
            )
            .with_settle(Settle {
                attempts: 3,
                interval: std::time::Duration::ZERO,
            }),
        );
        let settings = Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            web_dist: dist.path().to_path_buf(),
            artifacts_dir: None,
            tailscale_serve_listen: None,
        };
        let router = build_router(
            &settings,
            Some(store.pool().clone()),
            Some(&services),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(store.pool().clone())),
            Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
        ));
        let (status, body) = raw(
            address,
            "POST",
            "/api/v1/external-accounts",
            Some(json!({"kind": "coolify", "label": "prod", "baseUrl": base, "token": TOKEN})),
        )
        .await;
        assert_eq!(status, 201, "{body}");
        let account = body["data"]["id"].as_str().unwrap().to_owned();
        let rig = Self {
            address,
            store,
            operations,
            executor: CoolifyLifecycleExecutor::new(lifecycle),
            coolify,
            account,
            _dirs: vec![dist, store_dir, key_dir],
        };
        rig.discover().await;
        rig
    }

    async fn discover(&self) {
        let (status, body) = raw(
            self.address,
            "POST",
            &format!(
                "/api/v1/external-accounts/{}/coolify/discover",
                self.account
            ),
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
    }

    fn id(&self, uuid: &str) -> String {
        format!("coolify:{}:{uuid}", self.account)
    }

    async fn act(&self, uuid: &str, verb: &str) -> (u16, Value) {
        raw(
            self.address,
            "POST",
            &format!("/api/v1/services/{}/actions/{verb}", self.id(uuid)),
            Some(json!({"reason": "test"})),
        )
        .await
    }

    /// Runs the operation of a request and returns the request and the
    /// operation as the API serves them.
    async fn run(&self, request_id: &str) -> (Value, Value) {
        let (_, request) = raw(
            self.address,
            "GET",
            &format!("/api/v1/requests/{request_id}"),
            None,
        )
        .await;
        let operation_id = request["data"]["operationId"].as_str().unwrap().to_owned();
        self.operations
            .claim_only_execute(&self.executor, &operation_id, "test-worker")
            .await
            .ok();
        let (_, request) = raw(
            self.address,
            "GET",
            &format!("/api/v1/requests/{request_id}"),
            None,
        )
        .await;
        let (_, operation) = raw(
            self.address,
            "GET",
            &format!("/api/v1/operations/{operation_id}"),
            None,
        )
        .await;
        (request["data"].clone(), operation["data"].clone())
    }

    fn requests_to(&self, needle: &str) -> Vec<String> {
        self.coolify
            .lock()
            .unwrap()
            .log
            .iter()
            .filter(|line| line.contains(needle))
            .cloned()
            .collect()
    }

    async fn stored_text(&self) -> String {
        let mut out = String::new();
        for query in [
            "SELECT actor || action || COALESCE(resource,'') || COALESCE(metadata_json,'') AS t FROM audit_events",
            "SELECT kind || COALESCE(payload_json,'') || COALESCE(result_json,'') || COALESCE(error_json,'') AS t FROM operations",
            "SELECT action_id || target || parameters_json || COALESCE(failure,'') AS t FROM action_requests",
        ] {
            for row in sqlx::query(query)
                .fetch_all(self.store.pool())
                .await
                .unwrap()
            {
                out.push_str(&row.get::<String, _>("t"));
            }
        }
        out
    }
}

fn result_of(operation: &Value) -> Value {
    serde_json::from_str(operation["resultJson"].as_str().unwrap_or("null")).unwrap()
}

#[tokio::test]
async fn restart_runs_at_once_over_post_and_records_the_observed_status() {
    let rig = Rig::new().await;
    let (status, filed) = rig.act(APP, "restart").await;
    assert_eq!(status, 201, "{filed}");
    let request = &filed["data"];
    assert_eq!(request["actionId"], "coolify.application.restart");
    assert_eq!(request["riskClass"], "auto");
    assert_eq!(request["state"], "executing");
    assert_eq!(request["target"], rig.id(APP));
    assert_eq!(request["parameters"]["uuid"], APP);
    assert_eq!(request["parameters"]["accountId"], rig.account);

    let (request, operation) = rig.run(request["id"].as_str().unwrap()).await;
    assert_eq!(request["state"], "succeeded", "{request} {operation}");
    let result = result_of(&operation);
    assert_eq!(result["outcome"], "restarted");
    assert_eq!(result["previousStatus"], "running:healthy");
    assert_eq!(result["observedStatus"], "running:healthy");
    assert_eq!(result["settled"], true);

    // The call was a POST; no GET ever reached a lifecycle path.
    assert_eq!(
        rig.requests_to(&format!("POST /api/v1/applications/{APP}/restart")),
        vec![format!("POST /api/v1/applications/{APP}/restart")]
    );
    assert!(
        rig.requests_to("/restart")
            .iter()
            .all(|line| line.starts_with("POST"))
    );
    assert!(!rig.stored_text().await.contains(TOKEN));
}

#[tokio::test]
async fn stop_waits_for_approval_and_a_second_stop_changes_nothing() {
    let rig = Rig::new().await;
    let (status, filed) = rig.act(SVC, "stop").await;
    assert_eq!(status, 201, "{filed}");
    assert_eq!(filed["data"]["actionId"], "coolify.service.stop");
    assert_eq!(filed["data"]["riskClass"], "approve");
    assert_eq!(filed["data"]["state"], "pending");
    assert!(
        rig.requests_to("POST").is_empty(),
        "nothing before approval"
    );
    let id = filed["data"]["id"].as_str().unwrap().to_owned();

    let (status, approved) = raw(
        rig.address,
        "POST",
        &format!("/api/v1/requests/{id}/approve"),
        None,
    )
    .await;
    assert_eq!(status, 200, "{approved}");
    let (request, operation) = rig.run(&id).await;
    assert_eq!(request["state"], "succeeded", "{request} {operation}");
    let result = result_of(&operation);
    assert_eq!(result["outcome"], "stopped");
    assert_eq!(result["observedStatus"], "exited");
    assert_eq!(result["settled"], true);
    assert_eq!(rig.requests_to("POST").len(), 1);

    // Stopping what is already stopped sends nothing.
    let (_, again) = rig.act(SVC, "stop").await;
    let id = again["data"]["id"].as_str().unwrap().to_owned();
    raw(
        rig.address,
        "POST",
        &format!("/api/v1/requests/{id}/approve"),
        None,
    )
    .await;
    let (request, operation) = rig.run(&id).await;
    assert_eq!(request["state"], "succeeded");
    assert_eq!(result_of(&operation)["outcome"], "unchanged");
    assert_eq!(rig.requests_to("POST").len(), 1);
}

#[tokio::test]
async fn start_and_redeploy_follow_their_routes_and_report_the_deployment() {
    let rig = Rig::new().await;
    // A stopped database starts.
    rig.coolify
        .lock()
        .unwrap()
        .statuses
        .insert(DB.to_owned(), "exited".to_owned());
    let (_, filed) = rig.act(DB, "start").await;
    assert_eq!(filed["data"]["actionId"], "coolify.database.start");
    assert_eq!(filed["data"]["riskClass"], "auto");
    let (request, operation) = rig.run(filed["data"]["id"].as_str().unwrap()).await;
    assert_eq!(request["state"], "succeeded", "{request} {operation}");
    assert_eq!(result_of(&operation)["outcome"], "started");
    assert_eq!(
        rig.requests_to(&format!("POST /api/v1/databases/{DB}/start"))
            .len(),
        1
    );

    // An application redeploy goes through /deploy and names the deployment.
    let (status, filed) = rig.act(APP, "redeploy").await;
    assert_eq!(status, 201, "{filed}");
    assert_eq!(filed["data"]["riskClass"], "auto");
    let (request, operation) = rig.run(filed["data"]["id"].as_str().unwrap()).await;
    assert_eq!(request["state"], "succeeded", "{request} {operation}");
    let result = result_of(&operation);
    assert_eq!(result["outcome"], "redeploy_queued");
    assert_eq!(result["deploymentUuid"], DEPLOYMENT);
    assert_eq!(
        rig.requests_to("POST /api/v1/deploy"),
        vec![format!("POST /api/v1/deploy?uuid={APP}&force=false")]
    );

    // A service cannot be redeployed; an unknown resource and verb are refused.
    let (status, body) = rig.act(SVC, "redeploy").await;
    assert_eq!(status, 400, "{body}");
    let (status, body) = rig.act("nosuchresource0001", "restart").await;
    assert_eq!(status, 404, "{body}");
    let (status, body) = rig.act(APP, "obliterate").await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn an_old_coolify_is_refused_before_any_mutation() {
    let rig = Rig::new().await;
    let (_, filed) = rig.act(APP, "restart").await;
    rig.coolify.lock().unwrap().version = "4.0.0-beta.420".to_owned();
    let (request, operation) = rig.run(filed["data"]["id"].as_str().unwrap()).await;
    assert_eq!(request["state"], "failed", "{request} {operation}");
    let failure = operation.to_string();
    assert!(
        failure.contains("not supported") && failure.contains("4.2.0"),
        "{failure}"
    );
    assert!(rig.requests_to("POST").is_empty());
}

#[tokio::test]
async fn the_log_tail_is_bounded_redacted_and_needs_a_sensitive_token() {
    let rig = Rig::new().await;
    let (status, body) = raw(
        rig.address,
        "GET",
        &format!("/api/v1/services/{}/logs?lines=50", rig.id(APP)),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let data = &body["data"];
    assert_eq!(data["deploymentUuid"], DEPLOYMENT);
    assert_eq!(data["deploymentStatus"], "finished");
    let text = data["lines"].to_string();
    assert!(text.contains("Starting deployment of web"), "{text}");
    assert!(text.contains("Deployment finished"), "{text}");
    assert!(
        !text.contains("internal bookkeeping"),
        "hidden entries are dropped"
    );
    assert!(
        !text.contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
        "{text}"
    );
    assert!(!text.contains('\u{1b}'), "{text}");
    assert_eq!(data["redacted"], true);

    // One line only.
    let (_, body) = raw(
        rig.address,
        "GET",
        &format!("/api/v1/services/{}/logs?lines=1", rig.id(APP)),
        None,
    )
    .await;
    assert_eq!(body["data"]["lines"].as_array().unwrap().len(), 1);
    assert_eq!(body["data"]["truncated"], true);
    let (status, _) = raw(
        rig.address,
        "GET",
        &format!("/api/v1/services/{}/logs?lines=0", rig.id(APP)),
        None,
    )
    .await;
    assert_eq!(status, 400);
    // Only applications have deployment logs.
    let (status, _) = raw(
        rig.address,
        "GET",
        &format!("/api/v1/services/{}/logs", rig.id(SVC)),
        None,
    )
    .await;
    assert_eq!(status, 400);

    // A token that cannot read sensitive values gets no logs, and the
    // refusal says why.
    rig.coolify.lock().unwrap().sensitive = false;
    let (status, body) = raw(
        rig.address,
        "GET",
        &format!("/api/v1/services/{}/logs", rig.id(APP)),
        None,
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body.to_string().contains("read:sensitive"), "{body}");
    assert!(
        !rig.stored_text()
            .await
            .contains("ghp_abcdefghijklmnopqrstuvwxyz")
    );
}

#[tokio::test]
async fn discovery_still_sends_only_gets() {
    let rig = Rig::new().await;
    rig.discover().await;
    assert!(
        rig.coolify
            .lock()
            .unwrap()
            .log
            .iter()
            .all(|line| line.starts_with("GET")),
        "discovery sent a non-GET request"
    );
}
