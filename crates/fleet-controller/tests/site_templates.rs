//! FM-1035: deploy a site from a template, end to end over a real controller
//! router, a real secret store and SQLite, the action broker, the site
//! executor, and a stateful local stub that speaks the routes of Coolify
//! v4.4.6 (`routes/api.php`, `ServicesController::create_service`,
//! `ApplicationsController::create_application`). The bodies are synthetic,
//! written from the controllers' documented shapes; no live token was used.
//!
//! Covered: both template kinds through the broker (file, approve, run), the
//! partial-failure result and a retry that reuses the created resource, the
//! filing refusals, idempotent filing, and that the token appears in no
//! stored state or answer.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::coolify::lifecycle::{CoolifyLifecycle, Settle};
use fleet_application::operation::Operations;
use fleet_application::site_templates::{DeployProgress, SITE_KIND, SiteTemplates};
use fleet_controller::site_exec::SiteExecutor;
use fleet_controller::{Settings, build_router, compose_node_services};
use fleet_secrets::SecretStore;
use fleet_storage_sqlite::{OperationRepository, Store};
use serde_json::{Value, json};
use sqlx::Row as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const TOKEN: &str = "coolify-site-write-token-0001";
const SERVER: &str = "srvmain00000000001";
const PROJECT: &str = "projsites0000000001";
const TAKEN: &str = "https://taken.example.test";

#[derive(Clone, Default)]
struct Resource {
    description: String,
    body: Value,
    started: bool,
    envs: Vec<String>,
    deployment: Option<String>,
}

#[derive(Default)]
struct Coolify {
    applications: BTreeMap<String, Resource>,
    services: BTreeMap<String, Resource>,
    /// Answer `POST /deploy` with HTTP 500.
    fail_deploy: bool,
    /// Answer a creation with HTTP 422.
    fail_create: bool,
    /// Answer a deployment read with this status.
    deployment_status: Option<String>,
    log: Vec<String>,
    next: u32,
}

type Shared = Arc<Mutex<Coolify>>;

fn respond(state: &mut Coolify, method: &str, target: &str, body: &str) -> (u16, String) {
    state.log.push(format!("{method} {target}"));
    let path = target.split('?').next().unwrap_or_default();
    let path = path.strip_prefix("/api/v1").unwrap_or(path);
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    let sent: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    match (method, segments.as_slice()) {
        ("GET", ["version"]) => (200, "4.4.6".to_owned()),
        ("GET", ["servers"]) => (
            200,
            json!([{"uuid": SERVER, "name": "edge-1", "ip": "192.0.2.10"}]).to_string(),
        ),
        ("GET", ["projects"]) => {
            (200, json!([{"uuid": PROJECT, "name": "sites"}]).to_string())
        }
        ("GET", ["projects", _, "environments"]) => (
            200,
            json!([{"id": 1, "name": "production"}]).to_string(),
        ),
        ("GET", ["applications"]) => {
            let mut items: Vec<Value> = state
                .applications
                .iter()
                .map(|(uuid, app)| {
                    json!({"uuid": uuid, "name": app.body["name"], "description": app.description,
                           "status": "exited", "fqdn": app.body["domains"], "environment_id": 1})
                })
                .collect();
            items.push(json!({"uuid": "apptaken000000001", "name": "taken", "status": "running:healthy",
                              "environment_id": 1, "fqdn": TAKEN}));
            (200, Value::Array(items).to_string())
        }
        ("GET", ["services"]) => {
            let items: Vec<Value> = state
                .services
                .iter()
                .map(|(uuid, svc)| {
                    json!({"uuid": uuid, "name": svc.body["name"], "description": svc.description,
                           "status": if svc.started { "running:healthy" } else { "exited" },
                           "environment_id": 1})
                })
                .collect();
            (200, Value::Array(items).to_string())
        }
        ("GET", ["services", _, "applications"]) => (200, "[]".to_owned()),
        ("GET" | "POST", ["servers" | "projects" | "databases" | "deployments"]) => {
            (200, "[]".to_owned())
        }
        ("POST", ["services"] | ["applications", "public"]) if state.fail_create => (
            422,
            json!({"message": "Validation failed.", "errors": {"domains": ["The domain is invalid."]}})
                .to_string(),
        ),
        ("POST", ["services"]) => {
            assert_eq!(sent["instant_deploy"], json!(false), "{body}");
            state.next += 1;
            let uuid = format!("svcnew{:013}", state.next);
            state.services.insert(
                uuid.clone(),
                Resource {
                    description: sent["description"].as_str().unwrap_or_default().to_owned(),
                    body: sent.clone(),
                    ..Resource::default()
                },
            );
            (
                201,
                json!({"uuid": uuid, "domains": [sent["urls"][0]["url"]]}).to_string(),
            )
        }
        ("POST", ["applications", "public"]) => {
            assert_eq!(sent["instant_deploy"], json!(false), "{body}");
            state.next += 1;
            let uuid = format!("appnew{:013}", state.next);
            state.applications.insert(
                uuid.clone(),
                Resource {
                    description: sent["description"].as_str().unwrap_or_default().to_owned(),
                    body: sent.clone(),
                    ..Resource::default()
                },
            );
            (201, json!({"uuid": uuid, "domains": sent["domains"]}).to_string())
        }
        ("GET", ["applications", uuid, "envs"]) => {
            let items: Vec<Value> = state
                .applications
                .get(*uuid)
                .map(|app| {
                    app.envs
                        .iter()
                        .map(|key| json!({"uuid": format!("env-{key}"), "key": key, "is_preview": false}))
                        .collect()
                })
                .unwrap_or_default();
            (200, Value::Array(items).to_string())
        }
        ("POST", ["applications", uuid, "envs"]) => {
            let key = sent["key"].as_str().unwrap_or_default().to_owned();
            match state.applications.get_mut(*uuid) {
                Some(app) => {
                    app.envs.push(key);
                    (201, json!({"uuid": "env-new"}).to_string())
                }
                None => (404, json!({"message": "Application not found."}).to_string()),
            }
        }
        ("GET", ["deployments", "applications", uuid]) => {
            let items: Vec<Value> = state
                .applications
                .get(*uuid)
                .and_then(|app| app.deployment.clone())
                .map(|id| vec![json!({"deployment_uuid": id})])
                .unwrap_or_default();
            (200, json!({"count": items.len(), "deployments": items}).to_string())
        }
        ("GET", ["deployments", id]) => (
            200,
            json!({"deployment_uuid": id, "application_id": 7,
                   "status": state.deployment_status.clone().unwrap_or_else(|| "finished".to_owned())})
            .to_string(),
        ),
        ("POST", ["deploy"]) if state.fail_deploy => (
            500,
            json!({"message": "Deployment queue is unavailable."}).to_string(),
        ),
        ("POST", ["deploy"]) => {
            let uuid = target
                .split("uuid=")
                .nth(1)
                .and_then(|rest| rest.split('&').next())
                .unwrap_or_default()
                .to_owned();
            let id = format!("dep-{uuid}");
            if let Some(app) = state.applications.get_mut(&uuid) {
                app.deployment = Some(id.clone());
            }
            (
                200,
                json!({"deployments": [{"message": "queued", "resource_uuid": uuid,
                                        "deployment_uuid": id}]})
                .to_string(),
            )
        }
        ("POST", ["services", uuid, "start"]) => {
            if let Some(svc) = state.services.get_mut(*uuid) {
                svc.started = true;
            }
            (200, json!({"message": "Service starting request queued."}).to_string())
        }
        ("GET", ["applications", uuid]) => (
            200,
            json!({"id": 7, "uuid": uuid, "status": "running:healthy"}).to_string(),
        ),
        ("GET", ["services", uuid]) => {
            let started = state.services.get(*uuid).is_some_and(|svc| svc.started);
            (
                200,
                json!({"id": 8, "uuid": uuid,
                       "status": if started { "running:healthy" } else { "exited" }})
                .to_string(),
            )
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
                let mut buffer = Vec::new();
                let mut chunk = vec![0_u8; 8192];
                let split = loop {
                    let read = socket.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                        break at + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buffer[..split]).to_string();
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while buffer.len() < split + length {
                    let read = socket.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                }
                let body = String::from_utf8_lossy(&buffer[split..]).to_string();
                let mut words = head.split_whitespace();
                let method = words.next().unwrap_or_default().to_owned();
                let target = words.next().unwrap_or_default().to_owned();
                let (status, answer) = if head.contains(&format!("Bearer {TOKEN}")) {
                    respond(&mut state.lock().unwrap(), &method, &target, &body)
                } else {
                    (401, json!({"message": "Unauthenticated."}).to_string())
                };
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                    answer.len()
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

struct NoProgress;

#[async_trait]
impl DeployProgress for NoProgress {
    async fn note(&self, _: &str, _: &str) {}
}

struct Rig {
    address: std::net::SocketAddr,
    store: Store,
    operations: Arc<Operations>,
    executor: SiteExecutor,
    sites: Arc<SiteTemplates>,
    coolify: Shared,
    account: String,
    _dirs: Vec<tempfile::TempDir>,
}

impl Rig {
    async fn new() -> Self {
        let coolify: Shared = Arc::new(Mutex::new(Coolify::default()));
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
        let lifecycle = fleet_controller::coolify_exec::compose_coolify_lifecycle(
            store.pool(),
            secrets.clone(),
        );
        services.site_templates = Some(fleet_controller::site_exec::compose_site_templates(
            store.pool(),
            lifecycle.clone(),
        ));
        services.coolify_lifecycle = Some(lifecycle);
        // The executor under test: the same composition, no wait.
        let no_wait = Settle {
            attempts: 1,
            interval: std::time::Duration::ZERO,
        };
        let executor_lifecycle = Arc::new(CoolifyLifecycle::new(
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
        ));
        let sites = Arc::new(
            SiteTemplates::new(
                executor_lifecycle,
                Arc::new(fleet_provider_coolify::CoolifyHttpLifecycle),
                Arc::new(fleet_provider_coolify::CoolifyHttpSettings),
                Arc::new(fleet_provider_coolify::CoolifyHttpCreate),
                Arc::new(fleet_storage_sqlite::CoolifyObservationRepository::new(
                    store.pool().clone(),
                )),
            )
            .with_settle(no_wait),
        );
        let server_settings = Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            web_dist: dist.path().to_path_buf(),
            artifacts_dir: None,
            tailscale_serve_listen: None,
        };
        let router = build_router(
            &server_settings,
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
            executor: SiteExecutor::new(sites.clone()),
            sites,
            coolify,
            account,
            _dirs: vec![dist, store_dir, key_dir],
        };
        let (status, body) = raw(
            rig.address,
            "POST",
            &format!("/api/v1/external-accounts/{}/coolify/discover", rig.account),
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        rig
    }

    fn body(&self, template: &str, domain: &str) -> Value {
        let mut body = json!({
            "accountId": self.account, "templateId": template, "serverUuid": SERVER,
            "projectUuid": PROJECT, "environmentName": "production", "domain": domain,
            "reason": "a new site"
        });
        if template == "node-app" || template == "static-site" {
            body["repository"] = json!("https://example.test/owner/site");
            body["branch"] = json!("main");
        }
        body
    }

    async fn file(&self, body: Value) -> (u16, Value) {
        raw(self.address, "POST", "/api/v1/site-deployments", Some(body)).await
    }

    async fn approve(&self, id: &str) {
        let (status, body) = raw(
            self.address,
            "POST",
            &format!("/api/v1/requests/{id}/approve"),
            None,
        )
        .await;
        assert_eq!(status, 200, "{body}");
    }

    async fn run(&self, request_id: &str) -> (Value, Value) {
        let (_, request) = raw(
            self.address,
            "GET",
            &format!("/api/v1/requests/{request_id}"),
            None,
        )
        .await;
        let operation_id = request["data"]["operationId"]
            .as_str()
            .unwrap_or_else(|| panic!("no operation: {request}"))
            .to_owned();
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

    async fn file_approve_run(&self, body: Value) -> (Value, Value, Value) {
        let (status, filed) = self.file(body).await;
        assert_eq!(status, 201, "{filed}");
        assert_eq!(filed["data"]["riskClass"], "approve");
        assert_eq!(filed["data"]["state"], "pending");
        assert_eq!(filed["data"]["actionId"], "coolify.site.deploy");
        let id = filed["data"]["id"].as_str().unwrap().to_owned();
        self.approve(&id).await;
        let (request, operation) = self.run(&id).await;
        (filed["data"].clone(), request, operation)
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
async fn the_template_list_is_pinned_by_digest() {
    let rig = Rig::new().await;
    let (status, list) = raw(rig.address, "GET", "/api/v1/site-templates", None).await;
    assert_eq!(status, 200, "{list}");
    let templates = list["data"]["templates"].as_array().unwrap();
    let ids: Vec<&str> = templates
        .iter()
        .map(|t| t["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["ghost", "uptime-kuma", "static-site", "node-app"]);
    for template in templates {
        assert_eq!(template["digest"].as_str().unwrap().len(), 64);
        assert_eq!(template["version"], 1);
    }
    assert_eq!(templates[0]["source"]["kind"], "service");
    assert_eq!(templates[3]["source"]["kind"], "git");
    assert_eq!(templates[3]["needsRepository"], true);
}

#[tokio::test]
async fn a_service_template_creates_sets_the_domain_and_starts_it() {
    let rig = Rig::new().await;
    let (filed, request, operation) = rig
        .file_approve_run(rig.body("ghost", "Blog.Example.Test"))
        .await;
    assert_eq!(
        filed["target"],
        format!("site:{}:blog.example.test", rig.account)
    );
    assert_eq!(request["state"], "succeeded", "{request}");
    assert_eq!(operation["kind"], SITE_KIND);
    assert_eq!(operation["state"], "succeeded", "{operation}");
    let result = result_of(&operation);
    assert_eq!(result["outcome"], "deployed");
    assert_eq!(result["resourceKind"], "service");
    assert_eq!(result["domain"], "https://blog.example.test");
    assert_eq!(result["settled"], true);
    let uuid = result["uuid"].as_str().unwrap();
    assert_eq!(
        result["serviceId"],
        format!("coolify:{}:{uuid}", rig.account)
    );
    let steps: Vec<&str> = result["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["step"].as_str().unwrap())
        .collect();
    assert_eq!(steps, ["find", "create", "env", "start", "verify"]);
    {
        let state = rig.coolify.lock().unwrap();
        let created = state.services.get(uuid).expect("the service was created");
        assert_eq!(created.body["type"], "ghost");
        assert_eq!(created.body["urls"][0]["name"], "ghost");
        assert_eq!(created.body["urls"][0]["url"], "https://blog.example.test");
        assert!(created.description.starts_with("fleet-deploy:"));
        assert!(created.started);
        assert_eq!(state.services.len(), 1);
    }
    let text = rig.stored_text().await;
    assert!(!text.contains(TOKEN));
}

#[tokio::test]
async fn a_git_template_creates_the_application_writes_defaults_and_deploys() {
    let rig = Rig::new().await;
    let (_, request, operation) = rig
        .file_approve_run(rig.body("node-app", "https://app.example.test"))
        .await;
    assert_eq!(request["state"], "succeeded", "{request}");
    let result = result_of(&operation);
    assert_eq!(result["outcome"], "deployed");
    assert_eq!(result["resourceKind"], "application");
    assert!(
        result["deploymentUuid"]
            .as_str()
            .unwrap()
            .starts_with("dep-")
    );
    assert_eq!(result["deploymentStatus"], "finished");
    let uuid = result["uuid"].as_str().unwrap();
    let state = rig.coolify.lock().unwrap();
    let app = state.applications.get(uuid).unwrap();
    assert_eq!(
        app.body["git_repository"],
        "https://example.test/owner/site"
    );
    assert_eq!(app.body["git_branch"], "main");
    assert_eq!(app.body["build_pack"], "nixpacks");
    assert_eq!(app.body["domains"], "https://app.example.test");
    assert_eq!(app.envs, ["NODE_ENV", "PORT"]);
    assert!(app.deployment.is_some());
    // Creation, envs, then one deploy: in that order, once.
    let order: Vec<&String> = state
        .log
        .iter()
        .filter(|line| {
            line.starts_with("POST /api/v1/applications/public")
                || line.contains("/envs") && line.starts_with("POST")
                || line.starts_with("POST /api/v1/deploy")
        })
        .collect();
    assert_eq!(order.len(), 4, "{order:?}");
    assert!(order[0].contains("applications/public") && order[3].contains("/deploy"));
}

#[tokio::test]
async fn a_failure_after_creation_reports_what_exists_and_the_marker_guards_duplicates() {
    let rig = Rig::new().await;
    rig.coolify.lock().unwrap().fail_deploy = true;
    let (_, request, operation) = rig
        .file_approve_run(rig.body("node-app", "https://later.example.test"))
        .await;
    assert_eq!(operation["state"], "failed", "{operation}");
    assert_eq!(request["state"], "failed", "{request}");
    let partial = result_of(&operation);
    assert_eq!(partial["outcome"], "partial");
    let uuid = partial["uuid"].as_str().unwrap().to_owned();
    assert_eq!(partial["resourceKind"], "application");
    assert!(partial["error"].as_str().unwrap().contains("deploy"));
    let statuses: Vec<(&str, &str)> = partial["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["step"].as_str().unwrap(), s["status"].as_str().unwrap()))
        .collect();
    assert_eq!(
        statuses,
        [
            ("find", "done"),
            ("create", "done"),
            ("env", "done"),
            ("start", "failed")
        ]
    );
    let error: Value = serde_json::from_str(operation["errorJson"].as_str().unwrap()).unwrap();
    assert_eq!(error["reason"], "site_partial");
    assert_eq!(rig.coolify.lock().unwrap().applications.len(), 1);

    // A failed request is final and is never re-run. What this checks is the
    // duplicate guard for a worker that resumes an interrupted execution of
    // the same operation: it finds the resource by its marker and does not
    // create a second one.
    rig.coolify.lock().unwrap().fail_deploy = false;
    let payload: String =
        sqlx::query_scalar("SELECT payload_json FROM operations WHERE kind = 'coolify.site'")
            .fetch_one(rig.store.pool())
            .await
            .unwrap();
    let payload = payload.as_str();
    let again = rig
        .sites
        .execute(SITE_KIND, payload, &NoProgress)
        .await
        .expect("the retry finishes");
    assert_eq!(again.uuid, uuid);
    assert_eq!(again.outcome, "deployed");
    {
        let state = rig.coolify.lock().unwrap();
        assert_eq!(state.applications.len(), 1, "no second resource");
        assert_eq!(state.applications[&uuid].envs, ["NODE_ENV", "PORT"]);
    }

    // A third run changes nothing: the deployment already exists.
    let third = rig
        .sites
        .execute(SITE_KIND, payload, &NoProgress)
        .await
        .unwrap();
    assert_eq!(third.steps[1].status, "reused");
    assert!(
        third
            .steps
            .iter()
            .any(|s| s.step == "start" && s.status == "skipped")
    );
    assert_eq!(rig.coolify.lock().unwrap().applications.len(), 1);

    // A resource that carries the marker but is not the one this request
    // asked for (another name) is not reused, and nothing is created.
    rig.coolify
        .lock()
        .unwrap()
        .applications
        .get_mut(&uuid)
        .unwrap()
        .body["name"] = json!("someone-elses-app");
    let failure = rig
        .sites
        .execute(SITE_KIND, payload, &NoProgress)
        .await
        .expect_err("a different name is refused");
    assert!(failure.message.contains("different name"), "{failure}");
    assert!(failure.partial.is_none());
    assert_eq!(rig.coolify.lock().unwrap().applications.len(), 1);
}

#[tokio::test]
async fn a_deployment_still_running_is_started_not_deployed() {
    let rig = Rig::new().await;
    rig.coolify.lock().unwrap().deployment_status = Some("in_progress".to_owned());
    let (_, request, operation) = rig
        .file_approve_run(rig.body("node-app", "https://slow.example.test"))
        .await;
    assert_eq!(request["state"], "succeeded", "{request}");
    let result = result_of(&operation);
    assert_eq!(result["outcome"], "started");
    assert_eq!(result["settled"], false);
    assert_eq!(result["deploymentStatus"], "in_progress");
}

#[tokio::test]
async fn a_generic_request_with_a_forged_display_name_is_refused_at_execution() {
    let rig = Rig::new().await;
    // Everything the approver trusts is in the parameters: a valid template
    // digest, a real server and project, but a server name that is not the
    // observed one.
    let (_, list) = raw(rig.address, "GET", "/api/v1/site-templates", None).await;
    let ghost = &list["data"]["templates"][0];
    assert_eq!(ghost["id"], "ghost");
    let (status, filed) = raw(
        rig.address,
        "POST",
        "/api/v1/requests",
        Some(json!({
            "actionId": "coolify.site.deploy",
            "target": format!("site:{}:forged.example.test", rig.account),
            "parameters": {
                "accountId": rig.account, "templateId": "ghost", "templateVersion": 1,
                "templateDigest": ghost["digest"], "serverUuid": SERVER,
                "serverName": "production-database-host", "projectUuid": PROJECT,
                "projectName": "sites", "environmentName": "production",
                "domain": "https://forged.example.test", "name": "forged-example-test"
            },
            "reason": "forged"
        })),
    )
    .await;
    assert_eq!(status, 201, "{filed}");
    let id = filed["data"]["id"].as_str().unwrap().to_owned();
    rig.approve(&id).await;
    let (request, operation) = rig.run(&id).await;
    assert_eq!(operation["state"], "failed", "{operation}");
    assert_eq!(request["state"], "failed", "{request}");
    assert!(
        operation["errorJson"].as_str().unwrap().contains("re-file"),
        "{operation}"
    );
    assert!(rig.coolify.lock().unwrap().services.is_empty());
}

#[tokio::test]
async fn a_failed_first_deployment_is_a_partial_result_with_its_uuids() {
    let rig = Rig::new().await;
    rig.coolify.lock().unwrap().deployment_status = Some("failed".to_owned());
    let (_, _, operation) = rig
        .file_approve_run(rig.body("static-site", "https://static.example.test"))
        .await;
    assert_eq!(operation["state"], "failed");
    let partial = result_of(&operation);
    assert_eq!(partial["outcome"], "partial");
    assert_eq!(partial["deploymentStatus"], "failed");
    assert!(partial["deploymentUuid"].is_string());
    assert!(
        partial["error"]
            .as_str()
            .unwrap()
            .contains("did not finish")
    );
}

#[tokio::test]
async fn a_refused_creation_fails_the_operation_with_nothing_created() {
    let rig = Rig::new().await;
    rig.coolify.lock().unwrap().fail_create = true;
    let (_, request, operation) = rig
        .file_approve_run(rig.body("ghost", "https://one.example.test"))
        .await;
    assert_eq!(operation["state"], "failed", "{operation}");
    assert_eq!(request["state"], "failed", "{request}");
    // No resource exists, so there is no partial result to report.
    assert!(operation["resultJson"].is_null(), "{operation}");
    assert!(
        operation["errorJson"]
            .as_str()
            .unwrap()
            .contains("creating the resource"),
        "{operation}"
    );
    assert!(rig.coolify.lock().unwrap().services.is_empty());
}

#[tokio::test]
async fn filing_refuses_what_it_can_check_without_creating_anything() {
    let rig = Rig::new().await;
    let cases = [
        (json!({"templateId": "nope"}), 400, "not a site template"),
        (json!({"domain": TAKEN}), 400, "already routed"),
        (json!({"serverUuid": "srvother"}), 404, "server"),
        (json!({"projectUuid": "projother"}), 404, "project"),
        (json!({"environmentName": "staging"}), 404, "environment"),
        (
            json!({"repository": "https://example.test/o/r"}),
            400,
            "takes no repository",
        ),
        (
            json!({"domain": "https://blog.example.test/path"}),
            400,
            "host name",
        ),
        (json!({"domain": "not a host"}), 400, ""),
    ];
    for (patch, expected, needle) in cases {
        let mut body = rig.body("ghost", "https://blog.example.test");
        for (key, value) in patch.as_object().unwrap() {
            body[key] = value.clone();
        }
        let (status, answer) = rig.file(body).await;
        assert_eq!(status, expected, "{patch}: {answer}");
        assert!(
            answer.to_string().contains(needle),
            "{patch}: {answer} should mention {needle}"
        );
    }
    // A Git template needs its repository and a safe one.
    let mut body = rig.body("node-app", "https://app.example.test");
    body["repository"] = json!("https://user:pass@example.test/o/r");
    let (status, answer) = rig.file(body).await;
    assert_eq!(status, 400, "{answer}");
    let mut body = rig.body("node-app", "https://app.example.test");
    body.as_object_mut().unwrap().remove("branch");
    let (status, answer) = rig.file(body).await;
    assert_eq!(status, 400, "{answer}");
    assert!(rig.coolify.lock().unwrap().services.is_empty());
    assert!(rig.coolify.lock().unwrap().applications.is_empty());
}

#[tokio::test]
async fn the_same_idempotency_key_returns_the_request_already_made() {
    let rig = Rig::new().await;
    let mut body = rig.body("ghost", "https://once.example.test");
    body["idempotencyKey"] = json!("deploy-once");
    let (status, first) = rig.file(body.clone()).await;
    assert_eq!(status, 201, "{first}");
    let (status, second) = rig.file(body.clone()).await;
    assert!(status == 200 || status == 201, "{second}");
    assert_eq!(first["data"]["id"], second["data"]["id"]);
    let mut other = rig.body("ghost", "https://other.example.test");
    other["idempotencyKey"] = json!("deploy-once");
    let (status, conflict) = rig.file(other).await;
    assert_eq!(status, 409, "{conflict}");
}

#[tokio::test]
async fn a_generic_request_with_a_forged_template_pin_is_refused_at_filing() {
    let rig = Rig::new().await;
    let (status, answer) = raw(
        rig.address,
        "POST",
        "/api/v1/requests",
        Some(json!({
            "actionId": "coolify.site.deploy",
            "target": format!("site:{}:forged.example.test", rig.account),
            "parameters": {
                "accountId": rig.account, "templateId": "ghost", "templateVersion": 1,
                "templateDigest": "0".repeat(64), "serverUuid": SERVER, "projectUuid": PROJECT,
                "environmentName": "production", "domain": "https://forged.example.test",
                "name": "forged-example-test"
            },
            "reason": "forged"
        })),
    )
    .await;
    assert_eq!(status, 400, "{answer}");
    assert!(answer.to_string().contains("template changed"));
}
