//! FM-1034: Coolify settings (environment variables, domains, health checks)
//! end to end over a real controller router, a real secret store and SQLite,
//! the action broker, the settings executor, and a stateful local stub that
//! speaks the routes of Coolify v4.4.6 (`routes/api.php`,
//! `ApplicationsController`, `EnvironmentVariable`). The bodies are
//! synthetic, written from the controllers' documented shapes; no live token
//! was used.
//!
//! The write-only invariant: an environment value must never appear in an
//! API answer, the audit ledger, an operation's payload, result, or error, an
//! action request, or the secret store once the request is over. The token
//! must never appear in any of them either.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use fleet_application::coolify::lifecycle::{CoolifyLifecycle, Settle};
use fleet_application::coolify::settings::CoolifySettings;
use fleet_application::operation::Operations;
use fleet_controller::coolify_exec::{CoolifySettingsExecutor, HOLD_PREFIX};
use fleet_controller::{Settings, build_router, compose_node_services};
use fleet_secrets::{SecretStore, SecretValue};
use fleet_storage_sqlite::{OperationRepository, Store};
use serde_json::{Value, json};
use sqlx::Row as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const TOKEN: &str = "coolify-settings-write-token-0001";
const SECRET: &str = "Zq9-never-leave-the-adapter-7731";
const SECRET_TWO: &str = "Kx4-another-held-value-5512";
const APP: &str = "appweb000000000001";
const SVC: &str = "svcplausible000000001";
const DB: &str = "dbpostgres00000000001";
const COMPOSE: &str = "appcompose0000000001";
const DEPLOYMENT: &str = "dep0000000000000001";

#[derive(Clone)]
struct Env {
    uuid: String,
    key: String,
    value: String,
    is_preview: bool,
    flags: [bool; 5], // buildtime, runtime, multiline, literal, shown_once
}

#[derive(Default)]
struct Coolify {
    version: String,
    envs: HashMap<String, Vec<Env>>,
    fqdn: String,
    health: serde_json::Map<String, Value>,
    /// Include `value` and `real_value` in listings (a token that was given
    /// read:sensitive): Fleet must still never show them.
    leak_values: bool,
    /// Answer an env write with a 422 that quotes the submitted value.
    quote_value_on_error: bool,
    /// Answer a write to this variable name with HTTP 500.
    fail_key: Option<String>,
    /// Answer a deploy with 200 and no deployment.
    deploy_empty: bool,
    /// Every request as `METHOD target`.
    log: Vec<String>,
    /// Every request body, by `METHOD target`.
    bodies: Vec<(String, String)>,
    next_env: u32,
}

type Shared = Arc<Mutex<Coolify>>;

fn env_json(env: &Env, leak: bool) -> Value {
    let mut item = json!({
        "uuid": env.uuid, "key": env.key, "is_preview": env.is_preview,
        "is_buildtime": env.flags[0], "is_runtime": env.flags[1],
        "is_multiline": env.flags[2], "is_literal": env.flags[3],
        "is_shown_once": env.flags[4], "is_shared": false, "version": "4.4.6"
    });
    if leak {
        item["value"] = json!(env.value);
        item["real_value"] = json!(env.value);
    }
    item
}

fn app_json(state: &Coolify) -> Value {
    let mut app = json!({
        "id": 1, "uuid": APP, "name": "web", "status": "running:healthy",
        "fqdn": state.fqdn, "build_pack": "nixpacks"
    });
    for (key, value) in &state.health {
        app[key] = value.clone();
    }
    app
}

fn respond(state: &mut Coolify, method: &str, target: &str, body: &str) -> (u16, String) {
    state.log.push(format!("{method} {target}"));
    state
        .bodies
        .push((format!("{method} {target}"), body.to_owned()));
    let path = target.split('?').next().unwrap_or_default();
    let path = path.strip_prefix("/api/v1").unwrap_or(path);
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    let sent: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let leak = state.leak_values;
    match (method, segments.as_slice()) {
        ("GET", ["version"]) => (200, state.version.clone()),
        ("GET", ["servers" | "projects" | "deployments"]) => (200, "[]".to_owned()),
        ("GET", ["applications"]) => (
            200,
            json!([
                {"uuid": APP, "name": "web", "status": "running:healthy", "environment_id": 1,
                 "fqdn": state.fqdn, "build_pack": "nixpacks"},
                {"uuid": COMPOSE, "name": "stack", "status": "running:healthy", "environment_id": 1,
                 "fqdn": "", "build_pack": "dockercompose"}
            ])
            .to_string(),
        ),
        ("GET", ["services"]) => (
            200,
            json!([{"uuid": SVC, "name": "plausible", "status": "running:healthy", "environment_id": 1}])
                .to_string(),
        ),
        ("GET", ["services", _, "applications"]) => (200, "[]".to_owned()),
        ("GET", ["databases"]) => (
            200,
            json!([{"uuid": DB, "name": "shop-db", "status": "running:healthy", "environment_id": 1,
                    "image": "postgres:16-alpine"}])
            .to_string(),
        ),
        ("GET", ["applications", uuid]) if *uuid == APP => (200, app_json(state).to_string()),
        ("GET", ["applications", uuid]) if *uuid == COMPOSE => (
            200,
            json!({"id": 2, "uuid": COMPOSE, "name": "stack", "fqdn": null,
                   "build_pack": "dockercompose"})
            .to_string(),
        ),
        ("GET", [family @ ("applications" | "services"), uuid, "envs"]) => {
            let _ = family;
            let items: Vec<Value> = state
                .envs
                .get(*uuid)
                .map(|envs| envs.iter().map(|env| env_json(env, leak)).collect())
                .unwrap_or_default();
            (200, Value::Array(items).to_string())
        }
        ("POST", [_, uuid, "envs"]) => {
            let key = sent["key"].as_str().unwrap_or_default().to_owned();
            let value = sent["value"].as_str().unwrap_or_default().to_owned();
            if state.quote_value_on_error {
                return (
                    422,
                    json!({"message": "Validation failed.", "errors": {"value": [format!("The value {value} is invalid.")]}})
                        .to_string(),
                );
            }
            if state.fail_key.as_deref() == Some(key.as_str()) {
                return (500, json!({"message": format!("boom {value}")}).to_string());
            }
            let preview = sent["is_preview"].as_bool().unwrap_or(false);
            let envs = state.envs.entry((*uuid).to_owned()).or_default();
            if envs.iter().any(|e| e.key == key && e.is_preview == preview) {
                return (
                    409,
                    json!({"message": "Environment variable already exists. Use PATCH request to update it."})
                        .to_string(),
                );
            }
            state.next_env += 1;
            let env = Env {
                uuid: format!("env-{}", state.next_env),
                key,
                value,
                is_preview: preview,
                flags: [
                    sent["is_buildtime"].as_bool().unwrap_or(true),
                    sent["is_runtime"].as_bool().unwrap_or(true),
                    sent["is_multiline"].as_bool().unwrap_or(false),
                    sent["is_literal"].as_bool().unwrap_or(false),
                    sent["is_shown_once"].as_bool().unwrap_or(false),
                ],
            };
            let uuid_out = env.uuid.clone();
            state
                .envs
                .get_mut(*uuid)
                .expect("inserted above")
                .push(env);
            (201, json!({"uuid": uuid_out}).to_string())
        }
        ("PATCH", [_, uuid, "envs"]) => {
            let key = sent["key"].as_str().unwrap_or_default().to_owned();
            let preview = sent["is_preview"].as_bool().unwrap_or(false);
            if state.fail_key.as_deref() == Some(key.as_str()) {
                return (500, json!({"message": "boom"}).to_string());
            }
            if state.quote_value_on_error {
                return (
                    422,
                    json!({"message": format!("The value {} is invalid.", sent["value"])})
                        .to_string(),
                );
            }
            let Some(env) = state
                .envs
                .get_mut(*uuid)
                .and_then(|envs| envs.iter_mut().find(|e| e.key == key && e.is_preview == preview))
            else {
                return (404, json!({"message": "Environment variable not found."}).to_string());
            };
            env.value = sent["value"].as_str().unwrap_or_default().to_owned();
            env.flags = [
                sent["is_buildtime"].as_bool().unwrap_or(env.flags[0]),
                sent["is_runtime"].as_bool().unwrap_or(env.flags[1]),
                sent["is_multiline"].as_bool().unwrap_or(false),
                sent["is_literal"].as_bool().unwrap_or(false),
                sent["is_shown_once"].as_bool().unwrap_or(false),
            ];
            (201, env_json(env, false).to_string())
        }
        ("DELETE", [_, uuid, "envs", env_uuid]) => {
            let envs = state.envs.entry((*uuid).to_owned()).or_default();
            let before = envs.len();
            envs.retain(|e| e.uuid != *env_uuid);
            if envs.len() == before {
                return (404, json!({"message": "Environment variable not found."}).to_string());
            }
            (200, json!({"message": "Environment variable deleted."}).to_string())
        }
        ("PATCH", ["applications", uuid]) if *uuid == APP => {
            if let Some(domains) = sent.get("domains") {
                state.fqdn = domains.as_str().unwrap_or_default().to_owned();
            }
            if let Some(object) = sent.as_object() {
                for (key, value) in object {
                    if key.starts_with("health_check_") {
                        state.health.insert(key.clone(), value.clone());
                    }
                }
            }
            (200, json!({"uuid": APP}).to_string())
        }
        ("POST", ["deploy"]) if state.deploy_empty => (
            200,
            json!({"deployments": [{"message": "Deployment is already queued.", "resource_uuid": APP}]})
                .to_string(),
        ),
        ("POST", ["deploy"]) => (
            200,
            json!({"deployments": [{"message": "Application web deployment queued.",
                "resource_uuid": APP, "deployment_uuid": DEPLOYMENT}]})
            .to_string(),
        ),
        ("POST", ["services", _, "restart"]) => {
            (200, json!({"message": "Request queued."}).to_string())
        }
        ("GET", ["applications" | "services" | "databases", uuid]) => (
            200,
            json!({"id": 3, "uuid": uuid, "status": "running:healthy"}).to_string(),
        ),
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
                // Read the head, then the declared body.
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
                        let lower = line.to_ascii_lowercase();
                        lower
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
    assert!(!text.contains(SECRET), "a value reached an answer");
    assert!(!text.contains(SECRET_TWO), "a value reached an answer");
    (status, serde_json::from_str(rest).unwrap_or(Value::Null))
}

struct Rig {
    address: std::net::SocketAddr,
    store: Store,
    secrets: Arc<SecretStore>,
    operations: Arc<Operations>,
    executor: CoolifySettingsExecutor,
    settings: Arc<CoolifySettings>,
    coolify: Shared,
    account: String,
    _dirs: Vec<tempfile::TempDir>,
}

impl Rig {
    async fn new() -> Self {
        let mut state = Coolify {
            version: "4.4.6".to_owned(),
            fqdn: "https://shop.example.test".to_owned(),
            ..Coolify::default()
        };
        state.health = json!({
            "health_check_type": "http", "health_check_enabled": false, "health_check_path": "/",
            "health_check_port": null, "health_check_host": null,
            "health_check_method": "GET", "health_check_scheme": "http",
            "health_check_return_code": 200, "health_check_response_text": null,
            "health_check_interval": 5, "health_check_timeout": 5,
            "health_check_retries": 10, "health_check_start_period": 5
        })
        .as_object()
        .unwrap()
        .clone();
        let old = |uuid: &str, key: &str| Env {
            uuid: uuid.to_owned(),
            key: key.to_owned(),
            value: "an-existing-value-xx".to_owned(),
            is_preview: false,
            flags: [true, true, false, false, false],
        };
        state.envs.insert(
            APP.to_owned(),
            vec![old("env-old-1", "OLD_SETTING"), old("env-old-2", "KEEP_ME")],
        );
        state
            .envs
            .insert(SVC.to_owned(), vec![old("env-svc-1", "SERVICE_PASSWORD")]);
        state.next_env = 100;
        let coolify: Shared = Arc::new(Mutex::new(state));
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
        services.coolify_settings = Some(fleet_controller::coolify_exec::compose_coolify_settings(
            store.pool(),
            secrets.clone(),
            lifecycle.clone(),
        ));
        services.coolify_lifecycle = Some(lifecycle);
        // The executor under test: the same composition, no wait.
        let executor_lifecycle = Arc::new(
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
                attempts: 1,
                interval: std::time::Duration::ZERO,
            }),
        );
        let settings = fleet_controller::coolify_exec::compose_coolify_settings(
            store.pool(),
            secrets.clone(),
            executor_lifecycle,
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
            secrets,
            operations,
            executor: CoolifySettingsExecutor::new(settings.clone()),
            settings,
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

    fn id(&self, uuid: &str) -> String {
        format!("coolify:{}:{uuid}", self.account)
    }

    async fn post(&self, uuid: &str, what: &str, body: Value) -> (u16, Value) {
        raw(
            self.address,
            "POST",
            &format!("/api/v1/services/{}/settings/{what}", self.id(uuid)),
            Some(body),
        )
        .await
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

    async fn file_approve_run(&self, uuid: &str, what: &str, body: Value) -> (Value, Value) {
        let (status, filed) = self.post(uuid, what, body).await;
        assert_eq!(status, 201, "{filed}");
        assert_eq!(filed["data"]["riskClass"], "approve");
        assert_eq!(filed["data"]["state"], "pending");
        let id = filed["data"]["id"].as_str().unwrap().to_owned();
        self.approve(&id).await;
        self.run(&id).await
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

    async fn held_records(&self) -> usize {
        self.secrets
            .list()
            .await
            .unwrap()
            .into_iter()
            .filter(|record| record.name.starts_with(HOLD_PREFIX))
            .count()
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

    async fn assert_nothing_stored(&self) {
        let text = self.stored_text().await;
        for secret in [TOKEN, SECRET, SECRET_TWO] {
            assert!(!text.contains(secret), "a secret reached stored state");
        }
    }
}

fn result_of(operation: &Value) -> Value {
    serde_json::from_str(operation["resultJson"].as_str().unwrap_or("null")).unwrap()
}

fn env_set(key: &str, value: &str) -> Value {
    json!({"op": "set", "key": key, "value": value})
}

#[tokio::test]
async fn the_settings_view_lists_keys_and_flags_and_never_a_value() {
    let rig = Rig::new().await;
    // Even when the token could see values (read:sensitive), Fleet shows none.
    rig.coolify.lock().unwrap().leak_values = true;
    let (status, view) = raw(
        rig.address,
        "GET",
        &format!("/api/v1/services/{}/settings", rig.id(APP)),
        None,
    )
    .await;
    assert_eq!(status, 200, "{view}");
    let data = &view["data"];
    assert_eq!(data["resourceKind"], "application");
    let keys: Vec<&str> = data["env"]
        .as_array()
        .unwrap()
        .iter()
        .map(|env| env["key"].as_str().unwrap())
        .collect();
    assert_eq!(keys, ["OLD_SETTING", "KEEP_ME"]);
    assert_eq!(data["env"][0]["isBuildtime"], true);
    assert!(data["env"][0].get("value").is_none());
    assert_eq!(data["domains"], json!(["https://shop.example.test"]));
    assert_eq!(data["health"]["path"], "/");
    assert_eq!(data["health"]["enabled"], false);
    assert!(!view.to_string().contains("an-existing-value-xx"));

    let (_, service) = raw(
        rig.address,
        "GET",
        &format!("/api/v1/services/{}/settings", rig.id(SVC)),
        None,
    )
    .await;
    assert!(service["data"]["domains"].is_null());
    assert_eq!(service["data"]["env"][0]["key"], "SERVICE_PASSWORD");
    assert!(!service.to_string().contains("an-existing-value-xx"));

    let (_, compose) = raw(
        rig.address,
        "GET",
        &format!("/api/v1/services/{}/settings", rig.id(COMPOSE)),
        None,
    )
    .await;
    assert!(compose["data"]["domains"].is_null());
    assert!(
        compose["data"]["notes"][0]
            .as_str()
            .unwrap()
            .contains("Compose")
    );

    // The view only ever read.
    assert!(
        rig.requests_to("")
            .iter()
            .all(|line| line.starts_with("GET")),
        "{:?}",
        rig.requests_to("")
    );
}

#[tokio::test]
async fn setting_and_unsetting_variables_round_trips_without_a_value_leaving_the_adapter() {
    let rig = Rig::new().await;
    let (status, filed) = rig
        .post(
            APP,
            "env",
            json!({
                "changes": [
                    {"op": "set", "key": "API_URL", "value": SECRET, "isLiteral": true},
                    {"op": "set", "key": "OLD_SETTING", "value": SECRET_TWO},
                    {"op": "unset", "key": "KEEP_ME"}
                ],
                "reason": "rotate", "redeploy": true
            }),
        )
        .await;
    assert_eq!(status, 201, "{filed}");
    let request = &filed["data"];
    assert_eq!(request["actionId"], "coolify.env.update");
    assert_eq!(request["riskClass"], "approve");
    assert_eq!(request["state"], "pending");
    assert_eq!(request["target"], rig.id(APP));
    // The approver reads key names and flags; a value is write-only.
    let preview = request["parameters"]["preview"].as_array().unwrap();
    assert_eq!(preview.len(), 3);
    assert_eq!(preview[0]["key"], "API_URL");
    assert_eq!(preview[0]["operation"], "create");
    assert_eq!(preview[1]["operation"], "update");
    assert_eq!(preview[2]["operation"], "delete");
    assert!(request.to_string().contains("write-only"));
    // One held record, nothing sent to Coolify yet.
    assert_eq!(rig.held_records().await, 1);
    assert!(
        rig.requests_to("")
            .iter()
            .all(|line| line.starts_with("GET")),
        "nothing is written before approval"
    );
    rig.assert_nothing_stored().await;

    let id = request["id"].as_str().unwrap().to_owned();
    rig.approve(&id).await;
    let (request, operation) = rig.run(&id).await;
    assert_eq!(request["state"], "succeeded", "{request} {operation}");
    let result = result_of(&operation);
    assert_eq!(result["setting"], "env");
    assert_eq!(result["outcome"], "applied");
    assert_eq!(result["verified"], true);
    assert_eq!(
        result["changed"],
        json!(["set API_URL", "set OLD_SETTING", "unset KEEP_ME"])
    );
    assert_eq!(result["followUp"]["verb"], "redeploy");
    assert_eq!(result["followUp"]["deploymentUuid"], DEPLOYMENT);

    // The values reached Coolify exactly once each, by the documented routes.
    assert_eq!(
        rig.requests_to("POST /api/v1/applications/appweb000000000001/envs")
            .len(),
        1
    );
    assert_eq!(
        rig.requests_to("PATCH /api/v1/applications/appweb000000000001/envs")
            .len(),
        1
    );
    assert_eq!(
        rig.requests_to("DELETE /api/v1/applications/appweb000000000001/envs/env-old-2")
            .len(),
        1
    );
    {
        let state = rig.coolify.lock().unwrap();
        let envs = &state.envs[APP];
        let api = envs.iter().find(|e| e.key == "API_URL").unwrap();
        assert_eq!(api.value, SECRET);
        assert!(api.flags[3], "the literal flag was sent");
        let old = envs.iter().find(|e| e.key == "OLD_SETTING").unwrap();
        assert_eq!(old.value, SECRET_TWO);
        assert!(envs.iter().all(|e| e.key != "KEEP_ME"));
        // The full flag set is sent on a PATCH: nothing is left to a default.
        let body = state
            .bodies
            .iter()
            .find(|(line, _)| line.starts_with("PATCH") && line.ends_with("/envs"))
            .map(|(_, body)| body.clone())
            .unwrap();
        let sent: Value = serde_json::from_str(&body).unwrap();
        for field in [
            "is_literal",
            "is_multiline",
            "is_shown_once",
            "is_runtime",
            "is_buildtime",
            "is_preview",
        ] {
            assert!(sent.get(field).is_some(), "{field} missing from {body}");
        }
    }
    assert_eq!(rig.requests_to("POST /api/v1/deploy").len(), 1);
    // After the request the held record is gone and nothing stored has a
    // value or the token.
    assert_eq!(rig.held_records().await, 0);
    rig.assert_nothing_stored().await;
    // The finished request still shows names only.
    let (_, read) = raw(rig.address, "GET", &format!("/api/v1/requests/{id}"), None).await;
    assert_eq!(read["data"]["state"], "succeeded");
}

#[tokio::test]
async fn a_service_variable_is_set_and_the_service_restarts() {
    let rig = Rig::new().await;
    let (request, operation) = rig
        .file_approve_run(
            SVC,
            "env",
            json!({"changes": [env_set("SERVICE_TOKEN", SECRET)], "redeploy": true}),
        )
        .await;
    assert_eq!(request["state"], "succeeded", "{request} {operation}");
    assert_eq!(result_of(&operation)["followUp"]["verb"], "restart");
    assert_eq!(
        rig.requests_to("POST /api/v1/services/svcplausible000000001/envs")
            .len(),
        1
    );
    assert_eq!(
        rig.requests_to("POST /api/v1/services/svcplausible000000001/restart")
            .len(),
        1
    );
    // A service has no scope flags or preview variables.
    let body = rig
        .coolify
        .lock()
        .unwrap()
        .bodies
        .iter()
        .find(|(line, _)| line.starts_with("POST") && line.ends_with("/envs"))
        .map(|(_, body)| body.clone())
        .unwrap();
    assert!(
        !body.contains("is_preview") && !body.contains("is_buildtime"),
        "{body}"
    );
    rig.assert_nothing_stored().await;

    let (status, refused) = rig
        .post(
            SVC,
            "env",
            json!({"changes": [{"op": "set", "key": "X", "value": SECRET, "isPreview": true}]}),
        )
        .await;
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        rig.held_records().await,
        0,
        "a refused request stores nothing"
    );
}

#[tokio::test]
async fn invalid_variable_requests_are_refused_before_anything_is_held() {
    let rig = Rig::new().await;
    for (uuid, body) in [
        (DB, json!({"changes": [env_set("X", SECRET)]})),
        (APP, json!({"changes": []})),
        (APP, json!({"changes": [env_set("1BAD", SECRET)]})),
        (APP, json!({"changes": [env_set("A-B", SECRET)]})),
        (APP, json!({"changes": [{"op": "set", "key": "X"}]})),
        (
            APP,
            json!({"changes": [{"op": "unset", "key": "X", "value": SECRET}]}),
        ),
        (
            APP,
            json!({"changes": [{"op": "unset", "key": "NOT_THERE"}]}),
        ),
        (
            APP,
            json!({"changes": [{"op": "frob", "key": "X", "value": SECRET}]}),
        ),
        (
            APP,
            json!({"changes": [env_set("X", SECRET), env_set("X", SECRET_TWO)]}),
        ),
    ] {
        let (status, answer) = rig.post(uuid, "env", body.clone()).await;
        assert!(
            status == 400 || status == 404,
            "{status} {answer} for {body}"
        );
        assert_eq!(rig.held_records().await, 0, "{body}");
    }
    // A body that is not the documented shape is refused without echoing it.
    let (status, answer) = rig
        .post(APP, "env", json!({"changes": "nope", "value": SECRET}))
        .await;
    assert_eq!(status, 400, "{answer}");
    assert!(rig.requests_to("").iter().all(|l| l.starts_with("GET")));
}

#[tokio::test]
async fn a_forged_request_without_a_computed_preview_is_refused_by_the_broker() {
    let rig = Rig::new().await;
    for params in [
        json!({"accountId": rig.account, "resourceKind": "application", "uuid": APP, "name": "web",
               "changes": [{"op": "unset", "key": "OLD_SETTING", "isPreview": false}],
               "redeploy": false, "preview": []}),
        json!({"accountId": rig.account, "resourceKind": "application", "uuid": APP, "name": "web",
               "domains": ["https://evil.example.test"], "redeploy": false,
               "preview": {"before": [], "after": ["https://evil.example.test"], "changes": []}}),
    ] {
        let action = if params.get("domains").is_some() {
            "coolify.application.domains.set"
        } else {
            "coolify.env.update"
        };
        let (status, answer) = raw(
            rig.address,
            "POST",
            "/api/v1/requests",
            Some(json!({"actionId": action, "target": rig.id(APP), "parameters": params, "reason": "forged"})),
        )
        .await;
        assert_eq!(status, 400, "{answer}");
    }
}

#[tokio::test]
async fn a_denied_request_loses_its_held_value_to_the_sweep() {
    let rig = Rig::new().await;
    let (_, filed) = rig
        .post(APP, "env", json!({"changes": [env_set("API_URL", SECRET)]}))
        .await;
    let id = filed["data"]["id"].as_str().unwrap().to_owned();
    assert_eq!(rig.held_records().await, 1);
    // While the request is pending the value is kept, even long after.
    let day = fleet_core::SystemClock::now_unix_millis() + 60 * 60 * 1000;
    assert_eq!(rig.settings.sweep_held(day).await.unwrap(), 0);
    assert_eq!(rig.held_records().await, 1);

    let (status, denied) = raw(
        rig.address,
        "POST",
        &format!("/api/v1/requests/{id}/deny"),
        Some(json!({"note": "no"})),
    )
    .await;
    assert_eq!(status, 200, "{denied}");
    // Within the grace the sweep leaves a hold alone (it may be between its
    // storing and its request); after it, a denied request's value goes.
    let soon = fleet_core::SystemClock::now_unix_millis();
    assert_eq!(rig.settings.sweep_held(soon).await.unwrap(), 0);
    assert_eq!(rig.settings.sweep_held(day).await.unwrap(), 1);
    assert_eq!(rig.held_records().await, 0);
    assert!(
        rig.requests_to("")
            .iter()
            .all(|line| line.starts_with("GET")),
        "a denied request writes nothing"
    );
    rig.assert_nothing_stored().await;
}

#[tokio::test]
async fn a_request_that_copies_a_hold_id_cannot_spend_or_delete_the_victims_values() {
    let rig = Rig::new().await;
    let (_, filed) = rig
        .post(APP, "env", json!({"changes": [env_set("API_URL", SECRET)]}))
        .await;
    let victim = filed["data"]["id"].as_str().unwrap().to_owned();
    // The parameters are public: an attacker files another request with
    // exactly the same parameters (and so the same holdId).
    let (status, forged) = raw(
        rig.address,
        "POST",
        "/api/v1/requests",
        Some(json!({
            "actionId": "coolify.env.update", "target": rig.id(APP),
            "parameters": filed["data"]["parameters"], "reason": "forged",
        })),
    )
    .await;
    assert_eq!(status, 201, "{forged}");
    let forged = forged["data"]["id"].as_str().unwrap().to_owned();
    assert_ne!(forged, victim);
    rig.approve(&forged).await;
    let (request, operation) = rig.run(&forged).await;
    assert_eq!(request["state"], "failed", "{request} {operation}");
    assert!(
        operation.to_string().contains("belong to another request"),
        "{operation}"
    );
    // Nothing was written, and the victim's record is intact.
    assert!(rig.requests_to("").iter().all(|l| l.starts_with("GET")));
    assert_eq!(rig.held_records().await, 1);
    // The victim's own request still runs with its own value.
    rig.approve(&victim).await;
    let (request, operation) = rig.run(&victim).await;
    assert_eq!(request["state"], "succeeded", "{request} {operation}");
    assert_eq!(rig.held_records().await, 0);
    let value = rig.coolify.lock().unwrap().envs[APP]
        .iter()
        .find(|e| e.key == "API_URL")
        .map(|e| e.value.clone());
    assert_eq!(value.as_deref(), Some(SECRET));
    rig.assert_nothing_stored().await;
}

#[tokio::test]
async fn a_record_whose_binding_was_altered_is_refused_and_left_alone() {
    let rig = Rig::new().await;
    let (_, filed) = rig
        .post(APP, "env", json!({"changes": [env_set("API_URL", SECRET)]}))
        .await;
    let id = filed["data"]["id"].as_str().unwrap().to_owned();
    rig.approve(&id).await;
    let record = rig
        .secrets
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.name.starts_with(HOLD_PREFIX))
        .unwrap();
    rig.secrets
        .update(
            &record.id,
            SecretValue::new(
                json!({"binding": "0".repeat(64), "requestId": id, "values": {"0": SECRET_TWO}})
                    .to_string()
                    .into_bytes(),
            ),
        )
        .await
        .unwrap();
    let (request, operation) = rig.run(&id).await;
    assert_eq!(request["state"], "failed", "{request}");
    assert!(operation.to_string().contains("not bound"), "{operation}");
    assert!(rig.requests_to("").iter().all(|l| l.starts_with("GET")));
    assert_eq!(rig.held_records().await, 1);
}

#[tokio::test]
async fn staleness_is_checked_before_the_first_write_and_a_partial_change_is_recorded() {
    let rig = Rig::new().await;
    // Stale: the second variable's flags move before the run; nothing is written.
    let (_, filed) = rig
        .post(
            APP,
            "env",
            json!({"changes": [env_set("FIRST", SECRET), env_set("KEEP_ME", SECRET_TWO)]}),
        )
        .await;
    let id = filed["data"]["id"].as_str().unwrap().to_owned();
    rig.coolify.lock().unwrap().envs.get_mut(APP).unwrap()[1].flags[3] = true;
    rig.approve(&id).await;
    let (request, operation) = rig.run(&id).await;
    assert_eq!(request["state"], "failed", "{request}");
    assert!(operation.to_string().contains("stale"), "{operation}");
    assert!(
        rig.requests_to("").iter().all(|l| l.starts_with("GET")),
        "no write before every check passed"
    );
    assert_eq!(rig.held_records().await, 0);

    // Partial: the second write fails after the first was applied.
    rig.coolify.lock().unwrap().envs.get_mut(APP).unwrap()[1].flags[3] = false;
    rig.coolify.lock().unwrap().fail_key = Some("SECOND".to_owned());
    let (request, operation) = rig
        .file_approve_run(
            APP,
            "env",
            json!({"changes": [env_set("FIRST", SECRET), env_set("SECOND", SECRET_TWO)]}),
        )
        .await;
    assert_eq!(request["state"], "failed", "{request}");
    let result = result_of(&operation);
    assert_eq!(result["outcome"], "partial", "{operation}");
    assert_eq!(result["changed"], json!(["set FIRST"]));
    assert_eq!(result["verified"], false);
    let text = operation.to_string();
    assert!(
        text.contains("stopped at SECOND") && text.contains("500"),
        "{text}"
    );
    assert!(!text.contains(SECRET) && !text.contains(SECRET_TWO));
    assert_eq!(rig.held_records().await, 0);
    rig.assert_nothing_stored().await;
}

#[tokio::test]
async fn a_failed_redeploy_after_the_change_is_a_structured_partial_result() {
    let rig = Rig::new().await;
    rig.coolify.lock().unwrap().deploy_empty = true;
    let (request, operation) = rig
        .file_approve_run(
            APP,
            "domains",
            json!({"domains": ["https://shop.example.test", "https://www.example.test"], "redeploy": true}),
        )
        .await;
    assert_eq!(request["state"], "failed", "{request}");
    let result = result_of(&operation);
    assert_eq!(result["outcome"], "applied");
    assert_eq!(result["changed"], json!(["domains"]));
    assert!(
        result["followUp"]["error"]
            .as_str()
            .unwrap()
            .contains("did not queue")
    );
    assert!(
        operation
            .to_string()
            .contains("the change was applied but the redeploy failed")
    );
}

#[tokio::test]
async fn a_duplicated_variable_is_refused_empty_values_are_allowed_and_health_can_be_cleared() {
    let rig = Rig::new().await;
    {
        let mut state = rig.coolify.lock().unwrap();
        let dup = state.envs[APP][0].clone();
        state.envs.get_mut(APP).unwrap().push(Env {
            uuid: "env-dup".to_owned(),
            ..dup
        });
    }
    let (status, answer) = rig
        .post(
            APP,
            "env",
            json!({"changes": [env_set("OLD_SETTING", SECRET)]}),
        )
        .await;
    assert_eq!(status, 400, "{answer}");
    assert!(
        answer["message"]
            .as_str()
            .unwrap()
            .contains("more than once")
    );
    assert_eq!(rig.held_records().await, 0);
    let (_, view) = raw(
        rig.address,
        "GET",
        &format!("/api/v1/services/{}/settings", rig.id(APP)),
        None,
    )
    .await;
    assert!(
        view["data"]["notes"][0]
            .as_str()
            .unwrap()
            .contains("OLD_SETTING")
    );
    rig.coolify.lock().unwrap().envs.get_mut(APP).unwrap().pop();

    // An empty value is a value.
    let (request, operation) = rig
        .file_approve_run(APP, "env", json!({"changes": [env_set("EMPTY_ONE", "")]}))
        .await;
    assert_eq!(request["state"], "succeeded", "{request} {operation}");

    // A port can be cleared; a command check is shown but not edited.
    rig.coolify
        .lock()
        .unwrap()
        .health
        .insert("health_check_port".to_owned(), json!(8080));
    let (request, operation) = rig
        .file_approve_run(APP, "health", json!({"clear": ["port"]}))
        .await;
    assert_eq!(request["state"], "succeeded", "{request} {operation}");
    assert!(rig.coolify.lock().unwrap().health["health_check_port"].is_null());
    rig.coolify
        .lock()
        .unwrap()
        .health
        .insert("health_check_type".to_owned(), json!("cmd"));
    let (status, answer) = rig.post(APP, "health", json!({"retries": 3})).await;
    assert_eq!(status, 400, "{answer}");
    assert!(
        answer["message"]
            .as_str()
            .unwrap()
            .contains("command health check")
    );
}

#[tokio::test]
async fn a_coolify_failure_never_quotes_the_value() {
    let rig = Rig::new().await;
    rig.coolify.lock().unwrap().quote_value_on_error = true;
    let (request, operation) = rig
        .file_approve_run(APP, "env", json!({"changes": [env_set("API_URL", SECRET)]}))
        .await;
    assert_eq!(request["state"], "failed", "{request} {operation}");
    let failure = operation.to_string();
    assert!(failure.contains("422"), "{failure}");
    assert!(!failure.contains(SECRET));
    assert_eq!(rig.held_records().await, 0);
    rig.assert_nothing_stored().await;
}

#[tokio::test]
async fn a_retry_with_the_same_key_returns_the_same_request_and_holds_one_value() {
    let rig = Rig::new().await;
    let body = json!({"changes": [env_set("API_URL", SECRET)], "idempotencyKey": "k-1"});
    let (status, first) = rig.post(APP, "env", body.clone()).await;
    assert_eq!(status, 201, "{first}");
    let (status, again) = rig.post(APP, "env", body).await;
    assert_eq!(status, 201, "{again}");
    assert_eq!(first["data"]["id"], again["data"]["id"]);
    assert_eq!(rig.held_records().await, 1);
    // The same key with another value is a different request.
    let (status, conflict) = rig
        .post(
            APP,
            "env",
            json!({"changes": [env_set("API_URL", SECRET_TWO)], "idempotencyKey": "k-1"}),
        )
        .await;
    assert_eq!(status, 409, "{conflict}");
    assert_eq!(rig.held_records().await, 1);
}

#[tokio::test]
async fn domains_are_previewed_applied_verified_and_a_stale_preview_is_refused() {
    let rig = Rig::new().await;
    let (status, filed) = rig
        .post(
            APP,
            "domains",
            json!({"domains": ["https://Shop.Example.test", "https://www.example.test"]}),
        )
        .await;
    assert_eq!(status, 201, "{filed}");
    let preview = &filed["data"]["parameters"]["preview"];
    assert_eq!(preview["before"], json!(["https://shop.example.test"]));
    assert_eq!(
        preview["after"],
        json!(["https://shop.example.test", "https://www.example.test"])
    );
    assert_eq!(preview["changes"][0]["field"], "domains");
    assert_eq!(filed["data"]["actionId"], "coolify.application.domains.set");
    let id = filed["data"]["id"].as_str().unwrap().to_owned();
    // Someone changes the domains in Coolify before the approval.
    rig.coolify.lock().unwrap().fqdn = "https://other.example.test".to_owned();
    rig.approve(&id).await;
    let (request, operation) = rig.run(&id).await;
    assert_eq!(request["state"], "failed", "{request}");
    assert!(operation.to_string().contains("stale"), "{operation}");
    assert_eq!(
        rig.coolify.lock().unwrap().fqdn,
        "https://other.example.test"
    );
    assert!(rig.requests_to("PATCH").is_empty());

    // Back to what the preview saw: it applies and reads back.
    rig.coolify.lock().unwrap().fqdn = "https://shop.example.test".to_owned();
    let (request, operation) = rig
        .file_approve_run(
            APP,
            "domains",
            json!({"domains": ["https://shop.example.test", "https://www.example.test"], "redeploy": true}),
        )
        .await;
    assert_eq!(request["state"], "succeeded", "{request} {operation}");
    let result = result_of(&operation);
    assert_eq!(result["outcome"], "applied");
    assert_eq!(result["changed"], json!(["domains"]));
    assert_eq!(result["followUp"]["verb"], "redeploy");
    assert_eq!(
        rig.coolify.lock().unwrap().fqdn,
        "https://shop.example.test,https://www.example.test"
    );
    // No force override is ever sent.
    assert!(
        rig.coolify
            .lock()
            .unwrap()
            .bodies
            .iter()
            .all(|(_, body)| !body.contains("force_domain_override"))
    );

    // Refusals: nothing to change, a bad URL, a Compose app, a service.
    for (uuid, domains) in [
        (
            APP,
            json!(["https://shop.example.test", "https://www.example.test"]),
        ),
        (APP, json!(["not a url"])),
        (APP, json!(["https://user:pw@example.test"])),
        (COMPOSE, json!(["https://stack.example.test"])),
        (SVC, json!(["https://svc.example.test"])),
    ] {
        let (status, answer) = rig.post(uuid, "domains", json!({"domains": domains})).await;
        assert_eq!(status, 400, "{answer}");
    }
}

#[tokio::test]
async fn the_health_check_is_previewed_and_applied_field_by_field() {
    let rig = Rig::new().await;
    let (status, filed) = rig
        .post(
            APP,
            "health",
            json!({"enabled": true, "path": "/healthz", "interval": 30}),
        )
        .await;
    assert_eq!(status, 201, "{filed}");
    let preview = &filed["data"]["parameters"]["preview"];
    assert_eq!(preview["before"]["enabled"], false);
    assert_eq!(preview["after"]["enabled"], true);
    assert_eq!(preview["after"]["path"], "/healthz");
    let fields: Vec<&str> = preview["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["field"].as_str().unwrap())
        .collect();
    assert_eq!(fields, ["enabled", "interval", "path"]);
    let id = filed["data"]["id"].as_str().unwrap().to_owned();
    rig.approve(&id).await;
    let (request, operation) = rig.run(&id).await;
    assert_eq!(request["state"], "succeeded", "{request} {operation}");
    assert_eq!(
        result_of(&operation)["changed"],
        json!(["enabled", "interval", "path"])
    );
    {
        let state = rig.coolify.lock().unwrap();
        assert_eq!(state.health["health_check_path"], "/healthz");
        assert_eq!(state.health["health_check_interval"], 30);
        // Fields the request did not name are not sent.
        let body = state
            .bodies
            .iter()
            .find(|(line, _)| line.starts_with("PATCH"))
            .map(|(_, body)| body.clone())
            .unwrap();
        assert!(!body.contains("health_check_retries"), "{body}");
        assert!(!body.contains("instant_deploy"), "{body}");
    }
    for body in [
        json!({}),
        json!({"path": "healthz"}),
        json!({"method": "DELETE"}),
        json!({"retries": 0}),
        json!({"path": "/healthz"}),
    ] {
        let (status, answer) = rig.post(APP, "health", body.clone()).await;
        assert_eq!(status, 400, "{body}: {answer}");
    }
    let (status, answer) = rig.post(SVC, "health", json!({"retries": 3})).await;
    assert_eq!(status, 400, "{answer}");
}

#[tokio::test]
async fn an_unsupported_coolify_version_is_refused_before_any_write() {
    let rig = Rig::new().await;
    rig.coolify.lock().unwrap().version = "4.0.0-beta.400".to_owned();
    let (status, answer) = rig
        .post(APP, "env", json!({"changes": [env_set("X", SECRET)]}))
        .await;
    assert_eq!(status, 422, "{answer}");
    assert_eq!(rig.held_records().await, 0);
    assert!(rig.requests_to("").iter().all(|l| l.starts_with("GET")));
}
