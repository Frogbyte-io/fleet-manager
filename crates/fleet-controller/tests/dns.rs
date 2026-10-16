//! FM-1042: DNS reads and brokered record changes end to end. A real API
//! router, SQLite store, secret store, action broker, and DNS executor run
//! against a stateful local stub that speaks Cloudflare's documented API
//! (payload shapes adapted from its public examples; no live token was used).
//!
//! The token must never appear in any API answer, in the audit ledger, or in
//! an operation's payload or result.

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::broker::{ActionRegistry, Broker, BrokerSettings};
use fleet_application::dns::Dns;
use fleet_application::operation::Operations;
use fleet_controller::dns_exec::{DnsExecutor, compose_dns};
use fleet_controller::source::SourceExecutor;
use fleet_secrets::SecretStore;
use fleet_storage_sqlite::{
    ActionRequestRepository, DnsObservationRepository, OperationRepository, Store,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tower::ServiceExt as _;

const TOKEN: &str = "cf-end-to-end-dns-token-0001";
const ZONE_ID: &str = "023e105f4ecef8ad9ca31a8372d0c353";

// ---------------------------------------------------------------------
// A stateful Cloudflare stub.
// ---------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Rec {
    id: String,
    record_type: String,
    name: String,
    content: String,
    ttl: u64,
    proxied: bool,
    priority: Option<u64>,
}

impl Rec {
    fn json(&self) -> Value {
        let mut value = json!({
            "id": self.id,
            "zone_id": ZONE_ID,
            "zone_name": "example.com",
            "type": self.record_type,
            "name": self.name,
            "content": self.content,
            "ttl": self.ttl,
            "proxied": self.proxied,
            "proxiable": true,
        });
        if let Some(priority) = self.priority {
            value["priority"] = json!(priority);
        }
        value
    }
}

#[derive(Default)]
struct Cloud {
    records: Vec<Rec>,
    next: u32,
    log: Vec<String>,
}

type Shared = Arc<Mutex<Cloud>>;

fn rec(id: &str, record_type: &str, name: &str, content: &str, ttl: u64) -> Rec {
    Rec {
        id: id.to_owned(),
        record_type: record_type.to_owned(),
        name: name.to_owned(),
        content: content.to_owned(),
        ttl,
        proxied: false,
        priority: None,
    }
}

fn envelope(result: &Value) -> String {
    json!({
        "success": true, "errors": [], "messages": [], "result": result,
        "result_info": {"page": 1, "per_page": 100, "count": 1, "total_count": 1, "total_pages": 1}
    })
    .to_string()
}

fn error_body(code: u32, message: &str) -> String {
    json!({"success": false, "errors": [{"code": code, "message": message}], "messages": [], "result": null})
        .to_string()
}

fn query_of(target: &str) -> Vec<(String, String)> {
    target
        .split_once('?')
        .map(|(_, query)| {
            query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

fn handle(cloud: &mut Cloud, method: &str, target: &str, body: &str) -> (u16, String) {
    let path = target.split('?').next().unwrap_or_default();
    let path = path.strip_prefix("/client/v4").unwrap_or(path);
    cloud.log.push(format!("{method} {path}"));
    let query = query_of(target);
    let filter = |key: &str| query.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match (method, segments.as_slice()) {
        ("GET", ["zones"]) => {
            let zones = json!([{"id": ZONE_ID, "name": "example.com", "status": "active"}]);
            let wanted = filter("name");
            let list = match wanted.as_deref() {
                Some("example.com") | None => zones,
                Some(_) => json!([]),
            };
            (200, envelope(&list))
        }
        ("GET", ["zones", ZONE_ID, "dns_records"]) => {
            let list: Vec<Value> = cloud
                .records
                .iter()
                .filter(|r| filter("name").is_none_or(|name| name == r.name))
                .filter(|r| filter("type").is_none_or(|kind| kind == r.record_type))
                .map(Rec::json)
                .collect();
            (200, envelope(&Value::Array(list)))
        }
        ("POST", ["zones", ZONE_ID, "dns_records"]) => {
            let input: Value = serde_json::from_str(body).unwrap_or_default();
            let new = Rec {
                id: format!("rec{}", cloud.next),
                record_type: input["type"].as_str().unwrap_or_default().to_owned(),
                name: input["name"].as_str().unwrap_or_default().to_owned(),
                content: input["content"].as_str().unwrap_or_default().to_owned(),
                ttl: input["ttl"].as_u64().unwrap_or(1),
                proxied: input["proxied"].as_bool().unwrap_or(false),
                priority: input["priority"].as_u64(),
            };
            if cloud.records.iter().any(|r| {
                r.record_type == new.record_type && r.name == new.name && r.content == new.content
            }) {
                return (
                    400,
                    error_body(81058, "An identical record already exists."),
                );
            }
            cloud.next += 1;
            let answer = envelope(&new.json());
            cloud.records.push(new);
            (200, answer)
        }
        ("PUT", ["zones", ZONE_ID, "dns_records", id]) => {
            let input: Value = serde_json::from_str(body).unwrap_or_default();
            let Some(existing) = cloud.records.iter_mut().find(|r| r.id == *id) else {
                return (404, error_body(81044, "Record does not exist."));
            };
            existing.content = input["content"].as_str().unwrap_or_default().to_owned();
            existing.ttl = input["ttl"].as_u64().unwrap_or(1);
            existing.proxied = input["proxied"].as_bool().unwrap_or(false);
            existing.priority = input["priority"].as_u64();
            (200, envelope(&existing.json()))
        }
        ("DELETE", ["zones", ZONE_ID, "dns_records", id]) => {
            let before = cloud.records.len();
            cloud.records.retain(|r| r.id != *id);
            if cloud.records.len() == before {
                (404, error_body(81044, "Record does not exist."))
            } else {
                (200, envelope(&json!({"id": id})))
            }
        }
        _ => (404, error_body(7003, "No route")),
    }
}

async fn stub_cloudflare(cloud: Shared) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/client/v4", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let cloud = cloud.clone();
            tokio::spawn(async move {
                let mut data = Vec::new();
                let mut buffer = vec![0_u8; 8192];
                let (head, start) = loop {
                    let read = socket.read(&mut buffer).await.unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    data.extend_from_slice(&buffer[..read]);
                    if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        break (String::from_utf8_lossy(&data[..at]).to_string(), at + 4);
                    }
                };
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while data.len() < start + length {
                    let read = socket.read(&mut buffer).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    data.extend_from_slice(&buffer[..read]);
                }
                let body = String::from_utf8_lossy(&data[start..]).to_string();
                let mut first = head.lines().next().unwrap_or_default().split_whitespace();
                let method = first.next().unwrap_or_default().to_owned();
                let target = first.next().unwrap_or_default().to_owned();
                let (status, answer) = if head.contains(&format!("Bearer {TOKEN}")) {
                    handle(&mut cloud.lock().unwrap(), &method, &target, &body)
                } else {
                    (401, error_body(10000, "Authentication error"))
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

// ---------------------------------------------------------------------
// The harness.
// ---------------------------------------------------------------------

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.test"])
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

const DOMAIN_ENTRY: &str = "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryEntry\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58d201\n  name: domain-example-com\nspec:\n  type: domain\n  fields: { fqdn: example.com, dnsHost: Cloudflare }\n";

struct Harness {
    _dir: tempfile::TempDir,
    store: Store,
    state: Arc<ApiState>,
    operations: Arc<Operations>,
    dns: Arc<Dns>,
    accounts: Arc<fleet_application::external_accounts::ExternalAccounts>,
    source: SourceExecutor,
    cloud: Shared,
    base_url: String,
}

impl Harness {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let key_path = dir.path().join("master.key");
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
        let accounts = fleet_controller::external_accounts_store::compose_external_accounts(
            store.pool(),
            secrets.clone(),
        );
        let dns = compose_dns(store.pool(), secrets);
        let operations = Arc::new(
            Operations::new(
                Arc::new(OperationRepository::new(store.pool().clone())),
                Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
            )
            .with_brokered_kinds(fleet_controller::brokered_operation_kinds()),
        );
        let mut registry = ActionRegistry::new();
        for action in fleet_application::dns::dns_actions() {
            registry.register(action).unwrap();
        }
        let broker = Broker::new(
            Arc::new(ActionRequestRepository::new(store.pool().clone())),
            Arc::new(registry),
            operations.clone(),
            BrokerSettings::default(),
        );
        let desired = Arc::new(fleet_controller::compose_desired_source(store.pool()));
        let state = Arc::new(ApiState {
            operations: operations.clone(),
            desired: Some(desired.clone()),
            requests: Some(Arc::new(broker)),
            authorizer: Arc::new(fleet_auth::LanAllowAllAuthorizer),
            ..ApiState::for_document()
        });
        let cloud: Shared = Arc::new(Mutex::new(Cloud {
            records: vec![
                rec("rec-www-1", "A", "www.example.com", "203.0.113.1", 300),
                rec("rec-www-2", "A", "www.example.com", "203.0.113.2", 300),
                rec("rec-txt", "TXT", "example.com", "v=spf1 -all", 1),
            ],
            next: 100,
            log: Vec::new(),
        }));
        let base_url = stub_cloudflare(cloud.clone()).await;
        let harness = Self {
            source: SourceExecutor::new(dir.path().join("git-source"), desired),
            _dir: dir,
            store,
            state,
            operations,
            dns,
            accounts,
            cloud,
            base_url,
        };
        let (status, body) = harness
            .call(
                "POST",
                "/external-accounts",
                Some(json!({
                    "kind": "cloudflare", "label": "dns",
                    "baseUrl": harness.base_url, "token": TOKEN
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        harness
    }

    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let app = router(self.state.clone())
            .layer(axum::Extension(fleet_api::ActingPrincipal {
                id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
            }))
            .layer(axum::Extension(self.dns.clone()))
            .layer(axum::Extension(self.accounts.clone()));
        let builder = Request::builder()
            .method(method)
            .uri(format!("{API_BASE_PATH}{path}"))
            .header(
                CORRELATION_ID_HEADER,
                "01900000-0000-7000-8000-000000000000",
            );
        let request = match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        }
        .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes).to_string();
        assert!(!text.contains(TOKEN), "the token reached an answer: {text}");
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    /// Files a change and returns the request.
    async fn change(&self, body: Value) -> (StatusCode, Value) {
        self.call("POST", "/dns/changes", Some(body)).await
    }

    fn upsert(content: &str) -> Value {
        json!({
            "operation": "upsert", "name": "www.example.com", "type": "A",
            "content": content, "ttl": 600, "reason": "move www to the new host"
        })
    }

    /// Approves a request and runs its operation through the DNS executor.
    async fn approve_and_run(&self, id: &str) -> Value {
        let (status, approved) = self
            .call("POST", &format!("/requests/{id}/approve"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{approved}");
        assert_eq!(approved["data"]["state"], "executing", "{approved}");
        let operation_id = approved["data"]["operationId"].as_str().unwrap().to_owned();
        let executor = DnsExecutor::new(self.dns.clone());
        self.operations
            .claim_only_execute(&executor, &operation_id, "test-worker")
            .await
            .ok();
        let (_, request) = self.call("GET", &format!("/requests/{id}"), None).await;
        let (_, operation) = self
            .call("GET", &format!("/operations/{operation_id}"), None)
            .await;
        json!({"request": request["data"], "operation": operation["data"]})
    }

    /// Runs an accepted source operation through the source executor.
    async fn run_source(&self, accepted: &Value) -> String {
        let id = accepted["data"]["id"].as_str().unwrap().to_owned();
        self.operations
            .claim_only_execute(&self.source, &id, "w")
            .await
            .ok();
        id
    }

    fn record_count(&self, name: &str, record_type: &str) -> usize {
        self.cloud
            .lock()
            .unwrap()
            .records
            .iter()
            .filter(|r| r.name == name && r.record_type == record_type)
            .count()
    }

    fn writes(&self) -> usize {
        self.cloud
            .lock()
            .unwrap()
            .log
            .iter()
            .filter(|line| !line.starts_with("GET"))
            .count()
    }

    /// Everything the audit ledger and the operations table hold, as text.
    async fn stored_text(&self) -> String {
        use sqlx::Row as _;
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

// ---------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_change_is_previewed_approved_executed_and_verified() {
    let harness = Harness::new().await;

    // Reads: the zone is resolved from the name, records are normalized.
    let (status, body) = harness
        .call("GET", "/dns/records?name=WWW.example.com.&type=a", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["zone"]["name"], "example.com");
    assert_eq!(body["data"]["records"].as_array().unwrap().len(), 2);
    assert!(body["data"]["registryEntry"].is_null());
    let (status, zones) = harness.call("GET", "/dns/zones", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        zones["data"]["accounts"][0]["zones"][0]["name"],
        "example.com"
    );

    // The preview is computed now and stored in the request.
    let (status, filed) = harness
        .change(json!({
            "operation": "upsert", "name": "www.example.com", "type": "A",
            "content": "203.0.113.9", "ttl": 600, "replaces": "203.0.113.2",
            "reason": "move www to the new host"
        }))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{filed}");
    let request = &filed["data"];
    assert_eq!(request["actionId"], "dns.record.upsert");
    assert_eq!(request["riskClass"], "approve");
    assert_eq!(request["state"], "pending");
    assert_eq!(request["target"], "www.example.com A");
    let preview = &request["parameters"]["preview"];
    assert_eq!(preview["operation"], "update");
    assert_eq!(preview["before"]["content"], "203.0.113.2");
    assert_eq!(preview["before"]["ttl"], 300);
    assert_eq!(preview["after"]["content"], "203.0.113.9");
    assert_eq!(preview["after"]["ttl"], 600);
    assert!(request["parameters"]["accountId"].is_string());
    // Nothing was written before approval.
    assert_eq!(harness.writes(), 0);

    let done = harness
        .approve_and_run(request["id"].as_str().unwrap())
        .await;
    assert_eq!(done["request"]["state"], "succeeded", "{done}");
    assert_eq!(done["operation"]["state"], "succeeded", "{done}");
    let result: Value =
        serde_json::from_str(done["operation"]["resultJson"].as_str().unwrap()).unwrap();
    assert_eq!(result["outcome"], "updated");
    assert_eq!(result["verified"], true);
    assert_eq!(result["record"]["content"], "203.0.113.9");
    // One record replaced in place; the other value untouched.
    assert_eq!(harness.record_count("www.example.com", "A"), 2);
    {
        let cloud = harness.cloud.lock().unwrap();
        let updated = cloud.records.iter().find(|r| r.id == "rec-www-2").unwrap();
        assert_eq!(updated.content, "203.0.113.9");
        assert_eq!(updated.ttl, 600);
        // The write was a PUT, followed by a read for verification.
        assert!(
            cloud
                .log
                .iter()
                .any(|l| l == "PUT /zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records/rec-www-2")
        );
        assert!(cloud.log.last().unwrap().starts_with("GET"));
    }

    // A second value is added when nothing is replaced.
    let (_, filed) = harness.change(Harness::upsert("203.0.113.50")).await;
    assert_eq!(
        filed["data"]["parameters"]["preview"]["operation"],
        "create"
    );
    let done = harness
        .approve_and_run(filed["data"]["id"].as_str().unwrap())
        .await;
    assert_eq!(done["request"]["state"], "succeeded", "{done}");
    assert_eq!(harness.record_count("www.example.com", "A"), 3);

    // A delete is previewed, approved, executed, and verified.
    let (status, filed) = harness
        .change(json!({
            "operation": "delete", "name": "www.example.com", "type": "A",
            "content": "203.0.113.1", "reason": "retire the old host"
        }))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{filed}");
    assert_eq!(filed["data"]["actionId"], "dns.record.delete");
    assert_eq!(
        filed["data"]["parameters"]["preview"]["operation"],
        "delete"
    );
    let done = harness
        .approve_and_run(filed["data"]["id"].as_str().unwrap())
        .await;
    assert_eq!(done["request"]["state"], "succeeded", "{done}");
    assert_eq!(harness.record_count("www.example.com", "A"), 2);

    // The token is in no stored text: audit, operations, or requests.
    let stored = harness.stored_text().await;
    assert!(!stored.contains(TOKEN));
    assert!(stored.contains("dns.record.upsert"));
}

#[tokio::test]
async fn reads_are_recorded_as_observations_beside_the_matching_domain_entry() {
    let harness = Harness::new().await;
    let dir = harness._dir.path().to_path_buf();
    let repo = dir.join("desired");
    std::fs::create_dir_all(repo.join("fleet/registry/domain")).unwrap();
    git(&repo, &["init", "--quiet"]);
    std::fs::write(
        repo.join("fleet/registry/domain/example.com.yaml"),
        DOMAIN_ENTRY,
    )
    .unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "--quiet", "-m", "registry"]);
    let sha = git(&repo, &["rev-parse", "HEAD"]);
    harness
        .call(
            "PUT",
            "/desired/source",
            Some(json!({"remote": repo.to_str().unwrap()})),
        )
        .await;
    let (_, accepted) = harness
        .call("POST", "/desired/fetch", Some(json!({"commitSha": sha})))
        .await;
    let id = harness.run_source(&accepted).await;
    let (_, fetched) = harness
        .call("GET", &format!("/operations/{id}"), None)
        .await;
    assert_eq!(fetched["data"]["state"], "succeeded", "{fetched}");
    let result: Value =
        serde_json::from_str(fetched["data"]["resultJson"].as_str().unwrap()).unwrap();
    let digest = result["contentDigest"].as_str().unwrap().to_owned();
    let (_, accepted) = harness
        .call(
            "POST",
            "/desired/activate",
            Some(json!({"commitSha": sha, "contentDigest": digest})),
        )
        .await;
    let id = harness.run_source(&accepted).await;
    let (_, activated) = harness
        .call("GET", &format!("/operations/{id}"), None)
        .await;
    assert_eq!(activated["data"]["state"], "succeeded", "{activated}");

    let (status, body) = harness
        .call("GET", "/dns/records?name=www.example.com", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["registryEntry"], "domain/example.com");

    let seen = DnsObservationRepository::new(harness.store.pool().clone());
    let observed = fleet_application::dns::DnsObservationPort::for_name(&seen, "www.example.com")
        .await
        .unwrap();
    assert_eq!(observed.len(), 1);
    assert_eq!(
        observed[0].registry_entry.as_deref(),
        Some("domain/example.com")
    );
    assert_eq!(observed[0].records.len(), 2);

    // The entry itself is untouched: observations attach, never overwrite.
    let (_, entry) = harness
        .call("GET", "/registry/entries/domain/example.com", None)
        .await;
    assert_eq!(entry["data"]["fields"]["dnsHost"], "Cloudflare");
}

#[tokio::test]
async fn a_stale_preview_fails_without_overwriting() {
    let harness = Harness::new().await;
    let (_, filed) = harness
        .change(json!({
            "operation": "upsert", "name": "www.example.com", "type": "A",
            "content": "203.0.113.1", "ttl": 900, "reason": "slower refresh"
        }))
        .await;
    assert_eq!(
        filed["data"]["parameters"]["preview"]["operation"],
        "update"
    );
    // Someone changes the record between the request and the approval.
    {
        let mut cloud = harness.cloud.lock().unwrap();
        let changed = cloud
            .records
            .iter_mut()
            .find(|r| r.id == "rec-www-1")
            .unwrap();
        changed.ttl = 120;
    }
    let done = harness
        .approve_and_run(filed["data"]["id"].as_str().unwrap())
        .await;
    assert_eq!(done["operation"]["state"], "failed", "{done}");
    assert_eq!(done["request"]["state"], "failed", "{done}");
    let error = done["operation"]["errorJson"].as_str().unwrap();
    assert!(error.contains("stale preview"), "{error}");
    // Nothing was overwritten, and no write was attempted.
    assert_eq!(harness.writes(), 0);
    let cloud = harness.cloud.lock().unwrap();
    assert_eq!(
        cloud
            .records
            .iter()
            .find(|r| r.id == "rec-www-1")
            .unwrap()
            .ttl,
        120
    );
}

#[tokio::test]
async fn an_effect_already_in_place_is_an_idempotent_success() {
    let harness = Harness::new().await;
    // An upsert whose record appears before it executes: unchanged.
    let (_, filed) = harness.change(Harness::upsert("203.0.113.77")).await;
    assert_eq!(
        filed["data"]["parameters"]["preview"]["operation"],
        "create"
    );
    harness.cloud.lock().unwrap().records.push(rec(
        "rec-early",
        "A",
        "www.example.com",
        "203.0.113.77",
        600,
    ));
    let done = harness
        .approve_and_run(filed["data"]["id"].as_str().unwrap())
        .await;
    assert_eq!(done["request"]["state"], "succeeded", "{done}");
    let result: Value =
        serde_json::from_str(done["operation"]["resultJson"].as_str().unwrap()).unwrap();
    assert_eq!(result["outcome"], "unchanged");
    assert_eq!(harness.writes(), 0);
    assert_eq!(harness.record_count("www.example.com", "A"), 3);

    // A delete whose record is already gone: already_absent, no write.
    let (_, filed) = harness
        .change(json!({
            "operation": "delete", "name": "www.example.com", "type": "A",
            "content": "203.0.113.2", "reason": "cleanup"
        }))
        .await;
    harness
        .cloud
        .lock()
        .unwrap()
        .records
        .retain(|r| r.id != "rec-www-2");
    let done = harness
        .approve_and_run(filed["data"]["id"].as_str().unwrap())
        .await;
    assert_eq!(done["request"]["state"], "succeeded", "{done}");
    let result: Value =
        serde_json::from_str(done["operation"]["resultJson"].as_str().unwrap()).unwrap();
    assert_eq!(result["outcome"], "already_absent");
    assert_eq!(harness.writes(), 0);
}

#[tokio::test]
async fn invalid_and_credential_like_changes_are_refused_before_anything_is_stored() {
    let harness = Harness::new().await;
    let refused = [
        // A type outside the safe set.
        json!({"operation": "upsert", "name": "example.com", "type": "CAA", "content": "0 issue \"ca.example.net\"", "reason": "x"}),
        json!({"operation": "upsert", "name": "example.com", "type": "NS", "content": "ns.example.net", "reason": "x"}),
        // Values that do not fit their type.
        json!({"operation": "upsert", "name": "www.example.com", "type": "A", "content": "not-an-ip", "reason": "x"}),
        json!({"operation": "upsert", "name": "www.example.com", "type": "A", "content": "203.0.113.5", "ttl": 30, "reason": "x"}),
        json!({"operation": "upsert", "name": "www.example.com", "type": "A", "content": "203.0.113.5", "ttl": 300, "proxied": true, "reason": "x"}),
        json!({"operation": "upsert", "name": "mail.example.com", "type": "MX", "content": "mx.example.net", "reason": "x"}),
        // Nothing to change: the record already matches.
        json!({"operation": "upsert", "name": "www.example.com", "type": "A", "content": "203.0.113.1", "ttl": 300, "reason": "x"}),
        // A replace target that is not there.
        json!({"operation": "upsert", "name": "www.example.com", "type": "A", "content": "203.0.113.5", "replaces": "203.0.113.200", "reason": "x"}),
    ];
    for body in refused {
        let (status, answer) = harness.change(body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {answer}");
    }
    // A name outside every zone has no account to act through.
    let (status, _) = harness
        .change(json!({"operation": "upsert", "name": "www.example.org", "type": "A", "content": "203.0.113.5", "reason": "x"}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Deleting what is not there.
    let (status, _) = harness
        .change(json!({"operation": "delete", "name": "www.example.com", "type": "A", "content": "203.0.113.99", "reason": "x"}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A TXT value shaped like an API key is refused by the broker's
    // credential rule, like any other parameter.
    let (status, answer) = harness
        .change(json!({
            "operation": "upsert", "name": "example.com", "type": "TXT",
            "content": "api_key=Zx81QwErTy93LkJhGf62Mn40", "reason": "x"
        }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert!(answer["message"].as_str().unwrap().contains("credential"));
    let (status, answer) = harness
        .change(json!({
            "operation": "upsert", "name": "example.com", "type": "TXT",
            "content": "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "reason": "x"
        }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");

    // `mailto:user@host` is shaped like URL credentials, so a DMARC `rua`
    // is refused by the same rule (documented limitation).
    let (status, _) = harness
        .change(json!({
            "operation": "upsert", "name": "_dmarc.example.com", "type": "TXT",
            "content": "v=DMARC1; p=reject; rua=mailto:d@example.com", "reason": "x"
        }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Ordinary TXT policies and DKIM public keys are accepted.
    let dkim = format!(
        "v=DKIM1; k=rsa; p={}",
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA".repeat(4)
    );
    for content in [
        "v=spf1 include:_spf.example.net ~all",
        "v=DMARC1; p=reject; pct=100; adkim=s",
        dkim.as_str(),
    ] {
        let (status, answer) = harness
            .change(json!({
                "operation": "upsert", "name": "example.com", "type": "TXT",
                "content": content, "reason": "mail policy"
            }))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{content}: {answer}");
    }

    // Only the three accepted TXT requests exist; no write happened.
    let (_, listed) = harness.call("GET", "/requests", None).await;
    assert_eq!(listed["items"].as_array().unwrap().len(), 3);
    assert_eq!(harness.writes(), 0);
}

#[tokio::test]
async fn provider_failures_are_classified_at_the_api() {
    let harness = Harness::new().await;
    // Replace the token with one the provider refuses.
    let (_, accounts) = harness.call("GET", "/external-accounts", None).await;
    let id = accounts["items"][0]["id"].as_str().unwrap().to_owned();
    let (status, _) = harness
        .call(
            "PATCH",
            &format!("/external-accounts/{id}"),
            Some(json!({"token": "a-different-token-value-0002"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = harness
        .call("GET", "/dns/records?name=www.example.com", None)
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["code"], "dns_provider_auth");

    // The zones list reports the failure on the account, not as an error.
    let (status, zones) = harness.call("GET", "/dns/zones", None).await;
    assert_eq!(status, StatusCode::OK, "{zones}");
    assert_eq!(zones["data"]["accounts"][0]["failure"], "auth");

    // A name is required, and no account of another kind is ever used.
    let (status, _) = harness.call("GET", "/dns/records", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
