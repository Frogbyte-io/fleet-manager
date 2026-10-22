//! #493: the machine access HTTP surface over the real router, SQLite store,
//! secret store and artifact stores. The controller holds the key: a stored
//! key is answered with a reference only, no answer carries key text, a
//! principal without a permission is refused on every route, and an
//! oversized or mis-hashed upload is refused with nothing queued.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::lab::Lab;
use fleet_application::lab_artifacts::ArtifactPolicy;
use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::machine_access::{MachineAccess, MachineFilePort as _};
use fleet_application::operation::Operations;
use fleet_controller::lab_artifacts_store::FsArtifactStore;
use fleet_controller::lab_put_store::FsUploadStore;
use fleet_controller::machine_access::SecretBackedMachineKeys;
use fleet_core::EndpointKind;
use fleet_storage_sqlite::{
    AuditSink, EndpointAuthRepository, LabRepository, LeaseRepository, MachineFileRepository,
    MachineRepository, OperationRepository, ProjectRepository, Store,
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const KEY_BODY: &str = "b3BlbnNzaC1rZXktdjEAAAAAMARKERMARKERMARKERMARKERMARKER";
const MAX_BYTES: u64 = 1024;

fn key() -> String {
    format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{KEY_BODY}\n-----END OPENSSH PRIVATE KEY-----\n")
}

/// Denies exactly one permission.
#[derive(Debug)]
struct Deny(Permission);

impl Authorizer for Deny {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.action == self.0 {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

#[derive(Debug)]
struct NoPins;

#[async_trait::async_trait]
impl fleet_application::lab::ImagePinValidator for NoPins {
    async fn promoted_version(
        &self,
        _version_id: &str,
    ) -> Result<Option<fleet_application::images::RecipeVersion>, String> {
        Ok(None)
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    store: Store,
    state: Arc<ApiState>,
    machine_id: String,
    endpoint_id: String,
}

impl Harness {
    async fn new(authorizer: Arc<dyn Authorizer>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        let key_file = dir.path().join("master.key");
        std::fs::write(
            &key_file,
            "1 0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let secrets = Arc::new(fleet_secrets::SecretStore::open(pool.clone(), &key_file).unwrap());
        let artifacts = dir.path().join("artifacts");
        let uploads = Arc::new(FsUploadStore::open(&artifacts, MAX_BYTES).unwrap());
        let blobs = Arc::new(FsArtifactStore::open(&artifacts, MAX_BYTES).unwrap());
        let machines = Arc::new(MachineRepository::new(pool.clone()));
        let access = Arc::new(
            MachineAccess::new(
                machines.clone(),
                Arc::new(EndpointAuthRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )
            .with_keys(Arc::new(SecretBackedMachineKeys::new(secrets)))
            .with_uploads(uploads)
            .with_files(
                Arc::new(MachineFileRepository::new(pool.clone())),
                blobs,
                ArtifactPolicy {
                    retention_seconds: 3_600,
                    max_bytes: MAX_BYTES,
                },
            ),
        );
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let lab = Arc::new(
            Lab::new(
                labs.clone(),
                labs,
                Arc::new(LeaseRepository::new(pool.clone())),
                Arc::new(NoPins),
                Arc::new(ProjectRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )
            .with_machine_access(access),
        );
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            Arc::new(AuditSink::new(pool.clone())),
        ));
        let machine = machines
            .register(&RegisterMachine {
                name: "agent-box".to_owned(),
                description: String::new(),
                endpoints: vec![NewEndpoint {
                    kind: EndpointKind::Ssh,
                    reference: "agent@192.0.2.20:22".to_owned(),
                }],
                tags: vec![],
                groups: vec![],
            })
            .await
            .unwrap();
        let endpoint_id = machine.endpoints[0].id.clone();
        machines
            .confirm_fingerprint(&endpoint_id, "SHA256:fixture", 0)
            .await
            .unwrap();
        let state = Arc::new(ApiState {
            operations,
            authorizer,
            lab: Some(lab),
            ..ApiState::for_document()
        });
        Self {
            _dir: dir,
            store,
            state,
            machine_id: machine.id,
            endpoint_id,
        }
    }

    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let builder = Request::builder().method(method).uri(path);
        let request = match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        };
        self.send(request.unwrap()).await
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let (mut parts, body) = request.into_parts();
        parts.uri = format!("{API_BASE_PATH}{}", parts.uri).parse().unwrap();
        parts.headers.insert(
            CORRELATION_ID_HEADER,
            "01900000-0000-7000-8000-000000000000".parse().unwrap(),
        );
        let app = router(self.state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
            id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        }));
        let response = app.oneshot(Request::from_parts(parts, body)).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes).to_string();
        assert!(
            !text.contains(KEY_BODY),
            "the key reached an answer: {text}"
        );
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    async fn store_key(&self) -> String {
        let (status, body) = self
            .call(
                "POST",
                "/machine-ssh-keys",
                Some(json!({ "privateKey": key() })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["data"]["credentialRef"].as_str().unwrap().to_owned()
    }

    async fn audit(&self) -> String {
        sqlx::query_scalar::<_, String>(
            "SELECT coalesce(group_concat(action || ' ' || metadata_json, char(10)), '') FROM audit_events",
        )
        .fetch_one(self.store.pool())
        .await
        .unwrap()
    }
}

#[tokio::test]
async fn a_stored_key_is_answered_with_a_reference_and_becomes_the_endpoints_default() {
    let harness = Harness::new(Arc::new(fleet_auth::LanAllowAllAuthorizer)).await;
    let reference = harness.store_key().await;

    // Only an unencrypted private key is accepted.
    let (status, _) = harness
        .call(
            "POST",
            "/machine-ssh-keys",
            Some(json!({ "privateKey": "ghp_notakey" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let path = format!(
        "/machines/{}/endpoints/{}/auth",
        harness.machine_id, harness.endpoint_id
    );
    let (status, body) = harness.call("GET", &path, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["auth"], Value::Null);

    let (status, body) = harness
        .call(
            "PUT",
            &path,
            Some(json!({ "auth": { "type": "secret", "credential": reference } })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["auth"]["credential"], reference);

    // A reference that names nothing is refused.
    let (status, _) = harness
        .call(
            "PUT",
            &path,
            Some(json!({ "auth": { "type": "secret", "credential": "nope" } })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = harness.call("DELETE", &path, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["auth"], Value::Null);

    let audit = harness.audit().await;
    assert!(audit.contains("machine_ssh_key_stored"), "{audit}");
    assert!(audit.contains("machine_endpoint_auth_set"), "{audit}");
    assert!(!audit.contains(KEY_BODY), "{audit}");
}

#[tokio::test]
async fn exec_queues_a_machine_exec_operation_with_the_reference_and_not_the_key() {
    let harness = Harness::new(Arc::new(fleet_auth::LanAllowAllAuthorizer)).await;
    let reference = harness.store_key().await;
    let exec = format!("/machines/{}/exec", harness.machine_id);

    // No default and no explicit auth: refused, nothing queued.
    let (status, body) = harness
        .call("POST", &exec, Some(json!({ "command": ["uname", "-a"] })))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, body) = harness
        .call(
            "POST",
            &exec,
            Some(json!({
                "command": ["uname", "-a"],
                "timeoutSeconds": 30,
                "auth": { "type": "secret", "credential": reference },
            })),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["data"]["kind"], "machine.exec");
    let text = body.to_string();
    assert!(!text.contains(KEY_BODY));

    // Exactly one of command and script.
    for bad in [
        json!({ "auth": { "type": "agent" } }),
        json!({ "auth": { "type": "agent" }, "command": ["a"], "script": "b" }),
        json!({ "auth": { "type": "agent" }, "command": [] }),
        json!({ "auth": { "type": "agent" }, "command": ["a"], "timeoutSeconds": 100000 }),
        json!({ "auth": { "type": "agent" }, "command": ["a"], "guestOs": "plan9" }),
        json!({ "auth": { "type": "agent" }, "command": ["a"], "endpointId": "nope" }),
    ] {
        let (status, body) = harness.call("POST", &exec, Some(bad.clone())).await;
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
            "{bad}: {status} {body}"
        );
    }

    // The queued payload names the reference and the command's digest only.
    let payload: String = sqlx::query_scalar(
        "SELECT payload_json FROM operations WHERE kind = 'machine.exec' LIMIT 1",
    )
    .fetch_one(harness.store.pool())
    .await
    .unwrap();
    assert!(payload.contains(&reference), "{payload}");
    assert!(payload.contains("commandSha256"), "{payload}");
    assert!(!payload.contains(KEY_BODY), "{payload}");
    let audit = harness.audit().await;
    assert!(audit.contains("machine_exec_requested"), "{audit}");
    assert!(
        !audit.contains("uname"),
        "the command reached the audit: {audit}"
    );
}

#[tokio::test]
async fn a_principal_without_the_permission_is_refused_on_every_route() {
    for (denied, method, path, body) in [
        (
            Permission::MachineExec,
            "POST",
            "/machines/{m}/exec",
            Some(json!({ "command": ["id"], "auth": { "type": "agent" } })),
        ),
        (
            Permission::MachineCollect,
            "POST",
            "/machines/{m}/collect",
            Some(json!({ "paths": ["/etc/hostname"], "auth": { "type": "agent" } })),
        ),
        (
            Permission::MachineCollect,
            "GET",
            "/machines/{m}/files",
            None,
        ),
        (
            Permission::MachineCollect,
            "GET",
            "/machine-files/{f}",
            None,
        ),
        (
            Permission::MachineCollect,
            "GET",
            "/machine-files/{f}/content",
            None,
        ),
        (
            Permission::MachineUpdate,
            "PUT",
            "/machines/{m}/endpoints/{e}/auth",
            Some(json!({ "auth": { "type": "agent" } })),
        ),
        (
            Permission::MachineUpdate,
            "DELETE",
            "/machines/{m}/endpoints/{e}/auth",
            None,
        ),
        (
            Permission::SecretWrite,
            "POST",
            "/machine-ssh-keys",
            Some(json!({ "privateKey": key() })),
        ),
    ] {
        let harness = Harness::new(Arc::new(Deny(denied))).await;
        // A collected file to ask for (its bytes are never reached: the
        // refusal comes first).
        let sha = "a".repeat(64);
        let file = MachineFileRepository::new(harness.store.pool().clone())
            .insert(&fleet_application::machine_access::NewMachineFile {
                machine_id: harness.machine_id.clone(),
                owner: "tester".to_owned(),
                name: "/etc/hostname".to_owned(),
                blob: fleet_application::lab_artifacts::StoredBlob {
                    location: format!("sha256/aa/{sha}"),
                    size_bytes: 3,
                    sha256: sha,
                },
                operation_id: None,
                created_at: 0,
                retain_until: i64::MAX,
            })
            .await
            .unwrap();
        let path = path
            .replace("{m}", &harness.machine_id)
            .replace("{e}", &harness.endpoint_id)
            .replace("{f}", &file.id);
        let (status, response) = harness.call(method, &path, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{denied} on {method} {path}: {response}"
        );
    }
    // The put route refuses before reading a byte.
    let harness = Harness::new(Arc::new(Deny(Permission::MachinePut))).await;
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "/machines/{}/files?path=/tmp/x&authType=agent",
            harness.machine_id
        ))
        .header("content-type", "application/octet-stream")
        .body(Body::from("never read"))
        .unwrap();
    let (status, _) = harness.send(request).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_upload_over_the_cap_or_with_the_wrong_digest_is_refused_and_nothing_is_queued() {
    let harness = Harness::new(Arc::new(fleet_auth::LanAllowAllAuthorizer)).await;
    let put = |body: Vec<u8>, sha: Option<&str>| {
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!(
                "/machines/{}/files?path=/tmp/agent-file&authType=agent",
                harness.machine_id
            ))
            .header("content-type", "application/octet-stream");
        if let Some(sha) = sha {
            builder = builder.header("x-content-sha256", sha);
        }
        builder.body(Body::from(body)).unwrap()
    };
    let (status, _) = harness
        .send(put(vec![b'a'; (MAX_BYTES + 1) as usize], None))
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (status, _) = harness
        .send(put(b"hello".to_vec(), Some(&"0".repeat(64))))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = harness.send(put(b"hello".to_vec(), None)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["data"]["kind"], "machine.put");
    let queued: i64 =
        sqlx::query_scalar("SELECT count(*) FROM operations WHERE kind = 'machine.put'")
            .fetch_one(harness.store.pool())
            .await
            .unwrap();
    assert_eq!(queued, 1);
}

#[tokio::test]
async fn post_operations_refuses_a_stored_key_auth_and_the_machine_kinds() {
    let harness = Harness::new(Arc::new(fleet_auth::LanAllowAllAuthorizer)).await;
    let reference = harness.store_key().await;
    let payload = json!({
        "machineId": harness.machine_id,
        "endpointId": harness.endpoint_id,
        "script": "id",
        "timeoutSeconds": 10,
        "auth": { "type": "secret", "credential": reference },
    })
    .to_string();
    for kind in ["ssh.exec", "machine.exec", "machine.put", "machine.collect"] {
        let (status, body) = harness
            .call(
                "POST",
                "/operations",
                Some(json!({ "kind": kind, "payloadJson": payload })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{kind}: {body}");
    }
    let queued: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM operations WHERE kind IN ('ssh.exec', 'machine.exec', 'machine.put', 'machine.collect')",
    )
    .fetch_one(harness.store.pool())
    .await
    .unwrap();
    assert_eq!(queued, 0);
}
