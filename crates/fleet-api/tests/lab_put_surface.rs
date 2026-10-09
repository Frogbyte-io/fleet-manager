//! #393: the `POST /lab/leases/{id}/files` route. The body is streamed into
//! staging with the cap enforced while streaming (no whole-body buffering,
//! and no framework body limit in the way of a multi-MiB upload);
//! authorization and the lease checks run before any byte is read; the
//! declared digest is checked against what arrived. Real SQLite repositories
//! behind the real router.

use std::io::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::lab::{
    ImagePinValidator, Lab, LabTemplate, LabTemplatePort, LabTemplateVersion, LeasePort,
    NewLabTemplate, NewLease, NewProvision, ProvisionPort,
};
use fleet_application::lab_artifacts::BlobError;
use fleet_application::lab_put::{LabPuts, StagedUpload, UploadStagePort, UploadWriter};
use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::operation::Operations;
use fleet_core::{CleanupStrategy, LabTemplateContent, LeaseState, ReadinessProbe};
use fleet_storage_sqlite::{
    AuditSink, LabRepository, LeaseRepository, MachineRepository, OperationRepository,
    ProjectRepository, Store,
};
use tower::ServiceExt as _;

const CAP: u64 = 8 * 1024 * 1024;

#[derive(Debug)]
struct Permit;
impl Authorizer for Permit {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

/// Denies one permission, allows the rest.
#[derive(Debug)]
struct Without(Permission);
impl Authorizer for Without {
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
#[async_trait]
impl ImagePinValidator for NoPins {
    async fn promoted_version(
        &self,
        _version_id: &str,
    ) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok(None)
    }
}

/// A disk staging area that counts what it accepted.
#[derive(Debug)]
struct Stage {
    dir: std::path::PathBuf,
    begun: AtomicUsize,
}

struct Writer {
    file: Option<std::fs::File>,
    path: std::path::PathBuf,
    id: String,
    size: u64,
    hasher: sha2::Sha256,
    keep: bool,
}

#[async_trait]
impl UploadWriter for Writer {
    async fn write(&mut self, chunk: &[u8]) -> Result<(), BlobError> {
        use sha2::Digest as _;
        if self.size + chunk.len() as u64 > CAP {
            return Err(BlobError::TooLarge { max_bytes: CAP });
        }
        self.hasher.update(chunk);
        self.file
            .as_mut()
            .unwrap()
            .write_all(chunk)
            .map_err(|e| BlobError::Io(e.to_string()))?;
        self.size += chunk.len() as u64;
        Ok(())
    }
    async fn finish(mut self: Box<Self>) -> Result<StagedUpload, BlobError> {
        use sha2::Digest as _;
        self.keep = true;
        Ok(StagedUpload {
            id: self.id.clone(),
            size_bytes: self.size,
            sha256: self
                .hasher
                .clone()
                .finalize()
                .iter()
                .fold(String::new(), |mut text, byte| {
                    use std::fmt::Write as _;
                    let _ = write!(text, "{byte:02x}");
                    text
                }),
        })
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if !self.keep {
            drop(self.file.take());
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[async_trait]
impl UploadStagePort for Stage {
    fn max_bytes(&self) -> u64 {
        CAP
    }
    async fn begin(&self) -> Result<Box<dyn UploadWriter>, BlobError> {
        use sha2::Digest as _;
        let n = self.begun.fetch_add(1, Ordering::SeqCst);
        let id = format!("upload-{n}");
        let path = self.dir.join(&id);
        Ok(Box::new(Writer {
            file: Some(std::fs::File::create(&path).unwrap()),
            path,
            id,
            size: 0,
            hasher: sha2::Sha256::new(),
            keep: false,
        }))
    }
    async fn discard(&self, id: &str) {
        let _ = std::fs::remove_file(self.dir.join(id));
    }
}

/// The real audit sink, keeping each intent's metadata as text.
#[derive(Debug)]
struct Recorder {
    inner: AuditSink,
    events: Mutex<Vec<String>>,
}

#[async_trait]
impl fleet_application::operation::AuditPort for Recorder {
    async fn record_intent(
        &self,
        intent: &fleet_application::audit::AuditIntent,
    ) -> Result<(), String> {
        let text = intent
            .metadata
            .entries()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ");
        self.events.lock().unwrap().push(text);
        self.inner.record_intent(intent).await
    }
    async fn record_outcome(
        &self,
        operation_id: &str,
        outcome: fleet_application::audit::AuditOutcome,
    ) -> Result<(), String> {
        self.inner.record_outcome(operation_id, outcome).await
    }
}

struct World {
    _dir: tempfile::TempDir,
    audit: Arc<Recorder>,
    stage: Arc<Stage>,
    leases: Arc<LeaseRepository>,
    lab: Arc<Lab>,
    operations: Arc<Operations>,
    lease_id: String,
}

impl World {
    #[allow(clippy::too_many_lines)]
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        let now = fleet_core::SystemClock::now_unix_millis();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let leases = Arc::new(LeaseRepository::new(pool.clone()));
        let content = LabTemplateContent {
            name: "lab-base".to_owned(),
            description: String::new(),
            image_version_id: "image-version-1".to_owned(),
            cores: 2,
            memory_mib: 2048,
            disk_gib: 20,
            bootstrap_project_id: None,
            readiness_probe: ReadinessProbe::GuestAgent,
            readiness_command: None,
            ssh_user: "root".to_owned(),
            ssh_port: 22,
            ssh_trust_mode: "tofu".to_owned(),
            ssh_fingerprint: None,
            readiness_deadline_seconds: 0,
            ttl_seconds: 3_600,
            cleanup: CleanupStrategy::Destroy,
        };
        let template: LabTemplate = LabTemplatePort::create(
            labs.as_ref(),
            &NewLabTemplate {
                content: content.clone(),
            },
            now,
        )
        .await
        .unwrap();
        let version = labs
            .publish(
                &template.id,
                &LabTemplateVersion {
                    id: "template-version-1".to_owned(),
                    template_id: template.id.clone(),
                    name: content.name.clone(),
                    content,
                    image_digest: "sha256:abc".to_owned(),
                    published_by: "tester".to_owned(),
                    published_at: now,
                },
            )
            .await
            .unwrap();
        let machine = MachineRepository::new(pool.clone())
            .register(&RegisterMachine {
                name: "lab-guest".to_owned(),
                description: String::new(),
                endpoints: vec![NewEndpoint {
                    kind: fleet_core::EndpointKind::Ssh,
                    reference: "root@192.0.2.10:22".to_owned(),
                }],
                tags: vec!["lab".to_owned()],
                groups: vec![],
            })
            .await
            .unwrap();
        let lease = leases
            .create(
                &NewLease {
                    template_version_id: version.id.clone(),
                    purpose: "artifacts".to_owned(),
                    project_id: None,
                    cleanup: CleanupStrategy::Destroy,
                    ttl_seconds: 3_600,
                },
                "tester",
                now,
            )
            .await
            .unwrap();
        let mut record = ProvisionPort::create(
            labs.as_ref(),
            &NewProvision {
                template_version_id: version.id.clone(),
                lease_id: Some(lease.id.clone()),
                idempotency_key: None,
                readiness_deadline_at: None,
            },
            now,
        )
        .await
        .unwrap();
        leases
            .attach_provision(&lease.id, &record.id)
            .await
            .unwrap();
        record.machine_id = Some(machine.id.clone());
        record.endpoint_id = Some(machine.endpoints[0].id.clone());
        ProvisionPort::update(labs.as_ref(), &record).await.unwrap();
        let mut ready = leases.get(&lease.id).await.unwrap();
        ready.state = LeaseState::Ready;
        ready.ready_at = Some(now);
        ready.expires_at = Some(now + 3_600_000);
        leases.update(&ready).await.unwrap();

        let stage_dir = dir.path().join("uploads");
        std::fs::create_dir_all(&stage_dir).unwrap();
        let stage = Arc::new(Stage {
            dir: stage_dir,
            begun: AtomicUsize::new(0),
        });
        let audit = Arc::new(Recorder {
            inner: AuditSink::new(pool.clone()),
            events: Mutex::new(Vec::new()),
        });
        let puts = Arc::new(LabPuts::new(
            stage.clone(),
            leases.clone(),
            labs.clone(),
            audit.clone(),
        ));
        let lab = Lab::new(
            labs.clone(),
            labs.clone(),
            leases.clone(),
            Arc::new(NoPins),
            Arc::new(ProjectRepository::new(pool.clone())),
            audit.clone(),
        )
        .with_puts(puts);
        Self {
            operations: Arc::new(Operations::new(
                Arc::new(OperationRepository::new(pool.clone())),
                audit.clone(),
            )),
            lab: Arc::new(lab),
            lease_id: lease.id,
            stage,
            leases,
            audit,
            _dir: dir,
        }
    }

    fn state(&self, authorizer: Arc<dyn Authorizer>) -> Arc<ApiState> {
        Arc::new(ApiState {
            authorizer,
            operations: self.operations.clone(),
            lab: Some(self.lab.clone()),
            ..ApiState::for_document()
        })
    }

    fn staged(&self) -> usize {
        std::fs::read_dir(&self.stage.dir).unwrap().count()
    }

    fn audit(&self) -> Vec<String> {
        self.audit.events.lock().unwrap().clone()
    }
}

async fn put(
    state: &Arc<ApiState>,
    lease_id: &str,
    query: &str,
    extra_header: Option<(&str, String)>,
    body: Body,
) -> (StatusCode, serde_json::Value) {
    let router = router(state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }));
    let mut request = Request::builder()
        .method("POST")
        .uri(format!(
            "{API_BASE_PATH}/lab/leases/{lease_id}/files?{query}"
        ))
        .header("content-type", "application/octet-stream")
        .header(
            CORRELATION_ID_HEADER,
            "01900000-0000-7000-8000-000000000000",
        );
    if let Some((name, value)) = extra_header {
        request = request.header(name, value);
    }
    let response = router.oneshot(request.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn sha(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// A body of `chunks` chunks of `size` bytes each that counts how many were
/// pulled, so a test can see whether the route stopped reading.
fn counted(chunks: usize, size: usize, pulled: Arc<AtomicUsize>) -> Body {
    let stream = futures_util::stream::iter((0..chunks).map(move |_| {
        pulled.fetch_add(1, Ordering::SeqCst);
        Ok::<_, std::convert::Infallible>(axum::body::Bytes::from(vec![9_u8; size]))
    }));
    Body::from_stream(stream)
}

#[tokio::test]
async fn a_multi_mib_upload_streams_through_and_queues_a_put() {
    let world = World::new().await;
    let state = world.state(Arc::new(Permit));
    // 5 MiB: past axum's 2 MiB default body limit, under the cap.
    let bytes = vec![3_u8; 5 * 1024 * 1024];
    let (status, body) = put(
        &state,
        &world.lease_id,
        "path=/opt/qa/app.AppImage&overwrite=true",
        Some(("x-content-sha256", sha(&bytes))),
        Body::from(bytes.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["data"]["kind"], "lab.put");
    // The operation view never carries the payload; the staging file
    // holds the bytes, and the audit names size and digest only.
    assert!(body["data"].get("payloadJson").is_none());
    assert_eq!(world.staged(), 1);
    let staged_path = std::fs::read_dir(&world.stage.dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(std::fs::read(staged_path).unwrap(), bytes);
    let audit = world.audit();
    assert!(audit.iter().any(|e| e.contains("lab_put_requested")
        && e.contains(&sha(&bytes))
        && e.contains("guestPath=/opt/qa/app.AppImage")
        && e.contains("overwrite=true")
        && e.contains(&format!("sizeBytes={}", bytes.len()))));
}

#[tokio::test]
async fn an_oversized_upload_is_refused_with_413_and_reading_stops_early() {
    let world = World::new().await;
    let state = world.state(Arc::new(Permit));
    // 64 chunks of 1 MiB = 64 MiB against an 8 MiB cap.
    let pulled = Arc::new(AtomicUsize::new(0));
    let (status, body) = put(
        &state,
        &world.lease_id,
        "path=/opt/big.bin",
        None,
        counted(64, 1024 * 1024, pulled.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["code"], "payload_too_large");
    assert!(
        pulled.load(Ordering::SeqCst) <= 10,
        "the route kept reading after the cap: {} chunks",
        pulled.load(Ordering::SeqCst)
    );
    assert_eq!(world.staged(), 0, "the partial upload was not removed");

    // A declared Content-Length over the cap is refused without reading.
    let pulled = Arc::new(AtomicUsize::new(0));
    let router =
        router(world.state(Arc::new(Permit))).layer(axum::Extension(fleet_api::ActingPrincipal {
            id: "anonymous-lan-admin".to_owned(),
        }));
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "{API_BASE_PATH}/lab/leases/{}/files?path=/opt/big.bin",
            world.lease_id
        ))
        .header("content-length", (CAP + 1).to_string())
        .header(
            CORRELATION_ID_HEADER,
            "01900000-0000-7000-8000-000000000000",
        )
        .body(counted(1, 16, pulled.clone()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(pulled.load(Ordering::SeqCst), 0);
    assert_eq!(world.staged(), 0);
}

#[tokio::test]
async fn a_declared_digest_that_does_not_match_discards_the_upload() {
    let world = World::new().await;
    let state = world.state(Arc::new(Permit));
    let (status, _) = put(
        &state,
        &world.lease_id,
        "path=/opt/a.bin",
        Some(("x-content-sha256", sha(b"other"))),
        Body::from("abc"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(world.staged(), 0);
    let (status, _) = put(
        &state,
        &world.lease_id,
        "path=/opt/a.bin",
        Some(("x-content-sha256", "NOT-HEX".to_owned())),
        Body::from("abc"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(world.staged(), 0);
}

#[tokio::test]
async fn refusals_happen_before_any_byte_is_staged() {
    let world = World::new().await;
    // Denied.
    let denied = world.state(Arc::new(Without(Permission::LabPut)));
    let pulled = Arc::new(AtomicUsize::new(0));
    let (status, _) = put(
        &denied,
        &world.lease_id,
        "path=/opt/a.bin",
        None,
        counted(4, 1024, pulled.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(pulled.load(Ordering::SeqCst), 0);
    assert_eq!(world.stage.begun.load(Ordering::SeqCst), 0);

    let state = world.state(Arc::new(Permit));
    // Invalid paths.
    for query in [
        "path=relative",
        "path=/tmp/../etc/passwd",
        "path=/a//b",
        "path=%2Ftmp%2Fx%0Ay",
    ] {
        let (status, _) = put(&state, &world.lease_id, query, None, Body::from("x")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
    }
    // No such lease.
    let (status, _) = put(
        &state,
        "no-such-lease",
        "path=/opt/a.bin",
        None,
        Body::from("x"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A lease that is not ready.
    let mut lease = world.leases.get(&world.lease_id).await.unwrap();
    lease.state = LeaseState::Releasing;
    world.leases.update(&lease).await.unwrap();
    let (status, body) = put(
        &state,
        &world.lease_id,
        "path=/opt/a.bin",
        None,
        Body::from("x"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["message"].as_str().unwrap().contains("releasing"));
    assert_eq!(world.stage.begun.load(Ordering::SeqCst), 0);
    assert_eq!(world.staged(), 0);
}

#[tokio::test]
async fn a_replayed_idempotency_key_returns_the_first_operation_and_drops_the_copy() {
    let world = World::new().await;
    let state = world.state(Arc::new(Permit));
    let send = |bytes: &'static [u8]| {
        let state = state.clone();
        let lease = world.lease_id.clone();
        async move {
            let router = router(state).layer(axum::Extension(fleet_api::ActingPrincipal {
                id: "anonymous-lan-admin".to_owned(),
            }));
            let response = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "{API_BASE_PATH}/lab/leases/{lease}/files?path=/opt/a.bin"
                        ))
                        .header("idempotency-key", "k1")
                        .header(
                            CORRELATION_ID_HEADER,
                            "01900000-0000-7000-8000-000000000000",
                        )
                        .body(Body::from(bytes))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            )
        }
    };
    let (first_status, first) = send(b"abc").await;
    let (second_status, second) = send(b"abc").await;
    assert_eq!(first_status, StatusCode::ACCEPTED);
    assert_eq!(second_status, StatusCode::ACCEPTED);
    assert_eq!(first["data"]["id"], second["data"]["id"]);
    // Only the first upload's staging file remains.
    assert_eq!(world.staged(), 1);
}
