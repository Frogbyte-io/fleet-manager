//! #395: retry-safe `POST /lab/leases` (`Idempotency-Key`) and the
//! `GET /lab/leases` purpose, state, and owner filters. Real SQLite
//! repositories behind the real router; the replays run concurrently.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision};
use fleet_application::lab::{
    ImagePinValidator, Lab, LabTemplate, LabTemplatePort, LabTemplateVersion, LeaseFilter,
    LeasePort as _, NewLabTemplate,
};
use fleet_application::lab_pool::{FillResult, LabPoolPort as _, LabPools, NewLabPool};
use fleet_application::operation::{AuditPort, Operations};
use fleet_application::proxmox::{NewProxmoxAccount, ProxmoxAccountPort as _};
use fleet_core::{CleanupStrategy, LabTemplateContent, LeaseState, ReadinessProbe};
use fleet_storage_sqlite::{
    AuditSink, LabPoolRepository, LabRepository, LeaseRepository, OperationRepository,
    ProjectRepository, ProxmoxAccountRepository, Store,
};
use tower::ServiceExt as _;

const NOW: i64 = 1_700_000_000_000;
const VERSION: &str = "version-1";

#[derive(Debug)]
struct Permit;
impl Authorizer for Permit {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

#[derive(Debug)]
struct NoPins;
#[async_trait::async_trait]
impl ImagePinValidator for NoPins {
    async fn promoted_version(
        &self,
        _version_id: &str,
    ) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok(None)
    }
}

struct World {
    _dir: tempfile::TempDir,
    state: Arc<ApiState>,
    lab: Arc<Lab>,
    labs: Arc<LabRepository>,
    leases: Arc<LeaseRepository>,
    pools: Arc<LabPoolRepository>,
}

impl World {
    /// A published template version with a pool of two free members.
    #[allow(clippy::too_many_lines)]
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let content = LabTemplateContent {
            name: VERSION.to_owned(),
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
            readiness_deadline_seconds: 300,
            ttl_seconds: 3_600,
            cleanup: CleanupStrategy::Destroy,
        };
        let template: LabTemplate = LabTemplatePort::create(
            labs.as_ref(),
            &NewLabTemplate {
                content: content.clone(),
            },
            NOW,
        )
        .await
        .unwrap();
        labs.publish(
            &template.id,
            &LabTemplateVersion {
                id: VERSION.to_owned(),
                template_id: template.id.clone(),
                name: content.name.clone(),
                content,
                image_digest: "sha256:abc".to_owned(),
                published_by: "tester".to_owned(),
                published_at: NOW,
            },
        )
        .await
        .unwrap();
        let accounts = Arc::new(ProxmoxAccountRepository::new(pool.clone()));
        let account = accounts
            .create(&NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: "pve-api.example.test".to_owned(),
                port: None,
                token_id: "fleet@pve!lab".to_owned(),
            })
            .await
            .unwrap();
        let audit: Arc<dyn AuditPort> = Arc::new(AuditSink::new(pool.clone()));
        let leases = Arc::new(LeaseRepository::new(pool.clone()));
        let pools = Arc::new(LabPoolRepository::new(pool.clone()));
        let lab = Arc::new(
            Lab::new(
                labs.clone(),
                labs.clone(),
                leases.clone(),
                Arc::new(NoPins),
                Arc::new(ProjectRepository::new(pool.clone())),
                audit.clone(),
            )
            .with_pools(Arc::new(LabPools::new(
                pools.clone(),
                labs.clone(),
                accounts,
                audit.clone(),
            ))),
        );
        let pool_row = pools
            .create(
                &NewLabPool {
                    template_version_id: VERSION.to_owned(),
                    account_id: account.id,
                    baseline_snapshot: "baseline".to_owned(),
                    size: 2,
                },
                "tester",
                NOW,
            )
            .await
            .unwrap();
        for member in pools
            .add_members(&pool_row.id, &[101, 102], NOW)
            .await
            .unwrap()
        {
            pools
                .finish_fill(
                    &member.id,
                    &FillResult::Available {
                        node: "pve1".to_owned(),
                        name: format!("pool-{}", member.id),
                    },
                    NOW,
                )
                .await
                .unwrap();
        }
        let state = Arc::new(ApiState {
            authorizer: Arc::new(Permit),
            operations: Arc::new(Operations::new(
                Arc::new(OperationRepository::new(pool)),
                audit,
            )),
            lab: Some(lab.clone()),
            ..ApiState::for_document()
        });
        Self {
            _dir: dir,
            state,
            lab,
            labs,
            leases,
            pools,
        }
    }

    async fn call(
        &self,
        principal: &str,
        method: &str,
        path: &str,
        key: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        call(&self.state, principal, method, path, key, body).await
    }
}

async fn call(
    state: &Arc<ApiState>,
    principal: &str,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let router = router(state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
        id: principal.to_owned(),
    }));
    let mut request = Request::builder()
        .method(method)
        .uri(format!("{API_BASE_PATH}{path}"))
        .header(
            CORRELATION_ID_HEADER,
            "01900000-0000-7000-8000-000000000000",
        )
        .header("content-type", "application/json");
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    let request = request
        .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn create_body(purpose: &str) -> serde_json::Value {
    serde_json::json!({ "templateVersionId": VERSION, "purpose": purpose })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_replays_create_one_lease_and_claim_no_pool_member() {
    let world = World::new().await;
    let attempts: Vec<_> = (0..12)
        .map(|_| {
            let state = world.state.clone();
            tokio::spawn(async move {
                call(
                    &state,
                    "ci",
                    "POST",
                    "/lab/leases",
                    Some("run-42"),
                    Some(create_body("release-qa:v1:run-42")),
                )
                .await
            })
        })
        .collect();
    let mut ids = std::collections::BTreeSet::new();
    let mut created = 0;
    for attempt in attempts {
        let (status, body) = attempt.await.unwrap();
        assert!(
            status == StatusCode::CREATED || status == StatusCode::OK,
            "{status}: {body}"
        );
        created += usize::from(status == StatusCode::CREATED);
        ids.insert(body["data"]["id"].as_str().unwrap().to_owned());
    }
    assert_eq!(ids.len(), 1, "every replay answers the same lease");
    assert_eq!(created, 1, "exactly one request created it");
    let all = world.leases.list(None).await.unwrap();
    assert_eq!(all.len(), 1);
    // Creation claims nothing: no member is bound and no provision exists.
    assert!(
        world
            .pools
            .member_for_lease(&all[0].id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        fleet_application::lab::ProvisionPort::list(world.labs.as_ref())
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_replay_returns_the_same_lease_and_a_different_body_is_refused() {
    let world = World::new().await;
    let (status, first) = world
        .call(
            "ci",
            "POST",
            "/lab/leases",
            Some("k1"),
            Some(create_body("a")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let (status, replay) = world
        .call(
            "ci",
            "POST",
            "/lab/leases",
            Some("k1"),
            Some(create_body("a")),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["data"]["id"], first["data"]["id"]);
    // An explicit null project is the same request as an absent one.
    let mut with_null = create_body("a");
    with_null["projectId"] = serde_json::Value::Null;
    let (status, replay) = world
        .call("ci", "POST", "/lab/leases", Some("k1"), Some(with_null))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["data"]["id"], first["data"]["id"]);

    // A different purpose, version, or project under the same key: 409.
    for body in [
        create_body("b"),
        serde_json::json!({ "templateVersionId": "other", "purpose": "a" }),
        serde_json::json!({ "templateVersionId": VERSION, "purpose": "a", "projectId": "p" }),
    ] {
        let (status, error) = world
            .call("ci", "POST", "/lab/leases", Some("k1"), Some(body))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{error}");
    }

    // The key is scoped to the caller: another principal's "k1" is its own.
    let (status, other) = world
        .call(
            "other",
            "POST",
            "/lab/leases",
            Some("k1"),
            Some(create_body("b")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{other}");
    assert_ne!(other["data"]["id"], first["data"]["id"]);

    // No key: every call creates. A malformed key is a 400.
    for _ in 0..2 {
        let (status, _) = world
            .call("ci", "POST", "/lab/leases", None, Some(create_body("a")))
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let (status, _) = world
        .call(
            "ci",
            "POST",
            "/lab/leases",
            Some("has space"),
            Some(create_body("a")),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(world.leases.list(None).await.unwrap().len(), 4);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn leases_filter_by_purpose_state_and_owner() {
    let world = World::new().await;
    let mut ids = Vec::new();
    for (owner, purpose) in [
        ("ci", "release-qa:v1.2:run-1"),
        ("ci", "release-qa:v1.2:run-2"),
        ("ci", "release-qa:v1.3:run-1"),
        ("dev", "release-qa:v1.2:run-1"),
        ("dev", "100%_sure"),
        ("dev", "100xysure"),
    ] {
        let lease = world
            .lab
            .create_lease(
                &Permit,
                &fleet_application::authz::ActingPrincipal {
                    id: owner.to_owned(),
                },
                fleet_application::lab::NewLease {
                    template_version_id: VERSION.to_owned(),
                    purpose: purpose.to_owned(),
                    ..Default::default()
                },
                NOW,
            )
            .await
            .unwrap();
        ids.push(lease.id);
    }
    // Move the third lease to `ready` and the fourth to `failed`.
    for (id, state) in [(&ids[2], LeaseState::Ready), (&ids[3], LeaseState::Failed)] {
        let mut lease = world.leases.get(id).await.unwrap();
        lease.state = state;
        world.leases.update(&lease).await.unwrap();
    }
    let list = |query: &'static str| {
        let world = &world;
        async move {
            let (status, body) = world
                .call("anyone", "GET", &format!("/lab/leases{query}"), None, None)
                .await;
            (
                status,
                body["items"]
                    .as_array()
                    .map(|items| {
                        let mut purposes: Vec<String> = items
                            .iter()
                            .map(|i| {
                                format!(
                                    "{}|{}|{}",
                                    i["owner"].as_str().unwrap(),
                                    i["purpose"].as_str().unwrap(),
                                    i["state"].as_str().unwrap()
                                )
                            })
                            .collect();
                        purposes.sort();
                        purposes
                    })
                    .unwrap_or_default(),
            )
        }
    };
    assert_eq!(list("").await.1.len(), 6);
    assert_eq!(
        list("?purpose=release-qa:v1.2:run-1").await.1,
        [
            "ci|release-qa:v1.2:run-1|requested",
            "dev|release-qa:v1.2:run-1|failed"
        ]
    );
    assert_eq!(list("?purposePrefix=release-qa:v1.2:").await.1.len(), 3);
    // LIKE wildcards in the prefix are literal.
    assert_eq!(
        list("?purposePrefix=100%25_").await.1,
        ["dev|100%_sure|requested"]
    );
    assert_eq!(list("?purposePrefix=100%25").await.1.len(), 1);
    assert_eq!(
        list("?purposePrefix=RELEASE").await.1.len(),
        0,
        "case-sensitive"
    );
    assert_eq!(list("?owner=ci").await.1.len(), 3);
    assert_eq!(list("?state=ready").await.1.len(), 1);
    assert_eq!(list("?state=ready,failed").await.1.len(), 2);
    assert_eq!(list("?state=ready&state=failed").await.1.len(), 2);
    assert_eq!(
        list("?owner=ci&purposePrefix=release-qa:v1.2:&state=requested")
            .await
            .1
            .len(),
        2
    );
    assert_eq!(list("?state=nonsense").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(list("?owner=a&owner=b").await.0, StatusCode::BAD_REQUEST);

    // The application can force the owner: the asked-for owner can only
    // narrow within it (#392 plugs the scoped CI identity in here).
    let anyone = fleet_application::authz::ActingPrincipal {
        id: "ci".to_owned(),
    };
    let scoped = |owner: Option<&str>| LeaseFilter {
        owner: owner.map(str::to_owned),
        ..LeaseFilter::default()
    };
    let own = world
        .lab
        .search_leases(&Permit, &anyone, scoped(None), Some("ci"))
        .await
        .unwrap();
    assert_eq!(own.len(), 3);
    assert!(own.iter().all(|lease| lease.owner == "ci"));
    assert_eq!(
        world
            .lab
            .search_leases(&Permit, &anyone, scoped(Some("ci")), Some("ci"))
            .await
            .unwrap()
            .len(),
        3
    );
    assert!(
        world
            .lab
            .search_leases(&Permit, &anyone, scoped(Some("dev")), Some("ci"))
            .await
            .unwrap()
            .is_empty()
    );
}
