//! #327: `GET /lab/provisions` reports what became of each guest, beside the
//! record's saga state and the linked lease's state. Real SQLite
//! repositories behind the real router.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::lab::{
    ImagePinValidator, Lab, LabTemplate, LabTemplateVersion, LeasePort as _, NewLabTemplate,
    NewProvision, ProvisionPort,
};
use fleet_application::lab::{LabTemplatePort, NewLease};
use fleet_application::lab_pool::{FillResult, LabPoolPort as _, LabPools, NewLabPool};
use fleet_application::operation::{AuditPort, Operations};
use fleet_application::proxmox::{NewProxmoxAccount, ProxmoxAccountPort as _};
use fleet_core::{CleanupStrategy, GuestState, LabTemplateContent, LeaseState, ReadinessProbe};
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
    lab: Arc<Lab>,
    operations: Arc<Operations>,
    labs: Arc<LabRepository>,
    leases: Arc<LeaseRepository>,
    pools: Arc<LabPoolRepository>,
    pool_id: String,
    account_id: String,
}

impl World {
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
            audio: None,
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
        let lab = Lab::new(
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
        )));
        let pool_row = pools
            .create(
                &NewLabPool {
                    template_version_id: VERSION.to_owned(),
                    account_id: account.id.clone(),
                    baseline_snapshot: "baseline".to_owned(),
                    size: 2,
                },
                "tester",
                NOW,
            )
            .await
            .unwrap();
        Self {
            _dir: dir,
            operations: Arc::new(Operations::new(
                Arc::new(OperationRepository::new(pool.clone())),
                audit,
            )),
            lab: Arc::new(lab),
            labs,
            leases,
            pools,
            pool_id: pool_row.id,
            account_id: account.id,
        }
    }

    /// Registers a pool member at `vmid`, available or quarantined.
    async fn member(&self, vmid: u32, quarantined: bool) {
        for member in self
            .pools
            .add_members(&self.pool_id, &[vmid], NOW)
            .await
            .unwrap()
        {
            let result = if quarantined {
                FillResult::Quarantined {
                    detail: "kept by a lease".to_owned(),
                }
            } else {
                FillResult::Available {
                    node: "pve1".to_owned(),
                    name: format!("pool-{vmid}"),
                }
            };
            self.pools
                .finish_fill(&member.id, &result, NOW)
                .await
                .unwrap();
        }
    }

    /// A lease and its provision record, the lease in `state`. `clone` is
    /// whether the record started a clone; a pooled record did not.
    async fn seed(
        &self,
        cleanup: CleanupStrategy,
        state: LeaseState,
        vmid: Option<u32>,
        clone: bool,
    ) -> String {
        let lease = self
            .leases
            .create(
                &NewLease {
                    template_version_id: VERSION.to_owned(),
                    purpose: "provisions surface".to_owned(),
                    project_id: None,
                    cleanup,
                    ttl_seconds: 3_600,
                },
                "tester",
                NOW,
            )
            .await
            .unwrap();
        let record = self.record(Some(&lease.id), vmid, clone).await;
        self.leases
            .attach_provision(&lease.id, &record)
            .await
            .unwrap();
        let mut lease = self.leases.get(&lease.id).await.unwrap();
        lease.state = state;
        self.leases.update(&lease).await.unwrap();
        record
    }

    async fn record(&self, lease_id: Option<&str>, vmid: Option<u32>, clone: bool) -> String {
        let mut record = ProvisionPort::create(
            self.labs.as_ref(),
            &NewProvision {
                template_version_id: VERSION.to_owned(),
                lease_id: lease_id.map(str::to_owned),
                idempotency_key: None,
                readiness_deadline_at: None,
            },
            NOW,
        )
        .await
        .unwrap();
        record.state = GuestState::Ready;
        if let Some(vmid) = vmid {
            record.vmid = Some(vmid);
            record.node = Some("pve1".to_owned());
            record.account_id = Some(self.account_id.clone());
            if clone {
                record.clone_upid = Some(
                    "UPID:pve1:0015523F:0C6DF532:6AAFE1EC:qmclone:120:fleet@pve!lab:".to_owned(),
                );
            }
        }
        ProvisionPort::update(self.labs.as_ref(), &record)
            .await
            .unwrap();
        record.id
    }

    fn state(&self, authorizer: Arc<dyn Authorizer>) -> Arc<ApiState> {
        Arc::new(ApiState {
            authorizer,
            operations: self.operations.clone(),
            lab: Some(self.lab.clone()),
            ..ApiState::for_document()
        })
    }
}

async fn get(state: &Arc<ApiState>, path: &str) -> (StatusCode, serde_json::Value) {
    let router = router(state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }));
    let request = Request::builder()
        .method("GET")
        .uri(format!("{API_BASE_PATH}{path}"))
        .header(
            CORRELATION_ID_HEADER,
            "01900000-0000-7000-8000-000000000000",
        )
        .body(Body::empty())
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

fn field(items: &serde_json::Value, id: &str, key: &str) -> serde_json::Value {
    items["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == id)
        .unwrap_or_else(|| panic!("{id} is listed"))[key]
        .clone()
}

/// Seeds one record per fate and answers what the list must say for each:
/// the id, the guest, and the linked lease's state.
async fn seed_every_fate(world: &World) -> Vec<(String, &'static str, Option<&'static str>)> {
    // Pool members: one returned (available), one quarantined.
    world.member(300, false).await;
    world.member(301, true).await;

    let destroyed = world
        .seed(
            CleanupStrategy::Destroy,
            LeaseState::Released,
            Some(900),
            true,
        )
        .await;
    let kept = world
        .seed(CleanupStrategy::Keep, LeaseState::Released, Some(901), true)
        .await;
    let failed = world
        .seed(
            CleanupStrategy::Destroy,
            LeaseState::Failed,
            Some(902),
            true,
        )
        .await;
    let releasing = world
        .seed(
            CleanupStrategy::Destroy,
            LeaseState::Releasing,
            Some(903),
            true,
        )
        .await;
    let never_cloned = world
        .seed(CleanupStrategy::Destroy, LeaseState::Released, None, false)
        .await;
    // A pooled lease is never destroyed, whatever strategy it recorded.
    let returned = world
        .seed(
            CleanupStrategy::Destroy,
            LeaseState::Released,
            Some(300),
            false,
        )
        .await;
    let reverted = world
        .seed(
            CleanupStrategy::Revert,
            LeaseState::Released,
            Some(300),
            false,
        )
        .await;
    let quarantined = world
        .seed(
            CleanupStrategy::Keep,
            LeaseState::Released,
            Some(301),
            false,
        )
        .await;
    // A destroyed clone whose VMID a pool member later took stays destroyed:
    // it started a clone, so it was never the pool's guest.
    let reused = world
        .seed(
            CleanupStrategy::Destroy,
            LeaseState::Released,
            Some(300),
            true,
        )
        .await;
    // A record whose lease never linked back to it reads present: nothing
    // speaks for the guest, and the lease's state is not reported for it.
    let unlinked = world
        .leases
        .create(
            &NewLease {
                template_version_id: VERSION.to_owned(),
                purpose: "unlinked".to_owned(),
                project_id: None,
                cleanup: CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            "tester",
            NOW,
        )
        .await
        .unwrap();
    let orphaned = world.record(Some(&unlinked.id), Some(904), true).await;

    vec![
        (destroyed.clone(), "destroyed", Some("released")),
        (kept.clone(), "kept", Some("released")),
        (failed.clone(), "present", Some("failed")),
        (releasing.clone(), "present", Some("releasing")),
        (never_cloned.clone(), "not_allocated", Some("released")),
        (returned.clone(), "returned_to_pool", Some("released")),
        (reverted.clone(), "returned_to_pool", Some("released")),
        (quarantined.clone(), "quarantined_in_pool", Some("released")),
        (reused.clone(), "destroyed", Some("released")),
        (orphaned.clone(), "present", None),
    ]
}

#[tokio::test]
async fn the_list_reports_what_became_of_each_guest() {
    let world = World::new().await;
    let expected = seed_every_fate(&world).await;
    let destroyed = expected[0].0.clone();
    let state = world.state(Arc::new(Permit));
    let (status, body) = get(&state, "/lab/provisions").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for (id, guest, lease) in expected {
        let id = &id;
        assert_eq!(field(&body, id, "guest"), guest, "{id}");
        assert_eq!(
            field(&body, id, "leaseState"),
            lease.map_or(serde_json::Value::Null, serde_json::Value::from),
            "{id}"
        );
    }
    // The saga state and the history stay as they were.
    assert_eq!(field(&body, &destroyed, "state"), "ready");
    assert_eq!(field(&body, &destroyed, "vmid"), 900);
    assert_eq!(field(&body, &destroyed, "node"), "pve1");

    // Reading the list still needs `lab.read`.
    let (status, _) = get(
        &world.state(Arc::new(Without(Permission::LabRead))),
        "/lab/provisions",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
