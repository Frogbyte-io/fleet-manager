//! #489: the persistent-machine rules at the HTTP surface, over the real
//! router and SQLite store. Destroying a created persistent machine needs
//! `confirmPersistent` when the review and the run are made (not only when
//! the worker executes), the permission is checked before the marker is
//! looked at, and abandoning a marker is reviewed and refused for a created
//! machine.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::lab::Lab;
use fleet_application::machine_access::MachineAccess;
use fleet_application::operation::Operations;
use fleet_application::persistent::{
    PersistentGuest, PersistentGuestPort as _, PersistentMachines, PersistentState,
};
use fleet_storage_sqlite::{
    AuditSink, EndpointAuthRepository, LabRepository, LeaseRepository, MachineRepository,
    OperationRepository, PersistentGuestRepository, ProjectRepository, Store,
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

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
    state: Arc<ApiState>,
}

fn marker(vmid: u32, name: &str, cloned: bool) -> PersistentGuest {
    PersistentGuest {
        account_id: "acct".to_owned(),
        vmid,
        name: name.to_owned(),
        node: "pve".to_owned(),
        image_version_id: "ver".to_owned(),
        machine_id: None,
        cloned,
        state: if cloned {
            PersistentState::Ready
        } else {
            PersistentState::Creating
        },
        step: None,
        operation_id: None,
        created_at: 1,
        updated_at: 1,
    }
}

impl Harness {
    async fn new(authorizer: Arc<dyn Authorizer>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        std::mem::forget(store);
        let markers = Arc::new(PersistentGuestRepository::new(pool.clone()));
        markers.reserve(&marker(7100, "made", true)).await.unwrap();
        markers
            .reserve(&marker(7101, "never-made", false))
            .await
            .unwrap();
        let access = Arc::new(
            MachineAccess::new(
                Arc::new(MachineRepository::new(pool.clone())),
                Arc::new(EndpointAuthRepository::new(pool.clone())),
                Arc::new(AuditSink::new(pool.clone())),
            )
            .with_persistent(Arc::new(
                PersistentMachines::new(Arc::new(NoPins), Arc::new(AuditSink::new(pool.clone())))
                    .with_markers(markers),
            )),
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
        let state = Arc::new(ApiState {
            operations,
            authorizer,
            lab: Some(lab),
            ..ApiState::for_document()
        });
        Self { _dir: dir, state }
    }

    async fn call(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri(format!("{API_BASE_PATH}{path}"))
            .header("content-type", "application/json")
            .header(
                CORRELATION_ID_HEADER,
                "01900000-0000-7000-8000-000000000000",
            )
            .body(Body::from(body.to_string()))
            .unwrap();
        let app = router(self.state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
            id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
        }));
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }
}

#[tokio::test]
async fn destroying_a_created_persistent_machine_needs_confirmation_at_review_and_run() {
    let harness = Harness::new(Arc::new(fleet_auth::LanAllowAllAuthorizer)).await;
    let review = "/proxmox/accounts/acct/guests/7100/destroy/review";
    let run = "/proxmox/accounts/acct/guests/7100/destroy/run";

    let (status, body) = harness
        .call(review, json!({ "node": "pve", "params": {} }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("confirmPersistent"));
    let (status, body) = harness
        .call(
            run,
            json!({ "node": "pve", "reviewToken": "x", "params": {}, "timeoutSeconds": 300 }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Confirmed, the review answers a token; a guest with no marker, or a
    // stale marker, needs no confirmation.
    let (status, body) = harness
        .call(
            review,
            json!({ "node": "pve", "params": { "confirmPersistent": true } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = harness
        .call(
            "/proxmox/accounts/acct/guests/7101/destroy/review",
            json!({ "node": "pve", "params": {} }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = harness
        .call(
            "/proxmox/accounts/acct/guests/9999/destroy/review",
            json!({ "node": "pve", "params": {} }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_permission_is_checked_before_the_marker_is_revealed() {
    let harness = Harness::new(Arc::new(Deny(Permission::ProxmoxDestructive))).await;
    let (status, body) = harness
        .call(
            "/proxmox/accounts/acct/guests/7100/destroy/review",
            json!({ "node": "pve", "params": {} }),
        )
        .await;
    // Denied, not "needs confirmation": a caller without the permission
    // learns nothing about which VMIDs are persistent machines.
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!body.to_string().contains("persistent"));
}

#[tokio::test]
async fn an_abandon_is_reviewed_and_refused_for_a_created_machine() {
    let harness = Harness::new(Arc::new(fleet_auth::LanAllowAllAuthorizer)).await;
    let (status, _) = harness
        .call("/machines/persistent/acct/7100/abandon/review", json!(null))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, body) = harness
        .call("/machines/persistent/acct/7101/abandon/review", json!(null))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["data"]["reviewToken"].as_str().is_some());
    // A token that was not issued for this VMID abandons nothing.
    let (status, _) = harness
        .call(
            "/machines/persistent/acct/7101/abandon",
            json!({ "reviewToken": "0".repeat(64) }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
