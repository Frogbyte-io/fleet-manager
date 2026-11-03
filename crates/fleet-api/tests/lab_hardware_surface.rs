//! FM-1121: a template declares `hardware` through the API, the declaration is
//! validated and frozen into the published version, and a lease reads back the
//! devices it asked for and the reservation that holds them. A lease whose
//! version declares none reads exactly as before. Real SQLite repositories
//! behind the real router.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision};
use fleet_application::hardware::{DeviceObservation, HardwareStore as _, NewHardwareReservation};
use fleet_application::lab::{ImagePinValidator, Lab};
use fleet_application::operation::{AuditPort, Operations};
use fleet_core::{
    DeviceNodeEntry, DeviceStatus, GuestTarget, HardwareKind, HardwareReservationState,
    ReservationOwnerKind,
};
use fleet_storage_sqlite::{
    AuditSink, HardwareRepository, LabRepository, LeaseRepository, OperationRepository,
    ProjectRepository, Store,
};
use tower::ServiceExt as _;

const NOW: i64 = 1_800_000_000_000;

#[derive(Debug)]
struct Permit;
impl Authorizer for Permit {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

/// The promoted image every template pins.
#[derive(Debug)]
struct Promoted;
#[async_trait::async_trait]
impl ImagePinValidator for Promoted {
    async fn promoted_version(
        &self,
        version_id: &str,
    ) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok(
            (version_id == "image-version-1").then(|| fleet_core::RecipeVersion {
                id: version_id.to_owned(),
                recipe_id: "recipe-1".to_owned(),
                name: "image".to_owned(),
                content_digest: "sha256:0123456789abcdef".to_owned(),
                description: String::new(),
                content: "{}".to_owned(),
                source: fleet_core::RecipeSource::Clone,
                node: "pve-a".to_owned(),
                storage_pool: "local-lvm".to_owned(),
                published_at: 0,
                promoted_at: Some(0),
                promoted_by: Some("tester".to_owned()),
                promoted_build_id: Some("build-1".to_owned()),
                allow_insecure_tls: false,
            }),
        )
    }
}

struct World {
    _dir: tempfile::TempDir,
    state: Arc<ApiState>,
    hardware: HardwareRepository,
}

impl World {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        // The pool outlives the store handle for the test's duration.
        std::mem::forget(store);
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let audit: Arc<dyn AuditPort> = Arc::new(AuditSink::new(pool.clone()));
        let lab = Arc::new(
            Lab::new(
                labs.clone(),
                labs,
                Arc::new(LeaseRepository::new(pool.clone())),
                Arc::new(Promoted),
                Arc::new(ProjectRepository::new(pool.clone())),
                audit.clone(),
            )
            .with_hardware(Arc::new(HardwareRepository::new(pool.clone()))),
        );
        let state = Arc::new(ApiState {
            authorizer: Arc::new(Permit),
            operations: Arc::new(Operations::new(
                Arc::new(OperationRepository::new(pool.clone())),
                audit,
            )),
            lab: Some(lab),
            ..ApiState::for_document()
        });
        Self {
            _dir: dir,
            state,
            hardware: HardwareRepository::new(pool),
        }
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let router =
            router(self.state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
                id: "tester".to_owned(),
            }));
        let request = Request::builder()
            .method(method)
            .uri(format!("{API_BASE_PATH}{path}"))
            .header(
                CORRELATION_ID_HEADER,
                "01900000-0000-7000-8000-000000000000",
            )
            .header("content-type", "application/json")
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

    /// Creates and publishes a template; answers the version id.
    async fn version(&self, name: &str, hardware: Option<serde_json::Value>) -> String {
        let mut body = template_body(name);
        if let Some(hardware) = hardware {
            body["hardware"] = hardware;
        }
        let (status, created) = self.call("POST", "/lab/templates", Some(body)).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["data"]["id"].as_str().unwrap().to_owned();
        let (status, published) = self
            .call("POST", &format!("/lab/templates/{id}/publish"), None)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{published}");
        published["data"]["id"].as_str().unwrap().to_owned()
    }

    async fn lease(&self, version: &str) -> String {
        let (status, lease) = self
            .call(
                "POST",
                "/lab/leases",
                Some(serde_json::json!({ "templateVersionId": version, "purpose": "usb test" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{lease}");
        lease["data"]["id"].as_str().unwrap().to_owned()
    }
}

fn template_body(name: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "description": "",
        "imageVersionId": "image-version-1",
        "cores": 2,
        "memoryMib": 2048,
        "diskGib": 20,
        "readinessProbe": "guest_agent",
        "readinessDeadlineSeconds": 300,
        "ttlSeconds": 3600,
        "cleanup": "destroy",
    })
}

#[tokio::test]
async fn a_template_declares_hardware_and_the_published_version_freezes_it() {
    let world = World::new().await;
    let mut body = template_body("usb-lab");
    body["hardware"] = serde_json::json!([
        { "kind": "usb", "mapping": "fm-test-superdrive-a" },
        { "kind": "usb", "mapping": "fm-test-verbatim" },
    ]);
    let (status, created) = world
        .call("POST", "/lab/templates", Some(body.clone()))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(
        created["data"]["hardware"],
        serde_json::json!([
            { "kind": "usb", "mapping": "fm-test-superdrive-a" },
            { "kind": "usb", "mapping": "fm-test-verbatim" },
        ])
    );
    let id = created["data"]["id"].as_str().unwrap();

    let (status, published) = world
        .call("POST", &format!("/lab/templates/{id}/publish"), None)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{published}");
    assert_eq!(
        published["data"]["content"]["hardware"][1]["mapping"],
        "fm-test-verbatim"
    );

    // An update replaces the whole draft: omitting the field clears it, and
    // the published version is unchanged.
    let (status, updated) = world
        .call(
            "PUT",
            &format!("/lab/templates/{id}"),
            Some(template_body("usb-lab")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert!(updated["data"].get("hardware").is_none(), "{updated}");
    let (status, read) = world
        .call("GET", &format!("/lab/templates/{id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(read["data"].get("hardware").is_none(), "{read}");
}

#[tokio::test]
async fn a_malformed_hardware_declaration_is_refused() {
    let world = World::new().await;
    let long = "x".repeat(65);
    for (hardware, fragment) in [
        (
            serde_json::json!([{ "kind": "pci", "mapping": "gpu" }]),
            "unrecognized hardware kind",
        ),
        (
            serde_json::json!([{ "kind": "usb", "mapping": "a,host=05ac:1500" }]),
            "hardware mapping id",
        ),
        (
            serde_json::json!([{ "kind": "usb", "mapping": "" }]),
            "hardware mapping id",
        ),
        (
            serde_json::json!([{ "kind": "usb", "mapping": long }]),
            "hardware mapping id",
        ),
        (
            serde_json::json!([
                { "kind": "usb", "mapping": "a" },
                { "kind": "usb", "mapping": "a" },
            ]),
            "more than once",
        ),
        (
            serde_json::json!([
                { "kind": "usb", "mapping": "a" },
                { "kind": "usb", "mapping": "b" },
                { "kind": "usb", "mapping": "c" },
                { "kind": "usb", "mapping": "d" },
                { "kind": "usb", "mapping": "e" },
            ]),
            "at most 4",
        ),
    ] {
        let mut body = template_body("usb-bad");
        body["hardware"] = hardware.clone();
        let (status, error) = world.call("POST", "/lab/templates", Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{hardware}: {error}");
        assert!(
            error.to_string().contains(fragment),
            "{fragment} in {error}"
        );
    }
    // A key the declaration does not have (raw `host=` passthrough is not
    // Fleet's, and Fleet never writes it) is refused, never ignored.
    let mut body = template_body("usb-host");
    body["hardware"] = serde_json::json!([
        { "kind": "usb", "mapping": "a", "host": "05ac:1500" }
    ]);
    let (status, error) = world.call("POST", "/lab/templates", Some(body)).await;
    assert!(status.is_client_error(), "{status}: {error}");
    // Nothing was created.
    let (_, listed) = world.call("GET", "/lab/templates", None).await;
    assert_eq!(listed["items"], serde_json::json!([]), "{listed}");
}

#[tokio::test]
async fn a_lease_reads_the_devices_it_asked_for_and_the_reservation_that_holds_them() {
    let world = World::new().await;
    let version = world
        .version(
            "usb-lab",
            Some(serde_json::json!([
                { "kind": "usb", "mapping": "fm-test-superdrive-a" },
                { "kind": "usb", "mapping": "fm-test-verbatim" },
            ])),
        )
        .await;
    let lease = world.lease(&version).await;

    // Before placement: asked for, nothing held.
    let (status, detail) = world
        .call("GET", &format!("/lab/leases/{lease}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert_eq!(
        detail["data"]["hardware"],
        serde_json::json!([
            { "kind": "usb", "mapping": "fm-test-superdrive-a", "reservation": null },
            { "kind": "usb", "mapping": "fm-test-verbatim", "reservation": null },
        ])
    );

    // Placement reserves the first device and the saga attaches it.
    let device = world
        .hardware
        .upsert_device(
            &DeviceObservation {
                id: "device-a".to_owned(),
                account_id: "account-1".to_owned(),
                mapping_id: "fm-test-superdrive-a".to_owned(),
                kind: HardwareKind::Usb,
                entries: vec![DeviceNodeEntry {
                    node: "pve-a".to_owned(),
                    vendor_id: "05ac".to_owned(),
                    product_id: "1500".to_owned(),
                    usbpath: Some("1-10".to_owned()),
                    manufacturer: None,
                    product: None,
                    last_seen_at: NOW,
                }],
                status: DeviceStatus::Available,
            },
            NOW,
        )
        .await
        .unwrap();
    let held = world
        .hardware
        .insert_reservation(
            &NewHardwareReservation {
                id: "reservation-a".to_owned(),
                device_id: device.id.clone(),
                owner_kind: ReservationOwnerKind::Lease,
                owner_id: lease.clone(),
                guest: None,
            },
            NOW,
        )
        .await
        .unwrap();
    let (_, detail) = world
        .call("GET", &format!("/lab/leases/{lease}"), None)
        .await;
    let first = &detail["data"]["hardware"][0];
    assert_eq!(first["mapping"], "fm-test-superdrive-a");
    assert_eq!(first["reservation"]["id"], "reservation-a");
    assert_eq!(first["reservation"]["deviceId"], device.id);
    assert_eq!(first["reservation"]["state"], "held");
    assert_eq!(first["reservation"]["usbSlot"], serde_json::Value::Null);
    assert_eq!(
        detail["data"]["hardware"][1]["reservation"],
        serde_json::Value::Null
    );

    world
        .hardware
        .transition_reservation(
            &held.id,
            HardwareReservationState::Held,
            HardwareReservationState::Attaching,
            Some(&GuestTarget {
                account_id: "account-1".to_owned(),
                node: "pve-a".to_owned(),
                vmid: 9001,
                usb_slot: Some(2),
            }),
            NOW + 1,
        )
        .await
        .unwrap();
    let (_, detail) = world
        .call("GET", &format!("/lab/leases/{lease}"), None)
        .await;
    let first = &detail["data"]["hardware"][0]["reservation"];
    assert_eq!(first["state"], "attaching");
    assert_eq!(first["usbSlot"], 2);
}

#[tokio::test]
async fn a_lease_without_hardware_reads_as_it_always_did() {
    let world = World::new().await;
    let version = world.version("plain-lab", None).await;
    let lease = world.lease(&version).await;
    let (status, detail) = world
        .call("GET", &format!("/lab/leases/{lease}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert!(
        detail["data"].get("hardware").is_none(),
        "no hardware key: {detail}"
    );
    // The detail is otherwise the same shape it always had.
    assert!(detail["data"].get("reservation").is_some(), "{detail}");
    assert_eq!(detail["data"]["id"], lease.as_str());
}
