//! FM-1125 (#570): the persistent-machine USB routes at the HTTP surface,
//! over the real router and SQLite store. The saga behind the port is
//! `machine_usb.rs`'s (against a fake Proxmox); here the port is scripted, so
//! what is exercised is the review and execute routes, the review token,
//! authorization (the machine catalog entries, never a Lab credential), the
//! error envelope, and the lifecycle refusals (destroy, revert, template and
//! unregister while a machine holds a device).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState, router};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::hardware::{DeviceObservation, HardwareStore, NewHardwareReservation};
use fleet_application::lab::Lab;
use fleet_application::lab_hardware_hotplug::{HotplugError, HotplugResult};
use fleet_application::machine::{GuestLink, GuestLinkPort as _, MachinePort as _, NewEndpoint};
use fleet_application::machine_access::MachineAccess;
use fleet_application::machine_usb::{
    MachineHardwareGate, MachineUsb, MachineUsbAction, MachineUsbOutcome, MachineUsbPort,
    MachineUsbRequest, StoreMachineHardwareGate,
};
use fleet_application::operation::Operations;
use fleet_application::persistent::{
    GuestCheck, LiveGuest, PersistentGuest, PersistentGuestPort as _, PersistentMachines,
    PersistentState, RegisterGuard,
};
use fleet_core::{
    DeviceNodeEntry, DeviceStatus, EndpointKind, GuestTarget, HardwareKind,
    HardwareReservationState, ReservationOwnerKind,
};
use fleet_storage_sqlite::{
    AuditSink, EndpointAuthRepository, GuestLinkRepository, HardwareRepository, LabRepository,
    LeaseRepository, MachineRepository, OperationRepository, PersistentGuestRepository,
    ProjectRepository, Store,
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const ACCOUNT: &str = "acct";
const MAPPING: &str = "fm-test-reader-a";
const VMID: u32 = 8100;
const OTHER_VMID: u32 = 8101;

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
struct Permit;

impl Authorizer for Permit {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

#[derive(Debug)]
struct NoPins;

#[async_trait]
impl fleet_application::lab::ImagePinValidator for NoPins {
    async fn promoted_version(
        &self,
        _version_id: &str,
    ) -> Result<Option<fleet_core::RecipeVersion>, String> {
        Ok(None)
    }
}

/// A cluster with two eligible guests.
#[derive(Debug)]
struct FakeCluster;

#[async_trait]
impl RegisterGuard for FakeCluster {
    async fn inspect(&self, _account_id: &str, vmid: u32) -> Result<GuestCheck, String> {
        Ok(match vmid {
            VMID => GuestCheck::Eligible(LiveGuest {
                name: "bench".to_owned(),
                node: "pve".to_owned(),
            }),
            OTHER_VMID => GuestCheck::Eligible(LiveGuest {
                name: "registered-box".to_owned(),
                node: "pve".to_owned(),
            }),
            other => GuestCheck::Refused(format!("no guest with VMID {other} exists")),
        })
    }
}

/// A port that answers what the test scripted and remembers what it was asked.
#[derive(Debug)]
struct Scripted {
    answer: Mutex<Result<MachineUsbOutcome, HotplugError>>,
    seen: Mutex<Vec<MachineUsbRequest>>,
}

impl Scripted {
    fn new(answer: Result<MachineUsbOutcome, HotplugError>) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(answer),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<MachineUsbRequest> {
        self.seen.lock().unwrap().clone()
    }

    fn answer(&self, answer: Result<MachineUsbOutcome, HotplugError>) {
        *self.answer.lock().unwrap() = answer;
    }
}

#[async_trait]
impl MachineUsbPort for Scripted {
    async fn carry_out(
        &self,
        request: &MachineUsbRequest,
    ) -> Result<MachineUsbOutcome, HotplugError> {
        self.seen.lock().unwrap().push(request.clone());
        self.answer.lock().unwrap().clone()
    }
}

fn outcome(result: HotplugResult, state: HardwareReservationState) -> MachineUsbOutcome {
    MachineUsbOutcome {
        machine_id: "ignored".to_owned(),
        mapping_id: MAPPING.to_owned(),
        result,
        reservation_id: "reservation-1".to_owned(),
        reservation_state: state,
        usb_slot: matches!(
            state,
            HardwareReservationState::Attached | HardwareReservationState::Detaching
        )
        .then_some(1),
        released: state == HardwareReservationState::Released,
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    state: Arc<ApiState>,
    port: Arc<Scripted>,
    hardware: Arc<HardwareRepository>,
    /// A machine linked to a ready persistent guest.
    machine: String,
    /// A machine linked to a registered persistent guest (marker removable).
    registered: String,
}

fn marker(vmid: u32, name: &str, source: &str, machine_id: &str) -> PersistentGuest {
    PersistentGuest {
        account_id: ACCOUNT.to_owned(),
        vmid,
        name: name.to_owned(),
        node: "pve".to_owned(),
        image_version_id: source.to_owned(),
        machine_id: Some(machine_id.to_owned()),
        cloned: true,
        state: PersistentState::Ready,
        step: None,
        operation_id: None,
        created_at: 1,
        updated_at: 1,
    }
}

impl Harness {
    async fn new(authorizer: Arc<dyn Authorizer>) -> Self {
        Self::with(authorizer, true).await
    }

    async fn with(authorizer: Arc<dyn Authorizer>, wired: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
        let pool = store.pool().clone();
        std::mem::forget(store);
        sqlx::query(
            "INSERT INTO proxmox_accounts (id, name, host, port, token_id, created_at) \
             VALUES (?1, ?1, 'pve.example.test', 8006, 'fleet@pve!lab', 1)",
        )
        .bind(ACCOUNT)
        .execute(&pool)
        .await
        .unwrap();
        let machines = Arc::new(MachineRepository::new(pool.clone()));
        let links = Arc::new(GuestLinkRepository::new(pool.clone()));
        let markers = Arc::new(PersistentGuestRepository::new(pool.clone()));
        let hardware = Arc::new(HardwareRepository::new(pool.clone()));
        let mut ids = Vec::new();
        for (name, vmid, source, guest_name) in [
            ("bench", VMID, "image-version-1", "bench"),
            ("shelf", OTHER_VMID, "registered", "registered-box"),
        ] {
            let machine = machines
                .register(&fleet_application::machine::RegisterMachine {
                    name: name.to_owned(),
                    description: String::new(),
                    endpoints: vec![NewEndpoint {
                        kind: EndpointKind::Ssh,
                        reference: format!("root@{name}.invalid:22"),
                    }],
                    tags: vec![],
                    groups: vec![],
                })
                .await
                .unwrap();
            links
                .confirm(
                    &machine.id,
                    &GuestLink {
                        account_id: ACCOUNT.to_owned(),
                        guest_kind: "qemu".to_owned(),
                        node: "pve".to_owned(),
                        vmid,
                    },
                )
                .await
                .unwrap();
            markers
                .reserve(&marker(vmid, guest_name, source, &machine.id))
                .await
                .unwrap();
            ids.push(machine.id);
        }
        // The inventoried device (an attach is reviewed against it).
        let now = fleet_core::SystemClock::now_unix_millis();
        hardware
            .upsert_device(
                &DeviceObservation {
                    id: "device-1".to_owned(),
                    account_id: ACCOUNT.to_owned(),
                    mapping_id: MAPPING.to_owned(),
                    kind: HardwareKind::Usb,
                    entries: vec![DeviceNodeEntry {
                        node: "pve".to_owned(),
                        vendor_id: "aaaa".to_owned(),
                        product_id: "0001".to_owned(),
                        usbpath: Some("1-1".to_owned()),
                        manufacturer: None,
                        product: None,
                        last_seen_at: now,
                    }],
                    status: DeviceStatus::Available,
                },
                now,
            )
            .await
            .unwrap();
        let gate: Arc<dyn MachineHardwareGate> =
            Arc::new(StoreMachineHardwareGate::new(hardware.clone()));
        let port = Scripted::new(Ok(outcome(
            HotplugResult::Attached,
            HardwareReservationState::Attached,
        )));
        let audit = Arc::new(AuditSink::new(pool.clone()));
        let usb = Arc::new(MachineUsb::new(
            machines.clone(),
            links.clone(),
            markers.clone(),
            Arc::new(FakeCluster),
            hardware.clone(),
            port.clone(),
        ));
        let access = Arc::new(
            MachineAccess::new(
                machines.clone(),
                Arc::new(EndpointAuthRepository::new(pool.clone())),
                audit.clone(),
            )
            .with_persistent(Arc::new(
                PersistentMachines::new(Arc::new(NoPins), audit.clone())
                    .with_markers(markers)
                    .with_machines(machines)
                    .with_guest_links(links)
                    .with_register_guard(Arc::new(FakeCluster))
                    .with_hardware_gate(gate.clone()),
            )),
        );
        let labs = Arc::new(LabRepository::new(pool.clone()));
        let mut lab = Lab::new(
            labs.clone(),
            labs,
            Arc::new(LeaseRepository::new(pool.clone())),
            Arc::new(NoPins),
            Arc::new(ProjectRepository::new(pool.clone())),
            audit.clone(),
        )
        .with_machine_access(access);
        if wired {
            lab = lab.with_machine_usb(usb, gate);
        }
        let operations = Arc::new(Operations::new(
            Arc::new(OperationRepository::new(pool.clone())),
            audit,
        ));
        let state = Arc::new(ApiState {
            operations,
            authorizer,
            lab: Some(Arc::new(lab)),
            ..ApiState::for_document()
        });
        let [machine, registered] = <[String; 2]>::try_from(ids).unwrap();
        Self {
            _dir: dir,
            pool,
            state,
            port,
            hardware,
            machine,
            registered,
        }
    }

    /// The device, recorded and held by `machine_id` through a reservation in
    /// `state` on guest `vmid`.
    async fn holds(&self, machine_id: &str, vmid: u32, state: HardwareReservationState) -> String {
        let now = fleet_core::SystemClock::now_unix_millis();
        let device = self
            .hardware
            .device_by_mapping(ACCOUNT, MAPPING)
            .await
            .unwrap()
            .expect("the device is inventoried");
        let reservation = self
            .hardware
            .insert_reservation(
                &NewHardwareReservation {
                    id: "reservation-1".to_owned(),
                    device_id: device.id,
                    owner_kind: ReservationOwnerKind::Machine,
                    owner_id: machine_id.to_owned(),
                    guest: None,
                },
                now,
            )
            .await
            .unwrap();
        if state != HardwareReservationState::Held {
            let target = GuestTarget {
                account_id: ACCOUNT.to_owned(),
                node: "pve".to_owned(),
                vmid,
                usb_slot: Some(0),
            };
            self.hardware
                .transition_reservation(
                    &reservation.id,
                    HardwareReservationState::Held,
                    HardwareReservationState::Attaching,
                    Some(&target),
                    now,
                )
                .await
                .unwrap();
            self.hardware
                .transition_reservation(
                    &reservation.id,
                    HardwareReservationState::Attaching,
                    HardwareReservationState::Attached,
                    Some(&target),
                    now,
                )
                .await
                .unwrap();
        }
        reservation.id
    }

    async fn call_as(&self, principal: &str, path: &str, body: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri(format!("{API_BASE_PATH}{path}"))
            .header("content-type", "application/json")
            .header(
                CORRELATION_ID_HEADER,
                "01900000-0000-7000-8000-000000000000",
            )
            .body(Body::from(body.to_owned()))
            .unwrap();
        let app = router(self.state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
            id: principal.to_owned(),
        }));
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    async fn call(&self, path: &str, body: Value) -> (StatusCode, Value) {
        self.call_as(fleet_auth::LAN_PRINCIPAL_ID, path, &body.to_string())
            .await
    }

    async fn review_attach(&self, machine: &str) -> (StatusCode, Value) {
        self.call(
            &format!("/machines/{machine}/usb/attach/review"),
            json!({ "mapping": MAPPING }),
        )
        .await
    }

    async fn attach(&self, machine: &str, token: &str) -> (StatusCode, Value) {
        self.call(
            &format!("/machines/{machine}/usb/attach"),
            json!({ "mapping": MAPPING, "reviewToken": token }),
        )
        .await
    }

    async fn review_detach(&self, machine: &str) -> (StatusCode, Value) {
        self.call(
            &format!("/machines/{machine}/usb/detach/review"),
            json!({ "mapping": MAPPING }),
        )
        .await
    }

    async fn detach(&self, machine: &str, token: &str) -> (StatusCode, Value) {
        self.call(
            &format!("/machines/{machine}/usb/detach"),
            json!({ "mapping": MAPPING, "reviewToken": token }),
        )
        .await
    }
}

fn token(answer: &Value) -> String {
    answer["data"]["reviewToken"]
        .as_str()
        .expect("a review answers a token")
        .to_owned()
}

#[tokio::test]
async fn an_attach_is_reviewed_then_run_with_the_token_and_the_guest_the_review_resolved() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine.clone();

    let (status, review) = harness.review_attach(&machine).await;
    assert_eq!(status, StatusCode::OK, "{review}");
    let data = &review["data"];
    assert_eq!(data["action"], "attach");
    assert_eq!(data["machineId"], machine.as_str());
    assert_eq!(data["mapping"], MAPPING);
    assert_eq!(data["guest"]["vmid"], VMID);
    assert_eq!(data["guest"]["name"], "bench");
    assert_eq!(data["guest"]["node"], "pve");
    assert_eq!(data["guest"]["accountId"], ACCOUNT);
    assert!(
        harness.port.seen().is_empty(),
        "a review never reaches the port"
    );

    let (status, answer) = harness.attach(&machine, &token(&review)).await;

    assert_eq!(status, StatusCode::OK, "{answer}");
    let data = &answer["data"];
    assert_eq!(data["outcome"], "attached");
    assert_eq!(data["onGuest"], true);
    assert_eq!(data["reservationState"], "attached");
    assert_eq!(data["usbSlot"], "usb1");
    assert_eq!(data["released"], false);
    let seen = harness.port.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].principal_id, fleet_auth::LAN_PRINCIPAL_ID);
    assert_eq!(seen[0].machine_id, machine);
    assert_eq!(seen[0].mapping_id, MAPPING);
    assert_eq!(seen[0].action, MachineUsbAction::Attach);
    let guest = seen[0].guest.as_ref().expect("an attach names its guest");
    assert_eq!(
        (guest.account_id.as_str(), guest.vmid, guest.name.as_str()),
        (ACCOUNT, VMID, "bench")
    );
}

#[tokio::test]
async fn a_detach_is_reviewed_against_the_reservation_and_a_pending_removal_is_accepted_not_done() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine.clone();
    // Nothing held: nothing to detach.
    let (status, answer) = harness.review_detach(&machine).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "hardware_not_reserved");

    harness
        .holds(&machine, VMID, HardwareReservationState::Attached)
        .await;
    let (status, review) = harness.review_detach(&machine).await;
    assert_eq!(status, StatusCode::OK, "{review}");
    assert_eq!(review["data"]["action"], "detach");
    assert_eq!(review["data"]["reservation"]["state"], "attached");
    assert_eq!(review["data"]["reservation"]["guestVmid"], VMID);
    assert_eq!(review["data"]["reservation"]["usbSlot"], "usb0");
    assert!(review["data"]["guest"].is_null());

    harness.port.answer(Ok(outcome(
        HotplugResult::Detached,
        HardwareReservationState::Released,
    )));
    let (status, answer) = harness.detach(&machine, &token(&review)).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["data"]["outcome"], "detached");
    assert_eq!(answer["data"]["onGuest"], false);
    assert_eq!(answer["data"]["released"], true);
    assert!(answer["data"]["usbSlot"].is_null(), "{answer}");
    let seen = harness.port.seen();
    assert_eq!(seen[0].action, MachineUsbAction::Detach);
    assert!(
        seen[0].guest.is_none(),
        "a detach acts on the reservation's guest"
    );

    // A removal PVE keeps pending: 202, and the device is still on the guest.
    harness.port.answer(Ok(outcome(
        HotplugResult::DetachPending,
        HardwareReservationState::Detaching,
    )));
    let (status, answer) = harness.detach(&machine, &token(&review)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{answer}");
    assert_eq!(answer["data"]["outcome"], "detach_pending");
    assert_eq!(answer["data"]["onGuest"], true);
    assert_eq!(answer["data"]["reservationState"], "detaching");
}

#[tokio::test]
async fn the_review_token_binds_the_call_and_a_malformed_body_is_a_client_error() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine.clone();
    let (_, review) = harness.review_attach(&machine).await;
    let token = token(&review);

    // Another machine, another device, the detach route, a made-up token.
    let (status, answer) = harness.attach(&harness.registered, &token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["code"], "invalid_request");
    let (status, _) = harness
        .call(
            &format!("/machines/{machine}/usb/attach"),
            json!({ "mapping": "fm-test-reader-b", "reviewToken": token }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = harness
        .attach(
            &machine,
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    harness
        .holds(&machine, VMID, HardwareReservationState::Attached)
        .await;
    let (status, _) = harness.detach(&machine, &token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // No token, an unknown field, an id that could add a property.
    let (status, _) = harness
        .call(
            &format!("/machines/{machine}/usb/attach"),
            json!({ "mapping": MAPPING }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = harness
        .call(
            &format!("/machines/{machine}/usb/attach/review"),
            json!({ "mapping": MAPPING, "host": "1-7" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = harness
        .call(
            &format!("/machines/{machine}/usb/attach/review"),
            json!({ "mapping": "a,host=1-7" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(harness.port.seen().is_empty());
}

#[tokio::test]
async fn each_action_has_its_own_catalog_entry_and_a_lab_credential_has_neither() {
    // Attach denied, detach allowed.
    let harness = Harness::new(Arc::new(Deny(Permission::MachineUsbAttach))).await;
    let machine = harness.machine.clone();
    harness
        .holds(&machine, VMID, HardwareReservationState::Attached)
        .await;
    let (status, answer) = harness.review_attach(&machine).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    let (status, _) = harness.attach(&machine, "anything").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, review) = harness.review_detach(&machine).await;
    assert_eq!(status, StatusCode::OK, "{review}");
    assert!(harness.port.seen().is_empty());

    // Detach denied, attach allowed.
    let harness = Harness::new(Arc::new(Deny(Permission::MachineUsbDetach))).await;
    let machine = harness.machine.clone();
    harness
        .holds(&machine, VMID, HardwareReservationState::Attached)
        .await;
    let (status, _) = harness.review_detach(&machine).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = harness.detach(&machine, "anything").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = harness.review_attach(&machine).await;
    assert_eq!(status, StatusCode::OK);
    assert!(harness.port.seen().is_empty());

    // A delegated Lab credential (ADR 0011) has a row for neither, whatever
    // machine it names.
    let authorizer: Arc<dyn Authorizer> = Arc::new(fleet_auth::delegated::ScopedAuthorizer::new(
        Arc::new(fleet_application::credentials::GrantBook::new()),
    ));
    let harness = Harness::new(authorizer).await;
    let machine = harness.machine.clone();
    harness
        .holds(&machine, VMID, HardwareReservationState::Attached)
        .await;
    let credential = fleet_application::authz::delegated_principal_id("agent", "cred-1");
    for (path, body) in [
        (
            format!("/machines/{machine}/usb/attach/review"),
            json!({ "mapping": MAPPING }),
        ),
        (
            format!("/machines/{machine}/usb/attach"),
            json!({ "mapping": MAPPING, "reviewToken": "x" }),
        ),
        (
            format!("/machines/{machine}/usb/detach/review"),
            json!({ "mapping": MAPPING }),
        ),
        (
            format!("/machines/{machine}/usb/detach"),
            json!({ "mapping": MAPPING, "reviewToken": "x" }),
        ),
    ] {
        let (status, answer) = harness.call_as(&credential, &path, &body.to_string()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {answer}");
    }
    assert!(harness.port.seen().is_empty());
}

#[tokio::test]
async fn refusals_carry_their_reason_and_a_backend_failure_is_not_shown() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine.clone();

    // An unknown machine.
    let (status, answer) = harness.review_attach("no-such-machine").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");

    // A machine without a guest link.
    let bare = fleet_storage_sqlite::MachineRepository::new(harness.pool.clone())
        .register(&fleet_application::machine::RegisterMachine {
            name: "bare".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: "root@bare.invalid:22".to_owned(),
            }],
            tags: vec![],
            groups: vec![],
        })
        .await
        .unwrap();
    let (status, answer) = harness.review_attach(&bare.id).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "machine_has_no_guest");

    // A device another owner holds, found at the review (nothing queues).
    harness
        .hardware
        .insert_reservation(
            &NewHardwareReservation {
                id: "reservation-9".to_owned(),
                device_id: "device-1".to_owned(),
                owner_kind: ReservationOwnerKind::Machine,
                owner_id: harness.registered.clone(),
                guest: None,
            },
            1,
        )
        .await
        .unwrap();
    let (status, answer) = harness.review_attach(&machine).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "hardware_busy");
    assert!(
        answer["message"]
            .as_str()
            .unwrap()
            .contains(&harness.registered),
        "{answer}"
    );

    // What the port refuses is the answer, with its reason as the code.
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine.clone();
    let (_, review) = harness.review_attach(&machine).await;
    harness.port.answer(Err(HotplugError::refused(
        "hardware_attach_pending",
        "PVE would keep the attach pending until the guest restarts",
    )));
    let (status, answer) = harness.attach(&machine, &token(&review)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "hardware_attach_pending");
    harness.port.answer(Err(HotplugError::Backend {
        detail: "sqlite said something private".to_owned(),
    }));
    let (status, answer) = harness.attach(&machine, &token(&review)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!answer.to_string().contains("private"), "{answer}");
}

#[tokio::test]
async fn without_the_composition_the_routes_answer_unavailable() {
    let harness = Harness::with(Arc::new(Permit), false).await;
    let machine = harness.machine.clone();
    let (status, answer) = harness.review_attach(&machine).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    let (status, _) = harness.detach(&machine, "x").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn the_guest_cannot_be_destroyed_reverted_or_templated_while_its_machine_holds_a_device() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let machine = harness.machine.clone();
    let reservation = harness
        .holds(&machine, VMID, HardwareReservationState::Attached)
        .await;
    for (action, params) in [
        ("destroy", json!({ "confirmPersistent": true })),
        ("snapshot-revert", json!({ "snapshot": "baseline" })),
        ("template", json!({})),
    ] {
        for step in ["review", "run"] {
            let (status, answer) = harness
                .call(
                    &format!("/proxmox/accounts/{ACCOUNT}/guests/{VMID}/{action}/{step}"),
                    json!({
                        "node": "pve",
                        "params": params,
                        "reviewToken": "x",
                        "timeoutSeconds": 300
                    }),
                )
                .await;
            assert_eq!(status, StatusCode::CONFLICT, "{action} {step}: {answer}");
            assert_eq!(answer["code"], "hardware_attached", "{action} {step}");
            let message = answer["message"].as_str().unwrap();
            assert!(message.contains("machines usb detach"), "{message}");
            assert!(message.contains(&machine), "{message}");
            assert!(message.contains(MAPPING), "{message}");
        }
    }
    // A guest nobody holds a device on is not affected.
    let (status, answer) = harness
        .call(
            &format!("/proxmox/accounts/{ACCOUNT}/guests/{OTHER_VMID}/template/review"),
            json!({ "node": "pve", "params": {} }),
        )
        .await;
    assert_ne!(status, StatusCode::CONFLICT, "{answer}");

    // Released, the review goes through.
    harness
        .hardware
        .force_release_reservation(&reservation, 2)
        .await
        .unwrap();
    let (status, answer) = harness
        .call(
            &format!("/proxmox/accounts/{ACCOUNT}/guests/{VMID}/template/review"),
            json!({ "node": "pve", "params": {} }),
        )
        .await;
    assert_ne!(status, StatusCode::CONFLICT, "{answer}");
}

#[tokio::test]
async fn a_registered_marker_is_not_unregistered_while_its_machine_holds_a_device() {
    let harness = Harness::new(Arc::new(Permit)).await;
    let registered = harness.registered.clone();
    let reservation = harness
        .holds(&registered, OTHER_VMID, HardwareReservationState::Attached)
        .await;
    let path = format!("/machines/persistent/{ACCOUNT}/{OTHER_VMID}/unregister");

    let (status, answer) = harness.call(&format!("{path}/review"), json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    let message = answer["message"].as_str().unwrap();
    assert!(message.contains("machines usb detach"), "{message}");
    let (_, review_token) = PersistentMachines::unregister_payload(ACCOUNT, OTHER_VMID);
    let (status, answer) = harness
        .call(&path, json!({ "reviewToken": review_token }))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");

    // Released, it goes through.
    harness
        .hardware
        .force_release_reservation(&reservation, 2)
        .await
        .unwrap();
    let (status, answer) = harness.call(&format!("{path}/review"), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let (status, answer) = harness
        .call(&path, json!({ "reviewToken": review_token }))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{answer}");
}
