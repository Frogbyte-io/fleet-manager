//! The hardware inventory end to end (FM-1111): a real controller router and
//! SQLite store over a scripted Proxmox VE answering in the shapes FM-S11
//! recorded. Every device status comes out of the provider's real reads, the
//! trust gate holds, a refresh is audited and never mutates Proxmox, a
//! refused caller gets a 403 before anything is called, a stale observation
//! reads `missing`, and every answer matches the checked-in `OpenAPI` document.

#[path = "../../fleet-api/tests/support/hardware_pve.rs"]
mod hardware_pve;
#[path = "../../fleet-api/tests/support/openapi_shape.rs"]
mod openapi_shape;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleet_api::{API_BASE_PATH, CORRELATION_ID_HEADER, operations::ApiState};
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::hardware::{HardwareStore as _, NewHardwareReservation};
use fleet_core::{GuestTarget, HardwareReservationState, ReservationOwnerKind};
use fleet_storage_sqlite::HardwareRepository;
use hardware_pve::{SECRET, ScriptedPve, World};
use serde_json::{Value, json};
use tower::ServiceExt as _;

fn device<'a>(body: &'a Value, mapping: &str) -> &'a Value {
    body["devices"]
        .as_array()
        .or_else(|| body["items"].as_array())
        .unwrap()
        .iter()
        .find(|device| device["mappingId"] == mapping)
        .unwrap_or_else(|| panic!("no device {mapping} in {body}"))
}

async fn refresh(world: &World, account: &str) -> (u16, Value) {
    world
        .raw(
            "POST",
            "/api/v1/hardware/refresh",
            Some(json!({ "accountId": account })),
        )
        .await
}

#[tokio::test]
async fn a_refresh_reads_proxmox_and_every_status_comes_out_with_its_reason() {
    let world = World::start(ScriptedPve::standard()).await;
    let account = world.account(true).await;
    world.pve.clear_calls();

    let (status, body) = refresh(&world, &account).await;
    assert_eq!(status, 200, "{body}");
    let report = &body["data"];
    assert_eq!(report["accountId"], account.as_str());
    assert_eq!(report["pveVersion"], "9.2.2");
    assert_eq!(
        report["support"],
        json!({"state": "supported", "reason": null, "detail": null})
    );
    assert_eq!(
        report["guestScan"],
        json!({"listed": 3, "read": 3, "unreadable": 0, "truncated": false})
    );

    let expect = |mapping: &str, status: &str, reason: Option<&str>| {
        let device = device(report, mapping);
        assert_eq!(device["status"], status, "{mapping}: {device}");
        assert_eq!(
            device["reason"],
            reason.map_or(Value::Null, |reason| json!(reason)),
            "{mapping}: {device}"
        );
        assert_eq!(device["kind"], "usb");
        // Staleness is "not seen within the bound": a device that was never
        // seen on its node (fm-c) has no recent sighting, whatever this
        // refresh found.
        assert_eq!(device["stale"], mapping == "fm-c", "{mapping}: {device}");
        assert_eq!(
            device["reasonText"].is_string(),
            reason.is_some(),
            "{device}"
        );
    };
    // The template that carries fm-a holds nothing: it is available.
    expect("fm-a", "available", None);
    // The Decker case: a guest holds fm-b by hand.
    expect("fm-b", "externally_attached", None);
    expect("fm-c", "missing", None);
    expect("fm-d", "unsupported", Some("no_node_entry"));
    expect("fm-e", "unsupported", Some("ambiguous_mapping"));
    expect("fm-f", "unsupported", Some("token_lacks_mapping_use"));
    expect("fm-g", "available", None);

    // The external device names the guest and the template reference is
    // listed as one.
    let b = device(report, "fm-b");
    assert_eq!(
        b["observation"]["externalReferences"],
        json!([{
            "node": "pve", "vmid": 200, "guestName": "guest-a",
            "slot": "usb0", "template": false, "pending": null
        }])
    );
    let a = device(report, "fm-a");
    assert_eq!(a["observation"]["externalReferences"][0]["template"], true);
    // The missing device carries the finding behind it.
    assert!(
        device(report, "fm-c")["observation"]["notes"][0]
            .as_str()
            .unwrap()
            .contains("not found")
    );
    // Entries carry the mapping's own fingerprint: vendor:product and port.
    assert_eq!(device(report, "fm-a")["entries"][0]["vendorId"], "aaaa");
    assert_eq!(device(report, "fm-a")["entries"][0]["usbpath"], "1-1");

    // Every call was a pinned GET (the transport asserts it) and the node
    // inventory's 403 is a normal answer, not a warning.
    let calls = world.pve.calls();
    assert!(
        calls.iter().all(|call| call.starts_with("GET ")),
        "{calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|call| call == "GET /api2/json/cluster/mapping/usb?check-node=pve"),
        "{calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|call| call.ends_with("/qemu/200/config?current=1")),
        "the applied view of a running guest is read: {calls:?}"
    );
    assert!(
        !calls
            .iter()
            .any(|call| call.contains("/qemu/201/config?current=1")),
        "a stopped guest has no applied view: {calls:?}"
    );
    assert_eq!(report["warnings"], json!([]), "{report}");

    // The token never reaches an answer.
    assert!(!body.to_string().contains(SECRET));

    // The same page the list returns, minus what only a refresh observes.
    let (status, listed) = world.raw("GET", "/api/v1/hardware/devices", None).await;
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed["items"].as_array().unwrap().len(), 7);
    assert_eq!(device(&listed, "fm-b")["status"], "externally_attached");
    assert!(device(&listed, "fm-b")["observation"].is_null());
    assert_eq!(
        listed["items"][0]["mappingId"], "fm-a",
        "ordered by mapping id"
    );
}

#[tokio::test]
async fn the_answers_match_the_openapi_document() {
    let world = World::start(ScriptedPve::standard()).await;
    let account = world.account(true).await;
    let spec = openapi_shape::spec();

    let (_, refreshed) = refresh(&world, &account).await;
    openapi_shape::assert_matches_schema(&spec, "HardwareRefreshDto", &refreshed["data"]);
    let (_, listed) = world.raw("GET", "/api/v1/hardware/devices", None).await;
    for item in listed["items"].as_array().unwrap() {
        openapi_shape::assert_matches_schema(&spec, "HardwareDeviceDto", item);
    }
    // A held device carries its holder in the same documented shape.
    let repository = HardwareRepository::new(world.pool.clone());
    let g = repository
        .device_by_mapping(&account, "fm-g")
        .await
        .unwrap()
        .unwrap();
    repository
        .insert_reservation(
            &NewHardwareReservation {
                id: "res-g".to_owned(),
                device_id: g.id,
                owner_kind: ReservationOwnerKind::Lease,
                owner_id: "lease-1".to_owned(),
                guest: Some(GuestTarget {
                    account_id: account.clone(),
                    node: "pve".to_owned(),
                    vmid: 9100,
                    usb_slot: Some(1),
                }),
            },
            1,
        )
        .await
        .unwrap();
    let (_, listed) = world.raw("GET", "/api/v1/hardware/devices", None).await;
    let held = device(&listed, "fm-g");
    assert_eq!(held["status"], "reserved");
    assert_eq!(held["holder"]["ownerKind"], "lease");
    assert_eq!(held["holder"]["guest"]["usbSlot"], 1);
    openapi_shape::assert_matches_schema(&spec, "HardwareDeviceDto", held);
    // And the page envelope.
    assert!(listed["page"]["limit"].is_u64());
}

#[tokio::test]
async fn a_reserved_device_is_not_external_and_an_unknown_attach_is_quarantined() {
    let world = World::start(ScriptedPve::standard()).await;
    let account = world.account(true).await;
    refresh(&world, &account).await;
    let repository = HardwareRepository::new(world.pool.clone());
    let reserve = |mapping: &'static str, id: &'static str, vmid: u32| {
        let repository = &repository;
        let account = account.clone();
        async move {
            let device = repository
                .device_by_mapping(&account, mapping)
                .await
                .unwrap()
                .unwrap();
            repository
                .insert_reservation(
                    &NewHardwareReservation {
                        id: id.to_owned(),
                        device_id: device.id,
                        owner_kind: ReservationOwnerKind::Machine,
                        owner_id: format!("machine-{id}"),
                        guest: Some(GuestTarget {
                            account_id: account,
                            node: "pve".to_owned(),
                            vmid,
                            usb_slot: None,
                        }),
                    },
                    1,
                )
                .await
                .unwrap();
        }
    };
    // fm-b is Fleet's own now: guest 200 holds it under a reservation.
    reserve("fm-b", "res-b", 200).await;
    reserve("fm-g", "res-g", 9100).await;
    repository
        .transition_reservation(
            "res-g",
            HardwareReservationState::Held,
            HardwareReservationState::Attaching,
            None,
            2,
        )
        .await
        .unwrap();
    repository
        .transition_reservation(
            "res-g",
            HardwareReservationState::Attaching,
            HardwareReservationState::AttachUnknown,
            None,
            3,
        )
        .await
        .unwrap();
    let (status, body) = refresh(&world, &account).await;
    assert_eq!(status, 200, "{body}");
    let report = &body["data"];
    assert_eq!(device(report, "fm-b")["status"], "reserved");
    assert_eq!(
        device(report, "fm-b")["observation"]["externalReferences"],
        json!([]),
        "the reservation's own guest is not an external reference"
    );
    assert_eq!(device(report, "fm-g")["status"], "quarantined");
    assert_eq!(device(report, "fm-g")["holder"]["state"], "attach_unknown");
}

#[tokio::test]
async fn a_stale_observation_reads_missing_until_the_next_refresh() {
    let world = World::start(ScriptedPve::standard()).await;
    let account = world.account(true).await;
    refresh(&world, &account).await;
    // Seen an hour ago (the default bound is fifteen minutes).
    let hour_ago = fleet_core::SystemClock::now_unix_millis() - 3_600_000;
    sqlx::query("UPDATE hardware_device_entries SET last_seen_at = ?1")
        .bind(hour_ago)
        .execute(&world.pool)
        .await
        .unwrap();
    let (_, listed) = world.raw("GET", "/api/v1/hardware/devices", None).await;
    let a = device(&listed, "fm-a");
    assert_eq!(a["status"], "missing", "{a}");
    assert_eq!(a["stale"], true);
    assert_eq!(a["observedAt"], hour_ago);
    // The record still says what was observed, and other statuses keep
    // their meaning with the flag.
    let b = device(&listed, "fm-b");
    assert_eq!(b["status"], "externally_attached");
    assert_eq!(b["stale"], true);

    refresh(&world, &account).await;
    let (_, listed) = world.raw("GET", "/api/v1/hardware/devices", None).await;
    assert_eq!(device(&listed, "fm-a")["status"], "available");
    assert_eq!(device(&listed, "fm-a")["stale"], false);
}

#[tokio::test]
async fn a_token_without_the_opt_in_role_reports_the_reason_not_an_empty_inventory() {
    let pve = ScriptedPve::standard();
    // An auditor: Mapping.Audit everywhere, no Mapping.Use, no HWType.
    pve.data(
        "/api2/json/access/permissions",
        &json!({"/": {"Mapping.Audit": 1, "VM.Audit": 1}}),
    );
    let world = World::start(pve).await;
    let account = world.account(true).await;
    let (status, body) = refresh(&world, &account).await;
    assert_eq!(status, 200, "{body}");
    let report = &body["data"];
    assert_eq!(report["support"]["state"], "supported");
    assert_eq!(device(report, "fm-a")["status"], "unsupported");
    assert_eq!(device(report, "fm-a")["reason"], "token_lacks_mapping_use");
    assert!(
        device(report, "fm-a")["reasonText"]
            .as_str()
            .unwrap()
            .contains("FleetUsb")
    );
    // Evidence the token cannot allocate on is still reported.
    assert_eq!(
        device(report, "fm-b")["observation"]["externalReferences"][0]["vmid"],
        200
    );
}

#[tokio::test]
async fn without_mapping_audit_the_empty_list_is_no_mapping_audit_and_no_device_is_lost() {
    let pve = ScriptedPve::standard();
    let world = World::start(pve.clone()).await;
    let account = world.account(true).await;
    refresh(&world, &account).await;
    let (_, before) = world.raw("GET", "/api/v1/hardware/devices", None).await;

    // PVE answers an unprivileged listing with an empty 200.
    pve.data("/api2/json/cluster/mapping/usb", &json!([]));
    pve.data(
        "/api2/json/access/permissions",
        &json!({"/vms": {"VM.Audit": 1}}),
    );
    let (status, body) = refresh(&world, &account).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["support"]["state"], "unsupported", "{body}");
    assert_eq!(body["data"]["support"]["reason"], "no_mapping_audit");
    assert!(body["data"]["guestScan"].is_null());
    let (_, after) = world.raw("GET", "/api/v1/hardware/devices", None).await;
    assert_eq!(before["items"], after["items"], "nothing was touched");

    // The same empty list with Mapping.Audit held is genuinely no mappings.
    pve.data(
        "/api2/json/access/permissions",
        &json!({"/mapping/usb": {"Mapping.Audit": 1}}),
    );
    let (_, body) = refresh(&world, &account).await;
    assert_eq!(body["data"]["support"]["state"], "supported");
    assert!(
        body["data"]["devices"]
            .as_array()
            .unwrap()
            .iter()
            .all(|device| device["reason"] == "no_node_entry")
    );
}

#[tokio::test]
async fn an_old_proxmox_without_the_mapping_endpoint_is_pve_too_old() {
    let pve = ScriptedPve::standard();
    let world = World::start(pve.clone()).await;
    let account = world.account(true).await;
    refresh(&world, &account).await;
    pve.data(
        "/api2/json/version",
        &json!({"version": "7.4-3", "release": "7.4"}),
    );
    pve.route(
        "/api2/json/cluster/mapping/usb",
        501,
        r#"{"data":null,"message":"Method 'GET /cluster/mapping/usb' not implemented"}"#,
    );
    let (status, body) = refresh(&world, &account).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["support"]["reason"], "pve_too_old");
    assert_eq!(body["data"]["pveVersion"], "7.4-3");
    for item in body["data"]["devices"].as_array().unwrap() {
        assert_eq!(item["reason"], "pve_too_old", "{item}");
    }
}

#[tokio::test]
async fn a_guest_that_cannot_be_read_is_counted_and_never_fatal() {
    let pve = ScriptedPve::standard();
    pve.route(
        "/api2/json/nodes/pve/qemu/201/config",
        403,
        r#"{"data":null,"message":"Permission check failed (/vms/201, VM.Audit)"}"#,
    );
    let world = World::start(pve).await;
    let account = world.account(true).await;
    let (status, body) = refresh(&world, &account).await;
    assert_eq!(status, 200, "{body}");
    let report = &body["data"];
    assert_eq!(
        report["guestScan"],
        json!({"listed": 3, "read": 2, "unreadable": 1, "truncated": false})
    );
    assert_eq!(device(report, "fm-b")["status"], "externally_attached");
    let warnings = report["warnings"].to_string();
    assert!(warnings.contains("qemu/201"), "{warnings}");
    assert!(warnings.contains("guest scan is incomplete"), "{warnings}");
    assert!(!warnings.contains(SECRET));
}

#[tokio::test]
async fn an_unconfirmed_account_sends_no_credential_and_an_unknown_one_is_404() {
    let world = World::start(ScriptedPve::standard()).await;
    let account = world.account(false).await;
    let (status, body) = refresh(&world, &account).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["code"], "proxmox_unconfirmed");
    assert!(world.pve.calls().is_empty(), "no credential left the host");

    let (status, body) = refresh(&world, "no-such-account").await;
    assert_eq!(status, 404, "{body}");
    let (status, body) = world
        .raw(
            "GET",
            "/api/v1/hardware/devices?accountId=no-such-account",
            None,
        )
        .await;
    assert_eq!(status, 404, "{body}");
}

#[tokio::test]
async fn a_refresh_is_audited_without_secrets_and_the_list_is_not() {
    let world = World::start(ScriptedPve::standard()).await;
    let account = world.account(true).await;
    refresh(&world, &account).await;
    world.raw("GET", "/api/v1/hardware/devices", None).await;
    let rows: Vec<(String, Option<String>, String, String)> = sqlx::query_as(
        "SELECT action, resource, metadata_json, actor FROM audit_events \
         WHERE action LIKE 'hardware.%' ORDER BY seq",
    )
    .fetch_all(&world.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    for (action, resource, metadata, _) in &rows {
        assert_eq!(action, "hardware.refresh");
        assert_eq!(resource.as_deref(), Some(account.as_str()));
        assert!(!metadata.contains(SECRET), "{metadata}");
        assert!(!metadata.contains("192.0.2.10"), "{metadata}");
    }
    assert!(rows[0].2.contains("hardware_refresh_started"));
    assert!(rows[1].2.contains("hardware_refreshed"));
    assert!(rows[1].2.contains("externally_attached=1"), "{}", rows[1].2);
}

#[tokio::test]
async fn the_list_pages_and_filters_by_account() {
    let world = World::start(ScriptedPve::standard()).await;
    let account = world.account(true).await;
    refresh(&world, &account).await;
    let (_, first) = world
        .raw("GET", "/api/v1/hardware/devices?limit=3", None)
        .await;
    assert_eq!(first["items"].as_array().unwrap().len(), 3);
    let cursor = first["page"]["nextCursor"].as_str().unwrap().to_owned();
    let (_, second) = world
        .raw(
            "GET",
            &format!("/api/v1/hardware/devices?limit=10&cursor={cursor}&accountId={account}"),
            None,
        )
        .await;
    assert_eq!(second["items"].as_array().unwrap().len(), 4);
    assert!(second["page"]["nextCursor"].is_null());
    let (status, _) = world
        .raw("GET", "/api/v1/hardware/devices?cursor=nope", None)
        .await;
    assert_eq!(status, 400);
}

// ── authorization over the HTTP surface ─────────────────────────────────

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

async fn call(
    state: &Arc<ApiState>,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("{API_BASE_PATH}{path}"))
        .header(
            CORRELATION_ID_HEADER,
            "01900000-0000-7000-8000-000000000000",
        );
    let payload = match body {
        Some(body) => {
            builder = builder.header("content-type", "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    let app = fleet_api::router(state.clone()).layer(axum::Extension(fleet_api::ActingPrincipal {
        id: fleet_auth::LAN_PRINCIPAL_ID.to_owned(),
    }));
    let response = app.oneshot(builder.body(payload).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

#[tokio::test]
async fn a_caller_without_the_permission_gets_a_403_before_anything_is_called() {
    use fleet_controller::proxmox_store::compose_proxmox;
    let pve = ScriptedPve::standard();
    let dir = tempfile::tempdir().unwrap();
    let store = fleet_storage_sqlite::Store::open(&dir.path().join("fleet.db"))
        .await
        .unwrap();
    let key = dir.path().join("master.key");
    std::fs::write(
        &key,
        "1 0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let secrets = Arc::new(fleet_secrets::SecretStore::open(store.pool().clone(), &key).unwrap());
    let proxmox = Arc::new(compose_proxmox(
        store.pool().clone(),
        secrets,
        pve.clone(),
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    ));
    let operations = Arc::new(fleet_application::operation::Operations::new(
        Arc::new(fleet_storage_sqlite::OperationRepository::new(
            store.pool().clone(),
        )),
        Arc::new(fleet_storage_sqlite::AuditSink::new(store.pool().clone())),
    ));
    let state = |authorizer: Arc<dyn Authorizer>| {
        Arc::new(ApiState {
            operations: operations.clone(),
            authorizer,
            proxmox: Some(proxmox.clone()),
            ..ApiState::for_document()
        })
    };
    // Create and trust the account with an unrestricted caller.
    let open = state(Arc::new(fleet_auth::LanAllowAllAuthorizer));
    let (status, body) = call(
        &open,
        "POST",
        "/proxmox/accounts",
        Some(json!({
            "name": "pve-main", "host": "192.0.2.10", "port": 8006,
            "tokenId": "fleet@pve!fleet", "tokenSecret": SECRET
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let account = body["data"]["id"].as_str().unwrap().to_owned();
    call(
        &open,
        "POST",
        &format!("/proxmox/accounts/{account}/observe"),
        Some(json!({})),
    )
    .await;
    let (status, body) = call(
        &open,
        "POST",
        &format!("/proxmox/accounts/{account}/confirm"),
        Some(json!({"fingerprint": hardware_pve::FP})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    pve.clear_calls();

    // Without `hardware.refresh` nothing is called, nothing is audited.
    let refused = state(Arc::new(Deny(Permission::HardwareRefresh)));
    let (status, body) = call(
        &refused,
        "POST",
        "/hardware/refresh",
        Some(json!({"accountId": account})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(pve.calls().is_empty(), "{:?}", pve.calls());
    let audited: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'hardware.refresh'")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(audited, 0);

    // `hardware.read` does not refresh, and refresh does not read.
    let (status, _) = call(&refused, "GET", "/hardware/devices", None).await;
    assert_eq!(status, StatusCode::OK);
    let no_read = state(Arc::new(Deny(Permission::HardwareRead)));
    let (status, body) = call(&no_read, "GET", "/hardware/devices", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, _) = call(
        &no_read,
        "POST",
        "/hardware/refresh",
        Some(json!({"accountId": account})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    std::mem::forget(store);
}

#[tokio::test]
async fn the_hardware_surface_is_503_when_the_proxmox_surface_is_not_wired() {
    let state = Arc::new(ApiState::for_document());
    let (status, body) = call(&state, "GET", "/hardware/devices", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
}
