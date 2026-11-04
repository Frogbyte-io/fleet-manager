//! `fleetctl hardware` (FM-1111): the grammar, and the contract that
//! `--output json` is the controller's answer unchanged: `hardware list`
//! prints the API's page and `hardware refresh` the API's `data`, both
//! checked against a real controller over a scripted Proxmox VE and against
//! the checked-in `OpenAPI` document. `hardware override-release` (FM-1124)
//! needs its confirmation flag before anything is sent.

#[path = "../../fleet-api/tests/support/hardware_pve.rs"]
mod hardware_pve;
#[path = "../../fleet-api/tests/support/openapi_shape.rs"]
mod openapi_shape;

use fleetctl::hardware::HardwareAction;
use hardware_pve::{ScriptedPve, World};
use serde_json::{Value, json};

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(ToString::to_string).collect()
}

fn action(words: &[&str]) -> HardwareAction {
    match fleetctl::parse(&args(words)).expect("parses").command {
        fleetctl::Command::Hardware(action) => action,
        other => panic!("not a hardware command: {other:?}"),
    }
}

#[test]
fn the_grammar_covers_list_and_refresh() {
    assert_eq!(
        action(&["hardware", "list"]),
        HardwareAction::List {
            account: None,
            limit: None,
            cursor: None
        }
    );
    assert_eq!(
        action(&[
            "hardware",
            "list",
            "--account",
            "acc-1",
            "--limit",
            "5",
            "--cursor",
            "dev-9"
        ]),
        HardwareAction::List {
            account: Some("acc-1".to_owned()),
            limit: Some(5),
            cursor: Some("dev-9".to_owned())
        }
    );
    assert_eq!(
        action(&["hardware", "refresh", "--account", "acc-1"]),
        HardwareAction::Refresh {
            account: "acc-1".to_owned()
        }
    );
    // `--output` after the verb and the global form before the command word.
    let invocation = fleetctl::parse(&args(&["hardware", "list", "--output", "json"])).unwrap();
    assert_eq!(invocation.output, fleetctl::Output::Json);
    let invocation = fleetctl::parse(&args(&["--output", "json", "hardware", "list"])).unwrap();
    assert_eq!(invocation.output, fleetctl::Output::Json);
    assert_eq!(
        fleetctl::parse(&args(&["hardware", "list"]))
            .unwrap()
            .output,
        fleetctl::Output::Text
    );
}

#[test]
fn the_grammar_covers_override_release_and_demands_its_confirmation() {
    assert_eq!(
        action(&[
            "hardware",
            "override-release",
            "res-1",
            "--confirm-unverified"
        ]),
        HardwareAction::OverrideRelease {
            reservation: "res-1".to_owned()
        }
    );
    // The flag may come first, and `--output` is accepted.
    assert_eq!(
        action(&[
            "hardware",
            "override-release",
            "res-1",
            "--output",
            "json",
            "--confirm-unverified"
        ]),
        HardwareAction::OverrideRelease {
            reservation: "res-1".to_owned()
        }
    );
    // Without the confirmation nothing is sent: the refusal says why.
    let error = fleetctl::parse(&args(&["hardware", "override-release", "res-1"]))
        .unwrap_err()
        .message;
    assert!(error.contains("--confirm-unverified"), "{error}");
    assert!(
        error.contains("without Fleet verifying the guest"),
        "{error}"
    );
    for words in [
        vec!["hardware", "override-release"],
        vec!["hardware", "override-release", "--confirm-unverified"],
        vec![
            "hardware",
            "override-release",
            "res-1",
            "--confirm-unverified",
            "--account",
            "acc-1",
        ],
        vec![
            "hardware",
            "override-release",
            "res-1",
            "res-2",
            "--confirm-unverified",
        ],
        vec![
            "hardware",
            "refresh",
            "--account",
            "acc-1",
            "--confirm-unverified",
        ],
        vec!["hardware", "list", "--confirm-unverified"],
    ] {
        assert!(fleetctl::parse(&args(&words)).is_err(), "{words:?}");
    }
}

#[test]
fn undocumented_forms_are_refused() {
    for words in [
        vec!["hardware"],
        vec!["hardware", "attach"],
        vec!["hardware", "refresh"],
        vec!["hardware", "refresh", "acc-1"],
        vec!["hardware", "refresh", "--account"],
        vec!["hardware", "refresh", "--account", "--output", "json"],
        vec!["hardware", "refresh", "--account", "acc-1", "--limit", "3"],
        vec!["hardware", "list", "--limit", "many"],
        vec!["hardware", "list", "--output", "xml"],
        vec!["hardware", "list", "--serial", "x"],
        vec!["hardware", "list", "acc-1"],
    ] {
        assert!(fleetctl::parse(&args(&words)).is_err(), "{words:?}");
    }
}

/// Runs the CLI against the controller, off the async runtime (the client
/// blocks).
async fn cli(world: &World, words: &[&str]) -> Result<String, String> {
    let url = world.url();
    let mut all = vec!["--url".to_owned(), url];
    all.extend(words.iter().map(ToString::to_string));
    tokio::task::spawn_blocking(move || {
        let invocation = fleetctl::parse(&all).map_err(|error| error.message)?;
        fleetctl::run(&invocation).map_err(|error| error.message)
    })
    .await
    .unwrap()
}

/// What changes between two runs of the same refresh: timestamps.
fn without_times(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for key in [
                "observedAt",
                "lastSeenAt",
                "updatedAt",
                "createdAt",
                "reservedAt",
            ] {
                map.remove(key);
            }
            for member in map.values_mut() {
                without_times(member);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(without_times),
        _ => {}
    }
}

#[tokio::test]
async fn list_json_is_the_api_page_and_refresh_json_is_the_api_data() {
    let world = World::start(ScriptedPve::standard()).await;
    let account = world.account(true).await;
    let spec = openapi_shape::spec();

    // Refresh first, as an operator would.
    let printed = cli(
        &world,
        &[
            "--output",
            "json",
            "hardware",
            "refresh",
            "--account",
            &account,
        ],
    )
    .await
    .expect("a refresh");
    let mut printed: Value = serde_json::from_str(&printed).expect("JSON");
    openapi_shape::assert_matches_schema(&spec, "HardwareRefreshDto", &printed);
    let (status, mut api) = world
        .raw(
            "POST",
            "/api/v1/hardware/refresh",
            Some(json!({ "accountId": account })),
        )
        .await;
    assert_eq!(status, 200, "{api}");
    let mut api_data = api["data"].take();
    without_times(&mut printed);
    without_times(&mut api_data);
    assert_eq!(printed, api_data, "the CLI prints the API's data");

    // The list: byte-for-byte the API's page.
    let printed = cli(&world, &["--output", "json", "hardware", "list"])
        .await
        .expect("a list");
    let printed: Value = serde_json::from_str(&printed).expect("JSON");
    let (status, api) = world.raw("GET", "/api/v1/hardware/devices", None).await;
    assert_eq!(status, 200, "{api}");
    assert_eq!(printed, api, "the CLI prints the API's page");
    for item in printed["items"].as_array().unwrap() {
        openapi_shape::assert_matches_schema(&spec, "HardwareDeviceDto", item);
    }
    let statuses: Vec<(&str, &str)> = printed["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["mappingId"].as_str().unwrap(),
                item["status"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        statuses,
        [
            ("fm-a", "available"),
            ("fm-b", "externally_attached"),
            ("fm-c", "missing"),
            ("fm-d", "unsupported"),
            ("fm-e", "unsupported"),
            ("fm-f", "unsupported"),
            ("fm-g", "available"),
        ]
    );

    // The flags are the API's parameters.
    let printed = cli(
        &world,
        &[
            "--output",
            "json",
            "hardware",
            "list",
            "--account",
            &account,
            "--limit",
            "2",
        ],
    )
    .await
    .unwrap();
    let printed: Value = serde_json::from_str(&printed).unwrap();
    let (_, api) = world
        .raw(
            "GET",
            &format!("/api/v1/hardware/devices?accountId={account}&limit=2"),
            None,
        )
        .await;
    assert_eq!(printed, api);
    assert_eq!(printed["items"].as_array().unwrap().len(), 2);
    assert!(printed["page"]["nextCursor"].is_string());
}

#[tokio::test]
async fn the_text_output_names_the_status_the_reason_and_the_holder_of_each_device() {
    let world = World::start(ScriptedPve::standard()).await;
    let account = world.account(true).await;

    let empty = cli(&world, &["hardware", "list"]).await.unwrap();
    assert!(empty.contains("hardware refresh"), "{empty}");

    let refreshed = cli(&world, &["hardware", "refresh", "--account", &account])
        .await
        .unwrap();
    assert!(refreshed.contains("PVE 9.2.2"), "{refreshed}");
    assert!(refreshed.contains("supported"), "{refreshed}");
    assert!(
        refreshed.contains("guest scan: 3 listed, 3 read, 0 unreadable"),
        "{refreshed}"
    );
    let line = |text: &str, mapping: &str| {
        text.lines()
            .find(|line| line.starts_with(mapping))
            .unwrap_or_else(|| panic!("no row for {mapping} in\n{text}"))
            .to_owned()
    };
    assert!(line(&refreshed, "fm-a").contains("available"));
    assert!(line(&refreshed, "fm-b").contains("externally_attached"));
    assert!(line(&refreshed, "fm-e").contains("unsupported (ambiguous_mapping)"));
    assert!(line(&refreshed, "fm-f").contains("unsupported (token_lacks_mapping_use)"));
    // What an operator needs to act: who holds it, and why it is unusable.
    assert!(
        refreshed.contains("referenced by qemu/200 on pve (guest-a), usb0"),
        "{refreshed}"
    );
    assert!(refreshed.contains("FleetUsb"), "{refreshed}");
    assert!(
        refreshed.contains("not found"),
        "the finding behind missing: {refreshed}"
    );
    assert!(!refreshed.contains(hardware_pve::SECRET));

    let listed = cli(&world, &["hardware", "list"]).await.unwrap();
    assert!(line(&listed, "fm-c").contains("missing"));
    assert!(listed.contains("reads Fleet's own records"), "{listed}");
}

#[tokio::test]
async fn a_refusal_from_the_controller_is_an_error_not_an_empty_list() {
    let world = World::start(ScriptedPve::standard()).await;
    // An unconfirmed account: the controller refuses with 409.
    let account = world.account(false).await;
    let error = cli(&world, &["hardware", "refresh", "--account", &account])
        .await
        .unwrap_err();
    assert!(
        error.contains("409") || error.contains("proxmox_unconfirmed") || error.contains("confirm"),
        "{error}"
    );
    assert!(world.pve.calls().is_empty());
}

/// Puts the device `mapping`'s reservation in `attach_unknown` with a slot,
/// as a crash between the write and its record leaves it.
async fn stuck_reservation(world: &World, account: &str, mapping: &str) -> String {
    use fleet_application::hardware::{HardwareStore as _, NewHardwareReservation};
    use fleet_core::{GuestTarget, HardwareReservationState as State, ReservationOwnerKind};
    let repository = fleet_storage_sqlite::HardwareRepository::new(world.pool.clone());
    let device = repository
        .device_by_mapping(account, mapping)
        .await
        .unwrap()
        .expect("the device is inventoried");
    let id = "res-stuck-1".to_owned();
    repository
        .insert_reservation(
            &NewHardwareReservation {
                id: id.clone(),
                device_id: device.id,
                owner_kind: ReservationOwnerKind::Lease,
                owner_id: "lease-1".to_owned(),
                guest: None,
            },
            1,
        )
        .await
        .unwrap();
    let target = GuestTarget {
        account_id: account.to_owned(),
        node: "pve".to_owned(),
        vmid: 9100,
        usb_slot: Some(1),
    };
    repository
        .transition_reservation(&id, State::Held, State::Attaching, Some(&target), 2)
        .await
        .unwrap();
    repository
        .transition_reservation(
            &id,
            State::Attaching,
            State::AttachUnknown,
            Some(&target),
            3,
        )
        .await
        .unwrap();
    id
}

#[tokio::test]
async fn override_release_json_is_the_api_data_and_the_text_says_fleet_did_not_verify() {
    let world = World::start(ScriptedPve::standard()).await;
    let account = world.account(true).await;
    cli(&world, &["hardware", "refresh", "--account", &account])
        .await
        .unwrap();
    let id = stuck_reservation(&world, &account, "fm-g").await;
    world.pve.clear_calls();

    // Without the flag the CLI refuses and sends nothing.
    let refused = cli(&world, &["hardware", "override-release", &id])
        .await
        .unwrap_err();
    assert!(refused.contains("--confirm-unverified"), "{refused}");
    let state: String = sqlx::query_scalar("SELECT state FROM hardware_reservations WHERE id = ?1")
        .bind(&id)
        .fetch_one(&world.pool)
        .await
        .unwrap();
    assert_eq!(state, "attach_unknown");

    // With it: the API's data, in the documented shape.
    let printed = cli(
        &world,
        &[
            "--output",
            "json",
            "hardware",
            "override-release",
            &id,
            "--confirm-unverified",
        ],
    )
    .await
    .expect("an override release");
    let printed: Value = serde_json::from_str(&printed).expect("JSON");
    openapi_shape::assert_matches_schema(
        &openapi_shape::spec(),
        "HardwareOverrideReleaseDto",
        &printed,
    );
    assert_eq!(printed["outcome"], "released");
    assert_eq!(printed["previous"]["state"], "attach_unknown");
    assert_eq!(printed["previous"]["guest"]["usbSlot"], 1);
    assert_eq!(printed["guestVerified"], false);
    // It changed Fleet's record and called nothing on Proxmox.
    assert!(world.pve.calls().is_empty(), "{:?}", world.pve.calls());
    let (state, slot): (String, Option<i64>) =
        sqlx::query_as("SELECT state, usb_slot FROM hardware_reservations WHERE id = ?1")
            .bind(&id)
            .fetch_one(&world.pool)
            .await
            .unwrap();
    assert_eq!((state.as_str(), slot), ("released", None));

    // A repeat is the same command with the same exit and an honest text.
    let again = cli(
        &world,
        &["hardware", "override-release", &id, "--confirm-unverified"],
    )
    .await
    .expect("a repeat succeeds");
    assert!(again.contains("already released"), "{again}");
    assert!(again.contains("did not verify the guest"), "{again}");
    // The text of a first release names what it freed.
    let second = stuck_reservation_again(&world, &account).await;
    let text = cli(
        &world,
        &[
            "hardware",
            "override-release",
            &second,
            "--confirm-unverified",
        ],
    )
    .await
    .unwrap();
    assert!(text.contains("it was attach_unknown, usb1"), "{text}");
    assert!(text.contains("did not verify the guest"), "{text}");
}

/// A second stuck reservation on another device, for the text form.
async fn stuck_reservation_again(world: &World, account: &str) -> String {
    use fleet_application::hardware::{HardwareStore as _, NewHardwareReservation};
    use fleet_core::{GuestTarget, HardwareReservationState as State, ReservationOwnerKind};
    let repository = fleet_storage_sqlite::HardwareRepository::new(world.pool.clone());
    let device = repository
        .device_by_mapping(account, "fm-a")
        .await
        .unwrap()
        .unwrap();
    let id = "res-stuck-2".to_owned();
    repository
        .insert_reservation(
            &NewHardwareReservation {
                id: id.clone(),
                device_id: device.id,
                owner_kind: ReservationOwnerKind::Lease,
                owner_id: "lease-2".to_owned(),
                guest: None,
            },
            1,
        )
        .await
        .unwrap();
    let target = GuestTarget {
        account_id: account.to_owned(),
        node: "pve".to_owned(),
        vmid: 9101,
        usb_slot: Some(1),
    };
    repository
        .transition_reservation(&id, State::Held, State::Attaching, Some(&target), 2)
        .await
        .unwrap();
    repository
        .transition_reservation(
            &id,
            State::Attaching,
            State::AttachUnknown,
            Some(&target),
            3,
        )
        .await
        .unwrap();
    id
}
