//! `fleetctl lab hardware attach|detach` (FM-1126): the grammar, the request
//! each command sends, the contract that `--output json` is the controller's
//! `data` unchanged, and the exit status of a pending detach. Both the
//! request bodies and the answer are checked against the checked-in `OpenAPI`
//! document, so a drift between the API and the CLI fails here. The
//! controller is a scripted HTTP stub: the routes themselves are tested in
//! `fleet-api`.

#[path = "../../fleet-api/tests/support/openapi_shape.rs"]
mod openapi_shape;

use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::StatusCode};
use fleetctl::lab_hardware::LabHardwareAction;
use serde_json::{Value, json};

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(ToString::to_string).collect()
}

fn action(words: &[&str]) -> LabHardwareAction {
    match fleetctl::parse(&args(words)).expect("parses").command {
        fleetctl::Command::LabHardware(action) => action,
        other => panic!("not a lab hardware command: {other:?}"),
    }
}

#[test]
fn the_grammar_covers_attach_and_detach() {
    assert_eq!(
        action(&["lab", "hardware", "attach", "lease-1", "fm-test-reader-a"]),
        LabHardwareAction::Attach {
            lease_id: "lease-1".to_owned(),
            mapping: "fm-test-reader-a".to_owned()
        }
    );
    assert_eq!(
        action(&["lab", "hardware", "detach", "lease-1", "fm-test-reader-a"]),
        LabHardwareAction::Detach {
            lease_id: "lease-1".to_owned(),
            mapping: "fm-test-reader-a".to_owned(),
            release: false
        }
    );
    assert_eq!(
        action(&[
            "lab",
            "hardware",
            "detach",
            "lease-1",
            "fm-test-reader-a",
            "--release"
        ]),
        LabHardwareAction::Detach {
            lease_id: "lease-1".to_owned(),
            mapping: "fm-test-reader-a".to_owned(),
            release: true
        }
    );
    // `--output` after the verb and the global form before the command word.
    let invocation = fleetctl::parse(&args(&[
        "lab", "hardware", "attach", "lease-1", "m", "--output", "json",
    ]))
    .unwrap();
    assert_eq!(invocation.output, fleetctl::Output::Json);
    let invocation = fleetctl::parse(&args(&[
        "--output", "json", "lab", "hardware", "attach", "lease-1", "m",
    ]))
    .unwrap();
    assert_eq!(invocation.output, fleetctl::Output::Json);
    // The other Lab commands are not shadowed.
    assert!(matches!(
        fleetctl::parse(&args(&["lab", "status", "lease-1"]))
            .unwrap()
            .command,
        fleetctl::Command::LabStatus { .. }
    ));
}

#[test]
fn undocumented_forms_are_refused() {
    for words in [
        vec!["lab", "hardware"],
        vec!["lab", "hardware", "list"],
        vec!["lab", "hardware", "attach"],
        vec!["lab", "hardware", "attach", "lease-1"],
        vec!["lab", "hardware", "attach", "lease-1", "m", "extra"],
        // Only a detach can release.
        vec!["lab", "hardware", "attach", "lease-1", "m", "--release"],
        vec!["lab", "hardware", "detach", "lease-1", "m", "--keep"],
        vec![
            "lab", "hardware", "detach", "lease-1", "m", "--output", "xml",
        ],
        vec!["lab", "hardware", "detach", "lease-1", "m", "--output"],
        vec!["lab", "hardware", "detach", "lease-1", "m", "--serial", "x"],
    ] {
        assert!(fleetctl::parse(&args(&words)).is_err(), "{words:?}");
    }
}

/// What the stub controller was asked: method, path, body.
type Seen = Arc<Mutex<Vec<(String, String, Value)>>>;

#[derive(Clone)]
struct Stub {
    status: StatusCode,
    body: Value,
    seen: Seen,
}

async fn answer(
    State(stub): State<Stub>,
    request: axum::extract::Request,
) -> (StatusCode, Json<Value>) {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
    stub.seen.lock().unwrap().push((
        parts.method.to_string(),
        parts.uri.path().to_owned(),
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ));
    (stub.status, Json(stub.body))
}

/// Serves one scripted answer to every request; answers the URL.
async fn controller(status: StatusCode, body: Value) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let router = Router::new().fallback(answer).with_state(Stub {
        status,
        body,
        seen: seen.clone(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (url, seen)
}

/// Runs the CLI against the stub, off the async runtime (the client blocks).
async fn cli(url: &str, words: &[&str]) -> Result<(String, u8), String> {
    let mut all = vec!["--url".to_owned(), url.to_owned()];
    all.extend(words.iter().map(ToString::to_string));
    tokio::task::spawn_blocking(move || {
        let invocation = fleetctl::parse(&all).map_err(|error| error.message)?;
        fleetctl::run_with_exit(&invocation).map_err(|error| error.message)
    })
    .await
    .unwrap()
}

fn data(outcome: &str, state: &str, slot: Option<&str>, released: bool) -> Value {
    json!({
        "leaseId": "lease-1",
        "mapping": "fm-test-reader-a",
        "outcome": outcome,
        "onGuest": matches!(outcome, "attached" | "already_attached" | "detach_pending"),
        "reservationId": "reservation-1",
        "reservationState": state,
        "usbSlot": slot,
        "released": released,
    })
}

#[tokio::test]
async fn attach_posts_the_mapping_and_prints_the_controllers_data_unchanged() {
    let spec = openapi_shape::spec();
    let answer = data("attached", "attached", Some("usb0"), false);
    let (url, seen) = controller(StatusCode::OK, json!({ "data": answer })).await;

    let (printed, exit) = cli(
        &url,
        &[
            "--output",
            "json",
            "lab",
            "hardware",
            "attach",
            "lease-1",
            "fm-test-reader-a",
        ],
    )
    .await
    .unwrap();

    assert_eq!(exit, 0);
    assert_eq!(serde_json::from_str::<Value>(&printed).unwrap(), answer);
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "POST");
    assert_eq!(seen[0].1, "/api/v1/lab/leases/lease-1/hardware/attach");
    assert_eq!(seen[0].2, json!({ "mapping": "fm-test-reader-a" }));
    // What the CLI sends and what it prints are what the API documents.
    openapi_shape::assert_matches_schema(&spec, "AttachLabHardwareRequest", &seen[0].2);
    openapi_shape::assert_matches_schema(&spec, "LabHardwareHotplugDto", &answer);
    // The routes exist under the documented operation ids.
    for (path, operation) in [
        (
            "/api/v1/lab/leases/{leaseId}/hardware/attach",
            "attachLabLeaseHardware",
        ),
        (
            "/api/v1/lab/leases/{leaseId}/hardware/detach",
            "detachLabLeaseHardware",
        ),
    ] {
        assert_eq!(
            spec["paths"][path]["post"]["operationId"], operation,
            "{path}"
        );
    }
}

#[tokio::test]
async fn detach_keeps_the_device_unless_it_is_told_to_release() {
    let spec = openapi_shape::spec();
    let answer = data("detached", "held", None, false);
    let (url, seen) = controller(StatusCode::OK, json!({ "data": answer })).await;

    cli(&url, &["lab", "hardware", "detach", "lease-1", "m"])
        .await
        .unwrap();
    let released = data("detached", "released", None, true);
    let (url2, seen2) = controller(StatusCode::OK, json!({ "data": released })).await;
    let (text, exit) = cli(
        &url2,
        &["lab", "hardware", "detach", "lease-1", "m", "--release"],
    )
    .await
    .unwrap();

    assert_eq!(exit, 0);
    let kept = seen.lock().unwrap().clone();
    assert_eq!(kept[0].1, "/api/v1/lab/leases/lease-1/hardware/detach");
    assert_eq!(kept[0].2, json!({ "mapping": "m", "release": false }));
    let given_up = seen2.lock().unwrap().clone();
    assert_eq!(given_up[0].2, json!({ "mapping": "m", "release": true }));
    for sent in [&kept[0].2, &given_up[0].2] {
        openapi_shape::assert_matches_schema(&spec, "DetachLabHardwareRequest", sent);
    }
    openapi_shape::assert_matches_schema(&spec, "LabHardwareHotplugDto", &released);
    // The text form says what happened to the reservation.
    assert!(text.contains("detached"), "{text}");
    assert!(text.contains("gave the device up"), "{text}");
}

#[tokio::test]
async fn a_pending_detach_is_not_a_plain_success() {
    let spec = openapi_shape::spec();
    let answer = data("detach_pending", "detaching", Some("usb0"), false);
    let (url, _) = controller(StatusCode::ACCEPTED, json!({ "data": answer })).await;

    let (text, exit) = cli(&url, &["lab", "hardware", "detach", "lease-1", "m"])
        .await
        .unwrap();

    assert_eq!(exit, 2, "the device is still attached");
    assert!(text.contains("detach_pending"), "{text}");
    assert!(text.contains("still attached"), "{text}");
    openapi_shape::assert_matches_schema(&spec, "LabHardwareHotplugDto", &answer);
    // The 202 is documented for the detach route, and only for it.
    let detach =
        &spec["paths"]["/api/v1/lab/leases/{leaseId}/hardware/detach"]["post"]["responses"];
    assert!(detach["202"].is_object() && detach["200"].is_object());
    let attach =
        &spec["paths"]["/api/v1/lab/leases/{leaseId}/hardware/attach"]["post"]["responses"];
    assert!(attach["202"].is_null() && attach["409"].is_object());
}

#[tokio::test]
async fn a_refusal_is_an_error_that_names_the_reason() {
    let (url, _) = controller(
        StatusCode::CONFLICT,
        json!({
            "code": "hardware_attach_pending",
            "message": "PVE would keep the attach pending until the guest restarts",
            "retry": "never",
            "correlationId": "c-1",
        }),
    )
    .await;

    let error = cli(&url, &["lab", "hardware", "attach", "lease-1", "m"])
        .await
        .unwrap_err();

    assert!(error.contains("hardware_attach_pending"), "{error}");
    assert!(
        error.contains("pending until the guest restarts"),
        "{error}"
    );
}
