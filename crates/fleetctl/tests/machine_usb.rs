//! `fleetctl machines usb attach|detach` (FM-1125): the grammar, the review
//! and execute requests each command sends (the execute call carries the
//! review's token), the contract that `--output json` is the controller's
//! `data` unchanged, confirmation, and the exit status of a pending detach.
//! The request bodies and the answers are checked against the checked-in
//! `OpenAPI` document, so a drift between the API and the CLI fails here. The
//! controller is a scripted HTTP stub: the routes themselves are tested in
//! `fleet-controller`'s `machine_usb_surface`.

#[path = "../../fleet-api/tests/support/openapi_shape.rs"]
mod openapi_shape;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::StatusCode};
use fleetctl::machine_usb::{MachineUsbAction, MachineUsbArgs};
use serde_json::{Value, json};

const MACHINE: &str = "machine-1";
const MAPPING: &str = "fm-test-reader-a";
const TOKEN: &str = "0123456789abcdef";

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(ToString::to_string).collect()
}

fn action(words: &[&str]) -> MachineUsbAction {
    match fleetctl::parse(&args(words)).expect("parses").command {
        fleetctl::Command::MachineUsb(action) => action,
        other => panic!("not a machines usb command: {other:?}"),
    }
}

fn usb_args(yes: bool, review_only: bool) -> MachineUsbArgs {
    MachineUsbArgs {
        machine_id: MACHINE.to_owned(),
        mapping: MAPPING.to_owned(),
        yes,
        review_only,
    }
}

#[test]
fn the_grammar_covers_attach_and_detach() {
    assert_eq!(
        action(&["machines", "usb", "attach", MACHINE, "--mapping", MAPPING]),
        MachineUsbAction::Attach(usb_args(false, false))
    );
    assert_eq!(
        action(&[
            "machines",
            "usb",
            "detach",
            MACHINE,
            "--mapping",
            MAPPING,
            "--yes"
        ]),
        MachineUsbAction::Detach(usb_args(true, false))
    );
    assert_eq!(
        action(&[
            "machines",
            "usb",
            "attach",
            MACHINE,
            "--review-only",
            "--mapping",
            MAPPING
        ]),
        MachineUsbAction::Attach(usb_args(false, true))
    );
    // `--output` after the verb and the global form before the command word.
    let invocation = fleetctl::parse(&args(&[
        "machines",
        "usb",
        "attach",
        MACHINE,
        "--mapping",
        "m",
        "--output",
        "json",
    ]))
    .unwrap();
    assert_eq!(invocation.output, fleetctl::Output::Json);
    let invocation = fleetctl::parse(&args(&[
        "--output",
        "json",
        "machines",
        "usb",
        "attach",
        MACHINE,
        "--mapping",
        "m",
    ]))
    .unwrap();
    assert_eq!(invocation.output, fleetctl::Output::Json);
    // The other machines commands are not shadowed.
    assert!(matches!(
        fleetctl::parse(&args(&["machines", "get", MACHINE]))
            .unwrap()
            .command,
        fleetctl::Command::MachinesGet { .. }
    ));
}

#[test]
fn undocumented_forms_are_refused() {
    for words in [
        vec!["machines", "usb"],
        vec!["machines", "usb", "list"],
        vec!["machines", "usb", "attach"],
        vec!["machines", "usb", "attach", MACHINE],
        vec!["machines", "usb", "attach", "--mapping", "m"],
        vec![
            "machines",
            "usb",
            "attach",
            MACHINE,
            "extra",
            "--mapping",
            "m",
        ],
        vec!["machines", "usb", "attach", MACHINE, "--mapping"],
        // No `--release`: a machine's detach always gives the device back.
        vec![
            "machines",
            "usb",
            "detach",
            MACHINE,
            "--mapping",
            "m",
            "--release",
        ],
        vec![
            "machines",
            "usb",
            "attach",
            MACHINE,
            "--mapping",
            "m",
            "--serial",
            "x",
        ],
        vec![
            "machines",
            "usb",
            "attach",
            MACHINE,
            "--mapping",
            "m",
            "--output",
            "xml",
        ],
    ] {
        assert!(fleetctl::parse(&args(&words)).is_err(), "{words:?}");
    }
}

/// What the stub controller was asked: method, path, body.
type Seen = Arc<Mutex<Vec<(String, String, Value)>>>;

#[derive(Clone)]
struct Stub {
    routes: Arc<BTreeMap<String, (StatusCode, Value)>>,
    seen: Seen,
}

async fn answer(
    State(stub): State<Stub>,
    request: axum::extract::Request,
) -> (StatusCode, Json<Value>) {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
    let path = parts.uri.path().to_owned();
    stub.seen.lock().unwrap().push((
        parts.method.to_string(),
        path.clone(),
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ));
    match stub.routes.get(&path) {
        Some((status, body)) => (*status, Json(body.clone())),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "code": "not_found", "message": path, "retry": "never" })),
        ),
    }
}

/// Serves the scripted answers by path; answers the URL.
async fn controller(answers: Vec<(String, StatusCode, Value)>) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let scripted = answers
        .into_iter()
        .map(|(path, status, body)| (path, (status, body)))
        .collect();
    let router = Router::new().fallback(answer).with_state(Stub {
        routes: Arc::new(scripted),
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

fn attach_review() -> Value {
    json!({
        "reviewToken": TOKEN,
        "action": "attach",
        "machineId": MACHINE,
        "mapping": MAPPING,
        "guest": { "accountId": "acct", "node": "pve", "vmid": 9100, "name": "bench" },
        "reservation": null,
    })
}

fn detach_review() -> Value {
    json!({
        "reviewToken": TOKEN,
        "action": "detach",
        "machineId": MACHINE,
        "mapping": MAPPING,
        "guest": null,
        "reservation": { "id": "reservation-1", "state": "attached", "guestVmid": 9100, "usbSlot": "usb0" },
    })
}

fn data(outcome: &str, state: &str, slot: Option<&str>, released: bool) -> Value {
    json!({
        "machineId": MACHINE,
        "mapping": MAPPING,
        "outcome": outcome,
        "onGuest": matches!(outcome, "attached" | "already_attached" | "detach_pending"),
        "reservationId": "reservation-1",
        "reservationState": state,
        "usbSlot": slot,
        "released": released,
    })
}

fn path(verb: &str, review: bool) -> String {
    let tail = if review { "/review" } else { "" };
    format!("/api/v1/machines/{MACHINE}/usb/{verb}{tail}")
}

#[tokio::test]
async fn attach_reviews_then_runs_with_the_token_and_prints_the_controllers_data_unchanged() {
    let spec = openapi_shape::spec();
    let answer = data("attached", "attached", Some("usb0"), false);
    let (url, seen) = controller(vec![
        (
            path("attach", true),
            StatusCode::OK,
            json!({ "data": attach_review() }),
        ),
        (
            path("attach", false),
            StatusCode::OK,
            json!({ "data": answer }),
        ),
    ])
    .await;

    let (printed, exit) = cli(
        &url,
        &[
            "--output",
            "json",
            "machines",
            "usb",
            "attach",
            MACHINE,
            "--mapping",
            MAPPING,
            "--yes",
        ],
    )
    .await
    .unwrap();

    assert_eq!(exit, 0);
    assert_eq!(serde_json::from_str::<Value>(&printed).unwrap(), answer);
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0].0, "POST");
    assert_eq!(seen[0].1, path("attach", true));
    assert_eq!(seen[0].2, json!({ "mapping": MAPPING }));
    assert_eq!(seen[1].1, path("attach", false));
    assert_eq!(
        seen[1].2,
        json!({ "mapping": MAPPING, "reviewToken": TOKEN }),
        "the execute call carries the review's token"
    );
    // What the CLI sends and what it prints are what the API documents.
    openapi_shape::assert_matches_schema(&spec, "ReviewMachineUsbRequest", &seen[0].2);
    openapi_shape::assert_matches_schema(&spec, "ExecuteMachineUsbRequest", &seen[1].2);
    openapi_shape::assert_matches_schema(&spec, "MachineUsbReviewDto", &attach_review());
    openapi_shape::assert_matches_schema(&spec, "MachineUsbDto", &answer);
    // The routes exist under the documented operation ids.
    for (route, operation) in [
        (
            "/api/v1/machines/{machineId}/usb/attach/review",
            "reviewMachineUsbAttach",
        ),
        (
            "/api/v1/machines/{machineId}/usb/attach",
            "attachMachineUsb",
        ),
        (
            "/api/v1/machines/{machineId}/usb/detach/review",
            "reviewMachineUsbDetach",
        ),
        (
            "/api/v1/machines/{machineId}/usb/detach",
            "detachMachineUsb",
        ),
    ] {
        assert_eq!(
            spec["paths"][route]["post"]["operationId"], operation,
            "{route}"
        );
    }
}

#[tokio::test]
async fn nothing_is_confirmed_without_a_terminal_or_yes_and_a_review_only_run_changes_nothing() {
    let (url, seen) = controller(vec![
        (
            path("attach", true),
            StatusCode::OK,
            json!({ "data": attach_review() }),
        ),
        (
            path("attach", false),
            StatusCode::OK,
            json!({ "data": data("attached", "attached", Some("usb0"), false) }),
        ),
    ])
    .await;

    // No terminal here and no --yes: the answer is no, and only the review
    // was sent.
    let error = cli(
        &url,
        &["machines", "usb", "attach", MACHINE, "--mapping", MAPPING],
    )
    .await
    .unwrap_err();
    assert!(error.contains("Not confirmed"), "{error}");
    assert!(
        error.contains("bench"),
        "the question names the guest: {error}"
    );
    assert_eq!(seen.lock().unwrap().len(), 1);

    // --review-only prints the review and stops.
    let (printed, exit) = cli(
        &url,
        &[
            "--output",
            "json",
            "machines",
            "usb",
            "attach",
            MACHINE,
            "--mapping",
            MAPPING,
            "--review-only",
        ],
    )
    .await
    .unwrap();
    assert_eq!(exit, 0);
    assert_eq!(
        serde_json::from_str::<Value>(&printed).unwrap(),
        attach_review()
    );
    let paths: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|(_, path, _)| path.clone())
        .collect();
    assert!(
        paths.iter().all(|path| path.ends_with("/review")),
        "nothing but reviews were sent: {paths:?}"
    );
}

#[tokio::test]
async fn detach_releases_and_says_so() {
    let spec = openapi_shape::spec();
    let answer = data("detached", "released", None, true);
    let (url, seen) = controller(vec![
        (
            path("detach", true),
            StatusCode::OK,
            json!({ "data": detach_review() }),
        ),
        (
            path("detach", false),
            StatusCode::OK,
            json!({ "data": answer }),
        ),
    ])
    .await;

    let (text, exit) = cli(
        &url,
        &[
            "machines",
            "usb",
            "detach",
            MACHINE,
            "--mapping",
            MAPPING,
            "--yes",
        ],
    )
    .await
    .unwrap();

    assert_eq!(exit, 0);
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen[1].1, path("detach", false));
    assert_eq!(
        seen[1].2,
        json!({ "mapping": MAPPING, "reviewToken": TOKEN })
    );
    openapi_shape::assert_matches_schema(&spec, "MachineUsbReviewDto", &detach_review());
    openapi_shape::assert_matches_schema(&spec, "MachineUsbDto", &answer);
    // The text form says what happened to the reservation.
    assert!(text.contains("detached"), "{text}");
    assert!(text.contains("gave the device up"), "{text}");
}

#[tokio::test]
async fn a_pending_detach_is_not_a_plain_success() {
    let spec = openapi_shape::spec();
    let answer = data("detach_pending", "detaching", Some("usb0"), false);
    let (url, _) = controller(vec![
        (
            path("detach", true),
            StatusCode::OK,
            json!({ "data": detach_review() }),
        ),
        (
            path("detach", false),
            StatusCode::ACCEPTED,
            json!({ "data": answer }),
        ),
    ])
    .await;

    let (text, exit) = cli(
        &url,
        &[
            "machines",
            "usb",
            "detach",
            MACHINE,
            "--mapping",
            MAPPING,
            "--yes",
        ],
    )
    .await
    .unwrap();

    assert_eq!(exit, 2, "the device is still attached");
    assert!(text.contains("detach_pending"), "{text}");
    assert!(text.contains("still attached"), "{text}");
    openapi_shape::assert_matches_schema(&spec, "MachineUsbDto", &answer);
    // The 202 is documented for the detach route, and only for it.
    let detach = &spec["paths"]["/api/v1/machines/{machineId}/usb/detach"]["post"]["responses"];
    assert!(detach["202"].is_object() && detach["200"].is_object());
    let attach = &spec["paths"]["/api/v1/machines/{machineId}/usb/attach"]["post"]["responses"];
    assert!(attach["202"].is_null() && attach["409"].is_object());
}

#[tokio::test]
async fn a_refusal_is_an_error_that_names_the_reason_and_nothing_else_is_sent() {
    let (url, seen) = controller(vec![(
        path("attach", true),
        StatusCode::CONFLICT,
        json!({
            "code": "hardware_busy",
            "message": "the device is reserved by lease lease-1",
            "retry": "never",
            "correlationId": "c-1",
        }),
    )])
    .await;

    let error = cli(
        &url,
        &[
            "machines",
            "usb",
            "attach",
            MACHINE,
            "--mapping",
            MAPPING,
            "--yes",
        ],
    )
    .await
    .unwrap_err();

    assert!(error.contains("hardware_busy"), "{error}");
    assert!(error.contains("lease-1"), "{error}");
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "no execute call after a refused review"
    );
}
