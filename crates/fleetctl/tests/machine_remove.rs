//! `fleetctl machines remove` and `fleetctl nodes revoke` (#616): the
//! grammar, the review and remove requests (the removal carries the review's
//! token and the same uninstall), a blocked review that stops before any
//! removal, confirmation, and `--output json` printing the controller's
//! `data` unchanged. Bodies and answers are checked against the checked-in
//! `OpenAPI` document. The controller is a scripted HTTP stub: the routes
//! themselves are tested in `fleet-controller`'s `machine_remove_surface`.

#[path = "../../fleet-api/tests/support/openapi_shape.rs"]
mod openapi_shape;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::StatusCode};
use fleetctl::machine_access::AuthArgs;
use fleetctl::machine_remove::MachineRemoveArgs;
use serde_json::{Value, json};

const MACHINE: &str = "machine-1";
const ENDPOINT: &str = "endpoint-ssh";
const TOKEN: &str = "0123456789abcdef";

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(ToString::to_string).collect()
}

fn remove_args(words: &[&str]) -> MachineRemoveArgs {
    match fleetctl::parse(&args(words)).expect("parses").command {
        fleetctl::Command::MachineRemove(args) => args,
        other => panic!("not a machines remove command: {other:?}"),
    }
}

#[test]
fn the_grammar_covers_remove_and_revoke() {
    assert_eq!(
        remove_args(&["machines", "remove", MACHINE]),
        MachineRemoveArgs {
            machine_id: MACHINE.to_owned(),
            ..MachineRemoveArgs::default()
        }
    );
    assert_eq!(
        remove_args(&[
            "machines",
            "remove",
            MACHINE,
            "--uninstall",
            "--endpoint",
            ENDPOINT,
            "--auth",
            "identity-file",
            "--identity",
            "/keys/id",
            "--yes",
            "--review-only",
        ]),
        MachineRemoveArgs {
            machine_id: MACHINE.to_owned(),
            uninstall_endpoint: Some(ENDPOINT.to_owned()),
            auth: AuthArgs {
                kind: Some("identity-file".to_owned()),
                identity: Some("/keys/id".to_owned()),
                credential: None,
            },
            yes: true,
            review_only: true,
        }
    );
    let invocation = fleetctl::parse(&args(&[
        "--output", "json", "nodes", "revoke", MACHINE, "--yes",
    ]))
    .unwrap();
    assert_eq!(invocation.output, fleetctl::Output::Json);
    assert_eq!(
        invocation.command,
        fleetctl::Command::NodesRevoke {
            machine_id: MACHINE.to_owned(),
            yes: true
        }
    );
    // The other machines commands and `proxmox nodes` are not shadowed.
    assert!(matches!(
        fleetctl::parse(&args(&["machines", "get", MACHINE]))
            .unwrap()
            .command,
        fleetctl::Command::MachinesGet { .. }
    ));
    assert!(matches!(
        fleetctl::parse(&args(&["proxmox", "nodes", "acct"]))
            .unwrap()
            .command,
        fleetctl::Command::ProxmoxNodes { .. }
    ));
}

#[test]
fn undocumented_forms_are_refused() {
    for words in [
        vec!["machines", "remove"],
        vec!["machines", "remove", MACHINE, "extra"],
        // An uninstall needs its endpoint, and the endpoint means nothing
        // without the uninstall.
        vec!["machines", "remove", MACHINE, "--uninstall"],
        vec!["machines", "remove", MACHINE, "--endpoint", ENDPOINT],
        vec!["machines", "remove", MACHINE, "--auth", "agent"],
        vec![
            "machines",
            "remove",
            MACHINE,
            "--uninstall",
            "--endpoint",
            ENDPOINT,
            "--auth",
            "identity-file",
        ],
        vec!["machines", "remove", MACHINE, "--force"],
        vec!["nodes"],
        vec!["nodes", "list"],
        vec!["nodes", "revoke"],
        vec!["nodes", "revoke", MACHINE, "--purge"],
        // An option-like word is never taken as a machine id.
        vec!["machines", "remove", "-x"],
        vec!["nodes", "revoke", "-x"],
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

fn footprint() -> Value {
    json!({
        "endpoints": 2, "endpointAuth": 0, "endpointAuthSecrets": 0, "capabilities": 12,
        "inventorySnapshots": 3, "tagsAndGroups": 1, "nodeIdentity": 1, "nodeCredentials": 2,
        "projectCheckouts": 0, "skillsSnapshot": 1, "catalogSkillInstalls": 2, "guestLink": 0,
        "storedSshKeys": 1, "adminPasswords": 0, "collectedFilesKept": 0,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn review(token: Option<&str>, blockers: Value, uninstall: Value) -> Value {
    json!({
        "reviewToken": token,
        "machineId": MACHINE,
        "name": "box",
        "endpoints": [
            { "id": ENDPOINT, "kind": "ssh", "host": "box.lan" },
            { "id": "endpoint-node", "kind": "fleetd", "host": null },
        ],
        "nodeIdentity": "active",
        "unpinHosts": ["box.lan"],
        "keptHosts": [],
        "uninstall": uninstall,
        "footprint": footprint(),
        "warnings": [],
        "blockers": blockers,
    })
}

fn removed(uninstalled: bool) -> Value {
    json!({
        "machineId": MACHINE,
        "name": "box",
        "removed": true,
        "uninstalled": uninstalled,
        "uninstallSummary": if uninstalled { json!("uninstall: service removed") } else { Value::Null },
        "nodeIdentityRemoved": true,
        "sessionClosed": false,
        "secretsRevoked": 1,
        "secretRevocationError": null,
        "unpinnedHosts": ["box.lan"],
        "keptHosts": [],
        "unpinFailedHosts": [],
        "auditGaps": [],
        "footprint": footprint(),
    })
}

fn path(review: bool) -> String {
    let tail = if review { "/review" } else { "" };
    format!("/api/v1/machines/{MACHINE}/remove{tail}")
}

#[tokio::test]
async fn remove_reviews_then_removes_with_the_token_and_the_same_uninstall() {
    let spec = openapi_shape::spec();
    let uninstall = json!({ "endpointId": ENDPOINT, "auth": { "type": "agent" } });
    let plan = json!({ "endpointId": ENDPOINT, "auth": { "type": "agent" }, "layout": {} });
    let reviewed = review(Some(TOKEN), json!([]), plan);
    let answer = removed(true);
    let (url, seen) = controller(vec![
        (path(true), StatusCode::OK, json!({ "data": reviewed })),
        (path(false), StatusCode::OK, json!({ "data": answer })),
    ])
    .await;

    let (printed, exit) = cli(
        &url,
        &[
            "--output",
            "json",
            "machines",
            "remove",
            MACHINE,
            "--uninstall",
            "--endpoint",
            ENDPOINT,
            "--auth",
            "agent",
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
    assert_eq!(seen[1].0, "POST");
    assert_eq!(seen[0].1, path(true));
    assert_eq!(seen[0].2, json!({ "uninstall": uninstall }));
    assert_eq!(seen[1].1, path(false));
    assert_eq!(
        seen[1].2,
        json!({ "uninstall": uninstall, "reviewToken": TOKEN }),
        "the removal carries the review's token and the reviewed uninstall"
    );
    openapi_shape::assert_matches_schema(&spec, "ReviewMachineRemovalRequest", &seen[0].2);
    openapi_shape::assert_matches_schema(&spec, "RemoveMachineRequest", &seen[1].2);
    openapi_shape::assert_matches_schema(&spec, "MachineRemovalReviewDto", &reviewed);
    openapi_shape::assert_matches_schema(&spec, "MachineRemovedDto", &answer);
    for (route, operation) in [
        (
            "/api/v1/machines/{machineId}/remove/review",
            "reviewMachineRemoval",
        ),
        ("/api/v1/machines/{machineId}/remove", "removeMachine"),
        ("/api/v1/machines/{machineId}/node/revoke", "revokeNode"),
    ] {
        assert_eq!(
            spec["paths"][route]["post"]["operationId"], operation,
            "{route}"
        );
    }
}

#[tokio::test]
async fn a_blocked_review_stops_before_any_removal() {
    let blockers = json!([{
        "kind": "persistent_marker",
        "id": "acct/8100",
        "state": "registered",
        "detail": "machine machine-1 is the persistent machine of VM box (acct/8100); unregister it first with `fleetctl machines persistent unregister --account acct --vmid 8100`",
    }]);
    let reviewed = review(None, blockers, Value::Null);
    openapi_shape::assert_matches_schema(
        &openapi_shape::spec(),
        "MachineRemovalReviewDto",
        &reviewed,
    );
    let (url, seen) = controller(vec![
        (path(true), StatusCode::OK, json!({ "data": reviewed })),
        (
            path(false),
            StatusCode::OK,
            json!({ "data": removed(false) }),
        ),
    ])
    .await;
    let error = cli(&url, &["machines", "remove", MACHINE, "--yes"])
        .await
        .unwrap_err();
    assert!(error.contains("cannot be removed yet"), "{error}");
    assert!(error.contains("persistent unregister"), "{error}");
    let paths: Vec<String> = seen.lock().unwrap().iter().map(|s| s.1.clone()).collect();
    assert_eq!(paths, [path(true)]);

    // --review-only prints the blocked review and exits 0.
    let (printed, exit) = cli(
        &url,
        &[
            "--output",
            "json",
            "machines",
            "remove",
            MACHINE,
            "--review-only",
        ],
    )
    .await
    .unwrap();
    assert_eq!(exit, 0);
    assert_eq!(serde_json::from_str::<Value>(&printed).unwrap(), reviewed);
}

#[tokio::test]
async fn nothing_is_removed_or_revoked_without_a_terminal_or_yes() {
    let (url, seen) = controller(vec![
        (
            path(true),
            StatusCode::OK,
            json!({ "data": review(Some(TOKEN), json!([]), Value::Null) }),
        ),
        (
            path(false),
            StatusCode::OK,
            json!({ "data": removed(false) }),
        ),
        (
            format!("/api/v1/machines/{MACHINE}/node/revoke"),
            StatusCode::OK,
            json!({ "data": { "machineId": MACHINE, "status": "revoked" } }),
        ),
    ])
    .await;
    let error = cli(&url, &["machines", "remove", MACHINE])
        .await
        .unwrap_err();
    assert!(error.contains("Not confirmed"), "{error}");
    assert!(
        error.contains("box.lan"),
        "the question names the hosts: {error}"
    );
    let error = cli(&url, &["nodes", "revoke", MACHINE]).await.unwrap_err();
    assert!(error.contains("Not confirmed"), "{error}");
    let paths: Vec<String> = seen.lock().unwrap().iter().map(|s| s.1.clone()).collect();
    assert_eq!(paths, [path(true)], "only the review was sent");

    // Text output of a removal and a revocation.
    let (printed, _) = cli(&url, &["machines", "remove", MACHINE, "--yes"])
        .await
        .unwrap();
    assert!(printed.contains("removed machine box"), "{printed}");
    assert!(
        printed.contains("nothing on the machine was touched"),
        "{printed}"
    );
    let (printed, exit) = cli(
        &url,
        &["--output", "json", "nodes", "revoke", MACHINE, "--yes"],
    )
    .await
    .unwrap();
    assert_eq!(exit, 0);
    assert_eq!(
        serde_json::from_str::<Value>(&printed).unwrap(),
        json!({ "machineId": MACHINE, "status": "revoked" })
    );
    let last = seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(last.0, "POST");
    assert_eq!(last.1, format!("/api/v1/machines/{MACHINE}/node/revoke"));
}

#[tokio::test]
async fn a_refused_removal_exits_non_zero_with_the_controllers_reason() {
    let (url, _) = controller(vec![
        (
            path(true),
            StatusCode::OK,
            json!({ "data": review(Some(TOKEN), json!([]), json!({ "endpointId": ENDPOINT, "auth": { "type": "agent" }, "layout": {} })) }),
        ),
        (
            path(false),
            StatusCode::BAD_GATEWAY,
            json!({
                "code": "fleetd_uninstall_failed",
                "message": "the fleetd uninstall failed, so the machine was not removed: the uninstall script exited 1",
                "retry": "backoff",
                "correlationId": "01900000-0000-7000-8000-000000000000",
            }),
        ),
    ])
    .await;
    let error = cli(
        &url,
        &[
            "machines",
            "remove",
            MACHINE,
            "--uninstall",
            "--endpoint",
            ENDPOINT,
            "--yes",
        ],
    )
    .await
    .unwrap_err();
    assert!(error.contains("fleetd_uninstall_failed"), "{error}");
    assert!(error.contains("not removed"), "{error}");
}
