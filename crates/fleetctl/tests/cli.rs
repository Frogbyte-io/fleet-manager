//! Exercises the CLI contract: parsing, both output modes, and a real
//! end-to-end request against a running controller router.

use fleet_application::machine::{MachinePort, NewEndpoint, RegisterMachine};
use serde_json::json;

#[test]
fn parsing_accepts_the_documented_grammar() {
    let args: Vec<String> = ["--url", "http://box.lan:9000", "system"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(invocation.url, "http://box.lan:9000");
    assert!(invocation.url_explicit);
    assert_eq!(invocation.output, fleetctl::Output::Text);
    assert_eq!(invocation.command, fleetctl::Command::System);

    let args: Vec<String> = ["operations", "list", "--limit", "5"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(invocation.url, fleetctl::DEFAULT_URL);
    assert_eq!(
        invocation.command,
        fleetctl::Command::OperationsList { limit: Some(5) }
    );
}

#[test]
fn the_status_command_selects_its_route_explicitly() {
    // No --url: the local route through the node's socket.
    let args: Vec<String> = ["status"].iter().map(ToString::to_string).collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert!(!invocation.url_explicit, "the local route is the default");
    assert_eq!(invocation.command, fleetctl::Command::Status);

    // --socket points the local route elsewhere.
    let args: Vec<String> = ["--socket", "/run/fleetd/local.sock", "status"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(invocation.socket, "/run/fleetd/local.sock");
    assert!(!invocation.url_explicit);

    // --url is the explicit direct-controller override.
    let args: Vec<String> = ["--url", "http://controller:8080", "status"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert!(invocation.url_explicit, "the override must be explicit");
    assert_eq!(invocation.url, "http://controller:8080");
}

#[test]
fn parsing_refuses_the_undocumented() {
    for args in [
        vec!["frobnicate"],
        vec!["operations"],
        vec!["operations", "delete", "id"],
        vec!["--limit", "5", "operations", "list"],
        vec!["machines", "list", "--dormant", "yes"],
        vec!["machines", "list", "--tag"],
    ] {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        let error = fleetctl::parse(&args).unwrap_err();
        assert!(
            error.message.contains("Usage")
                || error.message.contains("requires a value")
                || error.message.contains("unknown flag"),
            "{error}"
        );
    }
}

#[test]
fn parsing_accepts_the_machine_grammar() {
    let args: Vec<String> = ["machines", "get", "0199-machine"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::MachinesGet {
            id: "0199-machine".to_owned()
        }
    );

    let args: Vec<String> = [
        "machines",
        "list",
        "--tag",
        "linux",
        "--group",
        "lab",
        "--capability",
        "tool:git",
        "--status",
        "connected",
        "--limit",
        "7",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::MachinesList {
            tag: Some("linux".to_owned()),
            group: Some("lab".to_owned()),
            capability: Some("tool:git".to_owned()),
            status: Some("connected".to_owned()),
            limit: Some(7),
        }
    );

    // Bare `machines list` and a lone `--limit` also parse.
    let args: Vec<String> = ["machines", "list"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::MachinesList {
            tag: None,
            group: None,
            capability: None,
            status: None,
            limit: None,
        }
    );
}

#[test]
fn text_output_renders_a_page_as_a_table() {
    let page = json!({
        "items": [
            {"id": "01900a3c-0000-7000-8000-000000000001", "kind": "noop", "state": "succeeded"},
            {"id": "01900a3c-0000-7000-8000-000000000002", "kind": "noop", "state": "pending"}
        ],
        "page": {"limit": 50, "nextCursor": null}
    });
    let text = fleetctl::render_for_test(&page);
    assert!(text.contains("ID"), "{text}");
    assert!(text.contains("KIND"), "{text}");
    assert!(text.contains("succeeded"), "{text}");
    assert!(
        text.contains("01900a3c-0000-7000-8000-000000000001"),
        "{text}"
    );
}

#[test]
fn text_output_renders_an_empty_page_honestly() {
    let page = json!({"items": [], "page": {"limit": 50, "nextCursor": null}});
    let text = fleetctl::render_for_test(&page);
    assert!(text.contains("no operations"), "{text}");
}

#[test]
fn text_output_renders_machines_as_a_table() {
    let page = json!({
        "items": [
            {
                "id": "01990000-0000-7000-8000-000000000001",
                "name": "build-host",
                "machineStatus": "connected",
                "endpoints": [
                    {"id": "e1", "kind": "ssh", "reference": "ops@build.lan:22"},
                    {"id": "e2", "kind": "fleetd", "reference": "0199-node"}
                ],
                "tags": ["linux", "build"]
            },
            {
                "id": "01990000-0000-7000-8000-000000000002",
                "name": "lab-box",
                "machineStatus": "agentless",
                "endpoints": [],
                "tags": []
            }
        ],
        "page": {"limit": 50, "nextCursor": null}
    });
    let text = fleetctl::render_machines_for_test(&page);
    assert!(text.contains("NAME"), "{text}");
    assert!(text.contains("STATUS"), "{text}");
    assert!(text.contains("build-host"), "{text}");
    assert!(text.contains("connected"), "{text}");
    assert!(text.contains("agentless"), "{text}");
    assert!(text.contains("ops@build.lan:22"), "{text}");
    assert!(text.contains("linux,build"), "{text}");
}

#[test]
fn text_output_renders_a_machine_detail_with_facts() {
    let machine = json!({
        "id": "01990000-0000-7000-8000-000000000001",
        "name": "build-host",
        "description": "the builder",
        "machineStatus": "connected",
        "lastSeenAt": 1500,
        "endpoints": [
            {"id": "e1", "kind": "ssh", "reference": "ops@build.lan:22"}
        ],
        "tags": ["linux"],
        "groups": [],
        "lastObservation": {"source": "fleetd/0.1.0", "collectedAt": 900},
        "capabilities": [
            {"namespace": "os", "name": "family", "value": "linux", "status": "known", "observedAt": 900, "source": "fleetd/0.1.0"},
            {"namespace": "tool", "name": "git", "value": null, "status": "unavailable", "observedAt": 900, "source": "fleetd/0.1.0"}
        ],
        "createdAt": 0,
        "updatedAt": 0
    });
    let text = fleetctl::render_machines_for_test(&machine);
    assert!(text.contains("name: build-host"), "{text}");
    assert!(text.contains("machineStatus: connected"), "{text}");
    assert!(text.contains("ssh ops@build.lan:22"), "{text}");
    assert!(
        text.contains("lastObservation: fleetd/0.1.0 at 900"),
        "{text}"
    );
    assert!(
        text.contains("os.family = linux (known, fleetd/0.1.0)"),
        "{text}"
    );
    assert!(
        text.contains("tool.git = – (unavailable, fleetd/0.1.0)"),
        "{text}"
    );
}

/// The end-to-end path: a real HTTP server on an ephemeral port serving the
/// real router, driven by the real CLI code.
#[test]
fn fleetctl_talks_to_a_real_controller() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let addr = runtime.block_on(async {
        let dist = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = fleet_storage_sqlite::Store::open(&dir.path().join("fleet.db"))
            .await
            .unwrap();
        let settings = fleet_controller::Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            web_dist: dist.path().to_path_buf(),
            artifacts_dir: None,
        };
        let router = fleet_controller::build_router(
            &settings,
            Some(store.pool().clone()),
            None,
            None,
            None,
            None,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        // Leak the server task and the directories keeping it fed; the test
        // process is short-lived.
        let server = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        );
        std::mem::forget((dist, dir, store));
        tokio::spawn(async move {
            let _ = server.await;
        });
        address
    });

    // The CLI is blocking; run it off the async runtime.
    let system = std::thread::spawn(move || {
        let args: Vec<String> = [
            "--url",
            &format!("http://{addr}"),
            "--output",
            "json",
            "system",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        let invocation = fleetctl::parse(&args).unwrap();
        fleetctl::run(&invocation).unwrap()
    })
    .join()
    .unwrap();
    let system: serde_json::Value = serde_json::from_str(&system).unwrap();
    assert_eq!(system["service"], "fleet-controller");
    assert_eq!(system["trustMode"], "trusted-lan");
    assert_eq!(system["storageOk"], true);

    // Create an operation through the CLI and see it in the list.
    let args: Vec<String> = [
        "--url",
        &format!("http://{addr}"),
        "operations",
        "list",
        "--limit",
        "5",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    let listing = fleetctl::run(&invocation).unwrap();
    assert!(listing.contains("no operations"), "{listing}");
}

/// The machines commands over the same real-router path: register one
/// machine behind the CLI's back, then list and read it in both modes.
#[test]
fn fleetctl_machines_read_a_real_controller() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let addr = runtime.block_on(async {
        let dist = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = fleet_storage_sqlite::Store::open(&dir.path().join("fleet.db"))
            .await
            .unwrap();
        let machines = fleet_storage_sqlite::MachineRepository::new(store.pool().clone());
        let machine = machines
            .register(&RegisterMachine {
                name: "cli-box".to_owned(),
                description: String::new(),
                endpoints: vec![NewEndpoint {
                    kind: fleet_core::EndpointKind::Ssh,
                    reference: "ops@cli-box.lan:22".to_owned(),
                }],
                tags: vec!["e2e".to_owned()],
                groups: Vec::new(),
            })
            .await
            .unwrap();
        let settings = fleet_controller::Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            web_dist: dist.path().to_path_buf(),
            artifacts_dir: None,
        };
        let router = fleet_controller::build_router(
            &settings,
            Some(store.pool().clone()),
            None,
            None,
            None,
            None,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        std::mem::forget((dist, dir, store));
        tokio::spawn(async move {
            let server = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            );
            let _ = server.await;
        });
        (address, machine.id)
    });

    let (address, machine_id) = addr;
    let base_url = format!("http://{address}");
    let run = |args: &[&str]| {
        let mut owned = vec!["--url", base_url.as_str()];
        owned.extend_from_slice(args);
        let owned: Vec<String> = owned.iter().map(ToString::to_string).collect();
        let invocation = fleetctl::parse(&owned).unwrap();
        fleetctl::run(&invocation).unwrap()
    };

    // Human text: an aligned table with the machine and its endpoint.
    let text = run(&["machines", "list"]);
    assert!(text.contains("cli-box"), "{text}");
    assert!(text.contains("agentless"), "{text}");
    assert!(text.contains("ops@cli-box.lan:22"), "{text}");
    assert!(text.contains("e2e"), "{text}");

    // JSON parity: the same page as the API sent it.
    let json = run(&["--output", "json", "machines", "list"]);
    let page: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(page["items"][0]["machineStatus"], "agentless");

    // Filters flow through as query parameters.
    let filtered = run(&["machines", "list", "--tag", "nothing-matches"]);
    assert!(filtered.contains("no machines"), "{filtered}");

    // The detail read unwraps the resource envelope.
    let detail = run(&["machines", "get", &machine_id]);
    assert!(detail.contains("cli-box"), "{detail}");
    assert!(detail.contains("machineStatus: agentless"), "{detail}");

    // An unknown machine reports the envelope code.
    let args: Vec<String> = [
        "--url",
        &format!("http://{address}"),
        "machines",
        "get",
        "no-such-machine",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    let error = fleetctl::run(&invocation).unwrap_err();
    assert!(error.message.contains("not_found"), "{error}");
}

#[test]
fn a_refused_request_reports_the_envelope_code() {
    // A port that refuses connections; the CLI must surface the transport
    // failure instead of hanging or lying.
    let args: Vec<String> = ["--url", "http://127.0.0.1:9", "system"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    let error = fleetctl::run(&invocation).unwrap_err();
    assert!(error.message.contains("did not answer"), "{error}");
}

// ---------------------------------------------------------------------------
// The status command's two routes
// ---------------------------------------------------------------------------

fn status_args(extra: &[&str]) -> Vec<String> {
    let mut args = vec!["--output", "json", "status"];
    args.extend_from_slice(extra);
    args.iter().map(ToString::to_string).collect()
}

#[test]
fn status_prefers_the_node_socket_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let state = std::sync::Arc::new(fleetd::state::NodeState::open(dir.path()).unwrap());
    let journal = std::sync::Arc::new(
        fleetd::journal::NodeJournal::open(&dir.path().join("journal.ndjson"))
            .map_err(|error| error.to_string())
            .unwrap(),
    );
    let inventory = std::sync::Arc::new(
        fleetd::inventory::InventoryState::open(&dir.path().join("inventory.json"))
            .map_err(|error| error.to_string())
            .unwrap(),
    );
    let connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    // The controller is unreachable by construction; the route assertion is
    // what matters here.
    let controller = fleetd::http::Controller::parse("http://127.0.0.1:1").unwrap();
    let server = std::sync::Arc::new(fleetd::local::LocalServer::new(
        dir.path(),
        controller,
        state,
        journal,
        inventory,
        connected,
        None,
    ));
    let socket = server.socket_path().to_path_buf();
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_flag = shutdown.clone();
    let thread = std::thread::spawn(move || {
        server.serve_blocking(|| shutdown_flag.load(std::sync::atomic::Ordering::Relaxed));
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !socket.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the local socket must bind"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let args = status_args(&["--socket", socket.to_str().unwrap()]);
    let invocation = fleetctl::parse(&args).unwrap();
    let rendered = fleetctl::run(&invocation).expect("the local route must answer");
    let body: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(body["route"], "local", "{body}");
    assert_eq!(
        body["status"]["node"]["nodeVersion"],
        env!("CARGO_PKG_VERSION")
    );

    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = thread.join();
}

#[tokio::test]
async fn an_explicit_url_sends_status_straight_to_the_controller() {
    let dist = tempfile::tempdir().unwrap();
    std::fs::write(dist.path().join("index.html"), "<html>fleet</html>").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = fleet_storage_sqlite::Store::open(&dir.path().join("fleet.db"))
        .await
        .unwrap();
    let settings = fleet_controller::Settings {
        listen: "127.0.0.1:0".parse().unwrap(),
        web_dist: dist.path().to_path_buf(),
        artifacts_dir: None,
    };
    let router = fleet_controller::build_router(
        &settings,
        Some(store.pool().clone()),
        None,
        None,
        None,
        None,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    std::mem::forget((dist, dir, store));
    tokio::spawn(async move {
        let server = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        );
        let _ = server.await;
    });

    let args: Vec<String> = [
        "--url",
        &format!("http://{address}"),
        "--output",
        "json",
        "status",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    let rendered = tokio::task::spawn_blocking(move || fleetctl::run(&invocation))
        .await
        .expect("the run task must not panic")
        .expect("the controller route must answer");
    let body: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(body["route"], "controller", "{body}");
    assert_eq!(body["status"]["service"], "fleet-controller", "{body}");
}

// ---------------------------------------------------------------------------
// The Add Machine onboarding surface
// ---------------------------------------------------------------------------

#[test]
fn parsing_accepts_the_onboarding_grammar() {
    let args: Vec<String> = [
        "machines",
        "onboard",
        "create",
        "--user",
        "deploy",
        "--host",
        "box.lan",
        "--port",
        "2222",
        "--name",
        "builder",
        "--description",
        "the builder",
        "--tag",
        "lab",
        "--group",
        "bench",
        "--auth",
        "identity-file",
        "--identity",
        "/keys/deploy",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::MachinesOnboardCreate {
            user: "deploy".to_owned(),
            host: "box.lan".to_owned(),
            port: Some(2222),
            name: Some("builder".to_owned()),
            description: Some("the builder".to_owned()),
            tags: vec!["lab".to_owned()],
            groups: vec!["bench".to_owned()],
            auth: fleetctl::OnboardAuthArg::IdentityFile("/keys/deploy".to_owned()),
        }
    );

    // The agent mode and the defaulted port parse too.
    let args: Vec<String> = [
        "machines", "onboard", "create", "--user", "ops", "--host", "box", "--auth", "agent",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::MachinesOnboardCreate {
            user: "ops".to_owned(),
            host: "box".to_owned(),
            port: None,
            name: None,
            description: None,
            tags: vec![],
            groups: vec![],
            auth: fleetctl::OnboardAuthArg::Agent,
        }
    );

    for (args, expected) in [
        (vec!["machines", "onboard", "list", "--limit", "3"], "list"),
        (vec!["machines", "onboard", "get", "d1"], "get"),
        (
            vec!["machines", "onboard", "test", "d1", "--wait"],
            "test-wait",
        ),
        (vec!["machines", "onboard", "test", "d1"], "test"),
        (
            vec![
                "machines",
                "onboard",
                "discover",
                "d1",
                "--wait",
                "--timeout",
                "30",
            ],
            "discover",
        ),
        (
            vec![
                "machines",
                "onboard",
                "confirm",
                "d1",
                "--fingerprint",
                "SHA256:abc",
            ],
            "confirm",
        ),
        (vec!["machines", "onboard", "add", "d1"], "add"),
        (vec!["machines", "onboard", "cancel", "d1"], "cancel"),
    ] {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        fleetctl::parse(&args).unwrap_or_else(|error| panic!("{expected} must parse: {error}"));
    }
}

#[test]
fn parsing_refuses_the_undocumented_onboarding() {
    for args in [
        vec![
            "machines", "onboard", "create", "--host", "box", "--auth", "agent",
        ],
        vec![
            "machines", "onboard", "create", "--user", "ops", "--auth", "agent",
        ],
        vec![
            "machines", "onboard", "create", "--user", "ops", "--host", "box",
        ],
        vec![
            "machines", "onboard", "create", "--user", "o", "--host", "b", "--auth", "password",
        ],
        vec![
            "machines",
            "onboard",
            "create",
            "--user",
            "o",
            "--host",
            "b",
            "--auth",
            "identity-file",
        ],
        vec!["machines", "onboard", "confirm", "d1"],
        vec!["machines", "onboard", "test", "d1", "--fingerprint", "x"],
        vec!["machines", "onboard"],
    ] {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        let error = fleetctl::parse(&args).unwrap_err();
        assert!(
            error.message.contains("Usage")
                || error.message.contains("requires")
                || error.message.contains("is required")
                || error.message.contains("must be")
                || error.message.contains("unknown flag"),
            "{error}"
        );
    }
}

#[test]
fn text_output_renders_the_onboarding_surface() {
    let page = json!({
        "items": [
            {
                "id": "draft-1",
                "endpoint": {"user": "***", "host": "box.lan", "port": 2222},
                "name": "builder",
                "tags": ["lab"],
                "groups": [],
                "stage": "ready",
                "hostKeyStage": "confirmed",
                "factCount": 0,
                "createdAt": 1,
                "updatedAt": 2
            }
        ],
        "page": {"limit": 50, "nextCursor": null}
    });
    let text = fleetctl::render_onboarding_for_test(&page);
    assert!(text.contains("ID"), "{text}");
    assert!(text.contains("STAGE"), "{text}");
    assert!(text.contains("draft-1"), "{text}");
    assert!(text.contains("***@box.lan:2222"), "{text}");

    let detail = json!({
        "id": "draft-1",
        "endpoint": {"user": "deploy", "host": "box.lan", "port": 22},
        "auth": {"type": "identityFile", "path": "/keys/deploy"},
        "name": "builder",
        "description": "",
        "tags": [],
        "groups": [],
        "stage": "review",
        "hostKeyStage": "observed",
        "hostKey": {"keyType": "ED25519", "fingerprint": "SHA256:abc", "rawLine": "[box.lan]:22 ssh-ed25519 x"},
        "confirmedFingerprint": null,
        "lastTest": {"connectAttempted": false, "connected": false, "detail": null, "at": 5},
        "facts": [],
        "discoveredAt": null,
        "profileHint": null,
        "duplicates": [
            {"machineId": "m1", "name": "twin", "machineStatus": "agentless", "reference": "ops@box.lan:22"}
        ],
        "createdAt": 1,
        "updatedAt": 2
    });
    let text = fleetctl::render_onboarding_for_test(&detail);
    assert!(text.contains("stage: review"), "{text}");
    assert!(text.contains("endpoint: deploy@box.lan:22"), "{text}");
    assert!(text.contains("auth: identity file /keys/deploy"), "{text}");
    assert!(text.contains("hostKey: ED25519 SHA256:abc"), "{text}");
    assert!(
        text.contains("lastTest: not attempted (fingerprint unconfirmed)"),
        "{text}"
    );
    assert!(text.contains("facts: (none discovered)"), "{text}");
    assert!(text.contains("duplicates (warned, not merged):"), "{text}");
    assert!(text.contains("m1 ops@box.lan:22"), "{text}");

    let added = json!({
        "machine": {
            "id": "machine-1",
            "name": "builder",
            "endpoints": [{"id": "e1", "kind": "ssh", "reference": "deploy@box.lan:22"}]
        },
        "duplicates": []
    });
    let text = fleetctl::render_onboarding_for_test(&added);
    assert!(
        text.contains("machine registered: machine-1 (builder)"),
        "{text}"
    );
    assert!(text.contains("duplicates: (none)"), "{text}");
}

/// The onboarding commands over a real controller: create, review, list,
/// and cancel a draft whose test stage never ran.
#[test]
fn fleetctl_onboards_a_real_controller() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let addr = runtime.block_on(async {
        let dist = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = fleet_storage_sqlite::Store::open(&dir.path().join("fleet.db"))
            .await
            .unwrap();
        let onboarding = std::sync::Arc::new(fleet_controller::compose_onboarding(
            store.pool(),
            dir.path().join("ssh"),
        ));
        let settings = fleet_controller::Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            web_dist: dist.path().to_path_buf(),
            artifacts_dir: None,
        };
        let router = fleet_controller::build_router(
            &settings,
            Some(store.pool().clone()),
            None,
            Some(&onboarding),
            None,
            None,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        std::mem::forget((dist, dir, store));
        tokio::spawn(async move {
            let server = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            );
            let _ = server.await;
        });
        address
    });

    let base_url = format!("http://{addr}");
    let run = |args: &[&str]| {
        let mut owned = vec!["--url", base_url.as_str()];
        owned.extend_from_slice(args);
        let owned: Vec<String> = owned.iter().map(ToString::to_string).collect();
        let invocation = fleetctl::parse(&owned).unwrap();
        fleetctl::run(&invocation).unwrap()
    };

    // Create in JSON: the draft exists, untested, and the user arrived
    // unredacted for its creator.
    let created = run(&[
        "--output", "json", "machines", "onboard", "create", "--user", "deploy", "--host",
        "box.lan", "--auth", "agent", "--tag", "lab",
    ]);
    let draft: serde_json::Value = serde_json::from_str(&created).unwrap();
    let draft_id = draft["id"].as_str().unwrap().to_owned();
    assert_eq!(draft["stage"], "untested");
    assert_eq!(draft["endpoint"]["user"], "deploy");

    // Text parity: the review surface reads as lines.
    let detail = run(&["machines", "onboard", "get", &draft_id]);
    assert!(detail.contains("stage: untested"), "{detail}");
    assert!(detail.contains("endpoint: deploy@box.lan:22"), "{detail}");

    // The list shows the draft with a redacted user (the default read).
    let listing = run(&["machines", "onboard", "list"]);
    assert!(listing.contains("***@box.lan:22"), "{listing}");
    assert!(listing.contains("untested"), "{listing}");

    // Cancel is a clean 204; the JSON answer is null and the draft is gone.
    let cancelled = run(&[
        "--output", "json", "machines", "onboard", "cancel", &draft_id,
    ]);
    assert_eq!(cancelled.trim(), "null", "{cancelled}");
    let args: Vec<String> = [
        "--url",
        base_url.as_str(),
        "machines",
        "onboard",
        "get",
        &draft_id,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    let error = fleetctl::run(&invocation).unwrap_err();
    assert!(error.message.contains("not_found"), "{error}");
}

#[test]
fn parsing_accepts_the_install_node_grammar() {
    let args: Vec<String> = [
        "machines",
        "install-node",
        "0199-machine",
        "--endpoint",
        "0199-endpoint",
        "--auth",
        "identity-file",
        "--identity",
        "/keys/deploy",
        "--artifact-url",
        "http://ctl.lan:8080/downloads/fleetd/fleetd-0.1.0-linux-x86_64.tar.gz",
        "--artifact-sha256",
        "2473b62b6d06708ca4fbf1bc45e1cbc5a2df4d7e5c5af25ce437e06ec407efb4",
        "--controller-url",
        "http://ctl.lan:8080",
        "--connect-timeout",
        "90",
        "--wait",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::MachinesInstallNode {
            machine_id: "0199-machine".to_owned(),
            endpoint: "0199-endpoint".to_owned(),
            auth: fleetctl::OnboardAuthArg::IdentityFile("/keys/deploy".to_owned()),
            artifact_url: Some(
                "http://ctl.lan:8080/downloads/fleetd/fleetd-0.1.0-linux-x86_64.tar.gz".to_owned(),
            ),
            artifact_sha256: Some(
                "2473b62b6d06708ca4fbf1bc45e1cbc5a2df4d7e5c5af25ce437e06ec407efb4".to_owned(),
            ),
            controller_url: Some("http://ctl.lan:8080".to_owned()),
            install_timeout: 300,
            connect_wait: Some(90),
            wait: true,
            poll_timeout: 300,
        }
    );

    // The agent mode and the defaults parse too.
    let args: Vec<String> = [
        "machines",
        "install-node",
        "m",
        "--endpoint",
        "e",
        "--auth",
        "agent",
        "--artifact-url",
        "http://ctl:8080/downloads/fleetd/x.tar.gz",
        "--artifact-sha256",
        "abc",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::MachinesInstallNode {
            machine_id: "m".to_owned(),
            endpoint: "e".to_owned(),
            auth: fleetctl::OnboardAuthArg::Agent,
            artifact_url: Some("http://ctl:8080/downloads/fleetd/x.tar.gz".to_owned()),
            artifact_sha256: Some("abc".to_owned()),
            controller_url: Some("http://127.0.0.1:8080".to_owned()),
            install_timeout: 300,
            connect_wait: None,
            wait: false,
            poll_timeout: 300,
        }
    );
}

#[test]
fn parsing_refuses_the_undocumented_install_node() {
    for args in [
        vec!["machines", "install-node", "m"],
        vec!["machines", "install-node", "m", "--auth", "agent"],
        vec![
            "machines",
            "install-node",
            "m",
            "--auth",
            "agent",
            "--artifact-url",
            "http://x/x.tar.gz",
        ],
        vec![
            "machines",
            "install-node",
            "m",
            "--auth",
            "identity-file",
            "--identity",
            "/k",
            "--artifact-url",
            "http://x/x.tar.gz",
            "--artifact-sha256",
            "d",
        ],
        vec![
            "machines",
            "install-node",
            "m",
            "--auth",
            "password",
            "--artifact-url",
            "u",
            "--artifact-sha256",
            "d",
        ],
    ] {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        let error = fleetctl::parse(&args).unwrap_err();
        assert!(
            error.message.contains("is required")
                || error.message.contains("must be")
                || error.message.contains("unknown flag"),
            "{error}"
        );
    }
}

#[test]
fn parsing_accepts_the_projects_grammar() {
    let args: Vec<String> = [
        "projects",
        "create",
        "--remote",
        "git@github.com:Frogbyte-io/fleet-manager.git",
        "--name",
        "fleet-manager",
        "--description",
        "the manager",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::ProjectsCreate {
            remote: "git@github.com:Frogbyte-io/fleet-manager.git".to_owned(),
            name: "fleet-manager".to_owned(),
            description: Some("the manager".to_owned()),
        }
    );

    for (args, expected) in [
        (vec!["projects", "list"], "list"),
        (
            vec!["projects", "list", "--remote-prefix", "github.com/"],
            "list-prefix",
        ),
        (vec!["projects", "get", "p1"], "get"),
        (vec!["projects", "update", "p1", "--name", "n"], "update"),
        (vec!["projects", "delete", "p1"], "delete"),
    ] {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        fleetctl::parse(&args).unwrap_or_else(|error| panic!("{expected} must parse: {error}"));
    }
}

#[test]
fn parsing_refuses_the_undocumented_projects() {
    for args in [
        vec!["projects", "create", "--name", "x"],
        vec!["projects", "create", "--remote", "u"],
        vec!["projects", "get"],
        vec!["projects", "update", "p1"],
        vec!["projects", "delete"],
        vec!["projects"],
    ] {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        let error = fleetctl::parse(&args).unwrap_err();
        assert!(
            error.message.contains("Usage")
                || error.message.contains("requires a value")
                || error.message.contains("unknown flag"),
            "{error}"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn parsing_accepts_the_checkout_grammar() {
    for (args, expected) in [
        (
            vec![
                "projects",
                "discover",
                "p1",
                "m1",
                "--endpoint",
                "e1",
                "--auth",
                "agent",
                "--wait",
                "--timeout",
                "30",
            ],
            "discover",
        ),
        (vec!["projects", "record", "p1", "m1"], "record"),
        (
            vec![
                "projects",
                "clone",
                "p1",
                "m1",
                "--root",
                "/srv/repo",
                "--branch",
                "main",
                "--endpoint",
                "e1",
                "--auth",
                "agent",
            ],
            "clone",
        ),
        (
            vec![
                "projects",
                "pull",
                "p1",
                "m1",
                "--root",
                "/srv/repo",
                "--endpoint",
                "e1",
                "--auth",
                "identity-file",
                "--identity",
                "/keys/id",
            ],
            "pull",
        ),
        (
            vec![
                "projects",
                "status",
                "p1",
                "m1",
                "--root",
                "/srv/repo",
                "--endpoint",
                "e1",
                "--auth",
                "agent",
            ],
            "status",
        ),
        (
            vec![
                "projects",
                "write-config",
                "p1",
                "m1",
                "--root",
                "/srv/repo",
                "--file",
                "AGENTS.md",
                "--endpoint",
                "e1",
                "--auth",
                "agent",
            ],
            "write-config",
        ),
    ] {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        fleetctl::parse(&args).unwrap_or_else(|error| panic!("{expected} must parse: {error}"));
    }

    let args: Vec<String> = [
        "projects",
        "discover",
        "p1",
        "m1",
        "--endpoint",
        "e1",
        "--auth",
        "agent",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::ProjectsDiscover {
            id: "p1".to_owned(),
            machine: "m1".to_owned(),
            endpoint: "e1".to_owned(),
            auth: fleetctl::OnboardAuthArg::Agent,
            identity: None,
            wait: false,
            timeout: None,
        }
    );
}

#[test]
fn parsing_refuses_the_undocumented_checkout_forms() {
    for args in [
        vec!["projects", "discover", "p1"],
        vec!["projects", "discover", "p1", "m1", "--auth", "agent"],
        vec![
            "projects",
            "clone",
            "p1",
            "m1",
            "--endpoint",
            "e1",
            "--auth",
            "agent",
        ],
        vec![
            "projects", "pull", "p1", "m1", "--root", "/x", "--auth", "agent",
        ],
        vec![
            "projects",
            "write-config",
            "p1",
            "m1",
            "--root",
            "/x",
            "--auth",
            "agent",
        ],
        vec![
            "projects",
            "clone",
            "p1",
            "m1",
            "--root",
            "/x",
            "--endpoint",
            "e1",
            "--auth",
            "identity-file",
        ],
    ] {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        let error = fleetctl::parse(&args).unwrap_err();
        assert!(
            error.message.contains("Usage")
                || error.message.contains("requires a value")
                || error.message.contains("unknown flag")
                || error.message.contains("--identity")
                || error.message.contains("--root")
                || error.message.contains("--endpoint"),
            "{error}"
        );
    }
}

#[test]
fn parsing_accepts_the_skills_grammar() {
    for (args, expected) in [
        (
            vec![
                "skills",
                "probe",
                "m1",
                "--endpoint",
                "e1",
                "--auth",
                "agent",
                "--wait",
                "--timeout",
                "30",
            ],
            "probe",
        ),
        (
            vec![
                "skills",
                "deploy",
                "m1",
                "--skill",
                "db",
                "--agent",
                "claude_code",
                "--agent",
                "codex",
                "--endpoint",
                "e1",
                "--auth",
                "agent",
                "--dry-run",
            ],
            "deploy",
        ),
        (
            vec![
                "skills",
                "undeploy",
                "m1",
                "--skill",
                "db",
                "--agent",
                "claude_code",
                "--endpoint",
                "e1",
                "--auth",
                "identity-file",
                "--identity",
                "/keys/id",
            ],
            "undeploy",
        ),
    ] {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        fleetctl::parse(&args).unwrap_or_else(|error| panic!("{expected} must parse: {error}"));
    }

    let args: Vec<String> = [
        "skills",
        "deploy",
        "m1",
        "--skill",
        "db",
        "--agent",
        "claude_code",
        "--endpoint",
        "e1",
        "--auth",
        "agent",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::SkillsDeploy {
            machine: "m1".to_owned(),
            endpoint: "e1".to_owned(),
            auth: fleetctl::OnboardAuthArg::Agent,
            skill: "db".to_owned(),
            agents: vec!["claude_code".to_owned()],
            skills_root: None,
            dry_run: false,
            wait: false,
            timeout: None,
        }
    );
}

#[test]
fn parsing_refuses_the_undocumented_skills_forms() {
    for args in [
        vec!["skills", "probe", "m1"],
        vec!["skills", "probe", "m1", "--auth", "agent"],
        vec![
            "skills",
            "deploy",
            "m1",
            "--endpoint",
            "e1",
            "--auth",
            "agent",
        ],
        vec![
            "skills",
            "deploy",
            "m1",
            "--skill",
            "db",
            "--endpoint",
            "e1",
            "--auth",
            "agent",
        ],
        vec![
            "skills",
            "deploy",
            "m1",
            "--skill",
            "db",
            "--agent",
            "claude_code",
            "--endpoint",
            "e1",
            "--auth",
            "agent",
            "--artifact-url",
            "https://x",
        ],
        vec![
            "skills",
            "probe",
            "m1",
            "--endpoint",
            "e1",
            "--auth",
            "agent",
            "--skill",
            "db",
        ],
        vec![
            "skills",
            "probe",
            "m1",
            "--endpoint",
            "e1",
            "--auth",
            "agent",
            "--artifact-url",
            "https://x",
        ],
    ] {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        let error = fleetctl::parse(&args).unwrap_err();
        assert!(
            error.message.contains("Usage")
                || error.message.contains("requires a value")
                || error.message.contains("unknown flag")
                || error.message.contains("is required")
                || error.message.contains("apply to probe only")
                || error.message.contains("apply to deploy")
                || error.message.contains("must be supplied together"),
            "{error}"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn parsing_accepts_the_frogenv_grammar() {
    for (args, expected) in [
        (
            vec![
                "frogenv",
                "status",
                "m1",
                "--endpoint",
                "e1",
                "--auth",
                "agent",
                "--wait",
                "--timeout",
                "30",
            ],
            "status",
        ),
        (
            vec![
                "frogenv",
                "setup",
                "m1",
                "--endpoint",
                "e1",
                "--auth",
                "agent",
            ],
            "setup",
        ),
        (
            vec![
                "frogenv",
                "login",
                "m1",
                "--endpoint",
                "e1",
                "--auth",
                "identity-file",
                "--identity",
                "/keys/id",
            ],
            "login",
        ),
        (
            vec![
                "frogenv",
                "request",
                "m1",
                "--endpoint",
                "e1",
                "--auth",
                "agent",
            ],
            "request",
        ),
        (
            vec![
                "frogenv",
                "sync",
                "m1",
                "--endpoint",
                "e1",
                "--auth",
                "agent",
            ],
            "sync",
        ),
        (
            vec![
                "frogenv",
                "run",
                "m1",
                "--root",
                "/srv/repo",
                "--endpoint",
                "e1",
                "--auth",
                "agent",
                "--",
                "pytest",
                "-q",
            ],
            "run",
        ),
    ] {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        fleetctl::parse(&args).unwrap_or_else(|error| panic!("{expected} must parse: {error}"));
    }

    for (args, expected_action) in [
        (
            vec![
                "frogenv",
                "status",
                "m1",
                "--endpoint",
                "e1",
                "--auth",
                "agent",
                "--wait",
                "--timeout",
                "30",
            ],
            "status",
        ),
        (
            vec![
                "frogenv",
                "setup",
                "m1",
                "--endpoint",
                "e1",
                "--auth",
                "agent",
            ],
            "setup",
        ),
    ] {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        let invocation = fleetctl::parse(&args)
            .unwrap_or_else(|error| panic!("{expected_action} must parse: {error}"));
        let fleetctl::Command::FrogenvOperation {
            action,
            wait,
            timeout,
            ..
        } = &invocation.command
        else {
            panic!("the frogenv grammar parses into a FrogenvOperation");
        };
        assert_eq!(action, expected_action);
        if expected_action == "status" {
            assert!(*wait, "the status case carries --wait");
            assert_eq!(*timeout, Some(30));
        }
    }

    let args: Vec<String> = [
        "frogenv",
        "run",
        "m1",
        "--root",
        "/srv/repo",
        "--endpoint",
        "e1",
        "--auth",
        "agent",
        "--",
        "pytest",
        "-q",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::FrogenvOperation {
            machine: "m1".to_owned(),
            endpoint: "e1".to_owned(),
            auth: fleetctl::OnboardAuthArg::Agent,
            action: "run".to_owned(),
            root: Some("/srv/repo".to_owned()),
            command: vec!["pytest".to_owned(), "-q".to_owned()],
            wait: false,
            timeout: None,
        }
    );
}

#[test]
fn parsing_refuses_the_undocumented_frogenv_forms() {
    for args in [
        vec!["frogenv", "status", "m1"],
        vec!["frogenv", "status", "m1", "--auth", "agent"],
        vec![
            "frogenv",
            "run",
            "m1",
            "--endpoint",
            "e1",
            "--auth",
            "agent",
        ],
        vec![
            "frogenv",
            "run",
            "m1",
            "--endpoint",
            "e1",
            "--auth",
            "agent",
            "--",
            "pytest",
        ],
        vec![
            "frogenv",
            "status",
            "m1",
            "--endpoint",
            "e1",
            "--auth",
            "agent",
            "--root",
            "/srv/repo",
        ],
        vec![
            "frogenv",
            "deploy",
            "m1",
            "--endpoint",
            "e1",
            "--auth",
            "agent",
        ],
    ] {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        let error = fleetctl::parse(&args).unwrap_err();
        assert!(
            error.message.contains("Usage")
                || error.message.contains("requires a value")
                || error.message.contains("unknown flag")
                || error.message.contains("is required")
                || error.message.contains("apply to env run only")
                || error.message.contains("applies to"),
            "{error}"
        );
    }
}
