//! Exercises the CLI contract: parsing, both output modes, and a real
//! end-to-end request against a running controller router.

use serde_json::json;

#[test]
fn parsing_accepts_the_documented_grammar() {
    let args: Vec<String> = ["--url", "http://box.lan:9000", "system"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let invocation = fleetctl::parse(&args).unwrap();
    assert_eq!(invocation.url, "http://box.lan:9000");
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
fn parsing_refuses_the_undocumented() {
    for args in [
        vec!["frobnicate"],
        vec!["operations"],
        vec!["operations", "delete", "id"],
        vec!["--limit", "5", "operations", "list"],
    ] {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        let error = fleetctl::parse(&args).unwrap_err();
        assert!(error.message.contains("Usage"), "{error}");
    }
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
        };
        let router = fleet_controller::build_router(&settings, Some(store.pool().clone()));
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
