//! Contract tests for the read-only USB reads (FM-1110, M11) over the FM-S11
//! recordings for PVE 8.4.0 and 9.2.2 (`tests/fixtures/usb/`), plus malformed,
//! oversized, refused and absent-endpoint answers.
//!
//! Each fixture is one recorded request and its response (see
//! `tests/fixtures/usb/README.md`). The transport serves a recording under
//! its recorded path and query, wrapping a successful body in PVE's
//! `{"data": ...}` envelope and returning an error body as recorded. Every
//! request must be a pinned, credential-carrying `GET`: the reads never
//! mutate.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_core::SensitiveString;
use fleet_provider_proxmox::usb::{
    MAX_USB_DEVICES, MAX_USB_MAPPINGS, PveUsbCheckKind, PveUsbError, PveUsbSeverity,
};
use fleet_provider_proxmox::{
    ProxmoxClient, PveApiError, PveCredentials, PveHttpMethod, PveHttpRequest, PveHttpResponse,
    PveTransport, PveTransportError,
};
use serde_json::{Value, json};

const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";

/// The recordings, by major.
mod fixtures {
    pub mod pve9 {
        pub const VERSION: &str = include_str!("fixtures/usb/pve9/v0-version.json");
        pub const LIST: &str = include_str!("fixtures/usb/pve9/q1-mapping-list.json");
        pub const LIST_CHECKED: &str =
            include_str!("fixtures/usb/pve9/q1-mapping-list-check-node.json");
        pub const GET: &str = include_str!("fixtures/usb/pve9/q1-mapping-get-path.json");
        pub const INVENTORY: &str = include_str!("fixtures/usb/pve9/q1-hardware-usb.json");
        pub const CHECK_NO_NODE: &str =
            include_str!("fixtures/usb/pve9/q5-mapping-nonode-check.json");
        pub const CHECK_AMBIGUOUS: &str =
            include_str!("fixtures/usb/pve9/i4-two-entries-check.json");
        pub const CHECK_UNPLUGGED: &str =
            include_str!("fixtures/usb/pve9/r1-mapping-check-unplugged.json");
        pub const UNPRIVILEGED_LIST: &str =
            include_str!("fixtures/usb/pve9/pr0-list-mappings.json");
        pub const UNPRIVILEGED_GET: &str = include_str!("fixtures/usb/pve9/pr0-get-mapping.json");
        pub const UNPRIVILEGED_INVENTORY: &str =
            include_str!("fixtures/usb/pve9/pr0-hardware-usb.json");
    }
    pub mod pve8 {
        pub const VERSION: &str = include_str!("fixtures/usb/pve8/v8-version.json");
        pub const LIST: &str = include_str!("fixtures/usb/pve8/v8-mapping-list.json");
        pub const LIST_CHECKED: &str =
            include_str!("fixtures/usb/pve8/v8-mapping-list-check-node.json");
        pub const LIST_EMPTY: &str = include_str!("fixtures/usb/pve8/v8-mapping-list-empty.json");
        pub const GET: &str = include_str!("fixtures/usb/pve8/v8-mapping-get.json");
        pub const INVENTORY: &str = include_str!("fixtures/usb/pve8/v8-hardware-usb.json");
        pub const UNPRIVILEGED_LIST: &str =
            include_str!("fixtures/usb/pve8/qr0-list-mappings.json");
        pub const UNPRIVILEGED_GET: &str = include_str!("fixtures/usb/pve8/qr0-get-mapping.json");
        pub const UNPRIVILEGED_INVENTORY: &str =
            include_str!("fixtures/usb/pve8/qr0-hardware-usb.json");
    }
}

/// One scripted answer: a status and body, or a transport failure.
type Answer = Result<(u16, Vec<u8>), PveTransportError>;

/// A scripted PVE: routes by exact path-and-query.
#[derive(Debug)]
struct UsbTransport {
    routes: Mutex<Vec<(String, Answer)>>,
    requests: Mutex<Vec<String>>,
}

impl UsbTransport {
    fn new() -> Self {
        Self {
            routes: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Serves a recording under its recorded path and `check-node` query.
    fn record(self, recording: &str) -> Self {
        let record: Value = serde_json::from_str(recording).expect("a fixture is JSON");
        let mut key = format!(
            "/api2/json{}",
            record["request"]["path"].as_str().expect("a path")
        );
        if let Some(node) = record["request"]["params"]["check-node"].as_str() {
            key.push_str("?check-node=");
            key.push_str(node);
        }
        let status = u16::try_from(record["http_status"].as_u64().expect("a status")).unwrap();
        let body = if status == 200 {
            json!({ "data": record["response"] }).to_string()
        } else {
            record["response"].to_string()
        };
        self.route(&key, status, body.as_bytes())
    }

    fn route(self, key: &str, status: u16, body: &[u8]) -> Self {
        self.routes
            .lock()
            .unwrap()
            .push((key.to_owned(), Ok((status, body.to_vec()))));
        self
    }

    fn fail(self, key: &str, error: PveTransportError) -> Self {
        self.routes
            .lock()
            .unwrap()
            .push((key.to_owned(), Err(error)));
        self
    }

    fn client(self) -> (ProxmoxClient, Arc<Self>) {
        let transport = Arc::new(self);
        (ProxmoxClient::new(transport.clone()), transport)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

#[async_trait]
impl PveTransport for UsbTransport {
    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        assert_eq!(request.method, PveHttpMethod::Get, "the reads never mutate");
        assert_eq!(
            request.pinned_fingerprint.as_deref(),
            Some(FP),
            "every credential-carrying call is pinned"
        );
        self.requests.lock().unwrap().push(request.path.clone());
        let routes = self.routes.lock().unwrap();
        let (_, answer) = routes
            .iter()
            .find(|(key, _)| *key == request.path)
            .unwrap_or_else(|| panic!("unexpected PVE request: {}", request.path));
        match answer {
            Ok((status, body)) => Ok(PveHttpResponse {
                status: *status,
                body: body.clone(),
            }),
            Err(error) => Err(clone_transport_error(error)),
        }
    }

    async fn execute_with_body(
        &self,
        _request: PveHttpRequest,
        _body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        panic!("a read sends no body");
    }
}

fn clone_transport_error(error: &PveTransportError) -> PveTransportError {
    match error {
        PveTransportError::Connect { detail } => PveTransportError::Connect {
            detail: detail.clone(),
        },
        PveTransportError::BodyTooLarge { limit } => {
            PveTransportError::BodyTooLarge { limit: *limit }
        }
        PveTransportError::FingerprintMismatch { observed, pinned } => {
            PveTransportError::FingerprintMismatch {
                observed: observed.clone(),
                pinned: pinned.clone(),
            }
        }
        _ => panic!("not needed by these tests"),
    }
}

fn request() -> PveHttpRequest {
    PveHttpRequest {
        host: "pve.test".to_owned(),
        port: 8006,
        path: "/api2/json/version".to_owned(),
        pinned_fingerprint: Some(FP.to_owned()),
        credentials: Arc::new(PveCredentials {
            token_id: "fleet@pve!fleet".to_owned(),
            token: SensitiveString::new("fixture-secret"),
        }),
        method: PveHttpMethod::Get,
    }
}

const LIST: &str = "/api2/json/cluster/mapping/usb";

/// A transport that knows the version of one major and the given recordings.
fn pve(version: &str, recordings: &[&str]) -> UsbTransport {
    recordings.iter().fold(
        UsbTransport::new().record(version),
        |transport, recording| transport.record(recording),
    )
}

/// A transport with the given version body and raw routes.
fn raw(version: &str) -> UsbTransport {
    UsbTransport::new().route(
        "/api2/json/version",
        200,
        json!({"data": {"version": version, "release": "x", "repoid": "x"}})
            .to_string()
            .as_bytes(),
    )
}

// --- Mapping list, PVE 9.2 and 8.4 -------------------------------------

#[tokio::test]
async fn pve9_lists_the_mappings_with_path_and_id_entries() {
    let (client, transport) = pve(fixtures::pve9::VERSION, &[fixtures::pve9::LIST]).client();

    let list = client.usb_mappings(request(), None).await.unwrap();

    assert_eq!(list.version, "9.2.2");
    assert_eq!(list.checked_node, None);
    assert!(list.warnings.is_empty(), "{:?}", list.warnings);
    assert!(!list.truncated);
    assert!(!list.could_be_unprivileged());
    let ids: Vec<_> = list.mappings.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "decker",
            "fm-test-superdrive-a",
            "fm-test-superdrive-b",
            "fm-test-verbatim"
        ],
        "sorted by id whatever order PVE answered in"
    );
    let a = &list.mappings[1];
    assert_eq!(
        a.description.as_deref(),
        Some("Fleet M11 test: MacBook Air SuperDrive (port 1-10)")
    );
    assert_eq!(
        a.digest.as_deref(),
        Some("9496fd191eaf9792205190511d20822ddd76722e")
    );
    assert_eq!(a.entries.len(), 1);
    assert_eq!(a.entries[0].node, "pve");
    assert_eq!(a.entries[0].hardware_id(), "05ac:1500");
    assert_eq!(a.entries[0].path.as_deref(), Some("1-10"));
    assert_eq!(a.unreadable_entries, 0);
    assert_eq!(a.issues, None, "no check-node was asked for");
    assert_eq!(a.check_passed(), None);
    let verbatim = &list.mappings[3];
    assert_eq!(verbatim.entries[0].path, None, "an id-only entry");
    assert_eq!(verbatim.entries[0].hardware_id(), "18a5:0428");
    assert_eq!(transport.requests(), ["/api2/json/version", LIST]);
}

#[tokio::test]
async fn pve8_lists_the_same_shape() {
    let (client, _) = pve(fixtures::pve8::VERSION, &[fixtures::pve8::LIST]).client();

    let list = client.usb_mappings(request(), None).await.unwrap();

    assert_eq!(list.version, "8.4.0");
    assert!(list.warnings.is_empty(), "{:?}", list.warnings);
    let ids: Vec<_> = list.mappings.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "fm-test-badid",
            "fm-test-badpath",
            "fm-test-tablet-id",
            "fm-test-tablet-path"
        ]
    );
    let tablet = &list.mappings[3];
    assert_eq!(tablet.entries[0].node, "pve8");
    assert_eq!(tablet.entries[0].hardware_id(), "0627:0001");
    assert_eq!(tablet.entries[0].path.as_deref(), Some("1-1"));
}

#[tokio::test]
async fn pve9_check_node_reports_present_devices_as_passing() {
    let (client, transport) =
        pve(fixtures::pve9::VERSION, &[fixtures::pve9::LIST_CHECKED]).client();

    let list = client.usb_mappings(request(), Some("pve")).await.unwrap();

    assert_eq!(list.checked_node.as_deref(), Some("pve"));
    assert_eq!(list.mappings.len(), 4);
    for mapping in &list.mappings {
        assert_eq!(mapping.check_passed(), Some(true), "{}", mapping.id);
    }
    assert_eq!(
        transport.requests(),
        [
            "/api2/json/version",
            "/api2/json/cluster/mapping/usb?check-node=pve"
        ]
    );
}

#[tokio::test]
async fn pve9_check_node_classifies_absent_devices_and_unmapped_nodes() {
    let (client, _) = pve(fixtures::pve9::VERSION, &[fixtures::pve9::CHECK_UNPLUGGED]).client();
    let list = client.usb_mappings(request(), Some("pve")).await.unwrap();
    let by_id = |id: &str| list.mappings.iter().find(|m| m.id == id).unwrap();

    let unplugged = by_id("fm-test-superdrive-a");
    let issues = unplugged.issues.as_ref().unwrap();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, PveUsbCheckKind::DeviceNotFound);
    assert_eq!(issues[0].severity, PveUsbSeverity::Error);
    assert_eq!(
        issues[0].message, "usb device '1-10' not found",
        "the recorded decoration (prefix, newline) is normalized"
    );
    assert_eq!(unplugged.check_passed(), Some(false));
    assert_eq!(by_id("fm-test-superdrive-b").check_passed(), Some(true));

    let unmapped = by_id("fm-test-tmp-nonode");
    let issues = unmapped.issues.as_ref().unwrap();
    assert_eq!(issues[0].kind, PveUsbCheckKind::NoMappingForNode);
    assert_eq!(issues[0].severity, PveUsbSeverity::Warning);
    assert_eq!(
        unmapped.entries_for_node("pve").count(),
        0,
        "the entry is for another node"
    );
    assert_eq!(
        unmapped.check_passed(),
        Some(false),
        "a warning is not a pass"
    );
}

#[tokio::test]
async fn pve9_exposes_what_pve_does_not_flag_as_ambiguous() {
    let (client, _) = pve(fixtures::pve9::VERSION, &[fixtures::pve9::CHECK_AMBIGUOUS]).client();
    let list = client.usb_mappings(request(), Some("pve")).await.unwrap();
    let by_id = |id: &str| list.mappings.iter().find(|m| m.id == id).unwrap();

    // PVE's check passes both, and both are refused or ambiguous at attach.
    let two = by_id("fm-test-tmp-two");
    assert_eq!(two.check_passed(), Some(true));
    assert_eq!(
        two.entries_for_node("pve").count(),
        2,
        "two entries for one node: PVE refuses every attach"
    );
    let id_only = by_id("fm-test-tmp-ambig");
    assert_eq!(id_only.check_passed(), Some(true));
    assert_eq!(id_only.entries[0].path, None);

    let absent = by_id("fm-test-tmp-absentpath");
    assert_eq!(
        absent.issues.as_ref().unwrap()[0].kind,
        PveUsbCheckKind::DeviceNotFound
    );
    assert_eq!(absent.entries[0].path.as_deref(), Some("1-55"));
}

#[tokio::test]
async fn pve9_check_node_flags_only_the_mapping_with_no_entry_for_the_node() {
    let (client, _) = pve(fixtures::pve9::VERSION, &[fixtures::pve9::CHECK_NO_NODE]).client();
    let list = client.usb_mappings(request(), Some("pve")).await.unwrap();
    assert_eq!(list.mappings.len(), 5);
    assert!(list.warnings.is_empty(), "{:?}", list.warnings);

    let mut flagged = Vec::new();
    for mapping in &list.mappings {
        match mapping.check_passed() {
            Some(true) => {}
            Some(false) => flagged.push(mapping.id.as_str()),
            None => panic!("{} was not checked", mapping.id),
        }
    }
    assert_eq!(flagged, ["fm-test-tmp-nonode"], "the other four pass");

    let unmapped = list
        .mappings
        .iter()
        .find(|m| m.id == "fm-test-tmp-nonode")
        .unwrap();
    let issues = unmapped.issues.as_ref().unwrap();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, PveUsbCheckKind::NoMappingForNode);
    assert_eq!(issues[0].severity, PveUsbSeverity::Warning);
    assert_eq!(issues[0].message, "No mapping for node pve.");
    assert_eq!(unmapped.entries.len(), 1, "it maps another node");
    assert_eq!(unmapped.entries[0].node, "nowhere");
    assert_eq!(unmapped.entries_for_node("pve").count(), 0);
}

#[tokio::test]
async fn pve8_check_node_classifies_a_bad_path_and_a_mismatched_id() {
    let (client, _) = pve(fixtures::pve8::VERSION, &[fixtures::pve8::LIST_CHECKED]).client();

    let list = client.usb_mappings(request(), Some("pve8")).await.unwrap();

    let kind_of = |id: &str| {
        let mapping = list.mappings.iter().find(|m| m.id == id).unwrap();
        mapping.issues.as_ref().unwrap().first().map(|i| i.kind)
    };
    assert_eq!(
        kind_of("fm-test-badpath"),
        Some(PveUsbCheckKind::DeviceNotFound)
    );
    assert_eq!(kind_of("fm-test-badid"), Some(PveUsbCheckKind::IdMismatch));
    assert_eq!(kind_of("fm-test-tablet-path"), None);
    assert_eq!(kind_of("fm-test-tablet-id"), None);
    let mismatch = list
        .mappings
        .iter()
        .find(|m| m.id == "fm-test-badid")
        .unwrap();
    assert_eq!(
        mismatch.issues.as_ref().unwrap()[0].message,
        "'id' does not match for 'fm-test-badid' (0627:0001 != 0627:0002)"
    );
}

#[tokio::test]
async fn an_empty_list_is_ambiguous_and_says_so() {
    for (version, empty) in [
        (fixtures::pve9::VERSION, fixtures::pve9::UNPRIVILEGED_LIST),
        (fixtures::pve8::VERSION, fixtures::pve8::UNPRIVILEGED_LIST),
        (fixtures::pve8::VERSION, fixtures::pve8::LIST_EMPTY),
    ] {
        let (client, _) = pve(version, &[empty]).client();
        let list = client.usb_mappings(request(), None).await.unwrap();
        assert!(list.mappings.is_empty());
        assert_eq!(list.rows_returned, 0);
        assert!(list.warnings.is_empty());
        assert!(
            list.could_be_unprivileged(),
            "PVE answers an unprivileged list with an empty 200; only a per-mapping read settles it"
        );
    }
}

// --- Per-mapping read (the Mapping.Audit probe) --------------------------

#[tokio::test]
async fn a_single_mapping_reads_on_both_majors() {
    let (client, transport) = pve(fixtures::pve9::VERSION, &[fixtures::pve9::GET]).client();
    let read = client
        .usb_mapping(request(), "fm-test-superdrive-a")
        .await
        .unwrap();
    assert_eq!(read.version, "9.2.2");
    assert_eq!(
        read.mapping.id, "fm-test-superdrive-a",
        "the id is the caller's"
    );
    assert_eq!(read.mapping.entries[0].path.as_deref(), Some("1-10"));
    assert_eq!(read.mapping.issues, None);
    assert!(read.warnings.is_empty());
    assert_eq!(
        transport.requests().last().unwrap(),
        "/api2/json/cluster/mapping/usb/fm-test-superdrive-a"
    );

    let (client, _) = pve(fixtures::pve8::VERSION, &[fixtures::pve8::GET]).client();
    let read = client
        .usb_mapping(request(), "fm-test-tablet-path")
        .await
        .unwrap();
    assert_eq!(read.version, "8.4.0");
    assert_eq!(read.mapping.entries[0].node, "pve8");
}

#[tokio::test]
async fn a_single_mapping_read_without_mapping_audit_is_a_permission_error() {
    for (version, get, id) in [
        (
            fixtures::pve9::VERSION,
            fixtures::pve9::UNPRIVILEGED_GET,
            "fm-test-superdrive-a",
        ),
        (
            fixtures::pve8::VERSION,
            fixtures::pve8::UNPRIVILEGED_GET,
            "fm-test-tablet-path",
        ),
    ] {
        let (client, _) = pve(version, &[get]).client();
        match client.usb_mapping(request(), id).await {
            Err(PveUsbError::PermissionDenied { detail, required }) => {
                assert!(detail.contains("Permission check failed"), "{detail}");
                assert_eq!(required, None, "PVE names no privilege here");
            }
            other => panic!("expected a permission error, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_single_mapping_answer_for_another_id_or_shape_is_refused() {
    let (client, _) = raw("9.2.2")
        .route(
            "/api2/json/cluster/mapping/usb/mine",
            200,
            br#"{"data":{"id":"theirs","map":[]}}"#,
        )
        .route(
            "/api2/json/cluster/mapping/usb/list",
            200,
            br#"{"data":[]}"#,
        )
        .client();
    for id in ["mine", "list"] {
        assert!(matches!(
            client.usb_mapping(request(), id).await,
            Err(PveUsbError::Unreadable {
                cause: PveApiError::InvalidPayload { .. }
            })
        ));
    }
}

#[tokio::test]
async fn an_unknown_mapping_is_not_found_and_never_an_absent_endpoint() {
    // Synthetic: the spike never read an unknown or deleted mapping id, so
    // how PVE answers it is an assumption. 404, a 500 saying the mapping is
    // not found, and a 200 with no data are all read as not found.
    let (client, _) = raw("9.2.2")
        .route(
            "/api2/json/cluster/mapping/usb/gone-404",
            404,
            br#"{"data":null,"message":"mapping 'gone-404' not found\n"}"#,
        )
        .route(
            "/api2/json/cluster/mapping/usb/gone-500",
            500,
            br#"{"data":null,"message":"mapping 'gone-500' not found\n"}"#,
        )
        .route(
            "/api2/json/cluster/mapping/usb/gone-null",
            200,
            br#"{"data":null}"#,
        )
        .route(
            "/api2/json/cluster/mapping/usb/broken",
            500,
            br#"{"data":null,"message":"boom\n"}"#,
        )
        .route(
            "/api2/json/cluster/mapping/usb/old-pve",
            501,
            br#"{"data":null,"message":"Method 'GET /cluster/mapping/usb/old-pve' not implemented\n"}"#,
        )
        .client();

    for id in ["gone-404", "gone-500", "gone-null"] {
        match client.usb_mapping(request(), id).await {
            Err(PveUsbError::NotFound { detail }) => {
                assert!(!detail.is_empty(), "{id}");
            }
            other => panic!("expected NotFound for {id}, got {other:?}"),
        }
    }
    assert!(
        matches!(
            client.usb_mapping(request(), "broken").await,
            Err(PveUsbError::Unreadable {
                cause: PveApiError::Http { status: 500, .. }
            })
        ),
        "a 500 for another reason is not a missing mapping"
    );
    assert!(
        matches!(
            client.usb_mapping(request(), "old-pve").await,
            Err(PveUsbError::EndpointAbsent { .. })
        ),
        "a 501 still means the PVE has no such endpoint"
    );
}

#[tokio::test]
async fn a_404_on_the_list_or_inventory_stays_an_absent_endpoint() {
    let (client, _) = raw("7.4-17")
        .route(LIST, 404, br#"{"data":null}"#)
        .route(
            "/api2/json/nodes/pve/hardware/usb",
            404,
            br#"{"data":null}"#,
        )
        .client();
    assert!(matches!(
        client.usb_mappings(request(), None).await,
        Err(PveUsbError::EndpointAbsent { .. })
    ));
    assert!(matches!(
        client.usb_inventory(request(), "pve").await,
        Err(PveUsbError::EndpointAbsent { .. })
    ));
}

#[tokio::test]
async fn a_mapping_answered_without_a_map_is_not_read_as_clean() {
    let (client, _) = raw("9.2.2")
        .route(
            "/api2/json/cluster/mapping/usb/nomap",
            200,
            br#"{"data":{"description":"x"}}"#,
        )
        .route(
            LIST,
            200,
            br#"{"data":[{"id":"nomap","type":"usb"},{"id":"ok","map":["node=pve,id=05ac:1500"]}]}"#,
        )
        .client();

    let read = client.usb_mapping(request(), "nomap").await.unwrap();
    assert_eq!(read.mapping.unreadable_entries, 1);
    assert!(read.warnings.iter().any(|w| w.contains("no map")));

    let list = client.usb_mappings(request(), None).await.unwrap();
    let by_id = |id: &str| list.mappings.iter().find(|m| m.id == id).unwrap();
    assert_eq!(by_id("nomap").unreadable_entries, 1);
    assert_eq!(by_id("ok").unreadable_entries, 0);
}

#[tokio::test]
async fn rows_that_are_all_malformed_do_not_look_like_a_missing_privilege() {
    let (client, _) = raw("9.2.2")
        .route(LIST, 200, br#"{"data":[{"type":"usb"},"junk",null]}"#)
        .client();

    let list = client.usb_mappings(request(), None).await.unwrap();

    assert!(list.mappings.is_empty());
    assert_eq!(list.rows_returned, 3);
    assert!(!list.warnings.is_empty());
    assert!(
        !list.could_be_unprivileged(),
        "PVE returned rows, so the token could see them"
    );
}

// --- Node inventory ------------------------------------------------------

#[tokio::test]
async fn pve9_inventory_skips_root_hubs_and_matches_the_mapping_paths() {
    let (client, transport) = pve(
        fixtures::pve9::VERSION,
        &[fixtures::pve9::INVENTORY, fixtures::pve9::LIST],
    )
    .client();

    let inventory = client.usb_inventory(request(), "pve").await.unwrap();

    assert_eq!(inventory.version, "9.2.2");
    assert_eq!(inventory.node, "pve");
    assert_eq!(inventory.root_hubs, 6);
    assert!(inventory.warnings.is_empty(), "{:?}", inventory.warnings);
    assert!(!inventory.truncated);
    let paths: Vec<_> = inventory.devices.iter().map(|d| d.path.as_str()).collect();
    assert_eq!(paths, ["1-10", "1-7", "5-1", "5-3"]);
    let drive = &inventory.devices[0];
    assert_eq!(drive.hardware_id(), "05ac:1500");
    assert_eq!(drive.usbpath, "10");
    assert_eq!(drive.port, Some(9));
    assert_eq!(drive.speed.as_deref(), Some("480"));
    assert_eq!(drive.manufacturer.as_deref(), Some("Apple Inc."));
    assert_eq!(drive.product.as_deref(), Some("MacBook Air SuperDrive"));
    assert_eq!(
        transport.requests().last().unwrap(),
        "/api2/json/nodes/pve/hardware/usb"
    );

    // The fingerprint join the allocation relies on: every path-based
    // mapping entry names a device by the same `<bus>-<usbpath>` and id.
    let list = client.usb_mappings(request(), None).await.unwrap();
    let (mut by_path, mut by_id) = (0, 0);
    for mapping in &list.mappings {
        for entry in &mapping.entries {
            if let Some(path) = &entry.path {
                // A path names exactly one device, whose id must agree.
                let device = inventory
                    .devices
                    .iter()
                    .find(|device| &device.path == path)
                    .unwrap_or_else(|| panic!("no device at {path} for {}", mapping.id));
                assert_eq!(device.hardware_id(), entry.hardware_id(), "{}", mapping.id);
                by_path += 1;
            } else {
                // An id-only entry matches by id alone: the inventory must
                // hold at least one device with that id, and PVE's choice
                // among several is not knowable from here.
                let matching = inventory
                    .devices
                    .iter()
                    .filter(|device| device.hardware_id() == entry.hardware_id())
                    .count();
                assert!(matching >= 1, "no device with the id of {}", mapping.id);
                by_id += 1;
            }
        }
    }
    assert_eq!(
        (by_path, by_id),
        (2, 2),
        "superdrive-a and -b by path; decker and verbatim by id"
    );
    // The two SuperDrives share an id, which is why a path matters.
    let drives = inventory
        .devices
        .iter()
        .filter(|device| device.hardware_id() == "05ac:1500")
        .count();
    assert_eq!(drives, 2);
}

#[tokio::test]
async fn pve8_inventory_reads_the_same_shape() {
    let (client, _) = pve(fixtures::pve8::VERSION, &[fixtures::pve8::INVENTORY]).client();

    let inventory = client.usb_inventory(request(), "pve8").await.unwrap();

    assert_eq!(inventory.version, "8.4.0");
    assert_eq!(inventory.root_hubs, 1);
    assert_eq!(inventory.devices.len(), 1);
    let tablet = &inventory.devices[0];
    assert_eq!(
        tablet.path, "1-1",
        "bus 1, usbpath 1: the mapping's path=1-1"
    );
    assert_eq!(tablet.hardware_id(), "0627:0001");
    assert_eq!(tablet.product.as_deref(), Some("QEMU USB Tablet"));
}

// --- Classified errors ---------------------------------------------------

#[tokio::test]
async fn the_inventory_without_sys_modify_is_a_permission_error_naming_it() {
    for (version, refused, node) in [
        (
            fixtures::pve9::VERSION,
            fixtures::pve9::UNPRIVILEGED_INVENTORY,
            "pve",
        ),
        (
            fixtures::pve8::VERSION,
            fixtures::pve8::UNPRIVILEGED_INVENTORY,
            "pve8",
        ),
    ] {
        let (client, _) = pve(version, &[refused]).client();
        match client.usb_inventory(request(), node).await {
            Err(PveUsbError::PermissionDenied { detail, required }) => {
                assert!(detail.contains("Sys.Modify"), "{detail}");
                let required = required.expect("the 403 names its privilege");
                assert_eq!(required.path, "/");
                assert_eq!(required.privilege, "Sys.Modify");
            }
            other => panic!("expected a permission error, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn an_old_pve_without_the_endpoints_is_endpoint_absent_with_its_version() {
    // Synthetic: the spike recorded no PVE that predates resource mappings.
    // PVE answers an unknown path 501 `Method '...' not implemented`; 404
    // is treated the same way.
    for status in [501_u16, 404] {
        let (client, _) = raw("7.4-17")
            .route(
                LIST,
                status,
                br#"{"data":null,"message":"Method 'GET /cluster/mapping/usb' not implemented\n"}"#,
            )
            .route(
                "/api2/json/nodes/pve/hardware/usb",
                status,
                br#"{"data":null,"message":"Method 'GET /nodes/pve/hardware/usb' not implemented\n"}"#,
            )
            .client();
        for result in [
            client.usb_mappings(request(), None).await.map(|_| ()),
            client.usb_inventory(request(), "pve").await.map(|_| ()),
        ] {
            match result {
                Err(PveUsbError::EndpointAbsent { version, detail }) => {
                    assert_eq!(version.as_deref(), Some("7.4-17"));
                    assert!(detail.contains("not implemented"), "{detail}");
                }
                other => panic!("expected EndpointAbsent for {status}, got {other:?}"),
            }
        }
    }
}

#[tokio::test]
async fn refused_credentials_and_unreadable_answers_are_classified() {
    let (client, _) = raw("9.2.2")
        .route(LIST, 401, b"{}")
        .route(
            "/api2/json/nodes/pve/hardware/usb",
            500,
            b"{\"data\":null,\"message\":\"boom\\n\"}",
        )
        .route("/api2/json/nodes/down/hardware/usb", 595, b"")
        .route(
            "/api2/json/nodes/junk/hardware/usb",
            200,
            b"<html>not json</html>",
        )
        .route(
            "/api2/json/nodes/obj/hardware/usb",
            200,
            br#"{"data":{"not":"a list"}}"#,
        )
        .client();

    assert!(matches!(
        client.usb_mappings(request(), None).await,
        Err(PveUsbError::Unauthenticated)
    ));
    assert!(matches!(
        client.usb_inventory(request(), "pve").await,
        Err(PveUsbError::Unreadable {
            cause: PveApiError::Http { status: 500, .. }
        })
    ));
    assert!(matches!(
        client.usb_inventory(request(), "down").await,
        Err(PveUsbError::Unreadable {
            cause: PveApiError::Http { status: 595, .. }
        })
    ));
    assert!(matches!(
        client.usb_inventory(request(), "junk").await,
        Err(PveUsbError::Unreadable {
            cause: PveApiError::InvalidPayload { .. }
        })
    ));
    assert!(matches!(
        client.usb_inventory(request(), "obj").await,
        Err(PveUsbError::Unreadable {
            cause: PveApiError::InvalidPayload { .. }
        })
    ));
}

#[tokio::test]
async fn transport_failures_keep_their_class() {
    let (client, _) = raw("9.2.2")
        .fail(
            LIST,
            PveTransportError::FingerprintMismatch {
                observed: "AA".to_owned(),
                pinned: Some(FP.to_owned()),
            },
        )
        .fail(
            "/api2/json/nodes/pve/hardware/usb",
            PveTransportError::BodyTooLarge { limit: 8 },
        )
        .client();
    assert!(matches!(
        client.usb_mappings(request(), None).await,
        Err(PveUsbError::Unreadable {
            cause: PveApiError::Transport(PveTransportError::FingerprintMismatch { .. })
        })
    ));
    assert!(matches!(
        client.usb_inventory(request(), "pve").await,
        Err(PveUsbError::Unreadable {
            cause: PveApiError::Transport(PveTransportError::BodyTooLarge { .. })
        })
    ));

    // A host that cannot be reached at all fails at the version, classified
    // the same way.
    let (client, _) = UsbTransport::new()
        .fail(
            "/api2/json/version",
            PveTransportError::Connect {
                detail: "refused".to_owned(),
            },
        )
        .client();
    assert!(matches!(
        client.usb_mappings(request(), None).await,
        Err(PveUsbError::Unreadable {
            cause: PveApiError::Transport(PveTransportError::Connect { .. })
        })
    ));
}

#[tokio::test]
async fn unsafe_names_are_refused_before_any_request() {
    let (client, transport) = UsbTransport::new().client();
    for node in ["", "..", "a/b", "pve?x=1", "pve\n", "pve node"] {
        assert!(matches!(
            client.usb_mappings(request(), Some(node)).await,
            Err(PveUsbError::InvalidRequest { .. })
        ));
        assert!(matches!(
            client.usb_inventory(request(), node).await,
            Err(PveUsbError::InvalidRequest { .. })
        ));
    }
    for id in ["", "a/b", "a,b", "a=b", "..", &"x".repeat(65)] {
        assert!(matches!(
            client.usb_mapping(request(), id).await,
            Err(PveUsbError::InvalidRequest { .. })
        ));
    }
    assert!(transport.requests().is_empty(), "nothing was sent");
}

// --- Malformed and oversized answers -------------------------------------

#[tokio::test]
async fn malformed_entries_are_isolated_into_warnings_over_the_wire() {
    let body = json!({"data": [
        {"id": "ok", "type": "usb", "digest": "abc", "map": ["node=pve,id=05ac:1500,path=1-10"],
         "errors": []},
        {"id": "no-id-in-entry", "map": ["node=pve,path=1-10"], "errors": []},
        {"id": "garbage-entry", "map": ["not a property string", 5, null], "errors": [{"severity": "error"}]},
        {"map": ["node=pve,id=05ac:1500"]},
        "a string",
        [],
        {"id": "no-errors", "map": ["node=pve,id=18a5:0428"]},
    ]});
    let (client, _) = raw("9.2.2")
        .route(
            "/api2/json/cluster/mapping/usb?check-node=pve",
            200,
            body.to_string().as_bytes(),
        )
        .client();

    let list = client.usb_mappings(request(), Some("pve")).await.unwrap();

    let ids: Vec<_> = list.mappings.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(ids, ["garbage-entry", "no-errors", "no-id-in-entry", "ok"]);
    let by_id = |id: &str| list.mappings.iter().find(|m| m.id == id).unwrap();
    assert_eq!(by_id("ok").check_passed(), Some(true));
    assert_eq!(by_id("no-id-in-entry").unreadable_entries, 1);
    assert!(by_id("no-id-in-entry").entries.is_empty());
    assert_eq!(by_id("garbage-entry").unreadable_entries, 3);
    assert_eq!(
        by_id("garbage-entry").check_passed(),
        Some(false),
        "an unreadable finding never reads as a pass"
    );
    assert_eq!(
        by_id("no-errors").issues,
        None,
        "a check that answered nothing is unknown, not clean"
    );
    assert!(!list.warnings.is_empty());
    assert!(list.warnings.iter().all(|w| !w.contains('\n')));
}

#[tokio::test]
async fn an_oversized_mapping_list_is_bounded_and_marked_incomplete() {
    let rows: Vec<Value> = (0..MAX_USB_MAPPINGS + 100)
        .map(|index| json!({"id": format!("m{index:05}"), "map": ["node=pve,id=05ac:1500"]}))
        .collect();
    let (client, _) = raw("9.2.2")
        .route(LIST, 200, json!({ "data": rows }).to_string().as_bytes())
        .client();

    let list = client.usb_mappings(request(), None).await.unwrap();

    assert_eq!(list.mappings.len(), MAX_USB_MAPPINGS);
    assert!(list.truncated, "an incomplete list must not pass as whole");
    assert!(!list.could_be_unprivileged());
}

#[tokio::test]
async fn an_oversized_inventory_is_bounded_and_marked_incomplete() {
    let rows: Vec<Value> = (0..MAX_USB_DEVICES + 100)
        .map(|index| {
            json!({"busnum": 1, "devnum": index + 2, "level": 1, "usbpath": "1",
                   "vendid": "05ac", "prodid": "1500", "product": "x".repeat(10_000)})
        })
        .collect();
    let (client, _) = raw("9.2.2")
        .route(
            "/api2/json/nodes/pve/hardware/usb",
            200,
            json!({ "data": rows }).to_string().as_bytes(),
        )
        .client();

    let inventory = client.usb_inventory(request(), "pve").await.unwrap();

    assert_eq!(inventory.devices.len(), MAX_USB_DEVICES);
    assert!(inventory.truncated);
    assert!(
        inventory
            .devices
            .iter()
            .all(|device| device.product.as_ref().unwrap().chars().count() <= 257),
        "display strings are bounded"
    );
}

#[tokio::test]
async fn malformed_inventory_rows_are_isolated_over_the_wire() {
    let body = json!({"data": [
        {"busnum": 1, "devnum": 1, "level": 0, "vendid": "1d6b", "prodid": "0002"},
        {"busnum": 1, "devnum": 2, "level": 1, "usbpath": "4", "vendid": "05ac", "prodid": "1500",
         "speed": "480", "class": "0", "product": "Fine\u{1b}[31m\nDevice"},
        {"busnum": 1, "devnum": 3, "level": 1, "vendid": "05ac", "prodid": "1500"},
        {"busnum": "x", "devnum": 4, "usbpath": "5", "vendid": "05ac", "prodid": "1500"},
        {"busnum": 1, "devnum": 5, "usbpath": "6", "vendid": "05ac"},
        7, null, "text"
    ]});
    let (client, _) = raw("9.2.2")
        .route(
            "/api2/json/nodes/pve/hardware/usb",
            200,
            body.to_string().as_bytes(),
        )
        .client();

    let inventory = client.usb_inventory(request(), "pve").await.unwrap();

    assert_eq!(inventory.root_hubs, 1);
    assert_eq!(inventory.devices.len(), 1);
    let device = &inventory.devices[0];
    assert_eq!(device.path, "1-4");
    assert_eq!(device.class, Some(0), "a stringly class is accepted");
    let product = device.product.as_deref().unwrap();
    assert!(
        !product.contains('\u{1b}') && !product.contains('\n'),
        "{product:?}"
    );
    assert_eq!(inventory.warnings.len(), 6, "{:#?}", inventory.warnings);
}

#[tokio::test]
async fn a_malformed_optional_device_field_keeps_the_device_over_the_wire() {
    let body = json!({"data": [
        {"busnum": 1, "devnum": 2, "level": "top", "port": [], "class": "no",
         "usbpath": "4", "vendid": "05ac", "prodid": "1500", "speed": "480"},
        {"busnum": 1, "devnum": 3, "level": 1, "usbpath": "5", "vendid": "xxxx", "prodid": "1500"},
    ]});
    let (client, _) = raw("9.2.2")
        .route(
            "/api2/json/nodes/pve/hardware/usb",
            200,
            body.to_string().as_bytes(),
        )
        .client();

    let inventory = client.usb_inventory(request(), "pve").await.unwrap();

    assert_eq!(inventory.devices.len(), 1, "a bad vendid still drops a row");
    let device = &inventory.devices[0];
    assert_eq!(device.path, "1-4");
    assert_eq!(
        (device.level, device.port, device.class),
        (None, None, None)
    );
    assert_eq!(device.speed.as_deref(), Some("480"));
    assert_eq!(
        inventory.warnings.len(),
        4,
        "three left-out fields and one dropped row: {:#?}",
        inventory.warnings
    );
}

// --- Fixture hygiene -------------------------------------------------------

/// The directory of this crate's fixture copies.
fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/usb")
}

/// Every `.json` file under `dir`, sorted, with its path relative to `dir`.
fn json_files(dir: &Path) -> Vec<(String, String)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()))
            .map(|entry| entry.expect("a directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(root, &path, out);
            } else if path.extension().is_some_and(|ext| ext == "json") {
                let relative = path
                    .strip_prefix(root)
                    .expect("under the root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
                out.push((relative, text));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out
}

/// Whether `text` holds something shaped like an IPv4 address: four or more
/// dot-separated digit groups (a trailing or leading dot, as at the end of a
/// sentence, does not hide one). Versions have at most three groups.
fn has_ipv4_like_run(text: &str) -> Option<String> {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .map(|run| run.trim_matches('.'))
        .find(|run| {
            let groups: Vec<_> = run.split('.').collect();
            groups.len() >= 4 && groups.iter().all(|group| !group.is_empty())
        })
        .map(str::to_owned)
}

/// Whether `text` holds a MAC address (six hex pairs joined by `:` or `-`)
/// or an IPv6-shaped run (four or more colon-separated hex groups).
fn has_mac_or_ipv6_like_run(text: &str) -> Option<String> {
    text.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '-'))
        .find(|token| {
            [':', '-'].iter().any(|separator| {
                let parts: Vec<_> = token.split(*separator).collect();
                parts.len() == 6
                    && parts
                        .iter()
                        .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
            }) || {
                let groups: Vec<_> = token.split(':').collect();
                groups.len() >= 4
                    && groups
                        .iter()
                        .all(|g| g.len() <= 4 && g.bytes().all(|b| b.is_ascii_hexdigit()))
            }
        })
        .map(str::to_owned)
}

/// Whether `text` holds a UUID (8-4-4-4-12 hex digits).
fn has_uuid_like_run(text: &str) -> Option<String> {
    text.split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
        .find(|token| {
            let parts: Vec<_> = token.split('-').collect();
            parts.len() == 5
                && parts.iter().zip([8, 4, 4, 4, 12]).all(|(part, len)| {
                    part.len() == len && part.bytes().all(|b| b.is_ascii_hexdigit())
                })
        })
        .map(str::to_owned)
}

#[test]
fn the_hygiene_detectors_detect_what_they_claim() {
    for positive in ["10.0.0.1", "see 192.168.1.20.", "(10.1.2.3)", "1.2.3.4.5"] {
        assert!(has_ipv4_like_run(positive).is_some(), "{positive}");
    }
    for negative in [
        "9.2.2",
        "pve-manager/9.2.2/abc",
        "05ac:1500",
        "version 8.4.",
    ] {
        assert!(has_ipv4_like_run(negative).is_none(), "{negative}");
    }
    for positive in [
        "aa:bb:cc:dd:ee:ff",
        "AA-BB-CC-DD-EE-FF",
        "mac=00:1a:2b:3c:4d:5e,",
        "fe80:0:0:0:1:2:3:4",
    ] {
        assert!(has_mac_or_ipv6_like_run(positive).is_some(), "{positive}");
    }
    for negative in [
        "05ac:1500",
        "node=pve,id=05ac:1500,path=1-10",
        "fm-test-superdrive-a",
        "usb device '1-10' not found",
    ] {
        assert!(has_mac_or_ipv6_like_run(negative).is_none(), "{negative}");
    }
    for positive in [
        "123e4567-e89b-12d3-a456-426614174000",
        "id 123E4567-E89B-12D3-A456-426614174000.",
    ] {
        assert!(has_uuid_like_run(positive).is_some(), "{positive}");
    }
    for negative in [
        "fm-test-superdrive-a",
        "1234-5678",
        "9496fd191eaf9792205190511d20822ddd76722e",
    ] {
        assert!(has_uuid_like_run(negative).is_none(), "{negative}");
    }
}

#[test]
fn fixtures_carry_no_serials_addresses_or_credentials() {
    let files = json_files(&fixture_dir());
    assert!(
        files.len() >= 20,
        "the fixture directory should hold the recordings, found {}",
        files.len()
    );
    for (name, fixture) in &files {
        assert!(
            serde_json::from_str::<Value>(fixture).is_ok(),
            "{name} is not JSON"
        );
        let lowered = fixture.to_ascii_lowercase();
        for forbidden in [
            "serial",
            "secret",
            "password",
            "ticket",
            "pveapitoken",
            "csrf",
        ] {
            assert!(!lowered.contains(forbidden), "{forbidden} in {name}");
        }
        if let Some(run) = has_ipv4_like_run(fixture) {
            panic!("an address-like run {run:?} in {name}");
        }
        if let Some(run) = has_mac_or_ipv6_like_run(fixture) {
            panic!("a MAC- or IPv6-like run {run:?} in {name}");
        }
        if let Some(run) = has_uuid_like_run(fixture) {
            panic!("a UUID-like run {run:?} in {name}");
        }
    }
}

/// The fixture copies must stay byte-identical to the spike's recordings
/// (`docs/research/fixtures/proxmox-usb/`): `pve9/` is `pve-9.2.2/` and
/// `pve8/` is `pve-8.4.0/`. Skipped, loudly, only when that directory is not
/// in this checkout (a packaged crate); a missing file inside it fails.
#[test]
fn the_fixture_copies_have_not_drifted_from_the_spike_recordings() {
    let source_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/research/fixtures/proxmox-usb");
    if !source_root.is_dir() {
        eprintln!(
            "SKIPPED: {} does not exist, so the fixture copies were not compared with the spike recordings",
            source_root.display()
        );
        return;
    }
    let mut compared = 0;
    for (copy_dir, source_dir) in [("pve9", "pve-9.2.2"), ("pve8", "pve-8.4.0")] {
        let copies = json_files(&fixture_dir().join(copy_dir));
        assert!(!copies.is_empty(), "no fixture copies under {copy_dir}");
        for (name, copy) in copies {
            let source_path = source_root.join(source_dir).join(&name);
            let source = std::fs::read_to_string(&source_path).unwrap_or_else(|error| {
                panic!(
                    "{copy_dir}/{name} has no source at {}: {error}",
                    source_path.display()
                )
            });
            assert_eq!(
                copy, source,
                "{copy_dir}/{name} drifted from {source_dir}/{name}; refresh the copy from the spike recordings"
            );
            compared += 1;
        }
    }
    assert!(compared >= 20, "only {compared} fixtures compared");
}
