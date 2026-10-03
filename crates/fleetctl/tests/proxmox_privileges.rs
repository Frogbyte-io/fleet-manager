//! `fleetctl proxmox privileges` (FM-604): parsing, the controller route,
//! JSON passthrough, and the human renderer.

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(ToString::to_string).collect()
}

fn report() -> Value {
    json!({
        "accountId": "acc-1",
        "pveVersion": "8.4.1",
        "rulesMajor": 8,
        "tiers": [
            {"tier": "discover", "status": "granted", "missing": [], "checks": [
                {"requirement": "read.guest-agent", "capability": "read.guest-agent",
                 "endpoint": "GET /nodes/{node}/qemu/{vmid}/agent/{info|network-get-interfaces|get-osinfo}",
                 "required": false, "status": "missing", "privileges": ["VM.Monitor"],
                 "anyOf": false, "path": "/vms/{vmid}", "grantedOn": [],
                 "missing": ["VM.Monitor"], "note": "Opt-in on 8.x."}
            ]},
            {"tier": "operate", "status": "missing", "missing": [
                {"privileges": ["VM.PowerMgmt"], "anyOf": false, "path": "/vms/{vmid}",
                 "capabilities": ["proxmox.guest.start", "proxmox.guest.stop"]}
            ], "checks": []},
            {"tier": "destructive", "status": "missing", "missing": [
                {"privileges": ["VM.Snapshot", "VM.Snapshot.Rollback"], "anyOf": true,
                 "path": "/vms/{vmid}", "capabilities": ["proxmox.guest.snapshot-revert"]}
            ], "checks": []},
            {"tier": "lab", "status": "missing", "missing": [], "checks": []}
        ],
        "unknownReason": null,
        "effectivePermissions": {"/": {"VM.Audit": true}},
        "warnings": ["the permissions answer exceeded the bounds"],
        "observedAt": 1
    })
}

#[test]
fn parsing_accepts_the_documented_forms() {
    let invocation = fleetctl::parse(&args(&["proxmox", "privileges", "acc-1"])).unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::ProxmoxPrivileges {
            account_id: "acc-1".to_owned()
        }
    );
    assert_eq!(invocation.output, fleetctl::Output::Text);

    // The issue documents `--output json` after the account.
    let invocation = fleetctl::parse(&args(&[
        "proxmox",
        "privileges",
        "acc-1",
        "--output",
        "json",
    ]))
    .unwrap();
    assert_eq!(invocation.output, fleetctl::Output::Json);

    // …and the global form before the command word works as everywhere.
    let invocation = fleetctl::parse(&args(&[
        "--output",
        "json",
        "proxmox",
        "privileges",
        "acc-1",
    ]))
    .unwrap();
    assert_eq!(invocation.output, fleetctl::Output::Json);
}

#[test]
fn parsing_refuses_malformed_forms() {
    for words in [
        vec!["proxmox", "privileges"],
        vec!["proxmox", "privileges", "--output", "json"],
        vec!["proxmox", "privileges", "acc-1", "--output", "xml"],
        vec!["proxmox", "privileges", "acc-1", "acc-2"],
    ] {
        assert!(fleetctl::parse(&args(&words)).is_err(), "{words:?}");
    }
}

/// One canned controller answer; returns the request line it saw.
fn fake_controller(body: String) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        // Bounded, so a client that never connects or stalls mid-request
        // fails the test instead of leaving this thread blocked forever.
        let deadline = Instant::now() + Duration::from_secs(10);
        listener.set_nonblocking(true).unwrap();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "no request reached the one-shot controller"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
        let _ = stream.read(&mut [0_u8; 1]);
        request_line
    });
    (format!("http://{address}"), handle)
}

#[test]
fn json_output_is_the_controller_report_from_the_privileges_route() {
    let (url, server) = fake_controller(json!({"data": report()}).to_string());
    let invocation = fleetctl::parse(&args(&[
        "--url",
        &url,
        "proxmox",
        "privileges",
        "acc-1",
        "--output",
        "json",
    ]))
    .unwrap();

    let output = fleetctl::run(&invocation).unwrap();

    let request_line = server.join().unwrap();
    assert!(
        request_line.starts_with("GET /api/v1/proxmox/accounts/acc-1/privileges "),
        "{request_line}"
    );
    let parsed: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed, report());
}

#[test]
fn text_output_names_tiers_missing_privileges_paths_and_opt_ins() {
    let text = fleetctl::render_proxmox_privileges_for_test(&report());
    assert!(
        text.contains("account acc-1  PVE 8.4.1  rules 8.x"),
        "{text}"
    );
    assert!(text.contains("discover     granted"), "{text}");
    assert!(text.contains("operate      missing"), "{text}");
    assert!(
        text.contains(
            "missing VM.PowerMgmt on /vms/{vmid}  (needed by proxmox.guest.start, proxmox.guest.stop)"
        ),
        "{text}"
    );
    assert!(
        text.contains("missing VM.Snapshot or VM.Snapshot.Rollback on /vms/{vmid}"),
        "{text}"
    );
    assert!(
        text.contains("opt-in read.guest-agent not granted: VM.Monitor on /vms/{vmid}"),
        "{text}"
    );
    assert!(text.contains("exceeded the bounds"), "{text}");
}

#[test]
fn text_output_reports_an_unknown_read_honestly() {
    let unknown = json!({
        "accountId": "acc-1",
        "pveVersion": null,
        "rulesMajor": null,
        "tiers": [
            {"tier": "discover", "status": "unknown", "missing": [], "checks": []},
            {"tier": "operate", "status": "unknown", "missing": [], "checks": []},
            {"tier": "destructive", "status": "unknown", "missing": [], "checks": []},
            {"tier": "lab", "status": "unknown", "missing": [], "checks": []}
        ],
        "unknownReason": "the permissions read was refused (403): Permission check failed",
        "effectivePermissions": {},
        "warnings": [],
        "observedAt": 1
    });
    let text = fleetctl::render_proxmox_privileges_for_test(&unknown);
    assert!(text.contains("PVE unknown  rules -"), "{text}");
    assert!(
        text.contains("unknown: the permissions read was refused (403)"),
        "{text}"
    );
    assert_eq!(text.matches(" unknown").count(), 5, "{text}");
}
