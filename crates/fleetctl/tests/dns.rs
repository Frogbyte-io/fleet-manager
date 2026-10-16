//! `fleetctl dns` (FM-1042): the parsed grammar, the controller requests it
//! sends, the bounded wait for approval and its JSON outcome, and the human
//! renderer.

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fleetctl::dns::{ChangeKind, DnsAction};
use serde_json::{Value, json};

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(ToString::to_string).collect()
}

#[derive(Clone, Debug)]
struct Seen {
    line: String,
    body: String,
}

/// A scripted controller: answers by request line prefix, in order for
/// repeated prefixes, repeating the last answer.
struct Controller {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Controller {
    fn start(script: Vec<(&'static str, u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen_in, stop_in) = (seen.clone(), stop.clone());
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut served: Vec<usize> = vec![0; script.len()];
            while !stop_in.load(Ordering::SeqCst) && Instant::now() < deadline {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut content_length = 0_usize;
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:")
                    {
                        content_length = value.trim().parse().unwrap();
                    }
                    if header == "\r\n" || header.is_empty() {
                        break;
                    }
                }
                let mut body = vec![0; content_length];
                reader.read_exact(&mut body).unwrap();
                let line = line.trim_end().to_owned();
                seen_in.lock().unwrap().push(Seen {
                    line: line.clone(),
                    body: String::from_utf8(body).unwrap(),
                });
                // The answers of the matching prefix, in order.
                let matching: Vec<usize> = script
                    .iter()
                    .enumerate()
                    .filter(|(_, (prefix, _, _))| line.starts_with(prefix))
                    .map(|(index, _)| index)
                    .collect();
                let pick = matching
                    .iter()
                    .copied()
                    .find(|index| served[*index] == 0)
                    .or_else(|| matching.last().copied());
                let (status, answer) = match pick {
                    Some(index) => {
                        served[index] += 1;
                        (script[index].1, script[index].2.clone())
                    }
                    None => (404, "{}".to_owned()),
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                    answer.len()
                );
                let _ = stream.flush();
            }
        });
        Self {
            url,
            seen,
            stop,
            handle: Some(handle),
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn request(state: &str, operation_id: Option<&str>) -> String {
    json!({ "data": {
        "id": "req-1",
        "requester": "agent-7",
        "origin": "api",
        "actionId": "dns.record.upsert",
        "target": "www.example.com A",
        "parameters": { "preview": {
            "operation": "update",
            "before": {"id": "r1", "type": "A", "name": "www.example.com", "content": "203.0.113.2", "ttl": 300, "proxied": false},
            "after": {"type": "A", "name": "www.example.com", "content": "203.0.113.9", "ttl": 600, "proxied": false},
            "changes": []
        } },
        "riskClass": "approve",
        "reason": "move www",
        "state": state,
        "terminal": !matches!(state, "pending" | "approved" | "executing"),
        "decidedBy": null, "decidedAt": null, "decisionNote": null,
        "operationId": operation_id, "failure": null,
        "createdAt": 1, "expiresAt": 2, "updatedAt": 3,
    } })
    .to_string()
}

fn run(controller: &Controller, words: &[&str]) -> Result<(String, u8), fleetctl::CliError> {
    let mut all = vec!["--url", &controller.url];
    all.extend_from_slice(words);
    let invocation = fleetctl::parse(&args(&all)).unwrap();
    fleetctl::run_with_exit(&invocation)
}

fn parse(words: &[&str]) -> Result<fleetctl::Invocation, fleetctl::CliError> {
    fleetctl::parse(&args(words))
}

#[test]
#[allow(clippy::too_many_lines)]
fn parsing_walks_the_dns_forms() {
    let invocation = parse(&[
        "dns",
        "records",
        "www.example.com",
        "--type",
        "A",
        "--account",
        "dns",
    ])
    .unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::Dns(DnsAction::Records {
            name: "www.example.com".to_owned(),
            record_type: Some("A".to_owned()),
            account: Some("dns".to_owned()),
        })
    );
    let invocation = parse(&[
        "dns",
        "set",
        "www.example.com",
        "--type",
        "A",
        "--content",
        "203.0.113.9",
        "--ttl",
        "600",
        "--proxied",
        "--replaces",
        "203.0.113.2",
        "--reason",
        "move",
        "--wait-approval=2m",
    ])
    .unwrap();
    let fleetctl::Command::Dns(DnsAction::Change {
        kind,
        ttl,
        proxied,
        replaces,
        wait,
        reason,
        ..
    }) = invocation.command
    else {
        panic!("a change");
    };
    assert_eq!(kind, ChangeKind::Set);
    assert_eq!(ttl, Some(600));
    assert_eq!(proxied, Some(true));
    assert_eq!(replaces.as_deref(), Some("203.0.113.2"));
    assert_eq!(wait, Some(Duration::from_secs(120)));
    assert_eq!(reason, "move");

    // A bare --wait-approval waits the default; a delete takes no TTL.
    let invocation = parse(&[
        "dns",
        "delete",
        "www.example.com",
        "--type",
        "A",
        "--content",
        "203.0.113.2",
        "--wait-approval",
    ])
    .unwrap();
    let fleetctl::Command::Dns(DnsAction::Change { kind, wait, .. }) = invocation.command else {
        panic!("a change");
    };
    assert_eq!(kind, ChangeKind::Delete);
    assert_eq!(wait, Some(fleetctl::requests::DEFAULT_WAIT));
    assert!(
        parse(&[
            "dns",
            "delete",
            "x.example.com",
            "--type",
            "A",
            "--content",
            "1.2.3.4",
            "--ttl",
            "60"
        ])
        .is_err()
    );

    // Missing pieces and bad values are refused.
    assert!(parse(&["dns", "set", "www.example.com", "--type", "A"]).is_err());
    assert!(parse(&["dns", "set", "www.example.com", "--content", "1.2.3.4"]).is_err());
    assert!(parse(&["dns", "records"]).is_err());
    assert!(parse(&["dns", "records", "--type", "A"]).is_err());
    assert!(parse(&["dns", "nope"]).is_err());
    assert!(
        parse(&[
            "dns",
            "set",
            "w.example.com",
            "--type",
            "A",
            "--content",
            "x",
            "--wait-approval=0"
        ])
        .is_err()
    );
    assert!(
        parse(&[
            "dns",
            "set",
            "w.example.com",
            "--type",
            "MX",
            "--content",
            "x",
            "--priority",
            "70000"
        ])
        .is_err()
    );
}

#[test]
fn records_and_zones_read_through_the_dns_routes() {
    let records = json!({"data": {
        "accountId": "acc1", "accountLabel": "dns",
        "zone": {"id": "z1", "name": "example.com", "status": "active"},
        "name": "www.example.com",
        "records": [{"id": "r1", "type": "A", "name": "www.example.com", "content": "203.0.113.1", "ttl": 300, "proxied": false}],
        "registryEntry": "domain/example.com", "observedAt": 1
    }})
    .to_string();
    let controller = Controller::start(vec![("GET /api/v1/dns/records", 200, records)]);
    let (text, exit) = run(
        &controller,
        &[
            "dns",
            "records",
            "www.example.com",
            "--type",
            "A",
            "--output",
            "text",
        ],
    )
    .unwrap();
    assert_eq!(exit, 0);
    assert!(text.contains("www.example.com"), "{text}");
    assert!(text.contains("203.0.113.1"), "{text}");
    assert!(text.contains("domain/example.com"), "{text}");
    let seen = controller.seen();
    assert!(
        seen[0].line.starts_with("GET /api/v1/dns/records?"),
        "{}",
        seen[0].line
    );
    assert!(seen[0].line.contains("name=www.example.com"));
    assert!(seen[0].line.contains("type=A"));

    let zones = json!({"data": {"accounts": [
        {"accountId": "acc1", "accountLabel": "dns", "zones": [{"id": "z1", "name": "example.com", "status": "active"}], "failure": null, "failureDetail": null},
        {"accountId": "acc2", "accountLabel": "other", "zones": [], "failure": "auth", "failureDetail": "the token was refused"}
    ]}})
    .to_string();
    let controller = Controller::start(vec![("GET /api/v1/dns/zones", 200, zones)]);
    let (text, _) = run(&controller, &["dns", "zones", "--output", "text"]).unwrap();
    assert!(text.contains("example.com"), "{text}");
    assert!(text.contains("failed (auth)"), "{text}");
}

#[test]
fn a_set_files_the_request_and_shows_the_preview_without_waiting() {
    let controller = Controller::start(vec![(
        "POST /api/v1/dns/changes",
        201,
        request("pending", None),
    )]);
    let (text, exit) = run(
        &controller,
        &[
            "dns",
            "set",
            "www.example.com",
            "--type",
            "a",
            "--content",
            "203.0.113.9",
            "--ttl",
            "600",
            "--replaces",
            "203.0.113.2",
            "--idempotency-key",
            "k1",
            "--output",
            "text",
        ],
    )
    .unwrap();
    assert_eq!(exit, 0);
    assert!(text.contains("pending"), "{text}");
    assert!(text.contains("now:"), "{text}");
    assert!(text.contains("203.0.113.2"), "{text}");
    assert!(text.contains("then:"), "{text}");
    assert!(text.contains("203.0.113.9"), "{text}");
    let seen = controller.seen();
    assert_eq!(seen.len(), 1, "no wait, no polling");
    let body: Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(body["operation"], "upsert");
    assert_eq!(body["type"], "a");
    assert_eq!(body["ttl"], 600);
    assert_eq!(body["replaces"], "203.0.113.2");
    assert_eq!(body["idempotencyKey"], "k1");
    assert_eq!(body["reason"], "requested with fleetctl dns");
    assert!(body.get("proxied").is_none());
}

#[test]
fn wait_approval_answers_the_json_outcome_with_what_the_operation_did() {
    let result = json!({"outcome": "updated", "verified": true, "record": {"id": "r1", "type": "A", "name": "www.example.com", "content": "203.0.113.9", "ttl": 600, "proxied": false}});
    let operation =
        json!({"data": {"id": "op-1", "state": "succeeded", "resultJson": result.to_string()}})
            .to_string();
    let controller = Controller::start(vec![
        ("POST /api/v1/dns/changes", 201, request("pending", None)),
        ("GET /api/v1/requests/req-1", 200, request("pending", None)),
        (
            "GET /api/v1/requests/req-1",
            200,
            request("executing", Some("op-1")),
        ),
        (
            "GET /api/v1/requests/req-1",
            200,
            request("succeeded", Some("op-1")),
        ),
        ("GET /api/v1/operations/op-1", 200, operation),
    ]);
    let (text, exit) = run(
        &controller,
        &[
            "dns",
            "set",
            "www.example.com",
            "--type",
            "A",
            "--content",
            "203.0.113.9",
            "--wait-approval=30s",
            "--output",
            "json",
        ],
    )
    .unwrap();
    assert_eq!(exit, 0, "{text}");
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["outcome"], "executed");
    assert_eq!(answer["request"]["state"], "succeeded");
    assert_eq!(answer["result"]["outcome"], "updated");
    assert_eq!(answer["result"]["record"]["content"], "203.0.113.9");
}

#[test]
fn wait_approval_reports_a_denial_and_a_bound_that_passes() {
    let controller = Controller::start(vec![
        ("POST /api/v1/dns/changes", 201, request("pending", None)),
        ("GET /api/v1/requests/req-1", 200, request("denied", None)),
    ]);
    let (text, exit) = run(
        &controller,
        &[
            "dns",
            "delete",
            "www.example.com",
            "--type",
            "A",
            "--content",
            "203.0.113.2",
            "--wait-approval=30s",
            "--output",
            "json",
        ],
    )
    .unwrap();
    assert_eq!(exit, 1);
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["outcome"], "denied");
    assert!(answer.get("result").is_none());

    // Nobody decides within the bound: still pending, exit 2, the request
    // stays durable.
    let controller = Controller::start(vec![
        ("POST /api/v1/dns/changes", 201, request("pending", None)),
        ("GET /api/v1/requests/req-1", 200, request("pending", None)),
    ]);
    let (text, exit) = run(
        &controller,
        &[
            "dns",
            "set",
            "www.example.com",
            "--type",
            "A",
            "--content",
            "203.0.113.9",
            "--wait-approval=1s",
            "--output",
            "json",
        ],
    )
    .unwrap();
    assert_eq!(exit, 2, "{text}");
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["outcome"], "still_pending");
    assert_eq!(answer["request"]["id"], "req-1");
}

#[test]
fn a_refused_change_is_a_cli_error_with_the_controllers_reason() {
    let refusal = json!({"code": "invalid_request", "message": "invalid: the record already matches; there is nothing to change", "retry": "never"}).to_string();
    let controller = Controller::start(vec![("POST /api/v1/dns/changes", 400, refusal)]);
    let error = run(
        &controller,
        &[
            "dns",
            "set",
            "www.example.com",
            "--type",
            "A",
            "--content",
            "203.0.113.1",
        ],
    )
    .expect_err("refused");
    assert!(
        error.message.contains("nothing to change"),
        "{}",
        error.message
    );
}

#[test]
fn add_no_proxied_priority_and_observations_parse_and_send() {
    let invocation = parse(&[
        "dns",
        "set",
        "www.example.com",
        "--type",
        "A",
        "--content",
        "203.0.113.9",
        "--add",
        "--no-proxied",
    ])
    .unwrap();
    let fleetctl::Command::Dns(DnsAction::Change { add, proxied, .. }) = invocation.command else {
        panic!("a change");
    };
    assert!(add);
    assert_eq!(proxied, Some(false));
    // A delete names an MX record's priority.
    let invocation = parse(&[
        "dns",
        "delete",
        "example.com",
        "--type",
        "MX",
        "--content",
        "mail.example.net",
        "--priority",
        "20",
    ])
    .unwrap();
    let fleetctl::Command::Dns(DnsAction::Change { priority, .. }) = invocation.command else {
        panic!("a change");
    };
    assert_eq!(priority, Some(20));
    // --add belongs to set only.
    assert!(
        parse(&[
            "dns",
            "delete",
            "x.example.com",
            "--type",
            "A",
            "--content",
            "1.2.3.4",
            "--add"
        ])
        .is_err()
    );

    let observed = json!({"data": {
        "name": "www.example.com",
        "observations": [{
            "accountId": "acc1", "zoneId": "z1", "zoneName": "example.com",
            "name": "www.example.com", "registryEntry": "domain/example.com",
            "records": [{"id": "r1", "type": "A", "name": "www.example.com", "content": "203.0.113.1", "ttl": 300, "proxied": false}],
            "observedAt": 5
        }]
    }})
    .to_string();
    let controller = Controller::start(vec![("GET /api/v1/dns/observations", 200, observed)]);
    let (text, exit) = run(
        &controller,
        &["dns", "observations", "www.example.com", "--output", "text"],
    )
    .unwrap();
    assert_eq!(exit, 0);
    assert!(text.contains("registry domain/example.com"), "{text}");
    assert!(text.contains("203.0.113.1"), "{text}");
    assert!(controller.seen()[0].line.contains("name=www.example.com"));
}

#[test]
fn wait_approval_reports_a_failed_or_stale_change_with_exit_one() {
    let controller = Controller::start(vec![
        ("POST /api/v1/dns/changes", 201, request("pending", None)),
        (
            "GET /api/v1/requests/req-1",
            200,
            request("failed", Some("op-1")),
        ),
    ]);
    let (text, exit) = run(
        &controller,
        &[
            "dns",
            "set",
            "www.example.com",
            "--type",
            "A",
            "--content",
            "203.0.113.9",
            "--wait-approval=30s",
            "--output",
            "json",
        ],
    )
    .unwrap();
    assert_eq!(exit, 1, "{text}");
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["outcome"], "failed");
    assert_eq!(answer["request"]["state"], "failed");
    assert!(
        answer.get("result").is_none(),
        "no result for a failed change"
    );
    // The text form says so too.
    let controller = Controller::start(vec![
        ("POST /api/v1/dns/changes", 201, request("pending", None)),
        (
            "GET /api/v1/requests/req-1",
            200,
            request("failed", Some("op-1")),
        ),
    ]);
    let (text, exit) = run(
        &controller,
        &[
            "dns",
            "delete",
            "www.example.com",
            "--type",
            "A",
            "--content",
            "203.0.113.2",
            "--wait-approval=30s",
            "--output",
            "text",
        ],
    )
    .unwrap();
    assert_eq!(exit, 1);
    assert!(text.contains("outcome: failed"), "{text}");
}
