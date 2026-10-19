//! `fleetctl services start|stop|restart|redeploy|logs` (FM-1033): the
//! parsed grammar, the controller requests, the bounded wait for approval
//! with its JSON outcome and operation result, and the log renderer.

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fleetctl::services::ServicesAction;
use serde_json::{Value, json};

const SERVICE: &str = "coolify:acc1:appweb0001";

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

fn request(action: &str, state: &str, operation_id: Option<&str>) -> String {
    json!({ "data": {
        "id": "req-1", "requester": "agent-7", "origin": "api",
        "actionId": action, "target": SERVICE,
        "parameters": {"accountId": "acc1", "resourceKind": "application", "uuid": "appweb0001", "name": "web"},
        "riskClass": if action == "coolify.application.stop" { "approve" } else { "auto" },
        "reason": "test", "state": state,
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
fn parsing_walks_the_action_and_log_forms() {
    let invocation = parse(&[
        "services",
        "restart",
        SERVICE,
        "--reason",
        "deploy fix",
        "--idempotency-key",
        "k1",
        "--wait-approval=2m",
    ])
    .unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::Services(ServicesAction::Action {
            verb: "restart".to_owned(),
            id: SERVICE.to_owned(),
            reason: Some("deploy fix".to_owned()),
            idempotency_key: Some("k1".to_owned()),
            wait: Some(Duration::from_secs(120)),
        })
    );
    let invocation = parse(&["services", "stop", SERVICE, "--wait-approval"]).unwrap();
    let fleetctl::Command::Services(ServicesAction::Action { wait, .. }) = invocation.command
    else {
        panic!("an action");
    };
    assert_eq!(wait, Some(fleetctl::requests::DEFAULT_WAIT));
    let invocation = parse(&[
        "services",
        "logs",
        SERVICE,
        "--deployment",
        "dep1",
        "--lines",
        "50",
    ])
    .unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::Services(ServicesAction::Logs {
            id: SERVICE.to_owned(),
            deployment: Some("dep1".to_owned()),
            lines: Some(50),
        })
    );
    for bad in [
        vec!["services", "start"],
        vec!["services", "start", "-x"],
        vec!["services", "start", SERVICE, "--wait-approval=0"],
        vec!["services", "start", SERVICE, "--lines", "5"],
        vec!["services", "logs", SERVICE, "--wait-approval"],
        vec!["services", "logs", SERVICE, "--lines", "many"],
        vec!["services", "list", "--reason", "x"],
    ] {
        assert!(parse(&bad).is_err(), "{bad:?}");
    }
}

#[test]
fn an_action_without_a_wait_prints_the_filed_request() {
    let controller = Controller::start(vec![(
        "POST /api/v1/services/",
        201,
        request("coolify.application.restart", "executing", Some("op-1")),
    )]);
    let (text, exit) = run(
        &controller,
        &[
            "services", "restart", SERVICE, "--reason", "why", "--output", "json",
        ],
    )
    .unwrap();
    assert_eq!(exit, 0);
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["state"], "executing");
    let seen = controller.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].line,
        "POST /api/v1/services/coolify%3Aacc1%3Aappweb0001/actions/restart HTTP/1.1"
    );
    let body: Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(body["reason"], "why");
}

#[test]
fn waiting_reports_the_outcome_and_the_observed_status() {
    let result = json!({
        "outcome": "restarted", "verb": "restart", "resourceKind": "application",
        "uuid": "appweb0001", "previousStatus": "running:healthy",
        "observedStatus": "running:healthy", "settled": true, "deploymentUuid": "dep1"
    })
    .to_string();
    let controller = Controller::start(vec![
        (
            "POST /api/v1/services/",
            201,
            request("coolify.application.restart", "executing", Some("op-1")),
        ),
        (
            "GET /api/v1/requests/req-1",
            200,
            request("coolify.application.restart", "succeeded", Some("op-1")),
        ),
        (
            "GET /api/v1/operations/op-1",
            200,
            json!({"data": {"id": "op-1", "state": "succeeded", "resultJson": result}}).to_string(),
        ),
    ]);
    let (text, exit) = run(
        &controller,
        &[
            "services",
            "restart",
            SERVICE,
            "--wait-approval=5s",
            "--output",
            "json",
        ],
    )
    .unwrap();
    assert_eq!(exit, 0);
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["outcome"], "executed");
    assert_eq!(answer["result"]["outcome"], "restarted");
    assert_eq!(answer["result"]["observedStatus"], "running:healthy");

    let controller = Controller::start(vec![
        (
            "POST /api/v1/services/",
            201,
            request("coolify.application.restart", "executing", Some("op-1")),
        ),
        (
            "GET /api/v1/requests/req-1",
            200,
            request("coolify.application.restart", "succeeded", Some("op-1")),
        ),
        (
            "GET /api/v1/operations/op-1",
            200,
            json!({"data": {"id": "op-1", "state": "succeeded", "resultJson": result}}).to_string(),
        ),
    ]);
    let (text, _) = run(
        &controller,
        &[
            "services",
            "restart",
            SERVICE,
            "--wait-approval=5s",
            "--output",
            "text",
        ],
    )
    .unwrap();
    assert!(text.contains("outcome: executed"), "{text}");
    assert!(
        text.contains("restarted (running:healthy -> running:healthy)"),
        "{text}"
    );
    assert!(text.contains("dep1"), "{text}");
}

#[test]
fn a_stop_still_pending_exits_two() {
    let controller = Controller::start(vec![
        (
            "POST /api/v1/services/",
            201,
            request("coolify.application.stop", "pending", None),
        ),
        (
            "GET /api/v1/requests/req-1",
            200,
            request("coolify.application.stop", "pending", None),
        ),
    ]);
    let (text, exit) = run(
        &controller,
        &[
            "services",
            "stop",
            SERVICE,
            "--wait-approval=1s",
            "--output",
            "json",
        ],
    )
    .unwrap();
    assert_eq!(exit, 2, "{text}");
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["outcome"], "still_pending");
}

#[test]
fn logs_print_the_lines_and_say_what_was_cut() {
    let body = json!({"data": {
        "deploymentUuid": "dep1", "deploymentStatus": "finished",
        "lines": ["building", "done\u{1b}[0m"], "truncated": true, "redacted": true
    }})
    .to_string();
    let controller = Controller::start(vec![("GET /api/v1/services/", 200, body)]);
    let (text, exit) = run(
        &controller,
        &[
            "services", "logs", SERVICE, "--lines", "20", "--output", "text",
        ],
    )
    .unwrap();
    assert_eq!(exit, 0);
    assert!(text.contains("building"), "{text}");
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(text.contains("earlier lines were cut"), "{text}");
    assert!(text.contains("credentials were redacted"), "{text}");
    let seen = controller.seen();
    assert_eq!(
        seen[0].line,
        "GET /api/v1/services/coolify%3Aacc1%3Aappweb0001/logs?lines=20 HTTP/1.1"
    );
}

#[test]
fn an_unreadable_result_is_reported_as_a_warning_not_hidden() {
    // The request executed, but the operation (and so its result) cannot be
    // read: the answer keeps the outcome and says why there is no result.
    let controller = Controller::start(vec![
        (
            "POST /api/v1/services/",
            201,
            request("coolify.application.restart", "executing", Some("op-1")),
        ),
        (
            "GET /api/v1/requests/req-1",
            200,
            request("coolify.application.restart", "succeeded", Some("op-1")),
        ),
        (
            "GET /api/v1/operations/op-1",
            500,
            json!({"error": {"code": "internal", "message": "boom"}}).to_string(),
        ),
    ]);
    let (text, exit) = run(
        &controller,
        &[
            "services",
            "restart",
            SERVICE,
            "--wait-approval=5s",
            "--output",
            "json",
        ],
    )
    .unwrap();
    assert_eq!(exit, 0, "the request did execute");
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["outcome"], "executed");
    assert!(answer.get("result").is_none());
    assert!(
        answer["resultWarning"]
            .as_str()
            .unwrap()
            .contains("could not be read"),
        "{answer}"
    );
}
