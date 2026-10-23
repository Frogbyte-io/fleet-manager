//! `fleetctl machines create --request` (#496): a caller that may ask but not
//! provision files an action request through the dedicated endpoint, never
//! the review or the direct create, and can wait for the approval and the
//! operation's result through the shared request waiter.

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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
        "id": "req-1", "requester": "credential:ci:c1", "origin": "api",
        "actionId": "proxmox.machine.create", "target": "machine:acct-1:build-box",
        "parameters": {"accountId": "acct-1", "imageVersionId": "ver-1", "name": "build-box"},
        "riskClass": "approve",
        "reason": "nightly build host", "state": state,
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

const CREATE: [&str; 9] = [
    "machines",
    "create",
    "--account",
    "acct-1",
    "--image-version",
    "ver-1",
    "--name",
    "build-box",
    "--request",
];

fn words(extra: &[&'static str]) -> Vec<&'static str> {
    let mut words: Vec<&'static str> = CREATE.to_vec();
    words.extend_from_slice(extra);
    words
}

#[test]
fn a_request_files_one_action_request_and_nothing_else() {
    let controller = Controller::start(vec![(
        "POST /api/v1/machines/create/request",
        201,
        request("pending", None),
    )]);
    let (text, exit) = run(
        &controller,
        &words(&[
            "--purpose",
            "nightly build host",
            "--cores",
            "2",
            "--idempotency-key",
            "k-1",
            "--output",
            "json",
        ]),
    )
    .unwrap();
    assert_eq!(exit, 0);
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["state"], "pending");
    assert_eq!(answer["id"], "req-1");
    assert_eq!(answer["actionId"], "proxmox.machine.create");
    let seen = controller.seen();
    assert_eq!(seen.len(), 1, "no review and no direct create: {seen:?}");
    assert_eq!(
        seen[0].line,
        "POST /api/v1/machines/create/request HTTP/1.1"
    );
    let body: Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(body["purpose"], "nightly build host");
    assert_eq!(body["idempotencyKey"], "k-1");
    assert_eq!(body["spec"]["accountId"], "acct-1");
    assert_eq!(body["spec"]["name"], "build-box");
    assert_eq!(body["spec"]["cores"], 2);
}

#[test]
fn waiting_prints_the_outcome_and_the_machine_the_operation_made() {
    let result = json!({
        "machineId": "m-1", "vmid": 7100, "state": "ready", "requestId": "req-1",
    })
    .to_string();
    let controller = Controller::start(vec![
        (
            "POST /api/v1/machines/create/request",
            201,
            request("pending", None),
        ),
        (
            "GET /api/v1/requests/req-1",
            200,
            request("succeeded", Some("op-1")),
        ),
        (
            "GET /api/v1/operations/op-1",
            200,
            json!({"data": {"id": "op-1", "state": "succeeded", "resultJson": result}}).to_string(),
        ),
    ]);
    let (text, exit) = run(
        &controller,
        &words(&["--purpose", "ci", "--wait-approval=5s", "--output", "json"]),
    )
    .unwrap();
    assert_eq!(exit, 0);
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["outcome"], "executed");
    assert_eq!(answer["request"]["id"], "req-1");
    assert_eq!(answer["result"]["machineId"], "m-1");
    assert_eq!(answer["result"]["requestId"], "req-1");
}

#[test]
fn a_denied_request_exits_one_and_names_the_outcome() {
    let controller = Controller::start(vec![
        (
            "POST /api/v1/machines/create/request",
            201,
            request("pending", None),
        ),
        ("GET /api/v1/requests/req-1", 200, request("denied", None)),
    ]);
    let (text, exit) = run(
        &controller,
        &words(&["--purpose", "ci", "--wait-approval=5s", "--output", "json"]),
    )
    .unwrap();
    assert_eq!(exit, 1);
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["outcome"], "denied");
}

#[test]
fn the_request_flags_are_checked_before_anything_is_sent() {
    let base = [
        "machines",
        "create",
        "--account",
        "a",
        "--image-version",
        "v",
        "--name",
        "n",
    ];
    let with = |extra: &[&str]| {
        let mut all = base.to_vec();
        all.extend_from_slice(extra);
        fleetctl::parse(&args(&all))
    };
    // A request needs a purpose.
    assert!(with(&["--request"]).is_err());
    assert!(with(&["--request", "--purpose", "x"]).is_ok());
    // A purpose or a wait without --request is a mistake, not a silent no-op.
    assert!(with(&["--purpose", "x"]).is_err());
    assert!(with(&["--wait-approval"]).is_err());
    // --request files a request: not a review, not a no-wait.
    for flag in ["--review-only", "--no-wait"] {
        assert!(
            with(&["--request", "--purpose", "x", flag]).is_err(),
            "{flag}"
        );
    }
}
