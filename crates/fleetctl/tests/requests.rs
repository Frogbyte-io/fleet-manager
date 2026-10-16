//! `fleetctl requests` (FM-1041): the parsed grammar, the controller
//! requests it sends, the bounded wait and its JSON outcomes (including
//! timeouts), and the human renderer.

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fleetctl::requests::{Outcome, RequestsAction, parse_duration, parse_wait_approval};
use serde_json::{Value, json};

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(ToString::to_string).collect()
}

/// One request line and body the scripted controller saw.
#[derive(Clone, Debug)]
struct Seen {
    line: String,
    body: String,
}

/// A scripted controller: answers each request with the next `(status,
/// body)` and repeats the last one when the script runs out. It stops when
/// the guard is dropped.
struct Controller {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Controller {
    fn start(script: Vec<(u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen_in, stop_in) = (seen.clone(), stop.clone());
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut served = 0_usize;
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
                seen_in.lock().unwrap().push(Seen {
                    line: line.trim_end().to_owned(),
                    body: String::from_utf8(body).unwrap(),
                });
                let (status, answer) = &script[served.min(script.len() - 1)];
                served += 1;
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

fn request_body(state: &str) -> (u16, String) {
    (
        200,
        json!({ "data": {
            "id": "req-1",
            "requester": "agent-7",
            "origin": "api",
            "actionId": "coolify.application.redeploy",
            "target": "app-1",
            "parameters": {},
            "riskClass": "approve",
            "reason": "ship the fix",
            "state": state,
            "terminal": !matches!(state, "pending" | "approved" | "executing"),
            "decidedBy": null,
            "decidedAt": null,
            "decisionNote": null,
            "operationId": null,
            "failure": null,
            "createdAt": 1,
            "expiresAt": 2,
            "updatedAt": 3,
        } })
        .to_string(),
    )
}

fn run_json(controller: &Controller, words: &[&str]) -> (Value, u8) {
    let mut all = vec!["--url", &controller.url];
    all.extend_from_slice(words);
    all.extend_from_slice(&["--output", "json"]);
    let invocation = fleetctl::parse(&args(&all)).unwrap();
    let (text, exit) = fleetctl::run_with_exit(&invocation).unwrap();
    (serde_json::from_str(&text).unwrap(), exit)
}

#[test]
fn parsing_walks_the_requests_forms() {
    let parse = |words: &[&str]| fleetctl::parse(&args(words)).unwrap().command;
    assert_eq!(
        parse(&["requests", "list"]),
        fleetctl::Command::Requests(RequestsAction::List {
            state: None,
            limit: None
        })
    );
    assert_eq!(
        parse(&["requests", "list", "--state", "pending", "--limit", "5"]),
        fleetctl::Command::Requests(RequestsAction::List {
            state: Some("pending".to_owned()),
            limit: Some(5)
        })
    );
    assert_eq!(
        parse(&["requests", "get", "req-1"]),
        fleetctl::Command::Requests(RequestsAction::Get {
            id: "req-1".to_owned(),
            wait: None
        })
    );
    assert_eq!(
        parse(&["requests", "get", "req-1", "--wait"]),
        fleetctl::Command::Requests(RequestsAction::Get {
            id: "req-1".to_owned(),
            wait: Some(Duration::from_secs(300))
        })
    );
    assert_eq!(
        parse(&["requests", "get", "req-1", "--wait=90s"]),
        fleetctl::Command::Requests(RequestsAction::Get {
            id: "req-1".to_owned(),
            wait: Some(Duration::from_secs(90))
        })
    );
    assert_eq!(
        parse(&["requests", "approve", "req-1"]),
        fleetctl::Command::Requests(RequestsAction::Approve {
            id: "req-1".to_owned()
        })
    );
    assert_eq!(
        parse(&["requests", "deny", "req-1", "--note", "not now"]),
        fleetctl::Command::Requests(RequestsAction::Deny {
            id: "req-1".to_owned(),
            note: Some("not now".to_owned())
        })
    );
    // The note is trimmed, and a blank one is no note.
    assert_eq!(
        parse(&["requests", "deny", "req-1", "--note", "  not now \t"]),
        fleetctl::Command::Requests(RequestsAction::Deny {
            id: "req-1".to_owned(),
            note: Some("not now".to_owned())
        })
    );
    assert_eq!(
        parse(&["requests", "deny", "req-1", "--note", "   "]),
        fleetctl::Command::Requests(RequestsAction::Deny {
            id: "req-1".to_owned(),
            note: None
        })
    );
}

#[test]
fn parsing_refuses_the_undocumented_requests_forms() {
    for words in [
        vec!["requests"],
        vec!["requests", "frobnicate"],
        vec!["requests", "get"],
        vec!["requests", "get", ""],
        vec!["requests", "get", "-x"],
        vec!["requests", "approve", "--wait"],
        // A wait belongs to `get` only, and a note to `deny` only.
        vec!["requests", "approve", "req-1", "--wait"],
        vec!["requests", "list", "--wait"],
        vec!["requests", "approve", "req-1", "--note", "x"],
        vec!["requests", "deny", "req-1", "--note"],
        vec!["requests", "deny", "req-1", "--note", "--output", "json"],
        vec!["requests", "list", "--limit", "many"],
        vec!["requests", "list", "--state"],
        vec!["requests", "get", "req-1", "--output", "yaml"],
        // Out-of-bounds or malformed waits.
        vec!["requests", "get", "req-1", "--wait=0"],
        vec!["requests", "get", "req-1", "--wait=0s"],
        vec!["requests", "get", "req-1", "--wait=61m"],
        vec!["requests", "get", "req-1", "--wait=2h"],
        vec!["requests", "get", "req-1", "--wait="],
        vec!["requests", "get", "req-1", "--wait=soon"],
        vec!["requests", "get", "req-1", "--wait=-5"],
        vec!["requests", "get", "req-1", "--wait=1.5m"],
        vec!["requests", "get", "req-1", "--wait=99999999999999999999h"],
    ] {
        assert!(fleetctl::parse(&args(&words)).is_err(), "{words:?}");
    }
}

#[test]
fn durations_are_bounded_and_bare_flags_use_the_default() {
    assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
    assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    assert!(parse_duration("3601").is_err());
    assert!(parse_duration("0").is_err());
    // The reusable flag parser for provider action commands.
    assert_eq!(
        parse_wait_approval("--wait-approval", "--wait-approval").unwrap(),
        Some(Duration::from_secs(300))
    );
    assert_eq!(
        parse_wait_approval("--wait-approval", "--wait-approval=2m").unwrap(),
        Some(Duration::from_secs(120))
    );
    assert_eq!(
        parse_wait_approval("--wait-approval", "--wait").unwrap(),
        None
    );
    assert_eq!(
        parse_wait_approval("--wait-approval", "--wait-approvals").unwrap(),
        None
    );
    assert!(parse_wait_approval("--wait-approval", "--wait-approval=2h").is_err());
}

#[test]
fn list_sends_the_filters() {
    let controller = Controller::start(vec![(
        200,
        json!({ "items": [], "page": { "nextCursor": null, "limit": 5 } }).to_string(),
    )]);
    let (body, exit) = run_json(
        &controller,
        &["requests", "list", "--state", "pending", "--limit", "5"],
    );
    assert_eq!(exit, 0);
    assert_eq!(body["items"], json!([]));
    assert_eq!(
        controller.seen()[0].line,
        "GET /api/v1/requests?state=pending&limit=5 HTTP/1.1"
    );
}

#[test]
fn get_prints_the_request_without_waiting() {
    let controller = Controller::start(vec![request_body("pending")]);
    let (body, exit) = run_json(&controller, &["requests", "get", "req-1"]);
    assert_eq!(exit, 0);
    assert_eq!(body["state"], "pending");
    assert_eq!(controller.seen().len(), 1);
    assert_eq!(
        controller.seen()[0].line,
        "GET /api/v1/requests/req-1 HTTP/1.1"
    );
}

#[test]
fn approve_and_deny_post_their_decisions() {
    let controller = Controller::start(vec![request_body("executing")]);
    let (body, _) = run_json(&controller, &["requests", "approve", "req-1"]);
    assert_eq!(body["state"], "executing");
    let controller = Controller::start(vec![request_body("denied")]);
    let (body, _) = run_json(
        &controller,
        &["requests", "deny", "req-1", "--note", "not now"],
    );
    assert_eq!(body["state"], "denied");
    let seen = controller.seen();
    assert_eq!(seen[0].line, "POST /api/v1/requests/req-1/deny HTTP/1.1");
    assert_eq!(
        serde_json::from_str::<Value>(&seen[0].body).unwrap(),
        json!({ "note": "not now" })
    );
}

#[test]
fn a_refusal_is_an_error_naming_the_code() {
    let controller = Controller::start(vec![(
        409,
        json!({ "code": "conflict", "message": "another decision was made first" }).to_string(),
    )]);
    let invocation = fleetctl::parse(&args(&[
        "--url",
        &controller.url,
        "requests",
        "approve",
        "req-1",
    ]))
    .unwrap();
    let error = fleetctl::run_with_exit(&invocation).unwrap_err();
    assert!(error.message.contains("409, conflict"), "{}", error.message);
}

#[test]
fn a_wait_reports_each_outcome_as_json_with_its_exit_code() {
    for (state, outcome, exit) in [
        ("succeeded", "executed", 0),
        ("denied", "denied", 1),
        ("expired", "expired", 1),
        ("failed", "failed", 1),
    ] {
        // Pending when first read, then it settles while the wait polls.
        let controller = Controller::start(vec![
            request_body("pending"),
            request_body("pending"),
            request_body(state),
        ]);
        let (body, code) = run_json(&controller, &["requests", "get", "req-1", "--wait=30s"]);
        assert_eq!(body["outcome"], outcome, "{state}");
        assert_eq!(body["request"]["state"], state);
        assert_eq!(code, exit, "{state}");
    }
}

#[test]
fn a_wait_follows_an_approved_request_through_execution() {
    let controller = Controller::start(vec![
        request_body("pending"),
        request_body("approved"),
        request_body("executing"),
        request_body("succeeded"),
    ]);
    let (body, code) = run_json(&controller, &["requests", "get", "req-1", "--wait=30s"]);
    assert_eq!(body["outcome"], "executed");
    assert_eq!(code, 0);
}

#[test]
fn a_wait_that_times_out_answers_still_pending_and_exits_2() {
    let controller = Controller::start(vec![request_body("pending")]);
    let started = Instant::now();
    let (body, code) = run_json(&controller, &["requests", "get", "req-1", "--wait=1s"]);
    let waited = started.elapsed();
    assert_eq!(body["outcome"], "still_pending");
    assert_eq!(body["request"]["state"], "pending");
    assert_eq!(code, 2);
    // Bounded: it neither returns early nor hangs.
    assert!(waited >= Duration::from_millis(900), "{waited:?}");
    assert!(waited < Duration::from_secs(8), "{waited:?}");
    assert!(controller.seen().len() >= 3, "{:?}", controller.seen());
}

#[test]
fn an_approved_request_still_running_at_the_bound_is_still_pending() {
    let controller = Controller::start(vec![request_body("executing")]);
    let (body, code) = run_json(&controller, &["requests", "get", "req-1", "--wait=1s"]);
    assert_eq!(body["outcome"], "still_pending");
    assert_eq!(code, 2);
}

#[test]
fn a_refused_read_during_the_wait_is_an_error_not_an_outcome() {
    let controller = Controller::start(vec![
        request_body("pending"),
        (
            403,
            json!({ "code": "denied", "message": "no" }).to_string(),
        ),
    ]);
    let invocation = fleetctl::parse(&args(&[
        "--url",
        &controller.url,
        "requests",
        "get",
        "req-1",
        "--wait=30s",
    ]))
    .unwrap();
    let error = fleetctl::run_with_exit(&invocation).unwrap_err();
    assert!(error.message.contains("403"), "{}", error.message);
}

#[test]
fn the_poll_backs_off_and_never_sleeps_past_the_bound() {
    let mut pauses = Vec::new();
    let mut reads = 0;
    let (outcome, _) = fleetctl::requests::poll_outcome(
        |_| {
            reads += 1;
            Ok(json!({ "state": "pending" }))
        },
        Duration::from_secs(20),
        |pause| pauses.push(pause),
    )
    .unwrap();
    assert_eq!(outcome, Outcome::StillPending);
    let millis: Vec<u128> = pauses.iter().map(Duration::as_millis).collect();
    assert_eq!(
        millis,
        [250, 500, 1000, 2000, 4000, 5000, 5000, 2250],
        "backoff doubles to 5s and the last pause is clamped to what remains"
    );
    assert_eq!(reads, pauses.len() + 1);
}

#[test]
fn the_poll_returns_at_once_for_a_settled_request() {
    let (outcome, request) = fleetctl::requests::poll_outcome(
        |_| Ok(json!({ "state": "succeeded" })),
        Duration::from_secs(5),
        |_| panic!("a settled request is not waited on"),
    )
    .unwrap();
    assert_eq!(outcome, Outcome::Executed);
    assert_eq!(request["state"], "succeeded");
}

#[test]
fn outcomes_have_stable_names_and_exit_codes() {
    assert_eq!(Outcome::Executed.id(), "executed");
    assert_eq!(Outcome::Denied.id(), "denied");
    assert_eq!(Outcome::Expired.id(), "expired");
    assert_eq!(Outcome::Failed.id(), "failed");
    assert_eq!(Outcome::StillPending.id(), "still_pending");
    for state in ["pending", "approved", "executing", "unknown"] {
        assert_eq!(Outcome::of_state(state), None, "{state}");
    }
}

#[test]
fn text_output_renders_rows_and_details_without_control_characters() {
    let list = json!({ "items": [{
        "id": "req-1", "state": "pending", "riskClass": "approve",
        "actionId": "coolify.application.redeploy", "target": "app\u{1b}[31m-1",
        "requester": "agent-7", "reason": "r"
    }], "page": { "nextCursor": null, "limit": 50 } });
    let text = fleetctl::render_requests_for_test(&list);
    assert!(text.contains("REQUESTER"), "{text}");
    assert!(text.contains("req-1"), "{text}");
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert_eq!(
        fleetctl::render_requests_for_test(&json!({ "items": [] })),
        "(no requests)"
    );
    let waited = fleetctl::requests::outcome_body(
        Outcome::Denied,
        &json!({
            "id": "req-1", "state": "denied", "riskClass": "approve",
            "actionId": "a", "target": "t", "requester": "r", "reason": "why",
            "decidedBy": "anonymous-lan-admin", "decisionNote": "not now"
        }),
    );
    let text = fleetctl::render_requests_for_test(&waited);
    assert!(text.starts_with("outcome: denied"), "{text}");
    assert!(text.contains("note: not now"), "{text}");
}

fn transient() -> fleetctl::requests::ReadFailure {
    fleetctl::requests::ReadFailure {
        error: fleetctl::CliError {
            message: "the controller did not answer".to_owned(),
        },
        transient: true,
    }
}

#[test]
fn the_poll_retries_three_transient_failures_and_resets_the_count() {
    let mut script = vec![
        Err(transient()),
        Err(transient()),
        Err(transient()),
        Ok(json!({ "state": "pending" })),
        Err(transient()),
        Err(transient()),
        Err(transient()),
        Ok(json!({ "state": "succeeded" })),
    ]
    .into_iter();
    let (outcome, _) = fleetctl::requests::poll_outcome(
        |_| script.next().unwrap(),
        Duration::from_secs(60),
        |_| {},
    )
    .unwrap();
    assert_eq!(outcome, Outcome::Executed);
}

#[test]
fn the_poll_gives_up_on_the_fourth_consecutive_transient_failure() {
    let mut reads = 0;
    let error = fleetctl::requests::poll_outcome(
        |_| {
            reads += 1;
            Err(transient())
        },
        Duration::from_secs(60),
        |_| {},
    )
    .unwrap_err();
    assert_eq!(reads, 4);
    assert!(
        error.message.contains("did not answer"),
        "{}",
        error.message
    );
}

#[test]
fn the_poll_does_not_retry_a_refusal_and_hands_each_read_the_time_left() {
    let mut reads = 0;
    let error = fleetctl::requests::poll_outcome(
        |_| {
            reads += 1;
            Err(fleetctl::requests::ReadFailure {
                error: fleetctl::CliError {
                    message: "refused (403)".to_owned(),
                },
                transient: false,
            })
        },
        Duration::from_secs(60),
        |_| {},
    )
    .unwrap_err();
    assert_eq!(reads, 1);
    assert!(error.message.contains("403"));

    let mut left = Vec::new();
    let _ = fleetctl::requests::poll_outcome(
        |remaining| {
            left.push(remaining);
            Ok(json!({ "state": "pending" }))
        },
        Duration::from_secs(2),
        |_| {},
    )
    .unwrap();
    assert!(
        left[0] <= Duration::from_secs(2) && left[0] > Duration::from_millis(1900),
        "{left:?}"
    );
    assert!(left.windows(2).all(|pair| pair[1] < pair[0]), "{left:?}");
}

#[test]
fn a_server_error_during_the_wait_is_retried_over_http() {
    let controller = Controller::start(vec![
        request_body("pending"),
        (
            503,
            r#"{"code":"unavailable","message":"restarting"}"#.to_owned(),
        ),
        request_body("succeeded"),
    ]);
    let (answer, code) = run_json(&controller, &["requests", "get", "req-1", "--wait=30s"]);
    assert_eq!(code, 0);
    assert_eq!(answer["outcome"], "executed");
}
