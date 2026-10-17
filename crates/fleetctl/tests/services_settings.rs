//! `fleetctl services settings|env|domains|health` (FM-1034): the controller
//! requests, values read from a file and never from argv, the bounded wait
//! for approval, and that no output carries a value.

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const SERVICE: &str = "coolify:acc1:appweb0001";
const VALUE: &str = "Zq9-cli-test-value-0042";

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
        "id": "req-1", "requester": "agent-7", "origin": "api",
        "actionId": "coolify.env.update", "target": SERVICE,
        "parameters": {
            "accountId": "acc1", "resourceKind": "application", "uuid": "appweb0001",
            "name": "web", "redeploy": true,
            "preview": [{"key": "API_URL", "isPreview": false, "operation": "create",
                "changes": [{"field": "value", "from": null, "to": "(write-only, digest ab12cd34ef56)"}]}]
        },
        "riskClass": "approve", "reason": "test", "state": state,
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

#[test]
fn an_env_set_reads_the_value_from_a_file_and_files_one_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.env");
    std::fs::write(&path, format!("API_URL={VALUE}\n")).unwrap();
    let controller = Controller::start(vec![(
        "POST /api/v1/services/",
        201,
        request("pending", None),
    )]);
    let argv = [
        "services",
        "env",
        "set",
        SERVICE,
        "--file",
        path.to_str().unwrap(),
        "--literal",
        "--redeploy",
        "--reason",
        "rotate",
    ];
    assert!(
        argv.iter().all(|word| !word.contains(VALUE)),
        "the value is never an argument"
    );
    let (text, exit) = run(&controller, &argv).unwrap();
    assert_eq!(exit, 0);
    // The answer shows the request and its preview, never the value.
    assert!(text.contains("create API_URL"), "{text}");
    assert!(text.contains("then: redeploy"), "{text}");
    assert!(!text.contains(VALUE), "{text}");
    let seen = controller.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].line,
        "POST /api/v1/services/coolify%3Aacc1%3Aappweb0001/settings/env HTTP/1.1"
    );
    let body: Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(body["changes"][0]["key"], "API_URL");
    assert_eq!(body["changes"][0]["value"], VALUE);
    assert_eq!(body["changes"][0]["isLiteral"], true);
    assert_eq!(body["redeploy"], true);
    assert_eq!(body["reason"], "rotate");

    // JSON output is the controller's request, unchanged.
    let controller = Controller::start(vec![(
        "POST /api/v1/services/",
        201,
        request("pending", None),
    )]);
    let mut json_argv = argv.to_vec();
    json_argv.extend(["--output", "json"]);
    let (text, _) = run(&controller, &json_argv).unwrap();
    assert!(!text.contains(VALUE), "{text}");
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["state"], "pending");
}

#[test]
fn waiting_reports_the_outcome_with_the_changed_names_only() {
    let result = json!({
        "setting": "env", "outcome": "applied", "changed": ["set API_URL"],
        "verified": true, "followUp": {"verb": "redeploy", "deploymentUuid": "dep1"}
    })
    .to_string();
    let script = || {
        vec![
            ("POST /api/v1/services/", 201, request("pending", None)),
            (
                "GET /api/v1/requests/req-1",
                200,
                request("succeeded", Some("op-1")),
            ),
            (
                "GET /api/v1/operations/op-1",
                200,
                json!({"data": {"id": "op-1", "state": "succeeded", "resultJson": result}})
                    .to_string(),
            ),
        ]
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v");
    std::fs::write(&path, format!("{VALUE}\n")).unwrap();
    let words = [
        "services",
        "env",
        "set",
        SERVICE,
        "--file",
        path.to_str().unwrap(),
        "--key",
        "API_URL",
        "--wait-approval=5s",
    ];
    let controller = Controller::start(script());
    let (text, exit) = run(&controller, &words).unwrap();
    assert_eq!(exit, 0);
    assert!(text.contains("outcome: executed"), "{text}");
    assert!(text.contains("result: applied (verified)"), "{text}");
    assert!(text.contains("set API_URL"), "{text}");
    assert!(text.contains("redeploy queued (deployment dep1)"), "{text}");
    assert!(!text.contains(VALUE), "{text}");

    let controller = Controller::start(script());
    let mut json_words = words.to_vec();
    json_words.extend(["--output", "json"]);
    let (text, exit) = run(&controller, &json_words).unwrap();
    assert_eq!(exit, 0);
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["outcome"], "executed");
    assert_eq!(answer["result"]["changed"][0], "set API_URL");
    assert!(!text.contains(VALUE));
}

#[test]
fn a_request_still_pending_exits_two() {
    let controller = Controller::start(vec![
        ("POST /api/v1/services/", 201, request("pending", None)),
        ("GET /api/v1/requests/req-1", 200, request("pending", None)),
    ]);
    let started = Instant::now();
    let (text, exit) = run(
        &controller,
        &[
            "services",
            "domains",
            "set",
            SERVICE,
            "https://a.example.test",
            "--wait-approval=1s",
            "--output",
            "json",
        ],
    )
    .unwrap();
    assert_eq!(exit, 2, "{text}");
    assert!(started.elapsed() < Duration::from_secs(20));
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["outcome"], "still_pending");
    let seen = controller.seen();
    assert_eq!(
        seen[0].line,
        "POST /api/v1/services/coolify%3Aacc1%3Aappweb0001/settings/domains HTTP/1.1"
    );
    let body: Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(body["domains"], json!(["https://a.example.test"]));
}

#[test]
fn the_settings_view_prints_names_and_flags() {
    let view = json!({"data": {
        "serviceId": SERVICE, "name": "web", "resourceKind": "application",
        "env": [{"key": "DATABASE_URL", "isBuildtime": true, "isRuntime": true,
                 "isMultiline": false, "isLiteral": false, "isShownOnce": true,
                 "isPreview": false, "isShared": false}],
        "domains": ["https://shop.example.test"],
        "health": {"enabled": false, "path": "/", "port": null, "host": null,
                   "method": "GET", "scheme": "http", "returnCode": 200,
                   "interval": 5, "timeout": 5, "retries": 10, "startPeriod": 5},
        "notes": []
    }})
    .to_string();
    let controller = Controller::start(vec![("GET /api/v1/services/", 200, view.clone())]);
    let (text, exit) = run(&controller, &["services", "settings", SERVICE]).unwrap();
    assert_eq!(exit, 0);
    assert!(
        text.contains("DATABASE_URL") && text.contains("shown-once"),
        "{text}"
    );
    assert!(text.contains("https://shop.example.test"), "{text}");
    assert!(text.contains("disabled GET"), "{text}");
    assert_eq!(
        controller.seen()[0].line,
        "GET /api/v1/services/coolify%3Aacc1%3Aappweb0001/settings HTTP/1.1"
    );
    let controller = Controller::start(vec![("GET /api/v1/services/", 200, view)]);
    let (text, _) = run(
        &controller,
        &["services", "env", "list", SERVICE, "--output", "json"],
    )
    .unwrap();
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["env"][0]["key"], "DATABASE_URL");
}
