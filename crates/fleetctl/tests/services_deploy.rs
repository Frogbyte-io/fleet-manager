//! `fleetctl services templates|deploy` (FM-1035): the controller requests,
//! the optional DNS request, the wait with the operation result (also for a
//! partial failure), and the registry patch printed after a success.

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
        "id": "req-1", "requester": "agent-7", "origin": "api",
        "actionId": "coolify.site.deploy", "target": "site:acc1:app.example.test",
        "parameters": {"accountId": "acc1", "templateId": "node-app"},
        "riskClass": "approve",
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

const DEPLOY: [&str; 16] = [
    "services",
    "deploy",
    "--template",
    "node-app",
    "--account",
    "acc1",
    "--server",
    "edge-1",
    "--project",
    "sites",
    "--environment",
    "production",
    "--domain",
    "app.example.test",
    "--repo",
    "https://example.test/o/r",
];

fn deploy_words(extra: &[&'static str]) -> Vec<&'static str> {
    let mut words: Vec<&'static str> = DEPLOY.to_vec();
    words.extend(["--branch", "main"]);
    words.extend_from_slice(extra);
    words
}

#[test]
fn deploy_files_one_request_with_the_documented_body() {
    let controller = Controller::start(vec![(
        "POST /api/v1/site-deployments",
        201,
        request("pending", None),
    )]);
    let (text, exit) = run(
        &controller,
        &deploy_words(&["--reason", "launch", "--output", "json"]),
    )
    .unwrap();
    assert_eq!(exit, 0);
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["state"], "pending");
    let seen = controller.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].line, "POST /api/v1/site-deployments HTTP/1.1");
    let body: Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(body["templateId"], "node-app");
    assert_eq!(body["serverUuid"], "edge-1");
    assert_eq!(body["environmentName"], "production");
    assert_eq!(body["domain"], "app.example.test");
    assert_eq!(body["repository"], "https://example.test/o/r");
    assert_eq!(body["branch"], "main");
    assert_eq!(body["reason"], "launch");
}

#[test]
fn a_waited_deploy_prints_the_result_the_dns_request_and_the_registry_patch() {
    let result = json!({
        "outcome": "deployed", "resourceKind": "application", "uuid": "appnew1",
        "serviceId": "coolify:acc1:appnew1", "domain": "https://app.example.test",
        "steps": [{"step": "create", "status": "done"}, {"step": "start", "status": "done"}],
        "deploymentUuid": "dep1", "deploymentStatus": "finished", "followUpEnvKeys": []
    })
    .to_string();
    let controller = Controller::start(vec![
        (
            "POST /api/v1/site-deployments",
            201,
            request("pending", None),
        ),
        (
            "POST /api/v1/dns/changes",
            201,
            json!({"data": {"id": "dns-1", "target": "dns.record.upsert", "state": "pending"}})
                .to_string(),
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
        &deploy_words(&[
            "--dns",
            "--dns-target",
            "203.0.113.9",
            "--wait-approval=5s",
            "--output",
            "json",
        ]),
    )
    .unwrap();
    assert_eq!(exit, 0);
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["outcome"], "executed");
    assert_eq!(answer["result"]["uuid"], "appnew1");
    assert_eq!(answer["dnsRequest"]["id"], "dns-1");
    assert_eq!(
        answer["registryPatch"],
        json!([
            "fleetctl registry set domain/app.example.test --field fqdn=app.example.test",
            "fleetctl registry relate domain/app.example.test hosted-on coolify:appnew1"
        ])
    );
    let dns = controller
        .seen()
        .into_iter()
        .find(|seen| seen.line.starts_with("POST /api/v1/dns/changes"))
        .expect("the DNS request was filed");
    let body: Value = serde_json::from_str(&dns.body).unwrap();
    assert_eq!(body["name"], "app.example.test");
    assert_eq!(body["type"], "A");
    assert_eq!(body["content"], "203.0.113.9");
    assert_eq!(body["operation"], "upsert");

    // The text form shows the steps and the patch.
    let controller = Controller::start(vec![
        (
            "POST /api/v1/site-deployments",
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
    let (text, _) = run(
        &controller,
        &deploy_words(&["--wait-approval=5s", "--output", "text"]),
    )
    .unwrap();
    assert!(text.contains("deployed application appnew1"), "{text}");
    assert!(
        text.contains("fleetctl registry set domain/app.example.test"),
        "{text}"
    );
}

#[test]
fn a_failed_deploy_still_reports_what_was_created() {
    let partial = json!({
        "outcome": "partial", "resourceKind": "application", "uuid": "appnew2",
        "serviceId": "coolify:acc1:appnew2", "domain": "https://app.example.test",
        "steps": [{"step": "create", "status": "done"},
                  {"step": "start", "status": "failed", "detail": "queue unavailable"}],
        "error": "queue unavailable", "followUpEnvKeys": []
    })
    .to_string();
    let controller = Controller::start(vec![
        (
            "POST /api/v1/site-deployments",
            201,
            request("pending", None),
        ),
        (
            "GET /api/v1/requests/req-1",
            200,
            request("failed", Some("op-1")),
        ),
        (
            "GET /api/v1/operations/op-1",
            200,
            json!({"data": {"id": "op-1", "state": "failed", "resultJson": partial}}).to_string(),
        ),
    ]);
    let (text, exit) = run(
        &controller,
        &deploy_words(&["--wait-approval=5s", "--output", "json"]),
    )
    .unwrap();
    assert_eq!(exit, 1);
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["outcome"], "failed");
    assert_eq!(answer["result"]["uuid"], "appnew2");
    assert!(answer.get("registryPatch").is_none());
}

#[test]
fn a_dns_failure_does_not_undo_the_deploy_request() {
    let controller = Controller::start(vec![
        (
            "POST /api/v1/site-deployments",
            201,
            request("pending", None),
        ),
        (
            "POST /api/v1/dns/changes",
            404,
            json!({"error": {"code": "not_found", "message": "no Cloudflare zone holds app.example.test", "retry": "never"}}).to_string(),
        ),
    ]);
    let (text, exit) = run(
        &controller,
        &deploy_words(&[
            "--dns",
            "--dns-target",
            "lb.example.test",
            "--output",
            "json",
        ]),
    )
    .unwrap();
    assert_eq!(exit, 0);
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["id"], "req-1");
    assert!(answer["dnsRequest"]["error"].is_string(), "{answer}");
}

#[test]
fn templates_are_listed() {
    let controller = Controller::start(vec![(
        "GET /api/v1/site-templates",
        200,
        json!({"data": {"templates": [
            {"id": "ghost", "version": 1, "needsRepository": false,
             "source": {"kind": "service", "serviceType": "ghost"}}
        ]}})
        .to_string(),
    )]);
    let (text, exit) = run(&controller, &["services", "templates", "--output", "text"]).unwrap();
    assert_eq!(exit, 0);
    assert!(text.contains("ghost") && text.contains("service"), "{text}");
}
