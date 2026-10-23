//! `fleetctl proxmox console` (FM-495): parsing, the controller route and
//! body, and the absolute URL in the JSON answer.

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(ToString::to_string).collect()
}

fn session() -> Value {
    json!({
        "sessionId": "console-0123456789abcdef",
        "token": "TOKEN-VALUE-0123456789",
        "expiresAt": 1,
        "accountId": "acc-1",
        "node": "pve-a",
        "vmid": 101,
        "socketPath": "/api/v1/proxmox/console/socket",
        "subprotocols": ["binary", "fleet-console-token.TOKEN-VALUE-0123456789"],
        "consolePath": "/proxmox/console#session=TOKEN-VALUE-0123456789",
        "idleTimeoutSeconds": 600,
        "maxDurationSeconds": 3600
    })
}

/// One canned controller answer; returns the request line and body it saw.
fn fake_controller(status: u16, body: String) -> (String, thread::JoinHandle<(String, String)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        listener.set_nonblocking(true).unwrap();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "no request reached the controller"
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
        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut length = 0_usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap();
            }
        }
        let mut request_body = vec![0_u8; length];
        reader.read_exact(&mut request_body).unwrap();
        write!(
            stream,
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
        let _ = stream.read(&mut [0_u8; 1]);
        (request_line, String::from_utf8(request_body).unwrap())
    });
    (format!("http://{address}"), handle)
}

#[test]
fn parsing_accepts_the_documented_form_and_refuses_the_rest() {
    let invocation = fleetctl::parse(&args(&[
        "proxmox",
        "console",
        "--account",
        "acc-1",
        "--node",
        "pve-a",
        "--vmid",
        "101",
        "--output",
        "json",
    ]))
    .unwrap();
    assert_eq!(
        invocation.command,
        fleetctl::Command::ProxmoxConsole {
            account_id: "acc-1".to_owned(),
            node: "pve-a".to_owned(),
            vmid: 101
        }
    );
    assert_eq!(invocation.output, fleetctl::Output::Json);
    for words in [
        vec!["proxmox", "console"],
        vec!["proxmox", "console", "--account", "a", "--node", "n"],
        vec![
            "proxmox",
            "console",
            "--account",
            "a",
            "--node",
            "n",
            "--vmid",
            "x",
        ],
        vec!["proxmox", "console", "acc-1", "pve-a", "101"],
    ] {
        assert!(fleetctl::parse(&args(&words)).is_err(), "{words:?}");
    }
}

#[test]
fn json_output_has_an_absolute_url_and_no_bare_token() {
    let (url, server) = fake_controller(201, json!({"data": session()}).to_string());
    let invocation = fleetctl::parse(&args(&[
        "--url",
        &url,
        "--output",
        "json",
        "proxmox",
        "console",
        "--account",
        "acc-1",
        "--node",
        "pve-a",
        "--vmid",
        "101",
    ]))
    .unwrap();

    let output = fleetctl::run(&invocation).unwrap();

    let (request_line, request_body) = server.join().unwrap();
    assert!(
        request_line.starts_with("POST /api/v1/proxmox/accounts/acc-1/console-sessions "),
        "{request_line}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&request_body).unwrap(),
        json!({"node": "pve-a", "vmid": 101})
    );
    let parsed: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(
        parsed["consoleUrl"],
        format!("{url}/proxmox/console#session=TOKEN-VALUE-0123456789")
    );
    assert_eq!(parsed["vmid"], 101);
    assert_eq!(parsed["node"], "pve-a");
    assert!(parsed.get("token").is_none());
    assert!(parsed.get("subprotocols").is_none());
    // The token appears exactly once: inside the URL fragment.
    assert_eq!(output.matches("TOKEN-VALUE-0123456789").count(), 1);
}

#[test]
fn a_refusal_is_reported_not_turned_into_a_url() {
    let (url, server) = fake_controller(
        502,
        json!({
            "code": "proxmox_source",
            "message": "the token lacks the privilege (403): the account's API token lacks VM.Console on /vms/101; grant it",
            "correlationId": "c1",
            "retry": {"class": "backoff"}
        })
        .to_string(),
    );
    let invocation = fleetctl::parse(&args(&[
        "--url",
        &url,
        "proxmox",
        "console",
        "--account",
        "acc-1",
        "--node",
        "pve-a",
        "--vmid",
        "101",
    ]))
    .unwrap();
    let error = fleetctl::run(&invocation).unwrap_err();
    server.join().unwrap();
    assert!(error.message.contains("VM.Console"), "{}", error.message);
}
