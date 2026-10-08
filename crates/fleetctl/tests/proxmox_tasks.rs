//! `fleetctl proxmox tasks` (FM-609): the parsed grammar, the controller
//! request it sends, the JSON output pinned in a snapshot, and the human
//! renderer.

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

const SNAPSHOT: &str = include_str!("snapshots/proxmox_tasks.json");

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(ToString::to_string).collect()
}

/// A one-shot controller: answers one request with `body` and returns the
/// request head it saw.
fn controller(body: &'static str) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        // Bounded, so a client that never connects fails the test instead
        // of leaving this thread blocked until the process exits.
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
        let mut head = String::new();
        let mut content_length = 0_usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = value.trim().parse().unwrap();
            }
            if line == "\r\n" || line.is_empty() {
                break;
            }
            head.push_str(&line);
        }
        let mut request_body = vec![0; content_length];
        reader.read_exact(&mut request_body).unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
        head
    });
    (format!("http://{address}"), handle)
}

#[test]
fn parsing_walks_the_task_history_forms() {
    let invocation = fleetctl::parse(&args(&["proxmox", "tasks", "acc-1"])).unwrap();
    assert_eq!(invocation.output, fleetctl::Output::Text);
    assert_eq!(
        invocation.command,
        fleetctl::Command::ProxmoxTasks {
            account_id: "acc-1".to_owned(),
            node: None,
            vmid: None,
            status: None,
            cursor: None,
            limit: None,
        }
    );

    let invocation = fleetctl::parse(&args(&[
        "proxmox", "tasks", "acc-1", "--node", "pve", "--vmid", "101", "--status", "error",
        "--cursor", "UPID:x", "--limit", "5", "--output", "json",
    ]))
    .unwrap();
    assert_eq!(invocation.output, fleetctl::Output::Json);
    assert_eq!(
        invocation.command,
        fleetctl::Command::ProxmoxTasks {
            account_id: "acc-1".to_owned(),
            node: Some("pve".to_owned()),
            vmid: Some(101),
            status: Some("error".to_owned()),
            cursor: Some("UPID:x".to_owned()),
            limit: Some(5),
        }
    );
}

#[test]
fn parsing_refuses_the_undocumented_task_history_forms() {
    for words in [
        vec!["proxmox", "tasks"],
        vec!["proxmox", "tasks", "--node", "pve"],
        // The account guard: an empty ID or any leading `-` is not one.
        vec!["proxmox", "tasks", ""],
        vec!["proxmox", "tasks", "-x"],
        vec!["proxmox", "tasks", "-acc-1", "--node", "pve"],
        vec!["proxmox", "tasks", "acc-1", "--vmid", "abc"],
        vec!["proxmox", "tasks", "acc-1", "--limit"],
        // Another option is not a value.
        vec!["proxmox", "tasks", "acc-1", "--node", "--output", "json"],
        vec!["proxmox", "tasks", "acc-1", "--cursor", "--limit", "5"],
        vec!["proxmox", "tasks", "acc-1", "--output", "yaml"],
        vec!["proxmox", "tasks", "acc-1", "--since", "1"],
    ] {
        assert!(fleetctl::parse(&args(&words)).is_err(), "{words:?}");
    }
}

#[test]
fn json_output_matches_the_snapshot_and_the_request_carries_the_filters() {
    let (url, server) = controller(SNAPSHOT);
    let invocation = fleetctl::parse(&args(&[
        "--url", &url, "proxmox", "tasks", "acc-1", "--node", "pve", "--vmid", "101", "--status",
        "ok", "--limit", "2", "--output", "json",
    ]))
    .unwrap();

    let output = fleetctl::run(&invocation).unwrap();

    assert_eq!(output.trim_end(), SNAPSHOT.trim_end());
    let head = server.join().unwrap();
    let request_line = head.lines().next().unwrap();
    assert_eq!(
        request_line,
        "GET /api/v1/proxmox/accounts/acc-1/tasks?node=pve&vmid=101&status=ok&limit=2 HTTP/1.1"
    );
}

#[test]
fn text_output_renders_tasks_links_cursor_and_warnings() {
    let page: serde_json::Value = serde_json::from_str(SNAPSHOT).unwrap();

    let text = fleetctl::render_proxmox_tasks_for_test(&page);

    assert!(text.contains("PVE 9.2.2"), "{text}");
    assert!(text.contains("FLEET OPERATION"), "{text}");
    let fleet_row = text
        .lines()
        .find(|line| line.contains("qmstart"))
        .expect("the qmstart row");
    assert!(fleet_row.starts_with("ok"), "{fleet_row}");
    assert!(fleet_row.contains("root@pam!GLM-AGENT"), "{fleet_row}");
    assert!(fleet_row.ends_with("op-1"), "{fleet_row}");
    let backup_row = text
        .lines()
        .find(|line| line.contains("vzdump"))
        .expect("the vzdump row");
    assert!(backup_row.ends_with('-'), "{backup_row}");
    assert!(text.contains("  exit: WARNINGS: 1"), "{text}");
    assert!(
        text.contains(
            "next page: --cursor 'UPID:pve:00154000:0C6DE000:6AAFDE04:vzdump::root@pam:'"
        ),
        "{text}"
    );
    assert!(
        text.contains("warnings:\n  node pve2 tasks are unavailable"),
        "{text}"
    );

    let empty = serde_json::json!({
        "items": [],
        "page": {"limit": 50, "nextCursor": null},
        "pveVersion": "8.4.1",
        "warnings": []
    });
    let text = fleetctl::render_proxmox_tasks_for_test(&empty);
    assert!(text.contains("(no tasks reported)"), "{text}");
    assert!(!text.contains("next page"), "{text}");
}

#[test]
fn the_next_page_cursor_is_shell_quoted() {
    let page = serde_json::json!({
        "items": [],
        "page": { "nextCursor": "UPID:pve:1:2:3:qmstart:101:fleet@pve!it's:", "limit": 1 },
        "warnings": []
    });
    let text = fleetctl::render_proxmox_tasks_for_test(&page);
    assert!(
        text.contains(r"next page: --cursor 'UPID:pve:1:2:3:qmstart:101:fleet@pve!it'\''s:'"),
        "{text}"
    );
}
