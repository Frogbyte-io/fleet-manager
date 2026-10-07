//! #271: a stopped or timed-out build is interrupted like Ctrl-C (SIGINT to
//! the CLI's process group), so the Proxmox plugin's cleanup runs, and is
//! killed only when it outlives the grace period. A shell script stands in
//! for `packer`.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::time::{Duration, Instant};

use fleet_provider_packer::{PackerCommand, PackerTransport as _, ProcessTransport, Stopped};

/// Writes an executable fake CLI and answers its transport and directory.
fn fake(script: &str, grace: Duration) -> (tempfile::TempDir, ProcessTransport) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("packer");
    std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    (
        dir,
        ProcessTransport::with_binary(path).with_stop_grace(grace),
    )
}

fn command(dir: &tempfile::TempDir) -> PackerCommand {
    PackerCommand {
        args: vec!["build".to_owned()],
        work_dir: dir.path().to_path_buf(),
    }
}

/// Traps the interrupt, "cleans up", and exits like Packer after Ctrl-C.
const CLEANS_UP: &str =
    "trap 'echo cleaned up; exit 1' INT\necho started\nwhile :; do sleep 0.1; done";

#[tokio::test]
async fn a_stop_request_interrupts_and_lets_the_cleanup_finish() {
    let (dir, transport) = fake(CLEANS_UP, Duration::from_secs(10));
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let started = Instant::now();
    let run = tokio::spawn(async move {
        transport
            .run_stoppable(&command(&dir), Duration::from_secs(60), stop_rx)
            .await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop.send(true).unwrap();
    let result = run.await.unwrap().unwrap();
    assert_eq!(result.stopped, Some(Stopped::Interrupted));
    assert!(!result.outcome.killed_by_deadline);
    assert_eq!(result.outcome.exit_code, Some(1));
    assert!(result.outcome.stdout.contains("started"));
    assert!(
        result.outcome.stdout.contains("cleaned up"),
        "{:?}",
        result.outcome.stdout
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn the_deadline_interrupts_too_and_says_so() {
    let (dir, transport) = fake(CLEANS_UP, Duration::from_secs(10));
    let (_stop, stop_rx) = tokio::sync::watch::channel(false);
    let result = transport
        .run_stoppable(&command(&dir), Duration::from_millis(300), stop_rx)
        .await
        .unwrap();
    assert_eq!(result.stopped, Some(Stopped::Interrupted));
    assert!(result.outcome.killed_by_deadline);
    assert!(result.outcome.stdout.contains("cleaned up"));
}

#[tokio::test]
async fn a_cli_that_ignores_the_interrupt_is_killed_after_the_grace_period() {
    let (dir, transport) = fake(
        "trap '' INT\necho started\nwhile :; do sleep 0.1; done",
        Duration::from_millis(500),
    );
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let run = tokio::spawn(async move {
        transport
            .run_stoppable(&command(&dir), Duration::from_secs(60), stop_rx)
            .await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop.send(true).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .expect("the kill ends the run")
        .unwrap()
        .unwrap();
    assert_eq!(result.stopped, Some(Stopped::Killed));
    assert_eq!(result.outcome.exit_code, None);
}

#[tokio::test]
async fn an_unstopped_run_completes_normally() {
    let (dir, transport) = fake("echo done", Duration::from_secs(1));
    let (_stop, stop_rx) = tokio::sync::watch::channel(false);
    let result = transport
        .run_stoppable(&command(&dir), Duration::from_secs(10), stop_rx)
        .await
        .unwrap();
    assert_eq!(result.stopped, None);
    assert_eq!(result.outcome.exit_code, Some(0));
    assert!(result.outcome.stdout.contains("done"));
}
