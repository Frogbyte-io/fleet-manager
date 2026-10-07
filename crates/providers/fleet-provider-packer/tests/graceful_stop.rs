//! #271: a stopped or timed-out build is interrupted like Ctrl-C (SIGINT to
//! the CLI's process group), so the Proxmox plugin's cleanup runs, and is
//! killed only when it outlives the grace period. A shell script stands in
//! for `packer`; it writes `ready` only once its trap is installed, so no
//! signal races its startup.
#![cfg(unix)]

use std::time::{Duration, Instant};

use fleet_provider_packer::{
    PIPE_DRAIN, PackerCommand, PackerTransport as _, ProcessTransport, Stopped,
};

/// Writes the fake CLI's script and answers its directory and a transport
/// that runs it through `/bin/sh`. The script is never executed directly:
/// writing an executable while a parallel test forks can fail with
/// `ETXTBSY`.
fn fake(script: &str, grace: Duration) -> (tempfile::TempDir, ProcessTransport) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("packer.sh"), format!("{script}\n")).unwrap();
    (
        dir,
        ProcessTransport::with_binary("/bin/sh".into()).with_stop_grace(grace),
    )
}

fn command(dir: &std::path::Path) -> PackerCommand {
    PackerCommand {
        args: vec![dir.join("packer.sh").display().to_string()],
        work_dir: dir.to_path_buf(),
    }
}

/// Waits until the fake CLI has installed its trap.
async fn ready(dir: &std::path::Path) {
    let started = Instant::now();
    while !dir.join("ready").exists() {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the fake CLI never started"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Traps the interrupt, "cleans up", reports it as Packer does, and exits.
const CLEANS_UP: &str = r#"trap 'echo cleaned up; echo "1,,ui,say,Cleanly cancelled builds after being interrupted."; exit 1' INT
echo started
touch ready
while :; do sleep 0.1; done"#;

/// Runs the fake until `ready`, then requests a stop; answers the outcome.
async fn stop_after_ready(
    script: &str,
    grace: Duration,
) -> fleet_provider_packer::StoppableOutcome {
    let (dir, transport) = fake(script, grace);
    let path = dir.path().to_path_buf();
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let run = tokio::spawn(async move {
        transport
            .run_stoppable(&command(&path), Duration::from_secs(60), stop_rx)
            .await
    });
    ready(dir.path()).await;
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(30), run)
        .await
        .expect("the stop ends the run")
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn a_stop_request_interrupts_and_lets_the_cleanup_finish() {
    let started = Instant::now();
    let result = stop_after_ready(CLEANS_UP, Duration::from_secs(10)).await;
    assert_eq!(result.stopped, Some(Stopped::Interrupted));
    assert!(result.cleanly_cancelled);
    assert!(!result.outcome.killed_by_deadline);
    assert_eq!(result.outcome.exit_code, Some(1));
    assert!(result.outcome.stdout.contains("started"));
    assert!(result.outcome.stdout.contains("cleaned up"));
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn the_deadline_interrupts_too_and_says_so() {
    let (dir, transport) = fake(CLEANS_UP, Duration::from_secs(10));
    let (_stop, stop_rx) = tokio::sync::watch::channel(false);
    // Generous, so the fake installs its trap long before the deadline even
    // on a loaded machine; the run still ends at the deadline.
    let result = transport
        .run_stoppable(&command(dir.path()), Duration::from_secs(10), stop_rx)
        .await
        .unwrap();
    assert_eq!(result.stopped, Some(Stopped::Interrupted));
    assert!(result.cleanly_cancelled);
    assert!(result.outcome.killed_by_deadline);
}

#[tokio::test]
async fn an_interrupt_without_packers_clean_cancel_report_is_not_called_clean() {
    let result = stop_after_ready(
        "trap 'exit 1' INT\ntouch ready\nwhile :; do sleep 0.1; done",
        Duration::from_secs(10),
    )
    .await;
    assert_eq!(result.stopped, Some(Stopped::Interrupted));
    assert!(!result.cleanly_cancelled);
}

#[tokio::test]
async fn a_cli_that_ignores_the_interrupt_is_killed_after_the_grace_period() {
    let result = stop_after_ready(
        "trap '' INT\ntouch ready\nwhile :; do sleep 0.1; done",
        Duration::from_millis(500),
    )
    .await;
    assert_eq!(result.stopped, Some(Stopped::Killed));
    assert_eq!(result.outcome.exit_code, None);
    assert!(!result.cleanly_cancelled);
}

#[tokio::test]
async fn a_descendant_holding_the_pipes_cannot_block_the_run() {
    // The CLI exits at once, but a child it started keeps stdout open.
    let (dir, transport) = fake("echo done\nsleep 60 &\nexit 0", Duration::from_secs(1));
    let (_stop, stop_rx) = tokio::sync::watch::channel(false);
    let started = Instant::now();
    let result = transport
        .run_stoppable(&command(dir.path()), Duration::from_secs(120), stop_rx)
        .await
        .unwrap();
    assert!(
        started.elapsed() < PIPE_DRAIN * 2 + Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(result.outcome.exit_code, Some(0));
    assert!(result.outcome.stdout.contains("done"));
}

#[tokio::test]
async fn an_unstopped_run_completes_normally() {
    let (dir, transport) = fake("echo done", Duration::from_secs(1));
    let (_stop, stop_rx) = tokio::sync::watch::channel(false);
    let result = transport
        .run_stoppable(&command(dir.path()), Duration::from_secs(10), stop_rx)
        .await
        .unwrap();
    assert_eq!(result.stopped, None);
    assert!(!result.cleanly_cancelled);
    assert_eq!(result.outcome.exit_code, Some(0));
    assert!(result.outcome.stdout.contains("done"));
}

#[tokio::test]
async fn the_clean_cancel_report_survives_output_past_the_bound() {
    // More than MAX_OUTPUT_BYTES of output, then Packer's closing report.
    let script = format!(
        "trap 'head -c {} /dev/zero | tr \"\\\\0\" a; echo; echo \"1,,ui,say,Cleanly cancelled builds after being interrupted.\"; exit 1' INT\ntouch ready\nwhile :; do sleep 0.1; done",
        fleet_provider_packer::MAX_OUTPUT_BYTES + 200_000
    );
    let result = stop_after_ready(&script, Duration::from_secs(20)).await;
    assert_eq!(result.stopped, Some(Stopped::Interrupted));
    assert!(result.cleanly_cancelled, "the trailing report was lost");
    assert!(result.outcome.stdout.contains("[... output truncated ...]"));
    assert!(result.outcome.stdout.len() <= fleet_provider_packer::MAX_STREAM_BYTES);
}
