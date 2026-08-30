use std::process::ExitStatus;

use xtask::{CommandRunner, VerificationError, verification_steps, verify_with};

#[derive(Default)]
struct FakeRunner {
    calls: Vec<String>,
    fail_at: Option<usize>,
}

impl CommandRunner for FakeRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> std::io::Result<ExitStatus> {
        self.calls.push(format!("{program} {}", args.join(" ")));
        let code = i32::from(self.fail_at == Some(self.calls.len() - 1));
        Ok(exit_status(code))
    }
}

#[cfg(unix)]
fn exit_status(code: i32) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(code << 8)
}

#[cfg(windows)]
fn exit_status(code: i32) -> ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    ExitStatus::from_raw(code as u32)
}

#[test]
fn rust_workspace_failure_is_legible_and_stops_verification() {
    let mut runner = FakeRunner {
        fail_at: Some(1),
        ..FakeRunner::default()
    };

    let error = verify_with(&mut runner).expect_err("the second Rust step must fail");

    assert_eq!(runner.calls.len(), 2);
    assert!(matches!(error, VerificationError::CommandFailed { .. }));
    assert_eq!(
        error.to_string(),
        "Rust clippy failed: cargo clippy --workspace --all-targets --all-features --locked -- -D warnings"
    );
}

#[test]
fn web_workspace_failure_is_legible_and_stops_verification() {
    let steps = verification_steps();
    let web_install = steps
        .iter()
        .position(|step| step.label == "Web frozen install")
        .expect("web install step exists");
    let mut runner = FakeRunner {
        fail_at: Some(web_install),
        ..FakeRunner::default()
    };

    let error = verify_with(&mut runner).expect_err("the web install must fail");

    assert_eq!(runner.calls.len(), web_install + 1);
    assert_eq!(
        error.to_string(),
        "Web frozen install failed: corepack pnpm install --frozen-lockfile"
    );
}

#[test]
fn successful_verification_runs_every_step_in_order() {
    let mut runner = FakeRunner::default();

    verify_with(&mut runner).expect("all fake commands succeed");

    assert_eq!(runner.calls.len(), verification_steps().len());
    assert_eq!(runner.calls.first().unwrap(), "cargo fmt --all --check");
    assert_eq!(
        runner.calls.last().unwrap(),
        "corepack pnpm -r --if-present run build"
    );
}
