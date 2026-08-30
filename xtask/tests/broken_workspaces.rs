use std::path::PathBuf;
use std::process::{Command, Output};

fn run_fixture(name: &str) -> Output {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("verify")
        .current_dir(fixture)
        .output()
        .expect("xtask binary runs")
}

#[test]
fn command_fails_for_a_broken_rust_workspace() {
    let output = run_fixture("rust-broken");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(
        stderr.contains("error: Rust formatting failed: cargo fmt --all --check"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn command_fails_for_a_broken_web_workspace() {
    let output = run_fixture("web-broken");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(
        stderr.contains("error: Web lint failed: corepack pnpm -r --if-present run lint"),
        "unexpected stderr: {stderr}"
    );
}
