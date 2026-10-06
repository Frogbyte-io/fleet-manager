//! `cargo xtask image-acceptance [--target NAME]`: runs the real-host image
//! build suite (`crates/fleet-controller/tests/images_live.rs`, FM-704)
//! through the shared [`crate::acceptance`] runner and prints its JSON
//! summary on stdout. It reads the same `FLEET_PVE_*` target contract as
//! `pve-acceptance`, and additionally needs an operator-installed `packer`
//! inside the FM-S09 pins on the machine that runs it.

use std::path::Path;

use crate::acceptance::{self, SuiteSpec, Summary};

/// The marker the suite prints before every result.
pub const RESULT_MARKER: &str = "FLEET_IMAGE_ACCEPTANCE_RESULT";

/// The scenarios, in report order. Kept in step with the suite's
/// `SCENARIOS`.
pub const SCENARIOS: [&str; 7] = [
    "version-gate",
    "validate-failure",
    "build",
    "build-record",
    "promotion",
    "rebuild-keeps-promotion",
    "cancel-cleanup",
];

/// The suite.
pub const SPEC: SuiteSpec = SuiteSpec {
    suite: "image-acceptance",
    marker: RESULT_MARKER,
    scenarios: &SCENARIOS,
    test_target: "images_live",
};

/// Parses the subcommand's arguments: `[--target NAME]`.
///
/// # Errors
///
/// On an unknown argument or a missing/invalid target name.
pub fn parse_args(args: &[String]) -> Result<Option<String>, String> {
    acceptance::parse_args(&SPEC, args)
}

/// Runs the suite and answers its summary.
///
/// # Errors
///
/// When cargo cannot run or the target filter names no configured target.
pub fn run(repo_root: &Path, target: Option<&str>) -> Result<Summary, String> {
    acceptance::run(&SPEC, repo_root, target)
}
