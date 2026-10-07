//! `cargo xtask pve-acceptance [--target NAME]`: runs the real-cluster
//! acceptance suite (`crates/fleet-controller/tests/proxmox_live.rs`,
//! FM-611) through the shared [`crate::acceptance`] runner and prints its
//! JSON summary on stdout.

use crate::acceptance::SuiteSpec;

/// The marker the suite prints before every result.
pub const RESULT_MARKER: &str = "FLEET_PVE_ACCEPTANCE_RESULT";

/// The scenarios, in report order. Kept in step with the suite's
/// `SCENARIOS`.
pub const SCENARIOS: [&str; 6] = [
    "trust",
    "privilege-failure",
    "task-polling",
    "destructive-gate",
    "association",
    "partial-node-failure",
];

/// The suite.
pub const SPEC: SuiteSpec = SuiteSpec {
    suite: "pve-acceptance",
    marker: RESULT_MARKER,
    scenarios: &SCENARIOS,
    test_target: "proxmox_live",
};
