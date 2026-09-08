//! Fleet use cases and provider/storage ports.
//!
//! Application code depends on [`fleet_core`], never on an adapter.

#![warn(missing_docs)]

pub mod audit;
pub mod authz;
pub mod machine;
pub mod node;
pub mod onboarding;
pub mod operation;
pub mod tailnet;
pub mod worker;

/// Skeleton marker proving that the application crate is loadable.
pub const SKELETON: &str = "fleet-application";
