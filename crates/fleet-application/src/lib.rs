//! Fleet use cases and provider/storage ports.
//!
//! Application code depends on [`fleet_core`], never on an adapter.

#![warn(missing_docs)]

pub mod apply;
pub mod audit;
pub mod authz;
pub mod composition;
pub mod machine;
pub mod node;
pub mod observed;
pub mod onboarding;
pub mod operation;
pub mod planner;
pub mod project;
pub mod ready;
pub mod tailnet;
pub mod worker;
