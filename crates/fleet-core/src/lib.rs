//! Fleet domain types and invariants.
//!
//! This crate intentionally has no framework, persistence, subprocess, or
//! provider dependencies. Product behavior will be added by later issues.

#![warn(missing_docs)]

/// Skeleton marker proving that the domain crate is loadable.
pub const SKELETON: &str = "fleet-core";

#[cfg(test)]
mod tests {
    #[test]
    fn domain_skeleton_is_available() {
        assert_eq!(super::SKELETON, "fleet-core");
    }
}
