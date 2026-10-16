//! The action request state machine and risk classes (FM-1040).
//!
//! An agent asks Fleet to run a typed provider action. The request is a
//! durable record whose lifecycle is a pure domain rule, kept here so every
//! adapter agrees on what a request can mean:
//!
//! ```text
//! pending -> approved -> executing -> succeeded | failed
//!    |           |
//!    |           +-> failed (the operation could not be started)
//!    +-> denied | expired
//! ```
//!
//! `denied`, `expired`, `succeeded`, and `failed` are terminal. Which
//! transitions are legal is decided here; who may perform one is decided by
//! the application's authorization port, never here.
#![warn(missing_docs)]

use thiserror::Error as ThisError;

/// How a provider action is handled when requested.
///
/// A provider action declares one as its default; an operator setting may
/// raise or lower it per action id. Before authenticated identities (M8)
/// this is a guardrail against agent mistakes, not a security boundary
/// (ADR 0016).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RiskClass {
    /// Runs when requested, without a human decision.
    Auto,
    /// Waits for a human approval.
    Approve,
    /// Refused: the request is recorded as denied by policy.
    Deny,
}

impl RiskClass {
    /// The stable id stored, served, and set in the operator override.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }

    /// Parses a stable id.
    ///
    /// # Errors
    ///
    /// Fails on an unknown id.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "auto" => Ok(Self::Auto),
            "approve" => Ok(Self::Approve),
            "deny" => Ok(Self::Deny),
            other => Err(format!(
                "unknown risk class {other:?}; expected auto, approve, or deny"
            )),
        }
    }
}

/// Where an action request is in its life.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ActionRequestState {
    /// Waiting for a human decision.
    Pending,
    /// Approved (by a person or by `auto` policy); the operation is about
    /// to be created.
    Approved,
    /// Refused by a person or by `deny` policy. Terminal.
    Denied,
    /// No decision before the deadline. Terminal.
    Expired,
    /// The durable operation exists and is running or queued.
    Executing,
    /// The operation succeeded. Terminal.
    Succeeded,
    /// The operation failed, or could not be created. Terminal.
    Failed,
}

/// Every state, for exhaustive tests and validation.
pub const ACTION_REQUEST_STATES: [ActionRequestState; 7] = [
    ActionRequestState::Pending,
    ActionRequestState::Approved,
    ActionRequestState::Denied,
    ActionRequestState::Expired,
    ActionRequestState::Executing,
    ActionRequestState::Succeeded,
    ActionRequestState::Failed,
];

impl ActionRequestState {
    /// The stable id stored, served, and audited.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Executing => "executing",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    /// Parses a stable id.
    ///
    /// # Errors
    ///
    /// Fails on an unknown id.
    pub fn from_id(id: &str) -> Result<Self, String> {
        ACTION_REQUEST_STATES
            .into_iter()
            .find(|state| state.id() == id)
            .ok_or_else(|| format!("unknown action request state {id:?}"))
    }

    /// Whether no transition leaves the state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Denied | Self::Expired | Self::Succeeded | Self::Failed
        )
    }
}

/// Whether `from -> to` is a legal transition.
#[must_use]
pub const fn can_transition_action_request(
    from: ActionRequestState,
    to: ActionRequestState,
) -> bool {
    use ActionRequestState::{Approved, Denied, Executing, Expired, Failed, Pending, Succeeded};
    matches!(
        (from, to),
        (Pending, Approved | Denied | Expired)
            | (Approved, Executing | Failed)
            | (Executing, Succeeded | Failed)
    )
}

/// An illegal transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
#[error("an action request cannot go from {} to {}", .from.id(), .to.id())]
pub struct InvalidActionTransition {
    /// The current state.
    pub from: ActionRequestState,
    /// The refused target state.
    pub to: ActionRequestState,
}

/// Checks a transition.
///
/// # Errors
///
/// Fails when the transition is not legal.
pub const fn validate_action_request_transition(
    from: ActionRequestState,
    to: ActionRequestState,
) -> Result<(), InvalidActionTransition> {
    if can_transition_action_request(from, to) {
        Ok(())
    } else {
        Err(InvalidActionTransition { from, to })
    }
}

/// Whether a pending request is past its deadline at `now` (epoch
/// milliseconds). At `expires_at` itself the request is expired.
#[must_use]
pub const fn action_request_deadline_passed(expires_at: i64, now: i64) -> bool {
    now >= expires_at
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_the_documented_transitions_are_legal() {
        let legal = [
            ("pending", "approved"),
            ("pending", "denied"),
            ("pending", "expired"),
            ("approved", "executing"),
            ("approved", "failed"),
            ("executing", "succeeded"),
            ("executing", "failed"),
        ];
        for from in ACTION_REQUEST_STATES {
            for to in ACTION_REQUEST_STATES {
                assert_eq!(
                    can_transition_action_request(from, to),
                    legal.contains(&(from.id(), to.id())),
                    "{} -> {}",
                    from.id(),
                    to.id()
                );
            }
        }
    }

    #[test]
    fn terminal_states_have_no_exit() {
        for from in ACTION_REQUEST_STATES
            .into_iter()
            .filter(|s| s.is_terminal())
        {
            for to in ACTION_REQUEST_STATES {
                assert!(validate_action_request_transition(from, to).is_err());
            }
        }
    }

    #[test]
    fn ids_round_trip() {
        for state in ACTION_REQUEST_STATES {
            assert_eq!(ActionRequestState::from_id(state.id()), Ok(state));
        }
        for class in [RiskClass::Auto, RiskClass::Approve, RiskClass::Deny] {
            assert_eq!(RiskClass::from_id(class.id()), Ok(class));
        }
        assert!(ActionRequestState::from_id("done").is_err());
        assert!(RiskClass::from_id("yolo").is_err());
    }

    #[test]
    fn the_deadline_is_inclusive() {
        assert!(!action_request_deadline_passed(100, 99));
        assert!(action_request_deadline_passed(100, 100));
    }
}
