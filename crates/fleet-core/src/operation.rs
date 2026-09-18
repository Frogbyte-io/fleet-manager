//! The durable operation state machine.
//!
//! Remote work is never request-scoped: an accepted action becomes an
//! operation record that survives restarts, carries a deadline, and can be
//! cancelled. This module owns the *states* and the *legal transitions*
//! between them — pure domain rules, no HTTP and no persistence — so every
//! adapter agrees on what an operation can mean, and an illegal transition is
//! a domain error rather than a database accident.
//!
//! The lifecycle, including the two ways work can stop without success:
//!
//! ```text
//! Pending -> Running -> Cancelling -> Cancelled
//!    |          |            |
//!    |          |            +-> Succeeded | Failed (cancel lost the race)
//!    |          +-> Succeeded | Failed | TimedOut
//!    +-> Cancelled (refused before it started) | TimedOut (never claimed)
//! ```
//!
//! Terminal states are terminal: no transition leaves them.
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;

use crate::time::Timestamp;

/// A durable operation's execution state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Accepted and durable, but not yet executing.
    Pending,
    /// Executing.
    Running,
    /// Executing and asked to stop at the next checkpoint.
    Cancelling,
    /// Completed successfully.
    Succeeded,
    /// Completed with a failure.
    Failed,
    /// Stopped by an explicit cancellation.
    Cancelled,
    /// Stopped because its deadline passed.
    TimedOut,
    /// Completed by reporting that a human must act: a security-sensitive
    /// ceremony Fleet cannot perform itself. A first-class terminal state,
    /// not a failure wearing a label (FM-303).
    BlockedManualApproval,
}

impl OperationState {
    /// Whether no further transition is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Cancelled
                | Self::TimedOut
                | Self::BlockedManualApproval
        )
    }

    /// The stable string used in storage, the API, and audit events.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Cancelling => "cancelling",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::BlockedManualApproval => "blocked_manual_approval",
        }
    }

    /// Parses the stable string.
    ///
    /// # Errors
    ///
    /// Fails on a string that is not a state id.
    pub fn from_id(id: &str) -> Result<Self, InvalidTransitionError> {
        Ok(match id {
            "pending" => Self::Pending,
            "running" => Self::Running,
            "cancelling" => Self::Cancelling,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            "timed_out" => Self::TimedOut,
            "blocked_manual_approval" => Self::BlockedManualApproval,
            _ => {
                return Err(InvalidTransitionError {
                    from: "<unknown>".to_owned(),
                    to: id.to_owned(),
                });
            }
        })
    }
}

/// An illegal state transition, refused by the domain.
#[derive(Clone, Debug, Eq, PartialEq, ThisError)]
#[error("illegal operation transition from {from} to {to}")]
pub struct InvalidTransitionError {
    /// The state the operation was in.
    pub from: String,
    /// The state it was asked to move to.
    pub to: String,
}

/// The transition rules. Anything not listed here is illegal: the match is
/// exhaustive on purpose, so adding a state forces a decision about its
/// transitions rather than silently allowing none or all.
#[must_use]
pub fn can_transition(from: OperationState, to: OperationState) -> bool {
    use OperationState::{
        BlockedManualApproval, Cancelled, Cancelling, Failed, Pending, Running, Succeeded, TimedOut,
    };
    match (from, to) {
        (Pending, Running | Cancelled | TimedOut)
        | (Running, Succeeded | Failed | Cancelling | TimedOut | BlockedManualApproval)
        | (Cancelling, Cancelled | Succeeded | Failed) => true,
        (Pending, Pending | Succeeded | Failed | Cancelling | BlockedManualApproval)
        | (Running, Pending | Running | Cancelled)
        | (Cancelling, Pending | Running | Cancelling | TimedOut | BlockedManualApproval)
        | (Succeeded | Failed | Cancelled | TimedOut | BlockedManualApproval, _) => false,
    }
}

/// Validates one transition.
///
/// # Errors
///
/// Returns [`InvalidTransitionError`] when the move is not legal.
pub fn validate_transition(
    from: OperationState,
    to: OperationState,
) -> Result<(), InvalidTransitionError> {
    if can_transition(from, to) {
        Ok(())
    } else {
        Err(InvalidTransitionError {
            from: from.id().to_owned(),
            to: to.id().to_owned(),
        })
    }
}

/// Whether a deadline has passed for an operation still executing.
///
/// A deadline is only consulted while work is live: a terminal operation's
/// deadline has no meaning, and a `Pending` operation that missed its start
/// deadline is [`OperationState::TimedOut`] rather than silently stale.
#[must_use]
pub fn deadline_passed(state: OperationState, deadline: Option<Timestamp>, now: Timestamp) -> bool {
    match (state, deadline) {
        (
            OperationState::Pending | OperationState::Running | OperationState::Cancelling,
            Some(deadline),
        ) => now.unix_millis() >= deadline.unix_millis(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATES: [OperationState; 7] = [
        OperationState::Pending,
        OperationState::Running,
        OperationState::Cancelling,
        OperationState::Succeeded,
        OperationState::Failed,
        OperationState::Cancelled,
        OperationState::TimedOut,
    ];

    #[test]
    fn terminal_states_never_transition() {
        for terminal in [
            OperationState::Succeeded,
            OperationState::Failed,
            OperationState::Cancelled,
            OperationState::TimedOut,
        ] {
            for to in STATES {
                assert!(!can_transition(terminal, to), "{terminal:?} -> {to:?}");
            }
        }
    }

    #[test]
    fn ids_round_trip() {
        for state in STATES {
            assert_eq!(OperationState::from_id(state.id()).unwrap(), state);
        }
    }

    #[test]
    fn no_state_transitions_to_itself() {
        for state in STATES {
            assert!(!can_transition(state, state), "{state:?}");
        }
    }
}
