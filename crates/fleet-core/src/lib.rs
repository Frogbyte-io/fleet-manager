//! Framework-independent Fleet Manager domain primitives.
//!
//! Values in this crate are safe to share between application and adapter
//! layers. It intentionally contains no HTTP, persistence, subprocess, or
//! provider-specific behavior.

#![warn(missing_docs)]

mod error;
mod id;
mod machine;
mod operation;
mod sensitive;
mod time;
mod value;

pub use error::{ErrorCode, FleetError, ParseErrorCodeError, PublicError, RetryClass};
pub use id::{CorrelationId, IdGenerator, ParseIdError, ResourceId, UuidV7Generator};
pub use machine::{CapabilityFact, CapabilityStatus, EndpointKind};
pub use operation::{
    InvalidTransitionError, OperationState, can_transition, deadline_passed, validate_transition,
};
pub use sensitive::{SecretReference, SensitiveString};
pub use time::{Clock, Deadline, FixedClock, SystemClock, Timestamp};
pub use value::{ParseSlugError, Revision, Slug};
