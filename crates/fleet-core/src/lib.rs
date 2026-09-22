//! Framework-independent Fleet Manager domain primitives.
//!
//! Values in this crate are safe to share between application and adapter
//! layers. It intentionally contains no HTTP, persistence, subprocess, or
//! provider-specific behavior.

#![warn(missing_docs)]

mod difference;
mod error;
mod id;
mod image;
mod lab;
mod machine;
mod operation;
mod project;
mod redact;
mod sensitive;
mod source;
mod time;
mod value;

pub use difference::{DifferenceSet, DifferenceState, FieldDifference, compare_field};
pub use error::{ErrorCode, FleetError, ParseErrorCodeError, PublicError, RetryClass};
pub use id::{CorrelationId, IdGenerator, ParseIdError, ResourceId, UuidV7Generator};
pub use image::{
    MAX_RECIPE_CONTENT_BYTES, RecipeContent, RecipeSource, RecipeVersion, StructuredRecipe,
};
pub use lab::{CleanupStrategy, GuestState, LabTemplateContent, ReadinessProbe};
pub use machine::{CapabilityFact, CapabilityStatus, EndpointKind};
pub use operation::{
    InvalidTransitionError, OperationState, can_transition, deadline_passed, validate_transition,
};
pub use project::{CheckoutFact, NormalizedRemote, Project, ProjectView};
pub use redact::{
    flatten_control_characters, redact_schemeless_credentials, redact_url_credentials,
};
pub use sensitive::{SecretReference, SensitiveString};
pub use source::CandidateDigest;
pub use time::{Clock, Deadline, FixedClock, SystemClock, Timestamp};
pub use value::{ParseSlugError, Revision, Slug};
