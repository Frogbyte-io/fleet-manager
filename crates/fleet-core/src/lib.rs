//! Framework-independent Fleet Manager domain primitives.
//!
//! Values in this crate are safe to share between application and adapter
//! layers. It intentionally contains no HTTP, persistence, subprocess, or
//! provider-specific behavior.

#![warn(missing_docs)]

mod build_address;
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
mod skill_catalog;
mod source;
mod time;
mod value;

pub use build_address::{
    BUILD_ADDRESS_REASONS, BuildAddressPool, BuildAddressPoolError, MAX_BUILD_ADDRESS_DNS_SERVERS,
    MAX_BUILD_ADDRESS_POOL_SIZE, REASON_ALLOCATION_FAILED, REASON_AUDIT_FAILED,
    REASON_BUILDER_UNSUPPORTED, REASON_ISO_REFUSED, REASON_POOL_EXHAUSTED,
    build_address_reason_message, build_addresses_needed, with_build_addresses,
};
pub use difference::{DifferenceSet, DifferenceState, FieldDifference, compare_field};
pub use error::{ErrorCode, FleetError, ParseErrorCodeError, PublicError, RetryClass};
pub use id::{CorrelationId, IdGenerator, ParseIdError, ResourceId, UuidV7Generator};

/// Tailscale Serve identity header names that may be recorded as audit evidence.
/// Values from these headers are never part of audit metadata.
pub const TAILSCALE_IDENTITY_HEADER_NAMES: [&str; 3] = [
    "tailscale-user-login",
    "tailscale-user-name",
    "tailscale-user-profile-pic",
];
pub use image::{
    ImageBuildRecord, ImageBuildTemplate, MAX_RECIPE_CONTENT_BYTES, RECIPE_REFUSAL_REASONS,
    RecipeContent, RecipeSource, RecipeVersion, StructuredRecipe, recipe_build_refusal,
    recipe_refusal_message, requests_insecure_tls,
};
pub use lab::{
    CleanupStrategy, GuestState, LabTemplateContent, Lease, LeaseState,
    MAX_LAB_LEASE_LIFETIME_MILLIS, ReadinessProbe,
};
pub use machine::{CapabilityFact, CapabilityStatus, EndpointKind};
pub use operation::{
    InvalidTransitionError, OperationState, can_transition, deadline_passed, validate_transition,
};
pub use project::{CheckoutFact, FetchScheme, NormalizedRemote, Project, ProjectView, RemoteFetch};
pub use redact::{
    flatten_control_characters, redact_credentials, redact_schemeless_credentials,
    redact_url_credentials,
};
pub use sensitive::{SecretReference, SensitiveString};
pub use skill_catalog::{
    BUILTIN_FLEET_SKILL_CATALOG_ID, BUILTIN_SKILL_CATALOG_PREFIX, MAX_SKILL_CATALOG_BYTES,
    MAX_SKILL_CATALOG_FILES, SkillCatalogContent, SkillCatalogFile, SkillCatalogSource,
    is_builtin_skill_catalog_id,
};
pub use source::CandidateDigest;
pub use time::{Clock, Deadline, FixedClock, SystemClock, Timestamp};
pub use value::{ParseSlugError, Revision, Slug};
