//! Audit event types and the rules that keep secrets out of them.
//!
//! Audit answers "who did what, on what, and with what result" for every
//! authorized action, including the ones that were refused. The event shape
//! and the metadata rules live here — in the application layer — because they
//! are policy: any storage adapter that persists audit events is constrained
//! by these types, and the metadata guard structurally rejects the raw
//! request material that would otherwise leak credentials into an
//! append-only ledger.
//!
//! The write pattern is two-phase: an **intent** is appended when an action
//! is accepted (inside the same transaction as the state change, wherever one
//! exists), and the **outcome** is appended separately when the action
//! terminates. An intent without an outcome is therefore itself evidence —
//! the action was accepted and its result is unknown.
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::fmt;

use crate::authz::Decision;

/// Metadata entry value bound. Audit metadata is for references and facts,
/// not payloads; anything larger belongs in an artifact or a log.
pub const MAX_METADATA_VALUE_BYTES: usize = 2048;
/// Total metadata bound per event.
pub const MAX_METADATA_TOTAL_BYTES: usize = 32 * 1024;
/// Maximum number of metadata entries per event.
pub const MAX_METADATA_ENTRIES: usize = 32;

/// Keys that may never appear in audit metadata, case-insensitively, as
/// substrings: a key named `x-authorization-token` is a leak attempt, not a
/// naming coincidence.
const FORBIDDEN_KEY_PARTS: [&str; 11] = [
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api-key",
    "private-key",
    "forwarded",
    "real-ip",
    "remote-addr",
];

/// Top-level keys that stand in for whole raw structures — a `headers` or
/// `env` entry is a bulk leak even if its own name is clean.
const FORBIDDEN_EXACT_KEYS: [&str; 4] = ["headers", "env", "environment", "query"];

/// A metadata problem: the key or value would put sensitive or unbounded
/// material into the audit trail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataError {
    /// The key matches a forbidden pattern.
    ForbiddenKey {
        /// The rejected key.
        key: String,
    },
    /// The value exceeds the per-entry bound.
    ValueTooLarge {
        /// The rejected key.
        key: String,
        /// The observed size in bytes.
        size: usize,
        /// The allowed size in bytes.
        limit: usize,
    },
    /// The event's metadata would exceed the total bound.
    TooManyEntries {
        /// The allowed count.
        limit: usize,
    },
}

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForbiddenKey { key } => write!(
                f,
                "audit metadata key {key:?} is forbidden; raw request or credential material must never be recorded"
            ),
            Self::ValueTooLarge { key, size, limit } => {
                write!(
                    f,
                    "audit metadata value for {key:?} is {size} bytes, over the {limit}-byte bound"
                )
            }
            Self::TooManyEntries { limit } => write!(f, "audit metadata exceeds {limit} entries"),
        }
    }
}

impl std::error::Error for MetadataError {}

/// Ordered, validated metadata for one audit event.
///
/// Order is stable (insertion), validation happens at insertion, and the
/// JSON serialization is derived from what was validated — there is no path
/// from a forbidden key into the stored event.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditMetadata {
    entries: BTreeMap<String, String>,
}

impl AuditMetadata {
    /// Inserts an entry, failing closed on forbidden or oversized material.
    ///
    /// # Errors
    ///
    /// Fails on a forbidden key, an oversized value, or too many entries.
    pub fn insert(&mut self, key: &str, value: &str) -> Result<(), MetadataError> {
        let normalized = key.to_ascii_lowercase();
        if FORBIDDEN_EXACT_KEYS.contains(&normalized.as_str())
            || FORBIDDEN_KEY_PARTS
                .iter()
                .any(|part| normalized.contains(part))
        {
            return Err(MetadataError::ForbiddenKey {
                key: key.to_owned(),
            });
        }
        if value.len() > MAX_METADATA_VALUE_BYTES {
            return Err(MetadataError::ValueTooLarge {
                key: key.to_owned(),
                size: value.len(),
                limit: MAX_METADATA_VALUE_BYTES,
            });
        }
        if self.entries.len() >= MAX_METADATA_ENTRIES {
            return Err(MetadataError::TooManyEntries {
                limit: MAX_METADATA_ENTRIES,
            });
        }
        self.entries.insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    /// The validated entries, in stable key order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Whether nothing was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The canonical JSON serialization stored in the event.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.entries).unwrap_or_else(|_| "{}".to_owned())
    }
}

/// The terminal result of an accepted action, appended separately from its
/// intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    /// The action completed successfully.
    Succeeded,
    /// The action failed; the detail is a bounded, already-redacted string.
    Failed,
    /// The action was cancelled before completing.
    Cancelled,
}

impl AuditOutcome {
    /// The stable outcome id recorded in the event.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// The intent record: who is about to do what, with which authorization, in
/// which correlation context.
#[derive(Clone, Debug)]
pub struct AuditIntent {
    /// The acting principal's stable id.
    pub actor: String,
    /// The catalog action id.
    pub action: String,
    /// The named resource, when the action has one.
    pub resource: Option<String>,
    /// The authorization decision that accepted (or refused) the request.
    pub decision: Decision,
    /// The correlation identity joining this event to the caller's flow.
    pub correlation_id: Option<String>,
    /// The durable operation this event belongs to, when one exists.
    pub operation_id: Option<String>,
    /// Validated metadata.
    pub metadata: AuditMetadata,
}

/// The stored audit event, as read back by queries.
#[derive(Clone, Debug)]
pub struct AuditEvent {
    /// Append-only position of the event within the ledger.
    pub seq: i64,
    /// The event's identity.
    pub id: String,
    /// When the event was appended (epoch milliseconds).
    pub occurred_at: i64,
    /// The acting principal.
    pub actor: String,
    /// The action id.
    pub action: String,
    /// The named resource, when any.
    pub resource: Option<String>,
    /// Whether the request was allowed.
    pub allowed: bool,
    /// The decision's stable reason.
    pub reason: String,
    /// The correlation identity, when supplied.
    pub correlation_id: Option<String>,
    /// The durable operation this event belongs to, when any.
    pub operation_id: Option<String>,
    /// The terminal outcome, when it has been appended.
    pub outcome: Option<AuditOutcome>,
    /// The validated metadata as canonical JSON.
    pub metadata_json: String,
}
