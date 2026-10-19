//! The Registry read model (FM-1012, ADR 0016): fast lookup of the active
//! revision's `RegistryType` and `RegistryEntry` resources.
//!
//! The cache is derived from the active revision's resource snapshot
//! (FM-404), never from Git directly and never written by a caller. It is
//! rebuilt after activation and rollback, and lazily on read whenever its
//! recorded revision (or the built-in type set) differs from the active
//! one, so it cannot drift into a second authority. Every answer names
//! the revision it came from.
//!
//! The Registry is descriptive: nothing here plans, applies, or writes.
#![warn(missing_docs)]

pub mod enrich;
mod projection;

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::authz::{AccessRequest, Authorizer, Permission, authorize};
use crate::project::ProjectUseCaseError;
use crate::source::{ActiveRevision, DesiredResourceRecord, SourcePort};

pub use projection::derive;

/// The relation target classes a Registry entry may point at.
pub const TARGET_CLASSES: [&str; 5] = ["registry", "machine", "project", "coolify", "proxmoxGuest"];

/// Resources read per page during a rebuild.
const REBUILD_PAGE: i64 = 500;
/// The most resources of one kind a rebuild reads; a revision beyond this
/// is refused rather than silently truncated.
const REBUILD_MAX: usize = 50_000;
/// How long a failed rebuild of a revision is remembered before a read
/// tries again.
const FAILURE_MEMORY: Duration = Duration::from_secs(5);

/// A type Fleet ships. The spec has the `RegistryType` spec's shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltinRegistryType {
    /// The type's name, as entries reference it.
    pub name: String,
    /// The type's spec (`displayName`, `key`, `fields`, `relations`).
    pub spec: serde_json::Value,
}

/// Where a type definition came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TypeOrigin {
    /// Shipped with Fleet.
    Builtin,
    /// Defined by a `RegistryType` resource in the Fleet Git repository.
    Repository,
}

impl TypeOrigin {
    /// The stable storage and API form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Builtin => "builtin",
            Self::Repository => "repository",
        }
    }

    /// Parses the stable form.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "builtin" => Some(Self::Builtin),
            "repository" => Some(Self::Repository),
            _ => None,
        }
    }
}

/// One Registry type of the active revision.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RegistryTypeRecord {
    /// The type's name.
    pub name: String,
    /// Built-in or repository-defined.
    pub origin: TypeOrigin,
    /// The resource identity, for repository types.
    pub resource_id: Option<String>,
    /// The human-facing name.
    pub display_name: String,
    /// The field holding an entry's natural key.
    pub key_field: String,
    /// The relation names entries of this type may declare.
    pub relations: Vec<String>,
    /// The full type spec (fields and their value types).
    pub spec: serde_json::Value,
    /// The defining document's repository path, for repository types.
    pub source_path: Option<String>,
    /// How many entries of the type the revision holds. Filled by the
    /// store when listing; zero in a projection.
    pub entry_count: i64,
}

/// What a relation points at: a class and a reference within it. A
/// `registry` reference is `<type>/<key>`; a machine or project reference
/// is its name; Coolify and Proxmox references are as recorded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistryTarget {
    /// One of [`TARGET_CLASSES`].
    pub class: String,
    /// The reference within the class.
    pub reference: String,
}

impl RegistryTarget {
    /// Parses `class:reference`.
    ///
    /// # Errors
    ///
    /// Fails when the class is unknown or the reference is empty,
    /// over-long, or carries whitespace or control characters.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (class, reference) = text
            .split_once(':')
            .ok_or("a target is `<class>:<reference>`")?;
        if !TARGET_CLASSES.contains(&class) {
            return Err(format!(
                "the target class must be one of {}",
                TARGET_CLASSES.join(", ")
            ));
        }
        if reference.is_empty()
            || reference.len() > 256
            || reference
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err("the target reference is empty or malformed".to_owned());
        }
        if class == "registry" && split_entry_ref(reference).is_none() {
            return Err("a registry target is `registry:<type>/<key>`".to_owned());
        }
        Ok(Self {
            class: class.to_owned(),
            reference: reference.to_owned(),
        })
    }
}

/// The case-insensitive form of an entry key. Keys are unique regardless of
/// case (FM-1010), so lookups, joins, and cursors use this form while the
/// key as written is kept for display.
#[must_use]
pub fn normalize_key(key: &str) -> String {
    key.to_lowercase()
}

/// Splits `<type>/<key>`; both halves must be non-empty and the key must
/// not itself contain a slash (the validator guarantees it never does).
#[must_use]
pub fn split_entry_ref(reference: &str) -> Option<(&str, &str)> {
    let (entry_type, key) = reference.split_once('/')?;
    (!entry_type.is_empty() && !key.is_empty() && !key.contains('/')).then_some((entry_type, key))
}

impl RegistryTarget {
    /// The reference in comparison form: a `registry` reference is
    /// case-insensitive (it names an entry), every other class compares
    /// as recorded.
    #[must_use]
    pub fn normalized_reference(&self) -> String {
        if self.class == "registry" {
            normalize_key(&self.reference)
        } else {
            self.reference.clone()
        }
    }
}

/// One relation of an entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistryRelationRecord {
    /// The relation type, for example `used-by`.
    pub relation_type: String,
    /// What it points at.
    pub target: RegistryTarget,
}

/// One Registry entry of the active revision.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RegistryEntryRecord {
    /// The entry's type name.
    pub entry_type: String,
    /// The natural key, unique per type.
    pub key: String,
    /// The stable resource identity.
    pub resource_id: String,
    /// The resource's slug name.
    pub name: String,
    /// The field values.
    pub fields: serde_json::Value,
    /// The tags.
    pub tags: Vec<String>,
    /// The links, as recorded.
    pub links: serde_json::Value,
    /// Free-form notes.
    pub notes: Option<String>,
    /// The outgoing relations.
    pub relations: Vec<RegistryRelationRecord>,
    /// The entry's repository-relative file path, when the snapshot
    /// recorded it, for edit links.
    pub source_path: Option<String>,
}

impl RegistryEntryRecord {
    /// The lowercase text a free-text query matches: address, name,
    /// field values, tags, and notes. Field names and link URLs are not
    /// part of it.
    #[must_use]
    pub fn search_text(&self) -> String {
        let mut text = format!("{}/{} {}", self.entry_type, self.key, self.name);
        if let Some(fields) = self.fields.as_object() {
            for value in fields.values() {
                push_scalars(value, &mut text);
            }
        }
        for tag in &self.tags {
            text.push(' ');
            text.push_str(tag);
        }
        if let Some(notes) = &self.notes {
            text.push(' ');
            text.push_str(notes);
        }
        text.to_lowercase()
    }
}

fn push_scalars(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::String(text) => {
            out.push(' ');
            out.push_str(text);
        }
        serde_json::Value::Number(number) => {
            out.push(' ');
            out.push_str(&number.to_string());
        }
        serde_json::Value::Bool(flag) => {
            out.push(' ');
            out.push_str(if *flag { "true" } else { "false" });
        }
        serde_json::Value::Array(items) => {
            for item in items {
                push_scalars(item, out);
            }
        }
        _ => {}
    }
}

/// An entry that points at a target: the reverse of a relation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistryReference {
    /// The relation type the entry declares.
    pub relation_type: String,
    /// The pointing entry's type.
    pub entry_type: String,
    /// The pointing entry's key.
    pub entry_key: String,
    /// The pointing entry's slug name.
    pub entry_name: String,
    /// The pointing entry's repository path, when recorded.
    pub source_path: Option<String>,
}

/// Everything the cache holds for one revision.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RegistryProjection {
    /// The types: ordered by name.
    pub types: Vec<RegistryTypeRecord>,
    /// The entries, ordered by type then key.
    pub entries: Vec<RegistryEntryRecord>,
}

/// What a cache was built from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheState {
    /// The revision whose snapshot the cache mirrors.
    pub revision: ActiveRevision,
    /// A digest of the built-in type set the cache was built with.
    pub builtin_fingerprint: String,
}

/// An entry listing filter. All set filters must match.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegistryEntryFilter {
    /// Only entries of this type.
    pub entry_type: Option<String>,
    /// Only entries carrying this tag (exact).
    pub tag: Option<String>,
    /// Only entries whose searchable text contains this text
    /// (case-insensitive).
    pub query: Option<String>,
    /// Only entries with a relation to this target.
    pub target: Option<RegistryTarget>,
    /// With `target`, only relations of this type.
    pub relation: Option<String>,
}

/// A position in an entry listing: after this `(type, key)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryCursor {
    /// The previous page's last entry type.
    pub entry_type: String,
    /// The previous page's last entry key.
    pub key: String,
}

/// A position in a reference listing: after this `(type, key, relation)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceCursor {
    /// The previous page's last pointing entry type.
    pub entry_type: String,
    /// The previous page's last pointing entry key.
    pub key: String,
    /// The previous page's last relation type.
    pub relation_type: String,
}

/// The cache's storage contract. Implementations only mirror what
/// [`RegistryReadModel`] derives from a snapshot.
#[async_trait::async_trait]
pub trait RegistryCachePort: std::fmt::Debug + Send + Sync {
    /// What the cache currently mirrors, when it was ever built.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn cache_state(&self) -> Result<Option<CacheState>, String>;
    /// Replaces the whole cache in one transaction. Returns `false`
    /// without writing when the active revision is no longer `state`'s
    /// (an activation raced the rebuild); the caller retries.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn replace_cache(
        &self,
        state: &CacheState,
        projection: &RegistryProjection,
    ) -> Result<bool, String>;
    /// All types with entry counts, ordered by name.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list_types(&self) -> Result<Vec<RegistryTypeRecord>, String>;
    /// At most `limit` entries after the cursor, ordered by type then key.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list_entries(
        &self,
        filter: &RegistryEntryFilter,
        after: Option<&EntryCursor>,
        limit: i64,
    ) -> Result<Vec<RegistryEntryRecord>, String>;
    /// One entry.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn get_entry(
        &self,
        entry_type: &str,
        key: &str,
    ) -> Result<Option<RegistryEntryRecord>, String>;
    /// At most `limit` entries that point at the target, optionally by
    /// relation type, ordered by type, key, then relation.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors.
    async fn list_references(
        &self,
        target: &RegistryTarget,
        relation: Option<&str>,
        after: Option<&ReferenceCursor>,
        limit: i64,
    ) -> Result<Vec<RegistryReference>, String>;
}

/// An answer and the revision it came from. `revision` is `None` when no
/// desired revision has been activated yet.
#[derive(Clone, Debug, PartialEq)]
pub struct Answered<T> {
    /// The active revision the answer was read at.
    pub revision: Option<ActiveRevision>,
    /// The answer.
    pub value: T,
}

/// The Registry read use cases.
#[derive(Clone, Debug)]
pub struct RegistryReadModel {
    cache: Arc<dyn RegistryCachePort>,
    source: Arc<dyn SourcePort>,
    builtins: Vec<BuiltinRegistryType>,
    fingerprint: String,
    /// Held across a rebuild (single-flight) and holding the last
    /// failure for [`FAILURE_MEMORY`].
    failure: Arc<tokio::sync::Mutex<Option<RebuildFailure>>>,
}

/// A remembered rebuild failure.
#[derive(Debug)]
struct RebuildFailure {
    revision: ActiveRevision,
    at: Instant,
    context: &'static str,
    detail: String,
}

fn backend(context: &'static str) -> impl Fn(String) -> ProjectUseCaseError {
    move |detail| ProjectUseCaseError::Backend { context, detail }
}

impl RegistryReadModel {
    /// Composes the read model over its cache and the desired source.
    #[must_use]
    pub fn new(cache: Arc<dyn RegistryCachePort>, source: Arc<dyn SourcePort>) -> Self {
        Self {
            cache,
            source,
            builtins: Vec::new(),
            fingerprint: fingerprint(&[]),
            failure: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Supplies the types Fleet ships. They appear in the type list and
    /// entries may use them; a repository type of the same name is
    /// ignored (the validator refuses it before activation anyway).
    #[must_use]
    pub fn with_builtin_types(mut self, builtins: Vec<BuiltinRegistryType>) -> Self {
        self.fingerprint = fingerprint(&builtins);
        self.builtins = builtins;
        self
    }

    /// Rebuilds the cache from the active revision's snapshot and returns
    /// that revision. Called after activation and rollback. Rebuilds are
    /// single-flight: concurrent callers queue behind one another.
    ///
    /// # Errors
    ///
    /// Fails when the backend errors or the revision is too large.
    pub async fn refresh(&self) -> Result<Option<ActiveRevision>, ProjectUseCaseError> {
        let mut failure = self.failure.lock().await;
        self.rebuild(&mut failure).await
    }

    /// One rebuild under the single-flight lock; records or clears the
    /// negative-cache entry.
    async fn rebuild(
        &self,
        failure: &mut Option<RebuildFailure>,
    ) -> Result<Option<ActiveRevision>, ProjectUseCaseError> {
        match self.derive_and_store().await {
            Ok(revision) => {
                *failure = None;
                Ok(revision)
            }
            Err((revision, error)) => {
                if let (Some(revision), ProjectUseCaseError::Backend { context, detail }) =
                    (revision, &error)
                {
                    *failure = Some(RebuildFailure {
                        revision,
                        at: Instant::now(),
                        context,
                        detail: detail.clone(),
                    });
                }
                Err(error)
            }
        }
    }

    async fn derive_and_store(
        &self,
    ) -> Result<Option<ActiveRevision>, (Option<ActiveRevision>, ProjectUseCaseError)> {
        // A concurrent activation can move the revision under a rebuild;
        // the store refuses the stale write and the loop re-reads.
        let mut last = None;
        for _ in 0..4 {
            let Some(revision) = self
                .source
                .active_revision()
                .await
                .map_err(|detail| (None, backend("registry_revision")(detail)))?
            else {
                return Ok(None);
            };
            last = Some(revision.clone());
            // The named revision's snapshot, never "the active" join: an
            // A to B to A flip between pages cannot mix revisions.
            let attempt = async {
                let types = self.read_kind(&revision, "RegistryType").await?;
                let entries = self.read_kind(&revision, "RegistryEntry").await?;
                let projection = derive(&self.builtins, &types, &entries);
                let state = CacheState {
                    revision: revision.clone(),
                    builtin_fingerprint: self.fingerprint.clone(),
                };
                self.cache
                    .replace_cache(&state, &projection)
                    .await
                    .map_err(backend("registry_rebuild"))
            }
            .await;
            match attempt {
                Ok(true) => return Ok(Some(revision)),
                Ok(false) => {}
                Err(error) => return Err((Some(revision), error)),
            }
        }
        Err((
            last,
            ProjectUseCaseError::Backend {
                context: "registry_rebuild",
                detail: "the active revision kept changing during the rebuild".to_owned(),
            },
        ))
    }

    async fn read_kind(
        &self,
        revision: &ActiveRevision,
        kind: &str,
    ) -> Result<Vec<DesiredResourceRecord>, ProjectUseCaseError> {
        let mut all = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = self
                .source
                .snapshot_resources(revision, Some(kind), after.as_deref(), REBUILD_PAGE)
                .await
                .map_err(backend("registry_snapshot"))?;
            let done = i64::try_from(page.len()).unwrap_or(i64::MAX) < REBUILD_PAGE;
            after = page.last().map(|resource| resource.id.clone());
            all.extend(page);
            if all.len() > REBUILD_MAX {
                return Err(ProjectUseCaseError::Backend {
                    context: "registry_snapshot",
                    detail: format!(
                        "the revision holds more than {REBUILD_MAX} {kind} resources, \
                         which the Registry read model refuses to cache"
                    ),
                });
            }
            if done || after.is_none() {
                return Ok(all);
            }
        }
    }

    async fn current(&self, active: &ActiveRevision) -> Result<bool, ProjectUseCaseError> {
        let state = self
            .cache
            .cache_state()
            .await
            .map_err(backend("registry_state"))?;
        Ok(state.is_some_and(|state| {
            state.revision == *active && state.builtin_fingerprint == self.fingerprint
        }))
    }

    /// The revision the cache serves, rebuilding when it is stale. The
    /// rebuild is single-flight, and a failed rebuild of a revision is
    /// remembered briefly so reads do not each repeat it.
    async fn fresh(&self) -> Result<Option<ActiveRevision>, ProjectUseCaseError> {
        let active = self
            .source
            .active_revision()
            .await
            .map_err(backend("registry_revision"))?;
        let Some(active) = active else {
            return Ok(None);
        };
        if self.current(&active).await? {
            return Ok(Some(active));
        }
        let mut failure = self.failure.lock().await;
        // Another reader may have rebuilt while this one waited.
        if self.current(&active).await? {
            return Ok(Some(active));
        }
        if let Some(known) = failure.as_ref()
            && known.revision == active
            && known.at.elapsed() < FAILURE_MEMORY
        {
            return Err(ProjectUseCaseError::Backend {
                context: known.context,
                detail: known.detail.clone(),
            });
        }
        self.rebuild(&mut failure).await
    }

    fn allow(authorizer: &dyn Authorizer, principal_id: &str) -> Result<(), ProjectUseCaseError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::RegistryRead,
                resource: None,
            },
        )
        .map(|_| ())
        .map_err(ProjectUseCaseError::Denied)
    }

    /// Lists the Registry types, built-in and repository-defined.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list_types(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
    ) -> Result<Answered<Vec<RegistryTypeRecord>>, ProjectUseCaseError> {
        Self::allow(authorizer, principal_id)?;
        let revision = self.fresh().await?;
        let value = if revision.is_some() {
            self.cache
                .list_types()
                .await
                .map_err(backend("registry_types"))?
        } else {
            Vec::new()
        };
        Ok(Answered { revision, value })
    }

    /// Lists entries matching the filter: up to `limit + 1` after the
    /// cursor, so the caller can tell whether more follow.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list_entries(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        filter: &RegistryEntryFilter,
        after: Option<&EntryCursor>,
        limit: i64,
    ) -> Result<Answered<Vec<RegistryEntryRecord>>, ProjectUseCaseError> {
        Self::allow(authorizer, principal_id)?;
        let revision = self.fresh().await?;
        let value = if revision.is_some() {
            self.cache
                .list_entries(filter, after, limit.saturating_add(1))
                .await
                .map_err(backend("registry_entries"))?
        } else {
            Vec::new()
        };
        Ok(Answered { revision, value })
    }

    /// Reads one entry by `<type>/<key>`.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown entry, or a backend failure.
    pub async fn get_entry(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        entry_type: &str,
        key: &str,
    ) -> Result<Answered<RegistryEntryRecord>, ProjectUseCaseError> {
        Self::allow(authorizer, principal_id)?;
        let revision = self.fresh().await?;
        let not_found = || ProjectUseCaseError::NotFound {
            what: "registry entry".to_owned(),
        };
        if revision.is_none() {
            return Err(not_found());
        }
        let entry = self
            .cache
            .get_entry(entry_type, key)
            .await
            .map_err(backend("registry_entry"))?
            .ok_or_else(not_found)?;
        Ok(Answered {
            revision,
            value: entry,
        })
    }

    /// Lists what points at a target (reverse relations): up to
    /// `limit + 1` after the cursor.
    ///
    /// # Errors
    ///
    /// Fails on denial or a backend failure.
    pub async fn list_references(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        target: &RegistryTarget,
        relation: Option<&str>,
        after: Option<&ReferenceCursor>,
        limit: i64,
    ) -> Result<Answered<Vec<RegistryReference>>, ProjectUseCaseError> {
        Self::allow(authorizer, principal_id)?;
        let revision = self.fresh().await?;
        let value = if revision.is_some() {
            self.cache
                .list_references(target, relation, after, limit.saturating_add(1))
                .await
                .map_err(backend("registry_references"))?
        } else {
            Vec::new()
        };
        Ok(Answered { revision, value })
    }
}

fn fingerprint(builtins: &[BuiltinRegistryType]) -> String {
    use std::fmt::Write as _;

    let mut sorted: Vec<&BuiltinRegistryType> = builtins.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut hasher = Sha256::new();
    for builtin in sorted {
        hasher.update(builtin.name.as_bytes());
        hasher.update([0]);
        hasher.update(builtin.spec.to_string().as_bytes());
        hasher.update([0]);
    }
    hasher
        .finalize()
        .iter()
        .fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

#[cfg(test)]
mod tests;
