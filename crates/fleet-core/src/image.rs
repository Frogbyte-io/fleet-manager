//! The image-recipe primitives (FM-700): the recipe content model, its
//! draft/version lifecycle, and the digest binding a build to the exact
//! bytes it was defined by.

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

/// The maximum recipe content Fleet accepts. A Packer template is bounded
/// configuration; anything larger is refused rather than materialized.
pub const MAX_RECIPE_CONTENT_BYTES: usize = 256 * 1024;

/// The source a recipe builds from.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeSource {
    /// Build from an ISO (the classic install flow).
    #[default]
    Iso,
    /// Build by cloning an existing guest.
    Clone,
}

impl RecipeSource {
    /// The stable string used in storage and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Iso => "iso",
            Self::Clone => "clone",
        }
    }

    /// Parses the stable string.
    ///
    /// # Errors
    ///
    /// Fails on an unrecognized source id.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "iso" => Ok(Self::Iso),
            "clone" => Ok(Self::Clone),
            other => Err(format!("unrecognized recipe source {other:?}")),
        }
    }
}

/// One image recipe: the Fleet metadata plus the raw `.pkr.json` content
/// stored verbatim. Packer's own fields are not re-validated by Fleet —
/// `packer validate` is the authority, and unknown fields pass through
/// untouched.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipeContent {
    /// The operator-facing recipe name.
    pub name: String,
    /// The operator-facing description.
    pub description: String,
    /// The PVE node the recipe builds on.
    pub node: String,
    /// The PVE storage pool the build writes to.
    pub storage_pool: String,
    /// What the recipe builds from.
    pub source: RecipeSource,
    /// The raw Packer template content (`.pkr.json`/`.pkr.hcl`), stored
    /// verbatim. Unknown fields are Fleet's problem never to touch.
    pub content: String,
}

impl RecipeContent {
    /// The SHA-256 digest of the recipe's bytes: the identity a build
    /// references, so a build of a since-edited recipe is reproducible.
    ///
    /// # Errors
    ///
    /// Fails when the content exceeds the bound.
    pub fn content_digest(&self) -> Result<String, String> {
        if self.content.len() > MAX_RECIPE_CONTENT_BYTES {
            return Err(format!(
                "the recipe content is {} bytes, over the {MAX_RECIPE_CONTENT_BYTES}-byte bound",
                self.content.len()
            ));
        }
        // The digest covers every build-affecting field: the Packer bytes
        // AND the Fleet metadata (node, pool, source), so a metadata-only
        // edit produces a new version instead of silently reusing one.
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.content.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.node.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.storage_pool.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.source.id().as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        Ok(digest.iter().fold(String::with_capacity(64), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        }))
    }

    /// Validates the Fleet-owned metadata. Packer's own fields are the
    /// CLI's authority, not Fleet's.
    ///
    /// # Errors
    ///
    /// Fails on a malformed field.
    pub fn validate(&self) -> Result<(), String> {
        let count = self.name.chars().count();
        if count == 0 || count > 128 {
            return Err("the name must be 1..=128 characters".to_owned());
        }
        if self.description.chars().count() > 512 {
            return Err("the description must be at most 512 characters".to_owned());
        }
        for (label, value) in [("node", &self.node), ("storage_pool", &self.storage_pool)] {
            let len = value.chars().count();
            if len == 0 || len > 128 {
                return Err(format!("the {label} must be 1..=128 characters"));
            }
        }
        if self.content.is_empty() {
            return Err("the recipe content must not be empty".to_owned());
        }
        self.content_digest()?;
        Ok(())
    }
}

/// A published recipe version: immutable, identified by its digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipeVersion {
    /// The version's identity: the recipe it came from plus the content
    /// digest, so the same content published twice is the same version.
    pub id: String,
    /// The recipe the version came from.
    pub recipe_id: String,
    /// The recipe name at publication time.
    pub name: String,
    /// The frozen content digest.
    pub content_digest: String,
    /// The frozen description.
    pub description: String,
    /// The frozen content.
    pub content: String,
    /// The source at publication time.
    pub source: RecipeSource,
    /// The node at publication time.
    pub node: String,
    /// The storage pool at publication time.
    pub storage_pool: String,
    /// When the version was published (epoch millis).
    pub published_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipe(content: &str) -> RecipeContent {
        RecipeContent {
            name: "ubuntu-base".to_owned(),
            description: "the base image".to_owned(),
            node: "pve".to_owned(),
            storage_pool: "local-lvm".to_owned(),
            source: RecipeSource::Iso,
            content: content.to_owned(),
        }
    }

    #[test]
    fn digests_are_stable_and_content_sensitive() {
        let a = recipe("{\"builders\":[]}");
        let b = recipe("{\"builders\":[]}");
        let c = recipe("{\"builders\":[{}]}");
        assert_eq!(a.content_digest().unwrap(), b.content_digest().unwrap());
        assert_ne!(a.content_digest().unwrap(), c.content_digest().unwrap());
    }

    #[test]
    fn validation_refuses_malformed_metadata_and_oversized_content() {
        let mut bad = recipe("{}");
        bad.name = String::new();
        assert!(bad.validate().is_err());
        bad.name = "ok".to_owned();
        bad.node = String::new();
        assert!(bad.validate().is_err());
        bad.node = "pve".to_owned();
        bad.content = "x".repeat(MAX_RECIPE_CONTENT_BYTES + 1);
        assert!(bad.validate().is_err());
        assert!(recipe("{}").validate().is_ok());
    }

    #[test]
    fn sources_round_trip_their_ids() {
        for id in ["iso", "clone"] {
            let source = RecipeSource::from_id(id).unwrap();
            assert_eq!(source.id(), id);
        }
        assert!(RecipeSource::from_id("mystery").is_err());
    }
}
