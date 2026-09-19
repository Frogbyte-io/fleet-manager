//! The desired-source primitives (FM-403): the candidate digest shared
//! by the Git provider and the desired-source use cases.

use serde::{Deserialize, Serialize};

/// The digest of one candidate: the commit SHA plus the content digest of
/// its file set, so two candidates are equal only when both match.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateDigest {
    /// The commit SHA the candidate was fetched at.
    pub commit_sha: String,
    /// The SHA-256 of the candidate's tracked file set (paths + contents).
    pub content_digest: String,
}

impl CandidateDigest {
    /// Whether two digests describe the same candidate.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.commit_sha == other.commit_sha && self.content_digest == other.content_digest
    }
}
