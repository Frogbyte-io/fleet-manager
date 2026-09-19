//! The Git source provider (FM-403): an isolated clone/worktree per
//! candidate, immutable candidates by SHA + content digest, and hooks
//! that never run.
//!
//! A Git repository becomes the canonical source of desired resources
//! only when validation gates activation. The provider clones a pinned
//! commit into an isolated directory (never shared with Fleet's runtime
//! state), records the candidate as (commit SHA + content digest), and
//! hands the file set to the schemas crate for validation. Every git
//! invocation passes `-c core.hooksPath=/nonexistent-fleet-hooks` — hook
//! execution is remote code execution by another name (the FM-301 rule).
//!
//! The provider runs git locally (the controller's own machine), not
//! over SSH: the desired repository is infrastructure, not a managed
//! machine's state.
#![warn(missing_docs)]

use fleet_core::CandidateDigest;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One candidate: the digest plus the isolated worktree path and the
/// diagnostics validation produced.
#[derive(Clone, Debug)]
pub struct Candidate {
    /// The candidate's digest.
    pub digest: CandidateDigest,
    /// The isolated worktree the candidate was materialized into.
    pub worktree: PathBuf,
    /// The validation diagnostics: empty means the candidate is valid and
    /// may be activated.
    pub diagnostics: Vec<String>,
}

impl Candidate {
    /// Whether the candidate may be activated.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.diagnostics.is_empty()
    }
}

/// The git transport: one isolated clone/worktree per candidate.
#[derive(Clone, Debug)]
pub struct GitSource {
    /// The root directory the provider materializes worktrees under.
    work_root: PathBuf,
}

impl GitSource {
    /// Composes the provider over a work root.
    ///
    /// # Panics
    ///
    /// Panics only if the work root cannot be prepared, which the
    /// controller's data-directory preparation already ensures.
    #[must_use]
    pub fn new(work_root: PathBuf) -> Self {
        std::fs::create_dir_all(&work_root).expect("the git work root must prepare");
        Self { work_root }
    }

    /// The work root.
    #[must_use]
    pub fn work_root(&self) -> &Path {
        &self.work_root
    }

    /// Runs one git command with hooks disabled; output is bounded by
    /// the caller's use.
    fn git(&self, arguments: &[&str]) -> Result<String, String> {
        let _ = self;
        let mut command = Command::new("git");
        command
            .arg("-c")
            .arg("core.hooksPath=/nonexistent-fleet-hooks")
            .args(arguments);
        let output = command
            .output()
            .map_err(|error| format!("git could not start: {error}"))?;
        if !output.status.success() {
            // The stderr is bounded and redacted: a credential-bearing
            // remote can echo its URL in a failure message.
            let stderr = fleet_core::redact_schemeless_credentials(
                &fleet_core::redact_url_credentials(&String::from_utf8_lossy(&output.stderr)),
            );
            let bounded = stderr.trim().chars().take(500).collect::<String>();
            return Err(format!(
                "git {} failed: {bounded}",
                arguments.first().unwrap_or(&"")
            ));
        }
        // The stdout is bounded: a large repository cannot consume
        // unbounded controller memory. A truncated listing would hash only
        // part of the file set, so oversized output is refused outright.
        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.stdout.len() > 1024 * 1024 {
            return Err(
                "the tracked file listing exceeds its 1 MiB bound; the candidate is refused rather than partially hashed".to_owned(),
            );
        }
        Ok(stdout.into_owned())
    }

    /// Fetches one candidate: clones the repository at the pinned commit
    /// into an isolated worktree, computes the digest, and returns the
    /// candidate with its validation diagnostics.
    ///
    /// # Errors
    ///
    /// Fails on transport errors (clone/checkout failures); a candidate
    /// whose validation fails is a valid return carrying diagnostics.
    pub fn fetch_candidate(
        &self,
        remote: &str,
        commit_sha: &str,
        validate: impl FnOnce(&[PathBuf]) -> Vec<String>,
    ) -> Result<Candidate, String> {
        // The SHA must be a full hexadecimal commit id: anything else
        // could escape the isolated work root through the path.
        if commit_sha.len() != 40
            || !commit_sha
                .chars()
                .all(|c| c.is_ascii_hexdigit() && c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return Err("the commit SHA must be a full 40-character hexadecimal id".to_owned());
        }
        // The worktree directory is named by the SHA: the same commit
        // materializes to the same isolated directory. An existing
        // directory is discarded and recreated — a stale or partial clone
        // must never be validated under the requested SHA.
        let worktree = self.work_root.join(format!("candidate-{commit_sha}"));
        if worktree.exists() {
            std::fs::remove_dir_all(&worktree)
                .map_err(|error| format!("the stale candidate could not be removed: {error}"))?;
        }
        self.git(&[
            "clone",
            "--quiet",
            "--no-recurse-submodules",
            remote,
            worktree.to_str().unwrap_or_default(),
        ])?;
        self.git(&[
            "-C",
            worktree.to_str().unwrap_or_default(),
            "checkout",
            "--quiet",
            "--detach",
            commit_sha,
        ])?;
        // Symlinks escape the isolated candidate: a repository carrying
        // one is refused before any file is read.
        reject_symlinks(&worktree)?;
        // The digest covers the tracked file set: paths + contents, so
        // two candidates are equal only when both the commit and the
        // content match.
        let content_digest = self.digest_worktree(&worktree)?;
        // Collect the YAML files for validation.
        let mut sources = Vec::new();
        collect_yaml(&worktree, &mut sources)?;
        let diagnostics = validate(&sources);
        Ok(Candidate {
            digest: CandidateDigest {
                commit_sha: commit_sha.to_owned(),
                content_digest,
            },
            worktree,
            diagnostics,
        })
    }

    /// Computes the SHA-256 of the tracked file set: sorted paths plus
    /// contents, hashed as one stream.
    /// Computes the digest of the tracked file set.
    ///
    /// # Errors
    ///
    /// Fails when a tracked file is unreadable.
    pub fn digest_worktree(&self, worktree: &Path) -> Result<String, String> {
        use sha2::Digest as _;
        let files = self.git(&["-C", worktree.to_str().unwrap_or_default(), "ls-files"])?;
        let mut hasher = sha2::Sha256::new();
        for path in files.lines() {
            hasher.update(path.as_bytes());
            hasher.update([0]);
            let contents = std::fs::read(worktree.join(path))
                .map_err(|error| format!("the candidate file {path} is unreadable: {error}"))?;
            hasher.update(&contents);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
}

/// Collects YAML files under a root, as relative paths.
fn collect_yaml(base: &Path, sources: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(base).map_err(|error| error.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            // Fleet's desired-state layout never descends into .git.
            if path.file_name().is_some_and(|name| name == ".git") {
                continue;
            }
            collect_yaml(&path, sources)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "yaml")
        {
            sources.push(path);
        }
    }
    Ok(())
}

/// Refuses a repository carrying symlinks: a symlink escapes the isolated
/// candidate and makes the digest dependent on controller filesystem
/// contents.
fn reject_symlinks(base: &Path) -> Result<(), String> {
    let entries = std::fs::read_dir(base).map_err(|error| error.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("the candidate file is unreadable: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "the candidate carries a symlink at {}; symlinks are refused so the digest stays confined to the clone",
                path.display()
            ));
        }
        if metadata.is_dir() && path.file_name().is_some_and(|name| name != ".git") {
            reject_symlinks(&path)?;
        }
    }
    Ok(())
}
