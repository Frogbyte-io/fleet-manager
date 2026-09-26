//! Fleet authored skill catalog content and immutable version primitives.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

/// Maximum total UTF-8 bytes accepted for one authored skill version.
pub const MAX_SKILL_CATALOG_BYTES: usize = 512 * 1024;
/// Maximum number of files accepted for one authored skill version.
pub const MAX_SKILL_CATALOG_FILES: usize = 64;

/// A skill source authored in Fleet or referenced from an external catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SkillCatalogSource {
    /// Content authored and versioned by Fleet.
    Authored,
    /// A third-party skills.sh or Git source, pinned where the source allows it.
    Referenced {
        /// A skills.sh reference or Git URL.
        reference: String,
        /// Optional path inside a Git repository.
        subpath: Option<String>,
        /// Optional immutable revision.
        revision: Option<String>,
    },
}

/// A path and UTF-8 text file in an authored Agent Skill.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillCatalogFile {
    /// Relative path below the skill directory.
    pub path: String,
    /// File contents.
    pub content: String,
}

/// Mutable catalog draft content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillCatalogContent {
    /// Stable Agent Skills name.
    pub name: String,
    /// Operator-facing description.
    pub description: String,
    /// Authored file set; empty for referenced sources.
    #[serde(default)]
    pub files: Vec<SkillCatalogFile>,
    /// Origin of this catalog entry.
    pub source: SkillCatalogSource,
}

impl SkillCatalogContent {
    /// Validates the catalog content and returns its deterministic SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the skill metadata, authored file set, or referenced
    /// source does not satisfy the catalog validation rules.
    pub fn validate_and_digest(&self) -> Result<String, String> {
        validate_skill_name(&self.name)?;
        if self.description.trim().is_empty() || self.description.chars().count() > 1024 {
            return Err("description must contain 1..=1024 characters".to_owned());
        }
        reject_secret_shaped_content(&self.description)?;
        match &self.source {
            SkillCatalogSource::Authored => {
                if self.files.is_empty() || self.files.len() > MAX_SKILL_CATALOG_FILES {
                    return Err(format!(
                        "authored skills must contain 1..={MAX_SKILL_CATALOG_FILES} files"
                    ));
                }
                let mut files = BTreeMap::new();
                let mut total = 0usize;
                for file in &self.files {
                    validate_relative_path(&file.path)?;
                    if files.insert(file.path.as_str(), &file.content).is_some() {
                        return Err(format!("duplicate file path {:?}", file.path));
                    }
                    total = total
                        .saturating_add(file.path.len())
                        .saturating_add(file.content.len());
                    reject_secret_shaped_content(&file.content)?;
                }
                if total > MAX_SKILL_CATALOG_BYTES {
                    return Err(format!(
                        "authored content exceeds {MAX_SKILL_CATALOG_BYTES} bytes"
                    ));
                }
                let skill_md = files
                    .get("SKILL.md")
                    .ok_or_else(|| "authored skills require SKILL.md at the root".to_owned())?;
                validate_skill_markdown(skill_md, &self.name, &self.description)?;
            }
            SkillCatalogSource::Referenced {
                reference,
                subpath,
                revision,
            } => validate_referenced_source(
                reference,
                subpath.as_deref(),
                revision.as_deref(),
                &self.files,
            )?,
        }
        let mut canonical_content = self.clone();
        canonical_content.files.sort_by(|a, b| a.path.cmp(&b.path));
        let canonical = serde_json::to_vec(&canonical_content)
            .map_err(|e| format!("cannot serialize skill content: {e}"))?;
        let digest = sha2::Sha256::digest(canonical);
        Ok(digest.iter().fold(String::with_capacity(64), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        }))
    }
}

fn validate_skill_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 64
        || name.starts_with('-')
        || name.ends_with('-')
        || name.contains("--")
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(
            "name must use 1..=64 lowercase letters, digits, and single hyphens".to_owned(),
        );
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 240
        || path.starts_with('/')
        || path.contains('\\')
        || path.bytes().any(|b| b.is_ascii_control())
    {
        return Err(format!("invalid relative skill path {path:?}"));
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
        || path.contains(':')
    {
        return Err(format!(
            "skill path must be normalized and remain within the skill directory: {path:?}"
        ));
    }
    Ok(())
}

fn validate_referenced_source(
    reference: &str,
    subpath: Option<&str>,
    revision: Option<&str>,
    files: &[SkillCatalogFile],
) -> Result<(), String> {
    if reference.trim().is_empty()
        || reference.len() > 2048
        || !reference.trim().is_ascii()
        || reference.trim_start().starts_with('-')
        || reference.chars().any(char::is_control)
    {
        return Err("referenced source must be a non-empty ASCII reference or URL".to_owned());
    }
    reject_secret_shaped_content(reference)?;
    if let Some(path) = subpath {
        validate_relative_path(path)?;
    }
    if revision
        .is_some_and(|rev| rev.is_empty() || rev.len() > 256 || rev.chars().any(char::is_control))
    {
        return Err("revision must be 1..=256 printable characters".to_owned());
    }
    if subpath.is_some() != revision.is_some() {
        return Err(
            "Git subpath and revision pins must be supplied together; Fleet does not guess a repository default branch".to_owned(),
        );
    }
    if let (Some(path), Some(revision)) = (subpath, revision) {
        validate_github_pin(reference, path, revision)?;
    }
    if files.is_empty() {
        Ok(())
    } else {
        Err("referenced entries cannot include authored files".to_owned())
    }
}

fn validate_github_pin(reference: &str, path: &str, revision: &str) -> Result<(), String> {
    let Some(repository) = reference.strip_prefix("https://github.com/") else {
        return Err(
            "separate subpath and revision pins currently require an HTTPS GitHub repository URL"
                .to_owned(),
        );
    };
    let repository = repository
        .strip_suffix(".git")
        .unwrap_or(repository)
        .trim_end_matches('/');
    let safe_component = |part: &str| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    };
    if repository.split('/').count() != 2
        || !repository.split('/').all(safe_component)
        || !revision
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        || !path.split('/').all(safe_component)
    {
        return Err(
            "GitHub subpath or revision contains unsupported URL path characters".to_owned(),
        );
    }
    Ok(())
}

fn validate_skill_markdown(markdown: &str, name: &str, description: &str) -> Result<(), String> {
    let mut lines = markdown.lines();
    if lines.next() != Some("---") {
        return Err("SKILL.md must begin with YAML frontmatter".to_owned());
    }
    let mut frontmatter_text = String::new();
    let mut closed = false;
    for line in lines.by_ref() {
        if line == "---" {
            closed = true;
            break;
        }
        frontmatter_text.push_str(line);
        frontmatter_text.push('\n');
    }
    if !closed {
        return Err("SKILL.md frontmatter is not terminated".to_owned());
    }
    let options = serde_saphyr::options! {
        duplicate_keys: serde_saphyr::options::DuplicateKeyPolicy::Error,
        merge_keys: serde_saphyr::options::MergeKeyPolicy::Error,
        budget: serde_saphyr::budget! {
            max_nodes: 2_000,
            max_anchors: 0,
            max_aliases: 0,
            max_depth: 16,
        },
    };
    let frontmatter: serde_json::Value =
        serde_saphyr::from_str_with_options(&frontmatter_text, options)
            .map_err(|_| "SKILL.md frontmatter must be valid YAML with unique keys".to_owned())?;
    let frontmatter = frontmatter
        .as_object()
        .ok_or_else(|| "SKILL.md frontmatter must be a YAML mapping".to_owned())?;
    if frontmatter.get("name").and_then(serde_json::Value::as_str) != Some(name) {
        return Err("SKILL.md frontmatter name must match the catalog name".to_owned());
    }
    if frontmatter
        .get("description")
        .and_then(serde_json::Value::as_str)
        != Some(description)
    {
        return Err(
            "SKILL.md frontmatter description must match the catalog description".to_owned(),
        );
    }
    Ok(())
}

fn reject_secret_shaped_content(content: &str) -> Result<(), String> {
    let lower = content.to_ascii_lowercase();
    let patterns = ["ghp_", "github_pat_", "xoxb-", "sk_live_"];
    let aws_key = content.match_indices("AKIA").any(|(index, _)| {
        let suffix = &content.as_bytes()[index + 4..];
        suffix.len() >= 16 && suffix[..16].iter().all(u8::is_ascii_alphanumeric)
    });
    let private_key = lower.contains("-----begin ") && lower.contains(" private key-----");
    if patterns.iter().any(|needle| lower.contains(needle)) || aws_key || private_key {
        return Err("authored content appears to contain a credential or private key".to_owned());
    }
    let query_credentials = content.split_whitespace().any(|token| {
        token
            .split(['?', '#'])
            .skip(1)
            .flat_map(|query| query.split('&'))
            .filter_map(|part| part.split_once('='))
            .any(|(key, value)| {
                !value.is_empty()
                    && [
                        "token",
                        "access_token",
                        "refresh_token",
                        "password",
                        "passwd",
                        "secret",
                        "client_secret",
                        "api_key",
                        "apikey",
                        "auth",
                        "signature",
                        "sig",
                        "credential",
                    ]
                    .contains(&key.to_ascii_lowercase().as_str())
            })
    });
    if query_credentials {
        return Err("catalog source contains a credential-bearing query parameter".to_owned());
    }
    if content.split_whitespace().any(|token| {
        token
            .split_once("://")
            .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
            .is_some_and(|authority| authority.contains('@'))
    }) {
        return Err("authored content appears to contain URL userinfo".to_owned());
    }
    for line in content.lines() {
        let line = line.trim().to_ascii_lowercase();
        if line.split_once(['=', ':']).is_some_and(|(key, value)| {
            [
                "password",
                "passwd",
                "secret",
                "api_key",
                "apikey",
                "access_token",
                "token",
            ]
            .iter()
            .any(|marker| key.contains(marker))
                && !value.trim().is_empty()
                && ![
                    "${...}",
                    "${token}",
                    "<redacted>",
                    "changeme",
                    "your-token",
                    "example",
                ]
                .contains(&value.trim())
        }) {
            return Err("authored content appears to contain a credential assignment".to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content(markdown: &str) -> SkillCatalogContent {
        SkillCatalogContent {
            name: "hello-world".into(),
            description: "Do useful work".into(),
            files: vec![SkillCatalogFile {
                path: "SKILL.md".into(),
                content: markdown.into(),
            }],
            source: SkillCatalogSource::Authored,
        }
    }

    #[test]
    fn authored_skill_validates_and_digest_is_order_independent() {
        let mut a = content("---\nname: hello-world\ndescription: Do useful work\n---\n# Hello\n");
        let mut b = a.clone();
        a.files.push(SkillCatalogFile {
            path: "references/guide.md".into(),
            content: "guide".into(),
        });
        b.files.push(SkillCatalogFile {
            path: "references/guide.md".into(),
            content: "guide".into(),
        });
        b.files.reverse();
        assert_eq!(
            a.validate_and_digest().unwrap(),
            b.validate_and_digest().unwrap()
        );
    }

    #[test]
    fn rejects_path_escape_secret_and_frontmatter_mismatch() {
        let mut bad = content("---\nname: hello-world\ndescription: Do useful work\n---\n");
        bad.files.push(SkillCatalogFile {
            path: "../oops".into(),
            content: String::new(),
        });
        assert!(bad.validate_and_digest().is_err());
        let mut bad = content("---\nname: hello-world\ndescription: Do useful work\n---\n");
        bad.files.push(SkillCatalogFile {
            path: "token.txt".into(),
            content: "password=cleartext".into(),
        });
        assert!(
            bad.validate_and_digest()
                .unwrap_err()
                .contains("credential")
        );
        assert!(
            content("---\nname: other\ndescription: Do useful work\n---\n")
                .validate_and_digest()
                .is_err()
        );
        assert!(
            content(
                "---\nname: hello-world\nname: hello-world\ndescription: Do useful work\n---\n"
            )
            .validate_and_digest()
            .is_err()
        );
        let mut credential_url =
            content("---\nname: hello-world\ndescription: Do useful work\n---\n");
        credential_url.files.push(SkillCatalogFile {
            path: "references/source.txt".into(),
            content: "https://operator:password@host.example/repo".into(),
        });
        assert!(
            credential_url
                .validate_and_digest()
                .unwrap_err()
                .contains("userinfo")
        );
    }

    #[test]
    fn referenced_sources_reject_options_controls_and_query_credentials() {
        let referenced = |reference: &str| SkillCatalogContent {
            name: "hello-world".into(),
            description: "Do useful work".into(),
            files: Vec::new(),
            source: SkillCatalogSource::Referenced {
                reference: reference.to_owned(),
                subpath: None,
                revision: None,
            },
        };
        assert!(referenced("--help").validate_and_digest().is_err());
        assert!(
            referenced("https://example.org/repo?token=secret")
                .validate_and_digest()
                .is_err()
        );
        assert!(
            referenced("https://example.org/repo?branch=stable")
                .validate_and_digest()
                .is_ok()
        );
        assert!(
            referenced("https://example.org/repo\n--help")
                .validate_and_digest()
                .is_err()
        );
    }
}
