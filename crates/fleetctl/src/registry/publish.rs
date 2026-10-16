//! `fleetctl registry publish`: commit the Registry changes of a checkout
//! and either push them to the default branch or open a pull request,
//! following the controller's `registry.changeMode`.
//!
//! Git and `gh` are run as argument arrays, never through a shell, and no
//! token is read, passed, or printed: authentication is whatever the
//! operator's Git and `gh` already have. `GIT_TERMINAL_PROMPT=0` keeps a
//! missing credential from hanging an agent.

use std::{
    path::Path,
    process::{Command, Stdio},
};

use serde_json::{Value, json};

use super::tree::{self, REGISTRY_DIR};
use crate::CliError;

/// How a publish reaches the default branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeMode {
    /// Push to the default branch.
    Direct,
    /// Push a branch and open a pull request.
    PullRequest,
}

impl ChangeMode {
    /// Parses the setting's value.
    ///
    /// # Errors
    ///
    /// Fails for anything but `direct` or `pull-request`.
    pub fn parse(text: &str) -> Result<Self, CliError> {
        match text {
            "direct" => Ok(Self::Direct),
            "pull-request" => Ok(Self::PullRequest),
            _ => Err(CliError {
                message: "the change mode must be direct or pull-request".to_owned(),
            }),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::PullRequest => "pull-request",
        }
    }
}

/// What `publish` was asked to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PublishRequest {
    /// The commit message.
    pub message: String,
    /// The mode, when the caller overrides the controller's setting.
    pub change_mode: Option<ChangeMode>,
    /// The default branch, when it cannot be read from `origin/HEAD`.
    pub base: Option<String>,
    /// The pull request branch, instead of a generated one.
    pub branch: Option<String>,
}

/// Runs one Git command in the checkout and returns its stdout.
fn git(root: &Path, args: &[&str]) -> Result<String, CliError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("--literal-pathspecs")
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| CliError {
            message: format!("git could not be run: {error}"),
        })?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(CliError {
            message: format!(
                "git {} failed: {}",
                args.first().copied().unwrap_or(""),
                first_line(&String::from_utf8_lossy(&output.stderr))
            ),
        })
    }
}

/// Runs Git and reports only whether it succeeded.
fn git_ok(root: &Path, args: &[&str]) -> bool {
    git(root, args).is_ok()
}

fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map_or_else(
            || "no detail".to_owned(),
            |line| line.chars().filter(|c| !c.is_control()).take(300).collect(),
        )
}

/// One entry of `git status --porcelain=v1 -z`.
#[derive(Debug)]
struct StatusEntry {
    index: char,
    worktree: char,
    path: String,
    /// The origin of a rename or copy.
    from: Option<String>,
}

fn status(root: &Path) -> Result<Vec<StatusEntry>, CliError> {
    let raw = git(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    let mut parts = raw.split('\0').filter(|part| !part.is_empty());
    let mut entries = Vec::new();
    while let Some(part) = parts.next() {
        let mut chars = part.chars();
        let (Some(index), Some(worktree)) = (chars.next(), chars.next()) else {
            continue;
        };
        let path = part.get(3..).unwrap_or_default().to_owned();
        let from = if matches!(index, 'R' | 'C') || matches!(worktree, 'R' | 'C') {
            parts.next().map(str::to_owned)
        } else {
            None
        };
        entries.push(StatusEntry {
            index,
            worktree,
            path,
            from,
        });
    }
    Ok(entries)
}

/// Whether a changed path is Registry content: anything under
/// `fleet/registry/`, or a `.yaml` file whose documents are all Registry
/// kinds (the controller's own rule for a Registry-only change).
fn is_registry_path(root: &Path, path: &str, deleted: bool) -> bool {
    if path.starts_with(&format!("{REGISTRY_DIR}/")) {
        return true;
    }
    if Path::new(path)
        .extension()
        .is_none_or(|extension| extension != "yaml")
    {
        return false;
    }
    let text = if deleted {
        git(root, &["show", &format!("HEAD:{path}")]).ok()
    } else {
        std::fs::read_to_string(root.join(path)).ok()
    };
    text.and_then(|text| fleet_schema::document_kinds(&text).ok())
        .is_some_and(|kinds| {
            !kinds.is_empty()
                && kinds
                    .iter()
                    .all(|kind| matches!(kind.as_str(), "RegistryType" | "RegistryEntry"))
        })
}

fn default_branch(root: &Path, base: Option<&str>) -> Result<String, CliError> {
    if let Some(base) = base {
        return Ok(base.to_owned());
    }
    let head = git(root, &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"]).map_err(|_| CliError {
        message: "the default branch is unknown (origin/HEAD is not set); pass --base <branch>, or run `git remote set-head origin --auto`".to_owned(),
    })?;
    Ok(head
        .trim()
        .strip_prefix("origin/")
        .unwrap_or(head.trim())
        .to_owned())
}

/// Removes any user information from a remote URL and turns an SSH or HTTPS
/// remote into its web address, or `None` for anything else (a local path).
fn web_address(remote: &str) -> Option<String> {
    let remote = remote.trim();
    let (host, path) = if let Some(rest) = remote
        .strip_prefix("https://")
        .or_else(|| remote.strip_prefix("http://"))
        .or_else(|| remote.strip_prefix("ssh://"))
        .or_else(|| remote.strip_prefix("git://"))
    {
        let (authority, path) = rest.split_once('/')?;
        let host = authority.rsplit('@').next()?;
        // Drop a port: it is the SSH or Git port, not the web port.
        (host.split(':').next()?.to_owned(), path.to_owned())
    } else if let Some((authority, path)) = remote.split_once(':')
        && !remote.contains("://")
        && !authority.contains('/')
    {
        // scp-style `git@host:owner/repo.git`.
        (authority.rsplit('@').next()?.to_owned(), path.to_owned())
    } else {
        return None;
    };
    let path = path.trim_matches('/').trim_end_matches(".git");
    (!host.is_empty() && !path.is_empty() && path.split('/').count() >= 2)
        .then(|| format!("https://{host}/{path}"))
}

fn encode(segment: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// The compare URL of a branch, when the remote has a web address.
fn compare_url(root: &Path, base: &str, branch: &str) -> Option<String> {
    let remote = git(root, &["remote", "get-url", "origin"]).ok()?;
    let address = web_address(&remote)?;
    Some(format!(
        "{address}/compare/{}...{}?expand=1",
        encode(base),
        encode(branch)
    ))
}

fn branch_slug(message: &str) -> String {
    let mut slug = String::new();
    for c in message.chars().take(40) {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            slug.push(c);
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "update".to_owned()
    } else {
        slug.to_owned()
    }
}

/// Opens a pull request with `gh`. `Ok(None)` when `gh` is not installed.
fn open_pull_request(
    root: &Path,
    base: &str,
    branch: &str,
    subject: &str,
    body: &str,
) -> Result<Option<String>, CliError> {
    let output = Command::new("gh")
        .current_dir(root)
        .args([
            "pr", "create", "--base", base, "--head", branch, "--title", subject, "--body", body,
        ])
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output();
    let output = match output {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CliError {
                message: format!("gh could not be run: {error}"),
            });
        }
    };
    if !output.status.success() {
        return Err(CliError {
            message: format!(
                "gh pr create failed: {}",
                first_line(&String::from_utf8_lossy(&output.stderr))
            ),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let url = stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| line.starts_with("https://") || line.starts_with("http://"))
        .map(str::to_owned);
    Ok(Some(url.unwrap_or_default()))
}

/// Publishes the Registry changes of the checkout at `root`.
#[allow(clippy::too_many_lines)]
pub(super) fn publish(
    root: &Path,
    request: &PublishRequest,
    mode_from_controller: impl FnOnce() -> Result<ChangeMode, CliError>,
) -> Result<Value, CliError> {
    let message = request.message.trim();
    if message.is_empty() {
        return Err(CliError {
            message: "publish needs a commit message: -m <message>".to_owned(),
        });
    }

    // 1. Never publish an invalid tree.
    let files = tree::load(root)?;
    let report = tree::validate(&files);
    if !report.errors.is_empty() {
        return Err(CliError {
            message: format!(
                "refusing to publish: the tree has {} validation error(s)\n  {}",
                report.errors.len(),
                report
                    .errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n  ")
            ),
        });
    }

    // 2. Split the working tree into Registry changes and everything else.
    let entries = status(root)?;
    let mut registry_paths: Vec<String> = Vec::new();
    let mut unrelated_staged: Vec<String> = Vec::new();
    for entry in &entries {
        let staged = entry.index != ' ' && entry.index != '?' && entry.index != '!';
        let deleted = entry.worktree == 'D' || entry.index == 'D';
        let paths = std::iter::once(&entry.path).chain(entry.from.iter());
        for path in paths {
            if is_registry_path(root, path, deleted || entry.from.as_ref() == Some(path)) {
                registry_paths.push(path.clone());
            } else if staged {
                unrelated_staged.push(path.clone());
            }
        }
    }
    if !unrelated_staged.is_empty() {
        unrelated_staged.sort();
        unrelated_staged.dedup();
        let shown: Vec<&str> = unrelated_staged
            .iter()
            .take(10)
            .map(String::as_str)
            .collect();
        return Err(CliError {
            message: format!(
                "refusing to publish: {} staged change(s) are not Registry content ({}{}); unstage them with `git restore --staged` or commit them separately",
                unrelated_staged.len(),
                shown.join(", "),
                if unrelated_staged.len() > shown.len() {
                    ", ..."
                } else {
                    ""
                }
            ),
        });
    }
    registry_paths.sort();
    registry_paths.dedup();
    if registry_paths.is_empty() {
        return Ok(json!({
            "published": false,
            "reason": "there are no Registry changes to publish",
        }));
    }

    // 3. Mode, branches.
    let mode = match request.change_mode {
        Some(mode) => mode,
        None => mode_from_controller()?,
    };
    let base = default_branch(root, request.base.as_deref())?;
    let current = git(root, &["symbolic-ref", "--short", "-q", "HEAD"])
        .map(|name| name.trim().to_owned())
        .map_err(|_| CliError {
            message: "HEAD is detached; check out a branch first".to_owned(),
        })?;
    if let Some(branch) = &request.branch
        && !git_ok(root, &["check-ref-format", "--branch", branch])
    {
        return Err(CliError {
            message: "--branch is not a valid branch name".to_owned(),
        });
    }
    if mode == ChangeMode::Direct && current != base {
        return Err(CliError {
            message: format!(
                "direct mode publishes to {base}, but the checkout is on {current}; switch to {base}, or publish with --change-mode pull-request"
            ),
        });
    }

    // 4. Commit exactly the Registry paths.
    let mut branch = current.clone();
    if mode == ChangeMode::PullRequest && (current == base || request.branch.is_some()) {
        branch = request.branch.clone().unwrap_or_else(|| {
            let id = uuid::Uuid::now_v7().simple().to_string();
            format!("registry/{}-{}", branch_slug(message), &id[id.len() - 8..])
        });
        if branch != current {
            git(root, &["checkout", "-b", &branch])?;
        }
    }
    let mut add: Vec<&str> = vec!["add", "-A", "--"];
    add.extend(registry_paths.iter().map(String::as_str));
    git(root, &add)?;
    let mut commit: Vec<&str> = vec!["commit", "-m", message, "--"];
    commit.extend(registry_paths.iter().map(String::as_str));
    git(root, &commit)?;
    let commit_sha = git(root, &["rev-parse", "HEAD"])?.trim().to_owned();

    // 5. Push, then open the pull request.
    let mut result = json!({
        "published": true,
        "mode": mode.name(),
        "base": base,
        "branch": branch,
        "commit": commit_sha,
        "paths": registry_paths,
        "pullRequest": Value::Null,
        "compareUrl": Value::Null,
    });
    match mode {
        ChangeMode::Direct => {
            git(
                root,
                &["push", "origin", &format!("HEAD:refs/heads/{base}")],
            )?;
        }
        ChangeMode::PullRequest => {
            git(
                root,
                &[
                    "push",
                    "--set-upstream",
                    "origin",
                    &format!("HEAD:refs/heads/{branch}"),
                ],
            )?;
            let compare = compare_url(root, &base, &branch);
            let (subject, rest) = message.split_once('\n').unwrap_or((message, ""));
            let body = if rest.trim().is_empty() {
                "Registry change published with `fleetctl registry publish`.".to_owned()
            } else {
                rest.trim().to_owned()
            };
            match open_pull_request(root, &base, &branch, subject.trim(), &body) {
                Ok(Some(url)) if !url.is_empty() => result["pullRequest"] = Value::String(url),
                Ok(Some(_) | None) => {}
                Err(error) => {
                    return Err(CliError {
                        message: format!(
                            "the branch {branch} was pushed, but the pull request was not opened: {}{}",
                            error.message,
                            compare
                                .as_ref()
                                .map_or(String::new(), |url| format!("\nopen it from {url}"))
                        ),
                    });
                }
            }
            result["compareUrl"] = compare.map_or(Value::Null, Value::String);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remotes_become_web_addresses_without_credentials() {
        for (remote, expected) in [
            ("https://github.com/o/r.git", Some("https://github.com/o/r")),
            (
                "https://user:tok3n@github.com/o/r.git",
                Some("https://github.com/o/r"),
            ),
            ("git@github.com:o/r.git", Some("https://github.com/o/r")),
            (
                "ssh://git@git.example.com:2222/o/r.git",
                Some("https://git.example.com/o/r"),
            ),
            ("/srv/git/r.git", None),
            ("../relative.git", None),
        ] {
            assert_eq!(web_address(remote).as_deref(), expected, "{remote}");
        }
    }

    #[test]
    fn branch_names_are_slugs() {
        assert_eq!(
            branch_slug("example.com DNS moved to Cloudflare!"),
            "example-com-dns-moved-to-cloudflare"
        );
        assert_eq!(branch_slug("!!!"), "update");
    }
}
