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

use fleet_core::{CandidateDigest, SensitiveString};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The stable failure detail for a remote that needs a credential the
/// transport cannot use.
pub const CREDENTIAL_MISMATCH: &str = "the credential does not fit the remote's transport: an HTTPS token needs an https:// remote and an SSH key needs an ssh remote";

/// One Git credential, resolved just in time by the caller. The value
/// exists in the process only for the duration of a fetch and never in a
/// command line or environment.
#[derive(Debug)]
pub enum GitCredential {
    /// An HTTPS access token, presented through a `GIT_ASKPASS` helper.
    HttpsToken(SensitiveString),
    /// An SSH private key, presented through `GIT_SSH_COMMAND`.
    SshKey(SensitiveString),
}

impl GitCredential {
    /// Classifies a stored value: a PEM/OpenSSH private key block is an SSH
    /// key, anything else is an HTTPS token.
    #[must_use]
    pub fn from_secret_value(value: &str) -> Self {
        let value = value.trim();
        if value.starts_with("-----BEGIN ") {
            Self::SshKey(SensitiveString::new(value))
        } else {
            Self::HttpsToken(SensitiveString::new(value))
        }
    }

    fn fits(&self, remote: &str) -> bool {
        let lower = remote.to_ascii_lowercase();
        match self {
            Self::HttpsToken(_) => lower.starts_with("https://"),
            Self::SshKey(_) => {
                lower.starts_with("ssh://")
                    || (!lower.contains("://") && remote.contains('@') && remote.contains(':'))
            }
        }
    }
}

/// The short-lived credential material of one fetch: a private directory
/// holding the secret files, the environment that points git at them, and
/// the value to scrub from any output. Dropping it deletes the files.
#[derive(Debug)]
struct Auth {
    dir: Option<PathBuf>,
    env: Vec<(&'static str, OsString)>,
    config: Vec<String>,
    scrub: Option<String>,
}

impl Auth {
    /// No credential: git authenticates with the host's own configuration.
    fn none() -> Self {
        Self {
            dir: None,
            env: Vec::new(),
            config: Vec::new(),
            scrub: None,
        }
    }

    /// Writes the credential into a fresh 0700 directory under the work
    /// root (outside every worktree).
    fn prepare(work_root: &Path, credential: &GitCredential) -> Result<Self, String> {
        use std::io::Write as _;
        use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = format!(
            ".credential-{}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        );
        let dir = work_root.join(unique);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|error| format!("the credential directory could not be prepared: {error}"))?;
        // From here the directory is owned by `auth`, so every early return
        // deletes it.
        let mut auth = Self {
            dir: Some(dir.clone()),
            env: Vec::new(),
            config: Vec::new(),
            scrub: None,
        };
        let write = |name: &str, mode: u32, contents: &[u8]| -> Result<PathBuf, String> {
            let path = dir.join(name);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&path)
                .map_err(|error| format!("the credential file could not be written: {error}"))?;
            file.write_all(contents)
                .map_err(|error| format!("the credential file could not be written: {error}"))?;
            Ok(path)
        };
        match credential {
            GitCredential::HttpsToken(token) => {
                write("secret", 0o600, token.expose().as_bytes())?;
                let script = write("askpass", 0o700, ASKPASS_SCRIPT.as_bytes())?;
                auth.env.push(("GIT_ASKPASS", script.into_os_string()));
                // No other helper may store or supply the credential.
                auth.config.push("credential.helper=".to_owned());
                auth.scrub = Some(token.expose().to_owned());
            }
            GitCredential::SshKey(key) => {
                let mut body = key.expose().to_owned();
                if !body.ends_with('\n') {
                    body.push('\n');
                }
                let path = write("key", 0o600, body.as_bytes())?;
                let quoted = path.display().to_string().replace('\'', "'\\''");
                auth.env.push((
                    "GIT_SSH_COMMAND",
                    OsString::from(format!(
                        "ssh -i '{quoted}' -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes"
                    )),
                ));
                auth.scrub = Some(key.expose().to_owned());
            }
        }
        Ok(auth)
    }
}

/// The askpass helper: the username prompt gets a fixed placeholder (hosts
/// authenticate the token alone); every other prompt gets the secret file
/// beside the script.
const ASKPASS_SCRIPT: &str = "#!/bin/sh\ncase \"$1\" in\n  Username*) printf '%s\\n' git ;;\n  *) cat \"$(dirname \"$0\")/secret\" ;;\nesac\n";

impl Drop for Auth {
    fn drop(&mut self) {
        if let Some(dir) = self.dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

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
        self.git_with(arguments, &Auth::none())
    }

    /// Builds the git command: hooks disabled, prompts off, and the
    /// credential reaching git only through file paths in the environment.
    fn command(arguments: &[&str], auth: &Auth) -> Command {
        let mut command = Command::new("git");
        command
            .arg("-c")
            .arg("core.hooksPath=/nonexistent-fleet-hooks");
        for setting in &auth.config {
            command.arg("-c").arg(setting);
        }
        command.args(arguments).env("GIT_TERMINAL_PROMPT", "0");
        for (name, value) in &auth.env {
            command.env(name, value);
        }
        command
    }

    fn git_with(&self, arguments: &[&str], auth: &Auth) -> Result<String, String> {
        let _ = self;
        let mut command = Self::command(arguments, auth);
        let output = command
            .output()
            .map_err(|error| format!("git could not start: {error}"))?;
        if !output.status.success() {
            // The stderr is bounded and redacted: a credential-bearing
            // remote can echo its URL in a failure message.
            let mut stderr = fleet_core::redact_schemeless_credentials(
                &fleet_core::redact_url_credentials(&String::from_utf8_lossy(&output.stderr)),
            );
            if let Some(secret) = auth.scrub.as_deref().filter(|secret| !secret.is_empty()) {
                stderr = stderr.replace(secret, "[redacted]");
            }
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
        self.fetch_inner(remote, commit_sha, &Auth::none(), validate)
    }

    /// Fetches one candidate with a credential the caller resolved just in
    /// time. The secret reaches git only through 0600 files in a private
    /// directory that is deleted before this returns; it is never in argv,
    /// never in the environment, never in `.git/config`, and is scrubbed
    /// from failure output.
    ///
    /// # Errors
    ///
    /// Fails on a credential that does not fit the remote's transport, on
    /// transport errors, and when the credential files cannot be prepared.
    pub fn fetch_candidate_with(
        &self,
        remote: &str,
        commit_sha: &str,
        credential: &GitCredential,
        validate: impl FnOnce(&[PathBuf]) -> Vec<String>,
    ) -> Result<Candidate, String> {
        if !credential.fits(remote) {
            return Err(CREDENTIAL_MISMATCH.to_owned());
        }
        let auth = Auth::prepare(&self.work_root, credential)?;
        self.fetch_inner(remote, commit_sha, &auth, validate)
    }

    fn fetch_inner(
        &self,
        remote: &str,
        commit_sha: &str,
        auth: &Auth,
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
        self.git_with(
            &[
                "clone",
                "--quiet",
                "--no-recurse-submodules",
                // An option-looking remote must never reach git as a flag.
                "--",
                remote,
                worktree.to_str().unwrap_or_default(),
            ],
            auth,
        )?;
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

#[cfg(test)]
mod tests {
    use super::{Auth, CREDENTIAL_MISMATCH, GitCredential, GitSource};
    use fleet_core::SensitiveString;
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn scratch(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("fleet-git-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn credential_dirs(root: &Path) -> usize {
        std::fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".credential-")
            })
            .count()
    }

    #[test]
    fn an_option_looking_remote_is_never_run_as_a_git_flag() {
        let root = std::env::temp_dir().join(format!("fleet-git-flag-{}", std::process::id()));
        let marker = root.join("ran");
        let source = GitSource::new(root.clone());
        let remote = format!("--upload-pack=touch {}", marker.display());
        let result = source.fetch_candidate(&remote, &"a".repeat(40), |_| Vec::new());
        assert!(result.is_err(), "the remote is a path, not an option");
        assert!(!marker.exists(), "the option must not have executed");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_spawned_command_carries_paths_never_the_secret() {
        let root = scratch("argv");
        let token = "ghp_TOPSECRET_token_value";
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nTOPSECRETKEYBODY\n-----END OPENSSH PRIVATE KEY-----";
        for credential in [
            GitCredential::HttpsToken(SensitiveString::new(token)),
            GitCredential::SshKey(SensitiveString::new(key)),
        ] {
            let auth = Auth::prepare(&root, &credential).unwrap();
            let command = GitSource::command(&["clone", "--", "https://h/r.git", "/w"], &auth);
            let dump = format!(
                "{:?} {:?}",
                command.get_args().collect::<Vec<_>>(),
                command.get_envs().collect::<Vec<_>>()
            );
            assert!(!dump.contains("TOPSECRET"), "{dump}");
            // The secret files are private to the controller user.
            let dir = auth.dir.clone().unwrap();
            assert_eq!(
                std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for name in ["secret", "key"] {
                if let Ok(metadata) = std::fs::metadata(dir.join(name)) {
                    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
                }
            }
            drop(auth);
            assert!(!dir.exists(), "the credential directory is deleted");
        }
        assert_eq!(credential_dirs(&root), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_askpass_helper_answers_the_username_and_password_prompts() {
        let root = scratch("askpass");
        let auth = Auth::prepare(
            &root,
            &GitCredential::HttpsToken(SensitiveString::new("tok-123")),
        )
        .unwrap();
        let script = auth
            .env
            .iter()
            .find(|(name, _)| *name == "GIT_ASKPASS")
            .unwrap();
        let ask = |prompt: &str| {
            let out = Command::new(&script.1).arg(prompt).output().unwrap();
            String::from_utf8(out.stdout).unwrap()
        };
        assert_eq!(ask("Username for 'https://h': ").trim(), "git");
        assert_eq!(ask("Password for 'https://git@h': "), "tok-123");
        drop(auth);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_credential_that_does_not_fit_the_transport_is_refused_stably() {
        let root = scratch("mismatch");
        let source = GitSource::new(root.clone());
        let token = GitCredential::HttpsToken(SensitiveString::new("tok"));
        let key = GitCredential::SshKey(SensitiveString::new(
            "-----BEGIN X-----\nk\n-----END X-----",
        ));
        for (credential, remote) in [
            (&token, "ssh://git@h/r.git"),
            (&token, "git@h:r.git"),
            (&key, "https://h/r.git"),
        ] {
            let error = source
                .fetch_candidate_with(remote, &"a".repeat(40), credential, |_| Vec::new())
                .unwrap_err();
            assert_eq!(error, CREDENTIAL_MISMATCH);
        }
        assert_eq!(credential_dirs(&root), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    fn base64(input: &[u8]) -> String {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// Serves a bare repository over dumb HTTP, demanding Basic auth for
    /// `git:<token>`. Returns the repository URL.
    fn serve(bare: PathBuf, token: &str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected = format!("Basic {}", base64(format!("git:{token}").as_bytes()));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        break;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let path = head
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .split('?')
                    .next()
                    .unwrap_or("/")
                    .to_owned();
                let authorized = head.lines().any(|line| {
                    line.to_ascii_lowercase().starts_with("authorization:")
                        && line
                            .split_once(':')
                            .is_some_and(|(_, value)| value.trim() == expected)
                });
                let (status, body) = if authorized {
                    match std::fs::read(bare.join(path.trim_start_matches('/'))) {
                        Ok(body) => ("200 OK", body),
                        Err(_) => ("404 Not Found", Vec::new()),
                    }
                } else {
                    (
                        "401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"t\"",
                        Vec::new(),
                    )
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(&body);
            }
        });
        format!("http://127.0.0.1:{port}/")
    }

    fn run(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.test"])
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn a_token_authenticates_a_fetch_without_reaching_argv_config_or_errors() {
        let root = scratch("e2e");
        let origin = root.join("origin");
        std::fs::create_dir_all(&origin).unwrap();
        run(&origin, &["init", "-q"]);
        std::fs::write(origin.join("a.yaml"), "kind: x\n").unwrap();
        run(&origin, &["add", "."]);
        run(&origin, &["commit", "-q", "-m", "one"]);
        let sha = run(&origin, &["rev-parse", "HEAD"]);
        run(&root, &["clone", "-q", "--bare", "origin", "bare.git"]);
        run(&root.join("bare.git"), &["update-server-info"]);
        let token = "ghp_E2E_TOKEN_value_9f3";
        let remote = serve(root.join("bare.git"), token);

        let work = root.join("work");
        let source = GitSource::new(work.clone());
        let auth = Auth::prepare(
            &work,
            &GitCredential::HttpsToken(SensitiveString::new(token)),
        )
        .unwrap();
        let candidate = source
            .fetch_inner(&remote, &sha, &auth, |_| Vec::new())
            .expect("the token authenticates the clone");
        let config = std::fs::read_to_string(candidate.worktree.join(".git/config")).unwrap();
        assert!(!config.contains(token), "no credential in .git/config");
        drop(auth);
        assert_eq!(credential_dirs(&work), 0);

        // A wrong token fails with a redacted reason that names neither.
        let wrong = "ghp_WRONG_value_123";
        let auth = Auth::prepare(
            &work,
            &GitCredential::HttpsToken(SensitiveString::new(wrong)),
        )
        .unwrap();
        let error = source
            .fetch_inner(&remote, &sha, &auth, |_| Vec::new())
            .unwrap_err();
        assert!(!error.contains(wrong) && !error.contains(token), "{error}");
        // No credential at all is refused too (the host demands one).
        assert!(
            source
                .fetch_candidate(&remote, &sha, |_| Vec::new())
                .is_err()
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
