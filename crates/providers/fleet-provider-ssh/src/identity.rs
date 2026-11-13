//! The controller's own SSH identity: the default key `--auth agent` falls
//! back to when no agent supplies one.
//!
//! OpenSSH finds the default identities (`~/.ssh/id_ed25519` and friends)
//! under the **passwd** home directory of the process uid, not `$HOME`. In
//! the controller image the two differ: the entrypoint drops root with
//! `setpriv`, which keeps root's `HOME=/root`, while the `fleet` user's home
//! is the data volume. [`ControllerIdentity::for_current_user`] therefore
//! resolves the home the way `ssh` does (`getent passwd <uid>`), and only
//! falls back to `$HOME` when the account database has no entry.
//!
//! Nothing here reads the private key into this process. A key is checked
//! for the problems `ssh` would hit (unreadable, permissions too open,
//! passphrase-protected), and its public half comes from `ssh-keygen -y`,
//! which proves the key is usable by this uid. Generation runs `ssh-keygen`
//! straight into the target path, never over an existing file.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The default identity file names, in the order `ssh` offers them
/// (`ssh_config(5)`, `IdentityFile`).
pub const DEFAULT_IDENTITY_NAMES: &[&str] = &[
    "id_rsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519",
    "id_ed25519_sk",
    "id_xmss",
    "id_dsa",
];

/// The file a generated identity is written to, under the `.ssh` directory.
pub const GENERATED_IDENTITY_NAME: &str = "id_ed25519";

/// The controller's usable identity, as published.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedIdentity {
    /// The private key file (its path only; the content is never read).
    pub path: PathBuf,
    /// The OpenSSH public key line.
    pub public_key: String,
    /// The key type, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// The `SHA256:` fingerprint.
    pub fingerprint: String,
}

/// What the controller's default identity looks like right now.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityState {
    /// A usable default identity.
    Present(PublishedIdentity),
    /// No default identity file exists.
    None {
        /// The `.ssh` directory that was searched.
        ssh_dir: PathBuf,
    },
    /// A default identity exists, but `ssh` cannot use it.
    Unusable {
        /// The offending file or directory.
        path: PathBuf,
        /// What is wrong and how to fix it. Never contains key material.
        detail: String,
    },
}

/// The outcome of [`ControllerIdentity::ensure`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnsureOutcome {
    /// A new key was generated.
    Generated(PublishedIdentity),
    /// Generation was not needed or not allowed; this is what exists.
    Existing(IdentityState),
}

/// The controller user's `.ssh` directory and the operations on it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerIdentity {
    ssh_dir: PathBuf,
}

impl ControllerIdentity {
    /// The identity directory of the process user, resolved as `ssh` does.
    ///
    /// # Errors
    ///
    /// Fails when neither the account database nor `$HOME` names a home.
    pub fn for_current_user() -> Result<Self, String> {
        let home = passwd_home()
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .filter(|home| home.is_absolute())
            .ok_or_else(|| {
                "the controller user has no home directory (no passwd entry and no absolute $HOME)"
                    .to_owned()
            })?;
        Ok(Self::at(home.join(".ssh")))
    }

    /// An identity directory at an explicit path (tests, tools).
    #[must_use]
    pub fn at(ssh_dir: impl Into<PathBuf>) -> Self {
        Self {
            ssh_dir: ssh_dir.into(),
        }
    }

    /// The `.ssh` directory.
    #[must_use]
    pub fn ssh_dir(&self) -> &Path {
        &self.ssh_dir
    }

    /// Finds the first default identity `ssh` would offer and reports
    /// whether it is usable.
    #[must_use]
    pub fn inspect(&self) -> IdentityState {
        match std::fs::metadata(&self.ssh_dir) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return IdentityState::None {
                    ssh_dir: self.ssh_dir.clone(),
                };
            }
            Err(error) => {
                return IdentityState::Unusable {
                    path: self.ssh_dir.clone(),
                    detail: format!(
                        "the controller user cannot read its SSH directory ({error}); {}",
                        ownership_fix(&self.ssh_dir)
                    ),
                };
            }
        }
        // `ssh` tries every default identity in order and authenticates with
        // the first one that works, so a broken file must not hide a usable
        // one after it: the first usable key wins, and the first problem is
        // reported only when no key is usable.
        let mut first_problem: Option<IdentityState> = None;
        for name in DEFAULT_IDENTITY_NAMES {
            let path = self.ssh_dir.join(name);
            let state = match std::fs::metadata(&path) {
                Ok(metadata) => inspect_key(&path, &metadata),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => IdentityState::Unusable {
                    detail: format!(
                        "the controller user cannot inspect {} ({error}); {}",
                        path.display(),
                        ownership_fix(&self.ssh_dir)
                    ),
                    path,
                },
            };
            match state {
                IdentityState::Present(_) => return state,
                problem => {
                    first_problem.get_or_insert(problem);
                }
            }
        }
        first_problem.unwrap_or_else(|| IdentityState::None {
            ssh_dir: self.ssh_dir.clone(),
        })
    }

    /// Generates `id_ed25519` when there is no default identity and
    /// `generate` allows it; otherwise reports what exists. An existing key,
    /// usable or not, is never touched.
    ///
    /// # Errors
    ///
    /// Fails, without key material, when the directory cannot be prepared
    /// or `ssh-keygen` fails.
    pub fn ensure(&self, generate: bool, comment: &str) -> Result<EnsureOutcome, String> {
        let state = self.inspect();
        if !generate || !matches!(state, IdentityState::None { .. }) {
            return Ok(EnsureOutcome::Existing(state));
        }
        self.prepare_dir()?;
        let path = self.ssh_dir.join(GENERATED_IDENTITY_NAME);
        // `inspect` saw no default identity; a stray public half from an
        // earlier failed run would make ssh-keygen prompt, so it goes.
        let public = public_path(&path);
        if std::fs::symlink_metadata(&path).is_ok() {
            return Ok(EnsureOutcome::Existing(self.inspect()));
        }
        let _ = std::fs::remove_file(&public);
        let comment = sanitize_comment(comment);
        let output = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", &comment, "-f"])
            .arg(&path)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("cannot run ssh-keygen: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "ssh-keygen could not generate {}: {}",
                path.display(),
                first_line(&String::from_utf8_lossy(&output.stderr))
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("cannot restrict {}: {error}", path.display()))?;
        }
        match self.inspect() {
            IdentityState::Present(identity) => Ok(EnsureOutcome::Generated(identity)),
            IdentityState::Unusable { detail, .. } => {
                Err(format!("the generated key is not usable: {detail}"))
            }
            IdentityState::None { .. } => {
                Err("ssh-keygen reported success but wrote no key".to_owned())
            }
        }
    }

    /// Creates the `.ssh` directory owner-only (0700).
    fn prepare_dir(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.ssh_dir)
            .map_err(|error| format!("cannot create {}: {error}", self.ssh_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&self.ssh_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("cannot restrict {}: {error}", self.ssh_dir.display()))?;
        }
        Ok(())
    }
}

/// Checks one existing key file the way `ssh` will use it.
fn inspect_key(path: &Path, metadata: &std::fs::Metadata) -> IdentityState {
    let unusable = |detail: String| IdentityState::Unusable {
        path: path.to_path_buf(),
        detail,
    };
    if !metadata.is_file() {
        return unusable(format!("{} is not a regular file", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let uid = rustix::process::getuid().as_raw();
        let mode = metadata.mode() & 0o777;
        if metadata.uid() == uid && mode & 0o077 != 0 {
            return unusable(format!(
                "{} is accessible by other users (mode {mode:03o}), and ssh refuses such a key; run `chmod 600 {}`",
                path.display(),
                path.display()
            ));
        }
    }
    if let Err(error) = std::fs::File::open(path) {
        return unusable(format!(
            "the controller user cannot read {} ({error}); {}",
            path.display(),
            ownership_fix(path.parent().unwrap_or(path))
        ));
    }
    // `-P ''` makes a passphrase-protected key fail instead of prompting.
    let output = Command::new("ssh-keygen")
        .args(["-y", "-P", "", "-f"])
        .arg(path)
        .stdin(Stdio::null())
        .output();
    let output = match output {
        Ok(output) => output,
        Err(error) => return unusable(format!("cannot run ssh-keygen: {error}")),
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        return unusable(if stderr.contains("passphrase") {
            format!(
                "{} is passphrase-protected; the controller connects non-interactively and cannot use it",
                path.display()
            )
        } else {
            format!("{} is not a usable private key", path.display())
        });
    }
    let line = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    match fleet_core::parse_public_key(&line) {
        Ok(key) => {
            // `ssh-keygen -y` omits the comment for some formats; the
            // `.pub` file beside the key keeps it when it is the same key.
            let public_key = std::fs::read_to_string(public_path(path))
                .ok()
                .and_then(|text| fleet_core::parse_public_key(&text).ok())
                .filter(|written| written.same_key(&key))
                .map_or_else(|| key.line(), |written| written.line());
            IdentityState::Present(PublishedIdentity {
                path: path.to_path_buf(),
                public_key,
                key_type: key.key_type,
                fingerprint: key.fingerprint,
            })
        }
        Err(detail) => unusable(format!(
            "ssh-keygen printed no usable public key for {}: {detail}",
            path.display()
        )),
    }
}

/// The fix for an SSH directory the controller user cannot read: own it.
/// `ssh_dir` is the `.ssh` directory itself, never its parent: the home is
/// the controller's data volume, which must not be re-owned wholesale.
fn ownership_fix(ssh_dir: &Path) -> String {
    #[cfg(unix)]
    {
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        format!(
            "it must belong to the controller user (uid {uid}): `chown -R {uid}:{gid} {}`",
            ssh_dir.display()
        )
    }
    #[cfg(not(unix))]
    {
        format!(
            "it must belong to the controller user: fix the owner of {}",
            ssh_dir.display()
        )
    }
}

/// `<key>.pub`.
fn public_path(path: &Path) -> PathBuf {
    let mut public = path.as_os_str().to_owned();
    public.push(".pub");
    PathBuf::from(public)
}

/// A key comment safe for a command-line argument and a log line.
#[must_use]
pub fn sanitize_comment(comment: &str) -> String {
    comment
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '-'))
        .take(64)
        .collect()
}

/// The comment a generated controller key carries:
/// `fleet-controller@<hostname>`.
#[must_use]
pub fn controller_key_comment() -> String {
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "controller".to_owned());
    sanitize_comment(&format!("fleet-controller@{host}"))
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("no detail").trim().to_owned()
}

/// The passwd home of the process uid, via `getent` (which honours NSS).
fn passwd_home() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        let uid = rustix::process::getuid().as_raw();
        let output = Command::new("getent")
            .args(["passwd", &uid.to_string()])
            .stdin(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        parse_passwd_home(&String::from_utf8_lossy(&output.stdout))
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// The home field (6th) of one passwd line.
#[must_use]
pub fn parse_passwd_home(line: &str) -> Option<PathBuf> {
    let line = line.lines().next()?;
    let home = line.split(':').nth(5)?.trim();
    (!home.is_empty()).then(|| PathBuf::from(home))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_passwd_home_is_the_sixth_field() {
        assert_eq!(
            parse_passwd_home("fleet:x:999:999::/var/lib/fleet:/usr/sbin/nologin\n"),
            Some(PathBuf::from("/var/lib/fleet"))
        );
        assert_eq!(parse_passwd_home("broken:x:1"), None);
        assert_eq!(parse_passwd_home("empty:x:1:1:::/bin/sh"), None);
    }

    #[test]
    fn comments_keep_only_safe_characters() {
        assert_eq!(
            sanitize_comment("fleet-controller@host 1;rm -rf"),
            "fleet-controller@host1rm-rf"
        );
        assert!(controller_key_comment().starts_with("fleet-controller@"));
    }

    #[test]
    fn a_missing_directory_is_no_identity() {
        let dir = tempfile::tempdir().unwrap();
        let identity = ControllerIdentity::at(dir.path().join(".ssh"));
        assert!(matches!(identity.inspect(), IdentityState::None { .. }));
        assert!(matches!(
            identity.ensure(false, "x").unwrap(),
            EnsureOutcome::Existing(IdentityState::None { .. })
        ));
        assert!(!dir.path().join(".ssh").exists(), "opt-out creates nothing");
    }

    #[test]
    fn generates_once_owner_only_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let identity = ControllerIdentity::at(dir.path().join(".ssh"));
        let EnsureOutcome::Generated(first) =
            identity.ensure(true, "fleet-controller@test").unwrap()
        else {
            panic!("a key must be generated");
        };
        assert_eq!(first.key_type, "ssh-ed25519");
        assert!(first.public_key.ends_with(" fleet-controller@test"));
        assert!(first.fingerprint.starts_with("SHA256:"));
        assert_eq!(first.path, dir.path().join(".ssh/id_ed25519"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir.path().join(".ssh")), 0o700);
            assert_eq!(mode(&first.path), 0o600);
        }
        let private = std::fs::read(&first.path).unwrap();
        let EnsureOutcome::Existing(IdentityState::Present(second)) =
            identity.ensure(true, "other").unwrap()
        else {
            panic!("an existing key must be reported, not replaced");
        };
        assert_eq!(second, first);
        assert_eq!(std::fs::read(&first.path).unwrap(), private);
        // The published fingerprint is the one ssh-keygen prints.
        let listed = Command::new("ssh-keygen")
            .arg("-lf")
            .arg(&first.path)
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&listed.stdout).contains(&first.fingerprint));
    }

    #[cfg(unix)]
    #[test]
    fn an_open_key_is_reported_with_the_fix() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let identity = ControllerIdentity::at(dir.path().join(".ssh"));
        let EnsureOutcome::Generated(key) = identity.ensure(true, "t").unwrap() else {
            panic!("generated");
        };
        std::fs::set_permissions(&key.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let IdentityState::Unusable { detail, .. } = identity.inspect() else {
            panic!("an open key is unusable");
        };
        assert!(detail.contains("chmod 600"), "{detail}");
        // Generation never replaces it.
        assert!(matches!(
            identity.ensure(true, "t").unwrap(),
            EnsureOutcome::Existing(IdentityState::Unusable { .. })
        ));
    }

    #[test]
    fn a_passphrase_protected_key_is_unusable() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let generated = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "not-a-real-secret", "-f"])
            .arg(ssh.join("id_ed25519"))
            .output()
            .unwrap();
        assert!(generated.status.success());
        let IdentityState::Unusable { detail, .. } = ControllerIdentity::at(&ssh).inspect() else {
            panic!("a protected key is unusable");
        };
        assert!(detail.contains("passphrase"), "{detail}");
    }

    #[cfg(unix)]
    #[test]
    fn a_broken_key_does_not_hide_a_usable_one_and_the_fix_targets_only_ssh() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        let identity = ControllerIdentity::at(&ssh);
        let EnsureOutcome::Generated(good) = identity.ensure(true, "t").unwrap() else {
            panic!("generated");
        };
        // An earlier name in ssh's order that ssh would skip.
        std::fs::write(ssh.join("id_rsa"), "not a key").unwrap();
        std::fs::set_permissions(ssh.join("id_rsa"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert_eq!(identity.inspect(), IdentityState::Present(good.clone()));
        // With the usable key gone, the first problem is reported.
        std::fs::set_permissions(&good.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let IdentityState::Unusable { path, .. } = identity.inspect() else {
            panic!("no usable key");
        };
        assert_eq!(path, ssh.join("id_rsa"));
        // The ownership fix names the .ssh directory, never the home.
        let fix = ownership_fix(&ssh);
        assert!(fix.ends_with(&format!("{}`", ssh.display())), "{fix}");
    }

    #[test]
    fn the_first_default_name_in_ssh_order_is_published() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        for (name, kind) in [("id_ed25519", "ed25519"), ("id_ecdsa", "ecdsa")] {
            let generated = Command::new("ssh-keygen")
                .args(["-q", "-t", kind, "-N", "", "-f"])
                .arg(ssh.join(name))
                .output()
                .unwrap();
            assert!(generated.status.success());
        }
        let IdentityState::Present(identity) = ControllerIdentity::at(&ssh).inspect() else {
            panic!("present");
        };
        assert_eq!(identity.path, ssh.join("id_ecdsa"));
        assert!(identity.key_type.starts_with("ecdsa-"));
    }
}
