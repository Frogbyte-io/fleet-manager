//! The fleetd service-package builder: one command that turns the workspace
//! plus `deploy/fleetd/` into a checksummed, self-contained archive.
//!
//! The artifact is the deployment truth FM-211's bootstrap operation
//! installs: a portable tar.gz holding the release `fleetd` binary, the
//! hardened systemd unit, the install/uninstall scripts, the README, and a
//! `SHA256SUMS` over the files. Nothing here signs; checksums are the
//! verified integrity story until a signing ADR exists.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest as _, Sha256};

/// The archive prefix, before the version and platform suffix.
pub const ARCHIVE_PREFIX: &str = "fleetd";

/// Builds the release binary and packs the service archive.
///
/// Returns the archive path and its sha256 digest. Refuses to overwrite an
/// existing artifact: a rebuilt package is a new package.
///
/// # Errors
///
/// Fails when the release build fails, a packaged source is missing, or the
/// staging/archive steps fail on the filesystem.
pub fn package_fleetd(repo_root: &Path) -> Result<(PathBuf, String), String> {
    let version = read_fleetd_version(&repo_root.join("crates/fleetd/Cargo.toml"))?;
    let platform = linux_platform();
    let dist_dir = repo_root.join("target/dist");
    let staging = dist_dir.join(format!("fleetd-{version}-package"));
    let archive_name = format!("{ARCHIVE_PREFIX}-{version}-{platform}.tar.gz");
    let archive = dist_dir.join(&archive_name);

    if archive.exists() {
        return Err(format!(
            "{} already exists; remove it first (a rebuilt package is a new package)",
            archive.display()
        ));
    }

    // The release build must be locked and up to date with the workspace.
    let status = Command::new("cargo")
        .current_dir(repo_root)
        .args(["build", "--release", "--locked", "-p", "fleetd"])
        .status()
        .map_err(|error| format!("cannot start the release build: {error}"))?;
    if !status.success() {
        return Err("the fleetd release build failed".to_owned());
    }
    let binary = repo_root.join("target/release/fleetd");
    if !binary.is_file() {
        return Err(format!(
            "the release build produced no binary at {}",
            binary.display()
        ));
    }

    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)
        .map_err(|error| format!("cannot stage {}: {error}", staging.display()))?;
    fs::copy(&binary, staging.join("fleetd"))
        .map_err(|error| format!("cannot copy the binary: {error}"))?;
    let deploy_dir = repo_root.join("deploy/fleetd");
    for name in ["fleetd.service", "install.sh", "uninstall.sh", "README.md"] {
        let source = deploy_dir.join(name);
        if !source.is_file() {
            return Err(format!(
                "the package source {} is missing",
                source.display()
            ));
        }
        fs::copy(&source, staging.join(name))
            .map_err(|error| format!("cannot package {name}: {error}"))?;
    }
    for name in ["install.sh", "uninstall.sh", "fleetd"] {
        make_executable(&staging.join(name))?;
    }

    let sums = checksums(&staging)?;
    fs::write(staging.join("SHA256SUMS"), sums)
        .map_err(|error| format!("cannot write SHA256SUMS: {error}"))?;

    // The archive holds the files at its root, so install.sh's own directory
    // is the extracted package.
    let status = Command::new("tar")
        .current_dir(&staging)
        .arg("-czf")
        .arg(&archive)
        .arg("fleetd")
        .arg("fleetd.service")
        .arg("install.sh")
        .arg("uninstall.sh")
        .arg("README.md")
        .arg("SHA256SUMS")
        .status()
        .map_err(|error| format!("cannot start tar: {error}"))?;
    if !status.success() {
        return Err("tar failed while packing the archive".to_owned());
    }
    let digest = file_sha256(&archive)?;
    Ok((archive, digest))
}

/// The archive file name for a fleetd version.
#[must_use]
pub fn archive_name(version: &str) -> String {
    format!("{ARCHIVE_PREFIX}-{version}-{}.tar.gz", linux_platform())
}

fn linux_platform() -> String {
    if cfg!(target_arch = "x86_64") {
        "linux-x86_64".to_owned()
    } else if cfg!(target_arch = "aarch64") {
        "linux-aarch64".to_owned()
    } else {
        "linux-unknown".to_owned()
    }
}

/// Reads the `[package] version` of fleetd's manifest, following the
/// workspace inheritance (`version.workspace = true`) to the root. A tiny
/// scan keeps the packaging step free of a TOML dependency; both files are
/// workspace-owned.
fn read_fleetd_version(manifest: &Path) -> Result<String, String> {
    let text = fs::read_to_string(manifest)
        .map_err(|error| format!("cannot read {}: {error}", manifest.display()))?;
    let mut in_package = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[package]" {
            in_package = true;
        } else if trimmed.starts_with('[') {
            in_package = false;
        } else if in_package {
            if trimmed.starts_with("version.") {
                // `version.workspace = true` inherits from the root manifest:
                // crates/<crate>/Cargo.toml → <workspace root>/Cargo.toml.
                let root = manifest
                    .parent()
                    .and_then(Path::parent)
                    .and_then(Path::parent)
                    .ok_or("cannot locate the workspace root")?
                    .join("Cargo.toml");
                return read_workspace_version(&root);
            }
            if let Some(value) = trimmed.strip_prefix("version =") {
                let raw = value.trim().trim_matches('"');
                if !raw.is_empty() {
                    return Ok(raw.to_owned());
                }
            }
        }
    }
    Err(format!("{} has no [package] version", manifest.display()))
}

fn read_workspace_version(manifest: &Path) -> Result<String, String> {
    let text = fs::read_to_string(manifest)
        .map_err(|error| format!("cannot read {}: {error}", manifest.display()))?;
    let mut in_package = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[workspace.package]" {
            in_package = true;
        } else if trimmed.starts_with('[') {
            in_package = false;
        } else if in_package && let Some(value) = trimmed.strip_prefix("version =") {
            let version = value.trim().trim_matches('"');
            if !version.is_empty() {
                return Ok(version.to_owned());
            }
        }
    }
    Err(format!(
        "{} has no [workspace.package] version",
        manifest.display()
    ))
}

fn make_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = fs::metadata(path)
            .map_err(|error| format!("cannot stat {}: {error}", path.display()))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)
            .map_err(|error| format!("cannot chmod {}: {error}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// The canonical `SHA256SUMS` content for the packaged files: `<digest>  <name>`,
/// sorted by name, newline-terminated.
fn checksums(staging: &Path) -> Result<String, String> {
    let mut lines = Vec::new();
    for name in [
        "fleetd",
        "fleetd.service",
        "install.sh",
        "uninstall.sh",
        "README.md",
    ] {
        let digest = file_sha256(&staging.join(name))?;
        lines.push(format!("{digest}  {name}\n"));
    }
    Ok(lines.concat())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    Ok(digest
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            // 64 hex characters, lowercase, the canonical digest form.
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        }))
}
