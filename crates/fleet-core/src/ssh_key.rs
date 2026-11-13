//! OpenSSH public key lines: parsing and the `SHA256:` fingerprint.
//!
//! The controller publishes its own public key with this fingerprint, and
//! `fleetctl machines join` computes a machine's host key fingerprint from
//! its `.pub` file with the same code, so both sides agree with
//! `ssh-keygen -lf` byte for byte: SHA-256 over the decoded key blob, base64
//! without padding.

use base64::Engine as _;
use sha2::Digest as _;

/// The longest public key line accepted. An RSA-16384 key is under 3 KiB;
/// anything larger is not a key line.
pub const MAX_PUBLIC_KEY_LINE_BYTES: usize = 16 * 1024;

/// One parsed OpenSSH public key line (`<type> <base64 blob> [comment]`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshPublicKey {
    /// The key type, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// The base64 key blob exactly as written.
    pub blob: String,
    /// The comment, when the line has one.
    pub comment: Option<String>,
    /// The `SHA256:` fingerprint, as `ssh-keygen -lf` prints it.
    pub fingerprint: String,
}

impl SshPublicKey {
    /// The canonical line: type, blob and the comment when present.
    #[must_use]
    pub fn line(&self) -> String {
        match &self.comment {
            Some(comment) => format!("{} {} {comment}", self.key_type, self.blob),
            None => format!("{} {}", self.key_type, self.blob),
        }
    }

    /// Whether `other` is the same key (type and blob), whatever its comment.
    #[must_use]
    pub fn same_key(&self, other: &Self) -> bool {
        self.key_type == other.key_type && self.blob == other.blob
    }
}

/// Parses one OpenSSH public key line and computes its fingerprint.
///
/// Options before the key type (an `authorized_keys` line such as
/// `from="..." ssh-ed25519 ...`) are not accepted: this parses a plain
/// public key, which is what a `.pub` file and the controller publish.
///
/// # Errors
///
/// Fails with a description (never the input) when the line is empty, too
/// long, has no blob, the blob is not base64, the blob's own type name does
/// not match the line's key type, or the blob is not a complete sequence of
/// SSH fields with key material after the type (an Ed25519 key must be
/// exactly 32 bytes).
pub fn parse_public_key(line: &str) -> Result<SshPublicKey, String> {
    let line = line.trim();
    if line.is_empty() {
        return Err("the public key is empty".to_owned());
    }
    if line.len() > MAX_PUBLIC_KEY_LINE_BYTES {
        return Err(format!(
            "the public key is longer than {MAX_PUBLIC_KEY_LINE_BYTES} bytes"
        ));
    }
    if line.contains(['\n', '\r']) {
        return Err("the public key must be a single line".to_owned());
    }
    let mut words = line.split_whitespace();
    let key_type = words.next().unwrap_or_default();
    let Some(blob) = words.next() else {
        return Err("the public key has no key data".to_owned());
    };
    let comment = {
        let rest: Vec<&str> = words.collect();
        (!rest.is_empty()).then(|| rest.join(" "))
    };
    if !is_key_type(key_type) {
        return Err("the public key does not start with a key type".to_owned());
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .map_err(|_| "the public key data is not base64".to_owned())?;
    // The blob is a sequence of SSH strings (a 4-byte big-endian length,
    // then the bytes; mpints are strings too): first the type name, which
    // must agree with the line, then the key material. Every public key
    // type has at least one material field, and the fields fill the blob
    // exactly.
    let fields =
        ssh_strings(&decoded).ok_or_else(|| "the public key data is truncated".to_owned())?;
    if fields.first().copied() != Some(key_type.as_bytes()) {
        return Err("the public key data does not match its key type".to_owned());
    }
    if fields.len() < 2 || fields[1..].iter().all(|field| field.is_empty()) {
        return Err("the public key data has no key material".to_owned());
    }
    if key_type == "ssh-ed25519" && (fields.len() != 2 || fields[1].len() != 32) {
        return Err("the public key data is not a 32-byte Ed25519 key".to_owned());
    }
    let digest = sha2::Sha256::digest(&decoded);
    let fingerprint = format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    );
    Ok(SshPublicKey {
        key_type: key_type.to_owned(),
        blob: blob.to_owned(),
        comment,
        fingerprint,
    })
}

/// Splits a blob into its SSH strings, or `None` when a length runs past
/// the end.
fn ssh_strings(mut blob: &[u8]) -> Option<Vec<&[u8]>> {
    let mut fields = Vec::new();
    while !blob.is_empty() {
        let length = blob.get(..4)?;
        let length = u32::from_be_bytes([length[0], length[1], length[2], length[3]]) as usize;
        let field = blob.get(4..4_usize.checked_add(length)?)?;
        fields.push(field);
        blob = &blob[4 + length..];
    }
    Some(fields)
}

/// Whether `word` is shaped like an OpenSSH key type (`ssh-ed25519`,
/// `ecdsa-sha2-nistp256`, `sk-ssh-ed25519@openssh.com`, ...).
fn is_key_type(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= 64
        && (word.starts_with("ssh-") || word.starts_with("ecdsa-") || word.starts_with("sk-"))
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '@' | '.'))
}

/// Compares two `SHA256:` fingerprints exactly (the base64 is
/// case-sensitive). Surrounding whitespace is ignored; nothing else is.
#[must_use]
pub fn fingerprints_match(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim(), b.trim());
    a.starts_with("SHA256:") && a.len() > "SHA256:".len() && a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway ed25519 key generated for this test only, with the
    // fingerprint `ssh-keygen -lf` prints for it.
    const LINE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9t4Xt9H44BCMC3Ab4ugXr+F9s8s/RCNEv6mkk3WHnV test@example";
    const FINGERPRINT: &str = "SHA256:2Mqm0WXnrxat1gQ/xKwNc1fp09Gh1IgfynaiOD4BH18";

    #[test]
    fn parses_type_blob_and_comment_and_fingerprints_like_ssh_keygen() {
        let key = parse_public_key(LINE).unwrap();
        assert_eq!(key.key_type, "ssh-ed25519");
        assert_eq!(key.comment.as_deref(), Some("test@example"));
        assert_eq!(key.fingerprint, FINGERPRINT);
        assert_eq!(key.line(), LINE);
    }

    #[test]
    fn a_line_without_a_comment_round_trips() {
        let bare = LINE.rsplit_once(' ').unwrap().0;
        let key = parse_public_key(bare).unwrap();
        assert_eq!(key.comment, None);
        assert_eq!(key.line(), bare);
        assert!(key.same_key(&parse_public_key(LINE).unwrap()));
    }

    #[test]
    fn malformed_lines_are_refused_without_echoing_them() {
        for (line, why) in [
            ("", "empty"),
            ("ssh-ed25519", "no key data"),
            ("ssh-ed25519 !!!notbase64", "not base64"),
            ("ssh-ed25519 AAAA", "truncated"),
            // The type name alone, no key material.
            ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5", "no key material"),
            // A key field that is not 32 bytes.
            ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAQA=", "32-byte"),
            ("from=\"x\" ssh-ed25519 AAAA", "key type"),
            (
                "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIH9t4Xt9H44BCMC3Ab4ugXr+F9s8s/RCNEv6mkk3WHnV",
                "match",
            ),
            ("ssh-ed25519 AAAA\nssh-ed25519 AAAA", "single line"),
        ] {
            let error = parse_public_key(line).unwrap_err();
            assert!(error.contains(why), "{line:?}: {error}");
            assert!(!error.contains("AAAA"), "{error}");
        }
    }

    #[test]
    fn fingerprints_compare_exactly() {
        assert!(fingerprints_match("SHA256:abc", " SHA256:abc\n"));
        assert!(!fingerprints_match("SHA256:abc", "SHA256:ABC"));
        assert!(!fingerprints_match("SHA256:", "SHA256:"));
        assert!(!fingerprints_match("MD5:aa", "MD5:aa"));
    }
}
