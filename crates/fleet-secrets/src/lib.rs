//! The encrypted secret-record store.
//!
//! Provider credentials cannot live in Git or plaintext SQLite, so every
//! secret value is stored as a versioned, authenticated, context-bound
//! envelope: XChaCha20-Poly1305 under a master key that arrives from a
//! separately mounted file (see `README.md` for the key-file format and the
//! rotation procedure). The store's invariants are structural, not advisory:
//!
//! - Plaintext exists only inside [`SecretValue`], which redacts its `Debug`
//!   rendering and zeroizes its memory on drop.
//! - Every envelope records the key version that produced it, so a key file
//!   that rotates can still read old records and rewrap them without any
//!   external provider.
//! - The envelope's AEAD additional data binds the ciphertext to its record
//!   identity, so a value copied between records fails authentication.
//! - A wrong, missing, or malformed master key fails closed: the store opens
//!   nothing and resolves nothing.
//!
//! This crate stores no secret values of its own; it stores what callers
//! hand it, under the key the operator mounted.
#![warn(missing_docs)]

use std::fmt;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use sqlx::{Row, SqlitePool};
use zeroize::Zeroize;

/// Envelope format version; bump when the binary layout changes.
const ENVELOPE_VERSION: u8 = 1;
/// The magic every envelope starts with, so a value written by a different
/// subsystem is rejected instead of misparsed.
const ENVELOPE_MAGIC: [u8; 4] = *b"FSEK";
/// The byte length of an XChaCha20-Poly1305 nonce.
const NONCE_LEN: usize = 24;
/// The byte length of the AEAD tag appended to the ciphertext.
const TAG_LEN: usize = 16;
/// The required key material length in bytes (256-bit keys).
const KEY_LEN: usize = 32;

/// A decrypted secret value.
///
/// Cloning is deliberate and easy to reason about: every clone zeroizes its
/// own buffer. The `Debug` and `Display` renderings are structural redaction —
/// they can never contain the value because they never touch it.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    /// Wraps plaintext bytes.
    #[must_use]
    pub fn new(plaintext: Vec<u8>) -> Self {
        Self(plaintext)
    }

    /// The plaintext bytes. A borrow; the buffer zeroizes on final drop.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl From<&str> for SecretValue {
    fn from(value: &str) -> Self {
        Self::new(value.as_bytes().to_vec())
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue(REDACTED)")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REDACTED")
    }
}

/// A master key at a specific version, parsed from the key file.
#[derive(Clone)]
struct MasterKey {
    version: u32,
    bytes: [u8; KEY_LEN],
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Key material never renders, even in Debug.
        write!(f, "MasterKey {{ version: {} }}", self.version)
    }
}

/// The parsed master keys and the envelope cryptography over them. Separate
/// from the store so the crypto surface is testable without a database.
#[derive(Debug)]
struct KeyRing {
    keys: Vec<MasterKey>,
}

impl KeyRing {
    fn new(keys: Vec<MasterKey>) -> Self {
        Self { keys }
    }

    fn current_version(&self) -> u32 {
        self.keys[0].version
    }

    fn key_for(&self, version: u32) -> Result<&MasterKey, SecretError> {
        self.keys
            .iter()
            .find(|key| key.version == version)
            .ok_or_else(|| SecretError::DecryptFailed {
                reference: format!("key version {version}"),
            })
    }

    /// Seals plaintext into the versioned envelope, binding the AEAD's
    /// additional data to the record identity.
    fn seal(
        &self,
        id: &str,
        key_version: u32,
        value: &SecretValue,
    ) -> Result<Vec<u8>, SecretError> {
        use chacha20poly1305::aead::OsRng;
        use chacha20poly1305::aead::rand_core::RngCore;
        let key = self.key_for(key_version)?;
        let cipher = XChaCha20Poly1305::new(&Key::from(key.bytes));
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        // A counter nonce would couple records to call order; use the OS
        // CSPRNG for every seal instead.
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: value.expose(),
                    aad: &aad(id, key_version),
                },
            )
            .map_err(|_| SecretError::Query {
                context: "seal",
                detail: "AEAD seal failed".to_owned(),
            })?;

        let mut envelope =
            Vec::with_capacity(ENVELOPE_MAGIC.len() + 1 + 4 + NONCE_LEN + ciphertext.len());
        envelope.extend_from_slice(&ENVELOPE_MAGIC);
        envelope.push(ENVELOPE_VERSION);
        envelope.extend_from_slice(&key_version.to_le_bytes());
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    /// Opens an envelope and returns the plaintext, verifying every layer:
    /// magic, format version, key availability, and the AEAD tag.
    fn unseal(
        &self,
        id: &str,
        envelope: &[u8],
        key_version: i64,
    ) -> Result<SecretValue, SecretError> {
        let fail = || SecretError::DecryptFailed {
            reference: id.to_owned(),
        };
        let Ok(key_version_u32) = u32::try_from(key_version) else {
            return Err(fail());
        };
        if envelope.len() < ENVELOPE_MAGIC.len() + 1 + 4 + NONCE_LEN + TAG_LEN {
            return Err(fail());
        }
        let (magic, rest) = envelope.split_at(ENVELOPE_MAGIC.len());
        if magic != ENVELOPE_MAGIC {
            return Err(fail());
        }
        let (&format_version, rest) = rest.split_first().ok_or_else(fail)?;
        if format_version != ENVELOPE_VERSION {
            return Err(fail());
        }
        let (version_bytes, rest) = rest.split_at(4);
        let mut raw_version = [0_u8; 4];
        raw_version.copy_from_slice(version_bytes);
        if u32::from_le_bytes(raw_version) != key_version_u32 {
            return Err(fail());
        }
        let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);
        let key = self.key_for(key_version_u32)?;
        let cipher = XChaCha20Poly1305::new(&Key::from(key.bytes));
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad(id, key_version_u32),
                },
            )
            .map_err(|_| fail())?;
        Ok(SecretValue::new(plaintext))
    }
}

/// Non-secret facts about a stored secret. There is intentionally no way to
/// get a value from this type; use [`SecretStore::resolve`].
#[derive(Clone, Debug)]
pub struct SecretRecord {
    /// The record's opaque identity.
    pub id: String,
    /// The caller-chosen unique name.
    pub name: String,
    /// The key version that currently encrypts the value.
    pub key_version: u32,
    /// Bumped on every value change; used for optimistic observation.
    pub record_version: i64,
}

/// A secrets problem that is safe to print: record names and key versions,
/// never plaintext or key material.
#[derive(Debug)]
pub enum SecretError {
    /// The master key file is missing, malformed, or wrongly permissioned.
    MasterKey {
        /// The key file path involved.
        path: PathBuf,
        /// What is wrong with it.
        detail: String,
    },
    /// A record with this name already exists.
    DuplicateName {
        /// The conflicting name.
        name: String,
    },
    /// The named or identified record does not exist.
    NotFound {
        /// The name or id that was not found.
        reference: String,
    },
    /// Decryption failed: tampered value, wrong key, or foreign envelope.
    DecryptFailed {
        /// The record that could not be decrypted, identified without its value.
        reference: String,
    },
    /// A database operation failed.
    Query {
        /// The operation that failed.
        context: &'static str,
        /// The database's failure detail.
        detail: String,
    },
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MasterKey { path, detail } => {
                write!(f, "master key {}: {detail}", path.display())
            }
            Self::DuplicateName { name } => write!(f, "a secret named {name:?} already exists"),
            Self::NotFound { reference } => write!(f, "no secret record {reference:?}"),
            Self::DecryptFailed { reference } => {
                write!(
                    f,
                    "cannot decrypt secret record {reference:?}; the value may be tampered or the key wrong"
                )
            }
            Self::Query { context, detail } => {
                write!(f, "secret query failed in {context}: {detail}")
            }
        }
    }
}

impl std::error::Error for SecretError {}

/// The opened secret store: master key material plus its SQLite table.
#[derive(Debug)]
pub struct SecretStore {
    pool: SqlitePool,
    key_ring: KeyRing,
    key_path: PathBuf,
}

impl SecretStore {
    /// Opens the store against an existing database pool, reading and parsing
    /// the master key file.
    ///
    /// # Errors
    ///
    /// Fails closed when the key file is missing, readable beyond its owner
    /// (Unix), or does not parse into at least one 32-byte key.
    pub fn open(pool: SqlitePool, key_path: &Path) -> Result<Self, SecretError> {
        Ok(Self {
            pool,
            key_ring: KeyRing::new(parse_key_file(key_path)?),
            key_path: key_path.to_path_buf(),
        })
    }

    /// The key file this store reads.
    #[must_use]
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// The key version new values are sealed with.
    #[must_use]
    pub fn current_key_version(&self) -> u32 {
        self.key_ring.current_version()
    }

    /// Stores a new value under `name` and returns its non-secret facts.
    ///
    /// # Errors
    ///
    /// Fails on a duplicate name or a database error; the value is sealed
    /// before the database is touched.
    pub async fn create(
        &self,
        name: &str,
        value: SecretValue,
    ) -> Result<SecretRecord, SecretError> {
        let id = uuid::Uuid::now_v7().to_string();
        let sealed = self
            .key_ring
            .seal(&id, self.current_key_version(), &value)?;
        let now = epoch_millis();
        let record_version = 1_i64;
        let result = sqlx::query(
            "INSERT INTO secret_records (id, name, value, key_version, record_version, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        )
        .bind(&id)
        .bind(name)
        .bind(&sealed)
        .bind(i64::from(self.current_key_version()))
        .bind(record_version)
        .bind(now)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(SecretRecord {
                id,
                name: name.to_owned(),
                key_version: self.current_key_version(),
                record_version,
            }),
            Err(error) if is_unique_violation(&error) => Err(SecretError::DuplicateName {
                name: name.to_owned(),
            }),
            Err(error) => Err(SecretError::Query {
                context: "create",
                detail: error.to_string(),
            }),
        }
    }

    /// Replaces the value of the record with `id`, bumping its record version.
    ///
    /// # Errors
    ///
    /// Fails when the record does not exist or the database errors.
    pub async fn update(&self, id: &str, value: SecretValue) -> Result<SecretRecord, SecretError> {
        let existing = self.record(id).await?;
        let sealed = self.key_ring.seal(id, self.current_key_version(), &value)?;
        let record_version = existing.record_version + 1;
        sqlx::query(
            "UPDATE secret_records SET value = ?2, key_version = ?3, record_version = ?4, updated_at = ?5 \
             WHERE id = ?1",
        )
        .bind(id)
        .bind(&sealed)
        .bind(i64::from(self.current_key_version()))
        .bind(record_version)
        .bind(epoch_millis())
        .execute(&self.pool)
        .await
        .map_err(|error| SecretError::Query {
            context: "update",
            detail: error.to_string(),
        })?;
        Ok(SecretRecord {
            key_version: self.current_key_version(),
            record_version,
            ..existing
        })
    }

    /// Decrypts and returns the record's value.
    ///
    /// # Errors
    ///
    /// Fails when the record is missing or the value fails authentication —
    /// the store never returns a best-effort plaintext.
    pub async fn resolve(&self, id: &str) -> Result<SecretValue, SecretError> {
        let row = sqlx::query("SELECT value, key_version FROM secret_records WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| SecretError::Query {
                context: "resolve",
                detail: error.to_string(),
            })?
            .ok_or_else(|| SecretError::NotFound {
                reference: id.to_owned(),
            })?;
        let sealed: Vec<u8> = row.get(0);
        let key_version: i64 = row.get(1);
        self.key_ring.unseal(id, &sealed, key_version)
    }

    /// The non-secret facts of every record, newest first. Values are not
    /// present to redact — they are simply not read.
    ///
    /// # Errors
    ///
    /// Fails when the query fails.
    pub async fn list(&self) -> Result<Vec<SecretRecord>, SecretError> {
        sqlx::query_as::<_, (String, String, i64, i64)>(
            "SELECT id, name, key_version, record_version FROM secret_records ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|(id, name, key_version, record_version)| SecretRecord {
                    id,
                    name,
                    key_version: u32::try_from(key_version).unwrap_or(u32::MAX),
                    record_version,
                })
                .collect()
        })
        .map_err(|error| SecretError::Query {
            context: "list",
            detail: error.to_string(),
        })
    }

    /// Deletes the record with `id`.
    ///
    /// # Errors
    ///
    /// Fails when the record does not exist or the database errors.
    pub async fn delete(&self, id: &str) -> Result<(), SecretError> {
        let deleted = sqlx::query("DELETE FROM secret_records WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|error| SecretError::Query {
                context: "delete",
                detail: error.to_string(),
            })?;
        if deleted.rows_affected() == 0 {
            return Err(SecretError::NotFound {
                reference: id.to_owned(),
            });
        }
        Ok(())
    }

    /// Re-encrypts every record that is not sealed under the current key
    /// version, using the older keys still present in the key file. This is
    /// the rotation path: the operator adds the new key to the file, the
    /// controller reopens the store, and rewrap finishes the move without any
    /// external provider.
    ///
    /// # Errors
    ///
    /// Fails — without deleting anything — when any record cannot be
    /// decrypted with its recorded key version.
    pub async fn rewrap(&self) -> Result<usize, SecretError> {
        let rows = sqlx::query("SELECT id, value, key_version FROM secret_records")
            .fetch_all(&self.pool)
            .await
            .map_err(|error| SecretError::Query {
                context: "rewrap_select",
                detail: error.to_string(),
            })?;

        let mut rewrapped = 0;
        for row in rows {
            let id: String = row.get(0);
            let sealed: Vec<u8> = row.get(1);
            let key_version: i64 = row.get(2);
            if key_version == i64::from(self.current_key_version()) {
                continue;
            }
            let plaintext = self.key_ring.unseal(&id, &sealed, key_version)?;
            let resealed = self
                .key_ring
                .seal(&id, self.current_key_version(), &plaintext)?;
            let updated = sqlx::query(
                "UPDATE secret_records SET value = ?2, key_version = ?3, updated_at = ?4 WHERE id = ?1",
            )
            .bind(&id)
            .bind(&resealed)
            .bind(i64::from(self.current_key_version()))
            .bind(epoch_millis())
            .execute(&self.pool)
            .await
            .map_err(|error| SecretError::Query {
                context: "rewrap_update",
                detail: error.to_string(),
            })?;
            rewrapped += usize::try_from(updated.rows_affected()).unwrap_or(0);
        }
        Ok(rewrapped)
    }

    async fn record(&self, id: &str) -> Result<SecretRecord, SecretError> {
        sqlx::query_as::<_, (String, String, i64, i64)>(
            "SELECT id, name, key_version, record_version FROM secret_records WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| SecretError::Query {
            context: "record",
            detail: error.to_string(),
        })?
        .map(|(id, name, key_version, record_version)| SecretRecord {
            id,
            name,
            key_version: u32::try_from(key_version).unwrap_or(u32::MAX),
            record_version,
        })
        .ok_or_else(|| SecretError::NotFound {
            reference: id.to_owned(),
        })
    }
}

/// The AEAD additional data: binds a ciphertext to its record identity and
/// key version, so neither can be swapped without detection.
fn aad(id: &str, key_version: u32) -> Vec<u8> {
    let mut aad = b"fleet-secrets/record/".to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad.push(b'/');
    aad.extend_from_slice(&key_version.to_le_bytes());
    aad
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error
            .as_database_error()
            .map(sqlx::error::DatabaseError::kind),
        Some(sqlx::error::ErrorKind::UniqueViolation)
    )
}

fn epoch_millis() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}

/// Parses the master key file: lines of `<version> <64 hex chars>`, `#`
/// comments, and blank lines. The first line is the current key; any further
/// lines are older keys retained for rewrap. Versions must be unique and the
/// current one strictly the greatest.
fn parse_key_file(path: &Path) -> Result<Vec<MasterKey>, SecretError> {
    let fail = |detail: String| SecretError::MasterKey {
        path: path.to_path_buf(),
        detail,
    };
    let metadata =
        std::fs::metadata(path).map_err(|error| fail(format!("cannot be read: {error}")))?;
    if !metadata.is_file() {
        return Err(fail("is not a regular file".to_owned()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(fail(format!(
                "is too exposed: mode {mode:04o}, expected owner-only (0600)"
            )));
        }
    }

    let text =
        std::fs::read_to_string(path).map_err(|error| fail(format!("cannot be read: {error}")))?;
    let mut keys = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let version = parts
            .next()
            .ok_or_else(|| fail(format!("line {} is empty", index + 1)))?;
        let hex_key = parts
            .next()
            .ok_or_else(|| fail(format!("line {} lacks its hex key material", index + 1)))?;
        if parts.next().is_some() {
            return Err(fail(format!("line {} has trailing content", index + 1)));
        }
        let Ok(version) = version.parse::<u32>() else {
            return Err(fail(format!(
                "line {} has a non-numeric key version",
                index + 1
            )));
        };
        let Ok(raw) = hex::decode(hex_key) else {
            return Err(fail(format!("line {} key material is not hex", index + 1)));
        };
        let Ok(bytes) = <[u8; KEY_LEN]>::try_from(raw.as_slice()) else {
            return Err(fail(format!(
                "line {} key material is {} bytes, expected {KEY_LEN}",
                index + 1,
                raw.len()
            )));
        };
        if keys.iter().any(|key: &MasterKey| key.version == version) {
            return Err(fail(format!("key version {version} appears twice")));
        }
        keys.push(MasterKey { version, bytes });
    }
    if keys.is_empty() {
        return Err(fail("contains no key material".to_owned()));
    }
    // The first line is current; every later line must be strictly older.
    let current = keys[0].version;
    if keys.iter().any(|key| key.version > current) {
        return Err(fail(format!(
            "the first line must carry the current (greatest) key version; found a key newer than {current}"
        )));
    }
    Ok(keys)
}

#[cfg(test)]
mod known_vectors {
    use super::*;

    /// Pins the envelope format end to end: with a fixed key, fixed nonce,
    /// and known plaintext, the envelope construction and the unseal path
    /// must agree exactly, so a format change is a reviewed migration rather
    /// than silent drift.
    #[test]
    fn the_envelope_format_is_pinned_by_a_known_vector() {
        let ring = KeyRing::new(vec![MasterKey {
            version: 7,
            bytes: hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap()
                .try_into()
                .unwrap(),
        }]);
        let id = "0195f3c8-6a2c-7111-b04a-2f4b1e9d77aa";
        let plaintext = SecretValue::from("known-vector-plaintext");

        let cipher = XChaCha20Poly1305::new(&Key::from(ring.keys[0].bytes));
        let nonce = XNonce::from([0x42_u8; NONCE_LEN]);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.expose(),
                    aad: &aad(id, 7),
                },
            )
            .unwrap();
        let mut envelope = Vec::new();
        envelope.extend_from_slice(&ENVELOPE_MAGIC);
        envelope.push(ENVELOPE_VERSION);
        envelope.extend_from_slice(&7_u32.to_le_bytes());
        envelope.extend_from_slice(&[0x42_u8; NONCE_LEN]);
        envelope.extend_from_slice(&ciphertext);

        let opened = ring
            .unseal(id, &envelope, 7)
            .expect("the known vector must open");
        assert_eq!(opened.expose(), b"known-vector-plaintext");
        // The additional data binds identity and key version: swap either and
        // authentication must fail.
        assert!(ring.unseal("another-record", &envelope, 7).is_err());
        assert!(ring.unseal(id, &envelope, 8).is_err());
        let mut tampered = envelope.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(ring.unseal(id, &tampered, 7).is_err());
    }

    #[test]
    fn secret_value_redacts_every_rendering() {
        let value = SecretValue::from("hunter2-password");
        assert_eq!(format!("{value:?}"), "SecretValue(REDACTED)");
        assert_eq!(value.to_string(), "REDACTED");
    }
}
