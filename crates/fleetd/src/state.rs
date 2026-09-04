//! Node-local state: the Ed25519 identity key and the enrollment credential.
//!
//! The private key is generated on the node and never leaves it (FM-204's
//! invariant): it is stored as a PKCS#8 document, hex-encoded, in a
//! node-local state directory with owner-only permissions. The credential is
//! the controller-signed node credential token; it is renewable by key
//! proof, so losing it only costs a re-enrollment, never the identity.

use std::path::{Path, PathBuf};
use std::time::Duration;

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

/// The state directory root. Overridable with `FLEETD_STATE_DIR` for
/// packaging (FM-211 owns the service layout).
pub const STATE_DIR_VAR: &str = "FLEETD_STATE_DIR";
/// The default state directory, relative to the working directory.
pub const DEFAULT_STATE_DIR: &str = "fleetd-state";

/// The node's local state: its key pair and its stored facts.
pub struct NodeState {
    dir: PathBuf,
    key_pair: Ed25519KeyPair,
    public_key_hex: String,
    credential: Option<String>,
    machine_id: Option<String>,
}

impl std::fmt::Debug for NodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key pair never renders; the credential is a bearer token.
        f.debug_struct("NodeState")
            .field("dir", &self.dir)
            .field("public_key_hex", &self.public_key_hex)
            .field("credential", &self.credential.as_ref().map(|_| "present"))
            .field("machine_id", &self.machine_id)
            .finish_non_exhaustive()
    }
}

impl NodeState {
    /// Loads (or initializes) the state directory: the key is created on
    /// first use, the credential is read when present.
    ///
    /// # Errors
    ///
    /// Fails when the directory or its files cannot be prepared, when the
    /// stored key is malformed, or when permissions are too open (Unix).
    pub fn open(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|error| {
            format!(
                "cannot create the state directory {}: {error}",
                dir.display()
            )
        })?;
        restrict_owner_only(dir)?;

        let key_path = dir.join("node.key");
        let key_pair = match std::fs::read_to_string(&key_path) {
            Ok(document) => {
                check_owner_only(&key_path)?;
                let bytes = hex_decode(document.trim())
                    .map_err(|_| format!("the stored key {} is not hex", key_path.display()))?;
                Ed25519KeyPair::from_pkcs8(&bytes).map_err(|error| {
                    format!(
                        "the stored key {} is not a PKCS#8 Ed25519 document: {error}",
                        key_path.display()
                    )
                })?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                    .map_err(|error| format!("cannot generate the node key: {error}"))?;
                std::fs::write(&key_path, hex_encode(document.as_ref()))
                    .map_err(|error| format!("cannot write {}: {error}", key_path.display()))?;
                restrict_owner_only(&key_path)?;
                eprintln!(
                    "fleetd: generated a new node identity key at {}",
                    key_path.display()
                );
                Ed25519KeyPair::from_pkcs8(document.as_ref())
                    .map_err(|error| format!("the generated key does not parse: {error}"))?
            }
            Err(error) => {
                return Err(format!("cannot read {}: {error}", key_path.display()));
            }
        };
        let public_key_hex = hex_encode(key_pair.public_key().as_ref());

        let credential = read_optional(&dir.join("credential"))?;
        let machine_id = read_optional(&dir.join("machine-id"))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            key_pair,
            public_key_hex,
            credential,
            machine_id,
        })
    }

    /// The node's hex-encoded public key.
    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// The stored node credential, when the node is enrolled.
    #[must_use]
    pub fn credential(&self) -> Option<&str> {
        self.credential.as_deref()
    }

    /// The machine this node is enrolled against.
    #[must_use]
    pub fn machine_id(&self) -> Option<&str> {
        self.machine_id.as_deref()
    }

    /// Signs the canonical proof message with the node's private key.
    #[must_use]
    pub fn sign_proof(&self, message: &[u8]) -> String {
        hex_encode(self.key_pair.sign(message).as_ref())
    }

    /// Stores the enrollment outcome: the credential and the machine id.
    ///
    /// # Errors
    ///
    /// Fails when the files cannot be written.
    pub fn store_enrollment(&self, machine_id: &str, credential: &str) -> Result<(), String> {
        write_private(&self.dir.join("machine-id"), machine_id)?;
        write_private(&self.dir.join("credential"), credential)?;
        Ok(())
    }
}

fn read_optional(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text.trim().to_owned()).filter(|text| !text.is_empty())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot read {}: {error}", path.display())),
    }
}

fn write_private(path: &Path, content: &str) -> Result<(), String> {
    std::fs::write(path, format!("{content}\n"))
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    restrict_owner_only(path)
}

fn restrict_owner_only(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path)
            .map_err(|error| format!("cannot stat {}: {error}", path.display()))?
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions)
            .map_err(|error| format!("cannot restrict {}: {error}", path.display()))?;
    }
    Ok(())
}

fn check_owner_only(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|error| format!("cannot stat {}: {error}", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "the key file {} is too exposed (mode {mode:04o})",
                path.display()
            ));
        }
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("a hex write is infallible");
    }
    text
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| "not hex".to_owned())
        })
        .collect()
}

/// A jitter source over the system random: the client's reconnect backoff
/// stays bounded by deriving a 0.75..=1.25 multiplier from fresh bytes.
pub struct Jitter {
    rng: SystemRandom,
}

impl Jitter {
    /// Creates the jitter source.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }

    /// Returns `base` scaled into its bounded jitter band: ±25%.
    #[must_use]
    pub fn scale(&self, base: Duration) -> Duration {
        use ring::rand::SecureRandom as _;
        let mut bytes = [0_u8; 2];
        if self.rng.fill(&mut bytes).is_err() {
            return base;
        }
        let draw = u16::from_le_bytes(bytes);
        // 0.75 .. 1.25 in 1/65536 steps.
        let factor = f64::from(draw) / f64::from(u16::MAX) * 0.5 + 0.75;
        Duration::from_secs_f64(base.as_secs_f64() * factor)
    }
}

impl Default for Jitter {
    fn default() -> Self {
        Self::new()
    }
}
