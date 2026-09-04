//! The node principal's cryptographic surface: enrollment tokens, signed
//! node credentials and sessions, and Ed25519 key-proof verification.
//!
//! This is the real implementation of [`fleet_application::node::NodeCrypto`]
//! (see the application module for the flow it serves). The formats are
//! pinned here and by known-vector tests, because these strings are the
//! boundary `fleetd` depends on:
//!
//! - **Enrollment token** `fmtenr1.<64 hex>`: 32 CSPRNG bytes. The value is
//!   shown once and stored only as a SHA-256 hash.
//! - **Node credential** `fmnc1.<credential id>.<machine id>.<node key
//!   version>.<expires at>.<HMAC>`: HMAC-SHA256 over the dotted prefix,
//!   under the controller's node-signing key. Presentation re-verifies the
//!   tag and then checks durable state, so revocation is storage-backed.
//! - **Node session** `fmns1.<session id>.<credential id>.<machine id>.<expires
//!   at>.<HMAC>`: the same codec for the short-lived session a successful
//!   proof exchanges the credential for.
//! - **Key proof**: an Ed25519 signature over the canonical proof message
//!   built by [`fleet_application::node::proof_message`], verified with the
//!   node's bound public key.
//!
//! Node credentials and sessions are only ever presented to the node surface
//! (the gateway), never to the operator API: a compromised node cannot walk
//! its session into an administrative endpoint.
#![warn(missing_docs)]

use ring::digest;
use ring::hmac::{self, HMAC_SHA256, Key};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, UnparsedPublicKey};

use fleet_application::node::{NodeCredentialClaims, NodeCrypto, NodeSessionClaims};

/// The credential token's format tag.
const CREDENTIAL_PREFIX: &str = "fmnc1";
/// The session token's format tag.
const SESSION_PREFIX: &str = "fmns1";
/// The enrollment token's format tag.
const TOKEN_PREFIX: &str = "fmtenr1";
/// The signing key length in bytes (256-bit HMAC-SHA256 keys).
const KEY_LEN: usize = 32;
/// The nonce length in bytes.
const NONCE_LEN: usize = 32;

/// The HMAC-SHA256 codec and Ed25519 verifier behind node trust.
///
/// Constructed from the controller's node-signing key. Replacing that key
/// invalidates every outstanding credential and session — verification fails
/// closed — so nodes re-prove (credentials) or re-enroll (identity) through
/// explicit, audited actions rather than silently trusting a new key.
#[derive(Debug)]
pub struct HmacNodeCrypto {
    signing_key: Key,
    rng: SystemRandom,
}

impl HmacNodeCrypto {
    /// Creates the codec from 32 bytes of signing-key material.
    ///
    /// # Panics
    ///
    /// Panics only if HMAC-SHA256 refuses the key length, which the type
    /// system already pins to 32 bytes.
    #[must_use]
    pub fn new(signing_key: [u8; KEY_LEN]) -> Self {
        Self {
            signing_key: Key::new(HMAC_SHA256, &signing_key),
            rng: SystemRandom::new(),
        }
    }
}

impl NodeCrypto for HmacNodeCrypto {
    fn generate_token(&self) -> String {
        let mut bytes = [0_u8; NONCE_LEN];
        self.rng
            .fill(&mut bytes)
            .expect("the system random source must not fail");
        format!("{TOKEN_PREFIX}.{}", hex_encode(&bytes))
    }

    fn hash_token(&self, token: &str) -> String {
        hex_encode(digest::digest(&digest::SHA256, token.as_bytes()).as_ref())
    }

    fn generate_nonce(&self) -> String {
        let mut bytes = [0_u8; NONCE_LEN];
        self.rng
            .fill(&mut bytes)
            .expect("the system random source must not fail");
        hex_encode(&bytes)
    }

    fn verify_key_proof(&self, public_key: &str, message: &[u8], signature_hex: &str) -> bool {
        let (Ok(key), Ok(signature)) = (hex_decode(public_key), hex_decode(signature_hex)) else {
            return false;
        };
        if key.len() != 32 || signature.len() != 64 {
            return false;
        }
        UnparsedPublicKey::new(&ED25519, &key)
            .verify(message, &signature)
            .is_ok()
    }

    fn issue_credential_token(&self, claims: &NodeCredentialClaims) -> Result<String, String> {
        let prefix = format!(
            "{CREDENTIAL_PREFIX}.{}.{}.{}.{}",
            claims.credential_id, claims.machine_id, claims.node_key_version, claims.expires_at
        );
        Ok(format!(
            "{prefix}.{}",
            sign(&self.signing_key, prefix.as_bytes())
        ))
    }

    fn verify_credential_token(&self, token: &str) -> Result<NodeCredentialClaims, String> {
        let parts = parse_tagged(token, CREDENTIAL_PREFIX)?;
        // The signed payload is the full dotted prefix, exactly as issued,
        // and the tag is the hex text decoded back to raw bytes.
        let payload = parts[0..5].join(".");
        let tag = hex_decode(parts[5]).map_err(|_| "the credential tag is not hex".to_owned())?;
        hmac::verify(&self.signing_key, payload.as_bytes(), &tag)
            .map_err(|_| "the credential tag did not verify".to_owned())?;
        Ok(NodeCredentialClaims {
            credential_id: parts[1].to_owned(),
            machine_id: parts[2].to_owned(),
            node_key_version: parts[3]
                .parse()
                .map_err(|_| "the node key version is not a number".to_owned())?,
            expires_at: parts[4]
                .parse()
                .map_err(|_| "the expiry is not a number".to_owned())?,
        })
    }

    fn issue_session_token(&self, claims: &NodeSessionClaims) -> Result<String, String> {
        let prefix = format!(
            "{SESSION_PREFIX}.{}.{}.{}.{}",
            claims.session_id, claims.credential_id, claims.machine_id, claims.expires_at
        );
        Ok(format!(
            "{prefix}.{}",
            sign(&self.signing_key, prefix.as_bytes())
        ))
    }

    fn verify_session_token(&self, token: &str) -> Result<NodeSessionClaims, String> {
        let parts = parse_tagged(token, SESSION_PREFIX)?;
        // The signed payload is the full dotted prefix, exactly as issued,
        // and the tag is the hex text decoded back to raw bytes.
        let payload = parts[0..5].join(".");
        let tag = hex_decode(parts[5]).map_err(|_| "the session tag is not hex".to_owned())?;
        hmac::verify(&self.signing_key, payload.as_bytes(), &tag)
            .map_err(|_| "the session tag did not verify".to_owned())?;
        Ok(NodeSessionClaims {
            session_id: parts[1].to_owned(),
            credential_id: parts[2].to_owned(),
            machine_id: parts[3].to_owned(),
            expires_at: parts[4]
                .parse()
                .map_err(|_| "the expiry is not a number".to_owned())?,
        })
    }
}

/// Signs `message` and returns the tag as lowercase hex.
fn sign(key: &Key, message: &[u8]) -> String {
    hex_encode(hmac::sign(key, message).as_ref())
}

/// Parses a dotted token, requiring the expected tag prefix.
fn parse_tagged<'a>(token: &'a str, expected_prefix: &str) -> Result<Vec<&'a str>, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 6 || parts[0] != expected_prefix {
        return Err(format!("not a {expected_prefix} token"));
    }
    Ok(parts)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble"));
        text.push(char::from_digit(u32::from(byte & 0x0F), 16).expect("nibble"));
    }
    text
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex".to_owned());
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| "not hex".to_owned())
        })
        .collect()
}

#[cfg(test)]
mod vectors {
    use super::*;

    fn codec() -> HmacNodeCrypto {
        HmacNodeCrypto::new([0x42; KEY_LEN])
    }

    #[test]
    fn the_hmac_key_derives_the_expected_rfc_4231_vector() {
        // RFC 4231 test case 1: key 20 bytes of 0x0b, data "Hi There".
        let key = Key::new(HMAC_SHA256, &[0x0b_u8; 20]);
        let tag = hmac::sign(&key, b"Hi There");
        assert_eq!(
            hex_encode(tag.as_ref()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn the_credential_token_format_is_pinned_and_round_trips() {
        let codec = codec();
        let claims = NodeCredentialClaims {
            credential_id: "0195f3c8-6a2c-7111-b04a-2f4b1e9d77aa".to_owned(),
            machine_id: "0195f3c8-6a2c-7111-b04a-2f4b1e9d77ab".to_owned(),
            node_key_version: 3,
            expires_at: 1_800_000_000_000,
        };
        let token = codec.issue_credential_token(&claims).expect("signs");
        let expected_prefix = format!(
            "{CREDENTIAL_PREFIX}.{}.{}.{}.{}",
            claims.credential_id, claims.machine_id, claims.node_key_version, claims.expires_at
        );
        assert!(token.starts_with(&expected_prefix), "{token}");
        assert_eq!(codec.verify_credential_token(&token), Ok(claims));
    }

    #[test]
    fn the_session_token_format_is_pinned_and_round_trips() {
        let codec = codec();
        let claims = NodeSessionClaims {
            session_id: "0195f3c8-6a2c-7111-b04a-2f4b1e9d77ac".to_owned(),
            credential_id: "0195f3c8-6a2c-7111-b04a-2f4b1e9d77aa".to_owned(),
            machine_id: "0195f3c8-6a2c-7111-b04a-2f4b1e9d77ab".to_owned(),
            expires_at: 1_800_000_000_000,
        };
        let token = codec.issue_session_token(&claims).expect("signs");
        assert_eq!(codec.verify_session_token(&token), Ok(claims));
    }

    #[test]
    fn tampered_tokens_refuse() {
        let codec = codec();
        let claims = NodeCredentialClaims {
            credential_id: "0195f3c8-6a2c-7111-b04a-2f4b1e9d77aa".to_owned(),
            machine_id: "0195f3c8-6a2c-7111-b04a-2f4b1e9d77ab".to_owned(),
            node_key_version: 1,
            expires_at: 1_800_000_000_000,
        };
        let token = codec.issue_credential_token(&claims).expect("signs");

        // A different key rejects the token outright.
        let other = HmacNodeCrypto::new([0x43; KEY_LEN]);
        assert!(other.verify_credential_token(&token).is_err());

        // Tampering with any field invalidates the tag.
        for mutated in [
            token.replace("fmnc1.", "fmnc2."),
            format!("{token}0"),
            token.replace(&claims.machine_id, "00000000-0000-7111-b04a-2f4b1e9d77ff"),
        ] {
            assert!(codec.verify_credential_token(&mutated).is_err());
        }
        assert!(codec.verify_credential_token("fmnc1.not-a-token").is_err());
    }

    #[test]
    fn the_ed25519_rfc_8032_test_vector_verifies_and_rejects_tampering() {
        // RFC 8032 section 7.1 TEST 1 (empty message).
        let public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        let codec = codec();
        assert!(codec.verify_key_proof(public_key, b"", signature));
        assert!(!codec.verify_key_proof(public_key, b"x", signature));
        assert!(!codec.verify_key_proof(
            "0000000000000000000000000000000000000000000000000000000000000000",
            b"",
            signature
        ));
        assert!(!codec.verify_key_proof(public_key, b"", "nothex"));
        assert!(!codec.verify_key_proof(public_key, b"", &signature[..signature.len() - 2]));
    }

    #[test]
    fn generated_tokens_and_nonces_have_the_pinned_shapes() {
        let codec = codec();
        let token = codec.generate_token();
        assert!(token.starts_with("fmtenr1."), "{token}");
        assert_eq!(token.len(), "fmtenr1.".len() + 64);
        assert_eq!(codec.hash_token("anything"), codec.hash_token("anything"));
        assert_ne!(codec.hash_token("a"), codec.hash_token("b"));
        let nonce = codec.generate_nonce();
        assert_eq!(nonce.len(), 64);
        assert_ne!(nonce, codec.generate_nonce());
    }
}
