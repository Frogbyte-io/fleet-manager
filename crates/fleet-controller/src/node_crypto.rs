//! The controller's node-crypto composition: the signing key that backs node
//! credentials and sessions, provisioned through the encrypted secret store.
//!
//! The HMAC key material is a secret record (`node-credential-signing-key`)
//! created on first use and re-encrypted by the store's normal rotation. It
//! is never written to disk in plaintext and never logged. Losing or
//! replacing it invalidates every outstanding node credential and session —
//! verification fails closed — which is the documented recovery story: nodes
//! re-prove or re-enroll through explicit, audited actions.
//!
//! Without a secret store there is no node trust surface: the use cases are
//! not wired, and the node endpoints answer with the standard envelope
//! rather than degrading into a mode that would mint unverifiable
//! credentials.

use fleet_application::node::{NodeCredentialClaims, NodeCrypto, NodeSessionClaims};
use fleet_secrets::{SecretRecord, SecretStore, SecretValue};

/// The secret record holding the node-credential signing key.
const SIGNING_KEY_RECORD: &str = "node-credential-signing-key";
/// The signing key length in bytes (256-bit HMAC-SHA256 keys).
const KEY_LEN: usize = 32;

/// The real [`NodeCrypto`] for the controller: a `fleet-auth` codec keyed
/// from the secret store.
#[derive(Debug)]
pub struct NodeCryptoService {
    inner: fleet_auth::node::HmacNodeCrypto,
}

impl NodeCryptoService {
    /// Opens the service against the secret store, provisioning the signing
    /// key record on first use.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot list or resolve records, when the key
    /// record exists but has the wrong shape, or when randomness is
    /// unavailable. The controller refuses to start rather than minting
    /// credentials under a key it does not understand.
    pub async fn open(store: &SecretStore) -> Result<Self, String> {
        let value = if let Some(record) = find_record(store, SIGNING_KEY_RECORD).await? {
            store
                .resolve(&record.id)
                .await
                .map_err(|error| format!("cannot resolve the node signing key record: {error}"))?
        } else {
            let mut bytes = [0_u8; KEY_LEN];
            getrandom::getrandom(&mut bytes)
                .map_err(|error| format!("cannot generate the node signing key: {error}"))?;
            let created = store
                .create(SIGNING_KEY_RECORD, SecretValue::new(bytes.to_vec()))
                .await
                .map_err(|error| format!("cannot store the node signing key: {error}"))?;
            eprintln!(
                "provisioned a new node-credential signing key (record {})",
                created.id
            );
            store
                .resolve(&created.id)
                .await
                .map_err(|error| format!("cannot re-read the node signing key: {error}"))?
        };
        let key: [u8; KEY_LEN] = value
            .expose()
            .try_into()
            .map_err(|_| "the node signing key record does not hold 32 bytes".to_owned())?;
        Ok(Self {
            inner: fleet_auth::node::HmacNodeCrypto::new(key),
        })
    }
}

async fn find_record(store: &SecretStore, name: &str) -> Result<Option<SecretRecord>, String> {
    store
        .list()
        .await
        .map(|records| records.into_iter().find(|record| record.name == name))
        .map_err(|error| format!("cannot list secret records: {error}"))
}

impl NodeCrypto for NodeCryptoService {
    fn generate_token(&self) -> String {
        self.inner.generate_token()
    }

    fn hash_token(&self, token: &str) -> String {
        self.inner.hash_token(token)
    }

    fn generate_nonce(&self) -> String {
        self.inner.generate_nonce()
    }

    fn verify_key_proof(&self, public_key: &str, message: &[u8], signature_hex: &str) -> bool {
        self.inner
            .verify_key_proof(public_key, message, signature_hex)
    }

    fn issue_credential_token(&self, claims: &NodeCredentialClaims) -> Result<String, String> {
        self.inner.issue_credential_token(claims)
    }

    fn verify_credential_token(&self, token: &str) -> Result<NodeCredentialClaims, String> {
        self.inner.verify_credential_token(token)
    }

    fn issue_session_token(&self, claims: &NodeSessionClaims) -> Result<String, String> {
        self.inner.issue_session_token(claims)
    }

    fn verify_session_token(&self, token: &str) -> Result<NodeSessionClaims, String> {
        self.inner.verify_session_token(token)
    }
}
