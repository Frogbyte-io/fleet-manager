//! The node session lifecycle: credential in, short-lived session out.
//!
//! Every gateway connection begins with a key proof over HTTP: the node
//! presents its credential, receives a single-use nonce, signs the canonical
//! proof message with its private key, and exchanges the verified proof for
//! a session. The session then travels as a header on the WebSocket upgrade.
//! Sessions are short-lived, so this runs on every (re)connection.

use std::time::Duration;

use fleet_application::node::{ChallengePurpose, proof_message};

use crate::http::Controller;
use crate::state::NodeState;

/// The proof timeout: the controller is on the LAN; seconds, not minutes.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// The session a successful proof obtained.
#[derive(Clone, Debug)]
pub struct NodeSession {
    /// The session token for the upgrade header.
    pub token: String,
    /// Expiry, in epoch milliseconds.
    pub expires_at: i64,
}

/// Exchanges the stored credential for a fresh session by key proof.
///
/// # Errors
///
/// Fails on transport errors or a refusal from the controller; the error
/// text is caller-safe because the controller's messages are.
pub fn prove(controller: &Controller, state: &NodeState) -> Result<NodeSession, String> {
    let Some(credential) = state.credential() else {
        return Err("the node is not enrolled: run `fleetd enroll` first".to_owned());
    };
    let (status, challenge) = controller.post_json(
        "/api/node/v1/challenge",
        &serde_json::json!({ "credential": credential }),
        HTTP_TIMEOUT,
    )?;
    if status != 200 {
        return Err(format!(
            "the controller refused the credential (status {status}): {}",
            error_detail(&challenge)
        ));
    }
    let challenge_id = challenge["data"]["challengeId"]
        .as_str()
        .ok_or("the challenge response has no challengeId")?
        .to_owned();
    let machine_id = challenge["data"]["machineId"]
        .as_str()
        .ok_or("the challenge response has no machineId")?
        .to_owned();

    let message = proof_message(&challenge_id, &machine_id, ChallengePurpose::Session, None);
    let signature = state.sign_proof(&message);

    let (status, session) = controller.post_json(
        "/api/node/v1/session",
        &serde_json::json!({
            "credential": credential,
            "challengeId": challenge_id,
            "signature": signature,
        }),
        HTTP_TIMEOUT,
    )?;
    if status != 200 {
        return Err(format!(
            "the controller refused the key proof (status {status}): {}",
            error_detail(&session)
        ));
    }
    Ok(NodeSession {
        token: session["data"]["session"]
            .as_str()
            .ok_or("the session response has no token")?
            .to_owned(),
        expires_at: session["data"]["sessionExpiresAt"].as_i64().unwrap_or(0),
    })
}

/// Enrolls the node: consumes a one-time token, binds the node's public
/// key, and stores the returned credential. The private key never leaves
/// the node.
///
/// # Errors
///
/// Fails on transport errors or a refusal from the controller.
pub fn enroll(controller: &Controller, state: &NodeState, token: &str) -> Result<(), String> {
    let key_pair = public_key_of(state)?;
    let (status, body) = controller.post_json(
        "/api/node/v1/enroll",
        &serde_json::json!({
            "token": token,
            "publicKey": key_pair,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "nodeVersion": env!("CARGO_PKG_VERSION"),
        }),
        HTTP_TIMEOUT,
    )?;
    if status != 201 {
        return Err(format!(
            "the controller refused the enrollment (status {status}): {}",
            error_detail(&body)
        ));
    }
    let machine_id = body["data"]["machineId"]
        .as_str()
        .ok_or("the enrollment response has no machineId")?
        .to_owned();
    let credential = body["data"]["credential"]
        .as_str()
        .ok_or("the enrollment response has no credential")?
        .to_owned();
    state.store_enrollment(&machine_id, &credential)?;
    eprintln!("fleetd: enrolled as machine {machine_id}; credential stored in the state directory");
    Ok(())
}

fn public_key_of(state: &NodeState) -> Result<String, String> {
    // The key pair derives the public key at load; surface it through the
    // state's stored hex to keep a single source of truth.
    if state.public_key_hex().len() != 64 {
        return Err("the node key is malformed".to_owned());
    }
    Ok(state.public_key_hex().to_owned())
}

fn error_detail(body: &serde_json::Value) -> String {
    body["message"].as_str().unwrap_or("no detail").to_owned()
}
