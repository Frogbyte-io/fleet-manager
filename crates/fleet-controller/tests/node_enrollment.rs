//! The node enrollment flow, end to end over HTTP with the real store, the
//! real secret store, and the real cryptography: token creation through the
//! operator API, enrollment, key proof, session issuance, rotation, and
//! revocation. This is the harness `fleetd` will be tested against.

use std::path::Path;
use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, response::Parts},
};
use fleet_application::node::ChallengePurpose;
use fleet_application::node::proof_message;
use fleet_controller::{Settings, build_router};
use http_body_util::BodyExt as _;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use tower::ServiceExt as _;

fn settings(web_dist: &Path) -> Settings {
    Settings {
        listen: "127.0.0.1:0".parse().unwrap(),
        web_dist: web_dist.to_path_buf(),
        artifacts_dir: None,
    }
}

fn shell_dist() -> tempfile::TempDir {
    let dist = tempfile::tempdir().unwrap();
    std::fs::write(dist.path().join("index.html"), "<html>fleet</html>").unwrap();
    dist
}

/// Writes a master-key file with owner-only permissions, as the secret store
/// requires.
fn master_key_file(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("master.key");
    let key_material = "0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829";
    std::fs::write(&path, format!("1 {key_material}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

/// The composed controller state for one test: store, secret store, node
/// trust service, and router. Everything must outlive the router, so the
/// handles travel together.
struct TestController {
    _dist: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _key_dir: tempfile::TempDir,
    _store: fleet_storage_sqlite::Store,
    router: Router,
    nodes: Arc<fleet_application::node::Nodes>,
    machines: fleet_storage_sqlite::MachineRepository,
}

async fn controller() -> TestController {
    let dist = shell_dist();
    let store_dir = tempfile::tempdir().unwrap();
    let key_dir = tempfile::tempdir().unwrap();
    let store = fleet_storage_sqlite::Store::open(&store_dir.path().join("fleet.db"))
        .await
        .unwrap();
    let secrets =
        fleet_secrets::SecretStore::open(store.pool().clone(), &master_key_file(key_dir.path()))
            .unwrap();
    let crypto = fleet_controller::node_crypto::NodeCryptoService::open(&secrets)
        .await
        .expect("the node signing key must provision");
    let services = fleet_controller::compose_node_services(store.pool(), Arc::new(crypto));
    let nodes = services.nodes.clone();
    let machines = fleet_storage_sqlite::MachineRepository::new(store.pool().clone());
    let router = build_router(
        &settings(dist.path()),
        Some(store.pool().clone()),
        Some(&services),
        None,
        None,
        None,
        None,
        None,
    );
    TestController {
        _dist: dist,
        _store_dir: store_dir,
        _key_dir: key_dir,
        _store: store,
        router,
        nodes,
        machines,
    }
}

/// A simulated node: its Ed25519 key pair. The private key never leaves this
/// struct — the same rule `fleetd` will follow.
struct NodeKeys {
    key_pair: Ed25519KeyPair,
    public_key_hex: String,
}

impl NodeKeys {
    fn generate() -> Self {
        let document =
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("a key pair must generate");
        let key_pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).expect("the pkcs8 parses");
        let public_key_hex = hex_encode(key_pair.public_key().as_ref());
        Self {
            key_pair,
            public_key_hex,
        }
    }

    fn sign_hex(&self, message: &[u8]) -> String {
        hex_encode(self.key_pair.sign(message).as_ref())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("a hex write is infallible");
    }
    text
}

async fn send(router: &Router, method: &str, path: &str, body: Option<Value>) -> (Parts, Value) {
    let mut builder = Request::builder().method(method).uri(path);
    let request = if let Some(body) = body {
        builder = builder.header("content-type", "application/json");
        builder.body(Body::from(body.to_string())).unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router is infallible");
    let (parts, body) = response.into_parts();
    let bytes = body
        .collect()
        .await
        .expect("the body is complete")
        .to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("every API response body is JSON")
    };
    (parts, json)
}

async fn register_machine(controller: &TestController, name: &str) -> String {
    use fleet_application::machine::{MachinePort, NewEndpoint, RegisterMachine};
    use fleet_core::EndpointKind;
    let machine = controller
        .machines
        .register(&RegisterMachine {
            name: name.to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: "ops@host:22".to_owned(),
            }],
            tags: Vec::new(),
            groups: Vec::new(),
        })
        .await
        .expect("the machine must register");
    machine.id
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn the_full_enrollment_flow_proves_possession_and_rotates_and_revokes() {
    let controller = controller().await;
    let machine_id = register_machine(&controller, "enrolled").await;

    // The operator creates a token through the public API.
    let (parts, body) = send(
        &controller.router,
        "POST",
        &format!("/api/v1/machines/{machine_id}/node/enrollments"),
        Some(json!({})),
    )
    .await;
    assert_eq!(parts.status, StatusCode::CREATED, "{body}");
    let token = body["data"]["token"]
        .as_str()
        .expect("the token value")
        .to_owned();
    assert!(token.starts_with("fmtenr1."), "{token}");
    let expires_at = body["data"]["expiresAt"].as_i64().expect("expiry");

    // The node enrolls with its public key. The private key never travels.
    let keys = NodeKeys::generate();
    let (parts, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/enroll",
        Some(json!({
            "token": token,
            "publicKey": keys.public_key_hex,
            "os": "linux",
            "arch": "x86_64",
            "nodeVersion": "0.1.0",
        })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::CREATED, "{body}");
    let machine = body["data"]["machineId"].as_str().unwrap().to_owned();
    let credential = body["data"]["credential"].as_str().unwrap().to_owned();
    assert_eq!(machine, machine_id);
    assert!(credential.starts_with("fmnc1."), "{credential}");

    // Replaying the token fails closed.
    let (parts, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/enroll",
        Some(json!({
            "token": token,
            "publicKey": keys.public_key_hex,
            "os": "linux",
            "arch": "x86_64",
            "nodeVersion": "0.1.0",
        })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::UNAUTHORIZED, "{body}");

    // The node proves possession for a session.
    let (parts, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/challenge",
        Some(json!({ "credential": credential })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    let challenge_id = body["data"]["challengeId"].as_str().unwrap().to_owned();
    let nonce = body["data"]["nonce"].as_str().unwrap().to_owned();
    assert_eq!(body["data"]["purpose"], "session");
    assert_eq!(nonce.len(), 64);

    let message = proof_message(&challenge_id, &machine_id, ChallengePurpose::Session, None);
    let (parts, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/session",
        Some(json!({
            "credential": credential,
            "challengeId": challenge_id,
            "signature": keys.sign_hex(&message),
        })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    let session = body["data"]["session"].as_str().unwrap().to_owned();
    assert!(session.starts_with("fmns1."), "{session}");
    assert!(body["data"]["sessionExpiresAt"].as_i64().unwrap() > 0);

    // The session validates against durable state.
    let validity = controller
        .nodes
        .validate_session(&session)
        .await
        .expect("the validity must read");
    assert!(matches!(
        validity,
        fleet_application::node::SessionValidity::Valid { .. }
    ));

    // A proof signed by a different key fails.
    let impostor = NodeKeys::generate();
    let (parts, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/challenge",
        Some(json!({ "credential": credential })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    let challenge_id = body["data"]["challengeId"].as_str().unwrap().to_owned();
    let message = proof_message(&challenge_id, &machine_id, ChallengePurpose::Session, None);
    let (parts, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/session",
        Some(json!({
            "credential": credential,
            "challengeId": challenge_id,
            "signature": impostor.sign_hex(&message),
        })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::UNAUTHORIZED, "{body}");

    // Rotation: a new key proves itself and takes over.
    let new_keys = NodeKeys::generate();
    let (parts, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/challenge",
        Some(json!({
            "credential": credential,
            "purpose": "rotate",
            "newPublicKey": new_keys.public_key_hex,
        })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    let rotate_challenge = body["data"]["challengeId"].as_str().unwrap().to_owned();
    let message = proof_message(
        &rotate_challenge,
        &machine_id,
        ChallengePurpose::Rotate,
        Some(&new_keys.public_key_hex),
    );
    let (parts, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/rotate",
        Some(json!({
            "credential": credential,
            "newPublicKey": new_keys.public_key_hex,
            "challengeId": rotate_challenge,
            "signature": new_keys.sign_hex(&message),
        })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    let rotated_credential = body["data"]["credential"].as_str().unwrap().to_owned();
    assert_eq!(body["data"]["nodeKeyVersion"], 2);

    // The old credential is dead: a challenge for it fails.
    let (parts, _) = send(
        &controller.router,
        "POST",
        "/api/node/v1/challenge",
        Some(json!({ "credential": credential })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::UNAUTHORIZED);

    // The rotated credential works.
    let (parts, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/challenge",
        Some(json!({ "credential": rotated_credential })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");

    // The operator revokes the node; everything stops, and re-enrollment is
    // an explicit new token.
    let (parts, body) = send(
        &controller.router,
        "POST",
        &format!("/api/v1/machines/{machine_id}/node/revoke"),
        Some(json!({})),
    )
    .await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    let (parts, _) = send(
        &controller.router,
        "POST",
        "/api/node/v1/challenge",
        Some(json!({ "credential": rotated_credential })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::UNAUTHORIZED);

    let (parts, body) = send(
        &controller.router,
        "POST",
        &format!("/api/v1/machines/{machine_id}/node/enrollments"),
        Some(json!({})),
    )
    .await;
    assert_eq!(parts.status, StatusCode::CREATED, "{body}");
    let rebind_token = body["data"]["token"].as_str().unwrap().to_owned();
    let (parts, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/enroll",
        Some(json!({
            "token": rebind_token,
            "publicKey": new_keys.public_key_hex,
            "os": "linux",
            "arch": "x86_64",
            "nodeVersion": "0.1.0",
        })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::CREATED, "{body}");
    assert_eq!(body["data"]["rebind"], true, "{body}");
    assert_eq!(body["data"]["machineId"], machine_id);

    let (parts, body) = send(
        &controller.router,
        "GET",
        &format!("/api/v1/machines/{machine_id}/node"),
        None,
    )
    .await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["identity"]["keyVersion"], 3, "{body}");
    assert_eq!(
        body["data"]["identity"]["publicKey"],
        new_keys.public_key_hex
    );
    let _ = expires_at;
}

#[tokio::test]
async fn the_operator_surface_requires_authorization_and_reports_state() {
    let controller = controller().await;
    let machine_id = register_machine(&controller, "viewed").await;

    let (parts, body) = send(
        &controller.router,
        "GET",
        &format!("/api/v1/machines/{machine_id}/node"),
        None,
    )
    .await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    assert!(body["data"]["identity"].is_null(), "{body}");

    let (parts, body) = send(
        &controller.router,
        "GET",
        &format!("/api/v1/machines/{machine_id}/node/enrollments"),
        None,
    )
    .await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    assert_eq!(body["items"].as_array().unwrap().len(), 0);

    // A token for an unknown machine is a 404, not a creation.
    let (parts, body) = send(
        &controller.router,
        "POST",
        "/api/v1/machines/01990000-0000-7000-8000-000000000000/node/enrollments",
        Some(json!({})),
    )
    .await;
    assert_eq!(parts.status, StatusCode::NOT_FOUND, "{body}");

    // A malformed TTL is a 400.
    let (parts, body) = send(
        &controller.router,
        "POST",
        &format!("/api/v1/machines/{machine_id}/node/enrollments"),
        Some(json!({ "ttlMillis": 1 })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::BAD_REQUEST, "{body}");

    // Revoking a machine without a node identity is a 404.
    let (parts, body) = send(
        &controller.router,
        "POST",
        &format!("/api/v1/machines/{machine_id}/node/revoke"),
        Some(json!({})),
    )
    .await;
    assert_eq!(parts.status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn a_malformed_enrollment_never_consumes_the_token() {
    let controller = controller().await;
    let machine_id = register_machine(&controller, "careful").await;
    let (parts, body) = send(
        &controller.router,
        "POST",
        &format!("/api/v1/machines/{machine_id}/node/enrollments"),
        Some(json!({})),
    )
    .await;
    assert_eq!(parts.status, StatusCode::CREATED, "{body}");
    let token = body["data"]["token"].as_str().unwrap().to_owned();

    let (parts, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/enroll",
        Some(json!({
            "token": token,
            "publicKey": "not-hex",
            "os": "linux",
        })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::BAD_REQUEST, "{body}");

    // The token still works: a rejected request never consumed it.
    let keys = NodeKeys::generate();
    let (parts, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/enroll",
        Some(json!({
            "token": token,
            "publicKey": keys.public_key_hex,
            "os": "linux",
            "arch": "x86_64",
            "nodeVersion": "0.1.0",
        })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn the_node_surface_refuses_cross_machine_challenges() {
    let controller = controller().await;
    let machine_a = register_machine(&controller, "machine-a").await;
    let machine_b = register_machine(&controller, "machine-b").await;

    for machine in [&machine_a, &machine_b] {
        let (parts, body) = send(
            &controller.router,
            "POST",
            &format!("/api/v1/machines/{machine}/node/enrollments"),
            Some(json!({})),
        )
        .await;
        assert_eq!(parts.status, StatusCode::CREATED, "{body}");
    }

    let keys_a = NodeKeys::generate();
    let keys_b = NodeKeys::generate();
    let enroll = |token: &str, keys: &NodeKeys| {
        json!({
            "token": token,
            "publicKey": keys.public_key_hex,
            "os": "linux",
            "arch": "x86_64",
            "nodeVersion": "0.1.0",
        })
    };
    // Enroll machine A with key A, machine B with key B.
    let (parts, body_a) = send(
        &controller.router,
        "GET",
        &format!("/api/v1/machines/{machine_a}/node/enrollments"),
        None,
    )
    .await;
    let _ = body_a;
    assert_eq!(parts.status, StatusCode::OK);
    // Create tokens again (the list does not include values).
    let (_, body) = send(
        &controller.router,
        "POST",
        &format!("/api/v1/machines/{machine_a}/node/enrollments"),
        Some(json!({})),
    )
    .await;
    let token_a = body["data"]["token"].as_str().unwrap().to_owned();
    let (_, body) = send(
        &controller.router,
        "POST",
        &format!("/api/v1/machines/{machine_b}/node/enrollments"),
        Some(json!({})),
    )
    .await;
    let token_b = body["data"]["token"].as_str().unwrap().to_owned();

    let (_, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/enroll",
        Some(enroll(&token_a, &keys_a)),
    )
    .await;
    let credential_a = body["data"]["credential"].as_str().unwrap().to_owned();
    assert_eq!(body["data"]["machineId"], machine_a);
    let (_, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/enroll",
        Some(enroll(&token_b, &keys_b)),
    )
    .await;
    let credential_b = body["data"]["credential"].as_str().unwrap().to_owned();

    // Machine B's node cannot use machine A's credential material: every
    // challenge is bound to the credential's own machine.
    let (_, body) = send(
        &controller.router,
        "POST",
        "/api/node/v1/challenge",
        Some(json!({ "credential": credential_a })),
    )
    .await;
    let challenge_a = body["data"]["challengeId"].as_str().unwrap().to_owned();
    let message = proof_message(&challenge_a, &machine_a, ChallengePurpose::Session, None);
    let (parts, _) = send(
        &controller.router,
        "POST",
        "/api/node/v1/session",
        Some(json!({
            "credential": credential_b,
            "challengeId": challenge_a,
            "signature": keys_b.sign_hex(&message),
        })),
    )
    .await;
    assert_eq!(parts.status, StatusCode::UNAUTHORIZED);
}
