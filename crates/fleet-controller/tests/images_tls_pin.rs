//! Packer's Proxmox plugin trusts exactly the pinned leaf (#284), proven
//! with the operator-installed Packer CLI and plugin against a local TLS
//! server shaped like pveproxy: a leaf signed by a private CA, served
//! without the CA, so nothing but the pin can make it verify.
//!
//! Skipped unless `FLEET_PACKER_LIVE=1`: it needs `packer` (FM-S09 pins)
//! and the Proxmox plugin installed. It never contacts a Proxmox host.
//!
//! - The pinned leaf: the plugin completes the handshake and sends its
//!   first API request, so Go accepted a CA-less leaf through the pin.
//! - A leaf that changes after Fleet's own pin check: the plugin's
//!   handshake fails, and the server receives no request byte at all, so
//!   the token never left.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision};
use fleet_application::images::{Images, NewRecipe, RecipePort as _};
use fleet_application::operation::{NewOperation, Operations};
use fleet_core::{RecipeContent, RecipeSource};
use fleet_storage_sqlite::{AuditSink, OperationRepository, RecipeRepository, Store};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::Digest as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Debug)]
struct Allow;
impl Authorizer for Allow {
    fn decide(&self, _: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

#[derive(Debug)]
struct Token;
#[async_trait::async_trait]
impl fleet_application::proxmox::ProxmoxCredentialStore for Token {
    async fn load(
        &self,
        _: &str,
    ) -> Result<Option<String>, fleet_application::proxmox::CredentialStoreError> {
        Ok(Some("00000000-fixture-token".to_owned()))
    }
    async fn store(
        &self,
        _: &str,
        _: &str,
    ) -> Result<(), fleet_application::proxmox::CredentialStoreError> {
        Ok(())
    }
    async fn clear(&self, _: &str) -> Result<(), fleet_application::proxmox::CredentialStoreError> {
        Ok(())
    }
}

fn live() -> bool {
    std::env::var("FLEET_PACKER_LIVE").is_ok_and(|value| value.trim() == "1")
}

/// A pveproxy-shaped leaf for 127.0.0.1: signed by a throwaway CA that is
/// never served or trusted.
fn leaf() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned(), "localhost".to_owned()])
            .unwrap();
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.signed_by(&key, &issuer).unwrap();
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

fn acceptor(leaf: &(CertificateDer<'static>, PrivateKeyDer<'static>)) -> tokio_rustls::TlsAcceptor {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![leaf.0.clone()], leaf.1.clone_key())
    .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// What the server saw: handshakes completed, and request bytes received
/// (with whether any carried the token header).
#[derive(Debug, Default)]
struct Seen {
    connections: AtomicUsize,
    handshakes: AtomicUsize,
    request_bytes: AtomicUsize,
    token_headers: AtomicUsize,
}

/// Serves `first` on the first connection (Fleet's credential-free pin
/// check) and `later` on every one after it (Packer's plugin).
async fn serve(
    first: tokio_rustls::TlsAcceptor,
    later: tokio_rustls::TlsAcceptor,
) -> (u16, Arc<Seen>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Seen::default());
    let shared = Arc::clone(&seen);
    tokio::spawn(async move {
        let mut connections = 0_usize;
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = if connections == 0 {
                first.clone()
            } else {
                later.clone()
            };
            connections += 1;
            shared.connections.fetch_add(1, Ordering::SeqCst);
            let seen = Arc::clone(&shared);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                seen.handshakes.fetch_add(1, Ordering::SeqCst);
                // Read the whole request head: one read can return a part.
                let mut buffer = vec![0_u8; 8192];
                let mut request = Vec::new();
                loop {
                    let Ok(read) = tls.read(&mut buffer).await else {
                        return;
                    };
                    if read == 0 {
                        break;
                    }
                    seen.request_bytes.fetch_add(read, Ordering::SeqCst);
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                if String::from_utf8_lossy(&request).contains("PVEAPIToken=") {
                    seen.token_headers.fetch_add(1, Ordering::SeqCst);
                }
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 401 fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (port, seen)
}

/// Builds one recipe against `port` with the account pinned to `pinned`;
/// answers the build record's outcome and reason.
async fn build(port: u16, pinned: &CertificateDer<'static>) -> (String, Option<String>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let digest: [u8; 32] = sha2::Sha256::digest(pinned.as_ref()).into();
    let pin: String = digest.iter().map(|byte| format!("{byte:02X}")).collect();
    sqlx::query("INSERT INTO proxmox_accounts (id, name, host, port, token_id, fingerprint, created_at) VALUES ('account-1', 'fixture', '127.0.0.1', ?1, 'fixture@pve!builder', ?2, 1)")
        .bind(i64::from(port))
        .bind(pin)
        .execute(store.pool())
        .await
        .unwrap();
    let repository = Arc::new(RecipeRepository::new(store.pool().clone()));
    let audit = Arc::new(AuditSink::new(store.pool().clone()));
    let images = Images::new(repository.clone(), audit.clone());
    let principal = ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    };
    let content = serde_json::json!({"builders": [{
        "type": "proxmox-clone",
        "proxmox_url": format!("https://127.0.0.1:{port}/api2/json"),
        "node": "pve",
        "clone_vm_id": 9000,
        "vm_id": 949,
        "vm_name": "fleet-tls-pin",
        "template_name": "fleet-tls-pin",
        "communicator": "none",
        "task_timeout": "30s"
    }]})
    .to_string();
    let recipe = images
        .create(
            &Allow,
            &principal,
            NewRecipe {
                content: RecipeContent {
                    name: "tls-pin".to_owned(),
                    description: String::new(),
                    node: "pve".to_owned(),
                    storage_pool: Some("local-lvm".to_owned()),
                    source: RecipeSource::Clone,
                    content,
                },
            },
            1,
        )
        .await
        .unwrap();
    let version = images
        .publish(&Allow, &principal, &recipe.id, 2)
        .await
        .unwrap();
    let operations = Operations::new(
        Arc::new(OperationRepository::new(store.pool().clone())),
        audit,
    );
    operations
        .create(
            &Allow,
            &principal.id,
            &NewOperation {
                kind: "image.build".to_owned(),
                payload_json: Some(
                    serde_json::json!({"versionId": version.id, "timeoutSeconds": 120, "accountId": "account-1"})
                        .to_string(),
                ),
                idempotency_key: None,
                deadline_at: None,
                correlation_id: None,
                review_token: None,
            },
        )
        .await
        .unwrap();
    let mut report = fleet_application::worker::TickReport::default();
    let operation = operations
        .claim_only(
            "tls-pin",
            fleet_core::SystemClock::now_unix_millis(),
            &mut report,
        )
        .await
        .unwrap()
        .unwrap();
    let executor = fleet_controller::images_exec::ImagesExecutor::new(
        repository.clone(),
        Arc::new(fleet_provider_packer::ProcessTransport::new()),
        None,
        dir.path().join("work"),
    )
    .with_account_credentials(
        Arc::new(fleet_storage_sqlite::ProxmoxAccountRepository::new(
            store.pool().clone(),
        )),
        Arc::new(Token),
        Arc::new(fleet_provider_proxmox::ReqwestPveTransport::new()),
    );
    assert!(
        operations
            .execute_claimed(&executor, operation.clone())
            .await
    );
    let record = repository.get_build(&operation.id).await.unwrap();
    (record.outcome, record.reason)
}

#[tokio::test]
async fn the_plugin_accepts_the_pinned_ca_less_leaf() {
    if !live() {
        eprintln!("skipped: set FLEET_PACKER_LIVE=1 with packer and the Proxmox plugin installed");
        return;
    }
    let pinned = leaf();
    let (port, seen) = serve(acceptor(&pinned), acceptor(&pinned)).await;
    let (outcome, reason) = build(port, &pinned.0).await;
    // The fixture answers 401, so the build fails, but only after the
    // plugin verified the pinned leaf and sent its first request.
    assert_eq!(outcome, "failed");
    assert_eq!(reason.as_deref(), Some("build_failed"));
    assert!(seen.handshakes.load(Ordering::SeqCst) >= 1, "{seen:?}");
    assert!(seen.token_headers.load(Ordering::SeqCst) >= 1, "{seen:?}");
}

#[tokio::test]
async fn a_leaf_changed_after_the_pin_check_never_receives_the_token() {
    if !live() {
        eprintln!("skipped: set FLEET_PACKER_LIVE=1 with packer and the Proxmox plugin installed");
        return;
    }
    let pinned = leaf();
    let swapped = leaf();
    let (port, seen) = serve(acceptor(&pinned), acceptor(&swapped)).await;
    let (outcome, reason) = build(port, &pinned.0).await;
    assert_eq!(outcome, "failed");
    assert_eq!(reason.as_deref(), Some("build_failed"));
    // Fleet's check passed on the first connection, and the plugin did
    // connect (so the build did not fail before reaching the network); its
    // handshake against the swapped leaf failed, so nothing was sent.
    assert!(seen.connections.load(Ordering::SeqCst) >= 2, "{seen:?}");
    assert_eq!(seen.handshakes.load(Ordering::SeqCst), 0, "{seen:?}");
    assert_eq!(seen.request_bytes.load(Ordering::SeqCst), 0, "{seen:?}");
}
