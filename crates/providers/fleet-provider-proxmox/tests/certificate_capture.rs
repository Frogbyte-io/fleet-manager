//! The credential-free certificate capture (#284) against a local TLS
//! server shaped like pveproxy: a leaf signed by a private cluster CA,
//! served without the CA.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fleet_provider_proxmox::{PveTransport as _, ReqwestPveTransport, certificate_names_host};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::Digest as _;
use tokio::io::AsyncReadExt as _;

/// A leaf for `names`, signed by a fresh CA (not self-signed, like
/// `pve-ssl.pem` under `pve-root-ca`), and its key.
fn pve_like_leaf(names: &[&str]) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
    )
    .unwrap()
    .signed_by(&leaf_key, &issuer)
    .unwrap();
    (
        leaf.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
}

/// Serves `leaf` on a loopback port; counts the application bytes any
/// client managed to send after a completed handshake.
async fn serve(
    leaf: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (u16, Arc<AtomicUsize>) {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![leaf], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&received);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut buffer = vec![0_u8; 4096];
                    while let Ok(read) = tls.read(&mut buffer).await {
                        if read == 0 {
                            break;
                        }
                        counter.fetch_add(read, Ordering::SeqCst);
                    }
                }
            });
        }
    });
    (port, received)
}

#[tokio::test]
async fn the_capture_returns_the_served_leaf_and_sends_nothing() {
    let (leaf, key) = pve_like_leaf(&["127.0.0.1", "pve.example.test"]);
    let (port, received) = serve(leaf.clone(), key).await;
    let observed = ReqwestPveTransport::new()
        .observe_certificate("127.0.0.1", port)
        .await
        .expect("the probe captures the leaf");
    assert_eq!(observed.der, leaf.as_ref());
    let digest: [u8; 32] = sha2::Sha256::digest(leaf.as_ref()).into();
    let expected = digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    assert_eq!(observed.fingerprint, expected);
    // The handshake was refused by the client after capture: no request
    // byte, and so no credential, reached the server.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(received.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_unreachable_host_reports_no_certificate() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    assert!(
        ReqwestPveTransport::new()
            .observe_certificate("127.0.0.1", port)
            .await
            .is_err()
    );
}

#[test]
fn the_name_check_follows_the_san_rules_go_applies() {
    let (leaf, _) = pve_like_leaf(&["127.0.0.1", "pve1", "pve1.example.test", "::1"]);
    assert!(certificate_names_host(leaf.as_ref(), "127.0.0.1"));
    assert!(certificate_names_host(leaf.as_ref(), "pve1.example.test"));
    assert!(certificate_names_host(leaf.as_ref(), "pve1"));
    assert!(certificate_names_host(leaf.as_ref(), "::1"));
    assert!(certificate_names_host(leaf.as_ref(), "[::1]"));
    // A name or address the leaf does not list is not covered, and an IP
    // never matches a DNS-only leaf.
    assert!(!certificate_names_host(leaf.as_ref(), "192.0.2.10"));
    assert!(!certificate_names_host(leaf.as_ref(), "pve2.example.test"));
    let (dns_only, _) = pve_like_leaf(&["pve1.example.test"]);
    assert!(!certificate_names_host(dns_only.as_ref(), "127.0.0.1"));
    // Bytes that are not a certificate never name anything.
    assert!(!certificate_names_host(b"not a certificate", "127.0.0.1"));
}
