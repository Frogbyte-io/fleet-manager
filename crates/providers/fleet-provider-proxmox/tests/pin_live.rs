//! Live trust verification against the integration PVE host. Skipped
//! without `FLEET_PVE_LIVE=1` and the `PROXMOX_*` environment; the CI gate
//! never depends on it.

use fleet_core::SensitiveString;
use fleet_provider_proxmox::{
    ProxmoxClient, ProxmoxSource as _, PveCredentials, PveHttpRequest, PveTransport,
    PveTransportError, ReqwestPveTransport,
};
use std::sync::Arc;

fn live() -> Option<(String, String, String, String, String)> {
    if std::env::var("FLEET_PVE_LIVE").ok()?.trim() != "1" {
        return None;
    }
    Some((
        std::env::var("PROXMOX_HOST").ok()?,
        std::env::var("PROXMOX_PORT").unwrap_or_else(|_| "8006".to_owned()),
        std::env::var("PROXMOX_TOKEN_ID").ok()?,
        std::env::var("PROXMOX_API_KEY").ok()?,
        std::env::var("PROXMOX_FINGERPRINT").ok()?,
    ))
}

#[tokio::test]
async fn pinned_transport_converses_with_the_live_host() {
    let Some((host, port, token_id, key, fingerprint)) = live() else {
        return;
    };
    let transport = Arc::new(ReqwestPveTransport::new().unwrap());
    let request = PveHttpRequest {
        host,
        port: port.parse().unwrap(),
        path: "/api2/json/version".to_owned(),
        pinned_fingerprint: Some(fingerprint),
        credentials: Arc::new(PveCredentials {
            token_id,
            token: SensitiveString::new(key),
        }),
    };
    let client = ProxmoxClient::new(transport);
    let discovery = client.discover(request).await.unwrap();
    assert!(!discovery.version.is_empty());
    assert!(!discovery.resources.is_empty());
    assert!(
        discovery.resources.iter().any(|r| r.kind == "node"),
        "a live cluster lists at least its node"
    );
}

#[tokio::test]
async fn a_wrong_fingerprint_is_refused_at_the_handshake() {
    let Some((host, port, token_id, key, _)) = live() else {
        return;
    };
    let transport = Arc::new(ReqwestPveTransport::new().unwrap());
    let request = PveHttpRequest {
        host,
        port: port.parse().unwrap(),
        path: "/api2/json/version".to_owned(),
        // All-zero: never the real certificate.
        pinned_fingerprint: Some("00".repeat(32)),
        credentials: Arc::new(PveCredentials {
            token_id,
            token: SensitiveString::new(key),
        }),
    };
    let error = transport.execute(request).await.unwrap_err();
    match error {
        PveTransportError::FingerprintMismatch { observed, pinned } => {
            assert_eq!(pinned, Some("00".repeat(32)));
            assert_eq!(observed.len(), 32 * 2 + 31, "{observed}");
        }
        other => panic!("expected a fingerprint mismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unpinned_host_is_observed_not_conversed_with() {
    let Some((host, port, token_id, key, fingerprint)) = live() else {
        return;
    };
    let transport = Arc::new(ReqwestPveTransport::new().unwrap());
    let request = PveHttpRequest {
        host,
        port: port.parse().unwrap(),
        path: "/api2/json/version".to_owned(),
        pinned_fingerprint: None,
        credentials: Arc::new(PveCredentials {
            token_id,
            token: SensitiveString::new(key),
        }),
    };
    let error = transport.execute(request).await.unwrap_err();
    match error {
        PveTransportError::ObserveRefused { observed } => {
            assert_eq!(
                fleet_provider_proxmox::normalize_fingerprint(&observed),
                fleet_provider_proxmox::normalize_fingerprint(&fingerprint)
            );
        }
        other => panic!("expected an observe refusal, got {other:?}"),
    }
}
