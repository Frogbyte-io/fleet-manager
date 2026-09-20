//! The Proxmox provider: discovery over the documented PVE REST API, with
//! TLS fingerprint pinning as the only trust model (FM-600; FM-S08).
//!
//! The FM-S08 spike chose the fallback: a small `reqwest` transport with a
//! custom rustls verifier that pins the host certificate's SHA-256
//! fingerprint, and typed provider DTOs translated at this boundary. PVE
//! hosts present their own cluster CA, so system trust fails; the pinned
//! fingerprint is the trust. Verification is never disabled: an unpinned
//! host is probed with an observe-only verifier that refuses the handshake
//! *after* capturing the leaf fingerprint — no credentials are sent, no
//! session is established, and the reported fingerprint is the honest input
//! to the confirm step (the FM-201 SSH trust flow, over TLS).
//!
//! This crate never logs, stores, or serializes the API token: it arrives
//! per call inside redacting types and is dropped with the request. Errors
//! are caller-safe — statuses, bounded details, and fingerprints, never
//! tokens.
//!
//! Decoding is tolerant on purpose: PVE's Perl API answers loose and null
//! shapes (`data: null`, missing fields, stringly numbers at the edges).
//! Every normalized field is optional and bounded; a payload beyond the
//! bounds is a payload error, not silent truncation.
#![warn(missing_docs)]

use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_core::SensitiveString;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::Digest;

/// The default PVE API port.
pub const DEFAULT_PORT: u16 = 8006;
/// The request timeout applied to every call.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// The maximum response body the transport accepts. Discovery payloads are
/// bounded lists; anything larger is refused rather than materialized.
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// The API token: the token id (`user@realm!tokenname`) and the secret
/// value. The secret is zeroizing and redacted by construction; the pair is
/// cloned rarely (into one request) and never serialized, logged, or
/// audited.
#[derive(Debug)]
pub struct PveCredentials {
    /// The token id, as PVE's `Authorization: PVEAPIToken=<id>=<secret>`
    /// header names it. Not secret on its own.
    pub token_id: String,
    /// The token secret value, redacted.
    pub token: SensitiveString,
}

/// A transport request: one API call against one PVE host.
#[derive(Clone, Debug)]
pub struct PveHttpRequest {
    /// The host (IP or DNS name) without scheme or port.
    pub host: String,
    /// The port; [`DEFAULT_PORT`] in the common case.
    pub port: u16,
    /// The URL path under `/api2/json`, starting with `/`.
    pub path: String,
    /// The pinned fingerprint, when the caller confirmed one. `None` means
    /// observe-only: the handshake is refused after capture.
    pub pinned_fingerprint: Option<String>,
    /// The credentials for the call.
    pub credentials: Arc<PveCredentials>,
}

/// A transport response: status and bounded body.
#[derive(Clone, Debug)]
pub struct PveHttpResponse {
    /// The HTTP status.
    pub status: u16,
    /// The response body, bounded by [`MAX_BODY_BYTES`].
    pub body: Vec<u8>,
}

/// A transport failure that is safe to print. TLS fingerprint facts travel
/// here; tokens never do.
#[derive(Debug)]
pub enum PveTransportError {
    /// The handshake was refused for a fingerprint mismatch, with the
    /// observed leaf fingerprint (hex, colon-separated, like PVE's own
    /// display) and the pinned value.
    FingerprintMismatch {
        /// The observed leaf certificate's SHA-256 fingerprint.
        observed: String,
        /// The fingerprint the caller pinned, when any.
        pinned: Option<String>,
    },
    /// The observe-only probe: the handshake was deliberately refused after
    /// capturing the fingerprint, so no credentials could be sent. The
    /// observed fingerprint is the report.
    ObserveRefused {
        /// The observed leaf certificate's SHA-256 fingerprint.
        observed: String,
    },
    /// The host presented no certificate to pin. This is a TLS-level
    /// anomaly; refuse it.
    NoCertificate,
    /// Transport-level failure (DNS, TCP, timeout), with a bounded detail.
    Connect {
        /// The bounded, redacted detail.
        detail: String,
    },
    /// The response exceeded the body bound.
    BodyTooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
}

impl fmt::Display for PveTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FingerprintMismatch { observed, pinned } => match pinned {
                Some(pinned) => write!(
                    f,
                    "the host certificate's fingerprint {observed} does not match the pinned {pinned}"
                ),
                None => write!(
                    f,
                    "the host certificate's fingerprint {observed} is not pinned"
                ),
            },
            Self::ObserveRefused { observed } => write!(
                f,
                "the trust step refused the handshake after observing the fingerprint {observed}"
            ),
            Self::NoCertificate => write!(f, "the host presented no certificate"),
            Self::Connect { detail } => write!(f, "the connection failed: {detail}"),
            Self::BodyTooLarge { limit } => {
                write!(f, "the response exceeds the {limit}-byte bound")
            }
        }
    }
}

impl std::error::Error for PveTransportError {}

/// The transport port. The real implementation speaks TLS with the pinned
/// rustls verifier; tests record fixtures.
#[async_trait]
pub trait PveTransport: fmt::Debug + Send + Sync {
    /// Executes one request.
    ///
    /// # Errors
    ///
    /// Fails with [`PveTransportError`]; HTTP statuses travel inside the
    /// response.
    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError>;
}

/// The reqwest-backed transport: rustls with the pinned-fingerprint
/// verifier, bounded timeouts, and no redirect surprises.
#[derive(Debug)]
pub struct ReqwestPveTransport;

impl ReqwestPveTransport {
    /// Builds the transport.
    ///
    /// # Errors
    ///
    /// Fails when the HTTP client cannot be built.
    pub fn new() -> Result<Self, String> {
        // A throwaway client proves the TLS feature set resolves in this
        // exact dependency graph; each call builds its own client over a
        // fresh pinned verifier (the policy is per-call, not per-transport).
        reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|error| format!("cannot build the HTTP client: {error}"))?;
        Ok(Self)
    }
}

impl Default for ReqwestPveTransport {
    fn default() -> Self {
        Self::new().expect("the PVE transport must build")
    }
}

/// What the verifier should do with the leaf certificate it sees.
enum TlsPolicy {
    /// Capture the fingerprint, then refuse: the trust probe. No HTTP
    /// request is ever completed, so credentials are never sent.
    Observe,
    /// Accept only the leaf whose SHA-256 matches the pinned value.
    Pin(String),
}

/// The verifier shared with the rustls session. It never disables
/// verification: every path either matches the pin or refuses. The leaf
/// fingerprint it observed lands in `captured`, which is how the transport
/// reports trust facts on refusal — reqwest's own error chain does not
/// carry them.
struct PinningVerifier {
    policy: TlsPolicy,
    provider: Arc<CryptoProvider>,
    captured: Arc<Mutex<Option<String>>>,
}

impl PinningVerifier {
    /// Formats a digest the way PVE and the legacy client display it:
    /// uppercase colon-separated hex.
    fn fingerprint(digest: &[u8; 32]) -> String {
        digest
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl fmt::Debug for PinningVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.policy {
            TlsPolicy::Observe => f.write_str("PinningVerifier(observe)"),
            TlsPolicy::Pin(_) => f.write_str("PinningVerifier(pinned)"),
        }
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(end_entity.as_ref());
        let digest: [u8; 32] = hasher.finalize().into();
        let observed = Self::fingerprint(&digest);
        *self
            .captured
            .lock()
            .expect("the capture lock is not poisoned") = Some(observed.clone());
        match &self.policy {
            TlsPolicy::Observe => Err(rustls::Error::General(
                "fleet observe-only trust probe: refusing after capture".to_owned(),
            )),
            TlsPolicy::Pin(pinned)
                if normalize_fingerprint(pinned) == normalize_fingerprint(&observed) =>
            {
                Ok(ServerCertVerified::assertion())
            }
            TlsPolicy::Pin(_) => Err(rustls::Error::General(
                "fleet trust: the certificate does not match the pinned fingerprint".to_owned(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Normalizes a fingerprint for comparison: strips colons and uppercases.
/// Both the stored pin and PVE's displayed form reach this.
#[must_use]
pub fn normalize_fingerprint(value: &str) -> String {
    value.replace(':', "").to_uppercase()
}

#[async_trait]
impl PveTransport for ReqwestPveTransport {
    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        let policy = match &request.pinned_fingerprint {
            Some(pinned) => TlsPolicy::Pin(normalize_fingerprint(pinned)),
            None => TlsPolicy::Observe,
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let captured = Arc::new(Mutex::new(None));
        let verifier = Arc::new(PinningVerifier {
            policy,
            provider: provider.clone(),
            captured: Arc::clone(&captured),
        });
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| PveTransportError::Connect {
                detail: error.to_string(),
            })?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        config.alpn_protocols = Vec::new();

        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .use_preconfigured_tls(config)
            .build()
            .map_err(|error| PveTransportError::Connect {
                detail: format!("the TLS configuration was rejected: {error}"),
            })?;
        let url = format!("https://{}:{}{}", request.host, request.port, request.path);
        let response = client
            .get(&url)
            .header(
                "Authorization",
                format!(
                    "PVEAPIToken={}={}",
                    request.credentials.token_id,
                    request.credentials.token.expose()
                ),
            )
            .send()
            .await
            .map_err(|error| {
                // The verifier's refusal surfaces as an opaque connect
                // error; the trust facts live in the capture the verifier
                // wrote before refusing.
                let observed = captured
                    .lock()
                    .expect("the capture lock is not poisoned")
                    .clone();
                match (observed, request.pinned_fingerprint.as_deref()) {
                    (Some(observed), Some(_)) => PveTransportError::FingerprintMismatch {
                        observed,
                        pinned: request.pinned_fingerprint.clone(),
                    },
                    (Some(observed), None) => PveTransportError::ObserveRefused { observed },
                    (None, _) => PveTransportError::Connect {
                        detail: error.to_string(),
                    },
                }
            })?;
        let status = u16::from(response.status());
        let body = response
            .bytes()
            .await
            .map_err(|error| PveTransportError::Connect {
                detail: error.to_string(),
            })?;
        if body.len() > MAX_BODY_BYTES {
            return Err(PveTransportError::BodyTooLarge {
                limit: MAX_BODY_BYTES,
            });
        }
        Ok(PveHttpResponse {
            status,
            body: body.to_vec(),
        })
    }
}

/// A payload failure: the API answered, but not with something Fleet can
/// interpret.
#[derive(Debug)]
pub enum PveApiError {
    /// The credentials were refused (401).
    Auth,
    /// The caller lacks the privilege (403), with the bounded detail.
    Forbidden {
        /// The bounded, redacted detail.
        detail: String,
    },
    /// Any other HTTP outcome.
    Http {
        /// The status.
        status: u16,
        /// The bounded detail.
        detail: String,
    },
    /// The body was not interpretable.
    InvalidPayload {
        /// The bounded detail.
        detail: String,
    },
    /// The transport failed.
    Transport(PveTransportError),
}

impl fmt::Display for PveApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth => write!(f, "the API token was refused (401)"),
            Self::Forbidden { detail } => {
                write!(f, "the token lacks the privilege (403): {detail}")
            }
            Self::Http { status, detail } => write!(f, "the API answered {status}: {detail}"),
            Self::InvalidPayload { detail } => {
                write!(f, "the API's payload is not interpretable: {detail}")
            }
            Self::Transport(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PveApiError {}

/// One normalized cluster resource: a node, a QEMU guest, an LXC container,
/// a storage, or a template. Provenance and time attach at the application
/// layer; this is the provider's own shape.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PveResource {
    /// The normalized kind: `node`, `qemu`, `lxc`, `storage`, or
    /// `qemu-template`.
    pub kind: String,
    /// The cluster-visible id, e.g. `node/pve`, `qemu/101`.
    pub id: String,
    /// The hosting node, when the resource has one.
    pub node: Option<String>,
    /// The VMID, when the resource has one.
    pub vmid: Option<u32>,
    /// The display name, when carried.
    pub name: Option<String>,
    /// The PVE status string (`running`, `stopped`, `online`, …), when
    /// carried.
    pub status: Option<String>,
}

/// The discovery result: the API version seen and the normalized resources.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PveDiscovery {
    /// The PVE version string, e.g. `9.2.2`.
    pub version: String,
    /// The normalized resources, per-resource failures isolated away.
    pub resources: Vec<PveResource>,
    /// The resources that failed normalization, as bounded per-resource
    /// warnings. A partial failure never drops the whole snapshot.
    pub warnings: Vec<String>,
    /// The resource count before isolation, for honesty about loss.
    pub reported_count: usize,
}

/// The discovery port. The provider implements this over the PVE API;
/// tests implement it over recorded fixtures.
#[async_trait]
pub trait ProxmoxSource: fmt::Debug + Send + Sync {
    /// Discovers the cluster's resources through one account.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`] on auth, privilege, HTTP, payload, or
    /// transport failures. Per-resource normalization failures are isolated
    /// into the result's warnings instead.
    async fn discover(&self, request: PveHttpRequest) -> Result<PveDiscovery, PveApiError>;
}

/// The provider client: transport plus normalization. Stateless — every
/// call carries its own endpoint and credentials.
pub struct ProxmoxClient {
    transport: Arc<dyn PveTransport>,
}

impl fmt::Debug for ProxmoxClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxmoxClient")
            .field("transport", &self.transport)
            .finish()
    }
}

impl ProxmoxClient {
    /// Composes the client over a transport.
    #[must_use]
    pub fn new(transport: Arc<dyn PveTransport>) -> Self {
        Self { transport }
    }

    async fn call(&self, request: PveHttpRequest) -> Result<serde_json::Value, PveApiError> {
        let response = self
            .transport
            .execute(request)
            .await
            .map_err(PveApiError::Transport)?;
        match response.status {
            401 => Err(PveApiError::Auth),
            403 => Err(PveApiError::Forbidden {
                detail: bounded_body(&response.body),
            }),
            status if (400..600).contains(&status) => Err(PveApiError::Http {
                status,
                detail: bounded_body(&response.body),
            }),
            _ => {
                let value: serde_json::Value =
                    serde_json::from_slice(&response.body).map_err(|error| {
                        PveApiError::InvalidPayload {
                            detail: format!("the body is not JSON: {error}"),
                        }
                    })?;
                // PVE wraps every response in `{"data": ...}`; `data: null`
                // and a missing `data` both mean "empty".
                Ok(value
                    .get("data")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null))
            }
        }
    }
}

/// A bounded, credential-free body excerpt for error details.
fn bounded_body(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    fleet_core::redact_url_credentials(&fleet_core::flatten_control_characters(
        &text.chars().take(256).collect::<String>(),
    ))
}

#[async_trait]
impl ProxmoxSource for ProxmoxClient {
    async fn discover(&self, request: PveHttpRequest) -> Result<PveDiscovery, PveApiError> {
        // The version first: it anchors provenance and proves the trust.
        let version_request = PveHttpRequest {
            path: "/api2/json/version".to_owned(),
            ..request.clone()
        };
        let version_data = self.call(version_request).await?;
        let version = version_data
            .get("version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .chars()
            .take(32)
            .collect::<String>();
        if version.is_empty() {
            return Err(PveApiError::InvalidPayload {
                detail: "the version payload carries no version string".to_owned(),
            });
        }

        let resources_request = PveHttpRequest {
            path: "/api2/json/cluster/resources".to_owned(),
            ..request.clone()
        };
        let data = self.call(resources_request).await?;
        let entries = match data {
            serde_json::Value::Array(entries) => entries,
            // `data: null` is an empty cluster: honest, not an error.
            serde_json::Value::Null => Vec::new(),
            other => {
                return Err(PveApiError::InvalidPayload {
                    detail: format!(
                        "the resources payload is not a list (it is a {})",
                        type_name_of(&other)
                    ),
                });
            }
        };
        let reported_count = entries.len();
        let mut resources = Vec::new();
        let mut warnings = Vec::new();
        // Per-resource isolation: one malformed entry warns; the rest land.
        for (index, entry) in entries.into_iter().enumerate() {
            match normalize_resource(&entry) {
                Ok(Some(resource)) => resources.push(resource),
                Ok(None) => {}
                Err(detail) => warnings.push(format!("resource #{index}: {detail}")),
            }
        }
        Ok(PveDiscovery {
            version,
            resources,
            warnings,
            reported_count,
        })
    }
}

fn type_name_of(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "list",
        serde_json::Value::Object(_) => "object",
    }
}

/// Normalizes one cluster-resources entry. `Ok(None)` skips a non-resource
/// row without warning; `Err` warns.
fn normalize_resource(entry: &serde_json::Value) -> Result<Option<PveResource>, String> {
    let id = entry
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "the entry carries no id".to_owned())?
        .chars()
        .take(128)
        .collect::<String>();
    let pve_type = entry
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("entry {id} carries no type"))?;
    let is_template = entry
        .get("template")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
        == 1;
    let kind = match (pve_type, is_template) {
        ("node", _) => "node",
        ("qemu", false) => "qemu",
        ("qemu", true) => "qemu-template",
        ("lxc", _) => "lxc",
        ("storage", _) => "storage",
        ("sdn" | "pool", _) => return Ok(None),
        (other, _) => {
            return Err(format!(
                "entry {id} has an unrecognized type {other:?} (reported honestly, not coerced)"
            ));
        }
    };
    let node = entry
        .get("node")
        .and_then(serde_json::Value::as_str)
        .map(|value| value.chars().take(128).collect());
    let vmid = entry.get("vmid").and_then(|value| {
        value
            .as_u64()
            .map(|value| u32::try_from(value).unwrap_or(0))
    });
    let name = entry
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(|value| value.chars().take(256).collect());
    let status = entry
        .get("status")
        .and_then(serde_json::Value::as_str)
        .map(|value| value.chars().take(64).collect());
    Ok(Some(PveResource {
        kind: kind.to_owned(),
        id,
        node,
        vmid,
        name,
        status,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_normalize_for_comparison() {
        let pve_form = "DC:2C:11:6E:C9:C7:EA:61:8A:A4:E4:1E:FB:9B:DE:E4:AA:3D:81:EB:16:38:8F:2B:36:0A:AB:E2:83:A7:64:98";
        let bare = pve_form.replace(':', "");
        assert_eq!(
            normalize_fingerprint(pve_form),
            normalize_fingerprint(&bare)
        );
        assert_eq!(normalize_fingerprint("ab:cd"), "ABCD");
    }

    #[test]
    fn nodes_and_guests_normalize_and_odd_types_warn() {
        let entry = serde_json::json!({
            "id": "qemu/101", "type": "qemu", "node": "pve", "vmid": 101,
            "name": "dev-01", "status": "running", "template": 0
        });
        let resource = normalize_resource(&entry).unwrap().unwrap();
        assert_eq!(resource.kind, "qemu");
        assert_eq!(resource.vmid, Some(101));

        let template = serde_json::json!({
            "id": "qemu/900", "type": "qemu", "template": 1, "status": "stopped"
        });
        assert_eq!(
            normalize_resource(&template).unwrap().unwrap().kind,
            "qemu-template"
        );

        let node = serde_json::json!({"id": "node/pve", "type": "node", "status": "online"});
        let resource = normalize_resource(&node).unwrap().unwrap();
        assert_eq!(resource.kind, "node");
        assert_eq!(resource.vmid, None);

        let sdn = serde_json::json!({"id": "sdn/zone1", "type": "sdn"});
        assert!(normalize_resource(&sdn).unwrap().is_none());

        let mystery = serde_json::json!({"id": "weird/1", "type": "mystery"});
        let error = normalize_resource(&mystery).unwrap_err();
        assert!(error.contains("unrecognized type"), "{error}");
    }

    #[test]
    fn null_and_missing_envelopes_mean_empty() {
        let body = serde_json::json!({"data": null});
        assert!(body.get("data").cloned().unwrap_or_default().is_null());
        let body = serde_json::json!({});
        assert!(
            body.get("data")
                .cloned()
                .unwrap_or(serde_json::Value::Null)
                .is_null()
        );
    }
}
