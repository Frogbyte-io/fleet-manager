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

mod tasks;

pub use tasks::{
    MAX_TASKS_PER_NODE, PveTaskHistory, PveTaskOutcome, PveTaskQuery, PveTaskSource, PveTaskSummary,
};

use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_core::SensitiveString;
use futures_util::StreamExt as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::Digest;

mod permissions;

pub use permissions::{
    MAX_PERMISSION_PATHS, MAX_PRIVILEGES_PER_PATH, MAX_VMID_CHECKS, PveTokenPermissions,
    concrete_vmids, normalize_token_permissions,
};

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
    /// The HTTP method; `GET` for reads, `POST` for mutations. PVE's
    /// lifecycle endpoints require `POST`; its synchronous config update
    /// is `PUT`.
    pub method: PveHttpMethod,
}

/// The HTTP methods the transport speaks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PveHttpMethod {
    /// A read.
    #[default]
    Get,
    /// A mutation.
    Post,
    /// A synchronous update (`PUT …/qemu/{vmid}/config`).
    Put,
    /// A removal.
    Delete,
}

impl PveHttpRequest {
    /// The URL authority: IPv6 literals bracketed, everything else bare.
    #[must_use]
    pub fn authority(&self) -> String {
        match self.host.parse::<std::net::Ipv6Addr>() {
            Ok(_) => format!("[{}]", self.host),
            Err(_) => self.host.clone(),
        }
    }
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

    /// Executes one request with a JSON body.
    ///
    /// # Errors
    ///
    /// Fails with [`PveTransportError`]; HTTP statuses travel inside the
    /// response.
    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError>;

    /// Captures the host's leaf certificate without sending any request:
    /// the observe-only policy refuses the handshake after capture, and no
    /// `Authorization` header exists on this path at all (#284). The
    /// caller decides what the bytes are worth by comparing their SHA-256
    /// with a pin it already holds.
    ///
    /// # Errors
    ///
    /// Fails when the host is unreachable or presents no certificate, or
    /// when the transport cannot capture certificates (the default, for
    /// fixture transports).
    async fn observe_certificate(
        &self,
        host: &str,
        port: u16,
    ) -> Result<ObservedCertificate, PveTransportError> {
        let _ = (host, port);
        Err(PveTransportError::Connect {
            detail: "this transport cannot capture certificates".to_owned(),
        })
    }
}

/// A leaf certificate one handshake presented, captured before the
/// handshake was refused. Public material: the DER bytes and their
/// SHA-256 fingerprint in PVE's display form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedCertificate {
    /// The leaf's SHA-256 fingerprint, uppercase colon-separated hex.
    pub fingerprint: String,
    /// The leaf certificate, DER-encoded.
    pub der: Vec<u8>,
}

/// Whether the leaf certificate is valid for `host` by RFC 6125 name
/// rules: an IP literal must be an IP SAN, a DNS name must match a DNS
/// SAN (wildcards included), and the subject CN is never consulted. Go's
/// `x509.Certificate.VerifyHostname` applies the same rules, so this is
/// the check Packer's Proxmox plugin will make against a pinned leaf; a
/// certificate this rejects (or cannot parse) is reported as not naming
/// the host.
#[must_use]
pub fn certificate_names_host(der: &[u8], host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let Ok(name) = ServerName::try_from(host) else {
        return false;
    };
    let der = CertificateDer::from(der);
    webpki::EndEntityCert::try_from(&der)
        .is_ok_and(|cert| cert.verify_is_valid_for_subject_name(&name).is_ok())
}

/// The reqwest-backed transport: rustls with the pinned-fingerprint
/// verifier, bounded timeouts, and no redirect surprises.
#[derive(Debug)]
pub struct ReqwestPveTransport;

impl ReqwestPveTransport {
    /// Builds the transport. The pinned verifier is per-call (each call
    /// carries its own policy), so there is no client state to keep.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for ReqwestPveTransport {
    fn default() -> Self {
        Self::new()
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
/// it observed lands in `captured`, which is how the transport reports
/// trust facts on refusal — reqwest's own error chain does not carry them.
struct PinningVerifier {
    policy: TlsPolicy,
    provider: Arc<CryptoProvider>,
    captured: Arc<Mutex<Option<ObservedCertificate>>>,
}

/// The leaf the verifier captured, shared with the transport.
type Captured = Arc<Mutex<Option<ObservedCertificate>>>;

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
            .expect("the capture lock is not poisoned") = Some(ObservedCertificate {
            fingerprint: observed.clone(),
            der: end_entity.as_ref().to_vec(),
        });
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
    async fn execute_with_body(
        &self,
        request: PveHttpRequest,
        body: Vec<u8>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        self.execute_inner(request, Some(body)).await
    }

    async fn execute(&self, request: PveHttpRequest) -> Result<PveHttpResponse, PveTransportError> {
        self.execute_inner(request, None).await
    }

    async fn observe_certificate(
        &self,
        host: &str,
        port: u16,
    ) -> Result<ObservedCertificate, PveTransportError> {
        let (client, captured) = Self::client(TlsPolicy::Observe)?;
        let authority = match host.parse::<std::net::Ipv6Addr>() {
            Ok(_) => format!("[{host}]"),
            Err(_) => host.to_owned(),
        };
        // No credential exists on this path: the request carries no
        // `Authorization` header, and the observe policy refuses the
        // handshake before any request byte is written.
        let sent = client
            .get(format!("https://{authority}:{port}/api2/json/version"))
            .send()
            .await;
        let observed = captured
            .lock()
            .expect("the capture lock is not poisoned")
            .take();
        match (sent, observed) {
            (Err(_), Some(certificate)) => Ok(certificate),
            (Err(error), None) => Err(PveTransportError::Connect {
                detail: error.to_string(),
            }),
            // The observe policy refuses every handshake; a completed
            // request means the policy did not run. Refuse to report it.
            (Ok(_), _) => Err(PveTransportError::Connect {
                detail: "the observe probe must refuse; refusing to report a certificate"
                    .to_owned(),
            }),
        }
    }
}

impl ReqwestPveTransport {
    /// A client whose every handshake runs `policy`, and the capture its
    /// verifier writes the observed leaf into.
    fn client(policy: TlsPolicy) -> Result<(reqwest::Client, Captured), PveTransportError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let captured = Arc::new(Mutex::new(None));
        let verifier = Arc::new(PinningVerifier {
            policy,
            provider: provider.clone(),
            captured: Arc::clone(&captured),
        });
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
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
        Ok((client, captured))
    }

    async fn execute_inner(
        &self,
        request: PveHttpRequest,
        body: Option<Vec<u8>>,
    ) -> Result<PveHttpResponse, PveTransportError> {
        let policy = match &request.pinned_fingerprint {
            Some(pinned) => TlsPolicy::Pin(normalize_fingerprint(pinned)),
            None => TlsPolicy::Observe,
        };
        let (client, captured) = Self::client(policy)?;
        let url = format!(
            "https://{}:{}{}",
            request.authority(),
            request.port,
            request.path
        );
        let request_builder = match request.method {
            PveHttpMethod::Get => client.get(&url),
            PveHttpMethod::Post => client.post(&url),
            PveHttpMethod::Put => client.put(&url),
            PveHttpMethod::Delete => client.delete(&url),
        };
        let request_builder = request_builder.header(
            "Authorization",
            format!(
                "PVEAPIToken={}={}",
                request.credentials.token_id,
                request.credentials.token.expose()
            ),
        );
        let request_builder = match body {
            Some(bytes) => request_builder
                .header("Content-Type", "application/json")
                .body(bytes),
            None => request_builder,
        };
        let response = request_builder.send().await.map_err(|error| {
            // The verifier's refusal surfaces as an opaque connect
            // error; the trust facts live in the capture the verifier
            // wrote before refusing.
            let observed = captured
                .lock()
                .expect("the capture lock is not poisoned")
                .take()
                .map(|certificate| certificate.fingerprint);
            match (observed, request.pinned_fingerprint.as_deref()) {
                // A mismatch is only a mismatch when the fingerprints
                // differ: a later TLS failure with a matching pin is a
                // connection failure, not an instruction to re-confirm.
                (Some(observed), Some(pinned))
                    if normalize_fingerprint(&observed) != normalize_fingerprint(pinned) =>
                {
                    PveTransportError::FingerprintMismatch {
                        observed,
                        pinned: Some(pinned.to_owned()),
                    }
                }
                (Some(_), Some(_)) | (None, _) => PveTransportError::Connect {
                    detail: error.to_string(),
                },
                (Some(observed), None) => PveTransportError::ObserveRefused { observed },
            }
        })?;
        let status = u16::from(response.status());
        // The body bound is enforced while streaming: a hostile or broken
        // host cannot make Fleet materialize an unbounded response.
        let mut stream = response.bytes_stream();
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| PveTransportError::Connect {
                detail: error.to_string(),
            })?;
            push_bounded(&mut body, &chunk)?;
        }
        Ok(PveHttpResponse { status, body })
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
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// One Proxmox node's current resource usage and storage capacity.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PveNodeCapacity {
    /// The Proxmox node name.
    pub node: String,
    /// CPU usage as a fraction in the range 0.0 through 1.0.
    pub cpu_usage_ratio: Option<f64>,
    /// Logical CPU count, when PVE reports it.
    pub cpu_count: Option<u64>,
    /// Used memory in bytes.
    pub memory_used_bytes: Option<u64>,
    /// Total memory in bytes.
    pub memory_total_bytes: Option<u64>,
    /// Storage pools visible from this node.
    pub storages: Vec<PveStorageCapacity>,
}

/// One Proxmox storage pool's current capacity.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PveStorageCapacity {
    /// The Proxmox storage identifier.
    pub storage: String,
    /// Used storage in bytes.
    pub used_bytes: u64,
    /// Total storage in bytes.
    pub total_bytes: u64,
}

/// The discovery result: the API version, normalized resources, and current
/// per-node capacity observations.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PveDiscovery {
    /// The PVE version string, e.g. `9.2.2`.
    pub version: String,
    /// The normalized resources, per-resource failures isolated away.
    pub resources: Vec<PveResource>,
    /// Current per-node capacity; endpoint failures are reflected in warnings.
    pub node_capacities: Vec<PveNodeCapacity>,
    /// The resources that failed normalization, as bounded per-resource
    /// warnings. A partial failure never drops the whole snapshot.
    pub warnings: Vec<String>,
    /// The resource count before isolation, for honesty about loss.
    pub reported_count: usize,
}

/// The QEMU Guest Agent's view of one guest, with honest availability per
/// surface. Every field is independent: an off guest is not an agentless
/// guest, and an agent that answers `info` but not `network` is reported
/// exactly so.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PveGuestAgent {
    /// The agent answered `info`: it is installed and reachable.
    pub online: bool,
    /// The agent version string, when `info` carried one.
    pub version: Option<String>,
    /// The guest's OS facts, when `get-osinfo` answered.
    pub os_name: Option<String>,
    /// The guest's kernel release, when `get-osinfo` carried one.
    pub kernel: Option<String>,
    /// The whole `get-osinfo` answer, when it answered. Classifying it
    /// (e.g. `mswindows` → Windows) is an application rule.
    #[serde(default)]
    pub os: Option<PveGuestOs>,
    /// The network interfaces the agent saw, when
    /// `network-get-interfaces` answered: the raw list, bounded to
    /// [`MAX_AGENT_INTERFACES`]. MACs are normalized (lowercase,
    /// colon-separated); addresses are as the agent printed them, minus
    /// loopback, so link-local and APIPA addresses (and a Windows `%zone`
    /// suffix) stay. Which addresses are usable is an application rule.
    pub interfaces: Vec<PveGuestInterface>,
}

/// The QEMU Guest Agent's `guest-get-osinfo` answer, every member bounded
/// and optional (QAPI omits absent members). On POSIX guests the members
/// come from os-release(5); on Windows `id` is `mswindows`, `name` is
/// `Microsoft Windows`, `pretty-name` is the registry `ProductName`,
/// `version`/`version-id` come from qemu-ga's build-number table, and
/// `variant`/`variant-id` are `client` or `server`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PveGuestOs {
    /// `id`, e.g. `debian` or `mswindows`.
    pub id: Option<String>,
    /// `name`, e.g. `Microsoft Windows`.
    pub name: Option<String>,
    /// `pretty-name`.
    pub pretty_name: Option<String>,
    /// `version`, e.g. `Microsoft Windows Server 2022`.
    pub version: Option<String>,
    /// `version-id`, e.g. `13` or `2022`.
    pub version_id: Option<String>,
    /// `variant`.
    pub variant: Option<String>,
    /// `variant-id`, e.g. `server` or `client` on Windows.
    pub variant_id: Option<String>,
    /// `kernel-release`: the kernel release, or the build number on
    /// Windows.
    pub kernel_release: Option<String>,
    /// `kernel-version`: e.g. `10.0` on Windows.
    pub kernel_version: Option<String>,
    /// `machine`, e.g. `x86_64`.
    pub machine: Option<String>,
}

/// The bound on the interfaces kept from one agent answer. Windows guests
/// list every adapter (tunnels, Bluetooth, Hyper-V switches), so the bound
/// is generous; overflow is a warning, never silence.
pub const MAX_AGENT_INTERFACES: usize = 64;
/// The bound on the addresses kept per agent interface.
pub const MAX_INTERFACE_ADDRESSES: usize = 32;
/// The bound on one `get-osinfo` member.
const MAX_OS_FIELD_CHARS: usize = 128;

/// One network interface as the guest agent saw it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PveGuestInterface {
    /// The interface name inside the guest, e.g. `ens18`.
    pub name: String,
    /// The normalized MAC address, when the interface has one.
    pub mac: Option<String>,
    /// The interface's addresses, when it has any.
    pub addresses: Vec<String>,
}

/// One guest with its provider-side facts: the cluster resource plus the
/// config's MAC addresses and the agent view. Association and provenance
/// attach at the application layer.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PveGuest {
    /// The cluster resource the guest came from (`qemu` or `lxc`).
    pub resource: PveResource,
    /// The MAC addresses from the guest config's `netN` entries, normalized
    /// lowercase colon-separated. LXC guests carry theirs in `config` too.
    pub macs: Vec<String>,
    /// The config's `ostype` (e.g. `win11`, `l26`), when the config was
    /// read and carried a well-formed one. An operator-set hint, not what
    /// the guest reports.
    #[serde(default)]
    pub ostype: Option<String>,
    /// The QEMU Guest Agent view; `None` only for LXC (no
    /// qemu-guest-agent by design). For QEMU the agent is always probed:
    /// per-surface availability lives inside, and a failed config read
    /// warns separately without hiding the agent's own state.
    pub agent: Option<PveGuestAgent>,
    /// The bounded per-surface warnings: one failed agent call or a
    /// malformed config entry warns here instead of dropping the guest.
    pub warnings: Vec<String>,
}

/// The guest discovery result: the guests of one account's cluster.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PveGuestDiscovery {
    /// The PVE version seen.
    pub version: String,
    /// The discovered guests.
    pub guests: Vec<PveGuest>,
    /// The cluster-level warnings (a guest whose config or agent probing
    /// failed is isolated here).
    pub warnings: Vec<String>,
}

/// One lifecycle action on one guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleAction {
    /// Start a stopped guest.
    Start,
    /// Stop a running guest immediately (no guest-side shutdown).
    Stop,
    /// ACPI-shutdown a running guest.
    Shutdown,
    /// Reboot a running guest.
    Reboot,
}

impl LifecycleAction {
    /// The URL path segment PVE expects for the action.
    #[must_use]
    pub const fn path_segment(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Shutdown => "shutdown",
            Self::Reboot => "reboot",
        }
    }

    /// Parses the stable string used in payloads and audit events.
    ///
    /// # Errors
    ///
    /// Fails on an unrecognized action id.
    pub fn from_id(id: &str) -> Result<Self, String> {
        match id {
            "start" => Ok(Self::Start),
            "stop" => Ok(Self::Stop),
            "shutdown" => Ok(Self::Shutdown),
            "reboot" => Ok(Self::Reboot),
            other => Err(format!("unrecognized lifecycle action {other:?}")),
        }
    }

    /// The stable string used in payloads and audit events.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Shutdown => "shutdown",
            Self::Reboot => "reboot",
        }
    }
}

/// The task types PVE starts without a target id. Only these may carry an
/// empty UPID `id` field. A type missing here with an empty id is refused
/// by [`Upid::parse`], which the task history reports as a per-task
/// warning instead of a silent row.
///
/// The list is every `$rpcenv->fork_worker(<type>, undef | '' | "", ...)`
/// call in the PVE sources, checked against the `master` branches of
/// `pve-manager`, `qemu-server`, `pve-container`, `pve-storage`,
/// `pve-cluster`, and `pve-network` (October 2026). To re-check it, grep
/// those repositories for `fork_worker` and look for an undefined or
/// empty second argument:
///
/// - `pve-manager`: `aptupdate`, `startall`/`stopall`/`suspendall`/
///   `migrateall`, the PVE 9 cluster `bulk-*` actions, `vzdump` (its id is
///   the VMID only for a single-guest backup), `vncshell` (also what the
///   node `termproxy` endpoint starts), `spiceshell`, `cephsetflags`, and
///   the ACME account (`acme{register,update,refresh,deactivate}`) and
///   certificate (`acme{newcert,renew,revoke}`) tasks.
/// - `pve-storage`: `imgcopy`, `imgdel`, `pbs-download`.
/// - `pve-cluster`: `clusterjoin`.
/// - `pve-network`: `reloadnetworkall`.
///
/// The `srv*` service tasks pass the service name today, but they are
/// node-scoped and never name a guest, so an empty id on one is not a
/// guest task missing its VMID; they stay accepted.
pub const NODE_LEVEL_TASK_TYPES: &[&str] = &[
    "acmedeactivate",
    "acmenewcert",
    "acmerefresh",
    "acmeregister",
    "acmerenew",
    "acmerevoke",
    "acmeupdate",
    "aptupdate",
    "bulk-migrate",
    "bulk-shutdown",
    "bulk-start",
    "bulk-suspend",
    "cephsetflags",
    "clusterjoin",
    "imgcopy",
    "imgdel",
    "migrateall",
    "pbs-download",
    "reloadnetworkall",
    "spiceshell",
    "srvreload",
    "srvrestart",
    "srvstart",
    "srvstop",
    "startall",
    "stopall",
    "suspendall",
    "vncshell",
    "vzdump",
];

/// A parsed UPID. Fleet parses the string itself — the node it polls comes
/// from the parse, never from trust in the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upid {
    /// The hosting node the task runs on.
    pub node: String,
    /// The task type, e.g. `qmstart`.
    pub task_type: String,
    /// The task's target id (the VMID for guest tasks); empty only for
    /// the [`NODE_LEVEL_TASK_TYPES`].
    pub target: String,
    /// The user the task runs as.
    pub user: String,
    /// The raw UPID string, for API round trips.
    pub raw: String,
}

impl Upid {
    /// Parses `UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:`.
    ///
    /// # Errors
    ///
    /// Fails on a malformed UPID, with a bounded detail and no echo of the
    /// raw value beyond its shape.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let body = raw
            .strip_prefix("UPID:")
            .ok_or_else(|| "the UPID is missing its UPID: prefix".to_owned())?;
        let parts: Vec<&str> = body.split(':').collect();
        if parts.len() != 8 {
            return Err(format!(
                "the UPID carries {} fields, expected 8",
                parts.len()
            ));
        }
        let [
            node,
            pid,
            pstart,
            starttime,
            task_type,
            target,
            user,
            trailing,
        ] = parts[..]
        else {
            return Err("the UPID fields did not destructure".to_owned());
        };
        for (label, part) in [
            ("node", node),
            ("pid", pid),
            ("pstart", pstart),
            ("starttime", starttime),
            ("type", task_type),
            ("user", user),
        ] {
            if part.is_empty() {
                return Err(format!("the UPID's {label} field is empty"));
            }
        }
        // The `id` field is legitimately empty only for node-level tasks
        // (`aptupdate`, `srvreload`, an all-guest `vzdump`): PVE encodes
        // them as `...:<type>::<user>:`. Any other task type must name its
        // target, so a guest task with no VMID is refused rather than
        // read as a node-level one.
        if target.is_empty() && !NODE_LEVEL_TASK_TYPES.contains(&task_type) {
            return Err(format!(
                "the UPID's id field is empty, but {:?} is not a node-level task type",
                task_type.chars().take(64).collect::<String>()
            ));
        }
        if !trailing.is_empty() {
            return Err("the UPID carries trailing material".to_owned());
        }
        if raw.len() > 256 {
            return Err(format!(
                "the UPID is {} bytes, over the 256-byte bound",
                raw.len()
            ));
        }
        let bounded = |part: &str, max: usize| part.chars().take(max).collect::<String>();
        Ok(Self {
            node: bounded(node, 128),
            task_type: bounded(task_type, 64),
            target: bounded(target, 64),
            user: bounded(user, 128),
            raw: raw.to_owned(),
        })
    }
}

/// The status of one PVE task, as the API reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskStatus {
    /// The task is still running.
    Running,
    /// The task finished successfully.
    Ok,
    /// The task finished with an error, carrying the bounded exit status.
    Error {
        /// The bounded exit status string.
        detail: String,
    },
    /// The task is unknown to the node: it may have been rotated out of
    /// the task list. Honest uncertainty, never assumed success.
    Unknown,
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

    /// Discovers the account's guests with their config MACs and guest-agent
    /// views. Read-only; a guest whose config or agent probing fails is
    /// isolated into the result's warnings instead of dropping the snapshot.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`] on auth, privilege, HTTP, payload, or
    /// transport failures.
    async fn guest_discover(
        &self,
        request: PveHttpRequest,
    ) -> Result<PveGuestDiscovery, PveApiError>;

    /// Reads the calling token's own effective permissions
    /// (`GET /access/permissions`, FM-604) with the PVE version they apply
    /// to. Every principal may read its own permissions, so a refusal here
    /// is itself evidence. Read-only and bounded; unknown privilege names
    /// are kept, not rejected.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`] on auth, privilege, HTTP, payload, or
    /// transport failures.
    async fn token_permissions(
        &self,
        request: PveHttpRequest,
    ) -> Result<PveTokenPermissions, PveApiError>;

    /// Runs one lifecycle action on one QEMU guest, returning the parsed
    /// UPID of the task PVE started. Read-only until this point; this is
    /// the first mutating surface in the provider.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`] on auth, privilege, HTTP, payload, or
    /// transport failures.
    async fn guest_lifecycle(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        action: LifecycleAction,
    ) -> Result<Upid, PveApiError>;

    /// Reads one task's status by node and UPID. An unknown task is an
    /// honest [`TaskStatus::Unknown`], not an error: PVE rotates old task
    /// entries out, and assuming success would be a lie.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`] on auth, privilege, HTTP, payload, or
    /// transport failures.
    async fn task_status(
        &self,
        request: PveHttpRequest,
        upid: &Upid,
    ) -> Result<TaskStatus, PveApiError>;

    /// Creates a snapshot of one guest. Idempotent on name: the caller
    /// checks existence first (or classifies the existing snapshot), and
    /// the provider refuses only transport/API-level failures.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`].
    async fn guest_snapshot(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        snapshot: &str,
        description: &str,
        include_ram: bool,
    ) -> Result<Option<Upid>, PveApiError>;

    /// Rolls one guest back to a snapshot. The task is synchronous for
    /// LXC and a UPID for QEMU; the provider normalizes both to an
    /// optional UPID.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`].
    async fn guest_snapshot_rollback(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        snapshot: &str,
    ) -> Result<Option<Upid>, PveApiError>;

    /// Deletes one snapshot. Synchronous on both guest kinds: the
    /// outcome is immediate.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`].
    async fn guest_snapshot_delete(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        snapshot: &str,
    ) -> Result<(), PveApiError>;

    /// Destroys a stopped QEMU guest. Returns its qmdestroy task, or None
    /// when the guest configuration is already absent. Refuses templates
    /// observed in a config read immediately before DELETE. PVE has no
    /// conditional-delete parameter: a concurrent external conversion after
    /// that read can race the DELETE, so this refusal is best-effort.
    /// Purge removes backup, replication and HA references; locks and
    /// unreferenced disks are never bypassed or removed.
    ///
    /// # Errors
    /// Returns API/transport failures, including permission refusals.
    async fn guest_destroy(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        purge: bool,
    ) -> Result<Option<Upid>, PveApiError>;

    /// Clones one guest to a new VMID with the requested name. The caller
    /// classifies idempotency; the provider refuses only transport/API
    /// failures.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`].
    async fn guest_clone(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        new_id: u32,
        name: &str,
        full_copy: bool,
    ) -> Result<Upid, PveApiError>;

    /// Converts one guest into a template. Idempotent: converting an
    /// existing template succeeds without an operation.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`].
    async fn guest_convert_template(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
    ) -> Result<Option<Upid>, PveApiError>;

    /// Stops one running task. Destructive-adjacent: the caller owns the
    /// authorization; the outcome may be unknown if the task exits
    /// between the stop and the status read.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`].
    async fn stop_task(&self, request: PveHttpRequest, upid: &Upid) -> Result<(), PveApiError>;

    /// Probes one guest's agent: the guest answers `agent/info` when the
    /// QEMU Guest Agent is installed and reachable. The readiness probe
    /// for the Lab saga (FM-710).
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`].
    async fn guest_agent_info(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
    ) -> Result<serde_json::Value, PveApiError>;

    /// Lists one guest's snapshots, normalized.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`].
    async fn guest_snapshots(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
    ) -> Result<Vec<PveSnapshot>, PveApiError>;
}

/// The config facts the Lab executor checks on a fresh clone before it
/// clears the clone's inherited `protection` flag (issue #290).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PveQemuConfigFlags {
    /// The guest's name, bounded.
    pub name: Option<String>,
    /// Whether the guest is a template (`template: 1`).
    pub template: bool,
    /// Whether PVE refuses to remove the guest (`protection: 1`).
    pub protection: bool,
    /// The config lock, such as `clone` while a clone is still running.
    pub lock: Option<String>,
    /// The config digest, for a conditional update.
    pub digest: Option<String>,
}

/// One guest snapshot, normalized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PveSnapshot {
    /// The snapshot's name.
    pub name: String,
    /// The snapshot's description, when carried.
    pub description: String,
    /// Whether the snapshot holds the guest's RAM.
    pub includes_ram: bool,
}

/// The provider client: transport plus normalization. Stateless — every
/// call carries its own endpoint and credentials.
#[derive(Clone)]
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

    /// One POST with a JSON body, unwrapping the envelope.
    async fn call_with_body(
        &self,
        request: PveHttpRequest,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, PveApiError> {
        self.call_method_with_body(request, PveHttpMethod::Post, path, body)
            .await
    }

    /// One call with a JSON body (`POST` or `PUT`), unwrapping the envelope.
    async fn call_method_with_body(
        &self,
        request: PveHttpRequest,
        method: PveHttpMethod,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, PveApiError> {
        let mut request = request;
        request.path = path.to_owned();
        request.method = method;
        let response = self
            .transport
            .execute_with_body(request, body.to_string().into_bytes())
            .await
            .map_err(PveApiError::Transport)?;
        Self::status_to_result(&response)
    }

    /// One DELETE, unwrapping the envelope.
    async fn call_delete(&self, request: PveHttpRequest, path: &str) -> Result<(), PveApiError> {
        let mut request = request;
        request.path = path.to_owned();
        request.method = PveHttpMethod::Delete;
        let response = self
            .transport
            .execute(request)
            .await
            .map_err(PveApiError::Transport)?;
        Self::status_to_result(&response).map(|_| ())
    }

    /// The version string and the raw cluster-resources entries: the
    /// prologue both discovery paths share.
    async fn version_and_resources(
        &self,
        request: &PveHttpRequest,
    ) -> Result<(String, Vec<serde_json::Value>), PveApiError> {
        // The version first: it anchors provenance and proves the trust.
        let version = self.read_version(request).await?;
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
        Ok((version, entries))
    }

    /// The bounded PVE version string (`GET /version`, which every
    /// authenticated principal may read).
    async fn read_version(&self, request: &PveHttpRequest) -> Result<String, PveApiError> {
        let version_request = PveHttpRequest {
            path: "/api2/json/version".to_owned(),
            method: PveHttpMethod::Get,
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
        Ok(version)
    }

    async fn call(&self, request: PveHttpRequest) -> Result<serde_json::Value, PveApiError> {
        let response = self
            .transport
            .execute(request)
            .await
            .map_err(PveApiError::Transport)?;
        Self::status_to_result(&response)
    }

    /// Reads CPU/memory and storage independently so either PVE endpoint can
    /// fail without hiding the other observation or the rest of discovery.
    async fn node_capacity(
        &self,
        request: &PveHttpRequest,
        node: String,
    ) -> (PveNodeCapacity, Vec<String>) {
        let mut warnings = Vec::new();
        if !safe_node_path_segment(&node) {
            warnings.push(format!(
                "node {node:?} capacity: the node name is not a safe API path segment"
            ));
            return (
                PveNodeCapacity {
                    node,
                    cpu_usage_ratio: None,
                    cpu_count: None,
                    memory_used_bytes: None,
                    memory_total_bytes: None,
                    storages: Vec::new(),
                },
                warnings,
            );
        }
        let status_request = PveHttpRequest {
            path: format!("/api2/json/nodes/{node}/status"),
            ..request.clone()
        };
        let (cpu_usage_ratio, cpu_count, memory_used_bytes, memory_total_bytes) =
            match self.call(status_request).await {
                Ok(status) => normalize_node_status(&status, &node, &mut warnings),
                Err(error) => {
                    warnings.push(format!("node {node} status: {error}"));
                    (None, None, None, None)
                }
            };

        let storage_request = PveHttpRequest {
            path: format!("/api2/json/nodes/{node}/storage"),
            ..request.clone()
        };
        let storages = match self.call(storage_request).await {
            Ok(serde_json::Value::Array(entries)) => entries
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| match normalize_storage(entry) {
                    Ok(storage) => Some(storage),
                    Err(detail) => {
                        warnings.push(format!("node {node} storage #{index}: {detail}"));
                        None
                    }
                })
                .collect(),
            // As with cluster resources, null is an empty result.
            Ok(serde_json::Value::Null) => Vec::new(),
            Ok(other) => {
                warnings.push(format!(
                    "node {node} storage: the payload is not a list (it is a {})",
                    type_name_of(&other)
                ));
                Vec::new()
            }
            Err(error) => {
                warnings.push(format!("node {node} storage: {error}"));
                Vec::new()
            }
        };

        (
            PveNodeCapacity {
                node,
                cpu_usage_ratio,
                cpu_count,
                memory_used_bytes,
                memory_total_bytes,
                storages,
            },
            warnings,
        )
    }

    /// Maps one response onto the envelope: statuses become caller-safe
    /// errors, a good body unwraps `{"data": ...}`.
    fn status_to_result(response: &PveHttpResponse) -> Result<serde_json::Value, PveApiError> {
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

/// Appends one streamed chunk under the body bound, refusing the response
/// the moment it would exceed it.
fn push_bounded(body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), PveTransportError> {
    if body.len() + chunk.len() > MAX_BODY_BYTES {
        return Err(PveTransportError::BodyTooLarge {
            limit: MAX_BODY_BYTES,
        });
    }
    body.extend_from_slice(chunk);
    Ok(())
}

/// The optional UPID string a mutating endpoint answered; a synchronous
/// outcome carries no UPID.
fn upid_from_data(data: &serde_json::Value) -> Result<Option<Upid>, PveApiError> {
    match data {
        // A synchronous outcome carries `null` or no UPID at all.
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(raw) => Upid::parse(raw)
            .map(Some)
            .map_err(|detail| PveApiError::InvalidPayload { detail }),
        other => Err(PveApiError::InvalidPayload {
            detail: format!(
                "the mutating answer is neither a UPID string nor null (it is a {})",
                type_name_of(other)
            ),
        }),
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
        let (version, entries) = self.version_and_resources(&request).await?;
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
        let mut nodes = resources
            .iter()
            .filter(|resource| resource.kind == "node")
            .filter_map(|resource| {
                resource
                    .node
                    .clone()
                    .or_else(|| resource.id.strip_prefix("node/").map(str::to_owned))
            })
            .collect::<Vec<_>>();
        nodes.sort();
        nodes.dedup();
        // Bound the number of simultaneous extra reads while keeping large
        // clusters from paying two network round trips serially per node.
        let mut capacities = futures_util::stream::iter(
            nodes
                .into_iter()
                .map(|node| self.node_capacity(&request, node)),
        )
        .buffer_unordered(8)
        .collect::<Vec<_>>()
        .await;
        capacities.sort_by(|left, right| left.0.node.cmp(&right.0.node));
        let mut node_capacities = Vec::with_capacity(capacities.len());
        for (capacity, mut node_warnings) in capacities {
            node_capacities.push(capacity);
            warnings.append(&mut node_warnings);
        }
        Ok(PveDiscovery {
            version,
            resources,
            node_capacities,
            warnings,
            reported_count,
        })
    }

    async fn guest_discover(
        &self,
        request: PveHttpRequest,
    ) -> Result<PveGuestDiscovery, PveApiError> {
        // The cluster snapshot names the guests; the config carries their
        // MACs; the agent carries their inner facts. Each step degrades
        // independently.
        let (version, entries) = self.version_and_resources(&request).await?;
        let mut guests = Vec::new();
        let mut warnings = Vec::new();
        for (index, entry) in entries.into_iter().enumerate() {
            let resource = match normalize_resource(&entry) {
                Ok(Some(resource)) if resource.kind == "qemu" || resource.kind == "lxc" => resource,
                Ok(_) => continue,
                Err(detail) => {
                    warnings.push(format!("resource #{index}: {detail}"));
                    continue;
                }
            };
            let Some(node) = resource.node.clone() else {
                warnings.push(format!(
                    "guest {}: the cluster entry carries no node",
                    resource.id
                ));
                continue;
            };
            let Some(vmid) = resource.vmid else {
                warnings.push(format!(
                    "guest {}: the cluster entry carries no vmid",
                    resource.id
                ));
                continue;
            };
            let mut guest = PveGuest {
                resource,
                ..PveGuest::default()
            };
            // The config: MACs for the association evidence. A config
            // failure warns; the guest survives without MAC evidence.
            let config_request = PveHttpRequest {
                path: format!(
                    "/api2/json/nodes/{}/{}/{vmid}/config",
                    urlencode(&node),
                    if guest.resource.kind == "lxc" {
                        "lxc"
                    } else {
                        "qemu"
                    }
                ),
                ..request.clone()
            };
            match self.call(config_request.clone()).await {
                Ok(config) => {
                    let (macs, mut config_warnings) = config_macs(&config);
                    guest.macs = macs;
                    match config_ostype(&config) {
                        Ok(ostype) => guest.ostype = ostype,
                        Err(warning) => config_warnings.push(warning),
                    }
                    for warning in config_warnings {
                        guest
                            .warnings
                            .push(format!("guest {}: {warning}", guest.resource.id));
                    }
                }
                Err(PveApiError::Http { status, detail }) => {
                    warnings.push(format!(
                        "guest {}: the config answered {status}: {detail}",
                        guest.resource.id
                    ));
                }
                Err(other) => {
                    warnings.push(format!(
                        "guest {}: the config failed: {other}",
                        guest.resource.id
                    ));
                }
            }
            // The agent: QEMU only, and every surface independently.
            if guest.resource.kind == "qemu" {
                guest.agent = Some(
                    self.probe_agent(&request, &node, vmid, &mut guest.warnings)
                        .await,
                );
            }
            guests.push(guest);
        }
        Ok(PveGuestDiscovery {
            version,
            guests,
            warnings,
        })
    }

    async fn token_permissions(
        &self,
        request: PveHttpRequest,
    ) -> Result<PveTokenPermissions, PveApiError> {
        // The version keys the privilege table (PVE 9 split VM.Monitor),
        // so it is read first; both reads go through the same pinned
        // request, never an unpinned one.
        let version = self.read_version(&request).await?;
        let permissions_request = PveHttpRequest {
            path: "/api2/json/access/permissions".to_owned(),
            method: PveHttpMethod::Get,
            ..request.clone()
        };
        let data = self.call(permissions_request).await?;
        let mut permissions = normalize_token_permissions(version, &data)?;
        // A grant on one concrete /vms/{id} is a usable clone target only
        // while that VMID is free. `/cluster/nextid?vmid=` answers that for
        // any caller (`user => 'all'` on 8.x and 9.x): 200 when free, 400
        // when the VMID exists or is invalid. Any other outcome fails the
        // read like every other source error. The checks run concurrently,
        // bounded like discovery's per-node reads.
        let vmids = concrete_vmids(&permissions.paths);
        if vmids.len() > MAX_VMID_CHECKS {
            permissions.warnings.push(format!(
                "{} VMID paths were not checked for being free (the first {MAX_VMID_CHECKS} were); they don't count as clone targets",
                vmids.len() - MAX_VMID_CHECKS
            ));
        }
        let checks =
            futures_util::stream::iter(vmids.into_iter().take(MAX_VMID_CHECKS).map(|vmid| {
                let nextid_request = PveHttpRequest {
                    path: format!("/api2/json/cluster/nextid?vmid={vmid}"),
                    method: PveHttpMethod::Get,
                    ..request.clone()
                };
                async move {
                    match self.call(nextid_request).await {
                        Ok(_) => Ok((vmid, false)),
                        Err(PveApiError::Http { status: 400, .. }) => Ok((vmid, true)),
                        Err(error) => Err(error),
                    }
                }
            }))
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        for check in checks {
            let (vmid, in_use) = check?;
            permissions.vmids_in_use.insert(vmid, in_use);
        }
        Ok(permissions)
    }

    async fn guest_lifecycle(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        action: LifecycleAction,
    ) -> Result<Upid, PveApiError> {
        let lifecycle_request = PveHttpRequest {
            path: format!(
                "/api2/json/nodes/{}/qemu/{vmid}/status/{}",
                urlencode(node),
                action.path_segment()
            ),
            method: PveHttpMethod::Post,
            ..request.clone()
        };
        let data = self.call(lifecycle_request).await?;
        // The mutating API answers `{"data": "<UPID string>"}`.
        let Some(upid_raw) = data.as_str() else {
            return Err(PveApiError::InvalidPayload {
                detail: "the lifecycle answer carries no UPID string".to_owned(),
            });
        };
        Upid::parse(upid_raw).map_err(|detail| PveApiError::InvalidPayload { detail })
    }

    async fn task_status(
        &self,
        request: PveHttpRequest,
        upid: &Upid,
    ) -> Result<TaskStatus, PveApiError> {
        self.task_status_impl(&request, upid).await
    }
    async fn guest_snapshot(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        snapshot: &str,
        description: &str,
        include_ram: bool,
    ) -> Result<Option<Upid>, PveApiError> {
        // PVE's qemu snapshot schema names the RAM flag `vmstate`; the
        // caller's `include_ram` intent maps onto it.
        let body = if include_ram {
            serde_json::json!({
                "snapname": snapshot,
                "description": description,
                "vmstate": 1,
            })
        } else {
            serde_json::json!({
                "snapname": snapshot,
                "description": description,
            })
        };
        let data = self
            .call_with_body(
                request,
                &format!("/api2/json/nodes/{}/qemu/{vmid}/snapshot", urlencode(node)),
                &body,
            )
            .await?;
        upid_from_data(&data)
    }

    async fn guest_snapshot_rollback(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        snapshot: &str,
    ) -> Result<Option<Upid>, PveApiError> {
        let data = self
            .call_with_body(
                request,
                &format!(
                    "/api2/json/nodes/{}/qemu/{vmid}/snapshot/{}/rollback",
                    urlencode(node),
                    urlencode(snapshot)
                ),
                &serde_json::json!({}),
            )
            .await?;
        upid_from_data(&data)
    }

    async fn guest_snapshot_delete(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        snapshot: &str,
    ) -> Result<(), PveApiError> {
        self.call_delete(
            request,
            &format!(
                "/api2/json/nodes/{}/qemu/{vmid}/snapshot/{}",
                urlencode(node),
                urlencode(snapshot)
            ),
        )
        .await
    }

    async fn guest_destroy(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        purge: bool,
    ) -> Result<Option<Upid>, PveApiError> {
        let config = self
            .call(PveHttpRequest {
                path: format!("/api2/json/nodes/{}/qemu/{vmid}/config", urlencode(node)),
                method: PveHttpMethod::Get,
                ..request.clone()
            })
            .await;
        let config = match config {
            Ok(config) => config,
            Err(error) if destroy_already_absent(&error, node, vmid) => return Ok(None),
            Err(error) => return Err(error),
        };
        if !config.is_object()
            || config
                .get("template")
                .is_some_and(|_| loose_number(&config, "template").is_none())
        {
            return Err(PveApiError::InvalidPayload {
                detail: "the destroy configuration is unreadable".to_owned(),
            });
        }
        if loose_number(&config, "template") == Some(1) {
            return Err(PveApiError::InvalidPayload {
                detail: "refusing to destroy a QEMU template".to_owned(),
            });
        }
        let result = self
            .call(PveHttpRequest {
                path: format!(
                    "/api2/json/nodes/{}/qemu/{vmid}?purge={}",
                    urlencode(node),
                    u8::from(purge)
                ),
                method: PveHttpMethod::Delete,
                ..request
            })
            .await;
        match result {
            Ok(data) => {
                let upid = upid_from_data(&data)?.ok_or_else(|| PveApiError::InvalidPayload {
                    detail: "the destroy answer carries no UPID".to_owned(),
                })?;
                if upid.task_type != "qmdestroy"
                    || upid.node != node
                    || upid.target != vmid.to_string()
                {
                    return Err(PveApiError::InvalidPayload {
                        detail: "the destroy UPID does not match the target".to_owned(),
                    });
                }
                Ok(Some(upid))
            }
            Err(error) if destroy_already_absent(&error, node, vmid) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn guest_clone(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        new_id: u32,
        name: &str,
        full_copy: bool,
    ) -> Result<Upid, PveApiError> {
        let body = serde_json::json!({
            "newid": new_id,
            "name": name,
            "full": full_copy,
        });
        let data = self
            .call_with_body(
                request,
                &format!("/api2/json/nodes/{}/qemu/{vmid}/clone", urlencode(node)),
                &body,
            )
            .await?;
        let Some(upid_raw) = data.as_str() else {
            return Err(PveApiError::InvalidPayload {
                detail: "the clone answer carries no UPID string".to_owned(),
            });
        };
        Upid::parse(upid_raw).map_err(|detail| PveApiError::InvalidPayload { detail })
    }

    async fn guest_convert_template(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
    ) -> Result<Option<Upid>, PveApiError> {
        let data = self
            .call_with_body(
                request,
                &format!("/api2/json/nodes/{}/qemu/{vmid}/template", urlencode(node)),
                &serde_json::json!({}),
            )
            .await?;
        upid_from_data(&data)
    }

    async fn stop_task(&self, request: PveHttpRequest, upid: &Upid) -> Result<(), PveApiError> {
        self.call_delete(
            request,
            // PVE's stop-task endpoint is the task itself, not its status
            // subresource.
            &format!(
                "/api2/json/nodes/{}/tasks/{}",
                urlencode(&upid.node),
                urlencode(&upid.raw)
            ),
        )
        .await
    }

    async fn guest_agent_info(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
    ) -> Result<serde_json::Value, PveApiError> {
        self.call(PveHttpRequest {
            path: format!(
                "/api2/json/nodes/{}/qemu/{vmid}/agent/info",
                urlencode(node)
            ),
            ..request.clone()
        })
        .await
    }

    async fn guest_snapshots(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
    ) -> Result<Vec<PveSnapshot>, PveApiError> {
        let data = self
            .call(PveHttpRequest {
                path: format!("/api2/json/nodes/{node}/qemu/{vmid}/snapshot"),
                ..request.clone()
            })
            .await?;
        let entries = match data {
            serde_json::Value::Array(entries) => entries,
            serde_json::Value::Null => Vec::new(),
            other => {
                return Err(PveApiError::InvalidPayload {
                    detail: format!(
                        "the snapshots payload is not a list (it is a {})",
                        type_name_of(&other)
                    ),
                });
            }
        };
        let mut snapshots = Vec::new();
        for entry in entries {
            // `current` is the live state marker, not a snapshot.
            let name = entry
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if name == "current" || name.is_empty() {
                continue;
            }
            snapshots.push(PveSnapshot {
                name: name.chars().take(64).collect(),
                description: entry
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .chars()
                    .take(512)
                    .collect(),
                includes_ram: entry
                    .get("vmstate")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(0)
                    == 1,
            });
        }
        Ok(snapshots)
    }
}

/// The config's `netN` entries, parsed for MAC addresses. The value shape
/// is `virtio=DE:AD:BE:EF:00:01,bridge=vmbr0` — the model is the first
/// key=value pair whose value looks like a MAC. A `netN` entry without a
/// valid MAC is a partial failure: it comes back as a warning, not silence.
fn config_macs(config: &serde_json::Value) -> (Vec<String>, Vec<String>) {
    let mut macs = Vec::new();
    let mut warnings = Vec::new();
    if let Some(extra) = config.as_object() {
        for (key, value) in extra {
            if !(key.starts_with("net") && key[3..].chars().all(|c| c.is_ascii_digit())) {
                continue;
            }
            let Some(text) = value.as_str() else {
                warnings.push(format!("the {key} entry is not a string"));
                continue;
            };
            let found = text.split(',').find_map(normalize_mac);
            match found {
                Some(mac) => macs.push(mac),
                None => warnings.push(format!("the {key} entry carries no parseable MAC address")),
            }
        }
    }
    (macs, warnings)
}

/// The config's `ostype`: an enum on both majors (`qemu-server`
/// `PVE/QemuServer.pm`: `other wxp w2k w2k3 w2k8 wvista win7 win8 win10
/// win11 l24 l26 solaris`; `pve-container` uses distribution names). The
/// value is kept verbatim when it is a short lowercase token; anything else
/// is a warning, never a guess.
fn config_ostype(config: &serde_json::Value) -> Result<Option<String>, String> {
    match config.get("ostype") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value))
            if !value.is_empty()
                && value.len() <= 32
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()) =>
        {
            Ok(Some(value.clone()))
        }
        Some(_) => Err("the ostype entry is not a recognizable OS type".to_owned()),
    }
}

/// Normalizes a MAC candidate: `key=AA:BB:…` or bare, lowercase
/// colon-separated, only when it is six hex pairs.
#[must_use]
pub fn normalize_mac(candidate: &str) -> Option<String> {
    let value = candidate.split('=').next_back().unwrap_or(candidate);
    let bytes = value.split(':').collect::<Vec<_>>();
    if bytes.len() != 6 {
        return None;
    }
    let mut normalized = Vec::with_capacity(17);
    for (index, byte) in bytes.iter().enumerate() {
        if byte.len() != 2 || !byte.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        if index > 0 {
            normalized.push(':');
        }
        normalized.extend(byte.to_lowercase().chars());
    }
    Some(normalized.into_iter().collect())
}

fn urlencode(value: &str) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

impl ProxmoxClient {
    /// Probes only one QEMU guest's agent info and network surfaces.
    /// Reuses discovery normalization without scanning unrelated guests or
    /// querying OS/config surfaces. Unavailable data stays explicitly unknown.
    pub async fn guest_agent_network(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
    ) -> PveGuestAgent {
        self.probe_agent_network(&request, node, vmid, &mut Vec::new())
            .await
    }

    async fn probe_agent_network(
        &self,
        request: &PveHttpRequest,
        node: &str,
        vmid: u32,
        warnings: &mut Vec<String>,
    ) -> PveGuestAgent {
        let mut agent = PveGuestAgent::default();
        let base = format!("/api2/json/nodes/{}/qemu/{vmid}/agent", urlencode(node));
        // info: is the agent there at all?
        let info_request = PveHttpRequest {
            path: format!("{base}/info"),
            ..request.clone()
        };
        let Ok(info_data) = self.call(info_request).await else {
            warnings.push(format!("guest qemu/{vmid}: the agent is unreachable"));
            // Every other surface would fail the same way; report the
            // honest offline agent and stop here.
            return agent;
        };
        // The agent answers inside a `result` envelope.
        let result = info_data.get("result").cloned().unwrap_or(info_data);
        agent.online = true;
        agent.version = result
            .get("version")
            .and_then(serde_json::Value::as_str)
            .map(|value| value.chars().take(64).collect());
        // network-get-interfaces
        let net_request = PveHttpRequest {
            path: format!("{base}/network-get-interfaces"),
            ..request.clone()
        };
        match self.call(net_request.clone()).await {
            Ok(data) => {
                let result = data.get("result").cloned().unwrap_or(data);
                if let Some(interfaces) = result.as_array() {
                    let mut dropped = 0_usize;
                    for interface in interfaces {
                        match normalize_interface(interface) {
                            Ok(Some(_)) if agent.interfaces.len() >= MAX_AGENT_INTERFACES => {
                                dropped += 1;
                            }
                            Ok(Some(mut interface)) => {
                                if interface.addresses.len() > MAX_INTERFACE_ADDRESSES {
                                    warnings.push(format!(
                                        "guest qemu/{vmid}: interface {} reported {} addresses; \
                                         kept the first {MAX_INTERFACE_ADDRESSES}",
                                        interface.name,
                                        interface.addresses.len()
                                    ));
                                    interface.addresses.truncate(MAX_INTERFACE_ADDRESSES);
                                }
                                agent.interfaces.push(interface);
                            }
                            Ok(None) => {}
                            Err(detail) => {
                                warnings.push(format!("guest qemu/{vmid}: {detail}"));
                            }
                        }
                    }
                    if dropped > 0 {
                        warnings.push(format!(
                            "guest qemu/{vmid}: the agent reported {dropped} interfaces over the \
                             {MAX_AGENT_INTERFACES}-interface bound; they were not kept"
                        ));
                    }
                }
            }
            Err(error) => {
                warnings.push(format!(
                    "guest qemu/{vmid}: the agent's network surface failed: {error}"
                ));
            }
        }
        agent
    }

    async fn probe_agent(
        &self,
        request: &PveHttpRequest,
        node: &str,
        vmid: u32,
        warnings: &mut Vec<String>,
    ) -> PveGuestAgent {
        let mut agent = self
            .probe_agent_network(request, node, vmid, warnings)
            .await;
        if !agent.online {
            return agent;
        }
        let base = format!("/api2/json/nodes/{}/qemu/{vmid}/agent", urlencode(node));
        // get-osinfo
        let os_request = PveHttpRequest {
            path: format!("{base}/get-osinfo"),
            ..request.clone()
        };
        match self.call(os_request.clone()).await {
            Ok(data) => {
                let result = data.get("result").cloned().unwrap_or(data);
                agent.os_name = result
                    .get("pretty-name")
                    .and_then(serde_json::Value::as_str)
                    .map(|value| value.chars().take(128).collect());
                agent.kernel = result
                    .get("kernel-release")
                    .and_then(serde_json::Value::as_str)
                    .map(|value| value.chars().take(128).collect());
                agent.os = normalize_osinfo(&result);
            }
            Err(error) => {
                warnings.push(format!(
                    "guest qemu/{vmid}: the agent's OS surface failed: {error}"
                ));
            }
        }
        agent
    }

    /// Lists the cluster's QEMU resources by the caller's purpose: the
    /// idempotency classifications read the cluster's truth, not a cache.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`].
    pub async fn list_guest_resources(
        &self,
        request: PveHttpRequest,
    ) -> Result<Vec<PveResource>, PveApiError> {
        let (version, entries) = self.version_and_resources(&request).await?;
        let mut resources = Vec::new();
        for entry in entries {
            if let Ok(Some(resource)) = normalize_resource(&entry) {
                let _ = &version;
                resources.push(resource);
            }
        }
        Ok(resources
            .into_iter()
            .filter(|resource| matches!(resource.kind.as_str(), "qemu" | "qemu-template" | "lxc"))
            .collect())
    }

    /// The cluster's next free VMID (`GET /cluster/nextid`). PVE picks the
    /// lowest free VMID inside the `datacenter.cfg` `next-id` range
    /// (`lower` inclusive, `upper` exclusive; default 100..1000000), so an
    /// operator reserves Fleet's clone targets there. Any caller may read
    /// it (`user => 'all'`). The answer only reflects the moment of the
    /// read: the caller reserves the VMID before it uses it.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`], including an answer that is not a VMID.
    pub async fn next_vmid(&self, request: PveHttpRequest) -> Result<u32, PveApiError> {
        let nextid_request = PveHttpRequest {
            path: "/api2/json/cluster/nextid".to_owned(),
            method: PveHttpMethod::Get,
            ..request
        };
        let data = self.call(nextid_request).await?;
        // PVE declares an integer but its JSON formatter may emit it as a
        // string; both shapes are accepted, nothing else is.
        let vmid = match &data {
            serde_json::Value::Number(number) => number.as_u64(),
            serde_json::Value::String(text) => text.parse::<u64>().ok(),
            _ => None,
        }
        .and_then(|vmid| u32::try_from(vmid).ok())
        .filter(|vmid| *vmid >= 100);
        vmid.ok_or_else(|| PveApiError::InvalidPayload {
            detail: format!(
                "the nextid answer is not a VMID (it is a {})",
                type_name_of(&data)
            ),
        })
    }

    /// The few facts of one QEMU guest's current config
    /// (`GET /nodes/{node}/qemu/{vmid}/config`) that the Lab executor
    /// checks before it changes a fresh clone (issue #290). Needs
    /// `VM.Audit` on `/vms/{vmid}`.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`], including a config that is not an object
    /// or whose `template`/`protection` flags are unreadable.
    pub async fn qemu_config_flags(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
    ) -> Result<PveQemuConfigFlags, PveApiError> {
        let config = self
            .call(PveHttpRequest {
                path: format!("/api2/json/nodes/{}/qemu/{vmid}/config", urlencode(node)),
                method: PveHttpMethod::Get,
                ..request
            })
            .await?;
        if !config.is_object() {
            return Err(PveApiError::InvalidPayload {
                detail: format!(
                    "the guest config is not an object (it is a {})",
                    type_name_of(&config)
                ),
            });
        }
        let flag = |key: &str| match config.get(key) {
            None | Some(serde_json::Value::Null) => Ok(false),
            Some(_) => match loose_number(&config, key) {
                Some(0) => Ok(false),
                Some(1) => Ok(true),
                _ => Err(PveApiError::InvalidPayload {
                    detail: format!("the guest config's {key} flag is unreadable"),
                }),
            },
        };
        // Over-long values are a payload error, never truncated: they feed
        // the clone-identity check and the conditional update.
        let text = |key: &str, limit: usize| {
            bounded_str(&config, key, limit)
                .map_err(|detail| PveApiError::InvalidPayload { detail })
        };
        Ok(PveQemuConfigFlags {
            name: text("name", MAX_ID_CHARS)?,
            template: flag("template")?,
            protection: flag("protection")?,
            // A present lock that is not a string is unreadable, never
            // "no lock": the caller would treat the guest as settled.
            lock: match config.get("lock") {
                None | Some(serde_json::Value::Null | serde_json::Value::String(_)) => {
                    text("lock", 32)?
                }
                Some(_) => {
                    return Err(PveApiError::InvalidPayload {
                        detail: "the guest config's lock field is unreadable".to_owned(),
                    });
                }
            },
            digest: text("digest", 64)?,
        })
    }

    /// Clears the `protection` flag of one QEMU guest
    /// (`PUT /nodes/{node}/qemu/{vmid}/config` with `protection=0`), which
    /// PVE answers synchronously. Needs `VM.Config.Options` on
    /// `/vms/{vmid}`. The update is always conditional on `digest` (from
    /// [`Self::qemu_config_flags`]): PVE refuses it when the config changed
    /// since that read. The caller decides
    /// which guest may be unprotected; Lab clears it only on its own fresh
    /// clones, never on a template (issue #290).
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`], including PVE's refusal of a locked guest
    /// or a stale digest.
    pub async fn qemu_clear_protection(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
        digest: &str,
    ) -> Result<(), PveApiError> {
        let body = serde_json::json!({ "protection": 0, "digest": digest });
        self.call_method_with_body(
            request,
            PveHttpMethod::Put,
            &format!("/api2/json/nodes/{}/qemu/{vmid}/config", urlencode(node)),
            &body,
        )
        .await
        .map(|_| ())
    }

    /// Reads one task's status.
    async fn task_status_impl(
        &self,
        request: &PveHttpRequest,
        upid: &Upid,
    ) -> Result<TaskStatus, PveApiError> {
        let status_request = PveHttpRequest {
            path: format!(
                "/api2/json/nodes/{}/tasks/{}/status",
                urlencode(&upid.node),
                urlencode(&upid.raw)
            ),
            ..request.clone()
        };
        let data = match self.call(status_request).await {
            Ok(data) => data,
            // A task the node no longer knows (rotated out of its task
            // index) is a 400 parameter error whose `errors.upid` reads
            // "no such task" on 8.x and 9.x (`read_task_status` in
            // pve-manager's `PVE/API2/Tasks.pm`): honest uncertainty.
            Err(PveApiError::Http {
                status: 400,
                detail,
            }) if serde_json::from_str::<serde_json::Value>(&detail)
                .ok()
                .as_ref()
                .and_then(|body| body.pointer("/errors/upid"))
                .and_then(serde_json::Value::as_str)
                == Some("no such task") =>
            {
                return Ok(TaskStatus::Unknown);
            }
            Err(error) => return Err(error),
        };
        // The task-status payload: `status: running|stopped`,
        // `exitstatus: OK|ERROR ...`. `data: null` means the task entry is
        // unknown to the node — honest uncertainty.
        let Some(object) = data.as_object() else {
            return Ok(TaskStatus::Unknown);
        };
        match object.get("status").and_then(serde_json::Value::as_str) {
            Some("running") => Ok(TaskStatus::Running),
            Some("stopped") => {
                match object.get("exitstatus").and_then(serde_json::Value::as_str) {
                    Some("OK") => Ok(TaskStatus::Ok),
                    Some(detail) => Ok(TaskStatus::Error {
                        detail: detail.chars().take(256).collect(),
                    }),
                    // A stopped task without an exit status is honest
                    // uncertainty, not an empty error.
                    None => Ok(TaskStatus::Unknown),
                }
            }
            _ => Ok(TaskStatus::Unknown),
        }
    }
}

/// Decodes a `guest-get-osinfo` result. `None` when the answer is not an
/// object; a member that is not a string or is over the bound is dropped
/// rather than truncated, so a classification never reads an altered id.
fn normalize_osinfo(result: &serde_json::Value) -> Option<PveGuestOs> {
    result.as_object()?;
    let member = |key: &str| {
        result
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty() && value.chars().count() <= MAX_OS_FIELD_CHARS)
            .map(str::to_owned)
    };
    Some(PveGuestOs {
        id: member("id"),
        name: member("name"),
        pretty_name: member("pretty-name"),
        version: member("version"),
        version_id: member("version-id"),
        variant: member("variant"),
        variant_id: member("variant-id"),
        kernel_release: member("kernel-release"),
        kernel_version: member("kernel-version"),
        machine: member("machine"),
    })
}

/// Normalizes one agent network interface. `Ok(None)` skips loopback-style
/// entries without a MAC; `Err` warns.
fn normalize_interface(interface: &serde_json::Value) -> Result<Option<PveGuestInterface>, String> {
    let Some(name) = interface
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(|value| value.chars().take(64).collect::<String>())
    else {
        return Err("the interface entry carries no name".to_owned());
    };
    let mac = interface
        .get("hardware-address")
        .and_then(serde_json::Value::as_str)
        .and_then(normalize_mac)
        // The all-zero MAC is a loopback artifact, not association
        // evidence.
        .filter(|mac| mac != "00:00:00:00:00:00");
    let mut addresses = Vec::new();
    if let Some(list) = interface
        .get("ip-addresses")
        .and_then(serde_json::Value::as_array)
    {
        for address in list {
            if let Some(text) = address
                .get("ip-address")
                .and_then(serde_json::Value::as_str)
            {
                // Every guest has `127.0.0.1`/`::1`; as address evidence a
                // loopback address would match any machine registered at
                // loopback. Windows prints IPv6 with a `%zone` suffix
                // (`WSAAddressToString`), so the zone is ignored here.
                if text
                    .split('%')
                    .next()
                    .unwrap_or(text)
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
                {
                    continue;
                }
                let bounded = text.chars().take(64).collect::<String>();
                if !bounded.is_empty() {
                    addresses.push(bounded);
                }
            }
        }
    }
    if mac.is_none() && addresses.is_empty() {
        // Loopback-style: no association evidence, skip silently.
        return Ok(None);
    }
    Ok(Some(PveGuestInterface {
        name,
        mac,
        addresses,
    }))
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

/// The bound on a resource id.
const MAX_ID_CHARS: usize = 128;
/// The bound on a node or display name.
const MAX_NAME_CHARS: usize = 256;
/// The bound on a status string.
const MAX_STATUS_CHARS: usize = 64;

/// PVE node names are interpolated into endpoint path segments; reject
/// separators and control characters from a provider response before use.
fn safe_node_path_segment(node: &str) -> bool {
    !node.is_empty()
        && node != "."
        && node != ".."
        && node
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Reads a bounded string field, refusing overlong values rather than
/// truncating them: a silently altered identity is worse than a warning.
fn bounded_str(entry: &serde_json::Value, key: &str, max: usize) -> Result<Option<String>, String> {
    match entry.get(key).and_then(serde_json::Value::as_str) {
        Some(value) if value.chars().count() > max => Err(format!(
            "the {key} field is {} characters, over the {max}-character bound",
            value.chars().count()
        )),
        Some(value) => Ok(Some(value.to_owned())),
        None => Ok(None),
    }
}

/// Reads a number that PVE may deliver as a JSON number or a string.
fn loose_number(entry: &serde_json::Value, key: &str) -> Option<u64> {
    match entry.get(key) {
        Some(serde_json::Value::Number(number)) => number.as_u64(),
        Some(serde_json::Value::String(text)) => text.trim().parse().ok(),
        _ => None,
    }
}

/// Normalizes one cluster-resources entry. `Ok(None)` skips a non-resource
/// row without warning; `Err` warns.
fn normalize_resource(entry: &serde_json::Value) -> Result<Option<PveResource>, String> {
    let id = bounded_str(entry, "id", MAX_ID_CHARS)?
        .ok_or_else(|| "the entry carries no id".to_owned())?;
    let pve_type = entry
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("entry {id} carries no type"))?;
    let is_template = loose_number(entry, "template").unwrap_or(0) == 1;
    let kind = match (pve_type, is_template) {
        ("node", _) => "node",
        ("qemu", false) => "qemu",
        ("qemu", true) => "qemu-template",
        ("lxc", _) => "lxc",
        ("storage", _) => "storage",
        // PVE 9.x lists each node's SDN zones and fabrics as `network` rows
        // (at least the default `localnetwork` zone per node); like `sdn`
        // and `pool`, they are not resources Fleet manages.
        ("sdn" | "pool" | "network", _) => return Ok(None),
        (other, _) => {
            return Err(format!(
                "entry {id} has an unrecognized type {other:?} (reported honestly, not coerced)"
            ));
        }
    };
    let node = bounded_str(entry, "node", MAX_NAME_CHARS)?;
    let vmid = loose_number(entry, "vmid").and_then(|value| u32::try_from(value).ok());
    let name = bounded_str(entry, "name", MAX_NAME_CHARS)?;
    let status = bounded_str(entry, "status", MAX_STATUS_CHARS)?;
    Ok(Some(PveResource {
        kind: kind.to_owned(),
        id,
        node,
        vmid,
        name,
        status,
    }))
}

/// Normalizes the capacity fields from GET `/nodes/{node}/status` while
/// keeping each metric independent so a partial response remains useful.
fn normalize_node_status(
    status: &serde_json::Value,
    node: &str,
    warnings: &mut Vec<String>,
) -> (Option<f64>, Option<u64>, Option<u64>, Option<u64>) {
    let cpu_usage_ratio = if let Some(value) = status.get("cpu") {
        let ratio = value
            .as_f64()
            .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()));
        match ratio {
            Some(ratio) if ratio.is_finite() && (0.0..=1.0).contains(&ratio) => Some(ratio),
            _ => {
                warnings.push(format!(
                    "node {node} status: cpu usage is missing or outside the 0..=1 range"
                ));
                None
            }
        }
    } else {
        warnings.push(format!("node {node} status: cpu usage is missing"));
        None
    };

    let cpu_count = status
        .get("cpuinfo")
        .and_then(|cpuinfo| loose_number(cpuinfo, "cpus"));
    let memory = status.get("memory");
    let memory_used_bytes = memory.and_then(|memory| loose_number(memory, "used"));
    let memory_total_bytes = memory.and_then(|memory| loose_number(memory, "total"));
    if memory_used_bytes.is_none() || memory_total_bytes.is_none() {
        warnings.push(format!(
            "node {node} status: memory used or total is missing or invalid"
        ));
    }

    (
        cpu_usage_ratio,
        cpu_count,
        memory_used_bytes,
        memory_total_bytes,
    )
}

/// Normalizes one row from GET `/nodes/{node}/storage`.
fn normalize_storage(entry: &serde_json::Value) -> Result<PveStorageCapacity, String> {
    let storage = bounded_str(entry, "storage", MAX_ID_CHARS)?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "the storage entry carries no storage id".to_owned())?;
    let used_bytes = loose_number(entry, "used")
        .ok_or_else(|| format!("storage {storage} carries no non-negative used byte count"))?;
    let total_bytes = loose_number(entry, "total")
        .ok_or_else(|| format!("storage {storage} carries no non-negative total byte count"))?;
    Ok(PveStorageCapacity {
        storage,
        used_bytes,
        total_bytes,
    })
}

// PVE reports a missing config as HTTP 500, rather than 404. Match the
// exact reviewed config path so routing errors and other failures remain errors.
fn destroy_already_absent(error: &PveApiError, node: &str, vmid: u32) -> bool {
    let PveApiError::Http {
        status: 404 | 500,
        detail,
    } = error
    else {
        return false;
    };
    let body: serde_json::Value = match serde_json::from_str(detail) {
        Ok(body) => body,
        Err(_) => return false,
    };
    body.get("message")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|message| {
            message.trim()
                == format!(
                    "Configuration file 'nodes/{node}/qemu-server/{vmid}.conf' does not exist"
                )
        })
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

        let network = serde_json::json!({
            "id": "network/n1/zone/localnetwork", "network": "localnetwork",
            "network-type": "zone", "node": "n1", "status": "ok", "type": "network"
        });
        assert!(normalize_resource(&network).unwrap().is_none());

        let mystery = serde_json::json!({"id": "weird/1", "type": "mystery"});
        let error = normalize_resource(&mystery).unwrap_err();
        assert!(error.contains("unrecognized type"), "{error}");
    }

    #[test]
    fn node_api_paths_accept_only_safe_segments() {
        for node in ["pve-1", "pve_1", "node.example"] {
            assert!(safe_node_path_segment(node), "{node}");
        }
        for node in [
            "",
            ".",
            "..",
            "../version",
            "pve/status",
            "pve?x=1",
            "pve\n",
        ] {
            assert!(!safe_node_path_segment(node), "{node:?}");
        }
    }

    #[test]
    fn node_status_keeps_valid_metrics_when_other_fields_are_malformed() {
        let mut warnings = Vec::new();
        let (cpu, cpus, used, total) = normalize_node_status(
            &serde_json::json!({
                "cpu": 1.5,
                "cpuinfo": {"cpus": "8"},
                "memory": {"used": "-1", "total": "32768"}
            }),
            "pve",
            &mut warnings,
        );
        assert_eq!(cpu, None);
        assert_eq!(cpus, Some(8));
        assert_eq!(used, None);
        assert_eq!(total, Some(32_768));
        assert_eq!(warnings.len(), 2, "{warnings:?}");
    }

    #[test]
    fn malformed_storage_rows_are_rejected_without_coercion() {
        let valid = normalize_storage(&serde_json::json!({
            "storage": "local-lvm", "used": "10", "total": 100
        }))
        .unwrap();
        assert_eq!(valid.used_bytes, 10);
        assert_eq!(valid.total_bytes, 100);
        assert!(
            normalize_storage(&serde_json::json!({
                "storage": "local", "used": -1, "total": 100
            }))
            .is_err()
        );
    }

    #[test]
    fn config_macs_parse_the_netn_entries() {
        let config = serde_json::json!({
            "net0": "virtio=DE:AD:BE:EF:00:01,bridge=vmbr0,firewall=1",
            "net1": "virtio=DE:AD:BE:EF:00:02",
            "scsi0": "local-lvm:vm-101-disk-0",
            "memory": 2048
        });
        let (macs, warnings) = config_macs(&config);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(macs.len(), 2, "{macs:?}");
        assert_eq!(macs[0], "de:ad:be:ef:00:01");
        assert_eq!(macs[1], "de:ad:be:ef:00:02");
    }

    #[test]
    fn upids_parse_and_refuse_malformed_shapes() {
        let raw = "UPID:pve:0015523F:0C6DF532:6AAFE1EC:qmreboot:101:root@pam!GLM-AGENT:";
        let upid = Upid::parse(raw).unwrap();
        assert_eq!(upid.node, "pve");
        assert_eq!(upid.task_type, "qmreboot");
        assert_eq!(upid.target, "101");
        assert_eq!(upid.user, "root@pam!GLM-AGENT");

        assert!(Upid::parse("not-a-upid").is_err());
        assert!(Upid::parse("UPID:pve:0015:0C6D:6AAF:qmreboot:101:").is_err());
        // A field is empty: refused.
        assert!(Upid::parse("UPID:pve::0C6DF532:6AAFE1EC:qmreboot:101:user:").is_err());
        assert!(Upid::parse("UPID:pve:0015523F:0C6DF532:6AAFE1EC:qmreboot:101::").is_err());
        // Except the id: node-level tasks carry none.
        let node_task =
            Upid::parse("UPID:pve:0015523F:0C6DF532:6AAFE1EC:aptupdate::root@pam:").unwrap();
        assert_eq!(node_task.target, "");
        assert_eq!(node_task.task_type, "aptupdate");
        for task_type in NODE_LEVEL_TASK_TYPES {
            let raw = format!("UPID:pve:0015523F:0C6DF532:6AAFE1EC:{task_type}::root@pam:");
            assert_eq!(Upid::parse(&raw).unwrap().target, "", "{task_type}");
        }
        // The list stays sorted and free of duplicates, so a re-check
        // against the PVE sources is a plain diff.
        assert!(
            NODE_LEVEL_TASK_TYPES
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "{NODE_LEVEL_TASK_TYPES:?}"
        );
        // A guest task type with an empty id is not a node-level task.
        for task_type in ["qmstart", "qmreboot", "qmclone", "vzstart", "unknowntype"] {
            let raw = format!("UPID:pve:0015523F:0C6DF532:6AAFE1EC:{task_type}::root@pam:");
            let error = Upid::parse(&raw).unwrap_err();
            assert!(error.contains("not a node-level task type"), "{error}");
        }
        // A node-level type may still name a target (a single-guest vzdump).
        let single =
            Upid::parse("UPID:pve:0015523F:0C6DF532:6AAFE1EC:vzdump:101:root@pam:").unwrap();
        assert_eq!(single.target, "101");
        // Trailing material: refused.
        assert!(
            Upid::parse("UPID:pve:0015523F:0C6DF532:6AAFE1EC:qmreboot:101:user:extra").is_err()
        );
    }

    #[test]
    fn lifecycle_actions_round_trip_their_ids() {
        for id in ["start", "stop", "shutdown", "reboot"] {
            let action = LifecycleAction::from_id(id).unwrap();
            assert_eq!(action.id(), id);
            assert_eq!(action.path_segment(), id);
        }
        assert!(LifecycleAction::from_id("destroy").is_err());
    }

    #[test]
    fn a_net_entry_without_a_mac_warns() {
        let config = serde_json::json!({"net0": "bridge=vmbr0,firewall=1"});
        let (macs, warnings) = config_macs(&config);
        assert!(macs.is_empty());
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("no parseable MAC"), "{warnings:?}");
    }

    #[test]
    fn mac_normalization_refuses_non_macs() {
        assert_eq!(
            normalize_mac("AA:BB:CC:DD:EE:FF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(
            normalize_mac("virtio=DE:AD:BE:EF:00:01").as_deref(),
            Some("de:ad:be:ef:00:01")
        );
        assert!(normalize_mac("bridge=vmbr0").is_none());
        assert!(normalize_mac("AA:BB:CC").is_none());
        assert!(normalize_mac("ZZ:BB:CC:DD:EE:FF").is_none());
    }

    #[test]
    fn interfaces_normalize_and_skip_loopback() {
        let interface = serde_json::json!({
            "name": "ens18",
            "hardware-address": "BC:24:11:97:DB:A8",
            "ip-addresses": [
                {"ip-address": "192.168.68.240", "ip-address-type": "ipv4", "prefix": 24}
            ]
        });
        let normalized = normalize_interface(&interface).unwrap().unwrap();
        assert_eq!(normalized.name, "ens18");
        assert_eq!(normalized.mac.as_deref(), Some("bc:24:11:97:db:a8"));
        assert_eq!(normalized.addresses, vec!["192.168.68.240".to_owned()]);

        let loopback = serde_json::json!({
            "name": "lo",
            "hardware-address": "00:00:00:00:00:00",
            "ip-addresses": [
                {"ip-address": "127.0.0.1", "ip-address-type": "ipv4", "prefix": 8}
            ]
        });
        // Loopback carries only the all-zero MAC and loopback addresses:
        // neither is association evidence, so the interface is skipped.
        assert!(normalize_interface(&loopback).unwrap().is_none());

        let nameless = serde_json::json!({"hardware-address": "BC:24:11:97:DB:A8"});
        assert!(normalize_interface(&nameless).is_err());
    }

    #[test]
    fn windows_interfaces_keep_link_local_and_skip_the_pseudo_loopback() {
        // qemu-ga on Windows omits `hardware-address` when the adapter has
        // no physical address and prints IPv6 with a `%zone` suffix.
        let loopback = serde_json::json!({
            "name": "Loopback Pseudo-Interface 1",
            "ip-addresses": [
                {"ip-address": "::1", "ip-address-type": "ipv6", "prefix": 128},
                {"ip-address": "127.0.0.1", "ip-address-type": "ipv4", "prefix": 8}
            ]
        });
        assert!(normalize_interface(&loopback).unwrap().is_none());

        let ethernet = serde_json::json!({
            "name": "Ethernet 2",
            "hardware-address": "bc:24:11:0a:02:02",
            "ip-addresses": [
                {"ip-address": "fe80::be24:11ff:fe0a:202%12", "ip-address-type": "ipv6", "prefix": 64},
                {"ip-address": "169.254.10.20", "ip-address-type": "ipv4", "prefix": 16}
            ]
        });
        let normalized = normalize_interface(&ethernet).unwrap().unwrap();
        assert_eq!(normalized.name, "Ethernet 2");
        // The raw list keeps them; usability is the application's rule.
        assert_eq!(
            normalized.addresses,
            ["fe80::be24:11ff:fe0a:202%12", "169.254.10.20"]
        );
    }

    #[test]
    fn osinfo_members_decode_bounded_and_unclassified() {
        let windows = serde_json::json!({
            "id": "mswindows",
            "name": "Microsoft Windows",
            "pretty-name": "Windows Server 2022 Standard",
            "version": "Microsoft Windows Server 2022",
            "version-id": "2022",
            "variant": "server",
            "variant-id": "server",
            "kernel-release": "20348",
            "kernel-version": "10.0",
            "machine": "x86_64"
        });
        let os = normalize_osinfo(&windows).unwrap();
        assert_eq!(os.id.as_deref(), Some("mswindows"));
        assert_eq!(os.version_id.as_deref(), Some("2022"));
        assert_eq!(os.variant_id.as_deref(), Some("server"));
        assert_eq!(os.kernel_version.as_deref(), Some("10.0"));

        let odd = serde_json::json!({"id": 7, "name": "x".repeat(129)});
        assert_eq!(normalize_osinfo(&odd), Some(PveGuestOs::default()));
        assert_eq!(normalize_osinfo(&serde_json::json!("nope")), None);
    }

    #[test]
    fn config_ostype_is_kept_verbatim_or_warned() {
        let config = |value: serde_json::Value| serde_json::json!({ "ostype": value });
        assert_eq!(
            config_ostype(&config(serde_json::json!("win11"))),
            Ok(Some("win11".to_owned()))
        );
        assert_eq!(config_ostype(&serde_json::json!({})), Ok(None));
        assert!(config_ostype(&config(serde_json::json!("Win 11"))).is_err());
        assert!(config_ostype(&config(serde_json::json!(11))).is_err());
    }

    #[test]
    fn authorities_bracket_ipv6_literals() {
        let request = |host: &str| PveHttpRequest {
            host: host.to_owned(),
            port: 8006,
            path: "/".to_owned(),
            pinned_fingerprint: None,
            credentials: Arc::new(PveCredentials {
                token_id: "t".to_owned(),
                token: SensitiveString::new("s"),
            }),
            method: PveHttpMethod::Get,
        };
        assert_eq!(request("2001:db8::1").authority(), "[2001:db8::1]");
        assert_eq!(request("192.168.68.223").authority(), "192.168.68.223");
        assert_eq!(request("pve.localdomain").authority(), "pve.localdomain");
    }

    #[test]
    fn the_body_bound_refuses_mid_stream() {
        let mut body = Vec::new();
        let chunk = vec![0u8; MAX_BODY_BYTES];
        push_bounded(&mut body, &chunk).unwrap();
        let error = push_bounded(&mut body, &[0u8; 1]).unwrap_err();
        assert!(matches!(error, PveTransportError::BodyTooLarge { .. }));
    }

    #[test]
    fn overlong_fields_are_rejected_not_truncated() {
        let long_id = "x".repeat(MAX_ID_CHARS + 1);
        let entry = serde_json::json!({"id": long_id, "type": "node"});
        let error = normalize_resource(&entry).unwrap_err();
        assert!(error.contains("over the"), "{error}");

        let long_name = "y".repeat(MAX_NAME_CHARS + 1);
        let entry = serde_json::json!({
            "id": "qemu/1", "type": "qemu", "vmid": 1, "name": long_name
        });
        let error = normalize_resource(&entry).unwrap_err();
        assert!(error.contains("over the"), "{error}");
    }

    #[test]
    fn stringly_numbers_are_tolerated() {
        let entry = serde_json::json!({
            "id": "qemu/7", "type": "qemu", "vmid": "7", "template": "1"
        });
        let resource = normalize_resource(&entry).unwrap().unwrap();
        assert_eq!(resource.kind, "qemu-template");
        assert_eq!(resource.vmid, Some(7));

        let entry = serde_json::json!({
            "id": "qemu/8", "type": "qemu", "vmid": 8, "template": 0
        });
        let resource = normalize_resource(&entry).unwrap().unwrap();
        assert_eq!(resource.kind, "qemu");
        assert_eq!(resource.vmid, Some(8));

        // An out-of-range vmid is absent, never coerced to zero.
        let entry = serde_json::json!({
            "id": "qemu/9", "type": "qemu", "vmid": 4_294_967_296_i64
        });
        let resource = normalize_resource(&entry).unwrap().unwrap();
        assert_eq!(resource.vmid, None);
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
