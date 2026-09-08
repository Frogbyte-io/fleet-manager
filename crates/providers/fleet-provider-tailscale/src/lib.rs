//! The Tailscale provider: tailnet device discovery over the documented
//! API v2, with a least-privilege OAuth client (FM-213).
//!
//! The integration requests exactly one scope — `devices:core:read` — and
//! uses the client-credentials flow: `POST /api/v2/oauth/token` answers an
//! access token that lives about an hour; the token cache refetches shortly
//! before expiry. Device listing is `GET /api/v2/tailnet/{tailnet}/devices`;
//! the API has no pagination, so the provider bounds its own output and
//! hands normalized devices to the application layer.
//!
//! This crate never logs, stores, or serializes credentials: the secret
//! arrives per call inside redacting types and is dropped with the request.
//! Errors are caller-safe — statuses and bounded details, never tokens.
//!
//! The HTTP boundary sits behind the [`Transport`] port so tests can feed
//! recorded fixtures; the real transport is reqwest over rustls. The crate
//! is async on purpose: its caller (the controller's use case) is async.
//!
//! Known upstream limitation (documented, not worked around): access tokens
//! derived from an OAuth client see only tailnet-owned devices, not devices
//! shared *into* the tailnet.
#![warn(missing_docs)]

use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use fleet_application::tailnet::{
    TailnetCredentials, TailnetDevice, TailnetSource, TailnetSourceError,
};
use serde::Deserialize;

/// The OAuth token endpoint.
pub const TOKEN_URL: &str = "https://api.tailscale.com/api/v2/oauth/token";
/// The devices endpoint root.
pub const API_BASE: &str = "https://api.tailscale.com/api/v2";
/// How long a single API call may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// The token is refreshed this long before its documented expiry, so a
/// listing never rides a token that dies mid-flight.
pub const TOKEN_REFRESH_MARGIN_MILLIS: i64 = 60_000;

/// One HTTP request the provider needs, in transport-neutral form.
#[derive(Clone, Debug)]
pub struct HttpRequest {
    /// The absolute URL.
    pub url: String,
    /// The HTTP method.
    pub method: &'static str,
    /// The Authorization header value (a bearer token) or Basic credentials
    /// for the token endpoint. Never logged by the provider.
    pub authorization: String,
    /// The form body, when the request carries one.
    pub form: Option<Vec<(String, String)>>,
}

/// The HTTP response in transport-neutral form.
#[derive(Clone, Debug)]
pub struct HttpResponse {
    /// The HTTP status.
    pub status: u16,
    /// The response body.
    pub body: Vec<u8>,
    /// The `Retry-After` header, in seconds, when carried.
    pub retry_after_secs: Option<u64>,
}

impl HttpResponse {
    /// The body as bounded UTF-8, for error details.
    #[must_use]
    pub fn bounded_text(&self) -> String {
        let text = String::from_utf8_lossy(&self.body);
        let line = text.lines().map(str::trim).find(|l| !l.is_empty());
        let detail = line.unwrap_or("no detail");
        if detail.len() > 200 {
            format!("{}…", &detail[..200])
        } else {
            detail.to_owned()
        }
    }
}

/// The HTTP port. The real transport speaks TLS with rustls; tests record
/// responses.
#[async_trait]
pub trait Transport: fmt::Debug + Send + Sync {
    /// Executes one request.
    ///
    /// # Errors
    ///
    /// Fails when the request cannot be completed at the transport level
    /// (DNS, TLS, timeout); HTTP statuses travel inside the response.
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, String>;
}

/// A cached OAuth access token: the bearer value and its expiry.
#[derive(Clone, Debug)]
struct CachedToken {
    bearer: String,
    expires_at_unix_millis: i64,
}

/// The Tailscale client: transport, token cache, and the credential the
/// cache mints tokens from. The credential lives only here; the Debug never
/// renders it.
pub struct TailscaleClient {
    transport: std::sync::Arc<dyn Transport>,
    token: Mutex<Option<CachedToken>>,
}

impl fmt::Debug for TailscaleClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TailscaleClient")
            .field("transport", &self.transport)
            .field("token", &"<cached>")
            .finish()
    }
}

impl TailscaleClient {
    /// Composes the client over a transport.
    #[must_use]
    pub fn new(transport: std::sync::Arc<dyn Transport>) -> Self {
        Self {
            transport,
            token: Mutex::new(None),
        }
    }

    /// The bearer token, fetching and caching one when needed. The cache is
    /// per client instance; the composition root shares one client.
    ///
    /// # Errors
    ///
    /// Fails when the token endpoint refuses the client or the transport
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics only if the token cache mutex is poisoned, which cannot happen
    /// without a panic while holding it.
    pub async fn bearer_token(
        &self,
        credentials: &TailnetCredentials,
        now_unix_millis: i64,
    ) -> Result<String, TailnetSourceError> {
        {
            let cached = self.token.lock().expect("the token cache must lock");
            if let Some(token) = cached.as_ref()
                && now_unix_millis < token.expires_at_unix_millis - TOKEN_REFRESH_MARGIN_MILLIS
            {
                return Ok(token.bearer.clone());
            }
        }
        let request = HttpRequest {
            url: TOKEN_URL.to_owned(),
            method: "POST",
            // The documented client-credentials flow: the id as the basic
            // user and the secret as the basic password.
            authorization: format!(
                "Basic {}",
                basic_auth(&credentials.client_id, credentials.client_secret.expose())
            ),
            form: Some(vec![
                ("grant_type".to_owned(), "client_credentials".to_owned()),
                (
                    "scope".to_owned(),
                    fleet_application::tailnet::TAILNET_SCOPE.to_owned(),
                ),
            ]),
        };
        let response =
            self.transport
                .execute(request)
                .await
                .map_err(|error| TailnetSourceError::Http {
                    status: 0,
                    detail: truncate(&error),
                })?;
        if response.status == 401 || response.status == 403 {
            return Err(TailnetSourceError::Auth {
                detail: response.bounded_text(),
            });
        }
        if !(200..300).contains(&response.status) {
            return Err(TailnetSourceError::Http {
                status: response.status,
                detail: response.bounded_text(),
            });
        }
        let token: TokenResponse = serde_json::from_slice(&response.body).map_err(|error| {
            TailnetSourceError::InvalidPayload {
                detail: truncate(&error.to_string()),
            }
        })?;
        let cached = CachedToken {
            bearer: token.access_token,
            expires_at_unix_millis: now_unix_millis + token.expires_in.unwrap_or(3600) * 1000,
        };
        {
            let mut slot = self.token.lock().expect("the token cache must lock");
            *slot = Some(cached.clone());
        }
        Ok(cached.bearer)
    }

    /// Lists the tailnet's devices.
    ///
    /// # Errors
    ///
    /// Fails with the caller-safe [`TailnetSourceError`] taxonomy.
    pub async fn list_devices(
        &self,
        tailnet: &str,
        credentials: &TailnetCredentials,
    ) -> Result<Vec<TailnetDevice>, TailnetSourceError> {
        let now = fleet_core::SystemClock::now_unix_millis();
        let bearer = self.bearer_token(credentials, now).await?;
        let request = HttpRequest {
            url: format!("{API_BASE}/tailnet/{tailnet}/devices"),
            method: "GET",
            authorization: format!("Bearer {bearer}"),
            form: None,
        };
        let response =
            self.transport
                .execute(request)
                .await
                .map_err(|error| TailnetSourceError::Http {
                    status: 0,
                    detail: truncate(&error),
                })?;
        match response.status {
            200 => {}
            401 | 403 => {
                return Err(TailnetSourceError::Auth {
                    detail: response.bounded_text(),
                });
            }
            404 => {
                return Err(TailnetSourceError::NotFound {
                    detail: response.bounded_text(),
                });
            }
            429 => {
                return Err(TailnetSourceError::RateLimited {
                    retry_after_secs: response.retry_after_secs,
                });
            }
            status => {
                return Err(TailnetSourceError::Http {
                    status,
                    detail: response.bounded_text(),
                });
            }
        }
        let document: DevicesResponse =
            serde_json::from_slice(&response.body).map_err(|error| {
                TailnetSourceError::InvalidPayload {
                    detail: truncate(&error.to_string()),
                }
            })?;
        Ok(document
            .devices
            .into_iter()
            .map(RawDevice::into_device)
            .collect())
    }
}

#[async_trait]
impl TailnetSource for TailscaleClient {
    async fn list_devices(
        &self,
        tailnet: &str,
        credentials: &TailnetCredentials,
    ) -> Result<Vec<TailnetDevice>, TailnetSourceError> {
        self.list_devices(tailnet, credentials).await
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<i64>,
    #[allow(dead_code)]
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DevicesResponse {
    devices: Vec<RawDevice>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDevice {
    node_id: Option<String>,
    id: Option<String>,
    name: Option<String>,
    hostname: Option<String>,
    os: Option<String>,
    addresses: Option<Vec<String>>,
    tags: Option<Vec<String>>,
    user: Option<String>,
    online: Option<bool>,
    connected_to_control: Option<bool>,
    last_seen: Option<String>,
}

impl RawDevice {
    fn into_device(self) -> TailnetDevice {
        let id = self.id;
        TailnetDevice {
            node_id: self.node_id.or(id.clone()).unwrap_or_default(),
            id,
            name: self.name.unwrap_or_default(),
            hostname: self.hostname.unwrap_or_default(),
            os: self.os.unwrap_or_default(),
            addresses: self.addresses.unwrap_or_default(),
            tags: self.tags.unwrap_or_default(),
            user: self.user.unwrap_or_default(),
            online: self.online,
            connected_to_control: self.connected_to_control,
            last_seen: self.last_seen,
        }
    }
}

/// RFC 7617 basic auth, base64 of `user:password`.
fn basic_auth(user: &str, password: &str) -> String {
    use base64::Engine as _;
    let combined = format!("{user}:{password}");
    base64::engine::general_purpose::STANDARD.encode(combined.as_bytes())
}

fn truncate(text: &str) -> String {
    if text.len() <= 200 {
        text.to_owned()
    } else {
        let mut end = 200;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &text[..end])
    }
}

/// The reqwest-backed transport: rustls TLS, bounded timeouts, and no
/// cookie/redirect surprises.
#[derive(Debug)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Builds the transport.
    ///
    /// # Errors
    ///
    /// Fails when the HTTP client cannot be built.
    pub fn new() -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|error| format!("cannot build the HTTP client: {error}"))?;
        Ok(Self { client })
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new().expect("the reqwest transport must build")
    }
}

#[async_trait]
impl Transport for ReqwestTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        let method = match request.method {
            "POST" => reqwest::Method::POST,
            "GET" => reqwest::Method::GET,
            other => reqwest::Method::from_bytes(other.as_bytes())
                .map_err(|error| format!("the method is malformed: {error}"))?,
        };
        let mut builder = self
            .client
            .request(method, &request.url)
            .header("Authorization", &request.authorization);
        if let Some(form) = &request.form {
            builder = builder.form(form);
        }
        let response = builder.send().await.map_err(|error| error.to_string())?;
        let retry_after_secs = response
            .headers()
            .get("Retry-After")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse().ok());
        let status = u16::from(response.status());
        let body = response.bytes().await.map_err(|error| error.to_string())?;
        Ok(HttpResponse {
            status,
            body: body.to_vec(),
            retry_after_secs,
        })
    }
}
